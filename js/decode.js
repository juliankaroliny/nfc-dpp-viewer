/**
 * Pure decoding helpers.
 *
 * Nothing in here touches the DOM or the network. Everything read from a
 * tag is decoded locally in the browser.
 */

const MAX_NESTING = 3;

/* ------------------------------------------------------------------ bytes */

export const utf8 = (text) => new TextEncoder().encode(text);

/** Copy a DataView (as delivered by Web NFC) into a standalone Uint8Array. */
export function bytesFromDataView(view) {
  if (!view) return new Uint8Array(0);
  return new Uint8Array(view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength));
}

/** NFC text records use big-endian UTF-16 unless a byte-order mark says otherwise. */
function resolveEncoding(label, bytes) {
  const l = String(label).toLowerCase();
  if (!/^utf-?16/.test(l)) return l;
  if (bytes[0] === 0xff && bytes[1] === 0xfe) return 'utf-16le';
  if (bytes[0] === 0xfe && bytes[1] === 0xff) return 'utf-16be';
  return l === 'utf-16le' ? 'utf-16le' : 'utf-16be';
}

/** Decode bytes as text. `valid` is false if the bytes are not valid in that encoding. */
export function decodeText(bytes, label = 'utf-8') {
  const encoding = resolveEncoding(label, bytes);
  try {
    return { text: new TextDecoder(encoding, { fatal: true }).decode(bytes), valid: true };
  } catch {
    let decoder;
    try { decoder = new TextDecoder(encoding); } catch { decoder = new TextDecoder(); }
    return { text: decoder.decode(bytes), valid: false };
  }
}

export function toHex(bytes, separator = ' ') {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join(separator);
}

export function hexRows(bytes, perRow = 16) {
  const rows = [];
  for (let i = 0; i < bytes.length; i += perRow) {
    rows.push({ offset: i.toString(16).padStart(4, '0'), hex: toHex(bytes.subarray(i, i + perRow)) });
  }
  return rows;
}

/** Printable ASCII; line feeds kept, every other byte shown as "·". */
export function toAscii(bytes) {
  let out = '';
  for (const b of bytes) {
    if (b === 0x0a) out += '\n';
    else if (b >= 0x20 && b <= 0x7e) out += String.fromCharCode(b);
    else out += '·';
  }
  return out;
}

/* ----------------------------------------------------------------- base64 */

export function encodeBase64(bytes, { url = false } = {}) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  const b64 = btoa(binary);
  return url ? b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') : b64;
}

/** Decode standard or URL-safe Base64 (padding optional, whitespace ignored). */
export function decodeBase64(input) {
  const s = String(input).replace(/\s+/g, '');
  if (!s) return { ok: false, error: 'empty input' };

  let variant;
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(s)) variant = 'base64';
  else if (/^[A-Za-z0-9_-]+={0,2}$/.test(s)) variant = 'base64url';
  else return { ok: false, error: 'contains characters outside the Base64 alphabet' };

  const body = s.replace(/=+$/, '');
  if (body.length % 4 === 1) return { ok: false, error: 'invalid length' };
  if (body.length !== s.length && s.length % 4 !== 0) return { ok: false, error: 'invalid padding' };

  const std = body.replace(/-/g, '+').replace(/_/g, '/');
  try {
    const binary = atob(std + '='.repeat((4 - (std.length % 4)) % 4));
    return { ok: true, variant, bytes: Uint8Array.from(binary, (c) => c.charCodeAt(0)) };
  } catch {
    return { ok: false, error: 'could not be decoded' };
  }
}

/* -------------------------------------------------------------- detection */

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/** Only called on strictly decoded text, so a U+FFFD here is a real character, not an error. */
function isPrintableText(text) {
  return !/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(text);
}

/**
 * JSON.parse reviver that keeps big integers exactly as written (e.g. 20-digit
 * serials) instead of rounding them. Uses JSON.rawJSON where available (Chrome 114+).
 */
function keepNumberSource(key, value, context) {
  if (typeof value === 'number' && !Number.isSafeInteger(value) && Number.isInteger(value) &&
      /^-?\d+$/.test(context?.source ?? '') && typeof JSON.rawJSON === 'function') {
    return JSON.rawJSON(context.source);
  }
  return value;
}
export const isRawJson = (v) => typeof JSON.isRawJSON === 'function' && JSON.isRawJSON(v);
export const parseJson = (text) => JSON.parse(text, keepNumberSource);

/** null = doesn't look like JSON; {value} = parsed; {error} = looks like JSON but is broken. */
function tryParseJson(text) {
  if (!/^[\[{]/.test(text)) return null;
  try {
    return { value: parseJson(text) };
  } catch (err) {
    return { error: err.message };
  }
}

function looksLikeBase64(text) {
  if (text.length < 8 || /[ \t]/.test(text)) return null;
  const compact = text.replace(/[\r\n]+/g, '');
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(compact) || /^\d+$/.test(compact)) return null;
  const res = decodeBase64(compact);
  if (!res.ok) return null;
  // "strong" = convincing enough to report even if the decoded bytes are binary.
  // Kept conservative so identifiers like "ProductPassport2024" or "a/b/c" stay plain text;
  // anything else can still be decoded manually via the Base64 tab.
  const strong = compact.endsWith('=') ||
    (compact.length >= 40 && /[+\/]/.test(compact) &&
      /[a-z]/.test(compact) && /[A-Z]/.test(compact) && /\d/.test(compact));
  return { ...res, strong };
}

// Strict: "data:" + optional type/subtype + ;params, no whitespace — so text like "Data: 92%, …" isn't matched.
const DATA_URL_RE = /^data:((?:[\w!#$&^.+-]+\/[\w!#$&^.+-]+)?(?:;[\w!#$&^.+-]+(?:=[^;,\s]*)?)*),([\s\S]*)$/i;

function parseDataUrl(text) {
  const m = DATA_URL_RE.exec(text);
  if (!m) return null;
  const params = m[1].split(';');
  const base64 = params.length > 1 && params[params.length - 1].toLowerCase() === 'base64';
  const mediaType = (base64 ? params.slice(0, -1) : params).join(';') || 'text/plain';
  if (base64) {
    const res = decodeBase64(m[2]);
    return res.ok ? { mediaType, base64, bytes: res.bytes } : null;
  }
  return { mediaType, base64, bytes: percentDecodeBytes(m[2]) };
}

/** Percent-decode to raw bytes (unlike decodeURIComponent this also handles non-UTF-8 like %FF). */
function percentDecodeBytes(text) {
  const src = utf8(text);
  const out = [];
  for (let i = 0; i < src.length; i++) {
    const hex = src[i] === 0x25 && i + 2 < src.length ? String.fromCharCode(src[i + 1], src[i + 2]) : '';
    if (/^[0-9a-f]{2}$/i.test(hex)) {
      out.push(parseInt(hex, 16));
      i += 2;
    } else {
      out.push(src[i]);
    }
  }
  return new Uint8Array(out);
}

/* ------------------------------------------------------------ JWT / JOSE */

const SEG = '[A-Za-z0-9_-]+';
const JWS_RE = new RegExp(`^${SEG}\\.${SEG}\\.[A-Za-z0-9_-]*$`);
const JWE_RE = new RegExp(`^${SEG}\\.[A-Za-z0-9_-]*\\.${SEG}\\.${SEG}\\.[A-Za-z0-9_-]*$`);

function decodeSegmentJson(segment) {
  const res = decodeBase64(segment);
  if (!res.ok) return undefined;
  const { text, valid } = decodeText(res.bytes);
  if (!valid) return undefined;
  try { return parseJson(text); } catch { return undefined; }
}

function parseDisclosure(raw) {
  const v = decodeSegmentJson(raw);
  if (Array.isArray(v) && v.length === 3) return { raw, salt: v[0], name: String(v[1]), value: v[2] };
  if (Array.isArray(v) && v.length === 2) return { raw, salt: v[0], name: null, value: v[1] };
  return { raw, invalid: true };
}

/**
 * Recognise a compact JWS (JWT), an SD-JWT (jwt~disclosure~…~[kb-jwt]) or a JWE.
 * Only decodes. Signatures are NOT verified.
 */
export function parseJose(input, allowSdJwt = true) {
  const raw = input.trim();
  const pieces = allowSdJwt ? raw.split('~') : [raw];
  const compact = pieces[0];

  if (JWE_RE.test(compact)) {
    const header = decodeSegmentJson(compact.split('.')[0]);
    return pieces.length === 1 && isObject(header) && 'enc' in header ? { kind: 'jwe', header, raw } : null;
  }
  if (!JWS_RE.test(compact)) return null;

  const [h, p, s] = compact.split('.');
  const header = decodeSegmentJson(h);
  if (!isObject(header) || typeof header.alg !== 'string') return null;

  const payloadRes = decodeBase64(p);
  const payloadText = payloadRes.ok ? decodeText(payloadRes.bytes).text : '';
  let payload;
  try { payload = parseJson(payloadText); } catch { payload = undefined; }
  const sigRes = s ? decodeBase64(s) : null;

  const token = {
    kind: 'jwt',
    header,
    payload,
    payloadText,
    signature: sigRes?.ok ? sigRes.bytes : new Uint8Array(0),
    raw,
  };
  if (pieces.length > 1) {
    // jwt~d1~d2~        → no key binding
    // jwt~d1~d2~kb-jwt  → last piece is the key-binding JWT
    // jwt~d1~d2         → (missing trailing "~") last piece is still a disclosure
    token.kind = 'sd-jwt';
    const last = pieces[pieces.length - 1];
    const keyBinding = last ? parseJose(last, false) : null;
    const disclosures = last && !keyBinding ? pieces.slice(1) : pieces.slice(1, -1);
    token.disclosures = disclosures.filter(Boolean).map(parseDisclosure);
    token.keyBinding = keyBinding;
  }
  return token;
}

/* --------------------------------------------------------------- analysis */

const STRUCTURED_KINDS = new Set(['json', 'jwt', 'sd-jwt', 'jwe', 'data-url', 'base64']);

/**
 * Work out what a payload most likely is.
 * kinds: empty | binary | text | json | invalid-json | jwt | sd-jwt | jwe | base64 | data-url
 */
export function analyze(bytes, { encoding = 'utf-8', mediaType = '' } = {}, depth = 0) {
  if (!bytes || bytes.length === 0) return { kind: 'empty' };

  const { text, valid } = decodeText(bytes, encoding);
  if (!valid || !isPrintableText(text)) return { kind: 'binary', bytes };

  const t = text.trim();
  if (!t) return { kind: 'text', text };

  const json = tryParseJson(t);
  if (json && 'value' in json) return { kind: 'json', value: json.value, text: t };

  const token = parseJose(t);
  if (token) return token;

  if (depth < MAX_NESTING) {
    const dataUrl = parseDataUrl(t);
    if (dataUrl) {
      return {
        kind: 'data-url',
        mediaType: dataUrl.mediaType,
        base64: dataUrl.base64,
        bytes: dataUrl.bytes,
        inner: analyze(dataUrl.bytes, { mediaType: dataUrl.mediaType }, depth + 1),
      };
    }
    const b64 = looksLikeBase64(t);
    if (b64) {
      const inner = analyze(b64.bytes, {}, depth + 1);
      // Many plain words/serials happen to be valid Base64 ("airports" → "j*颻l"), so without
      // strong evidence only accept results that are clearly meaningful.
      const meaningful = STRUCTURED_KINDS.has(inner.kind) ||
        (inner.kind === 'text' && /^[\x20-\x7e\t\r\n]+$/.test(inner.text) && /\s/.test(inner.text.trim()));
      if (meaningful || b64.strong) {
        return { kind: 'base64', variant: b64.variant, bytes: b64.bytes, inner };
      }
    }
  }

  if (json && 'error' in json && /json/i.test(mediaType)) {
    return { kind: 'invalid-json', error: json.error, text };
  }
  return { kind: 'text', text };
}

export function analysisLabel(a) {
  switch (a.kind) {
    case 'json': return 'JSON';
    case 'jwt': return `JWT · ${a.header.alg}`;
    case 'sd-jwt': return `SD-JWT · ${a.disclosures.length} disclosure${a.disclosures.length === 1 ? '' : 's'}`;
    case 'jwe': return 'JWE · encrypted';
    case 'base64': return `${a.variant === 'base64url' ? 'Base64url' : 'Base64'} → ${analysisLabel(a.inner)}`;
    case 'data-url': return `Data URL → ${analysisLabel(a.inner)}`;
    case 'invalid-json': return 'Invalid JSON';
    case 'text': return 'Text';
    case 'binary': return 'Binary';
    default: return 'Empty';
  }
}

/* ---------------------------------------------------------------- records */

const KNOWN_TYPES = {
  empty: ['Empty', 'TNF 0 · Empty'],
  text: ['Text', 'TNF 1 · Well-known "T"'],
  url: ['URL', 'TNF 1 · Well-known "U"'],
  'smart-poster': ['Smart Poster', 'TNF 1 · Well-known "Sp"'],
  mime: ['MIME', 'TNF 2 · Media type'],
  'absolute-url': ['Absolute URL', 'TNF 3 · Absolute URI'],
  unknown: ['Unknown', 'TNF 5 · Unknown'],
};

/** label: short type name; tnf: NDEF type name format (shown as tooltip); detail: type string worth showing. */
export function recordTypeInfo(rec) {
  const t = rec.recordType;
  if (KNOWN_TYPES[t]) return { label: KNOWN_TYPES[t][0], tnf: KNOWN_TYPES[t][1], detail: null };
  if (t.startsWith(':')) return { label: 'Local type', tnf: 'TNF 1 · Local type', detail: t.slice(1) };
  if (t.includes(':')) return { label: 'External', tnf: 'TNF 4 · External type', detail: t };
  return { label: 'Record', tnf: 'Unrecognised type', detail: t || null };
}

/** Text encoding for a record: the text record's own encoding, a MIME charset parameter, or UTF-8. */
export function recordEncoding(rec) {
  if (rec.recordType === 'text' && rec.encoding) return rec.encoding;
  const m = /;\s*charset\s*=\s*"?([\w.:-]+)"?/i.exec(rec.mediaType || '');
  if (m) {
    try {
      new TextDecoder(m[1]);
      return m[1];
    } catch {
      /* unknown charset → UTF-8 */
    }
  }
  return 'utf-8';
}

/** Turn a live NDEFRecord into a plain object (so the renderer and sample data share one shape). */
export function normalizeRecord(record) {
  const recordType = record.recordType || '';
  let children = null;
  if (recordType === 'smart-poster' || recordType.includes(':')) {
    try {
      const nested = record.toRecords?.();
      if (nested?.length) children = Array.from(nested, (r) => normalizeRecord(r));
    } catch {
      /* payload is not a nested NDEF message */
    }
  }
  return {
    recordType,
    mediaType: record.mediaType || null,
    id: record.id || null,
    encoding: record.encoding || null,
    lang: record.lang || null,
    bytes: bytesFromDataView(record.data),
    children,
  };
}
