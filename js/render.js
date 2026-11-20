/**
 * DOM rendering of scans and records.
 *
 * Security: tag content is only ever inserted as text nodes (never via
 * innerHTML), and only http(s) URLs become clickable links.
 */
import {
  analyze, analysisLabel, recordTypeInfo, decodeText, decodeBase64, toAscii, toHex, hexRows, isRawJson,
} from './decode.js';

/* ---------------------------------------------------------------- helpers */

export function h(tag, props, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props ?? {})) {
    if (value == null || value === false) continue;
    if (key === 'class') el.className = value;
    else if (key.startsWith('on')) el.addEventListener(key.slice(2), value);
    else el.setAttribute(key, value === true ? '' : String(value));
  }
  for (const child of children.flat(Infinity)) {
    if (child == null || child === false) continue;
    el.append(child instanceof Node ? child : String(child));
  }
  return el;
}

export async function copyToClipboard(text, button) {
  button.dataset.label ??= button.textContent;
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = 'Copied ✓';
  } catch {
    button.textContent = 'Copy failed';
  }
  clearTimeout(button._resetTimer);
  button._resetTimer = setTimeout(() => { button.textContent = button.dataset.label; }, 1400);
}

const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
const formatBytes = (n) => plural(n, 'byte');
const pre = (text) => h('pre', { class: 'code' }, text);
const note = (tone, text) => h('p', { class: `note note-${tone}` }, text);
const section = (title, ...content) => h('section', { class: 'sub' }, h('h4', {}, title), ...content);
const isUrlRecord = (rec) => rec.recordType === 'url' || rec.recordType === 'absolute-url';

function safeDecodeURI(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}

/* ------------------------------------------------------------- JSON tree */

function primitive(value) {
  if (isRawJson(value)) return h('span', { class: 'j-num' }, value.rawJSON); // number kept verbatim
  if (typeof value === 'string') return h('span', { class: 'j-str' }, JSON.stringify(value));
  if (typeof value === 'number') return h('span', { class: 'j-num' }, String(value));
  if (typeof value === 'boolean') return h('span', { class: 'j-bool' }, String(value));
  return h('span', { class: 'j-null' }, 'null');
}

function jsonNode(key, value, depth) {
  const keyEl = key === undefined ? null : [h('span', { class: 'j-key' }, key), h('span', { class: 'j-punct' }, ': ')];

  if (value === null || typeof value !== 'object' || isRawJson(value)) {
    return h('div', { class: 'j-line' }, keyEl, primitive(value));
  }

  const isArray = Array.isArray(value);
  const entries = isArray ? value.map((v) => [undefined, v]) : Object.entries(value);
  const [open, close] = isArray ? ['[', ']'] : ['{', '}'];
  if (entries.length === 0) {
    return h('div', { class: 'j-line' }, keyEl, h('span', { class: 'j-punct' }, open + close));
  }

  return h('details', { class: 'j-node', open: depth < 3 },
    h('summary', {},
      keyEl,
      h('span', { class: 'j-punct' }, open),
      h('span', { class: 'j-punct j-ellipsis' }, ` … ${close}`),
      h('span', { class: 'j-count' }, plural(entries.length, isArray ? 'item' : 'key'))),
    h('div', { class: 'j-children' }, entries.map(([k, v]) => jsonNode(k, v, depth + 1))),
    h('div', { class: 'j-punct j-close' }, close));
}

function jsonTree(value) {
  return h('div', { class: 'json' }, jsonNode(undefined, value, 0));
}

/* ------------------------------------------------------------ byte views */

function hexBlock(bytes) {
  if (!bytes.length) return h('p', { class: 'muted' }, 'No bytes.');
  const perRow = window.matchMedia('(min-width: 640px)').matches ? 16 : 8;
  return h('div', { class: 'code hex' },
    hexRows(bytes, perRow).map((row) => h('div', { class: 'hex-row' },
      h('span', { class: 'hex-off' }, row.offset), h('span', {}, row.hex))));
}

const HEX_NOTES = {
  text: 'Web NFC already removed the status byte and language code.',
  url: 'Web NFC already expanded the URI prefix byte (e.g. 0x04 → "https://").',
};

function viewText(rec) {
  const encoding = rec.recordType === 'text' && rec.encoding ? rec.encoding : 'utf-8';
  const { text, valid } = decodeText(rec.bytes, encoding);
  return {
    caption: `Decoded as ${encoding.toUpperCase()}${valid ? '' : '. Contains invalid byte sequences (shown as �), try Hex'}`,
    el: pre(text),
    copy: text,
  };
}

function viewAscii(rec) {
  const ascii = toAscii(rec.bytes);
  return { caption: 'Printable ASCII. Other bytes are shown as ·', el: pre(ascii), copy: ascii };
}

function viewHex(rec) {
  const extra = HEX_NOTES[rec.recordType];
  return {
    caption: `${formatBytes(rec.bytes.length)}${extra ? `. ${extra}` : ''}`,
    el: hexBlock(rec.bytes),
    copy: toHex(rec.bytes),
  };
}

function viewBase64(rec) {
  const { text } = decodeText(rec.bytes);
  const res = decodeBase64(text.trim());
  if (!res.ok) {
    return { el: note('error', `The payload is not valid Base64 (${res.error}).`), copy: null };
  }
  const inner = analyze(res.bytes);
  const view = viewAnalysis(inner);
  return {
    caption: `Decoded from ${res.variant === 'base64url' ? 'Base64url' : 'Base64'} → ${formatBytes(res.bytes.length)} · ${analysisLabel(inner)}`,
    el: h('div', { class: 'stack' },
      view.el,
      inner.kind !== 'binary' && h('details', { class: 'more' },
        h('summary', {}, 'Show decoded bytes as hex'), hexBlock(res.bytes))),
    copy: view.copy,
  };
}

/* --------------------------------------------------------- smart views */

const TEXT_CLAIMS = { iss: 'Issuer', sub: 'Subject', aud: 'Audience', vct: 'Credential type', jti: 'Token ID' };
const TIME_CLAIMS = { iat: 'Issued', nbf: 'Not before', exp: 'Expires' };

function claimsSummary(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
  const rows = [];
  for (const [key, label] of Object.entries(TEXT_CLAIMS)) {
    const v = payload[key];
    if (v != null) rows.push([label, Array.isArray(v) ? v.join(', ') : typeof v === 'object' ? JSON.stringify(v) : String(v)]);
  }
  const now = Date.now() / 1000;
  for (const [key, label] of Object.entries(TIME_CLAIMS)) {
    const v = payload[key];
    if (typeof v !== 'number') continue;
    let badge = null;
    if (key === 'exp') badge = v < now ? ['bad', 'expired'] : ['good', 'not expired'];
    if (key === 'nbf' && v > now) badge = ['bad', 'not yet valid'];
    rows.push([label, h('span', {}, new Date(v * 1000).toLocaleString(),
      badge && h('span', { class: `badge badge-${badge[0]}` }, badge[1]))]);
  }
  if (!rows.length) return null;
  return h('dl', { class: 'kv' }, rows.map(([dt, dd]) => [h('dt', {}, dt), h('dd', {}, dd)]));
}

function disclosureList(list) {
  if (!list.length) return h('p', { class: 'muted' }, 'No disclosures attached.');
  return h('div', { class: 'stack' }, list.map((d) => (d.invalid
    ? h('div', { class: 'stack' }, note('error', 'Could not decode this disclosure.'), pre(d.raw))
    : h('div', { class: 'disclosure' },
      h('div', { class: 'disclosure-name' }, d.name ?? '(array element)'),
      d.value !== null && typeof d.value === 'object' && !isRawJson(d.value)
        ? jsonTree(d.value)
        : h('div', { class: 'json' }, primitive(d.value))))));
}

function viewJwt(a) {
  const isSd = a.kind === 'sd-jwt';
  const parts = [
    note('info', 'Decoded only. The signature is not verified.'),
    claimsSummary(a.payload),
    section('Header', jsonTree(a.header)),
    section('Payload', a.payload !== undefined ? jsonTree(a.payload) : pre(a.payloadText)),
  ];
  if (isSd) parts.push(section(`Disclosures (${a.disclosures.length})`, disclosureList(a.disclosures)));
  parts.push(section('Signature',
    h('p', { class: 'caption' }, `${a.header.alg} · ${formatBytes(a.signature.length)}`),
    hexBlock(a.signature)));
  if (isSd && a.keyBinding) {
    parts.push(section('Key-binding JWT', jsonTree({
      header: a.keyBinding.header,
      payload: a.keyBinding.payload ?? a.keyBinding.payloadText,
    })));
  }
  return { el: h('div', { class: 'stack' }, parts), copy: a.raw };
}

function viewAnalysis(a) {
  switch (a.kind) {
    case 'json':
      return { el: jsonTree(a.value), copy: JSON.stringify(a.value, null, 2) };
    case 'jwt':
    case 'sd-jwt':
      return viewJwt(a);
    case 'jwe':
      return {
        el: h('div', { class: 'stack' },
          note('info', 'Encrypted token (JWE). Only the header is readable. The payload needs the recipient\'s private key.'),
          section('Protected header', jsonTree(a.header))),
        copy: a.raw,
      };
    case 'base64':
    case 'data-url': {
      const inner = viewAnalysis(a.inner);
      const label = a.kind === 'base64'
        ? `Decoded from ${a.variant === 'base64url' ? 'Base64url' : 'Base64'}`
        : `Data URL · ${a.mediaType}${a.base64 ? ' · Base64' : ''}`;
      return {
        caption: `${label} → ${formatBytes(a.bytes.length)}${inner.caption ? ` · ${inner.caption}` : ''}`,
        el: inner.el,
        copy: inner.copy,
      };
    }
    case 'invalid-json':
      return {
        el: h('div', { class: 'stack' }, note('error', `Declared as JSON but could not be parsed: ${a.error}`), pre(a.text)),
        copy: a.text,
      };
    case 'text':
      return { el: pre(a.text), copy: a.text };
    case 'binary':
      return { caption: `${formatBytes(a.bytes.length)} of binary data`, el: hexBlock(a.bytes), copy: toHex(a.bytes) };
    default:
      return { el: h('p', { class: 'muted' }, 'No payload.'), copy: null };
  }
}

function viewUrl(rec) {
  const { text } = decodeText(rec.bytes);
  let url = null;
  try { url = new URL(text); } catch { /* not a parseable URL */ }
  const openable = url && (url.protocol === 'https:' || url.protocol === 'http:');

  const rows = [];
  if (url) {
    rows.push(['Scheme', url.protocol.replace(/:$/, '')]);
    if (url.host) rows.push(['Host', url.host]);
    if (url.pathname && url.pathname !== '/') rows.push(['Path', safeDecodeURI(url.pathname)]);
    for (const [k, v] of url.searchParams) rows.push([`?${k}`, v]);
    if (url.hash) rows.push(['Fragment', safeDecodeURI(url.hash.slice(1))]);
  }

  // A button instead of an <a>: browsers may preconnect to a link's host as soon as it is
  // touched. With a button, nothing is contacted until the user explicitly opens it.
  const openBtn = openable && h('button', {
    class: 'btn btn-small btn-open',
    type: 'button',
    onclick: () => window.open(url.href, '_blank', 'noopener,noreferrer'),
  }, 'Open link ↗');

  return {
    caption: openable ? 'Opening the link leaves this page and contacts that server.' : null,
    el: h('div', { class: 'stack' },
      h('code', { class: 'url-link' }, text),
      openBtn,
      rows.length > 0 && h('dl', { class: 'kv' }, rows.map(([dt, dd]) => [h('dt', {}, dt), h('dd', {}, dd)]))),
    copy: text,
  };
}

/* ------------------------------------------------------------- records */

const VIEW_LABELS = { decoded: 'Decoded', text: 'Text', ascii: 'ASCII', hex: 'Hex', base64: 'Base64' };
const SMART_KINDS = new Set(['json', 'jwt', 'sd-jwt', 'jwe', 'base64', 'data-url', 'invalid-json']);

function renderRecord(rec, label) {
  const info = recordTypeInfo(rec);
  const isEmpty = rec.recordType === 'empty' || rec.bytes.length === 0;
  const analysis = isEmpty
    ? { kind: 'empty' }
    : analyze(rec.bytes, {
      encoding: rec.recordType === 'text' && rec.encoding ? rec.encoding : 'utf-8',
      mediaType: rec.mediaType || '',
    });
  const smart = SMART_KINDS.has(analysis.kind);

  const meta = [info.tnf];
  if (rec.mediaType) meta.push(rec.mediaType);
  if (rec.lang) meta.push(`lang ${rec.lang}`);
  if (rec.encoding) meta.push(rec.encoding);
  if (rec.id) meta.push(`id ${rec.id}`);

  const card = h('article', { class: 'record' },
    h('header', { class: 'record-head' },
      h('span', { class: 'record-index' }, `#${label}`),
      h('span', { class: 'chip' }, info.label),
      smart && h('span', { class: 'chip chip-accent' }, analysisLabel(analysis)),
      h('span', { class: 'record-size' }, formatBytes(rec.bytes.length))),
    h('p', { class: 'record-meta' }, meta.join(' · ')));

  if (isEmpty) {
    card.append(h('p', { class: 'muted' }, 'This record has no payload.'));
  } else {
    const viewFns = {
      decoded: () => (isUrlRecord(rec) ? viewUrl(rec) : viewAnalysis(analysis)),
      text: () => viewText(rec),
      ascii: () => viewAscii(rec),
      hex: () => viewHex(rec),
      base64: () => viewBase64(rec),
    };
    const views = [...(isUrlRecord(rec) || smart ? ['decoded'] : []), 'text', 'ascii', 'hex', 'base64'];
    // "Base64 → Binary" is only a guess, so plain text stays the default view there.
    const weakGuess = analysis.kind === 'base64' && analysis.inner.kind === 'binary';
    let initial = analysis.kind === 'binary' ? 'hex' : 'text';
    if (views[0] === 'decoded' && !weakGuess) initial = 'decoded';

    const tabs = h('div', { class: 'tabs', role: 'tablist', 'aria-label': 'Payload view' });
    const caption = h('p', { class: 'caption' });
    const copyBtn = h('button', { class: 'btn btn-small', type: 'button' }, 'Copy');
    const body = h('div', { class: 'view-body', role: 'tabpanel' });
    let copyText = null;

    const show = (name) => {
      const view = viewFns[name]();
      copyText = view.copy;
      caption.textContent = view.caption || '';
      copyBtn.hidden = !view.copy;
      body.replaceChildren(view.el);
      for (const tab of tabs.children) tab.setAttribute('aria-selected', String(tab.dataset.view === name));
    };

    for (const name of views) {
      tabs.append(h('button', { class: 'tab', type: 'button', role: 'tab', 'data-view': name, onclick: () => show(name) }, VIEW_LABELS[name]));
    }
    copyBtn.addEventListener('click', () => copyToClipboard(copyText, copyBtn));

    card.append(tabs, h('div', { class: 'view-bar' }, caption, copyBtn), body);
    show(initial);
  }

  if (rec.children?.length) {
    card.append(h('div', { class: 'nested' },
      h('p', { class: 'nested-title' }, `Contains ${plural(rec.children.length, 'nested record')}`),
      rec.children.map((child, i) => renderRecord(child, `${label}.${i + 1}`))));
  }
  return card;
}

export function renderScan(scan) {
  const n = scan.records.length;
  return h('details', { class: 'card scan', open: true },
    h('summary', { class: 'scan-head' },
      h('span', { class: 'scan-title' }, scan.sample ? 'Sample data' : 'NFC tag'),
      scan.serialNumber && h('code', { class: 'serial', title: 'Serial number' }, scan.serialNumber.toUpperCase()),
      h('span', { class: 'scan-meta' }, `${plural(n, 'record')} · ${scan.time.toLocaleTimeString()}`)),
    h('div', { class: 'scan-body' },
      n
        ? scan.records.map((rec, i) => renderRecord(rec, String(i + 1)))
        : h('p', { class: 'muted' }, 'The tag contains an empty NDEF message.')));
}
