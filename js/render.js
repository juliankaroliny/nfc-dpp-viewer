/**
 * DOM rendering of scans and records.
 *
 * Security: tag content is only ever inserted as text nodes (never via
 * innerHTML), and nothing is opened or contacted unless the user taps "Open link".
 */
import {
  analyze, analysisLabel, recordTypeInfo, recordEncoding, decodeText, decodeBase64,
  toAscii, toHex, hexRows, isRawJson,
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

let uid = 0;
const nextId = (prefix) => `${prefix}-${++uid}`;

/** Polite screen-reader announcement via a visually hidden live region. */
export function announce(text) {
  const region = document.getElementById('announcer');
  if (!region) return;
  region.textContent = '';
  // Set on the next frame so that repeating the same message is announced again.
  requestAnimationFrame(() => { region.textContent = text; });
}

export async function copyToClipboard(text, button) {
  button.dataset.label ??= button.textContent;
  let message;
  try {
    await navigator.clipboard.writeText(text);
    message = 'Copied';
  } catch {
    message = 'Copy failed';
  }
  button.textContent = message;
  announce(message);
  clearTimeout(button._resetTimer);
  button._resetTimer = setTimeout(() => { button.textContent = button.dataset.label; }, 1400);
}

const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
const formatBytes = (n) => plural(n, 'byte');
const pre = (text) => h('pre', { class: 'code' }, text);
const note = (text) => h('p', { class: 'note' }, text);
const isUrlRecord = (rec) => rec.recordType === 'url' || rec.recordType === 'absolute-url';

/** A titled block; `collapsed` ones start closed (for secondary detail like headers/signatures). */
function section(title, content, { collapsed = false } = {}) {
  return collapsed
    ? h('details', { class: 'sub' }, h('summary', { class: 'sub-title' }, title), content)
    : h('section', { class: 'sub' }, h('h3', { class: 'sub-title' }, title), content);
}

function safeDecodeURI(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}

function validLang(tag) {
  if (!tag) return null;
  try { return Intl.getCanonicalLocales(tag)[0] ?? null; } catch { return null; }
}

/* ------------------------------------------------------------- JSON tree */

const OPEN_DEPTH = 3;

function primitive(value) {
  if (isRawJson(value)) return h('span', { class: 'j-num' }, value.rawJSON); // big integer, verbatim
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

  // Children are only built when a node is first opened, so huge or deeply nested JSON stays fast.
  const children = h('div', { class: 'j-children' });
  const fill = () => {
    if (children.firstChild) return;
    for (const [k, v] of entries) children.append(jsonNode(k, v, depth + 1));
  };
  const node = h('details', { class: 'j-node' },
    h('summary', {},
      keyEl,
      h('span', { class: 'j-punct' }, open),
      h('span', { class: 'j-punct j-ellipsis' }, ` … ${close}`),
      h('span', { class: 'j-count' }, plural(entries.length, isArray ? 'item' : 'key'))),
    children,
    h('div', { class: 'j-punct j-close' }, close));

  if (depth < OPEN_DEPTH) {
    fill();
    node.open = true;
  } else {
    node.addEventListener('toggle', fill);
  }
  return node;
}

function jsonTree(value) {
  return h('div', { class: 'json' }, jsonNode(undefined, value, 0));
}

/* ------------------------------------------------------------ byte views */

function hexBlock(bytes) {
  if (!bytes.length) return h('p', { class: 'muted' }, 'No bytes.');
  const perRow = window.matchMedia('(min-width: 640px)').matches ? 16 : 8;
  return h('div', { class: 'code hex', role: 'group', 'aria-label': `Hex dump, ${formatBytes(bytes.length)}` },
    hexRows(bytes, perRow).map((row) => h('div', { class: 'hex-row' },
      h('span', { class: 'hex-off', 'aria-hidden': 'true' }, row.offset), h('span', {}, row.hex))));
}

const HEX_NOTES = {
  text: 'Web NFC already removed the status byte and language code.',
  url: 'Web NFC already expanded the URI prefix byte (e.g. 0x04 → "https://").',
};

function viewText(rec) {
  const encoding = recordEncoding(rec);
  const { text, valid } = decodeText(rec.bytes, encoding);
  const el = pre(text);
  const lang = rec.recordType === 'text' && validLang(rec.lang);
  if (lang) el.lang = lang;
  let caption = null;
  if (!valid) caption = `Not valid ${encoding.toUpperCase()}. Invalid bytes are shown as �, try Hex.`;
  else if (!/^utf-?8$/i.test(encoding)) caption = `Decoded as ${encoding.toUpperCase()}`;
  return { caption, el, copy: text };
}

function viewAscii(rec) {
  const ascii = toAscii(rec.bytes);
  return { caption: 'Non-printable bytes are shown as ·', el: pre(ascii), copy: ascii };
}

function viewHex(rec) {
  return { caption: HEX_NOTES[rec.recordType] ?? null, el: hexBlock(rec.bytes), copy: toHex(rec.bytes) };
}

function viewBase64(rec) {
  const { text } = decodeText(rec.bytes, recordEncoding(rec));
  const res = decodeBase64(text.trim());
  if (!res.ok) {
    return { el: note(`The payload is not valid Base64 (${res.error}).`), copy: null };
  }
  const inner = analyze(res.bytes);
  const view = viewAnalysis(inner);
  return {
    caption: `Decoded from ${res.variant === 'base64url' ? 'Base64url' : 'Base64'} → ${formatBytes(res.bytes.length)} · ${analysisLabel(inner)}`,
    el: h('div', { class: 'stack' },
      view.el,
      inner.kind !== 'binary' && h('details', { class: 'more' },
        h('summary', {}, 'Decoded bytes as hex'), hexBlock(res.bytes))),
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
      badge && [' ', h('span', { class: `badge badge-${badge[0]}` }, badge[1])])]);
  }
  if (!rows.length) return null;
  return h('dl', { class: 'kv' }, rows.map(([dt, dd]) => [h('dt', {}, dt), h('dd', {}, dd)]));
}

function disclosureList(list) {
  if (!list.length) return h('p', { class: 'muted' }, 'No disclosures attached.');
  return h('div', { class: 'stack' }, list.map((d) => (d.invalid
    ? h('div', { class: 'stack' }, note('Could not decode this disclosure.'), pre(d.raw))
    : h('div', { class: 'disclosure' },
      h('div', { class: 'disclosure-name' }, d.name ?? '(array element)'),
      d.value !== null && typeof d.value === 'object' && !isRawJson(d.value)
        ? jsonTree(d.value)
        : h('div', { class: 'json' }, primitive(d.value))))));
}

function viewJwt(a) {
  const isSd = a.kind === 'sd-jwt';
  const kb = isSd && a.keyBinding;
  return {
    caption: 'Decoded only. The signature is not verified.',
    el: h('div', { class: 'stack' },
      claimsSummary(a.payload),
      section('Payload', a.payload !== undefined ? jsonTree(a.payload) : pre(a.payloadText)),
      isSd && section(`Disclosures (${a.disclosures.length})`, disclosureList(a.disclosures)),
      section('Header', jsonTree(a.header), { collapsed: true }),
      section(`Signature · ${a.header.alg} · ${formatBytes(a.signature.length)}`, hexBlock(a.signature), { collapsed: true }),
      kb && section('Key-binding JWT', jsonTree({ header: kb.header, payload: kb.payload ?? kb.payloadText }), { collapsed: true })),
    copy: a.raw,
  };
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
        caption: 'Encrypted token (JWE). Only the header is readable.',
        el: section('Protected header', jsonTree(a.header)),
        copy: a.raw,
      };
    case 'base64':
    case 'data-url': {
      const inner = viewAnalysis(a.inner);
      const label = a.kind === 'base64'
        ? `Decoded from ${a.variant === 'base64url' ? 'Base64url' : 'Base64'}`
        : `Data URL · ${a.mediaType}${a.base64 ? ' · Base64' : ''}`;
      return {
        caption: `${label} → ${formatBytes(a.bytes.length)}${inner.caption ? `. ${inner.caption}` : ''}`,
        el: inner.el,
        copy: inner.copy,
      };
    }
    case 'invalid-json':
      return {
        el: h('div', { class: 'stack' }, note(`Declared as JSON but could not be parsed: ${a.error}`), pre(a.text)),
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
  return {
    caption: openable ? 'Opening the link leaves this page and contacts that server.' : null,
    el: h('div', { class: 'stack' },
      h('code', { class: 'url-link' }, text),
      openable && h('button', {
        class: 'btn btn-small btn-open',
        type: 'button',
        onclick: () => window.open(url.href, '_blank', 'noopener,noreferrer'),
      }, 'Open link ', h('span', { 'aria-hidden': 'true' }, '↗')),
      rows.length > 0 && h('dl', { class: 'kv' }, rows.map(([dt, dd]) => [h('dt', {}, dt), h('dd', {}, dd)]))),
    copy: text,
  };
}

/* ------------------------------------------------------------- records */

const VIEW_LABELS = { decoded: 'Decoded', text: 'Text', ascii: 'ASCII', hex: 'Hex', base64: 'Base64' };
const SMART_KINDS = new Set(['json', 'jwt', 'sd-jwt', 'jwe', 'base64', 'data-url', 'invalid-json']);

function renderRecord(rec, label, level) {
  const info = recordTypeInfo(rec);
  const isEmpty = rec.recordType === 'empty' || rec.bytes.length === 0;
  const analysis = isEmpty
    ? { kind: 'empty' }
    : analyze(rec.bytes, { encoding: recordEncoding(rec), mediaType: rec.mediaType || '' });
  const smart = SMART_KINDS.has(analysis.kind);
  // "Base64 → Binary" is only a guess, so it never becomes the default view.
  const weakGuess = analysis.kind === 'base64' && analysis.inner.kind === 'binary';

  const meta = [formatBytes(rec.bytes.length)];
  if (info.detail) meta.push(info.detail);
  if (rec.mediaType) meta.push(rec.mediaType);
  if (rec.lang) meta.push(rec.lang);
  if (rec.encoding && !/^utf-?8$/i.test(rec.encoding)) meta.push(rec.encoding);
  if (rec.id) meta.push(`id ${rec.id}`);

  const copyBtn = h('button', { class: 'btn btn-small', type: 'button', hidden: true }, 'Copy');
  const card = h('article', { class: 'record' },
    h('header', { class: 'record-head' },
      h(`h${level}`, { class: 'record-title', title: info.tnf },
        h('span', { class: 'record-index' }, `#${label}`), ' ', info.label),
      smart && h('span', { class: 'chip' }, analysisLabel(analysis)),
      h('span', { class: 'record-meta' }, meta.join(' · ')),
      !isEmpty && copyBtn));

  if (isEmpty) {
    card.append(h('p', { class: 'muted' }, 'No payload.'));
  } else {
    // URL records holding e.g. a data: URL get the smart view instead of the link breakdown.
    const viewFns = {
      decoded: () => (isUrlRecord(rec) && !smart ? viewUrl(rec) : viewAnalysis(analysis)),
      text: () => viewText(rec),
      ascii: () => viewAscii(rec),
      hex: () => viewHex(rec),
      base64: () => viewBase64(rec),
    };
    const views = [...(isUrlRecord(rec) || smart ? ['decoded'] : []), 'text', 'ascii', 'hex', 'base64'];
    let initial = analysis.kind === 'binary' ? 'hex' : 'text';
    if (views[0] === 'decoded' && !weakGuess) initial = 'decoded';

    const panelId = nextId('panel');
    const caption = h('p', { class: 'caption', hidden: true });
    const body = h('div', { class: 'view-body', role: 'tabpanel', id: panelId, tabindex: '0' });
    const tabs = views.map((name) => h('button', {
      class: 'tab', type: 'button', role: 'tab', id: nextId('tab'), 'aria-controls': panelId, 'data-view': name,
    }, VIEW_LABELS[name]));
    const tablist = h('div', { class: 'tabs', role: 'tablist', 'aria-label': `Views of record ${label}` }, tabs);
    let copyText = null;

    const show = (name) => {
      const view = viewFns[name]();
      copyText = view.copy;
      caption.textContent = view.caption || '';
      caption.hidden = !view.caption;
      copyBtn.hidden = !view.copy;
      copyBtn.setAttribute('aria-label', `Copy ${VIEW_LABELS[name]} view of record ${label}`);
      body.replaceChildren(view.el);
      for (const tab of tabs) {
        const selected = tab.dataset.view === name;
        tab.setAttribute('aria-selected', String(selected));
        tab.tabIndex = selected ? 0 : -1;
        if (selected) body.setAttribute('aria-labelledby', tab.id);
      }
    };

    for (const tab of tabs) tab.addEventListener('click', () => show(tab.dataset.view));
    // Tabs pattern: one tab stop, arrow keys / Home / End move between tabs.
    tablist.addEventListener('keydown', (event) => {
      const i = tabs.indexOf(document.activeElement);
      const target = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: tabs.length - 1 }[event.key];
      if (i < 0 || target === undefined) return;
      event.preventDefault();
      const tab = tabs[(target + tabs.length) % tabs.length];
      show(tab.dataset.view);
      tab.focus();
    });
    copyBtn.addEventListener('click', () => copyToClipboard(copyText, copyBtn));

    card.append(tablist, caption, body);
    show(initial);
  }

  if (rec.children?.length) {
    card.append(h('div', { class: 'nested' },
      h('p', { class: 'nested-title' }, `Contains ${plural(rec.children.length, 'nested record')}`),
      rec.children.map((child, i) => safeRenderRecord(child, `${label}.${i + 1}`, Math.min(level + 1, 6)))));
  }
  return card;
}

/** One broken record must not take the whole scan down with it. */
function safeRenderRecord(rec, label, level = 2) {
  try {
    return renderRecord(rec, label, level);
  } catch (err) {
    return h('article', { class: 'record' },
      h('p', { class: 'note' }, `Record #${label} could not be displayed: ${err?.message || err}`));
  }
}

export function renderScan(scan) {
  const n = scan.records.length;
  return h('details', { class: 'card scan', open: true },
    h('summary', { class: 'scan-head' },
      h('span', { class: 'scan-title' }, scan.sample ? 'Sample data' : 'NFC tag'),
      h('span', { class: 'scan-meta' }, `${plural(n, 'record')} · ${scan.time.toLocaleTimeString()}`),
      scan.serialNumber && h('code', { class: 'serial', title: 'Serial number' }, scan.serialNumber.toUpperCase())),
    h('div', { class: 'scan-body' },
      n
        ? scan.records.map((rec, i) => safeRenderRecord(rec, String(i + 1)))
        : h('p', { class: 'muted' }, 'The tag contains an empty NDEF message.')));
}
