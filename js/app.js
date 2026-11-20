import { detectEnvironment } from './env.js';
import { normalizeRecord } from './decode.js';
import { h, renderScan, copyToClipboard } from './render.js';
import { buildSampleScan } from './samples.js';

const MAX_SCANS = 20;
const env = detectEnvironment();

const $ = (id) => document.getElementById(id);
const ui = {
  notice: $('env-notice'),
  scanner: $('scanner'),
  scanBtn: $('scan-btn'),
  scanLabel: $('scan-label'),
  status: $('scan-status'),
  sampleBtn: $('sample-btn'),
  clearBtn: $('clear-btn'),
  results: $('results'),
  empty: $('empty-state'),
  deviceInfo: $('device-info'),
};

let reader = null;
let controller = null;
let scanning = false;
let starting = false;

/* ---------------------------------------------------------------- UI bits */

function showNotice(tone, title, ...content) {
  ui.notice.className = `notice notice-${tone}`;
  ui.notice.replaceChildren(
    h('strong', { class: 'notice-title' }, title),
    ...content.map((c) => (typeof c === 'string' ? h('p', {}, c) : c)),
  );
  ui.notice.hidden = false;
}

function setStatus(text, tone = '') {
  ui.status.textContent = text;
  if (tone) ui.status.dataset.tone = tone;
  else delete ui.status.dataset.tone;
}

function setScanning(active) {
  scanning = active;
  ui.scanner.classList.toggle('is-scanning', active);
  ui.scanBtn.setAttribute('aria-pressed', String(active));
  ui.scanLabel.textContent = active ? 'Stop scanning' : 'Start scanning';
}

function pageLinkBox() {
  const url = location.href.split('#')[0];
  const btn = h('button', { class: 'btn btn-small', type: 'button' }, 'Copy link');
  btn.addEventListener('click', () => copyToClipboard(url, btn));
  return h('div', { class: 'url-box' }, h('code', {}, url), btn);
}

function addScan(scan) {
  for (const el of ui.results.querySelectorAll('details.scan')) el.open = false;
  ui.results.prepend(renderScan(scan));
  while (ui.results.children.length > MAX_SCANS) ui.results.lastElementChild.remove();
  ui.empty.hidden = true;
  ui.clearBtn.hidden = false;
}

/* ---------------------------------------------------- environment check */

/** Show the right warning for this device. Returns true if NFC scanning can be offered. */
function checkSupport() {
  if (env.isIOS) {
    showNotice('error', `NFC reading isn't possible on ${env.device}`,
      'Apple does not let websites use the NFC chip. This applies to Safari, Chrome, Firefox and every other iOS browser, because they all have to run on Apple\'s WebKit engine.',
      'Please open this page on an Android phone with Chrome. You can still try the viewer with sample data.');
    return false;
  }
  if (env.hasWebNfc) return true;

  if (env.isAndroid && !env.isSecure) {
    showNotice('error', 'Secure connection required',
      'Web NFC only works on pages served over HTTPS (or from localhost). Open this page via its https:// address.');
    return false;
  }
  if (env.isWebView) {
    showNotice('warn', 'Open this page in Chrome',
      'You\'re in an in-app browser, which can\'t read NFC tags. Use the menu to open the page in Chrome, or copy the link:',
      pageLinkBox());
    return false;
  }
  if (env.isAndroid) {
    showNotice('warn', 'This browser can\'t read NFC tags',
      'Open this page in Chrome for Android (version 89 or newer). Other browsers, for example Firefox, don\'t support Web NFC.',
      pageLinkBox());
    return false;
  }
  if (env.isMobile) {
    showNotice('warn', 'NFC reading isn\'t available here',
      'Reading NFC tags from a website only works with Chrome on an Android phone.', pageLinkBox());
    return false;
  }
  showNotice('warn', 'This only works on a phone',
    'You\'re using a desktop browser. Websites can only read NFC tags with Chrome on an Android phone. Open this link there:',
    pageLinkBox(),
    'Meanwhile you can explore the viewer with sample data.');
  return false;
}

/* ------------------------------------------------------------- scanning */

function scanErrorMessage(err) {
  switch (err?.name) {
    case 'NotAllowedError':
      return 'NFC permission was denied. Allow NFC for this site (tap the icon left of the address bar, then Permissions) and try again.';
    case 'NotSupportedError':
      return 'This device has no NFC hardware that the browser can use.';
    case 'NotReadableError':
      return 'Could not access NFC. Make sure NFC is switched on in your phone settings, then try again.';
    case 'AbortError':
      return 'Scanning stopped.';
    default:
      return `Could not start scanning: ${err?.message || err}`;
  }
}

function onReading(event) {
  try {
    const records = Array.from(event.message?.records ?? [], (r) => normalizeRecord(r));
    addScan({ time: new Date(), serialNumber: event.serialNumber || '', records });
    navigator.vibrate?.(60);
    setStatus(`Read ${records.length} record${records.length === 1 ? '' : 's'}. Hold another tag to read it too.`, 'ok');
  } catch (err) {
    setStatus(`Tag read, but it could not be displayed: ${err.message}`, 'error');
  }
}

async function startScan() {
  starting = true;
  if (!reader) {
    reader = new NDEFReader();
    reader.addEventListener('reading', onReading);
    reader.addEventListener('readingerror', () => setStatus(
      'A tag was detected but could not be read. It may be empty, not NDEF-formatted, or an unsupported tag type.', 'error'));
  }
  controller = new AbortController();
  setStatus('Starting NFC…');
  try {
    await reader.scan({ signal: controller.signal });
    setScanning(true);
    setStatus('Scanning. Hold a tag against the back of your phone.');
  } catch (err) {
    controller = null;
    setScanning(false);
    setStatus(scanErrorMessage(err), 'error');
  } finally {
    starting = false;
  }
}

function stopScan() {
  controller?.abort();
  controller = null;
  setScanning(false);
  setStatus('Scanning stopped. Tap the button to start again.');
}

/** If NFC permission was granted before, start right away (no tap needed). */
async function autoStartIfPermitted() {
  try {
    const status = await navigator.permissions.query({ name: 'nfc' });
    if (status.state === 'granted' && !scanning && !starting) startScan();
  } catch {
    /* permission name not supported */
  }
}

/* ----------------------------------------------------------------- init */

ui.deviceInfo.textContent = [
  `Detected: ${env.device}`,
  env.hasWebNfc ? 'Web NFC available' : 'no Web NFC',
  env.isSecure ? 'secure context' : 'not a secure context',
].join(' · ');

ui.sampleBtn.addEventListener('click', () => addScan(buildSampleScan()));
ui.clearBtn.addEventListener('click', () => {
  ui.results.replaceChildren();
  ui.empty.hidden = false;
  ui.clearBtn.hidden = true;
});

if (checkSupport()) {
  ui.scanBtn.disabled = false;
  ui.scanBtn.addEventListener('click', () => {
    if (starting) return;
    if (scanning) stopScan();
    else startScan();
  });
  setStatus('Tap the button, then hold an NFC tag to the back of your phone.');
  autoStartIfPermitted();
} else {
  ui.scanBtn.disabled = true;
  ui.sampleBtn.classList.add('btn-primary');
  setStatus('NFC scanning is not available on this device.');
}
