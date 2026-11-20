/**
 * Sample scan so the viewer can be tried on any device (desktop, iPhone…).
 * All values are fake. Tokens carry random bytes instead of real signatures.
 */
import { utf8, encodeBase64 } from './decode.js';

const b64url = (data) => encodeBase64(typeof data === 'string' ? utf8(data) : data, { url: true });
const randomBytes = (n) => crypto.getRandomValues(new Uint8Array(n));

const rec = (recordType, bytes, extra = {}) => ({
  recordType, mediaType: null, id: null, encoding: null, lang: null, bytes, children: null, ...extra,
});
const textRec = (text, lang = 'en') => rec('text', utf8(text), { encoding: 'utf-8', lang });
const urlRec = (url) => rec('url', utf8(url));
const mimeRec = (mediaType, bytes) => rec('mime', bytes, { mediaType });

/** Minimal NDEF encoder (short records only), to give the smart poster realistic raw bytes. */
function encodeNdef(records) {
  const out = [];
  records.forEach((r, i) => {
    const type = utf8(r.type);
    let header = 0x10 | (r.tnf & 0x07); // SR (short record) + TNF
    if (i === 0) header |= 0x80; // MB (message begin)
    if (i === records.length - 1) header |= 0x40; // ME (message end)
    out.push(header, type.length, r.payload.length, ...type, ...r.payload);
  });
  return new Uint8Array(out);
}

export function buildSampleScan() {
  const now = Math.floor(Date.now() / 1000);

  const passport = {
    '@context': 'https://example.com/dpp/v1',
    type: 'DigitalProductPassport',
    id: 'urn:example:dpp:4711',
    product: { name: 'Aluminium Water Bottle 0.75 l', gtin: '09506000134352', batch: 'LOT42', manufacturer: 'Example GmbH' },
    materials: [
      { name: 'Aluminium', share: 0.92, recycled: true },
      { name: 'Silicone', share: 0.08, recycled: false },
    ],
    carbonFootprintKgCO2e: 2.7,
    repairable: true,
    endOfLife: null,
  };

  const jwt = [
    b64url(JSON.stringify({ alg: 'ES256', typ: 'JWT', kid: 'demo-key-1' })),
    b64url(JSON.stringify({
      iss: 'https://issuer.example.com',
      sub: 'urn:example:dpp:4711',
      iat: now - 86400,
      exp: now + 30 * 86400,
      product: { gtin: '09506000134352', batch: 'LOT42' },
    })),
    b64url(randomBytes(64)),
  ].join('.');

  const disclosures = [
    [b64url(randomBytes(16)), 'material', 'recycled aluminium'],
    [b64url(randomBytes(16)), 'carbon_footprint_kg', 2.7],
  ].map((d) => b64url(JSON.stringify(d)));
  const sdJwt = `${[
    b64url(JSON.stringify({ alg: 'ES256', typ: 'dc+sd-jwt' })),
    b64url(JSON.stringify({
      iss: 'https://issuer.example.com',
      iat: now - 2 * 86400,
      exp: now - 86400,
      vct: 'https://example.com/credentials/dpp',
      _sd_alg: 'sha-256',
      _sd: [b64url(randomBytes(32)), b64url(randomBytes(32))],
    })),
    b64url(randomBytes(64)),
  ].join('.')}~${disclosures.join('~')}~`;

  const posterUrl = 'https://example.com/dpp/4711';
  const posterTitle = 'Product passport';
  const smartPosterBytes = encodeNdef([
    { tnf: 1, type: 'U', payload: [0x04, ...utf8(posterUrl.replace('https://', ''))] },
    { tnf: 1, type: 'T', payload: [0x02, ...utf8('en'), ...utf8(posterTitle)] },
  ]);

  // CBOR: {1: "09506000134352", 2: "LOT42", 3: true}
  const cbor = Uint8Array.of(0xa3, 0x01, 0x6e, ...utf8('09506000134352'), 0x02, 0x65, ...utf8('LOT42'), 0x03, 0xf5);

  return {
    sample: true,
    time: new Date(),
    serialNumber: '04:a2:5b:1c:7e:61:80',
    records: [
      urlRec('https://id.example.com/01/09506000134352/10/LOT42/21/SN12345?linkType=gs1:dpp'),
      textRec('Hello from an NFC tag 👋'),
      mimeRec('application/json', utf8(JSON.stringify(passport))),
      textRec(encodeBase64(utf8(JSON.stringify({ id: passport.id, gtin: passport.product.gtin, recyclable: true })))),
      mimeRec('application/jwt', utf8(jwt)),
      textRec(sdJwt),
      rec('smart-poster', smartPosterBytes, { children: [urlRec(posterUrl), textRec(posterTitle)] }),
      rec('example.com:dpp', cbor),
    ],
  };
}
