/**
 * Sample scan, so the viewer can be tried on any device (desktop, iPhone…).
 *
 * 1. URL record: the unique product identifier of OwnYourData's reference passport
 *    (a fictitious test lamp). It resolves: https://id.ownyourdata.eu answers with the
 *    passport as HTML or, with Accept: application/json, as JSON.
 * 2. JWT record: exactly the format the PSoC 6 demonstrator firmware (dpp-nfc-demo) signs:
 *    header {"alg":"EdDSA","typ":"JWT"}, the same credential JSON and an issuer
 *    did:oyd:z6Mk… derived from the signing key. It is signed with a throwaway demo key,
 *    not a device key: the signature is valid for the key in its own issuer DID, but that
 *    DID is not registered anywhere.
 */
import { utf8 } from './decode.js';

const PRODUCT_ID = 'https://id.ownyourdata.eu/01/09520123456788/21/TEST-SIG-0002';

const DEVICE_JWT = [
  'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHM',
  'vdjIiLCJodHRwczovL3czaWQub3JnL3NlY3VyaXR5L3N1aXRlcy9lZDI1NTE5LTIwMjAvdjEiLHsiQHZvY2FiIjoiaHR0cHM6Ly9',
  'zb3lhLm93bnlvdXJkYXRhLmV1L0RQUF9MZXVjaHRtaXR0ZWwvIn1dLCJpZCI6InVybjp1dWlkOjNmYTg1ZjY0LTU3MTctNDU2Mi1',
  'iM2ZjLTJjOTYzZjY2YWZhNiIsInR5cGUiOiJEaWdpdGFsUHJvZHVjdFBhc3Nwb3J0IiwiaXNzdWVyIjoiZGlkOm95ZDp6Nk1rcVJ',
  'DcmVaM0pZV0NUeHpNV0RSc1MzcWFROWlRaFV3WEQxNU1HWVdwVHlrMm0iLCJ2YWxpZEZyb20iOiIyMDI2LTA0LTA5IiwiY3JlZGV',
  'udGlhbFN1YmplY3QiOnsicHJvZHVjdCI6eyJtYW51ZmFjdHVyZXIiOiJIaWthcmkgTGlnaHRpbmcgR21iSCIsIm1vZGVsIjoiU0F',
  'MLTUwMDAiLCJzZXJpYWxOdW1iZXIiOiJTTjAwMDEiLCJtYW51ZmFjdHVyZURhdGUiOiIyMDI2LTAxLTAxIn0sIm9wZXJhdGlvbmF',
  'sU3RhdHVzIjp7InVwdGltZVNlY29uZHMiOjE2MDE0MCwibnVtYmVyT2ZPcGVyYXRpb25zIjoyMjV9LCJkcHBBY2Nlc3MiOnsicmV',
  'naXN0cnlMaW5rIjoiaHR0cHM6Ly9kcHAtcG9kLmdvLWRhdGEuYXQvb2JqZWN0LzI3MDEifX19.ycR2AUZaKUmkfM9wxCUY9uLK43',
  'd_Lr_Gw2OTosHETd0THEczWYQ_mcOuzzecsEbPjkpOAdfzM5y8UWMy_WrFDQ',
].join('');

const rec = (recordType, bytes, extra = {}) => ({
  recordType, mediaType: null, id: null, encoding: null, lang: null, bytes, children: null, ...extra,
});

export function buildSampleScan() {
  return {
    sample: true,
    time: new Date(),
    serialNumber: '04:a2:5b:1c:7e:61:80',
    records: [
      rec('url', utf8(PRODUCT_ID)),
      rec('mime', utf8(DEVICE_JWT), { mediaType: 'application/jwt' }),
    ],
  };
}
