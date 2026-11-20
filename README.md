# NFC DPP Viewer

A small static web page that reads NFC tags (NDEF) with the [Web NFC API](https://w3c.github.io/web-nfc/) and shows every record in several views:

- **Decoded**: smart view, picked automatically:
  - JSON → collapsible tree
  - JWT / SD-JWT / JWE → header, payload, claims (iat/exp/nbf as dates), disclosures, signature (decoded only, **not verified**)
  - Base64 / Base64url / `data:` URLs → decoded and inspected again (e.g. Base64 → JSON or Base64 → JWT)
  - URL records → link plus a breakdown of host, path and query
- **Text**: UTF-8 (or the text record's own encoding)
- **ASCII**: printable characters, other bytes shown as `·`
- **Hex**: offset + hex dump
- **Base64**: the payload decoded from Base64

## Privacy

Everything runs in the browser. There is no backend, no analytics and no external scripts, fonts or images. The page's Content-Security-Policy sets `connect-src 'none'`, so the page can't send scanned data anywhere.

## Supported devices

| Device | Works? |
| --- | --- |
| Android + Chrome 89+ | ✅ (HTTPS required, NFC switched on) |
| iPhone / iPad (any browser) | ❌ Apple doesn't expose NFC to websites |
| Desktop browsers | ❌ |

The page detects the device and shows a matching hint. The **Try with sample data** button works everywhere, so the viewer can be checked on a desktop too.

Note: Web NFC gives the page each record's payload already parsed. URL prefixes are expanded, and the text record's status byte and language code are removed. So the hex view shows the payload, not the raw bytes on the chip.

## Run locally

ES modules don't load from `file://`, so serve the folder:

```sh
python3 -m http.server 8080
# open http://localhost:8080
```

Testing on a phone requires HTTPS (or `localhost`):

- **GitHub Pages**: push to `main` and enable Pages (branch `main`, folder `/`).
- **Tailscale**: `tailscale serve --bg 8080` gives an HTTPS `*.ts.net` URL that only your tailnet can reach.
- **USB**: `adb reverse tcp:8080 tcp:8080`, then open `http://localhost:8080` in Chrome on the phone.

## Structure

```
index.html        page + CSP
css/style.css     styles (light/dark)
js/app.js         device check, scanning, wiring
js/env.js         device/browser detection
js/decode.js      pure decoders (hex, ASCII, Base64, JSON, JWT, SD-JWT, …)
js/render.js      DOM rendering (text nodes only, never innerHTML)
js/samples.js     sample tag for testing without NFC
```
