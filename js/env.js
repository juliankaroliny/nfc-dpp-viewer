/**
 * Device / browser detection.
 *
 * Web NFC (NDEFReader) only exists in Chrome on Android, and only in secure
 * contexts (HTTPS or localhost). iOS never exposes it: every iOS browser is
 * built on Apple's WebKit, which has no Web NFC.
 */
export function detectEnvironment() {
  const ua = navigator.userAgent || '';
  const uaData = navigator.userAgentData; // Chromium only

  // iPadOS 13+ reports itself as "Macintosh", but real Macs have no touch screen.
  const isIPadOS = /Macintosh/.test(ua) && navigator.maxTouchPoints > 1;
  const isIOS = /iPhone|iPad|iPod/.test(ua) || isIPadOS;
  const isAndroid = uaData?.platform === 'Android' || /Android/i.test(ua);
  const isMobile = isIOS || isAndroid || uaData?.mobile === true || /Mobi/i.test(ua);

  let device = 'desktop';
  if (isIOS) device = /iPhone|iPod/.test(ua) ? 'iPhone' : /iPad/.test(ua) ? 'iPad' : 'iPhone or iPad';
  else if (isAndroid) device = 'Android';
  else if (isMobile) device = 'mobile';

  return {
    isIOS,
    isAndroid,
    isMobile,
    // Android in-app browsers (WebView: links opened inside Instagram, Gmail, …) have no Web NFC.
    isWebView: isAndroid && /; wv\)/.test(ua),
    device,
    isSecure: window.isSecureContext === true,
    hasWebNfc: 'NDEFReader' in window,
  };
}
