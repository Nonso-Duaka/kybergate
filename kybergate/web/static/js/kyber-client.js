// kybergate browser crypto: ML-KEM-768 (noble) + HKDF-SHA256 + AES-256-GCM (WebCrypto).
// Mirrors kybergate/envelope.py:derive_key and kybergate/web/app.py:unseal.
(function () {
  "use strict";
  const enc = new TextEncoder();

  const b64 = (u8) => { let s = ""; for (const b of u8) s += String.fromCharCode(b); return btoa(s); };
  const unb64 = (s) => Uint8Array.from(atob(s), (ch) => ch.charCodeAt(0));
  const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");
  const concat = (a, b) => { const out = new Uint8Array(a.length + b.length); out.set(a); out.set(b, a.length); return out; };

  async function api(url, body) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(body || {}),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { const e = new Error(data.error || "Request failed (" + res.status + ")"); e.status = res.status; throw e; }
    return data;
  }

  async function deriveAesKey(sharedSecret, kid, purpose) {
    const ikm = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: enc.encode(kid), info: enc.encode("kybergate/v1/web/" + purpose) },
      ikm, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  }

  async function fingerprint(sharedSecret) {
    const digest = await crypto.subtle.digest("SHA-256", concat(enc.encode("kybergate/fp"), sharedSecret));
    return hex(new Uint8Array(digest)).slice(0, 16);
  }

  // Runs the whole client side of the protocol. `payload` is a string (sent as raw
  // UTF-8) or an object (sent as JSON). `onStep(name, detail, done, body)` drives the UI;
  // `body` is passed once, just before the request leaves the browser.
  async function sealAndSend(purpose, payload, url, onStep, extra) {
    const step = onStep || (() => {});
    step("kex", "requesting a one-time ML-KEM-768 public key");
    const kx = await api("/api/kex", { purpose });
    step("kex", kx.algorithm + " public key, " + unb64(kx.public_key).length + " B, fp " + kx.fingerprint, true);

    step("encaps", "encapsulating against the server key");
    const { cipherText, sharedSecret } = MLKEM.ml_kem768.encapsulate(unb64(kx.public_key));
    const fp = await fingerprint(sharedSecret);
    step("encaps", "Kyber ciphertext " + cipherText.length + " B, shared secret fp " + fp, true);

    step("hkdf", "HKDF-SHA256 -> AES-256 key");
    const key = await deriveAesKey(sharedSecret, kx.kid, purpose);
    sharedSecret.fill(0);
    step("hkdf", "info = kybergate/v1/web/" + purpose, true);

    step("aead", "AES-256-GCM encrypting");
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const box = new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: enc.encode(purpose + "|" + kx.kid) },
      key, enc.encode(typeof payload === "string" ? payload : JSON.stringify(payload))));
    step("aead", box.length + " B sealed (incl. 16 B tag)", true);

    const body = Object.assign({ kid: kx.kid, kem_ct: b64(cipherText), iv: b64(iv), box: b64(box) }, extra ? extra(fp) : {});
    step("send", "POST " + url, false, body);
    const result = await api(url, body);
    step("send", "server opened it with the C reference code", true);
    return { result, body, fp, kex: kx };
  }

  window.KG = { api, sealAndSend, b64, unb64, hex };
})();
