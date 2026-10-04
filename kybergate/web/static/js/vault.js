(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);

  $("logout").addEventListener("click", async () => {
    const r = await KG.api("/api/logout");
    window.location.href = r.redirect;
  });

  const form = $("lab-form");
  const out = $("lab-result");
  const log = $("lab-log");

  function mark(id, pass) {
    const el = $(id);
    el.textContent = pass ? "PASS" : "FAIL";
    el.dataset.pass = String(pass);
  }

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const message = form.message.value;
    const btn = form.querySelector("button");
    btn.disabled = true;
    out.hidden = true;
    log.textContent = "";
    $("lab-error").textContent = "";
    try {
      const { result, body, fp } = await KG.sealAndSend("lab", message, "/api/lab",
        (name, detail, done) => { if (done) log.textContent += "✓ " + detail + "\n"; },
        (clientFp) => ({ client_fp: clientFp }));
      $("lab-ct-bytes").textContent = result.ciphertext_bytes + " bytes (" +
        new TextEncoder().encode(message).length + " B message + 16 B GCM tag)";
      $("lab-hex").textContent = result.ciphertext_hex;
      $("lab-b64").textContent = result.ciphertext_b64;
      $("lab-plain").textContent = result.decrypted;
      $("lab-fp-client").textContent = fp;
      $("lab-fp-server").textContent = result.server_fp;
      $("lab-kem").textContent = result.kem_ct_bytes + " B";
      $("lab-iv").textContent = result.iv;
      mark("chk-fp", result.fp_match);
      mark("chk-text", result.decrypted === message);
      mark("chk-wire", !JSON.stringify(body).includes(message));
      mark("chk-tamper", result.tamper_rejected);
      out.hidden = false;
    } catch (err) {
      $("lab-error").textContent = err.message;
    } finally {
      btn.disabled = false;
    }
  });
})();

document.querySelectorAll("time[data-ts]").forEach((t) => {
  t.textContent = new Date(parseFloat(t.dataset.ts) * 1000).toLocaleString();
});
