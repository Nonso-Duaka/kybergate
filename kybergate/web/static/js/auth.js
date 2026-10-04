(function () {
  "use strict";
  const form = document.getElementById("auth-form");
  if (!form) return;
  const tabs = document.querySelectorAll("[data-tab]");
  const confirmRow = document.getElementById("confirm-row");
  const submit = form.querySelector("button[type=submit]");
  const status = document.getElementById("status");
  const wireBox = document.getElementById("wire-json");
  let mode = form.dataset.mode;

  function setMode(next) {
    mode = next;
    tabs.forEach((t) => t.setAttribute("aria-selected", String(t.dataset.tab === mode)));
    confirmRow.hidden = mode !== "signup";
    form.confirm.required = mode === "signup";
    form.password.autocomplete = mode === "signup" ? "new-password" : "current-password";
    submit.textContent = mode === "signup" ? "Create account" : "Log in";
    history.replaceState(null, "", "/auth?mode=" + mode);
    say("");
  }
  tabs.forEach((t) => t.addEventListener("click", () => setMode(t.dataset.tab)));
  setMode(mode);

  function say(text, kind) {
    status.textContent = text;
    status.dataset.kind = kind || "";
  }

  function resetSteps() {
    document.querySelectorAll(".pipeline li").forEach((li) => {
      li.dataset.state = "";
      li.querySelector(".detail").textContent = li.dataset.idle;
    });
  }

  function onStep(name, detail, done, body) {
    if (body) showWire(body);
    const li = document.querySelector('.pipeline li[data-step="' + name + '"]');
    if (!li) return;
    li.dataset.state = done ? "done" : "active";
    li.querySelector(".detail").textContent = detail;
  }

  function showWire(body) {
    const short = (s) => (s.length > 44 ? s.slice(0, 44) + "… (" + KG.unb64(s).length + " bytes)" : s);
    wireBox.textContent = JSON.stringify({
      kid: body.kid, kem_ct: short(body.kem_ct), iv: body.iv, box: short(body.box),
    }, null, 2);
    document.getElementById("wire-note").hidden = false;
  }

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    if (mode === "signup" && form.password.value !== form.confirm.value) {
      say("Passwords do not match.", "error");
      return;
    }
    submit.disabled = true;
    resetSteps();
    say("Securing your credentials…");
    try {
      const out = await KG.sealAndSend(mode, {
        username: form.username.value.trim(),
        password: form.password.value,
      }, "/api/auth/" + mode, onStep);
      say("Verified. Opening your vault…", "ok");
      setTimeout(() => { window.location.href = out.result.redirect; }, 700);
    } catch (err) {
      document.querySelectorAll('.pipeline li[data-state="active"]').forEach((li) => { li.dataset.state = "fail"; });
      say(err.message, "error");
      submit.disabled = false;
    }
  });
})();
