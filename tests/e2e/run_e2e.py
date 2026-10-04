"""Drive the real website in Chromium (Playwright) and check every step.

    python tests/e2e/run_e2e.py                         # starts its own server
    python tests/e2e/run_e2e.py --base https://my.site  # test a deployed copy

Steps: sign up -> message lab -> log out -> wrong password -> log in.
Every /api/ request body is captured and searched for the password and the
message. Nothing is saved unless --shots DIR is given (then screenshots go there).
"""
import argparse
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from contextlib import contextmanager
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from kybergate import ASSIGNMENT_MESSAGE  # noqa: E402


@contextmanager
def local_server():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    env = dict(os.environ, KYBERGATE_DB=os.path.join(tempfile.mkdtemp(), "e2e.db"))
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "kybergate.web.asgi:app", "--port", str(port)],
                            cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            urllib.request.urlopen(base + "/auth", timeout=1)
            break
        except OSError:
            time.sleep(0.1)
    try:
        yield base
    finally:
        proc.terminate()
        proc.wait()


def run(base: str, shots: Path | None, label: str) -> int:
    if shots:
        shots.mkdir(parents=True, exist_ok=True)
    bodies, problems = [], []

    def say(line):
        print(line)

    user = f"nonso_{secrets.token_hex(2)}"
    password = f"Quantum-{secrets.token_urlsafe(6)}"
    def shot(page, name, full=False):
        if shots:
            page.screenshot(path=shots / f"{label}-{name}.png", full_page=full)

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1240, "height": 820}, device_scale_factor=2)
        page.on("request", lambda r: bodies.append((r.url, r.post_data or "")) if "/api/" in r.url else None)
        # The wrong-password step is supposed to produce one 401; anything else is a problem.
        expected = "the server responded with a status of 401"
        page.on("console", lambda m: problems.append(m.text)
                if m.type == "error" and expected not in m.text else None)
        page.on("pageerror", lambda e: problems.append(str(e)))
        say(f"target {base}   user {user}   chromium {browser.version}")

        # 1. sign up
        page.goto(f"{base}/auth?mode=signup")
        page.fill("input[name=username]", user)
        page.fill("input[name=password]", password)
        page.fill("input[name=confirm]", password)
        shot(page, "1-signup")
        page.click("button[type=submit]")
        expect(page.locator("#wire-note")).to_be_visible()
        shot(page, "2-signup-wire-inspector")
        page.wait_for_url("**/vault")
        say(f"sign-up           -> {page.url}")
        shot(page, "3-vault", full=True)

        # 2. message lab
        page.fill("textarea[name=message]", ASSIGNMENT_MESSAGE)
        page.click("#lab-form button")
        expect(page.locator("#lab-result")).to_be_visible()
        page.locator("#lab-result details").evaluate("d => d.open = true")
        decrypted = page.text_content("#lab-plain")
        checks = {k: page.text_content(f"#chk-{k}") for k in ("fp", "text", "wire", "tamper")}
        say(f"lab ciphertext    {page.text_content('#lab-hex')}")
        say(f"lab decrypted     {decrypted}")
        say(f"lab checks        {checks}")
        page.locator("#lab-result").scroll_into_view_if_needed()
        shot(page, "4-message-lab", full=True)

        # 3. wrong password
        page.click("#logout")
        page.wait_for_url("**/auth*")
        page.fill("input[name=username]", user)
        page.fill("input[name=password]", "definitely-wrong")
        page.click("button[type=submit]")
        expect(page.locator('#status[data-kind="error"]')).to_be_visible()
        wrong = page.text_content("#status")
        say(f"wrong password    -> {wrong!r}")
        shot(page, "5-wrong-password")

        # 4. correct login
        page.fill("input[name=password]", password)
        page.click("button[type=submit]")
        page.wait_for_url("**/vault")
        say(f"login             -> {page.url}")
        shot(page, "6-login-vault", full=True)
        browser.close()

    leaked = [u for u, b in bodies if password in b or user in b or ASSIGNMENT_MESSAGE in b]
    say(f"captured {len(bodies)} /api/ requests; password, username or message readable in any: "
        f"{'YES ' + str(leaked) if leaked else 'no'}")
    login_body = next(b for u, b in reversed(bodies) if u.endswith("/api/auth/login"))
    say(f"example /api/auth/login body: {login_body[:260]}...")
    say(f"browser console errors: {problems or 'none'}")
    ok = (not leaked and not problems and decrypted == ASSIGNMENT_MESSAGE
          and set(checks.values()) == {"PASS"} and "Incorrect" in wrong)
    say("E2E RESULT: " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", help="URL of a running site (default: start one locally)")
    ap.add_argument("--label", help="screenshot file prefix (default: local or deployed)")
    ap.add_argument("--shots", help="save screenshots to this folder (default: save nothing)")
    a = ap.parse_args()
    if a.base:
        sys.exit(run(a.base.rstrip("/"), Path(a.shots) if a.shots else None, a.label or "deployed"))
    with local_server() as base:
        sys.exit(run(base, Path(a.shots) if a.shots else None, a.label or "local"))
