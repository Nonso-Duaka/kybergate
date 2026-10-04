"""Run the official pq-crystals Kyber tests against the vendored reference code.

1. test_kyber{512,768,1024}: upstream self-test (keygen / encaps / decaps,
   plus wrong-key and corrupted-ciphertext cases), 1000 iterations each.
2. test_vectors{512,768,1024}: deterministic test-vector output, hashed with
   SHA-256 and compared against the SHA256SUMS published by the Kyber team.

    python -m kybergate.kat
"""
import hashlib
import platform
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "third_party" / "pq-crystals-kyber"
REF = ROOT / "ref"


def main() -> int:
    print(f"Official Kyber reference tests  {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}"
          f"  {platform.system()} {platform.machine()}")
    targets = [f"test/test_kyber{n}" for n in (512, 768, 1024)] + [f"test/test_vectors{n}" for n in (512, 768, 1024)]
    flags = "CFLAGS=-Wall -Wextra -O3 -fomit-frame-pointer"  # drop -z noexecstack for non-GNU linkers
    subprocess.run(["make", "-s", "-C", str(REF), flags, *targets], check=True)

    expected = {}
    for line in (ROOT / "SHA256SUMS").read_text().split("\n"):
        if line.strip():
            digest, name = line.split()
            expected[name] = digest

    failures = 0
    print("\n[self-tests]")
    for n in (512, 768, 1024):
        r = subprocess.run([str(REF / f"test/test_kyber{n}")], capture_output=True, text=True)
        passed = r.returncode == 0 and "ERROR" not in r.stdout
        failures += not passed
        print(f"  Kyber{n:<5} test_kyber{n:<5} exit={r.returncode}  {'PASS' if passed else 'FAIL'}")

    print("\n[known-answer test vectors vs published SHA256SUMS]")
    for n in (512, 768, 1024):
        out = subprocess.run([str(REF / f"test/test_vectors{n}")], capture_output=True, check=True).stdout
        got = hashlib.sha256(out).hexdigest()
        want = expected[f"tvecs{n}"]
        failures += got != want
        print(f"  Kyber{n:<5} {got}  {'PASS' if got == want else 'FAIL (expected ' + want + ')'}")

    print(f"\n{'ALL OFFICIAL TESTS PASSED' if not failures else f'{failures} FAILURE(S)'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
