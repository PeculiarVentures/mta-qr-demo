#!/usr/bin/env python3
"""
MTA-QR Interop Test Script
Builds and starts all six services (two issuers per algorithm × two implementations + two verifiers),
runs the 12-cell positive matrix (3 algorithms × 4 issuer/verifier combinations) plus 3 negative tests, and reports results.

Requires: Go 1.22+, Node 20+, tsx installed globally.
"""
import subprocess, time, json, urllib.request, urllib.error, sys, os, signal, os.path

REPO_DIR = os.path.dirname(os.path.abspath(__file__))
TS_DIR   = os.path.join(REPO_DIR, "ts")
GO_DIR   = os.path.join(REPO_DIR, "go")

# Each algo variant gets a distinct origin so the verifier's checkpoint cache
# cannot cross-contaminate between Ed25519 and ECDSA runs.
SERVICES = [
    {"name": "go-issuer-ed25519", "bin": "/tmp/mta-go-issuer", "port": 8081, "env": {
        "MTA_SIG_ALG": "", "MTA_ORIGIN": "demo.mta-qr.example/go-issuer/ed25519/v1"}},
    {"name": "go-issuer-ecdsa",   "bin": "/tmp/mta-go-issuer", "port": 8083, "env": {
        "MTA_SIG_ALG": "ecdsa-p256", "MTA_ORIGIN": "demo.mta-qr.example/go-issuer/ecdsa-p256/v1"}},
    {"name": "go-issuer-mldsa44", "bin": "/tmp/mta-go-issuer", "port": 8085, "env": {
        "MTA_SIG_ALG": "mldsa44", "MTA_ORIGIN": "demo.mta-qr.example/go-issuer/mldsa44/v1"}},
    {"name": "go-verifier",       "bin": "/tmp/mta-go-verifier", "port": 8082, "env": {}},
    {"name": "ts-issuer-ed25519", "bin": "npx", "args": ["tsx", "issuer/main.ts"], "port": 3001,
     "cwd": TS_DIR, "env": {
        "MTA_SIG_ALG": "", "MTA_ORIGIN": "demo.mta-qr.example/ts-issuer/ed25519/v1"}},
    {"name": "ts-issuer-ecdsa",   "bin": "npx", "args": ["tsx", "issuer/main.ts"], "port": 3003,
     "cwd": TS_DIR, "env": {
        "MTA_SIG_ALG": "ecdsa-p256", "MTA_ORIGIN": "demo.mta-qr.example/ts-issuer/ecdsa-p256/v1"}},
    {"name": "ts-issuer-mldsa44", "bin": "npx", "args": ["tsx", "issuer/main.ts"], "port": 3005,
     "cwd": TS_DIR, "env": {
        "MTA_SIG_ALG": "mldsa44", "MTA_ORIGIN": "demo.mta-qr.example/ts-issuer/mldsa44/v1"}},
    {"name": "ts-verifier",       "bin": "npx", "args": ["tsx", "verifier/main.ts"], "port": 3002,
     "cwd": TS_DIR, "env": {}},
    # Dedicated verifiers for negative tests — start completely clean (no MTA_TRUST_CONFIG_URLS)
    {"name": "neg-go-verifier",   "bin": "/tmp/mta-go-verifier", "port": 8089, "env": {}},
    {"name": "neg-ts-verifier",   "bin": "npx", "args": ["tsx", "verifier/main.ts"], "port": 3009,
     "cwd": TS_DIR, "env": {}},
]

procs = []

def build_go_binaries():
    """Build Go binaries before starting services."""
    import subprocess
    go_dir = GO_DIR
    for name, target, out in [("issuer", "./issuer/", "/tmp/mta-go-issuer"),
                               ("verifier", "./verifier/", "/tmp/mta-go-verifier")]:
        print(f"  Building Go {name}...")
        r = subprocess.run(["go", "build", "-o", out, target], cwd=go_dir,
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(f"  FAILED: {r.stderr}")
            sys.exit(1)
    print("  Go binaries built.")


def start_services():
    for svc in SERVICES:
        args = [svc["bin"]] + svc.get("args", [])
        log = open(f"/tmp/{svc['name']}.log", "w")
        cwd = svc.get("cwd", "/")
        env = {**os.environ, **svc.get("env", {})}
        # Pass port via env too
        env["MTA_PORT"] = str(svc["port"])
        p = subprocess.Popen(args, stdout=log, stderr=log, cwd=cwd, env=env)
        procs.append((svc["name"], p, log))
        print(f"  Started {svc['name']} (:{svc['port']}) PID {p.pid}")
    print("  Waiting for services to be ready (polling /checkpoint)...")
    deadline = time.time() + 45
    for svc in SERVICES:
        if "verifier" in svc["name"]:
            continue  # verifiers expose / not /checkpoint; checked via check_alive
        if svc.get("skip_poll"):
            continue
        url = f"http://localhost:{svc['port']}/checkpoint"
        while time.time() < deadline:
            try:
                urllib.request.urlopen(url, timeout=2)
                print(f"  ✓ {svc['name']} ready")
                break
            except:
                time.sleep(0.5)
        else:
            print(f"  ✗ {svc['name']} never became ready")
            stop_services()
            sys.exit(1)

def stop_services():
    for name, p, log in procs:
        p.terminate()
        log.close()
    for name, p, log in procs:
        try: p.wait(timeout=3)
        except: p.kill()

def get(url):
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())

def post(url, data):
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())

def check_alive(port):
    try:
        urllib.request.urlopen(f"http://localhost:{port}/", timeout=2)
        return True
    except urllib.error.HTTPError:
        return True  # HTTP error = server is alive
    except:
        return False

PASS = "✓"
FAIL = "✗"
SKIP = "–"

results = []

def run_test(label, issuer_port, verifier_port, load_tc_url=None):
    print(f"\n  [{label}]")
    row = {"label": label, "ok": False, "steps": [], "error": None}

    # Check services alive
    if not check_alive(issuer_port):
        row["error"] = f"issuer :{issuer_port} not responding"
        print(f"    {FAIL} issuer :{issuer_port} not responding")
        results.append(row)
        return

    if not check_alive(verifier_port):
        row["error"] = f"verifier :{verifier_port} not responding"
        print(f"    {FAIL} verifier :{verifier_port} not responding")
        results.append(row)
        return

    # Load trust config
    tc_url = load_tc_url or f"http://localhost:{issuer_port}/trust-config"
    try:
        tc_resp = post(f"http://localhost:{verifier_port}/load-trust-config",
                       {"url": tc_url})
        if not tc_resp.get("ok"):
            row["error"] = f"load-trust-config failed: {tc_resp}"
            print(f"    {FAIL} load-trust-config: {tc_resp}")
            results.append(row)
            return
        print(f"    {PASS} loaded trust config: {tc_resp.get('origin')}")
    except Exception as e:
        row["error"] = f"load-trust-config error: {e}"
        print(f"    {FAIL} load-trust-config error: {e}")
        results.append(row)
        return

    # Issue an assertion
    try:
        issue_resp = post(f"http://localhost:{issuer_port}/issue", {
            "schema_id": 42,
            "ttl_seconds": 3600,
            "claims": {"test": label, "subject": "interop-matrix"}
        })
        entry_index = issue_resp["entry_index"]
        payload_hex = issue_resp["payload_hex"]
        print(f"    {PASS} issued entry_index={entry_index} payload_len={len(payload_hex)//2}B")
    except Exception as e:
        row["error"] = f"issue error: {e}"
        print(f"    {FAIL} issue error: {e}")
        results.append(row)
        return

    # Verify with the other impl
    try:
        verify_resp = post(f"http://localhost:{verifier_port}/verify",
                           {"payload_hex": payload_hex})
        valid = verify_resp.get("valid", False)
        steps = verify_resp.get("steps", [])
        error = verify_resp.get("error", "")

        for step in steps:
            icon = PASS if step["ok"] else FAIL
            print(f"    {icon} {step['name']}: {step['detail'][:80]}")

        if valid:
            claims = verify_resp.get("claims", {})
            print(f"    {PASS} VALID — claims: {claims}")
            row["ok"] = True
        else:
            print(f"    {FAIL} INVALID — {error}")
            row["error"] = error

        row["steps"] = steps
    except Exception as e:
        row["error"] = f"verify error: {e}"
        print(f"    {FAIL} verify error: {e}")

    results.append(row)

def run_negative_test(label, issuer_port, verifier_port,
                      expect_valid=False, tamper=False, skip_tc=False,
                      override_tc_url=None):
    """
    Run a test where the verifier SHOULD reject the payload.
    The test passes (ok=True) only if the verifier returns valid=False.
    """
    print(f"\n  [{label}]")
    row = {"label": label, "ok": False, "steps": [], "error": None}

    if not check_alive(issuer_port) or not check_alive(verifier_port):
        row["error"] = "service not responding"
        print(f"    {FAIL} service not responding")
        results.append(row)
        return

    # Load a (possibly wrong) trust config unless skip_tc
    if not skip_tc:
        tc_url = override_tc_url or f"http://localhost:{issuer_port}/trust-config"
        try:
            tc_resp = post(f"http://localhost:{verifier_port}/load-trust-config", {"url": tc_url})
            print(f"    {PASS} loaded trust config: {tc_resp.get('origin', '(none)')}")
        except Exception as e:
            row["error"] = f"load-trust-config error: {e}"
            print(f"    {FAIL} load-trust-config error: {e}")
            results.append(row)
            return

    # Issue from the real issuer
    try:
        issue_resp = post(f"http://localhost:{issuer_port}/issue", {
            "schema_id": 1, "ttl_seconds": 3600,
            "claims": {"test": label, "subject": "negative-test"}
        })
        payload_hex = issue_resp["payload_hex"]
        print(f"    {PASS} issued payload_len={len(payload_hex)//2}B")
    except Exception as e:
        row["error"] = f"issue error: {e}"
        print(f"    {FAIL} issue error: {e}")
        results.append(row)
        return

    # Optionally tamper: flip a bit in the TBS portion (last ~40 bytes)
    if tamper:
        b = bytearray(bytes.fromhex(payload_hex))
        b[-10] ^= 0xFF  # corrupt deep in the TBS
        payload_hex = b.hex()
        print(f"    {PASS} tampered payload (bit-flipped TBS)")

    # Verify — expect rejection
    try:
        verify_resp = post(f"http://localhost:{verifier_port}/verify",
                           {"payload_hex": payload_hex})
        valid = verify_resp.get("valid", False)
        error = verify_resp.get("error", "")

        if not valid:
            print(f"    {PASS} correctly rejected: {error[:100]}")
            row["ok"] = True
        else:
            print(f"    {FAIL} INCORRECTLY ACCEPTED — verifier returned valid=true")
            row["error"] = "verifier accepted payload it should have rejected"

        row["steps"] = verify_resp.get("steps", [])
    except Exception as e:
        row["error"] = f"verify error: {e}"
        print(f"    {FAIL} verify error: {e}")

    results.append(row)

# ---- Main ----

print("MTA-QR Interop Test Matrix")
print("=" * 60)
print("\nBuilding Go binaries...")
build_go_binaries()
print("\nStarting services...")
start_services()

# Verify each service is up
print("\nHealth checks:")
for svc in SERVICES:
    ok = check_alive(svc["port"])
    icon = PASS if ok else FAIL
    print(f"  {icon} {svc['name']} :{svc['port']}")

print("\nRunning interop matrix...")

print("\n--- Ed25519 (sig_alg=6) ---")
run_test("Ed25519: Go issuer → Go verifier",    issuer_port=8081, verifier_port=8082)
run_test("Ed25519: TS issuer → TS verifier",    issuer_port=3001, verifier_port=3002)
run_test("Ed25519: Go issuer → TS verifier",    issuer_port=8081, verifier_port=3002)
run_test("Ed25519: TS issuer → Go verifier",    issuer_port=3001, verifier_port=8082)

print("\n--- ECDSA P-256 (sig_alg=4) ---")
run_test("ECDSA-P256: Go issuer → Go verifier", issuer_port=8083, verifier_port=8082)
run_test("ECDSA-P256: TS issuer → TS verifier", issuer_port=3003, verifier_port=3002)
run_test("ECDSA-P256: Go issuer → TS verifier", issuer_port=8083, verifier_port=3002)
run_test("ECDSA-P256: TS issuer → Go verifier", issuer_port=3003, verifier_port=8082)

print("\n--- ML-DSA-44 / FIPS 204 (sig_alg=1) ---")
run_test("ML-DSA-44: Go issuer → Go verifier",  issuer_port=8085, verifier_port=8082)
run_test("ML-DSA-44: TS issuer → TS verifier",  issuer_port=3005, verifier_port=3002)
run_test("ML-DSA-44: Go issuer → TS verifier",  issuer_port=8085, verifier_port=3002)
run_test("ML-DSA-44: TS issuer → Go verifier",  issuer_port=3005, verifier_port=8082)

print("\n--- Negative tests (must reject) ---")
run_negative_test("Reject: wrong trust anchor (Ed25519 payload, verifier has only ECDSA anchor)",
    issuer_port=8081, verifier_port=8089, expect_valid=False,
    override_tc_url="http://localhost:8083/trust-config")
run_negative_test("Reject: tampered payload (bit flip in TBS)",
    issuer_port=8081, verifier_port=8089, expect_valid=False, tamper=True)
run_negative_test("Reject: no trust config loaded for origin",
    issuer_port=8083, verifier_port=3009, expect_valid=False, skip_tc=True)

# ---- Summary ----
print("\n" + "=" * 60)
print("SUMMARY")
passed = sum(1 for r in results if r["ok"])
total  = len(results)
for r in results:
    icon = PASS if r["ok"] else FAIL
    err  = f"  ({r['error']})" if r["error"] else ""
    print(f"  {icon} {r['label']}{err}")

print(f"\n{passed}/{total} tests passed")

stop_services()

# Print service logs on any failure
if passed < total:
    print("\n--- Service logs ---")
    for svc in SERVICES:
        logf = f"/tmp/{svc['name']}.log"
        print(f"\n[{svc['name']}]")
        try:
            with open(logf) as f:
                lines = f.readlines()
                # Show last 20 lines
                for l in lines[-20:]:
                    print(" ", l.rstrip())
        except: pass

sys.exit(0 if passed == total else 1)
