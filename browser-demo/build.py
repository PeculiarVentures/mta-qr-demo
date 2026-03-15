#!/usr/bin/env python3
"""
build.py  —  Assembles browser-demo/index.html from:
  - index.template.html     (application HTML/CSS/JS, no vendored deps)
  - deps/nayuki_qr.js       (Nayuki QR Code generator v1.8.0, MIT)
  - deps/noble_pq.iife.js   (@noble/post-quantum v0.5.4 ml_dsa44 IIFE, MIT)
  - deps/mta_qr_sdk.iife.js (MTA-QR SDK browser bundle — CBOR, Merkle, payload codec)

Usage:
  python3 build.py              # writes index.html next to this script
  python3 build.py --check-only # validate deps exist, don't write

Rebuilding deps from source:
  Nayuki QR:
    curl -fsSL https://raw.githubusercontent.com/nayuki/QR-Code-generator/master/typescript-javascript/qrcodegen.js > deps/nayuki_qr.js

  noble/pq IIFE (requires npm install @noble/post-quantum in ../ts):
    cd ../ts
    npx esbuild node_modules/@noble/post-quantum/ml-dsa.js \\
      --bundle --format=iife --global-name=__noble_pq \\
      --minify --platform=browser \\
      --outfile=../browser-demo/deps/noble_pq.iife.js

  MTA-QR SDK browser bundle (from ts/ SDK directory):
    cd ../ts
    npx esbuild src/browser-bundle.ts \\
      --bundle --format=iife --global-name=__mta_qr \\
      --platform=browser --minify \\
      --outfile=../browser-demo/deps/mta_qr_sdk.iife.js
"""

import os
import sys
import hashlib

HERE = os.path.dirname(os.path.abspath(__file__))

TEMPLATE   = os.path.join(HERE, 'index.template.html')
NAYUKI     = os.path.join(HERE, 'deps', 'nayuki_qr.js')
NOBLE_PQ   = os.path.join(HERE, 'deps', 'noble_pq.iife.js')
MTA_QR_SDK = os.path.join(HERE, 'deps', 'mta_qr_sdk.iife.js')
OUTPUT     = os.path.join(HERE, 'index.html')

PLACEHOLDER_NAYUKI   = '/* {{NAYUKI_QR}} */'
PLACEHOLDER_NOBLE_PQ = '/* {{NOBLE_PQ}} */'
PLACEHOLDER_SDK      = '/* {{MTA_QR_SDK}} */'

NOBLE_PQ_LICENSE = """\
/*! @noble/post-quantum — MIT License (c) 2024 Paul Miller (paulmillr.com) */"""

NAYUKI_LICENSE = """\
/*! nayuki-qr-code-generator v1.8.0 — MIT License (c) Project Nayuki */"""


def check_deps():
    missing = []
    for label, path in [('template', TEMPLATE), ('nayuki', NAYUKI), ('noble_pq', NOBLE_PQ), ('mta_qr_sdk', MTA_QR_SDK)]:
        if not os.path.exists(path):
            missing.append(f"  {label}: {path}")
    if missing:
        print("ERROR: missing files:\n" + '\n'.join(missing))
        print("\nRun with --rebuild-deps to regenerate, or see header comment in build.py.")
        sys.exit(1)


def build():
    check_deps()

    template  = open(TEMPLATE).read()
    nayuki    = open(NAYUKI).read().strip()
    noble_pq  = open(NOBLE_PQ).read().strip()
    mta_qr_sdk = open(MTA_QR_SDK).read().strip()

    for ph in [PLACEHOLDER_NAYUKI, PLACEHOLDER_NOBLE_PQ, PLACEHOLDER_SDK]:
        if ph not in template:
            sys.exit(f"ERROR: placeholder '{ph}' not found in template")

    MTA_QR_SDK_LICENSE = """\
/*! @peculiarventures/mta-qr — Apache-2.0 (c) 2026 Peculiar Ventures */"""

    result = template
    result = result.replace(PLACEHOLDER_NAYUKI,   NAYUKI_LICENSE    + '\n' + nayuki)
    result = result.replace(PLACEHOLDER_NOBLE_PQ, NOBLE_PQ_LICENSE  + '\n' + noble_pq)
    result = result.replace(PLACEHOLDER_SDK,      MTA_QR_SDK_LICENSE + '\n' + mta_qr_sdk)

    with open(OUTPUT, 'w') as f:
        f.write(result)

    sha = hashlib.sha256(result.encode()).hexdigest()[:12]
    print(f"✓  {OUTPUT}")
    print(f"   {len(result):,} bytes  sha256:{sha}…")
    print(f"   template {len(template):,}B  nayuki {len(nayuki):,}B  noble_pq {len(noble_pq):,}B  sdk {len(mta_qr_sdk):,}B")


if __name__ == '__main__':
    if '--check-only' in sys.argv:
        check_deps()
        print("OK — all deps present")
    else:
        build()
