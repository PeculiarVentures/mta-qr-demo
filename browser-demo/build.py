#!/usr/bin/env python3
"""
build.py  —  Assembles browser-demo/index.html from:
  - index.template.html   (application HTML/CSS/JS, no vendored deps)
  - deps/nayuki_qr.js     (Nayuki QR Code generator v1.8.0, MIT)
  - deps/noble_pq.iife.js (@noble/post-quantum v0.5.4 ml_dsa44 IIFE, MIT)

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
"""

import os
import sys
import hashlib

HERE = os.path.dirname(os.path.abspath(__file__))

TEMPLATE   = os.path.join(HERE, 'index.template.html')
NAYUKI     = os.path.join(HERE, 'deps', 'nayuki_qr.js')
NOBLE_PQ   = os.path.join(HERE, 'deps', 'noble_pq.iife.js')
OUTPUT     = os.path.join(HERE, 'index.html')

PLACEHOLDER_NAYUKI   = '/* {{NAYUKI_QR}} */'
PLACEHOLDER_NOBLE_PQ = '/* {{NOBLE_PQ}} */'

NOBLE_PQ_LICENSE = """\
/*! @noble/post-quantum — MIT License (c) 2024 Paul Miller (paulmillr.com) */"""

NAYUKI_LICENSE = """\
/*! nayuki-qr-code-generator v1.8.0 — MIT License (c) Project Nayuki */"""


def check_deps():
    missing = []
    for label, path in [('template', TEMPLATE), ('nayuki', NAYUKI), ('noble_pq', NOBLE_PQ)]:
        if not os.path.exists(path):
            missing.append(f"  {label}: {path}")
    if missing:
        print("ERROR: missing files:\n" + '\n'.join(missing))
        print("\nRun with --rebuild-deps to regenerate, or see header comment in build.py.")
        sys.exit(1)


def build():
    check_deps()

    template = open(TEMPLATE).read()
    nayuki   = open(NAYUKI).read().strip()
    noble_pq = open(NOBLE_PQ).read().strip()

    if PLACEHOLDER_NAYUKI not in template:
        sys.exit(f"ERROR: placeholder '{PLACEHOLDER_NAYUKI}' not found in template")
    if PLACEHOLDER_NOBLE_PQ not in template:
        sys.exit(f"ERROR: placeholder '{PLACEHOLDER_NOBLE_PQ}' not found in template")

    result = template
    result = result.replace(PLACEHOLDER_NAYUKI,   NAYUKI_LICENSE   + '\n' + nayuki)
    result = result.replace(PLACEHOLDER_NOBLE_PQ, NOBLE_PQ_LICENSE + '\n' + noble_pq)

    with open(OUTPUT, 'w') as f:
        f.write(result)

    sha = hashlib.sha256(result.encode()).hexdigest()[:12]
    print(f"✓  {OUTPUT}")
    print(f"   {len(result):,} bytes  sha256:{sha}…")
    print(f"   template {len(template):,}B  +  nayuki {len(nayuki):,}B  +  noble_pq {len(noble_pq):,}B")


if __name__ == '__main__':
    if '--check-only' in sys.argv:
        check_deps()
        print("OK — all deps present")
    else:
        build()
