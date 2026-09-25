#!/usr/bin/env python3
"""Validate every ```mermaid block in diagrams/*.md by rendering it against
mermaid.ink (HTTP 200 = parses and renders). Usage: python3 scripts/lint_mermaid.py
"""

import base64
import glob
import re
import sys
import urllib.request

fail = 0
for path in sorted(glob.glob("diagrams/*.md")):
    text = open(path).read()
    blocks = re.findall(r"```mermaid\n(.*?)```", text, re.S)
    for i, block in enumerate(blocks, 1):
        b64 = base64.urlsafe_b64encode(block.encode()).decode().rstrip("=")
        url = f"https://mermaid.ink/img/{b64}?type=png"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (mermaid-lint)"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                ok = r.status == 200
        except Exception as e:
            ok = False
            err = e
        print(f"{'OK  ' if ok else 'FAIL'} {path} block {i}" + ("" if ok else f" ({err})"))
        fail |= not ok
sys.exit(1 if fail else 0)
