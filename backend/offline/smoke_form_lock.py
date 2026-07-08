#!/usr/bin/env python3
# encoding: utf-8
"""Smoke for "edit form should grey out while unlock is pending".

Verifies (over plain HTTP, no browser):
  1. The served /app.js declares `FORM_EDIT_LOCKED_IDS` listing every
     form element that should be disabled while the lock box is up.
  2. The served / defines every one of those ids (so the JS disable
     call has something to act on).
  3. setFormEditLocked is called from:
       - openAdd   -> false (unlocked)
       - openEdit  -> true for needs-password flow, false for legacy
       - unlockEdit success -> false, failure -> true
       - closeForm -> false
  4. The CSS has :disabled styling for inputs/selects/textareas.
"""
import sys, json
import urllib.request

BASE = "http://localhost:9012"
EXPECTED_IDS = [
    "f-username", "f-algorithm",
    "f-entry-password", "f-entry-password-confirm", "f-new-entry-password",
    "f-orgkey", "f-group", "f-secret",
    "f-reveal", "f-gen", "f-entry-reveal",
    "f-notes", "f-comment",
    "form-save",
]
EXPECTED_CALLS = [
    ("openAdd", "setFormEditLocked(false)"),
    ("openEdit", 'setFormEditLocked(true)'),       # needsPw branch presence
    ("openEdit", 'setFormEditLocked(false)'),      # legacy branch presence
    ("unlockEdit", 'setFormEditLocked(false)'),    # success
    ("unlockEdit", 'setFormEditLocked(true)'),     # failure
    ("closeForm", 'setFormEditLocked(false)'),
]


def get(path):
    with urllib.request.urlopen(BASE + path, timeout=5) as r:
        return r.read().decode("utf-8", errors="replace")


def main():
    fails = 0
    js = get("/app.js?v=999")  # cache-bust
    css = get("/styles.css?v=999")
    html = get("/")

    print(f"js_len={len(js)} css_len={len(css)} html_len={len(html)}")

    # 1. IDs in JS
    print("\n[1] FORM_EDIT_LOCKED_IDS list:")
    for i in EXPECTED_IDS:
        ok = f'"{i}"' in js
        print(f"  {'PASS' if ok else 'FAIL'}  contains {i!r}")
        if not ok: fails += 1

    # 2. IDs in HTML
    print("\n[2] DOM elements (must exist in / ):")
    for i in EXPECTED_IDS:
        ok = (f'id="{i}"' in html) or (f"id='{i}'" in html)
        print(f"  {'PASS' if ok else 'FAIL'}  has #{i}")
        if not ok: fails += 1

    # 3. Calls in JS
    print("\n[3] setFormEditLocked call sites:")
    for fn, call in EXPECTED_CALLS:
        ok = call in js
        # find ALL function decl positions for fn (function/async function)
        decls = []
        for kw in (f"function {fn}", f"async function {fn}"):
            start = 0
            while True:
                p = js.find(kw, start)
                if p < 0: break
                decls.append(p)
                start = p + len(kw)
        idxs_call = [i for i in range(len(js)) if js[i:i + len(call)] == call]
        in_scope = any(0 < ic - d < 4000 for d in decls for ic in idxs_call)
        marker = "PASS" if ok and in_scope else "FAIL"
        print(f"  {marker}  {fn:11} -> {call}  (found={ok}, in-scope={in_scope})")
        if not (ok and in_scope): fails += 1

    # 4. Disabled CSS
    print("\n[4] CSS disabled styling:")
    for piece in ("input:disabled", "select:disabled", "textarea:disabled"):
        ok = piece in css
        print(f"  {'PASS' if ok else 'FAIL'}  {piece}")
        if not ok: fails += 1

    print(f"\n结果: {len(EXPECTED_IDS)*2 + len(EXPECTED_CALLS) + 3 - fails} 通过, {fails} 失败")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
