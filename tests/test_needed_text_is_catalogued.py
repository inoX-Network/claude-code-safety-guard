#!/usr/bin/env python3
"""The "Needed: …" part of a path refusal comes from the message catalogue.

It was built in the code, so a German refusal read "Benötigt: level 2 OR an
allowed_paths grant for '…'" — half English, in exactly the sentence that tells
the reader what to do. And the write refusal said "(Write/Edit)" also when a
Bash command was refused. Both measured 2026-10-01 while merging the
maintainer's copy, whose refusals are German throughout.
"""
import json
import os
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
TARGET = "/opt/app/service/app.py"
RULES = {"blocked_paths_write": ["/opt/app"], "blocked_patterns": [], "allowed_sudo": []}


def _refusal(language: str | None) -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "rules.json").write_text(json.dumps(RULES), encoding="utf-8")
        cfg = Path(tmp) / "guard-config.json"
        if language:
            cfg.write_text(json.dumps({"language": language}), encoding="utf-8")
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = tmp + "/rules.json"
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = tmp + "/ov"
        env["CLAUDE_AUDIT_DIR"] = tmp + "/audit"
        env["CLAUDE_HOOK_DEV_FLAG"] = tmp + "/_none"
        env["CLAUDE_GUARD_CONFIG"] = str(cfg)
        p = subprocess.run(["python3", str(HOOK)],
                           input=json.dumps({"session_id": "needed-text", "tool_name": "Bash",
                                             "tool_input": {"command": f"echo x > {TARGET}"}}),
                           capture_output=True, text=True, env=env, cwd=tmp)
    return p.returncode, " ".join(p.stderr.split())


def check_german_refusal_has_no_english_remainder():
    rc, text = _refusal("de")
    ok = (rc == 2 and f"Benötigt: Stufe 2 ODER einen allowed_paths-Grant für '{TARGET}'" in text
          and "OR an allowed_paths" not in text)
    return ok, text[:220]


def check_english_refusal_unchanged():
    rc, text = _refusal(None)
    return rc == 2 and f"Needed: level 2 OR an allowed_paths grant for '{TARGET}'" in text, text[:220]


def check_bash_refusal_does_not_claim_write_edit():
    rc, text = _refusal(None)
    return rc == 2 and "(Write/Edit)" not in text, text[:220]


CHECKS = [(n, f) for n, f in sorted(globals().items()) if n.startswith("check_") and callable(f)]

try:
    import pytest

    @pytest.mark.parametrize("name,fn", CHECKS, ids=[c[0] for c in CHECKS])
    def test_needed_text_is_catalogued(name, fn):
        ok, detail = fn()
        assert ok, f"{name}: {detail}"

except ImportError:
    pass


if __name__ == "__main__":
    failures = 0
    for name, fn in CHECKS:
        ok, detail = fn()
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            print(f"      {detail}")
    raise SystemExit(0 if not failures else 1)
