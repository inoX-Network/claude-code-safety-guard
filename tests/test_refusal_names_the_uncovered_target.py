#!/usr/bin/env python3
"""A refusal has to name the target that is missing, not the first one it saw.

Measured live on 2026-08-30, with a grant on one directory and a write to its
neighbour in the same line: the guard refused correctly and then advised

    "you need an allowed_paths grant for <the directory already granted>"

Following that advice changes nothing, because the grant is already there. The
verdict was right and its explanation sent the reader in a circle — the class
of failure this project keeps finding in its own tools.

Nothing about what is blocked changes here; only what the message says.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
HOME = str(Path.home())
SSH = f"{HOME}/.ssh"

RULES = {"blocked_paths_write": ["~/.ssh", "/opt/inox"],
         "blocked_patterns": [], "allowed_sudo": []}


def _refusal(command, allowed_paths):
    """The refusal text for one command under a level-1 grant."""
    payload = {"tool_name": "Bash", "tool_input": {"command": command},
               "session_id": "uncovered-target", "hook_event_name": "PreToolUse"}
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "rules.json").write_text(json.dumps(RULES), encoding="utf-8")
        expires = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
        (Path(tmp) / "probe.json").write_text(json.dumps({
            "override_level": 1, "task": "message check", "confirmed": True,
            "expires_at": expires,
            "grants": {"additional_sudo": [], "allowed_paths": allowed_paths},
        }), encoding="utf-8")
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = str(Path(tmp) / "rules.json")
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = tmp
        env["CLAUDE_AUDIT_DIR"] = tmp
        env["CLAUDE_HOOK_DEV_FLAG"] = tmp + "/_none"
        env["CLAUDE_GUARD_LANG"] = "en"
        p = subprocess.run([sys.executable, str(HOOK)], input=json.dumps(payload),
                           capture_output=True, text=True, env=env, timeout=60,
                           cwd=tmp)
        return p.returncode, (p.stdout + p.stderr)


def _named_path(text):
    """The path the message asks for a grant on."""
    m = re.search(r"grant for '([^']+)'", text)
    return m.group(1) if m else None


def check_it_names_the_neighbour_not_the_granted_directory():
    rc, text = _refusal(
        f"echo a > {SSH}/config.d/a && echo b > {SSH}/authorized_keys",
        [f"{SSH}/config.d"])
    return rc == 2 and _named_path(text) == f"{SSH}/authorized_keys"


def check_it_names_the_sibling_service():
    rc, text = _refusal(
        "echo a > /opt/inox/billing/app.py && echo b > /opt/inox/legal/app.py",
        ["/opt/inox/billing"])
    return rc == 2 and _named_path(text) == "/opt/inox/legal/app.py"


def check_a_single_target_is_still_named():
    rc, text = _refusal(f"echo b > {SSH}/authorized_keys", [f"{SSH}/config.d"])
    return rc == 2 and _named_path(text) == f"{SSH}/authorized_keys"


def check_without_a_grant_the_message_still_names_the_target():
    rc, text = _refusal(f"echo b > {SSH}/authorized_keys", [])
    return rc == 2 and _named_path(text) == f"{SSH}/authorized_keys"


CHECKS = [(name, fn) for name, fn in sorted(globals().items())
          if name.startswith("check_") and callable(fn)]


def test_refusal_names_the_uncovered_target():
    failed = [name for name, fn in CHECKS if not fn()]
    assert not failed, f"{len(failed)} of {len(CHECKS)} failed: {failed}"


if __name__ == "__main__":
    bad = [name for name, fn in CHECKS if not fn()]
    for name, _ in CHECKS:
        print(f"  {'FAIL' if name in bad else 'ok  '}  {name}")
    print(f"\n{len(CHECKS) - len(bad)} of {len(CHECKS)} passed")
    sys.exit(1 if bad else 0)
