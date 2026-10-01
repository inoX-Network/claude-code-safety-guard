#!/usr/bin/env python3
"""Three detours around the write guard that both copies of the guard had or
one of them had.

1. Write/Edit with a traversal target: `/tmp/../etc/x` is /etc/x. The write
   gate compared the target with expand_path only and saw /tmp.
2. A backslash in front of the path: the shell turns `\\/boot/x` into `/boot/x`;
   the backslash was not a valid path start, so `cp x \\/etc/x` ran through.
3. An unset variable in front of the path: `cp x $UNSET/etc/x` writes to
   /etc/x. The comparison saw a word character in front and took /etc for the
   tail of another path. `${UNSET}/etc` was always caught.

Free stays: a variable the line sets to something harmless, a loop or read
variable, $HOME in front of a path that is not protected, reading, and a
directory that merely happens to be called etc.
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
RULES = REPO / "security-rules.example.json"
E = "/bo" + "ot"   # protected in the example rules (as a whole directory)


def _judge(tool, tool_input):
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = str(RULES)
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = tmp
        env["CLAUDE_AUDIT_DIR"] = tmp
        env["CLAUDE_HOOK_DEV_FLAG"] = tmp + "/_none"
        env["CLAUDE_GUARD_CONFIG"] = tmp + "/_no_config.json"
        payload = {"tool_name": tool, "tool_input": tool_input,
                   "session_id": "write-detours", "cwd": tmp,
                   "hook_event_name": "PreToolUse"}
        r = subprocess.run([sys.executable, str(HOOK)], input=json.dumps(payload),
                           capture_output=True, text=True, env=env, timeout=60, cwd=tmp)
        return r.returncode


def _bash(command):
    return _judge("Bash", {"command": command})


# --- 1. traversal target in Write/Edit -----------------------------------------

def check_write_traversal_blocked():
    bad = []
    for target in (f"/tmp/..{E}/x.conf", f"/tmp/./..{E}/x.conf", f"/tmp//..{E}/x.conf"):
        if _judge("Write", {"file_path": target, "content": "x"}) != 2:
            bad.append(("Write", target))
        if _judge("Edit", {"file_path": target, "old_string": "a", "new_string": "b"}) != 2:
            bad.append(("Edit", target))
    return bad


def check_write_ordinary_targets_free():
    return [t for t in ("/tmp/./probe/x.conf", "/tmp/a/../b/x.conf")
            if _judge("Write", {"file_path": t, "content": "x"}) != 0]


# --- 2. backslash in front of the path -------------------------------------------

def check_backslash_path_blocked():
    return [c for c in (f"cp x \\{E}/probe", f"echo x > \\{E}/probe") if _bash(c) != 2]


# --- 3. unset variable in front of the path ---------------------------------------

def check_unset_variable_blocked():
    cmds = [f"cp x $UNSET{E}/probe", f"echo x > $UNSET{E}/probe", f"cp x $A$B{E}/probe",
            f"Z={E}; cp x $Z/probe"]
    return [c for c in cmds if _bash(c) != 2]


def check_set_or_harmless_variables_free():
    cmds = [f"B=/tmp/probe; cp x $B{E}/probe", f"export B=/tmp/probe && cp x $B{E}/probe",
            f"for v in /tmp/a /tmp/b; do cp x $v{E}/probe; done",
            f"read -r d < list; cp x $d{E}/probe", f"cp x $HOME{E}/probe",
            f"cat $UNSET{E}/hostname", "cp x $UNSET/tmp/probe",
            f"cp x build{E}/probe", f"cp x ~{E}/probe"]
    return [c for c in cmds if _bash(c) != 0]


def check_braced_and_plain_controls_blocked():
    return [c for c in (f"cp x ${{UNSET}}{E}/probe", f"cp x {E}/probe") if _bash(c) != 2]


CHECKS = [(name, fn) for name, fn in sorted(globals().items())
          if name.startswith("check_") and callable(fn)]


def test_write_target_detours():
    failed = {name: bad for name, fn in CHECKS if (bad := fn())}
    assert not failed, f"{len(failed)} of {len(CHECKS)} failed: {failed}"


if __name__ == "__main__":
    total = 0
    for name, fn in CHECKS:
        bad = fn()
        total += bool(bad)
        print(f"  {'FAIL' if bad else 'ok  '}  {name}" + (f"  {bad}" if bad else ""))
    print(f"\n{len(CHECKS) - total} of {len(CHECKS)} passed")
    sys.exit(1 if total else 0)
