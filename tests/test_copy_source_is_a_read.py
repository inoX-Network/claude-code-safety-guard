# ============================================================================
# Copying reads the source and writes the destination.
#
# The write guard used to treat both positions alike: a protected path as the
# SOURCE was denied, although the command changes nothing there. Same idea as
# the remote-path gate — position, not mere occurrence.
#
# The counter-checks carry most of the weight here. This change turns a false
# positive into a hole very easily:
#   - move and delete DO modify their source and stay denied
#   - the read guard is untouched (copying is reading)
#   - a destination given as an option is not at the end and must not fool it
#
# Usage:  python3 tests/test_copy_source_is_a_read.py [path-to-hook]
# Every case is a dry run. No command is executed.
# ============================================================================
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_HOOK = REPO / "hooks" / "command-guard.py"
HOME = os.path.expanduser("~")

RULES = {
    "protected_reads": {
        "always_blocked_reads": ["/etc/shadow"],
        "require_override_1": ["~/.ssh/id_"],
        "always_allowed": [], "env_files_require_override_1": [],
    },
    "blocked_paths_write": ["~/.ssh", "/etc", "/boot"],
    "blocked_patterns": [],
}

LEVEL1 = {"override_level": 1, "task": "test", "confirmed": True,
          "expires_at": "2099-01-01T00:00:00+00:00",
          "grants": {"allowed_paths": ["/tmp"], "additional_sudo": []}}

# Write-protected, no read protection: a system config file.
WRITE_ONLY = "/etc/fstab"
WRITE_ONLY_DIR = "/boot"
# Read-protected.
KEY = f"{HOME}/.ssh/id_rsa"

# (description, command, denied)
CASES = [
    # --- the false positive that should go away ---------------------------
    ("copy a protected file out",        f"cp {WRITE_ONLY} /tmp/copy",        False),
    ("copy a protected directory out",   f"cp -r {WRITE_ONLY_DIR} /tmp/dir",  False),
    ("install a protected file out",     f"install {WRITE_ONLY} /tmp/copy",   False),

    # --- what must stay denied --------------------------------------------
    ("copy INTO a protected path",       f"cp /tmp/x {WRITE_ONLY}",           True),
    ("copy into a protected directory",  f"cp /tmp/x {WRITE_ONLY_DIR}/",      True),
    ("move out (modifies the source)",   f"mv {WRITE_ONLY} /tmp/gone",        True),
    ("delete in a protected path",       f"rm {WRITE_ONLY}",                  True),
    ("overwrite via redirect",           f"echo x > {WRITE_ONLY}",            True),
    ("truncate a protected file",        f"truncate -s 0 {WRITE_ONLY}",       True),
    ("destination as an option",         f"cp -t {WRITE_ONLY_DIR} /tmp/x",    True),
    ("destination as a long option",     f"cp --target-directory={WRITE_ONLY_DIR} /tmp/x", True),
    ("copy out, then write in",          f"cp {WRITE_ONLY} /tmp/c && echo x > {WRITE_ONLY}", True),

    # --- the read guard is untouched --------------------------------------
    ("a private key as the source",      f"cp {KEY} /tmp/copy",               True),
    ("copy the key directory",           f"cp -r {HOME}/.ssh /tmp/ssh",       True),

    # --- harmless stays harmless ------------------------------------------
    ("both harmless",                    "cp /tmp/a /tmp/b",                  False),
    ("harmless recursive",               "cp -r ./src /tmp/src",              False),
]

# With a level-1 approval a key under require_override_1 may be read. Direct
# reads, base64 and tar always allowed that; only copying was denied — as a
# side effect of the write guard, not as a rule. Now it is consistent.
CASES_WITH_APPROVAL = [
    ("level 1: read the key directly",   f"cat {KEY}",                        False),
    ("level 1: copy the key",            f"cp {KEY} /tmp/x",                  False),
    ("level 1: write-protected path stays denied", f"cp /tmp/x {WRITE_ONLY}", True),
]


def _denied(hook, command, approval=None):
    with tempfile.TemporaryDirectory() as ov:
        rules_path = os.path.join(ov, "rules.json")
        with open(rules_path, "w", encoding="utf-8") as f:
            json.dump(RULES, f)
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = rules_path
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = ov
        env["CLAUDE_AUDIT_DIR"] = ov
        env["CLAUDE_HOOK_DEV_FLAG"] = ov + "/_none"
        if approval:
            with open(os.path.join(ov, "t.json"), "w", encoding="utf-8") as f:
                json.dump(approval, f)
        p = subprocess.run(["python3", str(hook)],
                           input=json.dumps({"session_id": "s",
                                             "hook_event_name": "PreToolUse",
                                             "tool_name": "Bash",
                                             "tool_input": {"command": command}}),
                           capture_output=True, text=True, env=env, timeout=60)
        return p.returncode == 2


def test_copy_source_is_a_read(hook=None):
    hook = Path(hook or DEFAULT_HOOK)
    cases = [(n, c, d, None) for n, c, d in CASES] + \
            [(n, c, d, LEVEL1) for n, c, d in CASES_WITH_APPROVAL]
    failed = 0
    for name, command, want, approval in cases:
        got = _denied(hook, command, approval)
        ok = got == want
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name:44} "
              f"{'denied' if got else 'runs':8} (want: {'denied' if want else 'runs'})")
    print(f"\ncopy-source-is-a-read: {len(cases) - failed}/{len(cases)} passed")
    return failed


if __name__ == "__main__":
    sys.exit(1 if test_copy_source_is_a_read(
        sys.argv[1] if len(sys.argv) > 1 else None) else 0)
