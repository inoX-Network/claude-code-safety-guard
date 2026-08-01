# ============================================================================
# Packing up a directory must not walk around the read guard of its files.
#
# The read guard only ever saw commands that named a protected file. Whoever
# packed, copied or grepped its DIRECTORY took the file along, and nothing
# fired: `cat /etc/shadow` was denied, `tar czf x.tgz /etc` went through.
#
# Two protection tiers with DIFFERENT outcomes — that is the point:
#   hard    (always_blocked_reads) -> denied even with an override
#   level 1 (require_override_1)   -> allowed with an override
#
# Usage:  python3 tests/test_bulk_directory_reads.py [path-to-hook]
# Every case is a dry run: no command is executed.
# ============================================================================
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_HOOK = REPO / "hooks" / "command-guard.py"
HOME = str(Path.home())

RULES = {
    "protected_reads": {
        "always_blocked_reads": ["/etc/shadow", "/etc/gshadow"],
        "require_override_1": ["~/.ssh/id_", "~/.gnupg/"],
        "always_allowed": ["~/.ssh/*.pub"],
        "env_files_require_override_1": [],
    },
}

LEVEL1 = {
    "override_level": 1, "task": "test", "confirmed": True,
    "expires_at": "2099-01-01T00:00:00+00:00",
    "grants": {"allowed_paths": ["/tmp"], "additional_sudo": []},
}

# (description, command, denied_without_override, denied_with_override)
CASES = [
    # --- a hard-protected file inside the directory: stays denied ------------
    ("pack it up (tar)",            "tar czf /tmp/x.tgz /etc",           True, True),
    ("grep through it",             "grep -r secret /etc",               True, True),
    ("zip it up",                   "zip -r /tmp/x.zip /etc",            True, True),
    ("rsync it away",               "rsync -a /etc/ /tmp/etc-copy/",     True, True),
    ("copy it recursively",         "cp -r /etc /tmp/etc-copy",          True, True),
    ("pack it via a detour",        "tar czf /tmp/x.tgz /etc/../etc",    True, True),
    ("pack it with a trailing slash", "tar czf /tmp/x.tgz /etc/",        True, True),
    ("name the file itself",        "tar czf /tmp/x.tgz /etc/shadow",    True, True),

    # --- level-1 directories: an override still lifts it --------------------
    ("pack up the keys",            f"tar czf /tmp/k.tgz {HOME}/.ssh",   True, False),
    ("grep through the keyring",    f"grep -r pattern {HOME}/.gnupg",    True, False),
    ("pack the keys via a detour",  f"tar czf /tmp/k.tgz {HOME}/.ssh/../.ssh",
                                                                          True, False),

    # --- the direct path stays exactly as it was ----------------------------
    ("read the hard file directly", "cat /etc/shadow",                   True, True),
    ("read a key directly",         f"cat {HOME}/.ssh/id_rsa",           True, False),

    # --- counter-checks: these MUST stay free -------------------------------
    ("pack a project directory",    "tar czf /tmp/p.tgz /tmp/project",   False, False),
    ("grep a project directory",    "grep -r pattern /tmp/project",      False, False),
    ("copy a scratch directory",    "cp -r /tmp/src /tmp/dst",           False, False),
    ("merely list it",              f"ls -la {HOME}/.ssh",               False, False),
    ("a neighbour with a similar name", "tar czf /tmp/n.tgz /etcetera",  False, False),
    ("a subdirectory without a protected file", "grep -r pattern /etc/apt",
                                                                          False, False),
    ("a public key",                f"cat {HOME}/.ssh/id_rsa.pub",       False, False),
    # Boundary-exact: '/etc/sha' is not an ancestor directory of '/etc/shadow',
    # only a name prefix. A plain prefix compare would deny this — that is the
    # mutation probe against over-blocking.
    ("a name prefix of a protected path", "tar czf /tmp/s.tgz /etc/sha", False, False),
]


def _denied(hook, command, override=None):
    with tempfile.TemporaryDirectory() as ov:
        rules_path = os.path.join(ov, "rules.json")
        with open(rules_path, "w", encoding="utf-8") as f:
            json.dump(RULES, f)
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = rules_path
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = ov
        env["CLAUDE_AUDIT_DIR"] = ov
        env["CLAUDE_HOOK_DEV_FLAG"] = ov + "/_none"
        if override:
            with open(os.path.join(ov, "test.json"), "w", encoding="utf-8") as f:
                json.dump(override, f)
        p = subprocess.run(["python3", str(hook)],
                           input=json.dumps({"session_id": "s",
                                             "hook_event_name": "PreToolUse",
                                             "tool_name": "Bash",
                                             "tool_input": {"command": command}}),
                           capture_output=True, text=True, env=env, timeout=60)
        return p.returncode == 2


def run_all(hook=None):
    hook = Path(hook or DEFAULT_HOOK)
    failed = 0
    for name, command, want0, want1 in CASES:
        got0 = _denied(hook, command)
        got1 = _denied(hook, command, LEVEL1)
        ok0, ok1 = got0 == want0, got1 == want1
        failed += (not ok0) + (not ok1)
        print(f"{'PASS' if ok0 and ok1 else 'FAIL'}  {name:38} "
              f"no-override: {'denied' if got0 else 'free':6} "
              f"level-1: {'denied' if got1 else 'free':6}")

    total = len(CASES) * 2
    print(f"\nbulk-directory-reads: {total - failed}/{total} passed")
    return failed


def test_bulk_directory_reads():
    """pytest entry point: a return value would be IGNORED here.

    Without the assert pytest reports the file as passed no matter how
    the cases turn out. That is how a real failure stayed invisible.
    """
    assert run_all() == 0


if __name__ == "__main__":
    sys.exit(1 if run_all(
        sys.argv[1] if len(sys.argv) > 1 else None) else 0)
