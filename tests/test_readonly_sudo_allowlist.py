# ============================================================================
# Read-only commands in the escalation allowlist — and why that is not a hole.
#
# `sudo ls`, `sudo grep` and `sudo true` change nothing, yet they accounted for
# 47 of 910 real refusals: friction without protection. Adding them is only safe
# under one condition, and it is not obvious: `grep` and `cat` READ, with root
# rights. If this list decided reading, it would hand out /etc/shadow.
#
# It does not. protected_reads applies regardless of the allowlist, so
# `sudo cat /etc/shadow` stays refused while `sudo cat /var/log/syslog` runs.
# These cases pin that separation down — otherwise the next person to widen the
# list has no way to tell whether they just opened a door.
#
# The rules used here are the ones SHIPPED with the hook, not a fixture: the
# claim is about what an installation actually gets.
# ============================================================================
import json
import os
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
# Beside the hook under test, not beside this file: with GUARD_HOOK pointing at
# another copy, the rules of THAT copy are the ones whose claim is being checked.
EXAMPLE_RULES = HOOK.parent.parent / "security-rules.example.json"

READ_ONLY_EXPECTED = ["ls", "grep", "head", "tail", "true", "find"]


def _blocks(command: str) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = str(EXAMPLE_RULES)
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = str(tmp / "ov")
        env["CLAUDE_AUDIT_DIR"] = str(tmp / "audit")
        env["CLAUDE_HOOK_DEV_FLAG"] = str(tmp / "_no_window")
        env["CLAUDE_GUARD_CONFIG"] = str(tmp / "_no_config.json")
        p = subprocess.run(
            ["python3", str(HOOK)],
            input=json.dumps({"session_id": "readonly-sudo-test",
                              "tool_name": "Bash",
                              "tool_input": {"command": command}}),
            capture_output=True, text=True, env=env)
    return p.returncode == 2, f"exit {p.returncode}: {' '.join(p.stderr.split())[:150]}"


def _stays_free(command: str) -> tuple[bool, str]:
    blocked, detail = _blocks(command)
    return not blocked, detail


# --- the list is actually shipped -------------------------------------------

def check_read_only_commands_are_shipped():
    rules = json.loads(EXAMPLE_RULES.read_text(encoding="utf-8"))
    allowed = rules.get("allowed_sudo", [])
    missing = [c for c in READ_ONLY_EXPECTED if c not in allowed]
    return not missing, f"missing from allowed_sudo: {missing}"


# --- they run ---------------------------------------------------------------

def check_listing_runs():
    return _stays_free("sudo ls /var/log")


def check_searching_a_log_runs():
    return _stays_free("sudo grep error /var/log/syslog")


def check_doing_nothing_runs():
    return _stays_free("sudo true")


def check_checksum_runs():
    return _stays_free("sudo sha256sum /var/log/syslog")


# --- and they do NOT lift the read guard ------------------------------------

def check_system_password_file_still_refused():
    return _blocks("sudo cat /etc/shadow")


def check_searching_the_password_file_still_refused():
    return _blocks("sudo grep root /etc/shadow")


def check_private_key_still_refused():
    return _blocks("sudo cat ~/.ssh/id_rsa")


def check_public_key_still_runs():
    """The counter-case to the one above: a public key is not a secret."""
    return _stays_free("sudo cat ~/.ssh/id_rsa.pub")


def check_env_file_still_refused():
    return _blocks("sudo cat /opt/app/.env")


def check_packing_the_key_directory_still_refused():
    """The detour: not naming the key, taking its directory along."""
    return _blocks("sudo tar czf /tmp/keys.tgz ~/.ssh")


def check_deleting_still_refused():
    """The load-bearing counter-case: writing commands stay outside the list."""
    return _blocks("sudo rm -rf /var/tmp/x")


CASES = [
    ("read-only commands are shipped in the rules", check_read_only_commands_are_shipped),
    ("listing runs", check_listing_runs),
    ("searching a log runs", check_searching_a_log_runs),
    ("doing nothing runs", check_doing_nothing_runs),
    ("checksum runs", check_checksum_runs),
    ("system password file still refused", check_system_password_file_still_refused),
    ("searching the password file still refused",
     check_searching_the_password_file_still_refused),
    ("private key still refused", check_private_key_still_refused),
    ("public key still runs", check_public_key_still_runs),
    ("env file still refused", check_env_file_still_refused),
    ("packing the key directory still refused",
     check_packing_the_key_directory_still_refused),
    ("deleting still refused", check_deleting_still_refused),
]

try:
    import pytest

    @pytest.mark.parametrize("name,fn", CASES)
    def test_readonly_sudo_allowlist(name, fn):
        ok, detail = fn()
        assert ok, f"{name}: {detail}"

except ImportError:
    pass


if __name__ == "__main__":
    failures = 0
    for name, fn in CASES:
        ok, detail = fn()
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            print(f"      {detail}")
    raise SystemExit(0 if not failures else 1)
