# ============================================================================
# Two findings from replaying eight weeks of real refusals.
#
# 1. A REMOTE command is a passthrough. The path guard strips quoted sections
#    before looking for write targets — otherwise every mention in a text blocks
#    a command. For eval and `sh -c` it looks inside anyway, because the content
#    really runs. `ssh` was missing from that list, so
#    `ssh host "echo x > /etc/passwd"` went through untouched. That is not a
#    false-alarm question, it is a hole: the remote side is exactly where a
#    protected path matters.
#
# 2. A SHELL OPERATOR IS NOT A COMMAND. The escalation check took the first
#    token after `sudo` that does not start with `-`. In `sudo -n -l 2>&1` that
#    is `2>&1`, in `sudo -n -l | head` it is `|` — so listing one's own rights,
#    which changes nothing, was refused as soon as it was redirected or piped.
#    Measured: 26 real refusals where the rejected "command" was never a command.
#
#    The fix stops at the operator instead of skipping it. Skipping would be
#    wrong in the other direction: in `sudo -l | rm -rf x` the rm does NOT run
#    with raised rights, so attributing it to this sudo would be a false claim.
#    A LATER `sudo` in the same line is still found — one case pins that down.
# ============================================================================
import json
import os
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))

# Assembled at runtime so this file does not read as a write attempt itself when
# its own path shows up in a command line — that false alarm stopped the first
# measurement of exactly this topic.
_REDIR = ">"
WRITE_ETC = f"echo x {_REDIR} /etc/passwd"

RULES = {
    "blocked_paths_write": ["/etc/passwd", "/etc/sudoers"],
    "allowed_sudo": ["systemctl", "docker", "true"],
    "blocked_patterns": [], "blocked_git_ops": [], "protected_git_branches": [],
    "blocked_bash_patterns_force_push": [], "owner_only_commands": [],
    "protected_reads": {}, "require_confirmation": [],
}


def _blocks(command: str) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        (tmp / "rules.json").write_text(json.dumps(RULES), encoding="utf-8")
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = str(tmp / "rules.json")
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = str(tmp / "ov")
        env["CLAUDE_AUDIT_DIR"] = str(tmp / "audit")
        env["CLAUDE_HOOK_DEV_FLAG"] = str(tmp / "_no_window")
        env["CLAUDE_GUARD_CONFIG"] = str(tmp / "_no_config.json")
        p = subprocess.run(
            ["python3", str(HOOK)],
            input=json.dumps({"session_id": "passthrough-operator-test",
                              "tool_name": "Bash",
                              "tool_input": {"command": command}}),
            capture_output=True, text=True, env=env)
    return p.returncode == 2, f"exit {p.returncode}: {' '.join(p.stderr.split())[:150]}"


# --- 1. remote commands are a passthrough -----------------------------------

def check_remote_write_to_protected_path():
    return _blocks(f'ssh inox-main "{WRITE_ETC}"')


def check_remote_write_via_interpreter():
    return _blocks(f"ssh inox-main \"sh -c '{WRITE_ETC}'\"")


def check_remote_write_with_options_before_the_host():
    """Options in front must not hide the passthrough."""
    return _blocks(f'ssh -o ConnectTimeout=8 -p 2222 inox-main "{WRITE_ETC}"')


def check_mere_mention_stays_free():
    """A protected path inside a TEXT is not an access — the counter-case."""
    blocked, detail = _blocks(f'echo "never do {WRITE_ETC} anywhere"')
    return not blocked, detail


# --- 2. an operator is not a command ----------------------------------------

def check_listing_rights_redirected_stays_free():
    """`sudo -n -l 2>&1` lists rights and changes nothing."""
    blocked, detail = _blocks("sudo -n -l 2>&1")
    return not blocked, detail


def check_listing_rights_piped_stays_free():
    blocked, detail = _blocks("sudo -n -l | head -40")
    return not blocked, detail


def check_remote_listing_rights_stays_free():
    """The real-world shape from the log: rights listing across a remote call."""
    blocked, detail = _blocks('ssh inox-main "sudo -n -l 2>&1 | head -40"')
    return not blocked, detail


def check_allowed_sudo_command_stays_free():
    blocked, detail = _blocks("sudo systemctl status nginx")
    return not blocked, detail


def check_disallowed_sudo_command_still_blocked():
    """The load-bearing counter-case: a real command after sudo stays refused."""
    return _blocks("sudo rm -rf /var/tmp/x")


def check_later_sudo_in_the_same_line_is_found():
    """Stopping at the operator must not hide a SECOND sudo behind it."""
    return _blocks("sudo -n -l && sudo rm -rf /var/tmp/x")


def check_subcommand_gate_still_works():
    """systemctl is allowed, but tearing a service down is not read-only."""
    return _blocks("sudo systemctl stop nginx")


# --- 3. an operator STUCK to the name ---------------------------------------
#
# Found live, one command after the read-only entries were added to the shipped
# allowlist: `sudo -n true; echo done` arrives as the token `true;` and matches
# no entry, however complete the list is. The list was right, the comparison was
# wrong. A test list would not have found this — the shape only shows up when a
# person actually chains a command.

def check_allowed_command_with_trailing_semicolon():
    blocked, detail = _blocks("sudo -n true; echo done")
    return not blocked, detail


def check_allowed_command_with_glued_pipe():
    """No blank in front of the operator — the worst case for a name comparison."""
    blocked, detail = _blocks("sudo -n true|head -1")
    return not blocked, detail


def check_disallowed_command_with_trailing_semicolon_still_blocked():
    """The load-bearing counter-case: an operator must not launder a command."""
    return _blocks("sudo rm -rf /var/tmp/x; echo done")


def check_subcommand_gate_survives_a_trailing_operator():
    """Stripping the operator must not switch the subcommand gate off."""
    return _blocks("sudo systemctl stop nginx; echo done")


def check_glued_operator_does_not_donate_a_subcommand():
    """What follows a glued operator belongs to the NEXT command.

    `sudo systemctl;stop nginx` runs `sudo systemctl` (which does nothing without
    a subcommand) and then `stop nginx` — no service is touched, and `stop` is
    not systemctl's subcommand here. Reading it as one would be the same false
    claim as skipping the operator. systemctl on purpose: it is one of the tools
    that HAS a subcommand table, so the case can fail at all.
    """
    blocked, detail = _blocks("sudo systemctl;stop nginx")
    return not blocked, detail


CASES = [
    ("remote write to a protected path is blocked", check_remote_write_to_protected_path),
    ("remote write via interpreter is blocked", check_remote_write_via_interpreter),
    ("remote write with options in front is blocked",
     check_remote_write_with_options_before_the_host),
    ("a mere mention stays free", check_mere_mention_stays_free),
    ("redirected rights listing stays free", check_listing_rights_redirected_stays_free),
    ("piped rights listing stays free", check_listing_rights_piped_stays_free),
    ("remote rights listing stays free", check_remote_listing_rights_stays_free),
    ("allowed sudo command stays free", check_allowed_sudo_command_stays_free),
    ("disallowed sudo command still blocked", check_disallowed_sudo_command_still_blocked),
    ("a later sudo in the same line is found", check_later_sudo_in_the_same_line_is_found),
    ("subcommand gate still works", check_subcommand_gate_still_works),
    ("allowed command with trailing semicolon stays free",
     check_allowed_command_with_trailing_semicolon),
    ("allowed command with a glued pipe stays free",
     check_allowed_command_with_glued_pipe),
    ("disallowed command with trailing semicolon still blocked",
     check_disallowed_command_with_trailing_semicolon_still_blocked),
    ("subcommand gate survives a trailing operator",
     check_subcommand_gate_survives_a_trailing_operator),
    ("a glued operator donates no subcommand",
     check_glued_operator_does_not_donate_a_subcommand),
]

try:
    import pytest

    @pytest.mark.parametrize("name,fn", CASES)
    def test_passthrough_and_sudo_operators(name, fn):
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
