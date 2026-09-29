# ============================================================================
# Which command behind sudo REALLY runs with raised rights?
#
# The shell removes quotes, and a redirection (>, 2>&1, &>, <<<) does not end a
# command — it may stand anywhere, before the command name too. Only ; | & &&
# || and parentheses end it; whatever follows runs WITHOUT sudo.
#
# The guard used to stop at EVERY operator. That let these past the sudo
# allowlist (security, found 2026-09-29):
#     sudo 2>/dev/null <anything>
#     sudo "systemctl" stop nginx
#     sudo systemctl>/dev/null stop nginx     (subcommand gate skipped)
#
# Pure dry run with the example rules at level 0. Nothing is executed.
# ============================================================================
import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
EXAMPLE_RULES = REPO / "security-rules.example.json"

ALLOW = 0
BLOCK = 2

# Must block: the command runs with raised rights, however it is wrapped.
MUST_BLOCK = [
    "sudo systemctl stop nginx",
    "sudo >/dev/null systemctl stop nginx",
    "sudo > /dev/null systemctl stop nginx",
    "sudo 2>/dev/null systemctl stop nginx",
    "sudo &>/dev/null systemctl stop nginx",
    "sudo -n 2>&1 systemctl stop nginx",
    "sudo -S <<<x systemctl stop nginx",
    'sudo "systemctl" stop nginx',
    "sudo 'systemctl' 'stop' nginx",
    "sudo sys\\temctl stop nginx",
    "sudo systemctl>/dev/null stop nginx",
    "sudo systemctl 2>/dev/null stop nginx",
    'sudo systemctl "stop" nginx',
    "sudo reboot",
    'sudo "reboot"',
    "sudo 2>&1 reboot",
    # a LATER sudo in the same line is a finding of its own
    "sudo -v; sudo reboot",
    "sudo -l | sudo reboot",
    "sudo true && sudo 2>/dev/null reboot",
    # >| is a redirection (overwrite despite noclobber), not a pipe
    "sudo >|/tmp/x reboot",
    # "1" in quotes is a word, not a descriptor number
    'sudo "1">/dev/null',
]

# Must stay free: nothing runs with raised rights that is not allowed.
MUST_ALLOW = [
    "sudo -n -l 2>&1",
    "sudo -l | grep x",
    "sudo -S -v; echo done",
    "sudo -S -v;echo done",
    "sudo -S -v&&echo done",
    "sudo true; echo done",
    "sudo true;echo done",
    "sudo -n true && echo ok",
    "sudo ls|wc -l",
    "sudo systemctl status nginx 2>&1",
    "sudo systemctl status nginx >/dev/null",
    "sudo systemctl 2>/dev/null status nginx",
    "sudo systemctl status nginx | grep active",
    "sudo systemctl status nginx;echo done",
    'sudo "ls" /var/log',
    # the backslash goes, as in the shell
    "sudo l\\s /var/log",
    # a newline ends the command
    "sudo -S -v\necho done",
    "sudo -v & echo done",
    # ; and && end it even with a redirection glued on — reboot here runs
    # WITHOUT raised rights
    "sudo -v;>/tmp/x reboot",
    "sudo -v&&>/tmp/x reboot",
]

CASES = [(c, BLOCK) for c in MUST_BLOCK] + [(c, ALLOW) for c in MUST_ALLOW]


def _run(command: str) -> int:
    with tempfile.TemporaryDirectory() as ov:
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = str(EXAMPLE_RULES)
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = ov
        env["CLAUDE_AUDIT_DIR"] = ov
        env["CLAUDE_HOOK_DEV_FLAG"] = ov + "/_none"
        payload = {"session_id": "sudo-words-test", "hook_event_name": "PreToolUse",
                   "cwd": "/tmp", "tool_name": "Bash", "tool_input": {"command": command}}
        return subprocess.run(["python3", str(HOOK)], input=json.dumps(payload),
                              capture_output=True, text=True, env=env).returncode


@pytest.mark.parametrize("command,expected", CASES, ids=[c for c, _ in CASES])
def test_sudo_words(command, expected):
    assert _run(command) == expected, command
