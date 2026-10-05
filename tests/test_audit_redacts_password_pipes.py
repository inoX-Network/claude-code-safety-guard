#!/usr/bin/env python3
"""The audit log must not store a password that is piped into sudo.

The log redacted exactly one form: `echo '<pw>' | sudo`. Measured 2026-10-05
on a real installation: `printf '%s\\n' '<pw>' '<content>' | sudo -S tee <file>`
-- the password as the first line for sudo, the rest for tee -- went into the
log in clear text, 84 lines of it. The same holds for an unquoted echo, a
here-string, `--stdin`, a pipe into `ssh <host> sudo -S`, and `sshpass -p`.

The rule now: when a line hands sudo its password on stdin (`-S`/`--stdin`),
every echo/printf that feeds a pipe and every here-string in that line is
redacted. Redacting a little too much costs a log line its detail; redacting
too little leaves a password on disk. Lines without a stdin password keep their
content -- an audit log that hides everything is useless for the next audit.
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
PW = "Hunter2-Probe!x"


def _logged(command: str) -> str:
    """Run the hook on one Bash command and return what the audit log holds."""
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = str(REPO / "security-rules.example.json")
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = tmp + "/ov"
        env["CLAUDE_AUDIT_DIR"] = tmp + "/audit"
        env["CLAUDE_HOOK_DEV_FLAG"] = tmp + "/_none"
        env["CLAUDE_GUARD_CONFIG"] = tmp + "/_no_config.json"
        payload = {"tool_name": "Bash", "tool_input": {"command": command},
                   "session_id": "redact", "hook_event_name": "PreToolUse", "cwd": tmp}
        subprocess.run([sys.executable, str(HOOK)], input=json.dumps(payload),
                       capture_output=True, text=True, env=env, timeout=60, cwd=tmp)
        log = Path(tmp) / "audit" / "actions.jsonl"
        return log.read_text(encoding="utf-8") if log.exists() else ""


def _hidden(command: str) -> bool:
    text = _logged(command)
    return bool(text) and PW not in text and "[REDACTED]" in text


# --- password pipes: the password must not reach the log -------------------

def check_echo_quoted():                      # the one form covered before
    return _hidden(f"echo '{PW}' | sudo -S ls /root")


def check_echo_unquoted():
    return _hidden(f"echo {PW} | sudo -S ls /root")


def check_printf_single():
    return _hidden(f"printf '%s\\n' '{PW}' | sudo -S ls /root")


def check_printf_password_then_content():     # the measured leak
    return _hidden(f"printf '%s\\n' '{PW}' 'line one' 'line two' | sudo -S tee /tmp/x.conf")


def check_inside_ssh_quotes():
    return _hidden(f"ssh host \"printf '%s\\n' '{PW}' | sudo -S ls /root\"")


def check_pipe_into_ssh_sudo():
    return _hidden(f"echo '{PW}' | ssh host sudo -S ls /root")


def check_here_string():
    return _hidden(f"sudo -S ls /root <<< '{PW}'")


def check_here_string_unquoted():
    return _hidden(f"sudo -S ls /root <<<{PW}")


def check_long_option_stdin():
    # printf, not echo: the old echo rule would hide the result either way.
    return _hidden(f"printf '%s\\n' '{PW}' | sudo --stdin ls /root")


def check_combined_short_flags():
    return _hidden(f"printf '%s\\n' '{PW}' | sudo -kS ls /root")


def check_sshpass():
    return _hidden(f"sshpass -p '{PW}' ssh host ls")


def check_sshpass_attached():
    return _hidden(f"sshpass -p{PW} ssh host ls")


# --- the forms measured in the real log (84 lines) ----------------------------
# 79 of them: the password in a variable, used later as "$PW". 3: printf. 2: a
# brace group { echo "<pw>"; cat; } | sudo -S.

def check_variable_then_use():
    return _hidden(f"PW='{PW}'; echo \"$PW\" | sudo -S ls /root")


def check_variable_inside_ssh():
    return _hidden(f"ssh host 'PW=\"{PW}\"; echo \"$PW\" | sudo -S ls /root'")


def check_unremarkable_variable_name():
    # In a password line the name does not matter -- X holds it just as well.
    return _hidden(f"X='{PW}'; echo \"$X\" | sudo -S ls /root")


def check_suffixed_secret_name():
    # The old rule wanted 'password' as a whole word; DB_PASSWORD= slipped by.
    # Measured: hundreds of such lines in a real log.
    return _hidden(f"DB_PASSWORD='{PW}' docker compose up -d")


def check_named_variable_without_stdin():
    # SUDO_PW=... kept for later -- the name alone says what it holds.
    return _hidden(f"SUDO_PW='{PW}' ./deploy.sh")


def check_brace_group():
    return _hidden(f"{{ echo \"{PW}\"; cat /tmp/unit; }} | sudo -S tee /etc/x.service")


def check_askpass_file_written():
    # The 84th line: no sudo -S at all -- the password went into an askpass
    # file for later sudo -A calls.
    return _hidden(f"printf '%s\\n' '{PW}' | ssh host 'umask 077; cat > \"$HOME/.deploy_askpass_pw\"'")


def _hidden_value(value: str, command: str) -> bool:
    text = _logged(command)
    return bool(text) and value not in text and "[REDACTED]" in text


def check_password_with_semicolon():
    # A matcher that stops at ';' would leave the tail of the password behind.
    pw = "ab;cd-Probe7"
    return _hidden_value("cd-Probe7", f"echo '{pw}' | sudo -S ls /root")


def check_password_with_pipe():
    pw = "ab|cd-Probe8"
    return _hidden_value("cd-Probe8", f"printf '%s\\n' '{pw}' | sudo -S ls /root")


def check_password_with_ampersand_double_quotes():
    pw = "ab&cd-Probe9"
    return _hidden_value("cd-Probe9", f"echo \"{pw}\" | sudo -S ls /root")


# --- what must keep its content -----------------------------------------------

def check_plain_pipe_keeps_content():
    text = _logged("echo hello-visible | grep hello")
    return "hello-visible" in text and "[REDACTED]" not in text


def check_sudo_without_stdin_keeps_content():
    # tee gets file content, not a password -- the log should still say what.
    text = _logged("printf '%s\\n' 'content-visible' | sudo tee /tmp/x.conf")
    return "content-visible" in text


def check_command_after_redaction_still_readable():
    text = _logged(f"echo '{PW}' | sudo -S systemctl restart nginx")
    return PW not in text and "systemctl restart nginx" in text


CHECKS = [(name, fn) for name, fn in sorted(globals().items())
          if name.startswith("check_") and callable(fn)]


def test_audit_redacts_password_pipes():
    failed = [name for name, fn in CHECKS if not fn()]
    assert not failed, f"{len(failed)} of {len(CHECKS)} failed: {failed}"


if __name__ == "__main__":
    bad = [name for name, fn in CHECKS if not fn()]
    for name, _ in CHECKS:
        print(f"  {'FAIL' if name in bad else 'ok  '}  {name}")
    print(f"\n{len(CHECKS) - len(bad)} of {len(CHECKS)} passed")
    sys.exit(1 if bad else 0)
