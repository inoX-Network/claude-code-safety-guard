# ============================================================================
# The self-protection refusal says WHAT was blocked.
#
# When an interpreter one-liner names a self-protected path, the guard blocks
# READING too (on purpose: such a line can write in the same breath, and the
# shell cannot see it). The refusal still said "write access" — whoever read
# it went looking for a write that was not there, and was not told that cat or
# grep would do.
#
# Checked: the verdict (unchanged, always blocked) AND the text.
# Pure dry run with the example rules. Nothing is executed.
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
TARGET = str(Path.home() / ".claude" / "settings.json")

# (command, word the refusal must contain, word it must not contain)
CASES = [
    (f"python3 -c \"print(open('{TARGET}').read())\"", "one-liner", "write access"),
    (f"node -e \"console.log(require('fs').readFileSync('{TARGET}','utf8'))\"",
     "one-liner", "write access"),
    # a writing one-liner gets the same text: the one-liner branch is what blocked
    (f"python3 -c \"open('{TARGET}','w').write('x')\"", "one-liner", "write access"),
    # a shell write stays "write access"
    (f"echo x > {TARGET}", "write access", "one-liner"),
    (f"cp /tmp/source {TARGET}", "write access", "one-liner"),
]


def _run(command: str) -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as ov:
        # an empty configuration: no language file, so the built-in English
        config = Path(ov) / "guard-config.json"
        config.write_text("{}", encoding="utf-8")
        env = dict(os.environ)
        env["CLAUDE_GUARD_CONFIG"] = str(config)
        env["CLAUDE_SECURITY_RULES"] = str(EXAMPLE_RULES)
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = ov
        env["CLAUDE_AUDIT_DIR"] = ov
        env["CLAUDE_HOOK_DEV_FLAG"] = ov + "/_none"
        payload = {"session_id": "inline-message-test", "hook_event_name": "PreToolUse",
                   "cwd": "/tmp", "tool_name": "Bash", "tool_input": {"command": command}}
        p = subprocess.run(["python3", str(HOOK)], input=json.dumps(payload),
                           capture_output=True, text=True, env=env)
        return p.returncode, p.stderr


@pytest.mark.parametrize("command,wanted,unwanted", CASES, ids=[c[:50] for c, _, _ in CASES])
def test_self_protect_inline_message(command, wanted, unwanted):
    rc, text = _run(command)
    assert rc == 2, command
    assert wanted in text and unwanted not in text, text
