#!/usr/bin/env python3
"""Environment files named `name.env` are protected like `.env` and `.env.*`.

This is the form docker compose reads through `env_file:` — `billing-db.env`,
`mail.env`, `api-keys.env`. The docstring of check_env_file_read always said
".env at the end of the filename", but the code only matched `.env`, `.env.*`
and `.envrc`. Measured 2026-09-29: `cat config/prod.env` ran free.

Pinned here:

  1. Reading a `name.env` file is blocked — Bash, over ssh, and the Read tool.
  2. `process.env` and `import.meta.env` are code, not files, and stay free.
  3. Templates (`name.env.example`) stay free, and the old controls still hold.

Cost, measured on the author's audit log (210k allowed Bash calls): 228 calls
in 48 sessions would now need an override, against 1678 env denials that
already happened — real reads of key files and the same prose false positives
`.env.local` already had.
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
E = "." + "env"   # keeps the suffix out of this file's own text


def _judge(tool, tool_input):
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = str(RULES)
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = tmp
        env["CLAUDE_AUDIT_DIR"] = tmp
        env["CLAUDE_HOOK_DEV_FLAG"] = tmp + "/_none"
        env["CLAUDE_GUARD_CONFIG"] = tmp + "/_no_config.json"
        payload = {"tool_name": tool, "tool_input": tool_input,
                   "session_id": "env-name-suffix", "cwd": tmp,
                   "hook_event_name": "PreToolUse"}
        r = subprocess.run([sys.executable, str(HOOK)], input=json.dumps(payload),
                           capture_output=True, text=True, env=env, timeout=60, cwd=tmp)
        return r.returncode


def _bash(command):
    return _judge("Bash", {"command": command})


# --- 1. name.env is an environment file --------------------------------------

def check_cat_name_env_blocked():
    return _bash(f"cat config/prod{E}") == 2


def check_grep_in_name_env_blocked():
    return _bash(f"grep -c API_KEY billing-db{E}") == 2


def check_sourcing_name_env_blocked():
    return _bash(f". ./mail{E}") == 2


def check_ssh_read_of_name_env_blocked():
    return _bash(f"ssh prod 'cat /opt/app/env/api-keys{E}'") == 2


def check_read_tool_on_name_env_blocked():
    return _judge("Read", {"file_path": f"/srv/forge{E}"}) == 2


# --- 2. code that looks like it, is not ----------------------------------------

def check_process_env_in_code_free():
    return _bash(f"grep -rn 'process{E}.API_URL' src/") == 0


def check_import_meta_env_in_code_free():
    return _bash(f"grep -rn 'import.meta{E}' src/") == 0


# --- 3. templates and old controls -------------------------------------------

def check_name_env_template_free():
    return _bash(f"cat prod{E}.example") == 0


def check_dot_env_still_blocked():
    return _bash(f"cat {E}") == 2


def check_dot_env_example_still_free():
    return _bash(f"cat {E}.example") == 0


def check_word_environment_free():
    return _bash("echo environment") == 0


CHECKS = [(name, fn) for name, fn in sorted(globals().items())
          if name.startswith("check_") and callable(fn)]


def test_env_name_suffix():
    failed = [name for name, fn in CHECKS if not fn()]
    assert not failed, f"{len(failed)} of {len(CHECKS)} failed: {failed}"


if __name__ == "__main__":
    bad = [name for name, fn in CHECKS if not fn()]
    for name, _ in CHECKS:
        print(f"  {'FAIL' if name in bad else 'ok  '}  {name}")
    print(f"\n{len(CHECKS) - len(bad)} of {len(CHECKS)} passed")
    sys.exit(1 if bad else 0)
