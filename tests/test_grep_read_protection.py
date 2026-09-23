#!/usr/bin/env python3
"""The Grep tool prints file contents — it gets the read protection grep gets.

Measured 2026-09-23, two layers:

  1. Wiring. The example settings had no PreToolUse matcher for Grep, so the
     hook never saw it. Every read protection was one search away.
  2. Verdict. Even when asked, the hook compared the named path by prefix, the
     way it does for Read: a key FILE was caught, its DIRECTORY was not. Grep
     on the credential directory, or on a project with a filter for .env files,
     passed — while `grep -r` on the same directory in Bash was refused.

Layer 1 is pinned in test_verify_install.py and
test_settings_example_session_start.py. This file pins layer 2, and the other
side of it: an ordinary search stays free, and so does Glob, which lists names
and reads nothing.

Payload over stdin, dry run only — no file is opened.
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
HOME = str(Path.home())
EXAMPLE = json.loads((REPO / "security-rules.example.json").read_text(encoding="utf-8"))


def _code(tool, tool_input, cwd=None):
    with tempfile.TemporaryDirectory() as tmp:
        rules = Path(tmp) / "rules.json"
        rules.write_text(json.dumps(EXAMPLE), encoding="utf-8")
        payload = {"tool_name": tool, "tool_input": tool_input,
                   "session_id": "grep-read", "hook_event_name": "PreToolUse",
                   "cwd": cwd or tmp}
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = str(rules)
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = tmp
        env["CLAUDE_AUDIT_DIR"] = tmp
        env["CLAUDE_HOOK_DEV_FLAG"] = tmp + "/_none"
        env["CLAUDE_GUARD_CONFIG"] = tmp + "/_no_config.json"
        return subprocess.run([sys.executable, str(HOOK)], input=json.dumps(payload),
                              capture_output=True, text=True, env=env, timeout=60,
                              cwd=tmp).returncode


def _grep(**tool_input):
    return _code("Grep", {"pattern": ".", **tool_input})


# --- what passed before the fix ------------------------------------------------

def check_grep_on_the_key_directory_is_gated():
    return _grep(path=f"{HOME}/.ssh") == 2


def check_grep_on_the_cloud_credentials_directory_is_gated():
    return _grep(path=f"{HOME}/.aws") == 2


def check_grep_with_an_env_filter_is_gated():
    return _grep(path=f"{HOME}/proj", glob=".env") == 2


def check_grep_over_the_whole_home_is_gated():
    # Same as `grep -r x ~` in Bash: the home directory holds the keys.
    return _grep(path=HOME) == 2


def check_grep_without_a_path_searches_the_working_directory():
    # No path means the working directory. Started in the home directory, that
    # is the home directory — and it must not be a way around the rule above.
    return _code("Grep", {"pattern": "."}, cwd=HOME) == 2


def check_grep_with_a_relative_path_is_resolved():
    return _code("Grep", {"pattern": ".", "path": ".ssh"}, cwd=HOME) == 2


# --- what was already caught, and must stay so ---------------------------------

def check_grep_on_a_key_file_is_gated():
    return _grep(path=f"{HOME}/.ssh/id_ed25519") == 2


def check_grep_on_an_env_file_is_gated():
    return _grep(path=f"{HOME}/proj/.env") == 2


def check_bash_grep_on_the_key_directory_is_gated():
    # The reference the tool is measured against.
    return _code("Bash", {"command": f"grep -r x {HOME}/.ssh"}) == 2


# --- what must stay free -------------------------------------------------------

def check_ordinary_search_in_a_project_stays_free():
    return _grep(path=f"{HOME}/Projekte/some-project") == 0


def check_search_with_a_code_filter_stays_free():
    return _grep(path=f"{HOME}/Projekte/some-project", glob="*.py") == 0


def check_env_example_filter_stays_free():
    # Templates are not secrets — the same exemption the .env check has.
    return _grep(path=f"{HOME}/Projekte/some-project", glob=".env.example") == 0


def check_glob_on_the_key_directory_stays_free():
    # Glob lists names and reads nothing, like `ls ~/.ssh`.
    return _code("Glob", {"pattern": "**/id_*", "path": f"{HOME}/.ssh"}) == 0


CHECKS = [(name, fn) for name, fn in sorted(globals().items())
          if name.startswith("check_") and callable(fn)]


def test_grep_read_protection():
    failed = [name for name, fn in CHECKS if not fn()]
    assert not failed, f"{len(failed)} of {len(CHECKS)} failed: {failed}"


if __name__ == "__main__":
    bad = [name for name, fn in CHECKS if not fn()]
    for name, _ in CHECKS:
        print(f"  {'FAIL' if name in bad else 'ok  '}  {name}")
    print(f"\n{len(CHECKS) - len(bad)} of {len(CHECKS)} passed")
    sys.exit(1 if bad else 0)
