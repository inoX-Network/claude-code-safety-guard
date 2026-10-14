#!/usr/bin/env python3
"""A hook file that cannot be loaded must deny, not allow.

The crash net (test_guard_crash_denies.py) lives INSIDE command-guard.py. A
syntax error from an edit, or a file that is not there, stops Python before any
of it runs: exit 1, and the tool chain treats a hook that fails as "not
blocking" — the call goes through. Measured 2026-10-14 on copies of the
release: a broken copy exits 1 bare and 2 behind the wrapper; harmless and
blocked commands come out the same either way.

So the shipped configuration runs the guard behind a one-line wrapper that maps
every failure onto 2, and verify-install says so when an entry runs it bare.
These checks pin both halves: the example and INSTALL.md carry the wrapper, the
wrapper does what it says, and verify-install notices when it is missing.

Every hook run is a dry run: input on stdin, only the exit code is read.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = REPO / "hooks" / "command-guard.py"
TOOL = REPO / "tools" / "verify-install.py"
EXAMPLE_SETTINGS = REPO / "settings.example.json"
INSTALL = REPO / "INSTALL.md"
EXAMPLE_RULES = REPO / "security-rules.example.json"

HARMLESS = "echo hello"
BLOCKED = "chmod -R 777 /etc"


def _guard_commands(settings: dict) -> list[str]:
    return [h["command"] for e in settings.get("hooks", {}).get("PreToolUse", [])
            for h in e.get("hooks", []) if "command-guard" in h.get("command", "")]


EXAMPLE_COMMANDS = _guard_commands(json.loads(EXAMPLE_SETTINGS.read_text(encoding="utf-8")))


def _launch(command_template: str, hook: Path, command: str) -> int:
    """Run the registered command line the way the tool chain does: through a shell."""
    line = command_template.replace("~/.claude/hooks/command-guard.py", str(hook))
    payload = json.dumps({"session_id": "s", "hook_event_name": "PreToolUse",
                          "tool_name": "Bash", "tool_input": {"command": command}})
    with tempfile.TemporaryDirectory() as state:
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = str(EXAMPLE_RULES)
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = state
        env["CLAUDE_AUDIT_DIR"] = state
        env["CLAUDE_HOOK_DEV_FLAG"] = state + "/_none"
        return subprocess.run(["/bin/sh", "-c", line], input=payload, capture_output=True,
                              text=True, env=env, timeout=60).returncode


def _broken_copy(tmp: Path) -> Path:
    broken = tmp / "command-guard.py"
    broken.write_text(HOOK.read_text(encoding="utf-8") + "\ndef broken(:\n", encoding="utf-8")
    return broken


# --- the shipped configuration ----------------------------------------------

def check_example_wraps_every_guard_entry():
    return len(EXAMPLE_COMMANDS) == 8 and all(
        re.search(r"\|\|.*\bexit\s+2\b", c) for c in EXAMPLE_COMMANDS)


def check_install_md_shows_the_same_command():
    text = INSTALL.read_text(encoding="utf-8")
    return EXAMPLE_COMMANDS[0] in text and "python3 ~/.claude/hooks/command-guard.py\" }" not in text


# --- the wrapper does what it says ------------------------------------------

def check_broken_hook_is_denied_behind_the_wrapper():
    with tempfile.TemporaryDirectory() as tmp:
        return _launch(EXAMPLE_COMMANDS[0], _broken_copy(Path(tmp)), HARMLESS) == 2


def check_broken_hook_bare_would_allow():
    # The reason the wrapper exists. If this ever stops holding, the tool chain
    # changed and the wrapper is worth a second look, not removal by reflex.
    with tempfile.TemporaryDirectory() as tmp:
        return _launch("python3 ~/.claude/hooks/command-guard.py",
                       _broken_copy(Path(tmp)), HARMLESS) == 1


def check_missing_hook_is_denied_behind_the_wrapper():
    with tempfile.TemporaryDirectory() as tmp:
        return _launch(EXAMPLE_COMMANDS[0], Path(tmp) / "nothing-here.py", HARMLESS) == 2


def check_wrapper_keeps_harmless_allowed():
    return _launch(EXAMPLE_COMMANDS[0], HOOK, HARMLESS) == 0


def check_wrapper_keeps_blocked_blocked():
    return _launch(EXAMPLE_COMMANDS[0], HOOK, BLOCKED) == 2


# --- verify-install notices a bare entry -------------------------------------

def _verify(commands: list[str]) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp)
        hooks = home / ".claude" / "hooks"
        hooks.mkdir(parents=True)
        hook_path = hooks / "command-guard.py"
        hook_path.write_text(HOOK.read_text(encoding="utf-8"), encoding="utf-8")
        entries = [{"hooks": [{"type": "command", "command": c.replace("{hook}", str(hook_path))}]}
                   for c in commands]
        (home / ".claude" / "settings.json").write_text(
            json.dumps({"hooks": {"PreToolUse": entries}}), encoding="utf-8")
        env = dict(os.environ)
        env["HOME"] = str(home)
        for leaking in ("CLAUDE_SECURITY_RULES", "CLAUDE_GUARD_CONFIG",
                        "CLAUDE_HOOK_DEV_FLAG", "CLAUDE_SUDO_OVERRIDES_DIR"):
            env.pop(leaking, None)
        return subprocess.run([sys.executable, str(TOOL), "--wiring-only"], capture_output=True,
                              text=True, env=env, timeout=300).stdout


WRAPPED = "python3 {hook} || { echo guard failed to load >&2; exit 2; }"
BARE = "python3 {hook}"


def check_bare_entry_is_reported():
    return "run the hook bare" in _verify([BARE])


def check_wrapped_entry_is_accepted():
    out = _verify([WRAPPED])
    return "fail closed if the hook cannot be loaded" in out and "run the hook bare" not in out


def check_mixed_entries_name_the_count():
    return "1 of 2 guard entries run the hook bare" in _verify([WRAPPED, BARE])


CHECKS = [(name, fn) for name, fn in sorted(globals().items())
          if name.startswith("check_") and callable(fn)]


def test_fail_closed_launch():
    failed = [name for name, fn in CHECKS if not fn()]
    assert not failed, f"{len(failed)} of {len(CHECKS)} failed: {failed}"


if __name__ == "__main__":
    bad = [name for name, fn in CHECKS if not fn()]
    for name, _ in CHECKS:
        print(f"  {'FAIL' if name in bad else 'ok  '}  {name}")
    print(f"\n{len(CHECKS) - len(bad)} of {len(CHECKS)} passed")
    sys.exit(1 if bad else 0)
