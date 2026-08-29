#!/usr/bin/env python3
"""The three gaps where an installation is wrong and nothing complains.

Every other failure this tool catches is loud somewhere: a missing hook file
breaks a session, a broken rules file prints a warning. These three are silent
by construction —

  · `update_check.enabled` is on and no SessionStart hook runs the checker,
  · the VERSION file was not copied next to the hook, so the checker has
    nothing to compare and stays quiet — indistinguishable from "up to date",
  · the rules document for the assistant is missing, so it never learns that
    an approval channel exists and simply stops asking,
  · the proposal directory does not exist, so the documented approval path
    ends in an error the owner never sees.

Nothing is asserted about the real machine: every case runs against a
constructed HOME.
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TOOL = REPO / "tools" / "verify-install.py"
HOOK = REPO / "hooks" / "command-guard.py"

SOUND_RULES = {"blocked_paths_write": ["/etc"], "blocked_patterns": [],
               "owner_only_commands": ["grant-override", "hook-dev-mode"]}


def _build(home: Path, *, update_enabled=False, update_hook=False,
           version_file=False, rules_doc=True, pending=True):
    """A wired-up install, with the four optional pieces switched per case."""
    (home / ".claude" / "hooks").mkdir(parents=True, exist_ok=True)
    (home / ".claude" / "safety-guard").mkdir(parents=True, exist_ok=True)
    (home / ".claude" / "bin").mkdir(parents=True, exist_ok=True)
    if rules_doc:
        (home / ".claude" / "rules").mkdir(parents=True, exist_ok=True)
        (home / ".claude" / "rules" / "security-operations.md").write_text(
            "approval channel", encoding="utf-8")
    if pending:
        (home / ".claude" / ".sudo-overrides-pending").mkdir(
            parents=True, exist_ok=True)

    hook_path = home / ".claude" / "hooks" / "command-guard.py"
    hook_path.write_text(HOOK.read_text(encoding="utf-8"), encoding="utf-8")
    if version_file:
        (home / ".claude" / "hooks" / "VERSION").write_text(
            "2026.08.29", encoding="utf-8")
    (home / ".claude" / "safety-guard" / "security-rules.json").write_text(
        json.dumps(SOUND_RULES), encoding="utf-8")

    hooks = {"PreToolUse": [{"hooks": [
        {"type": "command", "command": f"python3 {hook_path}"}]}]}
    if update_hook:
        checker = home / ".claude" / "hooks" / "update-check.py"
        hooks["SessionStart"] = [{"hooks": [
            {"type": "command", "command": f"python3 {checker}"}]}]
    (home / ".claude" / "settings.json").write_text(
        json.dumps({"hooks": hooks}), encoding="utf-8")

    (home / ".claude" / "guard-config.json").write_text(json.dumps({
        "version": 1, "update_check": {"enabled": update_enabled},
    }), encoding="utf-8")


def _run(home: Path) -> str:
    env = dict(os.environ)
    env["HOME"] = str(home)
    for leaking in ("CLAUDE_SECURITY_RULES", "CLAUDE_GUARD_CONFIG",
                    "CLAUDE_HOOK_DEV_FLAG", "CLAUDE_SUDO_OVERRIDES_DIR"):
        env.pop(leaking, None)
    proc = subprocess.run([sys.executable, str(TOOL), "--wiring-only"],
                          capture_output=True, text=True, env=env, timeout=300)
    return proc.stdout


def _says(home_kwargs, needle) -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp)
        _build(home, **home_kwargs)
        return needle in _run(home)


# --- the update check ------------------------------------------------------

def check_enabled_without_a_session_hook_is_reported():
    return _says({"update_enabled": True, "version_file": True},
                 "no SessionStart hook")


def check_enabled_with_the_hook_is_accepted():
    return _says({"update_enabled": True, "update_hook": True,
                  "version_file": True}, "registered as a SessionStart hook")


def check_missing_version_file_is_reported():
    return _says({"update_enabled": True, "update_hook": True,
                  "version_file": False}, "no VERSION file next to the hook")


def check_disabled_update_check_stays_silent():
    # A tool that nags about a feature nobody switched on gets ignored — and
    # then it is not read when it matters.
    return not _says({"update_enabled": False}, "update check")


# --- the assistant's rules document ----------------------------------------

def check_missing_rules_document_is_reported():
    return _says({"rules_doc": False}, "security-operations.md")


def check_present_rules_document_is_accepted():
    return _says({"rules_doc": True}, "AI context")


# --- the proposal directory ------------------------------------------------

def check_missing_pending_directory_is_reported():
    return _says({"pending": False}, "nowhere to write a proposal")


def check_present_pending_directory_is_accepted():
    return _says({"pending": True}, "proposal directory ready")


CHECKS = [(name, fn) for name, fn in sorted(globals().items())
          if name.startswith("check_") and callable(fn)]


def test_verify_install_quiet_gaps():
    failed = [name for name, fn in CHECKS if not fn()]
    assert not failed, f"{len(failed)} of {len(CHECKS)} failed: {failed}"


if __name__ == "__main__":
    bad = [name for name, fn in CHECKS if not fn()]
    for name, _ in CHECKS:
        print(f"  {'FAIL' if name in bad else 'ok  '}  {name}")
    print(f"\n{len(CHECKS) - len(bad)} of {len(CHECKS)} passed")
    sys.exit(1 if bad else 0)
