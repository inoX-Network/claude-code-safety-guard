#!/usr/bin/env python3
"""What has to hold when the rules file is gone.

`load_rules()` falls back to a hardcoded minimal set and says so:
"FALLBACK ruleset active (fail-closed)". Measured 2026-08-29, three of the
things a reader would expect from that sentence were not in the set —
owner-only commands, git safety, and delete protection. The message created
trust the behaviour did not cover.

The chain that made this more than cosmetic: the rules file's PARENT directory
is not protected, so removing it is allowed; the pending directory is open by
design; and the approval script was, without `owner_only_commands`, an ordinary
command. Three allowed steps, and the assistant holds a level-2 grant.

`test_fail_closed.py` covers the other half — that blocked_patterns,
self-protection and read protection still hold in the fallback.
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


def _run(command, rules_present):
    """Judge one command with the rules file present or missing."""
    payload = {"tool_name": "Bash", "tool_input": {"command": command},
               "session_id": "fallback-completeness", "hook_event_name": "PreToolUse"}
    with tempfile.TemporaryDirectory() as tmp:
        if rules_present:
            rules = json.loads((REPO / "security-rules.example.json").read_text(
                encoding="utf-8"))
            path = Path(tmp) / "rules.json"
            path.write_text(json.dumps(rules), encoding="utf-8")
        else:
            path = Path(tmp) / "does-not-exist.json"
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = str(path)
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = tmp
        env["CLAUDE_AUDIT_DIR"] = tmp
        env["CLAUDE_HOOK_DEV_FLAG"] = tmp + "/_none"
        return subprocess.run([sys.executable, str(HOOK)], input=json.dumps(payload),
                              capture_output=True, text=True, env=env,
                              timeout=60, cwd=tmp).returncode


def _blocked_without_rules(command):
    """Blocked in the fallback — and blocked with rules too, or the case would
    not be about the fallback at all."""
    return _run(command, False) == 2 and _run(command, True) == 2


# --- the approval scripts ---------------------------------------------------

def check_approval_script_is_owner_only_in_the_fallback():
    return _blocked_without_rules(
        f"{HOME}/.claude/bin/grant-override self --minutes 120 --confirm FULL")


def check_dev_mode_script_is_owner_only_in_the_fallback():
    return _blocked_without_rules(f"{HOME}/.claude/bin/hook-dev-mode on 240")


def check_approval_script_without_a_path_is_owner_only():
    return _blocked_without_rules("grant-override self --minutes 60")


# --- git safety -------------------------------------------------------------

def check_reset_hard_blocked_in_the_fallback():
    return _blocked_without_rules("git reset --hard origin/main")


def check_no_verify_blocked_in_the_fallback():
    return _blocked_without_rules("git commit --no-verify -m x")


def check_amend_blocked_in_the_fallback():
    return _blocked_without_rules("git commit --amend -m x")


def check_add_all_blocked_in_the_fallback():
    return _blocked_without_rules("git add -A")


def check_writing_git_config_blocked_in_the_fallback():
    return _blocked_without_rules("git config user.email x@example.org")


# --- delete protection ------------------------------------------------------

def check_transcripts_not_deletable_in_the_fallback():
    return _blocked_without_rules(f"rm -rf {HOME}/.claude/projects")


# --- what must still run ----------------------------------------------------

def check_reading_git_config_stays_free():
    return _run("git config --get user.email", False) == 0


def check_ordinary_git_stays_free():
    return _run("git add README.md && git commit -m 'ordinary'", False) == 0


def check_ordinary_command_stays_free():
    return _run("ls -la /tmp", False) == 0


def check_writing_a_memory_entry_stays_free():
    # The delete list must not become a write block — that is the distinction
    # the whole second list exists for.
    return _run(f"echo x > {HOME}/.claude/projects/p/memory/note.md", False) == 0


CHECKS = [(name, fn) for name, fn in sorted(globals().items())
          if name.startswith("check_") and callable(fn)]


def test_fallback_ruleset_completeness():
    failed = [name for name, fn in CHECKS if not fn()]
    assert not failed, f"{len(failed)} of {len(CHECKS)} failed: {failed}"


if __name__ == "__main__":
    bad = [name for name, fn in CHECKS if not fn()]
    for name, _ in CHECKS:
        print(f"  {'FAIL' if name in bad else 'ok  '}  {name}")
    print(f"\n{len(CHECKS) - len(bad)} of {len(CHECKS)} passed")
    sys.exit(1 if bad else 0)
