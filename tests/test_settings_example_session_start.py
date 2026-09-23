# ============================================================================
# settings.example.json must wire up the update check, not just the guard.
#
# INSTALL.md's own install table says "merge its 7 PreToolUse matchers" — and
# taken literally, that is all a fresh install gets. `hooks/update-check.py`
# needs a SEPARATE entry, under SessionStart (see INSTALL.md, "Optional: the
# update check"). Without it in the shipped example, whoever merges only the
# PreToolUse array — which is exactly what the table tells them to do — has
# never wired the updater in, and nothing says so: the check is simply never
# invoked, which looks identical to "up to date".
#
# This does not touch whether the check ever phones home — that still needs
# `update_check.enabled: true` in guard-config.json. This only makes sure the
# hook is reachable at all.
# ============================================================================
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SETTINGS = REPO / "settings.example.json"
INSTALL = REPO / "INSTALL.md"


def _session_start_entries() -> list:
    data = json.loads(SETTINGS.read_text(encoding="utf-8"))
    return data.get("hooks", {}).get("SessionStart", [])


def _commands(entries: list) -> list:
    commands = []
    for entry in entries:
        for hook in entry.get("hooks", []):
            commands.append(hook.get("command", ""))
    return commands


def check_settings_example_is_valid_json():
    try:
        json.loads(SETTINGS.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, f"settings.example.json is not valid JSON: {exc}"
    return True, ""


def check_session_start_section_exists():
    entries = _session_start_entries()
    return bool(entries), \
        "settings.example.json has no hooks.SessionStart section at all"


def check_session_start_points_at_update_check():
    commands = _commands(_session_start_entries())
    hit = [c for c in commands if "update-check.py" in c]
    return len(hit) == 1, \
        f"no SessionStart entry runs update-check.py (found: {commands})"


def check_session_start_command_matches_install_md():
    """The entry must be runnable as shipped, not just present — same command
    INSTALL.md documents for section 'Optional: the update check'."""
    install_text = INSTALL.read_text(encoding="utf-8")
    if "python3 ~/.claude/hooks/update-check.py" not in install_text:
        return False, "INSTALL.md no longer documents this exact command " \
                      "— update the fixture, not just the assertion"
    commands = _commands(_session_start_entries())
    return "python3 ~/.claude/hooks/update-check.py" in commands, \
        f"settings.example.json's command does not match INSTALL.md: {commands}"


def check_pretooluse_matchers_are_still_untouched():
    """The fix adds SessionStart; it must not disturb the PreToolUse matchers
    (INSTALL.md counts on exactly eight: Grep joined on 2026-09-23)."""
    data = json.loads(SETTINGS.read_text(encoding="utf-8"))
    matchers = [e.get("matcher") for e in data["hooks"]["PreToolUse"]]
    expected = ["Bash", "Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "Grep",
                "mcp__.*"]
    return matchers == expected, f"PreToolUse matchers changed: {matchers}"


CASES = [
    ("settings.example.json is valid JSON", check_settings_example_is_valid_json),
    ("a SessionStart section exists", check_session_start_section_exists),
    ("SessionStart wires update-check.py", check_session_start_points_at_update_check),
    ("the command matches INSTALL.md", check_session_start_command_matches_install_md),
    ("the 8 PreToolUse matchers are untouched",
     check_pretooluse_matchers_are_still_untouched),
]

try:
    import pytest

    @pytest.mark.parametrize("name,fn", CASES)
    def test_settings_example_session_start(name, fn):
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
