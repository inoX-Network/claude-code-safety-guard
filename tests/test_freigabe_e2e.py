#!/usr/bin/env python3
"""End-to-end test: approval channel + dev mode + hook integration.

Tests the installed scripts (grant-override, hook-dev-mode) against the REAL
command-guard.py — the whole flow: AI proposal (pending) -> owner approval
(grant-override) -> hook respects the active override.

Everything runs in temp directories (env injection) — the real ~/.claude/ is
NOT touched. Complements test_command_guard.py (hook logic in isolation) with
the script and integration layer.

Run:  python3 test_freigabe_e2e.py
Exit: 0 = all green, 1 = at least one failure.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = REPO / "hooks" / "command-guard.py"
RULES = str(REPO / "security-rules.example.json")
BIN = REPO / "bin"
GRANT_OVERRIDE = BIN / "grant-override"
HOOK_DEV_MODE = BIN / "hook-dev-mode"

_G = "\033[32m" if sys.stdout.isatty() else ""
_R = "\033[31m" if sys.stdout.isatty() else ""
_X = "\033[0m" if sys.stdout.isatty() else ""

_passed = 0
_failed = 0
_fails: list[str] = []


def check(name: str, cond: bool) -> None:
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"{_G}PASS{_X}  {name}")
    else:
        _failed += 1
        _fails.append(name)
        print(f"{_R}FAIL{_X}  {name}")


def _env(active: Path, pending: Path, flag: Path, audit: Path) -> dict:
    e = dict(os.environ)
    e["CLAUDE_SECURITY_RULES"] = RULES
    e["CLAUDE_SUDO_OVERRIDES_DIR"] = str(active)
    e["CLAUDE_SUDO_PENDING_DIR"] = str(pending)
    e["CLAUDE_HOOK_DEV_FLAG"] = str(flag)
    e["CLAUDE_AUDIT_DIR"] = str(audit)
    return e


def run_freigeben(args: list[str], env: dict) -> int:
    return subprocess.run([sys.executable, str(GRANT_OVERRIDE), *args],
                          capture_output=True, text=True, env=env).returncode


def run_devmode(args: list[str], env: dict) -> int:
    return subprocess.run([sys.executable, str(HOOK_DEV_MODE), *args],
                          capture_output=True, text=True, env=env).returncode


def run_hook_bash(command: str, agent_id: str | None, env: dict) -> int:
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
               "tool_input": {"command": command}, "session_id": "e2e"}
    if agent_id:
        payload["agent_id"] = agent_id
        payload["agent_type"] = "test"
    return subprocess.run([sys.executable, str(HOOK)], input=json.dumps(payload),
                          capture_output=True, text=True, env=env).returncode


def run_hook_edit(file_path: str, env: dict) -> int:
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Edit",
               "tool_input": {"file_path": file_path, "old_string": "a", "new_string": "b"},
               "session_id": "e2e"}
    return subprocess.run([sys.executable, str(HOOK)], input=json.dumps(payload),
                          capture_output=True, text=True, env=env).returncode


def write_pending(pending: Path, name: str, data: dict) -> None:
    pending.mkdir(parents=True, exist_ok=True)
    (pending / name).write_text(json.dumps(data), encoding="utf-8")


def _pending_proposal(level: int, agent_id: str, additional_sudo=None) -> dict:
    """Simulates an AI proposal (confirmed:false, still without expires_at)."""
    return {
        "override_level": level,
        "label": {1: "EXTENDED", 2: "FULL", 3: "CRITICAL"}[level],
        "task": f"E2E test level {level}",
        "agent_id": agent_id,
        "confirmed": False,
        "grants": {"additional_sudo": additional_sudo or [], "allowed_paths": []},
    }


AID = "e2eagent1234567"


def test_freigabe_stufe1() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        t = Path(tmp)
        active, pending = t / "active", t / "pending"
        flag, audit = t / "flag", t / "audit"
        env = _env(active, pending, flag, audit)
        active.mkdir()

        write_pending(pending, f"agent-{AID}.json", _pending_proposal(1, AID, ["htop"]))

        rc = run_freigeben([f"agent-{AID}", "--minutes", "60"], env)
        check("Level1: grant-override exit 0", rc == 0)
        check("Level1: file removed from pending", not (pending / f"agent-{AID}.json").exists())
        activated = active / f"agent-{AID}.json"
        check("Level1: file in the active directory", activated.exists())
        if activated.exists():
            data = json.loads(activated.read_text())
            check("Level1: confirmed=true set", data.get("confirmed") is True)
            check("Level1: expires_at set", bool(data.get("expires_at")))

        # Hook respects the freshly activated override
        check("Level1: hook now allows 'sudo htop' (grant applies)",
              run_hook_bash("sudo htop", AID, env) == 0)
        check("Level1: hook blocks 'sudo iftop' (not in the grant)",
              run_hook_bash("sudo iftop", AID, env) == 2)


def test_freigabe_stufe2_reibung() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        t = Path(tmp)
        active, pending = t / "active", t / "pending"
        flag, audit = t / "flag", t / "audit"
        env = _env(active, pending, flag, audit)
        active.mkdir()

        write_pending(pending, f"agent-{AID}.json", _pending_proposal(2, AID))

        # Without --confirm: friction applies, stays pending
        check("Level2: without --confirm -> exit 1 (friction)",
              run_freigeben([f"agent-{AID}"], env) == 1)
        check("Level2: stays in pending (not activated)",
              (pending / f"agent-{AID}.json").exists())
        check("Level2: hook blocks 'sudo htop' (no active override)",
              run_hook_bash("sudo htop", AID, env) == 2)

        # Wrong label -> still blocked
        check("Level2: wrong --confirm -> exit 1",
              run_freigeben([f"agent-{AID}", "--confirm", "EXTENDED"], env) == 1)

        # Correct label -> activated
        check("Level2: --confirm FULL -> exit 0",
              run_freigeben([f"agent-{AID}", "--confirm", "FULL"], env) == 0)
        check("Level2: now active, hook allows 'sudo htop' (level2=all sudo)",
              run_hook_bash("sudo htop", AID, env) == 0)


def test_freigabe_stufe3_snapshot() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        t = Path(tmp)
        active, pending = t / "active", t / "pending"
        flag, audit = t / "flag", t / "audit"
        env = _env(active, pending, flag, audit)
        active.mkdir()

        write_pending(pending, f"agent-{AID}.json", _pending_proposal(3, AID))

        check("Level3: --confirm CRITICAL without --snapshot -> exit 1",
              run_freigeben([f"agent-{AID}", "--confirm", "CRITICAL"], env) == 1)
        check("Level3: stays in pending",
              (pending / f"agent-{AID}.json").exists())
        check("Level3: with --confirm CRITICAL --snapshot SNAP-9 -> exit 0",
              run_freigeben([f"agent-{AID}", "--confirm", "CRITICAL",
                             "--snapshot", "SNAP-9"], env) == 0)
        activated = active / f"agent-{AID}.json"
        if activated.exists():
            check("Level3: snapshot_id in the active file",
                  json.loads(activated.read_text()).get("snapshot_id") == "SNAP-9")


def test_dev_mode_toggle() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        t = Path(tmp)
        active, pending = t / "active", t / "pending"
        flag, audit = t / "flag", t / "audit"
        env = _env(active, pending, flag, audit)

        hookfile = "~/.claude/hooks/command-guard.py"

        # Before dev mode: Edit on the hook is blocked
        check("Dev: before 'on' -> Edit command-guard.py BLOCKED",
              run_hook_edit(hookfile, env) == 2)

        check("Dev: 'hook-dev-mode on 30' exit 0", run_devmode(["on", "30"], env) == 0)
        check("Dev: flag file exists", flag.exists())
        check("Dev: ON -> Edit command-guard.py ALLOWED",
              run_hook_edit(hookfile, env) == 0)
        # Even in dev mode, non-unlockable paths stay hard
        check("Dev: ON -> settings.json stays BLOCKED",
              run_hook_edit("~/.claude/settings.json", env) == 2)

        check("Dev: 'hook-dev-mode off' exit 0", run_devmode(["off"], env) == 0)
        check("Dev: flag file removed", not flag.exists())
        check("Dev: OFF -> Edit command-guard.py blocked again",
              run_hook_edit(hookfile, env) == 2)


def main() -> int:
    if not GRANT_OVERRIDE.is_file() or not HOOK_DEV_MODE.is_file():
        print(f"ERROR: scripts not found in {BIN}", file=sys.stderr)
        return 1
    test_freigabe_stufe1()
    test_freigabe_stufe2_reibung()
    test_freigabe_stufe3_snapshot()
    test_dev_mode_toggle()
    print(f"\n{'='*60}\n{_passed} passed, {_failed} failed")
    if _fails:
        print("FAILED:")
        for f in _fails:
            print(f"  - {f}")
    return 1 if _failed else 0


if __name__ == "__main__":
    sys.exit(main())
