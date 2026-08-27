#!/usr/bin/env python3
"""verify-install — is this installation actually armed, or does it only look it?

    python3 tools/verify-install.py [--json]

Section E of INSTALL.md asks you to try five things by hand. This does that
work, plus the part hands are bad at: checking that both halves of every
"two halves" pairing match.

WHY THIS TOOL EXISTS

The dangerous failure of a security hook is not that it crashes — it is that it
reports readiness and protects nothing. A setting pointing at a path where no
file lives looks exactly like a working install from the outside. Nothing says
otherwise until the day it matters.

THREE PARTS, AND THE THIRD ONE MATTERS MOST

  1. WIRING   Static checks. Does settings.json name the hook, and does a file
              exist at that exact path? Are the rules readable? Are the
              owner-only scripts executable?

  2. VERDICTS Behavioural checks. The hook is fed constructed payloads and only
              its exit code is read. Nothing is executed: the hook decides, it
              does not run commands.

  3. LIMITS   What this script CANNOT establish, printed rather than implied.
              Chief among them: whether your running session actually invokes
              the hook. Only a real tool call shows that. A green run here means
              "the parts are correct", not "you are protected".

Read-only apart from the hook's own audit log, which it writes anyway.
Standard library only.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

HOME = Path.home()
SETTINGS = HOME / ".claude" / "settings.json"

OK, WARN, FAIL = "ok", "warn", "FAIL"
results: list[tuple[str, str, str]] = []


def note(state: str, check: str, detail: str) -> None:
    results.append((state, check, detail))


# ---------------------------------------------------------------- part 1
def find_hook_from_settings() -> Path | None:
    """The hook path AS THE TOOL CHAIN SEES IT — not where we hope it is.

    Deliberately read out of settings.json instead of assuming the default
    location: a setting pointing somewhere else is precisely the failure this
    tool exists to catch.
    """
    if not SETTINGS.is_file():
        note(FAIL, "settings.json", f"not found at {SETTINGS}")
        return None
    try:
        data = json.loads(SETTINGS.read_text(encoding="utf-8"))
    except Exception as e:
        note(FAIL, "settings.json", f"not valid JSON: {e}")
        return None

    commands: list[str] = []
    for entry in data.get("hooks", {}).get("PreToolUse", []) or []:
        for hook in entry.get("hooks", []) or []:
            if hook.get("type") == "command" and hook.get("command"):
                commands.append(str(hook["command"]))

    guard = [c for c in commands if "command-guard" in c]
    if not guard:
        note(FAIL, "PreToolUse entry",
             f"no command-guard hook registered ({len(commands)} other PreToolUse hooks)")
        return None
    note(OK, "PreToolUse entry", f"{len(guard)} registered")

    # Pull the path out of the command line and expand it the way a shell would.
    raw = guard[0]
    candidate = None
    for token in raw.replace('"', " ").replace("'", " ").split():
        if "command-guard" in token:
            candidate = token
            break
    if candidate is None:
        note(WARN, "hook path", f"could not parse a path out of: {raw[:60]}")
        return None

    path = Path(os.path.expandvars(os.path.expanduser(candidate)))
    # THE TWO HALVES. The entry existing proves nothing about the file.
    if not path.is_file():
        note(FAIL, "hook file",
             f"settings.json points at {path} — nothing there. "
             "The entry and the file are two halves; one without the other is silent.")
        return None
    note(OK, "hook file", str(path))
    return path


def rules_path_as_the_hook_sees_it() -> Path:
    """Ask the configuration, do not guess the location.

    The first draft of this tool searched two hardcoded paths and reported
    "rules file not found" on an install that was perfectly fine — the rules
    simply lived elsewhere, exactly as guard-config.json said they should.
    A verification tool that guesses produces false alarms about the very
    thing it is supposed to certify.
    """
    env_override = os.environ.get("CLAUDE_SECURITY_RULES")
    if env_override:
        return Path(os.path.expanduser(env_override))

    config = Path(os.environ.get("CLAUDE_GUARD_CONFIG")
                  or (HOME / ".claude" / "guard-config.json"))
    if config.is_file():
        try:
            data = json.loads(config.read_text(encoding="utf-8"))
            configured = data.get("installation", {}).get("rules")
            if configured:
                return Path(os.path.expanduser(configured))
        except Exception as e:
            note(WARN, "guard-config.json", f"unreadable, falling back to default: {e}")

    return HOME / ".claude" / "safety-guard" / "security-rules.json"


def check_rules() -> dict | None:
    path = rules_path_as_the_hook_sees_it()
    if not path.is_file():
        note(FAIL, "rules file",
             f"the hook expects rules at {path} — nothing there. "
             "Without them it runs fail-closed and refuses everything.")
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        note(FAIL, "rules file", f"{path} is not valid JSON: {e}")
        return None
    keys = [k for k in data if not k.startswith("_")]
    note(OK, "rules file", f"{path}, {len(keys)} keys")
    if not data.get("blocked_paths_write"):
        note(WARN, "rules content",
             "blocked_paths_write is empty — nothing is write-protected by rule")
    return data


def check_owner_scripts() -> None:
    found = 0
    for name in ("grant-override", "hook-dev-mode"):
        for base in (HOME / ".claude" / "bin", HOME / ".claude" / "safety-guard" / "bin"):
            path = base / name
            if path.is_file():
                found += 1
                if not os.access(path, os.X_OK):
                    note(FAIL, f"script {name}",
                         f"{path} is not executable — the owner channel cannot run")
                else:
                    note(OK, f"script {name}", str(path))
                break
    if found == 0:
        note(WARN, "owner scripts",
             "neither approval script found — the escalation path has no exit")


def check_dev_window() -> bool:
    """An open dev window frees the very paths the probes aim at.

    Without this check the self-protection probes below would come back 'free'
    and the tool would report a hole that is not one. Cost this project twenty
    minutes once; it is a check, not a footnote.
    """
    flag = Path(os.environ.get("CLAUDE_HOOK_DEV_FLAG")
                or (HOME / ".claude" / ".hook-dev-mode"))
    if flag.exists():
        note(WARN, "dev window",
             f"{flag} exists — hook sources are unlocked, so self-protection "
             "verdicts below are NOT meaningful. Close it and re-run.")
        return True
    note(OK, "dev window", "closed")
    return False


# ---------------------------------------------------------------- part 2
def verdict(hook: Path, tool: str, payload_input: dict) -> int:
    payload = json.dumps({"tool_name": tool, "tool_input": payload_input,
                          "cwd": str(HOME), "session_id": "verify-install"})
    try:
        run = subprocess.run([sys.executable, str(hook)], input=payload,
                             capture_output=True, text=True, timeout=60)
    except Exception:
        return -1
    return run.returncode


def check_behaviour(hook: Path, dev_open: bool, rules: dict | None) -> None:
    """The five manual cases from INSTALL.md section E, plus three controls."""
    # Take the owner-only name FROM THE RULES, do not assume ours. Installs
    # rename these scripts (this one calls them differently in German), and a
    # probe against a name that is not configured proves nothing — it just
    # reports a hole where there is none.
    owner_cmds = (rules or {}).get("owner_only_commands") or []
    owner_probe = None
    if owner_cmds:
        first = str(owner_cmds[0])
        owner_probe = (f"owner-only command from Bash ({first})",
                       "Bash", {"command": f"{first} abc --minutes 5"}, True, False)
    else:
        note(WARN, "owner-only commands",
             "none configured — the approval scripts are not protected from AI Bash")

    cases = [
        # (name, tool, input, expect_block, skip_when_dev_open)
        ("self-protection: write to the hook", "Write",
         {"file_path": str(hook), "content": "x"}, True, True),
        ("self-protection: shell write to the hook", "Bash",
         {"command": f"echo x > {hook}"}, True, True),
        ("always-blocked pattern", "Bash",
         {"command": "chmod -R 777 /etc"}, True, False),
        ("protected read", "Read",
         {"file_path": f"{HOME}/.ssh/id_rsa"}, True, False),
        # Controls. Without these a hook that blocks EVERYTHING would look
        # perfect — and an install that blocks everything is unusable, which
        # people fix by removing the hook.
        ("control: harmless write is allowed", "Write",
         {"file_path": "/tmp/guard-verify-probe.txt", "content": "x"}, False, False),
        ("control: harmless command is allowed", "Bash",
         {"command": "echo hello"}, False, False),
        ("control: reading the hook is allowed", "Bash",
         {"command": f"grep -c def {hook}"}, False, False),
    ]
    if owner_probe:
        cases.insert(2, owner_probe)

    for name, tool, payload_input, expect_block, dev_sensitive in cases:
        if dev_open and dev_sensitive:
            note(WARN, name, "skipped — dev window is open, result would be misleading")
            continue
        code = verdict(hook, tool, payload_input)
        if code == -1:
            note(FAIL, name, "the hook could not be run at all")
            continue
        blocked = code == 2
        if blocked == expect_block:
            note(OK, name, "blocked" if blocked else "allowed")
        else:
            note(FAIL, name,
                 f"expected {'block' if expect_block else 'allow'}, "
                 f"got exit {code}")


# ---------------------------------------------------------------- report
def main() -> int:
    as_json = "--json" in sys.argv
    # --wiring-only: skip the payload probes and check the static half alone.
    # Needed because the hook resolves the home directory itself and ignores
    # $HOME on purpose (otherwise moving that variable would move the
    # self-protection). A constructed install under a temporary HOME therefore
    # gets real verdicts against the real rules — useful to know, useless to
    # assert against. The wiring half has no such problem: it reads the paths
    # this process sees.
    wiring_only = "--wiring-only" in sys.argv

    hook = find_hook_from_settings()
    if hook is not None:
        rules = check_rules()
        check_owner_scripts()
        dev_open = check_dev_window()
        if not wiring_only:
            check_behaviour(hook, dev_open, rules)

    if as_json:
        print(json.dumps([{"state": s, "check": c, "detail": d}
                          for s, c, d in results], indent=2))
    else:
        print("Safety guard — installation check\n")
        for state, check, detail in results:
            mark = {OK: "  ok  ", WARN: "  !!  ", FAIL: " FAIL "}[state]
            print(f"{mark}{check}")
            print(f"        {detail}")

    fails = sum(1 for s, _, _ in results if s == FAIL)
    warns = sum(1 for s, _, _ in results if s == WARN)

    if not as_json:
        print(f"\n{len(results) - fails - warns} ok, {warns} to look at, {fails} broken")
        print("\nWHAT THIS CANNOT TELL YOU:")
        print("  Whether your running session actually calls the hook. This")
        print("  script invokes it directly; a session that never reaches it")
        print("  would look identical here. Ask your assistant to write to the")
        print("  hook file and watch it be refused — that, and only that,")
        print("  proves the wiring.")
        if fails:
            print("\nSomething above is broken. An install that reports readiness")
            print("and protects nothing is the failure this tool exists to catch.")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
