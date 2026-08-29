#!/usr/bin/env python3
"""verify-install — is this installation actually armed, or does it only look it?

    python3 tools/verify-install.py [--json] [--wiring-only] [--strict]

      --json          machine-readable results instead of the report
      --wiring-only   static checks only, no payload probes (see main())
      --strict        exit non-zero on warnings too, for CI

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
import re
import shutil
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
# The tools the guard is meant to stand in front of. The last one is a stand-in
# for the whole mcp__* family: a matcher has to cover a name of that shape, not
# the literal string.
EXPECTED_TOOLS = ["Bash", "Read", "Write", "Edit", "MultiEdit", "NotebookEdit",
                  "mcp__example__tool"]


def _covers(matcher: str | None, tool: str) -> bool:
    """Does this matcher put the guard in front of `tool`?

    An absent or empty matcher covers every tool — that is the tool chain's own
    convention, and it is the SAFEST configuration, not a gap. A check that
    demanded seven literal names would report exactly that setup as broken;
    this project's own test suite builds one, and so does the author's machine.
    """
    if matcher is None or matcher in ("", "*", ".*"):
        return True
    try:
        return re.fullmatch(matcher, tool) is not None
    except re.error:
        # Not a usable pattern. Saying "covered" here would hide a real hole.
        return False


def check_matchers(matchers: list[str | None]) -> None:
    """The half the behavioural probes below CANNOT see.

    Those probes drive the hook directly and therefore prove what it decides —
    never whether it is asked. A settings file that registers the guard for
    `Bash` alone leaves Write, Edit, MultiEdit, NotebookEdit, Read and the MCP
    tools unguarded, and every probe still comes back green, because each one
    reaches the hook by hand. Measured on 2026-08-27: such an install reported
    "12 ok, 1 to look at, 0 broken" and exit code 0.

    Unlike the running session's wiring, this half is knowable from here: the
    matchers are sitting in the file.
    """
    missing = [t for t in EXPECTED_TOOLS
               if not any(_covers(m, t) for m in matchers)]
    if not missing:
        note(OK, "tool coverage",
             f"{len(matchers)} matcher(s) cover all {len(EXPECTED_TOOLS)} tool kinds")
        return
    shown = ["the mcp__* family" if t.startswith("mcp__") else t for t in missing]
    note(FAIL, "tool coverage",
         "no matcher puts the guard in front of: " + ", ".join(shown)
         + ". Those tool calls never reach it — see settings.example.json.")


def check_interpreter(guard_commands: list[str]) -> None:
    """The probes run under THIS python; production runs under that one."""
    named = set()
    for raw in guard_commands:
        first = raw.split()[0] if raw.split() else ""
        if "command-guard" not in first and first:
            named.add(first)
    if not named:
        return
    resolved = {shutil.which(n) or n for n in named}
    if any(r != sys.executable for r in resolved):
        note(WARN, "interpreter",
             f"settings.json runs the hook with {', '.join(sorted(named))}, "
             f"this check ran it with {sys.executable}. The verdicts below are "
             "from a different interpreter than the one that guards you.")


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
    guard_matchers: list[str | None] = []
    for entry in data.get("hooks", {}).get("PreToolUse", []) or []:
        for hook in entry.get("hooks", []) or []:
            if hook.get("type") == "command" and hook.get("command"):
                commands.append(str(hook["command"]))
                if "command-guard" in str(hook["command"]):
                    guard_matchers.append(entry.get("matcher"))

    guard = [c for c in commands if "command-guard" in c]
    if not guard:
        note(FAIL, "PreToolUse entry",
             f"no command-guard hook registered ({len(commands)} other PreToolUse hooks)")
        return None
    note(OK, "PreToolUse entry", f"{len(guard)} registered")

    check_matchers(guard_matchers)

    # Every registered entry, not just the first. With seven matchers the other
    # six went unchecked, so one left pointing at an old path stayed invisible
    # while the report said "hook file: ok".
    paths: list[Path] = []
    for raw in guard:
        candidate = None
        for token in raw.replace('"', " ").replace("'", " ").split():
            if "command-guard" in token:
                candidate = token
                break
        if candidate is None:
            note(WARN, "hook path", f"could not parse a path out of: {raw[:60]}")
            continue
        p = Path(os.path.expandvars(os.path.expanduser(candidate)))
        if p not in paths:
            paths.append(p)

    if not paths:
        return None
    if len(paths) > 1:
        note(WARN, "hook path",
             "the registered entries point at different files: "
             + ", ".join(str(p) for p in paths))
    for extra in paths[1:]:
        if not extra.is_file():
            note(FAIL, "hook file", f"an entry points at {extra} — nothing there")

    check_interpreter(guard)
    path = paths[0]
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


def check_owner_scripts(rules: dict | None) -> None:
    """Look for the scripts THIS installation calls its approval channel.

    The names are taken from the rules for the same reason the probes below
    take them from there: installations rename them. Measured on the author's
    own machine, where they are German — a fixed English list reported "the
    approval channel is missing" about a channel that was sitting right there.
    A verification tool that invents the thing it verifies produces false
    alarms about the very setup it is meant to certify.
    """
    configured = [str(c) for c in (rules or {}).get("owner_only_commands") or []]
    names = configured or ["grant-override", "hook-dev-mode"]

    missing = []
    for name in names:
        for base in (HOME / ".claude" / "bin", HOME / ".claude" / "safety-guard" / "bin"):
            path = base / name
            if path.is_file():
                if not os.access(path, os.X_OK):
                    note(FAIL, f"script {name}",
                         f"{path} is not executable — the owner channel cannot run")
                else:
                    note(OK, f"script {name}", str(path))
                break
        else:
            missing.append(name)

    # Half a channel used to pass in silence: with one script present the count
    # was non-zero and nothing was said about the other one.
    where = "the bin directories of this installation"
    if missing and len(missing) == len(names):
        note(WARN, "owner scripts",
             f"none of the approval scripts ({', '.join(names)}) found in "
             f"{where} — the escalation path has no exit")
    elif missing:
        note(WARN, "owner scripts",
             f"found, except: {', '.join(missing)} — not in {where}. "
             "Whatever that script grants cannot be granted until it is there.")


def check_update_hook(settings: dict) -> None:
    """The update check needs BOTH halves: the config key and the hook entry.

    The README calls this "the easy mistake" itself: `update_check.enabled` is
    on, nothing runs, and nothing complains — the quietest possible failure. It
    is exactly what a verification tool is for, and it was the one place this
    one did not look.

    Silence is correct when the check is off. A tool that nags about a feature
    nobody switched on gets ignored, and then it is not read when it matters.
    """
    config_path = HOME / ".claude" / "guard-config.json"
    enabled = False
    if config_path.is_file():
        try:
            cfg = json.loads(config_path.read_text(encoding="utf-8"))
            enabled = bool((cfg.get("update_check") or {}).get("enabled"))
        except Exception:
            enabled = False
    if not enabled:
        return

    registered = any(
        "update-check" in str(h.get("command", ""))
        for entry in settings.get("hooks", {}).get("SessionStart", []) or []
        for h in entry.get("hooks", []) or []
    )
    if registered:
        note(OK, "update check", "enabled and registered as a SessionStart hook")
    else:
        note(WARN, "update check",
             "update_check.enabled is true, but no SessionStart hook runs "
             "update-check.py — the setting is on and nothing checks. "
             "See the update section of INSTALL.md.")

    version_file = None
    for base in (HOME / ".claude" / "hooks", HOME / ".claude" / "safety-guard"):
        if (base / "VERSION").is_file():
            version_file = base / "VERSION"
            break
    if version_file is None:
        note(WARN, "update check",
             "no VERSION file next to the hook — the check has nothing to "
             "compare against and stays silent, which is indistinguishable "
             "from 'you are up to date'.")


def check_ai_context() -> None:
    """The rules document the assistant reads to know the approval path.

    Without it the assistant does not know the escalation channel exists and
    never proposes an override — the guard then reads as a wall rather than a
    gate, and people switch it off. INSTALL.md section B requires the file;
    nothing checked for it.
    """
    for candidate in (HOME / ".claude" / "rules" / "security-operations.md",
                      HOME / ".claude" / "rules" / "security-operations.markdown"):
        if candidate.is_file():
            note(OK, "AI context", str(candidate))
            return
    note(WARN, "AI context",
         f"{HOME}/.claude/rules/security-operations.md not found — the "
         "assistant has no description of the approval channel and will not "
         "propose overrides. INSTALL.md section B.")


def check_pending_dir() -> None:
    """The proposal directory — the one place the AI is SUPPOSED to write.

    It is deliberately not self-protected; that is what makes the channel work.
    Missing, the AI has nowhere to put a proposal and the documented path ends
    in an error the owner never sees.
    """
    pending = HOME / ".claude" / ".sudo-overrides-pending"
    if not pending.is_dir():
        note(WARN, "approval channel",
             f"{pending} does not exist — the AI has nowhere to write a "
             "proposal, so the documented approval path is broken. "
             "mkdir -p it.")
    elif not os.access(pending, os.W_OK):
        note(WARN, "approval channel",
             f"{pending} is not writable — proposals cannot be placed there.")
    else:
        note(OK, "approval channel", f"proposal directory ready: {pending}")


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
        check_owner_scripts(rules)
        try:
            settings = json.loads(SETTINGS.read_text(encoding="utf-8"))
        except Exception:
            settings = {}
        check_update_hook(settings)
        check_ai_context()
        check_pending_dir()
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
        print("  Whether your running session actually calls the hook. The")
        print("  matcher check above reads what settings.json registers; that")
        print("  a session honours it is a different question. This script")
        print("  invokes the hook directly, so a session that never reaches it")
        print("  would look identical here. Ask your assistant to write to the")
        print("  hook file and watch it be refused — that, and only that,")
        print("  proves the wiring.")
        if fails:
            print("\nSomething above is broken. An install that reports readiness")
            print("and protects nothing is the failure this tool exists to catch.")
    # --strict: warnings become failures. A CI job wants "everything is as
    # intended", not "nothing is outright broken".
    if "--strict" in sys.argv:
        return 1 if (fails or warns) else 0
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
