#!/usr/bin/env python3
"""would-it-help — would this guard actually be worth it on THIS machine?

    python3 tools/would-it-help.py            # run it from a fresh clone
    python3 tools/would-it-help.py --sample 5000
    python3 tools/would-it-help.py --json

Run this BEFORE installing anything. Nothing is written, nothing is sent
anywhere, and no file that the guard would protect is ever opened — only its
existence is noted.

WHAT THIS IS AND WHY IT IS BLUNT

Security tools are sold with fear. This one is not for everybody, and a report
that says "you need this" regardless of what it found would be worthless — you
could not tell the honest cases from the sales pitch.

So the verdict here can be **"probably not worth it"**, and it says so when the
numbers say so. Everything below is counted on your machine, from your own
history. There is no scoring curve and no marketing.

THE ONE THING THAT WOULD MAKE THIS DISHONEST

**The guard protects you from an agent, not from yourself.** You know what you
are doing; a model with tool access on your machine does not know what you
would never do. So the meaningful question is not "what dangerous things have
I typed" — it is "what would an assistant do here, and what would it reach".

That is why agent logs, where they exist, count for far more than shell
history. Where only shell history exists, this report says so instead of
quietly treating one as the other.

Method: your commands are fed to the REAL hook from this checkout — not to a
simplified copy of its rules — and only its verdict is read. Nothing runs.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HOME = Path.home()
REPO = Path(__file__).resolve().parent.parent
HOOK = REPO / "hooks" / "command-guard.py"
EXAMPLE_RULES = REPO / "security-rules.example.json"

# Never print a raw command: history lines contain tokens, passwords and paths
# that are nobody's business, least of all a report's. Quoted sections and
# anything that looks assigned are replaced wholesale — structure is enough to
# recognise a case, and this is the only way that does not depend on
# maintaining a list of secret shapes.
_QUOTED = re.compile(r"""(['"])(?:\\.|(?!\1).)*\1""")
_ASSIGNED = re.compile(r"(=)\s*\S+")


def redact(command: str) -> str:
    text = _QUOTED.sub("'…'", command)
    text = _ASSIGNED.sub(r"\1…", text)
    return " ".join(text.split())[:90]


# ---------------------------------------------------------------- what is here
# Where people keep work. The first six were the whole list once, and everyone
# whose repositories live in ~/git, ~/repos or /srv was told "nothing of the
# usual kinds found" — followed by "the guard would mostly be in your way".
# For a tool whose distinguishing feature is that it can say no, a wrong no is
# the expensive error: it is given to a well-exposed machine with confidence.
WORK_DIRS = ["Projects", "Projekte", "code", "src", "dev", "work",
             "git", "repos", "workspace", "Development", "Documents"]
SYSTEM_WORK_DIRS = [Path("/var/www"), Path("/srv"), Path("/opt")]

# Not searched: package and build directories. They hold thousands of entries,
# none of them anyone's work — and a .env inside node_modules is an example
# file, not a credential. Skipping them is what makes searching more places
# affordable. Measured before the change on a machine with 66 repositories:
# 4.0 s for two rglob passes over ~/Projekte alone.
SKIP_DIRS = {"node_modules", ".venv", "venv", "env", "site-packages", "target",
             "dist", "build", ".cache", ".tox", ".mypy_cache", "__pycache__",
             ".next", ".gradle", "vendor", ".terraform"}

MAX_REPOS = 400
MAX_ENV_FILES = 200


def _scan_work_dirs() -> tuple[int, int, int, list[Path]]:
    """Count repositories, unversioned ones and .env files. Returns the bases too.

    Returning what was searched matters as much as the counts: a zero has two
    very different meanings — "nothing here" and "not where you keep it" — and
    only one of them justifies advising against the guard.
    """
    # System locations only where this user can actually write. What they
    # cannot change, an assistant running as them cannot destroy either — and
    # /opt is full of installed software on most machines, which is not
    # anybody's work. Web roots and /srv, where they belong to the user, are.
    searched = [b for b in (HOME / d for d in WORK_DIRS) if b.is_dir()]
    searched += [b for b in SYSTEM_WORK_DIRS
                 if b.is_dir() and os.access(b, os.W_OK)]

    repos = unversioned = env_files = 0
    for base in searched:
        for root, dirs, files in os.walk(base, onerror=lambda err: None):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            if ".git" in dirs or ".git" in files:
                repos += 1
                config = Path(root) / ".git" / "config"
                try:
                    if config.is_file():
                        text = config.read_text(encoding="utf-8", errors="replace")
                        if "[remote " not in text:
                            unversioned += 1
                except OSError:
                    pass
                if ".git" in dirs:
                    dirs.remove(".git")     # nothing of interest below it

            if ".env" in files:
                env_files += 1

            if repos > MAX_REPOS or env_files > MAX_ENV_FILES:
                break
        if repos > MAX_REPOS or env_files > MAX_ENV_FILES:
            break

    return repos, unversioned, env_files, searched


def what_is_at_stake() -> tuple[list[str], int, int, int, list[Path]]:
    """Existence only. This function must never open a protected file."""
    findings: list[str] = []
    weight = 0

    ssh = HOME / ".ssh"
    if ssh.is_dir():
        # Not a name pattern: keys are called all sorts of things. Everything
        # that is not a known non-key is treated as one — the safe direction
        # for a report about risk.
        known_non_keys = {"config", "known_hosts", "known_hosts.old",
                          "authorized_keys", "environment"}
        keys = [f for f in ssh.iterdir()
                if f.is_file() and f.name not in known_non_keys
                and not f.name.endswith(".pub")]
        if keys:
            findings.append(f"{len(keys)} private key(s) in ~/.ssh")
            weight += 3
        cfg = ssh / "config"
        if cfg.is_file():
            hosts = sum(1 for line in cfg.open(encoding="utf-8", errors="replace")
                        if line.strip().lower().startswith("host ")
                        and "*" not in line)
            if hosts:
                findings.append(f"{hosts} remote host(s) configured in ~/.ssh/config")
                weight += hosts  # every reachable machine is its own blast radius

    repos, unversioned, env_files, searched = _scan_work_dirs()
    if repos:
        findings.append(f"{repos}+ git repositories under your work directories")
        weight += 2
    if unversioned:
        # This is the sharpest number in the report. Everything else measures
        # how much could go wrong; this measures how much of it would be
        # UNRECOVERABLE. A repository with a remote survives a bad command --
        # someone re-clones it and loses an afternoon. One without is simply
        # gone. Read from .git/config rather than by running git: faster, and
        # it opens a config file rather than anything private.
        findings.append(
            f"{unversioned} of them have no remote — a mistake there is final")
        weight += unversioned
    if env_files:
        findings.append(f"{env_files}+ .env files (credentials live in these)")
        weight += 3

    for name, tool in (("container tool", "docker"), ("kubernetes", "kubectl"),
                       ("cloud CLI", "aws"), ("cloud CLI", "gcloud")):
        if shutil.which(tool):
            findings.append(f"{name} installed ({tool}) — reaches beyond this machine")
            weight += 2

    for cloud in (HOME / ".aws" / "credentials", HOME / ".config" / "gcloud",
                  HOME / ".kube" / "config"):
        if cloud.exists():
            findings.append(f"cloud credentials present ({cloud.name})")
            weight += 3

    if not findings:
        # Say WHERE nothing was found. Without that the reader cannot tell
        # "there is nothing here" from "you keep your work somewhere I did not
        # look" — and the verdict below turns the second into advice.
        if searched:
            where = ", ".join(str(b) for b in searched[:6])
            findings.append(f"nothing of the usual kinds found (searched: {where})")
        else:
            findings.append(
                "no work directory of the usual names exists — searched for "
                + ", ".join(f"~/{d}" for d in WORK_DIRS[:6]) + " and others. "
                "If your projects live elsewhere, this report has not seen them.")
    return findings, weight, unversioned, repos, searched


# ------------------------------------------------------- who works here
def agents_present() -> list[str]:
    found = []
    if (HOME / ".claude").is_dir():
        found.append("Claude Code")
    if (HOME / ".config" / "opencode").is_dir() or shutil.which("opencode"):
        found.append("opencode")
    if (HOME / ".gemini").is_dir() or shutil.which("agy"):
        found.append("an Antigravity/Gemini CLI")
    if (HOME / ".cursor").is_dir():
        found.append("Cursor")
    return found


# ------------------------------------------------------- what actually happened
# This repository's own probes, which must never be counted as evidence.
#
# verify-install.py drives the INSTALLED hook, and there the environment is
# ignored on purpose — so its probes land in the real audit log, no matter what
# either tool would prefer. Roughly six in ten of them are blocks by
# construction: they exist to prove the walls stand. On a fresh install, where
# the log is otherwise almost empty, they were the whole sample, and this
# report concluded "60 % would have been stopped — expect real friction" from
# its own test material. Measured on 2026-08-27 in a clean container: five
# commands examined, three of them the checker's, and a real shell history of
# ten lines sitting right next to it, correctly ignored because the agent log
# outranks it.
#
# The session_id is the only reliable marker: real sessions carry a UUID.
OWN_SESSIONS = {"verify-install", "would-it-help"}

# Below this, no percentage is printed. A rate over a handful of commands says
# more about which commands happened to be in the log than about the guard: at
# n = 5 every single one moves the figure by 20 points. The commands are still
# shown — they are a finding; the rate is not.
MIN_SAMPLE = 30


def collect_commands(limit: int) -> tuple[list[str], str, int, bool]:
    """Returns (commands, source description, total seen, source is an agent log).

    Agent logs first — they record what a MODEL did, which is the thing this
    guard sits in front of. Shell history is a fallback and is labelled as the
    weaker evidence it is.

    The fourth value used to be re-derived by the caller from the description
    text ("log" in it, "history" not). A sentence written for humans is a poor
    place to keep a flag: rewording it flips the logic silently, and an
    IMPORTANT caveat in the report hangs on it.
    """
    audit = HOME / ".claude" / ".agent-audit" / "actions.jsonl"
    if audit.is_file():
        seen, cmds = 0, []
        with audit.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                except Exception:
                    continue
                if entry.get("session_id") in OWN_SESSIONS:
                    continue
                if entry.get("tool") != "Bash":
                    continue
                command = entry.get("target") or ""
                if command:
                    seen += 1
                    if len(cmds) < limit:
                        cmds.append(command)
        if cmds:
            return cmds, "your assistant's own log — what a model actually ran", seen, True

    for hist in (HOME / ".zsh_history", HOME / ".bash_history"):
        if not hist.is_file():
            continue
        cmds, seen = [], 0
        for line in hist.open(encoding="utf-8", errors="replace"):
            # zsh writes ': <epoch>:<elapsed>;<command>'
            command = line.split(";", 1)[1] if line.startswith(":") and ";" in line else line
            command = command.strip()
            if command:
                seen += 1
                if len(cmds) < limit:
                    cmds.append(command)
        if cmds:
            return cmds, f"{hist.name} — YOUR commands, not an agent's", seen, False

    return [], "no history found", 0, False


# ------------------------------------------------------- what the guard would do
def _kind_of(reason: str) -> str:
    """A category for a block message, so the report can group instead of list.

    Deliberately coarse: the message carries the offending path, so grouping
    on the full text would give every stop its own category and say nothing.
    """
    text = reason.split(":", 1)[1].strip() if ":" in reason else reason
    text = re.sub(r"[\'\"`].*?[\'\"`]", "…", text)
    text = re.sub(r"[~/][\w./-]+", "…", text)
    return " ".join(text.split())[:70] or "unclassified"


def ask_the_guard(commands: list[str]) -> tuple[Counter, Counter, list[tuple[str, str]]]:
    """Feed the REAL hook, read only its verdict. Nothing is executed."""
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = str(EXAMPLE_RULES)
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = str(Path(tmp) / "none")
        env["CLAUDE_AUDIT_DIR"] = str(Path(tmp) / "audit")
        env["CLAUDE_HOOK_DEV_FLAG"] = str(Path(tmp) / "no-dev")
        # Point the hook at an EMPTY config, so its messages come back in the
        # default language. Without this the report inherits whatever language
        # the reader's install happens to use — which on the development
        # machine produced an English report with German reasons in it.
        empty_config = Path(tmp) / "guard-config.json"
        empty_config.write_text("{}", encoding="utf-8")
        env["CLAUDE_GUARD_CONFIG"] = str(empty_config)

        def one(command: str):
            payload = json.dumps({"tool_name": "Bash",
                                  "tool_input": {"command": command},
                                  "cwd": str(HOME), "session_id": "would-it-help"})
            try:
                run = subprocess.run([sys.executable, str(HOOK)], input=payload,
                                     capture_output=True, text=True,
                                     timeout=30, env=env)
            except Exception:
                return command, None, ""
            reason = ""
            for line in (run.stdout + run.stderr).splitlines():
                if "BLOCKED" in line or "BLOCKIERT" in line:
                    reason = line.strip()
                    break
            return command, run.returncode, reason

        tally: Counter = Counter()
        reasons: Counter = Counter()
        examples: list[tuple[str, str]] = []
        with ThreadPoolExecutor(max_workers=8) as pool:
            for command, code, reason in pool.map(one, commands):
                if code is None:
                    tally["error"] += 1
                elif code == 2:
                    tally["blocked"] += 1
                    reasons[_kind_of(reason)] += 1
                    if len(examples) < 12:
                        examples.append((redact(command), reason[:80]))
                else:
                    tally["allowed"] += 1
        return tally, reasons, examples


# ---------------------------------------------------------------- verdict
def backup_advice(unversioned: int, repos: int) -> list[str]:
    """The one recommendation this report makes, and why it is not a demand.

    A guard reduces how often something goes wrong. A copy somewhere else
    decides whether it MATTERS when it does. The two are not alternatives, and
    of the pair the copy is the cheaper one — so a report that only recommends
    the guard would be selling rather than advising.

    Not a prerequisite: the guard works fine without it. Recommended, because
    the failure it cannot prevent is the one that ends your afternoon.
    """
    if not repos:
        return []
    if not unversioned:
        return ["Every repository found here has a remote. That is the single "
                "best protection there is, and it is already in place — a bad "
                "command costs you a re-clone, not the work."]
    return [
        f"{unversioned} of your {repos} repositories have no remote. Those are "
        "the ones where a mistake is permanent, and no guard can make that "
        "less true — it can only make it rarer.",
        "Pushing them somewhere (GitHub or anywhere else) is not required for "
        "this guard, and it is recommended anyway: it is the cheaper half of "
        "the pair. You do not need to know how — an assistant with tool access "
        "does this well, and setting it up is one of the things worth asking "
        "it for.",
    ]


def verdict(weight: int, agents: list[str], blocked: int, total: int,
            source_is_agent_log: bool) -> list[str]:
    """Plain sentences, and it is allowed to say no."""
    lines = []
    share = (blocked / total * 100) if total else 0.0

    if not agents:
        lines.append(
            "No AI assistant with tool access was found on this machine. "
            "This guard sits between such an assistant and your system, so "
            "TODAY it would protect you from nothing. Come back when you "
            "start using one.")
        return lines

    if weight <= 2:
        lines.append(
            f"Little was found that an accident could destroy ({weight} points "
            "of exposure). The guard would mostly be in your way. Worth it only "
            "if that changes.")
    elif weight <= 8:
        lines.append(
            f"A moderate amount is reachable from here ({weight} points): "
            "enough that a bad command would cost you an afternoon, not a "
            "month.")
    else:
        lines.append(
            f"A lot is reachable from here ({weight} points) — keys, remote "
            "machines or credentials. A single wrong recursive command reaches "
            "further than this machine.")

    if total and total < MIN_SAMPLE:
        lines.append(
            f"Only {total} command(s) could be examined, {blocked} of which "
            "would have been stopped or made to ask first. That is too few to "
            "put a rate on: with a sample this small the figure would say more "
            "about which commands happen to be in the log than about your "
            "work. Use the guard for a few days, then run this again.")
    elif total:
        lines.append(
            f"Of {total} commands examined, {blocked} ({share:.1f} %) would have "
            "been stopped or made to ask first.")
        if share < 0.5:
            lines.append(
                "That is a low rate: the guard would rarely interrupt you. It "
                "also means it would rarely act — its value here is the rare "
                "bad day, not daily friction.")
        elif share <= 8:
            lines.append(
                "That is the usual range: a handful of pauses a day, most of "
                "them on the same few kinds of command. Whether that is worth "
                "it depends on the first column of this report, not on this "
                "number.")
        else:
            lines.append(
                "That is a high rate. Expect real friction, and expect to spend "
                "the first days adjusting the rules to your work rather than "
                "the other way round.")

    if not source_is_agent_log:
        lines.append(
            "IMPORTANT: this was measured on YOUR shell history, not on an "
            "agent's actions. You know what you are doing — the guard exists "
            "for the case where something else is typing. Treat the number "
            "above as a rough shape, not as a prediction.")
    return lines


def consent(as_json: bool) -> bool:
    """Say what will be read, then wait for a yes. No yes, no reading.

    The notes for assistants ask them to offer this rather than run it. That is
    a request, not a barrier — and a request is the wrong instrument when the
    thing at stake is someone's shell history. So the gate lives here, where it
    cannot be skipped by an assistant being eager.

    Not a TTY (an assistant running it, a CI job)? Then --yes is required and
    the message says whose job it is to obtain that consent.
    """
    notice = [
        "This report will read:",
        "  · your assistant's command log, or your shell history — the",
        "    commands themselves, to see which ones would have been stopped",
        "  · the NAMES of files in ~/.ssh and similar places — never their",
        "    contents. No file this guard would protect is ever opened.",
        "",
        "It does not write, install, or send anything anywhere. Nothing leaves",
        "this machine, and commands are printed only with quotes and values",
        "removed.",
    ]
    if "--yes" in sys.argv:
        # Say it anyway. --yes answers the question; it does not make the
        # answer secret. An assistant that passes the flag would otherwise show
        # its user a report without ever having said what was read for it.
        print("\n".join(notice), file=sys.stderr)
        print("\n(--yes was passed: reading without asking again.)\n",
              file=sys.stderr)
        return True
    if as_json or not sys.stdin.isatty():
        print("\n".join(notice), file=sys.stderr)
        print("", file=sys.stderr)
        print("Refusing to read anything without consent. Re-run with --yes.",
              file=sys.stderr)
        print("If an assistant is running this for you: it should have asked "
              "you first, in its own words, and waited for your answer.",
              file=sys.stderr)
        return False
    print("\n".join(notice))
    try:
        answer = input("\nGo ahead? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if answer in ("y", "yes", "j", "ja"):
        return True
    print("Nothing was read.")
    return False


def main() -> int:
    limit = 20000
    if "--sample" in sys.argv:
        limit = int(sys.argv[sys.argv.index("--sample") + 1])
    as_json = "--json" in sys.argv

    if not consent(as_json):
        return 1

    if not HOOK.is_file():
        print(f"Run this from a checkout of the repo — no hook at {HOOK}")
        return 2

    stakes, weight, unversioned, repos, searched = what_is_at_stake()
    agents = agents_present()
    commands, source, total_seen, source_is_agent_log = collect_commands(limit)

    tally, reasons, examples = Counter(), Counter(), []
    if commands:
        tally, reasons, examples = ask_the_guard(commands)

    examined = tally["allowed"] + tally["blocked"]
    lines = verdict(weight, agents, tally["blocked"], examined, source_is_agent_log)
    advice = backup_advice(unversioned, repos)

    if as_json:
        print(json.dumps({
            "exposure": {"weight": weight, "findings": stakes,
                         "searched": [str(b) for b in searched]},
            "agents": agents,
            "source": source, "commands_seen": total_seen,
            "examined": examined, "blocked": tally["blocked"],
            "verdict": lines,
            "backup_advice": advice,
        }, indent=2))
        return 0

    print("Would this guard help on this machine?\n")
    print("WHAT IS REACHABLE FROM HERE")
    for item in stakes:
        print(f"  · {item}")
    print()
    print("WHO WORKS HERE WITH TOOL ACCESS")
    if agents:
        for a in agents:
            print(f"  · {a}")
    else:
        print("  · no AI assistant with tool access found")
    print()
    print("WHAT WAS MEASURED")
    print(f"  source: {source}")
    if total_seen > examined:
        print(f"  {examined} of {total_seen} commands examined "
              f"(--sample raises the cap; the rest were NOT looked at)")
    else:
        print(f"  {examined} commands examined")
    if reasons:
        # Grouped, not listed. Twelve near-identical container commands say
        # far less than "22 of your 40 stops are one kind of work" — and the
        # grouping is what tells you whether the friction would concentrate
        # in one corner of your day or spread across all of it.
        print("\n  Where the stops would fall:")
        for kind, count in reasons.most_common(8):
            share_here = count / max(tally["blocked"], 1) * 100
            print(f"    {count:>4}  ({share_here:4.0f} %)  {kind}")
    if examples:
        print("\n  A few of them, with quotes and values removed:")
        for cmd, _ in examples[:4]:
            print(f"    {cmd}")
    print("\nVERDICT")
    for line in lines:
        print(f"  {line}")
    if advice:
        print("\nTHE ONE THING WORTH DOING EITHER WAY")
        for line in advice:
            print(f"  {line}")
    print("\nWHAT THIS DOES NOT TELL YOU")
    print("  · Whether the rules fit your work. The defaults are a starting")
    print("    point; security-rules.json and docs/configuration-reference.md")
    print("    are where they become yours.")
    print("  · Anything about files it did not open — no protected file was")
    print("    read, only its existence noted.")
    print("  · How you would feel about the friction. That is not measurable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
