#!/usr/bin/env python3
"""A register for tool diagnostics — record, measure, put back in the way.

WHY THIS EXISTS

Language-server warnings arrive as an ATTACHMENT, not as an answer. The filter
"not my change, pre-existing code" is right most of the time and therefore runs
automatically — and that is exactly when it takes the one real warning with it.

Measured cost, in this project: `"delete_only" is possibly unbound` was shown
twice on the same day, on two different working copies, directly under the edit
result. Both times filed away as pre-existing. It was a crash in the most
common branch of a security hook, and it survived 13 test lists and 2993 test
cases — because a crash and a considered denial exit with the same code.
Someone else had to trip over it.

A resolution cannot fix that, because nothing about it is a decision. A hook
can: it records the warning, and the warning does not go away by being ignored.

THE FIVE STATES

  open           Starting state. Presented once every 24 hours.
  fixed          Set by NOBODY. This tool runs pyright and looks. A
                 measurement, not a claim — and harder to forge than any
                 marking, because it hangs on reality instead of on an
                 assertion.
  parked         The AI may set this, but only with a REASON and a DEADLINE.
                 When the deadline passes the entry is open again. Parking is
                 a postponement, not a disappearance.
  dismissed      Owner only. It is the single path on which a real warning
                 falls silent for good — whoever may walk it alone can switch
                 the whole thing off. The AI files a proposal; the owner
                 approves.
  moot           The file is gone. A finding, not a decision, so no approval
                 is needed. Not deleted: if the file returns and the warning
                 with it, it is recorded again.

WHY THE FILTER IS ON THE RULE NAME, NOT THE SEVERITY

Measured over 15942 real diagnostics from 570 transcripts: 8964 carry "Error".
Of those, 3720 are `reportMissingImports` — pyright not finding the virtual
environment, while the file is perfectly fine. A hook keyed on severity fires
on almost every edit and is switched off within a week.

The four rules below are decidable without import resolution, checkable in
seconds, and a hit is nearly always a real defect. Together: 2.1 percent of all
diagnostics. That is the order of magnitude at which an insisting hook is
bearable.

WHAT THIS PROTECTS AGAINST, AND WHAT IT DOES NOT

The register guards against NEGLIGENCE, not against intent. Anyone assembling
the path at runtime writes past it — the same limit the guard's own
self-protection has (measured, and named in THREAT-MODEL.md). That is the right
trade: the opponent here is one's own autopilot, not an attacker.

USAGE

  diagnostics-register.py stop            session-end hook (stdin: hook JSON)
  diagnostics-register.py start           session-start hook, throttled to 24h
  diagnostics-register.py list [--all]    show open entries
  diagnostics-register.py check           run pyright, close what is fixed
  diagnostics-register.py park <id> --reason "..." --days N
  diagnostics-register.py dismiss <id> --reason "..."   -> files a PROPOSAL
  diagnostics-register.py approve <id>    owner only: carries a proposal out
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# --- Storage --------------------------------------------------------------
# Overridable so test runs do NOT touch the real register. Without that
# separation every probe measures the everyday stock and writes into it at the
# same time.
BASE = Path(os.environ.get("DIAGNOSTICS_REGISTER_DIR")
            or (Path.home() / ".claude" / "diagnostics-register"))
REGISTER = BASE / "register.json"
PROPOSALS = BASE / "dismiss-proposals"
THROTTLE = BASE / "last-presented"
MISHAP = BASE / "mishap.log"

# See the module docstring for why this list is rule names and not severities.
SIGNAL_RULES = {
    "reportPossiblyUnboundVariable",
    "reportUndefinedVariable",
    "reportRedeclaration",
    "reportSelfClsParameterName",
}

# Throwaway places: warnings there are about code nobody maintains.
THROWAWAY = re.compile(r"/scratchpad/|/tmp/|/\.history/|/archiv/|/site-packages/")

MAX_PRESENTED = 3        # how many cases one reply names at most
THROTTLE_HOURS = 24


def now() -> datetime:
    return datetime.now(timezone.utc)


def _read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def load() -> dict:
    d = _read_json(REGISTER, {"version": 1, "entries": []})
    if not isinstance(d, dict) or "entries" not in d:
        return {"version": 1, "entries": []}
    return d


def save(d: dict) -> None:
    BASE.mkdir(parents=True, exist_ok=True)
    tmp = REGISTER.with_suffix(".json.new")
    tmp.write_text(json.dumps(d, ensure_ascii=False, indent=2) + "\n",
                   encoding="utf-8")
    tmp.replace(REGISTER)


def entry_id(file: str, rule: str, message: str) -> str:
    """A key without the line number.

    Lines move on every edit. The symbol name sits in the message ('"x" is
    possibly unbound') and stays stable — otherwise the same defect opens a new
    entry after every re-indent.
    """
    raw = f"{file}|{rule}|{message}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]


# --- Reading the transcript -----------------------------------------------

def from_transcript(path: Path) -> tuple[list[dict], set[str]]:
    """Returns (signal-class diagnostics, files touched in this session).

    Both from the same file: diagnostics arrive as their own entry
    (type=attachment, attachment.type=diagnostics), edits as tool calls. Only
    what is BOTH gets recorded — otherwise the hook complains about foreign
    code nobody touched in this session.
    """
    found: dict[str, dict] = {}
    touched: set[str] = set()
    try:
        with path.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                if ('"diagnostics"' not in line and '"tool_use"' not in line
                        and '"Edit"' not in line and '"Write"' not in line):
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue

                a = e.get("attachment") or {}
                if a.get("type") == "diagnostics":
                    for f_entry in a.get("files", []):
                        uri = f_entry.get("uri") or ""
                        if not uri or THROWAWAY.search(uri):
                            continue
                        for d in f_entry.get("diagnostics", []):
                            # The transcript calls the field 'code', the
                            # pyright CLI calls it 'rule'. Read both — knowing
                            # only one builds a hook that reliably stays silent
                            # in one of the two directions.
                            rule = d.get("code") or d.get("rule")
                            if rule not in SIGNAL_RULES:
                                continue
                            msg = d.get("message") or ""
                            k = entry_id(uri, rule, msg)
                            found[k] = {
                                "id": k, "file": uri, "rule": rule,
                                "message": msg,
                                "line": (d.get("range") or {}).get(
                                    "start", {}).get("line"),
                            }
                    continue

                content = (e.get("message") or {}).get("content")
                if isinstance(content, list):
                    for part in content:
                        if not isinstance(part, dict) or part.get("type") != "tool_use":
                            continue
                        if part.get("name") not in ("Edit", "Write", "MultiEdit",
                                                    "NotebookEdit"):
                            continue
                        p = (part.get("input") or {}).get("file_path")
                        if p:
                            touched.add(str(p))
    except OSError:
        return [], set()
    return list(found.values()), touched


# --- pyright: the measurement behind 'fixed' ------------------------------

def pyright_for(file: Path) -> list[dict] | None:
    """What pyright says about this file NOW. None = not measurable.

    None matters and must not be read as 'found nothing': if pyright is missing
    or the run breaks off, the entry is UNCHECKED, not fixed.
    """
    if not file.is_file():
        return None
    try:
        p = subprocess.run(["pyright", "--outputjson", str(file)],
                           capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return None
    try:
        d = json.loads(p.stdout)
    except json.JSONDecodeError:
        return None
    # NOTHING ANALYSED IS NOT NOTHING FOUND.
    # With filesAnalyzed=0 pyright reports "0 errors" and success — e.g. when
    # the file sits in a hidden directory (default exclude **/.*) or is
    # excluded by a pyrightconfig. Taking that as a result closes every entry
    # in such paths as fixed. Found by this project's own test list, not in
    # production.
    if (d.get("summary") or {}).get("filesAnalyzed", 0) < 1:
        return None
    return d.get("generalDiagnostics", [])


def check_fixed(register: dict) -> tuple[int, int, int]:
    """Hold every open/parked entry against reality."""
    closed = 0
    unchecked = 0
    moot = 0
    per_file: dict[str, list[dict] | None] = {}
    for e in register["entries"]:
        if e.get("state") not in ("open", "parked"):
            continue
        file = e["file"]
        # File gone is NOT the same as pyright silent. In the first case the
        # subject disappeared, in the second only the measurement failed.
        # Without the distinction every deleted throwaway file leaves an entry
        # that can never be measured fixed — presented daily, forever. That is
        # precisely the noise such a hook dies of. Found in the first live run,
        # not by the test list.
        if not Path(file).exists():
            e["state"] = "moot"
            e["moot_at"] = now().isoformat()
            moot += 1
            continue
        if file not in per_file:
            per_file[file] = pyright_for(Path(file))
        current = per_file[file]
        if current is None:
            unchecked += 1
            continue
        still_there = any(
            (x.get("rule") or x.get("code")) == e["rule"]
            and (x.get("message") or "") == e["message"]
            for x in current
        )
        e["last_checked"] = now().isoformat()
        if not still_there:
            e["state"] = "fixed"
            e["fixed_at"] = now().isoformat()
            closed += 1
    return closed, unchecked, moot


def check_deadlines(register: dict) -> int:
    """Expired parking deadlines go back to open. Parking is a postponement."""
    back = 0
    for e in register["entries"]:
        if e.get("state") != "parked":
            continue
        deadline = e.get("deadline")
        if not deadline:
            continue
        try:
            if datetime.fromisoformat(deadline) <= now():
                e["state"] = "open"
                e["deadline_passed_at"] = now().isoformat()
                back += 1
        except ValueError:
            continue
    return back


# --- Presentation ---------------------------------------------------------

def standing(e: dict) -> str:
    try:
        since = datetime.fromisoformat(e["first_seen"])
    except (KeyError, ValueError):
        return "?"
    hours = (now() - since).total_seconds() / 3600
    return f"{hours:.0f} h" if hours < 48 else f"{hours / 24:.0f} days"


def line_for(e: dict) -> str:
    short = Path(e["file"]).name
    return (f"  [{e['id']}] {short}:{(e.get('line') or 0) + 1}  "
            f"{e['message']}  ({e['rule']}, open for {standing(e)})")


def open_entries(register: dict) -> list[dict]:
    return [e for e in register["entries"] if e.get("state") == "open"]


# --- The hooks ------------------------------------------------------------

def hook_stop() -> int:
    """Session end: record what is new, close what is fixed, put it in the way."""
    payload = _read_stdin_json()
    path = payload.get("transcript_path")
    if not path:
        return 0
    found, touched = from_transcript(Path(path))
    register = load()
    known = {e["id"]: e for e in register["entries"]}

    fresh = []
    for m in found:
        if m["file"] not in touched:
            continue
        existing = known.get(m["id"])
        if existing:
            existing["last_seen"] = now().isoformat()
            existing["line"] = m["line"]
            continue
        m.update({
            "state": "open",
            "first_seen": now().isoformat(),
            "last_seen": now().isoformat(),
            "session": payload.get("session_id", ""),
        })
        register["entries"].append(m)
        fresh.append(m)

    check_deadlines(register)
    closed, _, _ = check_fixed(register)
    save(register)

    if not fresh:
        return 0

    text = [
        f"{len(fresh)} new tool diagnostic(s) recorded, state OPEN.",
        "These are classes that nearly always mean a real defect.",
        "",
    ]
    text += [line_for(e) for e in fresh[:MAX_PRESENTED]]
    if len(fresh) > MAX_PRESENTED:
        text.append(f"  ... and {len(fresh) - MAX_PRESENTED} more (see list)")
    text += [
        "",
        "What is expected is a REASON, not an acknowledgement. Three ways:",
        "  fixed     -- fix it; the register measures that itself, nothing to do",
        "  parked    -- diagnostics-register.py park <id> --reason \"...\" --days N",
        "  dismissed -- diagnostics-register.py dismiss <id> --reason \"...\"",
        "               (files a proposal; only the owner approves it)",
    ]
    if closed:
        text.insert(0, f"({closed} earlier entry measured as fixed.)")
    print(json.dumps({"decision": "block", "reason": "\n".join(text)}))
    return 0


def hook_start() -> int:
    """Session start: at most every 24h, present the oldest open case.

    ONE case, concretely — not a number. A message saying "3 open items" is the
    same wallpaper in two weeks that the warnings themselves are today.
    """
    register = load()
    if check_deadlines(register):
        save(register)
    entries = open_entries(register)
    if not entries:
        return 0

    last = _read_json(THROTTLE, {}).get("at")
    if last:
        try:
            if now() - datetime.fromisoformat(last) < timedelta(hours=THROTTLE_HOURS):
                return 0
        except ValueError:
            pass

    entries.sort(key=lambda e: e.get("first_seen", ""))
    oldest = entries[0]
    print("=" * 70)
    print(f"OPEN TOOL DIAGNOSTIC  ({len(entries)} total, oldest first)")
    print("=" * 70)
    print(f"  File    : {oldest['file']}")
    print(f"  Line    : {(oldest.get('line') or 0) + 1}")
    print(f"  Message : {oldest['message']}")
    print(f"  Rule    : {oldest['rule']}")
    print(f"  Open    : for {standing(oldest)}")
    print(f"  Id      : {oldest['id']}")
    print()
    print("  Check and decide: fix it, park it (with a deadline), or propose")
    print("  dismissing it. All open ones: diagnostics-register.py list")
    print("=" * 70)

    BASE.mkdir(parents=True, exist_ok=True)
    THROTTLE.write_text(json.dumps({"at": now().isoformat()}), encoding="utf-8")
    return 0


def _read_stdin_json() -> dict:
    try:
        return json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return {}


# --- Commands for the hand ------------------------------------------------

def cmd_list(args) -> int:
    register = load()
    check_deadlines(register)
    save(register)
    groups: dict[str, list[dict]] = {}
    for e in register["entries"]:
        if not args.all and e["state"] != "open":
            continue
        groups.setdefault(e["state"], []).append(e)
    if not groups:
        print("Register: no open entries.")
        return 0
    for state in ("open", "parked", "dismissed", "fixed", "moot"):
        if state not in groups:
            continue
        print(f"\n{state.upper()} ({len(groups[state])}):")
        for e in sorted(groups[state], key=lambda x: x.get("first_seen", "")):
            print(line_for(e))
            if e.get("reason"):
                print(f"        Reason: {e['reason']}")
            if e.get("deadline"):
                print(f"        Deadline: {e['deadline'][:10]}")
    return 0


def cmd_check(_args) -> int:      # signature kept uniform; arg unused
    register = load()
    back = check_deadlines(register)
    closed, unchecked, moot = check_fixed(register)
    save(register)
    print(f"measured as fixed: {closed}")
    print(f"moot (file gone): {moot}")
    print(f"parking deadline passed, open again: {back}")
    if unchecked:
        print(f"NOT measurable (pyright silent): {unchecked}")
        print("  These stay open -- unchecked is not fixed.")
    print(f"open now: {len(open_entries(register))}")
    return 0


def cmd_park(args) -> int:
    if args.days < 1 or args.days > 90:
        print("Deadline must be between 1 and 90 days.", file=sys.stderr)
        return 1
    if len(args.reason.strip()) < 15:
        print("The reason has to carry -- at least 15 characters.", file=sys.stderr)
        return 1
    register = load()
    for e in register["entries"]:
        if e["id"] != args.id:
            continue
        if e["state"] == "dismissed":
            print("Entry is dismissed, parking would do nothing.", file=sys.stderr)
            return 1
        e["state"] = "parked"
        e["reason"] = args.reason.strip()
        e["deadline"] = (now() + timedelta(days=args.days)).isoformat()
        e["parked_at"] = now().isoformat()
        save(register)
        print(f"Parked until {e['deadline'][:10]}. After that it is open again.")
        return 0
    print(f"No entry {args.id} in the register.", file=sys.stderr)
    return 1


def cmd_dismiss(args) -> int:
    """Files a PROPOSAL. Dismissing itself is the owner's call.

    Deliberately no write access to the state: dismissing is the single path on
    which a real warning falls silent for good. Whoever may walk it alone can
    switch the whole hook off.
    """
    if len(args.reason.strip()) < 25:
        print("Dismissing needs a carrying reason -- at least 25 characters.",
              file=sys.stderr)
        return 1
    register = load()
    hit = next((e for e in register["entries"] if e["id"] == args.id), None)
    if not hit:
        print(f"No entry {args.id} in the register.", file=sys.stderr)
        return 1
    PROPOSALS.mkdir(parents=True, exist_ok=True)
    target = PROPOSALS / f"{args.id}.json"
    target.write_text(json.dumps({
        "id": args.id, "file": hit["file"], "rule": hit["rule"],
        "message": hit["message"], "reason": args.reason.strip(),
        "proposed_at": now().isoformat(), "confirmed": False,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Proposal filed: {target}")
    print("The entry stays OPEN until the owner approves it.")
    return 0


def cmd_approve(args) -> int:
    """Owner side: carries a filed proposal out."""
    source = PROPOSALS / f"{args.id}.json"
    proposal = _read_json(source, None)
    if not proposal:
        print(f"No proposal for {args.id}.", file=sys.stderr)
        return 1
    register = load()
    for e in register["entries"]:
        if e["id"] != args.id:
            continue
        e["state"] = "dismissed"
        e["reason"] = proposal.get("reason", "")
        e["dismissed_at"] = now().isoformat()
        save(register)
        source.unlink(missing_ok=True)
        print(f"Dismissed: {e['message']}")
        return 0
    print(f"No entry {args.id} in the register.", file=sys.stderr)
    return 1


def main() -> int:
    p = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("stop")
    sub.add_parser("start")
    pl = sub.add_parser("list")
    pl.add_argument("--all", action="store_true")
    sub.add_parser("check")
    pp = sub.add_parser("park")
    pp.add_argument("id")
    pp.add_argument("--reason", required=True)
    pp.add_argument("--days", type=int, required=True)
    pd = sub.add_parser("dismiss")
    pd.add_argument("id")
    pd.add_argument("--reason", required=True)
    pa = sub.add_parser("approve")
    pa.add_argument("id")
    a = p.parse_args()

    try:
        if a.command == "stop":
            return hook_stop()
        if a.command == "start":
            return hook_start()
        if a.command == "list":
            return cmd_list(a)
        if a.command == "check":
            return cmd_check(a)
        if a.command == "park":
            return cmd_park(a)
        if a.command == "dismiss":
            return cmd_dismiss(a)
        if a.command == "approve":
            return cmd_approve(a)
    except Exception as err:                          # noqa: BLE001
        # A hook must not halt the session when IT is broken. But it must not
        # stay silent either: swallowing errors is exactly the blind spot that
        # kept a crash in the guard invisible for a day. So make it visible AND
        # let the session continue.
        try:
            BASE.mkdir(parents=True, exist_ok=True)
            with MISHAP.open("a", encoding="utf-8") as f:
                f.write(f"{now().isoformat()} {a.command}: {err!r}\n")
        except OSError:
            pass
        print(f"diagnostics-register: own failure ({err}). See {MISHAP}",
              file=sys.stderr)
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
