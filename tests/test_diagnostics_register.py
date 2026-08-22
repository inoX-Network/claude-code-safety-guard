# ============================================================================
# The diagnostics register: a warning you cannot file away.
#
# Language-server warnings arrive as an ATTACHMENT, not as an answer. The
# filter "not my change, pre-existing code" is right most of the time and runs
# automatically — and that is exactly when it takes the one real warning with
# it. Measured cost in this project: a crash in the most common branch of the
# write check, shown twice on the same day and filed away both times.
#
# Every case below pins ONE promise. The build is deliberately end to end: a
# real transcript is written, a real Python file with a real pyright error is
# created, and the hook runs with real stdin. A test calling the functions
# directly would miss the most important finding — that the diagnostics only
# appear in the transcript LATER, so a PostToolUse hook on the edit itself
# reliably finds nothing.
#
# Each run gets its own register directory. Without that separation the probe
# writes into the everyday stock while measuring it.
#
# Two traps this file has already fallen into, both kept as cases:
#   - The probe filtered ITSELF out: its files lived under /tmp, one of the
#     throwaway paths the hook deliberately skips. Red for the wrong reason
#     proves nothing.
#   - pyright reports "0 errors" and success when it analysed NOTHING
#     (filesAnalyzed=0, e.g. a hidden directory). The first version closed
#     every such entry as fixed — the exact opposite of its purpose.
# ============================================================================
import json
import os
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = Path(os.environ.get("DIAGNOSTICS_REGISTER")
              or (REPO / "hooks" / "diagnostics-register.py"))

BROKEN = '''def example(flag: bool) -> str:
    if flag:
        value = "set"
    return value
'''

SOUND = '''def example(flag: bool) -> str:
    value = "set" if flag else "unset"
    return value
'''

# A diagnostic that must NOT fire: pyright cannot find the environment.
# Measured the largest noise class -- 3720 of 8964 "Error".
NOISE = '''import a_module_that_is_not_installed
print(a_module_that_is_not_installed)
'''


class Bench:
    """A throwaway workbench: own register, own transcript."""

    def __init__(self, folder: Path):
        self.folder = folder
        self.register_dir = folder / "register"
        self.transcript = folder / "transcript.jsonl"
        self.file = folder / "module.py"

    def env(self) -> dict:
        e = dict(os.environ)
        e["DIAGNOSTICS_REGISTER_DIR"] = str(self.register_dir)
        return e

    def write_transcript(self, diagnostics: list[dict], touched: list[str]) -> None:
        """Rebuilds a transcript the way Claude Code writes one."""
        lines = []
        for path in touched:
            lines.append({
                "type": "assistant",
                "message": {"role": "assistant", "content": [
                    {"type": "tool_use", "name": "Edit",
                     "input": {"file_path": path}}]},
            })
        if diagnostics:
            lines.append({
                "type": "attachment",
                "attachment": {
                    "type": "diagnostics", "isNew": True,
                    "files": [{"uri": str(self.file), "diagnostics": diagnostics}],
                },
            })
        self.transcript.write_text(
            "\n".join(json.dumps(z, ensure_ascii=False) for z in lines) + "\n",
            encoding="utf-8")

    def hook(self, which: str) -> tuple[int, str]:
        payload = json.dumps({"session_id": "probe",
                              "hook_event_name": "Stop",
                              "transcript_path": str(self.transcript)})
        p = subprocess.run(["python3", str(SCRIPT), which],
                           input=payload, capture_output=True, text=True,
                           env=self.env(), timeout=300)
        return p.returncode, p.stdout + p.stderr

    def run(self, *parts: str) -> tuple[int, str]:
        p = subprocess.run(["python3", str(SCRIPT), *parts],
                           capture_output=True, text=True, env=self.env(),
                           timeout=300)
        return p.returncode, p.stdout + p.stderr

    def register(self) -> dict:
        path = self.register_dir / "register.json"
        if not path.is_file():
            return {"entries": []}
        return json.loads(path.read_text(encoding="utf-8"))


def _signal() -> dict:
    return {"message": '"value" is possibly unbound', "severity": "Error",
            "range": {"start": {"line": 3, "character": 11}},
            "source": "Pyright", "code": "reportPossiblyUnboundVariable"}


def _noise() -> dict:
    return {"message": 'Import "a_module_that_is_not_installed" could not be resolved',
            "severity": "Error", "range": {"start": {"line": 0, "character": 7}},
            "source": "Pyright", "code": "reportMissingImports"}


# --- what must be RECORDED --------------------------------------------------

def check_signal_class_is_recorded_and_presented(b: Bench):
    b.file.write_text(BROKEN, encoding="utf-8")
    b.write_transcript([_signal()], [str(b.file)])
    _, out = b.hook("stop")
    entries = b.register()["entries"]
    if len(entries) != 1:
        return False, f"{len(entries)} entries instead of 1"
    if entries[0]["state"] != "open":
        return False, f"state {entries[0]['state']} instead of open"
    if '"decision": "block"' not in out:
        return False, "no reply to the model"
    if "REASON" not in out:
        return False, "the reply does not ask for a reason"
    return True, "recorded and presented"


def check_noise_class_does_not_fire(b: Bench):
    """The most important free case: without it the hook is off within a week."""
    b.file.write_text(NOISE, encoding="utf-8")
    b.write_transcript([_noise()], [str(b.file)])
    _, out = b.hook("stop")
    if b.register()["entries"]:
        return False, "noise was recorded"
    if "decision" in out:
        return False, "replied although it was noise"
    return True, "stayed silent"


def check_only_files_edited_this_session(b: Bench):
    b.file.write_text(BROKEN, encoding="utf-8")
    b.write_transcript([_signal()], [])          # nothing edited
    b.hook("stop")
    if b.register()["entries"]:
        return False, "foreign code was recorded"
    return True, "foreign code ignored"


def check_no_duplicate_after_a_line_shift(b: Bench):
    b.file.write_text(BROKEN, encoding="utf-8")
    b.write_transcript([_signal()], [str(b.file)])
    b.hook("stop")
    shifted = _signal()
    shifted["range"]["start"]["line"] = 99
    b.write_transcript([shifted], [str(b.file)])
    b.hook("stop")
    n = len(b.register()["entries"])
    if n != 1:
        return False, f"{n} entries -- a line shift opens a new one"
    return True, "stable against line shifts"


# --- how an entry may LEAVE the open state ---------------------------------

def check_fixed_is_measured_not_claimed(b: Bench):
    """The core of the design: 'fixed' is a measurement, not an assertion."""
    b.file.write_text(BROKEN, encoding="utf-8")
    b.write_transcript([_signal()], [str(b.file)])
    b.hook("stop")
    if b.register()["entries"][0]["state"] != "open":
        return False, "does not start as open"
    b.file.write_text(SOUND, encoding="utf-8")       # fix it
    _, out = b.run("check")
    state = b.register()["entries"][0]["state"]
    if state != "fixed":
        return False, f"state {state} instead of fixed -- {out.strip()[:80]}"
    return True, "measured by itself"


def check_a_gone_file_is_moot_not_fixed(b: Bench):
    """From the first live run: two of four entries were about a deleted file.

    They can never be measured fixed, so they would have stayed open forever
    and been presented daily -- precisely the noise such a hook dies of. 'Moot'
    is a finding, not a decision, so it needs no approval.
    """
    b.file.write_text(BROKEN, encoding="utf-8")
    b.write_transcript([_signal()], [str(b.file)])
    b.hook("stop")
    b.file.unlink()
    b.run("check")
    state = b.register()["entries"][0]["state"]
    if state == "fixed":
        return False, "a gone file was counted as fixed"
    if state != "moot":
        return False, f"state {state} instead of moot"
    return True, "a finding, no approval"


def check_moot_entries_are_not_presented(b: Bench):
    b.file.write_text(BROKEN, encoding="utf-8")
    b.write_transcript([_signal()], [str(b.file)])
    b.hook("stop")
    b.file.unlink()
    b.run("check")
    _, out = b.run("start")
    if "OPEN TOOL DIAGNOSTIC" in out:
        return False, "a moot entry is still presented"
    return True, "silent"


def check_unanalysed_is_not_fixed(b: Bench):
    """pyright reports "0 errors" and success when it analysed NOTHING.

    Regression for a real defect: in a hidden directory pyright skips the file,
    reports success and zero errors. The first version closed every entry in
    such paths as fixed -- an empty result blamed on reality instead of on the
    method. Note this is a DIFFERENT case from the one above: the file is still
    there, only the measurement failed, so the entry must stay OPEN.
    """
    hidden = b.folder / ".invisible"
    hidden.mkdir()
    b.file = hidden / "module.py"
    b.file.write_text(BROKEN, encoding="utf-8")
    b.write_transcript([_signal()], [str(b.file)])
    b.hook("stop")
    entries = b.register()["entries"]
    if not entries:
        return False, "not recorded at all"
    if entries[0]["state"] != "open":
        return False, f"state {entries[0]['state']} -- unanalysed counted as resolved"
    return True, "unanalysed stays open"


def check_parking_needs_a_reason_and_a_deadline(b: Bench):
    b.file.write_text(BROKEN, encoding="utf-8")
    b.write_transcript([_signal()], [str(b.file)])
    b.hook("stop")
    ident = b.register()["entries"][0]["id"]
    rc, _ = b.run("park", ident, "--reason", "later", "--days", "7")
    if rc == 0:
        return False, "a thin reason was accepted"
    rc, _ = b.run("park", ident, "--reason",
                  "Goes away once the image path rework lands", "--days", "999")
    if rc == 0:
        return False, "a 999-day deadline was accepted"
    rc, _ = b.run("park", ident, "--reason",
                  "Goes away once the image path rework lands", "--days", "7")
    if rc != 0:
        return False, "a valid park was rejected"
    if b.register()["entries"][0]["state"] != "parked":
        return False, "state is not parked"
    return True, "reason and deadline enforced"


def check_an_expired_deadline_reopens(b: Bench):
    """Without this, parking is the comfortable exit everything vanishes through."""
    b.file.write_text(BROKEN, encoding="utf-8")
    b.write_transcript([_signal()], [str(b.file)])
    b.hook("stop")
    ident = b.register()["entries"][0]["id"]
    b.run("park", ident, "--reason",
          "Goes away once the image path rework lands", "--days", "7")
    path = b.register_dir / "register.json"
    d = json.loads(path.read_text(encoding="utf-8"))
    d["entries"][0]["deadline"] = (datetime.now(timezone.utc)
                                   - timedelta(days=1)).isoformat()
    path.write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")
    b.run("list")
    state = b.register()["entries"][0]["state"]
    if state != "open":
        return False, f"state {state} instead of open"
    return True, "a postponement, not a disappearance"


def check_dismissing_needs_approval(b: Bench):
    """The single path on which a real warning falls silent for good."""
    b.file.write_text(BROKEN, encoding="utf-8")
    b.write_transcript([_signal()], [str(b.file)])
    b.hook("stop")
    ident = b.register()["entries"][0]["id"]
    rc, _ = b.run("dismiss", ident, "--reason", "unimportant")
    if rc == 0:
        return False, "a thin reason was accepted"
    rc, _ = b.run("dismiss", ident, "--reason",
                  "Pyright misreads the dynamic pattern here, the code is sound")
    if rc != 0:
        return False, "a valid proposal was rejected"
    if b.register()["entries"][0]["state"] != "open":
        return False, "state changed without approval -- HOLE"
    proposal = b.register_dir / "dismiss-proposals" / f"{ident}.json"
    if not proposal.is_file():
        return False, "no proposal filed"
    if json.loads(proposal.read_text(encoding="utf-8")).get("confirmed") is not False:
        return False, "the proposal counts as confirmed"
    b.run("approve", ident)
    if b.register()["entries"][0]["state"] != "dismissed":
        return False, "approval had no effect"
    return True, "proposal needed, approval works"


# --- the reminder, and not halting the session ------------------------------

def check_the_reminder_is_concrete_and_throttled(b: Bench):
    b.file.write_text(BROKEN, encoding="utf-8")
    b.write_transcript([_signal()], [str(b.file)])
    b.hook("stop")
    _, first = b.run("start")
    if "OPEN TOOL DIAGNOSTIC" not in first:
        return False, "the first reminder did not appear"
    if "possibly unbound" not in first:
        return False, "the reminder does not name the case concretely"
    _, second = b.run("start")
    if "OPEN TOOL DIAGNOSTIC" in second:
        return False, "the second reminder came at once -- no throttle"
    return True, "once concretely, then silent"


def check_a_broken_transcript_halts_nothing(b: Bench):
    b.transcript.write_text("this is not JSON\n{half", encoding="utf-8")
    rc, _ = b.hook("stop")
    if rc != 0:
        return False, f"the hook halts the session (rc={rc})"
    return True, "let through"


CASES = [
    ("signal class is recorded and presented", check_signal_class_is_recorded_and_presented),
    ("noise class does not fire", check_noise_class_does_not_fire),
    ("only files edited this session", check_only_files_edited_this_session),
    ("no duplicate after a line shift", check_no_duplicate_after_a_line_shift),
    ("fixed is measured, not claimed", check_fixed_is_measured_not_claimed),
    ("a gone file is moot, not fixed", check_a_gone_file_is_moot_not_fixed),
    ("moot entries are not presented", check_moot_entries_are_not_presented),
    ("unanalysed is not fixed", check_unanalysed_is_not_fixed),
    ("parking needs a reason and a deadline", check_parking_needs_a_reason_and_a_deadline),
    ("an expired deadline reopens", check_an_expired_deadline_reopens),
    ("dismissing needs approval", check_dismissing_needs_approval),
    ("the reminder is concrete and throttled", check_the_reminder_is_concrete_and_throttled),
    ("a broken transcript halts nothing", check_a_broken_transcript_halts_nothing),
]


def _bench_root() -> Path:
    """NOT under /tmp: that is one of the throwaway paths the hook skips.

    The first run of this list reported 8 of 11 red -- the probe had filtered
    itself out and was measuring its own storage instead of the hook.
    """
    root = REPO / "tests" / "benches"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _run_case(fn):
    with tempfile.TemporaryDirectory(dir=_bench_root()) as d:
        return fn(Bench(Path(d)))


try:
    import pytest

    @pytest.mark.parametrize("name,fn", CASES)
    def test_diagnostics_register(name, fn):
        ok, detail = _run_case(fn)
        assert ok, f"{name}: {detail}"

except ImportError:
    pass


if __name__ == "__main__":
    failures = 0
    for name, fn in CASES:
        try:
            ok, detail = _run_case(fn)
        except Exception as err:                      # noqa: BLE001
            ok, detail = False, f"the probe itself stumbled: {err!r}"
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            print(f"      {detail}")
    raise SystemExit(0 if not failures else 1)
