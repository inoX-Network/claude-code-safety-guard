# ============================================================================
# The update check: opt-in, throttled, and silent when anything goes wrong.
#
# The point of this file is less "does it compare versions" (it does, they are
# dates) and more the three properties that make it acceptable in a security
# tool at all:
#
#   1. OFF unless the user says otherwise. Nothing may leave the machine before
#      someone put `enabled: true` in their config. A tool that phones home
#      uninvited spends the trust it needs.
#   2. Throttled. It runs at every session start, so a second start an hour
#      later must NOT produce a second request.
#   3. Silent on failure. No network, garbage answer, unreadable config — all of
#      it ends in silence, never a daily complaint about an optional feature.
#
# The network is never touched here. `_fetch_published` is replaced with a stand
# in, which also keeps a test klaxon out of the production code: there is no
# "test source" env var to be abused.
# ============================================================================
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "hooks" / "update-check.py"


def _load(config_path: Path, state_path: Path):
    """Load the script as a module with its paths pointed at a temp dir."""
    os.environ["CLAUDE_UPDATE_CONFIG"] = str(config_path)
    os.environ["CLAUDE_UPDATE_STATE"] = str(state_path)
    spec = importlib.util.spec_from_file_location("update_check_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.CONFIG_PATH = config_path
    module.STATE_PATH = state_path
    return module


def _run(config: dict | None, published: str | None, *,
         state: dict | None = None, installed: str = "2026.08.21"):
    """Run main() with a stand-in fetcher. Returns (output, state_after)."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        config_path = tmp / "guard-config.json"
        state_path = tmp / "state.json"
        if config is not None:
            config_path.write_text(json.dumps(config), encoding="utf-8")
        if state is not None:
            state_path.write_text(json.dumps(state), encoding="utf-8")

        module = _load(config_path, state_path)
        calls = []

        def _stand_in(source):
            calls.append(source)
            return published

        module._fetch_published = _stand_in
        module._installed_version = lambda: installed

        import io
        from contextlib import redirect_stdout
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            module.main()
        after = {}
        if state_path.exists():
            after = json.loads(state_path.read_text(encoding="utf-8"))
        return buffer.getvalue().strip(), after, calls


ON = {"update_check": {"enabled": True}}


# --- 1. nothing leaves the machine unless asked -----------------------------

def check_disabled_makes_no_request():
    _, _, calls = _run(None, "2026.09.01")
    return not calls, f"fetched despite being off: {calls}"


def check_missing_key_makes_no_request():
    _, _, calls = _run({"language": "de"}, "2026.09.01")
    return not calls, f"fetched without the key: {calls}"


def check_enabled_false_makes_no_request():
    _, _, calls = _run({"update_check": {"enabled": False}}, "2026.09.01")
    return not calls, f"fetched despite enabled=false: {calls}"


def check_enabled_must_be_true_not_truthy():
    """A string 'yes' is not consent — only a real true counts."""
    _, _, calls = _run({"update_check": {"enabled": "yes"}}, "2026.09.01")
    return not calls, f"a truthy value was taken as consent: {calls}"


def check_off_mentions_the_feature_once():
    out, state, _ = _run(None, None)
    if "update_check" not in out:
        return False, f"the one-time note does not name the key: {out!r}"
    return state.get("informed_about_feature") is True, "note not recorded"


def check_off_does_not_mention_it_twice():
    out, _, _ = _run(None, None, state={"informed_about_feature": True})
    return out == "", f"nagged a second time: {out!r}"


# --- 2. it reports only what is actually newer ------------------------------

def check_newer_version_is_reported():
    out, _, _ = _run(ON, "2026.09.01")
    return "2026.09.01" in out, f"no report: {out!r}"


def check_same_version_stays_quiet():
    out, _, _ = _run(ON, "2026.08.21")
    return out == "", f"reported although equal: {out!r}"


def check_older_version_stays_quiet():
    """A fork or a rollback must not be announced as an update."""
    out, _, _ = _run(ON, "2026.07.01")
    return out == "", f"reported although older: {out!r}"


# --- 3. throttling ----------------------------------------------------------

def check_recent_check_makes_no_request():
    recent = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    _, _, calls = _run(ON, "2026.09.01", state={"last_check": recent})
    return not calls, f"fetched inside the interval: {calls}"


def check_old_check_makes_a_request():
    old = (datetime.now(timezone.utc) - timedelta(hours=30)).isoformat()
    _, _, calls = _run(ON, "2026.09.01", state={"last_check": old})
    return len(calls) == 1, f"expected one request, got {calls}"


def check_broken_timestamp_is_treated_as_due():
    """A corrupt state file must not disable the check forever."""
    _, _, calls = _run(ON, "2026.09.01", state={"last_check": "not-a-date"})
    return len(calls) == 1, f"expected one request, got {calls}"


# --- 4. silence on every failure --------------------------------------------

def check_unreachable_source_stays_quiet():
    out, _, _ = _run(ON, None)
    return out == "", f"complained about the network: {out!r}"


def check_unreachable_source_still_records_the_attempt():
    """Otherwise a machine without network retries at every session start."""
    _, state, _ = _run(ON, None)
    return "last_check" in state, "no timestamp written after a failed fetch"


def check_missing_version_file_stays_quiet():
    out, _, calls = _run(ON, "2026.09.01", installed=None)
    return out == "" and not calls, f"acted without a local version: {out!r} {calls}"


# --- 5. the source is not free-form ----------------------------------------

def check_plain_http_source_is_refused():
    """An unencrypted answer could be tampered with in transit, and this one
    decides what the user is told about security."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        cfg = tmp / "c.json"
        cfg.write_text(json.dumps(
            {"update_check": {"enabled": True, "source": "http://evil.example/V"}}),
            encoding="utf-8")
        module = _load(cfg, tmp / "s.json")
        _, _, source = module._settings(json.loads(cfg.read_text(encoding="utf-8")))
    return source.startswith("https://github") or "githubusercontent" in source, \
        f"plain http was accepted: {source}"


def check_absurd_interval_falls_back():
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        cfg = tmp / "c.json"
        cfg.write_text(json.dumps(
            {"update_check": {"enabled": True, "interval_hours": -5}}), encoding="utf-8")
        module = _load(cfg, tmp / "s.json")
        _, interval, _ = module._settings(json.loads(cfg.read_text(encoding="utf-8")))
    return interval == 24, f"negative interval accepted: {interval}"


# --- 6. end to end, without a network --------------------------------------

def check_script_runs_and_exits_zero():
    """Called the way the session start calls it. Off by default, so no network."""
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        env = dict(os.environ)
        env["CLAUDE_UPDATE_CONFIG"] = str(tmp / "absent.json")
        env["CLAUDE_UPDATE_STATE"] = str(tmp / "state.json")
        p = subprocess.run([sys.executable, str(SCRIPT)],
                           capture_output=True, text=True, env=env, timeout=20)
    return p.returncode == 0, f"exit {p.returncode}: {p.stderr[:120]}"


CASES = [
    ("disabled makes no request", check_disabled_makes_no_request),
    ("missing key makes no request", check_missing_key_makes_no_request),
    ("enabled false makes no request", check_enabled_false_makes_no_request),
    ("only a real true counts as consent", check_enabled_must_be_true_not_truthy),
    ("off mentions the feature once", check_off_mentions_the_feature_once),
    ("off does not mention it twice", check_off_does_not_mention_it_twice),
    ("newer version is reported", check_newer_version_is_reported),
    ("same version stays quiet", check_same_version_stays_quiet),
    ("older version stays quiet", check_older_version_stays_quiet),
    ("recent check makes no request", check_recent_check_makes_no_request),
    ("old check makes a request", check_old_check_makes_a_request),
    ("broken timestamp is treated as due", check_broken_timestamp_is_treated_as_due),
    ("unreachable source stays quiet", check_unreachable_source_stays_quiet),
    ("failed fetch is still recorded", check_unreachable_source_still_records_the_attempt),
    ("missing version file stays quiet", check_missing_version_file_stays_quiet),
    ("plain http source is refused", check_plain_http_source_is_refused),
    ("absurd interval falls back", check_absurd_interval_falls_back),
    ("script runs and exits zero", check_script_runs_and_exits_zero),
]

try:
    import pytest

    @pytest.mark.parametrize("name,fn", CASES)
    def test_update_check(name, fn):
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
