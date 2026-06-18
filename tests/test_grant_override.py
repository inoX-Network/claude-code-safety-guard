"""Tests for grant-override's default session-binding (fail-safe default).

Drives the actual grant-override script via subprocess in an isolated temp env
(pending/active/audit dirs + CLAUDE_CODE_SESSION_ID), and checks the activated
override file. Covers the four acceptance criteria of the default-bind change.
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "bin" / "grant-override"


def _run(args, env_sid, pending_data):
    """Runs grant-override on a pending file. Returns (returncode, active_data|None)."""
    with tempfile.TemporaryDirectory() as d:
        pend = Path(d) / "pending"; pend.mkdir()
        active = Path(d) / "active"; active.mkdir()
        audit = Path(d) / "audit"; audit.mkdir()
        fname = "agent-test.json"
        (pend / fname).write_text(json.dumps(pending_data), encoding="utf-8")
        env = dict(os.environ)
        env["CLAUDE_SUDO_PENDING_DIR"] = str(pend)
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = str(active)
        env["CLAUDE_AUDIT_DIR"] = str(audit)
        if env_sid is None:
            env.pop("CLAUDE_CODE_SESSION_ID", None)
        else:
            env["CLAUDE_CODE_SESSION_ID"] = env_sid
        p = subprocess.run([sys.executable, str(SCRIPT), "test", *args],
                           capture_output=True, text=True, env=env)
        af = active / fname
        data = json.loads(af.read_text(encoding="utf-8")) if af.exists() else None
        return p.returncode, data


def _pending(session_id=None):
    d = {"override_level": 1, "task": "test task", "confirmed": False,
         "agent_id": "test", "grants": {"additional_sudo": ["htop"], "allowed_paths": []}}
    if session_id is not None:
        d["session_id"] = session_id
    return d


def main() -> int:
    results = []

    # 1. default-bind, env sid set -> active file carries session_id == env sid
    rc, data = _run([], "SID-1", _pending())
    results.append(("1 default-bind stamps env session_id",
                    rc == 0 and data is not None and data.get("session_id") == "SID-1"))

    # 2. default-bind, env sid EMPTY -> abort, no active file
    rc, data = _run([], None, _pending())
    results.append(("2 empty session_id -> abort, no active file",
                    rc != 0 and data is None))

    # 3. --all-sessions -> active file has NO session_id
    rc, data = _run(["--all-sessions"], "SID-1", _pending())
    results.append(("3 --all-sessions -> no session_id field",
                    rc == 0 and data is not None and "session_id" not in data))

    # 4. AI-supplied session_id in proposal is OVERWRITTEN with env sid
    rc, data = _run([], "SID-REAL", _pending(session_id="FAKE-FROM-AI"))
    results.append(("4 AI session_id overwritten by granting env",
                    rc == 0 and data is not None and data.get("session_id") == "SID-REAL"))

    passed = sum(1 for _, ok in results if ok)
    for name, ok in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
    print(f"\ngrant-override bind: {passed}/{len(results)} passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
