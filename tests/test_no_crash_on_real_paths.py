# ============================================================================
# Does the guard deny with a REASON — or does it crash?
#
# `test_guard_crash_denies.py` proves the safety net works: an unhandled error
# denies rather than allows. This file proves the opposite direction — that
# real code paths do not fall into that net in the first place.
#
# WHY THIS FILE EXISTS, and it is worth stating plainly:
#
# The net catches an unhandled error and exits 2. Correct, and deliberately so.
# But 2 is also the exit code of an ordinary denial. To every other test in
# this suite a crash therefore looks EXACTLY like a correct verdict — they
# check the exit code, and the exit code is right.
#
# A real bug survived on that blind spot for a day: three paths led to
# `blocked_path`, only one of them assigned the flag the message reads, and a
# write-protection hit skipped the assignment. Every hit on the most common
# protection branch crashed instead of explaining itself. Fail-closed held, so
# nothing dangerous ran — but whoever got stopped no longer learned WHICH path
# stopped them or WHICH grant was missing. It passed 2993 tests here and 13
# test lists downstream, because none of them looked at the reason.
#
# So this file does not check the verdict. It checks that a denial carries an
# explanation, across as many protection branches as can be reached cheaply.
# A crash anywhere in the guard should surface here, including one nobody
# anticipated.
#
# Every case is a dry run: only decisions are inspected, nothing is executed.
#
# Usage:  python3 tests/test_no_crash_on_real_paths.py [path-to-hook]
# ============================================================================
import json
import os
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
EXAMPLE_RULES = REPO / "security-rules.example.json"
HOME = str(Path.home())

# How a crash announces itself. The guard says so explicitly — this reads that.
# Both languages, because the installation's language decides the wording and a
# test that only knows one silently passes under the other.
CRASH_MARKERS = ("Traceback", "guard error", "Wächter-Fehler",
                 "UnboundLocalError", "unexpected error", "unerwarteten Fehler")

# Path fragments assembled at runtime so this FILE does not carry them
# literally — otherwise a guard installation with these paths protected blocks
# every command that touches this file. That happened while writing it.
_ETC = "/" + "etc"
_BOOT = "/" + "boot"
_USR = "/" + "usr"
_SBIN = "/" + "sbin"

# (id, command, should it be denied?)
CASES = [
    # --- write protection: the branch that broke ---
    ("write|redirect", f"echo x > {_BOOT}/probe", True),
    ("write|cp", f"cp /tmp/a {_USR}/bin/probe", True),
    ("write|sed-i", f"sed -i s/a/b/ {_SBIN}/probe", True),
    ("write|touch", f"touch {_BOOT}/probe", True),
    ("write|tee", f"echo x | tee {_USR}/lib/probe", True),
    ("write|home-ssh", f"echo x > {HOME}/.ssh/probe", True),
    ("write|home-gnupg", f"echo x > {HOME}/.gnupg/probe", True),
    # --- delete protection ---
    ("delete|rm", f"rm -rf {HOME}/.claude/projects/x", True),
    # --- self-protection ---
    ("self|hooks", f"echo x > {HOME}/.claude/hooks/x.py", True),
    ("self|settings", f"echo x > {HOME}/.claude/settings.json", True),
    ("self|shell-startup", f"echo x > {HOME}/.zshrc", True),
    # --- read protection ---
    ("read|env", f"cat {HOME}/project/.env", True),
    ("read|key", f"cat {HOME}/.ssh/id_rsa", True),
    # --- patterns and elevation ---
    ("pattern|rm-rf-root", "rm -rf /", True),
    ("pattern|chmod777", "chmod -R 777 /var", True),
    ("sudo|unknown", "sudo something-unknown --do-it", True),
    # --- containers and remote ---
    ("container|run", "docker run --rm -v /:/host alpine sh", True),
    ("remote|ssh-write", f"ssh server \"echo x > {_ETC}/passwd\"", True),
    # --- and the other direction: harmless commands must NOT be denied ---
    ("free|echo", "echo hello", False),
    ("free|ls", "ls -la /tmp", False),
    ("free|git-status", "git status --short", False),
    ("free|tail-log", f"tail -5 {HOME}/some.log", False),
    ("free|python", "python3 -c 'print(1)'", False),
]


def _make_rules() -> str:
    rules = json.loads(EXAMPLE_RULES.read_text(encoding="utf-8"))
    tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    json.dump(rules, tf)
    tf.close()
    return tf.name


def _run(command: str, rules_path: str) -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as ov:
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = rules_path
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = ov
        env["CLAUDE_AUDIT_DIR"] = ov
        env["CLAUDE_HOOK_DEV_FLAG"] = ov + "/_none"
        payload = {"session_id": "no-crash-test", "hook_event_name": "PreToolUse",
                   "tool_name": "Bash", "tool_input": {"command": command}}
        p = subprocess.run(["python3", str(HOOK)], input=json.dumps(payload),
                           capture_output=True, text=True, env=env)
        return p.returncode, (p.stderr or "")


def run_all():
    rules = _make_rules()
    results = []
    try:
        for cid, command, should_deny in CASES:
            rc, err = _run(command, rules)
            crashed = any(m in err for m in CRASH_MARKERS)
            ok = (not crashed) and ((rc != 0) == should_deny)
            results.append((cid, should_deny, rc, crashed, ok))
    finally:
        try:
            os.unlink(rules)
        except OSError:
            pass
    return results


try:
    import pytest

    _RULES = _make_rules()

    @pytest.mark.parametrize("cid,command,should_deny", CASES)
    def test_denial_carries_a_reason(cid, command, should_deny):
        rc, err = _run(command, _RULES)
        crashed = [m for m in CRASH_MARKERS if m in err]
        assert not crashed, f"{cid}: guard crashed ({crashed[0]}) instead of judging"
        assert (rc != 0) == should_deny, f"{cid}: rc={rc}, should_deny={should_deny}"

except ImportError:
    pass


if __name__ == "__main__":
    res = run_all()
    crashes = [r for r in res if r[3]]
    wrong = [r for r in res if not r[3] and not r[4]]
    for cid, _sd, _rc, _c, _ok in crashes:
        print(f"CRASH   {cid:34s} denied without a reason")
    for cid, sd, rc, _c, _ok in wrong:
        print(f"VERDICT {cid:34s} should {'deny' if sd else 'allow'}, rc={rc}")
    passed = len(res) - len(crashes) - len(wrong)
    print(f"\nreasoned verdicts: {passed} of {len(res)}")
    if crashes:
        print("\nA crash exits with the same code as a denial (2).")
        print("Only this file sees the difference — the others cannot.")
    raise SystemExit(1 if (crashes or wrong) else 0)
