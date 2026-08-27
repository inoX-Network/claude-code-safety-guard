# ============================================================================
# Force-push hides in a refspec.
#
# The force-push rules look for --force / -f. But git forces an update just as
# well with a refspec whose leading '+' means "force":
#
#   git push origin +main          == force-push main
#   git push origin +HEAD:main
#   git push origin +refs/heads/main
#
# None of those carries --force or -f, so the old patterns waved them through.
# Measured against a real command corpus (214,826 Bash commands): the naive
# catch "git push ... +" also matched an arithmetic 'a + b' inside a python
# heredoc that merely mentioned "git push" as text -- one false positive. Hence
# the tightened form: a remote token, then a refspec token that STARTS with '+'
# (the '+' followed by a non-space kills 'a + b').
#
# Pure dry run: only decisions are inspected. Nothing is pushed.
# ============================================================================
import json
import os
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
EXAMPLE_RULES = REPO / "security-rules.example.json"

ALLOW = 0
BLOCK = 2

# (id, command, must_block)
CASES = [
    # --- the hole: refspec force must now be BLOCKED ------------------------
    ("refspec +main", "git push origin +main", True),
    ("refspec +HEAD:main", "git push origin +HEAD:main", True),
    ("refspec +refs/heads/main", "git push origin +refs/heads/main", True),
    ("refspec force to a non-main branch", "git push origin +feature", True),
    ("refspec in a cd chain", "cd repo && git push origin +main", True),
    ("refspec after a push flag", "git push --set-upstream origin +main", True),

    # --- regression: the existing force catches must still BLOCK -------------
    ("classic --force", "git push --force origin main", True),
    ("classic -f", "git push -f origin main", True),

    # --- the other half: ordinary pushes must stay FREE ---------------------
    ("plain push", "git push origin main", False),
    ("set-upstream", "git push --set-upstream origin feature", False),
    ("push a branch", "git push origin feature", False),
    ("push a normal refspec", "git push origin HEAD:main", False),

    # --- false-positive guard: '+' as arithmetic, not a refspec -------------
    # 'git push' appears only as documentation text; the '+' is a sum far from
    # any remote token. The tightened pattern must NOT fire here.
    ("arithmetic in a heredoc that mentions git push", "Bash-heredoc", False),
]

_HEREDOC = (
    "python3 - <<'PY'\n"
    "# how to publish: git push origin main\n"
    "total = 1 + 2\n"
    "print(total)\n"
    "PY"
)


def _make_rules() -> str:
    rules = json.loads(EXAMPLE_RULES.read_text(encoding="utf-8"))
    tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    json.dump(rules, tf)
    tf.close()
    return tf.name


def _run(command: str, rules_path: str) -> int:
    if command == "Bash-heredoc":
        command = _HEREDOC
    payload = {"tool_name": "Bash", "tool_input": {"command": command},
               "session_id": "refspec-force-test", "hook_event_name": "PreToolUse"}
    with tempfile.TemporaryDirectory() as ov:
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = rules_path
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = ov
        env["CLAUDE_AUDIT_DIR"] = ov
        env["CLAUDE_HOOK_DEV_FLAG"] = ov + "/_none"
        p = subprocess.run(["python3", str(HOOK)], input=json.dumps(payload),
                           capture_output=True, text=True, env=env)
        return p.returncode


def run_all():
    rules = _make_rules()
    results = []
    try:
        for cid, command, must_block in CASES:
            rc = _run(command, rules)
            ok = rc == (BLOCK if must_block else ALLOW)
            results.append((cid, must_block, rc, ok))
    finally:
        try:
            os.unlink(rules)
        except OSError:
            pass
    return results


try:
    import pytest

    _RULES = _make_rules()

    @pytest.mark.parametrize("cid,command,must_block", CASES)
    def test_force_push_refspec(cid, command, must_block):
        assert _run(command, _RULES) == (BLOCK if must_block else ALLOW), cid

except ImportError:
    pass


if __name__ == "__main__":
    res = run_all()
    fails = [r for r in res if not r[3]]
    for cid, must_block, rc, ok in fails:
        exp = "block" if must_block else "allow"
        got = "block" if rc == BLOCK else ("allow" if rc == ALLOW else f"rc={rc}")
        print(f"FAIL  {cid:44s} exp={exp:5s} got={got}")
    passed = len(res) - len(fails)
    print(f"\nRefspec force-push: {passed}/{len(res)} passed  (hook: {HOOK})")
    raise SystemExit(0 if not fails else 1)
