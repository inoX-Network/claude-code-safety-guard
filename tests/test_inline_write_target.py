# ============================================================================
# An interpreter one-liner does not write past blocked_paths_write.
#
# Measured 2026-09-02 on a real machine, against a copy of the live version
# with the real rules file:
#
#   BLOCKED   echo x > /bin/x
#   passes    python3 -c "open('/bin/x','w').write('x')"
#   passes    python3 -c "open('~/.ssh/authorized_keys','w').write('x')"
#   BLOCKED   python3 -c "os.remove('<delete-protected>')"
#
# Every path in blocked_paths_write was reachable through a one-liner, the key
# directory included -- which is the very class this guard was built against.
# The cause was an asymmetry, not an oversight in the list: _command_deletes has
# carried its inline counterpart (_DELETE_INLINE_RE) from the start,
# _command_is_write never had one.
#
# THE HALF THAT IS EASIER TO FORGET is the second block below. A protected path
# inside a one-liner is not automatically a write target -- it can be the read
# SOURCE, or plain TEXT in the content being written. The first version of this
# fix did not separate those and turned both into rejections. Measured against a
# real audit log, the blanket form costs 47 genuine false positives across 32
# sessions while closing a single hole. It is the same failure class the guard
# exists to avoid: text is not an action.
#
# A THIRD PROMISE comes out of a measurement error made while building this:
# blocked_paths_write and blocked_paths_delete are TWO lists with two different
# prohibitions. An open(...,"w") under a delete-only path is allowed. Checking
# both lists against one shared verb list reported 12 "holes", eleven of which
# were none.
#
# Pure dry run: only decisions are inspected. Nothing is written or deleted.
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

ALLOW = 0
BLOCK = 2

WRITE_PROTECTED = "/etc"
KEYS = f"{HOME}/.ssh"
DELETE_ONLY = "/tmp/delete-protected-only"
FREE = "/tmp/harmless"

# (id, command, must block)
CASES = [
    # --- the barrier: the one-liner really writes there ---------------------
    ("open in write mode",
     f"python3 -c \"open('{WRITE_PROTECTED}/x','w').write('x')\"", True),
    ("open in append mode",
     f"python3 -c \"open('{WRITE_PROTECTED}/x','a').write('x')\"", True),
    ("pathlib write_text",
     f"python3 -c \"import pathlib; pathlib.Path('{WRITE_PROTECTED}/x')"
     f".write_text('x')\"", True),
    ("node writeFileSync",
     f"node -e \"require('fs').writeFileSync('{WRITE_PROTECTED}/x','x')\"", True),
    ("inner double quotes",
     f"python3 -c 'open(\"{WRITE_PROTECTED}/x\",\"w\").write(\"x\")'", True),
    # The heaviest case: writing to the key directory is exactly what this
    # guard exists for.
    ("the key directory",
     f"python3 -c \"open('{KEYS}/authorized_keys','w').write('x')\"", True),
    ("moving ONTO a protected path",
     f"python3 -c \"import os; os.rename('{FREE}/a','{WRITE_PROTECTED}/b')\"", True),
    # Moving takes something away at the SOURCE -- for the source it is a
    # deletion, so both arguments of rename/move count.
    ("moving OUT OF a protected path",
     f"python3 -c \"import os; os.rename('{WRITE_PROTECTED}/a','{FREE}/b')\"", True),
    # FAIL-CLOSED: with the target in a variable it cannot be read off, so the
    # whole block is checked, as before the fix. Without this promise the target
    # extraction would itself be the way around: put the path in a variable.
    ("target held in a variable",
     f"python3 -c \"p='{WRITE_PROTECTED}/x'; open(p,'w').write('x')\"", True),
    # The shell substitutes the value BEFORE the interpreter starts -- a way
    # that really works, not a theoretical obfuscation.
    ("shell assignment is substituted",
     f"P={WRITE_PROTECTED}; python3 -c \"open('$P/x','w').write('x')\"", True),
    # Counter-probe on the mechanism: the ordinary route was never open and
    # stays shut. If this were green, the list would be testing the wrong thing.
    ("shell redirect still blocked", f"echo x > {WRITE_PROTECTED}/x", True),

    # --- the other half: naming is not writing ------------------------------
    ("reading only",
     f"python3 -c \"print(open('{WRITE_PROTECTED}/hostname').read())\"", False),
    ("protected path is the read SOURCE",
     f"python3 -c \"open('{FREE}/x','w')"
     f".write(open('{WRITE_PROTECTED}/hostname').read())\"", False),
    ("protected path is plain TEXT in the content",
     f"python3 -c \"open('{FREE}/x','w')"
     f".write('see {WRITE_PROTECTED}/hostname')\"", False),
    ("checking existence",
     f"python3 -c \"import os; print(os.path.exists('{WRITE_PROTECTED}/hostname'))\"",
     False),
    ("writing somewhere free", f"python3 -c \"open('{FREE}/x','w').write('x')\"",
     False),
    ("an ordinary command", "ls -la /tmp", False),

    # --- the two lists mean different things --------------------------------
    # Writing under a delete-only path is ALLOWED; such data is maintained, not
    # destroyed. If this were blocked, the fix would have turned delete
    # protection into write protection.
    ("writing under delete-only protection",
     f"python3 -c \"open('{DELETE_ONLY}/x','w').write('x')\"", False),
    # Counterpart -- without it the case above proves nothing: it would also be
    # green if delete protection had failed altogether.
    ("deleting under delete-only protection stays blocked",
     f"python3 -c \"import os; os.remove('{DELETE_ONLY}/x')\"", True),
]


def _make_rules() -> str:
    rules = json.loads(EXAMPLE_RULES.read_text(encoding="utf-8"))
    rules["blocked_paths_write"] = [WRITE_PROTECTED, "~/.ssh"]
    rules["blocked_paths_delete"] = [DELETE_ONLY]
    tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                     encoding="utf-8")
    json.dump(rules, tf)
    tf.close()
    return tf.name


def _run(command: str, rules_path: str) -> int:
    payload = {"tool_name": "Bash", "tool_input": {"command": command},
               "session_id": "inline-write-target-test",
               "hook_event_name": "PreToolUse"}
    with tempfile.TemporaryDirectory() as ov:
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = rules_path
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = ov
        env["CLAUDE_AUDIT_DIR"] = ov
        # Isolating the dev window matters: without it the suite measures
        # something different while the window happens to be open.
        env["CLAUDE_HOOK_DEV_FLAG"] = ov + "/_none"
        p = subprocess.run(["python3", str(HOOK)], input=json.dumps(payload),
                           capture_output=True, text=True, env=env)
        return p.returncode


def test_inline_write_targets():
    rules_path = _make_rules()
    try:
        failures = []
        for name, command, must_block in CASES:
            code = _run(command, rules_path)
            expected = BLOCK if must_block else ALLOW
            if code != expected:
                failures.append(
                    f"{name}: expected {'BLOCK' if must_block else 'ALLOW'}, "
                    f"got exit {code}")
        assert not failures, "\n".join(failures)
    finally:
        os.unlink(rules_path)
