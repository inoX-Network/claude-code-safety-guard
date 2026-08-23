# ============================================================================
# The refusal must name the real reason — reading a control file in a one-liner.
#
# The interpreter branch blocks the mere MENTION of a project control file, and
# that is deliberate: `python -c "open(path,'w').write(x)"` carries no shell verb
# and no redirection, so the ordinary write detection cannot see it. Measured on
# 2026-08-23 over 608 distinct refusals, 44 were exactly that shape, and this
# branch was the only thing catching them.
#
# What was wrong is the WORDING. Both refusals said "writing it is blocked",
# including at a plain read. Ten real cases across seven sessions, every one a
# read: listing which hooks are configured, checking a matcher, comparing two
# files. Each time the message sent the reader looking for write permission,
# when the fix was to use `cat`.
#
# So the rule stays and the sentence changes. The test below has to prove the
# second half without accidentally proving the first, which is harder than it
# looks — see the two traps.
#
# TRAP 1 — the message contains the path. Comparing the refusal for path A
# against the refusal for path B "shows a difference" even with no fix at all.
# Every pair here therefore uses THE SAME path and varies only the access.
#
# TRAP 2 — binding a test to wording breaks on language. The catalogue is
# English by default and CLAUDE_GUARD_CONFIG points at a file that does not
# exist, so no installation setting can switch it underneath us.
# ============================================================================
import json
import os
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))

RULES = {
    "protected_reads": {"always_blocked_reads": [], "require_override_1": [],
                        "always_allowed": [], "env_files_require_override_1": []},
    "blocked_paths_write": [], "blocked_patterns": [], "blocked_git_ops": [],
    "protected_git_branches": [], "blocked_bash_patterns_force_push": [],
    "allowed_sudo": [], "owner_only_commands": [], "require_confirmation": [],
}

# A hard one (no override lifts it) and a gated one (override level 1+), so both
# refusal texts get exercised.
HARD = "/tmp/proj/.claude/settings.json"
GATED = "/tmp/proj/opencode.json"


def _run(command: str) -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        (tmp / "rules.json").write_text(json.dumps(RULES), encoding="utf-8")
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = str(tmp / "rules.json")
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = str(tmp / "ov")
        env["CLAUDE_AUDIT_DIR"] = str(tmp / "audit")
        env["CLAUDE_HOOK_DEV_FLAG"] = str(tmp / "_no_window")
        env["CLAUDE_GUARD_CONFIG"] = str(tmp / "_no_config.json")
        p = subprocess.run(
            ["python3", str(HOOK)],
            input=json.dumps({"session_id": "inline-control-read-message",
                              "tool_name": "Bash",
                              "tool_input": {"command": command}}),
            capture_output=True, text=True, env=env)
    return p.returncode, " ".join(p.stderr.split())


def _refusal(command: str) -> tuple[bool, str]:
    """The refusal text, and whether it was one at all."""
    code, err = _run(command)
    return code == 2, err


# --- the pairs: same path, two accesses, two sentences -----------------------

def check_hard_read_names_the_one_liner():
    """Reading a hard control file inside -c: the reason must be the one-liner,
    not "writing"."""
    blocked, err = _refusal(f"python3 -c \"print(open('{HARD}').read())\"")
    return blocked and "one-liner" in err and "cat/grep/head" in err, err


def check_hard_write_keeps_the_old_sentence():
    """SAME path, ordinary shell write: the plain wording must survive. If this
    one also said "one-liner", the branch detection would be firing everywhere
    and the pair above would prove nothing."""
    blocked, err = _refusal(f"cp /tmp/x {HARD}")
    return blocked and "one-liner" not in err and "at every location" in err, err


def check_gated_read_names_the_one_liner():
    blocked, err = _refusal(
        f"python3 -c \"import json; json.load(open('{GATED}'))\"")
    return blocked and "one-liner" in err and "cat/grep/head" in err, err


def check_gated_write_keeps_the_old_sentence():
    blocked, err = _refusal(f"cp /tmp/x {GATED}")
    return blocked and "one-liner" not in err and "level 1+" in err, err


# --- the refusal must not misdescribe what an override can do ---------------

def check_hard_inline_still_says_no_override():
    """A hard block stays hard. A friendlier sentence that quietly implied an
    override would help is worse than the old wrong one."""
    _, err = _refusal(f"python3 -c \"print(open('{HARD}').read())\"")
    return "No override lifts this" in err, err


def check_gated_inline_still_offers_level_one():
    """Gated stays gated: writing it is a matter of level 1+, and the sentence
    has to keep saying so."""
    _, err = _refusal(
        f"python3 -c \"import json; json.load(open('{GATED}'))\"")
    return "level 1+" in err, err


# --- the way out the message names has to actually exist --------------------

def check_the_suggested_way_out_works():
    """The message sends the reader to cat/grep/head. A message naming an exit
    that is also blocked would cost more time than the wrong one did."""
    for command in (f"cat {GATED}", f"grep -n context {GATED}",
                    f"head -5 {HARD}"):
        code, err = _run(command)
        if code != 0:
            return False, f"{command} -> exit {code}: {err}"
    return True, "cat, grep and head all pass"


# --- and the rule itself is untouched ---------------------------------------

def check_inline_write_is_still_blocked():
    """The 44 measured cases: writing inside the code, invisible to the shell.
    This is why the branch blocks on mention, and it must keep doing so."""
    blocked, err = _refusal(f"python3 -c \"open('{HARD}','w').write('x')\"")
    return blocked, err


def check_node_one_liner_is_still_blocked():
    blocked, err = _refusal(f"node -e \"require('fs').readFileSync('{GATED}')\"")
    return blocked, err


def check_harmless_path_in_a_one_liner_stays_free():
    """The counter-direction: a one-liner that names no control file runs."""
    code, err = _run("python3 -c \"print(open('/tmp/harmless.txt').read())\"")
    return code == 0, f"exit {code}: {err}"


def check_control_file_only_as_text_stays_free():
    """Text is not a deed: the path in an echo is not an access. Kept here
    because the new wording must not tempt anyone into widening the branch."""
    code, err = _run(f"echo 'the file {GATED} steers opencode'")
    return code == 0, f"exit {code}: {err}"


CASES = [
    ("hard read in a one-liner names the one-liner",
     check_hard_read_names_the_one_liner),
    ("hard write on the SAME path keeps the old sentence",
     check_hard_write_keeps_the_old_sentence),
    ("gated read in a one-liner names the one-liner",
     check_gated_read_names_the_one_liner),
    ("gated write on the SAME path keeps the old sentence",
     check_gated_write_keeps_the_old_sentence),
    ("hard inline refusal still says no override lifts it",
     check_hard_inline_still_says_no_override),
    ("gated inline refusal still offers level 1+",
     check_gated_inline_still_offers_level_one),
    ("the way out the message names actually works",
     check_the_suggested_way_out_works),
    ("writing inside the code is still blocked",
     check_inline_write_is_still_blocked),
    ("node one-liner is still blocked", check_node_one_liner_is_still_blocked),
    ("harmless path in a one-liner stays free",
     check_harmless_path_in_a_one_liner_stays_free),
    ("control file only as text stays free",
     check_control_file_only_as_text_stays_free),
]

try:
    import pytest

    @pytest.mark.parametrize("name,fn", CASES)
    def test_inline_control_read_message(name, fn):
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
