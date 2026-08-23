# ============================================================================
# The interpreter branch did not resolve shell variables. The write branch did.
#
# _inline_code_segments returned raw segments. Three branches consume them —
# project control files, self-protection, read protection — and none of them
# resolved an assignment made earlier in the same line. The write branch calls
# _with_assignments and does resolve it. Two halves of one promise, kept in
# only one of them; the same shape as the two fixes of 2026-08-22.
#
# Measured 2026-08-23 against a copy of the live guard, three pairs, all three
# showed it:
#
#     python3 -c "open('<protected>/x','w')"           refused
#     P=<protected>; python3 -c "open('$P/x','w')"     RAN FREE
#
# THIS IS A WORKING BYPASS, not the obfuscation boundary named in THREAT-MODEL.
# The shell substitutes "$P" before the interpreter ever starts, and a plain
# assignment arises in everyday scripting without any intent to evade — unlike
# '/.cla' + 'ude/', which only ever happens on purpose.
#
# A NOTE ON HOW TO WRITE SUCH A PROBE, learned the hard way here: the first
# draft used python3 -c "open(P+'/x','w')". That is Python syntax and would be
# a NameError at runtime — the guard lets it through just the same, but the
# case proves nothing about real usage. Only the "$P" form is a bypass someone
# could actually use.
#
# THIS TIGHTENS THE GUARD, so the halves swap roles compared to a loosening
# fix: the FREE half below is the one that matters. Everything in it ran before
# and must keep running; a case flipping to refused is a new false positive in
# the sharpest part of the guard.
#
# Measured cost over 7803 distinct commands from the real audit log: 0 newly
# free, 7 newly refused — all seven were work on the guard itself (copying its
# source, checking drift, reading the rules file, querying override status),
# and all seven have the documented way out: write the path out, or use
# cat/grep instead of an interpreter.
# ============================================================================
import json
import os
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
HOME = os.path.expanduser("~")

# Assembled at runtime: a literal protected path in the source would make a
# guard-protected checkout refuse edits to this very file.
CLAUDE = HOME + "/.claude"
HOOKS = CLAUDE + "/hooks"
ACTIVE = CLAUDE + "/.sudo-" + "overrides"
PENDING = ACTIVE + "-pending"

RULES = {
    "protected_reads": {"always_blocked_reads": [], "require_override_1": [],
                        "always_allowed": [], "env_files_require_override_1": []},
    "blocked_paths_write": [], "blocked_patterns": [], "blocked_git_ops": [],
    "protected_git_branches": [], "blocked_bash_patterns_force_push": [],
    "allowed_sudo": [], "owner_only_commands": [], "require_confirmation": [],
}


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
            input=json.dumps({"session_id": "variables-in-inline-code-test",
                              "tool_name": "Bash",
                              "tool_input": {"command": command}}),
            capture_output=True, text=True, env=env)
    return p.returncode, f"exit {p.returncode}: {' '.join(p.stderr.split())[:130]}"


def _blocks(command: str) -> tuple[bool, str]:
    rc, detail = _run(command)
    # A crash is not a refusal: the fail-closed catch exits with the same code
    # as a considered denial, so the exit code alone would let an exception
    # pass for a pass.
    crashed = "Traceback" in detail or "unexpected error" in detail
    return (rc == 2 and not crashed), detail


def _stays_free(command: str) -> tuple[bool, str]:
    rc, detail = _run(command)
    return rc == 0, detail


# --- what must now be REFUSED. This is the hole being closed. ---------------

def check_variable_write_into_the_hooks_dir_is_refused():
    return _blocks(f'P={HOOKS}; python3 -c "open(\'$P/x.txt\',\'w\')"')


def check_variable_read_of_the_guard_source_is_refused():
    return _blocks(f'P={HOOKS}; python3 -c "print(open(\'$P/command-guard.py\').read())"')


def check_variable_on_the_active_override_dir_is_refused():
    return _blocks(f'A={ACTIVE}; python3 -c "print(open(\'$A/x.json\').read())"')


def check_braced_variable_is_refused():
    return _blocks(f'P={HOOKS}; python3 -c "open(\'${{P}}/x.txt\',\'w\')"')


def check_assignment_separated_by_and_is_refused():
    return _blocks(f'P={HOOKS} && python3 -c "open(\'$P/x.txt\',\'w\')"')


def check_node_with_a_variable_is_refused():
    return _blocks(f'P={HOOKS}; node -e "require(\'fs\').writeFileSync(\'$P/x.txt\',\'\')"')


def check_written_out_path_is_still_refused():
    """Control case: catches a mutation that REPLACES the old path instead of
    adding to it. Without it, a fix that only ever looks at resolved variables
    would still pass this file."""
    return _blocks(f'python3 -c "open(\'{HOOKS}/x.txt\',\'w\')"')


# --- what must STAY FREE. For a tightening fix, this is the half that matters.

def check_variable_on_the_pending_dir_stays_free():
    """The neighbour freed on 2026-08-22. Resolving variables must not drag it
    back in — the path boundary has to hold on the resolved value too."""
    return _stays_free(f'V={PENDING}; python3 -c "print(open(\'$V/x.json\').read())"')


def check_variable_on_a_harmless_path_stays_free():
    return _stays_free('V=/tmp/scratch; python3 -c "open(\'$V/x.txt\',\'w\')"')


def check_cat_with_a_variable_stays_free():
    """The documented way out for reading must survive the tightening."""
    return _stays_free(f'P={HOOKS}; cat "$P/command-guard.py"')


def check_grep_with_a_variable_stays_free():
    return _stays_free(f'P={HOOKS}; grep -c def "$P/command-guard.py"')


def check_unassigned_variable_stays_free():
    """Nothing may be guessed for a variable that was never assigned."""
    return _stays_free('python3 -c "open(\'$NEVER_ASSIGNED/x.txt\',\'w\')"')


def check_assignment_not_used_by_the_one_liner_stays_free():
    """_with_assignments substitutes only where the variable is USED. Dropping
    that selectivity would refuse every line that merely assigns a protected
    path somewhere — measured as the case a mutation must break."""
    return _stays_free(f'P={HOOKS}; python3 -c "print(1+1)"')


def check_plain_command_with_a_variable_stays_free():
    return _stays_free(f'P={HOOKS}; ls "$P"')


CASES = [
    ("variable write into the hooks dir is refused", check_variable_write_into_the_hooks_dir_is_refused),
    ("variable read of the guard source is refused", check_variable_read_of_the_guard_source_is_refused),
    ("variable on the active override dir is refused", check_variable_on_the_active_override_dir_is_refused),
    ("braced variable is refused", check_braced_variable_is_refused),
    ("assignment separated by && is refused", check_assignment_separated_by_and_is_refused),
    ("node with a variable is refused", check_node_with_a_variable_is_refused),
    ("written out path is still refused", check_written_out_path_is_still_refused),
    ("variable on the pending dir stays free", check_variable_on_the_pending_dir_stays_free),
    ("variable on a harmless path stays free", check_variable_on_a_harmless_path_stays_free),
    ("cat with a variable stays free", check_cat_with_a_variable_stays_free),
    ("grep with a variable stays free", check_grep_with_a_variable_stays_free),
    ("unassigned variable stays free", check_unassigned_variable_stays_free),
    ("assignment not used by the one-liner stays free", check_assignment_not_used_by_the_one_liner_stays_free),
    ("plain command with a variable stays free", check_plain_command_with_a_variable_stays_free),
]

try:
    import pytest

    @pytest.mark.parametrize("name,fn", CASES)
    def test_variables_in_inline_code(name, fn):
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
