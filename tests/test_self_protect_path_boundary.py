# ============================================================================
# The interpreter branch of self-protection matched a PREFIX, not a PATH.
#
# command_hits_self_protect has two halves. The write half compares with
# _PATH_BOUNDARY. The interpreter half — which exists because a path inside
# open("...") never starts a shell token — compared with a plain substring:
#
#     if p in ce and not _dev_unlocked(prot):
#
# The docstring of that very function promises the opposite ("Path boundary via
# _PATH_BOUNDARY, so the pending directory is not wrongly matched"). It held in
# one of the two places.
#
# So every NEIGHBOUR of a protected path was dragged in as soon as an inline
# one-liner mentioned it. The expensive one is the directory holding override
# PROPOSALS: it carries the active directory's name as its prefix. Reported
# from outside this project, then measured — projects checking their own
# proposal for valid JSON were refused. The guard blocked the use of the
# escalation path it prescribes itself.
#
# Since shell startup files joined SELF_PROTECT the class grew: a backup of
# .zshrc, a .bashrc.bak, a hooks-alt directory — all prefixes, all blocked.
#
# THIS LOOSENS THE SHARPEST PART OF THE GUARD — self-protection is the one
# place no override can lift. So the refusal half below is the half that
# matters. Every case in it must stay refused; if one flips to free, the fix
# is wrong no matter how good the other half looks.
#
# Note the asymmetry that is deliberate: inside inline code, READING a
# protected path is refused too ("there is no legitimate reason to touch the
# guard's own files through -c/-e; cat/grep are there for reading"). That
# hardness is unchanged here. The only thing this fix changes is WHICH paths
# count as the protected one.
# ============================================================================
import json
import os
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
HOME = os.path.expanduser("~")

# Built from pieces at runtime: a literal protected path in the source makes a
# guard-protected checkout refuse edits to this very file.
CLAUDE = HOME + "/.claude"
ACTIVE = CLAUDE + "/.sudo-" + "overrides"
PENDING = ACTIVE + "-pending"
ARCHIVE = ACTIVE + "-archive"
HOOKS = CLAUDE + "/hooks"
SETTINGS = CLAUDE + "/settings" + ".json"
ZSHRC = HOME + "/.zsh" + "rc"

RULES = {
    "protected_reads": {"always_blocked_reads": [], "require_override_1": [],
                        "always_allowed": [], "env_files_require_override_1": []},
    "blocked_paths_write": [], "blocked_patterns": [], "blocked_git_ops": [],
    "protected_git_branches": [], "blocked_bash_patterns_force_push": [],
    "allowed_sudo": [], "owner_only_commands": [], "require_confirmation": [],
}


def _blocks(command: str) -> tuple[bool, str]:
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
            input=json.dumps({"session_id": "self-protect-boundary-test",
                              "tool_name": "Bash",
                              "tool_input": {"command": command}}),
            capture_output=True, text=True, env=env)
    detail = f"exit {p.returncode}: {' '.join(p.stderr.split())[:130]}"
    # A crash is not a refusal. _guard_stumbled exits fail-closed with the same
    # code as a considered denial, so checking the exit code alone would let an
    # exception pass for a pass (see test_no_crash_on_real_paths.py).
    crashed = any(m in p.stderr for m in
                  ("Traceback", "unexpected error", "unerwarteter Fehler"))
    return (p.returncode == 2 and not crashed), detail


def _stays_free(command: str) -> tuple[bool, str]:
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
            input=json.dumps({"session_id": "self-protect-boundary-test",
                              "tool_name": "Bash",
                              "tool_input": {"command": command}}),
            capture_output=True, text=True, env=env)
    return p.returncode == 0, f"exit {p.returncode}: {' '.join(p.stderr.split())[:130]}"


# --- what must STAY refused. A miss here is a way in, not a nuisance. --------

def check_write_into_the_active_override_dir_is_refused():
    return _blocks(f"python3 -c \"open('{ACTIVE}/x.json','w').write('x')\"")


def check_read_of_the_active_override_dir_is_refused():
    """Reading via -c stays refused on purpose: cat and grep are the way."""
    return _blocks(f"python3 -c \"print(open('{ACTIVE}/x.json').read())\"")


def check_node_reading_the_active_override_dir_is_refused():
    return _blocks(
        f"node -e \"console.log(require('fs').readFileSync('{ACTIVE}/x.json','utf8'))\"")


def check_the_active_directory_itself_is_refused():
    """The boundary must accept the quote that ends the path, not just a slash."""
    return _blocks(f"python3 -c \"print(open('{ACTIVE}').read())\"")


def check_write_into_the_hooks_dir_is_refused():
    return _blocks(f"python3 -c \"open('{HOOKS}/command-guard.py','w').write('x')\"")


def check_node_writing_into_the_hooks_dir_is_refused():
    return _blocks(f"node -e \"require('fs').writeFileSync('{HOOKS}/x.py','x')\"")


def check_write_to_the_settings_file_is_refused():
    return _blocks(f"python3 -c \"open('{SETTINGS}','w').write('x')\"")


def check_write_to_a_shell_startup_file_is_refused():
    return _blocks(f"python3 -c \"open('{ZSHRC}','a').write('x')\"")


def check_double_slash_disguise_is_refused():
    """Traversal is collapsed before the comparison — it must stay that way."""
    disguised = CLAUDE + "//.sudo-" + "overrides/x"
    return _blocks(f"python3 -c \"open('{disguised}','w')\"")


def check_dotdot_disguise_is_refused():
    return _blocks(f"python3 -c \"open('{CLAUDE}/rules/../hooks/x.py','w')\"")


def check_one_liner_after_a_harmless_command_is_refused():
    return _blocks(f"cat /etc/hostname; python3 -c \"open('{ACTIVE}/x','w')\"")


# --- what must run FREE: neighbours. Same prefix, different place. ----------

def check_reading_a_pending_proposal_stays_free():
    """The measured case: a project checking its own override proposal."""
    return _stays_free(f"python3 -c \"print(open('{PENDING}/p.json').read())\"")


def check_json_validating_a_pending_proposal_stays_free():
    return _stays_free(
        f"python3 -c \"import json; json.load(open('{PENDING}/p.json')); print('ok')\"")


def check_writing_a_pending_proposal_stays_free():
    """Writing the proposal IS the prescribed way to request a grant."""
    return _stays_free(f"python3 -c \"open('{PENDING}/p.json','w').write('{{}}')\"")


def check_node_reading_a_pending_proposal_stays_free():
    return _stays_free(
        f"node -e \"console.log(require('fs').readFileSync('{PENDING}/p.json','utf8'))\"")


def check_listing_the_pending_directory_stays_free():
    return _stays_free(f"python3 -c \"import os; print(os.listdir('{PENDING}'))\"")


def check_an_archive_neighbour_stays_free():
    return _stays_free(f"python3 -c \"print(open('{ARCHIVE}/old.json').read())\"")


def check_a_backup_of_a_shell_startup_file_stays_free():
    return _stays_free(f"python3 -c \"print(open('{ZSHRC}.bak').read())\"")


def check_a_local_shell_startup_neighbour_stays_free():
    return _stays_free(f"python3 -c \"open('{ZSHRC}.local','w').write('x')\"")


def check_a_hooks_neighbour_directory_stays_free():
    return _stays_free(f"python3 -c \"print(open('{HOOKS}-old/command-guard.py').read())\"")


def check_a_settings_backup_stays_free():
    return _stays_free(f"python3 -c \"print(open('{SETTINGS}.bak').read())\"")


# --- controls: these paths were always free WITHOUT an interpreter. ---------
# If they change, something other than the interpreter branch moved.

def check_cat_on_the_pending_directory_stays_free():
    return _stays_free(f"cat {PENDING}/p.json")


def check_redirect_into_the_pending_directory_stays_free():
    return _stays_free(f"echo x > {PENDING}/p.json")


def check_redirect_into_the_active_directory_is_refused():
    """The control for the other side: the shell path still guards the active one."""
    return _blocks(f"echo x > {ACTIVE}/p.json")


CASES = [
    ("write into the active override dir is refused", check_write_into_the_active_override_dir_is_refused),
    ("read of the active override dir is refused", check_read_of_the_active_override_dir_is_refused),
    ("node reading the active override dir is refused", check_node_reading_the_active_override_dir_is_refused),
    ("the active directory itself is refused", check_the_active_directory_itself_is_refused),
    ("write into the hooks dir is refused", check_write_into_the_hooks_dir_is_refused),
    ("node writing into the hooks dir is refused", check_node_writing_into_the_hooks_dir_is_refused),
    ("write to the settings file is refused", check_write_to_the_settings_file_is_refused),
    ("write to a shell startup file is refused", check_write_to_a_shell_startup_file_is_refused),
    ("double slash disguise is refused", check_double_slash_disguise_is_refused),
    ("dotdot disguise is refused", check_dotdot_disguise_is_refused),
    ("one liner after a harmless command is refused", check_one_liner_after_a_harmless_command_is_refused),
    ("reading a pending proposal stays free", check_reading_a_pending_proposal_stays_free),
    ("json validating a pending proposal stays free", check_json_validating_a_pending_proposal_stays_free),
    ("writing a pending proposal stays free", check_writing_a_pending_proposal_stays_free),
    ("node reading a pending proposal stays free", check_node_reading_a_pending_proposal_stays_free),
    ("listing the pending directory stays free", check_listing_the_pending_directory_stays_free),
    ("an archive neighbour stays free", check_an_archive_neighbour_stays_free),
    ("a backup of a shell startup file stays free", check_a_backup_of_a_shell_startup_file_stays_free),
    ("a local shell startup neighbour stays free", check_a_local_shell_startup_neighbour_stays_free),
    ("a hooks neighbour directory stays free", check_a_hooks_neighbour_directory_stays_free),
    ("a settings backup stays free", check_a_settings_backup_stays_free),
    ("cat on the pending directory stays free", check_cat_on_the_pending_directory_stays_free),
    ("redirect into the pending directory stays free", check_redirect_into_the_pending_directory_stays_free),
    ("redirect into the active directory is refused", check_redirect_into_the_active_directory_is_refused),
]

try:
    import pytest

    @pytest.mark.parametrize("name,fn", CASES)
    def test_self_protect_path_boundary(name, fn):
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
