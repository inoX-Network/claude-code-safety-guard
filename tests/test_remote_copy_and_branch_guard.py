# ============================================================================
# Two gaps that a purely local check never sees.
#
# 1. A copy TO the far side writes there, but names no redirect and no write
#    verb: `scp release.tar server:/etc/cron.d/` looks read-only to a check that
#    hunts for `>` or `rm`. That is the normal deploy path, not an edge case.
#    Position decides, not occurrence: `host:/path` LAST is a destination and is
#    checked; the same shape in front means fetching and stays free — otherwise
#    every read-only fetch would be blocked.
#
# 2. A commit straight onto a protected branch. "Never work on main directly" is
#    a prompt rule, and a prompt rule is a tendency, not a barrier: a small local
#    model tried exactly that with the rule sitting in its own instructions. Only
#    `git commit` is checked — merge and pull also create commits but belong to
#    the merge path a human drives. Reading (status, log, diff) stays untouched.
#
# The branch cases run in a REAL temporary repository. A test that mocks git
# would only prove that the mock was called.
# ============================================================================
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))

RULES = {
    "blocked_paths_write": ["/etc/passwd", "/etc/cron.d", "/boot"],
    "protected_git_branches": ["main", "master"],
    "blocked_patterns": [],
    "blocked_git_ops": [],
    "blocked_bash_patterns_force_push": [],
    "allowed_sudo": [],
    "owner_only_commands": [],
    "protected_reads": {},
    "require_confirmation": [],
}


def _run(command: str, tmp: Path, cwd: str | None = None) -> tuple[int, str]:
    """One Bash command through the hook. Returns (exit code, stderr)."""
    rules = tmp / "rules.json"
    rules.write_text(json.dumps(RULES), encoding="utf-8")
    env = dict(os.environ)
    env["CLAUDE_SECURITY_RULES"] = str(rules)
    env["CLAUDE_SUDO_OVERRIDES_DIR"] = str(tmp / "ov")
    env["CLAUDE_AUDIT_DIR"] = str(tmp / "audit")
    env["CLAUDE_HOOK_DEV_FLAG"] = str(tmp / "_no_window")
    env["CLAUDE_GUARD_CONFIG"] = str(tmp / "_no_config.json")

    payload = {"session_id": "remote-branch-test", "tool_name": "Bash",
               "tool_input": {"command": command}}
    if cwd:
        payload["cwd"] = cwd
    p = subprocess.run(["python3", str(HOOK)], input=json.dumps(payload),
                       capture_output=True, text=True, env=env)
    return p.returncode, " ".join(p.stderr.split())


def _blocks(command: str, cwd: str | None = None) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as d:
        code, err = _run(command, Path(d), cwd)
    return code == 2, f"exit {code}: {err[:170]}"


def _git(*args: str, cwd: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True,
                   capture_output=True, text=True)


def _repo_on(branch: str) -> tempfile.TemporaryDirectory:
    """A real repository with one commit, checked out on `branch`."""
    d = tempfile.TemporaryDirectory()
    p = Path(d.name)
    _git("init", "-q", "-b", "main", cwd=str(p))
    _git("config", "user.email", "test@example.invalid", cwd=str(p))
    _git("config", "user.name", "Test", cwd=str(p))
    (p / "file.txt").write_text("x", encoding="utf-8")
    _git("add", "file.txt", cwd=str(p))
    _git("commit", "-q", "-m", "initial", cwd=str(p))
    if branch != "main":
        _git("switch", "-q", "-c", branch, cwd=str(p))
    return d


# --- 1. remote copy ---------------------------------------------------------

def check_scp_to_protected_remote_path():
    """A copy onto a protected path on the far side is a write."""
    return _blocks("scp release.tar server:/etc/cron.d/deploy")


def check_rsync_to_protected_remote_path():
    return _blocks("rsync -a build/ user@host:/boot/efi/")


def check_scp_from_remote_stays_free():
    """Fetching FROM the far side reads — it must stay allowed."""
    blocked, detail = _blocks("scp server:/etc/cron.d/deploy ./local-copy")
    return not blocked, detail


def check_rsync_to_harmless_remote_path_stays_free():
    # Deliberately a neutral destination: the local installation protects /srv
    # out of its own configuration, so a case built on it would measure that
    # configuration instead of this hardening.
    blocked, detail = _blocks("rsync -a build/ user@host:/tmp/deploy/")
    return not blocked, detail


# --- 2. commit onto a protected branch --------------------------------------

def check_commit_on_main_is_blocked():
    with _repo_on("main") as repo:
        return _blocks("git commit -m 'change'", cwd=repo)


def check_commit_on_feature_branch_is_free():
    with _repo_on("feature/x") as repo:
        blocked, detail = _blocks("git commit -m 'change'", cwd=repo)
    return not blocked, detail


def check_commit_reached_via_cd_is_blocked():
    """`cd repo && git commit` moves the target — the check must follow."""
    with _repo_on("main") as repo:
        other = tempfile.TemporaryDirectory()
        try:
            blocked, detail = _blocks(f"cd {repo} && git commit -m 'change'",
                                      cwd=other.name)
        finally:
            other.cleanup()
    return blocked, detail


def check_commit_via_git_c_is_blocked():
    """`git -C repo commit` names its own target and outranks everything else."""
    with _repo_on("main") as repo:
        other = tempfile.TemporaryDirectory()
        try:
            blocked, detail = _blocks(f"git -C {repo} commit -m 'change'",
                                      cwd=other.name)
        finally:
            other.cleanup()
    return blocked, detail


def check_reading_git_stays_free():
    """Reading commands must not be touched, not even with 'commit' in the text."""
    with _repo_on("main") as repo:
        blocked, detail = _blocks("git log --grep=commit --oneline", cwd=repo)
    return not blocked, detail


def check_outside_a_repository_no_false_alarm():
    """No repository, no branch — and therefore no refusal."""
    with tempfile.TemporaryDirectory() as plain:
        blocked, detail = _blocks("git commit -m 'change'", cwd=plain)
    return not blocked, detail


def check_shipped_rules_carry_the_branch_list():
    """A hardening shipped without its rule key is silently inactive."""
    example = json.loads((REPO / "security-rules.example.json")
                         .read_text(encoding="utf-8"))
    branches = example.get("protected_git_branches")
    return bool(branches) and "main" in branches, f"got {branches!r}"


# Five cases build a REAL repository, on purpose (see the header). Where git is
# not installed they cannot be measured — and an unmeasurable case must say so
# rather than fail: without this the file died with FileNotFoundError deep in
# subprocess, which reads as "the guard is broken" when it means "no git here".
NEEDS_GIT = {
    "commit on main is blocked",
    "commit on a feature branch is free",
    "commit reached via cd is blocked",
    "commit via git -C is blocked",
    "reading git stays free",
}
HAVE_GIT = shutil.which("git") is not None

CASES = [
    ("scp onto a protected remote path is a write", check_scp_to_protected_remote_path),
    ("rsync onto a protected remote path is a write", check_rsync_to_protected_remote_path),
    ("fetching from the far side stays free", check_scp_from_remote_stays_free),
    ("rsync onto a harmless remote path stays free",
     check_rsync_to_harmless_remote_path_stays_free),
    ("commit on main is blocked", check_commit_on_main_is_blocked),
    ("commit on a feature branch is free", check_commit_on_feature_branch_is_free),
    ("commit reached via cd is blocked", check_commit_reached_via_cd_is_blocked),
    ("commit via git -C is blocked", check_commit_via_git_c_is_blocked),
    ("reading git stays free", check_reading_git_stays_free),
    ("outside a repository: no false alarm", check_outside_a_repository_no_false_alarm),
    ("shipped rules carry the branch list", check_shipped_rules_carry_the_branch_list),
]

try:
    import pytest

    @pytest.mark.parametrize("name,fn", CASES)
    def test_remote_copy_and_branch_guard(name, fn):
        if name in NEEDS_GIT and not HAVE_GIT:
            pytest.skip("needs git installed")
        ok, detail = fn()
        assert ok, f"{name}: {detail}"

except ImportError:
    pass


if __name__ == "__main__":
    failures = skipped = 0
    for name, fn in CASES:
        if name in NEEDS_GIT and not HAVE_GIT:
            skipped += 1
            print(f"SKIP  {name}  (needs git)")
            continue
        ok, detail = fn()
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            print(f"      {detail}")
    if skipped:
        print(f"\n{skipped} case(s) not measured — install git to run them.")
    raise SystemExit(0 if not failures else 1)
