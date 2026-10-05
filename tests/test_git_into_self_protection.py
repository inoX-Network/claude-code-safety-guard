# ============================================================================
# git wrote into the guard's own directories without naming a write.
#
# Self-protection checks the paths a command writes to. git writes through its
# own options, and none of them looks like a write target:
#
#   git --work-tree <hooks dir> checkout FETCH_HEAD -- .   replaces the guard
#   git -C <hooks dir> init                                 makes it a repository
#   git clone <url> <hooks dir>/new                         drops code beside it
#   git -C <checkout under the hooks dir> checkout <ref>    swaps the guard for
#                                                            any other version
#
# Measured 2026-10-05 against both language versions: 10 of 10 passed. The
# last form matters most for an installation that runs the guard from a
# release checkout under the hooks directory -- one `git checkout` and the
# guard is whatever version the agent picked, including one it pushed itself.
#
# Now: a git call whose working tree, git directory or path arguments lie in a
# self-protected path is refused unless the subcommand only reads. Where it
# acts comes from -C, --work-tree/--git-dir, GIT_DIR/GIT_WORK_TREE, a `cd`
# earlier on the line and the working directory the tool chain reports.
#
# A repository that merely CONTAINS a protected directory stays free: that is
# an ordinary working copy, where every session commits and switches branches.
# A path argument that points INTO the protected part is refused there too.
#
# Pure DRY-RUN: only the decision is inspected, nothing is executed.
# ============================================================================
import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
HOOK = REPO / "hooks" / "command-guard.py"
EXAMPLE_RULES = REPO / "security-rules.example.json"
HOME = str(Path.home())

# Assembled, so a guard-protected machine does not read this file's own text
# as a write into the hooks directory.
HOOKS = "~/.claude/" + "hooks"
RELEASE = HOOKS + "/safety-guard-release"
RULES_DIR = "~/.claude/" + "rules"


def _verdict(command: str, cwd: str | None = None) -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as ov:
        cfg = os.path.join(ov, "guard-config.json")
        Path(cfg).write_text(json.dumps({"installation": {}}), encoding="utf-8")
        payload = {
            "session_id": "git-self-protection-test",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "cwd": cwd or ov,
        }
        env = dict(os.environ)
        env["CLAUDE_GUARD_CONFIG"] = cfg
        env["CLAUDE_SECURITY_RULES"] = str(EXAMPLE_RULES)
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = ov
        env["CLAUDE_AUDIT_DIR"] = ov
        env["CLAUDE_HOOK_DEV_FLAG"] = ov + "/_none"
        p = subprocess.run(["python3", str(HOOK)], input=json.dumps(payload),
                           capture_output=True, text=True, env=env, timeout=60, cwd=ov)
        return p.returncode, (p.stderr or "")


def _blocked_by_self_protection(command: str, cwd: str | None = None) -> bool:
    code, err = _verdict(command, cwd)
    # Word stem of the self-protection message, English and German.
    return code == 2 and ("self-protection" in err.lower() or "selbstschutz" in err.lower())


WRITES = [
    f"git -C {HOOKS} init",
    f"cd {HOOKS} && git init",
    f"cd {HOOKS}; git init .",
    f"git init {HOOKS}/new",
    f"git --git-dir=/tmp/x.git --work-tree={HOOKS} checkout -f main",
    f"git --work-tree {HOOKS} checkout FETCH_HEAD -- .",
    f"GIT_WORK_TREE={HOOKS} git checkout -f main",
    f"env GIT_DIR={RELEASE}/.git git fetch origin",
    f"git -C {RELEASE} fetch origin && git -C {RELEASE} checkout -f origin/evil",
    f"cd {RELEASE} && git checkout 2026.10.01",
    f"git -C {RELEASE} switch -d origin/main",
    f"git -C {RELEASE} pull",
    f"git -C {RELEASE} reset --keep HEAD~1",
    f"git -C {RELEASE} apply /tmp/p.diff",
    f"git -C {RELEASE} stash pop",
    f"git -C {RELEASE} am /tmp/mail",
    f"git clone https://example.invalid/x.git {HOOKS}/new",
    f"git clone --depth 1 https://example.invalid/x.git {RELEASE}",
    f"git -C /tmp worktree add {HOOKS}/wt",
    f"git -C /tmp checkout main -- {HOOKS}/command-guard.py",
    f"git -C {RULES_DIR} checkout .",
    f"timeout 30 git -C {RELEASE} checkout -f main",
    f"bash -c 'git -C {RELEASE} checkout -f main'",
    f"git -C {RELEASE} -c core.x=1 checkout main",
]

READS = [
    f"git -C {RELEASE} log --oneline -1",
    f"git -C {RELEASE} status",
    f"git -C {RELEASE} describe --tags",
    f"git -C {RELEASE} diff",
    f"git -C {RELEASE} show HEAD:VERSION",
    f"git -C {RELEASE} rev-parse HEAD",
    f"cd {RELEASE} && git ls-files",
    f"git -C {RELEASE} --no-pager log -3",
    # -c takes a value: without knowing that, `color.ui=never` would read as
    # the subcommand and refuse a plain log.
    f"git -C {RELEASE} -c color.ui=never log -1",
]

ELSEWHERE = [
    "git -C /tmp/repo checkout main",
    "cd /tmp/repo && git pull",
    "git clone https://example.invalid/x.git /tmp/new",
    "git init /tmp/fresh",
    "git commit -m 'explain the hooks directory'",
    f"git commit -m 'touches {HOOKS}/command-guard.py'",
    f"git log -- {HOOKS}",
    f"grep -rn 'git -C {RELEASE} checkout' notes.md",
    f"echo 'git --work-tree {HOOKS} checkout' > /tmp/note.txt",
    # Unquoted behind a print tool: the words are text, not a git call.
    f"echo git init {HOOKS}/new",
]


@pytest.mark.parametrize("command", WRITES)
def test_git_writing_into_self_protection_is_refused(command):
    assert _blocked_by_self_protection(command)


@pytest.mark.parametrize("command", READS)
def test_reading_git_in_self_protection_stays_free(command):
    assert not _blocked_by_self_protection(command)


@pytest.mark.parametrize("command", ELSEWHERE)
def test_git_elsewhere_stays_free(command):
    assert not _blocked_by_self_protection(command)


def test_reported_working_directory_counts():
    # The session itself sits in the protected checkout: a bare `git checkout`
    # acts there.
    assert _blocked_by_self_protection("git checkout -f main",
                                       cwd=os.path.expanduser(RELEASE))


def test_reported_working_directory_read_stays_free():
    assert not _blocked_by_self_protection("git status",
                                           cwd=os.path.expanduser(RELEASE))


def test_working_copy_that_contains_a_protected_dir_stays_free(tmp_path):
    # A repository whose ROOT is not protected is an ordinary working copy.
    assert not _blocked_by_self_protection("git switch main", cwd=str(tmp_path))
