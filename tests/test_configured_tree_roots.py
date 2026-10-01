#!/usr/bin/env python3
"""Trees that must not be deleted as a whole — configured in the rules file.

The fixed rule protects '/' and the home directory (see check_root_delete). But
the trees that matter most on a given machine are below the home directory:
`rm -rf ~/Projects` is depth 1 under '~', and depth 1 under the home directory
is everyday work, so the fixed rule lets it through. blocked_paths_delete is no
answer either: it blocks deleting ANY file in the tree, which is everyday work
too.

`blocked_recursive_delete` names tree roots with the same two-step depth rule as
'/': the root itself blocks with every delete verb (`rm`, `rmdir`, `mv` away),
one level below it only a RECURSIVE delete does (`rm -rf`, `find -delete`,
`find | xargs rm`). From two levels down the rule is off. Single files, writing
and editing stay free everywhere. An override of level 1+ with a matching
allowed_paths entry lifts it.

The section is optional: without it there are no configured roots, and the
fixed rule for '/' and '~' still holds. The maintainer's copy has had this rule
since 2026-08-25; this file pins it down here.
"""
import json
import os
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))

BASE = {
    "protected_reads": {"always_blocked_reads": [], "require_override_1": [],
                        "always_allowed": [], "env_files_require_override_1": []},
    "blocked_paths_write": [], "blocked_paths_delete": [], "blocked_patterns": [],
    "blocked_git_ops": [], "protected_git_branches": [],
    "blocked_bash_patterns_force_push": [], "allowed_sudo": [],
    "owner_only_commands": [], "require_confirmation": [],
}
WITH_ROOTS = dict(BASE, blocked_recursive_delete=["~/Projects", "/mnt/Games"])


def _run(command: str, rules: dict, stream: str = "stderr") -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        (tmp / "rules.json").write_text(json.dumps(rules), encoding="utf-8")
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = str(tmp / "rules.json")
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = str(tmp / "ov")
        env["CLAUDE_AUDIT_DIR"] = str(tmp / "audit")
        env["CLAUDE_HOOK_DEV_FLAG"] = str(tmp / "_no_window")
        env["CLAUDE_GUARD_CONFIG"] = str(tmp / "_no_config.json")
        p = subprocess.run(
            ["python3", str(HOOK)],
            input=json.dumps({"session_id": "configured-tree-roots-test",
                              "tool_name": "Bash",
                              "tool_input": {"command": command}}),
            capture_output=True, text=True, env=env, cwd=tmp)
    return p.returncode, " ".join(getattr(p, stream).split())[:400]


# (name, command, root the refusal must name)
BLOCKED = [
    ("the root itself, recursive", "rm -rf ~/Projects", "~/Projects"),
    ("the root itself, plain rmdir", "rmdir ~/Projects", "~/Projects"),
    ("the root moved away", "mv ~/Projects /tmp/gone", "~/Projects"),
    ("one level below, recursive", "rm -rf ~/Projects/website", "~/Projects"),
    ("one level below, long flag", "rm --recursive --force ~/Projects/website", "~/Projects"),
    ("one level below, second segment", "cd /tmp && rm -fr ~/Projects/website", "~/Projects"),
    ("glob on the root", "rm -rf ~/Proj*", "~/Projects"),
    ("glob one level below", "rm -rf ~/Projects/*", "~/Projects"),
    ("find -delete one level below", "find ~/Projects/website -delete", "~/Projects"),
    ("find piped into xargs rm", "find ~/Projects -maxdepth 1 | xargs rm -rf", "~/Projects"),
    ("an absolute root", "rm -rf /mnt/Games/library", "/mnt/Games"),
]

FREE = [
    ("a single file one level below", "rm ~/Projects/notes.txt"),
    ("two levels below, recursive", "rm -rf ~/Projects/website/build"),
    ("listing the root", "find ~/Projects -maxdepth 1 | head"),
    ("writing below the root", "echo x > ~/Projects/website/a.txt"),
    ("a sibling with a longer name", "rm -rf ~/Projects-old/x"),
]


def _blocked(command, shown):
    rc, detail = _run(command, WITH_ROOTS)
    return rc == 2 and f"'{shown}'" in detail, f"exit {rc}: {detail}"


def _free(command):
    rc, detail = _run(command, WITH_ROOTS)
    return rc == 0, f"exit {rc}: {detail}"


def check_section_is_optional():
    """Without the section: no configured roots, and no crash or refusal."""
    rc, detail = _run("rm -rf ~/Projects/website", BASE)
    return rc == 0, f"exit {rc}: {detail}"


def check_section_missing_is_reported():
    """An older rules file is told the section exists -- not filled in."""
    rc, out = _run("ls /tmp", BASE, stream="stdout")
    return rc == 0 and "blocked_recursive_delete" in out, f"exit {rc}: {out}"


def check_refusal_names_the_rule():
    """The message says which rule fired -- not the one for the first level below '/'."""
    rc, detail = _run("rm -rf ~/Projects/website", WITH_ROOTS)
    return rc == 2 and "blocked_recursive_delete" in detail, f"exit {rc}: {detail}"


def check_fixed_roots_still_hold_without_section():
    rc, detail = _run("rm -rf ~", BASE)
    return rc == 2, f"exit {rc}: {detail}"


SINGLE = [
    ("section is optional", check_section_is_optional),
    ("a missing section is reported", check_section_missing_is_reported),
    ("the refusal names the rule", check_refusal_names_the_rule),
    ("fixed roots hold without the section", check_fixed_roots_still_hold_without_section),
]

try:
    import pytest

    @pytest.mark.parametrize("name,command,shown", BLOCKED, ids=[b[0] for b in BLOCKED])
    def test_configured_tree_root_blocks(name, command, shown):
        ok, detail = _blocked(command, shown)
        assert ok, f"{name}: {detail}"

    @pytest.mark.parametrize("name,command", FREE, ids=[f[0] for f in FREE])
    def test_configured_tree_root_stays_free(name, command):
        ok, detail = _free(command)
        assert ok, f"{name}: {detail}"

    @pytest.mark.parametrize("name,fn", SINGLE, ids=[s[0] for s in SINGLE])
    def test_configured_tree_root_section(name, fn):
        ok, detail = fn()
        assert ok, f"{name}: {detail}"

except ImportError:
    pass


if __name__ == "__main__":
    failures = 0
    for name, command, shown in BLOCKED:
        ok, detail = _blocked(command, shown)
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  blocks: {name}")
        if not ok:
            print(f"      {detail}")
    for name, command in FREE:
        ok, detail = _free(command)
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  free:   {name}")
        if not ok:
            print(f"      {detail}")
    for name, fn in SINGLE:
        ok, detail = fn()
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            print(f"      {detail}")
    raise SystemExit(0 if not failures else 1)
