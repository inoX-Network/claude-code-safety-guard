# ============================================================================
# Redirected shell startup files.
#
# ZDOTDIR (zsh), ENV (sh), BASH_ENV (bash) and XDG_CONFIG_HOME (fish) move the
# place the startup files are read from. The fixed list in the guard then
# misses: the shell loads a file nobody protects.
#
# Four directions:
#   1. with a variable set, writing to its target blocks
#   2. the fixed list STILL applies -- a harmless value does not free ~/.zshrc
#   3. reading the redirected target stays free
#   4. without the variable, with a relative value, or with a directory as ENV,
#      the same file stays free (otherwise this only proves a blanket block)
#
# Plus one source check: the guard must read os.environ, not _env(). At the
# production location _env() always returns None, so reading through it would
# make the protection dead exactly where it matters -- while every copy, and
# therefore every behaviour test, stays green.
#
# Pure dry run: only decisions are inspected. Nothing is written or created.
# ============================================================================
import ast
import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
EXAMPLE_RULES = REPO / "security-rules.example.json"
HOME = str(Path.home())

ALLOW = 0
BLOCK = 2
REDIRECTS = ("ZDOTDIR", "ENV", "BASH_ENV", "XDG_CONFIG_HOME")

BASE = tempfile.mkdtemp(prefix="guard-redirect-")
ZD = f"{BASE}/zd"
XDG = f"{BASE}/xdg"
BENV = f"{BASE}/bash-start.sh"
SHENV = f"{BASE}/sh-start"


def _run(payload: dict, extra_env: dict) -> int:
    with tempfile.TemporaryDirectory() as ov:
        env = {k: v for k, v in os.environ.items() if k not in REDIRECTS}
        env.update(extra_env)
        env["CLAUDE_SECURITY_RULES"] = str(EXAMPLE_RULES)
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = ov
        env["CLAUDE_AUDIT_DIR"] = ov
        env["CLAUDE_HOOK_DEV_FLAG"] = ov + "/_none"
        payload = {"session_id": "shell-redirect-test",
                   "hook_event_name": "PreToolUse", "cwd": "/tmp", **payload}
        return subprocess.run(["python3", str(HOOK)], input=json.dumps(payload),
                              capture_output=True, text=True, env=env).returncode


def _write(path: str) -> dict:
    return {"tool_name": "Write", "tool_input": {"file_path": path, "content": "x"}}


def _bash(cmd: str) -> dict:
    return {"tool_name": "Bash", "tool_input": {"command": cmd}}


CASES = [
    # 1. set -> target blocks, on the Write route and the Bash route
    *[(f"zdotdir|{f}|Write", _write(f"{ZD}/{f}"), {"ZDOTDIR": ZD}, BLOCK)
      for f in (".zshenv", ".zshrc", ".zlogin")],
    *[(f"zdotdir|{f}|bash", _bash(f"echo x >> {ZD}/{f}"), {"ZDOTDIR": ZD}, BLOCK)
      for f in (".zshenv", ".zshrc", ".zlogin")],
    ("bash_env|Write", _write(BENV), {"BASH_ENV": BENV}, BLOCK),
    ("bash_env|tee", _bash(f"echo x | tee -a {BENV}"), {"BASH_ENV": BENV}, BLOCK),
    ("env|Write", _write(SHENV), {"ENV": SHENV}, BLOCK),
    ("env|cp", _bash(f"cp /tmp/source {SHENV}"), {"ENV": SHENV}, BLOCK),
    ("xdg|config.fish", _write(f"{XDG}/fish/config.fish"), {"XDG_CONFIG_HOME": XDG}, BLOCK),
    ("xdg|conf.d", _bash(f"echo x > {XDG}/fish/conf.d/a.fish"), {"XDG_CONFIG_HOME": XDG}, BLOCK),
    # a tilde in the value: the shell expands it, so must the guard
    ("zdotdir|tilde", _write(f"{HOME}/.config/zsh-probe/.zshrc"),
     {"ZDOTDIR": "~/.config/zsh-probe"}, BLOCK),
    ("zdotdir|python-inline", _bash(f"python3 -c \"open('{ZD}/.zshrc','a').write('x')\""),
     {"ZDOTDIR": ZD}, BLOCK),

    # 2. the fixed list still applies, wherever the variable points
    ("fixed-stays|ZDOTDIR", _write(f"{HOME}/.zshrc"), {"ZDOTDIR": ZD}, BLOCK),
    ("fixed-stays|BASH_ENV", _write(f"{HOME}/.zshrc"), {"BASH_ENV": BENV}, BLOCK),
    ("fixed-stays|XDG|.zshrc", _write(f"{HOME}/.zshrc"), {"XDG_CONFIG_HOME": XDG}, BLOCK),
    ("fixed-stays|XDG|fish", _write(f"{HOME}/.config/fish/config.fish"),
     {"XDG_CONFIG_HOME": XDG}, BLOCK),

    # 3. reading stays free
    ("read|zdotdir|cat", _bash(f"cat {ZD}/.zshrc"), {"ZDOTDIR": ZD}, ALLOW),
    ("read|zdotdir|Read", {"tool_name": "Read", "tool_input": {"file_path": f"{ZD}/.zshrc"}},
     {"ZDOTDIR": ZD}, ALLOW),
    ("read|bash_env|grep", _bash(f"grep -n alias {BENV}"), {"BASH_ENV": BENV}, ALLOW),

    # 4. counter-probes
    ("no-variable|zd/.zshrc", _write(f"{ZD}/.zshrc"), {}, ALLOW),
    ("no-variable|bash-start", _bash(f"echo x > {BENV}"), {}, ALLOW),
    ("neighbour|zdotdir|other-file", _write(f"{ZD}/notes.txt"), {"ZDOTDIR": ZD}, ALLOW),
    ("neighbour|xdg|other-program", _write(f"{XDG}/git/config"),
     {"XDG_CONFIG_HOME": XDG}, ALLOW),
    ("relative|ENV=production|bash", _bash("echo x > /tmp/production"),
     {"ENV": "production"}, ALLOW),
    ("relative|ENV=production|Write", _write("/tmp/production"), {"ENV": "production"}, ALLOW),
    # a directory is not a startup file -- otherwise ENV=<dir> would lock the tree
    ("directory|ENV=base", _write(f"{BASE}/anything.txt"), {"ENV": BASE}, ALLOW),
]


@pytest.mark.parametrize("cid,payload,extra_env,expected", CASES, ids=[c[0] for c in CASES])
def test_shell_startup_redirect(cid, payload, extra_env, expected):
    assert _run(payload, extra_env) == expected, cid


def test_reads_os_environ_not_env_helper():
    tree = ast.parse(HOOK.read_text(encoding="utf-8"))
    func = next(n for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef) and n.name == "_redirected_startup_files")
    # calls in the tree, not text: the docstring names _env() itself
    nodes = list(ast.walk(func))
    calls_env = any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                    and n.func.id == "_env" for n in nodes)
    reads_environ = any(isinstance(n, ast.Attribute) and n.attr == "environ"
                        and isinstance(n.value, ast.Name) and n.value.id == "os"
                        for n in nodes)
    assert reads_environ and not calls_env
