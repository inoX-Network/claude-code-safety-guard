#!/usr/bin/env python3
"""An environment file named inside interpreter inline code.

`python3 -c "open(...)"` hides the file name inside a string, so the token scan
never sees it as a word of its own. The inline check looked for the suffix over
the WHOLE command line with a pattern of its own, separate from
check_env_file_read. Two consequences, both measured 2026-10-01:

  1. `name.env` (the docker compose env_file form, `config/prod.env`) was not
     recognised there: `python3 -c "print(open('config/prod.env').read())"`
     ran free, while `cat config/prod.env` is refused.
  2. Templates were refused: `python3 -c "print(open('.env.example').read())"`,
     even a template that is only an ARGUMENT after the inline code — the
     template exemption of check_env_file_read never applied.

The inline check now takes every quoted string (", ' or `) of the inline code
that contains the suffix and asks check_env_file_read — one rule for the token
scan and the inline code.
"""
import json
import os
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
RULES = REPO / "security-rules.example.json"
E = "." + "env"   # keeps the suffix out of this file's own text


def _run(command: str) -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = str(RULES)
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = tmp
        env["CLAUDE_AUDIT_DIR"] = tmp
        env["CLAUDE_HOOK_DEV_FLAG"] = tmp + "/_none"
        env["CLAUDE_GUARD_CONFIG"] = tmp + "/_no_config.json"
        p = subprocess.run(
            ["python3", str(HOOK)],
            input=json.dumps({"session_id": "env-inline-test", "tool_name": "Bash",
                              "tool_input": {"command": command}}),
            capture_output=True, text=True, env=env, cwd=tmp)
    return p.returncode, " ".join(p.stderr.split())[:160]


BLOCKED = [
    ("name.env in python", f"""python3 -c "print(open('config/prod{E}').read())" """),
    ("name.env in double quotes", f"""python3 -c 'print(open("mail{E}").read())'"""),
    ("bare file in python", f"""python3 -c "open('{E}').read()" """),
    ("bare file in node", f"""node -e "require('fs').readFileSync('{E}')" """),
    ("environment variant", f"""python3 -c "open('/app/{E}.production')" """),
    ("bare environment variant", f"""python3 -c "open('{E}.local')" """),
    ("rc file in an f-string", f"""python3 -c "open(f'{{d}}/{E}rc')" """),
    ("joined path", f"""python3 -c "import os; open(os.path.join('x', '{E}'))" """),
    ("perl redirect form", f"""perl -e 'open(F, "<{E}")'"""),
]

FREE = [
    ("template in python", f"""python3 -c "print(open('{E}.example').read())" """),
    ("sample in python", f"""python3 -c "print(open('{E}.sample').read())" """),
    ("template as an argument after the code",
     f"""python3 -c "import sys; print(sys.argv)" {E}.example"""),
    ("os.environ", """python3 -c "import os; print(os.environ)" """),
    ("process.env", """node -e "console.log(process.env.HOME)" """),
    ("prose with the suffix", f"""python3 -c "print('{E}-files are protected')" """),
]


def _blocked(command):
    rc, detail = _run(command.strip())
    return rc == 2, f"exit {rc}: {detail}"


def _free(command):
    rc, detail = _run(command.strip())
    return rc == 0, f"exit {rc}: {detail}"


try:
    import pytest

    @pytest.mark.parametrize("name,command", BLOCKED, ids=[b[0] for b in BLOCKED])
    def test_env_file_in_inline_code_blocks(name, command):
        ok, detail = _blocked(command)
        assert ok, f"{name}: {detail}"

    @pytest.mark.parametrize("name,command", FREE, ids=[f[0] for f in FREE])
    def test_env_file_in_inline_code_stays_free(name, command):
        ok, detail = _free(command)
        assert ok, f"{name}: {detail}"

except ImportError:
    pass


if __name__ == "__main__":
    failures = 0
    for name, command in BLOCKED:
        ok, detail = _blocked(command)
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
    raise SystemExit(0 if not failures else 1)
