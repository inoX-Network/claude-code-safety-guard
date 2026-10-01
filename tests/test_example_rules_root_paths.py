#!/usr/bin/env python3
"""Ways to root and around the commit hooks that only the example rules left open.

The code catches every case below — with the rules the maintainer runs. The
example rules shipped to new installations did not, and neither did the
built-in fallback for some of them. Measured 2026-10-01 against release
2026.10.01-6 with security-rules.example.json, all on level 0:

  * `git -c core.hooksPath=/dev/null commit` — the same as --no-verify, which
    is blocked; three spellings (-c, --config-env, GIT_CONFIG_KEY_n).
  * `sudo find / -exec bash …` — find is on the sudo allowlist for searching,
    and -exec hands a root shell to anything. Searching stays free; the actions
    that run or write (-exec, -execdir, -ok, -okdir, -delete, -fprint*, -fls)
    need an approval.
  * `sudo tee /etc/cron.d/x`, `sudo cp x /etc/sudoers.d/x` — the example
    protected four files under /etc, not /etc. (Announced in 2026.10.01-3.)
  * `sudo mv x /usr/local/bin/ls` — /usr/local/bin was not protected; a binary
    there shadows the system one for every later command.

The built-in fallback (no rules file) additionally lacked /usr/local/bin and
/usr/local/sbin, `chgrp -R` on system paths, ~/.npmrc and
~/.docker/config.json — all present in the example rules or the maintainer's.
"""
import json
import os
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
EXAMPLE = REPO / "security-rules.example.json"


def _run(tool: str, tool_input: dict, rules: Path | None) -> tuple[int, str]:
    """rules=None: no rules file at all, so the built-in fallback applies."""
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = str(rules or Path(tmp) / "missing.json")
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = tmp + "/ov"
        env["CLAUDE_AUDIT_DIR"] = tmp + "/audit"
        env["CLAUDE_HOOK_DEV_FLAG"] = tmp + "/_none"
        env["CLAUDE_GUARD_CONFIG"] = tmp + "/_no_config.json"
        p = subprocess.run(
            ["python3", str(HOOK)],
            input=json.dumps({"session_id": "example-rules-root-paths", "tool_name": tool,
                              "tool_input": tool_input}),
            capture_output=True, text=True, env=env, cwd=tmp)
    return p.returncode, " ".join(p.stderr.split())[:160]


def _bash(command):
    return ("Bash", {"command": command})


# (name, tool call, rules) — must be refused
BLOCKED = [
    ("hooks path via -c", _bash("git -c core.hooksPath=/dev/null commit -m x"), EXAMPLE),
    ("hooks path via --config-env", _bash("git --config-env=core.hooksPath=EMPTY commit -m x"), EXAMPLE),
    ("hooks path via the environment",
     _bash("GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null git commit -m x"),
     EXAMPLE),
    ("root shell through sudo find -exec", _bash("sudo find / -maxdepth 0 -exec bash -c id \\;"), EXAMPLE),
    ("root shell through sudo find -execdir", _bash("sudo find /tmp -maxdepth 0 -execdir sh \\;"), EXAMPLE),
    ("sudo find deletes as root", _bash("sudo find /var/lib/x -delete"), EXAMPLE),
    ("sudo find writes a file as root", _bash("sudo find /tmp -maxdepth 0 -fprint /root/x"), EXAMPLE),
    ("sudo tee into /etc/cron.d", _bash("echo x | sudo tee /etc/cron.d/x"), EXAMPLE),
    ("sudo cp into /etc/sudoers.d", _bash("sudo cp /tmp/x /etc/sudoers.d/x"), EXAMPLE),
    ("sudo mv into /usr/local/bin", _bash("sudo mv /tmp/x /usr/local/bin/ls"), EXAMPLE),
    ("fallback: hooks path", _bash("git -c core.hooksPath=/dev/null commit -m x"), None),
    ("fallback: write /usr/local/bin", ("Write", {"file_path": "/usr/local/bin/ls", "content": "x"}), None),
    ("fallback: write /usr/local/sbin", ("Write", {"file_path": "/usr/local/sbin/x", "content": "x"}), None),
    ("fallback: chgrp -R on a system path", _bash("chgrp -R users /usr"), None),
    ("fallback: read ~/.npmrc", ("Read", {"file_path": "~/.npmrc"}), None),
    ("fallback: read the docker credentials", ("Read", {"file_path": "~/.docker/config.json"}), None),
]

FREE = [
    ("reading the hooks path", _bash("git config --get core.hooksPath"), EXAMPLE),
    ("another -c setting", _bash("git -c color.ui=never log -1"), EXAMPLE),
    ("sudo grep a log", _bash("sudo grep -c error /var/log/syslog"), EXAMPLE),
    ("sudo find searching", _bash("sudo find /var/log -name '*.log' -mtime -1"), EXAMPLE),
    ("listing /etc", _bash("sudo ls /etc"), EXAMPLE),
    ("reading below /etc", _bash("cat /etc/hosts"), EXAMPLE),
    ("a directory that only contains etc", _bash("echo x > /tmp/etc/x"), EXAMPLE),
    ("reading /usr/local/bin", _bash("ls /usr/local/bin"), EXAMPLE),
]


def _blocked(call, rules):
    rc, detail = _run(call[0], call[1], rules)
    return rc == 2, f"exit {rc}: {detail}"


def _free(call, rules):
    rc, detail = _run(call[0], call[1], rules)
    return rc == 0, f"exit {rc}: {detail}"


try:
    import pytest

    @pytest.mark.parametrize("name,call,rules", BLOCKED, ids=[b[0] for b in BLOCKED])
    def test_example_rules_root_paths_block(name, call, rules):
        ok, detail = _blocked(call, rules)
        assert ok, f"{name}: {detail}"

    @pytest.mark.parametrize("name,call,rules", FREE, ids=[f[0] for f in FREE])
    def test_example_rules_root_paths_stay_free(name, call, rules):
        ok, detail = _free(call, rules)
        assert ok, f"{name}: {detail}"

except ImportError:
    pass


if __name__ == "__main__":
    failures = 0
    for name, call, rules in BLOCKED:
        ok, detail = _blocked(call, rules)
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  blocks: {name}")
        if not ok:
            print(f"      {detail}")
    for name, call, rules in FREE:
        ok, detail = _free(call, rules)
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  free:   {name}")
        if not ok:
            print(f"      {detail}")
    raise SystemExit(0 if not failures else 1)
