#!/usr/bin/env python3
"""The chain approval channel: one exact command form, switched on per installation.

Owner-only commands (the approval script, dev mode) are hard-blocked for the
assistant: whoever can run the approval script can grant themselves anything.
The maintainer's installation has one deliberate exception — a second channel
for approving from a distance: the owner sends a one-time value from a chain
the assistant cannot predict, and the assistant runs the approval script with
exactly that value. Anything that deviates from the one allowed form — a
prefix, a chained command, another script path, other flags — falls back to
the hard block.

Here it is a CONFIGURATION switch (`chain_approval` in guard-config.json), off
unless set. Script name and flag names come from the configuration, because
the approval script's interface belongs to the installation. The directory is
`installation.approval_scripts` (default ~/.claude/bin) — and a configured
directory is self-protected, otherwise placing a script with the right name
there would turn the exception into a door.

Also pinned: `.beispiel` and `.vorlage` count as template suffixes for
environment files, next to `.example` and `.sample`.
"""
import json
import os
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
HOME = str(Path.home())
NAME = "chain" + "-approve"            # composed: keeps the call out of this file's own text
CODE = "1a2b-3c4d-5e6f-7a8b-9c0d"
FORM = f"~/.claude/bin/{NAME} --code {CODE} probe-1 --expect-level 1 --expect-scope /tmp/x"
E = "." + "env"

RULES = {
    "protected_reads": {"always_blocked_reads": [], "require_override_1": [], "always_allowed": [],
                        "env_files_require_override_1": [E]},
    "blocked_paths_write": [], "blocked_paths_delete": [], "blocked_patterns": [],
    "blocked_git_ops": [], "protected_git_branches": [], "blocked_bash_patterns_force_push": [],
    "allowed_sudo": [], "owner_only_commands": [NAME], "require_confirmation": [],
}
ON = {"chain_approval": {"enabled": True, "script": NAME,
                         "flags": {"level": "--expect-level", "scope": "--expect-scope",
                                   "minutes": "--minutes"}}}


def _run(tool: str, tool_input: dict, config: dict | None, dev: bool = False) -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "rules.json").write_text(json.dumps(RULES), encoding="utf-8")
        cfg = Path(tmp) / "guard-config.json"
        if config is not None:
            cfg.write_text(json.dumps(config), encoding="utf-8")
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = tmp + "/rules.json"
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = tmp + "/ov"
        env["CLAUDE_AUDIT_DIR"] = tmp + "/audit"
        flag = Path(tmp) / "dev-flag"
        if dev:
            until = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
            flag.write_text(json.dumps({"expires_at": until, "reason": "test"}), encoding="utf-8")
        env["CLAUDE_HOOK_DEV_FLAG"] = str(flag)
        env["CLAUDE_GUARD_CONFIG"] = str(cfg)
        p = subprocess.run(["python3", str(HOOK)],
                           input=json.dumps({"session_id": "chain-switch", "tool_name": tool,
                                             "tool_input": tool_input}),
                           capture_output=True, text=True, env=env, cwd=tmp)
    return p.returncode, " ".join(p.stderr.split())[:160]


def _bash(command):
    return "Bash", {"command": command}


FREE = [
    ("the exact form, switched on", _bash(FORM), ON),
    ("with the minutes flag", _bash(FORM + " --minutes 30"), ON),
    ("home spelled out", _bash(FORM.replace("~", HOME, 1)), ON),
    ("a configured directory", _bash(FORM.replace("~/.claude/bin", "/opt/approval")),
     {**ON, "installation": {"approval_scripts": "/opt/approval"}}),
    ("template suffix .beispiel", ("Read", {"file_path": f"/tmp/v0/{E}.beispiel"}), None),
    ("template suffix .vorlage", ("Read", {"file_path": f"/tmp/v0/{E}.vorlage"}), None),
]

BLOCKED = [
    ("switched off by default", _bash(FORM), None),
    ("switched off explicitly", _bash(FORM), {"chain_approval": {**ON["chain_approval"], "enabled": False}}),
    ("a chained command after it", _bash(FORM + "; id"), ON),
    ("an environment prefix", _bash("X=1 " + FORM), ON),
    ("another script directory", _bash(FORM.replace("~/.claude/bin", "/tmp")), ON),
    ("the default directory when another is configured", _bash(FORM),
     {**ON, "installation": {"approval_scripts": "/opt/approval"}}),
    ("other flag names", _bash(FORM.replace("--expect-level", "--level")), ON),
    ("level out of range", _bash(FORM.replace("--expect-level 1", "--expect-level 4")), ON),
    ("a short code", _bash(FORM.replace(CODE, "1a2b-3c4d")), ON),
    # Each with the command the invalid configuration would otherwise let through.
    ("an invalid script name disables it",
     _bash(FORM.replace(f"bin/{NAME}", f"bin/../{NAME}")),
     {"chain_approval": {**ON["chain_approval"], "script": "../" + NAME}}),
    ("a flag that is no flag disables it",
     _bash(FORM.replace("--expect-level 1", "--expect-level; id 1")),
     {"chain_approval": {**ON["chain_approval"],
                         "flags": {"level": "--expect-level; id", "scope": "--expect-scope",
                                   "minutes": "--minutes"}}}),
    ("a configured directory is self-protected",
     ("Write", {"file_path": "/opt/approval/" + NAME, "content": "x"}),
     {"installation": {"approval_scripts": "/opt/approval"}}),
    ("... and stays shut in dev mode",
     ("Write", {"file_path": "/opt/approval/" + NAME, "content": "x"}),
     {"installation": {"approval_scripts": "/opt/approval"}}, True),
]


def _free(call, config):
    rc, detail = _run(call[0], call[1], config)
    return rc == 0, f"exit {rc}: {detail}"


def _blocked(call, config, dev=False):
    rc, detail = _run(call[0], call[1], config, dev)
    return rc == 2, f"exit {rc}: {detail}"


try:
    import pytest

    @pytest.mark.parametrize("name,call,config", FREE, ids=[f[0] for f in FREE])
    def test_chain_approval_free(name, call, config):
        ok, detail = _free(call, config)
        assert ok, f"{name}: {detail}"

    @pytest.mark.parametrize("case", BLOCKED, ids=[b[0] for b in BLOCKED])
    def test_chain_approval_blocked(case):
        name, call, config, *dev = case
        ok, detail = _blocked(call, config, *dev)
        assert ok, f"{name}: {detail}"

except ImportError:
    pass


if __name__ == "__main__":
    failures = 0
    for name, call, config in FREE:
        ok, detail = _free(call, config)
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  free:   {name}")
        if not ok:
            print(f"      {detail}")
    for name, call, config, *dev in BLOCKED:
        ok, detail = _blocked(call, config, *dev)
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  blocks: {name}")
        if not ok:
            print(f"      {detail}")
    raise SystemExit(0 if not failures else 1)
