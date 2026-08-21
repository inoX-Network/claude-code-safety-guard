# ============================================================================
# The guard did not protect its own second adapter.
#
# ~/.config/opencode/plugin/safety-guard.ts is what establishes the protection
# under opencode -- and Claude Code could overwrite it freely. One line, and
# opencode runs unguarded, while ~/.claude/hooks is protected. The exact
# equivalent one tool chain further along was open.
#
# The same structural weakness as in the read-protection and project-local
# control-file work: a protection anchored to fixed points rather than to a
# rule leaves every new point open. Here the new point was our own tool.
#
# The paths come from the opencode binary, not from the documentation. Both
# spellings are attested -- opencode accepts singular and plural
# (plugin/plugins, agent/agents, command/commands).
#
# Deliberately NOT covered: .opencode/bin. What lives there and who writes it
# could not be established, and a protection on suspicion is exactly the
# too-broad pattern this rule set warns about.
#
# The cut follows the same rule as for .claude:
#   hard   = code that runs on a tool call, plus the file registering it
#   gated  = instructions for future runs (level 1)
#   free   = presentation, and AGENTS.md -- the counterpart to CLAUDE.md, with
#            the same deliberate decision behind it
#
# opencode.json is matched by NAME because it carries no dot-directory. That is
# admissible for the same reason as .mcp.json: the name belongs to the tool
# chain, unlike an everyday name such as settings.json.
#
# Pure dry run: only decisions are inspected. Nothing is written or created.
# ============================================================================
import json
import os
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
EXAMPLE_RULES = REPO / "security-rules.example.json"
HOME = str(Path.home())

ALLOW = 0
BLOCK = 2

HARD = "hard"
GATED = "gated"
FREE = "free"

# Targets relative to a project root.
PROJECT_TARGETS = [
    (".opencode/plugin/safety-guard.ts", HARD),
    (".opencode/plugins/own.ts", HARD),
    (".opencode/tools/thing.ts", HARD),
    ("opencode.json", GATED),
    ("opencode.jsonc", GATED),
    (".opencode/opencode.json", GATED),
    (".opencode/agent/reviewer.md", GATED),
    (".opencode/agents/reviewer.md", GATED),
    (".opencode/command/deploy.md", GATED),
    (".opencode/commands/deploy.md", GATED),
    (".opencode/skills/thing/SKILL.md", GATED),
    # Counter-probes: without these the list only proves a total lockdown.
    (".opencode/themes/dark.json", FREE),   # presentation, not control
    ("AGENTS.md", FREE),                    # counterpart to CLAUDE.md
    ("docs/opencode-guide.md", FREE),       # name just off the pattern
    ("src/plugin/own.ts", FREE),            # plugin/, but not under .opencode
    ("src/app.ts", FREE),
]

LOCATIONS = [
    ("own-project", "/home/probe/Projekte/own"),
    ("foreign-project", "/home/probe/elsewhere/foreign"),
    ("throwaway", "/tmp/throwaway-probe"),
]

# Global targets. This is where the adapter itself lives.
GLOBAL_TARGETS = [
    (f"{HOME}/.config/opencode/plugin/safety-guard.ts", HARD),   # our own adapter
    (f"{HOME}/.config/opencode/plugins/own.ts", HARD),
    (f"{HOME}/.config/opencode/tools/thing.ts", HARD),
    (f"{HOME}/.config/opencode/opencode.json", GATED),
    (f"{HOME}/.config/opencode/agents/coder.md", GATED),
    (f"{HOME}/.config/opencode/agent/coder.md", GATED),
    (f"{HOME}/.config/opencode/command/deploy.md", GATED),
    (f"{HOME}/.config/opencode/skills/thing/SKILL.md", GATED),
    # Counter-probes: presentation, instruction file, runtime data.
    (f"{HOME}/.config/opencode/tui.json", FREE),
    (f"{HOME}/.config/opencode/AGENTS.md", FREE),
    (f"{HOME}/.local/share/opencode/log/run.log", FREE),
]


def _make_rules() -> str:
    """Example rules, untouched. The new protection must not depend on the rules
    file -- a control file that only the configuration protects can be
    unprotected by editing that configuration."""
    rules = json.loads(EXAMPLE_RULES.read_text(encoding="utf-8"))
    tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    json.dump(rules, tf)
    tf.close()
    return tf.name


def _run(payload: dict, rules_path: str, override_level: int | None = None) -> int:
    with tempfile.TemporaryDirectory() as ov:
        if override_level is not None:
            expires = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
            (Path(ov) / "probe.json").write_text(json.dumps({
                "override_level": override_level,
                "task": "second tool chain control file test",
                "confirmed": True,
                "expires_at": expires,
                "grants": {"additional_sudo": [], "allowed_paths": []},
            }), encoding="utf-8")
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = rules_path
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = ov
        env["CLAUDE_AUDIT_DIR"] = ov
        env["CLAUDE_HOOK_DEV_FLAG"] = ov + "/_none"
        payload = {"session_id": "second-toolchain-test",
                   "hook_event_name": "PreToolUse", **payload}
        p = subprocess.run(["python3", str(HOOK)], input=json.dumps(payload),
                           capture_output=True, text=True, env=env)
        return p.returncode


def _tool_payloads(path: str):
    yield "Write", {"tool_name": "Write",
                    "tool_input": {"file_path": path, "content": "x"}}
    yield "Edit", {"tool_name": "Edit",
                   "tool_input": {"file_path": path,
                                  "old_string": "a", "new_string": "b"}}
    yield "MultiEdit", {"tool_name": "MultiEdit",
                        "tool_input": {"file_path": path,
                                       "edits": [{"old_string": "a", "new_string": "b"}]}}


def _bash_payloads(path: str):
    """Every write path a shell offers. Each one alone is enough to plant a file."""
    d = os.path.dirname(path)
    yield "redirect", f"echo x > {path}"
    yield "append", f"echo x >> {path}"
    yield "tee", f"echo x | tee {path}"
    yield "cp", f"cp /tmp/source {path}"
    yield "mv", f"mv /tmp/source {path}"
    yield "sed-i", f"sed -i s/a/b/ {path}"
    yield "touch", f"touch {path}"
    yield "symlink", f"ln -sf /tmp/source {path}"
    yield "python-inline", f"python3 -c \"open('{path}','w').write('x')\""
    yield "heredoc", f"cat > {path} <<EOF\nx\nEOF"
    yield "mkdir-then-write", f"mkdir -p {d} && echo x > {path}"


def _expected(strength: str, override_level: int | None) -> int:
    if strength == FREE:
        return ALLOW
    if strength == HARD:
        return BLOCK
    return ALLOW if (override_level or 0) >= 1 else BLOCK


def _cases():
    """(id, payload, override_level, expected)"""
    out = []
    for loc_id, root in LOCATIONS:
        for rel, strength in PROJECT_TARGETS:
            path = f"{root}/{rel}"
            for tool_id, payload in _tool_payloads(path):
                out.append((f"{loc_id}|{rel}|{tool_id}", payload, None,
                            _expected(strength, None)))
            for way_id, cmd in _bash_payloads(path):
                out.append((f"{loc_id}|{rel}|bash:{way_id}",
                            {"tool_name": "Bash", "tool_input": {"command": cmd}},
                            None, _expected(strength, None)))

    for path, strength in GLOBAL_TARGETS:
        short = path.replace(HOME, "~")
        for tool_id, payload in _tool_payloads(path):
            out.append((f"global|{short}|{tool_id}", payload, None,
                        _expected(strength, None)))
        for way_id, cmd in _bash_payloads(path):
            out.append((f"global|{short}|bash:{way_id}",
                        {"tool_name": "Bash", "tool_input": {"command": cmd}},
                        None, _expected(strength, None)))

    # Level 1 must lift exactly the gated targets and nothing else.
    root = LOCATIONS[0][1]
    for rel, strength in PROJECT_TARGETS:
        path = f"{root}/{rel}"
        out.append((f"override1|{rel}|Write",
                    {"tool_name": "Write", "tool_input": {"file_path": path, "content": "x"}},
                    1, _expected(strength, 1)))
    # Even level 3 does not lift the hard ones.
    for rel, strength in PROJECT_TARGETS:
        if strength != HARD:
            continue
        path = f"{root}/{rel}"
        out.append((f"override3|{rel}|Write",
                    {"tool_name": "Write", "tool_input": {"file_path": path, "content": "x"}},
                    3, BLOCK))

    # Detours: the same target, spelled around the corner.
    base = LOCATIONS[2][1]
    for detour_id, path in [
        ("dotdot", f"{base}/sub/../.opencode/plugin/x.ts"),
        ("double-slash", f"{base}//.opencode//plugin//x.ts"),
        ("dot-segment", f"{base}/./.opencode/plugin/x.ts"),
        ("dotdot-root-file", f"{base}/sub/../opencode.json"),
    ]:
        out.append((f"detour|{detour_id}|Write",
                    {"tool_name": "Write", "tool_input": {"file_path": path, "content": "x"}},
                    None, BLOCK))
        out.append((f"detour|{detour_id}|bash",
                    {"tool_name": "Bash", "tool_input": {"command": f"echo x > {path}"}},
                    None, BLOCK))
    return out


CASES = _cases()


def run_all():
    rules = _make_rules()
    results = []
    try:
        for cid, payload, level, expected in CASES:
            rc = _run(payload, rules, level)
            results.append((cid, expected, rc, rc == expected))
    finally:
        try:
            os.unlink(rules)
        except OSError:
            pass
    return results


try:
    import pytest

    _RULES = _make_rules()

    @pytest.mark.parametrize("cid,payload,level,expected", CASES)
    def test_second_toolchain_control_files(cid, payload, level, expected):
        assert _run(payload, _RULES, level) == expected, cid

except ImportError:
    pass


if __name__ == "__main__":
    res = run_all()
    fails = [r for r in res if not r[3]]
    for cid, expected, rc, ok in fails:
        exp = "allow" if expected == ALLOW else "block"
        got = "allow" if rc == ALLOW else ("block" if rc == BLOCK else f"rc={rc}")
        print(f"FAIL  {cid:56s} exp={exp:5s} got={got}")
    passed = len(res) - len(fails)
    print(f"\nSecond tool chain control files: {passed}/{len(res)} passed  (hook: {HOOK})")
    raise SystemExit(0 if not fails else 1)
