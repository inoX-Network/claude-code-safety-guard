# ============================================================================
# Self-protection knew only fixed paths under the home directory.
#
# The tool chain loads its control files from EVERY project directory:
# .claude/settings.json, .claude/hooks/, .claude/agents|skills|commands/,
# .mcp.json. Every one of those was writable by the AI at any location, through
# any write path. The worst case is the combination: a project-local settings
# file can register a hook, and the hook code next to it was writable too --
# a complete way around the guard's own checks, without a single grant.
#
# The fix is a RULE, not a longer list: protected is whatever the tool chain
# reads as control, wherever it lies. A directory that does not exist yet is
# covered without anyone adding it.
#
# Deliberately NOT protected: a project's CLAUDE.md. 70 writes in two months make
# it everyday work; a hard block would be switched off within a week. The
# counterweight is traceability, not a barrier -- see THREAT-MODEL.
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

ALLOW = 0
BLOCK = 2

HARD = "hard"        # no override lifts it
GATED = "gated"      # override level 1 lifts it
FREE = "free"        # stays writable

# Targets and how hard they are protected. Paths are relative to a project root.
TARGETS = [
    (".claude/settings.json", HARD),
    (".claude/settings.local.json", HARD),
    (".claude/hooks/pre-tool.py", HARD),
    (".mcp.json", HARD),
    (".claude/agents/helper.md", GATED),
    (".claude/skills/thing/SKILL.md", GATED),
    (".claude/commands/deploy.md", GATED),
    # Counter-probes: without these the list only proves a total lockdown.
    ("CLAUDE.md", FREE),
    ("src/app.py", FREE),
    ("docs/settings.json", FREE),      # same name, but not under .claude
]

# Locations. The rule must not depend on where the project lies.
LOCATIONS = [
    ("own-project", "/home/probe/Projekte/eigenes"),
    ("foreign-project", "/home/probe/anderswo/fremdes"),
    ("throwaway", "/tmp/wegwerf-probe"),
]


def _make_rules() -> str:
    """Example rules, untouched. The new protection must not depend on the rules
    file -- a control file that only the configuration protects can be unprotected
    by editing that configuration."""
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
                "task": "project-local control file test",
                "confirmed": True,
                "expires_at": expires,
                "grants": {"additional_sudo": [], "allowed_paths": []},
            }), encoding="utf-8")
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = rules_path
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = ov
        env["CLAUDE_AUDIT_DIR"] = ov
        env["CLAUDE_HOOK_DEV_FLAG"] = ov + "/_none"
        payload = {"session_id": "project-control-test",
                   "hook_event_name": "PreToolUse", **payload}
        p = subprocess.run(["python3", str(HOOK)], input=json.dumps(payload),
                           capture_output=True, text=True, env=env)
        return p.returncode


def _tool_payloads(path: str):
    """The file-touching tools, each with its own argument shape."""
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
    yield "cp", f"cp /tmp/quelle {path}"
    yield "mv", f"mv /tmp/quelle {path}"
    yield "sed-i", f"sed -i s/a/b/ {path}"
    yield "touch", f"touch {path}"
    yield "symlink", f"ln -sf /tmp/quelle {path}"
    yield "python-inline", f"python3 -c \"open('{path}','w').write('x')\""
    yield "heredoc", f"cat > {path} <<EOF\nx\nEOF"
    yield "mkdir-then-write", f"mkdir -p {d} && echo x > {path}"


def _expected(strength: str, override_level: int | None) -> int:
    if strength == FREE:
        return ALLOW
    if strength == HARD:
        return BLOCK                      # no level lifts it
    return ALLOW if (override_level or 0) >= 1 else BLOCK


def _cases():
    """(id, payload, override_level, expected)"""
    out = []
    for loc_id, root in LOCATIONS:
        for rel, strength in TARGETS:
            path = f"{root}/{rel}"
            for tool_id, payload in _tool_payloads(path):
                out.append((f"{loc_id}|{rel}|{tool_id}", payload, None,
                            _expected(strength, None)))
            for way_id, cmd in _bash_payloads(path):
                out.append((f"{loc_id}|{rel}|bash:{way_id}",
                            {"tool_name": "Bash", "tool_input": {"command": cmd}},
                            None, _expected(strength, None)))

    # Level 1 must lift exactly the gated targets and nothing else.
    root = LOCATIONS[0][1]
    for rel, strength in TARGETS:
        path = f"{root}/{rel}"
        out.append((f"override1|{rel}|Write",
                    {"tool_name": "Write", "tool_input": {"file_path": path, "content": "x"}},
                    1, _expected(strength, 1)))
    # Even level 3 does not lift the hard ones.
    for rel, strength in TARGETS:
        if strength != HARD:
            continue
        path = f"{root}/{rel}"
        out.append((f"override3|{rel}|Write",
                    {"tool_name": "Write", "tool_input": {"file_path": path, "content": "x"}},
                    3, BLOCK))

    # Detours: the same target, spelled around the corner.
    base = LOCATIONS[2][1]
    for detour_id, path in [
        ("dotdot", f"{base}/unterordner/../.claude/settings.json"),
        ("double-slash", f"{base}//.claude//settings.json"),
        ("dot-segment", f"{base}/./.claude/settings.json"),
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
    def test_project_local_control_files(cid, payload, level, expected):
        assert _run(payload, _RULES, level) == expected, cid

except ImportError:
    pass


if __name__ == "__main__":
    res = run_all()
    fails = [r for r in res if not r[3]]
    for cid, expected, rc, ok in fails:
        exp = "allow" if expected == ALLOW else "block"
        got = "allow" if rc == ALLOW else ("block" if rc == BLOCK else f"rc={rc}")
        print(f"FAIL  {cid:52s} exp={exp:5s} got={got}")
    passed = len(res) - len(fails)
    print(f"\nProject-local control files: {passed}/{len(res)} passed  (hook: {HOOK})")
    raise SystemExit(0 if not fails else 1)
