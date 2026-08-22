# ============================================================================
# Antigravity (agy) is the third tool chain on this machine.
#
# The pattern is the one established for opencode: whoever can write another
# agent's control files switches off that agent's checking -- crosswise. Claude
# Code writes, the other CLI executes. This holds whether or not an adapter is
# ever built for it, which is why the protection lives in the core.
#
# hooks.json is the sharpest of these files. The documentation embedded in the
# binary lists it under "Lifecycle Event -- running scripts/commands at
# specific agent lifecycle points (e.g. pre-tool execution)". It is the exact
# counterpart to .claude/hooks/, and Antigravity has no guard of its own.
#
# The paths come from the binary, not from a report about it. An earlier
# report named ~/.gemini/config/settings.json, which does not exist, and
# proposed blanket protection for .agents/, which is also the sub-agents'
# WORKING directory (ORIGINAL_REQUEST.md, phase_*_results.json,
# segment_*/handoff_*.md). A blanket pattern there would cripple the CLI.
#
# The cut follows the same rule as for .claude and .opencode:
#   hard   = code that runs on a tool call, plus what registers or enables it
#   gated  = instructions for future runs (level 1)
#   free   = runtime data, and AGENTS.md/GEMINI.md -- the counterpart to
#            CLAUDE.md, with the same deliberate decision behind it
#
# Globally one catch-all covers ~/.gemini/config/ at level 1: that directory is
# documented as the global customization root and holds no runtime data. The
# hard patterns sit inside it and are what a level-1 grant must NOT lift --
# which is why the override cases below cover the global targets too. Without
# them those hard patterns are indistinguishable from the catch-all, and a
# mutation run reports them as dead code. It did exactly that.
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

# Targets relative to a project root. All four spellings of the customization
# root are documented: .agents/, .agent/, _agents/, _agent/.
PROJECT_TARGETS = [
    (".agents/hooks.json", HARD),
    (".agent/hooks.json", HARD),
    ("_agents/hooks.json", HARD),
    ("_agent/hooks.json", HARD),
    (".agents/mcp_config.json", HARD),
    (".agents/plugins.json", HARD),
    (".agents/plugins/kit/plugin.json", HARD),
    (".agents/plugins/kit/hooks.json", HARD),
    (".agents/plugins/kit/index.js", HARD),
    (".agents/skills/thing/SKILL.md", GATED),
    (".agents/skills.json", GATED),
    (".agents/rules/AGENTS.md", GATED),
    (".agents/agents/helper/AGENT.md", GATED),
    (".agents/workflows/flow.md", GATED),
    # Counter-probes. Without these the list only proves a total lockdown.
    # .agents/ is also the sub-agents' working directory -- these three MUST
    # stay writable or the CLI cannot run.
    (".agents/ORIGINAL_REQUEST.md", FREE),
    (".agents/phase_a_level_00_results.json", FREE),
    (".agents/segment_one/handoff_1.md", FREE),
    (".agents/DISPATCH.md", FREE),
    # Counterpart to CLAUDE.md: everyday instruction file, stays free.
    ("AGENTS.md", FREE),
    ("GEMINI.md", FREE),
    # Same file name, but not under a customization root.
    ("docs/hooks.json", FREE),
    ("src/app.py", FREE),
]

LOCATIONS = [
    ("own-project", "/home/probe/Projekte/own"),
    ("throwaway", "/tmp/throwaway-probe"),
]

# Global targets, in the machine-local customization root.
GLOBAL_TARGETS = [
    (f"{HOME}/.gemini/config/hooks.json", HARD),              # shared location
    (f"{HOME}/.gemini/antigravity-cli/hooks.json", HARD),     # legacy, still read
    (f"{HOME}/.gemini/config/mcp_config.json", HARD),         # launches processes
    (f"{HOME}/.gemini/config/plugins/kit/hooks.json", HARD),
    (f"{HOME}/.gemini/config/plugins.json", HARD),
    (f"{HOME}/.gemini/config/projects/one.json", HARD),       # takes precedence
    (f"{HOME}/.gemini/config/config.json", HARD),             # enables plugins
    (f"{HOME}/.gemini/antigravity-cli/settings.json", HARD),
    (f"{HOME}/.gemini/settings.json", HARD),
    (f"{HOME}/.gemini/trustedFolders.json", HARD),            # which folders are trusted
    (f"{HOME}/.gemini/config/skills/thing/SKILL.md", GATED),
    (f"{HOME}/.gemini/config/workflows/flow.md", GATED),
    (f"{HOME}/.gemini/config/global_workflows/flow.md", GATED),
    (f"{HOME}/.gemini/config/workflows.json", GATED),
    # Counter-probes: runtime data. Measured against the running CLI -- this is
    # where it writes during operation, while the control files stayed
    # untouched since installation.
    (f"{HOME}/.gemini/antigravity-cli/cache/projects.json", FREE),
    (f"{HOME}/.gemini/antigravity-cli/log/cli.log", FREE),
    (f"{HOME}/.gemini/antigravity-cli/conversations/x.db", FREE),
    (f"{HOME}/.gemini/antigravity-cli/history.jsonl", FREE),
    (f"{HOME}/.gemini/antigravity-cli/brain/abc/logs/transcript.jsonl", FREE),
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
                "task": "third tool chain control file test",
                "confirmed": True,
                "expires_at": expires,
                "grants": {"additional_sudo": [], "allowed_paths": []},
            }), encoding="utf-8")
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = rules_path
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = ov
        env["CLAUDE_AUDIT_DIR"] = ov
        env["CLAUDE_HOOK_DEV_FLAG"] = ov + "/_none"
        payload = {"session_id": "third-toolchain-test",
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
    for rel, strength in PROJECT_TARGETS:
        if strength != HARD:
            continue
        path = f"{root}/{rel}"
        out.append((f"override3|{rel}|Write",
                    {"tool_name": "Write", "tool_input": {"file_path": path, "content": "x"}},
                    3, BLOCK))

    # The same for the GLOBAL targets -- and this half is the one that earns
    # its keep. Under ~/.gemini/config/ a level-1 catch-all already blocks
    # every path without any grant, so the hard patterns beside it change
    # nothing about the verdict until a grant exists. Only with the grant do
    # the two separate: the catch-all yields, the hard patterns do not.
    for path, strength in GLOBAL_TARGETS:
        short = path.replace(HOME, "~")
        out.append((f"global-override1|{short}|Write",
                    {"tool_name": "Write", "tool_input": {"file_path": path, "content": "x"}},
                    1, _expected(strength, 1)))
        if strength == HARD:
            out.append((f"global-override3|{short}|Write",
                        {"tool_name": "Write",
                         "tool_input": {"file_path": path, "content": "x"}},
                        3, BLOCK))

    # Detours: the same target, spelled around the corner.
    base = LOCATIONS[1][1]
    for detour_id, path in [
        ("dotdot", f"{base}/sub/../.agents/hooks.json"),
        ("double-slash", f"{base}//.agents//hooks.json"),
        ("dot-segment", f"{base}/./.agents/hooks.json"),
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
    def test_third_toolchain_control_files(cid, payload, level, expected):
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
    print(f"\nthird tool chain control files: {passed} of {len(res)} passed")
    raise SystemExit(1 if fails else 0)
