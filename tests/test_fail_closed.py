# ============================================================================
# Finding B — fail-CLOSED on missing/invalid rules. Standalone (needs a custom
# rules path, unlike the CASES runner). Drop into tests/ or call from main().
# ============================================================================
import json, os, subprocess, tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent if (Path(__file__).resolve().parent.name == "tests") else Path("/tmp/ccsg")
HOOK = REPO / "hooks" / "command-guard.py"

def _run(command: str, rules_path: str) -> int:
    with tempfile.TemporaryDirectory() as ov:
        payload = {"session_id": "s", "hook_event_name": "PreToolUse",
                   "tool_name": "Bash", "tool_input": {"command": command}}
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = rules_path
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = ov
        env["CLAUDE_AUDIT_DIR"] = ov
        env["CLAUDE_HOOK_DEV_FLAG"] = ov + "/_none"
        p = subprocess.run(["python3", str(HOOK)], input=json.dumps(payload),
                           capture_output=True, text=True, env=env)
        return p.returncode

def test_fail_closed():
    results = []
    # B1: rules file missing -> fallback active -> rm -rf / still blocked
    results.append(("B1 missing rules: rm -rf / blocked", _run("rm -rf /", "/no/such/rules.json") == 2))
    # B2: rules file missing -> credential read still blocked
    results.append(("B2 missing rules: cat ~/.ssh/id_rsa blocked", _run("cat ~/.ssh/id_rsa", "/no/such/rules.json") == 2))
    # B3: invalid JSON -> fallback active -> rm -rf / blocked
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write("{ this is not json")
        bad = f.name
    results.append(("B3 corrupt rules: rm -rf / blocked", _run("rm -rf /", bad) == 2))
    os.unlink(bad)
    # B4: empty object -> fallback active -> rm -rf / blocked
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write("{}")
        empty = f.name
    results.append(("B4 empty rules: rm -rf / blocked", _run("rm -rf /", empty) == 2))
    os.unlink(empty)
    # B5: fallback must not over-block normal work
    results.append(("B5 missing rules: 'ls -la' allowed", _run("ls -la", "/no/such/rules.json") == 0))
    # B6: missing rules -> docker --privileged still blocked (hardcoded flag fallback)
    results.append(("B6 missing rules: docker --privileged blocked",
                    _run("docker run --privileged ubuntu", "/no/such/rules.json") == 2))

    passed = sum(1 for _, ok in results if ok)
    for name, ok in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
    print(f"\nfail-closed: {passed}/{len(results)} passed")
    return 0 if passed == len(results) else 1

if __name__ == "__main__":
    raise SystemExit(test_fail_closed())
