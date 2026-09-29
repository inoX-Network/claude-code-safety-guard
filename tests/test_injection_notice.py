#!/usr/bin/env python3
"""The prompt-injection warning reaches the model — and only for a real word.

Before, the warning went to stderr only. For a call the hook allows, Claude
Code sends that to its debug log: nobody read it. It now travels through
additionalContext, together with the rules notice in one JSON object.

That made the matching matter. Measured 2026-09-24 on 204,087 allowed commands
from the author's audit log, the substring test would have told the model
3,726 times in 340 sessions — "dan" inside ordinary words, "override" in the
guard's own approval vocabulary. Real injections: none. With whole words,
all-caps keywords matched case-sensitively and "override" dropped from the
example list, 31 hits in 8 sessions remained, all from work on injection
detection itself.

Keywords appear here only as assembled strings, so this file does not trip a
keyword scanner itself.
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
EXAMPLE = json.loads((REPO / "security-rules.example.json").read_text(encoding="utf-8"))
IGNORE = "ignore " + "previous"
ACRONYM = "D" + "AN"


def _call(command, rules=None, *, shared=None, session="injection-notice"):
    rules = EXAMPLE if rules is None else rules
    with tempfile.TemporaryDirectory() as own:
        tmp = shared or own
        path = Path(tmp) / "rules.json"
        path.write_text(json.dumps(rules), encoding="utf-8")
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = str(path)
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = tmp
        env["CLAUDE_AUDIT_DIR"] = tmp
        env["CLAUDE_HOOK_DEV_FLAG"] = tmp + "/_none"
        env["CLAUDE_GUARD_CONFIG"] = tmp + "/_no_config.json"
        payload = {"tool_name": "Bash", "tool_input": {"command": command},
                   "session_id": session, "hook_event_name": "PreToolUse"}
        r = subprocess.run([sys.executable, str(HOOK)], input=json.dumps(payload),
                           capture_output=True, text=True, env=env, timeout=60, cwd=tmp)
        out = r.stdout.strip()
        return r.returncode, (json.loads(out) if out else None)


def _context(out):
    return ((out or {}).get("hookSpecificOutput") or {}).get("additionalContext") or ""


def check_keyword_reaches_the_model():
    code, out = _call(f'echo "{IGNORE} instructions"')
    return code == 0 and IGNORE in _context(out)


def check_no_permission_decision():
    _, out = _call(f'echo "{IGNORE}"')
    spec = (out or {}).get("hookSpecificOutput") or {}
    return spec.get("hookEventName") == "PreToolUse" and "permissionDecision" not in spec


def check_acronym_in_capitals_reaches_the_model():
    code, out = _call(f"echo {ACRONYM} mode")
    return code == 0 and ACRONYM in _context(out)


def check_acronym_inside_ordinary_words_is_silent():
    return _call("echo abundant dandelion standard") == (0, None)


def check_acronym_in_lowercase_is_silent():
    return _call(f"echo {ACRONYM.lower()}") == (0, None)


def check_keyword_as_word_prefix_is_silent():
    return _call("echo " + "ignore " + "allowed") == (0, None)


def check_approval_vocabulary_is_silent():
    return _call("ls ~/.claude/.sudo-over" + "rides-pending") == (0, None)


def check_warning_on_every_affected_call():
    with tempfile.TemporaryDirectory() as shared:
        first = _call(f'echo "{IGNORE}"', shared=shared)[1]
        second = _call(f'echo "{IGNORE}"', shared=shared)[1]
        return IGNORE in _context(first) and IGNORE in _context(second)


def check_warning_and_rules_notice_share_one_output():
    rules = {k: v for k, v in EXAMPLE.items() if k != "blocked_git_ops"}
    code, out = _call(f'echo "{IGNORE}"', rules)
    text = _context(out)
    return (code == 0 and IGNORE in text and "blocked_git_ops" in text
            and text.index(IGNORE) < text.index("blocked_git_ops"))


def check_blocked_call_prints_nothing():
    return _call(f'git reset --hard; echo "{IGNORE}"') == (2, None)


CHECKS = [(name, fn) for name, fn in sorted(globals().items())
          if name.startswith("check_") and callable(fn)]


def test_injection_notice():
    failed = [name for name, fn in CHECKS if not fn()]
    assert not failed, f"{len(failed)} of {len(CHECKS)} failed: {failed}"


if __name__ == "__main__":
    bad = [name for name, fn in CHECKS if not fn()]
    for name, _ in CHECKS:
        print(f"  {'FAIL' if name in bad else 'ok  '}  {name}")
    print(f"\n{len(CHECKS) - len(bad)} of {len(CHECKS)} passed")
    sys.exit(1 if bad else 0)
