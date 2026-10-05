#!/usr/bin/env python3
"""A wildcard in a path list of the rules file must not fail silently.

The path lists -- blocked_paths_write, blocked_paths_delete,
blocked_recursive_delete and the two read tiers always_blocked_reads and
require_override_1 -- take exact paths. A wildcard in them is not expanded: the
entry is compared as written and matches nothing real.

Measured 2026-10-05 on a real installation. A tool's README recommended the
entry '~/.claude/rate-limit.json*' to cover the file and its .lock/.tmp
neighbours. Written that way, the entry protected NOTHING -- the main file
included. 15 of 20 probe cases were protected with the exact entry, 9 of 20
with the pattern. A natural way to write the rule turned protection off, and
nothing said so.

Teaching every matcher wildcards (shell writes, inline code, downloaders, the
write tool, docker mounts, grant reach, delete protection) was rejected: five
separate places, the very kind of change this project has paid for before. The
owner chose to REPORT instead: the verdicts stay exactly as they were, and the
entry is named -- to the model once per session (the same channel as a missing
section) and to the human in tools/verify-install.py.

always_allowed is NOT checked: it does understand '*' ('~/.ssh/*.pub' in the
example file), so a wildcard there is meant and works.
"""
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
HOME = str(Path.home())
EXAMPLE = json.loads((REPO / "security-rules.example.json").read_text(encoding="utf-8"))
PATTERN = "~/.claude/rate-limit.json*"


def _with_list(section, entry):
    rules = json.loads(json.dumps(EXAMPLE))
    rules[section] = list(rules.get(section, [])) + [entry]
    return rules


def _with_read_tier(tier, entry):
    rules = json.loads(json.dumps(EXAMPLE))
    rules["protected_reads"][tier] = list(rules["protected_reads"][tier]) + [entry]
    return rules


def _call(command, rules):
    payload = {"tool_name": "Bash", "tool_input": {"command": command},
               "session_id": "wildcard-in-rules", "hook_event_name": "PreToolUse"}
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "rules.json"
        path.write_text(json.dumps(rules), encoding="utf-8")
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = str(path)
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = tmp
        env["CLAUDE_AUDIT_DIR"] = tmp
        env["CLAUDE_HOOK_DEV_FLAG"] = tmp + "/_none"
        env["CLAUDE_GUARD_CONFIG"] = tmp + "/_no_config.json"
        r = subprocess.run([sys.executable, str(HOOK)], input=json.dumps(payload),
                           capture_output=True, text=True, env=env, timeout=60, cwd=tmp)
        out = r.stdout.strip()
        data = json.loads(out) if out else {}
        text = (data.get("hookSpecificOutput") or {}).get("additionalContext") or ""
        return r.returncode, text


def _named(rules, *needles):
    code, text = _call("ls /tmp", rules)
    return code == 0 and all(n in text for n in needles)


# --- 1. every list without wildcard support reports the entry ----------------

def check_blocked_paths_write_reports():
    return _named(_with_list("blocked_paths_write", PATTERN),
                  "blocked_paths_write", PATTERN)


def check_blocked_paths_delete_reports():
    return _named(_with_list("blocked_paths_delete", "~/data/*"),
                  "blocked_paths_delete", "~/data/*")


def check_blocked_recursive_delete_reports():
    return _named(_with_list("blocked_recursive_delete", "~/projects/*"),
                  "blocked_recursive_delete", "~/projects/*")


def check_always_blocked_reads_reports():
    return _named(_with_read_tier("always_blocked_reads", "/etc/shadow*"),
                  "always_blocked_reads", "/etc/shadow*")


def check_require_override_1_reports():
    return _named(_with_read_tier("require_override_1", "~/.kube/config?"),
                  "require_override_1", "~/.kube/config?")


def check_bracket_reports():
    return _named(_with_list("blocked_paths_write", "/srv/[ab]pp"), "/srv/[ab]pp")


def check_notice_says_the_entry_protects_nothing():
    code, text = _call("ls /tmp", _with_list("blocked_paths_write", PATTERN))
    return code == 0 and "NOT protected" in text


def check_notice_does_not_blame_an_update():
    # The tail for missing sections says the file predates an update. A
    # wildcard is a writing mistake, not an old file.
    code, text = _call("ls /tmp", _with_list("blocked_paths_write", PATTERN))
    return code == 0 and text and "predates an update" not in text


# --- 2. what must stay quiet --------------------------------------------------

def check_example_file_is_quiet():
    code, text = _call("ls /tmp", EXAMPLE)
    return code == 0 and text == ""


def check_always_allowed_wildcard_is_quiet():
    # '~/.ssh/*.pub' is in the example file already; another one must not
    # start a notice either.
    rules = _with_read_tier("always_allowed", "~/.ssh/*.cert")
    code, text = _call("ls /tmp", rules)
    return code == 0 and text == ""


# --- 3. verdicts are unchanged -- this reports, it does not judge -------------

def check_verdict_unchanged_for_the_pattern_itself():
    # The exact entry blocks; the pattern blocked nothing before and still does
    # not. If this ever flips, the change was more than a report.
    exact = _call(f"echo x > {HOME}/.claude/rate-limit.json",
                  _with_list("blocked_paths_write", "~/.claude/rate-limit.json"))[0]
    pattern = _call(f"echo x > {HOME}/.claude/rate-limit.json",
                    _with_list("blocked_paths_write", PATTERN))[0]
    return exact == 2 and pattern == 0


def check_other_entries_still_block():
    rules = _with_list("blocked_paths_write", PATTERN)
    return _call(f"echo x > {HOME}/.ssh/authorized_keys", rules)[0] == 2


# --- 4. the human sees it too ---------------------------------------------------

def _verify_install_notes(rules):
    spec = importlib.util.spec_from_file_location(
        "verify_install", REPO / "tools" / "verify-install.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    with redirect_stdout(io.StringIO()):
        spec.loader.exec_module(mod)
    seen = []
    setattr(mod, "note", lambda state, check, detail: seen.append((state, check, detail)))
    mod.check_rule_wildcards(rules)
    return mod, seen


def check_verify_install_warns():
    mod, seen = _verify_install_notes(_with_list("blocked_paths_write", PATTERN))
    return any(state == mod.WARN and PATTERN in detail for state, _, detail in seen)


def check_verify_install_quiet_on_example():
    mod, seen = _verify_install_notes(EXAMPLE)
    return bool(seen) and all(state == mod.OK for state, _, _ in seen)


CHECKS = [(name, fn) for name, fn in sorted(globals().items())
          if name.startswith("check_") and callable(fn)]


def test_wildcard_in_rule_paths():
    failed = [name for name, fn in CHECKS if not fn()]
    assert not failed, f"{len(failed)} of {len(CHECKS)} failed: {failed}"


if __name__ == "__main__":
    bad = []
    for name, fn in CHECKS:
        try:
            ok = fn()
        except Exception as exc:          # a missing function is a failure here
            ok = False
            print(f"        {name}: {type(exc).__name__}: {exc}")
        if not ok:
            bad.append(name)
    for name, _ in CHECKS:
        print(f"  {'FAIL' if name in bad else 'ok  '}  {name}")
    print(f"\n{len(CHECKS) - len(bad)} of {len(CHECKS)} passed")
    sys.exit(1 if bad else 0)
