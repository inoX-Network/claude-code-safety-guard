# ============================================================================
# The code carries message KEYS, the texts live beside them.
#
# Two failure modes decide whether this is safe to build at all, because both
# would otherwise end in a refusal nobody can act on:
#
#   - a key with no text          -> print the key plus the values
#   - a text whose placeholder    -> same
#     does not fit
#
# A refusal without a reason is worse than an ugly reason. And a broken language
# file must never stop the guard: English is built in, so the hook stays usable
# even when nothing travelled with it.
#
# The completeness check walks the syntax tree for msg("...") calls and demands
# a text for every key it finds. It therefore grows with the code instead of
# needing to be maintained alongside it.
# ============================================================================
import ast
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))


def _load_guard(config_path: str | None = None):
    """Import the hook as a module so its functions can be called directly."""
    env_backup = os.environ.get("CLAUDE_GUARD_CONFIG")
    if config_path:
        os.environ["CLAUDE_GUARD_CONFIG"] = config_path
    try:
        spec = importlib.util.spec_from_file_location("guard_under_test", HOOK)
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        sys.modules["guard_under_test"] = mod
        spec.loader.exec_module(mod)
        return mod
    finally:
        if env_backup is None:
            os.environ.pop("CLAUDE_GUARD_CONFIG", None)
        else:
            os.environ["CLAUDE_GUARD_CONFIG"] = env_backup


def _keys_used_in_code() -> set:
    """Every key handed to msg() as a literal, taken from the syntax tree."""
    tree = ast.parse(HOOK.read_text(encoding="utf-8"))
    keys = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "msg"):
            continue
        if node.args and isinstance(node.args[0], ast.Constant) \
                and isinstance(node.args[0].value, str):
            keys.add(node.args[0].value)
    return keys


def check_completeness():
    """Every key used in the code has a built-in English text."""
    guard = _load_guard()
    used = _keys_used_in_code()
    catalogue = set(guard._MESSAGES)
    missing = sorted(used - catalogue)
    unused = sorted(catalogue - used)
    return missing, unused, len(used)


def check_missing_key():
    """An unknown key must name itself, not vanish."""
    guard = _load_guard()
    out = guard.msg("this.key.does.not.exist", path="/tmp/x")
    return ("this.key.does.not.exist" in out and "/tmp/x" in out
            and out.startswith("BLOCKED"))


def check_bad_placeholder():
    """A text whose placeholder does not fit must not raise."""
    guard = _load_guard()
    guard._MESSAGES["test.bad.placeholder"] = "needs {missing_one} here"
    try:
        out = guard.msg("test.bad.placeholder", something_else="x")
    except Exception as exc:                      # noqa: BLE001 - that is the point
        return False, f"raised {type(exc).__name__}"
    return ("test.bad.placeholder" in out and "something_else=x" in out), out


def check_language_file_overrides():
    """A language file replaces the built-in text; unknown keys stay English."""
    with tempfile.TemporaryDirectory() as d:
        lang = Path(d) / "lang"
        lang.mkdir()
        (lang / "xx.json").write_text(json.dumps({"guard.stumbled": "ÜBERSETZT {reason}"}),
                                      encoding="utf-8")
        cfg = Path(d) / "guard-config.json"
        cfg.write_text(json.dumps({"language": "xx",
                                   "installation": {"lang_dir": str(lang)}}), encoding="utf-8")
        guard = _load_guard(str(cfg))
        guard._MESSAGES["guard.stumbled"] = "ENGLISH {reason}"
        guard._MESSAGES["guard.other"] = "STILL ENGLISH"
        uebersetzt = guard.msg("guard.stumbled", reason="weil")
        englisch = guard.msg("guard.other")
        return uebersetzt.startswith("ÜBERSETZT") and englisch == "STILL ENGLISH"


def check_broken_language_file():
    """A broken language file must not stop the guard — English applies."""
    with tempfile.TemporaryDirectory() as d:
        lang = Path(d) / "lang"
        lang.mkdir()
        (lang / "xx.json").write_text("{ this is not json", encoding="utf-8")
        cfg = Path(d) / "guard-config.json"
        cfg.write_text(json.dumps({"language": "xx",
                                   "installation": {"lang_dir": str(lang)}}), encoding="utf-8")
        guard = _load_guard(str(cfg))
        guard._MESSAGES["guard.other"] = "STILL ENGLISH"
        return guard.msg("guard.other") == "STILL ENGLISH"


def check_language_name_is_not_a_path():
    """A language name must not be able to point at an arbitrary file."""
    with tempfile.TemporaryDirectory() as d:
        cfg = Path(d) / "guard-config.json"
        cfg.write_text(json.dumps({"language": "../../etc/passwd"}), encoding="utf-8")
        guard = _load_guard(str(cfg))
        return guard._LANGUAGE == {}


def check_guard_still_runs():
    """End to end: the hook still refuses what it refused before."""
    with tempfile.TemporaryDirectory() as ov:
        env = dict(os.environ)
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = ov
        env["CLAUDE_AUDIT_DIR"] = ov
        env["CLAUDE_HOOK_DEV_FLAG"] = ov + "/_none"
        p = subprocess.run(
            ["python3", str(HOOK)],
            input=json.dumps({"session_id": "catalog-test", "tool_name": "Bash",
                              "tool_input": {"command": "echo x > ~/.claude/hooks/x.py"}}),
            capture_output=True, text=True, env=env)
        return p.returncode == 2 and bool(p.stderr.strip())


CASES = [
    ("missing key names itself", check_missing_key),
    ("bad placeholder does not raise", lambda: check_bad_placeholder()[0]),
    ("language file overrides", check_language_file_overrides),
    ("broken language file falls back", check_broken_language_file),
    ("language name cannot be a path", check_language_name_is_not_a_path),
    ("guard still refuses end to end", check_guard_still_runs),
]

try:
    import pytest

    @pytest.mark.parametrize("name,fn", CASES)
    def test_message_catalog(name, fn):
        assert fn() is True, name

    def test_catalogue_is_complete():
        missing, unused, used = check_completeness()
        assert not missing, f"keys used in code without a text: {missing}"

except ImportError:
    pass


if __name__ == "__main__":
    fehler = 0
    for name, fn in CASES:
        ok = fn() is True
        fehler += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
    missing, unused, used = check_completeness()
    print(f"\nKeys used in code: {used}")
    print(f"  without a text : {len(missing)}  {missing if missing else ''}")
    print(f"  text never used: {len(unused)}  {unused if unused else ''}")
    fehler += bool(missing)
    raise SystemExit(0 if not fehler else 1)
