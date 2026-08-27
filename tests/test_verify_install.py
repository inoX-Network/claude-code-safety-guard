# ============================================================================
# Does the installation check find a broken installation?
#
# A verification tool that reports "all good" is worthless until you have seen
# it report "broken". This project has been bitten by that twice: a graph tool
# that reported green without having read a single node, and a session gate
# that reported a clean state while looking at the wrong project.
#
# So each case here constructs a deliberately broken install in a temporary
# HOME and asserts the tool fails on it. The last case builds a sound one and
# asserts it passes — without that, a tool that simply always fails would look
# perfect here.
#
# Nothing touches the real ~/.claude: every case runs with HOME redirected.
# ============================================================================
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TOOL = REPO / "tools" / "verify-install.py"
HOOK = REPO / "hooks" / "command-guard.py"

SOUND_RULES = {
    "blocked_patterns": ["chmod -R 777"],
    "blocked_paths_write": ["/etc"],
    "blocked_paths_delete": [],
    "owner_only_commands": ["grant-override"],
    "allowed_sudo": [], "blocked_git_ops": [], "require_confirmation": [],
    "protected_git_branches": [], "blocked_bash_patterns_force_push": [],
    "prompt_injection_keywords": [],
    "protected_reads": {
        "always_blocked_reads": [], "require_override_1": ["~/.ssh/id_"],
        "always_allowed": [], "env_files_require_override_1": [".env"],
    },
}


def _build(home: Path, *, settings=True, hook_exists=True, rules_exist=True,
           guard_entry=True):
    """Assembles an install under `home`, leaving out whatever is asked."""
    (home / ".claude" / "hooks").mkdir(parents=True, exist_ok=True)
    (home / ".claude" / "safety-guard").mkdir(parents=True, exist_ok=True)
    (home / ".claude" / "bin").mkdir(parents=True, exist_ok=True)

    hook_path = home / ".claude" / "hooks" / "command-guard.py"
    if hook_exists:
        hook_path.write_text(HOOK.read_text(encoding="utf-8"), encoding="utf-8")

    if rules_exist:
        (home / ".claude" / "safety-guard" / "security-rules.json").write_text(
            json.dumps(SOUND_RULES), encoding="utf-8")

    if settings:
        command = (f"python3 {hook_path}" if guard_entry
                   else "python3 /some/other/hook.py")
        (home / ".claude" / "settings.json").write_text(json.dumps({
            "hooks": {"PreToolUse": [{"hooks": [
                {"type": "command", "command": command}]}]}
        }), encoding="utf-8")


def _run(home: Path):
    env = dict(os.environ)
    env["HOME"] = str(home)
    # Do not let the real machine's variables leak into a constructed install.
    for leaking in ("CLAUDE_SECURITY_RULES", "CLAUDE_GUARD_CONFIG",
                    "CLAUDE_HOOK_DEV_FLAG", "CLAUDE_SUDO_OVERRIDES_DIR"):
        env.pop(leaking, None)
    # --wiring-only on purpose: the hook resolves the home directory itself
    # and ignores $HOME (moving that variable must not move the
    # self-protection). So inside a constructed HOME the payload probes get
    # real verdicts against the REAL rules of this machine — which is correct
    # behaviour and useless to assert against. The wiring half reads the paths
    # this process sees, so it can be tested in a temporary home.
    proc = subprocess.run([sys.executable, str(TOOL), "--wiring-only"],
                          capture_output=True, text=True, env=env, timeout=300)
    return proc.returncode, proc.stdout


def _case(builder, expect_fail, why):
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp)
        builder(home)
        code, out = _run(home)
        failed = code != 0
        if failed == expect_fail:
            return True, ""
        return False, (f"{why}: expected {'failure' if expect_fail else 'success'}, "
                       f"got exit {code}\n{out[:400]}")


def check_missing_settings():
    return _case(lambda h: _build(h, settings=False), True,
                 "no settings.json at all")


def check_hook_entry_points_nowhere():
    # The two-halves failure: the entry exists, the file does not. This is the
    # one that looks like a working install from the outside.
    return _case(lambda h: _build(h, hook_exists=False), True,
                 "settings names a hook that is not there")


def check_no_guard_entry():
    return _case(lambda h: _build(h, guard_entry=False), True,
                 "PreToolUse exists but registers a different hook")


def check_missing_rules():
    return _case(lambda h: _build(h, rules_exist=False), True,
                 "rules file missing")


def check_sound_install_passes():
    # The control. Without it, a tool that always fails would pass every case
    # above and look thorough.
    return _case(lambda h: _build(h), False, "a sound install")


CASES = [
    ("missing settings.json is caught", check_missing_settings),
    ("hook entry pointing nowhere is caught", check_hook_entry_points_nowhere),
    ("a foreign PreToolUse hook is not mistaken for ours", check_no_guard_entry),
    ("missing rules file is caught", check_missing_rules),
    ("a sound install passes", check_sound_install_passes),
]

try:
    import pytest

    @pytest.mark.parametrize("name,fn", CASES)
    def test_verify_install(name, fn):
        ok, detail = fn()
        assert ok, f"{name}: {detail}"

except ImportError:
    pass


if __name__ == "__main__":
    failures = 0
    for name, fn in CASES:
        ok, detail = fn()
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            print(f"      {detail}")
    raise SystemExit(0 if not failures else 1)
