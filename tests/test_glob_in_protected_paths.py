# ============================================================================
# A single asterisk walked past the self-protection.
#
# The guard inspects the RAW command text. The shell assembles names only
# afterwards. So `echo x > ~/.claude/setting*.json` contains no literal
# "settings.json", matches nothing, and ran through — while the same command
# spelled out was refused. The hardest protection class in this hook, the one
# documented as "no override, never bypassable", was reachable with one
# character.
#
# Measured in an adversarial audit of 53 bypass attempts: this was the worst
# single finding, because it needs no tool, no encoding and no privilege — and
# because the target is the guard's own source and settings.
#
# THE FIX INVERTS THE QUESTION. Expanding the pattern to see what it hits was
# rejected: that makes the verdict depend on the file system, i.e. on state
# that can change between check and execution. Instead the PATTERN is held
# against the protection LIST — could it hit a protected path? Stateless, and
# coarse in the SAFE direction: a pattern that could match blocks even when it
# currently matches nothing.
#
# THE COUNTER-CASES CARRY THE SAME WEIGHT as the holes. Measured over 87,253
# real logged Bash commands: patterns aimed at hard-protected paths occur ZERO
# times, patterns inside the working tree four times — all of them harmless
# (copying fonts, reading a migration). Those four shapes are the "still free"
# cases below. If the rule eats one of them, the boundary is drawn wrong.
#
# Component-by-component matching matters: a glob must never match across a
# slash. Otherwise '/tmp/*' would count as a hit on '/tmp/a/b' and every path
# boundary in this file would be meaningless.
# ============================================================================
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))

HOME = os.path.expanduser("~")

RULES = {
    "protected_reads": {
        "always_blocked_reads": ["/etc/shadow"],
        "require_override_1": ["~/.ssh/id_"],
        "always_allowed": ["~/.ssh/*.pub"],
        "env_files_require_override_1": [".env"],
    },
    "blocked_paths_write": ["/etc", "~/.ssh"],
    "blocked_patterns": [], "blocked_git_ops": [],
    "protected_git_branches": [], "blocked_bash_patterns_force_push": [],
    "allowed_sudo": ["tar", "grep"], "owner_only_commands": [],
    "require_confirmation": [],
}


def _run(command):
    """Runs the hook on a Bash command. Returns the exit code (2 = blocked)."""
    with tempfile.TemporaryDirectory() as d:
        rules = Path(d) / "rules.json"
        rules.write_text(json.dumps(RULES), encoding="utf-8")
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = str(rules)
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = str(Path(d) / "no-overrides")
        env["CLAUDE_AUDIT_DIR"] = str(Path(d) / "audit")
        env["CLAUDE_HOOK_DEV_FLAG"] = str(Path(d) / "no-dev-mode")
        payload = json.dumps({
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "cwd": HOME,
            "session_id": "glob-tests",
        })
        p = subprocess.run([sys.executable, str(HOOK)], input=payload,
                           capture_output=True, text=True, env=env)
        return p.returncode


def _blocked(command, why):
    rc = _run(command)
    return rc == 2, f"{why}: expected block, got exit {rc} for: {command}"


def _free(command, why):
    rc = _run(command)
    return rc == 0, f"{why}: expected free, got exit {rc} for: {command}"


# --- the hole -------------------------------------------------------------

def check_settings_via_asterisk():
    return _blocked(f"echo x > {HOME}/.claude/setting*.json",
                    "settings.json reached through an asterisk")


def check_settings_via_question_mark():
    return _blocked(f"echo x > {HOME}/.claude/setting?.json",
                    "a question mark stands for exactly one character")


def check_settings_via_character_class():
    return _blocked(f"echo x > {HOME}/.claude/setting[s]*.json",
                    "character classes expand as well")


def check_hooks_dir_via_asterisk():
    return _blocked(f"rm -rf {HOME}/.claude/hoo*",
                    "the hook directory reached through an asterisk")


def check_extension_cut_short():
    return _blocked(f"cp /dev/null {HOME}/.claude/settings.jso*",
                    "cutting the extension short is the same trick")


def check_truncate_via_asterisk():
    return _blocked(f"truncate -s0 {HOME}/.claude/setting*.json",
                    "emptying a file is writing to it")


def check_override_dir_via_asterisk():
    return _blocked(f"echo x > {HOME}/.claude/.sudo-override*/forged.json",
                    "the override directory reached through an asterisk")


def check_tilde_form():
    return _blocked("echo x > ~/.claude/setting*.json",
                    "the tilde form must behave like the absolute one")


def check_glob_in_the_middle():
    # Carried by the component-by-component comparison ALONE: whoever compares
    # the whole path in one piece lets this through, because the asterisk would
    # have to match across a slash.
    return _blocked(f"echo x > {HOME}/.clau*/settings.json",
                    "a glob in the middle of the path")


def check_inline_one_liner_with_glob():
    return _blocked(
        "python3 -c \"import glob; [open(p,'w') for p in "
        f"glob.glob('{HOME}/.claude/setting*.json')]\"",
        "an inline one-liner can assemble its target too")


# --- still free: real commands, taken from 87,253 logged ones -------------

def check_copying_fonts_stays_free():
    return _free(
        f"cp {HOME}/work/project/src/fonts/Oxanium-*.ttf /tmp/target/",
        "copying fonts inside the working tree")


def check_reading_migrations_stays_free():
    return _free(
        f"sed -n '610,645p' {HOME}/work/project/db/migrations/001*.sql",
        "reading a migration file")


def check_copying_json_stays_free():
    return _free(f"cp {HOME}/work/project/data/parsed/*.json /tmp/target/",
                 "copying parsed data")


def check_listing_hooks_stays_free():
    # Reading inside a protected tree is decided by the read protection, not by
    # this rule. A glob must not change that.
    return _free(f"ls {HOME}/.claude/hooks/*.py",
                 "listing the hook directory")


def check_grep_in_hooks_stays_free():
    return _free(f"grep -n 'def ' {HOME}/.claude/hooks/*.py",
                 "searching inside the hook directory")


def check_scratch_glob_stays_free():
    return _free("rm -rf /tmp/probe*/", "a glob in the scratch area")


def check_scratch_write_stays_free():
    return _free("echo x > /tmp/probe*.txt", "writing to a scratch pattern")


def check_pattern_in_prose_stays_free():
    # The pattern sits in a message, not at a write position. If this blocks,
    # the fix has become a false-alarm generator.
    return _free("git commit -m 'describes setting*.json as an example'",
                 "a pattern quoted in prose")


def check_pattern_as_search_term_stays_free():
    return _free("grep -rn 'setting\\*' /tmp/notes.txt",
                 "a pattern used as a search term")


# --- controls: without these the list proves nothing ----------------------

def check_literal_settings_still_blocked():
    # If this one goes free, the hook is not running at all and every "free"
    # result above is meaningless.
    return _blocked(f"echo x > {HOME}/.claude/settings.json",
                    "the literal spelling must still block")


def check_literal_hooks_still_blocked():
    return _blocked(f"rm -rf {HOME}/.claude/hooks",
                    "the literal hook directory must still block")


def check_harmless_command_still_free():
    return _free("echo hello world", "a harmless command stays free")


def check_short_pattern_does_not_crash():
    # A pattern with FEWER components than the protected path once ran past the
    # end of the pattern and raised IndexError. The hook catches that
    # fail-closed and blocks — but then it blocks by stumbling, not by judging,
    # and a test that only asks "blocked?" stays green while doing so.
    with tempfile.TemporaryDirectory() as d:
        rules = Path(d) / "rules.json"
        rules.write_text(json.dumps(RULES), encoding="utf-8")
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = str(rules)
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = str(Path(d) / "no-overrides")
        env["CLAUDE_AUDIT_DIR"] = str(Path(d) / "audit")
        env["CLAUDE_HOOK_DEV_FLAG"] = str(Path(d) / "no-dev-mode")
        payload = json.dumps({
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /home/*"},
            "cwd": HOME,
            "session_id": "glob-tests",
        })
        p = subprocess.run([sys.executable, str(HOOK)], input=payload,
                           capture_output=True, text=True, env=env)
        out = p.stdout + p.stderr
        stumbled = ("Traceback" in out or "IndexError" in out
                    or "guard error" in out.lower())
        return not stumbled, f"the guard stumbled instead of judging: {out[:200]}"


CASES = [
    ("settings via asterisk", check_settings_via_asterisk),
    ("settings via question mark", check_settings_via_question_mark),
    ("settings via character class", check_settings_via_character_class),
    ("hook directory via asterisk", check_hooks_dir_via_asterisk),
    ("extension cut short", check_extension_cut_short),
    ("truncate via asterisk", check_truncate_via_asterisk),
    ("override directory via asterisk", check_override_dir_via_asterisk),
    ("tilde form", check_tilde_form),
    ("glob in the middle of the path", check_glob_in_the_middle),
    ("inline one-liner with glob", check_inline_one_liner_with_glob),
    ("copying fonts stays free", check_copying_fonts_stays_free),
    ("reading migrations stays free", check_reading_migrations_stays_free),
    ("copying json stays free", check_copying_json_stays_free),
    ("listing hooks stays free", check_listing_hooks_stays_free),
    ("grep in hooks stays free", check_grep_in_hooks_stays_free),
    ("scratch glob stays free", check_scratch_glob_stays_free),
    ("scratch write stays free", check_scratch_write_stays_free),
    ("pattern in prose stays free", check_pattern_in_prose_stays_free),
    ("pattern as search term stays free", check_pattern_as_search_term_stays_free),
    ("literal settings still blocked", check_literal_settings_still_blocked),
    ("literal hooks still blocked", check_literal_hooks_still_blocked),
    ("harmless command still free", check_harmless_command_still_free),
    ("short pattern does not crash", check_short_pattern_does_not_crash),
]

try:
    import pytest

    @pytest.mark.parametrize("name,fn", CASES)
    def test_glob_in_protected_paths(name, fn):
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
