# ============================================================================
# The shell rewrites the command AFTER the guard has read it.
#
# Self-protection compares paths. The shell assembles paths. Between those two
# facts sits a hole that needs no tool, no encoding and no override:
#
#   echo x > ~/.claude/set''tings.json     the shell drops '' -> settings.json
#   echo x > ~/.claude/{settings,x}.json   the shell expands the brace list
#
# Measured 2026-08-25 against a byte-identical copy of the live hook: the plain
# spelling was refused, both of these went through -- onto the file the guard is
# built to defend above all others, its own settings.
#
# THE LINE THIS FILE DEFENDS. Only rewrites whose result depends on the STRING
# are undone ahead of the check: IFS splitting, empty quote pairs, brace lists.
# Globbing is deliberately NOT expanded -- its result depends on the filesystem,
# so expanding it would make the verdict depend on what happens to exist. A
# pattern is instead held against the protected list unexpanded, which is a
# separate mechanism with its own file.
#
# The counter-cases matter as much as the blocks. Empty quotes and brace lists
# are ordinary shell in ordinary work (`cp a.{txt,md} dir/`), so a rule that
# treats their presence as suspicious would fire all day and be switched off.
# What is refused here is a protected path, however it was spelled -- never the
# spelling itself.
#
# WHAT THIS DOES NOT CLOSE, measured rather than assumed. The shell also
# removes NON-empty quotes and backslashes, and those spellings still reach a
# protected path:
#
#   echo x > ~/.claude/"settings".json      still allowed
#   echo x > ~/.claude/set\tings.json       still allowed
#
# Both behave identically before and after this change, so they are not a
# regression -- they are the next class in the same family, and they need a
# different answer: removing them is not state-free in the same simple way
# (a quote can span words, a backslash can escape a separator), so it is not
# a two-line addition here. Deliberately NOT asserted as "allowed": a test
# that pins an open hole in place makes closing it look like a regression.
#
# Pure dry run: only decisions are inspected. Nothing is written.
# ============================================================================
import json
import os
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
EXAMPLE_RULES = REPO / "security-rules.example.json"

ALLOW = 0
BLOCK = 2

# The hook resolves the home directory from the password database and ignores
# $HOME on purpose, so the protected paths have to be built the same way.
HOME = str(Path.home())
SETTINGS = f"{HOME}/.claude/settings.json"
HOOKS_DIR = f"{HOME}/.claude/hooks"

# (id, command, must_block)
CASES = [
    # --- controls: the plain spelling was never the problem -----------------
    ("plain redirect", f"echo x > {SETTINGS}", True),
    ("plain hook file", f"echo x > {HOOKS_DIR}/command-guard.py", True),

    # --- empty quote pairs: the shell removes them --------------------------
    ("empty quotes mid-name", f"echo x > {HOME}/.claude/set''tings.json", True),
    ("empty quotes at the end", f'echo x > {HOME}/.claude/settings""' + ".json", True),
    ("double quotes mid-name", f'echo x > {HOME}/.claude/set""tings.json', True),
    ("empty quotes in the directory", f"echo x > {HOME}/.cla''ude/settings.json", True),
    ("empty quotes on the hook directory",
     f"echo x > {HOME}/.cl''aude/hooks/command-guard.py", True),
    ("empty quotes with tee", f"echo x | tee {HOME}/.claude/set''tings.json", True),
    ("empty quotes with mv", f"mv /tmp/a {HOME}/.claude/set''tings.json", True),
    ("empty quotes with cp", f"cp /tmp/a {HOME}/.claude/set''tings.json", True),

    # --- brace lists: the shell expands them --------------------------------
    ("brace list on the file", f"echo x > {HOME}/.claude/{{settings,other}}.json", True),
    ("brace list on the directory", f"echo x > {HOME}/.claude/{{hooks,x}}/f.py", True),
    ("brace list with tee", f"echo x | tee {HOME}/.claude/{{settings,x}}.json", True),
    ("brace list with mv", f"mv /tmp/a {HOME}/.claude/settings.{{json,bak}}", True),
    # Only the FIRST expanded word is a redirect target: `> a b` writes to a and
    # hands b to the command as an argument. So a protected name in second place
    # is not written to, and refusing it would be a false alarm. Measured, not
    # assumed -- this case was written the other way round first.
    ("brace list, protected second, is not the target",
     f"echo x > {HOME}/.claude/{{x,settings}}.json", False),
    # With tee both words ARE written, so there the second place must block.
    ("brace list, protected second, with tee",
     f"echo x | tee {HOME}/.claude/{{x,settings}}.json", True),

    # --- both at once -------------------------------------------------------
    ("quotes and braces together",
     f"echo x > {HOME}/.cla''ude/{{settings,x}}.json", True),

    # --- counter-cases: ordinary shell must stay free -----------------------
    # Without these, a rule that simply distrusts quotes or braces would look
    # perfect here -- and would fire on everyday work until someone removes it.
    ("harmless quotes", "echo 'hello world' > /tmp/probe.txt", False),
    ("harmless empty quotes", "echo x > /tmp/no''tes.txt", False),
    ("harmless brace list", "cp /tmp/a.{txt,md} /tmp/target/", False),
    ("harmless brace on a path", "mkdir -p /tmp/{one,two}/deep", False),
    ("brace without a comma is not a list", "echo ${HOME}/x > /tmp/a.txt", False),
    # Mentioning a protected path in text stays free where nothing is written to
    # it. NOTE: the same sentence WITH a redirect elsewhere in the command is
    # refused today -- a known, pre-existing false alarm of the "text is not an
    # action" family, measured identically before and after this change. It is
    # not asserted here, because a test that pins a false alarm in place makes
    # fixing it look like a regression.
    ("text mentioning the settings file", f"echo 'see {SETTINGS}'", False),
    ("a neighbour is not the path", f"echo x > {HOME}/.claude/settings.json.bak", False),
    ("reading stays free", f"cat {SETTINGS}", False),
    ("grep stays free", f"grep -c x {HOOKS_DIR}/command-guard.py", False),

    # --- the cap: a crafted brace bomb must not hang the guard --------------
    # Over twelve alternatives the word is left alone. That is the position the
    # guard was in before, not a regression -- and it keeps a hostile command
    # from turning expansion into a combinatorial bomb.
    ("oversized brace list is left alone",
     "echo x > /tmp/{a,b,c,d,e,f,g,h,i,j,k,l,m,n}.txt", False),

    # --- JSON is not a brace list ------------------------------------------
    # Found by measurement, not by thinking: against 215,936 logged commands
    # this was the ONE real command the change newly refused. A JSON payload in
    # a variable assignment was expanded into two copies of the surrounding
    # word, which put a second container-tool name where a command name is
    # read. Expansion duplicates text, and duplicated text grows new command
    # positions -- so a data structure must not go through it. `"key":` is the
    # marker that separates the two.
    ("json payload next to a tool call",
     'PARAMS=\'{"product":"series","genre":"scifi"}\' docker ps', False),
    ("json holding a comma-separated value",
     'CONF=\'{"paths":"/home/x,/tmp"}\' echo ok', False),
]


def _make_rules() -> str:
    rules = json.loads(EXAMPLE_RULES.read_text(encoding="utf-8"))
    tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    json.dump(rules, tf)
    tf.close()
    return tf.name


def _run(command: str, rules_path: str) -> int:
    payload = {"tool_name": "Bash", "tool_input": {"command": command},
               "session_id": "shell-expansion-test", "hook_event_name": "PreToolUse"}
    with tempfile.TemporaryDirectory() as ov:
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = rules_path
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = ov
        env["CLAUDE_AUDIT_DIR"] = ov
        env["CLAUDE_HOOK_DEV_FLAG"] = ov + "/_none"
        # Working directory stated, not inherited: a relative target would
        # otherwise be resolved against wherever the suite was started.
        payload["cwd"] = ov
        p = subprocess.run(["python3", str(HOOK)], input=json.dumps(payload),
                           capture_output=True, text=True, env=env, cwd=ov)
        return p.returncode


def run_all():
    rules = _make_rules()
    return [(cid, must_block, rc, rc == (BLOCK if must_block else ALLOW))
            for cid, command, must_block in CASES
            for rc in [_run(command, rules)]]


try:
    import pytest

    _RULES = _make_rules()

    @pytest.mark.parametrize("cid,command,must_block", CASES)
    def test_shell_expansion_self_protect(cid, command, must_block):
        assert _run(command, _RULES) == (BLOCK if must_block else ALLOW), cid

except ImportError:
    pass


if __name__ == "__main__":
    res = run_all()
    fails = [r for r in res if not r[3]]
    for cid, must_block, rc, ok in fails:
        exp = "block" if must_block else "allow"
        got = "block" if rc == BLOCK else ("allow" if rc == ALLOW else f"rc={rc}")
        print(f"FAIL  {cid:44s} exp={exp:5s} got={got}")
    passed = len(res) - len(fails)
    print(f"\nShell expansion vs self-protection: {passed}/{len(res)} passed  "
          f"(hook: {HOOK})")
    raise SystemExit(0 if not fails else 1)
