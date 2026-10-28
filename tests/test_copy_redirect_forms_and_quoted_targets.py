# ============================================================================
# Two ways past the write guard that needed no tool, no encoding, no override.
#
# 1. A REDIRECT OF ANOTHER SHAPE behind a copy. Source and target of `cp` and
#    `install` are told apart by position: the last word is the target. A
#    redirect that is not a plain `>` put something else in last place --
#
#      cp /tmp/a ~/.claude/settings.json < /dev/null      /dev/null "is the target"
#      cp /tmp/a ~/.claude/settings.json &>/tmp/log       a stray `&` is
#      cp /tmp/a ~/.claude/settings.json >| /tmp/log      the line is cut at `|`
#      cp /tmp/a ~/.claude/settings.json <<< x            x is
#
#    -- and the real target slid into the source role, which counts as a read.
#    The `>` family had been closed on 2026-08-21; input redirects, `&>`, `>|`
#    and here-strings were not. Measured 2026-10-27 against a byte-identical
#    copy of release 2026.10.24: all of them ran free, onto the settings, the
#    hook files, the shell startup file, authorized_keys, project-local control
#    files and every entry of blocked_paths_write.
#
# 2. QUOTES AND BACKSLASHES INSIDE A PROTECTED NAME. The shell removes them
#    before the command runs; the guard compared the text with them still in:
#
#      echo x > ~/.claude/"settings".json
#      echo x > ~/.claude/sett\ings.json
#
#    A directory entry such as /etc happened to survive this (the quote sits
#    behind the matched prefix), a single protected FILE did not. Documented as
#    open in test_shell_expansion_self_protect.py since 2026-08-27 -- in a public
#    repository, with the two commands spelled out.
#
# The fix for both sits in the one function every write check goes through
# (_write_target_text): redirects of every shape are taken out before the
# position rule picks the target, and the target text is ALSO compared with
# quotes and backslashes removed. "Also" is the important word: the original
# spelling is still checked, so the change can only add refusals, never remove
# one. The counter-cases below hold the price of that at zero for ordinary work.
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
HOOK_FILE = f"{HOME}/.claude/hooks/command-guard.py"
STARTUP = f"{HOME}/.bashrc"
KEYS = f"{HOME}/.ssh/authorized_keys"
PROJECT = "/tmp/some-project"

REDIRECTS = [
    ("input from /dev/null", "< /dev/null"),
    ("input without a blank", "</dev/null"),
    ("output and input", "> /tmp/log < /dev/null"),
    ("both streams", "&>/tmp/log"),
    ("both streams appended", "&>>/tmp/log"),
    ("clobber", ">| /tmp/log"),
    ("here-string", "<<< x"),
    ("here-string with a quoted blank", '<<< "a b"'),
    ("descriptor duplication", "2>&1"),
    ("background", "&"),
]

TARGETS = [
    ("settings", SETTINGS),
    ("settings, tilde form", "~/.claude/settings.json"),
    ("hook file", HOOK_FILE),
    ("shell startup file", STARTUP),
    ("authorized keys", KEYS),
    ("project-local settings", f"{PROJECT}/.claude/settings.json"),
    ("project-local mcp file", f"{PROJECT}/.mcp.json"),
    ("blocked_paths_write entry", "/etc/fstab"),
]

# (id, command, must_block)
CASES = [
    (f"{verb} to {tname}, {rname}", f"{verb} /tmp/a {target} {redirect}", True)
    for verb in ("cp", "install")
    for tname, target in TARGETS
    for rname, redirect in REDIRECTS
]

CASES += [
    # --- controls: without a redirect it was always refused ----------------
    ("cp plain", f"cp /tmp/a {SETTINGS}", True),
    ("cp plain onto a startup file", f"cp /tmp/a {STARTUP}", True),

    # --- the clobber redirect pointing AT the protected file -----------------
    # Not behind a copy -- the redirect itself. `>|` was cut at its `|` as if it
    # were a pipe, and the redirect pattern did not know the form, so the
    # target stood alone in a "segment" that writes nothing. Found while
    # measuring the fix above, open in release 2026.10.24 as well.
    ("clobber onto the settings", f"echo x >| {SETTINGS}", True),
    ("clobber with a descriptor", f"echo x 1>| {SETTINGS}", True),
    ("clobber without a blank", f"echo x >|{SETTINGS}", True),
    ("clobber behind a copy", f"cp /tmp/a /tmp/b >| {SETTINGS}", True),
    ("clobber onto a hook file", f"echo x >| {HOOK_FILE}", True),
    ("clobber onto project-local settings", f"echo x >| {PROJECT}/.claude/settings.json", True),
    ("clobber onto a blocked path", "echo x >| /etc/fstab", True),
    ("clobber into scratch stays free", "echo x >| /tmp/log", False),
    ("clobber, then a real pipe", "echo x >| /tmp/log | cat", False),
    # With `>` a protected file in front of the arrow is only read; `>|` must
    # behave the same, or a checksum into the scratch area is refused.
    ("checksum of the settings, clobbered into scratch",
     f"sha256sum {SETTINGS} >| /tmp/sum.txt", False),

    # --- quotes and backslashes in a protected name -------------------------
    ("quoted file name", f'echo x > {HOME}/.claude/"settings.json"', True),
    ("quoted part of the name", f'echo x > {HOME}/.claude/"settings".json', True),
    ("single-quoted part", f"echo x > {HOME}/.claude/'sett'ings.json", True),
    ("backslash in the name", f"echo x > {HOME}/.claude/sett\\ings.json", True),
    ("tilde form, quoted name", 'echo x > ~/.claude/"settings.json"', True),
    ("quoted hook file", f'echo x > {HOME}/.claude/hooks/"command-guard".py', True),
    ("quoted startup file", f'echo x > {HOME}/."bashrc"', True),
    ("quoted with tee", f"echo x | tee {HOME}/.claude/'settings'.json", True),
    ("quoted with cp", f'cp /tmp/a {HOME}/.claude/"settings".json', True),
    ("quoted with mv", f'mv /tmp/a {HOME}/.claude/"settings".json', True),
    ("quoted with a redirect form", f'cp /tmp/a {HOME}/.claude/"settings".json < /dev/null', True),
    ("quoted project-local file", f'echo x > {PROJECT}/.claude/"settings".json', True),
    ("backslash project-local file", f"echo x > {PROJECT}/.m\\cp.json", True),
    ("quoted file under a blocked path", 'echo x > /etc/"fstab"', True),

    # --- counter-cases: ordinary work must stay free ------------------------
    # Copying FROM a protected path is reading -- whatever redirect follows.
    ("copy from the settings, input redirect", f"cp {SETTINGS} /tmp/backup < /dev/null", False),
    ("copy from the settings, both streams", f"cp {SETTINGS} /tmp/backup &>/tmp/log", False),
    ("copy from the hook file, clobber", f"cp {HOOK_FILE} /tmp/copy.py >| /tmp/log", False),
    ("copy between scratch files, input", "cp /tmp/a /tmp/b < /dev/null", False),
    ("copy between scratch files, here-string", "cp /tmp/a /tmp/b <<< x", False),
    ("copy between scratch files, both streams", "cp /tmp/a /tmp/b &>/tmp/log", False),
    ("copy between scratch files, background", "cp /tmp/a /tmp/b &", False),
    ("install into scratch, input", "install -m 644 /tmp/a /tmp/b < /dev/null", False),
    ("quoted scratch target with a blank", 'cp /tmp/a "/tmp/x y/z"', False),
    ("quoted scratch redirect", 'echo "hello world" > "/tmp/my notes.txt"', False),
    ("backslash in a scratch name", "echo x > /tmp/my\\ notes.txt", False),
    ("quoted neighbour is not the path", f'echo x > {HOME}/.claude/"settings.json.bak"', False),
    ("reading a quoted protected name", f'cat {HOME}/.claude/"settings".json', False),
    ("grep for a quoted protected name", f'grep -c x {HOME}/.claude/"settings".json', False),
    ("mentioning the name in text", 'echo "see ~/.claude/settings.json"', False),
]


def _make_rules() -> str:
    rules = json.loads(EXAMPLE_RULES.read_text(encoding="utf-8"))
    tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    json.dump(rules, tf)
    tf.close()
    return tf.name


def _run(command: str, rules_path: str) -> int:
    payload = {"tool_name": "Bash", "tool_input": {"command": command},
               "session_id": "copy-redirect-quotes-test", "hook_event_name": "PreToolUse"}
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
    def test_copy_redirect_forms_and_quoted_targets(cid, command, must_block):
        assert _run(command, _RULES) == (BLOCK if must_block else ALLOW), cid

except ImportError:
    pass


if __name__ == "__main__":
    res = run_all()
    fails = [r for r in res if not r[3]]
    for cid, must_block, rc, ok in fails:
        exp = "block" if must_block else "allow"
        got = "block" if rc == BLOCK else ("allow" if rc == ALLOW else f"rc={rc}")
        print(f"FAIL  {cid:60s} exp={exp:5s} got={got}")
    passed = len(res) - len(fails)
    print(f"\nCopy redirect forms and quoted targets: {passed}/{len(res)} passed  "
          f"(hook: {HOOK})")
    raise SystemExit(0 if not fails else 1)
