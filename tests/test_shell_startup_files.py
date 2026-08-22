# ============================================================================
# The shell's startup files are the ground every command check stands on.
#
# This guard judges the TEXT of a command. What a name means in the shell that
# runs it, the guard cannot see. A function named python3 in a startup file
# turns every later "python3 ..." into something else, while the guard keeps
# reading the harmless text.
#
# Measured on the machine this was found on: the tool chain starts /bin/zsh,
# and every alias and function from ~/.zshrc is defined in it — even though $-
# reports a non-interactive shell. So the file is loaded on every single
# command invocation, and the route is real rather than theoretical.
#
# Cut hard, from the write measurement: six of the seven files had zero writes
# in 2.5 months; ~/.zshrc had twelve, eight of them from a single clean-up
# session. Four remain, the last one four weeks before.
#
# Three directions are checked, not one:
#   1. writing blocks — on every route a shell offers
#   2. READING stays free — otherwise the guard locks you out of diagnosing it
#   3. ordinary files in the home directory stay free
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

# The full startup chains, including links with no measured write. Half a
# chain is an open door.
PROTECTED = [
    "~/.zshenv", "~/.zprofile", "~/.zshrc", "~/.zlogin", "~/.zlogout",
    "~/.bash_profile", "~/.bash_login", "~/.bashrc", "~/.bash_logout",
    "~/.profile",
    "~/.config/fish/config.fish",
    "~/.config/fish/conf.d/own.fish",
]

# Counter-probes. Without these the list only proves a blanket lockdown of the
# home directory, which would be useless.
STAYS_FREE = [
    "~/notes.txt",
    "~/.gitconfig",                        # dotfile, but not a startup file
    "~/.vimrc",                            # an EDITOR's startup file, not the shell's
    "~/Projects/thing/.zshrc",             # same name, but not in the home directory
    "~/Projects/thing/script.sh",
    "~/.config/fish/completions/x.fish",   # completion, not startup code
]


def _make_rules() -> str:
    """Example rules, untouched. The protection must not depend on the rules
    file — one that only the configuration protects can be unprotected by
    editing that configuration."""
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
                "task": "shell startup file test",
                "confirmed": True,
                "expires_at": expires,
                # The home directory is explicitly granted here. Even that must
                # not lift the block.
                "grants": {"additional_sudo": [], "allowed_paths": [HOME]},
            }), encoding="utf-8")
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = rules_path
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = ov
        env["CLAUDE_AUDIT_DIR"] = ov
        env["CLAUDE_HOOK_DEV_FLAG"] = ov + "/_none"
        payload = {"session_id": "shell-startup-test",
                   "hook_event_name": "PreToolUse", **payload}
        p = subprocess.run(["python3", str(HOOK)], input=json.dumps(payload),
                           capture_output=True, text=True, env=env)
        return p.returncode


def _write_routes(path: str):
    d = os.path.dirname(path)
    yield "Write", {"tool_name": "Write",
                    "tool_input": {"file_path": path, "content": "x"}}
    yield "Edit", {"tool_name": "Edit",
                   "tool_input": {"file_path": path,
                                  "old_string": "a", "new_string": "b"}}
    for tag, cmd in [
        ("redirect", f"echo x > {path}"),
        ("append", f"echo x >> {path}"),
        ("tee", f"echo x | tee -a {path}"),
        ("cp", f"cp /tmp/source {path}"),
        ("mv", f"mv /tmp/source {path}"),
        ("sed-i", f"sed -i s/a/b/ {path}"),
        ("touch", f"touch {path}"),
        ("symlink", f"ln -sf /tmp/source {path}"),
        ("python-inline", f"python3 -c \"open('{path}','w').write('x')\""),
        ("heredoc", f"cat > {path} <<EOF\nx\nEOF"),
        ("mkdir-then-write", f"mkdir -p {d} && echo x > {path}"),
    ]:
        yield f"bash:{tag}", {"tool_name": "Bash", "tool_input": {"command": cmd}}


def _read_routes(path: str):
    """Reading MUST stay free. A protection that locks you out of inspecting
    your own shell keeps you from proving a finding — and gets switched off."""
    yield "Read", {"tool_name": "Read", "tool_input": {"file_path": path}}
    for tag, cmd in [
        ("cat", f"cat {path}"),
        ("grep", f"grep -n alias {path}"),
        ("sed-p", f"sed -n '1,20p' {path}"),
        ("wc", f"wc -l {path}"),
        ("backup-outward", f"cp {path} /tmp/backup.bak"),
    ]:
        yield f"bash:{tag}", {"tool_name": "Bash", "tool_input": {"command": cmd}}


def _cases():
    """(id, payload, override_level, expected)"""
    out = []
    for short in PROTECTED:
        path = short.replace("~", HOME)
        for tag, payload in _write_routes(path):
            out.append((f"block|{short}|{tag}", payload, None, BLOCK))
        for tag, payload in _read_routes(path):
            out.append((f"read|{short}|{tag}", payload, None, ALLOW))

    for short in STAYS_FREE:
        path = short.replace("~", HOME)
        for tag, payload in _write_routes(path):
            out.append((f"free|{short}|{tag}", payload, None, ALLOW))

    # No override level lifts it — not even with the home directory granted.
    for level in (1, 3):
        for short in PROTECTED:
            path = short.replace("~", HOME)
            out.append((f"override{level}|{short}|Write",
                        {"tool_name": "Write",
                         "tool_input": {"file_path": path, "content": "x"}},
                        level, BLOCK))

    # Where "backup next to it" stops, so the boundary is recorded rather than
    # surprising: next to a protected FILE it is allowed (the .bak carries a
    # different name and is not a startup file); INTO a protected DIRECTORY it
    # is not, because every target in there is protected.
    out.append(("boundary|backup beside file|free",
                {"tool_name": "Bash",
                 "tool_input": {"command": f"cp {HOME}/.zshrc {HOME}/.zshrc.bak"}},
                None, ALLOW))
    out.append(("boundary|backup into directory|blocks",
                {"tool_name": "Bash",
                 "tool_input": {"command": f"cp {HOME}/.config/fish/conf.d/a.fish "
                                           f"{HOME}/.config/fish/conf.d/a.fish.bak"}},
                None, BLOCK))

    # Detours: the same target, spelled around the corner.
    for tag, path in [
        ("dotdot", f"{HOME}/Projects/../.zshrc"),
        ("double-slash", f"{HOME}//.zshrc"),
        ("dot-segment", f"{HOME}/./.zshenv"),
        ("deep-detour", f"{HOME}/a/b/../../.bashrc"),
    ]:
        out.append((f"detour|{tag}|Write",
                    {"tool_name": "Write", "tool_input": {"file_path": path, "content": "x"}},
                    None, BLOCK))
        out.append((f"detour|{tag}|bash",
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
    def test_shell_startup_files(cid, payload, level, expected):
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
    print(f"\nshell startup files: {passed} of {len(res)} passed")
    raise SystemExit(1 if fails else 0)
