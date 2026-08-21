# ============================================================================
# Deleting and writing are not the same thing.
#
# Measured 2026-08-21 on a real machine:
#
#   passes    rm -rf ~/.claude/projects   (806 MB: every memory entry and the
#                                          entire transcript store)
#   BLOCKED   rm -rf ~/.ssh
#
# ~/.ssh is in blocked_paths_write, ~/.claude/projects is not. The naive fix is
# to add it there -- but that costs the maintenance: writing, editing and
# redirecting into a single memory file all get blocked with it, four of four
# paths. A barrier like that gets switched off within the week.
#
# The missing concept is the distinction. "This data is valuable" almost always
# means DON'T THROW IT AWAY, not DON'T TOUCH IT. Hence a second list:
# blocked_paths_delete.
#
# SCOPE: this is deliberately NOT core self-protection. Transcripts and memory
# are user data, not the security system, so the list lives in the rules file
# and may be switched off -- exactly like ~/.ssh and ~/.gnupg. The hardcoded
# self-protection stays reserved for what the guard itself is made of.
#
# Pure dry run: only decisions are inspected. Nothing is written or deleted.
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

PROTECTED = f"{HOME}/.claude/projects"
NEIGHBOUR = f"{HOME}/.claude/projects-something-else"   # similar name, not the same
FILE = f"{PROTECTED}/-hub/memory/entry.md"

# (id, tool, payload text, must block)
CASES = [
    # --- the barrier: destroying commands on the protected place ------------
    ("rm -rf on the directory", "Bash", f"rm -rf {PROTECTED}", True),
    ("rm -r without f", "Bash", f"rm -r {PROTECTED}", True),
    ("rm a single file", "Bash", f"rm {FILE}", True),
    ("rmdir", "Bash", f"rmdir {PROTECTED}", True),
    ("unlink", "Bash", f"unlink {FILE}", True),
    ("shred", "Bash", f"shred -u {FILE}", True),
    ("truncate empties the file", "Bash", f"truncate -s 0 {FILE}", True),
    ("mv takes it away", "Bash", f"mv {PROTECTED} /tmp/elsewhere", True),
    ("mv a single file away", "Bash", f"mv {FILE} /tmp/elsewhere", True),
    ("dd overwrites", "Bash", f"dd if=/dev/zero of={FILE}", True),
    ("find -delete", "Bash", f"find {PROTECTED} -name '*.md' -delete", True),
    ("rm in the second segment", "Bash", f"echo start; rm -rf {PROTECTED}", True),
    ("interpreter one-liner", "Bash",
     f"python3 -c \"import shutil; shutil.rmtree('{PROTECTED}')\"", True),
    ("detour via ..", "Bash", f"rm -rf {HOME}/.claude/sub/../projects", True),

    # --- the other half: maintenance must keep working ----------------------
    # Without these the list only proves a total lockdown -- and this half is
    # precisely why blocked_paths_write does not do the job.
    ("write memory (Write)", "Write", FILE, False),
    ("edit memory (Edit)", "Edit", FILE, False),
    ("edit memory (MultiEdit)", "MultiEdit", FILE, False),
    ("memory via redirect", "Bash", f"echo x > {FILE}", False),
    ("memory via append", "Bash", f"echo x >> {FILE}", False),
    ("memory via tee", "Bash", f"echo x | tee {FILE}", False),
    ("memory via sed -i", "Bash", f"sed -i s/a/b/ {FILE}", False),
    ("create a new file", "Bash", f"touch {PROTECTED}/new.md", False),
    ("create a subdirectory", "Bash", f"mkdir -p {PROTECTED}/-new/memory", False),
    ("copy into it", "Bash", f"cp /tmp/source {FILE}", False),
    ("read", "Bash", f"cat {FILE}", False),
    ("list", "Bash", f"ls -la {PROTECTED}", False),
    ("search", "Bash", f"grep -r pattern {PROTECTED}", False),
    # Copying OUT of the directory is a read, not a delete.
    ("copy out of it", "Bash", f"cp {FILE} /tmp/backup.md", False),

    # --- counter-probes: the neighbour is not protected ----------------------
    ("neighbouring path", "Bash", f"rm -rf {NEIGHBOUR}", False),
    ("throwaway location", "Bash", "rm -rf /tmp/whatever", False),
]

# (id, override level, granted paths, expected) -- level 1 means EXPLICITLY
# NAMED paths, so an empty scope lifts nothing. That is the semantics, not a
# bug; the first version of this test got it wrong.
GATING = [
    ("level 0 blocks", None, None, BLOCK),
    ("level 1 without path scope still blocks", 1, [], BLOCK),
    ("level 1 with matching scope passes", 1, ["~/.claude/projects"], ALLOW),
    ("level 1 with a foreign scope blocks", 1, ["/opt/something"], BLOCK),
]


def _make_rules() -> str:
    rules = json.loads(EXAMPLE_RULES.read_text(encoding="utf-8"))
    rules["blocked_paths_delete"] = ["~/.claude/projects"]
    tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    json.dump(rules, tf)
    tf.close()
    return tf.name


def _run(tool: str, text: str, rules_path: str,
         level: int | None = None, scope: list | None = None) -> int:
    if tool == "Bash":
        payload = {"tool_name": "Bash", "tool_input": {"command": text}}
    elif tool == "MultiEdit":
        payload = {"tool_name": "MultiEdit",
                   "tool_input": {"file_path": text,
                                  "edits": [{"old_string": "a", "new_string": "b"}]}}
    else:
        payload = {"tool_name": tool,
                   "tool_input": {"file_path": text, "content": "x",
                                  "old_string": "a", "new_string": "b"}}
    with tempfile.TemporaryDirectory() as ov:
        if level is not None:
            expires = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
            (Path(ov) / "probe.json").write_text(json.dumps({
                "override_level": level, "task": "delete protection test",
                "confirmed": True, "expires_at": expires,
                "grants": {"additional_sudo": [], "allowed_paths": scope or []},
            }), encoding="utf-8")
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = rules_path
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = ov
        env["CLAUDE_AUDIT_DIR"] = ov
        env["CLAUDE_HOOK_DEV_FLAG"] = ov + "/_none"
        payload.update({"session_id": "delete-protection-test",
                        "hook_event_name": "PreToolUse"})
        p = subprocess.run(["python3", str(HOOK)], input=json.dumps(payload),
                           capture_output=True, text=True, env=env)
        return p.returncode


def _stderr(tool: str, text: str, rules_path: str) -> str:
    """Wie _run, aber liefert die Meldung statt des Codes."""
    payload = {"tool_name": "Bash", "tool_input": {"command": text},
               "session_id": "delete-protection-test", "hook_event_name": "PreToolUse"}
    with tempfile.TemporaryDirectory() as ov:
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = rules_path
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = ov
        env["CLAUDE_AUDIT_DIR"] = ov
        env["CLAUDE_HOOK_DEV_FLAG"] = ov + "/_none"
        p = subprocess.run(["python3", str(HOOK)], input=json.dumps(payload),
                           capture_output=True, text=True, env=env)
        return p.stderr


# The message has to name the right thing. Reusing the write wording would tell
# the user that WRITING is blocked -- while here it is expressly allowed, and
# they would fetch an override they do not need. Found in a live test; the case
# list above cannot see it, because it only reads exit codes.
#
# Checked LANGUAGE-NEUTRALLY: not against a wording, but against the two
# messages being distinguishable at all. A test pinned to English wording
# passes or fails depending on which language pack the installation loads --
# it would measure the catalogue, not the behaviour.
# Die zwei Meldungen muessen UNTERSCHEIDBAR sein -- sonst liest der Anwender
# "Schreibzugriff blockiert", waehrend Schreiben dort erlaubt ist, und holt
# sich eine Freigabe, die er nicht braucht.
#
# Zwei Fallen stecken in diesem Vergleich, beide beim Bauen hineingetappt:
#
#   1. Verschiedene Pfade vergleichen beweist nichts -- die Meldungen ENTHALTEN
#      den Pfad, unterscheiden sich also immer. Der erste Anlauf bestand
#      deshalb auch gegen eine Fassung ohne den Meldungs-Schluessel.
#   2. DENSELBEN Pfad in beide Listen zu setzen geht auch nicht: Der
#      Schreibschutz greift zuerst (absichtlich, damit ein Pfad in beiden
#      Listen die gewohnte Meldung behaelt), die Loeschmeldung erscheint gar
#      nicht.
#
# Also zwei Pfade, und der Pfad wird vor dem Vergleich herausgerechnet.
DELETE_ONLY = f"{HOME}/.claude/projects"
WRITE_ONLY = f"{HOME}/.ssh"


def _normalise(message: str, path: str) -> str:
    """Meldung ohne den Pfad -- damit nur der WORTLAUT verglichen wird."""
    return (message.replace(path, "<PATH>")
                   .replace(path.replace(HOME, "~"), "<PATH>").strip())


def _messages_differ() -> tuple[str, str]:
    rules_path = _make_rules()          # WRITE_ONLY steckt schon in den Beispielregeln
    try:
        delete_msg = _stderr("Bash", f"rm -rf {DELETE_ONLY}", rules_path)
        write_msg = _stderr("Bash", f"echo x > {WRITE_ONLY}/config", rules_path)
    finally:
        try:
            os.unlink(rules_path)
        except OSError:
            pass
    return (_normalise(delete_msg, DELETE_ONLY), _normalise(write_msg, WRITE_ONLY))


def run_all():
    rules = _make_rules()
    results = []
    try:
        for cid, tool, text, must_block in CASES:
            rc = _run(tool, text, rules)
            expected = BLOCK if must_block else ALLOW
            results.append((cid, expected, rc, rc == expected))
        for cid, level, scope, expected in GATING:
            rc = _run("Bash", f"rm -rf {PROTECTED}", rules, level, scope)
            results.append((cid, expected, rc, rc == expected))
        delete_msg, write_msg = _messages_differ()
        for cid, ok in [
            ("delete message differs from write message",
             bool(delete_msg.strip()) and delete_msg.strip() != write_msg.strip()),
            ("delete message mentions the path slot", "<PATH>" in delete_msg),
            ("write message still produced", bool(write_msg.strip())),
        ]:
            results.append((cid, "distinct", "ok" if ok else "same/empty", ok))
    finally:
        try:
            os.unlink(rules)
        except OSError:
            pass
    return results


try:
    import pytest

    _RULES = _make_rules()

    @pytest.mark.parametrize("cid,tool,text,must_block", CASES)
    def test_delete_protection(cid, tool, text, must_block):
        assert _run(tool, text, _RULES) == (BLOCK if must_block else ALLOW), cid

    @pytest.mark.parametrize("cid,level,scope,expected", GATING)
    def test_delete_protection_gating(cid, level, scope, expected):
        assert _run("Bash", f"rm -rf {PROTECTED}", _RULES, level, scope) == expected, cid

    def test_delete_message_is_distinguishable():
        delete_msg, write_msg = _messages_differ()
        assert delete_msg.strip(), "delete produced no message"
        assert write_msg.strip(), "write produced no message"
        assert delete_msg.strip() != write_msg.strip(), (
            "deleting and writing produce the SAME message — the user cannot "
            "tell that writing is still allowed")
        assert "<PATH>" in delete_msg, delete_msg[:150]

except ImportError:
    pass


if __name__ == "__main__":
    res = run_all()
    fails = [r for r in res if not r[3]]
    for cid, expected, rc, ok in fails:
        exp = "allow" if expected == ALLOW else "block"
        got = "allow" if rc == ALLOW else ("block" if rc == BLOCK else f"rc={rc}")
        print(f"FAIL  {cid:44s} exp={exp:5s} got={got}")
    passed = len(res) - len(fails)
    print(f"\nDelete protection: {passed}/{len(res)} passed  (hook: {HOOK})")
    raise SystemExit(0 if not fails else 1)
