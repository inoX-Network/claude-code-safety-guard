# ============================================================================
# Recursively deleting the file-system root or the home directory -- in every
# spelling, independent of the rules file.
#
# Measured 2026-09-30 against release 2026.09.29-4 with the example rules: the
# only barrier was the text pattern `rm\s+-rf?\s+/` in blocked_patterns, which
# covers exactly ONE spelling. Without any approval these ran through:
#
#   rm -fr /    rm -r -f /    rm --recursive --force /    rm -R /
#   rm -fr /*   rm -fr /.     rm -fr //    rm -fr -- /    find / -delete
#   echo go; rm -fr /                       (second segment)
#   rm -fr /home/<user>   rm -fr ~   rm -fr $HOME   mv /home/<user> /tmp/x
#   rm -fr /home   rm -fr /usr   rm -fr /etc
#
# The fix is a fixed rule, not a rules-file entry: '/' protects itself and the
# first level below it, '~' protects only itself -- `rm -rf ~/something` is
# everyday work. The root and the home directory stay blocked even with an
# approval; the first level below '/' follows the level like any protected
# path. Every case therefore runs twice more: with the example rules as
# shipped AND with the rm patterns stripped from blocked_patterns, because the
# fixed rule must not lean on them.
#
# Pure dry run: only decisions are inspected. Nothing is deleted.
# ============================================================================
import json
import os
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

try:
    import pwd
    HOME = pwd.getpwuid(os.getuid()).pw_dir     # the guard resolves ~ this way too
except (ImportError, KeyError):                 # pragma: no cover
    HOME = str(Path.home())

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
EXAMPLE_RULES = REPO / "security-rules.example.json"

# (id, command, blocks at level 0, blocks at level 2)
CASES = [
    # --- the root: always blocked, even with an approval --------------------
    ("root -rf (the one spelling that held)", "rm -rf /", True, True),
    ("root -fr", "rm -fr /", True, True),
    ("root -r -f", "rm -r -f /", True, True),
    ("root long form", "rm --recursive --force /", True, True),
    ("root -R", "rm -R /", True, True),
    ("root star", "rm -fr /*", True, True),
    ("root dot", "rm -fr /.", True, True),
    ("root double slash", "rm -fr //", True, True),
    ("root no-preserve", "rm -fr --no-preserve-root /", True, True),
    ("root behind --", "rm -fr -- /", True, True),
    ("root quoted", "rm -fr '/'", True, True),
    # The segment keeps its leading blank after '; ' -- the verb pattern wants
    # the verb at the start, so every delete in a later segment slipped past.
    ("root in the second segment", "echo go; rm -fr /", True, True),
    ("find deletes the root", "find / -delete", True, True),
    # The pipe separates find from its delete, so the check reads the whole line.
    ("find pipes the root into xargs rm", "find / -name x | xargs rm -f", True, True),
    # --- the home directory itself: always blocked --------------------------
    ("home tilde -fr", "rm -fr ~", True, True),
    ("home tilde slash", "rm -r ~/", True, True),
    ("home spelled out", f"rm -rf {HOME}", True, True),
    ("home spelled out -fr", f"rm -fr {HOME}", True, True),
    ("home variable -fr", "rm -fr $HOME", True, True),
    ("home star", f"rm -fr {HOME}/*", True, True),
    ("home moved away", f"mv {HOME} /tmp/away", True, True),
    # --- first level below '/': follows the approval ------------------------
    ("first level /home", "rm -fr /home", True, False),
    ("first level /usr", "rm -fr /usr", True, False),
    ("first level /opt", "rm -rf /opt", True, False),
    ("first level /etc", "rm -fr /etc", True, False),
    # Only here does the long form carry weight: the root itself blocks at
    # depth 0 even without a recursion flag, the first level only WITH one.
    ("first level long form", "rm --recursive /usr", True, False),
    # --- stays free ----------------------------------------------------------
    ("deep throwaway path", "rm -rf /tmp/whatever/x", False, False),
    ("child in home", f"rm -rf {HOME}/Downloads/old", False, False),
    ("child in home via tilde", "rm -rf ~/Downloads/old", False, False),
    # Exactly one level below home: home protects only itself.
    ("first level in home", "rm -rf ~/Downloads", False, False),
    ("relative build dir", "rm -rf ./build", False, False),
    ("single file", "rm file.txt", False, False),
    ("find in the project", "find . -name '*.pyc' -delete", False, False),
    ("rename a file in home", f"mv {HOME}/a.txt {HOME}/b.txt", False, False),
    ("list the root", "ls -la /", False, False),
    # 'find' only lists unless a delete action stands beside it.
    ("find searches the root", "find / -name '*.conf'", False, False),
    ("find lists the first level", "find /usr -maxdepth 1 | head", False, False),
    ("size of /usr", "du -sh /usr", False, False),
]


def _rules_variants(tmp: Path) -> dict:
    """The example rules as shipped, and the same without any rm pattern."""
    rules = json.loads(EXAMPLE_RULES.read_text(encoding="utf-8"))
    rules["blocked_patterns"] = [p for p in rules.get("blocked_patterns", [])
                                 if not p.startswith("rm")]
    stripped = tmp / "without-rm-patterns.json"
    stripped.write_text(json.dumps(rules), encoding="utf-8")
    return {"example": str(EXAMPLE_RULES), "without-rm-patterns": str(stripped)}


def _decide(command: str, rules_path: str, level: int) -> int:
    with tempfile.TemporaryDirectory() as ov:
        if level:
            expires = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
            (Path(ov) / "probe.json").write_text(json.dumps({
                "override_level": level, "task": "root delete test",
                "confirmed": True, "expires_at": expires,
                "grants": {"additional_sudo": [], "allowed_paths": []},
            }), encoding="utf-8")
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = rules_path
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = ov
        env["CLAUDE_AUDIT_DIR"] = ov + "/audit"
        env["CLAUDE_HOOK_DEV_FLAG"] = ov + "/_none"
        payload = {"tool_name": "Bash", "tool_input": {"command": command},
                   "cwd": HOME, "session_id": "root-delete-test",
                   "hook_event_name": "PreToolUse"}
        p = subprocess.run(["python3", str(HOOK)], input=json.dumps(payload),
                           capture_output=True, text=True, env=env)
        return p.returncode


@pytest.fixture(scope="module")
def rules_variants(tmp_path_factory):
    return _rules_variants(tmp_path_factory.mktemp("rules"))


@pytest.mark.parametrize("variant", ["example", "without-rm-patterns"])
@pytest.mark.parametrize("level", [0, 2])
@pytest.mark.parametrize("name,command,blocks0,blocks2", CASES, ids=[c[0] for c in CASES])
def test_root_and_home_delete(name, command, blocks0, blocks2, level, variant,
                              rules_variants):
    expected = blocks0 if level == 0 else blocks2
    blocked = _decide(command, rules_variants[variant], level) != 0
    assert blocked == expected, (
        f"{name!r} at level {level} with {variant} rules: "
        f"expected {'block' if expected else 'allow'}, got {'block' if blocked else 'allow'}")
