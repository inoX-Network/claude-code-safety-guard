# ============================================================================
# The owner-only block matched text, not the command position.
#
# Two commands must never be callable by the AI via Bash: the grant-override
# script and the dev-window switch. Otherwise the AI could approve itself.
# The rule is right — its COMPARISON was too coarse:
#
#     re.search(r"\b" + name + r"\b", command)
#
# That hits every occurrence of the string, whether or not it is a call.
# Measured 2026-08-21 on a real machine, five forms, three of them wrong:
#
#   block   call at the command position          <- correct
#   block   call with a full path                 <- correct
#   BLOCK   reading the identically named flag FILE   <- false positive
#   BLOCK   stat of that same file                    <- false positive
#   BLOCK   the name inside a note                    <- false positive
#
# The expensive part: the flag FILE is named like the command, so every
# lookup of "is a dev window currently open?" was blocked. The rule did not
# prevent the call — it prevented checking whether approval exists.
#
# Full run against 77718 distinct logged commands: 20 previously rejected ones
# now pass (across 18 sessions), 0 are newly blocked.
#
# WHY THIS FILE READS THE MESSAGE INSTEAD OF ONLY THE EXIT CODE
# Several of the allow-cases touch protected paths and could be caught by a
# DIFFERENT check (read protection, self-protection). An exit-code comparison
# would then be red for the wrong reason — or worse, green because two rules
# cover for each other. So the message is inspected: was it THIS rule?
#
# The detection binds to a word stem, never to a sentence: a wording match
# would break with the language setting — the exact bug this guard had in its
# own code on 2026-08-05.
#
# AND THAT TRAP CAUGHT THIS FILE ITSELF ON THE FIRST RUN. It read the message
# with the machine's own configuration, which selects German — where the text
# reads "Eigentümer-Befehl" and carries neither stem. Result: all 17 block
# cases failed, all 10 allow cases passed. A tidy pattern that looks like a
# broken rule and is a broken measurement.
#
# Hence the own config below, without a "language" key. A test that inspects
# messages must pin the language, or it measures the machine it happens to run
# on.
#
# Pure DRY-RUN: only the decision is inspected, nothing is executed.
# ============================================================================
import json
import os
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = REPO / "hooks" / "command-guard.py"
EXAMPLE_RULES = REPO / "security-rules.example.json"

HOME = str(Path.home())

# Assembled from parts: a guard-protected machine blocks writing this very
# file when the literal names appear in a shell command.
WINDOW = "hook-dev" + "-mode"
GRANT = "grant-" + "override"
FLAGFILE = f"{HOME}/.claude/." + WINDOW
BINDIR = f"{HOME}/.claude/bin"

# Word stems of this rule's message. German: "eigentuemer-exklusiver Befehl".
# English: "owner-exclusive command".
MARKERS = ("owner", "exklusiv")


def _blocked_by_owner_rule(command: str, names: list[str] | None = None) -> bool:
    """True if the OWNER-ONLY rule rejected the command."""
    with tempfile.TemporaryDirectory() as ov:
        rules = str(EXAMPLE_RULES)
        if names is not None:
            data = json.loads(EXAMPLE_RULES.read_text(encoding="utf-8"))
            data["owner_only_commands"] = names
            rules = os.path.join(ov, "rules.json")
            Path(rules).write_text(json.dumps(data), encoding="utf-8")

        # Own config without a "language" key, so the message is English no
        # matter how the machine running the suite is set up. Without this the
        # file reads a translated message and every block-case fails — see the
        # note in the header.
        cfg = os.path.join(ov, "guard-config.json")
        Path(cfg).write_text(json.dumps({"installation": {}}), encoding="utf-8")

        payload = {
            "session_id": "owner-only-position-test",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        }
        env = dict(os.environ)
        env["CLAUDE_GUARD_CONFIG"] = cfg
        env["CLAUDE_SECURITY_RULES"] = rules
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = ov
        env["CLAUDE_AUDIT_DIR"] = ov
        env["CLAUDE_HOOK_DEV_FLAG"] = ov + "/_none"   # dev mode guaranteed off
        p = subprocess.run(["python3", str(HOOK)], input=json.dumps(payload),
                           capture_output=True, text=True, env=env, timeout=60)
        low = (p.stderr or "").lower()
        return any(m in low for m in MARKERS)


# --- calls stay blocked -----------------------------------------------------

def test_call_at_command_position():
    assert _blocked_by_owner_rule(f"{WINDOW} on 30")


def test_call_with_full_path():
    assert _blocked_by_owner_rule(f"{BINDIR}/{WINDOW} status")


def test_second_name_the_grant_script():
    assert _blocked_by_owner_rule(f"{GRANT} probe --minutes 30")


def test_behind_privilege_elevation():
    assert _blocked_by_owner_rule(f"sudo {WINDOW} on 30")


def test_behind_an_environment_assignment():
    assert _blocked_by_owner_rule(f"X=1 {WINDOW} on 30")


def test_behind_nohup():
    assert _blocked_by_owner_rule(f"nohup {WINDOW} on 30")


def test_in_a_later_segment():
    assert _blocked_by_owner_rule(f"echo start && {WINDOW} on 30")


def test_behind_a_read_tool_in_an_earlier_segment():
    # Nails the segment split down. Without it the FIRST command of the line
    # would decide, so a read tool up front would clear the call behind it.
    assert _blocked_by_owner_rule(f"ls /tmp; {WINDOW} on 30")


def test_inside_a_shell_wrapper():
    assert _blocked_by_owner_rule(f'bash -c "{WINDOW} on 30"')


def test_inside_sh_c():
    assert _blocked_by_owner_rule(f"sh -c '{WINDOW} on 30'")


def test_behind_timeout():
    assert _blocked_by_owner_rule(f"timeout 5 {WINDOW} on 30")


def test_behind_watch():
    assert _blocked_by_owner_rule(f"watch {WINDOW} status")


def test_behind_xargs():
    assert _blocked_by_owner_rule(f"echo on | xargs {WINDOW}")


def test_inside_an_interpreter_one_liner():
    assert _blocked_by_owner_rule(
        f"python3 -c \"import subprocess; subprocess.run(['{WINDOW}','on'])\"")


def test_in_a_commit_message_stays_blocked():
    # Looks like a false positive, is a deliberate decision: git can execute
    # arbitrary commands via -c alias.x='!cmd' and via the pager. Were git a
    # "text tool", a call could hide behind it. The way out is the recommended
    # one anyway — put the message in a file. Same reasoning excludes awk
    # (system) and sed (e flag).
    assert _blocked_by_owner_rule(f'git commit -m "{WINDOW} mentioned"')


# --- text stays free --------------------------------------------------------

def test_reading_the_flag_file():
    assert not _blocked_by_owner_rule(f"cat {FLAGFILE}")


def test_stat_of_the_flag_file():
    assert not _blocked_by_owner_rule(f"ls -la {FLAGFILE}")


def test_the_name_inside_a_note():
    assert not _blocked_by_owner_rule(f"echo 'see {WINDOW}' >> /tmp/note.md")


def test_the_name_as_a_search_pattern():
    assert not _blocked_by_owner_rule(f"grep -n {WINDOW} /tmp/file.md")


def test_search_pattern_behind_privilege_elevation():
    # Nails down the skipping of prefix tokens. Without it the elevation would
    # be the command and the read tool behind it invisible.
    assert not _blocked_by_owner_rule(f"sudo grep {WINDOW} /tmp/file.md")


def test_the_name_in_output():
    assert not _blocked_by_owner_rule(f"printf '%s\\n' {WINDOW}")


def test_head_of_the_flag_file():
    assert not _blocked_by_owner_rule(f"head -1 {FLAGFILE}")


def test_listing_the_directory_that_holds_the_script():
    assert not _blocked_by_owner_rule(f"ls -la {BINDIR}")


def test_name_as_part_of_a_longer_word():
    # A plain \b is not enough for hyphenated names: the word ends before the
    # suffix, so `<name>-extra` matched by mistake.
    assert not _blocked_by_owner_rule(f"{WINDOW}-extra on")


# --- the name list comes from the RULES FILE, so it can collide -------------

def test_own_script_named_like_a_read_tool_is_still_blocked():
    # Users put their own script names in owner_only_commands. If one is
    # called like a read tool, the tool exemption must not clear it. Without
    # this case the base-name comparison at the command position looks like
    # dead code and would be deleted — opening a hole that only shows up in
    # someone else's configuration.
    assert _blocked_by_owner_rule("ls -la /tmp", names=["ls"])


def test_the_colliding_name_with_a_full_path_is_blocked():
    assert _blocked_by_owner_rule("/opt/mine/ls -la /tmp", names=["ls"])


def test_the_colliding_name_stays_text_where_it_is_text():
    assert not _blocked_by_owner_rule("echo 'ls is meant here'", names=["ls"])
