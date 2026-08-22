#!/usr/bin/env python3
"""Command Guard Hook for Claude Code PreToolUse.

Checks tool calls against security-rules.json before they are executed.
Exit 0 = allow, Exit 2 = block.

Part of: claude-code-safety-guard
License: MIT
"""

import json
import os
import re
import shlex
import subprocess
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

try:
    import pwd                      # Unix: home directory from the password database
except ImportError:                 # pragma: no cover — non-Unix
    pwd = None


def _real_home() -> Path:
    """The home directory from the password database, not from the environment.

    `Path.home()` and `~` read the HOME environment variable — and that is
    settable. Every protected path is written as "~/…"; point HOME elsewhere and
    every protected path points elsewhere too. Measured 2026-07-30: with HOME
    redirected, 4 out of 4 tested protections fell away — self-protection, the
    override directory, a write redirect and the read guard.

    The password database cannot be redirected through the environment. If it is
    unavailable, the old path remains as a last resort: a crash here would be
    turned into a denial by the safety net and would stop all work.
    """
    if pwd is not None:
        try:
            return Path(pwd.getpwuid(os.getuid()).pw_dir)
        except (KeyError, OSError):
            pass
    return Path(os.path.expanduser("~"))


_HOME = _real_home()

def expand_path(path: str) -> str:
    """Expand ~ and $HOME/${HOME} to the home directory.

    $HOME/${HOME} are resolved too so a directory/read vector like
    `tar "$HOME/.ssh"` is caught the same as `tar ~/.ssh` — the shell would
    expand it before execution, but the hook sees the literal string first.
    User-defined variables (`D=~/.ssh; ... $D`) stay out of scope (the hook
    does not run a shell), same inherent limit as blocked_patterns.
    """
    home = str(_HOME)
    return path.replace("~", home).replace("${HOME}", home).replace("$HOME", home)


# Where this hook lives in production. When the running file is there, EVERY
# path-determining environment variable is ignored.
#
# Reason (measured 2026-07-30): these variables were meant as test switches, but
# they are switches. Whoever sets one decides which directory the guard reads its
# approvals from, where its rules live, and whether the dev window is open — so
# they can grant themselves any approval, substitute their own rules, or lift
# self-protection. They are reachable through a single line in a shell profile,
# which every new terminal reads; the profiles are writable on every tested path.
#
# A copy elsewhere still honours them. That is necessary because every check here
# runs as a dry run against a copy — and it is harmless: a copy is not the hook
# that gates the tool calls.
_PRODUCTION_HOOK = _HOME / ".claude" / "hooks" / "command-guard.py"


def _is_production() -> bool:
    """Is this file running from its production location? When in doubt: yes."""
    try:
        return Path(__file__).resolve() == _PRODUCTION_HOOK.resolve()
    except OSError:
        return True


_ENV_ALLOWED = not _is_production()


def _env(name: str) -> str | None:
    """Read an environment variable — always None at the production location."""
    return os.environ.get(name) if _ENV_ALLOWED else None


# --------------------------------------------------------------------------
# This installation's own configuration
#
# Everything that depends on the machine — where the rules live, where the real
# hook source sits, where the runtime directories are — does not belong in the
# code. As long as it lives there, every update is a hand-merge, and that is
# exactly how a thousand diverging lines came about in the author's own copy.
#
# The PATH to this file is hardcoded and is the one value that must not be
# configurable: whoever could redirect it would have moved every wall. For the
# same reason the file itself is self-protected (in the builtin list below, not
# through its own contents — a file that can lift its own protection has none).
#
# If it is missing or unreadable, the builtin values apply. Those are the
# stricter choice, never the laxer one.
GUARD_CONFIG_PATH = Path(_env("CLAUDE_GUARD_CONFIG")
                         or _HOME / ".claude" / "guard-config.json")


def _load_config() -> dict:
    """Read this installation's configuration. On any doubt: empty."""
    try:
        data = json.loads(GUARD_CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


_CONFIG = _load_config()
_INSTALLATION = _CONFIG.get("installation") or {}
if not isinstance(_INSTALLATION, dict):
    _INSTALLATION = {}


def _config_path(key: str, default):
    """An installation path from the configuration, else the default.

    An empty or mistyped value falls back to the default rather than to an
    empty path — an empty protected path would be the laxer choice.
    """
    value = _INSTALLATION.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return default


# ---------------------------------------------------------------------------
# Message catalogue
#
# The code carries KEYS, the texts live beside them. English is built in and is
# therefore always available — the hook is a single file that gets copied to its
# place, and a guard that falls silent because a language file did not travel
# with it would be worse than an ugly message.
#
# A different language is a SETTING, not a fork in the code: put
# `lang/<code>.json` next to the hook (or point `installation.lang_dir` at it)
# and set `language` in the configuration. Missing keys fall back to English,
# so a half-translated file still works.
#
# Two failure modes are handled deliberately, because both would otherwise end
# in a refusal without a reason:
#   - key not in the catalogue  -> print the key plus the values
#   - placeholder does not fit  -> same
# A refusal nobody can act on is worse than an ugly one.
_MESSAGES = {
    # --- the guard itself ---
    "guard.unreadable_input": (
        "BLOCKED (guard failure): the input could not be read ({error}) — the "
        "guard was unable to check anything and therefore lets nothing through. "
        "This is not a verdict on the command itself."
    ),
    # --- read protection ---
    "read.env_file": (
        "BLOCKED: {tool} touches the .env file {path} — that requires override "
        "level 1+."
    ),
    "read.protected": "BLOCKED: {reason} (tool: {tool})",
    "read.always_blocked": (
        "{pattern} is never readable — no override lifts this"
    ),
    "read.needs_override": (
        "{access} {pattern} requires override level 1+. Ask the owner for an "
        "override."
    ),
    "read.allowed_by_override": "ACCESS ALLOWED (override level {level}): {path}",
    # --- project-local control files ---
    "control.hard": (
        "BLOCKED: '{what}' steers the tool chain itself — writing it is blocked "
        "at every location. No override lifts this, only the owner via !."
    ),
    "control.gated": (
        "BLOCKED: '{what}' carries instructions for future sessions — writing it "
        "requires override level 1+."
    ),
    # --- self-protection ---
    "self_protect.file": (
        "BLOCKED: self-protection — '{path}' belongs to the security system "
        "({hit}) and may only be changed by the owner via !. No override lifts "
        "this."
    ),
    "self_protect.command": (
        "BLOCKED: self-protection — write access to '{hit}' (security system). "
        "No override possible, only the owner via !."
    ),
    # --- protected paths, level dependent ---
    "path.write_blocked": (
        "BLOCKED: write access (Write/Edit) to protected path '{path}'. {extra}"
        "Needed: {needed}. ESCALATION: agent asks the coordinator → coordinator "
        "decides with the owner about adjusting the override file."
    ),
    # Deleting needs its own wording. Reusing path.write_blocked would tell the
    # user that WRITING is blocked -- while in a blocked_paths_delete directory
    # writing is expressly allowed. Whoever reads that goes and fetches an
    # override they do not need, and the whole point of the second list is lost.
    # Found in a live test, invisible to the test list.
    "path.delete_blocked": (
        "BLOCKED: deleting inside protected path '{path}' — changing and "
        "writing there stay allowed. {extra}"
        "Needed: {needed}. ESCALATION: agent asks the coordinator → coordinator "
        "decides with the owner about adjusting the override file."
    ),
    # --- who is asking, and which approval is in force ---
    # These are BUILDING BLOCKS: they go into other messages. Without them in
    # the catalogue a translated refusal stays half English.
    "who.agent": "Agent {agent}",
    "who.main": "main session",
    "override.none": "{who} has no valid override (level 0).",
    "override.current": "Current override: level {level}.",
    "override.active": (
        "OVERRIDE ACTIVE: level {level} ({label}) — {who} — task \"{task}\" "
        "[{source}]"
    ),
    "override.ambiguous": (
        "command-guard: ambiguous override selection (equal timestamp) -> "
        "fail-closed, no override applied"
    ),
    # --- the rules file ---
    "rules.missing": (
        "WARNING: {path} not found — FALLBACK ruleset active (fail-closed)"
    ),
    "rules.unreadable": (
        "WARNING: {path} unreadable ({error}) — FALLBACK ruleset active"
    ),
    "rules.invalid": "WARNING: {path} empty/invalid — FALLBACK ruleset active",
    # --- MCP tools ---
    "mcp.blocked": "BLOCKED: {reason}",
    "mcp.gated": (
        "MCP tool '{tool}' ({why}) requires override level 1+. {extra}"
        "ESCALATION: the agent asks the coordinator -> the coordinator decides "
        "with the owner about adjusting the override file."
    ),
    "mcp.why_sensitive_server": "server '{server}' is classified as sensitive",
    "mcp.why_not_readonly": "writing or not classified as read-only",
    # --- Bash: patterns, owner-exclusive commands, git, containers ---
    "bash.blocked_pattern": "BLOCKED: dangerous pattern detected: {pattern}",
    "bash.owner_only": (
        "BLOCKED: '{command}' is an owner-exclusive command (approval channel). "
        "The AI cannot run it — only the owner via ! (bypasses the guard). "
        "I can write an override PROPOSAL into the pending directory."
    ),
    "git.force_push": (
        "BLOCKED: force-push to main/master — ALWAYS blocked, no override "
        "possible."
    ),
    "git.safety": "BLOCKED: git-safety violation — pattern: {pattern}.",
    "git.protected_branch": (
        "BLOCKED: commit straight onto '{branch}' — that branch is protected. "
        "Start a branch instead: git switch -c feature/<short-description>"
    ),
    "docker.always_blocked": (
        "BLOCKED: docker — {reason}. ALWAYS blocked (no override); only the "
        "owner via ! may run this."
    ),
    # --- Bash: read path. The reason arrives WITHOUT a verdict of its own, the
    #     frame adds it — otherwise a translated reason doubles the prefix.
    "bash.read_blocked": (
        "BLOCKED: {reason} (Bash read path). {extra}ESCALATION: agent asks the "
        "coordinator → coordinator decides with the owner about adjusting the "
        "override file."
    ),
    "bash.read_blocked_hard": "BLOCKED: {reason} (Bash read path).",
    "read.env_file_inline": (
        "reading a .env file via interpreter inline code requires override "
        "level 1+"
    ),
    "read.env_file_bash": (
        "reading the .env file {path} requires override level 1+"
    ),
    "read.dir_always_blocked": (
        "recursively reading {path} — the directory contains a never-readable "
        "file. No override lifts this."
    ),
    "read.dir_credentials": (
        "recursively reading {path} (contains protected credentials) requires "
        "override level 1+"
    ),
    # --- Bash: escalation, lifecycle, injection ---
    "sudo.disallowed": (
        "BLOCKED: sudo with a disallowed command: '{command}'. {extra}Needed: "
        "level 2 OR an additional_sudo grant for '{command}'. ESCALATION: agent "
        "asks the coordinator → coordinator decides with the owner about "
        "adjusting the override file."
    ),
    "lifecycle.needs_override": (
        "BLOCKED: '{command}' changes or tears down and requires override "
        "level 1+. Read-only forms (ps, logs, inspect, exec, run, build) run "
        "without an approval. ESCALATION: the agent writes an override proposal "
        "into the pending directory and asks the owner to approve it."
    ),
    "injection.warning": (
        "WARNING: possible prompt injection detected: {keywords}"
    ),
    "guard.stumbled": (
        "BLOCKED (guard failure): the check aborted with an unexpected error — "
        "{error}: {detail}. The command was NOT allowed. This is not a verdict "
        "on the command itself, it is a bug in the guard."
    ),
}


def _load_language() -> dict:
    """Texts for the configured language, or an empty mapping.

    Never raises: a broken language file must not be able to stop the guard.
    """
    code = _CONFIG.get("language")
    if not isinstance(code, str) or not code.strip() or code.strip().lower() == "en":
        return {}
    code = code.strip().lower()
    if not re.fullmatch(r"[a-z]{2}(-[a-z]{2})?", code):
        return {}                                  # no path fragments as a name
    candidates = []
    configured = _INSTALLATION.get("lang_dir")
    if isinstance(configured, str) and configured.strip():
        candidates.append(Path(expand_path(configured.strip())) / f"{code}.json")
    try:
        candidates.append(Path(__file__).resolve().parent / "lang" / f"{code}.json")
    except OSError:
        pass
    for p in candidates:
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, ValueError):
            continue
        if isinstance(data, dict):
            return {k: v for k, v in data.items() if isinstance(v, str)}
    return {}


_LANGUAGE = _load_language()


def msg(key: str, **values) -> str:
    """The text for `key`, filled with `values`.

    Order: configured language, then the built-in English, then the key itself.
    """
    text = _LANGUAGE.get(key) or _MESSAGES.get(key)
    if text is None:
        return _msg_fallback(key, values, "no text for this key")
    try:
        return text.format(**values)
    except (KeyError, IndexError, ValueError):
        return _msg_fallback(key, values, "message text does not fit its values")


def _msg_fallback(key: str, values: dict, why: str) -> str:
    """Last resort: name the key and the values, so a refusal stays actionable."""
    detail = " ".join(f"{k}={v}" for k, v in values.items())
    return f"BLOCKED [{key}] ({why}) {detail}".rstrip()


def _who(agent_id: str | None) -> str:
    """Who is asking: a named agent, or the main session."""
    return msg("who.agent", agent=agent_id) if agent_id else msg("who.main")


def _override_note(override: dict | None, level: int, agent_id: str | None) -> str:
    """Which approval is in force — a sentence that slots into a refusal.

    The trailing blank belongs to the joint, not to the text: a language file
    must not have to carry an invisible space at the end of a line.
    """
    if not override:
        return msg("override.none", who=_who(agent_id)) + " "
    return msg("override.current", level=level) + " "


# Path to the security rules file.
# Override with CLAUDE_SECURITY_RULES — outside the production location only.
RULES_PATH = Path(
    _env("CLAUDE_SECURITY_RULES")
    or expand_path(str(_config_path(
        "rules", _HOME / ".claude" / "safety-guard" / "security-rules.json")))
)

# Self-protection of the security system: these paths must NEVER be written by
# AI tool calls (Bash AND Write/Edit). NO override lifts this — only the owner
# via ! (which bypasses the guard). Deliberately hardcoded (NOT in
# security-rules.json), otherwise the protection list would be modifiable
# through itself (chicken/egg). The pending directory
# (~/.claude/.sudo-overrides-pending) is DELIBERATELY NOT protected — the AI may
# write override proposals there, but only the owner activates them into the
# (protected) active directory.
# The builtin part holds on EVERY installation: these paths look the same
# everywhere because they belong to the tool, not to the machine. They live in
# the code and the configuration can only EXTEND them, never shrink them — so a
# tampered configuration file cannot switch the core off.
_BUILTIN_SELF_PROTECT = [
    "~/.claude/.sudo-overrides",                          # active override directory
    "~/.claude/bin",                                      # approval scripts
    "~/.claude/.hook-dev-mode",                           # dev-mode flag (only owner can set it via !)
    "~/.claude/hooks",                                    # all hooks incl. command-guard symlink
    "~/.claude/settings.json",
    "~/.claude/settings.local.json",
    "~/.claude/CLAUDE.md",
    "~/.claude/rules",                                    # the rules themselves
    "~/.claude/guard-config.json",                        # this installation's own config (see above)
]

# Installation-specific: where THIS machine keeps the real hook source and the
# rules file. Without a configuration the previous defaults still apply, so an
# existing install stays protected even before the file exists.
_DEFAULT_INSTALLATION_PATHS = [
    "~/.claude/safety-guard/security-rules.json",
]


def _installation_self_protect() -> list[str]:
    """The installation-specific self-protected paths from the configuration.

    Those are the install locations worth protecting: the real hook source and
    the rules file. Without a configuration the previous defaults apply — never
    an empty list, which would be the laxer choice.
    """
    from_config = [str(_config_path("hook_source", "")).strip(),
                   str(_config_path("rules", "")).strip()]
    # UNION, not replacement. An earlier version returned the configured paths
    # INSTEAD of the defaults — and a configuration pointing elsewhere then
    # silently unprotected the default location. The public test suite caught
    # it; locally it was invisible because default and configuration named the
    # same paths. Same principle as the builtin list: only ever extend.
    alle = _DEFAULT_INSTALLATION_PATHS + [p for p in from_config if p]
    # Reihenfolge erhalten, Doppelte entfernen
    return list(dict.fromkeys(alle))


# The shell's startup files — the ground every command check stands on.
#
# This guard judges the TEXT of a command. What a name means in the shell that
# actually runs it, the guard cannot see. A single line like
#
#     function python3() { ... }
#
# in a startup file turns every later "python3 ..." into something else, while
# the guard keeps reading the harmless text and lets it through. That is not a
# way around ONE rule; it is the ground under all of them.
#
# MEASURED, not assumed: on the machine this was found on, the tool chain
# starts /bin/zsh, and although $- reports a non-interactive shell, every alias
# and function from ~/.zshrc is defined in it. The file is loaded on every
# single command invocation.
#
# Cut hard, also from measurement (147k audit lines over 2.5 months): six of
# the seven files had ZERO writes. ~/.zshrc had twelve, eight of them from one
# clean-up session (a prompt injection and a key were removed). Four remain
# over 2.5 months, the last one four weeks before. That is not everyday work —
# a hard block here is not hit often enough to get switched off. The owner's
# own `!` bypasses the guard anyway.
#
# The chains are listed IN FULL, including links with no measured write at all.
# Half a chain is an open door: whoever cannot write .zshrc writes .zlogin
# instead. That is the same mistake the read protection and the project-local
# control files already demonstrated — protection anchored to fixed points
# rather than to a rule.
#
# NOT here: the system-wide equivalents (/etc/profile, /etc/zsh/*,
# /etc/profile.d/). Measured: they already block via the system-path guard.
_SHELL_STARTUP_FILES = [
    # zsh
    "~/.zshenv",                    # read by EVERY zsh, non-interactive too
    "~/.zprofile",
    "~/.zshrc",
    "~/.zlogin",
    "~/.zlogout",
    # bash
    "~/.bash_profile",
    "~/.bash_login",
    "~/.bashrc",
    "~/.bash_logout",
    # read by sh and bash
    "~/.profile",
    # fish
    "~/.config/fish/config.fish",
    "~/.config/fish/conf.d",
]

SELF_PROTECT_PATHS = (_BUILTIN_SELF_PROTECT + _SHELL_STARTUP_FILES
                      + _installation_self_protect())

# Project-local control files — a RULE, not a list of places.
#
# The tool chain reads control files out of EVERY project directory, not just
# the home directory. A settings file there grants permissions and registers
# hooks; the hook code next to it runs on every tool call. Protecting only the
# home copies leaves the same power open one directory further along, and every
# new project re-opens it.
#
# The pattern is bound to the .claude DIRECTORY, not to a file name: countless
# foreign projects carry some settings.json, and none of them steers this tool
# chain. The one exception is .mcp.json, whose name IS the tool chain's.
#
# Hard vs. gated follows measured everyday use, not gut feeling: settings, MCP
# wiring and hooks saw zero to three AI writes in two months, so a hard block
# costs nothing. Agents, skills and commands saw a handful — level 1.
#
# A project's own CLAUDE.md is deliberately absent: 70 writes in two months make
# it everyday work, and a block there would be switched off within the week. Its
# counterweight is traceability (version control), not a barrier — see
# THREAT-MODEL.
#
# Hardcoded like _BUILTIN_SELF_PROTECT: a protection that the rules file could
# switch off is no protection.
#
# The same holds one tool chain further along. On a machine that runs a second
# agent CLI beside Claude Code, that CLI's control files are just as much a way
# around this guard -- only crosswise: Claude Code writes, the other CLI
# executes. For opencode the case is not theoretical, because this project
# ships the adapter itself: ~/.config/opencode/plugin/safety-guard.ts is what
# establishes the protection under opencode -- and was freely writable until
# here. One line, and opencode runs unguarded.
#
# The cut follows measured everyday use again (145,104 audit lines, minus this
# project's own test runs):
#   plugin/, plugins/, tools/  ->  5 writes, all from installing the adapter
#       itself. Executable code: hard, like .claude/hooks/.
#   opencode.json / .jsonc     ->  25 writes (setup, pinning, provider swap).
#       Too important to be free (it registers plugins and grants permissions),
#       too frequent to be hard -- a barrier that blocks setup gets switched
#       off. So level 1.
#   agent(s)/, command(s)/, skills/ -> 8 writes. Level 1, like .claude/agents/.
#   AGENTS.md                  ->  9 writes, an instruction file. Stays free,
#       for the same reason as CLAUDE.md: the counterweight is version control,
#       not a barrier.
#
# opencode.json carries no dot-directory and is therefore matched by NAME --
# admissible for the same reason as .mcp.json: the name belongs to the tool
# chain, unlike an everyday name such as settings.json. opencode looks for its
# configuration from the starting directory, so a file of that name is control
# in a subdirectory too.
#
# NOT included: .opencode/bin. What lives there and who writes it could not be
# established from the binary -- a protection on suspicion would be exactly the
# too-broad pattern the paragraph above warns about.
_PROJECT_CONTROL_HARD = [
    (re.compile(r"(?:^|/)\.claude/settings\.json$"), ".claude/settings.json"),
    (re.compile(r"(?:^|/)\.claude/settings\.local\.json$"), ".claude/settings.local.json"),
    (re.compile(r"(?:^|/)\.claude/hooks(?:/|$)"), ".claude/hooks/"),
    (re.compile(r"(?:^|/)\.mcp\.json$"), ".mcp.json"),
    # opencode: executable code of the second tool chain
    (re.compile(r"(?:^|/)(?:\.opencode|\.config/opencode)/plugins?(?:/|$)"),
     ".opencode/plugin/"),
    (re.compile(r"(?:^|/)(?:\.opencode|\.config/opencode)/tools(?:/|$)"),
     ".opencode/tools/"),
    # Antigravity (agy): code execution of the third tool chain.
    # hooks.json is the counterpart to .claude/hooks/ -- the documentation
    # embedded in the binary names "pre-tool execution" as its example.
    # Two locations, because the CLI reads both: config/ is the shared one,
    # antigravity-cli/ the legacy one (still read, per its changelog).
    (re.compile(r"(?:^|/)\.gemini/(?:config|antigravity-cli)/hooks\.json$"),
     "~/.gemini/hooks.json"),
    (re.compile(r"(?:^|/)\.gemini/config/mcp_config\.json$"),
     "~/.gemini/config/mcp_config.json"),
    (re.compile(r"(?:^|/)\.gemini/config/plugins(?:\.json|/|$)"),
     "~/.gemini/config/plugins/"),
    # Per-project permissions -- these take PRECEDENCE over the global
    # setting, so they are the stronger lever of the two.
    (re.compile(r"(?:^|/)\.gemini/config/projects(?:/|$)"),
     "~/.gemini/config/projects/"),
    # config.json carries the list of active plugins ("plugins map keyed by
    # the plugin's directory name"). Writing it enables a plugin that shipped
    # with "disabled": true.
    (re.compile(r"(?:^|/)\.gemini/config/config\.json$"),
     "~/.gemini/config/config.json"),
    (re.compile(r"(?:^|/)\.gemini/antigravity-cli/settings\.json$"),
     "~/.gemini/antigravity-cli/settings.json"),
    (re.compile(r"(?:^|/)\.gemini/(?:settings|trustedFolders)\.json$"),
     "~/.gemini/settings.json"),
    # Workspace-local. FOUR spellings, all four documented:
    # .agents/, .agent/, _agents/, _agent/.
    (re.compile(r"(?:^|/)[._]agents?/hooks\.json$"), ".agents/hooks.json"),
    (re.compile(r"(?:^|/)[._]agents?/mcp_config\.json$"), ".agents/mcp_config.json"),
    (re.compile(r"(?:^|/)[._]agents?/plugins(?:\.json|/|$)"), ".agents/plugins/"),
]
_PROJECT_CONTROL_GATED = [
    (re.compile(r"(?:^|/)\.claude/agents(?:/|$)"), ".claude/agents/"),
    (re.compile(r"(?:^|/)\.claude/skills(?:/|$)"), ".claude/skills/"),
    (re.compile(r"(?:^|/)\.claude/commands(?:/|$)"), ".claude/commands/"),
    # opencode: configuration and instructions of the second tool chain
    (re.compile(r"(?:^|/)opencode\.jsonc?$"), "opencode.json"),
    (re.compile(r"(?:^|/)(?:\.opencode|\.config/opencode)/agents?(?:/|$)"),
     ".opencode/agent/"),
    (re.compile(r"(?:^|/)(?:\.opencode|\.config/opencode)/commands?(?:/|$)"),
     ".opencode/command/"),
    (re.compile(r"(?:^|/)(?:\.opencode|\.config/opencode)/skills(?:/|$)"),
     ".opencode/skills/"),
    # Antigravity: instructions for future runs. They do not execute anything
    # themselves, but they can tell the model to do anything -- so tier 1,
    # like .claude/agents/.
    #
    # Globally ONE pattern is enough: ~/.gemini/config/ is documented as the
    # global customization root ("Global Configuration (Machine-Local)"); no
    # runtime data lives there. This also covers skills/, workflows/ and
    # global_workflows/ -- and whatever a future release puts there. That gap
    # has cost us once already: new version, new files, old pattern.
    (re.compile(r"(?:^|/)\.gemini/config(?:/|$)"), "~/.gemini/config/"),
    # Workspace-local there is deliberately NO such catch-all: .agents/ is
    # also the working directory of the sub-agents (ORIGINAL_REQUEST.md,
    # phase_*_results.json, segment_*/handoff_*.md). A blanket pattern on
    # .agents/ would cripple the CLI -- hence only the named subdirectories,
    # exactly as for .opencode/.
    (re.compile(r"(?:^|/)[._]agents?/skills(?:\.json|/|$)"), ".agents/skills/"),
    (re.compile(r"(?:^|/)[._]agents?/rules(?:/|$)"), ".agents/rules/"),
    (re.compile(r"(?:^|/)[._]agents?/agents(?:/|$)"), ".agents/agents/"),
    (re.compile(r"(?:^|/)[._]agents?/workflows(?:/|$)"), ".agents/workflows/"),
]

# Tools that only ever read. Everything else counts as potentially writing, so a
# tool branch nobody has thought of yet is checked rather than skipped. A false
# positive here is loud and fixable; the opposite would be silent.
_READ_ONLY_TOOLS = frozenset({
    "Read", "Glob", "Grep", "LS", "NotebookRead", "WebFetch", "WebSearch",
})


def project_control_file(file_path: str,
                         extra_bases: list[str] | None = None) -> tuple[str, bool] | None:
    """Return (what was hit, hard) for a project-local control file — else None.

    Works on the lexically normalised path, so detours (../, ./, //) do not walk
    around the pattern. `hard` means no override lifts it.

    Dev mode: the home hook sources stay unlockable, otherwise this rule would
    lock the owner out of the very files the dev window exists for.
    """
    for fp in _norm_path_variants(file_path, extra_bases):
        for rx, what in _PROJECT_CONTROL_HARD:
            if rx.search(fp):
                return None if _dev_unlocked(fp) else (what, True)
        for rx, what in _PROJECT_CONTROL_GATED:
            if rx.search(fp):
                return None if _dev_unlocked(fp) else (what, False)
    return None


def _command_path_tokens(command: str):
    """Every shell token that could be a path. Quotes and shell operators split,
    so an interpreter one-liner (open('.../settings.json','w')) yields the path
    as its own token."""
    return re.findall(r"[^\s'\"|;&<>()]+", command)


# Interpreters and friends: what follows directly is the PROGRAM to run, not a
# write target. Without this exception every invocation of a tool that itself
# lives under a control directory gets blocked -- as soon as any write word
# appears anywhere in the command.
_INTERPRETERS = ("python3", "python", "node", "bash", "sh", "zsh", "perl",
                 "ruby", "uv", "uvx")


def _without_interpreter_program(command: str) -> str:
    """Drop the program path that follows an interpreter."""
    parts = command.split()
    drop = set()
    for i, part in enumerate(parts):
        if part.rsplit("/", 1)[-1] not in _INTERPRETERS:
            continue
        for j in range(i + 1, len(parts)):
            if parts[j].startswith("-"):
                continue                # skip switches
            drop.add(j)                 # first non-switch word is the program
            break
    return " ".join(p for k, p in enumerate(parts) if k not in drop)


def command_hits_project_control(command: str) -> tuple[str, bool] | None:
    """Bash counterpart: a write command aimed at a project-local control file.

    Only on detected write access, so reading one's own configuration stays free.
    A copy SOURCE is not a target — taking a working copy is reading.
    """
    command = _collapse_path_traversal(_normalize_obfuscation(command))

    # Interpreter one-liners carry no shell write indicator. Naming a control
    # file inside -c/-e code is enough: there is no legitimate reason to reach
    # the tool chain's own steering that way.
    cd_bases = _cd_targets(command)
    for block in _inline_code_segments(command):
        for tok in _command_path_tokens(block):
            hit = project_control_file(tok, cd_bases)
            if hit:
                return hit

    cleaned = re.sub(r'\d*>\s*/dev/null', '', command)
    cleaned = re.sub(r'\d*>&\d+', '', cleaned)
    if not _command_is_write(cleaned):
        return None
    # Same segment boundary as in check_blocked_paths and
    # command_hits_self_protect: only writing parts can carry a target.
    cleaned = _join_line_continuations(cleaned)
    writing = [s for s in split_segments(cleaned)
               if _command_is_write(s) or _CD_RE.search(s)]
    if not writing:
        writing = [cleaned]
    for segment in writing:
        segment = _without_interpreter_program(
            _write_target_text(_with_assignments(segment, cleaned)))
        for tok in _command_path_tokens(segment):
            hit = project_control_file(tok, cd_bases)
            if hit:
                return hit
    return None

# Hook development mode (Option B): the owner can lift the self-protection ONLY
# for this subset temporarily, to allow hook changes by the AI under
# supervision. Override directory, settings.json, bin/, CLAUDE.md and rules/
# stay hard-protected EVEN in dev mode — otherwise the AI could write itself
# overrides or approvals while in dev mode.
# The subset follows the same installation-specific paths as above: exactly the
# hook sources, nothing more.
DEV_UNLOCKABLE_PATHS = ["~/.claude/hooks"] + _installation_self_protect()

# Dev-mode flag file. Lives in SELF_PROTECT (see above) — the AI cannot set it
# via Write/Bash, only the owner via !. JSON with mandatory expires_at.
HOOK_DEV_FLAG = _config_path("dev_window", "~/.claude/.hook-dev-mode")

# Write-command detection — shared by check_blocked_paths and
# command_hits_self_protect, so both use the same write-access gate.
#
# Word-boundary matching (not substring): a bare "rm " substring also fires on
# "warm "/"firm " and on path fragments; \b-anchored verbs avoid that. The gate
# is only the FIRST condition — a block still requires a protected path present
# too (see check_blocked_paths), so a stray verb match alone blocks nothing.
# Purely lexical, no filesystem/symlink access (see _norm_path).
_WRITE_VERBS = [
    "rm", "rmdir", "unlink", "shred", "mv", "cp", "touch",
    "chmod", "chown", "mkdir", "ln", "dd", "install", "truncate", "tee",
]
_WRITE_VERB_RE = re.compile(r"\b(?:" + "|".join(_WRITE_VERBS) + r")\b")

# Deleting is not the same as writing, and that distinction was missing.
#
# "This data is valuable" almost always means DON'T THROW IT AWAY, not DON'T
# TOUCH IT. Putting ~/.claude/projects into blocked_paths_write also blocks
# writing a single memory entry -- measured 2026-08-21, four of four
# maintenance paths blocked. Such a barrier gets switched off within the week,
# the same arithmetic that keeps CLAUDE.md free.
#
# Hence a second list, blocked_paths_delete, with its own verb detection. It is
# a RULES entry, not core self-protection: transcripts and memory are user
# data, not the security system itself. What the guard is made of stays in
# _BUILTIN_SELF_PROTECT and cannot be switched off.
#
# `mv` belongs here because nothing remains at the origin -- a move is a delete
# as far as the source is concerned. That needs no special handling: the
# copy-source stripping only touches cp and install, and neither is a delete
# verb. A switch for it was built and a mutation probe exposed it as having no
# effect at all; it was removed again.
_DELETE_VERBS = ["rm", "rmdir", "unlink", "shred", "truncate", "mv", "dd"]
_DELETE_VERB_RE = re.compile(r"\b(?:" + "|".join(_DELETE_VERBS) + r")\b")

# Interpreter forms: a one-liner carries no shell verb but deletes just the
# same. Deliberately coarse -- a false positive here is loud and fixable.
_DELETE_INLINE_RE = re.compile(
    r"\b(?:rmtree|os\.remove|os\.unlink|os\.rmdir|shutil\.rmtree|"
    r"unlink\(|rm\(|removeSync|rmSync|fs\.unlink)")

# Tools that delete only WITH their delete flag. Without it they are harmless,
# and blocking them would be a pure false positive -- the same trade-off
# _command_is_write already makes for find/rsync.
_DELETE_FLAG_RE = re.compile(
    r"\bfind\b[^|;&]*(?:-delete\b|-exec\s+rm\b)"
    r"|\brsync\b[^|;&]*--delete\b"
    r"|\bgit\s+clean\b"
    r"|\bshred\b")


def _command_deletes(command: str) -> bool:
    """Whether the command DESTROYS data (rather than merely changing it).

    Counterpart to _command_is_write. Redirects deliberately do NOT count here:
    `echo x > file` does overwrite, but it is the ordinary maintenance path --
    blocking it blocks the maintenance.
    """
    return bool(_DELETE_VERB_RE.search(command)
                or _DELETE_INLINE_RE.search(command)
                or _DELETE_FLAG_RE.search(command))
# Redirects / in-place edit carry no word boundary — matched as operators.
_WRITE_OPS = [">", ">>", "sed -i"]

# awk runs its first argument as a PROGRAM, not as text. A redirect inside it
# (`print "x" > "/path"`) is a real write — but it sits inside quotes, and the
# operator search below strips quoted sections before looking. Measured
# 2026-08-20: this walked past EVERY protected path, self-protection included,
# while echo/perl/python/tee/dd were all refused there.
#
# Same failure class as the ssh hole fixed earlier: what sits inside the quotes
# is code, not prose.
#
# Why not simply feed the whole line to the operator search (i.e. add awk to
# _SHELL_PASSTHROUGH_RE): awk uses `>` as a COMPARISON too. Measured against
# eight weeks of real commands: of 708 awk calls containing `>`, 688 were
# comparisons (`$1 > 5`, `NR>=2730`) and only 20 were redirects. The blunt fix
# would have cost roughly nine false alarms a day.
#
# The distinction is the TARGET: a redirect writes to a string expression
# (`> "file"`), a comparison sits in front of a number, a field or a variable.
# The `>` must also sit OUTSIDE a string — without that, `awk '{print $2, "->",
# $1}'` reports a write, because in the text "->" a `>` stands right before a
# quote. So string literals are masked first.
_AWK_RE = re.compile(r"\b(?:g|m|n)?awk\b")
_AWK_STRING_RE = re.compile(r'"(?:[^"\\]|\\.)*"')
_AWK_REDIRECT_MASKED_RE = re.compile(r">>?\s*\x00")


def _awk_writes(command: str) -> bool:
    """True when an awk program in this line redirects into a file."""
    if not _AWK_RE.search(command):
        return False
    # Only the awk program matters: the single-quoted argument. A line may
    # carry more than one awk call.
    for program in re.findall(r"'([^']*)'", command):
        if _AWK_REDIRECT_MASKED_RE.search(_AWK_STRING_RE.sub("\x00", program)):
            return True
    return False

# A `>` INSIDE quotes is text, not a redirect: `echo "a -> b"` writes nothing. The
# substring test below did not know that, so any command printing an arrow in a
# MESSAGE while naming a protected path counted as a write — which is exactly what
# harmless one-line diagnostics look like (`echo "$f -> $(jq -r .key "$f")"`). In one
# measured setup this produced roughly 16 denials a day, a good share of them such
# false positives, and it blocked reading the guard's own settings for diagnosis.
#
# DO NOT fix this by exempting `->`. In a shell, `echo x -> file` IS a real redirect
# (`-` is an argument, `> file` the redirection); exempting the arrow would open a
# path to overwriting the hook file itself. The load-bearing difference is the
# quoting, not the dash.
#
# Exception so the relaxation does not become a hole: if the command hands its string
# to a shell (`eval`, `bash -c`), the text is executed after all. Then the old, strict
# check stands — fail-closed when in doubt.
#
# `ssh` belongs in that same exception, and its absence was a hole rather than a
# nicety: `ssh host "echo x > /etc/passwd"` had its quoted section stripped and
# went through, while the far side is exactly where a protected path matters.
# Measured against a copy that already carried it, the difference was one case.
# The price is the same one eval and `sh -c` already pay: a protected path merely
# MENTIONED inside an ssh call now counts. That is the deliberate trade.
_QUOTED_RE = re.compile(r"'[^']*'|\"[^\"]*\"")
_SHELL_PASSTHROUGH_RE = re.compile(r"\beval\b|\bssh\b|\b[a-z]*sh\b[^;|&]*?\s-c\b")


# Copy commands do not modify their SOURCE — they read it. For the write guard
# only the destination counts. `mv`, `rm`, `shred` and `truncate` are
# deliberately absent: those do modify their source.
#
# The read guard is untouched and still inspects the source — copying is
# reading. Mixing those two up turns a false positive into a hole.
_COPY_COMMANDS = ("cp", "install")

# Destination given as an option (`cp -t DEST src…`): then the destination is
# not the last argument, and the position rule would mistake it for a source.
# In that case the whole line is checked, as before.
_DEST_OPTION_RE = re.compile(r"(?:^|\s)(?:-t\b|--target-directory)")


# One split, not six. Every place that cut a command line into segments used to
# carry its own copy of this pattern, and on 2026-08-20 three of the six did not
# know the NEWLINE. The consequences ran in both directions: transfers onto a
# protected server path walked through 39 times because the wrong word sat in
# tokens[0], while copy commands after a line break were refused for the mirror
# reason. Six copies of one rule is how that drift happens; the seventh copy is
# what this function exists to prevent.
#
# `keep` is not convenience. Two callers reassemble the line afterwards and need
# the separators back in the result — a shared helper that could not do both
# would be wrong at the first call site that puts the line together again.
_SEGMENT_RE = re.compile(r"&&|\|\||[;|\n]")
_SEGMENT_KEEP_RE = re.compile(r"(&&|\|\||[;|\n])")


def split_segments(command: str, keep: bool = False) -> list[str]:
    """Cut a command line into the parts a shell would run as separate commands.

    Separators: `&&`, `||`, `;`, `|` and the newline. With `keep=True` the
    separators stay in the result, so the caller can join the parts back into a
    line without losing what sat between them.
    """
    return (_SEGMENT_KEEP_RE if keep else _SEGMENT_RE).split(command)


def _without_copy_sources(command: str) -> str:
    """Drop the source arguments of plain copy commands.

    Returns the command as the write guard should see it: the command, its
    options and the destination. Anything else is returned unchanged — so in
    case of doubt the whole line is still checked.

    Example: `cp -r ~/.config /tmp/x` becomes `cp -r /tmp/x`. The directory is
    only read; the write goes to /tmp.
    """
    parts = split_segments(command, keep=True)
    out = []
    for part in parts:
        tokens = part.split()
        if (len(tokens) >= 3
                and os.path.basename(tokens[0]) in _COPY_COMMANDS
                and not _DEST_OPTION_RE.search(part)):
            options = [t for t in tokens[1:-1] if t.startswith("-")]
            out.append(" " + " ".join([tokens[0]] + options + [tokens[-1]]) + " ")
        else:
            out.append(part)
    return "".join(out)


def _only_copy_sources(command: str) -> str:
    """Counterpart to _without_copy_sources: keeps ONLY the sources.

    For the READ guard the direction is reversed: a copy reads its source, the
    destination comes into being. `cp .env.example .env` therefore reads a
    template — that an environment file is CREATED is not a read.
    """
    parts = split_segments(command, keep=True)
    out = []
    for part in parts:
        tokens = part.split()
        if (len(tokens) >= 3
                and os.path.basename(tokens[0]) in _COPY_COMMANDS
                and not _DEST_OPTION_RE.search(part)):
            out.append(" " + " ".join(tokens[:-1]) + " ")
        else:
            out.append(part)
    return "".join(out)


# `scp`/`rsync` write on the far side without ever naming a redirect or a write
# verb, so the path guard never saw them — and that is the normal deploy path,
# not an edge case. POSITION decides, not occurrence: `host:/path` in LAST place
# is a destination and gets checked; the same shape in front means fetching and
# stays free. A match anywhere in the line would block every read-only fetch.
_REMOTE_DEST_RE = re.compile(r"^[A-Za-z0-9._-]+(?:@[A-Za-z0-9._-]+)?:/\S*$")


_ASSIGNMENT_RE = re.compile(r"(?:^|[\s;&|])([A-Za-z_][A-Za-z_0-9]*)=([^\s;&|]+)")
_VARIABLE_RE = re.compile(r"\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)")


_REDIRECT_TARGET_RE = re.compile(r"\d*>>?(?![&\d])\s*([^\s;&|]+)")


def _write_target_text(segment: str) -> str:
    """The part of a segment that can CARRY a write target.

    A redirect writes exactly where the arrow points. What stands before it is
    read -- unless a real write verb sits there, in which case the front half
    has a target too.

    This closes two things at once, because both hang on the same question:

    A HOLE (measured 2026-08-21): `cp <source> <protected> > log.txt` ran free.
    Source/target separation goes by position, and with a redirect the last
    argument is the log file -- so the protected path slid into the source
    role, i.e. into a read. The redirect is now split off first, which puts the
    copy target back at the end.

    A FALSE POSITIVE: `sha256sum <protected> > /tmp/sum.txt` was refused even
    though only the scratch area is written. With no write verb before the
    arrow, only the redirect target counts.

    Without a redirect NOTHING changes -- that line was missing in the first
    attempt, a cd segment collapsed to an empty string, and two holes closed
    earlier the same day stood open again. The refusal half of a DIFFERENT test
    list caught it.
    """
    targets = " ".join(_REDIRECT_TARGET_RE.findall(segment))
    if not targets:
        return _without_copy_sources(segment)
    before = _REDIRECT_TARGET_RE.sub(" ", segment)
    if _command_is_write(before):
        return _without_copy_sources(before) + " " + targets
    return targets


def _join_line_continuations(command: str) -> str:
    """Turn a continued line back into ONE line.

    A shell joins a line continuation BEFORE it splits anything. Splitting at
    newlines first cuts a single command in two and loses the link between verb
    and target -- measured with a create command whose target sat behind the
    continuation: it ran free as soon as the segment boundary applied.
    """
    return re.sub(r"\\\s*\n", " ", command)


def _with_assignments(segment: str, command: str) -> str:
    """Substitute values from assignments anywhere in the line into a segment.

    An assignment carries the path while the writing segment names only the
    variable. Without substitution the path falls between the segments.

    The assignment is deliberately NOT added to the checked text instead: an
    interpreter path in an assignment next to a write somewhere else would then
    be a false positive. Only where the variable is USED does its value count.
    """
    values = dict(_ASSIGNMENT_RE.findall(command))
    if not values or "$" not in segment:
        return segment

    def substitute(match):
        name = match.group(1) or match.group(2)
        return values.get(name, match.group(0))

    return _VARIABLE_RE.sub(substitute, segment)


def _remote_copy_writes(command: str) -> bool:
    """Whether scp/rsync writes to a remote path (destination = last argument).

    The segment split knows the NEWLINE. Without it, a multi-line command put
    the wrong word in tokens[0] -- `echo` instead of the transfer command -- and
    the check ran into nothing. Measured 2026-08-20: a transfer onto a protected
    server path was refused after `;` and after `&&`, but ran FREE after a
    newline. That is the deploy path this function exists to cover, and the log
    held a real deployment that had walked straight through it.

    The same gap sat in both copy-source helpers, where it worked the other way
    round and produced false alarms: a copy SOURCE counted as a write target as
    soon as any command preceded it on its own line."""
    for segment in split_segments(command):
        tokens = segment.split()
        if len(tokens) < 2:
            continue
        if os.path.basename(tokens[0]) not in ("scp", "rsync"):
            continue
        if _REMOTE_DEST_RE.match(tokens[-1]):
            return True
    return False


def _command_is_write(command: str) -> bool:
    """Whether a command writes/deletes, for the protected-path gate.

    Word-boundary verbs + redirect operators, plus tool-specific delete forms:
    find/rsync count ONLY with their delete flag (a bare find/rsync is read-only
    and would otherwise explode false positives); `git clean` removes files.

    Redirect operators are matched against the line WITHOUT quoted sections (see the
    comment at `_QUOTED_RE`); write VERBS still match against the whole line.
    """
    if _WRITE_VERB_RE.search(command):
        return True
    ops_target = (
        command
        if _SHELL_PASSTHROUGH_RE.search(command)
        else _QUOTED_RE.sub("", command)
    )
    if any(op in ops_target for op in _WRITE_OPS):
        return True
    # awk program text: a redirect onto a string target (see _AWK_RE).
    if _awk_writes(command):
        return True
    if re.search(r"\bfind\b", command) and "-delete" in command:
        return True
    if re.search(r"\brsync\b", command) and "--delete" in command:
        return True
    if re.search(r"\bgit\s+clean\b", command):
        return True
    if _remote_copy_writes(command):
        return True
    return False

# Commands that read a DIRECTORY's contents recursively. Handing one of these a
# directory that CONTAINS protected key files (e.g. `tar ~/.ssh`) exfiltrates
# the keys even though no individual key path is named — check_read_protection
# only matches the key FILES, not their parent dir. Metadata-only commands
# (ls, stat, find, du, file, tree) are DELIBERATELY absent: listing a protected
# directory stays allowed, only reading its contents out is gated. Compared by
# basename, so /usr/bin/tar matches too.
RECURSIVE_READ_CMDS = {
    "tar", "zip", "7z", "7za", "rsync", "scp", "sftp",
    "gpg", "gzip", "bzip2", "xz", "cpio", "pax", "cp",
    "grep", "egrep", "fgrep", "rg", "ag",
}

# `find … -exec CMD` hands every match to a command (see the comment where this
# is used). `-ok`/`-okdir` prompt first but execute just the same.
_FIND_EXEC_RE = re.compile(r"\bfind\b[^|;&]*?\s-(?:exec|execdir|ok|okdir)\b")

# Words that stand IN FRONT of the actual command without being one: escalation
# and environment wrappers. Without skipping them, `sudo tar ~/.ssh` hides its
# reading command behind the first token.
_COMMAND_PREFIXES = {"sudo", "doas", "env", "nice", "ionice", "nohup", "time",
                     "stdbuf", "command", "exec"}


def _recursive_read_targets(command: str) -> list[str]:
    """Paths handed TO a recursive-read command — per segment, not per line.

    A word is not a deed. Asking whether such a command appears ANYWHERE and a
    protected directory appears ANYWHERE refuses this:

        find ~ -maxdepth 4 -name "*.git" | grep -v cache

    The grep filters find's OUTPUT and opens no file. Measured over eight weeks
    of real work: 16 of 16 refusals of this shape were exactly that, not one of
    them read any contents.

    So each segment is asked on its own: does a reading command sit here, and is
    the directory ITS argument? Everything after that command in the same segment
    counts as its argument — which keeps `sudo tar czf x ~/.ssh` caught.
    """
    targets = []
    for segment in split_segments(command):
        tokens = [t.strip("'\"()") for t in segment.split()]
        tokens = [t for t in tokens if t]
        reading = False
        for tok in tokens:
            name = os.path.basename(tok)
            if not reading:
                if name in RECURSIVE_READ_CMDS:
                    reading = True
                elif name == "find" and _FIND_EXEC_RE.search(segment):
                    # `find` is deliberately NOT in RECURSIVE_READ_CMDS: listing a
                    # protected directory stays allowed. With `-exec` it is no
                    # longer listing — every file found is handed to a command,
                    # which reads the search path recursively. Measured
                    # 2026-08-20: `find /etc -name shadow -exec cat {} \;` ran
                    # free while `cat /etc/shadow` was refused, so the detour was
                    # the weaker door — exactly as directory packing once was.
                    reading = True
                elif name in _COMMAND_PREFIXES or tok.startswith("-") \
                        or re.match(r"^[A-Za-z_]\w*=", tok):
                    continue          # wrapper, flag or VAR=value in front
                else:
                    break             # some other command leads this segment
                continue
            if not tok.startswith("-"):
                targets.append(tok)
    return targets

# Path boundary for the Bash self-protection detection: the protected path must
# be followed by a separator (/, whitespace, quote, redirect, paren) or the end
# of the string. This prevents '~/.claude/.sudo-overrides' from wrongly matching
# '~/.claude/.sudo-overrides-pending' (after 'overrides' there is a '-').
_PATH_BOUNDARY = r"(?:/|\s|['\";|&>)]|$)"

# Script interpreters that can read/write files through inline code, bypassing
# shell-syntax detection (no WRITE_INDICATOR, no whitespace before the path).
_INTERPRETERS = {
    "python", "python2", "python3", "node", "nodejs", "deno", "bun",
    "ruby", "perl", "php", "lua", "Rscript", "tclsh",
}
# Flags that introduce INLINE code (vs. running a script file).
_INLINE_CODE_FLAGS = {
    "-c", "-e", "-E", "-r", "-p", "-n", "-pe", "-ne", "-np", "-pi",
    "--eval", "--exec", "--print",
}

# Shell word-splitting obfuscation: ${IFS}, $IFS, ${IFS%??} are expanded to
# whitespace by the shell before execution. The hook sees the literal string, so
# `cat${IFS}~/.ssh/id_rsa` would read as ONE token and slip past the tokenizer.
# Normalise these to a space up front so every downstream check benefits.
_IFS_RE = re.compile(r"\$\{IFS[^}]*\}|\$IFS\b")

# Path-like substrings inside opaque interpreter code (~/..., /abs/..., $HOME/...).
_PATHLIKE_RE = re.compile(r"(?:~|\$\{?HOME\}?|/)[\w./+\-]*")

# Detects a .env-style filename inside opaque interpreter code, on a word boundary.
# Used instead of a plain `".env" in command` substring test, which false-positives
# on os.environ / .environment (both contain ".env"). Matches .env, .envrc,
# .env.local, .env.production — must be preceded by start/separator and followed by
# end/separator. .envrc is included for parity with check_env_file_read (which also
# treats it as a .env file via startswith). os.environ / .environment do NOT match.
_ENV_RE = re.compile(r"""(?:^|[/\s='"])\.env(rc|\.[\w.\-]+)?(?=$|[\s'":])""")


def _normalize_obfuscation(command: str) -> str:
    """Replace IFS-style word-split obfuscation with a real space."""
    return _IFS_RE.sub(" ", command)


def _inline_code_segments(command: str) -> list[str]:
    """The parts of the line that actually CARRY inline interpreter code.

    Why at all: once an inline one-liner was detected anywhere, the guard used
    to check the WHOLE command against the protected paths. A path that merely
    sits in an echo next to it brought the line down -- measured against a real
    audit log: 47 such refusals across 33 sessions, nearly all of them status
    questions ("is the override active?").

    THE TRAP: split_segments also splits INSIDE quotes. `python3 -c "import os;
    os.remove(path)"` breaks apart at the semicolon -- the first piece carries
    the one-liner without the path, the second the path without a recognisable
    one-liner. Checking each segment naively would let exactly that through.
    So from a one-liner segment onwards, segments are appended until the quotes
    balance again.

    No fallback to the whole command is needed: _interpreter_inline_code
    iterates over the segments itself, so it is true for the whole line exactly
    when it is true for one segment. A fallback would be dead code -- it was
    written, and the mutation test exposed it as having no effect.
    """
    segments = split_segments(command)
    hits = []
    i = 0
    while i < len(segments):
        if _interpreter_inline_code(segments[i]):
            block = segments[i]
            # Odd quote count means the code continues in the next segment.
            while ((block.count('"') % 2) or (block.count("'") % 2)) \
                    and i + 1 < len(segments):
                i += 1
                block += " " + segments[i]
            hits.append(block)
        i += 1
    return hits


def _interpreter_inline_code(command: str) -> bool:
    """True if the command invokes a script interpreter with INLINE code
    (python -c, node -e, perl -ne, ...). Inline code is opaque to shell
    tokenisation: a protected path embedded in `open("...")` is not at a token
    start, so it must be scanned by substring instead of token-startswith.
    Running a script FILE (python manage.py) has no inline flag -> not flagged.
    """
    # Per segment, and the switch must come AFTER the interpreter. Pairing "some
    # interpreter appears" with "some switch appears" anywhere in the line made
    # `mkdir -p /tmp/a && python3 tool.py` count as inline code — the -p belonged
    # to mkdir. Text instead of action, the same defect class this guard exists
    # to avoid.
    for segment in split_segments(command):
        toks = [t.strip("'\"") for t in segment.split()]
        for i, tok in enumerate(toks):
            if os.path.basename(tok) not in _INTERPRETERS:
                continue
            if any(rest in _INLINE_CODE_FLAGS for rest in toks[i + 1:]):
                return True
    return False


# Hardcoded minimal ruleset. Used ONLY when security-rules.json is missing,
# unreadable, or empty — so deleting/corrupting the rules file can no longer
# disable the guard (fail-CLOSED instead of fail-open). Deliberately conservative:
# covers the catastrophic patterns, system paths, and credential reads.
_FALLBACK_RULES = {
    "blocked_patterns": [
        r"rm\s+-rf?\s+/(\s|$)", r"rm\s+-rf?\s+/\*", r"rm\s+-rf?\s+~(\s|$|/\*)",
        r"rm\s+-rf?\s+\$HOME(\s|$|/\*)", r"rm\s+-rf?\s+\.(\s|$)",
        r"\bmkfs\b", r"\bdd\s+if=.*\s+of=/dev/(sd|nvme|hd)", r"> /dev/sd",
        r"chmod\s+-?R?\s*777", r":\(\)\{ :\|:& \};:",
        r"curl\s+[^|]*\|\s*sh", r"curl\s+[^|]*\|\s*bash",
        r"wget\s+[^|]*\|\s*sh", r"wget\s+[^|]*\|\s*bash",
        r"chown -R.*(/etc|/usr|/var|/lib|/bin|/sbin|/boot)",
        r"chmod -R.*(/etc|/usr|/var|/lib|/bin|/sbin|/boot)",
    ],
    "blocked_paths_write": [
        "~/.ssh", "~/.gnupg", "/etc", "/boot", "/usr/bin", "/usr/sbin",
        "/usr/lib", "/sbin", "/bin",
    ],
    "protected_reads": {
        "always_blocked_reads": ["/etc/shadow", "/etc/gshadow"],
        "require_override_1": ["~/.ssh/id_", "~/.aws/credentials", "~/.gnupg/"],
        "always_allowed": ["~/.ssh/config", "~/.ssh/known_hosts", "~/.ssh/*.pub"],
        "env_files_require_override_1": [".env"],
    },
    "blocked_bash_patterns_force_push": [
        r"git\s+push\s+.*--force", r"git\s+push\s+.*\s-f(\s|$)",
    ],
}


def load_rules() -> dict:
    """Load security rules from JSON file.

    Fail-CLOSED: if the file is missing, unreadable, or empty/invalid, fall back
    to _FALLBACK_RULES (a hardcoded minimal ruleset) instead of returning {} —
    otherwise deleting/corrupting the rules file would silently disable the guard.
    """
    if not RULES_PATH.exists():
        print(msg("rules.missing", path=RULES_PATH), file=sys.stderr)
        return dict(_FALLBACK_RULES)
    try:
        with open(RULES_PATH, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        print(msg("rules.unreadable", path=RULES_PATH, error=exc), file=sys.stderr)
        return dict(_FALLBACK_RULES)
    if not isinstance(data, dict) or not data:
        print(msg("rules.invalid", path=RULES_PATH), file=sys.stderr)
        return dict(_FALLBACK_RULES)
    return data


_REGEX_METACHARS = re.compile(r"[.*+?^${}()|\[\]\\]")


def check_blocked_patterns(command: str, patterns: list[str]) -> str | None:
    """Check whether the command contains a blocked pattern.

    Automatically detects whether a pattern contains regex metacharacters:
    - With metacharacters: evaluate as regex
    - Without metacharacters: check as literal substring

    Important: an unescaped pipe | acts as OR in regex and produces
    false positives (e.g. matches " sh" in "stash show"). Patterns that
    mean a literal pipe must write it as \\|.
    """
    for pattern in patterns:
        if _REGEX_METACHARS.search(pattern):
            try:
                if re.search(pattern, command):
                    return pattern
            except re.error:
                # Broken regex: fall back to substring
                if pattern in command:
                    return pattern
        elif pattern in command:
            return pattern
    return None


def check_blocked_paths(command: str, paths: list[str],
                        detector=None) -> str | None:
    """Check whether the command touches a protected path.

    `detector` decides WHAT counts as touching -- _command_is_write by default
    (write protection), _command_deletes for delete protection. Everything else
    the delete protection inherits unchanged: segment boundary, traversal
    collapsing, assignments, boundary-exact path matching. A second copy of
    that machinery would be the safe road to divergence."""
    # Remove standard redirects (>/dev/null, 2>/dev/null are harmless)
    cleaned = re.sub(r'\d*>\s*/dev/null', '', command)
    cleaned = re.sub(r'\d*>&\d+', '', cleaned)

    # Resolve traversal detours (/./, //, /seg/../) BEFORE matching, otherwise a
    # disguised target slips past the substring match below: `cp x /tmp/../etc/passwd`
    # never contains the literal "/etc/passwd". Command-string-wide and lexical, the
    # same treatment the self-protect twin already applies (_collapse_path_traversal,
    # not _norm_path -- no filesystem access here).
    cleaned = _collapse_path_traversal(cleaned)

    # Detect write resp. delete operations
    touches = detector or _command_is_write
    if not touches(cleaned):
        return None

    # Segment boundary: a write in ONE part of the line does not turn a protected
    # path in ANOTHER part into its target. `ls -la /etc/hostname && rm -rf /tmp/x`
    # deletes in the scratch area, not in the system directory. The read guard has
    # drawn this line since the recursive-read work; the write guard had not --
    # measured against a real audit log: 11 rejections from 11 different sessions,
    # every one of them harmless.
    #
    # A DIRECTORY CHANGE counts as part of the write context: `cd <protected> &&
    # echo x > file` carries the protected path only in the cd segment, and the
    # target is a bare filename. Relative-target resolution deliberately ignores
    # bare words (otherwise every subcommand would look like a target), so without
    # keeping cd segments this narrowing would open a hole -- a test case that
    # states exactly this case found it.
    #
    # If NO single segment reads as a write although the whole line does, the old
    # coarse check on the entire line stays: a false positive beats a hole.
    cleaned = _join_line_continuations(cleaned)
    to_check = [s for s in split_segments(cleaned)
                if touches(s) or _CD_RE.search(s)]
    if not to_check:
        to_check = [cleaned]
    # Substitute assignment values, then drop copy SOURCES (in that order: only
    # once the variable is resolved can you tell whether it was a source).
    to_check = [_write_target_text(_with_assignments(s, cleaned))
                for s in to_check]

    # Path order stays outermost: a command touching several protected paths
    # still reports the same one as before.
    for path in paths:
        expanded = expand_path(path)
        for segment in to_check:
            # Check both variants: original (~) and expanded (/home/user)
            if (_names_path(segment, path) or _names_path(segment, expanded)
                    or _names_path(expand_path(segment), expanded)):
                return path
    return None


# What may sit directly BEFORE a path: nothing (start of line), whitespace, a
# quote, an operator, or one of the characters that introduce a value —
# `VAR=/bin/sh`, `host:/opt/x`. Anything else means the characters are the tail
# of a longer path, not a path of their own.
#
# The comma is in here because it was MISSING and that was a hole, found by
# asking where else a path can begin: `cp datei {/tmp/a,/bin/b}` slipped through
# without it. When in doubt this list errs on the LONG side — an extra character
# means the guard looks in one more place, which is the safe direction. A
# missing one is a way past it.
_PATH_START = r"(?:^|[\s;|&(){}\[\],=:'\"<>!])"


def _names_path(text: str, path: str) -> bool:
    """Whether `text` names `path` — as a path, not as the tail of another one.

    The write guard used to ask `path in text`, so the entry `/bin` matched
    `~/Projekte/.../in-progress/bin`, `$BASE/bin/name` and `/tmp/sync/bin`. None
    of those writes to /bin. Measured over the audit log, that shape accounted
    for 72 refusals across 49 sessions once a test run was excluded — the
    largest single cause of false refusals in the write guard.

    The self-protection gate already required a boundary AFTER the path
    (_PATH_BOUNDARY). What was missing is the one in front, and that is exactly
    where `in-progress/bin` ends in `/bin`.

    Deliberately still coarse: this asks where the characters sit in the TEXT,
    not which token a shell would build. Coarse in the safe direction — a path
    that appears at a plausible start is treated as named, even if a shell might
    disagree.
    """
    if not path:
        return False
    return re.search(_PATH_START + re.escape(path.rstrip("/")) + _PATH_BOUNDARY,
                     text) is not None


def _expiry_ok(data: dict, require_expiry: bool) -> bool:
    """Check the expiry field 'expires_at' (ISO-8601).

    require_expiry=True (main-session hygiene, K1): expires_at is MANDATORY —
    must be present, parsable, and in the future. If missing, the override is
    invalid. This keeps small the time window in which a (hypothetical)
    agent_id-less subagent could inherit a main-session override, and prevents
    eternally valid override leftovers.

    require_expiry=False (agent overrides): expires_at is optional. If missing,
    the override applies (the binding to agent_id limits the risk anyway).
    If set, it must be parsable and in the future.

    'expires_after: task_completion' cannot be determined by the hook itself —
    such overrides must be removed by the coordinator after the task ends.
    """
    exp = data.get("expires_at")
    if not exp:
        return not require_expiry  # main session without expires_at -> invalid
    try:
        dt = datetime.fromisoformat(exp)
    except (ValueError, TypeError):
        return False  # unparsable -> fail-closed (H3): do NOT treat as valid
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt > datetime.now(timezone.utc)


def load_override(agent_id: str | None = None, session_id: str | None = None) -> dict | None:
    """Load the matching active override for the calling context.

    Directory: $CLAUDE_SUDO_OVERRIDES_DIR (for tests) or
    ~/.claude/.sudo-overrides/. Each instance/agent has its own file:
    - Coordinator/system (main session): {name}.json / system-{...}.json,
      WITHOUT an 'agent_id' field.
    - Subagent: agent-{agent_id}.json, WITH an 'agent_id' field == the hook agent_id.

    NO INHERITANCE: a subagent command (agent_id set) only pulls override files
    whose 'agent_id' matches exactly. Coordinator overrides (without agent_id)
    NEVER apply to subagents. Conversely, the main session (agent_id=None) only
    sees files WITHOUT agent_id. That was the gap: an agent inherited the
    coordinator's privileges.

    OPTIONAL session_id binding: an override MAY carry a 'session_id' field. If
    it does, it only applies to the exact session it was issued for — this lets
    several parallel main sessions (all agent_id=None) hold distinct overrides
    instead of sharing one. An override WITHOUT a 'session_id' field still
    applies across sessions (backward-compatible).

    Expired overrides (expires_at < now) are ignored.
    With multiple matches, the highest override_level wins.
    blocked_patterns stay ALWAYS active — even at level 3.
    """
    dir_env = _env("CLAUDE_SUDO_OVERRIDES_DIR")
    overrides_dir = Path(dir_env) if dir_env else (_HOME / ".claude" / ".sudo-overrides")
    active_overrides = []

    def _matches_context(data: dict) -> bool:
        file_agent = data.get("agent_id")
        if agent_id is None:
            if file_agent is not None:
                return False
        else:
            if file_agent != agent_id:
                return False
        # Optional session_id binding: only when the override carries a session_id.
        # Without a session_id field -> applies across sessions (backward-compatible).
        file_session = data.get("session_id")
        if file_session is not None and file_session != session_id:
            return False
        return True

    def _valid_level(data: dict) -> bool:
        # override_level MUST be an int in {0,1,2,3}. bool counts as int in
        # Python, so explicitly exclude it. Otherwise discard the file (default-deny, H4).
        lvl = data.get("override_level")
        return isinstance(lvl, int) and not isinstance(lvl, bool) and lvl in (0, 1, 2, 3)

    if overrides_dir.is_dir():
        for filepath in overrides_dir.glob("*.json"):
            try:
                with open(filepath, encoding="utf-8") as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue
            if data.get("confirmed") is not True or not data.get("task"):
                continue
            if not _valid_level(data):
                continue
            # Main-session overrides (agent_id None) require mandatory expires_at.
            if not _expiry_ok(data, require_expiry=(agent_id is None)):
                continue
            if not _matches_context(data):
                continue
            data["_source_file"] = filepath.name
            active_overrides.append(data)

    # Backwards compatibility: old single file — applies only to the main session
    if agent_id is None:
        legacy_path = _HOME / ".claude" / ".sudo-override.json"
        if legacy_path.exists():
            try:
                with open(legacy_path, encoding="utf-8") as f:
                    data = json.load(f)
                if (data.get("confirmed") is True and data.get("task")
                        and data.get("agent_id") is None
                        and _valid_level(data)
                        and _expiry_ok(data, require_expiry=True)):
                    data["_source_file"] = ".sudo-override.json (legacy)"
                    active_overrides.append(data)
            except (json.JSONDecodeError, OSError):
                pass

    if not active_overrides:
        return None

    if len(active_overrides) == 1:
        return active_overrides[0]

    # FAIL-CLOSED SELECTION AMONG SEVERAL ACTIVE OVERRIDES.
    #
    # This used to return the HIGHEST level. That is a privilege-escalation path via
    # stale grants: a forgotten level-2 file that has not expired yet silently wins
    # over a level-1 grant the owner just issued deliberately and narrowly. The owner
    # sees "level 1 active" in the prompt and gets level 2.
    #
    # The most recently GRANTED override wins instead -- it is the one the owner
    # actually meant. Recency key: `granted_at` (grant time, written by the grant
    # tool). Only if NOT every active override carries it (files written by older
    # versions never did) fall back to `expires_at`, which rises monotonically with
    # grant time at a fixed --minutes. Both are ISO-8601 strings, so a lexicographic
    # compare is chronological.
    # Two names for the same field: an approval script may write either
    # `granted_at` or `freigegeben_am`. Reading only one of them means an
    # installation whose script uses the other silently falls back to the
    # weaker rule below — still fail-closed, but two grants of different age
    # with the same runtime then count as simultaneous.
    def _grant_time(o: dict) -> str:
        return o.get("granted_at") or o.get("freigegeben_am") or ""

    if all(_grant_time(o) for o in active_overrides):
        def _recency(o: dict) -> str:
            return _grant_time(o)
    else:
        def _recency(o: dict) -> str:
            return o.get("expires_at") or ""

    newest = max(active_overrides, key=_recency)

    # Exact tie (several overrides with an identical recency key): do not guess.
    # Fail closed -- no override applied -- and say so, because silently picking one
    # is how a stale grant sneaks back in.
    top = _recency(newest)
    if sum(1 for o in active_overrides if _recency(o) == top) > 1:
        print(msg("override.ambiguous"), file=sys.stderr)
        return None
    return newest


# Lifecycle commands: reading and building yes, tearing down no.
#
# The allowlist only ever checked the command NAME, never the subcommand: with
# the container tool on the list, every subcommand was allowed — on level 0,
# which is where every agent runs without doing anything.
#
# The check deliberately does NOT hang off the privilege-escalation command: if
# the user is in the container group, that command is not needed at all.
# Measured in the author's install: 9246 of 11056 calls ran without it, so a
# check bound to it would have missed 84 % of them.
#
# Scope from 107593 audit lines: the lifecycle is gated (3.6 % of calls). `exec`
# stays free — it is the most frequent form at 58.2 %, its inner command is an
# interpreter in ~70 % of cases (so not statically judgeable), and paths INSIDE
# a container cannot be judged from the host anyway. That is a named boundary,
# not an oversight.
_CONTAINER_FREE = {
    "ps", "logs", "inspect", "images", "stats", "top", "port", "diff",
    "events", "history", "version", "info", "exec", "run", "build", "cp",
    "pull", "push", "tag", "search", "wait", "attach", "df",
}

_CONTAINER_GROUP_FREE = {
    "volume": {"ls", "inspect"},
    "network": {"ls", "inspect"},
    "image": {"ls", "inspect", "history"},
    "system": {"df", "info", "events"},
    "container": {"ls", "logs", "inspect", "port", "top", "diff", "stats"},
    "compose": {"ps", "logs", "config", "top", "images", "version"},
    "context": {"ls", "inspect", "show"},
    "builder": {"ls"},
}

# Options that carry their own VALUE. Without this list the check mistakes the
# value for the subcommand: a compose call with a file option would read the
# file name and fail — on the single most common call there is.
_CONTAINER_VALUE_FLAGS = {
    "-f", "--file", "-p", "--project-name", "--env-file", "--project-directory",
    "-H", "--host", "--context", "-c", "--profile", "-l", "--log-level",
    "--ansi", "--parallel", "--progress", "-u", "--user", "-w", "--workdir",
    "-e", "--env", "-v", "--volume", "--network", "--name", "--label",
}

# Read-only subcommands for tools that genuinely need elevated rights — there
# the binding to the escalation command holds, because without it nothing runs.
_SUDO_READONLY_SUBCOMMANDS = {
    "systemctl": {"status", "list-units", "list-unit-files", "list-timers",
                  "list-sockets", "is-active", "is-enabled", "is-failed",
                  "is-system-running", "show", "cat", "show-environment"},
    "ufw": {"status"},
    "pacman": {"-Q", "-Qq", "-Qi", "-Qs", "-Ql", "-Qo", "-Qtdq", "-Qe", "-Qm",
               "-Ss", "-Si", "-Sl", "-Sg", "-V", "-T"},
}


# Options that carry their own VALUE. Without this list the check mistakes
# the value for the subcommand: a compose call with a file option would read
# the file name and fail — on the most common call there is.
_CONTAINER_VALUE_FLAGS = {
    "-f", "--file", "-p", "--project-name", "--env-file", "--project-directory",
    "-H", "--host", "--context", "-c", "--profile", "-l", "--log-level",
    "--ansi", "--parallel", "--progress", "-u", "--user", "-w", "--workdir",
    "-e", "--env", "-v", "--volume", "--network", "--name", "--label",
}


def _first_subcommand(tokens: list[str], flags_count: bool = False) -> str:
    """Erster echter Unterbefehl; Optionen und ihre Werte werden uebersprungen.

    flags_count=True fuer Werkzeuge, deren Operation SELBST eine Option ist.
    """
    skip = False
    for token in tokens:
        if skip:
            skip = False
            continue
        if token.startswith("-") and not flags_count:
            if "=" not in token and token in _CONTAINER_VALUE_FLAGS:
                skip = True
            continue
        return token.strip("\"'")
    return ""


def _container_subcommand_free(rest: str) -> tuple[bool, str]:
    """May this container call run without an approval?"""
    tokens = rest.split()
    first = _first_subcommand(tokens)
    if not first:
        return True, ""
    if first in _CONTAINER_GROUP_FREE:
        rest_tokens = tokens[tokens.index(first) + 1:] if first in tokens else []
        second = _first_subcommand(rest_tokens)
        return second in _CONTAINER_GROUP_FREE[first], f"{first} {second}".strip()
    return first in _CONTAINER_FREE, first


# Pass-through wrappers: the string behind them runs on a shell, where the
# same rules apply. Without this branch the remote path would be a hole.
_PASSTHROUGH_RE = re.compile(r"""\b(?:ssh|eval|[a-z]*sh\s+-c)\b[^"']*["']([^"']+)["']""")

# Prefixes that may sit in front of the actual command.
_PREFIX_TOKENS = ("sudo", "doas", "command", "env", "nohup", "time")

# Tools that only READ or print their arguments. With one of them in front, a
# container word behind it is text, not a command. This list may be incomplete:
# a missing entry costs a false alarm, never a hole. `find` and `xargs` are
# deliberately NOT here — they execute.
_TEXT_COMMANDS = {
    "echo", "printf", "grep", "rg", "ag", "cat", "less", "more", "head", "tail",
    "man", "which", "type", "whereis", "wc", "sort", "uniq", "diff", "git",
    "ls", "sed", "awk",
}


def _segment_tokens(segment: str) -> list[str]:
    """Split a segment; quoted text stays ONE token.

    That alone does most of the work: a message or a search pattern becomes a
    single token and can never match the name of a container command.
    """
    try:
        return shlex.split(segment)
    except ValueError:
        # Unbalanced quotes — e.g. a wrapper cut apart at a separator. Fall back
        # to a raw split: better one token too many than one too few.
        return [t.strip("\"'") for t in segment.split()]


def _is_container_command(segment: str) -> str | None:
    """Return the remainder if this segment RUNS a container command.

    Two ways lead there:

    1. The command sits at the command position — after privilege elevation,
       environment assignments and options.
    2. It sits behind one, and the segment's command is not a plain text tool.
       Then it is a wrapper (`timeout`, `nice`, `xargs`, and whatever shows up
       tomorrow), and it counts.

    Way 2 is the fail-closed direction. A list of allowed wrappers would be a
    denylist in disguise: every future one would be open. Measured, exactly
    three holes had opened that way.
    """
    tokens = _segment_tokens(segment)
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t in _PREFIX_TOKENS or "=" in t.split("/")[0] or t.startswith("-"):
            i += 1
            continue
        break
    if i >= len(tokens):
        return None
    if os.path.basename(tokens[i]) in ("docker", "podman"):
        return " ".join(tokens[i + 1:])
    if os.path.basename(tokens[i]) in _TEXT_COMMANDS:
        return None
    for j in range(i + 1, len(tokens)):
        if os.path.basename(tokens[j]) in ("docker", "podman"):
            return " ".join(tokens[j + 1:])
    return None


def check_lifecycle(command: str) -> str | None:
    """Return the subcommand that needs an approval, else None.

    Every segment of the line is checked, plus the contents of every pass-through
    wrapper, so a remote invocation cannot slip past.
    """
    to_check = [command]
    for hit in _PASSTHROUGH_RE.finditer(command):
        to_check.append(hit.group(1))
    for text in to_check:
        for segment in split_segments(text):
            rest = _is_container_command(segment)
            if rest is None:
                continue
            free, named = _container_subcommand_free(rest)
            if not free:
                return named
    return None


# Tokens that end a command instead of being one: redirections (`2>&1`, `>file`),
# pipes, list operators, grouping, and a stray quote. Matched at the START of the
# token, because that is where a shell would see the operator.
_SUDO_STOP_RE = re.compile(r"[|&;()<>\"']|\d+>")


def check_sudo(command: str, allowed: list[str],
               check_subcommands: bool = True) -> str | None:
    """Return the first sudo command that is NOT in `allowed`, otherwise None.

    `allowed` is the already fully assembled allowlist (base + level grants).
    The override merge happens in the caller (main), so the entire level logic
    sits in one place and load_override is not called twice (here without
    agent_id).
    """
    # 'sudo' as a standalone word, followed by whitespace (space, tab, ...).
    # \bsudo\b prevents matching 'pseudo'; \s+ closes the tab bypass (M2).
    matches = list(re.finditer(r"\bsudo\b\s+", command))
    if not matches:
        return None

    for m in matches:
        tokens = command[m.end():].split()
        cmd_after_sudo = ""
        rest_tokens: list[str] = []
        for idx, token in enumerate(tokens):
            if token.startswith("-"):  # skip sudo flags (-S, -E, -u, -n)
                continue
            # A shell operator is not a command. `sudo -n -l 2>&1` lists one's own
            # rights and changes nothing, yet `2>&1` was taken for the command and
            # refused — measured 26 real refusals of that shape.
            #
            # An operator also STICKS to the name: `sudo true; echo done` arrives
            # as the token `true;`, which matches no allowlist entry however
            # complete that list is. So the name is the part in FRONT of the
            # operator. Found live, one command after the read-only entries were
            # added — the list was right and the comparison still failed.
            #
            # Nothing left in front means the operator leads: STOP, do not skip
            # on. In `sudo -l | rm -rf x` the rm runs WITHOUT raised rights, so
            # blaming it on this sudo would be a false claim. A later `sudo` in
            # the line is a match of its own and is still examined.
            name = _SUDO_STOP_RE.split(token, 1)[0]
            if not name:
                break
            cmd_after_sudo = name
            # Trug das Token selbst einen Operator (`docker;rm -f x`), endet der
            # Befehl dort: Was dahinter steht, gehoert zum NAECHSTEN Befehl und
            # laeuft nicht mit erhoehten Rechten. Es ihm zuzurechnen waere
            # dieselbe Falschaussage wie beim Ueberspringen des Operators.
            rest_tokens = tokens[idx + 1:] if name == token else []
            break
        if cmd_after_sudo and cmd_after_sudo not in allowed:
            return cmd_after_sudo
        # The command name alone is not enough: a service manager entry would
        # otherwise cover its stop subcommand too. If the tool is in the map,
        # the subcommand decides — and whatever is not listed as read-only needs
        # an approval (fail-closed, no denylist).
        table = _SUDO_READONLY_SUBCOMMANDS.get(cmd_after_sudo) \
            if check_subcommands else None
        if table is not None:
            # By POSITION, not by searching for the value: with the operator
            # stripped, the name no longer appears in the token list, and a
            # value search silently found nothing — which switched the
            # subcommand gate off exactly where a command carried an operator.
            rest = rest_tokens
            sub = _first_subcommand(rest, flags_count=(cmd_after_sudo == "pacman"))
            if sub and sub not in table:
                return f"{cmd_after_sudo} {sub}"
    return None


def grant_covers_path(blocked_path: str, allowed_paths: list[str]) -> bool:
    """True if a grant covers the concretely touched protected path.

    Deliberately NARROW (H1): the grant must be at least as specific as the
    protected path. A broad grant '/etc' does NOT cover '/etc/shadow' — only
    '/etc/shadow' itself or a path below it. This prevents a harmlessly meant
    grant from defeating the entire path protection.

    Rule: grant == blocked_path OR grant lies below blocked_path.
    """
    bp = expand_path(blocked_path).rstrip("/")
    for ap in allowed_paths:
        if not isinstance(ap, str) or not ap:
            continue
        ap_exp = expand_path(ap).rstrip("/")
        if ap_exp == bp or ap_exp.startswith(bp + "/"):
            return True
    return False


def dev_mode_active() -> bool:
    """True if the hook development mode (Option B) is active.

    Reads the flag file ~/.claude/.hook-dev-mode (JSON with mandatory
    expires_at). Fail-closed: if the file is missing, unparsable, or expires_at
    is missing/expired -> dev mode OFF. Prevents eternally open dev leftovers.

    The flag file lives in SELF_PROTECT — only the owner can set it via !.
    """
    flag_env = _env("CLAUDE_HOOK_DEV_FLAG")
    flag = Path(flag_env) if flag_env else Path(expand_path(HOOK_DEV_FLAG))
    if not flag.exists():
        return False
    try:
        data = json.loads(flag.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    return _expiry_ok(data, require_expiry=True)


def _dev_unlocked(prot: str) -> bool:
    """True if the matched self-protection path `prot` is unlocked in the active
    dev mode (subset DEV_UNLOCKABLE_PATHS)."""
    if not dev_mode_active():
        return False
    pe = expand_path(prot).rstrip("/")
    for u in DEV_UNLOCKABLE_PATHS:
        ue = expand_path(u).rstrip("/")
        if pe == ue or pe.startswith(ue + "/"):
            return True
    return False


def hits_self_protect(file_path: str) -> str | None:
    """Return the self-protection path that `file_path` touches — otherwise None.

    For Write/Edit/MultiEdit (exact path). Path-boundary-exact:
    '~/.claude/.sudo-overrides' covers the directory and everything below it,
    but NOT '~/.claude/.sudo-overrides-pending' (where the AI may place
    proposals). NO override lifts a match — only dev mode unlocks the hook
    source files (DEV_UNLOCKABLE_PATHS).
    """
    for fp in _norm_path_variants(file_path):
        for prot in SELF_PROTECT_PATHS:
            p = _norm_path(prot)
            if fp == p or fp.startswith(p + "/"):
                return None if _dev_unlocked(prot) else prot
    return None


def command_hits_self_protect(command: str) -> str | None:
    """Return the self-protection path a Bash write command targets.

    Best-effort counterpart to hits_self_protect for the Bash side: closes the
    gap 'echo x > ~/.claude/hooks/command-guard.py'. Only on detected write
    access (see _command_is_write). Path boundary via _PATH_BOUNDARY, so the pending
    directory is not wrongly matched. NO override lifts a match — only dev mode
    unlocks DEV_UNLOCKABLE_PATHS.

    If a command targets multiple self-protection paths, the first one NOT
    unlocked in dev mode blocks.
    """
    command = _normalize_obfuscation(command)
    # Resolve path traversal lexically (/./ , // , /seg/../) so disguised
    # self-protect targets do not slip past the string matchers below (escalation
    # fix): re.search/substring on the raw line missed them otherwise.
    command = _collapse_path_traversal(command)

    # Interpreter one-liners (python -c open(hook,"w"), node -e fs.writeFileSync,
    # python -c os.remove(rules)) carry no shell WRITE_INDICATOR, so the detection
    # below misses them. When inline interpreter code references a self-protect
    # path AT ALL, block it: there is no legitimate reason for an AI to touch the
    # guard's own files through -c/-e (reading them is possible via cat/grep).
    for block in _inline_code_segments(command):
        ce = expand_path(block)
        for prot in SELF_PROTECT_PATHS:
            p = expand_path(prot).rstrip("/")
            # Path boundary as in the write branch below. Without it a plain
            # substring match drags in every NEIGHBOUR: the directory holding
            # override PROPOSALS carries the name of the active one as its
            # prefix, and so does a backup copy of a shell startup file.
            # Measured against a real audit log: anyone checking their own
            # override proposal for valid JSON was refused by self-protection --
            # the guard blocked the use of its own escalation path.
            if (re.search(re.escape(p) + _PATH_BOUNDARY, ce)
                    and not _dev_unlocked(prot)):
                return prot

    cleaned = re.sub(r'\d*>\s*/dev/null', '', command)
    cleaned = re.sub(r'\d*>&\d+', '', cleaned)
    if not _command_is_write(cleaned):
        return None
    # Same segment boundary as in check_blocked_paths: only the parts of the line
    # that write can carry a target. A checksum over the hook file next to a write
    # into the scratch area is not an attack on the hook. cd segments stay in (see
    # there); if no single segment writes, the whole line stays (fail-closed).
    cleaned = _join_line_continuations(cleaned)
    writing = [s for s in split_segments(cleaned)
               if _command_is_write(s) or _CD_RE.search(s)]
    if not writing:
        writing = [cleaned]
    # A copy SOURCE is not a write target here either: taking a working copy of
    # the guard's own file is reading, not an attack. The destination stays
    # checked.
    writing = [_write_target_text(_with_assignments(s, cleaned))
               for s in writing]
    cleaned = " ".join(writing)
    for prot in SELF_PROTECT_PATHS:
        p = re.escape(expand_path(prot).rstrip("/"))
        for segment in writing:
            if re.search(p + _PATH_BOUNDARY, expand_path(segment)) and not _dev_unlocked(prot):
                return prot
    # Relative targets carry no protected prefix literally, so the search above
    # cannot see them. Resolve every path-ish token instead — same check, just
    # with the working directory in hand.
    cd_bases = _cd_targets(command)
    for tok in _command_path_tokens(cleaned):
        if not _looks_relative(tok):
            continue
        for fp in _norm_path_variants(tok, cd_bases):
            for prot in SELF_PROTECT_PATHS:
                pe = _norm_path(prot)
                if (fp == pe or fp.startswith(pe + "/")) and not _dev_unlocked(prot):
                    return prot
    return None


def path_decision(blocked_path: str, level: int, grants: dict) -> tuple[bool, str]:
    """Level decision for a touched protected path (blocked_paths_write).

    Shared logic for Bash check 3 AND the Write/Edit block — avoids drift.
    Level 0: no protected path. Level 1: only explicitly granted ones
    (allowed_paths, path-boundary-exact via grant_covers_path). Level 2+: all
    protected paths (single ops; recursive-system stays hard-blocked via
    blocked_patterns).

    The 'system_paths' flag is deliberately NOT evaluated (H2) — otherwise a
    level-1 file could grant itself level-2 path rights.

    Returns: (allowed, needed_text).
    """
    system_paths_granted = level >= 2
    granted_single = level >= 1 and grant_covers_path(blocked_path, grants.get("allowed_paths", []))
    allowed = system_paths_granted or granted_single
    need = f"level 2 OR an allowed_paths grant for '{blocked_path}'"
    return allowed, need


# --- Docker / Podman bind-mount + flag protection ---------------------------
# A container started through the tool path can reach the host underneath the
# self-protection: a bind-mount onto a host path is, security-wise, a write to
# that host path (the "encirclement" vector — the container edits the guard's
# own files from the inside; on the host that is a write that never appeared as
# an Edit/>). The Docker socket, --privileged and host namespaces hand over the
# host directly. Implemented on the Bash command-string layer, so opencode
# (bash -> Bash -> command-guard.py) inherits it with zero plugin code.

# Catastrophic flags — hardcoded minimal fallback so they fire even with a
# missing/empty rules file (load_rules() then returns _FALLBACK_RULES, which has
# no "docker" key). rules["docker"]["blocked_flags"] is unioned on top. NEVER
# overridable — like blocked_patterns / force_push.
_DOCKER_FALLBACK_FLAGS = [
    "--privileged",
    "/var/run/docker.sock", "/run/docker.sock",
    "--pid=host", "--pid host",
    "--network=host", "--network host", "--net=host", "--net host",
    "--ipc=host", "--ipc host",
    "--uts=host", "--uts host",
    "--cap-add=ALL", "--cap-add ALL",
    "--cap-add=SYS_ADMIN", "--cap-add SYS_ADMIN",
    "seccomp=unconfined", "apparmor=unconfined",
]


# The working directory a command runs in. Set once in main() from the tool
# input; falls back to this process's own directory, which the tool chain starts
# in the same place. Both are checked (see _norm_path_variants) — a relative
# target must not slip through just because one of the two is unknown.
_WORKING_DIR = None


def _set_working_dir(reported: str | None) -> None:
    global _WORKING_DIR
    _WORKING_DIR = reported


def _working_dirs() -> list[str]:
    """Every directory a relative path could plausibly be resolved against."""
    out = []
    if _WORKING_DIR:
        out.append(_WORKING_DIR)
    try:
        here = os.getcwd()
    except OSError:
        here = ""
    if here and here not in out:
        out.append(here)
    return out


def _looks_relative(p: str) -> bool:
    """A relative path worth resolving.

    Only spellings carrying a separator: a bare word like `check` or `set` is a
    subcommand, not a target, and resolving it would turn every command run from
    inside a protected directory into a false positive.
    """
    return bool(p) and not p.startswith(("/", "~")) and "/" in p


_CD_RE = re.compile(r"\bcd\s+([^\s;&|]+)")


def _cd_targets(command: str) -> list[str]:
    """Directories the command itself changes into before it writes.

    At check time the cd has not run yet, so the reported working directory says
    nothing about where `cp x rules/f` will land. The guard already reads cd this
    way for git commits; write targets need the same.

    Every cd target counts, not just the last one: taking all of them is the
    fail-closed reading, and a wrong extra candidate can only ever cause a block
    on a path that is protected anyway.
    """
    out = []
    for raw in _CD_RE.findall(command):
        target = expand_path(raw.strip("'\""))
        if target.startswith("/"):
            out.append(_norm_path(target))
            continue
        for base in _working_dirs():                 # relative cd
            out.append(_norm_path(os.path.join(base, target)))
    return out


def _norm_path_variants(p: str, extra_bases: list[str] | None = None) -> list[str]:
    """The normalised forms a path may stand for.

    For an absolute path that is exactly one. For a relative one it is the
    resolution against every candidate working directory — a write target must
    be refused if ANY of them lands on a protected path (fail-closed).
    """
    base = _norm_path(p)
    if not _looks_relative(p):
        return [base]
    out = [base]
    for d in list(extra_bases or []) + _working_dirs():
        cand = _norm_path(os.path.join(d, p))
        if cand not in out:
            out.append(cand)
    return out


def _norm_path(p: str) -> str:
    """Expand ~/$HOME, collapse repeated slashes, resolve . / .. LEXICALLY.

    A bind-mount source like `/etc/../etc`, `//etc` or `/./etc` resolves to the
    same host dir as `/etc` once Docker mounts it, but a raw string compare would
    miss it — so an attacker could slip a protected path past _paths_overlap.
    os.path.normpath is purely lexical (no filesystem/symlink access, which the
    hook deliberately avoids), enough to close the traversal forms. Symlinked
    sources stay out of scope (filesystem boundary, see THREAT-MODEL).
    """
    expanded = re.sub(r"/{2,}", "/", expand_path(p))   # normpath keeps a leading //
    return os.path.normpath(expanded).rstrip("/")


def _collapse_path_traversal(s: str) -> str:
    """Resolve /./ , // and /seg/../ in an ARBITRARY string, lexically.

    Unlike _norm_path (single path) this works on a whole command line (multiple
    tokens/arguments). Needed because the Bash self-protect matchers check via
    substring / re.search across the whole line: a disguised
    `~/.claude/./.sudo-overrides/x`, `.../-pending/../.sudo-overrides/x` or
    `~/.claude//hooks/...` lands on the protected path on write but slipped past
    the string match (escalation gap). Purely lexical, no filesystem access (like
    _norm_path). Iterative until stable (resolves chained ../).
    """
    prev = None
    while prev != s:
        prev = s
        s = re.sub(r"/{2,}", "/", s)                  # // -> /
        s = re.sub(r"/\.(?=/)", "", s)                # /./ -> /
        s = re.sub(r"/[^/]+/\.\.(?=/|$)", "", s)      # /seg/.. -> ''
    return s


def _paths_overlap(a: str, b: str) -> bool:
    """True if two host paths overlap: equal, or one contains the other.

    A bind-mount is dangerous whenever the mounted dir IS a protected path, lies
    BELOW one, or CONTAINS one — mounting a parent hands the container every
    protected path underneath (`-v /:/host`, `-v /etc:/x`, `-v ~/.claude:/x`).
    Plain prefix matching (what a direct write uses) only covers the first two;
    a mount needs BOTH directions. Boundary-exact via the trailing "/", so /etc
    does not match /etc-other and .sudo-overrides not .sudo-overrides-pending.
    Both sides are normalised first (_norm_path), so `/etc/../etc`, `//etc` and
    `/./etc` cannot sneak a protected path past the comparison.
    """
    pa = _norm_path(a)
    pb = _norm_path(b)
    if pa == pb:
        return True
    # pa == "" is the root mount ("/"); pb.startswith("/") then matches every
    # absolute protected path, i.e. "/" contains them all.
    return pb.startswith(pa + "/") or pa.startswith(pb + "/")


def _mount_kv_src(val: str) -> str | None:
    """Extract src=/source= from a --mount comma-list (type=bind,src=SRC,dst=…)."""
    for part in val.split(","):
        part = part.strip()
        for key in ("src=", "source="):
            if part.startswith(key):
                return part[len(key):]
    return None


def _docker_bind_sources(command: str) -> list[str]:
    """Best-effort: parse host bind-mount sources out of a docker/podman command.

    High-signal, not exhaustive (like the sudo/self-protect parsers):
      -v SRC:DST[:opts] / --volume SRC:DST[:opts] / -vSRC:… / --volume=SRC:…
      --mount type=bind,src=SRC,… / source=SRC
      docker cp <ctr>:<path> SRC                 -> the host path argument
    Only path-like literal sources are kept (contain '/' or start with '~');
    named volumes (no '/') and substituted sources ($(…), ${…}, `…`) are skipped
    — covered by the harmless/limits path, not misclassified (see THREAT-MODEL).
    """
    sources: list[str] = []

    def _add(src: str | None) -> None:
        if not src:
            return
        src = src.strip().strip("'\"")
        if not src or "$" in src or "`" in src:          # substituted -> out of scope
            return
        if "/" not in src and not src.startswith("~"):   # named volume / non-path
            return
        sources.append(src)

    toks = command.split()
    for i, tok in enumerate(toks):
        nxt = toks[i + 1] if i + 1 < len(toks) else ""
        if tok in ("-v", "--volume") and nxt:
            _add(nxt.split(":", 1)[0])
        elif tok.startswith("-v") and len(tok) > 2:
            _add(tok[2:].split(":", 1)[0])
        elif tok.startswith("--volume="):
            _add(tok[len("--volume="):].split(":", 1)[0])
        elif tok == "--mount" and nxt:
            _add(_mount_kv_src(nxt))
        elif tok.startswith("--mount="):
            _add(_mount_kv_src(tok[len("--mount="):]))

    # docker cp <ctr>:<path> SRC -> host path argument(s). Container refs look
    # like name:/path (a ':' but no leading /, ~ or .); skip those, keep host paths.
    if "cp" in toks:
        for tok in toks:
            t = tok.strip("'\"")
            if t.startswith("-") or t in ("docker", "podman", "cp"):
                continue
            if ":" in t and t[:1] not in ("/", "~", "."):
                continue
            if "/" in t or t.startswith("~"):
                _add(t)
    return sources


def check_docker_always(command: str, rules: dict) -> tuple[bool, str]:
    """ALWAYS-block docker/podman checks — independent of override/agent/session.

    A — catastrophic flags: privileged, the Docker socket, host namespaces,
        cap-add ALL/SYS_ADMIN, seccomp/apparmor unconfined. Configured
        rules["docker"]["blocked_flags"] are unioned onto _DOCKER_FALLBACK_FLAGS.
    B-encirclement — a bind-mount whose host source overlaps a SELF_PROTECT path
        (incl. mounting a PARENT dir that contains it). No :ro/:rw distinction —
        there is no legitimate reason for an agent-started container to mount the
        guard's own files, so dev mode does NOT lift it either.
    Neither is overridable — only the owner via !. Called before the override
    load in main(), so it reaches every subagent and every opencode call.

    Returns (block, reason).
    """
    command = _normalize_obfuscation(command)
    if not re.search(r"\b(docker|podman)\b", command):
        return False, ""

    configured = rules.get("docker", {}).get("blocked_flags", [])
    flags = _DOCKER_FALLBACK_FLAGS + [f for f in configured if f not in _DOCKER_FALLBACK_FLAGS]
    # Case-insensitive: Docker treats `--cap-add=all` / `=ALL` and `--net=Host`
    # equivalently, so a lowercased flag value must not slip past the match.
    cl = command.lower()
    for flag in flags:
        if flag and flag.lower() in cl:
            return True, flag

    for src in _docker_bind_sources(command):
        for prot in SELF_PROTECT_PATHS:
            if _paths_overlap(src, prot):
                return True, f"bind-mount onto {prot}"
    return False, ""


def docker_mount_blocked_path(command: str, blocked_paths_write: list[str]) -> str | None:
    """Level-dependent B class: a bind-mount whose host source overlaps a
    blocked_paths_write entry. Returns which protected path is hit so main() runs
    the normal path_decision — identical level behaviour to a direct write to
    that path. Overlap is bidirectional, so `-v /:/host` / `-v /etc:/x` are caught
    even though `/` and `/etc` are not themselves listed (they CONTAIN listed
    paths like /etc/passwd).
    """
    command = _normalize_obfuscation(command)
    if not re.search(r"\b(docker|podman)\b", command):
        return None
    for src in _docker_bind_sources(command):
        for bp in blocked_paths_write:
            if _paths_overlap(src, bp):
                return bp
    return None


# Notification id reused for every install notice, so they replace one another
# instead of stacking up.
_NOTIFY_REPLACE_ID = "20500050"


def check_confirmation(command: str, patterns: list[str]) -> bool:
    """Whether the command actually INSTALLS something (desktop notification).

    The patterns are two words (`pip install`, `pacman -S`), and they used to be
    matched as a plain substring against the whole line. So the notification
    fired whenever the words appeared as TEXT — in a grep expression, a comment,
    a commit message, a file path. Measured over 86049 logged commands: 455
    notifications, 341 of them with the words merely inside some other word.

    Now the words have to appear as CONSECUTIVE TOKENS. That keeps
    `$VENV/bin/python -m pip install …` recognised (basename comparison), while
    `echo "pip install x"` no longer fires.

    Passed-through content is checked too, and that is not a nicety: of those
    341, a measured 180 were REAL installations sitting inside
    `docker exec … sh -c "pip install …"`. A token rule that ignored quotes
    would not have removed false alarms, it would have silenced exactly the
    container installs — which are the majority of real ones on this machine.
    """
    texts = [command]
    if _SHELL_PASSTHROUGH_RE.search(command):
        # Behind a pass-through the quotes are not a fence, they are packaging:
        # the install runs on the far side. Extracting the quoted section fails
        # on nesting — measured, `sh -c 'printf "x" && pip install y'` yields
        # only `printf `, and 13 real container installs were missed that way.
        #
        # So instead of parsing quotes, they are dropped and the words are read
        # as tokens. That is deliberately COARSER than a shell, and coarse in
        # the safe direction: at worst `ssh host "echo 'pip install'"` notifies
        # once too often. A notification too many costs a glance; a missing one
        # defeats the purpose.
        texts.append(command.replace('"', " ").replace("'", " "))

    for text in texts:
        for segment in split_segments(text):
            tokens = [os.path.basename(t) for t in segment.split()]
            for pattern in patterns:
                words = pattern.split()
                if not words:
                    continue
                for i in range(len(tokens) - len(words) + 1):
                    if all(_word_matches(tok, word) for tok, word
                           in zip(tokens[i:i + len(words)], words)):
                        return True
    return False


def _word_matches(token: str, word: str) -> bool:
    """Compare one token against one word of a pattern.

    Exact, with one exception: short flags bundle. `pacman -Syu` is an install
    and must match the pattern `pacman -S`, the same way `-Rns` is a removal.
    Measured — a strictly exact comparison silenced real system upgrades that
    the old substring rule still caught by accident.

    The trade is deliberate: `pacman -Si` merely queries and now notifies too.
    A surplus notification costs a glance, a missing one costs the point of
    having it. Long options (--sync) stay exact; only single-dash bundles are
    expanded.
    """
    if (len(word) == 2 and word.startswith("-") and word[1].isalpha()
            and token.startswith("-") and not token.startswith("--")):
        return word[1] in token[1:]
    return token == word


def check_injection(command: str, keywords: list[str]) -> list[str]:
    """Check for prompt injection keywords."""
    found = []
    command_lower = command.lower()
    for keyword in keywords:
        if keyword.lower() in command_lower:
            found.append(keyword)
    return found


def check_read_protection(file_path: str, rules: dict, agent_id: str | None = None,
                          session_id: str | None = None,
                          access: str = "reading") -> tuple[bool, str, bool]:
    """Check whether an access to protected files is allowed.

    `access` only shapes the wording of the message. The choke point applies this
    check to writing tools as well, where "reading" would be a lie.

    Returns: (blocked, reason, hard)
    - (False, "", False) = allow
    - (True, reason, hard) = block; `hard` = no override lifts it

    `hard` is returned as a FLAG on purpose. It used to be read back out of the
    message text (startswith "ALWAYS BLOCKED"), which turned the language
    setting into a behaviour setting: a translated refusal was mistaken for an
    overridable one and offered an escalation that cannot exist.
    """
    protected = rules.get("protected_reads", {})
    # _norm_path instead of expand_path: it also collapses ../ ./ // lexically, so a
    # traversal detour cannot walk around the read guard (/etc/../etc/shadow never
    # contains the literal "/etc/shadow"). Same hardening the self-protect path
    # already had. Purely lexical, no filesystem access -- symlinks stay out of scope.
    expanded = _norm_path(file_path)

    # 1. Always blocked (no override helps)
    for pattern in protected.get("always_blocked_reads", []):
        pat_expanded = _norm_path(pattern)
        # The raw `file_path.startswith(pattern)` fallback is gone on purpose: with
        # both sides normalised it adds nothing, and it was the one comparison a
        # detour could still slip past.
        if expanded.startswith(pat_expanded):
            return True, msg("read.always_blocked", pattern=pattern), True

    # 2. Always allowed (public keys, config, etc.)
    for pattern in protected.get("always_allowed", []):
        pat_expanded = _norm_path(pattern)
        if "*" in pattern:
            # Glob pattern: ~/.ssh/*.pub → directory + extension
            parts = pattern.split("*")
            dir_prefix = _norm_path(parts[0])
            extension = parts[1] if len(parts) > 1 else ""
            if expanded.startswith(dir_prefix) and expanded.endswith(extension):
                return False, "", False
        elif expanded == pat_expanded or expanded.startswith(pat_expanded + "/"):
            return False, "", False

    # 3. Requires override level 1 (private keys, credentials)
    for pattern in protected.get("require_override_1", []):
        pat_expanded = _norm_path(pattern)
        if expanded.startswith(pat_expanded):
            override = load_override(agent_id, session_id)
            if override and override.get("override_level", 0) >= 1:
                level = override.get("override_level", 1)
                print(msg("read.allowed_by_override", level=level, path=file_path),
                      file=sys.stderr)
                return False, "", False
            return True, msg("read.needs_override", access=access,
                             pattern=pattern), False

    return False, "", False


def check_force_push(command: str, patterns: list[str]) -> str | None:
    """Check whether a force-push to main/master is attempted."""
    for pattern in patterns:
        if re.search(pattern, command):
            return pattern
    return None


# Tools that only PRINT or READ their arguments. When one of these sits at the
# command position, an owner-only name behind it is text, not a call.
#
# This list is deliberately NARROWER than _TEXT_COMMANDS. A gap there costs a
# container call; a gap here costs the AI approving itself. Three entries are
# therefore missing on purpose:
#   awk  — can execute via system()
#   sed  — can execute via the e flag
#   git  — can execute via -c alias.x='!command' or the pager
# Writing a commit message that mentions such a name works the recommended way
# anyway: put the message in a FILE and commit that.
_OWNER_TEXT_COMMANDS = {
    "echo", "printf", "cat", "less", "more", "head", "tail", "wc",
    "ls", "stat", "file", "grep", "rg", "ag", "diff", "sort", "uniq",
    "man", "which", "type", "whereis",
}


def check_owner_only(command: str, names: list[str]) -> str | None:
    """Return the first owner-exclusive command the AI calls via Bash.

    Commands like the grant-override or dev-window tools activate overrides or
    lift the hook self-protection. If the AI called them via the normal Bash
    tool, they would pass through the guard (no dangerous pattern in the
    string) and the AI could approve itself. Therefore hard-blocked — only the
    owner's !-invocation bypasses the guard entirely.

    POSITION IS CHECKED, NOT TEXT. The previous version searched for the name
    anywhere in the line. Measured 2026-08-21: eight out of nine harmless forms
    were rejected — including every read of the identically named flag FILE.
    The block therefore did not prevent the call, it prevented checking whether
    an approval exists at all.

    Per segment:

    1. If the name sits at the command position (after privilege elevation,
       environment assignments and options), it is a call. Compared by base
       name so a full path hits just the same.
    2. Otherwise WHAT sits at the command position decides. A pure print or
       read tool executes nothing — behind it, the name is text.
    3. Everything else counts as executing, and there the name is searched
       anywhere in the segment. That catches wrappers like `bash -c`,
       `timeout`, `watch` or `xargs`, even when the call hides in quotes.

    Point 3 is the fail-closed direction: NO allowlist of wrappers, because
    every future one would then be open. Exactly that had already opened three
    holes elsewhere in this guard.

    The word boundary also considers dot and hyphen. A plain \\b is not enough
    for hyphenated names: there the word ends before the suffix, which made
    `<name>-extra` match by mistake.
    """
    if not names:
        return None
    for segment in split_segments(command):
        tokens = _segment_tokens(segment)
        i = 0
        while i < len(tokens):
            t = tokens[i]
            if t in _PREFIX_TOKENS or "=" in t.split("/")[0] or t.startswith("-"):
                i += 1
                continue
            break
        if i >= len(tokens):
            continue
        head = os.path.basename(tokens[i])
        for name in names:
            # Not redundant with the search below: a user may name their own
            # script like a read tool. Without this, the tool exemption would
            # silently let it through.
            if head == name:
                return name
        if head in _OWNER_TEXT_COMMANDS:
            continue
        for name in names:
            if re.search(r"(?<![\w.-])" + re.escape(name) + r"(?![\w.-])", segment):
                return name
    return None


# 'git commit' — including leading -C/-c flags (git -C /path commit). Does NOT
# match 'git log --grep=commit' (there 'log' sits between git and commit).
_GIT_COMMIT_RE = re.compile(r"\bgit\s+(?:-C\s+\S+\s+|-c\s+\S+\s+)*commit\b")


def _git_working_dir(command: str, cwd: str | None) -> str:
    """Where the commit will actually land.

    Order: 'git -C <path>' outranks everything. Otherwise the last 'cd <path>'
    BEFORE the commit (because 'cd repo && git commit' moves the target).
    Otherwise the cwd the tool chain reported.
    """
    hit = _GIT_COMMIT_RE.search(command)
    prefix = command[: hit.start()] if hit else command

    by_flag = re.search(r"\bgit\s+-C\s+(\S+)", command)
    if by_flag:
        return expand_path(by_flag.group(1).strip("'\""))

    cd_targets = re.findall(r"\bcd\s+([^\s;&|]+)", prefix)
    if cd_targets:
        return expand_path(cd_targets[-1].strip("'\""))

    return cwd or os.getcwd()


def check_git_commit_on_protected_branch(
    command: str, cwd: str | None, protected: list[str]
) -> str | None:
    """Return the branch if a commit would land on it directly.

    "Never work on main directly" is a prompt rule, and a prompt rule is a
    tendency, not a barrier: a small local model tried exactly this with the rule
    sitting in its own instructions.

    Only 'git commit' is checked. 'git merge' and 'git pull' also create commits
    but belong to the merge path a human drives. Reading commands (status, log,
    diff) stay untouched.
    """
    if not protected or not _GIT_COMMIT_RE.search(command):
        return None

    directory = _git_working_dir(command, cwd)
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=directory, capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None       # git not callable / path gone -> no repo, nothing to guard
    if result.returncode != 0:
        return None       # no repo -> no branch -> no false alarm

    branch = result.stdout.strip()
    return branch if branch in protected else None


def check_git_safety(command: str, patterns: list[str]) -> str | None:
    """Check whether the command violates git-safety rules.

    Technical implementation of the git rules (reset --hard, --no-verify,
    --amend, git add -A/., git config). These patterns are ALWAYS blocked (even
    with an override).
    """
    for pattern in patterns:
        if re.search(pattern, command):
            return pattern
    return None


# Template and example files are the OPPOSITE of a secret: they show which keys
# an application needs — with empty or made-up values — and are usually checked
# into the repository. Measured over 8 weeks of audit log in the author's own
# install: 29 denials on `.env.example` alone, every one of them pointless.
#
# The residual risk is stated plainly: whoever puts real credentials into a file
# with one of these names loses the protection. The naming convention is
# unambiguous enough that the trade is worth it.
_ENV_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist",
                          ".defaults")

# Trailing punctuation from surrounding prose or code (`"…/.env.example",`) must
# not defeat the suffix check — that turned the exemption off exactly where it
# was needed most.
_TRAILING_PUNCT = "\"'`,;:)]}>"


def check_env_file_read(file_path: str, env_patterns: list[str]) -> bool:
    """Check whether a path points to a .env file.

    Detects .env at the end of the filename (regardless of directory).
    Template and example files are exempt (see above).
    """
    basename = os.path.basename(file_path).rstrip(_TRAILING_PUNCT)
    if any(basename.endswith(s) for s in _ENV_TEMPLATE_SUFFIXES):
        return False
    # Follow the naming convention rather than any prefix match: `.env`,
    # `.env.anything` and `.envrc` are environment files — `.env-files` is prose
    # and `.environment` is a word.
    is_env_file = (basename == ".env"
                   or basename.startswith(".env.")
                   or basename == ".envrc")
    for pattern in env_patterns:
        # Exact filename OR following the convention (.env.production)
        if basename == pattern:
            return True
        if pattern.startswith(".env") and is_env_file:
            return True
    return False


_SECRET_PATTERNS = [
    # echo 'secret' | sudo -S  ->  password pipe
    (re.compile(r"echo\s+(['\"]).*?\1(\s*\|\s*sudo)", re.IGNORECASE), r"echo '[REDACTED]'\2"),
    # key=value / key: value secrets
    (re.compile(r"(?i)\b(password|passwd|token|secret|api[_-]?key|access[_-]?key|bearer)\b\s*[=:]\s*\S+"),
     r"\1=[REDACTED]"),
    # --flag value
    (re.compile(r"(?i)(--(?:password|token|secret|api-?key))(\s+)\S+"), r"\1\2[REDACTED]"),
    # Authorization: Bearer xyz
    (re.compile(r"(?i)(authorization:\s*\w+\s+)\S+"), r"\1[REDACTED]"),
]


def _redact(text: str) -> str:
    """Strip obvious secrets before a command goes into the audit log.

    Protection against the leak that an audit log itself stores passwords/tokens.
    Also truncates to 600 characters.
    """
    if not text:
        return text
    for pattern, repl in _SECRET_PATTERNS:
        text = pattern.sub(repl, text)
    return text[:600]


def _audit(input_data: dict, tool: str, target: str, decision: str,
           reason: str, level=None) -> None:
    """Write an audit line (JSONL) — traceability of all actions.

    Directory: $CLAUDE_AUDIT_DIR (tests) or ~/.claude/.agent-audit/.
    'actor' is the agent_id (subagent) or 'main' (main session). This makes it
    possible to trace per agent what was done/attempted where.

    Logging errors must NEVER block the guard — everything in try/except.
    """
    try:
        dir_env = _env("CLAUDE_AUDIT_DIR")
        audit_dir = Path(dir_env) if dir_env else (_HOME / ".claude" / ".agent-audit")
        audit_dir.mkdir(parents=True, exist_ok=True)
        agent_id = input_data.get("agent_id")
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "session_id": input_data.get("session_id"),
            "actor": agent_id if agent_id else "main",
            "agent_type": input_data.get("agent_type"),
            "tool": tool,
            "target": _redact(target),
            "decision": decision,
            "reason": reason,
            "level": level,
        }
        with open(audit_dir / "actions.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass  # audit must never break the guard


def command_hits_protected_read(command: str, rules: dict,
                                agent_id: str | None,
                                session_id: str | None = None) -> tuple[bool, str, bool]:
    """Scan a Bash command token-wise for reads of protected files.

    Closes the gap that credential-/.env-read protection only covered the Read
    tool. A protected-read path is dangerous regardless of the command touching
    it (cat, base64, cp-source, dd if=, xxd, head, ...). Reuses
    check_read_protection and check_env_file_read so the tier logic lives in ONE
    place (no second source of truth, no reader-tool enumeration arms race).

    Returns (blocked, reason, overridable). 'overridable' is True when an
    override level 1+ would lift the block (credentials/.env/key dirs) and False
    for always_blocked system files (/etc/shadow) — the caller uses it to decide
    whether to print the escalation hint (which would be misleading for hard
    blocks). fail-closed: with no protected_reads in the rules it cleanly
    returns (False, "", False).
    """
    protected = rules.get("protected_reads", {})
    if not protected:
        return False, "", False

    command = _normalize_obfuscation(command)
    env_patterns = protected.get("env_files_require_override_1", [])

    # Interpreter inline code (python -c 'open("~/.ssh/id_rsa")', node -e
    # readFileSync(...)) hides the path inside an opaque string, so the token scan
    # below never sees a token that STARTS with the protected path. Scan the full
    # expanded command by substring instead. Only fires for inline interpreters,
    # so a plain `python manage.py` is unaffected.
    inline = " ".join(_inline_code_segments(command))
    if inline:
        # Reuse the tier logic (always_blocked -> always_allowed -> require_override_1)
        # by extracting path-like substrings from the opaque inline code and running
        # each through check_read_protection — the SAME source of truth as the Read
        # tool, so always_allowed (e.g. ~/.ssh/*.pub) is honoured and we avoid the
        # false positive of blocking a public-key read.
        for cand in set(_PATHLIKE_RE.findall(inline)):
            blocked, reason, hard = check_read_protection(cand, rules, agent_id,
                                                          session_id)
            if blocked:
                return True, reason, not hard
        if env_patterns and _ENV_RE.search(command):
            override = load_override(agent_id, session_id)
            if not override or override.get("override_level", 0) < 1:
                return True, msg("read.env_file_inline"), True

    # Strip standard redirects (analogous to check_blocked_paths).
    cleaned = re.sub(r'\d*>\s*/dev/null', '', command)
    cleaned = re.sub(r'\d*>&\d+', '', cleaned)

    # A copy reads its SOURCE — the destination comes into being. For the READ
    # guard only the source counts, mirroring the write guard (where only the
    # destination counts). Without this the usual setup command that copies a
    # template into place fails on the newly created destination.
    cleaned = _only_copy_sources(cleaned)

    # Normalise tokens once (quotes, leading shell metachars, VAR=/if= prefixes).
    tokens = []
    for raw in cleaned.split():
        tok = raw.strip("'\"").lstrip("<>|&;()")
        tok = re.sub(r'^[a-zA-Z_]+=', '', tok)   # strip if=/of=/VAR=
        if tok:
            tokens.append(tok)

    # Directory-exfiltration vector (tar/zip/rsync ~/.ssh): only relevant when a
    # recursive-read command actually RECEIVES such a directory. Pre-compute the
    # protected key dirs so a plain `ls ~/.ssh` (metadata only, no such command)
    # stays allowed.
    req1_dirs = []
    hard_dirs = []
    recursive_targets = _recursive_read_targets(cleaned)
    if recursive_targets:
        # _norm_path rather than expand_path: otherwise a traversal detour
        # (`tar ~/.ssh/../.ssh`) walks around the directory gate, the same way it
        # would around the direct read guard.
        req1_dirs = [_norm_path(p).rstrip("/") for p in protected.get("require_override_1", [])]
        # Same pre-computation for the always-blocked files. Without it the
        # detour was weaker than the direct path: `cat /etc/shadow` was denied
        # while `tar czf x.tgz /etc` went through — and took the file with it.
        hard_dirs = [_norm_path(p).rstrip("/") for p in protected.get("always_blocked_reads", [])]

    for tok in tokens:
        if tok.startswith("-"):
            continue

        # 1. .env protection: basename-based, also catches a bare ".env".
        if env_patterns and check_env_file_read(tok, env_patterns):
            override = load_override(agent_id, session_id)
            if not override or override.get("override_level", 0) < 1:
                return True, msg("read.env_file_bash", path=tok), True
            continue

        # 2. Credential protection: only for path-like tokens.
        if "/" not in tok and not tok.startswith("~"):
            continue

        # 2a. Recursive read of a DIRECTORY that contains protected keys
        #     (e.g. `tar ~/.ssh` grabs ~/.ssh/id_*). The token is an ancestor of
        #     (or equal to) a require_override_1 path — same override gate as
        #     reading the key file directly.
        # 2a-hard. Recursive read of a DIRECTORY that contains an always-blocked
        #     file (e.g. `tar /etc` grabs /etc/shadow). No override lifts this —
        #     exactly like reading that file directly. Otherwise the detour would
        #     be the weaker door.
        #
        #     Only for tokens that a reading command actually RECEIVED. Checking
        #     every token of the line meant a pipe (`find ~ … | grep -v x`) hit
        #     the gate over a word instead of an action.
        if tok in recursive_targets:
            if hard_dirs:
                tok_hard = _norm_path(tok).rstrip("/")
                # Empty token: see the reasoning in the level-1 branch below.
                if tok_hard and any(d == tok_hard or d.startswith(tok_hard + "/")
                                    for d in hard_dirs):
                    return True, msg("read.dir_always_blocked", path=tok), False

            if req1_dirs:
                tok_exp = _norm_path(tok).rstrip("/")
                # An empty token (a bare "/" or a regex slash) would otherwise
                # match EVERY absolute key path via startswith("/") ->
                # over-block false positive (grep/rsync/cp with a /-argument).
                if tok_exp and any(d == tok_exp or d.startswith(tok_exp + "/")
                                   for d in req1_dirs):
                    override = load_override(agent_id, session_id)
                    if not override or override.get("override_level", 0) < 1:
                        return True, msg("read.dir_credentials", path=tok), True
                    continue

        blocked, reason, hard = check_read_protection(tok, rules, agent_id,
                                                      session_id)
        if blocked:
            # `hard` comes from the check itself, not from the wording: a
            # never-readable file must stay never-readable in every language.
            return True, reason, not hard

    return False, "", False


def check_mcp_policy(tool_name: str, policy: dict,
                     agent_id: str | None, session_id: str | None = None) -> tuple[bool, str]:
    """Decide on an MCP tool call (tool_name form: mcp__<server>__<tool>).

    Default-deny for writes:
    1. server in gate_servers          -> requires override level 1+ (e.g. postgres: 'query' is ambiguous).
    2. server in safe_servers          -> allowed (local/harmless, regardless of tool).
    3. tool verb starts with read verb -> allowed (read-only).
    4. otherwise (write/unknown)       -> requires override level 1+.

    Override level 1+ lifts cases 1 and 4 (same gate as allowed_paths / .env write protection).
    Returns: (blocked, reason).
    """
    parts = tool_name.split("__", 2)
    server = parts[1] if len(parts) > 1 else ""
    tool = parts[2] if len(parts) > 2 else ""
    gate_servers = policy.get("gate_servers", [])
    safe_servers = policy.get("safe_servers", [])
    read_prefixes = policy.get("read_verb_prefixes", [])

    def _gated(why: str) -> tuple[bool, str]:
        override = load_override(agent_id, session_id)
        level = override.get("override_level", 0) if override else 0
        if level >= 1:
            return False, ""
        return True, msg("mcp.gated", tool=tool_name, why=why,
                         extra=_override_note(override, level, agent_id))

    if server in gate_servers:
        return _gated(msg("mcp.why_sensitive_server", server=server))
    if server in safe_servers:
        return False, ""
    tool_l = tool.lower()
    if any(tool_l.startswith(p) for p in read_prefixes):
        return False, ""
    return _gated(msg("mcp.why_not_readonly"))


_PATH_CANDIDATE_MAX_DEPTH = 6


# Fields that carry CONTENT and are never an access target. A text being
# written may well mention a protected path -- documentation, tests and
# measuring tools do it constantly. Searching the content too blocks a write
# over a word in the text instead of over an action.
_CONTENT_FIELDS = frozenset({
    "content", "old_string", "new_string", "new_source", "body", "text",
    "prompt", "command", "description", "instructions", "message", "query",
})


def _path_candidates(value, depth: int = 0):
    """Yield every string inside a tool_input that looks like a filesystem path.

    Deliberately generic: the choke point must not know what a branch calls its
    argument (file_path, notebook_path, path, uri, ...). Whatever looks like a
    path is checked, so a NEW tool branch is covered without anyone having to
    remember it — that forgetting was the actual defect.

    "Looks like a path" = contains a slash or starts with ~. protected_reads
    entries are absolute paths and check_read_protection compares by prefix, so
    prose that merely mentions a protected path mid-sentence does not match.
    (No example path is spelled out here on purpose: the Bash read guard scans
    command text, so a documented path turns every command carrying this file
    into a false positive.)
    """
    if depth > _PATH_CANDIDATE_MAX_DEPTH:
        return
    if isinstance(value, str):
        if "/" in value or value.startswith("~"):
            yield value
    elif isinstance(value, dict):
        for key, v in value.items():
            if key in _CONTENT_FIELDS:
                continue
            yield from _path_candidates(v, depth + 1)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _path_candidates(v, depth + 1)


def enforce_read_protection(input_data: dict, tool_name: str, rules: dict,
                            agent_id: str | None, session_id: str | None) -> None:
    """CHOKE POINT: protected_reads for every file-touching tool. Exits on block.

    Before this existed, the check hung off the Read branch alone —
    Write/Edit/MultiEdit/NotebookEdit and every MCP tool reached read-protected
    files untouched. Wiring the call into those branches too would have preserved
    the defect: the next new branch gets forgotten again. Here every non-Bash
    tool passes ONE point before any branch-specific logic runs.

    Writing tools are covered on purpose, not by accident: whoever can REPLACE a
    credential file never needs to read it.

    Bash is exempt — it brings its own tokenising check
    (command_hits_protected_read) that understands shell syntax.
    """
    protected = rules.get("protected_reads", {})
    env_patterns = protected.get("env_files_require_override_1", [])
    for candidate in _path_candidates(input_data.get("tool_input", {})):
        if env_patterns and check_env_file_read(candidate, env_patterns):
            override = load_override(agent_id, session_id)
            if not override or override.get("override_level", 0) < 1:
                _audit(input_data, tool_name, candidate, "block", "env_protected", 0)
                print(msg("read.env_file", tool=tool_name, path=candidate),
                      file=sys.stderr)
                sys.exit(2)
        blocked, reason, _ = check_read_protection(candidate, rules, agent_id,
                                                  session_id, access="accessing")
        if blocked:
            _audit(input_data, tool_name, candidate, "block", "read_protected", 0)
            print(msg("read.protected", reason=reason, tool=tool_name), file=sys.stderr)
            sys.exit(2)


def enforce_project_control_files(input_data: dict, tool_name: str,
                                  agent_id: str | None, session_id: str | None) -> None:
    """CHOKE POINT, second gate: project-local control files. Exits on block.

    Sits next to enforce_read_protection at the same single point, so it inherits
    the same property: a tool branch nobody has written yet is covered.

    Read-only tools are skipped — reading one's own configuration stays free, and
    a Glob pattern naming a control file is a search, not a write. Anything not
    on that list counts as potentially writing (fail-closed).
    """
    if tool_name in _READ_ONLY_TOOLS:
        return
    for candidate in _path_candidates(input_data.get("tool_input", {})):
        hit = project_control_file(candidate)
        if not hit:
            continue
        what, hard = hit
        if hard:
            _audit(input_data, tool_name, candidate, "block",
                   f"project_control:{what}", "hard")
            print(msg("control.hard", what=what), file=sys.stderr)
            sys.exit(2)
        override = load_override(agent_id, session_id)
        if not override or override.get("override_level", 0) < 1:
            _audit(input_data, tool_name, candidate, "block",
                   f"project_control:{what}", 0)
            print(msg("control.gated", what=what), file=sys.stderr)
            sys.exit(2)


def main():
    """Main function — reads tool input from stdin, checks against rules."""
    try:
        input_data = json.load(sys.stdin)
    except (json.JSONDecodeError, EOFError, UnicodeDecodeError, ValueError) as exc:
        # Without readable input no check is possible — so the call is denied.
        # Deliberate choice: allowing it through would be the one remaining spot
        # where a failure switches the guard off silently. To reverse this,
        # replace these five lines with sys.exit(0).
        print(msg("guard.unreadable_input", error=type(exc).__name__),
              file=sys.stderr)
        sys.exit(2)

    # Before ANY check: a relative target can only be judged against the
    # directory the command runs in.
    _set_working_dir(input_data.get("cwd"))

    tool_name = input_data.get("tool_name", "")
    # Read the session_id once up front and thread it through every override
    # lookup, so an override bound to a session_id only applies to that session.
    session_id = input_data.get("session_id")

    # CHOKE POINT — everything path-based that must hold for EVERY file-touching
    # tool, before any branch-specific logic. Bash carries its own tokenising
    # counterparts further down, because it needs to understand shell syntax.
    if tool_name != "Bash":
        enforce_project_control_files(input_data, tool_name,
                                      input_data.get("agent_id"), session_id)
        choke_rules = load_rules()
        if choke_rules:
            enforce_read_protection(input_data, tool_name, choke_rules,
                                    input_data.get("agent_id"), session_id)

    # Read tool: the protection itself ran in the choke point above — for every
    # tool, not just this one. What remains here is the audit trail.
    if tool_name == "Read":
        file_path = input_data.get("tool_input", {}).get("file_path", "")
        if file_path:
            _audit(input_data, "Read", file_path, "allow", "ok")
        sys.exit(0)

    # Write/Edit/MultiEdit/NotebookEdit: file-based write protection.
    # Closes the blind spot that these tools were previously unhooked and the AI
    # could have written protected paths, override files, or the hook itself
    # through them.
    if tool_name in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        tool_input = input_data.get("tool_input", {})
        file_path = tool_input.get("file_path") or tool_input.get("notebook_path", "")
        if not file_path:
            sys.exit(0)
        agent_id = input_data.get("agent_id")

        # A. SELF-PROTECTION — no override lifts this. Only the owner via !.
        sp = hits_self_protect(file_path)
        if sp:
            _audit(input_data, tool_name, file_path, "block", f"self_protect:{sp}", "hard")
            print(msg("self_protect.file", path=file_path, hit=sp), file=sys.stderr)
            sys.exit(2)

        rules = load_rules()
        if rules:
            # B. .env write protection now runs in the choke point (same check for
            #    every tool). Only the path rules specific to writing remain here.

            # C. Protected paths — level-dependent (identical logic to Bash check 3).
            #    For Write we have the exact target path: prefix comparison with a
            #    path boundary instead of substring.
            expanded = expand_path(file_path).rstrip("/")
            blocked_path = None
            for p in rules.get("blocked_paths_write", []):
                pe = expand_path(p).rstrip("/")
                if expanded == pe or expanded.startswith(pe + "/"):
                    blocked_path = p
                    break
            if blocked_path:
                override = load_override(agent_id, session_id)
                level = override.get("override_level", 0) if override else 0
                grants = override.get("grants", {}) if override else {}
                allowed, need = path_decision(blocked_path, level, grants)
                if not allowed:
                    _audit(input_data, tool_name, file_path, "block",
                           f"protected_path:{blocked_path}", level)
                    print(msg("path.write_blocked", path=blocked_path,
                              extra=_override_note(override, level, agent_id),
                              needed=need), file=sys.stderr)
                    sys.exit(2)

        _audit(input_data, tool_name, file_path, "allow", "ok")
        sys.exit(0)

    # MCP tools: protect against unfiltered access (e.g. github writes, postgres).
    # MCP calls previously bypassed the guard entirely (only Bash/Read/Write/Edit
    # were hooked). Closes the gap: writing/sensitive MCP tools -> override 1+.
    if tool_name.startswith("mcp__"):
        rules = load_rules()
        policy = rules.get("mcp_policy", {}) if rules else {}
        # If the policy is entirely absent (older rules.json), no MCP protection ->
        # pass through, so existing workflows are not unexpectedly broken.
        if not policy:
            sys.exit(0)
        agent_id = input_data.get("agent_id")
        session_id = input_data.get("session_id")
        mcp_blocked, mcp_reason = check_mcp_policy(tool_name, policy, agent_id, session_id)
        if mcp_blocked:
            _audit(input_data, tool_name, tool_name, "block", "mcp_policy", 0)
            print(msg("mcp.blocked", reason=mcp_reason), file=sys.stderr)
            sys.exit(2)
        _audit(input_data, tool_name, tool_name, "allow", "mcp_ok")
        sys.exit(0)

    if tool_name != "Bash":
        sys.exit(0)

    tool_input = input_data.get("tool_input", {})
    command = tool_input.get("command", "")

    if not command:
        sys.exit(0)

    # De-obfuscate IFS-style word-splitting once, so EVERY downstream check
    # (blocked_patterns, paths, sudo, self-protect, reads) sees real whitespace.
    command = _normalize_obfuscation(command)

    rules = load_rules()
    if not rules:
        sys.exit(0)

    # 1. Blocked patterns — ALWAYS active, even with an override
    blocked = check_blocked_patterns(command, rules.get("blocked_patterns", []))
    if blocked:
        _audit(input_data, "Bash", command, "block", f"blocked_pattern:{blocked}", "hard")
        print(msg("bash.blocked_pattern", pattern=blocked), file=sys.stderr)
        sys.exit(2)

    # 1b. Owner-exclusive commands — ALWAYS blocked for AI Bash, no override.
    #     Only the owner's !-invocation bypasses the guard and reaches the script.
    owner_only = check_owner_only(command, rules.get("owner_only_commands", []))
    if owner_only:
        _audit(input_data, "Bash", command, "block", f"owner_only:{owner_only}", "hard")
        print(msg("bash.owner_only", command=owner_only), file=sys.stderr)
        sys.exit(2)

    # 2. Force-push to main/master — ALWAYS blocked, even with an override
    force_push = check_force_push(
        command, rules.get("blocked_bash_patterns_force_push", [])
    )
    if force_push:
        _audit(input_data, "Bash", command, "block", "force_push", "hard")
        print(msg("git.force_push"), file=sys.stderr)
        sys.exit(2)

    # 2b. Git-safety checks — ALWAYS blocked, even with an override
    git_violation = check_git_safety(command, rules.get("blocked_git_ops", []))
    if git_violation:
        _audit(input_data, "Bash", command, "block", f"git_safety:{git_violation}", "hard")
        print(msg("git.safety", pattern=git_violation), file=sys.stderr)
        sys.exit(2)

    # 2b3. A commit straight onto a protected branch — ALWAYS blocked, no override.
    #      Enforces technically what was a prompt rule before.
    protected_branch = check_git_commit_on_protected_branch(
        command, input_data.get("cwd"), rules.get("protected_git_branches", [])
    )
    if protected_branch:
        _audit(input_data, "Bash", command, "block",
               f"git_branch:{protected_branch}", "hard")
        print(msg("git.protected_branch", branch=protected_branch), file=sys.stderr)
        sys.exit(2)

    # 2c. Self-protection of the security system — ALWAYS blocked, no override.
    #     Closes the Bash gap 'echo x > ~/.claude/hooks/command-guard.py'.
    self_protect_hit = command_hits_self_protect(command)
    if self_protect_hit:
        _audit(input_data, "Bash", command, "block", f"self_protect:{self_protect_hit}", "hard")
        print(msg("self_protect.command", hit=self_protect_hit), file=sys.stderr)
        sys.exit(2)

    # 2d. Project-local control files. Same reasoning as 2c, but bound to a
    #     pattern instead of fixed places: the tool chain reads its steering out
    #     of every project directory, so protecting only the home copies leaves
    #     the same power open one directory further along.
    control_hit = command_hits_project_control(command)
    if control_hit:
        what, hard = control_hit
        if hard:
            _audit(input_data, "Bash", command, "block", f"project_control:{what}", "hard")
            print(msg("control.hard", what=what), file=sys.stderr)
            sys.exit(2)
        override = load_override(input_data.get("agent_id"), session_id)
        if not override or override.get("override_level", 0) < 1:
            _audit(input_data, "Bash", command, "block", f"project_control:{what}", 0)
            print(msg("control.gated", what=what), file=sys.stderr)
            sys.exit(2)

    # 2e. Docker/Podman ALWAYS-block — catastrophic flags + encirclement mounts.
    #     Sits before the override load (like 1/2/2b/2c), so it reaches every
    #     subagent and every opencode call (which forwards no agent_id) — neither
    #     A nor B-encirclement is overridable. A docker `-v` carries no
    #     WRITE_INDICATOR, so it slips under 2c and needs its own check.
    docker_always, docker_reason = check_docker_always(command, rules)
    if docker_always:
        _audit(input_data, "Bash", command, "block", f"docker:{docker_reason}", "hard")
        print(msg("docker.always_blocked", reason=docker_reason), file=sys.stderr)
        sys.exit(2)

    # 2d. Credential-/.env-read protection on the Bash side (closes the Read-tool gap).
    #     Runs BEFORE the override-dependent path/sudo logic: check_read_protection
    #     regulates its own override level (always_blocked is hard, require_override_1
    #     respects level 1+), so the Bash path mirrors the Read tool — a protected
    #     file is dangerous no matter which command (cat/base64/cp-source/dd if=/...)
    #     touches it.
    agent_id = input_data.get("agent_id")
    read_blocked, read_reason, read_overridable = command_hits_protected_read(
        command, rules, agent_id, session_id
    )
    if read_blocked:
        # The reason arrives without a verdict of its own, so the frame here is
        # the only place that judges. Cutting a prefix off the text was the same
        # mistake as reading the hardness out of it: it only worked in English.
        if read_overridable:
            # Mirror the path/sudo blocks: state who/level and the escalation path.
            override = load_override(agent_id, session_id)
            level = override.get("override_level", 0) if override else 0
            _audit(input_data, "Bash", command, "block", "protected_read", level)
            print(msg("bash.read_blocked", reason=read_reason,
                      extra=_override_note(override, level, agent_id)),
                  file=sys.stderr)
        else:
            _audit(input_data, "Bash", command, "block", "protected_read", "hard")
            print(msg("bash.read_blocked_hard", reason=read_reason), file=sys.stderr)
        sys.exit(2)

    # Load the override for the calling context (main session vs. subagent).
    # blocked_patterns + force_push + git above stay ALWAYS as a safety net —
    # even at level 3. The level controls ONLY checks 3 and 4.
    override = load_override(agent_id, session_id)
    level = override.get("override_level", 0) if override else 0
    grants = override.get("grants", {}) if override else {}
    additional_sudo = grants.get("additional_sudo", [])
    if override:
        print(msg("override.active", level=level,
                  label=override.get("label", "?"), who=_who(agent_id),
                  task=override.get("task", "?"),
                  source=override.get("_source_file", "?")),
              file=sys.stderr)

    # 3. Protected paths — level-dependent.
    #    Level 0: no protected path. Level 1: only explicitly granted ones
    #    (allowed_paths). Level 2+: all protected paths (single ops;
    #    recursive-system stays hard-blocked via blocked_patterns).
    delete_only = False
    blocked_path = check_blocked_paths(command, rules.get("blocked_paths_write", []))
    if not blocked_path:
        # Delete protection: same machinery, different verbs, its own path list.
        # After the write check, so a path that appears in BOTH lists still
        # produces the message it always did.
        blocked_path = check_blocked_paths(
            command, rules.get("blocked_paths_delete", []),
            detector=_command_deletes)
        # Remember WHICH list matched, so the message can say the right thing.
        delete_only = bool(blocked_path)
    if not blocked_path:
        # A docker bind-mount onto a blocked_paths_write entry is, security-wise,
        # a write to that path — same level behaviour as `echo x > /etc/passwd`.
        blocked_path = docker_mount_blocked_path(command, rules.get("blocked_paths_write", []))
    if blocked_path:
        allowed, need = path_decision(blocked_path, level, grants)
        if not allowed:
            _audit(input_data, "Bash", command, "block", f"protected_path:{blocked_path}", level)
            print(msg("path.delete_blocked" if delete_only else "path.write_blocked",
                      path=blocked_path, needed=need,
                      extra=_override_note(override, level, agent_id)),
                  file=sys.stderr)
            sys.exit(2)

    # 4. Sudo — level-dependent.
    #    Level 2+ or additional_sudo=="all": all sudo. Otherwise: base allowlist
    #    plus the commands granted in additional_sudo.
    if not (additional_sudo == "all" or level >= 2):
        merged = rules.get("allowed_sudo", []) + (
            additional_sudo if isinstance(additional_sudo, list) else []
        )
        bad_sudo = check_sudo(command, merged, check_subcommands=(level < 1))
        if bad_sudo:
            _audit(input_data, "Bash", command, "block", f"sudo_not_allowed:{bad_sudo}", level)
            print(msg("sudo.disallowed", command=bad_sudo,
                      extra=_override_note(override, level, agent_id)),
                  file=sys.stderr)
            sys.exit(2)

    # 4b. Container lifecycle — INDEPENDENT of the escalation command. If the
    #     user is in the container group, a check bound to it would miss 84 %
    #     of the calls (measured). Free from level 1 on, because that is what
    #     the approval is for.
    if level < 1:
        bad_lifecycle = check_lifecycle(command)
        if bad_lifecycle:
            _audit(input_data, "Bash", command, "block",
                   f"lifecycle_needs_override:{bad_lifecycle}", level)
            print(msg("lifecycle.needs_override", command=bad_lifecycle),
                  file=sys.stderr)
            sys.exit(2)

    # 5. Confirmation-required commands — desktop notification
    if check_confirmation(command, rules.get("require_confirmation", [])):
        try:
            subprocess.Popen(
                ["notify-send", "-u", "normal", "-t", "5000",
                 # A fixed replace-id, so a run of installs updates ONE
                 # notification instead of stacking. Without it a single
                 # measurement run produced 316 popups in a row. The id is
                 # deliberately far above what a session's counter reaches,
                 # so this cannot replace another application's notification.
                 "-r", _NOTIFY_REPLACE_ID,
                 "Claude Code — Package Installation",
                 f"Command being executed:\n{command[:200]}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            pass  # notify-send not installed — no problem

    # 6. Prompt injection warning (no block, just a warning)
    injections = check_injection(command, rules.get("prompt_injection_keywords", []))
    if injections:
        print(msg("injection.warning", keywords=", ".join(injections)),
              file=sys.stderr)

    # All good — allow through
    _audit(input_data, "Bash", command, "allow", "ok", level)
    sys.exit(0)


def _guard_stumbled(exc: BaseException) -> None:
    """Safety net: an unexpected failure denies the call instead of allowing it.

    Without this net the guard exits with code 1 on any unhandled error — and
    only exit code 2 means "deny". Every crash would therefore be a silent way
    past the guard: the command runs and it looks like a normal allow. A typo
    introduced by a later change is enough to trigger this.

    The message names the failure so it stays visible that the guard stumbled,
    rather than the command being rejected on its merits.
    """
    # The catalogue itself may be what broke. Whatever happens here, exit 2
    # must be reached: any other exit code reads as "allowed".
    try:
        print(msg("guard.stumbled", error=type(exc).__name__, detail=exc),
              file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
    except BaseException:                              # noqa: BLE001 — last resort
        try:
            print(f"BLOCKED (guard failure): {type(exc).__name__}. The command "
                  f"was NOT allowed.", file=sys.stderr)
        except BaseException:                          # noqa: BLE001
            pass
    sys.exit(2)


if __name__ == "__main__":
    # The net wraps the WHOLE run. sys.exit() raises SystemExit and must pass
    # through untouched — otherwise every regular allow (0) would be turned
    # into a denial.
    try:
        main()
    except SystemExit:
        raise
    except BaseException as exc:
        _guard_stumbled(exc)
