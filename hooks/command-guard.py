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
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Path to the security rules file.
# Override with CLAUDE_SECURITY_RULES (used by the test suite and for relocation).
RULES_PATH = Path(
    os.environ.get(
        "CLAUDE_SECURITY_RULES",
        Path.home() / ".claude" / "safety-guard" / "security-rules.json",
    )
)

# Self-protection of the security system: these paths must NEVER be written by
# AI tool calls (Bash AND Write/Edit). NO override lifts this — only the owner
# via ! (which bypasses the guard). Deliberately hardcoded (NOT in
# security-rules.json), otherwise the protection list would be modifiable
# through itself (chicken/egg). The pending directory
# (~/.claude/.sudo-overrides-pending) is DELIBERATELY NOT protected — the AI may
# write override proposals there, but only the owner activates them into the
# (protected) active directory.
SELF_PROTECT_PATHS = [
    "~/.claude/.sudo-overrides",                          # active override directory
    "~/.claude/bin",                                      # approval scripts
    "~/.claude/.hook-dev-mode",                           # dev-mode flag (only owner can set it via !)
    "~/.claude/hooks",                                    # all hooks incl. command-guard symlink
    "~/.claude/safety-guard/security-rules.json",
    "~/.claude/settings.json",
    "~/.claude/settings.local.json",
    "~/.claude/CLAUDE.md",
    "~/.claude/rules",                                    # the rules themselves
]

# Hook development mode (Option B): the owner can lift the self-protection ONLY
# for this subset temporarily, to allow hook changes by the AI under
# supervision. Override directory, settings.json, bin/, CLAUDE.md and rules/
# stay hard-protected EVEN in dev mode — otherwise the AI could write itself
# overrides or approvals while in dev mode.
DEV_UNLOCKABLE_PATHS = [
    "~/.claude/hooks",
    "~/.claude/safety-guard/security-rules.json",
]

# Dev-mode flag file. Lives in SELF_PROTECT (see above) — the AI cannot set it
# via Write/Bash, only the owner via !. JSON with mandatory expires_at.
HOOK_DEV_FLAG = "~/.claude/.hook-dev-mode"

# Write-command indicators — shared by check_blocked_paths and
# command_hits_self_protect, so both use the same write-access detection.
WRITE_INDICATORS = [
    ">", ">>", "tee ", "cp ", "mv ", "rm ", "touch ",
    "chmod ", "chown ", "mkdir ", "rmdir ", "ln ",
    "sed -i", "truncate ", "dd ", "install ",
]

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


def _interpreter_inline_code(command: str) -> bool:
    """True if the command invokes a script interpreter with INLINE code
    (python -c, node -e, perl -ne, ...). Inline code is opaque to shell
    tokenisation: a protected path embedded in `open("...")` is not at a token
    start, so it must be scanned by substring instead of token-startswith.
    Running a script FILE (python manage.py) has no inline flag -> not flagged.
    """
    toks = [t.strip("'\"") for t in command.split()]
    if not any(os.path.basename(t) in _INTERPRETERS for t in toks):
        return False
    return any(t in _INLINE_CODE_FLAGS for t in toks)


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
        print(f"WARNING: {RULES_PATH} not found — FALLBACK ruleset active (fail-closed)",
              file=sys.stderr)
        return dict(_FALLBACK_RULES)
    try:
        with open(RULES_PATH, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"WARNING: {RULES_PATH} unreadable ({exc}) — FALLBACK ruleset active",
              file=sys.stderr)
        return dict(_FALLBACK_RULES)
    if not isinstance(data, dict) or not data:
        print(f"WARNING: {RULES_PATH} empty/invalid — FALLBACK ruleset active",
              file=sys.stderr)
        return dict(_FALLBACK_RULES)
    return data


def expand_path(path: str) -> str:
    """Expand ~ and $HOME/${HOME} to the home directory.

    $HOME/${HOME} are resolved too so a directory/read vector like
    `tar "$HOME/.ssh"` is caught the same as `tar ~/.ssh` — the shell would
    expand it before execution, but the hook sees the literal string first.
    User-defined variables (`D=~/.ssh; ... $D`) stay out of scope (the hook
    does not run a shell), same inherent limit as blocked_patterns.
    """
    home = str(Path.home())
    return path.replace("~", home).replace("${HOME}", home).replace("$HOME", home)


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


def check_blocked_paths(command: str, paths: list[str]) -> str | None:
    """Check whether the command writes to a protected path."""
    # Remove standard redirects (>/dev/null, 2>/dev/null are harmless)
    cleaned = re.sub(r'\d*>\s*/dev/null', '', command)
    cleaned = re.sub(r'\d*>&\d+', '', cleaned)

    # Detect write operations
    is_write = any(indicator in cleaned for indicator in WRITE_INDICATORS)
    if not is_write:
        return None

    # Check both variants: original (~) and expanded (/home/user)
    cleaned_expanded = expand_path(cleaned)
    for path in paths:
        expanded = expand_path(path)
        if path in cleaned or expanded in cleaned or expanded in cleaned_expanded:
            return path
    return None


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
    dir_env = os.environ.get("CLAUDE_SUDO_OVERRIDES_DIR")
    overrides_dir = Path(dir_env) if dir_env else (Path.home() / ".claude" / ".sudo-overrides")
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
        legacy_path = Path.home() / ".claude" / ".sudo-override.json"
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

    # All collected overrides have a valid level (0-3); default 0 is only a
    # theoretical fallback and consistent with main().
    return max(active_overrides, key=lambda o: o.get("override_level", 0))


def check_sudo(command: str, allowed: list[str]) -> str | None:
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
        for token in tokens:
            if token.startswith("-"):  # skip sudo flags (-S, -E, -u, -n)
                continue
            cmd_after_sudo = token
            break
        if cmd_after_sudo and cmd_after_sudo not in allowed:
            return cmd_after_sudo
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
    flag_env = os.environ.get("CLAUDE_HOOK_DEV_FLAG")
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
    fp = _norm_path(file_path)
    for prot in SELF_PROTECT_PATHS:
        p = _norm_path(prot)
        if fp == p or fp.startswith(p + "/"):
            return None if _dev_unlocked(prot) else prot
    return None


def command_hits_self_protect(command: str) -> str | None:
    """Return the self-protection path a Bash write command targets.

    Best-effort counterpart to hits_self_protect for the Bash side: closes the
    gap 'echo x > ~/.claude/hooks/command-guard.py'. Only on detected write
    access (WRITE_INDICATORS). Path boundary via _PATH_BOUNDARY, so the pending
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
    if _interpreter_inline_code(command):
        ce = expand_path(command)
        for prot in SELF_PROTECT_PATHS:
            p = expand_path(prot).rstrip("/")
            if p in ce and not _dev_unlocked(prot):
                return prot

    cleaned = re.sub(r'\d*>\s*/dev/null', '', command)
    cleaned = re.sub(r'\d*>&\d+', '', cleaned)
    if not any(indicator in cleaned for indicator in WRITE_INDICATORS):
        return None
    cleaned_expanded = expand_path(cleaned)
    for prot in SELF_PROTECT_PATHS:
        p = re.escape(expand_path(prot).rstrip("/"))
        if re.search(p + _PATH_BOUNDARY, cleaned_expanded) and not _dev_unlocked(prot):
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


def check_confirmation(command: str, patterns: list[str]) -> bool:
    """Check whether the command requires confirmation (desktop notification)."""
    for pattern in patterns:
        if pattern in command:
            return True
    return False


def check_injection(command: str, keywords: list[str]) -> list[str]:
    """Check for prompt injection keywords."""
    found = []
    command_lower = command.lower()
    for keyword in keywords:
        if keyword.lower() in command_lower:
            found.append(keyword)
    return found


def check_read_protection(file_path: str, rules: dict, agent_id: str | None = None,
                          session_id: str | None = None) -> tuple[bool, str]:
    """Check whether a Read access to protected files is allowed.

    Returns: (blocked, reason)
    - (False, "") = allow
    - (True, reason) = block with error message
    """
    protected = rules.get("protected_reads", {})
    expanded = expand_path(file_path)

    # 1. Always blocked (no override helps)
    for pattern in protected.get("always_blocked_reads", []):
        pat_expanded = expand_path(pattern)
        if expanded.startswith(pat_expanded) or file_path.startswith(pattern):
            return True, f"ALWAYS BLOCKED: {pattern} — no override possible"

    # 2. Always allowed (public keys, config, etc.)
    for pattern in protected.get("always_allowed", []):
        pat_expanded = expand_path(pattern)
        if "*" in pattern:
            # Glob pattern: ~/.ssh/*.pub → directory + extension
            parts = pattern.split("*")
            dir_prefix = expand_path(parts[0])
            extension = parts[1] if len(parts) > 1 else ""
            if expanded.startswith(dir_prefix) and expanded.endswith(extension):
                return False, ""
        elif expanded == pat_expanded or expanded.startswith(pat_expanded + "/"):
            return False, ""

    # 3. Requires override level 1 (private keys, credentials)
    for pattern in protected.get("require_override_1", []):
        pat_expanded = expand_path(pattern)
        if expanded.startswith(pat_expanded) or file_path.startswith(pattern):
            override = load_override(agent_id, session_id)
            if override and override.get("override_level", 0) >= 1:
                level = override.get("override_level", 1)
                print(
                    f"READ ALLOWED (override level {level}): {file_path}",
                    file=sys.stderr,
                )
                return False, ""
            return True, (
                f"BLOCKED: reading {pattern} requires override level 1+. "
                f"Ask the owner for an override."
            )

    return False, ""


def check_force_push(command: str, patterns: list[str]) -> str | None:
    """Check whether a force-push to main/master is attempted."""
    for pattern in patterns:
        if re.search(pattern, command):
            return pattern
    return None


def check_owner_only(command: str, names: list[str]) -> str | None:
    """Return the first owner-exclusive command the AI calls via Bash.

    Commands like the grant-override or hook-dev-mode tools activate overrides
    or lift the hook self-protection. If the AI called them via the normal Bash
    tool, they would pass through the guard (no dangerous pattern in the string)
    and the AI could approve itself. Therefore hard-blocked — only the owner's
    !-invocation bypasses the guard entirely and reaches the script.

    Checked as a whole word (word boundaries) to avoid partial matches inside
    other words.
    """
    for name in names:
        if re.search(r"\b" + re.escape(name) + r"\b", command):
            return name
    return None


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


def check_env_file_read(file_path: str, env_patterns: list[str]) -> bool:
    """Check whether a path points to a .env file.

    Detects .env at the end of the filename (regardless of directory).
    """
    basename = os.path.basename(file_path)
    for pattern in env_patterns:
        # Exact filename OR .env in the suffix (.env.production)
        if basename == pattern:
            return True
        if pattern.startswith(".env") and basename.startswith(".env"):
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
        dir_env = os.environ.get("CLAUDE_AUDIT_DIR")
        audit_dir = Path(dir_env) if dir_env else (Path.home() / ".claude" / ".agent-audit")
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
    if _interpreter_inline_code(command):
        # Reuse the tier logic (always_blocked -> always_allowed -> require_override_1)
        # by extracting path-like substrings from the opaque inline code and running
        # each through check_read_protection — the SAME source of truth as the Read
        # tool, so always_allowed (e.g. ~/.ssh/*.pub) is honoured and we avoid the
        # false positive of blocking a public-key read.
        for cand in set(_PATHLIKE_RE.findall(command)):
            blocked, reason = check_read_protection(cand, rules, agent_id, session_id)
            if blocked:
                overridable = not reason.startswith("ALWAYS BLOCKED")
                return True, reason, overridable
        if env_patterns and _ENV_RE.search(command):
            override = load_override(agent_id, session_id)
            if not override or override.get("override_level", 0) < 1:
                return True, (
                    "reading a .env file via interpreter inline code "
                    "requires override level 1+"
                ), True

    # Strip standard redirects (analogous to check_blocked_paths).
    cleaned = re.sub(r'\d*>\s*/dev/null', '', command)
    cleaned = re.sub(r'\d*>&\d+', '', cleaned)

    # Normalise tokens once (quotes, leading shell metachars, VAR=/if= prefixes).
    tokens = []
    for raw in cleaned.split():
        tok = raw.strip("'\"").lstrip("<>|&;()")
        tok = re.sub(r'^[a-zA-Z_]+=', '', tok)   # strip if=/of=/VAR=
        if tok:
            tokens.append(tok)

    # Directory-exfiltration vector (tar/zip/rsync ~/.ssh): only relevant when a
    # recursive-read command is present. Pre-compute the protected key dirs so a
    # plain `ls ~/.ssh` (metadata only, no such command) stays allowed.
    req1_dirs = []
    if any(os.path.basename(t) in RECURSIVE_READ_CMDS for t in tokens):
        req1_dirs = [expand_path(p).rstrip("/") for p in protected.get("require_override_1", [])]

    for tok in tokens:
        if tok.startswith("-"):
            continue

        # 1. .env protection: basename-based, also catches a bare ".env".
        if env_patterns and check_env_file_read(tok, env_patterns):
            override = load_override(agent_id, session_id)
            if not override or override.get("override_level", 0) < 1:
                return True, f"reading the .env file {tok} requires override level 1+", True
            continue

        # 2. Credential protection: only for path-like tokens.
        if "/" not in tok and not tok.startswith("~"):
            continue

        # 2a. Recursive read of a DIRECTORY that contains protected keys
        #     (e.g. `tar ~/.ssh` grabs ~/.ssh/id_*). The token is an ancestor of
        #     (or equal to) a require_override_1 path — same override gate as
        #     reading the key file directly.
        if req1_dirs:
            tok_exp = expand_path(tok).rstrip("/")
            # An empty token (a bare "/" or a regex slash) would otherwise match
            # EVERY absolute key path via startswith("/") -> over-block false
            # positive (grep/rsync/cp with a /-argument).
            if tok_exp and any(d == tok_exp or d.startswith(tok_exp + "/") for d in req1_dirs):
                override = load_override(agent_id, session_id)
                if not override or override.get("override_level", 0) < 1:
                    return True, (
                        f"recursively reading {tok} (contains protected "
                        f"credentials) requires override level 1+"
                    ), True
                continue

        blocked, reason = check_read_protection(tok, rules, agent_id, session_id)
        if blocked:
            # always_blocked system files start with "ALWAYS BLOCKED" and no
            # override lifts them -> not overridable (no escalation hint).
            overridable = not reason.startswith("ALWAYS BLOCKED")
            return True, reason, overridable

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
        who = f"Agent {agent_id}" if agent_id else "main session"
        return True, (
            f"MCP tool '{tool_name}' ({why}) requires override level 1+. "
            f"{who} has no valid override (level 0). "
            f"ESCALATION: the agent asks the coordinator -> the coordinator "
            f"decides with the owner about adjusting the override file."
        )

    if server in gate_servers:
        return _gated(f"server '{server}' is classified as sensitive")
    if server in safe_servers:
        return False, ""
    tool_l = tool.lower()
    if any(tool_l.startswith(p) for p in read_prefixes):
        return False, ""
    return _gated("writing or not classified as read-only")


def main():
    """Main function — reads tool input from stdin, checks against rules."""
    try:
        input_data = json.load(sys.stdin)
    except (json.JSONDecodeError, EOFError):
        # No valid input — allow through
        sys.exit(0)

    tool_name = input_data.get("tool_name", "")
    # Read the session_id once up front and thread it through every override
    # lookup, so an override bound to a session_id only applies to that session.
    session_id = input_data.get("session_id")

    # Read tool: credential protection
    if tool_name == "Read":
        tool_input = input_data.get("tool_input", {})
        file_path = tool_input.get("file_path", "")
        if file_path:
            agent_id = input_data.get("agent_id")
            rules = load_rules()
            if rules:
                # 1. .env protection: override level 1+ required
                env_patterns = rules.get("protected_reads", {}).get(
                    "env_files_require_override_1", []
                )
                if env_patterns and check_env_file_read(file_path, env_patterns):
                    override = load_override(agent_id, session_id)
                    if not override or override.get("override_level", 0) < 1:
                        _audit(input_data, "Read", file_path, "block", "env_protected", 0)
                        print(
                            f"BLOCKED: reading the .env file {file_path} requires "
                            f"override level 1+.",
                            file=sys.stderr,
                        )
                        sys.exit(2)
                # 2. Further credential checks
                blocked, reason = check_read_protection(file_path, rules, agent_id, session_id)
                if blocked:
                    _audit(input_data, "Read", file_path, "block", "read_protected", 0)
                    print(reason, file=sys.stderr)
                    sys.exit(2)
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
            print(
                f"BLOCKED: self-protection — '{file_path}' belongs to the security "
                f"system ({sp}) and may only be changed by the owner via !. "
                f"No override lifts this.",
                file=sys.stderr,
            )
            sys.exit(2)

        rules = load_rules()
        if rules:
            # B. .env write protection (analogous to read protection: override level 1+).
            env_patterns = rules.get("protected_reads", {}).get(
                "env_files_require_override_1", []
            )
            if env_patterns and check_env_file_read(file_path, env_patterns):
                override = load_override(agent_id, session_id)
                if not override or override.get("override_level", 0) < 1:
                    _audit(input_data, tool_name, file_path, "block", "env_write_protected", 0)
                    print(
                        f"BLOCKED: writing to the .env file {file_path} requires "
                        f"override level 1+.",
                        file=sys.stderr,
                    )
                    sys.exit(2)

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
                    who = f"Agent {agent_id}" if agent_id else "main session"
                    _audit(input_data, tool_name, file_path, "block",
                           f"protected_path:{blocked_path}", level)
                    extra = (f"{who} has no valid override (level 0). " if not override
                             else f"Current override: level {level}. ")
                    print(
                        f"BLOCKED: write access (Write/Edit) to protected path "
                        f"'{blocked_path}'. {extra}Needed: {need}. "
                        f"ESCALATION: agent asks the coordinator → coordinator decides "
                        f"with the owner about adjusting the override file.",
                        file=sys.stderr,
                    )
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
            print(f"BLOCKED: {mcp_reason}", file=sys.stderr)
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
        print(f"BLOCKED: dangerous pattern detected: {blocked}", file=sys.stderr)
        sys.exit(2)

    # 1b. Owner-exclusive commands — ALWAYS blocked for AI Bash, no override.
    #     Only the owner's !-invocation bypasses the guard and reaches the script.
    owner_only = check_owner_only(command, rules.get("owner_only_commands", []))
    if owner_only:
        _audit(input_data, "Bash", command, "block", f"owner_only:{owner_only}", "hard")
        print(
            f"BLOCKED: '{owner_only}' is an owner-exclusive command (approval channel). "
            f"The AI cannot run it — only the owner via ! (bypasses the guard). "
            f"I can write an override PROPOSAL into the pending directory.",
            file=sys.stderr,
        )
        sys.exit(2)

    # 2. Force-push to main/master — ALWAYS blocked, even with an override
    force_push = check_force_push(
        command, rules.get("blocked_bash_patterns_force_push", [])
    )
    if force_push:
        _audit(input_data, "Bash", command, "block", "force_push", "hard")
        print(
            "BLOCKED: force-push to main/master — ALWAYS blocked, no override possible.",
            file=sys.stderr,
        )
        sys.exit(2)

    # 2b. Git-safety checks — ALWAYS blocked, even with an override
    git_violation = check_git_safety(command, rules.get("blocked_git_ops", []))
    if git_violation:
        _audit(input_data, "Bash", command, "block", f"git_safety:{git_violation}", "hard")
        print(
            f"BLOCKED: git-safety violation — pattern: {git_violation}.",
            file=sys.stderr,
        )
        sys.exit(2)

    # 2c. Self-protection of the security system — ALWAYS blocked, no override.
    #     Closes the Bash gap 'echo x > ~/.claude/hooks/command-guard.py'.
    self_protect_hit = command_hits_self_protect(command)
    if self_protect_hit:
        _audit(input_data, "Bash", command, "block", f"self_protect:{self_protect_hit}", "hard")
        print(
            f"BLOCKED: self-protection — write access to '{self_protect_hit}' "
            f"(security system). No override possible, only the owner via !.",
            file=sys.stderr,
        )
        sys.exit(2)

    # 2e. Docker/Podman ALWAYS-block — catastrophic flags + encirclement mounts.
    #     Sits before the override load (like 1/2/2b/2c), so it reaches every
    #     subagent and every opencode call (which forwards no agent_id) — neither
    #     A nor B-encirclement is overridable. A docker `-v` carries no
    #     WRITE_INDICATOR, so it slips under 2c and needs its own check.
    docker_always, docker_reason = check_docker_always(command, rules)
    if docker_always:
        _audit(input_data, "Bash", command, "block", f"docker:{docker_reason}", "hard")
        print(
            f"BLOCKED: docker — {docker_reason}. ALWAYS blocked (no override); "
            f"only the owner via ! may run this.",
            file=sys.stderr,
        )
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
        # Some reasons already carry a "BLOCKED: " prefix (check_read_protection);
        # strip it so the single prefix below does not double up.
        reason_text = read_reason[9:] if read_reason.startswith("BLOCKED: ") else read_reason
        if read_overridable:
            # Mirror the path/sudo blocks: state who/level and the escalation path.
            override = load_override(agent_id, session_id)
            level = override.get("override_level", 0) if override else 0
            who = f"Agent {agent_id}" if agent_id else "main session"
            extra = (f"{who} has no valid override (level 0). " if not override
                     else f"Current override: level {level}. ")
            _audit(input_data, "Bash", command, "block", "protected_read", level)
            print(
                f"BLOCKED: {reason_text} (Bash read path). {extra}"
                f"ESCALATION: agent asks the coordinator → coordinator decides with the owner "
                f"about adjusting the override file.",
                file=sys.stderr,
            )
        else:
            _audit(input_data, "Bash", command, "block", "protected_read", "hard")
            print(f"BLOCKED: {reason_text} (Bash read path).", file=sys.stderr)
        sys.exit(2)

    # Load the override for the calling context (main session vs. subagent).
    # blocked_patterns + force_push + git above stay ALWAYS as a safety net —
    # even at level 3. The level controls ONLY checks 3 and 4.
    override = load_override(agent_id, session_id)
    level = override.get("override_level", 0) if override else 0
    grants = override.get("grants", {}) if override else {}
    additional_sudo = grants.get("additional_sudo", [])
    who = f"Agent {agent_id}" if agent_id else "main session"

    if override:
        print(
            f"OVERRIDE ACTIVE: level {level} ({override.get('label', '?')}) — "
            f"{who} — task \"{override.get('task', '?')}\" "
            f"[{override.get('_source_file', '?')}]",
            file=sys.stderr,
        )

    # 3. Protected paths — level-dependent.
    #    Level 0: no protected path. Level 1: only explicitly granted ones
    #    (allowed_paths). Level 2+: all protected paths (single ops;
    #    recursive-system stays hard-blocked via blocked_patterns).
    blocked_path = check_blocked_paths(command, rules.get("blocked_paths_write", []))
    if not blocked_path:
        # A docker bind-mount onto a blocked_paths_write entry is, security-wise,
        # a write to that path — same level behaviour as `echo x > /etc/passwd`.
        blocked_path = docker_mount_blocked_path(command, rules.get("blocked_paths_write", []))
    if blocked_path:
        allowed, need = path_decision(blocked_path, level, grants)
        if not allowed:
            _audit(input_data, "Bash", command, "block", f"protected_path:{blocked_path}", level)
            extra = (f"{who} has no valid override (level 0). " if not override
                     else f"Current override: level {level}. ")
            print(
                f"BLOCKED: write access to protected path '{blocked_path}'. "
                f"{extra}Needed: {need}. "
                f"ESCALATION: agent asks the coordinator → coordinator decides with the owner "
                f"about adjusting the override file.",
                file=sys.stderr,
            )
            sys.exit(2)

    # 4. Sudo — level-dependent.
    #    Level 2+ or additional_sudo=="all": all sudo. Otherwise: base allowlist
    #    plus the commands granted in additional_sudo.
    if not (additional_sudo == "all" or level >= 2):
        merged = rules.get("allowed_sudo", []) + (
            additional_sudo if isinstance(additional_sudo, list) else []
        )
        bad_sudo = check_sudo(command, merged)
        if bad_sudo:
            _audit(input_data, "Bash", command, "block", f"sudo_not_allowed:{bad_sudo}", level)
            extra = (f"{who} has no valid override (level 0). " if not override
                     else f"Current override: level {level}. ")
            print(
                f"BLOCKED: sudo with a disallowed command: '{bad_sudo}'. "
                f"{extra}Needed: level 2 OR an additional_sudo grant for '{bad_sudo}'. "
                f"ESCALATION: agent asks the coordinator → coordinator decides with the owner "
                f"about adjusting the override file.",
                file=sys.stderr,
            )
            sys.exit(2)

    # 5. Confirmation-required commands — desktop notification
    if check_confirmation(command, rules.get("require_confirmation", [])):
        try:
            subprocess.Popen(
                ["notify-send", "-u", "normal", "-t", "5000",
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
        print(
            f"WARNING: possible prompt injection detected: {', '.join(injections)}",
            file=sys.stderr,
        )

    # All good — allow through
    _audit(input_data, "Bash", command, "allow", "ok", level)
    sys.exit(0)


if __name__ == "__main__":
    main()
