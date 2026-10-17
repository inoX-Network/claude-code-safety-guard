# ============================================================================
# Windows paths reach the same walls as Unix paths.
#
# Measured 2026-10-17 on Windows 11 against release 2026.10.14 with the
# example rules: the Write tool was ALLOWED (exit 0) to
#
#   C:\Users\<user>\Projekte\x\.claude\settings.json     (project control file)
#   C:/Users/<user>/Projekte/x/.claude/settings.json
#   C:\Users\<user>\.ssh\authorized_keys                 (blocked_paths_write)
#
# Cause: os.path.normpath turns '/' into '\' on Windows, and every protected
# path and control-file pattern is written with '/'. Only ~/.claude/settings.json
# held, by coincidence of the self-protection spelling.
#
# Second gap, same measurement: without the password database the home
# directory came from USERPROFILE -- settable, so the protection the Unix side
# closed on 2026-07-30 ("point HOME elsewhere and every wall moves") was open.
#
# The fix converts every path to ONE comparison form on Windows before it is
# compared (/c/users/<user>/...), the form Git Bash uses anyway, and reads the
# profile through the Known Folder API. On Unix nothing changes: the conversion
# is the identity there, which the first group of cases pins down.
# ============================================================================
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
EXAMPLE_RULES = REPO / "security-rules.example.json"
WINDOWS = os.name == "nt"


def _load_guard():
    spec = importlib.util.spec_from_file_location("_guard_win_paths", HOOK)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GUARD = _load_guard()

# (spelling, comparison form) -- the conversion as a pure function, run on
# every platform with windows=True so Linux CI measures it too.
CONVERSIONS = [
    (r"C:\Users\Bjoer\.ssh\id_rsa", "/c/users/bjoer/.ssh/id_rsa"),
    ("C:/Users/Bjoer/.ssh/id_rsa", "/c/users/bjoer/.ssh/id_rsa"),
    ("/c/Users/Bjoer/.ssh", "/c/users/bjoer/.ssh"),
    (r"c:\USERS\bjoer\.SSH", "/c/users/bjoer/.ssh"),
    (r"\\?\C:\Users\Bjoer\.ssh", "/c/users/bjoer/.ssh"),
    (r"\\.\C:\Users\Bjoer\.ssh", "/c/users/bjoer/.ssh"),
    (r"\\?\UNC\localhost\c$\Users\Bjoer\.ssh", "/c/users/bjoer/.ssh"),
    (r"\\localhost\C$\Users\Bjoer\.ssh", "/c/users/bjoer/.ssh"),
    (r"\\127.0.0.1\c$\Windows", "/c/windows"),
    (r"\\localhost\ADMIN$\System32", "/c/windows/system32"),
    (r"C:\Users\Bjoer\.ssh::$INDEX_ALLOCATION\id_rsa", "/c/users/bjoer/.ssh/id_rsa"),
    (r"C:\Users\Bjoer\.ssh.\id_rsa", "/c/users/bjoer/.ssh/id_rsa"),
    (r"C:\Users\Bjoer\.ssh \id_rsa", "/c/users/bjoer/.ssh/id_rsa"),
    (r"C:\Users\Bjoer\.claude\settings.json:stream", "/c/users/bjoer/.claude/settings.json"),
    (r"D:\Games", "/d/games"),
    ("D:", "/d"),
    (r"\\server\share\x", "//server/share/x"),
    ("relative\\dir\\file.txt", "relative/dir/file.txt"),
]


@pytest.mark.parametrize("spelling,expected", CONVERSIONS, ids=[c[0] for c in CONVERSIONS])
def test_windows_spelling_has_one_comparison_form(spelling, expected):
    assert GUARD._to_cmp(spelling, windows=True) == expected


@pytest.mark.parametrize("path", ["/home/u/.ssh/id_rsa", "/etc/Shadow", "relative/x", "~/.claude"])
def test_conversion_is_the_identity_on_unix(path):
    assert GUARD._to_cmp(path, windows=False) == path


B = "\\"
# (command line, after conversion) -- paths inside a command, everything else untouched
COMMAND_CONVERSIONS = [
    ("rm -rf /C/Users/Bjoer/x", "rm -rf /c/users/bjoer/x"),
    (f"cat C:{B}Users{B}Bjoer{B}.SSH{B}x", "cat /c/users/bjoer/.ssh/x"),
    (f"dir {B}{B}?{B}C:{B}Users{B}X", "dir /c/users/x"),
    (f"cat {B}{B}localhost{B}c${B}Users{B}Bjoer{B}.ssh{B}id_rsa", "cat /c/users/bjoer/.ssh/id_rsa"),
    (f"python -c \"open('C:{B}{B}Users{B}{B}Bjoer{B}{B}.SSH{B}{B}x')\"",
     "python -c \"open('/c/users/bjoer/.ssh/x')\""),
    ("echo x > ~/.CLAUDE/A", "echo x > ~/.claude/a"),
    ("cat $HOME/.SSH/x", "cat $HOME/.ssh/x"),
    ("git add -A", "git add -A"),                       # options keep their case
    ("echo 3/4 http://a.b/C/D", "echo 3/4 http://a.b/C/D"),
    ("cmd //c dir", "cmd //c dir"),
]


@pytest.mark.parametrize("command,expected", COMMAND_CONVERSIONS, ids=[c[0] for c in COMMAND_CONVERSIONS])
def test_paths_inside_a_command_line(command, expected):
    assert GUARD._win_command_paths(command, windows=True) == expected


# --- behaviour on a real Windows host ---------------------------------------
def _write(file_path: str, env_extra: dict | None = None) -> int:
    env = dict(os.environ)
    env["CLAUDE_SECURITY_RULES"] = str(EXAMPLE_RULES)
    env.update(env_extra or {})
    payload = {"tool_name": "Write", "tool_input": {"file_path": file_path, "content": "x"},
               "cwd": str(Path.home()), "session_id": "windows-paths-test",
               "hook_event_name": "PreToolUse"}
    p = subprocess.run([sys.executable, str(HOOK)], input=json.dumps(payload),
                       capture_output=True, text=True, env=env)
    return p.returncode


def _profile() -> str:
    # getattr: the same cases also run against older hook files (GUARD_HOOK)
    known = getattr(GUARD, "_known_folder_profile", lambda: None)
    return known() or str(Path.home())


WRITE_CASES = [
    # (id, path builder, expected exit)
    ("project control file, backslash",
     lambda h: h + r"\Projekte\x\.claude\settings.json", 2),
    ("project control file, forward slash",
     lambda h: h.replace("\\", "/") + "/Projekte/x/.claude/settings.json", 2),
    ("project control file, upper case",
     lambda h: h + r"\Projekte\x\.CLAUDE\SETTINGS.JSON", 2),
    # the one control-file pattern with an upper-case letter
    ("control file with upper case in the rule", lambda h: h + r"\.gemini\trustedFolders.json", 2),
    ("blocked_paths_write ~/.ssh", lambda h: h + r"\.ssh\authorized_keys", 2),
    ("~/.ssh through the device namespace", lambda h: "\\\\?\\" + h + r"\.ssh\authorized_keys", 2),
    ("~/.ssh through a stream name", lambda h: h + r"\.ssh::$INDEX_ALLOCATION\authorized_keys", 2),
    ("own settings.json", lambda h: h + r"\.claude\settings.json", 2),
    ("ordinary project file stays free", lambda h: h + r"\Projekte\x\app.py", 0),
]


@pytest.mark.skipif(not WINDOWS, reason="needs a Windows host")
@pytest.mark.parametrize("name,build,expected", WRITE_CASES, ids=[c[0] for c in WRITE_CASES])
def test_write_tool_with_windows_paths(name, build, expected):
    assert _write(build(_profile())) == expected, name


def _read(file_path: str) -> int:
    env = dict(os.environ)
    env["CLAUDE_SECURITY_RULES"] = str(EXAMPLE_RULES)
    payload = {"tool_name": "Read", "tool_input": {"file_path": file_path},
               "cwd": str(Path.home()), "session_id": "windows-paths-test",
               "hook_event_name": "PreToolUse"}
    p = subprocess.run([sys.executable, str(HOOK)], input=json.dumps(payload),
                       capture_output=True, text=True, env=env)
    return p.returncode


READ_CASES = [
    ("private key, backslash", lambda h: h + r"\.ssh\id_ed25519", 2),
    ("private key, forward slash", lambda h: h.replace("\\", "/") + "/.ssh/id_ed25519", 2),
    ("private key, upper case", lambda h: h + r"\.SSH\ID_ED25519", 2),
    ("project .env, backslash", lambda h: h + r"\Projekte\x\.env", 2),
    ("public key stays free", lambda h: h + r"\.ssh\id_ed25519.pub", 0),
    ("ordinary file stays free", lambda h: h + r"\Projekte\x\README.md", 0),
]


@pytest.mark.skipif(not WINDOWS, reason="needs a Windows host")
@pytest.mark.parametrize("name,build,expected", READ_CASES, ids=[c[0] for c in READ_CASES])
def test_read_tool_with_windows_paths(name, build, expected):
    assert _read(build(_profile())) == expected, name


def _bash(command: str) -> int:
    env = dict(os.environ)
    env["CLAUDE_SECURITY_RULES"] = str(EXAMPLE_RULES)
    payload = {"tool_name": "Bash", "tool_input": {"command": command},
               "cwd": str(Path.home()), "session_id": "windows-paths-test",
               "hook_event_name": "PreToolUse"}
    p = subprocess.run([sys.executable, str(HOOK)], input=json.dumps(payload),
                       capture_output=True, text=True, env=env)
    return p.returncode


def _slash(h: str) -> str:
    return h.replace("\\", "/")


def _gitbash(h: str) -> str:
    return "/" + h[0] + _slash(h[2:])          # C:\Users\x -> /C/Users/x (case kept)


# Paths inside a Git Bash command line, in the spellings Claude actually writes.
BASH_CASES = [
    ("rm on ~/.claude, drive + slash", lambda h: f"rm -rf {_slash(h)}/.claude/hooks", 2),
    ("rm on ~/.claude, Git Bash form, mixed case", lambda h: f"rm -rf {_gitbash(h)}/.claude/hooks", 2),
    ("rm on ~/.claude, quoted backslash", lambda h: f"rm -rf '{h}\\.claude\\hooks'", 2),
    ("redirect into settings.json, upper case", lambda h: f"echo x > {_gitbash(h).upper()}/.CLAUDE/SETTINGS.JSON", 2),
    ("read private key, Git Bash form", lambda h: f"cat {_gitbash(h)}/.ssh/id_ed25519", 2),
    ("read private key, drive + slash", lambda h: f"cat {_slash(h)}/.ssh/id_ed25519", 2),
    # inline interpreter code: Windows literals, escaped and raw
    ("python writes settings.json, escaped backslashes",
     lambda h: "python3 -c \"open('" + h.replace("\\", "\\\\") + "\\\\.claude\\\\settings.json','w').write('x')\"", 2),
    ("python writes settings.json, raw string",
     lambda h: "python3 -c \"open(r'" + h + "\\.claude\\settings.json','w').write('x')\"", 2),
    ("python reads private key, forward slash",
     lambda h: "python3 -c \"print(open('" + _slash(h) + "/.ssh/id_ed25519').read())\"", 2),
    ("python writes a project file stays free",
     lambda h: "python3 -c \"open(r'" + h + "\\Projekte\\x\\out.txt','w').write('x')\"", 0),
    # ~ and $HOME with upper case: the protected list is compared in lower case
    ("redirect via ~ with upper case", lambda h: "echo x > ~/.CLAUDE/settings.json", 2),
    ("read via $HOME with upper case", lambda h: "cat $HOME/.SSH/id_ed25519", 2),
    # a cd in Windows spelling before a relative write
    ("cd into ~/.claude/hooks, then write", lambda h: f"cd '{h}\\.claude\\hooks' && echo x > guard.py", 2),
    ("listing the home stays free", lambda h: f"ls -la {_gitbash(h)}", 0),
    ("ordinary project file stays free", lambda h: f"cat {_gitbash(h)}/Projekte/x/README.md", 0),
    ("flags keep their case: git add -a is not -A", lambda h: "git status -s", 0),
]


@pytest.mark.skipif(not WINDOWS, reason="needs a Windows host")
@pytest.mark.parametrize("name,build,expected", BASH_CASES, ids=[c[0] for c in BASH_CASES])
def test_bash_command_with_windows_paths(name, build, expected):
    assert _bash(build(_profile())) == expected, name


@pytest.mark.skipif(not WINDOWS, reason="needs a Windows host")
def test_upper_case_flag_is_not_lowered():
    # git add -A is refused, git add -a would not even be a valid flag; the
    # path conversion must not touch option words or the verdict flips.
    assert _bash("git add -A") == 2


@pytest.mark.skipif(not WINDOWS, reason="needs a Windows host")
def test_redirected_userprofile_does_not_move_the_walls():
    real = _profile()
    redirect = {"USERPROFILE": r"C:\Fake", "HOME": r"C:\Fake", "HOMEDRIVE": "C:", "HOMEPATH": r"\Fake"}
    assert _write(real + r"\.claude\settings.json", redirect) == 2
    assert _write(real + r"\.ssh\authorized_keys", redirect) == 2
