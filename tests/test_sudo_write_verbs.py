#!/usr/bin/env python3
"""Writing as root needs an approval; a setuid bit needs a full one.

The example rules (and most real ones) list cp, mv, chmod, chown and tee in
allowed_sudo -- for deploys and backups. Protection then hung on
blocked_paths_write alone: wherever the list did not reach, level 0 wrote as
root. Measured 2026-10-01: a root crontab, the root shell profile, and
`chown root` plus `chmod 4755` on one's own copy of a shell -- a setuid-root
shell, three commands, no approval.

Listing more paths would never end; the gate goes on the VERB instead, the
pattern systemctl and pacman already follow: a sudo whose command writes is
free from level 1 on. A setuid/setgid bit is a lasting back door, not part of a
deploy, so it needs level 2 even with a deploy approval.

Cost measured on a real audit log (4,909 distinct sudo lines, four months):
locally not a single real sudo write at level 0 (every hit was a probe), on the
remote host 4 at level 0 -- deploys run with an approval anyway (128 of 132).
"""
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
RULES = REPO / "security-rules.example.json"


def _run(command: str, level: int | None = None, allow_install: bool = False) -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as d:
        rules = RULES
        if allow_install:
            # install is not on the example allowlist; a user who adds it must
            # still not get a setuid binary out of it at level 1.
            data = json.loads(RULES.read_text(encoding="utf-8"))
            data["allowed_sudo"] = list(data["allowed_sudo"]) + ["install"]
            rules = Path(d) / "rules.json"
            rules.write_text(json.dumps(data), encoding="utf-8")
        ov = Path(d) / "ov"
        ov.mkdir()
        if level is not None:
            (ov / "t.json").write_text(json.dumps({
                "override_level": level, "task": "sudo write verbs test", "confirmed": True,
                "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat(),
                "grants": {"additional_sudo": [], "allowed_paths": []},
            }), encoding="utf-8")
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = str(rules)
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = str(ov)
        env["CLAUDE_AUDIT_DIR"] = d + "/audit"
        env["CLAUDE_HOOK_DEV_FLAG"] = d + "/_none"
        env["CLAUDE_GUARD_CONFIG"] = d + "/_no_config.json"
        p = subprocess.run([sys.executable, str(HOOK)], capture_output=True, text=True,
                           env=env, cwd=d, timeout=60,
                           input=json.dumps({"session_id": "sudo-write", "cwd": d,
                                             "tool_name": "Bash",
                                             "tool_input": {"command": command}}))
        return p.returncode, " ".join(p.stderr.split())


def _blocked(command, level=None, **kw):
    return _run(command, level, **kw)[0] == 2


def _free(command, level=None, **kw):
    return _run(command, level, **kw)[0] == 0


# --- 1. level 0: writing as root needs an approval -------------------------------
# The three measured root paths, then every write verb on the example allowlist,
# outside every protected path.

def check_root_crontab():
    return _blocked("sudo cp /tmp/x /var/spool/cron/crontabs/root")


def check_root_profile():
    return _blocked("sudo cp /tmp/x /root/.bashrc")


def check_chown_root_on_own_file():
    return _blocked("sudo chown root /tmp/x")


def check_every_allowed_write_verb():
    verbs = ["cp /tmp/a /tmp/b", "mv /tmp/a /tmp/b", "tee /tmp/b",
             "chmod 755 /tmp/b", "chown root /tmp/b", "mkdir /tmp/b"]
    return all(_blocked(f"sudo {v}") for v in verbs)


def check_remote():
    return _blocked("ssh host \"sudo cp /tmp/a /opt/app/b\"")


def check_message_names_level_1():
    code, text = _run("sudo cp /tmp/a /tmp/b")
    return code == 2 and "level 1" in text


# --- 2. level 0: reading as root stays free --------------------------------------

def check_reading_stays_free():
    return all(_free(c) for c in ("sudo ls /var/log", "sudo cat /var/log/syslog",
                                  "sudo grep error /var/log/syslog",
                                  "sudo systemctl status nginx"))


# --- 3. level 1: writing as root is free, a setuid bit is not ---------------------

def check_level1_write_free():
    return (all(_free(c, 1) for c in ("sudo cp /tmp/a /tmp/b", "sudo chmod 755 /tmp/b",
                                      "sudo chown root:root /tmp/b", "sudo mkdir /tmp/b"))
            and _free("sudo install -m 0755 /tmp/a /tmp/b", 1, allow_install=True))


def check_level1_setuid_numeric():
    return _blocked("sudo chmod 4755 /tmp/b", 1)


def check_level1_setgid_numeric():
    return _blocked("sudo chmod 2755 /tmp/b", 1)


def check_level1_setuid_symbolic():
    return all(_blocked(f"sudo chmod {m} /tmp/b", 1) for m in ("u+s", "+s", "g+s", "a=rwxs"))


def check_level1_setuid_behind_option():
    return _blocked("sudo chmod -v 4755 /tmp/b", 1)


def check_level1_install_with_setuid_mode():
    return all(_blocked(c, 1, allow_install=True)
               for c in ("sudo install -m 4755 /tmp/a /tmp/b",
                         "sudo install --mode=4755 /tmp/a /tmp/b",
                         "sudo install -m4755 /tmp/a /tmp/b"))


def check_level1_sticky_bit_is_no_setuid():
    # 1777 is the sticky bit (/tmp style), not a privilege.
    return _free("sudo chmod 1777 /tmp/b", 1)


def check_level1_removing_setuid_is_free():
    return _free("sudo chmod u-s /tmp/b", 1)


def check_setuid_message_names_level_2():
    code, text = _run("sudo chmod 4755 /tmp/b", 1)
    return code == 2 and "level 2" in text


# --- 4. level 2: everything ---------------------------------------------------------

def check_level2_setuid_free():
    return _free("sudo chmod 4755 /tmp/b", 2)


CHECKS = [(name, fn) for name, fn in sorted(globals().items())
          if name.startswith("check_") and callable(fn)]


def test_sudo_write_verbs():
    failed = [name for name, fn in CHECKS if not fn()]
    assert not failed, f"{len(failed)} of {len(CHECKS)} failed: {failed}"


if __name__ == "__main__":
    bad = [name for name, fn in CHECKS if not fn()]
    for name, _ in CHECKS:
        print(f"  {'FAIL' if name in bad else 'ok  '}  {name}")
    print(f"\n{len(CHECKS) - len(bad)} of {len(CHECKS)} passed")
    sys.exit(1 if bad else 0)
