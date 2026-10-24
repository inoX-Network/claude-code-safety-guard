# ============================================================================
# Two more single-spelling checks, measured 2026-10-24 against 2026.10.14.
#
# 1. Force push with another option IN FRONT. The rules pattern wants the
#    force flag right after 'push', and the normal form kept the flags in their
#    order -- so these overwrote a remote branch without any approval:
#
#      git push -q --force-with-lease origin x     (seen in real use)
#      git push -v -f origin x    git push -fq origin x
#      git push --force-with-lease=x origin x
#
#    Fix: in the normal form the force options go first, lose '=<value>', and
#    bundled short options made only of value-less letters are split.
#
# 2. Remote 'inspect' and 'compose config' print a container's environment --
#    every password from its env_file -- at level 0, while reading the .env
#    file itself needs level 1. Remotely they now stay free only when nothing
#    secret can come out: an inspect template that names only listed fields,
#    compose config with --services/--images/--hash/--quiet. Locally both stay
#    free, like exec and run.
#
# The working directory is a throwaway directory, not a repository. Pure dry
# run: only decisions are inspected.
# ============================================================================
import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
EXAMPLE_RULES = REPO / "security-rules.example.json"

# (id, command, must block)
CASES = [
    # --- force push: an option in front of the force flag ------------------
    ("-q before --force-with-lease", "git push -q --force-with-lease origin feature/x", True),
    ("-q before --force", "git push -q --force origin feature/x", True),
    ("-v before -f", "git push -v -f origin feature/x", True),
    ("-u before --force", "git push -u --force origin feature/x", True),
    ("--quiet before lease=value",
     "git push --quiet --force-with-lease=feature/x:abc origin feature/x", True),
    ("lease=value right after push", "git push --force-with-lease=feature/x origin feature/x", True),
    ("bundled -fq", "git push -fq origin feature/x", True),
    ("bundled -qf", "git push -qf origin feature/x", True),
    ("git -C, -q before --force", "git -C /tmp/repo push -q --force origin feature/x", True),
    ("lease after the branch, -q in front", "git push -q origin feature/x --force-with-lease", True),
    ("--force right after push (held)", "git push --force origin feature/x", True),
    # --- push: stays free -------------------------------------------------
    ("push -q", "git push -q origin feature/x", False),
    ("push -u", "git push -u origin feature/x", False),
    ("push --follow-tags", "git push --follow-tags origin feature/x", False),
    ("push -n (dry run)", "git push -n origin feature/x", False),
    ("branch name with f", "git push -q origin fix/force-f", False),
    ("--force-if-includes alone", "git push --force-if-includes origin feature/x", False),
    # '-o<value>' is a push option with text attached; split letter by letter,
    # the 'f' in it would read as a force flag.
    ("-o with a value is not split", "git push -ofast origin feature/x", False),

    # --- remote: container values from an env_file ------------------------
    ("remote env template",
     "ssh prod 'sudo -A docker inspect -f \"{{range .Config.Env}}{{println .}}{{end}}\" mail'", True),
    ("remote inspect without template", "ssh prod 'docker inspect mail'", True),
    ("remote container inspect", "ssh prod 'docker container inspect mail'", True),
    ("remote json .", "ssh prod \"docker inspect --format '{{json .}}' mail\"", True),
    ("remote whole Config", "ssh prod \"docker inspect --format '{{json .Config}}' mail\"", True),
    ("remote Cmd", "ssh prod \"docker inspect -f '{{.Config.Cmd}}' mail\"", True),
    ("remote behind timeout", "timeout 10 ssh prod docker inspect mail", True),
    ("remote via -H", "docker -H ssh://prod inspect mail", True),
    ("remote compose config", "ssh prod 'docker compose -f /srv/mail/compose.yml config'", True),
    ("remote compose config --format", "ssh prod 'docker compose config --format json'", True),
    ("Env next to a harmless field", "ssh prod \"docker inspect -f '{{.State.Status}} {{.Config.Env}}' c\"", True),
    ("with block on Config", "ssh prod \"docker inspect -f '{{with .Config}}{{.Env}}{{end}}' c\"", True),
    # --- remote: stays free -----------------------------------------------
    ("remote status template", "ssh prod \"docker inspect -f '{{.State.Status}}' mail\"", False),
    ("remote health", "ssh prod \"docker inspect --format '{{.State.Health.Status}}' c\"", False),
    ("remote mounts in a range",
     "ssh prod \"docker inspect -f '{{range .Mounts}}{{.Source}} {{.Destination}}{{end}}' c\"", False),
    ("remote labels as json", "ssh prod \"docker inspect --format '{{json .Config.Labels}}' c\"", False),
    ("remote label by index",
     "ssh prod \"docker inspect -f '{{index .Config.Labels \\\"com.docker.compose.project\\\"}}' c\"", False),
    ("remote name, image, created", "ssh prod \"docker inspect -f '{{.Name}} {{.Image}} {{.Created}}' c\"", False),
    ("remote networks with range variables",
     "ssh prod \"docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{$v.IPAddress}}{{end}}' c\"",
     False),
    ("remote health log", "ssh prod \"docker inspect -f '{{range .State.Health.Log}}{{.ExitCode}} {{.Output}}{{end}}' c\"", False),
    # The dot in a string literal is text, not the whole object.
    ("remote printf with a dot in the format",
     "ssh prod \"docker inspect -f '{{printf \\\"%.15s\\\" .Name}}' c\"", False),
    ("remote image inspect", "ssh prod 'docker image inspect nginx'", False),
    ("remote volume inspect", "ssh prod 'docker volume inspect data'", False),
    ("remote ps", "ssh prod 'docker ps'", False),
    ("remote compose config --services", "ssh prod 'docker compose -f x.yml config --services'", False),
    ("remote compose config -q", "ssh prod 'docker compose config -q'", False),
    # --- local: stays free (fatigue) --------------------------------------
    ("local inspect", "docker inspect mail", False),
    ("local env template", "docker inspect -f '{{.Config.Env}}' c", False),
    ("local compose config", "docker compose config", False),
    # --- text: stays free -------------------------------------------------
    ("search pattern", "grep -n 'docker inspect' notes.md", False),
]


def _decide(command: str) -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(os.environ)
        env["CLAUDE_SECURITY_RULES"] = str(EXAMPLE_RULES)
        env["CLAUDE_SUDO_OVERRIDES_DIR"] = tmp
        env["CLAUDE_AUDIT_DIR"] = tmp + "/audit"
        env["CLAUDE_HOOK_DEV_FLAG"] = tmp + "/_none"
        # No installed configuration: the message test reads the built-in English.
        env["CLAUDE_GUARD_CONFIG"] = tmp + "/_none.json"
        payload = {"tool_name": "Bash", "tool_input": {"command": command},
                   "cwd": tmp, "session_id": "push-order-remote-inspect-test",
                   "hook_event_name": "PreToolUse"}
        p = subprocess.run(["python3", str(HOOK)], input=json.dumps(payload),
                           capture_output=True, text=True, env=env, cwd=tmp)
        return p.returncode, p.stderr


@pytest.mark.parametrize("name,command,blocks", CASES, ids=[c[0] for c in CASES])
def test_push_flag_order_and_remote_inspect(name, command, blocks):
    blocked = _decide(command)[0] != 0
    assert blocked == blocks, (
        f"{name!r}: expected {'block' if blocks else 'allow'}, "
        f"got {'block' if blocked else 'allow'}")


def test_remote_inspect_message_names_the_secret_not_a_change():
    # The old text said the command "changes or tears down" and listed inspect
    # as read-only -- wrong for this block.
    code, err = _decide("ssh prod 'docker inspect mail'")
    assert code == 2
    assert "environment" in err and "changes or tears down" not in err
    assert "{{.State.Status}}" in err
