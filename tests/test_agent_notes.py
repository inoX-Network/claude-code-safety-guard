# ============================================================================
# Do the notes for assistants point at things that exist?
#
# AGENTS.md and CLAUDE.md are read by an assistant before it knows anything
# about this repository. A path in them that no longer exists is worse than no
# note at all: the assistant reports the command confidently, the user runs it,
# and nothing happens. This repository has already found that failure twice in
# its own docs — a case count that had moved on, and a tool named for a job it
# does not do.
#
# So: every file path mentioned in those two files must be present, and the two
# files must not drift into being two separate documents.
# ============================================================================
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
AGENTS = REPO / "AGENTS.md"
CLAUDE = REPO / "CLAUDE.md"

# Paths as they appear in prose: `tools/would-it-help.py`, `INSTALL.md`, …
_PATH_IN_BACKTICKS = re.compile(r"`([A-Za-z0-9_./-]+\.(?:py|md|json))`")


def check_both_files_exist():
    missing = [f.name for f in (AGENTS, CLAUDE) if not f.is_file()]
    return not missing, f"missing: {missing}"


def check_claude_points_at_agents():
    # One document, two names. If CLAUDE.md ever grows its own content, the two
    # will drift and one of them will be wrong without anyone noticing.
    text = CLAUDE.read_text(encoding="utf-8")
    return "AGENTS.md" in text, "CLAUDE.md does not reference AGENTS.md"


def check_every_mentioned_path_exists():
    missing = []
    for source in (AGENTS, CLAUDE):
        for match in _PATH_IN_BACKTICKS.findall(source.read_text(encoding="utf-8")):
            if not (REPO / match).exists():
                missing.append(f"{source.name} → {match}")
    return not missing, f"paths named but not present: {missing}"


def check_the_assessment_is_offered():
    # The whole reason these files exist: an assistant should know to offer the
    # assessment before anyone installs anything.
    text = AGENTS.read_text(encoding="utf-8")
    return "would-it-help.py" in text, "AGENTS.md never mentions the assessment"


def check_it_says_a_no_is_valid():
    # Without this, the note becomes a sales instruction — which is exactly what
    # the assessment tool was built not to be.
    text = AGENTS.read_text(encoding="utf-8").lower()
    honest = ("probably not worth it" in text
              or "protect against nothing" in text)
    return honest, "AGENTS.md does not tell the assistant that 'no' is a valid verdict"


CASES = [
    ("both agent notes exist", check_both_files_exist),
    ("CLAUDE.md points at AGENTS.md instead of duplicating it", check_claude_points_at_agents),
    ("every path they name exists", check_every_mentioned_path_exists),
    ("the assessment is offered", check_the_assessment_is_offered),
    ("a negative verdict is presented as valid", check_it_says_a_no_is_valid),
]

try:
    import pytest

    @pytest.mark.parametrize("name,fn", CASES)
    def test_agent_notes(name, fn):
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
