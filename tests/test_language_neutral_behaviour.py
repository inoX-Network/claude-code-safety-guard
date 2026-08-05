# ============================================================================
# A message is a text. It must never be a decision.
#
# The guard used to read its own wording back to decide how to carry on:
#
#   overridable = not reason.startswith("ALWAYS BLOCKED")
#   reason_text = read_reason[9:] if read_reason.startswith("BLOCKED: ")
#
# Both work in English only. With a language file in place the first one turned
# a never-readable file into a seemingly overridable one — it offered an
# escalation that cannot exist — and the second one printed the verdict twice.
# So the language setting silently became a behaviour setting.
#
# These cases run the SAME command twice, once built-in English and once with a
# translation, and compare what the refusal SAYS ABOUT ITSELF: does it offer an
# escalation, and does it pass judgement exactly once. The wording may differ;
# the statement may not.
#
# They deliberately do not assert on any English text. A test that pins wording
# breaks on every translation and proves nothing about behaviour.
# ============================================================================
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HOOK = Path(os.environ.get("GUARD_HOOK") or (REPO / "hooks" / "command-guard.py"))
RULES = REPO / "security-rules.example.json"

# A translation the way a real one looks: the reasons carry no verdict of their
# own, because the frame around them does that. Exactly the shape of the
# shipped de.json — which is the point: this is not a synthetic edge case.
TRANSLATION = {
    "read.always_blocked": "{pattern} ist nie lesbar — kein Override hebt das auf",
    "read.needs_override": ("{access} {pattern} erfordert Override-Stufe 1+. "
                            "Bitte den Eigentuemer um einen Override."),
    "read.dir_always_blocked": ("{path} rekursiv zu lesen — das Verzeichnis "
                                "enthaelt eine nie lesbare Datei."),
    "bash.read_blocked": ("BLOCKIERT: {reason} (Bash-Leseweg). {extra}ESKALATION: "
                          "Der Agent fragt den Koordinator."),
    "bash.read_blocked_hard": "BLOCKIERT: {reason} (Bash-Leseweg).",
}

# Both words, because the frame is translated too and the count must not depend
# on which language produced it.
_VERDICT = re.compile(r"BLOCKED:|BLOCKIERT:")
_ESCALATION = re.compile(r"ESCALATION|ESKALATION")


def _run(command: str, translated: bool, tmp: Path) -> tuple[int, str]:
    """Run one Bash command through the hook, with or without a language file."""
    config: dict = {"installation": {"lang_dir": str(tmp / "lang")}}
    if translated:
        config["language"] = "xx"
    cfg = tmp / f"guard-config-{'xx' if translated else 'en'}.json"
    cfg.write_text(json.dumps(config), encoding="utf-8")

    env = dict(os.environ)
    env["CLAUDE_GUARD_CONFIG"] = str(cfg)
    env["CLAUDE_SECURITY_RULES"] = str(RULES)
    env["CLAUDE_SUDO_OVERRIDES_DIR"] = str(tmp / "ov")
    env["CLAUDE_AUDIT_DIR"] = str(tmp / "audit")
    env["CLAUDE_HOOK_DEV_FLAG"] = str(tmp / "_no_window")

    p = subprocess.run(
        ["python3", str(HOOK)],
        input=json.dumps({"session_id": "language-neutral-test",
                          "tool_name": "Bash",
                          "tool_input": {"command": command}}),
        capture_output=True, text=True, env=env)
    return p.returncode, " ".join(p.stderr.split())


def _compare(command: str, escalation_expected: bool) -> tuple[bool, str]:
    """Same command, two languages — and the same STATEMENT in both.

    `escalation_expected` is not decoration. Comparing the two runs against each
    other only proves symmetry: break the hardness signal altogether and both
    sides are wrong in the same way, so a pure comparison stays green. Measured —
    two mutations survived exactly that gap. The expectation is therefore
    absolute: a never-readable file offers no escalation, in any language.
    """
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        (tmp / "lang").mkdir()
        (tmp / "lang" / "xx.json").write_text(
            json.dumps(TRANSLATION, ensure_ascii=False), encoding="utf-8")
        code_en, text_en = _run(command, False, tmp)
        code_xx, text_xx = _run(command, True, tmp)

    offers_en = bool(_ESCALATION.search(text_en))
    offers_xx = bool(_ESCALATION.search(text_xx))
    ok = (
        code_en == code_xx == 2
        and offers_en is escalation_expected
        and offers_xx is escalation_expected
        and len(_VERDICT.findall(text_en)) == len(_VERDICT.findall(text_xx))
    )
    detail = (f"escalation expected: {escalation_expected}\n"
              f"en: exit {code_en} offers {offers_en} | {text_en[:150]}\n"
              f"xx: exit {code_xx} offers {offers_xx} | {text_xx[:150]}")
    return ok, detail


def check_hard_block_stays_hard():
    """A never-readable file offers no escalation — there is none to offer."""
    return _compare("cat /etc/shadow", escalation_expected=False)


def check_hard_block_via_directory():
    """Same for the detour: reading a directory that contains such a file."""
    return _compare("tar czf /tmp/x.tgz /etc", escalation_expected=False)


def check_gated_read_keeps_its_escalation():
    """A level-1 refusal names its way out — in both languages."""
    return _compare("cat ~/.aws/credentials", escalation_expected=True)


def check_verdict_is_passed_once():
    """The refusal judges exactly once — no doubled prefix from a translation."""
    _, detail = _compare("cat ~/.aws/credentials", escalation_expected=True)
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        (tmp / "lang").mkdir()
        (tmp / "lang" / "xx.json").write_text(
            json.dumps(TRANSLATION, ensure_ascii=False), encoding="utf-8")
        _, text_xx = _run("cat ~/.aws/credentials", True, tmp)
    return len(_VERDICT.findall(text_xx)) == 1, f"{detail}\nverdicts: {text_xx[:160]}"


def check_building_blocks_are_translated():
    """The pieces INSIDE a refusal follow the language too.

    Who is asking and which approval is in force used to be built in the code as
    English f-strings and dropped into an otherwise translated message. The
    result was a half-English refusal — and no test noticed, because every case
    only ever looked at the frame.
    """
    marker_who = "SITZUNG-MARKE"
    marker_note = "KEINE-FREIGABE-MARKE"
    texts = dict(TRANSLATION)
    texts["who.main"] = marker_who
    texts["override.none"] = marker_note + " {who}"
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        (tmp / "lang").mkdir()
        (tmp / "lang" / "xx.json").write_text(json.dumps(texts, ensure_ascii=False),
                                              encoding="utf-8")
        _, out = _run("cat ~/.aws/credentials", True, tmp)
    ok = marker_who in out and marker_note in out
    return ok, out[:200]


def _builtin_catalogue() -> dict:
    """The built-in English texts, read out of the hook without running it."""
    import ast

    tree = ast.parse(HOOK.read_text(encoding="utf-8"))
    node = next(n for n in tree.body
                if isinstance(n, ast.Assign)
                and getattr(n.targets[0], "id", "") == "_MESSAGES")
    scope: dict = {}
    exec(compile(ast.Module(body=[node], type_ignores=[]), "<catalogue>", "exec"),
         scope)
    return scope["_MESSAGES"]


def check_shipped_language_files_are_complete():
    """Every shipped language file covers the whole catalogue, placeholders included.

    A missing key is not an error in itself (English fills in), but a file that
    TRAVELS WITH THE HOOK claims to be complete. And a placeholder that does not
    fit turns the message into a key dump — which nobody would notice.
    """
    english = _builtin_catalogue()

    def placeholders(text: str) -> set:
        return set(re.findall(r"{(\w+)}", text))

    problems = []
    for path in sorted((HOOK.parent / "lang").glob("*.json")):
        texts = json.loads(path.read_text(encoding="utf-8"))
        translated = {k: v for k, v in texts.items() if not k.startswith("_")}
        for key in sorted(set(english) - set(translated)):
            problems.append(f"{path.name}: no text for {key}")
        for key in sorted(set(translated) - set(english)):
            problems.append(f"{path.name}: {key} has no counterpart in the code")
        for key in sorted(set(english) & set(translated)):
            if placeholders(english[key]) != placeholders(translated[key]):
                problems.append(f"{path.name}: {key} placeholders differ")
    return not problems, "; ".join(problems)


# Keys whose text is EMBEDDED into another message ({reason}, {why}). The frame
# around them passes the verdict, so these must not pass one themselves —
# otherwise the refusal says BLOCKED twice. That is not a style question: the
# shipped German file used to open with its own verdict, and the code cut the
# ENGLISH prefix off to compensate, which of course never matched.
_EMBEDDED_KEYS = (
    "read.always_blocked", "read.needs_override", "read.env_file_inline",
    "read.env_file_bash", "read.dir_always_blocked", "read.dir_credentials",
    "mcp.gated", "mcp.why_sensitive_server", "mcp.why_not_readonly",
)
_OPENS_WITH_VERDICT = re.compile(r"^\s*(ALWAYS\s+BLOCKED|BLOCKED|IMMER\s+BLOCKIERT"
                                r"|BLOCKIERT)\b", re.IGNORECASE)


def check_embedded_reasons_pass_no_verdict():
    """An embedded reason must not judge — the frame it sits in does that."""
    catalogue = dict(_builtin_catalogue())
    sources = {"built-in": catalogue}
    for path in sorted((HOOK.parent / "lang").glob("*.json")):
        texts = json.loads(path.read_text(encoding="utf-8"))
        sources[path.name] = {k: v for k, v in texts.items() if not k.startswith("_")}

    problems = []
    for origin, texts in sources.items():
        for key in _EMBEDDED_KEYS:
            text = texts.get(key)
            if text and _OPENS_WITH_VERDICT.match(text):
                problems.append(f"{origin}: {key} opens with its own verdict")
    return not problems, "; ".join(problems)


CASES = [
    ("embedded reasons pass no verdict", check_embedded_reasons_pass_no_verdict),
    ("hard block stays hard when translated", check_hard_block_stays_hard),
    ("hard block via directory stays hard", check_hard_block_via_directory),
    ("gated read keeps its escalation", check_gated_read_keeps_its_escalation),
    ("verdict is passed exactly once", check_verdict_is_passed_once),
    ("building blocks are translated too", check_building_blocks_are_translated),
    ("shipped language files are complete", check_shipped_language_files_are_complete),
]

try:
    import pytest

    @pytest.mark.parametrize("name,fn", CASES)
    def test_language_neutral_behaviour(name, fn):
        ok, detail = fn()
        assert ok, f"{name}\n{detail}"

except ImportError:
    pass


if __name__ == "__main__":
    failures = 0
    for name, fn in CASES:
        ok, detail = fn()
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            print("      " + detail.replace("\n", "\n      "))
    raise SystemExit(0 if not failures else 1)
