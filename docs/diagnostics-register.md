# The diagnostics register — a second hook

`hooks/diagnostics-register.py` is **not** a security check. It is in this repo
because it answers the same kind of question with the same kind of mechanism:
what does an AI do reliably wrong, and what can be put in its way?

### The problem it solves

Language-server warnings arrive as an **attachment**, not as an answer. The
filter "not my change, pre-existing code" is right most of the time and
therefore runs automatically — and that is exactly when it takes the one real
warning with it.

The measured cost, in this repo: `"delete_only" is possibly unbound` was shown
twice on the same day, on two different working copies, directly under the edit
result. Filed away both times. It was a crash in the most common branch of the
write check, and it survived 13 local test lists and 2993 test cases here,
because a crash and a considered denial exit with the same code. Someone else
had to trip over it.

A resolution cannot fix that, because nothing about it is a decision. A hook
can.

### The five states

| state | who sets it | why |
|---|---|---|
| `open` | the hook, automatically | starting state |
| `fixed` | **nobody** — the tool runs pyright and looks | a measurement, not a claim. Harder to forge than a marking, and it keeps the owner out of the common case entirely |
| `parked` | the AI, with a **reason and a deadline** | "it goes away once X lands" is a real case. The deadline is the price: parking is a postponement, not a disappearance |
| `dismissed` | **the owner only** | the single path on which a real warning falls silent for good — whoever may walk it alone can switch the hook off |
| `moot` | nobody — the file is gone | a finding, not a decision. Not deleted: if the file returns and the warning with it, it is recorded again |

Whatever stays `open` is presented once every 24 hours — **the oldest case
concretely**, with file, line and how long it has been standing. Not a count. A
message saying "3 open items" is the same wallpaper in two weeks that the
warnings themselves are today.

### Why the filter is on the rule name, not the severity

This is the number that decides whether such a hook survives contact with
everyday work. Measured over 15942 real diagnostics from 570 transcripts:

```
Error    8964      <- of these, 3720 are reportMissingImports (41%)
Hint     6954
Warning    24
```

`reportMissingImports` is pyright not finding the virtual environment while the
file is perfectly fine. **A hook keyed on severity fires on almost every edit
and is switched off within a week.**

The four rules it does watch — `reportPossiblyUnboundVariable`,
`reportUndefinedVariable`, `reportRedeclaration`,
`reportSelfClsParameterName` — are decidable without import resolution,
checkable in seconds, and a hit is nearly always a real defect. Together they
are **2.1 percent** of all diagnostics. Over 30 days that worked out to roughly
two entries per week that actually needed presenting.

### Installing it

```jsonc
// ~/.claude/settings.json
"hooks": {
  "Stop":         [{ "hooks": [{ "type": "command",
                     "command": "python3 ~/.claude/hooks/diagnostics-register.py stop" }] }],
  "SessionStart": [{ "hooks": [{ "type": "command",
                     "command": "python3 ~/.claude/hooks/diagnostics-register.py start" }] }]
}
```

Needs `pyright` on the PATH. To keep the AI from editing the register
directly, add its directory to `blocked_paths_write` in your rules — the AI
then reaches it only through the tool, and the tool enforces the state rules.

### Two things worth knowing before you build on it

**The anchor is `Stop`, not `PostToolUse`.** Measured: at the moment a
`PostToolUse` hook on an edit runs, the diagnostics do not exist yet — the
language server has not answered. They appear in the transcript a few seconds
later. The timing is not deterministic either (sometimes they arrive with the
edit, sometimes only with the next tool call), which makes `Stop` the latest
and only reliable point.

**It guards against negligence, not against intent.** Anyone assembling the
register path at runtime writes past it — the same limit self-protection has,
named in THREAT-MODEL.md. That is the right trade: the opponent here is one's
own autopilot, not an attacker.

---

---

[Back to the README](../README.md)
