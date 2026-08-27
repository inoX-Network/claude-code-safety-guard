# Contributing

## Running the tests

```bash
pip install -r requirements-dev.txt
python3 -m pytest tests/ -q
```

Around 3150 cases across 50 files. The guard itself has no dependencies —
standard library only, on purpose — so the suite needs nothing installed
either, and nothing in it touches your real `~/.claude`.

Two tools decide how much can be measured rather than whether anything runs:

| Tool | What it unlocks | Without it |
|---|---|---|
| `git` | five cases that build a real repository to check the branch rules | they skip |
| `pyright` | two cases that measure "fixed" by re-analysing a file | they skip |

One case needs a real installation at `~/.claude` and skips where there is
none. **A skip means "not measured here", never "passed".**

### Where the suite is run matters

Two of these are worth knowing before you report a red test:

- **Run it from a normal directory.** The diagnostics hook ignores throwaway
  locations (`/tmp`, `scratchpad`, archives) on purpose, so a checkout inside
  one filters out its own test bench. The suite detects that and skips with an
  explanation rather than turning nine cases red.
- **Committing on `main` is blocked by the shipped rules.** That is a feature,
  and it used to reach into the tests: cases that inherited the caller's
  working directory got a different verdict from a clone standing on `main`
  than from anywhere else. They now state their working directory. If you add
  a case, do the same — pass `cwd` explicitly in the payload.

## Adding a rule or a fix

- **A fix comes with a test that fails without it.** Not a test that passes
  afterwards — one that goes red when the fix is removed. If you are unsure it
  measures what you think, take the fix out and watch it fail.
- **Say what you measured.** Numbers from your own machine are worth more than
  reasoning about what should happen. "Replayed 77,718 logged commands, 20
  previously refused now pass, none newly blocked" is the standard the existing
  comments set.
- **A new block must be checked against real commands**, not only against the
  case that motivated it. A rule that fires on everyday work gets switched off,
  and a guard that is switched off protects nothing.
- **Comments explain WHY, in whole sentences.** The unusual density of comments
  in this codebase is deliberate: most of them record a wrong first attempt.
  Those are the valuable ones.

## What to be careful with

`hooks/command-guard.py` decides every tool call. Changes there are read
closely, and a change that makes it more permissive needs a measurement, not
an argument.

The self-protection list is hardcoded rather than kept in the rules file. That
is not an oversight: a protection the rules could switch off is not a
protection. Keep it that way.

## Reporting a bypass

Not here. [SECURITY.md](SECURITY.md) has a private route — please use it before
posting a working payload.

## Style

- English for everything published: code, comments, documentation.
- No dependencies in the hook. Standard library only.
- Line length is not enforced; readability is.
