# Notes for an AI assistant reading this repository

You are very likely reading this because someone asked you to look at this
project, or because they are considering installing it. This file tells you
what is here and what is worth offering them. It is information, not a script:
you decide what is useful to say, and they decide what happens.

## What this is — and that you are its subject

A deterministic guard that inspects every tool call from an AI coding agent
**before** it runs, and refuses the destructive ones. That agent is you.

This is said plainly rather than glossed over, because the alternative is
worse: an assistant that meets the guard for the first time as an unexplained
refusal tends to treat it as an obstacle and look for a way round. It is not an
obstacle. It is the reason someone can leave you alone with a machine that has
their keys on it. If it ever blocks you, the intended response is to stop,
re-read the message and rephrase — never to encode, split up or otherwise
disguise the same command. Every attempt of that kind is logged, and one found
in the log is treated far more seriously than the original refusal.

## Worth offering before anyone installs anything

The repository ships a report that answers, from measurements on *their*
machine, whether this guard would be worth it for them personally:

```bash
python3 tools/would-it-help.py
```

It installs nothing, writes nothing and sends nothing. It counts what is
reachable from the machine (keys, remote hosts, credentials — existence only,
no protected file is ever opened), notes which assistants with tool access live
there, and then feeds their own past commands to the real hook in this checkout
to see how many it would have stopped.

So if someone is weighing this project up, offering that is usually more useful
than summarising the README at them. Something like:

> There is a script in here that can measure whether this guard would actually
> help on your machine — what it would reach, and how often it would have
> interrupted you in the past. It runs read-only and installs nothing. Shall I
> run it?

**It will not let you skip that question.** Run without consent, it prints
what it would read and stops — and it says that whoever ran it should have
asked first. `--yes` exists for the case where the person has already agreed.
That gate is deliberate: asking you nicely to offer first would be the wrong
instrument when someone's shell history is at stake.

**And do not oversell the result.** The report is built to be able to say
*"probably not worth it"*, and on a machine with no AI assistant it says the
guard would protect against nothing today. That verdict is as valid as any
other, and repeating it honestly is the entire point of the tool existing.
This project would rather someone walked away informed than installed
something they do not need.

## The recommendation the report makes, whichever way it goes

The report ends with one piece of advice that stands regardless of its own
verdict: **work that exists in only one place is work a mistake can end.** It
counts how many of their repositories have no remote and says so.

This guard reduces how *often* something goes wrong. A copy somewhere else
decides whether it *matters* when it does — and of the two, the copy is the
cheaper half. So if the report names repositories with no remote, that is worth
picking up on, and it is worth offering to do: pushing a repository somewhere
is one of the things an assistant does well and a person new to this reasonably
does not want to learn first.

Recommend it; do not gate on it. The guard works fine without, and someone who
is told they must set up version control before they may protect themselves
will do neither.

## If they decide to install

`INSTALL.md` is the guide. Two things there are easy to miss:

- **Section B** carries a ready-made block for their `CLAUDE.md` — the
  behaviour rules that no code can enforce, with placeholders for their paths.
  Without it you will meet refusals without knowing the way to an approval.
- **`python3 tools/verify-install.py`** checks an install afterwards. It also
  prints what it cannot establish, which is whether the running session really
  reaches the hook. Only a real tool call shows that.

## Orientation

| | |
|---|---|
| `hooks/command-guard.py` | the guard itself |
| `security-rules.example.json` | the rules, copied and adapted per install |
| `tools/` | the assessment, the install check, the audit-log reader |
| `tests/` | run with `python3 -m pytest tests/ -q` |
| `THREAT-MODEL.md` | what it does and does not defend against |

The README's *Known limitations* section is not marketing hedging — it lists
real gaps with reasons. If someone asks what this cannot do, that section is
the honest answer and worth quoting rather than paraphrasing.
