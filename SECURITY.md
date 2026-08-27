# Reporting a bypass

This project asks people to look for ways around it. That request needs a
route that is not a public issue, or the first person who finds something has
no choice but to publish it.

## Where to send it

**Use GitHub's private vulnerability reporting** — the *Report a vulnerability*
button under [Security](https://github.com/inoX-Network/claude-code-safety-guard/security).
It opens a private thread with the maintainer; nothing is visible to anyone
else.

If that is unavailable to you, open a public issue with **no working payload**:
say which class of bypass you found and roughly where, and ask for a private
channel. A sentence like "the interpreter branch can be reached through X, I
would rather not post the details" is enough to start.

## What counts

A **bypass** is anything that makes the guard allow what it means to refuse:

- reaching a self-protected path (the hook, the rules, the settings, the shell
  startup files, another tool chain's control files)
- reading a credential the read protection is meant to hold back
- getting a blocked pattern past the command check by rewriting it
- an override that grants more than its level should, or reaches an agent it
  was not bound to
- the hook failing open — crashing, timing out, or allowing when its input or
  its rules are missing or malformed

Also welcome, and treated the same way: **the guard reporting readiness it does
not have.** An installation that looks armed and is not is the failure this
project is most afraid of, and it has happened — see the tools under `tools/`.

## What does not count

The [threat model](THREAT-MODEL.md) names what this deliberately does not try
to do. In short: it is a deterministic filter in front of tool calls, not a
sandbox, not a permission system, and not protection against someone with a
shell on the machine. The owner's own `!` bypasses it on purpose.

A false alarm — the guard blocking something harmless — is a bug worth
reporting, but through a normal issue. It costs work, not safety.

## What happens next

You get an acknowledgement, and a question if anything is unclear. A confirmed
bypass is fixed with a regression test that fails without the fix; the test
goes into the suite so the same hole cannot come back quietly. The
[changelog](CHANGELOG.md) records the fix, and credits you unless you would
rather it did not.

This is a one-person project, so there is no response-time promise. There is a
promise about substance: a report is answered on its merits, and a report that
turns out to be right is not argued away.

## Supported versions

Only the current `main` receives fixes. Versions are dated
(`VERSION`, `YYYY.MM.DD`) and released as tags; there is no long-term support
branch and no backporting.
