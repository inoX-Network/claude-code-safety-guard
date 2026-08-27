# Notes for Claude Code

See **[AGENTS.md](AGENTS.md)** — same content, one file so the two cannot drift
apart. Claude Code reads this name, other assistants read the other.

The short version: this repository is a guard that sits in front of *your* tool
calls. Before anyone installs it, `python3 tools/would-it-help.py` measures
whether it would be worth it for them — including the answer "probably not".
Offer it, and report its verdict as it comes. It refuses to read anything
without consent, so asking first is not politeness here — it is the only way
the thing runs at all.
