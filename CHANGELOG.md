# Changelog

Versions are dates (`YYYY.MM.DD`) and match the `VERSION` file and the git tag
of the same name.

Every entry says whether it changes **what the guard blocks**. The update check
tells you a newer version exists; this file is where you find out whether that
matters to you. Entries marked **security** close a way around the guard.

---

## 2026.08.30

### Fixed — the guard

- **security-adjacent (false positive)** — The target extraction added in
  2026.08.29 read the WHOLE command line, while the path match reads only the
  segments that write. A reading segment naming the protected parent therefore
  poisoned the verdict: `rm -rf <granted dir> && ls <parent>` was refused
  although nothing outside the grant is written. The guard has drawn that
  segment boundary since 2026.08.20; the new function was walking around it.
  Both now use one shared helper, so they cannot drift apart again. Found by a
  live probe against the sharp installation, not by the suite — no test case
  named a protected path in a reading segment while holding a grant.

## 2026.08.29-2

### Fixed — the guard

- **security** — The fallback ruleset said "fail-closed" and left three things
  out. With the rules file missing, `owner_only_commands`, `blocked_git_ops` and
  `blocked_paths_delete` were simply absent, so the approval scripts became
  ordinary commands, `git reset --hard` and `--no-verify` ran, and the tool
  chain's transcripts and memory could be deleted. Worse as a chain: the rules
  file's parent directory is not protected, the pending directory is open by
  design, and the approval script was the third step — three allowed operations
  and the assistant holds a level-2 grant, with the guard printing "FALLBACK
  ruleset active (fail-closed)" throughout. All three keys are now in the
  fallback. Reported 2026-08-29 by an external review.

### Fixed — the tools, not the guard

- `tools/verify-install.py` now checks the three places where an installation
  is wrong and **nothing complains**: `update_check.enabled` on with no
  SessionStart hook running the checker; a missing `VERSION` file next to the
  hook (the checker then stays silent, which is indistinguishable from "you are
  up to date"); the assistant's rules document; and the proposal directory,
  without which the documented approval path ends in an error the owner never
  sees. Silent when the update check is off — a tool that nags about a feature
  nobody switched on is not read when it matters.
- `tools/would-it-help.py` pointed at a "setup dialogue" that does not exist
  anywhere in the repository. It now names the rules file and the configuration
  reference.

### Documentation

- The README claimed `sha256sum <protected file> > /tmp/sum.txt` is refused.
  Measured: it runs — the redirect target is what counts. Copying *onto* a
  protected path with a harmless redirect appended is still refused. The
  documented false positive had been fixed and the text never followed.
- Level 1 now says what a grant covers: what it names and what lies below it,
  not the directory above.
- The approval channel section covers session binding and `--all-sessions`.
  Without it, following the README literally produces an error the README does
  not explain — and other tool chains, which may not export
  `CLAUDE_CODE_SESSION_ID`, hit it every time.

### Changed — the example rules

- `blocked_paths_delete` now also lists the guard's own directories
  (`~/.claude/hooks`, `bin`, `rules`, `safety-guard`). Self-protection covers
  the FILES in them; naming the DIRECTORY removed them as a side effect — the
  documented ancestor-delete limitation, applied to the rules file itself.
  Measured over 216,972 real commands: 88 delete forms hit `~/.claude/hooks`, 1
  of which had been allowed.

## 2026.08.29

### Fixed — the guard

- **security** — A level-1 grant covered more than it named. `check_blocked_paths`
  reports which LIST ENTRY matched, and that entry — not the path the command
  actually touches — was what the grant was checked against. A grant on
  `~/.ssh/config.d` therefore opened all of `~/.ssh`: `authorized_keys`, the
  private key, `rm -rf ~/.ssh`. On an installation whose rules list directories
  (`/etc`, `/opt/inox`) rather than single files, a deployment grant on one
  service opened every other service and the recursive delete of the whole tree
  — the exact operation level 1 says it does not allow. The grant is now checked
  against the concretely touched target, and against the DEEPEST list entry that
  covers it, so a grant on a zone no longer swallows a more specific entry
  below it (`/etc` no longer covers `/etc/shadow` when both are listed).
  Reported 2026-08-29 by an external review, measured on both editions.

## 2026.08.27-3

### Fixed — the guard

- **security** — The shell rewrites a command after the guard has read it, and
  self-protection was reading the spelling that never executes. Empty quote
  pairs (`~/.claude/set''tings.json`) and brace lists
  (`~/.claude/{settings,x}.json`) both reached protected paths that the plain
  spelling could not — no tool, no encoding, no override. Both are undone
  before any check now, along with the IFS splitting that was already handled.
  Globbing is deliberately *not* expanded: its result depends on the
  filesystem, so a pattern is held against the protected list unexpanded
  instead.


### Fixed — the tools, not the guard

- **security (reporting)** — `tools/verify-install.py` never read the `matcher`
  field. An installation registering the guard for `Bash` alone, leaving
  `Read`, `Write`, `Edit`, `MultiEdit`, `NotebookEdit` and the `mcp__*` family
  unguarded, was reported as `12 ok, 1 to look at, 0 broken` with exit code 0.
  The behavioural probes cannot see this: they drive the hook directly, so they
  prove what it decides, never whether it is asked. The matcher coverage is now
  checked — accepting an absent or empty matcher, which covers every tool and
  is the safest configuration there is.
- `verify-install.py`: all registered entries are checked for their file, not
  just the first; a mismatch between the interpreter in `settings.json` and the
  one running the probes is reported; a half-present approval channel no longer
  passes in silence; `--strict` lets warnings decide the exit code.
- **`tools/would-it-help.py` counted this repository's own probes as evidence.**
  `verify-install.py` writes to the real audit log by design, and six in ten of
  its probes are blocks. On a fresh installation those were the entire sample,
  and the report concluded "60 % would have been stopped — expect real
  friction" from its own test material. Own sessions are skipped now, and below
  30 commands no rate is printed at all.
- `would-it-help.py`: the exposure scan looked in six directory names. Work in
  `~/git`, `~/repos`, `~/workspace` or a writable system location counted as
  "nothing found", which the verdict turned into advice against installing.
  Eleven names now plus writable system locations, package directories skipped
  (0.3 s over five locations, against 4.0 s over one before), and an empty
  result says where it looked.
- `would-it-help.py`: `--yes` no longer swallows the notice about what will be
  read.

### Fixed — tests

- Four test files gave different answers depending on where they were run.
  `test_relative_write_targets` needed a real `~/.claude` and died with a
  traceback without one; `test_command_position` inherited the caller's working
  directory and went red from a clone standing on `main`, where a second and
  unrelated rule applies; `test_remote_copy_and_branch_guard` needs `git` and
  `test_diagnostics_register` needs `pyright`, and both now skip instead of
  failing. The diagnostics file also detects a checkout inside a throwaway
  location, which used to turn nine cases red for a reason unrelated to the
  hook.
- `requirements-dev.txt` names what the suite needs.

### Documentation

- The self-protection table was missing `~/.claude/guard-config.json` — the
  file that says where the rules live. It **is** protected; only the table did
  not say so, which made a strength look like a hole.
- The README said "six tool matchers" where INSTALL.md said seven. Prose no
  longer counts: it points at `settings.example.json`, and a test asserts that
  file is complete.
- Blocking `git commit` on a protected branch is documented — it surprises
  people, and it reached into this project's own test suite.
- Reference sections moved to `docs/` (configuration, tool chains, diagnostics
  register, what's new in v2). The counter-test documents moved to
  `docs/counter-tests/`.
- `SECURITY.md`, `CONTRIBUTING.md` and this file added.

---

## 2026.08.27

- **security** — A single asterisk walked past the self-protection. A write
  target containing `*`, `?` or `[…]` is now held against every protected path
  component by component; patterns are never expanded, because that would make
  the verdict depend on the filesystem (#55).
- **security** — Force-push written as a `+refspec` (`git push origin
  +main:main`) was not recognised as a force-push (#64).
- Documentation: the container guard and glob matching (#56), the tool chains
  and what each covers (#54), and that the repository talks to assistants
  (#63). INSTALL.md corrected to seven PreToolUse matchers — the `mcp__.*`
  entry was missing, so MCP tool calls reached no guard on installations that
  followed it (#65).
- New: `tools/verify-install.py` (#58) and `tools/would-it-help.py` (#59, #61,
  #62), `AGENTS.md` (#60).
- Tests: check for zero failures rather than an expected case count (#57).

> Honest note: the version was bumped in #56, a documentation change, and the
> security fix #55 nine minutes earlier rode along with it. #64, a second
> security fix, landed the same day **after** the bump and was therefore never
> announced by the update check — dates cannot separate eleven commits in one
> day. That is why tags exist from here on.

## 2026.08.23

- **security** — Shell variables are resolved in the interpreter branch, so a
  protected path assembled from a variable is caught (#52).
- A refused inline one-liner now says *why*: naming a protected path, not
  writing to it (#53).

> This bump exists because five guard changes had been shipped without one.

## 2026.08.22

- **security** — Self-protection now matches a path, not a prefix, in the
  interpreter branch. While only one of the two comparison branches had the
  boundary, the guard refused the very thing it is supposed to allow: dropping
  an override proposal.
- **security** — Quoted text is not a command. Two further holes were found
  behind that question, and the first attempt at the fix — a danger list rather
  than a harmless list — tore four more, which is why the final shape is the
  other way round.
- **security** — The shell's startup files are protected. A single line in one
  of them redefines what every later command means, which is the ground every
  other check stands on.
- **security** — Antigravity's control files are protected: the third tool
  chain can execute what this one writes (#49).
- New: the diagnostics register, a second hook (#50).

> This bump exists because three merged changes had been shipped without one.

## 2026.08.21 and earlier

Before this point the version file was not maintained per change. The history
is in the commit log; the substantial entries of that day were: delete
protection as a second path list, owner-only commands matched by command
position rather than by text, redirect targets treated as writes, the adapter
contract for a second tool chain, and self-protection extended to that
adapter's own files.
