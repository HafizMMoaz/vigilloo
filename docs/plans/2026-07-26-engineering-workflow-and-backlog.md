# Engineering Workflow and Implementation Backlog

**Status:** reference. This is the working process document for the repo and the
atomized v0.1 task list. It records the workflow that already exists rather than
inventing a new one, and it is normative only where it restates `CLAUDE.md`,
`docs/23-dev-guide` or a subsystem spec - those remain the source of truth.

Produced 2026-07-26, repository inspected at `f6c3074` (slices 1-4 merged). Slice 5
(workspace) and slice 6 (SQLite store, TASK-006 and TASK-007 below) landed after it
was written; task entries are not rewritten as they ship, the `**Status:**` line of
each `docs/plans/` design and the Status paragraph in `CLAUDE.md` carry that.

One correction, since several tasks inherit it: every entry naming
`src/workspace/store.py` should read `src/store.py`. `docs/23-dev-guide` section
Repository layout is normative and puts the store under `graph/`, with `workspace/`
holding root, config and run manifest. The store therefore stays a flat module beside
`graph.py` until TASK-116 moves the flat modules into their subpackages together.
Affected: TASK-007, TASK-008, TASK-111, TASK-115.


# Engineering Workflow

Vigilloo Engineering Workflow
Derived from the repository as it stands at f6c3074 (slices 1-4 merged).
This document describes the workflow that already exists. It invents no new
process and duplicates no existing document.

## 0. What this repository actually uses

Before answering the questions, here is what the inspection found. Several of the
files a generic workflow assumes do NOT exist here, and their function is served
elsewhere.

| Concern              | Where it lives in this repo                              | File |
| -------------------- | -------------------------------------------------------- | ---- |
| Source of truth      | docs/NN-*/README.md, one per subsystem. Explicitly        | docs/00-...24-*/README.md |
|                      | normative: "Docs are the spec"                            | |
| Architecture         | docs/02-architecture (shape, layering), plus per-slice     | docs/plans/YYYY-MM-DD-slice-N-design.md |
| decisions            | decision records                                          | |
| Implementation       | Three places, none of them a status file: the Status      | CLAUDE.md, docs/plans/*.md, |
| status               | paragraph in CLAUDE.md, the **Status:** line at the top   | .github/workflows/ci.yml |
|                      | of each plan, and the CI wheel smoke test that asserts    | |
|                      | exact finding counts                                      | |
| Roadmap              | Capability-scoped release list, not a task list           | docs/24-roadmap/README.md |
| Technical debt       | ponytail: comments at the point of the shortcut, 15       | src/**/*.py (grep) |
|                      | currently, each naming the ceiling and the upgrade path   | |
| Coding standards     | Two layers: agent-facing rules and human-facing standards | CLAUDE.md, docs/23-dev-guide/README.md |
| How docs get updated | Same commit as the behaviour change. Stated twice, in     | docs/23-dev-guide, section Documentation |
|                      | both standards files                                      | |
| How completed work   | Conventional commit on a slice-N-<topic> branch, merged   | git history (PRs #1-#3) |
| is recorded          | by PR, plan Status flipped to implemented, CI assertions  | |
|                      | updated                                                   | |

Genuinely missing: CHANGELOG.md. It is the only artifact in the standard set with
no existing equivalent here, and docs/23-dev-guide section "Commits and releases"
already promises semver releases that record a ruleset hash. See section 6.

## 1. Repository Memory

Read before EVERY task, in this order:

1. CLAUDE.md
   The non-negotiable invariants, the src/-is-the-package layout rule, and the
   current Status paragraph. This is the only file that tells you what is already
   built.

2. docs/23-dev-guide/README.md
   Layout, standards, the "Adding a rule" procedure, the "Adding a framework
   adapter" procedure.

3. docs/02-architecture/README.md
   The pipeline and the layering rule (each subsystem knows only the one below
   it). Most architecture violations are caught by re-reading this before
   designing.

4. docs/24-roadmap/README.md
   Confirms the task belongs to the current version. v0.1 is Laravel-only;
   anything else is out of scope by decision, not by omission.

Read in addition, scoped to the task:

5. The subsystem doc for what you are touching. Non-optional. These contain
   decided schemas, sink tables and resolution strategies that are expensive to
   rediscover and easy to contradict. The mapping is the docs/README.md index
   table.

6. The most recent docs/plans/*.md touching the same area. Later slices build on
   earlier ones and record what was deliberately deferred.

7. grep -rn "ponytail:" src/   filtered to the modules in scope. Every known
   shortcut is annotated where it lives. A task that removes one should say so.

8. pyproject.toml if the task adds a directory under src/. Both package-dir and
   packages must gain an entry or the wheel silently omits it.

There is no project_state.md and no separate rules file. Do not create them:
their content is in CLAUDE.md and docs/23-dev-guide, and a second copy will drift
within a month.

## 2. Repository Rules

### The eight invariants (from CLAUDE.md, breaking one is a design error)

 1. The AI engine cannot create or delete a finding. Deterministic results
    identical with AI on and off, asserted in CI.
 2. Every finding carries a complete evidence path. Enforced in code:
    Finding.__post_init__ raises on an empty path.
 3. Node and finding IDs are content-derived, never autoincrement. Findings also
    carry a location-independent fingerprint.
 4. Coverage is reported, never hidden. Parse failures and unresolved call edges
    appear in every report.
 5. Analysed code is untrusted input. Never executed, never imported, delimited
    as data when sent to an LLM.
 6. Offline is complete. Only the AI layer and advisory refresh may require
    network.
 7. Rule IDs are permanent. They ship in SARIF, baselines and // vigilloo-ignore
    comments.
 8. Determinism. Same input plus same ruleset produces byte-identical JSON, AI
    excluded.

### Layout rules (breaking either fails quietly)

 9. Imports inside src/ are relative. from .models import Finding. There is no
    vigilloo/ on disk.
10. Every new subpackage is registered in pyproject.toml, in both tables. CI
    builds the wheel and installs it clean for exactly this reason. Do not remove
    that step.
11. Do not "fix" the layout back to src/vigilloo/. It is a deliberate decision.

### Architectural rules

12. Layering: parser has no Laravel awareness; graph engine has no security
    awareness; security engine has no LLM awareness. PathStep.rule_id being an
    opaque string exists to hold this line.
13. Two producers, one dispatcher. Taint paths and structural paths both yield
    list[PathStep] and name their rule on the final step. A structural rule never
    needs taint state.
14. Taint is kind-based, not boolean. A new sink arrives with its kind, its
    sanitizers and its fixtures, or it does not arrive.
15. Argument-precise sinks. whereRaw('age > ?', [$age]) is safe. Flagging every
    *Raw is the noise that gets the tool switched off.
16. No global state. Everything reaches code through the project or plugin
    context.
17. Never regex-parse a programming language. Blade rewriting is the one bounded
    exception, and it is annotated as such.

### Process rules

18. Docs update in the same commit as any change to detection behaviour, the
    Finding schema, plugin interfaces or the CLI surface.
19. Negative fixture before the rule. A rule written before its negative case
    reliably over-fires.
20. No em dashes anywhere. Use a hyphen.
21. Never add Claude as co-author or collaborator on any commit or PR.
22. No TODOs, no dead code. Deferred work is a ponytail: comment naming the
    ceiling and the upgrade path, or it is a backlog item.
23. Conventional commits, semver. CLI and SDK version independently.

## 3. Development Workflow

One task per branch, 30 minutes to 2 hours of engineering work.

 1. Read           CLAUDE.md, 23-dev-guide, 02-architecture, the subsystem doc,
                   the latest relevant docs/plans/*.md, ponytail: markers in
                   scope.

 2. Check scope    Does the task violate a section 2 rule or a spec decision?
                   If yes: STOP. Explain. Propose the compliant alternative.
                   Do not write code until the architecture is preserved.

 3. Branch         git checkout -b slice-N-<topic>       (existing convention)

 4. Plan           New capability or a slice boundary: write
                   docs/plans/YYYY-MM-DD-slice-N-design.md with Status:
                   designing, the goal stated as observable scan output, and
                   explicit non-goals. A single task inside an existing slice
                   needs no new plan.

 5. Fixtures       Write the positive AND negative case first, under
                   tests/fixtures/laravel-minimal/. The negative case is the one
                   that decides whether the rule is usable.

 6. Implement      Smallest change that satisfies the spec. Relative imports.
                   Frozen dataclasses. Full type hints. Register any new
                   subpackage in pyproject.toml, both tables.
                   Deliberate shortcut: leave a ponytail: comment naming the
                   ceiling and the upgrade path.

 7. Verify         uv run pytest
                   uv run ruff format --check .
                   uv run ruff check
                   uv run mypy
                   All four, all green, before claiming completion.
                   Changed the fixture finding count? Update the CI wheel smoke
                   assertion in .github/workflows/ci.yml or CI fails on merge.

 8. Document       Per section 4. Same commit.

 9. Commit         Conventional commit. No Claude trailer, no em dashes.

10. PR             gh pr create. Merge to main after CI passes.

Step 2 is the one that matters. The specs contain decided details. A task that
contradicts one is either a spec change (update the doc first, in its own commit,
with the reasoning) or a mistake.

## 4. Documentation Workflow

After a completed task, update exactly the documents whose contract changed.
Nothing else.

| What changed                       | Update                                    | Why |
| ---------------------------------- | ----------------------------------------- | --- |
| Detection behaviour, a new rule, a | The subsystem doc: docs/06-taint-analysis | The docs are normative. A rule not in |
| new sink or sanitizer              | for vocabulary, docs/13-security-engine   | its table does not officially exist. |
|                                    | for the rule catalogue,                   | |
|                                    | docs/08-framework-adapters for Laravel    | |
|                                    | facts                                     | |
| A capability became real           | The Status paragraph in CLAUDE.md         | The only running statement of what is |
|                                    |                                           | built versus spec-only. |
| A slice finished                   | The **Status:** line in                   | How completed work is recorded |
|                                    | docs/plans/<slice>.md, to implemented     | per-slice. |
| Fixture findings changed in number | The grep assertions in                    | These assertions are the executable |
| or rule ID                         | .github/workflows/ci.yml                  | status record. Stale ones fail build. |
| The Finding schema, plugin         | docs/13-security-engine,                  | Named explicitly in docs/23-dev-guide |
| interfaces or the CLI surface      | docs/11-plugin-sdk, docs/19-cli           | as same-commit obligations. |
| A new src/ subpackage              | pyproject.toml (both tables) and the      | Unregistered means silently absent |
|                                    | layout block in docs/23-dev-guide         | from the wheel. |
| A new spec document                | The index table in docs/README.md         | The index is how every future session |
|                                    |                                           | finds the doc. |
| A version shipped                  | CHANGELOG.md once it exists (section 6),  | Currently unrecorded anywhere. |
|                                    | and the ruleset hash per docs/17-database | |

Do NOT create: project_state.md, tech_debt.md, architecture_decisions.md,
roadmap.md, engineering_rules.md. Every one duplicates something above, and a
duplicated spec that disagrees with the original is worse than a missing one.

A deferred decision is recorded as a ponytail: comment at the site, not in a debt
file. The comment names the ceiling and the upgrade path.
grep -rn "ponytail:" src/  is the debt report, and it cannot go stale because it
lives beside the code it describes.

## 5. Conversation Workflow

### Compact when

- A task is complete, checks are green, and docs are updated. This is the natural
  boundary. The next task re-reads its own memory set anyway.
- The conversation has crossed a subsystem layer boundary, for example from
  parser work into rule work. The parser detail is no longer load-bearing.
- Exploration produced a large volume of file dumps that the conclusion has
  already absorbed.

### Start a new conversation when

- Starting a new SLICE or milestone. A slice has its own design plan, which is
  the context that matters, and carrying the previous slice's dead ends forward
  causes contradictions.
- The task is in a different subsystem, so the section 1 memory set is a
  different set of documents.
- A spec document changed during the session. The old reading is now wrong, and a
  fresh read is cheaper than a correction thread.
- Debugging has run long enough that early hypotheses are stale. Confirmed facts
  belong in the plan document, not in scrollback.

### Do not compact when

- Mid-task with checks unrun. An uncompleted verification step is exactly what
  gets lost.
- A design decision under discussion has not been written into a plan document.
  Write it first, then compact.

## 6. Recommended Improvements

Ordered by value. Each one adds capability without adding a second copy of an
existing document.

1. Add CHANGELOG.md. (The only genuinely missing artifact.)
   Four slices have shipped with no user-facing record. docs/23-dev-guide already
   promises semver, and invariant 7 makes rule IDs permanent, so the changelog is
   also where rule additions get announced. Keep-a-Changelog format, one entry
   per rule ID added. Does not duplicate the roadmap: the roadmap is
   forward-looking capability, the changelog is backward-looking release record.

2. Fix two live contradictions in docs/README.md.
   - Line ~13 says "Implementation has not started." Four slices are merged.
     Every future session reads this file early and will be misled.
   - The Licence section says "Open core. CLI, SDK, plugins, MCP and the graph
     engine are open source." LICENSE says "proprietary and confidential. All
     rights reserved." and CLAUDE.md says never add an open-source badge.
     docs/21-cloud describes an open-core boundary as a v3.0 decision. One of
     these is wrong today, and getting it wrong in the front-page doc is a
     commercial risk, not a documentation nit.

3. Add a Status column to the existing docs/24-roadmap v0.1 list.
   Not a new file. The roadmap already enumerates v0.1 capabilities as bullets.
   Turning that one list into a table with a Status column makes it the single
   implementation-status record and lets the CLAUDE.md Status paragraph shrink to
   a pointer. This is the closest thing to the project_state.md a generic
   workflow wants, achieved by editing one existing list.

4. Make the ponytail debt report generated, not written.
   A scripts/debt.py that greps ponytail: markers and prints file, line and text
   gives the tech-debt ledger with zero maintenance and zero drift risk. Print it
   in CI as an informational step so the count is visible on every PR. A
   hand-maintained tech_debt.md would be the same data with a staleness bug.

5. Build the expected.yml fixture harness that docs/22-testing already specifies.
   Currently fixture expectations are Python assertions spread across a dozen
   test files, plus grep assertions in CI. The spec defines a declarative format
   with findings: and must_not_find:. Implementing it makes adding a rule cheaper
   and makes must_not_find first-class, which is what keeps precision honest.
   This is TASK-015 in the backlog.

6. Add the determinism test and the coverage metrics gate.
   Invariant 8 is asserted nowhere. docs/22-testing specifies the exact test:
   scan a fixture twice, in different working directories, with different --jobs,
   diff the JSON. Cheap to write, and it is currently the least-defended of the
   eight invariants. Same for the parse-success and call-resolution rates, which
   docs/22-testing gates at 99.5% and 85%.

7. Pin the tool versions and add pip-audit.
   dev = ["pytest>=8.0", "mypy>=1.11", "ruff>=0.6"] means a new ruff release can
   break main with no change to the repo. docs/23-dev-guide section Security
   explicitly promises "pinned lockfile, pip-audit in CI. We do not get to skip
   our own advice." Currently unkept.

8. Add the pre-commit hook docs/23-dev-guide already references.
   It says "Both run in CI and in pre-commit." There is no pre-commit config.
   Either add it or drop the claim.

# Implementation Backlog

Vigilloo v0.1 Implementation Backlog
Derived from docs/24-roadmap v0.1, docs/22-testing ship gates, and the specs each
task cites. Follows existing conventions: rule IDs as spelled in
docs/08-framework-adapters and docs/13-security-engine, file paths relative to
repo root, docs updated in the same commit as behaviour.

This is not a new roadmap file. docs/24-roadmap remains the roadmap; this backlog
is its task-level decomposition and belongs in docs/plans/ if committed.

## Scope and method

Atomized: v0.1 only. It is the only release in docs/24-roadmap with a defined
ship gate ("the docs/22-testing corpus gates pass"). v0.5 and beyond are listed as
milestones without task breakdown at the end, because their specs decide
capability, not implementation order, and atomizing them now would produce tasks
that get rewritten before they are started.

Already implemented (slices 1-4, not in this backlog): PHP parsing, symbol
extraction, flat route table with middleware stack, call graph, kind-based
interprocedural taint for sql/html/mass_assign, Eloquent model config, policy
discovery, and the four rules php.sql-injection, php.xss,
laravel.mass-assignment, laravel.missing-authorization.

Difficulty scale: S = 30-60 min. M = 1-1.5 h. L = ~2 h (the cap).

Every task inherits these test requirements and they are not repeated per task:
uv run pytest, uv run ruff format --check ., uv run ruff check, uv run mypy all
pass, and if the fixture finding count changes, the CI wheel smoke assertion in
.github/workflows/ci.yml is updated in the same commit.

Total: 116 tasks across 14 milestones.

## MILESTONE A: PROCESS FOUNDATIONS
No code changes to the engine. Removes the documentation drift that every later
task would otherwise inherit. 5 tasks.

### TASK-001
- **Goal:** Front-page documentation stops contradicting reality.
- **Description:** docs/README.md states "Implementation has not started" and
  describes the project as open core, while LICENSE says
  proprietary and CLAUDE.md forbids open-source badging. Correct
  the status sentence to name the implemented slices, and resolve
  the licence sentence to match LICENSE. If open-core is genuinely
  intended for v3.0, phrase it as the future boundary
  docs/21-cloud describes, not as the current state.
- **Dependencies:** none
- **Acceptance:** No sentence in docs/README.md contradicts LICENSE, CLAUDE.md or
  the merged slices. The docs/21-cloud open-core boundary is
  referenced as a v3.0 decision, not a present fact.
- **Files:** docs/README.md
- **Difficulty:** S
- **Tests:** None. Documentation only. Verify by reading LICENSE and CLAUDE.md
  side by side.

### TASK-002
- **Goal:** Releases and rule additions have a user-facing record.
- **Description:** Create CHANGELOG.md, Keep-a-Changelog format, semver per
  docs/23-dev-guide section Commits and releases. Backfill entries
  for slices 1-4 from git history, listing the four shipped rule
  IDs explicitly, since invariant 7 makes them permanent public API.
- **Dependencies:** none
- **Acceptance:** File exists with an Unreleased section and one backfilled entry
  per merged slice. Every shipped rule ID appears exactly once. No
  em dashes.
- **Files:** CHANGELOG.md (new), README.md (link)
- **Difficulty:** S
- **Tests:** None.

### TASK-003
- **Goal:** Implementation status has one home instead of three.
- **Description:** Convert the v0.1 bullet list in docs/24-roadmap/README.md into a
  table with a Status column (done / partial / spec only),
  populated from the merged slices. Reduce the CLAUDE.md Status
  paragraph to a short summary plus a pointer. Creates no new file.
- **Dependencies:** TASK-001
- **Acceptance:** docs/24-roadmap v0.1 section is a status table. CLAUDE.md no
  longer restates the capability list. No information is lost.
- **Files:** docs/24-roadmap/README.md, CLAUDE.md
- **Difficulty:** S
- **Tests:** None.

### TASK-004
- **Goal:** The deliberate-shortcut ledger is generated, never stale.
- **Description:** Add scripts/debt.py printing every ponytail: marker as
  file:line  text, sorted, exit 0 always. Add an informational CI
  step running it. Fifteen markers exist today.
- **Dependencies:** none
- **Acceptance:** Script lists all 15 current markers. CI prints the report without
  gating on it. No hand-maintained debt file is created.
- **Files:** scripts/debt.py (new), .github/workflows/ci.yml
- **Difficulty:** S
- **Tests:** tests/test_debt_script.py asserting the script finds a marker in
  a temp file and exits 0 with none.

### TASK-005
- **Goal:** The toolchain cannot break main without a repo change, and
  Vigilloo follows its own dependency advice.
- **Description:** Pin pytest, mypy and ruff to exact minor ranges in pyproject.toml
  dev group. Add pip-audit to the dev group and a CI step, as
  promised in docs/23-dev-guide section Security. Add the
  .pre-commit-config.yaml that the same doc claims exists, running
  ruff format and ruff check.
- **Dependencies:** none
- **Acceptance:** A new upstream ruff release cannot change CI outcome. pip-audit
  runs in CI. docs/23-dev-guide's pre-commit claim is now true.
- **Files:** pyproject.toml, uv.lock, .github/workflows/ci.yml,
  .pre-commit-config.yaml (new)
- **Difficulty:** M
- **Tests:** CI green. pre-commit run --all-files clean.

## MILESTONE B: WORKSPACE AND PERSISTENCE
docs/17-database, docs/04-knowledge-graph. Everything downstream (incrementality,
baselines, graph, explain, report) reads from the store. Doing it before the rule
catalogue avoids rewriting every rule later. 9 tasks.

### TASK-006
- **Goal:** A Workspace object owns project root, config and store, replacing
  loose Path passing.
- **Description:** Create src/workspace/ with a frozen Workspace dataclass carrying
  root, .vigilloo/ directory and resolved config. Register in
  pyproject.toml both tables. docs/23-dev-guide section Standards
  requires everything reach code through Workspace rather than
  globals; today load_project takes a bare root.
- **Dependencies:** none
- **Acceptance:** Workspace.open(root) creates .vigilloo/ if absent. cli.scan
  constructs one and passes it down. Wheel smoke test imports
  vigilloo.workspace.
- **Files:** src/workspace/__init__.py (new), src/cli.py, pyproject.toml,
  .github/workflows/ci.yml, docs/23-dev-guide/README.md
- **Difficulty:** M
- **Tests:** tests/test_workspace.py covering creation, idempotent reopen, and
  refusal of a path outside the root (path traversal guard per
  docs/23-dev-guide section Security).

### TASK-007
- **Goal:** SQLite schema exists exactly as specified.
- **Description:** Implement projects, scans, files, schema_meta from
  docs/17-database section Schema, with the pragmas from section
  Pragmas. Schema DDL as a versioned constant, not scattered
  strings.
- **Dependencies:** TASK-006
- **Acceptance:** Store opens, applies pragmas, writes schema_meta.version. DDL
  matches the spec column for column.
- **Files:** src/workspace/store.py (new), docs/17-database/README.md if a
  column is corrected
- **Difficulty:** M
- **Tests:** tests/test_store.py asserting schema version, pragma values, and
  that reopening an existing DB does not re-run DDL.

### TASK-008
- **Goal:** Node and edge tables with their indexes.
- **Description:** Add nodes and edges plus the five indexes from docs/17-database.
  Batch insert helpers, since docs/23-dev-guide section Performance
  names N+1 SQLite queries as the dominant graph-construction cost.
- **Dependencies:** TASK-007
- **Acceptance:** 10k nodes insert in one transaction. Indexes present in
  sqlite_master.
- **Files:** src/workspace/store.py
- **Difficulty:** M
- **Tests:** Batch insert round-trip; index existence; insert of a duplicate
  content-derived ID is idempotent.

### TASK-009
- **Goal:** Content-derived node IDs, per invariant 3.
- **Description:** Implement the node ID derivation from docs/04-knowledge-graph
  section Node model. Stable under whitespace and comment changes,
  which docs/22-testing section Property-based testing names as a
  required property.
- **Dependencies:** TASK-008
- **Acceptance:** Reformatting a file leaves node IDs unchanged. Renaming a symbol
  changes its ID. No autoincrement anywhere.
- **Files:** src/graph.py or src/graph/ids.py, docs/04-knowledge-graph/README.md
- **Difficulty:** M
- **Tests:** Property test (Hypothesis) that whitespace and comment insertion
  preserve IDs.

### TASK-010
- **Goal:** The in-memory Project persists to the store.
- **Description:** Write files, symbols, classes and routes from Project into
  nodes/edges. Removes the first ponytail: in src/graph.py:3
  ("in-memory only, rebuilt per run").
- **Dependencies:** TASK-009
- **Acceptance:** After a scan, the store holds one node per symbol and one edge
  per call. The ponytail: marker is deleted, not moved.
- **Files:** src/graph.py, src/workspace/store.py
- **Difficulty:** L
- **Tests:** Scan the fixture, assert node and edge counts against the known
  symbol count.

### TASK-011
- **Goal:** Findings and evidence paths persist.
- **Description:** Implement findings and evidence_paths per docs/17-database,
  storing both id and fingerprint (already computed in
  src/models.py).
- **Dependencies:** TASK-010
- **Acceptance:** Every finding round-trips with its full path. A finding with an
  empty path cannot be written, matching Finding.__post_init__.
- **Files:** src/workspace/store.py, src/rules.py
- **Difficulty:** M
- **Tests:** Round-trip all 10 fixture findings, asserting path step count and
  roles survive.

### TASK-012
- **Goal:** Reading the previous scan without re-scanning.
- **Description:** Query helpers: findings by scan, by fingerprint, latest scan for a
  project. Backs vigilloo report and vigilloo explain.
- **Dependencies:** TASK-011
- **Acceptance:** Latest-scan lookup is a single indexed query. Fingerprint lookup
  uses idx_findings_fp.
- **Files:** src/workspace/store.py
- **Difficulty:** S
- **Tests:** Two scans stored, latest returns the second; fingerprint match
  spans both.

### TASK-013
- **Goal:** Schema migrations, so an upgrade does not discard a user's
  baseline.
- **Description:** Implement the migration runner from docs/17-database section
  Migrations. Version in schema_meta, forward-only, refuse to open
  a newer schema.
- **Dependencies:** TASK-007
- **Acceptance:** Opening an older DB migrates it. Opening a newer one exits with
  configuration-error code 4, not a crash.
- **Files:** src/workspace/store.py, src/workspace/migrations.py (new)
- **Difficulty:** M
- **Tests:** Fabricate a v1 DB, migrate, assert data preserved; assert refusal
  on a future version.

### TASK-014
- **Goal:** Graph export for external tooling.
- **Description:** GraphML and JSON export per docs/04-knowledge-graph section
  Export. Deterministic ordering.
- **Dependencies:** TASK-010
- **Acceptance:** Two exports of the same project are byte-identical. GraphML
  validates.
- **Files:** src/graph/export.py (new), docs/04-knowledge-graph/README.md
- **Difficulty:** M
- **Tests:** Byte-equality across two runs; XML well-formedness.

## MILESTONE C: TEST HARNESS AND GATES
docs/22-testing. Placed before the rule catalogue deliberately: every rule task
from Milestone I onward is cheaper and safer once expected.yml and the determinism
test exist. 7 tasks.

### TASK-015
- **Goal:** Declarative fixture expectations, as the spec already defines
  them.
- **Description:** Implement the expected.yml loader and pytest harness from
  docs/22-testing section The benchmark corpus, supporting
  findings: (rule, file, line, severity, path roles) and
  must_not_find:. Today expectations are hand-written assertions
  across a dozen test files.
- **Dependencies:** none
- **Acceptance:** A fixture directory with expected.yml is discovered and asserted
  automatically. A missing expected finding fails. A must_not_find
  hit fails with equal weight.
- **Files:** tests/harness.py (new), tests/test_corpus.py (new),
  docs/22-testing/README.md
- **Difficulty:** L
- **Tests:** The harness tests itself: a fixture with a deliberately wrong
  expected.yml must fail.

### TASK-016
- **Goal:** The existing fixture is expressed declaratively.
- **Description:** Write tests/fixtures/laravel-minimal/expected.yml covering the
  current 10 findings and the negative cases already present
  (CheckedInvoiceRequest, the safe controllers). Retire the
  assertions this subsumes; keep unit tests that check mechanics
  rather than outcomes.
- **Dependencies:** TASK-015
- **Acceptance:** All 10 findings and every negative case are declared. Deleted
  assertions are genuinely redundant, verified by mutating a rule
  and confirming the harness catches it.
- **Files:** tests/fixtures/laravel-minimal/expected.yml (new),
  tests/test_scan.py, tests/test_mass_assignment.py,
  tests/test_missing_authorization.py
- **Difficulty:** M
- **Tests:** Harness green; mutation check by hand.

### TASK-017
- **Goal:** Invariant 8 is asserted, not assumed.
- **Description:** Implement the determinism test from docs/22-testing section
  Determinism test: scan a fixture twice from different working
  directories with different --jobs, diff the JSON. This is
  currently the least-defended invariant.
- **Dependencies:** TASK-015, TASK-089 (JSON reporter)
- **Acceptance:** Test passes today and fails if any set iteration or unsorted
  collection leaks into output.
- **Files:** tests/test_determinism.py (new)
- **Difficulty:** M
- **Tests:** The test is the deliverable. Verify it fails when a deliberate
  set() ordering is introduced.

### TASK-018
- **Goal:** Coverage metrics are measured, per invariant 4.
- **Description:** Compute parse success rate and call-graph resolution rate over a
  scan, using the existing WalkStats.unresolved and
  Project.unparsed. Expose in the scan result.
- **Dependencies:** none
- **Acceptance:** Both rates appear in the scan output. Rates are computed, never
  estimated.
- **Files:** src/graph.py, src/models.py, src/report.py
- **Difficulty:** M
- **Tests:** Fixture with a deliberately unparseable file yields a rate below
  100%.

### TASK-019
- **Goal:** CI gates the two leading indicators.
- **Description:** Gate parse success at 99.5% and call resolution at 85% per
  docs/22-testing section Metrics gated in CI. Resolution rate is
  the leading indicator for false negatives.
- **Dependencies:** TASK-018
- **Acceptance:** CI fails when either rate drops below threshold on the fixture
  corpus.
- **Files:** .github/workflows/ci.yml, tests/test_coverage_gates.py (new)
- **Difficulty:** S
- **Tests:** The gate test itself.

### TASK-020
- **Goal:** Property tests for the parser and taint engine.
- **Description:** Add Hypothesis with the four properties from docs/22-testing
  section Property-based testing: valid PHP parses without
  crashing, taint propagation is monotonic, node IDs stable under
  whitespace, sanitizing clears exactly one kind.
- **Dependencies:** TASK-009
- **Acceptance:** Four properties implemented. Runtime under 30 seconds so the fast
  loop stays fast.
- **Files:** pyproject.toml, tests/test_properties.py (new)
- **Difficulty:** L
- **Tests:** The properties are the deliverable.

### TASK-021
- **Goal:** A regression test per fixed bug, permanently.
- **Description:** Create tests/regression/ and backfill the four bugs already fixed
  in git history (b9d7ff2 Blade loop taint, 42c9b2e Request
  receiver, 71412ca computed view name). docs/22-testing lists
  regression as a permanent layer.
- **Dependencies:** TASK-015
- **Acceptance:** Each historical fix has a named test that fails against the
  pre-fix behaviour.
- **Files:** tests/regression/ (new), docs/22-testing/README.md
- **Difficulty:** M
- **Tests:** The regression tests.

## MILESTONE D: PARSER COMPLETENESS
docs/03-parser. Language features the taint walk currently cannot see. Each gap
here is a silent false negative. 10 tasks.

### TASK-022
- **Goal:** PSR-4 autoload resolution from composer.json.
- **Description:** Read autoload.psr-4 and map namespace prefixes to directories,
  per docs/03-parser section Discovery. Today class resolution
  relies on file-local imports only. Must not read outside the
  project root, per docs/23-dev-guide section Security ("a crafted
  composer.json autoload map must not make Vigilloo read or write
  outside the project root").
- **Dependencies:** none
- **Acceptance:** A class in a PSR-4 directory resolves by FQN without an explicit
  import. A ../../ prefix in the autoload map is rejected, not
  followed.
- **Files:** src/symbols.py, src/laravel/detect.py (new),
  docs/03-parser/README.md
- **Difficulty:** M
- **Tests:** Positive resolution; path-traversal fixture with a malicious
  autoload map asserting refusal.

### TASK-023
- **Goal:** Static and scoped calls are visible to the taint walk.
- **Description:** The walk iterates member_call_expression only. Add
  scoped_call_expression, which is why DB::raw, DB::statement,
  DB::unprepared are unreachable today, explicitly noted at
  src/laravel/vocabulary.py:96.
- **Dependencies:** none
- **Acceptance:** Foo::bar($tainted) propagates. The ponytail: at vocabulary.py:96
  becomes removable by TASK-024.
- **Files:** src/taint.py
- **Difficulty:** L
- **Tests:** Fixture with a static call propagating taint into a known sink.

### TASK-024
- **Goal:** DB:: facade sinks fire.
- **Description:** With TASK-023 landed, add DB::raw, DB::statement, DB::unprepared,
  DB::select/insert/update/delete to SINKS per docs/06-taint-analysis
  section SQL. Handle the select name collision with the safe
  builder ->select(['col']) by requiring a DB receiver. Removes the
  vocabulary.py:96 marker.
- **Dependencies:** TASK-023
- **Acceptance:** DB::raw($input) fires php.sql-injection. $query->select(['col'])
  does not. The ponytail: comment is deleted.
- **Files:** src/laravel/vocabulary.py, tests/fixtures/laravel-minimal/,
  docs/06-taint-analysis/README.md
- **Difficulty:** M
- **Tests:** Positive DB::raw, negative ->select([...]), negative DB::select
  with bindings.

### TASK-025
- **Goal:** Traits and inheritance resolve.
- **Description:** use TraitName and extends Parent method resolution per
  docs/07-call-graph section Traits and inheritance. Removes the
  ponytail: at src/laravel/models.py:71 about use HasFactory-style
  traits and models whose base lives behind a trait.
- **Dependencies:** TASK-022
- **Acceptance:** A method inherited from a parent or trait is found by
  Project.method. Model detection works through an intermediate
  base class.
- **Files:** src/symbols.py, src/graph.py, src/laravel/models.py
- **Difficulty:** L
- **Tests:** Fixture model extending an app-level base that extends Model;
  trait-provided method reached by taint.

### TASK-026
- **Goal:** PHP superglobals are sources.
- **Description:** $_GET, $_POST, $_REQUEST, $_COOKIE, $_FILES, $argv as all-kinds
  sources. $_SERVER needs the per-key split from
  docs/06-taint-analysis section PHP native: HTTP_*, REQUEST_URI,
  QUERY_STRING, PATH_INFO, HTTP_HOST, HTTP_X_FORWARDED_FOR tainted,
  DOCUMENT_ROOT not.
- **Dependencies:** none
- **Acceptance:** $_GET['x'] into whereRaw fires. $_SERVER['DOCUMENT_ROOT'] does
  not.
- **Files:** src/laravel/vocabulary.py, src/taint.py,
  docs/06-taint-analysis/README.md
- **Difficulty:** M
- **Tests:** Positive per superglobal; negative for DOCUMENT_ROOT.

### TASK-027
- **Goal:** Magic property access on Request is a source.
- **Description:** $request->name is equivalent to $request->input('name') and is
  named in docs/06-taint-analysis as "commonly missed". Requires
  the Request-receiver check already added in 42c9b2e to extend to
  property fetches.
- **Dependencies:** none
- **Acceptance:** $request->bio into {!! !!} fires php.xss. $someObject->bio does
  not.
- **Files:** src/taint.py, src/laravel/vocabulary.py
- **Difficulty:** M
- **Tests:** Positive on a typed Request receiver; negative on any other
  object.

### TASK-028
- **Goal:** Route parameters injected into action signatures are sources.
- **Description:** public function show(Request $r, string $slug) makes $slug
  attacker-controlled, per docs/06-taint-analysis section Laravel
  HTTP. Reduces the ponytail: at src/taint.py:127 about untyped,
  unnamed Request parameters.
- **Dependencies:** none
- **Acceptance:** A scalar action parameter bound to a route URI segment carries
  all kinds. A model-bound parameter does not (it is a record,
  handled by the IDOR rule).
- **Files:** src/taint.py, src/laravel/routes.py
- **Difficulty:** M
- **Tests:** Positive scalar param into a sink; negative model-bound param.

### TASK-029
- **Goal:** The request() helper and Input::get legacy facade are sources.
- **Description:** Both appear in docs/06-taint-analysis section Laravel HTTP. The
  helper form is common in older Laravel code, which is exactly the
  code most likely to be vulnerable.
- **Dependencies:** TASK-023 for the facade form
- **Acceptance:** request('x') and Input::get('x') both taint.
- **Files:** src/laravel/vocabulary.py, src/taint.py
- **Difficulty:** S
- **Tests:** One positive per form.

### TASK-030
- **Goal:** Modern PHP syntax does not silently drop taint.
- **Description:** Arrow functions, nullsafe operator, match expressions,
  first-class callable syntax, enums, named arguments, readonly
  properties, per docs/03-parser section PHP features that must be
  handled correctly. Each unhandled form is a taint trail that ends
  silently.
- **Dependencies:** none
- **Acceptance:** Taint propagates through each construct. Named arguments map to
  the correct parameter index, which matters because sink rules are
  argument-precise.
- **Files:** src/taint.py, src/symbols.py, docs/03-parser/README.md
- **Difficulty:** L
- **Tests:** One fixture per construct, positive and negative.

### TASK-031
- **Goal:** Parse failures are counted per construct, not just per file.
- **Description:** Project.unparsed records the file; record which node types errored
  so the parse-rate gate points at a cause. Supports invariant 4 and
  TASK-019.
- **Dependencies:** TASK-018
- **Acceptance:** A file with one bad method reports the method, not just the file.
- **Files:** src/parser.py, src/graph.py
- **Difficulty:** M
- **Tests:** Fixture with one malformed method; assert the reported node type.

## MILESTONE E: CALL GRAPH RESOLUTION
docs/07-call-graph. Resolution rate is the leading indicator for false negatives,
gated at 85%. 6 tasks.

### TASK-032
- **Goal:** Facades resolve to their concrete classes.
- **Description:** Build the facade map per docs/07-call-graph section Facades:
  Cache, DB, Storage, Auth, Log, and app-registered facades from the
  alias array.
- **Dependencies:** TASK-023
- **Acceptance:** Cache::get() resolves to the concrete repository method. Unknown
  facades are recorded unresolved, never guessed.
- **Files:** src/laravel/facades.py (new), src/taint.py,
  docs/07-call-graph/README.md
- **Difficulty:** L
- **Tests:** Resolution for each built-in facade; unresolved count increments
  for an unknown one.

### TASK-033
- **Goal:** Container bindings resolve interface calls to implementations.
- **Description:** Read app()->bind, singleton, and service-provider register()
  bodies per docs/07-call-graph section Container bindings.
- **Dependencies:** TASK-022
- **Acceptance:** An interface-typed constructor parameter resolves to the bound
  concrete class. Multiple bindings record all candidates with
  confidence, per the spec's resolution-strategy table.
- **Files:** src/laravel/container.py (new), src/graph.py
- **Difficulty:** L
- **Tests:** Fixture with a bound interface reaching a sink through the
  implementation.

### TASK-034
- **Goal:** Framework-invoked entry points are entry points.
- **Description:** Queue jobs handle(), console commands, event listeners, observers,
  notifications, scheduled tasks, per docs/07-call-graph section
  Framework-invoked entry points and docs/08-framework-adapters
  section Jobs, commands, events, schedule. Code reachable only from
  a job is still reachable.
- **Dependencies:** TASK-025
- **Acceptance:** A sink reachable only from a job's handle() is reported, with the
  job as the entry step. Per docs/13-security-engine, console-only
  reachability lowers severity by one.
- **Files:** src/laravel/entrypoints.py (new), src/taint.py, src/structural.py
- **Difficulty:** L
- **Tests:** Job fixture with a sink; assert entry role and the severity
  adjustment.

### TASK-035
- **Goal:** Call edges carry confidence.
- **Description:** Implement the resolution-strategy confidence scale from
  docs/07-call-graph section Resolution strategies, best to worst.
  docs/13-security-engine requires "any path edge below 0.5
  confidence" to reduce severity and mark the finding "needs
  review".
- **Dependencies:** TASK-032, TASK-033
- **Acceptance:** Every edge has a confidence. The 85% resolution gate counts edges
  above 0.5.
- **Files:** src/graph.py, src/models.py, src/taint.py
- **Difficulty:** M
- **Tests:** Assert confidence per strategy; assert the severity adjustment
  fires.

### TASK-036
- **Goal:** Function summaries, so interprocedural analysis does not re-walk.
- **Description:** Implement summaries per docs/05-data-flow-analysis section
  Interprocedural flow: param_to_return, param_to_property,
  param_to_sink. Cached in summary_cache from docs/17-database.
- **Dependencies:** TASK-008, TASK-035
- **Acceptance:** A helper called from thirty controllers is summarised once.
  Results identical to the un-summarised walk on the fixture.
- **Files:** src/analysis/summaries.py (new), src/taint.py, pyproject.toml
- **Difficulty:** L
- **Tests:** Equivalence test: summarised and unsummarised walks produce
  identical findings.

### TASK-037
- **Goal:** Recursion and mutual recursion terminate.
- **Description:** Fixed-point iteration with a visited set per
  docs/05-data-flow-analysis section Precision and its limits.
- **Dependencies:** TASK-036
- **Acceptance:** A mutually recursive pair analyses in bounded time and reports the
  sink if one exists.
- **Files:** src/taint.py, src/analysis/summaries.py
- **Difficulty:** M
- **Tests:** Direct recursion, mutual recursion, and a recursion carrying taint
  to a sink.

## MILESTONE F: LARAVEL ADAPTER COMPLETENESS
docs/08-framework-adapters. The spec is explicit that a missed middleware entry
produces a false "unauthenticated route" finding, and that false positives on
access control destroy trust faster than anything else. 14 tasks.

### TASK-038
- **Goal:** Route files are found the way Laravel finds them.
- **Description:** Removes the ponytail: at src/graph.py:136: routes are recognised
  only by living in a directory literally named routes, so a Laravel
  10+ split like routes/api/v1.php is invisible. Read
  RouteServiceProvider for registered files, plus routes/console.php
  and routes/channels.php.
- **Dependencies:** TASK-022
- **Acceptance:** Nested route files are discovered. A provider-registered custom
  path is discovered. The ponytail: comment is deleted.
- **Files:** src/graph.py, src/laravel/routes.py, tests/fixtures/
- **Difficulty:** M
- **Tests:** Fixture with routes/api/v1.php and a provider-registered path.

### TASK-039
- **Goal:** Route groups with prefix and middleware inheritance.
- **Description:** Route::group(['prefix' => 'admin', 'middleware' => [...]], fn)
  including nesting, per docs/08-framework-adapters section Routes.
  Removes half of the ponytail: at src/laravel/routes.py:121. The
  spec requires exactness: prefix and name concatenation and group
  nesting all.
- **Dependencies:** TASK-038
- **Acceptance:** A route inside two nested groups has both prefixes concatenated
  and both middleware sets in order. Middleware order is preserved,
  since order is semantically meaningful.
- **Files:** src/laravel/routes.py, docs/08-framework-adapters/README.md
- **Difficulty:** L
- **Tests:** Two-level nested group fixture asserting URI, name and full
  middleware stack.

### TASK-040
- **Goal:** Route::resource and apiResource expand correctly.
- **Description:** 7 and 5 routes respectively, with correct verbs, URIs, names and
  action methods. Completes the routes.py:121 marker. Also
  Route::match and Route::any.
- **Dependencies:** TASK-039
- **Acceptance:** Route::resource('posts', PostController::class) yields exactly the
  7 documented routes. only() and except() modifiers respected. The
  ponytail: is deleted.
- **Files:** src/laravel/routes.py
- **Difficulty:** L
- **Tests:** Assert all 7 and all 5 by verb plus URI; only/except variants.

### TASK-041
- **Goal:** Middleware groups expand to their members.
- **Description:** Removes the ponytail: at src/laravel/routes.py:87: groups web and
  api are not expanded. Read Kernel.php for Laravel 9/10 and
  bootstrap/app.php for 11, per docs/08-framework-adapters section
  Middleware semantics.
- **Dependencies:** TASK-039
- **Acceptance:** A route with api middleware resolves to the member list including
  throttle:api. Both Kernel and bootstrap forms work. The ponytail:
  is deleted.
- **Files:** src/laravel/routes.py, src/laravel/kernel.py (new),
  tests/fixtures/
- **Difficulty:** L
- **Tests:** L9-style Kernel.php fixture and L11-style bootstrap/app.php
  fixture, same expected expansion.

### TASK-042
- **Goal:** Middleware semantics, turning a route table into an authorization
  model.
- **Description:** Implement the guarantee table from docs/08-framework-adapters
  section Middleware semantics: auth/auth:sanctum authenticated,
  guest, verified, signed, throttle:N,M, can:ability,model,
  password.confirm, and TrimStrings/ConvertEmptyStringsToNull as
  transforms that explicitly do NOT sanitize.
- **Dependencies:** TASK-041
- **Acceptance:** A query answers "is this route authenticated / rate-limited /
  gated / signed". TrimStrings never clears a taint kind.
- **Files:** src/laravel/middleware.py (new), src/structural.py
- **Difficulty:** M
- **Tests:** One assertion per middleware; explicit test that TrimStrings does
  not sanitize.

### TASK-043
- **Goal:** Custom middleware is classified by what it does.
- **Description:** Analyse the body for abort(403) and redirect patterns to infer
  whether it gates, per the same spec section. Unclassifiable custom
  middleware records low confidence rather than assuming either way.
- **Dependencies:** TASK-042
- **Acceptance:** Middleware calling abort(403) is treated as gating. One with no
  such pattern is recorded unknown, and an unknown never suppresses
  a finding silently.
- **Files:** src/laravel/middleware.py
- **Difficulty:** M
- **Tests:** Gating fixture, non-gating fixture, ambiguous fixture.

### TASK-044
- **Goal:** Dynamic routes are recorded, not dropped.
- **Description:** Route::get($var, ...) and routes built in a loop are recorded with
  low confidence and the URI marked dynamic, per
  docs/08-framework-adapters section Routes. Silently dropping them
  is a coverage lie under invariant 4.
- **Dependencies:** TASK-039
- **Acceptance:** A dynamic route appears in the route table flagged dynamic and
  counts toward the coverage report.
- **Files:** src/laravel/routes.py, src/models.py, src/report.py
- **Difficulty:** M
- **Tests:** Loop-registered route fixture; assert presence and flag.

### TASK-045
- **Goal:** Model metadata beyond $fillable/$guarded.
- **Description:** Extract $hidden, $casts, $appends, $timestamps, soft deletes,
  relationships, scopes, accessors and mutators, per
  docs/08-framework-adapters section Eloquent models.
- **Dependencies:** TASK-025
- **Acceptance:** Each attribute extracted for the fixture models. $hidden is
  available for a future serialization rule.
- **Files:** src/laravel/models.py
- **Difficulty:** M
- **Tests:** Assert each field against a fixture model declaring all of them.

### TASK-046
- **Goal:** Privileged column inference, cross-checked against migrations.
- **Description:** Name patterns (is_admin, role, role_id, permissions, verified_at,
  balance, price, owner_id, user_id) cross-checked against
  database/migrations/ for the real schema, which the spec calls
  more reliable than the property list alone.
- **Dependencies:** TASK-045
- **Acceptance:** A $fillable containing is_admin is flagged privileged even without
  $guarded = []. A column absent from migrations does not produce a
  phantom finding.
- **Files:** src/laravel/models.py, src/laravel/migrations.py (new),
  src/structural.py
- **Difficulty:** L
- **Tests:** Positive privileged-$fillable fixture; negative all-benign
  fixture; migration cross-check.

### TASK-047
- **Goal:** Validation rules map to cleared taint kinds.
- **Description:** Form requests and inline $request->validate([...]) and
  Validator::make(), with the rule-to-kind mapping from
  docs/06-taint-analysis: integer clears sql but not html, string
  clears nothing, in:a,b clears everything.
- **Dependencies:** TASK-025
- **Acceptance:** validate(['id' => 'integer']) then whereRaw with $id does not
  fire. The same $id into {!! !!} still does.
- **Files:** src/laravel/validation.py (new), src/taint.py,
  docs/06-taint-analysis/README.md
- **Difficulty:** L
- **Tests:** The exact positive and negative pair above, per rule class.

### TASK-048
- **Goal:** Gates and the explicit policy map.
- **Description:** Gate::define, Gate::allows/denies, $user->can(), @can,
  authorizeResource(), and AuthServiceProvider::$policies. Removes
  the ponytail: at src/laravel/policies.py:6 about the explicit
  override map, and the one at src/structural.py:100 about
  identifying policies by having an authorize() method.
- **Dependencies:** TASK-025
- **Acceptance:** A policy registered only via $policies is found.
  authorizeResource() in a constructor suppresses the IDOR finding
  for every action it covers. Both ponytail: markers deleted.
- **Files:** src/laravel/policies.py, src/structural.py
- **Difficulty:** L
- **Tests:** Explicit-map fixture, authorizeResource fixture, Gate::allows
  fixture, each with its negative.

### TASK-049
- **Goal:** Blade inheritance and includes.
- **Description:** @extends, @section, @yield, @stack, @include, and <x-component>
  plus class-based components, per docs/08-framework-adapters
  section Blade templates. Removes the ponytail: at
  src/laravel/views.py:7.
- **Dependencies:** none
- **Acceptance:** Taint from a controller reaches a raw echo inside an included
  partial. A variable passed to a component reaches the component
  template. Marker deleted.
- **Files:** src/laravel/views.py, src/laravel/blade.py, tests/fixtures/
- **Difficulty:** L
- **Tests:** Include chain fixture, inheritance fixture, component fixture,
  each positive and negative.

### TASK-050
- **Goal:** Blade collection aliasing in loops.
- **Description:** Removes the ponytail: at src/taint.py:316: loop variables are not
  aliased to the collection's kinds, so
  @foreach($items as $item) {!! $item !!} loses the trail.
- **Dependencies:** TASK-049
- **Acceptance:** A tainted collection iterated in Blade taints the loop variable.
  The lost-trail counter for this case drops to zero.
- **Files:** src/taint.py, src/laravel/blade.py
- **Difficulty:** M
- **Tests:** @foreach and @forelse fixtures, positive and negative.

### TASK-051
- **Goal:** Config and environment facts are extracted.
- **Description:** Parse config/*.php values with their env() defaults, plus .env and
  .env.example, per docs/08-framework-adapters section Configuration
  and environment. Backs six config rules in Milestone I.
- **Dependencies:** TASK-006
- **Acceptance:** config('app.debug') resolves to its env() default. .env values are
  read without ever being echoed into a report, since secrets must
  be redacted before transmit.
- **Files:** src/laravel/config.py (new), docs/08-framework-adapters/README.md
- **Difficulty:** M
- **Tests:** Config fixture with env() defaults; assert no secret value reaches
  a Finding field.

## MILESTONE G: TAINT KINDS AND SINKS
docs/06-taint-analysis. Three of twelve kinds implemented. Each task adds a kind
with its sinks and its sanitizers together, per the TaintKind docstring: a kind
with no sink and no sanitizer claims reasoning the engine cannot do. 9 tasks.

### TASK-052
- **Goal:** shell kind, CWE-78.
- **Description:** Sinks exec, shell_exec, system, passthru, popen, proc_open,
  pcntl_exec, backticks, Process::run/start,
  Process::fromShellCommandline. Sanitizer escapeshellarg. The spec
  notes new Process(['ls', $x]) array form does not go through a
  shell and is much lower severity.
- **Dependencies:** TASK-023
- **Acceptance:** String form fires critical; array form does not fire, or fires at
  reduced severity per spec. escapeshellarg clears shell only.
- **Files:** src/models.py, src/laravel/vocabulary.py, src/rules.py,
  docs/06-taint-analysis/README.md
- **Difficulty:** M
- **Tests:** Positive string form, negative array form, negative escaped form,
  and a test that escapeshellarg does not clear html.

### TASK-053
- **Goal:** code kind, CWE-94 and CWE-502.
- **Description:** Sinks eval, assert($string), create_function, unserialize, dynamic
  include/require, preg_replace with /e, dynamic invocation $fn(),
  call_user_func. Per the spec, NOTHING clears this kind: "never
  accept untrusted input here".
- **Dependencies:** TASK-052
- **Acceptance:** Every listed sink fires critical. No sanitizer entry exists for
  code, and adding one is rejected in review.
- **Files:** src/models.py, src/laravel/vocabulary.py, src/rules.py
- **Difficulty:** M
- **Tests:** One positive per sink form. Explicit test that no sanitizer clears
  code.

### TASK-054
- **Goal:** path kind, CWE-22 and CWE-434.
- **Description:** Sinks file_get_contents, file_put_contents, fopen, unlink, copy,
  rename, and the Storage facade. Sanitizers basename,
  realpath-within-root check, allowlist.
- **Dependencies:** TASK-052
- **Acceptance:** file_get_contents($input) fires. basename($input) clears path and
  nothing else.
- **Files:** src/models.py, src/laravel/vocabulary.py, src/rules.py
- **Difficulty:** M
- **Tests:** Positive, basename negative, kind-isolation test.

### TASK-055
- **Goal:** url kind, SSRF, CWE-918.
- **Description:** HTTP-client sinks with user-controlled URLs per
  docs/06-taint-analysis section SSRF: Guzzle, Http::get,
  curl_setopt with CURLOPT_URL, file_get_contents with a remote
  scheme. Sanitizers: host allowlist, scheme check.
- **Dependencies:** TASK-054
- **Acceptance:** Http::get($input) fires. A host-allowlist check on the path clears
  it.
- **Files:** src/models.py, src/laravel/vocabulary.py, src/rules.py
- **Difficulty:** M
- **Tests:** Positive per client; allowlist negative.

### TASK-056
- **Goal:** js kind, distinct from html.
- **Description:** Inline <script> and @json context. Sanitizers json_encode with
  escaping flags, Js::from. The distinction matters: e() clears html
  and does not make a value safe inside a script block.
- **Dependencies:** TASK-049
- **Acceptance:** {{ $x }} inside <script> fires js even though it is html-escaped.
  Js::from($x) does not.
- **Files:** src/models.py, src/laravel/vocabulary.py, src/laravel/blade.py,
  src/rules.py
- **Difficulty:** L
- **Tests:** The escaped-but-in-script positive is the important one. Plus
  @json and Js::from negatives.

### TASK-057
- **Goal:** header kind and open redirect, CWE-601.
- **Description:** header(), redirect($x), Response::header, per
  docs/06-taint-analysis section Open redirect and section Others.
  Sanitizer: URL validation against an allowlist.
- **Dependencies:** TASK-055
- **Acceptance:** redirect($request->input('next')) fires. A relative-path-only
  check clears it.
- **Files:** src/models.py, src/laravel/vocabulary.py, src/rules.py
- **Difficulty:** M
- **Tests:** Positive redirect, positive header split, allowlist negative.

### TASK-058
- **Goal:** ldap, xpath, log kinds.
- **Description:** The remaining three from the kinds table, each with its sinks and
  its encoder, per docs/06-taint-analysis section Others. log covers
  log injection and completes A09 coverage. Completes the ponytail:
  at src/models.py:21, which lists exactly these outstanding kinds.
- **Dependencies:** TASK-057
- **Acceptance:** All twelve kinds from the spec table exist. The models.py:21
  ponytail: comment is deleted.
- **Files:** src/models.py, src/laravel/vocabulary.py, src/rules.py,
  docs/06-taint-analysis/README.md
- **Difficulty:** L
- **Tests:** Positive and negative per kind.

### TASK-059
- **Goal:** Anti-sanitizers are findings, not sanitizers.
- **Description:** strip_tags, addslashes, mysql_real_escape_string are deliberately
  absent from SANITIZERS and the comment there says the spec classes
  them as findings in their own right. Implement that: a partial
  sanitizer on the path keeps severity and notes the weak control,
  per docs/13-security-engine section Taint rules.
- **Dependencies:** TASK-058
- **Acceptance:** addslashes on a SQL path keeps the finding and adds a "weak
  control" note to the step. It never clears a kind.
- **Files:** src/laravel/vocabulary.py, src/taint.py, src/rules.py
- **Difficulty:** M
- **Tests:** Fixture per anti-sanitizer asserting the finding survives with a
  note.

### TASK-060
- **Goal:** Response bodies and non-Blade templates as html sinks.
- **Description:** Removes the ponytail: at src/taint.py:302, which defers these
  until a fixture needs one. docs/06-taint-analysis section XSS
  lists Response with HTML content type.
- **Dependencies:** TASK-056
- **Acceptance:** response($tainted)->header('Content-Type', 'text/html') fires. A
  JSON response does not. Marker deleted.
- **Files:** src/taint.py, src/laravel/vocabulary.py
- **Difficulty:** M
- **Tests:** HTML response positive, JSON response negative.

## MILESTONE H: CONTROL FLOW AND PRECISION
docs/05-data-flow-analysis. Removes the largest single precision limitation,
annotated at src/taint.py:3. 5 tasks.

### TASK-061
- **Goal:** A control flow graph per function.
- **Description:** Build the CFG per docs/05-data-flow-analysis section Control flow
  graph. Today the walk is statement-order with no CFG and no branch
  sensitivity, per the module docstring.
- **Dependencies:** TASK-037
- **Acceptance:** CFG built for every method, with correct edges for if, while,
  foreach, switch, match, try, early return.
- **Files:** src/analysis/cfg.py (new), pyproject.toml
- **Difficulty:** L
- **Tests:** Edge-count assertions per construct.

### TASK-062
- **Goal:** SSA form for precise variable versioning.
- **Description:** Per docs/05-data-flow-analysis section Intraprocedural flow.
  Distinguishes $x = tainted(); $x = 'safe'; from the reverse, which
  the statement-order walk currently gets wrong in one direction.
- **Dependencies:** TASK-061
- **Acceptance:** Reassignment to a constant clears taint. Reassignment from a
  source introduces it. Phi nodes at joins union the kind sets.
- **Files:** src/analysis/ssa.py (new), src/taint.py
- **Difficulty:** L
- **Tests:** The reassignment pair in both orders; a branch join where one arm
  is tainted.

### TASK-063
- **Goal:** Branch-sensitive taint, replacing the statement-order walk.
- **Description:** Move the taint walk onto the CFG and SSA. Removes the ponytail: at
  src/taint.py:3.
- **Dependencies:** TASK-062
- **Acceptance:** Every existing fixture finding is preserved exactly. Sanitization
  inside one branch does not clear the other. Marker deleted.
- **Files:** src/taint.py, src/analysis/cfg.py
- **Difficulty:** L
- **Tests:** Full expected.yml corpus unchanged, plus a branch fixture where
  only one arm sanitizes.

### TASK-064
- **Goal:** Untyped Request parameters are handled or honestly reported.
- **Description:** Removes the ponytail: at src/taint.py:127: a Request parameter
  that is neither type-hinted nor conventionally named is not
  recognised. Use the route table to identify the parameter position
  instead of the name.
- **Dependencies:** TASK-028, TASK-063
- **Acceptance:** An untyped, unconventionally named Request parameter is recognised
  via its route binding. When it genuinely cannot be resolved, it
  counts as unresolved rather than being dropped.
- **Files:** src/taint.py, src/laravel/routes.py
- **Difficulty:** M
- **Tests:** Untyped parameter fixture; unresolvable fixture asserting the
  coverage counter increments.

### TASK-065
- **Goal:** Findings deduplicate across entry points.
- **Description:** Per docs/13-security-engine section Deduplication: multiple entry
  points reaching one sink produce one finding with several paths.
  Show the shortest, highest-confidence path; attach the rest.
  Without this, one bad helper called from thirty controllers
  reports thirty times.
- **Dependencies:** TASK-035, TASK-063
- **Acceptance:** A shared helper reached from three routes yields one finding with
  three paths. The displayed path is the shortest with highest
  confidence, chosen deterministically.
- **Files:** src/rules.py, src/models.py, src/report.py,
  docs/13-security-engine/README.md
- **Difficulty:** L
- **Tests:** Three-route shared-helper fixture; assert one finding, three
  paths, deterministic selection across runs.

## MILESTONE I: RULE CATALOGUE
docs/08-framework-adapters section Laravel-specific rule set and
docs/13-security-engine. Rule IDs as spelled in those tables, permanent per
invariant 7. Every task writes the negative fixture first. 16 tasks.

### TASK-066
- **Goal:** The Rule dataclass matches the specified shape.
- **Description:** Today src/rules.py has id, title, severity, cwe, remediation.
  docs/13-security-engine section Rule shape specifies also
  confidence, owasp, kind, languages, frameworks. Extend before
  adding sixteen rules under the wrong shape.
- **Dependencies:** none
- **Acceptance:** Rule matches the spec field for field. Existing four rules
  populate every field.
- **Files:** src/rules.py, docs/13-security-engine/README.md
- **Difficulty:** S
- **Tests:** Assert every field populated for all four existing rules.

### TASK-067
- **Goal:** Evidence-based severity adjustment.
- **Description:** Implement the adjustment table from docs/13-security-engine
  section Taint rules: unauthenticated route +1, console-only -1,
  sub-0.5 confidence edge -1 plus "needs review", weak sanitizer
  keeps severity with a note, vendor/ sink suppressed by default.
- **Dependencies:** TASK-035, TASK-042, TASK-066
- **Acceptance:** Each of the five adjustments observable on a fixture. Adjustment
  is deterministic.
- **Files:** src/rules.py, src/structural.py
- **Difficulty:** L
- **Tests:** One fixture per adjustment row.

### TASK-068
- **Goal:** laravel.raw-query as its own rule.
- **Description:** The spec's rule table lists it separately from php.sql-injection:
  *Raw and DB::raw reached by taint in the non-binding argument,
  critical. Decide and document whether this is an alias of the php
  rule or a distinct ID, because invariant 7 makes the choice
  permanent.
- **Dependencies:** TASK-024, TASK-066
- **Acceptance:** The decision is recorded in docs/13-security-engine. If distinct,
  no finding is emitted under both IDs, which would double-report.
- **Files:** src/laravel/vocabulary.py, src/rules.py,
  docs/13-security-engine/README.md
- **Difficulty:** M
- **Tests:** Assert exactly one finding per raw-query site.

### TASK-069
- **Goal:** laravel.blade-raw-echo as its own rule.
- **Description:** Same decision as TASK-068 for {!! $tainted !!} versus the existing
  php.xss.
- **Dependencies:** TASK-068
- **Acceptance:** Decision documented; no double-reporting.
- **Files:** src/laravel/vocabulary.py, src/rules.py,
  docs/13-security-engine/README.md
- **Difficulty:** S
- **Tests:** Assert one finding per raw echo.

### TASK-070
- **Goal:** laravel.csrf-except, high.
- **Description:** Wildcard or state-changing path in VerifyCsrfToken::$except, per
  docs/08-framework-adapters section Middleware semantics.
  Structural rule, no taint. Named in CLAUDE.md as a rule where the
  Laravel value concentrates.
- **Dependencies:** TASK-041, TASK-066
- **Acceptance:** 'api/*' fires. An empty $except does not. A single
  non-state-changing exact path does not.
- **Files:** src/structural.py, src/laravel/middleware.py, tests/fixtures/
- **Difficulty:** M
- **Tests:** Wildcard positive, empty negative, benign-exact-path negative.

### TASK-071
- **Goal:** laravel.unauthenticated-route, high.
- **Description:** State-changing route (POST/PUT/PATCH/DELETE) with no auth
  middleware. Depends on full middleware expansion, because a missed
  group entry produces a false positive here, which the spec calls
  the worst kind.
- **Dependencies:** TASK-042, TASK-066
- **Acceptance:** Unauthenticated POST fires. The same route inside an auth group
  does not. A GET does not. A signed public action does not.
- **Files:** src/structural.py
- **Difficulty:** M
- **Tests:** All four cases above.

### TASK-072
- **Goal:** laravel.no-throttle, medium.
- **Description:** Login, register and password-reset routes without throttle, per
  docs/13-security-engine section Structural rules.
- **Dependencies:** TASK-042
- **Acceptance:** A login route without throttle fires. One inside a group carrying
  throttle:api does not. A non-auth route does not.
- **Files:** src/structural.py
- **Difficulty:** M
- **Tests:** Three cases above.

### TASK-073
- **Goal:** laravel.unsigned-route, medium.
- **Description:** Public action routes (unsubscribe, confirm, approve) without
  signed.
- **Dependencies:** TASK-042
- **Acceptance:** An unsubscribe route without signed fires. With signed it does
  not. A generic public GET does not, since firing on every public
  page is the failure mode this rule must avoid.
- **Files:** src/structural.py
- **Difficulty:** M
- **Tests:** Three cases, with the generic-public-GET negative as the decisive
  one.

### TASK-074
- **Goal:** Dead authorization: a policy method never referenced.
- **Description:** Policy method defined but never referenced by any route or action,
  per docs/13-security-engine section Structural rules. A written
  but unwired policy is a strong oversight signal.
- **Dependencies:** TASK-048
- **Acceptance:** An unreferenced policy method fires. One referenced via can:
  middleware, $this->authorize(), @can or authorizeResource does
  not.
- **Files:** src/structural.py, src/laravel/policies.py
- **Difficulty:** M
- **Tests:** One negative per reference form, plus the positive.

### TASK-075
- **Goal:** Inconsistent authorization across a resource controller.
- **Description:** authorize() present in one action and absent in siblings, per
  docs/13-security-engine. Inconsistency is a strong signal of
  oversight rather than intent.
- **Dependencies:** TASK-048, TASK-040
- **Acceptance:** A controller with authorize() in show but not update fires on
  update. A controller with none in any action does not fire under
  this rule, since that is the IDOR rule's territory and
  double-reporting is the failure.
- **Files:** src/structural.py
- **Difficulty:** M
- **Tests:** Mixed fixture positive; uniformly-unauthorized fixture negative.

### TASK-076
- **Goal:** laravel.validated-bypass, medium.
- **Description:** Validation run, then $request->all() used instead of the
  validated() result. docs/08-framework-adapters section Validation
  calls this extremely common, and CLAUDE.md names it under
  concentrated Laravel value.
- **Dependencies:** TASK-047
- **Acceptance:** $request->validate([...]); User::create($request->all()); fires.
  Using $request->validated() does not. A FormRequest whose result
  is used correctly does not.
- **Files:** src/structural.py, src/laravel/validation.py
- **Difficulty:** M
- **Tests:** All three cases.

### TASK-077
- **Goal:** FormRequest authorize() returning true on a privileged action.
- **Description:** The first of the two Laravel traps in docs/08-framework-adapters
  section Validation: validation is not authorization.
- **Dependencies:** TASK-047, TASK-048
- **Acceptance:** A FormRequest with authorize() { return true; } guarding a
  state-changing model-bound action fires. One with a real check
  does not. One guarding a public create does not.
- **Files:** src/structural.py, src/laravel/validation.py
- **Difficulty:** M
- **Tests:** Three cases; the public-create negative decides usability.

### TASK-078
- **Goal:** laravel.env-outside-config, medium.
- **Description:** env() called outside config/. Returns null after config:cache,
  silently disabling whatever depended on it. Named in CLAUDE.md.
- **Dependencies:** TASK-051
- **Acceptance:** env('X') in a controller fires. The same call in config/app.php
  does not.
- **Files:** src/structural.py, src/laravel/config.py
- **Difficulty:** S
- **Tests:** Positive and negative.

### TASK-079
- **Goal:** laravel.debug-enabled critical and laravel.app-key critical.
- **Description:** APP_DEBUG=true with production indicators (Ignition RCE,
  CVE-2021-3129) and missing, empty, committed or framework-default
  APP_KEY (CVE-2018-15133). Both from docs/08-framework-adapters
  section Configuration and environment. .env tracked in git is
  itself a critical finding per docs/13-security-engine section
  Secret rules.
- **Dependencies:** TASK-051
- **Acceptance:** Each condition fires. APP_DEBUG=true in a .env.example does not. A
  present, non-default APP_KEY does not. No secret value appears in
  any Finding field.
- **Files:** src/structural.py, src/laravel/config.py, src/rules.py
- **Difficulty:** M
- **Tests:** Positive per condition; .env.example negative; redaction
  assertion.

### TASK-080
- **Goal:** laravel.trusted-proxies medium and insecure session cookie flags.
- **Description:** TRUSTED_PROXIES=* enables client IP spoofing, defeating rate
  limits and IP allowlists. Plus SESSION_SECURE_COOKIE,
  SESSION_HTTP_ONLY, SESSION_SAME_SITE.
- **Dependencies:** TASK-051
- **Acceptance:** Wildcard proxies fires. An explicit CIDR list does not. Each
  insecure cookie flag fires independently.
- **Files:** src/structural.py, src/laravel/config.py
- **Difficulty:** M
- **Tests:** One case per condition plus its negative.

### TASK-081
- **Goal:** The remaining four table rules.
- **Description:** laravel.unsafe-upload high (getClientOriginalName() as a storage
  path), laravel.debug-artifact low (dd, dump, ray, var_dump in
  non-test code), laravel.weak-hash high (md5/sha1 for passwords
  instead of Hash::make), and weak randomness (rand/mt_rand for
  tokens, A02 per docs/13-security-engine).
- **Dependencies:** TASK-054, TASK-066
- **Acceptance:** Each fires on its positive and stays silent on its negative.
  debug-artifact must not fire inside tests/, and md5 for a
  non-password checksum must not fire.
- **Files:** src/structural.py, src/laravel/vocabulary.py, src/rules.py
- **Difficulty:** L
- **Tests:** Four positives, four negatives; the md5-as-checksum negative is
  the one that keeps this rule usable.

## MILESTONE J: CONFIGURATION, SUPPRESSION, BASELINES
docs/19-cli section Configuration, docs/13-security-engine section Suppression.
7 tasks.

### TASK-082
- **Goal:** vigilloo.yml is loaded with the specified precedence.
- **Description:** CLI flags > env (VIGILLOO_*) > project file > user config >
  defaults, per docs/19-cli section Configuration. Full schema
  including scan, rules, taint, ai, suppress.
- **Dependencies:** TASK-006
- **Acceptance:** Each precedence level demonstrably overrides the next. An unknown
  key is a configuration error, exit code 4, not a silent ignore.
- **Files:** src/workspace/config.py (new), src/cli.py
- **Difficulty:** L
- **Tests:** One test per precedence pair; unknown-key rejection.

### TASK-083
- **Goal:** User-defined sources and sanitizers from config.
- **Description:** The taint.sources and taint.sanitizers blocks from docs/19-cli
  section Configuration, mapping an app-specific FQN to kinds it
  introduces or clears.
- **Dependencies:** TASK-082
- **Acceptance:** A configured custom source taints. A configured sanitizer clears
  exactly the listed kinds and no others.
- **Files:** src/workspace/config.py, src/laravel/vocabulary.py, src/taint.py
- **Difficulty:** M
- **Tests:** Custom source positive; custom sanitizer clearing one kind while
  another kind survives.

### TASK-084
- **Goal:** // vigilloo-ignore comments, with mandatory justification.
- **Description:** Per docs/13-security-engine section Suppression: next-line scope,
  justification required, and a bare ignore is itself reported.
- **Dependencies:** TASK-066
- **Acceptance:** A justified ignore suppresses the next-line finding. A bare
  // vigilloo-ignore produces its own finding. An ignore naming a
  different rule does not suppress.
- **Files:** src/rules.py, src/parser.py, docs/13-security-engine/README.md
- **Difficulty:** M
- **Tests:** All three cases.

### TASK-085
- **Goal:** suppress: blocks with expiry.
- **Description:** Path glob plus rule plus reason plus expires, per docs/19-cli.
  Expiring suppressions matter: a permanent ignore is how a backlog
  becomes invisible.
- **Dependencies:** TASK-082
- **Acceptance:** An unexpired suppression hides the finding. An expired one does
  not, and reports that it expired. A missing reason is a
  configuration error.
- **Files:** src/workspace/config.py, src/rules.py
- **Difficulty:** M
- **Tests:** Unexpired, expired, missing-reason.

### TASK-086
- **Goal:** vigilloo baseline create|update|diff.
- **Description:** Per docs/19-cli section baseline. Matching by fingerprint, not
  line number, which is why Finding.fingerprint already exists.
- **Dependencies:** TASK-012, TASK-089
- **Acceptance:** A baseline captures current findings. Reformatting the code does
  not resurrect a baselined finding. A genuinely new finding is not
  baselined.
- **Files:** src/cli.py, src/baseline.py (new), docs/19-cli/README.md
- **Difficulty:** L
- **Tests:** Reformat-survival test, new-finding test, diff output test.

### TASK-087
- **Goal:** --baseline suppression in scan.
- **Description:** Wire the baseline into the scan path so a team can gate on new
  findings without fixing the backlog first, the realistic adoption
  path per docs/19-cli.
- **Dependencies:** TASK-086
- **Acceptance:** Baselined findings are excluded from the report and from the exit
  code, but still counted in a summary line so they do not become
  invisible.
- **Files:** src/cli.py, src/rules.py, src/report.py
- **Difficulty:** M
- **Tests:** Exit code 0 with only baselined findings; summary still shows the
  count.

### TASK-088
- **Goal:** Rule selection and filtering flags.
- **Description:** --rules, --exclude-rules (glob), --severity, --min-confidence,
  --fail-on, --include-vendor, per docs/19-cli section scan.
- **Dependencies:** TASK-082, TASK-066
- **Acceptance:** Each flag filters as documented. --fail-on is independent of
  --severity, so a report can show medium findings while gating only
  on high.
- **Files:** src/cli.py, src/rules.py
- **Difficulty:** M
- **Tests:** One test per flag; the --severity versus --fail-on independence
  test.

## MILESTONE K: REPORTING
docs/16-reporting. 8 tasks.

### TASK-089
- **Goal:** JSON reporter with a published, versioned schema.
- **Description:** Per docs/16-reporting section Determinism: findings sorted by
  (severity, rule ID, path, line), JSON keys sorted, no timestamps
  in the body, run metadata in a separate header section CI diffing
  can ignore.
- **Dependencies:** TASK-066
- **Acceptance:** Two runs are byte-identical. Removing the metadata header leaves a
  diffable body.
- **Files:** src/report/json.py (new), pyproject.toml,
  docs/16-reporting/README.md
- **Difficulty:** M
- **Tests:** Byte-equality across runs and across working directories.

### TASK-090
- **Goal:** Terminal reporter degrades outside a TTY.
- **Description:** --format terminal must detect non-TTY and emit plain text, per
  docs/16-reporting, so piping into a CI log does not produce
  escape-code soup.
- **Dependencies:** none
- **Acceptance:** Piped output contains no ANSI escapes. TTY output keeps colour.
- **Files:** src/report.py or src/report/terminal.py
- **Difficulty:** S
- **Tests:** Capture piped output and assert no escape sequences.

### TASK-091
- **Goal:** Evidence paths render as code frames.
- **Description:** The example in docs/README.md and docs/16-reporting section
  Finding presentation: one numbered step per path element with
  file, line and the source line.
- **Dependencies:** TASK-090
- **Acceptance:** Output matches the documented example format. Blade steps quote
  the original Blade text, not the rewritten PHP, which
  Project.blade_line already supports.
- **Files:** src/report/terminal.py
- **Difficulty:** M
- **Tests:** Snapshot test against the fixture findings.

### TASK-092
- **Goal:** Markdown reporter.
- **Description:** Report structure per docs/16-reporting section Report structure,
  Jinja2 template overridable per project.
- **Dependencies:** TASK-089
- **Acceptance:** Deterministic output. A project-local template overrides the
  default.
- **Files:** src/report/markdown.py (new), src/report/templates/ (new),
  pyproject.toml
- **Difficulty:** M
- **Tests:** Byte-equality; template override test.

### TASK-093
- **Goal:** SARIF 2.1.0 reporter.
- **Description:** Per docs/16-reporting section SARIF specifics. Rule IDs appear
  here, which is one reason invariant 7 exists. docs/24-roadmap
  lists SARIF under v1.0, but the format work is cheap now and the
  schema is stable, so it is included here as optional-for-v0.1.
- **Dependencies:** TASK-089
- **Acceptance:** Output validates against the SARIF 2.1.0 schema. Evidence paths
  map to codeFlows, not to a flat message.
- **Files:** src/report/sarif.py (new), docs/16-reporting/README.md
- **Difficulty:** L
- **Tests:** Schema validation; codeFlows step count matches the evidence path.

### TASK-094
- **Goal:** Coverage caveats appear in every report format.
- **Description:** Invariant 4 says coverage is reported, never hidden. src/cli.py
  prints caveats to the terminal only; JSON, Markdown and SARIF
  currently omit them. A clean JSON result over a 40% unparsed
  codebase is a lie in exactly the format CI consumes.
- **Dependencies:** TASK-018, TASK-089, TASK-092, TASK-093
- **Acceptance:** Parse failures, unparsed files and unresolved call counts appear
  in all four formats.
- **Files:** src/report/*.py, src/cli.py, docs/16-reporting/README.md
- **Difficulty:** M
- **Tests:** One assertion per format on a fixture with a deliberate parse
  failure.

### TASK-095
- **Goal:** vigilloo report renders the last scan without re-scanning.
- **Description:** Per docs/19-cli section report, including --compare classifying
  findings as new, fixed or unchanged by fingerprint.
- **Dependencies:** TASK-012, TASK-089
- **Acceptance:** Rendering does not re-parse. --compare classification is by
  fingerprint, so a reformat shows unchanged, not fixed-plus-new.
- **Files:** src/cli.py, src/report/compare.py (new)
- **Difficulty:** M
- **Tests:** Reformat-between-scans test asserting "unchanged".

### TASK-096
- **Goal:** HTML reporter.
- **Description:** Jinja2, self-contained, per docs/16-reporting section Formats.
  Listed under v0.5 in docs/24-roadmap, included here as the last
  reporting task since it shares the template infrastructure.
- **Dependencies:** TASK-092
- **Acceptance:** Single self-contained file, no external assets, deterministic.
- **Files:** src/report/html.py (new), src/report/templates/
- **Difficulty:** M
- **Tests:** Byte-equality; assert no external URLs in output.

## MILESTONE L: CLI SURFACE
docs/19-cli. Currently only scan with a single positional argument. 10 tasks.

### TASK-097
- **Goal:** Exit codes as specified.
- **Description:** 0 success, 1 findings at or above --fail-on, 2 usage, 3 analysis
  error, 4 configuration error, 5 authorization missing. Today only
  0, 1 and 2 are used. Distinguishing 1 from 3 is what lets CI tell
  "your code has a vulnerability" from "the scanner broke".
- **Dependencies:** TASK-082, TASK-088
- **Acceptance:** Each code reachable and tested. A plugin crash or parse
  catastrophe yields 3, never 1.
- **Files:** src/cli.py, docs/19-cli/README.md
- **Difficulty:** M
- **Tests:** One test per exit code.

### TASK-098
- **Goal:** --format and -o on scan.
- **Description:** terminal, markdown, json, sarif, html; output to file or stdout.
- **Dependencies:** TASK-089, TASK-092, TASK-093, TASK-096
- **Acceptance:** Each format selectable. -o writes the file and prints nothing to
  stdout except a confirmation.
- **Files:** src/cli.py
- **Difficulty:** S
- **Tests:** One invocation per format.

### TASK-099
- **Goal:** vigilloo doctor.
- **Description:** Python version, grammars, corpus version and age, cache health,
  plugin status, per docs/19-cli section doctor. docs/23-dev-guide
  section Setup already instructs new contributors to run it, so it
  is currently a broken instruction.
- **Dependencies:** TASK-006
- **Acceptance:** Reports each item with pass or fail. Exits 0 when healthy, 3 when
  a grammar is missing.
- **Files:** src/cli.py, src/doctor.py (new), docs/23-dev-guide/README.md
- **Difficulty:** M
- **Tests:** Healthy environment passes; simulated missing grammar fails with
  the right code.

### TASK-100
- **Goal:** vigilloo init.
- **Description:** Interactive setup writing vigilloo.yml, offering a pre-commit hook
  and a CI workflow file, per docs/19-cli section init.
- **Dependencies:** TASK-082
- **Acceptance:** Generates a valid config that scan loads. Non-interactive --yes
  mode for CI. Never overwrites an existing config without
  confirmation.
- **Files:** src/cli.py, src/init.py (new)
- **Difficulty:** M
- **Tests:** Generated config round-trips through the loader; overwrite
  refusal.

### TASK-101
- **Goal:** vigilloo graph routes.
- **Description:** The attack-surface inventory, which docs/19-cli calls "often the
  first thing a security engineer runs on an unfamiliar codebase".
  Route table with middleware and auth status.
- **Dependencies:** TASK-042
- **Acceptance:** Every route listed with verbs, URI, action and resolved
  middleware. Auth status derived from middleware semantics, not
  from a name guess. Dynamic routes marked.
- **Files:** src/cli.py, src/report/routes.py (new)
- **Difficulty:** M
- **Tests:** Snapshot against the fixture route table.

### TASK-102
- **Goal:** vigilloo graph build|stats|export.
- **Description:** Per docs/19-cli section graph. build refreshes the store only;
  stats reports node and edge counts by kind plus resolution rate;
  export wraps TASK-014.
- **Dependencies:** TASK-014, TASK-018
- **Acceptance:** build populates the store without reporting. stats includes the
  resolution rate, the leading false-negative indicator.
- **Files:** src/cli.py
- **Difficulty:** M
- **Tests:** One test per subcommand.

### TASK-103
- **Goal:** vigilloo graph show and graph paths.
- **Description:** --focus <FQN> --depth N and paths --from route --to 'sink:sql',
  per docs/19-cli.
- **Dependencies:** TASK-102
- **Acceptance:** Focused subgraph respects depth. paths finds the known fixture
  path from route to SQL sink.
- **Files:** src/cli.py, src/graph/queries.py (new)
- **Difficulty:** L
- **Tests:** Depth-limit assertion; known-path assertion.

### TASK-104
- **Goal:** vigilloo explain FINDING-ID.
- **Description:** Full evidence path, CWE context and remediation from the stored
  scan, plus --cwe 89. Deterministic, no AI: docs/19-cli places AI
  explanation in fix, not here.
- **Dependencies:** TASK-012
- **Acceptance:** Explains a stored finding by ID with no re-scan. An unknown ID
  exits 2, not 3.
- **Files:** src/cli.py, src/report/explain.py (new)
- **Difficulty:** M
- **Tests:** Known ID, unknown ID, --cwe filter.

### TASK-105
- **Goal:** vigilloo review for changed code.
- **Description:** --staged, --base main, --commit A..B, per docs/19-cli section
  review. Reports only findings the change introduced, using the
  full graph for context, so a change that routes a tainted argument
  into an existing sink is new even though the sink line is
  untouched.
- **Dependencies:** TASK-086, TASK-095
- **Acceptance:** The cross-file case above is reported as new. An unrelated
  pre-existing finding is not. Full graph is built regardless of
  diff scope.
- **Files:** src/cli.py, src/review.py (new)
- **Difficulty:** L
- **Tests:** The cross-file introduction case is the decisive test.

### TASK-106
- **Goal:** --jobs parallelism without breaking determinism.
- **Description:** Parallelise parsing and per-entry-point taint per
  docs/23-dev-guide section Performance. Output order fixed by rule
  ID per docs/13-security-engine section Execution, regardless of
  scheduling.
- **Dependencies:** TASK-017, TASK-089
- **Acceptance:** --jobs 1 and --jobs 8 produce byte-identical output. The
  determinism test from TASK-017 covers this.
- **Files:** src/cli.py, src/rules.py, src/taint.py
- **Difficulty:** L
- **Tests:** The existing determinism test, extended across job counts.

## MILESTONE M: DEPENDENCIES, SECRETS, INCREMENTALITY
The last three v0.1 roadmap bullets. 6 tasks.

### TASK-107
- **Goal:** composer.lock parsing and advisory matching.
- **Description:** Exact versions matched against the PHP Security Advisories
  database and OSV (composer ecosystem), per
  docs/08-framework-adapters section Dependencies. Advisory data
  refreshed only by explicit vigilloo update, never mid-scan, per
  docs/19-cli section update and invariant 6.
- **Dependencies:** TASK-007
- **Acceptance:** Vulnerable packages identified offline from a cached advisory set.
  No network access during scan.
- **Files:** src/deps/ (new), pyproject.toml, docs/19-cli/README.md
- **Difficulty:** L
- **Tests:** Fixture lock file with a known vulnerable version; assert zero
  network calls during scan.

### TASK-108
- **Goal:** Reachability ranking, the dependency differentiator.
- **Description:** Cross-check the vulnerable function against the call graph, per
  docs/13-security-engine section Dependency rules: "47 vulnerable
  packages" is noise, "3 vulnerable packages with a vulnerable
  function reachable from a public route" is a work queue. Rank with
  CVSS, EPSS and CISA KEV.
- **Dependencies:** TASK-107, TASK-035
- **Acceptance:** A vulnerable-but-never-called package ranks below a reachable one.
  --reachable-only filters correctly.
- **Files:** src/deps/reachability.py, src/cli.py
- **Difficulty:** L
- **Tests:** Reachable and unreachable fixtures; assert ordering.

### TASK-109
- **Goal:** vigilloo secrets, working tree.
- **Description:** The filter chain from docs/13-security-engine section Secret
  rules, in order: provider pattern, entropy threshold, context
  (variable name, test or fixture file), checksum validation where
  the format allows it. Entropy alone is unusable. .env.example
  placeholders are not findings; .env tracked in git is critical.
- **Dependencies:** TASK-066
- **Acceptance:** AWS, Stripe, GitHub, Google, Slack, JWT and PEM patterns detected.
  A UUID, a hash and a base64 asset do not fire. Secret values are
  redacted before ever entering a Finding.
- **Files:** src/secrets/ (new), pyproject.toml,
  docs/13-security-engine/README.md
- **Difficulty:** L
- **Tests:** One positive per provider; the UUID, hash and base64 negatives; a
  redaction assertion that no secret value appears in any output.

### TASK-110
- **Goal:** vigilloo secrets --history.
- **Description:** Scan git history for rotated-but-never-purged keys, per
  docs/19-cli section secrets.
- **Dependencies:** TASK-109
- **Acceptance:** A secret removed in a later commit is still found in history and
  reported with the commit that introduced it.
- **Files:** src/secrets/history.py, src/cli.py
- **Difficulty:** M
- **Tests:** Temp repo fixture with an added-then-removed secret.

### TASK-111
- **Goal:** Incremental scanning via file-hash cache invalidation.
- **Description:** symbol_cache and summary_cache keyed by file SHA and parser
  version, per docs/17-database and docs/04-knowledge-graph section
  Invalidation. docs/23-dev-guide section Performance names cache
  correctness the single most important performance concern: a wrong
  cache is worse than no cache.
- **Dependencies:** TASK-013, TASK-036
- **Acceptance:** Re-scanning an unchanged project reuses the cache and produces
  identical findings. Changing one file invalidates exactly that
  file plus its dependents. A parser-version bump invalidates
  everything.
- **Files:** src/workspace/store.py, src/graph.py, src/analysis/summaries.py
- **Difficulty:** L
- **Tests:** Identical-output-after-cache-hit is the critical test;
  single-file-change invalidation scope; parser-version bump.

### TASK-112
- **Goal:** Performance benchmarks against the NFR targets.
- **Description:** pytest-benchmark guarding 60s at 100k LOC and 2 GB peak at 500k
  LOC, per docs/22-testing section Metrics gated in CI. Nightly, not
  per-PR, so the fast loop stays fast.
- **Dependencies:** TASK-111
- **Acceptance:** Benchmarks run nightly. A regression beyond threshold fails the
  nightly job, not the PR job.
- **Files:** pyproject.toml, tests/perf/ (new),
  .github/workflows/nightly.yml (new)
- **Difficulty:** M
- **Tests:** The benchmarks are the deliverable.

## MILESTONE N: SDK BOUNDARY AND LAYOUT CONVERGENCE
docs/11-plugin-sdk, docs/23-dev-guide section Repository layout. Deliberately
last: sdk/ is the only stability boundary, and freezing it before the internals
settle would freeze the wrong interface. 4 tasks.

### TASK-113
- **Goal:** FrameworkAdapter extracted as a Protocol.
- **Description:** Per docs/08-framework-adapters section The adapter interface. The
  Laravel code becomes the first implementation. Per
  docs/23-dev-guide, if the interface does not fit, change the
  interface rather than special-casing the adapter.
- **Dependencies:** Milestone F complete
- **Acceptance:** Laravel adapter satisfies the Protocol with no special-casing in
  core. mypy --strict verifies structural conformance.
- **Files:** src/sdk/ (new), src/laravel/, pyproject.toml,
  docs/11-plugin-sdk/README.md
- **Difficulty:** L
- **Tests:** A minimal stub adapter satisfying the Protocol proves it is not
  Laravel-shaped.

### TASK-114
- **Goal:** Declarative YAML rules.
- **Description:** docs/23-dev-guide section Adding a rule says to prefer YAML in
  plugins/<x>/rules/: declarative rules cannot crash a scan, cannot
  loop forever, and need no review of imperative logic. Implement
  the loader for the taint-rule shape in docs/13-security-engine
  section Taint rules.
- **Dependencies:** TASK-113
- **Acceptance:** At least one existing rule is expressed in YAML with identical
  output. A malformed YAML rule is disabled for the run and
  recorded, never fatal.
- **Files:** src/security/yaml_rules.py (new), src/laravel/rules/*.yml (new)
- **Difficulty:** L
- **Tests:** Equivalence test between the YAML and Python forms;
  malformed-rule isolation test.

### TASK-115
- **Goal:** A crashing rule is disabled, never fatal.
- **Description:** Per docs/13-security-engine section Execution: a rule that throws
  is disabled for the run and recorded in the manifest. One broken
  rule must never fail a scan.
- **Dependencies:** TASK-114
- **Acceptance:** A deliberately throwing rule is skipped, the scan completes, and
  the manifest records the failure. Exit code reflects analysis
  degradation, not a false clean result.
- **Files:** src/rules.py, src/workspace/store.py
- **Difficulty:** M
- **Tests:** Throwing-rule fixture asserting scan completion and manifest
  entry.

### TASK-116
- **Goal:** Flat modules converge on the specified layout.
- **Description:** Move the remaining flat modules into the subpackages
  docs/23-dev-guide section Repository layout names: parser/,
  graph/, analysis/, security/, report/, plugins/php/,
  plugins/laravel/. Mechanical, no behaviour change. Done last so it
  moves settled code once rather than churning code still in flux.
- **Dependencies:** TASK-115
- **Acceptance:** Layout matches the doc. Every subpackage registered in both
  pyproject.toml tables. Wheel smoke test imports each. Zero
  findings change, verified by the expected.yml corpus.
- **Files:** all of src/, pyproject.toml, .github/workflows/ci.yml, tests/
- **Difficulty:** L
- **Tests:** Corpus output byte-identical before and after; wheel imports every
  subpackage.

## SHIP GATE
v0.1 ships when docs/22-testing gates pass: 100% of seeded findings, 0
must_not_find hits, precision at or above 90% on the real-app corpus, parse
success at or above 99.5%, call resolution at or above 85%, 100k LOC in 60s, 500k
LOC under 2 GB, and clean runs on 10 open-source Laravel apps.

NOT in the 116 tasks above: assembling the real-application corpus.
docs/22-testing requires a pinned set of open-source Laravel projects, preferably
including applications with published CVEs at a vulnerable commit. That is a
research and curation effort measured in days, not a 2-hour engineering task, and
it does not decompose honestly into the format requested. It should be scheduled
as its own workstream running in parallel from Milestone I onward, since every
rule added after that point needs it to measure precision.

## LATER MILESTONES, NOT ATOMIZED

| Milestone         | Content                                          | Why not decomposed |
| ----------------- | ------------------------------------------------ | ------------------ |
| v0.5 Reasoning    | AI engine, RAG corpus, provider plugins,          | Depends on the SDK boundary settling |
|                   | dominator analysis, deep data flow, Webisters     | in Milestone N. Atomizing now |
|                   | adapter                                          | produces tasks rewritten before they |
|                   |                                                  | start. |
| v1.0 Integration  | MCP server, GitHub App and Action, GitLab CI, PR  | Scope depends on what v0.1 adoption |
|                   | comments, Python language support, Symfony,       | reveals. |
|                   | published SDK, SBOM                              | |
| v1.5+             | JavaScript and TypeScript, desktop, runtime,      | Specs exist and are decided; |
|                   | cloud, attack engine                             | sequencing does not. |

Per docs/24-roadmap sequencing, each release is defined by a capability that works
end to end. Decomposing v0.5 before v0.1 ships would violate that ordering rule.

Backlog totals: 116 tasks, 14 milestones, all under the 2-hour cap, ordered so no
task depends on a later one. Nothing was implemented and no files outside TEMP/
were modified.
