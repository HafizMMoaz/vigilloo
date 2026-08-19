# Stabilise, Measure, Ship v0.1 - Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Get `main` green, measure the 31-rule engine's precision against real Laravel
applications, and finish the CLI and report surface so v0.1 can actually be released.

**Architecture:** Three sequential phases. Phase 1 repairs the four CI gates and installs a
guard so red cannot land again. Phase 2 builds the machine-readable output and the real-world
corpus that the v0.1 ship gate in [22-testing](../22-testing/README.md) demands, then measures
precision per rule. Phase 3 spends that measurement on the remaining CLI commands and report
formats. No new detection capability is added until Phase 2 has told us which of the existing
31 rules are noisy.

**Tech Stack:** Python 3.13, uv, tree-sitter-php, SQLite, typer, pytest, ruff, mypy (strict).

**Spec:** [24-roadmap](../24-roadmap/README.md) v0.1 table (corrected in Task 7 of this plan),
[22-testing](../22-testing/README.md) for the corpus gates, [16-reporting](../16-reporting/README.md)
for report formats, [19-cli](../19-cli/README.md) for the command surface.

## Global Constraints

- **No em dashes** anywhere: code, comments, docs, commit messages. Use a hyphen (`-`).
- **Never add Claude as co-author.** No `Co-Authored-By`, no "Generated with" footer. All
  commits authored by `HafizMMoaz <hafizmoazkhalid@gmail.com>`.
- **Imports inside `src/` are relative.** `from .models import Finding`, never
  `from vigilloo.models import Finding`.
- **Rule IDs are permanent** (invariant 7). No task in this plan renames one.
- **Determinism** (invariant 8): same input plus same ruleset gives byte-identical output.
- **Every finding carries a complete evidence path** (invariant 2). No path, no finding.
- **Never use a shell heredoc.** Write throwaway scripts to `/private/tmp/` and run them from
  there. Scratch probes never go in the repo.
- Four gates must pass before any commit lands: `uv run pytest`,
  `uv run ruff format --check .`, `uv run ruff check`, `uv run mypy`.

---

# Phase 1: Stabilise

`main` has been red for seven consecutive commits (last green: `TASK-062: SSABuilder and
LocalState (#48)`, 2026-08-12). 399 tests pass; the other three gates fail. Phase 1 is
mechanical and fully specified below. Nothing in it changes detection behaviour, so
**`uv run pytest` must report 399 passed at the end of every task in this phase.** A test count
that moves means a fix changed behaviour, which is a bug in the fix.

### Task 1: Remove scratch files from the repository and ignore their kind

CLAUDE.md states "Scratch probes never go in the repo." Four scratch paths are tracked and
eleven more are untracked in the working directory; together they contribute 27 of the 113
`ruff check` errors and 9 of the 24 formatting failures. Removing them shrinks the problem
before any real fix is attempted.

**Files:**
- Delete (tracked): `scratch.py`, `scratch.php`, `tests/test_tmp.py`,
  `tmp_scratch/app/Http/Controllers/ThingController.php`,
  `tmp_scratch/resources/views/show.blade.php`, `tmp_scratch/routes/api.php`
- Delete (untracked): `debug_custom.py`, `debug_routes.py`, `dump_yaml.py`, `fix_localstate.py`,
  `fix_taint.py`, `generate_expected.py`, `update_blade.py`, `update_yaml.py`, `out.txt`,
  `tmp_test/`
- Modify: `.gitignore`
- Keep: `scripts/dump_ast.py` (a documented dev utility, named in CLAUDE.md)

**Interfaces:**
- Consumes: nothing.
- Produces: a working tree where `ruff check .` and `ruff check src tests` report the same
  count, so later tasks can trust either.

- [ ] **Step 1: Confirm nothing imports the scratch modules**

```bash
grep -rn "test_tmp\|tmp_scratch\|scratch" --include="*.py" --include="*.toml" src tests scripts pyproject.toml
```

Expected: no hits outside the files being deleted themselves. If `tests/conftest.py` or
`tests/harness.py` references `tmp_scratch`, stop and report it rather than deleting.

- [ ] **Step 2: Record the current test count**

```bash
uv run pytest -q 2>&1 | tail -1
```

Expected: `399 passed`. Write this number down. It must not change during Phase 1.

- [ ] **Step 3: Delete the tracked scratch files**

```bash
git rm -r scratch.py scratch.php tests/test_tmp.py tmp_scratch
```

- [ ] **Step 4: Delete the untracked scratch files**

```bash
rm -rf debug_custom.py debug_routes.py dump_yaml.py fix_localstate.py fix_taint.py \
       generate_expected.py update_blade.py update_yaml.py out.txt tmp_test
```

- [ ] **Step 5: Extend .gitignore so this cannot recur**

Append these lines to `.gitignore`, below the existing `scratch/` entry:

```gitignore
# Scratch probes never go in the repo (CLAUDE.md, "Agent tooling"). These patterns catch the
# throwaway names agents reach for; a probe that needs a real name belongs in /private/tmp/.
scratch.*
tmp_scratch/
tmp_test/
debug_*.py
fix_*.py
out.txt
```

- [ ] **Step 6: Verify the test count is unchanged**

```bash
uv run pytest -q 2>&1 | tail -1
```

Expected: `399 passed`. `tests/test_tmp.py` was deleted, so if the count dropped, that file
held a real test. Restore it under a descriptive name in the right module and re-run.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "chore: remove scratch probes from the repository

CLAUDE.md requires scratch probes to live in /private/tmp/, never in the repo. Four
scratch paths were tracked and ten more sat untracked in the working directory,
between them producing 27 ruff errors and 9 formatting failures that had nothing to
do with the package. .gitignore now catches the names by pattern."
```

---

### Task 2: Fix the two `graph.py` forward-reference errors

[src/graph.py:94](../../src/graph.py) and `:110` annotate `"frozenset[TaintKind]"` as a string
while importing `TaintKind` inside the function body. It works at runtime because the annotation
is never evaluated, and it is invisible to mypy, which resolves string annotations at module
scope.

**Files:**
- Modify: `src/graph.py:13` (the `TYPE_CHECKING` block), `src/graph.py:94-96`, `src/graph.py:109-111`

**Interfaces:**
- Consumes: `TaintKind` from `.models`.
- Produces: `Project.custom_sources` and `Project.custom_sanitizers`, both
  `dict[tuple[str, str], frozenset[TaintKind]]`. Unchanged signatures; only the annotation
  resolution changes.

- [ ] **Step 1: Confirm the two errors are present**

```bash
uv run mypy 2>&1 | grep "graph.py"
```

Expected:
```
src/graph.py:94: error: Name "TaintKind" is not defined  [name-defined]
src/graph.py:110: error: Name "TaintKind" is not defined  [name-defined]
```

- [ ] **Step 2: Add TaintKind to the module-level runtime import**

`TaintKind` is used at runtime here (the `TaintKind(k)` constructor call), not only in
annotations, so it must be a real import and not a `TYPE_CHECKING` one. `src/graph.py:22`
already has `from .models import (`; add `TaintKind` to that list, keeping it alphabetically
sorted among the existing names so ruff `I001` stays quiet:

```python
from .models import (
    Coverage,
    EdgeRow,
    ...
    TaintKind,
    ...
)
```

- [ ] **Step 3: Remove the two function-body imports and unquote the annotations**

In `custom_sources` (line 94) and `custom_sanitizers` (line 110), delete the line
`from .models import TaintKind` from each body. The module-level import from Step 2 now
supplies the name, so the return annotations no longer need to be strings.

The end state for both methods:

```python
    @cached_property
    def custom_sources(self) -> dict[tuple[str, str], frozenset[TaintKind]]:
        res: dict[tuple[str, str], frozenset[TaintKind]] = {}
        for src in self.vigilloo_config.taint.sources:
            fqn = src.get("fqn")
            if not fqn:
                continue
            fqn = fqn.lstrip("\\")
            if "::" in fqn:
                cls_fqn, method = fqn.split("::", 1)
                key = (cls_fqn, method)
            else:
                key = (fqn, "")
            res[key] = frozenset(TaintKind(k) for k in src.get("kinds", []))
        return res
```

Note the annotations are no longer quoted, and `if not fqn: continue` is split across two lines
(ruff `E701`).

- [ ] **Step 4: Verify both errors are gone and tests still pass**

```bash
uv run mypy 2>&1 | grep "graph.py" ; uv run pytest -q 2>&1 | tail -1
```

Expected: no `graph.py` lines from mypy, and `399 passed`.

- [ ] **Step 5: Commit**

```bash
git add src/graph.py
git commit -m "fix: resolve TaintKind at module scope in graph.py

The custom source and sanitizer maps annotated frozenset[TaintKind] as a string while
importing TaintKind inside the function body, so the annotation resolved at runtime
and never to the type checker. Both are now checked."
```

---

### Task 3: Repoint the `authenticated_by` import and un-couple the two producers

[src/taint.py:50](../../src/taint.py) reads `from .structural import authenticated_by`.
`authenticated_by` is defined at [src/laravel/middleware.py:179](../../src/laravel/middleware.py);
`structural.py` merely imports it. mypy reports this as an implicit re-export under strict mode,
but the deeper problem is architectural: CLAUDE.md requires that "a structural rule never needs
taint state and taint never learns what authorization is", and this import is the taint producer
reaching into the structural producer.

**Files:**
- Modify: `src/taint.py:50`

**Interfaces:**
- Consumes: `authenticated_by(route: Route) -> str | None` from `.laravel.middleware`.
- Produces: no signature change. After this task `src/taint.py` imports nothing from
  `src/structural.py`.

- [ ] **Step 1: Confirm taint.py imports nothing else from structural**

```bash
grep -n "from .structural import\|import structural" src/taint.py
```

Expected: exactly one line, `from .structural import authenticated_by`. If there are more
names, each must be traced to its defining module the same way before this task can complete.

- [ ] **Step 2: Repoint the import**

Replace line 50 of `src/taint.py`:

```python
from .structural import authenticated_by
```

with:

```python
from .laravel.middleware import authenticated_by
```

- [ ] **Step 3: Verify the producers are now independent**

```bash
grep -n "structural" src/taint.py ; uv run mypy 2>&1 | grep "taint.py:50"
```

Expected: no output from either command.

- [ ] **Step 4: Run the taint and structural test modules**

```bash
uv run pytest tests/test_taint.py tests/test_rules.py tests/test_missing_authorization.py \
  tests/regression/test_taint_walk_bugs.py -q 2>&1 | tail -3
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/taint.py
git commit -m "fix: import authenticated_by from its defining module

taint.py reached through structural.py for a helper that laravel/middleware.py owns.
mypy saw an implicit re-export; the architecture rule in CLAUDE.md sees the taint
producer depending on the structural producer. Both are fixed by importing from the
module that defines it. src/taint.py now imports nothing from src/structural.py."
```

---

### Task 4: Give the CFG walk its real types

[src/taint.py:1299](../../src/taint.py) declares `block: object`, so mypy cannot check any
attribute access on it and reports `"object" has no attribute "statements"` (line 1310),
`"successors"` (1837) and `"id"` (1838). The whole CFG-based branch-sensitive walk is therefore
unchecked. The real type is `BasicBlock` from [src/analysis/cfg.py:21](../../src/analysis/cfg.py).

**Files:**
- Modify: `src/taint.py` (import block and the `explore` signature at line 1298-1304)

**Interfaces:**
- Consumes: `BasicBlock` and `Edge` from `.analysis.cfg`. `BasicBlock` exposes `statements`,
  `successors` and `id`; `Edge` exposes `target: BasicBlock`.
- Produces: `explore(block: BasicBlock, current_prefix: list[PathStep],
  visited_edges: frozenset[tuple[int, int]], current_linear: dict[str, frozenset[TaintKind]],
  current_local_types: dict[str, str]) -> None`.

- [ ] **Step 1: Confirm the three errors and read the BasicBlock definition**

```bash
uv run mypy 2>&1 | grep -E "taint.py:(1310|1837|1838)" ; sed -n '15,48p' src/analysis/cfg.py
```

Expected: the three `"object" has no attribute` errors, and a `BasicBlock` dataclass carrying
`id`, `statements` and `successors`.

- [ ] **Step 2: Import BasicBlock in taint.py**

Add to the import block near the top of `src/taint.py`, keeping imports sorted (ruff `I001`):

```python
from .analysis.cfg import BasicBlock
```

- [ ] **Step 3: Type the explore signature**

At `src/taint.py:1298`, change:

```python
    def explore(
        block: object,
```

to:

```python
    def explore(
        block: BasicBlock,
```

- [ ] **Step 4: Verify the three errors are gone**

```bash
uv run mypy 2>&1 | grep "taint.py"
```

Expected: only the two `custom_entering` / `custom_cleared` errors from lines 242-243 remain.
Those are Task 5. If new errors appear inside `explore`, they are real bugs the `object`
annotation was hiding: fix each one and note it in the commit message rather than widening the
type back.

- [ ] **Step 5: Run the branch-sensitivity tests**

```bash
uv run pytest tests/analysis/ tests/test_taint.py tests/regression/ -q 2>&1 | tail -3
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/taint.py
git commit -m "fix: type the CFG walk as BasicBlock rather than object

explore() took block: object, so every attribute access on it was unchecked and the
whole branch-sensitive walk went past the type checker untouched. It is a
analysis.cfg.BasicBlock and is now declared as one."
```

---

### Task 5: Annotate the remaining four inference failures

Four sites need an explicit annotation: `src/structural.py:437`, `src/taint.py:242`,
`src/taint.py:243`, and `src/rules.py:786`.

**Files:**
- Modify: `src/structural.py:437`, `src/taint.py:242-243`, `src/rules.py:786`

**Interfaces:**
- Consumes: `PathStep` and `TaintKind` from `.models` (both already imported in their files).
- Produces: `path_sort_key(path: list[PathStep]) -> tuple[float, int, str]` in `rules.py`.

- [ ] **Step 1: Annotate the dead-authorization accumulator**

`src/structural.py:437`, inside `_dead_authorization_paths`, change:

```python
    paths = []
```

to:

```python
    paths: list[list[PathStep]] = []
```

- [ ] **Step 2: Annotate the custom taint sets**

`src/taint.py:242-243`, change:

```python
        custom_entering = frozenset()
        custom_cleared = frozenset()
```

to:

```python
        custom_entering: frozenset[TaintKind] = frozenset()
        custom_cleared: frozenset[TaintKind] = frozenset()
```

- [ ] **Step 3: Annotate the finding sort key**

`src/rules.py:786`, change:

```python
        def path_sort_key(path):
            min_conf = min((getattr(step, "confidence", 1.0) for step in path), default=1.0)
            return (-min_conf, len(path), str(path))
```

to:

```python
        def path_sort_key(path: list[PathStep]) -> tuple[float, int, str]:
            min_conf = min((getattr(step, "confidence", 1.0) for step in path), default=1.0)
            return (-min_conf, len(path), str(path))
```

This is the ordering that decides which evidence path a finding presents as its primary, so it
is load-bearing for invariant 8 (determinism). The `str(path)` tie-breaker is what makes it
total; leave it in place.

- [ ] **Step 4: Verify and test**

```bash
uv run mypy 2>&1 | tail -3 ; uv run pytest -q 2>&1 | tail -1
```

Expected: only the `structural.py:685-694` errors remain (Task 6), and `399 passed`.

- [ ] **Step 5: Commit**

```bash
git add src/structural.py src/taint.py src/rules.py
git commit -m "fix: annotate four sites mypy could not infer

The finding sort key in rules.py is the one that matters: it decides which evidence
path a finding presents as primary, so determinism depends on it being total."
```

---

### Task 6: Split the two walrus shapes in `find_structural_paths`

`src/structural.py:674-694` binds `steps` with the walrus operator to two different shapes. The
first binding takes `_missing_authorization(...) -> list[PathStep] | None` (one path). The later
bindings take `_env_outside_config_paths(...) -> list[list[PathStep]]` (many paths). mypy pins
`steps` to the first shape and reports ten errors. The code happens to work because
`paths.append` is used for the first shape and `paths.extend` for the second, but one name
meaning two things is how the wrong one gets called during the next edit.

**Files:**
- Modify: `src/structural.py:670-700`

**Interfaces:**
- Consumes: `_missing_authorization`, `_unauthenticated_route_paths`, `_no_throttle_paths`,
  `_unsigned_route_paths` (all `-> list[PathStep] | None`); `_env_outside_config_paths`,
  `_unsafe_upload_paths`, `_debug_artifact_paths`, `_weak_hash_paths`,
  `_weak_randomness_paths` (all `-> list[list[PathStep]]`).
- Produces: `find_structural_paths(project: Project) -> list[list[PathStep]]`, unchanged.

- [ ] **Step 1: Confirm the return shape of each helper before changing anything**

```bash
grep -nE "^def _(missing_authorization|unauthenticated_route_paths|no_throttle_paths|unsigned_route_paths|env_outside_config_paths|unsafe_upload_paths|debug_artifact_paths|weak_hash_paths|weak_randomness_paths)" src/structural.py
```

Read each signature. The plan assumes the split above. If a helper's actual return type differs,
follow the signature, not this plan.

- [ ] **Step 2: Rename the two bindings apart**

Rewrite `src/structural.py:677-700` so the single-path walrus is named `route_steps` and the
many-path walrus is named `rule_paths`:

```python
    for route in project.routes:
        if (route_steps := _unauthenticated_route_paths(route)) is not None:
            paths.append(route_steps)
        if (route_steps := _no_throttle_paths(route)) is not None:
            paths.append(route_steps)
        if (route_steps := _unsigned_route_paths(route)) is not None:
            paths.append(route_steps)

    if (rule_paths := _env_outside_config_paths(project)) is not None:
        paths.extend(rule_paths)
    if (rule_paths := _unsafe_upload_paths(project)) is not None:
        paths.extend(rule_paths)
    if (rule_paths := _debug_artifact_paths(project)) is not None:
        paths.extend(rule_paths)
    if (rule_paths := _weak_hash_paths(project)) is not None:
        paths.extend(rule_paths)
    if (rule_paths := _weak_randomness_paths(project)) is not None:
        paths.extend(rule_paths)

    paths.extend(_csrf_except_paths(project))
    paths.extend(_dead_authorization_paths(project))
```

The last two loops were `for x in f(project): paths.append(x)`, which is `paths.extend(f(project))`.

- [ ] **Step 3: Verify mypy is now clean**

```bash
uv run mypy
```

Expected: `Success: no issues found in 35 source files`.

- [ ] **Step 4: Run the full suite**

```bash
uv run pytest -q 2>&1 | tail -1
```

Expected: `399 passed`. This function assembles every structural finding, so a changed count
here means a rule stopped firing. Bisect on the individual rule tests
(`tests/test_missing_authorization.py`, `tests/test_validation_rules.py`,
`tests/test_routes_middleware.py`) before proceeding.

- [ ] **Step 5: Commit**

```bash
git add src/structural.py
git commit -m "fix: give the two path shapes in find_structural_paths distinct names

One walrus name held both list[PathStep] and list[list[PathStep]], so append and
extend were both correct for it depending on the line. mypy is now clean across src/."
```

---

### Task 6b: Reconcile the `php.sql-injection` rename and its dead assertion

Commit `529d72d` ("decouple laravel.raw-query and laravel.blade-raw-echo rules") renamed the
rule ID `php.sql-injection` to `laravel.raw-query`. `CHANGELOG.md:94` had already announced
`php.sql-injection` as a shipped rule, so this is a breach of invariant 7 ("Rule IDs are
permanent"). It is defensible in fact - nothing has been tagged or published, so no user's
baseline or `// vigilloo-ignore` comment breaks - but it must be announced, and it left one
live bug.

`tests/fixtures/laravel-minimal/expected.yml:958` still forbids `php.sql-injection` at
`app/Http/Controllers/BranchController.php:30` inside its `must_not_find` block. No rule can
emit that ID any more, so the assertion is vacuously true and can never fail. Whatever
over-fire it was guarding against is now unguarded, and the suite reports nothing.

**Files:**
- Modify: `tests/fixtures/laravel-minimal/expected.yml:956-958`
- Modify: `src/rules.py:631` (the `vigilloo.bare-ignore` remediation string, which cites the
  dead ID as its worked example)
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: `ForbiddenFinding` from `tests/harness.py`, matched on `(rule, file, line)`.
- Produces: no code interface. The fixture regains a live assertion.

- [ ] **Step 1: Confirm the assertion is dead**

```bash
grep -rn "php.sql-injection" src tests
awk 'NR>=805' tests/fixtures/laravel-minimal/expected.yml | grep -n "php.sql-injection"
```

Expected: hits only in `src/rules.py:631` and `tests/fixtures/laravel-minimal/expected.yml`,
and the fixture hit is below line 805, which is where `must_not_find:` begins.

- [ ] **Step 2: Find out what the assertion was guarding**

```bash
sed -n '25,35p' tests/fixtures/laravel-minimal/app/Http/Controllers/BranchController.php
git log --oneline -S "php.sql-injection" -- tests/fixtures/laravel-minimal/expected.yml
```

Read the controller method at line 30. The `must_not_find` entry means "no SQL injection
finding here"; the intent survives the rename even though the ID did not.

- [ ] **Step 3: Repoint the assertion at the live ID**

In `tests/fixtures/laravel-minimal/expected.yml`, change the entry to the current ID and give
it the `reason` that every other entry in that block carries:

```yaml
- rule: laravel.raw-query
  file: app/Http/Controllers/BranchController.php
  line: 30
  reason: renamed from php.sql-injection in 529d72d; the assertion had been dead since
```

Replace the trailing text of `reason` with what Step 2 established the method actually does.
Do not leave the sentence unfinished.

- [ ] **Step 4: Verify the assertion is live by breaking it on purpose**

Temporarily change the `line:` to the line number of a real `laravel.raw-query` finding in that
same file (take one from the `findings:` block above), and run:

```bash
uv run pytest tests/test_corpus.py -q 2>&1 | tail -5
```

Expected: **FAIL**, naming the forbidden finding. This proves the entry can now fail. Revert the
line number and re-run; expected: pass. An assertion never observed failing is not an assertion.

- [ ] **Step 5: Fix the remediation string**

`src/rules.py:631` uses `php.sql-injection` as its worked example of a valid rule ID, which now
teaches users a rule ID that does not exist. Change it to `laravel.raw-query`.

- [ ] **Step 6: Announce the rename in the changelog**

Under `## [Unreleased]`, add a `### Changed` section. Rule ID changes are announced by ID, per
the changelog's own preamble:

```markdown
### Changed

- **Rule `php.sql-injection` is now `laravel.raw-query`** (`529d72d`). This is a rule ID
  rename, which invariant 7 forbids: IDs ship in users' SARIF, baselines and
  `// vigilloo-ignore` comments, and renaming one un-suppresses findings everywhere it is
  used. Nothing has been tagged or published, so no user is affected, and the rename is kept
  rather than reverted because the new ID names what the rule detects: a raw query builder
  call, which is a Laravel construct, not a PHP one. It is recorded here because the old ID
  was already announced as shipped. **This is the last rule ID rename.** From the 0.0.1 tag
  onward, invariant 7 binds.
```

- [ ] **Step 7: Run the full suite and commit**

```bash
uv run pytest -q 2>&1 | tail -1
```

Expected: `399 passed`.

```bash
git add tests/fixtures/laravel-minimal/expected.yml src/rules.py CHANGELOG.md
git commit -m "fix: revive the dead php.sql-injection assertion after the rename

529d72d renamed php.sql-injection to laravel.raw-query but left a must_not_find entry
citing the old ID. No rule can emit it, so the entry was vacuously true and could
never fail. Repointed at the live ID and verified it fails when violated. The rename
itself is announced in the changelog: it breached invariant 7, and nothing is
published, so it stands as the last one."
```

---

### Task 7: Reformat, lint clean, correct the roadmap, and guard the gates

The last mile: 15 files need formatting, 86 ruff errors remain in `src`/`tests`, the roadmap
status table understates the work by 27 rules and 9 taint kinds, and nothing stops the next red
commit from landing on `main`.

**Files:**
- Modify (format): `src/config.py`, `src/graph.py`, `src/laravel/vocabulary.py`, `src/models.py`,
  `src/parser.py`, `src/rules.py`, `src/structural.py`, `src/taint.py`, `tests/harness.py`,
  `tests/test_coverage.py`, `tests/test_custom_taint.py`, `tests/test_missing_authorization.py`,
  `tests/test_rules.py`, `tests/test_scanner_config.py`, `tests/test_shell_taint.py`
- Modify: `docs/24-roadmap/README.md` (the v0.1 status table)
- Modify: `CHANGELOG.md`
- Create: `.github/branch-protection.md` (the settings to apply, recorded in-repo)

**Interfaces:**
- Consumes: a mypy-clean `src/` from Task 6.
- Produces: all four gates green, and a `main` that rejects a red push.

- [ ] **Step 1: Apply the safe autofixes**

```bash
uv run ruff check --fix src tests
uv run ruff format src tests
```

- [ ] **Step 2: Read what remains and fix it by hand**

```bash
uv run ruff check src tests --output-format=concise
```

The residue is dominated by `E501` (40 line-length) and `UP006` (15 deprecated typing generics,
`List[x]` to `list[x]`). Fix `UP006`, `UP035`, `UP045`, `F401` (unused import) and `F841`
(unused variable) by hand. For each `E501`, wrap the line; do not add a `noqa`.

- [ ] **Step 3: Confirm all four gates pass**

```bash
uv run pytest -q 2>&1 | tail -1
uv run ruff format --check .
uv run ruff check
uv run mypy
```

Expected: `399 passed`, `85 files already formatted`, `All checks passed!`,
`Success: no issues found`.

- [ ] **Step 4: Verify the v0.1 status table still matches the code**

`docs/24-roadmap/README.md` was corrected in the same commit that introduced this plan: the
rule set row went from "Four rules" to the 30 live IDs, the taint row from three kinds to
eleven, and the knowledge graph row stopped claiming the CFG was unbuilt. Two rows were added
for suppression and for user-defined sources. Re-verify the numbers still hold after Tasks 1-6b:

```bash
grep -oE '^[A-Z_]+_RULE = "[a-z]+\.[a-z-]+"' src/laravel/vocabulary.py \
  | sed 's/.*= "//;s/"//' | sort -u | wc -l          # expect 30 unique rule IDs
grep -oE "TaintKind\.[A-Z_]+" src/laravel/vocabulary.py | sort -u | wc -l   # expect 11
```

If either number moved, a task in this phase changed detection behaviour, which it was not
supposed to. Find out which before continuing, and update the table to match the code rather
than the other way round.

- [ ] **Step 5: Record the branch protection settings**

Create `.github/branch-protection.md` with exactly the content between the four-backtick
fences below (the inner three-backtick block is part of that file's content):

````markdown
# Branch protection on `main`

`main` was red for seven consecutive commits between 2026-08-12 and 2026-08-19 because pushes
land without CI having to pass. A build nobody can merge past is the only kind that stays
green.

Apply in Settings > Branches > Add rule, or with the `gh` command below:

- Branch name pattern: `main`
- Require a pull request before merging: **on**
- Require status checks to pass before merging: **on**
  - Required check: `check` (the single job in `.github/workflows/ci.yml`)
- Require branches to be up to date before merging: **on**
- Do not allow bypassing the above settings: **on**

```bash
gh api -X PUT repos/HafizMMoaz/vigilloo/branches/main/protection \
  -H "Accept: application/vnd.github+json" \
  -f 'required_status_checks[strict]=true' \
  -f 'required_status_checks[contexts][]=check' \
  -f 'enforce_admins=true' \
  -f 'required_pull_request_reviews[required_approving_review_count]=0' \
  -f 'restrictions=null'
```

The review count is zero deliberately: this is a solo repository, and the value of the rule is
the status check, not a second pair of eyes that does not exist.
````

- [ ] **Step 6: Apply the branch protection**

Run the `gh api` command from the file just created. Then verify:

```bash
gh api repos/HafizMMoaz/vigilloo/branches/main/protection -q '.required_status_checks.contexts'
```

Expected: `["check"]`.

- [ ] **Step 7: Add the changelog entry**

Under `## [Unreleased]`, add a `### Fixed` section:

```markdown
### Fixed

- **The four CI gates pass again.** `main` had been red for seven commits: 20 mypy errors
  across `taint.py`, `structural.py`, `graph.py` and `rules.py`, 113 ruff errors, and 24
  files that needed reformatting, while all 399 tests passed throughout. Two of the twenty
  were more than style. `taint.py` imported `authenticated_by` through `structural.py`
  rather than from `laravel/middleware.py` where it is defined, which is the taint producer
  depending on the structural producer that CLAUDE.md keeps apart. And the CFG walk took
  `block: object`, so every attribute access inside the branch-sensitive walk went
  unchecked. No rule changed behaviour: the test count is 399 before and after.
```

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "chore: green the four CI gates and protect main

Formatting, lint and the roadmap status table, which understated the shipped work by
27 rules and 8 taint kinds. main now requires the CI job to pass before a merge, which
is what would have caught the previous seven commits."
```

- [ ] **Step 9: Verify CI is green on the remote**

```bash
git push && sleep 60 && gh run list --limit 1
```

Expected: `completed  success`. This is the first green build since 2026-08-12.

---

# Phase 2: Measure

The v0.1 ship gate in [22-testing](../22-testing/README.md) requires "100% of seeded findings,
≥90% precision on real applications, clean runs on 10 open-source Laravel apps". Today every
fixture is synthetic and there is no machine-readable output to diff, so **the false-positive
rate of all 31 rules is unknown**. That is now the largest single risk in the project: a rule
that fires wrongly on real Laravel code is the noise CLAUDE.md warns makes developers stop
reading security reports.

Phase 2 is specified at task level here. Each task gets its own bite-sized plan written
immediately before it is executed, because the shape of Tasks 10 and 11 depends on what Task 9
measures.

### Task 8: JSON report format

Blocks everything else in this phase: precision cannot be measured without a stable
machine-readable output to diff between runs. Per [16-reporting](../16-reporting/README.md).
`vigilloo scan --format json` emits the `Finding` schema including the complete evidence path
and the `fingerprint`, sorted deterministically. A byte-identical-output test across two runs
on the same fixture enforces invariant 8. Ships with the Markdown format from the same
serialisation layer, since both read the same `Finding` list.

### Task 9: The ten-application corpus and the precision harness

Vendor ten real open-source Laravel applications as git submodules pinned to a commit, so the
corpus is reproducible and does not bloat the repository. Candidates to evaluate for Laravel
9-11 compatibility: Monica, Firefly III, Koel, Cachet, Akaunting, Snipe-IT, Pixelfed, Bagisto,
Invoice Ninja, and Laravel's own `laravel/laravel` skeleton as the clean-run control.

The harness runs `vigilloo scan --format json` over each, and produces a per-rule table:
findings emitted, findings triaged true, findings triaged false, precision. Triage is manual
and recorded in a checked-in `corpus/triage.yml` keyed by fingerprint, which is exactly what
location-independent fingerprints (invariant 3) exist to make possible. The output is a
report, not a gate, on its first run.

### Task 10: Retune or retire the rules the corpus indicts

Driven entirely by Task 9's table. Expect the structural rules with broad preconditions to be
the noisy ones: `laravel.no-throttle` and `laravel.unauthenticated-route` fire off the route
table alone and will hit every legitimately public API endpoint. Options per rule, in order of
preference: tighten the precondition, lower `confidence` so it sorts below the sharp findings,
or move it behind a non-default severity. **Retiring a rule ID is not an option** (invariant 7);
a rule that must stop firing gets its precondition narrowed to nothing and stays registered.

### Task 11: Turn the precision gate on in CI

Once Task 10 lands, add the corpus precision run to `.github/workflows/ci.yml` as a gate, in
the same shape as the existing coverage gates step. Below 90% precision or any regression in
seeded-finding recall fails the build. This is the check that lets the roadmap say v0.1
"ships when" honestly.

---

# Phase 3: Ship the surface

Only after Phase 2 says the engine is trustworthy. Each of these gets a bite-sized plan when
reached.

### Task 12: `vigilloo init` and `vigilloo doctor`
Per [19-cli](../19-cli/README.md). `init` writes a starter `vigilloo.yml`; `doctor` reports
detected framework, parse rate, and configuration problems. Smallest commands, and they make
the tool usable on a project it has never seen.

### Task 13: `vigilloo baseline` and `vigilloo review`
The suppression machinery already exists (inline, config globs, baseline files); these are the
commands that drive it. `baseline` writes the current findings as an accepted set; `review`
shows only what is new against it.

### Task 14: `vigilloo graph` and `vigilloo explain`
The store already reads findings back with complete evidence paths and exports the graph to
JSON and GraphML deterministically, but no command surfaces either. `explain <fingerprint>`
prints one finding's path step by step. This is the command that demonstrates the graph, which
is the product's differentiator, so it deserves care disproportionate to its size.

### Task 15: SARIF 2.1.0
The integration unlock: SARIF is what GitHub code scanning, GitLab and every CI dashboard
consume. Nominally a v1.0 item in the roadmap, but it is a serialisation of a `Finding` list
that Task 8 already produces, and without it the tool cannot enter anyone's pipeline. Pull it
forward and update the roadmap accordingly.

### Task 16: `vigilloo deps` and `vigilloo secrets`
The last two commands and the only ones needing new detection. `deps` reads `composer.lock`
against a vendored advisory database, offline per invariant 6. `secrets` is entropy plus
pattern matching over the tree. Both are self-contained and neither touches the taint engine.

---

## What this plan deliberately does not do

**No ASM and no red-teaming work.** [25-attack-surface-monitoring](../25-attack-surface-monitoring/README.md)
and [26-autonomous-red-teaming](../26-autonomous-red-teaming/README.md) are 21 and 24 lines of
vision, not specification, and the roadmap places them at v2.0 and v3.0. Two findings from the
competitive review support leaving them there: no open-source tool on either the OWASP or Wiz
list does interprocedural taint analysis for PHP or Laravel, so the deepest available moat is
the one already half-dug; and an attack engine built over an unmeasured static engine inherits
every one of its false positives and then tries to exploit them.

When ASM does arrive, two decisions from the reference review should be revisited before
implementation:

- `docs/25` currently states ASM modules will be built "natively in Python". For subdomain
  enumeration that is the wrong call: OWASP Amass is mature and shells out cleanly. Native
  building is right for the correlation layer (`DOMAIN` and `ENDPOINT` nodes joined to `ROUTE`
  nodes by `HOSTS` and `EXPOSES` edges), which is where the value is and where nothing
  off-the-shelf exists.
- Decepticon's two-network isolation (management plane separate from an offensive
  `sandbox-net`) is worth adopting in `docs/26` and is stronger than the container-only
  isolation currently written there. Its Neo4j dependency is not worth adopting: the
  deterministic content-addressed SQLite graph is the differentiator, and a second store is a
  second place for identity to drift.
