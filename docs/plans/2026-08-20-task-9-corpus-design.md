# Task 9 Design: The Corpus and the Precision Harness

**Status:** implemented.
**Supersedes nothing.** Builds on Task 8 (JSON and Markdown report formats), merged as PR #52.
**Normative references:** [22-testing](../22-testing/README.md), [16-reporting](../16-reporting/README.md),
[01-prd](../01-prd/README.md), [24-roadmap](../24-roadmap/README.md).
Where this document and those disagree, those win and this is the bug.

**Parent plan:** [2026-08-19-stabilise-measure-ship-v0.1.md](2026-08-19-stabilise-measure-ship-v0.1.md),
Phase 2 Task 9. That document specifies Task 9 at task level; this one designs it.

## Why this task

The engine registers 32 rules. Every one of them has only ever run against synthetic fixtures,
where the answer was known in advance because the finding was planted. The false-positive rate
on real Laravel code is unmeasured, and `CLAUDE.md` names the consequence directly: a rule that
fires wrongly on real code is the noise that makes developers stop reading security reports.

[01-prd](../01-prd/README.md) makes ≥90% precision on real applications a v0.1 ship gate
(NFR-6). Nothing today can produce that number. Task 9 produces it.

## Measured facts, 2026-08-20

A throwaway probe scanned `monicahq/monica` at `e08e917` (1,649 PHP files, 134,583 PHP LOC,
`vendor/` absent) on the Task 8 head. These numbers are recorded because they change the design,
not as a performance report:

| Measure | Value |
| --- | --- |
| Largest existing fixture | 36 PHP files |
| Monica | 1,649 PHP files, **46x** the largest fixture |
| NFR-1 budget at ≤60s per 100k LOC | ~81s |
| Observed | >1,849s, still running when the probe was cut |
| Overrun | **>22x**, unbounded at time of writing |
| Peak RSS | ~156 MB, against NFR-2's 2 GB ceiling |
| CPU | 98%+ throughout, single core |

Two conclusions follow. First, the problem is **time, not space**: no leak, no thrash, no hang,
something superlinear in file count. Second, the engine has never been shown more than 36 files,
which is why no existing test could have caught this.

### Consequence for sequencing

A nightly ten-application corpus is not reachable until scan cost is addressed. This is recorded
here as a **discovered prerequisite**, owned and explicit, rather than left to be rediscovered
during execution:

- **Task 9 wave 1 enrols only applications that scan in workable time.** Ten applications is a
  v0.1 ship-gate number from [01-prd](../01-prd/README.md), not a Task 9 delivery number.
- **A profiling pass is a real task** and belongs in the phase plan. It is not designed here.
  It wants a profile and a systematic-debugging pass, not a guess at the hot path.
- The harness records per-application scan duration and peak RSS from the outset, so the
  profiling work has real data rather than synthetic timings.

## What Task 9 produces

One artifact serving two gates:

- **Precision.** Of the findings reported, what fraction are real. The NFR-6 number.
- **Drift.** Whether the finding set has changed against the last reviewed state.

Precision answers "are we right"; drift answers "did we change". Both are needed, and both read
from the same file. [22-testing](../22-testing/README.md) specifies real-application
expectations as "a reviewed snapshot rather than ground truth"; the parent plan specifies
triage-based precision. They are two views of one triage record, not two records.

### Why precision alone is insufficient

A scanner that reports nothing scores 100% precision. Zero findings, zero wrong findings. If
precision were the only gate, the cheapest route to green would be to break every rule. Recall
is therefore in scope for Task 9, via CVE pins (below), and not deferred.

## Decisions

| # | Decision | Rationale |
| --- | --- | --- |
| 1 | One triage record per application, serving both gates | No second source of truth to drift |
| 2 | Nightly full corpus, PR-time subset | Resolves the cadence contradiction in `22-testing`; PR latency is on the critical path of a protected branch |
| 3 | Pin each application to its last Laravel 9-11 commit | v0.1 scope is Laravel 9-11 (`CLAUDE.md`). Monica's HEAD is already `^12.0` |
| 4 | 2-3 applications pinned at known-CVE commits | The only part of the corpus that measures recall |
| 5 | Pure set-diff logic in `src/`, orchestration in `scripts/` | mypy covers `src` only; the part computing the ship gate must be type-checked |
| 6 | Per-rule review quota, not a flat cap | A flat cap is consumed by the noisiest rule, leaving most rules unmeasured |
| 7 | Applications enrolled as git submodules, never vendored | Submodules reference by URL and SHA. Monica is AGPL-3.0; copying it into a proprietary repository would be a licensing problem. **Do not "simplify" this into a plain copy.** |

## Data model

`corpus/triage/<app>.yml`, one file per application. Per-application rather than a single
`corpus/triage.yml` so that re-pinning one application leaves every other application's reviewed
work untouched, and so each diff is scoped to what actually moved.

```yaml
# corpus/triage/monica.yml
pin: e08e91734170b6bbd582cb578532c3948196124e
reviewed_ruleset: 4f2a9c...          # RULESET_HASH at review time
findings:
  a3f9c2e1b8d47056:
    verdict: true                     # true | false | unreviewed
    rule: php.sql-injection
    note: "Reaches orderByRaw via $request->input, no binding."
    seen_at: app/Http/Controllers/ContactController.php:212
```

**Keyed by fingerprint.** Invariant 3's location-independent `fingerprint` is what makes hand
triage survive reformatting and upstream commits. A location key would orphan the entire file
the first time someone adds an import. Task 8's plan already anticipated this use.

**`seen_at` is non-authoritative.** Written by the harness, never parsed by it. It exists so a
reviewer opening the file months later is not reading bare hex. The moment a human-editable
location field is read back, there are two answers to where a finding is, and they will
disagree after the first pin bump.

**`reviewed_ruleset` records the `RULESET_HASH` at review time.** A verdict was reached against
a specific rule definition. `CLAUDE.md` records that editing rule prose moves the hash. When it
moves, prior verdicts are stale evidence, and the harness reports them as such rather than
silently counting them as current.

### The three-state verdict

`unreviewed` is a first-class state, not a missing entry.

- `precision = true / (true + false)`, over reviewed findings only
- `unreviewed` is reported as a separate review-coverage number, never folded into precision
- The gate requires **both** a precision floor and a review-coverage floor

On the first run everything is `unreviewed`, so precision is *undefined*, not 0%. A gate
treating undefined as 0% fails the build on day one; one treating it as 100% passes vacuously.
This mirrors [22-testing](../22-testing/README.md), which reports counts beside every rate
"so that a vacuous 100% cannot be mistaken for a scanned codebase".

The third state is also what makes the corpus incrementally adoptable. A binary schema forces
full triage of every application before any number exists, which is how corpus efforts stall.

### Bounding the triage work

Review up to **N findings per rule per application**, selected in fingerprint order.

- **Per-rule, not a flat cap.** A flat cap is consumed by whichever rule is noisiest, leaving
  most of the 32 rules with no precision estimate at all. The noisy rules are exactly what Task
  10 needs to find, and they must not crowd out the rest.
- **Fingerprint order, not arbitrary order.** Selection must be stable across runs, or the
  reviewed set churns and prior verdicts stop applying. Content-derived fingerprints give a
  deterministic order for free.
- Review coverage is then "rules with at least N reviewed findings", a meaningful denominator.

## Components and data flow

`mypy` covers `files = ["src"]`; `pytest` collects `testpaths = ["tests"]`. Placement therefore
decides whether the code computing the ship gate is type-checked.

| Path | Contents | Checked by |
| --- | --- | --- |
| `src/baseline.py` | Fingerprint-set diff: added / removed / unchanged. Pure, no I/O | mypy strict, already in scope |
| `scripts/corpus.py` | Orchestration: pins, scan runs, verdict recording, precision counting, table rendering | mypy, via extending `files` to name this script |
| `tests/test_corpus_precision.py` | Gate assertions and harness-can-fail cases | pytest |
| `corpus/<app>/` | Submodule pointers only. No vendored source | git |
| `corpus/pins.yml` | Pin SHA, Laravel version, PHP version, file count, LOC, rationale | review |
| `corpus/triage/<app>.yml` | Verdicts. Committed | review |
| `corpus/reports/<app>.json` | Raw scan output. Gitignored build artifact | nothing |

**Set-diff belongs in `src/`, not in the harness.** Comparing a fresh fingerprint set against an
approved one is precisely what `vigilloo baseline` does, scheduled as Task 13 in the parent
plan. Writing it as corpus-private code guarantees Task 13 reimplements it with subtly different
semantics about what counts as "the same finding". Two answers to that question is the drift
invariant 3 exists to prevent.

```
scripts/corpus.py scan    -> vigilloo scan --format json -> corpus/reports/<app>.json
scripts/corpus.py triage  -> reads reports + triage.yml  -> writes verdicts back
scripts/corpus.py report  -> joins both                  -> precision table + drift
tests/test_corpus_precision.py                           -> asserts the floors in CI
```

**Reports are gitignored.** Because triage is keyed by fingerprint, the triage file already
*is* the approved fingerprint set. Drift is `set(fresh scan)` against `set(triage file)`. No
separate snapshot exists to fall out of sync, and the repository does not grow without bound.

**A new finding is drift and unreviewed at once.** That is one condition, reported once.
Reporting it twice is how a corpus report becomes the noise Task 9 exists to measure.

## Corpus composition and pin selection

### Pin selection, per application

1. Full clone. `--depth 1` cannot reach history.
2. `git log --follow -p composer.json` for the `laravel/framework` constraint.
3. Take the newest commit still declaring `^9`, `^10` or `^11`.
4. Record SHA, Laravel version, PHP version, PHP file count and LOC in `corpus/pins.yml`.

Note: write the history walk in step 2 to a script file and run that, rather than pasting it as
a single multi-line shell invocation. The loop garbles when pasted, which cost time the first
time this was executed.

Step 4 is not bookkeeping. A pin with no recorded rationale cannot be audited, and when v1.0
widens the target, whoever re-pins needs to know why each SHA was chosen.

### CVE pins

For the 2-3 recall applications, select advisories whose weakness maps to a rule that already
exists. A CVE for an undetected class would sit permanently unfound and teach nothing. GitHub
Security Advisories are queryable per repository, so this is research, not guesswork.

**Acceptance criterion is a pair:** the engine finds the CVE at the vulnerable pin *and does not
find it* at the fixed pin. A rule firing at both is matching something incidental. This is
`must_not_find` from [22-testing](../22-testing/README.md) applied to real code.

### Enrolment in waves

Wave 1 enrols three or four applications spanning the size range, proving the harness and the
triage workflow end to end. Growth follows the profiling work. The PR-time subset is chosen by
measured scan time, not by preference: initially the `laravel/laravel` skeleton alone, since
nothing else currently fits on the critical path of a protected branch.

## CI wiring

| Workflow | Runs | Contents |
| --- | --- | --- |
| `ci.yml` `check` job | every push and PR | Unchanged. The four gates stay fast |
| `ci.yml` corpus subset | every PR | `laravel/laravel` skeleton, initially |
| `corpus-nightly.yml` | nightly | Full enrolled set, precision table, drift, duration, RSS |

Gates are **report-only in Task 9**. The parent plan is explicit that the first run produces a
report, not a gate, and that Task 11 turns it on. Reporting is wired completely and the
threshold comparison sits behind a flag, so Task 11 is a one-line change.

Per [22-testing](../22-testing/README.md), the corpus runs as a **named CI step** so a failure
reads as "corpus gate" rather than as one red test among hundreds, matching the existing
`test_coverage_gates.py` precedent.

`actions/checkout` with submodules clones every enrolled application on every nightly run. This
needs caching, or the job spends most of its time on git rather than analysis.

## Failure modes

The dangerous failures all point the same way: **toward a falsely good number.**

| Failure | Wrong behaviour | Required behaviour |
| --- | --- | --- |
| Scan crashes | Empty report scores 100% precision | Hard failure |
| Scan times out | Truncated report, inflated precision | Explicit timeout, hard failure |
| Scan OOM-killed | Partial report counted as complete | Hard failure |
| Parse rate collapses | Clean result over unparsed code | Fail if coverage is below floor |
| Zero findings, non-empty triage | Reported as perfect | Reported as drift |

Every scan gets an explicit timeout, and a timeout is never an empty report.

### The harness tests itself

`tests/test_corpus.py` sets the precedent and states the reason: "a test harness that cannot
fail is not a test harness." The corpus harness gets the same treatment, with cases for a
verdict referencing an unknown fingerprint, a stale `reviewed_ruleset`, malformed YAML, an empty
report, and a truncated report.

A buggy precision harness fails in the most dangerous direction, because the common bug is
dropping findings on a join miss, which reports a *better* number than reality.

## Spec changes this design requires

Docs are the spec, and these land in the same commits as the work:

1. **[22-testing](../22-testing/README.md) contradicts itself on cadence.** The Layers table
   says the corpus runs "every PR"; the Tooling section says "Full corpus runs nightly; PRs run
   unit + fixture + regression only". Resolved toward the Tooling section. The Layers table is
   corrected.
2. **[22-testing](../22-testing/README.md) real-application framing.** Currently specifies a
   reviewed snapshot only. Updated to describe the single triage record serving both precision
   and drift.
3. **[24-roadmap](../24-roadmap/README.md)** gains the corpus row, per the standing rule that
   per-capability status has one home.

## Out of scope

- **The profiling and performance work.** Named as a prerequisite above, designed separately.
- **Task 10 retuning.** Driven entirely by what the corpus measures.
- **Turning the gate on.** That is Task 11.
- **Widening scope to Laravel 12.** v0.1 is Laravel 9-11; changing that is a roadmap decision.

## Open questions

1. **N, the per-rule review quota.** Wants a first real finding distribution to set sensibly.
   Starts at a documented default and is tuned once wave 1 is triaged.
2. **Which applications reach wave 1.** Depends on measured scan times, which depend on the
   profiling work.
3. **Which CVEs map to existing rules.** Research, scheduled as its own plan step.
4. **Vigilloo's visibility into Laravel 11 routing and middleware.** `src/graph.py:52` excludes
   `bootstrap/` from discovery. That was correct for Laravel 9 and 10, where the directory held
   a trivial bootstrapper and a cache directory. In Laravel 11 and later, `bootstrap/app.php` is
   where routing and middleware are configured: it carries `->withRouting(...)` and
   `->withMiddleware(...)`. So on any Laravel 11 application the middleware stack and the
   route-file registration are invisible to the engine, a probable false-negative source for
   exactly the framework-structural rules `CLAUDE.md` calls the differentiator. Surfaced by the
   first enrolled application, whose scan reported 25 files discovered against 27 on disk.
   Fixing it means changing discovery and re-baselining every fixture's coverage numbers, so it
   wants its own task.
