# Testing

A security scanner's own test suite is the only evidence that its results mean anything. False
negatives are invisible in production - nobody notices the vulnerability that was never
reported - so they have to be caught here or not at all.

## Layers

| Layer | Scope | Speed | Runs on |
| --- | --- | --- | --- |
| **Unit** | Parser, symbol resolution, CFG, taint propagation, individual rules | ms | every commit |
| **Fixture** | Synthetic Laravel apps with known vulnerabilities | seconds | every commit |
| **Corpus** | Real open-source Laravel applications | minutes | nightly, subset on PRs |
| **Regression** | Every fixed bug, permanently | seconds | every commit |
| **Performance** | Scan time and memory against NFR targets | minutes | nightly |
| **Determinism** | Same input → byte-identical output | seconds | every PR |

## The benchmark corpus

The centre of the strategy. Two halves:

**Seeded fixtures** - small Laravel apps written for the purpose, each with a manifest of
exactly which findings should appear, at which lines, with which evidence path:

```
tests/corpus/laravel-sqli/
  app/, routes/, composer.json
  expected.yml
```

```yaml
findings:
  - rule: php.sql-injection
    file: app/Http/Controllers/OrderController.php
    line: 44
    severity: critical
    path:
      - { role: source, symbol: 'Illuminate\Http\Request::input' }
      - { role: sink,   symbol: 'Illuminate\Database\Query\Builder::orderByRaw' }
must_not_find:
  - rule: php.sql-injection
    file: app/Http/Controllers/SafeController.php   # correctly parameterised - must stay silent
```

`must_not_find` carries equal weight with `findings`. A rule that catches everything by firing
constantly is worthless, and only negative fixtures keep that honest.

**Real applications** - a pinned set of open-source Laravel projects. These catch what synthetic
fixtures never do: unusual project layouts, heavy package use, legacy patterns, sheer scale.
Expectations here are a reviewed snapshot rather than ground truth, so the test asserts "no new
findings and no lost findings versus the approved snapshot", with changes requiring human review.
The same per-application file, keyed by finding fingerprint, also carries a three-state verdict
per finding. Precision is counted over reviewed verdicts only, and unreviewed findings are
reported as a separate coverage number and never folded into precision. This third state exists
because on a first run precision is undefined rather than 0% or 100%, and a gate treating
undefined as either would be wrong in opposite directions.

Where possible, include applications with **published CVEs** at a vulnerable commit - real bugs
that were real, with a known correct answer.

## Metrics gated in CI

| Metric | Target |
| --- | --- |
| True positives on seeded fixtures | 100% - a missed seeded finding fails the build |
| False positives on `must_not_find` | 0 |
| Precision on the real-app corpus | ≥ 90% (NFR-6) |
| Parse success rate | ≥ 99.5% of PHP files across the corpus |
| Call-graph resolution rate | ≥ 85% of call sites resolved above 0.5 confidence |
| Scan time, 100k LOC | ≤ 60s |
| Peak memory, 500k LOC | ≤ 2 GB |

Resolution rate is the leading indicator: unresolved calls are where false negatives hide, so
tracking it catches regressions before they show up as missed findings.

### How the two rates are computed

Both are ratios of counts the scan already recorded while running, never a sample and never an
estimate. `vigilloo.models.Coverage` holds the counts; the rates are properties derived from
them, so the number and the counts printed beside it cannot disagree.

**Parse success rate** = files read and parsed with no syntax error ÷ every `.php` and
`.blade.php` file discovered under the project root, excluding `vendor/`, `node_modules/`,
`storage/`, `bootstrap/` and `.git/`. A file that could not be read counts against the rate
exactly like one that would not parse: both are source the scan did not analyse, and the
distinction is of no comfort to the reader of the report. A file with a syntax error is still
analysed as far as its syntax allows, and still counts as a failure here.

**Call-graph resolution rate** = resolutions followed ÷ resolutions attempted, where an attempt
is any point at which the analysis had to turn a name in the source into something it could
follow: a `Route::verb` registration into a route, a route into a controller action, a method
call into a callee, a `view()` call into a template. It is therefore a superset of call sites
today, and grows toward being dominated by them as the walk learns to follow more constructs.
Attempts are counted only where the answer would have changed what the analysis saw - an
unresolvable receiver carrying no tainted data is neither a success nor a failure - because a
counter that reports gaps on correct code trains people to ignore it.

The 0.5 confidence threshold in the table above is forward-looking: resolution is currently
all-or-nothing, so every attempt is scored 1 or 0 and the threshold has nothing to apply to.
It becomes meaningful with the confidence-scored strategies in
[07-call-graph](../07-call-graph/README.md), and the denominator does not change when it does.

**Zero attempts is 1.0**, for both rates. A project with no PHP files, or one whose walk found
nothing to resolve, hid nothing; 0.0 would report an empty diff as total blindness and fail this
gate on it, and an error would turn an empty directory into a crashed scan. The counts are
reported next to every rate exactly so that a vacuous 100% cannot be mistaken for a scanned
codebase.

`tests/fixtures/laravel-unparseable/` exists to keep one measurement below 100%. A fixture set
that always scores perfectly cannot tell a working metric from a constant, and the file in it
that does not parse is deliberate: fixing its syntax silently disables the test.

### Which corpus the two gates run over

`tests/test_coverage_gates.py` applies both floors, and CI runs it as a named step of its own so
a failure reads as "coverage gate" rather than as one red test among hundreds.

The gate is applied **per fixture, over the seeded fixtures only**, and `laravel-unparseable` is
excluded by name. That fixture scores 66.7% by design, so gating it would mean either a build
that is red forever or a parse floor low enough to clear 66.7%, which gates nothing. Its
exclusion is asserted rather than assumed: a test fails if its broken file ever starts parsing.

Per fixture rather than over pooled totals, because it is the stricter reading - a pooled ratio
of numbers each at or above the floor is itself at or above it - and because a failure that
names the fixture is one somebody can act on.

## Rule testing

Every rule ships with positive and negative cases in the same file as its definition. A rule
without both is rejected in review. The negative case is the important one - it is the
difference between a rule and a nuisance.

## Regression tests

`tests/regression/`, one test per bug that has already been fixed once. The Layers table calls
this a permanent layer, and permanent is the whole of the rule: a test lands here when a bug is
found and is never deleted because the bug looks old.

Four requirements, each of which a regression test fails without:

- **It names the commit that fixed the bug.** A reader who wants the reasoning needs the diff,
  and the commit message is where it is.
- **Its docstring says concretely what the engine produced before the fix** - the wrong output,
  not a description of the area. A test whose author could not state the old behaviour has not
  established that it would have caught it.
- **It pins the symptom, not the mechanism.** The unit tests a fix commit carries already pin
  the mechanism, and they are supposed to be rewritten when the mechanism is. This layer pins
  what a user would have seen: a finding in the report that should not be there, a scan
  claiming full coverage over a trail it silently dropped. When a refactor moves a give-up out
  of one function and into another, the unit test is what gets updated and this is what still
  has to hold.
- **It fails against the pre-fix behaviour.** A regression test that passes both before and
  after the fix is not a regression test, and the only way to know which one you have written
  is to check.

The bugs found so far cluster: the walk lost tainted data and said nothing, so the report was
clean and the coverage line claimed everything resolved. That is invariant 4's exact failure
mode, and it is invisible in production, because nobody files a bug about the vulnerability
that was never reported.

## Property-based testing

Hypothesis for the parser and taint engine, where hand-written cases run out:

- Any syntactically valid PHP parses without crashing
- Taint propagation is monotonic - adding a source never *removes* a finding
- Node IDs are stable under whitespace and comment changes
- Sanitizing a path always removes the finding for that taint kind, and only that kind

## Determinism test

Scan a fixture twice, in different working directories, with different `--jobs`, and diff the
JSON. Any difference is a bug - parallelism leaking into output ordering is the usual cause, and
it silently breaks CI diffing for every user.

## AI testing

The AI layer is non-deterministic, so it is tested differently: with the provider mocked for
pipeline logic, with the validation gate ([09-ai-engine](../09-ai-engine/README.md)) tested
against deliberately bad model output - invalid JSON, invented citations, non-applying patches,
patches that introduce new sinks - and with a small live-provider smoke suite run manually
before releases, never in CI.

The critical invariant, asserted in CI: **deterministic findings are identical with AI enabled
and disabled.**

## Tooling

pytest, pytest-xdist for parallelism, Hypothesis, pytest-benchmark, coverage with a floor on
core analysis modules. Full corpus runs nightly; PRs run unit + fixture + regression only, so
the fast loop stays fast.
