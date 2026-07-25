# Testing

A security scanner's own test suite is the only evidence that its results mean anything. False
negatives are invisible in production - nobody notices the vulnerability that was never
reported - so they have to be caught here or not at all.

## Layers

| Layer | Scope | Speed | Runs on |
| --- | --- | --- | --- |
| **Unit** | Parser, symbol resolution, CFG, taint propagation, individual rules | ms | every commit |
| **Fixture** | Synthetic Laravel apps with known vulnerabilities | seconds | every commit |
| **Corpus** | Real open-source Laravel applications | minutes | every PR |
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

## Rule testing

Every rule ships with positive and negative cases in the same file as its definition. A rule
without both is rejected in review. The negative case is the important one - it is the
difference between a rule and a nuisance.

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
