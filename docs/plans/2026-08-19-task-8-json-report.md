# Task 8: JSON and Markdown report formats

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** `vigilloo scan --format json` emits the complete `Finding` list, with evidence paths,
fingerprints and coverage, byte-identically across runs, so precision can be measured by diffing
two scans.

**Architecture:** `src/report.py` becomes the `src/report/` package the dev guide's target layout
already names. A format-neutral `ReportDocument` is built once from `(findings, coverage,
metadata)`; the JSON and Markdown renderers are pure functions over it. The terminal renderer
moves in unchanged. Both new formats read the same document, so they cannot disagree about what
a scan found.

**Tech Stack:** Python 3.13, stdlib `json`, Typer, Rich, pytest.

**Spec:** [docs/16-reporting/README.md](../16-reporting/README.md). Parent plan:
[docs/plans/2026-08-19-stabilise-measure-ship-v0.1.md](2026-08-19-stabilise-measure-ship-v0.1.md),
Phase 2 Task 8.

## Global Constraints

- **Invariant 8, determinism.** Same input + same ruleset produces byte-identical JSON. Asserted
  by a test running two full scans and comparing bytes.
- **Invariant 2.** Every finding carries a complete evidence path. The JSON always includes it.
- **Invariant 4.** Coverage is reported, never hidden. It is a required key in the JSON, present
  on clean scans too.
- **Invariant 3.** `id` and `fingerprint` are emitted for every finding. They are what
  `corpus/triage.yml` will key on in Task 9.
- **No em dashes** in code, comments, docstrings, docs or commit messages. Use a hyphen.
- **Imports inside `src/` are relative.** `from ..models import Finding`, never
  `from vigilloo.models import Finding`.
- **Every new subpackage is registered in `pyproject.toml`**, in both `package-dir` and
  `packages`. An unregistered subpackage imports fine in the dev install and is silently missing
  from the wheel.
- **No shell heredocs.** They hang this environment's shell. Write files with the file-write
  tool.
- Four gates must pass before each commit: `uv run pytest`, `uv run ruff format --check .`,
  `uv run ruff check`, `uv run mypy`.

## File Structure

| File | Responsibility |
| --- | --- |
| `src/report/__init__.py` | Re-exports the public surface so `from .report import render, render_coverage` in `cli.py` keeps working unchanged. |
| `src/report/terminal.py` | The existing Rich renderer, moved verbatim. Prints. |
| `src/report/document.py` | `ReportDocument`, `ReportMetadata` and `build_document()`. Format-neutral, sorted, no I/O, never prints. |
| `src/report/json_report.py` | `render_json(document) -> str`. Named `json_report` so it never shadows stdlib `json` for a reader. |
| `src/report/markdown.py` | `render_markdown(document) -> str`. |
| `tests/test_report_document.py` | Sorting, coverage mapping, metadata. |
| `tests/test_report_json.py` | Schema shape, determinism, path portability. |
| `tests/test_report_markdown.py` | Structure of the rendered Markdown. |
| `tests/test_cli_format.py` | The `--format` flag, stdout purity, exit codes. |

`document.py`, `json_report.py` and `markdown.py` must stay under the T20 (`flake8-print`) lint
rule. Only `terminal.py` gets the ignore. This is deliberate: Phase 1 found a debug `print` in
`src/taint.py` that would have corrupted exactly this output, and T20 is the guard that stops it
recurring.

---

### Task 8a: Convert `src/report.py` into the `src/report/` package

Behaviour-preserving move. Separate commit because the packaging registration is the step that
fails silently when skipped, and it deserves to be bisectable on its own.

**Files:**
- Create: `src/report/__init__.py`
- Create: `src/report/terminal.py` (contents of the current `src/report.py`, unchanged)
- Delete: `src/report.py`
- Modify: `pyproject.toml:48-49` (both packaging tables), `pyproject.toml:72-75`
  (per-file-ignores)

**Interfaces:**
- Consumes: nothing.
- Produces: `vigilloo.report.render(findings: list[Finding], console: Console) -> None` and
  `vigilloo.report.render_coverage(coverage: Coverage, console: Console) -> None`, importable at
  exactly the paths they are importable at today.

- [ ] **Step 1: Move the module with git, so history follows it**

```bash
mkdir -p src/report
git mv src/report.py src/report/terminal.py
```

- [ ] **Step 2: Create the package `__init__.py`**

Create `src/report/__init__.py`:

```python
"""Report rendering, one module per format.

Every format renders the same `ReportDocument`, built once from a scan's
findings and coverage. Two formats that each walked the `Finding` list
themselves would eventually disagree about what a scan found, and the one a
developer reads is not the one CI gates on.
"""

from .terminal import render, render_coverage

__all__ = ["render", "render_coverage"]
```

- [ ] **Step 3: Fix the relative import depth in the moved module**

`src/report/terminal.py` currently reads `from .models import Coverage, Finding`. It is now one
level deeper. Change that line to:

```python
from ..models import Coverage, Finding
```

- [ ] **Step 4: Register the subpackage in both packaging tables**

In `pyproject.toml`, replace lines 48-49 with:

```toml
package-dir = { "vigilloo" = "src", "vigilloo.laravel" = "src/laravel", "vigilloo.workspace" = "src/workspace", "vigilloo.analysis" = "src/analysis", "vigilloo.report" = "src/report" }
packages = ["vigilloo", "vigilloo.laravel", "vigilloo.workspace", "vigilloo.analysis", "vigilloo.report"]
```

- [ ] **Step 5: Move the T20 ignore to the one module that prints**

In `pyproject.toml`, in `[tool.ruff.lint.per-file-ignores]`, replace the line
`"src/report.py" = ["T20"]` with:

```toml
"src/report/terminal.py" = ["T20"]
```

Leave the `src/cli.py`, `scripts/dump_ast.py` and `scripts/debt.py` entries alone. Do not add a
blanket `src/report/*` ignore: the serialising modules added in later tasks must keep failing
lint if they ever print.

- [ ] **Step 6: Run the four gates**

```bash
uv run pytest && uv run ruff format --check . && uv run ruff check && uv run mypy
```

Expected: all pass, with the same test count as before the move. This task adds no test because
it adds no behaviour; the existing suite passing unchanged is the assertion.

- [ ] **Step 7: Prove the wheel still contains the package**

```bash
uv build --wheel && uv run python -c "import zipfile,glob; print([n for n in zipfile.ZipFile(sorted(glob.glob('dist/*.whl'))[-1]).namelist() if 'report' in n])"
```

Expected: lists `vigilloo/report/__init__.py` and `vigilloo/report/terminal.py`. If it lists
neither, step 4 was skipped or mistyped, which is the exact silent failure the pyproject comment
warns about.

- [ ] **Step 8: Commit**

```bash
git add -A src/report pyproject.toml && git commit -m "refactor: make report a package, per the dev guide target layout

No behaviour change. src/report.py becomes src/report/terminal.py so the
JSON and Markdown renderers have somewhere to live beside it rather than
growing a single module to four hundred lines.

The T20 ignore moves with it rather than widening to the package. Only
terminal.py is allowed to print; a stray print inside a serialiser would
corrupt the JSON that Phase 2 measures precision by diffing, which is the
same failure Phase 1 found in taint.py."
```

---

### Task 8b: The format-neutral `ReportDocument`

**Files:**
- Create: `src/report/document.py`
- Test: `tests/test_report_document.py`

**Interfaces:**
- Consumes: `vigilloo.models.Finding`, `vigilloo.models.Coverage`.
- Produces:
  - `ReportMetadata(engine_version: str, ruleset_hash: str, schema_version: str)` frozen dataclass
  - `ReportDocument(metadata: ReportMetadata, coverage: Coverage, findings: tuple[Finding, ...])`
    frozen dataclass, with a `severity_counts` property returning `dict[str, int]`
  - `build_document(findings, coverage, engine_version, ruleset_hash) -> ReportDocument`
  - `SCHEMA_VERSION: str` (value `"1.0"`)
  - `SEVERITY_ORDER: dict[str, int]`

- [ ] **Step 1: Write the failing test**

Create `tests/test_report_document.py`:

```python
"""The document every format renders is sorted before any format sees it."""

from pathlib import Path

from vigilloo.models import Coverage, Finding, PathStep, Span
from vigilloo.report.document import SCHEMA_VERSION, build_document


def _finding(rule_id: str, severity: str, file: str, line: int) -> Finding:
    span = Span(file=Path(file), start_line=line, start_col=0, end_line=line, end_col=9)
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=f"{rule_id} in {file}",
        cwe=("CWE-89",),
        span=span,
        evidence_path=(PathStep(role="sink", span=span, snippet="q($x)"),),
    )


def _coverage() -> Coverage:
    return Coverage(
        files_discovered=10,
        files_unreadable=0,
        files_with_errors=1,
        calls_resolved=8,
        calls_unresolved=2,
    )


def test_findings_sort_by_severity_then_rule_then_path_then_line() -> None:
    """docs/16-reporting fixes this order. Input order must not survive.

    scan_project's output order is an implementation detail of the rule
    dispatch; if it ever changes, two scans of unchanged code would diff
    against each other and Task 9's precision harness would report churn
    that is not a detection change.
    """
    unsorted = [
        _finding("php.xss", "low", "b.php", 5),
        _finding("php.xss", "critical", "b.php", 5),
        _finding("php.xss", "critical", "a.php", 99),
        _finding("laravel.raw-query", "critical", "b.php", 5),
        _finding("php.xss", "critical", "b.php", 2),
    ]

    doc = build_document(unsorted, _coverage(), engine_version="0.1.0", ruleset_hash="abc")

    assert [(f.rule_id, f.severity, str(f.span.file), f.span.start_line) for f in doc.findings] == [
        ("laravel.raw-query", "critical", "b.php", 5),
        ("php.xss", "critical", "a.php", 99),
        ("php.xss", "critical", "b.php", 2),
        ("php.xss", "critical", "b.php", 5),
        ("php.xss", "low", "b.php", 5),
    ]


def test_severity_counts_only_names_severities_present() -> None:
    """A zero is not reported as a key.

    An absent severity and a severity with zero findings are the same fact,
    and emitting both shapes lets a consumer write a check that passes on one
    scan and fails on the next for no reason.
    """
    doc = build_document(
        [_finding("php.xss", "critical", "a.php", 1), _finding("php.xss", "low", "b.php", 1)],
        _coverage(),
        engine_version="0.1.0",
        ruleset_hash="abc",
    )
    assert doc.severity_counts == {"critical": 1, "low": 1}


def test_metadata_carries_no_timestamp() -> None:
    """Invariant 8. A duration or a wall clock in the document is a byte that
    changes between two identical scans, so neither is allowed to enter it.
    """
    doc = build_document([], _coverage(), engine_version="0.1.0", ruleset_hash="abc")
    assert doc.metadata.engine_version == "0.1.0"
    assert doc.metadata.ruleset_hash == "abc"
    assert doc.metadata.schema_version == SCHEMA_VERSION
    assert not hasattr(doc.metadata, "duration_ms")
    assert not hasattr(doc.metadata, "timestamp")
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
uv run pytest tests/test_report_document.py -v
```

Expected: FAIL, `ModuleNotFoundError: No module named 'vigilloo.report.document'`.

- [ ] **Step 3: Write the implementation**

Create `src/report/document.py`:

```python
"""The format-neutral report, built once and rendered many times.

Every format renders this document rather than walking the `Finding` list
itself. Two formats each doing their own walk would eventually disagree about
what a scan found, and the one a developer reads is not the one CI gates on.

Sorting happens here, once, for the same reason: `scan_project` returns
findings in rule-dispatch order, which is an implementation detail. Invariant 8
requires byte-identical output for identical input, so the order every format
sees has to come from the finding's own content, never from the order the
engine happened to produce it in.
"""

from dataclasses import dataclass

from ..models import Coverage, Finding

# Bumped when a consumer reading the previous version would misread the new
# one: a removed key, a renamed key, or a changed type. Adding a key is not a
# break and does not bump it.
SCHEMA_VERSION = "1.0"

# Severity is an ordered scale, and sorted() on the string is alphabetical:
# "critical" would sort under "high" and "info" above "low". The report exists
# to put the worst finding first, so the rank is explicit.
SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

_UNKNOWN_SEVERITY_RANK = len(SEVERITY_ORDER)


def _sort_key(finding: Finding) -> tuple[int, str, str, int, int, str]:
    """docs/16-reporting: severity, rule ID, path, line.

    Two further components follow the four the spec names. Column and
    fingerprint break ties between findings that agree on all four, which
    happens when one line holds two sinks. Without them `sorted` would preserve
    input order for the tie, and input order is exactly what this key exists to
    stop mattering.
    """
    return (
        SEVERITY_ORDER.get(finding.severity, _UNKNOWN_SEVERITY_RANK),
        finding.rule_id,
        finding.span.file.as_posix(),
        finding.span.start_line,
        finding.span.start_col,
        finding.fingerprint,
    )


@dataclass(frozen=True)
class ReportMetadata:
    """What produced this report, and nothing about when.

    Invariant 8 forbids a timestamp or a duration here. Both change between two
    scans of unchanged code, which would make every report diff non-empty and
    make Task 9's precision measurement unreadable. Timing belongs to the
    terminal output and the store's scan row, neither of which is diffed.
    """

    engine_version: str
    ruleset_hash: str
    schema_version: str = SCHEMA_VERSION


@dataclass(frozen=True)
class ReportDocument:
    """One scan, sorted, ready for any format."""

    metadata: ReportMetadata
    coverage: Coverage
    findings: tuple[Finding, ...]

    @property
    def severity_counts(self) -> dict[str, int]:
        """Findings per severity, worst first, omitting severities with none.

        An absent severity and a severity with a zero count are the same fact.
        Emitting both shapes would let a consumer write a check that passes on
        one scan and fails on the next without the code having changed.
        """
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return dict(
            sorted(
                counts.items(),
                key=lambda item: SEVERITY_ORDER.get(item[0], _UNKNOWN_SEVERITY_RANK),
            )
        )


def build_document(
    findings: list[Finding],
    coverage: Coverage,
    engine_version: str,
    ruleset_hash: str,
) -> ReportDocument:
    """Assemble the document. Pure, and the only place findings are ordered."""
    return ReportDocument(
        metadata=ReportMetadata(engine_version=engine_version, ruleset_hash=ruleset_hash),
        coverage=coverage,
        findings=tuple(sorted(findings, key=_sort_key)),
    )
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
uv run pytest tests/test_report_document.py -v
```

Expected: 3 passed.

- [ ] **Step 5: Run the four gates**

```bash
uv run pytest && uv run ruff format --check . && uv run ruff check && uv run mypy
```

- [ ] **Step 6: Commit**

```bash
git add src/report/document.py tests/test_report_document.py && git commit -m "feat: add the format-neutral ReportDocument

Sorting lives here rather than in each renderer. scan_project returns
findings in rule-dispatch order, which is an implementation detail; a
format that inherited it would diff against itself the first time rule
registration moved.

Metadata deliberately carries no timestamp and no duration. Both change
between two scans of unchanged code, and invariant 8 is what Task 9's
precision harness rests on."
```

---

### Task 8c: The JSON renderer

**Files:**
- Create: `src/report/json_report.py`
- Modify: `src/report/__init__.py`
- Test: `tests/test_report_json.py`

**Interfaces:**
- Consumes: `ReportDocument`, `build_document` from Task 8b.
- Produces: `render_json(document: ReportDocument) -> str`, re-exported as
  `vigilloo.report.render_json`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_report_json.py`:

```python
"""The machine-readable output Phase 2 measures precision by diffing."""

import json
import shutil
from pathlib import Path

from typer.testing import CliRunner

from vigilloo.cli import app
from vigilloo.models import Coverage, Finding, PathStep, Span
from vigilloo.report.document import ReportDocument, build_document
from vigilloo.report.json_report import render_json

runner = CliRunner()
FIXTURE = Path("tests/fixtures/laravel-minimal")


def _document() -> ReportDocument:
    span = Span(file=Path("app/X.php"), start_line=4, start_col=2, end_line=4, end_col=20)
    finding = Finding(
        rule_id="laravel.raw-query",
        severity="critical",
        title="SQL injection in X",
        cwe=("CWE-89",),
        span=span,
        evidence_path=(
            PathStep(role="source", span=span, snippet="$r->input('q')", note="request"),
            PathStep(role="sink", span=span, snippet="whereRaw($q)", rule_id="laravel.raw-query"),
        ),
        remediation="Bind the parameter.",
    )
    coverage = Coverage(
        files_discovered=4,
        files_unreadable=0,
        files_with_errors=1,
        calls_resolved=3,
        calls_unresolved=1,
    )
    return build_document([finding], coverage, engine_version="0.1.0", ruleset_hash="abc")


def test_finding_carries_its_whole_evidence_path() -> None:
    """Invariant 2. A finding serialised without its path is not a finding."""
    payload = json.loads(render_json(_document()))
    (finding,) = payload["findings"]
    assert [step["role"] for step in finding["evidence_path"]] == ["source", "sink"]
    assert finding["evidence_path"][0]["snippet"] == "$r->input('q')"
    assert finding["fingerprint"]
    assert finding["id"]


def test_coverage_is_present_even_when_perfect() -> None:
    """Invariant 4. Coverage is reported, never hidden, and a consumer must
    never have to treat its absence as meaning 100%.
    """
    coverage = Coverage(
        files_discovered=2,
        files_unreadable=0,
        files_with_errors=0,
        calls_resolved=2,
        calls_unresolved=0,
    )
    doc = build_document([], coverage, engine_version="0.1.0", ruleset_hash="abc")
    payload = json.loads(render_json(doc))
    assert payload["coverage"]["parse_success_rate"] == 1.0
    assert payload["coverage"]["files_parsed"] == 2
    assert payload["findings"] == []


def test_paths_are_posix_so_output_does_not_depend_on_the_host() -> None:
    """A backslash on Windows would make the same codebase produce different
    bytes on different machines, and the corpus harness compares across them.
    """
    payload = json.loads(render_json(_document()))
    assert payload["findings"][0]["location"]["file"] == "app/X.php"
    assert "\\" not in render_json(_document())


def test_two_scans_of_one_project_are_byte_identical(tmp_path: Path) -> None:
    """Invariant 8, end to end through the real CLI.

    Not a unit test of the serialiser: the whole point is that nothing
    anywhere in the pipeline - dict ordering, a set iteration, a temp path,
    a duration - reaches the bytes.
    """
    root = tmp_path / "project"
    shutil.copytree(FIXTURE, root, ignore=shutil.ignore_patterns(".vigilloo"))

    first = runner.invoke(app, ["scan", str(root), "--format", "json"])
    second = runner.invoke(app, ["scan", str(root), "--format", "json"])

    assert first.exit_code == 1
    assert second.exit_code == 1
    assert first.stdout == second.stdout
    assert json.loads(first.stdout)["findings"]


def test_stdout_is_only_json(tmp_path: Path) -> None:
    """A warning printed to stdout would make the output unparseable.

    The scan prints several coverage caveats; under --format json every one
    of them belongs on stderr. This is the guard that catches a future
    console.print added to the scan path without thinking about it.
    """
    root = tmp_path / "project"
    shutil.copytree(FIXTURE, root, ignore=shutil.ignore_patterns(".vigilloo"))

    result = runner.invoke(app, ["scan", str(root), "--format", "json"])

    json.loads(result.stdout)  # raises if anything else reached stdout
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
uv run pytest tests/test_report_json.py -v
```

Expected: FAIL, `ModuleNotFoundError: No module named 'vigilloo.report.json_report'`. The two
CLI tests fail on the unknown `--format` option; Task 8d wires that.

- [ ] **Step 3: Write the implementation**

Create `src/report/json_report.py`:

```python
"""The canonical, lossless serialisation. Everything else is derived from it.

This is the format Task 9's precision harness diffs, so invariant 8 is not an
aspiration here: two scans of unchanged code must produce the same bytes, on
any host. Three things make that true and each is easy to break by accident:

* `sort_keys=True`, so a dict built in a different order serialises the same.
* `Path.as_posix()`, so a Windows run does not emit backslashes.
* No timestamp and no duration anywhere in the body. `ReportMetadata` refuses
  to carry them; the terminal output and the store's scan row keep them.
"""

import json

from ..models import Coverage, Finding, PathStep, Span
from .document import ReportDocument

# Rates are derived floats. Two runs on one host agree exactly, but the corpus
# harness compares runs across hosts and CI images, so they are rounded to a
# fixed precision rather than trusted to repr identically. The counts either
# side of them are integers and are the exact values the rate came from, so
# nothing is lost by rounding the convenience value.
_RATE_PRECISION = 6


def _span(span: Span) -> dict[str, object]:
    return {
        "file": span.file.as_posix(),
        "start_line": span.start_line,
        "start_col": span.start_col,
        "end_line": span.end_line,
        "end_col": span.end_col,
    }


def _step(step: PathStep) -> dict[str, object]:
    return {
        "role": step.role,
        "location": _span(step.span),
        "snippet": step.snippet,
        "note": step.note,
        "rule_id": step.rule_id,
        "confidence": step.confidence,
    }


def _finding(finding: Finding) -> dict[str, object]:
    return {
        "id": finding.id,
        "fingerprint": finding.fingerprint,
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "title": finding.title,
        "cwe": list(finding.cwe),
        "location": _span(finding.span),
        "evidence_path": [_step(step) for step in finding.evidence_path],
        "alternative_paths": [
            [_step(step) for step in path] for path in finding.alternative_paths
        ],
        "remediation": finding.remediation,
        "needs_review": finding.needs_review,
    }


def _coverage(coverage: Coverage) -> dict[str, object]:
    """Counts and the rates derived from them.

    The rates are emitted alongside the counts rather than left to the
    consumer, because invariant 4 is about what a reader sees without effort. A
    consumer that has to divide two numbers to learn a scan was 60% blind is a
    consumer that will not.
    """
    return {
        "files_discovered": coverage.files_discovered,
        "files_unreadable": coverage.files_unreadable,
        "files_with_errors": coverage.files_with_errors,
        "files_parsed": coverage.files_parsed,
        "parse_success_rate": round(coverage.parse_success_rate, _RATE_PRECISION),
        "calls_resolved": coverage.calls_resolved,
        "calls_unresolved": coverage.calls_unresolved,
        "calls_attempted": coverage.calls_attempted,
        "call_resolution_rate": round(coverage.call_resolution_rate, _RATE_PRECISION),
        "parse_failures": [
            {"file": failure.file.as_posix(), "kind": failure.kind, "name": failure.name}
            for failure in coverage.parse_failures
        ],
    }


def render_json(document: ReportDocument) -> str:
    """Serialise one scan. Returns the text; printing is the caller's job.

    Returning a string rather than printing is what lets `--format json` write
    to stdout while every coverage caveat goes to stderr, and it keeps this
    module under the T20 lint rule that would otherwise not protect it.
    """
    payload = {
        "schema_version": document.metadata.schema_version,
        "tool": {
            "name": "vigilloo",
            "version": document.metadata.engine_version,
            "ruleset_hash": document.metadata.ruleset_hash,
        },
        "summary": {
            "total": len(document.findings),
            "by_severity": document.severity_counts,
        },
        "coverage": _coverage(document.coverage),
        "findings": [_finding(finding) for finding in document.findings],
    }
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
```

- [ ] **Step 4: Re-export from the package**

Replace the body of `src/report/__init__.py` with:

```python
"""Report rendering, one module per format.

Every format renders the same `ReportDocument`, built once from a scan's
findings and coverage. Two formats that each walked the `Finding` list
themselves would eventually disagree about what a scan found, and the one a
developer reads is not the one CI gates on.
"""

from .document import ReportDocument, ReportMetadata, build_document
from .json_report import render_json
from .terminal import render, render_coverage

__all__ = [
    "ReportDocument",
    "ReportMetadata",
    "build_document",
    "render",
    "render_coverage",
    "render_json",
]
```

- [ ] **Step 5: Run the unit tests to verify they pass**

```bash
uv run pytest tests/test_report_json.py -v -k "not scans and not stdout"
```

Expected: 3 passed. The two CLI tests still fail on the unknown `--format` option and are fixed
by Task 8d.

- [ ] **Step 6: Commit**

```bash
git add src/report/json_report.py src/report/__init__.py tests/test_report_json.py && git commit -m "feat: add the JSON report format

The canonical, lossless serialisation, and the output Phase 2 measures
precision by diffing. Determinism rests on three things that are each easy
to break by accident: sort_keys, Path.as_posix, and a body with no
timestamp or duration in it.

The two CLI-level tests in this file fail until the --format flag lands."
```

---

### Task 8d: Wire `--format` into the scan command

**Files:**
- Modify: `src/cli.py:44-52` (add the option), `src/cli.py:64-175` (route output by format)
- Test: `tests/test_cli_format.py`, and the two CLI tests from Task 8c now pass

**Interfaces:**
- Consumes: `render_json`, `build_document` from Tasks 8b and 8c.
- Produces: `vigilloo scan --format {terminal,json,markdown}`, default `terminal`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_cli_format.py`:

```python
"""The --format flag, and the stdout discipline the machine formats need."""

import json
import shutil
from pathlib import Path

from typer.testing import CliRunner

from vigilloo.cli import app

runner = CliRunner()
FIXTURE = Path("tests/fixtures/laravel-minimal")
UNPARSEABLE = Path("tests/fixtures/laravel-unparseable")


def _copy(fixture: Path, tmp_path: Path) -> Path:
    root = tmp_path / "project"
    shutil.copytree(fixture, root, ignore=shutil.ignore_patterns(".vigilloo"))
    return root


def test_default_format_is_still_the_terminal_report(tmp_path: Path) -> None:
    """The flag is additive. Nobody's existing invocation changes behaviour."""
    root = _copy(FIXTURE, tmp_path)
    result = runner.invoke(app, ["scan", str(root)])
    assert result.exit_code == 1
    assert "Coverage:" in result.stdout


def test_unknown_format_is_rejected_with_the_config_exit_code(tmp_path: Path) -> None:
    """docs/19-cli gives 2 to a usage error. A typo must not silently fall
    back to the terminal format and produce output a pipeline cannot parse.
    """
    root = _copy(FIXTURE, tmp_path)
    result = runner.invoke(app, ["scan", str(root), "--format", "yaml"])
    assert result.exit_code == 2


def test_coverage_warnings_go_to_stderr_under_json(tmp_path: Path) -> None:
    """The unparseable fixture prints a syntax-error caveat. Under --format
    json that caveat must not land in the middle of the document.
    """
    root = _copy(UNPARSEABLE, tmp_path)
    result = runner.invoke(app, ["scan", str(root), "--format", "json"], catch_exceptions=False)
    payload = json.loads(result.stdout)
    assert payload["coverage"]["files_with_errors"] >= 1


def test_json_exit_code_matches_the_terminal_run(tmp_path: Path) -> None:
    """Format changes presentation, never the verdict CI gates on."""
    root = _copy(FIXTURE, tmp_path)
    terminal = runner.invoke(app, ["scan", str(root)])
    as_json = runner.invoke(app, ["scan", str(root), "--format", "json"])
    assert terminal.exit_code == as_json.exit_code == 1
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
uv run pytest tests/test_cli_format.py -v
```

Expected: 3 of 4 fail with exit code 2 on the unrecognised `--format` option.
`test_default_format_is_still_the_terminal_report` passes already, which is the point of having
it: it pins the behaviour this task must not change.

- [ ] **Step 3: Add the format enum and the option**

In `src/cli.py`, add to the imports at the top:

```python
from enum import Enum
```

and change the report import from `from .report import render, render_coverage` to:

```python
from .report import build_document, render, render_coverage, render_json
```

Then add above the `scan` command:

```python
class OutputFormat(str, Enum):
    """The formats `scan` can emit.

    An Enum rather than a bare string so Typer rejects a typo with a usage
    error and lists the valid values. A misspelled --format that silently fell
    back to the terminal report would hand a pipeline output it cannot parse
    and no signal about why.
    """

    terminal = "terminal"
    json = "json"
    markdown = "markdown"
```

and add the parameter to `scan`, after `baseline`:

```python
    output_format: OutputFormat = typer.Option(
        OutputFormat.terminal,
        "--format",
        help="Report format.",
    ),
```

- [ ] **Step 4: Route the diagnostics away from stdout**

In `src/cli.py`, immediately after `console = Console()` at the top of `scan`, add:

```python
    # Under a machine format stdout carries the document and nothing else: a
    # coverage caveat landing mid-JSON makes it unparseable, and a pipeline
    # that cannot parse the report learns nothing from the warning either.
    # Rich writes to stderr when told to, so every existing console.print in
    # this function moves wholesale rather than growing a conditional each.
    machine = output_format is not OutputFormat.terminal
    console = Console(stderr=True) if machine else Console()
```

replacing the existing `console = Console()` line.

- [ ] **Step 5: Route the report itself by format**

In `src/cli.py`, replace these two lines:

```python
    render_coverage(coverage(project, stats), console)
    render(findings, console)
```

with:

```python
    scan_coverage = coverage(project, stats)
    if machine:
        # print() rather than console.print(): Rich would wrap the JSON at the
        # terminal width and interpret square brackets as markup, and a report
        # that changes shape with the width of the window is not a report a
        # pipeline can diff.
        document = build_document(
            findings, scan_coverage, engine_version=__version__, ruleset_hash=RULESET_HASH
        )
        if output_format is OutputFormat.json:
            print(render_json(document), end="")
        else:
            print(render_markdown(document), end="")
    else:
        render_coverage(scan_coverage, console)
        render(findings, console)
```

Note: `render_markdown` does not exist until Task 8e. Until then, replace the `else` branch above
with `raise typer.BadParameter("markdown format is not implemented yet")` and reinstate the real
call in Task 8e. Do not import `render_markdown` before it exists.

- [ ] **Step 6: Run the tests to verify they pass**

```bash
uv run pytest tests/test_cli_format.py tests/test_report_json.py -v
```

Expected: all pass, including the two CLI tests from Task 8c that were failing.

- [ ] **Step 7: Run the four gates**

```bash
uv run pytest && uv run ruff format --check . && uv run ruff check && uv run mypy
```

`src/cli.py` already carries the T20 ignore, so the bare `print` there passes lint. That ignore
is correct: `cli.py` is the process's one legitimate writer to stdout.

- [ ] **Step 8: Commit**

```bash
git add src/cli.py tests/test_cli_format.py && git commit -m "feat: add scan --format, with stdout reserved for the document

Under a machine format every diagnostic moves to stderr in one place, by
constructing the Console with stderr=True, rather than each console.print
growing a conditional. A coverage caveat landing mid-JSON makes the
document unparseable, and the pipeline that cannot parse it learns nothing
from the warning either.

The format is an Enum so a typo is a usage error rather than a silent
fallback to the terminal report."
```

---

### Task 8e: The Markdown renderer

Ships from the same serialisation layer, per the parent plan. Markdown is what a PR comment and a
ticket need, and it reads the same document the JSON does, so the two cannot disagree.

**Files:**
- Create: `src/report/markdown.py`
- Modify: `src/report/__init__.py`, `src/cli.py` (replace the Task 8d placeholder)
- Test: `tests/test_report_markdown.py`

**Interfaces:**
- Consumes: `ReportDocument` from Task 8b.
- Produces: `render_markdown(document: ReportDocument) -> str`, re-exported as
  `vigilloo.report.render_markdown`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_report_markdown.py`:

```python
"""Markdown renders the same document the JSON does."""

from pathlib import Path

from vigilloo.models import Coverage, Finding, PathStep, Span
from vigilloo.report.document import ReportDocument, build_document
from vigilloo.report.markdown import render_markdown


def _document(findings: list[Finding]) -> ReportDocument:
    coverage = Coverage(
        files_discovered=4,
        files_unreadable=0,
        files_with_errors=1,
        calls_resolved=3,
        calls_unresolved=1,
    )
    return build_document(findings, coverage, engine_version="0.1.0", ruleset_hash="abc")


def _finding() -> Finding:
    span = Span(file=Path("app/X.php"), start_line=4, start_col=2, end_line=4, end_col=20)
    return Finding(
        rule_id="laravel.raw-query",
        severity="critical",
        title="SQL injection in X",
        cwe=("CWE-89",),
        span=span,
        evidence_path=(
            PathStep(role="source", span=span, snippet="$r->input('q')", note="request"),
            PathStep(role="sink", span=span, snippet="whereRaw($q)"),
        ),
        remediation="Bind the parameter.",
    )


def test_coverage_precedes_the_findings() -> None:
    """docs/16-reporting puts coverage second in every format, ahead of the
    findings, so a clean result can never be read without the size of the
    blind spot beside it.
    """
    out = render_markdown(_document([_finding()]))
    assert out.index("## Coverage") < out.index("## Findings")


def test_every_evidence_step_is_numbered_in_order() -> None:
    """Invariant 2. The path is the product; a Markdown report that dropped
    it would be the line-number-and-severity output every other scanner
    already produces.
    """
    out = render_markdown(_document([_finding()]))
    assert "1. `app/X.php:4`" in out
    assert "2. `app/X.php:4`" in out
    assert "$r->input('q')" in out
    assert "whereRaw($q)" in out


def test_clean_scan_still_reports_coverage() -> None:
    """Invariant 4. No findings is not the same as nothing to say."""
    out = render_markdown(_document([]))
    assert "## Coverage" in out
    assert "No findings" in out
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
uv run pytest tests/test_report_markdown.py -v
```

Expected: FAIL, `ModuleNotFoundError: No module named 'vigilloo.report.markdown'`.

- [ ] **Step 3: Write the implementation**

Create `src/report/markdown.py`:

```python
"""Markdown for a PR comment, a ticket, or a human reading a file.

Renders the same `ReportDocument` the JSON does, so the report a reviewer
reads and the report CI gates on cannot describe different scans.

Deterministic for the same reason and by the same means: the document arrives
sorted, and nothing here consults a clock or the environment.
"""

from ..models import Finding
from .document import ReportDocument

_SEVERITY_MARK = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}


def _finding_section(finding: Finding) -> list[str]:
    mark = _SEVERITY_MARK.get(finding.severity, "⚪")
    review = " (Needs Review)" if finding.needs_review else ""
    lines = [
        f"### {mark} {finding.severity.title()} - {finding.title}{review}",
        "",
        f"`{finding.span.file.as_posix()}:{finding.span.start_line}` · "
        f"{' '.join(finding.cwe)} · `{finding.rule_id}`",
        "",
        "**Evidence path**",
        "",
    ]
    for number, step in enumerate(finding.evidence_path, start=1):
        note = f" - {step.note}" if step.note else ""
        lines.append(
            f"{number}. `{step.span.file.as_posix()}:{step.span.start_line}` - "
            f"{step.role}{note}"
        )
        lines.append("")
        lines.append("   ```php")
        lines.append(f"   {step.snippet}")
        lines.append("   ```")
        lines.append("")

    if finding.alternative_paths:
        count = len(finding.alternative_paths)
        plural = "s" if count != 1 else ""
        lines.append(f"*{count} alternative path{plural} reached this sink.*")
        lines.append("")

    if finding.remediation:
        lines.append(f"**Fix** - {finding.remediation}")
        lines.append("")
    return lines


def render_markdown(document: ReportDocument) -> str:
    """Serialise one scan as Markdown. Returns the text; printing is the
    caller's job, which is what keeps this module under the T20 lint rule.
    """
    coverage = document.coverage
    breakdown = ", ".join(f"{count} {sev}" for sev, count in document.severity_counts.items())
    lines = [
        "# Vigilloo scan",
        "",
        "## Summary",
        "",
        f"{len(document.findings)} finding(s)" + (f" ({breakdown})" if breakdown else ""),
        "",
        f"Engine `{document.metadata.engine_version}` · "
        f"ruleset `{document.metadata.ruleset_hash}`",
        "",
        "## Coverage",
        "",
        f"- {coverage.files_parsed}/{coverage.files_discovered} files parsed "
        f"({coverage.parse_success_rate:.1%})",
        f"- {coverage.calls_resolved}/{coverage.calls_attempted} call sites resolved "
        f"({coverage.call_resolution_rate:.1%})",
        "",
    ]
    if coverage.parse_failures:
        lines.append("Parse errors in:")
        lines.append("")
        lines += [f"- {failure.label}" for failure in coverage.parse_failures]
        lines.append("")

    lines.append("## Findings")
    lines.append("")
    if not document.findings:
        lines.append("No findings.")
        lines.append("")
    else:
        for finding in document.findings:
            lines += _finding_section(finding)

    return "\n".join(lines)
```

- [ ] **Step 4: Re-export and wire it into the CLI**

Add to `src/report/__init__.py`: import `render_markdown` from `.markdown` and add
`"render_markdown"` to `__all__`, keeping the list alphabetically sorted.

In `src/cli.py`, add `render_markdown` to the `from .report import ...` line and replace the
Task 8d placeholder `raise typer.BadParameter(...)` with:

```python
            print(render_markdown(document), end="")
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
uv run pytest tests/test_report_markdown.py -v
```

Expected: 3 passed.

- [ ] **Step 6: Run the four gates**

```bash
uv run pytest && uv run ruff format --check . && uv run ruff check && uv run mypy
```

- [ ] **Step 7: Update the roadmap in the same commit**

`docs/24-roadmap/README.md`, the "Markdown, JSON, terminal reports" row of the v0.1 table, is
currently `partial` with "Terminal report only, and it opens with the scan's own coverage...".
Change the status to `done` and rewrite the cell so it names all three formats, keeps the
existing sentence about coverage opening the report, and states that JSON is sorted and
byte-identical across runs. `CLAUDE.md` requires the roadmap table move in the same commit as the
capability.

- [ ] **Step 8: Commit**

```bash
git add src/report/markdown.py src/report/__init__.py src/cli.py tests/test_report_markdown.py docs/24-roadmap/README.md && git commit -m "feat: add the Markdown report format

Renders the same ReportDocument the JSON does, so the report a reviewer
reads in a PR and the report CI gates on cannot describe different scans.

Closes Task 8. The v0.1 roadmap row for report formats moves to done in
this commit, per the rule that a capability and its status entry land
together."
```

---

## Definition of done

- [ ] `vigilloo scan --format json` emits the schema above, with every finding's complete
      evidence path, `id` and `fingerprint`.
- [ ] Two scans of one unchanged project produce byte-identical stdout, asserted through the real
      CLI rather than the serialiser alone.
- [ ] Under a machine format, stdout parses as one document with nothing else in it.
- [ ] Coverage is a required key, present and correct on a clean scan.
- [ ] `vigilloo scan` with no `--format` behaves exactly as it does today.
- [ ] The wheel contains `vigilloo/report/`.
- [ ] Four gates green.
- [ ] The v0.1 roadmap row for report formats reads `done`.

## What this task deliberately does not do

**No SARIF.** It is Phase 3 Task 15. It is a serialisation of the same document and will be
cheap once this lands, but pulling it forward here widens a task that already blocks the whole
phase.

**No `--output` file flag.** Shell redirection covers it, and a path argument brings encoding and
overwrite questions that nothing in Phase 2 needs answered.

**No schema file.** `docs/16-reporting` promises a published, versioned schema for third-party
consumers. `SCHEMA_VERSION` is emitted from the first release so that promise stays keepable, but
writing the JSON Schema document belongs with the SDK publication in v1.0, not here.

**No Jinja2 templating, and this is a deliberate deviation from the spec.**
[16-reporting](../16-reporting/README.md) says "Markdown and HTML use Jinja2 templates
overridable per project". Task 8e builds the Markdown by string assembly instead. The reason is
sequencing, not disagreement: template overriding is only meaningful once reporters are plugins
([11-plugin-sdk](../11-plugin-sdk/README.md)), which is a v1.0 capability, and adding a runtime
templating dependency for one format before anything can override it buys nothing while
enlarging the offline install that invariant 6 governs. `render_markdown` is a pure function
over `ReportDocument`, so swapping its body for a template render when the SDK lands changes no
caller and no test.

**Recorded so it is not lost:** whoever implements the plugin SDK owns converting Markdown and
HTML to Jinja2, or amending `docs/16-reporting` if string assembly turns out to be the better
answer. Leaving the spec and the code disagreeing silently is the outcome this note exists to
prevent.
