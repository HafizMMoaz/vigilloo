from pathlib import Path

from vigilloo.models import Finding, PathStep, Span


def _span(line: int) -> Span:
    return Span(Path("a.php"), line, 0, line, 10)


def test_finding_requires_evidence_path() -> None:
    """A finding without a path is a bug, not a finding."""
    try:
        Finding(
            rule_id="php.sql-injection",
            severity="critical",
            title="SQL Injection",
            cwe=("CWE-89",),
            span=_span(42),
            evidence_path=(),
        )
    except ValueError as exc:
        assert "evidence path" in str(exc).lower()
    else:
        raise AssertionError("expected ValueError for empty evidence path")


def test_fingerprint_is_stable_across_line_moves() -> None:
    """Fingerprints must survive reformatting so baselines keep working."""
    steps_a = (
        PathStep("source", _span(10), "$r->input('s')", ""),
        PathStep("sink", _span(42), "orderByRaw", ""),
    )
    steps_b = (
        PathStep("source", _span(30), "$r->input('s')", ""),
        PathStep("sink", _span(62), "orderByRaw", ""),
    )
    a = Finding("php.sql-injection", "critical", "t", ("CWE-89",), _span(42), steps_a)
    b = Finding("php.sql-injection", "critical", "t", ("CWE-89",), _span(62), steps_b)
    assert a.fingerprint == b.fingerprint
    assert a.id != b.id


def test_fingerprint_distinguishes_findings_in_different_files() -> None:
    """The same pattern in two files is two findings, not one."""
    steps = (
        PathStep("source", _span(10), "$r->input('s')", ""),
        PathStep("sink", _span(42), "orderByRaw", ""),
    )
    a = Finding("php.sql-injection", "critical", "t", ("CWE-89",), _span(42), steps)
    b = Finding(
        "php.sql-injection", "critical", "t", ("CWE-89",), Span(Path("b.php"), 42, 0, 42, 10), steps
    )
    assert a.fingerprint != b.fingerprint


def test_id_distinguishes_evidence_steps_in_different_files() -> None:
    """Two routes to the same action from two route files are two findings.

    Same roles, same line numbers, same sink - only the entry step's file
    differs. An id that carried the role and line alone collided here, and the
    store's PRIMARY KEY (scan_id, id) silently dropped the second row.
    """
    sink = PathStep("gap", _span(20), "InvoiceController::show", "", "laravel.missing-authz")
    web = Finding(
        "laravel.missing-authz",
        "high",
        "t",
        ("CWE-862",),
        _span(20),
        (PathStep("entry", Span(Path("routes/web.php"), 7, 0, 7, 10), "Route::get(...)", ""), sink),
    )
    admin = Finding(
        "laravel.missing-authz",
        "high",
        "t",
        ("CWE-862",),
        _span(20),
        (
            PathStep("entry", Span(Path("routes/admin.php"), 7, 0, 7, 10), "Route::get(...)", ""),
            sink,
        ),
    )
    assert web.id != admin.id


def test_id_distinguishes_evidence_steps_with_different_snippets() -> None:
    """Two sinks on one line are two findings, and the id must say so."""
    source = PathStep("source", _span(10), "$r->input('s')", "")
    a = Finding(
        "php.sql-injection",
        "critical",
        "t",
        ("CWE-89",),
        _span(42),
        (source, PathStep("sink", _span(42), "DB::raw($s)", "")),
    )
    b = Finding(
        "php.sql-injection",
        "critical",
        "t",
        ("CWE-89",),
        _span(42),
        (source, PathStep("sink", _span(42), "orderByRaw($s)", "")),
    )
    assert a.id != b.id
