"""The corpus harness, and the harness's own failure modes.

A precision harness that is itself buggy fails in the most dangerous direction, because the
common bug is dropping findings on a join miss, which reports a BETTER number than reality.
So every way this is supposed to refuse gets its own case, exactly as tests/test_corpus.py
does for the fixture harness.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import corpus  # noqa: E402
from corpus import Pin, load_pins, scan_app  # noqa: E402


def test_load_pins_reads_name_repo_and_sha(tmp_path: Path) -> None:
    path = tmp_path / "pins.yml"
    path.write_text(
        yaml.safe_dump(
            {
                "applications": {
                    "laravel-skeleton": {
                        "repo": "https://example.invalid/laravel.git",
                        "pin": "abc123",
                        "wave": 1,
                        "pr_subset": True,
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    pins = load_pins(path)
    assert pins["laravel-skeleton"] == Pin(
        name="laravel-skeleton",
        repo="https://example.invalid/laravel.git",
        pin="abc123",
        wave=1,
        pr_subset=True,
    )


def test_load_pins_rejects_a_missing_sha(tmp_path: Path) -> None:
    """An unpinned application is not reproducible, so it is a hard error, not a default."""
    path = tmp_path / "pins.yml"
    path.write_text(
        yaml.safe_dump({"applications": {"koel": {"repo": "https://example.invalid/koel.git"}}}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="koel"):
        load_pins(path)


def test_load_pins_on_an_empty_document_returns_no_applications(tmp_path: Path) -> None:
    """An empty corpus must read as empty, not crash: wave 1 starts with one application."""
    path = tmp_path / "pins.yml"
    path.write_text("applications: {}\n", encoding="utf-8")
    assert load_pins(path) == {}


def test_a_collapsed_parse_rate_is_refused() -> None:
    """Invariant 4. Unparsed files produce no findings, so they inflate precision twice
    over: no true positives lost that anyone notices, and no false positives either."""
    from corpus import check_coverage

    with pytest.raises(RuntimeError, match="below the"):
        check_coverage("monica", {"coverage": {"parse_success_rate": 0.62}})


def test_a_healthy_parse_rate_is_accepted() -> None:
    """The floor must be a real threshold, not a constant that rejects everything."""
    from corpus import check_coverage

    check_coverage("monica", {"coverage": {"parse_success_rate": 0.999}})


# --- scan_app's failure paths -----------------------------------------------------------
#
# scan_app is the one function enforcing "a failed scan must never be counted as a clean
# one", so each way it is supposed to refuse gets a case here, and each case asserts on
# both halves: that it raised, AND that no report file was written. Asserting only the
# raise would still pass an implementation that writes the file before raising - the exact
# bug this guards against.


def test_scan_app_on_a_timeout_raises_and_writes_no_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd="vigilloo", timeout=1)

    monkeypatch.setattr(corpus.subprocess, "run", fake_run)
    root = tmp_path / "app"
    root.mkdir()
    out = tmp_path / "report.json"

    with pytest.raises(RuntimeError, match="exceeded"):
        scan_app("demo", root, out, timeout_s=1)
    assert not out.exists()


def test_scan_app_on_a_nonzero_exit_raises_and_writes_no_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=["vigilloo"], returncode=1, stdout="", stderr="boom"
        )

    monkeypatch.setattr(corpus.subprocess, "run", fake_run)
    root = tmp_path / "app"
    root.mkdir()
    out = tmp_path / "report.json"

    with pytest.raises(RuntimeError, match="exited 1"):
        scan_app("demo", root, out)
    assert not out.exists()


def test_scan_app_on_malformed_json_raises_and_writes_no_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=["vigilloo"], returncode=0, stdout="{not json", stderr=""
        )

    monkeypatch.setattr(corpus.subprocess, "run", fake_run)
    root = tmp_path / "app"
    root.mkdir()
    out = tmp_path / "report.json"

    with pytest.raises(RuntimeError, match="demo: scan produced unparseable JSON:"):
        scan_app("demo", root, out)
    assert not out.exists()


def test_scan_app_on_missing_keys_raises_and_writes_no_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        stdout = json.dumps({"findings": []})  # no "coverage" key
        return subprocess.CompletedProcess(
            args=["vigilloo"], returncode=0, stdout=stdout, stderr=""
        )

    monkeypatch.setattr(corpus.subprocess, "run", fake_run)
    root = tmp_path / "app"
    root.mkdir()
    out = tmp_path / "report.json"

    with pytest.raises(RuntimeError, match="missing required keys"):
        scan_app("demo", root, out)
    assert not out.exists()


def test_scan_app_on_a_sub_floor_parse_rate_raises_and_writes_no_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    document = {"findings": [], "coverage": {"parse_success_rate": 0.5}}

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=["vigilloo"], returncode=0, stdout=json.dumps(document), stderr=""
        )

    monkeypatch.setattr(corpus.subprocess, "run", fake_run)
    root = tmp_path / "app"
    root.mkdir()
    out = tmp_path / "report.json"

    with pytest.raises(RuntimeError, match="below the"):
        scan_app("demo", root, out)
    assert not out.exists()


def test_scan_app_on_success_writes_a_report_that_round_trips(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    document = {"findings": [], "coverage": {"parse_success_rate": 1.0}}
    stdout = json.dumps(document)

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=["vigilloo"], returncode=0, stdout=stdout, stderr=""
        )

    monkeypatch.setattr(corpus.subprocess, "run", fake_run)
    root = tmp_path / "app"
    root.mkdir()
    out = tmp_path / "reports" / "demo.json"

    result = scan_app("demo", root, out)

    assert result == out
    assert json.loads(out.read_text(encoding="utf-8")) == document


def test_scan_app_removes_the_vigilloo_workspace_even_when_the_scan_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`vigilloo scan` unconditionally creates `<root>/.vigilloo`, and root is a corpus
    submodule checkout, so a failed scan must not leave that submodule's working tree
    dirty. Cleanup on the failure path is the one most likely to be missed, since the
    happy path exercises it far more often in practice."""
    root = tmp_path / "app"
    root.mkdir()
    workspace = root / ".vigilloo"

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        # Simulate the workspace `vigilloo scan` would have created before failing.
        workspace.mkdir()
        (workspace / "vigilloo.db").write_text("x", encoding="utf-8")
        return subprocess.CompletedProcess(
            args=["vigilloo"], returncode=1, stdout="", stderr="boom"
        )

    monkeypatch.setattr(corpus.subprocess, "run", fake_run)
    out = tmp_path / "report.json"

    with pytest.raises(RuntimeError):
        scan_app("demo", root, out)

    assert not workspace.exists()
    assert not out.exists()


def test_triage_round_trips_and_sorts_by_fingerprint(tmp_path: Path) -> None:
    """Invariant 8: the file must be byte-identical given the same entries in any order."""
    from corpus import TriageEntry, load_triage, save_triage

    path = tmp_path / "monica.yml"
    entries = {
        "ffff000000000001": TriageEntry(
            "false", "laravel.no-throttle", "Public API.", "routes/api.php:9"
        ),
        "0000000000000002": TriageEntry("true", "php.sql-injection", "Unbound.", "app/X.php:44"),
    }
    save_triage(path, pin="abc123", ruleset="b35162f4d187c91c", entries=entries)
    first = path.read_text(encoding="utf-8")

    save_triage(
        path,
        pin="abc123",
        ruleset="b35162f4d187c91c",
        entries=dict(reversed(list(entries.items()))),
    )
    assert path.read_text(encoding="utf-8") == first
    assert first.index("0000000000000002") < first.index("ffff000000000001")

    assert load_triage(path) == entries


def test_load_triage_rejects_an_unknown_verdict(tmp_path: Path) -> None:
    """A typo in a hand-edited verdict must not silently drop out of the precision count."""
    from corpus import load_triage

    path = tmp_path / "monica.yml"
    path.write_text(
        yaml.safe_dump(
            {
                "pin": "abc123",
                "reviewed_ruleset": "b35162f4d187c91c",
                "findings": {"aaaa000000000001": {"verdict": "yes", "rule": "php.sql-injection"}},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="yes"):
        load_triage(path)


def test_load_triage_on_a_missing_file_is_empty(tmp_path: Path) -> None:
    """A newly enrolled application has no verdicts yet; that is not an error."""
    from corpus import load_triage

    assert load_triage(tmp_path / "absent.yml") == {}


def _finding(fingerprint: str, rule: str) -> dict[str, object]:
    return {"fingerprint": fingerprint, "rule_id": rule}


def test_precision_is_none_when_nothing_is_reviewed() -> None:
    """Undefined, not 0% and not 100%. Both would be wrong in opposite directions."""
    from corpus import compute_precision

    rows = compute_precision([_finding("aaa", "php.sql-injection")], {})
    assert rows[0].precision is None
    assert rows[0].unreviewed_count == 1


def test_precision_counts_only_reviewed_verdicts() -> None:
    from corpus import TriageEntry, compute_precision

    findings = [_finding("a", "r"), _finding("b", "r"), _finding("c", "r"), _finding("d", "r")]
    triage = {
        "a": TriageEntry("true", "r"),
        "b": TriageEntry("true", "r"),
        "c": TriageEntry("false", "r"),
    }
    row = compute_precision(findings, triage)[0]
    assert (row.true_count, row.false_count, row.unreviewed_count) == (2, 1, 1)
    assert row.precision == pytest.approx(2 / 3)


def test_quota_is_per_rule_so_a_noisy_rule_cannot_crowd_others_out() -> None:
    """The failure a flat cap produces: one rule eats the budget, 31 rules go unmeasured.

    laravel.raw-query alone is 28 of 65 findings on tests/fixtures/laravel-minimal, so this
    is the real distribution, not a hypothetical one.
    """
    from corpus import select_for_review

    findings = [_finding(f"n{i:03d}", "laravel.raw-query") for i in range(50)]
    findings.append(_finding("z999", "php.sql-injection"))
    selected = select_for_review(findings, quota=2)
    assert "z999" in selected
    assert len([f for f in selected if f.startswith("n")]) == 2


def test_quota_selection_is_stable_across_runs() -> None:
    """Churn in the reviewed set would silently invalidate prior verdicts."""
    from corpus import select_for_review

    findings = [_finding("ccc", "r"), _finding("aaa", "r"), _finding("bbb", "r")]
    assert select_for_review(findings, quota=2) == select_for_review(
        list(reversed(findings)), quota=2
    )
    assert select_for_review(findings, quota=2) == ["aaa", "bbb"]


def test_seeding_preserves_an_existing_human_verdict() -> None:
    from corpus import TriageEntry, seed_entries

    findings: list[dict[str, object]] = [
        {
            "fingerprint": "abc",
            "rule_id": "r",
            "location": {"file": "app/Test.php", "start_line": 10},
        }
    ]
    existing = {
        "abc": TriageEntry(
            verdict="false", rule="r", note="human said no", seen_at="app/Test.php:10"
        )
    }

    seeded = seed_entries(findings, existing, quota=2)
    assert "abc" in seeded
    entry = seeded["abc"]
    assert entry.verdict == "false"
    assert entry.note == "human said no"


def test_seeding_adds_new_findings_as_unreviewed() -> None:
    from corpus import TriageEntry, seed_entries

    findings: list[dict[str, object]] = [
        {
            "fingerprint": "xyz",
            "rule_id": "r2",
            "location": {"file": "app/New.php", "start_line": 42},
        }
    ]
    existing: dict[str, TriageEntry] = {}

    seeded = seed_entries(findings, existing, quota=2)
    assert "xyz" in seeded
    entry = seeded["xyz"]
    assert entry.verdict == "unreviewed"
    assert entry.rule == "r2"
    assert entry.seen_at == "app/New.php:42"


def test_scan_continues_after_one_application_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    from corpus import Pin, main

    pins = {
        "app1": Pin(name="app1", repo="repo", pin="1", wave=1, pr_subset=False),
        "app2": Pin(name="app2", repo="repo", pin="2", wave=1, pr_subset=False),
    }
    monkeypatch.setattr(corpus, "load_pins", lambda *a, **kw: pins)

    scanned = []

    def fake_scan_app(name: str, *args: object, **kwargs: object) -> Path:
        scanned.append(name)
        if name == "app1":
            raise RuntimeError("fake timeout")
        return corpus.REPORTS / f"{name}.json"

    monkeypatch.setattr(corpus, "scan_app", fake_scan_app)

    exit_code = main(["scan"])
    assert exit_code != 0
    assert scanned == ["app1", "app2"]


def test_scan_names_the_failed_application_in_its_output(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from corpus import Pin, main

    pins = {
        "app1": Pin(name="app1", repo="repo", pin="1", wave=1, pr_subset=False),
    }
    monkeypatch.setattr(corpus, "load_pins", lambda *a, **kw: pins)

    def fake_scan_app(name: str, *args: object, **kwargs: object) -> Path:
        raise RuntimeError("fake timeout")

    monkeypatch.setattr(corpus, "scan_app", fake_scan_app)

    main(["scan"])
    stdout = capsys.readouterr().out
    assert "app1: scan failed" in stdout
    assert "fake timeout" in stdout


def test_report_marks_a_missing_report_and_returns_non_zero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from corpus import Pin, main

    pins = {
        "app1": Pin(name="app1", repo="repo", pin="1", wave=1, pr_subset=False),
    }
    monkeypatch.setattr(corpus, "load_pins", lambda *a, **kw: pins)

    exit_code = main(["report"])
    stdout = capsys.readouterr().out

    assert exit_code != 0
    assert "app1: NO REPORT - scan failed or was never run" in stdout


def test_scan_continues_when_one_application_produces_unparseable_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    import json
    import subprocess

    from corpus import Pin, main

    pins = {
        "app1": Pin(name="app1", repo="repo", pin="1", wave=1, pr_subset=False),
        "app2": Pin(name="app2", repo="repo", pin="2", wave=1, pr_subset=False),
    }
    monkeypatch.setattr(corpus, "load_pins", lambda *a, **kw: pins)

    # Use a temp dir so scan_app can create and remove paths safely
    monkeypatch.setattr(corpus, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(corpus, "CORPUS", tmp_path / "corpus")
    monkeypatch.setattr(corpus, "REPORTS", tmp_path / "reports")

    scanned = []

    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        cmd = args[0]
        assert isinstance(cmd, list)
        # cmd looks like ["uv", "run", "vigilloo", "scan", "...", "--format", "json"]
        app_name = Path(str(cmd[4])).name
        scanned.append(app_name)

        if app_name == "app1":
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="{not json", stderr=""
            )
        else:
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=0,
                stdout=json.dumps({"findings": [], "coverage": {"parse_success_rate": 1.0}}),
                stderr="",
            )

    monkeypatch.setattr(corpus.subprocess, "run", fake_run)

    exit_code = main(["scan"])
    stdout = capsys.readouterr().out

    assert scanned == ["app1", "app2"]
    assert exit_code != 0
    assert "app1" in stdout
