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

    with pytest.raises(json.JSONDecodeError):
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
