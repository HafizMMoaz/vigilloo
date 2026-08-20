"""The corpus harness, and the harness's own failure modes.

A precision harness that is itself buggy fails in the most dangerous direction, because the
common bug is dropping findings on a join miss, which reports a BETTER number than reality.
So every way this is supposed to refuse gets its own case, exactly as tests/test_corpus.py
does for the fixture harness.
"""

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from corpus import Pin, load_pins  # noqa: E402


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
