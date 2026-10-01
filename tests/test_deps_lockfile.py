"""Tests for composer.lock parser."""

import json
from pathlib import Path

import pytest

from vigilloo.deps.lockfile import parse_lockfile


def test_parse_lockfile_success(tmp_path: Path) -> None:
    data = {
        "_readme": ["readme"],
        "packages": [
            {
                "name": "guzzlehttp/guzzle",
                "version": "v7.4.4",
                "license": ["MIT"],
                "description": "Guzzle is a PHP HTTP client library",
                "autoload": {"psr-4": {"GuzzleHttp\\": "src/"}},
            }
        ],
        "packages-dev": [
            {
                "name": "phpunit/phpunit",
                "version": "9.5.10",
                "license": ["BSD-3-Clause"],
                "description": "The PHP Unit Testing framework.",
                "autoload": {"psr-4": {"PHPUnit\\": "src/"}},
            }
        ],
    }

    lock = tmp_path / "composer.lock"
    lock.write_text(json.dumps(data), encoding="utf-8")

    packages = parse_lockfile(lock)
    assert len(packages) == 2

    guzzle = next(p for p in packages if p.name == "guzzlehttp/guzzle")
    assert guzzle.version == "7.4.4"
    assert guzzle.raw_version == "v7.4.4"
    assert guzzle.is_dev is False
    assert guzzle.license == "MIT"
    assert "GuzzleHttp" in guzzle.namespaces

    phpunit = next(p for p in packages if p.name == "phpunit/phpunit")
    assert phpunit.version == "9.5.10"
    assert phpunit.is_dev is True
    assert "PHPUnit" in phpunit.namespaces


def test_parse_lockfile_missing_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        parse_lockfile(tmp_path / "composer.lock")
