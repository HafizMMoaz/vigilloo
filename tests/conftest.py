import shutil
from pathlib import Path

import pytest

FIXTURE = Path("tests/fixtures/laravel-minimal")


@pytest.fixture(scope="session")
def fixture_project(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A throwaway copy of the Laravel fixture, for tests that run the CLI over it.

    `vigilloo scan` writes a scan row into `.vigilloo/vigilloo.db` under whatever root it
    is given, so pointing it at `tests/fixtures/` makes the suite mutate a tracked tree and
    accumulate a row per test per run. Tests that only call `load_project` do not need this
    and keep using the fixture in place.
    """
    root = tmp_path_factory.mktemp("laravel-minimal")
    shutil.copytree(FIXTURE, root, dirs_exist_ok=True, ignore=shutil.ignore_patterns(".vigilloo"))
    return root
