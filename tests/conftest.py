import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

FIXTURE = Path("tests/fixtures/laravel-minimal")

# Rich decides whether to emit ANSI codes from the environment, and several of these variables
# are set by terminals and by tool harnesses without the developer ever choosing them. The CLI
# tests assert on the text a user reads, so a shell exporting FORCE_COLOR turns five unrelated
# tests red and sends whoever hit it looking for a bug in their own change. Neutralised for the
# whole session rather than per test: any test that invokes the CLI is affected, and remembering
# to opt in is exactly the kind of thing that gets forgotten.
_COLOUR_VARS = ("FORCE_COLOR", "CLICOLOR_FORCE", "COLORTERM")


@pytest.fixture(scope="session", autouse=True)
def _plain_output() -> Iterator[None]:
    monkeypatch = pytest.MonkeyPatch()
    for name in _COLOUR_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("TERM", "dumb")
    yield
    monkeypatch.undo()


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
