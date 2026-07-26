from pathlib import Path

import pytest

from vigilloo.workspace import Workspace


def project_dir(tmp_path: Path) -> Path:
    """A project root that is not the temporary directory itself."""
    root = tmp_path / "project"
    root.mkdir()
    return root


def test_open_creates_the_vigilloo_directory(tmp_path: Path) -> None:
    workspace = Workspace.open(tmp_path)
    assert workspace.root == tmp_path.resolve()
    assert workspace.dir == tmp_path.resolve() / ".vigilloo"
    assert workspace.dir.is_dir()


def test_reopen_is_idempotent_and_keeps_existing_contents(tmp_path: Path) -> None:
    """Reopening must not discard the store, the caches or the baseline."""
    first = Workspace.open(tmp_path)
    (first.dir / "vigilloo.db").write_text("existing")

    second = Workspace.open(tmp_path)

    assert second == first
    assert (second.dir / "vigilloo.db").read_text() == "existing"


def test_open_resolves_a_relative_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert Workspace.open(Path(".")).root == tmp_path.resolve()


def test_resolve_accepts_a_path_inside_the_project(tmp_path: Path) -> None:
    workspace = Workspace.open(tmp_path)
    assert workspace.resolve("app/Http/Controllers") == workspace.root / "app/Http/Controllers"
    assert workspace.resolve(".") == workspace.root


def test_resolve_refuses_a_traversing_relative_path(tmp_path: Path) -> None:
    workspace = Workspace.open(project_dir(tmp_path))
    with pytest.raises(ValueError, match="escapes the project root"):
        workspace.resolve("../../etc/passwd")


def test_resolve_refuses_an_absolute_path(tmp_path: Path) -> None:
    workspace = Workspace.open(tmp_path)
    with pytest.raises(ValueError, match="escapes the project root"):
        workspace.resolve("/etc/passwd")


def test_resolve_refuses_a_symlink_pointing_outside(tmp_path: Path) -> None:
    """A crafted autoload map cannot escape by pointing at a link inside the project."""
    outside = tmp_path / "outside"
    outside.mkdir()
    workspace = Workspace.open(project_dir(tmp_path))
    (workspace.root / "vendor").symlink_to(outside)

    with pytest.raises(ValueError, match="escapes the project root"):
        workspace.resolve("vendor")
