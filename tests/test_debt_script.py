import subprocess
import sys
from pathlib import Path

SCRIPT = Path("scripts/debt.py")
MARKER = "ponytail:"


def run_debt(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *arguments],
        capture_output=True,
        text=True,
        check=False,
    )


def test_a_marker_is_reported_with_its_location(tmp_path: Path) -> None:
    module = tmp_path / "shortcut.py"
    module.write_text(
        "value = 1\n"
        "# ponytail: one root only. Ceiling: multi-root projects, which need the\n"
        "# composer.json autoload map instead.\n",
        encoding="utf-8",
    )

    result = run_debt(str(tmp_path))

    assert result.returncode == 0
    assert f"{module}:2  ponytail: one root only." in result.stdout


def test_a_tree_with_no_markers_is_not_a_failure(tmp_path: Path) -> None:
    (tmp_path / "clean.py").write_text("value = 1\n", encoding="utf-8")

    result = run_debt(str(tmp_path))

    assert result.returncode == 0
    assert result.stdout == ""


def test_every_marker_in_the_package_is_listed() -> None:
    """The ledger is complete, counted independently of the script that prints it.

    No expected number is written down here on purpose. A hardcoded count would make
    adding a shortcut fail an unrelated test, and the ledger's whole point is that it
    tracks the code rather than a file someone has to remember to edit.
    """
    expected = [
        f"{path}:{number}"
        for path in sorted(Path("src").rglob("*.py"))
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)
        if MARKER in line
    ]

    result = run_debt()

    assert result.returncode == 0
    reported = [line.split("  ", 1)[0] for line in result.stdout.splitlines()]
    assert reported == expected
