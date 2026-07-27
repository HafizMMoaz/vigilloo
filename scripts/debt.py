"""Print the deliberate-shortcut ledger.

Every shortcut in this codebase is annotated with a `ponytail:` comment naming its ceiling
and its upgrade path, at the site of the shortcut. This script collects them. The ledger is
therefore generated from the code and cannot go stale the way a hand-maintained debt file
does, which is why `docs/plans/2026-07-26-engineering-workflow-and-backlog.md` section 4
forbids writing one.

The report goes to stdout, one marker per line, sorted by path then line. The exit status is
always 0: this reports debt, it does not gate on it.

Usage: uv run python scripts/debt.py [path ...]     (defaults to src/)
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

MARKER = "ponytail:"
DEFAULT_ROOTS = ("src",)


def markers(root: Path) -> Iterator[tuple[Path, int, str]]:
    """Yield (path, line number, comment text) for every marker under `root`.

    A missing root yields nothing rather than raising - the caller may be pointing at a
    subpackage that does not exist yet, and that is not a debt report failure.
    """
    sources = [root] if root.is_file() else sorted(root.rglob("*.py"))
    for path in sources:
        lines = path.read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines, start=1):
            if MARKER in line:
                yield path, number, line.strip().lstrip("#").strip()


def main(argv: list[str]) -> None:
    roots = [Path(argument) for argument in (argv or list(DEFAULT_ROOTS))]
    found = sorted(marker for root in roots for marker in markers(root))
    for path, number, text in found:
        print(f"{path}:{number}  {text}")
    # The count goes to stderr so stdout stays exactly the ledger and nothing else.
    print(
        f"{len(found)} deliberate shortcut(s) recorded in {', '.join(str(r) for r in roots)}.",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main(sys.argv[1:])
