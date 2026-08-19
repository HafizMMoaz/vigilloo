"""The workspace: a project root and the `.vigilloo/` directory beside it.

Everything below the CLI reaches the filesystem through a Workspace rather than a bare
`Path`, so the "is this still inside the project?" question is answered in one place.
docs/23-dev-guide section Security makes that question load-bearing: a crafted
`composer.json` autoload map must not make Vigilloo read outside the project root.
"""

from dataclasses import dataclass, field
from pathlib import Path

from ..config import VigillooConfig

# The store, the caches and the run manifest live here (docs/17-database). It belongs in
# .gitignore, unlike vigilloo.yml and the baseline, which are committed.
DIR_NAME = ".vigilloo"


@dataclass(frozen=True)
class Workspace:
    """A resolved project root and its `.vigilloo/` directory."""

    root: Path
    dir: Path
    config: VigillooConfig = field(default_factory=VigillooConfig)

    @classmethod
    def at(cls, root: Path) -> "Workspace":
        """A workspace over `root` that touches nothing on disk.

        The containment guard below is needed by read-only stages long before anything
        wants to write: `load_project` reads `composer.json` and its autoload map, and a
        scan that only reads must not leave a `.vigilloo/` directory behind in every tree
        it is pointed at. `open` is this plus the directory, so there is still one place
        that decides what a root resolves to.
        """
        # ponytail: no config yet. vigilloo.yml resolution (CLI > env > project > user >
        # defaults, docs/19-cli section Configuration) lands in src/workspace/config.py
        # and becomes another frozen field here.
        resolved = root.resolve()
        config = VigillooConfig.load(resolved)
        return cls(root=resolved, dir=resolved / DIR_NAME, config=config)

    @classmethod
    def open(cls, root: Path) -> "Workspace":
        """Resolve `root` and create its `.vigilloo/` directory if it is absent.

        Reopening an existing workspace keeps whatever is already in the directory:
        the database is a rebuildable cache, but the findings history and the baseline
        inside it are not.
        """
        workspace = cls.at(root)
        workspace.dir.mkdir(exist_ok=True)
        return workspace

    def resolve(self, path: Path | str) -> Path:
        """Resolve a project-relative path, refusing anything outside the root.

        Symlinks are followed before the check, so a link that lives inside the project
        but points out of it is refused too.
        """
        candidate = (self.root / path).resolve()
        if not candidate.is_relative_to(self.root):
            raise ValueError(f"path escapes the project root: {path}")
        return candidate
