"""What the project declares about itself in `composer.json`, read before anything is parsed.

The Detect stage of the pipeline in docs/02-architecture, and step 1 of docs/03-parser
section Discovery: `autoload.psr-4` maps a namespace prefix onto a directory, which is how
`App\\Http\\Controllers\\OrderController` becomes a file path without guessing. Without that
map a class named by its fully qualified name and no `use` statement cannot be told apart
from a class relative to the current namespace, and the symbol layer resolves it to a name
that matches nothing.

ponytail: this is Composer, not Laravel, so its home in the target layout of
docs/23-dev-guide is `plugins/php/`. It lives under `laravel/` because that is the only
framework-adjacent package that exists in this slice; move it when `plugins/php/` appears.

## The threat, and what "rejected" means here

`composer.json` belongs to the analysed project, and invariant 5 makes the analysed project
untrusted input. docs/23-dev-guide section "Security of Vigilloo itself" states the
consequence outright: a crafted autoload map must not make Vigilloo read or write outside
the project root. `{"Evil\\": "../../../../etc/"}` is the whole attack, and it costs the
attacker one line in a file they already control.

Every directory therefore goes through `Workspace.resolve`, which is the one containment
guard in this codebase. It resolves against the root and follows symlinks *before* testing
containment, so a link inside the project pointing out of it is refused too. There is
deliberately no second check here: a second implementation of the same rule is a second
thing to get wrong, and this one is already tested.

**Rejection skips one mapping and keeps the rest.** Refusing the whole file would let one
malformed vendor entry stop a scan, and a scan that does not run finds nothing at all. But
a skipped prefix is a whole namespace the scan can no longer resolve, so under invariant 4
it may not be silent: every skip is recorded in `Autoload.rejected` as a printable line,
and `vigilloo scan` prints them with the other coverage caveats, before any finding.

Nothing in here raises. A project with no `composer.json` is ordinary rather than
exceptional, and a malformed one degrades resolution instead of ending the scan - the same
bargain docs/03-parser section "Error handling" strikes for a file that will not parse.
"""

import json
from dataclasses import dataclass
from pathlib import Path

from ..workspace import Workspace

COMPOSER_FILE = "composer.json"


@dataclass(frozen=True)
class Autoload:
    """The PSR-4 namespace roots this scan is willing to use, and the ones it refused.

    `roots` pairs each accepted prefix - always ending in a single backslash, so that
    `App\\` cannot match `Application\\Foo` - with the directory it maps to, already
    resolved and already proven to be inside the project root.

    `rejected` holds one printable line per skipped mapping. It is prose rather than a
    structure because its only consumer is the reader of the report: what they need is
    which namespace stopped resolving and why, and any structure would be invented for a
    caller that does not exist.
    """

    roots: tuple[tuple[str, Path], ...] = ()
    rejected: tuple[str, ...] = ()

    @property
    def prefixes(self) -> frozenset[str]:
        """The accepted namespace prefixes, for name resolution in `vigilloo.symbols`.

        Only the prefixes cross into the parser layer. The parser has no framework
        awareness and no filesystem business (docs/23-dev-guide, and the layering rule in
        CLAUDE.md), so it gets the set of names Composer promises to autoload and nothing
        else - not the directories, and not this module.
        """
        return frozenset(prefix for prefix, _ in self.roots)


def read_autoload(workspace: Workspace) -> Autoload:
    """Read `autoload.psr-4` and `autoload-dev.psr-4` from the project's `composer.json`.

    Both sections are read because both describe first-party code: `autoload-dev` is where
    a Laravel application's `Tests\\` namespace lives, and test code holds real routes and
    real sinks often enough that ignoring it would be a silent blind spot.

    An absent, unreadable, malformed or non-object `composer.json` yields an empty result.
    Every failure mode of an untrusted file is therefore the same failure mode as not
    having one, which is the only reading that cannot be turned into a crash by editing a
    file in the scanned project.
    """
    composer = _read_composer(workspace)
    if composer is None:
        return Autoload(rejected=(f"{COMPOSER_FILE} (outside the project root)",))

    roots: list[tuple[str, Path]] = []
    rejected: list[str] = []

    for section in ("autoload", "autoload-dev"):
        block = composer.get(section)
        if not isinstance(block, dict):
            continue
        psr4 = block.get("psr-4")
        if not isinstance(psr4, dict):
            continue

        for raw_prefix, value in psr4.items():
            if not isinstance(raw_prefix, str):
                continue
            # Composer allows one directory or a list of them for a single prefix.
            directories = value if isinstance(value, list) else [value]
            for directory in directories:
                if not isinstance(directory, str):
                    rejected.append(f"{raw_prefix} -> (not a string)")
                    continue
                root = _accept(workspace, raw_prefix, directory, rejected)
                if root is not None:
                    roots.append(root)

    # Sorted so the accepted roots and the printed caveats do not inherit the key order of
    # a file in the scanned project (invariant 8).
    return Autoload(roots=tuple(sorted(roots)), rejected=tuple(sorted(rejected)))


def _accept(
    workspace: Workspace, raw_prefix: str, directory: str, rejected: list[str]
) -> tuple[str, Path] | None:
    """One `prefix -> directory` mapping, or None with a line appended to `rejected`."""
    prefix = _normalise(raw_prefix)
    if not prefix:
        # PSR-4's fallback form, `{"": "src/"}`. Legal Composer, but a prefix matching
        # every name would make the resolver below treat every written class name as
        # already fully qualified, which is not a rule about this project so much as the
        # absence of one. Skipped rather than half-supported, and skipped visibly.
        rejected.append(f'"" -> {directory} (an empty PSR-4 prefix matches every class name)')
        return None

    try:
        resolved = workspace.resolve(directory)
    except ValueError:
        rejected.append(f"{prefix} -> {directory} (outside the project root)")
        return None

    return prefix, resolved


def _normalise(prefix: str) -> str:
    """A PSR-4 prefix as `App\\`, whatever spelling `composer.json` used.

    The trailing separator is not cosmetic: prefix matching is done with `startswith`, and
    a prefix of `App` without it would claim `Application\\Kernel` for a mapping that
    covers no such thing. Composer requires the separator and errors without it; Vigilloo
    reads files Composer may never have validated, so it is added rather than assumed.
    """
    prefix = prefix.strip().lstrip("\\")
    if not prefix:
        return ""
    return prefix if prefix.endswith("\\") else prefix + "\\"


def _read_composer(workspace: Workspace) -> dict[str, object] | None:
    """The parsed `composer.json`, `{}` when there is nothing usable, None when refused.

    None is reserved for the one case worth reporting: `composer.json` itself resolving
    outside the root, which only happens if it is a symlink pointing out of the project.
    Everything else - absent, unreadable, invalid JSON, a JSON array instead of an object -
    is a project that says nothing about its autoloading, and says it uneventfully.
    """
    try:
        path = workspace.resolve(COMPOSER_FILE)
    except ValueError:
        return None

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {}

    return data if isinstance(data, dict) else {}
