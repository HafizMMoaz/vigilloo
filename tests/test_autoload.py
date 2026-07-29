"""PSR-4 autoload resolution, and the refusal of an autoload map that points out of the tree.

The traversal half is the half that matters. `composer.json` belongs to the analysed
project, invariant 5 makes the analysed project untrusted input, and docs/23-dev-guide
section Security says in as many words that a crafted autoload map must not make Vigilloo
read outside the project root. A path-traversal hole in a security scanner is not ironic,
it is disqualifying, so every shape of escape gets its own test.
"""

import json
from pathlib import Path

from typer.testing import CliRunner

from vigilloo.cli import app
from vigilloo.graph import load_project
from vigilloo.laravel.detect import Autoload, read_autoload
from vigilloo.symbols import resolve_type_name
from vigilloo.workspace import Workspace

runner = CliRunner()

# A controller that names a class by its fully qualified name with no `use` above it.
# Without the autoload map, `App\Repositories\OrderRepository` written inside
# `namespace App\Http\Controllers` is namespace-relative and resolves to
# `App\Http\Controllers\App\Repositories\OrderRepository`, which matches nothing.
_CONTROLLER = (
    "<?php\n"
    "namespace App\\Http\\Controllers;\n"
    "class OrderController\n"
    "{\n"
    "    public function __construct(private App\\Repositories\\OrderRepository $orders)\n"
    "    {\n"
    "    }\n"
    "}\n"
)

_REPOSITORY = "<?php\nnamespace App\\Repositories;\nclass OrderRepository\n{\n}\n"

_CONTROLLER_FQN = "App\\Http\\Controllers\\OrderController"


def project(tmp_path: Path, composer: object | None = None) -> Path:
    """A minimal PSR-4 project rooted below `tmp_path`, so `..` has somewhere to go."""
    root = tmp_path / "project"
    (root / "app" / "Http" / "Controllers").mkdir(parents=True)
    (root / "app" / "Repositories").mkdir(parents=True)
    (root / "app" / "Http" / "Controllers" / "OrderController.php").write_text(_CONTROLLER)
    (root / "app" / "Repositories" / "OrderRepository.php").write_text(_REPOSITORY)
    if composer is not None:
        (root / "composer.json").write_text(json.dumps(composer))
    return root


def psr4(mapping: dict[str, object], section: str = "autoload") -> dict[str, object]:
    return {section: {"psr-4": mapping}}


def autoload_of(root: Path) -> Autoload:
    return read_autoload(Workspace.at(root))


# --- the capability ---------------------------------------------------------------------


def test_class_in_a_psr4_directory_resolves_by_fqn_without_an_import(tmp_path: Path) -> None:
    """TASK-022's acceptance: no `use` statement, and the FQN still resolves."""
    root = project(tmp_path, psr4({"App\\": "app/"}))

    loaded = load_project(root)

    assert loaded.classes[_CONTROLLER_FQN].properties["orders"] == (
        "App\\Repositories\\OrderRepository"
    )


def test_without_the_map_the_same_name_is_namespace_relative(tmp_path: Path) -> None:
    """The negative control: it is the autoload map doing the work, not the parser.

    Also the honest description of a project with no `composer.json`. PHP really does read
    a bare `App\\...` inside `namespace App\\Http\\Controllers` as relative, so with
    nothing declaring `App\\` autoloadable that is the only reading available.
    """
    root = project(tmp_path, composer=None)

    loaded = load_project(root)

    assert loaded.classes[_CONTROLLER_FQN].properties["orders"] == (
        "App\\Http\\Controllers\\App\\Repositories\\OrderRepository"
    )


def test_autoload_dev_prefixes_are_read_too(tmp_path: Path) -> None:
    """Test namespaces hold real routes and real sinks; ignoring them is a blind spot."""
    root = project(tmp_path, {"autoload-dev": {"psr-4": {"Tests\\": "tests/"}}})

    assert autoload_of(root).prefixes == {"Tests\\"}


def test_an_import_still_wins_over_an_autoload_root() -> None:
    """PHP's own order: a `use` statement rebinds the name for this file."""
    resolved = resolve_type_name(
        "App\\Thing",
        namespace="App\\Http\\Controllers",
        imports={"App": "Vendor\\Aliased"},
        autoload_roots=frozenset({"App\\"}),
    )

    assert resolved == "Vendor\\Aliased\\Thing"


def test_a_prefix_does_not_match_a_longer_namespace_that_merely_starts_with_it() -> None:
    """`App\\` must not claim `Application\\Kernel`; the trailing separator is why."""
    resolved = resolve_type_name(
        "Application\\Kernel",
        namespace="App",
        imports={},
        autoload_roots=frozenset({"App\\"}),
    )

    assert resolved == "App\\Application\\Kernel"


def test_a_prefix_written_without_its_trailing_separator_is_normalised(tmp_path: Path) -> None:
    """Composer rejects `"App"`; Vigilloo reads files Composer may never have validated."""
    root = project(tmp_path, psr4({"App": "app/", "\\Vendor\\": "vendor-src/"}))

    assert autoload_of(root).prefixes == {"App\\", "Vendor\\"}


# --- the traversal guard ----------------------------------------------------------------


def test_a_relative_traversal_prefix_is_rejected_not_followed(tmp_path: Path) -> None:
    """The attack in TASK-022's acceptance, and one line in a file the attacker controls."""
    root = project(tmp_path, psr4({"Evil\\": "../../../../etc/", "App\\": "app/"}))

    autoload = autoload_of(root)

    assert autoload.prefixes == {"App\\"}
    assert [directory for _, directory in autoload.roots] == [root.resolve() / "app"]
    assert any(
        "Evil\\ -> ../../../../etc/ (outside the project root)" == m for m in autoload.rejected
    )


def test_an_absolute_prefix_is_rejected(tmp_path: Path) -> None:
    root = project(tmp_path, psr4({"Etc\\": "/etc", "App\\": "app/"}))

    autoload = autoload_of(root)

    assert autoload.prefixes == {"App\\"}
    assert any("Etc\\" in message for message in autoload.rejected)


def test_a_symlink_escaping_the_root_is_rejected(tmp_path: Path) -> None:
    """The escape the guard exists for: the mapping is relative and stays inside the tree.

    Only the target does not, which is why containment is tested after symlinks are
    resolved rather than on the written path.
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    root = project(tmp_path, psr4({"Linked\\": "linked", "App\\": "app/"}))
    (root / "linked").symlink_to(outside, target_is_directory=True)

    autoload = autoload_of(root)

    assert autoload.prefixes == {"App\\"}
    assert any("Linked\\" in message for message in autoload.rejected)


def test_a_rejected_prefix_does_not_resolve_names(tmp_path: Path) -> None:
    """Rejection has to reach resolution, or the guard is decoration.

    A refused prefix must leave the name resolving exactly as it would with no map at
    all, rather than being quietly honoured by the layer that consumes the map.
    """
    root = project(tmp_path, psr4({"App\\": "../../../../etc/"}))

    loaded = load_project(root)

    assert loaded.classes[_CONTROLLER_FQN].properties["orders"] == (
        "App\\Http\\Controllers\\App\\Repositories\\OrderRepository"
    )


def test_a_composer_json_symlinked_outside_the_root_is_refused(tmp_path: Path) -> None:
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps(psr4({"Evil\\": "app/"})))
    root = project(tmp_path, composer=None)
    (root / "composer.json").symlink_to(outside)

    autoload = autoload_of(root)

    assert autoload.prefixes == frozenset()
    assert autoload.rejected == ("composer.json (outside the project root)",)


def test_an_empty_prefix_is_refused_visibly(tmp_path: Path) -> None:
    """PSR-4's fallback form. Legal Composer, and a prefix that claims every class name."""
    root = project(tmp_path, psr4({"": "src/", "App\\": "app/"}))

    autoload = autoload_of(root)

    assert autoload.prefixes == {"App\\"}
    assert any("empty PSR-4 prefix" in message for message in autoload.rejected)


# --- a malformed composer.json degrades the scan, it never ends it ----------------------


def test_a_missing_composer_json_is_an_ordinary_project(tmp_path: Path) -> None:
    assert autoload_of(project(tmp_path, composer=None)) == Autoload()


def test_malformed_json_does_not_raise(tmp_path: Path) -> None:
    root = project(tmp_path, composer=None)
    (root / "composer.json").write_text("{ not json at all")

    assert autoload_of(root) == Autoload()


def test_a_composer_json_that_is_not_an_object_does_not_raise(tmp_path: Path) -> None:
    root = project(tmp_path, composer=None)
    (root / "composer.json").write_text('["not", "an", "object"]')

    assert autoload_of(root) == Autoload()


def test_a_psr4_section_of_the_wrong_shape_does_not_raise(tmp_path: Path) -> None:
    root = project(tmp_path, {"autoload": {"psr-4": "app/"}})

    assert autoload_of(root) == Autoload()


def test_a_prefix_mapped_to_several_directories_keeps_all_of_them(tmp_path: Path) -> None:
    """Composer allows a list, and dropping the tail would lose half a namespace."""
    root = project(tmp_path, psr4({"App\\": ["app/", "app-extra/"]}))

    autoload = autoload_of(root)

    assert [directory.name for _, directory in autoload.roots] == ["app", "app-extra"]


def test_a_directory_that_is_not_a_string_is_recorded_not_dropped(tmp_path: Path) -> None:
    root = project(tmp_path, psr4({"Odd\\": {"nested": "object"}}))

    autoload = autoload_of(root)

    assert autoload.prefixes == frozenset()
    assert autoload.rejected == ("Odd\\ -> (not a string)",)


# --- the skip is visible ----------------------------------------------------------------


def test_scan_prints_every_rejected_mapping_before_the_findings(tmp_path: Path) -> None:
    """Invariant 4: a dropped prefix is a whole namespace the scan cannot resolve.

    Printed with the other coverage caveats and ahead of any finding, so a clean report
    can never be read without the reason a namespace went missing beside it.
    """
    root = project(tmp_path, psr4({"Evil\\": "../../../../etc/", "App\\": "app/"}))

    result = runner.invoke(app, ["scan", str(root)])

    assert "Autoload mapping ignored" in result.stdout
    assert "Evil" in result.stdout
    assert result.stdout.index("Autoload mapping ignored") < result.stdout.index("Coverage:")
