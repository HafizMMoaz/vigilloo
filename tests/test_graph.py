from pathlib import Path

from vigilloo.graph import load_project

FIXTURE = Path("tests/fixtures/laravel-minimal")


def test_loads_all_php_files_and_routes() -> None:
    project = load_project(FIXTURE)
    assert {r.uri for r in project.routes} >= {"/orders/search", "/orders/display"}
    assert not project.failed
    assert "App\\Http\\Controllers\\OrderController" in project.classes
    assert "App\\Repositories\\OrderRepository" in project.classes


def test_resolves_injected_property_to_class() -> None:
    """$this->orders must resolve to OrderRepository for the call graph."""
    project = load_project(FIXTURE)
    resolved = project.resolve_property_type("App\\Http\\Controllers\\OrderController", "orders")
    assert resolved == "App\\Repositories\\OrderRepository"


def test_method_lookup_by_fqn() -> None:
    project = load_project(FIXTURE)
    method = project.method("App\\Repositories\\OrderRepository::search")
    assert method is not None
    assert method.params == ("sort",)


def test_method_lookup_walks_parents_and_traits(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "Types.php").write_text(
        "<?php\n"
        "namespace App;\n"
        "trait Shared { public function fromTrait($value) { return $value; } }\n"
        "class Base { public function inherited($value) { return $value; } }\n"
        "class Child extends Base { use Shared; }\n"
    )
    project = load_project(tmp_path)

    inherited = project.method("App\\Child::inherited")
    trait_method = project.method("App\\Child::fromTrait")
    assert inherited is not None and inherited.fqn == "App\\Base::inherited"
    assert trait_method is not None and trait_method.fqn == "App\\Shared::fromTrait"


def test_method_lookup_honours_trait_aliases(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "Types.php").write_text(
        "<?php\n"
        "namespace App;\n"
        "trait Shared { public function original($value) { return $value; } }\n"
        "class Child { use Shared { original as alias; } }\n"
    )
    project = load_project(tmp_path)

    aliased = project.method("App\\Child::alias")
    assert aliased is not None and aliased.fqn == "App\\Shared::original"


def test_ambiguous_trait_method_is_not_guessed(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "Types.php").write_text(
        "<?php\n"
        "namespace App;\n"
        "trait First { public function run($value) { return $value; } }\n"
        "trait Second { public function run($value) { return $value; } }\n"
        "class Child { use First, Second; }\n"
    )
    project = load_project(tmp_path)

    assert project.method("App\\Child::run") is None


def test_insteadof_excludes_only_the_traits_it_names(tmp_path: Path) -> None:
    """`A::run insteadof B` removes B's copy and says nothing about C.

    PHP rejects a class that still has two live copies, so a resolver that read the
    left-hand side as "the winner" would answer `A::run` for a class that cannot load -
    and would answer differently depending on the order the clauses were written.

    The `insteadof B, C` case also covers a grammar gap: this tree-sitter-php version has
    no rule for that comma list and parses part of it into an ERROR node, so the names
    have to be recovered from there or a fully disambiguated class reads as ambiguous.
    """
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "Types.php").write_text(
        "<?php\n"
        "namespace App;\n"
        "trait A { public function run($v) { return $v; } }\n"
        "trait B { public function run($v) { return $v; } }\n"
        "trait C { public function run($v) { return $v; } }\n"
        "class Settled { use A, B { A::run insteadof B; } }\n"
        "class StillAmbiguous { use A, B, C { A::run insteadof B; } }\n"
        "class AllNamed { use A, B, C { A::run insteadof B, C; } }\n"
    )
    project = load_project(tmp_path)

    settled = project.method("App\\Settled::run")
    all_named = project.method("App\\AllNamed::run")
    assert settled is not None and settled.fqn == "App\\A::run"
    assert all_named is not None and all_named.fqn == "App\\A::run"
    assert project.method("App\\StillAmbiguous::run") is None


def test_an_abstract_trait_method_is_a_requirement_not_an_implementation(
    tmp_path: Path,
) -> None:
    """The body PHP runs is the parent's, and an abstract declaration has none.

    Stopping on the abstract one looks like a resolved call while pointing at nothing a
    taint walk can enter, which is a false negative that reports itself as success.
    """
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "Types.php").write_text(
        "<?php\n"
        "namespace App;\n"
        "trait Requires { abstract protected function handle($v); }\n"
        "class Base { protected function handle($v) { return $v; } }\n"
        "class Child extends Base { use Requires; }\n"
    )
    project = load_project(tmp_path)

    resolved = project.method("App\\Child::handle")
    assert resolved is not None and resolved.fqn == "App\\Base::handle"


def test_a_class_method_beats_a_trait_and_a_trait_beats_the_parent(tmp_path: Path) -> None:
    """One method name at all three levels, which is the only way to test precedence."""
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "Types.php").write_text(
        "<?php\n"
        "namespace App;\n"
        "trait T { public function run($v) { return $v; } }\n"
        "class Base { public function run($v) { return $v; } }\n"
        "class OwnWins extends Base { use T; public function run($v) { return $v; } }\n"
        "class TraitWins extends Base { use T; }\n"
    )
    project = load_project(tmp_path)

    own = project.method("App\\OwnWins::run")
    from_trait = project.method("App\\TraitWins::run")
    assert own is not None and own.fqn == "App\\OwnWins::run"
    assert from_trait is not None and from_trait.fqn == "App\\T::run"


def test_a_trait_composed_through_another_trait_resolves(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "Types.php").write_text(
        "<?php\n"
        "namespace App;\n"
        "trait Inner { public function run($v) { return $v; } }\n"
        "trait Outer { use Inner; }\n"
        "class Child { use Outer; }\n"
    )
    project = load_project(tmp_path)

    resolved = project.method("App\\Child::run")
    assert resolved is not None and resolved.fqn == "App\\Inner::run"


def test_a_trait_composition_cycle_terminates(tmp_path: Path) -> None:
    """`trait A { use B; }` and `trait B { use A; }` parse, so lookup must survive them."""
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "Types.php").write_text(
        "<?php\nnamespace App;\ntrait A { use B; }\ntrait B { use A; }\nclass Child { use A; }\n"
    )
    project = load_project(tmp_path)

    assert project.method("App\\Child::missing") is None


def test_a_visibility_only_adaptation_is_not_an_alias(tmp_path: Path) -> None:
    """`Shared::work as protected;` renames nothing. `protected` is not a method."""
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "Types.php").write_text(
        "<?php\n"
        "namespace App;\n"
        "trait Shared { public function work($v) { return $v; } }\n"
        "class Child { use Shared { Shared::work as protected; } }\n"
    )
    project = load_project(tmp_path)

    work = project.method("App\\Child::work")
    assert work is not None and work.fqn == "App\\Shared::work"
    assert project.method("App\\Child::protected") is None


def test_a_trait_in_another_file_resolves_through_an_import_alias(tmp_path: Path) -> None:
    """The common shape: the trait is a separate file, imported and aliased."""
    (tmp_path / "app" / "Support").mkdir(parents=True)
    (tmp_path / "app" / "Http").mkdir(parents=True)
    (tmp_path / "app" / "Support" / "Shared.php").write_text(
        "<?php\nnamespace App\\Support;\ntrait Shared { public function run($v) { return $v; } }\n"
    )
    (tmp_path / "app" / "Http" / "Child.php").write_text(
        "<?php\n"
        "namespace App\\Http;\n"
        "use App\\Support\\Shared as ImportedShared;\n"
        "class Child { use ImportedShared; }\n"
    )
    project = load_project(tmp_path)

    resolved = project.method("App\\Http\\Child::run")
    assert resolved is not None and resolved.fqn == "App\\Support\\Shared::run"


def test_an_inherited_property_type_resolves(tmp_path: Path) -> None:
    """A repository injected on a base controller is still injected on the subclass."""
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "Types.php").write_text(
        "<?php\n"
        "namespace App;\n"
        "class Repo { public function search($q) { return $q; } }\n"
        "class Base { public function __construct(protected Repo $repo) {} }\n"
        "class Child extends Base {}\n"
    )
    project = load_project(tmp_path)

    assert project.resolve_property_type("App\\Child", "repo") == "App\\Repo"


def test_a_method_body_is_matched_by_its_whole_span(tmp_path: Path) -> None:
    """Two declarations can share a line, and the wrong body would be walked silently."""
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "Types.php").write_text(
        "<?php\nnamespace App;\n"
        "trait T { public function helper($v) { return $v; } } "
        "class C { use T; public function entry($v) { return $v; } }\n"
    )
    project = load_project(tmp_path)

    entry = project.method_node("App\\C::entry")
    helper = project.method_node("App\\C::helper")
    assert entry is not None and helper is not None
    assert entry[0].start_byte != helper[0].start_byte
    assert project.method("App\\C::entry") is not None
    assert project.method_node("App\\C::entry")[0].start_byte == entry[0].start_byte


def test_blade_templates_are_rewritten_not_parsed_as_php(tmp_path: Path) -> None:
    views = tmp_path / "resources" / "views" / "orders"
    views.mkdir(parents=True)
    (views / "show.blade.php").write_text("<div>\n{!! $sort !!}\n</div>\n")

    project = load_project(tmp_path)
    rel = Path("resources/views/orders/show.blade.php")

    assert rel in project.blade
    assert rel not in project.files
    assert not project.blade[rel].has_errors


def test_blade_originals_back_the_snippets(tmp_path: Path) -> None:
    """Snippets must show Blade, not the PHP it was rewritten into."""
    views = tmp_path / "resources" / "views"
    views.mkdir(parents=True)
    (views / "show.blade.php").write_text("<div>\n  {!! $sort !!}\n</div>\n")

    project = load_project(tmp_path)
    rel = Path("resources/views/show.blade.php")

    assert project.blade_line(rel, 2) == "{!! $sort !!}"
    assert project.blade_line(rel, 999) == ""
