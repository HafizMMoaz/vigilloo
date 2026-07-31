from pathlib import Path

from vigilloo.parser import parse_php
from vigilloo.symbols import extract_symbols

FIXTURE = Path("tests/fixtures/laravel-minimal")


def test_extracts_namespace_and_class_fqn() -> None:
    parsed = parse_php(FIXTURE / "app/Http/Controllers/OrderController.php")
    syms = extract_symbols(parsed)
    assert syms.namespace == "App\\Http\\Controllers"
    assert "App\\Http\\Controllers\\OrderController" in syms.classes


def test_resolves_use_statements() -> None:
    parsed = parse_php(FIXTURE / "app/Http/Controllers/OrderController.php")
    syms = extract_symbols(parsed)
    assert syms.imports["OrderRepository"] == "App\\Repositories\\OrderRepository"
    assert syms.imports["Request"] == "Illuminate\\Http\\Request"


def test_captures_promoted_constructor_property_type() -> None:
    """Constructor injection is how idiomatic Laravel obtains collaborators."""
    parsed = parse_php(FIXTURE / "app/Http/Controllers/OrderController.php")
    syms = extract_symbols(parsed)
    cls = syms.classes["App\\Http\\Controllers\\OrderController"]
    assert cls.properties["orders"] == "App\\Repositories\\OrderRepository"


def test_captures_method_parameters_in_order() -> None:
    parsed = parse_php(FIXTURE / "app/Repositories/OrderRepository.php")
    syms = extract_symbols(parsed)
    cls = syms.classes["App\\Repositories\\OrderRepository"]
    assert cls.methods["search"].params == ("sort",)


def test_scalar_parameter_types_are_not_namespace_prefixed() -> None:
    """A scalar type hint is not a class and must never gain a namespace."""
    parsed = parse_php(FIXTURE / "app/Repositories/OrderRepository.php")
    syms = extract_symbols(parsed)
    cls = syms.classes["App\\Repositories\\OrderRepository"]
    assert cls.methods["search"].param_types == ("string",)


def test_builtin_and_union_types_resolve_verbatim(tmp_path: Path) -> None:
    source = tmp_path / "Svc.php"
    source.write_text(
        "<?php\n"
        "namespace App\\Services;\n"
        "class Svc\n"
        "{\n"
        "    public function __construct(private int $perPage, private ?string $tag)\n"
        "    {\n"
        "    }\n"
        "\n"
        "    public function mix(int|string $id, self $other)\n"
        "    {\n"
        "    }\n"
        "}\n"
    )
    syms = extract_symbols(parse_php(source))
    cls = syms.classes["App\\Services\\Svc"]
    assert cls.properties == {"perPage": "int", "tag": "string"}
    assert cls.methods["mix"].param_types == ("int|string", "self")


def test_extracts_base_class_and_array_property_defaults(tmp_path: Path) -> None:
    """Model configuration the mass-assignment rule reads."""
    path = tmp_path / "User.php"
    path.write_text(
        "<?php\n"
        "namespace App\\Models;\n"
        "use Illuminate\\Database\\Eloquent\\Model;\n"
        "class User extends Model\n"
        "{\n"
        "    protected $guarded = [];\n"
        "    protected $fillable = ['name', 'is_admin'];\n"
        "    protected $unreadable = [self::LOCKED];\n"
        "}\n"
    )
    info = extract_symbols(parse_php(path)).classes["App\\Models\\User"]

    assert info.parent == "Illuminate\\Database\\Eloquent\\Model"
    assert info.array_props["guarded"] == ()
    assert info.array_props["fillable"] == ("name", "is_admin")
    # Unreadable is absent, not empty: the two mean opposite things.
    assert "unreadable" not in info.array_props
    assert info.array_prop_spans["guarded"].start_line == 6


def test_extracts_traits_and_their_methods(tmp_path: Path) -> None:
    path = tmp_path / "Auditable.php"
    path.write_text(
        "<?php\n"
        "namespace App\\Support;\n"
        "trait Auditable { public function audit(string $value) { return $value; } }\n"
        "class Service { use Auditable; }\n"
    )
    syms = extract_symbols(parse_php(path))

    trait = syms.traits["App\\Support\\Auditable"]
    service = syms.classes["App\\Support\\Service"]
    assert trait.methods["audit"].fqn == "App\\Support\\Auditable::audit"
    assert service.traits == ("App\\Support\\Auditable",)


def test_trait_use_aliases_are_resolved(tmp_path: Path) -> None:
    path = tmp_path / "Service.php"
    path.write_text(
        "<?php\n"
        "namespace App\\Support;\n"
        "trait Auditable { public function audit(string $value) { return $value; } }\n"
        "class Service { use Auditable { audit as record; } }\n"
    )
    service = extract_symbols(parse_php(path)).classes["App\\Support\\Service"]

    assert service.traits == ("App\\Support\\Auditable",)
    assert service.trait_aliases == {"record": ("App\\Support\\Auditable", "audit")}
