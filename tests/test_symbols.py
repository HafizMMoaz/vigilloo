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
