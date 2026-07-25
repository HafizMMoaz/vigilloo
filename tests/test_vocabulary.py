from vigilloo.laravel.vocabulary import is_source, sanitizer_clears, sink
from vigilloo.models import ALL_KINDS, TaintKind


def test_request_input_is_a_source() -> None:
    assert is_source("input")
    assert is_source("query")
    assert is_source("all")
    assert not is_source("validated")


def test_raw_sinks_declare_the_dangerous_argument_and_its_kind() -> None:
    """whereRaw('age > ?', [$age]) is safe; only argument 0 is a sink."""
    assert sink("orderByRaw") == (0, TaintKind.SQL)
    assert sink("whereRaw") == (0, TaintKind.SQL)
    assert sink("orderBy") is None
    assert sink("where") is None


def test_escaping_helpers_clear_html_but_not_sql() -> None:
    """The distinction a boolean taint flag cannot express."""
    assert sanitizer_clears("e") == frozenset({TaintKind.HTML})
    assert TaintKind.SQL not in sanitizer_clears("htmlspecialchars")


def test_numeric_coercion_clears_both_kinds() -> None:
    assert sanitizer_clears("intval") == frozenset({TaintKind.SQL, TaintKind.HTML})


def test_anti_sanitizers_clear_nothing() -> None:
    """strip_tags and addslashes are findings in themselves, never sanitizers.

    Treating either as clearing a kind converts a vulnerability into a clean
    result, which is the worst failure mode this tool has.
    """
    assert sanitizer_clears("strip_tags") == frozenset()
    assert sanitizer_clears("addslashes") == frozenset()
    assert sanitizer_clears("nonexistent_function") == frozenset()


def test_all_kinds_is_what_the_engine_can_reason_about() -> None:
    """Only kinds with both sinks and sanitizers wired are declared.

    Declaring `code` or `shell` with nothing able to consume or clear them
    would mark sources with coverage the engine does not have.
    """
    assert ALL_KINDS == frozenset({TaintKind.SQL, TaintKind.HTML})
