from vigilloo.laravel.vocabulary import (
    MAGIC_PROPERTY_KINDS,
    SQL_INJECTION_RULE,
    is_source,
    is_superglobal,
    sanitizer_clears,
    sinks,
    source_kinds,
    superglobal_kinds,
)
from vigilloo.models import ALL_KINDS, TaintKind


def test_request_input_is_a_source() -> None:
    assert is_source("input")
    assert is_source("query")
    assert is_source("all")
    assert not is_source("nonexistent_method")


def test_developer_chosen_keys_are_tainted_but_not_mass_assignable() -> None:
    """only()/validated() are still XSS-dangerous, and safe to mass-assign.

    A single boolean over the other kinds cannot express this, which is the
    whole reason mass_assign is a kind rather than a flag on the sink.
    """
    for method in ("only", "validated", "safe"):
        kinds = source_kinds(method)
        assert TaintKind.HTML in kinds, method
        assert TaintKind.MASS_ASSIGN not in kinds, method

    # except() is a blacklist: it does not protect a column added later.
    assert TaintKind.MASS_ASSIGN in source_kinds("except")
    assert TaintKind.MASS_ASSIGN in source_kinds("all")


def test_raw_sinks_declare_the_dangerous_argument_kind_and_rule() -> None:
    """whereRaw('age > ?', [$age]) is safe; only argument 0 is a sink."""
    assert sinks("orderByRaw") == [(0, TaintKind.SQL, SQL_INJECTION_RULE)]
    assert sinks("whereRaw") == [(0, TaintKind.SQL, SQL_INJECTION_RULE)]
    assert sinks("orWhereRaw") == [(0, TaintKind.SQL, SQL_INJECTION_RULE)]
    assert sinks("havingRaw") == [(0, TaintKind.SQL, SQL_INJECTION_RULE)]
    assert sinks("selectRaw") == [(0, TaintKind.SQL, SQL_INJECTION_RULE)]
    assert sinks("orderBy") == []
    assert sinks("where") == []


def test_escaping_helpers_clear_html_but_not_sql() -> None:
    """The distinction a boolean taint flag cannot express."""
    assert sanitizer_clears("e") == frozenset({TaintKind.HTML})
    assert TaintKind.SQL not in sanitizer_clears("htmlspecialchars")


def test_numeric_coercion_clears_multiple_kinds() -> None:
    assert sanitizer_clears("intval") == frozenset({TaintKind.SQL, TaintKind.HTML, TaintKind.PATH})


def test_anti_sanitizers_clear_nothing() -> None:
    """strip_tags and addslashes are findings in themselves, never sanitizers.

    Treating either as clearing a kind converts a vulnerability into a clean
    result, which is the worst failure mode this tool has.
    """
    assert sanitizer_clears("strip_tags") == frozenset()
    assert sanitizer_clears("addslashes") == frozenset()
    assert sanitizer_clears("nonexistent_function") == frozenset()


def test_all_kinds_is_what_the_engine_can_reason_about() -> None:
    """Only kinds with sinks wired are declared.

    Declaring `js` or `path` with nothing able to consume them would mark
    sources with coverage the engine does not have.

    NOTE: TaintKind.CODE is sink-only (no sanitizers). This is intentional:
    there is no function call that makes untrusted data safe to pass to eval()
    or unserialize(). The spec states 'nothing clears this kind', so adding a
    sanitizer for CODE would be rejected in review.
    """
    assert ALL_KINDS == frozenset(
        {
            TaintKind.SQL,
            TaintKind.HTML,
            TaintKind.MASS_ASSIGN,
            TaintKind.SHELL,
            TaintKind.CODE,
            TaintKind.PATH,
            TaintKind.URL,
            TaintKind.JS,
        }
    )


def test_every_key_of_a_request_superglobal_is_attacker_controlled() -> None:
    """$_GET and friends need no per-key rule: the attacker names the keys too."""
    for name in ("_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES", "argv"):
        assert superglobal_kinds(name, "anything") == ALL_KINDS
        assert superglobal_kinds(name, None) == ALL_KINDS


def test_a_superglobal_carries_mass_assign_as_well() -> None:
    """`?u[is_admin]=1` makes $_GET['u'] an array whose keys came off the wire.

    Without mass_assign the array reaching User::create() would be reported as XSS-
    and SQL-dangerous and not as the mass assignment it is, which is the finding that
    actually matters at an Eloquent write.
    """
    assert TaintKind.MASS_ASSIGN in superglobal_kinds("_GET", "u")


def test_server_is_split_by_key() -> None:
    """The half-request, half-configuration case, per docs/06-taint-analysis."""
    assert superglobal_kinds("_SERVER", "HTTP_HOST") == ALL_KINDS
    assert superglobal_kinds("_SERVER", "HTTP_X_FORWARDED_FOR") == ALL_KINDS
    assert superglobal_kinds("_SERVER", "REQUEST_URI") == ALL_KINDS
    assert superglobal_kinds("_SERVER", "QUERY_STRING") == ALL_KINDS
    assert superglobal_kinds("_SERVER", "PATH_INFO") == ALL_KINDS
    assert superglobal_kinds("_SERVER", "DOCUMENT_ROOT") == frozenset()


def test_any_request_header_is_tainted_by_the_prefix_rule() -> None:
    """A header arrives as HTTP_<NAME>, so the prefix is the rule.

    Listing headers one at a time would make every unlisted one a silent false
    negative, and the set of headers a client may send is not enumerable.
    """
    assert superglobal_kinds("_SERVER", "HTTP_REFERER") == ALL_KINDS
    assert superglobal_kinds("_SERVER", "HTTP_SOMETHING_NOBODY_LISTED") == ALL_KINDS


def test_an_unreadable_server_key_is_tainted() -> None:
    """`$_SERVER[$name]` and a bare `$_SERVER` are not known to be safe.

    The set of safe keys is short and knowable; the set of dangerous ones is open
    ended. Guessing clean here would be the silent false negative invariant 4 exists
    to prevent, so an unreadable key errs the other way.
    """
    assert superglobal_kinds("_SERVER", None) == ALL_KINDS


def test_an_ordinary_variable_is_not_a_superglobal() -> None:
    """The walk gained a rule for reading an array by key. It applies to seven names."""
    assert not is_superglobal("config")
    assert not is_superglobal("request")
    assert superglobal_kinds("config", "sort") == frozenset()
    assert is_superglobal("_GET")
    assert is_superglobal("_SERVER")


def test_a_magic_property_read_carries_the_same_kinds_as_input() -> None:
    """$request->bio and $request->input('bio') are one lookup written two ways.

    Laravel's Request implements __get(), so both forms return the same value out of
    the same bag. Giving the property form fewer kinds would make the danger depend on
    which spelling the developer happened to pick.
    """
    assert MAGIC_PROPERTY_KINDS == source_kinds("input")
    assert MAGIC_PROPERTY_KINDS == ALL_KINDS


def test_a_magic_property_read_carries_mass_assign() -> None:
    """`?bio[is_admin]=1` makes $request->bio an array whose keys came off the wire.

    The same property that puts mass_assign on $_GET. Without it, an Eloquent write fed
    by a magic read is reported as an injection rather than as the mass assignment that
    is the finding worth having there.
    """
    assert TaintKind.MASS_ASSIGN in MAGIC_PROPERTY_KINDS
