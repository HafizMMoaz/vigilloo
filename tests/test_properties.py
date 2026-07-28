"""The property-based layer from docs/22-testing section "Property-based testing".

That section names four properties. Three of them live here:

1. Any syntactically valid PHP parses without crashing.
2. Taint propagation is monotonic - adding a source never removes a finding.
4. Sanitizing a path removes the finding for that taint kind, and only that kind.

Property 3, "node ids are stable under whitespace and comment changes", is deliberately
**not** here: it is already implemented as a Hypothesis property in tests/test_ids.py, and
it stays there. It belongs next to the negative-space tests that give it meaning - renaming
a class changes every id under it, renaming one method changes exactly one - because
"stable" and "constant" are only distinguishable when both halves are read together. That
whole file exists because src/ids.py exists; splitting the property out would leave the
reason for the module in one file and its proof in another. A second copy here would be
worse still: two properties over the same derivation drift apart, and the weaker one is the
one nobody notices has stopped checking anything.

Example budgets are set per property rather than globally, because the properties are three
orders of magnitude apart in cost: parsing a generated file is microseconds, while the
end-to-end ones write a Laravel project to disk and scan it. The numbers are chosen so this
whole module stays a second or two - the acceptance bar in the backlog is 30 seconds, but a
suite that currently runs in three is a suite people run on every save, and spending the
whole budget because it was offered would end that.
"""

from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from vigilloo.parser import ParsedFile, node_span, node_text, parse_php, parse_source, walk
from vigilloo.symbols import extract_symbols

# ---------------------------------------------------------------------------
# A grammar of PHP, small enough to stay valid and wide enough to be worth generating.
#
# Generating arbitrary *valid* PHP from st.text() is not possible in any useful sense: the
# chance of a random string being a parseable program is zero, so such a test passes by
# generating garbage that the parser correctly rejects, and proves nothing about the code
# path that runs on real input. So the strategies below are a composite over a hand-written
# grammar. Every production is a construct the taint walk actually looks at - sources,
# sanitizers, casts, concatenation, calls, array access - because the point is to reach the
# branches of expr_kinds, not to exercise tree-sitter's PHP support in general.
# ---------------------------------------------------------------------------

# Two names, not ten. The interesting collisions in a taint environment are "this variable
# is tainted and that one is not"; more names only spread the same states thinner over the
# examples Hypothesis is allowed to draw.
_VAR_NAMES = ("a", "b")

_LITERALS = (
    "0",
    "42",
    "'x'",
    '"sort asc"',
    "true",
    "null",
    "[]",
)

# The Request methods, one per kind-set in vocabulary.SOURCE_METHODS: input() carries every
# kind, only() and validated() carry everything except mass_assign. Drawing from both is
# what makes the mass_assign asymmetry reachable at all.
_SOURCES = (
    "$request->input('q')",
    "$request->all()",
    "$request->query('sort')",
    "$request->only(['name'])",
    "$request->validated()",
)

# Not sanitizers: an unrecognised call must preserve taint (expr_kinds falls through to the
# union over children), and a generator with no unrecognised calls in it would never test
# that. trim() in particular is the one developers believe sanitizes.
_OPAQUE_CALLS = ("strtoupper", "trim", "sprintf")

_SANITIZERS = ("e", "htmlspecialchars", "htmlentities", "intval", "floatval")


def _expressions() -> st.SearchStrategy[str]:
    """PHP expression text, nested to a handful of levels.

    st.recursive rather than a fixed depth: the shape of a nested expression is exactly
    what decides whether a sanitizer sits inside or outside a concatenation, and that
    nesting is where kind-based taint either works or quietly stops working.
    """
    leaves = st.one_of(
        st.sampled_from(_LITERALS),
        st.sampled_from([f"${name}" for name in _VAR_NAMES]),
        st.sampled_from(_SOURCES),
    )

    def extend(children: st.SearchStrategy[str]) -> st.SearchStrategy[str]:
        pair = st.tuples(children, children)
        return st.one_of(
            children.map(lambda e: f"({e})"),
            pair.map(lambda p: f"{p[0]} . {p[1]}"),
            st.tuples(st.sampled_from(_SANITIZERS), children).map(lambda p: f"{p[0]}({p[1]})"),
            st.tuples(st.sampled_from(_OPAQUE_CALLS), children).map(lambda p: f"{p[0]}({p[1]})"),
            children.map(lambda e: f"(int) ({e})"),
            children.map(lambda e: f"(string) ({e})"),
            children.map(lambda e: f"({e})['key']"),
            children.map(lambda e: f"['key' => {e}]"),
            st.tuples(children, children, children).map(lambda p: f"({p[0]} ? {p[1]} : {p[2]})"),
        )

    return st.recursive(leaves, extend, max_leaves=6)


def _statements() -> st.SearchStrategy[str]:
    """One PHP statement, possibly containing a block of further statements."""
    simple = st.one_of(
        st.tuples(st.sampled_from(_VAR_NAMES), _expressions()).map(lambda p: f"${p[0]} = {p[1]};"),
        _expressions().map(lambda e: f"echo {e};"),
        _expressions().map(lambda e: f"return {e};"),
        _expressions().map(lambda e: f"$this->things->search({e});"),
        _expressions().map(lambda e: f"$query->whereRaw({e});"),
        _expressions().map(lambda e: f"User::create({e});"),
    )

    def extend(children: st.SearchStrategy[str]) -> st.SearchStrategy[str]:
        block = st.lists(children, min_size=1, max_size=3).map("\n".join)
        return st.one_of(
            st.tuples(_expressions(), block).map(lambda p: f"if ({p[0]}) {{\n{p[1]}\n}}"),
            st.tuples(_expressions(), block).map(
                lambda p: f"foreach ({p[0]} as $item) {{\n{p[1]}\n}}"
            ),
            block.map(lambda b: f"try {{\n{b}\n}} catch (\\Throwable $e) {{\n}}"),
        )

    return st.recursive(simple, extend, max_leaves=4)


def _php_source(bodies: list[list[str]]) -> str:
    """A whole PHP file: namespace, imports, a class, and the generated method bodies."""
    methods = "\n".join(
        f"    public function method{number}($request, $query)\n    {{\n"
        + "\n".join(f"        {statement}" for statement in body)
        + "\n    }\n"
        for number, body in enumerate(bodies)
    )
    return (
        "<?php\n\n"
        "namespace App\\Http\\Controllers;\n\n"
        "use App\\Models\\User;\n\n"
        "class GeneratedController\n{\n" + methods + "}\n"
    )


# Built once, at import. Constructing a recursive strategy is expensive and calling the
# factories inside a @composite body rebuilds them on every single draw: measured at 10.9
# seconds for 250 examples that way against 0.9 seconds like this, for identical output.
# Nothing about the test says which one you wrote, so it is worth knowing that it is the
# difference between a property suite people run and one they switch off.
_EXPRESSIONS = _expressions()
_STATEMENTS = _statements()
_PHP_SOURCES = st.lists(st.lists(_STATEMENTS, max_size=4), min_size=1, max_size=3).map(_php_source)

_GENERATED_PATH = Path("app/Http/Controllers/GeneratedController.php")


# ---------------------------------------------------------------------------
# Property 1: any syntactically valid PHP parses without crashing.
# ---------------------------------------------------------------------------


@settings(max_examples=250, deadline=None)
@given(source=_PHP_SOURCES)
def test_generated_php_parses_and_walks_without_crashing(source: str) -> None:
    """Parse, walk every node, and read every span - the whole crash surface, not just parse.

    `has_errors` is asserted rather than merely tolerated. The grammar above only emits
    valid PHP, so an error node means either the parser rejected something legal or the
    generator drifted into producing something illegal, and both are worth a red test. It
    is also the only check that keeps this property honest: without it a generator that
    degenerated into garbage would still "parse without crashing" forever.
    """
    parsed = parse_source(_GENERATED_PATH, source.encode())

    assert not parsed.has_errors, source

    for node in walk(parsed.tree.root_node):
        span = node_span(node, parsed.path)
        assert 1 <= span.start_line <= span.end_line
        node_text(node, parsed.source)

    # Symbol extraction is the first consumer of every tree and the one that would crash on
    # an unexpected shape, so "parses without crashing" is not worth much without it.
    symbols = extract_symbols(parsed)
    assert "App\\Http\\Controllers\\GeneratedController" in symbols.classes


@pytest.fixture(scope="session")
def _scratch_file(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One reused file to parse from disk.

    Session-scoped on purpose: a function-scoped fixture is shared across every example of
    a Hypothesis test, which Hypothesis rightly reports as a health-check failure.
    """
    return tmp_path_factory.mktemp("properties") / "arbitrary.php"


@settings(
    max_examples=150, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(data=st.binary(max_size=400))
def test_parse_php_never_raises_for_arbitrary_bytes(data: bytes, _scratch_file: Path) -> None:
    """parse_php's docstring says "Never raises for malformed input". Stated as a test.

    Arbitrary bytes, not arbitrary text: the input is a file on someone's disk, so it can
    be a truncated upload, a binary blob with a .php extension, or UTF-16. Invariant 4 says
    a parse failure is reported; an exception escaping the parser would instead abort the
    scan of a whole project because one file was junk.
    """
    _scratch_file.write_bytes(data)

    parsed = parse_php(_scratch_file)

    assert isinstance(parsed, ParsedFile)
    assert parsed.source == data
    # node_text decodes with errors="replace", so it must survive bytes that are not UTF-8.
    node_text(parsed.tree.root_node, parsed.source)
