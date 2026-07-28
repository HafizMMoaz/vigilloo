from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from vigilloo.ids import node_id
from vigilloo.parser import parse_source
from vigilloo.symbols import extract_symbols

_PROJECT_ID = 1
_REL_PATH = Path("app/Http/Controllers/OrderController.php")

_SOURCE = """<?php

namespace App\\Http\\Controllers;

use App\\Models\\Order;

class OrderController extends Controller
{
    protected $guarded = [];

    public function index()
    {
        return view('orders.index', ['orders' => Order::all()]);
    }

    public function show(int $id)
    {
        return Order::findOrFail($id);
    }
}
"""

# Reformattings, not edits: every one of these is a line that changes where the code sits and
# nothing about what it says. A node id that moves under any of them is a node id nothing can
# be baselined against.
_REFORMATTINGS = ["", "    ", "\t", "// a comment", "/* block */", "/** @var int */"]


def _node_ids(source: str) -> list[str]:
    """Every class and method in `source`, as the graph would key it.

    End to end through the parser and the symbol table on purpose. Calling node_id with
    hand-written arguments would only prove that a hash function is a function; the property
    docs/22-testing asks for is that the *whole derivation* survives a reformat, and it is the
    parser that decides what fqn a reformatted class has.
    """
    symbols = extract_symbols(parse_source(_REL_PATH, source.encode()))
    ids = []
    for info in symbols.classes.values():
        ids.append(node_id(_PROJECT_ID, "class", info.fqn))
        ids += [node_id(_PROJECT_ID, method.kind, method.fqn) for method in info.methods.values()]
    return sorted(ids)


_BASELINE = _node_ids(_SOURCE)


def _reformatted(edits: list[tuple[int, str]]) -> str:
    lines = _SOURCE.splitlines()
    # Applied last-first so an earlier insertion cannot shift a later index, which would make
    # the same edit list mean different things depending on order.
    for index, text in sorted(edits, reverse=True):
        lines.insert(index, text)
    return "\n".join(lines)


@settings(max_examples=200, deadline=None)
@given(
    edits=st.lists(
        st.tuples(
            # From 1: never above the opening <?php, which would put the insertion outside PHP
            # and test the parser's HTML handling instead of node identity.
            st.integers(min_value=1, max_value=len(_SOURCE.splitlines())),
            st.sampled_from(_REFORMATTINGS),
        ),
        max_size=8,
    )
)
def test_whitespace_and_comments_never_change_a_node_id(edits: list[tuple[int, str]]) -> None:
    """docs/22-testing section "Property-based testing", stated as its test.

    This is the case that fails the moment anyone puts the span back into the derivation.
    """
    assert _node_ids(_reformatted(edits)) == _BASELINE


def test_renaming_a_class_changes_every_id_under_it() -> None:
    """Stable is not the same as constant: a renamed symbol is a different symbol."""
    renamed = _node_ids(_SOURCE.replace("OrderController", "InvoiceController"))

    assert len(renamed) == len(_BASELINE)
    assert set(renamed).isdisjoint(_BASELINE)


def test_renaming_one_method_changes_only_that_method() -> None:
    renamed = set(_node_ids(_SOURCE.replace("function show", "function display")))

    assert len(renamed - set(_BASELINE)) == 1
    assert len(set(_BASELINE) - renamed) == 1


def test_kind_project_and_discriminator_each_change_the_id() -> None:
    """Nothing in the derivation may be ignored, or two distinct nodes share a row."""
    base = node_id(_PROJECT_ID, "class", "App\\Models\\Order")

    assert node_id(_PROJECT_ID, "route", "App\\Models\\Order") != base
    assert node_id(_PROJECT_ID + 1, "class", "App\\Models\\Order") != base
    assert node_id(_PROJECT_ID, "class", "App\\Models\\Order", discriminator="1") != base


def test_the_same_node_derives_the_same_id_from_a_known_value() -> None:
    """The scheme is part of the contract: ids are stored, exported and compared."""
    derived = node_id(1, "method", "App\\Http\\Controllers\\OrderController::show")

    assert derived == "8651dd15657a03f4"
    assert len(derived) == 16
