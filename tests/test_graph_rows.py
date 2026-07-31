"""The Project -> nodes/edges translation, and its trip through the store.

Counts here are asserted against the symbol table rather than against a literal, so the
fixture can gain a controller without this file needing an edit to stay true. A literal
count would either be maintained or - far more likely - loosened until it asserted nothing.
"""

import sqlite3
from collections import Counter
from pathlib import Path

import pytest

from vigilloo.graph import GraphRows, Project, graph_rows, load_project
from vigilloo.ids import node_id
from vigilloo.laravel.routes import UNRESOLVED_MIDDLEWARE, extract_routes
from vigilloo.models import Finding, PathStep, Span
from vigilloo.parser import parse_source
from vigilloo.store import connect, record_scan
from vigilloo.symbols import extract_symbols
from vigilloo.workspace import Workspace

FIXTURE = Path("tests/fixtures/laravel-minimal")


def _rows(project: Project, project_id: int = 1) -> GraphRows:
    """Build rows with a synthetic file_id per path, standing in for the store's."""
    paths = sorted(set(project.files) | set(project.blade) | set(project.failed))
    return graph_rows(project, project_id, {path: index for index, path in enumerate(paths, 1)})


def _project_from(source: str, path: str = "app/Example.php") -> Project:
    rel = Path(path)
    parsed = parse_source(rel, source.encode())
    syms = extract_symbols(parsed)
    return Project(
        root=Path("."),
        files={rel: parsed},
        symbols={rel: syms},
        classes=dict(syms.classes),
        traits=dict(syms.traits),
        digests={rel: "0" * 64},
    )


def _by_kind(rows: GraphRows) -> Counter[str]:
    return Counter(node.kind for node in rows.nodes)


# ─── Nodes ───────────────────────────────────────────────────────────────────


def test_every_symbol_in_the_project_becomes_exactly_one_node() -> None:
    project = load_project(FIXTURE)
    rows = _rows(project)

    kinds = _by_kind(rows)
    assert kinds["class"] == len(project.classes)
    assert kinds["trait"] == len(project.traits)
    assert kinds["method"] == sum(
        len(info.methods) for info in (*project.classes.values(), *project.traits.values())
    )
    assert kinds["route"] == len(project.routes)
    assert kinds["file"] == len(project.files) + len(project.blade) + len(project.failed)

    ids = [node.id for node in rows.nodes]
    assert len(ids) == len(set(ids)), "a node was emitted twice"


def test_node_ids_are_the_content_derived_ones_and_nothing_else() -> None:
    """Invariant 3, checked at the seam rather than only inside ids.py.

    A builder that derived its own ids would pass every count assertion above and quietly
    break every baseline, so the ids are recomputed here from the same public function.
    """
    project = load_project(FIXTURE)
    rows = _rows(project, project_id=7)

    for node in rows.nodes:
        assert node.fqn is not None
        assert node.id == node_id(7, node.kind, node.fqn)


def test_the_same_project_under_a_different_project_id_shares_no_node() -> None:
    project = load_project(FIXTURE)
    assert not {n.id for n in _rows(project, 1).nodes} & {n.id for n in _rows(project, 2).nodes}


def test_a_class_keeps_a_parent_it_cannot_resolve_as_an_attribute() -> None:
    """`extends Model` is how the Laravel rules recognise an Eloquent model.

    The base class lives in the framework and has no node here, so the EXTENDS edge cannot
    exist - and if the name were only ever carried by that edge, it would be lost entirely.
    """
    project = _project_from(
        "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\n"
        "class Invoice extends Model {}\n"
    )
    rows = _rows(project)

    invoice = next(n for n in rows.nodes if n.kind == "class")
    assert invoice.attrs == {"parent": "Illuminate\\Database\\Eloquent\\Model"}
    assert not [e for e in rows.edges if e.kind == "EXTENDS"]


def test_a_route_records_unreadable_middleware_as_a_count_not_as_a_node() -> None:
    """A sentinel is not a name: one node for '?' would merge unrelated routes' guards."""
    project = load_project(FIXTURE)
    rows = _rows(project)

    assert UNRESOLVED_MIDDLEWARE not in {n.fqn for n in rows.nodes}
    unreadable = [
        n
        for n in rows.nodes
        if n.kind == "route" and n.attrs and n.attrs.get("unresolved_middleware")
    ]
    assert unreadable, "the fixture registers ->middleware($extra); it should be counted"


# ─── Edges ───────────────────────────────────────────────────────────────────


def test_every_edge_lands_on_a_node_that_exists() -> None:
    """The graph's one structural invariant, and the one the foreign keys also enforce."""
    rows = _rows(load_project(FIXTURE))
    ids = {node.id for node in rows.nodes}

    for edge in rows.edges:
        assert edge.src_id in ids and edge.dst_id in ids, edge


def test_a_class_declares_its_methods_and_a_file_declares_its_classes() -> None:
    project = load_project(FIXTURE)
    rows = _rows(project)

    declares = [e for e in rows.edges if e.kind == "DECLARES"]
    methods = sum(len(info.methods) for info in project.classes.values())
    assert len(declares) == len(project.classes) + methods


def test_a_route_handles_its_action_and_is_protected_by_each_middleware() -> None:
    project = load_project(FIXTURE)
    rows = _rows(project)
    by_id = {node.id: node for node in rows.nodes}

    handled = {(by_id[e.src_id].attrs or {})["action"] for e in rows.edges if e.kind == "HANDLES"}
    assert handled == {r.action_fqn for r in project.routes if project.method(r.action_fqn)}

    guarded = Counter(by_id[e.src_id].fqn for e in rows.edges if e.kind == "PROTECTED_BY")
    for route in project.routes:
        named = [m for m in route.middleware if m != UNRESOLVED_MIDDLEWARE]
        assert guarded[f"{','.join(route.verbs)} {route.uri}"] == len(named)


def test_a_route_to_an_inherited_action_handles_the_real_method_node() -> None:
    project = _project_from(
        "<?php\nnamespace App;\n"
        "class Base { public function index() {} }\n"
        "class Child extends Base {}\n"
    )
    route_file = Path("routes/api.php")
    route_parsed = parse_source(
        route_file,
        b"<?php\nuse App\\Child;\nRoute::get('/child', [Child::class, 'index']);\n",
    )
    route_symbols = extract_symbols(route_parsed)

    project.files[route_file] = route_parsed
    project.symbols[route_file] = route_symbols
    project.routes.extend(extract_routes(route_parsed, route_symbols))
    project.digests[route_file] = "1" * 64

    rows = _rows(project)
    by_id = {node.id: node for node in rows.nodes}
    handled = [by_id[edge.dst_id].fqn for edge in rows.edges if edge.kind == "HANDLES"]
    assert handled == ["App\\Base::index"]


def test_a_call_through_a_typed_property_resolves_to_the_callee() -> None:
    """The Laravel controller shape: a repository injected in the constructor."""
    project = _project_from(
        "<?php\nnamespace App;\n"
        "class Repo { public function search($q) { return $q; } }\n"
        "class Controller {\n"
        "  public function __construct(private Repo $repo) {}\n"
        "  public function index() { return $this->repo->search('x'); }\n"
        "}\n"
    )
    rows = _rows(project)
    by_id = {node.id: node for node in rows.nodes}

    calls = [
        (by_id[e.src_id].fqn, by_id[e.dst_id].fqn, e.resolution)
        for e in rows.edges
        if e.kind == "CALLS"
    ]
    assert calls == [("App\\Controller::index", "App\\Repo::search", "property_type")]


def test_a_call_to_an_inherited_method_points_at_the_class_that_declares_it() -> None:
    """An edge must land on a node that exists, and a subclass has no node for what it inherits."""
    project = _project_from(
        "<?php\nnamespace App;\n"
        "class Base { public function run() {} }\n"
        "class Child extends Base { public function go() { $this->run(); } }\n"
    )
    rows = _rows(project)
    by_id = {node.id: node for node in rows.nodes}

    calls = [(by_id[e.src_id].fqn, by_id[e.dst_id].fqn) for e in rows.edges if e.kind == "CALLS"]
    assert calls == [("App\\Child::go", "App\\Base::run")]
    assert [e.kind for e in rows.edges if e.kind == "EXTENDS"] == ["EXTENDS"]


def test_a_trait_precedence_selects_the_declared_trait() -> None:
    project = _project_from(
        "<?php\nnamespace App;\n"
        "trait First { public function run() {} }\n"
        "trait Second { public function run() {} }\n"
        "class Child { use First, Second { First::run insteadof Second; }\n"
        "public function go() { $this->run(); } }\n"
    )
    rows = _rows(project)
    by_id = {node.id: node for node in rows.nodes}

    calls = [(by_id[e.src_id].fqn, by_id[e.dst_id].fqn) for e in rows.edges if e.kind == "CALLS"]
    assert calls == [("App\\Child::go", "App\\First::run")]


def test_a_trait_is_a_node_and_calls_land_on_its_method() -> None:
    project = _project_from(
        "<?php\nnamespace App;\n"
        "trait Shared { public function run() {} }\n"
        "class Child { use Shared; public function go() { $this->run(); } }\n"
    )
    rows = _rows(project)
    by_id = {node.id: node for node in rows.nodes}

    calls = [(by_id[e.src_id].fqn, by_id[e.dst_id].fqn) for e in rows.edges if e.kind == "CALLS"]
    assert calls == [("App\\Child::go", "App\\Shared::run")]
    assert [e.kind for e in rows.edges if e.kind == "USES_TRAIT"] == ["USES_TRAIT"]


def test_an_inheritance_cycle_terminates() -> None:
    """`class A extends B` and `class B extends A` both parse, so the walk must survive them."""
    project = _project_from(
        "<?php\nnamespace App;\n"
        "class A extends B { public function go() { $this->nope(); } }\n"
        "class B extends A {}\n"
    )
    rows = _rows(project)

    assert not [e for e in rows.edges if e.kind == "CALLS"]
    assert rows.unresolved_calls == 1


def test_a_call_that_cannot_be_resolved_is_counted_and_never_invented() -> None:
    """A missing edge is the accepted cost; a wrong one would be a false path."""
    project = _project_from(
        "<?php\nnamespace App;\nclass C { public function go($svc) { $svc->handle(); } }\n"
    )
    rows = _rows(project)

    assert not [e for e in rows.edges if e.kind == "CALLS"]
    assert rows.unresolved_calls == 1


def test_new_of_a_known_class_is_an_instantiates_edge() -> None:
    project = _project_from(
        "<?php\nnamespace App;\nclass Mailer {}\n"
        "class C { public function go() { return new Mailer(); } }\n"
    )
    rows = _rows(project)
    by_id = {node.id: node for node in rows.nodes}

    made = [
        (by_id[e.src_id].fqn, by_id[e.dst_id].fqn) for e in rows.edges if e.kind == "INSTANTIATES"
    ]
    assert made == [("App\\C::go", "App\\Mailer")]


# ─── Determinism and persistence ─────────────────────────────────────────────


def test_two_builds_of_the_same_project_are_identical() -> None:
    """Invariant 8. Dictionary insertion order is a directory walk's order, not a contract."""
    project = load_project(FIXTURE)
    assert _rows(project) == _rows(load_project(FIXTURE))


def test_a_scan_stores_the_graph(fixture_project: Path) -> None:
    workspace = Workspace.open(fixture_project)
    project = load_project(workspace.root)
    conn = connect(workspace)
    record_scan(conn, project, [], engine_version="0.0.1", ruleset_hash="rs1", duration_ms=1)

    stored = Counter(dict(conn.execute("SELECT kind, COUNT(*) FROM nodes GROUP BY kind")))
    assert stored["class"] == len(project.classes)
    assert stored["trait"] == len(project.traits)
    assert stored["method"] == sum(
        len(i.methods) for i in (*project.classes.values(), *project.traits.values())
    )
    assert stored["route"] == len(project.routes)
    assert conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0] > 0

    # Every node points at the file row for the file it was found in, not at a guess.
    orphans = conn.execute(
        "SELECT COUNT(*) FROM nodes n LEFT JOIN files f ON f.id = n.file_id "
        "WHERE n.file_id IS NOT NULL AND f.id IS NULL"
    ).fetchone()[0]
    assert orphans == 0


def test_rescanning_does_not_duplicate_the_graph(fixture_project: Path) -> None:
    """An edge has no identity of its own, so a second scan must replace and not append."""
    workspace = Workspace.open(fixture_project)
    project = load_project(workspace.root)
    conn = connect(workspace)

    def scan() -> tuple[int, int]:
        record_scan(conn, project, [], engine_version="0.0.1", ruleset_hash="rs1", duration_ms=1)
        return (
            conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0],
            conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0],
        )

    assert scan() == scan()


def test_the_graph_write_joins_the_scan_transaction(tmp_path: Path) -> None:
    """A scan that fails partway leaves no graph, not a graph with no scan to explain it."""
    workspace = Workspace.open(tmp_path)
    rel = Path("app/Example.php")
    (workspace.root / rel).parent.mkdir(parents=True)
    (workspace.root / rel).write_bytes(b"<?php\nnamespace App;\nclass Example {}\n")
    project = load_project(workspace.root)
    conn = connect(workspace)
    conn.execute("DROP TABLE evidence_paths")  # the last write record_scan makes

    with pytest.raises(sqlite3.Error):
        record_scan(
            conn,
            project,
            [_finding_touching(rel)],
            engine_version="0.0.1",
            ruleset_hash="rs1",
            duration_ms=1,
        )

    assert conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 0


def _finding_touching(rel: Path) -> Finding:
    span = Span(rel, 3, 0, 3, 5)
    return Finding(
        rule_id="php.sql-injection",
        severity="high",
        title="t",
        cwe=("CWE-89",),
        span=span,
        evidence_path=(PathStep("sink", span, "x", "", "php.sql-injection"),),
    )
