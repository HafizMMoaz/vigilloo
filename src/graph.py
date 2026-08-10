"""The project graph: files, symbols, classes and routes, in memory and as stored rows.

`load_project` builds the in-memory form the analyses walk. `graph_rows` turns that same
form into the `nodes` and `edges` of docs/04-knowledge-graph, which the store writes. Both
live here because they are one model in two shapes, and a second module deriving node
identity from the same Project would be a second place for the two to drift apart.
"""

import hashlib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING

from tree_sitter import Node

from .ids import node_id
from .laravel.blade import to_php
from .laravel.detect import Autoload, read_autoload
from .laravel.routes import UNRESOLVED_MIDDLEWARE, extract_routes
from .models import (
    Coverage,
    EdgeRow,
    EntryPoint,
    NodeRow,
    ParseFailure,
    Route,
    Span,
    Symbol,
    WalkStats,
)

if TYPE_CHECKING:
    from .summaries import FunctionSummary
from .parser import (
    ParsedFile,
    error_constructs,
    find_all,
    node_span,
    node_text,
    parse_php,
    parse_source,
)
from .symbols import ClassInfo, FileSymbols, extract_symbols, resolve_type_name
from .workspace import Workspace

_EXCLUDED_DIRS = {"vendor", "node_modules", "storage", "bootstrap", ".git"}


@dataclass(frozen=True)
class Project:
    root: Path
    files: dict[Path, ParsedFile] = field(default_factory=dict)
    symbols: dict[Path, FileSymbols] = field(default_factory=dict)
    classes: dict[str, ClassInfo] = field(default_factory=dict)
    traits: dict[str, ClassInfo] = field(default_factory=dict)
    routes: list[Route] = field(default_factory=list)
    entrypoints: list[EntryPoint] = field(default_factory=list)
    bindings: dict[str, list[str]] = field(default_factory=dict)
    blade: dict[Path, ParsedFile] = field(default_factory=dict)
    blade_lines: dict[Path, list[str]] = field(default_factory=dict)
    failed: list[Path] = field(default_factory=list)
    unparsed: list[Path] = field(default_factory=list)
    # The same parse failures as `unparsed`, one entry per broken construct
    # rather than one per file. Kept beside that list and not folded into it:
    # `unparsed` is the unit the parse rate divides by, so one file must stay
    # one element there however many of its methods broke. A file appears in
    # both, or in neither.
    parse_failures: list[ParseFailure] = field(default_factory=list)
    # sha256 of what was actually analysed, keyed like `files`/`blade`. Kept
    # separate from ParsedFile.source: for Blade that field holds the
    # rewritten PHP, not the template, so it is not a safe stand-in for the
    # template's own digest (docs/17-database, files.sha256 is "the
    # incrementality key" and store.py's coverage rows need the real one).
    digests: dict[Path, str] = field(default_factory=dict)
    # What composer.json says this project autoloads, and which of its mappings were
    # refused. Held on the Project rather than passed around because two consumers need
    # it at different times: name resolution while files are being read, and the CLI's
    # coverage caveats after they all have been.
    autoload: Autoload = field(default_factory=Autoload)
    summaries: dict[str, "FunctionSummary"] = field(default_factory=dict)

    def method(self, fqn: str) -> Symbol | None:
        """The method a call to `fqn` actually executes, or None if none does.

        `Child::handle` may be declared on `Child`, on a trait it composes, or on an
        ancestor, and the answer is the one node that owns the body - never a synthetic
        `Child::handle` that no file contains.
        """
        class_fqn, _, method_name = fqn.rpartition("::")
        return self._method(class_fqn, method_name, set())

    def _method(self, type_fqn: str, method_name: str, seen: set[tuple[str, str]]) -> Symbol | None:
        """Resolve PHP method precedence, returning only a declaration with a body.

        PHP looks in the class itself, then its composed traits, then its parent.
        A trait follows the same first two steps for traits it composes.

        Two rules here exist to avoid answers that look resolved and are not.

        An `abstract` declaration is a requirement and not an implementation, so it
        is stepped past rather than returned: `trait T { abstract function f(); }`
        composed into a class extending a base that defines `f` executes the base's
        body. Returning the abstract one would point the call graph at a bodyless
        declaration and end a taint walk with nothing to walk, which reads as a
        resolved call and hides whatever the real implementation does.

        Two traits providing the same method with no `insteadof` between them is a
        class PHP refuses to load, so None is returned rather than a pick. That is
        also why `insteadof` is stored as exclusions: it names the traits that lose,
        and a class using a third trait that no clause excludes still collides.
        """
        key = (type_fqn, method_name)
        if key in seen:
            return None
        seen.add(key)

        info = self.classes.get(type_fqn) or self.traits.get(type_fqn)
        if info is None:
            return None

        own = info.methods.get(method_name)
        if own is not None and method_name not in info.abstract_methods:
            return own

        alias = info.trait_aliases.get(method_name)
        if alias is not None:
            trait_fqn, original = alias
            if trait_fqn:
                return self._method(trait_fqn, original, seen)
            candidates = self._trait_candidates(info, original, seen)
            return candidates[0] if len(candidates) == 1 else None

        candidates = self._trait_candidates(info, method_name, seen)
        if len(candidates) == 1:
            return candidates[0]
        if len(candidates) > 1:
            # An unresolved collision. PHP would not load this class, so there is no
            # call to describe and picking one would invent a path through code that
            # cannot run.
            return None

        if type_fqn in self.classes and info.parent is not None:
            return self._method(info.parent, method_name, seen)
        return None

    def _trait_candidates(
        self, info: ClassInfo, method_name: str, seen: set[tuple[str, str]]
    ) -> list[Symbol]:
        """The distinct implementations this type's composed traits offer for a method.

        Sorted by FQN so a collision that a caller reports is the same one every run
        (invariant 8), and keyed by FQN so two traits that both compose the same third
        trait count once rather than as a conflict with itself.

        Each branch gets its own copy of `seen`: the set exists to stop a cycle from
        recursing forever, and sharing one across sibling traits would let the first
        branch visited mark a type as seen and silently blank the second.
        """
        excluded = info.trait_exclusions.get(method_name, frozenset())
        candidates: dict[str, Symbol] = {}
        for trait_fqn in info.traits:
            if trait_fqn in excluded:
                continue
            found = self._method(trait_fqn, method_name, set(seen))
            if found is not None:
                candidates[found.fqn] = found
        return [candidates[fqn] for fqn in sorted(candidates)]

    def ancestry(self, class_fqn: str) -> tuple[list[str], bool]:
        """The known ancestor chain of a class, and whether it is complete.

        Returns the classes from `class_fqn` upward that this project contains, and a flag
        that is True only when the chain ended at a class declaring no parent. False means it
        ran off the edge of the project - `extends Model` - so there are ancestors above the
        last entry that were never parsed.

        That flag is the difference between two things that look identical at a call site and
        mean opposite things. `Post::find` is not on `App\\Models\\Post`, and the chain leaving
        the project says why: `find` is Eloquent's, in `vendor/`, which `load_project` excludes
        by design and no better name resolution will ever reach. A method missing from a chain
        that stays inside the project is the other case - the code is here and the walk failed
        to reach it - and only that one is a coverage gap worth reporting.

        The `seen` set is not defensive padding: `class A extends B` and `class B extends A`
        both parse, and the symbol table records exactly what it read, so this must terminate
        on input the parser accepts.
        """
        chain: list[str] = []
        seen: set[str] = set()
        current: str | None = class_fqn
        while current is not None and current not in seen:
            info = self.classes.get(current)
            if info is None:
                return chain, False
            seen.add(current)
            chain.append(current)
            current = info.parent
        # A cycle is not a complete chain: the ancestors above it are unknowable, not absent.
        return chain, current is None

    def method_node(self, fqn: str) -> tuple[Node, ParsedFile] | None:
        """The syntax node of a method's declaration, and the file it lives in.

        Symbol carries a span, not a node, so any analysis that needs to read a
        method's body has to find it again. That lookup belongs here rather than
        in one analysis: the taint walk and the structural rules both need it,
        and a second private copy would be a second place to get the matching
        wrong.
        """
        symbol = self.method(fqn)
        if symbol is None:
            return None
        parsed = self.files.get(symbol.span.file)
        if parsed is None:
            return None
        for method in find_all(parsed.tree.root_node, "method_declaration"):
            # The whole span, not its first line. Two declarations can share a line -
            # `trait T { function a() {} } class C { use T; function b() {} }` is one
            # line of perfectly ordinary PHP - and matching on the line alone would
            # hand back a different method's body while every counter reported success.
            if node_span(method, parsed.path) == symbol.span:
                return method, parsed
        return None

    def resolve_property_type(self, class_fqn: str, prop: str) -> str | None:
        """The declared class of a property, wherever in the hierarchy it is declared.

        A property declared on a base class or supplied by a trait is as real as one
        declared locally, and `$this->repo->find($x)` has to resolve through it.
        """
        return self._property_type(class_fqn, prop, set())

    def _property_type(self, type_fqn: str, prop: str, seen: set[str]) -> str | None:
        if type_fqn in seen:
            return None
        seen.add(type_fqn)
        info = self.classes.get(type_fqn) or self.traits.get(type_fqn)
        if info is None:
            return None
        own = info.properties.get(prop)
        if own is not None:
            return own
        for trait_fqn in info.traits:
            found = self._property_type(trait_fqn, prop, seen)
            if found is not None:
                return found
        if type_fqn in self.classes and info.parent is not None:
            return self._property_type(info.parent, prop, seen)
        return None

    def resolve_class_name(self, file: Path, written: str) -> str | None:
        """Resolve a class name as written in `file` to its FQN.

        `User::create(...)` names the class at the call site, so this is all
        the resolution a static call needs - no receiver type inference.
        Returns None when the file has no symbol table, rather than guessing a
        global-namespace name that would not match any known class.
        """
        syms = self.symbols.get(file)
        if syms is None:
            return None
        return resolve_type_name(written, syms.namespace, syms.imports, self.autoload.prefixes)

    def blade_line(self, path: Path, line: int) -> str:
        """The original Blade text of a 1-indexed line, for evidence snippets.

        Findings must quote what the developer wrote, not the PHP it was
        rewritten into. Out-of-range lines return empty rather than raising:
        a snippet is presentation, and it must never be able to abort a scan.
        """
        lines = self.blade_lines.get(path, [])
        if 1 <= line <= len(lines):
            return lines[line - 1].strip()
        return ""


def _php_files(root: Path) -> list[Path]:
    found = [
        p
        for p in root.rglob("*.php")
        if not (_EXCLUDED_DIRS & set(p.relative_to(root).parts))
        and not p.name.endswith(".blade.php")
    ]
    return sorted(found)  # sorted for determinism


def _blade_files(root: Path) -> list[Path]:
    found = [
        p
        for p in root.rglob("*.blade.php")
        if not (_EXCLUDED_DIRS & set(p.relative_to(root).parts))
    ]
    return sorted(found)  # sorted for determinism


def load_project(root: Path, stats: WalkStats | None = None) -> Project:
    # Read before any file is parsed: the autoload map is what tells the symbol layer
    # which written names are already fully qualified, so it has to exist before the
    # first symbol table is built. `Workspace.at` rather than `.open` because loading a
    # project reads and must not create `.vigilloo/` in a tree nobody asked to scan.
    from .laravel.container import extract_bindings
    from .laravel.entrypoints import find_entrypoints

    autoload = read_autoload(Workspace.at(root))
    autoload_roots = autoload.prefixes
    project = Project(root=root, autoload=autoload)

    for path in _php_files(root):
        try:
            parsed = parse_php(path)
        except OSError:
            project.failed.append(path)
            continue

        # Store paths relative to the project root, not however the caller
        # spelled it. Span.file feeds Finding.id/.fingerprint (models.py), so
        # `vigilloo scan .` and `vigilloo scan /abs/path` must produce the
        # same identities for the same code, or every suppression baseline
        # silently stops matching depending on which form CI happened to use.
        rel_path = path.relative_to(root)
        parsed = replace(parsed, path=rel_path)
        project.digests[rel_path] = hashlib.sha256(parsed.source).hexdigest()

        # A syntax error degrades this file, it never aborts the scan - but
        # the gap in coverage must still be visible, so it is recorded even
        # though whatever symbols could be extracted are kept and used. The
        # constructs are collected here, where the path is already relative to
        # the root, so the failures carry the same file spelling as every span
        # and no second normalisation can drift from the one above.
        if parsed.has_errors:
            project.unparsed.append(rel_path)
            project.parse_failures.extend(error_constructs(parsed))

        project.files[rel_path] = parsed
        syms = extract_symbols(parsed, autoload_roots)
        project.symbols[rel_path] = syms
        project.classes.update(syms.classes)
        project.traits.update(syms.traits)

        file_bindings = extract_bindings(parsed, syms, autoload_roots)
        for interface, implementations in file_bindings.items():
            project.bindings.setdefault(interface, []).extend(implementations)

    from .laravel.middleware import extract_middleware_groups
    from .laravel.routes import discover_route_files
    
    middleware_groups = {}
    for rel_path, parsed in project.files.items():
        path_str = str(rel_path).replace("\\\\", "/")
        if path_str.endswith("app/Http/Kernel.php") or path_str.endswith("bootstrap/app.php"):
            middleware_groups.update(extract_middleware_groups(parsed))

    route_paths = discover_route_files(project.files)
    for rel_path in route_paths:
        parsed = project.files.get(rel_path)
        if parsed:
            syms = project.symbols.get(rel_path)
            if syms is not None:
                project.routes.extend(extract_routes(parsed, syms, stats, middleware_groups))

    for path in _blade_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            project.failed.append(path)
            continue

        rel_path = path.relative_to(root)
        project.digests[rel_path] = hashlib.sha256(text.encode("utf-8")).hexdigest()
        parsed = parse_source(rel_path, to_php(text).encode("utf-8"))

        # A template that will not parse degrades this file, never the scan.
        # The constructs come from the rewritten PHP rather than the template,
        # so a Blade failure usually lands on the file rather than on a name -
        # a template has no methods to name unless the author wrote one in a
        # @php block, and that one is genuinely theirs.
        if parsed.has_errors:
            project.unparsed.append(rel_path)
            project.parse_failures.extend(error_constructs(parsed))

        project.blade[rel_path] = parsed
        project.blade_lines[rel_path] = text.splitlines()

    project.routes.sort(key=lambda r: (str(r.span.file), r.span.start_line))
    project.entrypoints.extend(find_entrypoints(project))
    project.entrypoints.sort(key=lambda ep: (str(ep.span.file), ep.span.start_line))

    return project


@dataclass(frozen=True)
class GraphRows:
    """One project's graph, flattened into storable rows.

    `unresolved_calls` counts call sites this builder could not turn into an edge. It is
    deliberately *not* folded into `Coverage`: the taint walk already counts the calls it
    followed, over a different denominator, and adding a second producer to the same rate
    would move the number that docs/22-testing gates in CI without any analysis having
    changed. It is reported here so a caller can see the gap and a test can assert on it.
    """

    nodes: list[NodeRow]
    edges: list[EdgeRow]
    unresolved_calls: int = 0


# Node kinds are lowercase and edge kinds uppercase, following the tables in
# docs/04-knowledge-graph. Only the layers this slice can honestly populate appear: the AST,
# control-flow and data-flow layers named there have no rows here, because inventing an
# approximate `FLOWS_TO` would be worse than an absent one.
_KIND_FILE = "file"
_KIND_CLASS = "class"
_KIND_TRAIT = "trait"
_KIND_METHOD = "method"
_KIND_ROUTE = "route"
_KIND_MIDDLEWARE = "middleware"

_CALL_NODES = ("member_call_expression", "scoped_call_expression")


def graph_rows(project: Project, project_id: int, file_ids: dict[Path, int]) -> GraphRows:
    """Flatten a Project into the nodes and edges of docs/04-knowledge-graph.

    `project_id` namespaces node identity and `file_ids` maps each relative path to its
    `files` row, so both come from the store rather than being derived here - the store owns
    those two numbers and this function must agree with it rather than guess.

    Everything is emitted in sorted order. Invariant 8 makes byte-identical output the
    contract, and an export or a report reading these rows back would otherwise inherit
    dictionary insertion order, which is the parse order of a directory walk.
    """
    builder = _RowBuilder(project, project_id, file_ids)
    builder.add_files()
    builder.add_classes_and_methods()
    builder.add_routes()
    builder.add_calls()
    return GraphRows(builder.nodes, builder.edges, builder.unresolved_calls)


class _RowBuilder:
    """Accumulates rows for one project. A class only to avoid threading six lists around."""

    def __init__(self, project: Project, project_id: int, file_ids: dict[Path, int]) -> None:
        self.project = project
        self.project_id = project_id
        self.file_ids = file_ids
        self.nodes: list[NodeRow] = []
        self.edges: list[EdgeRow] = []
        self.unresolved_calls = 0

    def _id(self, kind: str, fqn: str) -> str:
        return node_id(self.project_id, kind, fqn)

    def add_files(self) -> None:
        """One node per file the scan discovered, unreadable ones included.

        A file that could not be read is still a file in the project, and dropping it here
        would make the graph quietly disagree with the `files` table and with the coverage
        report beside it (invariant 4).
        """
        for rel_path in sorted(self.file_ids):
            self.nodes.append(
                NodeRow(
                    id=self._id(_KIND_FILE, rel_path.as_posix()),
                    kind=_KIND_FILE,
                    name=rel_path.name,
                    fqn=rel_path.as_posix(),
                    file_id=self.file_ids[rel_path],
                )
            )

    def add_classes_and_methods(self) -> None:
        for fqn in sorted(self.project.classes):
            info = self.project.classes[fqn]
            class_id = self._id(_KIND_CLASS, fqn)
            self.nodes.append(
                NodeRow(
                    id=class_id,
                    kind=_KIND_CLASS,
                    name=fqn.rsplit("\\", 1)[-1],
                    fqn=fqn,
                    file_id=self.file_ids.get(info.span.file),
                    **_span_columns(info.span),
                    # The parent name is kept even when it resolves to no node of ours,
                    # because `extends Model` is precisely how the Laravel rules recognise an
                    # Eloquent model, and that fact would otherwise vanish with the edge.
                    attrs=None if info.parent is None else {"parent": info.parent},
                )
            )
            self._declares(self._id(_KIND_FILE, info.span.file.as_posix()), class_id)

            if info.parent is not None and info.parent in self.project.classes:
                self.edges.append(EdgeRow(class_id, self._id(_KIND_CLASS, info.parent), "EXTENDS"))

            for trait_fqn in info.traits:
                if trait_fqn in self.project.traits:
                    self.edges.append(
                        EdgeRow(class_id, self._id(_KIND_TRAIT, trait_fqn), "USES_TRAIT")
                    )

            for name in sorted(info.methods):
                symbol = info.methods[name]
                method_id = self._id(_KIND_METHOD, symbol.fqn)
                self.nodes.append(
                    NodeRow(
                        id=method_id,
                        kind=_KIND_METHOD,
                        name=name,
                        fqn=symbol.fqn,
                        file_id=self.file_ids.get(symbol.span.file),
                        **_span_columns(symbol.span),
                        attrs={"params": list(symbol.params)},
                    )
                )
                self._declares(class_id, method_id)

        for fqn in sorted(self.project.traits):
            info = self.project.traits[fqn]
            trait_id = self._id(_KIND_TRAIT, fqn)
            self.nodes.append(
                NodeRow(
                    id=trait_id,
                    kind=_KIND_TRAIT,
                    name=fqn.rsplit("\\", 1)[-1],
                    fqn=fqn,
                    file_id=self.file_ids.get(info.span.file),
                    **_span_columns(info.span),
                    attrs=None,
                )
            )
            self._declares(self._id(_KIND_FILE, info.span.file.as_posix()), trait_id)
            for used_fqn in info.traits:
                if used_fqn in self.project.traits:
                    self.edges.append(
                        EdgeRow(trait_id, self._id(_KIND_TRAIT, used_fqn), "USES_TRAIT")
                    )
            for name in sorted(info.methods):
                symbol = info.methods[name]
                method_id = self._id(_KIND_METHOD, symbol.fqn)
                self.nodes.append(
                    NodeRow(
                        id=method_id,
                        kind=_KIND_METHOD,
                        name=name,
                        fqn=symbol.fqn,
                        file_id=self.file_ids.get(symbol.span.file),
                        **_span_columns(symbol.span),
                        attrs={"params": list(symbol.params)},
                    )
                )
                self._declares(trait_id, method_id)

    def add_routes(self) -> None:
        """Route nodes, plus the two framework edges a structural rule traverses.

        `HANDLES` to the controller action and `PROTECTED_BY` to each middleware are the
        edges docs/04-knowledge-graph names for the query "which routes reach a sink without
        authentication", which is where the Laravel value concentrates.
        """
        middleware_seen: set[str] = set()
        for route in self.project.routes:
            fqn = _route_fqn(route)
            route_id = self._id(_KIND_ROUTE, fqn)
            named = [n for n in route.middleware if n != UNRESOLVED_MIDDLEWARE]
            self.nodes.append(
                NodeRow(
                    id=route_id,
                    kind=_KIND_ROUTE,
                    name=route.uri,
                    fqn=fqn,
                    file_id=self.file_ids.get(route.span.file),
                    **_span_columns(route.span),
                    attrs={
                        "uri": route.uri,
                        "verbs": list(route.verbs),
                        "action": route.action_fqn,
                        # `->middleware($extra)`: the route table knows something guards this
                        # route and not what. It is counted here rather than given a node,
                        # because `UNRESOLVED_MIDDLEWARE` is a sentinel and not a name - one
                        # node for it would make every unreadable middleware in the project
                        # the same node, and a traversal would then read two unrelated routes
                        # as sharing a guard. A count says "N guards I could not read", which
                        # is the truth, and leaves the route reading as unprotected, which is
                        # the direction structural.py already errs in.
                        "unresolved_middleware": len(route.middleware) - len(named),
                    },
                )
            )

            action = self.project.method(route.action_fqn)
            if action is not None:
                self.edges.append(EdgeRow(route_id, self._id(_KIND_METHOD, action.fqn), "HANDLES"))

            for name in named:
                mw_id = self._id(_KIND_MIDDLEWARE, name)
                if name not in middleware_seen:
                    middleware_seen.add(name)
                    # ponytail: a middleware node is the string the route table names, not the
                    # class that implements it. `auth` and `App\Http\Middleware\Authenticate`
                    # are one thing and this graph holds two, so no edge reaches the
                    # middleware's own code. Ceiling: a rule cannot ask what a middleware
                    # *does*, only what a route is labelled with - enough for the
                    # auth/authorization rules that read the label. Upgrade trigger: the
                    # middleware alias map from app/Http/Kernel.php, which is where the
                    # string-to-class resolution lives (docs/08-framework-adapters).
                    self.nodes.append(NodeRow(id=mw_id, kind=_KIND_MIDDLEWARE, name=name, fqn=name))
                self.edges.append(EdgeRow(route_id, mw_id, "PROTECTED_BY"))

    def add_calls(self) -> None:
        """`CALLS` and `INSTANTIATES` edges, for the call sites that resolve statically.

        One pass per file rather than one lookup per method: `Project.method_node` rescans a
        whole file to find one declaration, and doing that per method is quadratic in the
        file's method count for no gain when the walk is already standing on the tree.

        ponytail: plain `function_call_expression` is skipped entirely, so `e($x)` and a call
        to a project-level function look identical here - neither produces an edge. There are
        no function nodes in this graph yet, only methods, so every such call would resolve to
        nothing. Counting them as unresolved would be worse than skipping them: the overwhelming
        majority are PHP builtins and Laravel helpers with no node to point at, and a gap
        number that is mostly `count()` is one nobody reads. Upgrade trigger: function nodes,
        which arrive with docs/07-call-graph in Milestone F alongside the facade map.
        """
        for rel_path, parsed in sorted(self.project.files.items()):
            syms = self.project.symbols.get(rel_path)
            if syms is None:
                continue
            for cls in find_all(parsed.tree.root_node, "class_declaration"):
                name_node = cls.child_by_field_name("name")
                if name_node is None:
                    continue
                short = node_text(name_node, parsed.source)
                class_fqn = f"{syms.namespace}\\{short}" if syms.namespace else short
                for method in find_all(cls, "method_declaration"):
                    m_name = method.child_by_field_name("name")
                    if m_name is None:
                        continue
                    caller = f"{class_fqn}::{node_text(m_name, parsed.source)}"
                    self._calls_from(method, parsed, class_fqn, caller)
            for trait in find_all(parsed.tree.root_node, "trait_declaration"):
                name_node = trait.child_by_field_name("name")
                if name_node is None:
                    continue
                short = node_text(name_node, parsed.source)
                trait_fqn = f"{syms.namespace}\\{short}" if syms.namespace else short
                # ponytail: a trait's body is walked with the trait itself as the
                # receiver, so `$this->consumerMethod()` inside a trait resolves only
                # when the trait supplies that method too. In PHP `$this` there is
                # whichever class composed the trait, and a trait used by four classes
                # has four answers - emitting an edge per consumer would multiply one
                # call site into four claims, and picking one would be a guess. Such
                # calls are counted in `unresolved_calls` rather than invented, which
                # is the same direction every other unresolvable receiver takes here.
                # The taint walk does carry the consuming class, so a *path* through a
                # trait is followed even where this edge is absent. Upgrade trigger: a
                # per-consumer call layer, which needs edges that can say which
                # composition they belong to (docs/07-call-graph, `RESOLVES_TO`).
                for method in find_all(trait, "method_declaration"):
                    m_name = method.child_by_field_name("name")
                    if m_name is None:
                        continue
                    caller = f"{trait_fqn}::{node_text(m_name, parsed.source)}"
                    self._calls_from(method, parsed, trait_fqn, caller)

    def _calls_from(
        self, method: Node, parsed: ParsedFile, class_fqn: str, caller_fqn: str
    ) -> None:
        src_id = self._id(_KIND_METHOD, caller_fqn)

        # Constructor injection resolution
        if caller_fqn.endswith("::__construct"):
            symbol = self.project.method(caller_fqn)
            if symbol is not None:
                for param_type in symbol.param_types:
                    if param_type in self.project.bindings:
                        candidates = self.project.bindings[param_type]
                        confidence = 0.9 if len(candidates) == 1 else 0.6 / len(candidates)
                        for candidate in candidates:
                            self.edges.append(
                                EdgeRow(
                                    src_id,
                                    self._id(_KIND_CLASS, candidate),
                                    "RESOLVES_TO",
                                    confidence=confidence,
                                    resolution="container",
                                )
                            )

        for node in find_all(method, "object_creation_expression"):
            target = _resolved_class(self.project, parsed, node)
            if target is None:
                self.unresolved_calls += 1
                continue
            self.edges.append(
                EdgeRow(src_id, self._id(_KIND_CLASS, target), "INSTANTIATES", resolution="static")
            )

        for node in find_all(method, "function_call_expression"):
            target = _container_resolved_class(self.project, parsed, node)
            if target and target in self.project.bindings:
                candidates = self.project.bindings[target]
                confidence = 0.9 if len(candidates) == 1 else 0.6 / len(candidates)
                for candidate in candidates:
                    self.edges.append(
                        EdgeRow(
                            src_id,
                            self._id(_KIND_CLASS, candidate),
                            "RESOLVES_TO",
                            confidence=confidence,
                            resolution="container",
                        )
                    )

        for node in find_all(method, "scoped_call_expression"):
            target = _container_resolved_class(self.project, parsed, node)
            if target and target in self.project.bindings:
                candidates = self.project.bindings[target]
                confidence = 0.9 if len(candidates) == 1 else 0.6 / len(candidates)
                for candidate in candidates:
                    self.edges.append(
                        EdgeRow(
                            src_id,
                            self._id(_KIND_CLASS, candidate),
                            "RESOLVES_TO",
                            confidence=confidence,
                            resolution="container",
                        )
                    )

        for kind in _CALL_NODES:
            for node in find_all(method, kind):
                resolved = self._call_targets(node, parsed, class_fqn)
                if not resolved:
                    self.unresolved_calls += 1
                    continue
                for target_fqn, resolution, confidence in resolved:
                    self.edges.append(
                        EdgeRow(
                            src_id,
                            self._id(_KIND_METHOD, target_fqn),
                            "CALLS",
                            confidence=confidence,
                            resolution=resolution,
                        )
                    )

    def _call_targets(
        self, call: Node, parsed: ParsedFile, class_fqn: str
    ) -> list[tuple[str, str, float]]:
        """The methods a call reaches, how it was resolved, and its confidence.

        Returns an empty list if it could not be resolved.
        """
        name_node = call.child_by_field_name("name")
        if name_node is None:
            return []
        method_name = node_text(name_node, parsed.source)

        receiver: str | None = None
        how: str = ""
        confidence = 1.0

        if call.type == "scoped_call_expression":
            scope = call.child_by_field_name("scope")
            if scope is None:
                return []
            written = node_text(scope, parsed.source)
            if written in ("self", "static"):
                receiver, how = class_fqn, "self"
            elif written == "parent":
                info = self.project.classes.get(class_fqn)
                receiver, how = (info.parent if info else None), "parent"
            elif scope.type in ("name", "qualified_name"):
                receiver = self.project.resolve_class_name(parsed.path, written)
                how = "static"
        else:
            obj = call.child_by_field_name("object")
            if obj is None:
                return []
            if obj.type == "variable_name" and node_text(obj, parsed.source) == "$this":
                receiver, how = class_fqn, "self"
            elif obj.type == "member_access_expression":
                # `$this->service->handle()`: the property's declared type names the class,
                # so this is still a stated fact rather than an inference. Any other receiver
                # would need to know what an expression evaluates to, which this layer does not.
                inner = obj.child_by_field_name("object")
                prop = obj.child_by_field_name("name")
                if (
                    inner is not None
                    and prop is not None
                    and node_text(inner, parsed.source) == "$this"
                ):
                    receiver = self.project.resolve_property_type(
                        class_fqn, node_text(prop, parsed.source)
                    )
                    how = "property_type"
                    confidence = 0.95

        if receiver is not None:
            candidates = self.project.bindings.get(receiver, [receiver])
            if receiver in self.project.bindings:
                confidence = 0.9 if len(candidates) == 1 else 0.6 / len(candidates)

            results = []
            for candidate in candidates:
                target = self.project.method(f"{candidate}::{method_name}")
                if target is not None:
                    results.append((target.fqn, how, confidence))
            return results

        # Duck typing fallback
        candidates = []
        for cls_fqn in self.project.classes:
            if self.project.method(f"{cls_fqn}::{method_name}") is not None:
                candidates.append(cls_fqn)

        if not candidates:
            return []

        confidence = 0.4 if len(candidates) == 1 else 0.4 / len(candidates)
        results = []
        for candidate in candidates:
            target = self.project.method(f"{candidate}::{method_name}")
            if target is not None:
                results.append((target.fqn, "duck_type", confidence))
        return results

    def _declares(self, parent_id: str, child_id: str) -> None:
        self.edges.append(EdgeRow(parent_id, child_id, "DECLARES"))


class NodeLocator:
    """Maps a source position to the innermost graph node covering it.

    This is what makes a finding's evidence path a walk over the graph rather than a list of
    line numbers (invariant 2). Each step already knows its file and line; this turns that
    into the id of the method, class or route it happened inside, so a reader can ask what
    else touches that node instead of only what the report chose to print.

    Innermost wins, so a step inside a method resolves to the method and not to the class
    around it - and a step on a class body line that is in no method, like the `$guarded = []`
    a mass-assignment finding points at, correctly resolves to the class. Anything covered by
    nothing falls back to the file node, which is still a real position and never a guess.
    """

    def __init__(self, rows: GraphRows) -> None:
        self._files: dict[Path, str] = {}
        self._spans: dict[Path, list[tuple[int, int, str]]] = {}

        # One pass to learn what each file_id is called, then one pass to place the rest. The
        # obvious alternative - searching the node list for each node's file - is quadratic,
        # and docs/17-database section "Scale" expects ~10M nodes at 1M LOC.
        paths: dict[int, Path] = {}
        for node in rows.nodes:
            if node.kind == _KIND_FILE and node.file_id is not None:
                path = Path(node.fqn or "")
                paths[node.file_id] = path
                self._files[path] = node.id

        for node in rows.nodes:
            if node.kind == _KIND_FILE or node.file_id is None:
                continue
            if node.start_line is None or node.end_line is None:
                continue
            path = paths.get(node.file_id, Path(""))
            self._spans.setdefault(path, []).append((node.start_line, node.end_line, node.id))

    def at(self, file: Path, line: int) -> str | None:
        best: tuple[int, str] | None = None
        for start, end, candidate_id in self._spans.get(file, ()):
            if start <= line <= end:
                # The id breaks a tie, so two nodes of equal width over the same line always
                # resolve the same way. Iteration order would not be a promise; the id is.
                candidate = (end - start, candidate_id)
                if best is None or candidate < best:
                    best = candidate
        return best[1] if best else self._files.get(file)


def _route_fqn(route: Route) -> str:
    """`GET,POST /orders/{id}` - a route's identity is its verbs and its URI together.

    Two registrations of the same URI under different verbs are two routes with two
    middleware stacks, and collapsing them onto one node would let a rule read the wrong
    stack for a request.
    """
    return f"{','.join(route.verbs)} {route.uri}"


def _span_columns(span: Span) -> dict[str, int]:
    return {
        "start_line": span.start_line,
        "start_col": span.start_col,
        "end_line": span.end_line,
        "end_col": span.end_col,
    }


def _resolved_class(project: Project, parsed: ParsedFile, creation: Node) -> str | None:
    for child in creation.children:
        if child.type in ("name", "qualified_name"):
            resolved = project.resolve_class_name(parsed.path, node_text(child, parsed.source))
            return resolved if resolved in project.classes else None
    return None


def _container_resolved_class(project: Project, parsed: ParsedFile, node: Node) -> str | None:
    source = parsed.source
    if node.type == "function_call_expression":
        name_node = node.child_by_field_name("function")
        if name_node and node_text(name_node, source) in ("app", "resolve"):
            args = node.child_by_field_name("arguments")
            if args:
                first_arg = next((c for c in args.named_children if c.type == "argument"), None)
                if first_arg and first_arg.children:
                    expr = first_arg.children[0]
                    if expr.type == "class_constant_access_expression":
                        cls_node = expr.children[0]
                        if cls_node:
                            return project.resolve_class_name(
                                parsed.path, node_text(cls_node, source)
                            )
                    elif expr.type == "string":
                        val = node_text(expr, source)
                        if val.startswith("'") and val.endswith("'"):
                            return val[1:-1].replace("\\\\", "\\")
                        elif val.startswith('"') and val.endswith('"'):
                            return val[1:-1].replace("\\\\", "\\")
    elif node.type == "scoped_call_expression":
        scope = node.child_by_field_name("scope")
        if scope and scope.type in ("name", "qualified_name") and node_text(scope, source) == "App":
            name_node = node.child_by_field_name("name")
            if name_node and node_text(name_node, source) == "make":
                args = node.child_by_field_name("arguments")
                if args:
                    first_arg = next((c for c in args.named_children if c.type == "argument"), None)
                    if first_arg and first_arg.children:
                        expr = first_arg.children[0]
                        if expr.type == "class_constant_access_expression":
                            cls_node = expr.children[0]
                            if cls_node:
                                return project.resolve_class_name(
                                    parsed.path, node_text(cls_node, source)
                                )
    return None


def coverage(project: Project, stats: WalkStats) -> Coverage:
    """Measure what this scan could see, from what the scan already recorded.

    Both halves are counted where they happen and only totalled here: the
    parse half from the project's own file lists, the resolution half from the
    walk's counter. A second pass over the tree to count files again could
    disagree with the lists the analysis actually used, and a coverage number
    that does not describe the analysis it is printed beside is worse than none.

    Every discovered file is in exactly one of three states - parsed, parsed
    with syntax errors, or unreadable - so the three counts sum to the total.
    `failed` holds files that could not be read at all and are therefore absent
    from `files` and `blade`; `unparsed` holds files that were read, kept and
    analysed as far as their syntax allowed, so they are present in both.

    The failure detail is carried through sorted and deduplicated, and it is
    only detail: every count above still comes from a file list, so naming the
    broken methods cannot move either rate by so much as one file.
    """
    read = len(project.files) + len(project.blade)
    return Coverage(
        files_discovered=read + len(project.failed),
        files_unreadable=len(project.failed),
        files_with_errors=len(project.unparsed),
        calls_resolved=stats.resolved,
        calls_unresolved=stats.unresolved,
        parse_failures=tuple(sorted(set(project.parse_failures))),
    )
