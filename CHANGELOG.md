# Changelog

All notable changes to Vigilloo are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) per
[docs/23-dev-guide](docs/23-dev-guide/README.md) section "Commits and releases". The CLI and the
SDK version independently: an SDK major bump breaks plugins and is always deliberate.

**Rule IDs are permanent public API** (invariant 7 in [CLAUDE.md](CLAUDE.md)). They ship in
users' SARIF, baselines and `// vigilloo-ignore` comments, so renaming one un-suppresses
findings in every codebase using it. Every rule added or removed is announced here, by ID.

**Every released version records its ruleset hash**, so a scan result stays reproducible against
the ruleset that produced it. The hash covers the rule table, sorted by ID
(`vigilloo.rules.RULESET_HASH`), and is written into every `scans` row.

## [Unreleased]

`pyproject.toml` is at `0.0.1` and nothing has been tagged or published, so `0.0.1` has never
been released and gets no dated heading. Everything below is the work accumulated toward it,
backfilled from git history one entry per merged slice. Fix commits inside a slice are folded
into that slice's entry: there was no release for them to be fixes against.

Ruleset hash: `520914c8731f4c0d`.

### Added

- **Slice 1 - the first vertical slice** (PR #1, plan
  [`docs/plans/2026-07-25-first-vertical-slice.md`](docs/plans/2026-07-25-first-vertical-slice.md)).
  A thin cut through every layer of the pipeline: an error-tolerant tree-sitter PHP parser,
  symbol extraction with fully-qualified names and constructor-injected property types, a Laravel
  route table with resolved controller actions, an in-memory project graph with call resolution,
  an interprocedural taint engine that records each step it walks, and the `vigilloo scan`
  command that prints the evidence path. Coverage (parse failures, unresolved call sites) is
  reported in every run.
  - New rule `php.sql-injection` (critical, CWE-89). Argument-precise: `whereRaw('age > ?', [$age])`
    is not a finding, `whereRaw("age > $age")` is.

- **Slice 2 - kind-based taint and XSS through Blade** (PR #1 from `slice-2-xss`, design
  [`docs/plans/2026-07-26-slice-2-design.md`](docs/plans/2026-07-26-slice-2-design.md)). Taint
  became kind-based rather than boolean, with a sanitizer table: `e()` clears `html` and leaves
  `sql` alone. Blade templates are rewritten into line-preserving PHP, loaded into the project
  graph, and reached through `view()` calls resolved to their template and bound variables, so an
  evidence path now runs from a route through a controller into a `.blade.php` file.
  - New rule `php.xss` (high, CWE-79). Fires on a raw echo `{!! !!}`; the same value rendered
    through `{{ }}` produces nothing, which is what distinguishes kind-based taint from a flag.

- **Slice 3 - mass assignment** (PR #2 from `slice-3-mass-assignment`, design
  [`docs/plans/2026-07-26-slice-3-design.md`](docs/plans/2026-07-26-slice-3-design.md)). The
  first framework-structural rule, needing the route table, the call graph and an Eloquent
  model's `$fillable` / `$guarded` configuration together, from three files. Adds the
  `mass_assign` taint kind, under which `$request->only([...])` and `->validated()` are safe to
  mass-assign and still dangerous to print. `PathStep` now carries the rule its sink matched, so
  rules are dispatched on the walk's own verdict rather than on the sink's file extension. A
  model declaring neither property is read as guarded, matching Eloquent's own default.
  - New rule `laravel.mass-assignment` (high, CWE-915). Covers static and instance writes and the
    `force*` bypasses; a narrow `$fillable` produces nothing.

- **Slice 4 - IDOR on model-bound routes** (PR #3 from `slice-4-idor`, design
  [`docs/plans/2026-07-26-slice-4-design.md`](docs/plans/2026-07-26-slice-4-design.md)). Routes
  now collect their real middleware stack, walking out through the registration chain to any
  enclosing `->group(...)`; middleware that is not a string literal is recorded as unreadable and
  suppresses the finding. Policies are discovered by Laravel's naming convention. Adds
  `structural.py`, a second finding producer beside the taint walk: both yield `list[PathStep]`
  naming their rule on the final step, so a structural rule never needs taint state.
  - New rule `laravel.missing-authorization` (high, CWE-639). Requires the route to be
    authenticated, so a public detail route like `GET /posts/{post}` produces nothing.

- **Slice 5 - the workspace** (PR #4 from `slice-5-workspace`). `Workspace.open()` resolves the
  project root and creates its `.vigilloo/` directory, keeping whatever is already there on
  reopen. `Workspace.resolve()` is the single path-traversal guard: it resolves against the root
  and follows symlinks before checking containment, so a link inside the project pointing out of
  it is refused too.

- **Slice 6 - the SQLite store** (PR #5 from `slice-6-store`, design
  [`docs/plans/2026-07-27-slice-6-store-design.md`](docs/plans/2026-07-27-slice-6-store-design.md)).
  `vigilloo scan` now records its history in `.vigilloo/vigilloo.db`: one row per scan, one row
  per file with its coverage, and one row per finding with its complete evidence path. Scan rows
  carry the engine version and the ruleset hash, which is what lets an old result be told apart
  from one today's ruleset would produce. A failed write warns and leaves the exit code to the
  findings. Nothing reads this history back yet; the readers (`report --compare`, baselines) are
  their own slices.

- **Slice 8 - the graph tables** (branch `slice-8-graph-ids`, design
  [`docs/plans/2026-07-28-slice-8-graph-ids-design.md`](docs/plans/2026-07-28-slice-8-graph-ids-design.md)).
  The store gained `nodes` and `edges` with the five indexes from
  [docs/17-database](docs/17-database/README.md), and batch insert helpers that write a whole
  batch in one statement rather than one per row. Nothing writes graph rows into them yet; that
  is the slice that turns the in-memory `Project` into nodes and edges.

  The same slice added `vigilloo.ids.node_id`, the content-derived node identity invariant 3
  requires. It knows nothing about PHP, Laravel or the store: it takes a project, a kind, an
  FQN and a discriminator and returns 16 hex characters, so the graph layer and every adapter
  above it derive the same ID for the same node without any of them owning the rule.

- **Slice 9 - every scan writes its graph** (branch `slice-9-store-read-write`, TASK-010). The
  in-memory `Project` is now flattened into the `nodes` and `edges` of
  [docs/04-knowledge-graph](docs/04-knowledge-graph/README.md) and written inside the scan's own
  transaction: one node per file, class, method, route and named middleware, and `DECLARES`,
  `EXTENDS`, `HANDLES`, `PROTECTED_BY`, `CALLS` and `INSTANTIATES` between them. Node IDs are the
  content-derived ones from `vigilloo.ids.node_id`, so re-scanning an unchanged project rewrites
  the same rows; edges have no identity of their own and are replaced wholesale per scan rather
  than accumulating a duplicate every run.

  Call edges resolve only receivers the source states outright - `$this`, `self`, `parent`, a
  class name, and a property whose declared type names a class, which is the constructor-injected
  Laravel controller shape. A call reaching a facade, a variable receiver or a plain function
  produces no edge and is counted instead, since a wrong edge is a false evidence path and a
  missing one is only a missed finding. An inherited method's edge lands on the ancestor that
  declares it, because that is the node that exists. A class whose parent is outside the project
  keeps the parent's name in its node attributes, which is how `extends Model` survives having no
  `EXTENDS` edge to carry it.

- **Findings read back with their evidence paths** (TASK-011). `findings_for_scan` returns each
  stored finding with its complete path, in source order, in two queries rather than one per
  finding. The stored step is a `StoredStep` and not a `PathStep`: docs/17-database keeps a
  step's line and not its columns, and handing back a `Span` would mean inventing three numbers
  a caller could not distinguish from the real one. What matters survives regardless - every
  input to `Finding.id` and `Finding.fingerprint` is stored, so both hashes recompute exactly
  from a stored row, which is what makes a baseline written against one scan still match in the
  next.

  Each step now also carries the id of the innermost graph node covering it, so an evidence path
  is a walk over the graph rather than a list of line numbers (invariant 2). A step inside a
  controller action resolves to that method; one on a model's `$guarded` line resolves to the
  class; a Blade step, which no method covers, resolves to its file node rather than to a guess.
  Reading a finding whose path rows are missing raises instead of returning it, because a
  pathless finding is something the engine is not allowed to produce.

- **Reading a previous scan without re-scanning it** (TASK-012). `project_id_for` ->
  `latest_scan` -> `findings_for_scan` is the path `vigilloo report` and `vigilloo explain` will
  take, and `findings_by_fingerprint` returns every scan's view of one finding, oldest first, for
  "when did this get introduced". Latest is keyed on the scan's own id and not on `started_at`:
  a start time is a finish time minus a measured duration, so a long scan can carry an earlier
  start than a short one that ran after it.

  This needed an index [docs/17-database](docs/17-database/README.md) did not define. The
  document specifies the indexes the graph and finding readers need but none on `scans`, so
  "the latest scan of this project" read every scan row of every project in the file. It gains
  `idx_scans_project ON scans(project_id, id)`, and the schema version moves to 3. A test asserts
  the query plans rather than assuming them - at fixture scale an unused index is still fast and
  still correct, so nothing else would notice it being ignored.

- **Property-based tests for the parser and taint engine** (TASK-020), the layer from
  [docs/22-testing](docs/22-testing/README.md) section "Property-based testing". Valid PHP parses
  without crashing, generated from a composite strategy over a hand-written grammar of the
  constructs the taint walk looks at rather than from `st.text()`, which would pass by producing
  garbage the parser correctly rejects. `parse_php` never raising for malformed input is pinned
  over arbitrary bytes, not arbitrary text: the input is a file on disk and may be a truncated
  upload or a binary blob named `.php`. Taint propagation is monotonic, so more taint in never
  means less taint out - the property that makes silent under-reporting unreachable by accident.
  A sanitizer subtracts the kinds it declares and no others.

  The node-id stability property stays in `tests/test_ids.py` rather than moving here, next to
  the negative-space tests that give it meaning. Every property was verified by mutation. That
  is how the sanitizer property was found to be blind to its own table - both sides read
  `sanitizer_clears`, so widening an entry to every kind reverts taint to a boolean and the
  property still passes - and it is paired with an example-based test that pins the entries the
  design rests on.

- **Measured coverage in every scan** (TASK-018). `vigilloo scan` now opens with the two rates
  from [docs/22-testing](docs/22-testing/README.md) section "Metrics gated in CI" - parse success
  and call-graph resolution - each with the counts it was computed from, printed whether or not
  they are flattering and ahead of the findings, per invariant 4 and
  [docs/16-reporting](docs/16-reporting/README.md). Both are ratios of what the scan recorded
  while running, never estimates: the walk now counts the name resolutions it followed as well as
  the ones it gave up on, because a give-up count with no denominator cannot be read. Zero
  attempts is 1.0, a decision documented at the point it is made. This replaces the bare
  "N call site(s) could not be resolved" line, which said nothing about how many there were.

### Changed

- **The node ID scheme no longer contains the span**, correcting
  [docs/04-knowledge-graph](docs/04-knowledge-graph/README.md) section "Node model". That
  document specified `sha1(project_id : kind : fqn : span)` while requiring in the same section
  that IDs be stable across whitespace and comment changes. Both cannot hold: inserting one
  comment moves the span of every node below it, so a reformat with no code change would move
  every ID and un-suppress every finding in the file. A `discriminator` derived from ordinal
  position within the parent replaces it. The span is still on the node, it just is not
  identity.

- **The store schema is version 2, and a database at any other version is now refused** with an
  error naming the file to delete. There is no migration runner yet, so opening a version 1
  `.vigilloo/vigilloo.db` would otherwise fail much later with "no such table: nodes". Delete
  the file and re-scan; nothing has been released, so no findings history exists that a
  migration would have had to preserve.

- The specification and the engine were consolidated into a single repository, and `src/` was
  made the `vigilloo` package itself rather than a directory containing it. CI builds the wheel
  and installs it into a clean environment so an unregistered subpackage cannot ship missing.
