# Plugin SDK

Every capability is a plugin - including the ones that ship in the box. The Laravel adapter and
the PHP language plugin use the same interfaces a third party would, which is the only reliable
way to keep those interfaces honest.

## Categories

| Category | Implements | Example |
| --- | --- | --- |
| **Language** | Parsing, symbols, language-level sources/sinks | `vigilloo-php` |
| **Framework** | Framework facts, entry points, summaries, rules | `vigilloo-laravel` |
| **Scanner** | Rules over the graph | `vigilloo-secrets` |
| **Reporter** | Findings → output format | `vigilloo-sarif` |
| **AI provider** | Completion + embedding | `vigilloo-ollama` |
| **Attack module** | Authorized active validation | `vigilloo-sqli-probe` |
| **Integration** *(v1.0)* | Git hosts, CI, ticketing | `vigilloo-github` |

## Discovery

Python entry points, so `pip install vigilloo-something` is the whole installation step:

```toml
[project.entry-points."vigilloo.framework"]
laravel = "vigilloo_laravel:LaravelAdapter"

[project.entry-points."vigilloo.scanner"]
secrets = "vigilloo_secrets:SecretScanner"
```

Also loaded: `./.vigilloo/plugins/*.py` for project-local rules - the path teams actually use
for one-off in-house checks, where publishing a package is absurd overhead.

## Base contract

```python
class Plugin(Protocol):
    name: str
    version: str
    api_version: str          # SDK version this was built against
    def initialize(self, ctx: PluginContext) -> None: ...
    def shutdown(self) -> None: ...
```

`PluginContext` grants read access to the workspace, graph, config and logger. Plugins do not
receive raw filesystem or network handles - capability grants are explicit, both to make
sandboxing possible later and to make it obvious in review when a plugin wants something
unusual.

## Interfaces

### Scanner - the one most people write

```python
class Scanner(Protocol):
    def rules(self) -> list[Rule]: ...
    def scan(self, graph: GraphQuery, ctx: ScanContext) -> Iterator[Finding]: ...
```

`GraphQuery` is a read-only, typed traversal API - not raw SQL, so the storage backend can
change without breaking plugins:

```python
for route in graph.routes(unauthenticated=True):
    for sink in graph.reachable_sinks(route, kind="sql", max_depth=10):
        if not sink.is_sanitized_for("sql"):
            yield Finding(rule_id="php.sql-injection", location=sink.location,
                          evidence_path=graph.path(route, sink), severity="critical")
```

### Declarative rules - the one most people should write

Most rules need no Python at all. YAML in `.vigilloo/rules/`:

```yaml
id: acme.internal-api-no-auth
title: Internal API route without authentication middleware
severity: high
cwe: [CWE-306]
match:
  kind: route
  uri_prefix: /internal/
  not_middleware: [auth, auth:sanctum, internal-token]
message: "Internal route {uri} is publicly reachable."
remediation: "Add the internal-token middleware."
```

Taint rules are declarative too - see the schema in
[13-security-engine](../13-security-engine/README.md). Making the common case declarative is
what keeps the plugin API from becoming a maintenance burden: a YAML rule cannot crash a scan,
cannot go into an infinite loop, and cannot read the filesystem.

### Other interfaces

```python
class LanguagePlugin(Protocol):
    extensions: list[str]
    def grammar(self) -> Language: ...
    def parse(self, source: bytes) -> ParsedFile: ...
    def symbols(self, tree: Tree) -> list[Symbol]: ...
    def taint_vocabulary(self) -> TaintVocabulary: ...

class Reporter(Protocol):
    format_name: str
    def render(self, report: Report, out: BinaryIO) -> None: ...

class AttackModule(Protocol):
    def applicable_to(self, finding: Finding) -> bool: ...
    def probe(self, finding: Finding, target: AuthorizedTarget) -> ProbeResult: ...
```

`FrameworkAdapter` and `AIProvider` are specified in
[08-framework-adapters](../08-framework-adapters/README.md) and
[09-ai-engine](../09-ai-engine/README.md).

## Versioning

The SDK is semver'd independently of the CLI. Plugins declare `api_version`; a plugin built
against an incompatible major is refused with a clear message rather than half-loaded. Interfaces
are `Protocol` classes - structural typing, so plugins need no inheritance from core and core
can be swapped without touching them.

## Failure isolation

A plugin that raises during `initialize` is disabled for the run. A plugin that raises during a
scan has that unit of work marked failed; the scan continues and the report records the gap.
A plugin exceeding its time budget is cancelled. A third-party rule must never be able to
prevent a security scan from producing results.

Process-level sandboxing is a later addition, once there is a plugin ecosystem worth protecting
users from. Documented now so the capability-based `PluginContext` design does not get simplified
away in the meantime.

## Testing

The SDK ships a test kit: fixture projects, a graph builder for synthetic cases, and assertion
helpers.

```python
def test_detects_raw_query(vigilloo):
    project = vigilloo.fixture("laravel-minimal")
    project.write("app/Http/Controllers/X.php", """<?php
        class X { public function i(Request $r) {
            return DB::select("select * from u where n = '{$r->input('n')}'");
        }}""")
    findings = vigilloo.scan(project)
    assert findings.has("php.sql-injection", file="app/Http/Controllers/X.php")
    assert findings.one().evidence_path.starts_at_source("laravel.request.input")
```

Asserting on the evidence path, not just the finding, is the point - a rule that fires for the
wrong reason is a rule that will fire wrongly elsewhere.

## Distribution

PyPI under the `vigilloo-` prefix, `vigilloo plugin list|install|remove`, and a curated registry
of verified plugins in the docs. Core plugins ship in the main package with no separate install.
