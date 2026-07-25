# Call Graph

Who calls what. Interprocedural taint ([05](../05-data-flow-analysis/README.md)), reachability,
attack paths and dependency triage all traverse this layer.

## Nodes and edges

Nodes: functions, methods, closures, arrow functions, `__invoke`ables, constructors.
Edges:

| Edge | Source construct |
| --- | --- |
| `CALLS` | `foo()`, `$obj->m()`, `Cls::m()`, `$this->m()`, `parent::m()`, `static::m()` |
| `INSTANTIATES` | `new Cls()` → constructor |
| `RESOLVES_TO` | facade / container / interface → concrete implementation |
| `DISPATCHES` | `Job::dispatch()`, `event()`, `Bus::dispatch()` → handler |

Every edge carries `confidence` and `resolution` (how it was resolved). Consumers filter on
both. See [04-knowledge-graph](../04-knowledge-graph/README.md) for the node/edge schema.

## Resolution strategies, best to worst

| # | Strategy | Confidence | Example |
| --- | --- | --- | --- |
| 1 | Static, fully qualified | 1.0 | `\App\Services\Foo::bar()`, plain function calls |
| 2 | `$this->` / `self::` / `parent::` within a known class hierarchy | 1.0 | `$this->validate()` |
| 3 | Typed parameter or property | 0.95 | `public function __construct(private OrderRepo $repo)` then `$this->repo->find()` |
| 4 | Facade map | 0.95 | `DB::table()` → `Illuminate\Database\DatabaseManager::table()` |
| 5 | Container binding from a service provider | 0.9 | `app(PaymentGateway::class)` where the provider binds it to `StripeGateway` |
| 6 | Interface with exactly one implementation in the project | 0.85 | |
| 7 | Interface with N implementations | 0.6 / N | Edge to each candidate |
| 8 | Docblock `@var` / `@return` type only | 0.6 | Legacy untyped code |
| 9 | Name-based heuristic | 0.4 | A method name unique across the project |
| 10 | Unresolved | 0.0 | `call_user_func($x)`, `$$method()`, `__call` |

Default reporting threshold is 0.5; `--min-confidence` overrides. Unresolved calls are recorded
as edges to a sentinel `UNRESOLVED` node - never dropped, because a dropped edge is a silent
false negative and a recorded one is a visible coverage gap.

## Laravel-specific resolution

This is where a generic PHP call graph fails and the framework adapter earns its place.

### Facades

`DB::table()` is a static call to a class with no `table()` method. Laravel resolves it at
runtime through `Facade::getFacadeAccessor()` → container key → concrete class. Vigilloo ships a
**static facade map** from framework version to concrete class:

```text
Illuminate\Support\Facades\DB      → Illuminate\Database\DatabaseManager
Illuminate\Support\Facades\Http    → Illuminate\Http\Client\Factory
Illuminate\Support\Facades\Storage → Illuminate\Filesystem\FilesystemManager
Illuminate\Support\Facades\Auth    → Illuminate\Auth\AuthManager
… plus Cache, Log, Mail, Queue, Event, Gate, Route, Config, Session, Validator, Blade, Process
```

Real-time facades (`Facades\App\Services\Foo`) resolve by stripping the `Facades\` prefix.
Custom facades resolve by reading the app's own `getFacadeAccessor()` return value.

### Container bindings

Service providers register bindings that determine what an interface resolves to:

```php
$this->app->bind(PaymentGateway::class, StripeGateway::class);
$this->app->singleton('reports', fn () => new ReportService());
```

The adapter extracts these from `register()` methods across all providers, giving `RESOLVES_TO`
edges for `app(X::class)`, `resolve(X::class)`, `App::make(X::class)`, and - most importantly -
constructor injection, which is how idiomatic Laravel code obtains nearly all its collaborators.

### Framework-invoked entry points

Much Laravel code is never called by other application code; the framework calls it. Without
explicit entry-point edges the call graph looks like a field of disconnected islands and
reachability analysis reports nothing:

| Entry point | Edge created |
| --- | --- |
| Route → controller action | `route --HANDLES--> action` |
| Route → middleware `handle()` | `route --PROTECTED_BY--> middleware` |
| `Job::dispatch()` → `Job::handle()` | `DISPATCHES` |
| `event(X)` → listener `handle()` | `DISPATCHES`, via the provider's `$listen` map and auto-discovery |
| Console command → `handle()` | entry point |
| Scheduler (`Kernel::schedule`) → command | entry point |
| Model events → observers (`created`, `saving`, …) | `DISPATCHES` |
| `Notification` → `via()`/`toMail()` | entry point |
| Blade `@include` / `@component` | `RENDERS` |
| Policy method ← `authorize()` / `@can` / `can:` middleware | `AUTHORIZES` |
| Route model binding → `resolveRouteBinding()` | implicit query execution |

### Traits and inheritance

Trait methods are flattened into the using class before resolution, honouring `insteadof` and
`as` aliasing. Calls to an inherited method resolve to the nearest definition walking up the
hierarchy. Calls to an abstract or interface method fan out to implementations (strategy 6/7).

## Algorithms over the graph

- **Reachability** - is a sink reachable from any entry point? Recursive CTE in SQL, or BFS in
  NetworkX for the materialised layer. A sink that no route reaches is severity-reduced, not
  dropped: console commands and jobs are entry points too, and dead code gets resurrected.
- **SCC condensation** - recursive and mutually recursive functions collapse into components so
  summary computation terminates.
- **k-shortest paths** - for ranking multiple routes to the same sink; the shortest path is the
  clearest one to show a developer.
- **Dominators** - find the choke point where a single sanitizer would cut every path to a sink.
  This is what turns "12 findings" into "one fix here closes all 12", and it is the highest-value
  output of the whole layer.
- **Dead code** - functions unreachable from any entry point. Reported as informational; in a
  security context, unreachable code is also unmaintained code.

## Known limits

Dynamic dispatch through strings, `__call` / `__callStatic` magic, runtime-conditional container
bindings, `eval`-constructed callables, and reflection are not statically resolvable. They
become `UNRESOLVED` edges, are counted in the coverage section of every report, and never
silently vanish.
