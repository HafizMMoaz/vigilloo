# Framework Adapters

An adapter teaches the graph what a framework *means*. Without one, `$request->all()` is an
untyped method call and `{{ $x }}` is a string. With one, they are a taint source and a
sanitized echo.

**v0.1 ships exactly one adapter: Laravel.** Everything below is that adapter. The generic
interface and the planned targets are at the end.

---

# The Laravel adapter

Targets **Laravel 9, 10 and 11** on **PHP 8.1+**. Behaviour differs between majors (Laravel 11
flattened `app/Http/Kernel.php` into `bootstrap/app.php`), so the adapter reads `composer.lock`
for the exact `laravel/framework` version and selects its extraction strategy from it.

## Detection

| Signal | Weight |
| --- | --- |
| `laravel/framework` in `composer.json` require | decisive |
| `artisan` file at root | strong |
| `bootstrap/app.php` + `app/` + `routes/` | strong |
| `config/app.php` returning an array with `providers` | confirming |

Version from `composer.lock` (exact, resolved) before `composer.json` (a constraint range).

## What it extracts

### Routes - the attack surface inventory

From `routes/web.php`, `routes/api.php`, `routes/console.php`, `routes/channels.php`, and any
file loaded by a `RouteServiceProvider`:

```php
Route::get('/orders/{order}', [OrderController::class, 'show'])->middleware('auth');
Route::post('/orders', 'OrderController@store')->name('orders.store');
Route::resource('posts', PostController::class);          // expands to 7 routes
Route::apiResource('items', ItemController::class);       // expands to 5
Route::group(['prefix' => 'admin', 'middleware' => ['auth','can:admin']], function () { … });
Route::middleware(['signed'])->group(…);
Route::match(['get','post'], …);   Route::any(…);
```

Per route: URI (with prefix inheritance), HTTP verbs, name, controller + action, the
**fully-resolved middleware stack** (global + group + route middleware, in order), and route
parameters with their model bindings.

Resource expansion, group nesting, prefix and name concatenation must all be exact. A missed
middleware entry produces a false "unauthenticated route" finding, and false positives on access
control destroy user trust faster than anything else.

Dynamically registered routes (`Route::get($var, …)`, routes built in a loop) are recorded with
low confidence and the URI marked dynamic.

### Middleware semantics

The adapter knows what each built-in middleware *guarantees* - this is what turns a route table
into an authorization model:

| Middleware | Guarantee |
| --- | --- |
| `auth`, `auth:sanctum`, `auth:api` | Request is authenticated |
| `guest` | Explicitly unauthenticated |
| `verified` | Email verified |
| `signed` | URL signature valid - often the only protection on public action links |
| `throttle:N,M` | Rate limited; absence on auth endpoints is a finding |
| `can:ability,model` | Authorization gate applied |
| `password.confirm` | Recent re-authentication |
| `VerifyCsrfToken` | CSRF protected - **and its `$except` array is read**, since wildcards there are a common critical finding |
| `TrimStrings`, `ConvertEmptyStringsToNull` | Input transforms that do **not** sanitize |
| Custom middleware | Body analysed for `abort(403)` / redirect patterns to infer whether it gates |

`web` and `api` groups resolve to their member lists from `Kernel.php` (L9/10) or
`bootstrap/app.php` (L11).

### Eloquent models

Per model: table, `$fillable`, `$guarded`, `$hidden`, `$casts`, `$appends`, relationships,
scopes, accessors/mutators, `$timestamps`, soft deletes, traits in use.

Mass-assignment analysis needs all of it:

```php
class User extends Model {
    protected $guarded = [];                                // ← protection fully disabled
    // or
    protected $fillable = ['name', 'email', 'is_admin'];    // ← privileged column allowlisted
}
User::create($request->all());       // ← tainted array into an unguarded model
$user->update($request->all());
$user->forceFill($request->all());   // ← bypasses even $fillable
```

Column sensitivity is inferred from name patterns (`is_admin`, `role`, `role_id`, `permissions`,
`verified_at`, `balance`, `price`, `owner_id`, `user_id`) and cross-checked against migrations
for the real schema - more reliable than the property list alone.

### Validation

Form requests (`extends FormRequest`) contribute `rules()`, `authorize()` and
`prepareForValidation()`; inline `$request->validate([...])` and `Validator::make()` contribute
the same. Rule → cleared-taint-kind mapping lives in [06-taint-analysis](../06-taint-analysis/README.md).

Two Laravel traps the adapter must catch:

1. `authorize()` returning `true` on a FormRequest guarding a privileged action - validation is
   not authorization.
2. Validating `$request`, then using `$request->all()` instead of the `validated()` result. The
   validation cleaned nothing on that path. Extremely common.

### Authorization

Policies (`app/Policies/`, `AuthServiceProvider::$policies`, naming-convention auto-discovery),
gates (`Gate::define`), and every call site: `$this->authorize()`, `Gate::allows/denies`,
`$user->can()`, `@can`, `can:` middleware, `authorizeResource()`.

The high-value query this enables: **a route with model binding, no `can:` middleware, and no
`authorize()` in the action is an IDOR** -

```php
Route::get('/invoices/{invoice}', [InvoiceController::class, 'show'])->middleware('auth');
// InvoiceController::show(Invoice $invoice) - any authenticated user, any invoice.
```

Authenticated but not authorized. Seeing this needs the route table, the binding and the policy
map together - no single-file scanner can.

### Blade templates

Escaping mode per echo, inheritance (`@extends`, `@section`, `@yield`, `@stack`), includes and
components (`@include`, `<x-component>`, class-based), `@csrf` / `@method` presence in forms, and
`@can` / `@auth` / `@guest` guards. Controller-passed variables (`view('x', compact('y'))`,
`->with()`) are cross-referenced so taint flows from controller into template.

### Configuration and environment

`config/*.php` values and their `env()` defaults, `.env`, `.env.example`, plus:

- `APP_DEBUG=true` with production indicators - critical (Ignition RCE, CVE-2021-3129)
- `APP_KEY` missing, empty, committed or framework-default - enables encrypted-cookie
  deserialization RCE (CVE-2018-15133)
- `SESSION_SECURE_COOKIE`, `SESSION_HTTP_ONLY`, `SESSION_SAME_SITE`, `SESSION_DRIVER`
- `DB_PASSWORD` empty; `MAIL_*`, `AWS_*`, `STRIPE_*` credentials committed
- `env()` called **outside** `config/` - returns `null` after `php artisan config:cache`,
  silently disabling whatever depended on it
- `TRUSTED_PROXIES=*` - client IP spoofing, defeating rate limits and IP allowlists

### Jobs, commands, events, schedule

Queue jobs (`handle()`, retry config, whether payloads are user-supplied), console commands,
event listeners and subscribers, model observers, notifications, scheduled tasks. All are
**entry points** - code reachable only from a job is still reachable. See
[07-call-graph](../07-call-graph/README.md).

### Dependencies

`composer.lock` → exact versions → advisories from the PHP Security Advisories database and OSV
(`composer` ecosystem). Reachability is cross-checked against the call graph, so "vulnerable and
reachable from a public route" outranks "vulnerable, never called".

## Laravel-specific rule set

Rules that exist only because the adapter provides framework facts. Full catalogue in
[13-security-engine](../13-security-engine/README.md).

| Rule | Detects | Severity |
| --- | --- | --- |
| `laravel.mass-assignment` | `$guarded = []` or privileged `$fillable` column reached by request data | high |
| `laravel.missing-authorization` | Model-bound action with no policy/gate check | high |
| `laravel.csrf-except` | Wildcard or state-changing path in `VerifyCsrfToken::$except` | high |
| `laravel.debug-enabled` | `APP_DEBUG=true` with production indicators | critical |
| `laravel.app-key` | Missing, default or committed `APP_KEY` | critical |
| `laravel.unsigned-route` | Public action route without `signed` | medium |
| `laravel.unauthenticated-route` | State-changing route with no auth middleware | high |
| `laravel.raw-query` | `*Raw` / `DB::raw` reached by taint in the non-binding argument | critical |
| `laravel.blade-raw-echo` | `{!! $tainted !!}` | high |
| `laravel.env-outside-config` | `env()` in app code | medium |
| `laravel.validated-bypass` | Validation run, then `$request->all()` used | medium |
| `laravel.unsafe-upload` | `getClientOriginalName()` used as a storage path | high |
| `laravel.debug-artifact` | `dd()`, `dump()`, `ray()`, `var_dump()` in non-test code | low |
| `laravel.weak-hash` | `md5`/`sha1` for passwords instead of `Hash::make` | high |
| `laravel.no-throttle` | Login/register/reset route without `throttle` | medium |
| `laravel.trusted-proxies` | `TrustedProxy` set to `*` | medium |

## Framework summaries

Rather than analysing Laravel's own source, the adapter ships hand-written summaries for
framework methods - which bind parameters, which escape output, which propagate taint:

```yaml
- fqn: Illuminate\Database\Query\Builder::where
  params: [column, operator, value]
  sanitizes: { value: [sql] }        # bound, therefore safe
  propagates: { column: [sql] }      # identifier is quoted, not bound - lower risk, tracked

- fqn: Illuminate\Database\Query\Builder::whereRaw
  params: [sql, bindings]
  sink: { sql: [sql] }               # arg 0 is a sink
  sanitizes: { bindings: [sql] }     # arg 1 is bound

- fqn: e
  sanitizes: { 0: [html] }
```

Versioned YAML alongside the adapter, testable in isolation, far cheaper to maintain than
re-deriving the same facts from framework source on every scan.

---

# The adapter interface

```python
class FrameworkAdapter(Protocol):
    name: str
    def detect(self, project: ProjectProfile) -> DetectionResult: ...
    def extract(self, files: list[ParsedFile]) -> FrameworkFacts: ...
    def entry_points(self, facts: FrameworkFacts) -> list[EntryPoint]: ...
    def summaries(self) -> list[FunctionSummary]: ...
    def rules(self) -> list[Rule]: ...
```

`FrameworkFacts` carries routes, entry points, models, middleware, authorization checks,
templates and config in a framework-neutral shape, so the graph and security engines never
import anything Laravel-specific. The Laravel adapter is the reference implementation and the
proof the interface is genuinely neutral - if a second adapter forces an interface change, the
interface was wrong.

## Planned targets

Ordered by when the underlying language support lands, not by priority within a version.

| Wave | Language | Frameworks |
| --- | --- | --- |
| **v0.1** | PHP | **Laravel** |
| **v0.5** | PHP | **Webisters** (see below) |
| v1.0 | PHP | Symfony, CodeIgniter |
| v1.0 | Python | Django, FastAPI, Flask |
| v1.5 | JS/TS | Express, NestJS, Next.js |
| v1.5 | JS/TS | React, Angular, Vue *(client-side: DOM XSS, secret exposure, unsafe `dangerouslySetInnerHTML` / `[innerHTML]`)* |
| v2.0 | Java/Kotlin | Spring Boot |
| v2.0 | C# | ASP.NET Core (`.NET`) |

Client-side adapters (React, Angular, Vue) analyse a different threat model from server-side
ones - no server sinks, but DOM XSS, exposed secrets in bundles, insecure `postMessage`, and
`localStorage` token handling. They share the graph but have their own sink vocabulary.

---

# The Webisters adapter (v0.5)

[Webisters](https://github.com/webisters) is a full-stack PHP framework (webisters.com),
distributed as ~37 single-purpose Composer packages in the Symfony-components style: `mvc`,
`routing`, `http`, `database`, `validation`, `session`, `crypto`, `cache`, `log`, `theme`, plus
`app` / `api` / `one` / `site` project skeletons.

It is scheduled second, immediately after Laravel and ahead of Symfony, because it costs
almost nothing to add: same language, same parser, same PHP taint vocabulary, same Composer
dependency analysis. Only the framework-semantics layer is new. It is also the ideal second
adapter for validating that `FrameworkAdapter` is genuinely framework-neutral - Laravel's
facade-and-container idiom and Webisters' attribute-and-reflection idiom are different enough
that anything Laravel-shaped leaking into the interface will show up immediately.

## Detection

`webisters/framework` or any `webisters/*` package in `composer.json`; the `App` service
container from `webisters/mvc` bootstrapped in the entry script.

## Sources - `webisters/http`

`Request` exposes explicit per-superglobal accessors rather than one merged bag, which is a
precision advantage over Laravel: the adapter knows which channel input arrived on without
inference.

```php
$request->getGet($key)          $request->getPost($key)
$request->getPut($key)          $request->getPatch($key)
$request->getParsedBody()       $request->getJson()
$request->getBody()             $request->getHeader($name)
$request->getCookie($name)      $request->getFile($name)    // UploadedFile
$request->getIp()               $request->getEnv($key)
$request->getBasicAuth()        $request->getBearerAuth()   $request->getDigestAuth()
```

Route parameters bound into controller actions by `routing/Reflector` are sources, exactly as
with Laravel's implicit binding.

## Sinks and sanitizers - `webisters/database`

The framework marks its own raw-SQL parameters with a PHP attribute:

```php
public function exec(#[Language('SQL')] string $statement) : int|string
public function query(#[Language('SQL')] string $statement) : Result
public function prepare(#[Language('SQL')] string $statement) : PreparedStatement
```

`#[Language('SQL')]` is a machine-readable sink declaration in the framework source. The
adapter derives sinks by scanning for that attribute instead of maintaining a hand-written list,
so the sink set stays correct as the framework evolves - and the same mechanism extends to any
application code that adopts the attribute. This is a real advantage over frameworks where sink
identification is pure convention.

| Symbol | Role |
| --- | --- |
| `Database::exec()`, `Database::query()` | `sql` sink |
| `Database::prepare()` + `PreparedStatement` bind | sanitizer (the correct fix) |
| `Database::quote()` | value sanitizer for `sql` |
| `Database::protectIdentifier()` | identifier sanitizer - the ORDER BY / column-name case |
| `Manipulation\Select|Insert|Update|Delete|Replace|With` | fluent builder; per-method summaries mirroring the Laravel builder work |

## Framework facts to extract

| Area | Package | Extracted |
| --- | --- | --- |
| Routes | `routing` | `#[Route]` attributes and code-registered routes, `RouteCollection`, named routes, `Reflector` action binding, `#[Origin]` CORS, `#[RouteNotFound]` |
| Controllers, models, entities | `mvc` | `App` container bindings, `Controller`, `Model`, `Entity`, `View` |
| CSRF | `http/AntiCSRF` | `verify()`, `validate()`, `isSafeMethod()`, and `disable()` - a call to `disable()` is the Webisters analogue of a `VerifyCsrfToken::$except` wildcard, and a high-severity finding |
| CSP | `http/CSP` | Missing or unsafe directives (`unsafe-inline`, `unsafe-eval`) |
| Validation | `validation` | `Rules`, `BaseRules`, `FilesValidator` rule sets mapped to cleared taint kinds |
| Sessions | `session` | Save handler, cookie flags |
| Crypto | `crypto` | libsodium usage; flags hand-rolled crypto and weak password hashing bypassing the library |
| Views | `mvc/View`, `theme` | Template escaping mode, the XSS sink set |
| Uploads | `http/UploadedFile` | Client-supplied filename reaching a storage path |
| Config | `config` | PHP/INI/JSON/XML/YAML/ENV/database loaders; debug flags, committed credentials |

## Open questions for the Webisters adapter

Answerable from the source when the adapter is built, listed so they are not forgotten:

1. Does `mvc/View` escape by default, and is there a raw-output escape hatch? This determines
   the XSS sink set, and it is the single highest-value fact for the adapter.
2. Is there a middleware or filter pipeline that gates routes, equivalent to Laravel's
   middleware stack? Without one, the access-control structural rules need a different signal.
3. Is `Model`/`Entity` mass-assignable from an array, and if so what guards it? This decides
   whether the mass-assignment rule class applies at all.
4. Do routes carry authorization metadata in attributes, and how do policies get expressed?
