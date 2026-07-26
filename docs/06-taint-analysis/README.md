# Taint Analysis

Taint analysis is the security vocabulary layered onto [05-data-flow](../05-data-flow-analysis/README.md).
This document is the **canonical source/sink/sanitizer reference for PHP and Laravel** - other
docs cite it rather than restating it.

## Taint kinds

Taint is not a boolean. `e()` makes a value safe to print in HTML and does nothing for SQL.
A single boolean flag produces both false negatives and false positives, so every taint mark
carries a **kind set**, and a sanitizer clears only the kinds it actually addresses.

| Kind | Dangerous at | Cleared by |
| --- | --- | --- |
| `sql` | query builders, raw SQL | parameter binding, integer cast, allowlist |
| `html` | Blade raw echo, `Response` with HTML | `e()`, `htmlspecialchars`, `{{ }}` |
| `js` | inline `<script>`, `@json` context | `json_encode` with escaping flags, `Js::from` |
| `shell` | `exec` family, `Process` | `escapeshellarg` |
| `path` | file read/write/include, `Storage` | `basename`, realpath-within-root check, allowlist |
| `url` | HTTP clients (SSRF), redirects | host allowlist, scheme check |
| `code` | `eval`, `unserialize`, dynamic include | nothing - never accept untrusted input here |
| `ldap`, `xpath`, `header`, `log` | respective sinks | respective encoders |
| `mass_assign` | Eloquent array writes on a model with protection disabled | `validated()`, `safe()`, `only([...])`, an explicit array literal |

`mass_assign` is not an injection kind like the others. It marks a value whose **keys** the
attacker chose, which is what makes an Eloquent array write dangerous. It is a kind rather than
a property of the sink because `$request->only([...])` and `$request->validated()` are still
fully `html`- and `sql`-dangerous while being perfectly safe to mass-assign, and no boolean over
the other kinds can express that difference. `except([...])` is a blacklist and stays dangerous.

A value can hold several kinds at once, and typically does: `$request->input('name')` starts as
all of them.

## Sources - where taint enters

### Laravel HTTP

```php
$request->input('x')        $request->get('x')        $request->query('x')
$request->all()             $request->only([...])     $request->except([...])
$request->post('x')         $request->json('x')       $request->string('x')
$request->file('x')         $request->header('X')     $request->cookie('c')
$request->ip()              $request->userAgent()     $request->url()/fullUrl()
$request->route('param')    $request->segment(n)      $request->bearerToken()
request('x')                Input::get('x')           // helper + legacy facade
$request->x                 // magic property access - commonly missed
```

Route parameters injected into controller signatures are sources:
`public function show(Request $r, string $slug)` - `$slug` is attacker-controlled.

**Validated input is still tainted, with reduced kinds.** `$request->validate(['id' => 'integer'])`
clears `sql` for `id` but not `html`. `'string'` clears nothing. `'in:a,b'` clears everything
(allowlist). The rule → cleared-kinds mapping lives in the Laravel adapter.

### PHP native

```php
$_GET  $_POST  $_REQUEST  $_COOKIE  $_FILES  $_SERVER  $_ENV  $argv
file_get_contents('php://input')     getenv()     apache_request_headers()
```

`$_SERVER` needs care: `HTTP_*`, `REQUEST_URI`, `QUERY_STRING`, `PATH_INFO`, `HTTP_HOST` and
`HTTP_X_FORWARDED_FOR` are attacker-controlled; `DOCUMENT_ROOT` is not.

### Second-order (stored)

Database reads, cache reads, queue payloads, uploaded file *contents*, and third-party API
responses. Off by default (`--stored-taint` enables), because treating every Eloquent read as
tainted floods the report - but it is how real stored-XSS is found, and it is why
`param_to_property` summaries exist.

## Sinks - where taint causes harm

### SQL (`sql`) - CWE-89

```php
DB::raw($x)            DB::select($x)        DB::statement($x)     DB::unprepared($x)
DB::insert/update/delete($x)
->whereRaw($x)         ->orWhereRaw($x)      ->havingRaw($x)
->orderByRaw($x)       ->groupByRaw($x)      ->selectRaw($x)       ->fromRaw($x)
->join(..., DB::raw($x))
mysqli_query()   PDO::query()   PDO::exec()   pg_query()
```

Critical nuance: the `*Raw` methods **accept bindings as a second argument**.
`whereRaw('age > ?', [$age])` is safe; `whereRaw("age > $age")` is not. The rule must inspect
which argument the taint reaches. Flagging every `whereRaw` is exactly the noise that makes
developers stop reading security reports.

Also: `->orderBy($request->input('col'))` is not injectable in modern Laravel (identifiers are
quoted), but `orderByRaw` is. Version-check this - the adapter tracks the Laravel version.

### Command (`shell`) - CWE-78

```php
exec()  shell_exec()  system()  passthru()  popen()  proc_open()  pcntl_exec()
`backticks`
Process::run($cmd)   Process::start($cmd)          // Laravel 10+
Symfony\Component\Process\Process::fromShellCommandline($cmd)
```

`new Process(['ls', $x])` (array form) does not go through a shell - much lower severity than
`fromShellCommandline("ls $x")`.

### Code execution (`code`) - CWE-94/502

```php
eval()   assert($string)   create_function()
unserialize($x)                        // CWE-502 - Laravel gadget chains are plentiful
include/include_once/require/require_once($x)      // CWE-98 LFI/RFI
preg_replace('/…/e', …)                // removed in PHP 7, still in legacy code
$fn = $x; $fn();                       // dynamic invocation
call_user_func($x)   array_map($x, …)
```

### Filesystem (`path`) - CWE-22/434

```php
file_get_contents($x)  file_put_contents($x)  fopen($x)  unlink($x)  copy()  rename()
Storage::get($x)  Storage::put($x, …)  Storage::delete($x)  Storage::disk($x)
$request->file('f')->move($dir, $x)         // client filename → path traversal
$request->file('f')->getClientOriginalName()  // NEVER trust as a filename
```

`->store('dir')` and `->storeAs()` with a generated name are safe; the unsafe pattern is
`move()` or `storeAs()` using `getClientOriginalName()`.

### SSRF (`url`) - CWE-918

```php
Http::get($x)  Http::post($x)  Guzzle client->request(…, $x)
file_get_contents($url)  curl_setopt(CURLOPT_URL, $x)  fsockopen($x)
```

### XSS (`html`, `js`) - CWE-79

```blade
{!! $x !!}                     {{-- raw echo - the primary Blade XSS sink --}}
<div {!! $attrs !!}>           {{-- attribute injection --}}
<script>var a = {{ $x }}</script>   {{-- HTML-escaped ≠ JS-safe --}}
<a href="{{ $url }}">          {{-- javascript: scheme survives HTML escaping --}}
```

```php
response($html)   ->header('Content-Type', 'text/html')
Blade::render($x)         // template injection - treat as `code`
```

### Open redirect - CWE-601

```php
redirect($x)   redirect()->to($x)   redirect()->away($x)   Redirect::to($x)
header("Location: $x")
```

### Others

`ldap_search` (`ldap`), `DOMXPath::query` (`xpath`), `header($x)` (`header`, CWE-113),
`Log::info($x)` (`log`, CWE-117), `mail()` / `Mail::raw` additional headers.

## Sanitizers

| Sanitizer | Clears | Notes |
| --- | --- | --- |
| Query-builder binding (`where('c', $x)`, `?` placeholders) | `sql` | The correct fix for nearly all SQL findings |
| `(int)$x`, `intval()`, `+$x` | `sql`, `shell`, `path`, `html` | Numeric coercion is a genuine sanitizer |
| `e()`, `htmlspecialchars($x, ENT_QUOTES)` | `html` | Not `js`, not `url` |
| `htmlspecialchars` **without** `ENT_QUOTES` | partial | Leaves single-quoted attributes injectable - flag it |
| `{{ }}` Blade echo | `html` | Automatic |
| `escapeshellarg()` | `shell` | `escapeshellcmd()` is weaker - do not treat as full |
| `basename()` | `path` partially | Stops traversal, not overwrite of a sibling file |
| `realpath()` + prefix check | `path` | The real fix |
| `json_encode` with `JSON_HEX_*`, `Js::from()` | `js` | |
| `urlencode`, `rawurlencode` | `url` partially | |
| `$request->validate()` / FormRequest rules | per rule | `integer`,`numeric`,`uuid`,`in:`,`exists:` clear `sql`; `url`,`active_url` reduce `url`; `string` clears nothing |
| `Validator::make(...)->validated()` | per rule | Only the returned array is cleaned - **not** `$request->all()` afterwards |
| `preg_match` allowlist then use of `$matches` | contextual | Recognised when the pattern is anchored and literal |
| `Str::slug`, `Str::uuid` | most | Output alphabet is constrained |

**Anti-sanitizers** - must never be accepted, and are findings in themselves:
`addslashes()`, `mysql_real_escape_string`, `strip_tags()`, `str_replace("'", "", $x)`,
`stripslashes`, blacklist regexes, and `htmlspecialchars` applied to a value used in SQL.

## Propagation rules

Assignment, interpolation, concatenation, array read/write, object property read/write,
function argument → parameter, return value → call site, and by-reference writeback. Union at
CFG merge points: a value tainted on any incoming path is tainted after the join, with the
union of kinds.

## Path construction

A finding's evidence path is the node sequence from source to sink:

```text
routes/web.php:23            POST /orders/search → OrderController@search
OrderController.php:41       $sort = $request->input('sort')          [source: sql,html,…]
OrderController.php:44       $this->repo->search($sort)               [arg 0 → param 0]
OrderRepository.php:38       public function search(string $sort)
OrderRepository.php:42       ->orderByRaw("created_at $sort")         [sink: sql, unsanitized]
```

Every step is a real graph edge with a real span. This path is what the report renders, what
the AI engine explains, and what the attack engine turns into a probe. **A finding without a
complete path is a bug in Vigilloo, not a finding.**

## Configuration

Projects extend the built-in vocabulary in `vigilloo.yml` - custom sources for in-house request
wrappers, custom sanitizers for a team's own escaping helper, and suppressions with a required
justification. Custom entries carry lower default confidence than built-ins.
