# Parser Engine

Turns source files into an AST, a symbol table and an import graph. **Knows nothing about
Laravel or about security** - framework meaning is added in [08-framework-adapters](../08-framework-adapters/README.md),
security meaning in [13-security-engine](../13-security-engine/README.md).

## Technology

Tree-sitter, via `tree-sitter` + `tree-sitter-php`. Chosen because it is error-tolerant
(a syntax error yields a partial tree with `ERROR` nodes rather than nothing), fast enough for
whole-repo parsing, incremental at the file level, and gives byte-exact node spans - which the
report layer needs for precise code frames.

`tree-sitter-php` ships two grammars. Use **`php`** (text-mode, handles `?>` … `<?php`
interleaving) for `.php` and `.blade.php`; `php_only` is for embedded contexts we don't have.

## Discovery

1. Read `composer.json` → `autoload.psr-4` and `autoload-dev.psr-4` for namespace → directory
   maps. This is how `App\Http\Controllers\OrderController` becomes a file path without guessing.
2. Walk the project honouring `.gitignore`, plus built-in excludes: `vendor/`, `node_modules/`,
   `storage/`, `bootstrap/cache/`, `public/build/`, `*.min.js`.
3. `vendor/` is **indexed but not scanned** - symbols are needed to resolve calls into
   framework code, but framework code is not the user's bug. Findings inside `vendor/` are
   suppressed by default; dependency risk is handled by the dependency scanner instead.
4. Classify each file: PHP source, Blade template, config, migration, test, `.env`, JSON.

## Output per file

```text
ParsedFile
  path, sha256, language, role          # role: controller | model | middleware | blade | config | …
  tree                                  # Tree-sitter tree (cached, not persisted raw)
  symbols[]                             # see below
  imports[]                             # use statements, aliases, group-use
  namespace
  errors[]                              # ERROR/MISSING node spans
```

### Symbols

Namespaces, classes (with `extends` / `implements` / `use` traits), interfaces, traits, enums,
methods and functions (with parameters, defaults, type hints, return types, visibility,
static/abstract/final), properties (with type, default, visibility), class constants, closures
and arrow functions, and globals. Each carries a fully-qualified name and a byte span.

Fully-qualified names are the join key for every later stage, so resolution must handle PHP's
rules exactly: `use` aliases, group `use`, function/const imports, relative namespace paths,
`\` absolute references, and the fallback to global scope for unqualified function calls.

### Imports

`use` statements, grouped use, aliases, plus `require`/`include` targets when statically
resolvable. Laravel apps rely on autoloading, so `require` matters mostly in `bootstrap/` and
legacy corners.

## PHP features that must be handled correctly

These are the ones that break naive parsers and silently lose findings:

| Feature | Why it matters |
| --- | --- |
| Facades (`DB::`, `Http::`, `Storage::`) | A static call whose real target lives elsewhere. Parser records the static call verbatim; the adapter resolves it. |
| Traits | Methods are physically in another file. Method lookup must compose traits into the using class, honouring `insteadof` / `as`. |
| Magic methods `__call`, `__get`, `__callStatic` | Make some calls unresolvable statically. Record as unresolved rather than dropping. |
| Variable variables, `$$x`, `call_user_func`, `{$obj->$m}()` | Dynamic dispatch. Mark the edge unresolved; the taint engine treats unresolved sinks conservatively. |
| String interpolation `"... $x ..."` and heredoc | The single most common SQL-injection vehicle in PHP. Interpolated expressions must be first-class AST children, not opaque string text. |
| Null-safe `?->`, spread, named args, first-class callables `foo(...)` | PHP 8 syntax that must not produce ERROR nodes |
| Attributes `#[...]` | Used by newer packages for routing and validation |
| Anonymous classes, closures with `use (&$x)` | By-reference capture affects data flow |

**Implemented trait facts:** trait declarations and their methods are extracted separately from
classes. Class and trait `use` lists, `insteadof` precedence and `as` aliases are resolved by the
project method lookup rather than copied into each class, so a method keeps the span and FQN of
the trait that declares it. An unresolved trait conflict stays unresolved rather than selecting
whichever declaration happened to be parsed first.

## Blade templates

`.blade.php` is not PHP. Blade is compiled to PHP by Laravel; Vigilloo pre-processes it into
a normalised form the PHP grammar can read, while **preserving the escaping mode of every
echo**, because that distinction *is* the XSS rule:

| Blade | Meaning | Taint effect |
| --- | --- | --- |
| `{{ $x }}` | compiles to `e($x)` | HTML-sanitised |
| `{!! $x !!}` | raw echo | **HTML sink** |
| `@{{ x }}` | literal, for JS frameworks | inert |
| `{{-- --}}` | comment | stripped |
| `@php … @endphp` | inline PHP | parsed as PHP |
| `@include`, `@extends`, `@component`, `@each` | template edges | become graph edges for cross-template flow |
| `@csrf`, `@method` | form tokens | evidence for the CSRF rule |
| `@json($x)` | `json_encode` w/ escaping flags | JS-context-sanitised |

Directive coverage and the compiled-output mapping are owned by the Laravel adapter; the
parser only needs a faithful, span-preserving transformation.

## Caching and incrementality

Keyed on `sha256(file) + parser version + grammar version`. A cache hit skips parsing entirely
and rehydrates symbols from SQLite. Bumping the parser or grammar version invalidates globally,
which is the intended behaviour - stale symbol tables are worse than a slow scan.

## Error handling

Never abort a scan for one bad file. Record `ERROR` spans, mark the file partially parsed,
and surface the count in the report's coverage section. A file that cannot be parsed at all is
listed explicitly - silent coverage gaps are the most dangerous failure mode a security tool has.

## Later

Incremental re-parse using Tree-sitter edits (rather than whole-file reparse), multi-language
workspaces where a Laravel backend and a JS frontend share one graph, and a language-server
mode for editor integration.
