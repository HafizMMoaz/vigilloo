# Slice 3 Design: Mass Assignment

**Status:** implemented.
**Supersedes nothing.** Builds directly on slices 1 and 2.
**Normative references:** [08-framework-adapters](../08-framework-adapters/README.md),
[13-security-engine](../13-security-engine/README.md),
[06-taint-analysis](../06-taint-analysis/README.md).
Where this document and those disagree, those win and this is the bug.

## Goal

`vigilloo scan` reports a mass-assignment finding whose evidence path runs from an HTTP route,
through a controller, across `$request->all()`, into a model whose protection is disabled, and
stops at the Eloquent write. In the same run:

- the same call against a model with a narrow `$fillable` produces **no** finding, and
- `User::create($request->only(['name', 'email']))` against the unguarded model produces **no**
  finding.

Those two negatives are the slice. A structural rule that can only fire has not been shown to
read model configuration at all - it has been shown to recognise the string `create`.

## Why this slice

Slices 1 and 2 are both taint rules: source, sink, sanitizer. They exercise the call graph but
not the framework model. [13-security-engine](../13-security-engine/README.md) §2 puts the
Laravel value in *structural* rules, and CLAUDE.md names mass assignment first among them. This
is the first rule that cannot be produced by a single-file scanner: it needs the route table,
the call graph and the model's property configuration together, from three different files.

It also collects a debt that slice 2 deliberately left. `rules.py:51-57` picks the rule by the
sink's file extension and says so:

> The third rule breaks that assumption: at which point PathStep carries the rule identity from
> the walk and this branch goes away.

This is the third rule.

## Non-goals

Recorded so they read as decisions rather than oversights. Each gets a `ponytail:` comment at
the relevant place in code.

| Deferred | Why it is safe to defer |
| --- | --- |
| Migration cross-check for real column names | [08-framework-adapters](../08-framework-adapters/README.md) calls it more reliable than the property list. It is a second extractor for a precision gain on top of a rule that already works; the `$fillable` list is what the developer wrote and is enough to fire on. |
| `$hidden`, `$casts`, `$appends`, relationships, scopes | Extracted when a rule needs them. Slice 3 needs `$fillable` and `$guarded`. |
| Models reached through a repository or the container | Same receiver-resolution limit slices 1 and 2 already carry. |
| `$request->merge()` before the write, `Model::unguarded(fn() => ...)` | No fixture needs them, and both are rare enough to be worth a fixture first. |
| Traits contributing `$fillable` | Needs trait resolution, which no subsystem does yet. |
| SQLite persistence, CFG, facade and container resolution | Unchanged from the slice 1 and 2 deferral tables. |

## 1. Mass assignment is a taint kind, not a bespoke check

The obvious reading of [13-security-engine](../13-security-engine/README.md) §2 - "structural
rules, no taint required" - would make this a separate traversal. That is the wrong shape here,
because half the condition genuinely is a taint question: request data has to *reach* the write.
Building a second walk to answer "did request data get here" when a walk that answers exactly
that already exists would be a second analysis path, which
[02-architecture](../02-architecture/README.md) forbids for MCP and desktop and which is no more
attractive inside the engine.

So the rule is expressed as a taint kind plus a structural gate on the sink:

```python
class TaintKind(StrEnum):
    SQL = "sql"
    HTML = "html"
    MASS_ASSIGN = "mass_assign"     # new
```

**This adds a twelfth kind to the eleven in
[06-taint-analysis](../06-taint-analysis/README.md), so that document gains a row in the same
commit**, per the docs-are-the-spec rule in CLAUDE.md:

| Kind | Dangerous at | Cleared by |
| --- | --- | --- |
| `mass_assign` | Eloquent array writes on a model with protection disabled | `validated()`, `safe()`, `only([...])`, an explicit array literal |

The kind earns its place by the same test `models.py` already applies to the other nine: it
arrives with both sinks and sanitizers wired, so it never claims reasoning the engine cannot do.

## 2. Sources gain per-method kind sets

Today every source method marks a value `ALL_KINDS`. That is wrong for the new kind, and the
wrongness is the safe case in the Goal:

```php
User::create($request->only(['name', 'email']));   // safe: explicit allowlist
User::create($request->except(['is_admin']));      // NOT safe: blacklist, misses new columns
User::create($request->validated());               // safe: only validated keys survive
```

`only()` is in `SOURCE_METHODS` today and would carry `MASS_ASSIGN` into the sink. So the flat
set becomes a mapping:

```python
SOURCE_METHODS: dict[str, frozenset[TaintKind]]
```

| Method | Kinds | Why |
| --- | --- | --- |
| `input`, `get`, `all`, `query`, `except`, `header`, … | `ALL_KINDS` | Attacker chooses the keys. |
| `only` | `ALL_KINDS - {MASS_ASSIGN}` | The developer chose the keys. Still XSS- and SQL-dangerous. |
| `validated`, `safe` (new sources) | `ALL_KINDS - {MASS_ASSIGN}` | Only rule-covered keys survive. |

Adding `validated`/`safe` as sources is a bonus correctness fix unrelated to this rule:
[06-taint-analysis](../06-taint-analysis/README.md) line 45 states that validated input is
**still tainted with reduced kinds**, and today it produces no taint at all, so
`{!! $request->validated()['bio'] !!}` is a false negative. This slice closes it.

`except()` staying dangerous is deliberate and is the kind of detail that decides whether a
security tool is trusted: a blacklist does not protect the column added next month.

## 3. Inline sources

The canonical spec example has no intermediate variable:

```php
User::create($request->all());
```

Source recognition currently lives in `_walk_method`'s assignment branch, so it only fires on
`$x = $request->all()`. `expr_kinds` on the inline form walks into `member_call_expression`,
finds no sanitizer, unions its children, sees `$request` is not in `local`, and returns empty.
The sink would never fire.

Source recognition therefore **moves into `expr_kinds`**, which already recurses over exactly
the right shapes:

```python
def expr_kinds(node, source, local, request_vars) -> frozenset[TaintKind]:
```

The assignment branch in `_walk_method` loses its duplicate source detection and keeps only the
`PathStep` emission - it still needs to know *that* a source was crossed in order to record it.

This is a net deletion, and it fixes a second live false negative that predates this slice:
`whereRaw($request->input('sort'))` written inline is not reported today. It is after this
change. Slice 2 made the same kind of incidental fix to `intval()`, and the same rule applies:
the regression test for it belongs in this slice.

## 4. Model extraction

New module `src/laravel/models.py`. `ClassInfo` in `symbols.py` grows two fields, because both
are language facts rather than Laravel facts and the parser layer may not know what Eloquent is:

```python
@dataclass(frozen=True)
class ClassInfo:
    ...
    parent: str | None = None                        # resolved base class FQN
    array_props: dict[str, tuple[str, ...]] = ...    # $guarded/$fillable literal contents
```

Both come from node shapes verified against the real grammar before writing this:

- `class_declaration` has **no** `base_clause` field; the child of type `base_clause` is scanned
  for its `name`, then resolved through the existing import table.
- `protected $guarded = []` has **no** `type` field, which is why `symbols.py`'s current
  property loop skips it entirely - it requires a type node. The value hangs off
  `property_element`'s `default_value` field as an `array_creation_expression`.

Only array literals are recorded. `protected $fillable = self::FIELDS;` records nothing, and
"nothing" is distinguishable from "an empty array" because the key is absent rather than mapped
to `()`. That distinction carries the whole rule, so it is a `dict` membership test and never a
truthiness test.

`laravel/models.py` then answers two questions:

```python
def is_model(project, fqn) -> bool           # walks the parent chain
def protection(project, fqn) -> Protection   # OPEN | PRIVILEGED_FILLABLE | GUARDED
```

**`is_model`** walks `parent` upwards. A chain terminating in
`Illuminate\Database\Eloquent\Model`, `...\Pivot`, or `Illuminate\Foundation\Auth\User` is a
model. Laravel is not in `vendor/` in a fixture and is excluded from the walk in a real project,
so the chain ends at an unresolvable name: a parent whose short name is `Model`,
`Authenticatable` or `Pivot` counts, which is what the base classes are actually called at the
point a user's model extends them.

**`protection`** returns:

| Result | Condition |
| --- | --- |
| `OPEN` | `$guarded` present and empty - protection fully disabled |
| `PRIVILEGED_FILLABLE` | `$fillable` present and containing a privileged column |
| `GUARDED` | anything else, including a model declaring neither |

A model declaring neither is `GUARDED` and produces nothing. This is correct rather than
conservative: Eloquent's `Model::$guarded` defaults to `['*']`, so a model that configures
nothing is not mass-assignable at all. Getting this backwards would fire on every model in
every codebase, which is the failure mode CLAUDE.md describes for `*Raw`.

### Privileged columns

The heuristic, and the only one in the slice. From
[08-framework-adapters](../08-framework-adapters/README.md):

```python
PRIVILEGED_COLUMN = re.compile(
    r"^(is_)?(admin|superuser|staff)|^role(_id)?$|^permissions?$|"
    r"^(email_)?verified(_at)?$|^balance$|^price$|^(owner|user|account)_id$"
)
```

Anchored, not a substring search. `substring` matching turns `user_id` into a hit on
`contributor_id_hash` and the rule stops being read. The finding text names the matched column
so the developer can see the tool's reasoning and disagree with it in one glance.

## 5. Sinks

`SINKS` gains entries whose kind is `MASS_ASSIGN`. Two forms, and the second is why
`scoped_call_expression` finally enters the walk - a gap `laravel/vocabulary.py:36-42` already
names.

| Call | Tainted argument | Notes |
| --- | --- | --- |
| `User::create($data)` | 0 | |
| `User::make($data)`, `User::firstOrNew($data)`, `User::firstOrCreate($data)` | 0 | |
| `User::updateOrCreate($match, $data)` | **1** | Argument 0 is the lookup, not the write |
| `User::forceCreate($data)` | 0 | Bypasses protection |
| `$user->update($data)`, `$user->fill($data)` | 0 | |
| `$user->forceFill($data)` | 0 | Bypasses protection |

`updateOrCreate` is the `whereRaw('age > ?', [$age])` of this rule: flagging argument 0 would
report the safe lookup array and teach people the rule is noise.

**The `force*` pair fires on any model**, guarded or not. That is what "force" means in
Eloquent - it is the documented bypass of both `$fillable` and `$guarded` - so gating it on
model configuration would suppress the strongest true positive the rule has.

### Receiver resolution for the instance form

`$user->update(...)` needs to know that `$user` is a `User`. The walk gains a second local map
alongside `local`:

```python
local_types: dict[str, str]      # variable name -> class FQN
```

populated from three shapes, all already visible in the statement walk:

| Shape | Binding |
| --- | --- |
| `$u = User::find($id)` and any other static call on a model class | `u -> App\Models\User` |
| `$u = new User(...)` | `u -> App\Models\User` |
| `public function update(Request $r, Order $order)` | `order -> App\Models\Order` |

The third is route-model binding, and it is the form that matters most: `$order->update(
$request->all())` in a controller whose signature binds the model is idiomatic Laravel and is
where this bug actually ships.

A receiver that resolves to no known class is a give-up, counted only when tainted data was
being passed, consistent with the rule slice 1 and 2 already follow.

## 6. The sink carries its rule

`PathStep` gains one field:

```python
@dataclass(frozen=True)
class PathStep:
    ...
    rule_id: str = ""      # set on sink steps; "" everywhere else
```

`rules.py` looks the rule up by that string instead of sniffing the sink's file extension, and
the `ponytail:` comment at `rules.py:51-57` is deleted along with the branch it explains. The
default of `""` keeps every non-sink construction site unchanged.

This is the smallest form of the change the comment asked for. A richer `Rule` object on the
step would be nicer to read and would put the security engine's vocabulary inside the taint
engine, which the layering rule in CLAUDE.md forbids: the graph layer knows about kinds, not
about rules. A string that the security engine interprets keeps the dependency pointing the
right way.

## 7. The rule

```
id:          laravel.mass-assignment
title:       Mass Assignment
severity:    high
cwe:         CWE-915
kind:        structural (taint-gated)
```

The ID comes from [08-framework-adapters](../08-framework-adapters/README.md) line 170 and
[13-security-engine](../13-security-engine/README.md) line 12, which both spell it
`laravel.mass-assignment`. It is `laravel.` rather than `php.` because the rule is meaningless
outside Eloquent. Invariant 7 makes this permanent from the moment it is written, so it is taken
from the spec rather than invented to match the existing `php.` prefixes.

Remediation names the model and the fix that actually gets applied:

> Replace `$guarded = []` with an explicit `$fillable` listing only the columns a user may set,
> or pass `$request->validated()` / `$request->only([...])` instead of `$request->all()`.
> `App\Models\User` currently accepts every column, including `is_admin`.

## 8. Evidence path

Five steps, one more than slices 1 and 2, because the model configuration is evidence and
invariant 2 requires it to be on the path rather than in prose:

```
1. routes/api.php:11        entry    POST /users -> App\Http\Controllers\UserController::store
2. UserController.php:18    source   $request->all()          attacker-controlled request data
3. Models/User.php:9        model    protected $guarded = []  mass assignment protection disabled
4. UserController.php:18    sink     User::create($request->all())
```

The model step's `role` is `"model"`, a new value in `PathStep`'s documented set. Its span points
at the property declaration in the model file, so `vigilloo scan` prints the line the developer
has to change, which is not the line the finding is reported on.

## 9. Error handling and coverage

- A model class the walk cannot resolve is a give-up, counted only when tainted data reached the
  call. Unchanged rule from slices 1 and 2.
- `$fillable` built from a constant or a method call records nothing and is treated as `GUARDED`.
  This under-reports, and it is the right direction: the alternative is guessing the contents of
  an array the tool cannot see.
- A `force*` call on a class that is not a known model is not reported. `forceFill` is not a
  reserved word and reporting it on an arbitrary object would be a fabricated path.

## 10. Tests

The fixture gains `app/Models/User.php` (`$guarded = []`), `app/Models/Post.php`
(`$fillable = ['title', 'body']`), `app/Models/Profile.php`
(`$fillable = ['name', 'is_admin']`), a `UserController` and the routes that reach them.

| Case | Expected |
| --- | --- |
| `User::create($request->all())`, `$guarded = []` | finding |
| `Post::create($request->all())`, narrow `$fillable` | **no finding** |
| `Profile::create($request->all())`, privileged `$fillable` | finding, names `is_admin` |
| `User::create($request->only(['name']))` | **no finding** |
| `User::create($request->validated())` | **no finding** |
| `User::updateOrCreate($request->all(), ['x' => 1])` | **no finding** - taint in argument 0 |
| `$post->forceFill($request->all())`, narrow `$fillable` | finding - force bypasses |
| `$order->update($request->all())` via route-model binding | finding |
| `whereRaw($request->input('sort'))` inline | finding - the §3 regression |
| existing SQL and XSS paths | unchanged, byte-identical |

Rows two, four, five and six carry the slice. Row ten is the regression guard: this change moves
source recognition and rewrites the sink dispatch, so slices 1 and 2 must come out identical,
including every `id` and `fingerprint`.

## 11. Order of work

1. `PathStep.rule_id`, `rules.py` dispatching on it, the extension branch deleted. **Slices 1
   and 2 must still pass here**, before any new rule exists. Behaviour-preserving checkpoint.
2. `SOURCE_METHODS` becomes a kind mapping; source recognition moves into `expr_kinds`. Green
   gate again, plus the inline-source regression test.
3. `symbols.py`: `parent` and `array_props`. Pure extraction, unit-tested alone.
4. `laravel/models.py`: `is_model`, `protection`, the privileged-column pattern.
5. `scoped_call_expression` in the walk, and `local_types`.
6. `MASS_ASSIGN`, the sink table entries, the rule, the fixture, the ten assertions.
7. `docs/06-taint-analysis` gains the `mass_assign` row; `CLAUDE.md` records what shipped.
   `docs/08-framework-adapters` needs no edit - its rule table already specifies
   `laravel.mass-assignment` exactly as implemented, which is the point of writing the spec
   first.

Steps 1 and 2 are the risk and are deliberately sequenced first, each behind a green suite, so a
refactor of the engine's dispatch and a new rule are never being debugged at the same time.
