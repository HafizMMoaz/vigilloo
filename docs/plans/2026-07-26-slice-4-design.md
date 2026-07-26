# Slice 4 Design: IDOR - Model-Bound Routes With No Authorization

**Status:** implemented.
**Supersedes nothing.** Builds on slices 1 to 3.
**Normative references:** [08-framework-adapters](../08-framework-adapters/README.md),
[13-security-engine](../13-security-engine/README.md), [07-call-graph](../07-call-graph/README.md).
Where this document and those disagree, those win and this is the bug.

## Goal

`vigilloo scan` reports an IDOR whose evidence path runs from an authenticated route, through
the model bound to its URI parameter, past the policy that exists and is never consulted, to the
action that returns the record. In the same run:

- the same action with `$this->authorize('view', $order)` produces **no** finding,
- the same route with `can:view,order` middleware produces **no** finding, and
- an unauthenticated public route with model binding produces **no** finding.

The third negative is the one that decides whether this rule is usable. `GET /posts/{post}` on
a blog is model-bound, has no policy, and is entirely correct. A rule that cannot tell it from
`GET /invoices/{invoice}` fires on every public detail page in every application, and gets
switched off in a week.

## Why this slice

[08-framework-adapters](../08-framework-adapters/README.md) calls this "the high-value query
this enables", and it is the one CLAUDE.md names first under Laravel-structural rules. It also
completes A01 Broken Access Control alongside slice 3's mass assignment.

Practically, slice 3 already built two of the four things it needs: model identification
(`laravel/models.is_model`) and parameter type resolution on controller actions. The remaining
two - the middleware stack and the policy map - are the last pieces of the route table that
every other access-control rule in
[13-security-engine](../13-security-engine/README.md) §2 also wants.

## Non-goals

Recorded so they read as decisions rather than oversights. Each gets a `ponytail:` comment at
the relevant place in code.

| Deferred | Why it is safe to defer |
| --- | --- |
| `Kernel.php` / `bootstrap/app.php` group expansion (`web`, `api` member lists) | Costs findings, never fabricates them: an unexpanded group reads as "not authenticated", and the rule requires authentication to fire. A missed finding, not a false one. |
| `AuthServiceProvider::$policies` explicit map | Laravel 8+ auto-discovers by naming convention, which is what the convention lookup implements. The explicit map is the override, and it only ever *adds* policies - so missing it can only downgrade an evidence note, never flip a verdict. |
| Custom middleware body analysis (`abort(403)` inference) | [08-framework-adapters](../08-framework-adapters/README.md) wants it. It is a heuristic over arbitrary code, and it belongs with the middleware rules rather than smuggled in here. |
| `@can` in Blade | Guards what is displayed, not what the action returns. An IDOR is not fixed by hiding the link. |
| Gate closures (`Gate::define`) as *definitions* | Only call sites matter for this rule. Whether the gate exists changes the evidence note, not the verdict. |
| Policy method defined but never referenced anywhere ("dead authorization") | Its own rule in [13-security-engine](../13-security-engine/README.md) §2, and it needs a whole-project cross-reference this slice does not build. |

## 1. The rule's gate

A finding requires **all** of:

1. The route's URI has a `{param}` segment.
2. The action's signature binds that parameter to a class that `is_model` accepts.
3. The route is **authenticated** - `auth`, `auth.basic` or `password.confirm` in its
   middleware. The guard argument is ignored, so `auth:sanctum` and `auth:api` count.
4. No authorization signal (section 3) anywhere on the route or in the action.

Condition 3 is the precision decision and the reason this rule is worth shipping. It encodes
exactly what [08-framework-adapters](../08-framework-adapters/README.md) means by "authenticated
but not authorized": the developer demonstrably thought about who the caller is, and never
thought about which records that caller may see. Without it the rule reports every public detail
route in every application.

The cost is honest and stated in the report: a genuinely unauthenticated model-bound route is
**not** reported by this rule. That case is `laravel.unauthenticated-route`, which is a
different rule with a different remediation, and conflating them would produce one finding whose
advice is wrong for half its instances.

## 2. Middleware, finally populated

`Route.middleware` exists in `models.py` and `routes.py` has always set it to `()`. This slice
fills it, because conditions 3 and 4 both read it.

Two shapes, both verified against the grammar before writing this:

```php
Route::get('/invoices/{invoice}', [C::class, 'show'])->middleware('auth');
Route::middleware(['auth'])->group(function () {
    Route::get('/invoices/{invoice}', [C::class, 'show']);
});
```

`Route::get(...)` is a `scoped_call_expression`; the `->middleware(...)` chained onto it is a
`member_call_expression` whose **object** is that scoped call. So middleware is collected by
walking *up* from the route registration through enclosing member calls, not by looking at its
arguments.

The group form is collected by continuing that walk out through the enclosing closure to the
`->group(...)` call and its own chain. Group middleware is a real part of how Laravel
applications are written - a slice that only handled the inline chain would report nothing on a
typical `routes/api.php`.

Values are normalised to a flat tuple of strings: `'auth'`, `['auth', 'can:update,order']` and
`'auth:sanctum'` all end up as plain entries. A middleware argument that is not a string literal
(a variable, a class constant) is recorded as the unresolvable marker `?` rather than dropped,
so condition 4 can refuse to claim "no authorization present" over middleware it could not read.

**That marker is load-bearing.** Silently dropping unreadable middleware would turn "I cannot
tell" into "there is no protection here", which is a fabricated finding.

## 3. Authorization signals

Any one of these on the route or in the action clears condition 4:

| Signal | Where |
| --- | --- |
| `can:ability,model` middleware | route |
| unresolvable middleware (`?`) | route - refuses to claim the gap |
| `$this->authorize(...)`, `$this->authorizeForUser(...)` | action body |
| `Gate::allows/denies/authorize/check/any/none` | action body |
| `->can(...)` / `->cannot(...)` on any receiver | action body |
| `$this->authorizeResource(...)` | the controller's constructor, covering every action |
| a parameter whose type declares an `authorize()` that is not `return true` | action signature |

The FormRequest row implements the first of the two Laravel traps in
[08-framework-adapters](../08-framework-adapters/README.md) line 108: `authorize()` returning a
bare `true` is not authorization, and must not clear the condition. Anything else in that method
is treated as a real check.

`authorizeResource` is deliberately coarse. It authorizes the whole controller, so a controller
that calls it is silent for every one of its actions. Being more precise about which resource
methods it maps to would risk claiming an action is unguarded when it is not.

## 4. Policy discovery

New module `src/laravel/policies.py`. It does not gate the finding - a missing policy and an
uncalled policy are both IDOR - it makes the evidence path say which of the two it is:

| Situation | Evidence note |
| --- | --- |
| `OrderPolicy` exists | `App\Policies\OrderPolicy exists and this action never consults it` |
| no policy class found | `no policy is defined for App\Models\Order` |

Discovery is by Laravel's own auto-discovery convention: model `App\Models\Order` maps to a
class named `OrderPolicy`, looked up among the project's known classes. That is one dict lookup
over data slice 3 already collects, and it is what Laravel 8+ actually does at runtime.

The first note is the more damning finding of the two, and it is the one a reviewer acts on
fastest, which is why it is worth the module rather than printing "no authorization" and
stopping.

## 5. A second finding producer

This is the first rule with no taint in it at all, and it changes the pipeline's shape.
`rules.py::scan_project` currently has exactly one source of evidence paths:

```python
for path in find_taint_paths(project, stats=stats):
```

Slice 4 adds `src/structural.py` with `find_structural_paths(project)`, and `scan_project`
concatenates the two producers before sorting. Both yield the same `list[PathStep]` shape and
both name their rule on the final step, so the dispatch built in slice 3 needs no change and
`Finding` needs no new field.

Keeping this in a module beside `taint.py` rather than inside it is the layering rule: a
structural rule reads the graph and the framework model and never touches taint state. Threading
it through `_walk_method` would put an authorization concept inside the taint walk, which is the
same violation as putting `Rule` objects on `PathStep`.

## 6. Evidence path

Four steps. The rule is a claim about something *absent*, so the path has to make the absence
concrete rather than asserting it in prose:

```
1. routes/api.php:9         entry    GET|HEAD /invoices/{invoice} -> InvoiceController::show
                                     authenticated by: auth
2. InvoiceController.php:14 binding  Invoice $invoice
                                     {invoice} is resolved from the URL by route-model binding
3. Policies/InvoicePolicy.php:7 policy  App\Policies\InvoicePolicy
                                     exists and this action never consults it
4. InvoiceController.php:14 gap      public function show(Invoice $invoice)
                                     no authorize(), no can: middleware, no Gate check
```

Two new `PathStep` role values, `binding` and `gap`, added to the documented set in
`models.py` alongside `model` from slice 3. The policy step is omitted entirely when no policy
class exists, and step 4's note carries "no policy is defined" instead - a step that says
"nothing here" is worse than no step.

Step 1's note names *which* middleware authenticated the route. The rule's whole premise is
condition 3, so the report has to show the reader the evidence for it.

## 7. Rule

```
id:          laravel.missing-authorization
title:       Missing Authorization on Model-Bound Route
severity:    high
cwe:         CWE-639
kind:        structural
```

ID and severity from [08-framework-adapters](../08-framework-adapters/README.md) line 171.
Permanent per invariant 7.

Remediation:

> Add `$this->authorize('view', $invoice)` as the first statement of the action, or attach
> `can:view,invoice` middleware to the route. Authenticating a request says who the caller is;
> it never says which records that caller may read.

## 8. Error handling and coverage

- A route whose action cannot be resolved is already counted as unresolved by slice 1. Unchanged.
- A `{param}` with no matching parameter in the signature is not a binding, and is not a finding.
  Laravel would pass it as a string; there is no model to authorize against.
- A bound parameter whose type resolves to a class the project does not contain is not a
  finding. It may be a model from a package, and guessing would fabricate a path.
- Unreadable middleware suppresses the finding (section 2) rather than being ignored.

## 9. Tests

The fixture gains `app/Models/{Invoice,Receipt}.php`, `app/Policies/InvoicePolicy.php`,
`app/Http/Requests/{Stub,Checked}InvoiceRequest.php`, `app/Support/Token.php`, an
`InvoiceController` with one action per row, a `ReceiptController` for `authorizeResource`,
and the routes. `Receipt` deliberately has no policy class.

| Case | Expected |
| --- | --- |
| authenticated, bound, no check, policy exists | finding, path names the policy |
| authenticated, bound, no check, **no** policy class | finding, note says no policy defined |
| `$this->authorize('view', $invoice)` in the action | **no finding** |
| `can:view,invoice` middleware on the route | **no finding** |
| `Gate::allows(...)` in the action | **no finding** |
| `$request->user()->can(...)` in the action | **no finding** |
| `authorizeResource()` in the constructor | **no finding** for any action |
| FormRequest param whose `authorize()` returns `true` | finding - validation is not authorization |
| FormRequest param whose `authorize()` checks something | **no finding** |
| **unauthenticated** public route, bound, no check | **no finding** |
| route inside `Route::middleware('auth')->group(...)` | finding - group middleware is read |
| unreadable middleware (`->middleware($m)`) | **no finding** - refuses to claim the gap |
| bound param typed to a non-model class | **no finding** |
| slices 1-3 findings | unchanged, byte-identical |

Rows 3 to 7, 9, 10, 12 and 13 carry the slice. Row 10 is the one that keeps it usable, and row
14 is the regression guard: this change rewrites the route extractor, which every earlier slice
depends on.

## 10. Order of work

1. Middleware collection in `routes.py`, both shapes, with `?` for the unreadable case.
   **Slices 1 to 3 must still pass here** - the route extractor is load-bearing for all of them.
2. `laravel/policies.py`, convention lookup, unit-tested alone.
3. Binding detection: URI parameter to model-typed signature parameter.
4. Authorization signal detection in the action body and the constructor.
5. `structural.py`, the second producer, wired into `scan_project`.
6. The rule, the fixture, the fourteen assertions.
7. `CLAUDE.md` records what shipped. `docs/08-framework-adapters` needs no edit; its rule table
   already specifies `laravel.missing-authorization` as implemented here.

Step 1 is the risk and is sequenced first behind a green suite, for the same reason slice 3
sequenced its dispatch refactor first: a change under every existing slice should never be
debugged at the same time as a new rule.
