"""Structural findings: vulnerabilities that are a property of the wiring.

The taint walk answers "does attacker data reach a dangerous call". This module
answers a different question - "is this route missing a control it should have"
- and there is no tainted value anywhere in the answer. Keeping it beside
taint.py rather than inside it is the layering rule: a structural rule reads the
graph and the framework model and never touches taint state.

Both modules produce the same thing, a list of PathStep whose last step names
its rule, so rules.py consumes them identically and Finding needs no new field.
"""

import re

from tree_sitter import Node

from .graph import Project
from .laravel.middleware import authenticated_by, is_gated
from .laravel.models import is_model
from .laravel.policies import find_policy
from .laravel.routes import uri_params
from .laravel.vocabulary import MISSING_AUTHORIZATION_RULE
from .models import PathStep, Route
from .parser import ParsedFile, find_all, node_text

_AUTHORIZE_METHODS = frozenset(
    {
        "authorize",
        "authorizeForUser",
        "authorizeResource",
        # ->can()/->cannot()/->cant() on any receiver: $request->user()->can(...),
        # $user->cannot(...), auth()->user()->can(...). The receiver is not
        # checked, because every plausible receiver of a method with this name
        # is an authorization check, and demanding a resolved receiver would
        # turn a guarded action into a reported one.
        "can",
        "cannot",
        "cant",
        "canAny",
    }
)

# Gate::allows(...) and friends.
_GATE_METHODS = frozenset(
    {"allows", "denies", "authorize", "check", "any", "none", "inspect", "forUser"}
)

# A FormRequest::authorize() that does this is not authorization. It is the
# stub Laravel's make:request generates, and treating it as a control is the
# first of the two Laravel traps in docs/08-framework-adapters.
_RETURNS_TRUE = re.compile(r"^\{\s*return\s+true\s*;?\s*\}$")


def _calls_authorization(node: Node, source: bytes) -> bool:
    """Does this subtree contain an authorization check?"""
    for call in find_all(node, "member_call_expression"):
        if node_text(call.child_by_field_name("name"), source) in _AUTHORIZE_METHODS:
            return True
    for call in find_all(node, "scoped_call_expression"):
        scope = node_text(call.child_by_field_name("scope"), source).rsplit("\\", 1)[-1]
        name = node_text(call.child_by_field_name("name"), source)
        if scope == "Gate" and name in _GATE_METHODS:
            return True
    return False


def _form_request_authorizes(project: Project, param_type: str) -> bool:
    """Does a parameter of this type carry a real authorize() check?

    Identified by having an authorize() method. Laravel's base class lives in
    vendor/ and is not scanned, and a request-shaped class with an authorize()
    method is a FormRequest for every purpose this rule has.
    """
    found = project.method_node(f"{param_type}::authorize")
    if found is None:
        return False
    method, parsed = found
    body = method.child_by_field_name("body")
    if body is None:
        return False
    return not _RETURNS_TRUE.match(" ".join(node_text(body, parsed.source).split()))


def _controller_authorizes(project: Project, class_fqn: str) -> bool:
    """Does the controller authorize every one of its actions at once?

    $this->authorizeResource(Order::class) in the constructor maps the resource
    methods onto policy abilities. Deliberately coarse: a controller that calls
    it is silent for all of its actions, because being precise about which
    methods it covers risks reporting an action that is in fact guarded.
    """
    found = project.method_node(f"{class_fqn}::__construct")
    if found is None:
        return False
    method, parsed = found
    return any(
        node_text(call.child_by_field_name("name"), parsed.source) == "authorizeResource"
        for call in find_all(method, "member_call_expression")
    )


def _binding(project: Project, route: Route, fqn: str) -> tuple[str, str] | None:
    """The (parameter name, model FQN) this route binds from its URI, if any.

    A {param} with no matching parameter in the signature is not a binding -
    Laravel passes it as a string and there is no record to authorize. A
    parameter typed to a class the project does not contain is not one either:
    it may be a model from a package, and guessing would fabricate a path.
    """
    symbol = project.method(fqn)
    if symbol is None:
        return None
    params = uri_params(route.uri)
    for name, declared in zip(symbol.params, symbol.param_types, strict=True):
        if not declared:
            continue
        resolved = project.resolve_class_name(symbol.span.file, declared)
        target = resolved if (resolved and resolved in project.classes) else declared
        if name in params and target and target in project.classes:
            if is_model(project.classes, target):
                return name, target
    return None


def _signature(method: Node, parsed: ParsedFile) -> str:
    """The declaration line of a method, without its body."""
    return node_text(method, parsed.source).split("\n", 1)[0].split("{", 1)[0].strip()


def _missing_authorization(project: Project, route: Route) -> list[PathStep] | None:
    """The evidence path for an unauthorized model-bound route, if it is one.

    All four conditions from the design must hold: a URI parameter, bound to a
    model, on an authenticated route, with no authorization anywhere.

    Requiring authentication is what makes the rule usable rather than merely
    correct. `GET /posts/{post}` on a blog is model-bound, has no policy and is
    entirely right; without this condition the rule fires on every public detail
    page ever written. The cost is stated rather than hidden: an unauthenticated
    model-bound route is laravel.unauthenticated-route, a different rule with
    different advice, and merging the two would give half the instances the
    wrong remediation.
    """
    if not route.action_fqn:
        return None

    auth_middleware = authenticated_by(route)
    if auth_middleware is None or is_gated(project, route):
        return None

    bound = _binding(project, route, route.action_fqn)
    if bound is None:
        return None
    param, model_fqn = bound

    found = project.method_node(route.action_fqn)
    if found is None:
        return None
    method, parsed = found

    if _calls_authorization(method, parsed.source):
        return None
    if _controller_authorizes(project, route.action_fqn.rpartition("::")[0]):
        return None

    symbol = project.method(route.action_fqn)
    assert symbol is not None  # method_node already resolved it
    for declared in symbol.param_types:
        if declared and _form_request_authorizes(project, declared):
            return None

    model_short = model_fqn.rsplit("\\", 1)[-1]
    steps = [
        PathStep(
            role="entry",
            span=route.span,
            snippet=f"{'|'.join(route.verbs)} {route.uri} -> {route.action_fqn}",
            note=f"authenticated by: {auth_middleware}",
        ),
        PathStep(
            role="binding",
            span=symbol.span,
            snippet=f"{model_short} ${param}",
            note=f"{{{param}}} is resolved from the URL by route-model binding",
        ),
    ]

    # The policy does not gate the finding - an uncalled policy and a missing
    # one are both an IDOR. It decides which of the two the report says, and
    # "the policy you wrote is never consulted" is the more damning of the two
    # and the faster one to act on. When there is no policy class the step is
    # omitted entirely and the gap step carries the fact instead: a step that
    # says "nothing here" is worse than no step.
    policy_fqn = find_policy(project.classes, model_fqn, project.policies)
    if policy_fqn is not None:
        steps.append(
            PathStep(
                role="policy",
                span=project.classes[policy_fqn].span,
                snippet=policy_fqn,
                note="exists and this action never consults it",
            )
        )
        gap_note = "no authorize(), no can: middleware, no Gate check"
    else:
        gap_note = f"no policy is defined for {model_fqn}, and nothing else authorizes this action"

    steps.append(
        PathStep(
            role="gap",
            span=symbol.span,
            snippet=_signature(method, parsed),
            note=gap_note,
            rule_id=MISSING_AUTHORIZATION_RULE,
        )
    )
    return steps


def find_structural_paths(project: Project) -> list[list[PathStep]]:
    """Every structural finding's evidence path, in deterministic order."""
    paths = [
        steps
        for route in project.routes
        if (steps := _missing_authorization(project, route)) is not None
    ]
    return sorted(paths, key=lambda p: (str(p[-1].span.file), p[-1].span.start_line))
