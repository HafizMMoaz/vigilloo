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
from pathlib import Path

from tree_sitter import Node

from .graph import Project
from .laravel.middleware import authenticated_by, is_gated, is_rate_limited, is_signed
from .laravel.models import is_model
from .laravel.policies import find_policy
from .laravel.routes import uri_params
from .laravel.vocabulary import (
    LARAVEL_APP_KEY_RULE,
    LARAVEL_CSRF_EXCEPT_RULE,
    LARAVEL_DEAD_AUTHORIZATION_RULE,
    LARAVEL_DEBUG_ARTIFACT_RULE,
    LARAVEL_DEBUG_ENABLED_RULE,
    LARAVEL_ENV_OUTSIDE_CONFIG_RULE,
    LARAVEL_FORM_REQUEST_TRUE_RULE,
    LARAVEL_INCONSISTENT_AUTHORIZATION_RULE,
    LARAVEL_NO_THROTTLE_RULE,
    LARAVEL_SESSION_COOKIE_RULE,
    LARAVEL_TRUSTED_PROXIES_RULE,
    LARAVEL_UNAUTHENTICATED_ROUTE_RULE,
    LARAVEL_UNSAFE_UPLOAD_RULE,
    LARAVEL_UNSIGNED_ROUTE_RULE,
    LARAVEL_VALIDATED_BYPASS_RULE,
    LARAVEL_WEAK_HASH_RULE,
    LARAVEL_WEAK_RANDOMNESS_RULE,
    MISSING_AUTHORIZATION_RULE,
)
from .models import PathStep, Route, Span
from .parser import ParsedFile, find_all, node_span, node_text

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


def _form_request_returns_true(project: Project, param_type: str) -> tuple[Node, ParsedFile] | None:
    found = project.method_node(f"{param_type}::authorize")
    if found is None:
        return None
    method, parsed = found
    body = method.child_by_field_name("body")
    if body is None:
        return None
    if _RETURNS_TRUE.match(" ".join(node_text(body, parsed.source).split())):
        return method, parsed
    return None


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

    form_request_true = None
    for declared in symbol.param_types:
        if not declared:
            continue
        if _form_request_authorizes(project, declared):
            return None
        if form_request_true is None:
            form_request_true = _form_request_returns_true(project, declared)

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

    if form_request_true:
        auth_method, auth_parsed = form_request_true
        steps.append(
            PathStep(
                role="gap",
                span=node_span(auth_method, auth_parsed.path),
                snippet=_signature(auth_method, auth_parsed),
                note="unconditionally returns true, bypassing authorization",
                rule_id=LARAVEL_FORM_REQUEST_TRUE_RULE,
            )
        )
    else:
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


def _is_state_changing(project: Project, path_str: str) -> bool:
    if "*" in path_str:
        return True

    normalized_path = "/" + path_str.lstrip("/")
    state_changing_verbs = {"POST", "PUT", "PATCH", "DELETE"}

    for route in project.routes:
        route_uri = "/" + route.uri.lstrip("/")
        if route_uri == normalized_path:
            if any(verb in state_changing_verbs for verb in route.verbs):
                return True
    return False


def _extract_csrf_except(project: Project) -> list[tuple[Span, str]]:
    results = []

    # 1. VerifyCsrfToken::$except (Laravel 10-)
    for fqn, class_info in project.classes.items():
        if "VerifyCsrfToken" in fqn or (
            class_info.parent and "VerifyCsrfToken" in class_info.parent
        ):
            parsed = project.files.get(class_info.span.file)
            if not parsed:
                continue

            for prop in find_all(parsed.tree.root_node, "property_declaration"):
                for elem in find_all(prop, "property_element"):
                    if node_text(elem.child_by_field_name("name"), parsed.source) == "$except":
                        default_value = elem.child_by_field_name("default_value")
                        if default_value and default_value.type == "array_creation_expression":
                            for child in default_value.children:
                                if child.type == "array_element_initializer":
                                    val_node = child.children[0]
                                    if val_node.type in ("string", "encapsed_string"):
                                        val = (
                                            parsed.source[val_node.start_byte : val_node.end_byte]
                                            .decode("utf-8")
                                            .strip("'\"")
                                        )
                                        results.append((node_span(val_node, parsed.path), val))

    # 2. bootstrap/app.php validateCsrfTokens(except: [...]) (Laravel 11+)
    for path, parsed in project.files.items():
        if path.name == "app.php" and path.parent.name == "bootstrap":
            for call in find_all(parsed.tree.root_node, "member_call_expression"):
                name = call.child_by_field_name("name")
                if name and node_text(name, parsed.source) == "validateCsrfTokens":
                    args = call.child_by_field_name("arguments")
                    if args:
                        for arg in args.children:
                            if arg.type == "argument":
                                arg_name = arg.child_by_field_name("name")
                                if arg_name and node_text(arg_name, parsed.source) == "except":
                                    arg_val = arg.child_by_field_name("value")
                                    if arg_val and arg_val.type == "array_creation_expression":
                                        for child in arg_val.children:
                                            if child.type == "array_element_initializer":
                                                val_node = child.children[0]
                                                if val_node.type in ("string", "encapsed_string"):
                                                    s = (
                                                        parsed.source[
                                                            val_node.start_byte : val_node.end_byte
                                                        ]
                                                        .decode("utf-8")
                                                        .strip("'\"")
                                                    )
                                                    results.append(
                                                        (node_span(val_node, parsed.path), s)
                                                    )
    return results


def _csrf_except_paths(project: Project) -> list[list[PathStep]]:
    paths = []
    for span, path_str in _extract_csrf_except(project):
        if _is_state_changing(project, path_str):
            reason = "wildcard" if "*" in path_str else "state-changing route"
            step = PathStep(
                role="gap",
                span=span,
                snippet=path_str,
                note=f"disables CSRF protection for a {reason}",
                rule_id=LARAVEL_CSRF_EXCEPT_RULE,
            )
            paths.append([step])
    return paths


def _unauthenticated_route_paths(route: Route) -> list[PathStep] | None:
    if authenticated_by(route) is not None:
        return None

    state_changing_verbs = {"POST", "PUT", "PATCH", "DELETE"}
    if not any(verb in state_changing_verbs for verb in route.verbs):
        return None

    if is_signed(route):
        return None

    return [
        PathStep(
            role="gap",
            span=route.span,
            snippet=f"{'|'.join(route.verbs)} {route.uri}",
            note="state-changing route with no auth middleware",
            rule_id=LARAVEL_UNAUTHENTICATED_ROUTE_RULE,
        )
    ]


def _no_throttle_paths(route: Route) -> list[PathStep] | None:
    if "POST" not in route.verbs:
        return None

    auth_uris = {
        "login",
        "register",
        "password/email",
        "password/reset",
        "forgot-password",
        "reset-password",
    }
    normalized_uri = route.uri.strip("/")

    action = route.action_fqn or ""
    is_auth_route = normalized_uri in auth_uris or any(
        x in action
        for x in (
            "LoginController",
            "RegisterController",
            "ResetPasswordController",
            "ForgotPasswordController",
            "NewPasswordController",
            "AuthenticatedSessionController",
            "RegisteredUserController",
            "PasswordResetLinkController",
        )
    )

    if not is_auth_route:
        return None

    if is_rate_limited(route):
        return None

    return [
        PathStep(
            role="gap",
            span=route.span,
            snippet=f"{'|'.join(route.verbs)} {route.uri}",
            note="authentication route with no rate limiting middleware",
            rule_id=LARAVEL_NO_THROTTLE_RULE,
        )
    ]


def _unsigned_route_paths(route: Route) -> list[PathStep] | None:
    action_keywords = {"unsubscribe", "confirm", "approve"}
    normalized_uri = route.uri.lower()

    if not any(keyword in normalized_uri for keyword in action_keywords):
        return None

    if authenticated_by(route) is not None:
        return None

    if is_signed(route):
        return None

    return [
        PathStep(
            role="gap",
            span=route.span,
            snippet=f"{'|'.join(route.verbs)} {route.uri}",
            note="public action route missing signed middleware",
            rule_id=LARAVEL_UNSIGNED_ROUTE_RULE,
        )
    ]


def _dead_authorization_paths(project: Project) -> list[list[PathStep]]:
    paths: list[list[PathStep]] = []
    policy_fqns = set(project.policies.values())
    for fqn in project.classes:
        if fqn.endswith("Policy"):
            policy_fqns.add(fqn)

    if not policy_fqns:
        return paths

    abilities = set()
    has_authorize_resource = False

    can_re = re.compile(r'@can(?:not|any)?\(\s*[\'"]([^\'"]+)[\'"]')
    for text_lines in project.blade_lines.values():
        for line in text_lines:
            for match in can_re.finditer(line):
                abilities.add(match.group(1))

    authorize_methods = {"authorize", "can", "cannot", "allows", "denies", "check"}

    for parsed in project.files.values():
        for call in find_all(parsed.tree.root_node, "call_expression"):
            name_node = None
            if call.type == "member_call_expression":
                name_node = call.child_by_field_name("name")
            elif call.type == "scoped_call_expression":
                name_node = call.child_by_field_name("name")

            if name_node is None:
                continue

            name_text = node_text(name_node, parsed.source)
            if name_text == "authorizeResource":
                has_authorize_resource = True
                continue

            if name_text in authorize_methods:
                args_node = call.child_by_field_name("arguments")
                if args_node is not None:
                    real_args = [c for c in args_node.children if c.type not in ("(", ")", ",")]
                    if real_args:
                        arg_text = node_text(real_args[0], parsed.source).strip()
                        if arg_text.startswith(("'", '"')):
                            abilities.add(arg_text.strip("'\""))

    for route in project.routes:
        for mw in route.middleware:
            if mw.startswith("can:"):
                params = mw[4:].split(",")
                if params:
                    abilities.add(params[0])

    if has_authorize_resource:
        abilities.update(
            {"viewAny", "view", "create", "update", "delete", "restore", "forceDelete"}
        )

    for fqn in sorted(policy_fqns):
        class_info = project.classes.get(fqn)
        if not class_info:
            continue

        for method_name, symbol in class_info.methods.items():
            if method_name.startswith("__"):
                continue
            if method_name == "before":
                continue

            if method_name not in abilities:
                method_node_data = project.method_node(f"{fqn}::{method_name}")
                if not method_node_data:
                    continue

                method_node, parsed = method_node_data
                snippet = _signature(method_node, parsed)
                step = PathStep(
                    role="gap",
                    span=symbol.span,
                    snippet=snippet,
                    note="policy method is never referenced",
                    rule_id=LARAVEL_DEAD_AUTHORIZATION_RULE,
                )
                paths.append([step])

    return paths


def _inconsistent_authorization_paths(project: Project) -> list[list[PathStep]]:
    paths = []

    # Map controller FQN to unique action_fqns and their Route
    controller_actions: dict[str, dict[str, Route]] = {}
    for route in project.routes:
        if not route.action_fqn or "::" not in route.action_fqn:
            continue

        fqn, method = route.action_fqn.split("::", 1)
        if fqn not in controller_actions:
            controller_actions[fqn] = {}
        # Keep the first route for this action
        if route.action_fqn not in controller_actions[fqn]:
            controller_actions[fqn][route.action_fqn] = route

    for fqn, actions in controller_actions.items():
        if len(actions) < 2:
            continue

        if _controller_authorizes(project, fqn):
            continue

        authorized_actions = []
        unauthorized_actions = []

        for action_fqn, route in actions.items():
            if is_gated(project, route):
                authorized_actions.append(action_fqn)
                continue

            found = project.method_node(action_fqn)
            if not found:
                unauthorized_actions.append(action_fqn)
                continue

            method_node, method_parsed = found
            if _calls_authorization(method_node, method_parsed.source):
                authorized_actions.append(action_fqn)
                continue

            symbol = project.method(action_fqn)
            if symbol:
                is_auth = False
                for declared in symbol.param_types:
                    if declared and _form_request_authorizes(project, declared):
                        is_auth = True
                        break
                if is_auth:
                    authorized_actions.append(action_fqn)
                    continue

            unauthorized_actions.append(action_fqn)

        if authorized_actions and unauthorized_actions:
            for action_fqn in sorted(unauthorized_actions):
                route = actions[action_fqn]
                symbol = project.method(action_fqn)
                span = symbol.span if symbol else route.span

                snippet = ""
                found = project.method_node(action_fqn)
                if found:
                    snippet = _signature(found[0], found[1])

                controller_short = fqn.split("\\")[-1]
                step = PathStep(
                    role="gap",
                    span=span,
                    snippet=snippet,
                    note=(
                        f"action lacks authorization, but other actions in "
                        f"{controller_short} have it"
                    ),
                    rule_id=LARAVEL_INCONSISTENT_AUTHORIZATION_RULE,
                )
                paths.append([step])

    return paths


def _validated_bypass_paths(project: Project) -> list[list[PathStep]]:
    paths = []

    from .laravel.validation import extract_validation_cleared

    for fqn, class_info in project.classes.items():
        for method_name, symbol in class_info.methods.items():
            found = project.method_node(f"{fqn}::{method_name}")
            if not found:
                continue

            method_node, parsed = found

            # Check if this method performs validation
            performs_validation = False

            # 1. Inline validation: $request->validate() or Validator::make()
            cleared = extract_validation_cleared(method_node, parsed.source)
            if cleared:
                performs_validation = True

            # 2. FormRequest parameter
            if not performs_validation:
                for param_type in symbol.param_types:
                    if not param_type:
                        continue
                    if param_type == "Illuminate\\Http\\Request" or param_type == "Request":
                        continue
                    if param_type.endswith("Request") and param_type in project.classes:
                        performs_validation = True
                        break
                    if project.method_node(f"{param_type}::rules"):
                        performs_validation = True
                        break

            if not performs_validation:
                continue

            # Method performs validation. Does it call ->all()?
            for call in find_all(method_node, "member_call_expression"):
                name_node = call.child_by_field_name("name")
                if not name_node or node_text(name_node, parsed.source) != "all":
                    continue

                obj_node = call.child_by_field_name("object")
                if not obj_node:
                    continue

                obj_text = node_text(obj_node, parsed.source)

                is_request = False
                if obj_text == "$request":
                    is_request = True
                elif obj_node.type == "call_expression":
                    call_name = obj_node.child_by_field_name("function")
                    if call_name and node_text(call_name, parsed.source) == "request":
                        is_request = True

                if is_request:
                    step = PathStep(
                        role="gap",
                        span=node_span(call, parsed.path),
                        snippet=node_text(call, parsed.source),
                        note="uses all() after validation instead of validated()",
                        rule_id=LARAVEL_VALIDATED_BYPASS_RULE,
                    )
                    paths.append([step])

    return paths


def find_structural_paths(project: Project) -> list[list[PathStep]]:
    """Every structural finding's evidence path, in deterministic order."""
    paths = [
        route_steps
        for route in project.routes
        if (route_steps := _missing_authorization(project, route)) is not None
    ]
    for route in project.routes:
        if (route_steps := _unauthenticated_route_paths(route)) is not None:
            paths.append(route_steps)
        if (route_steps := _no_throttle_paths(route)) is not None:
            paths.append(route_steps)
        if (route_steps := _unsigned_route_paths(route)) is not None:
            paths.append(route_steps)

    if (rule_paths := _env_outside_config_paths(project)) is not None:
        paths.extend(rule_paths)
    if (rule_paths := _unsafe_upload_paths(project)) is not None:
        paths.extend(rule_paths)
    if (rule_paths := _debug_artifact_paths(project)) is not None:
        paths.extend(rule_paths)
    if (rule_paths := _weak_hash_paths(project)) is not None:
        paths.extend(rule_paths)
    if (rule_paths := _weak_randomness_paths(project)) is not None:
        paths.extend(rule_paths)

    for except_path in _csrf_except_paths(project):
        paths.append(except_path)

    for auth_path in _dead_authorization_paths(project):
        paths.append(auth_path)
    for auth_path in _inconsistent_authorization_paths(project):
        paths.append(auth_path)
    for auth_path in _validated_bypass_paths(project):
        paths.append(auth_path)
    paths.extend(_config_rules_paths(project))
    paths.extend(_env_outside_config_paths(project))
    return sorted(paths, key=lambda p: (str(p[-1].span.file), p[-1].span.start_line))


def _config_rules_paths(project: Project) -> list[list[PathStep]]:
    paths = []
    config = project.config

    # laravel.debug-enabled
    app_debug = config.env_vars.get("APP_DEBUG", "").lower() in ("true", "1")
    if not app_debug and config.get("app.debug") is True:
        app_debug = True

    app_env = config.env_vars.get("APP_ENV", "").lower()
    if not app_env:
        app_env = config.get("app.env", "")

    # We only fire if APP_DEBUG=true and it's a real environment (not from .env.example)
    # The requirement: APP_DEBUG=true in a .env.example does not fire.
    is_real_env = config.env_file_exists or not config.env_example_exists

    if app_debug and is_real_env and app_env == "production":
        paths.append(
            [
                PathStep(
                    role="gap",
                    span=Span(file=Path(".env"), start_line=1, start_col=1, end_line=1, end_col=1),
                    snippet="APP_DEBUG=true",
                    note="Debug mode is enabled",
                    rule_id=LARAVEL_DEBUG_ENABLED_RULE,
                )
            ]
        )

    # laravel.app-key
    app_key_val = config.get_value_object("app.key")
    is_deferred = False
    app_key_str = ""
    if app_key_val:
        app_key_str = app_key_val.value or ""
        if not isinstance(app_key_str, str):
            app_key_str = str(app_key_str)
        is_deferred = app_key_val.env_var is not None

    # Check for hardcoded insecure key in config/app.php
    hardcoded_insecure = False
    if app_key_val and not is_deferred:
        if (
            not app_key_str
            or app_key_str.startswith("base64:SomeRandomString")
            or app_key_str == "SomeRandomString"
        ):
            hardcoded_insecure = True

    # Check if .env is committed
    env_committed = config.env_file_exists

    should_fire_app_key = env_committed or hardcoded_insecure

    if should_fire_app_key:
        paths.append(
            [
                PathStep(
                    role="gap",
                    span=Span(
                        file=Path(".env" if env_committed else "config/app.php"),
                        start_line=1,
                        start_col=1,
                        end_line=1,
                        end_col=1,
                    ),
                    snippet="APP_KEY",
                    note="APP_KEY is missing, default, or committed",
                    rule_id=LARAVEL_APP_KEY_RULE,
                )
            ]
        )

    # laravel.trusted-proxies
    tp_val = config.get_value_object("trustedproxy.proxies")
    trusted_proxies = config.env_vars.get("TRUSTED_PROXIES")
    tp_file = Path(".env")
    if not trusted_proxies:
        if tp_val:
            trusted_proxies = tp_val.value
            tp_file = tp_val.file_path or Path("config/trustedproxy.php")

    if str(trusted_proxies).strip() == "*":
        paths.append(
            [
                PathStep(
                    role="gap",
                    span=Span(file=tp_file, start_line=1, start_col=1, end_line=1, end_col=1),
                    snippet="*",
                    note="TrustedProxy is set to trust all proxies ('*')",
                    rule_id=LARAVEL_TRUSTED_PROXIES_RULE,
                )
            ]
        )

    # laravel.session-cookie
    session_secure_val = config.get_value_object("session.secure")
    session_http_only_val = config.get_value_object("session.http_only")
    session_same_site_val = config.get_value_object("session.same_site")

    is_prod = app_env == "production"

    if session_secure_val is not None:
        val = str(session_secure_val.value).lower()
        if is_prod and val in ("false", "0", ""):
            paths.append(
                [
                    PathStep(
                        role="gap",
                        span=Span(
                            file=session_secure_val.file_path or Path("config/session.php"),
                            start_line=1,
                            start_col=1,
                            end_line=1,
                            end_col=1,
                        ),
                        snippet="false",
                        note="Session cookies are not marked as secure in production",
                        rule_id=LARAVEL_SESSION_COOKIE_RULE,
                    )
                ]
            )

    if session_http_only_val is not None:
        val = str(session_http_only_val.value).lower()
        if val in ("false", "0", ""):
            paths.append(
                [
                    PathStep(
                        role="gap",
                        span=Span(
                            file=session_http_only_val.file_path or Path("config/session.php"),
                            start_line=1,
                            start_col=1,
                            end_line=1,
                            end_col=1,
                        ),
                        snippet="false",
                        note="Session cookies are not marked as HTTP Only",
                        rule_id=LARAVEL_SESSION_COOKIE_RULE,
                    )
                ]
            )

    if session_same_site_val is not None:
        val = str(session_same_site_val.value).lower()
        if val == "none":
            paths.append(
                [
                    PathStep(
                        role="gap",
                        span=Span(
                            file=session_same_site_val.file_path or Path("config/session.php"),
                            start_line=1,
                            start_col=1,
                            end_line=1,
                            end_col=1,
                        ),
                        snippet="none",
                        note="Session cookies have SameSite set to None",
                        rule_id=LARAVEL_SESSION_COOKIE_RULE,
                    )
                ]
            )

    return paths


def _env_outside_config_paths(project: Project) -> list[list[PathStep]]:
    paths = []

    for path, parsed in project.files.items():
        if path.parts and path.parts[0] == "config":
            continue

        for call in find_all(parsed.tree.root_node, "function_call_expression"):
            fn = call.child_by_field_name("function")
            if fn and node_text(fn, parsed.source) == "env":
                steps = [
                    PathStep(
                        role="gap",
                        span=node_span(call, path),
                        snippet=node_text(call, parsed.source),
                        note="env() is called outside the config/ directory",
                        rule_id=LARAVEL_ENV_OUTSIDE_CONFIG_RULE,
                    )
                ]
                paths.append(steps)

    return paths


def _unsafe_upload_paths(project: Project) -> list[list[PathStep]]:
    paths = []
    for path, parsed in project.files.items():
        if path.parts and path.parts[0] == "tests":
            continue
        for call in find_all(parsed.tree.root_node, "member_call_expression"):
            name_node = call.child_by_field_name("name")
            if name_node and node_text(name_node, parsed.source) == "getClientOriginalName":
                paths.append(
                    [
                        PathStep(
                            role="gap",
                            span=node_span(call, path),
                            snippet=node_text(call, parsed.source),
                            note="uses getClientOriginalName() for file upload",
                            rule_id=LARAVEL_UNSAFE_UPLOAD_RULE,
                        )
                    ]
                )
    return paths


def _debug_artifact_paths(project: Project) -> list[list[PathStep]]:
    paths = []
    for path, parsed in project.files.items():
        if path.parts and path.parts[0] in ("tests", "vendor"):
            continue
        for call in find_all(parsed.tree.root_node, "function_call_expression"):
            fn = call.child_by_field_name("function")
            if fn:
                fn_name = node_text(fn, parsed.source)
                if fn_name in ("dd", "dump", "ray", "var_dump"):
                    paths.append(
                        [
                            PathStep(
                                role="gap",
                                span=node_span(call, path),
                                snippet=node_text(call, parsed.source),
                                note=f"debug artifact {fn_name}() found in production code",
                                rule_id=LARAVEL_DEBUG_ARTIFACT_RULE,
                            )
                        ]
                    )
    return paths


def _weak_hash_paths(project: Project) -> list[list[PathStep]]:
    paths = []
    for path, parsed in project.files.items():
        for call in find_all(parsed.tree.root_node, "function_call_expression"):
            fn = call.child_by_field_name("function")
            if fn:
                fn_name = node_text(fn, parsed.source)
                if fn_name in ("md5", "sha1"):
                    parent = call.parent
                    context_text = ""
                    if parent:
                        if parent.type == "assignment_expression":
                            left = parent.child_by_field_name("left")
                            if left:
                                context_text = node_text(left, parsed.source).lower()
                        elif parent.type in ("array_element_initializer", "pair"):
                            if len(parent.children) > 0:
                                context_text = node_text(parent.children[0], parsed.source).lower()
                    if "password" in context_text:
                        paths.append(
                            [
                                PathStep(
                                    role="gap",
                                    span=node_span(call, path),
                                    snippet=node_text(call, parsed.source),
                                    note=f"{fn_name}() used for hashing a password",
                                    rule_id=LARAVEL_WEAK_HASH_RULE,
                                )
                            ]
                        )
    return paths


def _weak_randomness_paths(project: Project) -> list[list[PathStep]]:
    paths = []
    for path, parsed in project.files.items():
        for call in find_all(parsed.tree.root_node, "function_call_expression"):
            fn = call.child_by_field_name("function")
            if fn:
                fn_name = node_text(fn, parsed.source)
                if fn_name in ("rand", "mt_rand"):
                    parent = call.parent
                    context_text = ""
                    if parent:
                        if parent.type == "assignment_expression":
                            left = parent.child_by_field_name("left")
                            if left:
                                context_text = node_text(left, parsed.source).lower()
                        elif parent.type in ("array_element_initializer", "pair"):
                            if len(parent.children) > 0:
                                context_text = node_text(parent.children[0], parsed.source).lower()

                    if (
                        "token" in context_text
                        or "salt" in context_text
                        or "password" in context_text
                    ):
                        paths.append(
                            [
                                PathStep(
                                    role="gap",
                                    span=node_span(call, path),
                                    snippet=node_text(call, parsed.source),
                                    note=f"{fn_name}() used for sensitive randomness",
                                    rule_id=LARAVEL_WEAK_RANDOMNESS_RULE,
                                )
                            ]
                        )
    return paths
