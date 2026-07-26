"""The laravel.mass-assignment rule, case by case.

The negatives carry this file. A structural rule that only ever fires has not
been shown to read model configuration - it has been shown to recognise the
string "create".
"""

from pathlib import Path

from vigilloo.graph import load_project
from vigilloo.models import WalkStats
from vigilloo.rules import scan_project

FIXTURE = Path("tests/fixtures/laravel-minimal")


def _mass_assignment_lines() -> set[int]:
    findings = scan_project(load_project(FIXTURE))
    return {f.span.start_line for f in findings if f.rule_id == "laravel.mass-assignment"}


def test_guarded_empty_model_is_reported() -> None:
    """User::create($request->all()) with $guarded = []."""
    assert 15 in _mass_assignment_lines()


def test_narrow_fillable_model_is_not_reported() -> None:
    """Post::create($request->all()) with $fillable = ['title', 'body']."""
    assert 20 not in _mass_assignment_lines()


def test_privileged_fillable_is_reported() -> None:
    """Profile::create($request->all()) with is_admin allowlisted."""
    assert 25 in _mass_assignment_lines()


def test_request_only_is_not_reported() -> None:
    """only([...]) is an allowlist the developer wrote."""
    assert 30 not in _mass_assignment_lines()


def test_request_validated_is_not_reported() -> None:
    assert 35 not in _mass_assignment_lines()


def test_update_or_create_lookup_argument_is_not_reported() -> None:
    """Argument 0 is the lookup; only argument 1 is written.

    The whereRaw('age > ?', [$age]) of this rule - flagging the safe half is
    the noise that makes people stop reading the report.
    """
    assert 40 not in _mass_assignment_lines()


def test_force_fill_is_reported_even_on_a_guarded_model() -> None:
    """forceFill bypasses both $fillable and $guarded, which is its purpose."""
    assert 47 in _mass_assignment_lines()


def test_route_model_bound_receiver_is_resolved() -> None:
    """$user->update($request->all()) where $user comes from the signature."""
    assert 52 in _mass_assignment_lines()


def test_route_model_bound_guarded_model_is_not_reported() -> None:
    """The same shape as above against a model with a narrow $fillable."""
    assert 57 not in _mass_assignment_lines()


def test_the_evidence_path_names_the_model_and_the_line_to_edit() -> None:
    """Invariant 2: the reason is on the path, not in the prose."""
    findings = scan_project(load_project(FIXTURE))
    finding = next(
        f for f in findings if f.rule_id == "laravel.mass-assignment" and f.span.start_line == 15
    )
    roles = [step.role for step in finding.evidence_path]
    assert roles == ["entry", "source", "model", "sink"]

    model_step = finding.evidence_path[2]
    assert model_step.snippet == "App\\Models\\User"
    # The line the developer has to change is not the line reported on.
    assert model_step.span.file.name == "User.php"
    assert model_step.span.start_line == 10
    assert "$guarded" in model_step.note


def test_a_resolved_but_safe_write_is_not_counted_as_a_lost_trail() -> None:
    """Coverage must not report gaps on code the walk fully understood.

    Post::create($request->all()) is resolved end to end - receiver, model
    configuration and argument kinds - and judged safe. Counting it as an
    unresolved call site trains people to ignore the coverage number.
    """
    stats = WalkStats()
    scan_project(load_project(FIXTURE, stats), stats)
    assert stats.unresolved == 0
