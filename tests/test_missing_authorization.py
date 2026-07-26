"""The fourteen rows of the slice 4 table in docs/plans/2026-07-26-slice-4-design.md."""

from pathlib import Path

from vigilloo.graph import load_project
from vigilloo.models import PathStep
from vigilloo.rules import scan_project
from vigilloo.structural import find_structural_paths

FIXTURE = Path("tests/fixtures/laravel-minimal")

RULE = "laravel.missing-authorization"


def paths_by_action() -> dict[str, list[PathStep]]:
    """Every structural path, keyed by the action its entry step names."""
    project = load_project(FIXTURE)
    return {p[0].snippet.rsplit("::", 1)[-1]: p for p in find_structural_paths(project)}


def test_only_the_unguarded_actions_are_reported() -> None:
    """One assertion covering every negative row at once.

    Listed as an exact set rather than as individual "not in" checks: a rule
    about something *absent* fails by over-reporting, and an exact set is the
    only shape that catches a newly invented finding as well as a lost one.
    """
    assert set(paths_by_action()) == {
        "show",  # policy exists, never consulted
        "showReceipt",  # no policy class at all
        "viaStubRequest",  # authorize() { return true; } is not authorization
        "inGroup",  # Route::middleware(['auth'])->group(...)
    }


def test_path_names_the_policy_that_is_never_consulted() -> None:
    path = paths_by_action()["show"]
    roles = [step.role for step in path]
    assert roles == ["entry", "binding", "policy", "gap"]

    assert path[0].note == "authenticated by: auth"
    assert path[1].snippet == "Invoice $invoice"
    assert "route-model binding" in path[1].note
    assert path[2].snippet == "App\\Policies\\InvoicePolicy"
    assert path[2].span.file.name == "InvoicePolicy.php"
    assert path[3].rule_id == RULE


def test_a_model_with_no_policy_omits_the_policy_step() -> None:
    """A step that says "nothing here" is worse than no step."""
    path = paths_by_action()["showReceipt"]
    assert [step.role for step in path] == ["entry", "binding", "gap"]
    assert "no policy is defined for App\\Models\\Receipt" in path[-1].note


def test_group_middleware_is_read() -> None:
    """Without this, a typical routes/api.php produces nothing at all."""
    assert paths_by_action()["inGroup"][0].note == "authenticated by: auth"


def test_unreadable_middleware_suppresses_the_finding() -> None:
    """->middleware($extra) means "I cannot tell", never "nothing guards this".

    The route is otherwise identical to `show`, which does fire, so this is
    only about the middleware the extractor could not resolve.
    """
    project = load_project(FIXTURE)
    route = next(r for r in project.routes if r.uri.endswith("/unreadable"))
    assert route.middleware == ("auth", "?")
    assert "unreadable" not in paths_by_action()


def test_findings_carry_the_rule_metadata() -> None:
    findings = [f for f in scan_project(load_project(FIXTURE)) if f.rule_id == RULE]
    assert len(findings) == 4
    for finding in findings:
        assert finding.severity == "high"
        assert finding.cwe == ("CWE-639",)
        assert finding.remediation
        # The finding is reported where the developer must edit, which is the
        # action, not the route file.
        assert finding.span.file.name.endswith("Controller.php")


def test_structural_paths_are_stable_across_runs() -> None:
    a = find_structural_paths(load_project(FIXTURE))
    b = find_structural_paths(load_project(FIXTURE))
    assert a == b
