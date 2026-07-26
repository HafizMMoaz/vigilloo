from pathlib import Path

from vigilloo.graph import load_project
from vigilloo.laravel.policies import find_policy

FIXTURE = Path("tests/fixtures/laravel-minimal")


def test_policy_is_found_by_laravel_naming_convention() -> None:
    classes = load_project(FIXTURE).classes
    assert find_policy(classes, "App\\Models\\Invoice") == "App\\Policies\\InvoicePolicy"


def test_a_model_with_no_policy_class_returns_none() -> None:
    """Distinct from "a policy exists and is not called" - different evidence."""
    classes = load_project(FIXTURE).classes
    assert find_policy(classes, "App\\Models\\Receipt") is None
