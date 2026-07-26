"""Which policy class Laravel would use to authorize a given model.

Discovery is by Laravel's own naming convention, which is what Laravel 8+ does
at runtime: App\\Models\\Order is authorized by a class named OrderPolicy.

ponytail: AuthServiceProvider::$policies, the explicit override map, is not
read. It only ever *adds* mappings, so missing it can downgrade an evidence
note but never flip a verdict - a missing policy and an uncalled policy are
both the same finding.
"""

from ..symbols import ClassInfo


def find_policy(classes: dict[str, ClassInfo], model_fqn: str) -> str | None:
    """The FQN of the policy class for this model, if the project defines one."""
    wanted = f"{model_fqn.rsplit('\\', 1)[-1]}Policy"
    # Sorted so two classes with the same short name in different namespaces
    # resolve to the same one on every run (invariant 8).
    for fqn in sorted(classes):
        if fqn.rsplit("\\", 1)[-1] == wanted:
            return fqn
    return None
