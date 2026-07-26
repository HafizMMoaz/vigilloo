"""Eloquent model configuration: what a model lets a request write.

The canonical reference is docs/08-framework-adapters. This module carries the
subset the mass-assignment rule needs - `$fillable` and `$guarded`. The other
model facts that document lists ($hidden, $casts, $appends, relationships,
scopes) arrive with the rules that read them.
"""

import re
from dataclasses import dataclass
from enum import StrEnum

from ..models import Span
from ..symbols import ClassInfo

# Base classes a user's model extends. The chain is walked upward, but Laravel
# itself lives in vendor/ and is excluded from the scan, so in practice the
# chain ends at an unresolvable name - which is why the short name is what
# counts. These are what the base classes are actually called at the point a
# user writes `class User extends Authenticatable`.
_MODEL_BASES: frozenset[str] = frozenset({"Model", "Authenticatable", "Pivot"})

# Columns a request must never be able to set. From the list in
# docs/08-framework-adapters.
#
# Anchored, never a substring search: `user_id` as a substring turns
# `contributor_id_hash` into a hit, and one confident false positive is enough
# for a team to stop reading the rule.
_PRIVILEGED_COLUMN = re.compile(
    r"^(?:is_)?(?:admin|superuser|staff|owner)$"
    r"|^role(?:_id)?$"
    r"|^permissions?$"
    r"|^(?:email_)?verified(?:_at)?$"
    r"|^balance$"
    r"|^price$"
    r"|^(?:owner|user|account|team)_id$",
    re.IGNORECASE,
)


class Protection(StrEnum):
    """How much of a model a request-supplied array is allowed to write."""

    OPEN = "open"
    """`$guarded = []` - every column, including ones added next year."""

    PRIVILEGED_FILLABLE = "privileged_fillable"
    """`$fillable` allowlists a column a request should never set."""

    GUARDED = "guarded"
    """Adequately configured, or configured in a way this module cannot read."""


@dataclass(frozen=True)
class ModelConfig:
    fqn: str
    protection: Protection
    # The property that decided it ("guarded"/"fillable"), its span in the
    # model file, and the offending column if there was one. All three exist to
    # put the model on the evidence path: invariant 2 wants the reason on the
    # path, not in prose, and the line the developer must edit is not the line
    # the finding is reported on.
    reason_prop: str = ""
    reason_span: Span | None = None
    privileged_column: str = ""


def is_model(classes: dict[str, ClassInfo], fqn: str) -> bool:
    """Does this class inherit from an Eloquent model base?

    ponytail: `use HasFactory`-style traits and models whose base lives behind
    an alias are not resolved. A model reached this way is missed rather than
    guessed at - fabricating a model relationship would fabricate a finding.
    """
    seen: set[str] = set()
    current: str | None = fqn
    while current is not None and current not in seen:
        seen.add(current)
        info = classes.get(current)
        if info is None:
            # The chain ran off the end of the scanned code, which is the
            # normal case: Laravel's own Model class is in vendor/.
            return current.rsplit("\\", 1)[-1] in _MODEL_BASES
        if info.parent is None:
            return False
        current = info.parent
    return False


def privileged_columns(columns: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(c for c in columns if _PRIVILEGED_COLUMN.match(c))


def model_config(classes: dict[str, ClassInfo], fqn: str) -> ModelConfig | None:
    """How this model is protected, or None if it is not a model at all."""
    info = classes.get(fqn)
    if info is None or not is_model(classes, fqn):
        return None

    guarded = info.array_props.get("guarded")
    if guarded == ():
        return ModelConfig(
            fqn=fqn,
            protection=Protection.OPEN,
            reason_prop="guarded",
            reason_span=info.array_prop_spans.get("guarded"),
        )

    fillable = info.array_props.get("fillable")
    if fillable:
        offending = privileged_columns(fillable)
        if offending:
            return ModelConfig(
                fqn=fqn,
                protection=Protection.PRIVILEGED_FILLABLE,
                reason_prop="fillable",
                reason_span=info.array_prop_spans.get("fillable"),
                privileged_column=offending[0],
            )

    # Includes a model that declares neither property, and that is correct
    # rather than merely cautious: Eloquent's own $guarded defaults to ['*'],
    # so a model configuring nothing is not mass-assignable at all. Reading
    # "unconfigured" as "open" would fire on almost every model ever written.
    return ModelConfig(fqn=fqn, protection=Protection.GUARDED)
