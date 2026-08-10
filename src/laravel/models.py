"""Eloquent model configuration: what a model lets a request write.

The canonical reference is docs/08-framework-adapters. This module carries the
subset the mass-assignment rule needs - `$fillable` and `$guarded`. The other
model facts that document lists ($hidden, $casts, $appends, relationships,
scopes) arrive with the rules that read them.
"""

import re
from dataclasses import dataclass, field
from enum import StrEnum

from tree_sitter import Node

from ..models import Span
from ..parser import ParsedFile, find_all, node_text
from ..symbols import ClassInfo, FileSymbols

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

    Parent names and import aliases are resolved by the core symbol layer before
    this framework-specific model check runs. A model whose base still cannot be
    resolved is missed rather than guessed at - fabricating a model relationship
    would fabricate a finding.
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


def model_config(
    classes: dict[str, ClassInfo],
    fqn: str,
    schema: dict[str, set[str]] | None = None,
) -> ModelConfig | None:
    """How this model is protected, or None if it is not a model at all."""
    info = classes.get(fqn)
    if info is None or not is_model(classes, fqn):
        return None

    table_name = info.properties.get("table", "").strip("'\"")
    if not table_name:
        short_name = fqn.rsplit("\\", 1)[-1]
        table_name = short_name.lower() + "s"

    table_columns = schema.get(table_name) if schema is not None else None

    guarded = info.array_props.get("guarded")
    if guarded == ():
        if table_columns is not None:
            has_privileged = any(_PRIVILEGED_COLUMN.match(c) for c in table_columns)
            if not has_privileged:
                return ModelConfig(fqn=fqn, protection=Protection.GUARDED)

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
            real_offending = tuple(
                c for c in offending if table_columns is None or c in table_columns
            )
            if real_offending:
                return ModelConfig(
                    fqn=fqn,
                    protection=Protection.PRIVILEGED_FILLABLE,
                    reason_prop="fillable",
                    reason_span=info.array_prop_spans.get("fillable"),
                    privileged_column=real_offending[0],
                )

    # Includes a model that declares neither property, and that is correct
    # rather than merely cautious: Eloquent's own $guarded defaults to ['*'],
    # so a model configuring nothing is not mass-assignable at all. Reading
    # "unconfigured" as "open" would fire on almost every model ever written.
    return ModelConfig(fqn=fqn, protection=Protection.GUARDED)


_RELATIONSHIP_METHODS = frozenset(
    {
        "hasOne",
        "belongsTo",
        "hasMany",
        "belongsToMany",
        "hasManyThrough",
        "hasOneThrough",
        "morphTo",
        "morphOne",
        "morphMany",
        "morphToMany",
        "morphedByMany",
    }
)


@dataclass(frozen=True)
class ModelMetadata:
    fqn: str
    table: str = ""
    fillable: tuple[str, ...] = ()
    guarded: tuple[str, ...] = ()
    hidden: tuple[str, ...] = ()
    casts: dict[str, str] = field(default_factory=dict)
    appends: tuple[str, ...] = ()
    timestamps: bool = True
    soft_deletes: bool = False
    traits: tuple[str, ...] = ()
    relationships: dict[str, tuple[str, str]] = field(default_factory=dict)
    scopes: tuple[str, ...] = ()
    accessors: tuple[str, ...] = ()
    mutators: tuple[str, ...] = ()


def _parse_dict_array(node: Node, source: bytes) -> dict[str, str]:
    res: dict[str, str] = {}
    for element in node.children:
        if element.type != "array_element_initializer":
            continue
        if len(element.children) >= 3 and element.children[1].type == "=>":
            k = node_text(element.children[0], source).strip("'\"")
            v = node_text(element.children[2], source).strip("'\"")
            res[k] = v
    return res


def extract_model_metadata(
    parsed: ParsedFile,
    symbols: FileSymbols,
    fqn: str,
) -> ModelMetadata | None:
    """Extract complete Eloquent model metadata for a given class FQN."""
    classes = symbols.classes
    info = classes.get(fqn)
    if info is None or not is_model(classes, fqn):
        return None

    class_node: Node | None = None
    for node in find_all(parsed.tree.root_node, "class_declaration"):
        name_node = node.child_by_field_name("name")
        if name_node is not None:
            short_name = node_text(name_node, parsed.source)
            candidate_fqn = f"{symbols.namespace}\\{short_name}".strip("\\")
            if candidate_fqn == fqn or short_name == fqn.rsplit("\\", 1)[-1]:
                class_node = node
                break

    if class_node is None:
        return None

    source = parsed.source
    table = ""
    timestamps = True
    fillable = info.array_props.get("fillable", ())
    guarded = info.array_props.get("guarded", ())
    hidden = info.array_props.get("hidden", ())
    appends = info.array_props.get("appends", ())
    casts: dict[str, str] = {}

    body = class_node.child_by_field_name("body")
    if body is not None:
        for member in body.children:
            if member.type == "property_declaration":
                for elem in member.children:
                    if elem.type == "property_element":
                        p_name_node = elem.child_by_field_name("name")
                        if p_name_node is None:
                            continue
                        p_name = node_text(p_name_node, source).lstrip("$")
                        val_node = elem.child_by_field_name("default_value")

                        if p_name == "table" and val_node is not None:
                            table = node_text(val_node, source).strip("'\"")
                        elif p_name == "timestamps" and val_node is not None:
                            val_text = node_text(val_node, source).lower()
                            if val_text == "false":
                                timestamps = False
                        elif p_name == "casts" and val_node is not None:
                            if val_node.type == "array_creation_expression":
                                casts = _parse_dict_array(val_node, source)

    soft_deletes = any(
        t.endswith("SoftDeletes") or t == "Illuminate\\Database\\Eloquent\\SoftDeletes"
        for t in info.traits
    )

    relationships: dict[str, tuple[str, str]] = {}
    scopes: list[str] = []
    accessors: list[str] = []
    mutators: list[str] = []

    for method_node in find_all(class_node, "method_declaration"):
        name_node = method_node.child_by_field_name("name")
        if name_node is None:
            continue
        method_name = node_text(name_node, source)

        if method_name.startswith("scope") and len(method_name) > 5:
            scopes.append(method_name)

        if method_name.startswith("get") and method_name.endswith("Attribute"):
            accessors.append(method_name)
        elif method_name.startswith("set") and method_name.endswith("Attribute"):
            mutators.append(method_name)
        else:
            return_type = method_node.child_by_field_name("return_type")
            if return_type is not None and "Attribute" in node_text(return_type, source):
                accessors.append(method_name)
                mutators.append(method_name)

        for call_node in find_all(method_node, "member_call_expression"):
            obj = call_node.child_by_field_name("object")
            name = call_node.child_by_field_name("name")
            if obj is not None and node_text(obj, source) == "$this" and name is not None:
                rel_type = node_text(name, source)
                if rel_type in _RELATIONSHIP_METHODS:
                    args_node = call_node.child_by_field_name("arguments")
                    target_fqn = ""
                    if args_node is not None and len(args_node.children) >= 2:
                        first_arg = args_node.children[1]
                        arg_text = node_text(first_arg, source).strip()
                        if "::class" in arg_text:
                            short_cls = arg_text.rsplit("::class", 1)[0].strip()
                            target_fqn = symbols.imports.get(short_cls, short_cls)
                        else:
                            target_fqn = arg_text.strip("'\"")
                    relationships[method_name] = (rel_type, target_fqn)

    return ModelMetadata(
        fqn=fqn,
        table=table,
        fillable=fillable,
        guarded=guarded,
        hidden=hidden,
        casts=casts,
        appends=appends,
        timestamps=timestamps,
        soft_deletes=soft_deletes,
        traits=info.traits,
        relationships=relationships,
        scopes=tuple(scopes),
        accessors=tuple(accessors),
        mutators=tuple(mutators),
    )
