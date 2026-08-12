r"""Laravel Facade resolution.

Maps facade classes like `Illuminate\Support\Facades\Cache` and aliases like `Cache`
to their concrete implementations, such as `Illuminate\Cache\CacheManager`.
Reads both a static built-in map and the application's `config/app.php` alias array.
"""

from functools import cache
from pathlib import Path

from ..graph import Project
from ..parser import find_all, node_text, parse_php

# The static facade map from framework version to concrete class.
BUILTIN_FACADES: dict[str, str] = {
    "Illuminate\\Support\\Facades\\DB": "Illuminate\\Database\\DatabaseManager",
    "Illuminate\\Support\\Facades\\Http": "Illuminate\\Http\\Client\\Factory",
    "Illuminate\\Support\\Facades\\Storage": "Illuminate\\Filesystem\\FilesystemManager",
    "Illuminate\\Support\\Facades\\Auth": "Illuminate\\Auth\\AuthManager",
    "Illuminate\\Support\\Facades\\Cache": "Illuminate\\Cache\\CacheManager",
    "Illuminate\\Support\\Facades\\Log": "Illuminate\\Log\\LogManager",
    "Illuminate\\Support\\Facades\\Mail": "Illuminate\\Mail\\Mailer",
    "Illuminate\\Support\\Facades\\Queue": "Illuminate\\Queue\\QueueManager",
    "Illuminate\\Support\\Facades\\Event": "Illuminate\\Events\\Dispatcher",
    "Illuminate\\Support\\Facades\\Gate": "Illuminate\\Contracts\\Auth\\Access\\Gate",
    "Illuminate\\Support\\Facades\\Route": "Illuminate\\Routing\\Router",
    "Illuminate\\Support\\Facades\\Config": "Illuminate\\Config\\Repository",
    "Illuminate\\Support\\Facades\\Session": "Illuminate\\Session\\SessionManager",
    "Illuminate\\Support\\Facades\\Validator": "Illuminate\\Validation\\Factory",
    "Illuminate\\Support\\Facades\\Blade": "Illuminate\\View\\Compilers\\BladeCompiler",
    "Illuminate\\Support\\Facades\\Process": "Illuminate\\Process\\Factory",
    "Illuminate\\Support\\Facades\\Redirect": "Illuminate\\Routing\\Redirector",
    "Illuminate\\Support\\Facades\\Response": "Illuminate\\Routing\\ResponseFactory",
}


@cache
def app_aliases(root: Path) -> dict[str, str]:
    """The alias map registered in `config/app.php`. Cached per workspace."""
    config_path = root / "config" / "app.php"

    if not config_path.is_file():
        return {}

    parsed = parse_php(config_path)
    aliases: dict[str, str] = {}

    # We look for an array element with key "aliases"
    for element in find_all(parsed.tree.root_node, "array_element_initializer"):
        if len(element.children) != 3:
            continue
        key = element.children[0]
        if key.type != "string":
            continue

        key_text = ""
        for child in key.named_children:
            if child.type == "string_content":
                key_text += node_text(child, parsed.source)

        if key_text == "aliases":
            value = element.children[2]
            if value.type != "array_creation_expression":
                continue

            for alias_el in find_all(value, "array_element_initializer"):
                if len(alias_el.children) != 3:
                    continue
                alias_key = alias_el.children[0]
                alias_val = alias_el.children[2]

                if alias_key.type != "string":
                    continue

                alias_name = node_text(alias_key, parsed.source)
                if alias_name.startswith("'") and alias_name.endswith("'"):
                    alias_name = alias_name[1:-1]
                elif alias_name.startswith('"') and alias_name.endswith('"'):
                    alias_name = alias_name[1:-1]

                if alias_val.type == "class_constant_access_expression":
                    cls_node = alias_val.children[0]
                    if cls_node:
                        aliases[alias_name] = node_text(cls_node, parsed.source)
                elif alias_val.type == "string":
                    val_text = node_text(alias_val, parsed.source)
                    if val_text.startswith("'") and val_text.endswith("'"):
                        val_text = val_text[1:-1].replace("\\\\", "\\")
                    elif val_text.startswith('"') and val_text.endswith('"'):
                        val_text = val_text[1:-1].replace("\\\\", "\\")
                    aliases[alias_name] = val_text

            break

    return aliases


def resolve_facade(fqn: str, project: Project) -> str | None:
    """Resolve a facade FQN to its concrete class FQN, or None if not a known facade.

    If the name matches one of the builtin facades, its concrete class is returned.
    If it has the Facades\\ prefix, it strips the prefix.
    If it is found in the app aliases array and that maps to a builtin facade, it resolves.
    """
    if fqn in BUILTIN_FACADES:
        return BUILTIN_FACADES[fqn]

    if fqn.startswith("Facades\\"):
        return fqn.removeprefix("Facades\\")

    aliases = app_aliases(project.root)
    # The FQN passed here might just be "Cache" if there's no import but there's a global alias.
    # So if fqn is in aliases, it maps to Illuminate\Support\Facades\Cache (for example),
    # which we then resolve again against BUILTIN_FACADES.
    # Note: `resolve_class_name` returns `Cache` if no import exists.
    if fqn in aliases:
        aliased_class = aliases[fqn]
        # Resolve recursively once in case it maps to a builtin facade
        if aliased_class in BUILTIN_FACADES:
            return BUILTIN_FACADES[aliased_class]
        return aliased_class

    # Also check if the FQN looks like a built-in facade (e.g. `Illuminate\Support\Facades\X`)
    # that wasn't in our explicit BUILTIN_FACADES list. But the spec says
    # "Unknown facades are recorded unresolved"
    # So we only return known ones.

    return None
