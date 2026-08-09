"""Discovery of framework-invoked entry points.

Finds jobs, commands, listeners, observers, and scheduled tasks that the framework
might invoke outside of an HTTP request.
"""

from typing import TYPE_CHECKING
from collections.abc import Iterable

from ..models import EntryPoint, Span
from ..symbols import ClassInfo

if TYPE_CHECKING:
    from ..graph import Project


def _is_job(cls: ClassInfo) -> bool:
    return "app/Jobs/" in str(cls.span.file)


def _is_command(cls: ClassInfo) -> bool:
    if cls.parent and "Command" in cls.parent:
        return True
    return "app/Console/Commands/" in str(cls.span.file)


def _is_listener(cls: ClassInfo) -> bool:
    return "app/Listeners/" in str(cls.span.file)


def _is_observer(cls: ClassInfo) -> bool:
    return "app/Observers/" in str(cls.span.file)


def _is_notification(cls: ClassInfo) -> bool:
    return "app/Notifications/" in str(cls.span.file)


def find_entrypoints(project: "Project") -> list[EntryPoint]:
    """Find all framework-invoked entry points in the project."""
    entrypoints = []

    for fqn, cls in project.classes.items():
        kind = None
        if _is_job(cls):
            kind = "job"
        elif _is_command(cls):
            kind = "command"
        elif _is_listener(cls):
            kind = "listener"
        elif _is_notification(cls):
            kind = "notification"
        elif _is_observer(cls):
            kind = "observer"

        if not kind:
            continue

        # Find relevant methods
        for method_name, method_span in cls.methods.items():
            # For jobs, commands, and listeners, `handle` is the entry point
            if kind in ("job", "command", "listener") and method_name != "handle":
                continue
                
            # For notifications, methods like `toMail`, `toArray`
            if kind == "notification" and not method_name.startswith("to"):
                continue
                
            # Observers have lifecycle events, we assume any public method is an entry point, 
            # but currently we don't track visibility. Exclude magic methods.
            if kind == "observer" and method_name.startswith("__"):
                continue

            entrypoints.append(
                EntryPoint(
                    fqn=f"{fqn}::{method_name}",
                    kind=kind,
                    span=method_span.span,
                )
            )
            
    # Add scheduled tasks? In a real Laravel app, they are in app/Console/Kernel.php -> schedule()
    # Let's see if we have an app/Console/Kernel.php
    for fqn, cls in project.classes.items():
        if "app/Console/Kernel.php" in str(cls.span.file) or fqn == "App\\Console\\Kernel":
            if "schedule" in cls.methods:
                entrypoints.append(
                    EntryPoint(
                        fqn=f"{fqn}::schedule",
                        kind="scheduler",
                        span=cls.methods["schedule"].span,
                    )
                )

    return entrypoints
