"""Content-derived node identity.

Backward-compatibility shim re-exporting vigilloo.graph.ids.
"""

from .graph.ids import _ID_LENGTH, _SEPARATOR, node_id

__all__ = ["_ID_LENGTH", "_SEPARATOR", "node_id"]
