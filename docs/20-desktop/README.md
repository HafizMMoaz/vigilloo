# Desktop

A PySide6 (Qt) application over the same engines as the CLI.

> **Status: v2.0. Not implemented in v0.1.**

## Why a desktop app

Two things a terminal genuinely cannot do well:

1. **Graph exploration.** A call graph or taint path is a spatial object. Reading one as
   indented text is possible; navigating one interactively is a different activity entirely.
2. **Triage at volume.** Working through 300 findings - reading each one, deciding, suppressing
   with a justification - is a UI problem. The CLI is right for "scan and fix"; it is wrong for
   "an afternoon of security review".

It is a client over the same SQLite workspace and the same engines. It contains no analysis
logic of its own, for the same reason the MCP server does not: two code paths producing
different answers for the same code is a worse outcome than one imperfect path.

## Views

| View | Purpose |
| --- | --- |
| **Dashboard** | Severity counts, trend over recent scans, coverage, top risky files |
| **Findings** | Sortable/filterable list; detail pane with the full evidence path and code frames |
| **Graph explorer** | Interactive call, data-flow and route graphs; focus a node, expand neighbours, follow a taint path |
| **Attack surface** | Route table with middleware, auth status, parameters, associated findings |
| **Dependency tree** | Composer graph with advisories and reachability overlaid |
| **Reports** | Generate, preview, export |
| **AI chat** | Ask about the codebase; queries compile to graph traversals ([09-ai-engine](../09-ai-engine/README.md)) |
| **Settings** | Providers, rules, suppressions, plugins |

## Interaction principles

- **The evidence path is the primary object.** Clicking a finding shows the path; clicking a
  step opens the code at that line; the graph view highlights the same path. All three views
  stay in sync on one selection.
- **Nothing blocks.** Scans run in a worker thread with progress and cancellation. A frozen
  window during a five-minute scan is unacceptable.
- **Read-only by default.** Patches are previewed as diffs and applied only on explicit
  confirmation.
- **Keyboard-first.** The users are developers; a triage flow requiring a mouse for every
  decision will not get used for 300 findings.

## Graph rendering

The hard part. A 5M-node graph cannot be drawn, so the view is always a **focused subgraph**:
pick a node, render its neighbourhood to a depth, expand on demand. Layout via Graphviz for
hierarchical views, force-directed for exploration. Taint paths render as a highlighted spine
with sanitizers and unresolved edges visually distinct - the two things a reviewer is actually
looking for.

## Distribution

Native bundles per platform (PyInstaller or Briefcase), signed on macOS and Windows. Ships with
the CLI included; the desktop app is a front end, not a separate product, and installing it must
not mean managing two versions.

## Not a replacement for the CLI

The CLI stays the primary interface and the one CI uses. The desktop app targets exploration and
triage - the moments when a human is thinking about the code rather than automating it.
