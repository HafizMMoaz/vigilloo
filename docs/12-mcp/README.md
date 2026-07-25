# MCP

Vigilloo exposes its analysis over the Model Context Protocol so AI coding agents can check
their own work before a human sees it.

## Why this matters more than it looks

AI agents now write a large share of new application code, and they write it fast enough that
human review is the bottleneck. An agent that can query "does the code I just wrote introduce a
taint path?" and get a deterministic, graph-backed answer is a fundamentally different safety
posture from one that reviews its own output by re-reading it.

This is also the tightest possible feedback loop: the agent gets the finding *while it still has
the context that produced it*, and can fix it before the code ever reaches a branch.

Compatible clients: Claude Code, Cursor, Codex, Cline, Roo Code, Windsurf, Zed, and anything
else speaking MCP.

## Transport

stdio for local editor integration (the default), HTTP+SSE for shared or remote servers.
Started with `vigilloo mcp` - see [19-cli](../19-cli/README.md).

## Tools

The tool list is open and grows with the platform. These are the v1.0 set.

### Analysis

| Tool | Input | Output |
| --- | --- | --- |
| `analyze_project` | `path`, `severity_min?`, `rules?` | Findings + summary for a whole project |
| `analyze_file` | `path` | Findings for one file, with cross-file context from the cached graph |
| `analyze_diff` | `base?`, `head?`, or `patch` | Findings introduced by a change - **the highest-value tool for agent workflows** |
| `security_review` | `path`, `focus?` | Prioritised review with explanations, tuned for reading |

`analyze_diff` is the one agents should call by default. Reporting only what a change introduced
avoids drowning an agent in a legacy backlog it did not create and cannot fix.

### Graph queries

| Tool | Input | Output |
| --- | --- | --- |
| `attack_surface` | `path`, `unauthenticated_only?` | Route inventory with middleware, auth status, parameters |
| `trace_taint` | `symbol` or `file:line` | Taint paths through that point |
| `find_callers` / `find_callees` | `symbol`, `depth?` | Call graph neighbourhood |
| `explain_route` | `uri` or `route_name` | Middleware, action, models, policies, findings |
| `query_graph` | `query` (structured) | Arbitrary typed traversal |

### Findings

| Tool | Input | Output |
| --- | --- | --- |
| `explain_finding` | `finding_id` | Full evidence path, CWE context, impact |
| `generate_patch` | `finding_id` | Validated unified diff |
| `list_findings` | filters | Current findings from the cached scan |

### Knowledge

| Tool | Input | Output |
| --- | --- | --- |
| `lookup_weakness` | `cwe` or `keyword` | Corpus entry with remediation |
| `check_dependency` | `package`, `version?` | Advisories, EPSS, reachability |

## Resources

Read-only context an agent can pull without a tool call: `vigilloo://project/profile`,
`vigilloo://project/routes`, `vigilloo://findings/latest`, `vigilloo://rules`,
`vigilloo://graph/summary`.

## Prompts

Reusable templates surfaced by MCP clients as slash commands: `security-review-diff`,
`explain-vulnerability`, `harden-route`, `audit-authorization`.

## Design rules

**No analysis logic lives here.** The MCP server is a thin adapter over the same engines the CLI
uses. Two code paths producing different findings for the same code would be worse than having
no MCP server at all.

**Warm cache or fast failure.** Agents call tools interactively; a 60-second cold scan inside a
tool call is unusable. The server keeps a warm graph for the open project, incrementally
updating on file changes. `analyze_diff` on a warm cache should land well under a second.

**Bounded responses.** Findings are truncated to a token budget with a documented cap and a
`total_count`, so a 400-finding legacy project cannot blow out an agent's context window.

**Read-only by default.** MCP tools analyse and propose. They do not write files, do not run the
attack engine, and do not commit. `generate_patch` returns a diff; applying it is the agent's
call, made with the user watching.

**Untrusted input.** Code analysed through MCP may contain prompt injection aimed at the calling
agent. Findings are returned as structured data, never as instruction-shaped prose, and content
from analysed source is delimited and labelled untrusted.

## Configuration

```json
{
  "mcpServers": {
    "vigilloo": {
      "command": "vigilloo",
      "args": ["mcp", "--project", "/path/to/app"]
    }
  }
}
```

Server config controls severity floor, rule set, AI on/off and cache behaviour, so a team can
standardise what their agents see.
