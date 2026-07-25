# API

Programmatic access to Vigilloo, for callers that are neither the CLI nor an MCP client.

> **Status: the Python API is v1.0; the HTTP API is v3.0 (cloud). Not implemented in v0.1.**

## Today's answer: use the library or MCP

Before building an HTTP service, note that three integration paths already exist and cover most
needs:

1. **`vigilloo scan --format json`** - the correct answer for CI and scripts. Stable schema,
   deterministic output, no server to run.
2. **MCP** ([12-mcp](../12-mcp/README.md)) - the correct answer for AI agents and editors.
3. **The Python API** - the correct answer for embedding analysis in another Python tool.

An HTTP API is a fourth surface to version, secure and keep consistent with the other three.
It gets built when the cloud platform needs it, not before.

## Python API (v1.0)

The library interface, stabilised alongside the plugin SDK:

```python
from vigilloo import Workspace, ScanOptions

ws = Workspace.open("/path/to/laravel-app")
report = ws.scan(ScanOptions(severity_min="high", ai=False))

for finding in report.findings:
    print(finding.rule_id, finding.location, finding.severity)
    for step in finding.evidence_path:
        print(" ", step.role, step.file, step.line)

# Direct graph access
routes = ws.graph.routes(unauthenticated=True)
sinks  = ws.graph.reachable_sinks(routes[0], kind="sql")
```

Stability guarantee matches `sdk/` - semver'd, with deprecation cycles. Everything else in the
package is internal.

## HTTP API (v3.0)

For the cloud platform. Direction, not specification:

- REST over JSON; resources are projects, scans, findings, policies
- Findings are the same schema the JSON reporter emits - one canonical shape across CLI, MCP,
  desktop and cloud
- Async scan submission with polling or webhook callback; scans are minutes-long, so a
  synchronous request/response is the wrong shape
- Token auth scoped per organisation and repository; rate limited; every access audit-logged
- Webhooks outbound for scan completion, new critical findings, and policy violations

gRPC is deliberately not planned. The consumers are web front ends, CI systems and scripts -
all of which want JSON over HTTP. gRPC would add a build-time dependency to every integration
for no benefit at this scale.

## Compatibility rule

Every surface - CLI JSON, MCP tools, Python API, HTTP API - serialises the **same `Finding`
type** from [17-database](../17-database/README.md). New fields may be added; existing fields
never change meaning. A consumer written against the CLI's JSON output must be able to read a
cloud API response without a translation layer.
