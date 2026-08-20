# Cloud

The hosted platform and the commercial tier.

> **Status: v3.0. Not implemented in v0.1.** Documented so the open-core boundary is decided
> before it becomes expensive to move.

## The open-core boundary

| Open source, forever | Commercial |
| --- | --- |
| CLI, all commands | Hosted platform |
| Analysis engines - parser, graph, taint, rules | Team collaboration |
| Plugin SDK and all core plugins | Organisation policy enforcement |
| MCP server | Compliance automation and evidence collection |
| Report formats | Fleet management across many repositories |
| Local AI integration | SSO / SCIM / audit logs |

The rule: **a single developer or a small team gets a complete, capable tool for free, offline,
with no account.** The commercial product sells the things that only matter at organisational
scale - coordination, policy, history, and access control across many people and repositories.

What must never happen: crippling the CLI to drive upgrades. Findings withheld from the free
tier, artificial repository limits, or a scanner that needs a login to run. That model destroys
the trust the product depends on, and for a security tool, trust is the entire moat.

## Capabilities

**Organisations and teams** - repository grouping, role-based access, per-team ownership of
findings.

**Continuous monitoring** - scheduled scans across every connected repository, with trends,
regressions and mean-time-to-fix. This is the thing a CLI structurally cannot do: nobody runs a
CLI on 200 repositories every night and reads the output.

**Policy** - organisation-wide rule configuration, required severity gates, mandatory
suppression justifications, expiry enforcement on suppressions. Policies flow down to CI and to
local runs via configuration; the client remains the same binary.

**Fleet view** - the security posture of an entire portfolio, ranked by real risk (severity ×
reachability × exposure), not by raw finding count.

**Compliance** - SOC 2, ISO 27001 and PCI DSS evidence collection: proof that scanning ran, that
findings were triaged, that suppressions were justified and reviewed. Mostly a reporting and
retention problem, and one organisations pay for precisely because it is tedious.

**Integrations** - GitHub, GitLab, Bitbucket, Jira, Linear, Slack, Teams.

## Architecture direction

Scanning runs in ephemeral, isolated workers using the same CLI - the cloud
orchestrates and stores; it does not reimplement analysis. Results land in Postgres (findings,
history, policy) with object storage for reports and graph artefacts. Neo4j becomes viable here
for cross-repository graph queries where SQLite does not fit.

## Data handling

Source code is processed in ephemeral workers and not retained after a scan; findings, graph
metadata and reports are. Customer-managed encryption keys, regional data residency, and a
self-hosted option for organisations that cannot send source anywhere - which, for a security
product sold to security teams, is a requirement rather than an enterprise upsell.

## Sequencing

Nothing here starts before v1.0 has real adoption. Building a collaboration platform for a tool
nobody has adopted yet is the most common way this kind of product dies - the CLI has to earn
the audience first.
