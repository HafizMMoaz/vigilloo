# Attack Surface Monitoring (ASM)

Beginning in v2.0, Vigilloo expands beyond pure static application security testing (SAST) into Attack Surface Monitoring. This capability maps the external footprint of the organization's infrastructure and correlates it with the internal codebase analysis.

## Core Capabilities

1. **Subdomain Enumeration:** Passively identifying associated subdomains and mapping them to services.
2. **Exposed Endpoint Mapping:** Cross-referencing exposed web ports with the static route table (from the SAST graph).
3. **Cloud Asset Discovery:** Scanning AWS, GCP, and Azure configurations for public buckets, unauthenticated APIs, and dangling DNS entries.
4. **Third-Party Risk:** Identifying SaaS services hooked into the architecture.

## Integration with the Knowledge Graph

ASM data will be ingested directly into the `.vigilloo/` SQLite store as distinct node types: `DOMAIN`, `ENDPOINT`, `IP_ADDRESS`, and `CLOUD_ASSET`.

Edges like `HOSTS` and `EXPOSES` will connect these external concepts to the internal `ROUTE` and `CONTROLLER` nodes discovered during static analysis. This allows a security engineer to query:
> *Which unauthenticated Laravel routes are currently exposed to the internet via an actively resolvable subdomain?*

## Tools & Prior Art

We will build ASM modules natively in Python to maintain strict control and dependency isolation, drawing architectural inspiration from tools indexed in awesome-attack-surface-monitoring. 
