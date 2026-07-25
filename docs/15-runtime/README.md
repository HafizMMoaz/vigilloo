# Runtime

Observes a deployed application and correlates what it sees against the static knowledge graph.

> **Status: v2.0. Not implemented in v0.1.**

## Why it belongs in the same product

Static analysis knows the code; runtime knows the reality. Individually each is half an answer.
Joined through the same graph they answer questions neither can alone:

- "This SQL injection is in a route nobody has called in 90 days" → deprioritise.
- "This vulnerable package's affected function is executing 4,000 times a day" → escalate.
- "Requests are hitting a route that the route table says does not exist" → investigate.
- "This finding's exact taint path just appeared in the WAF log" → active exploitation.

The correlation is the product. Log monitoring on its own is a crowded, well-served market;
log monitoring that knows the taint paths in the code producing the logs is not.

## Collection

**Agentless first.** Reading logs over SSH beats deploying an agent that a security team then
has to review and approve.

| Source | Signals |
| --- | --- |
| Laravel logs (`storage/logs/*.log`) | Exceptions, stack traces, `APP_DEBUG` leakage, auth failures |
| Web server logs (nginx/Apache) | Request volume per route, status codes, anomalous methods, scanner fingerprints |
| PHP-FPM logs | Slow requests, worker exhaustion, fatal errors |
| System (`journald`, `syslog`, `auth.log`) | SSH auth, sudo, service restarts, package changes |
| Process table | Unexpected processes, PHP spawning shells - the clearest post-exploitation signal |
| Network (`ss`, `netstat`) | Unexpected listeners, outbound connections to unknown hosts |
| Containers | Docker/K8s events, image drift, privileged containers |
| Filesystem | Writes to `public/` (webshells), permission changes, unexpected new PHP files |

## Detection

1. **Signature** - known attack patterns in request logs (SQLi, traversal, webshell paths,
   known scanner user agents), mapped to MITRE ATT&CK techniques.
2. **Anomaly** - baseline normal per route (volume, status distribution, timing) and alert on
   deviation. Requires a learning window; noisy before it has one, and honest about that.
3. **Graph-correlated** - the differentiator. A request pattern matching a known taint path in
   the code is a far stronger signal than either fact alone.
4. **Integrity** - new or modified PHP files in web-accessible directories, checked against the
   last known scan state.

## Laravel-specific runtime signals

- Stack traces in HTTP responses → `APP_DEBUG` enabled in production
- `/telescope`, `/horizon`, `/_ignition`, `/.env`, `/storage/logs` publicly reachable
- Queue failure spikes, jobs retrying indefinitely
- Session anomalies: fixation, mass invalidation, concurrent use of one session from many IPs
- Requests to routes not present in the route table - shadow routes or a compromised deployment

## Output

Events, not findings - a separate type with its own severity and lifecycle, correlated to static
findings where possible. Alerting via webhook, Slack, email or syslog. `vigilloo monitor --watch`
gives a live Textual dashboard.

## Constraints

Read-only by default: the monitor observes and reports, it does not block, kill processes or
modify firewall rules. Automated response requires explicit configuration and carries a real
risk of self-inflicted outage - the tool should be honest that a false positive with response
enabled takes down production.

Collection is rate-limited and resource-capped; a security monitor that degrades the host it
watches gets uninstalled.

## CLI

```bash
vigilloo monitor --target prod-web-01           # agentless over SSH
vigilloo monitor --logs /var/log/nginx/access.log --correlate
vigilloo monitor --watch                        # live dashboard
vigilloo monitor --baseline 7d                  # learn normal, then alert
```
