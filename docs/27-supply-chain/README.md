# Supply Chain

**v0.7.** The layer that answers one question before a developer's machine executes anything it
did not write: *is this package safe to install?*

This document is normative. It specifies the interception points, the verdict engine, the
ecosystem coverage and the boundary Vigilloo does not cross.

## Why this exists

The breaches that hurt engineering organisations are rarely a bug in code the team wrote. They
are a malicious `postinstall` script, a typosquatted dependency one edit-distance from a real
one, a compromised version of a package that was fine last week, or an IDE extension that
shipped a credential stealer to everyone who clicked install.

Every one of those has the same shape: **untrusted code arrives on a developer's machine and
runs, with that developer's privileges, before anyone reviews it.** That moment is the one this
layer defends.

## Scope

**In scope:** packages installed through a package manager, and extensions installed into an
IDE. The artifact is named, versioned, and fetched from a registry, which is what makes a
verdict possible.

**Out of scope, permanently:** software installed outside a package manager. A `.dmg`, an
`.msi`, a `brew install`, a curl-pipe-shell. See [The privilege boundary](#the-privilege-boundary).

## The privilege boundary

**Vigilloo ships no privileged component. Not now, not later.** There is no daemon, no root
helper, no kernel extension, no system extension.

Where an organisation needs host-level visibility into arbitrary software installation, Vigilloo
consumes events from [Santa](https://github.com/northpolesec/santa) or
[osquery](https://osquery.io), which the customer installs, configures and owns. Vigilloo reads;
it does not gain privilege.

This is a decision, not an omission. It was taken for three reasons, recorded here so it is not
re-litigated by accident:

1. **The entitlement is a hard dependency on a third party.** Observing process execution on
   macOS requires Apple's `com.apple.developer.endpoint-security.client` entitlement, granted
   case by case against a business justification, on Apple's timeline. Windows needs a separate
   ETW or minifilter implementation and Linux a third. That is three platform-specific
   codebases, none of which share the knowledge graph that is the product's differentiator.
2. **A root daemon in a security product is a privilege-escalation surface.** Any bug in a
   component running as root on a developer's machine is a local privilege escalation. For a
   tool whose entire proposition is trustworthiness, that is an existential bug class, and it
   would be shipped ahead of any measurement of the engine's precision.
3. **It is a commodity.** Santa, osquery, and the commercial EDR vendors do this well and for
   free or at scale. Building a fourth is spending the one resource that cannot be bought back
   on a capability nobody would choose Vigilloo for.

The interception this layer *does* perform needs no privilege at all. A package manager
integration runs in userland, as the developer.

## Architecture: two tiers

Tier 1 detects across every ecosystem for one implementation. Tier 2 prevents, for one
ecosystem per implementation. They are separately useful and they ship in that order.

```text
                    ┌──────────────────────────────┐
  lockfile change ──▶│  Tier 1: lockfile differ     │──┐
  (any ecosystem)    │  detects, cannot block       │  │
                    └──────────────────────────────┘  │
                                                      ├──▶ verdict engine ──▶ report
                    ┌──────────────────────────────┐  │        │
  install command ──▶│  Tier 2: pre-install hook    │──┘        │
  (per ecosystem)    │  blocks before code runs     │◀──────────┘
                    └──────────────────────────────┘   allow / warn / block
```

### Tier 1: the lockfile differ

Watches the project's lockfiles. On change, diffs old against new and evaluates every package
that was added, upgraded, or whose resolved integrity hash moved.

This needs no cooperation from any package manager, which is what makes broad coverage cheap: a
lockfile parser plus an [OSV](https://osv.dev) ecosystem identifier is the whole per-ecosystem
cost. No framework adapter is involved, and none is needed - a lockfile has no opinion about
whether the project is Laravel or Symfony or Django.

It runs as a git hook, a file watcher, or a CI step. It **detects and reports; it cannot block**,
because by the time a lockfile has changed the install has already happened.

### Tier 2: the pre-install hook

Per ecosystem, opt-in, and the only tier that stops malicious code before it executes.

- **Composer.** A Composer plugin subscribing to the package installation lifecycle events.
  Written in PHP and distributed on Packagist, because a Composer plugin is loaded and executed
  by Composer itself. See [Repository layout](#repository-layout).
- **npm, pnpm, yarn.** npm exposes no supported plugin API, so this is a wrapper command plus
  enforced `ignore-scripts`. Lifecycle scripts are the primary npm supply-chain attack vector;
  disabling them by default is most of the defence, and the wrapper re-enables them per package
  only after a verdict allows it.

Other ecosystems get Tier 2 only where a supported extension point exists. Where one does not,
Tier 1 is the coverage, and the documentation says so plainly rather than implying protection
that is not there.

## Ecosystem coverage

Tier 1 targets every ecosystem in this table at v0.7. Tier 2 arrives per ecosystem and is not a
v0.7 completeness requirement.

| Ecosystem | Lockfiles (Tier 1) | OSV ecosystem | Tier 2 |
| --- | --- | --- | --- |
| PHP | `composer.lock` | `Packagist` | Composer plugin |
| JavaScript | `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` | `npm` | wrapper |
| Python | `poetry.lock`, `uv.lock`, `requirements.txt` (pinned) | `PyPI` | not planned |
| Rust | `Cargo.lock` | `crates.io` | not planned |
| Go | `go.sum` | `Go` | not planned |
| Ruby | `Gemfile.lock` | `RubyGems` | not planned |
| Java / Kotlin | `gradle.lockfile`, resolved `pom.xml` | `Maven` | not planned |
| .NET | `packages.lock.json` | `NuGet` | not planned |

**This breadth is deliberate and it does not contradict depth-before-breadth.** That rule governs
the *analysis* engine, where a framework adapter costs the entire [08-framework-adapters](../08-framework-adapters/README.md)
surface per framework. Supply chain operates on package identity, so its per-ecosystem cost is a
lockfile parser. The two are not the same kind of breadth and are not traded against each other.

## The verdict engine

One entry point. Given `(ecosystem, name, version)`, return a verdict of `allow`, `warn` or
`block`, with the evidence that produced it.

Inputs, in descending order of trust:

1. **Vendored advisory database.** OSV format, per-ecosystem exports, shipped with Vigilloo and
   refreshed on demand. Offline, per invariant 6. A known-vulnerable version is the strongest
   and least ambiguous signal available.
2. **Static analysis of the package's own source.** For PHP packages this reuses the existing
   parser and taint engine unchanged - scanning a Composer package's PHP is exactly what
   [03-parser](../03-parser/README.md) and [06-taint-analysis](../06-taint-analysis/README.md)
   already do. This is the input no competitor derives from the same engine, and it is the reason
   this layer belongs in Vigilloo rather than beside it.
3. **Deterministic heuristics.** Lifecycle or install scripts present; publication recency
   against the rest of the dependency set; edit distance to a substantially more popular name in
   the same ecosystem (typosquat); maintainer set changed since the previous lockfile.
4. **Reputation.** Registry download counts, repository signals, and published discussion of the
   package. Network-dependent, and constrained by the invariant below.

### Invariant: reputation cannot create or delete a verdict

> Reputation **annotates**. It never decides. A package blocked by the offline inputs stays
> blocked; a package cleared by the offline inputs stays cleared. Verdicts must be byte-identical
> with reputation enabled and disabled, and this is asserted in CI.

This is the same constraint invariant 1 places on the AI engine, for the same reason. It keeps
invariant 6 (offline is complete) and invariant 8 (determinism) intact, and it means the
reputation source can be replaced or dropped without changing what Vigilloo blocks.

## IDE extensions

An extension is a package with a different registry. A `.vsix` is a zip containing a
`package.json` and JavaScript, so the same verdict engine applies with the marketplace as the
ecosystem: the VS Code Marketplace gallery API and the [Open VSX](https://open-vsx.org) REST API
resolve identity, version and publisher.

**This tier is advisories plus heuristics, not deep analysis, and the reports say so.** Static
analysis of bundled and minified JavaScript is weak, and Vigilloo has no JavaScript engine until
v1.5. Claiming otherwise would be the noise [CLAUDE.md](../../CLAUDE.md) warns makes developers
stop reading security output. The heuristics that do work without a JS engine are publisher
identity and change, extension-to-publisher popularity mismatch, requested capabilities against
declared purpose, and name similarity to a more popular extension.

## Graph model

Supply-chain data lands in the same `.vigilloo/` SQLite store as everything else, as node types
`PACKAGE` and `EXTENSION`, with a `DEPENDS_ON` edge from the project. Node IDs are
content-derived and deterministic, per invariant 3.

This is deliberately the shape [25-attack-surface-monitoring](../25-attack-surface-monitoring/README.md)
uses for `DOMAIN` and `ENDPOINT`, and it is what v1.0 reachability upgrades: once a `PACKAGE`
node connects to the symbol nodes its code declares, the existing call graph answers *"is the
vulnerable function reachable from an HTTP route"* with a traversal, not a guess.

## Relationship to neighbouring versions

| Version | Question it answers |
| --- | --- |
| v0.1 `vigilloo deps` | Does `composer.lock` contain a package with a known advisory? Flat lookup, PHP only. |
| **v0.7 (this document)** | Is this package safe to install, across every ecosystem, before it runs? |
| v1.0 Deep SCA | Is the vulnerable code in that package **reachable** from a route in this application? |

Each deepens the one above it and they share the advisory database. v0.1 shipping a shallow
`composer.lock` check is not superseded work; it is the first of three layers over one data
source.

## CLI surface

Per [19-cli](../19-cli/README.md). `vigilloo deps` gains the new ecosystems and the verdict
engine rather than growing a sibling command.

```text
vigilloo deps                    verdicts for every lockfile in the project
vigilloo deps --ecosystem npm    restrict to one
vigilloo deps --watch            Tier 1 lockfile watcher
vigilloo deps --explain <pkg>    the inputs behind one verdict
vigilloo extensions              installed IDE extensions, verdicts
```

## Repository layout

The Composer plugin is **PHP, released to Packagist**, and cannot live under `src/`, which is the
`vigilloo` Python package. It gets its own top-level directory and its own release process:

```text
integrations/
  composer-plugin/     PHP, Packagist, its own composer.json and CI job
  npm-guard/           the npm/pnpm/yarn wrapper
```

[23-dev-guide](../23-dev-guide/README.md) forbids sibling top-level *package* directories. That
rule is about Python packages competing with `src/` for the `vigilloo` import name, and
`integrations/` does not, so this is an explicit carve-out rather than an exception: nothing in
`integrations/` is importable Python, and nothing there is registered in `pyproject.toml`.

## To verify before implementation

Recorded so the implementation plan starts from checked facts rather than from this document's
assumptions:

- The exact Composer plugin event that permits **aborting** an install, as opposed to observing
  one. The plugin is worthless for Tier 2 if the lifecycle offers no veto point.
- Whether OSV's per-ecosystem exports are redistributable under Vigilloo's proprietary licence,
  and under what attribution. This gates vendoring, and vendoring is what invariant 6 requires.
- Whether the VS Code Marketplace gallery API is usable under its terms of service for this
  purpose. Open VSX is documented and openly licensed; the Microsoft gallery endpoint is neither
  officially documented nor obviously permitted, and may not be usable at all.
- Whether `requirements.txt` is worth supporting in Tier 1. It is frequently unpinned and
  unhashed, and a verdict on an unpinned requirement is a verdict on nothing.
