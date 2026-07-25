# RAG

Retrieval grounds the AI engine in real security knowledge instead of model memory. A finding's
explanation should cite CWE-89's actual description and Laravel's actual query-builder docs -
not a plausible paraphrase.

## Corpus

| Source | Content | Licence |
| --- | --- | --- |
| **CWE** | Weakness definitions, consequences, mitigations, relationships | MITRE, free |
| **OWASP Top 10 (2021)** | Category descriptions, prevention | CC BY-SA |
| **OWASP ASVS** | Verification requirements by level | CC BY-SA |
| **OWASP API Top 10** | API-specific categories | CC BY-SA |
| **OWASP Cheat Sheets** | The most practically useful remediation text available | CC BY-SA |
| **CAPEC** | Attack patterns, prerequisites, skill required | MITRE, free |
| **MITRE ATT&CK** | Tactics and techniques - used mainly by runtime (v2.0) | free |
| **NIST SSDF** | Secure development practices | public domain |
| **CIS Benchmarks** | Hardening baselines - infra scanning (v2.0) | free tier |
| **CVE / NVD** | Vulnerability records, CVSS | public domain |
| **EPSS** | Exploitation probability scores | FIRST, free |
| **CISA KEV** | Known-exploited catalogue | public domain |
| **Laravel docs** | Security, validation, authorization, queries, Blade | MIT |
| **PHP manual** | Function semantics, security notes | CC BY |

Every chunk keeps `source`, `version`, `url` and `licence` so citations resolve and attribution
is correct.

## Chunking

Chunk on **semantic units**, not fixed token windows: one CWE entry, one cheat-sheet section,
one Laravel doc subsection. A CWE description split across two chunks retrieves badly and reads
worse. Target 200-800 tokens with parent-document linking, so a retrieved chunk can pull its
surrounding section when the model needs more.

Each chunk carries structured metadata for pre-filtering:

```json
{
  "id": "cwe-89",
  "source": "CWE", "version": "4.14",
  "title": "Improper Neutralization of Special Elements used in an SQL Command",
  "cwe": ["CWE-89"], "owasp": ["A03:2021"],
  "languages": ["php"], "frameworks": ["laravel"],
  "kind": "weakness",
  "url": "https://cwe.mitre.org/data/definitions/89.html"
}
```

## Storage and retrieval

**LanceDB** - embedded, file-based, no server, ships inside the package. Matches the
offline-first constraint; a RAG layer requiring a running vector database would violate NFR-4.

Retrieval is **hybrid**, and mostly not semantic:

1. **Metadata pre-filter first.** A finding already carries its CWE, OWASP category, language
   and framework. Filtering on those beats semantic search outright - this is a lookup problem
   more than a search problem, and treating it as pure vector search is a common mistake.
2. **BM25 keyword search** over the filtered set - security text is full of exact terms
   (`whereRaw`, `escapeshellarg`, `CWE-89`) where lexical matching wins.
3. **Vector search** for conceptual similarity where wording differs.
4. **Reciprocal rank fusion** to merge, then take top-k (default 4).

Embeddings come from the configured provider, or a local sentence-transformer model when
offline. The index ships **pre-built** in the package: users must never wait on an embedding
pass at first run, and offline users could not do it at all.

## Corpus updates

Static knowledge (CWE, OWASP, CAPEC) is versioned with releases. Volatile data (CVE, EPSS, KEV,
Composer advisories) refreshes via `vigilloo update` - explicit, never automatic, never during a
scan. A scan's report records the corpus version it used, so a result from six months ago is
interpretable today.

## Grounding rules

- Chunks are supplied to the model as **reference material**, clearly delimited, never as
  instructions.
- Every citation in an `AIVerdict` must resolve to a chunk actually supplied for that finding.
  Unresolvable citations fail validation ([09-ai-engine](../09-ai-engine/README.md)).
- Retrieval returning nothing relevant is reported as such; the model is told to rely on the
  evidence path alone rather than inventing support.

## Not RAG

The user's own source code is **not** in the vector store. Code context comes from the graph,
which is exact, current and structured - retrieving code by embedding similarity would be
strictly worse than traversing a call graph that already knows the answer. Semantic code search
is a possible future convenience feature (`vigilloo ask`), not part of the analysis path.
