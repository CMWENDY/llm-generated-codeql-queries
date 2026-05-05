# LLM-Driven CodeQL Query Synthesis for C/C++ Vulnerabilities

Experimenting with using LLMs to automatically generate CodeQL queries for C/C++ vulnerability detection — given a CVE description and a patch diff, can a prompted LLM produce a query that fires on the vulnerable version of a codebase and goes silent on the fixed version?

This is inspired by [QLCoder](https://arxiv.org/abs/2511.08462) (Wang et al., ICLR 2026), which builds a full agentic framework around this problem: iterative refinement loops, a CodeQL Language Server via MCP, a RAG database of sample queries and CWE definitions, and execution feedback at every step. I'm working on a lighter version of this — prompt-driven, no custom infrastructure — to see how far careful prompting alone can get.

---

## What I'm Trying to Do

The core task is **vulnerability query synthesis**: given a known CVE, produce a CodeQL path query that:

1. Detects at least one dataflow path through the vulnerability in the pre-patch codebase
2. Produces zero results on the patched version

This is harder than it sounds. The query has to correctly identify the source (where untrusted input enters), the sink (where the dangerous operation happens), and the sanitizer (the exact check the patch introduced). If any of those three are wrong — wrong function name, wrong argument position, wrong AST shape — the query either misses the bug entirely or keeps firing after the fix.

The approach right now is structured prompting: give the model the CVE description, the patch diff, and a clear template, then iterate based on execution feedback.

---

## Progress

### What's working

- Prompt structure that forces the model to reason about source/sink/sanitizer explicitly before writing any code, rather than jumping straight to a query
- Separating the **diagnostic phase** from the **full taint query** — running two small queries first to confirm the source and sink patterns actually match something in the database before assembling the full query
- Using `TaintTracking::Global` with proper `isSource`/`isSink`/`isBarrier` predicates instead of pure structural AST matching (which was the original approach and the reason for consistent 0 results)

### What's not working yet

- Still getting 0 results on the vulnerable database in most cases
- The root cause is usually one of:
  - The sink function name doesn't match what's actually in the database (wrong spelling, namespaced differently, method vs free function)
  - The taint path is indirect — goes through a struct field, a wrapper function, or a callback — and without `isAdditionalFlowStep`, CodeQL can't see the connection
  - The model generates syntactically valid but semantically wrong predicates (correct structure, wrong API names for the CodeQL version being used)

---

## The Prompts
Located in repo.

---
