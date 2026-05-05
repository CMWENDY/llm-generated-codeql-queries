### Message 1 — Initial Query Generation

```
## Task
Write a CodeQL query that detects a real security vulnerability in C/C++.
Success means: ≥1 result on the VULNERABLE version, ZERO results on the FIXED version.

## Inputs

### CWE Type
[e.g. CWE-022 Path Traversal, CWE-125 Out-of-bounds Read, CWE-078 OS Command Injection]

### Vulnerability Description
[paste CVE description or vulnerability summary here]

### Patch Diff
[paste the patch diff here]

### Additional Context (optional)
[crash info, stack traces, notes about the codebase]

---

## Step 1 — Analyze Before Writing

Reason through these four things explicitly BEFORE writing any code:

1. SOURCE: Where does untrusted input enter the program?
   - What does the attacker control? (file path, buffer, network input, argument, etc.)
   - What is the exact function name or parameter where that input first appears?

2. SINK: Where does the dangerous operation happen?
   - Look at the - lines in the diff (code present in the vulnerable version, near the fix)
   - What function call uses the tainted input unsafely?
   - What is the exact spelling of that function name in the source?

3. SANITIZER: What exactly did the patch add?
   - Look ONLY at the + lines in the diff
   - What check, guard, or configuration was introduced?
   - Be precise: what function is called, with what arguments, on what object?
   - This must be ABSENT in the vulnerable version and PRESENT in the fixed version

4. TAINT PATH: Is the flow direct (arg passed straight to sink) or indirect?
   - Indirect means: the value goes through a struct field, a wrapper function,
     a callback, or a pointer before reaching the sink
   - If indirect, you will need isAdditionalFlowStep

---

## Step 2 — Validate Patterns With Diagnostic Queries First

Before writing the full taint query, write and run these two diagnostic queries.
Each one must return results before you proceed. Do not skip this step.

### Diagnostic A — Confirm the sink exists in the database
import cpp
from FunctionCall fc
where fc.getTarget().hasGlobalName("REPLACE_WITH_SINK_FUNCTION_NAME")
select fc, fc.getLocation()

- If this returns 0 results: the function name is wrong or namespaced differently.
  Try hasName("...") without the global qualifier, or check the diff for exact spelling.
- Do NOT proceed to the full query until Diagnostic A returns results.

### Diagnostic B — Confirm the source exists in the database
import cpp
from FunctionCall fc
where fc.getTarget().hasGlobalName("REPLACE_WITH_SOURCE_FUNCTION_NAME")
select fc, fc.getLocation()

- If source is a parameter rather than a function call, use:
import cpp
from Parameter p
where p.getType().getName() = "REPLACE_WITH_TYPE"
  and p.getFunction().hasGlobalName("REPLACE_WITH_ENCLOSING_FUNCTION")
select p, p.getLocation()

- If this returns 0 results: strip all qualifiers and match on name alone first,
  then add constraints back one at a time.
- Do NOT proceed to the full query until Diagnostic B returns results.

---

## Step 3 — Write the Full Taint Query

Only after both diagnostics return results, write the full query:

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.dataflow.DataFlow

class VulnSource extends DataFlow::Node {
  VulnSource() {
    exists(FunctionCall fc |
      fc.getTarget().hasGlobalName("SOURCE_FUNCTION_NAME") |
      this.asExpr() = fc
    )
    // OR for a parameter as source:
    // exists(Parameter p |
    //   p.getFunction().hasGlobalName("ENCLOSING_FUNCTION") |
    //   this.asParameter() = p
    // )
  }
}

class VulnSink extends DataFlow::Node {
  VulnSink() {
    exists(FunctionCall fc |
      fc.getTarget().hasGlobalName("SINK_FUNCTION_NAME") |
      this.asExpr() = fc.getArgument(N)
    )
  }
}

class VulnSanitizer extends DataFlow::Node {
  VulnSanitizer() {
    exists(FunctionCall fc |
      fc.getTarget().hasGlobalName("SANITIZER_FUNCTION_NAME") |
      this.asExpr() = fc.getArgument(N)
    )
  }
}

module VulnConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof VulnSource }
  predicate isSink(DataFlow::Node sink)     { sink instanceof VulnSink }
  predicate isBarrier(DataFlow::Node node)  { node instanceof VulnSanitizer }

  // Only include if taint path is indirect
  // predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
  //   exists(FunctionCall fc |
  //     fc.getTarget().hasGlobalName("WRAPPER_FUNCTION") and
  //     n1.asExpr() = fc.getArgument(0) and
  //     n2.asExpr() = fc
  //   )
  // }
}

module VulnFlow = TaintTracking::Global<VulnConfig>;
import VulnFlow::PathGraph

from VulnFlow::PathNode source, VulnFlow::PathNode sink
where VulnFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Tainted value from $@ reaches dangerous operation without sanitization",
  source.getNode(), "untrusted input"

---

## Step 4 — Self-Check Before Outputting

- Did Diagnostic A return results? If not, fix the sink name first.
- Did Diagnostic B return results? If not, fix the source pattern first.
- Does my sanitizer match the EXACT + lines from the diff, not a loose paraphrase?
- If the taint path crosses a function boundary or goes through a struct,
  do I have isAdditionalFlowStep to bridge it?
- Am I using hasGlobalName (fully qualified) or hasName (unqualified)?
  For functions in a namespace, hasGlobalName needs the full path including namespace.

Output the two diagnostic queries first, then the full .ql file.
```

