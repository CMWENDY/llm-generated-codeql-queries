### Message 2 — Iterative Refinement

```
## Objective
Refine the query based on the execution results below.

## Previous Query
[paste current .ql file here]

## Compilation Output
[paste exact compiler output — ALL lines including warnings]

## Execution Results
- Vulnerable DB: [N] results
- Fixed DB: [N] results

## Detailed Results (fill in what you can)
- On the vulnerable DB, which files/methods did the query match (if any)?
- On the fixed DB, which files/methods did the query match (if any)?
- Which file/method contains the actual vulnerability (from the diff)?

## Diagnosis

Pick the correct status:

COMPILE ERROR — Fix compilation errors first. Do not change any logic until it compiles.
Common C++ issues: use FunctionCall not MethodCall, getTarget().hasGlobalName(...)
not hasName(...).

MISS (0 results on vulnerable DB) — The source or sink pattern isn't matching.
Try these in order:
1. Loosen the source: remove qualifiers one at a time. Start with just the method name,
   then add package/class qualification back once it hits.
2. Loosen the sink: same approach — does ANY call to that function exist in the codebase?
3. Run a diagnostic query (separate file):
   from FunctionCall fc where fc.getTarget().hasName("yourSinkFunctionName") select fc
   If that returns nothing, the function name is wrong.
4. Check if the taint path is indirect — you may need isAdditionalFlowStep to bridge
   struct fields, function pointers, or wrapper calls.

PARTIAL (fixed DB still has results) — The sanitizer is not correctly excluding the fix.
The sanitizer must match the EXACT AST shape of the + lines in the patch:
- If the patch added a bounds check before the sink call, the barrier needs to match
  that guard, not the sink itself
- If the fixed DB results are in a different function than the vulnerable DB results,
  your sanitizer may be too broad — add qualifier constraints to tie it to the right object

## Revised Query Instructions

Apply exactly one class of changes per iteration.
Do not restructure the entire query — change only what the diagnosis points to.

Output the complete revised .ql file.
```
