## Global Plan Note

- The NDSS'15 paper "No More Gotos: Decompilation Using Pattern-Independent Control-Flow Structuring and Semantics-Preserving Transformations" looks useful as a source of structuring ideas for Inertia.
- If used, it should inform the CFG/structuring layer and not displace earlier recovery priorities such as alias recovery, far-pointer recovery, segmented-memory correctness, call/return recovery, or typed object recovery.
- Any adopted idea should become a general-purpose plan item tied to the existing `angr_platforms` modules, not a source-specific rescue.

## Architecture Strengthening

- The current architecture still makes sense and should not be replaced.
- What should change is the framing around it:
  - Recovery axis:
    - `IR -> Alias -> Widening -> Traits -> Types -> Rewrite`
  - Confidence axis:
    - evidence
    - assumptions
    - diagnostics
    - scan-safe classification
- This is not a new architecture. It is a second explicit layer that makes recovery quality and confidence visible without moving semantics into late rewrite.

## Structuring Layer

- Control-flow structuring should be treated as a more explicit layer between `Types` and `Rewrite`, or as a dedicated sub-pipeline adjacent to `Types`.
- Papers like DREAM are most useful here.
- Structuring must consume already good alias and widening facts; it must not replace them.

## Confidence Output

- Assumptions and confidence should become first-class output.
- The goal is not just `worked / did not work`, but more explicit states such as:
  - target recovered with strong evidence
  - helper guessed from weak evidence
  - far-pointer unresolved
  - return-shape uncertain
- This fits well with the formal-lifting ideas already tracked here and strengthens the current architecture instead of replacing it.

## Applicable Formal-Lifting Ideas

- The PLDI'22 work on formally verified lifting and the related FoxDec work look useful for Inertia as sources of engineering ideas, but not as wholesale architecture replacements.
- The most applicable idea is to make lifting and recovery produce more explicit evidence:
  - bounded indirect control-flow evidence
  - return-address or return-target integrity evidence
  - calling-convention and preserved-register evidence
  - explicit assumptions when the decompiler cannot prove a property
- This fits Inertia well because it can strengthen the early pipeline without pushing semantics into late rewrite.

## Ideas To Implement

1. Add explicit recovery evidence objects for risky control-flow facts.
   - Goal:
     - make `decompile.py` and `angr_platforms/X86_16` record why a call target, return path, or indirect branch target is believed to be sound
   - Good fit:
     - call recovery
     - far/near target recovery
     - scan-safe timeout and failure classification
   - Constraint:
     - keep this as conservative metadata and diagnostics, not as guessed semantics

2. Introduce assumption reporting instead of silent degradation.
   - Goal:
     - when recovery depends on an unresolved external helper, unknown alias relation, or uncertain segmented target, emit an explicit assumption or warning marker in analysis output and scan reports
   - Good fit:
     - external helper modeling
     - unresolved far-pointer relations
     - partially recovered wrappers
   - Constraint:
     - prefer honest output plus an assumption note over a pretty but guessed rewrite

3. Strengthen pre-codegen symbolic simplification using proof-style invariants.
   - Goal:
     - improve the symbolic execution / normalization layer so loop-carried values, stack-slot identities, and segmented addresses are simplified with stronger invariants before C text generation
   - Good fit:
     - `_strlen`-class loop-carried word values
     - stack-slot stabilization
     - segmented address normalization
   - Constraint:
     - this belongs before final text cleanup and should not become a late string-rewrite bandage

4. Add deterministic sanity checks for calls, returns, and indirect control flow.
   - Goal:
     - encode conservative checks that classify whether a function body appears to preserve stack/return discipline well enough for stronger recovery
   - Good fit:
     - wrapper detection
     - return-value recovery
     - medium/large-model far-call recovery diagnostics
   - Constraint:
     - use these checks to gate confidence and diagnostics, not to reject ordinary corpus inputs too aggressively

5. Expand scan reports with proof-style failure reasons.
   - Goal:
     - classify failures as unresolved aliasing, unresolved indirect target, weak return evidence, segmented-memory ambiguity, or structuring failure
   - Good fit:
     - existing scan-safe and timeout classification work
   - Constraint:
     - the reporting should guide earlier-layer fixes and reduce late rescue logic

## Not The Right Takeaways

- Do not try to turn Inertia into a formally verified x86-64 lifting project.
- Do not make proof obligations or Hoare-style modeling a prerequisite for ordinary decompilation output.
- Do not replace the current architecture rule `IR -> Alias model -> Widening -> Traits -> Types -> Rewrite`.
- Do not pursue recompilable output by sacrificing human-readable recovery for the main DOS corpus.
