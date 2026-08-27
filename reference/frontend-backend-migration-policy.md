# Angr Migration Policy

## Objective

Move incrementally from angr as a general toolkit toward small, owned,
deterministic components. This includes loading, decoding, lifting, memory and
machine state, execution, CFG construction, analyses, IR transport,
decompiler integration, and validation. Use Rizin only where evidence shows a
narrow adapter is more reliable and maintainable than owned code. This is
never a flag-day rewrite.

## Required sequence

1. Keep typed `Value`, `Address`, `Condition`, segmented-memory, register-effect,
   control-flow, and validation contracts backend-neutral.
   Migration must not reduce supported functionality or architectural effects;
   an audit exclusion is not permission to lose an in-scope capability.
2. Isolate angr and pyvex behind explicit adapters. New decompiler semantics
   must not depend on VEX temporaries, angr object shape, or undocumented
   symbolic-memory behavior.
3. Replace one bounded component at a time: DOS loading and relocation,
   decoding, effective-address calculation, instruction semantics, machine
   state and memory, block construction, CFG, analyses, decompiler adapters,
   then validation execution. Keep stable contracts between components so
   either implementation can be selected during migration.
4. Differentially validate each replacement against defined 80286/80386
   real-mode behavior and the current frontend on practical DOS inputs.
5. Require deterministic output, no silent instruction loss, focused tests,
   tail-validation parity, and representative corpus parity before changing a
   default. Keep the previous backend as an oracle until these gates pass.
6. Benchmark cold start, lift throughput, peak memory, and generated-IR size.
   Performance never justifies weakening correctness gates.
7. Prefer owned code when it is small enough to audit and test completely. Use
   Rizin only through a narrow, versioned adapter with explicit compatibility
   tests and a documented upgrade process.
8. Remove an angr dependency only after all owned projections, diagnostics,
   documentation, and tests consume the replacement contract.

## Implementation constraints

- Design owned modules as typed data plus small explicit functions. Avoid
  dynamic attribute discovery, monkeypatching, runtime class generation,
  plugin registries, and reflection in hot paths.
- Prefer enums, frozen or slotted dataclasses, tuples, integer bit operations,
  and compact arrays over large polymorphic object graphs.
- Keep decode and execution tables immutable and module-level. Separate cold
  setup from hot per-instruction paths and avoid repeated parsing or allocation.
- Make hot loops friendly to the CPython JIT and mypyc: stable value types,
  predictable branches, direct calls, typed collections, and no dependence on
  interpreter frame inspection or unsupported dynamic Python behavior.
- Keep multiprocessing inputs and results small, immutable, serializable, and
  deterministically ordered. Bound worker memory and avoid shared mutable state.
- Do not optimize by exposing backend details to semantic consumers. Measure
  each replacement independently and retain a simple non-JIT Python path for
  debugging and differential tests.

## Scope boundary

Follow `reference/real-mode-edge-policy.md`. Preserve divide errors and other
in-scope architectural effects. Backend artifacts, including angr host-side
4 KiB storage boundaries, must never become DOS architectural semantics.
