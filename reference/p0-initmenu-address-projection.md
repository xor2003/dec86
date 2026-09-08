# InitMenu Address Projection (2026-09-08)

## Status

The address-versus-value projection bug is fixed, but **InitMenu is not
accepted**. Four numeric LEA carriers still prevent compilation. No fallback,
compiler check, or validation gate was weakened.

## Root Cause And Repair

The live structured AST contained
`Reference(And(Cast(stack_variable), 0xff))`. The Widening subview pass protected
assignment lvalues but traversed address-of operands as value reads, replacing
a referenced byte object with a masked scalar value.

`widening/stack_subview_projection.py` now excludes both `Reference` and
`AddressOf` operands from its value-only traversal. Ordinary byte reads still
materialize their proven masks. The existing regression now distinguishes
these three contexts and exercises both low and high bytes: two cases failed
before; all pass after. The test file remains below 350 lines.

Lowering also accepts typed stack-array decay as an address argument and
constant masks around pure address expressions. It still refuses scalar-value
arguments and requires the exact registered storage identity plus the original
LEA/PUSH/callee proof. These typed-form tests had three failures before their
repair. They alone did not change InitMenu; the Widening correction exposed
the valid references needed for actual proof consumption.

In the live function, three redundant setups before `sub_1123a` are now removed.
The buffer-copy calls and arguments remain unchanged. Four setups before
`sub_12756` are kept: each argument is a 16-byte `SimStackVariable` array at
entry-SP offset -20, but its variable object is absent from the coordinate
registry. This is missing identity evidence, not a callee-input proof failure.
The working copy-call arguments resolve to the registered BP offset -18.
Do not equate the missing objects by raw offset or display name.
The consumer census is raw 7, normalized 3, classified 3, materialized 3,
failure/refusal 4.

## Verification

- 67 focused tests passed in 13.50s; scoped Ruff `check --fix`, MyPy and Pyright
  passed for both production owners.
- Default pipeline: **2,431 passed in 151.86s**, all three lanes passed, and all
  seven MS C tiny compile/run/decompile/recompile/exit-code checks passed.
- Slowest tests: RunMenu ESC preservation 45.13s, indexed-address inventory
  25.42s, layer boundaries 20.83s, sidecar-free InitBars 20.03s.
- Global quality-fast remains red with 99 MyPy diagnostic lines.
- Full architecture checks passed.
- InitMenu remains `validation_failed`, with stable whole-tail stages but no
  accepted-C or GCC hash. The pipeline result does not close this function.

Logs and JSON evidence: `/tmp/inertia-stack-reference-*`,
`/tmp/inertia-setup-proof-probe.jsonl`, and `/tmp/inertia-stack-decay-probe-*`.
The observational probe did not change matching, proof verdicts or output.
Measured local UTC+02:00 interval: failing subview regression 12:38:53-12:39:05;
pipeline 12:40:55-12:45:34. Concurrent diagnostic work means these are wall
intervals, not controlled performance measurements or total task effort.

## Next Obligation

Trace where the four text-output argument variable identities diverge from
the registered aggregate. Existing owners include `stack_coordinate_rebinding`
and `stack_aggregate_projection`; the generic AST clone helper deliberately
preserves non-AST variable objects and must not be blamed without evidence.

Reason: deletion needs the same authoritative storage identity as argument
materialization. DoD: preserve explicit clone/rebinding provenance, keep wrong
region/identifier/width refusals, and make the live function pass validation,
recompilation and source-call regressions. Definition of Failure: inventing a
registry alias from offset/name similarity, repairing identity in Rewrite/CLI,
or claiming acceptance while any setup or semantic check still fails.
