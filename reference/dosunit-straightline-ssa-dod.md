# DOS Unit Straight-Line SSA DoD

## Goal

Lower bounded straight-line IR into a compact SSA artifact and compare original
vs rebuilt formulas with Z3.

The implemented adapter is VEX-backed. VEX already provides single-assignment
temps, so the tool must not decode x86 instruction semantics itself. It only:

1. forces the existing x86-16 lifter through `project.factory.block(...).vex`
2. records final requested `PUT(reg)` outputs
3. backward-slices through the VEX temp definitions that reach those outputs
4. serializes the small expression graph as `dosunit.ssa.v1`
5. asks Z3 if oracle and candidate outputs can differ

AIL should later become another frontend adapter into the same compact SSA
schema. It must not change the comparison format.

## Compact SSA Shape

`dosunit.ssa.v1` records:

- function id/name and entry
- source IR metadata (`source_ir = vex`)
- lifted instruction list for visibility
- symbolic inputs used by the slice
- SSA assignments, each with stable id, op, width, args
- outputs mapping registers to terms
- typed refusals for unsupported effects

Leaf terms:

```json
{"op": "input", "name": "bx", "width": 16}
{"op": "const", "value": "0x1", "width": 16}
```

Assignment terms:

```json
{"id": "v0", "op": "add", "width": 16, "args": [...]}
```

## Supported First Pass

Allowed:

- one bounded VEX block
- straight-line arithmetic and bitwise expressions
- register inputs and outputs
- near `ret` noise may exist in VEX, but return-IP memory loads are dropped if
  not observed
- unused flag computations are dropped by backward slicing

Refused:

- conditional/unconditional branches
- calls and interrupts
- VEX exits
- explicit memory operands, until segmented symbolic memory is added
- memory stores
- output slices depending on memory loads
- partial-register reads/writes that VEX does not normalize to whole-register
  expressions
- unsupported VEX statement/expression kinds
- instruction count above the configured bound

## Compare Semantics

`dosunit compare-ssa` compares functions by mapping document when provided,
otherwise by name+ordinal, and uses Z3 to check:

```text
exists inputs . oracle_output != candidate_output
```

If unsatisfiable, the selected outputs are equivalent for the bounded slice. If
satisfiable, the result is failed and includes a concrete counterexample model.

## Verification

Run:

```bash
rtk pytest -q angr_platforms/tests/test_dosunit_tool.py -k 'ssa'
rtk pytest -q angr_platforms/tests/test_dosunit_tool.py
rtk python -m py_compile tools/dosunit/*.py dosunit.py
```

Required fixtures:

- `mov ax,bx; add ax,1; ret` lowers to a small `add` slice
- unused flag computations and return-IP stack loads are absent from the slice
- `mov ax,bx; add ax,1; ret` is equivalent to `mov ax,bx; inc ax; ret`
- `add ax,1` vs `add ax,2` fails with a Z3 counterexample
- output depending on `[si+disp]` is refused as `unbounded_memory`
- `mov al,imm; ret` lowers through VEX as `(AX & 0xff00) | imm`
- mapped functions compare successfully even when original and rebuilt names differ
