# DOS Unit Test Tool Plan

## Goal

Build a general-purpose DOS function unit-test tool for `.exe` and `.com`
programs.

The tool must generate and replay per-function machine-state tests:

- input registers, segment registers, flags, stack, and memory
- output registers, flags, memory writes, control-flow outcome, and calls
- oracle data from original x86 execution
- candidate comparison for reconstructed C, decompiled C, and reassembled ASM

This is not an F-15-specific tool. F-15 Strike Eagle 2 is the first corpus.

## Non-Goals

- Do not put unit-test orchestration into `kvikdos`.
- Do not make `kvikdos` responsible for VEX, Z3, manifests, discovery, or
  candidate comparison.
- Do not trust symbolic execution as the final oracle.
- Do not flatten segmented memory inside Inertia or the test manifest.
- Do not infer behavior from rendered C/ASM text.

## Core Split

```text
VEX / typed Inertia IR + Z3
  -> synthetic test input generation

libdosbox runtime recorder
  -> real gameplay/runtime seed data

libkvikdos execution backend
  -> fast in-process deterministic original/candidate execution

dosunit
  -> manifest handling, discovery, orchestration, oracle recording, comparison
```

## Components

### 1. `libkvikdos`

Extract an embeddable backend from `/home/xor/kvikdos/kvikdos.c`.

It should expose DOS execution primitives only:

```c
dosvm_create(...)
dosvm_destroy(...)
dosvm_load_program(...)
dosvm_snapshot_create(...)
dosvm_snapshot_restore(...)
dosvm_get_regs(...)
dosvm_set_regs(...)
dosvm_read_memory(...)
dosvm_write_memory(...)
dosvm_install_trap(...)
dosvm_run_until_trap(...)
```

The current `kvikdos` CLI remains a thin wrapper around this backend.

Important behavior:

- initialize KVM once per test session
- load each DOS program once
- create a clean baseline snapshot after load and relocation
- restore baseline with memory copy before each vector
- avoid spawning one process per function test
- expose full general registers, flags, and segment registers
- expose selected memory reads and diffs
- support near return, far return, HLT trap, timeout, and fault outcomes

### 2. `dosunit`

`dosunit` is the general unit-test tool.

Candidate commands:

```bash
dosunit discover --exe egame.exe --map egame.map --ida-listing egame.lst
dosunit gen-vectors --exe egame.exe --functions functions.json
dosunit import-libdosbox --trace EGAME.json --dump EGAME.1
dosunit record-oracle --exe original.exe --vectors vectors.json
dosunit compare --oracle original.exe --candidate rebuilt.exe --vectors vectors.json
```

Responsibilities:

- parse manifests
- discover functions and addresses
- call the VEX/Z3 generator
- import libdosbox runtime samples
- run original program through `libkvikdos` to record expected output
- run candidates through `libkvikdos`
- compare declared observables only
- emit structured pass/fail/refusal records

### 3. VEX / Inertia IR / Z3 Generator

Input generation uses:

- original DOS bytes
- VEX lifting
- typed Inertia IR
- function SSA
- path constraints solved with Z3

Z3 generates concrete test inputs, not expected outputs.

Generated fields:

- `regs`
- `sregs`
- `flags`
- stack bytes
- memory regions required by the path
- path target metadata
- assumptions and refusals

Unsupported operations must produce structured refusals:

- indirect control flow without a bounded target set
- unmodeled DOS/BIOS/device side effects
- unknown memory aliasing
- dirty helper with no semantics
- unconstrained memory explosion

Sympy can help simplify algebraic constraints. KLEE is optional later for
compiled-C stress tests, but it should not be the primary IR oracle.

### 4. libdosbox Runtime Recorder

Use `/home/xor/inertia_player/libdosbox` as a real-data source.

Existing useful hooks:

- runtime JSON from `ShadowMemory::dump()`
- code execution counts
- segment observations per executed instruction
- data read/write size summaries
- access-site samples
- pointer evidence
- ABI summaries
- Ctrl+0 memory dumps from `DumpExe1`
- metadata with PSP, load segment, runtime `CS:IP`, and runtime `SS:SP`

Import flow:

```text
play/run target in libdosbox with collection enabled
  -> runtime JSON
  -> memory dump and metadata
  -> dosunit import-libdosbox
  -> real seed vectors
  -> optional VEX/Z3 expansion
```

For best unit-test value, extend libdosbox with optional per-call snapshots:

```text
function entry:
  CS:IP, SS:SP, regs, sregs, flags, stack window, selected memory

function exit:
  regs, sregs, flags, return kind, written memory ranges
```

These samples become replayable test vectors. Aggregated runtime JSON remains
useful for prioritization and memory-range selection.

Keep the libdosbox memory contract:

- `m2c::m` is the translated-program memory view.
- It must reflect live DOSBox guest memory.
- Do not replace it with a zero-filled compatibility buffer.

## Test Vector Schema

Use structured JSON. A binary encoding can be added later for speed.

```json
{
  "schema": "dosunit.vector.v1",
  "module": "egame.exe",
  "function": {
    "name": "sub_155AB",
    "entry": { "cs": "auto", "ip": "0x155ab", "kind": "near" }
  },
  "source": {
    "kind": "z3",
    "origin": "vex",
    "assumptions": []
  },
  "pre": {
    "regs": {
      "ax": "0x0000",
      "bx": "0x0000",
      "cx": "0x0000",
      "dx": "0x0000",
      "si": "0x0000",
      "di": "0x0000",
      "bp": "0x0000",
      "sp": "0xff00",
      "flags": "0x0202"
    },
    "sregs": {
      "cs": "auto",
      "ds": "auto",
      "es": "auto",
      "ss": "auto"
    },
    "memory": [
      { "space": "SS", "offset": "0xff00", "bytes": "0000" },
      { "space": "DS", "offset": "0x0200", "bytes": "00112233" }
    ]
  },
  "observe": {
    "regs": ["ax", "bx", "cx", "dx", "si", "di", "bp", "sp"],
    "sregs": ["ds", "es", "ss"],
    "flags_mask": "0x08d5",
    "memory": [
      { "space": "DS", "offset": "0x0200", "size": 4 }
    ],
    "calls": true,
    "return": true
  },
  "expected": null
}
```

`record-oracle` fills `expected` by executing the original x86 program.

Segmented memory stays explicit in the manifest. Concrete linear translation
`(segment << 4) + offset` happens only inside the execution backend.

## Result Schema

Use typed statuses, not string matching.

```json
{
  "schema": "dosunit.result.v1",
  "vector_id": "...",
  "status": "passed",
  "verdict": {
    "kind": "equivalent",
    "changed_fields": []
  },
  "oracle": {
    "regs": {},
    "sregs": {},
    "flags": "0x0202",
    "memory": [],
    "return": { "kind": "near" }
  },
  "candidate": {
    "regs": {},
    "sregs": {},
    "flags": "0x0202",
    "memory": [],
    "return": { "kind": "near" }
  }
}
```

Status enum:

- `passed`
- `failed`
- `refused`
- `timeout`
- `faulted`
- `unsupported`

Refusal reasons should be structured:

- `unsupported_ir`
- `unsupported_effect`
- `unbounded_memory`
- `unbounded_indirect_control`
- `backend_error`
- `oracle_unavailable`

## F-15 First Corpus

Primary reconstruction project:

- `/home/xor/tmp/f15se2-re`

Useful files:

- `/home/xor/tmp/f15se2-re/src/*.c`
- `/home/xor/tmp/f15se2-re/src/*.asm`
- `/home/xor/tmp/f15se2-re/map/*.map`
- `/home/xor/tmp/f15se2-re/map/*.tgt`
- `/home/xor/tmp/f15se2-re/build/*.exe`
- `/home/xor/tmp/f15se2-re/bin/*.exe`

IDA data:

- `/home/xor/games/f15se2-ida/egame.lst`
- `/home/xor/games/f15se2-ida/start.lst`
- `/home/xor/games/f15se2-ida/end.lst`
- `/home/xor/games/f15se2-ida/start.asm`
- `/home/xor/games/f15se2-ida/su.asm`
- `/home/xor/games/f15se2-ida/egame.cpp`
- `/home/xor/games/f15se2-ida/egame.h`
- `/home/xor/games/f15se2-ida/egame.seg`

libdosbox F-15 custom sources:

- `/home/xor/inertia_player/libdosbox/src/custom/src_f15`

Start with deterministic leaf functions:

- math helpers
- stack/local-only routines
- small memory transforms
- no DOS interrupts
- no graphics or I/O
- no unbounded far calls

Then expand to:

- memory-heavy functions
- call-heavy functions
- overlay functions
- DOS/BIOS/graphics functions with explicit side-effect models

## Discovery Adapters

`dosunit discover` should support adapters:

- MZ EXE headers and relocation metadata
- MAP files
- IDA LST files
- IDA ASM files
- Inertia function metadata
- manually supplied JSON

Discovery output:

```json
{
  "schema": "dosunit.functions.v1",
  "module": "egame.exe",
  "functions": [
    {
      "name": "sub_155AB",
      "entry": { "segment": "text", "offset": "0x155ab" },
      "kind": "near",
      "source": ["ida_lst", "map"],
      "confidence": "medium"
    }
  ]
}
```

## Candidate Types

The same vectors should run against:

- original unpacked EXE
- rebuilt reconstruction EXE
- decompiled C compiled to DOS
- reassembled IDA ASM
- hybrid EXE with selected object replacement

Each candidate needs a function-address mapping. Mapping can be exact,
symbol-based, or manifest-provided.

## Comparison Rules

Compare only declared observables:

- selected live-out registers
- selected segment registers
- selected flag bits
- selected memory ranges or memory writes
- return kind and target
- call targets and argument classes when requested

Do not compare:

- unobserved scratch registers
- unobserved stack bytes
- whole memory images by default
- nondeterministic timer, keyboard, filesystem, or device state unless modeled

## Implementation Phases

### Phase 0: Design Baseline

- Finalize schemas.
- Add sample manifests.
- Decide initial language boundaries.
- Identify minimal `kvikdos.c` split points.

### Phase 1: `libkvikdos` Smoke Backend

- Extract backend API.
- Keep existing CLI behavior.
- Load a simple COM/EXE.
- Snapshot and restore guest memory.
- Run a synthetic function trap.
- Dump full registers, flags, segment registers, and selected memory.

Acceptance:

- one process can run 100 repeated function vectors with snapshot restore
- existing `kvikdos` CLI tests still pass

### Phase 2: Minimal `dosunit`

- Read vector JSON.
- Execute original as oracle.
- Store expected output.
- Execute candidate.
- Compare declared observables.

Acceptance:

- compare two identical EXEs and pass
- mutate a candidate output and fail with a precise field diff

### Phase 3: F-15 Discovery

- Parse F-15 MAP and IDA LST enough to create function catalog entries.
- Join function entries across `/home/xor/tmp/f15se2-re` and
  `/home/xor/games/f15se2-ida`.
- Produce `functions.json`.

Acceptance:

- discover a useful subset of `start.exe`, `egame.exe`, and `end.exe`
- addresses agree across at least two sources where possible

### Phase 4: VEX/Z3 Input Generation

- Lift selected functions.
- Build typed IR and SSA.
- Generate path constraints.
- Solve concrete input states.
- Emit vectors with structured assumptions/refusals.

Acceptance:

- generate branch-covering vectors for small deterministic functions
- refuse unsupported functions honestly

### Phase 5: libdosbox Trace Import

- Import runtime JSON.
- Import memory dump metadata.
- Prioritize hot functions and observed memory regions.
- Convert real observed states into seed vectors where enough data exists.

Acceptance:

- import F-15 runtime JSON and dumps
- produce replayable vectors for at least one hot deterministic function

### Phase 6: Per-Call libdosbox Recorder

- Add optional entry/exit function snapshot collection.
- Record bounded stack and memory windows.
- Export `dosunit.vector.v1` seeds directly.

Acceptance:

- gameplay execution records real per-call vectors
- vectors replay under `libkvikdos`

### Phase 7: Candidate Expansion

- Compare original against reconstructed C EXE.
- Compare original against decompiled C EXE.
- Compare original against reassembled ASM EXE or object replacement.

Acceptance:

- deterministic pass/fail reports per function
- no silent success when unsupported effects are present

## Risks

- DOSBox and KVM CPU/device behavior may differ for some BIOS, timer, or I/O
  paths. Treat KVM as the deterministic unit-test backend and libdosbox as
  real-data sampling unless a function specifically requires DOSBox behavior.
- Packed/self-modifying code needs careful snapshot timing.
- Segment aliases must be preserved through manifests and IR.
- Runtime samples may be aggregated and insufficient for direct replay until
  per-call snapshots are added.
- Function address mapping across original, reconstructed, and decompiled
  candidates may need explicit manifests.

## Validation Policy

A function vector is accepted only when:

- the original executable runs the vector under `libkvikdos`
- expected output is recorded from original x86 execution
- candidate execution reaches a comparable outcome
- declared observables match
- unsupported behavior is represented as a structured refusal

For Inertia integration, this complements tail validation. It must not replace
semantic recovery with rewrite-stage patches or text-based matching.
