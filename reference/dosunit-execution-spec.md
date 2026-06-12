# DOS Unit Test Tool Execution Specification

## 1. Purpose

This document turns `reference/dosunit-plan.md` into an execution
specification.

The target is a general DOS function unit-test system that can:

- generate concrete function inputs from VEX / typed Inertia IR using Z3
- import real runtime seed data from libdosbox traces and memory dumps
- execute original DOS code in-process through a reusable KVM backend
- record original x86 output as the oracle
- compare reconstructed C, decompiled C, and reassembled ASM candidates
- report typed pass/fail/refusal results

F-15 Strike Eagle 2 is the first corpus, but the tool must remain generic for
DOS `.exe` and `.com` files.

## 2. Repository And Artifact Boundaries

### 2.1 Inertia Repository

Primary planning and integration repository:

```text
/home/xor/vextest
```

Expected new files and modules:

```text
reference/dosunit-plan.md
reference/dosunit-execution-spec.md
tools/dosunit/
tools/dosunit/dosunit.py
tools/dosunit/schemas/
tools/dosunit/adapters/
tools/dosunit/backends/
tools/dosunit/tests/
```

The exact Python package location may change during implementation, but the
tool must remain logically separate from decompiler rewrite/postprocess code.

### 2.2 KVM Backend Repository

Execution backend source:

```text
/home/xor/kvikdos/kvikdos.c
```

Required direction:

- extract reusable `libkvikdos` primitives
- keep the current `kvikdos` CLI as a wrapper
- do not put `dosunit`, VEX, Z3, manifest parsing, or function discovery into
  `kvikdos`

### 2.3 libdosbox Runtime Recorder

Runtime trace and memory dump source:

```text
/home/xor/inertia_player/libdosbox
```

Relevant existing mechanisms:

- runtime JSON from `ShadowMemory::dump()`
- memory dumps from `DumpExe1`
- code execution counts
- segment observations
- memory access summaries
- pointer evidence
- ABI summaries
- program load metadata

libdosbox remains a runtime recorder and optional real-data source. It is not
the deterministic unit-test backend.

### 2.4 F-15 First Corpus

Reconstruction project:

```text
/home/xor/tmp/f15se2-re
```

IDA project and exports:

```text
/home/xor/games/f15se2-ida
```

Important first-corpus files:

```text
/home/xor/tmp/f15se2-re/map/*.map
/home/xor/tmp/f15se2-re/map/*.tgt
/home/xor/tmp/f15se2-re/src/*.c
/home/xor/tmp/f15se2-re/src/*.asm
/home/xor/tmp/f15se2-re/build/*.exe
/home/xor/tmp/f15se2-re/bin/*.exe

/home/xor/games/f15se2-ida/egame.lst
/home/xor/games/f15se2-ida/start.lst
/home/xor/games/f15se2-ida/end.lst
/home/xor/games/f15se2-ida/start.asm
/home/xor/games/f15se2-ida/su.asm
/home/xor/games/f15se2-ida/egame.cpp
/home/xor/games/f15se2-ida/egame.h
/home/xor/games/f15se2-ida/egame.seg
```

## 3. Non-Negotiable Invariants

1. VEX/Z3 generates inputs, not the final oracle.
2. The original x86 program executed by `libkvikdos` produces expected outputs.
3. Candidate comparison is against recorded original execution.
4. Memory is represented as segmented memory in manifests and IR.
5. Linear address translation happens only at backend execution boundaries.
6. `dosunit` is generic and must not contain F-15-specific rules outside
   adapter fixtures or corpus manifests.
7. `kvikdos` remains an emulator/backend, not a unit-test orchestrator.
8. Statuses, verdicts, and refusals are typed fields, not parsed strings.
9. Unsupported cases must be refused, not silently treated as passing.
10. Runtime traces from libdosbox are seed evidence, not equivalence proof.
11. Existing Inertia semantic rules still apply: no text-based recovery, no
    rewrite-stage semantic repairs, and no guessed alias/type facts.
12. libdosbox `m2c::m` must continue to reflect live DOSBox guest memory.

## 4. End-To-End Dataflow

```text
function discovery
  -> functions catalog

original EXE bytes
  -> VEX / typed Inertia IR
  -> SSA
  -> Z3 constraints
  -> synthetic vectors

libdosbox gameplay/runtime
  -> runtime JSON + memory dumps
  -> imported real seed vectors

vectors
  -> original execution through libkvikdos
  -> oracle outputs

vectors + oracle outputs
  -> candidate execution through libkvikdos
  -> structured comparison results

original/candidate EXE bytes
  -> lifter-backed region summaries
  -> static operand/effect comparison
  -> typed argument/effect drift before runtime
```

## 5. Execution Modes

### 5.1 Oracle Recording

Command shape:

```bash
dosunit record-oracle \
  --exe original.exe \
  --vectors vectors.json \
  --out oracle.json
```

Behavior:

1. Load the original DOS program.
2. Save a clean baseline snapshot.
3. For each vector:
   - restore baseline
   - apply vector pre-state
   - install the requested trap strategy
   - run until trap, timeout, fault, or unsupported external effect
   - collect declared observables
   - write expected output into the oracle artifact

The oracle is invalid if original execution times out, faults unexpectedly, or
requires unsupported side effects.

### 5.2 Candidate Comparison

Command shape:

```bash
dosunit compare \
  --oracle-exe original.exe \
  --candidate-exe rebuilt.exe \
  --vectors vectors.with-oracle.json \
  --mapping candidate-functions.json \
  --out results.json
```

Behavior:

1. Load candidate program.
2. Save candidate baseline snapshot.
3. For each vector:
   - translate function entry through candidate mapping
   - restore candidate baseline
   - apply the same pre-state
   - execute candidate
   - collect declared observables
   - compare against oracle expected output

Comparison must be field-based. It must not compare rendered source text.

### 5.3 Trace Import

Command shape:

```bash
dosunit import-libdosbox \
  --trace EGAME.json \
  --dump EGAME.20260609-170348-233.1 \
  --meta EGAME.20260609-170348-233.1.meta.json \
  --functions functions.json \
  --out seed-vectors.json
```

Behavior:

1. Read libdosbox runtime JSON.
2. Read dump metadata if available.
3. Map runtime linear addresses back to module-relative function addresses.
4. Extract hot functions, observed segment values, access-site samples, and
   memory ranges.
5. Emit seed vectors when there is enough state for replay.
6. Emit prioritization hints when data is only aggregate.

Aggregated runtime data cannot by itself become an oracle. It can become:

- function priority
- memory observation range hints
- segment defaults
- pointer evidence hints
- ABI hypothesis hints
- vector seeds if enough concrete data exists

### 5.4 Vector Generation

Command shape:

```bash
dosunit gen-vectors \
  --exe original.exe \
  --functions functions.json \
  --strategy edge \
  --out vectors.json
```

Behavior:

1. Lift selected functions to VEX.
2. Import to typed Inertia IR.
3. Build function SSA.
4. Construct path constraints.
5. Ask Z3 for concrete inputs.
6. Emit vectors with assumptions and generation provenance.
7. Emit structured refusals for unsupported functions or paths.

Z3 output is incomplete until oracle recording succeeds.

## 6. Public `libkvikdos` API Requirement

The concrete API can be C or C-compatible C++, but it must be callable from the
`dosunit` runner without spawning a process per test vector.

### 6.1 Types

Required public state types:

```c
typedef struct DosVm DosVm;
typedef struct DosVmSnapshot DosVmSnapshot;

typedef enum DosVmStatus {
    DOSVM_STATUS_OK = 0,
    DOSVM_STATUS_TRAP,
    DOSVM_STATUS_TIMEOUT,
    DOSVM_STATUS_FAULT,
    DOSVM_STATUS_UNSUPPORTED,
    DOSVM_STATUS_BACKEND_ERROR
} DosVmStatus;

typedef enum DosTrapKind {
    DOS_TRAP_HLT = 1,
    DOS_TRAP_MISSING_MEMORY,
    DOS_TRAP_SENTINEL_IP,
    DOS_TRAP_INT3,
    DOS_TRAP_BACKEND_WATCH
} DosTrapKind;

typedef struct DosRegs16 {
    uint16_t ax;
    uint16_t bx;
    uint16_t cx;
    uint16_t dx;
    uint16_t si;
    uint16_t di;
    uint16_t bp;
    uint16_t sp;
    uint16_t ip;
    uint16_t flags;
} DosRegs16;

typedef struct DosSRegs16 {
    uint16_t cs;
    uint16_t ds;
    uint16_t es;
    uint16_t ss;
    uint16_t fs;
    uint16_t gs;
} DosSRegs16;

typedef struct DosMachineState16 {
    DosRegs16 regs;
    DosSRegs16 sregs;
} DosMachineState16;

typedef struct DosProgramInfo {
    uint16_t psp;
    uint16_t loadseg;
    uint16_t entry_cs;
    uint16_t entry_ip;
    uint16_t entry_ss;
    uint16_t entry_sp;
    uint32_t loaded_low_linear;
    uint32_t loaded_high_linear;
} DosProgramInfo;
```

### 6.2 Functions

Minimum required functions:

```c
DosVmStatus dosvm_create(DosVm **out_vm, const DosVmConfig *config);
void dosvm_destroy(DosVm *vm);

DosVmStatus dosvm_load_program(DosVm *vm,
                               const char *path,
                               const char *argv,
                               DosProgramInfo *out_info);

DosVmStatus dosvm_snapshot_create(DosVm *vm, DosVmSnapshot **out_snapshot);
DosVmStatus dosvm_snapshot_restore(DosVm *vm, const DosVmSnapshot *snapshot);
void dosvm_snapshot_destroy(DosVmSnapshot *snapshot);

DosVmStatus dosvm_get_state(DosVm *vm, DosMachineState16 *out_state);
DosVmStatus dosvm_set_state(DosVm *vm, const DosMachineState16 *state);

DosVmStatus dosvm_read_memory(DosVm *vm,
                              uint32_t linear,
                              void *out_bytes,
                              size_t size);

DosVmStatus dosvm_write_memory(DosVm *vm,
                               uint32_t linear,
                               const void *bytes,
                               size_t size);

DosVmStatus dosvm_install_trap(DosVm *vm, const DosTrapConfig *trap);

DosVmStatus dosvm_run(DosVm *vm,
                      const DosRunLimits *limits,
                      DosRunResult *out_result);
```

### 6.3 Snapshot Contents

A backend snapshot must include:

- guest memory range used by the VM
- CPU registers
- segment registers
- flags
- KVM state required for deterministic replay
- DOS service state in the backend if INT handling mutates host-side state
- mapped DOS file-handle state when enabled

Phase 1 can restrict function tests to code that does not depend on mutable
host file-system state. If that restriction is active, it must be explicit in
results.

### 6.4 Backend Determinism Requirements

The backend must support deterministic configuration for:

- time and date
- timer ticks
- keyboard state
- random uninitialized initial registers
- initial memory fill
- file-system mount paths
- DOS version responses
- unsupported device I/O behavior

Default `dosunit` mode should refuse nondeterministic device effects unless a
model is configured.

## 7. Function Invocation Specification

### 7.1 Entry Address Resolution

Function entries can be specified as:

- absolute runtime `CS:IP`
- module-relative segment:offset
- module-relative linear offset from load segment
- function name resolved through a function catalog
- candidate-mapped function name

Resolution is a typed step:

```text
manifest entry
  -> function catalog entry
  -> program load segment
  -> runtime CS:IP
```

Do not guess when more than one mapping is possible. Emit
`mapping_ambiguous`.

### 7.2 Segment Defaults

`auto` segment values are resolved from:

1. vector explicit values
2. oracle/candidate mapping metadata
3. program load metadata
4. function catalog defaults
5. libdosbox imported runtime samples

If no safe segment can be resolved, emit `segment_unresolved`.

### 7.3 Stack Setup

Before invocation:

1. Restore baseline snapshot.
2. Set `SS:SP` from vector pre-state.
3. Apply explicit stack memory bytes.
4. Push a trap return frame according to function kind.
5. Apply register and segment values.
6. Set `CS:IP` to function entry.

Stack memory in vectors must use `space: "SS"` unless an explicit segment is
required.

### 7.4 Trap Strategies

#### Near Return

Near-return functions pop only `IP`, leaving `CS` unchanged.

Allowed trap strategies:

- `same_cs_hlt_slot`: patch a manifest-provided unused offset in the same code
  segment with `HLT`, then push that offset as the return IP.
- `missing_memory_return`: push an IP that returns outside the mapped executable
  range and configure the backend to treat the resulting KVM exit as a trap.
- `backend_watch`: run with a backend return watch if available.

Preferred for Phase 1:

```text
same_cs_hlt_slot when safe slot is known
missing_memory_return for smoke tests
```

If no safe near-return trap is available, emit `trap_unavailable`.

#### Far Return

Far-return functions pop `IP` and `CS`.

Trap strategy:

- create a backend-owned trap paragraph containing `HLT`
- push trap `CS`
- push trap `IP`
- execute function
- expect `KVM_EXIT_HLT` at trap location

#### No Return / Tail Jump

For functions that tail-jump or do not return:

- observe final `CS:IP`
- enforce an instruction limit
- stop at configured control target or trap
- otherwise emit `control_unbounded`

#### Explicit HLT

If the function naturally executes HLT, distinguish:

- expected program HLT
- dosunit trap HLT

Use trap address validation.

### 7.5 Call Handling

Supported modes:

- `whole_program`: calls execute normally in the loaded program
- `leaf_only`: refuse if a call is reached
- `stubbed`: intercept configured callees and apply summaries
- `record_calls`: execute calls but record observed direct call targets

Phase 1 should implement `leaf_only` and `whole_program`.

Stubbed calls require typed summaries:

```json
{
  "target": "sub_1234",
  "pre": { "args": [] },
  "post": {
    "regs": { "ax": "symbolic_or_concrete" },
    "memory": [],
    "stack_cleanup": 0
  }
}
```

No name-based helper substitution is allowed as proof. Summaries must be
manifest-provided or recovered from validated evidence.

## 8. Memory Model Specification

### 8.1 Manifest Spaces

Allowed memory spaces:

- `CS`
- `DS`
- `ES`
- `SS`
- `FS`
- `GS`
- `SEG`
- `LINEAR`

`SEG` requires an explicit segment value:

```json
{ "space": "SEG", "segment": "0x2345", "offset": "0x0010", "bytes": "aa" }
```

`LINEAR` is allowed only for backend/debug fixtures and imported dumps. It
must not be used as a replacement for segmented IR memory.

### 8.2 Translation

Concrete backend translation:

```text
linear = (segment << 4) + offset
```

This translation is valid only after segment values have been resolved for the
current vector and current loaded program.

### 8.3 Memory Application

Before execution:

1. Validate every memory write range is in guest addressable memory.
2. Reject overlapping writes unless bytes are identical.
3. Apply memory patches after restoring baseline.
4. Record before-bytes for all observed memory ranges.

After execution:

1. Read declared observed ranges.
2. Compute byte diffs against before-bytes.
3. Compare only declared observed ranges unless `observe.memory_writes` was
   populated by a write-tracking backend.

### 8.4 Write Observation

There are two supported write-observation modes:

- `range_diff`: compare configured observed ranges
- `backend_write_log`: compare backend-collected write events

Phase 1 can use `range_diff`.

`backend_write_log` is optional and can be implemented with KVM page
protection, emulator instrumentation, or a future backend hook.

## 9. Vector Schema Requirements

### 9.1 Required Fields

Every vector must have:

- `schema`
- `id`
- `module`
- `function`
- `source`
- `pre`
- `observe`

`expected` is null before oracle recording and required for candidate
comparison.

### 9.2 Vector ID

Vector IDs are deterministic:

```text
sha256(canonical_json_without_expected)
```

Canonical JSON means:

- sorted keys
- lowercase hex strings
- no insignificant whitespace
- stable ordering of arrays unless declared unordered

### 9.3 Source Kinds

Allowed source kinds:

- `z3`
- `libdosbox`
- `manual`
- `hybrid`

Allowed origins:

- `vex`
- `typed_ir`
- `runtime_json`
- `memory_dump`
- `per_call_snapshot`
- `manual_fixture`

### 9.4 Expected Output Fields

Expected output must include:

- run status
- final registers requested by `observe.regs`
- final segment registers requested by `observe.sregs`
- masked flags
- memory observations
- return/control-flow outcome if requested
- call observations if requested

Example:

```json
{
  "status": "trapped",
  "regs": { "ax": "0x0001" },
  "sregs": { "ds": "0x2000" },
  "flags": { "value": "0x0203", "mask": "0x08d5" },
  "memory": [
    {
      "space": "DS",
      "offset": "0x0200",
      "before": "00112233",
      "after": "00119933",
      "diff": [{ "offset": 2, "before": "22", "after": "99" }]
    }
  ],
  "return": { "kind": "near", "trap": "same_cs_hlt_slot" },
  "calls": []
}
```

## 10. Result Schema Requirements

### 10.1 Top-Level Fields

```json
{
  "schema": "dosunit.result.v1",
  "run_id": "...",
  "vector_id": "...",
  "module": "...",
  "function": "...",
  "oracle_exe": "...",
  "candidate_exe": "...",
  "status": "passed",
  "verdict": {
    "kind": "equivalent",
    "changed_fields": []
  },
  "oracle": {},
  "candidate": {},
  "diagnostics": []
}
```

### 10.2 Status Enum

Allowed statuses:

- `passed`
- `failed`
- `refused`
- `timeout`
- `faulted`
- `unsupported`
- `backend_error`

### 10.3 Verdict Enum

Allowed verdict kinds:

- `equivalent`
- `observable_mismatch`
- `oracle_unavailable`
- `candidate_unavailable`
- `mapping_unavailable`
- `unsupported_effect`
- `nondeterministic`
- `backend_failure`

### 10.4 Refusal Reasons

Allowed refusal reason codes:

- `unsupported_ir`
- `unsupported_effect`
- `unbounded_memory`
- `unbounded_indirect_control`
- `segment_unresolved`
- `mapping_ambiguous`
- `mapping_missing`
- `trap_unavailable`
- `call_unmodeled`
- `device_io_unmodeled`
- `dos_interrupt_unmodeled`
- `timeout`
- `backend_error`
- `oracle_unavailable`

## 11. Discovery Specification

### 11.1 Inputs

Discovery adapters must support:

- MZ EXE headers
- COM binary entry
- map files
- IDA LST files
- IDA ASM files
- Inertia function metadata
- manual JSON manifests

### 11.2 Function Catalog Fields

Required output:

```json
{
  "schema": "dosunit.functions.v1",
  "module": "egame.exe",
  "program_kind": "mz_exe",
  "functions": [
    {
      "id": "egame.exe:sub_155AB",
      "names": ["sub_155AB"],
      "entry": {
        "kind": "module_relative",
        "segment": "text",
        "segment_para": "0x0000",
        "offset": "0x155ab"
      },
      "return_kind": "near",
      "sources": ["ida_lst", "map"],
      "confidence": "medium",
      "size": null,
      "safe_traps": []
    }
  ]
}
```

### 11.3 Confidence Rules

Confidence values:

- `high`: at least two independent sources agree, or source has strong symbol
  and relocation evidence
- `medium`: one structured source gives plausible address
- `low`: heuristic or partial source only
- `refused`: ambiguous or contradictory

Contradictions must be retained in diagnostics, not overwritten.

## 12. VEX / Z3 Generation Specification

### 12.1 Solver Model

Use bitvectors for:

- general registers
- segment registers
- flags
- temporaries
- stack offsets
- integer memory values

Use segmented memory arrays:

```text
mem_SS[offset] -> byte
mem_DS[offset] -> byte
mem_ES[offset] -> byte
```

Do not model all memory as one flat array unless the vector explicitly uses
`LINEAR` for backend-only debug fixtures.

### 12.2 Path Strategy

Initial strategies:

- `entry`: one satisfiable input reaching function entry
- `edge`: cover discovered branch edges up to a path bound; candidate
  discovery must use the x86-16 lifter through `project.factory.block(...).vex`
  before lowering a compact branch `ConditionIR`
- `hot`: bias toward libdosbox observed hot paths
- `manual_seed`: expand from imported runtime seed states

Bounds:

- max basic blocks per path
- max loop unroll count
- max memory symbolic bytes
- max solver time per path
- max vectors per function

All bounds must be written into vector generation metadata.

For `edge`, raw VEX must not be sent directly to Z3. The lifter-backed adapter
extracts only branch-relevant condition facts, then `solver_slice.py` solves
that compact condition with lazy flag materialization. If the lifter project
cannot be loaded, the byte decoder may run as a fallback, but fallback use must
be reported in counters and each emitted vector's `source.coverage`.

### 12.2.1 Region Operand/Effect Strategy

`regions` is the static gate for checking instruction arguments over parts of a
function. It summarizes straight-line lifter-backed regions, not isolated
single instructions.

Each region records:

- function id/name
- region entry/end
- instruction mnemonic and structured operands
- operand widths and access mode
- register reads/writes
- flag reads/writes
- segmented memory reads/writes
- control exits and successors

Memory operands must stay segmented:

```text
DS:[si + 0x0004]
SS:[bp - 0x0002]
ES:[di]
```

`compare-regions` compares these summaries between original and candidate
artifacts. It must report typed mismatches for register, memory
base/index/displacement/segment, width, flag, and instruction effect drift.
Direct branch/call immediates are compared as control-target operands, not as
raw relocated candidate addresses.

### 12.2.2 Function Complexity Gate

`complexity` is the static gate that decides whether a function is small enough
to attempt as one whole-function comparison/solver part.

The gate is lifter-backed. It must use `project.factory.block(...).vex` before
reading Capstone instruction summaries, so the result follows the same decode
path as region and edge analysis.

Each function records:

- instruction count and block count
- condition/branch/jump counts
- call, interrupt, and indirect-control counts
- explicit memory read/write counts
- symbolic memory counts for register-indexed memory operands
- segment-sensitive memory counts
- flag read/write counts
- partial-register, variable-shift, mul/div, string-instruction, loop, and
  backward-branch counts
- a weighted `risk.score`
- typed blockers when the function is not simple
- risk points with address and disassembly

The first conservative simple class is `simple_whole_function`. It requires:

- no conditions, jumps, calls, interrupts, loops, backward branches, string
  instructions, or indirect control
- a return instruction
- instruction count at or below `--max-simple-insns`
- explicit symbolic memory count at or below `--max-simple-symbolic-memory`
- risk score at or below `--simple-score-threshold`

When a function passes this gate, the output includes one comparison part:

```json
{
  "kind": "whole_function",
  "function": {"id": "...", "name": "..."},
  "entry": {"cs": "0x0000", "ip": "0x0200", "linear": "0x1200"},
  "end": {"cs": "0x0000", "ip": "0x0206", "linear": "0x1206"},
  "instruction_count": 3,
  "reason": "simple_whole_function"
}
```

This gate does not replace runtime oracle comparison. It selects the functions
where a future compact VEX/AIL SSA-to-Z3 whole-function pass is expected to be
cheap enough. Functions that fail the gate remain testable through entry/edge
vectors, region comparison, and runtime replay.

`report-failures` must render `dosunit.complexity.v1` documents with:

- summary counters
- complex function names and entries
- blocker names
- compact metrics
- risk-point instruction addresses and disassembly

### 12.2.3 Straight-Line SSA Strategy

`ssa` lowers bounded straight-line function slices into compact SSA. The first
frontend adapter is VEX-backed:

```text
x86 bytes -> existing x86-16 lifter -> VEX IRSB
          -> final requested PUT(reg) outputs
          -> backward slice through VEX tmp definitions
          -> compact SSA expressions
```

VEX temps are already single assignment. The dosunit layer must not decode x86
instruction semantics. It only serializes the reachable VEX expression graph.

The compact SSA artifact records:

- source IR (`vex`)
- lifted instruction list for visibility
- input registers used by the slice
- topologically ordered assignments
- requested output register expressions
- typed refusals

The first pass supports one bounded VEX IRSB. It does not follow successor
blocks, but it does lower VEX exits into a selected-block `ip` expression.
Register outputs and a symbolic byte-array memory output are supported. VEX
loads/stores become `loadle`/`storele` or big-endian equivalents over the shared
memory input. Unsupported VEX statements/helpers, partial-register accesses
that VEX does not normalize to whole-register expressions, and functions above
the instruction bound are refused rather than guessed. Unused flag computations
and unused return-IP memory loads are dropped by the backward slice.

Lifted VEX blocks are cached on disk by default by the `ssa` CLI. Cache layout:

```text
.cache/dosunit/vex/<exe-sha256>.pickle
```

The cache file stores all lifted block entries for that EXE hash, keyed inside
the file by linear address, size bound, and VEX opt level. AIL should use the
same shape later under `ail/<exe-sha256>.pickle`.

`compare-ssa` asks Z3:

```text
exists input_regs . oracle_output != candidate_output
```

Unsat means the selected SSA outputs are equivalent for that bounded slice. Sat
means the result must include a concrete counterexample model.

When a mapping document is provided, `compare-ssa` resolves oracle functions to
candidate functions through that mapping. Unmapped oracle functions are visible
refusals by default. `--skip-unmapped` suppresses those refusals for targeted
audits. AIL should later lower into the same `dosunit.ssa.v1` schema. The
compare layer must not care whether the source was VEX or AIL.

### 12.3 Constraint Outputs

Each generated vector must include:

- source path summary
- solver bounds
- constraints count
- concrete model values
- assumptions
- refusal details if partial

### 12.4 Unsupported IR

Unsupported IR must not disappear. It must result in:

```json
{
  "status": "refused",
  "reason": "unsupported_ir",
  "detail": {
    "op": "...",
    "block": "0x...",
    "path": "..."
  }
}
```

### 12.5 Generation Counters

Each generator run must report:

- `functions_seen`
- `functions_attempted`
- `branches_seen`
- `branches_attempted`
- `paths_attempted`
- `paths_solved`
- `vectors_emitted`
- `edge_sources`
- `edge_fallback_diagnostics`
- `lifter_blocks_lifted`
- `simple_whole_functions`
- `complex_functions`
- `comparison_parts_emitted`
- `functions_lowered`
- `assignments_emitted`
- `regions_emitted`
- `instructions_summarized`
- `refusals_by_reason`
- `solver_time_ms`

For Inertia semantic integration, any semantic materialization work must keep
the existing evidence loop:

- `raw_fact_count`
- `normalized_fact_count`
- `classified_fact_count`
- `materialized_count`
- `failure_count`

## 13. libdosbox Import Specification

### 13.1 Runtime JSON Fields

Importer must understand at least:

- `Meta.DosboxLoadSeg`
- `Meta.ImageSizeBytes`
- `Code`
- `Data`
- `AccessSites`
- `PointerEvidence`
- `Jumps`
- `Abi`

### 13.2 Dump Metadata Fields

Importer must understand:

- dump filename
- PSP
- load segment
- runtime `CS:IP`
- runtime `SS:SP`
- first exec
- last exec
- exec requests

### 13.3 Address Normalization

Runtime linear address to module-relative mapping:

```text
module_linear = runtime_linear - (loadseg << 4)
```

Only use this mapping when `loadseg` and image size are known.

### 13.4 Seed Vector Eligibility

Aggregated trace data can produce a replayable vector only when:

- entry `CS:IP` is known
- segment defaults are known or can be resolved
- required stack and memory inputs are available
- memory ranges are bounded
- nondeterministic device state is absent or modeled

Otherwise produce priority hints, not replay vectors.

### 13.5 Per-Call Snapshot Extension

Required future record format:

```json
{
  "schema": "dosunit.libdosbox_call_snapshot.v1",
  "module": "EGAME.EXE",
  "function": { "cs": "0x....", "ip": "0x...." },
  "entry": {
    "regs": {},
    "sregs": {},
    "flags": "0x....",
    "stack": { "ss": "0x....", "sp": "0x....", "bytes": "..." },
    "memory": []
  },
  "exit": {
    "regs": {},
    "sregs": {},
    "flags": "0x....",
    "memory_writes": [],
    "return": {}
  }
}
```

This format can become a `dosunit.vector.v1` source with `source.kind =
"libdosbox"`.

## 14. Candidate Mapping Specification

Candidates may have different layout from original. Each candidate needs a
mapping:

```json
{
  "schema": "dosunit.mapping.v1",
  "oracle_module": "egame.exe",
  "candidate_module": "egame.exe",
  "functions": [
    {
      "oracle_id": "egame.exe:sub_155AB",
      "candidate_id": "egame.exe:egmath_func",
      "candidate_entry": {
        "kind": "module_relative",
        "segment": "text",
        "offset": "0x1234"
      }
    }
  ]
}
```

Mapping sources:

- same address
- map symbol
- IDA name
- decompiler metadata
- manual manifest

If mapping is missing, emit `mapping_missing`.

## 15. CLI Specification

### 15.1 Common Flags

All commands support:

```bash
--out PATH
--log PATH
--format json
--strict
--limit-functions N
--function NAME_OR_ID
--timeout-insns N
--seed HEX
```

### 15.2 `discover`

```bash
dosunit discover \
  --exe PATH \
  [--map PATH] \
  [--ida-listing PATH] \
  [--ida-asm PATH] \
  [--inertia-functions PATH] \
  --out functions.json
```

### 15.3 `gen-vectors`

```bash
dosunit gen-vectors \
  --exe PATH \
  --functions functions.json \
  --strategy edge \
  --max-vectors-per-function 8 \
  --solver-timeout-ms 1000 \
  --out vectors.json
```

### 15.4 `import-libdosbox`

```bash
dosunit import-libdosbox \
  --trace TRACE.json \
  [--dump DUMP.1] \
  [--meta DUMP.1.meta.json] \
  --functions functions.json \
  --out seed-vectors.json
```

### 15.5 `regions`

```bash
dosunit regions \
  --exe PATH \
  --functions functions.json \
  --max-regions-per-function 8 \
  --max-insns-per-region 32 \
  --out regions.json
```

### 15.6 `complexity`

```bash
dosunit complexity \
  --exe PATH \
  --functions functions.json \
  --max-blocks-per-function 32 \
  --max-insns-per-function 128 \
  --max-simple-insns 16 \
  --simple-score-threshold 8 \
  --max-simple-symbolic-memory 0 \
  --out complexity.json
```

### 15.7 `ssa`

```bash
dosunit ssa \
  --exe PATH \
  --functions functions.json \
  --output-reg ax \
  --output-reg bx \
  --max-insns-per-function 24 \
  --cache-dir .cache/dosunit \
  --out ssa.json
```

### 15.8 `compare-ssa`

```bash
dosunit compare-ssa \
  --oracle-ssa original.ssa.json \
  --candidate-ssa rebuilt.ssa.json \
  --mapping mapping.json \
  --solver-timeout-ms 60000 \
  --out ssa-results.json
```

### 15.9 `compare-regions`

```bash
dosunit compare-regions \
  --oracle-regions original.regions.json \
  --candidate-regions rebuilt.regions.json \
  --out region-results.json
```

### 15.10 `report-failures`

```bash
dosunit report-failures \
  --results region-results.json \
  --limit 50 \
  --mismatch-limit 8 \
  --out failures.md
```

The report must make failed/refused items visible without requiring direct JSON
inspection. It should include the function/region or vector id, mismatch kind,
and compact oracle/candidate values for changed operands/effects.
For complexity documents it should include blocker names and risk-point
instructions. For SSA compare documents it should include changed output
registers and any Z3 counterexample model.

### 15.11 `record-oracle`

```bash
dosunit record-oracle \
  --exe ORIGINAL.EXE \
  --vectors vectors.json \
  --out vectors.with-oracle.json
```

### 15.12 `compare`

```bash
dosunit compare \
  --candidate CANDIDATE.EXE \
  --vectors vectors.with-oracle.json \
  [--mapping mapping.json] \
  --out results.json
```

### 15.13 `summarize`

```bash
dosunit summarize \
  --results results.json \
  --out summary.txt
```

Summary must include:

- total vectors
- passed
- failed
- refused
- timeout
- faulted
- top changed fields
- top refusal reasons

## 16. Initial Implementation Phases

### Phase 0: Specification And Fixtures

Deliverables:

- this execution spec
- JSON schemas under `tools/dosunit/schemas`
- one manually written COM smoke vector
- one manually written EXE smoke vector
- sample result fixture

Definition of Done:

- schemas validate sample fixtures
- fixtures are deterministic
- no implementation is claiming semantic coverage yet

### Phase 1: `libkvikdos` Backend Extraction

Deliverables:

- `libkvikdos` build target
- `kvikdos` CLI still builds
- public backend header
- snapshot/restore API
- state get/set API
- memory read/write API
- run-until-trap API
- smoke tests

Definition of Done:

- existing `/home/xor/kvikdos` CLI tests pass
- a single process runs at least 100 repeated function invocations with
  snapshot restore
- full `AX/BX/CX/DX/SI/DI/BP/SP/IP/FLAGS` and `CS/DS/ES/SS/FS/GS` are captured
- baseline restore produces byte-identical observed memory before each vector
- timeout is deterministic and reported as `timeout`
- unexpected KVM exits are reported as `backend_error` or `faulted`

### Phase 2: Minimal `dosunit` Runner

Deliverables:

- `dosunit record-oracle`
- `dosunit compare`
- vector parser
- result writer
- field diff reporter

Definition of Done:

- identical original/candidate executable passes
- intentionally patched candidate fails with precise field diff
- unsupported trap strategy reports `refused/trap_unavailable`
- no process is spawned per vector
- result JSON validates against schema

### Phase 3: Function Discovery

Deliverables:

- MZ EXE parser
- MAP parser
- IDA LST parser
- manual JSON function catalog support
- F-15 discovery fixture

Definition of Done:

- discover functions from `/home/xor/tmp/f15se2-re/map/*.map`
- discover functions from `/home/xor/games/f15se2-ida/*.lst`
- join at least one function set for `start.exe`, `egame.exe`, and `end.exe`
- ambiguous mappings are retained as diagnostics
- function catalog validates against schema

### Phase 4: VEX/Z3 Vector Generator

Deliverables:

- VEX lifting adapter
- typed IR import bridge
- SSA path collector
- Z3 bitvector model
- vector emitter
- refusal emitter

Definition of Done:

- generates at least two branch-distinguishing vectors for a small test
  function
- emits segmented memory in vectors, not flattened memory
- refuses unsupported dirty helpers
- refuses unbounded indirect control flow
- reports generation counters
- solver output is deterministic with fixed seed and bounds

### Phase 5: libdosbox Trace Import

Deliverables:

- runtime JSON importer
- dump metadata importer
- load-segment normalizer
- access-site to observe-range mapper
- priority hint output
- seed vector output where concrete state exists

Definition of Done:

- imports `/home/xor/inertia_player/libdosbox/tmp_rt.json`
- imports a real F-15 runtime JSON if available
- maps runtime linear addresses to module-relative addresses when load segment
  is known
- refuses replay vector creation when concrete state is insufficient
- emits useful function prioritization for hot code

### Phase 6: libdosbox Per-Call Snapshot Recorder

Deliverables:

- optional libdosbox call-entry snapshot hook
- optional libdosbox call-exit snapshot hook
- bounded stack window capture
- bounded memory read/write capture
- direct `dosunit.vector.v1` export or import path

Definition of Done:

- gameplay can record at least one real function call vector
- vector replays under `libkvikdos`
- `m2c::m` still reflects live guest memory
- recorder can be disabled with zero behavior change to normal DOSBox use
- snapshot size is bounded by configuration

### Phase 7: F-15 Candidate Comparison

Deliverables:

- F-15 function catalog
- oracle vector set for selected deterministic functions
- mapping for reconstructed candidate EXEs
- comparison report

Definition of Done:

- compare original `start.exe` against rebuilt `start.exe` for at least one
  deterministic function
- compare original `egame.exe` against rebuilt `egame.exe` for at least one
  deterministic function
- compare original `end.exe` against rebuilt `end.exe` for at least one
  deterministic function
- failures identify exact observable fields
- existing F-15 `make verify` remains independent and can still be run

## 17. Overall Definition Of Done

The project is done for the first usable milestone when all of the following
are true:

1. `dosunit` can discover functions from structured inputs.
2. `dosunit` can run vectors against an original DOS executable through
   `libkvikdos` without spawning a process per vector.
3. Original x86 execution records oracle output.
4. Candidate execution compares against oracle output.
5. Result JSON uses typed statuses and typed refusal reasons.
6. Segmented memory is preserved in vectors and only translated at backend
   execution boundaries.
7. VEX/Z3 generates at least one nontrivial synthetic vector set.
8. libdosbox trace import produces at least prioritization hints and at least
   one replayable seed vector when a per-call snapshot is available.
9. F-15 first-corpus smoke comparison runs on at least one function from each
   of `start.exe`, `egame.exe`, and `end.exe`.
10. Identical executable comparison passes.
11. Deliberately mutated candidate comparison fails with precise diffs.
12. Unsupported behavior is refused, not passed.
13. Documentation explains command usage, schemas, and limitations.
14. Automated tests cover schema validation, snapshot restore, oracle
    recording, candidate comparison, and at least one refusal path.

## 18. Not Done If

The project is not done if any of these are true:

- expected output comes only from Z3 or VEX instead of original x86 execution
- vectors flatten segment spaces into one untyped linear memory model
- `kvikdos` contains `dosunit` orchestration logic
- comparison depends on rendered C or ASM text
- unsupported calls, I/O, dirty helpers, or indirect jumps silently pass
- one process is started per function vector in the normal runner
- result statuses are inferred by string parsing
- libdosbox `m2c::m` is replaced by independent shadow memory
- a function is marked passing without declared observable comparison
- tests are flaky due to timer, keyboard, filesystem, or device state

## 19. First Engineering Checklist

1. Add schema files and sample fixtures under `tools/dosunit/schemas`.
2. Split `/home/xor/kvikdos/kvikdos.c` into backend and CLI without changing
   current CLI behavior.
3. Add backend smoke test for snapshot restore.
4. Add `dosunit record-oracle` for one manual vector.
5. Add `dosunit compare` for identical executable pass and mutated executable
   fail.
6. Add MAP/LST discovery for F-15.
7. Add VEX/Z3 generator for a small leaf function.
8. Add libdosbox runtime JSON importer.
9. Add per-call snapshot recorder only after the import path is stable.

## 20. Open Decisions

These must be resolved during implementation:

- final language for `dosunit` runner: Python first is preferred for schema and
  adapter speed; C/C++ can remain backend-only
- exact `libkvikdos` public header name and build system
- first near-return trap strategy for MZ EXE code segments
- whether KVM backend will support write logs in Phase 1 or only range diffs
- first canonical F-15 original executable set for oracle recording
- how candidate mapping is maintained for decompiled C builds

Open decisions must be captured in follow-up ADRs or updates to this spec.
