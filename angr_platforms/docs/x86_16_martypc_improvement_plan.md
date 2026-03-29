# MartyPC Comparison Improvement Plan

This document compares Inertia's current x86-16 implementation against the
instruction-core organization used by MartyPC and turns that comparison into a
practical improvement plan.

The goal is not to turn Inertia into MartyPC. MartyPC is an emulator, while
Inertia is an angr-based decompiler stack. The useful borrowing here is:

- instruction-family factoring
- width and address-size discipline
- explicit stack/control-transfer/string/interrupt helpers
- better low-level testability

The architecture boundary for Inertia does not change:

`IR -> Alias model -> Widening -> Traits -> Types -> Rewrite`

This plan is only about improving the instruction-core and lifter-facing layers
so they become a cleaner and more reliable foundation for decompilation.

## Practical Comparison

### What MartyPC does better at the instruction-core layer

MartyPC keeps CPU semantics split into small family modules, for example:

- `cpu_808x/alu.rs`
- `cpu_808x/addressing.rs`
- `cpu_808x/string.rs`
- `cpu_808x/stack.rs`
- `cpu_808x/interrupt.rs`
- `cpu_808x/decode.rs`
- `cpu_808x/execute.rs`

This gives MartyPC several practical strengths:

- ALU flag behavior is centralized by family instead of repeated in handlers
- string instructions keep direction-flag and REP behavior localized
- stack semantics are small and explicit
- interrupt entry is distinct from generic control flow
- addressing rules are centralized, including default-segment behavior
- decode and execute are separate enough to debug independently

### Where Inertia is currently stronger

Inertia already has things MartyPC does not try to provide:

- angr integration
- AIL/VEX lifting
- decompiler pipeline integration
- alias/widening recovery layers
- corpus scan, milestone reporting, and readability tracking
- DOS/BIOS interrupt lowering into C-like helper calls

### Main current gaps in Inertia

The low-level x86-16 side is still less coherent than MartyPC in several ways:

- instruction-family semantics are spread across:
  - `instr_base.py`
  - `instr16.py`
  - `exec.py`
  - `access.py`
- address-width and operand-width concerns are still mixed in a few places
- stack, far-pointer, and segment-address helpers are not yet a single obvious
  source of truth
- repeated flag, repeat-prefix, and string-side-effect logic still lives in
  multiple handlers
- decode, ModRM addressing, and execute helpers remain more tightly coupled
  than they need to be

One concrete example that has already started moving in the right direction:

- far-pointer reads now have a helper-backed path instead of open-coded typed
  arithmetic in `instr16.py`, but the same cleanup still needs to spread to the
  remaining address-family helpers
- `exec.py` resolved operands now track effective address width instead of
  hardcoding 16-bit address metadata

## Improvement Principles

### What to borrow from MartyPC

- family-based semantic factoring
- width-parametric helpers
- explicit stack/control-transfer/string/interrupt helpers
- explicit default-segment and effective-address logic
- smaller modules with one semantic responsibility

### What not to borrow blindly

- full emulator architecture such as BIU/queue/cycle modeling where it does
  not improve lifting or decompilation quality
- hardware realism that does not affect corpus correctness or recovery quality
- emulator-only abstractions that make the angr path harder to understand

## Already Landed Foundations

The plan below intentionally omits foundations that are already present in the
tree:

- `addressing_helpers.py`
  - width helpers
  - displacement helpers
  - `ResolvedMemoryOperand`
- `stack_helpers.py`
  - push/pop
  - far-return frame helpers
  - `enter/leave`
- `alu_helpers.py`
  - binary/unary/compare helper families
- `string_helpers.py`
  - direction-step and REP helper logic
- focused unit tests for those helper modules

What remains below is the work needed to make those pieces the main source of
truth instead of just helper islands.

Recent progress on that front:

- far-pointer reads are helper-backed in both 16-bit and indirect 32-bit far
  control-transfer paths
- `ResolvedMemoryOperand` is now used outside `exec.py` in selected
  instruction-side memory helpers
- `xlat` and adjacent 16-bit word-pair reads no longer need purely local
  address-step logic
- `movzx` / `movsx` byte-source handlers now use the shared `rm8` access path
  instead of open-coding memory reads
- string-family handlers now route their memory reads and writes through shared
  `string_load` / `string_store` helpers instead of open-coded memory plumbing
- 32-bit `cmps` handlers now also use the same shared string-load boundary
  instead of local `get_data*` reads
- `pusha` / `popa` now delegate to shared stack-family helpers instead of
  owning their own stack choreography inside `instr16.py`
- near `ret` / `ret imm16` now delegate to a shared near-return helper instead
  of owning their own stack-unwind and `Ijk_Ret` plumbing in `instr16.py`
- byte-side ALU immediate handlers in `instr_base.py` now share local family
  helpers for `AL imm8`, `r/m8 imm8`, compare, and carry-aware variants
- resolved-memory instruction-side users now share generic
  `load_resolved_operand` / `store_resolved_operand` helpers instead of
  open-coding width-specific memory access after address resolution
- 32-bit stack-family handlers now also delegate to shared helpers for
  `pushad` / `popad`, segment push/pop, and near return instead of owning
  their own stack choreography in `instr32.py`
- 16-bit segment push/pop, `pushf/popf`, and near call/jump emission now also
  route through shared stack/control-transfer helpers instead of open-coding
  stack choreography in `instr16.py`
- 32-bit near call/jump handlers now use the same helper-layer style instead of
  open-coding `push32` / `set_eip` pairs in `instr32.py`
-  far call / far jump handlers now also use a shared helper boundary with
  explicit return-IP handling instead of keeping their own local call-frame
  plumbing in `instr16.py` and `instr32.py`
- normalized decode metadata now has an explicit width-profile abstraction, so
  the `16/16`, `32/16`, and `16/32` matrix is a named boundary instead of
  scattered width math
- 32-bit relative branches now also share a single helper emission path instead
  of repeating `update_eip` logic in each conditional branch handler
- 8-bit, 16-bit, and 32-bit relative-branch families now all use shared
  `branch_rel*` helpers, and the old local `_rel8_target`, `_rel16_target`,
  and `_decrement_cx` helpers were removed after the branch/loop boundary was
  centralized
- 32-bit near relative call/jump target math now also goes through the shared
  `near_relative_target32` helper instead of open-coding `get_eip() + imm32`
  in `instr32.py`
- 8-bit and 16-bit relative branches now also use shared branch helpers instead
  of each conditional branch handler open-coding its own target math and jump
  emission

## Remaining Priorities

### P0. Make instruction-core semantics width-clean and family-clean

This is the highest ROI work. It improves scan stability, real-sample
correctness, and future 386 real-mode extensibility at the same time.

#### P0.1. Split address-width and operand-width explicitly

- `Priority`: `P0`
- `Why`:
  - future 386 real-mode support needs 32-bit operands with 16-bit addressing
  - current code still has mixed-width hazards in far-pointer and address math
- `Current files`:
  - `angr_platforms/X86_16/access.py`
  - `angr_platforms/X86_16/exec.py`
  - `angr_platforms/X86_16/parse.py`
  - `angr_platforms/X86_16/instr16.py`
- `Work`:
  - finish moving real instruction handlers onto the existing width helpers
  - stop open-coding width casts in instruction handlers when the operation is
    really about address formation
  - replace remaining ad hoc `Type.int_16` / `Type.int_32` mixes in address
    math with the reusable helper API
  - make far-pointer load helpers width-correct for:
    - 16-bit operand, 16-bit address
    - future 32-bit operand, 16-bit address
- `Immediate deliverables`:
  - audit `instr32.py` for the same width-discipline issue
  - move more address-family helpers onto `addressing_helpers.py`
  - keep widening the helper-backed tests from far-pointer loads into more
    mixed-width address cases
- `Exit signal`:
  - no instruction handler needs to guess whether an addition is an address add
    or an operand arithmetic add

#### P0.2. Move effective-address and default-segment logic behind one boundary

- `Priority`: `P0`
- `Why`:
  - MartyPC's `addressing.rs` is valuable mainly because addressing rules live
    in one place
  - Inertia currently spreads related logic across `exec.py`, `access.py`, and
    instruction handlers
- `Current files`:
  - `angr_platforms/X86_16/exec.py`
  - `angr_platforms/X86_16/access.py`
  - `angr_platforms/X86_16/instr16.py`
- `Work`:
  - finish centralizing:
    - ModRM16 effective-address calculation
    - default segment choice
    - segment override handling
    - far-pointer memory pair access
  - keep moving `get_rm*` / `set_rm*` consumers onto the addressing boundary
  - make stack-address special handling explicit through the same API instead
    of a separate surprise path
- `Immediate deliverables`:
  - extend `ResolvedMemoryOperand` usage beyond `exec.py` into more
    instruction-side memory helpers
  - keep indirect far control-transfer on the same segment-aware addressing
    boundary instead of raw memory reads
  - remove the remaining direct segment/address re-derivation from
    instruction-side helpers
- `Exit signal`:
  - one can trace any memory operand through a single addressing boundary

#### P0.3. Extract stack semantics into a focused helper layer

- `Priority`: `P0`
- `Why`:
  - MartyPC's `stack.rs` is small and explicit
  - Inertia already has `push16/pop16/callf/jmpf/retf` pieces, but they are
    scattered
- `Current files`:
  - `angr_platforms/X86_16/access.py`
  - `angr_platforms/X86_16/instr_base.py`
  - `angr_platforms/X86_16/instr16.py`
- `Work`:
  - finish moving stack/control-transfer handlers onto the focused helper layer
  - keep stack pointer update order and segment behavior explicit
  - remove duplicated stack behavior from per-opcode handlers
- `Immediate deliverables`:
  - move more return-address and far-frame formation out of opcode handlers
  - add family regression tests for near/far call/ret paths still open-coded
- `Exit signal`:
  - call/ret/iret/enter/leave no longer each own their own stack rules

#### P0.4. Extract string semantics into one family module

- `Priority`: `P0`
- `Why`:
  - string ops are a real corpus hot path
  - MartyPC's `string.rs` keeps direction-flag and REP behavior local
  - Inertia has already had real bugs in `cmps*`, `stos*`, and REP handling
- `Current files`:
  - `angr_platforms/X86_16/instr16.py`
  - `angr_platforms/X86_16/instr_base.py`
  - `angr_platforms/X86_16/instr32.py`
- `Work`:
  - finish moving shared string-op pieces into one helper layer:
    - source/destination segment selection
    - direction-flag step size
    - REP/REPZ/REPNZ loop gate
    - compare/update flags path
  - keep byte and word widths parametric
  - make ES-fixed vs DS-overrideable behavior explicit
- `Immediate deliverables`:
  - finish refactoring any remaining string handlers that still own repeat or
    direction logic locally
  - add one real-code regression per string family
- `Exit signal`:
  - string instructions become a small family wrapper over shared helpers

#### P0.5. Centralize ALU flag/update families

- `Priority`: `P0`
- `Why`:
  - MartyPC keeps ALU family behavior centralized in `alu.rs`
  - Inertia already routes many flag updates through `update_eflags_*`, which
    is the right direction, but opcode handlers still open-code too much shape
- `Current files`:
  - `angr_platforms/X86_16/instr_base.py`
  - `angr_platforms/X86_16/instr16.py`
  - `angr_platforms/X86_16/eflags.py`
  - `angr_platforms/X86_16/processor.py`
- `Work`:
  - keep formalizing ALU-family helpers around:
    - binary op
    - unary op
    - shift/rotate
    - compare/test
  - make width a parameter, not a branch explosion
  - reduce repeated handler bodies that differ only by:
    - operand accessor
    - width
    - carry source
- `Immediate deliverables`:
  - finish moving byte-side handlers in `instr_base.py` onto the helper layer
  - make shift/rotate family coverage symmetric across byte and word cases
- `Exit signal`:
  - new ALU-like instruction support is added by plugging accessors into a
    shared helper, not by duplicating handler logic

### P1. Clean decode/execute boundaries and make 386 extension bounded

#### P1.1. Make decode metadata richer and execution dumber

- `Priority`: `P1`
- `Why`:
  - MartyPC's decode/execute split is clearer than Inertia's current mixing of
    parsing, ModRM resolution, and execution helpers
- `Current files`:
  - `angr_platforms/X86_16/parse.py`
  - `angr_platforms/X86_16/exec.py`
  - `angr_platforms/X86_16/instruction.py`
- `Work`:
  - enrich decoded instruction metadata with:
    - effective operand width
    - effective address width
    - displacement width
    - repeat prefix class
    - far/near control-transfer class
  - keep execution helpers consuming decoded facts instead of re-deriving them
- `Immediate deliverables`:
  - add normalized width/address fields to `InstrData`
  - remove repeated width/address checks from execute helpers
- `Exit signal`:
  - execution mostly consumes decode results and semantic helpers

#### P1.2. Make 386 real-mode with 16-bit addressing an explicit extension path

- `Priority`: `P1`
- `Why`:
  - this is one of the user's stated future targets
  - without an explicit mixed-width plan, support will be bolted onto handlers
- `Current files`:
  - `angr_platforms/X86_16/instr16.py`
  - `angr_platforms/X86_16/instr32.py`
  - `angr_platforms/X86_16/parse.py`
  - `angr_platforms/X86_16/exec.py`
- `Work`:
  - define one mixed-width matrix:
    - 16-bit operand / 16-bit address
    - 32-bit operand / 16-bit address
    - 16-bit operand / 32-bit address where applicable
  - keep instruction semantics parameterized by width instead of copying opcode
    families
  - ensure address helpers remain separate from ALU helpers
- `Immediate deliverables`:
  - width matrix doc in code comments or dedicated helper module
  - first mixed-width tests for instructions that already nearly support it
- `Exit signal`:
  - future 386 real-mode work extends existing helpers instead of forking them

#### P1.3. Separate interrupt-core semantics from DOS/BIOS API lowering

- `Priority`: `P1`
- `Why`:
  - MartyPC keeps interrupt entry logic explicit
  - Inertia additionally lowers DOS/BIOS services into C-like helpers
  - these two concerns should stay separate
- `Current files`:
  - `angr_platforms/X86_16/instr_base.py`
  - `angr_platforms/X86_16/interrupt.py`
  - `angr_platforms/X86_16/simos_86_16.py`
  - `angr_platforms/X86_16/analysis_helpers.py`
  - `decompile.py`
- `Work`:
  - keep interrupt instruction semantics limited to:
    - stack/flags/control transfer
    - synthetic target selection
  - keep DOS/BIOS/MS-C lowering in analysis/rewrite helpers
  - do not let low-level interrupt handlers grow decompiler policy
- `Immediate deliverables`:
  - clearer interrupt-core helper module boundary
  - tests that separate:
    - interrupt control-transfer correctness
    - service-call rendering correctness
- `Exit signal`:
  - BIOS/DOS helper rendering can evolve without touching interrupt stack logic

### P2. Make the low-level core easier to verify and mine

#### P2.1. Add instruction-family validation slices

- `Priority`: `P2`
- `Why`:
  - MartyPC benefits from family-local debugging
  - Inertia already has compare-style tests, but not enough family grouping
- `Work`:
  - group focused tests by family:
    - ALU
    - string
    - stack/control transfer
    - addressing/far pointer
    - interrupts
  - keep each family using:
    - unit tests
    - compare-style tests where possible
    - one or two real corpus anchors
- `Exit signal`:
  - a regression in one family can be isolated quickly without broad sample
    sweeps

#### P2.2. Add targeted MartyPC-assisted differential triage

- `Priority`: `P2`
- `Why`:
  - MartyPC should be a secondary semantic reference for tricky instruction
    families
  - this is especially useful for:
    - string ops
    - stack/control transfer
    - interrupt entry
    - addressing edge cases
- `Work`:
  - for a bounded set of opcodes, add a triage harness or workflow note that
    compares:
    - Inertia behavior
    - MartyPC behavior
    - existing compare-style or hardware-backed reference where available
  - use it for debugging, not as the sole truth source
- `Exit signal`:
  - when a low-level edge case appears, there is a standard reference workflow
    instead of ad hoc reasoning

#### P2.3. Make scan-safe failure clustering point back to semantic families

- `Priority`: `P2`
- `Why`:
  - current corpus scan already ranks failures
  - the next win is to tie failures to family ownership:
    - string
    - stack
    - far control transfer
    - addressing
    - interrupt lowering
- `Work`:
  - tag corpus failures and ugly clusters with semantic-family ownership
  - make milestone reports say which family is still causing pain
- `Exit signal`:
  - low-level cleanup priorities come from corpus evidence, not intuition alone

### P3. Decompiler-facing cleanup after the instruction core is stable

#### P3.1. Push more projection cleanup onto explicit low-level facts

- `Priority`: `P3`
- `Why`:
  - once low-level width/address behavior is cleaner, alias/widening can trust
    lifted facts more often
- `Work`:
  - remove remaining late byte-pair cleanup that exists only because low-level
    semantics are noisy
  - rely more on:
    - alias facts
    - widening proofs
    - width-clean instruction output
- `Exit signal`:
  - decompiler cleanup becomes thinner because the lift is cleaner

#### P3.2. Use interrupt/API lowering only after the instruction-core path is clean

- `Priority`: `P3`
- `Why`:
  - DOS/BIOS/MS-C helper lowering should look natural C, but only after the
    low-level stack/register/interrupt facts are stable
- `Work`:
  - keep improving `int 21h`, `int 10h`, and wrapper-call recovery
  - ensure argument recovery uses stack/register facts from earlier layers
  - do not paper over low-level bugs with nicer helper rendering
- `Exit signal`:
  - helper-call lowering looks more natural because the low-level evidence is
    better, not because rewrite guessed harder

## Recommended Execution Order

### First wave

1. `P0.1` split address-width and operand-width explicitly
2. `P0.2` centralize effective-address and default-segment logic
3. `P0.3` extract stack/control-transfer helpers
4. `P0.4` extract string-family helpers
5. `P0.5` centralize ALU family helpers

### Second wave

6. `P1.1` richer decode metadata, dumber execute path
7. `P1.2` bounded 386 real-mode mixed-width extension path
8. `P1.3` separate interrupt-core semantics from API lowering

### Third wave

9. `P2.1` family validation slices
10. `P2.2` MartyPC-assisted differential triage
11. `P2.3` semantic-family ownership in corpus reports

### Final wave

12. `P3.1` push more projection cleanup onto explicit low-level facts
13. `P3.2` keep DOS/BIOS/MS-C helper lowering downstream of stable low-level
    evidence

## Highest ROI Improvements

If only a small amount of work can be funded now, do these first:

1. width/address split
2. addressing boundary cleanup
3. stack/control-transfer helper extraction
4. string-family extraction
5. ALU family helper centralization

These five items are the most likely to:

- reduce scan-time failures
- reduce mixed-width typing bugs
- make future 386 support bounded
- improve decompiler-quality indirectly by making the low-level core cleaner

## Success Criteria

Progress is good if:

- new low-level fixes land as family helpers instead of bigger opcode files
- mixed-width bugs stop appearing as random typed mismatches in handlers
- string/stack/far-control regressions become easier to isolate
- more decompiler wins come from cleaner lifted semantics and less from late
  rescue code
- 386 real-mode extensions can reuse existing helpers instead of forking the
  architecture

Progress is bad if:

- every new fix adds more branches to `instr_base.py` or `instr16.py`
- width/address handling remains implicit and handler-local
- interrupt/API lowering grows to hide low-level stack/register problems
- decompiler cleanup keeps compensating for noisy instruction semantics
