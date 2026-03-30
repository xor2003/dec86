# x86-16 Snake Recompilation Plan

## Goal

Make `examples/snake.EXE` decompile into C that preserves the logic of the
checked-in `examples/snake.asm` / `examples/snake.lst` closely enough for a
recompilable subset, instead of merely producing non-empty or vaguely readable
output.

This plan is intentionally anchored to the current repository source snapshot.
If an external or older snake source differs from the checked-in `snake.asm`,
we do not treat that delta as a decompiler regression until it is reflected in
the checked-in source or listing.

## Root Causes Confirmed From Current Source

1. Register-passed helper functions lose their ABI.
   Current source confirms register-only helper surfaces:
   - `setcursorpos`: input in `DX` as packed `DH:DL`
   - `writecharat`: input in `DX` and `BL`
   - `readcharat`: input in `DX`, output in `BL`
   - `writestringat`: input in `DX` and `BX`
   - `readchar`: output in `DL`
   - `dispdigit`: input in `DL`
   - `dispnum`: input in `AX`

2. Mixed byte/word memory semantics are still too lossy.
   The snake source mixes byte globals with word-sized packed coordinates and
   word loads/stores through the same objects.

3. Segment-aware object recovery is incomplete.
   The binary relies on:
   - `DS` data globals
   - `ES = 0xB800` text video memory
   - `SS` stack

4. Interrupt lowering is still too register-opaque for recompilation.
   BIOS and DOS interrupts are partially recognized but do not yet expose the
   exact argument and result flow needed for source-like C.

5. Flag cleanup and control-flow structuring still leak CPU-level artifacts.
   This hurts loop and branch recovery in `delay`, `fruitgeneration`,
   `keyboardfunctions`, and `shiftsnake`.

## What Is Already True In The Current Source Snapshot

The checked-in `main` in `examples/snake.asm` is currently small. It:
- initializes `DS`
- sets `ES = 0xB800`
- sets video mode 3
- prints via `int 21h`
- waits for a key
- sets video mode 3 again
- exits via `int 21h 4C00h`

So the correctness target for `main` is the currently checked-in source, not a
larger hypothetical main loop from another variant of snake.

## Recovery Strategy

Do not try to “pretty-print” this into recompilable C only at the end.
The project rules require `IR -> Alias model -> Widening -> Traits -> Types ->
Rewrite`, and they explicitly forbid solving aliasing, widening, storage
identity, or prototype inference in late rewrite.

The snake work should therefore be split into:

- **recovery correctness**: ABI, alias, widening, segment, and condition
  recovery
- **text cleanup**: the last-stage naming and formatting polish

The existing `_decompile_function()` staging is already the right broad shape.
The change is to move snake-critical semantics earlier and keep `_fix_snake_*`
style text rewrites as temporary rescue, not the main fix path.

## Deterministic Steps

### S1. Register-helper ABI recovery

Deterministic goal:
- `setcursorpos`, `writecharat`, `readcharat`, `writestringat`, `readchar`,
  `dispdigit`, and `dispnum` decompile with explicit non-stack signatures that
  match the checked-in register conventions closely enough for recompilation.
- the callee and callsite surfaces agree on those signatures before final text
  cleanup runs
- `readchar` returns a byte-like DL result rather than a synthetic wide value
- `writecharat` and `writestringat` do not keep an address-like return type

Completion signals:
- `setcursorpos` is not rendered as `short setcursorpos(void)`
- `writecharat` is not rendered as `long writecharat(void)`
- `readcharat` is not rendered as `long readcharat(void)`
- `writestringat` is not rendered as `unsigned short writestringat(void)`
- callers no longer emit bare `writecharat();` / `readcharat();` /
  `writestringat();`
- `draw` and `fruitgeneration` show explicit helper arguments instead of empty
  calls

Validation:
- `tests/test_x86_16_snake_annotations.py`
- `tests/test_x86_16_cli.py` snake helper cases

Status:
- In progress

### S2. DS global recovery with names and widths

Deterministic goal:
- snake data offsets stop rendering as raw `*((char *)245)`-style DS artifacts
  for the known snake data objects.
- Named globals are recovered for at least:
  - `fruitactive`
  - `fruitx`
  - `fruity`
  - `segmentcount`
  - `head`
  - `body`
  - string literals and messages named in the listing

Completion signals:
- focused snake functions stop introducing raw DS byte offsets for these known
  objects
- byte globals stop being rendered as pointer-like artifacts
- `draw`, `fruitgeneration`, and `shiftsnake` show named globals rather than
  magic offsets for the covered data objects

Validation:
- `tests/test_x86_16_cli.py` snake draw / fruitgeneration / shiftsnake cases

Status:
- Not started

### S3. ES:B800 video memory lowering

Deterministic goal:
- video-memory helpers stop returning synthetic address arithmetic and instead
  expose side-effect-only or byte-return semantics with a stable video-memory
  abstraction boundary.
- ES:B800 accesses remain distinct from DS globals and do not collapse into
  flat process pointers

Completion signals:
- `writecharat` returns `void`
- `readcharat` returns a byte-like value, not a synthetic long or packed
  address expression
- `writestringat` returns `void`
- helper bodies do not use fabricated pointer-return semantics
- the callsites pass the expected row/col and string arguments explicitly

Validation:
- `tests/test_x86_16_cli.py` helper-specific snake cases

Status:
- Partially landed

### S4. Interrupt argument/result lowering for snake

Deterministic goal:
- the snake interrupt sites use helper calls that preserve required register
  semantics instead of null-argument or null-pointer placeholder calls.
- DOS and BIOS calls are lowered only after register arguments and results are
  recovered from the source semantics

Completion signals:
- DOS print does not lower to `print_dos_string((const char *)0x0)` when a
  concrete listing-backed string offset is available
- BIOS video and timer calls preserve the service semantics used in snake

Validation:
- `tests/test_x86_16_cli.py`
- focused snake `main`, `delay`, and `fruitgeneration`

Status:
- Not started

### S5. Flag-to-condition cleanup on snake control paths

Deterministic goal:
- snake branch conditions recover as comparisons against bytes, chars, counters,
  or packed coordinates rather than opaque flag-bit arithmetic wherever the
  checked-in source shows a simple compare/jcc pattern.
- this cleanup happens before late text rewrite so the source-level logic drives
  the emitted C shape

Completion signals:
- `delay` stops leaking raw flag-bit tests for the `sub dx, bx` / `jl` loop
- `fruitgeneration` and `shiftsnake` reduce obvious `cmp` / `jz` / `jnz`
  patterns to source-like comparisons

Validation:
- `tests/test_x86_16_cli.py`
- `tests/test_x86_16_compare_semantics.py` where applicable

Status:
- Not started

### S6. Structuring and loop recovery on snake

Deterministic goal:
- snake functions that are reducible loops in the checked-in source decompile as
  coherent loops without `if (...)`, invalid labels, or fake return/goto tails.
- loop reconstruction should rely on the structured decompiler passes, not a
  last-ditch text patch

Completion signals:
- `printbox` is not reduced to a broken `goto` tail
- `keyboardfunctions` is not cut off with placeholder conditions
- `shiftsnake` no longer depends on blind-spot patches to remain readable

Validation:
- `tests/test_x86_16_cli.py`
- focused Phoenix/non-Phoenix checks where needed

Status:
- Not started

### S7. Snake recompilation-oracle validation

Deterministic goal:
- a focused subset of snake functions is validated against the checked-in source
  as a recompilation-oriented oracle instead of merely “non-empty output”.
- this oracle should check recompilation-preserving shape, not just readability

Completion signals:
- the oracle subset checks:
  - helper signatures
  - helper return behavior
  - named globals in `draw` / `fruitgeneration`
  - absence of raw DS blind spots for the covered functions

Validation:
- new snake-focused CLI and/or oracle tests

Status:
- Not started

## Phase 0. Lock The Regression Target

### 0.1 Recovery test

Deterministic goal:
- verify recovered functions include the helper and control-flow surface named in
  the checked-in snake source.

Completion signal:
- the regression test fails if any expected helper/control function is missing.

### 0.2 Semantic text anchors

Deterministic goal:
- decompiled text contains the expected helper/global anchors and does not
  contain raw DS pointer artifacts.

Completion signal:
- the regression test fails on anchors like `*((char *)245)` and passes only if
  named snake globals are visible.

### 0.3 Recompilable-shape checks

Deterministic goal:
- helper calls are not zero-arg placeholders in caller output.

Completion signal:
- the regression test fails if `writestringat();`, `writecharat();`, or
  `readcharat();` appear as empty calls.

## Phase 1. Recovery Correctness Vs Text Cleanup

Implement snake-critical semantics in annotations, alias, widening, and
prototype recovery first.

Leave text cleanup rewrites as the last step and keep them narrow.

## Phase 2. Implementation Order

1. Register-helper ABI recovery.
2. DS globals and widths.
3. ES:B800 video memory lowering.
4. Interrupt argument/result lowering.
5. Flag-to-condition cleanup.
6. Structuring and loop recovery.
7. Recompilation-oracle validation.

## Current Progress Snapshot

- `S1`: partially landed
- `S2`: partially landed
- `S3`: partially landed
- `S4`: partially landed
- `S5`: open
- `S6`: open
- `S7`: open

Measured by step count:
- complete: `0/7`
- partially landed: `4/7`
- progress including partials at half credit: `28.57%`

Current code-backed landing so far:
- `snake_annotations.py` adds explicit helper ABI metadata.
- `annotations.py` accepts a custom calling convention override.
- `decompile.py` applies snake-specific annotations before decompilation.
- `snake_annotations.py` now carries snake-global names and typed byte globals
  into decompilation-time annotations.
- `decompile.py` applies a narrow snake DS-global cleanup pass for the known
  snake data labels.
- `decompile.py` applies a narrow snake `main` interrupt cleanup pass so the
  checked-in `instructions` label is used instead of a null placeholder.
- `tests/test_x86_16_snake_annotations.py` covers the helper ABI registry.
- `tests/test_x86_16_snake_annotations.py` covers typed snake data globals.
- `tests/test_x86_16_cli.py` now checks the improved snake helper call surface.
- `tests/test_x86_16_cli.py` now checks the cleaned snake `main` interrupt
  surface.

## Immediate Working Order

1. Finish `S1` by making register-helper signatures stable in both helper bodies
   and caller sites.
2. Finish `S2` by moving the remaining DS object identity out of cleanup and
   into alias / widening / type recovery.
3. Finish `S3` by removing the synthetic address-return artifacts from the
   video-memory helpers.
4. Finish `S4` by lowering the remaining interrupt call semantics in `main`,
   `delay`, and `fruitgeneration`.
5. Then spend effort on `S5` + `S6`.

## Text Cleanup Policy

Only after recovery correctness is stable should we keep or add snake-specific
text cleanup. Any `_fix_snake_*` rewrite should be treated as a temporary rescue
or regression oracle, not the primary implementation.

## COD Recompilation Workstream

The same architecture rules apply to `.COD` files, but the fix plan must be
more systematic than for `snake`. The repeating failures across the MSC corpus
are:

- helper calls collapsing into raw stack temps and magic addresses
- return values getting dropped
- globals like `rin`, `rout`, `sreg`, and `_exeLoadParams` not being recovered
  as typed objects
- far pointers and segment-based memory getting flattened or half-flattened
- medium-model far-call recovery still timing out or mis-targeting some
  functions
- larger COD functions hitting timeout, sparse-region, and under-recovery
  problems

### COD Success Criteria

Tier A correctness:
- parameters must match stack layout from the `.COD` listing
- return values must come from the real return register or memory object
- calls must use the right callee and argument order
- control flow must preserve branches, loops, and returns
- loads/stores must preserve byte vs word width
- `DS`, `SS`, `ES`, and far pointers must stay distinct

Tier B recompilation:
- helper-based C should be possible with typed objects such as
  `union REGS rin, rout`, `struct SREGS sreg`, and `struct ExeLoadParams`
- unresolved artifacts like `s_2 = &v3;`, `return v12 << 16 | 3823();`,
  `rin = 72;`, or split-byte far word stores are not acceptable

Tier C fixed first-milestone targets:
- `BIOSFUNC.COD::_bios_clearkeyflags` becomes a far word store
- `DOSFUNC.COD::_dos_getfree`, `_dos_free`, `_dos_resize`, `_dos_getReturnCode`
  emit typed `intdos`/`intdosx` calls and real returns
- wrappers like `_dos_loadOverlay`, `_dos_runProgram`, and `_openFileWrapper`
  emit direct helper calls with correct args and return propagation
- timeout rate on the fixed target set decreases measurably

### COD Fixed Regression Set

Use this starter set:
- `BIOSFUNC.COD`
- `DOSFUNC.COD`
- `OVERLAY.COD`
- `EGAME2.COD::_openFileWrapper`
- one timeout-heavy larger function from the wider COD corpus

### COD Deterministic Implementation Order

#### C1. COD regression harness

Deterministic goal:
- add focused regression tests for `_bios_clearkeyflags`, `_dos_getfree`,
  `_dos_loadOverlay`, `_openFileWrapper`, and `_dos_getReturnCode`
- lock both semantic anchors and anti-anchors before deeper recovery changes

Completion signals:
- the harness checks for:
  - `intdos(&rin, &rout)`
  - `loadprog`
  - real wrapper arguments
  - far word-store intent
- the harness fails on:
  - `rin = 72;`
  - `rin = 65535;`
  - `s_2 = &`
  - `3794()`
  - `3823()`
  - split-byte anonymous low-memory stores

Validation:
- `tests/test_x86_16_cod_regressions.py`

Status:
- In progress

#### C2. Metadata-driven function seeding

Deterministic goal:
- COD metadata becomes first-class recovery input:
  - function starts
  - near/far flags
  - stack arg names and sizes
  - known locals and callees
  - model hints where available

Completion signals:
- wrappers and medium-model targets are seeded directly from metadata instead
  of relying on heuristic rediscovery
- bogus tiny far-call targets decrease on the fixed target set

Validation:
- fixed COD regression set
- bounded COD scanner

Status:
- Not started

#### C3. MSC extern signature catalog and callsite typing

Deterministic goal:
- known MSC/DOS externs such as `_intdos`, `_intdosx`, `_fprintf`, `_fflush`,
  `_abort`, `_ERROR`, `_INFO`, `_DEBUG`, `_sprintf`, `_strlen`, and `_strcat`
  receive exact signatures before decompilation

Completion signals:
- helper calls render with correct argument lists
- wrapper returns propagate through the real callee instead of numeric
  pseudo-calls

Validation:
- `_dos_getfree`
- `_dos_loadOverlay`
- `_dos_getReturnCode`
- `_openFileWrapper`

Status:
- Not started

#### C4. Known COD object recovery

Deterministic goal:
- known globals recover as typed objects:
  - `rin`
  - `rout`
  - `sreg`
  - `exeLoadParams`
  - `ovlLoadParams`

Completion signals:
- field stores look like:
  - `rin.h.ah = ...`
  - `rin.x.bx = ...`
  - `sreg.es = ...`
  - `rout.x.cflag`
- whole-object scalar spam like `rin = 72;` disappears on the fixed target set

Validation:
- `_dos_getfree`
- `_dos_getReturnCode`
- `OVERLAY.COD`

Status:
- Not started

#### C5. Far-pointer and segmented COD recovery

Deterministic goal:
- far pointers and absolute low-memory objects stay segmented and width-correct
  instead of flattening into anonymous byte arithmetic

Completion signals:
- `_bios_clearkeyflags` lowers to a far word store or named BDA object
- far locals with `(segment, offset)` identity recover as one object

Validation:
- `_bios_clearkeyflags`
- `OVERLAY.COD`

Status:
- Not started

#### C6. Stack-frame cleanup for MSC wrappers

Deterministic goal:
- outgoing-call staging slots are distinguished from real locals so simple
  wrappers stop declaring synthetic `s_*` locals in final C

Completion signals:
- `_openFileWrapper` becomes a direct forwarding call
- `_dos_loadOverlay` becomes a direct `loadprog(...)` wrapper

Validation:
- `_openFileWrapper`
- `_dos_loadOverlay`

Status:
- Not started

#### C7. Condition and return recovery on typed COD objects

Deterministic goal:
- DOS helper conditions and returns are expressed in terms of typed object
  fields and source-level comparisons before final text emission

Completion signals:
- `_dos_getfree` recovers the `rout.x.cflag` check and returns `rout.x.bx`
- `_dos_getReturnCode` emits a real return value

Validation:
- `_dos_getfree`
- `_dos_getReturnCode`

Status:
- Not started

#### C8. Timeout triage and structuring improvement

Deterministic goal:
- timeout-heavy COD functions get stage-classified and the fixed target set
  shows measurable timeout reduction without regressing simple wrappers

Completion signals:
- scanner reports timeout stage, call count, block count, known-object count,
  and whether metadata seeding was used
- timeout rate drops on the bounded COD scan

Validation:
- bounded COD scanner
- sample matrix

Status:
- Not started

### COD Module Checklist

- driver / CLI pipeline:
  - add `CodRecoveryInfo`
  - seed CFG from COD proc metadata
  - record timeout stage
- `angr_platforms/X86_16/analysis_helpers.py`:
  - add MSC extern signature catalog
  - attach typed COD callsites
  - propagate wrapper returns
- `angr_platforms/X86_16/cod_known_objects.py`:
  - define `REGS`, `SREGS`, `exeLoadParams`, `ovlLoadParams`
- `angr_platforms/X86_16/alias_model.py`:
  - add `dgroup_global` object identity
  - add far-pointer local object domain
  - add outgoing-call staging-slot classification
- `angr_platforms/X86_16/widening_model.py`:
  - add DGROUP field joins
  - add far word load/store widening
- `angr_platforms/X86_16/cod_type_recovery.py`:
  - map stable object offsets to field syntax
  - lower stable far-pointer objects conservatively
- condition simplifier:
  - rewrite typed field comparisons and return paths before final C rendering
- `angr_platforms/X86_16/cod_wrapper_simplifier.py`:
  - simplify direct forwarding wrappers only after call recovery is correct

### COD Definition Of Done For This Phase

This COD phase is done when all of these are true on the fixed target set:

- `_bios_clearkeyflags` is a far word store, not two anonymous byte stores
- `_dos_getfree` emits typed `rin/rout` field accesses, the `intdos` call, the
  `cflag` check, and `return rout.x.bx;`
- `_dos_getReturnCode` emits a return value
- `_dos_loadOverlay` emits `return loadprog(file, segment, 3, 0);`
- `_openFileWrapper` emits a direct call without fake staging locals
- bounded COD scan reports fewer bogus numeric callees and fewer timeouts than
  before
