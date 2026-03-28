# Inertia Decompiler

## Overview

Project name: **Inertia decompiler**.

Decompiler for 16-bit x86 real mode based on angr.
angr_platforms - patched to support x86 16-bit.
angr_platforms/angr_platforms/X86_16 helps to convert x86 16-bit binary into AIL IR, and use angr as decompiler.
.venv/ have patched "angr" to support x86 16-bit which need to be moved upstream.

The `angr-platforms` project is a collection of AIL lifters that enhance the [angr](https://angr.io) binary analysis framework. These agents enable support for non-standard architectures, virtual machines, and esoteric languages by providing modular implementations of key angr subsystems:

- **Architecture (Arch)**: Defines register layouts, bit widths, endianness, and other hardware characteristics using [archinfo](https://github.com/angr/archinfo).
- **Loader**: Handles binary loading and memory mapping via [CLE](https://github.com/angr/cle) backends, supporting formats like ELF, raw blobs, or custom structures.
- **Lifter**: Translates machine code or instructions to VEX IR, allowing symbolic execution with angr's default engine.
- **Simulation Engine (SimEngine)**: Executes code symbolically, either via VEX (SimEngineVEX) or custom engines for direct interpretation.
- **SimOS**: Emulates operating system behaviors, including syscalls and high-level abstractions like file I/O, using angr's SimOS framework.

These agents are registered automatically upon import, integrating seamlessly with angr's lifecycle: loading → architecture identification → lifting → execution → OS simulation. For detailed internals, see the [tutorial](angr_platforms/tutorial/1_basics.md).

**Note**: Many platforms are better served by angr's pcode engine ([pypcode](https://github.com/angr/pypcode)). This repo receives limited maintenance; consider pcode for production use.

## Supported Platforms

The following platforms are supported, each with dedicated agents. Platforms marked [WIP] are works-in-progress.

### x86-16 (Real Mode)
- **Description**: Support for 16-bit x86 real mode decompiler.
- **Key Agents**:
  - Arch: [`arch_86_16.py`](angr_platforms/angr_platforms/X86_16/arch_86_16.py)
  - Lifter: [`lift_86_16.py`](angr_platforms/angr_platforms/X86_16/lift_86_16.py)
  - Core: [`emulator.py`](angr_platforms/angr_platforms/X86_16/emulator.py), [`processor.py`](angr_platforms/angr_platforms/X86_16/processor.py)
  - Instructions: [`instr_base.py`](angr_platforms/angr_platforms/X86_16/instr_base.py), [`instr16.py`](angr_platforms/angr_platforms/X86_16/instr16.py)
  - SimOS: [`simos_86_16.py`](angr_platforms/angr_platforms/X86_16/simos_86_16.py)
  - Hardware: Modules for memory ([memory.py](angr_platforms/angr_platforms/X86_16/memory.py)), I/O ([io.py](angr_platforms/angr_platforms/X86_16/io.py)), interrupts ([interrupt.py](angr_platforms/angr_platforms/X86_16/interrupt.py)).
- **Tests**: [`tests/test_x86_16bit.py`](angr_platforms/tests/test_x86_16bit.py)

#### AIL IR Lifting
Recent improvements include IRSB generation in [`lift_86_16.py`](angr_platforms/angr_platforms/X86_16/lift_86_16.py), instr16.py.

The AIL lifter supports a segment model for 16-bit real mode, handling CS shifts (<<4) for memory addressing in Load/Store operations. Use the existing lifter in /home/xor/vextest/angr_platforms/angr_platforms/X86_16 for decompilation without Capstone fallback.

**Verification**: Tested with raw bytes for MOV AX,1; ADD AX,2; RET (`b'\xb8\x01\x00\x05\x02\x00\xc3'`), loaded via blob backend. Produces correct pseudocode:  
```
AX = 1;
AX += 2;
return;
```
No external patched angr is needed for these basics; custom agents enable decompilation.

**Usage Example**:
```python
import angr

# Raw bytes example
binary = b'\xb8\x01\x00\x05\x02\x00\xc3'  # MOV AX,1; ADD AX,2; RET
p = angr.Project(binary, backend='blob', arch='X86_16')
cfg = p.analyses.CFG()
decomp = p.analyses.Decompiler(target_addr=0x0)
print(decomp.code)
```

## Usage

Install via `setup.py` ([setup.py](angr_platforms/setup.py), requires angr, cle, archinfo, pyvex). Import modules to register agents, then use angr as usual:

```python
import angr
p = angr.Project("path/to/binary")  # Auto-selects agents based on format/arch
```

## Global Goal

- This project is **not** aiming to become a transpiler.
- The goal here is an **angr-based decompiler** for 16/32-bit x86 real-mode binaries that produces **human-readable C**.
- Prefer building on angr's existing pipeline:
  - CFG recovery
  - VEX/AIL lifting
  - decompiler passes
  - structured C generation
- The main strategy is to make the decompiler better and faster by improving recovery quality before code generation, especially for:
  - control-flow structuring
  - variable and stack recovery
  - calling convention recovery
  - expression simplification
  - type recovery
  - naming and readability
- Priorities, in order:
  - improve human-readable C for the target corpus
  - preserve correctness while improving readability
  - make a useful subset of output recompilable where practical
- When forced to choose, favor decompiler-quality work over transpiler-style semantic re-expression.

### Architecture Model

Use this decompiler architecture as the default mental model:

`IR -> Alias model -> Widening -> Traits -> Types -> Rewrite`

In practice:

- `IR` is the normalized input layer produced by lifting.
- `Alias model` decides which values really refer to the same storage.
- `Widening` combines byte-pairs, projections, and joins into cleaner values.
- `Traits` collect repeated-offset, stride, and induction evidence.
- `Types` turn stable evidence into arrays, structs, and typed pointers.
- `Rewrite` is the last-stage C cleanup layer that applies only after the
  evidence is stable.

The intended order is important: alias + widening first, then traits and types,
and only then object rewriting. Avoid mixing those layers together in a single
local pass if a boundary object or helper can keep the responsibilities clear.

For x86-16 specifically, model aliasing as:

- a `domain` that says what storage the value belongs to
- a `view` that says which slice of that storage is visible
- a `state` object that records whether a full value must be synthesized

Start with register domains, stack-slot domains, and segmented-memory domains.
Only widen values after the alias model has already proved that the parts are
compatible.

## Tutorials

- [Part 1: Basics](angr_platforms/tutorial/1_basics.md) – angr lifecycle and components.
- Subsequent parts cover arch, loader, lifter, engine, SimOS, and analysis.

## Contributing

Add new agents by implementing and registering classes (e.g., subclass `Arch`, `CLEBackend`, `Lifter`, `SimEngine`, `SimOS`). See [BrainFuck](angr_platforms/angr_platforms/bf/) as an example. WIP branches for incomplete platforms.

For issues or maintenance, consider angr's pcode alternatives.

## Repository Coding Guidelines

- **Files:** Keep individual source files under 300 lines where practical to improve reviewability and maintainability.
- **Single Responsibility Principle:** Prefer small modules/functions that do one thing. If a file grows beyond its focused purpose, split it into smaller files following SRP.
- **Why:** Smaller, SRP-aligned files simplify testing, linting, and code review for this project which targets low-level lifters and simulation helpers.


## Current x86-16 Status

### Recent progress

- The active top-level `.venv` was upgraded to upstream angr `9.2.205` and related packages.
- 80286-focused real-mode progress now also has a dedicated board at:
  - `angr_platforms/docs/x86_16_80286_real_mode_coverage.md`
  - generated by `angr_platforms/scripts/build_x86_16_80286_real_mode_coverage.py`
- Direct edits that previously existed inside `.venv/` were backed up before the upgrade under:
  - `backups/venv_angr_stack_2026-03-20/README.md`
  - `backups/venv_angr_stack_2026-03-20/patched_files_manifest.json`
  - `backups/venv_angr_stack_2026-03-20/patches/python3.12-combined.patch`
- A helper to re-export those saved patches lives at:
  - `angr_platforms/scripts/export_saved_angr_patches.py`
- A new corpus-mining helper now exists at:
  - `angr_platforms/scripts/inventory_cod_mnemonics.py`
  - intended usage: `cd /home/xor/vextest/angr_platforms && ../.venv/bin/python scripts/inventory_cod_mnemonics.py ../cod --top 80`
  - current purpose:
    - count real mnemonics present in the `.COD` corpus
    - drive the “support all 286 real-mode mnemonics” effort from shipped code first instead of from an abstract opcode list
- A mnemonic coverage board now exists at:
  - `angr_platforms/docs/x86_16_mnemonic_coverage.md`
  - generated by: `angr_platforms/scripts/build_x86_16_mnemonic_coverage.py`
  - intended usage: `cd /home/xor/vextest/angr_platforms && ../.venv/bin/python scripts/build_x86_16_mnemonic_coverage.py ../cod --output docs/x86_16_mnemonic_coverage.md`
  - current purpose:
    - keep a canonical non-FPU 186-style mnemonic table in the repo
    - track per-mnemonic lifter support, simulator support, focused tests, and real `.COD` usage counts
- A DOSBox/86Box reference-priority board now exists at:
  - `angr_platforms/docs/x86_16_reference_priority.md`
  - generated by: `angr_platforms/scripts/build_x86_16_reference_priority.py`
  - intended usage:
    - `cd /home/xor/vextest/angr_platforms && ../.venv/bin/python scripts/build_x86_16_reference_priority.py ../cod --output docs/x86_16_reference_priority.md`
  - current purpose:
    - use DOSBox and 86Box as secondary semantic references for triage
    - highlight instructions that are good candidates for another 80286 dump-backed verification pass
    - keep the workflow explicit: DOSBox/86Box help implementation and bug-hunting, but the 80286 `.MOO` corpus remains the source of truth
- A hardware-backed 80286 real-mode verifier now exists at:
  - core module: `angr_platforms/angr_platforms/X86_16/verification_80286.py`
  - run script: `angr_platforms/scripts/verify_80286_real_mode.py`
  - table script: `angr_platforms/scripts/build_80286_real_mode_verification_table.py`
  - intended usage:
    - `cd /home/xor/vextest/angr_platforms && ../.venv/bin/python scripts/verify_80286_real_mode.py ../80286/v1_real_mode --opcode 00 --limit 10 --json-output /tmp/verify_286.json`
    - `cd /home/xor/vextest/angr_platforms && ../.venv/bin/python scripts/build_80286_real_mode_verification_table.py /tmp/verify_286.json --output docs/80286_real_mode_verification.md`
  - current purpose:
    - replay hardware-captured 286 real-mode instruction cases into the x86-16 simulator
    - compare final register subsets and RAM bytes against the dump
    - produce per-opcode pass/fail summaries and markdown tables
- Some of the old patched-angr behavior has already been moved into repo-managed compatibility shims in:
  - `angr_platforms/angr_platforms/X86_16/__init__.py`

### Important x86-16 test files

- `angr_platforms/tests/test_x86_16_smoketest.py`
- `angr_platforms/tests/test_x86_16_cod_samples.py`
- `angr_platforms/tests/test_x86_16_dos_mz_loader.py`
- `angr_platforms/tests/test_x86_16_sample_matrix.py`
- `angr_platforms/tests/test_x86_16_runtime_samples.py`
- `angr_platforms/tests/test_x86_16_compare_semantics.py`
- `angr_platforms/tests/test_x86_16_cli.py`

### Current known-good focused test command

Run from `/home/xor/vextest/angr_platforms`:

```bash
../.venv/bin/python -m pytest -q \
  tests/test_x86_16_smoketest.py \
  tests/test_x86_16_cod_samples.py \
  tests/test_x86_16_dos_mz_loader.py \
  tests/test_x86_16_sample_matrix.py \
  tests/test_x86_16_runtime_samples.py
```

Expected status as of 2026-03-21:
- `85 passed, 2 skipped`

### Focused lint/type-check scope

- `pyproject.toml` now targets `ruff` and `mypy` primarily at:
  - `angr_platforms/X86_16/*.py`
  - the `tests/test_x86_16*.py` files
  - `tests/conftest.py`
- This is intentional: it keeps lint/type work centered on the x86-16 lifter/decompiler surface we are actively enhancing instead of the whole historical repo.
- Current local nuance:
  - the repo `.venv` still does not have `ruff` or `mypy` installed, so `../.venv/bin/python -m ruff ...` and `../.venv/bin/python -m mypy` currently fail with `No module named ...`

### DOS / BIOS interrupt support status

- `int xx` lifting now routes to synthetic targets at `0xFF000 + vector`.
- `angr_platforms/angr_platforms/X86_16/simos_86_16.py` hooks all 256 vectors.
- For execution, the same handlers are also hooked at their 16-bit runtime aliases:
  - `interrupt_addr(vector) & 0xFFFF`
  - this is needed because symbolic execution lands on truncated 16-bit interrupt targets even when the lifted IR encodes `0xFF000 + vector`
- Named/common handlers exist for:
  - BIOS: `10h`, `11h`, `12h`, `13h`, `14h`, `15h`, `16h`, `17h`, `1Ah`
  - DOS: `20h`, `21h`, `25h`, `26h`, `27h`, `2Fh`
- `int 21h` has a few implemented semantics already:
  - `AH=09h`
  - `AH=19h`
  - `AH=30h`
  - `AH=35h`
  - `AH=4Ch` now terminates execution via `exit(code)`
- `INT 20h` and `INT 27h` now also behave as no-return DOS termination helpers
- All other vectors currently have safe generic hooks mainly for CFG/decompilation stability, not full semantics.

### Runtime sample status

- There is now execution-based coverage in:
  - `angr_platforms/tests/test_x86_16_runtime_samples.py`
- Current runtime scope:
  - runs the tiny `.COM` samples under angr/SimOS
  - verifies they reach clean DOS termination with both:
  - plain `simgr.step()` block stepping
  - instruction-by-instruction stepping using Capstone-derived sizes
- Recent fix:
  - `angr_platforms/angr_platforms/X86_16/lift_86_16.py` now stops decode at block-terminating instructions like `int`, `call`, `ret`, and jumps
  - this fixed the old decode-through-data failure on `ICOMDO.COM`, where lifting used to run past `int 21h` into the trailing `"sample$"` string bytes
  - `angr_platforms/angr_platforms/X86_16/access.py` now uses modern `Type.int_*` values for segmented constant construction and imports `JumpKind` for far calls
  - this fixed medium-model far-call lifting such as the `IMOD.EXE` block at `0x1180`
- Current nuance:
  - plain stepping now works for the covered COM runtime samples
  - the instruction-sized stepping helper remains useful as a narrower execution harness for future debugging

### Recent control-flow fixes

- `instr16.py` now routes near control-flow through shared helpers:
  - `_emit_near_call()`
  - `_emit_near_jump()`
- This was added after finding a real CFG/decompiler bug in `call r/m16`:
  - `call_rm16()` had been mutating `IP` directly instead of emitting `Ijk_Call`
  - the block could keep decoding into following instructions and collapse into a fake `ret`-shaped block if a `ret` byte sequence followed
- Fix:
  - `call_rel16()` and `call_rm16()` now both emit `Ijk_Call`
  - `jmp_rel16()` and `jmp_rm16()` now both go through the same bounded jump helper
- Regression coverage:
  - `tests/test_x86_16_smoketest.py::test_indirect_near_call_lifts_as_call_edge`
  - this checks `mov ax, 0x1005; call ax; ret` and verifies the block stops at the indirect call instead of folding in the trailing `ret`
- Far-control-flow paths were tightened too:
  - `retf_imm16()` in `instr_base.py` had two real bugs:
    - it called nonexistent `self.set_gpreg(...)` instead of `self.emu.set_gpreg(...)`
    - it adjusted `SP` before popping `IP`/`CS`, which is the wrong order for `retf imm16`
  - `access.py` now has a real `jmpf()` helper for far jumps
  - `access.py` `callf()` now accepts an explicit `return_ip`, which avoids hardcoding the 5-byte immediate far-call case for all far calls
  - `InstrData` now tracks `prefix_len` and total `size`
  - `parse.py` now records total instruction size during parsing
  - `callf_m16_16()` now uses the parsed instruction size for its return address instead of a guessed constant
- Current regression coverage in `tests/test_x86_16_smoketest.py` now includes:
  - immediate far call
  - immediate far jump
  - indirect far call
  - indirect far jump
  - `retf imm16`
  - indirect near call
- The simplified Capstone-backed branch path in `lift_86_16.py` also had a real jcc polarity bug:
  - `_lift_simple()` was feeding taken-branch predicates directly into `Instruction.jump()`
  - pyvex expects that helper condition to describe the fallthrough edge instead
  - result: short/near simple conditional branches could invert the edge shape in the lifted IRSB
- Fix:
  - `lift_86_16.py` now routes those through `_emit_simple_jcc()`, which inverts the taken predicate in one explicit place
- Regression coverage:
  - `tests/test_x86_16_smoketest.py::test_simple_je_short_targets_branch_destination`
  - `tests/test_x86_16_smoketest.py::test_simple_je_near_targets_branch_destination`

### Compare-based instruction semantics

- There is now a small compare-style regression file:
  - `angr_platforms/tests/test_x86_16_compare_semantics.py`
- It follows the same idea as `/home/xor/vextest/compare.py`:
  - run one instruction under upstream x86 VEX and under the x86-16 lifter
  - compare concrete effects on registers and memory
- Current covered cases:
  - `stosb`
  - `stosw` (compared against 32-bit `0x66 0xAB` so the operand size matches)
  - `lodsb`
  - `lodsw` (compared against 32-bit `0x66 0x67 0xAD` so operand and address size match)
  - `scasb`
  - `scasw`
  - `rcr ax, 1` (compared against 32-bit `0x66 0xD1 0xD8`)
  - `ror al, 1` result regression (compared against 32-bit `0xD0 0xC8`)
  - `adc ax, imm16` (compared against 32-bit `0x66 0x15 ...`)
  - `sar al, 1` result regression (compared against 32-bit `0xD0 0xF8`)
  - `loop rel8` (compared against 32-bit `0x67 0xE2 ...` using relative-target equivalence)
  - `cmpsb` (compared against 32-bit `0x67 0xA6`)
  - direct execution tests for `les` and `lds` far-pointer loads
  - `iret` lifting/runtime regression coverage, asserting the lifted block writes `CS` and `FLAGS`, returns with `Ijk_Ret`, and transfers control to the low 16-bit target without crashing
  - direct execution coverage for `pop r/m16` (`0x8f /0`)
- This was added while enabling real sample-matrix coverage, since medium-model startup code reached `f3 aa` and exposed the missing `stosb` lift.

### Recent rotate/return fixes

- `angr_platforms/angr_platforms/X86_16/instr16.py`
  - added missing `0xD1 /3` dispatch for `rcr r/m16,1`
  - added `rcr_rm16_1()`
  - fixed `rcl()` and `rcr()` to write updated `FLAGS` back after carry/overflow changes
  - fixed `loop`, `loope`, and `loopne` to use properly widened signed rel8 offsets
  - added `0x8f /0` support for `pop r/m16`
- `angr_platforms/angr_platforms/X86_16/instr_base.py`
  - fixed `iret()` to return to `v2p(cs, ip)` instead of crashing on an undefined `laddr`
  - `code_d0_d2()` is now a clearer lazy name-based dispatch table instead of a long `if/elif` chain
  - real bug found while improving readability: `reg == 7` (`sar r/m8`) had been unreachable because the old code repeated `reg == 5`
  - `shl_rm8()`, `shr_rm8()`, and `sar_rm8()` now exist for the Group-2 byte-op path
- `angr_platforms/angr_platforms/X86_16/processor.py`
  - fixed `get_carry()` to return a real wrapped bit expression (`flags[0]`) instead of a raw `Binop`, which had been breaking rotate-through-carry lifting

### Recent mnemonic-inventory-driven fixes

- `angr_platforms/angr_platforms/X86_16/instr_base.py`
  - added real handlers for:
    - `sahf` (`0x9E`)
    - `lahf` (`0x9F`)
    - `cmc` (`0xF5`)
    - `clc` (`0xF8`)
    - `stc` (`0xF9`)
  - kept `lohf()` as a compatibility alias to the corrected `lahf()` implementation
- `angr_platforms/tests/test_x86_16_compare_semantics.py`
  - now has compare-style execution regressions for:
    - `lahf`
    - `sahf`
    - `cmc`
    - `clc`
    - `stc`
- Current first corpus-driven inventory snapshot from `../cod` shows the remaining real-code long tail includes:
  - aliases/prefix spellings like `je`, `jne`, `jg`, `jge`, `rep`
  - low-frequency integer instructions such as `sahf`, `cmc`, `mul`
  - a separate FPU bucket (`fld`, `fstp`, `fdiv`, `fwait`, ...)
- Practical workflow going forward:
  - use `inventory_cod_mnemonics.py` to rank mnemonics seen in real `.COD` code
  - compare that list against current lift coverage in `instr_base.py` and `instr16.py`
  - prioritize integer/real-mode instructions that either:
    - still fail bounded lifting in `scripts/scan_cod_dir.py`, or
    - are present in the corpus but missing obvious handlers/tests
  - keep FPU mnemonics tracked separately from the 286 integer/control-flow backlog unless a real sample is blocked on them

### Current bounded real-sample decompilation findings

- Using `CFGFast(start_at_entry=False, function_starts=[...])` on `x16_samples/IMOD.EXE` exposed a real medium-model blocker before the latest loop fix:
  - `loop rel8` had been building malformed typed arithmetic (`Add16(..., 0x-e)`)
- After the loop fix, targeted decompilation on real sample functions is still expensive enough that a `timeout 20` probe can expire without producing stable output, so the next iteration should likely keep using bounded single-function probes with explicit timeouts rather than whole-program CFG/decompilation.
- A separate small-model bounded probe also surfaced an unknown `0x8f` opcode on one path, which is why `pop r/m16` was added.
- A relocation-free real sample from `x16_samples/ISOD.COD` now has direct regression coverage:
  - `fold_values` decompiles successfully from raw `.COD` bytes via `tests/test_x86_16_cod_samples.py`
  - this probe exposed a bogus `Iop_16Sto16` in the lifted IR, traced to duplicate sign extension in `sub rm16, imm8` / `and rm16, imm8` flag-update paths
  - that duplicate sign extension was removed, which unblocked decompilation of the sample blob
- The far-model counterpart `x16_samples/IMOD.COD` `fold_values` now also has direct regression coverage and decompiles successfully from raw `.COD` bytes.
- `tests/test_x86_16_cod_samples.py` is now organized as a small table-driven corpus spec:
  - `DecompCase` entries for source-backed decompilation oracles
  - `BlockLiftCase` entries for real-code block-lift oracles
  - this makes it much easier to add new `.COD` samples without duplicating boilerplate and keeps the original C intent visible near the expected anchors
- The external real-code corpus under `/home/xor/vextest/cod/f14/` is now being mined too.
  - `OVL.COD` `_dig_load_overlay` is relocation-free and now has direct block-lifting coverage in `tests/test_x86_16_cod_samples.py`.
  - That sample exposed a real missing opcode on live code: `0x15` (`adc ax, imm16`) at offset `0x37`.
  - Fix: `angr_platforms/angr_platforms/X86_16/instr16.py` now registers and implements `adc_ax_imm16()`.
  - Current regression shape: the lifted block at `0x1030` is checked for the real `adc`/flags/update path instead of running whole-function decompilation, which keeps the suite fast and stable.
  - `MONOPRIN.COD` `_mset_pos` is also relocation-free and now has direct decompilation coverage.
  - Current stable recovered features from that sample: `% 80`, `% 25`, and a clean `return` path.
  - `NHORZ.COD` `_ChangeWeather` is also relocation-free and now has direct decompilation coverage.
  - Current stable recovered features from that sample: the original weather constants `8150`, `500`, `125`, and `1000`.
  - `PLANES3.COD` `_Ready5` is also relocation-free and now has direct decompilation coverage.
  - Current stable recovered features from that sample: the original struct-stride constants `46` and `18`, plus a clean `return` path.
  - `COCKPIT.COD` `_ConfigCrts` now has direct block-lifting coverage for its indexed copy loop.
  - Current stable lifted features from that sample: scaled index via `Shl16`, source offset `0x0222`, `LDle:I16` / `STle`, and loop bound `8`.
  - `COCKPIT.COD` `_LookDown` now has direct decompilation coverage.
  - Current stable recovered features from that sample: the original UI/layout constants `50`, `27`, `25`, and `39`.
  - `COCKPIT.COD` `_LookUp` now has direct decompilation coverage.
  - Current stable recovered features from that sample: the original UI/layout constants `150`, `138`, `136`, and `139`.
  - `BILLASM.COD` `_MousePOS` now has direct decompilation coverage.
  - Current stable recovered features from that sample: the `MouseX = x * 2` scaling, a clean early-return path, and the mouse interrupt call site.
  - `x16_samples/ISOD.COD` `query_interrupts` now has direct block-lifting coverage for its relocation-free setup prefix before the first `_int86` call.
  - Current stable lifted features from that sample: `inregs.h.ah = 0x30`, `int86(0x21, ...)` setup, and the expected fallthrough IP before the unresolved call site.
  - `cod/default/MAX.COD` `_max` now has direct block-lifting coverage for its relocation-free compare/return body after the `__chkstk` prologue call.
  - Current stable lifted features from that sample: the `x > y` compare path, the two return-target branches, and the expected body-only fallthrough shape.
  - `CARR.COD` `_InBox` now has direct block-lifting coverage for its entry bounds-check block.
  - Current stable lifted features from that sample: unsigned compare IR (`CmpGT16U`) and the two source-corresponding branch targets for the `return 0` and `return 1` paths.
- A real sample-matrix crash site at `ISOD.EXE:0x1267` (`f3 a6`, `rep cmpsb`) is now covered and lifts successfully.
  - Root cause: `cmpsb/cmpsw` still had legacy handwritten logic; `cmpsb` used `self.emu.ES` as a nonexistent attribute and mixed repeat-condition widths incorrectly.
  - Fix: `cmpsb/cmpsw` were moved onto the same single-step/update/jump style as the newer string ops, and the `cmpsb` real-code block now lifts under test.
  - Current nuance: `cmpsw` still does not have a compare-style semantic regression because its behavior does not yet match upstream closely enough to lock in.

### DOS MZ loader status

- Real DOS MZ loading support exists in:
  - `angr_platforms/angr_platforms/X86_16/load_dos_mz.py`
- It is registered through:
  - `angr_platforms/angr_platforms/X86_16/__init__.py`
- Real MSC-built loader coverage exists against:
  - `/home/xor/games/f15se2-re/T.EXE`
  - `/home/xor/games/f15se2-re/T.COD`

### Small real EXE decompilation status

- We now have bounded entry-function decompilation coverage for two real MSC-built `.EXE` samples:
  - `x16_samples/ISOD.EXE`
  - `x16_samples/IMOD.EXE`
- Coverage lives in:
  - `angr_platforms/tests/test_x86_16_sample_matrix.py`
- Current guarantee:
  - bounded `CFGFast` recovers the entry function
  - `Decompiler` produces C text instead of crashing or timing out under the focused test settings
- Current stable anchors:
  - `ISOD.EXE` recovered entry C contains `520`
  - `IMOD.EXE` recovered entry C contains `526`
  - `IMOD.EXE` recovered entry C also now contains seeded far-call names such as `sub_1380()` and `sub_161f()`
- Interpretation:
  - this is good evidence that angr is a viable base for small DOS real-mode `.EXE` decompilation
  - current weaknesses are mostly decompilation quality issues around calling conventions, stack tracking, and startup-code readability, not basic loader/lifter viability
- Current nuance:
  - the helper-assisted bounded CFG makes the recovered C much more readable for medium-model startup code
  - angr decompiler warnings about `callee None` still remain, so callsite recovery inside the decompiler is not fully solved yet

### Real sample corpus

- The canonical reproducible real-mode sample matrix now lives in:
  - `/home/xor/vextest/angr_platforms/x16_samples/`
- User-facing rebuild entry point:
  - `/home/xor/vextest/angr_platforms/scripts/build_x16_samples.sh`
- User-facing decompiler entry point from the repo root:
  - `/home/xor/vextest/decompile.py`
  - intended usage: `./decompile.py binary.exe`
  - for raw blobs: `./decompile.py --blob binary.bin`
  - current behavior:
    - with `--addr`, it still decompiles one specific function
    - without `--addr`, it now recovers a bounded whole-binary function catalog, prints each recovered function it can decompile, and falls back to a short asm listing plus error/timeout info for functions it cannot
    - `.EXE` whole-binary recovery now stays bounded enough for small real samples like `snake.exe`
    - `.COM` entry decompilation now infers a small linear code region first, so tiny DOS stubs like `ICOMDO.COM` decompile instead of immediately walking into trailing strings
    - resource guardrails were added in the CLI: `--timeout`, `--window`, and `--max-memory-mb`
    - whole-binary printing is capped with `--max-functions`
    - the remaining nuance is quality, not basic usability: `.COM` output is still rough and call targets may remain unnamed
    - the CLI now suppresses most internal decompiler warning noise so the user sees function results instead of logger spam
- Real user-facing sample:
  - `/home/xor/vextest/snake.exe`
  - `./decompile.py ./snake.exe --timeout 10 --max-functions 6`
  - current behavior:
    - recovers 15 functions
    - decompiles the readable subset
    - prints asm fallback for functions like `sub_11a3` when decompilation returns no code
- Block-level flow troubleshooting helper:
  - `/home/xor/vextest/angr_platforms/scripts/inspect_x86_16_flow.py`
  - intended usage:
    - `cd /home/xor/vextest/angr_platforms && ../.venv/bin/python scripts/inspect_x86_16_flow.py x16_samples/ISOD.EXE --blocks 1`
  - it prints recovered blocks, jump kinds, next targets, asm, and VEX side by side for a bounded function window
- Bounded far-call recovery helpers:
  - `/home/xor/vextest/angr_platforms/angr_platforms/X86_16/analysis_helpers.py`
  - current helpers:
    - `collect_direct_far_call_targets(function)` recovers immediate far-call `seg:off` targets directly from the entry function blocks
    - `patch_far_call_sites(function, far_targets)` rewrites `Function._call_sites` for those direct far-call sites so `Function.get_call_target()` returns the real linear callee address instead of a bogus short target like `0x14`
    - `extend_cfg_for_far_calls(project, function, entry_window=..., callee_window=...)` reruns bounded `CFGFast` with those targets seeded as extra function starts/regions
  - this is now used by:
    - `tests/test_x86_16_sample_matrix.py`
    - `/home/xor/vextest/decompile.py`
  - motivation:
    - medium-model DOS startup code uses many immediate far calls that stock angr CFG still collapses to bogus `0x14`-style call targets
    - seeding the direct far callees materially improves user-visible decompiled C without requiring a wide CFG scan
- Main files:
  - `x16_samples/intdemo.c`
  - `x16_samples/IDEMO.C`
  - `x16_samples/build_matrix.sh`
  - `x16_samples/matrix_manifest.json`
  - `x16_samples/ICOMDO.ASM`
  - `x16_samples/ICOMBI.ASM`
- The manifest is consumed by:
  - `angr_platforms/tests/test_x86_16_sample_matrix.py`
- Compatibility setup:
  - `/home/xor/games/f15se2-re/x16_samples` is a symlink to the in-project copy
  - the pre-move directory was preserved at `/home/xor/games/f15se2-re/x16_samples.backup_2026-03-20`

### Sample matrix contents

- MSC 5.1 `.EXE` variants with `.COD` for:
  - small: `/Od`, `/Ot`, `/Ox`
  - medium: `/Od`, `/Ot`, `/Ox`
  - large: `/Od`, `/Ot`
  - huge: `/Od`, `/Ot`
- `.COM` coverage currently comes from UASM-built tiny binaries, because the packaged MSC linker in this environment did not accept `/T` or `/TINY`.

### Toolchain caveats in `f15se2-re`

- `x16_samples/build_matrix.sh` is meant to be run from `angr_platforms`, not from `f15se2-re`.
- The build still uses the DOS compiler toolchain from `f15se2-re` by default:
  - default toolchain root: `/home/xor/games/f15se2-re`
  - override with `X16_TOOLCHAIN_ROOT=/path/to/f15se2-re`
- The rebuild script stages sources into a real directory under the toolchain tree:
  - `x16_samples_stage`
  - this avoids DOSBox mount/write issues with symlinked source directories
- The DOS build environment for `x16_samples` may require compatibility copies of MSC runtime libraries:
  - `dos/msc510/lib/MLIBCE.LIB`
  - `dos/msc510/lib/LLIBCE.LIB`
- These were created by copying:
  - `dos/msc510/lib/MLIBCR.LIB -> dos/msc510/lib/MLIBCE.LIB`
  - `dos/msc510/lib/LLIBCR.LIB -> dos/msc510/lib/LLIBCE.LIB`
- If medium/large/huge sample builds fail at link time, check for those files first.

### Commit checkpoints already made

Useful recent commits in `angr_platforms`:
- `7fc1599` `Add COD-derived x86-16 regression tests`
- `96057ab` `Fix x86-16 shift lifting wrappers`
- `e013179` `Add lint config and BIOS COD coverage`
- `352fd5f` `Wrap raw x86-16 VEX expressions via tmps`
- `7fc2baa` `Port x86-16 angr compatibility shims`
- `9764be3` `Adapt Pointer16 specialization to new angr`
- `217354a` `Stabilize x86-16 decompiler smoke tests`
- `b5a88bb` `Add DOS MZ loader for x86-16 binaries`
- `d222b3e` `Route x86-16 interrupt lifts through a facade`
- `4e782ce` `Hook synthetic DOS int 21h targets`
- `29579cc` `Add DOS and BIOS interrupt handler framework`
- `ba3b8b8` `Add regression coverage for sample matrix`
- `521996c` `Add x86-16 runtime sample coverage`

Useful recent commit in `f15se2-re`:
- `0d19540` `Add x86-16 sample matrix corpus`

### Next likely steps

- Keep commits small and regular. The user explicitly asked for that.
- Prefer moving remaining 16-bit support out of patched `.venv/` behavior and into repo-managed code or upstreamable patches.
- Keep using `.COD` files as a decompilation-quality oracle whenever possible.
- Good next targets:
  - extend real-binary coverage beyond entry-block loading
  - improve decompiler-side far-call target recovery so clinic/callsite_maker stop reporting `callee None` on medium-model startup code
  - run/decompile more of the sample matrix end-to-end, not just entry or tiny runtime paths
  - sample-matrix decompilation currently gets farther, but still needs more real-code instruction coverage beyond the new `stos*`, `lods*`, `scas*`, `lds`, and `les` support
  - add stronger semantic checks for interrupt-heavy samples, especially BIOS data-area interactions such as `0x417`
  - improve decompilation quality for the BIOS `.COD` sample now that it no longer crashes
  - keep improving user-facing names/docs for BIOS Data Area symbols such as `0x417` (`0x40:0x17`, keyboard flag byte 0)

### Tips And Tricks For Next Agents

- For wide `.COD` triage, use the bounded scanner instead of ad hoc probing:
  - `../.venv/bin/python scripts/scan_cod_dir.py /path/to/cod_dir --timeout-sec 5 --max-memory-mb 1024`
  - `../.venv/bin/python scripts/scan_cod_dir.py /path/to/cod_dir --mode decompile-reloc-free --timeout-sec 5 --max-memory-mb 1024`
  - it now scans recursively with `rglob("*.COD")`, not just one directory level
  - it is sequential, applies a hard address-space cap with `RLIMIT_AS`, and prevents the multi-process RAM blowups the user reported
- Current bounded whole-directory result for `cod/default/`:
  - 31 functions scanned
  - no raw block-lift failures
  - no relocation-free decompilation failures under the same bounded settings
- Current early whole-tree `cod/` triage findings after switching the scanner to recursive mode:
  - first blocker was unknown opcode `0x1A` (`sbb r8, r/m8`)
  - second blocker was a typed-width bug in `sbb rm16, imm8`, where a 1-bit carry was subtracted from a 16-bit value without widening
  - both are fixed now, and the compare-style suite has direct regressions for them
- Current bounded `f14` batch triage (`--stop-after-failures 5`) surfaced these exact first-five lift blockers:
  - `3DPLANES.COD` `_Do3dObject` — timeout
  - `BULLETS.COD` `_TrackBullets` — timeout
  - `CARR.COD` `_GetCatHeading` — timeout
  - `CARR.COD` `_GlideScopeCheck` — timeout
  - `CARR.COD` `_ils` — timeout
- Best-next-step result from that batch:
  - `_GetCatHeading` was the best target because it is tiny and relocation-free
  - it was narrowed to the segmented direct-memory instruction `26 03 06 0c 00` (`add ax, WORD PTR es:[000Ch]`)
  - fixing `add_r16_rm16()` to use wrapped VEX arithmetic (`r16 + rm16`) instead of a raw `Binop(...)` removed the `f14` raw-lift failures in the bounded scan
- Current optional-sample nuance:
  - `tests/test_x86_16_cod_samples.py` now skips two old `output_Od_Gs.COD` tests if that optional file is not present in the current workspace
- For medium-model `.EXE` decompilation, prefer the new bounded far-call helper flow over widening the CFG region blindly:
  - `collect_direct_far_call_targets()` is good for quick inspection and tests
  - `extend_cfg_for_far_calls()` is the current best way to improve user-visible entry-function decompilation without triggering unrelated unsupported code paths
  - current stable real targets discovered in `IMOD.EXE` entry startup code include `0x111A`, `0x121E`, `0x1380`, and `0x161F`
  - current honest limitation: this improves recovered C and `Function.get_call_target()`, but it does not yet suppress decompiler warnings about unknown calling conventions or `callee None`
- For user-facing CLI work, prefer making failures visible instead of silent:
  - print a short per-function status
  - include first-block asm when decompilation fails or returns no code
  - cap the number of printed functions with `--max-functions` to keep output readable on real binaries
- Current small rotate nuance:
  - byte `ror` now lifts and real binaries like `snake.exe` no longer crash on missing `ror_rm8`
  - the compare-style regression currently locks in the correct data result, but not the full flags behavior yet
- Recent whole-tree-friendly lifter fixes:
  - `instr16.py` now registers the missing 8-bit ALU opcode families (`0x00/02/04`, `0x08/0A/0C`, `0x10/12/14`, `0x18/1A/1C`, `0x20/22/24`, `0x28/2A/2C`, `0x30/32/34`, `0x38/3A/3C`)
  - `instr_base.py` now implements `adc_al_imm8`, `sbb_rm8_r8`, `sbb_r8_rm8`, and `sbb_al_imm8`
  - `instr16.py` `sbb_rm16_imm8()` now widens both the signed imm8 and CF before subtracting
  - `div_dx_ax_rm16()` no longer crashes body analysis on the old missing `EXP_DE` attribute path
  - `instr16.py` `add_r16_rm16()` now uses wrapped arithmetic instead of a raw `Binop(...)`, which fixed the segmented-memory `_GetCatHeading` timeout
- Prefer relocation-free `.COD` helpers first. A fast scan for functions with no `e8 00 00` or `9a 00 00 00 00` usually finds the highest-value regressions quickly.
- Not every relocation-free helper is a good decompilation oracle. Tiny DGROUP/global-store wrappers can decompile into raw `ds * 16 + offset` stores with no useful symbol recovery. Current example: `CARR.COD` `_SetDLC` was easy to lift but not worth keeping as a human-facing decompilation regression.
- Use `.COD` in two modes:
  - decompilation regression when the recovered C stays bounded and preserves stable constants or operators
  - block-lift regression when full decompilation is too slow or too noisy, but a real block still exercises a missing opcode, loop, or segmented access
- Prefer the table-driven style in `tests/test_x86_16_cod_samples.py` when adding new cases:
  - put the original C fragment and expected anchors in `DecompCase` / `BlockLiftCase`
  - keep one parametric test per mode instead of adding another one-off test function
- Good current `f14` seeds:
  - decompilation-friendly: `MONOPRIN.COD` `_mset_pos`, `NHORZ.COD` `_ChangeWeather`, `PLANES3.COD` `_Ready5`, `COCKPIT.COD` `_LookDown`, `COCKPIT.COD` `_LookUp`, `BILLASM.COD` `_MousePOS`
  - block-lift-friendly: `OVL.COD` `_dig_load_overlay`, `COCKPIT.COD` `_ConfigCrts`, `CARR.COD` `_InBox`
- Good current `x16_samples` block-prefix seed:
  - `ISOD.COD` `query_interrupts` prefix from `0x35` to `0x4e`, which keeps the setup for `inregs.h.ah = 0x30; int86(0x21, &inregs, &outregs);` while avoiding the unresolved relocation on the call itself
- Good current `cod/default` simple body seed:
  - `MAX.COD` `_max` body from `0x4e` onward, which skips the unresolved `__chkstk` prologue call and keeps the source-intent-rich `if (x > y) return x; return y;` compare/return body
