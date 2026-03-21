# Agents in angr-platforms

## Overview

Decompiler for 16-bit x86 real mode based on angr.
angr_platforms - patched to support x86 16-bit.
angr_platforms/angr_platforms/X86_16 helps to convert x86 16-bit binary into VEX IR, and use angr as decompiler.
venv/ have patched "angr" to support x86 16-bit which need to be moved upstream.

The `angr-platforms` project is a collection of VEX lifters that enhance the [angr](https://angr.io) binary analysis framework. These agents enable support for non-standard architectures, virtual machines, and esoteric languages by providing modular implementations of key angr subsystems:

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

#### VEX IR Lifting
Recent improvements include IRSB generation in [`lift_86_16.py`](angr_platforms/angr_platforms/X86_16/lift_86_16.py), instr16.py.

The VEX lifter supports a segment model for 16-bit real mode, handling CS shifts (<<4) for memory addressing in Load/Store operations. Use the existing lifter in /home/xor/vextest/angr_platforms/angr_platforms/X86_16 for decompilation without Capstone fallback.

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

## Tutorials

- [Part 1: Basics](angr_platforms/tutorial/1_basics.md) – angr lifecycle and components.
- Subsequent parts cover arch, loader, lifter, engine, SimOS, and analysis.

## Contributing

Add new agents by implementing and registering classes (e.g., subclass `Arch`, `CLEBackend`, `Lifter`, `SimEngine`, `SimOS`). See [BrainFuck](angr_platforms/angr_platforms/bf/) as an example. WIP branches for incomplete platforms.

For issues or maintenance, consider angr's pcode alternatives.

## Current x86-16 Status

### Recent progress

- The active top-level `venv` was upgraded to upstream angr `9.2.205` and related packages.
- Direct edits that previously existed inside `venv/` were backed up before the upgrade under:
  - `backups/venv_angr_stack_2026-03-20/README.md`
  - `backups/venv_angr_stack_2026-03-20/patched_files_manifest.json`
  - `backups/venv_angr_stack_2026-03-20/patches/python3.12-combined.patch`
- A helper to re-export those saved patches lives at:
  - `angr_platforms/scripts/export_saved_angr_patches.py`
- Some of the old patched-angr behavior has already been moved into repo-managed compatibility shims in:
  - `angr_platforms/angr_platforms/X86_16/__init__.py`

### Important x86-16 test files

- `angr_platforms/tests/test_x86_16_smoketest.py`
- `angr_platforms/tests/test_x86_16_cod_samples.py`
- `angr_platforms/tests/test_x86_16_dos_mz_loader.py`
- `angr_platforms/tests/test_x86_16_sample_matrix.py`
- `angr_platforms/tests/test_x86_16_runtime_samples.py`
- `angr_platforms/tests/test_x86_16_compare_semantics.py`

### Current known-good focused test command

Run from `/home/xor/vextest/angr_platforms`:

```bash
../venv/bin/python -m pytest -q \
  tests/test_x86_16_smoketest.py \
  tests/test_x86_16_cod_samples.py \
  tests/test_x86_16_dos_mz_loader.py \
  tests/test_x86_16_sample_matrix.py \
  tests/test_x86_16_runtime_samples.py
```

Expected status as of 2026-03-20:
- `65 passed`

### Focused lint/type-check scope

- `pyproject.toml` now targets `ruff` and `mypy` primarily at:
  - `angr_platforms/X86_16/*.py`
  - the `tests/test_x86_16*.py` files
  - `tests/conftest.py`
- This is intentional: it keeps lint/type work centered on the x86-16 lifter/decompiler surface we are actively enhancing instead of the whole historical repo.
- Current local nuance:
  - the repo `venv` still does not have `ruff` or `mypy` installed, so `../venv/bin/python -m ruff ...` and `../venv/bin/python -m mypy` currently fail with `No module named ...`

### Recent BIOS `.COD` fix

- The former BIOS `.COD` `xfail` in `tests/test_x86_16_cod_samples.py` was fixed.
- Root cause:
  - segmented non-`SS` memory accesses in `access.py` still routed through synthetic `0xff0xx` helper-call trampolines
  - 16-bit ModRM address construction in `exec.py` still built raw `pyvex.Binop/Unop` nodes containing `VexValue` wrappers
- Fixes applied:
  - `angr_platforms/angr_platforms/X86_16/access.py` now uses direct real-mode linear-address load/store logic for segmented accesses
  - `angr_platforms/angr_platforms/X86_16/exec.py` now builds 16-bit ModRM addresses with `VexValue` arithmetic instead of raw malformed expressions
- Current behavior:
  - the BIOS sample now lifts, builds CFG, and decompiles without hanging
  - the decompiler still does not recover the source perfectly, but it does recover the `0x417` BIOS data-area store and is now stable enough for a passing regression

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
    - `.EXE` entry decompilation now uses a bounded recovery window by default, which makes it much less CPU/RAM hungry
    - `.COM` entry decompilation now infers a small linear code region first, so tiny DOS stubs like `ICOMDO.COM` decompile instead of immediately walking into trailing strings
    - resource guardrails were added in the CLI: `--timeout`, `--window`, and `--max-memory-mb`
    - the remaining nuance is quality, not basic usability: `.COM` output is still rough and call targets may remain unnamed
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
- Prefer moving remaining 16-bit support out of patched `venv/` behavior and into repo-managed code or upstreamable patches.
- Keep using `.COD` files as a decompilation-quality oracle whenever possible.
- Good next targets:
  - extend real-binary coverage beyond entry-block loading
  - run/decompile more of the sample matrix end-to-end, not just entry or tiny runtime paths
  - sample-matrix decompilation currently gets farther, but still needs more real-code instruction coverage beyond the new `stos*`, `lods*`, `scas*`, `lds`, and `les` support
  - add stronger semantic checks for interrupt-heavy samples, especially BIOS data-area interactions such as `0x417`
  - improve decompilation quality for the BIOS `.COD` sample now that it no longer crashes
  - keep improving user-facing names/docs for BIOS Data Area symbols such as `0x417` (`0x40:0x17`, keyboard flag byte 0)

### Tips And Tricks For Next Agents

- Prefer relocation-free `.COD` helpers first. A fast scan for functions with no `e8 00 00` or `9a 00 00 00 00` usually finds the highest-value regressions quickly.
- Use `.COD` in two modes:
  - decompilation regression when the recovered C stays bounded and preserves stable constants or operators
  - block-lift regression when full decompilation is too slow or too noisy, but a real block still exercises a missing opcode, loop, or segmented access
- Good current `f14` seeds:
  - decompilation-friendly: `MONOPRIN.COD` `_mset_pos`, `NHORZ.COD` `_ChangeWeather`, `PLANES3.COD` `_Ready5`, `COCKPIT.COD` `_LookDown`, `COCKPIT.COD` `_LookUp`, `BILLASM.COD` `_MousePOS`
  - block-lift-friendly: `OVL.COD` `_dig_load_overlay`, `COCKPIT.COD` `_ConfigCrts`
- When probing new real samples, start with a 4-5 second alarm-bounded single-function blob analysis before trying whole-program CFG. This avoids the RAM/CPU blowups the user complained about.
- If a real sample exposes a missing opcode, add the smallest compare-style semantic regression in `tests/test_x86_16_compare_semantics.py` when upstream x86 VEX has an equivalent encoding.
- If the data result matches but the flags still diverge, it is still worth landing the narrower regression and documenting the remaining flag gap explicitly. Current example: `sar al, 1`.
- If the equivalent upstream compare is awkward or absent, prefer a real `.COD` regression in `tests/test_x86_16_cod_samples.py` over adding a brittle synthetic test.
- For loop or array-copy helpers, block-level VEX checks are often more stable than decompiler-text checks. Useful anchors in `irsb._pp_str()` are:
  - `Shl16` for scaled indices
  - absolute DGROUP offsets like `0x0222`
  - `LDle:I16` / `STle`
  - loop-bound constants like `0x0008`
- For source-backed decompilation assertions, prefer stable tokens from the original source:
  - constants like `8150`, `500`, `125`, `1000`
  - stride constants like `46` and `18`
  - UI/layout constants like `50`, `27`, `25`, `39`, `150`, `138`, `136`, and `139`
  - simple behavioral anchors like `* 2` for `MouseX = x << 1`
  - operators like `% 80` and `% 25`
  - `return`
- Make tests readable for humans, not just protective for the lifter:
  - include a short original-C fragment in the assertion message when possible
  - for decompilation regressions, fail with both the expected source fragment and the recovered C text
  - for block-lift regressions, fail with both the expected source fragment and the recovered IRSB text
- When branch recovery is still ugly, constant-rich helpers are often better regression targets than predicate-heavy helpers. Current example: `COCKPIT.COD` `_LookDown` is a better decompilation oracle than `CARR.COD` `_InBox`.
- Avoid asserting on variable names in decompiler output. They still drift a lot on x86-16 and create low-value churn.
- The first `unicornlib.so` warning is expected in many local probes and is not the bug unless the actual lift/decompile fails afterwards.
