# Inertia Decompiler

Inertia decompiler provides support for decompiling 16-bit x86 real mode binaries using the angr framework, with custom agents for architecture, lifting, and simulation.

## Project overview

Inertia is an angr-based decompiler focused on readable, evidence-driven C for real-mode x86 binaries.

The project priorities are:

- correctness first
- readability second
- recompilable output where practical

The project is not aiming to become a transpiler.

## Decompiler Shape

The current x86-16 decompiler is organized around the recovery pipeline:

`IR -> Alias model -> Widening -> Traits -> Types -> Rewrite`

Recent work made two parts explicit:

- `control-flow structuring` now has its own stage instead of living inside late cleanup.
- `confidence` and `assumption` reporting now travel through scan and milestone outputs so the decompiler can say what is recovered, what is uncertain, and what is still unresolved.

## x86-16 platform map

The main x86-16 implementation lives under [`angr_platforms/angr_platforms/X86_16`](/home/xor/vextest/angr_platforms/angr_platforms/X86_16).

Key modules:

- Arch: [`arch_86_16.py`](/home/xor/vextest/angr_platforms/angr_platforms/X86_16/arch_86_16.py)
- Lifter: [`lift_86_16.py`](/home/xor/vextest/angr_platforms/angr_platforms/X86_16/lift_86_16.py)
- Instructions: [`instr_base.py`](/home/xor/vextest/angr_platforms/angr_platforms/X86_16/instr_base.py), [`instr16.py`](/home/xor/vextest/angr_platforms/angr_platforms/X86_16/instr16.py)
- Runtime/core: [`emulator.py`](/home/xor/vextest/angr_platforms/angr_platforms/X86_16/emulator.py), [`processor.py`](/home/xor/vextest/angr_platforms/angr_platforms/X86_16/processor.py)
- SimOS: [`simos_86_16.py`](/home/xor/vextest/angr_platforms/angr_platforms/X86_16/simos_86_16.py)
- Hardware helpers: [`memory.py`](/home/xor/vextest/angr_platforms/angr_platforms/X86_16/memory.py), [`io.py`](/home/xor/vextest/angr_platforms/angr_platforms/X86_16/io.py), [`interrupt.py`](/home/xor/vextest/angr_platforms/angr_platforms/X86_16/interrupt.py)

AIL lifting and decompilation use the in-tree x86-16 platform; this is the main supported path for the real-mode work in this repo.

Quick smoke example:

```python
import angr
import angr_platforms.X86_16

binary = b'\xb8\x01\x00\x05\x02\x00\xc3'  # MOV AX,1; ADD AX,2; RET
p = angr.Project(binary, backend="blob", arch="X86_16")
cfg = p.analyses.CFG()
decomp = p.analyses.Decompiler(target_addr=0x0)
print(decomp.code)
```

## TODO
- Unreal mode support

## Requirements
You will need:
1. [angr-platforms](https://github.com/xor2003/angr-platforms)
2. [patched angr](https://github.com/xor2003/angr)

Use a fresh Python virtual environment. The current checked setup is working
with Python 3.14.x. The package metadata supports Python 3.10+, but the
recommended path for this repo is to keep the project isolated in `.venv`.

From a fresh clone:

```bash
git submodule update --init --recursive
python3.14 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e ./angr_platforms[test]
```

If you already have a working `.venv`, re-run the last two commands after a
submodule update so the root environment and `angr_platforms` stay in sync.

Quick verification:

```bash
python -m pytest -q tests/test_x86_16_smoketest.py tests/test_x86_16_cod_samples.py
```

## Usage

For a COM file (e.g., `simple.com`), import the x86-16 platform once before creating the project:
```python
import angr
import angr_platforms.X86_16  # registers the custom x86-16 platform

project = angr.Project(
    "angr_platforms/test_programs/x86_16/simple.com",
    main_opts={"backend": "blob", "arch": "X86_16"},
    auto_load_libs=False,
    simos="DOS",
)
cfg = project.analyses.CFGFast(start_at_entry=False, function_starts=[0], normalize=True)
func = cfg.functions[0]
decomp = project.analyses.Decompiler(func, cfg=cfg)
print(decomp.codegen.text)
```

For raw blobs, use `angr.load_shellcode(...)` with the x86-16 architecture object:

```python
import angr
import angr_platforms.X86_16  # registers the custom x86-16 platform
from angr_platforms.X86_16.arch_86_16 import Arch86_16

binary = b'\xb8\x01\x00\x05\x02\x00\xc3'
project = angr.load_shellcode(
    binary,
    arch=Arch86_16(),
    start_offset=0x1000,
    load_address=0x1000,
    selfmodifying_code=False,
    rebase_granularity=0x1000,
)
cfg = project.analyses.CFGFast(normalize=True)
func = cfg.functions[0x1000]
decomp = project.analyses.Decompiler(func, cfg=cfg)
print(decomp.codegen.text)
```

Note: import `angr_platforms.X86_16` before constructing the project so the custom agents are registered. For COM files or other headerless binaries that you want to load from a file path, use `main_opts={"backend": "blob", "arch": "X86_16"}`. For raw blobs, prefer `angr.load_shellcode(...)` as shown above.

For legacy script usage:
```bash
./decompile.py test.bin
```

## Project docs and current status

Main docs:

- [`PLAN.md`](/home/xor/vextest/PLAN.md)
- [`angr_platforms/docs/dream_decompiler_execution_plan.md`](/home/xor/vextest/angr_platforms/docs/dream_decompiler_execution_plan.md)
- [`angr_platforms/docs/x86_16_80286_real_mode_coverage.md`](/home/xor/vextest/angr_platforms/docs/x86_16_80286_real_mode_coverage.md)
- [`angr_platforms/docs/x86_16_mnemonic_coverage.md`](/home/xor/vextest/angr_platforms/docs/x86_16_mnemonic_coverage.md)
- [`angr_platforms/docs/x86_16_reference_priority.md`](/home/xor/vextest/angr_platforms/docs/x86_16_reference_priority.md)

Focused x86-16 tests:

- [`angr_platforms/tests/test_x86_16_smoketest.py`](/home/xor/vextest/angr_platforms/tests/test_x86_16_smoketest.py)
- [`angr_platforms/tests/test_x86_16_cod_samples.py`](/home/xor/vextest/angr_platforms/tests/test_x86_16_cod_samples.py)
- [`angr_platforms/tests/test_x86_16_dos_mz_loader.py`](/home/xor/vextest/angr_platforms/tests/test_x86_16_dos_mz_loader.py)
- [`angr_platforms/tests/test_x86_16_sample_matrix.py`](/home/xor/vextest/angr_platforms/tests/test_x86_16_sample_matrix.py)
- [`angr_platforms/tests/test_x86_16_runtime_samples.py`](/home/xor/vextest/angr_platforms/tests/test_x86_16_runtime_samples.py)
- [`angr_platforms/tests/test_x86_16_compare_semantics.py`](/home/xor/vextest/angr_platforms/tests/test_x86_16_compare_semantics.py)
- [`angr_platforms/tests/test_x86_16_cli.py`](/home/xor/vextest/angr_platforms/tests/test_x86_16_cli.py)

Focused commands:

```bash
cd /home/xor/vextest/angr_platforms && ../.venv/bin/python -m pytest -q tests/test_x86_16_smoketest.py tests/test_x86_16_cod_samples.py tests/test_x86_16_dos_mz_loader.py tests/test_x86_16_sample_matrix.py tests/test_x86_16_runtime_samples.py
cd /home/xor/vextest/angr_platforms && ../.venv/bin/python scripts/scan_cod_dir.py ../cod --mode scan-safe --timeout-sec 5 --max-memory-mb 1024
```


## x86-16 Quick Start

This repo includes an in-tree real-mode DOS sample corpus under `x16_samples/`.

- Decompile a DOS executable directly from the repo root with:
  - `./decompile.py your_binary.exe`
- Decompile a `.COM` sample the same way:
  - `./decompile.py your_binary.com`
- For raw blobs, use:
  - `./decompile.py --blob your_binary.bin`
- If recovery is slow, pass a larger timeout or a concrete function start:
  - `./decompile.py your_binary.exe --timeout 60`
  - `./decompile.py your_binary.exe --addr 0x1146`
- To keep analysis bounded on large or awkward binaries, you can also tune:
  - `./decompile.py your_binary.exe --window 0x400`
  - `./decompile.py your_binary.exe --max-memory-mb 1024`

- Build or rebuild the sample matrix with `./scripts/build_x16_samples.sh`
- Run the focused x86-16 regression suite with:
  - `../.venv/bin/python -m pytest -q tests/test_x86_16_smoketest.py tests/test_x86_16_cod_samples.py tests/test_x86_16_dos_mz_loader.py tests/test_x86_16_sample_matrix.py`
- Run just the real-binary corpus coverage with:
  - `../.venv/bin/python -m pytest -q tests/test_x86_16_sample_matrix.py`

The sample rebuild uses the DOS toolchain from `/home/xor/games/f15se2-re` by default. If your toolchain checkout lives somewhere else, set `X16_TOOLCHAIN_ROOT=/path/to/f15se2-re`.

For repository operating rules and architecture constraints, see [`AGENTS.md`](/home/xor/vextest/AGENTS.md). For harness behavior and knobs, see [`meta_harness/README.md`](/home/xor/vextest/meta_harness/README.md).
