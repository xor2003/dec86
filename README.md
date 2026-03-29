# Inertia Decompiler

Inertia decompiler provides support for decompiling 16-bit x86 real mode binaries using the angr framework, with custom agents for architecture, lifting, and simulation.

## TODO
- Unreal mode support

## Requirements
You will need:
1. [angr-platforms](https://github.com/xor2003/angr-platforms)
2. [patched angr](https://github.com/xor2003/angr)

Install dependencies via `pip install -r requirements.txt` and then install the local `angr_platforms` package with:

```bash
cd angr_platforms
python -m pip install .
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

The same pattern works for raw blobs when you wrap the bytes in `io.BytesIO` and use `main_opts={"backend": "blob", "arch": "X86_16"}`.

```python
import angr
import io
import angr_platforms.X86_16  # registers the custom x86-16 platform

binary = b'\xb8\x01\x00\x05\x02\x00\xc3'
project = angr.Project(io.BytesIO(binary), auto_load_libs=False, main_opts={"backend": "blob", "arch": "X86_16"})
cfg = project.analyses.CFGFast(start_at_entry=False, function_starts=[0], normalize=True)
func = cfg.functions[0]
decomp = project.analyses.Decompiler(func, cfg=cfg)
print(decomp.codegen.text)
```

Note: Use `main_opts={"backend": "blob", "arch": "X86_16"}` for raw binaries or COM files without headers, and import `angr_platforms.X86_16` before constructing the project so the custom agents are registered.

For legacy script usage:
```bash
./decompile.py test.bin
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
  - `../venv/bin/python -m pytest -q tests/test_x86_16_smoketest.py tests/test_x86_16_cod_samples.py tests/test_x86_16_dos_mz_loader.py tests/test_x86_16_sample_matrix.py`
- Run just the real-binary corpus coverage with:
  - `../venv/bin/python -m pytest -q tests/test_x86_16_sample_matrix.py`

The sample rebuild uses the DOS toolchain from `/home/xor/games/f15se2-re` by default. If your toolchain checkout lives somewhere else, set `X16_TOOLCHAIN_ROOT=/path/to/f15se2-re`.

See [AGENTS.md](AGENTS.md) for more details on supported platforms and agents.
