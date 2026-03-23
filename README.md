# Inertia Decompiler

Inertia decompiler provides support for decompiling 16-bit x86 real mode binaries using the angr framework, with custom agents for architecture, lifting, and simulation.

## TODO
- Unreal mode support

## Requirements
You will need:
1. [angr-platforms](https://github.com/xor2003/angr-platforms)
2. [patched angr](https://github.com/xor2003/angr)

Install dependencies via `pip install -r requirements.txt` and run `python setup.py install` in the angr_platforms directory.

## Usage

For basic decompilation of a 16-bit x86 binary (e.g., raw bytes or COM file), use the blob backend:

```python
import angr

# Example with raw bytes (MOV AX,1; ADD AX,2; RET)
binary = b'\xb8\x01\x00\x05\x02\x00\xc3'
p = angr.Project(binary, backend='blob', arch='X86_16')
cfg = p.analyses.CFG()
decomp = p.analyses.Decompiler(target_addr=0x0)
print(decomp.code)
# Output:
# AX = 1;
# AX += 2;
# return;
```

For a COM file (e.g., simple.com):
```python
import angr

p = angr.Project('angr_platforms/test_programs/x86_16/simple.com', backend='blob', arch='X86_16')
cfg = p.analyses.CFG()
decomp = p.analyses.Decompiler(target_addr=0x0)
print(decomp.code)
```

Note: Use `backend='blob'` for raw binaries or COM files without headers. The custom X86_16 agents handle lifting to VEX IR for supported instructions (ADD, SUB, MOV reg-reg, JMP short/near, RET).

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
