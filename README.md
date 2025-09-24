# Decompiler for X86 16-bit

This project provides support for decompiling 16-bit x86 real mode binaries using the angr framework, with custom agents for architecture, lifting, and simulation.

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

See [AGENTS.md](AGENTS.md) for more details on supported platforms and agents.
