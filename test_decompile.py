#!/usr/bin/env python3
import subprocess
import sys

# Run the decompile script
result = subprocess.run([sys.executable, 'decompile.py', 'test2.bin'], capture_output=True, text=True, cwd='/home/xor/vextest')
print(f"Exit code: {result.returncode}")
print(f"STDOUT: {result.stdout}")
if result.stderr:
    print(f"STDERR: {result.stderr}")

if result.returncode == 0:
    print("PASS: Script ran without error")
else:
    print("FAIL: Script failed")