/* loading: START.EXE */
[dbg] build_project: path=START.EXE suffix=.exe force_blob=False
[dbg] DOS MZ load base=0x10000
[dbg] project built: arch=86_16 entry=0x15542
/* recovering functions... */
[dbg] recover_cfg: entry=0x15542 base_addr=0x1000 window=0x200 binary=START.EXE
[dbg] calling CFGFast (non-COM path)
/* Whole-binary catalog recovery failed; attempting bounded entry-window recovery. */
[dbg] skipping 0xfe020 int20: SimProcedure (DOS helper)
[dbg] skipping 0xfe030 dos_get_version: SimProcedure (DOS helper)
[dbg] build_project: path=/home/xor/vextest/START.EXE suffix=.exe force_blob=False
[dbg] explicit DOS MZ load failed at 0x10000: _AnalysisTimeout
[dbg] project built: arch=86_16 entry=0x6542
[dbg] build_project: path=/home/xor/vextest/START.EXE suffix=.exe force_blob=False
[dbg] DOS MZ load base=0x10000
[dbg] project built: arch=86_16 entry=0x15542
[dbg] build_project: path=/home/xor/vextest/START.EXE suffix=.exe force_blob=False
[dbg] DOS MZ load base=0x10000
[dbg] project built: arch=86_16 entry=0x15542
[dbg] build_project: path=/home/xor/vextest/START.EXE suffix=.exe force_blob=False
[dbg] DOS MZ load base=0x10000
[dbg] project built: arch=86_16 entry=0x15542
[dbg] build_project: path=/home/xor/vextest/START.EXE suffix=.exe force_blob=False
[dbg] DOS MZ load base=0x10000
[dbg] project built: arch=86_16 entry=0x15542
[dbg] build_project: path=/home/xor/vextest/START.EXE suffix=.exe force_blob=False
[dbg] DOS MZ load base=0x10000
[dbg] project built: arch=86_16 entry=0x15542
[dbg] build_project: path=/home/xor/vextest/START.EXE suffix=.exe force_blob=False
[dbg] DOS MZ load base=0x10000
[dbg] project built: arch=86_16 entry=0x15542
[dbg] build_project: path=/home/xor/vextest/START.EXE suffix=.exe force_blob=False
[dbg] DOS MZ load base=0x10000
[dbg] project built: arch=86_16 entry=0x15542
[dbg] build_project: path=/home/xor/vextest/START.EXE suffix=.exe force_blob=False
[dbg] DOS MZ load base=0x10000
[dbg] project built: arch=86_16 entry=0x15542
/* seeded EXE catalog recovered 6 additional function(s). */
/* binary: START.EXE */
/* arch: 86_16 */
/* entry: 0x15542 */
/* functions recovered: 7 */
/* parallel function decompilation: disabled (RAM pressure or single function) */
[dbg] function complexity for 0x15542 _start: blocks=3, bytes=10
[dbg] decompile_function: addr=0x15542 name=_start
[dbg] Decompiler returned for 0x15542
[dbg] decompilation time for 0x15542 _start: 12.58s

/* == function 0x15542 _start == */
/* -- c -- */
int get_dos_version(void);
int dos_int21(void);

void _start(void)
{
    char al;  // al

    al = get_dos_version();
    if (al - 2)
        goto LABEL_0x554c;
    dos_int20_terminate();
}
[dbg] function complexity for 0x15472 sub_15472: blocks=2, bytes=13
[dbg] decompile_function: addr=0x15472 name=sub_15472
[dbg] function 0x15472 not normalized, normalizing...
[dbg] Decompiler returned for 0x15472
[dbg] decompilation time for 0x15472 sub_15472: 1.46s

/* == function 0x15472 sub_15472 == */
-- empty --
Decompiler did not produce code.
-- asm fallback --
0x15472: push bp
0x15473: mov bp, sp
0x15475: mov ax, word ptr [bp + 8]
0x15478: cmp word ptr [bp + 4], ax
0x1547b: jle 0x1547f
[dbg] function complexity for 0x156b8 sub_156b8: blocks=3, bytes=23
[dbg] decompile_function: addr=0x156b8 name=sub_156b8
[dbg] function 0x156b8 not normalized, normalizing...
[dbg] Decompiler returned for 0x156b8
[dbg] decompilation time for 0x156b8 sub_156b8: 3.87s

/* == function 0x156b8 sub_156b8 == */
-- empty --
Decompiler did not produce code.
-- asm fallback --
0x156b8: push bp
0x156b9: mov bp, sp
0x156bb: mov si, 0x4586
0x156be: mov di, 0x4586
0x156c1: call 0x15741
[dbg] function complexity for 0x15764 sub_15764: blocks=2, bytes=23
[dbg] decompile_function: addr=0x15764 name=sub_15764
[dbg] function 0x15764 not normalized, normalizing...
[dbg] Decompiler returned for 0x15764
[dbg] decompilation time for 0x15764 sub_15764: 7.58s

/* == function 0x15764 sub_15764 == */
-- empty --
Decompiler did not produce code.
-- asm fallback --
0x15764: push bp
0x15765: mov bp, sp
0x15767: sub sp, 0x10
0x1576a: push di
0x1576b: push si
0x1576c: mov si, word ptr [bp + 4]
0x1576f: mov di, 0xffff
0x15772: test byte ptr [si + 6], 0x83
0x15776: jne 0x1577b
[dbg] function complexity for 0x1531c sub_1531c: blocks=1, bytes=17
[dbg] decompile_function: addr=0x1531c name=sub_1531c
[dbg] function 0x1531c not normalized, normalizing...
[dbg] Decompiler returned for 0x1531c
[dbg] decompilation time for 0x1531c sub_1531c: 14.09s

/* == function 0x1531c sub_1531c == */
-- empty --
Decompiler did not produce code.
-- asm fallback --
0x1531c: push bp
0x1531d: mov bp, sp
0x1531f: sub sp, 4
0x15322: les bx, ptr [0x4604]
0x15326: mov ax, word ptr es:[bx + 0x38]
0x1532a: jmp 0x153f2
[dbg] function complexity for 0x15268 sub_15268: blocks=1, bytes=25
[dbg] decompile_function: addr=0x15268 name=sub_15268
[dbg] function 0x15268 not normalized, normalizing...
[dbg] Decompiler returned for 0x15268
[dbg] decompilation time for 0x15268 sub_15268: 16.96s

/* == function 0x15268 sub_15268 == */
-- empty --
Decompiler did not produce code.
-- asm fallback --
0x15268: push bp
0x15269: mov bp, sp
0x1526b: mov ax, word ptr [0x77f2]
0x1526e: mov dx, word ptr [0x77f4]
0x15272: add ax, 0x7a
0x15275: mov word ptr [0x457c], ax
0x15278: mov word ptr [0x457e], dx
0x1527c: mov ax, 1
0x1527f: jmp 0x15281
[dbg] function complexity for 0x1581e sub_1581e: blocks=4, bytes=31
[dbg] decompile_function: addr=0x1581e name=sub_1581e
[dbg] function 0x1581e not normalized, normalizing...
[dbg] Decompiler returned for 0x1581e
[dbg] decompilation time for 0x1581e sub_1581e: 39.57s

/* == function 0x1581e sub_1581e == */
-- empty --
Decompiler did not produce code.
-- asm fallback --
0x1581e: push bp
0x1581f: mov bp, sp
0x15821: sub sp, 2
0x15824: push si
0x15825: call 0x162e2

summary: decompiled 1/7 shown functions
summary: 6 functions fell back to asm/details
