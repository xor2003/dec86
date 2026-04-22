/* loading: /home/xor/ida77/egame.exe */
[dbg] build_project: path=/home/xor/ida77/egame.exe suffix=.exe force_blob=False
[dbg] DOS MZ load base=0x10000
[dbg] project built: arch=86_16 entry=0x1e432
[dbg] loaded sidecar metadata: format=ida_map+ida_lst+ida_idc+ida_inc+mzre_map code_labels=1012 data_labels=3180 structs=10
/* recovering functions... */
/* binary: /home/xor/ida77/egame.exe */
/* arch: 86_16 */
/* entry: 0x1e432 */
/* functions recovered: 1012 */
/* sidecar catalog detected 1012 functions; showing first 3 by default for responsiveness. Use --max-functions to change the cap. */
/* parallel function decompilation: disabled (RAM pressure or single function) */
[dbg] function complexity for 0x1e432 start: blocks=3, bytes=10
[dbg] decompile_function: addr=0x1e432 name=start
[dbg] function 0x1e432 not normalized, normalizing...
[dbg] Decompiler returned for 0x1e432
[dbg] decompilation time for 0x1e432 start: 4.65s
WARNING  | 2026-04-05 15:53:57,476 | angr.project   | Address 0xfe030 is not hooked
WARNING  | 2026-04-05 15:53:57,476 | angr.project   | Address 0xfe020 is not hooked

/* == function 0x1e432 start == */
/* -- c -- */
int get_dos_version(void);
int dos_int21(void);

void start(void)
{
    char al;  // al

    al = get_dos_version();
    if (al - 2)
        goto LABEL_0xe43c;
    dos_int20_terminate();
}
[dbg] function complexity for 0x1e4c6 cintDIV: blocks=1, bytes=19
[dbg] decompile_function: addr=0x1e4c6 name=cintDIV
[dbg] function 0x1e4c6 not normalized, normalizing...
[dbg] Decompiler returned for 0x1e4c6
[dbg] decompilation time for 0x1e4c6 cintDIV: 1.37s

/* == function 0x1e4c6 cintDIV == */
[dbg] function complexity for 0x1e4c6 cintDIV: blocks=1, bytes=15
[dbg] decompile_function: addr=0x1e4c6 name=cintDIV
[dbg] function 0x1e4c6 not normalized, normalizing...
[dbg] Decompiler returned for 0x1e4c6
[dbg] decompilation time for 0x1e4c6 cintDIV: 0.22s
/* -- c (sidecar slice fallback) -- */

void cintDIV(void)
{
    *((char *)24888) = 168;
    *((char *)24889) = 229;
}

/* == function 0x10010 main == */
-- timeout --
Timed out while recovering main at 0x10010.
-- asm fallback --
0x10010: push bp
0x10011: mov bp, sp
0x10013: sub sp, 6
0x10016: mov word ptr [bp - 2], 0
0x1001b: mov word ptr [bp - 4], 0x4f0
0x10020: les bx, ptr [bp - 4]
0x10023: mov ax, word ptr es:[bx]
0x10026: mov word ptr [0x9df8], ax
0x10029: mov word ptr [0x9df6], 0
0x1002f: mov ax, word ptr es:[bx]
0x10032: mov word ptr [0x6742], ax
0x10035: mov word ptr [0x6740], 0x120e
0x1003b: les bx, ptr [0x9df6]
0x1003f: push word ptr es:[bx + 0x1a]
0x10043: call 0x10688
0x10046: add sp, 2
0x10049: les bx, ptr [0x9df6]
0x1004d: push word ptr es:[bx + 0x1e]
0x10051: call 0x10688
0x10054: add sp, 2
0x10057: les bx, ptr [0x9df6]
0x1005b: push word ptr es:[bx + 0x1c]
0x1005f: call 0x10688
0x10062: add sp, 2
0x10065: les bx, ptr [0x9df6]
0x10069: mov al, byte ptr es:[bx + 0x24]
0x1006d: mov byte ptr [0x8c32], al
0x10070: cmp word ptr es:[bx + 0x78], 1
0x10075: sbb ax, ax
0x10077: neg ax
0x10079: mov word ptr [0x86], ax
0x1007c: call 0x13bec
0x1007f: les bx, ptr [0x9df6]
0x10083: cmp word ptr es:[bx + 0x72], 1
0x10088: jne 0x1009d
0x1008a: mov ax, bx
0x1008c: mov dx, es
0x1008e: add ax, 0x48
0x10091: push dx
0x10092: push ax
0x10093: lcall 0x21a7, 0xcbe
0x10098: add sp, 4
0x1009b: jmp 0x100a5
0x1009d: mov al, 0x80
0x1009f: mov byte ptr [0x56e5], al
0x100a2: mov byte ptr [0x56e4], al
0x100a5: call 0x1029a
0x100a8: lcall 0x328b, 0xefa
0x100ad: les bx, ptr [0x9df6]
0x100b1: push word ptr es:[bx + 0x24]
0x100b5: lcall 0x328b, 0x1058
0x100ba: add sp, 2
0x100bd: les bx, ptr [0x6740]
0x100c1: cmp word ptr es:[bx + 0x38], 2
0x100c6: jae 0x100d6
0x100c8: mov ax, 0xc
0x100cb: push ax
0x100cc: lcall 0x328b, 0xfef
0x100d1: add sp, 2
0x100d4: jmp 0x100e2
0x100d6: mov ax, 0x10
0x100d9: push ax
0x100da: lcall 0x328b, 0xfef
0x100df: add sp, 2
0x100e2: les bx, ptr [0x9df6]
0x100e6: mov ax, word ptr es:[bx + 0x20]
0x100ea: mov word ptr [0xa004], ax
0x100ed: lcall 0x21a7, 0xe
0x100f2: call 0x10147
0x100f5: call 0x10211
0x100f8: les bx, ptr [0x9df6]
0x100fc: cmp word ptr es:[bx + 0x72], 1
0x10101: jne 0x10114
0x10103: mov ax, bx
0x10105: mov dx, es
0x10107: add ax, 0x48
0x1010a: push dx
0x1010b: push ax
0x1010c: lcall 0x21a7, 0xcaa
0x10111: add sp, 4
0x10114: call 0x13c0f
0x10117: cmp byte ptr [0x84], 0
0x1011c: jne 0x10137
0x1011e: mov byte ptr [0x96e3], 0
0x10123: mov byte ptr [0x96e2], 3
0x10128: mov ax, 0x96e2
0x1012b: push ax
0x1012c: push ax
0x1012d: mov ax, 0x10
0x10130: push ax
0x10131: call 0xea82
0x10134: add sp, 6
0x10137: mov al, byte ptr [0x84]
0x1013a: sub ah, ah
0x1013c: push ax
0x1013d: call 0xe5a8
0x10140: add sp, 2
0x10143: mov sp, bp
0x10145: pop bp
0x10146: ret

summary: decompiled 2/3 shown functions
summary: 1 functions fell back to asm/details
