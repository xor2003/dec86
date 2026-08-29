;;; Segment 0800 (0800:0000)
0800:0000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................

;; main: 0800:0010
main proc
	push	bp
	mov	bp,sp
	mov	ax,0h
	call	1222h
	push	di
	push	si
	mov	ax,2Bh
	push	ax
	nop
	push	cs
	call	2A29h
	add	sp,2h
	mov	[0BA2h],ax
	mov	ax,0h
	push	ax
	nop
	push	cs
	call	2B5Eh
	add	sp,2h
	mov	ax,0h
	push	ax
	nop
	push	cs
	call	2BC0h
	add	sp,2h
	call	0554h
	call	005Dh
	call	02CCh
	mov	ax,0FFFFh
	push	ax
	nop
	push	cs
	call	294Fh
	add	sp,2h
	pop	si
	pop	di
	mov	sp,bp
	pop	bp
	ret

;; fn0800_005D: 0800:005D
;;   Called from:
;;     0800:0045 (in main)
;;     0800:03E8 (in fn0800_02CC)
;;     0800:0412 (in fn0800_02CC)
;;     0800:0424 (in fn0800_02CC)
fn0800_005D proc
	nop
	nop
	nop
	push	bp
	mov	bp,sp
	mov	ax,12h
	call	1222h
	push	di
	push	si
	mov	ax,0Fh
	push	ax
	nop
	push	cs
	call	2B24h
	add	sp,2h
	sub	ax,ax
	push	ax
	push	ax
	nop
	push	cs
	call	2B3Eh
	add	sp,4h
	mov	ax,[0160h]
	add	ax,2h
	push	ax
	mov	ax,23h
	push	ax
	mov	ax,2Dh
	push	ax
	mov	ax,1h
	push	ax
	call	01DBh
	add	sp,8h
	mov	word ptr [bp-2h],0h
	jmp	00A7h

l0800_00A4:
	inc	word ptr [bp-2h]

l0800_00A7:
	mov	ax,[0160h]
	cmp	[bp-2h],ax
	jl	00B2h

l0800_00AF:
	jmp	00DAh

l0800_00B2:
	mov	ax,30h
	push	ax
	mov	ax,[bp-2h]
	add	ax,2h
	push	ax
	nop
	push	cs
	call	28E4h
	add	sp,4h
	mov	bx,[bp-2h]
	shl	bx,1h
	push	ds
	push	word ptr [bx+136h]
	nop
	push	cs
	call	2756h
	add	sp,4h
	jmp	00A4h

l0800_00DA:
	cmp	word ptr [0B46h],0h
	jnz	00E4h

l0800_00E1:
	jmp	00F5h

l0800_00E4:
	mov	ax,162h
	push	ax
	lea	ax,[bp-12h]
	push	ax
	call	123Ah
	add	sp,4h
	jmp	0103h

l0800_00F5:
	mov	ax,166h
	push	ax
	lea	ax,[bp-12h]
	push	ax
	call	123Ah
	add	sp,4h

l0800_0103:
	mov	ax,3Eh
	push	ax
	mov	ax,[0160h]
	sub	ax,7h
	push	ax
	nop
	push	cs
	call	28E4h
	add	sp,4h
	lea	ax,[bp-12h]
	push	ss
	push	ax
	nop
	push	cs
	call	2756h
	add	sp,4h
	mov	ax,1Eh
	mov	dx,0h
	push	dx
	push	ax
	push	word ptr [0134h]
	push	word ptr [0132h]
	call	143Ah
	push	dx
	push	ax
	mov	ax,16Ah
	push	ax
	lea	ax,[bp-12h]
	push	ax
	call	12BAh
	add	sp,8h
	mov	ax,3Eh
	push	ax
	mov	ax,[0160h]
	sub	ax,5h
	push	ax
	nop
	push	cs
	call	28E4h
	add	sp,4h
	lea	ax,[bp-12h]
	push	ss
	push	ax
	nop
	push	cs
	call	2756h
	add	sp,4h
	mov	ax,170h
	push	ax
	lea	ax,[bp-12h]
	push	ax
	call	123Ah
	add	sp,4h
	cmp	word ptr [0132h],384h
	jz	017Fh

l0800_017C:
	jmp	01A9h

l0800_017F:
	cmp	word ptr [0134h],0h
	jz	0189h

l0800_0186:
	jmp	01A9h

l0800_0189:
	mov	ax,30h
	push	ax
	mov	ax,[0160h]
	sub	ax,4h
	push	ax
	nop
	push	cs
	call	28E4h
	add	sp,4h
	lea	ax,[bp-12h]
	push	ss
	push	ax
	nop
	push	cs
	call	2756h
	add	sp,4h

l0800_01A9:
	mov	ax,[0134h]
	or	ax,[0132h]
	jz	01B5h

l0800_01B2:
	jmp	01D5h

l0800_01B5:
	mov	ax,30h
	push	ax
	mov	ax,[0160h]
	sub	ax,3h
	push	ax
	nop
	push	cs
	call	28E4h
	add	sp,4h
	lea	ax,[bp-12h]
	push	ss
	push	ax
	nop
	push	cs
	call	2756h
	add	sp,4h

l0800_01D5:
	pop	si
	pop	di
	mov	sp,bp
	pop	bp
	ret

;; fn0800_01DB: 0800:01DB
;;   Called from:
;;     0800:0096 (in fn0800_005D)
fn0800_01DB proc
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	push	bp
	mov	bp,sp
	mov	ax,52h
	call	1222h
	push	di
	push	si
	push	word ptr [bp+8h]
	mov	ax,0CDh
	push	ax
	lea	ax,[bp-52h]
	push	ax
	call	13D4h
	add	sp,6h
	mov	byte ptr [bp-52h],0C9h
	mov	si,[bp+8h]
	mov	byte ptr [bp+si-53h],0BBh
	mov	si,[bp+8h]
	mov	byte ptr [bp+si-52h],0h
	push	word ptr [bp+6h]
	push	word ptr [bp+4h]
	nop
	push	cs
	call	28E4h
	add	sp,4h
	lea	ax,[bp-52h]
	push	ss
	push	ax
	nop
	push	cs
	call	2756h
	add	sp,4h
	push	word ptr [bp+8h]
	mov	ax,20h
	push	ax
	lea	ax,[bp-52h]
	push	ax
	call	13D4h
	add	sp,6h
	mov	byte ptr [bp-52h],0BAh
	mov	si,[bp+8h]
	mov	byte ptr [bp+si-53h],0BAh
	mov	ax,[bp+4h]
	inc	ax
	mov	[bp-2h],ax
	jmp	0262h

l0800_025F:
	inc	word ptr [bp-2h]

l0800_0262:
	mov	ax,[bp+0Ah]
	cmp	[bp-2h],ax
	jle	026Dh

l0800_026A:
	jmp	028Bh

l0800_026D:
	push	word ptr [bp+6h]
	push	word ptr [bp-2h]
	nop
	push	cs
	call	28E4h
	add	sp,4h
	lea	ax,[bp-52h]
	push	ss
	push	ax
	nop
	push	cs
	call	2756h
	add	sp,4h
	jmp	025Fh

l0800_028B:
	push	word ptr [bp+8h]
	mov	ax,0CDh
	push	ax
	lea	ax,[bp-52h]
	push	ax
	call	13D4h
	add	sp,6h
	mov	byte ptr [bp-52h],0C8h
	mov	si,[bp+8h]
	mov	byte ptr [bp+si-53h],0BCh
	push	word ptr [bp+6h]
	mov	ax,[bp+0Ah]
	add	ax,[bp+4h]
	push	ax
	nop
	push	cs
	call	28E4h
	add	sp,4h
	lea	ax,[bp-52h]
	push	ss
	push	ax
	nop
	push	cs
	call	2756h
	add	sp,4h
	pop	si
	pop	di
	mov	sp,bp
	pop	bp
	ret

;; fn0800_02CC: 0800:02CC
;;   Called from:
;;     0800:0048 (in main)
fn0800_02CC proc
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	push	bp
	mov	bp,sp
	mov	ax,2h
	call	1222h
	push	di
	push	si

l0800_02EB:
	mov	ax,0h
	mov	[0BAAh],ax
	mov	[0BA4h],ax
	mov	ax,4Bh
	push	ax
	mov	ax,[0160h]
	inc	ax
	push	ax
	nop
	push	cs
	call	28E4h
	add	sp,4h
	mov	ax,1h
	push	ax
	nop
	push	cs
	call	2BC0h
	add	sp,2h
	call	1292h
	mov	[bp-2h],al
	mov	ax,0h
	push	ax
	nop
	push	cs
	call	2BC0h
	add	sp,2h
	mov	al,[bp-2h]
	cbw
	push	ax
	call	1278h
	add	sp,2h
	jmp	0433h

l0800_0331:
	mov	word ptr [0BACh],0h
	call	0672h
	call	07E7h
	mov	ax,0h
	push	ax
	call	0491h
	add	sp,2h
	jmp	0488h

l0800_034A:
	mov	word ptr [0BACh],1h
	call	0672h
	call	08C0h
	mov	ax,0h
	push	ax
	call	0491h
	add	sp,2h
	jmp	0488h

l0800_0363:
	mov	word ptr [0BACh],2h
	call	0672h
	call	095Bh
	mov	ax,0h
	push	ax
	call	0491h
	add	sp,2h
	jmp	0488h

l0800_037C:
	mov	word ptr [0BACh],3h
	call	0672h
	call	0B2Ch
	mov	ax,0h
	push	ax
	call	0491h
	add	sp,2h
	jmp	0488h

l0800_0395:
	mov	word ptr [0BACh],4h
	call	0672h
	call	0BF4h
	mov	ax,0h
	push	ax
	call	0491h
	add	sp,2h
	jmp	0488h

l0800_03AE:
	mov	word ptr [0BACh],5h
	call	0672h
	push	word ptr [0BA2h]
	mov	ax,0h
	push	ax
	call	0CD4h
	add	sp,4h
	mov	ax,0h
	push	ax
	call	0491h
	add	sp,2h
	jmp	0488h

l0800_03D2:
	mov	ax,[0134h]
	or	ax,[0132h]
	jnz	03DEh

l0800_03DB:
	jmp	03E8h

l0800_03DE:
	sub	word ptr [0132h],1Eh
	sbb	word ptr [0134h],0h

l0800_03E8:
	call	005Dh
	jmp	0488h

l0800_03EE:
	cmp	word ptr [0134h],0h
	jle	03F8h

l0800_03F5:
	jmp	0412h

l0800_03F8:
	jge	03FDh

l0800_03FA:
	jmp	0408h

l0800_03FD:
	cmp	word ptr [0132h],384h
	jbe	0408h

l0800_0405:
	jmp	0412h

l0800_0408:
	add	word ptr [0132h],1Eh
	adc	word ptr [0134h],0h

l0800_0412:
	call	005Dh
	jmp	0488h

l0800_0418:
	cmp	word ptr [0B46h],1h
	sbb	ax,ax
	neg	ax
	mov	[0B46h],ax
	call	005Dh
	jmp	0488h

l0800_042A:
	jmp	048Bh

l0800_042D:
	jmp	0488h
0800:0430 E9 55 00                                        .U.

l0800_0433:
	cmp	ax,45h
	jnz	043Bh

l0800_0438:
	jmp	037Ch

l0800_043B:
	jle	0440h

l0800_043D:
	jmp	0462h

l0800_0440:
	sub	ax,1Bh
	jnz	0448h

l0800_0445:
	jmp	042Ah

l0800_0448:
	sub	ax,21h
	jnz	0450h

l0800_044D:
	jmp	03EEh

l0800_0450:
	dec	ax
	dec	ax
	jnz	0457h

l0800_0454:
	jmp	03D2h

l0800_0457:
	sub	ax,4h
	jnz	045Fh

l0800_045C:
	jmp	034Ah

l0800_045F:
	jmp	042Dh

l0800_0462:
	sub	ax,48h
	jnz	046Ah

l0800_0467:
	jmp	0363h

l0800_046A:
	dec	ax
	jnz	0470h

l0800_046D:
	jmp	0331h

l0800_0470:
	sub	ax,8h
	jnz	0478h

l0800_0475:
	jmp	03AEh

l0800_0478:
	dec	ax
	dec	ax
	jnz	047Fh

l0800_047C:
	jmp	0395h

l0800_047F:
	dec	ax
	jnz	0485h

l0800_0482:
	jmp	0418h

l0800_0485:
	jmp	042Dh

l0800_0488:
	jmp	02EBh

l0800_048B:
	pop	si
	pop	di
	mov	sp,bp
	pop	bp
	ret

;; fn0800_0491: 0800:0491
;;   Called from:
;;     0800:0341 (in fn0800_02CC)
;;     0800:035A (in fn0800_02CC)
;;     0800:0373 (in fn0800_02CC)
;;     0800:038C (in fn0800_02CC)
;;     0800:03A5 (in fn0800_02CC)
;;     0800:03C9 (in fn0800_02CC)
;;     0800:0788 (in fn0800_075B)
;;     0800:088A (in fn0800_07E7)
;;     0800:08B1 (in fn0800_07E7)
;;     0800:0BB3 (in fn0800_0B2C)
fn0800_0491 proc
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	push	bp
	mov	bp,sp
	mov	ax,50h
	call	1222h
	push	di
	push	si
	mov	ax,0Fh
	push	ax
	nop
	push	cs
	call	2B24h
	add	sp,2h
	call	137Eh
	mov	[0B48h],ax
	mov	[0B4Ah],dx
	push	word ptr [0BAAh]
	push	word ptr [0BA4h]
	mov	ax,3E8h
	mov	dx,0h
	push	dx
	push	ax
	mov	ax,[0B48h]
	mov	dx,[0B4Ah]
	sub	ax,[0BA6h]
	sbb	dx,[0BA8h]
	push	dx
	push	ax
	call	143Ah
	push	dx
	push	ax
	mov	ax,17Dh
	push	ax
	lea	ax,[bp-50h]
	push	ax
	call	12BAh
	add	sp,0Ch
	mov	ax,3Bh
	push	ax
	mov	ax,[0BACh]
	add	ax,7h
	push	ax
	nop
	push	cs
	call	28E4h
	add	sp,4h
	lea	ax,[bp-50h]
	push	ss
	push	ax
	nop
	push	cs
	call	2756h
	add	sp,4h
	cmp	word ptr [0B46h],0h
	jnz	0517h

l0800_0514:
	jmp	0540h

l0800_0517:
	mov	ax,4Bh
	push	ax
	mov	ax,3Ch
	imul	word ptr [bp+4h]
	push	ax
	call	0E5Dh
	add	sp,4h
	mov	ax,[0132h]
	mov	dx,[0134h]
	sub	ax,4Bh
	sbb	dx,0h
	push	dx
	push	ax
	call	0F18h
	add	sp,4h
	jmp	054Eh

l0800_0540:
	push	word ptr [0134h]
	push	word ptr [0132h]
	call	0F18h
	add	sp,4h

l0800_054E:
	pop	si
	pop	di
	mov	sp,bp
	pop	bp
	ret

;; fn0800_0554: 0800:0554
;;   Called from:
;;     0800:0042 (in main)
fn0800_0554 proc
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	push	bp
	mov	bp,sp
	mov	ax,76h
	call	1222h
	push	di
	push	si
	mov	ax,0h
	push	ax
	call	132Ch
	add	sp,2h
	push	ax
	call	1402h
	add	sp,2h
	mov	word ptr [0B46h],1h
	mov	word ptr [0132h],1Eh
	mov	word ptr [0134h],0h
	lea	ax,[bp-70h]
	push	ss
	push	ax
	nop
	push	cs
	call	2AC8h
	add	sp,4h
	cmp	word ptr [bp-5Eh],1h
	jnz	05A4h

l0800_05A1:
	jmp	05B6h

l0800_05A4:
	cmp	word ptr [bp-62h],2h
	jnz	05ADh

l0800_05AA:
	jmp	05B6h

l0800_05AD:
	cmp	word ptr [bp-62h],0h
	jz	05B6h

l0800_05B3:
	jmp	05BEh

l0800_05B6:
	mov	word ptr [bp-74h],1h
	jmp	05C3h

l0800_05BE:
	mov	word ptr [bp-74h],0Fh

l0800_05C3:
	mov	word ptr [bp-2h],0h
	jmp	05CEh

l0800_05CB:
	inc	word ptr [bp-2h]

l0800_05CE:
	mov	ax,[bp-2h]
	cmp	[0BA2h],ax
	jg	05DAh

l0800_05D7:
	jmp	05E9h

l0800_05DA:
	mov	ax,[bp-2h]
	inc	ax
	mov	si,[bp-2h]
	shl	si,1h
	mov	[bp+si-5Ah],ax
	jmp	05CBh

l0800_05E9:
	mov	ax,[0BA2h]
	dec	ax
	mov	[bp-4h],ax
	mov	word ptr [bp-2h],0h
	jmp	05FBh

l0800_05F8:
	inc	word ptr [bp-2h]

l0800_05FB:
	mov	ax,[bp-2h]
	cmp	[0BA2h],ax
	jg	0607h

l0800_0604:
	jmp	0669h

l0800_0607:
	call	1414h
	mov	cx,[bp-4h]
	inc	cx
	cwd
	idiv	cx
	mov	[bp-76h],dx
	mov	si,[bp-76h]
	shl	si,1h
	mov	ax,[bp+si-5Ah]
	mov	[bp-72h],ax
	mov	si,[bp-4h]
	shl	si,1h
	mov	ax,[bp+si-5Ah]
	mov	si,[bp-76h]
	shl	si,1h
	mov	[bp+si-5Ah],ax
	dec	word ptr [bp-4h]
	mov	al,[bp-72h]
	mov	bx,[bp-2h]
	shl	bx,1h
	mov	[bx+8F0h],al
	cmp	word ptr [bp-74h],1h
	jz	0647h

l0800_0644:
	jmp	0654h

l0800_0647:
	mov	bx,[bp-2h]
	shl	bx,1h
	mov	byte ptr [bx+8F1h],7h
	jmp	0666h

l0800_0654:
	mov	ax,[bp-72h]
	cwd
	idiv	word ptr [bp-74h]
	inc	dl
	mov	bx,[bp-2h]
	shl	bx,1h
	mov	[bx+8F1h],dl

l0800_0666:
	jmp	05F8h

l0800_0669:
	call	0672h
	pop	si
	pop	di
	mov	sp,bp
	pop	bp
	ret

;; fn0800_0672: 0800:0672
;;   Called from:
;;     0800:0337 (in fn0800_02CC)
;;     0800:0350 (in fn0800_02CC)
;;     0800:0369 (in fn0800_02CC)
;;     0800:0382 (in fn0800_02CC)
;;     0800:039B (in fn0800_02CC)
;;     0800:03B4 (in fn0800_02CC)
;;     0800:0669 (in fn0800_0554)
fn0800_0672 proc
	nop
	nop
	nop
	nop
	nop
	nop
	push	bp
	mov	bp,sp
	mov	ax,2h
	call	1222h
	push	di
	push	si
	call	137Eh
	mov	[0BA6h],ax
	mov	[0BA8h],dx
	mov	word ptr [bp-2h],0h
	jmp	0698h

l0800_0695:
	inc	word ptr [bp-2h]

l0800_0698:
	mov	ax,[bp-2h]
	cmp	[0BA2h],ax
	jg	06A4h

l0800_06A1:
	jmp	06C2h

l0800_06A4:
	mov	bx,[bp-2h]
	shl	bx,1h
	mov	ax,[bx+8F0h]
	mov	bx,[bp-2h]
	shl	bx,1h
	mov	[bx+0B4Ch],ax
	push	word ptr [bp-2h]
	call	06C8h
	add	sp,2h
	jmp	0695h

l0800_06C2:
	pop	si
	pop	di
	mov	sp,bp
	pop	bp
	ret

;; fn0800_06C8: 0800:06C8
;;   Called from:
;;     0800:06B9 (in fn0800_0672)
;;     0800:0776 (in fn0800_075B)
;;     0800:077F (in fn0800_075B)
;;     0800:0881 (in fn0800_07E7)
;;     0800:08A8 (in fn0800_07E7)
fn0800_06C8 proc
	push	bp
	mov	bp,sp
	mov	ax,2Eh
	call	1222h
	push	di
	push	si
	mov	bx,[bp+4h]
	shl	bx,1h
	mov	al,[bx+0B4Ch]
	cbw
	push	ax
	mov	ax,0DFh
	push	ax
	lea	ax,[bp-2Ch]
	push	ax
	call	13D4h
	add	sp,6h
	mov	bx,[bp+4h]
	shl	bx,1h
	mov	al,[bx+0B4Ch]
	cbw
	sub	ax,[0BA2h]
	neg	ax
	mov	[bp-2Eh],ax
	push	word ptr [bp-2Eh]
	mov	ax,20h
	push	ax
	mov	bx,[bp+4h]
	shl	bx,1h
	mov	al,[bx+0B4Ch]
	cbw
	mov	si,ax
	lea	ax,[bp+si-2Ch]
	push	ax
	call	13D4h
	add	sp,6h
	mov	si,[0BA2h]
	mov	byte ptr [bp+si-2Ch],0h
	mov	bx,[bp+4h]
	shl	bx,1h
	mov	al,[bx+0B4Dh]
	cbw
	push	ax
	nop
	push	cs
	call	2B24h
	add	sp,2h
	mov	ax,0h
	push	ax
	mov	ax,[bp+4h]
	inc	ax
	push	ax
	nop
	push	cs
	call	28E4h
	add	sp,4h
	lea	ax,[bp-2Ch]
	push	ss
	push	ax
	nop
	push	cs
	call	2756h
	add	sp,4h
	pop	si
	pop	di
	mov	sp,bp
	pop	bp
	ret

;; fn0800_075B: 0800:075B
;;   Called from:
;;     0800:0937 (in fn0800_08C0)
;;     0800:09CE (in fn0800_095B)
;;     0800:0A46 (in fn0800_09E8)
;;     0800:0B11 (in fn0800_0A61)
;;     0800:0BE5 (in fn0800_0B2C)
;;     0800:0C9E (in fn0800_0BF4)
;;     0800:0D3B (in fn0800_0CD4)
;;     0800:0DD4 (in fn0800_0CD4)
;;     0800:0E03 (in fn0800_0CD4)
fn0800_075B proc
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	push	bp
	mov	bp,sp
	mov	ax,0h
	call	1222h
	push	di
	push	si
	push	word ptr [bp+4h]
	call	06C8h
	add	sp,2h
	push	word ptr [bp+6h]
	call	06C8h
	add	sp,2h
	push	word ptr [bp+4h]
	call	0491h
	add	sp,2h
	pop	si
	pop	di
	mov	sp,bp
	pop	bp
	ret

;; fn0800_0794: 0800:0794
;;   Called from:
;;     0800:0929 (in fn0800_08C0)
;;     0800:09C1 (in fn0800_095B)
;;     0800:0A3A (in fn0800_09E8)
;;     0800:0B05 (in fn0800_0A61)
;;     0800:0BD9 (in fn0800_0B2C)
;;     0800:0C8E (in fn0800_0BF4)
;;     0800:0D2F (in fn0800_0CD4)
;;     0800:0DC8 (in fn0800_0CD4)
;;     0800:0DF7 (in fn0800_0CD4)
fn0800_0794 proc
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	push	bp
	mov	bp,sp
	mov	ax,2h
	call	1222h
	push	di
	push	si
	inc	word ptr [0BA4h]
	mov	bx,[bp+4h]
	mov	ax,[bx]
	mov	[bp-2h],ax
	mov	bx,[bp+6h]
	mov	ax,[bx]
	mov	bx,[bp+4h]
	mov	[bx],ax
	mov	ax,[bp-2h]
	mov	bx,[bp+6h]
	mov	[bx],ax
	pop	si
	pop	di
	mov	sp,bp
	pop	bp
	ret

;; fn0800_07E7: 0800:07E7
;;   Called from:
;;     0800:033A (in fn0800_02CC)
fn0800_07E7 proc
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	push	bp
	mov	bp,sp
	mov	ax,8h
	call	1222h
	push	di
	push	si
	mov	word ptr [bp-2h],0h
	jmp	081Eh

l0800_081B:
	inc	word ptr [bp-2h]

l0800_081E:
	mov	ax,[bp-2h]
	cmp	[0BA2h],ax
	jg	082Ah

l0800_0827:
	jmp	08BAh

l0800_082A:
	mov	bx,[bp-2h]
	shl	bx,1h
	mov	ax,[bx+0B4Ch]
	mov	[bp-8h],ax
	mov	al,[bp-8h]
	cbw
	mov	[bp-6h],ax
	mov	ax,[bp-2h]
	mov	[bp-4h],ax
	jmp	0849h

l0800_0846:
	dec	word ptr [bp-4h]

l0800_0849:
	cmp	word ptr [bp-4h],0h
	jnz	0852h

l0800_084F:
	jmp	0899h

l0800_0852:
	inc	word ptr [0BAAh]
	mov	bx,[bp-4h]
	shl	bx,1h
	mov	al,[bx+0B4Ah]
	cbw
	cmp	ax,[bp-6h]
	jg	0868h

l0800_0865:
	jmp	0893h

l0800_0868:
	inc	word ptr [0BA4h]
	mov	bx,[bp-4h]
	shl	bx,1h
	mov	ax,[bx+0B4Ah]
	mov	bx,[bp-4h]
	shl	bx,1h
	mov	[bx+0B4Ch],ax
	push	word ptr [bp-4h]
	call	06C8h
	add	sp,2h
	push	word ptr [bp-4h]
	call	0491h
	add	sp,2h
	jmp	0896h

l0800_0893:
	jmp	0899h

l0800_0896:
	jmp	0846h

l0800_0899:
	mov	ax,[bp-8h]
	mov	bx,[bp-4h]
	shl	bx,1h
	mov	[bx+0B4Ch],ax
	push	word ptr [bp-4h]
	call	06C8h
	add	sp,2h
	push	word ptr [bp-4h]
	call	0491h
	add	sp,2h
	jmp	081Bh

l0800_08BA:
	pop	si
	pop	di
	mov	sp,bp
	pop	bp
	ret

;; fn0800_08C0: 0800:08C0
;;   Called from:
;;     0800:0353 (in fn0800_02CC)
fn0800_08C0 proc
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	push	bp
	mov	bp,sp
	mov	ax,6h
	call	1222h
	push	di
	push	si
	mov	ax,[0BA2h]
	mov	[bp-4h],ax

l0800_08E1:
	mov	word ptr [bp-6h],0h
	mov	word ptr [bp-2h],0h
	jmp	08F1h

l0800_08EE:
	inc	word ptr [bp-2h]

l0800_08F1:
	mov	ax,[bp-2h]
	cmp	[bp-4h],ax
	jg	08FCh

l0800_08F9:
	jmp	0946h

l0800_08FC:
	inc	word ptr [0BAAh]
	mov	bx,[bp-2h]
	shl	bx,1h
	mov	si,[bp-2h]
	shl	si,1h
	mov	al,[si+0B4Ch]
	cmp	[bx+0B4Eh],al
	jl	0917h

l0800_0914:
	jmp	0943h

l0800_0917:
	mov	ax,[bp-2h]
	shl	ax,1h
	add	ax,0B4Eh
	push	ax
	mov	ax,[bp-2h]
	shl	ax,1h
	add	ax,0B4Ch
	push	ax
	call	0794h
	add	sp,4h
	mov	ax,[bp-2h]
	inc	ax
	push	ax
	push	word ptr [bp-2h]
	call	075Bh
	add	sp,4h
	mov	ax,[bp-2h]
	mov	[bp-6h],ax

l0800_0943:
	jmp	08EEh

l0800_0946:
	mov	ax,[bp-6h]
	mov	[bp-4h],ax
	cmp	word ptr [bp-6h],0h
	jz	0955h

l0800_0952:
	jmp	08E1h

l0800_0955:
	pop	si
	pop	di
	mov	sp,bp
	pop	bp
	ret

;; fn0800_095B: 0800:095B
;;   Called from:
;;     0800:036C (in fn0800_02CC)
fn0800_095B proc
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	push	bp
	mov	bp,sp
	mov	ax,2h
	call	1222h
	push	di
	push	si
	mov	word ptr [bp-2h],1h
	jmp	0986h

l0800_0983:
	inc	word ptr [bp-2h]

l0800_0986:
	mov	ax,[bp-2h]
	cmp	[0BA2h],ax
	jg	0992h

l0800_098F:
	jmp	099Eh

l0800_0992:
	push	word ptr [bp-2h]
	call	09E8h
	add	sp,2h
	jmp	0983h

l0800_099E:
	mov	ax,[0BA2h]
	dec	ax
	mov	[bp-2h],ax
	jmp	09ABh

l0800_09A8:
	dec	word ptr [bp-2h]

l0800_09AB:
	cmp	word ptr [bp-2h],0h
	jg	09B4h

l0800_09B1:
	jmp	09E2h

l0800_09B4:
	mov	ax,[bp-2h]
	shl	ax,1h
	add	ax,0B4Ch
	push	ax
	mov	ax,0B4Ch
	push	ax
	call	0794h
	add	sp,4h
	push	word ptr [bp-2h]
	mov	ax,0h
	push	ax
	call	075Bh
	add	sp,4h
	mov	ax,[bp-2h]
	dec	ax
	push	ax
	call	0A61h
	add	sp,2h
	jmp	09A8h

l0800_09E2:
	pop	si
	pop	di
	mov	sp,bp
	pop	bp
	ret

;; fn0800_09E8: 0800:09E8
;;   Called from:
;;     0800:0995 (in fn0800_095B)
fn0800_09E8 proc
	push	bp
	mov	bp,sp
	mov	ax,4h
	call	1222h
	push	di
	push	si
	mov	ax,[bp+4h]
	mov	[bp-4h],ax

l0800_09F9:
	cmp	word ptr [bp-4h],0h
	jnz	0A02h

l0800_09FF:
	jmp	0A5Bh

l0800_0A02:
	mov	ax,[bp-4h]
	cwd
	sub	ax,dx
	sar	ax,1h
	mov	[bp-2h],ax
	inc	word ptr [0BAAh]
	mov	bx,[bp-4h]
	shl	bx,1h
	mov	si,[bp-2h]
	shl	si,1h
	mov	al,[si+0B4Ch]
	cmp	[bx+0B4Ch],al
	jg	0A28h

l0800_0A25:
	jmp	0A55h

l0800_0A28:
	mov	ax,[bp-4h]
	shl	ax,1h
	add	ax,0B4Ch
	push	ax
	mov	ax,[bp-2h]
	shl	ax,1h
	add	ax,0B4Ch
	push	ax
	call	0794h
	add	sp,4h
	push	word ptr [bp-4h]
	push	word ptr [bp-2h]
	call	075Bh
	add	sp,4h
	mov	ax,[bp-2h]
	mov	[bp-4h],ax
	jmp	0A58h

l0800_0A55:
	jmp	0A5Bh

l0800_0A58:
	jmp	09F9h

l0800_0A5B:
	pop	si
	pop	di
	mov	sp,bp
	pop	bp
	ret

;; fn0800_0A61: 0800:0A61
;;   Called from:
;;     0800:09D9 (in fn0800_095B)
fn0800_0A61 proc
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	push	bp
	mov	bp,sp
	mov	ax,4h
	call	1222h
	push	di
	push	si
	mov	word ptr [bp-2h],0h

l0800_0A98:
	mov	ax,[bp-2h]
	shl	ax,1h
	mov	[bp-4h],ax
	mov	ax,[bp+4h]
	cmp	[bp-4h],ax
	jg	0AABh

l0800_0AA8:
	jmp	0AAEh

l0800_0AAB:
	jmp	0B26h

l0800_0AAE:
	mov	ax,[bp-4h]
	inc	ax
	cmp	ax,[bp+4h]
	jle	0ABAh

l0800_0AB7:
	jmp	0AD8h

l0800_0ABA:
	inc	word ptr [0BAAh]
	mov	bx,[bp-4h]
	shl	bx,1h
	mov	si,[bp-4h]
	shl	si,1h
	mov	al,[si+0B4Ch]
	cmp	[bx+0B4Eh],al
	jg	0AD5h

l0800_0AD2:
	jmp	0AD8h

l0800_0AD5:
	inc	word ptr [bp-4h]

l0800_0AD8:
	inc	word ptr [0BAAh]
	mov	bx,[bp-2h]
	shl	bx,1h
	mov	si,[bp-4h]
	shl	si,1h
	mov	al,[si+0B4Ch]
	cmp	[bx+0B4Ch],al
	jl	0AF3h

l0800_0AF0:
	jmp	0B20h

l0800_0AF3:
	mov	ax,[bp-4h]
	shl	ax,1h
	add	ax,0B4Ch
	push	ax
	mov	ax,[bp-2h]
	shl	ax,1h
	add	ax,0B4Ch
	push	ax
	call	0794h
	add	sp,4h
	push	word ptr [bp-4h]
	push	word ptr [bp-2h]
	call	075Bh
	add	sp,4h
	mov	ax,[bp-4h]
	mov	[bp-2h],ax
	jmp	0B23h

l0800_0B20:
	jmp	0B26h

l0800_0B23:
	jmp	0A98h

l0800_0B26:
	pop	si
	pop	di
	mov	sp,bp
	pop	bp
	ret

;; fn0800_0B2C: 0800:0B2C
;;   Called from:
;;     0800:0385 (in fn0800_02CC)
fn0800_0B2C proc
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	push	bp
	mov	bp,sp
	mov	ax,6h
	call	1222h
	push	di
	push	si
	mov	word ptr [bp-6h],0h
	jmp	0B66h

l0800_0B63:
	inc	word ptr [bp-6h]

l0800_0B66:
	mov	ax,[bp-6h]
	cmp	[0BA2h],ax
	jg	0B72h

l0800_0B6F:
	jmp	0BEEh

l0800_0B72:
	mov	ax,[bp-6h]
	mov	[bp-4h],ax
	mov	ax,[bp-6h]
	mov	[bp-2h],ax
	jmp	0B84h

l0800_0B81:
	inc	word ptr [bp-2h]

l0800_0B84:
	mov	ax,[0BA2h]
	cmp	[bp-2h],ax
	jl	0B8Fh

l0800_0B8C:
	jmp	0BBCh

l0800_0B8F:
	inc	word ptr [0BAAh]
	mov	bx,[bp-2h]
	shl	bx,1h
	mov	si,[bp-4h]
	shl	si,1h
	mov	al,[si+0B4Ch]
	cmp	[bx+0B4Ch],al
	jl	0BAAh

l0800_0BA7:
	jmp	0BB9h

l0800_0BAA:
	mov	ax,[bp-2h]
	mov	[bp-4h],ax
	push	word ptr [bp-2h]
	call	0491h
	add	sp,2h

l0800_0BB9:
	jmp	0B81h

l0800_0BBC:
	mov	ax,[bp-6h]
	cmp	[bp-4h],ax
	jg	0BC7h

l0800_0BC4:
	jmp	0BEBh

l0800_0BC7:
	mov	ax,[bp-4h]
	shl	ax,1h
	add	ax,0B4Ch
	push	ax
	mov	ax,[bp-6h]
	shl	ax,1h
	add	ax,0B4Ch
	push	ax
	call	0794h
	add	sp,4h
	push	word ptr [bp-4h]
	push	word ptr [bp-6h]
	call	075Bh
	add	sp,4h

l0800_0BEB:
	jmp	0B63h

l0800_0BEE:
	pop	si
	pop	di
	mov	sp,bp
	pop	bp
	ret

;; fn0800_0BF4: 0800:0BF4
;;   Called from:
;;     0800:039E (in fn0800_02CC)
fn0800_0BF4 proc
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	push	bp
	mov	bp,sp
	mov	ax,8h
	call	1222h
	push	di
	push	si
	mov	ax,[0BA2h]
	cwd
	sub	ax,dx
	sar	ax,1h
	mov	[bp-2h],ax

l0800_0C2E:
	cmp	word ptr [bp-2h],0h
	jnz	0C37h

l0800_0C34:
	jmp	0CCEh

l0800_0C37:
	mov	ax,[0BA2h]
	sub	ax,[bp-2h]
	mov	[bp-6h],ax

l0800_0C40:
	mov	word ptr [bp-8h],0h
	mov	word ptr [bp-4h],0h
	jmp	0C50h

l0800_0C4D:
	inc	word ptr [bp-4h]

l0800_0C50:
	mov	ax,[bp-6h]
	cmp	[bp-4h],ax
	jle	0C5Bh

l0800_0C58:
	jmp	0CADh

l0800_0C5B:
	inc	word ptr [0BAAh]
	mov	bx,[bp-4h]
	add	bx,[bp-2h]
	shl	bx,1h
	mov	si,[bp-4h]
	shl	si,1h
	mov	al,[si+0B4Ch]
	cmp	[bx+0B4Ch],al
	jl	0C79h

l0800_0C76:
	jmp	0CAAh

l0800_0C79:
	mov	ax,[bp-4h]
	add	ax,[bp-2h]
	shl	ax,1h
	add	ax,0B4Ch
	push	ax
	mov	ax,[bp-4h]
	shl	ax,1h
	add	ax,0B4Ch
	push	ax
	call	0794h
	add	sp,4h
	mov	ax,[bp-4h]
	add	ax,[bp-2h]
	push	ax
	push	word ptr [bp-4h]
	call	075Bh
	add	sp,4h
	mov	ax,[bp-4h]
	mov	[bp-8h],ax

l0800_0CAA:
	jmp	0C4Dh

l0800_0CAD:
	mov	ax,[bp-8h]
	sub	ax,[bp-2h]
	mov	[bp-6h],ax
	cmp	word ptr [bp-8h],0h
	jz	0CBFh

l0800_0CBC:
	jmp	0C40h

l0800_0CBF:
	mov	cx,2h
	mov	ax,[bp-2h]
	cwd
	idiv	cx
	mov	[bp-2h],ax
	jmp	0C2Eh

l0800_0CCE:
	pop	si
	pop	di
	mov	sp,bp
	pop	bp
	ret

;; fn0800_0CD4: 0800:0CD4
;;   Called from:
;;     0800:03BF (in fn0800_02CC)
;;     0800:0E24 (in fn0800_0CD4)
;;     0800:0E32 (in fn0800_0CD4)
;;     0800:0E43 (in fn0800_0CD4)
;;     0800:0E51 (in fn0800_0CD4)
fn0800_0CD4 proc
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	push	bp
	mov	bp,sp
	mov	ax,6h
	call	1222h
	push	di
	push	si
	mov	ax,[bp+6h]
	cmp	[bp+4h],ax
	jl	0CF6h

l0800_0CF3:
	jmp	0E57h

l0800_0CF6:
	mov	ax,[bp+6h]
	sub	ax,[bp+4h]
	dec	ax
	jz	0D02h

l0800_0CFF:
	jmp	0D44h

l0800_0D02:
	inc	word ptr [0BAAh]
	mov	bx,[bp+4h]
	shl	bx,1h
	mov	si,[bp+6h]
	shl	si,1h
	mov	al,[si+0B4Ch]
	cmp	[bx+0B4Ch],al
	jg	0D1Dh

l0800_0D1A:
	jmp	0D41h

l0800_0D1D:
	mov	ax,[bp+6h]
	shl	ax,1h
	add	ax,0B4Ch
	push	ax
	mov	ax,[bp+4h]
	shl	ax,1h
	add	ax,0B4Ch
	push	ax
	call	0794h
	add	sp,4h
	push	word ptr [bp+6h]
	push	word ptr [bp+4h]
	call	075Bh
	add	sp,4h

l0800_0D41:
	jmp	0E57h

l0800_0D44:
	mov	bx,[bp+6h]
	shl	bx,1h
	mov	al,[bx+0B4Ch]
	cbw
	mov	[bp-4h],ax

l0800_0D51:
	mov	ax,[bp+4h]
	mov	[bp-6h],ax
	mov	ax,[bp+6h]
	mov	[bp-2h],ax
	inc	word ptr [0BAAh]

l0800_0D61:
	mov	ax,[bp-6h]
	cmp	[bp-2h],ax
	jg	0D6Ch

l0800_0D69:
	jmp	0D84h

l0800_0D6C:
	mov	bx,[bp-6h]
	shl	bx,1h
	mov	al,[bx+0B4Ch]
	cbw
	cmp	ax,[bp-4h]
	jle	0D7Eh

l0800_0D7B:
	jmp	0D84h

l0800_0D7E:
	inc	word ptr [bp-6h]
	jmp	0D61h

l0800_0D84:
	inc	word ptr [0BAAh]

l0800_0D88:
	mov	ax,[bp-6h]
	cmp	[bp-2h],ax
	jg	0D93h

l0800_0D90:
	jmp	0DABh

l0800_0D93:
	mov	bx,[bp-2h]
	shl	bx,1h
	mov	al,[bx+0B4Ch]
	cbw
	cmp	ax,[bp-4h]
	jge	0DA5h

l0800_0DA2:
	jmp	0DABh

l0800_0DA5:
	dec	word ptr [bp-2h]
	jmp	0D88h

l0800_0DAB:
	mov	ax,[bp-6h]
	cmp	[bp-2h],ax
	jg	0DB6h

l0800_0DB3:
	jmp	0DDAh

l0800_0DB6:
	mov	ax,[bp-2h]
	shl	ax,1h
	add	ax,0B4Ch
	push	ax
	mov	ax,[bp-6h]
	shl	ax,1h
	add	ax,0B4Ch
	push	ax
	call	0794h
	add	sp,4h
	push	word ptr [bp-2h]
	push	word ptr [bp-6h]
	call	075Bh
	add	sp,4h

l0800_0DDA:
	mov	ax,[bp-6h]
	cmp	[bp-2h],ax
	jle	0DE5h

l0800_0DE2:
	jmp	0D51h

l0800_0DE5:
	mov	ax,[bp+6h]
	shl	ax,1h
	add	ax,0B4Ch
	push	ax
	mov	ax,[bp-6h]
	shl	ax,1h
	add	ax,0B4Ch
	push	ax
	call	0794h
	add	sp,4h
	push	word ptr [bp+6h]
	push	word ptr [bp-6h]
	call	075Bh
	add	sp,4h
	mov	ax,[bp-6h]
	sub	ax,[bp+4h]
	mov	cx,[bp+6h]
	sub	cx,[bp-6h]
	cmp	ax,cx
	jl	0E1Ch

l0800_0E19:
	jmp	0E3Bh

l0800_0E1C:
	mov	ax,[bp-6h]
	dec	ax
	push	ax
	push	word ptr [bp+4h]
	call	0CD4h
	add	sp,4h
	push	word ptr [bp+6h]
	mov	ax,[bp-6h]
	inc	ax
	push	ax
	call	0CD4h
	add	sp,4h
	jmp	0E57h

l0800_0E3B:
	push	word ptr [bp+6h]
	mov	ax,[bp-6h]
	inc	ax
	push	ax
	call	0CD4h
	add	sp,4h
	mov	ax,[bp-6h]
	dec	ax
	push	ax
	push	word ptr [bp+4h]
	call	0CD4h
	add	sp,4h

l0800_0E57:
	pop	si
	pop	di
	mov	sp,bp
	pop	bp
	ret

;; fn0800_0E5D: 0800:0E5D
;;   Called from:
;;     0800:0522 (in fn0800_0491)
fn0800_0E5D proc
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	push	bp
	mov	bp,sp
	mov	ax,2h
	call	1222h
	push	di
	push	si
	cmp	word ptr [bp+4h],0h
	jnz	0E84h

l0800_0E81:
	jmp	0EF0h

l0800_0E84:
	cmp	word ptr [bp+6h],4Bh
	jl	0E8Dh

l0800_0E8A:
	jmp	0E92h

l0800_0E8D:
	mov	word ptr [bp+6h],4Bh

l0800_0E92:
	mov	ax,0B6h
	push	ax
	mov	ax,43h
	push	ax
	call	131Eh
	add	sp,4h
	mov	ax,[bp+4h]
	cwd
	push	dx
	push	ax
	mov	ax,34DCh
	mov	dx,12h
	push	dx
	push	ax
	call	143Ah
	mov	[bp+4h],ax
	mov	al,[bp+4h]
	cbw
	push	ax
	mov	ax,42h
	push	ax
	call	131Eh
	add	sp,4h
	mov	al,[bp+5h]
	cbw
	push	ax
	mov	ax,42h
	push	ax
	call	131Eh
	add	sp,4h
	mov	ax,61h
	push	ax
	call	1310h
	add	sp,2h
	mov	[bp-2h],ax
	mov	ax,[bp-2h]
	or	ax,3h
	push	ax
	mov	ax,61h
	push	ax
	call	131Eh
	add	sp,4h

l0800_0EF0:
	mov	ax,[bp+6h]
	cwd
	push	dx
	push	ax
	call	0F18h
	add	sp,4h
	cmp	word ptr [bp+4h],0h
	jnz	0F05h

l0800_0F02:
	jmp	0F12h

l0800_0F05:
	push	word ptr [bp-2h]
	mov	ax,61h
	push	ax
	call	131Eh
	add	sp,4h

l0800_0F12:
	pop	si
	pop	di
	mov	sp,bp
	pop	bp
	ret

;; fn0800_0F18: 0800:0F18
;;   Called from:
;;     0800:0537 (in fn0800_0491)
;;     0800:0548 (in fn0800_0491)
;;     0800:0EF6 (in fn0800_0E5D)
fn0800_0F18 proc
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	push	bp
	mov	bp,sp
	mov	ax,4h
	call	1222h
	push	di
	push	si
	call	137Eh
	add	ax,[bp+4h]
	adc	dx,[bp+6h]
	mov	[bp-4h],ax
	mov	[bp-2h],dx

l0800_0F52:
	call	137Eh
	cmp	dx,[bp-2h]
	jle	0F5Dh

l0800_0F5A:
	jmp	0F6Dh

l0800_0F5D:
	jge	0F62h

l0800_0F5F:
	jmp	0F6Ah

l0800_0F62:
	cmp	ax,[bp-4h]
	jbe	0F6Ah

l0800_0F67:
	jmp	0F6Dh

l0800_0F6A:
	jmp	0F52h

l0800_0F6D:
	pop	si
	pop	di
	mov	sp,bp
	pop	bp
	ret
0800:0F73          00 00 00 00 00 00 00 00 00 00 00 00 00    .............

;; fn0800_0F80: 0800:0F80
;;   Called from:
;;     0800:0F81 (in fn0800_0F81)
fn0800_0F80 proc
	ret

;; fn0800_0F81: 0800:0F81
;;   Called from:
;;     0800:5378 (in fn0800_5327)
;;     0800:5378 (in fn0800_3760)
fn0800_0F81 proc
	call	0F80h
	retf
0800:0F85                00 00 00 00 00 00 00 00 00 00 00      ...........

;; fn0800_0F90: 0800:0F90
;;   Called from:
;;     0800:5399 (in fn0800_5390)
fn0800_0F90 proc
	push	bx
	mov	bx,0FFFFh
	call	word ptr [063Ah]
	pop	bx
	retf
0800:0F9A                               B4 30 CD 21 3C 02           .0.!<.
0800:0FA0 73 05 33 C0 06 50 CB BF DA 0D 8B 36 02 00 2B F7 s.3..P.....6..+.
0800:0FB0 81 FE 00 10 72 03 BE 00 10 FA 8E D7 81 C4 AE 0B ....r...........
0800:0FC0 FB 73 10 16 1F E8 0C 05 33 C0 50 E8 85 07 B8 FF .s......3.P.....
0800:0FD0 4C CD 21 8B C6 B1 04 D3 E0 48 36 A3 54 02 BB 56 L.!......H6.T..V
0800:0FE0 02 36 8C 17 83 E4 FE 36 89 67 04 B8 FE FF 50 36 .6.....6.g....P6
0800:0FF0 89 67 0A F7 D0 50 36 89 67 06 36 89 67 08 36 89 .g...P6.g.6.g.6.
0800:1000 26 50 02 03 F7 89 36 02 00 8C C3 2B DE F7 DB B4 &P....6....+....
0800:1010 4A CD 21 36 8C 1E 90 02 16 07 FC BF 44 07 B9 B0 J.!6........D...
0800:1020 0B 2B CF 33 C0 F3 AA 16 1F 8B 0E 46 06 E3 02 FF .+.3.......F....
0800:1030 D1 E8 76 06 E8 E5 04 33 ED E8 48 00 16 1F FF 36 ..v....3..H....6
0800:1040 B1 02 FF 36 AF 02 FF 36 AD 02 E8 C3 EF 50 E8 01 ...6...6.....P..
0800:1050 01 C3 2E A1 81 10 8E D8 B8 03 00 36 C7 06 52 02 ...........6..R.
0800:1060 52 11                                           R.

;; fn0800_1062: 0800:1062
;;   Called from:
;;     0800:1236 (in fn0800_1222)
fn0800_1062 proc
	push	ax
	call	14D4h
	call	1753h
	cmp	word ptr ss:[0638h],0D6D6h
	jnz	1079h

l0800_1072:
	pop	ax
	push	ax
	call	word ptr ss:[063Ch]

l0800_1079:
	mov	ax,0FFh
	push	ax
	call	word ptr [0252h]
	fimul	dword ptr [di]
	add	[bx+si+3500h],bh
	int	21h
	mov	[027Ch],bx
	mov	[027Eh],es
	push	cs
	pop	ds
	mov	ax,2500h
	mov	dx,1052h
	int	21h
	push	ss
	pop	ds
	cmp	word ptr [064Ah],0h
	jz	10DAh

l0800_10A4:
	mov	[064Ch],cs
	mov	[0654h],cs
	mov	es,[0290h]
	mov	si,es:[002Ch]
	lds	ax,[064Eh]
	mov	dx,ds
	xor	bx,bx
	call	dword ptr ss:[064Ah]
	jnc	10C9h

l0800_10C4:
	push	ss
	pop	ds
	jmp	14F4h

l0800_10C9:
	lds	ax,ss:[0652h]
	mov	dx,ds
	mov	bx,3h
	call	dword ptr ss:[064Ah]
	push	ss
	pop	ds

l0800_10DA:
	mov	es,[0290h]
	mov	cx,es:[002Ch]
	jcxz	1123h

l0800_10E5:
	mov	es,cx
	xor	di,di

l0800_10E9:
	cmp	byte ptr es:[di],0h
	jz	1123h

l0800_10EF:
	mov	cx,0Dh
	mov	si,26Eh
	rep cmpsb
	jz	1104h

l0800_10F9:
	mov	cx,7FFFh
	xor	ax,ax

l0800_10FE:
	repne scasb

l0800_1100:
	jnz	1123h

l0800_1102:
	jmp	10E9h

l0800_1104:
	push	es
	push	ds
	pop	es
	pop	ds
	mov	si,di
	mov	di,299h
	mov	cl,4h

l0800_110F:
	lodsb
	sub	al,41h
	jc	1121h

l0800_1114:
	shl	al,cl
	xchg	dx,ax
	lodsb
	sub	al,41h
	jc	1121h

l0800_111C:
	or	al,dl
	stosb
	jmp	110Fh

l0800_1121:
	push	ss
	pop	ds

l0800_1123:
	mov	bx,4h

l0800_1126:
	and	byte ptr [bx+299h],0BFh
	mov	ax,4400h
	int	21h
	jc	113Ch

l0800_1132:
	test	dl,80h
	jz	113Ch

l0800_1137:
	or	byte ptr [bx+299h],40h

l0800_113C:
	dec	bx
	jns	1126h

l0800_113F:
	mov	si,630h
	mov	di,634h
	call	120Fh
	mov	si,656h
	mov	di,658h
	call	1200h
	ret
0800:1152       55 8B EC 33 C9 EB 1A 55 8B EC B9 01 00 EB   U..3...U......
0800:1160 12 55 8B EC 56 57 B9 00 01 EB 08 55 8B EC 56 57 .U..VW.....U..VW
0800:1170 B9 01 01 51 0A C9 75 1E BE E6 08 BF E6 08 E8 7F ...Q..u.........
0800:1180 00 BE 58 06 BF 5A 06 E8 76 00 81 3E 38 06 D6 D6 ..X..Z..v..>8...
0800:1190 75 04 FF 16 3E 06 BE 5A 06 BF 5A 06 E8 61 00 BE u...>..Z..Z..a..
0800:11A0 34 06 BF 38 06 E8 67 00 E8 4F 03 0B C0 74 11 58 4..8..g..O...t.X
0800:11B0 0A E4 50 75 0B 83 7E 04 00 75 05 C7 46 04 FF 00 ..Pu..~..u..F...
0800:11C0 E8 10 00 58 0A E4 75 07 8B 46 04 B4 4C CD 21 5F ...X..u..F..L.!_
0800:11D0 5E 5D C3 8B 0E 4C 06 E3 07 BB 02 00 FF 1E 4A 06 ^]...L........J.
0800:11E0 1E C5 16 7C 02 B8 00 25 CD 21 1F 80 3E BA 02 00 ...|...%.!..>...
0800:11F0 74 0D 1E A0 BB 02 C5 16 BC 02 B4 25 CD 21 1F C3 t..........%.!..

;; fn0800_1200: 0800:1200
;;   Called from:
;;     0800:114E (in fn0800_1062)
fn0800_1200 proc
	cmp	si,di
	jnc	120Eh

l0800_1204:
	dec	di
	dec	di
	mov	cx,[di]
	jcxz	1200h

l0800_120A:
	call	cx
	jmp	1200h

l0800_120E:
	ret

;; fn0800_120F: 0800:120F
;;   Called from:
;;     0800:1145 (in fn0800_1062)
fn0800_120F proc
	cmp	si,di
	jnc	1221h

l0800_1213:
	sub	di,4h
	mov	ax,[di]
	or	ax,[di+2h]
	jz	120Fh

l0800_121D:
	call	dword ptr [di]
	jmp	120Fh

l0800_1221:
	ret

;; fn0800_1222: 0800:1222
;;   Called from:
;;     0800:0016 (in main)
;;     0800:0066 (in fn0800_005D)
;;     0800:01F6 (in fn0800_01DB)
;;     0800:02E6 (in fn0800_02CC)
;;     0800:049E (in fn0800_0491)
;;     0800:0566 (in fn0800_0554)
;;     0800:067E (in fn0800_0672)
;;     0800:06CE (in fn0800_06C8)
;;     0800:076E (in fn0800_075B)
;;     0800:07BE (in fn0800_0794)
;;     0800:080E (in fn0800_07E7)
;;     0800:08D6 (in fn0800_08C0)
;;     0800:0976 (in fn0800_095B)
;;     0800:09EE (in fn0800_09E8)
;;     0800:0A8E (in fn0800_0A61)
;;     0800:0B56 (in fn0800_0B2C)
;;     0800:0C1E (in fn0800_0BF4)
;;     0800:0CE6 (in fn0800_0CD4)
;;     0800:0E76 (in fn0800_0E5D)
;;     0800:0F3E (in fn0800_0F18)
;;     0800:187E (in fn0800_1878)
;;     0800:20F8 (in fn0800_204A)
fn0800_1222 proc
	pop	cx
	mov	bx,sp
	sub	bx,ax
	jc	1233h

l0800_1229:
	cmp	bx,[02C2h]
	jc	1233h

l0800_122F:
	mov	sp,bx
	jmp	cx

l0800_1233:
	push	cx
	xor	ax,ax
	jmp	1062h
0800:1239                            00                            .

;; fn0800_123A: 0800:123A
;;   Called from:
;;     0800:00EC (in fn0800_005D)
;;     0800:00FD (in fn0800_005D)
;;     0800:016E (in fn0800_005D)
fn0800_123A proc
	push	bp
	mov	bp,sp
	mov	dx,di
	mov	bx,si
	mov	si,[bp+6h]
	mov	di,si
	mov	ax,ds
	mov	es,ax
	xor	ax,ax
	mov	cx,0FFFFh
	repne scasb
	not	cx
	mov	di,[bp+4h]
	mov	ax,di
	test	al,1h
	jz	125Eh

l0800_125C:
	movsb
	dec	cx

l0800_125E:
	shr	cx,1h
	rep movsw
	adc	cx,cx
	rep movsb
	mov	si,bx
	mov	di,dx
	pop	bp
	ret
0800:126C                                     55 8B EC 8B             U...
0800:1270 46 04 2D 20 00 5D C3 90                         F.- .]..

;; fn0800_1278: 0800:1278
;;   Called from:
;;     0800:0328 (in fn0800_02CC)
fn0800_1278 proc
	push	bp
	mov	bp,sp
	mov	bx,[bp+4h]
	test	byte ptr [bx+33Bh],2h
	jz	128Ah

l0800_1285:
	lea	ax,[bx-20h]
	jmp	128Ch

l0800_128A:
	mov	ax,bx

l0800_128C:
	pop	bp
	ret
0800:128E                                           B6 01               ..
0800:1290 EB 02                                           ..

;; fn0800_1292: 0800:1292
;;   Called from:
;;     0800:0311 (in fn0800_02CC)
fn0800_1292 proc
	mov	dh,8h
	mov	ax,[02C4h]
	or	ah,ah
	jnz	12A3h

l0800_129B:
	mov	word ptr [02C4h],0FFFFh
	jmp	12B9h

l0800_12A3:
	cmp	word ptr [0638h],0D6D6h
	jnz	12B4h

l0800_12AB:
	push	bx
	mov	bx,0FFFFh
	call	word ptr [063Ah]
	pop	bx

l0800_12B4:
	xchg	dx,ax
	int	21h
	mov	ah,0h

l0800_12B9:
	ret

;; fn0800_12BA: 0800:12BA
;;   Called from:
;;     0800:0140 (in fn0800_005D)
;;     0800:04E7 (in fn0800_0491)
fn0800_12BA proc
	push	bp
	mov	bp,sp
	sub	sp,2h
	push	di
	push	si
	mov	byte ptr [08E2h],42h
	mov	ax,[bp+4h]
	mov	[08E0h],ax
	mov	si,8DCh
	mov	[si],ax
	mov	word ptr [08DEh],7FFFh
	lea	ax,[bp+8h]
	push	ax
	push	word ptr [bp+6h]
	mov	ax,si
	push	ax
	call	1878h
	add	sp,6h
	mov	di,ax
	dec	word ptr [08DEh]
	js	12FEh

l0800_12F0:
	mov	bx,[08DCh]
	inc	word ptr [08DCh]
	mov	byte ptr [bx],0h
	jmp	1308h
0800:12FD                                        90                    .

l0800_12FE:
	push	si
	sub	ax,ax
	push	ax
	call	1788h
	add	sp,4h

l0800_1308:
	mov	ax,di
	pop	si
	pop	di
	mov	sp,bp
	pop	bp
	ret

;; fn0800_1310: 0800:1310
;;   Called from:
;;     0800:0ED6 (in fn0800_0E5D)
fn0800_1310 proc
	push	bp
	mov	bp,sp
	mov	dx,[bp+4h]
	in	al,dx
	xor	ah,ah
	mov	sp,bp
	pop	bp
	ret
0800:131D                                        00                    .

;; fn0800_131E: 0800:131E
;;   Called from:
;;     0800:0E9A (in fn0800_0E5D)
;;     0800:0EBD (in fn0800_0E5D)
;;     0800:0ECC (in fn0800_0E5D)
;;     0800:0EEA (in fn0800_0E5D)
;;     0800:0F0C (in fn0800_0E5D)
fn0800_131E proc
	push	bp
	mov	bp,sp
	mov	dx,[bp+4h]
	mov	al,[bp+6h]
	out	dx,al
	mov	ah,0h
	pop	bp
	ret

;; fn0800_132C: 0800:132C
;;   Called from:
;;     0800:056F (in fn0800_0554)
fn0800_132C proc
	push	bp
	mov	bp,sp
	push	si
	mov	ah,2Ah
	int	21h
	mov	bx,dx
	mov	si,cx
	mov	ah,2Ch
	int	21h
	mov	ah,0h
	mov	al,dh
	push	ax
	mov	al,cl
	push	ax
	mov	al,ch
	push	ax
	push	ax
	mov	ah,2Ah
	int	21h
	cmp	bx,dx
	pop	ax
	jz	1359h

l0800_1351:
	cmp	al,17h
	jnz	1359h

l0800_1355:
	mov	dx,bx
	mov	cx,si

l0800_1359:
	mov	ah,0h
	mov	al,dl
	push	ax
	mov	al,dh
	push	ax
	sub	cx,7BCh
	push	cx
	call	1E42h
	add	sp,0Ch
	cmp	word ptr [bp+4h],0h
	jz	137Ah

l0800_1372:
	mov	bx,[bp+4h]
	mov	[bx+2h],dx
	mov	[bx],ax

l0800_137A:
	pop	si
	pop	bp
	ret
0800:137D                                        00                    .

;; fn0800_137E: 0800:137E
;;   Called from:
;;     0800:04AF (in fn0800_0491)
;;     0800:0683 (in fn0800_0672)
;;     0800:0F43 (in fn0800_0F18)
;;     0800:0F52 (in fn0800_0F18)
fn0800_137E proc
	push	bp
	mov	bp,sp
	sub	sp,0Eh
	mov	word ptr [043Ch],0h
	lea	ax,[bp-0Ah]
	push	ax
	call	1D4Eh
	add	sp,2h
	mov	ax,3E8h
	cwd
	push	dx
	push	ax
	mov	ax,[bp-0Ah]
	mov	dx,[bp-8h]
	sub	ax,[02C6h]
	sbb	dx,[02C8h]
	push	dx
	push	ax
	call	1F38h
	mov	cx,ax
	mov	ax,[bp-6h]
	sub	ax,[02CAh]
	mov	bx,dx
	cwd
	add	ax,cx
	adc	dx,bx
	mov	[bp-0Eh],ax
	mov	[bp-0Ch],dx
	mov	sp,bp
	pop	bp
	ret
0800:13C7                      90 B8 C6 02 50 E8 7F 09 83        ....P....
0800:13D0 C4 02 C3 90                                     ....

;; fn0800_13D4: 0800:13D4
;;   Called from:
;;     0800:0206 (in fn0800_01DB)
;;     0800:0244 (in fn0800_01DB)
;;     0800:0296 (in fn0800_01DB)
;;     0800:06E6 (in fn0800_06C8)
;;     0800:0716 (in fn0800_06C8)
fn0800_13D4 proc
	push	bp
	mov	bp,sp
	mov	dx,di
	mov	ax,ds
	mov	es,ax
	mov	di,[bp+4h]
	mov	bx,di
	mov	cx,[bp+8h]
	jcxz	13FCh

l0800_13E7:
	mov	al,[bp+6h]
	mov	ah,al
	test	di,1h
	jz	13F4h

l0800_13F2:
	stosb
	dec	cx

l0800_13F4:
	shr	cx,1h

l0800_13F6:
	rep stosw

l0800_13F8:
	adc	cx,cx

l0800_13FA:
	rep stosb

l0800_13FC:
	mov	di,dx
	xchg	bx,ax
	pop	bp
	ret
0800:1401    00                                            .

;; fn0800_1402: 0800:1402
;;   Called from:
;;     0800:0576 (in fn0800_0554)
fn0800_1402 proc
	push	bp
	mov	bp,sp
	mov	ax,[bp+4h]
	mov	[02D0h],ax
	mov	word ptr [02D2h],0h
	pop	bp
	ret
0800:1413          90                                        .

;; fn0800_1414: 0800:1414
;;   Called from:
;;     0800:0607 (in fn0800_0554)
fn0800_1414 proc
	mov	ax,43FDh
	mov	dx,3h
	push	dx
	push	ax
	push	word ptr [02D2h]
	push	word ptr [02D0h]
	call	1F38h
	add	ax,9EC3h
	adc	dx,26h
	mov	[02D0h],ax
	mov	[02D2h],dx
	mov	ax,dx
	and	ah,7Fh
	ret

;; fn0800_143A: 0800:143A
;;   Called from:
;;     0800:0133 (in fn0800_005D)
;;     0800:04DA (in fn0800_0491)
;;     0800:0EAE (in fn0800_0E5D)
;;     0800:1D65 (in fn0800_1D4E)
fn0800_143A proc
	push	bp
	mov	bp,sp
	push	di
	push	si
	push	bx
	xor	di,di
	mov	ax,[bp+6h]
	or	ax,ax
	jge	145Ah

l0800_1449:
	inc	di
	mov	dx,[bp+4h]
	neg	ax
	neg	dx
	sbb	ax,0h
	mov	[bp+6h],ax
	mov	[bp+4h],dx

l0800_145A:
	mov	ax,[bp+0Ah]
	or	ax,ax
	jge	1472h

l0800_1461:
	inc	di
	mov	dx,[bp+8h]
	neg	ax
	neg	dx
	sbb	ax,0h
	mov	[bp+0Ah],ax
	mov	[bp+8h],dx

l0800_1472:
	or	ax,ax
	jnz	148Bh

l0800_1476:
	mov	cx,[bp+8h]
	mov	ax,[bp+6h]
	xor	dx,dx
	div	cx
	mov	bx,ax
	mov	ax,[bp+4h]
	div	cx
	mov	dx,bx
	jmp	14C3h

l0800_148B:
	mov	bx,ax
	mov	cx,[bp+8h]
	mov	dx,[bp+6h]
	mov	ax,[bp+4h]

l0800_1496:
	shr	bx,1h
	rcr	cx,1h
	shr	dx,1h
	rcr	ax,1h
	or	bx,bx
	jnz	1496h

l0800_14A2:
	div	cx
	mov	si,ax
	mul	word ptr [bp+0Ah]
	xchg	cx,ax
	mov	ax,[bp+8h]
	mul	si
	add	dx,cx
	jc	14BFh

l0800_14B3:
	cmp	dx,[bp+6h]
	ja	14BFh

l0800_14B8:
	jc	14C0h

l0800_14BA:
	cmp	ax,[bp+4h]
	jbe	14C0h

l0800_14BF:
	dec	si

l0800_14C0:
	xor	dx,dx
	xchg	si,ax

l0800_14C3:
	dec	di
	jnz	14CDh

l0800_14C6:
	neg	dx
	neg	ax
	sbb	dx,0h

l0800_14CD:
	pop	bx
	pop	si
	pop	di
	pop	bp
	ret	8h

;; fn0800_14D4: 0800:14D4
;;   Called from:
;;     0800:1063 (in fn0800_1062)
fn0800_14D4 proc
	push	bp
	mov	bp,sp
	mov	ax,0FCh
	push	ax
	call	1753h
	cmp	word ptr [02D4h],0h
	jz	14E9h

l0800_14E5:
	call	word ptr [02D4h]

l0800_14E9:
	mov	ax,0FFh
	push	ax
	call	1753h
	mov	sp,bp
	pop	bp
	ret

l0800_14F4:
	mov	ax,2h
	jmp	1062h
0800:14FA                               56 33 F6 B9 42 00           V3..B.
0800:1500 32 E4 FC AC 32 E0 E2 FB 80 F4 55 74 0D E8 C4 FF 2...2.....Ut....
0800:1510 B8 01 00 50 E8 3C 02 B8 01 00 5E C3 8F 06 D6 02 ...P.<....^.....
0800:1520 B4 30 CD 21 A3 92 02 BA 01 00 3C 02 74 29 8E 06 .0.!......<.t)..
0800:1530 90 02 26 8E 06 2C 00 8C 06 B5 02 33 C0 99 B9 00 ..&..,.....3....
0800:1540 80 33 FF F2 AE AE 75 FB 47 47 89 3E B3 02 B9 FF .3....u.GG.>....
0800:1550 FF F2 AE F7 D1 8B D1 BF 01 00 BE 81 00 8E 1E 90 ................
0800:1560 02 AC 3C 20 74 FB 3C 09 74 F7 3C 0D 74 6F 0A C0 ..< t.<.t.<.to..
0800:1570 74 6B 47 4E AC 3C 20 74 E8 3C 09 74 E4 3C 0D 74 tkGN.< t.<.t.<.t
0800:1580 5C 0A C0 74 58 3C 22 74 24 3C 5C 74 03 42 EB E4 \..tX<"t$<\t.B..
0800:1590 33 C9 41 AC 3C 5C 74 FA 3C 22 74 04 03 D1 EB D3 3.A.<\t.<"t.....
0800:15A0 8B C1 D1 E9 13 D1 A8 01 75 CA EB 01 4E AC 3C 0D ........u...N.<.
0800:15B0 74 2B 0A C0 74 27 3C 22 74 BA 3C 5C 74 03 42 EB t+..t'<"t.<\t.B.
0800:15C0 EC 33 C9 41 AC 3C 5C 74 FA 3C 22 74 04 03 D1 EB .3.A.<\t.<"t....
0800:15D0 DB 8B C1 D1 E9 13 D1 A8 01 75 D2 EB 97 16 1F 89 .........u......
0800:15E0 3E AD 02 03 D7 47 D1 E7 03 D7 42 80 E2 FE 2B E2 >....G....B...+.
0800:15F0 8B C4 A3 AF 02 8B D8 03 FB 16 07 36 89 3F 43 43 ...........6.?CC
0800:1600 C5 36 B3 02 AC AA 0A C0 75 FA 36 8E 1E 90 02 BE .6......u.6.....
0800:1610 81 00 EB 03 33 C0 AA AC 3C 20 74 FB 3C 09 74 F7 ....3...< t.<.t.
0800:1620 3C 0D 74 7C 0A C0 74 78 36 89 3F 43 43 4E AC 3C <.t|..tx6.?CCN.<
0800:1630 20 74 E1 3C 09 74 DD 3C 0D 74 62 0A C0 74 5E 3C  t.<.t.<.tb..t^<
0800:1640 22 74 27 3C 5C 74 03 AA EB E4 33 C9 41 AC 3C 5C "t'<\t....3.A.<\
0800:1650 74 FA 3C 22 74 06 B0 5C F3 AA EB D1 B0 5C D1 E9 t.<"t..\.....\..
0800:1660 F3 AA 73 06 B0 22 AA EB C5 4E AC 3C 0D 74 2E 0A ..s.."...N.<.t..
0800:1670 C0 74 2A 3C 22 74 B7 3C 5C 74 03 AA EB EC 33 C9 .t*<"t.<\t....3.
0800:1680 41 AC 3C 5C 74 FA 3C 22 74 06 B0 5C F3 AA EB D9 A.<\t.<"t..\....
0800:1690 B0 5C D1 E9 F3 AA 73 96 B0 22 AA EB CD 33 C0 AA .\....s.."...3..
0800:16A0 16 1F C7 07 00 00 FF 26 D6 02 55 8B EC 1E 8E 06 .......&..U.....
0800:16B0 90 02 26 8B 1E 2C 00 8E C3 33 C0 33 F6 33 FF B9 ..&..,...3.3.3..
0800:16C0 FF FF 0B DB 74 0E 26 80 3E 00 00 00 74 06 F2 AE ....t.&.>...t...
0800:16D0 46 AE 75 FA 8B C7 40 24 FE 46 8B FE D1 E6 B9 09 F.u...@$.F......
0800:16E0 00 E8 86 08 50 8B C6 E8 80 08 A3 B1 02 06 1E 07 ....P...........
0800:16F0 1F 8B CF 8B D8 33 F6 5F 49 E3 26 8B 04 36 3B 06 .....3._I.&..6;.
0800:1700 6E 02 75 10 51 56 57 BF 6E 02 B9 06 00 F3 A7 5F n.u.QVW.n......_
0800:1710 5E 59 74 05 26 89 3F 43 43 AC AA 0A C0 75 FA E2 ^Yt.&.?CC....u..
0800:1720 DA 26 89 0F 1F 5D C3 00                         .&...]..

;; fn0800_1728: 0800:1728
;;   Called from:
;;     0800:175A (in fn0800_1753)
fn0800_1728 proc
	push	bp
	mov	bp,sp
	push	si
	push	di
	push	ds
	pop	es
	mov	dx,[bp+4h]
	mov	si,66Ah

l0800_1735:
	lodsw
	cmp	ax,dx
	jz	174Ah

l0800_173A:
	inc	ax
	xchg	si,ax
	jz	174Ah

l0800_173E:
	xchg	di,ax
	xor	ax,ax
	mov	cx,0FFFFh
	repne scasb
	mov	si,di
	jmp	1735h

l0800_174A:
	xchg	si,ax
	pop	di
	pop	si
	mov	sp,bp
	pop	bp
	ret	2h

;; fn0800_1753: 0800:1753
;;   Called from:
;;     0800:1066 (in fn0800_1062)
;;     0800:14DB (in fn0800_14D4)
;;     0800:14ED (in fn0800_14D4)
fn0800_1753 proc
	push	bp
	mov	bp,sp
	push	di
	push	word ptr [bp+4h]
	call	1728h
	or	ax,ax
	jz	1781h

l0800_1761:
	xchg	dx,ax
	mov	di,dx
	xor	ax,ax
	mov	cx,0FFFFh
	repne scasb
	not	cx
	dec	cx
	mov	bx,2h
	cmp	word ptr [0638h],0D6D6h
	jnz	177Dh

l0800_1779:
	call	word ptr [063Ah]

l0800_177D:
	mov	ah,40h
	int	21h

l0800_1781:
	pop	di
	mov	sp,bp
	pop	bp
	ret	2h

;; fn0800_1788: 0800:1788
;;   Called from:
;;     0800:1302 (in fn0800_12BA)
fn0800_1788 proc
	push	bp
	mov	bp,sp
	push	si
	push	di
	mov	si,[bp+6h]
	mov	al,[si+6h]
	test	al,82h
	jz	17FFh

l0800_1797:
	test	al,40h
	jnz	17FFh

l0800_179B:
	mov	word ptr [si+2h],0h
	test	al,1h
	jz	17AFh

l0800_17A4:
	test	al,10h
	jz	17FFh

l0800_17A8:
	mov	cx,[si+4h]
	mov	[si],cx
	and	al,0FEh

l0800_17AF:
	or	al,2h
	and	al,0EFh
	mov	[si+6h],al
	mov	di,si
	sub	di,43Eh
	add	di,4DEh
	xor	bx,bx
	mov	bl,[si+7h]
	test	al,8h
	jnz	1815h

l0800_17C9:
	test	al,4h
	jnz	17EBh

l0800_17CD:
	test	byte ptr [di],1h
	jnz	1815h

l0800_17D2:
	cmp	si,446h
	jz	17E4h

l0800_17D8:
	cmp	si,44Eh
	jz	17E4h

l0800_17DE:
	cmp	si,45Eh
	jnz	1808h

l0800_17E4:
	test	byte ptr [bx+299h],40h
	jz	1808h

l0800_17EB:
	mov	cx,1h
	push	cx
	lea	di,[bp+4h]
	push	di
	push	bx
	call	204Ah
	add	sp,6h
	mov	cx,1h
	jmp	183Dh

l0800_17FF:
	mov	ax,0FFFFh
	or	byte ptr [si+6h],20h
	jmp	1864h

l0800_1808:
	push	bx
	push	si
	call	1F8Eh
	pop	bx
	pop	bx
	test	byte ptr [si+6h],8h
	jz	17EBh

l0800_1815:
	mov	cx,[si]
	mov	dx,[si+4h]
	sub	cx,dx
	inc	dx
	mov	[si],dx
	mov	dx,[di+2h]
	dec	dx
	mov	[si+2h],dx
	jcxz	1848h

l0800_1828:
	push	cx
	push	cx
	push	word ptr [si+4h]
	push	bx
	call	204Ah
	add	sp,6h
	pop	cx

l0800_1835:
	mov	di,[si+4h]
	mov	dx,[bp+4h]
	mov	[di],dl

l0800_183D:
	cmp	ax,cx
	jnz	17FFh

l0800_1841:
	xor	ax,ax
	mov	al,[bp+4h]
	jmp	1864h

l0800_1848:
	xor	ax,ax
	test	byte ptr [bx+299h],20h
	jz	1835h

l0800_1851:
	mov	cx,2h
	push	cx
	push	ax
	push	ax
	push	bx
	call	1FD0h
	add	sp,8h
	xor	ax,ax
	mov	cx,ax
	jmp	1835h

l0800_1864:
	pop	di
	pop	si
	pop	bp
	ret
0800:1868                         CE 18 D9 18 ED 18 21 19         ......!.
0800:1870 4D 19 55 19 7E 19 B0 19                         M.U.~...

;; fn0800_1878: 0800:1878
;;   Called from:
;;     0800:12E2 (in fn0800_12BA)
fn0800_1878 proc
	push	bp
	mov	bp,sp
	mov	ax,171h
	call	1222h
	push	si
	push	di
	xor	ax,ax
	mov	[bp-8h],ax
	mov	[bp-5h],al
	mov	si,[bp+6h]
	lodsb
	mov	[bp+6h],si
	mov	[bp-2h],al
	or	al,al
	jz	189Fh

l0800_1899:
	cmp	word ptr [bp-8h],0h
	jge	18A5h

l0800_189F:
	mov	ax,[bp-8h]
	jmp	1D47h

l0800_18A5:
	mov	bx,2D8h
	sub	al,20h
	cmp	al,58h
	ja	18B3h

l0800_18AE:
	xlat
	and	al,0Fh
	jmp	18B5h

l0800_18B3:
	mov	al,0h

l0800_18B5:
	mov	cl,3h
	shl	al,cl
	add	al,[bp-5h]
	xlat
	inc	cl
	shr	al,cl
	mov	[bp-5h],al
	cbw
	mov	bx,ax
	shl	bx,1h
	jmp	word ptr cs:[bx+1868h]
0800:18CE                                           8A 56               .V
0800:18D0 FE B9 01 00 E8 23 04 EB B2 33 C0 89 46 F0 89 46 .....#...3..F..F
0800:18E0 F6 89 46 EE 89 46 FC 48 89 46 F4 EB 9E 8A 46 FE ..F..F.H.F....F.
0800:18F0 3C 2D 75 06 80 4E FC 04 EB 91 3C 2B 75 06 80 4E <-u..N....<+u..N
0800:1900 FC 01 EB 87 3C 20 75 07 80 4E FC 02 E9 7C FF 3C ....< u..N...|.<
0800:1910 23 75 07 80 4E FC 80 E9 71 FF 80 4E FC 08 E9 6A #u..N...q..N...j
0800:1920 FF 8A 4E FE 80 F9 2A 75 0F E8 56 03 0B C0 79 17 ..N...*u..V...y.
0800:1930 F7 D8 80 4E FC 04 EB 0F 80 E9 30 32 ED 8B 46 F6 ...N......02..F.
0800:1940 BB 0A 00 F7 E3 03 C1 89 46 F6 E9 3E FF C7 46 F4 ........F..>..F.
0800:1950 00 00 E9 36 FF 8A 4E FE 80 F9 2A 75 0C E8 22 03 ...6..N...*u..".
0800:1960 0B C0 79 14 B8 FF FF EB 0F 80 E9 30 32 ED 8B 46 ..y........02..F
0800:1970 F4 BB 0A 00 F7 E3 03 C1 89 46 F4 E9 0D FF 8A 46 .........F.....F
0800:1980 FE 3C 6C 75 06 80 4E FC 10 EB 22 3C 46 75 06 80 .<lu..N..."<Fu..
0800:1990 4E FC 20 EB 18 3C 4E 75 06 80 4E FD 10 EB 0E 3C N. ..<Nu..N....<
0800:19A0 4C 75 06 80 4E FD 04 EB 04 80 4E FD 08 E9 DB FE Lu..N.....N.....
0800:19B0 8A 46 FE 3C 64 75 03 E9 8E 01 3C 69 75 03 E9 87 .F.<du....<iu...
0800:19C0 01 3C 75 75 03 E9 84 01 3C 58 75 03 E9 83 01 3C .<uu....<Xu....<
0800:19D0 78 75 03 E9 82 01 3C 6F 75 03 E9 9C 01 3C 63 74 xu....<ou....<ct
0800:19E0 1A 3C 73 74 27 3C 6E 74 51 3C 70 74 60 3C 45 74 .<st'<ntQ<pt`<Et
0800:19F0 07 3C 47 74 03 E9 BB 00 E9 B5 00 E8 84 02 8D BE .<Gt............
0800:1A00 8F FE 16 07 AA 4F B9 01 00 E9 EB 01 E8 87 02 0B .....O..........
0800:1A10 FF 75 12 8C C0 0B C0 75 0C 1E 07 BF 31 03 8B 0E .u.....u....1...
0800:1A20 37 03 E9 D2 01 57 8B 4E F4 E3 07 32 C0 F2 AE 75 7....W.N...2...u
0800:1A30 01 4F 59 2B F9 87 CF E9 BD 01 E8 59 02 8B 46 F8 .OY+.......Y..F.
0800:1A40 AB F6 46 FC 10 74 03 33 C0 AB E9 3E FE F6 46 FC ..F..t.3...>..F.
0800:1A50 30 75 05 E8 2C 02 EB 39 E8 2F 02 F6 46 FD 18 75 0u..,..9./..F..u
0800:1A60 30 C6 46 FF 07 B9 10 00 16 07 52 33 D2 8D BE 97 0.F.......R3....
0800:1A70 FE BE 04 00 E8 9F 02 B9 10 00 8D BE 92 FE 58 33 ..............X3
0800:1A80 D2 BE 04 00 E8 8F 02 C6 86 93 FE 3A B9 09 00 EB ...........:....
0800:1A90 18 C6 46 FF 07 B9 10 00 16 07 33 D2 8D BE 92 FE ..F.......3.....
0800:1AA0 BE 04 00 E8 70 02 B9 04 00 8D BE 8F FE E9 47 01 ....p.........G.
0800:1AB0 FF 46 EE 80 4E FC 40 8A 46 FE 0C 20 98 8B F0 83 .F..N.@.F.. ....
0800:1AC0 7E F4 00 7F 13 74 07 C7 46 F4 06 00 EB 0A 3D 67 ~....t..F.....=g
0800:1AD0 00 75 05 C7 46 F4 01 00 8D BE 8F FE FF 76 EE FF .u..F........v..
0800:1AE0 76 F4 56 57 FF 76 08 F6 46 FD 04 74 0A FF 16 8A v.VW.v..F..t....
0800:1AF0 05 83 46 08 0A EB 08 FF 16 80 05 83 46 08 08 83 ..F.........F...
0800:1B00 C4 0A F6 46 FC 80 74 0E 83 7E F4 00 75 08 57 FF ...F..t..~..u.W.
0800:1B10 16 86 05 83 C4 02 83 FE 67 75 0F F7 46 FC 80 00 ........gu..F...
0800:1B20 75 08 57 FF 16 82 05 83 C4 02 16 07 26 80 3D 2D u.W.........&.=-
0800:1B30 75 05 47 80 4E FD 01 B9 FF FF 57 B0 00 F2 AE 4F u.G.N.....W....O
0800:1B40 59 2B F9 87 CF E9 AF 00 80 4E FC 40 C6 46 FA 0A Y+.......N.@.F..
0800:1B50 EB 35 C6 46 FF 07 EB 04 C6 46 FF 27 F6 46 FC 80 .5.F.....F.'.F..
0800:1B60 74 11 C7 46 F0 02 00 C6 46 F2 30 B2 51 02 56 FF t..F....F.0.Q.V.
0800:1B70 88 56 F3 C6 46 FA 10 EB 0E F6 46 FC 80 74 04 80 .V..F.....F..t..
0800:1B80 4E FD 02 C6 46 FA 08 F6 46 FC 10 74 05 E8 FA 00 N...F...F..t....
0800:1B90 EB 0E E8 ED 00 F6 46 FC 40 74 03 99 EB 02 33 D2 ......F.@t....3.
0800:1BA0 F6 46 FC 40 74 0F 0B D2 7D 0B 80 4E FD 01 F7 D8 .F.@t...}..N....
0800:1BB0 83 D2 00 F7 DA 83 7E F4 00 7D 07 C7 46 F4 01 00 ......~..}..F...
0800:1BC0 EB 04 80 66 FC F7 8B D8 0B DA 75 05 C7 46 F0 00 ...f......u..F..
0800:1BD0 00 8D 7E EB 16 07 8A 4E FA 32 ED 8B 76 F4 E8 35 ..~....N.2..v..5
0800:1BE0 01 F6 46 FD 02 74 0E E3 06 26 80 3D 30 74 06 4F ..F..t...&.=0t.O
0800:1BF0 26 C6 05 30 41 EB 00 F6 46 FC 40 74 31 F6 46 FD &..0A...F.@t1.F.
0800:1C00 01 74 0B C6 46 F2 2D C7 46 F0 01 00 EB 20 F6 46 .t..F.-.F.... .F
0800:1C10 FC 01 74 0B C6 46 F2 2B C7 46 F0 01 00 EB 0F F6 ..t..F.+.F......
0800:1C20 46 FC 02 74 09 C6 46 F2 20 C7 46 F0 01 00 8B 46 F..t..F. .F....F
0800:1C30 F6 2B C1 2B 46 F0 7D 02 33 C0 06 57 51 F6 46 FC .+.+F.}.3..WQ.F.
0800:1C40 0C 75 07 8B C8 B2 20 E8 B0 00 50 16 07 8D 7E F2 .u.... ...P...~.
0800:1C50 8B 4E F0 E8 86 00 58 F6 46 FC 08 74 0D F6 46 FC .N....X.F..t..F.
0800:1C60 04 75 07 8B C8 B2 30 E8 90 00 59 5F 07 50 E8 6B .u....0...Y_.P.k
0800:1C70 00 58 F6 46 FC 04 74 07 8B C8 B2 20 E8 7B 00 E9 .X.F..t.... .{..
0800:1C80 09 FC 8B 76 08 AD 89 76 08 C3 8B 76 08 AD 8B D0 ...v...v...v....
0800:1C90 AD 92 89 76 08 C3 F6 46 FC 20 74 08 E8 EB FF 8E ...v...F. t.....
0800:1CA0 C2 8B F8 C3 E8 DB FF 8B F8 0B C0 75 03 8E C0 C3 ...........u....
0800:1CB0 1E 07 C3 98 57 8B 5E 04 FF 4F 02 78 0A 8B 3F FF ....W.^..O.x..?.
0800:1CC0 07 88 05 33 C0 5F C3 06 51 52 53 50 E8 B9 FA 83 ...3._..QRSP....
0800:1CD0 C4 04 5A 59 07 3D FF FF 75 E9 EB E9 E3 1B 8B F7 ..ZY.=..u.......
0800:1CE0 01 4E F8 57 33 FF 26 AC E8 C8 FF 0B F8 E2 F7 0B .N.W3.&.........
0800:1CF0 FF 5F 74 05 C7 46 F8 FF FF C3 E3 19 01 4E F8 57 ._t..F.......N.W
0800:1D00 33 FF 8A C2 E8 AC FF 0B F8 E2 F7 0B FF 5F 74 05 3............_t.
0800:1D10 C7 46 F8 FF FF C3 FD 57 93 0B F6 7F 0A 0B DB 75 .F.....W.......u
0800:1D20 06 0B D2 75 02 EB 1A 92 33 D2 F7 F1 93 F7 F1 92 ...u....3.......
0800:1D30 87 D3 04 30 3C 39 76 03 02 46 FF AA 8B C2 4E EB ...0<9v..F....N.
0800:1D40 D8 59 2B CF 47 FC C3                            .Y+.G..

l0800_1D47:
	pop	di
	pop	si
	mov	sp,bp
	pop	bp
	ret
0800:1D4D                                        00                    .

;; fn0800_1D4E: 0800:1D4E
;;   Called from:
;;     0800:138E (in fn0800_137E)
fn0800_1D4E proc
	push	bp
	mov	bp,sp
	sub	sp,22h
	call	2188h
	mov	ax,3Ch
	cwd
	push	dx
	push	ax
	push	word ptr [05D4h]
	push	word ptr [05D2h]
	call	143Ah
	mov	bx,[bp+4h]
	mov	[bx+6h],ax
	lea	ax,[bp-6h]
	push	ax
	call	22FEh
	add	sp,2h
	lea	ax,[bp-0Ah]
	push	ax
	call	2318h
	add	sp,2h
	cmp	byte ptr [bp-0Ah],0h
	jnz	1D98h

l0800_1D88:
	cmp	byte ptr [bp-9h],0h
	jnz	1D98h

l0800_1D8E:
	lea	ax,[bp-6h]
	push	ax
	call	22FEh
	add	sp,2h

l0800_1D98:
	mov	ax,[bp-4h]
	sub	ax,7BCh
	mov	[bp-20h],ax
	add	ax,50h
	mov	[bp-12h],ax
	mov	al,[bp-6h]
	sub	ah,ah
	mov	[bp-22h],ax
	mov	[bp-16h],ax
	mov	bl,[bp-5h]
	sub	bh,bh
	mov	[bp-1Eh],bx
	dec	bx
	mov	[bp-14h],bx
	shl	bx,1h
	add	ax,[bx+5ACh]
	mov	[bp-0Eh],ax
	test	byte ptr [bp-20h],3h
	jnz	1DD7h

l0800_1DCD:
	cmp	word ptr [bp-1Eh],2h
	jle	1DD7h

l0800_1DD3:
	inc	ax
	mov	[bp-0Eh],ax

l0800_1DD7:
	mov	al,[bp-0Ah]
	sub	ah,ah
	mov	[bp-18h],ax
	mov	al,[bp-7h]
	mov	cx,ax
	shl	ax,1h
	shl	ax,1h
	add	ax,cx
	shl	ax,1h
	mov	bx,[bp+4h]
	mov	[bx+4h],ax
	mov	al,[bp-8h]
	sub	ah,ah
	push	ax
	mov	al,[bp-9h]
	push	ax
	mov	al,[bp-0Ah]
	push	ax
	push	word ptr [bp-22h]
	push	word ptr [bp-1Eh]
	push	word ptr [bp-20h]
	call	1E42h
	add	sp,0Ch
	mov	bx,[bp+4h]
	mov	[bx],ax
	mov	[bx+2h],dx
	cmp	word ptr [05D6h],0h
	jz	1E36h

l0800_1E1E:
	lea	ax,[bp-1Ch]
	push	ax
	call	2234h
	add	sp,2h
	or	ax,ax
	jz	1E36h

l0800_1E2C:
	mov	bx,[bp+4h]
	mov	word ptr [bx+8h],1h
	jmp	1E3Eh

l0800_1E36:
	mov	bx,[bp+4h]
	mov	word ptr [bx+8h],0h

l0800_1E3E:
	mov	sp,bp
	pop	bp
	ret

;; fn0800_1E42: 0800:1E42
;;   Called from:
;;     0800:1366 (in fn0800_132C)
;;     0800:1E09 (in fn0800_1D4E)
fn0800_1E42 proc
	push	bp
	mov	bp,sp
	sub	sp,16h
	push	di
	push	si
	mov	si,[bp+4h]
	mov	ax,5180h
	mov	dx,1h
	push	dx
	push	ax
	lea	ax,[si+3h]
	cwd
	xor	ax,dx
	sub	ax,dx
	mov	cx,2h
	sar	ax,cl
	xor	ax,dx
	sub	ax,dx
	cwd
	push	dx
	push	ax
	call	1F38h
	mov	[bp-16h],ax
	mov	[bp-14h],dx
	mov	bx,[bp+6h]
	shl	bx,1h
	mov	di,[bx+5AAh]
	mov	ax,si
	mov	cx,4h
	cwd
	idiv	cx
	or	dx,dx
	jnz	1E8Eh

l0800_1E87:
	cmp	word ptr [bp+6h],2h
	jle	1E8Eh

l0800_1E8D:
	inc	di

l0800_1E8E:
	mov	ax,[bp+8h]
	add	ax,di
	mov	[bp-4h],ax
	call	2188h
	mov	ax,3Ch
	cwd
	push	dx
	push	ax
	push	dx
	push	ax
	mov	ax,18h
	cwd
	push	dx
	push	ax
	mov	cx,16Dh
	mov	ax,si
	imul	cx
	add	ax,[bp+8h]
	add	ax,di
	cwd
	add	ax,0E44h
	adc	dx,0h
	push	dx
	push	ax
	call	1F38h
	mov	cx,ax
	mov	ax,[bp+0Ah]
	mov	bx,dx
	cwd
	add	ax,cx
	adc	dx,bx
	push	dx
	push	ax
	call	1F38h
	mov	cx,ax
	mov	ax,[bp+0Ch]
	mov	bx,dx
	cwd
	add	ax,cx
	adc	dx,bx
	push	dx
	push	ax
	call	1F38h
	mov	cx,ax
	mov	ax,[bp+0Eh]
	mov	bx,dx
	cwd
	add	ax,cx
	adc	dx,bx
	add	ax,[05D2h]
	adc	dx,[05D4h]
	add	[bp-16h],ax
	adc	[bp-14h],dx
	lea	ax,[si+50h]
	mov	[bp-8h],ax
	mov	ax,[bp+6h]
	dec	ax
	mov	[bp-0Ah],ax
	mov	ax,[bp+0Ah]
	mov	[bp-0Eh],ax
	cmp	word ptr [05D6h],0h
	jz	1F2Ch

l0800_1F15:
	lea	ax,[bp-12h]
	push	ax
	call	2234h
	add	sp,2h
	or	ax,ax
	jz	1F2Ch

l0800_1F23:
	sub	word ptr [bp-16h],0E10h
	sbb	word ptr [bp-14h],0h

l0800_1F2C:
	mov	ax,[bp-16h]
	mov	dx,[bp-14h]
	pop	si
	pop	di
	mov	sp,bp
	pop	bp
	ret

;; fn0800_1F38: 0800:1F38
;;   Called from:
;;     0800:13AA (in fn0800_137E)
;;     0800:1424 (in fn0800_1414)
;;     0800:1E69 (in fn0800_1E42)
;;     0800:1EBC (in fn0800_1E42)
;;     0800:1ECD (in fn0800_1E42)
;;     0800:1EDE (in fn0800_1E42)
;;     0800:21D3 (in fn0800_2198)
fn0800_1F38 proc
	push	bp
	mov	bp,sp
	mov	ax,[bp+6h]
	mov	cx,[bp+0Ah]
	or	cx,ax
	mov	cx,[bp+8h]
	jnz	1F51h

l0800_1F48:
	mov	ax,[bp+4h]
	mul	cx
	pop	bp
	ret	8h

l0800_1F51:
	push	bx
	mul	cx
	mov	bx,ax
	mov	ax,[bp+4h]
	mul	word ptr [bp+0Ah]
	add	bx,ax
	mov	ax,[bp+4h]
	mul	cx
	add	dx,bx
	pop	bx
	pop	bp
	ret	8h
0800:1F6A                               53 06 51 B9 00 04           S.Q...
0800:1F70 87 0E 2E 06 51 50 E8 21 04 5B 8F 06 2E 06 59 8C ....QP.!.[....Y.
0800:1F80 DA 0B C0 74 03 07 5B C3 8B C1 E9 D5 F0 00       ...t..[.......

;; fn0800_1F8E: 0800:1F8E
;;   Called from:
;;     0800:180A (in fn0800_1788)
fn0800_1F8E proc
	push	bp
	mov	bp,sp
	push	si
	mov	si,[bp+4h]
	mov	ax,200h
	push	ax
	call	239Ah
	pop	cx
	mov	bx,si
	sub	bx,43Eh
	add	bx,4DEh
	or	ax,ax
	jz	1FB6h

l0800_1FAB:
	or	byte ptr [si+6h],8h
	mov	word ptr [bx+2h],200h
	jmp	1FC2h

l0800_1FB6:
	or	byte ptr [si+6h],4h
	mov	word ptr [bx+2h],1h
	lea	ax,[bx+1h]

l0800_1FC2:
	mov	[si],ax
	mov	[si+4h],ax
	mov	word ptr [si+2h],0h
	pop	si
	pop	bp
	ret
0800:1FCF                                              00                .

;; fn0800_1FD0: 0800:1FD0
;;   Called from:
;;     0800:1858 (in fn0800_1788)
fn0800_1FD0 proc
	push	bp
	mov	bp,sp
	sub	sp,4h
	mov	bx,[bp+4h]
	cmp	bx,[0297h]
	jc	1FE4h

l0800_1FDF:
	mov	ax,900h
	jmp	200Eh

l0800_1FE4:
	test	word ptr [bp+8h],8000h
	jz	2033h

l0800_1FEB:
	cmp	word ptr [bp+0Ah],0h
	jz	200Bh

l0800_1FF1:
	xor	cx,cx
	mov	dx,cx
	mov	ax,4201h
	int	21h
	jc	2047h

l0800_1FFC:
	test	word ptr [bp+0Ah],2h
	jnz	2011h

l0800_2003:
	add	ax,[bp+6h]
	adc	dx,[bp+8h]
	jns	2033h

l0800_200B:
	mov	ax,1600h

l0800_200E:
	stc
	jmp	2047h

l0800_2011:
	mov	[bp-2h],dx
	mov	[bp-4h],ax
	mov	dx,cx
	mov	ax,4202h
	int	21h
	add	ax,[bp+6h]
	adc	dx,[bp+8h]
	jns	2033h

l0800_2026:
	mov	cx,[bp-2h]
	mov	dx,[bp-4h]
	mov	ax,4200h
	int	21h
	jmp	200Bh

l0800_2033:
	mov	dx,[bp+6h]
	mov	cx,[bp+8h]
	mov	al,[bp+0Ah]
	mov	ah,42h
	int	21h
	jc	2047h

l0800_2042:
	and	byte ptr [bx+299h],0FDh

l0800_2047:
	jmp	2347h

;; fn0800_204A: 0800:204A
;;   Called from:
;;     0800:17F4 (in fn0800_1788)
;;     0800:182E (in fn0800_1788)
fn0800_204A proc
	push	bp
	mov	bp,sp
	sub	sp,8h
	mov	bx,[bp+4h]
	cmp	bx,[0297h]
	jc	2060h

l0800_2059:
	mov	ax,900h
	stc

l0800_205D:
	jmp	2347h

l0800_2060:
	cmp	word ptr [0638h],0D6D6h
	jnz	206Ch

l0800_2068:
	call	word ptr [063Ah]

l0800_206C:
	test	byte ptr [bx+299h],20h
	jz	207Eh

l0800_2073:
	mov	ax,4202h
	xor	cx,cx
	mov	dx,cx
	int	21h
	jc	205Dh

l0800_207E:
	test	byte ptr [bx+299h],80h
	jz	20F3h

l0800_2085:
	mov	dx,[bp+6h]
	push	ds
	pop	es
	xor	ax,ax
	mov	[bp-2h],ax
	mov	[bp-4h],ax
	cld
	push	di
	push	si
	mov	di,dx
	mov	si,dx
	mov	[bp-8h],sp
	mov	cx,[bp+8h]
	jcxz	20D9h

l0800_20A1:
	mov	al,0Ah

l0800_20A3:
	repne scasb

l0800_20A5:
	jnz	20F1h

l0800_20A7:
	call	2388h
	cmp	ax,0A8h
	jbe	20F5h

l0800_20AF:
	sub	sp,2h
	mov	bx,sp
	mov	dx,200h
	cmp	ax,228h
	jnc	20BFh

l0800_20BC:
	mov	dx,80h

l0800_20BF:
	sub	sp,dx
	mov	dx,sp
	mov	di,dx
	push	ss
	pop	es
	mov	cx,[bp+8h]

l0800_20CA:
	lodsb
	cmp	al,0Ah
	jz	20DBh

l0800_20CF:
	cmp	di,bx
	jz	20ECh

l0800_20D3:
	stosb
	loop	20CAh

l0800_20D6:
	call	20FBh

l0800_20D9:
	jmp	2145h

l0800_20DB:
	mov	al,0Dh
	cmp	di,bx
	jnz	20E4h

l0800_20E1:
	call	20FBh

l0800_20E4:
	stosb
	mov	al,0Ah
	inc	word ptr [bp-4h]
	jmp	20CFh

l0800_20EC:
	call	20FBh
	jmp	20D3h

l0800_20F1:
	pop	si
	pop	di

l0800_20F3:
	jmp	2153h

l0800_20F5:
	mov	ax,0FFFCh
	call	1222h

;; fn0800_20FB: 0800:20FB
;;   Called from:
;;     0800:20D6 (in fn0800_204A)
;;     0800:20E1 (in fn0800_204A)
;;     0800:20EC (in fn0800_204A)
;;     0800:20F8 (in fn0800_204A)
fn0800_20FB proc
	push	ax
	push	bx
	push	cx
	mov	cx,di
	sub	cx,dx
	jcxz	2116h

l0800_2104:
	push	cx
	mov	bx,[bp+4h]
	mov	ah,40h
	int	21h
	pop	cx
	jc	211Ch

l0800_210F:
	add	[bp-2h],ax
	cmp	cx,ax
	ja	211Ch

l0800_2116:
	pop	cx
	pop	bx
	pop	ax
	mov	di,dx
	ret

l0800_211C:
	lahf
	add	sp,8h
	cmp	word ptr [bp-2h],0h
	jnz	2145h

l0800_2126:
	sahf
	jnc	212Dh

l0800_2129:
	mov	ah,9h
	jmp	214Bh

l0800_212D:
	test	byte ptr [bx+299h],40h
	jz	213Fh

l0800_2134:
	mov	bx,[bp+6h]
	cmp	byte ptr [bx],1Ah
	jnz	213Fh

l0800_213C:
	clc
	jmp	214Bh

l0800_213F:
	stc
	mov	ax,1C00h
	jmp	214Bh

;; fn0800_2145: 0800:2145
;;   Called from:
;;     0800:20D9 (in fn0800_204A)
;;     0800:2124 (in fn0800_20FB)
fn0800_2145 proc
	mov	ax,[bp-2h]
	sub	ax,[bp-4h]

;; fn0800_214B: 0800:214B
;;   Called from:
;;     0800:212B (in fn0800_20FB)
;;     0800:213D (in fn0800_20FB)
;;     0800:2143 (in fn0800_20FB)
;;     0800:2148 (in fn0800_2145)
fn0800_214B proc
	mov	sp,[bp-8h]
	pop	si
	pop	di

;; fn0800_2150: 0800:2150
;;   Called from:
;;     0800:214F (in fn0800_214B)
;;     0800:216A (in fn0800_204A)
;;     0800:216E (in fn0800_204A)
;;     0800:217F (in fn0800_204A)
;;     0800:2185 (in fn0800_204A)
fn0800_2150 proc
	jmp	2347h

l0800_2153:
	mov	cx,[bp+8h]
	or	cx,cx
	jnz	215Fh

l0800_215A:
	mov	ax,cx
	jmp	2347h

l0800_215F:
	mov	dx,[bp+6h]
	mov	ah,40h
	int	21h
	jnc	216Ch

l0800_2168:
	mov	ah,9h
	jmp	2150h

l0800_216C:
	or	ax,ax
	jnz	2150h

l0800_2170:
	test	byte ptr [bx+299h],40h
	jz	2181h

l0800_2177:
	mov	bx,dx
	cmp	byte ptr [bx],1Ah
	jnz	2181h

l0800_217E:
	clc
	jmp	2150h

l0800_2181:
	stc
	mov	ax,1C00h
	jmp	2150h
0800:2187                      00                                .

;; fn0800_2188: 0800:2188
;;   Called from:
;;     0800:1D54 (in fn0800_1D4E)
;;     0800:1E96 (in fn0800_1E42)
fn0800_2188 proc
	cmp	word ptr [08E4h],0h
	jnz	2196h

l0800_218F:
	call	2198h
	inc	word ptr [08E4h]

l0800_2196:
	ret
0800:2197                      90                                .

;; fn0800_2198: 0800:2198
;;   Called from:
;;     0800:218F (in fn0800_2188)
fn0800_2198 proc
	push	di
	push	si
	mov	ax,5C6h
	push	ax
	call	24C8h
	add	sp,2h
	mov	si,ax
	or	si,si
	jnz	21ADh

l0800_21AA:
	jmp	2230h

l0800_21AD:
	cmp	byte ptr [si],0h
	jz	2230h

l0800_21B2:
	mov	ax,3h
	push	ax
	push	si
	push	word ptr [05D8h]
	call	249Ch
	add	sp,6h
	mov	ax,0E10h
	cwd
	push	dx
	push	ax
	add	si,3h
	push	si
	call	24C4h
	add	sp,2h
	push	dx
	push	ax
	call	1F38h
	mov	[05D2h],ax
	mov	[05D4h],dx
	sub	di,di

l0800_21DF:
	mov	bx,di
	add	bx,si
	cmp	byte ptr [bx],0h
	jz	2201h

l0800_21E8:
	mov	al,[bx]
	mov	cx,ax
	cbw
	mov	bx,ax
	test	byte ptr [bx+33Bh],4h
	jnz	21FBh

l0800_21F6:
	cmp	cl,2Dh
	jnz	2201h

l0800_21FB:
	inc	di
	cmp	di,3h
	jl	21DFh

l0800_2201:
	mov	bx,di
	add	bx,si
	cmp	byte ptr [bx],0h
	jz	221Ch

l0800_220A:
	mov	ax,3h
	push	ax
	push	bx
	push	word ptr [05DAh]
	call	249Ch
	add	sp,6h
	jmp	2223h
0800:221B                                  90                        .

l0800_221C:
	mov	bx,[05DAh]
	mov	byte ptr [bx],0h

l0800_2223:
	mov	bx,[05DAh]
	cmp	byte ptr [bx],1h
	sbb	ax,ax
	inc	ax
	mov	[05D6h],ax

l0800_2230:
	pop	si
	pop	di
	ret
0800:2233          90                                        .

;; fn0800_2234: 0800:2234
;;   Called from:
;;     0800:1E22 (in fn0800_1D4E)
;;     0800:1F19 (in fn0800_1E42)
fn0800_2234 proc
	push	bp
	mov	bp,sp
	sub	sp,4h
	push	di
	push	si
	mov	si,[bp+4h]
	cmp	word ptr [si+8h],3h
	jge	2248h

l0800_2245:
	jmp	22F5h

l0800_2248:
	cmp	word ptr [si+8h],9h
	jle	2251h

l0800_224E:
	jmp	22F5h

l0800_2251:
	cmp	word ptr [si+8h],3h
	jle	2260h

l0800_2257:
	cmp	word ptr [si+8h],9h
	jge	2260h

l0800_225D:
	jmp	22E1h

l0800_2260:
	mov	di,[si+0Ah]
	add	di,76Ch
	cmp	di,7C2h
	jle	2284h

l0800_226D:
	cmp	word ptr [si+8h],3h
	jnz	2284h

l0800_2273:
	mov	bx,[si+8h]
	shl	bx,1h
	mov	ax,[bx+5ACh]
	add	ax,7h
	jmp	228Dh
0800:2281    90 90 90                                      ...

l0800_2284:
	mov	bx,[si+8h]
	shl	bx,1h
	mov	ax,[bx+5AEh]

l0800_228D:
	mov	[bp-4h],ax
	test	di,3h
	jnz	2299h

l0800_2296:
	inc	word ptr [bp-4h]

l0800_2299:
	mov	di,[si+0Ah]
	sub	di,46h
	mov	ax,di
	mov	cx,16Dh
	imul	cx
	mov	cx,ax
	lea	ax,[di+1h]
	mov	bx,cx
	cwd
	xor	ax,dx
	sub	ax,dx
	mov	cx,2h
	sar	ax,cl
	xor	ax,dx
	sub	ax,dx
	add	ax,bx
	add	ax,[bp-4h]
	add	ax,4h
	mov	cx,7h
	cwd
	idiv	cx
	sub	dx,[bp-4h]
	neg	dx
	cmp	word ptr [si+8h],3h
	jnz	22E6h

l0800_22D4:
	cmp	dx,[si+0Eh]
	jl	22E1h

l0800_22D9:
	jnz	22F5h

l0800_22DB:
	cmp	word ptr [si+4h],2h
	jl	22F5h

l0800_22E1:
	mov	ax,1h
	jmp	22F7h

l0800_22E6:
	mov	ax,dx
	cmp	[si+0Eh],ax
	jl	22E1h

l0800_22ED:
	jnz	22F5h

l0800_22EF:
	cmp	word ptr [si+4h],1h
	jl	22E1h

l0800_22F5:
	sub	ax,ax

l0800_22F7:
	pop	si
	pop	di
	mov	sp,bp
	pop	bp
	ret
0800:22FD                                        90                    .

;; fn0800_22FE: 0800:22FE
;;   Called from:
;;     0800:1D72 (in fn0800_1D4E)
;;     0800:1D92 (in fn0800_1D4E)
fn0800_22FE proc
	push	bp
	mov	bp,sp
	mov	ah,2Ah
	int	21h
	mov	bx,[bp+4h]
	mov	[bx+2h],cx
	mov	[bx+1h],dh
	mov	[bx],dl
	mov	[bx+4h],al
	xor	ax,ax
	pop	bp
	ret
0800:2317                      00                                .

;; fn0800_2318: 0800:2318
;;   Called from:
;;     0800:1D7C (in fn0800_1D4E)
fn0800_2318 proc
	push	bp
	mov	bp,sp
	mov	ah,2Ch
	int	21h
	mov	bx,[bp+4h]
	mov	[bx],ch
	mov	[bx+1h],cl
	mov	[bx+2h],dh
	mov	[bx+3h],dl
	xor	ax,ax
	pop	bp
	ret
0800:2331    00 72 15 33 C0 8B E5 5D C3 73 F8 50 E8 1A 00  .r.3...].s.P...
0800:2340 58 32 E4 8B E5 5D C3                            X2...].

;; fn0800_2347: 0800:2347
;;   Called from:
;;     0800:2047 (in fn0800_1FD0)
;;     0800:205D (in fn0800_204A)
;;     0800:2150 (in fn0800_2150)
;;     0800:2150 (in fn0800_2150)
;;     0800:215C (in fn0800_204A)
fn0800_2347 proc
	jnc	2350h

l0800_2349:
	call	235Ah
	mov	ax,0FFFFh
	cwd

l0800_2350:
	mov	sp,bp
	pop	bp
	ret
0800:2354             32 E4 E8 01 00 C3                       2.....

;; fn0800_235A: 0800:235A
;;   Called from:
;;     0800:2349 (in fn0800_2347)
fn0800_235A proc
	mov	[0295h],al
	or	ah,ah
	jnz	2383h

l0800_2361:
	cmp	byte ptr [0292h],3h
	jc	2374h

l0800_2368:
	cmp	al,22h
	jnc	2378h

l0800_236C:
	cmp	al,20h
	jc	2374h

l0800_2370:
	mov	al,5h
	jmp	237Ah

l0800_2374:
	cmp	al,13h
	jbe	237Ah

l0800_2378:
	mov	al,13h

l0800_237A:
	mov	bx,618h
	xlat

l0800_237E:
	cbw
	mov	[028Ah],ax
	ret

l0800_2383:
	mov	al,ah
	jmp	237Eh
0800:2387                      00                                .

;; fn0800_2388: 0800:2388
;;   Called from:
;;     0800:20A7 (in fn0800_204A)
fn0800_2388 proc
	pop	cx
	mov	ax,[02C2h]
	cmp	ax,sp
	jnc	2396h

l0800_2390:
	sub	ax,sp
	neg	ax

l0800_2394:
	jmp	cx

l0800_2396:
	xor	ax,ax
	jmp	2394h

;; fn0800_239A: 0800:239A
;;   Called from:
;;     0800:1F99 (in fn0800_1F8E)
fn0800_239A proc
	jmp	2607h
0800:239D                                        00                    .

;; fn0800_239E: 0800:239E
;;   Called from:
;;     0800:261C (in fn0800_239A)
fn0800_239E proc
	push	cx
	push	di
	test	byte ptr [bx+2h],1h
	jz	2409h

l0800_23A6:
	call	247Bh
	mov	di,si
	mov	ax,[si]
	test	al,1h
	jz	23B4h

l0800_23B1:
	sub	cx,ax
	dec	cx

l0800_23B4:
	inc	cx
	inc	cx
	mov	si,[bx+4h]
	or	si,si
	jz	2409h

l0800_23BD:
	add	cx,si
	jnc	23CAh

l0800_23C1:
	xor	ax,ax
	mov	dx,0FFF0h
	jcxz	23F8h

l0800_23C8:
	jmp	2409h

l0800_23CA:
	push	ss
	pop	es
	mov	ax,es:[062Eh]
	cmp	ax,2000h
	jz	23EBh

l0800_23D5:
	mov	dx,8000h

l0800_23D8:
	cmp	dx,ax
	jc	23E2h

l0800_23DC:
	shr	dx,1h
	jnz	23D8h

l0800_23E0:
	jmp	2404h

l0800_23E2:
	cmp	dx,8h
	jc	2404h

l0800_23E7:
	shl	dx,1h
	mov	ax,dx

l0800_23EB:
	dec	ax
	mov	dx,ax
	add	ax,cx
	jnc	23F4h

l0800_23F2:
	xor	ax,ax

l0800_23F4:
	not	dx
	and	ax,dx

l0800_23F8:
	push	dx
	call	242Ah
	pop	dx
	jnc	240Ch

l0800_23FF:
	cmp	dx,0F0h
	jz	2409h

l0800_2404:
	mov	ax,10h
	jmp	23EBh

l0800_2409:
	stc
	jmp	2427h

l0800_240C:
	mov	dx,ax
	sub	dx,[bx+4h]
	mov	[bx+4h],ax
	mov	[bx+8h],di
	mov	si,[bx+0Ah]
	dec	dx
	mov	[si],dx
	inc	dx
	add	si,dx
	mov	word ptr [si],0FFFEh
	mov	[bx+0Ah],si

l0800_2427:
	pop	di
	pop	cx
	ret

;; fn0800_242A: 0800:242A
;;   Called from:
;;     0800:23F9 (in fn0800_239E)
fn0800_242A proc
	mov	dx,ax
	test	byte ptr [bx+2h],4h
	jz	2441h

l0800_2432:
	dec	dx
	mov	si,[bx+4h]
	dec	si
	cmp	dx,si
	jc	2440h

l0800_243B:
	cmp	[bx-2h],dx
	jnc	2476h

l0800_2440:
	inc	dx

l0800_2441:
	push	bx
	push	cx
	mov	si,ds
	mov	es,si
	mov	cl,4h
	shr	ax,cl
	jnz	2450h

l0800_244D:
	mov	ax,1000h

l0800_2450:
	test	byte ptr [bx+2h],4h
	jz	2460h

l0800_2456:
	add	ax,si
	mov	bx,[0290h]
	sub	ax,bx
	mov	es,bx

l0800_2460:
	mov	bx,ax
	mov	ah,4Ah
	int	21h
	pop	cx
	pop	bx
	jc	247Ah

l0800_246A:
	mov	ax,dx
	test	byte ptr [bx+2h],4h
	jz	2476h

l0800_2472:
	dec	dx
	mov	[bx-2h],dx

l0800_2476:
	clc
	jmp	247Ah
0800:2479                            F9                            .

l0800_247A:
	ret

;; fn0800_247B: 0800:247B
;;   Called from:
;;     0800:23A6 (in fn0800_239E)
fn0800_247B proc
	push	di
	mov	si,[bx+8h]
	cmp	si,[bx+0Ah]
	jnz	2487h

l0800_2484:
	mov	si,[bx+6h]

l0800_2487:
	lodsw
	cmp	ax,0FFFEh
	jz	2495h

l0800_248D:
	mov	di,si
	and	al,0FEh
	add	si,ax
	jmp	2487h

l0800_2495:
	dec	di
	dec	di
	mov	si,di
	pop	di
	ret
0800:249B                                  00                        .

;; fn0800_249C: 0800:249C
;;   Called from:
;;     0800:21BB (in fn0800_2198)
;;     0800:2213 (in fn0800_2198)
fn0800_249C proc
	push	bp
	mov	bp,sp
	push	di
	push	si
	push	ds
	pop	es
	mov	di,[bp+4h]
	mov	si,[bp+6h]
	mov	bx,di
	mov	cx,[bp+8h]
	jcxz	24BCh

l0800_24B0:
	lodsb
	or	al,al
	jz	24B8h

l0800_24B5:
	stosb
	loop	24B0h

l0800_24B8:
	xor	al,al

l0800_24BA:
	rep stosb

l0800_24BC:
	mov	ax,bx
	pop	si
	pop	di
	mov	sp,bp
	pop	bp
	ret

;; fn0800_24C4: 0800:24C4
;;   Called from:
;;     0800:21CB (in fn0800_2198)
fn0800_24C4 proc
	jmp	2686h
0800:24C7                      00                                .

;; fn0800_24C8: 0800:24C8
;;   Called from:
;;     0800:219E (in fn0800_2198)
fn0800_24C8 proc
	push	bp
	mov	bp,sp
	push	di
	push	si
	mov	si,[02B1h]
	or	si,si
	jz	2519h

l0800_24D5:
	cmp	word ptr [bp+4h],0h
	jz	2519h

l0800_24DB:
	push	word ptr [bp+4h]
	call	2630h
	add	sp,2h
	mov	di,ax
	jmp	2514h

l0800_24E8:
	push	word ptr [si]
	call	2630h
	add	sp,2h
	cmp	ax,di
	jle	2512h

l0800_24F4:
	mov	bx,[si]
	cmp	byte ptr [bx+di],3Dh
	jnz	2512h

l0800_24FB:
	push	di
	push	word ptr [bp+4h]
	push	bx
	call	264Ch
	add	sp,6h
	or	ax,ax
	jnz	2512h

l0800_250A:
	mov	ax,[si]
	add	ax,di
	inc	ax
	jmp	251Bh
0800:2511    90                                            .

l0800_2512:
	inc	si
	inc	si

l0800_2514:
	cmp	word ptr [si],0h
	jnz	24E8h

l0800_2519:
	sub	ax,ax

l0800_251B:
	pop	si
	pop	di
	mov	sp,bp
	pop	bp
	ret
0800:2521    90 55 8B EC 83 EC 02 57 56 2B FF 39 7E 04 75  .U.....WV+.9~.u
0800:2530 09 2B C0 50 E8 65 00 EB 55 90 8B 76 04 8A 44 06 .+.P.e..U..v..D.
0800:2540 8B C8 24 03 3C 02 75 3A F6 C1 08 75 0D 8B DE 81 ..$.<.u:...u....
0800:2550 EB 3E 04 F6 87 DE 04 01 74 28 8B 04 2B 44 04 89 .>......t(..+D..
0800:2560 46 FE 0B C0 7E 1C 50 FF 74 04 8A 4C 07 2A ED 51 F...~.P.t..L.*.Q
0800:2570 E8 D7 FA 83 C4 06 39 46 FE 74 07 80 4C 06 20 BF ......9F.t..L. .
0800:2580 FF FF 8B 44 04 89 04 C7 44 02 00 00 8B C7 5E 5F ...D....D.....^_
0800:2590 8B E5 5D C3 B8 01 00 50 E8 01 00 C3 55 8B EC 83 ..]....P....U...
0800:25A0 EC 02 57 56 BE 3E 04 2B FF 89 7E FE EB 08 C7 46 ..WV.>.+..~....F
0800:25B0 FE FF FF 83 C6 08 39 36 7E 05 72 14 F6 44 06 83 ......96~.r..D..
0800:25C0 74 F1 56 E8 5C FF 83 C4 02 40 74 E2 47 EB E4 90 t.V.\....@t.G...
0800:25D0 83 7E 04 01 75 04 8B C7 EB 03 8B 46 FE 5E 5F 8B .~..u......F.^_.
0800:25E0 E5 5D C2 02 00 90 55 8B EC 56 8B 5E 04 BE 56 02 .]....U..V.^..V.
0800:25F0 39 5C 06 73 0D 4B 4B 80 0F 01 39 5C 08 76 03 89 9\.s.KK...9\.v..
0800:2600 5C 08 5E 8B E5 5D C3                            \.^..].

l0800_2607:
	push	bp
	mov	bp,sp
	push	si
	push	di
	mov	cx,[bp+4h]
	cmp	cx,0E8h
	ja	2626h

l0800_2614:
	mov	bx,256h
	call	26DAh
	jnc	262Bh

l0800_261C:
	call	239Eh
	jc	2626h

l0800_2621:
	call	26DAh
	jnc	262Bh

l0800_2626:
	xor	ax,ax
	cwd
	jmp	262Bh

l0800_262B:
	pop	di
	pop	si
	pop	bp
	ret
0800:262F                                              00                .

;; fn0800_2630: 0800:2630
;;   Called from:
;;     0800:24DE (in fn0800_24C8)
;;     0800:24EA (in fn0800_24C8)
fn0800_2630 proc
	push	bp
	mov	bp,sp
	mov	dx,di
	mov	ax,ds
	mov	es,ax
	mov	di,[bp+4h]
	xor	ax,ax
	mov	cx,0FFFFh
	repne scasb
	not	cx
	dec	cx
	xchg	cx,ax
	mov	di,dx
	pop	bp
	ret
0800:264B                                  00                        .

;; fn0800_264C: 0800:264C
;;   Called from:
;;     0800:2500 (in fn0800_24C8)
fn0800_264C proc
	push	bp
	mov	bp,sp
	push	di
	push	si
	push	ds
	pop	es
	mov	cx,[bp+8h]
	jcxz	267Eh

l0800_2658:
	mov	bx,cx
	mov	di,[bp+4h]
	mov	si,di
	xor	ax,ax

l0800_2661:
	repne scasb

l0800_2663:
	neg	cx
	add	cx,bx
	mov	di,si
	mov	si,[bp+6h]
	rep cmpsb
	mov	al,[si-1h]
	xor	cx,cx
	cmp	al,[di-1h]
	ja	267Ch

l0800_2678:
	jz	267Eh

l0800_267A:
	dec	cx
	dec	cx

l0800_267C:
	not	cx

l0800_267E:
	mov	ax,cx
	pop	si
	pop	di
	mov	sp,bp
	pop	bp
	ret

l0800_2686:
	push	bp
	mov	bp,sp
	push	di
	push	si
	mov	si,[bp+4h]
	xor	ax,ax
	cwd
	xor	bx,bx

l0800_2693:
	lodsb
	cmp	al,20h
	jz	2693h

l0800_2698:
	cmp	al,9h
	jz	2693h

l0800_269C:
	push	ax
	cmp	al,2Dh
	jz	26A5h

l0800_26A1:
	cmp	al,2Bh
	jnz	26A6h

l0800_26A5:
	lodsb

l0800_26A6:
	cmp	al,39h
	ja	26C9h

l0800_26AA:
	sub	al,30h
	jc	26C9h

l0800_26AE:
	shl	bx,1h
	rcl	dx,1h
	mov	cx,bx
	mov	di,dx
	shl	bx,1h
	rcl	dx,1h
	shl	bx,1h
	rcl	dx,1h
	add	bx,cx
	adc	dx,di
	add	bx,ax
	adc	dx,0h
	jmp	26A5h

l0800_26C9:
	pop	ax
	cmp	al,2Dh
	xchg	bx,ax
	jnz	26D6h

l0800_26CF:
	neg	ax
	adc	dx,0h
	neg	dx

l0800_26D6:
	pop	si
	pop	di
	pop	bp
	ret

;; fn0800_26DA: 0800:26DA
;;   Called from:
;;     0800:2617 (in fn0800_239A)
;;     0800:2621 (in fn0800_239A)
fn0800_26DA proc
	inc	cx
	and	cl,0FEh
	push	bx
	cld
	mov	si,[bx+8h]
	mov	bx,[bx+0Ah]
	xor	di,di
	jmp	270Dh

l0800_26EA:
	mov	ax,bx
	pop	bx
	test	al,1h
	jnz	2733h

l0800_26F1:
	push	bx
	mov	si,[bx+6h]
	mov	bx,[bx+8h]
	cmp	bx,si
	jz	2732h

l0800_26FC:
	dec	bx
	xor	di,di
	jmp	270Dh
0800:2701    90                                            .

l0800_2702:
	lea	dx,[si-2h]
	cmp	dx,bx
	jnc	26EAh

l0800_2709:
	add	si,ax
	jc	2730h

l0800_270D:
	lodsw
	test	al,1h
	jz	2702h

l0800_2712:
	mov	di,si

l0800_2714:
	dec	ax
	cmp	ax,cx
	jnc	273Ch

l0800_2719:
	add	si,ax
	jc	2730h

l0800_271D:
	mov	dx,ax
	lodsw
	test	al,1h
	jz	2702h

l0800_2724:
	add	ax,dx
	add	ax,2h
	mov	si,di
	mov	[si-2h],ax
	jmp	2714h

l0800_2730:
	mov	ax,ax

l0800_2732:
	pop	bx

l0800_2733:
	mov	ax,[bx+6h]
	mov	[bx+8h],ax
	stc
	jmp	2755h

l0800_273C:
	pop	bx
	mov	[si-2h],cx
	jz	274Bh

l0800_2742:
	add	di,cx
	sub	ax,cx
	dec	ax
	mov	[di],ax
	sub	di,cx

l0800_274B:
	add	di,cx
	mov	[bx+8h],di
	mov	ax,si
	mov	dx,ds
	clc

l0800_2755:
	ret

;; fn0800_2756: 0800:2756
;;   Called from:
;;     0800:00D0 (in fn0800_005D)
;;     0800:011C (in fn0800_005D)
;;     0800:015F (in fn0800_005D)
;;     0800:01A2 (in fn0800_005D)
;;     0800:01CE (in fn0800_005D)
;;     0800:0232 (in fn0800_01DB)
;;     0800:0281 (in fn0800_01DB)
;;     0800:02BF (in fn0800_01DB)
;;     0800:0506 (in fn0800_0491)
;;     0800:074E (in fn0800_06C8)
fn0800_2756 proc
	push	bp
	mov	bp,sp
	push	si
	push	di
	call	2E1Ah
	mov	bl,[078Dh]
	call	2EFBh
	les	di,[bp+6h]
	lds	si,[bp+6h]

l0800_276B:
	mov	al,0Dh

l0800_276D:
	scasb
	jc	276Dh

l0800_2770:
	jz	277Eh

l0800_2772:
	mov	al,es:[di-1h]
	cmp	al,0Ah
	jz	277Eh

l0800_277A:
	or	al,al
	jnz	276Bh

l0800_277E:
	mov	cx,di
	sub	cx,si
	dec	cx
	call	27D8h
	lodsb
	or	al,al
	jz	27B3h

l0800_278B:
	mov	di,si
	cmp	al,0Dh
	jz	2796h

l0800_2791:
	call	2825h
	jmp	276Bh

l0800_2796:
	call	2836h
	jmp	276Bh
0800:279B                                  55 8B EC 56 57            U..VW
0800:27A0 E8 77 06 8A 1E 8D 07 E8 51 07 8B 4E 0A C5 76 06 .w......Q..N..v.
0800:27B0 E8 25 00                                        .%.

l0800_27B3:
	mov	ax,ss
	mov	ds,ax
	push	bp
	push	si
	push	di
	mov	ah,2h
	int	10h
	pop	di
	pop	si
	pop	bp
	sub	dl,[07B1h]
	sub	dh,[07AFh]
	mov	[07ADh],dl
	mov	[07ABh],dh
	call	2E3Bh
	pop	di
	pop	si
	pop	bp
	retf

;; fn0800_27D8: 0800:27D8
;;   Called from:
;;     0800:2783 (in fn0800_2756)
fn0800_27D8 proc
	jcxz	27F3h

l0800_27DA:
	cmp	byte ptr ss:[07B7h],0h
	jnz	2821h

l0800_27E2:
	push	bx
	mov	al,dl
	cbw
	add	ax,cx
	sub	ax,ss:[07B5h]
	ja	27F4h

l0800_27EF:
	call	36DAh
	pop	bx

l0800_27F3:
	ret

l0800_27F4:
	dec	ax
	sub	cx,ax
	push	ax
	jbe	27FDh

l0800_27FA:
	call	36DAh

l0800_27FD:
	pop	cx
	pop	bx
	cmp	byte ptr ss:[07B8h],0h
	jz	2810h

l0800_2807:
	push	cx
	call	2825h
	pop	cx
	jcxz	27F3h

l0800_280E:
	jmp	27E2h

l0800_2810:
	mov	byte ptr ss:[07B7h],1h
	dec	dx
	push	bp
	push	si
	push	di
	mov	ah,2h
	int	10h
	pop	di
	pop	si
	pop	bp

l0800_2821:
	add	si,cx
	jmp	27F3h

;; fn0800_2825: 0800:2825
;;   Called from:
;;     0800:2791 (in fn0800_2756)
;;     0800:2808 (in fn0800_27D8)
fn0800_2825 proc
	inc	dh
	cmp	dh,ss:[07B3h]
	jbe	2836h

l0800_282E:
	push	bx
	mov	ax,601h
	call	284Ch
	pop	bx

;; fn0800_2836: 0800:2836
;;   Called from:
;;     0800:2796 (in fn0800_2756)
;;     0800:282C (in fn0800_2825)
;;     0800:2835 (in fn0800_2825)
fn0800_2836 proc
	mov	dl,ss:[07B1h]
	push	bp
	push	si
	push	di
	mov	ah,2h
	int	10h
	pop	di
	pop	si
	pop	bp
	mov	byte ptr ss:[07B7h],0h
	ret

;; fn0800_284C: 0800:284C
;;   Called from:
;;     0800:2832 (in fn0800_2825)
;;     0800:28DD (in fn0800_2880)
;;     0800:2B93 (in fn0800_2B5E)
fn0800_284C proc
	mov	bh,0h
	cmp	ss:[01E8h],bh
	jnz	285Ah

l0800_2855:
	mov	bh,ss:[078Dh]

l0800_285A:
	mov	dh,ss:[07B3h]
	mov	bl,dh
	sub	bl,ss:[07AFh]
	inc	bx
	cmp	al,bl
	jbe	286Dh

l0800_286B:
	mov	al,bl

l0800_286D:
	mov	ch,ss:[07AFh]
	mov	cl,ss:[07B1h]
	mov	dl,ss:[07B5h]
	call	3199h
	ret

;; fn0800_2880: 0800:2880
;;   Called from:
;;     0800:293F (in fn0800_291A)
fn0800_2880 proc
	mov	bx,[07B5h]
	sub	bx,[07B1h]
	cmp	word ptr [07ADh],0h
	jge	2897h

l0800_288F:
	mov	word ptr [07ADh],0h
	jmp	28B9h

l0800_2897:
	cmp	[07ADh],bx
	jle	28B9h

l0800_289D:
	cmp	byte ptr [07B8h],0h
	jz	28B0h

l0800_28A4:
	mov	word ptr [07ADh],0h
	inc	word ptr [07ABh]
	jmp	28B9h

l0800_28B0:
	mov	[07ADh],bx
	mov	byte ptr [07B7h],1h

l0800_28B9:
	mov	bx,[07B3h]
	sub	bx,[07AFh]
	cmp	word ptr [07ABh],0h
	jge	28D0h

l0800_28C8:
	mov	word ptr [07ABh],0h
	jmp	28E0h

l0800_28D0:
	cmp	[07ABh],bx
	jle	28E0h

l0800_28D6:
	mov	[07ABh],bx
	mov	ax,601h
	call	284Ch

l0800_28E0:
	call	2EFBh
	ret

;; fn0800_28E4: 0800:28E4
;;   Called from:
;;     0800:00BE (in fn0800_005D)
;;     0800:010F (in fn0800_005D)
;;     0800:0152 (in fn0800_005D)
;;     0800:0195 (in fn0800_005D)
;;     0800:01C1 (in fn0800_005D)
;;     0800:0225 (in fn0800_01DB)
;;     0800:0274 (in fn0800_01DB)
;;     0800:02B2 (in fn0800_01DB)
;;     0800:02FE (in fn0800_02CC)
;;     0800:04F9 (in fn0800_0491)
;;     0800:0741 (in fn0800_06C8)
fn0800_28E4 proc
	push	bp
	mov	bp,sp
	call	2E1Ah
	mov	ax,[07ABh]
	inc	ax
	mov	dx,[07ADh]
	inc	dx
	push	ax
	push	dx
	mov	ax,[bp+6h]
	dec	ax
	mov	bx,[bp+8h]
	dec	bx
	call	291Ah
	pop	dx
	pop	ax
	call	2E3Bh
	pop	bp
	retf
0800:2907                      E8 10 05 E8 73 FF A1 AB 07        ....s....
0800:2910 40 8B 16 AD 07 42 E8 22 05 CB                   @....B."..

;; fn0800_291A: 0800:291A
;;   Called from:
;;     0800:28FD (in fn0800_28E4)
fn0800_291A proc
	push	bx
	mov	bx,[07B3h]
	sub	bx,[07AFh]
	inc	bx
	call	30DFh
	mov	[07ABh],ax
	pop	ax
	mov	bx,[07B5h]
	sub	bx,[07B1h]
	inc	bx
	call	30DFh
	mov	[07ADh],ax
	mov	byte ptr [07B7h],0h
	call	2880h
	ret
0800:2943          00                                        .

;; fn0800_2944: 0800:2944
;;   Called from:
;;     0800:2A66 (in fn0800_2A29)
fn0800_2944 proc
	push	bp
	mov	bp,sp
	mov	ax,[bp+8h]
	mov	[01CCh],al
	jmp	2952h

;; fn0800_294F: 0800:294F
;;   Called from:
;;     0800:0050 (in main)
fn0800_294F proc
	push	bp
	mov	bp,sp

;; fn0800_2952: 0800:2952
;;   Called from:
;;     0800:294D (in fn0800_2944)
;;     0800:2950 (in fn0800_294F)
fn0800_2952 proc
	call	2E1Ah
	mov	byte ptr [018Eh],0FFh
	jnz	2965h

l0800_295C:
	mov	ax,[01EBh]
	mov	al,[01E9h]
	mov	[07BAh],ax

l0800_2965:
	xor	ax,ax
	mov	bx,[bp+6h]
	cmp	bx,0FFh
	jz	2994h

l0800_296F:
	jg	29ADh

l0800_2971:
	cmp	bx,0FDh
	jl	298Dh

l0800_2976:
	mov	bl,[0745h]
	jz	2980h

l0800_297C:
	mov	bl,[0744h]

l0800_2980:
	xor	bh,bh
	or	bl,bl
	jnz	29ADh

l0800_2986:
	mov	byte ptr [0746h],0FEh
	jmp	2992h

l0800_298D:
	mov	byte ptr [0746h],0FCh

l0800_2992:
	jmp	2A0Fh

l0800_2994:
	xor	bx,bx
	cmp	[01CCh],bl
	jnz	29A4h

l0800_299C:
	mov	bl,[01E2h]
	mov	[01CCh],bl

l0800_29A4:
	mov	bl,[01E0h]
	mov	byte ptr [024Eh],1h

l0800_29AD:
	cmp	bx,13h
	jbe	29BDh

l0800_29B3:
	cmp	bx,40h
	jnz	298Dh

l0800_29B8:
	call	362Ah
	jmp	29C3h

l0800_29BD:
	shl	bx,1h
	call	word ptr [bx+190h]

l0800_29C3:
	mov	ax,0h
	jc	2986h

l0800_29C8:
	call	2C31h
	call	2C64h
	call	33AAh
	call	word ptr [0203h]
	call	339Ah
	jc	2A14h

l0800_29DA:
	call	2C31h
	call	2CC2h
	call	word ptr [0207h]
	call	2EF2h
	mov	[07AFh],ax
	mov	[07B1h],ax
	call	word ptr [0205h]
	call	33FAh
	jnz	2A08h

l0800_29F6:
	cmp	word ptr [bp+6h],0FFh
	jnz	2A05h

l0800_29FC:
	mov	ax,[01DEh]
	mov	[01DCh],ax
	call	3117h

l0800_2A05:
	call	30F7h

l0800_2A08:
	call	2CF2h
	and	al,[018Eh]

l0800_2A0F:
	call	2E3Bh
	pop	bp
	retf

l0800_2A14:
	mov	byte ptr [0746h],0FFh
	inc	byte ptr [018Eh]
	jnz	2A0Fh

l0800_2A1F:
	mov	bx,[07BAh]
	xchg	[01CCh],bh
	jmp	29ADh

;; fn0800_2A29: 0800:2A29
;;   Called from:
;;     0800:0020 (in main)
fn0800_2A29 proc
	push	bp
	mov	bp,sp
	mov	dx,[bp+6h]
	cmp	dx,0FFh
	jz	2A3Fh

l0800_2A34:
	mov	byte ptr [0746h],0FCh
	or	dh,dh
	jnz	2A74h

l0800_2A3D:
	mov	dh,dl

l0800_2A3F:
	xchg	[01ECh],dh
	cmp	dl,dh
	jz	2A6Fh

l0800_2A47:
	call	2C64h
	mov	[01ECh],dh
	cmp	dl,0FFh
	jz	2A5Ch

l0800_2A53:
	mov	byte ptr [0746h],3h
	cmp	dl,al
	jnz	2A74h

l0800_2A5C:
	xor	ah,ah
	mov	dx,ax
	mov	al,[01E9h]
	push	dx
	push	ax
	nop
	push	cs
	call	2944h
	add	sp,4h
	jmp	2A78h

l0800_2A6F:
	mov	byte ptr [0746h],0h

l0800_2A74:
	mov	al,[01ECh]
	cbw

l0800_2A78:
	pop	bp
	retf
0800:2A7A                               A1 55 07 33 DB 3C           .U.3.<
0800:2A80 01 74 40 BB 13 12 A8 08 74 05 F6 C4 10 75 34 B7 .t@.....t....u4.
0800:2A90 11 A8 10 75 2E B3 08 A8 20 75 26 BB 04 06 A8 02 ...u.... u&.....
0800:2AA0 75 18 B3 0F F6 C4 09 75 18 4B F6 C4 02 75 12 B7 u......u.K...u..
0800:2AB0 10 83 3E 57 07 40 76 02 8A DF A8 40 74 05 B7 40 ..>W.@v....@t..@
0800:2AC0 3D 8A FB 89 1E 44 07 C3                         =....D..

;; fn0800_2AC8: 0800:2AC8
;;   Called from:
;;     0800:0594 (in fn0800_0554)
fn0800_2AC8 proc
	push	bp
	mov	bp,sp
	push	di
	les	di,[bp+6h]
	cld
	xor	ax,ax
	mov	bx,ax
	mov	dx,ax
	mov	cx,20h
	mov	[0746h],al
	call	33FAh
	jz	2AF5h

l0800_2AE1:
	mov	al,[020Fh]
	mul	byte ptr [0210h]
	xchg	dx,ax
	mov	ax,[01EDh]
	mov	bx,[01EFh]
	mov	cl,[01F3h]
	inc	cx

l0800_2AF5:
	stosw
	xchg	bx,ax
	stosw
	xor	ax,ax
	mov	al,[01EBh]
	stosw
	mov	al,[01ECh]
	stosw
	xchg	cx,ax
	stosw
	xchg	dx,ax
	stosw
	mov	al,[01F8h]
	inc	ax
	stosw
	mov	al,[01E9h]
	stosw
	mov	al,[0755h]
	stosw
	mov	al,[0756h]
	stosw
	mov	ax,[0757h]
	stosw
	mov	ax,[bp+6h]
	mov	dx,es
	pop	di
	pop	bp
	retf
0800:2B23          00                                        .

;; fn0800_2B24: 0800:2B24
;;   Called from:
;;     0800:0070 (in fn0800_005D)
;;     0800:04A8 (in fn0800_0491)
;;     0800:0730 (in fn0800_06C8)
fn0800_2B24 proc
	push	bp
	mov	bp,sp
	call	2E1Ah
	mov	ax,[bp+6h]
	call	2FD1h
	call	2E3Bh
	pop	bp
	retf
0800:2B35                33 C0 A2 46 07 A0 8C 07 CB            3..F.....

;; fn0800_2B3E: 0800:2B3E
;;   Called from:
;;     0800:007C (in fn0800_005D)
fn0800_2B3E proc
	push	bp
	mov	bp,sp
	mov	byte ptr [0746h],0h
	mov	ax,[bp+6h]
	mov	dx,[bp+8h]
	call	2F3Eh
	pop	bp
	retf
0800:2B51    C6 06 46 07 00 A1 88 07 8B 16 8A 07 CB        ..F..........

;; fn0800_2B5E: 0800:2B5E
;;   Called from:
;;     0800:002F (in main)
fn0800_2B5E proc
	push	bp
	mov	bp,sp
	call	2E1Ah
	mov	ax,[bp+6h]
	cmp	ax,2h
	ja	2BB8h

l0800_2B6C:
	cmp	al,1h
	jz	2B9Eh

l0800_2B70:
	or	al,al
	mov	ax,600h
	jnz	2B93h

l0800_2B77:
	xor	bh,bh
	cmp	[01E8h],bh
	jnz	2B83h

l0800_2B7F:
	mov	bh,[078Dh]

l0800_2B83:
	xor	cx,cx
	mov	dl,[01EBh]
	dec	dx
	mov	dh,[01ECh]
	call	3199h
	jmp	2B96h

l0800_2B93:
	call	284Ch

l0800_2B96:
	call	2EF2h
	call	2EFBh
	jmp	2BB3h

l0800_2B9E:
	xor	ax,ax
	cmp	[01E8h],al
	jnz	2BADh

l0800_2BA6:
	mov	byte ptr [0746h],0FDh
	jmp	2BB3h

l0800_2BAD:
	mov	[0747h],al
	call	3760h

l0800_2BB3:
	call	2E3Bh
	pop	bp
	retf

l0800_2BB8:
	mov	byte ptr [0746h],0FCh
	jmp	2BB3h
0800:2BBF                                              00                .

;; fn0800_2BC0: 0800:2BC0
;;   Called from:
;;     0800:003B (in main)
;;     0800:030A (in fn0800_02CC)
;;     0800:031C (in fn0800_02CC)
fn0800_2BC0 proc
	push	bp
	mov	bp,sp
	call	2E1Ah
	pushf
	xor	ax,ax
	mov	al,[024Eh]
	mov	bx,[bp+6h]
	or	bl,bh
	jz	2BD5h

l0800_2BD3:
	mov	bl,0FFh

l0800_2BD5:
	mov	[024Eh],bl
	popf
	jnz	2BE2h

l0800_2BDC:
	push	ax
	call	30F7h
	pop	ax
	cmp	ax,0E8D0h

l0800_2BE2:
	shr	al,1h

l0800_2BE4:
	and	al,1h
	call	2E3Bh
	pop	bp
	retf
0800:2BEB                                  E8 2C 02 75 07            .,.u.
0800:2BF0 A1 E4 01 E8 45 02 CB C6 06 46 07 FD B8 FF FF EB ....E....F......
0800:2C00 F2 55 8B EC E8 13 02 75 19 FF 36 E4 01 8B 46 06 .U.....u..6...F.
0800:2C10 E8 29 05 A3 DC 01 E8 FE 04 E8 DB 04 58 E8 1B 02 .)..........X...
0800:2C20 5D CB C6 06 46 07 FD B8 FF FF EB F1 A0 46 07 98 ]...F........F..
0800:2C30 CB                                              .

;; fn0800_2C31: 0800:2C31
;;   Called from:
;;     0800:29C8 (in fn0800_2952)
;;     0800:29DA (in fn0800_2952)
fn0800_2C31 proc
	xor	dx,dx
	xchg	[01CCh],dl
	or	dl,dl
	jz	2C4Dh

l0800_2C3B:
	mov	[01ECh],dl
	call	2C64h
	cmp	dl,0FFh
	jnz	2C49h

l0800_2C47:
	mov	dl,al

l0800_2C49:
	cmp	dl,al
	jz	2C5Fh

l0800_2C4D:
	mov	dl,18h
	xor	cx,cx
	xor	bx,bx
	mov	ax,1130h
	push	es
	call	33E6h
	pop	es
	inc	dx
	xchg	cx,ax
	mul	dl

l0800_2C5F:
	mov	[01ECh],dl
	ret

;; fn0800_2C64: 0800:2C64
;;   Called from:
;;     0800:29CB (in fn0800_2952)
;;     0800:2A47 (in fn0800_2A29)
;;     0800:2C3F (in fn0800_2C31)
fn0800_2C64 proc
	mov	cx,[0755h]
	test	cl,1Ch
	jz	2CBCh

l0800_2C6D:
	mov	bx,1B8h
	mov	al,[01E9h]
	cmp	al,40h
	jz	2CBCh

l0800_2C77:
	xlat
	test	cl,8h
	jnz	2C87h

l0800_2C7D:
	test	cl,10h
	jnz	2C85h

l0800_2C82:
	and	al,5h
	cmp	ax,1324h

l0800_2C85:
	and	al,13h

l0800_2C87:
	xchg	bx,ax
	mov	al,[01ECh]
	cmp	al,0FFh
	jnz	2C91h

l0800_2C8F:
	mov	al,3Ch

l0800_2C91:
	cmp	al,3Ch
	jnz	2C9Ch

l0800_2C95:
	test	bl,10h
	jnz	2CBEh

l0800_2C9A:
	mov	al,32h

l0800_2C9C:
	cmp	al,32h
	jnz	2CA7h

l0800_2CA0:
	test	bl,8h
	jnz	2CBEh

l0800_2CA5:
	mov	al,2Bh

l0800_2CA7:
	cmp	al,2Bh
	jnz	2CB5h

l0800_2CAB:
	test	bl,4h
	jz	2CB5h

l0800_2CB0:
	test	ch,2h
	jz	2CBEh

l0800_2CB5:
	mov	al,1Eh
	test	bl,2h
	jnz	2CBEh

l0800_2CBC:
	mov	al,19h

l0800_2CBE:
	mov	[01ECh],al
	ret

;; fn0800_2CC2: 0800:2CC2
;;   Called from:
;;     0800:29DD (in fn0800_2952)
fn0800_2CC2 proc
	call	33FAh
	jnz	2CF1h

l0800_2CC7:
	mov	al,[01ECh]
	cmp	al,19h
	jz	2CEEh

l0800_2CCE:
	and	al,1h
	or	al,6h
	cmp	byte ptr [01EBh],28h
	jz	2CDBh

l0800_2CD9:
	shr	al,1h

l0800_2CDB:
	test	byte ptr [0755h],4h
	jz	2CEBh

l0800_2CE2:
	cmp	word ptr [0757h],40h
	ja	2CEBh

l0800_2CE9:
	shr	al,1h

l0800_2CEB:
	mov	[01F8h],al

l0800_2CEE:
	call	3993h

l0800_2CF1:
	ret

;; fn0800_2CF2: 0800:2CF2
;;   Called from:
;;     0800:2A08 (in fn0800_2952)
fn0800_2CF2 proc
	call	33FAh
	jz	2D1Eh

l0800_2CF7:
	call	530Bh
	mov	ax,[0872h]
	mov	[0784h],ax
	mov	ax,[0874h]
	mov	[0786h],ax
	mov	word ptr [078Eh],0FFFFh
	mov	byte ptr [074Fh],3h
	cmp	byte ptr [01E8h],1h
	jnz	2D1Eh

l0800_2D18:
	mov	ax,3h
	call	3034h

l0800_2D1E:
	xor	ax,ax
	mov	[0788h],ax
	mov	[078Ah],ax
	mov	al,[01F9h]
	call	2FD1h
	xor	ax,ax
	mov	[07B1h],ax
	mov	[07AFh],ax
	mov	[07B7h],al
	mov	[07B9h],al
	mov	[0798h],al
	mov	[0747h],al
	inc	ax
	mov	[07B8h],al
	mov	al,[01EBh]
	dec	ax
	mov	[07B5h],ax
	mov	al,[01ECh]
	dec	ax
	mov	[07B3h],ax
	inc	ax
	ret
0800:2D54             E8 26 26 33 C0 38 06 94 02 75 0B 8E     .&&3.8...u..
0800:2D60 C0 40 26 22 06 87 04 A2 48 07 E8 3D 04 B4 03 E8 .@&"....H..=....
0800:2D70 74 06 33 C0 86 F0 89 16 AD 07 A3 AB 07 8A 1E E9 t.3.............
0800:2D80 01 32 FF 80 FB 40 75 05 E8 9F 08 EB 06 D1 E3 FF .2...@u.........
0800:2D90 97 90 01 E8 9B FE E8 61 06 75 0D 0B C0 74 03 A3 .......a.u...t..
0800:2DA0 EF 01 A1 DC 01 E8 6F 03 E8 17 FF A1 E6 01 FF 16 ......o.........
0800:2DB0 05 02 E8 C5 FC E8 3A FF CB 80 3E 94 02 00 75 19 ......:...>...u.
0800:2DC0 F6 06 55 07 0C 74 12 33 C0 8E C0 A0 48 07 26 80 ..U..t.3....H.&.
0800:2DD0 26 87 04 FE 26 08 06 87 04 CB FF FF FF FF 00 2A &...&..........*
0800:2DE0 00 00 2A 00 00 00 2A 15 00 00 FF FF FF FF 00 2A ..*...*........*
0800:2DF0 2A 00 2A 00 2A 00 2A 2A 2A 00 FF FF FF FF 15 3F *.*.*.***......?
0800:2E00 15 00 3F 15 15 00 3F 3F 15 00 FF FF FF FF 15 3F ..?...??.......?
0800:2E10 3F 00 3F 15 3F 00 3F 3F 3F 00                   ?.?.?.???.

;; fn0800_2E1A: 0800:2E1A
;;   Called from:
;;     0800:275B (in fn0800_2756)
;;     0800:28E7 (in fn0800_28E4)
;;     0800:2952 (in fn0800_2952)
;;     0800:2B27 (in fn0800_2B24)
;;     0800:2B61 (in fn0800_2B5E)
;;     0800:2BC3 (in fn0800_2BC0)
fn0800_2E1A proc
	call	5390h
	cmp	byte ptr [01E8h],0h
	jz	2E35h

l0800_2E24:
	cmp	byte ptr [07B9h],0h
	jz	2E33h

l0800_2E2B:
	call	2E5Ch
	mov	byte ptr [07B9h],0h

l0800_2E33:
	or	sp,sp

l0800_2E35:
	mov	byte ptr [0746h],0h
	ret

;; fn0800_2E3B: 0800:2E3B
;;   Called from:
;;     0800:27D1 (in fn0800_2756)
;;     0800:2902 (in fn0800_28E4)
;;     0800:2A0F (in fn0800_2952)
;;     0800:2B30 (in fn0800_2B24)
;;     0800:2BB3 (in fn0800_2B5E)
;;     0800:2BE6 (in fn0800_2BC0)
fn0800_2E3B proc
	cmp	byte ptr [01E8h],0h
	jz	2E5Bh

l0800_2E42:
	cmp	byte ptr [024Eh],0h
	jge	2E5Bh

l0800_2E49:
	cmp	byte ptr [07B9h],0h
	jnz	2E5Bh

l0800_2E50:
	push	ax
	push	dx
	call	2E5Ch
	pop	dx
	pop	ax
	inc	byte ptr [07B9h]

l0800_2E5B:
	ret

;; fn0800_2E5C: 0800:2E5C
;;   Called from:
;;     0800:2E2B (in fn0800_2E1A)
;;     0800:2E52 (in fn0800_2E3B)
fn0800_2E5C proc
	call	2EFBh
	cmp	byte ptr [01E8h],2h
	ja	2E83h

l0800_2E66:
	xor	bx,bx
	mov	es,bx
	mov	bx,7Ch
	push	word ptr es:[bx+2h]
	push	word ptr es:[bx]
	push	es
	push	bx
	mov	word ptr es:[bx],1CEh
	mov	es:[bx+2h],ds
	mov	al,80h
	jmp	2E8Ch

l0800_2E83:
	cmp	word ptr [01E9h],13h
	jz	2EB5h

l0800_2E8A:
	mov	al,0DBh

l0800_2E8C:
	mov	bl,[078Dh]
	or	bl,80h
	mov	bh,[01E6h]
	mov	cx,1h
	push	bp
	push	si
	push	di
	mov	ah,9h
	int	10h
	pop	di
	pop	si
	pop	bp
	cmp	byte ptr [01E8h],2h
	ja	2EB4h

l0800_2EAB:
	pop	bx
	pop	es
	pop	word ptr es:[bx]
	pop	word ptr es:[bx+2h]

l0800_2EB4:
	ret

l0800_2EB5:
	mov	ax,[07AFh]
	add	ax,[07ABh]
	mov	dx,[07B1h]
	add	dx,[07ADh]
	mov	cl,3h
	shl	ax,cl
	shl	dx,cl
	mov	cx,dx
	mov	dx,ax
	call	word ptr [021Eh]
	mov	al,[078Dh]
	mov	ah,al
	les	bx,[075Ch]
	mov	cx,8h

l0800_2EDE:
	push	cx
	mov	cx,4h

l0800_2EE2:
	xor	es:[bx],ax
	inc	bx
	inc	bx
	loop	2EE2h

l0800_2EE9:
	pop	cx
	add	bx,138h
	loop	2EDEh

l0800_2EF0:
	jmp	2EB4h

;; fn0800_2EF2: 0800:2EF2
;;   Called from:
;;     0800:29E4 (in fn0800_2952)
;;     0800:2B96 (in fn0800_2B5E)
fn0800_2EF2 proc
	xor	ax,ax
	mov	[07ADh],ax
	mov	[07ABh],ax
	ret

;; fn0800_2EFB: 0800:2EFB
;;   Called from:
;;     0800:2762 (in fn0800_2756)
;;     0800:28E0 (in fn0800_2880)
;;     0800:2B99 (in fn0800_2B5E)
;;     0800:2E5C (in fn0800_2E5C)
fn0800_2EFB proc
	mov	dh,[07AFh]
	add	dh,[07ABh]
	mov	dl,[07B1h]
	add	dl,[07ADh]
	mov	bh,[01E6h]
	push	bp
	push	si
	push	di
	mov	ah,2h
	int	10h
	pop	di
	pop	si
	pop	bp
	ret
0800:2F1A                               8A 1E F3 01 0A E4           ......
0800:2F20 75 04 3A C3 76 09 8A C3 32 E4 C6 06 46 07 03 86 u.:.v...2...F...
0800:2F30 06 F9 01 C3                                     ....

l0800_2F34:
	and	ax,7h
	mov	byte ptr [0746h],3h
	jmp	2F60h

;; fn0800_2F3E: 0800:2F3E
;;   Called from:
;;     0800:2B4C (in fn0800_2B3E)
fn0800_2F3E proc
	push	si
	push	di
	mov	si,[0788h]
	mov	di,[078Ah]
	cmp	dx,di
	jnz	2F50h

l0800_2F4C:
	cmp	ax,si
	jz	2FCEh

l0800_2F50:
	cmp	byte ptr [01E8h],0h
	jnz	2F6Eh

l0800_2F57:
	or	dx,dx
	jnz	2F34h

l0800_2F5B:
	cmp	ax,7h
	ja	2F34h

l0800_2F60:
	mov	[0788h],ax
	mov	word ptr [078Ah],0h
	call	2FFAh
	jmp	2FCAh

l0800_2F6E:
	cmp	word ptr [01E9h],6h
	jz	2FB8h

l0800_2F75:
	cmp	word ptr [01E9h],40h
	jz	2FB8h

l0800_2F7C:
	call	5390h
	push	ax
	push	dx
	cmp	byte ptr [01E8h],1h
	jnz	2FAEh

l0800_2F88:
	test	byte ptr [0755h],1Ch
	jnz	2FAEh

l0800_2F8F:
	xor	bx,bx
	call	word ptr [020Bh]
	mov	bl,al
	jc	2FB4h

l0800_2F99:
	shl	al,1h
	and	al,10h
	or	bl,al
	xor	bh,bh
	push	bp
	push	si
	push	di
	mov	ah,0Bh
	int	10h
	pop	di
	pop	si
	pop	bp
	clc
	jmp	2FB4h

l0800_2FAE:
	xor	bl,bl
	call	word ptr [0209h]

l0800_2FB4:
	pop	dx
	pop	ax
	jnc	2FC3h

l0800_2FB8:
	mov	byte ptr [0746h],0FCh
	mov	ax,0FFFFh
	cwd
	jmp	2FCEh

l0800_2FC3:
	mov	[0788h],ax
	mov	[078Ah],dx

l0800_2FCA:
	mov	ax,si
	mov	dx,di

l0800_2FCE:
	pop	di
	pop	si
	ret

;; fn0800_2FD1: 0800:2FD1
;;   Called from:
;;     0800:2B2D (in fn0800_2B24)
;;     0800:2D29 (in fn0800_2CF2)
fn0800_2FD1 proc
	mov	bh,[01F3h]
	or	ah,ah
	jnz	2FE7h

l0800_2FD9:
	mov	bl,bh
	cmp	[01E8h],ah
	jnz	2FE3h

l0800_2FE1:
	mov	bl,1Fh

l0800_2FE3:
	cmp	al,bl
	jbe	2FF0h

l0800_2FE7:
	mov	al,bh
	xor	ah,ah
	mov	byte ptr [0746h],3h

l0800_2FF0:
	xchg	[078Ch],al
	push	ax
	call	2FFAh
	pop	ax
	ret

;; fn0800_2FFA: 0800:2FFA
;;   Called from:
;;     0800:2F69 (in fn0800_2F3E)
;;     0800:2FF5 (in fn0800_2FD1)
fn0800_2FFA proc
	mov	al,[078Ch]
	cmp	byte ptr [01E8h],0h
	jnz	3022h

l0800_3004:
	and	al,0Fh
	mov	bl,[078Ch]
	and	bl,10h
	mov	cl,3h
	shl	bl,cl
	or	al,bl
	mov	bl,[0788h]
	mov	cl,4h
	shl	bl,cl
	and	bl,70h
	or	al,bl
	jmp	3030h

l0800_3022:
	cmp	byte ptr [0210h],2h
	jnz	3030h

l0800_3029:
	call	word ptr [022Ah]
	mov	al,[075Bh]

l0800_3030:
	mov	[078Dh],al
	ret

;; fn0800_3034: 0800:3034
;;   Called from:
;;     0800:2D1B (in fn0800_2CF2)
fn0800_3034 proc
	push	si
	cmp	byte ptr [01E8h],4h
	jnz	305Ch

l0800_303C:
	cmp	ax,0Fh
	ja	3068h

l0800_3041:
	xor	bx,bx
	mov	es,bx
	mov	bl,es:[0466h]
	and	bl,0Fh
	xchg	bx,ax
	push	ax
	push	bp
	push	si
	push	di
	mov	ah,0Bh
	int	10h
	pop	di
	pop	si
	pop	bp
	pop	ax
	jmp	3073h

l0800_305C:
	cmp	byte ptr [01E8h],1h
	jnz	306Bh

l0800_3063:
	cmp	ax,3h
	jbe	3075h

l0800_3068:
	mov	al,0FCh
	cmp	ax,0FDB0h

l0800_306B:
	mov	al,0FDh

l0800_306D:
	mov	[0746h],al
	mov	ax,0FFFFh

l0800_3073:
	jmp	30DDh

l0800_3075:
	test	byte ptr [0755h],1Ch
	jz	3094h

l0800_307C:
	push	ax
	mov	bx,ax
	mov	cl,4h
	shl	bx,cl
	lea	si,[bx+2DDAh]
	push	cs
	pop	es
	call	word ptr [020Dh]
	pop	ax
	xchg	[074Ah],al
	jmp	30DDh

l0800_3094:
	sub	bx,bx
	mov	es,bx
	mov	ah,es:[0466h]
	push	ax
	mov	bh,1h
	mov	bl,al
	and	bl,1h
	push	bp
	push	si
	push	di
	mov	ah,0Bh
	int	10h
	pop	di
	pop	si
	pop	bp
	pop	ax
	push	ax
	and	al,2h
	mov	cl,3h
	shl	al,cl
	mov	bl,al
	and	ah,0Fh
	or	bl,ah
	mov	bh,0h
	push	bp
	push	si
	push	di
	mov	ah,0Bh
	int	10h
	pop	di
	pop	si
	pop	bp
	pop	ax
	mov	cl,4h
	sar	ah,cl
	mov	al,ah
	and	al,1h
	shl	al,1h
	and	ah,2h
	shr	ah,1h
	or	al,ah
	cbw

l0800_30DD:
	pop	si
	ret

;; fn0800_30DF: 0800:30DF
;;   Called from:
;;     0800:2924 (in fn0800_291A)
;;     0800:2934 (in fn0800_291A)
fn0800_30DF proc
	or	ax,ax
	jge	30EAh

l0800_30E3:
	sub	ax,ax
	mov	byte ptr [0746h],3h

l0800_30EA:
	cmp	ax,bx
	jl	30F6h

l0800_30EE:
	mov	ax,bx
	dec	ax
	mov	byte ptr [0746h],3h

l0800_30F6:
	ret

;; fn0800_30F7: 0800:30F7
;;   Called from:
;;     0800:2A05 (in fn0800_2952)
;;     0800:2BDD (in fn0800_2BC0)
fn0800_30F7 proc
	mov	dx,[07AFh]
	add	dx,[07ABh]
	inc	dx
	mov	dh,[07B1h]
	add	dh,[07ADh]
	inc	dh
	cmp	byte ptr [024Eh],0h
	jz	3114h

l0800_3111:
	jmp	346Fh

l0800_3114:
	jmp	3474h

;; fn0800_3117: 0800:3117
;;   Called from:
;;     0800:2A02 (in fn0800_2952)
fn0800_3117 proc
	mov	bx,[01EFh]
	shr	bx,1h
	mov	bh,64h
	call	314Bh
	mov	cx,2007h
	and	ch,ah
	and	ah,1Fh
	cmp	al,cl
	jc	3130h

l0800_312E:
	mov	al,cl

l0800_3130:
	cmp	ah,cl
	jc	3136h

l0800_3134:
	mov	ah,cl

l0800_3136:
	or	ah,ch
	mov	[01E4h],ax
	ret
0800:313C                                     A9 F8 D8 75             ...u
0800:3140 54 8B 1E EF 01 D1 EB B7 64 86 DF                T.......d..

;; fn0800_314B: 0800:314B
;;   Called from:
;;     0800:311F (in fn0800_3117)
fn0800_314B proc
	cmp	byte ptr [01ECh],19h
	jnz	3195h

l0800_3152:
	cmp	word ptr [01EFh],0C8h
	jz	3195h

l0800_315A:
	cmp	word ptr [01E9h],7h
	jz	3174h

l0800_3161:
	test	byte ptr [0755h],0Ch
	jz	3174h

l0800_3168:
	xor	cx,cx
	mov	es,cx
	test	byte ptr es:[0487h],1h
	jz	3195h

l0800_3174:
	mov	cl,ah
	mov	ch,cl
	and	cx,201Fh
	and	ax,1Fh
	cwd
	mov	dl,bl
	shr	dl,1h
	mul	bh
	add	ax,dx
	div	bl
	xchg	cl,al
	mul	bh
	add	ax,dx
	div	bl
	or	ch,al
	xchg	cx,ax

l0800_3195:
	and	ax,3F1Fh
	ret

;; fn0800_3199: 0800:3199
;;   Called from:
;;     0800:287C (in fn0800_284C)
;;     0800:2B8E (in fn0800_2B5E)
fn0800_3199 proc
	push	ax
	call	3406h
	pop	ax
	call	33E6h
	call	3400h
	mov	byte ptr [0747h],0h
	ret
0800:31AA                               33 DB 8E C3 26 A0           3...&.
0800:31B0 10 04 8A E0 A3 51 07 B4 0F E8 2A 02 8A D7 8A F7 .....Q....*.....
0800:31C0 A2 E0 01 8A CC A2 E9 01 89 16 E6 01 52 51 E8 26 ............RQ.&
0800:31D0 00 B0 30 33 DB 33 C9 BA 18 00 B4 11 E8 07 02 42 ..03.3.........B
0800:31E0 59 8A EA 5A 91 A3 EB 01 A3 E1 01 E8 3C 02 89 0E Y..Z........<...
0800:31F0 DE 01 89 0E DC 01 C3 50 53 51 57 B8 02 00 A2 55 .......PSQW....U
0800:3200 07 C7 06 57 07 10 00 A2 56 07 88 26 50 07 1E 07 ...W....V..&P...
0800:3210 BF BC 07 33 DB B4 1B E8 CC 01 3C 1B 75 43 8A 45 ...3......<.uC.E
0800:3220 25 3C 06 72 3C 8A 5D 31 8A 45 2D A2 53 07 C4 3D %<.r<.]1.E-.S..=
0800:3230 26 8B 05 A3 4C 07 26 8A 45 02 A2 4E 07 C6 06 55 &...L.&.E..N...U
0800:3240 07 10 C6 06 56 07 10 A8 04 74 56 C6 06 56 07 18 ....V....tV..V..
0800:3250 E8 E7 00 72 5A C6 06 55 07 08 C6 06 50 07 01 EB ...rZ..U....P...
0800:3260 40 B3 10 B4 12 E8 7E 01 F6 C3 FC 75 42 A0 52 07 @.....~....uB.R.
0800:3270 25 30 00 3C 30 75 02 FE C4 3A E7 75 32 C6 06 55 %0.<0u...:.u2..U
0800:3280 07 04 C6 06 50 07 01 80 E1 0F 80 F9 05 77 03 80 ....P........w..
0800:3290 C1 06 80 E9 09 72 0A B5 04 74 02 B5 01 88 2E 56 .....r...t.....V
0800:32A0 07 FE C3 32 FF B1 06 D3 E3 89 1E 57 07 EB 17 A0 ...2.......W....
0800:32B0 52 07 24 30 3C 30 75 0E FE 0E 56 07 FE 0E 55 07 R.$0<0u...V...U.
0800:32C0 C7 06 57 07 04 00 F6 06 55 07 0E 74 18 33 C0 E8 ..W.....U..t.3..
0800:32D0 9D 03 74 11 08 06 55 07 83 3E 57 07 20 77 06 C7 ..t...U..>W. w..
0800:32E0 06 57 07 20 00 BA FF FF B4 EF E8 F9 00 80 FA FF .W. ............
0800:32F0 74 20 F6 06 55 07 01 74 13 C6 06 55 07 20 C7 06 t ..U..t...U. ..
0800:3300 57 07 40 00 0A F6 75 0A D1 2E 57 07 BA BF 03 B0 W.@...u...W.....
0800:3310 01 EE 80 3E 55 07 02 75 1C 33 C9 C6 06 54 07 01 ...>U..u.3...T..
0800:3320 BA DA 03 EC 24 01 8A E0 EC 24 01 3A C4 E1 F9 75 ....$....$.:...u
0800:3330 04 88 0E 54 07 5F 59 5B 58 C3 33 C0 8E C0 26 A1 ...T._Y[X.3...&.
0800:3340 88 04 F6 C4 01 75 52 A8 08 75 02 34 02 26 8A 26 .....uR..u.4.&.&
0800:3350 10 04 88 26 52 07 80 E4 30 80 FC 30 74 02 34 02 ...&R...0..0t.4.
0800:3360 A8 02 74 24 80 FC 30 74 0D 81 26 4C 07 FF FE C6 ..t$..0t..&L....
0800:3370 06 56 07 10 EB 23 C6 06 4E 07 00 81 26 4C 07 00 .V...#..N...&L..
0800:3380 01 C6 06 56 07 08 EB 11 33 C0 A2 4E 07 A3 4C 07 ...V....3..N..L.
0800:3390 B0 02 A2 55 07 A2 56 07 F9 C3                   ...U..V...

;; fn0800_339A: 0800:339A
;;   Called from:
;;     0800:29D5 (in fn0800_2952)
fn0800_339A proc
	mov	ah,0Fh
	call	33E6h
	cmp	al,[01E9h]
	mov	ax,0h
	jz	33A9h

l0800_33A8:
	stc

l0800_33A9:
	ret

;; fn0800_33AA: 0800:33AA
;;   Called from:
;;     0800:29CE (in fn0800_2952)
fn0800_33AA proc
	cmp	byte ptr [0755h],8h
	jnz	33E4h

l0800_33B1:
	push	es
	xor	ax,ax
	mov	es,ax
	mov	ah,es:[0410h]
	or	ah,30h
	mov	al,[01E9h]
	and	al,7h
	sub	al,7h
	jz	33CCh

l0800_33C7:
	and	ah,0EFh
	mov	al,1h

l0800_33CC:
	mov	[0752h],ah
	mov	es:[0410h],ah
	pop	es
	test	byte ptr [0753h],4h
	jnz	33E4h

l0800_33DD:
	mov	bl,33h
	mov	ah,12h
	call	33E6h

l0800_33E4:
	ret
0800:33E5                00                                    .

;; fn0800_33E6: 0800:33E6
;;   Called from:
;;     0800:2C57 (in fn0800_2C31)
;;     0800:319E (in fn0800_3199)
;;     0800:339C (in fn0800_339A)
;;     0800:33E1 (in fn0800_33AA)
;;     0800:3486 (in fn0800_30F7)
;;     0800:348C (in fn0800_30F7)
fn0800_33E6 proc
	push	bp
	push	si
	push	di
	int	10h
	pop	di
	pop	si
	pop	bp
	ret

;; fn0800_33EF: 0800:33EF
;;   Called from:
;;     0800:5333 (in fn0800_5327)
fn0800_33EF proc
	mov	cx,[01EDh]
	dec	cx
	mov	dx,[01EFh]
	dec	dx
	ret

;; fn0800_33FA: 0800:33FA
;;   Called from:
;;     0800:29F1 (in fn0800_2952)
;;     0800:2ADC (in fn0800_2AC8)
;;     0800:2CC2 (in fn0800_2CC2)
;;     0800:2CF2 (in fn0800_2CF2)
;;     0800:532D (in fn0800_5327)
fn0800_33FA proc
	cmp	byte ptr [01E8h],0h
	ret

;; fn0800_3400: 0800:3400
;;   Called from:
;;     0800:31A1 (in fn0800_3199)
fn0800_3400 proc
	mov	al,ss:[01E7h]
	jmp	340Ah

;; fn0800_3406: 0800:3406
;;   Called from:
;;     0800:319A (in fn0800_3199)
fn0800_3406 proc
	mov	al,ss:[01E6h]

l0800_340A:
	push	dx
	mov	dx,ss:[01F6h]
	shl	dx,1h
	shl	dx,1h
	shl	dx,1h
	shl	dx,1h
	xor	ah,ah
	push	ds
	push	ax
	mul	dx
	mov	ds,dx
	mov	[044Eh],ax
	pop	ax
	mov	[0462h],al
	pop	ds
	pop	dx
	ret
0800:342A                               50 53 8A 3E E6 01           PS.>..
0800:3430 B4 03 E8 B1 FF 42 86 F2 42 F6 06 55 07 0C 74 2C .....B..B..U..t,
0800:3440 33 C0 38 06 94 02 75 24 8E C0 26 F6 06 87 04 01 3.8...u$..&.....
0800:3450 74 1A 52 26 8B 16 63 04 B8 0A 0B EE EB 00 42 EC t.R&..c.......B.
0800:3460 EB 00 86 C4 4A EE EB 00 42 EC 91 5A 5B 58 C3    ....J...B..Z[X.

l0800_346F:
	mov	ax,[01DCh]
	jmp	3477h

l0800_3474:
	mov	ax,2707h

l0800_3477:
	push	bx
	push	cx
	push	ax
	push	dx
	dec	dx
	xchg	dl,dh
	dec	dx
	mov	bh,[01E6h]
	push	ax
	mov	ah,2h
	call	33E6h
	pop	cx
	mov	ah,1h
	call	33E6h
	test	ch,20h
	jnz	34B1h

l0800_3494:
	test	byte ptr [0755h],4h
	jz	34B1h

l0800_349B:
	cmp	byte ptr [01ECh],19h
	jz	34B1h

l0800_34A2:
	xor	ax,ax
	mov	es,ax
	mov	dx,es:[0463h]
	xchg	cx,ax
	mov	al,0Ah
	call	357Ah

l0800_34B1:
	pop	dx
	pop	ax
	pop	cx
	pop	bx
	ret

;; fn0800_34B6: 0800:34B6
;;   Called from:
;;     0800:29BD (in fn0800_2952)
;;     0800:29BD (in fn0800_2952)
;;     0800:29BD (in fn0800_2952)
;;     0800:29BD (in fn0800_2952)
fn0800_34B6 proc
	stc
	ret

;; fn0800_34B8: 0800:34B8
;;   Called from:
;;     0800:3638 (in fn0800_362A)
;;     0800:391B (in fn0800_3917)
;;     0800:3B5D (in fn0800_3B4B)
;;     0800:3B8F (in fn0800_3B7B)
;;     0800:3F3F (in fn0800_3F35)
;;     0800:3F6E (in fn0800_3F50)
;;     0800:482E (in fn0800_47F5)
;;     0800:482E (in fn0800_481A)
;;     0800:482E (in fn0800_4833)
;;     0800:5240 (in fn0800_5232)
fn0800_34B8 proc
	push	si
	push	di
	push	es
	push	ds
	push	ds
	pop	es
	cmp	cx,27h
	jnz	34D0h

l0800_34C3:
	push	cx
	mov	di,21Eh
	mov	cx,17h
	mov	ax,34B6h

l0800_34CD:
	rep stosw

l0800_34CF:
	pop	cx

l0800_34D0:
	mov	di,1E8h
	push	cs
	pop	ds
	mov	si,bx
	cld
	rep movsb
	push	es
	pop	ds
	mov	al,[01F9h]
	call	word ptr [022Ah]
	mov	byte ptr [077Ah],0h
	pop	ds
	pop	es
	pop	di
	pop	si
	ret

;; fn0800_34ED: 0800:34ED
;;   Called from:
;;     0800:5364 (in fn0800_5327)
;;     0800:5364 (in fn0800_3760)
fn0800_34ED proc
	push	di
	push	word ptr [075Ch]
	push	bx
	push	ax
	xor	ah,ah
	mov	al,[075Ah]
	mov	di,ax
	push	dx
	mov	dx,cx
	xor	cx,cx
	call	word ptr [021Eh]
	mov	cx,[075Ch]
	add	cx,[0211h]
	mov	[076Ch],cx
	pop	dx
	xor	cx,cx
	call	word ptr [021Eh]
	mov	cx,[075Ch]
	mov	[076Eh],cx
	pop	ax
	mov	cx,ax
	xor	dx,dx
	call	word ptr [021Eh]
	mov	cx,[075Ch]
	mov	[0770h],cx
	mov	cl,[075Ah]
	mov	[0774h],cl
	pop	bx
	mov	cx,bx
	xor	dx,dx
	call	word ptr [021Eh]
	mov	cx,[075Ch]
	mov	[0772h],cx
	mov	cl,[075Ah]
	mov	[0775h],cl
	mov	ax,di
	mov	[075Ah],al
	pop	word ptr [075Ch]
	pop	di
	ret
0800:355C                                     50 8C D8 80             P...
0800:3560 C4 10 8E D8 58 C3 50 8C C0 80 C4 10 8E C0 58 C3 ....X.P.......X.
0800:3570 50 8C D8 80 EC 10 8E D8 58 C3                   P.......X.

;; fn0800_357A: 0800:357A
;;   Called from:
;;     0800:34AE (in fn0800_30F7)
fn0800_357A proc
	out	dx,al
	xchg	ah,al
	inc	dx
	out	dx,al
	dec	dx
	ret
0800:3581    50 52 BA C4 03 B0 02 EE 42 B0 0F EE BA CE 03  PR......B......
0800:3590 B0 01 EE 42 32 C0 EE 4A B0 02 EE 42 32 C0 EE 4A ...B2..J...B2..J
0800:35A0 B8 03 00 EE 42 32 C0 EE 4A B0 08 EE 42 B0 FF EE ....B2..J...B...
0800:35B0 4A B0 07 EE 42 B0 0F EE 4A B0 05 EE 42 A0 FA 01 J...B...J...B...
0800:35C0 24 10 EE 5A 58 C3 04 40 00 50 19 80 02 90 01 00 $..ZX..@.P......
0800:35D0 B8 01 0F 20 00 08 00 01 00 CE 4B 00 08 D0 4B 00 ... ......K...K.
0800:35E0 08 4F 36 E1 4B B6 34 B6 34 B6 34 B6 34 01 01 50 .O6.K.4.4.4.4..P
0800:35F0 00 80 01 08 00 03 07 00 D5 00 33 01 57 36 46 51 ..........3.W6FQ
0800:3600 53 51 6A 51 7C 51 93 51 D6 4B 21 4C 3C 4C 4D 4C SQjQ|Q.Q.K!L<LML
0800:3610 63 4C 67 4C 02 50 97 50 EB 50 7C 4C B1 4C D7 4C cLgL.P.P.P|L.L.L
0800:3620 39 4D A5 51 F7 4D 54 4E E8 4E                   9M.Q.MTN.N

;; fn0800_362A: 0800:362A
;;   Called from:
;;     0800:29B8 (in fn0800_2952)
fn0800_362A proc
	test	byte ptr [0755h],40h
	stc
	jz	364Eh

l0800_3632:
	mov	bx,35C6h
	mov	cx,64h
	call	34B8h
	mov	word ptr [0852h],2000h
	mov	word ptr [0854h],5FB0h
	mov	word ptr [0856h],7FB0h
	clc

l0800_364E:
	ret
0800:364F                                              B0                .
0800:3650 40 B4 00 E8 90 FD C3 B8 03 00 23 C2 33 D0 D1 C8 @.........#.3...
0800:3660 D1 C8 D1 E8 8B DA D1 E2 D1 E2 03 D3 E9 92 15 1E ................
0800:3670 B8 00 FC 8E D8 81 3E 50 00 4F 4C 75 58 81 3E 52 ......>P.OLuX.>R
0800:3680 00 49 56 75 50 B4 F0 8E D8 A1 FD FF 3D 46 FF 74 .IVuP.......=F.t
0800:3690 44 3D 00 FE 74 3F B8 00 C0 8E D8 81 3E 00 00 55 D=..t?......>..U
0800:36A0 AA 75 2C 81 3E 3C 00 50 41 74 24 81 3E 10 00 4F .u,.><.PAt$.>..O
0800:36B0 4C 75 22 A1 22 00 3D 56 47 74 14 3D 45 47 75 15 Lu".".=VGt.=EGu.
0800:36C0 33 C0 8E D8 A1 88 04 25 A0 00 3D A0 00 74 06 B0 3......%..=..t..
0800:36D0 3F FE C0 EB 02 32 C0 1F C3 00                   ?....2....

;; fn0800_36DA: 0800:36DA
;;   Called from:
;;     0800:27EF (in fn0800_27D8)
;;     0800:27FA (in fn0800_27D8)
fn0800_36DA proc
	cmp	byte ptr ss:[01E8h],0h
	jnz	371Fh

l0800_36E2:
	push	es
	call	3732h
	mov	ah,bl
	cmp	byte ptr ss:[0755h],2h
	jnz	3719h

l0800_36F0:
	test	byte ptr ss:[0754h],1h
	jz	3719h

l0800_36F8:
	push	dx
	mov	dx,3DAh

l0800_36FC:
	sti
	nop
	cli
	in	al,dx
	test	al,8h
	jnz	3717h

l0800_3704:
	test	al,1h
	jnz	36FCh

l0800_3708:
	lodsb
	xchg	bx,ax

l0800_370A:
	in	al,dx
	test	al,1h
	jz	370Ah

l0800_370F:
	xchg	bx,ax
	stosw
	loop	36FCh

l0800_3713:
	sti
	pop	dx
	pop	es
	ret

l0800_3717:
	sti
	pop	dx

l0800_3719:
	lodsb
	stosw
	loop	3719h

l0800_371D:
	pop	es
	ret

l0800_371F:
	mov	di,cx
	mov	cx,1h

l0800_3724:
	lodsb
	mov	ah,9h
	int	10h
	inc	dx
	mov	ah,2h
	int	10h
	dec	di
	jnz	3724h

l0800_3731:
	ret

;; fn0800_3732: 0800:3732
;;   Called from:
;;     0800:36E3 (in fn0800_36DA)
fn0800_3732 proc
	xor	ax,ax
	mov	es,ax
	mov	al,bh
	xchg	di,ax
	shl	di,1h
	mov	ax,dx
	add	al,cl
	mov	es:[di+450h],ax
	mov	al,ss:[01EBh]
	mul	ah
	add	al,dl
	adc	ah,0h
	shl	ax,1h
	add	ax,ss:[di+83Ch]
	xchg	di,ax
	mov	es,ss:[01F1h]
	add	dl,cl
	ret
0800:375F                                              00                .

;; fn0800_3760: 0800:3760
;;   Called from:
;;     0800:2BB0 (in fn0800_2B5E)
fn0800_3760 proc
	call	word ptr [022Ah]
	mov	ax,[0864h]
	mov	[087Ah],ax
	mov	ax,[0868h]
	mov	[087Ch],ax
	mov	cx,[0862h]
	mov	dx,[0866h]
	call	377Eh
	jmp	5354h

;; fn0800_377E: 0800:377E
;;   Called from:
;;     0800:3778 (in fn0800_3760)
fn0800_377E proc
	call	37D4h
	jc	37CDh

l0800_3783:
	call	3846h
	xchg	[087Ah],cx
	xchg	[087Ch],dx
	call	3846h
	call	3889h
	jnc	379Ah

l0800_3796:
	xchg	[087Ch],dx

l0800_379A:
	inc	bx
	push	bp
	push	bx
	call	387Eh
	jnc	37A6h

l0800_37A2:
	xchg	[087Ah],cx

l0800_37A6:
	mov	al,dl
	and	al,7h
	mov	[0896h],al
	inc	bx
	push	bx
	call	word ptr [021Eh]
	pop	bx
	pop	cx

l0800_37B5:
	push	cx
	push	bx
	call	word ptr [0242h]
	call	word ptr [0228h]
	pop	bx
	pop	cx
	inc	byte ptr [0896h]
	and	byte ptr [0896h],7h
	loop	37B5h

l0800_37CC:
	pop	bp

l0800_37CD:
	mov	word ptr [0886h],0FFFFh
	ret

;; fn0800_37D4: 0800:37D4
;;   Called from:
;;     0800:377E (in fn0800_377E)
fn0800_37D4 proc
	push	dx
	mov	ax,[087Ah]
	mov	dx,cx
	cmp	ax,dx
	jge	37DFh

l0800_37DE:
	xchg	dx,ax

l0800_37DF:
	mov	[077Ch],ax
	mov	[077Eh],dx
	pop	dx
	push	dx
	mov	ax,[087Ch]
	cmp	ax,dx
	jge	37F0h

l0800_37EF:
	xchg	dx,ax

l0800_37F0:
	mov	[0780h],ax
	mov	[0782h],dx
	call	37FCh
	pop	dx
	ret

;; fn0800_37FC: 0800:37FC
;;   Called from:
;;     0800:37F7 (in fn0800_37D4)
fn0800_37FC proc
	mov	ax,[077Ch]
	cmp	ax,[0862h]
	jl	3822h

l0800_3805:
	mov	ax,[0864h]
	cmp	ax,[077Eh]
	jl	3822h

l0800_380E:
	mov	ax,[0780h]
	cmp	ax,[0866h]
	jl	3822h

l0800_3817:
	mov	ax,[0868h]
	cmp	ax,[0782h]
	jl	3822h

l0800_3820:
	clc
	ret

l0800_3822:
	stc
	ret

;; fn0800_3824: 0800:3824
;;   Called from:
;;     0800:3846 (in fn0800_3846)
fn0800_3824 proc
	xor	al,al
	cmp	[0862h],cx
	jle	382Dh

l0800_382C:
	inc	ax

l0800_382D:
	cmp	[0864h],cx
	jge	3835h

l0800_3833:
	or	al,2h

l0800_3835:
	cmp	[0866h],dx
	jle	383Dh

l0800_383B:
	or	al,4h

l0800_383D:
	cmp	[0868h],dx
	jge	3845h

l0800_3843:
	or	al,8h

l0800_3845:
	ret

;; fn0800_3846: 0800:3846
;;   Called from:
;;     0800:3783 (in fn0800_377E)
;;     0800:378E (in fn0800_377E)
fn0800_3846 proc
	call	3824h
	or	al,al
	jz	3879h

l0800_384D:
	mov	byte ptr [0746h],2h
	mov	bx,[0862h]
	test	al,1h
	jnz	3862h

l0800_385A:
	mov	bx,[0864h]
	test	al,2h
	jz	3864h

l0800_3862:
	mov	cx,bx

l0800_3864:
	lahf
	mov	bx,[0866h]
	test	al,4h
	jnz	3875h

l0800_386D:
	mov	bx,[0868h]
	test	al,8h
	jz	3878h

l0800_3875:
	lahf
	mov	dx,bx

l0800_3878:
	sahf

l0800_3879:
	stc
	jz	387Dh

l0800_387C:
	cmc

l0800_387D:
	ret

;; fn0800_387E: 0800:387E
;;   Called from:
;;     0800:379D (in fn0800_377E)
fn0800_387E proc
	mov	bx,[087Ah]
	sub	bx,cx

;; fn0800_3884: 0800:3884
;;   Called from:
;;     0800:3882 (in fn0800_387E)
;;     0800:388F (in fn0800_3889)
fn0800_3884 proc
	jnc	3888h

l0800_3886:
	neg	bx

l0800_3888:
	ret

;; fn0800_3889: 0800:3889
;;   Called from:
;;     0800:3791 (in fn0800_377E)
fn0800_3889 proc
	mov	bx,[087Ch]
	sub	bx,dx
	jmp	3884h
0800:3891    00 00 00 00 28 19 40 01 C8 00 00 B8 0F 3F 02  ....(.@......?.
0800:38A0 80 00 07 07 00 5A 5C 00 08 F5 44 00 08 C3 39 33 .....Z\...D...93
0800:38B0 3A 80 5C B7 5C EC 5C 47 5D 00 02 00 50 19 80 02 :.\.\.\G]...P...
0800:38C0 C8 00 00 B8 0F 3F 04 00 01 03 07 00 5A 5C 00 08 .....?......Z\..
0800:38D0 F5 44 00 08 C3 39 33 3A 80 5C B7 5C EC 5C 47 5D .D...93:.\.\.\G]
0800:38E0 00 07 00 50 19 D0 02 5E 01 00 B0 0F 02 04 00 01 ...P...^........
0800:38F0 00 07 00 07 39 00 08 00 00 00 00 C3 39 33 3A 87 ....9.......93:.
0800:3900 5C BE 5C 43 3A 47 5D 00 08 08 08 08 08 08 08 00 \.\C:G].........
0800:3910 18 18 18 18 18 18 18                            .......

;; fn0800_3917: 0800:3917
;;   Called from:
;;     0800:396E (in fn0800_396E)
;;     0800:3991 (in fn0800_3984)
fn0800_3917 proc
	mov	cx,27h
	push	ax
	call	34B8h
	pop	ax
	mov	[01E9h],ax
	test	byte ptr [0755h],23h
	jnz	394Fh

l0800_3929:
	mov	ah,7h
	test	byte ptr [0755h],4h
	jz	393Fh

l0800_3932:
	cmp	word ptr [0757h],40h
	ja	393Fh

l0800_3939:
	cmp	al,1h
	jbe	393Fh

l0800_393D:
	shr	ah,1h

l0800_393F:
	mov	[01F8h],ah
	test	byte ptr [0756h],2h
	jz	394Fh

l0800_394A:
	mov	byte ptr [01F4h],0Fh

l0800_394F:
	cmp	al,7h
	jz	3960h

l0800_3953:
	test	byte ptr [0756h],1Ch
	jz	3960h

l0800_395A:
	mov	word ptr [01FBh],5C6Ah

l0800_3960:
	clc
	ret

;; fn0800_3962: 0800:3962
;;   Called from:
;;     0800:29BD (in fn0800_2952)
fn0800_3962 proc
	xor	ax,ax

;; fn0800_3964: 0800:3964
;;   Called from:
;;     0800:3962 (in fn0800_3962)
;;     0800:3975 (in fn0800_3972)
fn0800_3964 proc
	mov	bx,3892h

;; fn0800_3967: 0800:3967
;;   Called from:
;;     0800:3964 (in fn0800_3964)
;;     0800:397D (in fn0800_397A)
;;     0800:397D (in fn0800_397A)
fn0800_3967 proc
	test	byte ptr [0756h],16h
	jz	3970h

;; fn0800_396E: 0800:396E
;;   Called from:
;;     0800:396C (in fn0800_3967)
;;     0800:396C (in fn0800_3964)
;;     0800:396C (in fn0800_3967)
fn0800_396E proc
	jmp	3917h

l0800_3970:
	stc
	ret

;; fn0800_3972: 0800:3972
;;   Called from:
;;     0800:29BD (in fn0800_2952)
fn0800_3972 proc
	mov	ax,101h
	jmp	3964h

;; fn0800_3977: 0800:3977
;;   Called from:
;;     0800:29BD (in fn0800_2952)
fn0800_3977 proc
	mov	ax,2h

;; fn0800_397A: 0800:397A
;;   Called from:
;;     0800:3977 (in fn0800_3977)
;;     0800:3982 (in fn0800_397F)
fn0800_397A proc
	mov	bx,38B9h
	jmp	3967h

;; fn0800_397F: 0800:397F
;;   Called from:
;;     0800:29BD (in fn0800_2952)
fn0800_397F proc
	mov	ax,103h
	jmp	397Ah

;; fn0800_3984: 0800:3984
;;   Called from:
;;     0800:29BD (in fn0800_2952)
fn0800_3984 proc
	test	byte ptr [0756h],9h
	jz	3970h

l0800_398B:
	mov	ax,7h
	mov	bx,38E0h
	jmp	3917h

;; fn0800_3993: 0800:3993
;;   Called from:
;;     0800:2CEE (in fn0800_2CC2)
fn0800_3993 proc
	cmp	byte ptr [01ECh],19h
	jz	39A9h

l0800_399A:
	xor	ax,ax
	mov	es,ax
	mov	ax,es:[044Ch]
	mov	cl,4h
	shr	ax,cl
	mov	[01F6h],ax

l0800_39A9:
	push	di
	mov	di,83Ch
	mov	bx,[01F6h]
	mov	cl,4h
	shl	bx,cl
	xor	ax,ax
	mov	cx,8h
	push	ds
	pop	es

l0800_39BC:
	stosw
	add	ax,bx
	loop	39BCh

l0800_39C1:
	pop	di
	ret
0800:39C3          F6 06 55 07 58 74 2A C7 06 EF 01 90 01    ..U.Xt*......
0800:39D0 F6 06 55 07 18 74 1D B8 02 12 80 3E EC 01 2B 75 ..U..t.....>..+u
0800:39E0 09 B8 01 12 C7 06 EF 01 5E 01 B3 30 55 56 57 CD ........^..0UVW.
0800:39F0 10 5F 5E 5D A0 E9 01 55 56 57 B4 00 CD 10 5F 5E ._^]...UVW...._^
0800:3A00 5D 80 3E EC 01 32 74 14 F6 06 56 07 05 74 06 C7 ].>..2t...V..t..
0800:3A10 06 EF 01 5E 01 80 3E EC 01 2B 75 0D B8 12 11 32 ...^..>..+u....2
0800:3A20 DB 55 56 57 CD 10 5F 5E 5D A1 E4 01 E8 0D F7 A3 .UVW.._^].......
0800:3A30 DC 01 C3 A3 E6 01 8A C4 55 56 57 B4 05 CD 10 5F ........UVW...._
0800:3A40 5E 5D C3 3A 1E F3 01 77 18 0A F2 0A F4 75 10 3A ^].:...w.....u.:
0800:3A50 06 F4 01 77 0C 3C 01 72 06 B0 08 74 02 B0 18 F8 ...w.<.r...t....
0800:3A60 C3 F9 C3 00 01 04 00 28 19 40 01 C8 00 00 B8 03 .......(.@......
0800:3A70 0F 10 00 04 00 03 00 2C 3B 00 08 30 3B 00 08 B9 .......,;..0;...
0800:3A80 3B E1 4B 80 5C D7 3B EC 5C 47 5D 02 01 50 00 C0 ;.K.\.;.\G]..P..
0800:3A90 03 04 00 02 03 00 D5 00 33 01 40 3C 42 51 53 51 ........3.@<BQSQ
0800:3AA0 6A 51 7C 51 93 51 76 3C 21 4C 3C 4C 4D 4C 63 4C jQ|Q.Qv<!L<LMLcL
0800:3AB0 67 4C 02 50 97 50 EB 50 7C 4C B1 4C D7 4C 39 4D gL.P.P.P|L.L.L9M
0800:3AC0 A5 51 F7 4D 54 4E E8 4E 02 06 00 50 19 80 02 C8 .Q.MTN.N...P....
0800:3AD0 00 00 B8 01 0F 10 00 04 00 01 00 CE 4B 00 08 D0 ............K...
0800:3AE0 4B 00 08 B9 3B E1 4B 80 5C B7 5C EC 5C 47 5D 01 K...;.K.\.\.\G].
0800:3AF0 01 50 00 80 01 08 00 03 07 00 6B 00 66 02 EB 4B .P........k.f..K
0800:3B00 46 51 53 51 6A 51 7C 51 93 51 D6 4B 21 4C 3C 4C FQSQjQ|Q.Q.K!L<L
0800:3B10 4D 4C 63 4C 67 4C 02 50 97 50 EB 50 7C 4C B1 4C MLcLgL.P.P.P|L.L
0800:3B20 D7 4C 39 4D A5 51 F7 4D 54 4E E8 4E 00 3B 3D 3F .L9M.Q.MTN.N.;=?
0800:3B30 00 00 00 15 3F 3F 3F 15 3F 3F 3F 3F             ....???.????

;; fn0800_3B3C: 0800:3B3C
;;   Called from:
;;     0800:29BD (in fn0800_2952)
fn0800_3B3C proc
	mov	ax,101h
	jmp	3B44h

;; fn0800_3B41: 0800:3B41
;;   Called from:
;;     0800:29BD (in fn0800_2952)
fn0800_3B41 proc
	mov	ax,1h

;; fn0800_3B44: 0800:3B44
;;   Called from:
;;     0800:3B3F (in fn0800_3B3C)
;;     0800:3B41 (in fn0800_3B41)
fn0800_3B44 proc
	test	byte ptr [0755h],1Eh
	jz	3B79h

;; fn0800_3B4B: 0800:3B4B
;;   Called from:
;;     0800:3B49 (in fn0800_3B44)
;;     0800:3B49 (in fn0800_3B44)
;;     0800:3B49 (in fn0800_3B44)
fn0800_3B4B proc
	test	byte ptr [0756h],16h
	jz	3B79h

l0800_3B52:
	mov	al,ah
	add	al,4h
	mov	bx,3A64h
	mov	cx,64h
	push	ax
	call	34B8h
	pop	ax
	mov	[01E9h],ax
	test	byte ptr [0755h],10h
	jz	3B77h

l0800_3B6B:
	mov	word ptr [01FFh],44F5h
	mov	word ptr [020Bh],3C25h

l0800_3B77:
	jmp	3BA5h

l0800_3B79:
	stc
	ret

;; fn0800_3B7B: 0800:3B7B
;;   Called from:
;;     0800:29BD (in fn0800_2952)
fn0800_3B7B proc
	test	byte ptr [0755h],1Eh
	jz	3B79h

l0800_3B82:
	test	byte ptr [0756h],16h
	jz	3B79h

l0800_3B89:
	mov	bx,3AC8h
	mov	cx,64h
	call	34B8h
	test	byte ptr [0755h],10h
	jz	3BA5h

l0800_3B99:
	mov	word ptr [01FFh],44F5h
	mov	word ptr [020Bh],48E4h

l0800_3BA5:
	mov	word ptr [0852h],2000h
	mov	word ptr [0854h],1FB0h
	mov	word ptr [0856h],3FB0h
	clc
	ret
0800:3BB9                            A0 E9 01 B4 00 E8 25          ......%
0800:3BC0 F8 80 3E E8 01 01 75 0E F6 06 55 07 0C 74 07 33 ..>...u...U..t.3
0800:3BD0 DB B4 0B E8 10 F8 C3 3D FF FF 75 04 3B D0 74 44 .......=..u.;.tD
0800:3BE0 50 52 53 E8 D1 20 5B 5A 58 72 39 0A DB 75 35 E8 PRS.. [ZXr9..u5.
0800:3BF0 FA 20 F6 06 55 07 18 74 16 B3 10 86 F0 86 EC 86 . ..U..t........
0800:3C00 CA B0 10 55 56 57 B4 10 CD 10 5F 5E 5D EB 15 80 ...UVW...._^]...
0800:3C10 3E 50 07 00 74 0E 8A F8 B0 01 55 56 57 B4 10 CD >P..t.....UVW...
0800:3C20 10 5F 5E 5D C3 80 FB 03 77 14 D0 E3 74 03 80 C3 ._^]....w...t...
0800:3C30 09 F7 C2 C0 FF 75 07 A9 C0 C0 75 02 F8 C3 F9 C3 .....u....u.....
0800:3C40 33 C0 D1 EA D1 D8 D1 E8 D1 E8 8B DA D1 E2 D1 E2 3...............
0800:3C50 03 D3 D1 E2 D1 E2 D1 E2 D1 E2 03 D0 8B C1 D1 E8 ................
0800:3C60 D1 E8 03 D0 89 16 5C 07 80 E1 03 D0 E1 B5 C0 D2 ......\.........
0800:3C70 ED 88 2E 5A 07 C3 50 3A 06 F3 01 76 03 A0 F3 01 ...Z..P:...v....
0800:3C80 B1 02 8A E0 D2 E4 0A C4 D2 E4 0A C4 D2 E4 0A C4 ................
0800:3C90 A2 5B 07 58 C3 00 07 0D 00 28 19 40 01 C8 00 00 .[.X.....(.@....
0800:3CA0 A0 0F 0F 20 00 02 00 0F 02 5A 5C 00 08 F5 44 00 ... .....Z\...D.
0800:3CB0 08 86 3F AD 3F 80 5C B7 5C EC 5C 47 5D 01 04 28 ..?.?.\.\.\G]..(
0800:3CC0 00 80 01 08 00 03 07 00 D5 00 33 01 9E 53 D2 53 ..........3..S.S
0800:3CD0 DE 53 E9 53 F2 53 FD 53 06 54 16 54 66 54 92 54 .S.S.S.S.T.TfT.T
0800:3CE0 A6 54 81 35 BA 54 F9 54 22 55 4A 55 72 55 A7 55 .T.5.T.T"UJUrU.U
0800:3CF0 3D 56 E4 56 66 57 F4 5A AA 5B 08 0E 00 50 19 80 =V.VfW.Z.[...P..
0800:3D00 02 C8 00 00 A0 0F 0F 40 00 04 00 0F 02 5A 5C 00 .......@.....Z\.
0800:3D10 08 F5 44 00 08 86 3F AD 3F 80 5C B7 5C EC 5C 47 ..D...?.?.\.\.\G
0800:3D20 5D 01 04 50 00 80 01 08 00 03 07 00 6B 00 66 02 ]..P........k.f.
0800:3D30 A8 53 D2 53 DE 53 E9 53 F2 53 FD 53 06 54 16 54 .S.S.S.S.S.S.T.T
0800:3D40 66 54 92 54 A6 54 81 35 BA 54 F9 54 22 55 4A 55 fT.T.T.5.T.T"UJU
0800:3D50 72 55 A7 55 3D 56 F3 56 66 57 F4 5A AA 5B 0A 0F rU.U=V.VfW.Z.[..
0800:3D60 00 50 19 80 02 5E 01 00 A0 03 08 40 00 08 00 03 .P...^.....@....
0800:3D70 02 EE 3E 00 08 00 00 00 00 86 3F AD 3F 87 5C CB ..>.......?.?.\.
0800:3D80 3F 18 40 47 5D 01 02 50 00 80 01 08 00 03 07 00 ?.@G]..P........
0800:3D90 BB 00 5F 01 A8 53 D2 53 DE 53 E9 53 F2 53 FD 53 .._..S.S.S.S.S.S
0800:3DA0 57 40 4A 54 66 54 92 54 A6 54 81 35 BA 54 F9 54 W@JTfT.T.T.5.T.T
0800:3DB0 22 55 47 55 70 55 A2 55 3D 56 F3 56 66 57 F4 40 "UGUpU.U=V.VfW.@
0800:3DC0 E0 41 0A 0F 00 50 19 80 02 5E 01 00 A0 03 08 40 .A...P...^.....@
0800:3DD0 00 08 00 03 12 EE 3E 00 08 00 00 00 00 86 3F AD ......>.......?.
0800:3DE0 3F 87 5C CB 3F 18 40 47 5D 01 02 50 00 80 01 08 ?.\.?.@G]..P....
0800:3DF0 00 03 07 00 BB 00 5F 01 A8 53 D2 53 DE 53 E9 53 ......_..S.S.S.S
0800:3E00 F2 53 FD 53 57 40 55 54 66 54 92 54 A6 54 81 35 .S.SW@UTfT.T.T.5
0800:3E10 BA 54 F9 54 22 55 44 55 CD 42 38 43 3D 56 F3 56 .T.T"UDU.B8C=V.V
0800:3E20 66 57 F4 40 E0 41 09 10 00 50 19 80 02 5E 01 00 fW.@.A...P...^..
0800:3E30 A0 0F 3F 80 00 08 00 0F 02 6A 5C 00 08 F5 44 00 ..?......j\...D.
0800:3E40 08 86 3F AD 3F 80 5C B7 5C EC 5C 47 5D 01 04 50 ..?.?.\.\.\G]..P
0800:3E50 00 80 01 08 00 03 07 00 BB 00 5F 01 A8 53 D2 53 .........._..S.S
0800:3E60 DE 53 E9 53 F2 53 FD 53 06 54 16 54 66 54 92 54 .S.S.S.S.T.TfT.T
0800:3E70 A6 54 81 35 BA 54 F9 54 22 55 4A 55 72 55 A7 55 .T.5.T.T"UJUrU.U
0800:3E80 3D 56 F3 56 66 57 F4 5A AA 5B 09 10 00 50 19 80 =V.VfW.Z.[...P..
0800:3E90 02 5E 01 00 A0 03 3F 40 00 08 00 03 12 FE 3E 00 .^....?@......>.
0800:3EA0 08 04 3F 00 08 86 3F AD 3F 80 5C B7 5C 42 40 47 ..?...?.?.\.\B@G
0800:3EB0 5D 01 02 50 00 80 01 08 00 03 07 00 BB 00 5F 01 ]..P.........._.
0800:3EC0 A8 53 D2 53 DE 53 E9 53 F2 53 FD 53 57 40 55 54 .S.S.S.S.S.SW@UT
0800:3ED0 66 54 92 54 A6 54 81 35 BA 54 F9 54 22 55 44 55 fT.T.T.5.T.T"UDU
0800:3EE0 CD 42 38 43 3D 56 F3 56 66 57 F4 40 E0 41 00 08 .B8C=V.VfW.@.A..
0800:3EF0 00 00 18 18 00 00 00 08 00 00 00 18 00 00 00 3B ...............;
0800:3F00 00 00 3D 3F 00 00 00 15 3F 3F 3F 15 3F 3F 3F 3F ..=?....???.????

;; fn0800_3F10: 0800:3F10
;;   Called from:
;;     0800:29BD (in fn0800_2952)
fn0800_3F10 proc
	mov	bx,3C96h
	jmp	3F18h

;; fn0800_3F15: 0800:3F15
;;   Called from:
;;     0800:29BD (in fn0800_2952)
fn0800_3F15 proc
	mov	bx,3CFAh

;; fn0800_3F18: 0800:3F18
;;   Called from:
;;     0800:3F13 (in fn0800_3F10)
;;     0800:3F15 (in fn0800_3F15)
fn0800_3F18 proc
	test	byte ptr [0756h],16h
	jz	3F84h

l0800_3F1F:
	jmp	3F35h

;; fn0800_3F21: 0800:3F21
;;   Called from:
;;     0800:29BD (in fn0800_2952)
fn0800_3F21 proc
	test	byte ptr [0756h],14h
	jz	3F84h

l0800_3F28:
	mov	bx,3E26h
	cmp	word ptr [0757h],40h
	ja	3F35h

l0800_3F32:
	mov	bx,3E8Ah

;; fn0800_3F35: 0800:3F35
;;   Called from:
;;     0800:3F1F (in fn0800_3F18)
;;     0800:3F30 (in fn0800_3F21)
;;     0800:3F32 (in fn0800_3F21)
fn0800_3F35 proc
	test	byte ptr [0755h],0Ch
	jz	3F84h

l0800_3F3C:
	mov	cx,64h
	call	34B8h
	mov	ax,[0757h]
	div	byte ptr [01F5h]
	dec	al
	mov	[01F8h],al
	clc
	ret

;; fn0800_3F50: 0800:3F50
;;   Called from:
;;     0800:29BD (in fn0800_2952)
fn0800_3F50 proc
	test	byte ptr [0756h],9h
	jz	3F84h

l0800_3F57:
	mov	bx,3D5Eh
	cmp	word ptr [0757h],40h
	ja	3F64h

l0800_3F61:
	mov	bx,3DC2h

l0800_3F64:
	test	byte ptr [0755h],0Ch
	jz	3F84h

l0800_3F6B:
	mov	cx,64h
	call	34B8h
	mov	ax,[0757h]
	shr	ax,1h
	div	byte ptr [01F5h]
	sub	al,1h
	adc	al,0h
	mov	[01F8h],al
	clc
	jmp	3F85h

;; fn0800_3F84: 0800:3F84
;;   Called from:
;;     0800:3F1D (in fn0800_3F18)
;;     0800:3F26 (in fn0800_3F21)
;;     0800:3F3A (in fn0800_3F35)
fn0800_3F84 proc
	stc

l0800_3F85:
	ret
0800:3F86                   A0 E9 01 55 56 57 B4 00 CD 10       ...UVW....
0800:3F90 5F 5E 5D 80 3E EC 01 2B 75 0F B2 2B B8 23 11 32 _^].>..+u..+.#.2
0800:3FA0 DB 55 56 57 CD 10 5F 5E 5D E8 D5 F5 C3 A3 E6 01 .UVW.._^].......
0800:3FB0 50 8A C4 55 56 57 B4 05 CD 10 5F 5E 5D 58 98 F7 P..UVW...._^]X..
0800:3FC0 26 F6 01 03 06 F1 01 A3 5E 07 C3 3D FF FF 75 04 &.......^..=..u.
0800:3FD0 3B D0 74 31 E8 41 00 72 2C 32 FF 88 87 CA 08 88 ;.t1.A.r,2......
0800:3FE0 A7 D2 08 8A F8 8A C3 04 08 50 32 C0 55 56 57 B4 .........P2.UVW.
0800:3FF0 10 CD 10 5F 5E 5D 58 93 32 C0 55 56 57 B4 10 CD ..._^]X.2.UVW...
0800:4000 10 5F 5E 5D F8 C3 00 00 00 08 00 18 08 00 08 08 ._^]............
0800:4010 08 18 18 00 18 08 18 18 3A 1E F3 01 77 33 0A F2 ........:...w3..
0800:4020 0A F4 75 2D 3A 06 F4 01 77 27 80 FB 02 72 03 80 ..u-:...w'...r..
0800:4030 C3 02 57 BF 06 40 32 E4 D0 E0 03 F8 2E 8B 05 5F ..W..@2........_
0800:4040 F8 C3 E8 A7 1C 72 0A 80 FB 02 72 03 80 C3 02 F8 .....r....r.....
0800:4050 C3 F9 C3 00 03 0C 0F 50 53 3A 06 F3 01 76 03 A0 .......PS:...v..
0800:4060 F3 01 BB 53 40 2E D7 A2 5B 07 F8 5B 58 C3 52 BA ...S@...[..[X.R.
0800:4070 CE 03 B0 07 EE 42 B0 AA F7 C6 01 00 75 02 D0 C8 .....B......u...
0800:4080 EE 26 8A 0C 22 CB 32 CB 75 27 0A FF 74 21 0B FF .&..".2.u'..t!..
0800:4090 74 10 4E D0 C8 EE 26 8A 0C F6 D1 0A C9 75 12 4F t.N...&......u.O
0800:40A0 75 F0 4E D0 C8 EE 26 8A 0C 22 CF 32 CF 75 02 32 u.N...&..".2.u.2
0800:40B0 C9 5A C3 52 BA CE 03 B0 07 EE 42 B0 AA F7 C6 01 .Z.R......B.....
0800:40C0 00 75 02 D0 C8 EE 26 8A 0C 22 CB 32 CB 75 23 0B .u....&..".2.u#.
0800:40D0 FF 74 10 46 D0 C8 EE 26 8A 0C F6 D1 0A C9 75 12 .t.F...&......u.
0800:40E0 4F 75 F0 46 D0 C8 EE 26 8A 0C 22 CF 32 CF 75 02 Ou.F...&..".2.u.
0800:40F0 32 C9 5A C3 06 E8 90 16 D0 C5 73 03 4E 78 06 3B 2.Z.......s.Nx.;
0800:4100 36 76 07 73 03 E9 D3 00 75 09 3A 2E 74 07 76 03 6v.s....u.:.t.v.
0800:4110 E9 C8 00 8B FE 8A DD BD FF FF 32 E4 B1 AA F7 C6 ..........2.....
0800:4120 01 00 75 02 D0 C9 BA CE 03 B0 07 EE 42 8A C1 EE ..u.........B...
0800:4130 26 8A 05 84 C5 74 07 32 C9 8A D9 E9 9D 00 3B 3E &....t.2......;>
0800:4140 76 07 75 04 8A 26 74 07 84 C5 75 14 84 E5 75 10 v.u..&t...u...u.
0800:4150 D0 C5 73 F4 4F 45 D0 C9 8A C1 EE 26 8A 05 EB DE ..s.OE.....&....
0800:4160 3B 36 76 07 74 02 32 E4 8A EB B1 AA F7 C6 01 00 ;6v.t.2.........
0800:4170 75 02 D0 C9 8A C1 EE 26 8A 04 33 D2 E8 72 17 8A u......&..3..r..
0800:4180 DF 32 FF 56 45 74 25 4D 52 BA CF 03 B1 AA F7 C7 .2.VEt%MR.......
0800:4190 01 00 75 02 D0 C9 8A C1 EE 5A 26 8A 05 B5 01 3B ..u......Z&....;
0800:41A0 3E 76 07 75 04 8A 26 74 07 E8 45 17 89 3E 5C 07 >v.u..&t..E..>\.
0800:41B0 88 2E 5A 07 57 8B FD 80 3E 61 07 00 74 05 E8 1A ..Z.W...>a..t...
0800:41C0 18 EB 06 E8 F9 16 E8 A5 FE 5E 5F 0A C9 74 09 32 .........^_..t.2
0800:41D0 ED F6 D5 FD E8 D3 15 FC E8 D9 16 E8 A3 F3 07 C3 ................
0800:41E0 06 E8 A4 15 8B DA B1 AA F7 C6 01 00 75 02 D0 C9 ............u...
0800:41F0 BA CE 03 B0 07 EE 42 8A C1 EE 26 8A 04 32 E4 3B ......B...&..2.;
0800:4200 36 78 07 75 04 8A 26 75 07 84 C5 74 18 84 E5 75 6x.u..&u...t...u
0800:4210 14 4B 74 11 D0 CD 73 F1 46 D0 C9 8A C1 EE 26 8A .Kt...s.F.....&.
0800:4220 04 B5 80 EB DA 8B D3 84 C5 74 08 33 D2 8B DA 32 .........t.3...2
0800:4230 C9 EB 7B 52 33 D2 89 36 62 07 56 88 2E 64 07 E8 ..{R3..6b.V..d..
0800:4240 95 16 8A DF 32 FF 33 ED 8B 3E 78 07 2B FE F6 C3 ....2.3..>x.+...
0800:4250 01 74 2A 0B FF 74 26 4D B5 80 52 BA CF 03 45 46 .t*..t&M..R...EF
0800:4260 D0 C9 8A C1 EE 26 8A 04 0A C0 75 03 4F 75 EF 3B .....&....u.Ou.;
0800:4270 36 78 07 75 04 8A 26 75 07 5A E8 5A 16 89 36 5C 6x.u..&u.Z.Z..6\
0800:4280 07 88 2E 5A 07 5F 57 56 8B F7 8B FD 80 3E 61 07 ...Z._WV.....>a.
0800:4290 00 74 05 E8 A9 16 EB 06 E8 24 16 E8 15 FE 5E 5F .t.......$....^_
0800:42A0 0A C9 74 06 32 ED FC E8 00 15 E8 07 16 5A E8 D0 ..t.2........Z..
0800:42B0 F2 8B 36 62 07 A0 64 07 07 C3 B0 04 EE 42 32 C0 ..6b..d......B2.
0800:42C0 D1 CF 36 12 06 4F 08 D1 C7 EE 4A AC C3 BA CE 03 ..6..O....J.....
0800:42D0 D0 E7 36 88 3E 4F 08 E8 E0 FF 8A E0 E8 DB FF 8A ..6.>O..........
0800:42E0 F8 D3 C0 83 ED 08 76 0D 26 88 25 47 8A E7 75 EC ......v.&.%G..u.
0800:42F0 E8 73 F2 EB E7 22 E5 26 88 25 47 75 03 E8 66 F2 .s...".&.%Gu..f.
0800:4300 C3 50 52 50 BA CE 03 B0 04 EE 42 32 C0 D1 CF 36 .PRP......B2...6
0800:4310 12 06 4F 08 D1 C7 EE BA C4 03 B0 02 EE 42 36 A0 ..O..........B6.
0800:4320 65 07 36 22 06 4E 08 24 0F EE 36 D0 06 4E 08 58 e.6".N.$..6..N.X
0800:4330 36 FF 16 4C 02 5A 58 C3 36 D0 06 65 07 36 D0 06 6..L.ZX.6..e.6..
0800:4340 65 07 36 C6 06 4E 08 55 F7 C7 01 00 74 05 36 D0 e.6..N.U....t.6.
0800:4350 06 4E 08 D0 E7 36 88 3E 4F 08 52 8A E6 BA CE 03 .N...6.>O.R.....
0800:4360 B0 08 E8 15 F2 5A 8A 24 46 75 03 E8 EE F1 D3 C8 .....Z.$Fu......
0800:4370 03 E9 83 ED 08 76 2F E8 87 FF B6 FF 50 52 8A E6 .....v/.....PR..
0800:4380 BA CE 03 B0 08 E8 F2 F1 5A 58 EB 03 E8 72 FF D3 ........ZX...r..
0800:4390 C0 86 E0 3B CD 73 08 8A 24 46 75 03 E8 BD F1 D3 ...;.s..$Fu.....
0800:43A0 C8 83 ED 08 77 E6 50 22 F2 8A E6 BA CE 03 B0 08 ....w.P"........
0800:43B0 E8 C7 F1 58 E8 4A FF C3 0B 11 00 50 1E 80 02 E0 ...X.J.....P....
0800:43C0 01 00 A0 01 FF 40 00 00 00 01 00 F5 44 00 08 F5 .....@......D...
0800:43D0 44 00 08 46 48 6A 48 7C 48 BF 48 E4 48 04 49 01 D..FHjH|H.H.H.I.
0800:43E0 01 50 00 80 01 08 00 03 07 00 00 01 00 01 A8 53 .P.............S
0800:43F0 D2 53 DE 53 E9 53 F2 53 FD 53 D6 4B 21 4C 3C 4C .S.S.S.S.S.K!L<L
0800:4400 4D 4C 63 4C 67 4C 02 50 97 50 EB 50 7C 4C B1 4C MLcLgL.P.P.P|L.L
0800:4410 D7 4C 39 4D D6 56 F7 4D 54 4E E8 4E 0C 12 00 50 .L9M.V.MTN.N...P
0800:4420 1E 80 02 E0 01 00 A0 0F FF FF 00 00 00 0F 02 F5 ................
0800:4430 44 00 08 F5 44 00 08 46 48 6A 48 7C 48 BF 48 F0 D...D..FHjH|H.H.
0800:4440 48 04 49 01 04 50 00 80 01 08 00 03 07 00 00 01 H.I..P..........
0800:4450 00 01 A8 53 D2 53 DE 53 E9 53 F2 53 FD 53 06 54 ...S.S.S.S.S.S.T
0800:4460 16 54 66 54 92 54 A6 54 81 35 BA 54 F9 54 22 55 .TfT.T.T.5.T.T"U
0800:4470 4A 55 72 55 A7 55 3D 56 F3 56 66 57 F4 5A AA 5B JUrU.U=V.VfW.Z.[
0800:4480 0D 13 00 28 19 40 01 C8 00 00 A0 FF FF 40 00 00 ...(.@.......@..
0800:4490 00 0F 02 F5 44 00 08 F5 44 00 08 46 48 6A 48 74 ....D...D..FHjHt
0800:44A0 48 BF 48 F5 48 04 49 08 01 40 01 FF FF 01 00 00 H.H.H.I..@......
0800:44B0 00 00 D5 00 33 01 07 49 D9 53 DE 53 E9 53 F2 53 ....3..I.S.S.S.S
0800:44C0 FD 53 20 49 25 49 2E 49 3A 49 63 4C 67 4C 4A 49 .S I%I.I:IcLgLJI
0800:44D0 8B 49 CF 49 22 4A 39 4A 5B 4A 92 4A D1 4A F7 4D .I.I"J9J[J.J.J.M
0800:44E0 FA 4A 47 4B 00 01 02 03 04 05 06 07 08 09 0A 0B .JGK............
0800:44F0 0C 0D 0E 0F 10 00 00 00 00 00 2A 00 2A 00 00 2A ..........*.*..*
0800:4500 2A 2A 00 00 2A 00 2A 2A 15 00 2A 2A 2A 15 15 15 **..*.**..***...
0800:4510 15 15 3F 15 3F 15 15 3F 3F 3F 15 15 3F 15 3F 3F ..?.?..???..?.??
0800:4520 3F 15 3F 3F 3F 00 00 00 05 05 05 08 08 08 0B 0B ?.???...........
0800:4530 0B 0E 0E 0E 11 11 11 14 14 14 18 18 18 1C 1C 1C ................
0800:4540 20 20 20 24 24 24 28 28 28 2D 2D 2D 32 32 32 38    $$$(((---2228
0800:4550 38 38 3F 3F 3F 00 00 3F 10 00 3F 1F 00 3F 2F 00 88???..?..?..?/.
0800:4560 3F 3F 00 3F 3F 00 2F 3F 00 1F 3F 00 10 3F 00 00 ??.??./?..?..?..
0800:4570 3F 10 00 3F 1F 00 3F 2F 00 3F 3F 00 2F 3F 00 1F ?..?..?/.??./?..
0800:4580 3F 00 10 3F 00 00 3F 00 00 3F 10 00 3F 1F 00 3F ?..?..?..?..?..?
0800:4590 2F 00 3F 3F 00 2F 3F 00 1F 3F 00 10 3F 1F 1F 3F /.??./?..?..?..?
0800:45A0 27 1F 3F 2F 1F 3F 37 1F 3F 3F 1F 3F 3F 1F 37 3F '.?/.?7.??.??.7?
0800:45B0 1F 2F 3F 1F 27 3F 1F 1F 3F 27 1F 3F 2F 1F 3F 37 ./?.'?..?'.?/.?7
0800:45C0 1F 3F 3F 1F 37 3F 1F 2F 3F 1F 27 3F 1F 1F 3F 1F .??.7?./?.'?..?.
0800:45D0 1F 3F 27 1F 3F 2F 1F 3F 37 1F 3F 3F 1F 37 3F 1F .?'.?/.?7.??.7?.
0800:45E0 2F 3F 1F 27 3F 2D 2D 3F 31 2D 3F 36 2D 3F 3A 2D /?.'?--?1-?6-?:-
0800:45F0 3F 3F 2D 3F 3F 2D 3A 3F 2D 36 3F 2D 31 3F 2D 2D ??-??-:?-6?-1?--
0800:4600 3F 31 2D 3F 36 2D 3F 3A 2D 3F 3F 2D 3A 3F 2D 36 ?1-?6-?:-??-:?-6
0800:4610 3F 2D 31 3F 2D 2D 3F 2D 2D 3F 31 2D 3F 36 2D 3F ?-1?--?--?1-?6-?
0800:4620 3A 2D 3F 3F 2D 3A 3F 2D 36 3F 2D 31 3F 00 00 1C :-??-:?-6?-1?...
0800:4630 07 00 1C 0E 00 1C 15 00 1C 1C 00 1C 1C 00 15 1C ................
0800:4640 00 0E 1C 00 07 1C 00 00 1C 07 00 1C 0E 00 1C 15 ................
0800:4650 00 1C 1C 00 15 1C 00 0E 1C 00 07 1C 00 00 1C 00 ................
0800:4660 00 1C 07 00 1C 0E 00 1C 15 00 1C 1C 00 15 1C 00 ................
0800:4670 0E 1C 00 07 1C 0E 0E 1C 11 0E 1C 15 0E 1C 18 0E ................
0800:4680 1C 1C 0E 1C 1C 0E 18 1C 0E 15 1C 0E 11 1C 0E 0E ................
0800:4690 1C 11 0E 1C 15 0E 1C 18 0E 1C 1C 0E 18 1C 0E 15 ................
0800:46A0 1C 0E 11 1C 0E 0E 1C 0E 0E 1C 11 0E 1C 15 0E 1C ................
0800:46B0 18 0E 1C 1C 0E 18 1C 0E 15 1C 0E 11 1C 14 14 1C ................
0800:46C0 16 14 1C 18 14 1C 1A 14 1C 1C 14 1C 1C 14 1A 1C ................
0800:46D0 14 18 1C 14 16 1C 14 14 1C 16 14 1C 18 14 1C 1A ................
0800:46E0 14 1C 1C 14 1A 1C 14 18 1C 14 16 1C 14 14 1C 14 ................
0800:46F0 14 1C 16 14 1C 18 14 1C 1A 14 1C 1C 14 1A 1C 14 ................
0800:4700 18 1C 14 16 1C 00 00 10 04 00 10 08 00 10 0C 00 ................
0800:4710 10 10 00 10 10 00 0C 10 00 08 10 00 04 10 00 00 ................
0800:4720 10 04 00 10 08 00 10 0C 00 10 10 00 0C 10 00 08 ................
0800:4730 10 00 04 10 00 00 10 00 00 10 04 00 10 08 00 10 ................
0800:4740 0C 00 10 10 00 0C 10 00 08 10 00 04 10 08 08 10 ................
0800:4750 0A 08 10 0C 08 10 0E 08 10 10 08 10 10 08 0E 10 ................
0800:4760 08 0C 10 08 0A 10 08 08 10 0A 08 10 0C 08 10 0E ................
0800:4770 08 10 10 08 0E 10 08 0C 10 08 0A 10 08 08 10 08 ................
0800:4780 08 10 0A 08 10 0C 08 10 0E 08 10 10 08 0E 10 08 ................
0800:4790 0C 10 08 0A 10 0B 0B 10 0C 0B 10 0D 0B 10 0F 0B ................
0800:47A0 10 10 0B 10 10 0B 0F 10 0B 0D 10 0B 0C 10 0B 0B ................
0800:47B0 10 0C 0B 10 0D 0B 10 0F 0B 10 10 0B 0F 10 0B 0D ................
0800:47C0 10 0B 0C 10 0B 0B 10 0B 0B 10 0C 0B 10 0D 0B 10 ................
0800:47D0 0F 0B 10 10 0B 0F 10 0B 0D 10 0B 0C 10 00 00 00 ................
0800:47E0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
0800:47F0 00 00 00 00 00                                  .....

;; fn0800_47F5: 0800:47F5
;;   Called from:
;;     0800:29BD (in fn0800_2952)
fn0800_47F5 proc
	mov	bx,43B8h
	test	byte ptr [0756h],10h
	jz	4844h

l0800_47FF:
	test	byte ptr [074Eh],2h
	jz	4844h

l0800_4806:
	mov	word ptr [0852h],50h
	mov	word ptr [0854h],0FFB0h
	mov	word ptr [0856h],0h
	jmp	482Bh

;; fn0800_481A: 0800:481A
;;   Called from:
;;     0800:29BD (in fn0800_2952)
fn0800_481A proc
	mov	bx,441Ch
	test	byte ptr [0756h],10h
	jz	4844h

l0800_4824:
	test	byte ptr [074Eh],4h
	jz	4844h

l0800_482B:
	mov	cx,64h
	call	34B8h
	clc
	ret

;; fn0800_4833: 0800:4833
;;   Called from:
;;     0800:29BD (in fn0800_2952)
fn0800_4833 proc
	mov	bx,4480h
	test	byte ptr [0756h],10h
	jz	4844h

l0800_483D:
	test	byte ptr [074Eh],8h
	jnz	482Bh

l0800_4844:
	stc
	ret
0800:4846                   A0 E9 01 55 56 57 B4 00 CD 10       ...UVW....
0800:4850 5F 5E 5D 80 3E EC 01 3C 75 0F B2 3C B8 23 11 32 _^].>..<u..<.#.2
0800:4860 DB 55 56 57 CD 10 5F 5E 5D C3 A3 E6 01 A1 F1 01 .UVW.._^].......
0800:4870 A3 5E 07 C3 06 0E 07 B9 00 01 EB 2F 06 0E 07 80 .^........./....
0800:4880 3E 50 07 00 74 22 B0 10 BB 10 00 33 D2 33 C9 55 >P..t".....3.3.U
0800:4890 56 57 B4 10 CD 10 5F 5E 5D BA E4 44 B0 02 55 56 VW...._^]..D..UV
0800:48A0 57 B4 10 CD 10 5F 5E 5D B9 10 00 33 DB C4 16 FF W...._^]...3....
0800:48B0 01 B0 12 55 56 57 B4 10 CD 10 5F 5E 5D 07 C3 3D ...UVW...._^]..=
0800:48C0 FF FF 75 04 3B D0 74 1B FF 16 0B 02 72 15 8A FE ..u.;.t.....r...
0800:48D0 86 F0 86 EC 86 CA B0 10 55 56 57 B4 10 CD 10 5F ........UVW...._
0800:48E0 5E 5D F8 C3 80 FB 01 77 19 F6 DB 80 E3 0F EB 05 ^].....w........
0800:48F0 80 FB 0F 77 0D F7 C2 C0 FF 75 07 A9 C0 C0 75 02 ...w.....u....u.
0800:4900 F8 C3 F9 C3 E9 40 14 8B C1 8B DA D1 E2 D1 E2 03 .....@..........
0800:4910 D3 B1 06 D3 E2 03 C2 A3 5C 07 C6 06 5A 07 FF C3 ........\...Z...
0800:4920 A2 5B 07 F8 C3 1E C5 1E 5C 07 8A 07 1F C3 1E A0 .[......\.......
0800:4930 5B 07 C5 1E 5C 07 88 07 1F C3 C6 06 A9 07 01 A0 [...\...........
0800:4940 5B 07 8B 1E 5C 07 26 88 07 C3 8B 1E 66 07 42 F6 [...\.&.....f.B.
0800:4950 06 4F 07 02 74 1A D1 C5 73 03 26 88 25 0B F6 79 .O..t...s.&.%..y
0800:4960 06 03 F3 47 E2 F0 C3 03 36 68 07 03 FA E2 E7 C3 ...G....6h......
0800:4970 D1 C5 73 04 FF 16 50 08 0B F6 79 06 03 F3 47 E2 ..s...P...y...G.
0800:4980 EF C3 03 36 68 07 03 FA E2 E6 C3 8B 1E 66 07 F6 ...6h........f..
0800:4990 06 4F 07 02 74 1C D1 C5 73 03 26 88 25 0B F6 79 .O..t...s.&.%..y
0800:49A0 07 03 F3 03 FA E2 EF C3 03 36 68 07 F9 13 FA E2 .........6h.....
0800:49B0 E5 C3 D1 C5 73 04 FF 16 50 08 0B F6 79 07 03 F3 ....s...P...y...
0800:49C0 03 FA E2 EE C3 03 36 68 07 F9 13 FA E2 E4 C3 8B ......6h........
0800:49D0 36 6A 07 F6 06 4F 07 02 74 19 83 FD FF 75 08 26 6j...O..t....u.&
0800:49E0 88 25 03 FA E2 F9 C3 D1 C5 73 03 26 88 25 03 FA .%.......s.&.%..
0800:49F0 E2 F5 C3 8B 1E 50 08 D1 C5 73 02 FF D3 03 FA E2 .....P...s......
0800:4A00 F6 C3 26 08 25 C3 26 20 25 C3 26 30 25 C3 02 4A ..&.%.& %.&0%..J
0800:4A10 06 4A 00 00 00 00 0A 4A 7C 4A 77 4A 81 4A 5C 35 .J.....J|JwJ.J\5
0800:4A20 86 4A 32 E4 D1 E0 8B D8 2E 8B 87 0E 4A A3 50 08 .J2.........J.P.
0800:4A30 2E 8B 87 18 4A A3 4C 02 C3 8B CD D1 E9 D1 E9 D1 ....J.L.........
0800:4A40 E9 BB 66 35 8B D7 F7 DA 3B CA 77 03 F3 A4 C3 2B ..f5....;.w....+
0800:4A50 CA 87 CA F3 A4 87 CA FF D3 EB F1 36 8B 1E 4C 02 ...........6..L.
0800:4A60 8B D6 8B CD D1 E9 D1 E9 D1 E9 81 FB 5C 35 74 D6 ............\5t.
0800:4A70 AC 0B F6 74 18 FF E3 26 20 05 EB 0D 26 08 05 EB ...t...& ...&...
0800:4A80 08 F6 D0 AA EB 04 26 30 05 47 E2 E4 C3 E8 CC EA ......&0.G......
0800:4A90 FF E3 57 06 C6 06 A9 07 01 C4 3E 5C 07 A0 5B 07 ..W.......>\..[.
0800:4AA0 80 3E 61 07 00 74 23 8B CF 83 E1 07 B4 01 D2 CC .>a..t#.........
0800:4AB0 87 CB 8A 1E 96 08 8A 97 99 07 D0 CC 84 E2 74 05 ..............t.
0800:4AC0 AA E2 F7 EB 09 47 E2 F2 EB 04 8B CB F3 AA 07 5F .....G........._
0800:4AD0 C3 A1 5C 07 33 D2 B9 40 01 F7 F1 8B D8 D1 E0 D1 ..\.3..@........
0800:4AE0 E0 03 C3 B1 06 D3 E0 8B D0 A1 70 07 03 C2 A3 76 ..........p....v
0800:4AF0 07 03 16 72 07 89 16 78 07 C3 52 57 06 C4 3E 5C ...r...x..RW..>\
0800:4B00 07 8A 16 60 07 8A 36 5B 07 33 C9 33 DB B4 FF 84 ...`..6[.3.3....
0800:4B10 26 61 07 74 05 E8 A2 00 D0 C4 3B 3E 76 07 74 14 &a.t......;>v.t.
0800:4B20 4F 26 8A 05 3A C2 74 0B 32 C6 D0 CC 73 02 0A C8 O&..:.t.2...s...
0800:4B30 43 EB E7 47 89 3E 5C 07 0B DB 74 07 53 51 E8 51 C..G.>\...t.SQ.Q
0800:4B40 FF 59 5B 07 5F 5A C3 57 06 55 8B DA C4 3E 5C 07 .Y[._Z.W.U...>\.
0800:4B50 8A 16 60 07 8A 36 5B 07 33 C9 26 8A 05 3A C2 75 ..`..6[.3.&..:.u
0800:4B60 11 4B 74 0A 47 3B 3E 78 07 76 EF 4F 33 DB 8B D3 .Kt.G;>x.v.O3...
0800:4B70 EB 3C 89 3E 62 07 89 3E 5C 07 53 33 DB B4 FF 84 .<.>b..>\.S3....
0800:4B80 26 61 07 74 03 E8 32 00 3B 3E 78 07 77 13 26 8A &a.t..2.;>x.w.&.
0800:4B90 05 3A C2 74 0D 32 C6 D0 C4 73 02 0A C8 43 47 EB .:.t.2...s...CG.
0800:4BA0 E7 4F 0B DB 74 07 53 51 E8 E7 FE 59 5B 5A 89 3E .O..t.SQ...Y[Z.>
0800:4BB0 5C 07 8B 36 62 07 5D 07 5F C3 8A 1E 96 08 8A A7 \..6b.]._.......
0800:4BC0 99 07 8A DF 8B CF 80 E1 07 D2 C4 33 C9 C3 00 3F ...........3...?
0800:4BD0 00 00 00 3F 3F 3F 50 F6 D8 1A C0 A2 5B 07 F8 58 ...???P.....[..X
0800:4BE0 C3 A3 E6 01 A1 F1 01 A3 5E 07 C3 33 C0 D1 EA D1 ........^..3....
0800:4BF0 D8 D1 E8 D1 E8 8B DA D1 E2 D1 E2 03 D3 D1 E2 D1 ................
0800:4C00 E2 D1 E2 D1 E2 03 D0 8B C1 D1 E8 D1 E8 D1 E8 03 ................
0800:4C10 D0 89 16 5C 07 80 E1 07 B5 80 D2 ED 88 2E 5A 07 ...\..........Z.
0800:4C20 C3 06 A0 5A 07 C4 1E 5C 07 8A 0E 0F 02 26 8A 27 ...Z...\.....&.'
0800:4C30 22 E0 D3 E8 73 FC D3 E0 8A C4 07 C3 1E 8B 0E 5A "...s..........Z
0800:4C40 07 C5 1E 5C 07 32 2F 22 E9 30 2F 1F C3 C6 06 A9 ...\.2/".0/.....
0800:4C50 07 01 8B 0E 5A 07 8B 1E 5C 07 26 32 2F 22 E9 26 ....Z...\.&2/".&
0800:4C60 30 2F C3 8E 06 5E 07 C3 9E 4C 93 4C A5 4C A7 4C 0/...^...L.L.L.L
0800:4C70 AA 4C FD 4C F8 4C 02 4D 04 4D 09 4D 32 E4 D1 E0 .L.L.L.M.M.M2...
0800:4C80 8B D8 2E 8B 87 68 4C A3 4C 02 2E 8B 87 72 4C A3 .....hL.L....rL.
0800:4C90 5B 08 C3 F6 D6 0A E6 F6 D6 26 20 25 47 C3 22 E6 [........& %G.".
0800:4CA0 26 08 25 47 C3 F6 D4 26 32 25 22 E6 26 30 25 47 &.%G...&2%".&0%G
0800:4CB0 C3 8A 24 46 AC 8A F8 D3 C0 83 ED 08 76 0D 26 88 ..$F........v.&.
0800:4CC0 25 47 8A E7 75 EE E8 9D E8 EB E9 22 E5 26 88 25 %G..u......".&.%
0800:4CD0 47 75 03 E8 90 E8 C3 8A 24 46 75 03 E8 7D E8 D3 Gu......$Fu..}..
0800:4CE0 C8 03 E9 83 ED 08 76 44 36 FF 16 4C 02 B6 FF 36 ......vD6..L...6
0800:4CF0 8B 1E 5B 08 EB 17 FF E3 26 20 25 EB 0F 26 08 25 ..[.....& %..&.%
0800:4D00 EB 0A F6 D4 26 88 25 EB 03 26 30 25 47 D3 C0 AC ....&.%..&0%G...
0800:4D10 0B F6 74 20 86 E0 D3 C8 83 ED 08 77 D9 83 C5 08 ..t .......w....
0800:4D20 3B CD 72 08 0B F6 75 03 E8 45 E8 4E 22 F2 36 FF ;.r...u..E.N".6.
0800:4D30 16 4C 02 C3 E8 25 E8 EB DB 57 06 C6 06 A9 07 01 .L...%...W......
0800:4D40 C4 3E 5C 07 8B 16 5A 07 0A D2 78 24 32 E4 8A 0E .>\...Z...x$2...
0800:4D50 0F 02 0A E2 4B 74 71 D2 CA 73 F7 80 3E 61 07 00 ....Ktq..s..>a..
0800:4D60 74 03 E8 78 00 8A C6 26 32 05 22 C4 26 30 05 47 t..x...&2.".&0.G
0800:4D70 8B C3 8A 0E 17 02 D3 E8 74 46 91 80 3E 61 07 00 ........tF..>a..
0800:4D80 74 3A 53 32 FF 8A 1E 96 08 80 3E 0F 02 02 75 1A t:S2......>...u.
0800:4D90 8B C7 D1 C8 D1 D3 8A C6 26 32 05 22 87 99 07 26 ........&2."...&
0800:4DA0 30 05 47 D1 CB E2 E9 5B EB 16 8A C6 26 32 05 22 0.G....[....&2."
0800:4DB0 87 99 07 26 30 05 47 E2 F1 5B EB 04 8A C6 F3 AA ...&0.G..[......
0800:4DC0 23 1E 18 02 74 14 EB 84 80 3E 61 07 00 74 03 E8 #...t....>a..t..
0800:4DD0 0B 00 26 32 35 22 F4 26 30 35 07 5F C3 53 32 FF ..&25".&05._.S2.
0800:4DE0 8A 1E 96 08 80 3E 0F 02 02 75 06 57 D1 CF D1 D3 .....>...u.W....
0800:4DF0 5F 22 A7 99 07 5B C3 88 1E 5B 07 C3 C4 3E 5C 07 _"...[...[...>\.
0800:4E00 8A 0E 0F 02 8A 2E 5A 07 8A 16 60 07 8A 36 5B 07 ......Z...`..6[.
0800:4E10 B4 FF 8A FC 84 26 61 07 74 20 32 FF 33 F6 8A 1E .....&a.t 2.3...
0800:4E20 96 08 80 3E 0F 02 02 75 03 46 D1 E3 8A A7 99 07 ...>...u.F......
0800:4E30 8A B8 99 07 85 FE 74 02 86 E7 26 8A 1D 33 F6 C3 ......t...&..3..
0800:4E40 8A C3 32 C2 22 C5 74 0B 8A C3 32 C6 22 C5 22 C4 ..2.".t...2.".".
0800:4E50 0B F0 45 C3 52 56 57 06 55 E8 A0 FF 8B EE 3B 3E ..E.RVW.U.....;>
0800:4E60 76 07 74 5D D2 C5 72 09 E8 D5 FF 74 2E D2 C5 EB v.t]..r....t....
0800:4E70 F5 83 EF 01 72 2B 86 E7 26 8A 1D 3B 3E 76 07 74 ....r+..&..;>v.t
0800:4E80 27 8A C3 32 C2 84 C5 74 1F D2 C5 73 F8 8A C3 32 '..2...t...s...2
0800:4E90 C6 22 C4 0B F0 03 2E 15 02 EB D6 D2 CD 73 2E EB ."...........s..
0800:4EA0 04 8A 2E 13 02 47 EB 25 8A 0E 0F 02 8A 2E 14 02 .....G.%........
0800:4EB0 E8 8D FF 74 E6 D2 C5 72 12 3A 2E 74 07 77 DC EB ...t...r.:.t.w..
0800:4EC0 EF D2 C5 72 06 3A 2E 74 07 76 E5 D2 CD 8B DD 0B ...r.:.t.v......
0800:4ED0 DB 74 0B 89 3E 5C 07 88 2E 5A 07 E8 5B FE 8B DD .t..>\...Z..[...
0800:4EE0 8B CE 5D 07 5F 5E 5A C3 57 06 55 8B EA E8 0C FF ..]._^Z.W.U.....
0800:4EF0 8A C3 32 C2 84 C5 75 1E 4D 74 18 D2 CD 73 F5 47 ..2...u.Mt...s.G
0800:4F00 86 E7 26 8A 1D 3B 3E 78 07 75 E5 3A 2E 75 07 73 ..&..;>x.u.:.u.s
0800:4F10 DF 33 ED E9 C6 00 89 3E 58 08 88 2E 5A 08 89 3E .3.....>X...Z..>
0800:4F20 5C 07 88 2E 5A 07 55 33 ED F6 C5 80 75 1C E8 0F \...Z.U3....u...
0800:4F30 FF 74 70 3B 3E 78 07 75 0C 3A 2E 75 07 74 64 77 .tp;>x.u.:.u.tdw
0800:4F40 04 33 ED EB 5E D2 CD 73 E5 47 80 3E 0F 02 02 74 .3..^..s.G.>...t
0800:4F50 1D 26 8A 1D 39 3E 78 07 76 40 8A C3 F6 D0 32 C2 .&..9>x.v@....2.
0800:4F60 75 CC 32 DE 22 DC 0B F3 83 C5 08 47 EB E3 86 E7 u.2."......G....
0800:4F70 26 8A 1D 39 3E 78 07 76 21 8A C3 F6 D0 32 C2 53 &..9>x.v!....2.S
0800:4F80 8A F8 D0 EF 80 E7 55 22 F8 5B 75 A2 32 DE 22 DC ......U".[u.2.".
0800:4F90 86 E7 0B F3 83 C5 04 47 EB D6 74 09 8A 0E 0F 02 .......G..t.....
0800:4FA0 D2 C5 47 EB 1D 8A 2E 13 02 E8 94 FE 74 14 D2 CD ..G.........t...
0800:4FB0 72 0E 3B 3E 78 07 75 F1 3A 2E 75 07 72 02 EB E9 r.;>x.u.:.u.r...
0800:4FC0 D2 C5 51 8B DD 0B DB 74 03 E8 6D FD 8B DD 59 89 ..Q....t..m...Y.
0800:4FD0 3E 5C 07 88 2E 5A 07 5A 8B CE EB 0E 8B DD 8B D5 >\...Z.Z........
0800:4FE0 8A CB 89 3E 5C 07 88 2E 5A 07 8B 36 58 08 A0 5A ...>\...Z..6X..Z
0800:4FF0 08 5D 07 5F C3 0B D2 8B 16 52 08 78 04 8B 16 54 .]._.....R.x...T
0800:5000 08 C3 E8 F0 FF 87 D9 8A 0E 0F 02 D1 C5 73 02 0A .............s..
0800:5010 C5 0B F6 79 49 03 36 66 07 D2 CD 72 19 4B 75 EB ...yI.6f...r.Ku.
0800:5020 F6 06 4F 07 02 74 09 26 32 25 22 E0 26 30 25 C3 ..O..t.&2%".&0%.
0800:5030 8A F0 FF 26 4C 02 F6 06 4F 07 02 74 15 8A CC 26 ...&L...O..t...&
0800:5040 32 0D 22 C8 26 30 0D 47 32 C0 8A 0E 0F 02 4B 75 2.".&0.G2.....Ku
0800:5050 BA C3 50 86 F0 FF 16 4C 02 8A F0 58 EB EA 03 36 ..P....L...X...6
0800:5060 68 07 F6 06 4F 07 02 74 21 8A CC 26 32 0D 22 C8 h...O..t!..&2.".
0800:5070 26 30 0D 32 C0 8A 0E 0F 02 D2 CD 83 D7 00 2B FA &0.2..........+.
0800:5080 73 04 03 3E 56 08 4B 75 82 C3 50 86 F0 FF 16 4C s..>V.Ku..P....L
0800:5090 02 8A F0 58 4F EB DC E8 5B FF 87 D9 8A 0E 0F 02 ...XO...[.......
0800:50A0 D1 C5 73 11 F6 06 4F 07 02 74 1E 8A EC 26 32 2D ..s...O..t...&2-
0800:50B0 22 E8 26 30 2D 0B F6 79 1D 03 36 66 07 2B FA 73 ".&0-..y..6f.+.s
0800:50C0 04 03 3E 56 08 4B 75 D8 C3 50 86 F0 FF 16 4C 02 ..>V.Ku..P....L.
0800:50D0 8A F0 58 4F EB DF 03 36 68 07 D2 C8 83 D7 00 2B ..XO...6h......+
0800:50E0 FA 73 04 03 3E 56 08 4B 75 B6 C3 E8 07 FF 8B 36 .s..>V.Ku......6
0800:50F0 56 08 F6 06 4F 07 02 74 2F 83 FD FF 75 13 8A FC V...O..t/...u...
0800:5100 26 32 3D 22 F8 26 30 3D 2B FA 73 02 03 FE E2 EE &2=".&0=+.s.....
0800:5110 C3 D1 C5 73 0A 8A FC 26 32 3D 22 F8 26 30 3D 2B ...s...&2=".&0=+
0800:5120 FA 73 02 03 FE E2 EA C3 8B DA 8A F0 8A C4 D1 C5 .s..............
0800:5130 73 07 FF 16 4C 02 8A E0 4F 2B FB 73 02 03 FE E2 s...L...O+.s....
0800:5140 ED C3 D0 06 5A 07 D0 06 5A 07 72 01 C3 FF 0E 5C ....Z...Z.r....\
0800:5150 07 C3 C3 A1 5C 07 33 06 6C 07 80 E4 60 75 0B A1 ....\.3.l...`u..
0800:5160 5C 07 3B 06 6C 07 73 02 F9 C3 A1 5C 07 2B 06 52 \.;.l.s....\.+.R
0800:5170 08 73 05 03 06 56 08 F8 A3 5C 07 C3 A1 5C 07 33 .s...V...\...\.3
0800:5180 06 6E 07 80 E4 60 75 0B A1 5C 07 3B 06 6E 07 72 .n...`u..\.;.n.r
0800:5190 02 F9 C3 A1 5C 07 2B 06 54 08 73 05 03 06 56 08 ....\.+.T.s...V.
0800:51A0 F8 A3 5C 07 C3 A1 5C 07 8A EC 80 E5 60 80 E4 1F ..\...\.....`...
0800:51B0 33 D2 F7 36 11 02 F7 26 11 02 0A E5 92 A1 70 07 3..6...&......p.
0800:51C0 03 C2 A3 76 07 A1 72 07 03 C2 A3 78 07 C3 03 08 ...v..r....x....
0800:51D0 00 50 19 D0 02 5C 01 00 B0 01 FF 20 00 08 01 01 .P...\..... ....
0800:51E0 00 00 00 00 00 00 00 00 00 61 52 6A 52 B6 34 B6 .........aRjR.4.
0800:51F0 34 B6 34 B6 34 01 01 5A 00 80 01 08 00 03 07 00 4.4.4..Z........
0800:5200 A5 00 8D 01 88 52 46 51 53 51 6A 51 7C 51 93 51 .....RFQSQjQ|Q.Q
0800:5210 D6 4B 21 4C 3C 4C 4D 4C 63 4C 67 4C 02 50 97 50 .K!L<LMLcLgL.P.P
0800:5220 EB 50 7C 4C B1 4C D7 4C 39 4D A5 51 F7 4D 54 4E .P|L.L.L9M.Q.MTN
0800:5230 E8 4E                                           .N

;; fn0800_5232: 0800:5232
;;   Called from:
;;     0800:29BD (in fn0800_2952)
fn0800_5232 proc
	test	byte ptr [0755h],20h
	stc
	jz	5260h

l0800_523A:
	mov	bx,51CEh
	mov	cx,64h
	call	34B8h
	mov	word ptr [0852h],2000h
	mov	word ptr [0854h],5FA6h
	mov	word ptr [0856h],7FA6h
	mov	ax,[0757h]
	rol	al,1h
	rol	al,1h
	and	[01F8h],al

l0800_5260:
	ret
0800:5261    A0 E9 01 B4 00 E8 7D E1 C3 A3 E6 01 50 8A C4  ......}.....P..
0800:5270 55 56 57 B4 05 CD 10 5F 5E 5D 58 98 F7 26 F6 01 UVW...._^]X..&..
0800:5280 03 06 F1 01 A3 5E 07 C3 33 C0 D1 EA D1 D8 D1 EA .....^..3.......
0800:5290 D1 D8 D1 E8 8B DA D1 E2 D1 E2 03 D3 D1 E2 8B DA ................
0800:52A0 D1 E2 D1 E2 D1 E2 03 D3 03 D0 8B C1 D1 E8 D1 E8 ................
0800:52B0 D1 E8 03 D0 89 16 5C 07 80 E1 07 B5 80 D2 ED 88 ......\.........
0800:52C0 2E 5A 07 C3                                     .Z..

;; fn0800_52C4: 0800:52C4
;;   Called from:
;;     0800:5367 (in fn0800_5327)
;;     0800:5367 (in fn0800_3760)
fn0800_52C4 proc
	push	ax
	push	cx
	xor	cx,cx
	mov	ax,[085Eh]
	cmp	byte ptr [08A9h],0h
	jnz	52D9h

l0800_52D2:
	mov	cx,[0862h]
	mov	ax,[0864h]

l0800_52D9:
	sub	ax,cx
	mov	[086Eh],ax
	inc	ax
	shr	ax,1h
	add	cx,ax
	mov	[0872h],cx
	xor	cx,cx
	mov	ax,[0860h]
	cmp	byte ptr [08A9h],0h
	jnz	52FAh

l0800_52F3:
	mov	cx,[0866h]
	mov	ax,[0868h]

l0800_52FA:
	sub	ax,cx
	mov	[0870h],ax
	inc	ax
	shr	ax,1h
	add	cx,ax
	mov	[0874h],cx
	pop	cx
	pop	ax
	ret

;; fn0800_530B: 0800:530B
;;   Called from:
;;     0800:2CF7 (in fn0800_2CF2)
fn0800_530B proc
	push	bx
	push	ax
	push	cx
	push	dx
	push	si
	push	di
	mov	word ptr [0886h],0FFFFh
	call	5327h
	mov	word ptr [08A6h],0h
	pop	di
	pop	si
	pop	dx
	pop	cx
	pop	ax
	pop	bx
	ret

;; fn0800_5327: 0800:5327
;;   Called from:
;;     0800:5317 (in fn0800_530B)
fn0800_5327 proc
	mov	word ptr [08A8h],0h
	call	33FAh
	jnz	5333h

l0800_5332:
	ret

l0800_5333:
	call	33EFh
	mov	[085Eh],cx
	mov	[0860h],dx
	xor	ax,ax
	mov	[0862h],ax
	mov	[0866h],ax
	mov	[086Ah],ax
	mov	[086Ch],ax
	mov	[0864h],cx
	mov	[0868h],dx

l0800_5354:
	mov	ax,[0862h]
	mov	bx,[0864h]
	mov	cx,[0866h]
	mov	dx,[0868h]
	push	bp
	call	34EDh
	call	52C4h
	mov	cx,[0872h]
	mov	dx,[0874h]
	call	word ptr [021Eh]
	pop	bp
	nop
	push	cs
	call	0F81h
	ret
0800:537D                                        9C 50 53              .PS
0800:5380 33 C0 C7 06 A6 08 00 00 E8 80 FF F9 5B 58 9D C3 3...........[X..

;; fn0800_5390: 0800:5390
;;   Called from:
;;     0800:2E1A (in fn0800_2E1A)
;;     0800:2F7C (in fn0800_2F3E)
fn0800_5390 proc
	cmp	word ptr [0638h],0D6D6h
	jnz	539Dh

l0800_5398:
	nop
	push	cs
	call	0F90h

l0800_539D:
	ret
0800:539E                                           8B DA               ..
0800:53A0 D1 E2 D1 E2 03 D3 EB 0A 8B DA D1 E2 D1 E2 03 D3 ................
0800:53B0 D1 E2 D1 E2 D1 E2 D1 E2 8B C1 D1 E8 D1 E8 D1 E8 ................
0800:53C0 03 D0 89 16 5C 07 80 E1 07 B5 80 D2 ED 88 2E 5A ....\..........Z
0800:53D0 07 C3 D0 06 5A 07 72 01 C3 FF 0E 5C 07 C3 A1 5C ....Z.r....\...\
0800:53E0 07 3B 06 6C 07 73 02 F9 C3 A1 11 02 29 06 5C 07 .;.l.s......).\.
0800:53F0 F8 C3 A1 5C 07 3B 06 6E 07 72 02 F9 C3 A1 11 02 ...\.;.n.r......
0800:5400 01 06 5C 07 F8 C3 50 3A 06 F3 01 76 03 A0 F3 01 ..\...P:...v....
0800:5410 A2 5B 07 F8 58 C3 56 06 C4 36 5C 07 BB 03 01 BA .[..X.V..6\.....
0800:5420 CE 03 B8 05 00 E8 52 E1 B0 04 EE 42 8A C3 32 E4 ......R....B..2.
0800:5430 8A 0E 5A 07 EE 26 8A 2C 22 E9 F6 DD D0 D4 2A C7 ..Z..&.,".....*.
0800:5440 73 F2 86 E0 E8 3A E1 07 5E C3 56 06 C4 36 5C 07 s....:..^.V..6\.
0800:5450 BB 02 02 EB CA 56 06 C4 36 5C 07 8B DE B7 02 80 .....V..6\......
0800:5460 E3 01 02 DF EB B9 06 BA CE 03 B0 05 EE A0 FA 01 ................
0800:5470 42 EE B0 08 4A EE A1 5A 07 42 EE C4 1E 5C 07 26 B...J..Z.B...\.&
0800:5480 86 27 B0 FF EE B0 05 4A EE A0 FA 01 24 10 42 EE .'.....J....$.B.
0800:5490 07 C3 C6 06 A9 07 01 BA CF 03 A1 5A 07 EE 8B 1E ...........Z....
0800:54A0 5C 07 26 86 27 C3 8E 06 5E 07 BA CE 03 B0 05 EE \.&.'...^.......
0800:54B0 A0 FA 01 42 EE B0 08 4A EE C3 BA CF 03 D1 C5 73 ...B...J.......s
0800:54C0 02 0A C7 0B F6 79 19 03 36 66 07 D0 CF 72 04 E2 .....y..6f...r..
0800:54D0 EC EB 21 EE 8A C4 26 86 05 32 C0 47 E2 DF EB 14 ..!...&..2.G....
0800:54E0 03 36 68 07 EE 8A C4 26 86 05 32 C0 D0 CF 13 3E .6h....&..2....>
0800:54F0 6A 07 E2 C9 EE 26 86 25 C3 BA CF 03 D1 C5 73 06 j....&.%......s.
0800:5500 EE 8A FC 26 86 3D 0B F6 79 0B 03 36 66 07 03 3E ...&.=..y..6f..>
0800:5510 6A 07 E2 E8 C3 03 36 68 07 D0 C8 13 3E 6A 07 E2 j.....6h....>j..
0800:5520 DB C3 BA CF 03 EE 8B 1E 6A 07 D1 C5 73 05 8A C4 ........j...s...
0800:5530 26 86 05 03 FB E2 F3 C3 F6 D4 26 86 25 47 C3 10 &.........&.%G..
0800:5540 08 00 00 18 B3 CC 3D B3 44 3D B3 88 88 1E 65 07 ......=.D=....e.
0800:5550 BB 38 55 3C 02 74 03 BB 3A 55 89 1E 4C 02 BB 3F .8U<.t..:U..L..?
0800:5560 55 2E D7 52 8A E0 BA CE 03 B0 03 E8 0C E0 5A C3 U..R..........Z.
0800:5570 D0 E7 BA CE 03 B0 04 EE 8A C7 42 EE 8A 24 46 AC ..........B..$F.
0800:5580 8A F8 D3 C0 83 ED 08 76 0D 26 88 25 47 8A E7 75 .......v.&.%G..u
0800:5590 EE E8 D2 DF EB E9 22 E5 26 88 25 47 75 03 E8 C5 ......".&.%Gu...
0800:55A0 DF C3 36 D0 06 65 07 36 D0 06 65 07 52 8A DE BA ..6..e.6..e.R...
0800:55B0 CE 03 B0 08 EE 93 42 EE 4A B0 05 EE 32 C0 42 EE ......B.J...2.B.
0800:55C0 4A B0 04 EE 8A C4 42 EE BA C4 03 B0 02 EE 36 A0 J.....B.......6.
0800:55D0 65 07 24 0F 42 EE 5A 8A 24 46 75 03 E8 7D DF 36 e.$.B.Z.$Fu..}.6
0800:55E0 8B 1E 4C 02 D3 C8 03 E9 83 ED 08 76 37 FF D3 B6 ..L........v7...
0800:55F0 FF 50 52 8A E6 BA CE 03 B0 08 EE 86 C4 42 EE 5A .PR..........B.Z
0800:5600 58 EB 02 FF D3 D3 C0 AC 0B F6 74 2C 86 E0 D3 C8 X.........t,....
0800:5610 83 ED 08 77 EE 83 C5 08 3B CD 72 08 0B F6 75 03 ...w....;.r...u.
0800:5620 E8 4D DF 4E 50 22 F2 8A E6 BA CE 03 B0 08 EE 86 .M.NP"..........
0800:5630 C4 42 EE 4A 58 FF D3 C3 E8 21 DF EB CF 57 06 C6 .B.JX....!...W..
0800:5640 06 A9 07 01 BA CE 03 B0 05 EE A0 FA 01 42 EE 4A .............B.J
0800:5650 B0 08 EE 42 C4 3E 5C 07 8B 0E 5A 07 0A C9 78 1E ...B.>\...Z...x.
0800:5660 32 E4 0A E1 4B 74 4C D0 C9 73 F7 80 3E 61 07 00 2...KtL..s..>a..
0800:5670 74 03 E8 54 00 8A C4 EE 8A C5 26 86 05 47 51 B0 t..T......&..GQ.
0800:5680 FF EE 8B C3 8A 0E 17 02 D3 E8 74 1E 91 8A C4 80 ..........t.....
0800:5690 3E 61 07 00 74 12 50 B4 FF E8 2D 00 8A C4 EE 58 >a..t.P...-....X
0800:56A0 26 8A 25 AA E2 FA EB 02 F3 AA 59 23 1E 18 02 75 &.%.......Y#...u
0800:56B0 AF EB 10 80 3E 61 07 00 74 03 E8 0C 00 8A C4 EE ....>a..t.......
0800:56C0 26 86 2D E8 BB DE 07 5F C3 53 32 FF 8A 1E 96 08 &.-...._.S2.....
0800:56D0 22 A7 99 07 5B C3 A1 5C 07 B9 50 00 33 D2 F7 F1 "...[..\..P.3...
0800:56E0 D1 E0 EB 62 A1 5C 07 B9 28 00 33 D2 F7 F1 E8 55 ...b.\..(.3....U
0800:56F0 00 EB 0F A1 5C 07 B9 50 00 33 D2 F7 F1 D1 E0 E8 ....\..P.3......
0800:5700 44 00 57 56 53 BE 07 00 BF 03 00 32 FF D0 8D AA D.WVS......2....
0800:5710 08 D0 D7 4F F6 06 10 02 02 74 09 4F D0 8D AA 08 ...O.....t.O....
0800:5720 D0 D7 EB 14 D0 8D AA 08 D0 D7 4F D0 8D AA 08 D0 ..........O.....
0800:5730 D7 4F D0 8D AA 08 D0 D7 88 BC AE 08 BF 03 00 4E .O.............N
0800:5740 79 C9 5B 5E 5F C3 D1 E0 D1 E0 D1 E0 8B D0 D1 E0 y.[^_...........
0800:5750 D1 E0 03 C2 8B D0 03 06 70 07 A3 76 07 03 16 72 ........p..v...r
0800:5760 07 89 16 78 07 C3 50 57 8A C7 32 E4 8B F8 80 3E ...x..PW..2....>
0800:5770 10 02 02 77 07 D1 E7 4F 88 9D AA 08 4F 88 9D AA ...w...O....O...
0800:5780 08 88 1E 5B 07 5F 58 C3 52 C4 36 5C 07 8A 2E 5A ...[._X.R.6\...Z
0800:5790 07 BA CE 03 B0 05 EE B0 08 42 EE 4A B0 02 EE A0 .........B.J....
0800:57A0 60 07 42 EE 32 C9 33 DB 5A C3 52 BA CE 03 8A 26 `.B.2.3.Z.R....&
0800:57B0 FA 01 80 3E 61 07 00 74 03 80 E4 10 B0 05 EE 86 ...>a..t........
0800:57C0 C4 42 EE 4A B0 08 EE 8A C3 80 3E 61 07 00 74 07 .B.J......>a..t.
0800:57D0 8A E0 E8 F4 FE 8A C4 42 EE 4A 26 8A 05 80 3E 61 .......B.J&...>a
0800:57E0 07 00 74 05 E8 7E 00 EB 07 8A 1E 5B 07 26 88 1D ..t..~.....[.&..
0800:57F0 0A FF 75 05 E8 D6 00 EB 2F B0 08 EE 8A C7 80 3E ..u...../......>
0800:5800 61 07 00 74 07 8A E0 E8 BF FE 8A C4 42 EE 4A 26 a..t........B.J&
0800:5810 8A 04 80 3E 61 07 00 74 09 87 FE E8 47 00 87 FE ...>a..t....G...
0800:5820 EB 03 26 88 1C E8 A5 00 0B ED 74 35 47 0A ED 74 ..&.......t5G..t
0800:5830 02 4F 4F 8A FD 8B CD 8A C3 80 3E 61 07 00 74 1F .OO.......>a..t.
0800:5840 B4 FF E8 84 FE B0 08 E8 30 DD 0A FF BB 01 00 74 ........0......t
0800:5850 02 F7 DB 26 8A 05 E8 0C 00 03 FB E2 F6 EB 02 F3 ...&............
0800:5860 AA B1 01 5A C3 52 53 BA C4 03 B0 02 EE 42 B0 08 ...Z.RS......B..
0800:5870 BB 03 00 EE 8A A7 AA 08 26 88 25 26 8A 25 4B D0 ........&.%&.%K.
0800:5880 E8 73 F0 4A B0 02 EE 86 C4 B0 0F 42 EE 5B 5A C3 .s.J.......B.[Z.
0800:5890 F6 06 10 02 04 75 0E 57 BF 60 6D E8 C7 FF 47 E8 .....u.W.`m...G.
0800:58A0 C3 FF 5F EB 06 E8 BD FF 26 8A 05 B0 08 EE 32 C0 .._.....&.....2.
0800:58B0 42 EE 4A C3 D1 E5 D1 E5 D1 E5 03 D5 8B DA C3 52 B.J............R
0800:58C0 BA CE 03 B0 02 EE A0 5B 07 42 EE 5A C3 B8 08 FF .......[.B.Z....
0800:58D0 EE 86 C4 42 EE 4A C3 8A FD 84 E8 75 0D 0A FD 84 ...B.J.....u....
0800:58E0 FC 75 0C 42 D0 CD 73 F1 D0 C5 F6 D0 22 F8 C3 42 .u.B..s....."..B
0800:58F0 C3 84 C5 74 03 47 EB 15 8A FD 84 FC 75 16 84 E8 ...t.G......u...
0800:5900 75 0B 0A FD 84 FC 75 0C 42 D0 C5 73 F1 D0 CD F6 u.....u.B..s....
0800:5910 D0 22 F8 C3 42 C3 32 C9 26 8A 04 22 C3 32 C3 75 ."..B.2.&..".2.u
0800:5920 1B 0B FF 74 0D 46 26 8A 04 F6 D0 0A C0 75 0D 4F ...t.F&......u.O
0800:5930 75 F3 46 26 8A 04 22 C7 32 C7 74 02 8A C8 C3 52 u.F&..".2.t....R
0800:5940 55 FF 36 5C 07 FF 36 5A 07 53 89 3E B6 08 8A C3 U.6\..6Z.S.>....
0800:5950 B4 FF E8 74 FD 0A C0 74 05 E8 23 01 75 42 83 3E ...t...t..#.uB.>
0800:5960 B6 08 00 74 2B 46 89 36 5C 07 C6 06 5A 07 80 33 ...t+F.6\...Z..3
0800:5970 ED 84 26 5A 07 74 0C 50 FF 16 2C 02 3A 86 AE 08 ..&Z.t.P..,.:...
0800:5980 58 75 1D 45 D0 2E 5A 07 73 E7 FF 0E B6 08 75 D5 Xu.E..Z.s.....u.
0800:5990 5B 0A FF 53 74 08 8A C7 46 E8 AF 00 75 02 B1 FF [..St...F...u...
0800:59A0 FE C1 5B 8F 06 5A 07 8F 06 5C 07 5D 5A C3 32 C9 ..[..Z...\.]Z.2.
0800:59B0 26 8A 04 22 C3 32 C3 75 1F 0A FF 74 1D 0B FF 74 &..".2.u...t...t
0800:59C0 0D 4E 26 8A 04 F6 D0 0A C0 75 0D 4F 75 F3 4E 26 .N&......u.Ou.N&
0800:59D0 8A 04 22 C7 32 C7 74 02 8A C8 C3 52 55 FF 36 5C ..".2.t....RU.6\
0800:59E0 07 FF 36 5A 07 53 8A C3 89 3E B6 08 B4 FF E8 D8 ..6Z.S...>......
0800:59F0 FC 0A C0 74 05 E8 53 00 75 43 83 3E B6 08 00 74 ...t..S.uC.>...t
0800:5A00 2C 4E 89 36 5C 07 C6 06 5A 07 01 BD 07 00 84 26 ,N.6\...Z......&
0800:5A10 5A 07 74 0C 50 FF 16 2C 02 3A 86 AE 08 58 75 1D Z.t.P..,.:...Xu.
0800:5A20 4D D0 26 5A 07 73 E7 FF 0E B6 08 75 D4 5B 0A FF M.&Z.s.....u.[..
0800:5A30 53 74 08 8A C7 4E E8 46 00 75 02 B1 FF FE C1 5B St...N.F.u.....[
0800:5A40 8F 06 5A 07 8F 06 5C 07 5D 5A C3 B5 80 BD 08 00 ..Z...\.]Z......
0800:5A50 D0 C5 4D D0 C8 73 F9 88 2E 5A 07 84 26 5A 07 74 ..M..s...Z..&Z.t
0800:5A60 10 50 89 36 5C 07 FF 16 2C 02 38 86 AE 08 58 75 .P.6\...,.8...Xu
0800:5A70 0D 4D D0 C8 73 06 D0 26 5A 07 73 DF 33 ED C3 B5 .M..s..&Z.s.3...
0800:5A80 01 33 ED F7 D5 D0 CD 45 D0 C0 73 F9 89 36 5C 07 .3.....E..s..6\.
0800:5A90 88 2E 5A 07 84 26 5A 07 74 0C 50 FF 16 2C 02 38 ..Z..&Z.t.P..,.8
0800:5AA0 86 AE 08 58 75 0D D0 C0 73 07 45 D0 2E 5A 07 73 ...Xu...s.E..Z.s
0800:5AB0 E3 33 ED C3 BE 60 6D F7 C7 01 00 75 0C 46 4E 26 .3...`m....u.FN&
0800:5AC0 8A 04 26 88 05 4F 49 E3 0A 46 26 8A 04 26 88 05 ..&..OI..F&..&..
0800:5AD0 4F E2 EB C3 BE 60 6D F7 C7 01 00 75 0C 46 4E 26 O....`m....u.FN&
0800:5AE0 8A 04 26 88 05 47 49 E3 0A 46 26 8A 04 26 88 05 ..&..GI..F&..&..
0800:5AF0 47 E2 EB C3 06 E8 90 FC D0 C5 73 08 83 EE 01 73 G.........s....s
0800:5B00 03 E9 A1 00 3B 36 76 07 73 03 E9 98 00 75 09 3A ....;6v.s....u.:
0800:5B10 2E 74 07 76 03 E9 8D 00 8B FE 8A CD BD FF FF 33 .t.v...........3
0800:5B20 D2 32 E4 26 8A 05 84 C5 74 04 32 C9 EB 77 3B 3E .2.&....t.2..w;>
0800:5B30 76 07 75 04 8A 26 74 07 84 C5 75 0F 84 E5 75 0B v.u..&t...u...u.
0800:5B40 D0 C5 73 F4 4F 45 26 8A 05 EB E3 3B 36 76 07 74 ..s.OE&....;6v.t
0800:5B50 02 32 E4 8A E9 26 8A 04 E8 96 FD 8A DF 32 FF 56 .2...&.......2.V
0800:5B60 45 74 13 4D B5 01 26 8A 05 3B 3E 76 07 75 04 8A Et.M..&..;>v.u..
0800:5B70 26 74 07 E8 7B FD 89 3E 5C 07 88 2E 5A 07 57 8B &t..{..>\...Z.W.
0800:5B80 FD 80 3E 61 07 00 74 05 E8 50 FE EB 06 E8 2F FD ..>a..t..P..../.
0800:5B90 E8 1B FE 5E 5F 0A C9 74 09 32 ED F6 D5 FD E8 09 ...^_..t.2......
0800:5BA0 FC FC E8 0F FD E8 D9 D9 07 C3 06 E8 DA FB 26 8A ..............&.
0800:5BB0 04 32 E4 3B 36 78 07 75 04 8A 26 75 07 84 C5 74 .2.;6x.u..&u...t
0800:5BC0 13 84 E5 75 0F 4A 74 0C D0 CD 73 F1 46 26 8A 04 ...u.Jt...s.F&..
0800:5BD0 B5 80 EB DF 84 C5 74 04 33 D2 EB 71 52 33 D2 89 ......t.3..qR3..
0800:5BE0 36 62 07 56 88 2E 64 07 E8 EC FC 8A DF 32 FF 33 6b.V..d......2.3
0800:5BF0 ED 8B 3E 78 07 2B FE F6 C3 01 74 20 0B FF 74 1C ..>x.+....t ..t.
0800:5C00 4D B5 80 45 46 26 8A 04 0A C0 75 03 4F 75 F4 3B M..EF&....u.Ou.;
0800:5C10 36 78 07 75 04 8A 26 75 07 E8 BB FC 89 36 5C 07 6x.u..&u.....6\.
0800:5C20 88 2E 5A 07 5F 57 56 8B F7 8B FD 80 3E 61 07 00 ..Z._WV.....>a..
0800:5C30 74 05 E8 0A FD EB 06 E8 85 FC E8 D9 FC 5E 5F 0A t............^_.
0800:5C40 C9 74 06 32 ED FC E8 61 FB E8 68 FC 5A E8 31 D9 .t.2...a..h.Z.1.
0800:5C50 8B 36 62 07 A0 64 07 07 C3 00 00 01 02 03 04 05 .6b..d..........
0800:5C60 06 07 10 11 12 13 14 15 16 17 00 01 02 03 04 05 ................
0800:5C70 14 07 38 39 3A 3B 3C 3D 3E 3F E9 FF EB E9 3F EC ..89:;<=>?....?.
0800:5C80 F6 06 55 07 18 75 F3 80 3E 50 07 00 74 28 A0 7A ..U..u..>P..t(.z
0800:5C90 07 56 57 06 1E 1E 07 BF CA 08 57 C5 36 FB 01 B9 .VW.......W.6...
0800:5CA0 10 00 F3 A4 AA 5A 1F B0 02 55 56 57 B4 10 CD 10 .....Z...UVW....
0800:5CB0 5F 5E 5D 07 5F 5E C3 F6 06 55 07 18 75 BF 80 3E _^]._^...U..u..>
0800:5CC0 50 07 00 74 25 3D FF FF 75 04 3B D0 74 1D FF 16 P..t%=..u.;.t...
0800:5CD0 0B 02 72 16 32 FF 88 87 CA 08 86 F8 B0 00 55 56 ..r.2.........UV
0800:5CE0 57 B4 10 CD 10 5F 5E 5D F8 C3 F9 C3 3A 1E F3 01 W...._^]....:...
0800:5CF0 77 F8 83 E2 3F 25 3F 3F F6 06 55 07 18 75 46 B9 w...?%??..U..uF.
0800:5D00 04 00 D3 E8 D3 EA D0 E8 D0 D5 D0 EC D0 D5 D0 EA ................
0800:5D10 D0 D5 D0 E8 D0 D5 D0 EC D0 D5 D0 EA D0 D5 8A C5 ................
0800:5D20 80 3E F4 01 0F 75 1E 24 07 80 E5 38 D0 ED D0 ED .>...u.$...8....
0800:5D30 D0 ED 84 C5 75 0D 0A C5 3C 07 75 09 F6 C5 02 74 ....u...<.u....t
0800:5D40 04 32 C0 0C 10 F8 C3 57 FC 33 C9 8A 0E F3 01 41 .2.....W.3.....A
0800:5D50 26 AD 92 26 AD 92 83 FA FF 75 04 3B D0 74 0A 33 &..&.....u.;.t.3
0800:5D60 DB 51 FF 16 0B 02 59 72 22 E2 E5 8A 0E F3 01 41 .Q....Yr"......A
0800:5D70 8B D9 4E 4E FD 4B 26 AD 99 92 26 AD 53 51 FF 16 ..NN.K&...&.SQ..
0800:5D80 09 02 59 5B 72 05 E2 ED F8 EB 01 F9 FC 5F C3 00 ..Y[r........_..
0800:5D90 DA 0D 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................
