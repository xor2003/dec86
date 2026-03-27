	.286
	ifndef	??version
?debug	macro
	endm
$comm	macro	name,dist,size,count
	comm	dist name:BYTE:count*size
	endm
	else
$comm	macro	name,dist,size,count
	comm	dist name[size]:BYTE:count
	endm
	endif
	?debug	S "matrixmu.c"
	?debug	C E924AD04590A6D61747269786D752E63
_TEXT	segment byte public 'CODE'
_TEXT	ends
DGROUP	group	_DATA,_BSS
	assume	cs:_TEXT,ds:DGROUP
_DATA	segment word public 'DATA'
d@	label	byte
d@w	label	word
_DATA	ends
_BSS	segment word public 'BSS'
b@	label	byte
b@w	label	word
_BSS	ends
_TEXT	segment byte public 'CODE'
   ;	
   ;	static void multMatrix (int a[n][m], int b[m][n], int c[n][n])
   ;	
	assume	cs:_TEXT
multMatrix	proc	near
	push	bp
	mov	bp,sp
	push	si
	push	di
   ;	
   ;	{ int i,j,k;
   ;	
   ;		for (i=0; i<n; i++)
   ;	
	xor	di,di
	jmp	short @1@242
@1@50:
   ;	
   ;		    for (j=0; j<m; j++)
   ;	
	xor	si,si
	jmp	short @1@194
@1@74:
   ;	
   ;			for (k=0; k<m; k++)
   ;	
	xor	cx,cx
	jmp	short @1@146
@1@98:
   ;	
   ;			    c[i][j] = a[i][k] * b[k][j] + c[i][j];
   ;	
	mov	ax,di
	shl	ax,3
	mov	bx,word ptr [bp+4]
	add	bx,ax
	mov	ax,cx
	shl	ax,1
	add	bx,ax
	mov	ax,word ptr [bx]
	push	ax
	mov	ax,cx
	mov	dx,10
	imul	dx
	mov	bx,word ptr [bp+6]
	add	bx,ax
	mov	ax,si
	shl	ax,1
	add	bx,ax
	pop	ax
	imul	word ptr [bx]
	push	ax
	mov	ax,di
	mov	dx,10
	imul	dx
	mov	bx,word ptr [bp+8]
	add	bx,ax
	mov	ax,si
	shl	ax,1
	add	bx,ax
	pop	ax
	add	ax,word ptr [bx]
	push	ax
	mov	ax,di
	mov	dx,10
	imul	dx
	mov	bx,word ptr [bp+8]
	add	bx,ax
	mov	ax,si
	shl	ax,1
	add	bx,ax
	pop	ax
	mov	word ptr [bx],ax
	inc	cx
@1@146:
	cmp	cx,4
	jl	short @1@98
	inc	si
@1@194:
	cmp	si,4
	jl	short @1@74
	inc	di
@1@242:
	cmp	di,5
	jl	short @1@50
   ;	
   ;	}
   ;	
	pop	di
	pop	si
	pop	bp
	ret	
multMatrix	endp
   ;	
   ;	main()
   ;	
	assume	cs:_TEXT
_main	proc	near
	enter	120,0
   ;	
   ;	{ int a[n][m], b[n][m], c[n][m];
   ;	
   ;		multMatrix (a,b,c);
   ;	
	lea	ax,word ptr [bp-120]
	push	ax
	lea	ax,word ptr [bp-80]
	push	ax
	lea	ax,word ptr [bp-40]
	push	ax
	call	near ptr multMatrix
	add	sp,6
   ;	
   ;	}
   ;	
	leave	
	ret	
_main	endp
	?debug	C E9
_TEXT	ends
_DATA	segment word public 'DATA'
s@	label	byte
_DATA	ends
_TEXT	segment byte public 'CODE'
_TEXT	ends
_multMatrix	equ	multMatrix
	public	_main
	end
