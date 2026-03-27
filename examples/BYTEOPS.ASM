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
	?debug	S "byteops.c"
	?debug	C E924AD045909627974656F70732E63
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
   ;	main()
   ;	
	assume	cs:_TEXT
_main	proc	near
	enter	2,0
   ;	
   ;	{ TYPE a, b;
   ;	
   ;		a = 255;
   ;	
	mov	byte ptr [bp-1],255
   ;	
   ;		b = 143;
   ;	
	mov	byte ptr [bp-2],143
   ;	
   ;		b = a + b;
   ;	
	mov	al,byte ptr [bp-1]
	add	al,byte ptr [bp-2]
	mov	byte ptr [bp-2],al
   ;	
   ;		a = a - b;
   ;	
	mov	al,byte ptr [bp-1]
	sub	al,byte ptr [bp-2]
	mov	byte ptr [bp-1],al
   ;	
   ;		a = a * b;
   ;	
	mov	al,byte ptr [bp-1]
	mov	ah,0
	mov	dl,byte ptr [bp-2]
	mov	dh,0
	imul	dx
	mov	byte ptr [bp-1],al
   ;	
   ;		b = b / a;
   ;	
	mov	al,byte ptr [bp-2]
	mov	ah,0
	mov	dl,byte ptr [bp-1]
	mov	dh,0
	push	dx
	cwd	
	pop	bx
	idiv	bx
	mov	byte ptr [bp-2],al
   ;	
   ;		b = b % a;
   ;	
	mov	al,byte ptr [bp-2]
	mov	ah,0
	mov	dl,byte ptr [bp-1]
	mov	dh,0
	push	dx
	cwd	
	pop	bx
	idiv	bx
	mov	byte ptr [bp-2],dl
   ;	
   ;		a = a << 5;
   ;	
	mov	al,byte ptr [bp-1]
	shl	al,5
	mov	byte ptr [bp-1],al
   ;	
   ;		b = b >> a;
   ;	
	mov	al,byte ptr [bp-2]
	mov	ah,0
	mov	cl,byte ptr [bp-1]
	sar	ax,cl
	mov	byte ptr [bp-2],al
   ;	
   ;		printf ("a = %d, b = %d\n", a, b);
   ;	
	mov	al,byte ptr [bp-2]
	mov	ah,0
	push	ax
	mov	al,byte ptr [bp-1]
	mov	ah,0
	push	ax
	push	offset DGROUP:s@
	call	near ptr _printf
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
	db	'a = %d, b = %d'
	db	10
	db	0
_DATA	ends
_TEXT	segment byte public 'CODE'
_TEXT	ends
	extrn	_printf:near
	public	_main
	end
