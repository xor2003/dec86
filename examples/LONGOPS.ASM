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
	?debug	S "longops.c"
	?debug	C E924AD0459096C6F6E676F70732E63
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
	enter	8,0
   ;	
   ;	{ TYPE a, b;
   ;	
   ;		a = 255;
   ;	
	mov	word ptr [bp-4],255
	mov	word ptr [bp-2],0
   ;	
   ;		b = 143;
   ;	
	mov	word ptr [bp-8],143
	mov	word ptr [bp-6],0
   ;	
   ;		b = a + b;
   ;	
	mov	ax,word ptr [bp-2]
	mov	dx,word ptr [bp-4]
	add	dx,word ptr [bp-8]
	adc	ax,word ptr [bp-6]
	mov	word ptr [bp-8],dx
	mov	word ptr [bp-6],ax
   ;	
   ;		a = a - b;
   ;	
	mov	ax,word ptr [bp-2]
	mov	dx,word ptr [bp-4]
	sub	dx,word ptr [bp-8]
	sbb	ax,word ptr [bp-6]
	mov	word ptr [bp-4],dx
	mov	word ptr [bp-2],ax
   ;	
   ;		a = a * b;
   ;	
	mov	cx,word ptr [bp-2]
	mov	bx,word ptr [bp-4]
	mov	dx,word ptr [bp-6]
	mov	ax,word ptr [bp-8]
	call	near ptr N_LXMUL@
	mov	word ptr [bp-4],ax
	mov	word ptr [bp-2],dx
   ;	
   ;		b = b / a;
   ;	
	push	word ptr [bp-2]
	push	word ptr [bp-4]
	push	word ptr [bp-6]
	push	word ptr [bp-8]
	call	near ptr N_LDIV@
	mov	word ptr [bp-8],ax
	mov	word ptr [bp-6],dx
   ;	
   ;		b = b % a;
   ;	
	push	word ptr [bp-2]
	push	word ptr [bp-4]
	push	word ptr [bp-6]
	push	word ptr [bp-8]
	call	near ptr N_LMOD@
	mov	word ptr [bp-8],ax
	mov	word ptr [bp-6],dx
   ;	
   ;		a = a << 5;
   ;	
	mov	dx,word ptr [bp-2]
	mov	ax,word ptr [bp-4]
	mov	cl,5
	call	near ptr N_LXLSH@
	mov	word ptr [bp-4],ax
	mov	word ptr [bp-2],dx
   ;	
   ;		b = b >> a;
   ;	
	mov	dx,word ptr [bp-6]
	mov	ax,word ptr [bp-8]
	mov	cl,byte ptr [bp-4]
	call	near ptr N_LXRSH@
	mov	word ptr [bp-8],ax
	mov	word ptr [bp-6],dx
   ;	
   ;		printf ("a = %ld, b = %ld\n", a, b);
   ;	
	push	word ptr [bp-6]
	push	word ptr [bp-8]
	push	word ptr [bp-2]
	push	word ptr [bp-4]
	push	offset DGROUP:s@
	call	near ptr _printf
	add	sp,10
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
	db	'a = %ld, b = %ld'
	db	10
	db	0
_DATA	ends
_TEXT	segment byte public 'CODE'
_TEXT	ends
	extrn	_printf:near
	public	_main
	extrn	N_LDIV@:far
	extrn	N_LXMUL@:far
	extrn	N_LXRSH@:far
	extrn	N_LXLSH@:far
	extrn	N_LMOD@:far
	end
