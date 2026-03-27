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
	?debug	S "intops.c"
	?debug	C E924AD045908696E746F70732E63
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
	push	si
   ;	
   ;	{ TYPE a, b;
   ;	
   ;		a = 255;
   ;	
	mov	word ptr [bp-2],255
   ;	
   ;		b = 143;
   ;	
	mov	si,143
   ;	
   ;		b = a + b;
   ;	
	mov	ax,word ptr [bp-2]
	add	ax,si
	mov	si,ax
   ;	
   ;		a = a - b;
   ;	
	mov	ax,word ptr [bp-2]
	sub	ax,si
	mov	word ptr [bp-2],ax
   ;	
   ;		a = a * b;
   ;	
	mov	ax,word ptr [bp-2]
	imul	si
	mov	word ptr [bp-2],ax
   ;	
   ;		b = b / a;
   ;	
	mov	ax,si
	cwd	
	idiv	word ptr [bp-2]
	mov	si,ax
   ;	
   ;		b = b % a;
   ;	
	mov	ax,si
	cwd	
	idiv	word ptr [bp-2]
	mov	si,dx
   ;	
   ;		a = a << 5;
   ;	
	mov	ax,word ptr [bp-2]
	shl	ax,5
	mov	word ptr [bp-2],ax
   ;	
   ;		b = b >> a;
   ;	
	mov	ax,si
	mov	cl,byte ptr [bp-2]
	sar	ax,cl
	mov	si,ax
   ;	
   ;		printf ("a = %d, b = %d\n", a, b);
   ;	
	push	si
	push	word ptr [bp-2]
	push	offset DGROUP:s@
	call	near ptr _printf
	add	sp,6
   ;	
   ;	}
   ;	
	pop	si
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