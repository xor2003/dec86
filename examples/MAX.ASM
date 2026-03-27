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
	?debug	S "max.c"
	?debug	C E924AD0459056D61782E63
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
	enter	4,0
   ;	
   ;	{ int a, b;
   ;	
   ;		printf ("Enter 2 numbers: ");
   ;	
	push	offset DGROUP:s@
	call	near ptr _printf
	pop	cx
   ;	
   ;		scanf ("%d %d", &a, &b);
   ;	
	lea	ax,word ptr [bp-4]
	push	ax
	lea	ax,word ptr [bp-2]
	push	ax
	push	offset DGROUP:s@+18
	call	near ptr _scanf
	add	sp,6
   ;	
   ;		if (a != b)
   ;	
	mov	ax,word ptr [bp-2]
	cmp	ax,word ptr [bp-4]
	je	short @1@74
   ;	
   ;		   printf ("Maximum: %d\n", max (a,b));
   ;	
	push	word ptr [bp-4]
	push	word ptr [bp-2]
	call	near ptr _max
	pop	cx
	pop	cx
	push	ax
	push	offset DGROUP:s@+24
	call	near ptr _printf
	pop	cx
	pop	cx
@1@74:
   ;	
   ;	}
   ;	
	leave	
	ret	
_main	endp
   ;	
   ;	max (int x, int y)
   ;	
	assume	cs:_TEXT
_max	proc	near
	push	bp
	mov	bp,sp
   ;	
   ;	{
   ;		if (x > y)
   ;	
	mov	ax,word ptr [bp+4]
	cmp	ax,word ptr [bp+6]
	jle	short @2@74
   ;	
   ;		   return (x);
   ;	
	mov	ax,word ptr [bp+4]
	jmp	short @2@98
@2@74:
   ;	
   ;		return (y);
   ;	
	mov	ax,word ptr [bp+6]
	jmp	short @2@98
@2@98:
   ;	
   ;	}
   ;	
	pop	bp
	ret	
_max	endp
	?debug	C E9
_TEXT	ends
_DATA	segment word public 'DATA'
s@	label	byte
	db	'Enter 2 numbers: '
	db	0
	db	'%d %d'
	db	0
	db	'Maximum: %d'
	db	10
	db	0
_DATA	ends
_TEXT	segment byte public 'CODE'
_TEXT	ends
	extrn	_printf:near
	public	_main
	public	_max
	extrn	_scanf:near
	end
