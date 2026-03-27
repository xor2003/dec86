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
	?debug	S "testlong.c"
	?debug	C E924AD04590A746573746C6F6E672E63
	?debug	C E95DAF045916433A5C5443435C494E434C5544455C737464696F2E+
	?debug	C 68
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
   ;	{ long a, d;
   ;	
   ;		scanf ("%d", &d);
   ;	
	lea	ax,word ptr [bp-8]
	push	ax
	push	offset DGROUP:s@
	call	near ptr _scanf
	pop	cx
	pop	cx
   ;	
   ;		scanf ("%d", &a);
   ;	
	lea	ax,word ptr [bp-4]
	push	ax
	push	offset DGROUP:s@+3
	call	near ptr _scanf
	pop	cx
	pop	cx
   ;	
   ;		scanf ("%d %d", &a, &d);
   ;	
	lea	ax,word ptr [bp-8]
	push	ax
	lea	ax,word ptr [bp-4]
	push	ax
	push	offset DGROUP:s@+6
	call	near ptr _scanf
	add	sp,6
   ;	
   ;		printf ("%ld %ld", a, d);
   ;	
	push	word ptr [bp-6]
	push	word ptr [bp-8]
	push	word ptr [bp-2]
	push	word ptr [bp-4]
	push	offset DGROUP:s@+12
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
	db	'%d'
	db	0
	db	'%d'
	db	0
	db	'%d %d'
	db	0
	db	'%ld %ld'
	db	0
_DATA	ends
_TEXT	segment byte public 'CODE'
_TEXT	ends
	extrn	_printf:near
	public	_main
	extrn	_scanf:near
	end
