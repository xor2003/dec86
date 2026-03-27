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
	?debug	S "benchmul.c"
	?debug	C E924AD04590A62656E63686D756C2E63
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
   ;	main(int ac, char *av[])
   ;	
	assume	cs:_TEXT
_main	proc	near
	enter	12,0
	push	si
   ;	
   ;	{ STOR_CL TYPE a, b, c;
   ;	  long d, major;
   ;	
   ;		printf ("enter number of iterations\n");
   ;	
	push	offset DGROUP:s@
	call	near ptr _printf
	pop	cx
   ;	
   ;		scanf ("%ld", &major);
   ;	
	lea	ax,word ptr [bp-12]
	push	ax
	push	offset DGROUP:s@+28
	call	near ptr _scanf
	pop	cx
	pop	cx
   ;	
   ;	        printf("executing %ld iterations\n", major);
   ;	
	push	word ptr [bp-10]
	push	word ptr [bp-12]
	push	offset DGROUP:s@+32
	call	near ptr _printf
	add	sp,6
   ;	
   ;		scanf ("%d", &a);
   ;	
	lea	ax,word ptr [bp-2]
	push	ax
	push	offset DGROUP:s@+58
	call	near ptr _scanf
	pop	cx
	pop	cx
   ;	
   ;		scanf ("%d", &b);
   ;	
	lea	ax,word ptr [bp-4]
	push	ax
	push	offset DGROUP:s@+61
	call	near ptr _scanf
	pop	cx
	pop	cx
   ;	
   ;		for (d = 1; d <= major; ++d)
   ;	
	mov	word ptr [bp-8],1
	mov	word ptr [bp-6],0
	jmp	short @1@170
@1@50:
   ;	
   ;		{
   ;	                /* inner loop executes 1000 selected operations */
   ;	                for (c = 1; c <= 40; ++c)
   ;	
	mov	si,1
	jmp	short @1@122
@1@74:
   ;	
   ;			{
   ;	                        a = 3 *a*a*a*a*a*a*a*a * a*a*a*a*a*a*a*a * a*a*a*a*a*a*a*a * a; /* 25 * */
   ;	
	mov	ax,word ptr [bp-2]
	imul	word ptr [bp-2]
	imul	word ptr [bp-2]
	imul	word ptr [bp-2]
	imul	word ptr [bp-2]
	imul	word ptr [bp-2]
	imul	word ptr [bp-2]
	imul	word ptr [bp-2]
	imul	word ptr [bp-2]
	imul	word ptr [bp-2]
	imul	word ptr [bp-2]
	imul	word ptr [bp-2]
	imul	word ptr [bp-2]
	imul	word ptr [bp-2]
	imul	word ptr [bp-2]
	imul	word ptr [bp-2]
	imul	word ptr [bp-2]
	imul	word ptr [bp-2]
	imul	word ptr [bp-2]
	imul	word ptr [bp-2]
	imul	word ptr [bp-2]
	imul	word ptr [bp-2]
	imul	word ptr [bp-2]
	imul	word ptr [bp-2]
	imul	word ptr [bp-2]
	mov	dx,3
	imul	dx
	mov	word ptr [bp-2],ax
	inc	si
@1@122:
	cmp	si,40
	jle	short @1@74
	add	word ptr [bp-8],1
	adc	word ptr [bp-6],0
@1@170:
	mov	ax,word ptr [bp-6]
	mov	dx,word ptr [bp-8]
	cmp	ax,word ptr [bp-10]
	jl	short @1@50
	jg	short @1@242
	cmp	dx,word ptr [bp-12]
	jbe	short @1@50
@1@242:
   ;	
   ;			}
   ;		}
   ;	        printf("a=%d\n", a);
   ;	
	push	word ptr [bp-2]
	push	offset DGROUP:s@+64
	call	near ptr _printf
	pop	cx
	pop	cx
   ;	
   ;	  }
   ;	
	pop	si
	leave	
	ret	
_main	endp
	?debug	C E9
_TEXT	ends
_DATA	segment word public 'DATA'
s@	label	byte
	db	'enter number of iterations'
	db	10
	db	0
	db	'%ld'
	db	0
	db	'executing %ld iterations'
	db	10
	db	0
	db	'%d'
	db	0
	db	'%d'
	db	0
	db	'a=%d'
	db	10
	db	0
_DATA	ends
_TEXT	segment byte public 'CODE'
_TEXT	ends
	extrn	_printf:near
	public	_main
	extrn	__setargv__:far
	extrn	_scanf:near
	end
