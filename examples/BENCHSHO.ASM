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
	?debug	S "benchsho.c"
	?debug	C E924AD04590A62656E636873686F2E63
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
   ;		scanf ("%ld", &major);
   ;	
	lea	ax,word ptr [bp-12]
	push	ax
	push	offset DGROUP:s@
	call	near ptr _scanf
	pop	cx
	pop	cx
   ;	
   ;	        printf("executing %ld iterations\n", major);
   ;	
	push	word ptr [bp-10]
	push	word ptr [bp-12]
	push	offset DGROUP:s@+4
	call	near ptr _printf
	add	sp,6
   ;	
   ;		scanf ("%ld", &a);
   ;	
	lea	ax,word ptr [bp-2]
	push	ax
	push	offset DGROUP:s@+30
	call	near ptr _scanf
	pop	cx
	pop	cx
   ;	
   ;		scanf ("%ld", &b);
   ;	
	lea	ax,word ptr [bp-4]
	push	ax
	push	offset DGROUP:s@+34
	call	near ptr _scanf
	pop	cx
	pop	cx
   ;	
   ;		for (d = 1; d <= major; ++d)
   ;	
	mov	word ptr [bp-8],1
	mov	word ptr [bp-6],0
	jmp	short @1@314
@1@50:
   ;	
   ;		{
   ;	                /* inner loop executes 1000 selected operations */
   ;	                for (c = 1; c <= 40; ++c)
   ;	
	mov	si,1
	jmp	short @1@266
@1@74:
   ;	
   ;			{
   ;	                        a = a + b + c;
   ;	
	mov	ax,word ptr [bp-2]
	add	ax,word ptr [bp-4]
	add	ax,si
	mov	word ptr [bp-2],ax
   ;	
   ;	                        b = a >> 1;
   ;	
	mov	ax,word ptr [bp-2]
	sar	ax,1
	mov	word ptr [bp-4],ax
   ;	
   ;	                        a = b % 10;
   ;	
	mov	ax,word ptr [bp-4]
	mov	bx,10
	cwd	
	idiv	bx
	mov	word ptr [bp-2],dx
   ;	
   ;	                        a = b == c;
   ;	
	cmp	word ptr [bp-4],si
	jne	short @1@122
	mov	ax,1
	jmp	short @1@146
@1@122:
	xor	ax,ax
@1@146:
	mov	word ptr [bp-2],ax
   ;	
   ;	                        b = a | c;
   ;	
	mov	ax,word ptr [bp-2]
	or	ax,si
	mov	word ptr [bp-4],ax
   ;	
   ;	                        a = !b;
   ;	
	mov	ax,word ptr [bp-4]
	neg	ax
	sbb	ax,ax
	inc	ax
	mov	word ptr [bp-2],ax
   ;	
   ;	                        b = a + c;
   ;	
	mov	ax,word ptr [bp-2]
	add	ax,si
	mov	word ptr [bp-4],ax
   ;	
   ;	                        a = b > c;
   ;	
	cmp	word ptr [bp-4],si
	jle	short @1@194
	mov	ax,1
	jmp	short @1@218
@1@194:
	xor	ax,ax
@1@218:
	mov	word ptr [bp-2],ax
	mov	ax,si
	inc	ax
	mov	si,ax
@1@266:
	cmp	si,40
	jle	short @1@74
	add	word ptr [bp-8],1
	adc	word ptr [bp-6],0
@1@314:
	mov	ax,word ptr [bp-6]
	mov	dx,word ptr [bp-8]
	cmp	ax,word ptr [bp-10]
	jl	short @1@50
	jg	short @1@386
	cmp	dx,word ptr [bp-12]
	ja	@@0
	jmp	@1@50
@@0:
@1@386:
   ;	
   ;			}
   ;		}
   ;	        printf("a=%d\n", a);
   ;	
	push	word ptr [bp-2]
	push	offset DGROUP:s@+38
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
	db	'%ld'
	db	0
	db	'executing %ld iterations'
	db	10
	db	0
	db	'%ld'
	db	0
	db	'%ld'
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