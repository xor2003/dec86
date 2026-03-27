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
	?debug	S "benchlng.c"
	?debug	C E924AD04590A62656E63686C6E672E63
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
	enter	20,0
   ;	
   ;	{ TYPE a, b, c;
   ;	  long d, major;
   ;	
   ;		scanf ("%ld", &major);
   ;	
	lea	ax,word ptr [bp-20]
	push	ax
	push	offset DGROUP:s@
	call	near ptr _scanf
	pop	cx
	pop	cx
   ;	
   ;	        printf("executing %ld iterations\n", major);
   ;	
	push	word ptr [bp-18]
	push	word ptr [bp-20]
	push	offset DGROUP:s@+4
	call	near ptr _printf
	add	sp,6
   ;	
   ;		scanf ("%ld", &a);
   ;	
	lea	ax,word ptr [bp-4]
	push	ax
	push	offset DGROUP:s@+30
	call	near ptr _scanf
	pop	cx
	pop	cx
   ;	
   ;		scanf ("%ld", &b);
   ;	
	lea	ax,word ptr [bp-8]
	push	ax
	push	offset DGROUP:s@+34
	call	near ptr _scanf
	pop	cx
	pop	cx
   ;	
   ;	        for (d = 1; d <= major; ++d)
   ;	
	mov	word ptr [bp-16],1
	mov	word ptr [bp-14],0
	jmp	@1@506
@1@50:
   ;	
   ;		{
   ;	                /* inner loop executes 1000 selected operations */
   ;	                for (c = 1; c <= 40; ++c)
   ;	
	mov	word ptr [bp-12],1
	mov	word ptr [bp-10],0
	jmp	@1@410
@1@74:
   ;	
   ;			{
   ;	                        a = a + b + c;
   ;	
	mov	ax,word ptr [bp-2]
	mov	dx,word ptr [bp-4]
	add	dx,word ptr [bp-8]
	adc	ax,word ptr [bp-6]
	add	dx,word ptr [bp-12]
	adc	ax,word ptr [bp-10]
	mov	word ptr [bp-4],dx
	mov	word ptr [bp-2],ax
   ;	
   ;	                        b = a >> 1;
   ;	
	mov	ax,word ptr [bp-2]
	mov	dx,word ptr [bp-4]
	sar	ax,1
	rcr	dx,1
	mov	word ptr [bp-8],dx
	mov	word ptr [bp-6],ax
   ;	
   ;	                        a = b % 10;
   ;	
	push	0
	push	10
	push	word ptr [bp-6]
	push	word ptr [bp-8]
	call	near ptr N_LMOD@
	mov	word ptr [bp-4],ax
	mov	word ptr [bp-2],dx
   ;	
   ;	                        a = b == c;
   ;	
	mov	ax,word ptr [bp-6]
	mov	dx,word ptr [bp-8]
	cmp	ax,word ptr [bp-10]
	jne	short @1@146
	cmp	dx,word ptr [bp-12]
	jne	short @1@146
	mov	ax,1
	jmp	short @1@170
@1@146:
	xor	ax,ax
@1@170:
	cwd	
	mov	word ptr [bp-4],ax
	mov	word ptr [bp-2],dx
   ;	
   ;	                        b = a | c;
   ;	
	mov	ax,word ptr [bp-2]
	mov	dx,word ptr [bp-4]
	or	dx,word ptr [bp-12]
	or	ax,word ptr [bp-10]
	mov	word ptr [bp-8],dx
	mov	word ptr [bp-6],ax
   ;	
   ;	                        a = !b;
   ;	
	mov	ax,word ptr [bp-8]
	or	ax,word ptr [bp-6]
	jne	short @1@218
	mov	ax,1
	jmp	short @1@242
@1@218:
	xor	ax,ax
@1@242:
	cwd	
	mov	word ptr [bp-4],ax
	mov	word ptr [bp-2],dx
   ;	
   ;	                        b = a + c;
   ;	
	mov	ax,word ptr [bp-2]
	mov	dx,word ptr [bp-4]
	add	dx,word ptr [bp-12]
	adc	ax,word ptr [bp-10]
	mov	word ptr [bp-8],dx
	mov	word ptr [bp-6],ax
   ;	
   ;	                        a = b > c;
   ;	
	mov	ax,word ptr [bp-6]
	mov	dx,word ptr [bp-8]
	cmp	ax,word ptr [bp-10]
	jl	short @1@338
	jg	short @1@314
	cmp	dx,word ptr [bp-12]
	jbe	short @1@338
@1@314:
	mov	ax,1
	jmp	short @1@362
@1@338:
	xor	ax,ax
@1@362:
	cwd	
	mov	word ptr [bp-4],ax
	mov	word ptr [bp-2],dx
	add	word ptr [bp-12],1
	adc	word ptr [bp-10],0
@1@410:
	cmp	word ptr [bp-10],0
	jge	@@0
	jmp	@1@74
@@0:
	jg	short @1@482
	cmp	word ptr [bp-12],40
	ja	@@1
	jmp	@1@74
@@1:
@1@482:
	add	word ptr [bp-16],1
	adc	word ptr [bp-14],0
@1@506:
	mov	ax,word ptr [bp-14]
	mov	dx,word ptr [bp-16]
	cmp	ax,word ptr [bp-18]
	jge	@@2
	jmp	@1@50
@@2:
	jg	short @1@578
	cmp	dx,word ptr [bp-20]
	ja	@@3
	jmp	@1@50
@@3:
@1@578:
   ;	
   ;			}
   ;		}
   ;	        printf("a=%d\n", a);
   ;	
	push	word ptr [bp-2]
	push	word ptr [bp-4]
	push	offset DGROUP:s@+38
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
	extrn	N_LMOD@:far
	extrn	_scanf:near
	end
