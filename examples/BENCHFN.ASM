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
	?debug	S "benchfn.c"
	?debug	C E924AD04590962656E6368666E2E63
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
   ;	f3() { ;}
   ;	
	assume	cs:_TEXT
_f3	proc	near
	push	bp
	mov	bp,sp
	pop	bp
	ret	
_f3	endp
   ;	
   ;	f2() { f3();f3();f3();f3();f3();f3();f3();f3();f3();f3();} /* 10 */
   ;	
	assume	cs:_TEXT
_f2	proc	near
	push	bp
	mov	bp,sp
	call	near ptr _f3
	call	near ptr _f3
	call	near ptr _f3
	call	near ptr _f3
	call	near ptr _f3
	call	near ptr _f3
	call	near ptr _f3
	call	near ptr _f3
	call	near ptr _f3
	call	near ptr _f3
	pop	bp
	ret	
_f2	endp
   ;	
   ;	f1() { f2();f2();f2();f2();f2();f2();f2();f2();f2();f2();} /* 10 */
   ;	
	assume	cs:_TEXT
_f1	proc	near
	push	bp
	mov	bp,sp
	call	near ptr _f2
	call	near ptr _f2
	call	near ptr _f2
	call	near ptr _f2
	call	near ptr _f2
	call	near ptr _f2
	call	near ptr _f2
	call	near ptr _f2
	call	near ptr _f2
	call	near ptr _f2
	pop	bp
	ret	
_f1	endp
   ;	
   ;	f0() { f1();f1();f1();f1();f1();f1();f1();f1();f1();} /* 9 */
   ;	
	assume	cs:_TEXT
_f0	proc	near
	push	bp
	mov	bp,sp
	call	near ptr _f1
	call	near ptr _f1
	call	near ptr _f1
	call	near ptr _f1
	call	near ptr _f1
	call	near ptr _f1
	call	near ptr _f1
	call	near ptr _f1
	call	near ptr _f1
	pop	bp
	ret	
_f0	endp
   ;	
   ;	main(int ac, char *av[])
   ;	
	assume	cs:_TEXT
_main	proc	near
	enter	8,0
   ;	
   ;	{ long d, major;
   ;	
   ;		printf ("enter number of iterations ");
   ;	
	push	offset DGROUP:s@
	call	near ptr _printf
	pop	cx
   ;	
   ;		scanf ("%ld", &major);
   ;	
	lea	ax,word ptr [bp-8]
	push	ax
	push	offset DGROUP:s@+28
	call	near ptr _scanf
	pop	cx
	pop	cx
   ;	
   ;	        printf("executing %ld iterations\n", major);
   ;	
	push	word ptr [bp-6]
	push	word ptr [bp-8]
	push	offset DGROUP:s@+32
	call	near ptr _printf
	add	sp,6
   ;	
   ;	        for (d = 1; d <= major; ++d)
   ;	
	mov	word ptr [bp-4],1
	mov	word ptr [bp-2],0
	jmp	short @5@98
@5@50:
   ;	
   ;	                f0(); /* executes 1000 calls */
   ;	
	call	near ptr _f0
	add	word ptr [bp-4],1
	adc	word ptr [bp-2],0
@5@98:
	mov	ax,word ptr [bp-2]
	mov	dx,word ptr [bp-4]
	cmp	ax,word ptr [bp-6]
	jl	short @5@50
	jg	short @5@170
	cmp	dx,word ptr [bp-8]
	jbe	short @5@50
@5@170:
   ;	
   ;		printf ("finished\n");
   ;	
	push	offset DGROUP:s@+58
	call	near ptr _printf
	pop	cx
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
	db	'enter number of iterations '
	db	0
	db	'%ld'
	db	0
	db	'executing %ld iterations'
	db	10
	db	0
	db	'finished'
	db	10
	db	0
_DATA	ends
_TEXT	segment byte public 'CODE'
_TEXT	ends
	extrn	_printf:near
	public	_f3
	public	_f2
	public	_main
	public	_f1
	extrn	__setargv__:far
	extrn	_scanf:near
	public	_f0
	end
