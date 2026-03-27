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
	?debug	S "fibo.c"
	?debug	C E924AD0459066669626F2E63
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
   ;	int main()
   ;	
	assume	cs:_TEXT
_main	proc	near
	enter	4,0
	push	si
	push	di
   ;	
   ;	{ int i, numtimes, number;
   ;	  unsigned value, fib();
   ;	
   ;	    printf("Input number of iterations: ");
   ;	
	push	offset DGROUP:s@
	call	near ptr _printf
	pop	cx
   ;	
   ;	    scanf ("%d", &numtimes);
   ;	
	lea	ax,word ptr [bp-2]
	push	ax
	push	offset DGROUP:s@+29
	call	near ptr _scanf
	pop	cx
	pop	cx
   ;	
   ;	    for (i = 1; i <= numtimes; i++)
   ;	
	mov	si,1
	jmp	short @1@98
@1@50:
   ;	
   ;	    {
   ;		printf ("Input number: ");
   ;	
	push	offset DGROUP:s@+32
	call	near ptr _printf
	pop	cx
   ;	
   ;		scanf ("%d", &number);
   ;	
	lea	ax,word ptr [bp-4]
	push	ax
	push	offset DGROUP:s@+47
	call	near ptr _scanf
	pop	cx
	pop	cx
   ;	
   ;		value = fib(number);
   ;	
	push	word ptr [bp-4]
	call	near ptr _fib
	pop	cx
	mov	di,ax
   ;	
   ;		printf("fibonacci(%d) = %u\n", number, value);
   ;	
	push	di
	push	word ptr [bp-4]
	push	offset DGROUP:s@+50
	call	near ptr _printf
	add	sp,6
	inc	si
@1@98:
	cmp	si,word ptr [bp-2]
	jle	short @1@50
   ;	
   ;	    }
   ;	    exit(0);
   ;	
	push	0
	call	near ptr _exit
	pop	cx
   ;	
   ;	}
   ;	
	pop	di
	pop	si
	leave	
	ret	
_main	endp
   ;	
   ;	unsigned fib(x) 		/* compute fibonacci number recursively */
   ;	
	assume	cs:_TEXT
_fib	proc	near
	push	bp
	mov	bp,sp
	push	si
	mov	si,word ptr [bp+4]
   ;	
   ;	int x;
   ;	{
   ;	    if (x > 2)
   ;	
	cmp	si,2
	jle	short @2@98
   ;	
   ;		return (fib(x - 1) + fib(x - 2));
   ;	
	mov	ax,si
	dec	ax
	push	ax
	call	near ptr _fib
	pop	cx
	push	ax
	mov	ax,si
	add	ax,65534
	push	ax
	call	near ptr _fib
	pop	cx
	mov	dx,ax
	pop	ax
	add	ax,dx
	jmp	short @2@122
	jmp	short @2@122
@2@98:
   ;	
   ;	    else
   ;		return (1);
   ;	
	mov	ax,1
	jmp	short @2@122
@2@122:
   ;	
   ;	}
   ;	
	pop	si
	pop	bp
	ret	
_fib	endp
	?debug	C E9
_TEXT	ends
_DATA	segment word public 'DATA'
s@	label	byte
	db	'Input number of iterations: '
	db	0
	db	'%d'
	db	0
	db	'Input number: '
	db	0
	db	'%d'
	db	0
	db	'fibonacci(%d) = %u'
	db	10
	db	0
_DATA	ends
_TEXT	segment byte public 'CODE'
_TEXT	ends
	extrn	_printf:near
	public	_main
	public	_fib
	extrn	_exit:near
	extrn	_scanf:near
	end
