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
	?debug	S "dhamp.c"
	?debug	C E924AD0459076468616D702E63
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
	enter	216,0
	push	si
   ;	
   ;	{
   ;	char buf1[TINY], buf2[TINY];
   ;	int i = 0;
   ;	
	xor	si,si
   ;	
   ;	unsigned fib ();
   ;	long square, sq ();
   ;	double dmath, sroot (), dply ();
   ;	
   ;	printf("Start...%c\n\n",BELL);
   ;	
	push	7
	push	offset DGROUP:s@
	call	near ptr _printf
	pop	cx
	pop	cx
	jmp	@1@314
@1@50:
   ;	
   ;	while (i < NUMTEST)
   ;	    {
   ;	    switch (i)
   ;	
	mov	bx,si
	cmp	bx,5
	jbe	@@0
	jmp	@1@266
@@0:
	shl	bx,1
	jmp	word ptr cs:@1@C1336[bx]
@1@122:
   ;	
   ;	        {
   ;	    case (0):                                   /* Character test       */
   ;	        results.cresult = stest (buf1,buf2);
   ;	
	lea	ax,word ptr [bp-216]
	push	ax
	lea	ax,word ptr [bp-116]
	push	ax
	call	near ptr _stest
	pop	cx
	pop	cx
	mov	word ptr DGROUP:_results,ax
   ;	
   ;	        printf ("\ncresult = %d\n",results.cresult);
   ;	
	push	word ptr DGROUP:_results
	push	offset DGROUP:s@+13
	call	near ptr _printf
	pop	cx
	pop	cx
   ;	
   ;	        break;
   ;	
	jmp	@1@290
@1@146:
   ;	
   ;	    case (1):                                   /* Integer test         */
   ;	        results.iresult = intest ();
   ;	
	call	near ptr _intest
	mov	word ptr DGROUP:_results+2,ax
   ;	
   ;	        printf ("\niresult = %d\n",results.iresult);
   ;	
	push	word ptr DGROUP:_results+2
	push	offset DGROUP:s@+28
	call	near ptr _printf
	pop	cx
	pop	cx
   ;	
   ;	        break;
   ;	
	jmp	@1@290
@1@170:
   ;	
   ;	    case (2):                                   /* Unsigned test        */
   ;	        results.uresult = fib (FIB);
   ;	
	push	24
	call	near ptr _fib
	pop	cx
	mov	word ptr DGROUP:_results+6,ax
   ;	
   ;	        printf ("\nuresult = %u\n",results.uresult);
   ;	
	push	word ptr DGROUP:_results+6
	push	offset DGROUP:s@+43
	call	near ptr _printf
	pop	cx
	pop	cx
   ;	
   ;	        break;
   ;	
	jmp	@1@290
@1@194:
   ;	
   ;	    case (3):                                   /* Long test            */
   ;	        square = 0L;
   ;	
	mov	word ptr [bp-4],0
	mov	word ptr [bp-2],0
   ;	
   ;	        results.lresult = sq (square);
   ;	
	push	word ptr [bp-2]
	push	word ptr [bp-4]
	call	near ptr _sq
	pop	cx
	pop	cx
	mov	word ptr DGROUP:_results+8,ax
	mov	word ptr DGROUP:_results+10,dx
   ;	
   ;	        square = sq (results.lresult);          /* Check the value      */
   ;	
	push	word ptr DGROUP:_results+10
	push	word ptr DGROUP:_results+8
	call	near ptr _sq
	pop	cx
	pop	cx
	mov	word ptr [bp-4],ax
	mov	word ptr [bp-2],dx
   ;	
   ;	        printf ("\nlresult = %ld",results.lresult);
   ;	
	push	word ptr DGROUP:_results+10
	push	word ptr DGROUP:_results+8
	push	offset DGROUP:s@+58
	call	near ptr _printf
	add	sp,6
   ;	
   ;	        printf ("\n square = %ld\n",square);
   ;	
	push	word ptr [bp-2]
	push	word ptr [bp-4]
	push	offset DGROUP:s@+73
	call	near ptr _printf
	add	sp,6
   ;	
   ;	        break;
   ;	
	jmp	@1@290
@1@218:
   ;	
   ;	    case (4):                                   /* Double test          */
   ;	        results.dresult = sroot ((double) results.lresult);
   ;	
	mov	ax,word ptr DGROUP:_results+10
	mov	dx,word ptr DGROUP:_results+8
	mov	word ptr [bp-16],dx
	mov	word ptr [bp-14],ax
	FILD	dword ptr [bp-16]
	add	sp,65528
	FSTP	qword ptr [bp-226]
	FWAIT	
	call	near ptr _sroot
	add	sp,8
	FSTP	qword ptr DGROUP:_results+12
   ;	
   ;	        printf ("\ndresult = %f\n",results.dresult);
   ;	
	FLD	qword ptr DGROUP:_results+12
	add	sp,65528
	FSTP	qword ptr [bp-226]
	push	offset DGROUP:s@+89
	FWAIT	
	call	near ptr _printf
	add	sp,10
   ;	
   ;	        dmath = dply (results.dresult);
   ;	
	FLD	qword ptr DGROUP:_results+12
	add	sp,65528
	FSTP	qword ptr [bp-226]
	FWAIT	
	call	near ptr _dply
	add	sp,8
	FSTP	qword ptr [bp-12]
   ;	
   ;	        printf ("  dmath = %f\n",dmath);
   ;	
	FLD	qword ptr [bp-12]
	add	sp,65528
	FSTP	qword ptr [bp-226]
	push	offset DGROUP:s@+104
	FWAIT	
	call	near ptr _printf
	add	sp,10
   ;	
   ;	        break;
   ;	
	jmp	short @1@290
@1@242:
   ;	
   ;	    case (5):                                   /* Disk copy            */
   ;	        results.cprsult = mcopy ();
   ;	
	call	near ptr _mcopy
	mov	word ptr DGROUP:_results+4,ax
   ;	
   ;	        printf ("\b   copy = %d",results.cprsult);
   ;	
	push	word ptr DGROUP:_results+4
	push	offset DGROUP:s@+118
	call	near ptr _printf
	pop	cx
	pop	cx
   ;	
   ;	        break;
   ;	
	jmp	short @1@290
@1@266:
   ;	
   ;	    default:
   ;	        break;
   ;	
	jmp	short @1@290
@1@290:
   ;	
   ;	        }
   ;	    ++i;
   ;	
	inc	si
@1@314:
	cmp	si,6
	jge	@@1
	jmp	@1@50
@@1:
   ;	
   ;	    }                                           /* End while i          */
   ;	printf ("\n\n...End%c",BELL);
   ;	
	push	7
	push	offset DGROUP:s@+132
	call	near ptr _printf
	pop	cx
	pop	cx
   ;	
   ;	}
   ;	
	pop	si
	leave	
	ret	
_main	endp
@1@C1336	label	word
	dw	@1@122
	dw	@1@146
	dw	@1@170
	dw	@1@194
	dw	@1@218
	dw	@1@242
_TEXT	ends
_DATA	segment word public 'DATA'
	db	1
	db	0
	db	0
	db	0
_DATA	ends
_TEXT	segment byte public 'CODE'
   ;	
   ;	long sq (big)           /* Function to square a number by iteration */
   ;	
	assume	cs:_TEXT
_sq	proc	near
	push	bp
	mov	bp,sp
	push	si
   ;	
   ;	long big;
   ;	{
   ;	int i;
   ;	static long j = 1L;
   ;	
   ;	if (!big)
   ;	
	mov	ax,word ptr [bp+4]
	or	ax,word ptr [bp+6]
	jne	short @2@170
   ;	
   ;	    for (i = 0; i < SMALL; ++i)
   ;	
	xor	si,si
	jmp	short @2@122
@2@74:
   ;	
   ;	        {
   ;	        big += j;
   ;	
	mov	ax,word ptr DGROUP:d@w+0+2
	mov	dx,word ptr DGROUP:d@w+0
	add	word ptr [bp+4],dx
	adc	word ptr [bp+6],ax
   ;	
   ;	        j += 2;
   ;	
	add	word ptr DGROUP:d@w+0,2
	adc	word ptr DGROUP:d@w+0+2,0
	inc	si
@2@122:
	cmp	si,9000
	jl	short @2@74
   ;	
   ;	        }
   ;	
	jmp	short @2@266
@2@170:
   ;	
   ;	else
   ;	    for (i = 0; i < SMALL; ++i)
   ;	
	xor	si,si
	jmp	short @2@242
@2@194:
   ;	
   ;	        {
   ;	        j -= 2;
   ;	
	sub	word ptr DGROUP:d@w+0,2
	sbb	word ptr DGROUP:d@w+0+2,0
   ;	
   ;	        big -= j;
   ;	
	mov	ax,word ptr DGROUP:d@w+0+2
	mov	dx,word ptr DGROUP:d@w+0
	sub	word ptr [bp+4],dx
	sbb	word ptr [bp+6],ax
	inc	si
@2@242:
	cmp	si,9000
	jl	short @2@194
@2@266:
   ;	
   ;	        }
   ;	return (big);
   ;	
	mov	dx,word ptr [bp+6]
	mov	ax,word ptr [bp+4]
	jmp	short @2@290
@2@290:
   ;	
   ;	}
   ;	
	pop	si
	pop	bp
	ret	
_sq	endp
   ;	
   ;	double sroot (num)      /* Find square root of number */
   ;	
	assume	cs:_TEXT
_sroot	proc	near
	enter	18,0
   ;	
   ;	double num;
   ;	{
   ;	double temp1, temp2, abs ();
   ;	
   ;	temp2 = num / 2.0;
   ;	
	FLD	qword ptr [bp+4]
	FDIV	dword ptr DGROUP:s@+143
	FSTP	qword ptr [bp-16]
   ;	
   ;	temp1 = num;
   ;	
	FLD	qword ptr [bp+4]
	FSTP	qword ptr [bp-8]
	FWAIT	
	jmp	short @3@74
@3@50:
   ;	
   ;	while (temp1 > PRECISION * temp2)
   ;	    {
   ;	    temp1 = (num / temp2) - temp2;
   ;	
	FLD	qword ptr [bp+4]
	FDIV	qword ptr [bp-16]
	FSUB	qword ptr [bp-16]
	FSTP	qword ptr [bp-8]
   ;	
   ;	    temp1 = abs (temp1);
   ;	
	FLD	qword ptr [bp-8]
	add	sp,65528
	FSTP	qword ptr [bp-26]
	FWAIT	
	call	near ptr _abs
	add	sp,8
	FSTP	qword ptr [bp-8]
   ;	
   ;	    temp2 = ((num / temp2) + temp2) / 2.0;
   ;	
	FLD	qword ptr [bp+4]
	FDIV	qword ptr [bp-16]
	FADD	qword ptr [bp-16]
	FDIV	dword ptr DGROUP:s@+143
	FSTP	qword ptr [bp-16]
	FWAIT	
@3@74:
	FLD	qword ptr DGROUP:s@+147
	FMUL	qword ptr [bp-16]
	FCOMP	qword ptr [bp-8]
	FSTSW	word ptr [bp-18]
	FWAIT	
	mov	ax,word ptr [bp-18]
	sahf	
	jb	short @3@50
   ;	
   ;	    }
   ;	return (temp2);
   ;	
	FLD	qword ptr [bp-16]
	jmp	short @3@122
@3@122:
   ;	
   ;	}
   ;	
	leave	
	ret	
_sroot	endp
   ;	
   ;	double abs (x)          /* Absolute value of a double */
   ;	
	assume	cs:_TEXT
_abs	proc	near
	enter	2,0
   ;	
   ;	double x;
   ;	{
   ;	
   ;	return (x < 0 ? -x : x);
   ;	
	FLD	qword ptr [bp+4]
	FLDZ	
	FCOMPP
	FSTSW	word ptr [bp-2]
	FWAIT	
	mov	ax,word ptr [bp-2]
	sahf	
	jbe	short @4@74
	FLD	qword ptr [bp+4]
	FCHS	
	jmp	short @4@98
@4@74:
	FLD	qword ptr [bp+4]
@4@98:
	jmp	short @4@122
@4@122:
   ;	
   ;	}
   ;	
	leave	
	ret	
_abs	endp
   ;	
   ;	double dply (x)         /* Exercise some doubles */
   ;	
	assume	cs:_TEXT
_dply	proc	near
	enter	8,0
	push	si
   ;	
   ;	double x;
   ;	{
   ;	int i = TINY;
   ;	
	mov	si,100
	jmp	@5@74
@5@50:
   ;	
   ;	double y;
   ;	
   ;	while (i--)
   ;	    {
   ;	    y = x * x * x * x * x * x * x;
   ;	
	FLD	qword ptr [bp+4]
	FMUL	qword ptr [bp+4]
	FMUL	qword ptr [bp+4]
	FMUL	qword ptr [bp+4]
	FMUL	qword ptr [bp+4]
	FMUL	qword ptr [bp+4]
	FMUL	qword ptr [bp+4]
	FSTP	qword ptr [bp-8]
   ;	
   ;	    y = y / x / x / x / x / x / x;
   ;	
	FLD	qword ptr [bp-8]
	FDIV	qword ptr [bp+4]
	FDIV	qword ptr [bp+4]
	FDIV	qword ptr [bp+4]
	FDIV	qword ptr [bp+4]
	FDIV	qword ptr [bp+4]
	FDIV	qword ptr [bp+4]
	FSTP	qword ptr [bp-8]
   ;	
   ;	
   ;	    y = y + x + x + x + x + x + x;
   ;	
	FLD	qword ptr [bp-8]
	FADD	qword ptr [bp+4]
	FADD	qword ptr [bp+4]
	FADD	qword ptr [bp+4]
	FADD	qword ptr [bp+4]
	FADD	qword ptr [bp+4]
	FADD	qword ptr [bp+4]
	FSTP	qword ptr [bp-8]
   ;	
   ;	    y = y - x - x - x - x - x - x;
   ;	
	FLD	qword ptr [bp-8]
	FSUB	qword ptr [bp+4]
	FSUB	qword ptr [bp+4]
	FSUB	qword ptr [bp+4]
	FSUB	qword ptr [bp+4]
	FSUB	qword ptr [bp+4]
	FSUB	qword ptr [bp+4]
	FSTP	qword ptr [bp-8]
	FWAIT	
@5@74:
	mov	ax,si
	dec	si
	or	ax,ax
	je	@@2
	jmp	@5@50
@@2:
   ;	
   ;	    }
   ;	return (y);
   ;	
	FLD	qword ptr [bp-8]
	jmp	short @5@122
@5@122:
   ;	
   ;	}
   ;	
	pop	si
	leave	
	ret	
_dply	endp
   ;	
   ;	unsigned fib (x)        /* Common Fibonacci function */
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
   ;	
   ;	if (x > 2)
   ;	
	cmp	si,2
	jle	short @6@98
   ;	
   ;	    return (fib (x-1) + fib (x-2));
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
	jmp	short @6@122
	jmp	short @6@122
@6@98:
   ;	
   ;	else
   ;	    return (1);
   ;	
	mov	ax,1
	jmp	short @6@122
@6@122:
   ;	
   ;	}
   ;	
	pop	si
	pop	bp
	ret	
_fib	endp
   ;	
   ;	int stest (b1,b2)       /* String test using strcpy() and strcmp() */
   ;	
	assume	cs:_TEXT
_stest	proc	near
	push	bp
	mov	bp,sp
	push	si
	push	di
   ;	
   ;	char *b1, *b2;
   ;	{
   ;	int i,j;
   ;	void mstrcpy ();
   ;	
   ;	for (i = 0, j = 0; i < SMALL; ++i)
   ;	
	xor	di,di
	xor	si,si
	jmp	short @7@98
@7@50:
   ;	
   ;	    {
   ;	    mstrcpy (b1, "0123456789abcdef");
   ;	
	push	offset DGROUP:s@+155
	push	word ptr [bp+4]
	call	near ptr _mstrcpy
	pop	cx
	pop	cx
   ;	
   ;	    mstrcpy (b2, "0123456789abcdee"); /* Note it's a different string. */
   ;	
	push	offset DGROUP:s@+172
	push	word ptr [bp+6]
	call	near ptr _mstrcpy
	pop	cx
	pop	cx
   ;	
   ;	    j += mstrcmp (b1,b2);
   ;	
	push	word ptr [bp+6]
	push	word ptr [bp+4]
	call	near ptr _mstrcmp
	pop	cx
	pop	cx
	add	si,ax
	inc	di
@7@98:
	cmp	di,9000
	jl	short @7@50
   ;	
   ;	    }
   ;	return (j);
   ;	
	mov	ax,si
	jmp	short @7@146
@7@146:
   ;	
   ;	}
   ;	
	pop	di
	pop	si
	pop	bp
	ret	
_stest	endp
   ;	
   ;	int mstrcmp (c,d)       /* External string compare */
   ;	
	assume	cs:_TEXT
_mstrcmp	proc	near
	push	bp
	mov	bp,sp
	push	si
	push	di
	mov	si,word ptr [bp+4]
	mov	di,word ptr [bp+6]
	jmp	short @8@122
@8@50:
   ;	
   ;	char *c, *d;
   ;	{
   ;	
   ;	while (*c == *d)
   ;	    {
   ;	    if (!*c)
   ;	
	mov	al,byte ptr [si]
	cbw	
	or	ax,ax
	jne	short @8@98
   ;	
   ;	        return (0);
   ;	
	xor	ax,ax
	jmp	short @8@170
@8@98:
   ;	
   ;	    ++c;
   ;	
	inc	si
   ;	
   ;	    ++d;
   ;	
	inc	di
@8@122:
	mov	al,byte ptr [si]
	cmp	al,byte ptr [di]
	je	short @8@50
   ;	
   ;	    }
   ;	return (*c - *d);
   ;	
	mov	al,byte ptr [si]
	cbw	
	push	ax
	mov	al,byte ptr [di]
	cbw	
	mov	dx,ax
	pop	ax
	sub	ax,dx
	jmp	short @8@170
@8@170:
   ;	
   ;	}
   ;	
	pop	di
	pop	si
	pop	bp
	ret	
_mstrcmp	endp
   ;	
   ;	void mstrcpy (c,d)      /* External string copy */
   ;	
	assume	cs:_TEXT
_mstrcpy	proc	near
	push	bp
	mov	bp,sp
	jmp	short @9@50
@9@50:
   ;	
   ;	char *c, *d;
   ;	{
   ;	
   ;	while (*c++ = *d++)
   ;	
	mov	bx,word ptr [bp+6]
	inc	word ptr [bp+6]
	mov	al,byte ptr [bx]
	mov	bx,word ptr [bp+4]
	inc	word ptr [bp+4]
	mov	byte ptr [bx],al
	or	al,al
	jne	short @9@50
   ;	
   ;	    ;
   ;	}
   ;	
	pop	bp
	ret	
_mstrcpy	endp
   ;	
   ;	int mcopy ()            /* Disk copy.  Test assumes file doesn't exist */
   ;	
	assume	cs:_TEXT
_mcopy	proc	near
	enter	102,0
	push	si
	push	di
   ;	
   ;	{
   ;	FILE *fp, *fopen ();
   ;	char buf[TINY];
   ;	int i, j;
   ;	
   ;	mstrcpy (buf, "Disk I/O test");
   ;	
	push	offset DGROUP:s@+189
	lea	ax,word ptr [bp-102]
	push	ax
	call	near ptr _mstrcpy
	pop	cx
	pop	cx
   ;	
   ;	if ((fp = fopen(FILENAME,"w")) == NULL)
   ;	
	push	offset DGROUP:s@+212
	push	offset DGROUP:s@+203
	call	near ptr _fopen
	pop	cx
	pop	cx
	mov	di,ax
	or	ax,ax
	jne	short @10@74
   ;	
   ;	    {
   ;	    printf ("Cannot open file");
   ;	
	push	offset DGROUP:s@+214
	call	near ptr _printf
	pop	cx
   ;	
   ;	    exit (ERR);
   ;	
	push	65535
	call	near ptr _exit
	pop	cx
@10@74:
   ;	
   ;	    }
   ;	i = 0;
   ;	
	mov	word ptr [bp-2],0
	jmp	short @10@242
@10@98:
   ;	
   ;	while (++i < LITTLE)
   ;	    for (j = 0; buf[j]; ++j)
   ;	
	xor	si,si
	jmp	short @10@218
@10@122:
   ;	
   ;	        putc (buf[j], fp);
   ;	
	mov	ax,word ptr [di]
	inc	ax
	mov	word ptr [di],ax
	or	ax,ax
	jge	short @10@170
	mov	bx,word ptr [di+10]
	inc	word ptr [di+10]
	mov	al,byte ptr [bp+si-102]
	mov	byte ptr [bx],al
	mov	ah,0
	jmp	short @10@194
@10@170:
	push	di
	mov	al,byte ptr [bp+si-102]
	push	ax
	call	near ptr __fputc
	pop	cx
	pop	cx
@10@194:
	inc	si
@10@218:
	cmp	byte ptr [bp+si-102],0
	jne	short @10@122
@10@242:
	inc	word ptr [bp-2]
	mov	ax,word ptr [bp-2]
	cmp	ax,1000
	jl	short @10@98
   ;	
   ;	fclose (fp);
   ;	
	push	di
	call	near ptr _fclose
	pop	cx
   ;	
   ;	return (i);
   ;	
	mov	ax,word ptr [bp-2]
	jmp	short @10@290
@10@290:
   ;	
   ;	}
   ;	
	pop	di
	pop	si
	leave	
	ret	
_mcopy	endp
   ;	
   ;	int intest ()           /* Square an integer by iteration */
   ;	
	assume	cs:_TEXT
_intest	proc	near
	push	bp
	mov	bp,sp
	push	si
	push	di
   ;	
   ;	{
   ;	int i, j, k, sum;
   ;	
   ;	for (i = 0; i < LITTLE; ++i)
   ;	
	xor	bx,bx
	jmp	short @11@170
@11@50:
   ;	
   ;	    {
   ;	    sum = 0;
   ;	
	xor	si,si
   ;	
   ;	    for (j = 0, k = 1; j < MAXINT; ++j)
   ;	
	xor	dx,dx
	mov	di,1
	jmp	short @11@122
@11@74:
   ;	
   ;	        {
   ;	        sum += k;
   ;	
	add	si,di
   ;	
   ;	        k += 2;
   ;	
	inc	di
	inc	di
	inc	dx
@11@122:
	cmp	dx,179
	jl	short @11@74
	inc	bx
@11@170:
	cmp	bx,1000
	jl	short @11@50
   ;	
   ;	        }
   ;	    }
   ;	return (sum);
   ;	
	mov	ax,si
	jmp	short @11@218
@11@218:
   ;	
   ;	}
   ;	
	pop	di
	pop	si
	pop	bp
	ret	
_intest	endp
_TEXT	ends
_BSS	segment word public 'BSS'
_results	label	word
	db	20 dup (?)
	?debug	C E9
_BSS	ends
_DATA	segment word public 'DATA'
s@	label	byte
	db	'Start...%c'
	db	10
	db	10
	db	0
	db	10
	db	'cresult = %d'
	db	10
	db	0
	db	10
	db	'iresult = %d'
	db	10
	db	0
	db	10
	db	'uresult = %u'
	db	10
	db	0
	db	10
	db	'lresult = %ld'
	db	0
	db	10
	db	' square = %ld'
	db	10
	db	0
	db	10
	db	'dresult = %f'
	db	10
	db	0
	db	'  dmath = %f'
	db	10
	db	0
	db	8
	db	'   copy = %d'
	db	0
	db	10
	db	10
	db	'...End%c'
	db	0
	db	0
	db	0
	db	0
	db	'@'
	db	-115
	db	-19
	db	-75
	db	-96
	db	-9
	db	-58
	db	-80
	db	'>0123456789abcdef'
	db	0
	db	'0123456789abcdee'
	db	0
	db	'Disk I/O test'
	db	0
	db	'zyxw.vut'
	db	0
	db	'w'
	db	0
	db	'Cannot open file'
	db	0
_DATA	ends
_TEXT	segment byte public 'CODE'
_TEXT	ends
	extrn	_fopen:near
	extrn	_printf:near
	public	_intest
	extrn	__fputc:near
	public	_sroot
	public	_results
	public	_abs
	public	_main
	public	_sq
	public	_fib
	public	_stest
	public	_dply
	extrn	_exit:near
	public	_mstrcpy
	public	_mstrcmp
	extrn	_fclose:near
	public	_mcopy
	end
