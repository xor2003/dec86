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
	?debug	S "strlen.c"
	?debug	C E924AD0459087374726C656E2E63
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
	push	bp
	mov	bp,sp
	push	si
   ;	
   ;	{ char *s = "test";
   ;	
	mov	si,offset DGROUP:s@
   ;	
   ;	
   ;		strlen(s);
   ;	
	push	si
	call	near ptr _strlen
	pop	cx
   ;	
   ;	}
   ;	
	pop	si
	pop	bp
	ret	
_main	endp
   ;	
   ;	strlen(char *s)
   ;	
	assume	cs:_TEXT
_strlen	proc	near
	push	bp
	mov	bp,sp
	push	si
   ;	
   ;	{ int n = 0;
   ;	
	xor	si,si
	jmp	short @2@74
@2@50:
   ;	
   ;	
   ;		while (*s++)
   ;		  n++;
   ;	
	inc	si
@2@74:
	mov	bx,word ptr [bp+4]
	inc	word ptr [bp+4]
	cmp	byte ptr [bx],0
	jne	short @2@50
   ;	
   ;		return (n);
   ;	
	mov	ax,si
	jmp	short @2@122
@2@122:
   ;	
   ;	}
   ;	
	pop	si
	pop	bp
	ret	
_strlen	endp
	?debug	C E9
_TEXT	ends
_DATA	segment word public 'DATA'
s@	label	byte
	db	'test'
	db	0
_DATA	ends
_TEXT	segment byte public 'CODE'
_TEXT	ends
	public	_main
	public	_strlen
	end
