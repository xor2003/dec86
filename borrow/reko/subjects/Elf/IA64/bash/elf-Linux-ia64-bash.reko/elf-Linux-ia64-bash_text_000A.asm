;;; Segment .text (400000000001C480)

l40000000000BC480:
	{ adds	r14,0x10,r14; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p07,p06,r14,r16; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000BC4F0; }

l40000000000BC4A0:
	{ nop.m	0x0; ld8	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r33,r15; (p06) br.cond.dptk.few	40000000000BC480 }

l40000000000BC4C0:
	{ nop.m	0x0; adds	r15,0x8,r14; nop.i	0x0 }
	{ st8	[r32],r18; st8	[r14],r17; nop.i	0x0; }
	{ ld8	r8,[r15]; nop.i	0x0; br.ret	b0; }

l40000000000BC4F0:
	{ nop.m	0x0; adds	r8,0x0,r0; nop.i	0x0 }
	{ st8	[r0],r18; st8	[r0],r17; br.ret	b0; }

l40000000000BC510:
	{ nop.m	0x0; adds	r8,0x0,r0; br.ret	b0 }

l40000000000BC520:
	{ ld8	r15,[r14]; cmp.lt	p06,p07,r33,r15; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r15,0x18,r32; nop.i	0x0; }

l40000000000BC53C:
	{ Invalid; Invalid; mov	pr,r32,0x0 }

l40000000000BC546:
	{ chk.a.nc	f0,3FFFFFFFFF0BCD46; nop; (p32) nop }

l40000000000BC550:
	{ adds	r14,0x18,r32; ld8	r16,[r14]; nop.i	0x0; }
	{ nop.m	0x0; adds	r14,0x10,r16; nop.i	0x0; }
	{ ld8	r14,[r14]; nop.i	0x0; br.cond.sptk.few	40000000000BC450; }

;; array_to_word_list: 40000000000BC580
;;   Called from:
;;     40000000000C190C (in fn40000000000C14C0)
array_to_word_list proc
	{ alloc	r37,ar.pfs,0x9,0x0,0x7; adds	r14,0x10,r32; mov	r36,b4 }
	{ cmp.eq	p07,p06,0x0,r32; adds	r35,0x18,r32; (p07) br.cond.dpnt.few	40000000000BC6E0; }

l40000000000BC5A0:
	{ ld4	r14,[r14]; adds	r38,0x0,r1; adds	r34,0x0,r0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BC6E0; }

l40000000000BC5C0:
	{ ld8	r14,[r35]; adds	r15,0x10,r14; nop.i	0x0; }
	{ nop.m	0x0; ld8	r33,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,r33,r14; (p06) br.cond.dpnt.few	40000000000BC6E0; }

l40000000000BC5F0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000BC600:
	{ adds	r14,0x8,r33; nop.m	0x0; adds	r33,0x10,r33; }
	{ ld8	r39,[r14]; nop.i	0x0; br.call.sptk.many	b0,make_bare_word; }
	{ adds	r1,0x0,r38; nop.m	0x0; adds	r40,0x0,r34 }
	{ adds	r39,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,make_word_list; }
	{ ld8	r14,[r35]; nop.m	0x0; adds	r1,0x0,r38 }
	{ adds	r34,0x0,r8; ld8	r33,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r33,r14; (p06) br.cond.dptk.few	40000000000BC600; }

l40000000000BC670:
	{ cmp.eq	p06,p07,0x0,r8; adds	r39,0x0,r8; (p06) br.cond.dpnt.few	40000000000BC6E0; }

l40000000000BC680:
	{ nop.m	0x0; ld8	r14,[r8]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BC6C0; }

l40000000000BC6A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,list_reverse; }
	{ nop.m	0x0; adds	r1,0x0,r38; adds	r34,0x0,r8; }

l40000000000BC6C0:
	{ adds	r8,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000BC6D0; br.ret	b0 }

l40000000000BC6E0:
	{ adds	r34,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ adds	r8,0x0,r34; mov.spnt	b0,r36,40000000000BC6F0; br.ret	b0; }

;; array_keys_to_word_list: 40000000000BC700
;;   Called from:
;;     40000000000C208C (in array_keys)
array_keys_to_word_list proc
	{ alloc	r38,ar.pfs,0xA,0x0,0x8; adds	r14,0x10,r32; mov	r37,b5 }
	{ cmp.eq	p07,p06,0x0,r32; adds	r36,0x18,r32; (p07) br.cond.dpnt.few	40000000000BC890; }

l40000000000BC720:
	{ ld4	r14,[r14]; adds	r39,0x0,r1; adds	r35,0x0,r0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BC890; }

l40000000000BC740:
	{ ld8	r14,[r36]; adds	r15,0x10,r14; nop.i	0x0; }
	{ nop.m	0x0; ld8	r33,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,r33,r14; (p06) br.cond.dpnt.few	40000000000BC890; }

l40000000000BC770:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000BC780:
	{ ld8	r40,[r33],16; nop.i	0x0; br.call.sptk.many	b0,itos; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r34,0x0,r8 }
	{ adds	r40,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,make_bare_word; }
	{ adds	r41,0x0,r35; nop.m	0x0; adds	r1,0x0,r39 }
	{ adds	r40,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,make_word_list; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r40,0x0,r34; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; ld8	r14,[r36]; adds	r1,0x0,r39 }
	{ nop.m	0x0; ld8	r33,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r33,r14; (p06) br.cond.dptk.few	40000000000BC780; }

l40000000000BC820:
	{ cmp.eq	p06,p07,0x0,r35; adds	r40,0x0,r35; (p06) br.cond.dpnt.few	40000000000BC890; }

l40000000000BC830:
	{ nop.m	0x0; ld8	r14,[r35]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BC870; }

l40000000000BC850:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,list_reverse; }
	{ nop.m	0x0; adds	r1,0x0,r39; adds	r35,0x0,r8; }

l40000000000BC870:
	{ adds	r8,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000BC880; br.ret	b0 }

l40000000000BC890:
	{ adds	r35,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ adds	r8,0x0,r35; mov.spnt	b0,r37,40000000000BC8A0; br.ret	b0; }
40000000000BC8B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; array_assign_list: 40000000000BC8C0
;;   Called from:
;;     40000000000BC9D0 (in array_from_word_list)
array_assign_list proc
	{ alloc	r37,ar.pfs,0xA,0x0,0x7; adds	r38,0x0,r1; nop.b	0x0 }
	{ adds	r34,0x0,r33; mov	r36,b4; cmp.eq	p07,p06,0x0,r33; }
	{ nop.m	0x0; adds	r35,0x0,r0; (p07) br.cond.dpnt.few	40000000000BC950; }

l40000000000BC8F0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000BC900:
	{ adds	r14,0x8,r34; adds	r40,0x0,r35; adds	r39,0x0,r32 }
	{ adds	r35,0x1,r35; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r41,[r14]; nop.i	0x0; br.call.sptk.many	b0,array_insert; }
	{ ld8	r34,[r34]; nop.m	0x0; adds	r1,0x0,r38; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	40000000000BC900 }

l40000000000BC950:
	{ adds	r8,0x0,r32; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000BC960; br.ret	b0; }
40000000000BC970 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; array_from_word_list: 40000000000BC980
array_from_word_list proc
	{ alloc	r35,ar.pfs,0x5,0x0,0x5; mov	r34,b2; cmp.eq	p06,p07,0x0,r32 }
	{ adds	r36,0x0,r1; adds	r33,0x0,r32; (p06) br.cond.dpnt.few	40000000000BC9E0; }

l40000000000BC9A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,array_create; }
	{ adds	r1,0x0,r36; adds	r32,0x0,r8; mov.spnt	b0,r34,40000000000BC9B0; }
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	array_assign_list }

l40000000000BC9E0:
	{ adds	r8,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000BC9F0; br.ret	b0; }

;; array_to_argv: 40000000000BCA00
;;   Called from:
;;     40000000000E6C9C (in gen_compspec_completions)
array_to_argv proc
	{ alloc	r40,ar.pfs,0xC,0x0,0xA; adds	r14,0x10,r32; mov	r39,b7 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r41,0x0,r1; (p06) br.cond.dpnt.few	40000000000BCB80; }

l40000000000BCA20:
	{ ld4	r14,[r14]; adds	r37,0x18,r32; adds	r35,0x0,r0; }
	{ cmp4.eq	p06,p07,0x0,r14; adds	r42,0x1,r14; (p06) br.cond.dpnt.few	40000000000BCB80; }

l40000000000BCA40:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strvec_create; }
	{ ld8	r14,[r37]; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r1,0x0,r41; adds	r38,0x0,r8; adds	r15,0x10,r14; }
	{ ld8	r33,[r15]; cmp.eq	p06,p07,r33,r14; nop.i	0x0; }
	{ nop.m	0x0; (p06) adds	r35,0x0,r0; (p06) br.cond.dpnt.few	40000000000BCB60; }

l40000000000BCA8C:
	{ (p07) nop; break.i	0x1000; break.i	0x1000 }

l40000000000BCA90:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000BCAA0:
	{ nop.m	0x0; adds	r14,0x8,r33; nop.i	0x0; }
	{ ld8	r34,[r14]; cmp.eq	p06,p07,0x0,r34; adds	r42,0x0,r34; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BCB20; }

l40000000000BCAC6:
	{ chk.a.nc	r0,3FFFFFFFFF0BD2C6; nop; break.i	0x80000 }

l40000000000BCAD0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r41; adds	r42,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r42,0x0,r8 }
	{ adds	r43,0x0,r34; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r41; nop.m	0x0; nop.i	0x0 }

l40000000000BCB20:
	{ st8	[r36],r8,8; adds	r33,0x10,r33; adds	r35,0x1,r35; }
	{ ld8	r33,[r33]; ld8	r14,[r37]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r33,r14; (p06) br.cond.dptk.few	40000000000BCAA0 }

l40000000000BCB50:
	{ nop.m	0x0; sxt4	r35,r35; shladd	r35,r35,0x3,r0; }

l40000000000BCB60:
	{ add	r35,r38,r35; adds	r8,0x0,r38; mov.i	ar.pfs,r40; }
	{ st8	[r0],r35; mov.spnt	b0,r39,40000000000BCB70; br.ret	b0 }

l40000000000BCB80:
	{ adds	r38,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r40; }
	{ adds	r8,0x0,r38; mov.spnt	b0,r39,40000000000BCB90; br.ret	b0; }
40000000000BCBA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000BCBB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; array_to_assign: 40000000000BCBC0
;;   Called from:
;;     40000000000BFAEC (in print_array_assignment)
array_to_assign proc
	{ alloc	r47,ar.pfs,0x15,0x0,0x12; adds	r12,0xFFFFFFFFFFFFFFE0,r12; mov	r49,pr }
	{ adds	r14,0x10,r32; cmp.eq	p06,p07,0x0,r32; adds	r48,0x0,r1; }
	{ addl	r50,128,r0; adds	r40,0x18,r32; mov	r46,b6 }
	{ addl	r35,1,r0; addl	r34,128,r0; (p06) br.cond.dpnt.few	40000000000BD350; }

l40000000000BCC00:
	{ nop.m	0x0; ld4	r14,[r14]; addl	r42,91,r0 }
	{ addl	r43,93,r0; addl	r44,61,r0; addl	r45,32,r0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BD350; }

l40000000000BCC30:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ addl	r14,40,r0; adds	r1,0x0,r48; adds	r36,0x0,r8; }
	{ st1	[r14],r8; ld8	r14,[r40]; nop.i	0x0; }
	{ adds	r15,0x10,r14; ld8	r39,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,r39,r14; (p06) br.cond.dpnt.few	40000000000BD380; }

l40000000000BCC80:
	{ adds	r37,0x0,r39; adds	r51,0x10,r12; addl	r52,22,r0; }
	{ ld8	r50,[r37],8; nop.i	0x0; br.call.sptk.many	b0,inttostr; }
	{ ld8	r50,[r37]; adds	r1,0x0,r48; adds	r38,0x0,r8; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r50; nop.i	0x0; }
	{ (p06) adds	r37,0x0,r0; (p06) br.cond.dpnt.few	40000000000BCCE0; br.call.sptk.many	b0,sh_double_quote; }

l40000000000BCCC6:
	{ Invalid; (p32) nop; break.i	0x80000; }

l40000000000BCCCC:
	{ (p08) nop; nop; nop }
	{ cmpxchg4.acq	r8,[r66],r0; break.x	0x1C89A600501000 }

l40000000000BCCE0:
	{ cmp.eq	p18,p19,0x0,r38; nop.i	0x0; (p18) br.cond.dpnt.few	40000000000BD2D0; }

l40000000000BCCF0:
	{ ld1	r14,[r38]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000BD2D0 }

l40000000000BCD10:
	{ adds	r14,0x1,r38; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r41,9,r0; (p06) br.cond.dptk.few	40000000000BCDA0 }

l40000000000BCD3C:
	{ (p03) cmp.lt	p00,p11,r0,r33; (p33) cmp.lt.unc	p00,p16,r9,r64; (p01) rfi }

l40000000000BCD40:
	{ adds	r14,0x2,r38; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r41,10,r0; (p06) br.cond.dptk.few	40000000000BCDA0 }

l40000000000BCD6C:
	{ (p02) cmpxchg4.acq	r0,[r33],r0; zxt1	r64,r64; break.i	0x1000 }

l40000000000BCD70:
	{ adds	r50,0x0,r38; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; adds	r1,0x0,r48; adds	r41,0x8,r8; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000BCDA0:
	{ cmp.eq	p16,p17,0x0,r37; nop.i	0x0; (p16) br.cond.dpnt.few	40000000000BD290; }

l40000000000BCDB0:
	{ ld1	r14,[r37]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000BD290 }

l40000000000BCDD0:
	{ adds	r14,0x1,r37; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r8,1,r0; (p06) br.cond.dptk.few	40000000000BCE50 }

l40000000000BCDFC:
	{ (p03) cmp.lt	p00,p11,r0,r33; (p33) cmp.lt	p32,p16,r9,r64; Invalid }

l40000000000BCE00:
	{ adds	r14,0x2,r37; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r8,2,r0; (p06) br.cond.dptk.few	40000000000BCE50 }

l40000000000BCE2C:
	{ Invalid; dep	r0,r32,r0,63,1; (p06) epc }

l40000000000BCE30:
	{ nop.m	0x0; adds	r50,0x0,r37; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r48; nop.m	0x0; nop.i	0x0 }

l40000000000BCE50:
	{ add	r14,r41,r8,0x1; add	r14,r14,r35; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r14,r34; (p07) br.cond.dptk.few	40000000000BD1E0 }

l40000000000BCE70:
	{ nop.m	0x0; sxt4	r14,r35; adds	r35,0x1,r35 }
	{ nop.m	0x0; adds	r51,0x0,r38; nop.b	0x0; }
	{ add	r14,r36,r14; sxt4	r50,r35; add	r50,r36,r50 }
	{ st1	[r42],r14; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; adds	r1,0x0,r48; (p18) br.cond.dpnt.few	40000000000BD280 }

l40000000000BCEC0:
	{ ld1	r14,[r38]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000BD280 }

l40000000000BCEE0:
	{ adds	r14,0x1,r38; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r8,1,r0; (p06) br.cond.dptk.few	40000000000BCF60 }

l40000000000BCF0C:
	{ (p03) cmp.lt	p00,p11,r0,r33; (p33) cmp.lt.unc	p00,p16,r9,r64; Invalid }

l40000000000BCF10:
	{ adds	r14,0x2,r38; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r8,2,r0; (p06) br.cond.dptk.few	40000000000BCF60 }

l40000000000BCF3C:
	{ Invalid; dep	r0,r32,r0,63,1; (p06) epc }

l40000000000BCF40:
	{ nop.m	0x0; adds	r50,0x0,r38; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r48; nop.m	0x0; nop.i	0x0; }

l40000000000BCF60:
	{ nop.m	0x0; add	r35,r8,r35; nop.i	0x0; }
	{ adds	r14,0x1,r35; sxt4	r15,r35; adds	r35,0x2,r35; }
	{ nop.m	0x0; sxt4	r14,r14; add	r15,r36,r15; }
	{ add	r14,r36,r14; st1	[r43],r15; nop.i	0x0; }
	{ st1	[r44],r14; nop.i	0x0; (p16) br.cond.dpnt.few	40000000000BD090; }

l40000000000BCFB0:
	{ nop.m	0x0; sxt4	r50,r35; adds	r51,0x0,r37; }
	{ add	r50,r36,r50; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ ld1	r14,[r37]; nop.m	0x0; adds	r1,0x0,r48; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) adds	r8,0x0,r0; (p06) br.cond.dptk.few	40000000000BD080 }

l40000000000BCFFC:
	{ (p04) cmp.lt	p00,p11,r0,r33; (p17) cmp.lt	p32,p16,r9,r64; (p01) rfi }

l40000000000BD000:
	{ adds	r14,0x1,r37; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r8,1,r0; (p06) br.cond.dptk.few	40000000000BD080 }

l40000000000BD02C:
	{ (p03) cmp.lt	p00,p11,r0,r33; (p33) cmp.lt	p32,p16,r9,r64; Invalid }

l40000000000BD030:
	{ adds	r14,0x2,r37; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r8,2,r0; (p06) br.cond.dptk.few	40000000000BD080 }

l40000000000BD05C:
	{ Invalid; dep	r0,r32,r0,63,1; (p06) epc }

l40000000000BD060:
	{ nop.m	0x0; adds	r50,0x0,r37; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r48; nop.m	0x0; nop.i	0x0; }

l40000000000BD080:
	{ add	r35,r8,r35; nop.m	0x0; nop.i	0x0 }

l40000000000BD090:
	{ adds	r39,0x10,r39; ld8	r14,[r40]; (p17) adds	r50,0x0,r37; }

l40000000000BD0A0:
	{ ld8	r15,[r39]; cmp.eq	p06,p07,r14,r15; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r14,r35; (p07) adds	r35,0x1,r35; }

l40000000000BD0C0:
	{ nop.m	0x0; (p07) add	r14,r36,r14; nop.i	0x0; }

l40000000000BD0CC:
	{ Invalid; Invalid; Invalid }

l40000000000BD0D6:
	{ nop; (p32) nop; break.i	0x80000 }

l40000000000BD0E0:
	{ nop.m	0x0; ld8	r14,[r40]; (p17) adds	r1,0x0,r48 }

l40000000000BD0F0:
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r39,r14; (p06) br.cond.dptk.few	40000000000BCC80 }

l40000000000BD110:
	{ adds	r37,0x1,r35; adds	r15,0x8,r34; sxt4	r14,r35 }
	{ nop.m	0x0; adds	r50,0x0,r36; nop.i	0x0; }
	{ sub	r16,r37,r34; cmp4.lt	p07,p06,r37,r34; (p07) br.cond.dpnt.few	40000000000BD170; }

l40000000000BD140:
	{ nop.m	0x0; extr	r16,r16,3,29; shladd	r51,r16,0x3,r15; }
	{ nop.m	0x0; sxt4	r51,r51; br.call.sptk.many	b0,xrealloc; }
	{ adds	r1,0x0,r48; adds	r36,0x0,r8; sxt4	r14,r35; }

l40000000000BD170:
	{ nop.m	0x0; sxt4	r37,r37; nop.b	0x0 }
	{ add	r14,r36,r14; addl	r15,41,r0; cmp4.eq	p06,p07,0x0,r33; }
	{ add	r37,r36,r37; st1	[r15],r14; nop.i	0x0; }
	{ st1	[r0],r37; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000BD2E0 }

l40000000000BD1B0:
	{ adds	r8,0x0,r36; mov	pr,r49,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r47; }
	{ nop.m	0x0; mov.spnt	b0,r46,40000000000BD1C0; nop.i	0x0 }
	{ adds	r12,0x20,r12; nop.m	0x0; br.ret	b0 }

l40000000000BD1E0:
	{ nop.m	0x0; shladd	r34,r34,0x1,r0; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r14,r34; (p06) br.cond.dptk.few	40000000000BD1E0 }

l40000000000BD200:
	{ adds	r50,0x0,r36; sxt4	r51,r34; br.call.sptk.many	b0,xrealloc; }
	{ nop.m	0x0; sxt4	r14,r35; nop.b	0x0 }
	{ adds	r36,0x0,r8; adds	r35,0x1,r35; adds	r1,0x0,r48; }
	{ add	r14,r36,r14; sxt4	r50,r35; adds	r51,0x0,r38; }
	{ nop.m	0x0; add	r50,r36,r50; nop.i	0x0 }
	{ st1	[r42],r14; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; adds	r1,0x0,r48; (p19) br.cond.dptk.few	40000000000BCEC0; }

l40000000000BD270:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000BD280:
	{ nop.m	0x0; adds	r8,0x0,r0; br.cond.sptk.few	40000000000BCF60; }

l40000000000BD290:
	{ adds	r8,0x0,r0; add	r14,r41,r8,0x1; nop.i	0x0; }
	{ nop.m	0x0; add	r14,r14,r35; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r14,r34; (p06) br.cond.dptk.few	40000000000BCE70 }

l40000000000BD2C0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000BD1E0 }

l40000000000BD2D0:
	{ nop.m	0x0; addl	r41,8,r0; br.cond.sptk.few	40000000000BCDA0 }

l40000000000BD2E0:
	{ adds	r50,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,sh_single_quote; }
	{ adds	r34,0x0,r8; nop.m	0x0; adds	r1,0x0,r48 }
	{ adds	r50,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r36,0x0,r34; nop.m	0x0; adds	r1,0x0,r48; }
	{ adds	r8,0x0,r36; mov	pr,r49,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r47; }
	{ nop.m	0x0; mov.spnt	b0,r46,40000000000BD330; nop.i	0x0 }
	{ adds	r12,0x20,r12; nop.m	0x0; br.ret	b0 }

l40000000000BD350:
	{ adds	r36,0x0,r0; adds	r8,0x0,r36; mov	pr,r49,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r47; mov.spnt	b0,r46,40000000000BD360 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0 }

l40000000000BD380:
	{ addl	r37,2,r0; nop.m	0x0; addl	r14,1,r0 }
	{ addl	r15,41,r0; nop.m	0x0; cmp4.eq	p06,p07,0x0,r33; }
	{ add	r14,r36,r14; add	r37,r36,r37; nop.i	0x0 }
	{ st1	[r15],r14; st1	[r0],r37; (p06) br.cond.dptk.few	40000000000BD1B0 }

l40000000000BD3C0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000BD2E0; }
40000000000BD3D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000BD3E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000BD3F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; array_to_string: 40000000000BD400
;;   Called from:
;;     40000000000BD9DC (in array_modcase)
;;     40000000000BDA9C (in array_modcase)
;;     40000000000BDB3C (in array_modcase)
;;     40000000000BDE2C (in array_patsub)
;;     40000000000BDEEC (in array_patsub)
;;     40000000000BDF8C (in array_patsub)
;;     40000000000BE26C (in array_subrange)
;;     40000000000BE38C (in array_subrange)
;;     40000000000BE3FC (in array_subrange)
array_to_string proc
	{ alloc	r45,ar.pfs,0x12,0x0,0x10; adds	r14,0x10,r32; mov	r47,pr }
	{ adds	r15,0x18,r32; cmp.eq	p06,p07,0x0,r32; adds	r46,0x0,r1; }
	{ adds	r48,0x0,r33; adds	r39,0x0,r0; mov	r44,b4 }
	{ adds	r36,0x0,r0; adds	r35,0x0,r0; (p06) br.cond.dpnt.few	40000000000BD730; }

l40000000000BD440:
	{ ld4	r14,[r14]; nop.m	0x0; cmp4.eq	p16,p17,0x0,r34; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000BD6E0; }

l40000000000BD460:
	{ ld8	r41,[r15]; adds	r14,0x10,r41; nop.i	0x0; }
	{ nop.m	0x0; ld8	r38,[r14]; nop.i	0x0; }
	{ cmp.eq	p07,p06,r38,r41; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000BD730; }

l40000000000BD490:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ cmp4.eq	p07,p06,0x0,r34; adds	r1,0x0,r46; adds	r42,0x0,r8; }
	{ (p06) addl	r43,1,r0; nop.i	0x0; (p07) adds	r43,0x0,r0; }

l40000000000BD4B6:
	{ addp4	r0,0xFFFFFFFFFFFFE000,r1; (p21) nop; break.i	0x80000 }

l40000000000BD4C0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r35; (p07) br.cond.dpnt.few	40000000000BD6A0 }

l40000000000BD4D0:
	{ adds	r14,0x8,r38; ld8	r37,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r37; nop.i	0x0; }
	{ (p06) adds	r38,0x10,r38; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BD640; }

l40000000000BD4F6:
	{ chk.a.nc	r0,3FFFFFFFFF0BDCF6; nop; (p04) nop }

l40000000000BD500:
	{ (p17) adds	r48,0x0,r37; nop.i	0x0; (p17) br.call.dpnt.many	b0,quote_string; }

l40000000000BD506:
	{ nop; (p32) extr.u	r116,r127,19,46; (p20) nop }

l40000000000BD510:
	{ (p17) adds	r37,0x0,r8; nop.m	0x0; (p17) adds	r1,0x0,r46; }

l40000000000BD516:
	{ nop; nop; nop }

l40000000000BD520:
	{ adds	r48,0x0,r37; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ add	r14,r42,r8; adds	r1,0x0,r46; adds	r40,0x0,r8; }
	{ adds	r14,0x2,r14; add	r14,r14,r36; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r14,r35; (p06) br.cond.dptk.few	40000000000BD5A0; }

l40000000000BD560:
	{ nop.m	0x0; shladd	r35,r35,0x1,r0; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r14,r35; (p06) br.cond.dptk.few	40000000000BD560 }

l40000000000BD580:
	{ adds	r48,0x0,r39; sxt4	r49,r35; br.call.sptk.many	b0,xrealloc; }
	{ nop.m	0x0; adds	r1,0x0,r46; adds	r39,0x0,r8 }

l40000000000BD5A0:
	{ nop.m	0x0; sxt4	r48,r36; nop.b	0x0 }
	{ adds	r49,0x0,r37; adds	r38,0x10,r38; add	r36,r36,r40; }
	{ add	r48,r39,r48; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ cmp.eq	p07,p06,0x0,r37; adds	r1,0x0,r46; (p06) addl	r14,1,r0; }

l40000000000BD5E0:
	{ (p07) adds	r14,0x0,r0; and	r14,r43,r14; nop.i	0x0; }

l40000000000BD5E6:
	{ Invalid; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	f0,3FFFFFFFFFD80ED6; mov	pr,0x430000D; (p32) nop }

l40000000000BD600:
	{ ld8	r14,[r38]; sxt4	r48,r36; adds	r49,0x0,r33; }
	{ cmp.eq	p06,p07,r14,r41; add	r48,r39,r48; (p06) br.cond.dpnt.few	40000000000BD660; }

l40000000000BD620:
	{ nop.m	0x0; add	r36,r36,r42; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r46; nop.m	0x0; nop.i	0x0 }

l40000000000BD640:
	{ nop.m	0x0; ld8	r38,[r38]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r38,r41; (p06) br.cond.sptk.few	40000000000BD4C0; }

l40000000000BD660:
	{ cmp.eq	p06,p07,0x0,r39; adds	r8,0x0,r39; mov.i	ar.pfs,r45 }
	{ nop.m	0x0; sxt4	r36,r36; (p06) br.cond.dpnt.few	40000000000BD730; }

l40000000000BD680:
	{ add	r36,r39,r36; nop.m	0x0; mov	pr,r47,0xFFFFFFFFFFFFFFFE; }
	{ st1	[r0],r36; mov.spnt	b0,r44,40000000000BD690; br.ret	b0; }

l40000000000BD6A0:
	{ addl	r48,64,r0; addl	r35,64,r0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r46; adds	r39,0x0,r8; br.cond.sptk.few	40000000000BD4D0 }

l40000000000BD6C0:
	{ adds	r48,0x0,r37; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r46; br.cond.sptk.few	40000000000BD600 }

l40000000000BD6E0:
	{ addl	r48,1,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r39,0x0,r8; st1	[r0],r8; nop.b	0x0 }
	{ adds	r1,0x0,r46; nop.m	0x0; mov	pr,r47,0xFFFFFFFFFFFFFFFE; }
	{ adds	r8,0x0,r39; nop.m	0x0; mov.i	ar.pfs,r45; }
	{ nop.m	0x0; mov.spnt	b0,r44,40000000000BD720; br.ret	b0 }

l40000000000BD730:
	{ adds	r39,0x0,r0; nop.m	0x0; mov	pr,r47,0xFFFFFFFFFFFFFFFE; }
	{ adds	r8,0x0,r39; nop.m	0x0; mov.i	ar.pfs,r45; }
	{ nop.m	0x0; mov.spnt	b0,r44,40000000000BD750; br.ret	b0; }
40000000000BD760 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000BD770 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; array_modcase: 40000000000BD780
array_modcase proc
	{ alloc	r42,ar.pfs,0xF,0x0,0xC; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ adds	r14,0x18,r32; mov	r41,b1; adds	r15,0x10,r32; }
	{ cmp.eq	p06,p07,0x0,r32; nop.m	0x0; adds	r43,0x0,r1 }
	{ adds	r44,0x0,r32; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000BDAD0; }

l40000000000BD7C0:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BDAD0; }

l40000000000BD7E0:
	{ nop.m	0x0; ld4	r14,[r15]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BDAD0; }

l40000000000BD800:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,array_copy; }
	{ adds	r39,0x18,r8; adds	r1,0x0,r43; adds	r40,0x0,r8; }
	{ ld8	r14,[r39]; adds	r15,0x10,r14; nop.i	0x0; }
	{ nop.m	0x0; ld8	r36,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r36,r14; (p07) br.cond.dpnt.few	40000000000BD8F0; }

l40000000000BD850:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000BD860:
	{ adds	r37,0x8,r36; adds	r45,0x0,r33; adds	r46,0x0,r34; }
	{ ld8	r44,[r37]; nop.i	0x0; br.call.sptk.many	b0,sh_modcase; }
	{ ld8	r44,[r37]; adds	r1,0x0,r43; adds	r38,0x0,r8; }
	{ cmp.eq	p06,p07,0x0,r44; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BD8C0; }

l40000000000BD8A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r43; nop.m	0x0; nop.i	0x0 }

l40000000000BD8C0:
	{ adds	r36,0x10,r36; ld8	r14,[r39]; nop.i	0x0 }
	{ st8	[r38],r37; ld8	r36,[r36]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r36,r14; (p06) br.cond.dptk.few	40000000000BD860; }

l40000000000BD8F0:
	{ nop.m	0x0; tbit.z	p07,p06,r35,0x5; (p07) br.cond.dptk.few	40000000000BDA50 }

l40000000000BD900:
	{ adds	r44,0x0,r40; nop.i	0x0; br.call.sptk.many	b0,array_quote; }
	{ nop.m	0x0; tbit.z	p06,p07,r35,0x6; nop.i	0x0 }
	{ adds	r1,0x0,r43; adds	r44,0x10,r12; (p07) br.cond.dpnt.few	40000000000BDB00; }

l40000000000BD930:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,ifs_firstchar; }
	{ adds	r1,0x0,r43; adds	r37,0x0,r8; br.call.sptk.many	b0,getifs; }
	{ adds	r1,0x0,r43; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	40000000000BD980; }

l40000000000BD960:
	{ ld1	r14,[r8]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000BD9C0 }

l40000000000BD980:
	{ adds	r15,0x10,r12; ld4	r14,[r15]; addl	r15,32,r0; }
	{ cmp4.lt	p06,p07,0x1,r14; adds	r14,0x0,r37; (p07) br.cond.dpnt.few	40000000000BDB70; }

l40000000000BD9A0:
	{ nop.m	0x0; st1	[r14],r1,1; nop.i	0x0; }
	{ st1	[r0],r14; nop.m	0x0; nop.i	0x0 }

l40000000000BD9C0:
	{ adds	r45,0x0,r37; nop.m	0x0; adds	r46,0x0,r0 }
	{ adds	r44,0x0,r40; nop.m	0x0; br.call.sptk.many	b0,array_to_string; }
	{ adds	r1,0x0,r43; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r44,0x0,r37; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r43; nop.m	0x0; nop.i	0x0 }

l40000000000BDA10:
	{ nop.m	0x0; adds	r44,0x0,r40; br.call.sptk.many	b0,array_dispose; }
	{ adds	r1,0x0,r43; nop.m	0x0; nop.i	0x0 }

l40000000000BDA30:
	{ adds	r8,0x0,r36; mov.i	ar.pfs,r42; mov.spnt	b0,r41,40000000000BDA30 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000000BDA50:
	{ adds	r44,0x0,r40; nop.i	0x0; br.call.sptk.many	b0,array_quote_escapes; }
	{ nop.m	0x0; adds	r1,0x0,r43; tbit.z	p07,p06,r35,0x6 }
	{ adds	r44,0x0,r40; adds	r46,0x0,r0; (p06) br.cond.dpnt.few	40000000000BDB00; }

l40000000000BDA80:
	{ nop.m	0x0; addl	r45,-9444,r1; nop.i	0x0; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,array_to_string; }
	{ adds	r1,0x0,r43; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r44,0x0,r40; nop.m	0x0; br.call.sptk.many	b0,array_dispose; }
	{ nop.m	0x0; adds	r1,0x0,r43; br.cond.sptk.few	40000000000BDA30 }

l40000000000BDAD0:
	{ nop.m	0x0; adds	r36,0x0,r0; nop.i	0x0; }
	{ adds	r8,0x0,r36; mov.i	ar.pfs,r42; mov.spnt	b0,r41,40000000000BDAE0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000000BDB00:
	{ adds	r44,0x0,r40; nop.i	0x0; br.call.sptk.many	b0,array_remove_quoted_nulls; }
	{ adds	r1,0x0,r43; adds	r44,0x0,r0; br.call.sptk.many	b0,ifs_firstchar; }
	{ adds	r1,0x0,r43; adds	r37,0x0,r8; adds	r44,0x0,r40 }
	{ adds	r45,0x0,r8; adds	r46,0x0,r0; br.call.sptk.many	b0,array_to_string; }
	{ adds	r1,0x0,r43; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r44,0x0,r37; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r43; br.cond.sptk.few	40000000000BDA10 }

l40000000000BDB70:
	{ adds	r44,0x0,r37; addl	r45,2,r0; br.call.sptk.many	b0,xrealloc; }
	{ adds	r37,0x0,r8; addl	r15,32,r0; adds	r1,0x0,r43; }
	{ adds	r14,0x0,r37; st1	[r14],r1,1; nop.i	0x0; }
	{ st1	[r0],r14; nop.i	0x0; br.cond.sptk.few	40000000000BD9C0; }
40000000000BDBB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; array_patsub: 40000000000BDBC0
array_patsub proc
	{ alloc	r42,ar.pfs,0x10,0x0,0xC; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ adds	r14,0x18,r32; mov	r41,b1; adds	r15,0x10,r32; }
	{ cmp.eq	p06,p07,0x0,r32; nop.m	0x0; adds	r43,0x0,r1 }
	{ adds	r44,0x0,r32; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000BDF20; }

l40000000000BDC00:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BDF20; }

l40000000000BDC20:
	{ nop.m	0x0; ld4	r14,[r15]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BDF20; }

l40000000000BDC40:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,array_copy; }
	{ adds	r39,0x18,r8; adds	r1,0x0,r43; adds	r40,0x0,r8; }
	{ ld8	r14,[r39]; adds	r15,0x10,r14; nop.i	0x0; }
	{ nop.m	0x0; ld8	r36,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r36,r14; (p07) br.cond.dpnt.few	40000000000BDD40; }

l40000000000BDC90:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000BDCA0:
	{ adds	r37,0x8,r36; nop.m	0x0; adds	r45,0x0,r33 }
	{ adds	r46,0x0,r34; nop.m	0x0; adds	r47,0x0,r35; }
	{ ld8	r44,[r37]; nop.i	0x0; br.call.sptk.many	b0,pat_subst; }
	{ ld8	r44,[r37]; adds	r1,0x0,r43; adds	r38,0x0,r8; }
	{ cmp.eq	p06,p07,0x0,r44; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BDD10; }

l40000000000BDCF0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r43; nop.m	0x0; nop.i	0x0 }

l40000000000BDD10:
	{ adds	r36,0x10,r36; ld8	r14,[r39]; nop.i	0x0 }
	{ st8	[r38],r37; ld8	r36,[r36]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r36,r14; (p06) br.cond.dptk.few	40000000000BDCA0; }

l40000000000BDD40:
	{ nop.m	0x0; tbit.z	p07,p06,r35,0x5; (p07) br.cond.dptk.few	40000000000BDEA0 }

l40000000000BDD50:
	{ adds	r44,0x0,r40; nop.i	0x0; br.call.sptk.many	b0,array_quote; }
	{ nop.m	0x0; tbit.z	p06,p07,r35,0x6; nop.i	0x0 }
	{ adds	r1,0x0,r43; adds	r44,0x10,r12; (p07) br.cond.dpnt.few	40000000000BDF50; }

l40000000000BDD80:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,ifs_firstchar; }
	{ adds	r1,0x0,r43; adds	r37,0x0,r8; br.call.sptk.many	b0,getifs; }
	{ adds	r1,0x0,r43; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	40000000000BDDD0; }

l40000000000BDDB0:
	{ ld1	r14,[r8]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000BDE10 }

l40000000000BDDD0:
	{ adds	r15,0x10,r12; ld4	r14,[r15]; addl	r15,32,r0; }
	{ cmp4.lt	p06,p07,0x1,r14; adds	r14,0x0,r37; (p07) br.cond.dpnt.few	40000000000BDFC0; }

l40000000000BDDF0:
	{ nop.m	0x0; st1	[r14],r1,1; nop.i	0x0; }
	{ st1	[r0],r14; nop.m	0x0; nop.i	0x0 }

l40000000000BDE10:
	{ adds	r45,0x0,r37; nop.m	0x0; adds	r46,0x0,r0 }
	{ adds	r44,0x0,r40; nop.m	0x0; br.call.sptk.many	b0,array_to_string; }
	{ adds	r1,0x0,r43; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r44,0x0,r37; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r43; nop.m	0x0; nop.i	0x0 }

l40000000000BDE60:
	{ nop.m	0x0; adds	r44,0x0,r40; br.call.sptk.many	b0,array_dispose; }
	{ adds	r1,0x0,r43; nop.m	0x0; nop.i	0x0 }

l40000000000BDE80:
	{ adds	r8,0x0,r36; mov.i	ar.pfs,r42; mov.spnt	b0,r41,40000000000BDE80 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000000BDEA0:
	{ adds	r44,0x0,r40; nop.i	0x0; br.call.sptk.many	b0,array_quote_escapes; }
	{ nop.m	0x0; adds	r1,0x0,r43; tbit.z	p07,p06,r35,0x6 }
	{ adds	r44,0x0,r40; adds	r46,0x0,r0; (p06) br.cond.dpnt.few	40000000000BDF50; }

l40000000000BDED0:
	{ nop.m	0x0; addl	r45,-9444,r1; nop.i	0x0; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,array_to_string; }
	{ adds	r1,0x0,r43; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r44,0x0,r40; nop.m	0x0; br.call.sptk.many	b0,array_dispose; }
	{ nop.m	0x0; adds	r1,0x0,r43; br.cond.sptk.few	40000000000BDE80 }

l40000000000BDF20:
	{ nop.m	0x0; adds	r36,0x0,r0; nop.i	0x0; }
	{ adds	r8,0x0,r36; mov.i	ar.pfs,r42; mov.spnt	b0,r41,40000000000BDF30 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000000BDF50:
	{ adds	r44,0x0,r40; nop.i	0x0; br.call.sptk.many	b0,array_remove_quoted_nulls; }
	{ adds	r1,0x0,r43; adds	r44,0x0,r0; br.call.sptk.many	b0,ifs_firstchar; }
	{ adds	r1,0x0,r43; adds	r37,0x0,r8; adds	r44,0x0,r40 }
	{ adds	r45,0x0,r8; adds	r46,0x0,r0; br.call.sptk.many	b0,array_to_string; }
	{ adds	r1,0x0,r43; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r44,0x0,r37; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r43; br.cond.sptk.few	40000000000BDE60 }

l40000000000BDFC0:
	{ adds	r44,0x0,r37; addl	r45,2,r0; br.call.sptk.many	b0,xrealloc; }
	{ adds	r37,0x0,r8; addl	r15,32,r0; adds	r1,0x0,r43; }
	{ adds	r14,0x0,r37; st1	[r14],r1,1; nop.i	0x0; }
	{ st1	[r0],r14; nop.i	0x0; br.cond.sptk.few	40000000000BDE10; }

;; array_subrange: 40000000000BE000
array_subrange proc
	{ alloc	r41,ar.pfs,0xF,0x0,0xC; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r43,LC }
	{ adds	r14,0x18,r32; cmp.eq	p06,p07,0x0,r32; adds	r42,0x0,r1; }
	{ nop.m	0x0; mov	r40,b0; (p06) br.cond.dpnt.few	40000000000BE2F0; }

l40000000000BE030:
	{ ld8	r46,[r14]; nop.m	0x0; adds	r14,0x10,r32; }
	{ cmp.eq	p06,p07,0x0,r46; nop.i	0x0; (p06) br.cond.spnt.few	40000000000BE2F0; }

l40000000000BE050:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; adds	r14,0x8,r32; (p06) br.cond.dpnt.few	40000000000BE2F0; }

l40000000000BE070:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.lt	p06,p07,r14,r33; adds	r14,0x10,r46; (p06) br.cond.dpnt.few	40000000000BE2F0; }

l40000000000BE090:
	{ nop.m	0x0; ld8	r45,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,r45,r46; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BE2F0; }

l40000000000BE0B0:
	{ nop.m	0x0; ld8	r14,[r45]; nop.i	0x0; }
	{ nop.m	0x0; cmp.lt	p07,p06,r14,r33; (p06) br.cond.dpnt.few	40000000000BE120; }

l40000000000BE0D0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000BE0E0:
	{ adds	r45,0x10,r45; ld8	r45,[r45]; nop.i	0x0; }
	{ cmp.eq	p06,p07,r45,r46; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BE2F0; }

l40000000000BE100:
	{ nop.m	0x0; ld8	r14,[r45]; nop.i	0x0; }
	{ nop.m	0x0; cmp.lt	p06,p07,r14,r33; (p06) br.cond.dptk.few	40000000000BE0E0; }

l40000000000BE120:
	{ cmp.lt	p07,p06,0x0,r34; adds	r14,0x10,r45; adds	r15,0xFFFFFFFFFFFFFFFF,r34; }
	{ (p06) adds	r46,0x0,r45; mov.i	LC,r15; (p06) br.cond.dpnt.few	40000000000BE170; }

l40000000000BE136:
	{ chk.a.nc	r15,3FFFFFFFFF0D3546; nop; (p32) nop }

l40000000000BE140:
	{ ld8	r14,[r14]; cmp.eq	p07,p06,r46,r14; adds	r15,0x10,r14 }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	40000000000BE170; br.cloop.sptk.few	40000000000BE320; }

l40000000000BE15C:
	{ (p14) cmp.lt	p00,p08,r0,r32; zxt1	r64,r64; break.b	0x1000 }

l40000000000BE160:
	{ adds	r46,0x0,r14; nop.m	0x0; nop.i	0x0 }

l40000000000BE170:
	{ adds	r44,0x0,r32; and	r36,0x3,r36; br.call.sptk.many	b0,array_slice; }
	{ adds	r1,0x0,r42; nop.m	0x0; adds	r38,0x0,r8 }
	{ adds	r44,0x0,r8; cmp4.eq	p06,p07,0x0,r36; (p06) br.cond.dptk.few	40000000000BE350 }

l40000000000BE1A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,array_quote; }
	{ adds	r1,0x0,r42; cmp4.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	40000000000BE3C0 }

l40000000000BE1C0:
	{ adds	r44,0x10,r12; nop.i	0x0; br.call.sptk.many	b0,ifs_firstchar; }
	{ adds	r1,0x0,r42; adds	r39,0x0,r8; br.call.sptk.many	b0,getifs; }
	{ adds	r1,0x0,r42; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	40000000000BE210; }

l40000000000BE1F0:
	{ ld1	r14,[r8]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000BE250 }

l40000000000BE210:
	{ adds	r15,0x10,r12; ld4	r14,[r15]; addl	r15,32,r0; }
	{ cmp4.lt	p06,p07,0x1,r14; adds	r14,0x0,r39; (p07) br.cond.dpnt.few	40000000000BE430; }

l40000000000BE230:
	{ nop.m	0x0; st1	[r14],r1,1; nop.i	0x0; }
	{ st1	[r0],r14; nop.m	0x0; nop.i	0x0 }

l40000000000BE250:
	{ adds	r45,0x0,r39; nop.m	0x0; adds	r46,0x0,r0 }
	{ adds	r44,0x0,r38; nop.m	0x0; br.call.sptk.many	b0,array_to_string; }
	{ adds	r1,0x0,r42; nop.m	0x0; adds	r37,0x0,r8 }
	{ adds	r44,0x0,r39; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r42; nop.m	0x0; nop.i	0x0 }

l40000000000BE2A0:
	{ nop.m	0x0; adds	r44,0x0,r38; br.call.sptk.many	b0,array_dispose; }
	{ adds	r1,0x0,r42; nop.m	0x0; nop.i	0x0 }

l40000000000BE2C0:
	{ adds	r8,0x0,r37; mov.i	ar.pfs,r41; mov.i	LC,r43; }
	{ nop.m	0x0; mov.spnt	b0,r40,40000000000BE2D0; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l40000000000BE2F0:
	{ adds	r37,0x0,r0; adds	r8,0x0,r37; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.i	LC,r43; mov.spnt	b0,r40,40000000000BE300 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000BE320:
	{ ld8	r14,[r15]; cmp.eq	p06,p07,r14,r46; adds	r15,0x10,r14 }
	{ nop.b	0x0; (p06) br.cond.dpnt.few	40000000000BE170; br.cloop.sptk.few	40000000000BE320 }

l40000000000BE33C:
	{ (p63) invala; break.i	0x1000; break.b	0x1000 }

l40000000000BE340:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000BE160 }

l40000000000BE350:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,array_quote_escapes; }
	{ adds	r1,0x0,r42; adds	r44,0x0,r38; adds	r46,0x0,r0; }
	{ nop.m	0x0; addl	r45,-9444,r1; nop.i	0x0; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,array_to_string; }
	{ adds	r1,0x0,r42; nop.m	0x0; adds	r37,0x0,r8 }
	{ adds	r44,0x0,r38; nop.m	0x0; br.call.sptk.many	b0,array_dispose; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	40000000000BE2C0 }

l40000000000BE3C0:
	{ adds	r44,0x0,r38; nop.i	0x0; br.call.sptk.many	b0,array_remove_quoted_nulls; }
	{ adds	r1,0x0,r42; adds	r44,0x0,r0; br.call.sptk.many	b0,ifs_firstchar; }
	{ adds	r1,0x0,r42; adds	r39,0x0,r8; adds	r44,0x0,r38 }
	{ adds	r45,0x0,r8; adds	r46,0x0,r0; br.call.sptk.many	b0,array_to_string; }
	{ adds	r1,0x0,r42; nop.m	0x0; adds	r37,0x0,r8 }
	{ adds	r44,0x0,r39; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	40000000000BE2A0 }

l40000000000BE430:
	{ adds	r44,0x0,r39; addl	r45,2,r0; br.call.sptk.many	b0,xrealloc; }
	{ adds	r39,0x0,r8; addl	r15,32,r0; adds	r1,0x0,r42; }
	{ adds	r14,0x0,r39; st1	[r14],r1,1; nop.i	0x0; }
	{ st1	[r0],r14; nop.i	0x0; br.cond.sptk.few	40000000000BE250; }
40000000000BE470 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; fn40000000000BE480: 40000000000BE480
;;   Called from:
;;     40000000000BED06 (in bind_array_variable)
;;     40000000000BED8C (in bind_array_variable)
;;     40000000000BEDDC (in bind_array_variable)
;;     40000000000BEE2C (in bind_array_element)
;;     40000000000BEF0C (in bind_assoc_variable)
;;     40000000000C05D6 (in assign_compound_array_list)
;;     40000000000C0A3C (in assign_compound_array_list)
fn40000000000BE480 proc
	{ alloc	r41,ar.pfs,0xF,0x0,0xB; mov	r40,b0; adds	r42,0x0,r1; }
	{ nop.m	0x0; tbit.z	p06,p07,r36,0x0; (p06) br.cond.dptk.few	40000000000BE6F0 }

l40000000000BE4A0:
	{ addl	r43,48,r0; adds	r37,0x0,r32; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r42; nop.m	0x0; adds	r38,0x0,r8 }
	{ ld8	r43,[r32]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r42; adds	r43,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r44,[r37],40; nop.m	0x0; adds	r1,0x0,r42 }
	{ adds	r43,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; ld4	r14,[r37]; adds	r1,0x0,r42 }
	{ st8	[r8],r38; nop.i	0x0; tbit.z	p06,p07,r14,0x6 }
	{ nop.m	0x0; adds	r14,0x8,r32; (p06) br.cond.dptk.few	40000000000BE7A0; }

l40000000000BE530:
	{ nop.m	0x0; adds	r44,0x0,r34; nop.i	0x0 }
	{ ld8	r43,[r14]; nop.m	0x0; br.call.sptk.many	b0,assoc_reference; }
	{ nop.m	0x0; adds	r1,0x0,r42; adds	r39,0x0,r8; }

l40000000000BE560:
	{ cmp.eq	p06,p07,0x0,r39; adds	r43,0x0,r39; (p06) br.cond.dpnt.few	40000000000BE800; }

l40000000000BE570:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r42; adds	r43,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r42; nop.m	0x0; adds	r43,0x0,r8 }
	{ adds	r44,0x0,r39; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ ld4	r15,[r37]; adds	r14,0x8,r38; adds	r16,0x10,r38 }
	{ adds	r1,0x0,r42; adds	r44,0x0,r35; adds	r45,0x0,r36; }
	{ and	r15,0xFFFFFFFFFFFFFFBA,r15; st8	[r8],r14; adds	r14,0x28,r38 }
	{ adds	r43,0x0,r38; st8	[r0],r16; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,make_variable_value; }
	{ adds	r1,0x0,r42; nop.m	0x0; adds	r37,0x0,r8 }
	{ adds	r43,0x0,r38; nop.m	0x0; br.call.sptk.many	b0,dispose_variable; }
	{ adds	r1,0x0,r42; nop.m	0x0; nop.i	0x0 }

l40000000000BE630:
	{ adds	r14,0x20,r32; ld8	r8,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	40000000000BE740 }

l40000000000BE650:
	{ nop.m	0x0; ld8	r14,[r8],8; adds	r43,0x0,r32 }
	{ adds	r44,0x0,r37; adds	r45,0x0,r33; adds	r46,0x0,r34; }
	{ nop.m	0x0; ld8	r1,[r8]; mov.spnt	b6,r14,40000000000BE670 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,b6; }
	{ adds	r1,0x0,r42; nop.m	0x0; nop.i	0x0 }

l40000000000BE6A0:
	{ cmp.eq	p06,p07,0x0,r37; adds	r43,0x0,r37; (p06) br.cond.dpnt.few	40000000000BE6D0; }

l40000000000BE6B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r42; nop.m	0x0; nop.i	0x0 }

l40000000000BE6D0:
	{ adds	r8,0x0,r32; nop.m	0x0; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.spnt	b0,r40,40000000000BE6E0; br.ret	b0; }

l40000000000BE6F0:
	{ adds	r43,0x0,r32; nop.m	0x0; adds	r44,0x0,r35 }
	{ adds	r45,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,make_variable_value; }
	{ adds	r14,0x20,r32; adds	r37,0x0,r8; adds	r1,0x0,r42; }
	{ nop.m	0x0; ld8	r8,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	40000000000BE650 }

l40000000000BE740:
	{ nop.m	0x0; adds	r14,0x28,r32; nop.i	0x0; }
	{ ld4	r14,[r14]; nop.i	0x0; tbit.z	p06,p07,r14,0x6 }
	{ nop.m	0x0; adds	r14,0x8,r32; (p06) br.cond.dptk.few	40000000000BE7D0; }

l40000000000BE770:
	{ adds	r44,0x0,r34; nop.m	0x0; adds	r45,0x0,r37 }
	{ ld8	r43,[r14]; nop.m	0x0; br.call.sptk.many	b0,assoc_insert; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	40000000000BE6A0 }

l40000000000BE7A0:
	{ nop.m	0x0; adds	r44,0x0,r33; nop.i	0x0 }
	{ ld8	r43,[r14]; nop.m	0x0; br.call.sptk.many	b0,array_reference; }
	{ adds	r1,0x0,r42; adds	r39,0x0,r8; br.cond.sptk.few	40000000000BE560 }

l40000000000BE7D0:
	{ adds	r44,0x0,r33; nop.m	0x0; adds	r45,0x0,r37 }
	{ ld8	r43,[r14]; nop.m	0x0; br.call.sptk.many	b0,array_insert; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	40000000000BE6A0 }

l40000000000BE800:
	{ addl	r43,1,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r14,0x8,r38; ld4.a	r15,[r37]; adds	r16,0x10,r38 }
	{ adds	r1,0x0,r42; adds	r44,0x0,r35; adds	r45,0x0,r36; }
	{ st8	[r8],r14; st1	[r0],r8; adds	r14,0x28,r38 }
	{ adds	r43,0x0,r38; ld4.c.clr	r15,[r37]; nop.i	0x0 }
	{ st8	[r0],r16; and	r15,0xFFFFFFFFFFFFFFBA,r15; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,make_variable_value; }
	{ adds	r1,0x0,r42; nop.m	0x0; adds	r37,0x0,r8 }
	{ adds	r43,0x0,r38; nop.m	0x0; br.call.sptk.many	b0,dispose_variable; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	40000000000BE630; }
40000000000BE8A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000BE8B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; convert_var_to_array: 40000000000BE8C0
;;   Called from:
;;     400000000004FA5C (in coproc_setvars)
;;     40000000000BED5C (in bind_array_variable)
;;     40000000000BF07C (in find_or_make_array_variable)
;;     40000000000E361C (in fn40000000000E3200)
;;     40000000000E6F7C (in gen_compspec_completions)
;;     40000000000F1FBC (in fn40000000000F0900)
convert_var_to_array proc
	{ alloc	r38,ar.pfs,0xB,0x0,0x8; adds	r33,0x8,r32; nop.b	0x0 }
	{ adds	r39,0x0,r1; mov	r37,b5; adds	r34,0x10,r32; }
	{ ld8	r36,[r33]; nop.i	0x0; br.call.sptk.many	b0,array_create; }
	{ cmp.eq	p06,p07,0x0,r36; adds	r1,0x0,r39; adds	r35,0x0,r8 }
	{ adds	r40,0x0,r8; adds	r41,0x0,r0; (p06) br.cond.dpnt.few	40000000000BE930; }

l40000000000BE910:
	{ nop.m	0x0; adds	r42,0x0,r36; br.call.sptk.many	b0,array_insert; }
	{ adds	r1,0x0,r39; nop.m	0x0; nop.i	0x0 }

l40000000000BE930:
	{ nop.m	0x0; ld8	r40,[r33]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r40; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BE970; }

l40000000000BE950:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r39; nop.m	0x0; nop.i	0x0 }

l40000000000BE970:
	{ ld8	r14,[r34]; nop.m	0x0; adds	r16,0x18,r32 }
	{ adds	r15,0x20,r32; st8	[r35],r33; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; st8	[r0],r16; nop.i	0x0 }
	{ st8	[r0],r15; adds	r40,0x0,r14; (p06) br.cond.dpnt.few	40000000000BE9D0; }

l40000000000BE9B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r39; st8	[r0],r34; nop.i	0x0; }

l40000000000BE9D0:
	{ adds	r14,0x28,r32; addl	r16,5780,r1; nop.b	0x0 }
	{ addl	r17,-4097,r0; adds	r8,0x0,r32; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; ld4	r15,[r14]; mov.spnt	b0,r37,40000000000BE9F0 }
	{ nop.m	0x0; nop.i	0x0; tbit.z	p06,p07,r15,0x0 }
	{ and	r17,r17,r15; (p07) ld4	r15,[r16]; nop.i	0x0; }

l40000000000BEA1C:
	{ cmp4.eq.or.andcm	p00,p43,r1,r0; (p17) mov	pr,r3,0x84C0; (p48) cmp.eq	p03,p08,r4,r100 }

l40000000000BEA26:
	{ Invalid; (p07) nop; nop; }

l40000000000BEA2C:
	{ Invalid; Invalid; add	r0,r32,r0; }
	{ cmp.lt	p00,p24,r33,r0; (p52) nop; zxt1	r2,r64 }

;; convert_var_to_assoc: 40000000000BEA40
;;   Called from:
;;     40000000000F201C (in fn40000000000F0900)
convert_var_to_assoc proc
	{ alloc	r38,ar.pfs,0xB,0x0,0x8; adds	r33,0x8,r32; nop.b	0x0 }
	{ adds	r39,0x0,r1; mov	r37,b5; adds	r34,0x10,r32; }
	{ ld8	r36,[r33]; adds	r40,0x0,r0; br.call.sptk.many	b0,hash_create; }
	{ cmp.eq	p06,p07,0x0,r36; adds	r1,0x0,r39; nop.i	0x0 }
	{ adds	r35,0x0,r8; addl	r40,2,r0; (p06) br.cond.dpnt.few	40000000000BEAF0; }

l40000000000BEA90:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ addl	r15,48,r0; adds	r14,0x0,r8; adds	r1,0x0,r39 }
	{ adds	r41,0x0,r8; adds	r40,0x0,r35; adds	r42,0x0,r36; }
	{ st1	[r14],r1,1; nop.i	0x0; nop.i	0x0 }
	{ st1	[r0],r14; nop.m	0x0; br.call.sptk.many	b0,assoc_insert; }
	{ adds	r1,0x0,r39; nop.m	0x0; nop.i	0x0 }

l40000000000BEAF0:
	{ nop.m	0x0; ld8	r40,[r33]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r40; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BEB30; }

l40000000000BEB10:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r39; nop.m	0x0; nop.i	0x0 }

l40000000000BEB30:
	{ ld8	r14,[r34]; nop.m	0x0; adds	r16,0x18,r32 }
	{ adds	r15,0x20,r32; st8	[r35],r33; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; st8	[r0],r16; nop.i	0x0 }
	{ st8	[r0],r15; adds	r40,0x0,r14; (p06) br.cond.dpnt.few	40000000000BEB90; }

l40000000000BEB70:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r39; st8	[r0],r34; nop.i	0x0; }

l40000000000BEB90:
	{ adds	r14,0x28,r32; addl	r16,5780,r1; nop.b	0x0 }
	{ addl	r17,-4097,r0; adds	r8,0x0,r32; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; ld4	r15,[r14]; mov.spnt	b0,r37,40000000000BEBB0 }
	{ nop.m	0x0; nop.i	0x0; tbit.z	p06,p07,r15,0x0 }
	{ and	r17,r17,r15; (p07) ld4	r15,[r16]; nop.i	0x0; }

l40000000000BEBDC:
	{ cmp4.eq.or.andcm	p00,p43,r1,r0; (p17) mov	pr,r3,0x84C0; (p48) cmp.eq	p03,p08,r4,r100 }

l40000000000BEBE6:
	{ Invalid; (p07) nop; nop; }

l40000000000BEBEC:
	{ Invalid; Invalid; add	r0,r32,r0; }
	{ nop; (p05) cmp.lt.unc	p03,p02,r2,r96; zxt4	r33,r14 }

;; bind_array_variable: 40000000000BEC00
;;   Called from:
;;     400000000004F90C (in coproc_setvars)
;;     400000000004F96C (in coproc_setvars)
;;     400000000004FABC (in coproc_setvars)
;;     400000000004FB1C (in coproc_setvars)
;;     40000000000C118C (in assign_array_element)
;;     40000000000F223C (in fn40000000000F0900)
bind_array_variable proc
	{ alloc	r40,ar.pfs,0xC,0x0,0xA; addl	r14,7172,r1; nop.b	0x0 }
	{ adds	r41,0x0,r1; mov	r39,b7; adds	r42,0x0,r32; }
	{ nop.m	0x0; adds	r38,0x0,r34; adds	r36,0x0,r35; }
	{ ld8	r43,[r14]; nop.i	0x0; br.call.sptk.many	b0,var_lookup; }
	{ adds	r14,0x28,r8; adds	r1,0x0,r41; cmp.eq	p07,p06,0x0,r8 }
	{ addl	r16,16386,r0; adds	r37,0x0,r8; (p07) br.cond.dpnt.few	40000000000BED90; }

l40000000000BEC60:
	{ ld8	r15,[r14]; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; and	r15,r15,r16; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	40000000000BECD0; }

l40000000000BEC90:
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x1; adds	r8,0x0,r37 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000BED10; }

l40000000000BECB0:
	{ nop.m	0x0; mov.i	ar.pfs,r40; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000BECC0; br.ret	b0 }

l40000000000BECD0:
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x2; adds	r32,0x0,r37 }
	{ adds	r34,0x0,r0; adds	r35,0x0,r38; (p07) br.cond.dpnt.few	40000000000BED40; }

l40000000000BECF0:
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000BECF0; mov.i	ar.pfs,r40; }
	{ alloc	r2,ar.pfs,0x5,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000BE480; }

l40000000000BED10:
	{ adds	r42,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,err_readonly; }
	{ adds	r8,0x0,r37; adds	r1,0x0,r41; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000BED30; br.ret	b0; }

l40000000000BED40:
	{ adds	r42,0x0,r8; nop.m	0x0; adds	r34,0x0,r0 }
	{ adds	r35,0x0,r38; nop.m	0x0; br.call.sptk.many	b0,convert_var_to_array; }
	{ adds	r37,0x0,r8; adds	r1,0x0,r41; mov.spnt	b0,r39,40000000000BED60; }
	{ adds	r32,0x0,r37; nop.m	0x0; mov.i	ar.pfs,r40; }
	{ alloc	r2,ar.pfs,0x5,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000BE480; }

l40000000000BED90:
	{ adds	r42,0x0,r32; nop.m	0x0; adds	r34,0x0,r0 }
	{ adds	r35,0x0,r38; nop.m	0x0; br.call.sptk.many	b0,make_new_array_variable; }
	{ adds	r37,0x0,r8; adds	r1,0x0,r41; mov.spnt	b0,r39,40000000000BEDB0; }
	{ adds	r32,0x0,r37; nop.m	0x0; mov.i	ar.pfs,r40; }
	{ alloc	r2,ar.pfs,0x5,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000BE480; }
40000000000BEDE0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000BEDF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; bind_array_element: 40000000000BEE00
;;   Called from:
;;     40000000001013CC (in mapfile_builtin)
bind_array_element proc
	{ alloc	r16,ar.pfs,0x5,0x0,0x5; adds	r14,0x0,r34; adds	r36,0x0,r35; }
	{ adds	r34,0x0,r0; nop.m	0x0; adds	r35,0x0,r14; }
	{ alloc	r2,ar.pfs,0x5,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000BE480; }
40000000000BEE30 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; bind_assoc_variable: 40000000000BEE40
;;   Called from:
;;     40000000000C135C (in assign_array_element)
;;     40000000000F1CDC (in fn40000000000F0900)
bind_assoc_variable proc
	{ alloc	r39,ar.pfs,0xA,0x0,0x9; adds	r14,0x28,r32; mov	r38,b6 }
	{ adds	r37,0x0,r32; nop.m	0x0; adds	r40,0x0,r1; }
	{ ld8	r15,[r14]; addl	r16,16386,r0; nop.b	0x0 }
	{ adds	r8,0x0,r37; nop.m	0x0; mov.i	ar.pfs,r39; }
	{ and	r15,r15,r16; nop.m	0x0; mov.spnt	b0,r38,40000000000BEE80; }
	{ cmp.eq	p06,p07,0x0,r15; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BEEF0; }

l40000000000BEEA0:
	{ ld4	r14,[r14]; nop.i	0x0; tbit.z	p06,p07,r14,0x1 }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	40000000000BEEC0; br.ret	b0; }

l40000000000BEEBC:
	{ nop; (p05) invala; break.i	0x1000 }

l40000000000BEEC0:
	{ adds	r41,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,err_readonly; }
	{ adds	r8,0x0,r37; adds	r1,0x0,r40; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000BEEE0; br.ret	b0; }

l40000000000BEEF0:
	{ adds	r33,0x0,r0; mov.spnt	b0,r38,40000000000BEEF0; mov.i	ar.pfs,r39; }
	{ alloc	r2,ar.pfs,0x5,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000BE480; }
40000000000BEF10 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000BEF20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000BEF30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; find_or_make_array_variable: 40000000000BEF40
;;   Called from:
;;     40000000000C0DBC (in assign_array_from_string)
;;     400000000010114C (in mapfile_builtin)
;;     400000000010545C (in read_builtin)
find_or_make_array_variable proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; adds	r36,0x0,r1; mov	r34,b2 }
	{ nop.m	0x0; adds	r37,0x0,r32; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ cmp.eq	p07,p06,0x0,r8; adds	r1,0x0,r36; nop.i	0x0 }
	{ adds	r14,0x0,r8; adds	r15,0x28,r8; (p07) br.cond.dpnt.few	40000000000BF0B0; }

l40000000000BEF90:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x0; (p06) br.cond.dptk.few	40000000000BF010 }

l40000000000BEFA0:
	{ ld8	r16,[r15]; addl	r17,16386,r0; and	r16,r16,r17; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r16; (p06) br.cond.dptk.few	40000000000BF010 }

l40000000000BEFC0:
	{ ld4	r14,[r15]; nop.i	0x0; tbit.z	p06,p07,r14,0x1 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000BF080; }

l40000000000BEFE0:
	{ (p06) adds	r14,0x0,r0; nop.m	0x0; nop.i	0x0; }

l40000000000BEFE6:
	{ break.m	0x4000; nop; nop }

l40000000000BEFF0:
	{ adds	r8,0x0,r14; nop.m	0x0; mov.i	ar.pfs,r35; }

l40000000000BEFF2:
	{ (p32) break.m	0x42003; nop; Invalid }
	{ ld1	r32,[r0]; (p20) nop; Invalid }

l40000000000BF010:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x1; (p06) br.cond.dptk.few	40000000000BF040 }

l40000000000BF020:
	{ nop.m	0x0; ld4	r16,[r15]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r16,0x2; (p07) br.cond.dpnt.few	40000000000BF120 }

l40000000000BF040:
	{ ld8	r15,[r15]; and	r15,0x44,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	40000000000BEFF0 }

l40000000000BF060:
	{ adds	r32,0x0,r14; mov.spnt	b0,r34,40000000000BF060; mov.i	ar.pfs,r35; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	convert_var_to_array; }

l40000000000BF080:
	{ adds	r37,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,err_readonly; }
	{ adds	r14,0x0,r0; adds	r1,0x0,r36; mov.i	ar.pfs,r35; }
	{ adds	r8,0x0,r14; mov.spnt	b0,r34,40000000000BF0A0; br.ret	b0 }

l40000000000BF0B0:
	{ adds	r37,0x0,r32; tbit.z	p06,p07,r33,0x1; (p06) br.cond.dptk.few	40000000000BF0F0; }

l40000000000BF0C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,make_new_assoc_variable; }
	{ adds	r14,0x0,r8; adds	r1,0x0,r36; mov.i	ar.pfs,r35; }
	{ adds	r8,0x0,r14; mov.spnt	b0,r34,40000000000BF0E0; br.ret	b0; }

l40000000000BF0F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,make_new_array_variable; }
	{ adds	r14,0x0,r8; adds	r1,0x0,r36; mov.i	ar.pfs,r35; }
	{ adds	r8,0x0,r14; mov.spnt	b0,r34,40000000000BF110; br.ret	b0 }

l40000000000BF120:
	{ addl	r38,-4764,r1; addl	r39,5,r0; adds	r37,0x0,r0; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r37,0x0,r8 }
	{ adds	r38,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,report_error; }
	{ adds	r14,0x0,r0; adds	r1,0x0,r36; mov.i	ar.pfs,r35; }
	{ adds	r8,0x0,r14; mov.spnt	b0,r34,40000000000BF170; br.ret	b0; }

;; assign_array_var_from_word_list: 40000000000BF180
;;   Called from:
;;     40000000000E356C (in fn40000000000E3200)
;;     40000000000E363C (in fn40000000000E3200)
;;     400000000010557C (in read_builtin)
;;     4000000000107EFC (in read_builtin)
assign_array_var_from_word_list proc
	{ alloc	r40,ar.pfs,0xE,0x0,0xA; adds	r14,0x8,r32; tbit.z	p06,p07,r34,0x0 }
	{ adds	r41,0x0,r1; adds	r35,0x0,r33; adds	r37,0x20,r32; }
	{ ld8	r38,[r14]; adds	r36,0x0,r0; mov	r39,b7; }
	{ (p07) adds	r14,0x8,r38; (p07) ld8	r36,[r14]; nop.i	0x0; }

l40000000000BF1B6:
	{ (p18) fwb; cmp4.eq	p00,p00,r0,r1; (p01) nop; }

l40000000000BF1BC:
	{ nop; (p20) cmp.eq	p00,p16,r9,r64; mov	pr,r72,0xE440 }

l40000000000BF1C6:
	{ (p03) chk.a.clr	f0,3FFFFFFFFFD423D6; nop; break.b	0x80000 }

l40000000000BF1D0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000BF1E0:
	{ nop.m	0x0; ld8	r8,[r37]; adds	r15,0x8,r35 }
	{ adds	r44,0x0,r36; adds	r42,0x0,r32; adds	r45,0x0,r0; }
	{ cmp.eq	p06,p07,0x0,r8; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BF280; }

l40000000000BF210:
	{ nop.m	0x0; ld8	r15,[r15]; adds	r36,0x1,r36 }
	{ ld8	r14,[r8],8; ld8	r1,[r8]; mov.spnt	b6,r14,40000000000BF220; }
	{ ld8	r43,[r15]; nop.i	0x0; br.call.sptk.many	b0,b6; }
	{ ld8	r35,[r35]; nop.m	0x0; adds	r1,0x0,r41; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	40000000000BF1E0 }

l40000000000BF260:
	{ adds	r8,0x0,r32; nop.m	0x0; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000BF270; br.ret	b0 }

l40000000000BF280:
	{ adds	r14,0x8,r35; adds	r43,0x0,r36; adds	r42,0x0,r38 }
	{ adds	r36,0x1,r36; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r44,[r14]; nop.i	0x0; br.call.sptk.many	b0,array_insert; }
	{ ld8	r35,[r35]; nop.m	0x0; adds	r1,0x0,r41; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	40000000000BF1E0 }

l40000000000BF2D0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000BF260; }
40000000000BF2E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000BF2F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; expand_compound_array_assignment: 40000000000BF300
;;   Called from:
;;     400000000009980C (in fn4000000000099100)
;;     40000000000C0CEC (in assign_array_var_from_string)
expand_compound_array_assignment proc
	{ alloc	r53,ar.pfs,0x1C,0x0,0x18; adds	r12,0xFFFFFFFFFFFFFFE0,r12; addl	r41,-9996,r1 }
	{ ld1	r14,[r33]; addl	r45,23540,r1; adds	r39,0x0,r33; }
	{ adds	r54,0x0,r1; adds	r42,0x18,r12; sxt1	r14,r14 }
	{ addl	r43,92,r0; ld8	r41,[r41]; addl	r46,93,r0; }
	{ nop.m	0x0; mov	r55,LC; nop.b	0x0 }
	{ nop.m	0x0; nop.m	0x0; cmp4.eq	p07,p06,0x28,r14; }
	{ nop.m	0x0; mov	r52,b4; (p07) br.cond.dpnt.few	40000000000BF770 }

l40000000000BF370:
	{ addl	r58,-4756,r1; adds	r56,0x0,r39; addl	r57,1,r0; }
	{ ld8	r58,[r58]; nop.i	0x0; br.call.sptk.many	b0,parse_string_to_word_list; }
	{ cmp.eq	p06,p07,0x0,r8; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r1,0x0,r54; nop.m	0x0; adds	r38,0x0,r8; }
	{ nop.m	0x0; (p06) adds	r34,0x0,r0; (p06) br.cond.dpnt.few	40000000000BF460; }

l40000000000BF3BC:
	{ Invalid; (p04) cmp.lt.unc	p34,p16,r8,r64; (p01) rfi }

l40000000000BF3C0:
	{ adds	r36,0x8,r35; ld8	r14,[r36]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000BF420; }

l40000000000BF3E0:
	{ nop.m	0x0; ld8	r56,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r56; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BF420; }

l40000000000BF400:
	{ ld1	r15,[r56]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5B,r15; (p07) br.cond.dpnt.few	40000000000BF4E0 }

l40000000000BF420:
	{ nop.m	0x0; ld8	r35,[r35]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	40000000000BF3C0 }

l40000000000BF440:
	{ adds	r56,0x0,r38; nop.i	0x0; br.call.sptk.many	b0,expand_words_no_vars; }
	{ nop.m	0x0; adds	r1,0x0,r54; adds	r34,0x0,r8 }

l40000000000BF460:
	{ adds	r56,0x0,r38; nop.i	0x0; br.call.sptk.many	b0,dispose_words; }
	{ cmp.eq	p06,p07,r33,r39; nop.m	0x0; adds	r1,0x0,r54 }
	{ adds	r56,0x0,r39; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000BF4B0; }

l40000000000BF490:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r54; nop.m	0x0; nop.i	0x0 }

l40000000000BF4B0:
	{ adds	r8,0x0,r34; mov.i	ar.pfs,r53; mov.i	LC,r55; }
	{ nop.m	0x0; mov.spnt	b0,r52,40000000000BF4C0; nop.i	0x0 }
	{ adds	r12,0x20,r12; nop.m	0x0; br.ret	b0; }

l40000000000BF4E0:
	{ addl	r57,61,r0; adds	r40,0x0,r0; br.call.sptk.many	b0,mbschr; }
	{ adds	r1,0x0,r54; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	40000000000BF420; }

l40000000000BF500:
	{ nop.m	0x0; ld8	r14,[r36]; nop.i	0x0; }
	{ ld8	r44,[r14]; st8	[r0],r42; nop.i	0x0; }
	{ adds	r56,0x0,r44; adds	r37,0x0,r44; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r54; nop.m	0x0; add	r48,r44,r8 }
	{ add	r56,r8,r8,0x1; nop.m	0x0; br.call.sptk.many	b0,xmalloc; }
	{ ld1	r14,[r44]; adds	r1,0x0,r54; adds	r47,0x0,r8 }
	{ adds	r34,0x0,r8; nop.m	0x0; sxt1	r14,r14; }

l40000000000BF570:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000BF700; }

l40000000000BF580:
	{ cmp4.eq	p06,p07,0x3D,r14; adds	r56,0x0,r37; (p06) br.cond.dpnt.few	40000000000BF950; }

l40000000000BF590:
	{ cmp4.eq	p07,p06,0x0,r40; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BF600; }

l40000000000BF5A0:
	{ cmp4.eq	p07,p06,0x5B,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000BF960; }

l40000000000BF5B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,glob_char_p; }
	{ adds	r1,0x0,r54; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000000BF900 }

l40000000000BF5D0:
	{ ld1	r14,[r37]; add	r14,r45,r14; nop.i	0x0; }
	{ nop.m	0x0; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	40000000000BF900; }

l40000000000BF600:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r54; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	40000000000BF920 }

l40000000000BF620:
	{ ld1	r14,[r37]; addl	r8,1,r0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r15,r14,5,3; and	r16,0x1F,r14; }
	{ shladd	r15,r15,0x2,r41; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r15,r15,r16; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r15,0x0; (p07) br.cond.dpnt.few	40000000000BF840; }

l40000000000BF670:
	{ sub	r19,r37,r37,0x1; cmp.eq	p06,p07,0x0,r8; adds	r15,0x0,r37 }
	{ adds	r16,0x0,r34; adds	r17,0x1,r37; add	r18,r19,r8; }
	{ nop.m	0x0; mov.i	LC,r18; nop.i	0x0; }
	{ nop.m	0x0; (p07) mov.i	LC,r18; (p06) mov.i	LC,0x0 }

l40000000000BF6AC:
	{ cmpxchg2.acq	r65,[r0],r10; zxt1	r0,r64; nop }

l40000000000BF6B0:
	{ adds	r34,0x0,r16; nop.m	0x0; adds	r57,0x1,r15; }
	{ st1	[r34],r1,1; nop.m	0x0; adds	r15,0x0,r57; }
	{ nop.m	0x0; adds	r16,0x0,r34; br.cloop.sptk.few	40000000000BF7F0; }

l40000000000BF6E0:
	{ ld1	r14,[r57]; adds	r37,0x0,r57; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000BF580 }

l40000000000BF700:
	{ ld8.a	r14,[r36]; st1	[r0],r34; nop.i	0x0; }
	{ nop.m	0x0; ld8.c.clr	r14,[r36]; nop.i	0x0; }
	{ ld8	r56,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; ld8	r14,[r36]; adds	r1,0x0,r54 }
	{ ld8	r35,[r35]; cmp.eq	p07,p06,0x0,r35; nop.i	0x0; }
	{ st8	[r47],r14; nop.i	0x0; (p06) br.cond.dptk.few	40000000000BF3C0 }

l40000000000BF760:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000BF440 }

l40000000000BF770:
	{ adds	r14,0x20,r12; addl	r15,1,r0; adds	r56,0x0,r33; }
	{ nop.m	0x0; adds	r57,0x0,r14; nop.i	0x0 }
	{ st4	[r15],r14; nop.m	0x0; br.call.sptk.many	b0,extract_array_assignment_list; }
	{ nop.m	0x0; adds	r1,0x0,r54; adds	r39,0x0,r8 }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	40000000000BF370 }

l40000000000BF7C0:
	{ adds	r34,0x0,r0; adds	r8,0x0,r34; mov.i	ar.pfs,r53; }
	{ nop.m	0x0; mov.i	LC,r55; mov.spnt	b0,r52,40000000000BF7D0 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0 }

l40000000000BF7F0:
	{ ld1	r14,[r17],1; adds	r34,0x0,r16; adds	r57,0x1,r15; }
	{ nop.m	0x0; sxt1	r14,r14; adds	r15,0x0,r57; }
	{ nop.m	0x0; st1	[r34],r1,1; nop.i	0x0; }
	{ nop.m	0x0; adds	r16,0x0,r34; br.cloop.sptk.few	40000000000BF7F0 }

l40000000000BF830:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000BF6E0 }

l40000000000BF840:
	{ ld8	r14,[r42]; adds	r15,0x10,r12; adds	r56,0x0,r0 }
	{ adds	r57,0x0,r37; sub	r58,r48,r37; adds	r59,0x0,r42; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r18,0x10,r12; adds	r1,0x0,r54; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BFA50; }

l40000000000BF890:
	{ ld8	r14,[r18]; nop.m	0x0; addl	r8,1,r0; }
	{ nop.m	0x0; st8	[r14],r42; nop.i	0x0; }
	{ ld1	r14,[r37]; nop.i	0x0; sxt1	r14,r14 }

l40000000000BF8C0:
	{ sub	r19,r37,r37,0x1; cmp.eq	p06,p07,0x0,r8; adds	r15,0x0,r37 }
	{ adds	r16,0x0,r34; adds	r17,0x1,r37; add	r18,r19,r8; }
	{ nop.m	0x0; mov.i	LC,r18; (p07) mov.i	LC,r18; }

l40000000000BF8F0:
	{ nop.m	0x0; (p06) mov.i	LC,0x0; br.cond.sptk.few	40000000000BF6B0 }

l40000000000BF8FC:
	{ (p46) nop; Invalid; break.i	0x1000 }

l40000000000BF900:
	{ st1	[r34],r1,1; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r54; cmp.ltu	p07,p06,0x1,r8; (p07) br.cond.dptk.few	40000000000BF620 }

l40000000000BF920:
	{ ld1	r14,[r37],1; st1	[r34],r1,1; nop.i	0x0; }
	{ nop.m	0x0; ld1	r14,[r37]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; br.cond.sptk.few	40000000000BF570 }

l40000000000BF950:
	{ nop.m	0x0; addl	r40,1,r0; br.cond.sptk.few	40000000000BF600 }

l40000000000BF960:
	{ sub	r50,r37,r44; adds	r56,0x0,r44; adds	r58,0x0,r0; }
	{ adds	r57,0x0,r50; adds	r51,0x0,r50; br.call.sptk.many	b0,skipsubscript; }
	{ adds	r1,0x0,r54; adds	r58,0x0,r8; adds	r49,0x0,r8 }
	{ adds	r56,0x0,r37; adds	r57,0x0,r50; br.call.sptk.many	b0,substring; }
	{ st1	[r34],r1,1; nop.m	0x0; adds	r1,0x0,r54 }
	{ adds	r50,0x0,r8; nop.m	0x0; adds	r57,0x0,r8; }
	{ adds	r56,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ sub	r14,r49,r51; nop.m	0x0; sxt4	r49,r49 }
	{ adds	r1,0x0,r54; nop.m	0x0; adds	r56,0x0,r50; }
	{ nop.m	0x0; sxt4	r14,r14; add	r37,r37,r49,0x1; }
	{ add	r34,r34,r14; adds	r14,0x0,r34; adds	r34,0x2,r34; }
	{ nop.m	0x0; st1	[r14],r1,1; nop.i	0x0; }
	{ st1	[r46],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ ld1	r14,[r37]; nop.m	0x0; adds	r1,0x0,r54; }
	{ nop.m	0x0; sxt1	r14,r14; br.cond.sptk.few	40000000000BF570 }

l40000000000BFA50:
	{ cmp.eq	p06,p07,0x0,r8; (p07) ld1	r14,[r37]; nop.i	0x0; }

l40000000000BFA5C:
	{ Invalid; cmp4.eq.and	p00,p32,r32,r0; (p01) mov	pr,r3,0x80 }
	{ (p32) cmp.lt.unc	p63,p09,r127,r36; Invalid; break.b	0x1000 }

l40000000000BFA70:
	{ ld1	r14,[r37]; nop.m	0x0; addl	r8,1,r0; }
	{ nop.m	0x0; sxt1	r14,r14; br.cond.sptk.few	40000000000BF8C0; }
40000000000BFA90 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000BFAA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000BFAB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; print_array_assignment: 40000000000BFAC0
;;   Called from:
;;     4000000000061C6C (in print_assignment)
;;     400000000010B42C (in show_var_attributes)
print_array_assignment proc
	{ alloc	r36,ar.pfs,0xA,0x0,0x6; adds	r14,0x8,r32; mov	r35,b3 }
	{ adds	r37,0x0,r1; nop.m	0x0; adds	r39,0x0,r33; }
	{ ld8	r38,[r14]; nop.i	0x0; br.call.sptk.many	b0,array_to_assign; }
	{ adds	r1,0x0,r37; cmp.eq	p07,p06,0x0,r8; adds	r41,0x0,r8 }
	{ adds	r34,0x0,r8; addl	r38,1,r0; addl	r39,-4732,r1; }
	{ ld8	r39,[r39]; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000BFB60; }

l40000000000BFB20:
	{ ld8	r40,[r32]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; adds	r38,0x0,r34; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r37; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000BFB50; br.ret	b0 }

l40000000000BFB60:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r33; addl	r38,1,r0 }
	{ ld8	r40,[r32]; (p07) addl	r41,-4748,r1; nop.i	0x0; }

l40000000000BFB7C:
	{ nop; (p05) nop; Invalid }

l40000000000BFB86:
	{ (p20) fwb; nop; (p17) br.call.sptk.few	b2,b0; }

l40000000000BFB8C:
	{ nop; Invalid; break.i	0x1000 }

l40000000000BFB96:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ Invalid; (p34) nop; Invalid }

;; print_assoc_assignment: 40000000000BFBC0
;;   Called from:
;;     4000000000061BDC (in print_assignment)
;;     400000000010B50C (in show_var_attributes)
print_assoc_assignment proc
	{ alloc	r36,ar.pfs,0xA,0x0,0x6; adds	r14,0x8,r32; mov	r35,b3 }
	{ adds	r37,0x0,r1; nop.m	0x0; adds	r39,0x0,r33; }
	{ ld8	r38,[r14]; nop.i	0x0; br.call.sptk.many	b0,assoc_to_assign; }
	{ adds	r1,0x0,r37; cmp.eq	p07,p06,0x0,r8; adds	r41,0x0,r8 }
	{ adds	r34,0x0,r8; addl	r38,1,r0; addl	r39,-4732,r1; }
	{ ld8	r39,[r39]; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000BFC60; }

l40000000000BFC20:
	{ ld8	r40,[r32]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; adds	r38,0x0,r34; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r37; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000BFC50; br.ret	b0 }

l40000000000BFC60:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r33; addl	r38,1,r0 }
	{ ld8	r40,[r32]; (p07) addl	r41,-4748,r1; nop.i	0x0; }

l40000000000BFC7C:
	{ nop; (p05) nop; Invalid }

l40000000000BFC86:
	{ (p20) fwb; nop; (p17) br.call.sptk.few	b2,b0; }

l40000000000BFC8C:
	{ nop; Invalid; break.i	0x1000 }

l40000000000BFC96:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ Invalid; (p34) nop; Invalid }

;; valid_array_reference: 40000000000BFCC0
;;   Called from:
;;     40000000000687EC (in bind_int_variable)
;;     40000000000A5FEC (in fn40000000000A5B80)
;;     40000000000A63CC (in fn40000000000A5B80)
;;     40000000000F0F0C (in fn40000000000F0900)
;;     4000000000100E1C (in mapfile_builtin)
;;     400000000010442C (in fn4000000000104400)
;;     400000000010797C (in read_builtin)
;;     40000000001079EC (in read_builtin)
;;     400000000010AA1C (in unset_builtin)
;;     40000000001160AC (in fn4000000000116080)
;;     4000000000116FCC (in printf_builtin)
valid_array_reference proc
	{ alloc	r35,ar.pfs,0x9,0x0,0x6; nop.m	0x0; mov	r34,b2 }
	{ adds	r36,0x0,r1; nop.m	0x0; adds	r38,0x0,r32; }
	{ addl	r39,91,r0; mov	r37,LC; br.call.sptk.many	b0,mbschr; }
	{ cmp.eq	p07,p06,0x0,r8; adds	r1,0x0,r36; nop.i	0x0 }
	{ adds	r33,0x0,r8; adds	r38,0x0,r32; (p07) br.cond.dpnt.few	40000000000BFD40; }

l40000000000BFD10:
	{ st1	[r0],r8; nop.i	0x0; br.call.sptk.many	b0,legal_identifier; }
	{ addl	r14,91,r0; adds	r1,0x0,r36; cmp4.eq	p06,p07,0x0,r8; }
	{ st1	[r14],r33; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000BFD70 }

l40000000000BFD40:
	{ adds	r8,0x0,r0; nop.m	0x0; nop.i	0x0 }

l40000000000BFD50:
	{ nop.m	0x0; mov.i	ar.pfs,r35; mov.i	LC,r37; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000BFD60; br.ret	b0; }

l40000000000BFD70:
	{ adds	r38,0x0,r33; nop.m	0x0; adds	r39,0x0,r0 }
	{ adds	r40,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,skipsubscript; }
	{ nop.m	0x0; sxt4	r14,r8; adds	r1,0x0,r36; }
	{ nop.m	0x0; add	r14,r33,r14; nop.i	0x0; }
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5D,r14; (p06) br.cond.dptk.few	40000000000BFD40; }

l40000000000BFDD0:
	{ adds	r15,0x1,r33; cmp4.eq	p06,p07,0x1,r8; nop.i	0x0 }
	{ adds	r14,0xFFFFFFFFFFFFFFFE,r8; adds	r33,0x2,r33; (p06) br.cond.dpnt.few	40000000000BFD40; }

l40000000000BFDF0:
	{ addp4	r14,r14,r0; cmp4.lt	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	40000000000BFD40; }

l40000000000BFE00:
	{ ld1	r15,[r15]; nop.m	0x0; mov.i	LC,r14; }
	{ nop.m	0x0; sxt1	r14,r15; cmp4.eq	p07,p06,0x9,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x20,r14; (p06) br.cond.dpnt.few	40000000000BFE90; }

l40000000000BFE30:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000BFE40:
	{ nop.m	0x0; nop.i	0x0; br.cloop.sptk.few	40000000000BFE60 }

l40000000000BFE50:
	{ nop.m	0x0; adds	r8,0x0,r0; br.cond.sptk.few	40000000000BFD50 }

l40000000000BFE60:
	{ nop.m	0x0; ld1	r14,[r33],1; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x9,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x20,r14; (p07) br.cond.dptk.few	40000000000BFE40 }

l40000000000BFE90:
	{ addl	r8,1,r0; mov.i	ar.pfs,r35; mov.i	LC,r37; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000BFEA0; br.ret	b0; }
40000000000BFEB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; array_expand_index: 40000000000BFEC0
;;   Called from:
;;     40000000000C023C (in unbind_array_element)
;;     40000000000C0C3C (in assign_compound_array_list)
;;     40000000000C115C (in assign_array_element)
;;     40000000000C189C (in fn40000000000C14C0)
array_expand_index proc
	{ alloc	r38,ar.pfs,0xB,0x0,0x8; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ adds	r39,0x0,r1; mov	r37,b5; sxt4	r35,r33; }
	{ adds	r40,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r34,0x0,r8; adds	r42,0xFFFFFFFFFFFFFFFF,r33; nop.i	0x0 }
	{ adds	r1,0x0,r39; adds	r41,0x0,r32; adds	r40,0x0,r8; }
	{ add	r35,r34,r35; sxt4	r42,r42; br.call.sptk.many	b0,fn400000000001B920; }
	{ adds	r35,0xFFFFFFFFFFFFFFFF,r35; nop.m	0x0; adds	r1,0x0,r39 }
	{ adds	r40,0x0,r34; nop.m	0x0; adds	r41,0x0,r0; }
	{ st1	[r0],r35; nop.i	0x0; br.call.sptk.many	b0,expand_arith_string; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r41,0x10,r12 }
	{ adds	r35,0x0,r8; adds	r40,0x0,r8; addl	r14,9036,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st8	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,evalexp; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r40,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r39; adds	r40,0x0,r34; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r15,0x10,r12; adds	r1,0x0,r39; adds	r8,0x0,r36; }
	{ nop.m	0x0; ld4	r14,[r15]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.spnt.few	40000000000C0010; }

l40000000000BFFF0:
	{ nop.m	0x0; mov.i	ar.pfs,r38; mov.spnt	b0,r37,40000000000BFFF0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000C0010:
	{ addl	r14,9044,r1; nop.m	0x0; addl	r15,1,r0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,top_level_cleanup; }
	{ adds	r1,0x0,r39; addl	r40,2,r0; br.call.sptk.many	b0,jump_to_top_level; }
	{ nop.m	0x0; break.f	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

;; unbind_array_element: 40000000000C0080
;;   Called from:
;;     40000000000C007C (in assign_array_var_from_string)
;;     400000000010AB7C (in unset_builtin)
unbind_array_element proc
	{ alloc	r36,ar.pfs,0xA,0x0,0x6; adds	r37,0x0,r1; mov	r35,b3 }
	{ nop.m	0x0; adds	r38,0x0,r33; nop.i	0x0; }
	{ adds	r39,0x0,r0; adds	r40,0x0,r0; br.call.sptk.many	b0,skipsubscript; }
	{ nop.m	0x0; sxt4	r14,r8; adds	r1,0x0,r37; }
	{ nop.m	0x0; add	r14,r33,r14; nop.i	0x0; }
	{ ld1	r15,[r14]; nop.m	0x0; sxt1	r15,r15; }
	{ cmp4.eq	p07,p06,0x5D,r15; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C02F0; }

l40000000000C00F0:
	{ cmp4.eq	p07,p06,0x0,r8; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000C02F0; }

l40000000000C0100:
	{ st1	[r0],r14; ld1	r14,[r33]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x2A,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x40,r14; (p06) br.cond.dptk.few	40000000000C0160 }

l40000000000C0130:
	{ adds	r14,0x1,r33; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000C02C0 }

l40000000000C0160:
	{ adds	r14,0x28,r32; nop.m	0x0; adds	r38,0x0,r33; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x6; (p06) br.cond.dptk.few	40000000000C0230 }

l40000000000C0190:
	{ adds	r39,0x0,r0; adds	r32,0x8,r32; br.call.sptk.many	b0,expand_assignment_string_to_string; }
	{ adds	r1,0x0,r37; cmp.eq	p06,p07,0x0,r8; nop.i	0x0 }
	{ adds	r34,0x0,r8; adds	r39,0x0,r8; (p06) br.cond.spnt.few	40000000000C0370; }

l40000000000C01C0:
	{ ld1	r14,[r8]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000C0370; }

l40000000000C01E0:
	{ ld8	r38,[r32]; nop.i	0x0; br.call.sptk.many	b0,assoc_remove; }
	{ adds	r1,0x0,r37; adds	r38,0x0,r34; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r37; adds	r8,0x0,r0 }

l40000000000C0210:
	{ nop.m	0x0; mov.i	ar.pfs,r36; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000C0220; br.ret	b0; }

l40000000000C0230:
	{ adds	r39,0x1,r8; adds	r32,0x8,r32; br.call.sptk.many	b0,array_expand_index; }
	{ cmp.lt	p07,p06,r8,r0; nop.m	0x0; adds	r1,0x0,r37 }
	{ adds	r39,0x0,r8; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000C0370; }

l40000000000C0260:
	{ ld8	r38,[r32]; nop.i	0x0; br.call.sptk.many	b0,array_remove; }
	{ cmp.eq	p06,p07,0x0,r8; nop.m	0x0; adds	r1,0x0,r37; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C0210; }

l40000000000C0286:
	{ chk.a.nc	r0,3FFFFFFFFF0C0A86; nop; (p32) nop }

l40000000000C0290:
	{ adds	r38,0x0,r8; nop.i	0x0; br.call.sptk.many	b0,array_dispose_element; }
	{ adds	r8,0x0,r0; adds	r1,0x0,r37; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000C02B0; br.ret	b0; }

l40000000000C02C0:
	{ ld8	r38,[r32]; nop.i	0x0; br.call.sptk.many	b0,unbind_variable; }
	{ adds	r8,0x0,r0; adds	r1,0x0,r37; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000C02E0; br.ret	b0 }

l40000000000C02F0:
	{ addl	r39,-4724,r1; ld8	r34,[r32]; adds	r38,0x0,r0 }
	{ nop.m	0x0; addl	r40,5,r0; nop.i	0x0; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r41,0x0,r8 }
	{ adds	r39,0x0,r34; adds	r40,0x0,r33; addl	r38,-4716,r1; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,builtin_error; }
	{ addl	r8,-1,r0; adds	r1,0x0,r37; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000C0360; br.ret	b0 }

l40000000000C0370:
	{ addl	r39,-4724,r1; adds	r38,0x0,r0; addl	r40,5,r0; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r37; adds	r40,0x0,r8; adds	r39,0x0,r33; }
	{ nop.m	0x0; addl	r38,-4708,r1; nop.i	0x0; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,builtin_error; }
	{ addl	r8,-1,r0; adds	r1,0x0,r37; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000C03D0; br.ret	b0; }
40000000000C03E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C03F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; assign_compound_array_list: 40000000000C0400
;;   Called from:
;;     40000000000998CC (in fn4000000000099100)
;;     40000000000999AC (in fn4000000000099100)
;;     40000000000C0D0C (in assign_array_var_from_string)
assign_compound_array_list proc
	{ alloc	r47,ar.pfs,0x17,0x0,0x12; adds	r14,0x28,r32; mov	r49,pr }
	{ adds	r48,0x0,r1; nop.m	0x0; cmp.eq	p16,p17,0x0,r32; }
	{ nop.m	0x0; mov	r46,b6; (p16) br.cond.dpnt.few	40000000000C0800; }

l40000000000C0430:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x2; (p07) adds	r15,0x8,r32; }

l40000000000C0450:
	{ (p07) ld8	r42,[r15]; nop.i	0x0; (p07) br.cond.dptk.few	40000000000C0470; }

l40000000000C0456:
	{ chk.a.nc	f0,3FFFFFFFFF0C0C56; nop; (p32) nop }

l40000000000C0460:
	{ adds	r42,0x0,r0; nop.m	0x0; nop.i	0x0 }

l40000000000C0470:
	{ nop.m	0x0; and	r14,0x40,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p09,p08,0x0,r14; (p08) br.cond.dptk.few	40000000000C08C0; }

l40000000000C0490:
	{ (p09) adds	r50,0x0,r0; nop.m	0x0; nop.i	0x0 }

l40000000000C0496:
	{ break.m	0x4000; nop; break.i	0x80000 }

l40000000000C04A0:
	{ nop.m	0x0; tbit.z	p09,p08,r34,0x0; (p09) br.cond.dptk.few	40000000000C0870 }

l40000000000C04B0:
	{ cmp.eq	p07,p06,0x0,r42; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000C0820; }

l40000000000C04C0:
	{ nop.m	0x0; (p06) adds	r14,0x8,r42; nop.i	0x0; }

l40000000000C04CC:
	{ padd2.uus	r0,r1,r0; Invalid; padd2	r0,r32,r0 }

l40000000000C04D6:
	{ chk.a.nc	r0,3FFFFFFFFF0C0CD6; (p18) nop; nop }

l40000000000C04E0:
	{ addl	r40,9036,r1; cmp.eq	p07,p06,0x0,r33; adds	r39,0x0,r0 }
	{ adds	r37,0x0,r0; adds	r38,0x28,r32; (p07) br.cond.dpnt.few	40000000000C0610; }

l40000000000C0500:
	{ adds	r43,0x20,r32; nop.m	0x0; or	r44,0x1,r34; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000C0520:
	{ adds	r14,0x8,r33; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r35,[r14],8; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x2; (p06) br.cond.dptk.few	40000000000C0570 }

l40000000000C0550:
	{ ld1	r14,[r35]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5B,r14; (p07) br.cond.dpnt.few	40000000000C06A0 }

l40000000000C0570:
	{ nop.m	0x0; ld4	r14,[r38]; adds	r54,0x0,r34 }
	{ adds	r53,0x0,r35; nop.i	0x0; tbit.z	p06,p07,r14,0x6 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000C0630; }

l40000000000C05A0:
	{ (p06) adds	r37,0x0,r36; nop.m	0x0; nop.i	0x0; }

l40000000000C05A6:
	{ break.m	0x4000; nop; break.i	0x80000 }

l40000000000C05B0:
	{ nop.m	0x0; adds	r50,0x0,r32; tbit.z	p06,p07,r14,0x4 }
	{ adds	r51,0x0,r37; adds	r52,0x0,r39; adds	r36,0x1,r36; }
	{ (p07) st8	[r0],r40; br.call.sptk.many	b0,fn40000000000BE480; nop.b	0x0; }

l40000000000C05D6:
	{ (p32) flushrs; nop; (p16) nop }
	{ break.m	0x4000; nop; break.i	0x80000 }

l40000000000C05F0:
	{ nop.m	0x0; ld8	r33,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	40000000000C0520; }

l40000000000C0610:
	{ nop.m	0x0; mov	pr,r49,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r47; }
	{ nop.m	0x0; mov.spnt	b0,r46,40000000000C0620; br.ret	b0 }

l40000000000C0630:
	{ addl	r51,-4684,r1; addl	r52,5,r0; adds	r50,0x0,r0; }
	{ ld8	r51,[r51]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r48; adds	r52,0x0,r35; nop.i	0x0 }
	{ adds	r50,0x0,r8; ld8	r51,[r32]; br.call.sptk.many	b0,report_error; }
	{ ld8	r33,[r33]; nop.m	0x0; adds	r1,0x0,r48; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	40000000000C0520 }

l40000000000C0690:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000C0610 }

l40000000000C06A0:
	{ (p17) ld4	r52,[r38]; adds	r51,0x0,r0; adds	r50,0x0,r35; }

l40000000000C06A6:
	{ Invalid; (p25) mov	pr,r35,0x1000; br.cond.sptk.few	40000000000D06A6 }
	{ (p26) nop; (p04) nop }

l40000000000C06BC:
	{ shladd	r0,r1,0x2,r0; zxt1	r0,r64; break.i	0x1000 }

l40000000000C06C6:
	{ break.m	0x4000; (p32) mov	pr,0x58FC7A8; break.i	0x80000 }
	{ (p20) add	r0,r8,r22; nop; break.b	0x80000 }
	{ Invalid; nop; (p48) nop }
	{ add	r0,r0,r1; (p07) nop; break.i	0x80000 }
	{ (p03) chk.a.clr	f93,3FFFFFFFFFD837F6; nop; break.b	0x80000 }

l40000000000C0710:
	{ nop.m	0x0; ld4	r14,[r38]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x6; (p07) br.cond.dptk.few	40000000000C0830 }

l40000000000C0730:
	{ adds	r51,0x0,r35; nop.m	0x0; adds	r50,0x0,r32 }
	{ adds	r52,0x0,r34; nop.m	0x0; br.call.sptk.many	b0,make_variable_value; }
	{ adds	r35,0x0,r8; ld8	r8,[r43]; adds	r1,0x0,r48 }
	{ adds	r52,0x0,r36; adds	r50,0x0,r32; adds	r53,0x0,r0; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r51,0x0,r35; (p06) br.cond.dpnt.few	40000000000C0A70; }

l40000000000C0780:
	{ nop.m	0x0; ld8	r14,[r8],8; nop.i	0x0; }
	{ ld8	r1,[r8]; mov.spnt	b6,r14,40000000000C0790; br.call.sptk.many	b0,b6; }
	{ adds	r1,0x0,r48; cmp.eq	p06,p07,0x0,r35; (p06) br.cond.dpnt.few	40000000000C07D0 }

l40000000000C07B0:
	{ nop.m	0x0; adds	r50,0x0,r35; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r48; nop.m	0x0; nop.i	0x0 }

l40000000000C07D0:
	{ ld8	r33,[r33]; nop.m	0x0; adds	r36,0x1,r36; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	40000000000C0520 }

l40000000000C07F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000C0610 }

l40000000000C0800:
	{ adds	r42,0x0,r0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000C0820:
	{ nop.m	0x0; adds	r36,0x0,r0; br.cond.sptk.few	40000000000C04E0 }

l40000000000C0830:
	{ adds	r50,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,err_badarraysub; }
	{ ld8	r33,[r33]; nop.m	0x0; adds	r1,0x0,r48; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	40000000000C0520 }

l40000000000C0860:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000C0610 }

l40000000000C0870:
	{ cmp.eq	p08,p09,0x0,r42; (p08) br.cond.dpnt.few	40000000000C0880; (p07) br.cond.dpnt.few	40000000000C0A50; }

l40000000000C087C:
	{ (p15) cmp.lt	p00,p17,r64,r33; czx1.r	r64,r65; mov	pr,r32,0x0 }

l40000000000C0880:
	{ cmp.eq	p06,p07,0x0,r50; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C0820; }

l40000000000C0890:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000C0820 }

l40000000000C08A0:
	{ adds	r36,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,assoc_flush; }
	{ nop.m	0x0; adds	r1,0x0,r48; br.cond.sptk.few	40000000000C04E0 }

l40000000000C08C0:
	{ nop.m	0x0; adds	r15,0x8,r32; nop.i	0x0; }
	{ ld8	r50,[r15]; nop.i	0x0; br.cond.sptk.few	40000000000C04A0 }

l40000000000C08E0:
	{ add	r45,r35,r41,0x1; ld1	r15,[r45]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x3D,r15; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C0960; }

l40000000000C0910:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2B,r15; (p06) br.cond.dptk.few	40000000000C0710 }

l40000000000C0920:
	{ adds	r14,0x2,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x3D,r14; (p07) br.cond.dptk.few	40000000000C0710; }

l40000000000C0950:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000C0960:
	{ adds	r50,0x1,r35; cmp4.eq	p07,p06,0x1,r8; (p07) br.cond.dpnt.few	40000000000C0830; }

l40000000000C0970:
	{ ld1	r14,[r50]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x2A,r14; nop.i	0x0; cmp4.eq.or.andcm	p07,p06,0x40,r14 }
	{ nop.m	0x0; ld4	r14,[r38]; (p06) br.cond.dptk.few	40000000000C09B0; }

l40000000000C09A0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2,r8; (p07) br.cond.dpnt.few	40000000000C0BA0; }

l40000000000C09B0:
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x2; adds	r53,0x2,r41 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000C0C30; }

l40000000000C09D0:
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x6; add	r53,r35,r53 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000C0AF0; }

l40000000000C09F0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2B,r15; (p07) br.cond.dpnt.few	40000000000C0AB0 }

l40000000000C0A00:
	{ adds	r54,0x0,r34; nop.m	0x0; nop.i	0x0; }

l40000000000C0A10:
	{ nop.m	0x0; adds	r50,0x0,r32; tbit.z	p06,p07,r14,0x4 }
	{ adds	r51,0x0,r37; adds	r52,0x0,r39; adds	r36,0x1,r36; }
	{ (p07) st8	[r0],r40; nop.i	0x0; br.call.sptk.many	b0,fn40000000000BE480; }

l40000000000C0A36:
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; nop; (p32) nop.b	0x2A00C }

l40000000000C0A50:
	{ adds	r50,0x0,r42; adds	r36,0x0,r0; br.call.sptk.many	b0,array_flush; }
	{ nop.m	0x0; adds	r1,0x0,r48; br.cond.sptk.few	40000000000C04E0 }

l40000000000C0A70:
	{ adds	r50,0x0,r42; nop.m	0x0; adds	r51,0x0,r36 }
	{ adds	r52,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,array_insert; }
	{ adds	r1,0x0,r48; cmp.eq	p06,p07,0x0,r35; (p07) br.cond.dptk.few	40000000000C07B0 }

l40000000000C0AA0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000C07D0 }

l40000000000C0AB0:
	{ ld1	r15,[r53]; nop.m	0x0; sxt1	r15,r15; }
	{ cmp4.eq	p07,p06,0x3D,r15; (p07) adds	r53,0x3,r41; (p07) adds	r54,0x0,r44; }

l40000000000C0ACC:
	{ Invalid; Invalid; Invalid }

l40000000000C0AD0:
	{ (p07) add	r53,r35,r53; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000C05B0; }

l40000000000C0AD6:
	{ chk.a.nc	f0,3FFFFFFFFF0C12D6; nop; break.i	0x80000 }

l40000000000C0AE0:
	{ nop.m	0x0; adds	r54,0x0,r34; br.cond.sptk.few	40000000000C0A10 }

l40000000000C0AF0:
	{ adds	r50,0x0,r35; nop.m	0x0; addl	r51,1,r0 }
	{ adds	r52,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,substring; }
	{ adds	r1,0x0,r48; nop.m	0x0; adds	r39,0x0,r8 }
	{ cmp.eq	p06,p07,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000C0830; }

l40000000000C0B30:
	{ ld1	r14,[r8]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000C0830 }

l40000000000C0B50:
	{ nop.m	0x0; ld1	r15,[r45]; adds	r53,0x2,r41 }
	{ nop.m	0x0; ld4	r14,[r38]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; add	r53,r35,r53; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2B,r15; (p06) br.cond.dptk.few	40000000000C0A00 }

l40000000000C0B90:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000C0AB0; }

l40000000000C0BA0:
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x6; addl	r52,5,r0 }
	{ adds	r50,0x0,r0; (p07) addl	r51,-4700,r1; nop.i	0x0; }

l40000000000C0BBC:
	{ nop; (p06) nop; Invalid }

l40000000000C0BC6:
	{ (p25) fwb; nop; (p49) br.call.sptk.few	b4,b0; }

l40000000000C0BCC:
	{ nop; Invalid; break.i	0x1000 }

l40000000000C0BD6:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; (p25) nop; (p48) nop }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ add	r0,r0,r1; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD43E26; nop; break.b	0x80000 }

l40000000000C0C20:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000C0610 }

l40000000000C0C30:
	{ adds	r51,0x0,r8; nop.i	0x0; br.call.sptk.many	b0,array_expand_index; }
	{ adds	r1,0x0,r48; adds	r37,0x0,r8; nop.i	0x0 }
	{ cmp.lt	p07,p06,r8,r0; adds	r53,0x2,r41; (p07) br.cond.dpnt.few	40000000000C0830; }

l40000000000C0C60:
	{ ld1	r15,[r45]; adds	r36,0x0,r8; add	r53,r35,r53 }
	{ ld4	r14,[r38]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2B,r15; (p06) br.cond.dptk.few	40000000000C0A00 }

l40000000000C0C90:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000C0AB0; }
40000000000C0CA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C0CB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; assign_array_var_from_string: 40000000000C0CC0
;;   Called from:
;;     40000000000C0DFC (in assign_array_from_string)
;;     40000000000F205C (in fn40000000000F0900)
assign_array_var_from_string proc
	{ alloc	r37,ar.pfs,0xA,0x0,0x7; cmp.eq	p07,p06,0x0,r33; mov	r36,b4 }
	{ adds	r38,0x0,r1; adds	r39,0x0,r32; (p07) br.cond.dpnt.few	40000000000C0D50; }

l40000000000C0CE0:
	{ adds	r40,0x0,r33; adds	r41,0x0,r34; br.call.sptk.many	b0,expand_compound_array_assignment; }
	{ adds	r1,0x0,r38; adds	r35,0x0,r8; adds	r39,0x0,r32 }
	{ adds	r40,0x0,r8; adds	r41,0x0,r34; br.call.sptk.many	b0,assign_compound_array_list; }
	{ cmp.eq	p06,p07,0x0,r35; nop.m	0x0; adds	r1,0x0,r38 }
	{ adds	r39,0x0,r35; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000C0D50; }

l40000000000C0D30:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,dispose_words; }
	{ adds	r1,0x0,r38; nop.m	0x0; nop.i	0x0 }

l40000000000C0D50:
	{ adds	r8,0x0,r32; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000C0D60; br.ret	b0; }
40000000000C0D70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; assign_array_from_string: 40000000000C0D80
;;   Called from:
;;     400000000009973C (in fn4000000000099100)
;;     400000000009973C (in fn4000000000099100)
assign_array_from_string proc
	{ alloc	r36,ar.pfs,0x8,0x0,0x6; nop.m	0x0; tbit.z	p06,p07,r34,0x2 }
	{ adds	r37,0x0,r1; nop.m	0x0; adds	r38,0x0,r32; }
	{ nop.m	0x0; mov	r35,b3; (p06) addl	r39,1,r0; }

l40000000000C0DB0:
	{ (p07) addl	r39,3,r0; nop.i	0x0; br.call.sptk.many	b0,find_or_make_array_variable; }

l40000000000C0DB6:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; nop; nop }
	{ chk.a.nc	r35,3FFFFFFFFF1A0DE6; mov	pr,0x4300003; break.i	0x80000 }

l40000000000C0DE0:
	{ nop.m	0x0; mov.i	ar.pfs,r36; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x3,0x0,0x0; nop.i	0x0; br.cond.sptk.many	assign_array_var_from_string }

l40000000000C0E00:
	{ nop.m	0x0; mov.i	ar.pfs,r36; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000C0E10; br.ret	b0; }
40000000000C0E20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C0E30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; array_variable_name: 40000000000C0E40
;;   Called from:
;;     400000000007201C (in fn4000000000071E00)
;;     400000000007201C (in fn4000000000071FC0)
;;     40000000000757FC (in fn4000000000074880)
;;     40000000000C107C (in assign_array_element)
;;     40000000000C13EC (in array_variable_part)
array_variable_name proc
	{ alloc	r39,ar.pfs,0xC,0x0,0x9; nop.m	0x0; mov	r38,b6 }
	{ adds	r40,0x0,r1; nop.m	0x0; adds	r41,0x0,r32; }
	{ addl	r42,91,r0; nop.i	0x0; br.call.sptk.many	b0,mbschr; }
	{ cmp.eq	p07,p06,0x0,r8; sub	r42,r8,r32; adds	r1,0x0,r40 }
	{ adds	r35,0x0,r8; adds	r41,0x0,r32; (p07) br.cond.dpnt.few	40000000000C0F60; }

l40000000000C0E90:
	{ adds	r37,0x0,r42; adds	r43,0x0,r0; br.call.sptk.many	b0,skipsubscript; }
	{ adds	r14,0x1,r37; nop.m	0x0; adds	r1,0x0,r40 }
	{ adds	r41,0x0,r32; nop.m	0x0; adds	r36,0x0,r8; }
	{ cmp4.lt	p07,p06,r14,r8; sxt4	r14,r8; (p06) br.cond.dpnt.few	40000000000C0F00; }

l40000000000C0ED0:
	{ add	r14,r32,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x5D,r14; (p06) br.cond.dpnt.few	40000000000C0F90 }

l40000000000C0F00:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,err_badarraysub; }
	{ cmp.eq	p06,p07,0x0,r33; adds	r1,0x0,r40; nop.i	0x0 }
	{ (p07) st8	[r35],r33; cmp.eq	p06,p07,0x0,r34; (p06) br.cond.dpnt.few	40000000000C0F40; }

l40000000000C0F26:
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD44946; nop; nop }

l40000000000C0F30:
	{ st4	[r0],r34; nop.m	0x0; nop.i	0x0 }

l40000000000C0F40:
	{ adds	r8,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000C0F50; br.ret	b0 }

l40000000000C0F60:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r33; nop.i	0x0; }
	{ (p07) st8	[r0],r33; cmp.eq	p07,p06,0x0,r34; (p07) br.cond.dpnt.few	40000000000C0F40; }

l40000000000C0F76:
	{ (p03) chk.a.clr	f0,3FFFFFFFFFD44196; nop; br.call.spnt.few	b0,b0 }

l40000000000C0F80:
	{ st4	[r0],r34; nop.i	0x0; br.cond.sptk.few	40000000000C0F40 }

l40000000000C0F90:
	{ st1	[r0],r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r40; adds	r41,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r41,0x0,r8 }
	{ adds	r42,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ addl	r14,91,r0; cmp.eq	p06,p07,0x0,r33; nop.b	0x0 }
	{ adds	r1,0x0,r40; nop.m	0x0; mov.i	ar.pfs,r39; }
	{ st1	[r35],r1,1; nop.m	0x0; mov.spnt	b0,r38,40000000000C0FF0; }
	{ (p07) st8	[r35],r33; cmp.eq	p06,p07,0x0,r34; (p07) sub	r36,r36,r37; }

l40000000000C1006:
	{ (p03) chk.a.clr	f0,3FFFFFFFFFD44A26; (p18) cmp4.eq.or.andcm	p36,p00,r37,r5; (p01) nop }

l40000000000C1010:
	{ (p07) st4	[r36],r34; nop.i	0x0; br.ret	b0; }

l40000000000C1016:
	{ break.m	0x4000; (p34) nop; break.i	0x80000 }
40000000000C1020 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C1030 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; assign_array_element: 40000000000C1040
;;   Called from:
;;     400000000006887C (in bind_int_variable)
;;     400000000009953C (in fn4000000000099100)
;;     40000000000A601C (in fn40000000000A5B80)
;;     40000000000F20CC (in fn40000000000F0900)
;;     40000000001044FC (in fn4000000000104400)
;;     40000000001160DC (in fn4000000000116080)
assign_array_element proc
	{ alloc	r39,ar.pfs,0xE,0x0,0x9; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r38,b6 }
	{ adds	r40,0x0,r1; nop.m	0x0; adds	r41,0x0,r32; }
	{ adds	r36,0x18,r12; nop.m	0x0; adds	r42,0x10,r12; }
	{ adds	r43,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,array_variable_name; }
	{ adds	r14,0x10,r12; adds	r1,0x0,r40; nop.i	0x0 }
	{ cmp.eq	p06,p07,0x0,r8; adds	r35,0x0,r8; (p06) br.cond.dpnt.few	40000000000C1390; }

l40000000000C10A0:
	{ ld8	r15,[r14]; ld1	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x2A,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x40,r14; (p07) br.cond.dptk.few	40000000000C11E0 }

l40000000000C10D0:
	{ ld4	r14,[r36]; nop.m	0x0; adds	r41,0x0,r35; }
	{ cmp4.lt	p06,p07,0x1,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000C1220; }

l40000000000C10F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r14,0x28,r8; adds	r1,0x0,r40; nop.i	0x0 }
	{ cmp.eq	p06,p07,0x0,r8; adds	r37,0x0,r8; (p06) br.cond.dpnt.few	40000000000C1140; }

l40000000000C1120:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x6; (p07) br.cond.dpnt.few	40000000000C1280 }

l40000000000C1140:
	{ adds	r14,0x10,r12; ld4	r42,[r36]; nop.i	0x0; }
	{ ld8	r41,[r14]; nop.i	0x0; br.call.sptk.many	b0,array_expand_index; }
	{ cmp.lt	p07,p06,r8,r0; adds	r1,0x0,r40; adds	r41,0x0,r35 }
	{ adds	r42,0x0,r8; adds	r43,0x0,r33; (p07) br.cond.dpnt.few	40000000000C1230; }

l40000000000C1180:
	{ adds	r44,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,bind_array_variable; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r41,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r40; nop.m	0x0; nop.i	0x0 }

l40000000000C11C0:
	{ adds	r8,0x0,r36; mov.i	ar.pfs,r39; mov.spnt	b0,r38,40000000000C11C0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000C11E0:
	{ adds	r15,0x1,r15; ld1	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x5D,r14; (p07) br.cond.dptk.few	40000000000C10D0; }

l40000000000C1210:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000C1220:
	{ adds	r41,0x0,r35; nop.m	0x0; nop.i	0x0 }

l40000000000C1230:
	{ adds	r36,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r40; adds	r41,0x0,r32; br.call.sptk.many	b0,err_badarraysub; }
	{ adds	r8,0x0,r36; adds	r1,0x0,r40; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000C1260; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l40000000000C1280:
	{ ld4	r16,[r36]; adds	r42,0x0,r0; sxt4	r15,r16 }
	{ adds	r16,0x10,r12; ld8	r14,[r16]; nop.i	0x0 }
	{ ld8.a	r41,[r16]; add	r14,r14,r15; nop.i	0x0; }
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r14; st1	[r0],r14; nop.i	0x0; }
	{ ld8.c.clr	r41,[r16]; nop.i	0x0; br.call.sptk.many	b0,expand_assignment_string_to_string; }
	{ ld4	r15,[r36]; adds	r16,0x10,r12; adds	r1,0x0,r40 }
	{ cmp.eq	p06,p07,0x0,r8; adds	r41,0x0,r37; adds	r42,0x0,r35; }
	{ nop.m	0x0; ld8	r14,[r16]; sxt4	r15,r15 }
	{ adds	r43,0x0,r8; adds	r44,0x0,r33; adds	r45,0x0,r34; }
	{ add	r14,r14,r15; addl	r15,93,r0; adds	r14,0xFFFFFFFFFFFFFFFF,r14; }
	{ st1	[r15],r14; nop.i	0x0; (p06) br.cond.spnt.few	40000000000C1220; }

l40000000000C1330:
	{ ld1	r14,[r8]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000C1220; }

l40000000000C1350:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,bind_assoc_variable; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r41,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r40; br.cond.sptk.few	40000000000C11C0 }

l40000000000C1390:
	{ nop.m	0x0; adds	r36,0x0,r0; nop.i	0x0; }
	{ adds	r8,0x0,r36; mov.i	ar.pfs,r39; mov.spnt	b0,r38,40000000000C13A0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

;; array_variable_part: 40000000000C13C0
;;   Called from:
;;     400000000006881C (in bind_int_variable)
;;     4000000000074DDC (in fn4000000000074880)
;;     40000000000C14FC (in fn40000000000C14C0)
;;     40000000000C1E6C (in array_keys)
array_variable_part proc
	{ alloc	r38,ar.pfs,0xB,0x0,0x8; adds	r39,0x0,r1; mov	r37,b5 }
	{ adds	r41,0x0,r33; adds	r42,0x0,r34; adds	r40,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,array_variable_name; }
	{ cmp.eq	p07,p06,0x0,r8; adds	r1,0x0,r39; nop.i	0x0 }
	{ adds	r36,0x0,r8; adds	r40,0x0,r8; (p07) br.cond.dpnt.few	40000000000C14A0; }

l40000000000C1410:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r40,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r14,0x28,r35; nop.m	0x0; adds	r1,0x0,r39 }
	{ cmp.eq	p06,p07,0x0,r35; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000C14A0; }

l40000000000C1460:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0xC; (p06) br.cond.dptk.few	40000000000C14A0 }

l40000000000C1480:
	{ adds	r8,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000C1490; br.ret	b0 }

l40000000000C14A0:
	{ adds	r35,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ adds	r8,0x0,r35; mov.spnt	b0,r37,40000000000C14B0; br.ret	b0; }

;; fn40000000000C14C0: 40000000000C14C0
;;   Called from:
;;     40000000000C1D9C (in array_value)
;;     40000000000C1DFC (in get_array_value)
fn40000000000C14C0 proc
	{ alloc	r42,ar.pfs,0x10,0x0,0xD; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r44,pr }
	{ adds	r43,0x0,r1; nop.m	0x0; adds	r45,0x0,r32; }
	{ adds	r38,0x18,r12; mov	r41,b1; adds	r46,0x10,r12; }
	{ adds	r47,0x0,r38; nop.i	0x0; br.call.sptk.many	b0,array_variable_part; }
	{ ld4	r46,[r38]; nop.m	0x0; adds	r14,0x10,r12 }
	{ adds	r1,0x0,r43; nop.m	0x0; adds	r37,0x0,r8; }
	{ cmp4.eq	p07,p06,0x0,r46; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000C1940; }

l40000000000C1530:
	{ ld8	r45,[r14]; ld1	r15,[r45]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ cmp4.eq	p08,p09,0x2A,r15; cmp4.eq	p06,p07,0x40,r15; (p08) addl	r14,1,r0; }

l40000000000C1560:
	{ nop.m	0x0; (p09) adds	r14,0x0,r0; nop.i	0x0; }

l40000000000C156C:
	{ cmp.eq	p00,p17,r1,r0; (p01) cmp.lt.unc	p00,p16,r3,r64; (p08) mov	pr,r99,0xE580 }
	{ (p09) cmp.lt	p00,p09,r0,r33; cmp.lt.unc	p32,p28,r104,r65; zxt1	r42,r64 }

l40000000000C1580:
	{ cmp.eq	p06,p07,0x0,r35; adds	r14,0x28,r37; cmp.eq	p16,p17,0x0,r37; }
	{ (p07) st4	[r0],r35; nop.i	0x0; (p16) br.cond.dpnt.few	40000000000C15C0; }

l40000000000C1596:
	{ nop; nop; (p48) nop }

l40000000000C15A0:
	{ ld8	r15,[r14]; and	r15,0x44,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x40,r15; (p06) br.cond.dpnt.few	40000000000C19F0; }

l40000000000C15C0:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x2; (p06) br.cond.dpnt.few	40000000000C1890; }

l40000000000C15D0:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r36; nop.i	0x0 }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	40000000000C1890; (p16) br.cond.dpnt.few	40000000000C1940; }

l40000000000C15EC:
	{ (p27) cmp4.eq.or.andcm	p00,p08,r64,r33; Invalid; break.i	0x1000 }

l40000000000C15F0:
	{ (p06) ld8	r39,[r36]; nop.m	0x0; nop.i	0x0 }

l40000000000C15F6:
	{ break.m	0x4000; nop; (p32) nop }

l40000000000C1600:
	{ adds	r14,0x8,r37; nop.m	0x0; adds	r37,0x28,r37; }
	{ nop.m	0x0; ld8	r38,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r38; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C1940; }

l40000000000C1630:
	{ ld8	r14,[r37]; and	r14,0x44,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000C1970; }

l40000000000C1650:
	{ cmp.eq	p06,p07,0x0,r39; adds	r8,0x0,r38; (p07) br.cond.dpnt.few	40000000000C1940; }

l40000000000C1660:
	{ nop.m	0x0; mov	pr,r44,0xFFFFFFFFFFFFFFFE; nop.i	0x0; }
	{ nop.m	0x0; mov.i	ar.pfs,r42; mov.spnt	b0,r41,40000000000C1670 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000C1690:
	{ adds	r14,0x1,r45; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5D,r14; (p06) br.cond.dptk.few	40000000000C1580; }

l40000000000C16C0:
	{ cmp.eq	p06,p07,0x0,r35; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C1700; }

l40000000000C16D0:
	{ cmp4.eq	p06,p07,0x0,r15; (p06) addl	r15,2,r0; nop.i	0x0; }

l40000000000C16DC:
	{ nop; cmp4.eq.or.andcm	p00,p32,r32,r0; zxt4	r0,r0 }

l40000000000C16EC:
	{ nop; Invalid; break.i	0x1000 }
	{ break.m	0x80; cmp.eq	p00,p00,r32,r0; cmp.lt.unc	p00,p10,r72,r1 }

l40000000000C1700:
	{ nop.m	0x0; tbit.z	p07,p06,r34,0x0; adds	r14,0x8,r37 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000C1C90; }

l40000000000C1720:
	{ cmp.eq	p06,p07,0x0,r37; adds	r37,0x28,r37; (p06) br.cond.dpnt.few	40000000000C1940; }

l40000000000C1730:
	{ nop.m	0x0; ld8	r45,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r45; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C1940; }

l40000000000C1750:
	{ ld8	r14,[r37]; and	r14,0x44,r14; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000C1C50; }

l40000000000C1770:
	{ nop.m	0x0; ld4	r14,[r37]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x6; (p06) br.cond.dptk.few	40000000000C1900 }

l40000000000C1790:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,assoc_to_word_list; }
	{ nop.m	0x0; adds	r37,0x0,r8; adds	r1,0x0,r43 }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	40000000000C1940; }

l40000000000C17C0:
	{ adds	r15,0x10,r12; nop.m	0x0; adds	r45,0x0,r37; }
	{ ld8	r14,[r15]; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2A,r14; (p06) br.cond.dptk.few	40000000000C1820 }

l40000000000C1800:
	{ nop.m	0x0; and	r14,0x3,r33; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000C1BE0 }

l40000000000C1820:
	{ adds	r46,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,string_list_dollar_at; }
	{ adds	r1,0x0,r43; nop.m	0x0; adds	r38,0x0,r8 }
	{ adds	r45,0x0,r37; nop.m	0x0; br.call.sptk.many	b0,dispose_words; }
	{ adds	r1,0x0,r43; nop.m	0x0; nop.i	0x0 }

l40000000000C1860:
	{ adds	r8,0x0,r38; mov	pr,r44,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r42; }
	{ nop.m	0x0; mov.spnt	b0,r41,40000000000C1870; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0; }

l40000000000C1890:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,array_expand_index; }
	{ cmp.lt	p07,p06,r8,r0; nop.m	0x0; adds	r1,0x0,r43 }
	{ adds	r39,0x0,r8; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000C1B50; }

l40000000000C18C0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r36; nop.i	0x0; }
	{ (p07) st8	[r39],r36; nop.m	0x0; nop.i	0x0 }

l40000000000C18D6:
	{ break.m	0x4000; nop; break.i	0x80000 }

l40000000000C18E0:
	{ nop.m	0x0; nop.i	0x0; (p17) br.cond.dptk.few	40000000000C1600 }

l40000000000C18F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000C1940 }

l40000000000C1900:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,array_to_word_list; }
	{ nop.m	0x0; adds	r1,0x0,r43; adds	r37,0x0,r8 }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	40000000000C17C0; }

l40000000000C1930:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000C1940:
	{ adds	r38,0x0,r0; adds	r8,0x0,r38; mov	pr,r44,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r42; mov.spnt	b0,r41,40000000000C1950 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000C1970:
	{ nop.m	0x0; ld4	r14,[r37]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x6; (p06) br.cond.dptk.few	40000000000C1B00 }

l40000000000C1990:
	{ adds	r46,0x0,r40; adds	r45,0x0,r38; br.call.sptk.many	b0,assoc_reference; }
	{ adds	r1,0x0,r43; nop.m	0x0; adds	r38,0x0,r8 }
	{ adds	r45,0x0,r40; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r8,0x0,r38; adds	r1,0x0,r43; mov	pr,r44,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r42; mov.spnt	b0,r41,40000000000C19D0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000C19F0:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x6; (p06) br.cond.dptk.few	40000000000C1600 }

l40000000000C1A10:
	{ nop.m	0x0; sxt4	r17,r46; adds	r46,0x0,r0; }
	{ nop.m	0x0; add	r16,r45,r17; nop.i	0x0; }
	{ adds	r16,0xFFFFFFFFFFFFFFFF,r16; st1	[r0],r16; adds	r16,0x10,r12; }
	{ ld8	r45,[r16]; nop.i	0x0; br.call.sptk.many	b0,expand_assignment_string_to_string; }
	{ ld4	r15,[r38]; adds	r16,0x10,r12; adds	r1,0x0,r43 }
	{ cmp.eq	p06,p07,0x0,r8; adds	r40,0x0,r8; sxt4	r15,r15 }
	{ ld8	r14,[r16]; add	r14,r14,r15; addl	r15,93,r0; }
	{ nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; }
	{ st1	[r15],r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C1AC0; }

l40000000000C1AA0:
	{ ld1	r14,[r8]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000C1600 }

l40000000000C1AC0:
	{ ld8	r45,[r37]; adds	r38,0x0,r0; br.call.sptk.many	b0,err_badarraysub; }
	{ adds	r8,0x0,r38; adds	r1,0x0,r43; mov	pr,r44,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r42; mov.spnt	b0,r41,40000000000C1AE0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000000C1B00:
	{ adds	r45,0x0,r38; adds	r46,0x0,r39; br.call.sptk.many	b0,array_reference; }
	{ adds	r38,0x0,r8; nop.m	0x0; adds	r1,0x0,r43; }
	{ adds	r8,0x0,r38; mov	pr,r44,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r42; }
	{ nop.m	0x0; mov.spnt	b0,r41,40000000000C1B30; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l40000000000C1B50:
	{ adds	r14,0x28,r37; nop.i	0x0; (p16) br.cond.dpnt.few	40000000000C1CD0; }

l40000000000C1B60:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x2; (p06) br.cond.dptk.few	40000000000C1AC0 }

l40000000000C1B80:
	{ adds	r14,0x8,r37; ld8	r14,[r14]; nop.i	0x0; }
	{ adds	r14,0x8,r14; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; add	r39,r8,r14,0x1; nop.i	0x0; }
	{ cmp.lt	p07,p06,r39,r0; nop.i	0x0; (p07) br.cond.spnt.few	40000000000C1AC0; }

l40000000000C1BC0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r36; nop.i	0x0; }
	{ (p07) st8	[r39],r36; nop.i	0x0; br.cond.sptk.few	40000000000C18E0 }

l40000000000C1BD6:
	{ break.m	0x4000; nop; break.i	0x80000 }

l40000000000C1BE0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,string_list_dollar_star; }
	{ adds	r1,0x0,r43; nop.m	0x0; adds	r39,0x0,r8 }
	{ adds	r45,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,quote_string; }
	{ adds	r1,0x0,r43; nop.m	0x0; adds	r38,0x0,r8 }
	{ adds	r45,0x0,r39; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r43; adds	r45,0x0,r37; br.call.sptk.many	b0,dispose_words; }
	{ nop.m	0x0; adds	r1,0x0,r43; br.cond.sptk.few	40000000000C1860 }

l40000000000C1C50:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,make_word; }
	{ adds	r1,0x0,r43; nop.m	0x0; adds	r45,0x0,r8 }
	{ adds	r46,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,make_word_list; }
	{ adds	r1,0x0,r43; adds	r37,0x0,r8; br.cond.sptk.few	40000000000C17C0 }

l40000000000C1C90:
	{ adds	r45,0x0,r32; adds	r38,0x0,r0; br.call.sptk.many	b0,err_badarraysub; }
	{ adds	r8,0x0,r38; adds	r1,0x0,r43; mov	pr,r44,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r42; mov.spnt	b0,r41,40000000000C1CB0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000000C1CD0:
	{ adds	r16,0x10,r12; adds	r45,0x0,r32; adds	r38,0x0,r0; }
	{ ld8	r14,[r16]; adds	r14,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; }
	{ st1	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,err_badarraysub; }
	{ adds	r15,0x10,r12; adds	r8,0x0,r38; adds	r1,0x0,r43; }
	{ ld8	r14,[r15]; addl	r15,91,r0; adds	r14,0xFFFFFFFFFFFFFFFF,r14; }
	{ st1	[r15],r14; mov	pr,r44,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r42; }
	{ nop.m	0x0; mov.spnt	b0,r41,40000000000C1D30; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0; }
40000000000C1D50 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C1D60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C1D70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; array_value: 40000000000C1D80
array_value proc
	{ nop.m	0x0; or	r34,0x1,r34; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x5,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000C14C0; }
40000000000C1DA0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000C1DB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; get_array_value: 40000000000C1DC0
;;   Called from:
;;     400000000007533C (in fn4000000000074880)
get_array_value proc
	{ alloc	r16,ar.pfs,0x5,0x0,0x5; nop.m	0x0; adds	r15,0x0,r33 }
	{ adds	r14,0x0,r34; nop.m	0x0; adds	r36,0x0,r35; }
	{ adds	r33,0x0,r0; adds	r34,0x0,r15; adds	r35,0x0,r14; }
	{ alloc	r2,ar.pfs,0x5,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000C14C0; }
40000000000C1E00 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000C1E10 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C1E20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C1E30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; array_keys: 40000000000C1E40
array_keys proc
	{ alloc	r38,ar.pfs,0xB,0x0,0x8; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r37,b5 }
	{ adds	r39,0x0,r1; nop.m	0x0; adds	r40,0x0,r32; }
	{ adds	r41,0x10,r12; adds	r42,0x18,r12; br.call.sptk.many	b0,array_variable_part; }
	{ adds	r14,0x10,r12; nop.m	0x0; adds	r1,0x0,r39 }
	{ cmp.eq	p07,p06,0x0,r8; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000C2050; }

l40000000000C1E90:
	{ ld8	r15,[r14]; ld1	r14,[r15]; adds	r15,0x1,r15; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x2A,r14; }
	{ cmp4.eq.or.andcm	p07,p06,0x40,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C2050; }

l40000000000C1EC0:
	{ ld1	r14,[r15]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x5D,r14; nop.m	0x0; adds	r14,0x8,r8 }
	{ adds	r8,0x28,r8; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000C2050; }

l40000000000C1EF0:
	{ nop.m	0x0; ld8	r40,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r40; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C2050; }

l40000000000C1F10:
	{ nop.m	0x0; ld4	r14,[r8]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0xC; (p06) br.cond.dpnt.few	40000000000C2050; }

l40000000000C1F30:
	{ ld8	r15,[r8]; and	r15,0x44,r15; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r15; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000C20A0; }

l40000000000C1F50:
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x6; (p06) br.cond.dptk.few	40000000000C2080 }

l40000000000C1F60:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,assoc_keys_to_word_list; }
	{ nop.m	0x0; adds	r1,0x0,r39; adds	r34,0x0,r8; }

l40000000000C1F80:
	{ adds	r15,0x10,r12; nop.m	0x0; cmp.eq	p06,p07,0x0,r34 }
	{ adds	r40,0x0,r34; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000C2050; }

l40000000000C1FA0:
	{ ld8	r14,[r15]; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2A,r14; (p06) br.cond.dptk.few	40000000000C1FF0 }

l40000000000C1FD0:
	{ nop.m	0x0; and	r14,0x3,r33; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000C20F0 }

l40000000000C1FF0:
	{ adds	r41,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,string_list_dollar_at; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r40,0x0,r34; nop.m	0x0; br.call.sptk.many	b0,dispose_words; }
	{ adds	r1,0x0,r39; nop.m	0x0; nop.i	0x0 }

l40000000000C2030:
	{ adds	r8,0x0,r35; mov.i	ar.pfs,r38; mov.spnt	b0,r37,40000000000C2030 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000C2050:
	{ nop.m	0x0; adds	r35,0x0,r0; nop.i	0x0; }
	{ adds	r8,0x0,r35; mov.i	ar.pfs,r38; mov.spnt	b0,r37,40000000000C2060 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000000C2080:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,array_keys_to_word_list; }
	{ adds	r1,0x0,r39; adds	r34,0x0,r8; br.cond.sptk.few	40000000000C1F80; }

l40000000000C20A0:
	{ nop.m	0x0; addl	r40,-4676,r1; nop.i	0x0; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,make_word; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r40,0x0,r8 }
	{ adds	r41,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,make_word_list; }
	{ adds	r1,0x0,r39; adds	r34,0x0,r8; br.cond.sptk.few	40000000000C1F80 }

l40000000000C20F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,string_list_dollar_star; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r40,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,quote_string; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r40,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r39; adds	r40,0x0,r34; br.call.sptk.many	b0,dispose_words; }
	{ nop.m	0x0; adds	r1,0x0,r39; br.cond.sptk.few	40000000000C2030; }
40000000000C2160 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000C2170 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; fn40000000000C2180: 40000000000C2180
;;   Called from:
;;     40000000000C381C (in assoc_to_word_list)
;;     40000000000C3A9C (in assoc_keys_to_word_list)
fn40000000000C2180 proc
	{ alloc	r40,ar.pfs,0xD,0x0,0xB; adds	r14,0xC,r32; mov	r42,pr }
	{ adds	r38,0x8,r32; cmp.eq	p07,p06,0x0,r32; adds	r41,0x0,r1; }
	{ adds	r37,0x0,r0; mov	r39,b7; adds	r36,0x0,r0 }
	{ adds	r35,0x0,r0; cmp4.eq	p17,p16,0x0,r33; (p07) br.cond.dpnt.few	40000000000C2340; }

l40000000000C21C0:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C2340; }

l40000000000C21E0:
	{ nop.m	0x0; ld4	r14,[r38]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,0x0,r14; (p06) br.cond.dpnt.few	40000000000C2340; }

l40000000000C2200:
	{ ld8	r14,[r32]; add	r14,r14,r37; nop.i	0x0; }
	{ nop.m	0x0; ld8	r34,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r34; (p06) br.cond.dpnt.few	40000000000C22B0; }

l40000000000C2230:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000C2240:
	{ adds	r14,0x8,r34; nop.m	0x0; adds	r15,0x10,r34; }
	{ nop.m	0x0; (p17) ld8	r43,[r15]; nop.i	0x0; }

l40000000000C225C:
	{ ldfps	f0,f1,[r0],8; Invalid; break.i	0x1000 }

l40000000000C2266:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ add	r0,r0,r1; (p21) nop; nop }
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ Invalid; (p17) nop; break.b	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD454C6; nop; nop.b	0x24029 }

l40000000000C22B0:
	{ adds	r36,0x1,r36; ld4	r14,[r38]; adds	r37,0x8,r37; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r36,r14; (p06) br.cond.dptk.few	40000000000C2200; }

l40000000000C22D0:
	{ cmp.eq	p06,p07,0x0,r35; adds	r43,0x0,r35; (p06) br.cond.dpnt.few	40000000000C2340; }

l40000000000C22E0:
	{ nop.m	0x0; ld8	r14,[r35]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C2320; }

l40000000000C2300:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,list_reverse; }
	{ nop.m	0x0; adds	r1,0x0,r41; adds	r35,0x0,r8; }

l40000000000C2320:
	{ adds	r8,0x0,r35; mov	pr,r42,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000C2330; br.ret	b0 }

l40000000000C2340:
	{ adds	r35,0x0,r0; nop.m	0x0; mov	pr,r42,0xFFFFFFFFFFFFFFFE; }
	{ adds	r8,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000C2360; br.ret	b0; }
40000000000C2370 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; assoc_dispose: 40000000000C2380
;;   Called from:
;;     400000000006108C (in fn4000000000060F80)
;;     400000000006BD2C (in makunbound)
;;     40000000000C40AC (in assoc_modcase)
;;     40000000000C414C (in assoc_modcase)
;;     40000000000C44FC (in assoc_patsub)
;;     40000000000C459C (in assoc_patsub)
assoc_dispose proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x4; cmp.eq	p06,p07,0x0,r32; mov	r33,b1 }
	{ adds	r35,0x0,r1; adds	r36,0x0,r32; (p06) br.cond.dpnt.few	40000000000C23E0; }

l40000000000C23A0:
	{ adds	r37,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,hash_flush; }
	{ nop.m	0x0; adds	r1,0x0,r35; adds	r36,0x0,r32 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,hash_dispose; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l40000000000C23E0:
	{ nop.m	0x0; mov.i	ar.pfs,r34; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000C23F0; br.ret	b0; }

;; assoc_flush: 40000000000C2400
;;   Called from:
;;     40000000000C08AC (in assign_compound_array_list)
assoc_flush proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x4; nop.m	0x0; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; adds	r36,0x0,r32; }
	{ adds	r37,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,hash_flush; }
	{ adds	r1,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000C2440; br.ret	b0; }
40000000000C2450 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C2460 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C2470 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; assoc_insert: 40000000000C2480
;;   Called from:
;;     400000000006731C (in fn4000000000066D40)
;;     40000000000BE78C (in fn40000000000BE480)
;;     40000000000BE78C (in fn40000000000BE480)
;;     40000000000BEADC (in convert_var_to_assoc)
assoc_insert proc
	{ alloc	r37,ar.pfs,0xA,0x0,0x7; mov	r36,b4; nop.b	0x0 }
	{ adds	r38,0x0,r1; adds	r40,0x0,r32; adds	r39,0x0,r33; }
	{ addl	r41,2,r0; nop.i	0x0; br.call.sptk.many	b0,hash_search; }
	{ adds	r14,0x8,r8; adds	r1,0x0,r38; cmp.eq	p06,p07,0x0,r8 }
	{ adds	r35,0x0,r8; adds	r39,0x0,r33; (p06) br.cond.spnt.few	40000000000C25E0; }

l40000000000C24D0:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,r33,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C2510; }

l40000000000C24F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r38; nop.m	0x0; nop.i	0x0 }

l40000000000C2510:
	{ adds	r35,0x10,r35; ld8	r39,[r35]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r39; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C2550; }

l40000000000C2530:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r38; nop.m	0x0; nop.i	0x0 }

l40000000000C2550:
	{ cmp.eq	p06,p07,0x0,r34; nop.m	0x0; adds	r39,0x0,r34; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C25C0; }

l40000000000C2566:
	{ chk.a.nc	r0,3FFFFFFFFF0C2D66; nop; break.i	0x80000 }

l40000000000C2570:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r38; adds	r39,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r38; nop.m	0x0; adds	r39,0x0,r8 }
	{ adds	r40,0x0,r34; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r38; nop.m	0x0; nop.i	0x0 }

l40000000000C25C0:
	{ st8	[r8],r35; mov.i	ar.pfs,r37; adds	r8,0x0,r0; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000C25D0; br.ret	b0 }

l40000000000C25E0:
	{ addl	r8,-1,r0; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000C25F0; br.ret	b0; }

;; assoc_remove: 40000000000C2600
;;   Called from:
;;     40000000000C01EC (in unbind_array_element)
assoc_remove proc
	{ alloc	r36,ar.pfs,0x9,0x0,0x6; mov	r35,b3; nop.b	0x0 }
	{ adds	r37,0x0,r1; adds	r39,0x0,r32; adds	r38,0x0,r33; }
	{ adds	r40,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,hash_remove; }
	{ adds	r14,0x10,r8; cmp.eq	p06,p07,0x0,r8; nop.i	0x0 }
	{ adds	r34,0x0,r8; adds	r1,0x0,r37; (p06) br.cond.dpnt.few	40000000000C26B0; }

l40000000000C2650:
	{ ld8	r38,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r14,0x8,r34; nop.m	0x0; adds	r1,0x0,r37; }
	{ ld8	r38,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r37; adds	r38,0x0,r34 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r37; nop.m	0x0; nop.i	0x0 }

l40000000000C26B0:
	{ nop.m	0x0; mov.i	ar.pfs,r36; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000C26C0; br.ret	b0; }
40000000000C26D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C26E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C26F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; assoc_reference: 40000000000C2700
;;   Called from:
;;     400000000006307C (in get_variable_value)
;;     400000000009EDCC (in fn400000000009A180)
;;     40000000000BE54C (in fn40000000000BE480)
;;     40000000000C199C (in fn40000000000C14C0)
assoc_reference proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; cmp.eq	p07,p06,0x0,r32; mov	r34,b2 }
	{ adds	r36,0x0,r1; adds	r37,0x0,r33; (p07) br.cond.dpnt.few	40000000000C2770; }

l40000000000C2720:
	{ adds	r39,0x0,r0; adds	r38,0x0,r32; br.call.sptk.many	b0,hash_search; }
	{ adds	r14,0x10,r8; cmp.eq	p06,p07,0x0,r8; nop.b	0x0 }
	{ adds	r1,0x0,r36; mov.i	ar.pfs,r35; (p06) br.cond.dpnt.few	40000000000C2770; }

l40000000000C2750:
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000C2750; nop.i	0x0 }
	{ ld8	r8,[r14]; nop.m	0x0; br.ret	b0; }

l40000000000C2770:
	{ adds	r8,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000C2780; br.ret	b0; }
40000000000C2790 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C27A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C27B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; assoc_quote: 40000000000C27C0
;;   Called from:
;;     40000000000C3F9C (in assoc_modcase)
;;     40000000000C43EC (in assoc_patsub)
assoc_quote proc
	{ alloc	r40,ar.pfs,0xB,0x0,0xA; adds	r14,0xC,r32; mov	r39,b7 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r38,0x8,r32; (p06) br.cond.dpnt.few	40000000000C2920; }

l40000000000C27E0:
	{ ld4	r14,[r14]; nop.m	0x0; adds	r41,0x0,r1 }
	{ adds	r37,0x0,r0; adds	r36,0x0,r0; cmp4.eq	p06,p07,0x0,r14; }
	{ (p06) adds	r32,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C2920; }

l40000000000C2806:
	{ chk.a.nc	r0,3FFFFFFFFF0C3006; nop; break.i	0x80000 }

l40000000000C2810:
	{ nop.m	0x0; ld4	r14,[r38]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000C2920; }

l40000000000C2830:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000C2840:
	{ ld8	r14,[r32]; add	r14,r14,r37; nop.i	0x0; }
	{ nop.m	0x0; ld8	r33,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p07) br.cond.dpnt.few	40000000000C2900; }

l40000000000C2870:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000C2880:
	{ nop.m	0x0; adds	r34,0x10,r33; nop.i	0x0; }
	{ ld8	r42,[r34]; nop.i	0x0; br.call.sptk.many	b0,quote_string; }
	{ ld8	r42,[r34]; adds	r1,0x0,r41; adds	r35,0x0,r8; }
	{ cmp.eq	p06,p07,0x0,r42; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C28E0; }

l40000000000C28C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r41; nop.m	0x0; nop.i	0x0 }

l40000000000C28E0:
	{ ld8	r33,[r33]; st8	[r35],r34; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	40000000000C2880 }

l40000000000C2900:
	{ adds	r36,0x1,r36; ld4	r14,[r38]; adds	r37,0x8,r37; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r36,r14; (p06) br.cond.dptk.few	40000000000C2840 }

l40000000000C2920:
	{ adds	r8,0x0,r32; nop.m	0x0; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000C2930; br.ret	b0; }

;; assoc_quote_escapes: 40000000000C2940
;;   Called from:
;;     40000000000C40EC (in assoc_modcase)
;;     40000000000C453C (in assoc_patsub)
assoc_quote_escapes proc
	{ alloc	r40,ar.pfs,0xB,0x0,0xA; adds	r14,0xC,r32; mov	r39,b7 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r38,0x8,r32; (p06) br.cond.dpnt.few	40000000000C2AA0; }

l40000000000C2960:
	{ ld4	r14,[r14]; nop.m	0x0; adds	r41,0x0,r1 }
	{ adds	r37,0x0,r0; adds	r36,0x0,r0; cmp4.eq	p06,p07,0x0,r14; }
	{ (p06) adds	r32,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C2AA0; }

l40000000000C2986:
	{ chk.a.nc	r0,3FFFFFFFFF0C3186; nop; break.i	0x80000 }

l40000000000C2990:
	{ nop.m	0x0; ld4	r14,[r38]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000C2AA0; }

l40000000000C29B0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000C29C0:
	{ ld8	r14,[r32]; add	r14,r14,r37; nop.i	0x0; }
	{ nop.m	0x0; ld8	r33,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p07) br.cond.dpnt.few	40000000000C2A80; }

l40000000000C29F0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000C2A00:
	{ nop.m	0x0; adds	r34,0x10,r33; nop.i	0x0; }
	{ ld8	r42,[r34]; nop.i	0x0; br.call.sptk.many	b0,quote_escapes; }
	{ ld8	r42,[r34]; adds	r1,0x0,r41; adds	r35,0x0,r8; }
	{ cmp.eq	p06,p07,0x0,r42; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C2A60; }

l40000000000C2A40:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r41; nop.m	0x0; nop.i	0x0 }

l40000000000C2A60:
	{ ld8	r33,[r33]; st8	[r35],r34; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	40000000000C2A00 }

l40000000000C2A80:
	{ adds	r36,0x1,r36; ld4	r14,[r38]; adds	r37,0x8,r37; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r36,r14; (p06) br.cond.dptk.few	40000000000C29C0 }

l40000000000C2AA0:
	{ adds	r8,0x0,r32; nop.m	0x0; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000C2AB0; br.ret	b0; }

;; assoc_dequote: 40000000000C2AC0
assoc_dequote proc
	{ alloc	r40,ar.pfs,0xB,0x0,0xA; adds	r14,0xC,r32; mov	r39,b7 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r38,0x8,r32; (p06) br.cond.dpnt.few	40000000000C2C20; }

l40000000000C2AE0:
	{ ld4	r14,[r14]; nop.m	0x0; adds	r41,0x0,r1 }
	{ adds	r37,0x0,r0; adds	r36,0x0,r0; cmp4.eq	p06,p07,0x0,r14; }
	{ (p06) adds	r32,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C2C20; }

l40000000000C2B06:
	{ chk.a.nc	r0,3FFFFFFFFF0C3306; nop; break.i	0x80000 }

l40000000000C2B10:
	{ nop.m	0x0; ld4	r14,[r38]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000C2C20; }

l40000000000C2B30:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000C2B40:
	{ ld8	r14,[r32]; add	r14,r14,r37; nop.i	0x0; }
	{ nop.m	0x0; ld8	r33,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p07) br.cond.dpnt.few	40000000000C2C00; }

l40000000000C2B70:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000C2B80:
	{ nop.m	0x0; adds	r34,0x10,r33; nop.i	0x0; }
	{ ld8	r42,[r34]; nop.i	0x0; br.call.sptk.many	b0,dequote_string; }
	{ ld8	r42,[r34]; adds	r1,0x0,r41; adds	r35,0x0,r8; }
	{ cmp.eq	p06,p07,0x0,r42; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C2BE0; }

l40000000000C2BC0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r41; nop.m	0x0; nop.i	0x0 }

l40000000000C2BE0:
	{ ld8	r33,[r33]; st8	[r35],r34; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	40000000000C2B80 }

l40000000000C2C00:
	{ adds	r36,0x1,r36; ld4	r14,[r38]; adds	r37,0x8,r37; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r36,r14; (p06) br.cond.dptk.few	40000000000C2B40 }

l40000000000C2C20:
	{ adds	r8,0x0,r32; nop.m	0x0; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000C2C30; br.ret	b0; }

;; assoc_dequote_escapes: 40000000000C2C40
assoc_dequote_escapes proc
	{ alloc	r40,ar.pfs,0xB,0x0,0xA; adds	r14,0xC,r32; mov	r39,b7 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r38,0x8,r32; (p06) br.cond.dpnt.few	40000000000C2DA0; }

l40000000000C2C60:
	{ ld4	r14,[r14]; nop.m	0x0; adds	r41,0x0,r1 }
	{ adds	r37,0x0,r0; adds	r36,0x0,r0; cmp4.eq	p06,p07,0x0,r14; }
	{ (p06) adds	r32,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C2DA0; }

l40000000000C2C86:
	{ chk.a.nc	r0,3FFFFFFFFF0C3486; nop; break.i	0x80000 }

l40000000000C2C90:
	{ nop.m	0x0; ld4	r14,[r38]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000C2DA0; }

l40000000000C2CB0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000C2CC0:
	{ ld8	r14,[r32]; add	r14,r14,r37; nop.i	0x0; }
	{ nop.m	0x0; ld8	r33,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p07) br.cond.dpnt.few	40000000000C2D80; }

l40000000000C2CF0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000C2D00:
	{ nop.m	0x0; adds	r34,0x10,r33; nop.i	0x0; }
	{ ld8	r42,[r34]; nop.i	0x0; br.call.sptk.many	b0,dequote_escapes; }
	{ ld8	r42,[r34]; adds	r1,0x0,r41; adds	r35,0x0,r8; }
	{ cmp.eq	p06,p07,0x0,r42; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C2D60; }

l40000000000C2D40:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r41; nop.m	0x0; nop.i	0x0 }

l40000000000C2D60:
	{ ld8	r33,[r33]; st8	[r35],r34; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	40000000000C2D00 }

l40000000000C2D80:
	{ adds	r36,0x1,r36; ld4	r14,[r38]; adds	r37,0x8,r37; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r36,r14; (p06) br.cond.dptk.few	40000000000C2CC0 }

l40000000000C2DA0:
	{ adds	r8,0x0,r32; nop.m	0x0; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000C2DB0; br.ret	b0; }

;; assoc_remove_quoted_nulls: 40000000000C2DC0
;;   Called from:
;;     40000000000C419C (in assoc_modcase)
;;     40000000000C45EC (in assoc_patsub)
assoc_remove_quoted_nulls proc
	{ alloc	r39,ar.pfs,0xA,0x0,0x9; adds	r14,0xC,r32; mov	r38,b6 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r37,0x8,r32; (p06) br.cond.dpnt.few	40000000000C2EF0; }

l40000000000C2DE0:
	{ ld4	r14,[r14]; nop.m	0x0; adds	r40,0x0,r1 }
	{ adds	r36,0x0,r0; adds	r35,0x0,r0; cmp4.eq	p06,p07,0x0,r14; }
	{ (p06) adds	r32,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C2EF0; }

l40000000000C2E06:
	{ chk.a.nc	r0,3FFFFFFFFF0C3606; nop; break.i	0x80000 }

l40000000000C2E10:
	{ nop.m	0x0; ld4	r14,[r37]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000C2EF0; }

l40000000000C2E30:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000C2E40:
	{ ld8	r14,[r32]; add	r14,r14,r36; nop.i	0x0; }
	{ nop.m	0x0; ld8	r33,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p07) br.cond.dpnt.few	40000000000C2ED0; }

l40000000000C2E70:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000C2E80:
	{ nop.m	0x0; adds	r34,0x10,r33; nop.i	0x0; }
	{ ld8	r41,[r34]; nop.i	0x0; br.call.sptk.many	b0,remove_quoted_nulls; }
	{ nop.m	0x0; ld8	r33,[r33]; adds	r1,0x0,r40 }
	{ nop.m	0x0; st8	[r8],r34; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	40000000000C2E80 }

l40000000000C2ED0:
	{ adds	r35,0x1,r35; ld4	r14,[r37]; adds	r36,0x8,r36; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r35,r14; (p06) br.cond.dptk.few	40000000000C2E40 }

l40000000000C2EF0:
	{ adds	r8,0x0,r32; nop.m	0x0; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000C2F00; br.ret	b0; }
40000000000C2F10 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C2F20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C2F30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; assoc_to_assign: 40000000000C2F40
;;   Called from:
;;     40000000000BFBEC (in print_assoc_assignment)
assoc_to_assign proc
	{ alloc	r50,ar.pfs,0x17,0x0,0x15; adds	r14,0xC,r32; mov	r52,pr }
	{ cmp.eq	p06,p07,0x0,r32; adds	r51,0x0,r1; adds	r48,0x8,r32; }
	{ addl	r53,128,r0; adds	r47,0x0,r0; mov	r49,b1 }
	{ addl	r38,1,r0; addl	r34,128,r0; (p06) br.cond.dpnt.few	40000000000C3760; }

l40000000000C2F80:
	{ ld4	r14,[r14]; adds	r46,0x0,r0; addl	r42,91,r0 }
	{ addl	r43,93,r0; addl	r44,61,r0; addl	r45,32,r0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C3760; }

l40000000000C2FB0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ addl	r14,40,r0; adds	r1,0x0,r51; adds	r36,0x0,r8; }
	{ st1	[r14],r8; ld4	r14,[r48]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,0x0,r14; (p06) br.cond.dpnt.few	40000000000C3790; }

l40000000000C2FF0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }
	{ ld8	r14,[r32]; add	r14,r14,r47; nop.i	0x0; }
	{ nop.m	0x0; ld8	r39,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r39; (p06) br.cond.dpnt.few	40000000000C3500; }

l40000000000C3030:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; adds	r40,0x8,r39; nop.i	0x0; }
	{ ld8	r53,[r40]; nop.i	0x0; br.call.sptk.many	b0,sh_contains_shell_metas; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r8; adds	r1,0x0,r51 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000C35E0; }

l40000000000C3080:
	{ (p06) ld8	r35,[r40]; nop.m	0x0; nop.i	0x0 }

l40000000000C3086:
	{ break.m	0x4000; nop; (p32) nop }

l40000000000C3090:
	{ adds	r14,0x10,r39; ld8	r53,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r53; nop.i	0x0; }
	{ (p06) adds	r37,0x0,r0; (p06) br.cond.dpnt.few	40000000000C30D0; br.call.sptk.many	b0,sh_double_quote; }

l40000000000C30B6:
	{ Invalid; (p32) nop; break.i	0x80000; }

l40000000000C30BC:
	{ (p40) nop; nop; Invalid }
	{ cmpxchg4.acq	r8,[r66],r0; break.x	0x1C89A300501000 }

l40000000000C30D0:
	{ cmp.eq	p18,p19,0x0,r35; nop.i	0x0; (p18) br.cond.dpnt.few	40000000000C36B0; }

l40000000000C30E0:
	{ ld1	r14,[r35]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000C36B0 }

l40000000000C3100:
	{ adds	r14,0x1,r35; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r41,9,r0; (p06) br.cond.dptk.few	40000000000C3180 }

l40000000000C312C:
	{ (p03) cmp.lt	p00,p11,r0,r33; (p33) cmp.lt.unc	p32,p16,r8,r64; Invalid }

l40000000000C3130:
	{ adds	r14,0x2,r35; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r41,10,r0; (p06) br.cond.dptk.few	40000000000C3180 }

l40000000000C315C:
	{ (p01) nop; zxt1	r96,r64; break.b	0x1000 }

l40000000000C3160:
	{ adds	r53,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; adds	r1,0x0,r51; adds	r41,0x8,r8 }

l40000000000C3180:
	{ nop.m	0x0; cmp.eq	p16,p17,0x0,r37; (p16) br.cond.dpnt.few	40000000000C36C0 }

l40000000000C3190:
	{ ld1	r14,[r37]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000C36C0 }

l40000000000C31B0:
	{ adds	r14,0x1,r37; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r8,1,r0; (p06) br.cond.dptk.few	40000000000C3230 }

l40000000000C31DC:
	{ (p03) cmp.lt	p00,p11,r0,r33; (p33) cmp.lt	p32,p16,r9,r64; Invalid }

l40000000000C31E0:
	{ adds	r14,0x2,r37; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r8,2,r0; (p06) br.cond.dptk.few	40000000000C3230 }

l40000000000C320C:
	{ Invalid; nop; (p06) epc }

l40000000000C3210:
	{ nop.m	0x0; adds	r53,0x0,r37; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r51; nop.m	0x0; nop.i	0x0 }

l40000000000C3230:
	{ add	r14,r41,r8,0x1; add	r14,r14,r38; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r14,r34; (p07) br.cond.dptk.few	40000000000C3600 }

l40000000000C3250:
	{ nop.m	0x0; sxt4	r14,r38; adds	r38,0x1,r38 }
	{ nop.m	0x0; adds	r54,0x0,r35; nop.b	0x0; }
	{ add	r14,r36,r14; sxt4	r53,r38; add	r53,r36,r53 }
	{ st1	[r42],r14; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; adds	r1,0x0,r51; (p18) br.cond.dpnt.few	40000000000C36A0 }

l40000000000C32A0:
	{ ld1	r14,[r35]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000C36A0 }

l40000000000C32C0:
	{ adds	r14,0x1,r35; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r8,1,r0; (p06) br.cond.dptk.few	40000000000C3340 }

l40000000000C32EC:
	{ (p03) cmp.lt	p00,p11,r0,r33; (p33) cmp.lt.unc	p32,p16,r8,r64; Invalid }

l40000000000C32F0:
	{ adds	r14,0x2,r35; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r8,2,r0; (p06) br.cond.dptk.few	40000000000C3340 }

l40000000000C331C:
	{ Invalid; nop; (p06) epc }

l40000000000C3320:
	{ nop.m	0x0; adds	r53,0x0,r35; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r51; nop.m	0x0; nop.i	0x0; }

l40000000000C3340:
	{ nop.m	0x0; add	r38,r8,r38; nop.i	0x0; }
	{ adds	r14,0x1,r38; sxt4	r15,r38; adds	r38,0x2,r38; }
	{ nop.m	0x0; sxt4	r14,r14; add	r15,r36,r15; }
	{ add	r14,r36,r14; st1	[r43],r15; nop.i	0x0; }
	{ st1	[r44],r14; nop.i	0x0; (p16) br.cond.dpnt.few	40000000000C3470; }

l40000000000C3390:
	{ nop.m	0x0; sxt4	r53,r38; adds	r54,0x0,r37; }
	{ add	r53,r36,r53; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ ld1	r14,[r37]; nop.m	0x0; adds	r1,0x0,r51; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) adds	r8,0x0,r0; (p06) br.cond.dptk.few	40000000000C3460 }

l40000000000C33DC:
	{ (p04) cmp.lt	p00,p11,r0,r33; (p17) cmp.lt	p32,p16,r9,r64; (p01) rfi }

l40000000000C33E0:
	{ adds	r14,0x1,r37; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r8,1,r0; (p06) br.cond.dptk.few	40000000000C3460 }

l40000000000C340C:
	{ (p03) cmp.lt	p00,p11,r0,r33; (p33) cmp.lt	p32,p16,r9,r64; Invalid }

l40000000000C3410:
	{ adds	r14,0x2,r37; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r8,2,r0; (p06) br.cond.dptk.few	40000000000C3460 }

l40000000000C343C:
	{ Invalid; nop; (p06) epc }

l40000000000C3440:
	{ nop.m	0x0; adds	r53,0x0,r37; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r51; nop.m	0x0; nop.i	0x0; }

l40000000000C3460:
	{ add	r38,r8,r38; nop.m	0x0; nop.i	0x0; }

l40000000000C3470:
	{ nop.m	0x0; sxt4	r14,r38; adds	r38,0x1,r38; }
	{ nop.m	0x0; add	r14,r36,r14; nop.i	0x0; }
	{ st1	[r45],r14; ld8	r14,[r40]; nop.i	0x0; }
	{ cmp.eq	p06,p07,r35,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C34D0; }

l40000000000C34B0:
	{ nop.m	0x0; (p19) adds	r53,0x0,r35; (p19) br.call.dptk.many	b0,fn400000000001A7E0; }

l40000000000C34BC:
	{ (p25) nop; invala; break.b	0x1000 }

l40000000000C34C0:
	{ (p19) adds	r1,0x0,r51; nop.m	0x0; nop.i	0x0 }

l40000000000C34C6:
	{ break.m	0x4000; nop; (p20) nop }

l40000000000C34D0:
	{ (p17) adds	r53,0x0,r37; nop.i	0x0; (p17) br.call.dptk.many	b0,fn400000000001A7E0; }

l40000000000C34D2:
	{ (p16) break.m	0x42009; nop; (p38) nop; }

l40000000000C34D6:
	{ nop; (p32) nop; (p48) nop }

l40000000000C34D8:
	{ (p16) cmp.lt	p00,p24,0xFFFFFFFFFFFFFFA0,r4; (p21) mov	pr,0x38095AF; (p28) break.i	0x80C2 }

l40000000000C34DC:
	{ (p24) cmp.eq	p46,p09,r61,r45; (p04) nop; nop }

l40000000000C34DE:
	{ Invalid; Invalid; Invalid }

l40000000000C34E2:
	{ (p48) break.m	0x20309; sxt1	r32,r32; Invalid; }

l40000000000C34E4:
	{ break.m	0x100002; Invalid; (p08) break.b	0x84 }

l40000000000C34E8:
	{ (p16) ldfe	f0,[r20]; (p06) break.i	0x10840; czx1.r	r8,r0 }

l40000000000C34EE:
	{ (p32) break.m	0x210; (p04) nop; (p25) nop; }

l40000000000C34F4:
	{ nop; (p08) nop; Invalid; }

l40000000000C3500:
	{ adds	r46,0x1,r46; ld4	r14,[r48]; adds	r47,0x8,r47; }

l40000000000C3504:
	{ (p08) padd2	r4,r56,r0; mov	pr,0x7885E02; (p08) break.i	0x84 }

l40000000000C3506:
	{ Invalid; (p23) nop; break.i	0x80000 }

l40000000000C3508:
	{ (p06) cmp4.eq	p04,p05,r8,r112; (p05) break.i	0x10840; Invalid }

l40000000000C350E:
	{ (p32) break.m	0x210; (p04) nop; (p28) nop; }

l40000000000C3514:
	{ nop; (p04) nop; (p21) dep	r66,r0,r35,15,2; }

l40000000000C3520:
	{ adds	r35,0x1,r38; adds	r15,0x8,r34; sxt4	r14,r38 }

l40000000000C3524:
	{ Invalid; (p08) nop; break.i	0x48 }
	{ Invalid; (p08) break.i	0x100004; dep	r8,r1,r54,45,4; }
	{ nop; break.x	0x2001F080001A; }
	{ cmp4.eq.or.andcm	p00,p24,r88,r25; (p36) addl	r2,1449688,r1; break.i	0x8C; }
	{ nop; Invalid; (p32) nop; }
	{ (p08) fwb; (p08) nop; break.i	0x80 }
	{ nop; break.i	0x0; nop; }
	{ nop.m	0x91E04; (p32) nop; (p12) dep	r79,r0,r35,37,5 }
	{ nop; (p12) break.i	0x100002; dep	r0,r1,r0,39,1 }
	{ (p12) break.m	0x100002; break.i	0x50038; (p06) dep	r26,r0,r8,31,1 }

l40000000000C35C0:
	{ adds	r8,0x0,r36; mov	pr,r52,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r50; }
	{ nop.m	0x0; mov.spnt	b0,r49,40000000000C35D0; br.ret	b0; }

l40000000000C35E0:
	{ ld8	r53,[r40]; nop.i	0x0; br.call.sptk.many	b0,sh_double_quote; }
	{ adds	r1,0x0,r51; adds	r35,0x0,r8; br.cond.sptk.few	40000000000C3090 }

l40000000000C3600:
	{ nop.m	0x0; shladd	r34,r34,0x1,r0; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r14,r34; (p06) br.cond.dptk.few	40000000000C3600 }

l40000000000C3620:
	{ adds	r53,0x0,r36; sxt4	r54,r34; br.call.sptk.many	b0,xrealloc; }
	{ nop.m	0x0; sxt4	r14,r38; nop.b	0x0 }
	{ adds	r36,0x0,r8; adds	r38,0x1,r38; adds	r1,0x0,r51; }
	{ add	r14,r36,r14; sxt4	r53,r38; adds	r54,0x0,r35; }
	{ nop.m	0x0; add	r53,r36,r53; nop.i	0x0 }
	{ st1	[r42],r14; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; adds	r1,0x0,r51; (p19) br.cond.dptk.few	40000000000C32A0; }

l40000000000C3690:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000C36A0:
	{ nop.m	0x0; adds	r8,0x0,r0; br.cond.sptk.few	40000000000C3340 }

l40000000000C36B0:
	{ addl	r41,8,r0; cmp.eq	p16,p17,0x0,r37; (p17) br.cond.dptk.few	40000000000C3190; }

l40000000000C36C0:
	{ adds	r8,0x0,r0; add	r14,r41,r8,0x1; nop.i	0x0; }
	{ nop.m	0x0; add	r14,r14,r38; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r14,r34; (p06) br.cond.dptk.few	40000000000C3250 }

l40000000000C36F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000C3600 }

l40000000000C3700:
	{ adds	r53,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,sh_single_quote; }
	{ adds	r34,0x0,r8; nop.m	0x0; adds	r1,0x0,r51 }
	{ adds	r53,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r36,0x0,r34; adds	r1,0x0,r51; mov	pr,r52,0xFFFFFFFFFFFFFFFE; }
	{ adds	r8,0x0,r36; nop.m	0x0; mov.i	ar.pfs,r50; }
	{ nop.m	0x0; mov.spnt	b0,r49,40000000000C3750; br.ret	b0 }

l40000000000C3760:
	{ adds	r36,0x0,r0; nop.m	0x0; mov	pr,r52,0xFFFFFFFFFFFFFFFE; }
	{ adds	r8,0x0,r36; nop.m	0x0; mov.i	ar.pfs,r50; }
	{ nop.m	0x0; mov.spnt	b0,r49,40000000000C3780; br.ret	b0 }

l40000000000C3790:
	{ addl	r35,2,r0; nop.m	0x0; addl	r14,1,r0 }
	{ addl	r15,41,r0; nop.m	0x0; cmp4.eq	p06,p07,0x0,r33; }
	{ add	r14,r36,r14; add	r35,r36,r35; nop.i	0x0 }
	{ st1	[r15],r14; st1	[r0],r35; (p06) br.cond.dptk.few	40000000000C35C0 }

l40000000000C37D0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000C3700; }
40000000000C37E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C37F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; assoc_to_word_list: 40000000000C3800
;;   Called from:
;;     40000000000C179C (in fn40000000000C14C0)
;;     40000000000C388C (in assoc_subrange)
assoc_to_word_list proc
	{ alloc	r16,ar.pfs,0x2,0x0,0x2; adds	r33,0x0,r0; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000C2180; }
40000000000C3820 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000C3830 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; assoc_subrange: 40000000000C3840
assoc_subrange proc
	{ alloc	r42,ar.pfs,0x10,0x0,0xD; adds	r14,0xC,r32; mov	r44,LC }
	{ adds	r43,0x0,r1; nop.m	0x0; adds	r45,0x0,r32; }
	{ ld4	r14,[r14]; nop.m	0x0; mov	r41,b1; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000C3A00; }

l40000000000C3880:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,assoc_to_word_list; }
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r33; cmp.lt	p09,p08,0x0,r33; adds	r39,0x0,r8 }
	{ adds	r1,0x0,r43; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	40000000000C3A00; }

l40000000000C38B0:
	{ nop.m	0x0; mov.i	LC,r14; adds	r14,0x0,r8; }
	{ nop.m	0x0; mov	r15,LC; nop.i	0x0; }
	{ nop.m	0x0; (p08) mov.i	LC,0x0; (p09) mov.i	LC,r15; }

l40000000000C38DC:
	{ Invalid; break.i	0x1000; Invalid }

l40000000000C38E0:
	{ nop.m	0x0; nop.i	0x0; br.cloop.sptk.few	40000000000C39E0; }

l40000000000C38F0:
	{ nop.m	0x0; mov.i	LC,r34; nop.b	0x0 }
	{ cmp.lt	p06,p07,r34,r0; adds	r38,0x0,r14; adds	r46,0x0,r14; }
	{ nop.m	0x0; mov	r34,LC; (p06) mov.i	LC,0x0; }

l40000000000C3920:
	{ nop.m	0x0; (p07) mov.i	LC,r34; nop.i	0x0; }

l40000000000C392C:
	{ Invalid; break.i	0x1000; nop }
	{ (p08) nop; zxt1	r64,r64; break.i	0x1000 }

l40000000000C3940:
	{ adds	r37,0x0,r14; nop.m	0x0; nop.i	0x0 }

l40000000000C3950:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r35; adds	r47,0x0,r36 }
	{ st8	[r0],r38; (p06) addl	r45,64,r0; nop.i	0x0; }

l40000000000C396C:
	{ nop; zxt4	r10,r0; break.i	0x1000 }

l40000000000C3976:
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ add	r0,r0,r1; nop; nop }
	{ add	r0,r0,r1; (p22) cmp4.eq.or.andcm	p00,p02,r39,r0; (p01) nop }

l40000000000C39A6:
	{ break.m	0x4000; (p32) nop; nop }
	{ Invalid; mov	pr,0xAA02A; break.b	0x80000 }
	{ break.m	0xAA0AC; nop; break.i	0x80000 }
	{ Invalid; (p34) nop; break.i	0x80000 }

l40000000000C39E0:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	40000000000C38E0 }

l40000000000C3A00:
	{ adds	r40,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r42; }
	{ adds	r8,0x0,r40; nop.m	0x0; mov.i	LC,r44; }
	{ nop.m	0x0; mov.spnt	b0,r41,40000000000C3A20; br.ret	b0 }

l40000000000C3A30:
	{ ld8	r37,[r14]; nop.m	0x0; adds	r38,0x0,r14; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r37; adds	r14,0x0,r37 }
	{ nop.b	0x0; (p06) br.cond.dpnt.few	40000000000C3950; br.cloop.sptk.few	40000000000C3A30 }

l40000000000C3A5C:
	{ Invalid; break.i	0x1000; break.i	0x1000 }

l40000000000C3A60:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000C3940; }
40000000000C3A70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; assoc_keys_to_word_list: 40000000000C3A80
;;   Called from:
;;     40000000000C1F6C (in array_keys)
assoc_keys_to_word_list proc
	{ alloc	r16,ar.pfs,0x2,0x0,0x2; addl	r33,1,r0; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000C2180; }
40000000000C3AA0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000C3AB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; assoc_to_string: 40000000000C3AC0
;;   Called from:
;;     40000000000C406C (in assoc_modcase)
;;     40000000000C412C (in assoc_modcase)
;;     40000000000C41CC (in assoc_modcase)
;;     40000000000C44BC (in assoc_patsub)
;;     40000000000C457C (in assoc_patsub)
;;     40000000000C461C (in assoc_patsub)
assoc_to_string proc
	{ alloc	r42,ar.pfs,0xF,0x0,0xD; adds	r14,0xC,r32; mov	r44,pr }
	{ adds	r40,0x8,r32; cmp.eq	p06,p07,0x0,r32; adds	r43,0x0,r1; }
	{ adds	r39,0x0,r0; mov	r41,b1; adds	r37,0x0,r0 }
	{ adds	r38,0x0,r0; cmp4.eq	p16,p17,0x0,r34; (p06) br.cond.dpnt.few	40000000000C3DB0; }

l40000000000C3B00:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C3D70; }

l40000000000C3B20:
	{ nop.m	0x0; ld4	r14,[r40]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000C3D70; }

l40000000000C3B40:
	{ ld8	r14,[r32]; add	r14,r14,r39; nop.i	0x0; }
	{ nop.m	0x0; ld8	r35,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r35; (p06) br.cond.dpnt.few	40000000000C3C90; }

l40000000000C3B70:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000C3B80:
	{ adds	r14,0x10,r35; ld8	r36,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r36; adds	r45,0x0,r36; (p06) br.cond.dpnt.few	40000000000C3C70; }

l40000000000C3BA0:
	{ nop.m	0x0; nop.i	0x0; (p17) br.call.dptk.many	b0,quote_string; }

l40000000000C3BB0:
	{ nop.m	0x0; nop.i	0x0; (p16) br.call.dptk.many	b0,fn400000000001B6C0; }

l40000000000C3BC0:
	{ (p16) adds	r1,0x0,r43; (p16) adds	r45,0x1,r8; (p16) br.call.dptk.many	b0,xmalloc; }

l40000000000C3BC6:
	{ Invalid; Invalid; Invalid }

l40000000000C3BCC:
	{ (p08) cmp.le.and	p10,p08,r0,r41; (p05) invala; nop }

l40000000000C3BD0:
	{ (p16) adds	r46,0x0,r36; nop.m	0x0; (p16) adds	r45,0x0,r8 }

l40000000000C3BD6:
	{ nop; (p22) nop; (p20) nop }

l40000000000C3BE0:
	{ (p16) adds	r1,0x0,r43; nop.m	0x0; (p16) br.call.dptk.many	b0,fn400000000001B180; }

l40000000000C3BE6:
	{ nop; (p32) nop; (p16) nop }

l40000000000C3BF0:
	{ adds	r1,0x0,r43; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r45,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,make_bare_word; }
	{ adds	r46,0x0,r37; nop.m	0x0; adds	r1,0x0,r43 }
	{ adds	r45,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,make_word_list; }
	{ cmp.eq	p06,p07,0x0,r36; adds	r1,0x0,r43; nop.i	0x0 }
	{ adds	r37,0x0,r8; adds	r45,0x0,r36; (p06) br.cond.dpnt.few	40000000000C3C70; }

l40000000000C3C50:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r43; nop.m	0x0; nop.i	0x0 }

l40000000000C3C70:
	{ nop.m	0x0; ld8	r35,[r35]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	40000000000C3B80 }

l40000000000C3C90:
	{ adds	r38,0x1,r38; ld4	r14,[r40]; adds	r39,0x8,r39; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r38,r14; (p06) br.cond.dptk.few	40000000000C3B40; }

l40000000000C3CB0:
	{ cmp.eq	p06,p07,0x0,r37; adds	r45,0x0,r37; (p06) br.cond.dpnt.few	40000000000C3D70; }

l40000000000C3CC0:
	{ nop.m	0x0; ld8	r14,[r37]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C3D50; }

l40000000000C3CE0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,list_reverse; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r43; nop.i	0x0 }
	{ adds	r45,0x0,r8; adds	r46,0x0,r33; (p06) br.cond.spnt.few	40000000000C3D70; }

l40000000000C3D10:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,string_list_internal; }
	{ adds	r1,0x0,r43; nop.m	0x0; nop.i	0x0 }

l40000000000C3D30:
	{ nop.m	0x0; mov	pr,r44,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r42; }
	{ nop.m	0x0; mov.spnt	b0,r41,40000000000C3D40; br.ret	b0; }

l40000000000C3D50:
	{ adds	r45,0x0,r37; adds	r46,0x0,r33; br.call.sptk.many	b0,string_list_internal; }
	{ nop.m	0x0; adds	r1,0x0,r43; br.cond.sptk.few	40000000000C3D30 }

l40000000000C3D70:
	{ addl	r45,1,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r43; st1	[r0],r8; mov	pr,r44,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r42; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r41,40000000000C3DA0; br.ret	b0 }

l40000000000C3DB0:
	{ adds	r8,0x0,r0; mov	pr,r44,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r42; }
	{ nop.m	0x0; mov.spnt	b0,r41,40000000000C3DC0; br.ret	b0; }
40000000000C3DD0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C3DE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C3DF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; assoc_modcase: 40000000000C3E00
assoc_modcase proc
	{ alloc	r44,ar.pfs,0x11,0x0,0xE; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ adds	r14,0xC,r32; mov	r43,b3; cmp.eq	p06,p07,0x0,r32; }
	{ adds	r45,0x0,r1; adds	r47,0x0,r0; adds	r46,0x0,r32 }
	{ adds	r40,0x0,r0; adds	r39,0x0,r0; (p06) br.cond.dpnt.few	40000000000C4160; }

l40000000000C3E40:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C4160; }

l40000000000C3E60:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,hash_copy; }
	{ adds	r41,0x8,r8; adds	r1,0x0,r45; adds	r42,0x0,r8; }
	{ nop.m	0x0; ld4	r14,[r41]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000C3F80; }

l40000000000C3EA0:
	{ ld8	r14,[r42]; add	r14,r14,r40; nop.i	0x0; }
	{ nop.m	0x0; ld8	r36,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r36; (p07) br.cond.dpnt.few	40000000000C3F60; }

l40000000000C3ED0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000C3EE0:
	{ adds	r37,0x10,r36; adds	r47,0x0,r33; adds	r48,0x0,r34; }
	{ ld8	r46,[r37]; nop.i	0x0; br.call.sptk.many	b0,sh_modcase; }
	{ ld8	r46,[r37]; adds	r1,0x0,r45; adds	r38,0x0,r8; }
	{ cmp.eq	p06,p07,0x0,r46; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C3F40; }

l40000000000C3F20:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r45; nop.m	0x0; nop.i	0x0 }

l40000000000C3F40:
	{ ld8	r36,[r36]; st8	[r38],r37; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r36; (p06) br.cond.dptk.few	40000000000C3EE0 }

l40000000000C3F60:
	{ adds	r39,0x1,r39; ld4	r14,[r41]; adds	r40,0x8,r40; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r39,r14; (p06) br.cond.dptk.few	40000000000C3EA0; }

l40000000000C3F80:
	{ nop.m	0x0; tbit.z	p07,p06,r35,0x5; (p07) br.cond.dptk.few	40000000000C40E0 }

l40000000000C3F90:
	{ adds	r46,0x0,r42; nop.i	0x0; br.call.sptk.many	b0,assoc_quote; }
	{ nop.m	0x0; tbit.z	p06,p07,r35,0x6; nop.i	0x0 }
	{ adds	r1,0x0,r45; adds	r46,0x10,r12; (p07) br.cond.dpnt.few	40000000000C4190; }

l40000000000C3FC0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,ifs_firstchar; }
	{ adds	r1,0x0,r45; adds	r37,0x0,r8; br.call.sptk.many	b0,getifs; }
	{ adds	r1,0x0,r45; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	40000000000C4010; }

l40000000000C3FF0:
	{ ld1	r14,[r8]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000C4050 }

l40000000000C4010:
	{ adds	r15,0x10,r12; ld4	r14,[r15]; addl	r15,32,r0; }
	{ cmp4.lt	p06,p07,0x1,r14; adds	r14,0x0,r37; (p07) br.cond.dpnt.few	40000000000C4200; }

l40000000000C4030:
	{ nop.m	0x0; st1	[r14],r1,1; nop.i	0x0; }
	{ st1	[r0],r14; nop.m	0x0; nop.i	0x0 }

l40000000000C4050:
	{ adds	r47,0x0,r37; nop.m	0x0; adds	r48,0x0,r0 }
	{ adds	r46,0x0,r42; nop.m	0x0; br.call.sptk.many	b0,assoc_to_string; }
	{ adds	r1,0x0,r45; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r46,0x0,r37; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r45; nop.m	0x0; nop.i	0x0 }

l40000000000C40A0:
	{ nop.m	0x0; adds	r46,0x0,r42; br.call.sptk.many	b0,assoc_dispose; }
	{ adds	r1,0x0,r45; nop.m	0x0; nop.i	0x0 }

l40000000000C40C0:
	{ adds	r8,0x0,r36; mov.i	ar.pfs,r44; mov.spnt	b0,r43,40000000000C40C0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000000C40E0:
	{ adds	r46,0x0,r42; nop.i	0x0; br.call.sptk.many	b0,assoc_quote_escapes; }
	{ nop.m	0x0; adds	r1,0x0,r45; tbit.z	p07,p06,r35,0x6 }
	{ adds	r46,0x0,r42; adds	r48,0x0,r0; (p06) br.cond.dpnt.few	40000000000C4190; }

l40000000000C4110:
	{ nop.m	0x0; addl	r47,-476,r1; nop.i	0x0; }
	{ ld8	r47,[r47]; nop.i	0x0; br.call.sptk.many	b0,assoc_to_string; }
	{ adds	r1,0x0,r45; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r46,0x0,r42; nop.m	0x0; br.call.sptk.many	b0,assoc_dispose; }
	{ nop.m	0x0; adds	r1,0x0,r45; br.cond.sptk.few	40000000000C40C0 }

l40000000000C4160:
	{ nop.m	0x0; adds	r36,0x0,r0; nop.i	0x0; }
	{ adds	r8,0x0,r36; mov.i	ar.pfs,r44; mov.spnt	b0,r43,40000000000C4170 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000000C4190:
	{ adds	r46,0x0,r42; nop.i	0x0; br.call.sptk.many	b0,assoc_remove_quoted_nulls; }
	{ adds	r1,0x0,r45; adds	r46,0x0,r0; br.call.sptk.many	b0,ifs_firstchar; }
	{ adds	r1,0x0,r45; adds	r37,0x0,r8; adds	r46,0x0,r42 }
	{ adds	r47,0x0,r8; adds	r48,0x0,r0; br.call.sptk.many	b0,assoc_to_string; }
	{ adds	r1,0x0,r45; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r46,0x0,r37; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r45; br.cond.sptk.few	40000000000C40A0 }

l40000000000C4200:
	{ adds	r46,0x0,r37; addl	r47,2,r0; br.call.sptk.many	b0,xrealloc; }
	{ adds	r37,0x0,r8; addl	r15,32,r0; adds	r1,0x0,r45; }
	{ adds	r14,0x0,r37; st1	[r14],r1,1; nop.i	0x0; }
	{ st1	[r0],r14; nop.i	0x0; br.cond.sptk.few	40000000000C4050; }

;; assoc_patsub: 40000000000C4240
assoc_patsub proc
	{ alloc	r44,ar.pfs,0x12,0x0,0xE; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ adds	r14,0xC,r32; mov	r43,b3; cmp.eq	p06,p07,0x0,r32; }
	{ adds	r45,0x0,r1; adds	r47,0x0,r0; adds	r46,0x0,r32 }
	{ adds	r40,0x0,r0; adds	r39,0x0,r0; (p06) br.cond.dpnt.few	40000000000C45B0; }

l40000000000C4280:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C45B0; }

l40000000000C42A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,hash_copy; }
	{ adds	r41,0x8,r8; adds	r1,0x0,r45; adds	r42,0x0,r8; }
	{ nop.m	0x0; ld4	r14,[r41]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000C43D0; }

l40000000000C42E0:
	{ ld8	r14,[r42]; add	r14,r14,r40; nop.i	0x0; }
	{ nop.m	0x0; ld8	r36,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r36; (p07) br.cond.dpnt.few	40000000000C43B0; }

l40000000000C4310:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000C4320:
	{ adds	r37,0x10,r36; nop.m	0x0; adds	r47,0x0,r33 }
	{ adds	r48,0x0,r34; nop.m	0x0; adds	r49,0x0,r35; }
	{ ld8	r46,[r37]; nop.i	0x0; br.call.sptk.many	b0,pat_subst; }
	{ ld8	r46,[r37]; adds	r1,0x0,r45; adds	r38,0x0,r8; }
	{ cmp.eq	p06,p07,0x0,r46; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C4390; }

l40000000000C4370:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r45; nop.m	0x0; nop.i	0x0 }

l40000000000C4390:
	{ ld8	r36,[r36]; st8	[r38],r37; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r36; (p06) br.cond.dptk.few	40000000000C4320 }

l40000000000C43B0:
	{ adds	r39,0x1,r39; ld4	r14,[r41]; adds	r40,0x8,r40; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r39,r14; (p06) br.cond.dptk.few	40000000000C42E0; }

l40000000000C43D0:
	{ nop.m	0x0; tbit.z	p07,p06,r35,0x5; (p07) br.cond.dptk.few	40000000000C4530 }

l40000000000C43E0:
	{ adds	r46,0x0,r42; nop.i	0x0; br.call.sptk.many	b0,assoc_quote; }
	{ nop.m	0x0; tbit.z	p06,p07,r35,0x6; nop.i	0x0 }
	{ adds	r1,0x0,r45; adds	r46,0x10,r12; (p07) br.cond.dpnt.few	40000000000C45E0; }

l40000000000C4410:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,ifs_firstchar; }
	{ adds	r1,0x0,r45; adds	r37,0x0,r8; br.call.sptk.many	b0,getifs; }
	{ adds	r1,0x0,r45; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	40000000000C4460; }

l40000000000C4440:
	{ ld1	r14,[r8]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000C44A0 }

l40000000000C4460:
	{ adds	r15,0x10,r12; ld4	r14,[r15]; addl	r15,32,r0; }
	{ cmp4.lt	p06,p07,0x1,r14; adds	r14,0x0,r37; (p07) br.cond.dpnt.few	40000000000C4650; }

l40000000000C4480:
	{ nop.m	0x0; st1	[r14],r1,1; nop.i	0x0; }
	{ st1	[r0],r14; nop.m	0x0; nop.i	0x0 }

l40000000000C44A0:
	{ adds	r47,0x0,r37; nop.m	0x0; adds	r48,0x0,r0 }
	{ adds	r46,0x0,r42; nop.m	0x0; br.call.sptk.many	b0,assoc_to_string; }
	{ adds	r1,0x0,r45; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r46,0x0,r37; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r45; nop.m	0x0; nop.i	0x0 }

l40000000000C44F0:
	{ nop.m	0x0; adds	r46,0x0,r42; br.call.sptk.many	b0,assoc_dispose; }
	{ adds	r1,0x0,r45; nop.m	0x0; nop.i	0x0 }

l40000000000C4510:
	{ adds	r8,0x0,r36; mov.i	ar.pfs,r44; mov.spnt	b0,r43,40000000000C4510 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000000C4530:
	{ adds	r46,0x0,r42; nop.i	0x0; br.call.sptk.many	b0,assoc_quote_escapes; }
	{ nop.m	0x0; adds	r1,0x0,r45; tbit.z	p07,p06,r35,0x6 }
	{ adds	r46,0x0,r42; adds	r48,0x0,r0; (p06) br.cond.dpnt.few	40000000000C45E0; }

l40000000000C4560:
	{ nop.m	0x0; addl	r47,-476,r1; nop.i	0x0; }
	{ ld8	r47,[r47]; nop.i	0x0; br.call.sptk.many	b0,assoc_to_string; }
	{ adds	r1,0x0,r45; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r46,0x0,r42; nop.m	0x0; br.call.sptk.many	b0,assoc_dispose; }
	{ nop.m	0x0; adds	r1,0x0,r45; br.cond.sptk.few	40000000000C4510 }

l40000000000C45B0:
	{ nop.m	0x0; adds	r36,0x0,r0; nop.i	0x0; }
	{ adds	r8,0x0,r36; mov.i	ar.pfs,r44; mov.spnt	b0,r43,40000000000C45C0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000000C45E0:
	{ adds	r46,0x0,r42; nop.i	0x0; br.call.sptk.many	b0,assoc_remove_quoted_nulls; }
	{ adds	r1,0x0,r45; adds	r46,0x0,r0; br.call.sptk.many	b0,ifs_firstchar; }
	{ adds	r1,0x0,r45; adds	r37,0x0,r8; adds	r46,0x0,r42 }
	{ adds	r47,0x0,r8; adds	r48,0x0,r0; br.call.sptk.many	b0,assoc_to_string; }
	{ adds	r1,0x0,r45; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r46,0x0,r37; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r45; br.cond.sptk.few	40000000000C44F0 }

l40000000000C4650:
	{ adds	r46,0x0,r37; addl	r47,2,r0; br.call.sptk.many	b0,xrealloc; }
	{ adds	r37,0x0,r8; addl	r15,32,r0; adds	r1,0x0,r45; }
	{ adds	r14,0x0,r37; st1	[r14],r1,1; nop.i	0x0; }
	{ st1	[r0],r14; nop.i	0x0; br.cond.sptk.few	40000000000C44A0; }
40000000000C4690 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000C46A0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000C46B0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; fn40000000000C46C0: 40000000000C46C0
;;   Called from:
;;     40000000000C65DC (in brace_expand)
;;     40000000000C65DC (in brace_expand)
;;     40000000000C664C (in brace_expand)
;;     40000000000C664C (in brace_expand)
fn40000000000C46C0 proc
	{ alloc	r47,ar.pfs,0x14,0x0,0x12; mov	r49,pr; nop.b	0x0 }
	{ cmp.eq	p07,p06,0x0,r32; adds	r48,0x0,r1; adds	r50,0x0,r32; }
	{ nop.m	0x0; mov	r46,b6; nop.i	0x0 }
	{ adds	r42,0x0,r0; adds	r38,0x0,r32; (p07) br.cond.dpnt.few	40000000000C4990; }

l40000000000C4700:
	{ cmp.eq	p07,p06,0x0,r33; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000C4950; }

l40000000000C4710:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strvec_len; }
	{ adds	r1,0x0,r48; nop.m	0x0; adds	r34,0x0,r8 }
	{ adds	r50,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,strvec_len; }
	{ setf.sig	f6,r34; setf.sig	f7,r8; adds	r1,0x0,r48 }
	{ adds	r45,0xFFFFFFFFFFFFFFFF,r8; adds	r44,0xFFFFFFFFFFFFFFFF,r34; cmp4.lt	p17,p16,0x0,r8; }
	{ addp4	r41,r45,r0; nop.m	0x0; addp4	r44,r44,r0; }
	{ nop.m	0x0; nop.m	0x0; xma.l	f6,f6,f7,f0; }
	{ getf.sig	r50,f6; adds	r50,0x1,r50; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r50,r50; nop.i	0x0; }
	{ shladd	r50,r50,0x3,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r14,0x8,r32; adds	r15,0x8,r33; cmp4.lt	p07,p06,0x0,r34 }
	{ adds	r1,0x0,r48; adds	r43,0x0,r8; shladd	r41,r41,0x3,r15 }
	{ shladd	r44,r44,0x3,r14; (p06) adds	r34,0x0,r0; (p06) br.cond.dpnt.few	40000000000C4910; }

l40000000000C47DC:
	{ (p10) cmpxchg2.acq	r0,[r33],r64; Invalid; nop }

l40000000000C47E0:
	{ ld8	r34,[r38]; nop.m	0x0; sxt4	r35,r42; }
	{ adds	r50,0x0,r34; shladd	r35,r35,0x3,r43; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r39,0x1,r8; nop.m	0x0; adds	r1,0x0,r48 }
	{ nop.m	0x0; sxt4	r40,r8; (p16) br.cond.dpnt.few	40000000000C48E0; }

l40000000000C4820:
	{ nop.m	0x0; sxt4	r39,r39; adds	r34,0x0,r33; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000C4840:
	{ adds	r36,0x0,r34; ld8	r50,[r34],8; adds	r37,0x0,r35 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r48; add	r50,r8,r39; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r48; st8	[r35],r8,8; adds	r50,0x0,r8; }
	{ ld8	r51,[r38]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; ld8	r50,[r37]; adds	r1,0x0,r48 }
	{ nop.m	0x0; ld8	r51,[r36]; nop.i	0x0; }
	{ add	r50,r50,r40; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r48; cmp.eq	p07,p06,r41,r34; (p06) br.cond.dptk.few	40000000000C4840 }

l40000000000C48D0:
	{ add	r42,r42,r45,0x1; ld8	r34,[r38]; nop.i	0x0; }

l40000000000C48E0:
	{ adds	r38,0x8,r38; adds	r50,0x0,r34; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r48; cmp.eq	p07,p06,r44,r38; (p06) br.cond.dptk.few	40000000000C47E0 }

l40000000000C4900:
	{ nop.m	0x0; sxt4	r34,r42; shladd	r34,r34,0x3,r0; }

l40000000000C4910:
	{ adds	r50,0x0,r32; add	r34,r43,r34; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r8,0x0,r43; adds	r1,0x0,r48; nop.b	0x0 }
	{ st8	[r0],r34; mov	pr,r49,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r47; }
	{ nop.m	0x0; mov.spnt	b0,r46,40000000000C4940; br.ret	b0; }

l40000000000C4950:
	{ adds	r50,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,strvec_copy; }
	{ adds	r43,0x0,r8; adds	r1,0x0,r48; mov	pr,r49,0xFFFFFFFFFFFFFFFE; }
	{ adds	r8,0x0,r43; nop.m	0x0; mov.i	ar.pfs,r47; }
	{ nop.m	0x0; mov.spnt	b0,r46,40000000000C4980; br.ret	b0; }

l40000000000C4990:
	{ adds	r50,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,strvec_copy; }
	{ adds	r43,0x0,r8; adds	r1,0x0,r48; mov	pr,r49,0xFFFFFFFFFFFFFFFE; }
	{ adds	r8,0x0,r43; nop.m	0x0; mov.i	ar.pfs,r47; }
	{ nop.m	0x0; mov.spnt	b0,r46,40000000000C49C0; br.ret	b0; }
40000000000C49D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C49E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C49F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000C4A00: 40000000000C4A00
;;   Called from:
;;     40000000000C540C (in brace_expand)
;;     40000000000C545C (in brace_expand)
;;     40000000000C55BC (in brace_expand)
;;     40000000000C5C7C (in brace_expand)
;;     40000000000C5DDC (in brace_expand)
fn40000000000C4A00 proc
	{ alloc	r50,ar.pfs,0x19,0x0,0x15; adds	r12,0xFFFFFFFFFFFFFFD0,r12; mov	r52,pr }
	{ cmp4.eq	p06,p07,0x7D,r35; cmp4.eq	p09,p08,0x7D,r35; addl	r41,-9996,r1; }
	{ (p06) addl	r14,1,r0; adds	r42,0x28,r12; mov	r49,b1 }

l40000000000C4A26:
	{ Invalid; (p24) nop; (p48) nop }
	{ Invalid; (p21) cmp.eq.or	p00,p02,r0,r0; (p33) nop }

l40000000000C4A46:
	{ Invalid; (p19) nop; nop }
	{ Invalid; (p23) br.call.spnt.few	b0,4000000000144B16; (p50) nop.b	0xB }

l40000000000C4A5C:
	{ (p12) cmp.eq	p12,p40,0x0,r66; (p05) nop; }

l40000000000C4A66:
	{ (p20) fwb; (p24) nop; break.b	0x80000 }
	{ Invalid; (p22) mov.sptk	b0,r12,40000000000C4B76; break.i	0x80000 }

l40000000000C4A80:
	{ nop.m	0x0; sxt4	r38,r36; add	r37,r32,r38; }
	{ ld1	r8,[r37]; nop.m	0x0; sxt1	r8,r8; }
	{ adds	r14,0x0,r8; cmp4.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	40000000000C4BE0; }

l40000000000C4AB0:
	{ cmp4.eq	p06,p07,0x0,r40; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000C4CF0; }

l40000000000C4AC0:
	{ cmp4.eq	p07,p06,0x5C,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000C5020; }

l40000000000C4AD0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x24,r14; (p07) br.cond.dpnt.few	40000000000C4C10; }

l40000000000C4AE0:
	{ cmp4.eq	p06,p07,0x0,r39; nop.m	0x0; nop.i	0x0 }

l40000000000C4AF0:
	{ nop.m	0x0; nop.i	0x0; (p06) br.cond.dptk.few	40000000000C4DF0; }

l40000000000C4B00:
	{ cmp4.eq	p06,p07,r39,r8; nop.i	0x0; (p06) adds	r39,0x0,r0 }

l40000000000C4B10:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r51; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	40000000000C5080; }

l40000000000C4B30:
	{ ld1	r14,[r37]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r41; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000C4C80; }

l40000000000C4B80:
	{ (p06) addl	r14,1,r0; nop.m	0x0; nop.i	0x0; }

l40000000000C4B86:
	{ break.m	0x4000; nop; nop }

l40000000000C4B90:
	{ add	r36,r14,r36; nop.m	0x0; sxt4	r38,r36; }
	{ add	r37,r32,r38; ld1	r8,[r37]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r8,r8; nop.i	0x0; }
	{ adds	r14,0x0,r8; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000000C4AB0; }

l40000000000C4BD0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000C4BE0:
	{ st4	[r36],r34; mov	pr,r52,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r50; }
	{ nop.m	0x0; mov.spnt	b0,r49,40000000000C4BF0; nop.i	0x0 }
	{ adds	r12,0x30,r12; nop.m	0x0; br.ret	b0 }

l40000000000C4C10:
	{ adds	r15,0x1,r37; ld1	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x7B,r15; (p06) br.cond.dptk.few	40000000000C4AE0; }

l40000000000C4C40:
	{ cmp4.eq	p06,p07,0x27,r39; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C4B10; }

l40000000000C4C50:
	{ cmp4.eq	p07,p06,0x0,r39; nop.m	0x0; adds	r36,0x1,r36; }
	{ (p07) adds	r43,0x1,r43; (p07) addl	r40,1,r0; (p07) br.cond.dptk.few	40000000000C4A80; }

l40000000000C4C66:
	{ (p20) chk.a.clr	f1,3FFFFFFFFF2C4C66; nop; break.i	0x80000; }

l40000000000C4C6C:
	{ (p49) invala; break.i	0x1000; zxt4	r0,r0 }

l40000000000C4C70:
	{ nop.m	0x0; addl	r40,1,r0; br.cond.sptk.few	40000000000C4A80 }

l40000000000C4C80:
	{ nop.m	0x0; ld8	r14,[r42]; adds	r53,0x0,r0 }
	{ adds	r54,0x0,r37; sub	r55,r33,r38; adds	r56,0x0,r42; }
	{ st8	[r14],r46; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; nop.m	0x0; adds	r1,0x0,r51; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C5060; }

l40000000000C4CD0:
	{ ld8	r14,[r46]; nop.m	0x0; adds	r36,0x1,r36; }
	{ st8	[r14],r42; nop.i	0x0; br.cond.sptk.few	40000000000C4A80 }

l40000000000C4CF0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r51; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	40000000000C50C0; }

l40000000000C4D10:
	{ ld1	r14,[r37]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r41; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000C4D80; }

l40000000000C4D60:
	{ (p06) addl	r14,1,r0; nop.m	0x0; nop.i	0x0; }

l40000000000C4D66:
	{ break.m	0x4000; nop; nop }

l40000000000C4D70:
	{ add	r36,r14,r36; adds	r40,0x0,r0; br.cond.sptk.few	40000000000C4A80; }

l40000000000C4D80:
	{ ld8	r14,[r42]; adds	r53,0x0,r0; adds	r54,0x0,r37 }
	{ sub	r55,r33,r38; adds	r56,0x0,r42; adds	r40,0x0,r0; }
	{ st8	[r14],r45; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; nop.m	0x0; adds	r1,0x0,r51; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C50A0; }

l40000000000C4DD0:
	{ ld8	r14,[r45]; nop.m	0x0; adds	r36,0x1,r36; }
	{ st8	[r14],r42; nop.i	0x0; br.cond.sptk.few	40000000000C4A80 }

l40000000000C4DF0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x22,r8; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x27,r8; (p06) br.cond.dptk.few	40000000000C5090; }

l40000000000C4E10:
	{ cmp4.eq	p07,p06,0x60,r8; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000C5090; }

l40000000000C4E20:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x24,r8; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x3C,r8; (p06) br.cond.dptk.few	40000000000C4F90; }

l40000000000C4E40:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x3E,r8; (p07) br.cond.dpnt.few	40000000000C4F90; }

l40000000000C4E50:
	{ cmp4.eq	p06,p07,r35,r8; nop.m	0x0; cmp4.eq	p08,p09,0x0,r43; }
	{ (p06) addl	r15,1,r0; nop.m	0x0; (p08) addl	r44,1,r0; }

l40000000000C4E66:
	{ Invalid; (p22) cmp4.eq.and	p01,p08,0x0,r0; (p49) nop }

l40000000000C4E70:
	{ (p07) adds	r15,0x0,r0; (p09) adds	r44,0x0,r0; and	r15,r44,r15; }

l40000000000C4E76:
	{ Invalid; (p07) nop; break.i	0x80000 }

l40000000000C4E7C:
	{ Invalid; cmp.lt	p00,p00,r32,r0; mov	pr,r99,0xE6C0; }
	{ Invalid; cmp.lt	p00,p00,r32,r0; nop }

l40000000000C4E90:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r47; (p06) br.cond.dptk.few	40000000000C50D0; }

l40000000000C4EA0:
	{ cmp4.eq	p07,p06,0x7B,r8; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C4BE0; }

l40000000000C4EB0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r36; (p06) br.cond.dptk.few	40000000000C4F20 }

l40000000000C4EC0:
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r37; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; and	r15,0xFFFFFFFFFFFFFFDF,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	40000000000C4F20; }

l40000000000C4EF0:
	{ cmp4.eq	p06,p07,0x9,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C4F20; }

l40000000000C4F00:
	{ nop.m	0x0; cmp4.eq	p07,p06,0xA,r14; (p06) br.cond.dpnt.few	40000000000C4BE0; }

l40000000000C4F10:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000C4F20:
	{ adds	r37,0x1,r37; ld1	r15,[r37]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; and	r16,0xFFFFFFFFFFFFFFDF,r15; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r16; (p06) br.cond.dptk.few	40000000000C4F80; }

l40000000000C4F50:
	{ cmp4.eq	p06,p07,0x9,r15; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C4F80; }

l40000000000C4F60:
	{ cmp4.eq	p06,p07,0xA,r15; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C4F80; }

l40000000000C4F70:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x7D,r15; (p06) br.cond.dptk.few	40000000000C4BE0; }

l40000000000C4F80:
	{ adds	r36,0x1,r36; adds	r43,0x0,r0; br.cond.sptk.few	40000000000C4A80 }

l40000000000C4F90:
	{ adds	r15,0x1,r37; ld1	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x28,r15; (p06) br.cond.dptk.few	40000000000C4E50 }

l40000000000C4FC0:
	{ adds	r54,0x30,r12; nop.m	0x0; adds	r36,0x2,r36 }
	{ adds	r53,0x0,r32; nop.m	0x0; adds	r55,0x0,r0; }
	{ st4	[r36],r54; nop.i	0x0; br.call.sptk.many	b0,extract_command_subst; }
	{ adds	r14,0x30,r12; adds	r1,0x0,r51; adds	r53,0x0,r8; }
	{ ld4	r36,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r51; adds	r36,0x1,r36; br.cond.sptk.few	40000000000C4A80 }

l40000000000C5020:
	{ cmp4.eq	p06,p07,0x0,r39; (p06) cmp.eq.unc	p08,p00,r0,r0; (p07) cmp.eq.unc	p09,p00,r0,r0; }

l40000000000C502C:
	{ Invalid; break.m	0x1000; Invalid; }

l40000000000C5030:
	{ nop.m	0x0; cmp4.eq.or.andcm	p08,p09,0x22,r39; (p08) br.cond.dptk.few	40000000000C5050; }

l40000000000C5040:
	{ nop.m	0x0; cmp4.eq	p09,p08,0x60,r39; (p08) br.cond.dptk.few	40000000000C4AF0 }

l40000000000C5050:
	{ adds	r36,0x1,r36; addl	r40,1,r0; br.cond.sptk.few	40000000000C4A80 }

l40000000000C5060:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r14,0x0,r8; (p07) br.cond.spnt.few	40000000000C4B90; }

l40000000000C507C:
	{ Invalid; add	r0,r32,r0; zxt1	r0,r64 }

l40000000000C5080:
	{ nop.m	0x0; adds	r36,0x1,r36; br.cond.sptk.few	40000000000C4A80; }

l40000000000C5090:
	{ adds	r36,0x1,r36; adds	r39,0x0,r8; br.cond.sptk.few	40000000000C4A80 }

l40000000000C50A0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r14,0x0,r8; (p07) br.cond.spnt.few	40000000000C4D70; }

l40000000000C50BC:
	{ (p38) shladd	r127,r127,0x1,r36; zxt1	r0,r64; zxt1	r0,r64 }

l40000000000C50C0:
	{ adds	r36,0x1,r36; adds	r40,0x0,r0; br.cond.sptk.few	40000000000C4A80 }

l40000000000C50D0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x7B,r8; nop.i	0x0; }
	{ (p07) adds	r43,0x1,r43; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000C5200; }

l40000000000C50E6:
	{ chk.a.nc	f0,3FFFFFFFFF0C58E6; Invalid; (p16) nop }

l40000000000C50F0:
	{ cmp4.eq	p09,p08,0x0,r43; cmp4.eq	p06,p07,0x7D,r8; (p06) addl	r16,1,r0 }

l40000000000C5100:
	{ (p08) addl	r15,1,r0; (p07) adds	r16,0x0,r0; (p09) adds	r15,0x0,r0; }

l40000000000C5106:
	{ (p08) addl	r0,24832,r0; (p07) nop; (p48) nop; }

l40000000000C510C:
	{ cmp.eq	p00,p11,r0,r66; (p49) cmp.lt	p03,p16,r4,r3; czx1.r	r96,r97; }

l40000000000C5110:
	{ and	r15,r15,r16; cmp4.eq	p06,p07,0x0,r15; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r43,0xFFFFFFFFFFFFFFFF,r43; (p07) br.cond.dptk.few	40000000000C5200 }

l40000000000C512C:
	{ (p07) cmp.lt	p00,p11,r0,r33; mov	pr,r98,0xE616; zxt4	r0,r0 }

l40000000000C5130:
	{ cmp4.eq	p06,p07,0x2C,r8; (p06) addl	r8,1,r0; nop.i	0x0; }

l40000000000C513C:
	{ Invalid; zxt1	r0,r64; zxt1	r2,r3 }

l40000000000C5146:
	{ Invalid; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD889D6; nop; break.i	0x80000 }

l40000000000C5160:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r44; (p07) br.cond.dptk.few	40000000000C5330; }

l40000000000C5170:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r14; (p06) br.cond.dptk.few	40000000000C5200 }

l40000000000C5180:
	{ addl	r54,-8908,r1; adds	r53,0x0,r37; addl	r55,2,r0; }
	{ ld8	r54,[r54]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C020; }
	{ adds	r1,0x0,r51; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000000C5200 }

l40000000000C51B0:
	{ adds	r14,0x2,r37; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x7D,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C5200; }

l40000000000C51E0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r44; (p07) br.cond.dptk.few	40000000000C5330; }

l40000000000C51F0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000C5200:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r51; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	40000000000C5080; }

l40000000000C5220:
	{ ld1	r14,[r37]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r41; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000C5290; }

l40000000000C5270:
	{ (p06) addl	r15,1,r0; nop.m	0x0; nop.i	0x0; }

l40000000000C5276:
	{ break.m	0x4000; nop; break.i	0x80000 }

l40000000000C5280:
	{ nop.m	0x0; add	r36,r15,r36; br.cond.sptk.few	40000000000C4A80 }

l40000000000C5290:
	{ adds	r15,0x10,r12; ld8	r14,[r42]; adds	r53,0x0,r0 }
	{ adds	r54,0x0,r37; sub	r55,r33,r38; adds	r56,0x0,r42; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; nop.m	0x0; adds	r1,0x0,r51; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C5340; }

l40000000000C52E0:
	{ adds	r15,0x10,r12; nop.m	0x0; adds	r36,0x1,r36; }
	{ nop.m	0x0; ld8	r14,[r15]; nop.i	0x0; }
	{ st8	[r14],r42; nop.i	0x0; br.cond.sptk.few	40000000000C4A80 }

l40000000000C5310:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.sptk.few	40000000000C5200 }

l40000000000C5320:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000C5170 }

l40000000000C5330:
	{ adds	r47,0x1,r47; adds	r43,0x0,r0; br.cond.sptk.few	40000000000C5200 }

l40000000000C5340:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ (p07) adds	r15,0x0,r8; nop.i	0x0; (p07) br.cond.spnt.few	40000000000C5280; }

l40000000000C5356:
	{ chk.a.nc	f0,3FFFFFFFFF0C5B56; nop; break.i	0x80000 }

l40000000000C5360:
	{ nop.m	0x0; adds	r36,0x1,r36; br.cond.sptk.few	40000000000C4A80; }
40000000000C5370 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; brace_expand: 40000000000C5380
;;   Called from:
;;     40000000000A7AAC (in fn40000000000A7940)
;;     40000000000C5CCC (in brace_expand)
;;     40000000000C5E1C (in brace_expand)
;;     40000000000C662C (in brace_expand)
;;     40000000000C662C (in brace_expand)
brace_expand proc
	{ alloc	r53,ar.pfs,0x1D,0x0,0x18; adds	r12,0xFFFFFFFFFFFFFFB0,r12; nop.b	0x0 }
	{ adds	r54,0x0,r1; mov	r55,pr; adds	r56,0x0,r32; }
	{ adds	r38,0x30,r12; nop.m	0x0; mov	r52,b4 }
	{ adds	r33,0x58,r12; nop.m	0x0; adds	r36,0x54,r12; }
	{ st8	[r0],r38; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r54; nop.m	0x0; adds	r34,0x0,r8 }
	{ st4	[r0],r33; nop.m	0x0; nop.i	0x0; }

l40000000000C53F0:
	{ adds	r56,0x0,r32; adds	r57,0x0,r34; nop.i	0x0 }
	{ adds	r58,0x0,r33; addl	r59,123,r0; br.call.sptk.many	b0,fn40000000000C4A00; }
	{ adds	r1,0x0,r54; adds	r35,0x0,r8; cmp4.eq	p06,p07,0x0,r8 }
	{ adds	r56,0x0,r32; adds	r57,0x0,r34; (p06) br.cond.dpnt.few	40000000000C5490; }

l40000000000C5430:
	{ ld4	r14,[r33]; adds	r58,0x0,r36; addl	r59,125,r0; }
	{ nop.m	0x0; adds	r14,0x1,r14; nop.i	0x0; }
	{ st4	[r14],r36; nop.i	0x0; br.call.sptk.many	b0,fn40000000000C4A00; }
	{ adds	r1,0x0,r54; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000000C5490 }

l40000000000C5470:
	{ ld4	r14,[r33]; adds	r14,0x1,r14; nop.i	0x0; }
	{ st4	[r14],r33; nop.i	0x0; br.cond.sptk.few	40000000000C53F0 }

l40000000000C5490:
	{ ld4	r14,[r33]; adds	r56,0x1,r14; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r56,r56; br.call.sptk.many	b0,xmalloc; }
	{ nop.m	0x0; ld4	r14,[r33]; adds	r37,0x0,r8 }
	{ adds	r1,0x0,r54; adds	r57,0x0,r32; adds	r56,0x0,r8; }
	{ nop.m	0x0; sxt4	r58,r14; br.call.sptk.many	b0,fn400000000001B920; }
	{ ld4	r15,[r33]; adds	r1,0x0,r54; addl	r56,16,r0; }
	{ nop.m	0x0; sxt4	r14,r15; add	r14,r37,r14; }
	{ st1	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r14,0x0,r8; adds	r36,0x0,r8; adds	r1,0x0,r54 }
	{ cmp4.eq	p07,p06,0x7B,r35; st8	[r14],r8,8; adds	r8,0x0,r36; }
	{ st8	[r0],r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000C5570; }

l40000000000C5540:
	{ nop.m	0x0; mov	pr,r55,0xFFFFFFFFFFFFFFFE; nop.i	0x0; }
	{ nop.m	0x0; mov.i	ar.pfs,r53; mov.spnt	b0,r52,40000000000C5550 }
	{ nop.m	0x0; adds	r12,0x50,r12; br.ret	b0 }

l40000000000C5570:
	{ ld4	r40,[r33]; addl	r39,-9996,r1; adds	r57,0x0,r34 }
	{ adds	r58,0x0,r33; addl	r59,125,r0; adds	r56,0x0,r32; }
	{ adds	r40,0x1,r40; ld8	r39,[r39]; adds	r35,0x54,r12 }
	{ nop.m	0x0; adds	r41,0x20,r12; nop.i	0x0; }
	{ st4	[r40],r33; nop.i	0x0; br.call.sptk.many	b0,fn40000000000C4A00; }
	{ cmp4.eq	p07,p06,0x0,r8; adds	r1,0x0,r54; nop.i	0x0 }
	{ adds	r57,0x0,r40; adds	r56,0x0,r32; (p07) br.cond.dpnt.few	40000000000C5BC0; }

l40000000000C55E0:
	{ ld4	r58,[r33]; nop.i	0x0; br.call.sptk.many	b0,substring; }
	{ ld4	r14,[r33]; adds	r1,0x0,r54; adds	r34,0x0,r8 }
	{ st8	[r0],r38; st4	[r0],r35; adds	r15,0x0,r0; }
	{ sub	r40,r14,r40; nop.i	0x0; sxt4	r44,r40; }

l40000000000C5620:
	{ nop.m	0x0; sxt4	r14,r15; add	r14,r34,r14; }
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000C58F0; }

l40000000000C5650:
	{ cmp4.eq	p07,p06,0x5C,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000C57D0; }

l40000000000C5660:
	{ cmp4.eq	p06,p07,0x2C,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C5C50; }

l40000000000C5670:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ ld4	r15,[r35]; nop.m	0x0; adds	r1,0x0,r54 }
	{ cmp.ltu	p07,p06,0x1,r8; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000C57B0; }

l40000000000C56A0:
	{ nop.m	0x0; sxt4	r58,r15; add	r57,r34,r58; }
	{ ld1	r14,[r57]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r19,r14,5,3; and	r18,0x1F,r14; }
	{ shladd	r14,r19,0x2,r39; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r18; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x0; (p07) br.cond.dpnt.few	40000000000C5730 }

l40000000000C5700:
	{ addl	r14,1,r0; nop.m	0x0; nop.i	0x0; }

l40000000000C5710:
	{ nop.m	0x0; add	r15,r15,r14; nop.i	0x0; }
	{ st4	[r15],r35; nop.i	0x0; br.cond.sptk.few	40000000000C5620 }

l40000000000C5730:
	{ ld8	r14,[r38]; nop.m	0x0; adds	r56,0x0,r0 }
	{ sub	r58,r44,r58; nop.m	0x0; adds	r59,0x0,r38; }
	{ st8	[r14],r41; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; nop.m	0x0; adds	r1,0x0,r54; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C68B0; }

l40000000000C5780:
	{ ld4	r15,[r35]; ld8	r14,[r41]; nop.i	0x0; }
	{ adds	r15,0x1,r15; st8	[r14],r38; nop.i	0x0; }
	{ st4	[r15],r35; nop.i	0x0; br.cond.sptk.few	40000000000C5620 }

l40000000000C57B0:
	{ nop.m	0x0; adds	r15,0x1,r15; nop.i	0x0; }
	{ st4	[r15],r35; nop.i	0x0; br.cond.sptk.few	40000000000C5620 }

l40000000000C57D0:
	{ nop.m	0x0; adds	r15,0x1,r15; nop.i	0x0; }
	{ st4	[r15],r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ ld4	r15,[r35]; nop.m	0x0; adds	r1,0x0,r54 }
	{ cmp.ltu	p07,p06,0x1,r8; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000C57B0; }

l40000000000C5810:
	{ nop.m	0x0; sxt4	r58,r15; add	r57,r34,r58; }
	{ ld1	r14,[r57]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r18,r14,5,3; and	r17,0x1F,r14; }
	{ shladd	r14,r18,0x2,r39; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r17; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x0; (p06) br.cond.dptk.few	40000000000C5700 }

l40000000000C5870:
	{ adds	r15,0x28,r12; ld8	r14,[r38]; nop.i	0x0 }
	{ adds	r56,0x0,r0; sub	r58,r44,r58; adds	r59,0x0,r38; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r1,0x0,r54; adds	r16,0x28,r12; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C68B0; }

l40000000000C58C0:
	{ ld4	r15,[r35]; ld8	r14,[r16]; nop.i	0x0; }
	{ adds	r15,0x1,r15; st8	[r14],r38; nop.i	0x0; }
	{ st4	[r15],r35; nop.i	0x0; br.cond.sptk.few	40000000000C5620 }

l40000000000C58F0:
	{ addl	r57,-8908,r1; nop.m	0x0; adds	r56,0x0,r34; }
	{ ld8	r57,[r57]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A3C0; }
	{ cmp.eq	p06,p07,0x0,r8; sub	r14,r8,r34; adds	r1,0x0,r54 }
	{ adds	r56,0x0,r34; adds	r57,0x0,r0; (p06) br.cond.dpnt.few	40000000000C5B90; }

l40000000000C5930:
	{ adds	r35,0x0,r14; nop.m	0x0; adds	r58,0x0,r14 }
	{ adds	r43,0x0,r14; nop.m	0x0; br.call.sptk.many	b0,substring; }
	{ adds	r1,0x0,r54; adds	r45,0x0,r8; adds	r56,0x0,r34 }
	{ adds	r57,0x2,r35; adds	r58,0x0,r40; br.call.sptk.many	b0,substring; }
	{ ld1	r15,[r45]; adds	r1,0x0,r54; adds	r41,0x0,r8 }
	{ adds	r56,0x0,r45; adds	r57,0x48,r12; sxt1	r15,r15; }
	{ cmp4.eq	p06,p07,0x0,r15; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C5B50; }

l40000000000C59A0:
	{ ld1	r15,[r8]; nop.m	0x0; sxt1	r15,r15; }
	{ cmp4.eq	p07,p06,0x0,r15; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000C5B50; }

l40000000000C59C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,legal_number; }
	{ adds	r1,0x0,r54; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	40000000000C6810 }

l40000000000C59E0:
	{ addl	r40,1,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C3C0; }
	{ adds	r1,0x0,r54; ld8	r16,[r8]; nop.i	0x0 }

l40000000000C5A00:
	{ ld1.a	r15,[r41]; nop.m	0x0; adds	r38,0x40,r12; }
	{ st8	[r0],r38; ld1.c.clr	r15,[r41]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; shladd	r17,r15,0x1,r16; }
	{ nop.m	0x0; ld2	r17,[r17]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r17,0xB; (p06) br.cond.dpnt.few	40000000000C5AC0; }

l40000000000C5A50:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x2B,r15; (p06) br.cond.dptk.few	40000000000C6020 }

l40000000000C5A70:
	{ adds	r14,0x1,r41; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ shladd	r16,r14,0x1,r16; nop.m	0x0; addl	r14,2048,r0; }
	{ ld2	r15,[r16]; and	r14,r14,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000C6020 }

l40000000000C5AC0:
	{ adds	r56,0x0,r41; adds	r57,0x0,r38; nop.i	0x0 }
	{ addl	r58,10,r0; adds	r59,0x0,r0; br.call.sptk.many	b0,fn400000000001A520; }
	{ ld8	r39,[r38]; adds	r1,0x0,r54; adds	r42,0x0,r8; }
	{ cmp.eq	p06,p07,0x0,r39; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C6930; }

l40000000000C5B00:
	{ ld1	r14,[r39]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000C66A0; }

l40000000000C5B20:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r14; nop.i	0x0; }
	{ nop.m	0x0; (p07) addl	r46,1,r0; (p07) br.cond.dpnt.few	40000000000C60A0 }

l40000000000C5B3C:
	{ (p43) nop; zxt1	r32,r64; break.b	0x1000 }

l40000000000C5B40:
	{ adds	r56,0x0,r45; nop.m	0x0; nop.i	0x0 }

l40000000000C5B50:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r54; adds	r56,0x0,r41 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r54; nop.m	0x0; nop.i	0x0 }

l40000000000C5B90:
	{ nop.m	0x0; adds	r56,0x0,r34; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r54; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000C5BC0:
	{ adds	r56,0x0,r37; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r54; adds	r56,0x0,r32; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r54; adds	r56,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r54; nop.m	0x0; adds	r56,0x0,r8 }
	{ adds	r57,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r54; st8	[r8],r36; nop.b	0x0 }
	{ adds	r8,0x0,r36; mov	pr,r55,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r53; }
	{ nop.m	0x0; mov.spnt	b0,r52,40000000000C5C30; nop.i	0x0 }
	{ adds	r12,0x50,r12; nop.m	0x0; br.ret	b0; }

l40000000000C5C50:
	{ adds	r37,0x50,r12; adds	r46,0x18,r12; addl	r59,44,r0 }
	{ adds	r57,0x0,r44; adds	r56,0x0,r34; adds	r58,0x0,r37 }
	{ st8	[r0],r46; st4	[r0],r37; br.call.sptk.many	b0,fn40000000000C4A00; }
	{ adds	r1,0x0,r54; adds	r56,0x0,r34; adds	r57,0x0,r0 }
	{ ld4	r58,[r37]; adds	r43,0x0,r8; addl	r45,-9996,r1; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,substring; }
	{ adds	r1,0x0,r54; nop.m	0x0; adds	r39,0x0,r8 }
	{ adds	r56,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,brace_expand; }
	{ nop.m	0x0; adds	r1,0x0,r54; adds	r35,0x0,r8 }

l40000000000C5CE0:
	{ adds	r56,0x0,r39; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r54; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r54; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	40000000000C5F80 }

l40000000000C5D10:
	{ ld4	r15,[r37]; nop.m	0x0; sxt4	r58,r15; }
	{ add	r57,r34,r58; ld1	r14,[r57]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; extr.u	r17,r14,5,3; and	r16,0x1F,r14; }
	{ shladd	r14,r17,0x2,r45; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r16; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000C5FA0; }

l40000000000C5D80:
	{ (p06) addl	r38,1,r0; nop.m	0x0; nop.i	0x0; }

l40000000000C5D86:
	{ break.m	0x4000; nop; break.i	0x80000 }

l40000000000C5D90:
	{ nop.m	0x0; add	r38,r15,r38; nop.i	0x0; }
	{ st4	[r38],r37; nop.m	0x0; nop.i	0x0 }

l40000000000C5DB0:
	{ cmp4.eq	p07,p06,0x0,r43; addl	r59,44,r0; adds	r58,0x0,r37 }
	{ adds	r56,0x0,r34; adds	r57,0x0,r44; (p07) br.cond.dpnt.few	40000000000C65D0; }

l40000000000C5DD0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000C4A00; }
	{ adds	r57,0x0,r38; ld4	r58,[r37]; adds	r43,0x0,r8 }
	{ adds	r1,0x0,r54; adds	r56,0x0,r34; br.call.sptk.many	b0,substring; }
	{ adds	r1,0x0,r54; nop.m	0x0; adds	r39,0x0,r8 }
	{ adds	r56,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,brace_expand; }
	{ cmp.eq	p06,p07,0x0,r35; adds	r38,0x0,r8; adds	r1,0x0,r54; }
	{ (p06) adds	r35,0x0,r8; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C5CE0; }

l40000000000C5E36:
	{ chk.a.nc	r0,3FFFFFFFFF0C6636; nop; nop }

l40000000000C5E40:
	{ adds	r56,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,strvec_len; }
	{ adds	r42,0x0,r8; nop.m	0x0; adds	r1,0x0,r54 }
	{ adds	r56,0x0,r38; nop.m	0x0; br.call.sptk.many	b0,strvec_len; }
	{ add	r41,r42,r8; nop.m	0x0; adds	r40,0x0,r8 }
	{ adds	r1,0x0,r54; nop.m	0x0; adds	r56,0x0,r35; }
	{ adds	r57,0x1,r41; nop.i	0x0; br.call.sptk.many	b0,strvec_resize; }
	{ adds	r17,0xFFFFFFFFFFFFFFFF,r40; adds	r16,0x8,r38; sxt4	r15,r42 }
	{ cmp4.lt	p07,p06,0x0,r40; adds	r14,0x0,r38; adds	r1,0x0,r54; }
	{ addp4	r17,r17,r0; shladd	r15,r15,0x3,r8; nop.i	0x0 }
	{ adds	r35,0x0,r8; (p06) adds	r41,0x0,r42; (p06) br.cond.dpnt.few	40000000000C5F20; }

l40000000000C5EDC:
	{ (p02) nop; zxt1	r4,r4; break.b	0x1000 }

l40000000000C5EE0:
	{ shladd	r17,r17,0x3,r16; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000C5F00:
	{ nop.m	0x0; ld8	r16,[r14],8; nop.i	0x0; }
	{ st8	[r15],r8,8; cmp.eq	p07,p06,r17,r14; (p06) br.cond.dptk.few	40000000000C5F00 }

l40000000000C5F20:
	{ nop.m	0x0; sxt4	r41,r41; adds	r56,0x0,r38; }
	{ nop.m	0x0; shladd	r41,r41,0x3,r35; nop.i	0x0; }
	{ st8	[r0],r41; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r54; adds	r56,0x0,r39; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r54; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r54; cmp.ltu	p07,p06,0x1,r8; (p07) br.cond.dptk.few	40000000000C5D10 }

l40000000000C5F80:
	{ ld4	r38,[r37]; adds	r38,0x1,r38; nop.i	0x0; }
	{ st4	[r38],r37; nop.i	0x0; br.cond.sptk.few	40000000000C5DB0 }

l40000000000C5FA0:
	{ nop.m	0x0; ld8	r14,[r46]; adds	r15,0x10,r12 }
	{ adds	r56,0x0,r0; sub	r58,r44,r58; adds	r59,0x0,r46; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r1,0x0,r54; adds	r16,0x10,r12; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C68F0; }

l40000000000C5FF0:
	{ ld4	r38,[r37]; ld8	r14,[r16]; nop.i	0x0; }
	{ adds	r38,0x1,r38; st8	[r14],r46; nop.i	0x0; }
	{ st4	[r38],r37; nop.i	0x0; br.cond.sptk.few	40000000000C5DB0 }

l40000000000C6020:
	{ nop.m	0x0; tbit.z	p06,p07,r17,0xA; (p06) br.cond.dptk.few	40000000000C5B40 }

l40000000000C6030:
	{ adds	r39,0x1,r41; ld1	r14,[r39]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x2E,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000C5B40; }

l40000000000C6060:
	{ st8	[r39],r38; nop.m	0x0; cmp.eq	p06,p07,0x0,r39 }
	{ addl	r46,2,r0; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000C6980; }

l40000000000C6080:
	{ ld1	r14,[r39]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2E,r14; (p07) br.cond.dptk.few	40000000000C66B0 }

l40000000000C60A0:
	{ adds	r14,0x1,r39; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r14; (p07) br.cond.dpnt.few	40000000000C6730 }

l40000000000C60D0:
	{ nop.m	0x0; ld8	r14,[r38]; addl	r49,1,r0 }
	{ adds	r46,0x0,r0; nop.i	0x0; sub	r39,r39,r14; }

l40000000000C60F0:
	{ cmp4.eq	p06,p07,r46,r40; nop.m	0x0; adds	r15,0x48,r12 }
	{ sub	r43,0xFFFFFFFFFFFFFFFE,r43; nop.m	0x0; add	r14,r39,r44; }
	{ cmp4.eq.or.andcm	p07,p06,0x0,r40; add	r14,r43,r14; (p07) br.cond.dpnt.few	40000000000C5B40; }

l40000000000C6120:
	{ cmp4.eq	p07,p06,0x2,r40; (p07) ld1	r38,[r45]; (p07) addl	r46,1,r0 }

l40000000000C612C:
	{ Invalid; Invalid; Invalid }

l40000000000C6130:
	{ (p07) ld1	r42,[r41]; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000C62B0; }

l40000000000C6136:
	{ chk.a.nc	f0,3FFFFFFFFF0C6936; nop; (p32) nop }

l40000000000C6140:
	{ ld8	r38,[r15]; cmp4.lt	p07,p06,0x1,r35; (p06) br.cond.dpnt.few	40000000000C61A0; }

l40000000000C6150:
	{ nop.m	0x0; ld1	r15,[r45]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; cmp4.eq	p06,p07,0x30,r15; }
	{ (p06) adds	r46,0x0,r35; (p06) addl	r40,3,r0; (p06) br.cond.dpnt.few	40000000000C61B0; }

l40000000000C6176:
	{ (p20) chk.a.clr	r3,3FFFFFFFFF2C6176; nop; (p32) nop; }

l40000000000C617C:
	{ (p02) cmp.lt	p00,p17,r64,r33; czx1.r	r96,r97; mov	pr,r32,0x0 }

l40000000000C6180:
	{ cmp4.eq	p06,p07,0x2,r35; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C61A0; }

l40000000000C6190:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r15; (p07) br.cond.dpnt.few	40000000000C66F0 }

l40000000000C61A0:
	{ nop.m	0x0; adds	r46,0x0,r0; addl	r40,1,r0; }

l40000000000C61B0:
	{ cmp4.lt	p07,p06,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C6240; }

l40000000000C61C0:
	{ ld1	r15,[r41]; nop.m	0x0; sxt1	r15,r15; }
	{ cmp4.eq	p07,p06,0x30,r15; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000C6230; }

l40000000000C61E0:
	{ cmp4.eq	p06,p07,0x2,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C6240; }

l40000000000C61F0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r15; (p06) br.cond.dptk.few	40000000000C6240 }

l40000000000C6200:
	{ adds	r15,0x1,r41; ld1	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x30,r15; (p06) br.cond.dptk.few	40000000000C6240; }

l40000000000C6230:
	{ cmp4.lt	p06,p07,r46,r14; (p06) addl	r40,3,r0; (p06) adds	r46,0x0,r14; }

l40000000000C623C:
	{ cmp.lt	p14,p09,r0,r66; break.x	0x1843A35C001000; }

l40000000000C6240:
	{ cmp4.lt	p06,p07,r46,r35; nop.m	0x0; cmp4.eq	p08,p09,0x3,r40; }
	{ (p06) addl	r16,1,r0; nop.m	0x0; (p08) addl	r15,1,r0; }

l40000000000C6256:
	{ addl	r0,0,r1; (p07) cmp4.eq.and	p01,p08,0x0,r0; (p01) nop }

l40000000000C6260:
	{ (p07) adds	r16,0x0,r0; (p09) adds	r15,0x0,r0; and	r16,r16,r15; }

l40000000000C6266:
	{ Invalid; (p08) br.call.dpnt.few.clr	b0,b7; Invalid }

l40000000000C626C:
	{ (p08) cmp.lt	p15,p11,r12,r64; cmp4.eq.and	p00,p60,r100,r97; zxt1	r96,r64 }

l40000000000C627C:
	{ cmp.lt	p00,p11,r1,r0; (p32) mov	pr,r99,0xC296; zxt4	r0,r0 }

l40000000000C628C:
	{ Invalid; (p02) cmp.eq	p00,p16,r0,r64; zxt1	r100,r3 }

l40000000000C6296:
	{ Invalid; nop; Invalid }
	{ (p20) chk.a.clr	f3,3FFFFFFFFF2C62A6; (p23) nop; (p32) nop; }

l40000000000C62AC:
	{ cmp.lt	p14,p11,r0,r66; (p32) nop; }

l40000000000C62B0:
	{ sub	r14,r42,r38; cmp4.lt	p07,p06,r14,r0; nop.i	0x0; }
	{ (p06) adds	r56,0x0,r14; (p07) sub	r56,r0,r14; nop.i	0x0; }

l40000000000C62C6:
	{ Invalid; nop; nop; }

l40000000000C62CC:
	{ Invalid; zxt1	r0,r64; break.i	0x1000 }
	{ (p51) cmp.lt.unc	p19,p09,r1,r40; nop; nop }
	{ cmp4.eq.and	p08,p17,r0,r66; (p22) nop }

l40000000000C62F6:
	{ (p24) chk.a.clr	r1,3FFFFFFFFF2C62F6; nop; break.b	0x80000; }

l40000000000C62FC:
	{ (p01) nop; cmp.lt	p00,p00,r32,r0; nop }

l40000000000C6300:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x0,r49; nop.i	0x0; }
	{ (p06) addl	r14,1,r0; nop.i	0x0; (p07) adds	r14,0x0,r0 }

l40000000000C6316:
	{ chk.a.nc	f0,3FFFFFFFFF0C6B16; (p07) nop; (p32) nop }

l40000000000C6320:
	{ cmp.lt	p06,p07,r42,r38; (p07) adds	r15,0x0,r0; nop.i	0x0; }

l40000000000C632C:
	{ cmp4.eq.or.andcm	p00,p11,r1,r0; (p17) cmp.lt	p00,p18,r0,r0; zxt1	r99,r3 }

l40000000000C6336:
	{ Invalid; nop; (p32) nop }
	{ Invalid; nop; Invalid; }

l40000000000C634C:
	{ Invalid; nop; (p37) mov	pr,r12,0x525E }

l40000000000C635C:
	{ (p02) cmp.lt	p00,p03,r0,r33; (p32) shladdp4	r73,r106,0x1,r1; (p37) cmp4.eq.and	p47,p10,r12,r32 }

l40000000000C6360:
	{ cmp.lt	p06,p07,r38,r42; extr.u	r44,r49,31,1; (p06) addl	r14,1,r0; }

l40000000000C6370:
	{ (p07) adds	r14,0x0,r0; and	r14,r14,r44; nop.i	0x0; }

l40000000000C6376:
	{ Invalid; nop; (p32) nop }
	{ (p24) chk.a.clr	f0,3FFFFFFFFF0C8E96; (p22) nop; (p48) nop; }

l40000000000C638C:
	{ ldf8	f0,[r66]; nop; }

l40000000000C6390:
	{ addl	r43,7676,r1; cmp4.lt	p06,p07,0x0,r49; addl	r47,7684,r1 }
	{ cmp4.eq	p17,p16,0x1,r40; cmp4.eq	p19,p18,0x3,r40; adds	r39,0x0,r0; }
	{ nop.m	0x0; (p06) addl	r48,1,r0; sxt4	r49,r49 }

l40000000000C63BC:
	{ Invalid; Invalid; Invalid }
	{ nop; mov	pr,r32,0x0; (p06) dep	r0,r0,r64,62,1 }

l40000000000C63DC:
	{ Invalid; Invalid; Invalid }

l40000000000C63E0:
	{ nop.m	0x0; ld4.acq	r14,[r43]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000C6420 }

l40000000000C6400:
	{ ld4.acq	r56,[r50]; br.call.sptk.many	b0,termsig_handler; nop.b	0x0; }
	{ adds	r1,0x0,r54; nop.m	0x0; nop.i	0x0 }

l40000000000C6420:
	{ nop.m	0x0; ld4.acq	r14,[r47]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000C6460 }

l40000000000C6440:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,throw_to_top_level; }
	{ adds	r1,0x0,r54; nop.m	0x0; nop.i	0x0; }

l40000000000C6460:
	{ addl	r56,2,r0; (p19) addl	r58,-8900,r1; (p19) addl	r57,1,r0 }

l40000000000C646C:
	{ nop; Invalid; (p07) nop; }

l40000000000C6470:
	{ (p19) adds	r59,0x0,r46; (p19) adds	r60,0x0,r38; (p17) br.cond.dpnt.few	40000000000C67D0; }

l40000000000C6476:
	{ (p30) nop; nop }

l40000000000C647C:
	{ (p27) nop; chk.s.i	r32,3FFFFFFFFF8C647C; zxt1	r0,r64 }

l40000000000C6480:
	{ nop.m	0x0; (p19) adds	r56,0x0,r40; nop.i	0x0 }

l40000000000C648C:
	{ Invalid; Invalid; chk.s.i	r32,3FFFFFFFFF8C648C }

l40000000000C6496:
	{ nop; (p32) nop; cmp.lt	p00,p00,r0,r32 }

l40000000000C64A0:
	{ nop.m	0x0; sxt4	r15,r39; nop.b	0x0 }
	{ (p19) ld8	r14,[r40]; (p19) adds	r1,0x0,r54; (p19) adds	r39,0x1,r39; }

l40000000000C64B6:
	{ Invalid; Invalid; Invalid }

l40000000000C64BC:
	{ Invalid; Invalid; Invalid }

l40000000000C64C0:
	{ nop.m	0x0; (p19) shladd	r15,r15,0x3,r35; nop.i	0x0; }

l40000000000C64CC:
	{ Invalid; break.i	0x1000; chk.s.i	r32,3FFFFFFFFF0C64CC }
	{ (p63) invala; cmp.ge.or.andcm	p00,p00,r0,r0; (p01) break.b	0x164E0 }

l40000000000C64E0:
	{ nop.m	0x0; sxt4	r15,r39; nop.b	0x0 }
	{ (p18) st8	[r8],r40; (p18) st1	[r38],r8; (p18) adds	r1,0x0,r54; }

l40000000000C64F6:
	{ nop; (p36) nop }

l40000000000C64FC:
	{ cmp.ge.and	p54,p09,r0,r66; (p01) cmp.ge.or.andcm	p00,p08,r0,r6; (p49) cmp.lt.or.andcm	p35,p16,r0,r4 }

l40000000000C6500:
	{ (p18) ld8	r14,[r40]; (p18) shladd	r15,r15,0x3,r35; (p18) adds	r39,0x1,r39; }

l40000000000C6506:
	{ Invalid; Invalid; Invalid }

l40000000000C650C:
	{ Invalid; Invalid; Invalid }

l40000000000C6510:
	{ (p18) adds	r14,0x1,r14; (p18) st1	[r0],r14; nop.i	0x0; }

l40000000000C6516:
	{ mf.a; nop }

l40000000000C651C:
	{ nop; cmp.ge.and	p00,p00,r0,r0; Invalid }

l40000000000C652C:
	{ nop; Invalid; break.i	0x1000 }
	{ cmp.lt	p00,p11,r1,r0; zxt1	r41,r0; (p33) cmp.lt.unc	p09,p24,r42,r2 }

l40000000000C6540:
	{ add	r38,r38,r49; cmp.lt	p08,p09,r38,r42; cmp.lt	p06,p07,r42,r38; }
	{ (p08) addl	r14,1,r0; tbit.z.or.andcm	p07,p06,r48,0x0; (p09) adds	r14,0x0,r0; }

l40000000000C6556:
	{ (p03) nop; (p07) nop; break.b	0x80000 }

l40000000000C6560:
	{ nop.m	0x0; and	r14,r14,r44; nop.i	0x0; }
	{ cmp4.eq	p08,p09,0x0,r14; (p09) br.cond.dpnt.few	40000000000C6580; (p07) br.cond.dptk.few	40000000000C63E0 }

l40000000000C657C:
	{ (p51) nop.m	0x95FFF; cmp.lt	p00,p00,r32,r0; (p01) break.b	0x164E0 }

l40000000000C6580:
	{ nop.m	0x0; sxt4	r14,r39; adds	r56,0x0,r45; }
	{ nop.m	0x0; shladd	r14,r14,0x3,r35; nop.i	0x0; }
	{ st8	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r54; adds	r56,0x0,r41; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r54; cmp.eq	p07,p06,0x0,r35; (p07) br.cond.spnt.few	40000000000C5B90 }

l40000000000C65D0:
	{ adds	r57,0x0,r35; adds	r56,0x0,r36; br.call.sptk.many	b0,fn40000000000C46C0; }
	{ adds	r1,0x0,r54; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r56,0x0,r34; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r54; adds	r56,0x0,r35; br.call.sptk.many	b0,strvec_dispose; }
	{ ld4	r56,[r33]; adds	r1,0x0,r54; sxt4	r56,r56; }
	{ add	r56,r32,r56,0x1; nop.i	0x0; br.call.sptk.many	b0,brace_expand; }
	{ adds	r1,0x0,r54; adds	r33,0x0,r8; nop.i	0x0 }
	{ adds	r56,0x0,r36; adds	r57,0x0,r8; br.call.sptk.many	b0,fn40000000000C46C0; }
	{ adds	r1,0x0,r54; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r56,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,strvec_dispose; }
	{ adds	r8,0x0,r36; adds	r1,0x0,r54; mov	pr,r55,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r53; mov.spnt	b0,r52,40000000000C6680 }
	{ nop.m	0x0; adds	r12,0x50,r12; br.ret	b0 }

l40000000000C66A0:
	{ addl	r46,1,r0; nop.m	0x0; nop.i	0x0 }

l40000000000C66B0:
	{ ld8	r14,[r38]; addl	r49,1,r0; sub	r39,r39,r14; }
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000C60F0 }

l40000000000C66E0:
	{ nop.m	0x0; adds	r46,0x0,r0; br.cond.sptk.few	40000000000C60F0 }

l40000000000C66F0:
	{ adds	r15,0x1,r45; ld1	r46,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r46,r46; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x30,r46; (p06) addl	r40,3,r0; (p06) adds	r46,0x0,r35; }

l40000000000C671C:
	{ Invalid; (p05) nop; }

l40000000000C6720:
	{ (p07) addl	r40,1,r0; (p07) adds	r46,0x0,r0; br.cond.sptk.few	40000000000C61B0 }

l40000000000C6726:
	{ Invalid; nop; nop; }

l40000000000C672C:
	{ Invalid; (p39) cmp.lt.unc	p32,p16,r9,r64; (p01) rfi }

l40000000000C6730:
	{ adds	r56,0x2,r39; ld1	r14,[r56]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000C60D0 }

l40000000000C6760:
	{ adds	r57,0x0,r38; nop.m	0x0; addl	r58,10,r0 }
	{ adds	r59,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A520; }
	{ ld8	r14,[r38]; adds	r1,0x0,r54; adds	r49,0x0,r8; }
	{ sub	r39,r39,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000C60F0 }

l40000000000C67C0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000C66E0 }

l40000000000C67D0:
	{ nop.m	0x0; sxt4	r51,r39; nop.i	0x0 }
	{ adds	r56,0x0,r38; adds	r39,0x1,r39; br.call.sptk.many	b0,itos; }
	{ shladd	r51,r51,0x3,r35; nop.m	0x0; adds	r1,0x0,r54; }
	{ st8	[r8],r51; nop.i	0x0; br.cond.sptk.few	40000000000C6540 }

l40000000000C6810:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C3C0; }
	{ nop.m	0x0; ld1	r14,[r45]; adds	r1,0x0,r54 }
	{ ld8	r16,[r8]; nop.m	0x0; sxt1	r14,r14; }
	{ shladd	r14,r14,0x1,r16; ld2	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0xA; nop.i	0x0; }
	{ nop.m	0x0; (p06) adds	r40,0x0,r0; (p06) br.cond.dptk.few	40000000000C5A00 }

l40000000000C686C:
	{ (p13) cmp.lt.unc	p62,p11,r63,r37; zxt1	r32,r64; Invalid }

l40000000000C6870:
	{ adds	r14,0x1,r45; ld1	r40,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r40,r40; cmp4.eq	p07,p06,0x0,r40; }
	{ nop.m	0x0; (p06) adds	r40,0x0,r0; nop.i	0x0; }

l40000000000C689C:
	{ invala; mov	pr,r32,0x0; zxt4	r0,r0 }

l40000000000C68AC:
	{ (p11) nop; cmp.lt	p00,p00,r32,r0; czx1.r	r0,r65 }

l40000000000C68B0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ (p07) ld4	r15,[r35]; (p07) adds	r14,0x0,r8; (p07) br.cond.spnt.few	40000000000C5710; }

l40000000000C68C6:
	{ (p07) chk.a.clr	f0,3FFFFFFFFF146946; nop; (p48) nop; }

l40000000000C68CC:
	{ (p50) cmp.eq.unc	p61,p11,r127,r36; (p01) cmp.eq.unc	p32,p08,r8,r4; (p17) epc }

l40000000000C68D0:
	{ ld4	r15,[r35]; adds	r15,0x1,r15; nop.i	0x0; }
	{ st4	[r15],r35; nop.i	0x0; br.cond.sptk.few	40000000000C5620 }

l40000000000C68F0:
	{ cmp.eq	p06,p07,0x0,r8; nop.m	0x0; (p07) adds	r38,0x0,r8 }

l40000000000C6900:
	{ nop.m	0x0; (p07) ld4	r15,[r37]; (p07) br.cond.spnt.few	40000000000C5D90; }

l40000000000C690C:
	{ (p36) cmp.lt.unc	p62,p11,r127,r36; (p04) cmp.lt	p32,p08,r9,r4; (p20) epc }

l40000000000C6910:
	{ ld4	r38,[r37]; adds	r38,0x1,r38; nop.i	0x0; }
	{ st4	[r38],r37; nop.i	0x0; br.cond.sptk.few	40000000000C5DB0 }

l40000000000C6930:
	{ adds	r14,0x0,r0; adds	r39,0x0,r0; addl	r46,1,r0 }
	{ addl	r49,1,r0; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000C60F0 }

l40000000000C6970:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000C66E0 }

l40000000000C6980:
	{ adds	r14,0x0,r0; adds	r39,0x0,r0; addl	r46,2,r0 }
	{ addl	r49,1,r0; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000C60F0 }

l40000000000C69C0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000C66E0; }
40000000000C69D0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000C69E0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000C69F0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000C6A00 08 A8 6D 2E 80 05 60 03 04 00 42 C0 01 08 59 00 ..m...`...B...Y.
40000000000C6A10 09 40 01 42 00 21 E0 FA 8B 7E 46 A0 05 18 59 00 .@.B.!...~F...Y.
40000000000C6A20 08 B8 41 00 00 24 30 03 00 00 42 80 06 00 C4 00 ..A..$0...B.....
40000000000C6A30 09 48 41 00 00 24 00 DB 03 00 48 40 D6 07 00 90 .HA..$....H@....
40000000000C6A40 10 78 B1 00 00 24 70 10 85 0C 71 03 70 00 00 42 .x...$p...q.p..B
40000000000C6A50 0B 70 38 40 12 20 70 03 38 30 20 00 00 00 04 00 .p8@. p.80 .....
40000000000C6A60 0B 30 00 6E 07 F9 71 BB B5 00 40 00 00 00 04 00 .0.n..q...@.....
40000000000C6A70 D3 B8 01 40 18 10 00 4C 58 03 28 00 00 00 00 20 ...@...LX.(.... 
40000000000C6A80 08 08 00 6C 00 21 00 00 00 02 00 00 00 00 04 00 ...l.!..........
40000000000C6A90 01 00 00 00 01 00 00 A8 01 55 00 00 00 00 04 00 .........U......
40000000000C6AA0 11 00 00 00 01 00 00 A0 05 80 03 80 08 00 84 00 ................
40000000000C6AB0 11 00 00 00 01 00 00 00 00 02 00 00 18 22 02 50 .............".P
40000000000C6AC0 08 40 00 46 89 39 70 08 89 0C 61 20 00 B0 01 84 .@.F.9p...a ....
40000000000C6AD0 09 38 01 10 00 21 00 00 20 00 23 00 00 00 04 00 .8...!.. .#.....
40000000000C6AE0 08 00 00 00 01 00 12 0B 00 00 48 63 06 00 00 84 ..........Hc....
40000000000C6AF0 19 00 00 00 01 00 00 00 00 02 00 03 80 04 00 43 ...............C
40000000000C6B00 29 89 01 00 00 21 00 00 00 02 00 00 00 00 04 00 )....!..........
40000000000C6B10 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C6B20 01 00 00 00 01 00 A0 02 A0 2C 00 80 14 40 01 84 .........,...@..
40000000000C6B30 0B 50 A9 40 12 20 60 02 A8 30 20 00 00 00 04 00 .P.@. `..0 .....
40000000000C6B40 11 B8 01 4C 00 21 00 00 00 02 00 00 88 4B F5 58 ...L.!.......K.X
40000000000C6B50 08 38 90 44 86 30 10 00 D8 00 42 A0 04 40 00 84 .8.D.0....B..@..
40000000000C6B60 11 B0 04 4C 00 21 40 01 90 2C 00 03 50 01 00 43 ...L.!@..,..P..C
40000000000C6B70 09 30 00 4C 07 39 00 00 00 02 00 80 42 01 49 80 .0.L.9......B.I.
40000000000C6B80 C3 A8 04 00 00 24 00 00 00 02 80 A3 02 00 00 84 .....$..........
40000000000C6B90 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C6BA0 03 90 20 28 18 14 10 01 58 00 42 C0 00 90 1C E4 .. (....X.B.....
40000000000C6BB0 11 30 02 2A 47 39 00 00 00 02 00 03 40 04 00 43 .0.*G9......@..C
40000000000C6BC0 0B 70 00 4C 00 10 00 00 00 02 00 C0 01 70 50 00 .p.L.........pP.
40000000000C6BD0 11 30 00 1C 87 39 00 00 00 02 00 03 20 04 00 43 .0...9...... ..C
40000000000C6BE0 0B 78 00 24 00 10 00 00 00 02 00 E0 01 78 50 00 .x.$.........xP.
40000000000C6BF0 11 30 00 1E 87 39 00 00 00 02 00 03 00 04 00 43 .0...9.........C
40000000000C6C00 11 00 00 00 01 00 70 78 38 0C 71 03 F0 03 00 43 ......px8.q....C
40000000000C6C10 09 70 00 24 00 21 00 00 00 02 00 00 00 00 04 00 .p.$.!..........
40000000000C6C20 09 78 04 22 00 14 00 00 00 02 00 C0 11 70 00 84 .x.".........p..
40000000000C6C30 01 00 00 00 01 00 F0 00 3C 28 00 60 E2 90 14 80 ........<(.`....
40000000000C6C40 11 30 00 1E 87 39 00 00 00 02 00 03 40 00 00 43 .0...9......@..C
40000000000C6C50 0B 80 00 1C 00 10 00 00 00 02 00 00 02 80 50 00 ..............P.
40000000000C6C60 11 38 00 20 86 39 00 00 00 02 80 03 20 00 00 43 .8. .9...... ..C
40000000000C6C70 11 00 00 00 01 00 70 80 3C 0C F1 03 B0 FF FF 4A ......p.<......J
40000000000C6C80 11 38 8C 26 86 30 00 00 00 02 00 03 30 00 00 43 .8.&.0......0..C
40000000000C6C90 09 20 05 48 00 21 00 00 00 02 00 A0 04 98 00 84 . .H.!..........
40000000000C6CA0 11 00 00 00 01 00 70 10 91 0C 71 03 00 FF FF 4A ......p...q....J
40000000000C6CB0 09 30 84 50 87 38 60 FA 93 7E 46 60 55 1A 15 80 .0.P.8`..~F`U...
40000000000C6CC0 C9 70 04 00 00 24 80 30 B9 12 71 80 05 58 59 00 .p...$.0..q..XY.
40000000000C6CD0 EB 70 00 00 00 21 E0 70 C4 18 40 00 00 00 04 00 .p...!.p..@.....
40000000000C6CE0 10 00 00 00 01 00 60 00 38 0E 73 03 70 00 00 42 ......`.8.s.p..B
40000000000C6CF0 11 B8 01 4E 00 21 00 00 00 02 00 04 60 00 00 43 ...N.!......`..C
40000000000C6D00 09 48 05 52 00 21 00 00 00 02 00 60 16 98 01 84 .H.R.!.....`....
40000000000C6D10 11 00 00 00 01 00 80 03 A4 2C 00 00 F8 20 02 50 .........,... .P
40000000000C6D20 09 70 00 10 00 21 10 00 D8 00 42 E0 04 40 00 84 .p...!....B..@..
40000000000C6D30 09 00 00 00 01 00 10 80 39 00 2B 00 00 00 04 00 ........9.+.....
40000000000C6D40 08 00 00 1C 80 11 00 00 00 02 00 00 00 00 04 00 ................
40000000000C6D50 11 38 98 50 86 38 70 0B AC 00 C2 03 B0 02 00 43 .8.P.8p........C
40000000000C6D60 11 00 00 00 01 00 70 03 DC 2C 00 00 68 1F 02 50 ......p..,..h..P
40000000000C6D70 08 00 00 00 01 00 80 03 A8 30 20 C0 04 40 00 84 .........0 ..@..
40000000000C6D80 09 C8 01 58 00 21 10 00 D8 00 42 E0 06 40 00 84 ...X.!....B..@..
40000000000C6D90 11 C0 E1 5A 00 20 C0 32 B1 00 40 00 98 4B F5 58 ...Z. .2..@..K.X
40000000000C6DA0 08 08 00 6C 00 21 00 00 00 02 00 E0 06 30 01 84 ...l.!.......0..
40000000000C6DB0 19 00 00 58 80 11 00 00 00 02 00 00 58 AD 06 50 ...X........X..P
40000000000C6DC0 08 08 00 6C 00 21 00 00 00 02 00 40 05 40 00 84 ...l.!.....@.@..
40000000000C6DD0 19 B8 01 4C 00 21 00 00 00 02 00 00 18 3A F5 58 ...L.!.......:.X
40000000000C6DE0 11 08 00 6C 00 21 70 03 A8 00 42 00 E8 48 F5 58 ...l.!p...B..H.X
40000000000C6DF0 09 48 21 52 01 20 70 03 9C 00 42 20 00 B0 01 84 .H!R. p...B ....
40000000000C6E00 11 00 00 00 01 00 80 03 A4 2C 00 00 08 20 02 50 .........,... .P
40000000000C6E10 08 C0 01 54 00 21 70 02 20 00 42 00 00 00 04 00 ...T.!p. .B.....
40000000000C6E20 19 08 00 6C 00 21 70 03 20 00 42 00 C8 42 F5 58 ...l.!p. .B..B.X
40000000000C6E30 11 08 00 6C 00 21 70 03 A8 00 42 00 B8 39 F5 58 ...l.!p...B..9.X
40000000000C6E40 11 B8 01 4E 00 21 10 00 D8 00 42 00 88 48 F5 58 ...N.!....B..H.X
40000000000C6E50 08 40 9C 10 00 20 A0 03 94 00 42 20 07 20 01 84 .@... ....B . ..
40000000000C6E60 09 C0 01 50 00 21 10 00 D8 00 42 E0 06 00 01 84 ...P.!....B.....
40000000000C6E70 09 08 C0 10 80 15 00 00 00 02 00 00 05 20 01 84 ............. ..
40000000000C6E80 11 00 00 10 80 11 00 00 00 02 00 00 88 FB FF 58 ...............X
40000000000C6E90 08 28 01 10 00 21 00 00 00 02 00 20 00 B0 01 84 .(...!..... ....
40000000000C6EA0 19 B8 01 10 00 21 00 00 00 02 00 00 28 48 F5 58 .....!......(H.X
40000000000C6EB0 09 40 94 10 00 20 10 00 D8 00 42 E0 06 28 01 84 .@... ....B..(..
40000000000C6EC0 09 00 00 00 01 00 E0 F8 23 7E 46 00 00 00 04 00 ........#~F.....
40000000000C6ED0 11 00 C8 1C 80 11 00 00 00 02 00 00 F8 47 F5 58 .............G.X
40000000000C6EE0 09 48 21 52 01 20 70 03 9C 00 42 20 00 B0 01 84 .H!R. p...B ....
40000000000C6EF0 11 00 00 00 01 00 80 03 A4 2C 00 00 18 1F 02 50 .........,.....P
40000000000C6F00 08 08 00 6C 00 21 00 00 00 02 00 E0 04 40 00 84 ...l.!.......@..
40000000000C6F10 19 B8 01 10 00 21 00 00 00 02 00 00 B8 47 F5 58 .....!.......G.X
40000000000C6F20 08 08 00 6C 00 21 00 00 00 02 00 00 07 28 01 84 ...l.!.......(..
40000000000C6F30 19 B8 9D 10 00 20 00 00 00 02 00 00 B8 3B F5 58 ..... .......;.X
40000000000C6F40 09 08 BC 10 80 15 10 00 D8 00 42 E0 06 28 01 84 ..........B..(..
40000000000C6F50 11 00 00 10 80 11 00 00 00 02 00 00 98 38 F5 58 .............8.X
40000000000C6F60 11 08 00 6C 00 21 60 20 89 0E 61 03 C0 FB FF 4A ...l.!` ..a....J
40000000000C6F70 08 00 00 00 01 00 70 03 9C 00 42 00 01 38 01 84 ......p...B..8..
40000000000C6F80 18 00 00 00 01 00 70 00 8C 0C 73 03 10 FB FF 4A ......p...s....J
40000000000C6F90 11 00 00 00 01 00 00 00 00 02 00 00 38 47 F5 58 ............8G.X
40000000000C6FA0 18 30 00 66 87 39 E0 F8 23 7E 46 00 00 00 00 20 .0.f.9..#~F.... 
40000000000C6FB0 09 40 00 4E 00 21 10 00 D8 00 42 00 50 03 AA 00 .@.N.!....B.P...
40000000000C6FC0 C9 98 01 00 00 21 70 3A 39 00 40 00 40 0B 00 07 .....!p:9.@.@...
40000000000C6FD0 09 00 00 00 01 C0 31 EB 03 00 48 00 00 00 04 00 ......1...H.....
40000000000C6FE0 10 00 CC 4E 80 11 00 00 00 02 00 80 08 00 84 00 ...N............
40000000000C6FF0 10 00 00 00 01 00 30 01 00 00 42 00 90 FC FF 48 ......0...B....H
40000000000C7000 09 B8 01 54 18 10 00 00 00 02 00 00 05 20 01 84 ...T......... ..
40000000000C7010 11 B8 DD 5A 00 20 00 00 00 02 00 00 B8 46 F5 58 ...Z. .......F.X
40000000000C7020 11 08 00 6C 00 21 70 0B 20 00 42 00 A8 1C 02 50 ...l.!p. .B....P
40000000000C7030 09 C0 01 54 18 10 10 00 D8 00 42 E0 06 40 00 84 ...T......B..@..
40000000000C7040 11 C0 E1 5A 00 20 00 00 00 02 00 00 48 41 F5 58 ...Z. ......HA.X
40000000000C7050 08 08 00 6C 00 21 00 00 00 02 00 C0 04 40 00 84 ...l.!.......@..
40000000000C7060 19 B8 01 10 00 21 00 00 00 02 00 00 A8 AA 06 50 .....!.........P
40000000000C7070 08 08 00 6C 00 21 00 00 00 02 00 A0 04 40 00 84 ...l.!.......@..
40000000000C7080 19 B8 01 4C 00 21 00 00 00 02 00 00 68 37 F5 58 ...L.!......h7.X
40000000000C7090 11 08 00 6C 00 21 70 03 94 00 42 00 38 46 F5 58 ...l.!p...B.8F.X
40000000000C70A0 09 48 21 52 01 20 70 03 9C 00 42 20 00 B0 01 84 .H!R. p...B ....
40000000000C70B0 11 00 00 00 01 00 80 03 A4 2C 00 00 58 1D 02 50 .........,..X..P
40000000000C70C0 08 08 00 6C 00 21 00 00 00 02 00 E0 04 40 00 84 ...l.!.......@..
40000000000C70D0 19 B8 01 10 00 21 00 00 00 02 00 00 F8 45 F5 58 .....!.......E.X
40000000000C70E0 08 08 00 6C 00 21 00 00 00 02 00 00 07 28 01 84 ...l.!.......(..
40000000000C70F0 19 B8 9D 10 00 20 00 00 00 02 00 00 F8 39 F5 58 ..... .......9.X
40000000000C7100 09 08 BC 10 80 15 10 00 D8 00 42 E0 06 28 01 84 ..........B..(..
40000000000C7110 11 00 00 10 80 11 00 00 00 02 00 00 D8 36 F5 58 .............6.X
40000000000C7120 10 08 00 6C 00 21 60 20 89 0E 61 03 00 FA FF 4A ...l.!` ..a....J
40000000000C7130 11 00 00 00 01 00 00 00 00 02 00 00 40 FE FF 48 ............@..H
40000000000C7140 08 28 2D 0E 80 05 60 02 04 00 42 80 04 00 C4 00 .(-...`...B.....
40000000000C7150 09 38 01 40 00 21 10 42 80 00 42 40 04 00 01 84 .8.@.!.B..B@....
40000000000C7160 11 00 00 00 01 00 00 00 00 02 00 00 E8 90 06 50 ...............P
40000000000C7170 11 08 00 4C 00 21 30 02 20 00 42 00 58 3F F5 58 ...L.!0. .B.X?.X
40000000000C7180 11 38 04 10 06 35 10 00 98 00 42 03 20 00 00 43 .8...5....B. ..C
40000000000C7190 10 00 00 00 01 00 70 10 8C 0C E3 03 B0 00 00 43 ......p........C
40000000000C71A0 08 38 01 40 00 21 90 02 8C 00 42 00 00 00 04 00 .8.@.!....B.....
40000000000C71B0 19 40 05 00 00 24 A0 02 00 00 42 00 58 F8 FF 58 .@...$....B.X..X
40000000000C71C0 09 38 01 40 18 10 10 00 98 00 42 60 04 40 00 84 .8.@......B`.@..
40000000000C71D0 11 00 00 00 01 00 70 00 9C 0C F2 03 50 00 00 43 ......p.....P..C
40000000000C71E0 11 00 00 00 01 00 00 00 00 02 00 00 08 36 F5 58 .............6.X
40000000000C71F0 09 00 00 44 98 11 20 02 84 00 42 20 00 30 01 84 ...D.. ...B .0..
40000000000C7200 09 00 00 00 01 00 70 42 84 30 28 00 00 00 04 00 ......pB.0(.....
40000000000C7210 10 00 00 00 01 00 70 00 9C 0C 72 03 D0 FF FF 4A ......p...r....J
40000000000C7220 09 40 00 00 00 21 00 18 81 30 23 00 50 02 AA 00 .@...!...0#.P...
40000000000C7230 10 00 00 00 01 00 00 20 05 80 03 80 08 00 84 00 ....... ........
40000000000C7240 08 50 B1 03 05 24 00 00 00 02 00 00 F5 1F FD 8C .P...$..........
40000000000C7250 09 38 01 42 00 21 00 00 00 02 00 20 85 00 00 90 .8.B.!..... ....
40000000000C7260 11 50 01 54 18 10 80 02 A0 2C 00 00 A8 4D F5 58 .P.T.....,...M.X
40000000000C7270 08 08 00 4C 00 21 70 02 80 00 42 20 05 18 01 84 ...L.!p...B ....
40000000000C7280 19 40 05 00 00 24 A0 02 00 00 42 00 88 F7 FF 58 .@...$....B....X
40000000000C7290 09 38 01 40 18 10 10 00 98 00 42 60 04 40 00 84 .8.@......B`.@..
40000000000C72A0 10 00 00 00 01 00 70 00 9C 0C 72 03 40 FF FF 4A ......p...r.@..J
40000000000C72B0 11 00 00 00 01 00 00 00 00 02 00 00 70 FF FF 48 ............p..H
40000000000C72C0 08 18 1D 0A 80 05 E0 00 80 30 20 40 04 00 C4 00 .........0 @....
40000000000C72D0 09 20 01 02 00 21 F0 00 84 30 20 00 00 00 04 00 . ...!...0 .....
40000000000C72E0 09 28 01 1C 00 21 00 00 00 02 00 C0 04 78 00 84 .(...!.......x..
40000000000C72F0 09 40 00 1C 00 10 E0 00 3C 00 20 00 00 00 04 00 .@......<. .....
40000000000C7300 01 00 00 00 01 00 E0 00 38 28 00 00 01 40 50 00 ........8(...@P.
40000000000C7310 09 00 00 00 01 00 80 40 38 0A 40 00 00 00 04 00 .......@8.@.....
40000000000C7320 11 38 00 10 86 39 00 00 00 02 00 03 30 00 00 43 .8...9......0..C
40000000000C7330 11 00 00 00 01 00 00 00 00 02 00 00 18 32 F5 58 .............2.X
40000000000C7340 08 08 00 48 00 21 00 00 00 02 00 00 00 00 04 00 ...H.!..........
40000000000C7350 01 00 00 00 01 00 00 18 01 55 00 00 00 00 04 00 .........U......
40000000000C7360 11 00 00 00 01 00 00 10 05 80 03 80 08 00 84 00 ................
40000000000C7370 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; bash_brace_completion: 40000000000C7380
bash_brace_completion proc
	{ alloc	r43,ar.pfs,0xE,0x0,0xD; addl	r34,-10292,r1; addl	r14,-10564,r1 }
	{ addl	r36,-10332,r1; addl	r35,-10644,r1; addl	r33,-10372,r1; }
	{ ld8	r34,[r34]; addl	r32,-10708,r1; mov	r42,b2 }
	{ adds	r44,0x0,r1; ld8	r14,[r14]; addl	r45,9,r0; }
	{ ld8	r36,[r36]; ld8	r35,[r35]; nop.i	0x0; }
	{ ld8	r33,[r33]; ld8	r32,[r32]; nop.i	0x0; }
	{ ld8	r39,[r34]; st8	[r14],r34; addl	r14,740,r1 }
	{ ld8	r41,[r36]; ld8	r14,[r14]; nop.i	0x0 }
	{ ld8	r40,[r35]; st8	[r0],r35; nop.i	0x0; }
	{ ld8	r38,[r33]; st8	[r14],r36; nop.i	0x0 }
	{ st8	[r0],r33; ld4	r37,[r32]; nop.i	0x0; }
	{ st4	[r0],r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A800; }
	{ adds	r1,0x0,r44; st8	[r41],r36; nop.b	0x0 }
	{ st8	[r40],r35; nop.m	0x0; mov.i	ar.pfs,r43; }
	{ st8	[r39],r34; st8	[r38],r33; mov.spnt	b0,r42,40000000000C7460; }
	{ st4	[r37],r32; nop.i	0x0; br.ret	b0; }
40000000000C7480 09 00 00 00 01 00 E0 00 80 30 20 00 00 00 04 00 .........0 .....
40000000000C7490 11 30 00 1C 07 39 00 00 00 02 00 03 A0 00 00 43 .0...9.........C
40000000000C74A0 0B 78 00 1C 00 10 00 00 00 02 00 E0 01 78 50 00 .x...........xP.
40000000000C74B0 11 00 00 00 01 00 60 00 3C 0E 73 03 80 00 00 43 ......`.<.s....C
40000000000C74C0 09 38 70 1F 86 39 00 00 00 02 00 00 02 70 00 84 .8p..9.......p..
40000000000C74D0 F1 80 04 1C 00 21 00 00 00 02 80 03 20 00 00 43 .....!...... ..C
40000000000C74E0 10 00 00 00 01 00 60 30 3D 0E 73 03 60 00 00 43 ......`0=.s.`..C
40000000000C74F0 09 00 00 00 01 00 E0 08 40 00 42 00 00 00 04 00 ........@.B.....
40000000000C7500 11 30 00 1C 07 39 00 00 00 02 00 03 30 00 00 43 .0...9......0..C
40000000000C7510 0B 78 00 1C 00 10 00 00 00 02 00 E0 01 78 50 00 .x...........xP.
40000000000C7520 10 00 00 00 01 00 70 00 3C 0C 73 03 A0 FF FF 4A ......p.<.s....J
40000000000C7530 11 00 00 00 01 00 80 00 00 00 42 80 08 00 84 00 ..........B.....
40000000000C7540 09 00 31 40 00 21 00 00 00 02 00 00 01 00 00 84 ..1@.!..........
40000000000C7550 0B 70 00 40 10 10 E0 08 38 5C 40 00 00 00 04 00 .p.@....8\@.....
40000000000C7560 11 00 38 40 90 11 00 00 00 02 00 80 08 00 84 00 ..8@............
40000000000C7570 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C7580 00 28 25 0E 80 05 40 02 00 62 00 00 00 00 04 00 .(%...@..b......
40000000000C7590 19 30 01 02 00 21 70 00 84 0C 63 03 10 01 00 43 .0...!p...c....C
40000000000C75A0 03 00 00 00 01 00 20 02 84 2C 00 60 F4 17 FD 8C ...... ..,.`....
40000000000C75B0 0B 18 81 46 00 20 E0 00 8C 00 20 00 00 00 04 00 ...F. .... .....
40000000000C75C0 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
40000000000C75D0 11 00 00 00 01 00 60 D8 3A 0E 73 03 50 02 00 43 ......`.:.s.P..C
40000000000C75E0 11 38 04 42 86 39 00 00 00 02 80 03 A0 00 00 41 .8.B.9.........A
40000000000C75F0 0B 70 00 46 00 10 00 00 00 02 00 C0 01 70 50 00 .p.F.........pP.
40000000000C7600 11 00 00 00 01 00 70 D8 3B 0C F3 03 20 01 00 43 ......p.;... ..C
40000000000C7610 10 00 00 00 01 00 60 20 39 0E 73 03 B0 01 00 43 ......` 9.s....C
40000000000C7620 0B 70 C0 03 3B 24 00 00 00 02 00 00 00 00 04 00 .p..;$..........
40000000000C7630 09 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
40000000000C7640 10 00 00 00 01 00 70 00 38 0C F3 03 40 00 00 43 ......p.8...@..C
40000000000C7650 0B 70 80 44 01 20 E0 00 38 00 20 00 00 00 04 00 .p.D. ..8. .....
40000000000C7660 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
40000000000C7670 11 00 00 00 01 00 70 40 39 0C F3 03 E0 01 00 43 ......p@9......C
40000000000C7680 09 40 00 00 00 21 00 00 00 02 00 00 50 02 AA 00 .@...!......P...
40000000000C7690 10 00 00 00 01 00 00 20 05 80 03 80 08 00 84 00 ....... ........
40000000000C76A0 0B 70 C0 03 3B 24 00 00 00 02 00 00 00 00 04 00 .p..;$..........
40000000000C76B0 09 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
40000000000C76C0 11 38 00 1C 86 39 00 00 00 02 80 03 C0 FF FF 4B .8...9.........K
40000000000C76D0 11 30 04 42 87 31 00 00 00 02 80 03 B0 FF FF 4B .0.B.1.........K
40000000000C76E0 03 00 00 00 01 80 21 02 84 2C 00 C0 01 12 05 80 ......!..,......
40000000000C76F0 0B 70 00 1C 00 10 00 00 00 02 00 C0 01 70 50 00 .p...........pP.
40000000000C7700 10 00 00 00 01 00 70 40 39 0C 73 03 80 FF FF 4A ......p@9.s....J
40000000000C7710 10 00 00 00 01 00 00 00 00 02 00 00 40 01 00 40 ............@..@
40000000000C7720 0B 70 80 44 00 20 E0 F0 3B 7E 46 00 00 00 04 00 .p.D. ..;~F.....
40000000000C7730 0B 70 00 1C 00 10 00 00 00 02 00 C0 01 70 50 00 .p...........pP.
40000000000C7740 10 00 00 00 01 00 70 20 39 0C 73 03 E0 FE FF 4A ......p 9.s....J
40000000000C7750 11 38 81 44 01 20 80 EA 03 00 48 00 78 FE 06 50 .8.D. ....H.x..P
40000000000C7760 09 38 00 10 06 39 00 00 00 02 00 20 00 30 01 84 .8...9..... .0..
40000000000C7770 09 00 00 00 01 C0 E1 00 8C 00 20 00 00 00 04 00 .......... .....
40000000000C7780 10 00 00 00 01 C0 E1 00 38 28 80 03 90 FE FF 4B ........8(.....K
40000000000C7790 08 40 04 00 00 24 00 00 00 02 00 00 00 00 04 00 .@...$..........
40000000000C77A0 01 00 00 00 01 00 00 28 01 55 00 00 00 00 04 00 .......(.U......
40000000000C77B0 10 00 00 00 01 00 00 20 05 80 03 80 08 00 84 00 ....... ........
40000000000C77C0 0B 70 80 44 00 20 E0 00 38 00 20 00 00 00 04 00 .p.D. ..8. .....
40000000000C77D0 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
40000000000C77E0 11 30 84 1C 87 39 E0 80 07 76 48 03 B0 FF FF 4B .0...9...vH....K
40000000000C77F0 0B 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
40000000000C7800 10 00 00 00 01 00 70 00 38 0C 73 03 50 FE FF 4A ......p.8.s.P..J
40000000000C7810 10 00 00 00 01 00 00 00 00 02 00 00 70 FE FF 48 ............p..H
40000000000C7820 11 38 81 44 01 20 80 EA 02 00 48 00 A8 FD 06 50 .8.D. ....H....P
40000000000C7830 08 08 00 4C 00 21 60 00 20 0E 72 00 11 00 00 90 ...L.!`. .r.....
40000000000C7840 16 00 00 00 00 88 01 D0 FE FF 25 00 60 FF FF 48 ..........%.`..H
40000000000C7850 09 38 09 44 00 21 00 00 00 02 00 00 95 02 00 90 .8.D.!..........
40000000000C7860 11 38 81 4E 00 20 00 00 00 02 00 00 68 FD 06 50 .8.N. ......h..P
40000000000C7870 09 38 00 10 06 39 10 00 98 00 42 00 50 02 AA 00 .8...9....B.P...
40000000000C7880 C9 40 04 00 00 24 00 00 00 02 00 00 40 0A 00 07 .@...$......@...
40000000000C7890 11 00 00 00 01 C0 81 00 00 00 42 80 08 00 84 00 ..........B.....
40000000000C78A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C78B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; bash_initialize_history: 40000000000C78C0
;;   Called from:
;;     400000000001F85C (in main)
bash_initialize_history proc
	{ alloc	r33,ar.pfs,0x4,0x0,0x3; addl	r14,-10300,r1; mov	r32,b0 }
	{ addl	r35,-4252,r1; nop.m	0x0; adds	r34,0x0,r1; }
	{ nop.m	0x0; ld8	r14,[r14]; addl	r15,1,r0 }
	{ nop.m	0x0; ld8	r35,[r35]; nop.i	0x0; }
	{ st4	[r15],r14; addl	r14,-10388,r1; addl	r15,-4260,r1; }
	{ ld8	r14,[r14]; ld8	r15,[r15]; nop.i	0x0; }
	{ st8	[r15],r14; addl	r14,-10588,r1; addl	r15,-4268,r1; }
	{ ld8	r14,[r14]; ld8	r15,[r15]; nop.i	0x0; }
	{ st8	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,sv_histchars; }
	{ adds	r1,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ nop.m	0x0; mov.spnt	b0,r32,40000000000C7960; br.ret	b0; }
40000000000C7970 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; bash_history_reinit: 40000000000C7980
;;   Called from:
;;     400000000001D07C (in main)
;;     400000000002131C (in fn4000000000021300)
bash_history_reinit proc
	{ addl	r14,5860,r1; cmp4.eq	p07,p06,0x0,r32; addl	r15,1,r0; }
	{ nop.m	0x0; nop.m	0x0; (p06) addl	r32,1,r0; }

l40000000000C79A0:
	{ (p07) adds	r32,0x0,r0; st4	[r32],r14; addl	r14,9156,r1; }

l40000000000C79A6:
	{ mf.a; (p07) nop; break.i	0x80000 }
	{ mf.a; (p07) nop; (p48) nop }
	{ mf.a; (p07) nop; (p48) nop }
	{ mf.a; (p07) nop; break.i	0x80000 }
	{ (p07) fwb; nop; nop }
	{ break.m	0x4000; (p34) nop; (p32) nop }

;; bash_history_disable: 40000000000C7A00
;;   Called from:
;;     400000000003D7BC (in parse_string_to_word_list)
;;     40000000000F60BC (in fn40000000000F5E00)
bash_history_disable proc
	{ addl	r14,6116,r1; nop.m	0x0; addl	r15,1,r0; }
	{ st4	[r0],r14; nop.m	0x0; addl	r14,9156,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.ret	b0; }

;; bash_history_enable: 40000000000C7A40
bash_history_enable proc
	{ alloc	r33,ar.pfs,0x4,0x0,0x3; addl	r14,6116,r1; nop.b	0x0 }
	{ addl	r35,-4244,r1; mov	r32,b0; adds	r34,0x0,r1; }
	{ addl	r15,1,r0; ld8	r35,[r35]; nop.i	0x0; }
	{ st4	[r15],r14; addl	r14,9156,r1; addl	r15,-4268,r1; }
	{ nop.m	0x0; ld8	r15,[r15]; nop.i	0x0; }
	{ st4	[r0],r14; nop.m	0x0; addl	r14,-10588,r1; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ st8	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,sv_history_control; }
	{ adds	r1,0x0,r34; addl	r35,-4236,r1; nop.i	0x0; }
	{ ld8	r35,[r35]; nop.i	0x0; br.call.sptk.many	b0,sv_histignore; }
	{ adds	r1,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ nop.m	0x0; mov.spnt	b0,r32,40000000000C7AF0; br.ret	b0; }

;; load_history: 40000000000C7B00
;;   Called from:
;;     40000000000209AC (in main)
load_history proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x4; addl	r37,-4220,r1; nop.b	0x0 }
	{ addl	r36,-4228,r1; mov	r33,b1; adds	r35,0x0,r1; }
	{ nop.m	0x0; ld8	r37,[r37]; nop.i	0x0 }
	{ ld8	r36,[r36]; nop.m	0x0; br.call.sptk.many	b0,set_if_not; }
	{ adds	r1,0x0,r35; addl	r36,-4228,r1; nop.i	0x0; }
	{ ld8	r36,[r36]; nop.i	0x0; br.call.sptk.many	b0,sv_histsize; }
	{ adds	r1,0x0,r35; addl	r36,-4228,r1; nop.i	0x0; }
	{ ld8	r36,[r36]; nop.i	0x0; br.call.sptk.many	b0,get_string_value; }
	{ adds	r1,0x0,r35; adds	r37,0x0,r8; addl	r36,-4212,r1; }
	{ ld8	r36,[r36]; nop.i	0x0; br.call.sptk.many	b0,set_if_not; }
	{ adds	r1,0x0,r35; addl	r36,-4212,r1; nop.i	0x0; }
	{ ld8	r36,[r36]; nop.i	0x0; br.call.sptk.many	b0,sv_histsize; }
	{ adds	r1,0x0,r35; addl	r36,-4204,r1; nop.i	0x0; }
	{ ld8	r36,[r36]; nop.i	0x0; br.call.sptk.many	b0,get_string_value; }
	{ adds	r1,0x0,r35; nop.m	0x0; cmp.eq	p07,p06,0x0,r8 }
	{ adds	r32,0x0,r8; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000C7C20; }

l40000000000C7C00:
	{ ld1	r14,[r8]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000C7C40 }

l40000000000C7C20:
	{ nop.m	0x0; mov.i	ar.pfs,r34; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000C7C30; br.ret	b0; }

l40000000000C7C40:
	{ adds	r36,0x0,r8; nop.i	0x0; br.call.sptk.many	b0,file_exists; }
	{ adds	r1,0x0,r35; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	40000000000C7C20 }

l40000000000C7C60:
	{ adds	r36,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AC00; }
	{ adds	r1,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B7A0; }
	{ adds	r1,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A700; }
	{ adds	r1,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ addl	r14,9144,r1; nop.m	0x0; mov.spnt	b0,r33,40000000000C7CA0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r8],r14; nop.i	0x0; br.ret	b0; }
40000000000C7CD0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C7CE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C7CF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; bash_clear_history: 40000000000C7D00
;;   Called from:
;;     40000000000FE2EC (in history_builtin)
bash_clear_history proc
	{ alloc	r33,ar.pfs,0x3,0x0,0x3; mov	r32,b0; adds	r34,0x0,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AA60; }
	{ adds	r1,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ addl	r14,9148,r1; nop.m	0x0; mov.spnt	b0,r32,40000000000C7D30; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r0],r14; nop.i	0x0; br.ret	b0; }
40000000000C7D60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C7D70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; bash_delete_histent: 40000000000C7D80
;;   Called from:
;;     40000000000C7F2C (in bash_delete_last_history)
;;     40000000000FE6BC (in history_builtin)
bash_delete_histent proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; nop.m	0x0; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; adds	r36,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C060; }
	{ cmp.eq	p06,p07,0x0,r8; nop.m	0x0; adds	r1,0x0,r35 }
	{ adds	r36,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000C7DF0; }

l40000000000C7DD0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AFA0; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0; }

l40000000000C7DF0:
	{ addl	r14,9148,r1; addl	r8,1,r0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; nop.m	0x0; mov.spnt	b0,r33,40000000000C7E00; }
	{ ld4	r15,[r14]; adds	r15,0xFFFFFFFFFFFFFFFF,r15; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.ret	b0; }
40000000000C7E30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; bash_delete_last_history: 40000000000C7E40
;;   Called from:
;;     40000000000F9BBC (in fc_builtin)
;;     40000000000F9EAC (in fc_builtin)
;;     40000000000FE24C (in history_builtin)
;;     40000000000FE66C (in history_builtin)
bash_delete_last_history proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; mov	r33,b1; adds	r35,0x0,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B5C0; }
	{ adds	r1,0x0,r35; cmp.eq	p07,p06,0x0,r8; nop.i	0x0 }
	{ adds	r14,0x8,r8; adds	r36,0x0,r0; (p07) br.cond.dpnt.few	40000000000C7FC0; }

l40000000000C7E80:
	{ ld8	r15,[r8]; cmp.eq	p06,p07,0x0,r15; nop.i	0x0; }
	{ nop.m	0x0; (p06) addl	r32,-1,r0; (p06) br.cond.dpnt.few	40000000000C7ED0; }

l40000000000C7E9C:
	{ (p02) cmp.eq	p00,p09,r64,r33; (p01) mov.i	KR6,0x3; add	r0,r32,r0 }

l40000000000C7EA0:
	{ ld8	r15,[r14],8; nop.m	0x0; adds	r36,0x1,r36; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	40000000000C7EA0 }

l40000000000C7EC0:
	{ adds	r32,0xFFFFFFFFFFFFFFFF,r36; nop.m	0x0; nop.i	0x0 }

l40000000000C7ED0:
	{ addl	r14,-10068,r1; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; ld4	r36,[r14]; nop.i	0x0; }
	{ add	r36,r32,r36; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B140; }
	{ cmp.eq	p06,p07,0x0,r8; nop.m	0x0; adds	r1,0x0,r35 }
	{ adds	r36,0x0,r32; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000C7FC0; }

l40000000000C7F20:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,bash_delete_histent; }
	{ adds	r1,0x0,r35; adds	r32,0x0,r8; br.call.sptk.many	b0,fn400000000001A700; }
	{ adds	r1,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ addl	r14,-10380,r1; nop.m	0x0; mov.spnt	b0,r33,40000000000C7F50; }
	{ ld8	r14,[r14]; ld4	r36,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r36,r8; adds	r8,0x0,r32 }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	40000000000C7F90; br.ret	b0; }

l40000000000C7F8C:
	{ Invalid; break.m	0x1000; break.i	0x1000 }

l40000000000C7F90:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BBA0; }
	{ adds	r8,0x0,r32; adds	r1,0x0,r35; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000C7FB0; br.ret	b0 }

l40000000000C7FC0:
	{ adds	r32,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ adds	r8,0x0,r32; mov.spnt	b0,r33,40000000000C7FD0; br.ret	b0; }
40000000000C7FE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C7FF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; maybe_append_history: 40000000000C8000
;;   Called from:
;;     40000000000FE7DC (in history_builtin)
maybe_append_history proc
	{ alloc	r36,ar.pfs,0x9,0x0,0x6; adds	r12,0xFFFFFFFFFFFFFF70,r12; nop.b	0x0 }
	{ addl	r33,9148,r1; mov	r35,b3; adds	r37,0x0,r1; }
	{ nop.m	0x0; ld4	r14,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dpnt.few	40000000000C8060 }

l40000000000C8040:
	{ adds	r8,0x0,r0; mov.i	ar.pfs,r36; mov.spnt	b0,r35,40000000000C8040 }
	{ nop.m	0x0; adds	r12,0x90,r12; br.ret	b0; }

l40000000000C8060:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A700; }
	{ ld4	r14,[r33]; nop.m	0x0; adds	r1,0x0,r37; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r8,r14; (p06) br.cond.dptk.few	40000000000C8040 }

l40000000000C8090:
	{ adds	r39,0x0,r32; nop.m	0x0; adds	r40,0x10,r12 }
	{ addl	r38,1,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AFE0; }
	{ adds	r1,0x0,r37; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dpnt.few	40000000000C8140 }

l40000000000C80C0:
	{ ld4	r38,[r33]; adds	r39,0x0,r32; br.call.sptk.many	b0,fn400000000001C380; }
	{ adds	r1,0x0,r37; ld4	r16,[r33]; nop.i	0x0 }
	{ st4	[r0],r33; addl	r14,9144,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; add	r15,r15,r16; nop.i	0x0; }
	{ st4	[r15],r14; nop.m	0x0; nop.i	0x0 }

l40000000000C8120:
	{ nop.m	0x0; mov.i	ar.pfs,r36; mov.spnt	b0,r35,40000000000C8120 }
	{ nop.m	0x0; adds	r12,0x90,r12; br.ret	b0; }

l40000000000C8140:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ ld4	r14,[r8]; adds	r34,0x0,r8; adds	r1,0x0,r37; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2,r14; (p06) br.cond.dptk.few	40000000000C80C0 }

l40000000000C8170:
	{ addl	r40,384,r0; nop.m	0x0; adds	r38,0x0,r32 }
	{ addl	r39,65,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B4E0; }
	{ cmp4.lt	p07,p06,r8,r0; nop.m	0x0; adds	r1,0x0,r37 }
	{ adds	r38,0x0,r8; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000C8230; }

l40000000000C81B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C340; }
	{ adds	r1,0x0,r37; ld4	r38,[r33]; adds	r39,0x0,r32 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C380; }
	{ adds	r1,0x0,r37; ld4	r16,[r33]; nop.i	0x0 }
	{ st4	[r0],r33; addl	r14,9144,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; add	r15,r15,r16; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.cond.sptk.few	40000000000C8120 }

l40000000000C8230:
	{ addl	r39,-4196,r1; addl	r40,5,r0; adds	r38,0x0,r0; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r33,0x0,r8 }
	{ ld4	r38,[r34]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B4A0; }
	{ adds	r1,0x0,r37; adds	r40,0x0,r8; nop.i	0x0 }
	{ adds	r38,0x0,r33; adds	r39,0x0,r32; br.call.sptk.many	b0,builtin_error; }
	{ addl	r8,1,r0; adds	r1,0x0,r37; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000C82A0; nop.i	0x0 }
	{ adds	r12,0x90,r12; nop.m	0x0; br.ret	b0; }

;; maybe_save_shell_history: 40000000000C82C0
;;   Called from:
;;     400000000002248C (in exit_shell)
;;     40000000000B4D0C (in termsig_handler)
;;     40000000000B503C (in termsig_handler)
;;     40000000000F844C (in exec_builtin)
maybe_save_shell_history proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ addl	r32,9148,r1; mov	r34,b2; adds	r36,0x0,r1; }
	{ nop.m	0x0; ld4	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dpnt.few	40000000000C8320 }

l40000000000C8300:
	{ adds	r8,0x0,r0; mov.i	ar.pfs,r35; mov.spnt	b0,r34,40000000000C8300 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000C8320:
	{ nop.m	0x0; addl	r37,-4204,r1; nop.i	0x0; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,get_string_value; }
	{ adds	r1,0x0,r36; nop.m	0x0; cmp.eq	p06,p07,0x0,r8 }
	{ adds	r33,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000C8300; }

l40000000000C8360:
	{ ld1	r14,[r8]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000C8300 }

l40000000000C8380:
	{ adds	r37,0x0,r8; nop.i	0x0; br.call.sptk.many	b0,file_exists; }
	{ adds	r1,0x0,r36; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	40000000000C84B0 }

l40000000000C83A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B7A0; }
	{ adds	r1,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A700; }
	{ adds	r1,0x0,r36; ld4	r37,[r32]; nop.i	0x0; }
	{ addl	r14,9180,r1; cmp4.lt	p07,p06,r8,r37; (p06) br.cond.dpnt.few	40000000000C8400; }

l40000000000C83E0:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	40000000000C8510 }

l40000000000C8400:
	{ adds	r38,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C380; }
	{ adds	r1,0x0,r36; ld4	r15,[r32]; nop.i	0x0 }
	{ st4	[r0],r32; addl	r14,9144,r1; addl	r37,-4212,r1; }
	{ nop.m	0x0; ld8	r37,[r37]; nop.i	0x0; }
	{ nop.m	0x0; ld4	r16,[r14]; nop.i	0x0; }
	{ add	r15,r16,r15; st4	[r15],r14; adds	r14,0x10,r12; }
	{ st8	[r8],r14; nop.i	0x0; br.call.sptk.many	b0,sv_histsize; }
	{ adds	r14,0x10,r12; nop.m	0x0; adds	r1,0x0,r36; }
	{ ld8	r8,[r14]; nop.m	0x0; nop.i	0x0 }

l40000000000C8490:
	{ nop.m	0x0; mov.i	ar.pfs,r35; mov.spnt	b0,r34,40000000000C8490 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000000C84B0:
	{ adds	r37,0x0,r33; nop.m	0x0; addl	r38,577,r0 }
	{ addl	r39,384,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B4E0; }
	{ cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r8; nop.m	0x0; adds	r1,0x0,r36 }
	{ adds	r37,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000C83A0; }

l40000000000C84F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C340; }
	{ nop.m	0x0; adds	r1,0x0,r36; br.cond.sptk.few	40000000000C83A0 }

l40000000000C8510:
	{ adds	r37,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AAA0; }
	{ adds	r1,0x0,r36; addl	r14,9148,r1; addl	r37,-4212,r1; }
	{ nop.m	0x0; ld8	r37,[r37]; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r14]; addl	r14,9144,r1 }
	{ nop.m	0x0; st4	[r0],r32; nop.i	0x0; }
	{ nop.m	0x0; st4	[r15],r14; adds	r14,0x10,r12; }
	{ st8	[r8],r14; nop.i	0x0; br.call.sptk.many	b0,sv_histsize; }
	{ adds	r14,0x10,r12; nop.m	0x0; adds	r1,0x0,r36; }
	{ ld8	r8,[r14]; nop.i	0x0; br.cond.sptk.few	40000000000C8490; }
40000000000C85A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C85B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; bash_add_history: 40000000000C85C0
;;   Called from:
;;     40000000000C8C7C (in check_add_history)
;;     40000000000C92CC (in maybe_add_history)
;;     40000000000C937C (in maybe_add_history)
bash_add_history proc
	{ alloc	r38,ar.pfs,0xF,0x0,0x8; addl	r14,6108,r1; mov	r37,b5 }
	{ adds	r39,0x0,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000C8840 }

l40000000000C85F0:
	{ addl	r14,8952,r1; nop.m	0x0; addl	r35,-4188,r1; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.lt	p07,p06,0x1,r14; addl	r14,9164,r1; (p06) br.cond.dpnt.few	40000000000C8840; }

l40000000000C8620:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000C8960; }

l40000000000C8640:
	{ ld8	r35,[r35]; nop.m	0x0; nop.i	0x0 }

l40000000000C8650:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B7A0; }
	{ adds	r1,0x0,r39; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B1C0; }
	{ adds	r1,0x0,r39; nop.m	0x0; cmp.eq	p06,p07,0x0,r8 }
	{ adds	r33,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000C8840; }

l40000000000C8690:
	{ nop.m	0x0; ld8	r36,[r8]; nop.i	0x0; }
	{ adds	r40,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r39; adds	r34,0x0,r8; addl	r14,9308,r1; }
	{ nop.m	0x0; adds	r14,0x8,r14; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p07) br.cond.dptk.few	40000000000C88E0 }

l40000000000C86F0:
	{ adds	r40,0x0,r32; adds	r34,0x1,r34; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r40,0x0,r35; adds	r36,0x0,r8; nop.i	0x0 }
	{ adds	r1,0x0,r39; sxt4	r34,r34; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ add	r40,r8,r36; nop.m	0x0; adds	r1,0x0,r39; }
	{ add	r40,r40,r34; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r39; ld8	r44,[r33],16; adds	r45,0x0,r35 }
	{ adds	r46,0x0,r32; adds	r34,0x0,r8; adds	r40,0x0,r8; }
	{ addl	r43,-4172,r1; addl	r42,-1,r0; addl	r41,1,r0; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C440; }
	{ adds	r1,0x0,r39; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A700; }
	{ nop.m	0x0; ld8	r42,[r33]; adds	r41,0x0,r34 }
	{ adds	r1,0x0,r39; adds	r40,0x0,r8; br.call.sptk.many	b0,fn400000000001C320; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r33,0x0,r8 }
	{ adds	r40,0x0,r34; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ cmp.eq	p06,p07,0x0,r33; nop.m	0x0; adds	r1,0x0,r39 }
	{ adds	r40,0x0,r33; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000C8810; }

l40000000000C87F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AFA0; }
	{ adds	r1,0x0,r39; nop.m	0x0; nop.i	0x0 }

l40000000000C8810:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B7A0; }
	{ adds	r1,0x0,r39; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000C8830; br.ret	b0 }

l40000000000C8840:
	{ addl	r14,9160,r1; addl	r15,1,r0; adds	r40,0x0,r32; }
	{ nop.m	0x0; st4	[r15],r14; addl	r14,9184,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A8E0; }
	{ adds	r1,0x0,r39; addl	r14,9148,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; adds	r15,0x1,r15; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B7A0; }
	{ adds	r1,0x0,r39; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000C88D0; br.ret	b0 }

l40000000000C88E0:
	{ nop.m	0x0; sxt4	r16,r8; adds	r17,0xFFFFFFFFFFFFFFFF,r16; }
	{ add	r17,r36,r17; ld1	r15,[r17]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x5C,r15; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000C8980; }

l40000000000C8920:
	{ nop.m	0x0; cmp4.eq	p07,p06,0xA,r15; (p06) br.cond.dptk.few	40000000000C86F0 }

l40000000000C8930:
	{ nop.m	0x0; ld1	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x3B,r14; }
	{ nop.m	0x0; (p07) adds	r35,0x1,r35; br.cond.sptk.few	40000000000C86F0 }

l40000000000C895C:
	{ Invalid; zxt1	r0,r64; break.i	0x1000 }

l40000000000C8960:
	{ adds	r40,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,history_delimiting_chars; }
	{ adds	r1,0x0,r39; adds	r35,0x0,r8; br.cond.sptk.few	40000000000C8650 }

l40000000000C8980:
	{ add	r16,r36,r16; adds	r16,0xFFFFFFFFFFFFFFFE,r16; nop.i	0x0; }
	{ ld1	r15,[r16]; nop.m	0x0; sxt1	r15,r15; }
	{ cmp4.eq	p06,p07,0x5C,r15; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C86F0; }

l40000000000C89B0:
	{ st1	[r0],r17; adds	r34,0xFFFFFFFFFFFFFFFF,r8; addl	r35,-4180,r1; }
	{ ld4	r14,[r14]; nop.m	0x0; sxt4	r15,r34; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p06) br.cond.spnt.few	40000000000C8A30; }

l40000000000C89E0:
	{ ld8	r14,[r33]; ld8	r35,[r35]; nop.i	0x0; }
	{ add	r14,r14,r15; adds	r14,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; }
	{ ld1	r15,[r14]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0xA,r15; (p06) br.cond.dptk.few	40000000000C86F0 }

l40000000000C8A20:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000C8930 }

l40000000000C8A30:
	{ nop.m	0x0; addl	r35,-4180,r1; nop.i	0x0; }
	{ ld8	r35,[r35]; nop.i	0x0; br.cond.sptk.few	40000000000C86F0; }
40000000000C8A50 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C8A60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C8A70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; check_add_history: 40000000000C8A80
;;   Called from:
;;     40000000000C92DC (in maybe_add_history)
;;     40000000000FE28C (in history_builtin)
check_add_history proc
	{ alloc	r43,ar.pfs,0x11,0x0,0xD; addl	r41,9168,r1; mov	r42,b2 }
	{ adds	r44,0x0,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r41]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C8B00; }

l40000000000C8AC0:
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x0; (p06) br.cond.dptk.few	40000000000C8AF0 }

l40000000000C8AD0:
	{ ld1	r15,[r32]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x20,r15; (p06) br.cond.dpnt.few	40000000000C8CC0; }

l40000000000C8AF0:
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x1; (p07) br.cond.dpnt.few	40000000000C8DE0 }

l40000000000C8B00:
	{ addl	r37,-19604,r1; nop.m	0x0; nop.i	0x0; }
	{ adds	r40,0x10,r37; ld4	r14,[r40]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	40000000000C8C40; }

l40000000000C8B30:
	{ addl	r39,7664,r1; cmp4.lt	p06,p07,0x0,r14; adds	r34,0x0,r0 }
	{ adds	r35,0x0,r0; adds	r37,0x8,r37; (p07) br.cond.dpnt.few	40000000000C8C40; }

l40000000000C8B50:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }

l40000000000C8B60:
	{ ld8	r14,[r37]; adds	r46,0x0,r32; add	r14,r14,r34; }
	{ adds	r15,0xC,r14; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r15,0x0; (p07) br.cond.dpnt.few	40000000000C8CF0; }

l40000000000C8B90:
	{ nop.m	0x0; ld4	r47,[r39]; adds	r35,0x1,r35 }
	{ (p06) ld8	r36,[r14]; cmp4.eq	p06,p07,0x0,r47; adds	r45,0x0,r36; }

l40000000000C8BA6:
	{ Invalid; (p22) nop; cmp.lt	p00,p00,r0,r32 }
	{ Invalid; nop; (p49) nop.b	0xB; }

l40000000000C8BBC:
	{ cmp4.eq.or.andcm	p00,p17,r1,r0; zxt1	r0,r64; break.i	0x1000 }

l40000000000C8BC6:
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ Invalid; (p19) mov.sptk	b0,r8,40000000000C8CD6; (p32) nop.b	0x221C3 }
	{ Invalid; (p07) nop; break.i	0x80000 }
	{ (p07) fwb; nop; break.i	0x80000 }
	{ (p03) chk.a.nc	f0,3FFFFFFFFFACC4E6; nop; break.i	0x80000 }

l40000000000C8C10:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x1,r38; (p06) br.cond.dpnt.few	40000000000C8CC0 }

l40000000000C8C20:
	{ nop.m	0x0; ld4	r14,[r40]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r35,r14; (p06) br.cond.dptk.few	40000000000C8B60 }

l40000000000C8C40:
	{ ld4	r14,[r41]; nop.m	0x0; adds	r45,0x0,r32; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x2; (p07) br.cond.dpnt.few	40000000000C8F50; }

l40000000000C8C60:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r33; (p07) br.cond.dpnt.few	40000000000C8EB0 }

l40000000000C8C70:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,bash_add_history; }
	{ addl	r8,1,r0; adds	r1,0x0,r44; mov.i	ar.pfs,r43; }
	{ nop.m	0x0; mov.spnt	b0,r42,40000000000C8C90; br.ret	b0; }

l40000000000C8CA0:
	{ adds	r45,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r44; cmp4.eq	p07,p06,0x1,r38; (p07) br.cond.dptk.few	40000000000C8C20; }

l40000000000C8CC0:
	{ adds	r8,0x0,r0; nop.m	0x0; nop.i	0x0 }

l40000000000C8CD0:
	{ nop.m	0x0; mov.i	ar.pfs,r43; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r42,40000000000C8CE0; br.ret	b0; }

l40000000000C8CF0:
	{ ld8	r38,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B7A0; }
	{ adds	r1,0x0,r44; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B1C0; }
	{ adds	r1,0x0,r44; adds	r36,0x0,r8; br.call.sptk.many	b0,fn400000000001B7A0; }
	{ cmp.eq	p07,p06,0x0,r36; adds	r45,0x0,r38; adds	r1,0x0,r44 }
	{ addl	r46,38,r0; addl	r48,1,r0; (p07) br.cond.dpnt.few	40000000000C9070; }

l40000000000C8D40:
	{ ld8	r47,[r36]; adds	r35,0x1,r35; br.call.sptk.many	b0,strcreplace; }
	{ ld4	r47,[r39]; adds	r36,0x0,r8; adds	r1,0x0,r44 }
	{ adds	r46,0x0,r32; cmp4.eq	p06,p07,0x0,r47; adds	r45,0x0,r36; }
	{ nop.m	0x0; (p07) addl	r47,32,r0; nop.i	0x0; }

l40000000000C8D7C:
	{ cmp4.eq.or.andcm	p00,p17,r1,r0; zxt1	r0,r64; break.i	0x1000 }

l40000000000C8D86:
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ Invalid; (p19) mov.sptk	b0,r8,40000000000C8E96; (p32) nop.b	0x221C3 }
	{ Invalid; (p07) nop; break.i	0x80000 }
	{ (p07) fwb; nop; break.i	0x80000 }
	{ (p03) chk.a.nc	r0,3FFFFFFFFFACC6A6; nop; break.i	0x80000 }

l40000000000C8DD0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000C8CA0 }

l40000000000C8DE0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B7A0; }
	{ adds	r1,0x0,r44; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B1C0; }
	{ adds	r1,0x0,r44; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	40000000000C8E50; }

l40000000000C8E10:
	{ ld8	r45,[r8]; ld1	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r14; nop.i	0x0; }
	{ ld1	r14,[r45]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r15; (p07) br.cond.dpnt.few	40000000000C9030 }

l40000000000C8E50:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B7A0; }
	{ adds	r1,0x0,r44; addl	r37,-19604,r1; nop.i	0x0; }
	{ nop.m	0x0; adds	r40,0x10,r37; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r40]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	40000000000C8B30 }

l40000000000C8EA0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000C8C40 }

l40000000000C8EB0:
	{ addl	r14,9160,r1; nop.m	0x0; addl	r15,1,r0; }
	{ nop.m	0x0; st4	[r15],r14; addl	r14,9184,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A8E0; }
	{ adds	r1,0x0,r44; addl	r14,9148,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; adds	r15,0x1,r15; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B7A0; }
	{ addl	r8,1,r0; adds	r1,0x0,r44; mov.i	ar.pfs,r43; }
	{ nop.m	0x0; mov.spnt	b0,r42,40000000000C8F40; br.ret	b0; }

l40000000000C8F50:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B7A0; }
	{ adds	r1,0x0,r44; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000C8F80:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B1C0; }
	{ adds	r1,0x0,r44; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	40000000000C9140; }

l40000000000C8FA0:
	{ ld8	r45,[r8]; ld1	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r14; nop.i	0x0; }
	{ ld1	r14,[r45]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r15; (p06) br.cond.dptk.few	40000000000C8F80 }

l40000000000C8FE0:
	{ adds	r46,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r44; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000000C8F80 }

l40000000000C9000:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A700; }
	{ adds	r1,0x0,r44; adds	r45,0x0,r8; br.call.sptk.many	b0,fn400000000001C060; }
	{ nop.m	0x0; adds	r1,0x0,r44; br.cond.sptk.few	40000000000C8F80 }

l40000000000C9030:
	{ adds	r46,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r44; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	40000000000C8E50 }

l40000000000C9050:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B7A0; }
	{ adds	r1,0x0,r44; adds	r8,0x0,r0; br.cond.sptk.few	40000000000C8CD0 }

l40000000000C9070:
	{ adds	r35,0x1,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r44; adds	r45,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r46,0x0,r38; nop.m	0x0; adds	r1,0x0,r44 }
	{ adds	r45,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ ld4	r47,[r39]; adds	r36,0x0,r8; adds	r1,0x0,r44 }
	{ adds	r46,0x0,r32; cmp4.eq	p06,p07,0x0,r47; adds	r45,0x0,r36; }
	{ nop.m	0x0; (p07) addl	r47,32,r0; nop.i	0x0; }

l40000000000C90DC:
	{ cmp4.eq.or.andcm	p00,p17,r1,r0; zxt1	r0,r64; break.i	0x1000 }

l40000000000C90E6:
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ Invalid; (p19) mov.sptk	b0,r8,40000000000C91F6; (p32) nop.b	0x221C3 }
	{ Invalid; (p07) nop; break.i	0x80000 }
	{ (p07) fwb; nop; break.i	0x80000 }
	{ (p03) chk.a.nc	r0,3FFFFFFFFFACCA06; nop; break.i	0x80000 }

l40000000000C9130:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000C8CA0 }

l40000000000C9140:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B7A0; }
	{ nop.m	0x0; adds	r1,0x0,r44; adds	r45,0x0,r32 }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r33; (p06) br.cond.dptk.few	40000000000C8C70 }

l40000000000C9170:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000C8EB0; }

;; maybe_add_history: 40000000000C9180
;;   Called from:
;;     400000000002A02C (in fn4000000000029100)
;;     400000000002A47C (in fn4000000000029100)
;;     400000000002ABDC (in read_secondary_line)
;;     40000000000C96BC (in pre_process_line)
;;     40000000000C98BC (in pre_process_line)
;;     40000000000F9BDC (in fc_builtin)
maybe_add_history proc
	{ alloc	r34,ar.pfs,0x7,0x0,0x5; addl	r14,8952,r1; mov	r36,LC }
	{ addl	r15,9160,r1; adds	r35,0x0,r1; cmp.eq	p08,p09,0x0,r32; }
	{ nop.m	0x0; nop.m	0x0; mov	r33,b1 }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0 }
	{ st4	[r0],r15; adds	r15,0x1,r32; cmp4.lt	p07,p06,0x1,r14 }
	{ addl	r14,7772,r1; sub	r16,r0,r15; (p06) br.cond.dpnt.few	40000000000C92D0; }

l40000000000C91E0:
	{ ld4	r14,[r14]; nop.m	0x0; mov.i	LC,r16; }
	{ cmp4.eq	p06,p07,0x0,r14; addl	r14,9164,r1; (p06) br.cond.dpnt.few	40000000000C9300; }

l40000000000C9200:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; addl	r14,9308,r1; (p06) br.cond.dpnt.few	40000000000C92A0; }

l40000000000C9220:
	{ nop.m	0x0; adds	r14,0x8,r14; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dpnt.few	40000000000C92A0; (p08) br.cond.dpnt.few	40000000000C92A0; }

l40000000000C924C:
	{ (p03) cmp.lt	p00,p11,r64,r33; Invalid; cmp.lt	p00,p00,r32,r0 }

l40000000000C9250:
	{ ld1	r14,[r32]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x20,r14; cmp4.eq	p08,p09,0x0,r14; (p08) br.cond.dpnt.few	40000000000C92A0; }

l40000000000C9270:
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x9,r14; (p06) br.cond.dpnt.few	40000000000C9350; }

l40000000000C9280:
	{ nop.m	0x0; nop.i	0x0; br.cloop.sptk.few	40000000000C9320; }

l40000000000C9290:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000C92A0:
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000C92A0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.i	LC,r36; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x1,0x0,0x0; nop.i	0x0; br.cond.sptk.many	bash_add_history; }

l40000000000C92D0:
	{ adds	r37,0x0,r32; adds	r38,0x0,r0; br.call.sptk.many	b0,check_add_history; }
	{ adds	r1,0x0,r35; nop.i	0x0; addl	r14,7772,r1; }
	{ st4	[r8],r14; nop.m	0x0; nop.i	0x0 }

l40000000000C9300:
	{ nop.m	0x0; mov.i	ar.pfs,r34; mov.i	LC,r36; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000C9310; br.ret	b0 }

l40000000000C9320:
	{ ld1	r14,[r15],1; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x20,r14; cmp4.eq	p08,p09,0x0,r14; (p08) br.cond.dpnt.few	40000000000C92A0; }

l40000000000C9340:
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x9,r14; (p06) br.cond.dptk.few	40000000000C9280; }

l40000000000C9350:
	{ cmp4.eq	p06,p07,0x23,r14; mov.spnt	b0,r33,40000000000C9350; (p06) br.cond.dpnt.few	40000000000C9300; }

l40000000000C9360:
	{ nop.m	0x0; mov.i	ar.pfs,r34; mov.i	LC,r36; }
	{ alloc	r2,ar.pfs,0x1,0x0,0x0; nop.i	0x0; br.cond.sptk.many	bash_add_history; }
40000000000C9380 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000C9390 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C93A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C93B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; pre_process_line: 40000000000C93C0
;;   Called from:
;;     400000000002A15C (in fn4000000000029100)
pre_process_line proc
	{ alloc	r38,ar.pfs,0xC,0x0,0x8; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r37,b5 }
	{ addl	r14,9156,r1; adds	r39,0x0,r1; adds	r35,0x0,r32; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000C9660 }

l40000000000C9400:
	{ addl	r14,5860,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000C96F0 }

l40000000000C9430:
	{ ld1	r14,[r32]; nop.m	0x0; addl	r16,-10108,r1 }
	{ addl	r17,-10204,r1; adds	r15,0x1,r32; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C96F0; }

l40000000000C9460:
	{ ld8	r16,[r16]; ld1	r16,[r16]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r16,r16; nop.i	0x0; }
	{ cmp4.eq	p06,p07,r14,r16; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C9500; }

l40000000000C9490:
	{ ld8	r17,[r17]; ld1	r17,[r17]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r17,r17; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,r17,r14; (p06) br.cond.dpnt.few	40000000000C9500; }

l40000000000C94C0:
	{ ld1	r14,[r15],1; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000C96F0; }

l40000000000C94E0:
	{ cmp4.eq	p06,p07,r16,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C9500; }

l40000000000C94F0:
	{ nop.m	0x0; cmp4.eq	p06,p07,r17,r14; (p07) br.cond.dptk.few	40000000000C94C0 }

l40000000000C9500:
	{ adds	r40,0x0,r32; adds	r41,0x10,r12; br.call.sptk.many	b0,fn400000000001C0E0; }
	{ nop.m	0x0; adds	r35,0x0,r8; adds	r1,0x0,r39 }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r8; (p07) br.cond.dptk.few	40000000000C9640; }

l40000000000C9530:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r33; (p06) br.cond.dptk.few	40000000000C9760; }

l40000000000C9540:
	{ addl	r14,9152,r1; cmp4.lt	p07,p06,r35,r0; (p07) br.cond.dpnt.few	40000000000C9950; }

l40000000000C9550:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C9710; }

l40000000000C9570:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2,r35; (p07) br.cond.dpnt.few	40000000000C9710; }

l40000000000C9580:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x1,r35; (p06) br.cond.dptk.few	40000000000C9640 }

l40000000000C9590:
	{ adds	r14,0x10,r12; ld8	r40,[r14]; addl	r14,22532,r1; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x1,r14; (p06) br.cond.dptk.few	40000000000C9830 }

l40000000000C95C0:
	{ nop.m	0x0; adds	r35,0x0,r0; br.call.sptk.many	b0,bash_re_edit; }
	{ adds	r1,0x0,r39; nop.m	0x0; nop.i	0x0; }

l40000000000C95E0:
	{ adds	r8,0x0,r35; mov.i	ar.pfs,r38; mov.spnt	b0,r37,40000000000C95E0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000C9600:
	{ addl	r14,9152,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dpnt.few	40000000000C9580; }

l40000000000C9630:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000C9640:
	{ nop.m	0x0; adds	r14,0x10,r12; nop.i	0x0; }
	{ ld8	r35,[r14]; nop.m	0x0; nop.i	0x0; }

l40000000000C9660:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r34; (p06) br.cond.dptk.few	40000000000C95E0 }

l40000000000C9670:
	{ addl	r14,6116,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000C95E0 }

l40000000000C9690:
	{ ld1	r14,[r35]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000C95E0 }

l40000000000C96B0:
	{ adds	r40,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,maybe_add_history; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r39; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000C96D0; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l40000000000C96F0:
	{ adds	r35,0x0,r32; cmp4.eq	p06,p07,0x0,r34; (p06) br.cond.dptk.few	40000000000C95E0 }

l40000000000C9700:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000C9670; }

l40000000000C9710:
	{ adds	r14,0x10,r12; addl	r42,-4156,r1; addl	r41,1,r0; }
	{ nop.m	0x0; ld8	r43,[r14]; addl	r14,-10652,r1 }
	{ ld8	r42,[r42]; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r40,[r14]; br.call.sptk.many	b0,fn400000000001C040; nop.b	0x0; }
	{ adds	r1,0x0,r39; nop.m	0x0; nop.i	0x0 }

l40000000000C9760:
	{ cmp4.eq	p06,p07,0x2,r35; nop.m	0x0; extr.u	r36,r35,31,1; }
	{ (p06) addl	r14,1,r0; nop.m	0x0; zxt1	r15,r36; }

l40000000000C9776:
	{ add	r0,r0,r1; (p07) cmp4.ltu	p00,p00,0x24,r16; (p33) nop }

l40000000000C9786:
	{ Invalid; (p07) nop; (p48) nop }
	{ (p07) chk.a.clr	f16,3FFFFFFFFF149856; nop; break.i	0x80000 }

l40000000000C97A0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r16; (p06) br.cond.dpnt.few	40000000000C9860; }

l40000000000C97B0:
	{ ld8	r40,[r14]; nop.m	0x0; nop.i	0x0 }

l40000000000C97C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r39; addl	r14,9172,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; addl	r14,-10324,r1; (p07) br.cond.dpnt.few	40000000000C9830; }

l40000000000C9800:
	{ cmp4.eq	p06,p07,0x0,r36; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C9830; }

l40000000000C9810:
	{ ld8	r14,[r14]; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000C98E0 }

l40000000000C9830:
	{ nop.m	0x0; adds	r35,0x0,r0; nop.i	0x0; }
	{ adds	r8,0x0,r35; mov.i	ar.pfs,r38; mov.spnt	b0,r37,40000000000C9840 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000C9860:
	{ addl	r14,-10164,r1; ld8	r14,[r14]; nop.i	0x0; }
	{ ld4	r14,[r14]; cmp4.eq	p06,p07,0x0,r14; adds	r14,0x10,r12; }
	{ ld8	r40,[r14]; nop.i	0x0; (p07) br.cond.dptk.few	40000000000C97C0; }

l40000000000C9890:
	{ ld1	r14,[r40]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000C97C0 }

l40000000000C98B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,maybe_add_history; }
	{ adds	r14,0x10,r12; nop.m	0x0; adds	r1,0x0,r39; }
	{ ld8	r40,[r14]; nop.i	0x0; br.cond.sptk.few	40000000000C97C0 }

l40000000000C98E0:
	{ addl	r14,22532,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x1,r14; (p06) br.cond.dptk.few	40000000000C9830 }

l40000000000C9910:
	{ adds	r40,0x0,r32; adds	r35,0x0,r0; br.call.sptk.many	b0,bash_re_edit; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r39; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000C9930; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0; }

l40000000000C9950:
	{ adds	r14,0x10,r12; addl	r40,-4164,r1; addl	r36,1,r0; }
	{ nop.m	0x0; ld8	r41,[r14]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,internal_error; }
	{ adds	r14,0x10,r12; nop.m	0x0; adds	r1,0x0,r39; }
	{ ld8	r40,[r14]; nop.i	0x0; br.cond.sptk.few	40000000000C97C0; }
40000000000C99A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C99B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; history_number: 40000000000C99C0
;;   Called from:
;;     400000000002770C (in decode_prompt_string)
history_number proc
	{ alloc	r33,ar.pfs,0x3,0x0,0x3; mov	r32,b0; adds	r34,0x0,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B7A0; }
	{ adds	r1,0x0,r34; addl	r8,1,r0; mov.i	ar.pfs,r33; }
	{ addl	r14,6116,r1; nop.m	0x0; mov.spnt	b0,r32,40000000000C99F0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000C9A20; br.ret	b0; }

l40000000000C9A1C:
	{ Invalid; break.m	0x1000; break.i	0x1000 }

l40000000000C9A20:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A700; }
	{ adds	r1,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ addl	r14,-10068,r1; nop.m	0x0; mov.spnt	b0,r32,40000000000C9A40; }
	{ ld8	r14,[r14]; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; add	r8,r8,r14; br.ret	b0; }
40000000000C9A70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; setup_history_ignore: 40000000000C9A80
;;   Called from:
;;     400000000005F2EC (in sv_histignore)
;;     400000000006D4DC (in initialize_shell_variables)
setup_history_ignore proc
	{ alloc	r33,ar.pfs,0x4,0x0,0x3; nop.m	0x0; mov	r32,b0 }
	{ addl	r35,-19604,r1; nop.m	0x0; adds	r34,0x0,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,setup_ignore_patterns; }
	{ adds	r1,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ nop.m	0x0; mov.spnt	b0,r32,40000000000C9AC0; br.ret	b0; }
40000000000C9AD0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C9AE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C9AF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; last_history_line: 40000000000C9B00
;;   Called from:
;;     4000000000070C0C (in programming_error)
last_history_line proc
	{ alloc	r34,ar.pfs,0x4,0x0,0x4; mov	r33,b1; adds	r35,0x0,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B7A0; }
	{ adds	r1,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B1C0; }
	{ adds	r1,0x0,r35; adds	r32,0x0,r8; br.call.sptk.many	b0,fn400000000001B7A0; }
	{ cmp.eq	p06,p07,0x0,r32; adds	r1,0x0,r35; mov.i	ar.pfs,r34; }
	{ (p07) ld8	r8,[r32]; nop.m	0x0; mov.spnt	b0,r33,40000000000C9B50; }

l40000000000C9B56:
	{ break.m	0x4000; nop; add	r0,r0,r32 }
	{ Invalid; (p34) break.i	0x84000; (p32) break.i	0x80001; }

l40000000000C9B6C:
	{ cmp.lt	p00,p00,r33,r0; cmp.eq	p00,p00,r32,r0; break.i	0x1000 }
40000000000C9B70 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000C9B80 09 78 B0 02 3D 24 70 00 84 0C 73 C0 41 0A F4 90 .x..=$p...s.A...
40000000000C9B90 E9 80 00 1E 00 21 E0 00 38 30 20 00 00 00 04 00 .....!..80 .....
40000000000C9BA0 F1 00 00 20 90 11 60 00 38 0E 72 03 50 00 00 43 ... ..`.8.r.P..C
40000000000C9BB0 02 80 00 1E 10 10 00 00 00 02 00 20 02 80 58 00 ........... ..X.
40000000000C9BC0 0B 80 04 20 00 21 E0 88 38 24 40 00 00 00 04 00 ... .!..8$@.....
40000000000C9BD0 0B 40 00 1C 18 10 60 00 20 0E 72 00 00 00 04 00 .@....`. .r.....
40000000000C9BE0 F1 00 40 1E 90 11 00 00 00 02 00 80 08 00 84 00 ..@.............
40000000000C9BF0 11 00 00 00 01 00 80 00 00 00 42 80 08 00 84 00 ..........B.....
40000000000C9C00 11 00 00 00 01 00 80 00 00 00 42 80 08 00 84 00 ..........B.....
40000000000C9C10 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C9C20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000C9C30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000C9C40: 40000000000C9C40
;;   Called from:
;;     40000000000CAD9C (in fn40000000000CAD40)
;;     40000000000CB04C (in fn40000000000CAD40)
;;     40000000000CC98C (in command_word_completion_function)
;;     40000000000CD92C (in command_word_completion_function)
;;     40000000000D8C9C (in bash_directory_completion_matches)
;;     40000000000D8DC8 (in bash_dequote_text)
fn40000000000C9C40 proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; adds	r37,0x0,r32; mov	r34,b2 }
	{ nop.m	0x0; adds	r36,0x0,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r37,0x1,r8; nop.m	0x0; adds	r1,0x0,r36; }
	{ nop.m	0x0; sxt4	r37,r37; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r36; cmp.eq	p06,p07,0x0,r32; nop.i	0x0 }
	{ adds	r16,0x0,r8; adds	r15,0x0,r32; (p06) br.cond.dpnt.few	40000000000C9EE0; }

l40000000000C9CB0:
	{ addl	r18,-18556,r1; ld1	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	40000000000C9EE0; }

l40000000000C9CE0:
	{ cmp4.eq	p07,p06,0x5C,r14; nop.m	0x0; cmp4.eq	p08,p09,0x0,r33 }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	40000000000C9DE0; (p09) br.cond.dptk.few	40000000000C9DB0; }

l40000000000C9CFC:
	{ (p06) cmp.eq	p00,p09,r0,r33; czx1.r	r72,r97; break.i	0x1000 }

l40000000000C9D00:
	{ cmp4.eq	p07,p06,0x22,r14; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x27,r14; (p06) br.cond.dptk.few	40000000000C9DC0; }

l40000000000C9D20:
	{ (p07) adds	r33,0x0,r14; nop.m	0x0; nop.i	0x0; }

l40000000000C9D26:
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ break.m	0x4000; nop; break.i	0x80000 }

l40000000000C9D40:
	{ nop.m	0x0; adds	r15,0x1,r15; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r15; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C9D80; }

l40000000000C9D60:
	{ ld1	r14,[r15]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000C9CE0 }

l40000000000C9D80:
	{ st1	[r0],r16; nop.m	0x0; nop.i	0x0 }

l40000000000C9D90:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000C9DA0; br.ret	b0 }

l40000000000C9DB0:
	{ nop.m	0x0; cmp4.eq	p06,p07,r33,r14; (p06) br.cond.dpnt.few	40000000000C9DD0 }

l40000000000C9DC0:
	{ st1	[r16],r1,1; nop.i	0x0; br.cond.sptk.few	40000000000C9D40 }

l40000000000C9DD0:
	{ nop.m	0x0; adds	r33,0x0,r0; br.cond.sptk.few	40000000000C9D40; }

l40000000000C9DE0:
	{ adds	r17,0x1,r15; cmp4.eq	p07,p06,0x27,r33; (p07) br.cond.dpnt.few	40000000000C9EB0; }

l40000000000C9DF0:
	{ cmp4.eq	p06,p07,0x22,r33; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000C9E70; }

l40000000000C9E00:
	{ ld1	r15,[r17]; nop.i	0x0; sxt1	r15,r15; }

l40000000000C9E10:
	{ ld1.a	r14,[r17]; st1	[r15],r16; adds	r15,0x0,r17 }
	{ adds	r16,0x1,r16; ld1.c.clr	r14,[r17]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	40000000000C9D40 }

l40000000000C9E50:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000C9E60; br.ret	b0 }

l40000000000C9E70:
	{ adds	r17,0x1,r15; ld1	r15,[r17]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; shladd	r19,r15,0x2,r18; }
	{ nop.m	0x0; ld4	r19,[r19]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r19,0x6; (p06) br.cond.dptk.few	40000000000C9E10 }

l40000000000C9EB0:
	{ ld1.a	r15,[r17]; st1	[r16],r1,1; nop.i	0x0; }
	{ nop.m	0x0; ld1.c.clr	r15,[r17]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; br.cond.sptk.few	40000000000C9E10 }

l40000000000C9EE0:
	{ nop.m	0x0; adds	r16,0x0,r8; nop.i	0x0; }
	{ st1	[r0],r16; nop.i	0x0; br.cond.sptk.few	40000000000C9D90; }

;; fn40000000000C9F00: 40000000000C9F00
;;   Called from:
;;     40000000000CA52C (in fn40000000000CA500)
fn40000000000C9F00 proc
	{ alloc	r45,ar.pfs,0x10,0x0,0xF; adds	r42,0x8,r32; nop.b	0x0 }
	{ adds	r34,0x10,r32; mov	r44,b4; adds	r46,0x0,r1; }
	{ ld8	r15,[r42]; nop.m	0x0; addl	r36,1,r0 }
	{ adds	r43,0x0,r42; nop.m	0x0; adds	r14,0x0,r34; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r15; (p06) br.cond.dpnt.few	40000000000CA390; }

l40000000000C9F50:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000C9F60:
	{ ld8	r15,[r14],8; nop.m	0x0; adds	r36,0x1,r36; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	40000000000C9F60 }

l40000000000C9F80:
	{ addl	r40,6132,r1; adds	r47,0x1,r36; adds	r37,0x0,r42 }
	{ adds	r39,0x0,r0; addl	r35,1,r0; br.call.sptk.many	b0,strvec_create; }
	{ ld4	r14,[r40]; adds	r38,0x0,r8; adds	r1,0x0,r46; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000CA2C0; }

l40000000000C9FC0:
	{ ld8	r14,[r32]; ld8.a	r47,[r42]; nop.i	0x0; }
	{ nop.m	0x0; st8	[r14],r38; cmp.eq	p06,p07,0x0,r47 }
	{ nop.m	0x0; chk.a.clr	r47,40000000000CA4A0; nop.b	0x0 }

l40000000000C9FEC:
	{ Invalid; break.i	0x1000; mov	pr,r32,0x0 }

l40000000000C9FF0:
	{ nop.m	0x0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000CA310; }

l40000000000CA000:
	{ nop.m	0x0; ld8	r14,[r33],8; nop.i	0x0; }
	{ ld8	r1,[r33],-8; mov.spnt	b6,r14,40000000000CA010; br.call.sptk.many	b0,b6; }
	{ nop.m	0x0; sxt4	r14,r35; adds	r1,0x0,r46 }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	40000000000CA1B0; }

l40000000000CA040:
	{ ld8	r15,[r37]; shladd	r14,r14,0x3,r38; adds	r37,0x0,r34 }
	{ adds	r35,0x1,r35; st8	[r15],r14; nop.i	0x0; }
	{ nop.m	0x0; ld8	r47,[r34],8; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r47; (p06) br.cond.dptk.few	40000000000CA000; }

l40000000000CA080:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x1,r35; sxt4	r14,r35 }
	{ adds	r16,0xFFFFFFFFFFFFFFFF,r39; adds	r36,0xFFFFFFFFFFFFFFF0,r41; cmp4.eq	p09,p08,0x0,r39; }
	{ shladd	r14,r14,0x3,r38; nop.m	0x0; addp4	r16,r16,r0; }
	{ st8	[r0],r14; sxt4	r14,r39; (p07) br.cond.dpnt.few	40000000000CA330; }

l40000000000CA0C0:
	{ ld4	r15,[r40]; nop.m	0x0; shladd	r14,r14,0x3,r0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p07) br.cond.dptk.few	40000000000CA250; }

l40000000000CA0E0:
	{ adds	r14,0x8,r38; cmp4.eq	p06,p07,0x2,r35; nop.i	0x0 }
	{ adds	r15,0x10,r38; addl	r16,8,r0; (p06) br.cond.dpnt.few	40000000000CA440; }

l40000000000CA100:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000CA160; }

l40000000000CA120:
	{ add	r17,r32,r16; nop.m	0x0; sub	r16,r15,r38; }
	{ st8	[r14],r17; ld8	r14,[r15],8; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000CA120 }

l40000000000CA150:
	{ add	r43,r32,r16; nop.m	0x0; nop.i	0x0; }

l40000000000CA160:
	{ nop.m	0x0; st8	[r0],r43; adds	r47,0x0,r38 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r46; nop.m	0x0; nop.i	0x0 }

l40000000000CA190:
	{ nop.m	0x0; mov.i	ar.pfs,r45; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r44,40000000000CA1A0; br.ret	b0 }

l40000000000CA1B0:
	{ ld4	r14,[r40]; nop.m	0x0; sxt4	r15,r39; }
	{ cmp4.eq	p07,p06,0x0,r14; shladd	r15,r15,0x3,r41; (p06) br.cond.dpnt.few	40000000000CA210; }

l40000000000CA1D0:
	{ ld8	r14,[r37]; adds	r37,0x0,r34; adds	r39,0x1,r39; }
	{ st8	[r14],r15; ld8	r47,[r34],8; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r47; (p06) br.cond.dptk.few	40000000000CA000 }

l40000000000CA200:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000CA080 }

l40000000000CA210:
	{ ld8	r47,[r37]; adds	r37,0x0,r34; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ ld8	r47,[r34],8; nop.m	0x0; adds	r1,0x0,r46; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r47; (p06) br.cond.dptk.few	40000000000CA000 }

l40000000000CA240:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000CA080 }

l40000000000CA250:
	{ adds	r34,0xFFFFFFFFFFFFFFF8,r14; nop.m	0x0; add	r36,r14,r36 }
	{ shladd	r16,r16,0x3,r0; nop.m	0x0; (p09) br.cond.dpnt.few	40000000000CA2A0; }

l40000000000CA270:
	{ nop.m	0x0; (p08) add	r34,r41,r34; (p08) sub	r36,r36,r16; }

l40000000000CA27C:
	{ (p18) cmp.eq	p16,p17,r5,r64; break.x	0xB0CA2F0A01000 }

l40000000000CA280:
	{ ld8	r47,[r34],-8; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r46; cmp.eq	p07,p06,r36,r34; (p06) br.cond.dptk.few	40000000000CA280 }

l40000000000CA2A0:
	{ adds	r47,0x0,r41; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r46; br.cond.sptk.few	40000000000CA0E0 }

l40000000000CA2C0:
	{ adds	r47,0xFFFFFFFFFFFFFFFF,r36; nop.i	0x0; br.call.sptk.many	b0,strvec_create; }
	{ ld8	r14,[r32]; adds	r1,0x0,r46; adds	r41,0x0,r8 }
	{ ld8.a	r47,[r42]; st8	[r14],r38; cmp.eq	p06,p07,0x0,r47 }
	{ nop.m	0x0; chk.a.clr	r47,40000000000CA4C0; nop.b	0x0 }

l40000000000CA2FC:
	{ invala; break.i	0x1000; mov	pr,r32,0x0 }

l40000000000CA300:
	{ nop.m	0x0; nop.i	0x0; (p07) br.cond.dptk.few	40000000000CA000 }

l40000000000CA302:
	{ break.m	0x20; nop.i	0x80020; Invalid }

l40000000000CA306:
	{ chk.a.nc	f0,3FFFFFFFFF0CAB06; nop; break.i	0x80000 }

l40000000000CA308:
	{ (p16) nop; (p63) break.i	0x94AF; dep	r8,r0,r0,60,9 }

l40000000000CA30C:
	{ (p40) nop; cmp.lt	p00,p00,r32,r0; zxt1	r66,r64 }

l40000000000CA310:
	{ nop.m	0x0; adds	r14,0x8,r38; nop.i	0x0; }

l40000000000CA312:
	{ Invalid; (p33) break.i	0x42009; Invalid }
	{ (p32) break.m	0x23303; break.i	0x20; Invalid }

l40000000000CA330:
	{ ld4	r14,[r40]; nop.m	0x0; adds	r47,0x0,r41; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000CA410 }

l40000000000CA350:
	{ ld8	r47,[r32]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r46; st8	[r0],r32; adds	r47,0x0,r38 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r46; br.cond.sptk.few	40000000000CA190; }

l40000000000CA390:
	{ addl	r14,6132,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	40000000000CA190 }

l40000000000CA3B0:
	{ ld8	r14,[r33],8; ld8	r47,[r32]; nop.i	0x0; }
	{ ld8	r1,[r33],-8; mov.spnt	b6,r14,40000000000CA3C0; br.call.sptk.many	b0,b6; }
	{ adds	r1,0x0,r46; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000000CA190 }

l40000000000CA3E0:
	{ ld8	r47,[r32]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r46; st8	[r0],r32; mov.i	ar.pfs,r45; }
	{ nop.m	0x0; mov.spnt	b0,r44,40000000000CA400; br.ret	b0; }

l40000000000CA410:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r46; adds	r47,0x0,r38; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r46; br.cond.sptk.few	40000000000CA190 }

l40000000000CA440:
	{ ld8	r47,[r32]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r14,0x8,r38; adds	r1,0x0,r46; adds	r47,0x0,r38; }
	{ ld8	r14,[r14]; st8	[r14],r32; nop.i	0x0 }
	{ st8	[r0],r42; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r46; nop.m	0x0; mov.i	ar.pfs,r45; }
	{ nop.m	0x0; mov.spnt	b0,r44,40000000000CA490; br.ret	b0 }

l40000000000CA4A0:
	{ nop.m	0x0; ld8	r47,[r42]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r47; br.cond.sptk.few	40000000000C9FF0 }

l40000000000CA4C0:
	{ nop.m	0x0; ld8	r47,[r42]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r47; br.cond.sptk.few	40000000000CA300; }
40000000000CA4E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000CA4F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000CA500: 40000000000CA500
;;   Called from:
;;     40000000000D8D3C (in bash_directory_completion_matches)
fn40000000000CA500 proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x4; mov	r33,b1; nop.b	0x0 }
	{ addl	r37,-7636,r1; adds	r35,0x0,r1; adds	r36,0x0,r32; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,fn40000000000C9F00; }
	{ adds	r8,0x0,r0; adds	r1,0x0,r35; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000CA540; br.ret	b0; }
40000000000CA550 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000CA560 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000CA570 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000CA580 10 10 19 08 80 05 10 02 00 62 00 00 00 00 00 20 .........b..... 
40000000000CA590 09 28 91 FA C3 27 30 02 04 00 42 80 04 00 01 84 .(...'0...B.....
40000000000CA5A0 11 28 01 4A 18 10 00 00 00 02 00 00 68 F9 FF 58 .(.J........h..X
40000000000CA5B0 09 40 00 00 00 21 10 00 8C 00 42 00 20 02 AA 00 .@...!....B. ...
40000000000CA5C0 11 00 00 00 01 00 00 08 05 80 03 80 08 00 84 00 ................
40000000000CA5D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000CA5E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000CA5F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000CA600: 40000000000CA600
;;   Called from:
;;     40000000000CD78C (in command_word_completion_function)
;;     40000000000D714C (in bash_default_completion)
;;     40000000000D755C (in bash_default_completion)
fn40000000000CA600 proc
	{ alloc	r36,ar.pfs,0x8,0x0,0x6; nop.m	0x0; mov	r35,b3 }
	{ adds	r37,0x0,r1; nop.m	0x0; adds	r38,0x0,r32; }
	{ adds	r39,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,bash_tilde_expand; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r33,0x0,r8 }
	{ adds	r38,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,file_isdir; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r34,0x0,r8 }
	{ adds	r38,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r8,0x0,r34; adds	r1,0x0,r37; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000CA680; br.ret	b0; }
40000000000CA690 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000CA6A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000CA6B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000CA6C0: 40000000000CA6C0
;;   Called from:
;;     40000000000D89BC (in bind_keyseq_to_unix_command)
;;     40000000000D8ADC (in bind_keyseq_to_unix_command)
fn40000000000CA6C0 proc
	{ alloc	r38,ar.pfs,0xB,0x0,0x8; adds	r8,0x0,r33; mov	r37,b5 }
	{ adds	r39,0x0,r1; nop.m	0x0; sxt4	r15,r33; }
	{ add	r14,r32,r15; nop.m	0x0; add	r15,r32,r15,0x1; }
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x9,r14; cmp4.eq	p08,p09,0x0,r14; (p08) br.cond.dpnt.few	40000000000CA9D0; }

l40000000000CA710:
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x20,r14; (p06) br.cond.dpnt.few	40000000000CA9C0; }

l40000000000CA720:
	{ ld1	r14,[r15],1; adds	r8,0x1,r8; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x20,r14; cmp4.eq	p08,p09,0x0,r14; (p08) br.cond.dpnt.few	40000000000CA9E0; }

l40000000000CA740:
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x9,r14; (p06) br.cond.dptk.few	40000000000CA720; }

l40000000000CA750:
	{ cmp4.eq	p07,p06,0x27,r14; cmp4.eq	p10,p11,0x0,r34; (p10) br.cond.dptk.few	40000000000CA8E0; }

l40000000000CA760:
	{ cmp4.eq	p06,p07,0x22,r14; addl	r36,34,r0; (p07) br.cond.dpnt.few	40000000000CA9F0; }

l40000000000CA770:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p07) br.cond.dpnt.few	40000000000CA7B0; }

l40000000000CA780:
	{ adds	r8,0x1,r8; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000CA7A0:
	{ st4	[r8],r35; nop.m	0x0; nop.i	0x0 }

l40000000000CA7B0:
	{ nop.m	0x0; sxt4	r16,r8; adds	r17,0x0,r0; }
	{ add	r15,r32,r16; nop.m	0x0; add	r16,r32,r16,0x1; }
	{ ld1	r15,[r15]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dpnt.few	40000000000CA850; }

l40000000000CA7F0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000CA800:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r17; (p06) br.cond.dptk.few	40000000000CA940; }

l40000000000CA810:
	{ cmp4.eq	p06,p07,0x5C,r15; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000CA980; }

l40000000000CA820:
	{ cmp4.eq	p06,p07,r15,r36; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000CA8C0; }

l40000000000CA830:
	{ ld1	r15,[r16],1; adds	r8,0x1,r8; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	40000000000CA800; }

l40000000000CA850:
	{ cmp4.eq	p06,p07,0x0,r36; addl	r41,-7612,r1; nop.i	0x0 }
	{ adds	r40,0x0,r0; addl	r42,5,r0; (p06) br.cond.dpnt.few	40000000000CA8C0; }

l40000000000CA870:
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r39; adds	r40,0x0,r8; nop.i	0x0 }
	{ adds	r41,0x0,r36; adds	r42,0x0,r32; br.call.sptk.many	b0,builtin_error; }
	{ nop.m	0x0; adds	r1,0x0,r39; addl	r8,-1,r0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000CA8C0:
	{ nop.m	0x0; mov.i	ar.pfs,r38; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000CA8D0; br.ret	b0 }

l40000000000CA8E0:
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x22,r14; (p07) br.cond.dpnt.few	40000000000CA910; }

l40000000000CA8F0:
	{ adds	r36,0x0,r0; cmp.eq	p07,p06,0x0,r35; (p07) br.cond.dpnt.few	40000000000CA7B0; }

l40000000000CA900:
	{ st4	[r8],r35; nop.i	0x0; br.cond.sptk.few	40000000000CA7B0 }

l40000000000CA910:
	{ nop.m	0x0; adds	r36,0x0,r14; cmp.eq	p06,p07,0x0,r35 }
	{ nop.b	0x0; (p06) br.cond.dpnt.few	40000000000CA7B0; (p08) br.cond.dptk.few	40000000000CA7A0 }

l40000000000CA92C:
	{ Invalid; break.i	0x1000; zxt1	r0,r64 }

l40000000000CA930:
	{ nop.m	0x0; adds	r8,0x1,r8; br.cond.sptk.few	40000000000CA7A0; }

l40000000000CA940:
	{ ld1	r15,[r16],1; adds	r17,0x0,r0; adds	r8,0x1,r8; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	40000000000CA800 }

l40000000000CA970:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000CA850 }

l40000000000CA980:
	{ ld1	r15,[r16],1; addl	r17,1,r0; adds	r8,0x1,r8; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	40000000000CA800 }

l40000000000CA9B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000CA850 }

l40000000000CA9C0:
	{ nop.m	0x0; adds	r8,0x0,r33; br.cond.sptk.few	40000000000CA750; }

l40000000000CA9D0:
	{ adds	r8,0x0,r33; nop.m	0x0; nop.i	0x0; }

l40000000000CA9E0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r34; (p07) br.cond.dptk.few	40000000000CA8F0 }

l40000000000CA9F0:
	{ addl	r41,-7620,r1; addl	r42,5,r0; adds	r40,0x0,r0; }
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r40,0x0,r8 }
	{ adds	r41,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,builtin_error; }
	{ addl	r8,-1,r0; adds	r1,0x0,r39; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000CAA40; br.ret	b0; }
40000000000CAA50 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000CAA60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000CAA70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000CAA80 08 20 21 0C 80 05 00 00 00 02 00 60 04 00 C4 00 . !........`....
40000000000CAA90 09 28 01 02 00 21 00 00 00 02 00 C0 04 00 01 84 .(...!..........
40000000000CAAA0 11 00 00 00 01 00 00 00 00 02 00 00 28 0C F5 58 ............(..X
40000000000CAAB0 03 08 00 4A 00 21 20 02 20 00 42 C0 41 E9 9F 9D ...J.! . .B.A...
40000000000CAAC0 0B 00 00 00 01 00 E0 40 38 00 42 00 00 00 04 00 .......@8.B.....
40000000000CAAD0 0B 08 01 1C 18 10 60 02 84 30 20 00 00 00 04 00 ......`..0 .....
40000000000CAAE0 11 00 00 00 01 00 60 00 98 0E 72 03 C0 00 00 43 ......`...r....C
40000000000CAAF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000CAB00 09 70 20 42 00 21 00 00 00 02 00 20 04 09 01 84 .p B.!..... ....
40000000000CAB10 09 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
40000000000CAB20 11 00 00 00 01 00 70 70 88 0C 61 03 60 00 00 42 ......pp..a.`..B
40000000000CAB30 11 38 89 1C 05 20 70 00 38 0C 63 03 50 00 00 43 .8... p.8.c.P..C
40000000000CAB40 00 00 00 00 01 00 70 02 9C 2C 00 00 00 00 04 00 ......p..,......
40000000000CAB50 0B 70 00 4C 00 10 70 02 9D 00 40 E0 01 70 50 00 .p.L..p...@..pP.
40000000000CAB60 0B 70 00 4E 00 10 00 00 00 02 00 C0 01 70 50 00 .p.N.........pP.
40000000000CAB70 10 00 00 00 01 00 70 78 38 0C F1 03 50 00 00 43 ......px8...P..C
40000000000CAB80 09 00 00 00 01 00 60 02 84 30 20 00 00 00 04 00 ......`..0 .....
40000000000CAB90 10 00 00 00 01 00 70 00 98 0C 72 03 70 FF FF 4A ......p...r.p..J
40000000000CABA0 09 40 04 00 00 24 00 00 00 02 00 00 40 02 AA 00 .@...$......@...
40000000000CABB0 11 00 00 00 01 00 00 18 05 80 03 80 08 00 84 00 ................
40000000000CABC0 11 00 00 00 01 00 00 00 00 02 00 00 88 F9 F4 58 ...............X
40000000000CABD0 10 08 00 4A 00 21 60 00 20 0E F3 03 B0 FF FF 4A ...J.!`. ......J
40000000000CABE0 09 40 00 00 00 21 00 00 00 02 00 00 40 02 AA 00 .@...!......@...
40000000000CABF0 11 00 00 00 01 00 00 18 05 80 03 80 08 00 84 00 ................
40000000000CAC00 08 10 15 08 80 05 00 E2 06 7C 48 20 04 00 C4 00 .........|H ....
40000000000CAC10 0B 18 01 02 00 21 E0 00 80 30 20 00 00 00 04 00 .....!...0 .....
40000000000CAC20 11 30 00 1C 07 39 40 02 38 00 42 03 80 00 00 43 .0...9@.8.B....C
40000000000CAC30 11 00 00 00 01 00 00 00 00 02 00 00 38 F8 F4 58 ............8..X
40000000000CAC40 08 00 00 00 01 00 10 00 8C 00 42 00 00 00 04 00 ..........B.....
40000000000CAC50 19 20 01 40 18 10 00 00 00 02 00 00 98 FB F4 58 . .@...........X
40000000000CAC60 09 08 00 46 00 21 00 00 80 30 23 00 00 00 04 00 ...F.!...0#.....
40000000000CAC70 0B 70 50 03 3E 24 F0 00 38 30 20 C0 C1 EE B7 9E .pP.>$..80 .....
40000000000CAC80 09 00 00 00 01 00 E0 00 38 30 20 00 00 00 04 00 ........80 .....
40000000000CAC90 08 00 3C 1C 98 11 00 00 00 02 00 00 00 00 04 00 ..<.............
40000000000CACA0 09 40 00 00 00 21 00 00 00 02 00 00 20 02 AA 00 .@...!...... ...
40000000000CACB0 11 00 00 00 01 00 00 08 05 80 03 80 08 00 84 00 ................
40000000000CACC0 08 10 19 08 80 05 E0 A0 F5 59 4F 20 04 00 C4 00 .........YO ....
40000000000CACD0 09 18 01 02 00 21 00 00 00 02 00 80 04 00 01 84 .....!..........
40000000000CACE0 09 00 00 00 01 00 E0 00 38 30 20 00 00 00 04 00 ........80 .....
40000000000CACF0 11 28 01 1C 18 10 00 00 00 02 00 00 D8 01 F5 58 .(.............X
40000000000CAD00 09 08 00 46 00 21 00 00 00 02 00 00 20 02 AA 00 ...F.!...... ...
40000000000CAD10 11 00 00 00 01 00 00 08 05 80 03 80 08 00 84 00 ................
40000000000CAD20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000CAD30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000CAD40: 40000000000CAD40
;;   Called from:
;;     40000000000CD57C (in command_word_completion_function)
;;     40000000000CD57C (in command_word_completion_function)
;;     40000000000CDD6C (in command_word_completion_function)
fn40000000000CAD40 proc
	{ alloc	r40,ar.pfs,0xC,0x0,0xA; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ adds	r41,0x0,r1; mov	r39,b7; adds	r42,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ cmp.eq	p06,p07,0x0,r33; adds	r1,0x0,r41; nop.i	0x0 }
	{ adds	r38,0x0,r8; adds	r42,0x0,r33; adds	r43,0x0,r0; }
	{ (p06) adds	r34,0x0,r0; (p06) br.cond.dpnt.few	40000000000CADB0; br.call.sptk.many	b0,fn40000000000C9C40; }

l40000000000CAD96:
	{ Invalid; (p32) nop; break.i	0x80000; }

l40000000000CAD9C:
	{ (p53) nop; nop; br.cond.sptk.few	40000000004EAE3C }
	{ cmpxchg4.acq	r8,[r66],r0; break.x	0x10802200A01000 }

l40000000000CADB0:
	{ adds	r42,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r41; adds	r42,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r42,0x0,r8 }
	{ adds	r43,0x0,r34; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r41; adds	r14,0x10,r12; adds	r42,0x10,r12; }
	{ st8	[r8],r14; nop.m	0x0; addl	r14,-10196,r1; }
	{ ld8	r14,[r14]; ld8	r8,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r8; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000CAF90; }

l40000000000CAE30:
	{ ld8	r14,[r8],8; ld8	r1,[r8]; mov.spnt	b6,r14,40000000000CAE30 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,b6; }
	{ adds	r1,0x0,r41; nop.m	0x0; nop.i	0x0 }

l40000000000CAE60:
	{ adds	r42,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r43,0x0,r0; adds	r36,0x0,r8; nop.i	0x0 }
	{ adds	r1,0x0,r41; adds	r42,0x0,r33; br.call.sptk.many	b0,bash_tilde_expand; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r42,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r37,0x0,r8 }
	{ adds	r42,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r42,0x2,r36; sub	r38,r38,r37; adds	r1,0x0,r41; }
	{ nop.m	0x0; add	r42,r42,r38,0x1; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r42,r42; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r41; adds	r35,0x0,r8; nop.i	0x0 }
	{ adds	r43,0x0,r34; adds	r42,0x0,r8; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; sxt4	r43,r37; sxt4	r42,r36 }
	{ nop.m	0x0; adds	r1,0x0,r41; nop.b	0x0; }
	{ add	r43,r32,r43; add	r42,r35,r42; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r41; adds	r42,0x0,r34; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r41; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000CAF70; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0; }

l40000000000CAF90:
	{ addl	r14,-10612,r1; nop.m	0x0; adds	r42,0x10,r12; }
	{ ld8	r14,[r14]; ld8	r8,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r8; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000CAFF0; }

l40000000000CAFC0:
	{ nop.m	0x0; ld8	r14,[r8],8; nop.i	0x0; }
	{ ld8	r1,[r8]; mov.spnt	b6,r14,40000000000CAFD0; br.call.sptk.many	b0,b6; }
	{ adds	r1,0x0,r41; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dpnt.few	40000000000CB1C0; }

l40000000000CAFF0:
	{ addl	r14,-10228,r1; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000CAE60 }

l40000000000CB020:
	{ adds	r14,0x10,r12; ld8	r42,[r14]; addl	r14,-10572,r1; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ ld4	r43,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn40000000000C9C40; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r42,0x0,r34; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r14,0x10,r12; adds	r34,0x0,r35; adds	r1,0x0,r41; }
	{ ld8	r42,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r41; adds	r42,0x0,r34; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r43,0x0,r0; adds	r36,0x0,r8; nop.i	0x0 }
	{ adds	r1,0x0,r41; adds	r42,0x0,r33; br.call.sptk.many	b0,bash_tilde_expand; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r42,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r37,0x0,r8 }
	{ adds	r42,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r42,0x2,r36; sub	r38,r38,r37; adds	r1,0x0,r41; }
	{ nop.m	0x0; add	r42,r42,r38,0x1; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r42,r42; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r41; adds	r35,0x0,r8; nop.i	0x0 }
	{ adds	r43,0x0,r34; adds	r42,0x0,r8; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; sxt4	r43,r37; sxt4	r42,r36 }
	{ nop.m	0x0; adds	r1,0x0,r41; nop.b	0x0; }
	{ add	r43,r32,r43; add	r42,r35,r42; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r41; adds	r42,0x0,r34; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r41; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000CB1A0; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0; }

l40000000000CB1C0:
	{ adds	r42,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r14,0x10,r12; nop.m	0x0; adds	r1,0x0,r41; }
	{ nop.m	0x0; ld8	r34,[r14]; nop.i	0x0; }
	{ adds	r42,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r43,0x0,r0; adds	r36,0x0,r8; nop.i	0x0 }
	{ adds	r1,0x0,r41; adds	r42,0x0,r33; br.call.sptk.many	b0,bash_tilde_expand; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r42,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r37,0x0,r8 }
	{ adds	r42,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r42,0x2,r36; sub	r38,r38,r37; adds	r1,0x0,r41; }
	{ nop.m	0x0; add	r42,r42,r38,0x1; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r42,r42; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r41; adds	r35,0x0,r8; nop.i	0x0 }
	{ adds	r43,0x0,r34; adds	r42,0x0,r8; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; sxt4	r43,r37; sxt4	r42,r36 }
	{ nop.m	0x0; adds	r1,0x0,r41; nop.b	0x0; }
	{ add	r43,r32,r43; add	r42,r35,r42; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r41; adds	r42,0x0,r34; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r41; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000CB300; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0; }
40000000000CB320 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000CB330 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000CB340 18 50 3D 18 80 05 C0 80 33 7C 46 00 00 00 00 20 .P=.....3|F.... 
40000000000CB350 09 08 01 40 18 10 B0 02 04 00 42 20 05 00 C4 00 ...@......B ....
40000000000CB360 11 68 91 00 00 24 C0 02 84 00 42 00 68 C2 06 50 .h...$....B.h..P
40000000000CB370 08 30 00 10 07 39 00 00 00 02 00 00 11 40 00 84 .0...9.......@..
40000000000CB380 19 08 00 56 00 21 00 00 00 02 00 03 80 05 00 43 ...V.!.........C
40000000000CB390 09 00 00 00 01 00 20 02 20 00 20 00 00 00 04 00 ...... . . .....
40000000000CB3A0 03 00 00 00 01 00 20 02 88 28 00 C0 80 12 1D E6 ...... ..(......
40000000000CB3B0 D1 20 A5 00 00 A4 51 22 01 00 48 03 30 00 00 43 . ....Q"..H.0..C
40000000000CB3C0 09 30 EC 45 87 39 00 00 00 02 00 A0 44 02 00 90 .0.E.9......D...
40000000000CB3D0 E2 10 01 00 00 A1 41 EA 03 00 C8 83 04 00 00 84 ......A.........
40000000000CB3E0 08 60 05 00 00 24 00 00 00 02 00 A0 05 08 01 84 .`...$..........
40000000000CB3F0 19 70 41 18 00 21 00 00 00 02 00 00 B8 0C F5 58 .pA..!.........X
40000000000CB400 10 08 00 56 00 21 60 00 20 0E 73 03 20 05 00 42 ...V.!`. .s. ..B
40000000000CB410 11 60 01 42 00 21 00 00 00 02 00 00 B8 02 F5 58 .`.B.!.........X
40000000000CB420 11 08 00 56 00 21 C0 0A 20 00 42 00 A8 D8 01 50 ...V.!.. .B....P
40000000000CB430 08 08 00 56 00 21 00 00 00 02 00 80 05 40 00 84 ...V.!.......@..
40000000000CB440 19 68 01 42 00 21 00 00 00 02 00 00 48 FD F4 58 .h.B.!......H..X
40000000000CB450 08 08 00 56 00 21 80 02 20 00 42 80 05 40 00 84 ...V.!.. .B..@..
40000000000CB460 19 68 01 00 00 21 E0 02 00 10 48 00 68 A4 FD 58 .h...!....H.h..X
40000000000CB470 08 30 01 10 00 21 00 00 00 02 00 E0 00 40 18 E4 .0...!.......@..
40000000000CB480 19 08 00 56 00 21 00 00 00 02 80 03 C0 07 00 43 ...V.!.........C
40000000000CB490 11 60 01 4C 00 21 00 00 00 02 00 00 B8 37 FC 58 .`.L.!.......7.X
40000000000CB4A0 09 78 00 42 40 10 00 40 80 30 23 20 00 58 01 84 .x.B@..@.0# .X..
40000000000CB4B0 09 70 00 10 00 10 F0 00 84 00 22 00 00 00 04 00 .p........".....
40000000000CB4C0 01 00 00 00 01 00 E0 00 38 28 00 E0 01 78 50 00 ........8(...xP.
40000000000CB4D0 11 00 00 00 01 00 70 78 38 0C F1 03 E0 05 00 43 ......px8......C
40000000000CB4E0 C8 18 05 00 00 24 00 00 00 02 00 00 00 00 04 00 .....$..........
40000000000CB4F0 09 38 51 FA B0 27 00 00 00 02 00 80 05 08 01 84 .8Q..'..........
40000000000CB500 11 38 01 4E 18 10 00 00 00 02 00 00 E8 F2 F4 58 .8.N...........X
40000000000CB510 11 08 00 56 00 21 C0 02 A0 00 42 00 D8 F2 F4 58 ...V.!....B....X
40000000000CB520 11 08 00 56 00 21 C0 02 98 00 42 00 A8 06 F8 58 ...V.!....B....X
40000000000CB530 08 00 00 00 01 00 E0 00 9C 30 20 20 00 58 01 84 .........0  .X..
40000000000CB540 09 00 00 00 01 00 10 02 80 30 20 00 00 00 04 00 .........0 .....
40000000000CB550 11 30 00 1C 07 39 00 00 00 02 00 03 20 01 00 43 .0...9...... ..C
40000000000CB560 0B 70 00 1C 00 10 00 00 00 02 00 C0 01 70 50 00 .p...........pP.
40000000000CB570 10 00 00 00 01 00 60 00 38 0E 73 03 00 01 00 42 ......`.8.s....B
40000000000CB580 09 30 71 02 3D 24 00 00 00 02 00 A0 A5 01 00 90 .0q.=$..........
40000000000CB590 11 60 01 4C 18 10 00 00 00 02 00 00 78 D8 01 50 .`.L........x..P
40000000000CB5A0 08 08 00 56 00 21 00 40 98 30 23 C0 01 02 00 90 ...V.!.@.0#.....
40000000000CB5B0 02 78 80 00 00 24 10 01 00 00 42 00 C2 0E BC 90 .x...$....B.....
40000000000CB5C0 0B 00 00 00 01 00 00 01 40 30 20 00 00 00 04 00 ........@0 .....
40000000000CB5D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000CB5E0 09 30 94 1C 87 38 00 00 00 02 00 00 41 72 24 E2 .0...8......Ar$.
40000000000CB5F0 10 00 00 00 01 00 60 10 39 8E 71 03 40 00 00 42 ......`.9.q.@..B
40000000000CB600 01 00 00 00 01 00 E0 00 44 2C 80 24 12 88 00 84 ........D,.$....
40000000000CB610 29 71 20 1C 00 20 00 00 00 02 00 00 00 00 04 00 )q .. ..........
40000000000CB620 28 01 3C 1C 80 11 00 00 00 02 00 00 00 00 04 00 (.<.............
40000000000CB630 0B 70 04 20 00 14 00 00 00 02 00 C0 01 70 50 00 .p. .........pP.
40000000000CB640 10 78 00 1C 00 21 70 00 38 0C 73 03 A0 FF FF 4A .x...!p.8.s....J
40000000000CB650 03 00 00 00 01 00 10 01 44 2C 00 20 82 88 00 80 ........D,. ....
40000000000CB660 08 00 00 22 80 11 00 40 9C 30 23 00 00 00 04 00 ..."...@.0#.....
40000000000CB670 0B 70 00 03 39 24 00 00 00 02 00 00 00 00 04 00 .p..9$..........
40000000000CB680 09 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
40000000000CB690 10 00 00 00 01 00 70 00 38 0C 73 03 50 02 00 42 ......p.8.s.P..B
40000000000CB6A0 0B 70 00 42 00 10 00 00 00 02 00 C0 01 70 50 00 .p.B.........pP.
40000000000CB6B0 10 00 00 00 01 00 70 70 39 0C 73 03 40 00 00 42 ......pp9.s.@..B
40000000000CB6C0 0B 70 04 42 00 21 E0 00 38 00 20 00 00 00 04 00 .p.B.!..8. .....
40000000000CB6D0 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
40000000000CB6E0 10 00 00 00 01 00 60 00 38 0E 73 03 00 02 00 42 ......`.8.s....B
40000000000CB6F0 09 00 00 00 01 00 C0 E2 F6 89 4F 00 00 00 04 00 ..........O.....
40000000000CB700 11 60 01 58 18 10 00 00 00 02 00 00 C8 3B 02 50 .`.X.........;.P
40000000000CB710 08 08 00 56 00 21 40 02 20 00 42 00 00 00 04 00 ...V.!@. .B.....
40000000000CB720 19 68 01 10 00 21 C0 02 84 00 42 00 E8 55 F7 58 .h...!....B..U.X
40000000000CB730 08 60 01 48 00 21 00 00 00 02 00 40 04 40 00 84 .`.H.!.....@.@..
40000000000CB740 19 08 00 56 00 21 00 00 00 02 00 00 A8 F0 F4 58 ...V.!.........X
40000000000CB750 08 08 00 56 00 21 00 00 00 02 00 80 05 10 01 84 ...V.!..........
40000000000CB760 19 68 0D 00 00 24 00 00 00 02 00 00 E8 16 06 50 .h...$.........P
40000000000CB770 08 38 00 10 06 39 10 00 AC 00 42 00 00 00 04 00 .8...9....B.....
40000000000CB780 19 20 01 10 00 21 C0 02 88 00 C2 03 60 04 00 43 . ...!......`..C
40000000000CB790 11 00 00 00 01 00 00 00 00 02 00 00 38 FF F4 58 ............8..X
40000000000CB7A0 01 00 00 00 01 00 80 00 20 2C 00 20 00 58 01 84 ........ ,. .X..
40000000000CB7B0 03 70 88 10 00 20 00 00 00 02 00 C0 F1 77 FC 8C .p... .......w..
40000000000CB7C0 0B 28 01 1C 00 10 00 00 00 02 00 A0 04 28 51 00 .(...........(Q.
40000000000CB7D0 10 00 00 00 01 00 70 78 95 0C F3 03 20 03 00 43 ......px.... ..C
40000000000CB7E0 09 70 A0 03 3C 24 50 02 84 00 20 00 00 00 04 00 .p..<$P... .....
40000000000CB7F0 09 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
40000000000CB800 10 00 00 00 01 00 60 00 38 0E F3 03 70 02 00 42 ......`.8...p..B
40000000000CB810 03 00 00 00 01 00 50 02 94 28 00 C0 21 2D FD 8C ......P..(..!-..
40000000000CB820 01 00 00 00 01 00 E0 00 38 20 00 00 00 00 04 00 ........8 ......
40000000000CB830 11 38 04 1C 86 35 00 00 00 02 00 03 70 00 00 43 .8...5......p..C
40000000000CB840 09 30 01 48 00 10 E0 00 88 00 20 00 00 00 04 00 .0.H...... .....
40000000000CB850 01 00 00 00 01 00 60 02 98 28 00 C0 01 70 50 00 ......`..(...pP.
40000000000CB860 11 00 00 00 01 00 70 70 98 0C F1 03 F0 04 00 43 ......pp.......C
40000000000CB870 11 00 00 00 01 00 70 30 95 0C F1 03 30 03 00 43 ......p0....0..C
40000000000CB880 C9 40 04 00 00 24 00 00 00 02 00 00 00 00 04 00 .@...$..........
40000000000CB890 08 18 8D 10 0E 20 00 00 00 02 00 00 00 00 04 00 ..... ..........
40000000000CB8A0 11 60 01 42 00 21 00 00 00 02 00 00 48 EF F4 58 .`.B.!......H..X
40000000000CB8B0 08 08 00 56 00 21 00 00 00 02 00 80 05 10 01 84 ...V.!..........
40000000000CB8C0 19 00 90 40 98 11 00 00 00 02 00 00 28 EF F4 58 ...@........(..X
40000000000CB8D0 08 08 00 56 00 21 00 00 00 02 00 00 00 00 04 00 ...V.!..........
40000000000CB8E0 02 40 00 46 00 21 00 50 01 55 00 00 90 0A 00 07 .@.F.!.P.U......
40000000000CB8F0 19 00 00 00 01 00 C0 80 30 02 42 80 08 00 84 00 ........0.B.....
40000000000CB900 11 60 01 42 00 21 D0 02 03 00 48 00 C8 BC 06 50 .`.B.!....H....P
40000000000CB910 11 08 00 56 00 21 60 00 20 0E F2 03 A0 03 00 42 ...V.!`. ......B
40000000000CB920 09 70 D0 FA AD 27 00 00 00 02 00 80 05 08 01 84 .p...'..........
40000000000CB930 09 00 00 00 01 00 E0 00 38 30 20 00 00 00 04 00 ........80 .....
40000000000CB940 11 68 01 1C 10 10 00 00 00 02 00 00 08 E3 FF 58 .h.............X
40000000000CB950 08 78 00 42 00 10 00 00 00 02 00 20 00 58 01 84 .x.B....... .X..
40000000000CB960 09 10 01 10 00 21 E0 00 20 00 20 00 00 00 04 00 .....!.. . .....
40000000000CB970 01 00 00 00 01 00 F0 00 3C 28 00 C0 01 70 50 00 ........<(...pP.
40000000000CB980 10 00 00 00 01 00 60 78 38 0E 71 03 80 00 00 43 ......`x8.q....C
40000000000CB990 08 60 01 42 00 21 00 00 00 02 00 60 14 00 00 90 .`.B.!.....`....
40000000000CB9A0 19 08 01 44 00 21 00 00 00 02 00 00 48 EE F4 58 ...D.!......H..X
40000000000CB9B0 09 08 00 56 00 21 00 10 81 30 23 00 00 00 04 00 ...V.!...0#.....
40000000000CB9C0 0B 70 00 03 39 24 00 00 00 02 00 00 00 00 04 00 .p..9$..........
40000000000CB9D0 09 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
40000000000CB9E0 10 00 00 00 01 00 70 00 38 0C 73 03 00 FF FF 4A ......p.8.s....J
40000000000CB9F0 10 00 00 00 01 00 00 00 00 02 00 00 B0 FC FF 48 ...............H
40000000000CBA00 11 60 01 42 00 21 D0 02 88 00 42 00 48 EB F4 58 .`.B.!....B.H..X
40000000000CBA10 08 00 00 00 01 00 60 00 20 0E 73 20 00 58 01 84 ......`. .s .X..
40000000000CBA20 19 00 00 00 01 00 00 00 00 02 80 03 70 FF FF 4A ............p..J
40000000000CBA30 C8 18 01 00 00 21 00 00 00 02 00 00 00 00 04 00 .....!..........
40000000000CBA40 11 60 01 42 00 21 10 02 88 00 42 00 A8 ED F4 58 .`.B.!....B....X
40000000000CBA50 08 00 00 00 01 00 10 00 AC 00 42 00 00 00 04 00 ..........B.....
40000000000CBA60 18 00 88 40 98 11 00 00 00 02 00 00 60 FF FF 48 ...@........`..H
40000000000CBA70 09 30 01 48 00 10 00 00 00 02 00 A0 04 28 51 00 .0.H.........(Q.
40000000000CBA80 03 00 00 00 01 00 60 02 98 28 00 E0 60 2A 19 E2 ......`..(..`*..
40000000000CBA90 10 00 00 00 01 80 81 08 00 00 48 03 00 FE FF 4A ..........H....J
40000000000CBAA0 11 00 00 00 01 00 00 00 00 02 00 00 00 01 00 40 ...............@
40000000000CBAB0 11 60 01 42 00 21 D0 02 20 00 42 00 98 EA F4 58 .`.B.!.. .B....X
40000000000CBAC0 03 38 00 10 86 39 10 00 AC 00 42 03 11 00 00 90 .8...9....B.....
40000000000CBAD0 09 00 00 00 01 C0 81 00 00 00 42 00 00 00 04 00 ..........B.....
40000000000CBAE0 10 00 00 00 01 00 30 02 20 00 42 00 10 FA FF 48 ......0. .B....H
40000000000CBAF0 11 60 01 48 00 21 00 00 00 02 00 00 D8 FB F4 58 .`.H.!.........X
40000000000CBB00 08 00 00 00 01 00 60 02 20 00 42 20 00 58 01 84 ......`. .B .X..
40000000000CBB10 19 00 00 00 01 00 70 10 20 0C 63 03 D0 FC FF 4A ......p. .c....J
40000000000CBB20 01 68 09 10 00 21 60 02 98 2C 00 80 05 20 01 84 .h...!`..,... ..
40000000000CBB30 11 00 00 00 01 00 D0 02 B4 2C 00 00 D8 D2 01 50 .........,.....P
40000000000CBB40 09 30 21 4C 00 20 10 00 AC 00 42 80 04 40 00 84 .0!L. ....B..@..
40000000000CBB50 09 08 94 4C 80 15 00 00 00 02 00 C0 81 0E F0 90 ...L............
40000000000CBB60 09 00 00 00 01 00 00 00 98 00 23 00 00 00 04 00 ..........#.....
40000000000CBB70 09 70 00 1C 10 10 50 02 84 00 20 00 00 00 04 00 .p....P... .....
40000000000CBB80 10 00 00 00 01 00 60 00 38 0E 73 03 90 FC FF 4A ......`.8.s....J
40000000000CBB90 10 00 00 00 01 00 00 00 00 02 00 00 E0 FE FF 48 ...............H
40000000000CBBA0 11 60 01 42 00 21 D0 02 90 00 42 00 A8 E9 F4 58 .`.B.!....B....X
40000000000CBBB0 03 38 00 10 86 39 10 00 AC 00 42 03 11 00 00 90 .8...9....B.....
40000000000CBBC0 09 00 00 00 01 C0 81 00 00 00 42 00 00 00 04 00 ..........B.....
40000000000CBBD0 10 00 00 00 01 00 30 1A 21 1C 40 00 D0 FC FF 48 ......0.!.@....H
40000000000CBBE0 0B 70 C0 03 3C 24 E0 00 38 20 20 00 00 00 04 00 .p..<$..8  .....
40000000000CBBF0 10 00 00 00 01 00 60 00 38 0E F3 03 C0 01 00 43 ......`.8......C
40000000000CBC00 11 60 01 44 00 21 00 00 00 02 00 00 E8 EB F4 58 .`.D.!.........X
40000000000CBC10 09 40 00 46 00 21 10 00 AC 00 42 00 A0 02 AA 00 .@.F.!....B.....
40000000000CBC20 00 00 00 00 01 00 00 48 05 80 03 00 00 00 04 00 .......H........
40000000000CBC30 19 60 40 18 01 21 00 00 00 02 00 80 08 00 84 00 .`@..!..........
40000000000CBC40 11 60 01 50 00 21 30 0A 00 00 48 00 A8 EB F4 58 .`.P.!0...H....X
40000000000CBC50 11 08 00 56 00 21 C0 02 84 00 42 00 98 EB F4 58 ...V.!....B....X
40000000000CBC60 11 08 00 56 00 21 C0 0A 00 00 48 00 68 D0 01 50 ...V.!....H.h..P
40000000000CBC70 18 08 00 56 00 21 00 40 80 30 23 00 00 00 00 20 ...V.!.@.0#.... 
40000000000CBC80 09 00 00 10 80 11 80 00 8C 00 42 00 A0 02 AA 00 ..........B.....
40000000000CBC90 00 00 00 00 01 00 00 48 05 80 03 00 00 00 04 00 .......H........
40000000000CBCA0 19 60 40 18 01 21 00 00 00 02 00 80 08 00 84 00 .`@..!..........
40000000000CBCB0 11 60 01 42 00 21 00 00 00 02 00 00 18 FA F4 58 .`.B.!.........X
40000000000CBCC0 09 08 00 56 00 21 C0 02 84 00 42 A0 05 40 00 84 ...V.!....B..@..
40000000000CBCD0 09 00 00 00 01 00 E0 62 F6 89 4F 00 00 00 04 00 .......b..O.....
40000000000CBCE0 11 70 01 5C 18 10 00 00 00 02 00 00 28 18 FC 58 .p.\........(..X
40000000000CBCF0 10 08 00 56 00 21 60 00 20 0E F3 03 30 FC FF 4A ...V.!`. ...0..J
40000000000CBD00 08 60 05 00 00 24 D0 02 84 00 42 C0 05 61 00 84 .`...$....B..a..
40000000000CBD10 19 20 01 00 00 21 20 02 00 00 42 00 98 03 F5 58 . ...! ...B....X
40000000000CBD20 08 00 00 00 01 00 50 02 03 00 48 20 00 58 01 84 ......P...H .X..
40000000000CBD30 18 00 00 00 01 00 60 00 20 0E 73 03 F0 FB FF 4A ......`. .s....J
40000000000CBD40 10 00 00 00 01 00 00 00 00 02 00 00 D0 F6 FF 48 ...............H
40000000000CBD50 11 60 01 44 00 21 D0 02 90 00 42 00 F8 E7 F4 58 .`.D.!....B....X
40000000000CBD60 10 08 00 56 00 21 60 00 20 0E F3 03 10 FB FF 4A ...V.!`. ......J
40000000000CBD70 11 60 01 42 00 21 00 00 00 02 00 00 78 EA F4 58 .`.B.!......x..X
40000000000CBD80 08 08 00 56 00 21 00 00 00 02 00 80 05 10 01 84 ...V.!..........
40000000000CBD90 19 00 90 40 98 11 00 00 00 02 00 00 58 EA F4 58 ...@........X..X
40000000000CBDA0 10 00 00 00 01 00 10 00 AC 00 42 00 40 FB FF 48 ..........B.@..H
40000000000CBDB0 11 60 01 44 00 21 00 00 00 02 00 00 58 55 06 50 .`.D.!......XU.P
40000000000CBDC0 08 30 00 10 07 39 50 02 20 00 42 00 00 00 04 00 .0...9P. .B.....
40000000000CBDD0 19 08 00 56 00 21 C0 02 88 00 42 03 30 FE FF 4B ...V.!....B.0..K
40000000000CBDE0 11 00 00 00 01 00 00 00 00 02 00 00 08 EA F4 58 ...............X
40000000000CBDF0 08 60 01 4A 00 21 10 00 AC 00 42 00 00 00 04 00 .`.J.!....B.....
40000000000CBE00 19 68 0D 00 00 24 20 02 94 00 42 00 48 10 06 50 .h...$ ...B.H..P
40000000000CBE10 08 38 00 10 06 39 00 00 00 02 00 20 00 58 01 84 .8...9..... .X..
40000000000CBE20 03 20 01 10 00 21 C0 02 88 00 42 C3 11 00 00 90 . ...!....B.....
40000000000CBE30 09 00 00 00 01 C0 E1 00 00 00 42 00 00 00 04 00 ..........B.....
40000000000CBE40 13 18 8D 1C 0E E0 01 E0 FE FF 24 00 88 F8 F4 58 ..........$....X
40000000000CBE50 01 00 00 00 01 00 80 00 20 2C 00 20 00 58 01 84 ........ ,. .X..
40000000000CBE60 03 70 88 10 00 20 00 00 00 02 00 C0 F1 77 FC 8C .p... .......w..
40000000000CBE70 0B 28 01 1C 00 10 00 00 00 02 00 A0 04 28 51 00 .(...........(Q.
40000000000CBE80 10 00 00 00 01 00 70 78 95 0C 73 03 60 F9 FF 4A ......px..s.`..J
40000000000CBE90 11 00 00 00 01 00 00 00 00 02 00 00 60 FC FF 48 ............`..H
40000000000CBEA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000CBEB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000CBEC0 08 40 31 14 80 05 00 00 00 02 00 E0 04 00 C4 00 .@1.............
40000000000CBED0 19 48 01 02 00 21 60 00 84 0E 73 03 70 00 00 42 .H...!`...s.p..B
40000000000CBEE0 09 80 F0 03 3C 24 E0 A0 04 7A 48 00 80 02 AA 00 ....<$...zH.....
40000000000CBEF0 08 00 00 00 01 00 80 00 40 30 20 00 70 0A 00 07 ........@0 .p...
40000000000CBF00 0B 78 00 1C 10 10 60 00 20 0E 72 00 12 78 00 84 .x....`. .r..x..
40000000000CBF10 00 00 00 00 01 C0 F1 00 3C 2C 00 03 01 00 00 84 ........<,......
40000000000CBF20 0B 00 40 1C 90 D1 81 78 20 24 40 00 00 00 04 00 ..@....x $@.....
40000000000CBF30 F0 40 00 10 18 10 00 00 00 02 00 80 08 00 84 00 .@..............
40000000000CBF40 09 20 F1 03 3C 24 E0 20 F6 61 4F E0 11 00 00 90 . ..<$. .aO.....
40000000000CBF50 09 50 01 48 18 10 E0 00 38 30 20 00 00 00 04 00 .P.H....80 .....
40000000000CBF60 0A 30 00 54 07 39 00 78 38 20 23 00 00 00 04 00 .0.T.9.x8 #.....
40000000000CBF70 17 00 00 00 00 88 01 10 00 80 21 00 78 E8 F4 58 ..........!.x..X
40000000000CBF80 09 08 00 52 00 21 00 00 00 02 00 00 00 00 04 00 ...R.!..........
40000000000CBF90 09 28 11 02 3D 24 00 00 00 02 00 60 C4 08 F4 90 .(..=$.....`....
40000000000CBFA0 09 10 01 46 18 10 A0 02 94 30 20 00 00 00 04 00 ...F.....0 .....
40000000000CBFB0 11 30 88 54 07 38 00 00 00 02 00 03 40 00 00 43 .0.T.8......@..C
40000000000CBFC0 11 30 00 54 07 39 00 00 00 02 00 03 30 00 00 43 .0.T.9......0..C
40000000000CBFD0 11 00 00 00 01 00 00 00 00 02 00 00 18 E8 F4 58 ...............X
40000000000CBFE0 08 08 00 52 00 21 00 00 00 02 00 00 00 00 04 00 ...R.!..........
40000000000CBFF0 11 30 00 44 07 39 A0 02 88 00 42 03 30 00 00 43 .0.D.9....B.0..C
40000000000CC000 11 00 00 00 01 00 00 00 00 02 00 00 E8 E7 F4 58 ...............X
40000000000CC010 08 08 00 52 00 21 00 00 00 02 00 00 00 00 04 00 ...R.!..........
40000000000CC020 11 50 01 40 00 21 B0 02 00 00 42 00 A8 5B F7 58 .P.@.!....B..[.X
40000000000CC030 09 08 00 52 00 21 20 02 20 00 42 40 05 40 00 84 ...R.! . .B@.@..
40000000000CC040 0B 70 50 FB B0 27 E0 00 38 30 20 00 00 00 04 00 .pP..'..80 .....
40000000000CC050 09 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
40000000000CC060 10 00 00 00 01 00 60 00 38 0E 73 03 D0 01 00 42 ......`.8.s....B
40000000000CC070 11 00 00 00 01 00 00 00 00 02 00 00 58 F6 F4 58 ............X..X
40000000000CC080 11 08 00 52 00 21 A0 0A 20 00 42 00 48 CC 01 50 ...R.!.. .B.H..P
40000000000CC090 08 58 01 44 00 21 00 00 00 02 00 20 00 48 01 84 .X.D.!..... .H..
40000000000CC0A0 19 50 01 10 00 21 00 00 00 02 00 00 E8 F0 F4 58 .P...!.........X
40000000000CC0B0 08 50 01 44 00 21 00 00 00 02 00 20 00 48 01 84 .P.D.!..... .H..
40000000000CC0C0 19 00 20 4A 98 11 00 00 00 02 00 00 08 F6 F4 58 .. J...........X
40000000000CC0D0 09 50 09 10 00 21 10 00 A4 00 42 C0 04 40 00 84 .P...!....B..@..
40000000000CC0E0 00 00 00 00 01 00 A0 02 A8 2C 00 C0 04 30 59 00 .........,...0Y.
40000000000CC0F0 19 00 00 00 01 00 00 00 00 02 00 00 D8 CB 01 50 ...............P
40000000000CC100 08 00 00 00 01 00 10 00 A4 00 42 A0 04 40 00 84 ..........B..@..
40000000000CC110 09 00 20 46 98 11 A0 02 20 00 42 60 05 10 01 84 .. F.... .B`....
40000000000CC120 11 00 00 00 01 00 00 00 00 02 00 00 68 F0 F4 58 ............h..X
40000000000CC130 09 28 95 4C 00 20 E0 50 01 00 48 20 00 48 01 84 .(.L. .P..H .H..
40000000000CC140 09 00 00 00 01 00 10 70 94 00 2B 00 00 00 04 00 .......p..+.....
40000000000CC150 08 00 00 4A 80 11 00 00 00 02 00 00 00 00 04 00 ...J............
40000000000CC160 11 30 80 44 07 38 A0 02 88 00 42 03 30 00 00 43 .0.D.8....B.0..C
40000000000CC170 11 00 00 00 01 00 00 00 00 02 00 00 78 E6 F4 58 ............x..X
40000000000CC180 08 08 00 52 00 21 00 00 00 02 00 00 00 00 04 00 ...R.!..........
40000000000CC190 11 50 01 46 18 10 00 00 00 02 00 00 78 74 FE 58 .P.F........xt.X
40000000000CC1A0 18 08 00 52 00 21 00 40 90 30 23 00 00 00 00 20 ...R.!.@.0#.... 
40000000000CC1B0 09 78 00 00 00 21 00 09 00 00 48 00 80 02 AA 00 .x...!....H.....
40000000000CC1C0 09 70 10 03 48 24 00 00 00 02 00 00 70 0A 00 07 .p..H$......p...
40000000000CC1D0 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000CC1E0 0B 38 38 10 06 F8 81 00 00 00 C2 C3 C1 0F F0 90 .88.............
40000000000CC1F0 E9 00 00 1C 98 11 60 00 20 0E 72 C0 41 09 F4 90 ......`. .r.A...
40000000000CC200 00 00 00 00 01 C0 F1 00 3C 2C 00 03 01 00 00 84 ........<,......
40000000000CC210 0B 00 40 1C 90 D1 81 78 20 24 40 00 00 00 04 00 ..@....x $@.....
40000000000CC220 F1 40 00 10 18 10 00 00 00 02 00 80 08 00 84 00 .@..............
40000000000CC230 11 00 00 00 01 00 00 00 00 02 00 00 98 F4 F4 58 ...............X
40000000000CC240 11 08 00 52 00 21 A0 0A 20 00 42 00 88 CA 01 50 ...R.!.. .B....P
40000000000CC250 08 08 00 52 00 21 00 00 00 02 00 40 05 40 00 84 ...R.!.....@.@..
40000000000CC260 19 58 01 44 00 21 00 00 00 02 00 00 28 EF F4 58 .X.D.!......(..X
40000000000CC270 08 00 00 00 01 00 10 00 A4 00 42 00 00 00 04 00 ..........B.....
40000000000CC280 19 00 20 4A 98 11 00 40 8C 30 23 00 E0 FE FF 48 .. J...@.0#....H
40000000000CC290 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000CC2A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000CC2B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; command_word_completion_function: 40000000000CC2C0
command_word_completion_function proc
	{ alloc	r53,ar.pfs,0x1C,0x0,0x19; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r55,pr }
	{ cmp4.eq	p07,p06,0x0,r33; nop.m	0x0; adds	r54,0x0,r1; }
	{ nop.m	0x0; mov	r56,LC; (p06) addl	r39,8064,r1; }

l40000000000CC2F0:
	{ nop.m	0x0; mov	r52,b4; (p06) br.cond.dptk.few	40000000000CCAE0 }

l40000000000CC300:
	{ addl	r36,8044,r1; nop.m	0x0; addl	r38,8052,r1; }
	{ ld8	r57,[r36]; ld8	r34,[r38]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r57; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000CC360; }

l40000000000CC330:
	{ cmp.eq	p06,p07,r34,r57; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000CC370; }

l40000000000CC340:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r54; nop.m	0x0; nop.i	0x0 }

l40000000000CC360:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r34; (p06) br.cond.dpnt.few	40000000000CC390 }

l40000000000CC370:
	{ nop.m	0x0; adds	r57,0x0,r34; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r54; nop.m	0x0; nop.i	0x0; }

l40000000000CC390:
	{ addl	r39,8064,r1; addl	r14,8060,r1; adds	r57,0x0,r32; }
	{ nop.m	0x0; st4	[r0],r14; nop.i	0x0 }
	{ st4	[r0],r39; nop.m	0x0; br.call.sptk.many	b0,absolute_pathname; }
	{ adds	r1,0x0,r54; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	40000000000CD740; }

l40000000000CC3D0:
	{ addl	r34,8076,r1; addl	r14,8068,r1; addl	r57,-7580,r1 }
	{ adds	r8,0x0,r0; st4	[r8],r14; nop.i	0x0 }
	{ st8	[r0],r34; ld8	r57,[r57]; br.call.sptk.many	b0,fn400000000001BCA0; }
	{ ld1	r14,[r8]; adds	r1,0x0,r54; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x6F,r14; (p07) br.cond.dpnt.few	40000000000CD800 }

l40000000000CC420:
	{ adds	r14,0x0,r0; nop.m	0x0; nop.i	0x0 }

l40000000000CC430:
	{ addl	r37,8092,r1; nop.m	0x0; addl	r42,8084,r1; }
	{ ld8	r57,[r37]; st4	[r14],r42; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r57; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000CC480; }

l40000000000CC460:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r54; st8	[r0],r37; nop.i	0x0; }
