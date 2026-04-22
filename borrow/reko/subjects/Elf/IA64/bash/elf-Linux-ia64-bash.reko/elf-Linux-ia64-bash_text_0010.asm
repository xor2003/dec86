;;; Segment .text (400000000001C480)

l400000000011C4A0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011C410; }

l400000000011C4B0:
	{ addl	r39,-3764,r1; addl	r40,-3740,r1; addl	r38,1,r0; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; tbit.z	p06,p07,r34,0x5; (p06) br.cond.dptk.few	400000000011B880 }

l400000000011C4F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011C460; }

l400000000011C500:
	{ addl	r39,-3764,r1; addl	r40,-3748,r1; addl	r38,1,r0; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; tbit.z	p06,p07,r34,0x4; (p06) br.cond.dptk.few	400000000011B870 }

l400000000011C540:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011C4B0; }

l400000000011C550:
	{ addl	r39,-3764,r1; addl	r40,-3756,r1; addl	r38,1,r0; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; tbit.z	p06,p07,r34,0x3; (p06) br.cond.dptk.few	400000000011B860 }

l400000000011C590:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011C500; }

l400000000011C5A0:
	{ addl	r39,-3812,r1; addl	r40,-3772,r1; addl	r38,1,r0; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r14,0x8,r33; nop.m	0x0; adds	r1,0x0,r37; }
	{ nop.m	0x0; ld8	r34,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x0; (p06) br.cond.dptk.few	400000000011B850 }

l400000000011C600:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011C550 }

l400000000011C610:
	{ addl	r39,-3812,r1; addl	r40,-3780,r1; addl	r38,1,r0; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; tbit.z	p06,p07,r34,0x6; (p06) br.cond.dptk.few	400000000011B830 }

l400000000011C650:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011C5A0; }

l400000000011C660:
	{ addl	r39,-3812,r1; addl	r40,-3788,r1; addl	r38,1,r0; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; tbit.z	p06,p07,r34,0x4; (p06) br.cond.dptk.few	400000000011B820 }

l400000000011C6A0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011C610; }

l400000000011C6B0:
	{ addl	r39,-3812,r1; addl	r40,-3796,r1; addl	r38,1,r0; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; tbit.z	p06,p07,r34,0x2; (p06) br.cond.dptk.few	400000000011B810 }

l400000000011C6F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011C660; }

l400000000011C700:
	{ addl	r39,-3812,r1; addl	r40,-3804,r1; addl	r38,1,r0; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; tbit.z	p06,p07,r34,0x3; (p06) br.cond.dptk.few	400000000011B800 }

l400000000011C740:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011C6B0; }

l400000000011C750:
	{ addl	r39,-3812,r1; addl	r40,-3884,r1; addl	r38,1,r0; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; tbit.z	p06,p07,r34,0x1; (p06) br.cond.dptk.few	400000000011B7F0 }

l400000000011C790:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011C700; }

l400000000011C7A0:
	{ addl	r39,-3492,r1; nop.m	0x0; adds	r38,0x0,r32; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r37; nop.m	0x0; cmp4.eq	p07,p06,0x0,r8 }
	{ adds	r38,0x0,r32; nop.m	0x0; (p07) br.cond.dpnt.few	400000000011C850; }

l400000000011C7E0:
	{ nop.m	0x0; addl	r39,-3484,r1; nop.i	0x0; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r37; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	400000000011BE00; }

l400000000011C810:
	{ nop.m	0x0; addl	r38,-3852,r1; nop.i	0x0; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B380; }
	{ adds	r8,0x0,r0; adds	r1,0x0,r37; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,400000000011C840; br.ret	b0 }

l400000000011C850:
	{ nop.m	0x0; addl	r38,-3844,r1; nop.i	0x0; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B380; }
	{ adds	r8,0x0,r0; adds	r1,0x0,r37; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,400000000011C880; br.ret	b0; }
400000000011C890 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000011C8A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000011C8B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000011C8C0 09 80 08 04 80 05 E0 80 80 00 42 E0 81 00 01 84 ..........B.....
400000000011C8D0 09 00 01 1E 18 10 10 02 38 30 20 00 00 00 04 00 ........80 .....
400000000011C8E0 11 10 08 00 80 05 00 00 00 02 00 00 A8 EE FF 48 ...............H
400000000011C8F0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; fn400000000011C900: 400000000011C900
;;   Called from:
;;     400000000011D0CC (in complete_builtin)
;;     400000000011D1FC (in complete_builtin)
fn400000000011C900 proc
	{ alloc	r37,ar.pfs,0xA,0x0,0x7; cmp.eq	p06,p07,0x0,r32; nop.b	0x0 }
	{ adds	r33,0x0,r32; mov	r36,b4; adds	r38,0x0,r1; }
	{ nop.m	0x0; adds	r35,0x0,r0; nop.i	0x0; }
	{ nop.m	0x0; (p06) adds	r35,0x0,r0; (p06) br.cond.dpnt.few	400000000011C9C0; }

l400000000011C93C:
	{ (p04) cmpxchg2.acq.nt1	r0,[r33],r64; (p04) cmp.lt	p34,p16,r8,r64; (p01) rfi }

l400000000011C940:
	{ adds	r34,0x8,r33; ld8	r14,[r34]; nop.i	0x0; }
	{ ld8	r39,[r14]; nop.i	0x0; br.call.sptk.many	b0,progcomp_search; }
	{ adds	r1,0x0,r38; nop.m	0x0; cmp.eq	p06,p07,0x0,r8 }
	{ adds	r40,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	400000000011C9F0; }

l400000000011C980:
	{ nop.m	0x0; ld8	r14,[r34]; nop.i	0x0; }
	{ ld8	r39,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000011B780; }
	{ ld8	r33,[r33]; nop.m	0x0; adds	r1,0x0,r38; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	400000000011C940 }

l400000000011C9C0:
	{ adds	r39,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,sh_chkwrite; }
	{ adds	r1,0x0,r38; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,400000000011C9E0; br.ret	b0 }

l400000000011C9F0:
	{ addl	r40,-3476,r1; nop.m	0x0; adds	r39,0x0,r0 }
	{ addl	r41,5,r0; nop.m	0x0; addl	r35,1,r0; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ ld8	r14,[r34]; adds	r1,0x0,r38; adds	r39,0x0,r8; }
	{ ld8	r40,[r14]; nop.i	0x0; br.call.sptk.many	b0,builtin_error; }
	{ ld8	r33,[r33]; nop.m	0x0; adds	r1,0x0,r38; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	400000000011C940 }

l400000000011CA60:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011C9C0; }
400000000011CA70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn400000000011CA80: 400000000011CA80
;;   Called from:
;;     400000000011D1AC (in complete_builtin)
;;     400000000011D89C (in complete_builtin)
fn400000000011CA80 proc
	{ alloc	r37,ar.pfs,0xA,0x0,0x7; cmp.eq	p06,p07,0x0,r32; nop.b	0x0 }
	{ adds	r38,0x0,r1; adds	r33,0x0,r32; mov	r36,b4; }
	{ nop.m	0x0; adds	r35,0x0,r0; nop.i	0x0; }
	{ nop.m	0x0; (p06) adds	r35,0x0,r0; (p06) br.cond.dpnt.few	400000000011CB10; }

l400000000011CABC:
	{ (p03) cmpxchg2.acq.nt1	r0,[r33],r64; (p04) cmp.lt	p34,p16,r8,r64; Invalid }

l400000000011CAC0:
	{ adds	r34,0x8,r33; ld8	r14,[r34]; nop.i	0x0; }
	{ ld8	r39,[r14]; nop.i	0x0; br.call.sptk.many	b0,progcomp_remove; }
	{ adds	r1,0x0,r38; cmp4.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	400000000011CB30; }

l400000000011CAF0:
	{ nop.m	0x0; ld8	r33,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	400000000011CAC0 }

l400000000011CB10:
	{ adds	r8,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,400000000011CB20; br.ret	b0 }

l400000000011CB30:
	{ addl	r40,-3476,r1; nop.m	0x0; adds	r39,0x0,r0 }
	{ addl	r41,5,r0; nop.m	0x0; addl	r35,1,r0; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ ld8	r14,[r34]; adds	r1,0x0,r38; adds	r39,0x0,r8; }
	{ ld8	r40,[r14]; nop.i	0x0; br.call.sptk.many	b0,builtin_error; }
	{ ld8	r33,[r33]; nop.m	0x0; adds	r1,0x0,r38; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	400000000011CAC0 }

l400000000011CBA0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011CB10; }
400000000011CBB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn400000000011CBC0: 400000000011CBC0
;;   Called from:
;;     400000000011E68C (in compopt_builtin)
;;     400000000011E88C (in compopt_builtin)
fn400000000011CBC0 proc
	{ alloc	r36,ar.pfs,0x9,0x0,0x6; addl	r39,-3468,r1; nop.b	0x0 }
	{ adds	r33,0x10,r33; adds	r37,0x0,r1; mov	r35,b3; }
	{ ld8	r39,[r39]; addl	r38,1,r0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ ld8	r34,[r33]; adds	r1,0x0,r37; addl	r38,1,r0; }
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x5; addl	r40,-3884,r1; }
	{ (p07) addl	r39,-3812,r1; ld8	r40,[r40]; nop.i	0x0; }

l400000000011CC16:
	{ (p20) fwb; addl	r0,49152,r1; (p49) cmp4.eq.or.andcm	p09,p57,0x3F,r31 }

l400000000011CC26:
	{ (p19) fwb; nop; (p49) br.call.sptk.few	b1,b0; }

l400000000011CC2C:
	{ cmp4.eq.or.andcm	p00,p17,r1,r0; Invalid; break.i	0x1000 }

l400000000011CC36:
	{ break.m	0x4000; Invalid; break.i	0x80000 }
	{ Invalid; nop; (p32) cmp.eq	p41,p00,0x0,r0 }
	{ Invalid; (p20) addl	r36,1599485,r2; (p49) nop; }

l400000000011CC5C:
	{ (p18) cmp4.ne.or.andcm	p61,p09,r98,r79; (p05) nop; }

l400000000011CC66:
	{ (p20) fwb; nop; cmp.lt	p00,p00,r0,r32 }
	{ (p19) fwb; nop; (p49) br.call.sptk.few	b1,b0; }

l400000000011CC7C:
	{ cmp4.eq.or.andcm	p00,p17,r1,r0; Invalid; break.i	0x1000 }

l400000000011CC86:
	{ break.m	0x4000; Invalid; break.i	0x80000 }
	{ Invalid; nop; (p32) cmp.eq	p41,p00,0x0,r0 }
	{ Invalid; (p20) addl	r44,1599485,r2; (p49) nop; }

l400000000011CCAC:
	{ (p22) cmp4.ne.or.andcm	p61,p09,r98,r79; (p05) nop; }

l400000000011CCB6:
	{ (p20) fwb; nop; cmp.lt	p00,p00,r0,r32 }
	{ (p19) fwb; nop; (p49) br.call.sptk.few	b1,b0; }

l400000000011CCCC:
	{ cmp4.eq.or.andcm	p00,p17,r1,r0; Invalid; break.i	0x1000 }

l400000000011CCD6:
	{ break.m	0x4000; Invalid; break.i	0x80000 }
	{ Invalid; nop; (p32) cmp.eq	p41,p00,0x0,r0 }
	{ Invalid; (p20) addl	r52,1599485,r2; (p49) nop; }

l400000000011CCFC:
	{ (p26) cmp4.ne.or.andcm	p61,p09,r98,r79; (p05) nop; }

l400000000011CD06:
	{ (p20) fwb; nop; cmp.lt	p00,p00,r0,r32 }
	{ (p19) fwb; nop; (p49) br.call.sptk.few	b1,b0; }

l400000000011CD1C:
	{ cmp4.eq.or.andcm	p00,p17,r1,r0; Invalid; break.i	0x1000 }

l400000000011CD26:
	{ break.m	0x4000; Invalid; break.i	0x80000 }
	{ Invalid; nop; (p32) cmp.eq	p41,p00,0x0,r0 }
	{ Invalid; (p20) addl	r60,1599485,r2; (p49) nop; }

l400000000011CD4C:
	{ (p30) cmp4.ne.or.andcm	p61,p09,r98,r79; (p05) nop; }

l400000000011CD56:
	{ (p20) fwb; nop; cmp.lt	p00,p00,r0,r32 }
	{ (p19) fwb; nop; (p49) br.call.sptk.few	b1,b0; }

l400000000011CD6C:
	{ cmp4.eq.or.andcm	p00,p17,r1,r0; Invalid; break.i	0x1000 }

l400000000011CD76:
	{ break.m	0x4000; Invalid; break.i	0x80000 }
	{ Invalid; nop; (p32) cmp.eq	p41,p00,0x0,r0 }
	{ Invalid; (p20) addl	r68,1599485,r2; (p49) nop; }

l400000000011CD9C:
	{ (p34) cmp4.ne.or.andcm	p61,p09,r98,r79; (p05) nop; }

l400000000011CDA6:
	{ (p20) fwb; nop; cmp.lt	p00,p00,r0,r32 }
	{ (p19) fwb; nop; (p49) br.call.sptk.few	b1,b0; }

l400000000011CDBC:
	{ cmp4.eq.or.andcm	p00,p17,r1,r0; Invalid; break.i	0x1000 }

l400000000011CDC6:
	{ break.m	0x4000; Invalid; (p32) nop }
	{ Invalid; (p07) nop; break.b	0x80000 }
	{ (p03) chk.a.clr	f95,3FFFFFFFFFDDFEC6; nop; (p32) nop.b	0x20009 }

l400000000011CDF0:
	{ adds	r38,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B380; }
	{ adds	r1,0x0,r37; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,400000000011CE10; br.ret	b0 }

l400000000011CE20:
	{ addl	r39,-3492,r1; nop.m	0x0; adds	r38,0x0,r32; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r37; nop.m	0x0; cmp4.eq	p07,p06,0x0,r8 }
	{ adds	r38,0x0,r32; nop.m	0x0; (p07) br.cond.dpnt.few	400000000011CED0; }

l400000000011CE60:
	{ nop.m	0x0; addl	r39,-3484,r1; nop.i	0x0; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r37; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	400000000011CDF0; }

l400000000011CE90:
	{ nop.m	0x0; addl	r38,-3852,r1; nop.i	0x0; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B380; }
	{ adds	r1,0x0,r37; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,400000000011CEC0; br.ret	b0 }

l400000000011CED0:
	{ nop.m	0x0; addl	r38,-3844,r1; nop.i	0x0; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B380; }
	{ adds	r1,0x0,r37; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,400000000011CF00; br.ret	b0; }
400000000011CF10 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000011CF20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000011CF30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; complete_builtin: 400000000011CF40
complete_builtin proc
	{ alloc	r48,ar.pfs,0x17,0x0,0x13; adds	r12,0xFFFFFFFFFFFFFFE0,r12; mov	r50,pr }
	{ adds	r49,0x0,r1; cmp.eq	p07,p06,0x0,r32; addl	r40,8716,r1; }
	{ adds	r34,0x10,r12; addl	r41,8724,r1; mov	r47,b7 }
	{ addl	r39,8732,r1; addl	r42,8740,r1; (p07) br.cond.dpnt.few	400000000011D310; }

l400000000011CF80:
	{ addl	r43,8748,r1; st4	[r34],r16,16; addl	r44,8756,r1 }
	{ addl	r45,8764,r1; adds	r35,0x28,r12; adds	r36,0x18,r12; }
	{ adds	r38,0x14,r12; adds	r37,0x1C,r12; adds	r51,0x0,r32 }
	{ st4	[r0],r36; st8	[r0],r34; adds	r52,0x10,r12; }
	{ st4	[r0],r37; st4	[r0],r38; adds	r53,0x0,r35 }
	{ adds	r54,0x0,r34; st8	[r0],r35; nop.i	0x0 }
	{ st8	[r0],r40; st8	[r0],r41; nop.i	0x0 }
	{ st8	[r0],r39; st8	[r0],r42; nop.i	0x0 }
	{ st8	[r0],r43; st8	[r0],r44; nop.i	0x0 }
	{ st8	[r0],r45; nop.m	0x0; br.call.sptk.many	b0,fn400000000011B040; }
	{ adds	r1,0x0,r49; addl	r14,258,r0; adds	r33,0x0,r8; }
	{ addl	r15,9268,r1; cmp4.eq	p06,p07,r14,r8; (p06) br.cond.dpnt.few	400000000011D100; }

l400000000011D040:
	{ nop.m	0x0; ld4	r14,[r36]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; }
	{ ld8	r46,[r15]; adds	r15,0x10,r12; (p07) br.cond.dpnt.few	400000000011D240; }

l400000000011D070:
	{ nop.m	0x0; ld4	r14,[r37]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000011D2C0; }

l400000000011D090:
	{ ld4	r14,[r15]; nop.m	0x0; (p06) adds	r36,0x0,r0; }

l400000000011D0A0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	400000000011D130; }

l400000000011D0B0:
	{ cmp.eq	p06,p07,0x0,r36; adds	r51,0x0,r36; (p06) br.cond.dpnt.few	400000000011D1E0; }

l400000000011D0C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000011C900; }
	{ adds	r1,0x0,r49; nop.m	0x0; adds	r33,0x0,r8 }
	{ adds	r51,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,dispose_words; }
	{ adds	r1,0x0,r49; nop.m	0x0; nop.i	0x0 }

l400000000011D100:
	{ adds	r8,0x0,r33; mov	pr,r50,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r48; }
	{ nop.m	0x0; mov.spnt	b0,r47,400000000011D110; nop.i	0x0 }
	{ adds	r12,0x20,r12; nop.m	0x0; br.ret	b0 }

l400000000011D130:
	{ cmp.eq	p06,p07,0x0,r46; cmp4.eq	p09,p08,0x1,r33; (p06) addl	r15,1,r0 }

l400000000011D140:
	{ (p08) addl	r33,1,r0; (p07) adds	r15,0x0,r0; (p09) adds	r33,0x0,r0; }

l400000000011D146:
	{ (p07) addl	r0,24832,r0; (p16) mov.sptk	b0,r0,400000000011D246; nop; }

l400000000011D14C:
	{ Invalid; break.x	0x1017A1024101E0 }

l400000000011D150:
	{ xor	r16,0x1,r33; zxt1	r14,r15; and	r16,r16,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r16; (p07) br.cond.dptk.few	400000000011D0B0 }

l400000000011D170:
	{ nop.m	0x0; ld4	r16,[r38]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r16; (p06) br.cond.dptk.few	400000000011D360; }

l400000000011D190:
	{ cmp.eq	p06,p07,0x0,r36; adds	r51,0x0,r36; (p06) br.cond.dpnt.few	400000000011D880; }

l400000000011D1A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000011CA80; }
	{ adds	r1,0x0,r49; nop.m	0x0; adds	r33,0x0,r8 }
	{ adds	r51,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,dispose_words; }
	{ nop.m	0x0; adds	r1,0x0,r49; br.cond.sptk.few	400000000011D100 }

l400000000011D1E0:
	{ cmp.eq	p06,p07,0x0,r46; adds	r51,0x0,r46; (p06) br.cond.dpnt.few	400000000011D310; }

l400000000011D1F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000011C900; }
	{ adds	r33,0x0,r8; nop.m	0x0; adds	r1,0x0,r49; }
	{ adds	r8,0x0,r33; mov	pr,r50,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r48; }
	{ nop.m	0x0; mov.spnt	b0,r47,400000000011D220; nop.i	0x0 }
	{ adds	r12,0x20,r12; nop.m	0x0; br.ret	b0 }

l400000000011D240:
	{ nop.m	0x0; addl	r51,-3484,r1; nop.i	0x0; }
	{ ld8	r51,[r51]; nop.i	0x0; br.call.sptk.many	b0,make_bare_word; }
	{ adds	r1,0x0,r49; nop.m	0x0; adds	r51,0x0,r8 }
	{ adds	r52,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,make_word_list; }
	{ nop.m	0x0; adds	r1,0x0,r49; adds	r36,0x0,r8 }

l400000000011D290:
	{ adds	r15,0x10,r12; ld4	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	400000000011D0B0 }

l400000000011D2B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011D130 }

l400000000011D2C0:
	{ nop.m	0x0; addl	r51,-3492,r1; nop.i	0x0; }
	{ ld8	r51,[r51]; nop.i	0x0; br.call.sptk.many	b0,make_bare_word; }
	{ adds	r1,0x0,r49; nop.m	0x0; adds	r51,0x0,r8 }
	{ adds	r52,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,make_word_list; }
	{ adds	r1,0x0,r49; adds	r36,0x0,r8; br.cond.sptk.few	400000000011D290; }

l400000000011D310:
	{ addl	r51,-3364,r1; nop.m	0x0; adds	r33,0x0,r0; }
	{ ld8	r51,[r51]; nop.i	0x0; br.call.sptk.many	b0,progcomp_walk; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r49; mov	pr,r50,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r48; mov.spnt	b0,r47,400000000011D340 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0 }

l400000000011D360:
	{ cmp.eq	p16,p17,0x0,r36; (p16) addl	r15,1,r0; nop.i	0x0; }

l400000000011D36C:
	{ cmp.gt.or.andcm	p00,p43,r0,r0; (p01) cmp.lt	p00,p16,r0,r64; zxt1	r67,r3 }

l400000000011D376:
	{ Invalid; nop; (p32) nop }
	{ chk.a.nc	r0,3FFFFFFFFF11DB86; nop; break.i	0x80000 }

l400000000011D390:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r33; (p07) br.cond.dpnt.few	400000000011D810 }

l400000000011D3A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,compspec_create; }
	{ ld8	r51,[r45]; adds	r17,0x8,r8; adds	r16,0x10,r8 }
	{ adds	r37,0x0,r8; ld8	r15,[r35]; adds	r1,0x0,r49; }
	{ cmp.eq	p06,p07,0x0,r51; ld8	r14,[r34]; nop.i	0x0 }
	{ st8	[r15],r17; nop.m	0x0; (p06) adds	r8,0x0,r0 }

l400000000011D3F0:
	{ nop.m	0x0; st8	[r14],r16; (p06) br.cond.dpnt.few	400000000011D450; }

l400000000011D400:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r49; adds	r51,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r49; adds	r51,0x0,r8; addl	r14,8764,r1; }
	{ ld8	r52,[r14]; br.call.sptk.many	b0,fn400000000001B180; nop.b	0x0; }
	{ adds	r1,0x0,r49; nop.m	0x0; nop.i	0x0 }

l400000000011D450:
	{ ld8	r51,[r44]; nop.m	0x0; adds	r14,0x18,r37; }
	{ cmp.eq	p06,p07,0x0,r51; st8	[r8],r14; nop.i	0x0; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011D4D0; }

l400000000011D476:
	{ chk.a.nc	r0,3FFFFFFFFF11DC76; nop; break.i	0x80000 }

l400000000011D480:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r49; adds	r51,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r49; adds	r51,0x0,r8; addl	r14,8756,r1; }
	{ ld8	r52,[r14]; br.call.sptk.many	b0,fn400000000001B180; nop.b	0x0; }
	{ adds	r1,0x0,r49; nop.m	0x0; nop.i	0x0 }

l400000000011D4D0:
	{ ld8	r51,[r43]; nop.m	0x0; adds	r14,0x20,r37; }
	{ cmp.eq	p06,p07,0x0,r51; st8	[r8],r14; nop.i	0x0; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011D550; }

l400000000011D4F6:
	{ chk.a.nc	r0,3FFFFFFFFF11DCF6; nop; break.i	0x80000 }

l400000000011D500:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r49; adds	r51,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r49; adds	r51,0x0,r8; addl	r14,8748,r1; }
	{ ld8	r52,[r14]; br.call.sptk.many	b0,fn400000000001B180; nop.b	0x0; }
	{ adds	r1,0x0,r49; nop.m	0x0; nop.i	0x0 }

l400000000011D550:
	{ ld8	r51,[r42]; nop.m	0x0; adds	r14,0x28,r37; }
	{ cmp.eq	p06,p07,0x0,r51; st8	[r8],r14; nop.i	0x0; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011D5D0; }

l400000000011D576:
	{ chk.a.nc	r0,3FFFFFFFFF11DD76; nop; break.i	0x80000 }

l400000000011D580:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r49; adds	r51,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r49; adds	r51,0x0,r8; addl	r14,8740,r1; }
	{ ld8	r52,[r14]; br.call.sptk.many	b0,fn400000000001B180; nop.b	0x0; }
	{ adds	r1,0x0,r49; nop.m	0x0; nop.i	0x0 }

l400000000011D5D0:
	{ ld8	r51,[r41]; nop.m	0x0; adds	r14,0x30,r37; }
	{ cmp.eq	p06,p07,0x0,r51; st8	[r8],r14; nop.i	0x0; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011D650; }

l400000000011D5F6:
	{ chk.a.nc	r0,3FFFFFFFFF11DDF6; nop; break.i	0x80000 }

l400000000011D600:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r49; adds	r51,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r49; adds	r51,0x0,r8; addl	r14,8724,r1; }
	{ ld8	r52,[r14]; br.call.sptk.many	b0,fn400000000001B180; nop.b	0x0; }
	{ adds	r1,0x0,r49; nop.m	0x0; nop.i	0x0 }

l400000000011D650:
	{ ld8	r51,[r40]; nop.m	0x0; adds	r14,0x38,r37; }
	{ cmp.eq	p06,p07,0x0,r51; st8	[r8],r14; nop.i	0x0; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011D6D0; }

l400000000011D676:
	{ chk.a.nc	r0,3FFFFFFFFF11DE76; nop; break.i	0x80000 }

l400000000011D680:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r49; adds	r51,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r49; adds	r51,0x0,r8; addl	r14,8716,r1; }
	{ ld8	r52,[r14]; br.call.sptk.many	b0,fn400000000001B180; nop.b	0x0; }
	{ adds	r1,0x0,r49; nop.m	0x0; nop.i	0x0 }

l400000000011D6D0:
	{ ld8	r51,[r39]; nop.m	0x0; adds	r14,0x40,r37; }
	{ cmp.eq	p06,p07,0x0,r51; st8	[r8],r14; nop.i	0x0; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011D750; }

l400000000011D6F6:
	{ chk.a.nc	r0,3FFFFFFFFF11DEF6; nop; break.i	0x80000 }

l400000000011D700:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r49; adds	r51,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r49; adds	r51,0x0,r8; addl	r14,8732,r1; }
	{ ld8	r52,[r14]; br.call.sptk.many	b0,fn400000000001B180; nop.b	0x0; }
	{ adds	r1,0x0,r49; nop.m	0x0; nop.i	0x0 }

l400000000011D750:
	{ adds	r14,0x50,r37; (p17) adds	r34,0x0,r36; nop.i	0x0 }

l400000000011D75C:
	{ nop; Invalid; break.i	0x101000 }
	{ (p07) nop; zxt1	r0,r64; break.b	0x1000 }

l400000000011D770:
	{ adds	r33,0x0,r0; nop.m	0x0; nop.i	0x0; }

l400000000011D780:
	{ adds	r14,0x8,r34; nop.m	0x0; adds	r52,0x0,r37; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r51,[r14]; nop.i	0x0; br.call.sptk.many	b0,progcomp_insert; }
	{ ld8	r34,[r34]; cmp4.eq	p06,p07,0x0,r8; adds	r1,0x0,r49; }
	{ (p06) addl	r33,1,r0; cmp.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	400000000011D780 }

l400000000011D7C6:
	{ (p03) chk.a.clr	r0,3FFFFFFFFFDA09E6; nop; (p48) nop.b	0x2400C }

l400000000011D7D0:
	{ adds	r51,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,dispose_words; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r49; mov	pr,r50,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r48; mov.spnt	b0,r47,400000000011D7F0 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0; }

l400000000011D810:
	{ addl	r33,258,r0; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r49; mov	pr,r50,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r48; mov.spnt	b0,r47,400000000011D830 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0 }

l400000000011D850:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r46; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r33,0x0,r0; (p07) br.cond.dptk.few	400000000011D7D0; }

l400000000011D86C:
	{ (p59) ld4	r127,[r37]; (p04) nop; (p04) epc }

l400000000011D870:
	{ adds	r34,0x0,r46; adds	r33,0x0,r0; br.cond.sptk.few	400000000011D780 }

l400000000011D880:
	{ cmp4.eq	p06,p07,0x0,r15; adds	r51,0x0,r46; (p07) br.cond.dpnt.few	400000000011D8E0; }

l400000000011D890:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000011CA80; }
	{ adds	r33,0x0,r8; nop.m	0x0; adds	r1,0x0,r49; }
	{ adds	r8,0x0,r33; mov	pr,r50,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r48; }
	{ nop.m	0x0; mov.spnt	b0,r47,400000000011D8C0; nop.i	0x0 }
	{ adds	r12,0x20,r12; nop.m	0x0; br.ret	b0; }

l400000000011D8E0:
	{ adds	r33,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,progcomp_flush; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r49; mov	pr,r50,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r48; mov.spnt	b0,r47,400000000011D900 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0; }
400000000011D920 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000011D930 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; compgen_builtin: 400000000011D940
compgen_builtin proc
	{ alloc	r44,ar.pfs,0x14,0x0,0xE; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r43,b3 }
	{ cmp.eq	p07,p06,0x0,r32; addl	r36,8716,r1; (p07) br.cond.dpnt.few	400000000011E0E0; }

l400000000011D960:
	{ adds	r34,0x10,r12; addl	r37,8724,r1; addl	r38,8732,r1 }
	{ addl	r39,8740,r1; addl	r40,8748,r1; addl	r41,8756,r1; }
	{ st8	[r34],r8,8; addl	r42,8764,r1; adds	r45,0x0,r1 }
	{ st8	[r0],r36; adds	r46,0x0,r32; adds	r47,0x0,r0; }
	{ st8	[r0],r34; st8	[r0],r37; adds	r48,0x0,r34 }
	{ nop.m	0x0; adds	r49,0x10,r12; nop.i	0x0; }
	{ st8	[r0],r38; st8	[r0],r39; nop.i	0x0; }
	{ st8	[r0],r40; st8	[r0],r41; nop.i	0x0; }
	{ st8	[r0],r42; nop.i	0x0; br.call.sptk.many	b0,fn400000000011B040; }
	{ adds	r1,0x0,r45; addl	r14,258,r0; adds	r35,0x0,r8; }
	{ cmp4.eq	p06,p07,r14,r8; addl	r14,9268,r1; (p06) br.cond.dpnt.few	400000000011E010; }

l400000000011DA10:
	{ cmp4.eq	p06,p07,0x1,r8; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011E0E0; }

l400000000011DA20:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; adds	r14,0x8,r14; (p06) br.cond.dpnt.few	400000000011E260; }

l400000000011DA40:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	400000000011E260; }

l400000000011DA60:
	{ (p07) ld8	r35,[r14]; nop.m	0x0; nop.i	0x0 }

l400000000011DA66:
	{ break.m	0x4000; nop; (p32) nop }

l400000000011DA70:
	{ ld8	r14,[r37]; nop.m	0x0; addl	r47,-3444,r1 }
	{ addl	r48,5,r0; nop.m	0x0; adds	r46,0x0,r0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011DAE0; }

l400000000011DAA0:
	{ ld8	r47,[r47]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ nop.m	0x0; adds	r1,0x0,r45; adds	r46,0x0,r8 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,builtin_error; }
	{ adds	r1,0x0,r45; nop.m	0x0; nop.i	0x0; }

l400000000011DAE0:
	{ ld8	r14,[r36]; nop.m	0x0; addl	r47,-3436,r1 }
	{ addl	r48,5,r0; nop.m	0x0; adds	r46,0x0,r0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011DB50; }

l400000000011DB10:
	{ ld8	r47,[r47]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ nop.m	0x0; adds	r1,0x0,r45; adds	r46,0x0,r8 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,builtin_error; }
	{ adds	r1,0x0,r45; nop.m	0x0; nop.i	0x0 }

l400000000011DB50:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,compspec_create; }
	{ ld8	r16,[r34]; adds	r14,0x8,r8; adds	r15,0x10,r8 }
	{ adds	r33,0x0,r8; ld8	r46,[r42]; adds	r1,0x0,r45; }
	{ st8	[r16],r14; adds	r16,0x10,r12; cmp.eq	p06,p07,0x0,r46; }
	{ ld8	r14,[r16]; st8	[r14],r15; addl	r14,1,r0; }
	{ st4	[r14],r8; (p06) adds	r8,0x0,r0; (p06) br.cond.dpnt.few	400000000011DC00; }

l400000000011DBAC:
	{ Invalid; break.i	0x1000; break.i	0x1000 }

l400000000011DBB0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r45; adds	r46,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r45; adds	r46,0x0,r8; addl	r14,8764,r1; }
	{ ld8	r47,[r14]; br.call.sptk.many	b0,fn400000000001B180; nop.b	0x0; }
	{ adds	r1,0x0,r45; nop.m	0x0; nop.i	0x0 }

l400000000011DC00:
	{ ld8	r46,[r41]; nop.m	0x0; adds	r14,0x18,r33; }
	{ cmp.eq	p06,p07,0x0,r46; st8	[r8],r14; nop.i	0x0; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011DC80; }

l400000000011DC26:
	{ chk.a.nc	r0,3FFFFFFFFF11E426; nop; break.i	0x80000 }

l400000000011DC30:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r45; adds	r46,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r45; adds	r46,0x0,r8; addl	r14,8756,r1; }
	{ ld8	r47,[r14]; br.call.sptk.many	b0,fn400000000001B180; nop.b	0x0; }
	{ adds	r1,0x0,r45; nop.m	0x0; nop.i	0x0 }

l400000000011DC80:
	{ ld8	r46,[r40]; nop.m	0x0; adds	r14,0x20,r33; }
	{ cmp.eq	p06,p07,0x0,r46; st8	[r8],r14; nop.i	0x0; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011DD00; }

l400000000011DCA6:
	{ chk.a.nc	r0,3FFFFFFFFF11E4A6; nop; break.i	0x80000 }

l400000000011DCB0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r45; adds	r46,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r45; adds	r46,0x0,r8; addl	r14,8748,r1; }
	{ ld8	r47,[r14]; br.call.sptk.many	b0,fn400000000001B180; nop.b	0x0; }
	{ adds	r1,0x0,r45; nop.m	0x0; nop.i	0x0 }

l400000000011DD00:
	{ ld8	r46,[r39]; nop.m	0x0; adds	r14,0x28,r33; }
	{ cmp.eq	p06,p07,0x0,r46; st8	[r8],r14; nop.i	0x0; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011DD80; }

l400000000011DD26:
	{ chk.a.nc	r0,3FFFFFFFFF11E526; nop; break.i	0x80000 }

l400000000011DD30:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r45; adds	r46,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r45; adds	r46,0x0,r8; addl	r14,8740,r1; }
	{ ld8	r47,[r14]; br.call.sptk.many	b0,fn400000000001B180; nop.b	0x0; }
	{ adds	r1,0x0,r45; nop.m	0x0; nop.i	0x0 }

l400000000011DD80:
	{ ld8	r46,[r37]; nop.m	0x0; adds	r14,0x30,r33; }
	{ cmp.eq	p06,p07,0x0,r46; st8	[r8],r14; nop.i	0x0; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011DE00; }

l400000000011DDA6:
	{ chk.a.nc	r0,3FFFFFFFFF11E5A6; nop; break.i	0x80000 }

l400000000011DDB0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r45; adds	r46,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r45; adds	r46,0x0,r8; addl	r14,8724,r1; }
	{ ld8	r47,[r14]; br.call.sptk.many	b0,fn400000000001B180; nop.b	0x0; }
	{ adds	r1,0x0,r45; nop.m	0x0; nop.i	0x0 }

l400000000011DE00:
	{ ld8	r46,[r36]; nop.m	0x0; adds	r14,0x38,r33; }
	{ cmp.eq	p06,p07,0x0,r46; st8	[r8],r14; nop.i	0x0; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011DE80; }

l400000000011DE26:
	{ chk.a.nc	r0,3FFFFFFFFF11E626; nop; break.i	0x80000 }

l400000000011DE30:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r45; adds	r46,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r45; adds	r46,0x0,r8; addl	r14,8716,r1; }
	{ ld8	r47,[r14]; br.call.sptk.many	b0,fn400000000001B180; nop.b	0x0; }
	{ adds	r1,0x0,r45; nop.m	0x0; nop.i	0x0 }

l400000000011DE80:
	{ ld8	r46,[r38]; nop.m	0x0; adds	r14,0x40,r33; }
	{ cmp.eq	p06,p07,0x0,r46; st8	[r8],r14; nop.i	0x0; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011DF00; }

l400000000011DEA6:
	{ chk.a.nc	r0,3FFFFFFFFF11E6A6; nop; break.i	0x80000 }

l400000000011DEB0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r45; adds	r46,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r45; adds	r46,0x0,r8; addl	r14,8732,r1; }
	{ ld8	r47,[r14]; br.call.sptk.many	b0,fn400000000001B180; nop.b	0x0; }
	{ adds	r1,0x0,r45; nop.m	0x0; nop.i	0x0; }

l400000000011DF00:
	{ adds	r14,0x50,r33; addl	r47,-3428,r1; adds	r46,0x0,r33 }
	{ adds	r48,0x0,r35; adds	r49,0x0,r0; adds	r50,0x0,r0; }
	{ st8	[r8],r14; ld8	r47,[r47]; adds	r51,0x0,r0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,gen_compspec_completions; }
	{ adds	r14,0xC,r8; adds	r1,0x0,r45; nop.i	0x0 }
	{ adds	r34,0x0,r8; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	400000000011E030; }

l400000000011DF60:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p09,p08,0x0,r14; (p09) br.cond.dptk.few	400000000011E030 }

l400000000011DF80:
	{ nop.m	0x0; ld8	r14,[r34]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; adds	r14,0xC,r34; (p06) br.cond.dpnt.few	400000000011DFC0; }

l400000000011DFA0:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	400000000011E110 }

l400000000011DFC0:
	{ nop.m	0x0; adds	r46,0x0,r34; addl	r35,1,r0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,strlist_dispose; }
	{ adds	r1,0x0,r45; nop.m	0x0; nop.i	0x0 }

l400000000011DFF0:
	{ nop.m	0x0; adds	r46,0x0,r33; br.call.sptk.many	b0,compspec_dispose; }
	{ adds	r1,0x0,r45; nop.m	0x0; nop.i	0x0 }

l400000000011E010:
	{ adds	r8,0x0,r35; mov.i	ar.pfs,r44; mov.spnt	b0,r43,400000000011E010 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l400000000011E030:
	{ adds	r15,0x10,r12; ld8	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p08,p09,r14,0x5; (p09) br.cond.dpnt.few	400000000011E1F0 }

l400000000011E050:
	{ adds	r14,0xC,r34; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011E080; }

l400000000011E060:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p09,p08,0x0,r14; (p08) br.cond.spnt.few	400000000011DF80 }

l400000000011E080:
	{ adds	r16,0x10,r12; ld8	r14,[r16]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p08,p09,r14,0x1; nop.i	0x0 }
	{ nop.b	0x0; (p09) br.cond.dpnt.few	400000000011E150; (p07) br.cond.dptk.few	400000000011DF80; }

l400000000011E0AC:
	{ (p55) nop; zxt4	r0,r0; break.i	0x1000 }

l400000000011E0B0:
	{ (p06) addl	r35,1,r0; nop.m	0x0; nop.i	0x0 }

l400000000011E0B6:
	{ break.m	0x4000; nop; (p32) nop }

l400000000011E0C0:
	{ adds	r46,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,compspec_dispose; }
	{ nop.m	0x0; adds	r1,0x0,r45; br.cond.sptk.few	400000000011E010 }

l400000000011E0E0:
	{ nop.m	0x0; adds	r35,0x0,r0; nop.i	0x0; }
	{ adds	r8,0x0,r35; mov.i	ar.pfs,r44; mov.spnt	b0,r43,400000000011E0F0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l400000000011E110:
	{ adds	r46,0x0,r34; nop.m	0x0; adds	r47,0x0,r0 }
	{ adds	r35,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,strlist_print; }
	{ adds	r1,0x0,r45; adds	r46,0x0,r34; br.call.sptk.many	b0,strlist_dispose; }
	{ nop.m	0x0; adds	r1,0x0,r45; br.cond.sptk.few	400000000011DFF0; }

l400000000011E150:
	{ addl	r47,-10564,r1; nop.m	0x0; adds	r46,0x0,r35; }
	{ ld8	r47,[r47]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A860; }
	{ adds	r1,0x0,r45; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r46,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,completions_to_stringlist; }
	{ adds	r1,0x0,r45; nop.m	0x0; adds	r34,0x0,r8 }
	{ adds	r46,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,strvec_dispose; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r34; adds	r1,0x0,r45 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dptk.few	400000000011DF80; }

l400000000011E1D0:
	{ (p06) addl	r35,1,r0; nop.m	0x0; nop.i	0x0 }

l400000000011E1D6:
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ break.m	0x4000; nop; (p48) nop }

l400000000011E1F0:
	{ adds	r47,0x0,r0; adds	r48,0x0,r0; adds	r49,0x0,r0 }
	{ adds	r50,0x0,r0; adds	r46,0x0,r35; br.call.sptk.many	b0,bash_default_completion; }
	{ adds	r1,0x0,r45; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r46,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,completions_to_stringlist; }
	{ adds	r1,0x0,r45; nop.m	0x0; adds	r34,0x0,r8 }
	{ adds	r46,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,strvec_dispose; }
	{ adds	r1,0x0,r45; cmp.eq	p06,p07,0x0,r34; br.cond.sptk.few	400000000011E050; }

l400000000011E260:
	{ nop.m	0x0; addl	r35,-3452,r1; nop.i	0x0; }
	{ ld8	r35,[r35]; nop.i	0x0; br.cond.sptk.few	400000000011DA70; }

;; compopt_builtin: 400000000011E280
compopt_builtin proc
	{ alloc	r43,ar.pfs,0x10,0x0,0xD; adds	r12,0xFFFFFFFFFFFFFFF0,r12; addl	r34,9276,r1 }
	{ addl	r39,9252,r1; addl	r40,-3380,r1; adds	r44,0x0,r1; }
	{ adds	r33,0x10,r12; nop.m	0x0; mov	r42,b2 }
	{ adds	r38,0x0,r0; nop.m	0x0; adds	r37,0x0,r0; }
	{ st4	[r33],r4,4; ld8	r40,[r40]; nop.i	0x0; }
	{ st4	[r0],r33; br.call.sptk.many	b0,reset_internal_getopt; nop.b	0x0; }
	{ adds	r1,0x0,r44; nop.m	0x0; nop.i	0x0; }

l400000000011E2F0:
	{ addl	r46,-3420,r1; nop.m	0x0; adds	r45,0x0,r32; }
	{ ld8	r46,[r46]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r44; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dpnt.few	400000000011E3F0 }

l400000000011E320:
	{ ld4	r14,[r34]; cmp4.eq	p07,p06,0x2D,r14; nop.i	0x0; }
	{ (p06) adds	r14,0x10,r12; (p07) ld4	r36,[r33]; (p07) adds	r35,0x0,r33; }

l400000000011E336:
	{ (p18) addp4	r0,0xFFFFFFFFFFFFF021,r16; (p17) addl	r0,8481,r0; (p01) nop; }

l400000000011E33C:
	{ nop; movl	r0,0x10101C01006020 }

l400000000011E340:
	{ (p06) ld4	r36,[r14]; nop.m	0x0; (p06) adds	r35,0x0,r14 }

l400000000011E346:
	{ adds	r0,0xFFFFFFFFFFFFE000,r1; (p17) nop; (p32) nop }

l400000000011E350:
	{ cmp4.eq	p06,p07,0x45,r8; nop.m	0x0; (p06) br.cond.dpnt.few	400000000011E5E0; }

l400000000011E360:
	{ cmp4.eq	p06,p07,0x6F,r8; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011E570; }

l400000000011E370:
	{ cmp4.eq	p06,p07,0x44,r8; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011E3C0; }

l400000000011E380:
	{ nop.m	0x0; addl	r34,258,r0; br.call.sptk.many	b0,builtin_usage; }
	{ adds	r1,0x0,r44; nop.m	0x0; nop.i	0x0 }

l400000000011E3A0:
	{ adds	r8,0x0,r34; mov.i	ar.pfs,r43; mov.spnt	b0,r42,400000000011E3A0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l400000000011E3C0:
	{ addl	r46,-3420,r1; adds	r45,0x0,r32; addl	r37,1,r0; }
	{ ld8	r46,[r46]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r44; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p06) br.cond.dptk.few	400000000011E320; }

l400000000011E3F0:
	{ addl	r14,9268,r1; nop.m	0x0; cmp4.eq	p06,p07,0x0,r37; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld8	r34,[r14]; nop.i	0x0; (p07) br.cond.dpnt.few	400000000011E6D0; }

l400000000011E420:
	{ cmp4.eq	p06,p07,0x0,r38; nop.i	0x0; (p07) br.cond.dpnt.few	400000000011E9A0; }

l400000000011E430:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r34; (p07) br.cond.dptk.few	400000000011E8D0 }

l400000000011E440:
	{ addl	r14,-10404,r1; ld8	r14,[r14]; nop.i	0x0; }
	{ ld4	r14,[r14]; nop.m	0x0; tbit.z	p06,p07,r14,0xE }
	{ addl	r14,9220,r1; nop.m	0x0; (p06) br.cond.dpnt.few	400000000011E5F0; }

l400000000011E470:
	{ nop.m	0x0; ld8	r35,[r14]; adds	r14,0x10,r12; }
	{ cmp.eq	p07,p06,0x0,r35; nop.i	0x0; (p07) br.cond.dpnt.few	400000000011E5F0; }

l400000000011E490:
	{ ld4	r33,[r33]; ld4	r36,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r33; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011E4C0; }

l400000000011E4B0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r36; (p07) br.cond.dpnt.few	400000000011E660 }

l400000000011E4C0:
	{ adds	r45,0x0,r35; adds	r46,0x0,r33; nop.i	0x0 }
	{ addl	r47,1,r0; adds	r34,0x0,r0; br.call.sptk.many	b0,pcomp_set_compspec_options; }
	{ adds	r47,0x0,r0; adds	r1,0x0,r44; nop.i	0x0 }
	{ adds	r45,0x0,r35; adds	r46,0x0,r36; br.call.sptk.many	b0,pcomp_set_compspec_options; }
	{ adds	r1,0x0,r44; nop.m	0x0; adds	r45,0x0,r33 }
	{ addl	r46,1,r0; nop.m	0x0; br.call.sptk.many	b0,pcomp_set_readline_variables; }
	{ adds	r1,0x0,r44; nop.m	0x0; adds	r45,0x0,r36 }
	{ adds	r46,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,pcomp_set_readline_variables; }
	{ adds	r8,0x0,r34; adds	r1,0x0,r44; mov.i	ar.pfs,r43; }
	{ nop.m	0x0; mov.spnt	b0,r42,400000000011E550; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l400000000011E570:
	{ nop.m	0x0; ld8	r41,[r39]; nop.i	0x0; }
	{ adds	r45,0x0,r41; nop.i	0x0; br.call.sptk.many	b0,fn400000000011AF00; }
	{ cmp4.lt	p07,p06,r8,r0; nop.m	0x0; sxt4	r8,r8 }
	{ adds	r1,0x0,r44; nop.m	0x0; (p07) br.cond.dpnt.few	400000000011E960; }

l400000000011E5B0:
	{ shladd	r8,r8,0x4,r40; adds	r8,0x8,r8; nop.i	0x0; }
	{ ld4	r14,[r8]; or	r36,r14,r36; nop.i	0x0; }
	{ st4	[r36],r35; nop.i	0x0; br.cond.sptk.few	400000000011E2F0 }

l400000000011E5E0:
	{ nop.m	0x0; addl	r38,1,r0; br.cond.sptk.few	400000000011E2F0 }

l400000000011E5F0:
	{ addl	r46,-3412,r1; nop.m	0x0; addl	r47,5,r0 }
	{ adds	r45,0x0,r0; nop.m	0x0; addl	r34,1,r0; }
	{ ld8	r46,[r46]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r44; adds	r45,0x0,r8; br.call.sptk.many	b0,builtin_error; }
	{ adds	r8,0x0,r34; adds	r1,0x0,r44; mov.i	ar.pfs,r43; }
	{ nop.m	0x0; mov.spnt	b0,r42,400000000011E640; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l400000000011E660:
	{ addl	r14,9212,r1; nop.m	0x0; adds	r46,0x0,r35; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld8	r45,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000011CBC0; }
	{ adds	r1,0x0,r44; adds	r45,0x0,r0; br.call.sptk.many	b0,sh_chkwrite; }
	{ adds	r34,0x0,r8; nop.m	0x0; adds	r1,0x0,r44; }
	{ adds	r8,0x0,r34; mov.i	ar.pfs,r43; mov.spnt	b0,r42,400000000011E6B0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l400000000011E6D0:
	{ nop.m	0x0; addl	r45,-3484,r1; nop.i	0x0; }
	{ ld8	r45,[r45]; nop.m	0x0; nop.i	0x0 }

l400000000011E6F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,make_bare_word; }
	{ adds	r1,0x0,r44; nop.m	0x0; adds	r45,0x0,r8 }
	{ adds	r46,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,make_word_list; }
	{ cmp.eq	p08,p09,0x0,r34; cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r44; }
	{ (p08) addl	r14,1,r0; nop.m	0x0; (p06) addl	r15,1,r0; }

l400000000011E736:
	{ adds	r0,0xFFFFFFFFFFFFE000,r1; (p07) dep	r1,r0,r0,35,9; (p34) cmp.eq.or.andcm	p03,p00,r0,r0 }

l400000000011E740:
	{ (p09) adds	r14,0x0,r0; (p07) adds	r15,0x0,r0; and	r14,r14,r15; }

l400000000011E746:
	{ Invalid; (p07) nop; break.b	0x80000; }

l400000000011E74C:
	{ (p07) invala; break.i	0x1000; Invalid; }
	{ Invalid; nop; (p04) epc }

l400000000011E760:
	{ nop.m	0x0; (p07) adds	r35,0x0,r8; (p06) br.cond.dpnt.few	400000000011E8C0; }

l400000000011E76C:
	{ (p11) cmpxchg2.acq	r0,[r33],r64; zxt1	r0,r64; break.i	0x1000 }

l400000000011E770:
	{ adds	r34,0x0,r0; nop.m	0x0; nop.i	0x0; }

l400000000011E780:
	{ adds	r38,0x8,r35; ld8	r14,[r38]; nop.i	0x0; }
	{ ld8	r45,[r14]; nop.i	0x0; br.call.sptk.many	b0,progcomp_search; }
	{ adds	r1,0x0,r44; cmp.eq	p07,p06,0x0,r8; adds	r36,0x0,r8 }
	{ addl	r47,1,r0; adds	r45,0x0,r8; (p07) br.cond.dpnt.few	400000000011E8E0; }

l400000000011E7C0:
	{ nop.m	0x0; ld4	r14,[r33]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; adds	r46,0x0,r14; adds	r14,0x10,r12; }
	{ ld4	r37,[r14]; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011E800; }

l400000000011E7F0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r37; (p07) br.cond.dpnt.few	400000000011E870 }

l400000000011E800:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,pcomp_set_compspec_options; }
	{ adds	r1,0x0,r44; adds	r45,0x0,r36; nop.i	0x0 }
	{ adds	r46,0x0,r37; adds	r47,0x0,r0; br.call.sptk.many	b0,pcomp_set_compspec_options; }
	{ ld8	r35,[r35]; nop.m	0x0; adds	r1,0x0,r44; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	400000000011E780 }

l400000000011E850:
	{ adds	r8,0x0,r34; mov.i	ar.pfs,r43; mov.spnt	b0,r42,400000000011E850 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l400000000011E870:
	{ ld8	r14,[r38]; nop.m	0x0; adds	r46,0x0,r8; }
	{ ld8	r45,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000011CBC0; }
	{ ld8	r35,[r35]; nop.m	0x0; adds	r1,0x0,r44; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	400000000011E780 }

l400000000011E8B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011E850; }

l400000000011E8C0:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r34; (p07) br.cond.dptk.few	400000000011E3A0 }

l400000000011E8D0:
	{ adds	r35,0x0,r34; adds	r34,0x0,r0; br.cond.sptk.few	400000000011E780; }

l400000000011E8E0:
	{ addl	r46,-3476,r1; nop.m	0x0; adds	r45,0x0,r0 }
	{ addl	r47,5,r0; nop.m	0x0; addl	r34,1,r0; }
	{ ld8	r46,[r46]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ ld8	r14,[r38]; adds	r1,0x0,r44; adds	r45,0x0,r8; }
	{ ld8	r46,[r14]; nop.i	0x0; br.call.sptk.many	b0,builtin_error; }
	{ ld8	r35,[r35]; nop.m	0x0; adds	r1,0x0,r44; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	400000000011E780 }

l400000000011E950:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011E850 }

l400000000011E960:
	{ adds	r45,0x0,r41; addl	r34,258,r0; br.call.sptk.many	b0,sh_invalidoptname; }
	{ adds	r8,0x0,r34; adds	r1,0x0,r44; mov.i	ar.pfs,r43; }
	{ nop.m	0x0; mov.spnt	b0,r42,400000000011E980; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l400000000011E9A0:
	{ nop.m	0x0; addl	r45,-3492,r1; nop.i	0x0; }
	{ ld8	r45,[r45]; nop.i	0x0; br.cond.sptk.few	400000000011E6F0; }

;; fn400000000011E9C0: 400000000011E9C0
;;   Called from:
;;     400000000011FA2C (in glob_pattern_p)
fn400000000011E9C0 proc
	{ nop.m	0x0; addl	r17,-6204,r1; adds	r18,0x0,r0 }
	{ ld1	r14,[r32]; ld8	r17,[r17]; nop.i	0x0 }

l400000000011E9E0:
	{ cmp4.eq	p07,p06,0x0,r14; nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFFDF,r14 }
	{ adds	r15,0x1,r32; nop.m	0x0; (p07) br.cond.dpnt.few	400000000011EAF0; }

l400000000011EA00:
	{ nop.m	0x0; zxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x3C,r14; (p07) br.cond.dptk.few	400000000011EA30 }

l400000000011EA20:
	{ ld1	r14,[r15]; adds	r32,0x0,r15; br.cond.sptk.few	400000000011E9E0; }

l400000000011EA30:
	{ shladd	r14,r14,0x3,r17; ld8	r16,[r14]; nop.i	0x0; }
	{ nop.m	0x0; add	r14,r14,r16; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r14,400000000011EA50; br.cond	b6; }
400000000011EA60 10 00 00 00 01 00 70 00 48 0C F3 03 C0 FF FF 4A ......p.H......J
400000000011EA70 10 00 00 00 01 00 80 08 00 00 48 80 08 00 84 00 ..........H.....
400000000011EA80 09 70 00 1E 00 10 00 00 00 02 00 00 04 78 00 84 .p...........x..
400000000011EA90 12 30 A0 1C 87 B9 01 F0 FF FF 25 00 50 FF FF 48 .0........%.P..H
400000000011EAA0 09 70 00 1E 00 10 00 00 00 02 00 00 24 00 01 84 .p..........$...
400000000011EAB0 11 30 00 1C 07 39 00 00 00 02 00 03 40 00 00 43 .0...9......@..C
400000000011EAC0 11 70 00 40 00 10 00 00 00 02 00 00 20 FF FF 48 .p.@........ ..H
400000000011EAD0 08 00 00 00 01 00 E0 00 3C 00 20 40 12 90 00 84 ........<. @....
400000000011EAE0 18 00 00 00 01 00 00 02 3C 00 42 00 00 FF FF 48 ........<.B....H

l400000000011EAF0:
	{ nop.m	0x0; adds	r8,0x0,r0; br.ret	b0; }

;; fn400000000011EB00: 400000000011EB00
;;   Called from:
;;     400000000011F7EC (in fn400000000011F5C0)
fn400000000011EB00 proc
	{ cmp.eq	p06,p07,0x0,r32; nop.m	0x0; adds	r14,0x0,r0 }
	{ adds	r16,0x0,r32; nop.m	0x0; (p06) br.ret	b0; }

l400000000011EB20:
	{ ld1	r15,[r32]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dpnt.few	400000000011EBE0; }

l400000000011EB40:
	{ cmp4.eq	p07,p06,0x5C,r15; (p07) adds	r14,0x1,r14; nop.i	0x0; }

l400000000011EB4C:
	{ nop.m	0x80; nop; (p02) cmp.lt.unc	p00,p00,r67,r5 }
	{ nop; (p02) cmp.eq	p40,p16,r4,r0; Invalid; }
	{ (p16) nop; (p02) nop; (p16) nop; }
	{ (p63) nop; (p02) br.cond.sptk.few	400000000031EBBC; (p02) brp.sptk	b0,400000000011EBBC }
	{ cmp.eq	p17,p17,r20,r0; czx1.r	r32,r97; mov	pr,r32,0x0 }
	{ (p01) cmp.eq	p00,p11,r64,r33; Invalid; Invalid }

l400000000011EBA0:
	{ ld1	r15,[r15]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	400000000011EB40 }

l400000000011EBC0:
	{ nop.m	0x0; sxt4	r18,r18; add	r32,r32,r18; }
	{ st1	[r0],r32; nop.i	0x0; br.ret	b0 }

l400000000011EBE0:
	{ adds	r18,0x0,r0; add	r32,r32,r18; nop.i	0x0; }
	{ st1	[r0],r32; nop.i	0x0; br.ret	b0; }

;; fn400000000011EC00: 400000000011EC00
;;   Called from:
;;     400000000011FD8C (in glob_vector)
;;     400000000012020C (in glob_vector)
;;     400000000012040C (in glob_vector)
fn400000000011EC00 proc
	{ alloc	r34,ar.pfs,0x7,0x0,0x4; adds	r12,0xFFFFFFFFFFFFFF70,r12; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; adds	r37,0x0,r32; }
	{ addl	r36,1,r0; adds	r38,0x10,r12; br.call.sptk.many	b0,fn400000000001AFE0; }
	{ adds	r15,0x28,r12; adds	r1,0x0,r35; nop.i	0x0 }
	{ cmp4.lt	p07,p06,r8,r0; adds	r14,0x0,r0; (p07) br.cond.dpnt.few	400000000011ECA0; }

l400000000011EC50:
	{ ld4	r16,[r15]; addl	r15,61440,r0; adds	r8,0x0,r14; }
	{ and	r16,r15,r16; nop.m	0x0; addl	r15,16384,r0; }
	{ cmp4.eq	p07,p06,r15,r16; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011ECA0; }

l400000000011EC80:
	{ nop.m	0x0; mov.i	ar.pfs,r34; mov.spnt	b0,r33,400000000011EC80 }
	{ nop.m	0x0; adds	r12,0x90,r12; br.ret	b0 }

l400000000011ECA0:
	{ nop.m	0x0; addl	r14,-1,r0; nop.i	0x0; }
	{ adds	r8,0x0,r14; mov.i	ar.pfs,r34; mov.spnt	b0,r33,400000000011ECB0 }
	{ nop.m	0x0; adds	r12,0x90,r12; br.ret	b0; }
400000000011ECD0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000011ECE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000011ECF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn400000000011ED00: 400000000011ED00
;;   Called from:
;;     4000000000120FBC (in glob_filename)
fn400000000011ED00 proc
	{ alloc	r48,ar.pfs,0x16,0x0,0x13; adds	r12,0xFFFFFFFFFFFFFF70,r12; mov	r50,pr }
	{ adds	r49,0x0,r1; nop.m	0x0; adds	r51,0x0,r32; }
	{ nop.m	0x0; mov	r47,b7; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r49; tbit.z	p07,p06,r34,0x0; adds	r14,0x0,r0 }
	{ adds	r16,0xFFFFFFFFFFFFFFFF,r8; cmp4.eq	p09,p08,0x0,r8; (p08) br.cond.dptk.few	400000000011EE50 }

l400000000011ED50:
	{ adds	r36,0x0,r33; adds	r35,0x0,r0; adds	r37,0x28,r12 }
	{ addl	r38,61440,r0; addl	r39,16384,r0; (p07) br.cond.dpnt.few	400000000011EE20; }

l400000000011ED70:
	{ nop.m	0x0; addp4	r43,0xFFFFFFFFFFFFFFFF,r0; addl	r44,47,r0 }
	{ nop.m	0x0; ld8	r52,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r52; (p06) br.cond.dpnt.few	400000000011EE20; }

l400000000011EDA0:
	{ adds	r53,0x10,r12; nop.m	0x0; addl	r51,1,r0 }
	{ adds	r35,0x1,r35; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AFE0; }
	{ adds	r1,0x0,r49; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	400000000011EDF0 }

l400000000011EDD0:
	{ ld4	r14,[r37]; and	r14,r38,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r39,r14; (p07) br.cond.dpnt.few	400000000011F1E0 }

l400000000011EDF0:
	{ addp4	r36,r35,r0; shladd	r36,r36,0x3,r33; nop.i	0x0; }
	{ nop.m	0x0; ld8	r52,[r36]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r52; (p06) br.cond.dptk.few	400000000011EDA0; }

l400000000011EE20:
	{ adds	r8,0x0,r33; mov	pr,r50,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r48; }
	{ nop.m	0x0; mov.spnt	b0,r47,400000000011EE30; nop.i	0x0 }
	{ adds	r12,0x90,r12; nop.m	0x0; br.ret	b0 }

l400000000011EE50:
	{ addp4	r16,r16,r0; ld8	r35,[r33]; nop.i	0x0; }
	{ add	r16,r32,r16; cmp.eq	p06,p07,0x0,r35; (p06) br.cond.dpnt.few	400000000011F2D0; }

l400000000011EE70:
	{ nop.m	0x0; ld1	r41,[r16]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r41,r41; cmp4.eq	p09,p08,0x2F,r41; }
	{ (p08) addl	r41,1,r0; nop.i	0x0; (p09) adds	r41,0x0,r0; }

l400000000011EE96:
	{ addl	r0,16384,r1; (p20) nop; (p32) nop }

l400000000011EEA0:
	{ adds	r14,0x1,r14; addp4	r15,r14,r0; nop.i	0x0; }
	{ shladd	r15,r15,0x3,r33; ld8	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	400000000011EEA0 }

l400000000011EED0:
	{ adds	r14,0x1,r14; addp4	r42,r8,r0; cmp4.eq	p16,p17,0x0,r41 }
	{ adds	r37,0x0,r33; adds	r36,0x0,r0; zxt1	r41,r41; }
	{ addp4	r51,r14,r0; add	r41,r41,r42; nop.b	0x0 }
	{ addl	r43,47,r0; adds	r40,0x3,r42; tnat.z	p19,p18,r34; }
	{ shladd	r51,r51,0x3,r0; adds	r44,0x28,r12; nop.i	0x0 }
	{ addl	r45,61440,r0; addl	r46,16384,r0; br.call.sptk.many	b0,fn400000000001B340; }
	{ adds	r14,0x0,r0; nop.m	0x0; adds	r39,0x0,r8 }
	{ adds	r1,0x0,r49; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	400000000011F2A0; }

l400000000011EF50:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000011EF60:
	{ add	r38,r39,r14; nop.m	0x0; adds	r51,0x0,r35 }
	{ adds	r36,0x1,r36; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r49; add	r51,r8,r40; br.call.sptk.many	b0,fn400000000001B340; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r49; adds	r35,0x0,r8 }
	{ st8	[r8],r38; adds	r51,0x0,r8; (p06) br.cond.dpnt.few	400000000011F2A0; }

l400000000011EFB0:
	{ adds	r52,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ (p17) add	r14,r35,r42; adds	r1,0x0,r49; add	r51,r35,r41 }

l400000000011EFC6:
	{ Invalid; (p25) nop; br.call.sptk.few	b5,40000000006A39C6 }
	{ mf.a; nop }

l400000000011EFDC:
	{ shladd	r0,r1,0x2,r0; Invalid; break.i	0x1000 }
	{ (p13) invala; nop; chk.s.i	r12,3FFFFFFFFF53F1EC }
	{ (p08) cmp.lt	p00,p11,r64,r33; (p01) cmp.lt	p09,p16,r0,r2; (p33) epc }

l400000000011F000:
	{ addp4	r14,r36,r0; shladd	r14,r14,0x3,r0; nop.i	0x0; }
	{ add	r37,r33,r14; ld8	r35,[r37]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	400000000011EF60 }

l400000000011F030:
	{ nop.m	0x0; add	r14,r39,r14; adds	r35,0x0,r0 }
	{ ld8.a	r51,[r33]; st8	[r0],r14; cmp.eq	p07,p06,0x0,r51 }
	{ nop.m	0x0; chk.a.clr	r51,400000000011F350; nop.b	0x0 }

l400000000011F05C:
	{ Invalid; break.i	0x1000; mov	pr,r32,0x0 }

l400000000011F060:
	{ nop.m	0x0; nop.i	0x0; (p07) br.cond.dpnt.few	400000000011F0C0; }

l400000000011F070:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000011F080:
	{ adds	r35,0x1,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ addp4	r14,r35,r0; adds	r1,0x0,r49; shladd	r14,r14,0x3,r33; }
	{ nop.m	0x0; ld8	r51,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r51; (p06) br.cond.dptk.few	400000000011F080 }

l400000000011F0C0:
	{ adds	r51,0x0,r33; adds	r33,0x0,r39; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r49; mov	pr,r50,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r48; mov.spnt	b0,r47,400000000011F0E0 }
	{ nop.m	0x0; adds	r12,0x90,r12; br.ret	b0; }

l400000000011F100:
	{ addl	r51,1,r0; ld8	r52,[r38]; adds	r53,0x10,r12 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AFE0; }
	{ adds	r1,0x0,r49; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	400000000011F000 }

l400000000011F130:
	{ ld4	r14,[r44]; and	r14,r45,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r46,r14; (p06) br.cond.dptk.few	400000000011F000 }

l400000000011F150:
	{ nop.m	0x0; ld8	r35,[r38]; nop.i	0x0; }
	{ adds	r51,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ ld8.a	r14,[r38]; add	r35,r35,r8; adds	r1,0x0,r49; }
	{ nop.m	0x0; st1	[r43],r35; nop.i	0x0; }
	{ ld8.c.clr	r14,[r38]; add	r8,r14,r8,0x1; addp4	r14,r36,r0; }
	{ shladd	r14,r14,0x3,r0; st1	[r0],r8; nop.i	0x0; }
	{ add	r37,r33,r14; ld8	r35,[r37]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	400000000011EF60 }

l400000000011F1D0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011F030 }

l400000000011F1E0:
	{ nop.m	0x0; ld8	r42,[r36]; nop.i	0x0; }
	{ adds	r51,0x0,r42; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r40,0x0,r8; adds	r52,0x2,r8; adds	r1,0x0,r49 }
	{ adds	r51,0x0,r42; adds	r41,0x1,r40; and	r40,r43,r40 }
	{ addp4	r52,r52,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AD60; }
	{ addp4	r41,r41,r0; add	r40,r8,r40; nop.i	0x0 }
	{ adds	r1,0x0,r49; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	400000000011F2A0; }

l400000000011F250:
	{ add	r41,r8,r41; st1	[r44],r40; nop.i	0x0; }
	{ st1	[r0],r41; st8	[r8],r36; addp4	r36,r35,r0; }
	{ shladd	r36,r36,0x3,r33; ld8	r52,[r36]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r52; (p06) br.cond.dptk.few	400000000011EDA0 }

l400000000011F290:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011EE20 }

l400000000011F2A0:
	{ adds	r33,0x0,r0; adds	r8,0x0,r33; mov	pr,r50,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r48; mov.spnt	b0,r47,400000000011F2B0 }
	{ nop.m	0x0; adds	r12,0x90,r12; br.ret	b0; }

l400000000011F2D0:
	{ addl	r51,8,r0; adds	r35,0x0,r0; br.call.sptk.many	b0,fn400000000001B340; }
	{ adds	r14,0x0,r0; adds	r39,0x0,r8; nop.i	0x0 }
	{ adds	r1,0x0,r49; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	400000000011F2A0; }

l400000000011F300:
	{ add	r14,r39,r14; ld8.a	r51,[r33]; nop.i	0x0; }
	{ nop.m	0x0; st8	[r0],r14; cmp.eq	p07,p06,0x0,r51 }
	{ nop.m	0x0; chk.a.clr	r51,400000000011F370; nop.b	0x0 }

l400000000011F32C:
	{ Invalid; Invalid; Invalid }

l400000000011F330:
	{ (p06) br.cond.dptk.few	400000000011F080; nop.b	0x0; nop.b	0x0 }

l400000000011F336:
	{ invala; nop; break.i	0x80000 }
	{ break.m	0x4000; nop; break.i	0x80000 }

l400000000011F350:
	{ nop.m	0x0; ld8	r51,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r51; br.cond.sptk.few	400000000011F060 }

l400000000011F370:
	{ nop.m	0x0; ld8	r51,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r51; br.cond.sptk.few	400000000011F330; }
400000000011F390 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000011F3A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000011F3B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn400000000011F3C0: 400000000011F3C0
;;   Called from:
;;     400000000011FD2C (in glob_vector)
;;     40000000001206CC (in glob_vector)
fn400000000011F3C0 proc
	{ addl	r14,6372,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	400000000011F440 }

l400000000011F3E0:
	{ ld1	r14,[r32]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x2E,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011F430; }

l400000000011F400:
	{ cmp4.eq	p07,p06,0x5C,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000011F4A0; }

l400000000011F410:
	{ ld1	r14,[r33]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r14; (p07) br.cond.dpnt.few	400000000011F4F0 }

l400000000011F430:
	{ nop.m	0x0; adds	r8,0x0,r0; br.ret	b0 }

l400000000011F440:
	{ ld1	r14,[r33]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r14; (p06) br.cond.dptk.few	400000000011F430 }

l400000000011F460:
	{ ld1	r14,[r32]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x2E,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011F430; }

l400000000011F480:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5C,r14; (p07) br.cond.dpnt.few	400000000011F560 }

l400000000011F490:
	{ nop.m	0x0; addl	r8,1,r0; br.ret	b0 }

l400000000011F4A0:
	{ adds	r32,0x1,r32; ld1	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x2E,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011F430; }

l400000000011F4D0:
	{ ld1	r14,[r33]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r14; (p06) br.cond.dptk.few	400000000011F430 }

l400000000011F4F0:
	{ adds	r14,0x1,r33; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000011F490; }

l400000000011F520:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r14; (p06) br.cond.dptk.few	400000000011F430 }

l400000000011F530:
	{ adds	r33,0x2,r33; nop.m	0x0; adds	r8,0x0,r0; }
	{ ld1	r14,[r33]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	400000000011F490; br.ret	b0 }

l400000000011F55C:
	{ nop; (p20) invala; break.i	0x1000 }

l400000000011F560:
	{ adds	r32,0x1,r32; nop.m	0x0; addl	r8,1,r0; }
	{ ld1	r14,[r32]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x2E,r14; (p07) br.cond.dpnt.few	400000000011F430; br.ret	b0; }

l400000000011F58C:
	{ nop; break.m	0x1000; break.i	0x1000 }
400000000011F590 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000011F5A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000011F5B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn400000000011F5C0: 400000000011F5C0
;;   Called from:
;;     4000000000120AFC (in glob_vector)
;;     40000000001219FC (in glob_filename)
fn400000000011F5C0 proc
	{ alloc	r36,ar.pfs,0xA,0x0,0x6; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ adds	r37,0x0,r1; nop.m	0x0; mov	r35,b3; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ cmp.ltu	p07,p06,0x1,r8; nop.m	0x0; adds	r1,0x0,r37 }
	{ adds	r38,0x0,r32; nop.m	0x0; (p06) br.cond.dpnt.few	400000000011F7E0; }

l400000000011F610:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r37; adds	r34,0x0,r8; adds	r38,0x18,r12 }
	{ adds	r39,0x0,r0; adds	r40,0x0,r32; br.call.sptk.many	b0,xdupmbstowcs; }
	{ adds	r15,0x18,r12; adds	r1,0x0,r37; cmp.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8 }
	{ adds	r16,0x0,r0; adds	r14,0x0,r0; (p07) br.cond.dpnt.few	400000000011F7E0; }

l400000000011F660:
	{ nop.m	0x0; ld8	r33,[r15]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r33; adds	r17,0x0,r33; (p06) br.cond.dpnt.few	400000000011F770; }

l400000000011F680:
	{ nop.m	0x0; ld4	r15,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dpnt.few	400000000011F810; }

l400000000011F6A0:
	{ cmp4.eq	p07,p06,0x5C,r15; adds	r16,0x1,r16; (p07) adds	r14,0x1,r14; }

l400000000011F6B0:
	{ nop.m	0x0; sxt4	r18,r14; adds	r14,0x1,r14; }
	{ nop.m	0x0; sxt4	r15,r14; shladd	r18,r18,0x2,r33; }
	{ ld4	r19,[r18]; adds	r18,0xFFFFFFFFFFFFFFFF,r15; shladd	r15,r15,0x2,r33; }
	{ st4	[r17],r4,4; nop.m	0x0; shladd	r18,r18,0x2,r33; }
	{ nop.m	0x0; ld4	r18,[r18]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r18; nop.i	0x0; (p07) br.cond.dpnt.few	400000000011F740; }

l400000000011F710:
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	400000000011F6A0; }

l400000000011F730:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000011F740:
	{ nop.m	0x0; sxt4	r16,r16; shladd	r16,r16,0x2,r0; }
	{ nop.m	0x0; add	r16,r33,r16; nop.i	0x0; }
	{ st4	[r0],r16; nop.m	0x0; nop.i	0x0 }

l400000000011F770:
	{ adds	r14,0x10,r12; adds	r38,0x0,r32; nop.i	0x0 }
	{ adds	r39,0x18,r12; adds	r40,0x0,r34; add	r32,r32,r34; }
	{ st8	[r0],r14; adds	r41,0x0,r14; br.call.sptk.many	b0,fn400000000001A7A0; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r38,0x0,r33 }
	{ st1	[r0],r32; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r37; mov.i	ar.pfs,r36; mov.spnt	b0,r35,400000000011F7C0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l400000000011F7E0:
	{ adds	r38,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000011EB00; }
	{ adds	r1,0x0,r37; mov.i	ar.pfs,r36; mov.spnt	b0,r35,400000000011F7F0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l400000000011F810:
	{ adds	r16,0x0,r0; add	r16,r33,r16; nop.i	0x0; }
	{ st4	[r0],r16; nop.i	0x0; br.cond.sptk.few	400000000011F770; }
400000000011F830 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; glob_pattern_p: 400000000011F840
;;   Called from:
;;     40000000000CC48C (in command_word_completion_function)
;;     40000000000D72CC (in bash_default_completion)
;;     40000000000D75FC (in bash_default_completion)
;;     40000000000D9BFC (in strcreplace)
;;     40000000000FC40C (in help_builtin)
;;     40000000000FC40C (in help_builtin)
;;     400000000011FB1C (in glob_vector)
;;     4000000000120E6C (in glob_filename)
;;     40000000001218FC (in glob_filename)
glob_pattern_p proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ adds	r36,0x0,r1; nop.m	0x0; mov	r34,b2; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ cmp.eq	p07,p06,0x1,r8; adds	r1,0x0,r36; adds	r37,0x10,r12 }
	{ adds	r38,0x0,r0; adds	r39,0x0,r32; (p07) br.cond.dpnt.few	400000000011FA20; }

l400000000011F890:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,xdupmbstowcs; }
	{ adds	r14,0x10,r12; adds	r1,0x0,r36; nop.i	0x0 }
	{ cmp.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; adds	r19,0x0,r0; (p07) br.cond.dpnt.few	400000000011FA20; }

l400000000011F8C0:
	{ ld8	r37,[r14]; nop.m	0x0; addl	r18,-6196,r1; }
	{ ld8	r18,[r18]; adds	r16,0x0,r37; nop.i	0x0; }
	{ ld4	r14,[r37]; nop.m	0x0; nop.i	0x0; }

l400000000011F8F0:
	{ cmp4.eq	p07,p06,0x0,r14; nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFFDF,r14 }
	{ adds	r15,0x4,r16; nop.m	0x0; (p07) br.cond.dpnt.few	400000000011FA60; }

l400000000011F910:
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x3C,r14; (p07) br.cond.dptk.few	400000000011F930 }

l400000000011F920:
	{ ld4	r14,[r15]; adds	r16,0x0,r15; br.cond.sptk.few	400000000011F8F0; }

l400000000011F930:
	{ addp4	r14,r14,r0; shladd	r14,r14,0x3,r18; nop.i	0x0; }
	{ ld8	r17,[r14]; add	r14,r14,r17; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r14,400000000011F950; br.cond	b6; }
400000000011F960 10 00 00 00 01 00 70 00 4C 0C F3 03 C0 FF FF 4A ......p.L......J
400000000011F970 11 00 00 00 01 00 10 0A 00 00 48 00 78 AE EF 58 ..........H.x..X
400000000011F980 08 08 00 48 00 21 00 00 00 02 00 00 00 00 04 00 ...H.!..........

l400000000011F990:
	{ adds	r8,0x0,r33; mov.i	ar.pfs,r35; mov.spnt	b0,r34,400000000011F990 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }
400000000011F9B0 09 70 00 1E 10 10 00 00 00 02 00 00 82 80 00 84 .p..............
400000000011F9C0 11 30 00 1C 87 39 00 00 00 02 00 03 A0 00 00 43 .0...9.........C
400000000011F9D0 11 70 00 20 10 10 00 00 00 02 00 00 20 FF FF 48 .p. ........ ..H
400000000011F9E0 08 00 00 00 01 00 30 09 4C 00 42 00 00 00 04 00 ......0.L.B.....
400000000011F9F0 19 70 00 1E 10 10 00 01 3C 00 42 00 00 FF FF 48 .p......<.B....H
400000000011FA00 09 70 00 1E 10 10 00 00 00 02 00 00 02 78 00 84 .p...........x..
400000000011FA10 12 30 A0 1C 87 B9 01 B0 FF FF 25 00 E0 FE FF 48 .0........%....H

l400000000011FA20:
	{ adds	r37,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000011E9C0; }
	{ adds	r33,0x0,r8; nop.m	0x0; adds	r1,0x0,r36; }
	{ adds	r8,0x0,r33; mov.i	ar.pfs,r35; mov.spnt	b0,r34,400000000011FA40 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l400000000011FA60:
	{ adds	r33,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r36; br.cond.sptk.few	400000000011F990; }

;; glob_vector: 400000000011FA80
;;   Called from:
;;     400000000011FDDC (in glob_vector)
;;     4000000000120F4C (in glob_filename)
glob_vector proc
	{ alloc	r60,ar.pfs,0x23,0x0,0x20; adds	r61,0x0,r12; nop.b	0x0 }
	{ adds	r12,0xFFFFFFFFFFFFFF60,r12; mov	r63,pr; adds	r62,0x0,r1; }
	{ nop.m	0x0; mov	r59,b3; cmp.eq	p06,p07,0x0,r32 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dpnt.few	40000000001201F0; }

l400000000011FAC0:
	{ ld1	r14,[r32]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	40000000001201F0 }

l400000000011FAE0:
	{ adds	r64,0x0,r32; tnat.z	p18,p19,r34; addl	r50,528,r0 }
	{ adds	r36,0x0,r0; adds	r54,0x0,r0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r62; adds	r35,0x0,r8; adds	r64,0x0,r32 }
	{ and	r50,r50,r34; adds	r41,0x0,r0; br.call.sptk.many	b0,glob_pattern_p; }
	{ cmp4.eq	p06,p07,0x0,r8; adds	r1,0x0,r62; adds	r64,0x0,r33 }
	{ adds	r46,0x8,r61; addl	r56,99999,r0; (p06) br.cond.dpnt.few	4000000000120400; }

l400000000011FB40:
	{ nop.m	0x0; tnat.z	p24,p25,r34; adds	r35,0x0,r0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C3E0; }
	{ adds	r1,0x0,r62; cmp.eq	p06,p07,0x0,r8; nop.i	0x0 }
	{ and	r16,0x18,r34; adds	r39,0x0,r8; (p06) br.cond.dpnt.few	4000000000120420; }

l400000000011FB80:
	{ addl	r14,8772,r1; addl	r49,6372,r1; addl	r38,7684,r1 }
	{ addl	r40,7676,r1; cmp4.eq	p20,p21,0x0,r16; addl	r57,21276,r1; }
	{ ld4	r14,[r14]; nop.m	0x0; addl	r16,-513,r0 }
	{ addl	r58,9284,r1; ld4	r48,[r49]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; addl	r14,7664,r1; cmp4.eq	p08,p09,0x0,r48 }
	{ nop.m	0x0; nop.m	0x0; and	r55,r16,r34; }
	{ nop.m	0x0; nop.m	0x0; (p08) addl	r48,1,r0 }

l400000000011FBF0:
	{ nop.m	0x0; nop.i	0x0; (p09) addl	r48,5,r0 }

l400000000011FC00:
	{ nop.m	0x0; ld4	r14,[r14]; (p07) or	r48,0x10,r48; }

l400000000011FC10:
	{ cmp4.eq	p06,p07,0x0,r14; nop.m	0x0; and	r14,0x10,r34; }
	{ cmp4.eq	p16,p17,0x0,r14; (p07) or	r48,0x20,r48; cmp4.eq	p23,p22,0x0,r14; }

l400000000011FC2C:
	{ cmp.gt.or.andcm	p14,p11,r0,r115; (p01) cmp.gt.or.andcm	p00,p48,r0,r64; zxt4	r1,r0 }

l400000000011FC36:
	{ Invalid; Invalid; Invalid }

l400000000011FC3C:
	{ cmpxchg1.acq.nt1	r0,[r0],r1; (p08) nop; (p06) nop }

l400000000011FC4C:
	{ Invalid; Invalid; Invalid }

l400000000011FC50:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000011FC60:
	{ ld4.acq	r14,[r38]; nop.m	0x0; adds	r64,0x0,r39; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000120840; }

l400000000011FC80:
	{ nop.m	0x0; ld4.acq	r14,[r40]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000120840; }

l400000000011FCA0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BC60; }
	{ adds	r1,0x0,r62; nop.m	0x0; cmp.eq	p06,p07,0x0,r8 }
	{ adds	r37,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000120CE0; }

l400000000011FCD0:
	{ nop.m	0x0; ld8	r14,[r8]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000011FC60 }

l400000000011FCF0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r62; cmp.ltu	p06,p07,0x1,r8; (p06) br.cond.dptk.few	4000000000120550 }

l400000000011FD10:
	{ adds	r37,0x13,r37; nop.m	0x0; nop.i	0x0; }

l400000000011FD20:
	{ adds	r64,0x0,r32; adds	r65,0x0,r37; br.call.sptk.many	b0,fn400000000011F3C0; }
	{ adds	r1,0x0,r62; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	400000000011FC60 }

l400000000011FD40:
	{ nop.m	0x0; nop.i	0x0; (p20) br.cond.dptk.few	400000000011FDB0 }

l400000000011FD50:
	{ adds	r65,0x0,r37; nop.m	0x0; adds	r66,0x0,r53 }
	{ adds	r64,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,sh_makepath; }
	{ adds	r1,0x0,r62; nop.m	0x0; adds	r47,0x0,r8 }
	{ adds	r64,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000011EC00; }
	{ nop.m	0x0; adds	r1,0x0,r62; adds	r52,0x0,r8 }
	{ nop.m	0x0; cmp4.lt	p07,p06,r8,r0; (p07) br.cond.dpnt.few	40000000001208F0; }

l400000000011FDB0:
	{ cmp4.eq	p07,p06,0x0,r52; (p16) br.cond.dpnt.few	4000000000120900; (p06) br.cond.dptk.few	4000000000120760 }

l400000000011FDBC:
	{ (p13) nop; zxt1	r0,r64; nop.b	0x1000 }

l400000000011FDC0:
	{ adds	r64,0x0,r32; nop.m	0x0; adds	r65,0x0,r47 }
	{ adds	r66,0x0,r55; nop.m	0x0; br.call.sptk.many	b0,glob_vector; }
	{ adds	r1,0x0,r62; nop.m	0x0; cmp.eq	p06,p07,0x0,r8 }
	{ adds	r51,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000120760; }

l400000000011FE00:
	{ nop.m	0x0; ld8	r14,[r8]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000120720; }

l400000000011FE20:
	{ (p06) adds	r44,0x8,r8; nop.m	0x0; (p06) adds	r43,0x0,r8 }

l400000000011FE26:
	{ adds	r0,0xFFFFFFFFFFFFE000,r1; (p21) addl	r0,24840,r0; (p17) nop }

l400000000011FE30:
	{ (p06) adds	r45,0x0,r0; (p06) adds	r37,0x0,r0; (p06) adds	r42,0x0,r0; }

l400000000011FE36:
	{ (p18) chk.a.clr	r0,3FFFFFFFFF19FE36; (p21) nop; nop.b	0x210; }

l400000000011FE3C:
	{ Invalid; (p21) nop; }

l400000000011FE40:
	{ addl	r64,16,r0; adds	r45,0x1,r45; br.call.sptk.many	b0,fn400000000001B340; }
	{ adds	r14,0x0,r8; adds	r1,0x0,r62; nop.i	0x0 }
	{ cmp.eq	p07,p06,0x0,r8; cmp.eq	p08,p09,0x0,r42; (p07) br.cond.dpnt.few	4000000000120520; }

l400000000011FE70:
	{ st8	[r14],r8,8; (p08) adds	r42,0x0,r8; adds	r37,0x0,r8; }

l400000000011FE7C:
	{ cmp.eq	p08,p09,r0,r66; (p05) nop }
	{ Invalid; (p01) nop; }
	{ invala; cmp.eq	p00,p00,r32,r0; mov	pr,r67,0xE480 }
	{ Invalid; zxt1	r96,r64; break.i	0x1000 }

l400000000011FEB0:
	{ adds	r64,0x0,r51; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ cmp.eq	p07,p06,0x0,r36; cmp.eq	p09,p08,r57,r37; nop.i	0x0 }
	{ addl	r64,16,r0; adds	r1,0x0,r62; (p09) br.cond.spnt.few	400000000011FF70; }

l400000000011FEE0:
	{ (p07) adds	r36,0x0,r42; st8	[r35],r42; nop.i	0x0 }

l400000000011FEE6:
	{ mf.a; nop; (p48) nop }
	{ Invalid; (p32) nop; (p16) nop.b	0x3E000 }
	{ add	r0,r0,r1; (p18) nop; nop }
	{ break.m	0x4000; Invalid; nop }
	{ Invalid; (p21) nop; nop.b	0x2A010 }
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ Invalid; (p08) nop; (p16) nop.b	0x2F010 }
	{ Invalid; (p32) nop; break.i	0x80000 }
	{ (p03) chk.a.clr	f0,3FFFFFFFFFDC37E6; nop; break.i	0x80000 }

l400000000011FF70:
	{ nop.m	0x0; adds	r64,0x0,r47; addl	r37,1,r0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r62; nop.m	0x0; nop.i	0x0 }

l400000000011FFA0:
	{ adds	r64,0x0,r39; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C300; }
	{ addl	r14,528,r0; adds	r1,0x0,r62; adds	r64,0x0,r33; }
	{ cmp4.eq	p07,p06,r14,r50; nop.i	0x0; (p06) br.cond.spnt.few	40000000001200A0; }

l400000000011FFD0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r8,0x1,r8; adds	r1,0x0,r62; sxt4	r42,r8; }
	{ adds	r64,0x0,r42; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B340; }
	{ adds	r1,0x0,r62; nop.m	0x0; adds	r40,0x0,r8 }
	{ addl	r64,16,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B340; }
	{ cmp.eq	p06,p07,0x0,r8; nop.m	0x0; adds	r39,0x0,r8 }
	{ adds	r14,0x8,r8; nop.m	0x0; adds	r1,0x0,r62; }
	{ nop.m	0x0; cmp.eq.or.andcm	p06,p07,0x0,r40; (p06) br.cond.dptk.few	40000000001200E0 }

l4000000000120050:
	{ st8	[r35],r8; st8	[r40],r14; (p18) adds	r64,0x0,r40 }

l4000000000120060:
	{ (p18) adds	r65,0x0,r33; (p18) adds	r66,0x0,r42; adds	r41,0x1,r41; }

l4000000000120066:
	{ Invalid; nop }

l400000000012006C:
	{ Invalid; Invalid; Invalid }

l400000000012007C:
	{ nop; break.x	0x8000101000 }
	{ (p58) nop; invala; break.i	0x1000 }

l4000000000120090:
	{ (p18) adds	r1,0x0,r62; nop.m	0x0; nop.i	0x0 }

l4000000000120096:
	{ break.m	0x4000; nop; break.i	0x80000 }

l40000000001200A0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r37; (p07) br.cond.dpnt.few	4000000000120290; }

l40000000001200A2:
	{ Invalid; (p16) cmp.eq.unc	p09,p01,r97,r124; Invalid }

l40000000001200A6:
	{ (p03) chk.a.clr	f0,3FFFFFFFFFDE32F6; nop; break.b	0x80000 }

l40000000001200AC:
	{ (p15) nop; break.i	0x1000; break.b	0x1000 }
	{ nop; cmp.lt	p00,p00,r32,r0; zxt4	r33,r15 }

l40000000001200C0:
	{ nop.m	0x0; addl	r38,7684,r1; nop.i	0x0; }

l40000000001200C2:
	{ Invalid; (p16) break.i	0x48780; Invalid }
	{ break.m	0x20; break.i	0x20; Invalid }

l40000000001200E0:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p07) br.cond.dpnt.few	4000000000120170; }

l40000000001200F0:
	{ cmp.eq	p06,p07,0x0,r36; nop.m	0x0; cmp.eq	p08,p09,r36,r35 }
	{ adds	r14,0x8,r35; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000120460; }

l4000000000120110:
	{ nop.m	0x0; (p08) adds	r36,0x0,r0; nop.i	0x0 }

l400000000012011C:
	{ nop; Invalid; break.i	0x1000 }
	{ (p54) nop; (p04) nop; nop }
	{ nop; zxt1	r96,r64; break.i	0x1000 }
	{ (p53) ldfp8	f116,f59,[r44]; (p04) invala; nop }
	{ invala; cmp.eq	p00,p00,r32,r0; mov	pr,r72,0xE4C0 }
	{ (p60) cmp.lt.unc	p63,p11,r63,r37; zxt4	r63,r14; break.b	0x1000 }

l4000000000120170:
	{ addl	r14,7676,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4.acq	r15,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r15; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001204E0; }

l40000000001201A0:
	{ ld4.acq	r14,[r38]; nop.m	0x0; adds	r38,0x0,r0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000001204A0; }

l40000000001201C0:
	{ adds	r8,0x0,r38; mov	pr,r63,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r60; }
	{ nop.m	0x0; mov.spnt	b0,r59,40000000001201D0; nop.i	0x0 }
	{ adds	r12,0x0,r61; nop.m	0x0; br.ret	b0; }

l40000000001201F0:
	{ adds	r64,0x0,r33; adds	r37,0x0,r0; nop.i	0x0 }
	{ addl	r41,1,r0; adds	r36,0x0,r0; br.call.sptk.many	b0,fn400000000011EC00; }
	{ adds	r1,0x0,r62; nop.m	0x0; cmp4.lt	p07,p06,r8,r0 }
	{ addl	r64,1,r0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000120420; }

l4000000000120230:
	{ adds	r12,0xFFFFFFFFFFFFFFE0,r12; adds	r35,0x10,r12; nop.i	0x0; }
	{ st8	[r0],r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B340; }
	{ adds	r14,0x8,r35; nop.m	0x0; adds	r1,0x0,r62 }
	{ cmp.eq	p06,p07,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000120850; }

l4000000000120270:
	{ st1	[r0],r8; st8	[r8],r14; nop.i	0x0 }

l4000000000120280:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r37; (p06) br.cond.dptk.few	40000000001200C0 }

l4000000000120290:
	{ adds	r64,0x1,r41; addp4	r64,r64,r0; nop.i	0x0; }
	{ shladd	r64,r64,0x3,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B340; }
	{ adds	r17,0xFFFFFFFFFFFFFFFF,r41; cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r62 }
	{ adds	r14,0x0,r8; adds	r15,0x0,r35; (p06) br.cond.spnt.few	40000000001200C0; }

l40000000001202D0:
	{ addp4	r17,r17,r0; nop.m	0x0; cmp4.eq	p07,p06,0x0,r41 }
	{ adds	r38,0x0,r8; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000120330; }

l40000000001202F0:
	{ (p06) shladd	r17,r17,0x3,r8; nop.i	0x0; (p06) adds	r17,0x8,r17; }

l40000000001202F6:
	{ adds	r0,0xFFFFFFFFFFFFE000,r1; (p08) nop; nop }

l4000000000120300:
	{ adds	r16,0x8,r15; ld8	r16,[r16]; nop.i	0x0; }
	{ nop.m	0x0; st8	[r14],r8,8; nop.i	0x0; }
	{ ld8	r15,[r15]; cmp.eq	p07,p06,r17,r14; (p06) br.cond.dptk.few	4000000000120300; }

l4000000000120330:
	{ addp4	r41,r41,r0; cmp.eq	p07,p06,0x0,r36; cmp.eq	p08,p09,0x0,r35; }
	{ nop.m	0x0; shladd	r41,r41,0x3,r38; nop.i	0x0; }
	{ st8	[r0],r41; (p07) br.cond.dpnt.few	40000000001201C0; (p08) br.cond.dpnt.few	40000000001201C0; }

l400000000012035C:
	{ Invalid; cmp.lt	p00,p00,r32,r0; nop }

l4000000000120360:
	{ nop.m	0x0; cmp.eq	p06,p07,r36,r35; (p06) br.cond.dpnt.few	40000000001203C0; }

l4000000000120370:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000120380:
	{ ld8	r37,[r35]; adds	r64,0x0,r35; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r35,0x0,r37; nop.m	0x0; cmp.eq	p07,p06,0x0,r37 }
	{ adds	r1,0x0,r62; nop.m	0x0; (p07) br.cond.spnt.few	40000000001201C0; }

l40000000001203B0:
	{ nop.m	0x0; cmp.eq	p06,p07,r36,r35; (p07) br.cond.dptk.few	4000000000120380 }

l40000000001203C0:
	{ adds	r64,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r8,0x0,r38; adds	r1,0x0,r62; mov	pr,r63,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r60; mov.spnt	b0,r59,40000000001203E0 }
	{ nop.m	0x0; adds	r12,0x0,r61; br.ret	b0; }

l4000000000120400:
	{ adds	r64,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,fn400000000011EC00; }
	{ adds	r1,0x0,r62; cmp4.lt	p07,p06,r8,r0; (p06) br.cond.dptk.few	4000000000120A50; }

l4000000000120420:
	{ addl	r38,9284,r1; nop.m	0x0; nop.i	0x0; }
	{ adds	r8,0x0,r38; mov	pr,r63,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r60; }
	{ nop.m	0x0; mov.spnt	b0,r59,4000000000120440; nop.i	0x0 }
	{ adds	r12,0x0,r61; nop.m	0x0; br.ret	b0 }

l4000000000120460:
	{ nop.m	0x0; adds	r14,0x8,r35; nop.i	0x0; }
	{ ld8	r64,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r62; nop.i	0x0 }
	{ ld8	r35,[r35]; nop.m	0x0; br.cond.sptk.few	40000000001200E0 }

l40000000001204A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,throw_to_top_level; }
	{ adds	r8,0x0,r38; adds	r1,0x0,r62; mov	pr,r63,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r60; mov.spnt	b0,r59,40000000001204C0 }
	{ nop.m	0x0; adds	r12,0x0,r61; br.ret	b0; }

l40000000001204E0:
	{ ld4.acq	r64,[r14]; nop.i	0x0; br.call.sptk.many	b0,termsig_handler; }
	{ ld4.acq	r14,[r38]; adds	r1,0x0,r62; adds	r38,0x0,r0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000001201C0 }

l4000000000120510:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000001204A0; }

l4000000000120520:
	{ cmp.eq	p07,p06,0x0,r37; adds	r64,0x0,r37; (p07) br.cond.dpnt.few	4000000000120CF0; }

l4000000000120530:
	{ ld8	r40,[r37]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r62; adds	r37,0x0,r40; br.cond.sptk.few	4000000000120520; }

l4000000000120550:
	{ adds	r37,0x13,r37; adds	r64,0x0,r46; adds	r65,0x0,r0 }
	{ st8	[r0],r61; st8	[r0],r46; adds	r66,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,xdupmbstowcs; }
	{ cmp.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r8; adds	r1,0x0,r62; adds	r64,0x0,r61 }
	{ adds	r65,0x0,r0; adds	r66,0x0,r37; (p06) br.cond.dpnt.few	40000000001206C0; }

l40000000001205A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,xdupmbstowcs; }
	{ adds	r1,0x0,r62; cmp.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r8; (p06) br.cond.dpnt.few	40000000001206C0; }

l40000000001205C0:
	{ nop.m	0x0; ld4	r15,[r49]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	4000000000120870 }

l40000000001205E0:
	{ ld8	r64,[r46]; ld4	r15,[r64]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x2E,r15; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000120640; }

l4000000000120600:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5C,r15; nop.i	0x0 }
	{ ld8	r15,[r61]; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000120BE0; }

l4000000000120620:
	{ nop.m	0x0; ld4	r16,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r16; (p07) br.cond.dpnt.few	4000000000120C30 }

l4000000000120640:
	{ nop.m	0x0; adds	r42,0x0,r0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r62; nop.m	0x0; nop.i	0x0 }

l4000000000120660:
	{ nop.m	0x0; ld8	r64,[r61]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r64; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001206A0; }

l4000000000120680:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r62; nop.m	0x0; nop.i	0x0 }

l40000000001206A0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r42; (p06) br.cond.dptk.few	400000000011FC60 }

l40000000001206B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011FD20 }

l40000000001206C0:
	{ adds	r64,0x0,r32; adds	r65,0x0,r37; br.call.sptk.many	b0,fn400000000011F3C0; }
	{ adds	r1,0x0,r62; nop.m	0x0; adds	r42,0x0,r8 }
	{ ld8	r64,[r46]; nop.m	0x0; nop.i	0x0; }

l40000000001206F0:
	{ cmp.eq	p06,p07,0x0,r64; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000120660; }

l4000000000120700:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r62; br.cond.sptk.few	4000000000120660 }

l4000000000120720:
	{ cmp.eq	p06,p07,r58,r8; adds	r64,0x0,r8; (p06) br.cond.dpnt.few	4000000000120760; }

l4000000000120730:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r62; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000120760:
	{ addl	r64,16,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B340; }
	{ cmp.eq	p06,p07,0x0,r36; nop.m	0x0; adds	r37,0x0,r8 }
	{ adds	r1,0x0,r62; nop.m	0x0; adds	r64,0x0,r47; }
	{ (p06) adds	r36,0x0,r8; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }

l4000000000120796:
	{ break.m	0x4000; Invalid; nop }
	{ Invalid; (p21) nop; nop.b	0x2A010 }
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ Invalid; (p32) nop; (p32) nop.b	0x2A010 }
	{ Invalid; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFDC4066; nop; nop }

l40000000001207F0:
	{ st8	[r17],r8,8; adds	r41,0x1,r41; adds	r35,0x0,r37; }
	{ st8	[r8],r17; br.call.sptk.many	b0,fn400000000001A7C0; nop.b	0x0; }
	{ adds	r1,0x0,r62; nop.m	0x0; nop.i	0x0 }

l4000000000120820:
	{ adds	r64,0x0,r47; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r62; br.cond.sptk.few	400000000011FC60 }

l4000000000120840:
	{ nop.m	0x0; addl	r37,1,r0; br.cond.sptk.few	400000000011FFA0; }

l4000000000120850:
	{ addl	r37,1,r0; nop.m	0x0; adds	r41,0x0,r0 }
	{ adds	r35,0x0,r0; adds	r36,0x0,r0; br.cond.sptk.few	4000000000120280 }

l4000000000120870:
	{ ld8	r14,[r61]; ld8	r64,[r46]; nop.i	0x0; }
	{ ld4	r14,[r14]; cmp4.eq	p06,p07,0x2E,r14; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r42,0x0,r0; (p07) br.cond.dptk.few	40000000001206F0 }

l400000000012089C:
	{ (p51) nop; cmp.eq	p00,p00,r32,r0; Invalid }

l40000000001208A0:
	{ nop.m	0x0; ld4	r15,[r64]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x2E,r15; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000120640; }

l40000000001208C0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5C,r15; (p07) br.cond.dpnt.few	4000000000120CA0 }

l40000000001208D0:
	{ addl	r42,1,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r62; br.cond.sptk.few	4000000000120660 }

l40000000001208F0:
	{ nop.m	0x0; (p25) br.cond.dpnt.few	4000000000120820; (p22) br.cond.dptk.few	4000000000120760; }

l40000000001208FC:
	{ Invalid; zxt1	r32,r64; break.b	0x1000 }

l4000000000120900:
	{ adds	r64,0x0,r37; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r62; nop.m	0x0; adds	r64,0x0,r37 }
	{ adds	r65,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fnx_fromfs; }
	{ adds	r1,0x0,r62; adds	r64,0x0,r32; nop.i	0x0 }
	{ adds	r65,0x0,r8; adds	r66,0x0,r48; br.call.sptk.many	b0,strmatch; }
	{ cmp4.eq	p06,p07,0x1,r8; adds	r1,0x0,r62; (p06) br.cond.dpnt.few	400000000011FC60; }

l4000000000120960:
	{ cmp4.lt	p06,p07,r56,r54; (p07) adds	r12,0xFFFFFFFFFFFFFFE0,r12; (p07) adds	r54,0x10,r54; }

l400000000012096C:
	{ Invalid; Invalid; Invalid }

l4000000000120970:
	{ nop.m	0x0; (p07) adds	r42,0x10,r12; (p07) br.cond.dptk.few	40000000001209B0 }

l400000000012097C:
	{ Invalid; zxt4	r4,r0; break.i	0x1000 }

l4000000000120980:
	{ addl	r64,16,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B340; }
	{ cmp.eq	p06,p07,0x0,r36; adds	r1,0x0,r62; nop.i	0x0 }
	{ adds	r42,0x0,r8; nop.i	0x0; (p06) adds	r36,0x0,r8 }

l40000000001209B0:
	{ adds	r64,0x0,r37; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r62; adds	r64,0x1,r8; br.call.sptk.many	b0,fn400000000001B340; }
	{ cmp.eq	p06,p07,0x0,r42; adds	r14,0x0,r42; nop.i	0x0 }
	{ adds	r1,0x0,r62; adds	r43,0x0,r8; adds	r64,0x0,r37; }
	{ cmp.eq.or.andcm	p06,p07,0x0,r8; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000120840; }

l4000000000120A00:
	{ st8	[r14],r8,8; adds	r41,0x1,r41; adds	r35,0x0,r42; }
	{ st8	[r8],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r62; adds	r64,0x0,r43; nop.i	0x0 }
	{ adds	r65,0x0,r37; adds	r66,0x1,r8; br.call.sptk.many	b0,fn400000000001A7C0; }
	{ nop.m	0x0; adds	r1,0x0,r62; br.cond.sptk.few	400000000011FC60 }

l4000000000120A50:
	{ adds	r64,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ add	r64,r8,r35; adds	r1,0x0,r62; adds	r37,0x0,r8; }
	{ nop.m	0x0; adds	r64,0x2,r64; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r64,r64; br.call.sptk.many	b0,fn400000000001B340; }
	{ adds	r64,0x1,r35; adds	r1,0x0,r62; adds	r36,0x0,r8; }
	{ nop.m	0x0; sxt4	r64,r64; br.call.sptk.many	b0,fn400000000001B340; }
	{ cmp.eq	p06,p07,0x0,r36; adds	r38,0x0,r8; adds	r1,0x0,r62; }
	{ nop.m	0x0; cmp.eq.or.andcm	p06,p07,0x0,r8; (p06) br.cond.dptk.few	4000000000120850 }

l4000000000120AD0:
	{ adds	r65,0x0,r32; nop.m	0x0; adds	r64,0x0,r8 }
	{ addl	r41,1,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r62; adds	r64,0x0,r38; br.call.sptk.many	b0,fn400000000011F5C0; }
	{ adds	r1,0x0,r62; nop.m	0x0; adds	r64,0x0,r36 }
	{ adds	r65,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; adds	r64,0x1,r37; sxt4	r14,r37 }
	{ addl	r15,47,r0; adds	r1,0x0,r62; adds	r65,0x0,r38; }
	{ add	r14,r36,r14; sxt4	r64,r64; adds	r37,0x0,r0; }
	{ st1	[r15],r14; add	r64,r36,r64; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r65,0x0,r36; adds	r1,0x0,r62; nop.i	0x0 }
	{ adds	r66,0xFFFFFFFFFFFFFF70,r61; addl	r64,1,r0; br.call.sptk.many	b0,fn400000000001C0A0; }
	{ cmp4.lt	p06,p07,r8,r0; adds	r1,0x0,r62; nop.i	0x0 }
	{ adds	r64,0x0,r36; adds	r36,0x0,r0; (p06) br.cond.dpnt.few	4000000000120D20; }

l4000000000120BA0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r12,0xFFFFFFFFFFFFFFE0,r12; adds	r1,0x0,r62; adds	r35,0x10,r12; }
	{ adds	r14,0x0,r35; st8	[r14],r8,8; nop.i	0x0; }
	{ st8	[r38],r14; nop.i	0x0; br.cond.sptk.few	4000000000120280 }

l4000000000120BE0:
	{ adds	r15,0x4,r64; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2E,r15; nop.i	0x0 }
	{ ld8	r15,[r61]; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000120640; }

l4000000000120C10:
	{ nop.m	0x0; ld4	r16,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r16; (p06) br.cond.dptk.few	4000000000120640 }

l4000000000120C30:
	{ adds	r16,0x4,r15; ld4	r16,[r16]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r16; (p06) br.cond.dptk.few	40000000001208D0; }

l4000000000120C50:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r16; (p06) br.cond.dptk.few	4000000000120640 }

l4000000000120C60:
	{ adds	r15,0x8,r15; ld4	r42,[r15]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r42; (p06) adds	r42,0x0,r0; nop.i	0x0; }

l4000000000120C7C:
	{ getf.s	r0,f1; zxt4	r0,r0; break.i	0x1000 }

l4000000000120C86:
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; nop; (p48) nop.b	0x40083 }

l4000000000120CA0:
	{ adds	r15,0x4,r64; ld4	r42,[r15]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x2E,r42; (p06) addl	r42,1,r0; nop.i	0x0; }

l4000000000120CBC:
	{ getf.s	r0,f1; zxt1	r0,r64; break.i	0x1000 }

l4000000000120CC6:
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; nop; break.b	0x80000 }

l4000000000120CE0:
	{ nop.m	0x0; adds	r37,0x0,r0; br.cond.sptk.few	400000000011FFA0; }

l4000000000120CF0:
	{ adds	r64,0x0,r51; addl	r37,1,r0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r62; adds	r64,0x0,r47; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r62; br.cond.sptk.few	400000000011FFA0 }

l4000000000120D20:
	{ adds	r41,0x0,r0; nop.m	0x0; adds	r35,0x0,r0 }
	{ adds	r36,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r62; adds	r64,0x0,r38; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r62; br.cond.sptk.few	4000000000120280; }
4000000000120D60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000120D70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; glob_filename: 4000000000120D80
;;   Called from:
;;     40000000000B369C (in shell_glob_filename)
;;     40000000000E5B5C (in gen_compspec_completions)
;;     400000000012109C (in glob_filename)
;;     400000000012189C (in glob_filename)
glob_filename proc
	{ alloc	r51,ar.pfs,0x19,0x0,0x16; mov	r53,pr; adds	r52,0x0,r1; }
	{ nop.m	0x0; mov	r50,b2; nop.i	0x0 }
	{ addl	r54,8,r0; addl	r45,1,r0; br.call.sptk.many	b0,fn400000000001B340; }
	{ cmp.eq	p07,p06,0x0,r8; adds	r1,0x0,r52; adds	r35,0x0,r8 }
	{ addl	r55,47,r0; adds	r54,0x0,r32; (p07) br.cond.dpnt.few	40000000001216A0; }

l4000000000120DD0:
	{ st8	[r0],r8; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BEA0; }
	{ sub	r34,r8,r32; cmp.eq	p06,p07,0x0,r8; nop.i	0x0 }
	{ adds	r1,0x0,r52; adds	r38,0x0,r8; (p06) br.cond.dpnt.few	40000000001218D0; }

l4000000000120E00:
	{ adds	r54,0x2,r34; adds	r34,0x1,r34; adds	r38,0x1,r38; }
	{ addp4	r54,r54,r0; addp4	r36,r34,r0; br.call.sptk.many	b0,fn400000000001B340; }
	{ adds	r42,0x0,r8; cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r52 }
	{ adds	r56,0x0,r36; adds	r54,0x0,r8; (p06) br.cond.dpnt.few	40000000001216A0; }

l4000000000120E40:
	{ adds	r55,0x0,r32; add	r36,r42,r36; br.call.sptk.many	b0,fn400000000001A7C0; }
	{ adds	r1,0x0,r52; st1	[r0],r36; adds	r54,0x0,r42 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,glob_pattern_p; }
	{ adds	r1,0x0,r52; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	4000000000121020 }

l4000000000120E80:
	{ ld1	r14,[r38]; nop.m	0x0; cmp4.eq	p16,p17,0x0,r34 }
	{ adds	r54,0x0,r35; and	r36,0xFFFFFFFFFFFFFFFE,r33; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	4000000000121920; (p17) br.cond.dpnt.few	40000000001219F0; }

l4000000000120EAC:
	{ Invalid; break.i	0x1000; break.b	0x1000 }

l4000000000120EB0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ addl	r14,256,r0; adds	r1,0x0,r52; tbit.z	p06,p07,r33,0xA; }
	{ nop.m	0x0; or	r36,r14,r36; (p06) br.cond.dptk.few	4000000000120F30 }

l4000000000120EE0:
	{ ld1	r14,[r38]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2A,r14; (p06) br.cond.dptk.few	4000000000120F30 }

l4000000000120F00:
	{ adds	r14,0x1,r38; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2A,r14; (p07) br.cond.dpnt.few	4000000000121AC0 }

l4000000000120F30:
	{ nop.m	0x0; adds	r55,0x0,r42; (p16) br.cond.dpnt.few	40000000001216D0 }

l4000000000120F40:
	{ adds	r54,0x0,r38; adds	r56,0x0,r36; br.call.sptk.many	b0,glob_vector; }
	{ adds	r1,0x0,r52; cmp.eq	p06,p07,0x0,r8; nop.i	0x0 }
	{ adds	r55,0x0,r8; adds	r56,0x0,r33; (p06) br.cond.dpnt.few	4000000000121A30; }

l4000000000120F70:
	{ addl	r14,9284,r1; nop.m	0x0; nop.i	0x0; }
	{ cmp.eq	p07,p06,r14,r8; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000121A30; }

l4000000000120F90:
	{ nop.m	0x0; tbit.z	p06,p07,r36,0x4; (p07) addl	r54,-6188,r1; }

l4000000000120FA0:
	{ nop.m	0x0; (p06) adds	r54,0x0,r42; nop.i	0x0; }

l4000000000120FAC:
	{ cmp4.eq.and	p00,p49,r1,r0; Invalid; break.i	0x1000 }

l4000000000120FB6:
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; (p17) nop; break.b	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFDE4AA6; nop; break.i	0x80000 }

l4000000000120FE0:
	{ nop.m	0x0; adds	r54,0x0,r42; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r52; nop.m	0x0; nop.i	0x0 }

l4000000000121000:
	{ adds	r8,0x0,r35; mov	pr,r53,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r51; }
	{ nop.m	0x0; mov.spnt	b0,r50,4000000000121010; br.ret	b0 }

l4000000000121020:
	{ and	r14,0xFFFFFFFFFFFFFFFE,r33; nop.m	0x0; tnat.z	p16,p17,r33; }
	{ nop.m	0x0; adds	r55,0x0,r14; (p16) br.cond.dptk.few	4000000000121060 }

l4000000000121040:
	{ ld1	r15,[r42]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2A,r15; (p07) br.cond.dpnt.few	40000000001217F0 }

l4000000000121060:
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r34; adds	r54,0x0,r42; addp4	r14,r14,r0; }
	{ add	r14,r42,r14; ld1	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; cmp4.eq	p07,p06,0x2F,r15; }
	{ (p07) st1	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,glob_filename; }

l4000000000121096:
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; (p20) nop; break.b	0x80000 }
	{ (p03) chk.a.clr	f0,3FFFFFFFFFDE4B86; nop; nop }

l40000000001210C0:
	{ addl	r44,9284,r1; addl	r43,-530,r0; cmp.eq	p06,p07,0x0,r41 }
	{ addl	r14,528,r0; adds	r40,0x0,r41; (p06) br.cond.dpnt.few	4000000000121590; }

l40000000001210E0:
	{ nop.m	0x0; and	r43,r43,r33; adds	r39,0x0,r0 }
	{ addl	r36,1,r0; adds	r46,0x1,r38; adds	r48,0x2,r38; }
	{ cmp.eq	p07,p06,r44,r41; nop.m	0x0; addl	r47,256,r0 }
	{ or	r49,r14,r43; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000121B60; }

l4000000000121120:
	{ nop.m	0x0; ld8	r55,[r41]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r55; (p07) br.cond.dpnt.few	4000000000121BA0; }

l4000000000121140:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dptk.few	4000000000121170 }

l4000000000121150:
	{ ld1	r14,[r38]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2A,r14; (p07) br.cond.dpnt.few	4000000000121540 }

l4000000000121170:
	{ adds	r34,0x0,r43; nop.m	0x0; nop.i	0x0 }

l4000000000121180:
	{ ld1	r14,[r55]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000001211D0 }

l40000000001211A0:
	{ ld1	r14,[r38]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) addl	r55,-6180,r1 }

l40000000001211C0:
	{ (p07) or	r34,r47,r34; (p07) ld8	r55,[r55]; nop.i	0x0 }

l40000000001211C6:
	{ (p27) fwb; nop; (p32) nop.b	0x2600D; }

l40000000001211CC:
	{ cmp.lt	p00,p17,r1,r0; zxt1	r64,r64; zxt1	r64,r64 }

l40000000001211D0:
	{ adds	r54,0x0,r38; adds	r56,0x0,r34; br.call.sptk.many	b0,glob_vector; }

l40000000001211D2:
	{ (p32) chk.a.nc	f9,3FFFFFFFFF1295D2; Invalid; (p17) nop; }

l40000000001211D6:
	{ Invalid; (p32) nop; (p32) nop }

l40000000001211D8:
	{ (p04) nop; (p63) nop; (p32) break.i	0x1C838 }

l40000000001211DE:
	{ Invalid; Invalid; Invalid }

l40000000001211E4:
	{ Invalid; Invalid; Invalid }

l40000000001211E8:
	{ (p16) add	r0,r0,r16; (p06) mov	pr,0x2819840; (p32) break.i	0x10800 }

l40000000001211EE:
	{ (p32) cmpxchg1.acq	r48,[r20],r6; break.i	0x210; (p04) mov	pr,r48,0x4000; }

l40000000001211F4:
	{ (p08) break.m	0x100004; nop.i	0xA0030; (p06) nop }

l40000000001211F8:
	{ (p16) chk.a.nc	f0,3FFFFFFFFF921DF8; nop; (p33) break.i	0x1C038 }

l40000000001211FE:
	{ (p24) ld4.acq	r40,[r24]; (p28) break.i	0x380; (p04) chk.s.i	r48,4000000000F211FE }

l4000000000121208:
	{ (p16) chk.a.clr	f0,4000000000921E08; break.i	0x11430; dep	r8,r0,r0,62,9 }

l400000000012120E:
	{ (p24) break.m	0x228; (p04) nop; Invalid }

l400000000012121E:
	{ (p24) nop; (p01) break.i	0x100; Invalid }

l4000000000121228:
	{ (p16) cmp.lt	p00,p01,r0,r96; (p01) break.i	0x10005; tnat.z	p08,p28,r0 }

l400000000012122E:
	{ (p02) break.m	0x200; (p04) nop; (p24) nop }

l4000000000121234:
	{ nop; (p12) nop.i	0x9003F; (p06) tbit.z.unc	p02,p00,r54,0x0; }
	{ break.m	0x100002; Invalid; Invalid }
	{ (p08) break.m	0x100004; nop; (p49) nop }
	{ (p08) break.m	0x100004; mov	pr,r4,0x8000; (p08) break.i	0x4C }
	{ cmp4.lt	p00,p08,r56,r0; break.i	0x100002; nop; }
	{ Invalid; Invalid; Invalid }
	{ break.m	0x100000; break.i	0x100000; nop; }
	{ (p08) ld1	r4,[r56]; break.i	0x100004; dep	r88,r0,r15,47,16 }
	{ cmp.lt	p04,p60,r60,r0; break.b	0x100002; break.b	0x80 }
	{ nop; (p08) nop; (p21) dep	r26,r0,r14,31,15; }
	{ Invalid; (p08) dep	r4,r92,r57,63,1; Invalid }
	{ break.m	0x100004; Invalid; nop }
	{ (p08) break.m	0x100004; nop; (p08) nop }
	{ (p08) break.m	0x100004; nop.i	0x20030; (p06) dep	r74,r0,r15,47,1 }
	{ break.m	0x100002; Invalid; (p08) break.b	0x8C }
	{ nop; (p08) break.i	0x70037; (p06) break.i	0x42; }
	{ break.m	0x100000; break.i	0x100000; nop; }
	{ Invalid; Invalid; Invalid }
	{ nop; addl	r4,1132100,r0; zxt1	r92,r16 }
	{ cmp.eq.and	p04,p04,r0,r60; (p12) addl	r2,1066044,r0; break.i	0x4C }
	{ cmp.lt	p00,p60,r60,r0; break.i	0x100002; break.i	0x88; }
	{ nop; (p08) nop; (p21) nop; }
	{ Invalid; Invalid; Invalid }
	{ (p08) ld1	r4,[r60]; Invalid; (p08) dep	r84,r0,r15,39,16 }
	{ cmp.lt	p04,p60,r0,r0; (p12) break.b	0x100002; break.b	0xB8 }
	{ break.m	0x20031; (p06) cmp4.eq.or	p02,p10,0xFFFFFFFFFFFFFF80,r10; (p49) nop }
	{ (p08) break.m	0x100004; break.i	0x100000; dep	r88,r0,r39,7,2 }
	{ (p08) cmpxchg1.acq	r4,[r29],r32; break.i	0x100004; extr.u	r88,r40,0,41 }
	{ cmp4.lt	p04,p32,r92,r1; break.b	0x100002; break.b	0x80 }
	{ nop; (p08) nop; (p21) extr.u	r74,r54,0,1; }
	{ break.m	0x100002; break.m	0x4400; (p08) break.b	0x8C }
	{ nop; (p08) break.i	0x60037; (p06) break.i	0x42; }
	{ break.m	0x100000; break.i	0x100000; dep	r8,r1,r34,47,2; }
	{ (p08) break.m	0x100004; cmp4.eq.or	p00,p09,0xFFFFFFFFFFFFFF80,r106; Invalid }
	{ Invalid; (p08) addl	r4,938552,r0; break.i	0x4C }
	{ cmp.lt	p00,p56,r88,r1; break.i	0x100002; break.i	0x80; }
	{ nop; (p08) nop; (p21) extr.u	r10,r54,0,1; }
	{ (p08) break.m	0x100004; cmp4.eq.or	p00,p09,0xFFFFFFFFFFFFFF80,r90; (p49) dep	r74,r0,r8,39,1 }
	{ Invalid; (p08) nop; (p22) break.i	0x8 }
	{ ld1.c.clr	r0,[r76],128; (p01) break.i	0x100000; break.i	0x80; }
	{ rum	0x120000; (p14) break.i	0x108800; Invalid; }
	{ break.m	0x100002; nop; break.i	0x80 }
	{ nop; (p12) nop; (p21) nop; }
	{ break.m	0x100002; nop; break.i	0x88 }
	{ nop; (p12) nop; (p21) nop; }
	{ (p08) break.m	0x100004; break.i	0x100000; break.i	0x48 }
	{ cmp4.lt	p00,p08,r56,r0; break.i	0x100002; nop; }
	{ Invalid; Invalid; Invalid }
	{ break.m	0x100000; nop; Invalid; }

l4000000000121540:
	{ ld1	r14,[r46]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2A,r14; (p06) br.cond.dptk.few	4000000000121170 }

l4000000000121560:
	{ ld1	r34,[r48]; nop.m	0x0; sxt1	r34,r34; }
	{ cmp4.eq	p07,p06,0x0,r34; (p06) adds	r34,0x0,r43; nop.i	0x0; }

l400000000012157C:
	{ Invalid; dep	r0,r32,r0,49,1; zxt1	r32,r64 }

l400000000012158C:
	{ (p32) cmp.lt.unc	p63,p09,r63,r36; Invalid; dep	r0,r32,r0,63,1 }

l4000000000121590:
	{ ld8	r54,[r35]; nop.m	0x0; adds	r34,0x0,r0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r54; (p07) br.cond.spnt.few	4000000000121600; }

l40000000001215B0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000001215C0:
	{ adds	r34,0x1,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ addp4	r14,r34,r0; adds	r1,0x0,r52; shladd	r14,r14,0x3,r35; }
	{ nop.m	0x0; ld8	r54,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r54; (p06) br.cond.dptk.few	40000000001215C0 }

l4000000000121600:
	{ nop.m	0x0; adds	r54,0x0,r35; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r52; nop.m	0x0; nop.i	0x0 }
	{ cmp.eq	p07,p06,0x0,r42; (p06) addl	r14,1,r0; nop.i	0x0; }

l400000000012162C:
	{ cmp4.eq.and	p00,p43,r1,r0; (p01) nop; (p21) cmp.lt.unc	p11,p16,r3,r3 }

l4000000000121636:
	{ Invalid; (p07) nop; nop }
	{ chk.a.nc	f0,3FFFFFFFFF121E46; nop; break.i	0x80000 }

l4000000000121650:
	{ nop.m	0x0; ld4.acq	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p07) br.cond.dpnt.few	4000000000121750 }

l4000000000121670:
	{ addl	r14,7684,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4.acq	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	4000000000121710; }

l40000000001216A0:
	{ adds	r35,0x0,r0; nop.m	0x0; mov	pr,r53,0xFFFFFFFFFFFFFFFE; }
	{ adds	r8,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r51; }
	{ nop.m	0x0; mov.spnt	b0,r50,40000000001216C0; br.ret	b0 }

l40000000001216D0:
	{ nop.m	0x0; addl	r55,-6180,r1; nop.i	0x0; }
	{ ld8	r55,[r55]; nop.i	0x0; br.cond.sptk.few	4000000000120F40 }

l40000000001216F0:
	{ adds	r54,0x0,r42; adds	r42,0x0,r0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r52; br.cond.sptk.few	40000000001210C0 }

l4000000000121710:
	{ adds	r35,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,throw_to_top_level; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r52; mov	pr,r53,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r51; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r50,4000000000121740; br.ret	b0; }

l4000000000121750:
	{ ld4.acq	r54,[r14]; nop.i	0x0; br.call.sptk.many	b0,termsig_handler; }
	{ adds	r1,0x0,r52; addl	r14,7684,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4.acq	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000001216A0 }

l4000000000121790:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000121710 }

l40000000001217A0:
	{ adds	r54,0x0,r42; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r52; addl	r14,7676,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4.acq	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	4000000000121670 }

l40000000001217E0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000121750 }

l40000000001217F0:
	{ adds	r15,0x1,r42; ld1	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2A,r15; (p06) br.cond.dptk.few	4000000000121060 }

l4000000000121820:
	{ adds	r15,0x2,r42; nop.m	0x0; adds	r54,0x0,r42; }
	{ ld1	r15,[r15]; nop.m	0x0; sxt1	r15,r15; }
	{ cmp4.eq	p06,p07,0x2F,r15; cmp4.eq.or.andcm	p06,p07,0x0,r15; nop.i	0x0; }
	{ (p06) addl	r55,528,r0; (p06) or	r55,r55,r14; adds	r14,0xFFFFFFFFFFFFFFFF,r34; }

l4000000000121856:
	{ Invalid; (p07) nop; (p32) nop; }

l400000000012185C:
	{ (p63) cmp.lt	p34,p11,r63,r70; (p33) cmp.lt	p03,p16,r0,r2; (p33) epc; }
	{ nop; cmp.eq	p00,p00,r32,r0; Invalid }
	{ Invalid; cmp.eq	p00,p00,r32,r0; (p01) cmp.eq.unc	p32,p00,r3,r5 }
	{ Invalid; Invalid; break.b	0x1000 }

l4000000000121896:
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; (p20) nop; break.b	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFDE5386; nop; break.i	0x80000 }

l40000000001218C0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000001216F0; }

l40000000001218D0:
	{ addl	r42,-6188,r1; adds	r38,0x0,r32; adds	r45,0x0,r0 }
	{ adds	r34,0x0,r0; ld8	r42,[r42]; nop.i	0x0; }
	{ adds	r54,0x0,r42; nop.i	0x0; br.call.sptk.many	b0,glob_pattern_p; }
	{ adds	r1,0x0,r52; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	4000000000120E80 }

l4000000000121910:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000121020 }

l4000000000121920:
	{ adds	r34,0x1,r34; nop.m	0x0; adds	r54,0x0,r35 }
	{ addl	r55,16,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AD60; }
	{ cmp.eq	p06,p07,0x0,r8; addp4	r34,r34,r0; nop.i	0x0 }
	{ adds	r35,0x0,r8; adds	r1,0x0,r52; (p06) br.cond.dpnt.few	40000000001216A0; }

l4000000000121960:
	{ adds	r54,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B340; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r52; adds	r54,0x0,r8 }
	{ st8	[r8],r35; adds	r55,0x0,r42; (p06) br.cond.dpnt.few	4000000000121600; }

l4000000000121990:
	{ adds	r56,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ adds	r14,0x8,r35; nop.m	0x0; adds	r1,0x0,r52 }
	{ cmp4.eq	p06,p07,0x0,r45; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000121A90; }

l40000000001219C0:
	{ st8	[r0],r14; nop.m	0x0; nop.i	0x0 }

l40000000001219D0:
	{ adds	r8,0x0,r35; mov	pr,r53,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r51; }
	{ nop.m	0x0; mov.spnt	b0,r50,40000000001219E0; br.ret	b0; }

l40000000001219F0:
	{ adds	r54,0x0,r42; and	r36,0xFFFFFFFFFFFFFFFE,r33; br.call.sptk.many	b0,fn400000000011F5C0; }
	{ adds	r1,0x0,r52; adds	r54,0x0,r35; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r52; tbit.z	p06,p07,r33,0xA; (p06) br.cond.dptk.few	4000000000120F30 }

l4000000000121A20:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000120EE0; }

l4000000000121A30:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r45; nop.i	0x0; }
	{ nop.m	0x0; (p06) adds	r35,0x0,r8; (p06) br.cond.dptk.few	4000000000121000; }

l4000000000121A4C:
	{ (p46) ldfps	f126,f63,[r37]; (p04) cmp.lt	p00,p16,r2,r64; zxt1	r64,r64 }

l4000000000121A50:
	{ adds	r35,0x0,r8; adds	r54,0x0,r42; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r52; mov	pr,r53,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r51; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r50,4000000000121A80; br.ret	b0; }

l4000000000121A90:
	{ adds	r54,0x0,r42; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r14,0x8,r35; nop.m	0x0; adds	r1,0x0,r52; }
	{ st8	[r0],r14; nop.i	0x0; br.cond.sptk.few	40000000001219D0 }

l4000000000121AC0:
	{ adds	r14,0x2,r38; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000120F30; }

l4000000000121AF0:
	{ addl	r15,528,r0; nop.m	0x0; cmp4.eq	p07,p06,0x0,r34; }
	{ nop.m	0x0; or	r15,r15,r36; (p06) br.cond.dptk.few	4000000000121C00; }

l4000000000121B10:
	{ adds	r14,0x0,r15; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; tbit.z	p07,p06,r33,0x4; addl	r55,-6180,r1; }
	{ (p07) addl	r14,-513,r0; ld8	r55,[r55]; nop.i	0x0; }

l4000000000121B36:
	{ (p27) fwb; cmp4.ltu	p00,p00,0x0,r1; Invalid }

l4000000000121B46:
	{ Invalid; nop; break.i	0x80000; }

l4000000000121B4C:
	{ invala; add	r0,r32,r0; zxt1	r64,r64 }
	{ (p31) cmp.lt.unc	p62,p17,r63,r36; (p06) nop; (p04) epc }

l4000000000121B60:
	{ adds	r54,0x0,r35; adds	r35,0x0,r41; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r52; mov	pr,r53,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r51; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r50,4000000000121B90; br.ret	b0; }

l4000000000121BA0:
	{ adds	r54,0x0,r41; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r52; nop.m	0x0; adds	r54,0x0,r35 }
	{ adds	r35,0x0,r44; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r52; mov	pr,r53,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r51; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r50,4000000000121BF0; br.ret	b0 }

l4000000000121C00:
	{ adds	r36,0x0,r15; adds	r55,0x0,r42; br.cond.sptk.few	4000000000120F40; }
4000000000121C10 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
4000000000121C20 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
4000000000121C30 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; strmatch: 4000000000121C40
;;   Called from:
;;     400000000008614C (in fn4000000000085EA6)
;;     400000000008634C (in fn4000000000085EA6)
;;     40000000000865AC (in fn4000000000085EA6)
;;     400000000008664C (in fn4000000000085EA6)
;;     40000000000B257C (in fn40000000000B24C0)
;;     40000000000B61AC (in binary_test)
;;     40000000000B63CC (in binary_test)
;;     40000000000C8BCC (in check_add_history)
;;     40000000000C8D8C (in check_add_history)
;;     40000000000C90EC (in check_add_history)
;;     40000000000D90EC (in find_string_in_alist)
;;     40000000000D93AC (in find_index_in_alist)
;;     40000000000E45FC (in filter_stringlist)
;;     40000000000FC65C (in help_builtin)
;;     400000000012094C (in glob_vector)
;;     400000000012094C (in glob_vector)
;;     4000000000135F7C (in sh_modcase)
;;     400000000013650C (in sh_modcase)
;;     400000000013683C (in sh_modcase)
strmatch proc
	{ alloc	r36,ar.pfs,0x9,0x0,0x6; nop.m	0x0; mov	r35,b3 }
	{ cmp.eq	p06,p07,0x0,r32; nop.m	0x0; adds	r37,0x0,r1; }
	{ addl	r8,1,r0; cmp.eq.or.andcm	p06,p07,0x0,r33; mov.i	ar.pfs,r36 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000121C90; }

l4000000000121C80:
	{ nop.m	0x0; mov.spnt	b0,r35,4000000000121C80; br.ret	b0; }

l4000000000121C90:
	{ adds	r38,0x0,r32; nop.m	0x0; adds	r39,0x0,r33 }
	{ adds	r40,0x0,r34; nop.m	0x0; br.call.sptk.many	b0,xstrmatch; }
	{ adds	r1,0x0,r37; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,4000000000121CC0; br.ret	b0; }
4000000000121CD0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000121CE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000121CF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; wcsmatch: 4000000000121D00
wcsmatch proc
	{ alloc	r36,ar.pfs,0x9,0x0,0x6; nop.m	0x0; mov	r35,b3 }
	{ cmp.eq	p06,p07,0x0,r32; nop.m	0x0; adds	r37,0x0,r1; }
	{ addl	r8,1,r0; cmp.eq.or.andcm	p06,p07,0x0,r33; mov.i	ar.pfs,r36 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000121D50; }

l4000000000121D40:
	{ nop.m	0x0; mov.spnt	b0,r35,4000000000121D40; br.ret	b0; }

l4000000000121D50:
	{ adds	r38,0x0,r32; nop.m	0x0; adds	r39,0x0,r33 }
	{ adds	r40,0x0,r34; nop.m	0x0; br.call.sptk.many	b0,internal_wstrmatch; }
	{ adds	r1,0x0,r37; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,4000000000121D80; br.ret	b0; }
4000000000121D90 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
4000000000121DA0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
4000000000121DB0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; fn4000000000121DC0: 4000000000121DC0
;;   Called from:
;;     40000000001234EC (in fn4000000000122C80)
;;     4000000000124A0C (in fn40000000001249C0)
fn4000000000121DC0 proc
	{ ld1	r14,[r32]; adds	r15,0x0,r0; adds	r18,0x0,r0 }
	{ adds	r19,0x0,r0; cmp.ltu	p09,p08,r32,r33; adds	r8,0x0,r32; }
	{ cmp4.eq	p06,p07,0x0,r14; adds	r16,0x0,r0; nop.i	0x0 }
	{ adds	r17,0x0,r0; cmp4.eq	p10,p11,0x7C,r34; (p06) br.cond.dpnt.few	4000000000121E70; }

l4000000000121E00:
	{ nop.m	0x0; nop.i	0x0; (p08) br.cond.dpnt.few	4000000000122160; }

l4000000000121E10:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	4000000000121F10; }

l4000000000121E20:
	{ cmp4.eq	p06,p07,0x5B,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000122030; }

l4000000000121E30:
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x5B,r14; (p06) br.cond.dptk.few	4000000000121E80; }

l4000000000121E40:
	{ cmp4.eq	p06,p07,0x28,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001220D0; }

l4000000000121E50:
	{ cmp4.eq	p06,p07,0x29,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000122080; }

l4000000000121E60:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	4000000000121EB0 }

l4000000000121E70:
	{ nop.m	0x0; adds	r8,0x0,r0; br.ret	b0; }

l4000000000121E80:
	{ cmp4.eq	p06,p07,0x5D,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000121FA0; }

l4000000000121E90:
	{ nop.m	0x0; cmp4.ltu	p07,p06,0x5C,r14; (p06) br.cond.dptk.few	4000000000121F80; }

l4000000000121EA0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x7C,r14; (p06) br.cond.dpnt.few	4000000000121F30 }

l4000000000121EB0:
	{ nop.m	0x0; adds	r8,0x1,r8; nop.i	0x0; }
	{ ld1	r14,[r8]; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000121EE0:
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000121E70; }

l4000000000121EF0:
	{ cmp.ltu	p07,p06,r8,r33; nop.i	0x0; (p06) br.ret	b0; }

l4000000000121F00:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p07) br.cond.dptk.few	4000000000121E20 }

l4000000000121F10:
	{ adds	r8,0x1,r8; nop.m	0x0; adds	r15,0x0,r0; }
	{ ld1	r14,[r8]; nop.i	0x0; br.cond.sptk.few	4000000000121EE0; }

l4000000000121F30:
	{ nop.m	0x0; or	r14,r16,r17; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	4000000000121EB0 }

l4000000000121F50:
	{ adds	r8,0x1,r8; nop.m	0x0; adds	r16,0x0,r0 }
	{ adds	r17,0x0,r0; nop.m	0x0; (p10) br.cond.dpnt.few	4000000000122170; }

l4000000000121F70:
	{ ld1	r14,[r8]; nop.i	0x0; br.cond.sptk.few	4000000000121EE0 }

l4000000000121F80:
	{ adds	r8,0x1,r8; nop.m	0x0; addl	r15,1,r0; }
	{ ld1	r14,[r8]; nop.i	0x0; br.cond.sptk.few	4000000000121EE0 }

l4000000000121FA0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r16; (p07) br.cond.dptk.few	4000000000121EB0; }

l4000000000121FB0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r19; (p06) br.cond.dptk.few	4000000000121FF0 }

l4000000000121FC0:
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r8; ld1	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,r14,r19; (p07) adds	r8,0x1,r8; (p07) adds	r19,0x0,r0; }

l4000000000121FDC:
	{ cmp4.eq.and	p00,p48,r0,r66; Invalid; mov	pr,r32,0x0 }

l4000000000121FE0:
	{ (p07) ld1	r14,[r8]; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000121EE0 }

l4000000000121FE6:
	{ chk.a.nc	f0,3FFFFFFFFF1227E6; Invalid; (p48) nop }

l4000000000121FF0:
	{ cmp.eq	p07,p06,r18,r8; nop.i	0x0; (p07) adds	r20,0x1,r8 }

l4000000000122000:
	{ (p06) adds	r8,0x1,r8; (p06) adds	r16,0xFFFFFFFFFFFFFFFF,r16; (p06) adds	r18,0x0,r0; }

l4000000000122006:
	{ (p08) chk.a.clr	r127,3FFFFFFFFF2C1906; (p09) cmp4.eq.or	p00,p02,r0,r0; (p33) cmp.eq.or.andcm	p04,p00,r0,r2; }

l400000000012200C:
	{ getf.exp	r0,f0; (p02) cmp4.eq.and	p00,p48,r2,r64; (p01) mov	pr,r5,0x4000 }

l4000000000122010:
	{ (p07) adds	r18,0x0,r8; (p07) ld1	r14,[r20]; (p07) adds	r8,0x0,r20; }

l4000000000122016:
	{ (p07) chk.a.nc	f0,3FFFFFFFFF922156; (p04) nop; (p33) nop; }

l400000000012201C:
	{ cmp4.eq.and	p20,p16,r0,r66; Invalid; break.i	0x1000; }

l4000000000122020:
	{ (p06) ld1	r14,[r8]; nop.i	0x0; br.cond.sptk.few	4000000000121EE0 }

l4000000000122026:
	{ break.m	0x4000; nop; break.i	0x80000 }

l4000000000122030:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r16; (p06) br.cond.dptk.few	4000000000122100 }

l4000000000122040:
	{ adds	r16,0x1,r8; ld1	r14,[r16]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5E,r14; nop.i	0x0; }
	{ cmp4.eq.or.andcm	p07,p06,0x21,r14; (p07) adds	r18,0x2,r8; adds	r8,0x0,r16; }

l400000000012206C:
	{ nop; zxt1	r0,r64; zxt4	r0,r0; }

l4000000000122076:
	{ Invalid; nop; break.i	0x80000 }

l4000000000122080:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r16; (p07) br.cond.dptk.few	4000000000121EB0; }

l4000000000122090:
	{ adds	r8,0x1,r8; nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFFFF,r17 }
	{ cmp4.lt	p07,p06,0x0,r17; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000122180; }

l40000000001220B0:
	{ nop.m	0x0; adds	r17,0x0,r14; nop.i	0x0 }
	{ ld1	r14,[r8]; nop.m	0x0; br.cond.sptk.few	4000000000121EE0 }

l40000000001220D0:
	{ cmp4.eq	p06,p07,0x0,r16; adds	r8,0x1,r8; (p06) adds	r17,0x1,r17 }

l40000000001220E0:
	{ nop.m	0x0; (p06) ld1	r14,[r8]; (p06) br.cond.dptk.few	4000000000121EE0; }

l40000000001220EC:
	{ (p48) cmp.lt.unc	p63,p16,r63,r37; Invalid; break.i	0x1000 }

l40000000001220F0:
	{ ld1	r14,[r8]; nop.i	0x0; br.cond.sptk.few	4000000000121EE0 }

l4000000000122100:
	{ adds	r8,0x1,r8; ld1	r14,[r8]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x3A,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x2E,r14; (p07) br.cond.dptk.few	4000000000122140 }

l4000000000122130:
	{ nop.m	0x0; adds	r19,0x0,r14; br.cond.sptk.few	4000000000121EE0; }

l4000000000122140:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x3D,r14; (p07) br.cond.dptk.few	4000000000121EE0 }

l4000000000122150:
	{ nop.m	0x0; adds	r19,0x0,r14; br.cond.sptk.few	4000000000121EE0 }

l4000000000122160:
	{ nop.m	0x0; adds	r8,0x0,r32; br.ret	b0; }

l4000000000122170:
	{ nop.m	0x0; nop.i	0x0; br.ret	b0; }

l4000000000122180:
	{ nop.m	0x0; nop.i	0x0; br.ret	b0; }
4000000000122190 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001221A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001221B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000001221C0: 40000000001221C0
;;   Called from:
;;     4000000000125A4C (in fn4000000000125100)
;;     4000000000126A0C (in fn40000000001269C0)
fn40000000001221C0 proc
	{ ld4	r14,[r32]; adds	r15,0x0,r0; adds	r18,0x0,r0 }
	{ adds	r19,0x0,r0; cmp.ltu	p09,p08,r32,r33; adds	r8,0x0,r32; }
	{ cmp4.eq	p06,p07,0x0,r14; adds	r16,0x0,r0; nop.i	0x0 }
	{ adds	r17,0x0,r0; cmp4.eq	p10,p11,0x7C,r34; (p06) br.cond.dpnt.few	4000000000122270; }

l4000000000122200:
	{ nop.m	0x0; nop.i	0x0; (p08) br.cond.dpnt.few	4000000000122560; }

l4000000000122210:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	4000000000122310; }

l4000000000122220:
	{ cmp4.eq	p06,p07,0x5B,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000122430; }

l4000000000122230:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x5B,r14; (p06) br.cond.dptk.few	4000000000122280; }

l4000000000122240:
	{ cmp4.eq	p06,p07,0x28,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001224D0; }

l4000000000122250:
	{ cmp4.eq	p06,p07,0x29,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000122480; }

l4000000000122260:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	40000000001222B0 }

l4000000000122270:
	{ nop.m	0x0; adds	r8,0x0,r0; br.ret	b0; }

l4000000000122280:
	{ cmp4.eq	p06,p07,0x5D,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001223A0; }

l4000000000122290:
	{ nop.m	0x0; cmp4.lt	p07,p06,0x5C,r14; (p06) br.cond.dptk.few	4000000000122380; }

l40000000001222A0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x7C,r14; (p06) br.cond.dpnt.few	4000000000122330 }

l40000000001222B0:
	{ nop.m	0x0; adds	r8,0x4,r8; nop.i	0x0; }
	{ ld4	r14,[r8]; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000001222E0:
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000122270; }

l40000000001222F0:
	{ cmp.ltu	p07,p06,r8,r33; nop.i	0x0; (p06) br.ret	b0; }

l4000000000122300:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p07) br.cond.dptk.few	4000000000122220 }

l4000000000122310:
	{ adds	r8,0x4,r8; nop.m	0x0; adds	r15,0x0,r0; }
	{ ld4	r14,[r8]; nop.i	0x0; br.cond.sptk.few	40000000001222E0; }

l4000000000122330:
	{ nop.m	0x0; or	r14,r16,r17; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	40000000001222B0 }

l4000000000122350:
	{ adds	r8,0x4,r8; nop.m	0x0; adds	r16,0x0,r0 }
	{ adds	r17,0x0,r0; nop.m	0x0; (p10) br.cond.dpnt.few	4000000000122570; }

l4000000000122370:
	{ ld4	r14,[r8]; nop.i	0x0; br.cond.sptk.few	40000000001222E0 }

l4000000000122380:
	{ adds	r8,0x4,r8; nop.m	0x0; addl	r15,1,r0; }
	{ ld4	r14,[r8]; nop.i	0x0; br.cond.sptk.few	40000000001222E0 }

l40000000001223A0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r16; (p07) br.cond.dptk.few	40000000001222B0; }

l40000000001223B0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r19; (p06) br.cond.dptk.few	40000000001223F0 }

l40000000001223C0:
	{ adds	r14,0xFFFFFFFFFFFFFFFC,r8; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,r19,r14; (p07) adds	r8,0x4,r8; (p07) adds	r19,0x0,r0; }

l40000000001223DC:
	{ cmp4.eq.and	p00,p48,r0,r66; Invalid; mov	pr,r32,0x0 }

l40000000001223E0:
	{ (p07) ld4	r14,[r8]; nop.i	0x0; (p07) br.cond.dpnt.few	40000000001222E0 }

l40000000001223E6:
	{ chk.a.nc	f0,3FFFFFFFFF122BE6; Invalid; (p48) nop }

l40000000001223F0:
	{ cmp.eq	p07,p06,r18,r8; nop.i	0x0; (p07) adds	r20,0x4,r8 }

l4000000000122400:
	{ (p06) adds	r8,0x4,r8; (p06) adds	r16,0xFFFFFFFFFFFFFFFF,r16; (p06) adds	r18,0x0,r0; }

l4000000000122406:
	{ (p08) chk.a.clr	r127,3FFFFFFFFF2C1D06; (p09) cmp4.eq.or	p00,p02,r0,r0; (p33) cmp.eq.or.andcm	p04,p00,r0,r2; }

l400000000012240C:
	{ getf.exp	r0,f0; (p02) cmp4.eq.and	p00,p48,r2,r64; (p01) mov	pr,r5,0x4000 }

l4000000000122410:
	{ (p07) adds	r18,0x0,r8; (p07) ld4	r14,[r20]; (p07) adds	r8,0x0,r20; }

l4000000000122416:
	{ (p07) chk.a.nc	f0,3FFFFFFFFF92A556; (p04) nop; (p33) nop; }

l400000000012241C:
	{ cmp4.eq.and	p20,p16,r0,r66; Invalid; break.i	0x1000; }

l4000000000122420:
	{ (p06) ld4	r14,[r8]; nop.i	0x0; br.cond.sptk.few	40000000001222E0 }

l4000000000122426:
	{ break.m	0x4000; nop; break.i	0x80000 }

l4000000000122430:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r16; (p06) br.cond.dptk.few	4000000000122500 }

l4000000000122440:
	{ adds	r16,0x4,r8; ld4	r14,[r16]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5E,r14; nop.i	0x0; }
	{ cmp4.eq.or.andcm	p07,p06,0x21,r14; (p07) adds	r18,0x8,r8; adds	r8,0x0,r16; }

l400000000012246C:
	{ nop; zxt1	r0,r64; zxt4	r0,r0; }

l4000000000122476:
	{ Invalid; nop; break.i	0x80000 }

l4000000000122480:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r16; (p07) br.cond.dptk.few	40000000001222B0; }

l4000000000122490:
	{ adds	r8,0x4,r8; nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFFFF,r17 }
	{ cmp4.lt	p07,p06,0x0,r17; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000122580; }

l40000000001224B0:
	{ nop.m	0x0; adds	r17,0x0,r14; nop.i	0x0 }
	{ ld4	r14,[r8]; nop.m	0x0; br.cond.sptk.few	40000000001222E0 }

l40000000001224D0:
	{ cmp4.eq	p06,p07,0x0,r16; adds	r8,0x4,r8; (p06) adds	r17,0x1,r17 }

l40000000001224E0:
	{ nop.m	0x0; (p06) ld4	r14,[r8]; (p06) br.cond.dptk.few	40000000001222E0; }

l40000000001224EC:
	{ (p48) cmp.lt.unc	p63,p16,r63,r37; Invalid; break.i	0x1000 }

l40000000001224F0:
	{ ld4	r14,[r8]; nop.i	0x0; br.cond.sptk.few	40000000001222E0 }

l4000000000122500:
	{ adds	r8,0x4,r8; ld4	r14,[r8]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x3A,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x2E,r14; (p07) br.cond.dptk.few	4000000000122540 }

l4000000000122530:
	{ nop.m	0x0; adds	r19,0x0,r14; br.cond.sptk.few	40000000001222E0; }

l4000000000122540:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x3D,r14; (p07) br.cond.dptk.few	40000000001222E0 }

l4000000000122550:
	{ nop.m	0x0; adds	r19,0x0,r14; br.cond.sptk.few	40000000001222E0 }

l4000000000122560:
	{ nop.m	0x0; adds	r8,0x0,r32; br.ret	b0; }

l4000000000122570:
	{ nop.m	0x0; nop.i	0x0; br.ret	b0; }

l4000000000122580:
	{ nop.m	0x0; nop.i	0x0; br.ret	b0; }
4000000000122590 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001225A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001225B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000001225C0: 40000000001225C0
;;   Called from:
;;     4000000000125FFC (in fn4000000000125100)
;;     400000000012665C (in fn4000000000125100)
fn40000000001225C0 proc
	{ alloc	r43,ar.pfs,0x10,0x0,0xD; adds	r40,0x4,r32; mov	r42,b2 }
	{ adds	r44,0x0,r1; nop.m	0x0; adds	r32,0x8,r32; }
	{ ld4	r39,[r40]; nop.m	0x0; addl	r34,1,r0 }
	{ adds	r38,0x0,r0; nop.m	0x0; adds	r16,0x0,r0; }
	{ cmp4.eq	p06,p07,0x0,r39; adds	r37,0xFFFFFFFFFFFFFFFF,r34; (p06) br.cond.dpnt.few	4000000000122880; }

l4000000000122610:
	{ nop.m	0x0; (p07) adds	r14,0x0,r39; nop.i	0x0; }

l400000000012261C:
	{ Invalid; cmp.eq	p00,p00,r32,r0; (p32) mov	pr,r67,0xE696 }
	{ (p04) nop; break.i	0x1000; break.i	0x1000 }

l4000000000122630:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000122640:
	{ nop.m	0x0; ld4	r14,[r32],4; adds	r15,0x1,r34 }
	{ adds	r37,0x0,r34; shladd	r38,r34,0x2,r0; adds	r16,0x0,r34; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000001227A0; }

l4000000000122670:
	{ nop.m	0x0; adds	r34,0x0,r15; cmp4.eq	p07,p06,0x2E,r14 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dptk.few	4000000000122640; }

l4000000000122690:
	{ adds	r37,0xFFFFFFFFFFFFFFFF,r34; nop.m	0x0; nop.i	0x0 }

l40000000001226A0:
	{ adds	r14,0x1,r16; shladd	r14,r14,0x2,r40; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5D,r14; (p06) br.cond.dptk.few	4000000000122640 }

l40000000001226D0:
	{ addl	r36,-12300,r1; adds	r41,0x2,r16; adds	r34,0x0,r16; }
	{ nop.m	0x0; nop.m	0x0; shladd	r41,r41,0x2,r0; }
	{ nop.m	0x0; ld8	r35,[r36]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r35; (p06) br.cond.dpnt.few	4000000000122760; }

l4000000000122710:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000122720:
	{ nop.m	0x0; ld4	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r39,r14; (p07) br.cond.dpnt.few	40000000001227F0 }

l4000000000122740:
	{ adds	r36,0x10,r36; ld8	r35,[r36]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	4000000000122720; }

l4000000000122760:
	{ cmp4.eq	p07,p06,0x1,r37; add	r8,r40,r41; mov.i	ar.pfs,r43; }
	{ (p07) adds	r37,0x0,r39; nop.m	0x0; mov.spnt	b0,r42,4000000000122770; }

l4000000000122776:
	{ break.m	0x4000; addl	r42,1065345,r0; (p17) nop }

l4000000000122786:
	{ break.m	0x4000; (p03) cmp.eq.or.andcm	p00,p50,r33,r7; (p01) nop }

l4000000000122796:
	{ break.m	0x4000; (p34) nop; nop }

l40000000001227A0:
	{ addl	r36,-12300,r1; nop.m	0x0; adds	r41,0x2,r34; }
	{ nop.m	0x0; nop.m	0x0; shladd	r41,r41,0x2,r0; }
	{ nop.m	0x0; ld8	r35,[r36]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r35; (p07) br.cond.dptk.few	4000000000122720 }

l40000000001227E0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000122760 }

l40000000001227F0:
	{ adds	r45,0x0,r35; adds	r46,0x0,r40; nop.i	0x0 }
	{ adds	r47,0x0,r34; add	r35,r35,r38; br.call.sptk.many	b0,fn400000000001AB40; }
	{ adds	r1,0x0,r44; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	4000000000122740 }

l4000000000122820:
	{ nop.m	0x0; ld4	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000122740; }

l4000000000122840:
	{ adds	r36,0x8,r36; cmp.eq	p06,p07,0x0,r33; nop.b	0x0 }
	{ add	r8,r40,r41; nop.m	0x0; mov.i	ar.pfs,r43; }
	{ ld4	r37,[r36]; nop.m	0x0; mov.spnt	b0,r42,4000000000122860; }
	{ (p07) st4	[r37],r33; nop.i	0x0; br.ret	b0 }

l4000000000122876:
	{ break.m	0x4000; (p34) nop; nop }

l4000000000122880:
	{ addl	r36,-12300,r1; addl	r41,8,r0; nop.i	0x0 }
	{ adds	r38,0x0,r0; adds	r34,0x0,r0; adds	r37,0x0,r0; }
	{ nop.m	0x0; ld8	r35,[r36]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r35; (p07) br.cond.dptk.few	4000000000122720 }

l40000000001228C0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000122760; }
40000000001228D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001228E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001228F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000122900: 4000000000122900
;;   Called from:
;;     4000000000123ABC (in fn4000000000122C80)
;;     4000000000123C4C (in fn4000000000122C80)
;;     4000000000123C7C (in fn4000000000122C80)
;;     4000000000123DEC (in fn4000000000122C80)
fn4000000000122900 proc
	{ alloc	r35,ar.pfs,0x7,0x0,0x5; addl	r16,6388,r1; nop.b	0x0 }
	{ addl	r15,6396,r1; mov	r34,b2; adds	r36,0x0,r1; }
	{ addl	r14,255,r0; adds	r37,0x0,r16; adds	r38,0x0,r15; }
	{ and	r32,r14,r32; and	r33,r14,r33; cmp4.eq	p06,p07,r33,r32; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000122980; }

l4000000000122946:
	{ chk.a.nc	r0,3FFFFFFFFF123146; nop; break.i	0x80000 }

l4000000000122950:
	{ nop.m	0x0; st1	[r32],r16; nop.i	0x0 }
	{ st1	[r33],r15; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B440; }
	{ cmp4.eq	p07,p06,0x0,r8; adds	r1,0x0,r36; (p07) sub	r8,r32,r33 }

l4000000000122980:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000122990; br.ret	b0; }
40000000001229A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001229B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000001229C0: 40000000001229C0
;;   Called from:
;;     4000000000123BEC (in fn4000000000122C80)
;;     40000000001240DC (in fn4000000000122C80)
fn40000000001229C0 proc
	{ alloc	r43,ar.pfs,0x10,0x0,0xD; adds	r39,0x1,r32; mov	r42,b2 }
	{ adds	r44,0x0,r1; nop.m	0x0; adds	r32,0x2,r32; }
	{ ld1	r14,[r39]; addl	r34,1,r0; adds	r16,0x0,r0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.m	0x0; adds	r40,0x0,r14 }
	{ adds	r37,0xFFFFFFFFFFFFFFFF,r34; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000122C30; }

l4000000000122A10:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r14; (p07) br.cond.dpnt.few	4000000000122A80; }

l4000000000122A20:
	{ ld1	r14,[r32],1; nop.m	0x0; adds	r15,0x1,r34 }
	{ adds	r37,0x0,r34; nop.m	0x0; adds	r16,0x0,r34; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000122B60; }

l4000000000122A50:
	{ nop.m	0x0; adds	r34,0x0,r15; cmp4.eq	p07,p06,0x2E,r14 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dptk.few	4000000000122A20; }

l4000000000122A70:
	{ adds	r37,0xFFFFFFFFFFFFFFFF,r34; nop.m	0x0; nop.i	0x0 }

l4000000000122A80:
	{ add	r14,r39,r16,0x1; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x5D,r14; (p06) br.cond.dptk.few	4000000000122A20 }

l4000000000122AA0:
	{ addl	r36,-13836,r1; adds	r34,0x0,r16; sxt1	r38,r40 }
	{ adds	r41,0x2,r16; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld8	r35,[r36]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r35; (p06) br.cond.dpnt.few	4000000000122B20; }

l4000000000122AE0:
	{ ld1	r14,[r35]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r38; (p07) br.cond.dpnt.few	4000000000122BA0 }

l4000000000122B00:
	{ adds	r36,0x10,r36; ld8	r35,[r36]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	4000000000122AE0; }

l4000000000122B20:
	{ cmp4.eq	p07,p06,0x1,r37; add	r8,r39,r41; mov.i	ar.pfs,r43; }
	{ (p07) adds	r37,0x0,r40; nop.m	0x0; mov.spnt	b0,r42,4000000000122B30; }

l4000000000122B36:
	{ break.m	0x4000; addl	r42,1065345,r0; (p17) nop }

l4000000000122B46:
	{ break.m	0x4000; (p03) cmp.eq.or.andcm	p00,p50,r33,r7; (p01) nop }

l4000000000122B56:
	{ break.m	0x4000; (p34) nop; nop }

l4000000000122B60:
	{ addl	r36,-13836,r1; adds	r41,0x2,r34; sxt1	r38,r40; }
	{ nop.m	0x0; ld8	r35,[r36]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r35; (p07) br.cond.dptk.few	4000000000122AE0 }

l4000000000122B90:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000122B20 }

l4000000000122BA0:
	{ adds	r45,0x0,r35; adds	r46,0x0,r39; nop.i	0x0 }
	{ adds	r47,0x0,r34; add	r35,r35,r34; br.call.sptk.many	b0,fn400000000001C020; }
	{ adds	r1,0x0,r44; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	4000000000122B00 }

l4000000000122BD0:
	{ ld1	r14,[r35]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000122B00; }

l4000000000122BF0:
	{ adds	r36,0x8,r36; cmp.eq	p06,p07,0x0,r33; nop.b	0x0 }
	{ add	r8,r39,r41; nop.m	0x0; mov.i	ar.pfs,r43; }
	{ ld1	r37,[r36]; nop.m	0x0; mov.spnt	b0,r42,4000000000122C10; }
	{ (p07) st4	[r37],r33; nop.i	0x0; br.ret	b0 }

l4000000000122C26:
	{ break.m	0x4000; (p34) nop; nop }

l4000000000122C30:
	{ addl	r36,-13836,r1; addl	r41,2,r0; nop.i	0x0 }
	{ adds	r34,0x0,r0; adds	r37,0x0,r0; sxt1	r38,r40; }
	{ nop.m	0x0; ld8	r35,[r36]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r35; (p07) br.cond.dptk.few	4000000000122AE0 }

l4000000000122C70:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000122B20; }

;; fn4000000000122C80: 4000000000122C80
;;   Called from:
;;     40000000001242DC (in fn4000000000122C80)
;;     40000000001271AC (in internal_strmatch)
fn4000000000122C80 proc
	{ alloc	r60,ar.pfs,0x26,0x0,0x20; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r62,pr }
	{ cmp.eq	p06,p07,0x0,r32; and	r47,0x20,r36; and	r46,0x2,r36; }
	{ cmp.eq.or.andcm	p06,p07,0x0,r34; addl	r51,-5820,r1; mov	r63,LC }
	{ adds	r61,0x0,r1; adds	r39,0x0,r32; addl	r42,256,r0; }
	{ addl	r49,255,r0; mov	r59,b3; cmp4.eq	p18,p19,0x0,r47 }
	{ cmp4.eq	p23,p22,0x0,r46; addl	r50,6380,r1; (p06) br.cond.dpnt.few	4000000000122F20; }

l4000000000122CE0:
	{ cmp.ltu	p07,p06,r34,r35; tnat.z	p16,p17,r36; (p06) br.cond.dpnt.few	4000000000124580; }

l4000000000122CF0:
	{ nop.m	0x0; tnat.z	p24,p25,r36; nop.i	0x0 }
	{ ld8	r51,[r51]; nop.i	0x0; tnat.z	p26,p27,r36 }

l4000000000122D10:
	{ adds	r38,0x0,r34; ld1	r37,[r38],1; nop.i	0x0; }
	{ adds	r14,0x0,r37; adds	r45,0x0,r38; (p16) br.cond.dptk.few	4000000000122DA0 }

l4000000000122D30:
	{ nop.m	0x0; zxt1	r40,r37; br.call.sptk.many	b0,fn400000000001C3C0; }
	{ ld8	r14,[r8]; adds	r1,0x0,r61; shladd	r14,r40,0x1,r14; }
	{ ld2	r14,[r14]; and	r14,r42,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000122DA0 }

l4000000000122D70:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C3A0; }
	{ ld8	r14,[r8]; adds	r1,0x0,r61; shladd	r40,r40,0x2,r14 }
	{ nop.m	0x0; ld4	r37,[r40]; nop.i	0x0 }

l4000000000122DA0:
	{ cmp.ltu	p21,p20,r39,r33; (p21) ld1	r40,[r39]; nop.i	0x0; }

l4000000000122DAC:
	{ invala; mov	pr,0x8001000; (p05) chk.s.i	r0,3FFFFFFFFF542DAC }

l4000000000122DBC:
	{ (p01) nop; cmp.lt	p00,p00,r32,r0; (p01) rfi }

l4000000000122DC0:
	{ nop.m	0x0; ld1	r14,[r38]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x28,r14; (p07) br.cond.dpnt.few	40000000001230C0; }

l4000000000122DE0:
	{ cmp4.eq	p06,p07,0x3F,r37; nop.m	0x0; nop.i	0x0 }

l4000000000122DF0:
	{ nop.m	0x0; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000123680; }

l4000000000122E00:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x3F,r37; (p06) br.cond.dptk.few	4000000000122F60; }

l4000000000122E10:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2A,r37; (p06) br.cond.dpnt.few	4000000000123170 }

l4000000000122E20:
	{ nop.m	0x0; and	r37,r49,r37; (p16) br.cond.dptk.few	4000000000122EA0 }

l4000000000122E30:
	{ nop.m	0x0; sxt4	r41,r40; br.call.sptk.many	b0,fn400000000001C3C0; }
	{ ld8	r14,[r8]; adds	r1,0x0,r61; shladd	r14,r41,0x1,r14; }
	{ ld2	r14,[r14]; and	r14,r42,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000122EA0 }

l4000000000122E70:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C3A0; }
	{ ld8	r14,[r8]; adds	r1,0x0,r61; shladd	r41,r41,0x2,r14 }
	{ nop.m	0x0; ld4	r40,[r41]; nop.i	0x0; }

l4000000000122EA0:
	{ nop.m	0x0; cmp4.eq	p07,p06,r40,r37; (p06) br.cond.dpnt.few	4000000000122F20 }

l4000000000122EB0:
	{ adds	r34,0x0,r38; nop.m	0x0; nop.i	0x0; }

l4000000000122EC0:
	{ adds	r39,0x1,r39; cmp.ltu	p06,p07,r34,r35; (p06) br.cond.dptk.few	4000000000122D10; }

l4000000000122ED0:
	{ cmp.eq	p06,p07,r39,r33; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000123520; }

l4000000000122EE0:
	{ nop.m	0x0; tbit.z	p06,p07,r36,0x3; (p06) br.cond.dptk.few	4000000000122F20 }

l4000000000122EF0:
	{ nop.m	0x0; ld1	r14,[r39]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x2F,r14; (p06) br.cond.dpnt.few	4000000000123520; }

l4000000000122F10:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000122F20:
	{ addl	r8,1,r0; nop.m	0x0; nop.i	0x0; }

l4000000000122F30:
	{ nop.m	0x0; mov	pr,r62,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r60; }
	{ nop.m	0x0; mov.i	LC,r63; mov.spnt	b0,r59,4000000000122F40 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000122F60:
	{ cmp4.eq	p06,p07,0x5B,r37; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000123700; }

l4000000000122F70:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x5C,r37; (p07) br.cond.dptk.few	4000000000122E20; }

l4000000000122F80:
	{ cmp.eq	p06,p07,r38,r35; (p06) br.cond.dpnt.few	4000000000122F20; (p22) br.cond.dptk.few	4000000000123550 }

l4000000000122F8C:
	{ (p46) nop; (p37) nop; (p04) rfi }

l4000000000122F90:
	{ adds	r45,0x2,r34; ld1	r37,[r38]; nop.i	0x0; }
	{ cmp.ltu	p06,p07,r35,r45; (p06) br.cond.dpnt.few	4000000000122F20; (p16) br.cond.dptk.few	4000000000123560 }

l4000000000122FAC:
	{ Invalid; nop; (p05) break.i	0x104A0 }

l4000000000122FB0:
	{ nop.m	0x0; zxt1	r41,r37; br.call.sptk.many	b0,fn400000000001C3C0; }
	{ ld8	r38,[r8]; adds	r1,0x0,r61; shladd	r14,r41,0x1,r38; }
	{ ld2	r14,[r14]; and	r14,r42,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000123020 }

l4000000000122FF0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C3A0; }
	{ ld8	r14,[r8]; adds	r1,0x0,r61; shladd	r41,r41,0x2,r14 }
	{ nop.m	0x0; ld4	r37,[r41]; nop.i	0x0; }

l4000000000123020:
	{ nop.m	0x0; and	r37,r49,r37; adds	r34,0x0,r45 }

l4000000000123030:
	{ nop.m	0x0; sxt4	r41,r40; shladd	r38,r41,0x1,r38; }
	{ ld2	r14,[r38]; and	r14,r42,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000123090 }

l4000000000123060:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C3A0; }
	{ ld8	r14,[r8]; adds	r1,0x0,r61; shladd	r41,r41,0x2,r14 }
	{ nop.m	0x0; ld4	r40,[r41]; nop.i	0x0; }

l4000000000123090:
	{ nop.m	0x0; cmp4.eq	p07,p06,r37,r40; (p06) br.cond.dpnt.few	4000000000122F20; }

l40000000001230A0:
	{ adds	r39,0x1,r39; cmp.ltu	p06,p07,r34,r35; (p06) br.cond.dptk.few	4000000000122D10 }

l40000000001230B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000122ED0; }

l40000000001230C0:
	{ adds	r14,0xFFFFFFFFFFFFFFD6,r37; cmp4.eq	p06,p07,0x3F,r37; cmp4.ltu	p09,p08,0x1,r14; }
	{ (p06) cmp4.eq.or.andcm	p08,p09,0x0,r0; nop.i	0x0; (p08) br.cond.dpnt.few	4000000000123100; }

l40000000001230E0:
	{ nop.m	0x0; cmp4.eq	p09,p08,0x21,r37; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p09,p08,0x40,r37; (p08) br.cond.dptk.few	4000000000122DF0 }

l4000000000123100:
	{ cmp.eq	p06,p07,r39,r32; adds	r64,0x0,r37; adds	r65,0x0,r39 }
	{ adds	r66,0x0,r33; adds	r67,0x0,r38; adds	r68,0x0,r35; }
	{ nop.m	0x0; (p07) and	r36,0xFFFFFFFFFFFFFFFB,r36; nop.i	0x0; }

l400000000012312C:
	{ nop; zxt1	r0,r64; break.i	0x1000 }
	{ (p04) nop; cmp.eq	p32,p16,r15,r64; (p47) nop }
	{ Invalid; break.i	0x1000; (p48) break.i	0x2A82F }
	{ (p29) nop; add	r0,r32,r0; Invalid }
	{ cmp.eq	p00,p17,r33,r0; (p32) flushrs; mov	pr,r32,0x0 }

l4000000000123170:
	{ cmp.eq	p07,p06,r38,r35; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000123520; }

l4000000000123180:
	{ nop.m	0x0; tbit.z	p06,p07,r36,0x2; (p06) br.cond.dptk.few	40000000001231A0; }

l4000000000123190:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r40; (p07) br.cond.dpnt.few	4000000000124160 }

l40000000001231A0:
	{ ld1	r37,[r38]; adds	r38,0x2,r34; cmp4.eq	p07,p06,0x2A,r37; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x3F,r37; (p06) br.cond.dpnt.few	4000000000123270; }

l40000000001231C0:
	{ nop.m	0x0; tnat.z	p20,p21,r36; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000001231E0:
	{ nop.m	0x0; nop.i	0x0; (p20) br.cond.dptk.few	4000000000123200 }

l40000000001231F0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2F,r40; (p06) br.cond.dpnt.few	4000000000122F20; }

l4000000000123200:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x3F,r37; (p18) br.cond.dptk.few	4000000000123580 }

l4000000000123210:
	{ nop.m	0x0; nop.i	0x0; (p07) br.cond.dpnt.few	40000000001235C0; }

l4000000000123220:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2A,r37; (p07) br.cond.dpnt.few	4000000000123440; }

l4000000000123230:
	{ cmp.eq	p06,p07,r38,r35; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000123520; }

l4000000000123240:
	{ ld1	r37,[r38],1; cmp4.eq	p06,p07,0x3F,r37; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x2A,r37; (p06) br.cond.dptk.few	40000000001231E0 }

l4000000000123260:
	{ cmp.ltu	p21,p20,r39,r33; nop.m	0x0; nop.i	0x0; }

l4000000000123270:
	{ nop.m	0x0; tbit.z	p07,p06,r36,0x1; (p06) br.cond.dptk.few	40000000001232A0; }

l4000000000123280:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5C,r37; nop.i	0x0; }
	{ (p07) ld1	r41,[r38]; nop.i	0x0; (p07) br.cond.dpnt.few	40000000001232B0; }

l4000000000123296:
	{ chk.a.nc	f0,3FFFFFFFFF123A96; nop; (p16) nop }

l40000000001232A0:
	{ adds	r41,0x0,r37; nop.m	0x0; nop.i	0x0 }

l40000000001232B0:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dptk.few	4000000000123330; }

l40000000001232C0:
	{ nop.m	0x0; zxt1	r40,r41; br.call.sptk.many	b0,fn400000000001C3C0; }
	{ ld8	r14,[r8]; adds	r1,0x0,r61; shladd	r14,r40,0x1,r14; }
	{ nop.m	0x0; ld2	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x8; (p06) br.cond.dptk.few	4000000000123330 }

l4000000000123300:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C3A0; }
	{ ld8	r14,[r8]; adds	r1,0x0,r61; shladd	r40,r40,0x2,r14 }
	{ nop.m	0x0; ld1	r41,[r40]; nop.i	0x0 }

l4000000000123330:
	{ adds	r40,0xFFFFFFFFFFFFFFFF,r38; sub	r14,r33,r39,0x1; cmp4.eq	p19,p18,0x0,r47 }
	{ and	r36,0xFFFFFFFFFFFFFFFB,r36; addl	r43,256,r0; (p20) br.cond.dpnt.few	4000000000122F20; }

l4000000000123350:
	{ nop.m	0x0; cmp4.eq	p20,p21,0x5B,r37; mov.i	LC,r14; }

l4000000000123360:
	{ nop.m	0x0; nop.i	0x0; (p18) br.cond.dptk.few	40000000001241B0 }

l4000000000123370:
	{ nop.m	0x0; nop.i	0x0; (p20) br.cond.dpnt.few	40000000001242C0; }

l4000000000123380:
	{ (p16) ld1	r14,[r39]; nop.i	0x0; (p16) br.cond.dptk.few	4000000000123410 }

l4000000000123386:
	{ nop; nop; break.i	0x80000 }

l4000000000123390:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C3C0; }
	{ nop.m	0x0; ld1	r14,[r39]; adds	r1,0x0,r61 }
	{ ld8	r15,[r8]; shladd	r15,r14,0x1,r15; adds	r42,0x0,r14; }
	{ ld2	r15,[r15]; and	r15,r43,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	4000000000123410 }

l40000000001233E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C3A0; }
	{ ld8	r14,[r8]; adds	r1,0x0,r61; shladd	r42,r42,0x2,r14 }
	{ nop.m	0x0; ld4	r14,[r42]; nop.i	0x0; }

l4000000000123410:
	{ nop.m	0x0; cmp4.eq	p06,p07,r14,r41; (p06) br.cond.dpnt.few	40000000001242C0 }

l4000000000123420:
	{ nop.m	0x0; adds	r39,0x1,r39; br.cloop.sptk.few	4000000000123360 }

l4000000000123430:
	{ nop.m	0x0; addl	r8,1,r0; br.cond.sptk.few	4000000000122F30 }

l4000000000123440:
	{ nop.m	0x0; ld1	r14,[r38]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x28,r14; (p06) br.cond.dptk.few	4000000000123230; }

l4000000000123460:
	{ cmp.ltu	p06,p07,r39,r33; nop.i	0x0; (p07) br.cond.dpnt.few	40000000001234D0; }

l4000000000123470:
	{ (p06) sub	r14,r33,r39,0x1; (p06) adds	r37,0x0,r39; (p06) mov.i	LC,r14; }

l4000000000123476:
	{ (p18) chk.a.clr	r0,3FFFFFFFFF1A36E6; nop; (p16) nop.b	0x25010; }

l400000000012347C:
	{ (p07) nop; zxt1	r32,r64; (p40) dep	r10,r0,r0,62,3 }

l4000000000123480:
	{ adds	r65,0x0,r37; addl	r64,42,r0; adds	r66,0x0,r33 }
	{ adds	r67,0x0,r38; adds	r68,0x0,r35; adds	r69,0x0,r36; }
	{ adds	r37,0x1,r37; nop.i	0x0; br.call.sptk.many	b0,fn40000000001249C0; }
	{ nop.m	0x0; adds	r1,0x0,r61; cmp4.eq	p06,p07,0x0,r8 }
	{ nop.b	0x0; (p06) br.cond.dpnt.few	4000000000123520; br.cloop.sptk.few	4000000000123480 }

l40000000001234CC:
	{ (p62) nop; zxt1	r64,r64; nop }

l40000000001234D0:
	{ adds	r64,0x1,r38; nop.m	0x0; adds	r65,0x0,r35 }
	{ adds	r66,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,fn4000000000121DC0; }
	{ nop.m	0x0; adds	r1,0x0,r61; adds	r38,0x0,r8 }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	4000000000123230; }

l4000000000123510:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000123520:
	{ adds	r8,0x0,r0; mov	pr,r62,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r60; }
	{ nop.m	0x0; mov.i	LC,r63; mov.spnt	b0,r59,4000000000123530 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000123550:
	{ nop.m	0x0; nop.i	0x0; (p17) br.cond.dptk.few	40000000001240A0 }

l4000000000123560:
	{ adds	r34,0x0,r45; cmp4.eq	p07,p06,r37,r40; (p07) br.cond.dptk.few	40000000001230A0 }

l4000000000123570:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000122F20 }

l4000000000123580:
	{ nop.m	0x0; nop.i	0x0; (p06) br.cond.dptk.few	4000000000123230; }

l4000000000123590:
	{ cmp4.eq	p06,p07,0x0,r40; adds	r39,0x1,r39; (p06) br.cond.dpnt.few	4000000000122F20; }

l40000000001235A0:
	{ cmp.ltu	p07,p06,r39,r33; (p07) ld1	r40,[r39]; nop.i	0x0; }

l40000000001235AC:
	{ invala; mov	pr,r32,0x0; zxt1	r0,r64 }

l40000000001235BC:
	{ (p36) nop; cmp.lt	p00,p00,r32,r0; Invalid }

l40000000001235C0:
	{ nop.m	0x0; ld1	r14,[r38]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x28,r14; (p06) br.cond.dptk.few	4000000000123590; }

l40000000001235E0:
	{ nop.m	0x0; sub	r14,r33,r39,0x1; cmp.ltu	p07,p06,r39,r33 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000122F20; }

l4000000000123600:
	{ nop.m	0x0; mov.i	LC,r14; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000123620:
	{ adds	r65,0x0,r39; addl	r64,63,r0; adds	r66,0x0,r33 }
	{ adds	r67,0x0,r38; adds	r68,0x0,r35; adds	r69,0x0,r36; }
	{ adds	r39,0x1,r39; nop.i	0x0; br.call.sptk.many	b0,fn40000000001249C0; }
	{ nop.m	0x0; adds	r1,0x0,r61; cmp4.eq	p06,p07,0x0,r8 }
	{ nop.b	0x0; (p06) br.cond.dpnt.few	4000000000123520; br.cloop.sptk.few	4000000000123620 }

l400000000012366C:
	{ Invalid; break.i	0x1000; zxt4	r0,r0 }

l4000000000123670:
	{ nop.m	0x0; addl	r8,1,r0; br.cond.sptk.few	4000000000122F30; }

l4000000000123680:
	{ cmp4.eq	p07,p06,0x0,r40; (p07) br.cond.dpnt.few	4000000000122F20; (p24) br.cond.dptk.few	40000000001236A0; }

l400000000012368C:
	{ (p01) invala; cmp.lt	p00,p00,r32,r0; (p48) mov	pr,r106,0xE616 }

l4000000000123690:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2F,r40; (p06) br.cond.dpnt.few	4000000000122F20 }

l40000000001236A0:
	{ nop.m	0x0; nop.i	0x0; (p26) br.cond.dptk.few	4000000000122EB0; }

l40000000001236B0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r40; (p06) br.cond.dptk.few	4000000000122EB0; }

l40000000001236C0:
	{ cmp.eq	p06,p07,r39,r32; (p06) br.cond.dpnt.few	4000000000122F20; (p24) br.cond.dptk.few	4000000000122EB0 }

l40000000001236CC:
	{ (p63) cmp.lt.unc	p62,p09,r63,r37; zxt2	r127,r79; br.cond.sptk.few	40000000001238CC }

l40000000001236D0:
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r39; nop.m	0x0; adds	r34,0x0,r38; }
	{ nop.m	0x0; ld1	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x2F,r14; (p06) br.cond.dpnt.few	4000000000122F20; br.cond.sptk.few	4000000000122EC0; }

l40000000001236FC:
	{ (p62) nop; cmp.lt	p00,p00,r32,r0; (p48) nop }

l4000000000123700:
	{ nop.m	0x0; cmp.eq	p06,p07,r39,r33; nop.i	0x0; }
	{ cmp4.eq.or.andcm	p06,p07,0x0,r40; (p06) br.cond.dpnt.few	4000000000122F20; (p26) br.cond.dpnt.few	4000000000123730; }

l400000000012371C:
	{ (p01) invala; cmp.eq	p00,p00,r32,r0; (p32) mov	pr,r74,0xE616 }

l4000000000123720:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r40; (p07) br.cond.dpnt.few	4000000000124120 }

l4000000000123730:
	{ nop.m	0x0; zxt1	r43,r40; (p16) br.cond.dptk.few	40000000001237B0 }

l4000000000123740:
	{ nop.m	0x0; sxt4	r40,r40; br.call.sptk.many	b0,fn400000000001C3C0; }
	{ ld8	r14,[r8]; adds	r1,0x0,r61; shladd	r14,r40,0x1,r14; }
	{ ld2	r14,[r14]; and	r14,r42,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000001237B0 }

l4000000000123780:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C3A0; }
	{ ld8	r14,[r8]; adds	r1,0x0,r61; shladd	r40,r40,0x2,r14 }
	{ nop.m	0x0; ld1	r43,[r40]; nop.i	0x0; }

l40000000001237B0:
	{ ld1	r37,[r38]; nop.m	0x0; and	r17,0xFFFFFFFFFFFFFF80,r43 }
	{ adds	r15,0x1,r43; zxt1	r16,r43; cmp4.eq	p06,p07,0x5E,r37 }
	{ cmp4.eq	p08,p09,0x21,r37; shladd	r53,r16,0x1,r0; zxt1	r55,r15; }
	{ (p06) addl	r14,1,r0; (p08) addl	r48,1,r0; (p07) adds	r14,0x0,r0 }

l40000000001237E6:
	{ (p24) chk.a.clr	f1,3FFFFFFFFF3237E6; (p07) dep	r0,r0,r0,35,2; (p02) nop }

l40000000001237EC:
	{ chk.a.nc	r0,4000000000C047EC; zxt1	r0,r64; (p06) cmp.lt.unc	p12,p16,r67,r3; }

l40000000001237F0:
	{ (p09) adds	r48,0x0,r0; or	r48,r48,r14; adds	r14,0xFFFFFFFFFFFFFFFF,r43; }

l40000000001237F6:
	{ Invalid; (p07) mov.dpnt.imp	b7,r43,4000000000123B26; (p32) nop }
	{ (p28) chk.a.nc	f0,3FFFFFFFFF12B8E6; (p19) cmp4.eq.or	p02,p02,r34,r0; (p17) br.call.sptk.few	b1,b0 }

l4000000000123810:
	{ (p07) ld1	r37,[r38]; cmp4.eq	p06,p07,0x5F,r43; adds	r34,0x1,r38; }

l4000000000123816:
	{ Invalid; (p17) addl	r1,57638,r0; (p01) cmp.eq	p46,p00,0x0,r0 }

l4000000000123826:
	{ Invalid; Invalid; (p33) nop; }

l400000000012382C:
	{ nop; zxt4	r0,r0; dep	r0,r32,r0,49,1 }

l4000000000123836:
	{ chk.a.nc	f0,3FFFFFFFFF124036; (p29) nop; break.i	0x80000 }

l4000000000123840:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5B,r37; (p07) br.cond.dpnt.few	4000000000123B60 }

l4000000000123850:
	{ nop.m	0x0; nop.i	0x0; (p22) br.cond.dptk.few	4000000000123870; }

l4000000000123860:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5C,r37; (p07) br.cond.dpnt.few	4000000000123BB0 }

l4000000000123870:
	{ adds	r40,0x0,r37; nop.m	0x0; nop.i	0x0 }

l4000000000123880:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dptk.few	4000000000123900; }

l4000000000123890:
	{ nop.m	0x0; zxt1	r38,r40; br.call.sptk.many	b0,fn400000000001C3C0; }
	{ ld8	r14,[r8]; adds	r1,0x0,r61; shladd	r14,r38,0x1,r14; }
	{ ld2	r14,[r14]; and	r14,r42,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000123900 }

l40000000001238D0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C3A0; }
	{ ld8	r14,[r8]; adds	r1,0x0,r61; shladd	r38,r38,0x2,r14 }
	{ nop.m	0x0; ld1	r40,[r38]; nop.i	0x0 }

l4000000000123900:
	{ adds	r38,0x0,r34; cmp4.eq	p07,p06,0x0,r37; (p07) br.cond.dpnt.few	4000000000124490; }

l4000000000123910:
	{ ld1	r37,[r38],1; nop.i	0x0; (p16) br.cond.dptk.few	4000000000123990; }

l4000000000123920:
	{ nop.m	0x0; zxt1	r41,r37; br.call.sptk.many	b0,fn400000000001C3C0; }
	{ ld8	r14,[r8]; adds	r1,0x0,r61; shladd	r14,r41,0x1,r14; }
	{ ld2	r14,[r14]; and	r14,r42,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000123990 }

l4000000000123960:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C3A0; }
	{ ld8	r14,[r8]; adds	r1,0x0,r61; shladd	r41,r41,0x2,r14 }
	{ nop.m	0x0; ld1	r37,[r41]; nop.i	0x0 }

l4000000000123990:
	{ nop.m	0x0; nop.i	0x0; (p24) br.cond.dptk.few	40000000001239B0; }

l40000000001239A0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2F,r37; (p06) br.cond.dpnt.few	4000000000122F20; }

l40000000001239B0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r37; (p06) br.cond.dptk.few	4000000000123C30 }

l40000000001239C0:
	{ nop.m	0x0; ld1	r41,[r38]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x5D,r41; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000123C30; }

l40000000001239E0:
	{ adds	r38,0x2,r34; cmp4.eq	p07,p06,0x0,r46; (p06) br.cond.dptk.few	4000000000123A00; }

l40000000001239F0:
	{ cmp4.eq	p07,p06,0x5C,r41; (p07) ld1	r41,[r38]; (p07) adds	r38,0x3,r34; }

l40000000001239FC:
	{ Invalid; Invalid; Invalid }

l4000000000123A00:
	{ cmp4.eq	p06,p07,0x0,r41; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000122F20; }

l4000000000123A10:
	{ ld1	r37,[r38]; cmp4.eq	p06,p07,0x5B,r41; (p06) br.cond.dpnt.few	4000000000123BD0 }

l4000000000123A20:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dptk.few	4000000000123AA0 }

l4000000000123A30:
	{ nop.m	0x0; zxt1	r44,r41; br.call.sptk.many	b0,fn400000000001C3C0; }
	{ ld8	r14,[r8]; adds	r1,0x0,r61; shladd	r14,r44,0x1,r14; }
	{ ld2	r14,[r14]; and	r14,r42,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000123AA0 }

l4000000000123A70:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C3A0; }
	{ ld8	r14,[r8]; adds	r1,0x0,r61; shladd	r44,r44,0x2,r14 }
	{ nop.m	0x0; ld1	r41,[r44]; nop.i	0x0; }

l4000000000123AA0:
	{ adds	r65,0x0,r41; adds	r64,0x0,r40; nop.i	0x0 }
	{ adds	r34,0x1,r38; adds	r44,0x0,r40; br.call.sptk.many	b0,fn4000000000122900; }
	{ cmp4.lt	p07,p06,0x0,r8; adds	r1,0x0,r61; (p06) br.cond.dpnt.few	4000000000123CE0; }

l4000000000123AD0:
	{ cmp4.eq	p06,p07,0x5D,r37; (p06) br.cond.dpnt.few	4000000000123CA0; (p16) br.cond.dptk.few	4000000000123840 }

l4000000000123ADC:
	{ Invalid; cmp.lt	p00,p00,r32,r0; (p04) break.b	0x104A0 }

l4000000000123AE0:
	{ nop.m	0x0; zxt1	r38,r37; br.call.sptk.many	b0,fn400000000001C3C0; }
	{ ld8	r16,[r8]; adds	r1,0x0,r61; shladd	r16,r38,0x1,r16; }
	{ ld2	r16,[r16]; and	r16,r42,r16; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r16; (p06) br.cond.dptk.few	4000000000123840 }

l4000000000123B20:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C3A0; }
	{ ld8	r14,[r8]; adds	r1,0x0,r61; shladd	r38,r38,0x2,r14 }
	{ nop.m	0x0; ld1	r37,[r38]; nop.i	0x0; }

l4000000000123B50:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5B,r37; (p06) br.cond.dptk.few	4000000000123850; }

l4000000000123B60:
	{ nop.m	0x0; ld1	r14,[r34]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x3D,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000123CF0; }

l4000000000123B80:
	{ cmp4.eq	p07,p06,0x3A,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000123EC0; }

l4000000000123B90:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r14; (p07) br.cond.dpnt.few	40000000001240D0 }

l4000000000123BA0:
	{ nop.m	0x0; addl	r40,91,r0; br.cond.sptk.few	4000000000123880; }

l4000000000123BB0:
	{ ld1	r40,[r34]; nop.m	0x0; adds	r34,0x1,r34; }
	{ cmp4.eq	p06,p07,0x0,r40; (p06) br.cond.dpnt.few	4000000000122F20; br.cond.sptk.few	4000000000123880; }

l4000000000123BCC:
	{ (p38) invala; cmp.eq	p00,p00,r32,r0; (p32) mov	pr,r73,0xE656 }

l4000000000123BD0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r37; (p06) br.cond.dptk.few	4000000000123A20 }

l4000000000123BE0:
	{ adds	r64,0x0,r38; adds	r65,0x10,r12; br.call.sptk.many	b0,fn40000000001229C0; }
	{ adds	r15,0x10,r12; adds	r1,0x0,r61; adds	r38,0x0,r8; }
	{ ld4	r14,[r15]; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; }
	{ (p07) ld1	r37,[r8]; (p07) adds	r41,0x0,r57; zxt1	r41,r14 }

l4000000000123C16:
	{ Invalid; (p20) nop; Invalid; }

l4000000000123C1C:
	{ nop; (p04) nop; }

l4000000000123C2C:
	{ (p48) nop; add	r0,r32,r0; (p05) dep	r0,r10,r64,62,1 }

l4000000000123C30:
	{ nop.m	0x0; adds	r44,0x0,r40; adds	r34,0x0,r38; }

l4000000000123C40:
	{ adds	r65,0x0,r44; adds	r64,0x0,r43; br.call.sptk.many	b0,fn4000000000122900; }
	{ cmp4.lt	p07,p06,r8,r0; nop.m	0x0; adds	r1,0x0,r61 }
	{ adds	r64,0x0,r43; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000123C90; }

l4000000000123C70:
	{ adds	r65,0x0,r40; nop.i	0x0; br.call.sptk.many	b0,fn4000000000122900; }
	{ adds	r1,0x0,r61; cmp4.lt	p07,p06,0x0,r8; (p06) br.cond.dpnt.few	40000000001243A0; }

l4000000000123C90:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x5D,r37; (p07) br.cond.dptk.few	4000000000123840; }

l4000000000123CA0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r48; (p07) br.cond.dpnt.few	4000000000122F20; }

l4000000000123CB0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r34; (p06) br.cond.spnt.few	4000000000122F20; }

l4000000000123CC0:
	{ adds	r39,0x1,r39; cmp.ltu	p06,p07,r34,r35; (p06) br.cond.dptk.few	4000000000122D10 }

l4000000000123CD0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000122ED0 }

l4000000000123CE0:
	{ nop.m	0x0; adds	r40,0x0,r41; br.cond.sptk.few	4000000000123C40 }

l4000000000123CF0:
	{ adds	r16,0x2,r34; ld1	r16,[r16]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x3D,r16; (p06) br.cond.dptk.few	4000000000123BA0 }

l4000000000123D10:
	{ adds	r14,0x3,r34; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x5D,r14; (p06) br.cond.dptk.few	4000000000123BA0 }

l4000000000123D30:
	{ nop.m	0x0; (p16) adds	r14,0x1,r34; nop.i	0x0; }

l4000000000123D3C:
	{ nop; Invalid; break.i	0x101000 }

l4000000000123D46:
	{ nop; nop; break.i	0x80000 }

l4000000000123D50:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C3C0; }
	{ adds	r14,0x1,r34; ld8	r15,[r8]; adds	r1,0x0,r61; }
	{ ld1	r65,[r14]; shladd	r14,r65,0x1,r15; adds	r37,0x0,r65; }
	{ ld2	r14,[r14]; and	r14,r42,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000123DD0 }

l4000000000123DA0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C3A0; }
	{ ld8	r14,[r8]; adds	r1,0x0,r61; shladd	r37,r37,0x2,r14 }
	{ nop.m	0x0; ld4	r65,[r37]; nop.i	0x0 }

l4000000000123DD0:
	{ adds	r14,0x10,r12; nop.m	0x0; adds	r64,0x0,r43; }
	{ st4	[r65],r14; nop.i	0x0; br.call.sptk.many	b0,fn4000000000122900; }
	{ adds	r14,0x4,r34; nop.m	0x0; adds	r1,0x0,r61 }
	{ cmp4.eq	p07,p06,0x0,r8; nop.m	0x0; (p07) br.cond.dpnt.few	40000000001249B0; }

l4000000000123E10:
	{ ld1	r37,[r14]; nop.m	0x0; adds	r34,0x5,r34; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r37; (p07) br.cond.dptk.few	4000000000124490; }

l4000000000123E30:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000123E40:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dptk.few	4000000000123840 }

l4000000000123E50:
	{ nop.m	0x0; zxt1	r38,r37; br.call.sptk.many	b0,fn400000000001C3C0; }
	{ ld8	r14,[r8]; adds	r1,0x0,r61; shladd	r14,r38,0x1,r14; }
	{ ld2	r14,[r14]; and	r14,r42,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000123840 }

l4000000000123E90:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C3A0; }
	{ ld8	r14,[r8]; adds	r1,0x0,r61; shladd	r38,r38,0x2,r14; }
	{ ld1	r37,[r38]; nop.i	0x0; br.cond.sptk.few	4000000000123B50 }

l4000000000123EC0:
	{ adds	r14,0x10,r12; nop.m	0x0; adds	r41,0x1,r34; }
	{ st4	[r0],r14; nop.m	0x0; adds	r37,0x0,r41; }
	{ nop.m	0x0; ld1	r14,[r41]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	4000000000123F30; }

l4000000000123F00:
	{ adds	r15,0x1,r37; nop.m	0x0; cmp4.eq	p06,p07,0x3A,r14; }
	{ ld1	r14,[r15]; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000123F80; }

l4000000000123F20:
	{ adds	r37,0x0,r15; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000123F00; }

l4000000000123F30:
	{ ld1	r37,[r34]; nop.m	0x0; adds	r34,0x0,r41; }
	{ cmp4.eq	p07,p06,0x0,r37; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000124490; }

l4000000000123F50:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x5D,r37; (p07) br.cond.dptk.few	4000000000123E40; }

l4000000000123F60:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r48; (p06) br.cond.dptk.few	4000000000123CB0 }

l4000000000123F70:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000122F20; }

l4000000000123F80:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x5D,r14; (p07) br.cond.dptk.few	4000000000123F20 }

l4000000000123F90:
	{ sub	r40,r37,r34; addl	r44,1,r0; addl	r38,1,r0; }
	{ adds	r64,0x0,r40; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B340; }
	{ adds	r54,0x0,r8; cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r61 }
	{ adds	r66,0xFFFFFFFFFFFFFFFF,r40; adds	r65,0x0,r41; (p06) br.cond.dpnt.few	4000000000124530; }

l4000000000123FD0:
	{ adds	r64,0x0,r54; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ add	r14,r54,r40; adds	r1,0x0,r61; nop.b	0x0 }
	{ ld8	r40,[r50]; mov.i	LC,0xD; adds	r14,0xFFFFFFFFFFFFFFFF,r14; }
	{ nop.m	0x0; st1	[r0],r14; nop.i	0x0; }
	{ ld1	r14,[r54]; nop.i	0x0; sxt1	r52,r14; }

l4000000000124020:
	{ ld8	r65,[r40],8; ld1	r14,[r65]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r52; (p07) br.cond.dpnt.few	4000000000124310 }

l4000000000124050:
	{ nop.m	0x0; adds	r38,0x1,r38; nop.i	0x0; }
	{ nop.m	0x0; adds	r44,0x0,r38; br.cloop.sptk.few	4000000000124020 }

l4000000000124070:
	{ adds	r14,0x10,r12; nop.m	0x0; adds	r64,0x0,r54; }
	{ st4	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r61; br.cond.sptk.few	4000000000123F30 }

l40000000001240A0:
	{ adds	r34,0x0,r38; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C3C0; }
	{ nop.m	0x0; adds	r1,0x0,r61; nop.i	0x0 }
	{ ld8	r38,[r8]; nop.m	0x0; br.cond.sptk.few	4000000000123030 }

l40000000001240D0:
	{ adds	r64,0x0,r34; adds	r65,0x10,r12; br.call.sptk.many	b0,fn40000000001229C0; }
	{ adds	r15,0x10,r12; adds	r1,0x0,r61; adds	r34,0x0,r8; }
	{ ld4	r14,[r15]; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r40,0x0,r55; nop.i	0x0; }

l400000000012410C:
	{ invala; mov	pr,r32,0x0; (p05) break.i	0x101C0 }
	{ (p59) cmp.lt.unc	p62,p18,r63,r36; (p48) mov	pr,r104,0xE012; nop }

l4000000000124120:
	{ cmp.eq	p06,p07,r39,r32; (p06) br.cond.dpnt.few	4000000000122F20; (p24) br.cond.dptk.few	4000000000123730 }

l400000000012412C:
	{ (p48) cmp.lt.unc	p62,p11,r63,r37; (p49) cmp.lt.unc	p63,p17,r105,r79; (p01) rfi }

l4000000000124130:
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r39; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x2F,r14; (p07) br.cond.dptk.few	4000000000123730 }

l4000000000124150:
	{ nop.m	0x0; addl	r8,1,r0; br.cond.sptk.few	4000000000122F30; }

l4000000000124160:
	{ cmp.eq	p06,p07,r39,r32; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000122F20; }

l4000000000124170:
	{ nop.m	0x0; tbit.z	p06,p07,r36,0x0; (p06) br.cond.dptk.few	40000000001231A0 }

l4000000000124180:
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r39; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x2F,r14; (p07) br.cond.dptk.few	40000000001231A0 }

l40000000001241A0:
	{ nop.m	0x0; addl	r8,1,r0; br.cond.sptk.few	4000000000122F30 }

l40000000001241B0:
	{ ld1	r14,[r38]; nop.m	0x0; addl	r64,-5836,r1; }
	{ cmp.eq	p06,p07,0x28,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001242C0; }

l40000000001241D0:
	{ nop.m	0x0; ld1	r65,[r40]; nop.i	0x0 }
	{ ld8	r64,[r64]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B680; }
	{ adds	r1,0x0,r61; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000001242C0 }

l4000000000124200:
	{ nop.m	0x0; nop.i	0x0; (p20) br.cond.dpnt.few	40000000001242C0; }

l4000000000124210:
	{ (p16) ld1	r14,[r39]; nop.i	0x0; (p16) br.cond.dptk.few	40000000001242A0 }

l4000000000124216:
	{ nop; nop; break.i	0x80000 }

l4000000000124220:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C3C0; }
	{ nop.m	0x0; ld1	r14,[r39]; adds	r1,0x0,r61 }
	{ ld8	r15,[r8]; shladd	r15,r14,0x1,r15; adds	r42,0x0,r14; }
	{ ld2	r15,[r15]; and	r15,r43,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	40000000001242A0 }

l4000000000124270:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C3A0; }
	{ ld8	r14,[r8]; adds	r1,0x0,r61; shladd	r42,r42,0x2,r14 }
	{ nop.m	0x0; ld4	r14,[r42]; nop.i	0x0; }

l40000000001242A0:
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r41; (p06) br.cond.dptk.few	4000000000123420; }

l40000000001242B0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000001242C0:
	{ adds	r64,0x0,r39; adds	r65,0x0,r33; adds	r66,0x0,r40 }
	{ adds	r67,0x0,r35; adds	r68,0x0,r36; br.call.sptk.many	b0,fn4000000000122C80; }
	{ adds	r1,0x0,r61; cmp4.eq	p06,p07,0x0,r8; adds	r39,0x1,r39 }
	{ nop.b	0x0; (p06) br.cond.dpnt.few	4000000000123520; br.cloop.sptk.few	4000000000123360 }

l40000000001242FC:
	{ (p03) invala; break.i	0x1000; break.b	0x1000 }

l4000000000124300:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000123430 }

l4000000000124310:
	{ adds	r64,0x0,r54; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r61; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	4000000000124050; }

l4000000000124330:
	{ nop.m	0x0; cmp4.ltu	p06,p07,0xE,r44; (p07) br.cond.dptk.few	4000000000124550 }

l4000000000124340:
	{ adds	r38,0x0,r58; nop.m	0x0; adds	r15,0x10,r12; }
	{ st4	[r38],r15; nop.m	0x0; nop.i	0x0; }

l4000000000124360:
	{ adds	r64,0x0,r54; nop.m	0x0; adds	r34,0x2,r37 }
	{ adds	r41,0x3,r37; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r61; cmp4.eq	p07,p06,0x0,r38; (p07) br.cond.dptk.few	4000000000123F30 }

l4000000000124390:
	{ adds	r34,0x0,r41; nop.m	0x0; nop.i	0x0; }

l40000000001243A0:
	{ adds	r15,0xFFFFFFFFFFFFFFFF,r34; nop.m	0x0; addl	r16,1,r0; }
	{ ld1	r14,[r15]; nop.m	0x0; adds	r34,0x1,r15; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000124490; }

l40000000001243D0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5B,r14; (p07) br.cond.dpnt.few	4000000000124450; }

l40000000001243E0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5D,r14; nop.i	0x0; }
	{ (p07) adds	r16,0xFFFFFFFFFFFFFFFF,r16; (p07) br.cond.dpnt.few	40000000001244F0; (p22) br.cond.dptk.few	4000000000124410 }

l40000000001243F6:
	{ nop; nop; break.i	0x80000; }

l40000000001243FC:
	{ Invalid; cmp.eq	p00,p00,r32,r0; mov	pr,r67,0xE6AE }

l4000000000124400:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5C,r14; (p07) br.cond.dpnt.few	40000000001244D0; }

l4000000000124410:
	{ cmp4.lt	p06,p07,0x0,r16; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000124500; }

l4000000000124420:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	4000000000124490 }

l4000000000124430:
	{ ld1	r14,[r34]; nop.m	0x0; adds	r15,0x0,r34; }
	{ adds	r34,0x1,r15; cmp4.eq	p07,p06,0x5B,r14; (p06) br.cond.dptk.few	40000000001243E0; }

l4000000000124450:
	{ ld1	r14,[r34]; cmp4.eq	p06,p07,0x3D,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x3A,r14; (p06) br.cond.dptk.few	4000000000124480; }

l4000000000124470:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r14; (p06) br.cond.dptk.few	40000000001244F0 }

l4000000000124480:
	{ nop.m	0x0; adds	r16,0x1,r16; br.cond.sptk.few	40000000001244F0; }

l4000000000124490:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x5B,r43; (p07) br.cond.dptk.few	4000000000122F20 }

l40000000001244A0:
	{ nop.m	0x0; adds	r34,0x0,r45; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r34; (p07) br.cond.sptk.few	4000000000123CC0 }

l40000000001244C0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000122F20 }

l40000000001244D0:
	{ ld1	r14,[r34]; nop.m	0x0; adds	r34,0x2,r15; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	4000000000122F20; }

l40000000001244F0:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x0,r16; (p06) br.cond.dptk.few	4000000000124430; }

l4000000000124500:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r48; (p06) br.cond.dptk.few	4000000000122F20; }

l4000000000124510:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r34; (p07) br.cond.sptk.few	4000000000123CC0 }

l4000000000124520:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000122F20 }

l4000000000124530:
	{ adds	r15,0x10,r12; nop.m	0x0; adds	r38,0x0,r0; }
	{ st4	[r0],r15; nop.i	0x0; br.cond.sptk.few	4000000000124360 }

l4000000000124550:
	{ addp4	r14,r44,r0; shladd	r14,r14,0x3,r51; nop.i	0x0; }
	{ ld8	r15,[r14]; add	r14,r14,r15; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r14,4000000000124570; br.cond	b6; }

l4000000000124580:
	{ nop.m	0x0; adds	r39,0x0,r32; br.cond.sptk.few	4000000000122ED0 }
4000000000124590 11 00 00 00 01 00 00 00 00 02 00 00 38 7E EF 58 ............8~.X
40000000001245A0 09 70 00 10 18 10 F0 80 30 00 42 20 00 E8 01 84 .p......0.B ....
40000000001245B0 0B 70 38 6A 00 20 60 02 38 10 20 00 00 00 04 00 .p8j. `.8. .....
40000000001245C0 03 00 00 00 01 00 70 30 98 0C 28 C3 14 00 00 90 ......p0..(.....
40000000001245D0 09 00 00 00 01 C0 61 02 E0 00 42 00 00 00 04 00 ......a...B.....
40000000001245E0 10 00 98 1E 90 11 00 00 00 02 00 00 80 FD FF 48 ...............H
40000000001245F0 11 00 00 00 01 00 00 00 00 02 00 00 D8 7D EF 58 .............}.X
4000000000124600 09 70 00 10 18 10 F0 80 30 00 42 20 00 E8 01 84 .p......0.B ....
4000000000124610 0B 70 38 6A 00 20 60 02 38 10 20 00 00 00 04 00 .p8j. `.8. .....
4000000000124620 01 00 00 00 01 00 60 82 98 00 29 00 00 00 04 00 ......`...).....
4000000000124630 10 00 98 1E 90 11 00 00 00 02 00 00 30 FD FF 48 ............0..H
4000000000124640 11 00 00 00 01 00 00 00 00 02 00 00 88 7D EF 58 .............}.X
4000000000124650 09 70 00 10 18 10 F0 80 30 00 42 20 00 E8 01 84 .p......0.B ....
4000000000124660 0B 70 38 6A 00 20 60 02 38 10 20 00 00 00 04 00 .p8j. `.8. .....
4000000000124670 01 00 00 00 01 00 60 D2 98 00 29 00 00 00 04 00 ......`...).....
4000000000124680 10 00 98 1E 90 11 00 00 00 02 00 00 E0 FC FF 48 ...............H
4000000000124690 11 00 00 00 01 00 00 00 00 02 00 00 38 7D EF 58 ............8}.X
40000000001246A0 09 70 00 10 18 10 F0 80 30 00 42 20 00 E8 01 84 .p......0.B ....
40000000001246B0 0B 70 38 6A 00 20 60 02 38 10 20 00 00 00 04 00 .p8j. `.8. .....
40000000001246C0 01 00 00 00 01 00 60 22 98 00 29 00 00 00 04 00 ......`"..).....
40000000001246D0 10 00 98 1E 90 11 00 00 00 02 00 00 90 FC FF 48 ...............H
40000000001246E0 11 00 00 00 01 00 00 00 00 02 00 00 E8 7C EF 58 .............|.X
40000000001246F0 09 70 00 10 18 10 F0 80 30 00 42 20 00 E8 01 84 .p......0.B ....
4000000000124700 0B 70 38 6A 00 20 60 02 38 10 20 00 00 00 04 00 .p8j. `.8. .....
4000000000124710 01 00 00 00 01 00 60 E2 98 00 29 00 00 00 04 00 ......`...).....
4000000000124720 10 00 98 1E 90 11 00 00 00 02 00 00 40 FC FF 48 ............@..H
4000000000124730 11 00 00 00 01 00 00 00 00 02 00 00 98 7C EF 58 .............|.X
4000000000124740 09 70 00 10 18 10 F0 80 30 00 42 20 00 E8 01 84 .p......0.B ....
4000000000124750 0B 70 38 6A 00 20 60 02 38 10 20 00 00 00 04 00 .p8j. `.8. .....
4000000000124760 01 00 00 00 01 00 60 92 98 00 29 00 00 00 04 00 ......`...).....
4000000000124770 10 00 98 1E 90 11 00 00 00 02 00 00 F0 FB FF 48 ...............H
4000000000124780 11 00 00 00 01 00 00 00 00 02 00 00 48 7C EF 58 ............H|.X
4000000000124790 09 70 00 10 18 10 F0 80 30 00 42 20 00 E8 01 84 .p......0.B ....
40000000001247A0 0B 70 38 6A 00 20 60 02 38 10 20 00 00 00 04 00 .p8j. `.8. .....
40000000001247B0 01 00 00 00 01 00 60 F2 98 00 29 00 00 00 04 00 ......`...).....
40000000001247C0 10 00 98 1E 90 11 00 00 00 02 00 00 A0 FB FF 48 ...............H
40000000001247D0 11 00 00 00 01 00 00 00 00 02 00 00 F8 7B EF 58 .............{.X
40000000001247E0 09 70 00 10 18 10 F0 80 30 00 42 20 00 E8 01 84 .p......0.B ....
40000000001247F0 0B 70 38 6A 00 20 60 02 38 10 20 00 00 00 04 00 .p8j. `.8. .....
4000000000124800 01 00 00 00 01 00 60 B2 98 00 29 00 00 00 04 00 ......`...).....
4000000000124810 10 00 98 1E 90 11 00 00 00 02 00 00 50 FB FF 48 ............P..H
4000000000124820 11 00 00 00 01 00 00 00 00 02 00 00 A8 7B EF 58 .............{.X
4000000000124830 09 70 00 10 18 10 F0 80 30 00 42 20 00 E8 01 84 .p......0.B ....
4000000000124840 0B 70 38 6A 00 20 60 02 38 10 20 00 00 00 04 00 .p8j. `.8. .....
4000000000124850 01 00 00 00 01 00 60 12 98 00 29 00 00 00 04 00 ......`...).....
4000000000124860 10 00 98 1E 90 11 00 00 00 02 00 00 00 FB FF 48 ...............H
4000000000124870 11 00 00 00 01 00 00 00 00 02 00 00 58 7B EF 58 ............X{.X
4000000000124880 09 70 00 10 18 10 F0 80 30 00 42 20 00 E8 01 84 .p......0.B ....
4000000000124890 0B 70 38 6A 00 20 60 02 38 10 20 00 00 00 04 00 .p8j. `.8. .....
40000000001248A0 09 00 00 00 01 00 60 0A 98 58 40 00 00 00 04 00 ......`..X@.....
40000000001248B0 10 00 98 1E 90 11 00 00 00 02 00 00 B0 FA FF 48 ...............H
40000000001248C0 11 00 00 00 01 00 00 00 00 02 00 00 08 7B EF 58 .............{.X
40000000001248D0 09 70 00 10 18 10 F0 80 30 00 42 20 00 E8 01 84 .p......0.B ....
40000000001248E0 0B 70 38 6A 00 20 60 02 38 10 20 00 00 00 04 00 .p8j. `.8. .....
40000000001248F0 01 00 00 00 01 00 60 A2 98 00 29 00 00 00 04 00 ......`...).....
4000000000124900 10 00 98 1E 90 11 00 00 00 02 00 00 60 FA FF 48 ............`..H
4000000000124910 11 00 00 00 01 00 00 00 00 02 00 00 B8 7A EF 58 .............z.X
4000000000124920 09 70 00 10 18 10 F0 80 30 00 42 20 00 E8 01 84 .p......0.B ....
4000000000124930 0B 70 38 6A 00 20 60 02 38 10 20 00 00 00 04 00 .p8j. `.8. .....
4000000000124940 01 00 00 00 01 00 60 32 98 00 29 00 00 00 04 00 ......`2..).....
4000000000124950 10 00 98 1E 90 11 00 00 00 02 00 00 10 FA FF 48 ...............H
4000000000124960 11 00 00 00 01 00 00 00 00 02 00 00 68 7A EF 58 ............hz.X
4000000000124970 09 70 00 10 18 10 F0 80 30 00 42 20 00 E8 01 84 .p......0.B ....
4000000000124980 0B 70 38 6A 00 20 60 02 38 10 20 00 00 00 04 00 .p8j. `.8. .....
4000000000124990 01 00 00 00 01 00 60 C2 98 00 29 00 00 00 04 00 ......`...).....
40000000001249A0 10 00 98 1E 90 11 00 00 00 02 00 00 C0 F9 FF 48 ...............H

l40000000001249B0:
	{ nop.m	0x0; adds	r34,0x5,r34; br.cond.sptk.few	40000000001243A0; }

;; fn40000000001249C0: 40000000001249C0
;;   Called from:
;;     400000000012313C (in fn4000000000122C80)
;;     40000000001234AC (in fn4000000000122C80)
;;     400000000012364C (in fn4000000000122C80)
fn40000000001249C0 proc
	{ alloc	r46,ar.pfs,0x16,0x0,0x11; ld1	r14,[r35]; mov	r48,pr }
	{ adds	r47,0x0,r1; nop.m	0x0; adds	r50,0x0,r36; }
	{ cmp.eq	p06,p07,0x28,r14; mov	r45,b5; adds	r51,0x0,r0; }
	{ (p06) addl	r49,1,r0; (p07) adds	r49,0x0,r0; nop.i	0x0; }

l40000000001249F6:
	{ Invalid; nop; (p16) nop.b	0x3146C; }

l40000000001249FC:
	{ nop; zxt1	r40,r0; break.i	0x1000 }
	{ (p30) cmp.eq.unc	p58,p08,r63,r44; cmp.lt	p00,p28,r66,r65; zxt2	r23,r79 }
	{ nop; nop; (p05) mov	pr,r2,0x8400 }
	{ (p50) invala; cmp.lt	p00,p00,r32,r0; (p48) nop }

l4000000000124A30:
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x1F,r14; (p07) br.cond.dptk.few	4000000000124A70 }

l4000000000124A40:
	{ addl	r8,1,r0; nop.m	0x0; nop.i	0x0; }

l4000000000124A50:
	{ nop.m	0x0; mov	pr,r48,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r46; }
	{ nop.m	0x0; mov.spnt	b0,r45,4000000000124A60; br.ret	b0 }

l4000000000124A70:
	{ addl	r15,-5812,r1; nop.m	0x0; addp4	r14,r14,r0; }
	{ ld8	r15,[r15]; shladd	r14,r14,0x3,r15; nop.i	0x0; }
	{ ld8	r15,[r14]; add	r14,r14,r15; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r14,4000000000124AA0; br.cond	b6; }
4000000000124AB0 08 40 05 46 00 21 10 21 A5 20 70 60 22 0A 49 D0 .@.F.!.!. p`".I.
4000000000124AC0 19 58 ED 4B 2C 22 60 F8 81 0E 73 03 60 05 00 43 .X.K,"`...s.`..C
4000000000124AD0 28 32 01 44 00 21 10 03 A0 00 42 00 00 00 04 00 (2.D.!....B.....
4000000000124AE0 19 90 01 48 00 21 30 E3 03 00 48 00 E8 D2 FF 58 ...H.!0...H....X
4000000000124AF0 08 08 00 5E 00 21 00 00 00 02 00 80 05 40 00 84 ...^.!.......@..
4000000000124B00 17 00 00 00 00 48 04 10 00 80 A1 09 B0 00 00 43 .....H.........C
4000000000124B10 48 32 01 42 00 21 00 00 00 02 00 00 00 00 04 00 H2.B.!..........
4000000000124B20 09 50 FD 59 3F 23 00 00 00 02 00 00 00 00 04 00 .P.Y?#..........
4000000000124B30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000124B40 08 38 84 4C 06 34 10 03 84 00 42 40 06 30 01 84 .8.L.4....B@.0..
4000000000124B50 09 98 01 50 00 21 40 03 A8 00 42 A0 06 28 01 84 ...P.!@...B..(..
4000000000124B60 09 00 00 00 01 80 71 02 94 00 42 00 00 00 04 00 ......q...B.....
4000000000124B70 F1 38 01 56 00 21 00 00 00 02 00 00 18 E1 FF 58 .8.V.!.........X
4000000000124B80 10 08 00 5E 00 21 60 00 20 0E 73 03 50 00 00 43 ...^.!`. .s.P..C
4000000000124B90 09 00 00 00 01 00 60 0A 98 00 42 00 00 00 04 00 ......`...B.....
4000000000124BA0 11 00 00 00 01 00 70 10 99 0C 68 03 A0 FF FF 4A ......p...h....J
4000000000124BB0 10 40 01 58 00 21 60 48 B1 0E F0 03 20 FF FF 4A .@.X.!`H.... ..J
4000000000124BC0 10 00 00 00 01 00 80 08 00 00 48 00 90 FE FF 48 ..........H....H
4000000000124BD0 08 88 01 4C 00 21 20 03 88 00 42 60 06 48 01 84 ...L.! ...B`.H..
4000000000124BE0 19 A0 01 48 00 21 50 03 9C 00 42 00 A8 E0 FF 58 ...H.!P...B....X
4000000000124BF0 11 08 00 5E 00 21 60 00 20 0E F3 03 A0 FF FF 4A ...^.!`. ......J
4000000000124C00 03 40 00 00 00 21 F0 87 C1 BF 05 00 E0 02 AA 00 .@...!..........
4000000000124C10 10 00 00 00 01 00 00 68 05 80 03 80 08 00 84 00 .......h........
4000000000124C20 08 30 A8 40 87 39 70 0A 8C 00 42 00 00 00 04 00 .0.@.9p...B.....
4000000000124C30 19 88 88 42 10 34 B0 DA 97 58 44 03 A0 03 00 43 ...B.4...XD....C
4000000000124C40 08 18 FD 47 3F 23 00 00 00 02 00 00 00 00 04 00 ...G?#..........
4000000000124C50 08 88 01 4E 00 21 20 03 90 00 42 00 00 00 04 00 ...N.! ...B.....
4000000000124C60 19 98 F1 01 00 24 64 02 84 00 42 00 68 D1 FF 58 .....$d...B.h..X
4000000000124C70 08 00 00 00 01 00 84 FA 23 7E 46 20 00 78 01 84 ........#~F .x..
4000000000124C80 19 00 00 00 01 00 C0 02 20 00 C2 08 E0 00 00 43 ........ ......C
4000000000124C90 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000124CA0 08 88 01 42 00 21 20 03 98 00 42 60 06 38 01 84 ...B.! ...B`.8..
4000000000124CB0 19 A0 01 50 00 21 50 03 94 00 42 00 D8 DF FF 58 ...P.!P...B....X
4000000000124CC0 11 08 00 5E 00 21 70 00 20 0C 73 03 80 00 00 42 ...^.!p. .s....B
4000000000124CD0 08 88 01 4C 00 21 20 03 88 00 42 60 06 48 01 84 ...L.! ...B`.H..
4000000000124CE0 18 A0 01 48 00 21 70 08 99 0C 68 03 40 02 00 42 ...H.!p...h.@..B
4000000000124CF0 11 A8 01 56 00 21 A0 02 AC 00 42 00 98 DF FF 58 ...V.!....B....X
4000000000124D00 10 08 00 5E 00 21 60 00 20 0E 73 03 00 FF FF 4A ...^.!`. .s....J
4000000000124D10 08 88 01 4C 00 21 20 03 88 00 42 60 06 18 01 84 ...L.! ...B`....
4000000000124D20 19 A0 01 48 00 21 50 03 A8 00 42 00 68 DF FF 58 ...H.!P...B.h..X
4000000000124D30 11 08 00 5E 00 21 60 00 20 0E 73 03 D0 FE FF 4A ...^.!`. .s....J
4000000000124D40 09 00 00 00 01 00 60 0A 98 00 42 00 00 00 04 00 ......`...B.....
4000000000124D50 11 00 00 00 01 00 70 10 99 0C 68 03 50 FF FF 4A ......p...h.P..J
4000000000124D60 08 38 01 58 00 21 60 48 B1 0E 70 40 06 20 01 84 .8.X.!`H..p@. ..
4000000000124D70 19 98 F1 01 00 24 64 02 84 00 42 03 D0 FC FF 4B .....$d...B....K
4000000000124D80 11 88 01 4E 00 21 00 00 00 02 00 00 48 D0 FF 58 ...N.!......H..X
4000000000124D90 08 00 00 00 01 00 10 00 BC 00 42 80 05 40 00 84 ..........B..@..
4000000000124DA0 18 00 00 00 01 00 84 FA 23 7E 46 08 00 FF FF 4A ........#~F....J
4000000000124DB0 10 00 00 00 01 00 00 00 00 02 00 00 B0 FF FF 48 ...............H
4000000000124DC0 11 38 88 42 06 34 00 00 00 02 80 03 80 FC FF 4B .8.B.4.........K
4000000000124DD0 C8 58 05 46 00 A1 81 02 84 00 42 00 00 00 04 00 .X.F......B.....
4000000000124DE0 C3 50 ED 4B 2C 22 00 00 00 02 00 C0 04 58 01 84 .P.K,".......X..
4000000000124DF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000124E00 08 88 01 4C 00 21 00 00 00 02 00 40 06 20 01 84 ...L.!.....@. ..
4000000000124E10 19 98 F1 01 00 24 00 00 00 02 00 00 B8 CF FF 58 .....$.........X
4000000000124E20 08 08 00 5E 00 21 70 02 20 00 42 60 06 30 01 84 ...^.!p. .B`.0..
4000000000124E30 09 A8 01 4A 00 21 10 03 84 00 42 40 06 40 01 84 ...J.!....B@.@..
4000000000124E40 11 A0 FD 11 3F 23 60 02 9C 00 42 00 48 DE FF 58 ....?#`...B.H..X
4000000000124E50 11 30 00 10 87 39 10 00 BC 00 42 03 40 01 00 43 .0...9....B.@..C
4000000000124E60 10 00 00 00 01 00 70 48 9D 0C 70 03 A0 FF FF 4A ......pH..p....J
4000000000124E70 09 48 84 50 08 34 00 00 00 02 00 C0 01 00 00 84 .H.P.4..........
4000000000124E80 09 30 00 1C 87 39 00 00 00 02 00 A4 06 28 01 84 .0...9.......(..
4000000000124E90 10 00 00 00 01 40 52 03 A8 00 42 03 40 00 00 43 .....@R...B.@..C
4000000000124EA0 09 00 00 00 01 00 80 0A A0 00 42 00 00 00 04 00 ..........B.....
4000000000124EB0 10 00 00 00 01 00 70 10 A1 0C E8 03 90 FB FF 4B ......p........K
4000000000124EC0 10 00 00 00 01 00 60 02 AC 00 42 00 40 FF FF 48 ......`...B.@..H
4000000000124ED0 08 88 01 50 00 21 20 03 88 00 42 60 06 48 01 84 ...P.! ...B`.H..
4000000000124EE0 19 A0 01 48 00 21 80 0A A0 00 42 00 A8 DD FF 58 ...H.!....B....X
4000000000124EF0 11 30 00 10 87 39 10 00 BC 00 42 03 10 FD FF 4B .0...9....B....K
4000000000124F00 10 00 00 00 01 00 70 10 A1 0C 68 03 C0 FF FF 4A ......p...h....J
4000000000124F10 10 00 00 00 01 00 00 00 00 02 00 00 30 FB FF 48 ............0..H
4000000000124F20 11 A8 01 4A 00 21 00 00 00 02 00 00 68 DD FF 58 ...J.!......h..X
4000000000124F30 11 08 00 5E 00 21 60 00 20 0E 73 03 D0 FC FF 4A ...^.!`. .s....J
4000000000124F40 08 30 98 42 07 38 A0 02 94 00 42 20 06 30 01 84 .0.B.8....B .0..
4000000000124F50 19 90 01 44 00 21 30 03 8C 00 42 03 F0 FD FF 4B ...D.!0...B....K
4000000000124F60 11 A0 01 48 00 21 50 03 A8 00 42 00 28 DD FF 58 ...H.!P...B.(..X
4000000000124F70 10 08 00 5E 00 21 60 00 20 0E 73 03 90 FC FF 4A ...^.!`. .s....J
4000000000124F80 10 00 00 00 01 00 00 00 00 02 00 00 C0 FD FF 48 ...............H
4000000000124F90 02 48 84 50 08 34 E0 08 00 00 48 A4 06 28 01 84 .H.P.4....H..(..
4000000000124FA0 19 30 00 1C 87 39 00 00 00 02 80 03 00 FF FF 4A .0...9.........J
4000000000124FB0 28 A9 01 54 00 21 00 00 00 02 00 00 00 00 04 00 (..T.!..........
4000000000124FC0 11 00 00 00 01 00 00 00 00 02 00 00 10 FF FF 48 ...............H
4000000000124FD0 08 88 01 42 00 21 20 03 88 00 42 60 06 40 00 84 ...B.! ...B`.@..
4000000000124FE0 19 A0 01 48 00 21 50 03 94 00 42 00 A8 DC FF 58 ...H.!P...B....X
4000000000124FF0 08 08 00 5E 00 21 70 00 20 0C 73 E0 14 18 01 84 ...^.!p. .s.....
4000000000125000 19 88 88 42 10 34 30 FA 8F 7E C6 03 00 FC FF 4B ...B.40..~.....K
4000000000125010 10 00 00 00 01 00 B0 DA 97 58 44 00 40 FC FF 48 .........XD.@..H
4000000000125020 08 88 01 42 00 21 20 03 88 00 42 60 06 40 00 84 ...B.! ...B`.@..
4000000000125030 19 A0 01 48 00 21 50 03 94 00 42 00 58 DC FF 58 ...H.!P...B.X..X
4000000000125040 08 08 00 5E 00 21 60 00 20 0E 73 00 15 18 01 84 ...^.!`. .s.....
4000000000125050 19 88 90 52 10 38 30 11 85 24 68 03 B0 FB FF 4B ...R.80..$h....K
4000000000125060 10 00 00 00 01 00 B0 DA 97 58 44 00 70 FA FF 48 .........XD.p..H

l4000000000125070:
	{ ld1	r39,[r36]; adds	r49,0xFFFFFFFFFFFFFFFF,r35; adds	r50,0x0,r33 }
	{ ld1	r38,[r34]; st1	[r0],r34; nop.i	0x0; }
	{ st1	[r0],r36; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B440; }
	{ cmp4.eq	p07,p06,0x0,r8; st1	[r39],r36; adds	r1,0x0,r47 }
	{ st1	[r38],r34; (p06) addl	r8,1,r0; nop.i	0x0; }

l40000000001250BC:
	{ Invalid; mov	pr,r32,0x0; zxt1	r0,r64 }

l40000000001250CC:
	{ (p12) nop; break.i	0x1000; break.b	0x1000 }
40000000001250D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001250E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001250F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000125100: 4000000000125100
;;   Called from:
;;     400000000012727C (in internal_wstrmatch)
fn4000000000125100 proc
	{ alloc	r55,ar.pfs,0x20,0x0,0x1A; adds	r12,0xFFFFFFFFFFFFFFE0,r12; mov	r57,pr }
	{ and	r47,0x20,r36; cmp.eq	p06,p07,0x0,r32; and	r46,0x2,r36; }
	{ addl	r49,-5772,r1; cmp.eq.or.andcm	p06,p07,0x0,r34; adds	r56,0x0,r1 }
	{ addl	r44,6400,r1; adds	r38,0x0,r32; addl	r45,6408,r1; }
	{ nop.m	0x0; tnat.z	p16,p17,r36; nop.b	0x0 }
	{ ld8	r49,[r49]; cmp4.eq	p18,p19,0x0,r47; cmp4.eq	p21,p20,0x0,r46; }
	{ nop.m	0x0; tnat.z	p24,p25,r36; tnat.z	p26,p27,r36; }
	{ nop.m	0x0; mov	r54,b6; (p06) br.cond.dpnt.few	4000000000125460; }

l4000000000125180:
	{ nop.m	0x0; cmp.ltu	p07,p06,r34,r35; (p06) br.cond.dpnt.few	4000000000126890 }

l4000000000125190:
	{ nop.m	0x0; adds	r42,0x0,r34; nop.i	0x0; }
	{ ld4	r37,[r42],4; nop.i	0x0; (p16) br.cond.dptk.few	40000000001251F0; }

l40000000001251B0:
	{ adds	r58,0x0,r37; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B780; }
	{ adds	r1,0x0,r56; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	40000000001251F0 }

l40000000001251D0:
	{ adds	r58,0x0,r37; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A760; }
	{ nop.m	0x0; adds	r1,0x0,r56; adds	r37,0x0,r8 }

l40000000001251F0:
	{ cmp.ltu	p23,p22,r38,r33; (p23) ld4	r39,[r38]; nop.i	0x0; }

l40000000001251FC:
	{ invala; cmp4.ge.or.andcm	p00,p00,r0,r0; (p04) chk.s.i	r0,3FFFFFFFFF5451FC }

l400000000012520C:
	{ (p01) nop; cmp.lt	p00,p00,r32,r0; (p01) rfi }

l4000000000125210:
	{ nop.m	0x0; ld4	r14,[r42]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x28,r14; (p07) br.cond.dpnt.few	40000000001255A0; }

l4000000000125230:
	{ cmp4.eq	p06,p07,0x3F,r37; nop.m	0x0; nop.i	0x0 }

l4000000000125240:
	{ nop.m	0x0; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000125B60; }

l4000000000125250:
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x3F,r37; (p06) br.cond.dptk.few	40000000001254A0; }

l4000000000125260:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2A,r37; (p06) br.cond.dpnt.few	4000000000125650 }

l4000000000125270:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dptk.few	40000000001252C0 }

l4000000000125280:
	{ adds	r58,0x0,r39; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B780; }
	{ adds	r1,0x0,r56; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	40000000001252C0 }

l40000000001252A0:
	{ adds	r58,0x0,r39; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A760; }
	{ nop.m	0x0; adds	r1,0x0,r56; adds	r39,0x0,r8; }

l40000000001252C0:
	{ nop.m	0x0; cmp4.eq	p07,p06,r39,r37; (p06) br.cond.dpnt.few	4000000000125460 }

l40000000001252D0:
	{ adds	r34,0x0,r42; nop.m	0x0; nop.i	0x0; }

l40000000001252E0:
	{ adds	r38,0x4,r38; cmp.ltu	p06,p07,r34,r35; (p06) br.cond.dptk.few	4000000000125190; }

l40000000001252F0:
	{ cmp.eq	p06,p07,r38,r33; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000125950; }

l4000000000125300:
	{ nop.m	0x0; tbit.z	p06,p07,r36,0x3; (p06) br.cond.dptk.few	4000000000125460 }

l4000000000125310:
	{ ld4	r14,[r38]; nop.m	0x0; addl	r8,1,r0; }
	{ cmp4.eq	p06,p07,0x2F,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000125950; }

l4000000000125330:
	{ nop.m	0x0; mov	pr,r57,0xFFFFFFFFFFFFFFFE; nop.i	0x0; }
	{ nop.m	0x0; mov.i	ar.pfs,r55; mov.spnt	b0,r54,4000000000125340 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0 }

l4000000000125360:
	{ adds	r14,0x8,r43; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x3D,r14; (p06) br.cond.dptk.few	4000000000125FB0 }

l4000000000125380:
	{ adds	r14,0xC,r43; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5D,r14; (p06) br.cond.dptk.few	4000000000125FB0 }

l40000000001253A0:
	{ nop.m	0x0; adds	r14,0x4,r43; nop.i	0x0; }
	{ ld4	r37,[r14]; nop.i	0x0; (p16) br.cond.dptk.few	4000000000125400; }

l40000000001253C0:
	{ adds	r58,0x0,r37; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B780; }
	{ adds	r1,0x0,r56; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	4000000000125400 }

l40000000001253E0:
	{ adds	r58,0x0,r37; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A760; }
	{ nop.m	0x0; adds	r1,0x0,r56; adds	r37,0x0,r8; }

l4000000000125400:
	{ adds	r14,0x20,r12; cmp4.eq	p07,p06,r39,r37; adds	r34,0x14,r43; }
	{ st4	[r37],r14; adds	r14,0x10,r43; (p07) br.cond.dpnt.few	4000000000126970; }

l4000000000125420:
	{ nop.m	0x0; ld4	r37,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r37; (p06) br.cond.dptk.few	4000000000125F10; }

l4000000000125440:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x5B,r39; (p06) br.cond.dpnt.few	4000000000126750; }

l4000000000125450:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000125460:
	{ addl	r8,1,r0; nop.m	0x0; nop.i	0x0; }

l4000000000125470:
	{ nop.m	0x0; mov	pr,r57,0xFFFFFFFFFFFFFFFE; nop.i	0x0; }
	{ nop.m	0x0; mov.i	ar.pfs,r55; mov.spnt	b0,r54,4000000000125480 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0 }

l40000000001254A0:
	{ cmp4.eq	p06,p07,0x5B,r37; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000125BE0; }

l40000000001254B0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x5C,r37; (p07) br.cond.dptk.few	4000000000125270; }

l40000000001254C0:
	{ cmp.eq	p06,p07,r42,r35; (p06) br.cond.dpnt.few	4000000000125460; (p20) br.cond.dptk.few	4000000000126610 }

l40000000001254CC:
	{ (p10) cmpxchg2.acq	r2,[r33],r0; (p04) nop; (p04) rfi }

l40000000001254D0:
	{ adds	r34,0x8,r34; ld4	r37,[r42]; nop.i	0x0; }
	{ cmp.ltu	p06,p07,r35,r34; (p06) br.cond.dpnt.few	4000000000125460; (p16) br.cond.dptk.few	4000000000125570 }

l40000000001254EC:
	{ (p04) cmpxchg4.acq	r0,[r33],r0; zxt1	r32,r64; break.b	0x1000 }

l40000000001254F0:
	{ adds	r58,0x0,r37; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B780; }
	{ adds	r1,0x0,r56; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	4000000000125530 }

l4000000000125510:
	{ adds	r58,0x0,r37; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A760; }
	{ nop.m	0x0; adds	r1,0x0,r56; adds	r37,0x0,r8 }

l4000000000125530:
	{ adds	r58,0x0,r39; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B780; }
	{ adds	r1,0x0,r56; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	4000000000125570 }

l4000000000125550:
	{ adds	r58,0x0,r39; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A760; }
	{ nop.m	0x0; adds	r1,0x0,r56; adds	r39,0x0,r8; }

l4000000000125570:
	{ cmp4.eq	p07,p06,r37,r39; adds	r38,0x4,r38; (p06) br.cond.dpnt.few	4000000000125460; }

l4000000000125580:
	{ nop.m	0x0; cmp.ltu	p06,p07,r34,r35; (p06) br.cond.dptk.few	4000000000125190 }

l4000000000125590:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000001252F0; }

l40000000001255A0:
	{ adds	r14,0xFFFFFFFFFFFFFFD6,r37; cmp4.eq	p06,p07,0x3F,r37; cmp4.ltu	p09,p08,0x1,r14; }
	{ (p06) cmp4.eq.or.andcm	p08,p09,0x0,r0; nop.i	0x0; (p08) br.cond.dpnt.few	40000000001255E0; }

l40000000001255C0:
	{ nop.m	0x0; cmp4.eq	p08,p09,0x40,r37; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p08,p09,0x21,r37; (p09) br.cond.dptk.few	4000000000125240 }

l40000000001255E0:
	{ cmp.eq	p07,p06,r38,r32; adds	r58,0x0,r37; adds	r59,0x0,r38 }
	{ adds	r60,0x0,r33; adds	r61,0x0,r42; adds	r62,0x0,r35; }
	{ nop.m	0x0; (p06) and	r36,0xFFFFFFFFFFFFFFFB,r36; nop.i	0x0; }

l400000000012560C:
	{ cmp.eq	p00,p17,r1,r0; zxt1	r0,r64; break.i	0x1000 }
	{ (p29) nop; cmp.eq	p00,p16,r14,r64; (p31) nop }
	{ (p27) break.m	0x1540; break.i	0x1000; (p32) break.b	0xC002D }
	{ shladdp4	r0,r1,0x1,r0; zxt1	r8,r64; add	r0,r32,r0 }
	{ cmp.eq	p00,p17,r33,r0; Invalid; (p02) mov	pr,r41,0x5000 }

l4000000000125650:
	{ cmp.eq	p07,p06,r42,r35; tnat.z	p20,p21,r36; (p07) br.cond.dpnt.few	4000000000125950; }

l4000000000125660:
	{ nop.m	0x0; tbit.z	p06,p07,r36,0x2; (p06) br.cond.dptk.few	4000000000125680; }

l4000000000125670:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r39; (p07) br.cond.dpnt.few	40000000001266E0 }

l4000000000125680:
	{ ld4	r14,[r42]; adds	r37,0x8,r34; cmp4.eq	p07,p06,0x2A,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x3F,r14; (p06) br.cond.dpnt.few	4000000000125730; }

l40000000001256A0:
	{ nop.m	0x0; nop.i	0x0; (p20) br.cond.dptk.few	40000000001256C0; }

l40000000001256B0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2F,r39; (p06) br.cond.dpnt.few	4000000000125460; }

l40000000001256C0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x3F,r14; (p18) br.cond.dptk.few	4000000000125A80 }

l40000000001256D0:
	{ nop.m	0x0; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000125AC0; }

l40000000001256E0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2A,r14; (p07) br.cond.dpnt.few	4000000000125990; }

l40000000001256F0:
	{ cmp.eq	p06,p07,r37,r35; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000125950; }

l4000000000125700:
	{ ld4	r14,[r37],4; cmp4.eq	p06,p07,0x3F,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x2A,r14; (p06) br.cond.dptk.few	40000000001256A0 }

l4000000000125720:
	{ cmp.ltu	p23,p22,r38,r33; nop.m	0x0; nop.i	0x0; }

l4000000000125730:
	{ adds	r41,0x0,r14; tbit.z	p07,p06,r36,0x1; (p06) br.cond.dptk.few	4000000000125760; }

l4000000000125740:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5C,r14; nop.i	0x0; }
	{ (p07) ld4	r41,[r37]; nop.m	0x0; nop.i	0x0 }

l4000000000125756:
	{ break.m	0x4000; nop; break.i	0x80000 }

l4000000000125760:
	{ nop.m	0x0; cmp4.eq	p19,p18,0x0,r47; and	r36,0xFFFFFFFFFFFFFFFB,r36 }

l4000000000125762:
	{ chk.a.nc	r32,4000000000D25762; (p48) nop; Invalid }

l4000000000125766:
	{ Invalid; (p18) nop; break.b	0x80000 }

l4000000000125768:
	{ (p37) addl	r100,-992740,r0; (p04) break.f	0x1988B; Invalid }

l400000000012576E:
	{ (p05) break.m	0x331; (p04) nop; (p20) nop; }

l4000000000125774:
	{ nop; (p12) break.i	0x60087; (p04) extr.u	r10,r58,0,1; }

l400000000012577A:
	{ (p03) break.m	0x100C01; (p05) nop; (p02) break.b	0x1; }

l400000000012577E:
	{ Invalid; (p01) break.i	0x210; (p04) nop }
	{ (p07) break.m	0x10B; Invalid; (p01) fpma.s0	f16,f4,f0,f4; }
	{ (p32) break.m	0x310; (p04) dep	r0,r0,r24,63,1; Invalid; }
	{ (p16) break.m	0x228; (p04) break.i	0x0; (p04) dep	r0,r0,r0,1,15 }
	{ (p07) break.m	0x10B; (p04) cmp.lt	p00,p00,r0,r4; (p01) fcmp.eq	p16,p01,f4,f4; }
	{ (p32) nop; (p61) nop; Invalid }
	{ (p16) break.m	0x228; (p04) break.i	0x0; (p04) chk.s.i	r32,4000000000525FDE }
	{ (p24) nop; (p01) break.i	0x101; sxt1	r0,r1 }
	{ (p16) cmpxchg1.acq	r40,[r104],r4; (p01) break.i	0x210; (p04) dep	r0,r0,r0,1,2 }
	{ (p07) cmp.lt	p11,p00,r4,r4; (p01) ld1	r16,[r24]; (p28) nop; }
	{ (p16) cmpxchg1.acq	r40,[r104],r4; (p01) break.i	0x210; (p04) dep	r0,r0,r0,2,3 }
	{ (p07) break.m	0x12B; (p04) cmp.lt	p00,p00,r0,r4; (p01) fcmp.eq	p16,p01,f4,f4; }
	{ (p32) break.m	0x210; (p04) dep	r0,r0,r24,21,1; Invalid }
	{ (p24) break.m	0x128; (p04) nop; (p01) break.i	0x210 }
	{ Invalid; (p63) nop }
	{ Invalid; Invalid; Invalid }
	{ (p48) cmp.ltu	p60,p01,r6,r104; (p33) break.f	0x101; (p04) nop }
	{ (p24) nop; (p01) break.i	0x101; (p04) nop }
	{ (p07) cmp.lt	p11,p00,r4,r4; (p01) ld1	r16,[r28]; (p24) nop; }
	{ (p16) break.m	0x228; (p04) break.i	0x0; czx1.r	r0,r1 }
	{ (p24) nop; (p01) break.i	0x101; sxt1	r0,r1 }
	{ (p16) cmpxchg1.acq	r40,[r104],r4; (p01) break.i	0x210; (p04) shrp	r0,r0,r0,46 }
	{ (p07) cmp.lt	p11,p00,r4,r4; (p01) ld1	r16,[r24]; (p28) nop; }
	{ (p16) cmpxchg1.acq	r40,[r104],r4; (p01) break.i	0x210; (p04) dep	r0,r0,r0,6,15 }
	{ (p07) break.m	0x12B; (p04) cmp.lt	p00,p00,r0,r4; (p01) fcmp.eq	p16,p01,f4,f4; }
	{ (p32) break.m	0x230; (p04) dep	r0,r0,r28,21,1; (p25) nop }
	{ Invalid; Invalid; Invalid }
	{ Invalid; (p01) nop; (p01) nop; }
	{ Invalid; Invalid; Invalid }
	{ Invalid; Invalid; Invalid }

l4000000000125950:
	{ adds	r8,0x0,r0; nop.m	0x0; nop.i	0x0; }

l4000000000125960:
	{ nop.m	0x0; mov	pr,r57,0xFFFFFFFFFFFFFFFE; nop.i	0x0; }
	{ nop.m	0x0; mov.i	ar.pfs,r55; mov.spnt	b0,r54,4000000000125970 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0 }

l4000000000125990:
	{ nop.m	0x0; ld4	r14,[r37]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x28,r14; (p06) br.cond.dptk.few	40000000001256F0; }

l40000000001259B0:
	{ nop.m	0x0; cmp.ltu	p06,p07,r38,r33; (p07) br.cond.dpnt.few	4000000000125A30; }

l40000000001259C0:
	{ (p06) adds	r40,0x0,r38; nop.m	0x0; nop.i	0x0; }

l40000000001259C6:
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ break.m	0x4000; nop; (p48) nop }

l40000000001259E0:
	{ adds	r59,0x0,r40; addl	r58,42,r0; adds	r40,0x4,r40 }

l40000000001259E2:
	{ nop; (p05) padd4	r0,r0,r18; cmp.eq	p10,p02,r64,r48; }
	{ (p16) chk.a.clr	f8,3FFFFFFFFF52DDF2; (p16) mov.sptk	b1,r64,4000000000124A02; (p48) nop; }
	{ break.m	0x42009; addl	r32,0,r0; (p31) nop; }
	{ invala; add	r14,r64,r80,0x1; Invalid }

l4000000000125A20:
	{ nop.m	0x0; cmp.ltu	p06,p07,r40,r33; (p06) br.cond.dptk.few	40000000001259E0 }

l4000000000125A30:
	{ adds	r58,0x4,r37; nop.m	0x0; adds	r59,0x0,r35 }
	{ adds	r60,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,fn40000000001221C0; }
	{ nop.m	0x0; adds	r1,0x0,r56; adds	r37,0x0,r8 }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000001256F0 }

l4000000000125A70:
	{ nop.m	0x0; adds	r8,0x0,r0; br.cond.sptk.few	4000000000125960 }

l4000000000125A80:
	{ nop.m	0x0; nop.i	0x0; (p06) br.cond.dptk.few	40000000001256F0; }

l4000000000125A90:
	{ cmp4.eq	p06,p07,0x0,r39; adds	r38,0x4,r38; (p06) br.cond.dpnt.few	4000000000125460; }

l4000000000125AA0:
	{ cmp.ltu	p07,p06,r38,r33; (p07) ld4	r39,[r38]; nop.i	0x0; }

l4000000000125AAC:
	{ invala; cmp4.eq.or.andcm	p00,p00,r32,r0; zxt1	r0,r64 }

l4000000000125ABC:
	{ (p34) nop; cmp.lt	p00,p00,r32,r0; Invalid }

l4000000000125AC0:
	{ nop.m	0x0; ld4	r14,[r37]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x28,r14; (p06) br.cond.dptk.few	4000000000125A90; }

l4000000000125AE0:
	{ nop.m	0x0; cmp.ltu	p07,p06,r38,r33; (p06) br.cond.dpnt.few	4000000000125460; }

l4000000000125AF0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000125B00:
	{ adds	r59,0x0,r38; addl	r58,63,r0; adds	r38,0x4,r38 }
	{ adds	r60,0x0,r33; adds	r61,0x0,r37; adds	r62,0x0,r35; }
	{ adds	r63,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,fn40000000001269C0; }
	{ cmp4.eq	p06,p07,0x0,r8; adds	r1,0x0,r56; (p06) br.cond.dpnt.few	4000000000125950; }

l4000000000125B40:
	{ nop.m	0x0; cmp.ltu	p06,p07,r38,r33; (p06) br.cond.dptk.few	4000000000125B00 }

l4000000000125B50:
	{ nop.m	0x0; addl	r8,1,r0; br.cond.sptk.few	4000000000125470; }

l4000000000125B60:
	{ cmp4.eq	p07,p06,0x0,r39; (p07) br.cond.dpnt.few	4000000000125460; (p24) br.cond.dptk.few	4000000000125B80; }

l4000000000125B6C:
	{ (p01) invala; cmp.lt	p00,p00,r32,r0; (p48) mov	pr,r105,0xE6D6 }

l4000000000125B70:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2F,r39; (p06) br.cond.dpnt.few	4000000000125460 }

l4000000000125B80:
	{ nop.m	0x0; nop.i	0x0; (p26) br.cond.dptk.few	40000000001252D0; }

l4000000000125B90:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r39; (p06) br.cond.dptk.few	40000000001252D0; }

l4000000000125BA0:
	{ cmp.eq	p06,p07,r38,r32; (p06) br.cond.dpnt.few	4000000000125460; (p24) br.cond.dptk.few	40000000001252D0 }

l4000000000125BAC:
	{ (p57) cmp.lt.unc	p62,p09,r63,r37; zxt2	r95,r79; br.cond.sptk.few	4000000000125DAC }

l4000000000125BB0:
	{ adds	r14,0xFFFFFFFFFFFFFFFC,r38; nop.m	0x0; adds	r34,0x0,r42; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x2F,r14; (p06) br.cond.dpnt.few	4000000000125460; br.cond.sptk.few	40000000001252E0; }

l4000000000125BDC:
	{ (p56) nop; cmp.lt	p00,p00,r32,r0; (p32) nop }

l4000000000125BE0:
	{ nop.m	0x0; cmp.eq	p06,p07,r38,r33; nop.i	0x0; }
	{ cmp4.eq.or.andcm	p06,p07,0x0,r39; (p06) br.cond.dpnt.few	4000000000125460; (p26) br.cond.dpnt.few	4000000000125C10; }

l4000000000125BFC:
	{ (p01) invala; cmp.eq	p00,p00,r32,r0; (p32) mov	pr,r73,0xE6D6 }

l4000000000125C00:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r39; (p07) br.cond.dpnt.few	40000000001266A0 }

l4000000000125C10:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dptk.few	4000000000125C60 }

l4000000000125C20:
	{ adds	r58,0x0,r39; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B780; }
	{ adds	r1,0x0,r56; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	4000000000125C60 }

l4000000000125C40:
	{ adds	r58,0x0,r39; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A760; }
	{ nop.m	0x0; adds	r1,0x0,r56; adds	r39,0x0,r8; }

l4000000000125C60:
	{ ld4	r37,[r42]; adds	r52,0xFFFFFFFFFFFFFFFF,r39; adds	r50,0x1,r39; }
	{ cmp4.eq	p06,p07,0x5E,r37; cmp4.eq	p08,p09,0x21,r37; (p06) addl	r14,1,r0 }

l4000000000125C80:
	{ (p08) addl	r48,1,r0; (p07) adds	r14,0x0,r0; (p09) adds	r48,0x0,r0; }

l4000000000125C86:
	{ (p07) chk.s	f0,40000000001A5C86; (p24) nop; nop; }

l4000000000125C8C:
	{ Invalid; Invalid; Invalid }

l4000000000125C90:
	{ or	r48,r48,r14; cmp4.eq	p06,p07,0x0,r48; nop.i	0x0; }
	{ (p07) adds	r43,0x8,r34; (p07) ld4	r37,[r43]; (p06) adds	r43,0x0,r42 }

l4000000000125CA6:
	{ (p18) adds	r0,0xFFFFFFFFFFFFF02B,r16; (p21) nop; Invalid; }

l4000000000125CAC:
	{ cmp.lt	p42,p11,r0,r66; (p06) movl	r0,0x39874F7C100800; }

l4000000000125CB0:
	{ cmp4.eq	p06,p07,0x5F,r39; (p07) adds	r51,0x0,r0; adds	r43,0x4,r43; }

l4000000000125CBC:
	{ (p02) nop; (p48) nop; }

l4000000000125CC6:
	{ (p03) chk.a.clr	f91,3FFFFFFFFFDE8F16; nop; break.b	0x80000 }

l4000000000125CD0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000125CE0:
	{ nop.m	0x0; nop.i	0x0; (p20) br.cond.dptk.few	4000000000125D00; }

l4000000000125CF0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5C,r37; (p07) br.cond.dpnt.few	4000000000125FC0 }

l4000000000125D00:
	{ adds	r40,0x0,r37; nop.m	0x0; nop.i	0x0 }

l4000000000125D10:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dptk.few	4000000000125D60; }

l4000000000125D20:
	{ adds	r58,0x0,r40; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B780; }
	{ adds	r1,0x0,r56; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	4000000000125D60 }

l4000000000125D40:
	{ adds	r58,0x0,r40; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A760; }
	{ nop.m	0x0; adds	r1,0x0,r56; adds	r40,0x0,r8 }

l4000000000125D60:
	{ adds	r41,0x0,r43; cmp4.eq	p07,p06,0x0,r37; (p07) br.cond.dpnt.few	4000000000125440; }

l4000000000125D70:
	{ nop.m	0x0; ld4	r37,[r41],4; nop.i	0x0; }
	{ nop.m	0x0; adds	r34,0x0,r41; (p16) br.cond.dptk.few	4000000000125DD0 }

l4000000000125D90:
	{ adds	r58,0x0,r37; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B780; }
	{ adds	r1,0x0,r56; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	4000000000125DD0 }

l4000000000125DB0:
	{ adds	r58,0x0,r37; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A760; }
	{ nop.m	0x0; adds	r1,0x0,r56; adds	r37,0x0,r8 }

l4000000000125DD0:
	{ nop.m	0x0; nop.i	0x0; (p24) br.cond.dptk.few	4000000000125DF0; }

l4000000000125DE0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2F,r37; (p06) br.cond.dpnt.few	4000000000125460; }

l4000000000125DF0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r37; (p06) br.cond.dptk.few	4000000000126040 }

l4000000000125E00:
	{ nop.m	0x0; ld4	r41,[r41]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x5D,r41; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000126040; }

l4000000000125E20:
	{ adds	r34,0x8,r43; cmp4.eq	p07,p06,0x0,r46; (p06) br.cond.dptk.few	4000000000125E40; }

l4000000000125E30:
	{ cmp4.eq	p07,p06,0x5C,r41; (p07) ld4	r41,[r34]; (p07) adds	r34,0xC,r43; }

l4000000000125E3C:
	{ (p06) cmp.lt	p43,p17,r0,r66; break.x	0x1CC3A900001000 }

l4000000000125E40:
	{ cmp4.eq	p06,p07,0x0,r41; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000125460; }

l4000000000125E50:
	{ ld4	r37,[r34]; cmp4.eq	p06,p07,0x5B,r41; (p06) br.cond.dpnt.few	4000000000125FE0 }

l4000000000125E60:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dptk.few	4000000000125EB0 }

l4000000000125E70:
	{ adds	r58,0x0,r41; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B780; }
	{ adds	r1,0x0,r56; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	4000000000125EB0 }

l4000000000125E90:
	{ adds	r58,0x0,r41; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A760; }
	{ nop.m	0x0; adds	r1,0x0,r56; adds	r41,0x0,r8; }

l4000000000125EB0:
	{ cmp4.eq	p06,p07,r41,r40; adds	r34,0x4,r34; nop.i	0x0 }
	{ addl	r58,6400,r1; addl	r59,6408,r1; (p06) br.cond.dpnt.few	4000000000126040; }

l4000000000125ED0:
	{ nop.m	0x0; st4	[r40],r44; nop.i	0x0 }
	{ st4	[r41],r45; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A620; }
	{ cmp4.lt	p07,p06,0x0,r8; adds	r1,0x0,r56; (p06) br.cond.spnt.few	4000000000126050; }

l4000000000125F00:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x5D,r37; (p06) br.cond.dpnt.few	4000000000126100 }

l4000000000125F10:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dptk.few	4000000000125F60 }

l4000000000125F20:
	{ adds	r58,0x0,r37; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B780; }
	{ adds	r1,0x0,r56; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	4000000000125F60 }

l4000000000125F40:
	{ adds	r58,0x0,r37; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A760; }
	{ nop.m	0x0; adds	r1,0x0,r56; adds	r37,0x0,r8; }

l4000000000125F60:
	{ adds	r43,0x0,r34; cmp4.eq	p07,p06,0x5B,r37; (p06) br.cond.dptk.few	4000000000125CE0; }

l4000000000125F70:
	{ nop.m	0x0; ld4	r14,[r43]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x3D,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000125360; }

l4000000000125F90:
	{ cmp4.eq	p07,p06,0x3A,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000126140; }

l4000000000125FA0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r14; (p07) br.cond.dpnt.few	4000000000126650 }

l4000000000125FB0:
	{ nop.m	0x0; addl	r40,91,r0; br.cond.sptk.few	4000000000125D10; }

l4000000000125FC0:
	{ ld4	r40,[r43]; nop.m	0x0; adds	r43,0x4,r43; }
	{ cmp4.eq	p06,p07,0x0,r40; (p06) br.cond.dpnt.few	4000000000125460; br.cond.sptk.few	4000000000125D10; }

l4000000000125FDC:
	{ (p42) invala; cmp.eq	p00,p00,r32,r0; (p32) mov	pr,r73,0xE656 }

l4000000000125FE0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r37; (p06) br.cond.dptk.few	4000000000125E60 }

l4000000000125FF0:
	{ adds	r58,0x0,r34; adds	r59,0x20,r12; br.call.sptk.many	b0,fn40000000001225C0; }
	{ adds	r14,0x20,r12; adds	r1,0x0,r56; adds	r34,0x0,r8 }
	{ ld4	r37,[r8]; ld4	r41,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r41; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r41,0x0,r52; br.cond.sptk.few	4000000000125E60; }

l400000000012603C:
	{ (p49) nop; zxt1	r0,r64; break.b	0x1000 }

l4000000000126040:
	{ adds	r41,0x0,r40; nop.m	0x0; nop.i	0x0 }

l4000000000126050:
	{ cmp4.eq	p07,p06,r40,r39; nop.m	0x0; addl	r58,6400,r1 }
	{ addl	r59,6408,r1; nop.m	0x0; (p07) br.cond.dpnt.few	40000000001260A0; }

l4000000000126070:
	{ nop.m	0x0; st4	[r39],r44; nop.i	0x0 }
	{ st4	[r40],r45; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A620; }
	{ adds	r1,0x0,r56; cmp4.lt	p07,p06,r8,r0; (p07) br.cond.dptk.few	40000000001260F0; }

l40000000001260A0:
	{ cmp4.eq	p06,p07,r41,r39; nop.m	0x0; addl	r58,6400,r1 }
	{ addl	r59,6408,r1; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000126520; }

l40000000001260C0:
	{ nop.m	0x0; st4	[r39],r44; nop.i	0x0 }
	{ st4	[r41],r45; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A620; }
	{ adds	r1,0x0,r56; cmp4.lt	p07,p06,0x0,r8; (p06) br.cond.spnt.few	4000000000126520; }

l40000000001260F0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x5D,r37; (p07) br.cond.dptk.few	4000000000125F60; }

l4000000000126100:
	{ cmp4.eq	p07,p06,0x0,r48; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000125460; }

l4000000000126110:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r34; (p06) br.cond.spnt.few	4000000000125460; }

l4000000000126120:
	{ adds	r38,0x4,r38; cmp.ltu	p06,p07,r34,r35; (p06) br.cond.dptk.few	4000000000125190 }

l4000000000126130:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000001252F0 }

l4000000000126140:
	{ adds	r34,0x4,r43; nop.m	0x0; adds	r14,0x20,r12; }
	{ st4	[r0],r14; ld4	r14,[r34]; adds	r37,0x0,r34; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	40000000001261C0; }

l4000000000126170:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000126180:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x3A,r14; adds	r15,0x4,r37 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000126200; }

l40000000001261A0:
	{ (p07) ld4	r14,[r15]; nop.m	0x0; nop.i	0x0; }

l40000000001261A6:
	{ break.m	0x4000; nop; (p16) nop }

l40000000001261B0:
	{ adds	r37,0x0,r15; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000126180; }

l40000000001261C0:
	{ nop.m	0x0; ld4	r37,[r43]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r37; (p07) br.cond.dpnt.few	4000000000125440; }

l40000000001261E0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x5D,r37; (p07) br.cond.dptk.few	4000000000125F10 }

l40000000001261F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000126100 }

l4000000000126200:
	{ adds	r15,0x4,r37; ld4	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x5D,r14; (p07) br.cond.dptk.few	40000000001261B0 }

l4000000000126220:
	{ sub	r41,r37,r43; nop.m	0x0; extr	r41,r41,2,62; }
	{ shladd	r58,r41,0x2,r0; adds	r41,0xFFFFFFFFFFFFFFFF,r41; br.call.sptk.many	b0,fn400000000001B340; }
	{ adds	r40,0x0,r8; cmp.eq	p06,p07,0x0,r8; shladd	r41,r41,0x2,r0 }
	{ adds	r1,0x0,r56; adds	r59,0x0,r34; (p06) br.cond.dpnt.few	4000000000126850; }

l4000000000126260:
	{ adds	r60,0x0,r41; nop.m	0x0; adds	r58,0x0,r40 }
	{ add	r41,r40,r41; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7C0; }
	{ nop.m	0x0; adds	r1,0x0,r56; adds	r15,0x18,r12 }
	{ nop.m	0x0; st4	[r0],r41; nop.i	0x0; }
	{ addl	r58,-5828,r1; st8	[r40],r15; nop.i	0x0; }
	{ ld8	r58,[r58]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A360; }
	{ adds	r14,0x18,r12; adds	r1,0x0,r56; cmp.eq	p07,p06,0x0,r8; }
	{ ld8	r41,[r14]; nop.i	0x0; (p07) br.cond.dptk.few	4000000000126780; }

l40000000001262E0:
	{ addl	r59,-5780,r1; nop.m	0x0; adds	r58,0x0,r41; }
	{ ld8	r59,[r59]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B240; }
	{ cmp4.eq	p23,p22,0x0,r8; adds	r14,0x18,r12; adds	r1,0x0,r56; }
	{ (p23) adds	r15,0x18,r12; ld8.a	r58,[r14]; nop.i	0x0; }

l4000000000126316:
	{ (p29) fwb; cmp.lt	p00,p00,0x0,r1; (p05) nop }

l4000000000126326:
	{ Invalid; nop; br.call.spnt.few	b0,b0 }
	{ (p29) mf; (p32) nop; (p16) nop }
	{ Invalid; (p32) nop; (p48) br.call.sptk.few	b1,b2 }
	{ Invalid; nop; break.i	0x80000 }
	{ break.m	0x4000; (p03) nop; break.i	0x80000 }
	{ Invalid; nop; (p32) nop }
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ Invalid; nop; (p32) br.call.sptk.few	b6,b0 }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; (p32) nop; (p48) br.call.sptk.few	b1,b5 }
	{ Invalid; (p29) nop; (p16) nop }
	{ Invalid; (p29) nop; break.b	0x80000 }
	{ break.m	0x4000; (p03) nop; break.i	0x80000 }
	{ Invalid; nop; nop }
	{ break.m	0x4000; (p32) nop; nop }
	{ Invalid; (p29) nop; nop }
	{ chk.a.nc	f0,3FFFFFFFFF126C26; nop; break.i	0x80000 }

l4000000000126430:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A360; }
	{ adds	r1,0x0,r56; nop.m	0x0; adds	r53,0x0,r8 }
	{ adds	r58,0x0,r41; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r56; cmp.eq	p06,p07,0x0,r53; nop.i	0x0 }
	{ adds	r58,0x0,r39; adds	r59,0x0,r53; (p06) br.cond.dpnt.few	4000000000126940; }

l4000000000126480:
	{ nop.m	0x0; nop.i	0x0; (p22) br.cond.dptk.few	4000000000126900 }

l4000000000126490:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A580; }
	{ cmp4.eq	p07,p06,0x0,r8; nop.m	0x0; adds	r1,0x0,r56; }
	{ (p06) addl	r41,1,r0; nop.i	0x0; (p07) adds	r41,0x0,r51; }

l40000000001264B6:
	{ addp4	r0,0xFFFFFFFFFFFFE000,r1; (p20) nop; (p32) nop }

l40000000001264C0:
	{ adds	r14,0x20,r12; nop.m	0x0; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r41; }
	{ st4	[r41],r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000126810 }

l40000000001264E0:
	{ adds	r58,0x0,r40; nop.m	0x0; adds	r43,0x8,r37 }
	{ adds	r34,0xC,r37; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r56; cmp4.eq	p07,p06,0x0,r41; (p07) br.cond.dptk.few	40000000001261C0; }

l4000000000126510:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000126520:
	{ adds	r15,0xFFFFFFFFFFFFFFFC,r34; nop.m	0x0; addl	r16,1,r0; }
	{ ld4	r14,[r15]; nop.m	0x0; adds	r34,0x4,r15; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000125440; }

l4000000000126550:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5B,r14; (p07) br.cond.dpnt.few	40000000001265D0; }

l4000000000126560:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5D,r14; nop.i	0x0; }
	{ (p07) adds	r16,0xFFFFFFFFFFFFFFFF,r16; (p07) br.cond.dpnt.few	40000000001268C0; (p20) br.cond.dptk.few	4000000000126590 }

l4000000000126576:
	{ nop; nop; break.i	0x80000; }

l400000000012657C:
	{ Invalid; cmp.eq	p00,p00,r32,r0; mov	pr,r67,0xE6AE }

l4000000000126580:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5C,r14; (p07) br.cond.dpnt.few	40000000001268A0; }

l4000000000126590:
	{ cmp4.lt	p06,p07,0x0,r16; nop.i	0x0; (p07) br.cond.dpnt.few	40000000001268D0; }

l40000000001265A0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	4000000000125440 }

l40000000001265B0:
	{ ld4	r14,[r34]; nop.m	0x0; adds	r15,0x0,r34; }
	{ adds	r34,0x4,r15; cmp4.eq	p07,p06,0x5B,r14; (p06) br.cond.dptk.few	4000000000126560; }

l40000000001265D0:
	{ ld4	r14,[r34]; cmp4.eq	p06,p07,0x3D,r14; cmp4.eq	p09,p08,0x2E,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x3A,r14; (p06) br.cond.dptk.few	4000000000126600 }

l40000000001265F0:
	{ nop.m	0x0; nop.i	0x0; (p08) br.cond.dptk.few	40000000001268C0 }

l4000000000126600:
	{ nop.m	0x0; adds	r16,0x1,r16; br.cond.sptk.few	40000000001268C0 }

l4000000000126610:
	{ adds	r34,0x0,r42; nop.m	0x0; adds	r58,0x0,r39 }
	{ nop.b	0x0; (p16) br.cond.dpnt.few	4000000000125570; br.call.sptk.many	b0,fn400000000001B780; }

l400000000012662C:
	{ (p11) nop; cmp.lt	p00,p16,r14,r64; mov	pr,r98,0xE600 }
	{ (p58) invala; break.i	0x1000; break.i	0x1000 }

l4000000000126640:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000125550 }

l4000000000126650:
	{ adds	r58,0x0,r43; adds	r59,0x20,r12; br.call.sptk.many	b0,fn40000000001225C0; }
	{ adds	r15,0x20,r12; adds	r1,0x0,r56; adds	r43,0x0,r8; }
	{ ld4	r14,[r15]; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; }
	{ nop.m	0x0; (p06) adds	r40,0x0,r14; nop.i	0x0; }

l400000000012668C:
	{ invala; mov	pr,r32,0x0; zxt1	r64,r64 }

l400000000012669C:
	{ (p52) cmp.lt.unc	p62,p18,r63,r36; (p32) mov	pr,r104,0xE012; Invalid }

l40000000001266A0:
	{ cmp.eq	p06,p07,r38,r32; (p06) br.cond.dpnt.few	4000000000125460; (p24) br.cond.dptk.few	4000000000125C10 }

l40000000001266AC:
	{ (p43) cmp.lt.unc	p62,p11,r63,r37; (p01) cmp.lt.unc	p31,p17,r105,r79; (p01) rfi }

l40000000001266B0:
	{ adds	r14,0xFFFFFFFFFFFFFFFC,r38; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2F,r14; (p07) br.cond.dptk.few	4000000000125C10 }

l40000000001266D0:
	{ nop.m	0x0; addl	r8,1,r0; br.cond.sptk.few	4000000000125470; }

l40000000001266E0:
	{ cmp.eq	p06,p07,r38,r32; adds	r14,0xFFFFFFFFFFFFFFFC,r38; (p06) br.cond.dpnt.few	4000000000125460; }

l40000000001266F0:
	{ nop.m	0x0; tbit.z	p06,p07,r36,0x0; (p06) br.cond.dptk.few	4000000000125680 }

l4000000000126700:
	{ ld4	r14,[r14]; nop.m	0x0; adds	r37,0x8,r34; }
	{ cmp4.eq	p06,p07,0x2F,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000125460; }

l4000000000126720:
	{ ld4	r14,[r42]; cmp4.eq	p07,p06,0x2A,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x3F,r14; (p07) br.cond.dptk.few	40000000001256A0 }

l4000000000126740:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000125730 }

l4000000000126750:
	{ nop.m	0x0; adds	r34,0x0,r42; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r34; (p07) br.cond.sptk.few	4000000000126120 }

l4000000000126770:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000125460 }

l4000000000126780:
	{ addl	r59,-5788,r1; nop.m	0x0; adds	r58,0x0,r41; }
	{ ld8	r59,[r59]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B240; }
	{ adds	r1,0x0,r56; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000001262E0 }

l40000000001267B0:
	{ adds	r58,0x0,r39; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B5E0; }
	{ cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r8; adds	r1,0x0,r56; adds	r14,0x20,r12; }
	{ (p06) adds	r41,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001264C0; }

l40000000001267D6:
	{ chk.a.nc	r0,3FFFFFFFFF126FD6; nop; (p48) nop }

l40000000001267E0:
	{ cmp4.lt	p07,p06,0x7F,r8; (p06) addl	r8,1,r0; nop.i	0x0; }

l40000000001267EC:
	{ Invalid; (p01) nop; zxt1	r0,r64 }

l40000000001267F6:
	{ Invalid; nop; br.call.spnt.few	b0,b2 }
	{ (p03) chk.a.clr	r127,3FFFFFFFFFEE9A96; nop; br.call.spnt.few	b0,b0 }

l4000000000126810:
	{ st4	[r0],r14; adds	r58,0x0,r40; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ ld4	r37,[r43]; nop.m	0x0; adds	r1,0x0,r56; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r37; (p06) br.cond.dptk.few	40000000001261E0 }

l4000000000126840:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000125440 }

l4000000000126850:
	{ adds	r41,0x0,r0; adds	r58,0x0,r40; nop.i	0x0 }
	{ adds	r43,0x8,r37; adds	r34,0xC,r37; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r56; cmp4.eq	p07,p06,0x0,r41; (p07) br.cond.dptk.few	40000000001261C0 }

l4000000000126880:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000126520 }

l4000000000126890:
	{ nop.m	0x0; adds	r38,0x0,r32; br.cond.sptk.few	40000000001252F0 }

l40000000001268A0:
	{ ld4	r14,[r34]; nop.m	0x0; adds	r34,0x8,r15; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	4000000000125460; }

l40000000001268C0:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x0,r16; (p06) br.cond.dptk.few	40000000001265B0; }

l40000000001268D0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r48; (p06) br.cond.dptk.few	4000000000125460; }

l40000000001268E0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r34; (p07) br.cond.sptk.few	4000000000126120 }

l40000000001268F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000125460 }

l4000000000126900:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A580; }
	{ adds	r14,0x20,r12; adds	r41,0x0,r8; adds	r1,0x0,r56; }
	{ st4	[r41],r14; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r41; (p06) br.cond.dptk.few	40000000001264E0 }

l4000000000126930:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000126810 }

l4000000000126940:
	{ addl	r41,-1,r0; nop.m	0x0; adds	r14,0x20,r12; }
	{ st4	[r41],r14; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r41; (p06) br.cond.dptk.few	40000000001264E0 }

l4000000000126960:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000126810 }

l4000000000126970:
	{ nop.m	0x0; adds	r34,0x14,r43; br.cond.sptk.few	4000000000126520 }

l4000000000126980:
	{ addl	r41,-1,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r14,0x20,r12; adds	r1,0x0,r56; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r41; }
	{ st4	[r41],r14; nop.i	0x0; (p06) br.cond.dptk.few	40000000001264E0 }

l40000000001269B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000126810; }

;; fn40000000001269C0: 40000000001269C0
;;   Called from:
;;     400000000012561C (in fn4000000000125100)
;;     4000000000125A0C (in fn4000000000125100)
;;     4000000000125B2C (in fn4000000000125100)
fn40000000001269C0 proc
	{ alloc	r46,ar.pfs,0x16,0x0,0x11; ld4	r14,[r35]; mov	r48,pr }
	{ adds	r47,0x0,r1; nop.m	0x0; adds	r50,0x0,r36; }
	{ cmp4.eq	p07,p06,0x28,r14; mov	r45,b5; adds	r51,0x0,r0; }
	{ (p06) adds	r49,0x0,r0; (p07) addl	r49,4,r0; nop.i	0x0; }

l40000000001269F6:
	{ Invalid; nop; (p16) nop.b	0x3146C; }

l40000000001269FC:
	{ nop; zxt1	r40,r0; break.i	0x1000 }
	{ (p62) cmp.eq.unc	p54,p08,r63,r44; cmp.lt	p00,p28,r66,r65; zxt2	r23,r79 }
	{ nop; nop; (p05) mov	pr,r2,0x8400 }
	{ (p50) invala; cmp.lt	p00,p00,r32,r0; (p48) nop }

l4000000000126A30:
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x1F,r14; (p07) br.cond.dptk.few	4000000000126A70 }

l4000000000126A40:
	{ addl	r8,1,r0; nop.m	0x0; nop.i	0x0; }

l4000000000126A50:
	{ nop.m	0x0; mov	pr,r48,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r46; }
	{ nop.m	0x0; mov.spnt	b0,r45,4000000000126A60; br.ret	b0 }

l4000000000126A70:
	{ addl	r15,-5804,r1; nop.m	0x0; addp4	r14,r14,r0; }
	{ ld8	r15,[r15]; shladd	r14,r14,0x3,r15; nop.i	0x0; }
	{ ld8	r15,[r14]; add	r14,r14,r15; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r14,4000000000126AA0; br.cond	b6; }
4000000000126AB0 08 40 11 46 00 21 10 21 A5 20 70 60 22 0A 49 D0 .@.F.!.!. p`".I.
4000000000126AC0 19 58 ED 4B 2C 22 60 F8 81 0E 73 03 60 05 00 43 .X.K,"`...s.`..C
4000000000126AD0 28 32 01 44 00 21 10 03 A0 00 42 00 00 00 04 00 (2.D.!....B.....
4000000000126AE0 19 90 01 48 00 21 30 E3 03 00 48 00 E8 B6 FF 58 ...H.!0...H....X
4000000000126AF0 08 08 00 5E 00 21 00 00 00 02 00 80 05 40 00 84 ...^.!.......@..
4000000000126B00 17 00 00 00 00 48 04 10 00 80 A1 09 B0 00 00 43 .....H.........C
4000000000126B10 48 32 01 42 00 21 00 00 00 02 00 00 00 00 04 00 H2.B.!..........
4000000000126B20 09 50 F1 59 3F 23 00 00 00 02 00 00 00 00 04 00 .P.Y?#..........
4000000000126B30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000126B40 08 38 84 4C 06 34 10 03 84 00 42 40 06 30 01 84 .8.L.4....B@.0..
4000000000126B50 09 98 01 50 00 21 40 03 A8 00 42 A0 06 28 01 84 ...P.!@...B..(..
4000000000126B60 09 00 00 00 01 80 71 02 94 00 42 00 00 00 04 00 ......q...B.....
4000000000126B70 F1 38 01 56 00 21 00 00 00 02 00 00 98 E5 FF 58 .8.V.!.........X
4000000000126B80 10 08 00 5E 00 21 60 00 20 0E 73 03 50 00 00 43 ...^.!`. .s.P..C
4000000000126B90 09 00 00 00 01 00 60 22 98 00 42 00 00 00 04 00 ......`"..B.....
4000000000126BA0 11 00 00 00 01 00 70 10 99 0C 68 03 A0 FF FF 4A ......p...h....J
4000000000126BB0 10 40 01 58 00 21 60 48 B1 0E F0 03 20 FF FF 4A .@.X.!`H.... ..J
4000000000126BC0 10 00 00 00 01 00 80 08 00 00 48 00 90 FE FF 48 ..........H....H
4000000000126BD0 08 88 01 4C 00 21 20 03 88 00 42 60 06 48 01 84 ...L.! ...B`.H..
4000000000126BE0 19 A0 01 48 00 21 50 03 9C 00 42 00 28 E5 FF 58 ...H.!P...B.(..X
4000000000126BF0 11 08 00 5E 00 21 60 00 20 0E F3 03 A0 FF FF 4A ...^.!`. ......J
4000000000126C00 03 40 00 00 00 21 F0 87 C1 BF 05 00 E0 02 AA 00 .@...!..........
4000000000126C10 10 00 00 00 01 00 00 68 05 80 03 80 08 00 84 00 .......h........
4000000000126C20 08 30 A8 40 87 39 70 22 8C 00 42 00 00 00 04 00 .0.@.9p"..B.....
4000000000126C30 19 88 88 42 10 34 B0 DA 97 58 44 03 A0 03 00 43 ...B.4...XD....C
4000000000126C40 08 18 F1 47 3F 23 00 00 00 02 00 00 00 00 04 00 ...G?#..........
4000000000126C50 08 88 01 4E 00 21 20 03 90 00 42 00 00 00 04 00 ...N.! ...B.....
4000000000126C60 19 98 F1 01 00 24 64 02 84 00 42 00 68 B5 FF 58 .....$d...B.h..X
4000000000126C70 08 00 00 00 01 00 84 E2 23 7E 46 20 00 78 01 84 ........#~F .x..
4000000000126C80 19 00 00 00 01 00 C0 02 20 00 C2 08 E0 00 00 43 ........ ......C
4000000000126C90 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000126CA0 08 88 01 42 00 21 20 03 98 00 42 60 06 38 01 84 ...B.! ...B`.8..
4000000000126CB0 19 A0 01 50 00 21 50 03 94 00 42 00 58 E4 FF 58 ...P.!P...B.X..X
4000000000126CC0 11 08 00 5E 00 21 70 00 20 0C 73 03 80 00 00 42 ...^.!p. .s....B
4000000000126CD0 08 88 01 4C 00 21 20 03 88 00 42 60 06 48 01 84 ...L.! ...B`.H..
4000000000126CE0 18 A0 01 48 00 21 70 08 99 0C 68 03 40 02 00 42 ...H.!p...h.@..B
4000000000126CF0 11 A8 01 56 00 21 A0 02 AC 00 42 00 18 E4 FF 58 ...V.!....B....X
4000000000126D00 10 08 00 5E 00 21 60 00 20 0E 73 03 00 FF FF 4A ...^.!`. .s....J
4000000000126D10 08 88 01 4C 00 21 20 03 88 00 42 60 06 18 01 84 ...L.! ...B`....
4000000000126D20 19 A0 01 48 00 21 50 03 A8 00 42 00 E8 E3 FF 58 ...H.!P...B....X
4000000000126D30 11 08 00 5E 00 21 60 00 20 0E 73 03 D0 FE FF 4A ...^.!`. .s....J
4000000000126D40 09 00 00 00 01 00 60 22 98 00 42 00 00 00 04 00 ......`"..B.....
4000000000126D50 11 00 00 00 01 00 70 10 99 0C 68 03 50 FF FF 4A ......p...h.P..J
4000000000126D60 08 38 01 58 00 21 60 48 B1 0E 70 40 06 20 01 84 .8.X.!`H..p@. ..
4000000000126D70 19 98 F1 01 00 24 64 02 84 00 42 03 D0 FC FF 4B .....$d...B....K
4000000000126D80 11 88 01 4E 00 21 00 00 00 02 00 00 48 B4 FF 58 ...N.!......H..X
4000000000126D90 08 00 00 00 01 00 10 00 BC 00 42 80 05 40 00 84 ..........B..@..
4000000000126DA0 18 00 00 00 01 00 84 E2 23 7E 46 08 00 FF FF 4A ........#~F....J
4000000000126DB0 10 00 00 00 01 00 00 00 00 02 00 00 B0 FF FF 48 ...............H
4000000000126DC0 11 38 88 42 06 34 00 00 00 02 80 03 80 FC FF 4B .8.B.4.........K
4000000000126DD0 C8 58 11 46 00 A1 81 02 84 00 42 00 00 00 04 00 .X.F......B.....
4000000000126DE0 C3 50 ED 4B 2C 22 00 00 00 02 00 C0 04 58 01 84 .P.K,".......X..
4000000000126DF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000126E00 08 88 01 4C 00 21 00 00 00 02 00 40 06 20 01 84 ...L.!.....@. ..
4000000000126E10 19 98 F1 01 00 24 00 00 00 02 00 00 B8 B3 FF 58 .....$.........X
4000000000126E20 08 08 00 5E 00 21 70 02 20 00 42 60 06 30 01 84 ...^.!p. .B`.0..
4000000000126E30 09 A8 01 4A 00 21 10 03 84 00 42 40 06 40 01 84 ...J.!....B@.@..
4000000000126E40 11 A0 F1 11 3F 23 60 02 9C 00 42 00 C8 E2 FF 58 ....?#`...B....X
4000000000126E50 11 30 00 10 87 39 10 00 BC 00 42 03 40 01 00 43 .0...9....B.@..C
4000000000126E60 10 00 00 00 01 00 70 48 9D 0C 70 03 A0 FF FF 4A ......pH..p....J
4000000000126E70 09 48 84 50 08 34 00 00 00 02 00 C0 01 00 00 84 .H.P.4..........
4000000000126E80 09 30 00 1C 87 39 00 00 00 02 00 A4 06 28 01 84 .0...9.......(..
4000000000126E90 10 00 00 00 01 40 52 03 A8 00 42 03 40 00 00 43 .....@R...B.@..C
4000000000126EA0 09 00 00 00 01 00 80 22 A0 00 42 00 00 00 04 00 ......."..B.....
4000000000126EB0 10 00 00 00 01 00 70 10 A1 0C E8 03 90 FB FF 4B ......p........K
4000000000126EC0 10 00 00 00 01 00 60 02 AC 00 42 00 40 FF FF 48 ......`...B.@..H
4000000000126ED0 08 88 01 50 00 21 20 03 88 00 42 60 06 48 01 84 ...P.! ...B`.H..
4000000000126EE0 19 A0 01 48 00 21 80 22 A0 00 42 00 28 E2 FF 58 ...H.!."..B.(..X
4000000000126EF0 11 30 00 10 87 39 10 00 BC 00 42 03 10 FD FF 4B .0...9....B....K
4000000000126F00 10 00 00 00 01 00 70 10 A1 0C 68 03 C0 FF FF 4A ......p...h....J
4000000000126F10 10 00 00 00 01 00 00 00 00 02 00 00 30 FB FF 48 ............0..H
4000000000126F20 11 A8 01 4A 00 21 00 00 00 02 00 00 E8 E1 FF 58 ...J.!.........X
4000000000126F30 11 08 00 5E 00 21 60 00 20 0E 73 03 D0 FC FF 4A ...^.!`. .s....J
4000000000126F40 08 30 98 42 07 38 A0 02 94 00 42 20 06 30 01 84 .0.B.8....B .0..
4000000000126F50 19 90 01 44 00 21 30 03 8C 00 42 03 F0 FD FF 4B ...D.!0...B....K
4000000000126F60 11 A0 01 48 00 21 50 03 A8 00 42 00 A8 E1 FF 58 ...H.!P...B....X
4000000000126F70 10 08 00 5E 00 21 60 00 20 0E 73 03 90 FC FF 4A ...^.!`. .s....J
4000000000126F80 10 00 00 00 01 00 00 00 00 02 00 00 C0 FD FF 48 ...............H
4000000000126F90 02 48 84 50 08 34 E0 08 00 00 48 A4 06 28 01 84 .H.P.4....H..(..
4000000000126FA0 19 30 00 1C 87 39 00 00 00 02 80 03 00 FF FF 4A .0...9.........J
4000000000126FB0 28 A9 01 54 00 21 00 00 00 02 00 00 00 00 04 00 (..T.!..........
4000000000126FC0 11 00 00 00 01 00 00 00 00 02 00 00 10 FF FF 48 ...............H
4000000000126FD0 08 88 01 42 00 21 20 03 88 00 42 60 06 40 00 84 ...B.! ...B`.@..
4000000000126FE0 19 A0 01 48 00 21 50 03 94 00 42 00 28 E1 FF 58 ...H.!P...B.(..X
4000000000126FF0 08 08 00 5E 00 21 70 00 20 0C 73 E0 44 18 01 84 ...^.!p. .s.D...
4000000000127000 19 88 88 42 10 34 30 E2 8F 7E C6 03 00 FC FF 4B ...B.40..~.....K
4000000000127010 10 00 00 00 01 00 B0 DA 97 58 44 00 40 FC FF 48 .........XD.@..H
4000000000127020 08 88 01 42 00 21 20 03 88 00 42 60 06 40 00 84 ...B.! ...B`.@..
4000000000127030 19 A0 01 48 00 21 50 03 94 00 42 00 D8 E0 FF 58 ...H.!P...B....X
4000000000127040 08 08 00 5E 00 21 60 00 20 0E 73 00 45 18 01 84 ...^.!`. .s.E...
4000000000127050 19 88 90 52 10 38 30 11 85 24 68 03 B0 FB FF 4B ...R.80..$h....K
4000000000127060 10 00 00 00 01 00 B0 DA 97 58 44 00 70 FA FF 48 .........XD.p..H

l4000000000127070:
	{ ld4	r39,[r36]; adds	r49,0xFFFFFFFFFFFFFFFC,r35; adds	r50,0x0,r33 }
	{ ld4	r38,[r34]; st4	[r0],r34; nop.i	0x0; }
	{ st4	[r0],r36; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A620; }
	{ cmp4.eq	p07,p06,0x0,r8; st4	[r39],r36; adds	r1,0x0,r47 }
	{ st4	[r38],r34; (p06) addl	r8,1,r0; nop.i	0x0; }

l40000000001270BC:
	{ Invalid; mov	pr,r32,0x0; zxt1	r0,r64 }

l40000000001270CC:
	{ (p12) nop; break.i	0x1000; break.b	0x1000 }
40000000001270D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001270E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001270F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; internal_strmatch: 4000000000127100
;;   Called from:
;;     400000000012746C (in xstrmatch)
;;     40000000001274DC (in xstrmatch)
internal_strmatch proc
	{ alloc	r39,ar.pfs,0xA,0x0,0x9; mov	r38,b6; nop.b	0x0 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r40,0x0,r1; adds	r36,0x0,r34; }
	{ addl	r8,1,r0; cmp.eq.or.andcm	p06,p07,0x0,r33; mov.i	ar.pfs,r39 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000127150; }

l4000000000127140:
	{ nop.m	0x0; mov.spnt	b0,r38,4000000000127140; br.ret	b0; }

l4000000000127150:
	{ adds	r41,0x0,r33; adds	r34,0x0,r32; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r40; adds	r37,0x0,r8; nop.i	0x0 }
	{ adds	r41,0x0,r32; adds	r32,0x0,r33; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r40; add	r33,r33,r37; nop.b	0x0 }
	{ add	r35,r34,r8; mov.spnt	b0,r38,4000000000127190; mov.i	ar.pfs,r39; }
	{ alloc	r2,ar.pfs,0x5,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn4000000000122C80; }
40000000001271B0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; internal_wstrmatch: 40000000001271C0
;;   Called from:
;;     4000000000121D6C (in wcsmatch)
;;     40000000001273BC (in xstrmatch)
internal_wstrmatch proc
	{ alloc	r40,ar.pfs,0xB,0x0,0xA; mov	r39,b7; nop.b	0x0 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r41,0x0,r1; adds	r37,0x0,r32; }
	{ addl	r8,1,r0; cmp.eq.or.andcm	p06,p07,0x0,r33; mov.i	ar.pfs,r40 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000127210; }

l4000000000127200:
	{ nop.m	0x0; mov.spnt	b0,r39,4000000000127200; br.ret	b0; }

l4000000000127210:
	{ adds	r42,0x0,r33; nop.m	0x0; adds	r36,0x0,r34 }
	{ adds	r34,0x0,r37; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BD40; }
	{ adds	r1,0x0,r41; adds	r42,0x0,r32; nop.i	0x0 }
	{ shladd	r38,r8,0x2,r33; adds	r32,0x0,r33; br.call.sptk.many	b0,fn400000000001BD40; }
	{ adds	r1,0x0,r41; adds	r33,0x0,r38; nop.b	0x0 }
	{ shladd	r35,r8,0x2,r37; mov.spnt	b0,r39,4000000000127260; mov.i	ar.pfs,r40; }
	{ alloc	r2,ar.pfs,0x5,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn4000000000125100; }
4000000000127280 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
4000000000127290 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001272A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001272B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; xstrmatch: 40000000001272C0
;;   Called from:
;;     4000000000121CAC (in strmatch)
xstrmatch proc
	{ alloc	r38,ar.pfs,0xB,0x0,0x8; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ adds	r39,0x0,r1; mov	r37,b5; adds	r40,0x0,r33; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,mbsmbchar; }
	{ adds	r1,0x0,r39; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	40000000001274A0 }

l4000000000127300:
	{ adds	r35,0x18,r12; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ cmp.eq	p07,p06,0x1,r8; adds	r1,0x0,r39; adds	r42,0x0,r32 }
	{ adds	r40,0x0,r35; adds	r41,0x0,r0; (p07) br.cond.dpnt.few	4000000000127450; }

l4000000000127330:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,xdupmbstowcs; }
	{ adds	r8,0x2,r8; adds	r1,0x0,r39; nop.i	0x0 }
	{ adds	r40,0x10,r12; adds	r42,0x0,r33; adds	r41,0x0,r0; }
	{ cmp.ltu	p06,p07,0x1,r8; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000127450; }

l4000000000127370:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,xdupmbstowcs; }
	{ adds	r8,0x2,r8; adds	r14,0x10,r12; nop.i	0x0 }
	{ adds	r1,0x0,r39; ld8	r40,[r35]; adds	r42,0x0,r34; }
	{ cmp.ltu	p06,p07,0x1,r8; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000127430; }

l40000000001273B0:
	{ ld8	r41,[r14]; nop.i	0x0; br.call.sptk.many	b0,internal_wstrmatch; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r36,0x0,r8 }
	{ ld8	r40,[r35]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r14,0x10,r12; nop.m	0x0; adds	r1,0x0,r39; }
	{ ld8	r40,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r8,0x0,r36; adds	r1,0x0,r39; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,4000000000127410; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0; }

l4000000000127430:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r39; nop.m	0x0; nop.i	0x0 }

l4000000000127450:
	{ adds	r40,0x0,r32; nop.m	0x0; adds	r41,0x0,r33 }
	{ adds	r42,0x0,r34; nop.m	0x0; br.call.sptk.many	b0,internal_strmatch; }
	{ nop.m	0x0; adds	r1,0x0,r39; adds	r36,0x0,r8; }

l4000000000127480:
	{ adds	r8,0x0,r36; mov.i	ar.pfs,r38; mov.spnt	b0,r37,4000000000127480 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000001274A0:
	{ adds	r40,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,mbsmbchar; }
	{ adds	r1,0x0,r39; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	4000000000127300 }

l40000000001274C0:
	{ adds	r40,0x0,r32; nop.m	0x0; adds	r41,0x0,r33 }
	{ adds	r42,0x0,r34; nop.m	0x0; br.call.sptk.many	b0,internal_strmatch; }
	{ adds	r1,0x0,r39; adds	r36,0x0,r8; br.cond.sptk.few	4000000000127480; }
40000000001274F0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; xmbsrtowcs: 4000000000127500
xmbsrtowcs proc
	{ alloc	r41,ar.pfs,0x10,0x0,0xC; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r43,LC }
	{ adds	r42,0x0,r1; nop.m	0x0; cmp.eq	p07,p06,0x0,r35; }
	{ nop.m	0x0; mov	r40,b0; (p07) br.cond.dpnt.few	4000000000127760 }

l4000000000127530:
	{ nop.m	0x0; ld8	r36,[r33]; nop.i	0x0; }
	{ adds	r44,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ cmp.eq	p06,p07,0x0,r32; nop.m	0x0; adds	r1,0x0,r42 }
	{ adds	r37,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	40000000001277F0; }

l4000000000127570:
	{ cmp.eq	p07,p06,0x0,r34; nop.m	0x0; adds	r34,0xFFFFFFFFFFFFFFFF,r34; }
	{ nop.m	0x0; (p07) adds	r38,0x0,r0; mov.i	LC,r34 }

l400000000012758C:
	{ (p17) nop; break.i	0x1000; mov	pr,r32,0x0 }
	{ (p06) cmp.lt	p00,p09,r64,r33; zxt1	r0,r64; break.i	0x1000 }

l40000000001275A0:
	{ adds	r38,0x0,r0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000001275C0:
	{ adds	r44,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A880; }
	{ adds	r1,0x0,r42; cmp4.eq	p06,p07,0x0,r8; adds	r44,0x0,r32 }
	{ adds	r45,0x0,r36; adds	r46,0x0,r37; (p06) br.cond.dpnt.few	4000000000127680; }

l40000000001275F0:
	{ ld1	r15,[r36]; adds	r47,0x0,r35; sxt1	r15,r15; }
	{ cmp4.eq	p07,p06,0x0,r15; nop.i	0x0; (p07) br.cond.dpnt.few	40000000001277B0; }

l4000000000127610:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5C,r15; (p06) br.cond.dptk.few	40000000001276A0 }

l4000000000127620:
	{ adds	r36,0x1,r36; st4	[r15],r32; nop.i	0x0 }
	{ adds	r37,0xFFFFFFFFFFFFFFFF,r37; st8	[r36],r33; nop.i	0x0 }

l4000000000127640:
	{ adds	r38,0x1,r38; adds	r32,0x4,r32; br.cloop.sptk.few	40000000001275C0; }

l4000000000127650:
	{ adds	r8,0x0,r38; mov.i	ar.pfs,r41; mov.i	LC,r43; }
	{ nop.m	0x0; mov.spnt	b0,r40,4000000000127660; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l4000000000127680:
	{ nop.m	0x0; adds	r44,0x0,r32; adds	r45,0x0,r36 }
	{ nop.m	0x0; adds	r46,0x0,r37; adds	r47,0x0,r35; }

l40000000001276A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r1,0x0,r42; sub	r37,r37,r8; }
	{ cmp.ltu	p07,p06,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000127730; }

l40000000001276D0:
	{ ld8	r36,[r33]; ld4	r14,[r32]; nop.i	0x0; }
	{ add	r36,r36,r8; nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; }
	{ st8	[r36],r33; nop.i	0x0; (p06) br.cond.dptk.few	4000000000127640 }

l4000000000127700:
	{ adds	r8,0x0,r38; st8	[r0],r33; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.i	LC,r43; mov.spnt	b0,r40,4000000000127710 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000127730:
	{ addl	r38,-1,r0; adds	r8,0x0,r38; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.i	LC,r43; mov.spnt	b0,r40,4000000000127740 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000127760:
	{ addl	r14,8776,r1; nop.m	0x0; addl	r35,8780,r1; }
	{ nop.m	0x0; ld4	r15,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r15; (p07) adds	r15,0x0,r35; (p07) addl	r16,1,r0; }

l400000000012778C:
	{ nop; nop; rfi }

l4000000000127790:
	{ (p07) st4	[r15],r4,4; (p07) st4	[r16],r14; nop.i	0x0; }

l4000000000127796:
	{ mf.a; cmp.eq	p00,p00,r0,r1; (p01) nop; }

l400000000012779C:
	{ Invalid; Invalid; break.i	0x1000 }

l40000000001277A6:
	{ break.m	0x4000; nop; nop }

l40000000001277B0:
	{ st4	[r0],r32; adds	r8,0x0,r38; nop.b	0x0 }
	{ st8	[r0],r33; mov.i	ar.pfs,r41; mov.i	LC,r43; }
	{ nop.m	0x0; mov.spnt	b0,r40,40000000001277D0; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l40000000001277F0:
	{ nop.m	0x0; adds	r44,0x1,r8; nop.i	0x0; }
	{ shladd	r44,r44,0x2,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B340; }
	{ adds	r14,0x10,r12; ld4	r15,[r35],4; adds	r45,0x18,r12 }
	{ adds	r39,0x0,r8; adds	r1,0x0,r42; adds	r46,0x0,r37; }
	{ adds	r47,0x0,r14; st4	[r14],r4,4; nop.i	0x0 }
	{ ld4	r15,[r35]; st8	[r36],r45; adds	r44,0x0,r8; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A4C0; }
	{ cmp.eq	p06,p07,0x0,r39; adds	r1,0x0,r42; nop.i	0x0 }
	{ adds	r38,0x0,r8; adds	r44,0x0,r39; (p06) br.cond.dpnt.few	4000000000127650; }

l4000000000127880:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r8,0x0,r38; adds	r1,0x0,r42; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.i	LC,r43; mov.spnt	b0,r40,40000000001278A0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

;; xdupmbstowcs: 40000000001278C0
;;   Called from:
;;     4000000000095EAC (in pat_subst)
;;     4000000000095EAC (in pat_subst)
;;     4000000000095EDC (in pat_subst)
;;     4000000000095EDC (in pat_subst)
;;     400000000011F63C (in fn400000000011F5C0)
;;     400000000011F89C (in glob_pattern_p)
;;     400000000012057C (in glob_vector)
;;     40000000001205AC (in glob_vector)
;;     400000000012733C (in xstrmatch)
;;     400000000012737C (in xstrmatch)
xdupmbstowcs proc
	{ alloc	r46,ar.pfs,0x15,0x0,0x10; adds	r12,0xFFFFFFFFFFFFFFD0,r12; nop.b	0x0 }
	{ cmp.eq	p06,p07,0x0,r32; mov	r45,b5; adds	r47,0x0,r1; }
	{ (p06) cmp.eq.unc	p08,p00,r0,r0; nop.m	0x0; (p07) cmp.eq.unc	p09,p00,r0,r0; }

l40000000001278E6:
	{ addp4	r0,0xFFFFFFFFFFFFE000,r1; (p36) nop; break.i	0x80000 }

l40000000001278F0:
	{ nop.m	0x0; cmp.eq.or.andcm	p08,p09,0x0,r34; (p09) br.cond.dptk.few	4000000000127940 }

l4000000000127900:
	{ nop.m	0x0; (p06) addl	r36,-1,r0; (p06) br.cond.dpnt.few	4000000000127920; }

l400000000012790C:
	{ (p01) nop; break.i	0x1000; addp4	r0,r8,r102 }

l4000000000127910:
	{ nop.m	0x0; st8	[r0],r32; addl	r36,-1,r0; }

l4000000000127920:
	{ adds	r8,0x0,r36; mov.i	ar.pfs,r46; mov.spnt	b0,r45,4000000000127920 }
	{ nop.m	0x0; adds	r12,0x30,r12; br.ret	b0; }

l4000000000127940:
	{ cmp.eq	p07,p06,0x0,r33; nop.m	0x0; adds	r42,0x20,r12 }
	{ addl	r48,128,r0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000127C20; }

l4000000000127960:
	{ st8	[r0],r42; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B340; }
	{ cmp.eq	p07,p06,0x0,r8; adds	r1,0x0,r47; nop.i	0x0 }
	{ adds	r41,0x0,r8; addl	r48,256,r0; (p07) br.cond.dpnt.few	4000000000127910; }

l4000000000127990:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B340; }
	{ cmp.eq	p07,p06,0x0,r8; nop.m	0x0; adds	r43,0x0,r8 }
	{ adds	r1,0x0,r47; nop.m	0x0; (p07) br.cond.dpnt.few	40000000001280C0; }

l40000000001279C0:
	{ nop.m	0x0; (p06) adds	r35,0x0,r0; (p06) adds	r36,0x0,r0 }

l40000000001279CC:
	{ nop; (p05) nop }

l40000000001279D0:
	{ nop.m	0x0; (p06) addl	r40,32,r0; (p06) adds	r37,0x38,r12; }

l40000000001279DC:
	{ Invalid; break.x	0x10802A00C01000 }

l40000000001279E0:
	{ adds	r48,0x0,r42; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A880; }
	{ adds	r1,0x0,r47; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	4000000000127A50; }

l4000000000127A00:
	{ nop.m	0x0; ld1	r15,[r34]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; cmp4.eq	p07,p06,0x0,r15; }
	{ (p07) st4	[r0],r37; nop.i	0x0; (p07) br.cond.dptk.few	4000000000127BF0 }

l4000000000127A26:
	{ chk.a.nc	f0,3FFFFFFFFF128226; nop; break.i	0x80000 }

l4000000000127A30:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5C,r15; nop.i	0x0; }
	{ (p07) st4	[r15],r37; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000127BF0 }

l4000000000127A46:
	{ chk.a.nc	f0,3FFFFFFFFF128246; nop; nop }

l4000000000127A50:
	{ adds	r48,0x0,r37; adds	r49,0x0,r34; addl	r50,16,r0 }
	{ adds	r51,0x0,r42; adds	r38,0x1,r36; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r1,0x0,r47; adds	r39,0x0,r8; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000127FE0; }

l4000000000127A90:
	{ nop.m	0x0; cmp.ltu	p07,p06,r40,r38; (p07) br.cond.dpnt.few	4000000000127B00 }

l4000000000127AA0:
	{ ld4	r14,[r37]; nop.m	0x0; add	r16,r41,r35 }
	{ shladd	r15,r35,0x1,r43; nop.m	0x0; adds	r35,0x4,r35; }
	{ st4	[r14],r16; st8	[r34],r15; add	r34,r34,r39; }
	{ nop.m	0x0; ld4	r14,[r37]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	4000000000127BC0 }

l4000000000127AF0:
	{ nop.m	0x0; adds	r36,0x0,r38; br.cond.sptk.few	40000000001279E0 }

l4000000000127B00:
	{ adds	r40,0x20,r40; nop.m	0x0; adds	r48,0x0,r41; }
	{ shladd	r49,r40,0x2,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AD60; }
	{ cmp.eq	p07,p06,0x0,r8; adds	r1,0x0,r47; adds	r44,0x0,r8 }
	{ adds	r48,0x0,r43; shladd	r49,r40,0x3,r0; (p07) br.cond.dpnt.few	4000000000127FE0; }

l4000000000127B40:
	{ adds	r41,0x0,r8; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AD60; }
	{ adds	r1,0x0,r47; nop.m	0x0; cmp.eq	p07,p06,0x0,r8 }
	{ add	r16,r41,r35; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000128120; }

l4000000000127B70:
	{ ld4	r14,[r37]; nop.m	0x0; adds	r43,0x0,r8; }
	{ st4	[r14],r16; shladd	r15,r35,0x1,r43; adds	r35,0x4,r35; }
	{ ld4	r14,[r37]; st8	[r34],r15; add	r34,r34,r39; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000127AF0; }

l4000000000127BB0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000127BC0:
	{ st8	[r41],r32; adds	r8,0x0,r36; nop.b	0x0 }
	{ st8	[r43],r33; mov.i	ar.pfs,r46; mov.spnt	b0,r45,4000000000127BD0 }
	{ nop.m	0x0; adds	r12,0x30,r12; br.ret	b0 }

l4000000000127BF0:
	{ adds	r38,0x1,r36; nop.m	0x0; addl	r39,1,r0; }
	{ nop.m	0x0; cmp.ltu	p07,p06,r40,r38; (p06) br.cond.dptk.few	4000000000127AA0 }

l4000000000127C10:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000127B00 }

l4000000000127C20:
	{ adds	r40,0x18,r12; adds	r41,0x30,r12; adds	r39,0x0,r0 }
	{ adds	r35,0x0,r0; adds	r43,0x0,r0; adds	r42,0x28,r12; }
	{ st8	[r0],r40; st8	[r34],r41; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000127C60:
	{ adds	r48,0x0,r34; addl	r49,92,r0; br.call.sptk.many	b0,fn400000000001A840; }
	{ ld1	r14,[r8]; sub	r37,r8,r34; adds	r1,0x0,r47 }
	{ st8	[r34],r42; adds	r48,0x0,r0; adds	r49,0x0,r42; }
	{ nop.m	0x0; sxt1	r14,r14; nop.b	0x0 }
	{ ld8	r15,[r40]; adds	r51,0x0,r0; adds	r52,0x10,r12; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.m	0x0; adds	r14,0x10,r12; }
	{ st8	[r15],r14; nop.m	0x0; (p07) adds	r37,0x1,r37; }

l4000000000127CD0:
	{ cmp.eq	p07,p06,0x0,r37; adds	r50,0x0,r37; (p06) br.cond.dpnt.few	4000000000127D00; }

l4000000000127CE0:
	{ ld1	r14,[r34]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x5C,r14; (p06) br.cond.dpnt.few	4000000000127FA0 }

l4000000000127D00:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B2C0; }
	{ adds	r1,0x0,r47; nop.m	0x0; adds	r38,0x0,r8 }
	{ cmp.eq	p07,p06,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000128030; }

l4000000000127D30:
	{ nop.m	0x0; ld8	r15,[r41]; addl	r38,1,r0 }
	{ ld8	r14,[r40]; st8	[r15],r42; adds	r15,0x10,r12 }
	{ nop.m	0x0; st8	[r14],r15; nop.i	0x0 }

l4000000000127D60:
	{ add	r36,r38,r39; adds	r14,0x1,r36; nop.i	0x0; }
	{ nop.m	0x0; cmp.ltu	p07,p06,r35,r14; (p07) br.cond.dptk.few	4000000000127E50 }

l4000000000127D80:
	{ shladd	r44,r39,0x2,r43; adds	r49,0x0,r41; nop.i	0x0 }
	{ adds	r50,0x0,r37; sub	r51,r35,r39; adds	r52,0x0,r40; }
	{ adds	r48,0x0,r44; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B2C0; }
	{ adds	r1,0x0,r47; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	4000000000127DE0 }

l4000000000127DC0:
	{ nop.m	0x0; ld8	r14,[r41]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	4000000000128100; }

l4000000000127DE0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x1,r38; (p06) br.cond.dpnt.few	4000000000127EA0 }

l4000000000127DF0:
	{ ld8	r34,[r41]; adds	r48,0x0,r40; br.call.sptk.many	b0,fn400000000001A880; }
	{ adds	r1,0x0,r47; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	4000000000127F60; }

l4000000000127E10:
	{ cmp.eq	p06,p07,0x0,r34; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000127F70; }

l4000000000127E20:
	{ ld1	r14,[r34]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5C,r14; (p07) br.cond.dpnt.few	4000000000128080 }

l4000000000127E40:
	{ nop.m	0x0; adds	r39,0x0,r36; br.cond.sptk.few	4000000000127C60 }

l4000000000127E50:
	{ nop.m	0x0; adds	r35,0x20,r35; nop.i	0x0; }
	{ nop.m	0x0; cmp.ltu	p06,p07,r35,r14; (p06) br.cond.dptk.few	4000000000127E50 }

l4000000000127E70:
	{ adds	r48,0x0,r43; shladd	r49,r35,0x2,r0; br.call.sptk.many	b0,fn400000000001AD60; }
	{ adds	r1,0x0,r47; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	4000000000128040; }

l4000000000127E90:
	{ nop.m	0x0; adds	r43,0x0,r8; br.cond.sptk.few	4000000000127D80 }

l4000000000127EA0:
	{ nop.m	0x0; adds	r8,0xFFFFFFFFFFFFFFFF,r8; nop.i	0x0; }
	{ nop.m	0x0; cmp.ltu	p06,p07,0xFFFFFFFFFFFFFFFD,r8; (p07) br.cond.dptk.few	4000000000127DF0 }

l4000000000127EC0:
	{ adds	r15,0x10,r12; ld8	r34,[r42]; adds	r48,0x0,r40 }
	{ adds	r36,0x1,r39; ld8	r14,[r15]; nop.i	0x0 }
	{ st8	[r34],r41; st8	[r14],r40; nop.i	0x0; }
	{ ld1	r14,[r34]; nop.m	0x0; sxt1	r14,r14; }
	{ st4	[r14],r44; ld1	r14,[r34]; adds	r34,0x1,r34; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000128160; }

l4000000000127F30:
	{ st8	[r34],r41; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A880; }
	{ adds	r1,0x0,r47; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	4000000000127E10; }

l4000000000127F50:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000127F60:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	4000000000127E40 }

l4000000000127F70:
	{ st8	[r43],r32; nop.m	0x0; nop.i	0x0 }

l4000000000127F80:
	{ adds	r8,0x0,r36; mov.i	ar.pfs,r46; mov.spnt	b0,r45,4000000000127F80 }
	{ nop.m	0x0; adds	r12,0x30,r12; br.ret	b0 }

l4000000000127FA0:
	{ addl	r38,1,r0; addl	r37,1,r0; add	r36,r38,r39; }
	{ nop.m	0x0; adds	r14,0x1,r36; nop.i	0x0; }
	{ nop.m	0x0; cmp.ltu	p07,p06,r35,r14; (p06) br.cond.dptk.few	4000000000127D80 }

l4000000000127FD0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000127E50 }

l4000000000127FE0:
	{ adds	r48,0x0,r41; addl	r36,-1,r0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r47; adds	r48,0x0,r43; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r47; st8	[r0],r32; nop.i	0x0 }

l4000000000128010:
	{ adds	r8,0x0,r36; mov.i	ar.pfs,r46; mov.spnt	b0,r45,4000000000128010 }
	{ nop.m	0x0; adds	r12,0x30,r12; br.ret	b0 }

l4000000000128030:
	{ nop.m	0x0; cmp.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p06) br.cond.dptk.few	4000000000127D60; }

l4000000000128040:
	{ adds	r48,0x0,r43; addl	r36,-1,r0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r8,0x0,r36; adds	r1,0x0,r47; nop.b	0x0 }
	{ st8	[r0],r32; mov.i	ar.pfs,r46; mov.spnt	b0,r45,4000000000128060 }
	{ nop.m	0x0; adds	r12,0x30,r12; br.ret	b0 }

l4000000000128080:
	{ adds	r34,0x1,r34; shladd	r15,r36,0x2,r43; adds	r36,0x1,r36; }
	{ nop.m	0x0; st4	[r14],r15; cmp.eq	p07,p06,0x0,r34 }
	{ nop.m	0x0; st8	[r34],r41; (p06) br.cond.dptk.few	4000000000127E40 }

l40000000001280B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000127F70 }

l40000000001280C0:
	{ adds	r48,0x0,r41; addl	r36,-1,r0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r8,0x0,r36; adds	r1,0x0,r47; nop.b	0x0 }
	{ st8	[r0],r32; mov.i	ar.pfs,r46; mov.spnt	b0,r45,40000000001280E0 }
	{ nop.m	0x0; adds	r12,0x30,r12; br.ret	b0 }

l4000000000128100:
	{ nop.m	0x0; st4	[r0],r44; adds	r36,0x0,r39 }
	{ nop.m	0x0; st8	[r43],r32; br.cond.sptk.few	4000000000127F80; }

l4000000000128120:
	{ adds	r48,0x0,r44; addl	r36,-1,r0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r47; adds	r48,0x0,r43; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r47; nop.i	0x0 }
	{ st8	[r0],r32; nop.m	0x0; br.cond.sptk.few	4000000000128010 }

l4000000000128160:
	{ nop.m	0x0; adds	r36,0x0,r39; nop.i	0x0 }
	{ st8	[r43],r32; nop.m	0x0; br.cond.sptk.few	4000000000127F80; }

;; match_pattern_wchar: 4000000000128180
match_pattern_wchar proc
	{ nop.m	0x0; ld4	r14,[r33]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001282C0; }

l40000000001281A0:
	{ ld4	r16,[r32]; adds	r15,0xFFFFFFFFFFFFFFDF,r16; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x3B,r15; (p07) br.cond.dptk.few	40000000001281F0; }

l40000000001281C0:
	{ cmp4.eq	p06,p07,r16,r14; (p06) addl	r14,1,r0; nop.i	0x0; }

l40000000001281CC:
	{ nop; cmp4.eq.and	p00,p32,r32,r0; zxt1	r0,r64 }

l40000000001281DC:
	{ invala; break.i	0x1000; (p01) shladd	r64,r3,0x1,r64 }
	{ nop; (p18) invala.e	r0; cmp.eq	p00,p00,r32,r0 }

l40000000001281F0:
	{ addl	r17,1,r0; nop.m	0x0; sxt4	r15,r15; }
	{ nop.m	0x0; shl	r15,r17,r15; nop.b	0x0 }
	{ nop.m	0x0; movl	r17,0x80000401; }
	{ nop.m	0x0; and	r17,r17,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r17; (p06) br.cond.dptk.few	40000000001282D0 }

l4000000000128240:
	{ nop.m	0x0; movl	r17,0x40000200; }
	{ nop.m	0x0; and	r17,r17,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r17; (p06) br.cond.dptk.few	40000000001282F0; }

l4000000000128270:
	{ nop.m	0x0; tbit.z	p07,p06,r15,0x3B; (p07) br.cond.dptk.few	40000000001281C0 }

l4000000000128280:
	{ adds	r32,0x4,r32; ld4	r15,[r32]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,r15,r14; (p06) addl	r14,1,r0; nop.i	0x0; }

l400000000012829C:
	{ nop; cmp4.eq.and	p00,p32,r32,r0; zxt1	r0,r64 }

l40000000001282AC:
	{ Invalid; break.i	0x1000; (p01) shladd	r64,r3,0x1,r64 }
	{ invala; break.m	0x1000; (p01) shladd	r0,r0,0x1,r64 }

l40000000001282C0:
	{ nop.m	0x0; adds	r8,0x0,r0; br.ret	b0 }

l40000000001282D0:
	{ adds	r32,0x4,r32; ld4	r15,[r32]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x28,r15; (p07) br.cond.dptk.few	40000000001281C0 }

l40000000001282F0:
	{ nop.m	0x0; addl	r8,1,r0; br.ret	b0; }

;; wmatchlen: 4000000000128300
wmatchlen proc
	{ ld4	r14,[r32]; addl	r17,-5748,r1; adds	r15,0x4,r32 }
	{ adds	r18,0x0,r0; adds	r20,0x0,r0; adds	r19,0x0,r0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; adds	r8,0x0,r0 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000128730; }

l4000000000128340:
	{ ld8	r17,[r17]; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000128360:
	{ nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFFDF,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x3B,r14; (p07) br.cond.dptk.few	40000000001283B0 }

l4000000000128380:
	{ ld4	r14,[r15]; adds	r32,0x0,r15; adds	r8,0x1,r8; }
	{ adds	r15,0x4,r32; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.sptk.few	4000000000128360 }

l40000000001283A0:
	{ nop.m	0x0; nop.i	0x0; br.ret	b0 }

l40000000001283B0:
	{ addp4	r14,r14,r0; shladd	r14,r14,0x3,r17; nop.i	0x0; }
	{ ld8	r16,[r14]; add	r14,r14,r16; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r14,40000000001283D0; br.cond	b6; }
40000000001283E0 09 70 00 1E 10 10 00 02 3C 00 42 00 11 40 00 84 .p......<.B..@..
40000000001283F0 11 30 A0 1C 87 39 F0 20 80 00 42 03 30 00 00 43 .0...9. ..B.0..C
4000000000128400 10 00 00 00 01 00 70 00 38 0C 73 03 60 FF FF 48 ......p.8.s.`..H
4000000000128410 10 00 00 00 01 00 00 00 00 02 00 00 90 FF FF 48 ...............H
4000000000128420 10 00 00 00 01 00 80 F8 F3 FF 4F 80 08 00 84 00 ..........O.....
4000000000128430 09 70 00 1E 10 10 00 42 80 00 42 E0 11 00 00 90 .p.....B..B.....
4000000000128440 11 00 00 00 01 00 60 00 38 0E 73 03 40 01 00 43 ......`.8.s.@..C
4000000000128450 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000128460 11 38 70 1D 86 39 00 00 00 02 80 03 80 01 00 43 .8p..9.........C
4000000000128470 11 38 6C 1D 86 39 00 00 00 02 80 03 D0 01 00 43 .8l..9.........C
4000000000128480 09 00 00 00 01 00 60 D0 39 0E 73 00 00 00 04 00 ......`.9.s.....
4000000000128490 10 00 00 00 01 00 70 00 4C 8C AC 03 10 03 00 42 ......p.L......B
40000000001284A0 0B 80 00 40 10 10 70 E8 42 0C 73 00 00 00 04 00 ...@..p.B.s.....
40000000001284B0 E9 00 11 40 00 E1 F1 08 3C 00 C2 63 02 00 00 84 ...@....<..c....
40000000001284C0 F1 70 00 40 10 10 00 00 00 02 80 03 A0 00 00 43 .p.@...........C
40000000001284D0 09 00 00 00 01 00 60 70 39 0E 73 00 00 00 04 00 ......`p9.s.....
40000000001284E0 11 00 00 00 01 00 70 00 50 8C 2C 03 70 00 00 42 ......p.P.,.p..B
40000000001284F0 0B 30 F4 1C 87 B9 E1 08 00 00 48 00 00 00 04 00 .0........H.....
4000000000128500 EB 70 00 00 00 21 E0 90 38 18 40 00 00 00 04 00 .p...!..8.@.....
4000000000128510 11 30 00 1C 87 39 00 00 00 02 00 03 40 00 00 43 .0...9......@..C
4000000000128520 09 00 00 00 01 00 70 E8 42 0C 73 00 00 00 04 00 ......p.B.s.....
4000000000128530 E9 00 11 40 00 E1 F1 08 3C 00 C2 43 02 00 00 84 ...@....<..C....
4000000000128540 F1 70 00 40 10 10 00 00 00 02 80 03 20 00 00 43 .p.@........ ..C
4000000000128550 09 00 00 00 01 00 F0 08 3C 00 42 C0 01 80 00 84 ........<.B.....
4000000000128560 11 00 11 40 00 21 70 E8 3A 0C F3 03 A0 01 00 43 ...@.!p.:......C
4000000000128570 10 00 00 00 01 00 70 00 38 0C 73 03 F0 FE FF 4A ......p.8.s....J
4000000000128580 10 00 00 00 01 00 80 40 3C 00 40 80 08 00 84 00 .......@<.@.....
4000000000128590 09 70 00 1E 10 10 00 00 00 02 00 00 84 00 01 84 .p..............
40000000001285A0 11 38 00 1C 86 39 F0 20 80 00 C2 03 F0 01 00 43 .8...9. .......C
40000000001285B0 09 70 00 40 10 10 00 00 00 02 00 00 11 40 00 84 .p.@.........@..
40000000001285C0 10 00 00 00 01 00 70 00 38 0C 73 03 A0 FD FF 48 ......p.8.s....H
40000000001285D0 10 00 00 00 01 00 00 00 00 02 00 00 D0 FD FF 48 ...............H
40000000001285E0 09 70 00 40 10 10 00 22 80 00 42 E0 11 78 00 84 .p.@..."..B..x..
40000000001285F0 11 30 00 1C 87 39 00 00 00 02 00 03 90 FF FF 4B .0...9.........K
4000000000128600 09 70 00 40 10 10 00 00 00 02 00 00 44 00 01 84 .p.@........D...
4000000000128610 11 38 00 1C 86 39 00 00 00 02 80 03 70 FF FF 4B .8...9......p..K
4000000000128620 10 00 00 00 01 00 70 E8 3A 0C 73 03 50 FF FF 4A ......p.:.s.P..J
4000000000128630 10 00 00 00 01 00 00 00 00 02 00 00 D0 00 00 40 ...............@
4000000000128640 0B 80 00 40 10 10 70 D0 41 0C 73 00 00 00 04 00 ...@..p.A.s.....
4000000000128650 E9 00 11 40 00 E1 F1 08 3C 00 C2 63 12 00 00 90 ...@....<..c....
4000000000128660 F1 70 00 40 10 10 00 00 00 02 80 03 00 FF FF 4B .p.@...........K
4000000000128670 11 30 B8 20 87 39 00 00 00 02 00 03 D0 00 00 43 .0. .9.........C
4000000000128680 10 00 00 00 01 00 70 E8 41 0C 73 03 D0 FE FF 4A ......p.A.s....J
4000000000128690 0B 80 10 40 00 21 E0 00 40 20 20 00 00 00 04 00 ...@.!..@  .....
40000000001286A0 0A 30 74 1D 87 B9 01 42 80 00 42 E3 21 78 00 84 .0t....B..B.!x..
40000000001286B0 CA 90 04 00 00 A4 E1 00 80 20 A0 E3 11 78 00 84 ......... ...x..
40000000001286C0 F9 90 04 00 00 24 00 00 00 02 00 03 A0 FE FF 4B .....$.........K
40000000001286D0 08 00 11 20 00 21 00 00 00 02 00 00 00 00 04 00 ... .!..........
40000000001286E0 10 00 00 00 01 00 70 00 38 0C 73 03 80 FD FF 4A ......p.8.s....J
40000000001286F0 11 00 00 00 01 00 00 00 00 02 00 00 90 FE FF 48 ...............H
4000000000128700 09 70 00 40 10 10 80 08 20 00 42 E0 41 00 01 84 .p.@.... .B.A...
4000000000128710 10 00 00 00 01 00 70 00 38 0C 73 03 50 FC FF 48 ......p.8.s.P..H
4000000000128720 10 00 00 00 01 00 00 00 00 02 00 00 80 FC FF 48 ...............H

l4000000000128730:
	{ nop.m	0x0; adds	r8,0x0,r0; br.ret	b0 }
4000000000128740 0B 80 10 40 00 21 E0 00 40 20 20 00 00 00 04 00 ...@.!..@  .....
4000000000128750 0A 30 74 1D 87 B9 01 42 80 00 42 E3 21 78 00 84 .0t....B..B.!x..
4000000000128760 CA A0 04 00 00 A4 E1 00 80 20 A0 E3 11 78 00 84 ......... ...x..
4000000000128770 F9 A0 04 00 00 24 00 00 00 02 00 03 F0 FD FF 4B .....$.........K
4000000000128780 10 00 00 00 01 00 00 22 40 00 42 00 60 FF FF 48 ......."@.B.`..H
4000000000128790 11 00 00 00 01 00 80 08 20 00 42 80 08 00 84 00 ........ .B.....
40000000001287A0 09 30 B8 1C 87 39 00 01 80 20 20 00 00 00 04 00 .0...9...  .....
40000000001287B0 11 00 00 00 01 00 70 00 50 8C AC 03 40 FD FF 4A ......p.P...@..J
40000000001287C0 09 00 00 00 01 00 70 E8 42 0C 73 00 00 00 04 00 ......p.B.s.....
40000000001287D0 E9 00 11 40 00 E1 F1 08 3C 00 C2 83 02 00 00 84 ...@....<.......
40000000001287E0 F1 70 00 40 10 10 00 00 00 02 80 03 80 FD FF 4B .p.@...........K
40000000001287F0 11 78 04 1E 00 21 E0 00 40 00 42 00 70 FD FF 48 .x...!..@.B.p..H

;; match_pattern_char: 4000000000128800
;;   Called from:
;;     40000000000862AC (in fn4000000000085EA6)
;;     400000000008650C (in fn4000000000085EA6)
;;     400000000008650C (in fn4000000000085EA6)
match_pattern_char proc
	{ ld1	r14,[r33]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000128950; }

l4000000000128820:
	{ ld1	r16,[r32]; nop.m	0x0; sxt1	r16,r16; }
	{ adds	r15,0xFFFFFFFFFFFFFFDF,r16; nop.m	0x0; zxt1	r17,r15; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x3B,r17; (p07) br.cond.dptk.few	4000000000128880; }

l4000000000128850:
	{ cmp4.eq	p06,p07,r16,r14; (p06) addl	r14,1,r0; nop.i	0x0; }

l400000000012885C:
	{ nop; cmp4.eq.and	p00,p32,r32,r0; zxt1	r0,r64 }

l400000000012886C:
	{ invala; break.i	0x1000; (p01) shladd	r64,r3,0x1,r64 }
	{ nop; (p18) invala.e	r0; cmp.eq	p00,p00,r32,r0 }

l4000000000128880:
	{ addl	r17,1,r0; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; shl	r15,r17,r15; nop.b	0x0 }
	{ nop.m	0x0; movl	r17,0x80000401; }
	{ nop.m	0x0; and	r17,r17,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r17; (p06) br.cond.dptk.few	4000000000128960 }

l40000000001288D0:
	{ nop.m	0x0; movl	r17,0x40000200; }
	{ nop.m	0x0; and	r17,r17,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r17; (p06) br.cond.dptk.few	4000000000128990; }

l4000000000128900:
	{ nop.m	0x0; tbit.z	p07,p06,r15,0x3B; (p07) br.cond.dptk.few	4000000000128850 }

l4000000000128910:
	{ adds	r32,0x1,r32; ld1	r15,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; cmp4.eq	p06,p07,r15,r14; }
	{ (p06) addl	r14,1,r0; (p07) adds	r14,0x0,r0; nop.i	0x0; }

l4000000000128936:
	{ Invalid; nop; break.i	0x80000; }

l400000000012893C:
	{ Invalid; break.i	0x1000; (p01) shladd	r64,r3,0x1,r64 }
	{ invala; break.m	0x1000; (p01) shladd	r0,r0,0x1,r64 }

l4000000000128950:
	{ nop.m	0x0; adds	r8,0x0,r0; br.ret	b0 }

l4000000000128960:
	{ adds	r32,0x1,r32; ld1	r15,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x28,r15; (p07) br.cond.dptk.few	4000000000128850 }

l4000000000128990:
	{ nop.m	0x0; addl	r8,1,r0; br.ret	b0; }
40000000001289A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001289B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; umatchlen: 40000000001289C0
;;   Called from:
;;     400000000008622C (in fn4000000000085EA6)
;;     40000000000864CC (in fn4000000000085EA6)
umatchlen proc
	{ ld1	r14,[r32]; addl	r17,-5740,r1; adds	r15,0x1,r32 }
	{ adds	r18,0x0,r0; adds	r20,0x0,r0; adds	r19,0x0,r0; }
	{ nop.m	0x0; sxt1	r14,r14; adds	r8,0x0,r0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	4000000000128E60; }

l4000000000128A00:
	{ ld8	r17,[r17]; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000128A20:
	{ adds	r14,0xFFFFFFFFFFFFFFDF,r14; nop.m	0x0; zxt1	r14,r14; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x3B,r14; (p07) br.cond.dptk.few	4000000000128A80 }

l4000000000128A40:
	{ ld1	r14,[r15]; adds	r32,0x0,r15; adds	r8,0x1,r8; }
	{ nop.m	0x0; sxt1	r14,r14; adds	r15,0x1,r32; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.sptk.few	4000000000128A20 }

l4000000000128A70:
	{ nop.m	0x0; nop.i	0x0; br.ret	b0 }

l4000000000128A80:
	{ shladd	r14,r14,0x3,r17; ld8	r16,[r14]; nop.i	0x0; }
	{ nop.m	0x0; add	r14,r14,r16; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r14,4000000000128AA0; br.cond	b6; }
4000000000128AB0 09 70 00 1E 00 10 00 02 3C 00 42 00 11 40 00 84 .p......<.B..@..
4000000000128AC0 01 00 00 00 01 00 E0 00 38 28 00 E0 11 00 01 84 ........8(......
4000000000128AD0 11 30 A0 1C 87 39 00 00 00 02 00 03 30 00 00 43 .0...9......0..C
4000000000128AE0 10 00 00 00 01 00 70 00 38 0C 73 03 40 FF FF 48 ......p.8.s.@..H
4000000000128AF0 10 00 00 00 01 00 00 00 00 02 00 00 80 FF FF 48 ...............H
4000000000128B00 10 00 00 00 01 00 80 F8 F3 FF 4F 80 08 00 84 00 ..........O.....
4000000000128B10 09 70 00 1E 00 10 00 12 80 00 42 E0 11 00 00 90 .p........B.....
4000000000128B20 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
4000000000128B30 11 00 00 00 01 00 60 00 38 0E 73 03 C0 00 00 43 ......`.8.s....C
4000000000128B40 11 38 70 1D 86 39 00 00 00 02 80 03 D0 01 00 43 .8p..9.........C
4000000000128B50 11 38 6C 1D 86 39 00 00 00 02 80 03 30 02 00 43 .8l..9......0..C
4000000000128B60 09 30 E8 1C 87 39 00 01 80 00 20 00 00 00 04 00 .0...9.... .....
4000000000128B70 11 00 00 00 01 00 70 00 4C 8C 2C 03 F0 00 00 42 ......p.L.,....B
4000000000128B80 09 30 B8 1C 87 39 00 00 00 02 00 00 02 80 50 00 .0...9........P.
4000000000128B90 11 00 00 00 01 00 70 00 50 8C AC 03 10 01 00 42 ......p.P......B
4000000000128BA0 10 00 00 00 01 00 70 E8 42 0C 73 03 40 01 00 42 ......p.B.s.@..B
4000000000128BB0 09 00 05 40 00 21 F0 08 3C 00 42 80 02 00 00 84 ...@.!..<.B.....
4000000000128BC0 03 70 00 40 00 10 00 0A 80 00 42 C0 01 70 50 00 .p.@......B..pP.
4000000000128BD0 11 00 00 00 01 00 70 E8 3A 0C F3 03 50 02 00 43 ......p.:...P..C
4000000000128BE0 10 00 00 00 01 00 70 00 38 0C 73 03 60 FF FF 4A ......p.8.s.`..J
4000000000128BF0 10 00 00 00 01 00 80 40 3C 00 40 80 08 00 84 00 .......@<.@.....
4000000000128C00 09 70 00 1E 00 10 00 00 00 02 00 00 24 00 01 84 .p..........$...
4000000000128C10 01 00 00 00 01 00 E0 00 38 28 00 E0 11 00 01 84 ........8(......
4000000000128C20 11 38 00 1C 86 39 00 00 00 02 80 03 C0 03 00 43 .8...9.........C
4000000000128C30 03 70 00 40 00 10 80 08 20 00 42 C0 01 70 50 00 .p.@.... .B..pP.
4000000000128C40 10 00 00 00 01 00 70 00 38 0C 73 03 E0 FD FF 48 ......p.8.s....H
4000000000128C50 10 00 00 00 01 00 00 00 00 02 00 00 20 FE FF 48 ............ ..H
4000000000128C60 01 00 00 00 01 00 00 01 40 28 00 00 00 00 04 00 ........@(......
4000000000128C70 11 38 74 21 86 39 00 00 00 02 80 03 00 02 00 43 .8t!.9.........C
4000000000128C80 09 00 00 00 01 00 60 70 39 0E 73 00 00 00 04 00 ......`p9.s.....
4000000000128C90 11 00 00 00 01 00 70 00 50 8C 2C 03 50 00 00 42 ......p.P.,.P..B
4000000000128CA0 0B 30 F4 1C 87 B9 E1 08 00 00 48 00 00 00 04 00 .0........H.....
4000000000128CB0 EB 70 00 00 00 21 E0 90 38 18 40 00 00 00 04 00 .p...!..8.@.....
4000000000128CC0 11 30 00 1C 87 39 00 00 00 02 00 03 20 00 00 43 .0...9...... ..C
4000000000128CD0 10 00 00 00 01 00 70 E8 42 0C F3 03 E0 01 00 43 ......p.B......C
4000000000128CE0 09 70 00 20 00 21 F0 08 3C 00 42 00 14 00 01 84 .p. .!..<.B.....
4000000000128CF0 10 00 00 00 01 00 70 E8 3A 0C 73 03 F0 FE FF 4A ......p.:.s....J
4000000000128D00 10 00 00 00 01 00 00 00 00 02 00 00 20 01 00 40 ............ ..@
4000000000128D10 09 70 00 40 00 10 00 0A 80 00 42 E0 11 78 00 84 .p.@......B..x..
4000000000128D20 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
4000000000128D30 11 30 00 1C 87 39 00 00 00 02 00 03 C0 FE FF 4B .0...9.........K
4000000000128D40 03 70 00 40 00 10 00 0A 80 00 42 C0 01 70 50 00 .p.@......B..pP.
4000000000128D50 11 38 00 1C 86 39 00 00 00 02 80 03 A0 FE FF 4B .8...9.........K
4000000000128D60 10 00 00 00 01 00 70 E8 3A 0C 73 03 80 FE FF 4A ......p.:.s....J
4000000000128D70 10 00 00 00 01 00 00 00 00 02 00 00 B0 00 00 40 ...............@
4000000000128D80 0B 80 00 40 00 10 00 00 00 02 00 00 02 80 50 00 ...@..........P.
4000000000128D90 11 38 E8 20 86 39 00 00 00 02 80 03 60 01 00 43 .8. .9......`..C
4000000000128DA0 11 30 B8 20 87 39 00 00 00 02 00 03 90 01 00 43 .0. .9.........C
4000000000128DB0 10 00 00 00 01 00 70 E8 41 0C 73 03 30 FF FF 4A ......p.A.s.0..J
4000000000128DC0 0B 80 04 40 00 21 E0 00 40 00 20 00 00 00 04 00 ...@.!..@. .....
4000000000128DD0 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
4000000000128DE0 11 30 74 1D 87 39 00 00 00 02 00 03 C0 01 00 43 .0t..9.........C
4000000000128DF0 08 00 00 00 01 C0 F1 08 3C 00 C2 43 12 00 00 90 ........<..C....
4000000000128E00 10 00 05 20 00 21 70 00 38 0C 73 03 40 FD FF 4A ... .!p.8.s.@..J
4000000000128E10 11 00 00 00 01 00 00 00 00 02 00 00 E0 FD FF 48 ...............H
4000000000128E20 09 70 00 40 00 10 80 08 20 00 42 E0 11 00 01 84 .p.@.... .B.....
4000000000128E30 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
4000000000128E40 10 00 00 00 01 00 70 00 38 0C 73 03 E0 FB FF 48 ......p.8.s....H
4000000000128E50 10 00 00 00 01 00 00 00 00 02 00 00 20 FC FF 48 ............ ..H

l4000000000128E60:
	{ nop.m	0x0; adds	r8,0x0,r0; br.ret	b0 }
4000000000128E70 09 00 05 40 00 21 F0 08 3C 00 42 60 02 00 00 84 ...@.!..<.B`....
4000000000128E80 03 70 00 40 00 10 00 0A 80 00 42 C0 01 70 50 00 .p.@......B..pP.
4000000000128E90 10 00 00 00 01 00 70 E8 3A 0C 73 03 50 FD FF 4A ......p.:.s.P..J
4000000000128EA0 10 00 00 00 01 00 00 00 00 02 00 00 80 FF FF 48 ...............H
4000000000128EB0 09 00 05 40 00 21 F0 08 3C 00 42 40 02 00 00 84 ...@.!..<.B@....
4000000000128EC0 03 70 00 40 00 10 00 0A 80 00 42 C0 01 70 50 00 .p.@......B..pP.
4000000000128ED0 10 00 00 00 01 00 70 E8 3A 0C 73 03 10 FD FF 4A ......p.:.s....J
4000000000128EE0 10 00 00 00 01 00 00 00 00 02 00 00 40 FF FF 48 ............@..H
4000000000128EF0 09 00 05 40 00 21 F0 08 3C 00 42 60 12 00 00 90 ...@.!..<.B`....
4000000000128F00 03 70 00 40 00 10 00 0A 80 00 42 C0 01 70 50 00 .p.@......B..pP.
4000000000128F10 10 00 00 00 01 00 70 E8 3A 0C 73 03 D0 FC FF 4A ......p.:.s....J
4000000000128F20 10 00 00 00 01 00 00 00 00 02 00 00 00 FF FF 48 ...............H
4000000000128F30 0B 80 04 40 00 21 E0 00 40 00 20 00 00 00 04 00 ...@.!..@. .....
4000000000128F40 03 00 00 00 01 00 E0 00 38 28 00 C0 D0 75 1C E6 ........8(...u..
4000000000128F50 F1 78 04 1E 00 E1 41 09 00 00 C8 03 B0 FE FF 4A .x....A........J
4000000000128F60 09 00 09 40 00 21 F0 10 3C 00 42 80 12 00 00 90 ...@.!..<.B.....
4000000000128F70 03 70 00 40 00 10 00 0A 80 00 42 C0 01 70 50 00 .p.@......B..pP.
4000000000128F80 10 00 00 00 01 00 70 E8 3A 0C 73 03 60 FC FF 4A ......p.:.s.`..J
4000000000128F90 10 00 00 00 01 00 00 00 00 02 00 00 90 FE FF 48 ...............H
4000000000128FA0 09 00 09 40 00 21 F0 10 3C 00 42 40 12 00 00 90 ...@.!..<.B@....
4000000000128FB0 03 70 00 40 00 10 00 0A 80 00 42 C0 01 70 50 00 .p.@......B..pP.
4000000000128FC0 10 00 00 00 01 00 70 E8 3A 0C 73 03 20 FC FF 4A ......p.:.s. ..J
4000000000128FD0 10 00 00 00 01 00 00 00 00 02 00 00 50 FE FF 48 ............P..H
4000000000128FE0 11 00 00 00 01 00 80 08 20 00 42 80 08 00 84 00 ........ .B.....
4000000000128FF0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; getenv: 4000000000129000
;;   Called from:
;;     400000000001CCFC (in main)
;;     400000000001E3FC (in main)
;;     400000000001EC3C (in main)
;;     400000000012938C (in _getenv)
getenv proc
	{ alloc	r37,ar.pfs,0xB,0x0,0x8; ld1	r14,[r32]; mov	r39,pr }
	{ adds	r38,0x0,r1; nop.m	0x0; adds	r40,0x0,r32; }
	{ nop.m	0x0; mov	r36,b4; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000129200; }

l4000000000129040:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,find_tempenv_variable; }
	{ adds	r1,0x0,r38; nop.m	0x0; cmp.eq	p06,p07,0x0,r8 }
	{ adds	r33,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000129220; }

l4000000000129070:
	{ addl	r34,8788,r1; ld8	r40,[r34]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r40; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001290B0; }

l4000000000129090:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r38; nop.m	0x0; nop.i	0x0 }

l40000000001290B0:
	{ adds	r33,0x8,r33; ld8	r40,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r40; nop.i	0x0; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000129130; }

l40000000001290D6:
	{ chk.a.nc	r0,3FFFFFFFFF1298D6; nop; break.i	0x80000 }

l40000000001290E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r38; adds	r40,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r38; nop.m	0x0; adds	r40,0x0,r8 }
	{ ld8	r41,[r33]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r38; nop.m	0x0; nop.i	0x0 }

l4000000000129130:
	{ st8	[r8],r34; mov	pr,r39,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,4000000000129140; br.ret	b0; }

l4000000000129150:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r38; sxt4	r35,r8; cmp4.eq	p16,p17,0x0,r8; }
	{ addl	r14,-10116,r1; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r34,[r14]; ld8	r33,[r34]; adds	r34,0x8,r34; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r33; (p06) br.cond.dpnt.few	4000000000129200; }

l40000000001291A0:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dptk.few	4000000000129300 }

l40000000001291B0:
	{ ld1	r15,[r33]; ld1	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r15,r14; (p07) br.cond.dpnt.few	40000000001292D0 }

l40000000001291E0:
	{ nop.m	0x0; ld8	r33,[r34],8; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	40000000001291A0; }

l4000000000129200:
	{ adds	r8,0x0,r0; mov	pr,r39,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,4000000000129210; br.ret	b0 }

l4000000000129220:
	{ addl	r14,7172,r1; nop.m	0x0; adds	r40,0x0,r32; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000129150; }

l4000000000129250:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r14,0x28,r8; adds	r1,0x0,r38; nop.i	0x0 }
	{ cmp.eq	p06,p07,0x0,r8; adds	r8,0x8,r8; (p06) br.cond.dpnt.few	4000000000129200; }

l4000000000129280:
	{ ld4	r14,[r14]; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x0; (p06) br.cond.dpnt.few	4000000000129200; }

l40000000001292A0:
	{ nop.m	0x0; mov.spnt	b0,r36,40000000001292A0; nop.i	0x0 }
	{ ld8	r8,[r8]; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; mov	pr,r39,0xFFFFFFFFFFFFFFFE; br.ret	b0; }

l40000000001292D0:
	{ adds	r40,0x0,r33; nop.m	0x0; adds	r41,0x0,r32 }
	{ adds	r42,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C020; }
	{ adds	r1,0x0,r38; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000001291E0; }

l4000000000129300:
	{ add	r14,r33,r35; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x3D,r14; (p06) br.cond.dptk.few	40000000001291E0; }

l4000000000129330:
	{ add	r8,r33,r35,0x1; mov	pr,r39,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,4000000000129340; br.ret	b0; }
4000000000129350 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000129360 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000129370 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; _getenv: 4000000000129380
_getenv proc
	{ alloc	r2,ar.pfs,0x1,0x0,0x0; nop.i	0x0; br.cond.sptk.many	getenv; }
4000000000129390 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000001293A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001293B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; putenv: 40000000001293C0
putenv proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; ld1	r14,[r32]; mov	r34,b2 }
	{ adds	r36,0x0,r1; nop.m	0x0; adds	r37,0x0,r32; }
	{ nop.m	0x0; sxt1	r14,r14; adds	r38,0x0,r0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000129520; }

l4000000000129400:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,assignment; }
	{ nop.m	0x0; sxt4	r33,r8; adds	r37,0x0,r32 }
	{ adds	r1,0x0,r36; add	r14,r32,r33; nop.i	0x0; }
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x3D,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000129520; }

l4000000000129450:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r37,0x1,r8; adds	r1,0x0,r36; br.call.sptk.many	b0,xmalloc; }
	{ adds	r37,0x0,r8; nop.m	0x0; adds	r1,0x0,r36 }
	{ adds	r38,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r37,0x0,r8; nop.m	0x0; add	r8,r8,r33 }
	{ adds	r1,0x0,r36; adds	r39,0x0,r0; add	r38,r33,r37,0x1 }
	{ st1	[r0],r8; nop.m	0x0; br.call.sptk.many	b0,bind_variable; }
	{ cmp.eq	p07,p06,0x0,r8; adds	r15,0x28,r8; nop.i	0x0 }
	{ adds	r16,0x0,r0; adds	r1,0x0,r36; (p07) br.cond.spnt.few	4000000000129520; }

l40000000001294E0:
	{ (p06) ld4	r14,[r15]; (p06) addl	r17,-4097,r0; nop.b	0x0 }

l40000000001294E6:
	{ Invalid; nop; nop.b	0x10002; }

l40000000001294EC:
	{ nop; zxt1	r0,r64; break.i	0x1000 }
	{ (p17) cmp4.ne.and	p00,p03,r42,r0; zxt1	r68,r3; Invalid }

l4000000000129506:
	{ chk.a.nc	r34,3FFFFFFFFF209516; (p07) nop; (p01) nop }

l4000000000129510:
	{ (p06) st4	[r14],r15; nop.i	0x0; br.ret	b0; }

l4000000000129516:
	{ break.m	0x4000; (p34) nop; break.i	0x80000 }

l4000000000129520:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ addl	r16,-1,r0; addl	r14,22,r0; nop.b	0x0 }
	{ adds	r1,0x0,r36; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; st4	[r14],r8; mov.spnt	b0,r34,4000000000129550 }
	{ nop.m	0x0; adds	r8,0x0,r16; br.ret	b0; }
4000000000129570 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; setenv: 4000000000129580
setenv proc
	{ alloc	r36,ar.pfs,0x9,0x0,0x6; adds	r37,0x0,r1; mov	r35,b3 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r38,0x0,r32; (p06) br.cond.spnt.few	40000000001296E0; }

l40000000001295A0:
	{ ld1	r14,[r32]; addl	r39,61,r0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001296E0; }

l40000000001295C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B680; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r37; (p07) br.cond.dpnt.few	40000000001296E0; }

l40000000001295E0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r34; (p06) br.cond.dpnt.few	4000000000129680 }

l40000000001295F0:
	{ adds	r38,0x0,r32; nop.m	0x0; adds	r39,0x0,r33 }
	{ adds	r40,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r14,0x28,r8; adds	r1,0x0,r37; cmp.eq	p06,p07,0x0,r8 }
	{ addl	r17,-4097,r0; adds	r15,0x0,r0; (p06) br.cond.dpnt.few	4000000000129730; }

l4000000000129630:
	{ ld4	r16,[r14]; and	r16,r17,r16; nop.i	0x0; }
	{ nop.m	0x0; or	r16,0x1,r16; nop.i	0x0; }
	{ st4	[r16],r14; nop.m	0x0; nop.i	0x0 }

l4000000000129660:
	{ adds	r8,0x0,r15; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,4000000000129670; br.ret	b0; }

l4000000000129680:
	{ adds	r38,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r14,0x28,r8; adds	r1,0x0,r37; cmp.eq	p06,p07,0x0,r8 }
	{ addl	r17,-4097,r0; adds	r15,0x0,r0; (p06) br.cond.spnt.few	40000000001295F0; }

l40000000001296B0:
	{ ld4	r16,[r14]; and	r16,r17,r16; nop.i	0x0; }
	{ nop.m	0x0; or	r16,0x1,r16; nop.i	0x0; }
	{ st4	[r16],r14; nop.i	0x0; br.cond.sptk.few	4000000000129660 }

l40000000001296E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ addl	r15,-1,r0; addl	r14,22,r0; nop.b	0x0 }
	{ adds	r1,0x0,r37; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; st4	[r14],r8; mov.spnt	b0,r35,4000000000129710 }
	{ nop.m	0x0; adds	r8,0x0,r15; br.ret	b0 }

l4000000000129730:
	{ addl	r15,-1,r0; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ adds	r8,0x0,r15; mov.spnt	b0,r35,4000000000129740; br.ret	b0; }
4000000000129750 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000129760 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000129770 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; unsetenv: 4000000000129780
unsetenv proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x4; ld1	r14,[r32]; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; adds	r36,0x0,r32; }
	{ nop.m	0x0; sxt1	r14,r14; addl	r37,61,r0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000129820; }

l40000000001297C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B680; }
	{ cmp.eq	p06,p07,0x0,r8; nop.m	0x0; adds	r1,0x0,r35 }
	{ adds	r36,0x0,r32; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000129820; }

l40000000001297F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,unbind_variable; }
	{ adds	r14,0x0,r0; adds	r1,0x0,r35; mov.i	ar.pfs,r34; }
	{ adds	r8,0x0,r14; mov.spnt	b0,r33,4000000000129810; br.ret	b0; }

l4000000000129820:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ addl	r14,-1,r0; addl	r15,22,r0; nop.b	0x0 }
	{ adds	r1,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; st4	[r15],r8; mov.spnt	b0,r33,4000000000129850 }
	{ nop.m	0x0; adds	r8,0x0,r14; br.ret	b0; }
4000000000129870 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; getmaxgroups: 4000000000129880
;;   Called from:
;;     400000000003ED1C (in fn400000000003E980)
getmaxgroups proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; mov	r33,b1; addl	r32,6420,r1 }
	{ adds	r35,0x0,r1; ld4	r8,[r32]; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; cmp4.lt	p06,p07,0x0,r8; mov.spnt	b0,r33,40000000001298A0 }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	40000000001298C0; br.ret	b0; }

l40000000001298BC:
	{ shladd	r0,r33,0x2,r0; (p52) invala.e	r0; break.i	0x1000 }

l40000000001298C0:
	{ addl	r36,3,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AD00; }
	{ adds	r14,0x0,r8; cmp4.lt	p07,p06,0x0,r8; nop.b	0x0 }
	{ adds	r1,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ (p06) addl	r14,64,r0; (p06) addl	r8,64,r0; mov.spnt	b0,r33,40000000001298F0; }

l40000000001298F6:
	{ Invalid; nop; nop; }

l40000000001298FC:
	{ Invalid; Invalid; Invalid }
	{ nop; break.m	0x1000; break.i	0x1000 }
4000000000129910 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000129920 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000129930 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; getmaxchild: 4000000000129940
;;   Called from:
;;     400000000007AE0C (in fn400000000007A7C0)
;;     400000000007FC2C (in initialize_job_control)
getmaxchild proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; mov	r33,b1; addl	r32,6428,r1 }
	{ adds	r35,0x0,r1; ld8	r8,[r32]; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; cmp.lt	p06,p07,0x0,r8; mov.spnt	b0,r33,4000000000129960 }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	4000000000129980; br.ret	b0; }

l400000000012997C:
	{ shladd	r0,r33,0x2,r0; (p20) invala.e	r0; break.i	0x1000 }

l4000000000129980:
	{ addl	r36,1,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AD00; }
	{ adds	r1,0x0,r35; st8	[r8],r32; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000001299A0; br.ret	b0; }
40000000001299B0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; sh_setlinebuf: 40000000001299C0
sh_setlinebuf proc
	{ alloc	r34,ar.pfs,0x8,0x0,0x4; mov	r33,b1; adds	r35,0x0,r1 }
	{ adds	r36,0x0,r32; adds	r37,0x0,r0; addl	r38,1,r0 }
	{ addl	r39,8192,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B720; }
	{ adds	r1,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,4000000000129A00; br.ret	b0; }
4000000000129A10 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
4000000000129A20 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
4000000000129A30 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; inttostr: 4000000000129A40
;;   Called from:
;;     40000000000458FC (in fn4000000000045480)
;;     4000000000068A2C (in sh_set_lines_and_columns)
;;     4000000000068A7C (in sh_set_lines_and_columns)
;;     4000000000068B4C (in set_ppid)
;;     400000000006C68C (in initialize_shell_variables)
;;     400000000006C6EC (in initialize_shell_variables)
;;     400000000006C96C (in initialize_shell_variables)
;;     400000000006C9DC (in initialize_shell_variables)
;;     400000000006D51C (in initialize_shell_variables)
;;     400000000006EA5C (in set_pipestatus_array)
;;     400000000006EB1C (in set_pipestatus_array)
;;     400000000006EBFC (in set_pipestatus_array)
;;     400000000006EC5C (in set_pipestatus_array)
;;     40000000000A28AC (in fn40000000000A1400)
;;     40000000000BCC9C (in array_to_assign)
;;     40000000000E32BC (in fn40000000000E3200)
;;     40000000000E335C (in fn40000000000E3200)
;;     40000000000E33FC (in fn40000000000E3200)
;;     40000000000E35AC (in fn40000000000E3200)
;;     40000000000E367C (in fn40000000000E3200)
inttostr proc
	{ alloc	r36,ar.pfs,0xB,0x0,0x6; adds	r37,0x0,r1; mov	r35,b3 }
	{ adds	r38,0x0,r32; adds	r40,0x0,r33; adds	r41,0x0,r34; }
	{ addl	r39,10,r0; adds	r42,0x0,r0; br.call.sptk.many	b0,fmtumax; }
	{ adds	r1,0x0,r37; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,4000000000129A80; br.ret	b0; }
4000000000129A90 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000129AA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000129AB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; itos: 4000000000129AC0
;;   Called from:
;;     400000000001FD9C (in main)
;;     400000000002771C (in decode_prompt_string)
;;     400000000004226C (in get_group_list)
;;     400000000004F8DC (in coproc_setvars)
;;     400000000004F93C (in coproc_setvars)
;;     400000000004F9CC (in coproc_setvars)
;;     400000000004FA8C (in coproc_setvars)
;;     400000000004FAEC (in coproc_setvars)
;;     400000000004FB7C (in coproc_setvars)
;;     4000000000063D8C (in make_variable_value)
;;     400000000006AB3C (in push_args)
;;     400000000006E9CC (in set_pipestatus_array)
;;     400000000006ED1C (in set_pipestatus_array)
;;     400000000007260C (in fn4000000000072100)
;;     40000000000727EC (in fn4000000000072100)
;;     4000000000073DAC (in fn4000000000073B40)
;;     40000000000BC78C (in array_keys_to_word_list)
;;     40000000000C67EC (in brace_expand)
;;     40000000000E0EAC (in redirection_error)
;;     40000000000E150C (in redirection_error)
;;     40000000000E15EC (in redirection_error)
;;     40000000000F4C2C (in fn40000000000F4180)
;;     40000000000F56BC (in fn40000000000F4180)
;;     40000000000FF5AC (in jobs_builtin)
itos proc
	{ alloc	r35,ar.pfs,0xA,0x0,0x5; adds	r12,0xFFFFFFFFFFFFFFE0,r12; mov	r34,b2 }
	{ adds	r36,0x0,r1; nop.m	0x0; adds	r37,0x0,r32; }
	{ adds	r39,0x10,r12; addl	r40,22,r0; nop.i	0x0 }
	{ adds	r41,0x0,r0; addl	r38,10,r0; br.call.sptk.many	b0,fmtumax; }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r33,0x0,r8 }
	{ adds	r37,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r36; adds	r37,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r37,0x0,r8 }
	{ adds	r38,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r36; mov.i	ar.pfs,r35; mov.spnt	b0,r34,4000000000129B50 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0; }
4000000000129B70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; uinttostr: 4000000000129B80
uinttostr proc
	{ alloc	r36,ar.pfs,0xB,0x0,0x6; adds	r37,0x0,r1; mov	r35,b3 }
	{ adds	r38,0x0,r32; adds	r40,0x0,r33; adds	r41,0x0,r34; }
	{ addl	r39,10,r0; addl	r42,8,r0; br.call.sptk.many	b0,fmtumax; }
	{ adds	r1,0x0,r37; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,4000000000129BC0; br.ret	b0; }
4000000000129BD0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000129BE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000129BF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; uitos: 4000000000129C00
uitos proc
	{ alloc	r35,ar.pfs,0xA,0x0,0x5; adds	r12,0xFFFFFFFFFFFFFFE0,r12; mov	r34,b2 }
	{ adds	r36,0x0,r1; nop.m	0x0; adds	r37,0x0,r32; }
	{ adds	r39,0x10,r12; addl	r40,21,r0; nop.i	0x0 }
	{ addl	r41,8,r0; addl	r38,10,r0; br.call.sptk.many	b0,fmtumax; }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r33,0x0,r8 }
	{ adds	r37,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r36; adds	r37,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r37,0x0,r8 }
	{ adds	r38,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r36; mov.i	ar.pfs,r35; mov.spnt	b0,r34,4000000000129C90 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0; }
4000000000129CB0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; zread: 4000000000129CC0
;;   Called from:
;;     400000000009454C (in command_substitute)
;;     40000000000B000C (in buffered_getchar)
;;     40000000000B011C (in buffered_getchar)
;;     40000000000B01DC (in buffered_getchar)
;;     4000000000105D8C (in read_builtin)
;;     40000000001073AC (in read_builtin)
;;     4000000000129F5C (in zreadcn)
;;     4000000000134C7C (in zcatfd)
;;     4000000000134DAC (in zmapfd)
;;     4000000000134E7C (in zmapfd)
;;     400000000013527C (in zgetline)
zread proc
	{ alloc	r37,ar.pfs,0xA,0x0,0x7; mov	r36,b4; adds	r38,0x0,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000129CE0:
	{ adds	r39,0x0,r32; nop.m	0x0; adds	r40,0x0,r33 }
	{ adds	r41,0x0,r34; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A600; }
	{ cmp.lt	p06,p07,r8,r0; nop.m	0x0; adds	r1,0x0,r38 }
	{ adds	r35,0x0,r8; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000129D50; }

l4000000000129D20:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ ld4	r14,[r8]; nop.m	0x0; adds	r1,0x0,r38; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x4,r14; (p06) br.cond.dptk.few	4000000000129CE0 }

l4000000000129D50:
	{ adds	r8,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,4000000000129D60; br.ret	b0; }
4000000000129D70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; zreadretry: 4000000000129D80
zreadretry proc
	{ alloc	r38,ar.pfs,0xB,0x0,0x8; mov	r37,b5; nop.i	0x0 }
	{ adds	r39,0x0,r1; nop.i	0x0; addl	r36,3,r0; }

l4000000000129DA0:
	{ adds	r40,0x0,r32; adds	r41,0x0,r33; nop.i	0x0 }
	{ adds	r42,0x0,r34; adds	r36,0xFFFFFFFFFFFFFFFF,r36; br.call.sptk.many	b0,fn400000000001A600; }
	{ cmp.lt	p07,p06,r8,r0; nop.m	0x0; adds	r1,0x0,r39 }
	{ adds	r35,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000129E20; }

l4000000000129DE0:
	{ cmp.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000129E20; }

l4000000000129DF0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ ld4	r14,[r8]; adds	r1,0x0,r39; cmp4.eq	p09,p08,0x0,r36; }
	{ cmp4.eq	p07,p06,0x4,r14; (p06) br.cond.dpnt.few	4000000000129E20; (p08) br.cond.dptk.few	4000000000129DA0 }

l4000000000129E1C:
	{ (p60) nop; zxt1	r96,r64; break.b	0x1000 }

l4000000000129E20:
	{ adds	r8,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,4000000000129E30; br.ret	b0; }

;; zreadintr: 4000000000129E40
;;   Called from:
;;     400000000012A0FC (in zreadcintr)
zreadintr proc
	{ alloc	r36,ar.pfs,0x9,0x0,0x6; adds	r37,0x0,r1; mov	r35,b3 }
	{ adds	r38,0x0,r32; adds	r39,0x0,r33; adds	r40,0x0,r34; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A600; }
	{ adds	r1,0x0,r37; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,4000000000129E80; br.ret	b0; }
4000000000129E90 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000129EA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000129EB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; zreadcn: 4000000000129EC0
;;   Called from:
;;     400000000010736C (in read_builtin)
;;     400000000012A05C (in zreadc)
zreadcn proc
	{ alloc	r38,ar.pfs,0xB,0x0,0x8; addl	r35,8796,r1; nop.b	0x0 }
	{ addl	r36,8804,r1; addl	r41,21292,r1; mov	r37,b5; }
	{ addl	r42,128,r0; ld8	r14,[r36]; adds	r39,0x0,r1 }
	{ adds	r40,0x0,r32; ld8	r15,[r35]; nop.i	0x0; }
	{ cmp4.ltu	p06,p07,r42,r34; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; (p06) adds	r42,0x1,r0; nop.i	0x0; }

l4000000000129F1C:
	{ getf.s	r0,f1; (p05) cmp.lt	p00,p16,r0,r64; (p32) mov	pr,r99,0xE0C6 }

l4000000000129F26:
	{ (p03) chk.a.clr	r14,3FFFFFFFFFD2D816; nop; break.i	0x80000 }

l4000000000129F30:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000129FA0; }

l4000000000129F40:
	{ nop.m	0x0; tbit.z	p07,p06,r42,0x0; (p07) adds	r42,0x0,r34; }

l4000000000129F50:
	{ (p06) addl	r42,128,r0; nop.i	0x0; br.call.sptk.many	b0,zread; }

l4000000000129F56:
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; Invalid; nop }
	{ break.m	0x4000; nop; (p01) nop }

l4000000000129F86:
	{ chk.a.nc	f0,3FFFFFFFFF12A786; nop; nop }

l4000000000129F90:
	{ st8	[r8],r36; nop.m	0x0; nop.i	0x0 }

l4000000000129FA0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r33; nop.i	0x0; }
	{ (p07) addl	r15,21292,r1; (p07) ld8	r14,[r35]; (p07) addl	r8,1,r0; }

l4000000000129FB6:
	{ (p07) chk.a.nc	f0,3FFFFFFFFF9361E6; Invalid; add	r0,r0,r32; }

l4000000000129FBC:
	{ Invalid; mov	pr,r32,0x0; Invalid; }

l4000000000129FC0:
	{ nop.m	0x0; (p06) addl	r8,1,r0; (p07) add	r15,r15,r14 }

l4000000000129FCC:
	{ (p07) cmp4.eq.and	p14,p42,r0,r64; (p17) cmp4.ne.or.andcm	p00,p48,r3,r64; (p01) rfi; }

l4000000000129FD0:
	{ (p07) adds	r14,0x1,r14; (p07) ld1	r15,[r15]; nop.i	0x0 }

l4000000000129FD6:
	{ (p07) fwb; cmp.ltu	p00,p00,0x0,r1; Invalid; }

l4000000000129FDC:
	{ Invalid; (p32) mov	pr,r8,0x46C6; Invalid }

l4000000000129FE6:
	{ mf.a; mov	pr,0x4000; break.i	0x80000; }

l4000000000129FEC:
	{ nop.m	0x80; break.i	0x1000; (p32) break.i	0x2A809 }

l4000000000129FF0:
	{ nop.m	0x0; mov.i	ar.pfs,r38; nop.i	0x0; }

l4000000000129FF2:
	{ cmp.lt	p32,p00,r0,r0; (p04) break.i	0x550; Invalid }
	{ nop; (p20) nop; Invalid }
400000000012A010 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012A020 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012A030 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; zreadc: 400000000012A040
;;   Called from:
;;     4000000000105DAC (in read_builtin)
;;     4000000000105F4C (in read_builtin)
;;     400000000013528C (in zgetline)
zreadc proc
	{ alloc	r16,ar.pfs,0x3,0x0,0x3; addl	r34,128,r0; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x3,0x0,0x0; nop.i	0x0; br.cond.sptk.many	zreadcn; }
400000000012A060 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
400000000012A070 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; zreadcintr: 400000000012A080
zreadcintr proc
	{ alloc	r37,ar.pfs,0xA,0x0,0x7; addl	r34,8796,r1; nop.b	0x0 }
	{ addl	r35,8804,r1; addl	r40,21292,r1; mov	r36,b4; }
	{ ld8	r14,[r35]; adds	r38,0x0,r1; addl	r41,128,r0 }
	{ adds	r39,0x0,r32; ld8	r15,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,r14,r15; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dpnt.few	400000000012A0F0; }

l400000000012A0E0:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	400000000012A140 }

l400000000012A0F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,zreadintr; }
	{ nop.m	0x0; cmp.lt	p06,p07,0x0,r8; adds	r1,0x0,r38 }
	{ st8	[r0],r34; nop.i	0x0; nop.i	0x0 }
	{ (p07) st8	[r0],r35; nop.m	0x0; (p07) br.cond.dpnt.few	400000000012A190; }

l400000000012A126:
	{ chk.a.nc	f0,3FFFFFFFFF12A926; nop; nop }

l400000000012A130:
	{ st8	[r8],r35; nop.m	0x0; nop.i	0x0 }

l400000000012A140:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r33; nop.i	0x0; }
	{ (p07) addl	r15,21292,r1; (p07) ld8	r14,[r34]; (p07) addl	r8,1,r0; }

l400000000012A156:
	{ (p07) chk.a.nc	f0,3FFFFFFFFF936376; Invalid; add	r0,r0,r32; }

l400000000012A15C:
	{ Invalid; mov	pr,r32,0x0; Invalid; }

l400000000012A160:
	{ nop.m	0x0; (p06) addl	r8,1,r0; (p07) add	r15,r15,r14 }

l400000000012A16C:
	{ (p07) cmp4.eq.and	p14,p42,r0,r64; (p17) cmp4.ne.or.andcm	p00,p48,r3,r64; (p01) rfi; }

l400000000012A170:
	{ (p07) adds	r14,0x1,r14; (p07) ld1	r15,[r15]; nop.i	0x0 }

l400000000012A176:
	{ (p07) fwb; cmp.ltu	p00,p00,0x0,r1; Invalid; }

l400000000012A17C:
	{ Invalid; (p32) mov	pr,r8,0x4686; Invalid }

l400000000012A186:
	{ mf.a; mov	pr,0x4000; break.i	0x80000; }

l400000000012A18C:
	{ nop.m	0x80; break.i	0x1000; (p16) break.i	0x2A809 }

l400000000012A190:
	{ nop.m	0x0; mov.i	ar.pfs,r37; nop.i	0x0; }

l400000000012A192:
	{ nop; (p04) break.i	0x550; Invalid }
	{ add	r32,r0,r0; (p20) nop; Invalid }
400000000012A1B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; zreset: 400000000012A1C0
;;   Called from:
;;     400000000010121C (in mapfile_builtin)
;;     400000000010178C (in mapfile_builtin)
;;     400000000010178C (in mapfile_builtin)
zreset proc
	{ addl	r14,8804,r1; st8	[r0],r14; addl	r14,8796,r1; }
	{ st8	[r0],r14; nop.i	0x0; br.ret	b0; }
400000000012A1E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012A1F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; zsyncfd: 400000000012A200
;;   Called from:
;;     400000000010161C (in mapfile_builtin)
;;     40000000001016BC (in mapfile_builtin)
;;     4000000000106E3C (in read_builtin)
zsyncfd proc
	{ alloc	r36,ar.pfs,0x9,0x0,0x6; addl	r34,8804,r1; mov	r35,b3 }
	{ addl	r33,8796,r1; adds	r37,0x0,r1; adds	r38,0x0,r32; }
	{ nop.m	0x0; ld8	r39,[r34]; addl	r40,1,r0 }
	{ ld8	r14,[r33]; sub	r39,r39,r14; nop.i	0x0; }
	{ cmp.lt	p06,p07,0x0,r39; sub	r39,r0,r39; (p07) br.cond.dpnt.few	400000000012A270; }

l400000000012A250:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AA20; }
	{ adds	r1,0x0,r37; cmp.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dpnt.few	400000000012A280 }

l400000000012A270:
	{ st8	[r0],r33; st8	[r0],r34; nop.i	0x0 }

l400000000012A280:
	{ nop.m	0x0; mov.i	ar.pfs,r36; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r35,400000000012A290; br.ret	b0; }
400000000012A2A0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
400000000012A2B0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; ttgetattr: 400000000012A2C0
;;   Called from:
;;     40000000001066EC (in read_builtin)
;;     4000000000106F2C (in read_builtin)
;;     400000000012A41C (in ttsave)
;;     400000000012A43C (in ttsave)
ttgetattr proc
	{ alloc	r35,ar.pfs,0x7,0x0,0x5; mov	r34,b2; nop.b	0x0 }
	{ adds	r36,0x0,r1; adds	r37,0x0,r32; adds	r38,0x0,r33; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C400; }
	{ adds	r1,0x0,r36; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,400000000012A300; br.ret	b0; }
400000000012A310 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012A320 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012A330 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; ttsetattr: 400000000012A340
;;   Called from:
;;     400000000010456C (in fn4000000000104540)
;;     400000000012A4DC (in ttrestore)
;;     400000000012A4FC (in ttrestore)
;;     400000000012A6EC (in ttfd_onechar)
;;     400000000012A86C (in ttfd_noecho)
;;     400000000012AA0C (in ttfd_eightbit)
;;     400000000012AB6C (in ttfd_nocanon)
;;     400000000012AD26 (in ttfd_cbreak)
ttsetattr proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; mov	r34,b2; nop.b	0x0 }
	{ adds	r36,0x0,r1; adds	r37,0x0,r32; adds	r39,0x0,r33; }
	{ addl	r38,1,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B1E0; }
	{ adds	r1,0x0,r36; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,400000000012A380; br.ret	b0; }
400000000012A390 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012A3A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012A3B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; ttsave: 400000000012A3C0
ttsave proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x4; mov	r33,b1; addl	r32,8812,r1 }
	{ adds	r35,0x0,r1; ld4	r14,[r32]; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; mov.spnt	b0,r33,400000000012A3E0 }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	400000000012A400; br.ret	b0 }

l400000000012A3FC:
	{ nop; (p04) invala.e	r43; add	r0,r32,r0 }

l400000000012A400:
	{ addl	r37,21420,r1; nop.m	0x0; adds	r36,0x0,r0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,ttgetattr; }
	{ adds	r1,0x0,r35; addl	r36,1,r0; addl	r37,21480,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,ttgetattr; }
	{ addl	r14,1,r0; adds	r1,0x0,r35; mov.i	ar.pfs,r34; }
	{ st4	[r14],r32; mov.spnt	b0,r33,400000000012A450; br.ret	b0; }
400000000012A460 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012A470 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; ttrestore: 400000000012A480
ttrestore proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x4; mov	r33,b1; addl	r32,8812,r1 }
	{ adds	r35,0x0,r1; ld4	r14,[r32]; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; mov.spnt	b0,r33,400000000012A4A0 }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	400000000012A4C0; br.ret	b0 }

l400000000012A4BC:
	{ nop; (p04) invala.e	r43; add	r0,r32,r0 }

l400000000012A4C0:
	{ addl	r37,21420,r1; nop.m	0x0; adds	r36,0x0,r0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,ttsetattr; }
	{ adds	r1,0x0,r35; addl	r36,1,r0; addl	r37,21480,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,ttsetattr; }
	{ adds	r1,0x0,r35; st4	[r0],r32; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,400000000012A510; br.ret	b0; }
400000000012A520 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012A530 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; ttattr: 400000000012A540
ttattr proc
	{ cmp4.eq	p07,p06,0x1,r32; addl	r14,8812,r1; cmp4.eq	p08,p09,0x0,r32; }
	{ (p07) addl	r8,21480,r1; ld4	r14,[r14]; nop.i	0x0; }

l400000000012A556:
	{ (p07) fwb; addl	r0,32768,r1; (p01) nop }

l400000000012A566:
	{ break.m	0x4000; (p03) nop; (p01) nop }

l400000000012A576:
	{ Invalid; (p34) nop; break.i	0x80000 }

l400000000012A57C:
	{ nop; break.m	0x1000; zxt4	r43,r41 }

l400000000012A580:
	{ nop.m	0x0; addl	r8,21420,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.ret	b0; }

l400000000012A5A0:
	{ nop.m	0x0; adds	r8,0x0,r0; br.ret	b0; }
400000000012A5B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; tt_setonechar: 400000000012A5C0
;;   Called from:
;;     400000000012A6AC (in ttfd_onechar)
;;     400000000012AC6C (in tt_setcbreak)
tt_setonechar proc
	{ ld4	r17,[r32]; adds	r18,0x17,r32; addl	r19,1,r0 }
	{ adds	r15,0xC,r32; adds	r14,0x0,r32; adds	r32,0x16,r32; }
	{ st1	[r19],r18; and	r17,0xFFFFFFFFFFFFFFBF,r17; addl	r18,256,r0 }
	{ ld4	r16,[r15]; st1	[r0],r32; adds	r8,0x0,r0; }
	{ or	r17,r18,r17; nop.m	0x0; and	r16,0xFFFFFFFFFFFFFFFD,r16; }
	{ st4	[r14],r4,4; addl	r17,32769,r0; or	r17,r17,r16 }
	{ ld4	r16,[r14]; nop.i	0x0; and	r16,0xFFFFFFFFFFFFFFC7,r16 }
	{ st4	[r17],r15; or	r16,0x5,r16; nop.i	0x0; }
	{ st4	[r16],r14; nop.i	0x0; br.ret	b0; }
400000000012A650 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012A660 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012A670 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; ttfd_onechar: 400000000012A680
;;   Called from:
;;     4000000000107FEC (in read_builtin)
;;     400000000012A7BC (in ttonechar)
ttfd_onechar proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; nop.m	0x0; mov	r34,b2 }
	{ adds	r36,0x0,r1; nop.m	0x0; adds	r37,0x0,r33; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,tt_setonechar; }
	{ adds	r1,0x0,r36; cmp4.lt	p06,p07,r8,r0; mov.spnt	b0,r34,400000000012A6B0 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dpnt.few	400000000012A6F0; }

l400000000012A6D0:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	ttsetattr }

l400000000012A6F0:
	{ addl	r8,-1,r0; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,400000000012A700; br.ret	b0; }
400000000012A710 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012A720 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012A730 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; ttonechar: 400000000012A740
ttonechar proc
	{ alloc	r33,ar.pfs,0x6,0x0,0x3; adds	r12,0xFFFFFFFFFFFFFFC0,r12; mov	r32,b0 }
	{ addl	r14,8812,r1; addl	r36,21420,r1; adds	r34,0x0,r1; }
	{ ld4	r14,[r14]; adds	r35,0x10,r12; addl	r37,60,r0 }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; }
	{ (p06) addl	r8,-1,r0; nop.i	0x0; (p06) br.cond.dpnt.few	400000000012A7D0; }

l400000000012A786:
	{ chk.a.nc	r0,3FFFFFFFFF12AF86; nop; break.i	0x80000 }

l400000000012A790:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ adds	r1,0x0,r34; nop.m	0x0; adds	r35,0x0,r0 }
	{ adds	r36,0x10,r12; nop.m	0x0; br.call.sptk.many	b0,ttfd_onechar; }
	{ adds	r1,0x0,r34; nop.m	0x0; nop.i	0x0 }

l400000000012A7D0:
	{ nop.m	0x0; mov.i	ar.pfs,r33; mov.spnt	b0,r32,400000000012A7D0 }
	{ nop.m	0x0; adds	r12,0x40,r12; br.ret	b0; }
400000000012A7F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; tt_setnoecho: 400000000012A800
tt_setnoecho proc
	{ adds	r32,0xC,r32; nop.m	0x0; adds	r8,0x0,r0; }
	{ ld4	r14,[r32]; and	r14,0xFFFFFFFFFFFFFF97,r14; nop.i	0x0; }
	{ st4	[r14],r32; nop.i	0x0; br.ret	b0; }
400000000012A830 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; ttfd_noecho: 400000000012A840
;;   Called from:
;;     400000000010674C (in read_builtin)
;;     400000000012A8FC (in ttnoecho)
ttfd_noecho proc
	{ adds	r14,0xC,r33; ld4	r15,[r14]; nop.i	0x0; }
	{ and	r15,0xFFFFFFFFFFFFFF97,r15; st4	[r15],r14; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	ttsetattr; }
400000000012A870 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; ttnoecho: 400000000012A880
ttnoecho proc
	{ alloc	r33,ar.pfs,0x6,0x0,0x3; adds	r12,0xFFFFFFFFFFFFFFC0,r12; mov	r32,b0 }
	{ addl	r14,8812,r1; addl	r36,21420,r1; adds	r34,0x0,r1; }
	{ ld4	r14,[r14]; adds	r35,0x10,r12; addl	r37,60,r0 }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; }
	{ (p06) addl	r8,-1,r0; nop.i	0x0; (p06) br.cond.dpnt.few	400000000012A910; }

l400000000012A8C6:
	{ chk.a.nc	r0,3FFFFFFFFF12B0C6; nop; break.i	0x80000 }

l400000000012A8D0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ adds	r1,0x0,r34; nop.m	0x0; adds	r35,0x0,r0 }
	{ adds	r36,0x10,r12; nop.m	0x0; br.call.sptk.many	b0,ttfd_noecho; }
	{ adds	r1,0x0,r34; nop.m	0x0; nop.i	0x0 }

l400000000012A910:
	{ nop.m	0x0; mov.i	ar.pfs,r33; mov.spnt	b0,r32,400000000012A910 }
	{ nop.m	0x0; adds	r12,0x40,r12; br.ret	b0; }
400000000012A930 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; tt_seteightbit: 400000000012A940
tt_seteightbit proc
	{ ld4	r14,[r32]; addl	r15,-257,r0; adds	r8,0x0,r0; }
	{ and	r14,0xFFFFFFFFFFFFFFDF,r14; st4	[r32],r8,8; nop.i	0x0; }
	{ ld4	r14,[r32]; and	r14,r15,r14; nop.i	0x0; }
	{ nop.m	0x0; or	r14,0x30,r14; nop.i	0x0; }
	{ st4	[r14],r32; nop.i	0x0; br.ret	b0; }
400000000012A990 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012A9A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012A9B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; ttfd_eightbit: 400000000012A9C0
;;   Called from:
;;     400000000012AABC (in tteightbit)
ttfd_eightbit proc
	{ ld4	r15,[r33]; adds	r14,0x0,r33; addl	r16,-257,r0; }
	{ and	r15,0xFFFFFFFFFFFFFFDF,r15; st4	[r14],r8,8; nop.i	0x0; }
	{ ld4	r15,[r14]; and	r15,r16,r15; nop.i	0x0; }
	{ or	r15,0x30,r15; st4	[r15],r14; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	ttsetattr; }
400000000012AA10 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
400000000012AA20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012AA30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; tteightbit: 400000000012AA40
tteightbit proc
	{ alloc	r33,ar.pfs,0x6,0x0,0x3; adds	r12,0xFFFFFFFFFFFFFFC0,r12; mov	r32,b0 }
	{ addl	r14,8812,r1; addl	r36,21420,r1; adds	r34,0x0,r1; }
	{ ld4	r14,[r14]; adds	r35,0x10,r12; addl	r37,60,r0 }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; }
	{ (p06) addl	r8,-1,r0; nop.i	0x0; (p06) br.cond.dpnt.few	400000000012AAD0; }

l400000000012AA86:
	{ chk.a.nc	r0,3FFFFFFFFF12B286; nop; break.i	0x80000 }

l400000000012AA90:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ adds	r1,0x0,r34; nop.m	0x0; adds	r35,0x0,r0 }
	{ adds	r36,0x10,r12; nop.m	0x0; br.call.sptk.many	b0,ttfd_eightbit; }
	{ adds	r1,0x0,r34; nop.m	0x0; nop.i	0x0 }

l400000000012AAD0:
	{ nop.m	0x0; mov.i	ar.pfs,r33; mov.spnt	b0,r32,400000000012AAD0 }
	{ nop.m	0x0; adds	r12,0x40,r12; br.ret	b0; }
400000000012AAF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; tt_setnocanon: 400000000012AB00
tt_setnocanon proc
	{ adds	r32,0xC,r32; nop.m	0x0; adds	r8,0x0,r0; }
	{ ld4	r14,[r32]; and	r14,0xFFFFFFFFFFFFFFFD,r14; nop.i	0x0; }
	{ st4	[r14],r32; nop.i	0x0; br.ret	b0; }
400000000012AB30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; ttfd_nocanon: 400000000012AB40
;;   Called from:
;;     400000000012ABFC (in ttnocanon)
ttfd_nocanon proc
	{ adds	r14,0xC,r33; ld4	r15,[r14]; nop.i	0x0; }
	{ and	r15,0xFFFFFFFFFFFFFFFD,r15; st4	[r15],r14; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	ttsetattr; }
400000000012AB70 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; ttnocanon: 400000000012AB80
ttnocanon proc
	{ alloc	r33,ar.pfs,0x6,0x0,0x3; adds	r12,0xFFFFFFFFFFFFFFC0,r12; mov	r32,b0 }
	{ addl	r14,8812,r1; addl	r36,21420,r1; adds	r34,0x0,r1; }
	{ ld4	r14,[r14]; adds	r35,0x10,r12; addl	r37,60,r0 }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; }
	{ (p06) addl	r8,-1,r0; nop.i	0x0; (p06) br.cond.dpnt.few	400000000012AC10; }

l400000000012ABC6:
	{ chk.a.nc	r0,3FFFFFFFFF12B3C6; nop; break.i	0x80000 }

l400000000012ABD0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ adds	r1,0x0,r34; nop.m	0x0; adds	r35,0x0,r0 }
	{ adds	r36,0x10,r12; nop.m	0x0; br.call.sptk.many	b0,ttfd_nocanon; }
	{ adds	r1,0x0,r34; nop.m	0x0; nop.i	0x0 }

l400000000012AC10:
	{ nop.m	0x0; mov.i	ar.pfs,r33; mov.spnt	b0,r32,400000000012AC10 }
	{ nop.m	0x0; adds	r12,0x40,r12; br.ret	b0; }
400000000012AC30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; tt_setcbreak: 400000000012AC40
;;   Called from:
;;     400000000012ACEC (in ttfd_cbreak)
tt_setcbreak proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; mov	r33,b1; nop.b	0x0 }
	{ adds	r35,0x0,r1; adds	r36,0x0,r32; adds	r32,0xC,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,tt_setonechar; }
	{ cmp4.lt	p06,p07,r8,r0; adds	r1,0x0,r35; mov.i	ar.pfs,r34; }
	{ (p07) ld4	r14,[r32]; (p07) adds	r8,0x0,r0; mov.spnt	b0,r33,400000000012AC80; }

l400000000012AC86:
	{ Invalid; cmp4.ltu	p33,p03,r1,r64; (p33) nop; }

l400000000012AC8C:
	{ (p16) cmp4.eq.and	p01,p41,r64,r3; zxt2	r69,r11; break.b	0x1000 }

l400000000012AC96:
	{ chk.a.nc	r0,3FFFFFFFFF12B496; (p04) cmp4.ne.or.andcm	p63,p15,r124,r127; (p01) nop }

l400000000012ACA0:
	{ (p07) st4	[r14],r32; nop.i	0x0; br.ret	b0; }

l400000000012ACA6:
	{ break.m	0x4000; (p34) nop; break.i	0x80000 }
400000000012ACB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; ttfd_cbreak: 400000000012ACC0
;;   Called from:
;;     4000000000106FAC (in read_builtin)
;;     400000000012ADFC (in ttcbreak)
ttfd_cbreak proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; nop.m	0x0; mov	r34,b2 }
	{ adds	r36,0x0,r1; nop.m	0x0; adds	r37,0x0,r33; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,tt_setcbreak; }
	{ adds	r1,0x0,r36; cmp4.lt	p06,p07,r8,r0; mov.spnt	b0,r34,400000000012ACF0 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dpnt.few	400000000012AD30; }

l400000000012AD10:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	ttsetattr }

l400000000012AD30:
	{ addl	r8,-1,r0; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,400000000012AD40; br.ret	b0; }
400000000012AD50 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012AD60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012AD70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; ttcbreak: 400000000012AD80
ttcbreak proc
	{ alloc	r33,ar.pfs,0x6,0x0,0x3; adds	r12,0xFFFFFFFFFFFFFFC0,r12; mov	r32,b0 }
	{ addl	r14,8812,r1; addl	r36,21420,r1; adds	r34,0x0,r1; }
	{ ld4	r14,[r14]; adds	r35,0x10,r12; addl	r37,60,r0 }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; }
	{ (p06) addl	r8,-1,r0; nop.i	0x0; (p06) br.cond.dpnt.few	400000000012AE10; }

l400000000012ADC6:
	{ chk.a.nc	r0,3FFFFFFFFF12B5C6; nop; break.i	0x80000 }

l400000000012ADD0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ adds	r1,0x0,r34; nop.m	0x0; adds	r35,0x0,r0 }
	{ adds	r36,0x10,r12; nop.m	0x0; br.call.sptk.many	b0,ttfd_cbreak; }
	{ adds	r1,0x0,r34; nop.m	0x0; nop.i	0x0 }

l400000000012AE10:
	{ nop.m	0x0; mov.i	ar.pfs,r33; mov.spnt	b0,r32,400000000012AE10 }
	{ nop.m	0x0; adds	r12,0x40,r12; br.ret	b0; }
400000000012AE30 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; sh_regmatch: 400000000012AE40
sh_regmatch proc
	{ alloc	r45,ar.pfs,0x14,0x0,0xF; adds	r12,0xFFFFFFFFFFFFFFC0,r12; nop.b	0x0 }
	{ addl	r15,8772,r1; mov	r44,b4; adds	r46,0x0,r1; }
	{ adds	r14,0x10,r12; nop.m	0x0; addl	r49,3,r0; }
	{ st8	[r14],r8,8; st8	[r14],r8,8; nop.i	0x0 }
	{ ld4	r15,[r15]; st8	[r14],r8,8; cmp4.eq	p07,p06,0x0,r15; }
	{ st8	[r14],r8,8; st8	[r14],r8,8; nop.i	0x0; }
	{ st8	[r14],r8,8; st8	[r14],r8,8; nop.i	0x0; }
	{ st8	[r0],r14; nop.i	0x0; (p06) br.cond.dptk.few	400000000012AEF0 }

l400000000012AEC0:
	{ addl	r14,7036,r1; nop.m	0x0; nop.i	0x0; }
	{ ld4	r49,[r14]; cmp4.eq	p07,p06,0x0,r49; nop.i	0x0; }
	{ (p06) addl	r49,3,r0; nop.i	0x0; (p07) addl	r49,1,r0 }

l400000000012AEE6:
	{ addp4	r0,0xFFFFFFFFFFFFE000,r1; (p24) nop; (p48) nop }

l400000000012AEF0:
	{ addl	r35,2,r0; nop.m	0x0; adds	r47,0x10,r12 }
	{ adds	r48,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BE80; }
	{ adds	r1,0x0,r46; nop.m	0x0; cmp4.eq	p07,p06,0x0,r8 }
	{ adds	r8,0x0,r35; nop.m	0x0; (p07) br.cond.dpnt.few	400000000012AF50; }

l400000000012AF30:
	{ nop.m	0x0; mov.i	ar.pfs,r45; mov.spnt	b0,r44,400000000012AF30 }
	{ nop.m	0x0; adds	r12,0x40,r12; br.ret	b0; }

l400000000012AF50:
	{ adds	r40,0x40,r12; ld8	r35,[r40]; nop.i	0x0; }
	{ nop.m	0x0; adds	r35,0x1,r35; nop.i	0x0; }
	{ shladd	r47,r35,0x3,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B340; }
	{ adds	r49,0x0,r35; adds	r48,0x0,r32; adds	r50,0x0,r8 }
	{ adds	r51,0x0,r0; adds	r1,0x0,r46; adds	r39,0x0,r8; }
	{ adds	r47,0x10,r12; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B9A0; }
	{ cmp4.eq	p07,p06,0x0,r8; adds	r47,0x0,r32; adds	r1,0x0,r46; }
	{ (p06) addl	r8,1,r0; (p07) adds	r8,0x0,r0; nop.i	0x0; }

l400000000012AFC6:
	{ Invalid; nop; (p48) nop; }

l400000000012AFCC:
	{ ldfps	f0,f1,[r0]; zxt1	r0,r64; break.i	0x1000 }
	{ (p55) cmp.eq.unc	p32,p09,r59,r44; (p53) nop; br.cond.sptk.many	400000000054B08C }
	{ Invalid; break.x	0x80000165E0; }
	{ (p26) nop; nop; Invalid }
	{ (p18) cmp.eq	p01,p17,r7,r72; break.x	0x80C2F00A01000; }
	{ (p41) nop; cmp.eq.unc	p00,p16,r11,r64; (p05) nop }
	{ cmp.eq	p00,p17,r1,r0; Invalid; break.i	0x1000 }
	{ (p16) cmp.eq.unc	p57,p08,r60,r44; cmp.lt	p32,p28,r73,r65; (p01) brp.sptk	b2,400000000012B05C }
	{ nop; nop; (p05) cmp.eq	p00,p16,r2,r64; }
	{ Invalid; zxt4	r0,r0; cmp.eq	p00,p00,r32,r0; }

l400000000012B066:
	{ add	r0,r0,r1; (p07) nop; (p16) nop }
	{ nop; cmp4.ltu	p15,p33,r0,r0; (p01) nop }

l400000000012B080:
	{ (p07) adds	r16,0x0,r0; nop.m	0x0; nop.i	0x0; }

l400000000012B086:
	{ break.m	0x4000; nop; (p48) nop }
	{ break.m	0x4000; (p21) nop; nop }
	{ break.m	0x4000; (p19) nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFDEE9A6; nop; (p48) nop }

l400000000012B0C0:
	{ adds	r47,0x0,r37; nop.m	0x0; adds	r48,0x0,r0 }
	{ adds	r49,0x0,r42; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B8C0; }
	{ shladd	r14,r38,0x3,r39; adds	r1,0x0,r46; adds	r47,0x0,r37; }
	{ ld4	r15,[r14],4; ld4	r14,[r14]; sxt4	r48,r15; }
	{ sub	r49,r14,r15; nop.m	0x0; add	r48,r32,r48; }
	{ nop.m	0x0; sxt4	r49,r49; br.call.sptk.many	b0,fn400000000001B920; }
	{ adds	r1,0x0,r46; adds	r48,0x0,r36; adds	r47,0x0,r41 }
	{ adds	r49,0x0,r37; adds	r36,0x1,r36; br.call.sptk.many	b0,array_insert; }
	{ ld8	r14,[r40]; adds	r1,0x0,r46; adds	r38,0x0,r36; }
	{ nop.m	0x0; cmp.ltu	p07,p06,r14,r36; (p06) br.cond.dptk.few	400000000012B0C0 }

l400000000012B160:
	{ adds	r43,0x28,r43; nop.m	0x0; adds	r47,0x0,r37; }
	{ ld4	r14,[r43]; or	r14,0x2,r14; nop.i	0x0; }
	{ st4	[r14],r43; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r46; adds	r47,0x0,r39; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r46; adds	r47,0x10,r12; br.call.sptk.many	b0,fn400000000001B080; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r46; mov.i	ar.pfs,r45; }
	{ nop.m	0x0; mov.spnt	b0,r44,400000000012B1C0; nop.i	0x0 }
	{ adds	r12,0x40,r12; nop.m	0x0; br.ret	b0; }
400000000012B1E0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
400000000012B1F0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; sh_stat: 400000000012B200
;;   Called from:
;;     40000000000B566C (in fn40000000000B5640)
;;     40000000000B566C (in fn40000000000B5640)
;;     40000000000B569C (in fn40000000000B5690)
;;     40000000000B586C (in fn40000000000B5840)
;;     400000000012B5EC (in sh_eaccess)
sh_stat proc
	{ alloc	r39,ar.pfs,0xC,0x0,0x9; ld1	r34,[r32]; mov	r38,b6 }
	{ adds	r40,0x0,r1; adds	r14,0x1,r32; sxt1	r34,r34; }
	{ cmp4.eq	p07,p06,0x0,r34; nop.i	0x0; (p07) br.cond.dpnt.few	400000000012B3D0; }

l400000000012B230:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2F,r34; (p07) br.cond.dpnt.few	400000000012B280 }

l400000000012B240:
	{ addl	r41,1,r0; nop.m	0x0; adds	r42,0x0,r32 }
	{ adds	r43,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AFE0; }
	{ adds	r14,0x0,r8; adds	r1,0x0,r40; mov.i	ar.pfs,r39; }
	{ adds	r8,0x0,r14; mov.spnt	b0,r38,400000000012B270; br.ret	b0 }

l400000000012B280:
	{ ld1	r35,[r14]; nop.m	0x0; sxt1	r35,r35; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x64,r35; (p06) br.cond.dptk.few	400000000012B240 }

l400000000012B2A0:
	{ addl	r42,-8492,r1; addl	r43,8,r0; adds	r41,0x0,r32; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C020; }
	{ adds	r1,0x0,r40; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	400000000012B240; }

l400000000012B2D0:
	{ adds	r32,0x8,r32; nop.m	0x0; addl	r37,8820,r1; }
	{ adds	r41,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r40; ld8	r41,[r37]; adds	r42,0x9,r8 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,xrealloc; }
	{ adds	r14,0x0,r8; st8	[r8],r37; addl	r15,101,r0 }
	{ adds	r1,0x0,r40; adds	r36,0x0,r8; adds	r42,0x0,r32; }
	{ st1	[r14],r1,1; nop.m	0x0; adds	r41,0x8,r8; }
	{ st1	[r14],r1,1; st1	[r14],r1,1; addl	r15,118,r0; }
	{ st1	[r14],r1,1; nop.m	0x0; addl	r15,102,r0; }
	{ st1	[r14],r1,1; st1	[r14],r1,1; nop.i	0x0; }
	{ nop.m	0x0; st1	[r14],r1,1; nop.i	0x0; }
	{ st1	[r34],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r40; addl	r41,1,r0; nop.i	0x0 }
	{ adds	r42,0x0,r36; adds	r43,0x0,r33; br.call.sptk.many	b0,fn400000000001AFE0; }
	{ adds	r14,0x0,r8; adds	r1,0x0,r40; mov.i	ar.pfs,r39; }
	{ adds	r8,0x0,r14; mov.spnt	b0,r38,400000000012B3C0; br.ret	b0; }

l400000000012B3D0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ addl	r14,-1,r0; addl	r15,2,r0; nop.b	0x0 }
	{ adds	r1,0x0,r40; nop.m	0x0; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; st4	[r15],r8; mov.spnt	b0,r38,400000000012B400 }
	{ nop.m	0x0; adds	r8,0x0,r14; br.ret	b0; }
400000000012B420 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012B430 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; sh_eaccess: 400000000012B440
;;   Called from:
;;     4000000000040A2C (in file_iswdir)
sh_eaccess proc
	{ alloc	r36,ar.pfs,0xA,0x0,0x6; adds	r12,0xFFFFFFFFFFFFFF70,r12; nop.b	0x0 }
	{ ld1	r14,[r32]; mov	r35,b3; adds	r37,0x0,r1; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2F,r14; (p07) br.cond.dpnt.few	400000000012B4D0 }

l400000000012B480:
	{ addl	r38,-100,r0; adds	r39,0x0,r32; nop.i	0x0 }
	{ adds	r40,0x0,r33; addl	r41,512,r0; br.call.sptk.many	b0,fn400000000001A920; }
	{ nop.m	0x0; adds	r1,0x0,r37; adds	r14,0x0,r8; }

l400000000012B4B0:
	{ adds	r8,0x0,r14; mov.i	ar.pfs,r36; mov.spnt	b0,r35,400000000012B4B0 }
	{ nop.m	0x0; adds	r12,0x90,r12; br.ret	b0 }

l400000000012B4D0:
	{ adds	r14,0x1,r32; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x64,r14; (p07) br.cond.dpnt.few	400000000012B710 }

l400000000012B500:
	{ addl	r39,-8484,r1; adds	r38,0x0,r32; addl	r40,8,r0; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C020; }
	{ adds	r14,0x8,r32; nop.m	0x0; adds	r1,0x0,r37 }
	{ cmp4.eq	p07,p06,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	400000000012B480; }

l400000000012B540:
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x69,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000012B750; }

l400000000012B560:
	{ cmp4.eq	p07,p06,0x6F,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000012B7C0; }

l400000000012B570:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x65,r14; (p06) br.cond.dptk.few	400000000012B480 }

l400000000012B580:
	{ adds	r14,0x9,r32; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x72,r14; (p06) br.cond.dptk.few	400000000012B480 }

l400000000012B5A0:
	{ adds	r14,0xA,r32; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x72,r14; (p07) br.cond.dptk.few	400000000012B480 }

l400000000012B5C0:
	{ adds	r14,0xB,r32; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; (p07) br.cond.spnt.few	400000000012B480; }

l400000000012B5E0:
	{ adds	r38,0x0,r32; adds	r39,0x10,r12; br.call.sptk.many	b0,sh_stat; }
	{ adds	r1,0x0,r37; cmp4.lt	p06,p07,r8,r0; (p06) br.cond.dpnt.few	400000000012B880; }

l400000000012B600:
	{ addl	r14,-22276,r1; nop.m	0x0; nop.i	0x0; }
	{ adds	r14,0x4,r14; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; }
	{ nop.m	0x0; (p06) adds	r34,0x28,r12; (p06) br.cond.dptk.few	400000000012B670; }

l400000000012B63C:
	{ (p02) cmpxchg4.acq	r0,[r33],r0; (p04) cmp.eq	p10,p16,r3,r64; mov	pr,r72,0x5040 }

l400000000012B640:
	{ adds	r34,0x28,r12; tbit.z	p07,p06,r33,0x0; (p07) br.cond.dpnt.few	400000000012B6E0; }

l400000000012B650:
	{ ld4	r15,[r34]; and	r15,0x49,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p06) br.cond.dpnt.few	400000000012B6E0 }

l400000000012B670:
	{ nop.m	0x0; adds	r15,0x2C,r12; nop.i	0x0; }
	{ ld4	r15,[r15]; cmp4.eq	p07,p06,r15,r14; adds	r14,0x30,r12; }
	{ nop.m	0x0; (p07) dep.z	r33,0x21,6,26; (p07) br.cond.dpnt.few	400000000012B6C0; }

l400000000012B69C:
	{ (p01) cmp.lt	p00,p17,r64,r33; Invalid; break.b	0x1000 }

l400000000012B6A0:
	{ ld4	r38,[r14]; nop.i	0x0; br.call.sptk.many	b0,group_member; }
	{ cmp4.eq	p06,p07,0x0,r8; adds	r1,0x0,r37; (p07) shladd	r33,r33,0x3,r0 }

l400000000012B6C0:
	{ ld4	r14,[r34]; and	r33,r14,r33; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r33; (p07) br.cond.dpnt.few	400000000012B830 }

l400000000012B6E0:
	{ nop.m	0x0; adds	r14,0x0,r0; nop.i	0x0; }
	{ adds	r8,0x0,r14; mov.i	ar.pfs,r36; mov.spnt	b0,r35,400000000012B6F0 }
	{ nop.m	0x0; adds	r12,0x90,r12; br.ret	b0 }

l400000000012B710:
	{ addl	r39,-8492,r1; adds	r38,0x0,r32; addl	r40,8,r0; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C020; }
	{ adds	r1,0x0,r37; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	400000000012B500 }

l400000000012B740:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000012B5E0 }

l400000000012B750:
	{ adds	r14,0x9,r32; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x6E,r14; (p06) br.cond.dptk.few	400000000012B480 }

l400000000012B770:
	{ adds	r14,0xA,r32; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000012B5E0 }

l400000000012B790:
	{ addl	r38,-100,r0; adds	r39,0x0,r32; nop.i	0x0 }
	{ adds	r40,0x0,r33; addl	r41,512,r0; br.call.sptk.many	b0,fn400000000001A920; }
	{ adds	r1,0x0,r37; adds	r14,0x0,r8; br.cond.sptk.few	400000000012B4B0; }

l400000000012B7C0:
	{ adds	r14,0x9,r32; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x75,r14; (p06) br.cond.dptk.few	400000000012B480 }

l400000000012B7E0:
	{ adds	r14,0xA,r32; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x74,r14; (p06) br.cond.dptk.few	400000000012B480 }

l400000000012B800:
	{ adds	r14,0xB,r32; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.sptk.few	400000000012B5E0 }

l400000000012B820:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000012B480 }

l400000000012B830:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ addl	r14,-1,r0; addl	r15,13,r0; adds	r1,0x0,r37; }
	{ st4	[r15],r8; adds	r8,0x0,r14; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,400000000012B860; nop.i	0x0 }
	{ adds	r12,0x90,r12; nop.m	0x0; br.ret	b0 }

l400000000012B880:
	{ nop.m	0x0; addl	r14,-1,r0; nop.i	0x0; }
	{ adds	r8,0x0,r14; mov.i	ar.pfs,r36; mov.spnt	b0,r35,400000000012B890 }
	{ nop.m	0x0; adds	r12,0x90,r12; br.ret	b0; }
400000000012B8B0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; isnetconn: 400000000012B8C0
isnetconn proc
	{ alloc	r34,ar.pfs,0x7,0x0,0x4; adds	r12,0xFFFFFFFFFFFFFFE0,r12; nop.b	0x0 }
	{ adds	r35,0x0,r1; mov	r33,b1; adds	r36,0x0,r32; }
	{ adds	r14,0x20,r12; addl	r15,16,r0; adds	r37,0x10,r12; }
	{ nop.m	0x0; adds	r38,0x0,r14; nop.i	0x0 }
	{ st4	[r15],r14; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BF00; }
	{ nop.m	0x0; addl	r14,1,r0; adds	r1,0x0,r35 }
	{ nop.m	0x0; cmp4.lt	p07,p06,r8,r0; (p07) br.cond.dpnt.few	400000000012B950; }

l400000000012B930:
	{ adds	r8,0x0,r14; mov.i	ar.pfs,r34; mov.spnt	b0,r33,400000000012B930 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0; }

l400000000012B950:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ ld4	r15,[r8]; adds	r1,0x0,r35; adds	r14,0x0,r0; }
	{ cmp4.eq	p07,p06,0x58,r15; nop.m	0x0; cmp4.eq	p08,p09,0x16,r15; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x6B,r15; (p07) br.cond.dptk.few	400000000012B930 }

l400000000012B990:
	{ nop.m	0x0; (p09) addl	r14,1,r0; nop.i	0x0; }

l400000000012B99C:
	{ Invalid; zxt1	r64,r64; (p32) break.i	0x2A808 }
	{ (p16) nop; add	r0,r32,r0; Invalid }
	{ cmp.eq	p00,p24,r33,r0; Invalid; zxt2	r16,r79 }

;; netopen: 400000000012B9C0
netopen proc
	{ alloc	r39,ar.pfs,0xD,0x0,0x9; adds	r12,0xFFFFFFFFFFFFFFC0,r12; nop.b	0x0 }
	{ adds	r40,0x0,r1; mov	r38,b6; adds	r41,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r41,0x1,r8 }
	{ adds	r37,0x40,r12; nop.m	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r36,0x0,r8; adds	r1,0x0,r40; nop.i	0x0 }
	{ adds	r41,0x0,r8; adds	r42,0x0,r32; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r35,0x9,r36; adds	r1,0x0,r40; addl	r42,47,r0; }
	{ adds	r41,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B680; }
	{ adds	r15,0x10,r12; adds	r33,0x0,r8; adds	r1,0x0,r40 }
	{ cmp.eq	p07,p06,0x0,r8; adds	r16,0x5,r32; (p07) br.cond.spnt.few	400000000012BED0; }

l400000000012BA70:
	{ adds	r43,0x0,r15; st1	[r33],r1,1; nop.i	0x0 }
	{ st8	[r15],r8,8; adds	r44,0x0,r37; adds	r41,0x0,r35; }
	{ adds	r14,0x0,r15; ld1	r16,[r16]; adds	r42,0x0,r33; }
	{ st8	[r14],r8,8; nop.m	0x0; sxt1	r16,r16; }
	{ st8	[r14],r8,8; nop.m	0x0; cmp4.eq	p07,p06,0x74,r16; }
	{ st8	[r14],r8,8; (p06) addl	r16,2,r0; (p07) addl	r16,1,r0 }

l400000000012BACC:
	{ loadrs; (p01) nop; rfi }

l400000000012BAD0:
	{ st8	[r14],r8,8; st4	[r16],r15; nop.i	0x0 }
	{ st8	[r0],r14; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BF60; }
	{ adds	r1,0x0,r40; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dpnt.few	400000000012BDB0; }

l400000000012BB00:
	{ nop.m	0x0; ld8	r33,[r37]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r33; (p06) br.cond.dpnt.few	400000000012BC10; }

l400000000012BB20:
	{ adds	r16,0x4,r33; nop.m	0x0; adds	r15,0x8,r33 }
	{ adds	r14,0xC,r33; nop.m	0x0; adds	r35,0x28,r33; }
	{ ld4	r41,[r16]; ld4	r42,[r15]; nop.i	0x0; }
	{ ld4	r43,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BFE0; }
	{ adds	r14,0x18,r33; cmp4.lt	p07,p06,r8,r0; adds	r33,0x10,r33 }
	{ adds	r34,0x0,r8; adds	r1,0x0,r40; (p07) br.cond.dpnt.few	400000000012BC50; }

l400000000012BB80:
	{ adds	r41,0x0,r8; ld8	r42,[r14]; nop.i	0x0 }
	{ ld4	r43,[r33]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C280; }
	{ adds	r1,0x0,r40; nop.m	0x0; cmp4.lt	p07,p06,r8,r0 }
	{ adds	r41,0x0,r34; nop.m	0x0; (p06) br.cond.dpnt.few	400000000012BCD0; }

l400000000012BBC0:
	{ nop.m	0x0; ld8	r14,[r35]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.spnt.few	400000000012BD00; }

l400000000012BBE0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C340; }
	{ ld8	r33,[r35]; nop.m	0x0; adds	r1,0x0,r40; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	400000000012BB20 }

l400000000012BC10:
	{ nop.m	0x0; adds	r41,0x0,r36; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r40; nop.m	0x0; nop.i	0x0 }

l400000000012BC30:
	{ adds	r8,0x0,r34; mov.i	ar.pfs,r39; mov.spnt	b0,r38,400000000012BC30 }
	{ nop.m	0x0; adds	r12,0x40,r12; br.ret	b0 }

l400000000012BC50:
	{ nop.m	0x0; ld8	r33,[r35]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.sptk.few	400000000012BB20 }

l400000000012BC70:
	{ addl	r41,-8460,r1; nop.m	0x0; addl	r34,-1,r0; }
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,sys_error; }
	{ nop.m	0x0; adds	r1,0x0,r40; nop.i	0x0 }
	{ ld8	r41,[r37]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BF80; }
	{ adds	r1,0x0,r40; adds	r41,0x0,r36; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r40; br.cond.sptk.few	400000000012BC30 }

l400000000012BCD0:
	{ ld8	r41,[r37]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BF80; }
	{ adds	r1,0x0,r40; adds	r41,0x0,r36; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r40; br.cond.sptk.few	400000000012BC30 }

l400000000012BD00:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ nop.m	0x0; adds	r1,0x0,r40; adds	r33,0x0,r8 }
	{ ld4	r35,[r8]; addl	r41,-8452,r1; nop.i	0x0; }
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,sys_error; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r41,0x0,r34 }
	{ addl	r34,-1,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C340; }
	{ nop.m	0x0; adds	r1,0x0,r40; nop.i	0x0 }
	{ ld8	r41,[r37]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BF80; }
	{ adds	r1,0x0,r40; st4	[r35],r33; adds	r41,0x0,r36 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r40; br.cond.sptk.few	400000000012BC30 }

l400000000012BDB0:
	{ cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFF8,r8; nop.m	0x0; adds	r41,0x0,r8 }
	{ addl	r34,-1,r0; nop.m	0x0; (p07) br.cond.dpnt.few	400000000012BE60; }

l400000000012BDD0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A740; }
	{ adds	r1,0x0,r40; adds	r42,0x0,r35; adds	r43,0x0,r8; }
	{ nop.m	0x0; addl	r41,-8468,r1; nop.i	0x0; }
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,internal_error; }
	{ adds	r1,0x0,r40; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ addl	r14,22,r0; nop.m	0x0; adds	r1,0x0,r40; }
	{ st4	[r14],r8; nop.m	0x0; nop.i	0x0 }

l400000000012BE40:
	{ adds	r41,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r40; br.cond.sptk.few	400000000012BC30 }

l400000000012BE60:
	{ addl	r41,-8,r0; addl	r34,-1,r0; br.call.sptk.many	b0,fn400000000001A740; }
	{ adds	r1,0x0,r40; adds	r42,0x0,r33; adds	r43,0x0,r8; }
	{ nop.m	0x0; addl	r41,-8468,r1; nop.i	0x0; }
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,internal_error; }
	{ adds	r1,0x0,r40; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ addl	r14,22,r0; nop.m	0x0; adds	r1,0x0,r40; }
	{ st4	[r14],r8; nop.i	0x0; br.cond.sptk.few	400000000012BE40 }

l400000000012BED0:
	{ addl	r42,-8476,r1; nop.m	0x0; addl	r43,5,r0 }
	{ adds	r41,0x0,r0; nop.m	0x0; addl	r34,-1,r0; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r41,0x0,r8 }
	{ adds	r42,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,internal_error; }
	{ adds	r8,0x0,r34; adds	r1,0x0,r40; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,400000000012BF30; nop.i	0x0 }
	{ adds	r12,0x40,r12; nop.m	0x0; br.ret	b0; }
400000000012BF50 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
400000000012BF60 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
400000000012BF70 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; difftimeval: 400000000012BF80
difftimeval proc
	{ ld8	r17,[r34],8; adds	r14,0x0,r32; adds	r8,0x0,r32 }
	{ ld8	r15,[r33],8; ld8	r2,[r34]; sub	r15,r17,r15 }
	{ ld8	r16,[r33]; st8	[r14],r8,8; sub	r2,r2,r16; }
	{ st8	[r2],r14; cmp.lt	p06,p07,r2,r0; (p07) br.ret	b0 }

l400000000012BFC0:
	{ adds	r15,0xFFFFFFFFFFFFFFFF,r15; nop.m	0x0; addl	r2,1000000,r2; }
	{ cmp.lt	p07,p06,r15,r0; st8	[r2],r14; nop.i	0x0 }
	{ st8	[r15],r32; nop.i	0x0; nop.i	0x0 }
	{ (p07) st8	[r0],r14; (p07) st8	[r0],r32; br.ret	b0; }

l400000000012BFF6:
	{ mf.a; (p34) nop; nop; }

l400000000012BFFC:
	{ nop; (p02) nop; zxt1	r2,r64 }

;; addtimeval: 400000000012C000
addtimeval proc
	{ ld8	r16,[r33],8; adds	r17,0x8,r32; adds	r8,0x0,r32 }
	{ ld8	r14,[r34],8; ld8	r15,[r34]; add	r14,r16,r14 }
	{ ld8	r2,[r33]; nop.i	0x0; add	r2,r2,r15 }
	{ adds	r16,0x1,r14; st8	[r14],r32; addl	r14,999999,r0; }
	{ cmp.lt	p06,p07,r14,r2; addl	r15,-1000000,r2; (p07) adds	r14,0x0,r17 }

l400000000012C050:
	{ (p06) st8	[r15],r17; (p06) st8	[r16],r32; nop.i	0x0; }

l400000000012C056:
	{ mf.a; cmp4.eq	p00,p00,r0,r1; (p01) nop; }

l400000000012C05C:
	{ Invalid; Invalid; add	r0,r32,r0 }

l400000000012C066:
	{ break.m	0x4000; (p34) nop; break.i	0x80000 }
400000000012C070 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; timeval_to_cpu: 400000000012C080
timeval_to_cpu proc
	{ alloc	r36,ar.pfs,0x9,0x0,0x7; ld8	r15,[r34],8; mov	r38,LC }
	{ adds	r37,0x0,r1; ld8	r39,[r33],8; nop.i	0x0; }
	{ ld8	r16,[r34]; add	r39,r39,r15; addl	r15,999999,r0 }
	{ ld8	r2,[r33]; movl	r14,0x1BDE82D7B634DB; }
	{ add	r2,r2,r16; setf.sig	f7,r14; mov	r35,b3 }
	{ ld8	r40,[r32],8; movl	r17,0x316B11C6D1E109; }
	{ cmp.lt	p07,p06,r15,r2; ld8	r16,[r32]; nop.i	0x0 }
	{ setf.sig	f6,r17; movl	r18,0x5F5E0FF; }
	{ (p07) addl	r2,-1000000,r2; shladd	r21,r16,0x2,r16; mov.i	LC,0x4 }

l400000000012C106:
	{ Invalid; cmp4.ltu	p04,p00,r65,r10; (p49) nop.b	0x27029 }

l400000000012C116:
	{ Invalid; (p11) nop; (p48) nop }
	{ Invalid; (p10) nop; nop }
	{ (p11) chk.a.clr	r39,3FFFFFFFFF134BA6; nop; (p48) nop }

l400000000012C140:
	{ shladd	r19,r19,0x1,r0; cmp.lt	p06,p07,r18,r40; extr.u	r25,r21,63,1 }
	{ nop.m	0x0; extr.u	r2,r2,63,1; (p06) br.cond.dpnt.few	400000000012C410; }

l400000000012C160:
	{ setf.sig	f11,r19; nop.m	0x0; extr.u	r24,r19,63,1; }
	{ nop.m	0x0; nop.m	0x0; xma.h	f8,f9,f6,f0; }
	{ nop.m	0x0; nop.m	0x0; xma.h	f10,f11,f7,f0 }
	{ setf.sig	f11,r16; nop.m	0x0; extr.u	r16,r16,63,1; }
	{ getf.sig	r18,f8; getf.sig	r17,f10; nop.i	0x0; }
	{ nop.m	0x0; xma.h	f9,f11,f6,f0; nop.i	0x0 }
	{ setf.sig	f11,r21; nop.m	0x0; extr	r39,r18,14,50; }
	{ nop.m	0x0; sub	r2,r39,r2; nop.i	0x0; }
	{ getf.sig	r18,f9; extr.u	r15,r17,18,46; shladd	r39,r23,0x1,r2; }
	{ nop.m	0x0; xma.h	f11,f11,f7,f0; sub	r15,r15,r24; }
	{ getf.sig	r14,f11; extr	r17,r18,14,50; dep.z	r18,0xF,5,59; }
	{ sub	r16,r17,r16; nop.m	0x0; sub	r18,r18,r15; }
	{ shladd	r40,r22,0x1,r16; dep.z	r17,r18,6,58; sub	r18,r17,r18; }
	{ nop.m	0x0; shladd	r15,r18,0x3,r15; nop.i	0x0; }
	{ nop.m	0x0; extr.u	r14,r14,18,46; dep.z	r15,0xF,6,58; }
	{ sub	r14,r14,r25; sub	r15,r19,r15; dep.z	r16,r14,5,59; }
	{ sub	r16,r16,r14; nop.m	0x0; dep.z	r17,r16,6,58; }
	{ sub	r16,r17,r16; shladd	r14,r16,0x3,r14; nop.i	0x0; }
	{ nop.m	0x0; dep.z	r14,r14,6,58; sub	r14,r21,r14; }

l400000000012C290:
	{ setf.sig	f8,r15; setf.sig	f10,r14; shladd	r17,r15,0x2,r15 }
	{ shladd	r16,r14,0x2,r14; cmp.lt	p07,p06,r20,r39; extr.u	r22,r14,63,1; }
	{ shladd	r17,r17,0x1,r0; shladd	r16,r16,0x1,r0; extr.u	r23,r15,63,1 }
	{ shladd	r21,r40,0x2,r40; shladd	r24,r39,0x2,r39; (p07) br.cond.dpnt.few	400000000012C410; }

l400000000012C2D0:
	{ setf.sig	f12,r16; extr.u	r18,r16,63,1; extr.u	r19,r17,63,1 }
	{ cmp.lt	p06,p07,r20,r40; nop.m	0x0; (p06) br.cond.dpnt.few	400000000012C410; }

l400000000012C2F0:
	{ nop.m	0x0; xma.h	f9,f8,f6,f0; nop.i	0x0 }
	{ nop.m	0x0; xma.h	f8,f10,f6,f0; nop.i	0x0; }
	{ nop.m	0x0; setf.sig	f10,r17; nop.i	0x0; }
	{ nop.m	0x0; xma.h	f11,f10,f7,f0; nop.i	0x0 }
	{ nop.m	0x0; xma.h	f10,f12,f7,f0; nop.i	0x0; }
	{ getf.sig	r14,f11; getf.sig	r25,f10; nop.i	0x0; }
	{ nop.m	0x0; extr.u	r15,r14,18,46; extr.u	r14,r25,18,46 }
	{ getf.sig	r25,f8; nop.m	0x0; sub	r15,r15,r19; }
	{ sub	r14,r14,r18; getf.sig	r18,f9; dep.z	r19,0xF,5,59; }
	{ sub	r19,r19,r15; nop.m	0x0; extr	r40,r25,14,50; }
	{ nop.m	0x0; extr	r39,r18,14,50; dep.z	r18,r14,5,59 }
	{ nop.m	0x0; sub	r40,r40,r22; nop.b	0x0; }
	{ sub	r18,r18,r14; shladd	r40,r21,0x1,r40; dep.z	r22,0x13,6,58 }
	{ sub	r39,r39,r23; nop.m	0x0; dep.z	r21,r18,6,58 }
	{ sub	r19,r22,r19; shladd	r39,r24,0x1,r39; sub	r18,r21,r18 }
	{ shladd	r15,r19,0x3,r15; shladd	r14,r18,0x3,r14; dep.z	r15,0xF,6,58; }
	{ nop.m	0x0; dep.z	r14,r14,6,58; sub	r15,r17,r15; }
	{ nop.m	0x0; sub	r14,r16,r14; br.cloop.sptk.few	400000000012C290; }

l400000000012C410:
	{ nop.m	0x0; movl	r14,0x26666666666667 }
	{ nop.m	0x0; movl	r16,0x5F5E0FF; }
	{ nop.m	0x0; setf.sig	f7,r14; mov.i	LC,0x3 }

l400000000012C440:
	{ setf.sig	f8,r40; nop.m	0x0; cmp.lt	p06,p07,r16,r39 }
	{ shladd	r15,r39,0x2,r39; extr.u	r14,r40,63,1; (p07) shladd	r39,r15,0x1,r0; }

l400000000012C460:
	{ nop.m	0x0; nop.m	0x0; xma.h	f6,f8,f7,f0; }
	{ (p06) getf.sig	r15,f6; nop.m	0x0; (p06) extr	r40,r15,2,62; }

l400000000012C476:
	{ chk.a.nc	r0,3FFFFFFFFF12CC76; (p20) nop; add	r0,r0,r32 }
