;;; Segment .text (400000000001C480)

l400000000008C490:
	{ cmp4.eq	p08,p09,0x27,r39; cmp4.eq	p06,p07,0x22,r39; (p08) addl	r15,1,r0; }

l400000000008C4A0:
	{ nop.m	0x0; (p09) adds	r15,0x0,r0; nop.i	0x0; }

l400000000008C4AC:
	{ Invalid; cmp.lt	p00,p00,r32,r0; (p08) mov	pr,r99,0xE5C0 }
	{ (p07) cmp.lt	p00,p09,r0,r33; cmp.lt.unc	p32,p28,r99,r97; Invalid }

l400000000008C4C0:
	{ cmp4.eq	p06,p07,0x0,r15; adds	r54,0x0,r32; adds	r55,0x0,r45; }
	{ (p07) adds	r33,0x1,r33; nop.m	0x0; (p07) adds	r14,0x18,r12; }

l400000000008C4D6:
	{ chk.a.nc	f0,3FFFFFFFFF08CCD6; (p07) cmp.eq.or	p24,p02,r12,r0; (p01) nop }

l400000000008C4E0:
	{ (p07) st8	[r0],r14; nop.m	0x0; adds	r56,0x1,r33 }

l400000000008C4E6:
	{ break.m	0x4000; (p28) nop; cmp.gt	p00,p00,r0,r0 }
	{ Invalid; (p32) nop; break.i	0x80000; }

l400000000008C4FC:
	{ (p06) nop; nop; brp.sptk	b5,400000000008C4FC }
	{ invala; break.x	0x8000016100 }
	{ (p40) nop; cmp.lt	p00,p00,r32,r0; nop }

l400000000008C520:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r14,0x0,r8; (p07) br.cond.spnt.few	400000000008C410; }

l400000000008C53C:
	{ (p55) nop; zxt1	r32,r64; add	r0,r32,r0 }

l400000000008C540:
	{ adds	r33,0x1,r33; nop.m	0x0; adds	r44,0x0,r0; }
	{ nop.m	0x0; sxt4	r37,r33; br.cond.sptk.few	400000000008C220 }

l400000000008C560:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r14,0x0,r8; (p07) br.cond.spnt.few	400000000008C370; }

l400000000008C57C:
	{ (p48) nop; nop; zxt1	r32,r64 }

l400000000008C580:
	{ nop.m	0x0; adds	r33,0x1,r33; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r37,r33; br.cond.sptk.few	400000000008C220 }

l400000000008C5A0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x24,r39; (p07) br.cond.dpnt.few	400000000008C990 }

l400000000008C5B0:
	{ nop.m	0x0; nop.i	0x0; (p18) br.cond.dptk.few	400000000008CA70 }

l400000000008C5C0:
	{ nop.m	0x0; sxt1	r15,r36; and	r15,0xFFFFFFFFFFFFFFFD,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x3C,r15; (p06) br.cond.dptk.few	400000000008CA70 }

l400000000008C5E0:
	{ adds	r15,0x1,r38; ld1	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x28,r15; (p06) br.cond.dptk.few	400000000008CA70 }

l400000000008C610:
	{ adds	r33,0x2,r33; adds	r15,0x40,r12; adds	r54,0x0,r32 }
	{ adds	r56,0x40,r12; nop.m	0x0; sxt4	r14,r33 }
	{ st4	[r33],r15; add	r14,r32,r14; nop.i	0x0; }
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000008C700; }

l400000000008C660:
	{ cmp4.eq	p07,p06,0x3C,r39; (p07) addl	r55,-6764,r1; nop.i	0x0; }

l400000000008C66C:
	{ cmp4.eq.or.andcm	p00,p11,r1,r0; (p06) cmp4.eq.or.andcm	p39,p51,r127,r114; Invalid }

l400000000008C676:
	{ (p27) fwb; nop; (p49) br.call.sptk.few	b5,b0; }

l400000000008C67C:
	{ cmp4.eq.or.andcm	p00,p19,r1,r0; Invalid; Invalid }

l400000000008C686:
	{ (p32) flushrs; nop; (p16) nop }
	{ break.m	0x4000; nop; break.i	0x80000 }

l400000000008C6A0:
	{ nop.m	0x0; adds	r14,0x40,r12; nop.i	0x0; }
	{ ld4	r33,[r14]; nop.m	0x0; nop.i	0x0; }

l400000000008C6C0:
	{ nop.m	0x0; sxt4	r14,r33; add	r14,r32,r14; }
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	400000000008C580; }

l400000000008C6F0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000008C700:
	{ adds	r8,0x0,r33; st4	[r0],r43; mov	pr,r53,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r51; mov.spnt	b0,r50,400000000008C710 }
	{ nop.m	0x0; adds	r12,0x40,r12; br.ret	b0; }

l400000000008C730:
	{ adds	r15,0x18,r12; nop.m	0x0; adds	r54,0x0,r0 }
	{ adds	r55,0x0,r38; nop.m	0x0; sub	r56,r45,r37; }
	{ ld8	r14,[r15]; adds	r57,0x0,r15; adds	r15,0x10,r12; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r15,0x10,r12; adds	r1,0x0,r52; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000008CD70; }

l400000000008C790:
	{ nop.m	0x0; ld8	r14,[r15]; adds	r15,0x18,r12 }
	{ adds	r33,0x1,r33; st8	[r14],r15; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000008C7C0:
	{ nop.m	0x0; sxt4	r37,r33; add	r38,r32,r37; }
	{ nop.m	0x0; ld1	r15,[r38]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; cmp4.eq	p07,p06,0x0,r15; }
	{ cmp4.eq.or.andcm	p07,p06,0x27,r15; nop.i	0x0; (p07) br.cond.dpnt.few	400000000008CD40; }

l400000000008C800:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r52; nop.m	0x0; cmp.ltu	p07,p06,0x1,r8 }
	{ addl	r17,1,r0; nop.m	0x0; (p06) br.cond.dpnt.few	400000000008CD30; }

l400000000008C830:
	{ ld1	r15,[r38]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; extr.u	r16,r15,5,3; and	r14,0x1F,r15; }
	{ shladd	r15,r16,0x2,r42; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r15,r15,r14; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r15,0x0; (p07) br.cond.dpnt.few	400000000008C730; }

l400000000008C880:
	{ nop.m	0x0; add	r33,r17,r33; br.cond.sptk.few	400000000008C7C0 }

l400000000008C890:
	{ adds	r15,0x30,r12; ld8	r14,[r40]; sub	r56,r45,r37 }
	{ adds	r54,0x0,r0; adds	r55,0x0,r38; adds	r57,0x0,r40; }
	{ st8	[r14],r15; adds	r44,0x0,r0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; nop.m	0x0; adds	r1,0x0,r52; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000008C520; }

l400000000008C8E0:
	{ adds	r15,0x30,r12; nop.m	0x0; adds	r33,0x1,r33; }
	{ ld8	r14,[r15]; nop.m	0x0; sxt4	r37,r33; }
	{ st8	[r14],r40; nop.i	0x0; br.cond.sptk.few	400000000008C220 }

l400000000008C910:
	{ adds	r15,0x28,r12; ld8	r14,[r40]; sub	r56,r45,r37 }
	{ adds	r54,0x0,r0; adds	r55,0x0,r38; adds	r57,0x0,r40; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; nop.m	0x0; adds	r1,0x0,r52; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000008C560; }

l400000000008C960:
	{ adds	r15,0x28,r12; nop.m	0x0; adds	r33,0x1,r33; }
	{ ld8	r14,[r15]; nop.m	0x0; sxt4	r37,r33; }
	{ st8	[r14],r40; nop.i	0x0; br.cond.sptk.few	400000000008C220 }

l400000000008C990:
	{ adds	r15,0x1,r38; ld1	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; (p21) br.cond.dptk.few	400000000008C9C0; }

l400000000008C9B0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x28,r15; (p06) br.cond.dpnt.few	400000000008C9D0; }

l400000000008C9C0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x7B,r15; (p06) br.cond.dptk.few	400000000008C5B0 }

l400000000008C9D0:
	{ adds	r33,0x2,r33; adds	r15,0x40,r12; adds	r38,0x1,r38 }
	{ adds	r54,0x0,r32; adds	r55,0x40,r12; adds	r56,0x0,r0; }
	{ nop.m	0x0; sxt4	r14,r33; nop.i	0x0 }
	{ st4	[r33],r15; addl	r57,1,r0; add	r14,r32,r14; }
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000008C700; }

l400000000008CA30:
	{ ld1	r14,[r38]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x28,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000008CDA0; }

l400000000008CA50:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000089000; }
	{ nop.m	0x0; adds	r1,0x0,r52; br.cond.sptk.few	400000000008C6A0 }

l400000000008CA70:
	{ nop.m	0x0; nop.i	0x0; (p22) br.cond.dptk.few	400000000008CC00 }

l400000000008CA80:
	{ nop.m	0x0; ld4	r15,[r47]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	400000000008CC00 }

l400000000008CAA0:
	{ adds	r15,0x1,r38; ld1	r48,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r48,r48; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x28,r48; (p06) br.cond.dptk.few	400000000008CC00 }

l400000000008CAD0:
	{ addl	r54,-6748,r1; nop.m	0x0; adds	r55,0x0,r39; }
	{ ld8	r54,[r54]; nop.i	0x0; br.call.sptk.many	b0,mbschr; }
	{ adds	r1,0x0,r52; cmp.eq	p06,p07,0x0,r8; adds	r15,0x40,r12 }
	{ adds	r54,0x0,r32; adds	r55,0x40,r12; (p06) br.cond.dpnt.few	400000000008CC00; }

l400000000008CB10:
	{ adds	r33,0x2,r33; nop.m	0x0; addl	r57,-6836,r1 }
	{ addl	r58,-6828,r1; addl	r59,1,r0; sxt4	r14,r33 }
	{ st4	[r33],r15; adds	r15,0x45,r12; add	r14,r32,r14; }
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x0,r14; adds	r14,0x44,r12; (p07) br.cond.dpnt.few	400000000008C700; }

l400000000008CB60:
	{ adds	r56,0x0,r14; st1	[r36],r14; adds	r14,0x46,r12 }
	{ st1	[r48],r15; ld8	r57,[r57]; nop.i	0x0; }
	{ nop.m	0x0; st1	[r0],r14; nop.i	0x0 }
	{ ld8	r58,[r58]; nop.m	0x0; br.call.sptk.many	b0,fn400000000008A3C0; }
	{ adds	r15,0x40,r12; nop.m	0x0; adds	r1,0x0,r52; }
	{ ld4	r33,[r15]; nop.m	0x0; sxt4	r14,r33; }
	{ add	r14,r32,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000008C700 }

l400000000008CBF0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000008C580; }

l400000000008CC00:
	{ cmp4.eq	p07,p06,0x0,r49; nop.m	0x0; adds	r54,0x0,r34 }
	{ adds	r55,0x0,r39; nop.m	0x0; (p07) br.cond.dpnt.few	400000000008CC40; }

l400000000008CC20:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,mbschr; }
	{ adds	r1,0x0,r52; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	400000000008C700 }

l400000000008CC40:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r52; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	400000000008C580; }

l400000000008CC60:
	{ ld1	r14,[r38]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r42; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x0; (p06) br.cond.dptk.few	400000000008C360 }

l400000000008CCB0:
	{ adds	r15,0x20,r12; ld8	r14,[r40]; sub	r56,r45,r37 }
	{ adds	r54,0x0,r0; adds	r55,0x0,r38; adds	r57,0x0,r40; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; nop.m	0x0; adds	r1,0x0,r52; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000008C560; }

l400000000008CD00:
	{ adds	r15,0x20,r12; nop.m	0x0; adds	r33,0x1,r33; }
	{ ld8	r14,[r15]; nop.m	0x0; sxt4	r37,r33; }
	{ st8	[r14],r40; nop.i	0x0; br.cond.sptk.few	400000000008C220 }

l400000000008CD30:
	{ nop.m	0x0; adds	r33,0x1,r33; br.cond.sptk.few	400000000008C7C0 }

l400000000008CD40:
	{ cmp4.eq	p06,p07,0x0,r15; nop.i	0x0; (p06) br.cond.dpnt.few	400000000008C220; }

l400000000008CD50:
	{ nop.m	0x0; adds	r33,0x1,r33; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r37,r33; br.cond.sptk.few	400000000008C220 }

l400000000008CD70:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.sptk.few	400000000008CD30 }

l400000000008CD80:
	{ nop.m	0x0; adds	r17,0x0,r8; nop.i	0x0; }
	{ nop.m	0x0; add	r33,r17,r33; br.cond.sptk.few	400000000008C7C0 }

l400000000008CDA0:
	{ addl	r56,-6844,r1; nop.m	0x0; addl	r57,-6836,r1 }
	{ addl	r58,-6828,r1; nop.m	0x0; addl	r59,9,r0; }
	{ ld8	r56,[r56]; ld8	r57,[r57]; nop.i	0x0; }
	{ ld8	r58,[r58]; nop.i	0x0; br.call.sptk.many	b0,fn400000000008A3C0; }
	{ adds	r14,0x40,r12; nop.m	0x0; adds	r1,0x0,r52; }
	{ ld4	r33,[r14]; nop.i	0x0; br.cond.sptk.few	400000000008C6C0; }

;; char_is_quoted: 400000000008CE00
char_is_quoted proc
	{ alloc	r44,ar.pfs,0x13,0x0,0xF; adds	r12,0xFFFFFFFFFFFFFFD0,r12; mov	r46,pr }
	{ addl	r39,7548,r1; adds	r45,0x0,r1; adds	r47,0x0,r32; }
	{ adds	r40,0x30,r12; adds	r37,0x0,r0; mov	r43,b3 }
	{ adds	r34,0x0,r0; cmp.eq	p16,p17,r0,r0; adds	r41,0x18,r12; }
	{ st8	[r0],r40; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r45; nop.m	0x0; addl	r14,1,r0 }
	{ adds	r42,0x0,r8; cmp4.lt	p07,p06,r33,r0; addl	r38,-9996,r1 }
	{ nop.m	0x0; st4	[r14],r39; (p07) br.cond.dpnt.few	400000000008D440; }

l400000000008CE80:
	{ ld8	r38,[r38]; nop.m	0x0; nop.i	0x0 }

l400000000008CE90:
	{ nop.m	0x0; sxt4	r36,r34; add	r35,r32,r36; }
	{ nop.m	0x0; ld1	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; (p16) br.cond.dptk.few	400000000008D000 }

l400000000008CEC0:
	{ nop.m	0x0; cmp4.lt	p06,p07,r34,r33; addl	r8,1,r0 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dpnt.few	400000000008CF20; }

l400000000008CEE0:
	{ st4	[r0],r39; nop.m	0x0; nop.i	0x0 }

l400000000008CEF0:
	{ nop.m	0x0; mov	pr,r46,0xFFFFFFFFFFFFFFFE; nop.i	0x0; }
	{ nop.m	0x0; mov.i	ar.pfs,r44; mov.spnt	b0,r43,400000000008CF00 }
	{ nop.m	0x0; adds	r12,0x30,r12; br.ret	b0; }

l400000000008CF20:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r45; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	400000000008D2A0; }

l400000000008CF40:
	{ ld1	r14,[r35]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r38; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	400000000008D340; }

l400000000008CF90:
	{ (p06) addl	r14,1,r0; nop.m	0x0; nop.i	0x0; }

l400000000008CF96:
	{ break.m	0x4000; nop; break.i	0x80000 }

l400000000008CFA0:
	{ nop.m	0x0; add	r34,r14,r34; adds	r37,0x0,r0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000008CFC0:
	{ nop.m	0x0; sxt4	r36,r34; nop.i	0x0 }
	{ cmp4.lt	p07,p06,r33,r34; cmp4.eq	p16,p17,0x0,r37; (p07) br.cond.dpnt.few	400000000008D440; }

l400000000008CFE0:
	{ add	r35,r32,r36; nop.i	0x0; (p17) br.cond.dptk.few	400000000008CEC0; }

l400000000008CFF0:
	{ ld1	r14,[r35]; nop.i	0x0; sxt1	r14,r14; }

l400000000008D000:
	{ cmp4.eq	p07,p06,0x5C,r14; nop.m	0x0; cmp4.eq	p08,p09,0x27,r14 }
	{ adds	r47,0x0,r32; nop.m	0x0; adds	r48,0x0,r42; }
	{ (p07) adds	r34,0x1,r34; (p07) addl	r37,1,r0; (p07) br.cond.dpnt.few	400000000008CFC0; }

l400000000008D026:
	{ (p18) chk.a.clr	f1,3FFFFFFFFF28D026; Invalid; (p50) nop.b	0x23; }

l400000000008D02C:
	{ (p61) cmp.eq.unc	p63,p03,0x7F,r37; (p17) cmp.lt	p00,p18,r0,r0; (p32) cmp.eq.unc	p08,p60,0x63,r97 }

l400000000008D030:
	{ (p08) addl	r15,1,r0; cmp4.eq	p06,p07,0x22,r14; (p09) adds	r15,0x0,r0; }

l400000000008D036:
	{ (p03) addl	r34,96654,r3; (p07) nop; (p32) nop }

l400000000008D040:
	{ cmp.ne.or.andcm	p06,p07,0x0,r15; nop.i	0x0; (p07) br.cond.dpnt.few	400000000008D2B0; }

l400000000008D050:
	{ cmp4.eq	p06,p07,0x0,r15; nop.m	0x0; (p07) adds	r34,0x1,r34 }

l400000000008D060:
	{ nop.m	0x0; (p07) st8	[r0],r41; (p07) br.cond.dpnt.few	400000000008D120; }

l400000000008D06C:
	{ (p06) nop; zxt1	r64,r64; break.i	0x1000 }

l400000000008D070:
	{ adds	r49,0x1,r34; nop.i	0x0; br.call.sptk.many	b0,fn4000000000089DC0; }
	{ adds	r34,0x0,r8; nop.m	0x0; adds	r1,0x0,r45; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r33,r34; (p06) br.cond.dptk.few	400000000008CE90 }

l400000000008D0A0:
	{ st4	[r0],r39; addl	r8,1,r0; br.cond.sptk.few	400000000008CEF0 }

l400000000008D0B0:
	{ adds	r15,0x10,r12; ld8	r14,[r41]; adds	r47,0x0,r0 }
	{ adds	r48,0x0,r35; sub	r49,r42,r36; adds	r50,0x0,r41; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; nop.m	0x0; adds	r1,0x0,r45; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000008D4B0; }

l400000000008D100:
	{ adds	r15,0x10,r12; adds	r34,0x1,r34; nop.i	0x0 }
	{ ld8	r14,[r15]; st8	[r14],r41; nop.i	0x0 }

l400000000008D120:
	{ nop.m	0x0; sxt4	r36,r34; add	r35,r32,r36; }
	{ nop.m	0x0; ld1	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x0,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x27,r14; (p07) br.cond.dpnt.few	400000000008D230 }

l400000000008D160:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r45; nop.m	0x0; cmp.ltu	p07,p06,0x1,r8 }
	{ addl	r17,1,r0; nop.m	0x0; (p06) br.cond.dpnt.few	400000000008D260; }

l400000000008D190:
	{ ld1	r14,[r35]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r38; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	400000000008D0B0; }

l400000000008D1E0:
	{ add	r34,r17,r34; nop.m	0x0; nop.i	0x0; }

l400000000008D1F0:
	{ nop.m	0x0; sxt4	r36,r34; add	r35,r32,r36; }
	{ nop.m	0x0; ld1	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x0,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x27,r14; (p06) br.cond.dptk.few	400000000008D160; }

l400000000008D230:
	{ cmp4.eq	p06,p07,0x0,r14; (p07) adds	r34,0x1,r34; nop.i	0x0; }

l400000000008D23C:
	{ invala; cmp.eq	p00,p00,r32,r0; (p16) mov	pr,r72,0xC290 }
	{ (p34) invala; break.i	0x1000; break.b	0x1000 }

l400000000008D250:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000008D0A0 }

l400000000008D260:
	{ nop.m	0x0; adds	r34,0x1,r34; br.cond.sptk.few	400000000008D120; }

l400000000008D270:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r14,0x0,r8; (p07) br.cond.spnt.few	400000000008CFA0; }

l400000000008D28C:
	{ (p41) nop; break.i	0x1000; break.i	0x1000 }

l400000000008D290:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000008D2A0:
	{ adds	r34,0x1,r34; adds	r37,0x0,r0; br.cond.sptk.few	400000000008CFC0 }

l400000000008D2B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r45; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	400000000008D4A0; }

l400000000008D2D0:
	{ ld1	r14,[r35]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r38; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	400000000008D3C0; }

l400000000008D320:
	{ (p06) addl	r14,1,r0; nop.m	0x0; nop.i	0x0; }

l400000000008D326:
	{ break.m	0x4000; nop; break.i	0x80000 }

l400000000008D330:
	{ nop.m	0x0; add	r34,r14,r34; br.cond.sptk.few	400000000008CFC0 }

l400000000008D340:
	{ adds	r15,0x28,r12; ld8	r14,[r40]; adds	r47,0x0,r0 }
	{ adds	r48,0x0,r35; sub	r49,r42,r36; adds	r50,0x0,r40; }
	{ st8	[r14],r15; adds	r37,0x0,r0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; nop.m	0x0; adds	r1,0x0,r45; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000008D270; }

l400000000008D390:
	{ adds	r15,0x28,r12; nop.m	0x0; adds	r34,0x1,r34; }
	{ nop.m	0x0; ld8	r14,[r15]; nop.i	0x0; }
	{ st8	[r14],r40; nop.i	0x0; br.cond.sptk.few	400000000008CFC0 }

l400000000008D3C0:
	{ adds	r15,0x20,r12; ld8	r14,[r40]; adds	r47,0x0,r0 }
	{ adds	r48,0x0,r35; sub	r49,r42,r36; adds	r50,0x0,r40; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; nop.m	0x0; adds	r1,0x0,r45; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000008D470; }

l400000000008D410:
	{ adds	r15,0x20,r12; nop.m	0x0; adds	r34,0x1,r34; }
	{ nop.m	0x0; ld8	r14,[r15]; nop.i	0x0; }
	{ st8	[r14],r40; nop.i	0x0; br.cond.sptk.few	400000000008CFC0 }

l400000000008D440:
	{ adds	r8,0x0,r0; st4	[r0],r39; mov	pr,r46,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r44; mov.spnt	b0,r43,400000000008D450 }
	{ nop.m	0x0; adds	r12,0x30,r12; br.ret	b0 }

l400000000008D470:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r14,0x0,r8; (p07) br.cond.spnt.few	400000000008D330; }

l400000000008D48C:
	{ (p53) nop; break.i	0x1000; break.b	0x1000 }

l400000000008D490:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000008D4A0:
	{ nop.m	0x0; adds	r34,0x1,r34; br.cond.sptk.few	400000000008CFC0 }

l400000000008D4B0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.sptk.few	400000000008D260 }

l400000000008D4C0:
	{ nop.m	0x0; adds	r17,0x0,r8; nop.i	0x0; }
	{ nop.m	0x0; add	r34,r17,r34; br.cond.sptk.few	400000000008D1F0; }
400000000008D4E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000008D4F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; unclosed_pair: 400000000008D500
unclosed_pair proc
	{ alloc	r47,ar.pfs,0x16,0x0,0x12; adds	r12,0xFFFFFFFFFFFFFFD0,r12; mov	r49,pr }
	{ addl	r43,-9996,r1; adds	r48,0x0,r1; adds	r50,0x0,r32; }
	{ adds	r42,0x30,r12; ld8	r43,[r43]; mov	r46,b6 }
	{ adds	r38,0x0,r0; adds	r39,0x0,r0; adds	r35,0x0,r0; }
	{ st8	[r0],r42; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r48; nop.m	0x0; adds	r44,0x0,r8 }
	{ adds	r50,0x0,r34; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ cmp4.lt	p07,p06,r33,r0; adds	r1,0x0,r48; adds	r40,0x0,r8 }
	{ cmp4.eq	p16,p17,0x0,r8; sxt4	r45,r8; (p07) br.cond.dpnt.few	400000000008D5B0; }

l400000000008D590:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r38; (p06) br.cond.dptk.few	400000000008D6C0; }

l400000000008D5A0:
	{ nop.m	0x0; cmp4.lt	p07,p06,r35,r33; (p07) br.cond.dpnt.few	400000000008D5F0 }

l400000000008D5B0:
	{ adds	r39,0x0,r0; nop.m	0x0; nop.i	0x0; }

l400000000008D5C0:
	{ adds	r8,0x0,r39; mov	pr,r49,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r47; }
	{ nop.m	0x0; mov.spnt	b0,r46,400000000008D5D0; nop.i	0x0 }
	{ adds	r12,0x30,r12; nop.m	0x0; br.ret	b0; }

l400000000008D5F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ nop.m	0x0; sxt4	r52,r35; nop.i	0x0 }
	{ adds	r1,0x0,r48; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	400000000008DA00; }

l400000000008D620:
	{ add	r51,r32,r52; ld1	r14,[r51]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r43; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	400000000008DA70; }

l400000000008D680:
	{ (p06) addl	r14,1,r0; nop.m	0x0; nop.i	0x0; }

l400000000008D686:
	{ break.m	0x4000; nop; break.i	0x80000 }

l400000000008D690:
	{ nop.m	0x0; add	r35,r14,r35; adds	r38,0x0,r0; }

l400000000008D6A0:
	{ nop.m	0x0; cmp4.lt	p07,p06,r33,r35; (p07) br.cond.dpnt.few	400000000008D5C0; }

l400000000008D6B0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r38; (p07) br.cond.dptk.few	400000000008D5A0 }

l400000000008D6C0:
	{ nop.m	0x0; sxt4	r37,r35; add	r41,r32,r37; }
	{ ld1	r36,[r41]; nop.m	0x0; sxt1	r36,r36; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5C,r36; (p07) br.cond.dpnt.few	400000000008D7D0 }

l400000000008D6F0:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dptk.few	400000000008D840 }

l400000000008D700:
	{ ld1	r14,[r34]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r36; (p07) br.cond.dpnt.few	400000000008D800; }

l400000000008D720:
	{ cmp4.eq	p08,p09,0x27,r36; cmp4.eq	p06,p07,0x22,r36; adds	r52,0x0,r35 }
	{ adds	r50,0x0,r32; adds	r51,0x0,r44; (p08) addl	r14,1,r0; }

l400000000008D740:
	{ nop.m	0x0; (p09) adds	r14,0x0,r0; nop.i	0x0; }

l400000000008D74C:
	{ cmp.lt	p00,p17,r1,r0; czx1.r	r64,r81; mov	pr,r32,0x0 }
	{ (p28) cmp.lt	p00,p11,r64,r33; cmp4.ne.and	p00,p60,r99,r97; (p01) epc }

l400000000008D760:
	{ cmp4.eq	p06,p07,0x0,r14; (p07) adds	r14,0x18,r12; nop.i	0x0; }

l400000000008D76C:
	{ Invalid; mov	pr,r3,0x4680; Invalid }

l400000000008D776:
	{ Invalid; (p32) nop; (p48) nop; }

l400000000008D77C:
	{ (p50) ldfp8	f120,f63,[r44]; (p04) invala; nop.b	0x1000 }
	{ invala; cmp.lt	p00,p00,r32,r0; (p16) mov	pr,r104,0xC2D0 }
	{ Invalid; nop; (p04) nop }

l400000000008D7A0:
	{ nop.m	0x0; sxt4	r37,r35; add	r41,r32,r37; }
	{ ld1	r36,[r41]; nop.m	0x0; sxt1	r36,r36; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5C,r36; (p06) br.cond.dptk.few	400000000008D6F0 }

l400000000008D7D0:
	{ adds	r35,0x1,r35; nop.m	0x0; addl	r38,1,r0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r33,r35; (p06) br.cond.dptk.few	400000000008D6B0 }

l400000000008D7F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000008D5C0 }

l400000000008D800:
	{ adds	r50,0x0,r41; nop.m	0x0; adds	r51,0x0,r34 }
	{ adds	r52,0x0,r45; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C020; }
	{ adds	r1,0x0,r48; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	400000000008D720; }

l400000000008D830:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000008D840:
	{ add	r35,r35,r40; nop.m	0x0; sub	r39,0x1,r39; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r33,r35; (p06) br.cond.dptk.few	400000000008D6B0 }

l400000000008D860:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000008D5C0 }

l400000000008D870:
	{ adds	r15,0x18,r12; sub	r52,r44,r37; adds	r50,0x0,r0; }
	{ ld8	r14,[r15]; adds	r53,0x0,r15; adds	r15,0x10,r12; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r1,0x0,r48; adds	r15,0x10,r12; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000008DA10; }

l400000000008D8C0:
	{ adds	r35,0x1,r35; ld8	r14,[r15]; adds	r15,0x18,r12; }
	{ nop.m	0x0; sxt4	r37,r35; nop.i	0x0 }
	{ st8	[r14],r15; add	r14,r32,r37; nop.i	0x0; }
	{ ld1	r36,[r14]; nop.i	0x0; sxt1	r36,r36; }

l400000000008D900:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r36; nop.i	0x0; }
	{ cmp4.eq.or.andcm	p07,p06,0x27,r36; nop.i	0x0; (p07) br.cond.dpnt.few	400000000008DB90; }

l400000000008D920:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ add	r51,r32,r37; nop.m	0x0; adds	r1,0x0,r48 }
	{ cmp.ltu	p07,p06,0x1,r8; nop.m	0x0; (p06) br.cond.dpnt.few	400000000008DA40; }

l400000000008D950:
	{ ld1	r14,[r51]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r43; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	400000000008D870; }

l400000000008D9A0:
	{ (p06) addl	r14,1,r0; nop.m	0x0; nop.i	0x0; }

l400000000008D9A6:
	{ break.m	0x4000; nop; (p48) nop }

l400000000008D9B0:
	{ add	r35,r14,r35; nop.m	0x0; sxt4	r37,r35; }
	{ add	r14,r32,r37; ld1	r36,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r36,r36; br.cond.sptk.few	400000000008D900 }

l400000000008D9E0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r14,0x0,r8; (p07) br.cond.spnt.few	400000000008D690; }

l400000000008D9FC:
	{ (p37) ldfs	f127,[r36]; (p20) cmp.lt.unc	p32,p16,r8,r64; zxt1	r0,r64 }

l400000000008DA00:
	{ adds	r35,0x1,r35; adds	r38,0x0,r0; br.cond.sptk.few	400000000008D6A0 }

l400000000008DA10:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r14,0x0,r8; (p07) br.cond.spnt.few	400000000008D9B0; }

l400000000008DA2C:
	{ (p60) nop; break.i	0x1000; break.b	0x1000 }

l400000000008DA30:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000008DA40:
	{ adds	r35,0x1,r35; nop.m	0x0; sxt4	r37,r35; }
	{ add	r14,r32,r37; ld1	r36,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r36,r36; br.cond.sptk.few	400000000008D900 }

l400000000008DA70:
	{ ld8	r14,[r42]; adds	r15,0x28,r12; adds	r50,0x0,r0 }
	{ sub	r52,r44,r52; adds	r53,0x0,r42; adds	r38,0x0,r0; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r15,0x28,r12; adds	r1,0x0,r48; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000008D9E0; }

l400000000008DAC0:
	{ ld8	r14,[r15]; nop.m	0x0; adds	r35,0x1,r35; }
	{ st8	[r14],r42; nop.i	0x0; br.cond.sptk.few	400000000008D6A0 }

l400000000008DAE0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r48; nop.m	0x0; cmp.ltu	p07,p06,0x1,r8 }
	{ addl	r17,1,r0; nop.m	0x0; (p06) br.cond.dpnt.few	400000000008DBC0; }

l400000000008DB10:
	{ ld1	r14,[r41]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r43; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	400000000008DBF0; }

l400000000008DB60:
	{ add	r35,r17,r35; nop.m	0x0; nop.i	0x0; }

l400000000008DB70:
	{ nop.m	0x0; cmp4.lt	p07,p06,r33,r35; (p06) br.cond.dptk.few	400000000008D6B0 }

l400000000008DB80:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000008D5C0; }

l400000000008DB90:
	{ cmp4.eq	p06,p07,0x0,r36; (p07) adds	r35,0x1,r35; nop.i	0x0; }

l400000000008DB9C:
	{ invala; cmp.lt	p00,p00,r32,r0; (p16) mov	pr,r104,0xC2D0 }
	{ (p32) invala; break.i	0x1000; break.i	0x1000 }

l400000000008DBB0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000008D5B0 }

l400000000008DBC0:
	{ nop.m	0x0; adds	r35,0x1,r35; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r33,r35; (p06) br.cond.dptk.few	400000000008D6B0 }

l400000000008DBE0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000008D5C0 }

l400000000008DBF0:
	{ ld8	r14,[r42]; adds	r15,0x20,r12; adds	r50,0x0,r0 }
	{ adds	r51,0x0,r41; sub	r52,r44,r37; adds	r53,0x0,r42; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r15,0x20,r12; adds	r1,0x0,r48; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000008DC70; }

l400000000008DC40:
	{ adds	r35,0x1,r35; ld8	r14,[r15]; nop.i	0x0; }
	{ st8	[r14],r42; cmp4.lt	p07,p06,r33,r35; (p06) br.cond.dptk.few	400000000008D6B0 }

l400000000008DC60:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000008D5C0; }

l400000000008DC70:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.sptk.few	400000000008DBC0 }

l400000000008DC80:
	{ nop.m	0x0; adds	r17,0x0,r8; nop.i	0x0; }
	{ nop.m	0x0; add	r35,r17,r35; br.cond.sptk.few	400000000008DB70; }
400000000008DCA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000008DCB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; split_at_delims: 400000000008DCC0
;;   Called from:
;;     40000000000E5CBC (in gen_compspec_completions)
;;     40000000000E60BC (in gen_compspec_completions)
split_at_delims proc
	{ alloc	r53,ar.pfs,0x1C,0x0,0x18; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r55,pr }
	{ cmp.eq	p06,p07,0x0,r32; adds	r54,0x0,r1; adds	r56,0x0,r34; }
	{ nop.m	0x0; mov	r52,b4; adds	r45,0x18,r12 }
	{ cmp.eq	p09,p08,0x0,r34; adds	r40,0x0,r0; (p06) br.cond.dpnt.few	400000000008DFF0; }

l400000000008DD00:
	{ ld1	r57,[r32]; adds	r43,0x0,r0; sxt1	r57,r57; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r57; (p07) br.cond.dptk.few	400000000008DFF0 }

l400000000008DD20:
	{ nop.m	0x0; nop.i	0x0; (p09) br.cond.dpnt.few	400000000008E750; }

l400000000008DD30:
	{ st8	[r0],r45; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r54; nop.m	0x0; adds	r41,0x0,r8 }
	{ adds	r56,0x1,r8; nop.m	0x0; br.call.sptk.many	b0,xmalloc; }
	{ nop.m	0x0; adds	r1,0x0,r54; adds	r46,0x0,r8; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000008DD80:
	{ nop.m	0x0; sxt4	r39,r40; add	r39,r34,r39; }
	{ ld1	r14,[r39]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	400000000008DEC0 }

l400000000008DDB0:
	{ adds	r15,0x10,r12; ld8	r14,[r45]; nop.i	0x0; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ cmp.ltu	p07,p06,0x1,r8; adds	r1,0x0,r54; adds	r58,0x0,r41 }
	{ adds	r57,0x0,r39; adds	r56,0x0,r0; (p06) br.cond.dpnt.few	400000000008E050; }

l400000000008DDF0:
	{ adds	r59,0x0,r45; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r44,0x0,r8; sxt4	r56,r43 }
	{ adds	r57,0x0,r39; adds	r58,0x0,r8; cmp.ltu	p09,p08,0x1,r8; }
	{ cmp.ltu	p06,p07,0x1,r14; add	r56,r46,r56; adds	r1,0x0,r54; }
	{ (p07) adds	r15,0x10,r12; (p07) ld8	r14,[r15]; nop.i	0x0; }

l400000000008DE36:
	{ (p07) fwb; cmp.eq	p00,p00,r0,r1; (p01) nop; }

l400000000008DE3C:
	{ Invalid; Invalid; mov	pr,r32,0x0 }

l400000000008DE46:
	{ chk.a.nc	f0,3FFFFFFFFF08E646; nop; break.i	0x80000 }

l400000000008DE50:
	{ nop.m	0x0; nop.i	0x0; (p08) br.cond.spnt.few	400000000008E050; }

l400000000008DE60:
	{ add	r40,r44,r40; nop.m	0x0; sub	r41,r41,r8 }
	{ add	r43,r44,r43; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ nop.m	0x0; sxt4	r39,r40; adds	r1,0x0,r54; }
	{ nop.m	0x0; add	r39,r34,r39; nop.i	0x0; }
	{ ld1	r14,[r39]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	400000000008DDB0 }

l400000000008DEC0:
	{ nop.m	0x0; adds	r39,0x1,r32; sxt4	r14,r43 }
	{ adds	r41,0x0,r32; adds	r40,0x0,r0; adds	r42,0x0,r0; }
	{ add	r14,r46,r14; st1	[r0],r14; nop.i	0x0; }
	{ ld1	r14,[r32]; nop.m	0x0; sxt1	r57,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r57; (p07) br.cond.dpnt.few	400000000008DFB0; }

l400000000008DF10:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000008DF20:
	{ adds	r56,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,mbschr; }
	{ nop.m	0x0; ld1	r14,[r41]; adds	r1,0x0,r54 }
	{ cmp.eq	p07,p06,0x0,r8; adds	r41,0x0,r39; (p07) br.cond.dpnt.few	400000000008E0A0; }

l400000000008DF50:
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x20,r14; nop.m	0x0; cmp4.eq	p08,p09,0xA,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x9,r14; (p06) br.cond.dptk.few	400000000008DF90 }

l400000000008DF80:
	{ nop.m	0x0; nop.i	0x0; (p09) br.cond.dpnt.few	400000000008E0B0 }

l400000000008DF90:
	{ ld1	r57,[r39],1; adds	r40,0x1,r40; sxt1	r57,r57; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r57; (p07) br.cond.dptk.few	400000000008DF20 }

l400000000008DFB0:
	{ adds	r44,0x0,r0; nop.m	0x0; nop.i	0x0; }
	{ adds	r8,0x0,r44; mov	pr,r55,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r53; }
	{ nop.m	0x0; mov.spnt	b0,r52,400000000008DFD0; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l400000000008DFF0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r37; nop.i	0x0; }
	{ (p07) st4	[r0],r37; cmp.eq	p07,p06,0x0,r38; (p07) br.cond.dpnt.few	400000000008DFB0; }

l400000000008E006:
	{ (p03) chk.a.clr	f0,3FFFFFFFFFD11266; addl	r123,2052863,r3; Invalid }

l400000000008E010:
	{ (p06) adds	r44,0x0,r0; (p06) st4	[r0],r38; nop.i	0x0; }

l400000000008E016:
	{ mf.a; Invalid; nop; }

l400000000008E01C:
	{ Invalid; (p01) cmp.eq	p00,p16,r11,r64; (p63) nop.i	0xDFE0D }
	{ (p26) break.m	0x1540; break.i	0x1000; break.b	0xC002D }
	{ shladdp4	r0,r1,0x1,r0; zxt1	r4,r64; add	r0,r32,r0 }
	{ cmp.lt	p00,p08,r33,r0; (p01) nop; cmp.eq	p00,p00,r32,r0 }

l400000000008E050:
	{ ld1	r14,[r39]; nop.m	0x0; sxt4	r15,r43 }
	{ adds	r40,0x1,r40; nop.m	0x0; adds	r41,0xFFFFFFFFFFFFFFFF,r41; }
	{ nop.m	0x0; sxt1	r14,r14; add	r15,r46,r15; }
	{ cmp4.eq	p06,p07,0x20,r14; cmp4.eq.or.andcm	p06,p07,0x9,r14; nop.i	0x0; }
	{ (p07) st1	[r14],r15; (p07) adds	r43,0x1,r43; br.cond.sptk.few	400000000008DD80 }

l400000000008E096:
	{ Invalid; mov	pr,0x48FFFCF; break.b	0x80000; }

l400000000008E09C:
	{ (p39) nop.m	0x91FFF; cmp.lt	p00,p00,r32,r0; (p01) break.b	0x141C0 }

l400000000008E0A0:
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }

l400000000008E0B0:
	{ cmp.eq	p07,p06,0x0,r38; cmp.eq	p09,p08,0x0,r46; or	r49,0x1,r36 }
	{ adds	r44,0x0,r0; addl	r43,-1,r0; adds	r47,0x0,r0; }
	{ (p06) addl	r51,1,r0; (p08) addl	r50,1,r0; nop.i	0x0 }

l400000000008E0D6:
	{ Invalid; nop; (p16) nop }

l400000000008E0DC:
	{ nop; (p02) dep	r64,r10,r100,62,13; Invalid }
	{ (p54) nop; (p06) dep	r0,r0,r64,44,1; (p06) epc }

l400000000008E0F0:
	{ (p07) adds	r51,0x0,r0; (p09) adds	r50,0x0,r0; zxt1	r48,r51 }

l400000000008E0F6:
	{ Invalid; (p24) nop; nop }

l400000000008E0FC:
	{ Invalid; Invalid; Invalid }

l400000000008E100:
	{ adds	r56,0x0,r32; adds	r57,0x0,r40; nop.i	0x0 }
	{ adds	r58,0x0,r34; adds	r59,0x0,r49; br.call.sptk.many	b0,skip_to_delim; }
	{ cmp4.eq	p06,p07,r8,r40; adds	r1,0x0,r54; adds	r42,0x0,r8; }
	{ nop.m	0x0; tbit.z.or.andcm	p07,p06,r50,0x0; (p07) br.cond.dptk.few	400000000008E170 }

l400000000008E140:
	{ nop.m	0x0; sxt4	r14,r40; add	r14,r32,r14; }
	{ ld1	r57,[r14]; nop.m	0x0; sxt1	r57,r57; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r57; (p06) br.cond.dpnt.few	400000000008E480 }

l400000000008E170:
	{ nop.m	0x0; sxt4	r41,r42; add	r41,r32,r41 }

l400000000008E180:
	{ adds	r58,0x0,r42; adds	r57,0x0,r40; nop.i	0x0 }
	{ adds	r56,0x0,r32; adds	r45,0x1,r47; br.call.sptk.many	b0,substring; }
	{ adds	r1,0x0,r54; nop.m	0x0; adds	r39,0x0,r8 }
	{ adds	r56,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,make_word; }
	{ adds	r57,0x0,r44; nop.m	0x0; adds	r1,0x0,r54 }
	{ adds	r56,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,make_word_list; }
	{ adds	r1,0x0,r54; nop.m	0x0; adds	r44,0x0,r8 }
	{ adds	r56,0x0,r39; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ cmp4.lt	p07,p06,r42,r35; cmp4.lt	p09,p08,r35,r40; adds	r15,0xFFFFFFFFFFFFFFFF,r40 }
	{ adds	r1,0x0,r54; (p08) addl	r14,1,r0; (p06) addl	r16,1,r0; }

l400000000008E21C:
	{ cmp.lt	p00,p41,0x0,r72; (p01) nop; (p02) epc }

l400000000008E220:
	{ (p09) adds	r14,0x0,r0; (p07) adds	r16,0x0,r0; cmp4.eq	p08,p09,r35,r15; }

l400000000008E226:
	{ Invalid; (p04) nop; (p32) nop; }

l400000000008E22C:
	{ (p17) cmp.lt	p15,p11,r9,r113; (p33) cmp.lt	p03,p16,r4,r3; nop; }
	{ setf.exp	f0,r1; (p05) cmp.lt	p32,p16,r11,r64; czx2.r	r127,r97 }

l400000000008E246:
	{ Invalid; addl	r0,49152,r1; (p33) cmp.eq	p35,p00,0x0,r0 }

l400000000008E256:
	{ Invalid; nop; break.i	0x80000; }

l400000000008E25C:
	{ nop; cmp.lt	p00,p00,r32,r0; zxt1	r3,r3 }
	{ Invalid; cmp.lt	p00,p00,r32,r0; mov	pr,r99,0xE680 }
	{ (p01) ldfp8	f0,f0,[r33]; Invalid; Invalid }

l400000000008E280:
	{ addl	r43,-1,r0; nop.m	0x0; cmp4.lt	p07,p06,r35,r40; }
	{ (p08) adds	r43,0x0,r45; (p08) br.cond.dpnt.few	400000000008E2A0; (p07) br.cond.dpnt.few	400000000008E590 }

l400000000008E296:
	{ chk.a.nc	f1,3FFFFFFFFF8EE296; mov	pr,0x4300030; (p16) nop }

l400000000008E29C:
	{ (p24) nop; (p07) cmp.eq	p32,p08,r10,r0; (p04) break.i	0x16540 }

l400000000008E2A0:
	{ ld1	r57,[r41]; sxt4	r39,r42; adds	r40,0x0,r42; }
	{ nop.m	0x0; sxt1	r57,r57; add	r39,r32,r39,0x1; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r57; (p07) br.cond.dpnt.few	400000000008E380; }

l400000000008E2D0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000008E2E0:
	{ adds	r56,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,mbschr; }
	{ nop.m	0x0; adds	r1,0x0,r54; cmp.eq	p07,p06,0x0,r8 }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	400000000008E620; (p16) br.cond.dptk.few	400000000008E350 }

l400000000008E30C:
	{ (p02) cmp.lt	p00,p11,r0,r33; Invalid; Invalid }

l400000000008E310:
	{ ld1	r14,[r41]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x20,r14; nop.m	0x0; cmp4.eq	p08,p09,0xA,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x9,r14; (p06) br.cond.dptk.few	400000000008E350 }

l400000000008E340:
	{ nop.m	0x0; nop.i	0x0; (p09) br.cond.dpnt.few	400000000008E630 }

l400000000008E350:
	{ adds	r41,0x0,r39; ld1	r57,[r39],1; adds	r40,0x1,r40; }
	{ nop.m	0x0; sxt1	r57,r57; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r57; (p06) br.cond.dptk.few	400000000008E2E0; }

l400000000008E380:
	{ nop.m	0x0; cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r43; nop.i	0x0; }
	{ nop.m	0x0; tbit.z.or.andcm	p07,p06,r48,0x0; (p07) br.cond.dptk.few	400000000008E3E0; }

l400000000008E3A0:
	{ cmp4.lt	p07,p06,r35,r33; nop.m	0x0; cmp4.lt	p09,p08,r35,r42; }
	{ nop.m	0x0; (p08) cmp4.eq.or.andcm	p06,p07,0x0,r0; (p06) br.cond.dptk.few	400000000008E6B0; }

l400000000008E3C0:
	{ (p07) addl	r43,-1,r0; nop.m	0x0; nop.i	0x0; }

l400000000008E3C6:
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ break.m	0x4000; nop; (p32) nop }

l400000000008E3E0:
	{ cmp.eq	p06,p07,0x0,r37; nop.m	0x0; adds	r56,0x0,r44; }

l400000000008E3E2:
	{ (p16) break.m	0x720E9; Invalid; Invalid }

l400000000008E3E6:
	{ break.m	0x4000; (p28) cmp4.eq.or	p00,p02,r44,r0; (p01) nop }

l400000000008E3E8:
	{ Invalid; (p05) nop; (p21) break.i	0x8C82 }

l400000000008E3EC:
	{ Invalid; Invalid; Invalid }
	{ Invalid; (p48) cmp.lt.unc	p10,p08,r9,r100; mov	pr,r107,0xE400 }
	{ (p29) nop; cmp.lt	p00,p00,r32,r0; (p01) rfi }
	{ cmp.lt	p00,p17,r1,r0; czx1.r	r64,r65; mov	pr,r32,0x0 }
	{ Invalid; break.i	0x1000; break.i	0x1000 }
	{ Invalid; (p05) invala; nop.b	0x1000 }
	{ Invalid; (p01) cmp.eq	p00,p16,r11,r64; (p63) nop.i	0xDFE0D }
	{ (p26) break.m	0x1540; break.i	0x1000; break.b	0xC002D }
	{ shladdp4	r0,r1,0x2,r0; zxt1	r4,r64; add	r0,r32,r0 }
	{ Invalid; (p07) invala; break.i	0x1000 }

l400000000008E480:
	{ adds	r56,0x0,r46; nop.i	0x0; br.call.sptk.many	b0,mbschr; }
	{ adds	r1,0x0,r54; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	400000000008E170; }

l400000000008E4A0:
	{ adds	r42,0x1,r40; nop.m	0x0; sxt4	r39,r42; }
	{ add	r41,r32,r39; ld1	r14,[r41]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r57,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r57; (p17) br.cond.dptk.few	400000000008E650; }

l400000000008E4E0:
	{ nop.m	0x0; (p06) add	r39,r32,r39,0x1; (p07) br.cond.dpnt.few	400000000008E180; }

l400000000008E4EC:
	{ (p37) nop; break.i	0x1000; break.i	0x1000 }

l400000000008E4F0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000008E500:
	{ adds	r56,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,mbschr; }
	{ adds	r1,0x0,r54; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	400000000008E170; }

l400000000008E520:
	{ ld1	r14,[r41]; adds	r41,0x0,r39; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x20,r14; nop.m	0x0; cmp4.eq	p08,p09,0xA,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x9,r14; (p06) br.cond.dptk.few	400000000008E560 }

l400000000008E550:
	{ nop.m	0x0; nop.i	0x0; (p09) br.cond.dpnt.few	400000000008E170 }

l400000000008E560:
	{ ld1	r57,[r39],1; adds	r42,0x1,r42; sxt1	r57,r57; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r57; (p06) br.cond.dptk.few	400000000008E500 }

l400000000008E580:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000008E180 }

l400000000008E590:
	{ nop.m	0x0; addl	r56,-6740,r1; sxt4	r39,r42 }
	{ adds	r43,0x0,r45; adds	r40,0x0,r42; adds	r45,0x2,r47; }
	{ ld8	r56,[r56]; add	r39,r32,r39,0x1; br.call.sptk.many	b0,make_word; }
	{ adds	r1,0x0,r54; ld8	r57,[r44]; adds	r56,0x0,r8 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,make_word_list; }
	{ ld1.a	r57,[r41]; st8	[r8],r44; adds	r1,0x0,r54; }
	{ ld1.c.clr	r57,[r41]; nop.m	0x0; sxt1	r57,r57; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r57; (p06) br.cond.dptk.few	400000000008E2E0 }

l400000000008E610:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000008E380 }

l400000000008E620:
	{ ld1	r14,[r41]; nop.i	0x0; sxt1	r14,r14; }

l400000000008E630:
	{ adds	r47,0x0,r45; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.sptk.few	400000000008E100 }

l400000000008E640:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000008E380; }

l400000000008E650:
	{ nop.m	0x0; (p06) add	r39,r32,r39,0x1; (p07) br.cond.dpnt.few	400000000008E180; }

l400000000008E65C:
	{ Invalid; (p07) nop; (p05) epc }

l400000000008E660:
	{ adds	r56,0x0,r46; adds	r41,0x0,r39; br.call.sptk.many	b0,mbschr; }
	{ adds	r1,0x0,r54; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	400000000008E170; }

l400000000008E680:
	{ ld1	r57,[r39],1; adds	r42,0x1,r42; sxt1	r57,r57; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r57; (p06) br.cond.dptk.few	400000000008E660 }

l400000000008E6A0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000008E180 }

l400000000008E6B0:
	{ nop.m	0x0; sxt4	r14,r35; add	r14,r32,r14; }
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x9,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x20,r14; nop.i	0x0; }
	{ nop.m	0x0; (p06) adds	r43,0x0,r45; (p06) br.cond.dptk.few	400000000008E3E0 }

l400000000008E6FC:
	{ (p39) nop; Invalid; Invalid }

l400000000008E700:
	{ addl	r56,-6740,r1; nop.m	0x0; adds	r45,0x1,r45; }
	{ ld8	r56,[r56]; adds	r43,0x0,r45; br.call.sptk.many	b0,make_word; }
	{ adds	r1,0x0,r54; nop.m	0x0; adds	r57,0x0,r44 }
	{ adds	r56,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,make_word_list; }
	{ adds	r1,0x0,r54; adds	r44,0x0,r8; br.cond.sptk.few	400000000008E3E0; }

l400000000008E750:
	{ addl	r14,9092,r1; addl	r42,1,r0; adds	r46,0x0,r0 }
	{ adds	r39,0x1,r32; adds	r41,0x0,r32; adds	r40,0x0,r0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld8	r34,[r14]; nop.i	0x0; br.cond.sptk.few	400000000008DF20; }
400000000008E790 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000008E7A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000008E7B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; string_list_internal: 400000000008E7C0
;;   Called from:
;;     400000000008EC6C (in string_list)
;;     400000000008EE7C (in string_list_dollar_star)
;;     400000000008EECC (in string_list_dollar_star)
;;     40000000000912DC (in string_list_dollar_at)
;;     400000000009135C (in string_list_dollar_at)
;;     40000000000C3D1C (in assoc_to_string)
;;     40000000000C3D5C (in assoc_to_string)
string_list_internal proc
	{ alloc	r41,ar.pfs,0xF,0x0,0xC; nop.m	0x0; mov	r43,pr }
	{ cmp.eq	p06,p07,0x0,r32; nop.m	0x0; adds	r42,0x0,r1; }
	{ nop.m	0x0; mov	r40,b0; (p06) br.cond.dpnt.few	400000000008EC10; }

l400000000008E7F0:
	{ nop.m	0x0; ld8	r34,[r32]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r34; nop.i	0x0; (p07) br.cond.dpnt.few	400000000008EB90; }

l400000000008E810:
	{ cmp.eq	p06,p07,0x0,r33; nop.i	0x0; (p06) br.cond.dpnt.few	400000000008E980; }

l400000000008E820:
	{ ld1	r14,[r33]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000008E980 }

l400000000008E840:
	{ adds	r14,0x1,r33; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r36,1,r0; (p06) br.cond.dptk.few	400000000008E8C0 }

l400000000008E86C:
	{ (p03) cmp.lt	p00,p11,r0,r33; (p33) cmp.lt	p32,p16,r8,r64; Invalid }

l400000000008E870:
	{ adds	r14,0x2,r33; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r36,2,r0; (p06) br.cond.dptk.few	400000000008E8C0 }

l400000000008E89C:
	{ (p01) shladd	r0,r0,0x2,r33; zxt1	r32,r64; break.b	0x1000 }

l400000000008E8A0:
	{ adds	r44,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; adds	r1,0x0,r42; adds	r36,0x0,r8 }

l400000000008E8C0:
	{ adds	r14,0x0,r32; adds	r35,0x0,r0; adds	r37,0x8,r32; }

l400000000008E8D0:
	{ adds	r15,0x8,r14; cmp.eq	p06,p07,r32,r14; (p06) br.cond.dpnt.few	400000000008E940; }

l400000000008E8E0:
	{ ld8	r14,[r15]; nop.m	0x0; add	r35,r35,r36; }
	{ ld8	r44,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ cmp.eq	p07,p06,0x0,r34; adds	r1,0x0,r42; nop.i	0x0 }
	{ add	r35,r35,r8; adds	r14,0x0,r34; (p07) br.cond.dpnt.few	400000000008E9A0; }

l400000000008E920:
	{ ld8	r34,[r34]; nop.m	0x0; nop.i	0x0 }

l400000000008E930:
	{ adds	r15,0x8,r14; cmp.eq	p06,p07,r32,r14; (p07) br.cond.dptk.few	400000000008E8E0 }

l400000000008E940:
	{ nop.m	0x0; ld8	r14,[r37]; nop.i	0x0; }
	{ ld8	r44,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r14,0x0,r34; nop.m	0x0; adds	r1,0x0,r42 }
	{ add	r35,r35,r8; ld8	r34,[r34]; br.cond.sptk.few	400000000008E930; }

l400000000008E980:
	{ adds	r36,0x0,r0; nop.m	0x0; adds	r14,0x0,r32 }
	{ adds	r35,0x0,r0; adds	r37,0x8,r32; br.cond.sptk.few	400000000008E8D0; }

l400000000008E9A0:
	{ adds	r44,0x1,r35; nop.m	0x0; adds	r34,0x0,r32 }
	{ cmp4.lt	p17,p16,0x1,r36; nop.m	0x0; sxt4	r38,r36; }
	{ nop.m	0x0; sxt4	r44,r44; br.call.sptk.many	b0,xmalloc; }
	{ cmp4.eq	p07,p06,0x0,r36; nop.m	0x0; adds	r1,0x0,r42 }
	{ adds	r39,0x0,r8; nop.m	0x0; adds	r35,0x0,r8; }
	{ (p06) addl	r37,1,r0; nop.i	0x0; (p07) adds	r37,0x0,r0; }

l400000000008E9F6:
	{ addp4	r0,0xFFFFFFFFFFFFE000,r1; (p18) nop; (p32) nop }

l400000000008EA00:
	{ adds	r14,0x8,r34; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; ld8	r36,[r14]; nop.i	0x0; }
	{ adds	r44,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; sxt4	r8,r8; nop.b	0x0 }
	{ adds	r1,0x0,r42; adds	r44,0x0,r35; adds	r45,0x0,r36; }
	{ add	r35,r35,r8; adds	r46,0x0,r8; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ ld8	r34,[r34]; nop.m	0x0; adds	r1,0x0,r42; }
	{ cmp.eq	p09,p08,r34,r32; cmp.eq	p07,p06,0x0,r34; (p07) br.cond.dpnt.few	400000000008EB60; }

l400000000008EA80:
	{ (p08) addl	r14,1,r0; nop.m	0x0; (p17) adds	r44,0x0,r35 }

l400000000008EA86:
	{ nop; (p22) dep	r0,r35,r0,35,3; (p20) nop }

l400000000008EA90:
	{ (p17) adds	r45,0x0,r33; (p17) adds	r46,0x0,r38; (p09) adds	r14,0x0,r0; }

l400000000008EA96:
	{ (p23) chk.s	f38,400000000010EA96; break.x	0x2000000E80000 }

l400000000008EA9C:
	{ nop; cmp.lt	p00,p00,r32,r0; zxt1	r35,r3; }

l400000000008EAA0:
	{ nop.m	0x0; and	r14,r14,r37; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000008EA00; }

l400000000008EAC0:
	{ (p17) add	r35,r35,r38; nop.i	0x0; (p17) br.call.dptk.many	b0,fn400000000001A8A0; }

l400000000008EAC6:
	{ nop; (p32) nop; (p36) nop }

l400000000008EAD0:
	{ (p16) ld1	r14,[r33]; nop.m	0x0; (p17) adds	r1,0x0,r42; }

l400000000008EAD6:
	{ nop; nop; (p20) nop }

l400000000008EAE0:
	{ (p16) st1	[r35],r1,1; nop.m	0x0; adds	r14,0x8,r34; }

l400000000008EAE6:
	{ break.m	0x4000; (p07) nop; (p32) nop }
	{ (p18) fwb; nop; nop }
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ (p04) break.m	0x58400; nop; nop }
	{ Invalid; (p22) nop; (p32) nop.b	0x800B }
	{ Invalid; (p32) nop; (p32) br.call.sptk.few	b0,b0 }
	{ add	r0,r0,r1; nop; (p16) nop }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD11D76; nop; nop.b	0x27002 }

l400000000008EB60:
	{ adds	r8,0x0,r39; st1	[r0],r35; mov	pr,r43,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r41; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r40,400000000008EB80; br.ret	b0 }

l400000000008EB90:
	{ adds	r32,0x8,r32; ld8	r14,[r32]; nop.i	0x0; }
	{ ld8	r44,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r42; adds	r44,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r14,[r32]; adds	r1,0x0,r42; adds	r44,0x0,r8; }
	{ ld8	r45,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r39,0x0,r8; adds	r1,0x0,r42; mov	pr,r43,0xFFFFFFFFFFFFFFFE; }
	{ adds	r8,0x0,r39; nop.m	0x0; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.spnt	b0,r40,400000000008EC00; br.ret	b0 }

l400000000008EC10:
	{ adds	r39,0x0,r0; nop.m	0x0; mov	pr,r43,0xFFFFFFFFFFFFFFFE; }
	{ adds	r8,0x0,r39; nop.m	0x0; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.spnt	b0,r40,400000000008EC30; br.ret	b0; }

;; string_list: 400000000008EC40
;;   Called from:
;;     400000000002766C (in decode_prompt_string)
;;     400000000002766C (in decode_prompt_string)
;;     4000000000033B2C (in fn4000000000030880)
;;     400000000008FF8C (in string_rest_of_args)
;;     400000000009346C (in string_list_pos_params)
;;     400000000009352C (in string_list_pos_params)
;;     40000000000935CC (in string_list_pos_params)
;;     40000000000978CC (in fn4000000000097540)
;;     40000000000A64FC (in fn40000000000A5B80)
;;     40000000000A65FC (in cond_expand_word)
;;     40000000000A66CC (in cond_expand_word)
;;     40000000000A69CC (in expand_assignment_string_to_string)
;;     40000000000A6D8C (in expand_string_unsplit_to_string)
;;     40000000000A78CC (in expand_string_to_string)
;;     40000000000DE52C (in redirection_expand)
;;     40000000000F40FC (in eval_builtin)
;;     40000000000FE26C (in history_builtin)
string_list proc
	{ alloc	r16,ar.pfs,0x2,0x0,0x2; nop.m	0x0; addl	r33,-6732,r1; }
	{ nop.m	0x0; ld8	r33,[r33]; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	string_list_internal; }
400000000008EC70 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; ifs_firstchar: 400000000008EC80
;;   Called from:
;;     40000000000BD93C (in array_modcase)
;;     40000000000BDB1C (in array_modcase)
;;     40000000000BDD8C (in array_patsub)
;;     40000000000BDF6C (in array_patsub)
;;     40000000000BE1CC (in array_subrange)
;;     40000000000BE3DC (in array_subrange)
;;     40000000000C3FCC (in assoc_modcase)
;;     40000000000C41AC (in assoc_modcase)
;;     40000000000C441C (in assoc_patsub)
;;     40000000000C45FC (in assoc_patsub)
ifs_firstchar proc
	{ alloc	r36,ar.pfs,0x9,0x0,0x6; addl	r34,9108,r1; mov	r35,b3 }
	{ nop.m	0x0; adds	r37,0x0,r1; nop.i	0x0; }
	{ nop.m	0x0; addl	r38,17,r0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r15,0x0,r8 }
	{ adds	r33,0x0,r8; nop.m	0x0; adds	r38,0x0,r8; }
	{ ld8	r14,[r34]; addl	r39,23524,r1; cmp.eq	p07,p06,0x1,r14 }
	{ nop.m	0x0; adds	r40,0x0,r14; (p07) br.cond.dpnt.few	400000000008ED50; }

l400000000008ECF0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ ld4	r14,[r34]; cmp.eq	p06,p07,0x0,r32; nop.b	0x0 }
	{ adds	r8,0x0,r33; adds	r1,0x0,r37; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,400000000008ED20; sxt4	r15,r14; }
	{ add	r15,r33,r15; nop.i	0x0; nop.i	0x0 }
	{ st1	[r0],r15; (p07) st4	[r14],r32; br.ret	b0 }

l400000000008ED4C:
	{ nop; (p02) cmp.lt.unc	p32,p08,r9,r0; zxt1	r96,r64 }

l400000000008ED50:
	{ ld1	r16,[r39]; adds	r14,0x0,r39; nop.b	0x0 }
	{ adds	r8,0x0,r33; mov.i	ar.pfs,r36; mov.spnt	b0,r35,400000000008ED60 }
	{ nop.m	0x0; sxt1	r16,r16; cmp4.eq	p07,p06,0x0,r16 }
	{ st1	[r15],r1,1; nop.i	0x0; (p07) adds	r14,0x0,r0 }

l400000000008ED90:
	{ st1	[r0],r15; (p06) addl	r14,1,r0; cmp.eq	p06,p07,0x0,r32; }

l400000000008ED9C:
	{ Invalid; Invalid; add	r0,r32,r0 }

l400000000008EDA6:
	{ break.m	0x4000; (p34) nop; break.i	0x80000 }
400000000008EDB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; string_list_dollar_star: 400000000008EDC0
;;   Called from:
;;     400000000008FFDC (in string_rest_of_args)
;;     40000000000934BC (in string_list_pos_params)
;;     40000000000934EC (in string_list_pos_params)
;;     400000000009357C (in string_list_pos_params)
;;     40000000000A5E8C (in fn40000000000A5B80)
;;     40000000000C1BEC (in fn40000000000C14C0)
;;     40000000000C20FC (in array_keys)
string_list_dollar_star proc
	{ alloc	r36,ar.pfs,0xA,0x0,0x7; adds	r37,0x0,r12; mov	r35,b3 }
	{ nop.m	0x0; adds	r38,0x0,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r38; nop.m	0x0; adds	r8,0x10,r8; }
	{ addl	r14,9108,r1; and	r8,0xFFFFFFFFFFFFFFF0,r8; addl	r40,23524,r1; }
	{ nop.m	0x0; nop.m	0x0; sub	r12,r12,r8 }
	{ nop.m	0x0; adds	r34,0x10,r12; nop.i	0x0; }
	{ ld8	r33,[r14]; adds	r39,0x0,r34; cmp.eq	p07,p06,0x1,r33 }
	{ adds	r41,0x0,r33; add	r33,r34,r33; (p07) br.cond.dpnt.few	400000000008EEA0; }

l400000000008EE50:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ adds	r1,0x0,r38; st1	[r0],r33; nop.i	0x0 }
	{ adds	r39,0x0,r32; adds	r40,0x0,r34; br.call.sptk.many	b0,string_list_internal; }
	{ adds	r1,0x0,r38; mov.i	ar.pfs,r36; mov.spnt	b0,r35,400000000008EE80 }
	{ nop.m	0x0; adds	r12,0x0,r37; br.ret	b0; }

l400000000008EEA0:
	{ ld1	r14,[r40]; nop.m	0x0; adds	r15,0x11,r12 }
	{ adds	r39,0x0,r32; adds	r40,0x0,r34; nop.i	0x0 }
	{ st1	[r14],r34; st1	[r0],r15; br.call.sptk.many	b0,string_list_internal; }
	{ adds	r1,0x0,r38; mov.i	ar.pfs,r36; mov.spnt	b0,r35,400000000008EED0 }
	{ nop.m	0x0; adds	r12,0x0,r37; br.ret	b0; }
400000000008EEF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; get_word_from_string: 400000000008EF00
;;   Called from:
;;     400000000010762C (in read_builtin)
;;     40000000001081FC (in read_builtin)
get_word_from_string proc
	{ alloc	r41,ar.pfs,0x11,0x0,0xC; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r43,LC }
	{ cmp.eq	p07,p06,0x0,r32; nop.m	0x0; adds	r42,0x0,r1; }
	{ nop.m	0x0; mov	r40,b0; (p07) br.cond.dpnt.few	400000000008F130; }

l400000000008EF30:
	{ nop.m	0x0; ld8	r35,[r32]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r35; nop.i	0x0; (p06) br.cond.dpnt.few	400000000008F130; }

l400000000008EF50:
	{ ld1	r14,[r35]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000008F130; }

l400000000008EF70:
	{ cmp.eq	p06,p07,0x0,r33; nop.i	0x0; (p06) br.cond.dpnt.few	400000000008EFA0; }

l400000000008EF80:
	{ ld1	r15,[r33]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p09,p08,0x20,r15; (p09) br.cond.dpnt.few	400000000008F4D0 }

l400000000008EFA0:
	{ (p06) addl	r17,1,r0; nop.i	0x0; (p07) adds	r17,0x0,r0 }

l400000000008EFA6:
	{ addp4	r0,0xFFFFFFFFFFFFE000,r1; (p08) nop; (p48) nop }

l400000000008EFB0:
	{ addl	r15,9092,r1; nop.m	0x0; adds	r36,0x0,r0; }
	{ nop.m	0x0; ld8	r16,[r15]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r16; nop.i	0x0; (p06) br.cond.dpnt.few	400000000008F7D0; }

l400000000008EFE0:
	{ ld1	r15,[r16]; nop.m	0x0; adds	r16,0x1,r16; }
	{ nop.m	0x0; sxt1	r15,r15; sub	r18,r0,r16; }
	{ cmp4.eq	p06,p07,0x0,r15; mov.i	LC,r18; (p06) br.cond.dpnt.few	400000000008F7D0; }

l400000000008F010:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000008F020:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x1,r15; nop.i	0x0; }
	{ (p07) or	r36,0x10,r36; nop.i	0x0; (p07) br.cond.dpnt.few	400000000008F050; }

l400000000008F036:
	{ chk.a.nc	f0,3FFFFFFFFF08F836; Invalid; (p48) nop }

l400000000008F040:
	{ cmp4.eq	p07,p06,0x7F,r15; nop.i	0x0; (p07) or	r36,0x20,r36 }

l400000000008F050:
	{ nop.m	0x0; nop.i	0x0; br.cloop.sptk.few	400000000008F160 }

l400000000008F060:
	{ addl	r16,23540,r1; nop.m	0x0; cmp4.eq	p07,p06,0x0,r17; }
	{ nop.m	0x0; nop.i	0x0; (p07) br.cond.dptk.few	400000000008F1A0; }

l400000000008F080:
	{ nop.m	0x0; zxt1	r15,r14; cmp4.eq	p06,p07,0x20,r14 }
	{ nop.m	0x0; cmp4.eq	p09,p08,0xA,r14; nop.b	0x0; }
	{ add	r15,r16,r15; cmp4.eq.or.andcm	p06,p07,0x9,r14; (p06) br.cond.dptk.few	400000000008F0C0 }

l400000000008F0B0:
	{ nop.m	0x0; nop.i	0x0; (p08) br.cond.dpnt.few	400000000008F1C0; }

l400000000008F0C0:
	{ nop.m	0x0; ld1	r14,[r15]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000008F1C0; }

l400000000008F0E0:
	{ adds	r35,0x1,r35; ld1	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	400000000008F080; }

l400000000008F110:
	{ cmp.eq	p07,p06,0x0,r34; st8	[r35],r32; nop.i	0x0; }
	{ (p06) st8	[r35],r34; nop.m	0x0; nop.i	0x0 }

l400000000008F126:
	{ break.m	0x4000; nop; nop }

l400000000008F130:
	{ adds	r36,0x0,r0; adds	r8,0x0,r36; mov.i	ar.pfs,r41; }

l400000000008F132:
	{ Invalid; nop; (p05) break.i	0x550; }
	{ ldfe	f32,[r0]; (p21) break.i	0x550; Invalid }
	{ Invalid; (p02) nop; Invalid }

l400000000008F160:
	{ ld1	r15,[r16],1; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	400000000008F020; }

l400000000008F180:
	{ addl	r16,23540,r1; nop.m	0x0; cmp4.eq	p07,p06,0x0,r17; }
	{ nop.m	0x0; nop.i	0x0; (p06) br.cond.dptk.few	400000000008F080 }

l400000000008F1A0:
	{ ld1	r15,[r33]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	400000000008F080 }

l400000000008F1C0:
	{ nop.m	0x0; adds	r37,0x18,r12; nop.i	0x0; }
	{ st4	[r0],r37; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ cmp.ltu	p07,p06,0x1,r8; adds	r1,0x0,r42; adds	r44,0x0,r35; }
	{ (p06) addl	r38,1,r0; (p06) br.cond.dpnt.few	400000000008F210; br.call.sptk.many	b0,fn400000000001B6C0; }

l400000000008F1F6:
	{ Invalid; (p32) nop; break.i	0x80000; }

l400000000008F1FC:
	{ (p38) nop; nop; Invalid }
	{ nop; (p05) nop }

l400000000008F210:
	{ adds	r48,0x0,r36; adds	r44,0x0,r35; adds	r45,0x0,r38 }
	{ adds	r46,0x0,r37; adds	r47,0x0,r33; br.call.sptk.many	b0,fn4000000000086900; }
	{ ld4	r14,[r37]; nop.m	0x0; cmp.eq	p07,p06,0x0,r34 }
	{ adds	r1,0x0,r42; nop.m	0x0; adds	r36,0x0,r8; }
	{ nop.m	0x0; sxt4	r18,r14; add	r18,r35,r18; }
	{ ld1.a	r14,[r18]; (p06) st8	[r18],r34; nop.i	0x0; }

l400000000008F26C:
	{ cmp.lt	p00,p11,r1,r0; Invalid; cmp.lt	p00,p00,r32,r0 }
	{ Invalid; cmp.lt	p00,p00,r32,r0; mov	pr,r99,0xE680; }
	{ (p16) nop; cmp.lt	p00,p00,r32,r0; nop }

l400000000008F290:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x20,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x9,r14; (p07) br.cond.dptk.few	400000000008F580; }

l400000000008F2B0:
	{ (p06) addl	r39,1,r0; nop.m	0x0; nop.i	0x0 }

l400000000008F2B6:
	{ break.m	0x4000; nop; break.i	0x80000 }

l400000000008F2C0:
	{ nop.m	0x0; adds	r14,0x10,r12; nop.i	0x0; }
	{ st8	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r42; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	400000000008F610; }

l400000000008F2F0:
	{ ld4	r15,[r37]; nop.m	0x0; sxt4	r46,r15; }
	{ add	r45,r35,r46; ld1	r14,[r45]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ and	r16,0x1F,r14; extr.u	r17,r14,5,3; addl	r14,-9996,r1; }
	{ ld8	r14,[r14]; shladd	r14,r17,0x2,r14; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r16; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	400000000008F5B0; }

l400000000008F370:
	{ (p06) addl	r16,1,r0; nop.m	0x0; nop.i	0x0; }

l400000000008F376:
	{ break.m	0x4000; nop; break.i	0x80000 }

l400000000008F380:
	{ nop.m	0x0; add	r16,r15,r16; nop.i	0x0; }
	{ st4	[r16],r37; nop.m	0x0; nop.i	0x0 }

l400000000008F3A0:
	{ nop.m	0x0; sxt4	r15,r16; addl	r19,23540,r1; }
	{ add	r18,r35,r15; nop.m	0x0; add	r15,r35,r15,0x1; }
	{ ld1	r14,[r18]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.spnt.few	400000000008F490; }

l400000000008F3E0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000008F400:
	{ nop.m	0x0; zxt1	r17,r14; nop.b	0x0 }
	{ cmp4.eq	p06,p07,0x20,r14; cmp4.eq	p09,p08,0xA,r14; adds	r18,0x0,r15; }
	{ add	r17,r19,r17; cmp4.eq.or.andcm	p06,p07,0x9,r14; (p06) br.cond.dptk.few	400000000008F440 }

l400000000008F430:
	{ nop.m	0x0; nop.i	0x0; (p08) br.cond.dpnt.few	400000000008F630; }

l400000000008F440:
	{ nop.m	0x0; ld1	r17,[r17]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r17; nop.i	0x0; (p07) br.cond.dpnt.few	400000000008F630; }

l400000000008F460:
	{ adds	r16,0x1,r16; st4	[r16],r37; nop.i	0x0; }
	{ ld1	r14,[r15],1; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	400000000008F400 }

l400000000008F490:
	{ st8	[r18],r32; nop.m	0x0; nop.i	0x0 }

l400000000008F4A0:
	{ adds	r8,0x0,r36; mov.i	ar.pfs,r41; mov.i	LC,r43; }
	{ nop.m	0x0; mov.spnt	b0,r40,400000000008F4B0; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l400000000008F4D0:
	{ adds	r15,0x1,r33; ld1	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p09,p08,0x9,r15; (p08) br.cond.dptk.few	400000000008EFA0 }

l400000000008F500:
	{ adds	r15,0x2,r33; ld1	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p09,p08,0xA,r15; (p08) br.cond.dptk.few	400000000008EFA0 }

l400000000008F530:
	{ adds	r15,0x3,r33; ld1	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; cmp4.eq	p08,p09,0x0,r15; }
	{ nop.m	0x0; (p08) addl	r17,1,r0; (p08) br.cond.dptk.few	400000000008EFB0; }

l400000000008F55C:
	{ (p19) nop; nop; zxt4	r0,r0 }

l400000000008F560:
	{ nop.m	0x0; (p06) addl	r17,1,r0; nop.i	0x0; }

l400000000008F56C:
	{ invala; nop; zxt1	r0,r64 }

l400000000008F57C:
	{ (p18) cmp.lt.unc	p63,p11,r63,r36; (p32) cmp4.ne.and	p02,p28,r99,r97; zxt4	r0,r0 }

l400000000008F580:
	{ cmp4.eq	p06,p07,0xA,r14; (p06) addl	r14,1,r0; nop.i	0x0; }

l400000000008F58C:
	{ nop; cmp4.eq.and	p00,p32,r32,r0; zxt1	r0,r64 }

l400000000008F59C:
	{ invala; cmp.eq	p00,p00,r32,r0; zxt1	r64,r64 }
	{ (p41) addp4	r127,r63,r36; zxt1	r0,r64; cmp.lt	p00,p00,r32,r0 }

l400000000008F5B0:
	{ adds	r44,0x0,r0; nop.m	0x0; sub	r46,r38,r46 }
	{ adds	r47,0x10,r12; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; nop.m	0x0; adds	r1,0x0,r42; }
	{ nop.m	0x0; cmp.ltu	p06,p07,0x1,r14; (p07) br.cond.dptk.few	400000000008F610; }

l400000000008F5F0:
	{ cmp.eq	p06,p07,0x0,r8; nop.i	0x0; (p07) adds	r16,0x0,r8 }

l400000000008F600:
	{ nop.m	0x0; (p07) ld4	r15,[r37]; (p07) br.cond.spnt.few	400000000008F380; }

l400000000008F60C:
	{ Invalid; Invalid; zxt1	r0,r64 }

l400000000008F610:
	{ ld4	r16,[r37]; adds	r16,0x1,r16; nop.i	0x0; }
	{ st4	[r16],r37; nop.i	0x0; br.cond.sptk.few	400000000008F3A0 }

l400000000008F630:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r39; (p07) br.cond.dptk.few	400000000008F7A0 }

l400000000008F640:
	{ addl	r19,23540,r1; nop.m	0x0; zxt1	r15,r14; }
	{ nop.m	0x0; add	r15,r19,r15; nop.i	0x0; }
	{ nop.m	0x0; ld1	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r15; (p07) br.cond.dptk.few	400000000008F7A0; }

l400000000008F680:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x20,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x9,r14; (p07) br.cond.dptk.few	400000000008F7A0; }

l400000000008F6A0:
	{ adds	r16,0x1,r16; cmp4.eq	p07,p06,0xA,r14; (p07) br.cond.dpnt.few	400000000008F7A0; }

l400000000008F6B0:
	{ nop.m	0x0; sxt4	r15,r16; nop.i	0x0 }
	{ st4	[r16],r37; add	r18,r35,r15; nop.i	0x0; }
	{ ld1	r14,[r18]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	400000000008F490; }

l400000000008F6F0:
	{ (p06) add	r15,r35,r15,0x1; nop.m	0x0; nop.i	0x0; }

l400000000008F6F6:
	{ break.m	0x4000; nop; break.i	0x80000 }

l400000000008F700:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x20,r14; zxt1	r17,r14 }

l400000000008F702:
	{ Invalid; Invalid; (p32) dep	r3,r4,r32,63,3 }
	{ (p33) nop; chk.a.nc	r4,4000000000897B12; (p48) sub	r3,r64,r16,0x1 }
	{ (p18) nop; (p33) fcmp.eq.unc	p35,p01,f113,f113; Invalid }

l400000000008F730:
	{ nop.m	0x0; nop.i	0x0; (p09) br.cond.dpnt.few	400000000008F7A0; }

l400000000008F740:
	{ nop.m	0x0; ld1	r14,[r17]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000008F7A0; }

l400000000008F760:
	{ st4	[r16],r37; ld1	r14,[r15],1; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	400000000008F700 }

l400000000008F790:
	{ st8	[r18],r32; nop.i	0x0; br.cond.sptk.few	400000000008F4A0 }

l400000000008F7A0:
	{ nop.m	0x0; ld4	r18,[r37]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r18,r18; add	r18,r35,r18; }
	{ st8	[r18],r32; nop.i	0x0; br.cond.sptk.few	400000000008F4A0 }

l400000000008F7D0:
	{ addl	r16,23540,r1; adds	r36,0x0,r0; cmp4.eq	p07,p06,0x0,r17; }
	{ nop.m	0x0; nop.i	0x0; (p06) br.cond.dptk.few	400000000008F080 }

l400000000008F7F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000008F1A0; }

;; strip_trailing_ifs_whitespace: 400000000008F800
;;   Called from:
;;     400000000010834C (in read_builtin)
strip_trailing_ifs_whitespace proc
	{ alloc	r36,ar.pfs,0x8,0x0,0x7; nop.m	0x0; mov	r38,LC }
	{ cmp.eq	p06,p07,0x0,r32; nop.m	0x0; adds	r37,0x0,r1; }
	{ nop.m	0x0; mov	r35,b3; (p06) br.cond.dpnt.few	400000000008FAA0; }

l400000000008F830:
	{ ld1	r14,[r32]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000008FA30 }

l400000000008F850:
	{ adds	r17,0x1,r32; ld1	r14,[r17]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000008FA00 }

l400000000008F880:
	{ adds	r14,0x2,r32; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r8,1,r0; (p06) br.cond.dptk.few	400000000008F8D0 }

l400000000008F8AC:
	{ (p01) cmp.eq	p00,p17,r0,r33; zxt1	r0,r64; break.b	0x1000 }

l400000000008F8B0:
	{ adds	r39,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; adds	r1,0x0,r37; adds	r8,0xFFFFFFFFFFFFFFFF,r8; }

l400000000008F8D0:
	{ nop.m	0x0; add	r15,r32,r8; nop.i	0x0; }
	{ nop.m	0x0; cmp.ltu	p06,p07,r32,r15; (p07) br.cond.spnt.few	400000000008F9F0 }

l400000000008F8F0:
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r15; nop.m	0x0; sub	r16,r15,r32,0x1 }
	{ addl	r18,23540,r1; nop.m	0x0; cmp4.eq	p12,p13,0x0,r34; }
	{ cmp.ltu	p06,p07,r14,r32; nop.m	0x0; mov.i	LC,r16 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.spnt.few	400000000008FAB0; }

l400000000008F930:
	{ nop.m	0x0; cmp.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r32; (p06) br.cond.spnt.few	400000000008FAB0; }

l400000000008F940:
	{ ld1	r14,[r15]; adds	r17,0x1,r15; sxt1	r14,r14; }
	{ nop.m	0x0; zxt1	r16,r14; nop.b	0x0 }
	{ cmp4.eq	p06,p07,0x20,r14; cmp4.eq	p11,p10,0xA,r14; cmp4.eq	p09,p08,0x1,r14; }
	{ add	r16,r18,r16; cmp4.eq.or.andcm	p06,p07,0x9,r14; (p06) br.cond.dptk.few	400000000008FA60 }

l400000000008F980:
	{ nop.m	0x0; nop.i	0x0; (p11) br.cond.dpnt.few	400000000008FA60 }

l400000000008F990:
	{ nop.m	0x0; (p12) br.cond.dpnt.few	400000000008F9F0; (p08) br.cond.dpnt.few	400000000008F9F0; }

l400000000008F99C:
	{ (p03) cmp.lt	p00,p11,r64,r33; Invalid; cmp.lt	p00,p00,r32,r0 }

l400000000008F9A0:
	{ ld1	r14,[r17]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x20,r14; nop.m	0x0; cmp4.eq	p08,p09,0xA,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x9,r14; (p06) br.cond.dptk.few	400000000008F9E0 }

l400000000008F9D0:
	{ nop.m	0x0; nop.i	0x0; (p09) br.cond.dpnt.few	400000000008FA00 }

l400000000008F9E0:
	{ nop.m	0x0; adds	r15,0xFFFFFFFFFFFFFFFF,r15; br.cloop.sptk.few	400000000008F940; }

l400000000008F9F0:
	{ adds	r17,0x1,r15; nop.m	0x0; nop.i	0x0; }

l400000000008FA00:
	{ adds	r8,0x0,r32; st1	[r0],r17; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.i	LC,r38; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r35,400000000008FA20; br.ret	b0 }

l400000000008FA30:
	{ addl	r8,-1,r0; add	r15,r32,r8; nop.i	0x0; }
	{ nop.m	0x0; cmp.ltu	p06,p07,r32,r15; (p06) br.cond.sptk.few	400000000008F8F0 }

l400000000008FA50:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000008F9F0 }

l400000000008FA60:
	{ nop.m	0x0; ld1	r14,[r16]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	400000000008F990 }

l400000000008FA80:
	{ nop.m	0x0; adds	r15,0xFFFFFFFFFFFFFFFF,r15; br.cloop.sptk.few	400000000008F940 }

l400000000008FA90:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000008F9F0; }

l400000000008FAA0:
	{ nop.m	0x0; addl	r15,-1,r0; br.cond.sptk.few	400000000008F8F0 }

l400000000008FAB0:
	{ nop.m	0x0; mov.i	LC,0x0; br.cond.sptk.few	400000000008F940; }

;; list_rest_of_args: 400000000008FAC0
;;   Called from:
;;     400000000006A46C (in push_dollar_vars)
;;     400000000006A50C (in push_dollar_vars)
;;     400000000008FF5C (in string_rest_of_args)
list_rest_of_args proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x6; addl	r14,5924,r1; mov	r34,b2 }
	{ nop.m	0x0; adds	r36,0x0,r1; nop.i	0x0; }
	{ adds	r33,0x0,r0; ld8	r32,[r14]; mov	r37,LC }
	{ nop.m	0x0; nop.m	0x0; mov.i	LC,0x8; }

l400000000008FB00:
	{ nop.m	0x0; ld8	r38,[r32],8; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r38; nop.i	0x0; (p07) br.cond.dpnt.few	400000000008FB60; }

l400000000008FB20:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,make_bare_word; }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r39,0x0,r33 }
	{ adds	r38,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,make_word_list; }
	{ adds	r1,0x0,r36; adds	r33,0x0,r8; br.cloop.sptk.few	400000000008FB00; }

l400000000008FB60:
	{ addl	r14,7132,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld8	r32,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r32; (p06) br.cond.dpnt.few	400000000008FC00; }

l400000000008FB90:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000008FBA0:
	{ adds	r14,0x8,r32; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r38,[r14]; nop.i	0x0; br.call.sptk.many	b0,make_bare_word; }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r39,0x0,r33 }
	{ adds	r38,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,make_word_list; }
	{ ld8	r32,[r32]; adds	r1,0x0,r36; adds	r33,0x0,r8; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p06) br.cond.dptk.few	400000000008FBA0; }

l400000000008FC00:
	{ cmp.eq	p06,p07,0x0,r33; adds	r38,0x0,r33; (p06) br.cond.dpnt.few	400000000008FC50; }

l400000000008FC10:
	{ nop.m	0x0; ld8	r14,[r33]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000008FC50; }

l400000000008FC30:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,list_reverse; }
	{ nop.m	0x0; adds	r1,0x0,r36; adds	r33,0x0,r8; }

l400000000008FC50:
	{ adds	r8,0x0,r33; mov.i	ar.pfs,r35; mov.i	LC,r37; }
	{ nop.m	0x0; mov.spnt	b0,r34,400000000008FC60; br.ret	b0; }
400000000008FC70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; number_of_args: 400000000008FC80
;;   Called from:
;;     400000000010C85C (in shift_builtin)
number_of_args proc
	{ addl	r14,5932,r1; adds	r8,0x0,r0; mov	r2,LC; }
	{ nop.m	0x0; ld8	r14,[r14]; mov.i	LC,0x8; }

l400000000008FCA0:
	{ ld8	r15,[r14],8; nop.m	0x0; adds	r16,0x1,r8; }
	{ cmp.eq	p07,p06,0x0,r15; nop.i	0x0; (p07) br.cond.dpnt.few	400000000008FCD0; }

l400000000008FCC0:
	{ nop.m	0x0; adds	r8,0x0,r16; br.cloop.sptk.few	400000000008FCA0 }

l400000000008FCD0:
	{ addl	r14,7132,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	400000000008FD20; }

l400000000008FD00:
	{ ld8	r14,[r14]; nop.m	0x0; adds	r8,0x1,r8; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	400000000008FD00 }

l400000000008FD20:
	{ nop.m	0x0; mov.i	LC,r2; br.ret	b0; }
400000000008FD30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; get_dollar_var_value: 400000000008FD40
get_dollar_var_value proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x6; addl	r14,23444,r1; mov	r37,LC }
	{ adds	r36,0x0,r1; nop.m	0x0; cmp.lt	p06,p07,0x9,r32; }
	{ nop.m	0x0; nop.m	0x0; mov	r34,b2 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dptk.few	400000000008FE10; }

l400000000008FD80:
	{ shladd	r33,r32,0x3,r14; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r33]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; adds	r38,0x0,r14; (p06) br.cond.dpnt.few	400000000008FEF0; }

l400000000008FDB0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r36; adds	r38,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r38,0x0,r8 }
	{ ld8	r39,[r33]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r36; mov.i	ar.pfs,r35; mov.i	LC,r37; }
	{ nop.m	0x0; mov.spnt	b0,r34,400000000008FE00; br.ret	b0 }

l400000000008FE10:
	{ addl	r14,7132,r1; adds	r15,0xFFFFFFFFFFFFFFF5,r32; cmp.eq	p08,p09,0xA,r32; }
	{ nop.m	0x0; nop.m	0x0; mov.i	LC,r15; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	400000000008FEF0; (p08) br.cond.dpnt.few	400000000008FE80; }

l400000000008FE4C:
	{ (p02) nop; break.i	0x1000; break.i	0x1000 }

l400000000008FE50:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000008FE60:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	400000000008FEF0; br.cloop.sptk.few	400000000008FE60 }

l400000000008FE7C:
	{ (p63) nop; (p04) cmp.lt.unc	p02,p16,r3,r64; (p01) rfi }

l400000000008FE80:
	{ adds	r33,0x8,r14; ld8	r14,[r33]; nop.i	0x0; }
	{ ld8	r38,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r36; adds	r38,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r14,[r33]; adds	r1,0x0,r36; adds	r38,0x0,r8; }
	{ ld8	r39,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r36; mov.i	ar.pfs,r35; mov.i	LC,r37; }
	{ nop.m	0x0; mov.spnt	b0,r34,400000000008FEE0; br.ret	b0 }

l400000000008FEF0:
	{ adds	r8,0x0,r0; mov.i	ar.pfs,r35; mov.i	LC,r37; }
	{ nop.m	0x0; mov.spnt	b0,r34,400000000008FF00; br.ret	b0; }
400000000008FF10 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000008FF20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000008FF30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; string_rest_of_args: 400000000008FF40
string_rest_of_args proc
	{ alloc	r36,ar.pfs,0x7,0x0,0x6; mov	r35,b3; adds	r37,0x0,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,list_rest_of_args; }
	{ cmp4.eq	p06,p07,0x0,r32; adds	r1,0x0,r37; nop.i	0x0 }
	{ adds	r33,0x0,r8; adds	r38,0x0,r8; (p07) br.cond.dpnt.few	400000000008FFD0; }

l400000000008FF80:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,string_list; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r34,0x0,r8 }
	{ adds	r38,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,dispose_words; }
	{ adds	r8,0x0,r34; adds	r1,0x0,r37; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,400000000008FFC0; br.ret	b0; }

l400000000008FFD0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,string_list_dollar_star; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r34,0x0,r8 }
	{ adds	r38,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,dispose_words; }
	{ adds	r8,0x0,r34; adds	r1,0x0,r37; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,4000000000090010; br.ret	b0; }
4000000000090020 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000090030 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; remove_backslashes: 4000000000090040
remove_backslashes proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; nop.m	0x0; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; adds	r36,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r35; adds	r36,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r35; cmp.eq	p06,p07,0x0,r32; nop.i	0x0 }
	{ adds	r15,0x0,r8; adds	r14,0x0,r32; (p06) br.cond.dpnt.few	4000000000090160; }

l40000000000900A0:
	{ ld1	r17,[r32]; nop.m	0x0; sxt1	r17,r17; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r17; (p06) br.cond.dpnt.few	4000000000090160; }

l40000000000900C0:
	{ adds	r16,0x0,r14; cmp4.eq	p07,p06,0x5C,r17; adds	r18,0x0,r15; }
	{ (p07) adds	r16,0x1,r14; ld1	r17,[r16]; adds	r14,0x1,r16; }

l40000000000900D6:
	{ (p08) fwb; (p07) mov	pr,r16,0x1002; break.b	0x80000 }
	{ (p08) break.m	0x50880; (p04) nop; (p32) nop }
	{ chk.a.nc	r0,3FFFFFFFFF0908F6; nop; break.i	0x80000 }

l4000000000090100:
	{ nop.m	0x0; st1	[r15],r1,1; nop.i	0x0; }
	{ adds	r18,0x0,r15; nop.i	0x0; (p08) br.cond.dpnt.few	4000000000090140; }

l4000000000090120:
	{ ld1	r17,[r14]; nop.m	0x0; sxt1	r17,r17; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r17; (p06) br.cond.dptk.few	40000000000900C0 }

l4000000000090140:
	{ st1	[r0],r18; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,4000000000090150; br.ret	b0 }

l4000000000090160:
	{ adds	r18,0x0,r8; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ st1	[r0],r18; mov.spnt	b0,r33,4000000000090170; br.ret	b0; }

;; quote_escapes: 4000000000090180
;;   Called from:
;;     400000000009128C (in string_list_dollar_at)
;;     400000000009DA5C (in fn400000000009A180)
;;     40000000000BAB9C (in array_quote_escapes)
;;     40000000000C2A1C (in assoc_quote_escapes)
quote_escapes proc
	{ alloc	r42,ar.pfs,0x12,0x0,0xE; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r44,pr }
	{ adds	r43,0x0,r1; nop.m	0x0; adds	r46,0x0,r32; }
	{ nop.m	0x0; adds	r37,0x18,r12; mov	r41,b1 }
	{ adds	r33,0x0,r0; adds	r35,0x0,r0; addl	r36,1,r0; }
	{ st8	[r0],r37; mov	r45,LC; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r43; add	r40,r32,r8; addl	r14,9092,r1; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ adds	r15,0x1,r14; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	4000000000090670; }

l4000000000090200:
	{ ld1	r14,[r14]; sub	r16,r0,r15; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; mov.i	LC,r16; (p07) br.cond.dptk.few	4000000000090480; }

l4000000000090220:
	{ nop.m	0x0; (p06) adds	r33,0x0,r0; (p06) adds	r35,0x0,r0; }

l400000000009022C:
	{ cmp.lt	p00,p08,r0,r66; (p02) nop }

l4000000000090230:
	{ add	r46,r8,r8,0x1; cmp4.eq	p18,p19,0x0,r36; cmp4.eq	p17,p16,0x0,r33 }
	{ adds	r34,0x0,r32; cmp4.eq	p21,p20,0x0,r35; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r43; ld1	r14,[r32]; nop.i	0x0 }
	{ addl	r38,1,r0; adds	r39,0x0,r8; adds	r33,0x0,r8; }
	{ addl	r36,-9996,r1; sxt1	r14,r14; nop.i	0x0; }
	{ ld8	r36,[r36]; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000902A0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	4000000000090420 }

l40000000000902B0:
	{ nop.m	0x0; nop.i	0x0; (p20) br.cond.dptk.few	40000000000902D0; }

l40000000000902C0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x1,r14; (p06) br.cond.dpnt.few	4000000000090620 }

l40000000000902D0:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dptk.few	40000000000902F0; }

l40000000000902E0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x7F,r14; (p06) br.cond.dpnt.few	4000000000090620 }

l40000000000902F0:
	{ nop.m	0x0; nop.i	0x0; (p18) br.cond.dptk.few	4000000000090310; }

l4000000000090300:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x20,r14; (p07) br.cond.dpnt.few	4000000000090620 }

l4000000000090310:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r43; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	4000000000090640 }

l4000000000090330:
	{ ld1	r14,[r34]; addl	r8,1,r0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r15,r14,5,3; and	r16,0x1F,r14; }
	{ shladd	r15,r15,0x2,r36; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r15,r15,r16; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r15,0x0; (p07) br.cond.dpnt.few	4000000000090560; }

l4000000000090380:
	{ sub	r19,r34,r34,0x1; cmp.eq	p06,p07,0x0,r8; adds	r15,0x0,r34 }
	{ adds	r16,0x0,r33; adds	r17,0x1,r34; add	r18,r19,r8; }
	{ nop.m	0x0; mov.i	LC,r18; nop.i	0x0; }
	{ nop.m	0x0; (p07) mov.i	LC,r18; (p06) mov.i	LC,0x0 }

l40000000000903BC:
	{ nop; zxt1	r0,r64; cmp.eq	p00,p00,r32,r0 }

l40000000000903C0:
	{ adds	r33,0x0,r16; nop.m	0x0; adds	r47,0x1,r15; }
	{ st1	[r33],r1,1; nop.m	0x0; adds	r15,0x0,r47; }
	{ nop.m	0x0; adds	r16,0x0,r33; br.cloop.sptk.few	4000000000090510; }

l40000000000903F0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000090400:
	{ ld1	r14,[r47]; adds	r34,0x0,r47; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000902B0; }

l4000000000090420:
	{ adds	r8,0x0,r39; st1	[r0],r33; mov	pr,r44,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r42; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r45; mov.spnt	b0,r41,4000000000090440 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000090460:
	{ ld1	r14,[r15],1; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000904B0; }

l4000000000090480:
	{ cmp4.eq	p06,p07,0x1,r14; cmp4.eq	p08,p09,0x7F,r14; (p06) addl	r16,1,r0 }

l4000000000090490:
	{ (p08) addl	r14,1,r0; (p07) adds	r16,0x0,r0; (p09) adds	r14,0x0,r0; }

l4000000000090496:
	{ (p08) chk.s	f0,4000000000110496; (p07) nop; (p48) nop; }

l400000000009049C:
	{ ldfps	f0,f0,[r66]; (p52) nop; (p20) nop; }

l40000000000904A0:
	{ or	r35,r35,r16; or	r33,r33,r14; br.cloop.sptk.few	4000000000090460; }

l40000000000904B0:
	{ add	r46,r8,r8,0x1; adds	r36,0x0,r0; cmp4.eq	p17,p16,0x0,r33 }
	{ adds	r34,0x0,r32; cmp4.eq	p21,p20,0x0,r35; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r43; ld1	r14,[r32]; cmp4.eq	p18,p19,0x0,r36 }
	{ addl	r38,1,r0; adds	r39,0x0,r8; adds	r33,0x0,r8; }
	{ addl	r36,-9996,r1; nop.m	0x0; sxt1	r14,r14; }
	{ ld8	r36,[r36]; nop.i	0x0; br.cond.sptk.few	40000000000902A0 }

l4000000000090510:
	{ ld1	r14,[r17],1; adds	r33,0x0,r16; adds	r47,0x1,r15; }
	{ nop.m	0x0; sxt1	r14,r14; adds	r15,0x0,r47; }
	{ nop.m	0x0; st1	[r33],r1,1; nop.i	0x0; }
	{ nop.m	0x0; adds	r16,0x0,r33; br.cloop.sptk.few	4000000000090510 }

l4000000000090550:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000090400 }

l4000000000090560:
	{ ld8	r14,[r37]; adds	r15,0x10,r12; adds	r46,0x0,r0 }
	{ adds	r47,0x0,r34; sub	r48,r40,r34; adds	r49,0x0,r37; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r18,0x10,r12; adds	r1,0x0,r43; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000906E0; }

l40000000000905B0:
	{ ld8	r14,[r18]; nop.m	0x0; addl	r8,1,r0; }
	{ nop.m	0x0; st8	[r14],r37; nop.i	0x0 }
	{ ld1	r14,[r34]; nop.i	0x0; sxt1	r14,r14 }

l40000000000905E0:
	{ sub	r19,r34,r34,0x1; cmp.eq	p06,p07,0x0,r8; adds	r15,0x0,r34 }
	{ adds	r16,0x0,r33; adds	r17,0x1,r34; add	r18,r19,r8; }
	{ nop.m	0x0; mov.i	LC,r18; (p07) mov.i	LC,r18; }

l4000000000090610:
	{ nop.m	0x0; (p06) mov.i	LC,0x0; br.cond.sptk.few	40000000000903C0 }

l400000000009061C:
	{ (p45) nop; Invalid; break.b	0x1000 }

l4000000000090620:
	{ st1	[r33],r1,1; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r43; cmp.ltu	p07,p06,0x1,r8; (p07) br.cond.dptk.few	4000000000090330 }

l4000000000090640:
	{ ld1	r14,[r34],1; st1	[r33],r1,1; nop.i	0x0; }
	{ nop.m	0x0; ld1	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; br.cond.sptk.few	40000000000902A0 }

l4000000000090670:
	{ add	r46,r8,r8,0x1; adds	r36,0x0,r0; adds	r33,0x0,r0 }
	{ adds	r35,0x0,r0; adds	r34,0x0,r32; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r43; ld1	r14,[r32]; cmp4.eq	p18,p19,0x0,r36 }
	{ cmp4.eq	p17,p16,0x0,r33; cmp4.eq	p21,p20,0x0,r35; addl	r38,1,r0; }
	{ addl	r36,-9996,r1; nop.m	0x0; adds	r39,0x0,r8 }
	{ adds	r33,0x0,r8; nop.m	0x0; sxt1	r14,r14; }
	{ ld8	r36,[r36]; nop.i	0x0; br.cond.sptk.few	40000000000902A0 }

l40000000000906E0:
	{ cmp.eq	p06,p07,0x0,r8; (p07) ld1	r14,[r34]; nop.i	0x0; }

l40000000000906EC:
	{ Invalid; cmp4.eq.and	p00,p32,r32,r0; (p01) mov	pr,r3,0x80 }
	{ (p36) cmp.lt.unc	p63,p09,r127,r36; Invalid; break.b	0x1000 }

l4000000000090700:
	{ ld1	r14,[r34]; nop.m	0x0; addl	r8,1,r0; }
	{ nop.m	0x0; sxt1	r14,r14; br.cond.sptk.few	40000000000905E0; }
4000000000090720 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000090730 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; dequote_escapes: 4000000000090740
;;   Called from:
;;     400000000009206C (in remove_quoted_escapes)
;;     40000000000BAE9C (in array_dequote_escapes)
;;     40000000000C2D1C (in assoc_dequote_escapes)
dequote_escapes proc
	{ alloc	r41,ar.pfs,0x11,0x0,0xD; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r43,pr }
	{ cmp.eq	p06,p07,0x0,r32; adds	r42,0x0,r1; adds	r45,0x0,r32; }
	{ adds	r37,0x18,r12; mov	r40,b0; mov	r44,LC }
	{ st8	[r0],r37; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000090A10; }

l4000000000090780:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r42; nop.m	0x0; add	r38,r32,r8 }
	{ adds	r45,0x1,r8; nop.m	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r42; adds	r39,0x0,r8; nop.i	0x0 }
	{ adds	r45,0x0,r32; addl	r46,1,r0; br.call.sptk.many	b0,fn400000000001B680; }
	{ adds	r1,0x0,r42; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	4000000000090BF0; }

l40000000000907E0:
	{ addl	r14,9092,r1; nop.m	0x0; nop.i	0x0; }
	{ ld8	r14,[r14]; cmp.eq	p06,p07,0x0,r14; nop.i	0x0; }
	{ (p06) adds	r15,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000090840; }

l4000000000090806:
	{ chk.a.nc	r0,3FFFFFFFFF091006; nop; break.i	0x80000 }

l4000000000090810:
	{ nop.m	0x0; ld1	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; cmp4.eq	p06,p07,0x0,r15; }
	{ (p06) addl	r15,1,r0; nop.i	0x0; (p07) adds	r15,0x0,r0; }

l4000000000090836:
	{ addp4	r0,0xFFFFFFFFFFFFE000,r1; (p07) nop; break.i	0x80000 }

l4000000000090840:
	{ nop.m	0x0; ld1	r14,[r32]; addl	r36,-9996,r1 }
	{ adds	r33,0x0,r39; adds	r34,0x0,r32; cmp4.eq	p16,p17,0x0,r15; }
	{ nop.m	0x0; ld8	r36,[r36]; sxt1	r14,r14; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000090880:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	4000000000090A00; }

l4000000000090890:
	{ adds	r35,0x1,r34; cmp4.eq	p07,p06,0x1,r14; (p06) br.cond.dptk.few	4000000000090900; }

l40000000000908A0:
	{ nop.m	0x0; ld1	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x1,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x7F,r14; (p06) br.cond.dptk.few	4000000000090B80 }

l40000000000908D0:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dptk.few	4000000000090900; }

l40000000000908E0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x20,r14; (p06) br.cond.dpnt.few	4000000000090BA0; }

l40000000000908F0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000090900:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ nop.m	0x0; ld1	r14,[r34]; cmp.ltu	p07,p06,0x1,r8 }
	{ adds	r1,0x0,r42; addl	r8,1,r0; (p06) br.cond.dpnt.few	4000000000090B50; }

l4000000000090930:
	{ nop.m	0x0; sxt1	r14,r14; extr.u	r15,r14,5,3 }
	{ and	r16,0x1F,r14; shladd	r15,r15,0x2,r36; nop.i	0x0; }
	{ ld4	r15,[r15]; nop.m	0x0; shr.u	r15,r15,r16; }
	{ nop.m	0x0; tbit.z	p07,p06,r15,0x0; (p07) br.cond.dpnt.few	4000000000090A90; }

l4000000000090970:
	{ sub	r18,r34,r34,0x1; cmp.eq	p06,p07,0x0,r8; adds	r15,0x0,r34 }
	{ adds	r16,0x0,r33; adds	r17,0x0,r35; add	r18,r18,r8; }
	{ nop.m	0x0; mov.i	LC,r18; nop.i	0x0; }
	{ nop.m	0x0; (p07) mov.i	LC,r18; (p06) mov.i	LC,0x0 }

l40000000000909AC:
	{ nop; zxt1	r0,r64; cmp.lt	p00,p00,r32,r0 }

l40000000000909B0:
	{ adds	r33,0x0,r16; nop.m	0x0; adds	r46,0x1,r15; }
	{ st1	[r33],r1,1; nop.m	0x0; adds	r15,0x0,r46; }
	{ nop.m	0x0; adds	r16,0x0,r33; br.cloop.sptk.few	4000000000090A40; }

l40000000000909E0:
	{ ld1	r14,[r46]; adds	r34,0x0,r46; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000090890 }

l4000000000090A00:
	{ nop.m	0x0; st1	[r0],r33; adds	r32,0x0,r39; }

l4000000000090A10:
	{ adds	r8,0x0,r32; mov	pr,r43,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.i	LC,r44; mov.spnt	b0,r40,4000000000090A20 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000090A40:
	{ ld1	r14,[r17],1; adds	r33,0x0,r16; adds	r46,0x1,r15; }
	{ nop.m	0x0; sxt1	r14,r14; adds	r15,0x0,r46; }
	{ nop.m	0x0; st1	[r33],r1,1; nop.i	0x0; }
	{ nop.m	0x0; adds	r16,0x0,r33; br.cloop.sptk.few	4000000000090A40 }

l4000000000090A80:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000909E0 }

l4000000000090A90:
	{ ld8	r14,[r37]; adds	r15,0x10,r12; adds	r45,0x0,r0 }
	{ adds	r46,0x0,r34; sub	r47,r38,r34; adds	r48,0x0,r37; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r18,0x10,r12; adds	r1,0x0,r42; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000090BB0; }

l4000000000090AE0:
	{ ld8	r14,[r18]; nop.m	0x0; addl	r8,1,r0; }
	{ nop.m	0x0; st8	[r14],r37; nop.i	0x0 }
	{ ld1	r14,[r34]; nop.i	0x0; sxt1	r14,r14 }

l4000000000090B10:
	{ sub	r18,r34,r34,0x1; cmp.eq	p06,p07,0x0,r8; adds	r15,0x0,r34 }
	{ adds	r16,0x0,r33; adds	r17,0x0,r35; add	r18,r18,r8; }
	{ nop.m	0x0; mov.i	LC,r18; (p07) mov.i	LC,r18; }

l4000000000090B40:
	{ nop.m	0x0; (p06) mov.i	LC,0x0; br.cond.sptk.few	40000000000909B0 }

l4000000000090B4C:
	{ (p51) nop; Invalid; br.cond.sptk.few	4000000000090D4C }

l4000000000090B50:
	{ st1	[r33],r1,1; nop.m	0x0; adds	r34,0x0,r35; }
	{ nop.m	0x0; ld1	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; br.cond.sptk.few	4000000000090880; }

l4000000000090B80:
	{ adds	r34,0x0,r35; cmp4.eq	p06,p07,0x0,r14; adds	r35,0x1,r35 }
	{ nop.b	0x0; (p06) br.cond.dpnt.few	4000000000090A00; br.cond.sptk.few	4000000000090900; }

l4000000000090B9C:
	{ (p43) ld4	r127,[r36]; (p04) nop; (p20) epc }

l4000000000090BA0:
	{ adds	r34,0x0,r35; adds	r35,0x1,r35; br.cond.sptk.few	4000000000090900 }

l4000000000090BB0:
	{ cmp.eq	p06,p07,0x0,r8; (p07) ld1	r14,[r34]; nop.i	0x0; }

l4000000000090BBC:
	{ Invalid; cmp4.eq.and	p00,p32,r32,r0; (p01) mov	pr,r3,0x80 }
	{ (p45) cmp.lt.unc	p63,p09,r127,r36; Invalid; break.b	0x1000 }

l4000000000090BD0:
	{ ld1	r14,[r34]; nop.m	0x0; addl	r8,1,r0; }
	{ nop.m	0x0; sxt1	r14,r14; br.cond.sptk.few	4000000000090B10 }

l4000000000090BF0:
	{ adds	r46,0x0,r32; adds	r45,0x0,r39; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r32,0x0,r8; nop.m	0x0; adds	r1,0x0,r42; }
	{ adds	r8,0x0,r32; mov	pr,r43,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.i	LC,r44; mov.spnt	b0,r40,4000000000090C20 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

;; quote_string: 4000000000090C40
;;   Called from:
;;     400000000009102C (in fn4000000000090FC0)
;;     400000000009DAEC (in fn400000000009A180)
;;     40000000000A356C (in fn40000000000A1400)
;;     40000000000A41FC (in fn40000000000A1400)
;;     40000000000BAA1C (in array_quote)
;;     40000000000BD50C (in array_to_string)
;;     40000000000C1C0C (in fn40000000000C14C0)
;;     40000000000C211C (in array_keys)
;;     40000000000C289C (in assoc_quote)
;;     40000000000C3BAC (in assoc_to_string)
quote_string proc
	{ alloc	r40,ar.pfs,0xF,0x0,0xB; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ addl	r36,-9996,r1; ld1	r14,[r32]; mov	r39,b7; }
	{ adds	r41,0x0,r1; adds	r37,0x18,r12; sxt1	r14,r14 }
	{ adds	r43,0x0,r32; ld8	r36,[r36]; addl	r35,1,r0; }
	{ cmp4.eq	p07,p06,0x0,r14; mov	r42,LC; (p07) br.cond.dpnt.few	4000000000090F10; }

l4000000000090C90:
	{ st8	[r0],r37; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r41; nop.m	0x0; add	r34,r32,r8 }
	{ add	r43,r8,r8,0x1; nop.m	0x0; br.call.sptk.many	b0,xmalloc; }
	{ cmp.ltu	p07,p06,r32,r34; nop.m	0x0; adds	r33,0x0,r8 }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r38,0x0,r8; }
	{ nop.m	0x0; (p06) adds	r33,0x0,r8; (p06) br.cond.dpnt.few	4000000000090E00; }

l4000000000090CEC:
	{ (p09) nop; break.i	0x1000; break.i	0x1000 }

l4000000000090CF0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000090D00:
	{ st1	[r35],r33; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r41; nop.m	0x0; cmp.ltu	p07,p06,0x1,r8 }
	{ addl	r8,1,r0; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000090EE0; }

l4000000000090D30:
	{ ld1	r14,[r32]; adds	r33,0x1,r33; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r18,r14,5,3; and	r17,0x1F,r14; }
	{ shladd	r14,r18,0x2,r36; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r17; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x0; (p07) br.cond.dpnt.few	4000000000090E30; }

l4000000000090D80:
	{ sub	r17,r32,r32,0x1; nop.m	0x0; cmp.eq	p06,p07,0x0,r8 }
	{ adds	r14,0x0,r32; adds	r15,0x0,r33; add	r16,r17,r8; }
	{ nop.m	0x0; mov.i	LC,r16; nop.i	0x0; }
	{ nop.m	0x0; (p07) mov.i	LC,r16; (p06) mov.i	LC,0x0; }

l4000000000090DBC:
	{ loadrs; (p18) nop; Invalid }

l4000000000090DC0:
	{ ld1	r16,[r14],1; st1	[r15],r1,1; adds	r32,0x0,r14 }
	{ nop.m	0x0; nop.m	0x0; br.cloop.sptk.few	4000000000090DC0; }

l4000000000090DE0:
	{ adds	r33,0x0,r15; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; cmp.ltu	p06,p07,r32,r34; (p06) br.cond.dptk.few	4000000000090D00; }

l4000000000090E00:
	{ adds	r8,0x0,r38; st1	[r0],r33; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.i	LC,r42; mov.spnt	b0,r39,4000000000090E10 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l4000000000090E30:
	{ ld8	r14,[r37]; adds	r15,0x10,r12; adds	r43,0x0,r0 }
	{ adds	r44,0x0,r32; sub	r45,r34,r32; adds	r46,0x0,r37; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r16,0x10,r12; adds	r1,0x0,r41; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000090F70; }

l4000000000090E80:
	{ ld8	r14,[r16]; nop.m	0x0; addl	r8,1,r0; }
	{ st8	[r14],r37; nop.m	0x0; nop.i	0x0 }

l4000000000090EA0:
	{ sub	r17,r32,r32,0x1; nop.m	0x0; cmp.eq	p06,p07,0x0,r8 }
	{ adds	r14,0x0,r32; adds	r15,0x0,r33; add	r16,r17,r8; }
	{ nop.m	0x0; mov.i	LC,r16; (p07) mov.i	LC,r16; }

l4000000000090ED0:
	{ nop.m	0x0; (p06) mov.i	LC,0x0; br.cond.sptk.few	4000000000090DC0 }

l4000000000090EDC:
	{ (p55) cmp.lt.unc	p63,p09,r63,r36; (p17) cmp.eq	p00,p10,r8,r0; (p17) brp.sptk	b0,40000000000910DC }

l4000000000090EE0:
	{ ld1	r14,[r32],1; adds	r15,0x1,r33; adds	r33,0x2,r33; }
	{ st1	[r14],r15; cmp.ltu	p06,p07,r32,r34; (p06) br.cond.dptk.few	4000000000090D00 }

l4000000000090F00:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000090E00 }

l4000000000090F10:
	{ addl	r43,2,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ addl	r15,127,r0; adds	r14,0x0,r8; adds	r38,0x0,r8 }
	{ adds	r1,0x0,r41; st1	[r14],r1,1; adds	r8,0x0,r38; }
	{ st1	[r0],r14; mov.i	ar.pfs,r40; mov.i	LC,r42; }
	{ nop.m	0x0; mov.spnt	b0,r39,4000000000090F50; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l4000000000090F70:
	{ cmp.eq	p06,p07,0x0,r8; nop.i	0x0; (p07) br.cond.spnt.few	4000000000090D80; }

l4000000000090F80:
	{ nop.m	0x0; addl	r8,1,r0; br.cond.sptk.few	4000000000090EA0; }
4000000000090F90 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000090FA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000090FB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000090FC0: 4000000000090FC0
;;   Called from:
;;     400000000009133C (in string_list_dollar_at)
;;     40000000000934FC (in string_list_pos_params)
;;     400000000009353C (in string_list_pos_params)
;;     400000000009358C (in string_list_pos_params)
fn4000000000090FC0 proc
	{ alloc	r39,ar.pfs,0xA,0x0,0x9; adds	r40,0x0,r1; nop.b	0x0 }
	{ adds	r33,0x0,r32; mov	r38,b6; cmp.eq	p07,p06,0x0,r32; }
	{ nop.m	0x0; addl	r37,262144,r0; (p07) br.cond.dpnt.few	40000000000910E0; }

l4000000000090FF0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000091000:
	{ adds	r35,0x8,r33; ld8	r36,[r35]; nop.i	0x0; }
	{ nop.m	0x0; ld8	r34,[r36]; nop.i	0x0; }
	{ adds	r41,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,quote_string; }
	{ ld1.a	r14,[r34]; st8	[r8],r36; adds	r1,0x0,r40 }
	{ adds	r41,0x0,r34; ld1.c.clr	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x0,r14; }
	{ (p07) ld8	r14,[r35]; (p07) adds	r14,0x8,r14; nop.i	0x0; }

l4000000000091066:
	{ Invalid; cmp4.ltu	p00,p00,0x0,r1; (p49) cmp.ltu	p03,p04,r64,r3; }

l400000000009106C:
	{ cmp4.eq.or.andcm	p00,p43,r1,r0; (p01) cmp4.ne.or.andcm	p00,p40,r3,r4; zxt1	r105,r3 }

l4000000000091076:
	{ Invalid; cmp4.ltu	p00,p00,r0,r1; (p01) br.call.spnt.many	b0,b3; }

l400000000009107C:
	{ Invalid; (p48) cmp.lt.unc	p03,p08,r3,r100; Invalid }

l4000000000091086:
	{ (p07) fwb; nop; (p32) nop }
	{ (p07) fwb; nop; break.b	0x80000 }
	{ Invalid; nop; br.call.spnt.many	b0,b3 }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ add	r0,r0,r1; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD142E6; nop; nop.b	0x20002 }

l40000000000910E0:
	{ adds	r8,0x0,r32; nop.m	0x0; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000910F0; br.ret	b0; }

;; string_list_dollar_at: 4000000000091100
;;   Called from:
;;     40000000000935EC (in string_list_pos_params)
;;     40000000000C182C (in fn40000000000C14C0)
;;     40000000000C1FFC (in array_keys)
string_list_dollar_at proc
	{ alloc	r39,ar.pfs,0xD,0x0,0xA; adds	r40,0x0,r12; nop.b	0x0 }
	{ adds	r41,0x0,r1; nop.m	0x0; mov	r38,b6; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r41; adds	r8,0x10,r8; addl	r14,9076,r1 }
	{ and	r15,0xFFFFFFFFFFFFFFF0,r8; nop.m	0x0; sub	r12,r12,r15; }
	{ adds	r37,0x10,r12; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; adds	r14,0x8,r14; (p06) br.cond.dpnt.few	4000000000091300; }

l4000000000091170:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.spnt.few	4000000000091300; }

l4000000000091190:
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000091300 }

l40000000000911B0:
	{ addl	r14,9108,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld8	r34,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x1,r34; (p06) br.cond.dptk.few	4000000000091380 }

l40000000000911E0:
	{ addl	r14,23524,r1; nop.m	0x0; adds	r15,0x11,r12; }
	{ nop.m	0x0; ld1	r14,[r14]; nop.i	0x0; }
	{ st1	[r14],r37; st1	[r0],r15; nop.i	0x0 }

l4000000000091210:
	{ nop.m	0x0; and	r33,0xB,r33; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r33; (p06) br.cond.dpnt.few	4000000000091330; }

l4000000000091230:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p07) br.cond.dpnt.few	40000000000912D0; }

l4000000000091240:
	{ (p06) adds	r34,0x0,r32; nop.m	0x0; nop.i	0x0; }

l4000000000091246:
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ break.m	0x4000; nop; (p32) nop }

l4000000000091260:
	{ adds	r14,0x8,r34; ld8	r35,[r14]; nop.i	0x0; }

l4000000000091262:
	{ (p33) srlz.d; (p32) break.i	0x20303; Invalid }
	{ Invalid; (p48) break.i	0x20308; tbit.z	p32,p04,r32,0x0 }
	{ break.m	0x42009; nop; Invalid; }
	{ (p16) break.m	0x4200A; mov	pr,0xC000020; Invalid }
	{ (p49) break.m	0x23308; addl	r32,0,r0; (p42) nop }
	{ (p32) break.m	0x20308; zxt1	r32,r0; Invalid; }
	{ Invalid; (p32) dep	r72,r65,r92,63,2; (p63) tbit.z.unc	p63,p04,r41,0x17 }

l40000000000912D0:
	{ adds	r42,0x0,r32; adds	r43,0x0,r37; br.call.sptk.many	b0,string_list_internal; }
	{ adds	r1,0x0,r41; mov.i	ar.pfs,r39; mov.spnt	b0,r38,40000000000912E0 }
	{ nop.m	0x0; adds	r12,0x0,r40; br.ret	b0 }

l4000000000091300:
	{ adds	r14,0x0,r37; addl	r15,32,r0; and	r33,0xB,r33; }
	{ st1	[r14],r1,1; nop.m	0x0; cmp4.eq	p07,p06,0x0,r33; }
	{ st1	[r0],r14; nop.i	0x0; (p07) br.cond.dptk.few	4000000000091230 }

l4000000000091330:
	{ adds	r42,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn4000000000090FC0; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r42,0x0,r8 }
	{ adds	r43,0x0,r37; nop.m	0x0; br.call.sptk.many	b0,string_list_internal; }
	{ adds	r1,0x0,r41; mov.i	ar.pfs,r39; mov.spnt	b0,r38,4000000000091360 }
	{ nop.m	0x0; adds	r12,0x0,r40; br.ret	b0 }

l4000000000091380:
	{ addl	r43,23524,r1; nop.m	0x0; adds	r44,0x0,r34 }
	{ adds	r42,0x0,r37; nop.m	0x0; add	r34,r37,r34; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ nop.m	0x0; adds	r1,0x0,r41; nop.i	0x0 }
	{ st1	[r0],r34; nop.m	0x0; br.cond.sptk.few	4000000000091210; }
40000000000913D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000913E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000913F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; dequote_string: 4000000000091400
;;   Called from:
;;     40000000000278AC (in decode_prompt_string)
;;     4000000000091EDC (in dequote_list)
;;     40000000000A5FBC (in fn40000000000A5B80)
;;     40000000000A639C (in fn40000000000A5B80)
;;     40000000000A807C (in fn40000000000A7940)
;;     40000000000A8BDC (in fn40000000000A7940)
;;     40000000000BAD1C (in array_dequote)
;;     40000000000C2B9C (in assoc_dequote)
;;     4000000000107A8C (in read_builtin)
;;     40000000001080DC (in read_builtin)
;;     400000000010829C (in read_builtin)
dequote_string proc
	{ alloc	r41,ar.pfs,0x10,0x0,0xC; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ addl	r36,-9996,r1; adds	r42,0x0,r1; mov	r40,b0; }
	{ adds	r37,0x18,r12; ld8	r36,[r36]; nop.b	0x0 }
	{ adds	r44,0x0,r32; mov	r43,LC; adds	r34,0x0,r32; }
	{ st8	[r0],r37; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r42; nop.m	0x0; adds	r44,0x1,r8 }
	{ add	r39,r32,r8; nop.m	0x0; br.call.sptk.many	b0,xmalloc; }
	{ ld1	r14,[r32]; adds	r1,0x0,r42; adds	r38,0x0,r8 }
	{ adds	r44,0x0,r32; addl	r45,1,r0; adds	r33,0x0,r8; }
	{ nop.m	0x0; sxt1	r35,r14; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x7F,r35; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000917D0; }

l40000000000914B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B680; }
	{ adds	r1,0x0,r42; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	4000000000091860; }

l40000000000914D0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000914E0:
	{ adds	r14,0x1,r34; cmp4.eq	p07,p06,0x0,r35; (p07) br.cond.dpnt.few	4000000000091650; }

l40000000000914F0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x1,r35; (p06) br.cond.dptk.few	4000000000091520 }

l4000000000091500:
	{ ld1	r15,[r14]; adds	r34,0x0,r14; sxt1	r14,r15; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	4000000000091650 }

l4000000000091520:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r42; nop.m	0x0; cmp.ltu	p07,p06,0x1,r8 }
	{ addl	r8,1,r0; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000917A0; }

l4000000000091550:
	{ ld1	r14,[r34]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r15,r14,5,3; and	r16,0x1F,r14; }
	{ shladd	r15,r15,0x2,r36; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r15,r15,r16; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r15,0x0; (p07) br.cond.dpnt.few	40000000000916E0; }

l40000000000915A0:
	{ sub	r19,r34,r34,0x1; cmp.eq	p06,p07,0x0,r8; adds	r15,0x0,r34 }
	{ adds	r16,0x0,r33; adds	r17,0x1,r34; add	r18,r19,r8; }
	{ nop.m	0x0; mov.i	LC,r18; nop.i	0x0; }
	{ nop.m	0x0; (p07) mov.i	LC,r18; (p06) mov.i	LC,0x0 }

l40000000000915DC:
	{ nop; zxt1	r0,r64; nop }

l40000000000915E0:
	{ adds	r33,0x0,r16; nop.m	0x0; adds	r45,0x1,r15; }
	{ st1	[r33],r1,1; nop.m	0x0; adds	r15,0x0,r45; }
	{ nop.m	0x0; adds	r16,0x0,r33; br.cloop.sptk.few	4000000000091690; }

l4000000000091610:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000091620:
	{ ld1	r35,[r45]; nop.m	0x0; adds	r34,0x0,r45; }
	{ nop.m	0x0; sxt1	r35,r35; adds	r14,0x1,r34; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	40000000000914F0 }

l4000000000091650:
	{ st1	[r0],r33; nop.m	0x0; nop.i	0x0 }

l4000000000091660:
	{ adds	r8,0x0,r38; mov.i	ar.pfs,r41; mov.i	LC,r43; }
	{ nop.m	0x0; mov.spnt	b0,r40,4000000000091670; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l4000000000091690:
	{ ld1	r14,[r17],1; adds	r33,0x0,r16; adds	r45,0x1,r15; }
	{ nop.m	0x0; sxt1	r14,r14; adds	r15,0x0,r45; }
	{ nop.m	0x0; st1	[r33],r1,1; nop.i	0x0; }
	{ nop.m	0x0; adds	r16,0x0,r33; br.cloop.sptk.few	4000000000091690 }

l40000000000916D0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000091620 }

l40000000000916E0:
	{ ld8	r14,[r37]; adds	r15,0x10,r12; adds	r44,0x0,r0 }
	{ adds	r45,0x0,r34; sub	r46,r39,r34; adds	r47,0x0,r37; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r18,0x10,r12; adds	r1,0x0,r42; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000091820; }

l4000000000091730:
	{ ld8	r14,[r18]; nop.m	0x0; addl	r8,1,r0; }
	{ nop.m	0x0; st8	[r14],r37; nop.i	0x0 }
	{ ld1	r14,[r34]; nop.i	0x0; sxt1	r14,r14 }

l4000000000091760:
	{ sub	r19,r34,r34,0x1; cmp.eq	p06,p07,0x0,r8; adds	r15,0x0,r34 }
	{ adds	r16,0x0,r33; adds	r17,0x1,r34; add	r18,r19,r8; }
	{ nop.m	0x0; mov.i	LC,r18; (p07) mov.i	LC,r18; }

l4000000000091790:
	{ nop.m	0x0; (p06) mov.i	LC,0x0; br.cond.sptk.few	40000000000915E0 }

l400000000009179C:
	{ (p50) cmp.lt.unc	p63,p10,r63,r36; (p17) nop; (p04) rfi }

l40000000000917A0:
	{ ld1	r14,[r34],1; ld1.a	r35,[r34]; nop.i	0x0 }
	{ st1	[r33],r1,1; ld1.c.clr	r35,[r34]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r35,r35; br.cond.sptk.few	40000000000914E0 }

l40000000000917D0:
	{ adds	r14,0x1,r32; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x0,r14; }
	{ (p07) st1	[r0],r8; (p07) br.cond.dpnt.few	4000000000091660; br.call.sptk.many	b0,fn400000000001B680; }

l40000000000917F6:
	{ rum	0x5FFFE7; (p32) nop; (p16) nop; }

l40000000000917FC:
	{ (p52) nop; cmp.eq.unc	p00,p16,r10,r64; nop }
	{ Invalid; break.i	0x1000; break.i	0x1000 }

l4000000000091810:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000091860; }

l4000000000091820:
	{ cmp.eq	p06,p07,0x0,r8; (p07) ld1	r14,[r34]; nop.i	0x0; }

l400000000009182C:
	{ Invalid; cmp4.eq.and	p00,p32,r32,r0; (p01) mov	pr,r3,0x80 }
	{ (p43) cmp.lt.unc	p63,p09,r127,r36; Invalid; break.b	0x1000 }

l4000000000091840:
	{ ld1	r14,[r34]; nop.m	0x0; addl	r8,1,r0; }
	{ nop.m	0x0; sxt1	r14,r14; br.cond.sptk.few	4000000000091760 }

l4000000000091860:
	{ adds	r44,0x0,r38; adds	r45,0x0,r32; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r38,0x0,r8; nop.m	0x0; adds	r1,0x0,r42; }
	{ adds	r8,0x0,r38; mov.i	ar.pfs,r41; mov.i	LC,r43; }
	{ nop.m	0x0; mov.spnt	b0,r40,4000000000091890; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0; }
40000000000918B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000918C0 18 50 45 18 80 05 C0 80 33 7E 46 00 00 00 00 20 .PE.....3~F.... 
40000000000918D0 01 78 00 40 00 10 90 02 00 62 00 60 05 08 00 84 .x.@.....b.`....
40000000000918E0 01 00 00 00 01 00 F0 00 3C 28 00 00 00 00 04 00 ........<(......
40000000000918F0 03 40 A8 1E 89 39 60 00 3E 0E 73 C4 11 00 00 90 .@...9`.>.s.....
4000000000091900 09 00 00 00 01 40 E2 00 00 00 42 00 00 00 04 00 .....@....B.....
4000000000091910 10 38 01 1C 00 21 60 04 38 8E F2 03 F0 01 00 42 .8...!`.8......B
4000000000091920 0B 70 04 40 00 21 E0 00 38 00 20 00 00 00 04 00 .p.@.!..8. .....
4000000000091930 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
4000000000091940 11 00 00 00 01 00 60 00 38 0E F3 03 C0 01 00 42 ......`.8......B
4000000000091950 08 00 00 00 01 00 70 00 9C 0C 73 80 05 00 01 84 ......p...s.....
4000000000091960 0B 00 00 4A 98 91 71 0A 00 02 48 00 00 00 04 00 ...J..q...H.....
4000000000091970 F1 38 05 00 00 24 00 00 00 02 00 00 58 E3 02 50 .8...$......X..P
4000000000091980 08 00 00 00 01 00 10 00 AC 00 42 80 05 00 01 84 ..........B.....
4000000000091990 18 00 00 00 01 00 60 00 20 0E 73 03 B0 01 00 42 ......`. .s....B
40000000000919A0 11 70 01 00 00 21 D0 C2 30 00 42 00 28 FA 02 50 .p...!..0.B.(..P
40000000000919B0 04 00 00 00 01 00 00 00 00 00 00 C0 01 00 00 68 ...............h
40000000000919C0 03 08 00 56 00 21 80 02 20 00 42 C0 E0 10 1D E0 ...V.!.. .B.....
40000000000919D0 D1 10 01 00 00 21 00 00 00 02 00 03 20 00 00 43 .....!...... ..C
40000000000919E0 02 00 00 00 01 00 60 20 90 0E 28 43 04 00 00 84 ......` ..(C....
40000000000919F0 09 70 40 18 00 21 00 00 00 02 00 C0 00 40 1D E4 .p@..!.......@..
4000000000091A00 11 00 88 1C 98 11 E0 40 A1 00 42 03 10 03 00 43 .......@..B....C
4000000000091A10 0B 70 00 1C 18 10 E0 20 3A 58 40 00 00 00 04 00 .p..... :X@.....
4000000000091A20 11 30 00 1C 07 39 E0 C0 30 00 42 03 90 02 00 42 .0...9..0.B....B
4000000000091A30 0B 80 00 1C 18 10 F0 00 40 00 20 00 12 80 00 84 ........@. .....
4000000000091A40 01 00 00 00 01 00 F0 00 3C 28 00 00 00 00 04 00 ........<(......
4000000000091A50 03 40 A8 1E 89 39 60 00 3E 0E 73 C4 11 00 00 90 .@...9`.>.s.....
4000000000091A60 09 00 00 00 01 40 E2 00 00 00 42 00 00 00 04 00 .....@....B.....
4000000000091A70 11 30 02 1C 47 39 70 02 38 00 C2 03 30 00 00 43 .0..G9p.8...0..C
4000000000091A80 0B 70 00 20 00 10 00 00 00 02 00 C0 01 70 50 00 .p. .........pP.
4000000000091A90 10 00 00 00 01 00 70 E8 3A 0C F3 03 90 03 00 43 ......p.:......C
4000000000091AA0 08 60 01 40 00 21 D0 0A 00 00 48 C0 05 20 01 84 .`.@.!....H.. ..
4000000000091AB0 19 78 01 00 00 21 00 83 30 00 42 00 D8 02 03 50 .x...!..0.B....P
4000000000091AC0 08 38 0D 00 00 24 00 40 98 30 23 00 00 00 04 00 .8...$.@.0#.....
4000000000091AD0 09 08 00 56 00 21 00 40 95 30 23 00 00 00 04 00 ...V.!.@.0#.....
4000000000091AE0 02 40 00 4E 00 21 00 50 01 55 00 00 90 0A 00 07 .@.N.!.P.U......
4000000000091AF0 19 00 00 00 01 00 C0 80 30 00 42 80 08 00 84 00 ........0.B.....
4000000000091B00 08 60 01 40 00 21 00 00 94 30 23 E0 04 00 00 84 .`.@.!...0#.....
4000000000091B10 19 00 00 00 01 00 00 00 00 02 00 00 B8 E1 02 50 ...............P
4000000000091B20 08 00 00 00 01 00 10 00 AC 00 42 80 05 00 01 84 ..........B.....
4000000000091B30 18 00 00 00 01 00 60 00 20 0E F3 03 70 FE FF 4A ......`. ...p..J
4000000000091B40 11 00 00 00 01 00 00 00 00 02 00 00 08 0A FD 58 ...............X
4000000000091B50 11 08 00 56 00 21 60 00 20 0E 72 03 C0 00 00 43 ...V.!`. .r....C
4000000000091B60 0B 70 A0 10 00 21 F0 00 38 20 20 00 00 00 04 00 .p...!..8  .....
4000000000091B70 10 00 00 00 01 00 70 C0 3C 0C 28 03 A0 00 00 42 ......p.<.(....B
4000000000091B80 0B 70 00 1C 18 10 E0 20 3A 58 40 00 00 00 04 00 .p..... :X@.....
4000000000091B90 11 30 00 1C 07 39 00 00 00 02 00 03 80 00 00 43 .0...9.........C
4000000000091BA0 08 00 00 00 01 00 00 40 94 30 23 C0 C0 78 1C 50 .......@.0#..x.P
4000000000091BB0 19 00 00 00 01 00 80 40 20 00 42 03 30 02 00 42 .......@ .B.0..B
4000000000091BC0 09 68 F1 FA CB 27 C0 02 20 30 20 E0 34 00 00 90 .h...'.. 0 .4...
4000000000091BD0 11 68 01 5A 18 10 00 00 00 02 00 00 38 0B 03 50 .h.Z........8..P
4000000000091BE0 08 08 00 56 00 21 00 40 98 30 23 00 00 00 04 00 ...V.!.@.0#.....
4000000000091BF0 02 40 00 4E 00 21 00 50 01 55 00 00 90 0A 00 07 .@.N.!.P.U......
4000000000091C00 18 00 00 00 01 00 C0 80 30 00 42 80 08 00 84 00 ........0.B.....
4000000000091C10 02 30 00 4E 87 39 90 00 84 10 72 E3 11 00 00 90 .0.N.9....r.....
4000000000091C20 0B 71 04 00 00 E4 F1 00 00 00 C2 C4 01 00 00 84 .q..............
4000000000091C30 0B 70 38 1E 0C 20 60 00 38 0E 73 00 00 00 04 00 .p8.. `.8.s.....
4000000000091C40 D0 00 84 4C 98 11 00 00 00 02 00 03 A0 FE FF 4A ...L...........J
4000000000091C50 09 18 0D 46 2C 20 C0 02 84 00 42 E0 04 00 00 84 ...F, ....B.....
4000000000091C60 10 00 00 00 01 00 60 00 8C 0E 73 03 40 01 00 42 ......`...s.@..B
4000000000091C70 11 00 00 00 01 00 00 00 00 02 00 00 98 F7 FF 58 ...............X
4000000000091C80 18 08 00 56 00 21 00 40 98 30 23 00 00 00 00 20 ...V.!.@.0#.... 
4000000000091C90 02 40 00 4E 00 21 00 50 01 55 00 00 90 0A 00 07 .@.N.!.P.U......
4000000000091CA0 18 00 00 00 01 00 C0 80 30 00 42 80 08 00 84 00 ........0.B.....
4000000000091CB0 0B 78 00 1C 18 10 E0 00 3C 00 20 00 00 00 04 00 .x......<. .....
4000000000091CC0 03 00 00 00 01 00 E0 00 38 28 00 E0 A0 72 18 E6 ........8(...r..
4000000000091CD0 10 00 00 00 01 00 70 00 3A 8C 73 03 40 00 00 42 ......p.:.s.@..B
4000000000091CE0 0B 78 04 1E 00 21 E0 00 3C 00 20 00 00 00 04 00 .x...!..<. .....
4000000000091CF0 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
4000000000091D00 10 00 00 00 01 00 70 E8 3A 0C F3 03 70 00 00 43 ......p.:...p..C
4000000000091D10 08 00 A0 4A 98 11 C0 02 80 00 42 A0 15 00 00 90 ...J......B.....
4000000000091D20 09 70 01 48 00 21 F0 02 00 00 42 00 06 61 00 84 .p.H.!....B..a..
4000000000091D30 11 38 0D 00 00 24 00 00 00 02 00 00 58 00 03 50 .8...$......X..P
4000000000091D40 18 08 00 56 00 21 00 40 98 30 23 00 00 00 00 20 ...V.!.@.0#.... 
4000000000091D50 02 40 00 4E 00 21 00 50 01 55 00 00 90 0A 00 07 .@.N.!.P.U......
4000000000091D60 18 00 00 00 01 00 C0 80 30 00 42 80 08 00 84 00 ........0.B.....
4000000000091D70 08 18 0D 46 2C 20 00 40 95 30 23 80 05 08 01 84 ...F, .@.0#.....
4000000000091D80 09 00 00 00 01 00 70 02 00 00 42 00 00 00 04 00 ......p...B.....
4000000000091D90 11 00 00 00 01 00 60 00 8C 0E F3 03 E0 FE FF 4A ......`........J
4000000000091DA0 11 00 00 00 01 00 00 00 00 02 00 00 A8 E9 FF 58 ...............X
4000000000091DB0 18 08 00 56 00 21 00 40 98 30 23 00 00 00 00 20 ...V.!.@.0#.... 
4000000000091DC0 02 40 00 4E 00 21 00 50 01 55 00 00 90 0A 00 07 .@.N.!.P.U......
4000000000091DD0 19 00 00 00 01 00 C0 80 30 00 42 80 08 00 84 00 ........0.B.....
4000000000091DE0 08 68 01 00 00 21 C0 02 20 30 20 E0 34 00 00 90 .h...!.. 0 .4...
4000000000091DF0 19 00 00 00 01 00 00 00 00 02 00 00 98 A5 02 50 ...............P
4000000000091E00 08 00 00 00 01 00 10 00 AC 00 42 00 00 00 04 00 ..........B.....
4000000000091E10 18 00 20 4C 98 11 00 00 00 02 00 00 E0 FD FF 48 .. L...........H
4000000000091E20 09 70 20 50 00 21 00 00 00 02 00 E0 00 38 19 E6 .p P.!.......8..
4000000000091E30 09 70 00 1C 18 10 00 00 00 02 00 E3 24 00 04 90 .p..........$...
4000000000091E40 08 00 00 00 01 00 00 70 98 30 A3 E3 24 00 00 90 .......p.0..$...
4000000000091E50 19 00 00 00 01 00 00 40 95 30 23 00 90 FC FF 48 .......@.0#....H
4000000000091E60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000091E70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; dequote_list: 4000000000091E80
;;   Called from:
;;     400000000009A15C (in expand_string)
;;     40000000000A4B7C (in fn40000000000A1400)
;;     40000000000A5AAC (in expand_prompt_string)
;;     40000000000A66BC (in cond_expand_word)
;;     40000000000A68AC (in expand_string_assignment)
;;     40000000000A6CBC (in expand_string_unsplit)
;;     40000000000A6ECC (in expand_word_unsplit)
;;     40000000000A878C (in fn40000000000A7940)
;;     40000000000A906C (in expand_word)
;;     400000000010554C (in read_builtin)
dequote_list proc
	{ alloc	r38,ar.pfs,0x9,0x0,0x8; adds	r39,0x0,r1; nop.b	0x0 }
	{ adds	r33,0x0,r32; mov	r37,b5; cmp.eq	p07,p06,0x0,r32; }
	{ nop.m	0x0; addl	r36,-262145,r0; (p07) br.cond.dpnt.few	4000000000091F60; }

l4000000000091EB0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000091EC0:
	{ adds	r34,0x8,r33; ld8	r14,[r34]; nop.i	0x0; }
	{ ld8	r40,[r14]; nop.i	0x0; br.call.sptk.many	b0,dequote_string; }
	{ ld8	r15,[r34]; adds	r1,0x0,r39; adds	r35,0x0,r8; }
	{ ld8	r14,[r15]; adds	r40,0x0,r14; nop.i	0x0; }
	{ ld1	r16,[r14]; nop.m	0x0; sxt1	r16,r16; }
	{ cmp4.eq	p07,p06,0x7F,r16; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000091F80; }

l4000000000091F20:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; ld8	r14,[r34]; adds	r1,0x0,r39 }
	{ ld8	r33,[r33]; cmp.eq	p07,p06,0x0,r33; nop.i	0x0; }
	{ st8	[r35],r14; nop.i	0x0; (p06) br.cond.dptk.few	4000000000091EC0 }

l4000000000091F60:
	{ adds	r8,0x0,r32; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,4000000000091F70; br.ret	b0 }

l4000000000091F80:
	{ adds	r14,0x1,r14; nop.m	0x0; adds	r15,0x8,r15; }
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x0,r14; (p07) ld4	r14,[r15]; nop.i	0x0; }

l4000000000091FAC:
	{ nop; cmp4.eq.and	p00,p32,r32,r0; zxt1	r73,r3 }

l4000000000091FBC:
	{ Invalid; Invalid; break.i	0x1000 }

l4000000000091FC6:
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; nop; (p16) nop }
	{ Invalid; nop; br.call.spnt.many	b0,b0 }
	{ chk.a.nc	r0,3FFFFFFFFF0927F6; nop; break.i	0x80000 }

l4000000000092000:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000091F60; }
4000000000092010 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000092020 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000092030 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; remove_quoted_escapes: 4000000000092040
;;   Called from:
;;     400000000004B63C (in named_function_string)
;;     4000000000094C0C (in command_substitute)
;;     40000000000A41EC (in fn40000000000A1400)
remove_quoted_escapes proc
	{ alloc	r35,ar.pfs,0x7,0x0,0x5; cmp.eq	p06,p07,0x0,r32; mov	r34,b2 }
	{ adds	r36,0x0,r1; adds	r37,0x0,r32; (p06) br.cond.dpnt.few	40000000000920C0; }

l4000000000092060:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,dequote_escapes; }
	{ adds	r1,0x0,r36; adds	r33,0x0,r8; nop.i	0x0 }
	{ adds	r37,0x0,r32; adds	r38,0x0,r8; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; adds	r1,0x0,r36; adds	r37,0x0,r33 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r36; nop.m	0x0; nop.i	0x0 }

l40000000000920C0:
	{ adds	r8,0x0,r32; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000920D0; br.ret	b0; }
40000000000920E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000920F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; remove_quoted_nulls: 4000000000092100
;;   Called from:
;;     400000000009312C (in list_string)
;;     400000000009312C (in list_string)
;;     400000000009339C (in word_list_remove_quoted_nulls)
;;     40000000000A5A5C (in expand_prompt_string)
;;     40000000000A685C (in expand_string_assignment)
;;     40000000000A6C6C (in expand_string_unsplit)
;;     40000000000BB01C (in array_remove_quoted_nulls)
;;     40000000000C2E9C (in assoc_remove_quoted_nulls)
remove_quoted_nulls proc
	{ alloc	r40,ar.pfs,0xF,0x0,0xB; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r39,b7 }
	{ adds	r41,0x0,r1; nop.m	0x0; adds	r43,0x0,r32; }
	{ adds	r38,0x18,r12; addl	r44,127,r0; nop.b	0x0 }
	{ adds	r33,0x0,r0; mov	r42,LC; adds	r35,0x0,r0; }
	{ st8	[r0],r38; sxt4	r34,r33; br.call.sptk.many	b0,fn400000000001B680; }
	{ adds	r1,0x0,r41; nop.m	0x0; cmp.eq	p06,p07,0x0,r8 }
	{ adds	r43,0x0,r32; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000923D0; }

l4000000000092170:
	{ nop.m	0x0; addl	r37,-9996,r1; nop.i	0x0; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r36,0x0,r8; nop.m	0x0; adds	r1,0x0,r41; }
	{ nop.m	0x0; cmp.ltu	p06,p07,r34,r36; (p07) br.cond.dpnt.few	40000000000923B0; }

l40000000000921B0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000921C0:
	{ add	r14,r32,r34; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x1,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000924B0; }

l40000000000921F0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x7F,r14; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r18,0x1,r33; (p07) br.cond.dpnt.few	4000000000092390 }

l400000000009220C:
	{ Invalid; break.i	0x1000; break.b	0x1000 }

l4000000000092210:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ add	r44,r32,r34; nop.m	0x0; adds	r1,0x0,r41 }
	{ cmp.ltu	p07,p06,0x1,r8; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000924A0; }

l4000000000092240:
	{ ld1	r14,[r44]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r37; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000092400; }

l4000000000092290:
	{ (p06) addl	r18,1,r0; nop.m	0x0; nop.i	0x0; }

l4000000000092296:
	{ break.m	0x4000; nop; (p32) nop }

l40000000000922A0:
	{ add	r18,r18,r33; nop.m	0x0; nop.i	0x0 }

l40000000000922B0:
	{ nop.m	0x0; cmp4.lt	p07,p06,r35,r33; nop.i	0x0; }
	{ nop.m	0x0; (p06) adds	r35,0x0,r18; (p06) br.cond.dptk.few	4000000000092390; }

l40000000000922CC:
	{ (p06) nop; (p50) nop; (p18) epc }

l40000000000922D0:
	{ andcm	r17,0xFFFFFFFFFFFFFFFF,r35; adds	r19,0x1,r33; sxt4	r16,r35 }
	{ adds	r14,0x0,r35; nop.m	0x0; add	r15,r32,r34; }
	{ sub	r17,r17,r33; nop.m	0x0; cmp4.lt	p08,p09,r18,r19 }
	{ add	r16,r32,r16; movl	r19,0x803FFFFF80000000; }
	{ add	r17,r17,r18; nop.m	0x0; cmp4.eq	p06,p07,r19,r18 }
	{ nop.b	0x0; (p08) br.cond.spnt.few	4000000000092510; (p06) br.cond.spnt.few	4000000000092510; }

l400000000009232C:
	{ (p15) nop; nop; (p18) epc }

l4000000000092330:
	{ nop.m	0x0; add	r17,r17,r35; nop.i	0x0; }
	{ addp4	r17,r17,r0; nop.i	0x0; mov.i	LC,r17; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000092360:
	{ ld1	r17,[r15],1; nop.m	0x0; adds	r14,0x1,r14; }
	{ st1	[r16],r1,1; nop.i	0x0; br.cloop.sptk.few	4000000000092360 }

l4000000000092380:
	{ adds	r35,0x0,r14; nop.m	0x0; nop.i	0x0 }

l4000000000092390:
	{ adds	r33,0x0,r18; nop.m	0x0; sxt4	r34,r33; }
	{ nop.m	0x0; cmp.ltu	p06,p07,r34,r36; (p06) br.cond.dptk.few	40000000000921C0 }

l40000000000923B0:
	{ nop.m	0x0; sxt4	r35,r35; add	r35,r32,r35 }
	{ nop.m	0x0; st1	[r0],r35; nop.i	0x0 }

l40000000000923D0:
	{ adds	r8,0x0,r32; mov.i	ar.pfs,r40; mov.i	LC,r42; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000923E0; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0; }

l4000000000092400:
	{ nop.m	0x0; ld8	r14,[r38]; adds	r15,0x10,r12 }
	{ adds	r43,0x0,r0; sub	r45,r36,r34; adds	r46,0x0,r38; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; nop.m	0x0; adds	r15,0x10,r12 }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r18,0x1,r33; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000092480; }

l4000000000092460:
	{ nop.m	0x0; ld8	r14,[r15]; nop.i	0x0; }
	{ st8	[r14],r38; nop.i	0x0; br.cond.sptk.few	40000000000922B0 }

l4000000000092480:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r18,0x0,r8; (p07) br.cond.spnt.few	40000000000922A0; }

l400000000009249C:
	{ (p48) invala; dep	r0,r32,r0,63,1; (p18) epc }

l40000000000924A0:
	{ nop.m	0x0; adds	r18,0x1,r33; br.cond.sptk.few	40000000000922B0 }

l40000000000924B0:
	{ nop.m	0x0; sxt4	r15,r35; adds	r33,0x1,r33 }
	{ nop.m	0x0; adds	r35,0x1,r35; nop.b	0x0; }
	{ nop.m	0x0; sxt4	r34,r33; add	r15,r32,r15; }
	{ st1	[r14],r15; cmp.eq	p06,p07,r36,r34; (p07) br.cond.dptk.few	4000000000092210 }

l40000000000924F0:
	{ nop.m	0x0; sxt4	r35,r35; add	r35,r32,r35; }
	{ st1	[r0],r35; nop.i	0x0; br.cond.sptk.few	40000000000923D0 }

l4000000000092510:
	{ ld1	r17,[r15],1; mov.i	LC,0x0; adds	r14,0x1,r14; }
	{ st1	[r16],r1,1; nop.i	0x0; br.cloop.sptk.few	4000000000092360 }

l4000000000092530:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000092380; }

;; list_string: 4000000000092540
;;   Called from:
;;     4000000000099EFC (in word_split)
;;     40000000000A302C (in fn40000000000A1400)
;;     40000000001054FC (in read_builtin)
list_string proc
	{ alloc	r49,ar.pfs,0x1A,0x0,0x15; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r51,pr }
	{ cmp.eq	p07,p06,0x0,r32; adds	r50,0x0,r1; cmp.eq	p08,p09,0x0,r33; }
	{ nop.m	0x0; mov	r52,LC; nop.i	0x0; }
	{ nop.m	0x0; mov	r48,b0; (p07) br.cond.dpnt.few	4000000000092790; }

l4000000000092580:
	{ ld1	r14,[r32]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	4000000000092790; (p08) br.cond.dpnt.few	40000000000925C0; }

l400000000009259C:
	{ (p01) cmp.eq	p00,p11,r64,r33; Invalid; Invalid }

l40000000000925A0:
	{ ld1	r15,[r33]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x20,r15; (p07) br.cond.dpnt.few	4000000000092FC0 }

l40000000000925C0:
	{ adds	r35,0x0,r0; nop.m	0x0; nop.i	0x0 }

l40000000000925D0:
	{ addl	r15,9092,r1; nop.m	0x0; adds	r40,0x0,r0; }
	{ nop.m	0x0; ld8	r16,[r15]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r16; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000932C0; }

l4000000000092600:
	{ ld1	r15,[r16]; nop.m	0x0; adds	r16,0x1,r16; }
	{ nop.m	0x0; sxt1	r15,r15; sub	r17,r0,r16; }
	{ cmp4.eq	p06,p07,0x0,r15; mov.i	LC,r17; (p06) br.cond.dpnt.few	40000000000932C0; }

l4000000000092630:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000092640:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x1,r15; nop.i	0x0; }
	{ (p07) or	r40,0x10,r40; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000092670; }

l4000000000092656:
	{ chk.a.nc	f0,3FFFFFFFFF092E56; Invalid; (p48) nop }

l4000000000092660:
	{ cmp4.eq	p07,p06,0x7F,r15; nop.i	0x0; (p07) or	r40,0x20,r40 }

l4000000000092670:
	{ nop.m	0x0; nop.i	0x0; br.cloop.sptk.few	40000000000927D0 }

l4000000000092680:
	{ nop.m	0x0; cmp4.eq.or.andcm	p08,p09,0x0,r34; (p09) br.cond.dptk.few	4000000000092800 }

l4000000000092690:
	{ adds	r15,0x0,r32; nop.m	0x0; nop.i	0x0 }

l40000000000926A0:
	{ addl	r19,23540,r1; nop.m	0x0; adds	r20,0x1,r33; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }

l40000000000926C0:
	{ nop.m	0x0; zxt1	r16,r14; cmp4.eq	p06,p07,0x20,r14 }
	{ nop.m	0x0; cmp4.eq	p09,p08,0xA,r14; nop.b	0x0; }
	{ add	r18,r19,r16; cmp4.eq.or.andcm	p06,p07,0x9,r14; (p06) br.cond.dptk.few	4000000000092700 }

l40000000000926F0:
	{ nop.m	0x0; nop.i	0x0; (p08) br.cond.dpnt.few	4000000000093070 }

l4000000000092700:
	{ ld1	r17,[r33]; nop.m	0x0; sxt1	r16,r17; }
	{ cmp4.eq	p06,p07,0x0,r16; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000093070; }

l4000000000092720:
	{ ld1	r17,[r20]; cmp4.eq	p06,p07,r16,r14; sxt1	r17,r17; }
	{ nop.m	0x0; cmp4.eq	p08,p09,0x0,r17; (p08) br.cond.dptk.few	4000000000093060 }

l4000000000092740:
	{ nop.m	0x0; ld1	r14,[r18]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	4000000000093070 }

l4000000000092760:
	{ adds	r15,0x1,r15; ld1	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000926C0 }

l4000000000092790:
	{ adds	r41,0x0,r0; nop.m	0x0; nop.i	0x0; }

l40000000000927A0:
	{ adds	r8,0x0,r41; mov	pr,r51,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r49; }
	{ nop.m	0x0; mov.i	LC,r52; mov.spnt	b0,r48,40000000000927B0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000927D0:
	{ ld1	r15,[r16],1; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	4000000000092640 }

l40000000000927F0:
	{ nop.m	0x0; cmp4.eq.or.andcm	p08,p09,0x0,r34; (p08) br.cond.dptk.few	4000000000092690 }

l4000000000092800:
	{ ld1	r16,[r33]; adds	r15,0x0,r32; sxt1	r16,r16; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r16; (p06) br.cond.dptk.few	40000000000926A0 }

l4000000000092820:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ cmp.ltu	p07,p06,0x1,r8; adds	r1,0x0,r50; adds	r53,0x0,r32; }
	{ (p06) addl	r42,1,r0; (p06) br.cond.dpnt.few	4000000000092860; br.call.sptk.many	b0,fn400000000001B6C0; }

l4000000000092846:
	{ Invalid; (p32) nop; break.i	0x80000; }

l400000000009284C:
	{ (p52) nop; nop; dep	r64,r12,r64,62,1 }
	{ cmp.lt	p08,p08,r0,r66; (p04) nop; }

l4000000000092860:
	{ ld1	r14,[r32]; adds	r37,0x18,r12; and	r34,0x3,r34 }
	{ cmp4.eq	p17,p16,0x0,r35; addl	r44,-9996,r1; addl	r35,23540,r1; }
	{ adds	r41,0x0,r0; addl	r43,-262145,r0; cmp4.eq	p18,p19,0x0,r34 }
	{ st4	[r0],r37; addl	r46,127,r0; sxt1	r14,r14; }
	{ nop.m	0x0; addl	r45,262146,r0; adds	r36,0x1,r33 }
	{ ld8	r44,[r44]; nop.m	0x0; nop.i	0x0; }

l40000000000928C0:
	{ cmp4.eq	p07,p06,0x0,r14; adds	r53,0x0,r32; adds	r54,0x0,r42 }
	{ adds	r55,0x0,r37; adds	r56,0x0,r33; (p07) br.cond.dpnt.few	4000000000092AB0; }

l40000000000928E0:
	{ adds	r57,0x0,r40; nop.i	0x0; br.call.sptk.many	b0,fn4000000000086900; }
	{ adds	r1,0x0,r50; nop.m	0x0; cmp.eq	p07,p06,0x0,r8 }
	{ adds	r38,0x0,r8; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000092AB0; }

l4000000000092910:
	{ ld1	r39,[r8]; nop.m	0x0; sxt1	r39,r39; }
	{ cmp4.eq	p07,p06,0x7F,r39; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000930F0; }

l4000000000092930:
	{ cmp4.eq	p06,p07,0x0,r39; (p07) br.cond.dpnt.few	4000000000093120; (p16) br.cond.dptk.few	4000000000092A60 }

l400000000009293C:
	{ (p09) cmp.eq	p00,p11,r0,r33; Invalid; Invalid }

l4000000000092940:
	{ ld4	r15,[r37]; nop.m	0x0; sxt4	r14,r15; }
	{ add	r14,r32,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x9,r14 }
	{ cmp4.eq	p09,p08,0x20,r14; (p06) addl	r16,1,r0; (p08) addl	r15,1,r0; }

l400000000009297C:
	{ Invalid; (p02) cmp.eq	p00,p48,0x0,r64; Invalid; }

l4000000000092980:
	{ (p07) adds	r16,0x0,r0; (p09) adds	r15,0x0,r0; and	r15,r15,r16; }

l4000000000092986:
	{ Invalid; (p07) nop.b	0x3080F; break.b	0x80000 }

l400000000009298C:
	{ Invalid; cmp.lt	p00,p00,r32,r0; nop; }
	{ (p06) cmp.lt	p00,p17,r0,r33; czx1.r	r66,r97; break.b	0x1000 }

l40000000000929A0:
	{ cmp4.eq	p06,p07,0xA,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000092A60; }

l40000000000929B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,alloc_word_desc; }
	{ adds	r1,0x0,r50; nop.m	0x0; adds	r39,0x0,r8 }
	{ addl	r53,3,r0; nop.m	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r15,0x0,r8; adds	r14,0x0,r39; nop.i	0x0 }
	{ adds	r1,0x0,r50; adds	r54,0x0,r41; adds	r53,0x0,r39; }
	{ nop.m	0x0; st1	[r15],r1,1; nop.i	0x0; }
	{ st1	[r0],r15; st8	[r14],r8,8; nop.i	0x0; }
	{ ld4	r15,[r14]; or	r15,r45,r15; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,make_word_list; }
	{ nop.m	0x0; adds	r1,0x0,r50; adds	r41,0x0,r8; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000092A60:
	{ adds	r53,0x0,r38; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ ld4	r15,[r37]; adds	r1,0x0,r50; sxt4	r14,r15; }
	{ add	r14,r32,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	4000000000092B30; }

l4000000000092AB0:
	{ cmp.eq	p07,p06,0x0,r41; adds	r53,0x0,r41; (p07) br.cond.dpnt.few	4000000000092790; }

l4000000000092AC0:
	{ nop.m	0x0; ld8	r14,[r41]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000927A0; }

l4000000000092AE0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,list_reverse; }
	{ adds	r41,0x0,r8; nop.m	0x0; adds	r1,0x0,r50; }
	{ adds	r8,0x0,r41; mov	pr,r51,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r49; }
	{ nop.m	0x0; mov.i	LC,r52; mov.spnt	b0,r48,4000000000092B10 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000092B30:
	{ cmp4.eq	p06,p07,0x20,r14; cmp4.eq.or.andcm	p06,p07,0x9,r14; nop.i	0x0; }
	{ nop.m	0x0; (p06) addl	r38,1,r0; (p06) br.cond.dptk.few	4000000000092B70 }

l4000000000092B4C:
	{ (p01) cmp.lt	p00,p11,r0,r33; (p32) cmp4.ne.and	p02,p28,r99,r97; (p17) nop }

l4000000000092B50:
	{ cmp4.eq	p06,p07,0xA,r14; (p06) addl	r14,1,r0; nop.i	0x0; }

l4000000000092B5C:
	{ cmp4.eq.and	p00,p34,r1,r0; zxt1	r0,r64; cmp.lt	p00,p00,r32,r0 }

l4000000000092B66:
	{ break.m	0x4000; (p19) nop; break.i	0x80000 }

l4000000000092B70:
	{ nop.m	0x0; adds	r14,0x10,r12; nop.i	0x0; }
	{ st8	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r50; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	4000000000092FA0; }

l4000000000092BA0:
	{ ld4	r15,[r37]; nop.m	0x0; sxt4	r55,r15; }
	{ add	r54,r32,r55; ld1	r14,[r54]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; extr.u	r17,r14,5,3; and	r16,0x1F,r14; }
	{ shladd	r14,r17,0x2,r44; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r16; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000092F60; }

l4000000000092C10:
	{ (p06) addl	r16,1,r0; nop.m	0x0; nop.i	0x0; }

l4000000000092C16:
	{ break.m	0x4000; nop; break.i	0x80000 }

l4000000000092C20:
	{ nop.m	0x0; add	r16,r15,r16; nop.i	0x0; }
	{ st4	[r16],r37; nop.m	0x0; nop.i	0x0 }

l4000000000092C40:
	{ nop.m	0x0; sxt4	r18,r16; nop.i	0x0; }
	{ add	r14,r32,r18; nop.m	0x0; add	r18,r32,r18,0x1; }
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.spnt.few	4000000000092AB0; }

l4000000000092C80:
	{ ld4	r20,[r37]; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000092CA0:
	{ nop.m	0x0; zxt1	r15,r14; cmp4.eq	p06,p07,0x20,r14 }
	{ nop.m	0x0; cmp4.eq	p09,p08,0xA,r14; nop.b	0x0; }
	{ add	r19,r35,r15; cmp4.eq.or.andcm	p06,p07,0x9,r14; (p06) br.cond.dptk.few	4000000000092CE0 }

l4000000000092CD0:
	{ nop.m	0x0; nop.i	0x0; (p08) br.cond.dpnt.few	4000000000092DA0 }

l4000000000092CE0:
	{ ld1	r17,[r33]; nop.m	0x0; sxt1	r15,r17; }
	{ cmp4.eq	p07,p06,0x0,r15; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000092DA0; }

l4000000000092D00:
	{ ld1	r17,[r36]; cmp4.eq	p06,p07,r15,r14; sxt1	r17,r17; }
	{ nop.m	0x0; cmp4.eq	p08,p09,0x0,r17; (p08) br.cond.dptk.few	4000000000092D80 }

l4000000000092D20:
	{ nop.m	0x0; ld1	r15,[r19]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r15; (p07) br.cond.dpnt.few	4000000000092DA0 }

l4000000000092D40:
	{ ld1	r14,[r18],1; nop.m	0x0; adds	r16,0x1,r16; }
	{ nop.m	0x0; sxt1	r14,r14; adds	r20,0x0,r16; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000092CA0 }

l4000000000092D70:
	{ st4	[r16],r37; nop.i	0x0; br.cond.sptk.few	4000000000092AB0 }

l4000000000092D80:
	{ nop.m	0x0; nop.i	0x0; (p06) br.cond.dptk.few	4000000000092D40; }

l4000000000092D90:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000092DA0:
	{ st4	[r20],r37; cmp4.eq	p07,p06,0x0,r38; (p07) br.cond.dptk.few	40000000000930C0 }

l4000000000092DB0:
	{ ld1	r15,[r33]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p07) br.cond.dptk.few	40000000000930C0 }

l4000000000092DD0:
	{ ld1	r17,[r36]; nop.m	0x0; sxt1	r17,r17; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r17; (p06) br.cond.dptk.few	40000000000932A0 }

l4000000000092DF0:
	{ nop.m	0x0; zxt1	r15,r14; add	r15,r35,r15; }
	{ ld1	r15,[r15]; cmp.eq	p07,p06,0x0,r15; nop.i	0x0; }
	{ (p06) addl	r15,1,r0; nop.i	0x0; (p07) adds	r15,0x0,r0; }

l4000000000092E16:
	{ addp4	r0,0xFFFFFFFFFFFFE000,r1; (p07) nop; (p48) nop }

l4000000000092E20:
	{ cmp4.eq	p07,p06,0x0,r15; nop.i	0x0; (p07) br.cond.spnt.few	40000000000930C0; }

l4000000000092E30:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x20,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x9,r14; (p07) br.cond.dptk.few	40000000000930C0; }

l4000000000092E50:
	{ adds	r18,0x1,r16; nop.m	0x0; cmp4.eq	p07,p06,0xA,r14 }
	{ adds	r16,0x2,r16; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000930C0; }

l4000000000092E70:
	{ nop.m	0x0; sxt4	r17,r18; nop.i	0x0 }
	{ st4	[r18],r37; add	r14,r32,r17; add	r17,r32,r17,0x1; }
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	4000000000092AB0; }

l4000000000092EB0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000092EC0:
	{ nop.m	0x0; zxt1	r15,r14; cmp4.eq	p06,p07,0x20,r14 }
	{ nop.m	0x0; cmp4.eq	p08,p09,0xA,r14; nop.b	0x0; }
	{ add	r15,r35,r15; cmp4.eq.or.andcm	p06,p07,0x9,r14; (p06) br.cond.dptk.few	4000000000092F00 }

l4000000000092EF0:
	{ nop.m	0x0; nop.i	0x0; (p09) br.cond.dpnt.few	4000000000093080; }

l4000000000092F00:
	{ nop.m	0x0; ld1	r14,[r15]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000093080; }

l4000000000092F20:
	{ ld1	r14,[r17],1; adds	r18,0x0,r16; adds	r16,0x1,r16; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000092EC0 }

l4000000000092F50:
	{ st4	[r18],r37; nop.i	0x0; br.cond.sptk.few	4000000000092AB0 }

l4000000000092F60:
	{ adds	r53,0x0,r0; nop.m	0x0; sub	r55,r42,r55 }
	{ adds	r56,0x10,r12; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; nop.m	0x0; adds	r1,0x0,r50; }
	{ nop.m	0x0; cmp.ltu	p06,p07,0x1,r14; (p06) br.cond.dpnt.few	40000000000932E0 }

l4000000000092FA0:
	{ ld4	r16,[r37]; adds	r16,0x1,r16; nop.i	0x0; }
	{ st4	[r16],r37; nop.i	0x0; br.cond.sptk.few	4000000000092C40 }

l4000000000092FC0:
	{ adds	r15,0x1,r33; ld1	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x9,r15; (p06) br.cond.dptk.few	40000000000925C0 }

l4000000000092FF0:
	{ adds	r15,0x2,r33; ld1	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0xA,r15; (p06) br.cond.dptk.few	40000000000925C0 }

l4000000000093020:
	{ adds	r15,0x3,r33; ld1	r35,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r35,r35; cmp4.eq	p06,p07,0x0,r35; }
	{ nop.m	0x0; (p06) addl	r35,1,r0; nop.i	0x0; }

l400000000009304C:
	{ invala; nop; zxt1	r0,r64 }

l400000000009305C:
	{ (p44) invala; break.i	0x1000; mov	pr,r32,0x0 }

l4000000000093060:
	{ nop.m	0x0; nop.i	0x0; (p06) br.cond.dptk.few	4000000000092760 }

l4000000000093070:
	{ nop.m	0x0; adds	r32,0x0,r15; br.cond.sptk.few	4000000000092820 }

l4000000000093080:
	{ nop.m	0x0; sxt4	r14,r18; nop.i	0x0 }
	{ st4	[r18],r37; add	r14,r32,r14; nop.i	0x0; }
	{ nop.m	0x0; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; br.cond.sptk.few	40000000000928C0 }

l40000000000930C0:
	{ ld4	r15,[r37]; nop.m	0x0; sxt4	r14,r15; }
	{ add	r14,r32,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; br.cond.sptk.few	40000000000928C0; }

l40000000000930F0:
	{ adds	r14,0x1,r8; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	4000000000093200 }

l4000000000093120:
	{ adds	r53,0x0,r38; nop.i	0x0; br.call.sptk.many	b0,remove_quoted_nulls; }
	{ adds	r1,0x0,r50; adds	r53,0x0,r38; br.call.sptk.many	b0,make_word; }
	{ adds	r54,0x0,r41; nop.m	0x0; adds	r1,0x0,r50 }
	{ adds	r53,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,make_word_list; }
	{ adds	r14,0x8,r8; adds	r1,0x0,r50; adds	r41,0x0,r8 }
	{ adds	r53,0x0,r38; ld8	r14,[r14]; nop.i	0x0; }
	{ adds	r14,0x8,r14; ld4	r15,[r14]; nop.i	0x0; }
	{ and	r15,r43,r15; st4	[r15],r14; (p19) or	r15,0x2,r15; }

l40000000000931A0:
	{ (p19) st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }

l40000000000931A6:
	{ break.m	0x4000; Invalid; (p48) nop }
	{ Invalid; (p07) nop; (p32) nop.b	0xE403 }
	{ (p07) fwb; mov	pr,0x4000; break.i	0x80000 }
	{ (p07) break.m	0x50700; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD56AC6; nop; break.i	0x80000 }

l40000000000931F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000092B30 }

l4000000000093200:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,alloc_word_desc; }
	{ adds	r1,0x0,r50; nop.m	0x0; adds	r47,0x0,r8 }
	{ addl	r53,3,r0; nop.m	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r15,0x0,r8; adds	r14,0x0,r47; nop.i	0x0 }
	{ adds	r1,0x0,r50; adds	r54,0x0,r41; adds	r53,0x0,r47; }
	{ nop.m	0x0; st1	[r15],r1,1; nop.i	0x0; }
	{ st1	[r0],r15; st8	[r14],r8,8; nop.i	0x0; }
	{ ld4	r15,[r14]; or	r15,r45,r15; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,make_word_list; }
	{ adds	r1,0x0,r50; adds	r41,0x0,r8; br.cond.sptk.few	4000000000092A60 }

l40000000000932A0:
	{ cmp4.eq	p06,p07,r15,r14; (p06) addl	r15,1,r0; nop.i	0x0; }

l40000000000932AC:
	{ invala; cmp4.eq.or.andcm	p00,p32,r32,r0; zxt1	r0,r64 }

l40000000000932BC:
	{ (p27) invala; zxt1	r0,r64; (p01) nop }

l40000000000932C0:
	{ adds	r40,0x0,r0; cmp4.eq.or.andcm	p08,p09,0x0,r34; (p08) br.cond.dptk.few	4000000000092690 }

l40000000000932D0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000092800 }

l40000000000932E0:
	{ cmp.eq	p06,p07,0x0,r8; nop.m	0x0; (p07) adds	r16,0x0,r8 }

l40000000000932F0:
	{ nop.m	0x0; (p07) ld4	r15,[r37]; (p07) br.cond.spnt.few	4000000000092C20; }

l40000000000932FC:
	{ Invalid; Invalid; (p18) epc }

l4000000000093300:
	{ ld4	r16,[r37]; adds	r16,0x1,r16; nop.i	0x0; }
	{ st4	[r16],r37; nop.i	0x0; br.cond.sptk.few	4000000000092C40; }
4000000000093320 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000093330 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; word_list_remove_quoted_nulls: 4000000000093340
;;   Called from:
;;     400000000009355C (in string_list_pos_params)
;;     40000000000935AC (in string_list_pos_params)
;;     40000000000A7E6C (in fn40000000000A7940)
;;     4000000000107ECC (in read_builtin)
word_list_remove_quoted_nulls proc
	{ alloc	r37,ar.pfs,0x8,0x0,0x7; adds	r38,0x0,r1; nop.b	0x0 }
	{ adds	r33,0x0,r32; mov	r36,b4; cmp.eq	p07,p06,0x0,r32; }
	{ nop.m	0x0; addl	r35,-262145,r0; (p07) br.cond.dpnt.few	40000000000933E0; }

l4000000000093370:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000093380:
	{ adds	r34,0x8,r33; ld8	r14,[r34]; nop.i	0x0; }
	{ ld8	r39,[r14]; nop.i	0x0; br.call.sptk.many	b0,remove_quoted_nulls; }
	{ nop.m	0x0; ld8	r14,[r34]; adds	r1,0x0,r38 }
	{ ld8	r33,[r33]; adds	r14,0x8,r14; cmp.eq	p07,p06,0x0,r33; }
	{ ld4	r15,[r14]; and	r15,r35,r15; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; (p06) br.cond.dptk.few	4000000000093380 }

l40000000000933E0:
	{ nop.m	0x0; mov.i	ar.pfs,r37; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000933F0; br.ret	b0; }

;; string_list_pos_params: 4000000000093400
;;   Called from:
;;     40000000000C397C (in assoc_subrange)
string_list_pos_params proc
	{ alloc	r36,ar.pfs,0x7,0x0,0x6; mov	r35,b3; nop.i	0x0 }
	{ cmp4.eq	p07,p06,0x2A,r32; adds	r37,0x0,r1; (p07) br.cond.dpnt.few	4000000000093470; }

l4000000000093420:
	{ cmp4.eq	p07,p06,0x40,r32; adds	r32,0x0,r33; mov.i	ar.pfs,r36 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000934C0; }

l4000000000093440:
	{ and	r34,0x3,r34; nop.m	0x0; mov.spnt	b0,r35,4000000000093440; }
	{ cmp4.eq	p06,p07,0x0,r34; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000934F0; }

l4000000000093460:
	{ alloc	r2,ar.pfs,0x3,0x0,0x0; nop.i	0x0; br.cond.sptk.many	string_list }

l4000000000093470:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x0; adds	r32,0x0,r33 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000093530; }

l4000000000093490:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x1; (p07) br.cond.dpnt.few	4000000000093580; }

l40000000000934A0:
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000934A0; mov.i	ar.pfs,r36; }
	{ alloc	r2,ar.pfs,0x3,0x0,0x0; nop.i	0x0; br.cond.sptk.many	string_list_dollar_star }

l40000000000934C0:
	{ and	r14,0x3,r34; adds	r32,0x0,r33; mov.spnt	b0,r35,40000000000934C0; }
	{ cmp4.eq	p06,p07,0x0,r14; mov.i	ar.pfs,r36; (p07) br.cond.dpnt.few	40000000000935D0; }

l40000000000934E0:
	{ alloc	r2,ar.pfs,0x3,0x0,0x0; nop.i	0x0; br.cond.sptk.many	string_list_dollar_star; }

l40000000000934F0:
	{ adds	r38,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,fn4000000000090FC0; }
	{ adds	r33,0x0,r8; adds	r1,0x0,r37; mov.spnt	b0,r35,4000000000093500; }
	{ adds	r32,0x0,r33; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ alloc	r2,ar.pfs,0x3,0x0,0x0; nop.i	0x0; br.cond.sptk.many	string_list; }

l4000000000093530:
	{ adds	r38,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,fn4000000000090FC0; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r32,0x0,r8 }
	{ adds	r38,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,word_list_remove_quoted_nulls; }
	{ adds	r1,0x0,r37; mov.spnt	b0,r35,4000000000093560; mov.i	ar.pfs,r36; }
	{ alloc	r2,ar.pfs,0x3,0x0,0x0; nop.i	0x0; br.cond.sptk.many	string_list_dollar_star; }

l4000000000093580:
	{ adds	r38,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,fn4000000000090FC0; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r32,0x0,r8 }
	{ adds	r38,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,word_list_remove_quoted_nulls; }
	{ adds	r1,0x0,r37; mov.spnt	b0,r35,40000000000935B0; mov.i	ar.pfs,r36; }
	{ alloc	r2,ar.pfs,0x3,0x0,0x0; nop.i	0x0; br.cond.sptk.many	string_list }

l40000000000935D0:
	{ adds	r33,0x0,r34; mov.spnt	b0,r35,40000000000935D0; mov.i	ar.pfs,r36; }
	{ alloc	r2,ar.pfs,0x3,0x0,0x0; nop.i	0x0; br.cond.sptk.many	string_list_dollar_at; }
40000000000935F0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
4000000000093600 08 50 3D 18 80 05 50 02 80 00 42 20 05 00 C4 00 .P=...P...B ....
4000000000093610 19 58 01 02 00 21 70 00 80 0C F2 03 F0 01 00 43 .X...!p........C
4000000000093620 09 40 01 00 00 21 00 00 00 02 00 00 00 00 04 00 .@...!..........
4000000000093630 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000093640 09 70 20 4A 00 21 D0 02 84 00 42 C0 05 10 01 84 .p J.!....B.....
4000000000093650 09 00 00 00 01 00 E0 00 38 30 20 00 00 00 04 00 ........80 .....
4000000000093660 11 60 01 1C 18 10 00 00 00 02 00 00 28 3B FF 58 .`..........(;.X
4000000000093670 11 08 00 56 00 21 60 02 20 00 42 00 18 F0 FA 58 ...V.!`. .B....X
4000000000093680 08 38 00 4C 06 39 70 02 20 00 42 00 00 00 04 00 .8.L.9p. .B.....
4000000000093690 19 08 00 56 00 21 D0 02 A0 00 C2 03 00 01 00 43 ...V.!.........C
40000000000936A0 08 00 00 00 01 00 C0 02 9C 00 42 00 00 00 04 00 ..........B.....
40000000000936B0 19 00 98 4E 98 11 00 00 00 02 00 00 98 F5 FA 58 ...N...........X
40000000000936C0 09 28 01 4A 18 10 10 00 AC 00 42 00 05 40 00 84 .(.J......B..@..
40000000000936D0 11 00 00 00 01 00 70 00 94 0C 72 03 70 FF FF 4A ......p...r.p..J
40000000000936E0 11 30 00 10 07 39 C0 02 20 00 42 03 20 01 00 43 .0...9.. .B. ..C
40000000000936F0 09 00 00 00 01 00 E0 00 20 30 20 00 00 00 04 00 ........ 0 .....
4000000000093700 11 30 00 1C 07 39 00 00 00 02 00 03 30 00 00 43 .0...9......0..C
4000000000093710 11 00 00 00 01 00 00 00 00 02 00 00 F8 56 04 50 .............V.P
4000000000093720 09 00 00 00 01 00 10 00 AC 00 42 00 05 40 00 84 ..........B..@..
4000000000093730 08 68 01 50 00 21 00 00 00 02 00 C0 05 20 01 84 .h.P.!....... ..
4000000000093740 19 60 01 46 00 21 00 00 00 02 00 00 C8 FC FF 58 .`.F.!.........X
4000000000093750 08 08 00 56 00 21 00 00 00 02 00 A0 04 40 00 84 ...V.!.......@..
4000000000093760 19 60 01 50 00 21 00 00 00 02 00 00 68 84 FB 58 .`.P.!......h..X
4000000000093770 09 40 00 4A 00 21 10 00 AC 00 42 00 A0 02 AA 00 .@.J.!....B.....
4000000000093780 11 00 00 00 01 00 00 48 05 80 03 80 08 00 84 00 .......H........
4000000000093790 11 60 05 00 00 24 00 00 00 02 00 00 38 55 05 50 .`...$......8U.P
40000000000937A0 08 00 00 00 01 00 60 02 20 00 42 20 00 58 01 84 ......`. .B .X..
40000000000937B0 09 00 00 10 80 11 D0 02 A0 00 42 80 05 38 01 84 ..........B..8..
40000000000937C0 11 00 98 4E 98 11 00 00 00 02 00 00 88 F4 FA 58 ...N...........X
40000000000937D0 09 28 01 4A 18 10 10 00 AC 00 42 00 05 40 00 84 .(.J......B..@..
40000000000937E0 10 00 00 00 01 00 70 00 94 0C 72 03 60 FE FF 4A ......p...r.`..J
40000000000937F0 10 00 00 00 01 00 00 00 00 02 00 00 F0 FE FF 48 ...............H
4000000000093800 09 40 01 00 00 21 E0 02 90 00 42 80 05 18 01 84 .@...!....B.....
4000000000093810 11 68 01 50 00 21 00 00 00 02 00 00 F8 FB FF 58 .h.P.!.........X
4000000000093820 08 08 00 56 00 21 00 00 00 02 00 A0 04 40 00 84 ...V.!.......@..
4000000000093830 19 60 01 50 00 21 00 00 00 02 00 00 98 83 FB 58 .`.P.!.........X
4000000000093840 09 40 00 4A 00 21 10 00 AC 00 42 00 A0 02 AA 00 .@.J.!....B.....
4000000000093850 11 00 00 00 01 00 00 48 05 80 03 80 08 00 84 00 .......H........
4000000000093860 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000093870 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; copy_fifo_list: 4000000000093880
copy_fifo_list proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; addl	r14,7576,r1; mov	r34,b2 }
	{ adds	r36,0x0,r1; addl	r33,7572,r1; cmp.eq	p08,p09,0x0,r32; }
	{ ld4	r14,[r14]; nop.m	0x0; adds	r8,0x0,r0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000938F0 }

l40000000000938C0:
	{ ld4	r14,[r33]; (p08) cmp.eq.unc	p10,p00,r0,r0; (p09) cmp.eq.unc	p11,p00,r0,r0; }

l40000000000938CC:
	{ break.m	0xC0000; nop; (p04) break.i	0x161C0; }

l40000000000938D0:
	{ nop.m	0x0; sxt4	r37,r14; nop.i	0x0 }
	{ cmp4.eq	p07,p06,0x0,r14; nop.m	0x0; (p06) br.cond.dptk.few	4000000000093910 }

l40000000000938F0:
	{ (p09) st4	[r0],r32; mov.i	ar.pfs,r35; (p08) br.cond.dpnt.few	4000000000093970; }

l40000000000938F6:
	{ Invalid; nop; break.i	0x80000 }

l4000000000093900:
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000093900; br.ret	b0; }

l4000000000093910:
	{ (p11) st4	[r14],r32; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }

l4000000000093916:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; (p18) nop; (p32) nop }
	{ add	r0,r0,r1; (p19) nop; (p32) nop }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ Invalid; (p34) nop; nop }

l4000000000093970:
	{ adds	r8,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000093980; br.ret	b0; }
4000000000093990 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000939A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000939B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fifos_pending: 40000000000939C0
fifos_pending proc
	{ nop.m	0x0; adds	r8,0x0,r0; br.ret	b0; }
40000000000939D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000939E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000939F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; num_fifos: 4000000000093A00
num_fifos proc
	{ nop.m	0x0; addl	r14,7576,r1; nop.i	0x0; }
	{ ld4	r8,[r14]; nop.i	0x0; br.ret	b0; }
4000000000093A20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000093A30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; unlink_fifo: 4000000000093A40
;;   Called from:
;;     4000000000093B6C (in unlink_fifo_list)
;;     4000000000093D0C (in close_new_fifos)
;;     4000000000093D5C (in close_new_fifos)
unlink_fifo proc
	{ alloc	r36,ar.pfs,0x7,0x0,0x6; addl	r34,7564,r1; mov	r35,b3 }
	{ adds	r37,0x0,r1; nop.m	0x0; sxt4	r33,r32; }
	{ ld8	r14,[r34]; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ add	r14,r14,r33; nop.m	0x0; mov.spnt	b0,r35,4000000000093A70; }
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	4000000000093AA0; br.ret	b0; }

l4000000000093A9C:
	{ cmp.lt	p00,p17,r33,r0; (p04) invala; break.i	0x1000 }

l4000000000093AA0:
	{ adds	r38,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C340; }
	{ adds	r1,0x0,r37; ld8	r16,[r34]; mov.i	ar.pfs,r36; }
	{ addl	r14,7576,r1; add	r33,r16,r33; mov.spnt	b0,r35,4000000000093AC0; }
	{ ld4	r15,[r14]; st1	[r0],r33; nop.i	0x0; }
	{ nop.m	0x0; adds	r15,0xFFFFFFFFFFFFFFFF,r15; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.ret	b0; }

;; unlink_fifo_list: 4000000000093B00
;;   Called from:
;;     4000000000021C7C (in fn4000000000021C00)
;;     400000000002238C (in exit_shell)
;;     40000000000224CC (in exit_shell)
;;     4000000000023C7C (in reader_loop)
;;     400000000005E78C (in execute_command)
;;     4000000000093DBC (in close_new_fifos)
;;     4000000000094D6C (in command_substitute)
;;     400000000009502C (in command_substitute)
;;     400000000009532C (in command_substitute)
;;     40000000000953EC (in command_substitute)
;;     40000000000B43FC (in top_level_cleanup)
;;     40000000000B46CC (in throw_to_top_level)
;;     40000000000B494C (in throw_to_top_level)
;;     40000000000B4D4C (in termsig_handler)
;;     40000000000B4D4C (in termsig_handler)
;;     40000000000B4EEC (in termsig_handler)
unlink_fifo_list proc
	{ alloc	r36,ar.pfs,0x7,0x0,0x6; addl	r33,7576,r1; nop.b	0x0 }
	{ addl	r34,7572,r1; mov	r35,b3; adds	r37,0x0,r1; }
	{ ld4	r14,[r33]; nop.m	0x0; adds	r32,0x0,r0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000093BC0; }

l4000000000093B40:
	{ nop.m	0x0; ld4	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,0x0,r14; (p06) br.cond.dpnt.few	4000000000093BB0; }

l4000000000093B60:
	{ adds	r38,0x0,r32; adds	r32,0x1,r32; br.call.sptk.many	b0,unlink_fifo; }
	{ ld4	r14,[r33]; nop.m	0x0; adds	r1,0x0,r37; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000093BB0; }

l4000000000093B90:
	{ nop.m	0x0; ld4	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r32,r14; (p06) br.cond.dptk.few	4000000000093B60 }

l4000000000093BB0:
	{ st4	[r0],r33; nop.m	0x0; nop.i	0x0 }

l4000000000093BC0:
	{ nop.m	0x0; mov.i	ar.pfs,r36; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r35,4000000000093BD0; br.ret	b0; }
4000000000093BE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000093BF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; close_new_fifos: 4000000000093C00
close_new_fifos proc
	{ alloc	r39,ar.pfs,0xB,0x0,0xA; cmp.eq	p06,p07,0x0,r32; nop.b	0x0 }
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r33; mov	r41,LC; addl	r36,7572,r1; }
	{ adds	r34,0x0,r0; addp4	r14,r14,r0; mov	r38,b6 }
	{ adds	r35,0x0,r32; addl	r37,7564,r1; (p06) br.cond.dpnt.few	4000000000093D90; }

l4000000000093C40:
	{ cmp4.lt	p06,p07,0x0,r33; nop.m	0x0; adds	r40,0x0,r1 }
	{ ld4	r16,[r36]; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000093CF0; }

l4000000000093C60:
	{ nop.m	0x0; (p06) mov.i	LC,r14; nop.i	0x0; }

l4000000000093C6C:
	{ nop; break.i	0x1000; break.i	0x1000 }
	{ cmp.lt	p00,p03,r1,r0; (p17) nop; (p33) cmp.lt	p08,p24,r4,r34 }

l4000000000093C80:
	{ ld1	r14,[r35],1; cmp4.lt	p09,p08,r34,r16; sxt1	r14,r14; }

l4000000000093C82:
	{ (p48) ld4.bias	r8,[r10]; (p32) nop }
	{ Invalid; (p32) nop; Invalid }

l4000000000093CA0:
	{ nop.m	0x0; nop.i	0x0; (p08) br.cond.dptk.few	4000000000093CE0 }

l4000000000093CB0:
	{ ld8	r14,[r37]; add	r14,r14,r34; nop.i	0x0; }
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	4000000000093D50; }

l4000000000093CE0:
	{ nop.m	0x0; adds	r34,0x1,r34; br.cloop.sptk.few	4000000000093C80; }

l4000000000093CF0:
	{ adds	r34,0x0,r33; cmp4.lt	p06,p07,r33,r16; (p07) br.cond.dpnt.few	4000000000093D30; }

l4000000000093D00:
	{ adds	r42,0x0,r34; adds	r34,0x1,r34; br.call.sptk.many	b0,unlink_fifo; }
	{ ld4	r14,[r36]; nop.m	0x0; adds	r1,0x0,r40; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r34,r14; (p06) br.cond.dptk.few	4000000000093D00 }

l4000000000093D30:
	{ nop.m	0x0; mov.i	ar.pfs,r39; mov.i	LC,r41; }
	{ nop.m	0x0; mov.spnt	b0,r38,4000000000093D40; br.ret	b0; }

l4000000000093D50:
	{ adds	r42,0x0,r34; adds	r34,0x1,r34; br.call.sptk.many	b0,unlink_fifo; }
	{ nop.m	0x0; adds	r1,0x0,r40; nop.i	0x0 }
	{ ld4	r16,[r36]; nop.m	0x0; br.cloop.sptk.few	4000000000093C80 }

l4000000000093D80:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000093CF0 }

l4000000000093D90:
	{ nop.m	0x0; mov.spnt	b0,r38,4000000000093D90; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.i	LC,r41; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	unlink_fifo_list; }
4000000000093DC0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
4000000000093DD0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000093DE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000093DF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; command_substitute: 4000000000093E00
;;   Called from:
;;     40000000000A35CC (in fn40000000000A1400)
;;     40000000000E67FC (in gen_compspec_completions)
command_substitute proc
	{ alloc	r51,ar.pfs,0x18,0x0,0x15; adds	r16,0x0,r12; nop.b	0x0 }
	{ adds	r12,0xFFFFFFFFFFFFFF40,r12; nop.m	0x0; mov	r17,LC; }
	{ adds	r14,0xA0,r12; mov	r52,pr; cmp.eq	p06,p07,0x0,r32; }
	{ st8	[r32],r14; nop.m	0x0; mov	r50,b2; }
	{ nop.m	0x0; st8	[r16],r8,8; nop.i	0x0; }
	{ st8.spill	[r1],r16; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000944E0; }

l4000000000093E60:
	{ ld1	r14,[r32]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000944E0; }

l4000000000093E80:
	{ nop.m	0x0; cmp4.eq	p07,p06,0xA,r14; (p07) br.cond.dpnt.few	40000000000944A0 }

l4000000000093E90:
	{ addl	r14,6464,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	40000000000943E0 }

l4000000000093EC0:
	{ addl	r14,7540,r1; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; addl	r14,7588,r1; (p06) br.cond.dpnt.few	4000000000095050; }

l4000000000093EE0:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r14; addl	r14,6516,r1; (p07) br.cond.dpnt.few	4000000000095050; }

l4000000000093F00:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dptk.few	40000000000943A0; }

l4000000000093F20:
	{ nop.m	0x0; (p06) adds	r14,0xB0,r12; nop.i	0x0; }

l4000000000093F2C:
	{ Invalid; Invalid; break.i	0x1000 }

l4000000000093F36:
	{ break.m	0x4000; nop; (p16) nop }

l4000000000093F40:
	{ adds	r53,0x90,r12; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB40; }
	{ adds	r1,0xC8,r12; nop.m	0x0; cmp4.lt	p07,p06,r8,r0; }
	{ ld8	r1,[r1]; (p07) addl	r54,-6716,r1; addl	r15,9028,r1 }

l4000000000093F6C:
	{ (p34) cmp.lt	p01,p09,r70,r72; zxt4	r35,r14; (p02) nop; }
	{ (p34) cmp4.eq.and	p01,p49,r70,r72; nop }

l4000000000093F86:
	{ chk.a.nc	f0,3FFFFFFFFF094786; nop; break.i	0x80000 }

l4000000000093F90:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4	r15,[r15]; ld4	r47,[r16]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r15,0x4; nop.i	0x0 }
	{ ld4	r38,[r14]; (p07) addl	r15,5896,r1; nop.i	0x0; }

l4000000000093FDC:
	{ Invalid; cmp4.eq.or.andcm	p00,p32,r32,r0; Invalid }

l4000000000093FEC:
	{ Invalid; Invalid; break.i	0x1000 }

l4000000000093FF6:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; (p26) mov.sptk	b0,r0,4000000000094106; (p16) nop }
	{ Invalid; (p17) nop; break.i	0x80000 }
	{ break.m	0x4000; nop; nop }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ add	r0,r0,r1; (p03) nop; (p16) nop }
	{ mf.a; nop; (p16) cmp.ltu	p00,p06,r32,r0 }
	{ Invalid; (p32) nop; break.i	0x80000; }

l400000000009406C:
	{ (p21) nop; nop; zxt1	r18,r64 }
	{ nop; Invalid; break.i	0x1000 }
	{ (p56) nop; invala; cmp.lt	p00,p00,r32,r0 }
	{ (p20) nop; cmp.lt	p32,p08,r0,r6; (p01) nop }
	{ nop; break.i	0x1000; break.i	0x1000 }
	{ invala.e	f0; (p32) mov	pr,r3,0x4692; Invalid }

l40000000000940CC:
	{ (p22) cmp.lt.unc	p34,p02,r63,r44; (p01) nop; zxt1	r18,r64 }
	{ nop; nop; Invalid }
	{ (p19) nop; cmp.lt	p18,p16,r35,r64; zxt1	r4,r64 }
	{ cmp.eq	p00,p10,r0,r66; (p01) nop; Invalid }
	{ ldfp8	f0,f1,[r0]; (p05) cmp.lt.unc	p00,p08,r3,r4; zxt4	r33,r17 }
	{ Invalid; nop; Invalid }
	{ cmp.eq	p00,p17,r1,r0; czx1.r	r32,r65; mov	pr,r32,0x0 }
	{ (p26) cmp.lt	p02,p11,r64,r33; Invalid; cmp.lt	p00,p00,r32,r0 }

l4000000000094140:
	{ ld1	r14,[r17]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; cmp4.eq	p08,p09,0x7F,r14; (p06) br.cond.dpnt.few	4000000000095470; }

l4000000000094160:
	{ adds	r17,0x1,r17; cmp4.eq	p06,p07,0x1,r14; (p08) addl	r14,1,r0; }

l4000000000094170:
	{ sub	r18,r0,r17; (p09) adds	r14,0x0,r0; mov.i	LC,r18 }

l400000000009417C:
	{ (p09) nop; zxt4	r0,r0; (p02) dep	r68,r67,r3,48,1 }

l4000000000094186:
	{ (p08) chk.a.clr	f16,3FFFFFFFFF09B266; (p09) nop; break.i	0x80000 }

l4000000000094190:
	{ nop.m	0x0; or	r15,r15,r18; br.cloop.sptk.few	4000000000094440; }

l40000000000941A0:
	{ and	r14,0x3,r33; addl	r48,9092,r1; cmp4.lt	p06,p07,r43,r0 }
	{ adds	r44,0x0,r0; adds	r38,0x0,r0; (p06) br.cond.dpnt.few	4000000000095530; }

l40000000000941C0:
	{ adds	r39,0x0,r0; adds	r34,0x0,r0; adds	r35,0x0,r0 }
	{ cmp4.eq	p16,p17,0x0,r14; andcm	r42,0x1,r15; andcm	r46,0x1,r16; }
	{ addl	r40,1,r0; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; movl	r45,0x200000; }

l4000000000094200:
	{ nop.m	0x0; adds	r35,0xFFFFFFFFFFFFFFFF,r35; nop.i	0x0; }
	{ nop.m	0x0; cmp.lt	p06,p07,0x0,r35; (p07) br.cond.dpnt.few	4000000000094530 }

l4000000000094220:
	{ nop.m	0x0; ld1	r14,[r37],1; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; adds	r36,0x0,r14 }
	{ adds	r49,0x0,r14; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000094200 }

l4000000000094250:
	{ nop.m	0x0; adds	r15,0x2,r34; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r15,r39; (p06) br.cond.dptk.few	40000000000942D0 }

l4000000000094270:
	{ sub	r17,r15,r39; adds	r39,0x80,r39; adds	r53,0x0,r38; }
	{ nop.m	0x0; extr	r17,r17,7,25; dep.z	r17,0x11,7,25; }
	{ nop.m	0x0; add	r39,r39,r17; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r54,r39; br.call.sptk.many	b0,xrealloc; }
	{ adds	r1,0xC8,r12; nop.m	0x0; adds	r38,0x0,r8; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0 }

l40000000000942D0:
	{ nop.m	0x0; nop.i	0x0; (p17) br.cond.dptk.few	40000000000945E0 }

l40000000000942E0:
	{ cmp4.eq	p06,p07,0x1,r49; (p06) addl	r17,1,r0; nop.i	0x0; }

l40000000000942EC:
	{ nop; (p02) nop; zxt1	r42,r3 }

l40000000000942F6:
	{ Invalid; nop; break.b	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD57C16; Invalid; break.i	0x80000 }

l4000000000094310:
	{ nop.m	0x0; sxt4	r14,r34; nop.i	0x0 }
	{ adds	r44,0x0,r45; adds	r34,0x1,r34; add	r14,r38,r14; }
	{ st1	[r40],r14; nop.m	0x0; nop.i	0x0 }

l4000000000094340:
	{ nop.m	0x0; sxt4	r14,r34; adds	r34,0x1,r34; }
	{ add	r14,r38,r14; nop.m	0x0; nop.i	0x0; }
	{ st1	[r36],r14; nop.m	0x0; nop.i	0x0 }

l4000000000094370:
	{ nop.m	0x0; adds	r35,0xFFFFFFFFFFFFFFFF,r35; nop.i	0x0; }
	{ nop.m	0x0; cmp.lt	p06,p07,0x0,r35; (p06) br.cond.dptk.few	4000000000094220 }

l4000000000094390:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000094530 }

l40000000000943A0:
	{ addl	r14,8412,r1; nop.m	0x0; addl	r15,16,r0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; adds	r14,0xB0,r12; nop.i	0x0 }
	{ (p06) st4	[r0],r14; (p07) st4	[r15],r14; br.cond.sptk.few	4000000000093F40 }

l40000000000943D6:
	{ mf.a; nop; (p32) nop; }

l40000000000943DC:
	{ (p27) cmp.lt.unc	p63,p11,r63,r36; zxt4	r56,r14; break.b	0x1000 }

l40000000000943E0:
	{ addl	r14,7392,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.sptk.few	4000000000093EC0 }

l4000000000094410:
	{ addl	r14,9044,r1; addl	r15,125,r0; addl	r53,3,r0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,jump_to_top_level }

l4000000000094440:
	{ ld1	r14,[r17],1; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x0,r14; cmp4.eq	p08,p09,0x7F,r14; (p07) br.cond.dpnt.few	40000000000941A0; }

l4000000000094460:
	{ cmp4.eq	p06,p07,0x1,r14; (p08) addl	r14,1,r0; (p06) addl	r18,1,r0 }

l400000000009446C:
	{ cmp.lt	p00,p43,0x0,r72; (p01) br.cond.dpnt.few	4000000000CB446C; (p02) epc }

l4000000000094470:
	{ (p09) adds	r14,0x0,r0; (p07) adds	r18,0x0,r0; or	r16,r16,r14; }

l4000000000094476:
	{ Invalid; (p08) nop; break.i	0x80000; }

l400000000009447C:
	{ (p08) invala; cmp.eq	p00,p00,r32,r0; (p49) nop }
	{ (p62) invala; break.i	0x1000; break.i	0x1000 }

l4000000000094490:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000941A0 }

l40000000000944A0:
	{ adds	r14,0x1,r32; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	4000000000093E90; }

l40000000000944D0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000944E0:
	{ adds	r8,0x0,r0; nop.m	0x0; nop.i	0x0; }

l40000000000944F0:
	{ adds	r18,0xC0,r12; nop.m	0x0; mov	pr,r52,0xFFFFFFFFFFFFFFFE; }
	{ ld8	r19,[r18]; mov.i	ar.pfs,r51; mov.i	LC,r19; }
	{ nop.m	0x0; mov.spnt	b0,r50,4000000000094510; nop.i	0x0 }
	{ adds	r12,0xC0,r12; nop.m	0x0; br.ret	b0; }

l4000000000094530:
	{ adds	r53,0x0,r43; adds	r54,0x10,r12; nop.i	0x0 }
	{ addl	r55,128,r0; adds	r37,0x10,r12; br.call.sptk.many	b0,zread; }
	{ adds	r1,0xC8,r12; cmp.lt	p07,p06,0x0,r8; adds	r35,0x0,r8; }
	{ ld8	r1,[r1]; (p06) br.cond.dpnt.few	4000000000094620; br.cond.sptk.few	4000000000094220 }

l400000000009456C:
	{ (p38) nop; cmp.lt	p00,p00,r32,r0; czx1.r	r63,r97 }

l4000000000094570:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x7F,r49; nop.i	0x0; }
	{ nop.m	0x0; tbit.z.or.andcm	p07,p06,r46,0x0; (p06) br.cond.dptk.few	40000000000945E0; }

l4000000000094590:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x20,r49; (p06) br.cond.dptk.few	4000000000094340 }

l40000000000945A0:
	{ nop.m	0x0; ld8	r14,[r48]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000094340; }

l40000000000945C0:
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000094340; }

l40000000000945E0:
	{ nop.m	0x0; sxt4	r14,r34; adds	r34,0x1,r34; }
	{ add	r14,r38,r14; st1	[r40],r14; sxt4	r14,r34 }
	{ adds	r34,0x1,r34; add	r14,r38,r14; nop.i	0x0; }
	{ st1	[r36],r14; nop.i	0x0; br.cond.sptk.few	4000000000094370 }

l4000000000094620:
	{ nop.m	0x0; sxt4	r14,r34; cmp.eq	p06,p07,0x0,r38 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000094D90; }

l4000000000094640:
	{ add	r14,r38,r14; nop.m	0x0; cmp4.eq	p07,p06,0x0,r34; }
	{ st1	[r0],r14; nop.i	0x0; (p06) br.cond.dptk.few	4000000000094DA0 }

l4000000000094660:
	{ adds	r53,0x0,r38; adds	r38,0x0,r0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0xC8,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0 }

l4000000000094690:
	{ nop.m	0x0; adds	r14,0x90,r12; nop.i	0x0; }
	{ ld4	r53,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C340; }
	{ adds	r1,0xC8,r12; nop.m	0x0; adds	r53,0x0,r41; }
	{ ld8	r1,[r1]; addl	r14,5956,r1; nop.i	0x0; }
	{ st4	[r41],r14; nop.i	0x0; br.call.sptk.many	b0,wait_for; }
	{ adds	r1,0xC8,r12; ld8	r1,[r1]; nop.i	0x0; }
	{ nop.m	0x0; addl	r14,9044,r1; nop.i	0x0; }
	{ nop.m	0x0; st4	[r8],r14; addl	r14,5960,r1; }
	{ st4	[r41],r14; addl	r14,130,r0; cmp4.eq	p07,p06,r14,r8 }
	{ addl	r14,5876,r1; nop.m	0x0; nop.i	0x0; }
	{ st4	[r47],r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000950C0 }

l4000000000094740:
	{ addl	r14,6516,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000947E0 }

l4000000000094770:
	{ addl	r14,7436,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r53,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r53; (p06) br.cond.dptk.few	40000000000947E0 }

l40000000000947A0:
	{ addl	r14,9028,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x0; (p07) br.cond.dpnt.few	4000000000095410; }

l40000000000947D0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000947E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,alloc_word_desc; }
	{ adds	r1,0xC8,r12; adds	r14,0x0,r8; nop.i	0x0 }
	{ ld8	r1,[r1]; st8	[r14],r8,8; nop.i	0x0; }
	{ st4	[r44],r14; nop.m	0x0; nop.i	0x0 }

l4000000000094820:
	{ adds	r18,0xC0,r12; nop.m	0x0; mov	pr,r52,0xFFFFFFFFFFFFFFFE; }
	{ ld8	r19,[r18]; mov.i	ar.pfs,r51; mov.i	LC,r19; }
	{ nop.m	0x0; mov.spnt	b0,r50,4000000000094840; nop.i	0x0 }
	{ adds	r12,0xC0,r12; nop.m	0x0; br.ret	b0; }

l4000000000094860:
	{ adds	r34,0x94,r12; nop.i	0x0; br.call.sptk.many	b0,reset_signal_handlers; }
	{ addl	r15,128,r0; ld4	r14,[r35]; adds	r1,0xC8,r12; }
	{ or	r14,r15,r14; ld8	r1,[r1]; nop.i	0x0; }
	{ st4	[r14],r35; nop.i	0x0; br.call.sptk.many	b0,set_sigchld_handler; }
	{ nop.m	0x0; adds	r1,0xC8,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,stop_making_children; }
	{ nop.m	0x0; adds	r1,0xC8,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,set_sigint_handler; }
	{ nop.m	0x0; adds	r1,0xC8,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,free_pushed_string_input; }
	{ nop.m	0x0; adds	r1,0xC8,r12; addl	r54,1,r0 }
	{ nop.m	0x0; ld4	r53,[r34]; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AE60; }
	{ adds	r1,0xC8,r12; nop.m	0x0; cmp4.lt	p06,p07,r8,r0; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000095140; }

l4000000000094950:
	{ addl	r14,-10356,r1; ld4	r35,[r34]; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r53,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BBC0; }
	{ adds	r1,0xC8,r12; nop.m	0x0; cmp4.eq	p07,p06,r8,r35; }
	{ ld8	r1,[r1]; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000094A80; }

l40000000000949A0:
	{ addl	r14,-10260,r1; ld4	r35,[r34]; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r53,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BBC0; }
	{ adds	r1,0xC8,r12; nop.m	0x0; cmp4.eq	p06,p07,r8,r35; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000094A80; }

l40000000000949F0:
	{ addl	r14,-10652,r1; ld4	r35,[r34]; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r53,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BBC0; }
	{ adds	r1,0xC8,r12; nop.m	0x0; cmp4.eq	p06,p07,r8,r35; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000094A80; }

l4000000000094A40:
	{ ld4	r53,[r34]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C340; }
	{ nop.m	0x0; adds	r1,0xC8,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000094A80:
	{ addl	r14,-10356,r1; nop.m	0x0; adds	r34,0x90,r12; }
	{ ld8	r14,[r14]; ld4	r35,[r34]; nop.i	0x0; }
	{ ld8	r53,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BBC0; }
	{ adds	r1,0xC8,r12; nop.m	0x0; cmp4.eq	p07,p06,r8,r35; }
	{ ld8	r1,[r1]; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000094BA0; }

l4000000000094AD0:
	{ addl	r14,-10260,r1; ld4	r35,[r34]; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r53,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BBC0; }
	{ adds	r1,0xC8,r12; nop.m	0x0; cmp4.eq	p06,p07,r8,r35; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000094BA0; }

l4000000000094B20:
	{ addl	r14,-10652,r1; ld4	r35,[r34]; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r53,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BBC0; }
	{ adds	r1,0xC8,r12; nop.m	0x0; cmp4.eq	p06,p07,r8,r35; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000094BA0; }

l4000000000094B70:
	{ ld4	r53,[r34]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C340; }
	{ nop.m	0x0; adds	r1,0xC8,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0; }

l4000000000094BA0:
	{ addl	r14,9028,r1; addl	r16,6456,r1; addl	r17,6516,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r14]; nop.i	0x0 }
	{ ld4	r16,[r16]; cmp4.eq	p07,p06,0x0,r16; or	r15,0x4,r15 }
	{ st4	[r0],r17; st4	[r15],r14; (p07) addl	r14,7404,r1; }

l4000000000094BF0:
	{ nop.m	0x0; (p07) st4	[r0],r14; adds	r14,0xA0,r12; }

l4000000000094BFC:
	{ (p16) nop; Invalid; break.i	0x1000; }
	{ (p34) nop; cmp.eq	p18,p16,r35,r64; (p33) cmp.lt	p00,p18,r0,r0 }
	{ nop; Invalid; Invalid }
	{ Invalid; Invalid; Invalid }
	{ Invalid; Invalid; break.i	0x1000 }
	{ (p09) nop; invala; cmp.eq	p00,p00,r32,r0 }
	{ nop; Invalid; mov	pr,r32,0x0 }
	{ (p27) cmp.lt	p00,p11,r0,r33; zxt4	r50,r17; break.i	0x1000 }

l4000000000094C70:
	{ addl	r14,9032,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	4000000000095350 }

l4000000000094CA0:
	{ addl	r34,7040,r1; nop.m	0x0; adds	r14,0xA0,r12 }
	{ adds	r15,0xB0,r12; nop.m	0x0; addl	r54,-6692,r1; }
	{ nop.m	0x0; ld8	r53,[r14]; nop.i	0x0; }
	{ ld4	r15,[r15]; ld8	r54,[r54]; nop.i	0x0; }
	{ ld4	r14,[r34]; or	r55,0x4,r15; adds	r14,0x1,r14; }
	{ st4	[r14],r34; nop.i	0x0; br.call.sptk.many	b0,parse_and_execute; }
	{ ld4	r14,[r34]; nop.m	0x0; adds	r1,0xC8,r12; }
	{ ld8	r1,[r1]; nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFFFF,r14; }
	{ st4	[r14],r34; nop.m	0x0; addl	r14,9044,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r8],r14; nop.i	0x0; br.call.sptk.many	b0,run_exit_trap; }
	{ adds	r1,0xC8,r12; nop.m	0x0; adds	r34,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,unlink_fifo_list; }
	{ adds	r1,0xC8,r12; nop.m	0x0; adds	r53,0x0,r34; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B580 }

l4000000000094D90:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r34; (p06) br.cond.dptk.few	4000000000094690; }

l4000000000094DA0:
	{ nop.m	0x0; and	r33,0x3,r33; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r33; (p07) br.cond.dpnt.few	40000000000951A0; }

l4000000000094DC0:
	{ (p06) sub	r18,0x1,r38; nop.m	0x0; nop.i	0x0 }

l4000000000094DC6:
	{ break.m	0x4000; mov	pr,0x4000; break.i	0x80000 }

l4000000000094DD0:
	{ nop.m	0x0; sxt4	r17,r34; adds	r15,0xFFFFFFFFFFFFFFFF,r34; }

l4000000000094DD2:
	{ chk.a.nc	r32,4000000000494DD2; (p32) cmp4.ne.or.andcm	p08,p48,r5,r0; Invalid }

l4000000000094DD6:
	{ (p08) add	r0,r34,r22; (p07) mov.dpnt.imp	b7,r34,4000000000095106; (p32) nop.b	0x114C3 }

l4000000000094DD8:
	{ Invalid; (p52) nop; (p05) break.i	0x10001 }
	{ (p16) cmp4.eq.or	p00,p49,0xFFFFFFFFFFFFFF80,r96; Invalid; (p56) break.i	0x8000 }
	{ (p16) cmp.lt	p00,p01,r0,r96; (p01) tnat.z	p05,p28,r4; Invalid }
	{ Invalid; nop; nop }

l4000000000094E10:
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r14; add	r14,r38,r14; nop.i	0x0; }
	{ ld1	r16,[r14]; nop.m	0x0; sxt1	r16,r16; }
	{ cmp4.eq	p06,p07,0x1,r16; addp4	r16,r15,r0; (p06) br.cond.dpnt.few	4000000000095280; }

l4000000000094E40:
	{ nop.m	0x0; mov.i	LC,r16; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.cloop.sptk.few	4000000000094F50 }

l4000000000094E60:
	{ adds	r17,0x0,r0; nop.m	0x0; nop.i	0x0; }

l4000000000094E70:
	{ nop.m	0x0; add	r17,r38,r17; nop.i	0x0; }
	{ st1	[r0],r17; nop.m	0x0; nop.i	0x0 }

l4000000000094E90:
	{ nop.m	0x0; adds	r14,0x90,r12; nop.i	0x0; }
	{ ld4	r53,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C340; }
	{ adds	r1,0xC8,r12; nop.m	0x0; adds	r53,0x0,r41; }
	{ ld8	r1,[r1]; addl	r14,5956,r1; nop.i	0x0; }
	{ st4	[r41],r14; nop.i	0x0; br.call.sptk.many	b0,wait_for; }
	{ adds	r1,0xC8,r12; ld8	r1,[r1]; nop.i	0x0; }
	{ nop.m	0x0; addl	r14,9044,r1; nop.i	0x0; }
	{ nop.m	0x0; st4	[r8],r14; addl	r14,5960,r1; }
	{ st4	[r41],r14; addl	r14,130,r0; cmp4.eq	p07,p06,r14,r8 }
	{ addl	r14,5876,r1; nop.m	0x0; nop.i	0x0; }
	{ st4	[r47],r14; nop.i	0x0; (p06) br.cond.dptk.few	4000000000094740 }

l4000000000094F40:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000950C0 }

l4000000000094F50:
	{ add	r17,r18,r14; ld1	r16,[r14],-1; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r16,r16; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0xA,r16; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000094E70; }

l4000000000094F80:
	{ ld1	r16,[r14]; adds	r17,0xFFFFFFFFFFFFFFFF,r15; sxt1	r16,r16; }
	{ cmp4.eq	p06,p07,0x1,r16; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000952A0; }

l4000000000094FA0:
	{ nop.m	0x0; adds	r15,0x0,r17; br.cloop.sptk.few	4000000000094F50 }

l4000000000094FB0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000094E60 }

l4000000000094FC0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x4,r8; (p06) br.cond.dpnt.few	40000000000952E0 }

l4000000000094FD0:
	{ nop.m	0x0; addl	r14,9044,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r8,[r14]; addl	r14,9044,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r8],r14; nop.i	0x0; br.call.sptk.many	b0,run_exit_trap; }
	{ adds	r1,0xC8,r12; nop.m	0x0; adds	r34,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,unlink_fifo_list; }
	{ adds	r1,0xC8,r12; nop.m	0x0; adds	r53,0x0,r34; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B580; }

l4000000000095050:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,maybe_make_export_env; }
	{ adds	r1,0xC8,r12; ld8	r1,[r1]; nop.i	0x0; }
	{ addl	r14,6516,r1; nop.m	0x0; nop.i	0x0; }
	{ ld4	r14,[r14]; cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; }
	{ nop.m	0x0; (p06) adds	r14,0xB0,r12; nop.i	0x0; }

l400000000009509C:
	{ Invalid; Invalid; mov	pr,r32,0x0 }

l40000000000950A6:
	{ chk.a.nc	r0,3FFFFFFFFF0958A6; nop; break.i	0x80000 }

l40000000000950B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000943A0 }

l40000000000950C0:
	{ addl	r14,9016,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2,r14; (p06) br.cond.dptk.few	4000000000094740 }

l40000000000950F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B1A0; }
	{ adds	r1,0xC8,r12; adds	r53,0x0,r8; addl	r54,2,r0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B520; }
	{ nop.m	0x0; adds	r1,0xC8,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	4000000000094740; }

l4000000000095140:
	{ addl	r54,-6700,r1; addl	r55,5,r0; adds	r53,0x0,r0; }
	{ ld8	r54,[r54]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0xC8,r12; nop.m	0x0; adds	r53,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,sys_error; }
	{ adds	r1,0xC8,r12; nop.m	0x0; addl	r53,1,r0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B580; }

l40000000000951A0:
	{ adds	r54,0xFFFFFFFFFFFFFFFF,r34; nop.m	0x0; addl	r55,1,r0 }
	{ adds	r53,0x0,r38; nop.m	0x0; br.call.sptk.many	b0,strip_trailing; }
	{ adds	r14,0x90,r12; adds	r1,0xC8,r12; nop.i	0x0 }
	{ ld4	r53,[r14]; ld8	r1,[r1]; br.call.sptk.many	b0,fn400000000001C340; }
	{ adds	r1,0xC8,r12; nop.m	0x0; adds	r53,0x0,r41; }
	{ ld8	r1,[r1]; addl	r14,5956,r1; nop.i	0x0; }
	{ st4	[r41],r14; nop.i	0x0; br.call.sptk.many	b0,wait_for; }
	{ adds	r1,0xC8,r12; ld8	r1,[r1]; nop.i	0x0; }
	{ nop.m	0x0; addl	r14,9044,r1; nop.i	0x0; }
	{ nop.m	0x0; st4	[r8],r14; addl	r14,5960,r1; }
	{ st4	[r41],r14; addl	r14,130,r0; cmp4.eq	p07,p06,r14,r8 }
	{ addl	r14,5876,r1; nop.m	0x0; nop.i	0x0; }
	{ st4	[r47],r14; nop.i	0x0; (p06) br.cond.dptk.few	4000000000094740 }

l4000000000095270:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000950C0 }

l4000000000095280:
	{ adds	r15,0x0,r34; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000952A0:
	{ nop.m	0x0; adds	r34,0xFFFFFFFFFFFFFFFE,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,0x0,r34; (p06) br.cond.dptk.few	4000000000094DD0 }

l40000000000952C0:
	{ nop.m	0x0; sxt4	r17,r34; add	r17,r38,r17; }
	{ st1	[r0],r17; nop.i	0x0; br.cond.sptk.few	4000000000094E90 }

l40000000000952E0:
	{ addl	r14,9044,r1; cmp4.eq	p06,p07,0x3,r8; (p06) br.cond.dpnt.few	4000000000094FD0; }

l40000000000952F0:
	{ nop.m	0x0; nop.m	0x0; (p07) addl	r8,1,r0; }

l4000000000095300:
	{ st4	[r8],r14; nop.i	0x0; br.call.sptk.many	b0,run_exit_trap; }
	{ adds	r1,0xC8,r12; nop.m	0x0; adds	r34,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,unlink_fifo_list; }
	{ adds	r1,0xC8,r12; nop.m	0x0; adds	r53,0x0,r34; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B580; }

l4000000000095350:
	{ addl	r53,22740,r1; nop.m	0x0; addl	r54,1,r0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BD60; }
	{ adds	r1,0xC8,r12; nop.m	0x0; cmp4.eq	p07,p06,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p07) br.cond.spnt.few	4000000000094CA0; }

l4000000000095390:
	{ nop.m	0x0; addl	r14,9012,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r8,[r14]; addl	r14,9044,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r8],r14; nop.i	0x0; br.call.sptk.many	b0,run_exit_trap; }
	{ adds	r1,0xC8,r12; nop.m	0x0; adds	r34,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,unlink_fifo_list; }
	{ adds	r1,0xC8,r12; nop.m	0x0; adds	r53,0x0,r34; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B580; }

l4000000000095410:
	{ adds	r54,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,give_terminal_to; }
	{ nop.m	0x0; adds	r1,0xC8,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,alloc_word_desc; }
	{ adds	r1,0xC8,r12; nop.m	0x0; adds	r14,0x0,r8; }
	{ ld8	r1,[r1]; st8	[r14],r8,8; nop.i	0x0; }
	{ st4	[r44],r14; nop.i	0x0; br.cond.sptk.few	4000000000094820 }

l4000000000095470:
	{ adds	r16,0x0,r0; adds	r15,0x0,r0; br.cond.sptk.few	40000000000941A0 }

l4000000000095480:
	{ nop.m	0x0; addl	r54,-6708,r1; nop.i	0x0; }
	{ ld8	r54,[r54]; nop.m	0x0; nop.i	0x0 }

l40000000000954A0:
	{ addl	r55,5,r0; adds	r53,0x0,r0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0xC8,r12; nop.m	0x0; adds	r53,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,sys_error; }
	{ adds	r14,0x90,r12; adds	r1,0xC8,r12; nop.i	0x0 }
	{ ld4	r53,[r14]; ld8	r1,[r1]; br.call.sptk.many	b0,fn400000000001C340; }
	{ adds	r14,0x94,r12; adds	r1,0xC8,r12; nop.i	0x0 }
	{ ld8	r1,[r1]; ld4	r53,[r14]; br.call.sptk.many	b0,fn400000000001C340; }
	{ adds	r1,0xC8,r12; nop.m	0x0; adds	r8,0x0,r0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	40000000000944F0 }

l4000000000095530:
	{ adds	r14,0x90,r12; adds	r44,0x0,r0; adds	r38,0x0,r0; }
	{ ld4	r53,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C340; }
	{ adds	r1,0xC8,r12; nop.m	0x0; adds	r53,0x0,r41; }
	{ ld8	r1,[r1]; addl	r14,5956,r1; nop.i	0x0; }
	{ st4	[r41],r14; nop.i	0x0; br.call.sptk.many	b0,wait_for; }
	{ adds	r1,0xC8,r12; ld8	r1,[r1]; nop.i	0x0; }
	{ nop.m	0x0; addl	r14,9044,r1; nop.i	0x0; }
	{ nop.m	0x0; st4	[r8],r14; addl	r14,5960,r1; }
	{ st4	[r41],r14; addl	r14,130,r0; cmp4.eq	p07,p06,r14,r8 }
	{ addl	r14,5876,r1; nop.m	0x0; nop.i	0x0; }
	{ st4	[r47],r14; nop.i	0x0; (p06) br.cond.dptk.few	4000000000094740 }

l40000000000955E0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000950C0; }
40000000000955F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; pat_subst: 4000000000095600
;;   Called from:
;;     40000000000BDCCC (in array_patsub)
;;     40000000000C434C (in assoc_patsub)
pat_subst proc
	{ alloc	r65,ar.pfs,0x2A,0x0,0x25; adds	r12,0xFFFFFFFFFFFFFFC0,r12; mov	r67,pr }
	{ adds	r66,0x0,r1; cmp.eq	p07,p06,0x0,r32; and	r47,0x3,r35; }
	{ nop.m	0x0; mov	r68,LC; cmp.eq	p24,p25,0x0,r33; }
	{ nop.m	0x0; mov	r64,b0; nop.i	0x0 }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	4000000000096C20; (p24) br.cond.dpnt.few	4000000000095990; }

l400000000009564C:
	{ (p26) cmp.lt	p00,p11,r64,r33; Invalid; Invalid }

l4000000000095650:
	{ ld1	r14,[r33]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	4000000000095990 }

l4000000000095670:
	{ addl	r69,64,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r66; st1	[r0],r8; nop.i	0x0 }
	{ adds	r39,0x0,r8; cmp.eq	p06,p07,0x0,r34; (p06) br.cond.dpnt.few	4000000000095BA0; }

l40000000000956A0:
	{ ld1	r14,[r34]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000095BA0 }

l40000000000956C0:
	{ adds	r14,0x1,r34; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r41,1,r0; (p06) br.cond.dptk.few	4000000000095740 }

l40000000000956EC:
	{ (p03) cmp.lt	p00,p11,r0,r33; (p33) cmp.lt.unc	p00,p16,r8,r64; Invalid }

l40000000000956F0:
	{ adds	r14,0x2,r34; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r41,2,r0; (p06) br.cond.dptk.few	4000000000095740 }

l400000000009571C:
	{ (p01) nop; zxt1	r64,r64; break.b	0x1000 }

l4000000000095720:
	{ adds	r69,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; adds	r1,0x0,r66; adds	r41,0x0,r8; }

l4000000000095740:
	{ addl	r45,7664,r1; addl	r37,64,r0; adds	r38,0x0,r0 }
	{ adds	r53,0x18,r12; adds	r56,0x20,r12; cmp4.eq	p26,p27,0x1,r47; }
	{ adds	r40,0x30,r12; nop.m	0x0; adds	r42,0x28,r12 }
	{ cmp4.eq	p28,p29,0x2,r47; cmp4.eq	p30,p31,0x0,r47; addl	r60,42,r0; }
	{ nop.m	0x0; cmp4.eq	p18,p19,0x0,r41; tnat.z	p16,p17,r35 }
	{ nop.m	0x0; cmp4.eq	p21,p20,0x0,r47; sxt4	r54,r41; }

l40000000000957A0:
	{ ld1	r14,[r32]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	4000000000096730; (p24) br.cond.dpnt.few	4000000000096730; }

l40000000000957BC:
	{ (p60) cmp.lt	p01,p03,r64,r33; (p01) cmp.lt	p32,p08,r8,r0; cmp.lt	p00,p28,r104,r65 }

l40000000000957C0:
	{ ld1	r14,[r33]; cmp.eq	p06,p07,0x0,r32; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p08,p09,0x0,r14; (p09) br.cond.dpnt.few	4000000000095E40; }

l40000000000957E0:
	{ nop.m	0x0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000966E0; }

l40000000000957F0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000095800:
	{ ld1	r14,[r32]; adds	r15,0x1,r32; sxt4	r36,r38; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000966E0 }

l4000000000095830:
	{ ld1	r14,[r15]; adds	r16,0x2,r32; addl	r8,2,r0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p16,p17,0x0,r14; (p16) br.cond.dptk.few	40000000000958C0 }

l4000000000095860:
	{ ld1	r14,[r16]; adds	r69,0x0,r32; addl	r8,3,r0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000958C0 }

l4000000000095890:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; adds	r1,0x0,r66; adds	r8,0x1,r8; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000958C0:
	{ nop.m	0x0; sxt4	r37,r37; add	r8,r8,r36; }
	{ nop.m	0x0; cmp.ltu	p06,p07,r8,r37; (p06) br.cond.dptk.few	40000000000965B0 }

l40000000000958E0:
	{ adds	r38,0x2,r32; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000095900:
	{ nop.m	0x0; (p16) addl	r8,2,r0; (p16) br.cond.dptk.few	4000000000095960; }

l400000000009590C:
	{ (p03) cmp.eq	p00,p09,r0,r33; (p01) nop; zxt1	r0,r64 }

l4000000000095910:
	{ ld1	r15,[r38]; adds	r69,0x0,r32; addl	r8,3,r0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	4000000000095960 }

l4000000000095940:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; adds	r1,0x0,r66; adds	r8,0x1,r8; }

l4000000000095960:
	{ add	r14,r8,r36; nop.m	0x0; adds	r15,0x40,r37; }
	{ cmp.ltu	p07,p06,r14,r37; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000096590; }

l4000000000095980:
	{ nop.m	0x0; adds	r37,0x0,r15; br.cond.sptk.few	4000000000095900 }

l4000000000095990:
	{ nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFFFF,r47; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x1,r14; (p06) br.cond.dptk.few	4000000000095670; }

l40000000000959B0:
	{ cmp.eq	p06,p07,0x0,r34; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000096B70; }

l40000000000959C0:
	{ ld1	r14,[r34]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000096B70 }

l40000000000959E0:
	{ adds	r14,0x1,r34; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r36,1,r0; (p06) br.cond.dptk.few	4000000000095A60 }

l4000000000095A0C:
	{ (p03) cmp.lt	p00,p11,r0,r33; (p33) cmp.lt.unc	p00,p16,r8,r64; Invalid }

l4000000000095A10:
	{ adds	r14,0x2,r34; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r36,2,r0; (p06) br.cond.dptk.few	4000000000095A60 }

l4000000000095A3C:
	{ (p01) nop; zxt1	r64,r64; break.b	0x1000 }

l4000000000095A40:
	{ adds	r69,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; adds	r1,0x0,r66; adds	r36,0x0,r8; }

l4000000000095A60:
	{ nop.m	0x0; ld1	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) adds	r37,0x0,r0; (p06) br.cond.dptk.few	4000000000095AD0 }

l4000000000095A8C:
	{ (p02) cmp.lt	p00,p11,r0,r33; (p17) cmp.lt	p00,p16,r8,r64; (p01) rfi }

l4000000000095A90:
	{ adds	r14,0x1,r32; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	4000000000096C70; }

l4000000000095AC0:
	{ (p06) addl	r37,1,r0; nop.m	0x0; nop.i	0x0; }

l4000000000095AC6:
	{ break.m	0x4000; nop; (p16) nop }

l4000000000095AD0:
	{ add	r69,r36,r37; adds	r69,0x2,r69; nop.i	0x0; }

l4000000000095AD2:
	{ (p20) ld4.a	r9,[r16],0; (p16) break.b	0x42011; clrrrb }

l4000000000095AD6:
	{ Invalid; nop; break.b	0x80000 }

l4000000000095AD8:
	{ Invalid; Invalid; Invalid }

l4000000000095ADE:
	{ break.m	0x220; (p26) nop }

l4000000000095AE8:
	{ Invalid; Invalid; Invalid }

l4000000000095AEE:
	{ nop; nop; }

l4000000000095AF2:
	{ Invalid; zxt1	r2,r16; (p32) nop }
	{ chk.s.m	r64,400000000089DB22; add	r8,r64,r112,0x1; (p21) nop }
	{ (p48) break.m	0x730CB; (p35) nop }
	{ break.m	0x20; cmp.ltu	p32,p00,r0,r0; (p44) break.i	0x2C7C2 }
	{ chk.s.m	r0,4000000000495D32; zxt1	r73,r0; Invalid }
	{ chk.s.m	r0,4000000000895D42; (p32) break.i	0x42008; nop }
	{ Invalid; Invalid; Invalid }
	{ (p48) invala; Invalid; (p08) break.i	0x85BFC }
	{ nop; (p08) break.i	0x550; break.i	0x20 }
	{ add	r32,r0,r0; (p24) break.i	0x550; Invalid }
	{ Invalid; (p08) nop; dep	r32,r8,r0,31,3 }

l4000000000095BA0:
	{ adds	r41,0x0,r0; addl	r45,7664,r1; addl	r37,64,r0 }
	{ adds	r38,0x0,r0; adds	r53,0x18,r12; adds	r56,0x20,r12; }
	{ cmp4.eq	p26,p27,0x1,r47; adds	r40,0x30,r12; adds	r42,0x28,r12 }
	{ nop.m	0x0; cmp4.eq	p28,p29,0x2,r47; cmp4.eq	p30,p31,0x0,r47; }
	{ addl	r60,42,r0; cmp4.eq	p18,p19,0x0,r41; tnat.z	p16,p17,r35 }
	{ cmp4.eq	p21,p20,0x0,r47; sxt4	r54,r41; br.cond.sptk.few	40000000000957A0 }
4000000000095C00 08 70 00 7C 18 10 00 70 91 20 23 C0 B7 F2 49 80 .p.|...p. #...I.
4000000000095C10 09 58 05 00 00 24 50 04 D4 30 20 00 00 00 04 00 .X...$P..0 .....
4000000000095C20 0B 00 38 50 98 11 E0 00 F8 30 20 00 00 00 04 00 ..8P.....0 .....
4000000000095C30 11 00 38 54 98 11 00 00 00 02 00 00 B8 4B F8 58 ..8T.........K.X
4000000000095C40 08 00 00 00 01 00 10 00 08 01 42 00 00 00 04 00 ..........B.....
4000000000095C50 19 28 02 70 18 10 00 00 00 02 00 00 98 4B F8 58 .(.p.........K.X
4000000000095C60 02 70 40 18 00 21 10 00 08 01 42 00 00 00 04 00 .p@..!....B.....
4000000000095C70 19 28 02 1C 18 10 00 00 00 02 00 00 78 4B F8 58 .(..........xK.X
4000000000095C80 09 08 00 84 00 21 00 00 00 02 00 00 00 00 04 00 .....!..........
4000000000095C90 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

l4000000000095CA0:
	{ cmp4.eq	p06,p07,0x0,r43; nop.i	0x0; (p06) br.cond.spnt.few	4000000000095800; }

l4000000000095CB0:
	{ ld8	r36,[r40]; sub	r36,r36,r32; nop.i	0x0; }
	{ add	r14,r41,r36; add	r14,r14,r38; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r14,r37; (p06) br.cond.dptk.few	4000000000095D30 }

l4000000000095CE0:
	{ sub	r14,r14,r37; adds	r37,0x40,r37; adds	r69,0x0,r39; }
	{ nop.m	0x0; extr	r14,r14,6,26; dep.z	r14,r14,6,26; }
	{ nop.m	0x0; add	r37,r37,r14; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r70,r37; br.call.sptk.many	b0,xrealloc; }
	{ nop.m	0x0; adds	r1,0x0,r66; adds	r39,0x0,r8 }

l4000000000095D30:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r36; (p06) br.cond.dptk.few	4000000000095D80 }

l4000000000095D40:
	{ nop.m	0x0; sxt4	r69,r38; nop.b	0x0 }
	{ adds	r70,0x0,r32; add	r38,r38,r36; sxt4	r71,r36; }
	{ nop.m	0x0; add	r69,r39,r69; br.call.sptk.many	b0,fn400000000001B920; }
	{ adds	r1,0x0,r66; nop.m	0x0; nop.i	0x0 }

l4000000000095D80:
	{ nop.m	0x0; sxt4	r69,r38; nop.b	0x0 }
	{ (p19) adds	r70,0x0,r34; (p19) adds	r71,0x0,r54; (p19) add	r38,r38,r41; }

l4000000000095D96:
	{ Invalid; Invalid; Invalid }

l4000000000095D9C:
	{ (p19) nop; nop }

l4000000000095DA0:
	{ (p19) add	r69,r39,r69; nop.i	0x0; (p19) br.call.dpnt.many	b0,fn400000000001B920; }

l4000000000095DA6:
	{ nop; (p32) cmp.ltu	p56,p45,r11,r126; (p20) nop }

l4000000000095DB0:
	{ (p19) adds	r1,0x0,r66; ld8	r32,[r42]; nop.i	0x0 }

l4000000000095DB6:
	{ (p16) fwb; nop; break.i	0x100000 }
	{ nop; break.x	0x18004B8080000 }

l4000000000095DCC:
	{ (p11) nop; cmp.lt	p00,p00,r32,r0; (p01) rfi }

l4000000000095DD0:
	{ nop.m	0x0; ld8	r14,[r40]; nop.i	0x0; }
	{ cmp.eq	p07,p06,r14,r32; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000096610; }

l4000000000095DF0:
	{ cmp.eq	p06,p07,0x0,r32; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000966E0; }

l4000000000095E00:
	{ ld1	r14,[r32]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p08,p09,0x0,r14; nop.i	0x0; (p08) br.cond.dpnt.few	40000000000957E0; }

l4000000000095E20:
	{ ld1	r14,[r33]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p08,p09,0x0,r14; (p08) br.cond.dptk.few	40000000000957E0 }

l4000000000095E40:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ cmp.ltu	p07,p06,0x1,r8; nop.m	0x0; adds	r1,0x0,r66 }
	{ adds	r69,0x0,r32; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000964B0; }

l4000000000095E70:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,mbsmbchar; }
	{ adds	r1,0x0,r66; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	4000000000096470 }

l4000000000095E90:
	{ adds	r69,0x0,r53; nop.m	0x0; adds	r70,0x0,r0 }
	{ adds	r71,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,xdupmbstowcs; }
	{ cmp.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; adds	r1,0x0,r66; adds	r71,0x0,r32 }
	{ adds	r69,0x0,r56; adds	r70,0x10,r12; (p07) br.cond.dpnt.few	40000000000964A0; }

l4000000000095ED0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,xdupmbstowcs; }
	{ adds	r1,0x0,r66; cmp.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; nop.i	0x0 }
	{ adds	r14,0x10,r12; adds	r49,0x0,r8; (p07) br.cond.dpnt.few	4000000000096760; }

l4000000000095F00:
	{ ld8	r44,[r53]; ld8	r62,[r14]; nop.i	0x0; }
	{ ld8	r48,[r56]; ld4	r14,[r44]; nop.i	0x0; }
	{ cmp4.eq	p09,p08,0x2A,r14; cmp4.eq	p07,p06,0x5C,r14; (p08) addl	r36,1,r0 }

l4000000000095F30:
	{ (p06) addl	r15,1,r0; (p09) adds	r36,0x0,r0; (p07) adds	r15,0x0,r0; }

l4000000000095F36:
	{ Invalid; (p07) mov.sptk	b0,r0,4000000000096036; break.i	0x80000 }

l4000000000095F3C:
	{ Invalid; break.i	0x1000; (p02) cmp.eq	p00,p00,r9,r4; }

l4000000000095F40:
	{ nop.m	0x0; zxt1	r16,r36; and	r15,r15,r16; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	4000000000096750; }

l4000000000095F60:
	{ cmp4.eq	p06,p07,0x3F,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000096750; }

l4000000000095F70:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5B,r14; nop.i	0x0; }
	{ (p06) addl	r46,1,r0; nop.i	0x0; (p07) adds	r46,0x0,r0 }

l4000000000095F86:
	{ chk.a.nc	f0,3FFFFFFFFF096786; (p23) nop; (p48) nop }

l4000000000095F90:
	{ ld4	r43,[r45]; cmp4.eq	p06,p07,0x0,r43; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r71,0x0,r0; nop.i	0x0; }

l4000000000095FAC:
	{ invala; cmp4.eq.or.andcm	p00,p00,r32,r0; (p24) mov	pr,r0,0x8400 }

l4000000000095FBC:
	{ (p01) cmp.eq	p00,p11,r0,r33; (p01) cmp.eq	p01,p16,r11,r64; (p01) rfi }

l4000000000095FC0:
	{ adds	r15,0x4,r44; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x28,r15; (p07) br.cond.dpnt.few	4000000000096780 }

l4000000000095FE0:
	{ adds	r14,0x40,r12; nop.m	0x0; adds	r69,0x0,r44; }
	{ st8	[r71],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BD40; }
	{ adds	r14,0x40,r12; nop.m	0x0; adds	r1,0x0,r66 }
	{ cmp4.eq	p07,p06,0x0,r36; nop.m	0x0; (p06) br.cond.dptk.few	4000000000096080; }

l4000000000096020:
	{ ld8	r71,[r14]; nop.m	0x0; nop.i	0x0 }
	{ adds	r15,0x4,r44; ld4	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x28,r14; (p07) br.cond.dpnt.few	4000000000096800 }

l4000000000096050:
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r8; shladd	r14,r14,0x2,r44; nop.i	0x0; }
	{ ld4	r14,[r14]; cmp4.eq	p06,p07,0x2A,r14; nop.i	0x0; }
	{ nop.m	0x0; (p06) adds	r36,0x0,r44; (p06) br.cond.dpnt.few	40000000000961B0 }

l400000000009607C:
	{ (p10) nop; nop; zxt1	r0,r64 }

l4000000000096080:
	{ nop.m	0x0; adds	r69,0x3,r8; nop.i	0x0; }
	{ shladd	r69,r69,0x2,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ ld4	r14,[r44]; adds	r1,0x0,r66; adds	r36,0x0,r8; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2A,r14; (p07) br.cond.dpnt.few	40000000000964E0 }

l40000000000960C0:
	{ ld4.a	r14,[r44]; adds	r17,0x0,r36; cmp4.eq	p07,p06,0x0,r14 }
	{ st4	[r17],r4,4; chk.a.clr	r14,4000000000096D60; nop.i	0x0 }

l40000000000960DC:
	{ cmp4.eq.or.andcm	p00,p00,r1,r0; zxt1	r1,r64; break.i	0x1000 }

l40000000000960E0:
	{ (p06) adds	r15,0x4,r44; nop.i	0x0; nop.i	0x0 }

l40000000000960E6:
	{ break.m	0x4000; nop; cmp.lt	p00,p00,r0,r32 }
	{ (p09) chk.a.clr	f0,3FFFFFFFFF1163B6; nop; nop; }

l40000000000960FC:
	{ (p03) nop; zxt1	r32,r64; break.i	0x1000 }

l4000000000096100:
	{ adds	r16,0x0,r17; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000096120:
	{ st4	[r16],r4,4; nop.m	0x0; adds	r18,0x0,r15; }
	{ adds	r17,0x0,r16; ld4	r14,[r15],4; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000096120 }

l4000000000096150:
	{ adds	r14,0xFFFFFFFFFFFFFFFC,r18; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2A,r14; (p07) br.cond.dpnt.few	4000000000096520 }

l4000000000096170:
	{ ld4.a	r43,[r45]; st4	[r17],r4,4; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r43; st4	[r0],r17; nop.i	0x0; }
	{ chk.a.clr	r43,4000000000096D80; nop.i	0x0; nop.i	0x0 }

l4000000000096196:
	{ break.m	0x4000; addl	r0,49152,r1; (p49) cmp.eq.or.andcm	p49,p00,r0,r0 }

l40000000000961A0:
	{ (p06) adds	r71,0x1,r0; (p07) adds	r71,0x0,r0; nop.i	0x0; }

l40000000000961A6:
	{ Invalid; break.i	0x4000; break.b	0x80000; }

l40000000000961AC:
	{ break.m	0x80; cmp.eq	p00,p00,r32,r0; nop }

l40000000000961B0:
	{ nop.m	0x0; tbit.z	p07,p06,r71,0x0; adds	r69,0x0,r36 }

l40000000000961B2:
	{ Invalid; (p48) nop; nop }

l40000000000961B6:
	{ Invalid; (p34) nop; Invalid }
	{ Invalid; nop; (p49) nop.b	0x11; }
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ Invalid; nop; (p48) nop.b	0x800A }
	{ (p34) chk.a.clr	r0,3FFFFFFFFF116436; nop; break.b	0x80000 }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; nop; (p48) nop }
	{ add	r0,r0,r1; (p34) nop; (p32) nop }
	{ chk.a.nc	f0,3FFFFFFFFF096A36; nop; break.i	0x80000 }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ add	r0,r0,r1; (p30) nop; (p06) nop }
	{ Invalid; Invalid; Invalid }
	{ Invalid; (p29) nop; nop }
	{ Invalid; (p11) nop; break.i	0x80000 }
	{ break.m	0x4000; nop; (p48) nop }
	{ (p26) ld1.a.nt1	r0,[r0]; nop; (p48) nop }
	{ (p07) fwb; nop; nop }
	{ Invalid; nop; add	r0,r0,r32 }
	{ Invalid; cmp4.lt	p00,p00,0x0,r1; (p33) nop; }
	{ break.m	0x4000; (p04) nop; break.i	0x80000 }
	{ (p03) chk.a.clr	f0,3FFFFFFFFFD59376; cmp4.ltu	p15,p33,r0,r0; (p56) nop.b	0x3B7AC }
	{ Invalid; Invalid; (p56) nop.b	0x3100C }
	{ break.m	0x4000; (p25) nop; (p32) nop }
	{ Invalid; (p04) nop; break.b	0x100000 }
	{ chk.a.nc	r13,3FFFFFFFFF8F6336; nop; (p48) nop }
	{ Invalid; (p34) nop; nop.b	0x24029 }
	{ (p23) fwb; (p35) nop; break.i	0x80000 }
	{ mf.a; (p03) nop; (p48) chk.s.i	r40,4000000000496A76 }
	{ break.m	0x4000; cmp4.lt	p00,p00,r0,r1; (p49) nop }
	{ break.m	0x4000; nop; (p49) nop }
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ add	r0,r0,r1; (p03) nop; (p16) nop }
	{ chk.a.nc	f0,3FFFFFFFFF096BB6; nop; break.i	0x80000 }
	{ (p62) xor	r46,0x2B,r17; (p03) nop; add	r0,r0,r0 }
	{ chk.a.nc	r1,3FFFFFFFFF8F63D6; break.x	0x57FFFB8080000; }
	{ Invalid; nop; (p48) nop }
	{ (p03) chk.a.clr	r63,3FFFFFFFFFC99796; nop; (p48) nop.b	0xA }
	{ break.m	0x4000; nop; (p16) nop }
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; nop; (p16) br.call.sptk.few	b1,b0 }
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ add	r0,r0,r1; nop; (p16) nop }
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; nop; (p16) nop.b	0x21011 }

l4000000000096470:
	{ adds	r69,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,mbsmbchar; }
	{ adds	r1,0x0,r66; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	4000000000095E90; }

l4000000000096490:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000964A0:
	{ adds	r69,0x0,r32; nop.m	0x0; nop.i	0x0 }

l40000000000964B0:
	{ adds	r70,0x0,r33; adds	r71,0x0,r47; nop.i	0x0 }
	{ adds	r72,0x0,r40; adds	r73,0x0,r42; br.call.sptk.many	b0,fn4000000000085E80; }
	{ adds	r1,0x0,r66; adds	r43,0x0,r8; br.cond.sptk.few	4000000000095CA0 }

l40000000000964E0:
	{ adds	r15,0x4,r44; ld4	r16,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x28,r16; (p07) br.cond.dpnt.few	4000000000096860 }

l4000000000096500:
	{ nop.m	0x0; adds	r17,0x0,r36; nop.i	0x0; }
	{ nop.m	0x0; adds	r16,0x0,r17; br.cond.sptk.few	4000000000096120 }

l4000000000096520:
	{ adds	r18,0xFFFFFFFFFFFFFFF8,r18; ld4	r14,[r18]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x5C,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000096170; }

l4000000000096540:
	{ ld4.a	r43,[r45]; st4	[r0],r17; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r43; chk.a.clr	r43,4000000000096DC0; nop.i	0x0 }

l400000000009655C:
	{ nop.m	0x80; break.i	0x1000; break.i	0x1000 }

l4000000000096560:
	{ nop.m	0x0; nop.i	0x0; nop.i	0x0; }
	{ nop.m	0x0; (p06) adds	r71,0x1,r0; nop.i	0x0; }

l400000000009657C:
	{ invala; cmp4.eq.or.andcm	p00,p32,r32,r0; zxt1	r0,r64 }

l400000000009658C:
	{ (p33) nop; (p08) cmp.lt.unc	p32,p16,r9,r64; (p08) epc }

l4000000000096590:
	{ adds	r69,0x0,r39; adds	r70,0x0,r37; br.call.sptk.many	b0,xrealloc; }
	{ nop.m	0x0; adds	r1,0x0,r66; adds	r39,0x0,r8; }

l40000000000965B0:
	{ add	r69,r39,r36; nop.m	0x0; nop.i	0x0 }
	{ adds	r70,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r8,0x0,r39; adds	r1,0x0,r66; mov	pr,r67,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r65; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r68; mov.spnt	b0,r64,40000000000965F0 }
	{ nop.m	0x0; adds	r12,0x40,r12; br.ret	b0 }

l4000000000096610:
	{ adds	r36,0x0,r38; nop.m	0x0; adds	r14,0x40,r37 }
	{ adds	r38,0x1,r38; nop.m	0x0; adds	r69,0x0,r39; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r38,r37; (p06) br.cond.dptk.few	4000000000096680 }

l4000000000096640:
	{ sub	r37,r38,r37; nop.m	0x0; extr	r37,r37,6,26; }
	{ nop.m	0x0; dep.z	r37,0x25,6,26; add	r37,r14,r37; }
	{ nop.m	0x0; sxt4	r70,r37; br.call.sptk.many	b0,xrealloc; }
	{ nop.m	0x0; adds	r1,0x0,r66; adds	r39,0x0,r8 }

l4000000000096680:
	{ nop.m	0x0; sxt4	r36,r36; nop.i	0x0 }
	{ ld1	r14,[r32],1; add	r36,r39,r36; cmp.eq	p06,p07,0x0,r32; }
	{ st1	[r14],r36; ld8	r14,[r42]; nop.i	0x0; }
	{ nop.m	0x0; adds	r14,0x1,r14; nop.i	0x0; }
	{ st8	[r14],r42; nop.i	0x0; (p07) br.cond.dptk.few	40000000000957A0; }

l40000000000966D0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000966E0:
	{ nop.m	0x0; sxt4	r14,r38; adds	r8,0x0,r39; }
	{ add	r14,r39,r14; st1	[r0],r14; mov	pr,r67,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r65; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r68; mov.spnt	b0,r64,4000000000096710 }
	{ nop.m	0x0; adds	r12,0x40,r12; br.ret	b0 }

l4000000000096730:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r32; (p07) br.cond.dptk.few	4000000000095800 }

l4000000000096740:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000966E0 }

l4000000000096750:
	{ nop.m	0x0; adds	r46,0x0,r0; br.cond.sptk.few	4000000000095F90; }

l4000000000096760:
	{ ld8	r69,[r53]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r66; adds	r69,0x0,r32; br.cond.sptk.few	40000000000964B0 }

l4000000000096780:
	{ cmp4.eq	p07,p06,0x3F,r14; (p06) addl	r15,1,r0; nop.i	0x0; }

l400000000009678C:
	{ cmp4.eq.or.andcm	p00,p43,r1,r0; zxt1	r0,r64; zxt1	r3,r3 }

l4000000000096796:
	{ Invalid; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD5A0A6; nop; (p32) nop }

l40000000000967B0:
	{ cmp4.eq	p06,p07,0x2B,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000968D0; }

l40000000000967C0:
	{ cmp4.eq	p06,p07,0x21,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000968D0; }

l40000000000967D0:
	{ cmp4.eq	p07,p06,0x40,r14; (p06) addl	r14,1,r0; nop.i	0x0; }

l40000000000967DC:
	{ nop; cmp4.eq.and	p00,p32,r32,r0; zxt1	r0,r64 }

l40000000000967EC:
	{ invala; cmp.lt	p00,p00,r32,r0; zxt1	r75,r3 }
	{ (p63) invala; cmp.eq	p00,p00,r32,r0; nop }

l4000000000096800:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r43; (p07) br.cond.dptk.few	4000000000096050 }

l4000000000096810:
	{ nop.m	0x0; adds	r69,0x3,r8; nop.i	0x0; }
	{ shladd	r69,r69,0x2,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ ld4	r14,[r44]; adds	r1,0x0,r66; adds	r36,0x0,r8; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2A,r14; (p06) br.cond.dptk.few	40000000000960C0 }

l4000000000096850:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000964E0 }

l4000000000096860:
	{ nop.m	0x0; ld4	r16,[r45]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r16; (p06) br.cond.dptk.few	4000000000096500 }

l4000000000096880:
	{ ld4.a	r14,[r44]; adds	r17,0x0,r36; cmp4.eq	p07,p06,0x0,r14 }
	{ st4	[r17],r4,4; chk.a.clr	r14,4000000000096DE0; nop.i	0x0 }

l400000000009689C:
	{ Invalid; zxt1	r0,r64; break.i	0x1000 }

l40000000000968A0:
	{ (p07) adds	r18,0x0,r44; nop.i	0x0; nop.i	0x0 }

l40000000000968A6:
	{ break.m	0x4000; nop; add	r0,r0,r32 }
	{ (p07) chk.a.clr	r4,3FFFFFFFFF116B76; nop; break.b	0x80000; }

l40000000000968BC:
	{ (p02) invala; break.i	0x1000; break.b	0x1000 }

l40000000000968C0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000096150 }

l40000000000968D0:
	{ nop.m	0x0; adds	r46,0x0,r0; br.cond.sptk.few	4000000000095FE0 }
40000000000968E0 09 B8 E9 00 11 20 00 00 00 02 00 A0 08 60 01 84 ..... .......`..
40000000000968F0 11 30 C2 6E 00 20 00 00 00 02 00 00 98 18 09 50 .0.n. .........P
4000000000096900 10 00 00 00 01 00 10 00 08 01 42 00 F0 F9 FF 48 ..........B....H
4000000000096910 11 58 C5 10 05 20 70 F9 23 2C F7 0B B0 03 00 43 .X... p.#,.....C
4000000000096920 02 00 00 00 01 00 B0 02 AC 2C 00 E0 10 5B 19 D0 .........,...[..
4000000000096930 19 20 01 56 00 21 B0 0A AC 00 C2 03 D0 FA FF 4B . .V.!.........K
4000000000096940 09 38 02 5A 10 10 60 24 C1 22 40 A0 08 60 01 84 .8.Z..`$."@..`..
4000000000096950 0B 30 00 8E 87 F9 71 04 01 00 48 00 00 00 04 00 .0....q...H.....
4000000000096960 D1 38 02 00 00 21 00 00 00 02 00 00 A8 B3 08 50 .8...!.........P
4000000000096970 08 08 00 84 00 21 00 00 00 02 00 E0 00 40 18 E6 .....!.......@..
4000000000096980 17 00 00 00 00 C8 01 00 01 80 21 0B 80 FA FF 4B ..........!....K
4000000000096990 09 20 01 56 00 21 00 00 00 02 00 60 15 58 01 84 . .V.!.....`.X..
40000000000969A0 10 00 00 00 01 00 70 88 91 0C 68 03 A0 FF FF 4A ......p...h....J
40000000000969B0 10 00 00 00 01 00 B0 02 00 00 42 00 60 FA FF 48 ..........B.`..H
40000000000969C0 08 B8 FC 7B 96 3B 00 00 00 02 00 A0 08 60 01 84 ...{.;.......`..
40000000000969D0 19 30 02 60 00 21 00 00 00 02 00 00 B8 17 09 50 .0.`.!.........P
40000000000969E0 08 30 00 10 87 39 00 00 00 02 00 6B 05 E8 01 84 .0...9.....k....
40000000000969F0 19 08 00 84 00 21 00 00 00 02 00 03 10 FA FF 4B .....!.........K
4000000000096A00 09 00 00 00 01 C0 B5 02 C4 00 42 00 00 00 04 00 ..........B.....
4000000000096A10 11 30 AC 00 87 30 B0 02 AC 2C 00 03 F0 F9 FF 4B .0...0...,.....K
4000000000096A20 09 00 00 00 01 00 40 5A C1 22 40 00 B0 0A AA 00 ......@Z."@.....
4000000000096A30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000096A40 08 38 02 5A 50 10 50 04 B0 00 42 C0 08 80 01 84 .8.ZP.P...B.....
4000000000096A50 09 70 01 48 10 10 00 00 90 20 23 00 00 00 04 00 .p.H..... #.....
4000000000096A60 0B 38 02 5A 10 11 60 00 1C 0F 73 00 00 00 04 00 .8.Z..`...s.....
4000000000096A70 09 00 00 00 01 C0 71 04 01 00 48 00 00 00 04 00 ......q...H.....
4000000000096A80 D1 38 02 00 00 21 00 00 00 02 00 00 88 B2 08 50 .8...!.........P
4000000000096A90 11 08 00 84 00 21 70 00 20 0C F3 03 70 F1 FF 4B .....!p. ...p..K
4000000000096AA0 08 00 00 00 01 00 C0 77 91 22 2F 60 F5 5F FD 8C .......w."/`._..
4000000000096AB0 17 00 00 00 00 88 05 A8 FC FF 25 A0 90 FF FF 48 ..........%....H
4000000000096AC0 11 00 00 00 01 00 B0 02 00 00 42 00 50 F9 FF 48 ..........B.P..H
4000000000096AD0 08 D0 E9 7C 12 20 00 70 AD 20 23 00 00 00 04 00 ...|. .p. #.....
4000000000096AE0 09 C8 E5 7C 12 20 50 04 D4 30 20 60 15 00 00 90 ...|. P..0 `....
4000000000096AF0 0B 70 00 74 18 10 00 70 A0 30 23 00 00 00 04 00 .p.t...p.0#.....
4000000000096B00 09 00 00 00 01 00 E0 00 E4 30 20 00 00 00 04 00 .........0 .....
4000000000096B10 11 00 38 54 98 11 00 00 00 02 00 00 D8 3C F8 58 ..8T.........<.X
4000000000096B20 08 00 00 00 01 00 10 00 08 01 42 00 00 00 04 00 ..........B.....
4000000000096B30 19 28 02 70 18 10 00 00 00 02 00 00 B8 3C F8 58 .(.p.........<.X
4000000000096B40 09 70 40 18 00 21 00 00 00 02 00 20 00 10 02 84 .p@..!..... ....
4000000000096B50 11 28 02 1C 18 10 00 00 00 02 00 00 98 3C F8 58 .(...........<.X
4000000000096B60 10 00 00 00 01 00 10 00 08 01 42 00 40 F1 FF 48 ..........B.@..H

l4000000000096B70:
	{ nop.m	0x0; adds	r36,0x0,r0; br.cond.sptk.few	4000000000095A60; }
4000000000096B80 08 20 91 7C 12 20 00 00 00 02 00 20 16 F3 49 80 . .|. ..... ..I.
4000000000096B90 09 28 02 6A 18 10 00 00 00 02 00 60 15 00 00 90 .(.j.......`....
4000000000096BA0 0B 70 00 48 18 10 00 70 A0 30 23 00 00 00 04 00 .p.H...p.0#.....
4000000000096BB0 09 00 00 00 01 00 E0 00 C4 30 20 00 00 00 04 00 .........0 .....
4000000000096BC0 11 00 38 54 98 11 00 00 00 02 00 00 28 3C F8 58 ..8T........(<.X
4000000000096BD0 08 00 00 00 01 00 10 00 08 01 42 00 00 00 04 00 ..........B.....
4000000000096BE0 19 28 02 70 18 10 00 00 00 02 00 00 08 3C F8 58 .(.p.........<.X
4000000000096BF0 09 70 40 18 00 21 00 00 00 02 00 20 00 10 02 84 .p@..!..... ....
4000000000096C00 11 28 02 1C 18 10 00 00 00 02 00 00 E8 3B F8 58 .(...........;.X
4000000000096C10 10 00 00 00 01 00 10 00 08 01 42 00 90 F0 FF 48 ..........B....H

l4000000000096C20:
	{ addl	r69,1,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r39,0x0,r8; st1	[r0],r8; adds	r1,0x0,r66; }
	{ adds	r8,0x0,r39; mov	pr,r67,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r65; }
	{ nop.m	0x0; mov.i	LC,r68; mov.spnt	b0,r64,4000000000096C50 }
	{ nop.m	0x0; adds	r12,0x40,r12; br.ret	b0 }

l4000000000096C70:
	{ adds	r14,0x2,r32; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r37,2,r0; (p06) br.cond.dptk.few	4000000000095AD0 }

l4000000000096C9C:
	{ (p50) nop; zxt1	r0,r64; break.i	0x1000 }

l4000000000096CA0:
	{ adds	r69,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r66; adds	r37,0x0,r8; br.cond.sptk.few	4000000000095AD0 }
4000000000096CC0 09 58 01 00 00 21 00 00 00 02 00 80 04 00 00 84 .X...!..........
4000000000096CD0 10 00 00 00 01 00 B0 0A AC 00 42 00 70 FC FF 48 ..........B.p..H
4000000000096CE0 11 30 02 44 00 21 00 00 00 02 00 00 A8 44 F8 58 .0.D.!.......D.X
4000000000096CF0 00 00 00 00 01 00 50 04 90 2C 00 20 00 10 02 84 ......P..,. ....
4000000000096D00 19 00 00 00 01 00 60 04 80 00 42 00 00 00 00 20 ......`...B.... 
4000000000096D10 11 28 9E 8A 00 20 00 00 00 02 00 00 78 44 F8 58 .(... ......xD.X
4000000000096D20 09 40 00 4E 00 21 10 00 08 01 42 E0 3F 84 7F 0B .@.N.!....B.?...
4000000000096D30 01 00 00 00 01 00 00 08 02 55 00 00 00 00 04 00 .........U......
4000000000096D40 02 00 00 00 01 00 00 20 06 55 00 00 00 0C 00 07 ....... .U......
4000000000096D50 18 00 00 00 01 00 C0 00 32 00 42 80 08 00 84 00 ........2.B.....

l4000000000096D60:
	{ nop.m	0x0; ld4	r14,[r44]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; br.cond.sptk.few	40000000000960E0 }

l4000000000096D80:
	{ nop.m	0x0; ld4	r43,[r45]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r43; br.cond.sptk.few	40000000000961A0 }
4000000000096DA0 09 00 00 00 01 00 70 04 B4 20 20 00 00 00 04 00 ......p..  .....
4000000000096DB0 10 00 00 00 01 00 60 00 1C 0F 73 00 D0 F5 FF 48 ......`...s....H

l4000000000096DC0:
	{ nop.m	0x0; ld4	r43,[r45]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r43; br.cond.sptk.few	4000000000096560 }

l4000000000096DE0:
	{ nop.m	0x0; ld4	r14,[r44]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; br.cond.sptk.few	40000000000968A0; }

;; string_quote_removal: 4000000000096E00
;;   Called from:
;;     400000000002D55C (in fn400000000002AC80)
;;     40000000000441BC (in make_here_document)
;;     400000000009792C (in fn4000000000097540)
string_quote_removal proc
	{ alloc	r48,ar.pfs,0x16,0x0,0x12; adds	r12,0xFFFFFFFFFFFFFFE0,r12; mov	r47,b7 }
	{ adds	r49,0x0,r1; adds	r50,0x0,r32; and	r33,0x3,r33; }
	{ adds	r40,0x28,r12; adds	r37,0x0,r0; nop.i	0x0 }
	{ adds	r35,0x0,r0; adds	r39,0x18,r12; adds	r43,0x20,r12; }
	{ st8	[r0],r40; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r49; add	r45,r32,r8; adds	r50,0x1,r8; }
	{ nop.m	0x0; addl	r38,-9996,r1; nop.i	0x0; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r49; adds	r41,0x0,r8; adds	r36,0x0,r8 }
	{ adds	r15,0x0,r0; addl	r46,-18556,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000096EC0:
	{ add	r34,r32,r15; ld1	r15,[r34]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; zxt1	r14,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	4000000000097000; }

l4000000000096EF0:
	{ cmp4.eq	p06,p07,0x27,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000971C0; }

l4000000000096F00:
	{ cmp4.eq	p06,p07,0x5C,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000970F0; }

l4000000000096F10:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x22,r14; (p06) br.cond.dpnt.few	4000000000097030 }

l4000000000096F20:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ nop.m	0x0; adds	r1,0x0,r49; nop.i	0x0 }
	{ ld1	r14,[r34]; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	40000000000971A0; }

l4000000000096F50:
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0 }
	{ adds	r50,0x0,r36; adds	r51,0x0,r34; extr.u	r16,r14,5,3 }
	{ and	r15,0x1F,r14; shladd	r14,r16,0x2,r38; nop.i	0x0; }
	{ ld4	r14,[r14]; nop.m	0x0; shr.u	r14,r14,r15; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x0; (p07) br.cond.dpnt.few	4000000000097050; }

l4000000000096FA0:
	{ (p06) addl	r15,1,r0; (p06) addl	r8,1,r0; add	r35,r15,r35 }

l4000000000096FA6:
	{ Invalid; (p17) nop; nop; }

l4000000000096FAC:
	{ Invalid; Invalid; Invalid }
	{ (p07) nop; nop; Invalid }
	{ cmpxchg2.acq.nt1	r35,[r0],r22; (p04) cmp.eq.unc	p40,p16,r3,r0; Invalid; }

l4000000000096FD0:
	{ add	r34,r32,r15; ld1	r15,[r34]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; zxt1	r14,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000096EF0 }

l4000000000097000:
	{ adds	r8,0x0,r41; st1	[r0],r36; mov.i	ar.pfs,r48; }
	{ nop.m	0x0; mov.spnt	b0,r47,4000000000097010; nop.i	0x0 }
	{ adds	r12,0x20,r12; nop.m	0x0; br.ret	b0 }

l4000000000097030:
	{ nop.m	0x0; adds	r35,0x1,r35; sub	r37,0x1,r37; }

l4000000000097040:
	{ nop.m	0x0; sxt4	r15,r35; br.cond.sptk.few	4000000000096EC0 }

l4000000000097050:
	{ nop.m	0x0; ld8	r14,[r40]; adds	r51,0x0,r34 }
	{ sub	r52,r45,r34; adds	r53,0x0,r40; adds	r50,0x0,r0; }
	{ st8	[r14],r43; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r15,0x2,r8; nop.m	0x0; adds	r1,0x0,r49 }
	{ adds	r50,0x0,r36; nop.m	0x0; adds	r51,0x0,r34; }
	{ cmp.ltu	p06,p07,0x1,r15; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000974B0; }

l40000000000970B0:
	{ ld8	r16,[r43]; addl	r15,1,r0; addl	r8,1,r0; }
	{ add	r35,r15,r35; st8	[r16],r40; nop.i	0x0 }
	{ adds	r52,0x0,r8; add	r36,r36,r8; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ adds	r1,0x0,r49; sxt4	r15,r35; br.cond.sptk.few	4000000000096FD0 }

l40000000000970F0:
	{ adds	r35,0x1,r35; nop.m	0x0; sxt4	r15,r35; }
	{ add	r34,r32,r15; ld1	r16,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r16; nop.i	0x0; }
	{ (p07) st1	[r36],r1,1; nop.i	0x0; (p07) br.cond.dptk.few	4000000000096EC0 }

l4000000000097126:
	{ chk.a.nc	f0,3FFFFFFFFF097926; nop; break.i	0x80000 }

l4000000000097130:
	{ nop.m	0x0; or	r15,r37,r33; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	4000000000096F20 }

l4000000000097150:
	{ nop.m	0x0; sxt4	r16,r16; shladd	r16,r16,0x2,r46; }
	{ ld4	r15,[r16]; nop.m	0x0; tbit.z	p07,p06,r15,0x6; }
	{ (p07) st1	[r36],r1,1; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }

l4000000000097176:
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; nop; (p32) br.call.sptk.few	b3,b0 }
	{ (p03) chk.a.clr	f1,3FFFFFFFFFB1A216; nop; (p48) nop.b	0x23028 }

l40000000000971A0:
	{ adds	r35,0x1,r35; st1	[r36],r1,1; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r15,r35; br.cond.sptk.few	4000000000096EC0 }

l40000000000971C0:
	{ nop.m	0x0; or	r14,r37,r33; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000097200; }

l40000000000971E0:
	{ adds	r35,0x1,r35; st1	[r36],r1,1; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r15,r35; br.cond.sptk.few	4000000000096EC0 }

l4000000000097200:
	{ nop.m	0x0; adds	r42,0x1,r35; nop.i	0x0 }
	{ st8	[r0],r39; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ nop.m	0x0; sxt4	r44,r42; cmp.ltu	p07,p06,0x1,r8 }
	{ nop.m	0x0; adds	r1,0x0,r49; nop.b	0x0; }
	{ (p06) adds	r44,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000097270; }

l4000000000097246:
	{ chk.a.nc	r0,3FFFFFFFFF097A46; nop; (p32) nop }

l4000000000097250:
	{ add	r50,r32,r44; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; adds	r1,0x0,r49; add	r44,r8,r44 }

l4000000000097270:
	{ adds	r35,0x0,r42; nop.m	0x0; nop.i	0x0; }

l4000000000097280:
	{ nop.m	0x0; sxt4	r37,r35; add	r34,r32,r37; }
	{ nop.m	0x0; ld1	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x0,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x27,r14; (p07) br.cond.dpnt.few	4000000000097390 }

l40000000000972C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r49; nop.m	0x0; cmp.ltu	p07,p06,0x1,r8 }
	{ addl	r17,1,r0; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000974A0; }

l40000000000972F0:
	{ ld1	r14,[r34]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r38; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000097420; }

l4000000000097340:
	{ add	r35,r17,r35; nop.m	0x0; nop.i	0x0; }

l4000000000097350:
	{ nop.m	0x0; sxt4	r37,r35; add	r34,r32,r37; }
	{ nop.m	0x0; ld1	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x0,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x27,r14; (p06) br.cond.dptk.few	40000000000972C0 }

l4000000000097390:
	{ adds	r52,0x0,r35; adds	r50,0x0,r32; nop.i	0x0 }
	{ adds	r51,0x0,r42; adds	r37,0x0,r0; br.call.sptk.many	b0,substring; }
	{ ld1	r14,[r34]; cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r49 }
	{ adds	r42,0x0,r8; adds	r51,0x0,r8; adds	r50,0x0,r36; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p08,p09,0x0,r14; }
	{ (p09) adds	r35,0x1,r35; (p06) br.cond.dpnt.few	4000000000097040; br.call.sptk.many	b0,fn400000000001AAE0; }

l40000000000973E6:
	{ rum	0x5FFFC6; (p32) nop; (p16) nop; }

l40000000000973EC:
	{ (p56) nop; invala; add	r0,r32,r0 }
	{ cmpxchg8.acq	r8,[r66],r0; break.x	0x10802A00C01000 }
	{ (p31) nop; cmp.eq	p32,p16,r12,r64; (p01) break.i	0x16460 }
	{ (p21) cmp.lt.unc	p63,p08,r63,r36; (p01) cmp.eq.unc	p32,p08,r9,r6; Invalid }

l4000000000097420:
	{ ld8	r14,[r39]; adds	r15,0x10,r12; adds	r50,0x0,r0 }
	{ adds	r51,0x0,r34; sub	r52,r44,r37; adds	r53,0x0,r39; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r15,0x10,r12; adds	r1,0x0,r49; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000097490; }

l4000000000097470:
	{ ld8	r14,[r15]; nop.m	0x0; adds	r35,0x1,r35; }
	{ st8	[r14],r39; nop.i	0x0; br.cond.sptk.few	4000000000097280 }

l4000000000097490:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; (p07) br.cond.spnt.few	4000000000097500; }

l40000000000974A0:
	{ nop.m	0x0; adds	r35,0x1,r35; br.cond.sptk.few	4000000000097280; }

l40000000000974B0:
	{ cmp.eq	p06,p07,0x0,r8; adds	r50,0x0,r36; adds	r51,0x0,r34; }
	{ (p06) addl	r15,1,r0; nop.m	0x0; (p06) addl	r8,1,r0; }

l40000000000974C6:
	{ chk.a.nc	r0,3FFFFFFFFF097CC6; (p04) cmp4.eq.or	p01,p08,r0,r0; (p49) nop }

l40000000000974D0:
	{ (p07) adds	r15,0x0,r8; adds	r52,0x0,r8; add	r36,r36,r8; }

l40000000000974D6:
	{ Invalid; (p18) nop; (p48) nop }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ (p07) break.m	0x59180; nop; break.b	0x80000 }

l4000000000097500:
	{ nop.m	0x0; adds	r17,0x0,r8; nop.i	0x0; }
	{ nop.m	0x0; add	r35,r17,r35; br.cond.sptk.few	4000000000097350; }
4000000000097520 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000097530 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000097540: 4000000000097540
;;   Called from:
;;     40000000000979AC (in expand_arith_string)
;;     40000000000997AC (in fn4000000000099100)
fn4000000000097540 proc
	{ alloc	r43,ar.pfs,0x11,0x0,0xD; adds	r12,0xFFFFFFFFFFFFFFE0,r12; nop.b	0x0 }
	{ adds	r44,0x0,r1; mov	r42,b2; adds	r39,0x18,r12; }
	{ st8	[r0],r39; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ cmp.ltu	p07,p06,0x1,r8; adds	r1,0x0,r44; adds	r45,0x0,r32; }
	{ (p06) adds	r41,0x0,r0; (p06) br.cond.dpnt.few	40000000000975A0; br.call.sptk.many	b0,fn400000000001B6C0; }

l4000000000097586:
	{ Invalid; (p32) nop; break.i	0x80000; }

l400000000009758C:
	{ (p10) nop; nop; nop }
	{ nop; (p04) nop; }

l40000000000975A0:
	{ addl	r40,-9996,r1; adds	r38,0x0,r0; nop.i	0x0 }
	{ adds	r35,0x0,r0; ld8	r40,[r40]; nop.i	0x0; }

l40000000000975C0:
	{ nop.m	0x0; sxt4	r37,r35; add	r36,r32,r37; }
	{ ld1	r14,[r36]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	4000000000097740; }

l40000000000975F0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x24,r14; nop.i	0x0; }
	{ cmp4.eq.or.andcm	p06,p07,0x60,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000097870; }

l4000000000097610:
	{ cmp4.eq	p06,p07,0x3C,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000097870; }

l4000000000097620:
	{ cmp4.eq	p06,p07,0x3E,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000097870; }

l4000000000097630:
	{ cmp4.eq	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000097870; }

l4000000000097640:
	{ cmp4.eq	p06,p07,0x7E,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000097870; }

l4000000000097650:
	{ cmp4.eq	p06,p07,0x27,r14; cmp4.eq.or.andcm	p06,p07,0x5C,r14; nop.i	0x0; }
	{ nop.m	0x0; (p06) addl	r38,1,r0; (p06) br.cond.dptk.few	4000000000097680 }

l400000000009766C:
	{ (p01) cmp.lt	p00,p02,r0,r33; czx1.r	r72,r97; cmp4.eq.and	p00,p00,r32,r0 }

l4000000000097670:
	{ cmp4.eq	p06,p07,0x22,r14; nop.i	0x0; (p06) addl	r38,1,r0 }

l4000000000097680:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r44; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	4000000000097860; }

l40000000000976A0:
	{ ld1	r14,[r36]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r40; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000977C0; }

l40000000000976F0:
	{ (p06) addl	r14,1,r0; nop.m	0x0; nop.i	0x0; }

l40000000000976F6:
	{ break.m	0x4000; nop; (p48) nop }

l4000000000097700:
	{ add	r35,r14,r35; nop.m	0x0; sxt4	r37,r35; }
	{ add	r36,r32,r37; ld1	r14,[r36]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000975F0; }

l4000000000097740:
	{ cmp4.eq	p07,p06,0x0,r38; and	r14,0x3,r33; (p07) br.cond.dpnt.few	4000000000097760; }

l4000000000097750:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	4000000000097920 }

l4000000000097760:
	{ adds	r45,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r44; adds	r45,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r44; nop.m	0x0; adds	r45,0x0,r8 }
	{ adds	r46,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r44; mov.i	ar.pfs,r43; mov.spnt	b0,r42,40000000000977A0 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0; }

l40000000000977C0:
	{ ld8	r14,[r39]; adds	r15,0x10,r12; adds	r45,0x0,r0 }
	{ adds	r46,0x0,r36; sub	r47,r41,r37; adds	r48,0x0,r39; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r15,0x10,r12; adds	r1,0x0,r44; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000097830; }

l4000000000097810:
	{ ld8	r14,[r15]; nop.m	0x0; adds	r35,0x1,r35; }
	{ st8	[r14],r39; nop.i	0x0; br.cond.sptk.few	40000000000975C0 }

l4000000000097830:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r14,0x0,r8; (p07) br.cond.spnt.few	4000000000097700; }

l400000000009784C:
	{ (p54) nop; break.i	0x1000; break.i	0x1000 }

l4000000000097850:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000097860:
	{ nop.m	0x0; adds	r35,0x1,r35; br.cond.sptk.few	40000000000975C0; }

l4000000000097870:
	{ ld8	r14,[r34],8; adds	r46,0x0,r33; adds	r45,0x0,r32; }
	{ nop.m	0x0; mov.spnt	b6,r14,4000000000097880; nop.i	0x0 }
	{ ld8	r1,[r34],-8; nop.m	0x0; br.call.sptk.many	b0,b6; }
	{ adds	r35,0x0,r8; nop.m	0x0; cmp.eq	p07,p06,0x0,r8 }
	{ adds	r1,0x0,r44; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000097950; }

l40000000000978C0:
	{ adds	r45,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,string_list; }
	{ adds	r14,0x20,r12; adds	r1,0x0,r44; adds	r45,0x0,r35; }
	{ st8	[r8],r14; nop.i	0x0; br.call.sptk.many	b0,dispose_words; }
	{ adds	r15,0x20,r12; nop.m	0x0; adds	r1,0x0,r44; }
	{ ld8	r8,[r15]; mov.i	ar.pfs,r43; mov.spnt	b0,r42,4000000000097900 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0; }

l4000000000097920:
	{ adds	r45,0x0,r32; adds	r46,0x0,r33; br.call.sptk.many	b0,string_quote_removal; }
	{ adds	r1,0x0,r44; mov.i	ar.pfs,r43; mov.spnt	b0,r42,4000000000097930 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0 }

l4000000000097950:
	{ adds	r8,0x0,r0; mov.i	ar.pfs,r43; mov.spnt	b0,r42,4000000000097950 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0; }
4000000000097970 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; expand_arith_string: 4000000000097980
;;   Called from:
;;     40000000000BFF4C (in array_expand_index)
expand_arith_string proc
	{ alloc	r16,ar.pfs,0x3,0x0,0x3; nop.m	0x0; addl	r34,-9900,r1; }
	{ nop.m	0x0; ld8	r34,[r34]; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x3,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn4000000000097540; }
40000000000979B0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000979C0 18 D0 95 3C 80 05 C0 00 31 7E 46 00 00 00 00 20 ...<....1~F.... 
40000000000979D0 01 68 31 03 46 24 C0 03 00 66 00 E0 00 08 19 E4 .h1.F$...f......
40000000000979E0 18 00 00 00 01 00 F0 02 32 00 42 00 00 00 00 20 ........2.B.... 
40000000000979F0 01 70 21 19 00 21 90 03 00 62 00 60 07 08 00 84 .p!..!...b.`....
4000000000097A00 08 F8 01 42 00 21 30 04 BC 00 42 A0 07 08 CA 00 ...B.!0...B.....
4000000000097A10 19 20 02 5C 00 21 E0 03 80 00 C2 03 70 02 00 43 . .\.!......p..C
4000000000097A20 08 08 02 48 00 21 10 03 B4 30 20 00 08 10 59 00 ...H.!...0 ...Y.
4000000000097A30 19 10 02 4A 00 21 00 00 B5 30 23 00 98 9E FF 58 ...J.!...0#....X
4000000000097A40 08 38 FC 11 86 3B B0 C2 31 00 42 00 06 40 00 84 .8...;..1.B..@..
4000000000097A50 09 08 00 76 00 21 E0 03 8C 00 42 C0 04 00 00 84 ...v.!....B.....
4000000000097A60 E8 40 00 00 00 E1 01 88 B5 30 23 20 05 00 00 84 .@.......0# ....
4000000000097A70 19 50 01 00 00 21 30 43 31 00 C2 03 20 02 00 43 .P...!0C1... ..C
4000000000097A80 08 00 00 56 98 11 60 03 BC 30 20 00 00 00 04 00 ...V..`..0 .....
4000000000097A90 19 A0 C1 18 00 21 50 03 B8 30 20 00 38 3C F8 58 .....!P..0 .8<.X
4000000000097AA0 02 08 00 76 00 21 20 03 20 00 42 80 45 EF C7 9E ...v.! . .B.E...
4000000000097AB0 0B 00 00 00 01 00 C0 02 B0 30 20 00 00 00 04 00 .........0 .....
4000000000097AC0 03 00 00 00 01 00 80 02 98 2C 00 E0 34 42 01 80 .........,..4B..
4000000000097AD0 0B 70 00 4E 00 10 00 00 00 02 00 C0 01 70 50 00 .p.N.........pP.
4000000000097AE0 11 00 00 00 01 00 70 00 38 0C F3 03 C0 00 00 43 ......p.8......C
4000000000097AF0 09 00 00 00 01 00 70 40 39 0C 73 00 00 00 04 00 ......p@9.s.....
4000000000097B00 F1 48 05 52 00 E1 61 0A 98 00 C2 03 C0 FF FF 4B .H.R..a........K
4000000000097B10 11 38 A4 1C 86 39 00 00 00 02 80 03 B0 01 00 43 .8...9.........C
4000000000097B20 11 30 00 52 87 39 00 00 00 02 80 03 C0 02 00 43 .0.R.9.........C
4000000000097B30 11 38 E8 1C 86 39 00 00 00 02 80 03 B0 03 00 43 .8...9.........C
4000000000097B40 10 00 00 00 01 00 70 F8 39 0C 73 03 A0 01 00 42 ......p.9.s....B
4000000000097B50 08 50 05 54 00 21 00 00 00 02 00 00 00 00 04 00 .P.T.!..........
4000000000097B60 09 30 05 4C 00 21 00 00 00 02 00 00 00 00 04 00 .0.L.!..........
4000000000097B70 03 00 00 00 01 00 80 02 98 2C 00 E0 34 42 01 80 .........,..4B..
4000000000097B80 0B 70 00 4E 00 10 00 00 00 02 00 C0 01 70 50 00 .p.N.........pP.
4000000000097B90 10 00 00 00 01 00 70 00 38 0C 73 03 60 FF FF 4A ......p.8.s.`..J
4000000000097BA0 08 F0 01 46 00 21 F0 0B 00 00 48 00 00 00 04 00 ...F.!....H.....
4000000000097BB0 19 30 41 19 00 21 70 02 00 00 42 00 D8 FD FF 58 .0A..!p...B....X
4000000000097BC0 08 08 00 76 00 21 80 02 20 00 42 00 00 00 04 00 ...v.!.. .B.....
4000000000097BD0 19 F8 01 4C 00 21 E0 03 20 00 42 00 B8 E4 FD 58 ...L.!.. .B....X
4000000000097BE0 08 08 00 76 00 21 00 00 00 02 00 20 05 40 00 84 ...v.!..... .@..
4000000000097BF0 19 F0 01 50 00 21 00 00 00 02 00 00 F8 2B F8 58 ...P.!.......+.X
4000000000097C00 09 70 00 4C 10 10 00 00 00 02 00 20 00 D8 01 84 .p.L....... ....
4000000000097C10 10 00 00 00 01 00 60 00 38 0E 73 03 70 03 00 43 ......`.8.s.p..C
4000000000097C20 09 00 00 00 01 00 A0 FA F3 FD 4F 00 00 00 04 00 ..........O.....
4000000000097C30 0A 50 A9 60 0C 20 60 08 A8 0E 63 00 12 50 45 E6 .P.`. `...c..PE.
4000000000097C40 17 00 00 00 00 08 04 E0 01 80 A1 03 30 09 00 43 ............0..C
4000000000097C50 11 30 08 54 87 39 00 00 00 02 00 03 90 10 00 43 .0.T.9.........C
4000000000097C60 10 00 00 00 01 00 60 18 A8 0E 73 03 20 09 00 43 ......`...s. ..C
4000000000097C70 08 00 C4 5A 98 11 00 00 00 02 00 00 00 00 04 00 ...Z............
4000000000097C80 09 40 00 00 00 21 00 00 00 02 00 00 00 00 04 00 .@...!..........
4000000000097C90 03 00 00 00 01 00 F0 E7 C1 BF 05 00 A0 03 AA 00 ................
4000000000097CA0 02 00 00 00 01 00 00 E8 05 55 00 00 90 0B 00 07 .........U......
4000000000097CB0 18 00 00 00 01 00 C0 00 33 00 42 80 08 00 84 00 ........3.B.....
4000000000097CC0 09 00 00 00 01 00 60 00 A4 0E 73 00 00 00 04 00 ......`...s.....
4000000000097CD0 F0 48 FD 53 3F E3 61 0A 98 00 C2 03 F0 FD FF 4A .H.S?.a........J
4000000000097CE0 11 00 00 00 01 00 00 00 00 02 00 00 E8 33 F8 58 .............3.X
4000000000097CF0 11 08 00 76 00 21 70 08 20 0C 6A 03 F0 02 00 43 ...v.!p. .j....C
4000000000097D00 0B 70 00 4E 00 10 00 00 00 02 00 C0 01 70 50 00 .p.N.........pP.
4000000000097D10 01 00 00 00 01 00 00 51 38 04 29 E0 F1 71 B0 80 .......Q8.)..q..
4000000000097D20 0B 70 40 58 11 20 E0 00 38 20 20 00 00 00 04 00 .p@X. ..8  .....
4000000000097D30 02 00 00 00 01 00 E0 78 38 80 3C E0 00 70 18 50 .......x8.<..p.P
4000000000097D40 19 00 00 00 01 00 00 00 00 02 80 03 30 00 00 43 ............0..C
4000000000097D50 C9 70 04 00 00 24 00 00 00 02 00 00 00 00 04 00 .p...$..........
4000000000097D60 11 30 39 4C 00 20 90 02 00 00 42 00 60 FD FF 48 .09L. ....B.`..H
4000000000097D70 08 70 00 56 18 10 E0 03 00 00 42 E0 07 38 01 84 .p.V......B..8..
4000000000097D80 09 00 CA 50 05 20 10 04 AC 00 42 20 05 00 00 84 ...P. ....B ....
4000000000097D90 11 00 38 66 98 11 00 00 00 02 00 00 18 33 F8 58 ..8f.........3.X
4000000000097DA0 09 70 08 10 00 21 00 00 00 02 00 20 00 D8 01 84 .p...!..... ....
4000000000097DB0 11 30 04 1C 07 35 00 00 00 02 00 03 10 02 00 43 .0...5.........C
4000000000097DC0 09 70 00 66 18 10 00 00 00 02 00 C0 14 30 01 84 .p.f.........0..
4000000000097DD0 10 00 38 56 98 11 00 00 00 02 00 00 F0 FC FF 48 ..8V...........H
4000000000097DE0 11 00 00 00 01 00 00 00 00 02 00 00 E8 32 F8 58 .............2.X
4000000000097DF0 11 08 00 76 00 21 70 08 20 0C 6A 03 70 FD FF 4B ...v.!p. .j.p..K
4000000000097E00 0B 70 00 4E 00 10 00 00 00 02 00 C0 01 70 50 00 .p.N.........pP.
4000000000097E10 01 00 00 00 01 00 00 51 38 04 29 E0 F1 71 B0 80 .......Q8.)..q..
4000000000097E20 0B 70 40 58 11 20 E0 00 38 20 20 00 00 00 04 00 .p@X. ..8  .....
4000000000097E30 02 00 00 00 01 00 E0 78 38 80 3C E0 00 70 18 50 .......x8.<..p.P
4000000000097E40 19 00 00 00 01 00 00 00 00 02 80 03 30 00 00 43 ............0..C
4000000000097E50 C9 70 04 00 00 24 00 00 00 02 00 00 00 00 04 00 .p...$..........
4000000000097E60 10 00 00 00 01 00 60 72 98 00 40 00 60 FC FF 48 ......`r..@.`..H
4000000000097E70 08 00 00 00 01 00 E0 00 AC 30 20 C0 07 00 00 84 .........0 .....
4000000000097E80 09 F8 01 4E 00 21 00 94 A1 0A 40 20 08 58 01 84 ...N.!....@ .X..
4000000000097E90 11 00 38 68 98 11 00 00 00 02 00 00 18 32 F8 58 ..8h.........2.X
4000000000097EA0 09 70 08 10 00 21 00 00 00 02 00 20 00 D8 01 84 .p...!..... ....
4000000000097EB0 11 30 04 1C 07 35 00 00 00 02 00 03 90 0F 00 43 .0...5.........C
4000000000097EC0 09 70 00 68 18 10 00 00 00 02 00 C0 14 30 01 84 .p.h.........0..
4000000000097ED0 10 00 38 56 98 11 00 00 00 02 00 00 F0 FB FF 48 ..8V...........H
4000000000097EE0 10 00 00 00 01 00 60 00 A8 0E F3 03 10 01 00 42 ......`........B
4000000000097EF0 08 30 41 19 00 21 E0 03 8C 00 42 00 00 00 04 00 .0A..!....B.....
4000000000097F00 19 F8 05 00 00 24 00 00 9C 00 23 00 88 FA FF 58 .....$....#....X
4000000000097F10 08 08 00 76 00 21 80 02 20 00 42 00 00 00 04 00 ...v.!.. .B.....
4000000000097F20 19 F8 01 4C 00 21 E0 03 20 00 42 00 68 E1 FD 58 ...L.!.. .B.h..X
4000000000097F30 08 08 00 76 00 21 00 00 00 02 00 20 05 40 00 84 ...v.!..... .@..
4000000000097F40 19 F0 01 50 00 21 00 00 00 02 00 00 A8 28 F8 58 ...P.!.......(.X
4000000000097F50 09 70 00 4C 10 10 00 00 00 02 00 20 00 D8 01 84 .p.L....... ....
4000000000097F60 11 00 00 00 01 00 60 00 38 0E F3 03 C0 FC FF 4A ......`.8......J
4000000000097F70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000097F80 09 00 00 00 01 00 00 88 B5 30 23 00 C1 09 EC 90 .........0#.....
4000000000097F90 03 00 00 00 01 00 F0 E7 C1 BF 05 00 A0 03 AA 00 ................
4000000000097FA0 02 00 00 00 01 00 00 E8 05 55 00 00 90 0B 00 07 .........U......
4000000000097FB0 18 00 00 00 01 00 C0 00 33 00 42 80 08 00 84 00 ........3.B.....
4000000000097FC0 09 00 00 00 01 00 60 00 20 0E 72 00 00 00 04 00 ......`. .r.....
4000000000097FD0 11 00 00 00 01 C0 E1 00 20 00 C2 03 90 FD FF 49 ........ ......I
4000000000097FE0 11 30 05 4C 00 21 90 02 00 00 42 00 E0 FA FF 48 .0.L.!....B....H
4000000000097FF0 10 50 FD 55 3F 23 60 0A 98 00 42 00 D0 FA FF 48 .P.U?#`...B....H
4000000000098000 08 70 D0 02 2E 24 F0 00 00 00 42 00 80 08 2A 00 .p...$....B...*.
4000000000098010 0B 00 00 00 01 00 E0 00 38 30 20 00 00 00 04 00 ........80 .....
4000000000098020 09 80 20 1C 18 14 00 00 00 02 00 60 15 78 00 84 .. ........`.x..
4000000000098030 11 38 00 20 06 39 00 00 00 02 80 03 30 00 00 43 .8. .9......0..C
4000000000098040 10 00 00 00 01 00 F0 00 AC 00 42 A0 E0 FF FF 48 ..........B....H
4000000000098050 08 58 29 00 00 24 00 00 00 02 00 00 00 00 04 00 .X)..$..........
4000000000098060 0B 70 70 03 37 24 00 00 00 02 00 00 00 00 04 00 .pp.7$..........
4000000000098070 09 00 00 00 01 00 E0 00 38 30 20 00 00 00 04 00 ........80 .....
4000000000098080 11 00 00 00 01 00 60 00 38 0E 72 03 50 00 00 43 ......`.8.r.P..C
4000000000098090 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000980A0 09 70 00 1C 18 10 00 00 00 02 00 E0 11 78 00 84 .p...........x..
40000000000980B0 10 00 00 00 01 00 70 00 38 0C 72 03 F0 FF FF 4A ......p.8.r....J
40000000000980C0 09 58 05 1E 00 21 00 00 00 02 00 00 00 00 04 00 .X...!..........
40000000000980D0 00 00 00 00 01 00 B0 02 AC 2C 00 E0 00 48 19 E4 .........,...H..
40000000000980E0 19 00 00 00 01 00 00 00 00 02 00 03 40 05 00 42 ............@..B
40000000000980F0 E9 58 05 56 00 21 00 00 00 02 00 00 00 00 04 00 .X.V.!..........
4000000000098100 08 00 00 00 01 00 60 58 A5 0E 60 60 22 50 49 E6 ......`X..``"PI.
4000000000098110 17 00 00 00 00 88 01 B0 FD FF A5 09 70 05 00 43 ............p..C
4000000000098120 11 30 00 4E 07 39 80 0A 9C 00 42 03 40 01 00 43 .0.N.9....B.@..C
4000000000098130 11 F0 01 50 00 21 00 00 00 02 00 00 98 35 F8 58 ...P.!.......5.X
4000000000098140 11 08 00 76 00 21 E0 0B 20 00 42 00 88 0B 05 50 ...v.!.. .B....P
4000000000098150 08 08 00 76 00 21 00 00 00 02 00 C0 07 40 00 84 ...v.!.......@..
4000000000098160 19 F8 01 50 00 21 00 00 00 02 00 00 28 30 F8 58 ...P.!......(0.X
4000000000098170 08 F8 05 00 00 24 10 00 EC 00 42 00 00 00 04 00 .....$....B.....
4000000000098180 19 90 01 10 00 21 E0 03 20 00 42 00 08 F8 FF 58 .....!.. .B....X
4000000000098190 08 08 00 76 00 21 00 00 00 02 00 80 05 40 00 84 ...v.!.......@..
40000000000981A0 19 F0 01 64 00 21 00 00 00 02 00 00 48 26 F8 58 ...d.!......H&.X
40000000000981B0 08 70 E8 00 00 24 00 00 00 02 00 20 00 D8 01 84 .p...$..... ....
40000000000981C0 09 F8 01 4C 00 21 00 00 00 02 00 C0 07 60 01 84 ...L.!.......`..
40000000000981D0 11 00 38 4E 80 11 00 00 00 02 00 00 B8 DE FD 58 ..8N...........X
40000000000981E0 08 08 00 76 00 21 00 00 00 02 00 E0 04 40 00 84 ...v.!.......@..
40000000000981F0 19 F0 01 58 00 21 00 00 00 02 00 00 F8 25 F8 58 ...X.!.......%.X
4000000000098200 09 70 00 4C 10 10 00 00 00 02 00 20 00 D8 01 84 .p.L....... ....
4000000000098210 11 30 00 1C 87 39 E0 F8 AB 7E 46 03 70 FD FF 4B .0...9...~F.p..K
4000000000098220 11 30 04 1C 87 35 00 00 00 02 80 03 F0 07 00 43 .0...5.........C
4000000000098230 10 00 00 00 01 00 70 38 01 0C E0 03 80 0B 00 43 ......p8.......C
4000000000098240 09 38 A5 4E 00 20 00 00 00 02 00 00 00 00 04 00 .8.N. ..........
4000000000098250 02 38 AC 4E 06 30 00 00 00 02 00 63 05 38 01 84 .8.N.0.....c.8..
4000000000098260 08 30 04 54 87 31 00 88 B5 30 23 00 00 00 04 00 .0.T.1...0#.....
4000000000098270 17 00 00 00 00 08 04 30 04 80 A1 03 B0 0C 00 43 .......0.......C
4000000000098280 11 30 08 54 87 39 00 00 00 02 00 03 C0 07 00 43 .0.T.9.........C
4000000000098290 10 00 00 00 01 00 60 18 A8 0E F3 03 F0 F9 FF 4A ......`........J
40000000000982A0 11 60 81 18 00 21 10 03 A4 00 42 00 28 2E F8 58 .`...!....B.(..X
40000000000982B0 11 08 00 76 00 21 70 08 20 0C 6A 03 90 0C 00 43 ...v.!p. .j....C
40000000000982C0 08 00 00 00 01 00 80 02 B8 30 20 00 00 00 04 00 .........0 .....
40000000000982D0 19 00 00 58 98 11 00 00 00 02 00 00 F8 2D F8 58 ...X.........-.X
40000000000982E0 11 38 04 10 06 35 10 00 EC 00 42 03 F0 03 00 43 .8...5....B....C
40000000000982F0 11 30 00 50 07 39 00 00 00 02 00 03 E0 03 00 43 .0.P.9.........C
4000000000098300 0B 70 00 50 00 10 00 00 00 02 00 C0 01 70 50 00 .p.P.........pP.
4000000000098310 10 00 00 00 01 00 60 00 38 0E 73 03 C0 03 00 42 ......`.8.s....B
4000000000098320 0B 70 04 50 00 21 E0 00 38 00 20 00 00 00 04 00 .p.P.!..8. .....
4000000000098330 03 00 00 00 01 00 E0 00 38 28 00 C0 00 70 1C E6 ........8(...p..
4000000000098340 10 00 00 00 01 80 F1 0A 00 00 48 03 60 00 00 42 ..........H.`..B
4000000000098350 0B 70 08 50 00 21 E0 00 38 00 20 00 00 00 04 00 .p.P.!..8. .....
4000000000098360 03 00 00 00 01 00 E0 00 38 28 00 C0 00 70 1C E6 ........8(...p..
4000000000098370 10 00 00 00 01 80 F1 12 00 00 48 03 30 00 00 42 ..........H.0..B
4000000000098380 11 F0 01 50 00 21 00 00 00 02 00 00 48 33 F8 58 ...P.!......H3.X
4000000000098390 09 00 00 00 01 00 10 00 EC 00 42 E0 05 40 00 84 ..........B..@..
40000000000983A0 08 68 D1 FB B1 27 90 4A 01 10 40 C0 04 00 00 84 .h...'.J..@.....
40000000000983B0 0B 80 61 18 00 21 D0 02 B4 30 20 00 90 0A AA 00 ..a..!...0 .....
40000000000983C0 03 00 00 00 01 00 70 02 98 2C 00 20 85 3A 01 80 ......p..,. .:..
40000000000983D0 0B 70 00 52 00 10 00 00 00 02 00 C0 01 70 50 00 .p.R.........pP.
40000000000983E0 12 38 00 1C 86 F9 01 08 00 80 21 A0 20 03 00 40 .8........!. ..@
40000000000983F0 09 70 AC 62 05 20 90 A2 F7 63 4F A0 05 30 01 84 .p.b. ...cO..0..
4000000000098400 08 00 00 00 01 00 E0 70 00 10 40 00 00 00 04 00 .......p..@.....
4000000000098410 03 48 01 52 18 10 00 00 00 02 00 00 E0 08 AA 00 .H.R............
4000000000098420 13 00 00 00 01 C0 01 10 00 80 21 00 00 00 00 20 ..........!.... 
4000000000098430 10 00 00 00 01 00 00 00 00 02 00 A0 D0 03 00 40 ...............@
4000000000098440 08 00 02 4C 00 21 00 00 00 02 00 C0 07 40 01 84 ...L.!.......@..
4000000000098450 19 F8 01 5A 00 21 00 00 00 02 00 00 B8 0F 04 50 ...Z.!.........P
4000000000098460 08 00 00 00 01 00 10 00 EC 00 42 C0 04 40 00 84 ..........B..@..
4000000000098470 10 00 00 00 01 00 70 00 A8 0C 73 03 50 00 00 42 ......p...s.P..B
4000000000098480 09 00 00 00 01 00 E0 03 B8 30 20 00 00 00 04 00 .........0 .....
4000000000098490 11 30 00 7C 07 39 00 00 00 02 00 03 30 00 00 43 .0.|.9......0..C
40000000000984A0 11 00 00 00 01 00 00 00 00 02 00 00 48 23 F8 58 ............H#.X
40000000000984B0 08 08 00 76 00 21 00 00 00 02 00 00 00 00 04 00 ...v.!..........
40000000000984C0 09 20 0D 48 2C 20 60 00 98 0E 72 C0 07 30 01 84 . .H, `...r..0..
40000000000984D0 13 40 00 48 89 79 02 10 05 80 21 03 B0 F7 FF 4B .@.H.y....!....K
40000000000984E0 11 00 00 00 01 00 00 00 00 02 00 00 A8 7C FF 58 .............|.X
40000000000984F0 08 00 00 00 01 00 10 00 EC 00 42 C0 07 30 01 84 ..........B..0..
4000000000098500 09 00 00 00 01 00 E0 00 33 00 42 00 00 00 04 00 ........3.B.....
4000000000098510 11 00 20 1C 98 11 00 00 00 02 00 00 D8 22 F8 58 .. ..........".X
4000000000098520 09 78 80 19 00 21 00 00 00 02 00 20 00 D8 01 84 .x...!..... ....
4000000000098530 08 40 00 1E 18 10 00 00 00 02 00 00 00 00 04 00 .@..............
4000000000098540 03 00 00 00 01 00 F0 E7 C1 BF 05 00 A0 03 AA 00 ................
4000000000098550 02 00 00 00 01 00 00 E8 05 55 00 00 90 0B 00 07 .........U......
4000000000098560 18 00 00 00 01 00 C0 00 33 00 42 80 08 00 84 00 ........3.B.....
4000000000098570 11 00 00 00 01 00 60 00 A8 0E F3 03 00 F7 FF 4A ......`........J
4000000000098580 11 00 00 00 01 00 00 00 00 02 00 00 48 2B F8 58 ............H+.X
4000000000098590 11 38 04 10 06 35 10 00 EC 00 42 03 60 0A 00 43 .8...5....B.`..C
40000000000985A0 11 30 00 6A 07 39 00 00 00 02 00 03 D0 00 00 43 .0.j.9.........C
40000000000985B0 0B 70 00 6A 00 10 00 00 00 02 00 C0 01 70 50 00 .p.j.........pP.
40000000000985C0 10 00 00 00 01 00 60 00 38 0E 73 03 B0 00 00 42 ......`.8.s....B
40000000000985D0 0B 70 04 6A 00 21 E0 00 38 00 20 00 00 00 04 00 .p.j.!..8. .....
40000000000985E0 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
40000000000985F0 10 00 00 00 01 00 60 00 38 0E F3 03 C0 08 00 43 ......`.8......C
4000000000098600 09 58 05 00 00 24 00 00 00 02 00 00 00 00 04 00 .X...$..........
4000000000098610 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000098620 10 00 00 00 01 00 70 48 01 0C 60 03 E0 FA FF 4A ......pH..`....J
4000000000098630 09 48 A5 56 00 20 00 00 00 02 00 60 22 50 49 E6 .H.V. .....`"PI.
4000000000098640 11 30 AC 52 07 30 00 00 00 02 00 03 30 F6 FF 4B .0.R.0......0..K
4000000000098650 12 30 A4 00 07 B0 01 10 FB FF 25 09 D0 FA FF 4A .0........%....J
4000000000098660 10 00 00 00 01 00 00 00 00 02 00 00 20 00 00 40 ............ ..@
4000000000098670 10 00 00 00 01 00 B0 02 00 00 42 00 B0 FF FF 48 ..........B....H
4000000000098680 0B B0 A1 6C 00 21 E0 00 D8 20 20 00 00 00 04 00 ...l.!...  .....
4000000000098690 01 00 00 00 01 00 60 60 38 0E 28 00 00 00 04 00 ......``8.(.....
40000000000986A0 E9 B8 31 6E 00 21 00 00 00 02 00 03 07 C1 01 84 ..1n.!..........
40000000000986B0 EB 58 01 6E 10 90 B1 02 E0 20 20 00 00 00 04 00 .X.n.....  .....
40000000000986C0 10 00 00 00 01 00 B0 02 AC 2C 00 00 60 FA FF 48 .........,..`..H
40000000000986D0 08 48 A5 00 08 20 D0 A2 F7 63 4F 00 00 00 04 00 .H... ...cO.....
40000000000986E0 09 78 01 00 00 21 60 02 00 00 42 00 86 61 00 84 .x...!`...B..a..
40000000000986F0 10 68 01 5A 18 10 00 48 05 55 00 00 D0 FC FF 48 .h.Z...H.U.....H
4000000000098700 11 00 00 00 01 00 00 00 00 02 00 00 C8 29 F8 58 .............).X
4000000000098710 11 08 00 76 00 21 70 08 20 0C 6A 03 F0 02 00 43 ...v.!p. .j....C
4000000000098720 0B 70 00 52 00 10 00 00 00 02 00 C0 01 70 50 00 .p.R.........pP.
4000000000098730 01 00 00 00 01 00 00 51 38 04 29 E0 F1 71 B0 80 .......Q8.)..q..
4000000000098740 0B 70 40 5A 11 20 E0 00 38 20 20 00 00 00 04 00 .p@Z. ..8  .....
4000000000098750 02 00 00 00 01 00 E0 78 38 80 3C E0 00 70 18 50 .......x8.<..p.P
4000000000098760 19 00 00 00 01 00 00 00 00 02 80 03 30 00 00 43 ............0..C
4000000000098770 C9 70 04 00 00 24 00 00 00 02 00 00 00 00 04 00 .p...$..........
4000000000098780 11 00 00 00 01 00 60 72 98 00 40 00 40 FC FF 48 ......`r..@.@..H
4000000000098790 08 00 00 00 01 00 E0 00 B0 30 20 00 F8 32 15 80 .........0 ..2..
40000000000987A0 09 F0 01 00 00 21 F0 03 A4 00 42 20 08 60 01 84 .....!....B .`..
40000000000987B0 11 00 38 60 98 11 00 04 00 2D 00 00 F8 28 F8 58 ..8`.....-...(.X
40000000000987C0 09 70 08 10 00 21 00 00 00 02 00 20 00 D8 01 84 .p...!..... ....
40000000000987D0 11 30 04 1C 07 35 00 00 00 02 00 03 10 02 00 43 .0...5.........C
40000000000987E0 09 70 00 60 18 10 00 00 00 02 00 C0 14 30 01 84 .p.`.........0..
40000000000987F0 10 00 38 58 98 11 00 00 00 02 00 00 D0 FB FF 48 ..8X...........H
4000000000098800 11 00 00 00 01 00 00 00 00 02 00 00 C8 28 F8 58 .............(.X
4000000000098810 08 F8 A1 4E 00 20 00 00 00 02 00 20 00 D8 01 84 ...N. ..... ....
4000000000098820 19 38 04 10 06 35 00 00 00 02 00 03 80 01 00 43 .8...5.........C
4000000000098830 0B 70 00 7E 00 10 00 00 00 02 00 C0 01 70 50 00 .p.~.........pP.
4000000000098840 01 00 00 00 01 00 00 51 38 04 29 E0 F1 71 B0 80 .......Q8.)..q..
4000000000098850 0B 70 40 52 11 20 E0 00 38 20 20 00 00 00 04 00 .p@R. ..8  .....
4000000000098860 02 00 00 00 01 00 E0 78 38 80 3C E0 00 70 18 50 .......x8.<..p.P
4000000000098870 19 00 00 00 01 00 00 00 00 02 80 03 60 00 00 43 ............`..C
4000000000098880 C9 70 04 00 00 24 00 00 00 02 00 00 00 00 04 00 .p...$..........
4000000000098890 0B 30 39 4C 00 20 00 00 00 02 00 E0 04 30 59 00 .09L. .......0Y.
40000000000988A0 0B 70 A0 4E 00 20 E0 00 38 00 20 00 00 00 04 00 .p.N. ..8. .....
40000000000988B0 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
40000000000988C0 10 00 00 00 01 00 70 00 38 0C 73 00 60 FB FF 48 ......p.8.s.`..H
40000000000988D0 08 00 00 00 01 00 E0 00 B0 30 20 E0 01 61 00 84 .........0 ..a..
40000000000988E0 09 00 BE 4C 05 20 E0 03 00 00 42 20 08 60 01 84 ...L. ....B .`..
40000000000988F0 11 00 38 1E 98 11 00 04 00 2D 00 00 B8 27 F8 58 ..8......-...'.X
4000000000098900 09 70 08 10 00 21 10 00 EC 00 42 E0 01 61 00 84 .p...!....B..a..
4000000000098910 11 30 04 1C 07 35 00 00 00 02 00 03 60 00 00 43 .0...5......`..C
4000000000098920 09 30 05 4C 00 21 E0 00 3C 30 20 00 00 00 04 00 .0.L.!..<0 .....
4000000000098930 00 00 00 00 01 00 70 02 98 2C 00 00 00 00 04 00 ......p..,......
4000000000098940 0B 00 38 58 98 11 E0 40 9D 00 40 00 00 00 04 00 ..8X...@..@.....
4000000000098950 0B 70 00 1C 00 10 00 00 00 02 00 C0 01 70 50 00 .p...........pP.
4000000000098960 11 00 00 00 01 00 70 00 38 0C 73 00 C0 FA FF 48 ......p.8.s....H
4000000000098970 09 00 00 00 01 00 60 00 20 0E 72 00 00 00 04 00 ......`. .r.....
4000000000098980 11 00 00 00 01 C0 E1 00 20 00 C2 03 10 FF FF 49 ........ ......I
4000000000098990 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000989A0 0B 30 05 4C 00 21 00 00 00 02 00 E0 04 30 59 00 .0.L.!.......0Y.
40000000000989B0 0B 70 A0 4E 00 20 E0 00 38 00 20 00 00 00 04 00 .p.N. ..8. .....
40000000000989C0 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
40000000000989D0 11 00 00 00 01 00 70 00 38 0C 73 00 50 FA FF 48 ......p.8.s.P..H
40000000000989E0 09 00 00 00 01 00 60 00 20 0E 72 00 00 00 04 00 ......`. .r.....
40000000000989F0 11 00 00 00 01 C0 E1 00 20 00 C2 03 90 FD FF 49 ........ ......I
4000000000098A00 10 00 00 00 01 00 60 0A 98 00 42 00 C0 F9 FF 48 ......`...B....H
4000000000098A10 08 38 9C 00 06 30 00 00 00 02 80 69 05 38 01 84 .8...0.....i.8..
4000000000098A20 17 00 00 00 00 C8 01 E0 01 80 21 09 20 F8 FF 4B ..........!. ..K
4000000000098A30 68 02 C4 5A 98 11 00 00 00 02 00 00 00 00 04 00 h..Z............
4000000000098A40 08 00 00 00 01 00 E0 00 BC 30 20 00 02 00 04 90 .........0 .....
4000000000098A50 09 F8 01 52 00 21 00 04 AC 00 42 40 08 20 01 84 ...R.!....B@. ..
4000000000098A60 09 78 A0 1C 00 21 E0 40 38 00 42 20 08 81 31 80 .x...!.@8.B ..1.
4000000000098A70 09 78 00 1E 10 10 E0 03 38 30 20 00 00 00 04 00 .x......80 .....
4000000000098A80 10 00 00 00 01 00 60 60 3C 0E 28 03 F0 02 00 42 ......``<.(....B
4000000000098A90 11 00 00 00 01 00 00 00 00 02 00 00 B8 AD 02 50 ...............P
4000000000098AA0 03 08 00 76 00 21 F0 E7 C1 BF 05 00 A0 03 AA 00 ...v.!..........
4000000000098AB0 02 00 00 00 01 00 00 E8 05 55 00 00 90 0B 00 07 .........U......
4000000000098AC0 18 00 00 00 01 00 C0 00 33 00 42 80 08 00 84 00 ........3.B.....
4000000000098AD0 11 30 AC 52 87 38 00 00 00 02 00 03 B0 F1 FF 4B .0.R.8.........K
4000000000098AE0 11 00 00 00 01 00 00 00 00 02 00 00 E8 6F FF 58 .............o.X
4000000000098AF0 08 30 00 10 07 39 10 00 EC 00 42 00 05 40 00 84 .0...9....B..@..
4000000000098B00 19 F8 01 10 00 21 E0 08 00 00 48 03 80 F1 FF 4B .....!....H....K
4000000000098B10 11 38 00 52 86 39 00 00 00 02 80 03 60 04 00 43 .8.R.9......`..C
4000000000098B20 11 00 00 00 01 00 70 08 A4 0C 63 03 60 00 00 41 ......p...c.`..A
4000000000098B30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000098B40 09 70 04 1C 00 21 F0 03 FC 30 20 00 00 00 04 00 .p...!...0 .....
4000000000098B50 09 00 00 00 01 00 60 70 A4 0E 61 00 00 00 04 00 ......`p..a.....
4000000000098B60 11 00 00 00 01 00 70 00 FC 8C 72 03 E0 FF FF 4A ......p...r....J
4000000000098B70 11 00 00 00 01 00 60 00 FC 0E 72 03 10 F1 FF 4B ......`...r....K
4000000000098B80 11 38 38 56 86 30 E0 08 38 00 42 03 F0 02 00 43 .88V.0..8.B....C
4000000000098B90 E9 38 01 7E 00 21 00 00 00 02 00 C0 E0 58 1D C2 .8.~.!.......X..
4000000000098BA0 09 00 00 00 01 00 60 02 9C 30 20 00 00 00 04 00 ......`..0 .....
4000000000098BB0 11 00 00 00 01 00 70 00 98 8C F2 03 40 00 00 43 ......p.....@..C
4000000000098BC0 09 70 04 1C 00 21 00 00 00 02 00 E0 04 30 01 84 .p...!.......0..
4000000000098BD0 09 30 01 4E 18 10 00 00 00 02 00 C0 E0 58 1D C2 .0.N.........X..
4000000000098BE0 10 00 00 00 01 00 70 00 98 8C 72 03 E0 FF FF 4A ......p...r....J
4000000000098BF0 09 F0 01 40 40 10 00 00 9C 30 23 00 08 20 01 84 ...@@....0#.. ..
4000000000098C00 09 00 00 00 01 00 E0 03 80 00 22 00 00 00 04 00 ..........".....
4000000000098C10 11 00 00 00 01 00 E0 03 F8 28 00 00 F8 A7 FF 58 .........(.....X
4000000000098C20 08 30 9C 4C 07 38 10 00 EC 00 42 00 00 00 04 00 .0.L.8....B.....
4000000000098C30 0A 48 01 10 00 E1 01 30 9D 30 23 00 00 00 04 00 .H.....0.0#.....
4000000000098C40 09 70 80 19 00 21 E0 03 A0 00 42 80 34 20 B1 80 .p...!....B.4 ..
4000000000098C50 11 00 A4 1C 98 11 00 00 00 02 00 00 78 2F FB 58 ............x/.X
4000000000098C60 08 78 80 19 00 21 00 00 00 02 00 E0 00 48 19 E4 .x...!.......H..
4000000000098C70 09 08 00 76 00 21 00 00 00 02 00 20 01 20 21 E6 ...v.!..... . !.
4000000000098C80 10 40 00 1E 18 10 00 00 00 02 00 04 10 F0 FF 4A .@.............J
4000000000098C90 13 F0 01 52 00 E1 01 F8 F7 FF 25 00 F8 74 FF 58 ...R......%..t.X
4000000000098CA0 09 70 80 19 00 21 10 00 EC 00 42 C0 07 48 01 84 .p...!....B..H..
4000000000098CB0 11 00 20 1C 98 11 00 00 00 02 00 00 38 1B F8 58 .. .........8..X
4000000000098CC0 09 78 80 19 00 21 00 00 00 02 00 20 00 D8 01 84 .x...!..... ....
4000000000098CD0 10 40 00 1E 18 10 00 00 00 02 00 00 70 F8 FF 48 .@..........p..H
4000000000098CE0 0B 70 A0 6C 00 21 E0 00 38 20 20 00 00 00 04 00 .p.l.!..8  .....
4000000000098CF0 01 00 00 00 01 00 60 60 38 0E 28 00 00 00 04 00 ......``8.(.....
4000000000098D00 E8 78 20 6C 00 A1 E1 40 D4 00 42 63 E5 4F 01 52 .x l...@..Bc.O.R
4000000000098D10 CB C0 01 6A 00 E1 71 03 3C 30 A0 C3 E1 4F 01 52 ...j..q.<0...O.R
4000000000098D20 E9 78 30 6E 00 A1 E1 00 38 30 20 00 00 00 04 00 .x0n....80 .....
4000000000098D30 EB 58 01 1E 10 D0 B1 5A 39 00 40 00 00 00 04 00 .X.....Z9.@.....
4000000000098D40 03 00 00 00 01 C0 B1 02 AC 2C 00 63 B5 72 00 80 .........,.c.r..
4000000000098D50 10 00 00 00 01 00 60 F8 AF 0E F6 03 D0 F8 FF 48 ......`........H
4000000000098D60 10 00 C4 5A 98 11 00 00 00 02 00 00 20 EF FF 48 ...Z........ ..H
4000000000098D70 11 00 00 00 01 00 00 00 00 02 00 00 98 52 02 50 .............R.P
4000000000098D80 03 08 00 76 00 21 F0 E7 C1 BF 05 00 A0 03 AA 00 ...v.!..........
4000000000098D90 02 00 00 00 01 00 00 E8 05 55 00 00 90 0B 00 07 .........U......
4000000000098DA0 18 00 00 00 01 00 C0 00 33 00 42 80 08 00 84 00 ........3.B.....
4000000000098DB0 09 00 00 00 01 00 70 3A AD 00 40 00 00 00 04 00 ......p:..@.....
4000000000098DC0 11 30 9C 00 07 30 00 00 00 02 00 03 20 00 00 43 .0...0...... ..C
4000000000098DD0 10 00 00 00 01 00 70 38 A5 0C 60 03 80 F4 FF 4A ......p8..`....J
4000000000098DE0 09 F8 91 FB CB 27 00 2C 00 00 48 C0 07 00 00 84 .....'.,..H.....
4000000000098DF0 11 F8 01 7E 18 10 00 00 00 02 00 00 78 1D F8 58 ...~........x..X
4000000000098E00 08 08 00 76 00 21 00 00 00 02 00 C0 07 40 00 84 ...v.!.......@..
4000000000098E10 19 F8 01 50 00 21 00 00 00 02 00 00 78 82 FD 58 ...P.!......x..X
4000000000098E20 09 08 00 76 00 21 00 88 B5 30 23 00 00 00 04 00 ...v.!...0#.....
4000000000098E30 11 00 00 00 01 00 80 E0 04 76 48 00 60 F1 FF 48 .........vH.`..H
4000000000098E40 09 00 00 00 01 00 60 00 20 0E 72 00 00 00 04 00 ......`. .r.....
4000000000098E50 F1 70 00 10 00 21 00 00 00 02 80 03 10 F0 FF 49 .p...!.........I
4000000000098E60 10 00 00 00 01 00 60 0A 98 00 42 00 10 ED FF 48 ......`...B....H
4000000000098E70 09 F0 01 40 40 10 00 00 FC 30 23 00 08 20 01 84 ...@@....0#.. ..
4000000000098E80 09 00 00 00 01 00 E0 03 80 00 22 00 00 00 04 00 ..........".....
4000000000098E90 11 00 00 00 01 00 E0 03 F8 28 00 00 78 A5 FF 58 .........(..x..X
4000000000098EA0 10 08 00 76 00 21 90 02 20 00 42 00 A0 FD FF 48 ...v.!.. .B....H
4000000000098EB0 11 F0 01 6A 00 21 00 00 00 02 00 00 58 E3 09 50 ...j.!......X..P
4000000000098EC0 09 58 01 10 00 21 00 00 00 02 00 20 00 D8 01 84 .X...!..... ....
4000000000098ED0 10 00 00 00 01 00 60 F8 AF 0E F6 03 50 F7 FF 48 ......`.....P..H
4000000000098EE0 10 00 00 00 01 00 00 00 00 02 00 00 80 FE FF 48 ...............H
4000000000098EF0 11 00 00 00 01 00 00 00 00 02 00 00 58 7D FF 58 ............X}.X
4000000000098F00 08 08 00 76 00 21 70 00 98 0C 72 C0 07 30 01 84 ...v.!p...r..0..
4000000000098F10 17 00 00 00 00 C8 01 C0 F6 FF 25 00 F0 F5 FF 48 ..........%....H
4000000000098F20 10 00 00 00 01 00 60 00 A8 0E 73 03 80 F3 FF 4A ......`...s....J
4000000000098F30 10 00 00 00 01 00 80 00 00 00 42 00 60 ED FF 48 ..........B.`..H
4000000000098F40 08 F0 01 5C 18 10 00 00 00 02 00 E0 07 48 01 84 ...\.........H..
4000000000098F50 19 00 02 56 00 21 00 00 00 02 00 00 B8 04 04 50 ...V.!.........P
4000000000098F60 11 08 00 76 00 21 60 02 20 00 42 00 10 F5 FF 48 ...v.!`. .B....H
4000000000098F70 0B 70 50 02 B7 24 00 00 00 02 00 00 00 00 04 00 .pP..$..........
4000000000098F80 11 F0 01 1C 18 10 00 00 00 02 00 00 C8 9B FA 58 ...............X
4000000000098F90 08 F8 01 50 00 21 00 00 00 02 00 20 00 D8 01 84 ...P.!..... ....
4000000000098FA0 19 F0 01 10 00 21 00 00 00 02 00 00 A8 9C FA 58 .....!.........X
4000000000098FB0 08 F8 01 10 00 21 00 00 00 02 00 20 00 D8 01 84 .....!..... ....
4000000000098FC0 09 40 01 10 00 21 00 00 00 02 00 C0 01 00 00 84 .@...!..........
4000000000098FD0 10 00 00 00 01 00 60 00 FC 0E F2 03 B0 FB FF 4A ......`........J
4000000000098FE0 11 00 00 00 01 00 00 00 00 02 00 00 A0 EC FF 48 ...............H
4000000000098FF0 11 30 00 6A 07 39 00 00 00 02 00 03 80 F6 FF 4B .0.j.9.........K
4000000000099000 0B 70 00 6A 00 10 00 00 00 02 00 C0 01 70 50 00 .p.j.........pP.
4000000000099010 10 00 00 00 01 00 60 00 38 0E 73 03 60 F6 FF 4A ......`.8.s.`..J
4000000000099020 0B 70 04 6A 00 21 E0 00 38 00 20 00 00 00 04 00 .p.j.!..8. .....
4000000000099030 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
4000000000099040 10 00 00 00 01 00 60 00 38 0E 73 03 C0 F5 FF 4A ......`.8.s....J
4000000000099050 0B 70 08 6A 00 21 E0 00 38 00 20 00 00 00 04 00 .p.j.!..8. .....
4000000000099060 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
4000000000099070 10 00 00 00 01 00 60 00 38 0E 73 03 50 00 00 42 ......`.8.s.P..B
4000000000099080 11 F0 01 6A 00 21 00 00 00 02 00 00 48 26 F8 58 ...j.!......H&.X
4000000000099090 09 58 01 10 00 21 00 00 00 02 00 20 00 D8 01 84 .X...!..... ....
40000000000990A0 10 00 00 00 01 00 60 F8 AF 0E F6 03 80 F5 FF 48 ......`........H
40000000000990B0 10 00 00 00 01 00 00 00 00 02 00 00 B0 FC FF 48 ...............H
40000000000990C0 11 00 00 00 01 00 B0 12 00 00 48 00 60 F5 FF 48 ..........H.`..H
40000000000990D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000990E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000990F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000099100: 4000000000099100
;;   Called from:
;;     4000000000099A0C (in do_assignment_no_expand)
;;     4000000000099A5C (in do_word_assignment)
;;     4000000000099ACC (in do_assignment)
;;     40000000000A7D0C (in fn40000000000A7940)
;;     40000000000A8B0C (in fn40000000000A7940)
fn4000000000099100 proc
	{ alloc	r41,ar.pfs,0x10,0x0,0xC; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r43,pr }
	{ cmp.eq	p06,p07,0x0,r32; adds	r42,0x0,r1; mov	r40,b0 }
	{ adds	r45,0x0,r0; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000993A0; }

l4000000000099130:
	{ nop.m	0x0; ld8	r34,[r32]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r34; adds	r44,0x0,r34; (p06) br.cond.dpnt.few	40000000000993A0; }

l4000000000099150:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,assignment; }
	{ adds	r44,0x0,r34; nop.m	0x0; adds	r1,0x0,r42 }
	{ adds	r35,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r42; nop.m	0x0; sxt4	r35,r35 }
	{ adds	r44,0x1,r8; nop.m	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r42; nop.m	0x0; adds	r45,0x0,r34 }
	{ adds	r44,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ add	r14,r8,r35; adds	r1,0x0,r42; adds	r34,0x0,r8; }
	{ ld1	r15,[r14]; nop.m	0x0; sxt1	r15,r15; }
	{ cmp4.eq	p07,p06,0x3D,r15; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000993D0; }

l40000000000991F0:
	{ nop.m	0x0; (p06) adds	r37,0x0,r0; (p06) adds	r38,0x0,r0 }

l40000000000991FC:
	{ shladd	r0,r0,0x2,r66; break.x	0x12000002A01000 }

l4000000000099200:
	{ addl	r44,1,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r42; st1	[r0],r8; adds	r36,0x0,r8; }
	{ addl	r14,7372,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000994F0; }

l4000000000099250:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000099260:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r38; (p06) br.cond.dptk.few	4000000000099650 }

l4000000000099270:
	{ adds	r35,0xFFFFFFFFFFFFFFFF,r35; addl	r14,43,r0; adds	r44,0x0,r34 }
	{ adds	r45,0x0,r36; adds	r46,0x0,r37; addl	r47,1,r0; }
	{ nop.m	0x0; add	r35,r34,r35; nop.i	0x0; }
	{ st1	[r14],r35; nop.i	0x0; br.call.sptk.many	b0,xtrace_print_assignment; }
	{ adds	r1,0x0,r42; st1	[r0],r35; addl	r35,1,r0 }

l40000000000992C0:
	{ adds	r44,0x0,r34; addl	r45,91,r0; br.call.sptk.many	b0,mbschr; }
	{ adds	r1,0x0,r42; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	40000000000996A0; }

l40000000000992E0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r37; (p06) br.cond.dptk.few	4000000000099520 }

l40000000000992F0:
	{ addl	r45,-6676,r1; nop.m	0x0; addl	r46,5,r0 }
	{ adds	r44,0x0,r0; nop.m	0x0; adds	r35,0x0,r0; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r42; nop.m	0x0; adds	r44,0x0,r8 }
	{ adds	r45,0x0,r34; nop.m	0x0; br.call.sptk.many	b0,report_error; }
	{ nop.m	0x0; adds	r1,0x0,r42; adds	r44,0x0,r36 }

l4000000000099350:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r42; adds	r44,0x0,r34; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r42; mov	pr,r43,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r41; mov.spnt	b0,r40,4000000000099380 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000993A0:
	{ adds	r35,0x0,r0; adds	r8,0x0,r35; mov	pr,r43,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r41; mov.spnt	b0,r40,40000000000993B0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000993D0:
	{ adds	r15,0xFFFFFFFFFFFFFFFF,r35; add	r36,r8,r35,0x1; add	r15,r8,r15; }
	{ ld1	r16,[r15]; nop.m	0x0; sxt1	r16,r16; }
	{ cmp4.eq	p07,p06,0x2B,r16; (p07) st1	[r0],r15; (p06) adds	r38,0x0,r0 }

l40000000000993FC:
	{ nop; nop }

l4000000000099400:
	{ nop.m	0x0; st1	[r0],r14; nop.i	0x0; }
	{ (p07) addl	r38,1,r0; cmp4.eq	p06,p07,0x0,r33; (p06) br.cond.dptk.few	4000000000099460 }

l4000000000099416:
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD5CE26; nop; (p32) nop }

l4000000000099420:
	{ adds	r14,0x8,r32; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0xF; (p07) br.cond.dpnt.few	4000000000099910; }

l4000000000099440:
	{ ld1	r14,[r36]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	4000000000099780 }

l4000000000099460:
	{ adds	r44,0x0,r36; adds	r37,0x0,r0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r42; adds	r44,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r42; nop.m	0x0; adds	r45,0x0,r36 }
	{ adds	r44,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r36,0x0,r8; nop.m	0x0; adds	r1,0x0,r42; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r36; (p07) br.cond.spnt.few	4000000000099200 }

l40000000000994C0:
	{ addl	r14,7372,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	4000000000099260; }

l40000000000994F0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r38; nop.i	0x0; }
	{ (p06) adds	r35,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000992C0; }

l4000000000099506:
	{ chk.a.nc	r0,3FFFFFFFFF099D06; nop; break.i	0x80000 }

l4000000000099510:
	{ nop.m	0x0; addl	r35,1,r0; br.cond.sptk.few	40000000000992C0; }

l4000000000099520:
	{ adds	r44,0x0,r34; nop.m	0x0; adds	r46,0x0,r35 }
	{ adds	r45,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,assign_array_element; }
	{ cmp.eq	p07,p06,0x0,r8; adds	r1,0x0,r42; adds	r37,0x0,r8; }
	{ (p07) adds	r44,0x0,r36; (p07) adds	r35,0x0,r0; (p07) br.cond.dpnt.few	4000000000099350; }

l4000000000099556:
	{ (p17) chk.a.clr	f0,3FFFFFFFFF119556; nop; break.b	0x80000; }

l400000000009955C:
	{ Invalid; add	r0,r32,r0; zxt1	r64,r64 }

l4000000000099560:
	{ nop.m	0x0; adds	r44,0x0,r34; br.call.sptk.many	b0,stupidly_hack_special_variables; }
	{ adds	r1,0x0,r42; nop.m	0x0; nop.i	0x0 }

l4000000000099580:
	{ adds	r37,0x28,r37; ld4	r14,[r37]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x1; (p06) br.cond.dptk.few	4000000000099640; }

l40000000000995A0:
	{ nop.m	0x0; tbit.z	p06,p07,r14,0xE; addl	r35,1,r0 }
	{ adds	r44,0x0,r36; (p07) addl	r14,9044,r1; (p06) addl	r15,-4097,r0; }

l40000000000995BC:
	{ (p63) nop; break.i	0x1000; Invalid; }

l40000000000995C0:
	{ nop.m	0x0; nop.m	0x0; (p07) addl	r15,1,r0; }

l40000000000995D0:
	{ (p06) and	r14,r15,r14; nop.i	0x0; nop.i	0x0 }

l40000000000995D6:
	{ break.m	0x4000; nop; (p01) cmp.ne.or	p00,p36,r35,r9 }

l40000000000995E6:
	{ mf.a; nop; nop; }

l40000000000995EC:
	{ (p43) addp4	r127,r63,r36; zxt1	r64,r64; Invalid }

l40000000000995F0:
	{ adds	r44,0x0,r34; nop.m	0x0; adds	r45,0x0,r36 }
	{ adds	r46,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r1,0x0,r42; adds	r37,0x0,r8; nop.i	0x0 }
	{ cmp.eq	p16,p17,0x0,r8; adds	r44,0x0,r34; br.call.sptk.many	b0,stupidly_hack_special_variables; }
	{ nop.m	0x0; adds	r1,0x0,r42; (p17) br.cond.dpnt.few	4000000000099580; }

l4000000000099640:
	{ adds	r35,0x0,r0; adds	r44,0x0,r36; br.cond.sptk.few	4000000000099350; }

l4000000000099650:
	{ adds	r44,0x0,r34; adds	r45,0x0,r36; adds	r46,0x0,r37 }
	{ addl	r47,1,r0; adds	r35,0x0,r0; br.call.sptk.many	b0,xtrace_print_assignment; }
	{ adds	r1,0x0,r42; nop.m	0x0; adds	r44,0x0,r34 }
	{ addl	r45,91,r0; nop.m	0x0; br.call.sptk.many	b0,mbschr; }
	{ adds	r1,0x0,r42; cmp.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	40000000000992E0; }

l40000000000996A0:
	{ adds	r32,0x8,r32; cmp4.eq	p06,p07,0x0,r37; nop.i	0x0 }
	{ addl	r38,7148,r1; adds	r44,0x0,r34; (p06) br.cond.dpnt.few	40000000000995F0; }

l40000000000996C0:
	{ nop.m	0x0; movl	r15,0x1020000 }
	{ ld8	r14,[r32]; and	r14,r15,r14; addl	r15,131072,r0; }
	{ cmp.eq	p07,p06,r15,r14; ld4	r14,[r32]; nop.i	0x0; }
	{ (p07) or	r35,0x2,r35; tbit.z	p06,p07,r14,0x16; (p07) or	r35,0x4,r35; }

l40000000000996F6:
	{ (p03) addp4	r44,0xFFFFFFFFFFFFF40E,r7; (p17) nop; break.i	0x80000 }

l4000000000099700:
	{ nop.m	0x0; tbit.z	p06,p07,r35,0x1; (p06) br.cond.dpnt.few	4000000000099730; }

l4000000000099710:
	{ nop.m	0x0; ld4	r14,[r38]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000997E0 }

l4000000000099730:
	{ adds	r45,0x0,r36; adds	r46,0x0,r35; br.call.sptk.many	b0,assign_array_from_string; }
	{ adds	r1,0x0,r42; cmp.eq	p16,p17,0x0,r8; nop.i	0x0 }
	{ adds	r37,0x0,r8; adds	r44,0x0,r34; br.call.sptk.many	b0,stupidly_hack_special_variables; }
	{ nop.m	0x0; adds	r1,0x0,r42; (p16) br.cond.dptk.few	4000000000099640 }

l4000000000099770:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000099580; }

l4000000000099780:
	{ addl	r46,-9788,r1; nop.m	0x0; adds	r44,0x0,r36 }
	{ adds	r45,0x0,r0; nop.m	0x0; adds	r37,0x0,r0; }
	{ ld8	r46,[r46]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000097540; }
	{ adds	r36,0x0,r8; nop.m	0x0; adds	r1,0x0,r42; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r36; (p06) br.cond.sptk.few	40000000000994C0 }

l40000000000997D0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000099200 }

l40000000000997E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x0,r42; adds	r37,0x0,r8; adds	r44,0x0,r8 }
	{ adds	r45,0x0,r36; adds	r46,0x0,r35; br.call.sptk.many	b0,expand_compound_array_assignment; }
	{ adds	r14,0x28,r37; adds	r1,0x0,r42; nop.b	0x0 }
	{ adds	r39,0x0,r8; tbit.z	p06,p07,r35,0x2; (p07) br.cond.dpnt.few	4000000000099970; }

l4000000000099830:
	{ cmp.eq	p16,p17,0x0,r37; nop.i	0x0; (p16) br.cond.dpnt.few	4000000000099890; }

l4000000000099840:
	{ ld8	r14,[r14]; and	r14,0x44,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000099890 }

l4000000000099860:
	{ adds	r15,0x2C,r37; ld4	r14,[r38]; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,r14,r15; (p06) br.cond.dpnt.few	40000000000998B0 }

l4000000000099890:
	{ adds	r44,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,make_local_array_variable; }
	{ adds	r1,0x0,r42; adds	r37,0x0,r8; cmp.eq	p16,p17,0x0,r8; }

l40000000000998B0:
	{ adds	r44,0x0,r37; nop.m	0x0; adds	r45,0x0,r39 }
	{ adds	r46,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,assign_compound_array_list; }
	{ adds	r1,0x0,r42; nop.m	0x0; nop.i	0x0 }

l40000000000998E0:
	{ adds	r44,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,stupidly_hack_special_variables; }
	{ nop.m	0x0; adds	r1,0x0,r42; (p16) br.cond.dptk.few	4000000000099640 }

l4000000000099900:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000099580 }

l4000000000099910:
	{ adds	r45,0x10,r12; nop.m	0x0; addl	r14,1,r0 }
	{ adds	r44,0x0,r36; nop.m	0x0; addl	r37,1,r0; }
	{ st4	[r14],r45; nop.i	0x0; br.call.sptk.many	b0,extract_array_assignment_list; }
	{ adds	r36,0x0,r8; nop.m	0x0; adds	r1,0x0,r42; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r36; (p06) br.cond.sptk.few	40000000000994C0 }

l4000000000099960:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000099200 }

l4000000000099970:
	{ adds	r44,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,make_local_assoc_variable; }
	{ adds	r37,0x0,r8; adds	r1,0x0,r42; nop.i	0x0 }
	{ cmp.eq	p16,p17,0x0,r8; adds	r45,0x0,r39; adds	r46,0x0,r35; }
	{ adds	r44,0x0,r37; nop.i	0x0; br.call.sptk.many	b0,assign_compound_array_list; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	40000000000998E0; }

;; do_assignment_no_expand: 40000000000999C0
;;   Called from:
;;     400000000010C33C (in set_or_show_attributes)
do_assignment_no_expand proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x4; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r33,b1 }
	{ nop.m	0x0; adds	r35,0x0,r1; nop.i	0x0; }
	{ adds	r14,0x10,r12; addl	r15,4,r0; adds	r37,0x0,r0; }
	{ st8	[r32],r14; adds	r36,0x0,r14; adds	r14,0x18,r12; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,fn4000000000099100; }
	{ adds	r1,0x0,r35; mov.i	ar.pfs,r34; mov.spnt	b0,r33,4000000000099A10 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }
4000000000099A30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; do_word_assignment: 4000000000099A40
do_word_assignment proc
	{ nop.m	0x0; addl	r33,1,r0; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn4000000000099100; }
4000000000099A60 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
4000000000099A70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; do_assignment: 4000000000099A80
do_assignment proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x4; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r33,b1 }
	{ nop.m	0x0; adds	r35,0x0,r1; nop.i	0x0; }
	{ adds	r14,0x10,r12; addl	r15,4,r0; addl	r37,1,r0; }
	{ st8	[r32],r14; adds	r36,0x0,r14; adds	r14,0x18,r12; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,fn4000000000099100; }
	{ adds	r1,0x0,r35; mov.i	ar.pfs,r34; mov.spnt	b0,r33,4000000000099AD0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }
4000000000099AF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; setifs: 4000000000099B00
;;   Called from:
;;     4000000000062E3C (in sv_ifs)
;;     4000000000067F8C (in make_local_variable)
;;     400000000006C16C (in initialize_shell_variables)
setifs proc
	{ alloc	r36,ar.pfs,0xB,0x0,0x7; addl	r14,9076,r1; nop.b	0x0 }
	{ adds	r15,0x8,r32; adds	r37,0x0,r1; mov	r38,LC; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r32; mov	r35,b3 }
	{ addl	r34,9092,r1; addl	r39,23540,r1; adds	r40,0x0,r0; }
	{ nop.m	0x0; addl	r41,256,r0; nop.i	0x0; }
	{ st8	[r32],r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000099DB0; }

l4000000000099B60:
	{ ld8	r33,[r15]; nop.m	0x0; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r33; nop.m	0x0; nop.i	0x0; }
	{ (p07) addl	r33,-6668,r1; (p07) ld8	r33,[r33]; nop.i	0x0; }

l4000000000099B86:
	{ (p16) fwb; nop; br.call.spnt.few	b0,b0; }

l4000000000099B8C:
	{ Invalid; Invalid; break.i	0x1000 }
	{ (p41) nop; cmp.lt	p32,p16,r9,r64; Invalid }
	{ cmpxchg2.acq.nt1	r33,[r66],r0; (p18) nop; zxt4	r61,r45; }
	{ (p07) nop; break.i	0x1000; break.i	0x1000 }
	{ nop; break.i	0x1000; break.i	0x1000 }
	{ nop; cmp.lt	p00,p00,r32,r0; (p17) mov.i	KR0,0x3 }

l4000000000099BE0:
	{ nop.m	0x0; ld1	r14,[r15],1; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; zxt1	r16,r14 }
	{ cmp4.eq	p07,p06,0x0,r14; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000099C30; }

l4000000000099C10:
	{ nop.m	0x0; add	r16,r17,r16; nop.i	0x0; }
	{ st1	[r18],r16; nop.i	0x0; br.cloop.sptk.few	4000000000099BE0 }

l4000000000099C30:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r39,0x0,r33; nop.m	0x0; adds	r1,0x0,r37 }
	{ adds	r40,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB20; }
	{ adds	r1,0x0,r37; adds	r33,0x0,r8; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ cmp.ltu	p06,p07,0x1,r8; nop.m	0x0; adds	r1,0x0,r37 }
	{ adds	r40,0x0,r33; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000099D30; }

l4000000000099C90:
	{ ld8	r39,[r34]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AF80; }
	{ adds	r1,0x0,r37; sxt4	r41,r8; addl	r42,16,r0; }
	{ addl	r14,9108,r1; adds	r15,0xFFFFFFFFFFFFFFFE,r41; addl	r39,23524,r1; }
	{ nop.m	0x0; nop.m	0x0; cmp.ltu	p07,p06,0xFFFFFFFFFFFFFFFB,r15 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st8	[r41],r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000099D50; }

l4000000000099CF0:
	{ addl	r14,9092,r1; nop.m	0x0; nop.i	0x0; }
	{ ld8	r40,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B480; }
	{ adds	r1,0x0,r37; mov.i	ar.pfs,r36; mov.i	LC,r38; }
	{ nop.m	0x0; mov.spnt	b0,r35,4000000000099D20; br.ret	b0 }

l4000000000099D30:
	{ addl	r14,9108,r1; addl	r15,1,r0; nop.i	0x0 }
	{ nop.m	0x0; st8	[r15],r14; nop.i	0x0 }

l4000000000099D50:
	{ ld8	r16,[r34]; addl	r15,23524,r1; nop.b	0x0 }
	{ addl	r17,1,r0; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; nop.m	0x0; mov.i	LC,r38; }
	{ nop.m	0x0; ld1	r16,[r16]; mov.spnt	b0,r35,4000000000099D80 }
	{ st8	[r17],r14; st1	[r15],r1,1; nop.i	0x0; }
	{ st1	[r0],r15; nop.i	0x0; br.ret	b0 }

l4000000000099DB0:
	{ addl	r34,9092,r1; addl	r33,-6668,r1; nop.i	0x0 }
	{ addl	r39,23540,r1; adds	r40,0x0,r0; addl	r41,256,r0; }
	{ nop.m	0x0; ld8	r33,[r33]; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st8	[r33],r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B8C0; }
	{ adds	r1,0x0,r37; andcm	r14,0xFFFFFFFFFFFFFFFF,r33; adds	r15,0x0,r33 }
	{ addl	r18,1,r0; addl	r17,23540,r1; mov.i	LC,r14; }
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000099BE0; }
4000000000099E30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; getifs: 4000000000099E40
;;   Called from:
;;     40000000000BD94C (in array_modcase)
;;     40000000000BDD9C (in array_patsub)
;;     40000000000BE1DC (in array_subrange)
;;     40000000000C3FDC (in assoc_modcase)
;;     40000000000C442C (in assoc_patsub)
;;     4000000000104E5C (in read_builtin)
getifs proc
	{ addl	r14,9092,r1; nop.m	0x0; nop.i	0x0; }
	{ ld8	r8,[r14]; nop.i	0x0; br.ret	b0; }
4000000000099E60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000099E70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; word_split: 4000000000099E80
;;   Called from:
;;     4000000000099F8C (in fn4000000000099F40)
;;     4000000000099FDC (in fn4000000000099F40)
word_split proc
	{ alloc	r16,ar.pfs,0x3,0x0,0x3; adds	r15,0x8,r32; cmp.eq	p06,p07,0x0,r32 }
	{ addl	r14,-6740,r1; cmp.eq	p09,p08,0x0,r33; (p06) br.cond.dpnt.few	4000000000099F00; }

l4000000000099EA0:
	{ ld4	r34,[r15]; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; and	r34,0x2,r34; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	4000000000099EE0 }

l4000000000099ED0:
	{ (p08) adds	r14,0x0,r33; nop.m	0x0; nop.i	0x0; }

l4000000000099ED6:
	{ break.m	0x4000; nop; nop }

l4000000000099EE0:
	{ ld8	r32,[r32]; nop.m	0x0; adds	r33,0x0,r14; }

l4000000000099EE2:
	{ break.m	0x20308; zxt1	r32,r0; (p32) nop; }
	{ break.m	0xB000; fms.d.s0	f32,f0,f0,f0; Invalid }

l4000000000099F00:
	{ nop.m	0x0; adds	r8,0x0,r0; br.ret	b0; }
4000000000099F10 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000099F20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000099F30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000099F40: 4000000000099F40
;;   Called from:
;;     400000000009A0FC (in expand_string)
;;     40000000000A842C (in fn40000000000A7940)
;;     40000000000A900C (in expand_word)
fn4000000000099F40 proc
	{ alloc	r37,ar.pfs,0x9,0x0,0x7; addl	r35,9092,r1; mov	r36,b4 }
	{ cmp.eq	p07,p06,0x0,r32; adds	r14,0x8,r32; adds	r38,0x0,r1; }
	{ nop.m	0x0; (p07) adds	r34,0x0,r0; (p07) br.cond.dpnt.few	400000000009A050; }

l4000000000099F6C:
	{ (p07) nop; cmp.eq	p00,p00,r32,r0; (p04) rfi }

l4000000000099F70:
	{ nop.m	0x0; ld8	r39,[r14]; nop.i	0x0; }
	{ ld8	r40,[r35]; nop.i	0x0; br.call.sptk.many	b0,word_split; }
	{ adds	r1,0x0,r38; adds	r33,0x0,r8; adds	r34,0x0,r8; }

l4000000000099FA0:
	{ nop.m	0x0; ld8	r32,[r32]; nop.i	0x0; }
	{ adds	r14,0x8,r32; cmp.eq	p07,p06,0x0,r32; (p07) br.cond.dpnt.few	400000000009A050; }

l4000000000099FC0:
	{ nop.m	0x0; ld8	r39,[r14]; nop.i	0x0 }
	{ ld8	r40,[r35]; nop.m	0x0; br.call.sptk.many	b0,word_split; }
	{ adds	r1,0x0,r38; nop.m	0x0; cmp.eq	p06,p07,0x0,r34 }
	{ adds	r14,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	400000000009A070; }

l400000000009A000:
	{ st8	[r8],r33; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000009A020:
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000099FA0; }

l400000000009A030:
	{ nop.m	0x0; adds	r33,0x0,r14; nop.i	0x0 }
	{ ld8	r14,[r14]; nop.m	0x0; br.cond.sptk.few	400000000009A020 }

l400000000009A050:
	{ adds	r8,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,400000000009A060; br.ret	b0 }

l400000000009A070:
	{ adds	r33,0x0,r8; adds	r34,0x0,r8; br.cond.sptk.few	4000000000099FA0; }

;; expand_string: 400000000009A080
;;   Called from:
;;     40000000000A789C (in expand_string_to_string)
expand_string proc
	{ alloc	r36,ar.pfs,0x8,0x0,0x6; cmp.eq	p07,p06,0x0,r32; mov	r35,b3 }
	{ adds	r37,0x0,r1; adds	r39,0x0,r33; (p07) br.cond.dpnt.few	400000000009A160; }

l400000000009A0A0:
	{ ld1	r14,[r32]; adds	r38,0x0,r32; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000009A160; }

l400000000009A0C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000A6A40; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r37; nop.i	0x0 }
	{ adds	r34,0x0,r8; adds	r38,0x0,r8; (p06) br.cond.dpnt.few	400000000009A160; }

l400000000009A0F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000099F40; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r32,0x0,r8 }
	{ adds	r38,0x0,r34; nop.m	0x0; br.call.sptk.many	b0,dispose_words; }
	{ adds	r1,0x0,r37; cmp.eq	p06,p07,0x0,r32; mov.spnt	b0,r35,400000000009A120 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dpnt.few	400000000009A160; }

l400000000009A140:
	{ nop.m	0x0; mov.i	ar.pfs,r36; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	dequote_list }

l400000000009A160:
	{ adds	r8,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,400000000009A170; br.ret	b0; }

;; fn400000000009A180: 400000000009A180
;;   Called from:
;;     40000000000A2BAC (in fn40000000000A1400)
fn400000000009A180 proc
	{ alloc	r59,ar.pfs,0x26,0x0,0x1F; adds	r12,0xFFFFFFFFFFFFFFA0,r12; nop.b	0x0 }
	{ ld4	r16,[r33]; mov	r61,pr; adds	r60,0x0,r1; }
	{ adds	r41,0x1,r16; nop.m	0x0; mov	r62,LC; }
	{ nop.m	0x0; mov	r58,b2; sxt4	r43,r41; }
	{ add	r42,r32,r43; ld1	r14,[r42]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; zxt1	r40,r14; }
	{ adds	r15,0xFFFFFFFFFFFFFFDF,r40; nop.m	0x0; zxt1	r15,r15; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x5A,r15; (p07) br.cond.dptk.few	400000000009A390; }

l400000000009A200:
	{ adds	r14,0x64,r12; cmp4.eq	p06,p07,0x0,r40; adds	r42,0x0,r41; }
	{ st4	[r41],r14; (p06) br.cond.dpnt.few	400000000009A2B0; br.call.sptk.many	b0,fn400000000001C3C0; }

l400000000009A21C:
	{ (p13) nop; invala; Invalid }
	{ (p16) nop; Invalid; break.i	0x1000; }
	{ Invalid; cmp.eq	p00,p00,r32,r0; (p01) cmp.eq	p00,p00,r10,r4 }

l400000000009A240:
	{ nop.m	0x0; zxt1	r15,r40; shladd	r15,r15,0x1,r16; }
	{ nop.m	0x0; ld2	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r15,0x3; (p06) br.cond.dptk.few	400000000009A280; }

l400000000009A270:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x5F,r40; (p07) br.cond.dpnt.few	400000000009A2A0 }

l400000000009A280:
	{ ld1	r40,[r14],1; nop.m	0x0; adds	r42,0x1,r42; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r40; (p07) br.cond.dptk.few	400000000009A240; }

l400000000009A2A0:
	{ nop.m	0x0; cmp4.lt	p07,p06,r41,r42; (p07) br.cond.dpnt.few	400000000009BBE0 }

l400000000009A2B0:
	{ addl	r63,2,r0; nop.m	0x0; adds	r41,0x0,r42 }
	{ adds	r43,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,xmalloc; }
	{ addl	r15,36,r0; adds	r14,0x0,r8; nop.i	0x0 }
	{ cmp.eq	p06,p07,0x0,r35; adds	r40,0x0,r8; adds	r1,0x0,r60; }
	{ nop.m	0x0; st1	[r14],r1,1; nop.i	0x0; }
	{ st1	[r0],r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000009E150; }

l400000000009A310:
	{ nop.m	0x0; st4	[r0],r35; nop.i	0x0 }
	{ st4	[r41],r33; nop.m	0x0; br.call.sptk.many	b0,alloc_word_desc; }
	{ adds	r14,0x8,r8; st8	[r40],r8; adds	r1,0x0,r60 }
	{ adds	r40,0x0,r8; st4	[r43],r14; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000009A360:
	{ adds	r8,0x0,r40; mov	pr,r61,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r59; }
	{ nop.m	0x0; mov.i	LC,r62; mov.spnt	b0,r58,400000000009A370 }
	{ nop.m	0x0; adds	r12,0x60,r12; br.ret	b0 }

l400000000009A390:
	{ addl	r17,-6396,r1; ld8	r17,[r17]; nop.i	0x0; }
	{ shladd	r15,r15,0x3,r17; ld8	r17,[r15]; nop.i	0x0; }
	{ nop.m	0x0; add	r15,r15,r17; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r15,400000000009A3C0; br.cond	b6; }
400000000009A3D0 0B 78 C0 03 2D 24 00 00 00 02 00 00 00 00 04 00 .x..-$..........
400000000009A3E0 09 00 00 00 01 00 F0 03 3C 20 20 00 00 00 04 00 ........<  .....
400000000009A3F0 10 00 00 00 01 00 70 F8 FF 0C F7 03 A0 16 00 43 ......p........C
400000000009A400 00 00 00 00 01 00 F0 03 FC 2C 00 60 05 00 00 84 .........,.`....
400000000009A410 19 00 00 00 01 00 00 00 00 02 00 00 B8 F6 08 50 ...............P
400000000009A420 08 00 00 00 01 00 E0 00 A8 00 20 20 00 E0 01 84 ..........  ....
400000000009A430 03 40 01 10 00 21 00 00 00 02 00 C0 01 70 50 00 .@...!.......pP.
400000000009A440 03 30 00 1C 87 39 00 00 00 02 80 23 15 48 01 84 .0...9.....#.H..
400000000009A450 11 00 A4 42 90 11 00 00 00 02 00 00 38 82 FA 58 ...B........8..X
400000000009A460 08 70 20 10 00 21 00 40 21 30 23 20 00 E0 01 84 .p ..!.@!0# ....
400000000009A470 09 00 00 00 01 00 80 02 20 00 42 00 00 00 04 00 ........ .B.....
400000000009A480 10 00 AC 1C 90 11 00 00 00 02 00 00 E0 FE FF 48 ...............H
400000000009A490 08 70 F0 02 2E 24 F0 03 00 00 42 00 80 08 2A 00 .p...$....B...*.
400000000009A4A0 0B 00 00 00 01 00 E0 00 38 30 20 00 00 00 04 00 ........80 .....
400000000009A4B0 09 78 20 1C 18 14 00 00 00 02 00 00 12 F8 01 84 .x .............
400000000009A4C0 11 38 00 1E 06 39 00 00 00 02 80 03 20 00 00 43 .8...9...... ..C
400000000009A4D0 10 00 00 00 01 00 F0 03 40 00 42 A0 E0 FF FF 48 ........@.B....H
400000000009A4E0 0B 70 70 03 37 24 00 00 00 02 00 00 00 00 04 00 .pp.7$..........
400000000009A4F0 09 00 00 00 01 00 E0 00 38 30 20 00 00 00 04 00 ........80 .....
400000000009A500 11 00 00 00 01 00 60 00 38 0E 72 03 00 FF FF 4B ......`.8.r....K
400000000009A510 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000009A520 09 70 00 1C 18 10 00 00 00 02 00 E0 17 F8 01 84 .p..............
400000000009A530 11 38 00 1C 06 39 00 00 00 02 80 03 D0 FE FF 4B .8...9.........K
400000000009A540 09 70 00 1C 18 10 00 00 00 02 00 E0 17 F8 01 84 .p..............
400000000009A550 10 00 00 00 01 00 70 00 38 0C 72 03 D0 FF FF 4A ......p.8.r....J
400000000009A560 10 00 00 00 01 00 00 00 00 02 00 00 A0 FE FF 48 ...............H
400000000009A570 09 70 A0 03 46 24 00 00 00 02 00 60 05 00 00 84 .p..F$.....`....
400000000009A580 0B 00 00 00 01 00 F0 03 38 20 20 00 00 00 04 00 ........8  .....
400000000009A590 11 00 00 00 01 00 F0 03 FC 2C 00 00 38 F5 08 50 .........,..8..P
400000000009A5A0 09 70 00 54 00 10 10 00 F0 00 42 00 05 40 00 84 .p.T......B..@..
400000000009A5B0 10 00 00 00 01 00 E0 00 38 28 00 00 90 FE FF 48 ........8(.....H
400000000009A5C0 08 40 91 19 00 21 00 00 00 02 00 00 22 80 00 84 .@...!......"...
400000000009A5D0 09 F8 01 40 00 21 00 00 00 02 00 20 08 00 00 84 ...@.!..... ....
400000000009A5E0 11 00 40 50 90 11 00 04 A0 00 42 00 28 10 FF 58 ..@P......B.(..X
400000000009A5F0 08 00 00 00 01 00 10 00 F0 00 42 40 05 40 00 84 ..........B@.@..
400000000009A600 19 48 01 50 10 10 60 00 20 0E 72 03 30 00 00 43 .H.P..`. .r.0..C
400000000009A610 0B 70 00 10 00 10 00 00 00 02 00 C0 01 70 50 00 .p...........pP.
400000000009A620 11 00 00 00 01 00 70 40 39 0C F3 03 10 20 00 43 ......p@9.... .C
400000000009A630 10 00 00 00 01 00 60 00 9C 0E A8 03 60 13 00 42 ......`.....`..B
400000000009A640 11 F8 01 54 00 21 00 04 88 00 42 00 C8 97 FF 58 ...T.!....B....X
400000000009A650 09 30 00 10 07 39 10 00 F0 00 42 E0 07 40 00 84 .0...9....B..@..
400000000009A660 D1 40 01 00 00 21 00 00 00 02 00 03 30 00 00 43 .@...!......0..C
400000000009A670 13 40 01 10 18 10 00 CC 89 7D 2C 00 00 00 00 20 .@.......},.... 
400000000009A680 08 08 00 78 00 21 00 00 00 02 00 00 00 00 04 00 ...x.!..........
400000000009A690 08 38 00 54 06 39 00 00 00 02 00 E0 07 50 01 84 .8.T.9.......P..
400000000009A6A0 19 58 01 00 00 21 00 00 00 02 80 03 D0 2D 00 43 .X...!.......-.C
400000000009A6B0 11 00 00 00 01 00 00 00 00 02 00 00 38 01 F8 58 ............8..X
400000000009A6C0 01 00 00 00 01 00 E0 00 A4 2C 00 20 00 E0 01 84 .........,. ....
400000000009A6D0 0B 00 81 1C 00 20 E0 00 80 00 20 00 00 00 04 00 ..... .... .....
400000000009A6E0 03 00 00 00 01 00 E0 00 38 28 00 C0 00 70 1C E6 ........8(...p..
400000000009A6F0 10 00 00 00 01 C0 91 0A A4 00 42 00 60 FD FF 48 ..........B.`..H
400000000009A700 11 00 00 00 01 00 00 00 00 02 00 00 C8 53 FF 58 .............S.X
400000000009A710 09 70 0C 44 2C 20 10 00 F0 00 42 80 05 40 00 84 .p.D, ....B..@..
400000000009A720 11 00 00 00 01 00 60 00 38 0E 73 03 20 00 00 42 ......`.8.s. ..B
400000000009A730 10 00 00 00 01 00 70 00 20 0C F2 03 40 20 00 43 ......p. ...@ .C
400000000009A740 09 00 00 00 01 00 E0 58 88 58 40 00 00 00 04 00 .......X.X@.....
400000000009A750 10 00 00 00 01 00 60 00 38 0E 73 03 B0 13 00 42 ......`.8.s....B
400000000009A760 09 10 25 44 2C 20 00 00 00 02 00 E0 07 60 01 84 ..%D, .......`..
400000000009A770 10 00 00 00 01 00 60 00 88 0E 73 03 00 34 00 42 ......`...s..4.B
400000000009A780 11 00 00 00 01 00 00 00 00 02 00 00 48 46 FF 58 ............HF.X
400000000009A790 09 00 00 00 01 00 10 00 F0 00 42 A0 05 40 00 84 ..........B..@..
400000000009A7A0 11 30 00 5A 07 39 F0 03 B4 00 42 03 D0 1F 00 43 .0.Z.9....B....C
400000000009A7B0 11 00 00 00 01 00 00 00 00 02 00 00 98 64 FF 58 .............d.X
400000000009A7C0 08 58 01 5A 00 10 00 00 00 02 00 20 00 E0 01 84 .X.Z....... ....
400000000009A7D0 03 F8 01 5A 00 21 80 02 20 00 42 60 05 58 51 00 ...Z.!.. .B`.XQ.
400000000009A7E0 0B 30 00 56 87 B9 B1 02 40 00 48 00 00 00 04 00 .0.V....@.H.....
400000000009A7F0 11 00 00 00 01 C0 B1 02 00 00 42 00 F8 FF F7 58 ..........B....X
400000000009A800 08 08 00 78 00 21 00 00 00 02 00 00 00 00 04 00 ...x.!..........
400000000009A810 11 F8 01 58 00 21 00 00 00 02 00 00 B8 13 FB 58 ...X.!.........X
400000000009A820 03 70 00 54 00 10 10 00 F0 00 42 C0 01 70 50 00 .p.T......B..pP.
400000000009A830 09 00 00 00 01 00 60 00 38 0E 73 00 00 00 04 00 ......`.8.s.....
400000000009A840 10 00 00 00 01 C0 91 0A A4 00 42 00 10 FC FF 48 ..........B....H
400000000009A850 11 58 01 00 00 21 00 00 00 02 00 00 B8 BF FD 58 .X...!.........X
400000000009A860 09 70 00 54 00 10 10 00 F0 00 42 00 05 40 00 84 .p.T......B..@..
400000000009A870 03 00 00 00 01 00 E0 00 38 28 00 C0 00 70 1C E6 ........8(...p..
400000000009A880 10 00 00 00 01 C0 91 0A A4 00 42 00 D0 FB FF 48 ..........B....H
400000000009A890 09 78 50 03 39 24 80 82 A2 7E 46 00 42 09 DC 92 .xP.9$...~F.B...
400000000009A8A0 08 00 00 00 01 00 00 00 00 02 00 00 05 40 59 00 .............@Y.
400000000009A8B0 0B 00 00 00 01 00 80 42 41 24 40 00 00 00 04 00 .......BA$@.....
400000000009A8C0 09 78 00 1E 10 10 F0 03 A0 30 20 00 00 00 04 00 .x.......0 .....
400000000009A8D0 11 00 00 00 01 00 60 00 3C 0E 73 03 E0 0F 00 42 ......`.<.s....B
400000000009A8E0 10 00 00 00 01 00 70 00 FC 0C F2 03 80 1F 00 43 ......p........C
400000000009A8F0 09 70 00 7E 00 10 20 1A 88 58 40 60 05 00 00 84 .p.~.. ..X@`....
400000000009A900 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
400000000009A910 11 30 00 1C 87 39 00 00 00 02 00 03 20 00 00 43 .0...9...... ..C
400000000009A920 10 00 00 00 01 00 60 00 88 0E F3 03 A0 1A 00 43 ......`........C
400000000009A930 11 00 00 00 01 00 00 00 00 02 00 00 58 58 FF 58 ............XX.X
400000000009A940 09 70 00 54 00 10 10 00 F0 00 42 00 05 40 00 84 .p.T......B..@..
400000000009A950 03 00 00 00 01 00 E0 00 38 28 00 C0 00 70 1C E6 ........8(...p..
400000000009A960 10 00 00 00 01 C0 91 0A A4 00 42 00 F0 FA FF 48 ..........B....H
400000000009A970 09 70 50 03 46 24 00 00 00 02 00 60 05 00 00 84 .pP.F$.....`....
400000000009A980 0B 00 00 00 01 00 F0 03 38 20 20 00 00 00 04 00 ........8  .....
400000000009A990 11 00 00 00 01 00 F0 03 FC 2C 00 00 38 F1 08 50 .........,..8..P
400000000009A9A0 09 70 00 54 00 10 10 00 F0 00 42 00 05 40 00 84 .p.T......B..@..
400000000009A9B0 10 00 00 00 01 00 E0 00 38 28 00 00 90 FA FF 48 ........8(.....H
400000000009A9C0 11 00 00 00 01 00 00 00 00 02 00 00 08 51 FF 58 .............Q.X
400000000009A9D0 08 30 00 4A 07 39 00 00 00 02 00 20 00 E0 01 84 .0.J.9..... ....
400000000009A9E0 19 60 01 10 00 21 00 00 00 02 00 03 40 00 00 43 .`...!......@..C
400000000009A9F0 0B 70 0C 44 2C 20 60 00 38 0E 73 00 00 00 04 00 .p.D, `.8.s.....
400000000009AA00 09 00 00 00 01 C0 E1 08 00 00 48 00 00 00 04 00 ..........H.....
400000000009AA10 E8 00 38 4A 90 11 00 00 00 02 00 00 00 00 04 00 ..8J............
400000000009AA20 08 30 00 48 07 39 00 00 00 02 00 00 08 10 01 84 .0.H.9..........
400000000009AA30 03 F8 01 58 00 21 B0 02 00 00 C2 C3 11 00 00 90 ...X.!..........
400000000009AA40 F1 00 38 48 90 11 00 00 00 02 00 00 C8 66 FF 58 ..8H.........f.X
400000000009AA50 08 08 00 78 00 21 00 00 00 02 00 00 05 40 00 84 ...x.!.......@..
400000000009AA60 19 F8 01 58 00 21 00 00 00 02 00 00 68 11 FB 58 ...X.!......h..X
400000000009AA70 09 70 00 54 00 10 00 00 00 02 00 20 00 E0 01 84 .p.T....... ....
400000000009AA80 10 00 00 00 01 00 E0 00 38 28 00 00 B0 FD FF 48 ........8(.....H
400000000009AA90 09 40 91 19 00 21 00 11 40 00 42 E0 07 00 01 84 .@...!..@.B.....
400000000009AAA0 11 00 40 50 90 11 00 04 A0 00 42 00 E8 0A FF 58 ..@P......B....X
400000000009AAB0 08 38 00 10 06 39 10 00 F0 00 42 40 05 40 00 84 .8...9....B@.@..
400000000009AAC0 19 48 01 50 10 10 F0 03 20 00 C2 03 C0 32 00 43 .H.P.... ....2.C
400000000009AAD0 11 00 06 00 00 24 00 00 00 02 00 00 B8 CE FF 58 .....$.........X
400000000009AAE0 09 00 00 00 01 00 10 00 F0 00 42 00 05 40 00 84 ..........B..@..
400000000009AAF0 09 70 30 03 46 24 B0 02 33 00 42 E0 07 40 01 84 .p0.F$..3.B..@..
400000000009AB00 09 00 00 00 01 00 00 00 00 02 00 00 08 58 01 84 .............X..
400000000009AB10 11 00 00 1C 98 11 00 00 00 02 00 00 78 B5 FD 58 ............x..X
400000000009AB20 08 08 00 78 00 21 00 00 00 02 00 80 05 40 00 84 ...x.!.......@..
400000000009AB30 19 F8 01 54 00 21 00 00 00 02 00 00 B8 FC F7 58 ...T.!.........X
400000000009AB40 11 08 00 78 00 21 F0 03 A0 00 42 00 A8 FC F7 58 ...x.!....B....X
400000000009AB50 09 08 00 78 00 21 E0 00 AC 20 20 00 00 00 04 00 ...x.!...  .....
400000000009AB60 11 38 00 1C 86 39 E0 80 07 64 48 03 80 2D 00 43 .8...9...dH..-.C
400000000009AB70 0B 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
400000000009AB80 11 38 00 1C 86 39 E0 C0 05 64 48 03 E0 0C 00 43 .8...9...dH....C
400000000009AB90 0B 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
400000000009ABA0 10 00 00 00 01 00 60 00 38 0E 73 03 C0 0C 00 42 ......`.8.s....B
400000000009ABB0 09 70 50 03 46 24 80 A2 05 2C 49 E0 11 00 00 90 .pP.F$...,I.....
400000000009ABC0 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000009ABD0 0B 40 00 50 00 21 00 78 38 20 23 E0 DF 83 7F 0B .@.P.!.x8 #.....
400000000009ABE0 01 00 00 00 01 00 00 D8 01 55 00 00 00 00 04 00 .........U......
400000000009ABF0 02 00 00 00 01 00 00 F0 05 55 00 00 A0 0B 00 07 .........U......
400000000009AC00 19 00 00 00 01 00 C0 00 33 00 42 80 08 00 84 00 ........3.B.....
400000000009AC10 09 80 08 20 00 21 B0 22 33 00 42 40 85 66 00 84 ... .!."3.B@.f..
400000000009AC20 00 00 00 00 01 00 80 02 40 2C 00 00 00 00 04 00 ........@,......
400000000009AC30 09 00 40 56 90 11 00 80 A8 20 23 00 00 00 04 00 ..@V..... #.....
400000000009AC40 0B 40 81 50 00 20 E0 00 A0 00 20 00 00 00 04 00 .@.P. .... .....
400000000009AC50 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
400000000009AC60 10 00 00 00 01 00 70 18 39 0C F3 03 60 0D 00 43 ......p.9...`..C
400000000009AC70 08 08 12 FA CC 27 F0 03 80 00 42 00 00 00 04 00 .....'....B.....
400000000009AC80 09 00 02 54 00 21 20 14 00 00 48 C0 85 65 00 84 ...T.! ...H..e..
400000000009AC90 11 08 02 82 18 10 00 00 00 02 00 00 B8 DE FE 58 ...............X
400000000009ACA0 04 78 00 56 10 10 00 00 00 00 00 00 02 00 00 68 .x.V...........h
400000000009ACB0 09 08 00 78 00 21 E0 00 A8 20 20 20 05 40 00 84 ...x.!...   .@..
400000000009ACC0 10 00 40 5C 98 11 70 70 3C 0C F1 03 A0 0F 00 43 ..@\..pp<......C
400000000009ACD0 09 00 00 00 01 00 00 F9 3B 7E 46 00 00 00 04 00 ........;~F.....
400000000009ACE0 10 00 00 00 01 00 60 80 3C 0E 71 03 C0 13 00 43 ......`.<.q....C
400000000009ACF0 03 00 00 00 01 00 F0 00 38 2C 00 E0 01 7A 00 80 ........8,...z..
400000000009AD00 03 40 01 1E 00 10 00 00 00 02 00 00 05 40 51 00 .@...........@Q.
400000000009AD10 11 00 38 56 90 11 60 00 A0 0E 73 03 40 0C 00 42 ..8V..`...s.@..B
400000000009AD20 09 78 04 1C 00 21 70 D0 A1 0C 73 20 42 E8 BF 9D .x...!p...s B...
400000000009AD30 11 00 3C 56 90 11 00 00 00 02 00 03 C0 0B 00 43 ..<V...........C
400000000009AD40 00 00 00 00 01 00 F0 00 3C 2C 00 00 00 00 04 00 ........<,......
400000000009AD50 0B 00 00 00 01 00 F0 00 3D 00 40 00 00 00 04 00 ........=.@.....
400000000009AD60 0B 80 00 1E 00 10 00 00 00 02 00 00 02 80 50 00 ..............P.
400000000009AD70 03 00 00 00 01 00 20 01 40 20 00 20 22 89 44 80 ...... .@ . ".D.
400000000009AD80 09 00 00 00 01 00 10 01 44 20 20 00 00 00 04 00 ........D  .....
400000000009AD90 11 00 00 00 01 00 60 C0 44 0E 28 03 90 2D 00 42 ......`.D.(..-.B
400000000009ADA0 10 40 01 20 00 21 60 00 40 0E 73 03 D0 35 00 42 .@. .!`.@.s..5.B
400000000009ADB0 08 70 08 1C 00 21 30 03 00 00 42 00 00 00 04 00 .p...!0...B.....
400000000009ADC0 09 90 01 00 00 21 10 03 00 00 42 00 16 00 00 90 .....!....B.....
400000000009ADD0 08 00 38 56 90 11 00 00 00 02 00 00 00 00 04 00 ..8V............
400000000009ADE0 0B 50 01 52 00 10 00 00 00 02 00 40 05 50 51 00 .P.R.......@.PQ.
400000000009ADF0 11 00 00 00 01 00 70 18 A9 0C F3 03 40 10 00 43 ......p.....@..C
400000000009AE00 10 00 00 00 01 00 70 08 A9 0C F3 03 E0 10 00 43 ......p........C
400000000009AE10 0B 50 41 55 3F 23 00 00 00 02 00 40 05 50 41 00 .PAU?#.....@.PA.
400000000009AE20 11 00 00 00 01 00 70 48 A8 0C 6B 03 90 26 00 43 ......pH..k..&.C
400000000009AE30 09 60 05 52 00 21 00 00 00 02 00 00 00 00 04 00 .`.R.!..........
400000000009AE40 08 00 00 00 01 00 E0 00 B0 00 20 A0 05 00 00 84 .......... .....
400000000009AE50 09 00 00 00 01 00 A0 02 A4 00 20 00 00 00 04 00 .......... .....
400000000009AE60 01 00 00 00 01 00 E0 00 38 28 00 40 05 50 51 00 ........8(.@.PQ.
400000000009AE70 08 78 10 FA 6F 27 00 00 00 02 00 E0 00 70 18 E6 .x..o'.......p..
400000000009AE80 11 00 00 00 01 00 00 01 A8 20 00 03 F0 12 00 43 ......... .....C
400000000009AE90 0B 00 00 00 01 00 F0 80 3C 22 40 00 00 00 04 00 ........<"@.....
400000000009AEA0 09 00 00 00 01 00 F0 00 3C 20 20 00 00 00 04 00 ........<  .....
400000000009AEB0 10 00 00 00 01 00 70 B0 3C 0C A8 03 C0 12 00 42 ......p.<......B
400000000009AEC0 09 78 05 00 00 24 00 00 00 02 00 00 00 00 04 00 .x...$..........
400000000009AED0 11 38 8C 54 86 39 00 00 00 02 80 03 20 26 00 43 .8.T.9...... &.C
400000000009AEE0 11 00 00 00 01 00 70 00 AA 0C F3 03 50 14 00 43 ......p.....P..C
400000000009AEF0 10 00 00 00 01 00 60 00 B4 0E 73 03 40 25 00 42 ......`...s.@%.B
400000000009AF00 0B 78 00 56 10 10 00 00 00 02 00 C0 01 78 58 00 .x.V.........xX.
400000000009AF10 0B 70 80 1C 00 20 F0 F8 3B 7E 46 00 00 00 04 00 .p... ..;~F.....
400000000009AF20 0B 78 00 1E 00 10 00 00 00 02 00 E0 01 78 50 00 .x...........xP.
400000000009AF30 11 00 00 00 01 00 70 E8 3F 0C F3 03 D0 14 00 43 ......p.?......C
400000000009AF40 C9 60 05 52 00 21 00 00 00 02 00 00 00 00 04 00 .`.R.!..........
400000000009AF50 0B 70 00 58 00 10 E0 80 3A 7E 46 00 00 00 04 00 .p.X....:~F.....
400000000009AF60 01 00 00 00 01 00 E0 00 38 20 00 00 00 00 04 00 ........8 ......
400000000009AF70 11 00 00 00 01 00 70 48 38 0C 6B 03 80 13 00 43 ......pH8.k....C
400000000009AF80 11 00 00 00 01 00 70 00 BC 0C F3 03 10 12 00 43 ......p........C
400000000009AF90 10 00 00 00 01 00 70 00 B4 0C F3 03 50 2C 00 42 ......p.....P,.B
400000000009AFA0 08 F8 05 52 00 21 00 04 BC 00 42 20 08 10 01 84 ...R.!....B ....
400000000009AFB0 19 10 0A 00 00 24 30 04 00 00 42 00 98 C1 00 50 .....$0...B....P
400000000009AFC0 08 50 01 10 18 10 00 00 00 02 00 C0 31 10 B1 80 .P..........1...
400000000009AFD0 09 08 00 78 00 21 00 00 00 02 00 A0 05 40 00 84 ...x.!.......@..
400000000009AFE0 11 30 00 54 07 39 F0 03 A8 00 42 03 D0 31 00 43 .0.T.9....B..1.C
400000000009AFF0 10 00 00 00 01 00 60 00 38 0E 73 03 80 32 00 42 ......`.8.s..2.B
400000000009B000 11 00 00 00 01 00 00 00 00 02 00 00 08 64 FF 58 .............d.X
400000000009B010 08 00 00 00 01 00 10 00 F0 00 42 80 05 40 00 84 ..........B..@..
400000000009B020 11 F8 01 54 00 21 00 00 00 02 00 00 C8 F7 F7 58 ...T.!.........X
400000000009B030 11 08 00 78 00 21 F0 03 B4 00 42 00 D8 09 FB 58 ...x.!....B....X
400000000009B040 08 08 00 78 00 21 F0 03 B0 00 42 00 08 10 01 84 ...x.!....B.....
400000000009B050 19 08 02 4A 00 21 20 04 90 00 42 00 78 A4 FE 58 ...J.! ...B.x..X
400000000009B060 11 08 00 78 00 21 60 00 B0 0E 72 03 90 31 00 41 ...x.!`...r..1.A
400000000009B070 0B 70 00 58 00 10 E0 80 3A 7E 46 00 00 00 04 00 .p.X....:~F.....
400000000009B080 01 00 00 00 01 00 E0 00 38 20 00 00 00 00 04 00 ........8 ......
400000000009B090 10 00 00 00 01 00 70 48 38 0C 6B 03 20 17 00 43 ......pH8.k. ..C
400000000009B0A0 0B 70 04 58 00 21 E0 00 38 00 20 00 00 00 04 00 .p.X.!..8. .....
400000000009B0B0 03 00 00 00 01 00 E0 00 38 28 00 C0 00 70 1C E6 ........8(...p..
400000000009B0C0 10 00 00 00 01 C0 01 04 00 00 C2 03 40 00 00 42 ............@..B
400000000009B0D0 09 70 10 FA 6F 27 F0 00 B0 00 20 00 00 00 04 00 .p..o'.... .....
400000000009B0E0 0B 00 00 00 01 00 E0 78 38 22 40 00 00 00 04 00 .......x8"@.....
400000000009B0F0 02 00 02 1C 10 10 00 00 00 02 00 00 68 01 02 52 ............h..R
400000000009B100 08 08 02 44 00 21 20 04 00 00 42 00 00 00 04 00 ...D.! ...B.....
400000000009B110 19 18 02 00 00 21 F0 03 B0 00 42 00 38 C0 00 50 .....!....B.8..P
400000000009B120 08 08 00 78 00 21 00 00 00 02 00 40 05 40 00 84 ...x.!.....@.@..
400000000009B130 19 F8 01 58 00 21 00 00 00 02 00 00 B8 F6 F7 58 ...X.!.........X
400000000009B140 08 08 00 78 00 21 00 00 00 02 00 00 00 00 04 00 ...x.!..........
400000000009B150 08 70 00 54 00 21 00 00 00 02 00 C0 00 50 1D E4 .p.T.!.......P..
400000000009B160 19 F8 01 54 00 21 00 00 00 02 00 03 90 30 00 43 ...T.!.......0.C
400000000009B170 09 00 00 00 01 00 C0 42 38 30 28 00 00 00 04 00 .......B80(.....
400000000009B180 11 C8 01 1C 10 10 00 00 00 02 00 00 88 08 FB 58 ...............X
400000000009B190 09 38 00 58 06 39 10 00 F0 00 42 E0 07 48 01 84 .8.X.9....B..H..
400000000009B1A0 CB 70 04 00 00 E4 E1 00 00 00 42 00 00 00 04 00 .p........B.....
400000000009B1B0 11 C0 01 1C 00 21 70 03 38 00 42 00 18 4B 02 50 .....!p.8.B..K.P
400000000009B1C0 11 08 00 78 00 21 60 00 20 0E F3 03 80 15 00 43 ...x.!`. ......C
400000000009B1D0 11 00 00 00 01 00 60 00 C0 0E 73 03 70 16 00 42 ......`...s.p..B
400000000009B1E0 10 00 00 00 01 00 70 00 DC 0C F3 03 30 00 00 42 ......p.....0..B
400000000009B1F0 0B 70 00 58 00 10 00 00 00 02 00 C0 01 70 50 00 .p.X.........pP.
400000000009B200 10 00 00 00 01 00 60 00 38 0E F3 03 40 16 00 42 ......`.8...@..B
400000000009B210 08 80 05 00 00 24 00 00 00 02 00 00 00 00 04 00 .....$..........
400000000009B220 0B 88 F4 51 90 39 64 04 00 00 F0 E8 08 00 00 E0 ...Q.9d.........
400000000009B230 09 00 00 00 01 00 70 00 A0 8C 73 00 00 00 04 00 ......p...s.....
400000000009B240 F0 68 01 56 10 D0 A1 02 00 00 C2 03 F0 00 00 42 .h.V...........B
400000000009B250 09 00 00 00 01 00 60 28 A1 0E 73 00 00 00 04 00 ......`(..s.....
400000000009B260 11 00 00 00 01 00 60 18 A1 8E 73 03 10 2B 00 42 ......`...s..+.B
400000000009B270 09 00 00 00 01 00 60 78 A1 0E 73 00 00 00 04 00 ......`x..s.....
400000000009B280 11 00 00 00 01 00 60 F0 A2 8E 73 03 F0 2A 00 42 ......`...s..*.B
400000000009B290 0B 30 B0 50 87 39 60 D0 A1 8E 73 00 00 00 04 00 .0.P.9`...s.....
400000000009B2A0 C2 10 02 00 06 24 00 00 00 02 80 43 08 00 10 90 .....$.....C....
400000000009B2B0 08 F8 01 40 00 21 00 00 00 02 00 00 08 58 01 84 ...@.!.......X..
400000000009B2C0 19 08 02 44 00 21 00 00 00 02 00 00 48 DD FE 58 ...D.!......H..X
400000000009B2D0 09 68 01 56 10 10 10 00 F0 00 42 40 05 40 00 84 .h.V......B@.@..
400000000009B2E0 03 00 00 00 01 00 E0 00 B4 2C 00 C0 01 72 00 80 .........,...r..
400000000009B2F0 0B 70 00 1C 00 10 00 00 00 02 00 C0 01 70 50 00 .p...........pP.
400000000009B300 10 00 00 00 01 00 70 E8 3B 0C 73 03 E0 0E 00 42 ......p.;.s....B
400000000009B310 09 00 00 00 01 00 D0 0A B4 00 42 00 00 00 04 00 ..........B.....
400000000009B320 08 00 B4 56 90 11 00 00 00 02 00 00 00 00 04 00 ...V............
400000000009B330 0B 70 C4 64 0E 20 E0 98 39 1C 40 00 00 00 04 00 .p.d. ..9.@.....
400000000009B340 11 00 00 00 01 00 70 00 38 0C 73 03 30 19 00 42 ......p.8.s.0..B
400000000009B350 09 00 00 00 01 00 60 18 A1 0E 73 00 00 00 04 00 ......`...s.....
400000000009B360 10 00 00 00 01 00 60 28 A1 8E 73 03 10 19 00 42 ......`(..s....B
400000000009B370 11 00 00 00 01 00 00 00 00 02 80 08 00 19 00 43 ...............C
400000000009B380 11 00 00 00 01 00 60 00 CC 0E 73 03 90 36 00 42 ......`...s..6.B
400000000009B390 08 70 30 03 46 24 70 00 B0 0C 72 00 E1 CA 25 50 .p0.F$p...r...%P
400000000009B3A0 19 08 02 5C 10 10 70 C3 31 00 C2 03 D0 42 00 43 ...\..p.1....B.C
400000000009B3B0 08 00 00 00 01 00 F0 02 32 00 42 64 08 00 00 84 ........2.Bd....
400000000009B3C0 09 F8 01 52 00 21 00 04 B0 00 42 40 08 10 01 84 ...R.!....B@....
400000000009B3D0 28 19 12 00 00 24 40 04 DC 00 42 20 08 08 5A 00 (....$@...B ..Z.
400000000009B3E0 09 28 02 5E 00 21 20 1B 88 58 40 00 F5 E7 FB 9F .(.^.! ..X@.....
400000000009B3F0 11 00 A4 1C 98 11 00 00 00 02 00 00 D8 64 FF 58 .............d.X
400000000009B400 08 30 FC 11 87 3B 80 00 C8 12 73 00 00 00 04 00 .0...;....s.....
400000000009B410 19 08 00 78 00 21 80 42 21 18 40 03 60 42 00 43 ...x.!.B!.@.`B.C
400000000009B420 03 91 01 00 00 21 60 70 20 0E A8 44 06 02 00 90 .....!`p ..D....
400000000009B430 F1 90 01 65 2E 20 70 F0 DA 0C F3 03 90 3E 00 43 ...e. p......>.C
400000000009B440 11 38 B0 6C 86 39 00 00 00 02 80 03 D0 3E 00 43 .8.l.9.......>.C
400000000009B450 11 38 F8 6D 86 39 00 00 00 02 80 03 A0 1E 00 43 .8.m.9.........C
400000000009B460 C9 58 01 54 00 A1 E1 02 00 00 42 03 02 50 45 E4 .X.T......B..PE.
400000000009B470 09 30 00 56 07 39 00 00 00 02 00 E0 07 58 01 84 .0.V.9.......X..
400000000009B480 C8 98 01 00 00 21 00 00 00 02 00 03 06 00 00 84 .....!..........
400000000009B490 17 00 00 00 00 88 01 40 00 80 21 00 38 02 F8 58 .......@..!.8..X
400000000009B4A0 11 08 00 78 00 21 F0 0B 20 00 42 00 28 D8 04 50 ...x.!.. .B.(..P
400000000009B4B0 08 08 00 78 00 21 00 00 00 02 00 E0 07 40 00 84 ...x.!.......@..
400000000009B4C0 19 00 02 56 00 21 00 00 00 02 00 00 C8 FC F7 58 ...V.!.........X
400000000009B4D0 08 30 00 10 07 39 10 00 F0 00 42 60 06 40 00 84 .0...9....B`.@..
400000000009B4E0 19 F8 01 10 00 21 00 04 88 00 42 03 C0 55 00 43 .....!....B..U.C
400000000009B4F0 11 00 00 00 01 00 00 00 00 02 00 00 D8 BA 00 50 ...............P
400000000009B500 08 00 00 00 01 00 10 00 F0 00 42 00 06 40 00 84 ..........B..@..
400000000009B510 11 30 04 50 87 39 00 00 00 02 00 03 30 3F 00 43 .0.P.9......0?.C
400000000009B520 11 30 04 50 87 31 00 00 00 02 80 03 20 1E 00 43 .0.P.1...... ..C
400000000009B530 11 30 08 50 87 39 00 00 00 02 00 03 B0 3E 00 43 .0.P.9.......>.C
400000000009B540 11 00 00 00 01 00 60 18 A0 0E 73 03 10 1E 00 43 ......`...s....C
400000000009B550 11 30 00 60 07 39 F0 03 C0 00 42 03 30 00 00 43 .0.`.9....B.0..C
400000000009B560 11 00 00 00 01 00 00 00 00 02 00 00 88 F2 F7 58 ...............X
400000000009B570 08 08 00 78 00 21 00 00 00 02 00 00 00 00 04 00 ...x.!..........
400000000009B580 11 00 00 00 01 00 F0 03 CC 00 42 00 68 F2 F7 58 ..........B.h..X
400000000009B590 08 08 00 78 00 21 00 00 00 02 00 00 00 00 04 00 ...x.!..........
400000000009B5A0 11 F8 01 52 00 21 00 00 00 02 00 00 48 F2 F7 58 ...R.!......H..X
400000000009B5B0 11 08 00 78 00 61 F4 03 A8 00 C2 08 38 F2 F7 5A ...x.a......8..Z
400000000009B5C0 08 30 00 70 87 39 00 00 00 02 80 28 00 E0 01 84 .0.p.9.....(....
400000000009B5D0 19 F8 01 58 00 21 00 00 00 02 00 03 30 00 00 43 ...X.!......0..C
400000000009B5E0 11 00 00 00 01 00 00 00 00 02 00 00 08 F2 F7 58 ...............X
400000000009B5F0 09 08 00 78 00 21 00 00 00 02 00 00 00 00 04 00 ...x.!..........
400000000009B600 09 00 00 00 01 00 E0 E0 04 76 48 00 00 00 04 00 .........vH.....
400000000009B610 11 30 38 6A 07 38 E0 E8 04 76 48 03 50 02 00 43 .08j.8...vH.P..C
400000000009B620 11 30 38 6A 07 38 00 00 00 02 00 03 E0 12 00 43 .08j.8.........C
400000000009B630 11 00 00 00 01 00 00 00 00 02 00 00 58 70 FA 58 ............Xp.X
400000000009B640 08 08 00 78 00 21 00 A8 21 30 23 00 00 00 04 00 ...x.!..!0#.....
400000000009B650 19 40 01 10 00 21 60 00 D4 0E 72 03 A0 00 00 43 .@...!`...r....C
400000000009B660 0B 70 00 6A 00 10 00 00 00 02 00 C0 01 70 50 00 .p.j.........pP.
400000000009B670 10 00 00 00 01 00 70 F8 3B 0C 73 03 80 00 00 42 ......p.;.s....B
400000000009B680 0B A8 05 6A 00 21 E0 00 D4 00 20 00 00 00 04 00 ...j.!.... .....
400000000009B690 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
400000000009B6A0 10 00 00 00 01 00 70 00 38 0C 73 03 50 00 00 43 ......p.8.s.P..C
400000000009B6B0 09 10 0D 44 2C 20 E0 40 A0 00 42 00 22 80 00 90 ...D, .@..B."...
400000000009B6C0 11 30 00 44 87 39 00 00 00 02 00 03 30 00 00 43 .0.D.9......0..C
400000000009B6D0 03 78 00 1C 10 10 00 00 00 02 00 E0 01 79 38 80 .x...........y8.
400000000009B6E0 08 00 3C 1C 90 11 00 00 00 02 00 00 00 00 04 00 ..<.............
400000000009B6F0 0B 70 90 02 96 24 00 00 00 02 00 00 00 00 04 00 .p...$..........
400000000009B700 11 30 38 50 07 38 E0 A0 05 2C 49 03 60 01 00 41 .08P.8...,I.`..A
400000000009B710 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000009B720 11 38 38 50 06 38 E0 40 A0 00 C2 03 E0 11 00 43 .88P.8.@.......C
400000000009B730 09 00 00 00 01 00 F0 03 A0 30 20 00 00 00 04 00 .........0 .....
400000000009B740 11 30 00 7E 07 39 00 00 00 02 00 03 50 00 00 43 .0.~.9......P..C
400000000009B750 09 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
400000000009B760 10 00 00 00 01 00 60 20 39 0E 28 03 30 00 00 42 ......` 9.(.0..B
400000000009B770 0B 70 00 7E 00 10 00 00 00 02 00 C0 01 70 50 00 .p.~.........pP.
400000000009B780 10 00 00 00 01 00 70 F8 3B 0C F3 03 20 17 00 43 ......p.;... ..C
400000000009B790 09 00 B4 42 90 11 00 00 00 02 00 00 00 00 04 00 ...B............
400000000009B7A0 03 40 00 50 00 21 F0 EF C1 BF 05 00 B0 03 AA 00 .@.P.!..........
400000000009B7B0 02 00 00 00 01 00 00 F0 05 55 00 00 A0 0B 00 07 .........U......
400000000009B7C0 18 00 00 00 01 00 C0 00 33 00 42 80 08 00 84 00 ........3.B.....
400000000009B7D0 09 00 B2 FA CC 27 10 2C 00 00 48 E0 07 00 00 84 .....'.,..H.....
400000000009B7E0 11 00 02 80 18 10 00 00 00 02 00 00 88 F3 F7 58 ...............X
400000000009B7F0 08 00 02 52 00 21 00 00 00 02 00 E0 07 40 00 84 ...R.!.......@..
400000000009B800 19 08 00 78 00 21 00 00 00 02 00 00 48 55 FD 58 ...x.!......HU.X
400000000009B810 11 08 00 78 00 21 F0 03 A4 00 42 00 D8 EF F7 58 ...x.!....B....X
400000000009B820 08 00 00 00 01 00 10 00 F0 00 42 E0 07 50 01 84 ..........B..P..
400000000009B830 19 00 00 00 01 00 00 00 00 02 00 00 B8 EF F7 58 ...............X
400000000009B840 09 08 00 78 00 21 00 00 00 02 00 00 00 00 04 00 ...x.!..........
400000000009B850 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

l400000000009B860:
	{ nop.m	0x0; addl	r40,19236,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }

l400000000009B880:
	{ adds	r8,0x0,r40; mov	pr,r61,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r59; }
	{ nop.m	0x0; mov.i	LC,r62; mov.spnt	b0,r58,400000000009B890 }
	{ nop.m	0x0; adds	r12,0x60,r12; br.ret	b0 }
400000000009B8B0 11 30 00 7E 07 39 00 00 00 02 80 03 40 F0 FF 4A .0.~.9......@..J
400000000009B8C0 08 00 00 00 01 80 B1 02 00 00 42 03 05 00 00 84 ..........B.....
400000000009B8D0 09 00 00 00 01 00 60 00 38 0E 73 00 00 00 04 00 ......`.8.s.....
400000000009B8E0 10 00 00 00 01 C0 91 0A A4 00 42 00 70 EB FF 48 ..........B.p..H
400000000009B8F0 11 30 BC 50 87 39 00 00 00 02 00 03 30 23 00 43 .0.P.9......0#.C
400000000009B900 09 00 00 00 01 00 60 F0 A2 0E 73 00 00 00 04 00 ......`...s.....
400000000009B910 11 00 00 00 01 00 60 60 A1 8E 73 03 80 22 00 42 ......``..s..".B
400000000009B920 09 00 00 00 01 00 70 F0 A3 0C 73 00 00 00 04 00 ......p...s.....
400000000009B930 E8 B0 F9 01 00 E4 31 0B 00 00 C8 43 06 00 00 84 ......1....C....
400000000009B940 F9 88 01 00 00 E1 01 03 00 00 C2 03 A0 F4 FF 4B ...............K
400000000009B950 08 50 01 52 00 10 30 03 00 00 42 40 06 00 00 84 .P.R..0...B@....
400000000009B960 03 88 01 00 00 21 00 03 00 00 42 40 05 50 51 00 .....!....B@.PQ.
400000000009B970 10 00 00 00 01 00 70 18 A9 0C 73 03 90 F4 FF 4A ......p...s....J
400000000009B980 10 00 00 00 01 00 00 00 00 02 00 00 B0 04 00 40 ...............@
400000000009B990 08 F8 01 40 00 21 00 04 84 20 20 20 18 48 01 84 ...@.!...   .H..
400000000009B9A0 19 00 00 00 01 00 00 00 00 02 00 00 68 DA 03 50 ............h..P
400000000009B9B0 11 08 00 78 00 21 80 02 20 00 42 00 E0 EC FF 48 ...x.!.. .B....H
400000000009B9C0 11 40 05 50 00 21 00 00 00 02 00 00 08 0A F8 58 .@.P.!.........X
400000000009B9D0 08 00 00 00 01 00 E0 00 A0 00 20 20 00 E0 01 84 ..........  ....
400000000009B9E0 0B 78 00 10 18 10 00 00 00 02 00 C0 01 70 50 00 .x...........pP.
400000000009B9F0 0B 78 38 1E 10 20 F0 00 3C 10 20 00 00 00 04 00 .x8.. ..<. .....
400000000009BA00 11 00 00 00 01 00 70 A0 3C 0C 28 03 20 00 00 43 ......p.<.(. ..C
400000000009BA10 10 00 00 00 01 00 70 F8 3A 0C 73 03 60 F2 FF 4A ......p.:.s.`..J
400000000009BA20 08 08 D2 FB CA 27 F0 03 80 00 42 00 00 00 04 00 .....'....B.....
400000000009BA30 09 00 02 54 00 21 20 14 00 00 48 C0 85 65 00 84 ...T.! ...H..e..
400000000009BA40 11 08 02 82 18 10 00 00 00 02 00 00 08 D1 FE 58 ...............X
400000000009BA50 04 78 00 56 10 10 00 00 00 00 00 00 02 00 00 68 .x.V...........h
400000000009BA60 09 08 00 78 00 21 E0 00 A8 20 20 20 05 40 00 84 ...x.!...   .@..
400000000009BA70 10 00 40 5C 98 11 70 70 3C 0C 71 03 60 F2 FF 4A ..@\..pp<.q.`..J
400000000009BA80 11 00 00 00 01 00 00 00 00 02 00 00 E0 01 00 40 ...............@
400000000009BA90 08 78 50 03 39 24 60 00 8C 0E 72 60 05 00 00 84 .xP.9$`...r`....
400000000009BAA0 0A 40 01 00 00 21 00 00 00 02 00 00 00 00 04 00 .@...!..........
400000000009BAB0 EB 00 00 46 90 11 F0 00 3C 20 20 00 00 00 04 00 ...F....<  .....
400000000009BAC0 11 38 00 1E 86 39 00 00 00 02 00 03 A0 0D 00 43 .8...9.........C
400000000009BAD0 09 00 00 00 01 00 E0 00 A8 00 20 00 00 00 04 00 .......... .....
400000000009BAE0 03 00 00 00 01 00 E0 00 38 28 00 C0 00 70 1C E6 ........8(...p..
400000000009BAF0 10 00 00 00 01 C0 91 0A A4 00 42 00 60 E9 FF 48 ..........B.`..H
400000000009BB00 09 58 11 02 3B 24 00 00 00 02 00 E0 07 60 01 84 .X..;$.......`..
400000000009BB10 09 00 00 00 01 00 E0 00 AC 20 20 00 00 00 04 00 .........  .....
400000000009BB20 11 30 00 1C 87 39 E0 20 07 6E 49 03 30 00 00 43 .0...9. .nI.0..C
400000000009BB30 0B 00 00 00 01 00 E0 00 38 00 20 00 00 00 04 00 ........8. .....
400000000009BB40 10 00 00 00 01 00 70 00 38 0C F2 03 E0 0B 00 43 ......p.8......C
400000000009BB50 11 00 02 44 00 21 00 00 00 02 00 00 B8 55 FF 58 ...D.!.......U.X
400000000009BB60 08 00 00 00 01 00 10 00 F0 00 42 00 05 40 00 84 ..........B..@..
400000000009BB70 09 70 00 56 10 10 00 00 00 02 00 60 05 00 00 84 .p.V.......`....
400000000009BB80 11 00 00 00 01 00 70 00 38 0C 73 03 90 EC FF 4A ......p.8.s....J
400000000009BB90 08 30 00 48 07 39 00 00 00 02 00 C0 11 00 00 90 .0.H.9..........
400000000009BBA0 19 F8 01 58 00 21 00 00 00 02 00 03 70 EC FF 4B ...X.!......p..K
400000000009BBB0 11 00 38 48 90 11 00 00 00 02 00 00 18 00 FB 58 ..8H...........X
400000000009BBC0 09 70 00 54 00 10 00 00 00 02 00 20 00 E0 01 84 .p.T....... ....
400000000009BBD0 10 00 00 00 01 00 E0 00 38 28 00 00 60 EC FF 48 ........8(..`..H

l400000000009BBE0:
	{ adds	r64,0x0,r41; nop.m	0x0; adds	r63,0x0,r32 }
	{ adds	r65,0x0,r42; nop.m	0x0; br.call.sptk.many	b0,substring; }
	{ adds	r1,0x0,r60; cmp.eq	p06,p07,0x0,r8; nop.i	0x0 }
	{ adds	r63,0x0,r8; adds	r41,0x0,r8; (p06) br.cond.spnt.few	400000000009A2B0; }

l400000000009BC20:
	{ ld1	r14,[r8]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000009D940; }

l400000000009BC40:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r60; br.cond.sptk.few	400000000009A2B0 }
400000000009BC60 03 00 00 00 01 00 00 01 3C 2C 00 00 02 82 00 80 ........<,......
400000000009BC70 09 00 00 00 01 00 00 01 40 00 20 00 00 00 04 00 ........@. .....
400000000009BC80 03 00 00 00 01 00 00 01 40 28 00 C0 D0 82 1C E6 ........@(......
400000000009BC90 11 00 00 00 01 00 60 F8 41 8E 73 03 30 00 00 42 ......`.A.s.0..B
400000000009BCA0 11 00 00 00 01 00 60 18 41 0E F3 03 30 F0 FF 4A ......`.A...0..J
400000000009BCB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000009BCC0 09 70 04 1C 00 21 00 00 00 02 00 E0 07 48 01 84 .p...!.......H..
400000000009BCD0 11 00 38 54 90 11 00 00 00 02 00 00 18 EB F7 58 ..8T...........X
400000000009BCE0 08 08 00 78 00 21 00 00 00 02 00 00 08 50 01 84 ...x.!.......P..
400000000009BCF0 03 10 02 00 00 21 F0 03 80 00 42 20 C8 E8 33 9F .....!....B ..3.
400000000009BD00 11 08 02 82 18 10 00 00 00 02 00 00 48 CE FE 58 ............H..X
400000000009BD10 08 08 00 78 00 21 00 00 00 02 00 00 05 40 00 84 ...x.!.......@..
400000000009BD20 19 F8 01 10 00 21 00 00 00 02 00 00 A8 F9 F7 58 .....!.........X
400000000009BD30 11 08 00 78 00 21 F0 1B 20 00 42 00 98 CF 04 50 ...x.!.. .B....P
400000000009BD40 08 78 00 56 10 10 10 00 F0 00 42 20 05 40 00 84 .x.V......B .@..
400000000009BD50 0B 80 00 56 50 10 00 00 00 02 00 C0 01 78 58 00 ...VP........xX.
400000000009BD60 0B 70 80 1C 00 20 E0 00 38 00 20 00 00 00 04 00 .p... ..8. .....
400000000009BD70 08 00 00 00 01 00 00 70 20 00 23 C0 01 80 58 00 .......p .#...X.
400000000009BD80 09 80 94 15 40 01 00 00 00 02 00 00 00 00 04 00 ....@...........
400000000009BD90 01 70 80 1C 00 20 00 00 00 02 00 00 00 00 04 00 .p... ..........
400000000009BDA0 0B 78 00 1C 00 10 00 00 00 02 00 E0 01 78 50 00 .x...........xP.
400000000009BDB0 02 38 84 1E 86 39 00 00 00 02 80 C3 11 70 00 84 .8...9.......p..
400000000009BDC0 E9 60 05 10 00 E1 F1 13 20 00 C2 03 08 40 01 84 .`...... ....@..
400000000009BDD0 E9 70 00 1C 00 90 F1 0B 20 00 42 03 08 40 01 84 .p...... .B..@..
400000000009BDE0 F1 00 38 58 80 11 00 00 00 02 00 00 A8 F3 F7 58 ..8X...........X
400000000009BDF0 11 08 00 78 00 21 F0 03 A0 00 42 00 F8 E9 F7 58 ...x.!....B....X
400000000009BE00 03 70 00 54 10 10 10 00 F0 00 42 E0 01 70 58 00 .p.T......B..pX.
400000000009BE10 0B 78 80 1E 00 20 80 02 3C 00 20 00 00 00 04 00 .x... ..<. .....
400000000009BE20 10 00 00 00 01 00 80 02 A0 28 00 00 F0 EE FF 48 .........(.....H
400000000009BE30 0B 60 05 52 00 21 E0 00 B0 00 20 00 00 00 04 00 .`.R.!.... .....
400000000009BE40 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
400000000009BE50 11 00 00 00 01 00 70 00 38 0C 73 03 70 00 00 42 ......p.8.s.p..B
400000000009BE60 11 00 00 00 01 00 70 00 C0 0C 73 03 60 00 00 42 ......p...s.`..B
400000000009BE70 09 00 00 00 01 00 60 68 A1 0E 73 00 00 00 04 00 ......`h..s.....
400000000009BE80 11 00 00 00 01 00 60 F8 A1 8E 73 03 60 13 00 42 ......`...s.`..B
400000000009BE90 11 00 00 00 01 00 70 18 A1 0C F3 03 50 13 00 43 ......p.....P..C
400000000009BEA0 11 00 00 00 01 00 60 00 A0 0E F3 03 20 0D 00 43 ......`..... ..C
400000000009BEB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000009BEC0 09 00 00 00 01 00 A0 02 A4 00 20 00 00 00 04 00 .......... .....
400000000009BED0 10 00 00 00 01 00 A0 02 A8 28 00 00 40 EF FF 48 .........(..@..H
400000000009BEE0 11 60 05 52 00 21 00 00 00 02 00 00 E8 04 F8 58 .`.R.!.........X
400000000009BEF0 08 00 00 00 01 00 E0 00 B0 00 20 20 00 E0 01 84 ..........  ....
400000000009BF00 0B 80 00 10 18 10 00 00 00 02 00 C0 01 70 50 00 .............pP.
400000000009BF10 03 00 00 00 01 00 F0 00 38 20 00 00 F2 80 40 80 ........8 ....@.
400000000009BF20 09 00 00 00 01 00 00 01 40 10 20 00 00 00 04 00 ........@. .....
400000000009BF30 11 00 00 00 01 00 70 A0 40 0C 28 03 C0 10 00 42 ......p.@.(....B
400000000009BF40 11 78 40 1F 3F 23 60 F8 3A 0E 73 03 A0 00 00 43 .x@.?#`.:.s....C
400000000009BF50 01 00 00 00 01 00 F0 00 3C 20 00 00 00 00 04 00 ........< ......
400000000009BF60 10 00 00 00 01 00 70 48 3C 0C 6B 03 80 00 00 42 ......pH<.k....B
400000000009BF70 0B 78 E0 02 32 24 00 00 00 02 00 00 00 00 04 00 .x..2$..........
400000000009BF80 09 00 00 00 01 00 F0 00 3C 20 20 00 00 00 04 00 ........<  .....
400000000009BF90 11 00 00 00 01 00 70 00 3C 0C 73 03 30 00 00 42 ......p.<.s.0..B
400000000009BFA0 09 00 00 00 01 00 60 18 39 0E 73 00 00 00 04 00 ......`.9.s.....
400000000009BFB0 11 00 00 00 01 00 60 F8 39 8E 73 03 40 10 00 42 ......`.9.s.@..B
400000000009BFC0 11 30 00 1D 87 39 00 00 00 02 00 03 20 00 00 43 .0...9...... ..C
400000000009BFD0 11 00 00 00 01 00 60 50 39 0E F3 03 70 EE FF 4A ......`P9...p..J
400000000009BFE0 0B 78 08 52 00 21 F0 00 3C 00 20 00 00 00 04 00 .x.R.!..<. .....
400000000009BFF0 01 00 00 00 01 00 F0 00 3C 28 00 00 00 00 04 00 ........<(......
400000000009C000 10 00 00 00 01 00 70 00 3C 0C 73 03 C0 1C 00 42 ......p.<.s....B
400000000009C010 0B 78 E0 02 32 24 00 00 00 02 00 00 00 00 04 00 .x..2$..........
400000000009C020 09 00 00 00 01 00 F0 00 3C 20 20 00 00 00 04 00 ........<  .....
400000000009C030 11 00 00 00 01 00 70 00 3C 0C 73 03 30 00 00 42 ......p.<.s.0..B
400000000009C040 09 00 00 00 01 00 60 18 39 0E 73 00 00 00 04 00 ......`.9.s.....
400000000009C050 11 00 00 00 01 00 60 F8 39 8E 73 03 00 08 00 42 ......`.9.s....B
400000000009C060 11 30 00 1D 87 39 D0 0A 00 00 48 03 F0 07 00 43 .0...9....H....C
400000000009C070 0B 30 A8 1C 87 B9 E1 08 00 00 48 00 00 00 04 00 .0........H.....
400000000009C080 09 00 00 00 01 C0 E1 00 00 00 42 00 00 00 04 00 ..........B.....
400000000009C090 10 00 00 00 01 00 F0 02 38 00 42 00 40 EE FF 48 ........8.B.@..H
400000000009C0A0 03 00 00 00 01 00 F0 00 3C 2C 00 E0 01 7A 00 80 ........<,...z..
400000000009C0B0 0B 78 00 1E 00 10 00 00 00 02 00 E0 01 78 50 00 .x...........xP.
400000000009C0C0 10 00 00 00 01 00 60 08 3D 0E F3 03 30 EC FF 4A ......`.=...0..J
400000000009C0D0 0B 78 E0 02 32 24 00 00 00 02 00 00 00 00 04 00 .x..2$..........
400000000009C0E0 0B 78 00 1E 10 10 60 00 3C 0E 73 E0 01 70 58 00 .x....`.<.s..pX.
400000000009C0F0 0B 78 80 1E 00 20 80 02 3C 00 20 00 00 00 04 00 .x... ..<. .....
400000000009C100 11 00 00 00 01 00 80 02 A0 28 80 03 30 00 00 42 .........(..0..B
400000000009C110 09 00 00 00 01 00 60 18 A1 0E 73 00 00 00 04 00 ......`...s.....
400000000009C120 11 00 00 00 01 00 60 F8 A1 8E 73 03 A0 FB FF 4A ......`...s....J
400000000009C130 11 30 00 51 87 39 00 00 00 02 00 03 90 FB FF 4B .0.Q.9.........K
400000000009C140 11 38 A8 50 86 39 00 00 00 02 80 03 80 FB FF 4B .8.P.9.........K
400000000009C150 10 00 38 56 90 11 60 00 A0 0E 73 03 00 F8 FF 4A ..8V..`...s....J
400000000009C160 11 00 00 00 01 00 00 00 00 02 00 00 C0 EB FF 48 ...............H
400000000009C170 08 00 00 00 01 00 60 00 B4 0E 73 E0 05 00 00 84 ......`...s.....
400000000009C180 16 00 00 00 00 C8 01 30 FF FF 25 00 50 ED FF 48 .......0..%.P..H
400000000009C190 11 F8 01 58 00 21 00 00 00 02 00 00 38 3B 02 50 ...X.!......8;.P
400000000009C1A0 10 08 00 78 00 21 70 00 20 0C 73 03 F0 ED FF 4A ...x.!p. .s....J
400000000009C1B0 11 F8 01 58 00 21 00 00 00 02 00 00 98 34 FA 58 ...X.!.......4.X
400000000009C1C0 10 08 00 78 00 21 70 00 20 0C 73 03 D0 ED FF 4B ...x.!p. .s....K
400000000009C1D0 09 00 00 00 01 00 C0 02 00 00 42 40 05 00 00 84 ..........B@....
400000000009C1E0 08 70 50 03 46 24 F0 08 00 00 48 00 00 00 04 00 .pP.F$....H.....
400000000009C1F0 09 00 92 FA CC 27 10 2C 00 00 48 E0 07 00 00 84 .....'.,..H.....
400000000009C200 09 00 00 00 01 00 00 04 00 31 20 00 00 00 04 00 .........1 .....
400000000009C210 11 00 3C 1C 90 11 00 00 00 02 00 00 58 E9 F7 58 ..<.........X..X
400000000009C220 09 38 00 40 06 39 10 00 F0 00 42 E0 07 40 00 84 .8.@.9....B..@..
400000000009C230 EB 00 F2 FB CB A7 01 04 80 00 42 00 00 00 04 00 ..........B.....
400000000009C240 F1 00 02 80 18 10 00 00 00 02 00 00 08 4B FD 58 .............K.X
400000000009C250 08 30 00 54 07 39 00 00 00 02 00 20 00 E0 01 84 .0.T.9..... ....
400000000009C260 19 F8 01 54 00 21 00 00 00 02 00 03 30 00 00 43 ...T.!......0..C
400000000009C270 11 00 00 00 01 00 00 00 00 02 00 00 78 E5 F7 58 ............x..X
400000000009C280 08 08 00 78 00 21 00 00 00 02 00 00 00 00 04 00 ...x.!..........
400000000009C290 11 30 00 58 07 39 F0 03 B0 00 42 03 30 00 00 43 .0.X.9....B.0..C
400000000009C2A0 11 00 00 00 01 00 00 00 00 02 00 00 48 E5 F7 58 ............H..X
400000000009C2B0 08 08 00 78 00 21 00 00 00 02 00 00 00 00 04 00 ...x.!..........
400000000009C2C0 11 F8 01 52 00 21 00 00 00 02 00 00 28 E5 F7 58 ...R.!......(..X
400000000009C2D0 0B 08 00 78 00 21 80 22 05 2C 49 00 00 00 04 00 ...x.!.".,I.....
400000000009C2E0 10 00 00 00 01 00 00 00 00 02 00 00 A0 F5 FF 48 ...............H
400000000009C2F0 11 F8 01 58 00 21 00 00 00 02 00 00 18 31 FA 58 ...X.!.......1.X
400000000009C300 11 38 00 10 86 39 10 00 F0 00 42 03 90 EC FF 4B .8...9....B....K
400000000009C310 10 00 00 00 01 00 70 00 BC 0C 73 03 80 EC FF 4A ......p...s....J
400000000009C320 10 00 00 00 01 00 00 00 00 02 00 00 70 FE FF 48 ............p..H
400000000009C330 0B 60 05 52 00 21 E0 00 B0 00 20 00 00 00 04 00 .`.R.!.... .....
400000000009C340 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
400000000009C350 10 00 00 00 01 00 70 00 38 0C 73 03 A0 EB FF 4A ......p.8.s....J
400000000009C360 09 00 00 00 01 00 E0 18 88 58 40 00 00 00 04 00 .........X@.....
400000000009C370 11 00 00 00 01 00 60 00 38 0E 73 03 30 00 00 42 ......`.8.s.0..B
400000000009C380 03 30 00 4A 07 39 00 00 00 02 80 C3 11 00 00 90 .0.J.9..........
400000000009C390 E8 00 38 4A 90 11 00 00 00 02 00 00 00 00 04 00 ..8J............
400000000009C3A0 0B 30 00 48 07 F9 E1 08 00 00 48 00 00 00 04 00 .0.H......H.....
400000000009C3B0 F0 00 38 48 90 11 00 00 00 02 00 00 40 EB FF 48 ..8H........@..H
400000000009C3C0 11 00 00 00 01 00 00 00 00 02 00 00 88 48 FF 58 .............H.X
400000000009C3D0 09 70 00 54 00 10 10 00 F0 00 42 00 05 40 00 84 .p.T......B..@..
400000000009C3E0 03 00 00 00 01 00 E0 00 38 28 00 C0 00 70 1C E6 ........8(...p..
400000000009C3F0 11 00 00 00 01 C0 91 0A A4 00 42 00 60 E0 FF 48 ..........B.`..H
400000000009C400 09 70 F8 1D 3F 23 00 00 00 02 00 80 15 48 01 84 .p..?#.......H..
400000000009C410 09 00 00 00 01 00 A0 02 38 00 20 00 00 00 04 00 ........8. .....
400000000009C420 03 00 00 00 01 00 A0 02 A8 28 00 E0 00 54 19 E6 .........(...T..
400000000009C430 10 00 00 00 01 00 70 50 A9 8C 73 03 80 00 00 42 ......pP..s....B
400000000009C440 11 00 00 00 01 00 00 00 00 02 00 00 88 FF F7 58 ...............X
400000000009C450 08 00 00 00 01 00 E0 00 B0 00 20 20 00 E0 01 84 ..........  ....
400000000009C460 0B 78 00 10 18 10 00 00 00 02 00 C0 01 70 50 00 .x...........pP.
400000000009C470 03 00 00 00 01 00 00 01 38 20 00 E0 01 79 40 80 ........8 ...y@.
400000000009C480 09 00 00 00 01 00 F0 00 3C 10 20 00 00 00 04 00 ........<. .....
400000000009C490 11 00 00 00 01 00 70 A0 3C 0C 28 03 70 0B 00 43 ......p.<.(.p..C
400000000009C4A0 11 00 00 00 01 00 70 F8 3A 0C F3 03 60 0B 00 43 ......p.:...`..C
400000000009C4B0 10 00 00 00 01 00 60 E8 AA 0E F3 03 A0 EA FF 4A ......`........J
400000000009C4C0 11 F8 01 58 00 21 00 00 00 02 00 00 08 38 02 50 ...X.!.......8.P
400000000009C4D0 10 08 00 78 00 21 60 00 20 0E 73 03 80 EA FF 4A ...x.!`. .s....J
400000000009C4E0 11 F8 01 58 00 21 70 C3 31 00 42 00 E8 F1 F7 58 ...X.!p.1.B....X
400000000009C4F0 11 08 00 78 00 21 F0 0B 20 00 42 00 D8 C7 04 50 ...x.!.. .B....P
400000000009C500 08 08 00 78 00 21 00 00 00 02 00 E0 07 40 00 84 ...x.!.......@..
400000000009C510 19 00 02 58 00 21 00 00 00 02 00 00 78 EC F7 58 ...X.!......x..X
400000000009C520 08 08 00 78 00 21 A0 02 20 00 42 E0 07 40 00 84 ...x.!.. .B..@..
400000000009C530 19 00 02 6E 00 21 10 04 00 00 42 00 18 49 02 50 ...n.!....B..I.P
400000000009C540 08 30 00 10 07 39 00 00 00 02 00 20 00 E0 01 84 .0...9..... ....
400000000009C550 19 F8 01 10 00 21 00 00 00 02 00 03 30 00 00 43 .....!......0..C
400000000009C560 11 00 00 00 01 00 00 00 00 02 00 00 88 E2 F7 58 ...............X
400000000009C570 08 08 00 78 00 21 00 00 00 02 00 00 00 00 04 00 ...x.!..........
400000000009C580 09 70 00 6E 18 10 00 00 00 02 00 E0 07 50 01 84 .p.n.........P..
400000000009C590 09 78 00 1C 00 10 00 00 00 02 00 C0 11 70 00 84 .x...........p..
400000000009C5A0 03 00 00 00 01 00 F0 00 3C 28 00 E0 A0 7A 18 E6 ........<(...z..
400000000009C5B0 11 38 00 1F C6 39 00 00 00 02 00 03 30 00 00 43 .8...9......0..C
400000000009C5C0 0B 70 00 1C 00 10 00 00 00 02 00 C0 01 70 50 00 .p...........pP.
400000000009C5D0 10 00 00 00 01 00 70 E8 3A 0C F3 03 A0 43 00 43 ......p.:....C.C
400000000009C5E0 11 00 00 00 01 00 00 00 00 02 00 00 08 E2 F7 58 ...............X
400000000009C5F0 03 70 00 58 00 10 10 00 F0 00 42 C0 01 75 FC 8C .p.X......B..u..
400000000009C600 01 00 00 00 01 00 E0 00 38 20 00 00 00 00 04 00 ........8 ......
400000000009C610 10 00 00 00 01 00 70 48 38 0C EB 03 70 E9 FF 4A ......pH8...p..J
400000000009C620 10 00 00 00 01 00 00 00 00 02 00 00 D0 FC FF 48 ...............H
400000000009C630 09 00 00 00 01 00 B0 0A 20 00 42 00 00 00 04 00 ........ .B.....
400000000009C640 11 F8 01 56 00 21 00 00 00 02 00 00 88 F0 F7 58 ...V.!.........X
400000000009C650 11 08 00 78 00 21 F0 0B 20 00 42 00 78 C6 04 50 ...x.!.. .B.x..P
400000000009C660 08 08 00 78 00 21 00 00 00 02 00 E0 07 40 00 84 ...x.!.......@..
400000000009C670 19 00 02 56 00 21 00 00 00 02 00 00 18 EB F7 58 ...V.!.........X
400000000009C680 08 08 00 78 00 21 00 00 00 02 00 A0 05 40 00 84 ...x.!.......@..
400000000009C690 19 F8 01 10 00 21 00 00 00 02 00 00 38 F0 F7 58 .....!......8..X
400000000009C6A0 02 40 FC 11 3F 23 10 00 F0 00 42 C0 01 40 58 00 .@..?#....B..@X.
400000000009C6B0 0B 00 20 50 90 11 E0 68 39 00 40 00 00 00 04 00 .. P...h9.@.....
400000000009C6C0 0B 78 00 1C 00 10 00 00 00 02 00 E0 01 78 50 00 .x...........xP.
400000000009C6D0 10 00 00 00 01 00 60 48 3D 0E 73 03 70 02 00 43 ......`H=.s.p..C
400000000009C6E0 11 00 00 00 01 00 F0 03 B4 00 42 00 08 E1 F7 58 ..........B....X
400000000009C6F0 08 08 00 78 00 21 00 00 00 02 00 00 00 00 04 00 ...x.!..........
400000000009C700 10 00 00 00 01 00 60 00 9C 0E 28 03 40 DF FF 4A ......`...(.@..J
400000000009C710 10 00 00 00 01 00 00 00 00 02 00 00 80 F2 FF 48 ...............H
400000000009C720 11 00 00 00 01 00 00 00 00 02 00 00 A8 26 FF 58 .............&.X
400000000009C730 10 08 00 78 00 21 80 02 20 00 42 00 40 F4 FF 48 ...x.!.. .B.@..H
400000000009C740 08 F8 01 52 00 21 00 04 88 00 42 00 00 00 04 00 ...R.!....B.....
400000000009C750 19 08 02 4A 00 21 20 04 90 00 42 00 78 8D FE 58 ...J.! ...B.x..X
400000000009C760 10 00 00 00 01 00 10 00 F0 00 42 00 70 EA FF 48 ..........B.p..H
400000000009C770 08 F8 01 58 00 21 00 00 00 02 00 60 05 00 00 84 ...X.!.....`....
400000000009C780 19 40 01 00 00 21 00 00 00 02 00 00 48 F4 FA 58 .@...!......H..X
400000000009C790 09 70 00 54 00 10 00 00 00 02 00 20 00 E0 01 84 .p.T....... ....
400000000009C7A0 10 00 00 00 01 00 E0 00 38 28 00 00 90 E0 FF 48 ........8(.....H
400000000009C7B0 11 F8 01 58 00 21 00 00 00 02 00 00 58 2C FA 58 ...X.!......X,.X
400000000009C7C0 08 00 00 00 01 00 70 00 20 0C 73 20 00 E0 01 84 ......p. .s ....
400000000009C7D0 19 00 00 00 01 00 00 00 00 02 80 03 D0 E8 FF 4A ...............J
400000000009C7E0 C8 00 06 00 00 24 00 00 00 02 00 00 00 00 04 00 .....$..........
400000000009C7F0 08 08 02 44 00 21 20 04 00 00 42 00 00 00 04 00 ...D.! ...B.....
400000000009C800 19 18 02 00 00 21 F0 03 B0 00 42 00 48 A9 00 50 .....!....B.H..P
400000000009C810 08 08 00 78 00 21 00 00 00 02 00 40 05 40 00 84 ...x.!.....@.@..
400000000009C820 19 F8 01 58 00 21 00 00 00 02 00 00 C8 DF F7 58 ...X.!.........X
400000000009C830 10 00 00 00 01 00 10 00 F0 00 42 00 20 E9 FF 48 ..........B. ..H
400000000009C840 10 00 00 00 01 00 00 03 00 00 42 00 E0 E9 FF 48 ..........B....H
400000000009C850 10 68 05 00 00 24 F0 0A 00 00 48 00 80 E6 FF 48 .h...$....H....H
400000000009C860 09 F8 B1 19 00 21 00 00 00 02 00 E0 41 02 00 90 .....!......A...
400000000009C870 09 00 3C 7E 80 11 00 00 00 02 00 E0 D1 66 00 84 ..<~.........f..
400000000009C880 09 00 38 1E 80 11 E0 70 33 00 42 E0 11 00 00 90 ..8....p3.B.....
400000000009C890 09 00 00 1C 80 11 00 00 00 02 00 C0 41 0D 18 91 ............A...
400000000009C8A0 02 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000009C8B0 19 00 3C 1C 90 11 00 00 00 02 00 00 D8 52 FD 58 ..<..........R.X
400000000009C8C0 09 08 00 78 00 21 00 00 00 02 00 00 00 00 04 00 ...x.!..........
400000000009C8D0 0B 70 C0 03 32 24 00 00 00 02 00 00 00 00 04 00 .p..2$..........
400000000009C8E0 09 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
400000000009C8F0 10 00 00 00 01 00 70 00 38 0C 73 03 70 EF FF 4B ......p.8.s.p..K
