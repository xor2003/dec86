;;; Segment .text (400000000001C480)

;; fn400000000001C480: 400000000001C480
;;   Called from:
;;     40000000000366CC (in fn4000000000030880)
;;     400000000003678C (in fn4000000000030880)
fn400000000001C480 proc
	{ addl	r14,6456,r1; nop.m	0x0; mov	r2,LC; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000001C600 }

l400000000001C4B0:
	{ nop.m	0x0; addl	r14,6044,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r14]; adds	r14,0x0,r0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,0x29,r15; (p06) br.cond.dptk.few	400000000001C600 }

l400000000001C4E0:
	{ nop.m	0x0; addl	r15,6724,r1; addl	r18,6788,r1 }
	{ nop.m	0x0; movl	r20,0x803FFFFF80000000; }
	{ nop.m	0x0; ld4	r16,[r15]; addl	r15,6720,r1 }
	{ ld8	r19,[r18]; ld4	r15,[r15]; sxt4	r18,r16; }
	{ sub	r17,r15,r16; add	r18,r19,r18; nop.i	0x0 }
	{ cmp4.lt	p06,p07,r15,r16; cmp4.eq	p08,p09,r20,r15; (p06) br.cond.spnt.few	400000000001C560; }

l400000000001C540:
	{ nop.m	0x0; addp4	r17,r17,r0; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r17; (p09) br.cond.sptk.few	400000000001C570; }

l400000000001C560:
	{ nop.m	0x0; mov.i	LC,0x0; nop.i	0x0; }

l400000000001C570:
	{ add	r15,r18,r14; add	r17,r16,r14; br.cloop.sptk.few	400000000001C5C0; }

l400000000001C580:
	{ nop.m	0x0; sxt4	r17,r17; add	r19,r19,r17; }
	{ ld1	r14,[r19]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2D,r14; (p07) br.cond.dptk.few	400000000001C600 }

l400000000001C5B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000001C780 }

l400000000001C5C0:
	{ ld1	r15,[r15]; nop.m	0x0; adds	r14,0x1,r14; }
	{ nop.m	0x0; sxt1	r15,r15; cmp4.eq	p06,p07,0x20,r15; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x9,r15; (p06) br.cond.dptk.few	400000000001C570 }

l400000000001C5F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000001C580 }

l400000000001C600:
	{ addl	r14,6740,r1; nop.m	0x0; addl	r15,260,r0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r15,r14; (p06) br.cond.dptk.few	400000000001C6E0 }

l400000000001C630:
	{ nop.m	0x0; addl	r15,259,r0; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r14,r15; (p06) br.cond.dptk.few	400000000001C770; }

l400000000001C650:
	{ cmp4.eq	p06,p07,0x26,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000001C770; }

l400000000001C660:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x26,r14; (p06) br.cond.dptk.few	400000000001C6A0; }

l400000000001C670:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000001C770; }

l400000000001C680:
	{ nop.m	0x0; cmp4.eq	p06,p07,0xA,r14; (p07) br.cond.dptk.few	400000000001C780 }

l400000000001C690:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000001C770; }

l400000000001C6A0:
	{ cmp4.eq	p06,p07,0x3B,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000001C770; }

l400000000001C6B0:
	{ cmp4.eq	p06,p07,0x7B,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000001C770; }

l400000000001C6C0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x28,r14; (p07) br.cond.dptk.few	400000000001C780 }

l400000000001C6D0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000001C770 }

l400000000001C6E0:
	{ nop.m	0x0; addl	r15,280,r0; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r15,r14; (p06) br.cond.dptk.few	400000000001C750 }

l400000000001C700:
	{ nop.m	0x0; addl	r15,277,r0; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r14,r15; (p06) br.cond.dptk.few	400000000001C770 }

l400000000001C720:
	{ nop.m	0x0; addl	r15,269,r0; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,r15,r14; (p07) br.cond.dptk.few	400000000001C780 }

l400000000001C740:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000001C770 }

l400000000001C750:
	{ nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFEE0,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x1,r14; (p06) br.cond.dptk.few	400000000001C780 }

l400000000001C770:
	{ nop.m	0x0; addl	r8,1,r0; br.cond.sptk.few	400000000001C790; }

l400000000001C780:
	{ adds	r8,0x0,r0; nop.m	0x0; nop.i	0x0 }

l400000000001C790:
	{ nop.m	0x0; mov.i	LC,r2; br.ret	b0; }

;; fn400000000001C7A0: 400000000001C7A0
;;   Called from:
;;     4000000000075C5C (in fn4000000000074880)
;;     4000000000075E7C (in fn4000000000074880)
fn400000000001C7A0 proc
	{ cmp4.eq	p06,p07,0x2F,r32; nop.i	0x0; (p06) br.cond.dpnt.few	400000000001C8A0; }

l400000000001C7B0:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x2F,r32; (p06) br.cond.dptk.few	400000000001C830; }

l400000000001C7C0:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x26,r32; (p06) br.cond.dptk.few	400000000001C800; }

l400000000001C7D0:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x24,r32; (p06) br.cond.dptk.few	400000000001C8A0; }

l400000000001C7E0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x21,r32; (p07) br.cond.dptk.few	400000000001C8B0 }

l400000000001C7F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000001C8A0 }

l400000000001C800:
	{ nop.m	0x0; adds	r32,0xFFFFFFFFFFFFFFD8,r32; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x5,r32; (p06) br.cond.dptk.few	400000000001C8B0 }

l400000000001C820:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000001C8A0; }

l400000000001C830:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x3F,r32; (p06) br.cond.dptk.few	400000000001C870; }

l400000000001C840:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x3B,r32; (p06) br.cond.dptk.few	400000000001C8A0; }

l400000000001C850:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x3A,r32; (p07) br.cond.dptk.few	400000000001C8B0 }

l400000000001C860:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000001C8A0; }

l400000000001C870:
	{ cmp4.eq	p06,p07,0x7C,r32; nop.i	0x0; (p06) br.cond.dpnt.few	400000000001C8A0; }

l400000000001C880:
	{ cmp4.eq	p06,p07,0x7E,r32; nop.i	0x0; (p06) br.cond.dpnt.few	400000000001C8A0; }

l400000000001C890:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x5E,r32; (p07) br.cond.dptk.few	400000000001C8B0 }

l400000000001C8A0:
	{ nop.m	0x0; addl	r8,1,r0; br.ret	b0; }

l400000000001C8B0:
	{ nop.m	0x0; adds	r8,0x0,r0; br.ret	b0; }

;; fn400000000001C8C0: 400000000001C8C0
;;   Called from:
;;     40000000000B595C (in binary_test)
;;     40000000000B5BCC (in binary_test)
fn400000000001C8C0 proc
	{ alloc	r34,ar.pfs,0x7,0x0,0x4; addl	r37,-9244,r1; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.i	0x0; addl	r38,5,r0 }
	{ adds	r36,0x0,r0; ld8	r37,[r37]; br.call.sptk.many	b0,fn400000000001AB60; }
	{ nop.m	0x0; adds	r1,0x0,r35; adds	r36,0x0,r8 }
	{ nop.m	0x0; adds	r37,0x0,r32; br.call.sptk.many	b0,fn40000000000B5540; }
	{ nop.m	0x0; break.f	0x0; nop.i	0x0; }
	{ nop.m	0x6; nop.i	0x7; nop.i	0x8 }
	{ nop.m	0x6; nop.i	0x7; nop.i	0x8 }

;; main: 400000000001C940
;;   Called from:
;;     400000000001C93C (in fn400000000001C8C0)
main proc
	{ alloc	r49,ar.pfs,0x16,0x0,0x12; adds	r16,0x0,r12; nop.b	0x0 }
	{ adds	r12,0xFFFFFFFFFFFFFEE0,r12; mov	r17,LC; addl	r50,25252,r1; }
	{ adds	r14,0x108,r12; adds	r15,0x100,r12; mov	r48,b0 }
	{ addl	r51,1,r0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r32],r14; st8	[r33],r15; nop.i	0x0; }
	{ st8	[r16],r8,8; st8.spill	[r1],r16; adds	r16,0x110,r12; }
	{ st8	[r34],r16; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BD60; }
	{ adds	r1,0x128,r12; nop.m	0x0; cmp4.eq	p06,p07,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p07) br.cond.dptk.few	400000000001E1D0 }

l400000000001C9D0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,xtrace_init; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,check_dev_tty; }
	{ adds	r1,0x128,r12; ld8	r1,[r1]; nop.i	0x0; }
	{ addl	r35,6492,r1; ld4	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	400000000001CA70; }

l400000000001CA30:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000001CA40:
	{ addl	r50,3,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB20; }
	{ adds	r1,0x128,r12; ld4	r14,[r35]; nop.i	0x0; }
	{ ld8	r1,[r1]; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	400000000001CA40 }

l400000000001CA70:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,set_default_locale; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001ACC0; }
	{ adds	r1,0x128,r12; nop.m	0x0; adds	r38,0x0,r8; }
	{ ld8	r1,[r1]; addl	r14,-22276,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r14]; adds	r14,0x10,r14; }
	{ cmp4.eq	p07,p06,r15,r8; nop.i	0x0; (p07) br.cond.dpnt.few	400000000001CC30; }

l400000000001CAE0:
	{ nop.m	0x0; ld8	r50,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r50; nop.i	0x0; (p06) br.cond.dpnt.few	400000000001CB30; }

l400000000001CB00:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0; }

l400000000001CB30:
	{ addl	r14,-22276,r1; nop.m	0x0; nop.i	0x0; }
	{ adds	r14,0x18,r14; ld8	r50,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r50; nop.i	0x0; (p06) br.cond.dpnt.few	400000000001CB90; }

l400000000001CB60:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0; }

l400000000001CB90:
	{ addl	r14,-22276,r1; nop.m	0x0; nop.i	0x0; }
	{ adds	r14,0x20,r14; ld8	r50,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r50; nop.i	0x0; (p06) br.cond.dpnt.few	400000000001CBF0; }

l400000000001CBC0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0; }

l400000000001CBF0:
	{ addl	r14,-22276,r1; nop.m	0x0; nop.i	0x0; }
	{ adds	r16,0x20,r14; adds	r15,0x18,r14; nop.i	0x0 }
	{ adds	r14,0x10,r14; st8	[r0],r16; nop.i	0x0 }
	{ st8	[r0],r15; st8	[r0],r14; nop.i	0x0 }

l400000000001CC30:
	{ nop.m	0x0; addl	r35,-22276,r1; nop.i	0x0; }
	{ nop.m	0x0; adds	r36,0x0,r35; adds	r37,0x4,r35; }
	{ st4	[r36],r8,8; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B8E0; }
	{ adds	r1,0x128,r12; st4	[r8],r36; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AD80; }
	{ adds	r1,0x128,r12; st4	[r8],r37; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AF60; }
	{ ld4	r14,[r37]; adds	r1,0x128,r12; adds	r16,0xC,r35 }
	{ ld4	r15,[r35]; ld8	r1,[r1]; cmp4.eq	p07,p06,r14,r15 }
	{ st4	[r8],r16; nop.m	0x0; (p07) br.cond.dpnt.few	400000000001E3C0; }

l400000000001CCD0:
	{ (p06) addl	r8,1,r0; addl	r50,332,r1; addl	r14,6544,r1; }

l400000000001CCD6:
	{ Invalid; (p07) nop; break.i	0x80000 }
	{ (p25) fwb; nop; nop }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; (p03) nop; (p16) nop }
	{ chk.a.nc	r0,3FFFFFFFFF01D516; nop; (p48) nop }

l400000000001CD20:
	{ addl	r15,1,r0; nop.m	0x0; addl	r14,6456,r1; }
	{ st4	[r15],r14; nop.m	0x0; nop.i	0x0 }

l400000000001CD40:
	{ addl	r50,21828,r1; nop.m	0x0; addl	r51,1,r0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BD60; }
	{ adds	r1,0x128,r12; nop.m	0x0; cmp4.eq	p06,p07,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dptk.few	400000000001CE00; }

l400000000001CD80:
	{ addl	r14,8932,r1; adds	r15,0x108,r12; adds	r16,0x100,r12 }
	{ adds	r18,0x110,r12; nop.m	0x0; nop.i	0x0; }
	{ ld4	r14,[r14]; st4	[r14],r15; addl	r14,8860,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld8	r14,[r14]; st8	[r14],r16; addl	r14,8852,r1; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ st8	[r14],r18; nop.m	0x0; addl	r14,6548,r1; }
	{ st4	[r0],r14; nop.m	0x0; nop.i	0x0 }

l400000000001CE00:
	{ adds	r14,0xF4,r12; addl	r15,1,r0; adds	r16,0x108,r12; }
	{ nop.m	0x0; st4.rel	[r15],r14; addl	r15,6552,r1 }
	{ ld4	r16,[r16]; st4	[r0],r15; nop.i	0x0 }
	{ ld4.acq	r15,[r14]; cmp4.lt	p07,p06,r16,r15; nop.i	0x0; }
	{ (p07) st4.rel	[r16],r14; addl	r14,-10356,r1; addl	r16,8908,r1; }

l400000000001CE46:
	{ Invalid; (p08) nop; (p32) nop }
	{ break.m	0x4000; nop; (p48) nop }
	{ break.m	0x4000; (p07) nop; nop }
	{ break.m	0x4000; (p08) nop; (p32) nop }
	{ break.m	0x4000; nop; (p48) nop }
	{ break.m	0x4000; (p07) nop; break.i	0x80000 }
	{ mf.a; (p08) nop; nop }
	{ mf.a; (p07) nop; nop }
	{ Invalid; (p07) nop; nop }
	{ break.m	0x4000; (p07) nop; nop }
	{ break.m	0x4000; (p07) nop; nop }
	{ chk.a.nc	r0,3FFFFFFFFF01D6F6; nop; (p32) nop }

l400000000001CF00:
	{ addl	r14,6476,r1; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	400000000001D1B0 }

l400000000001CF20:
	{ addl	r14,6476,r1; addl	r35,1,r0; adds	r50,0x0,r0; }
	{ ld8	r15,[r14]; ld1	r16,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r16,r16; cmp4.eq	p07,p06,0x2D,r16; }
	{ (p07) adds	r15,0x1,r15; (p07) st8	[r15],r14; addl	r14,5708,r1 }

l400000000001CF56:
	{ mf.a; (p07) nop; (p48) nop; }

l400000000001CF5C:
	{ (p38) cmp.eq	p01,p10,r44,r72; zxt4	r55,r0; break.i	0x1000; }
	{ cmp.eq	p00,p10,r1,r0; Invalid; (p48) cmp.lt.unc	p03,p08,r3,r102 }
	{ (p34) cmp.eq	p01,p10,r44,r72; zxt4	r57,r0; break.i	0x1000; }
	{ cmp.eq	p00,p11,r1,r0; Invalid; (p48) cmp.lt.unc	p03,p08,r3,r102 }
	{ (p06) nop; Invalid; cmp.lt	p00,p00,r32,r0; }
	{ (p32) nop; Invalid; cmp.lt	p00,p00,r32,r0; }
	{ (p34) nop; Invalid; cmp.lt	p00,p00,r32,r0; }
	{ (p44) nop; Invalid; cmp.lt	p00,p00,r32,r0; }
	{ (p58) nop; Invalid; cmp.lt	p00,p00,r32,r0; }
	{ Invalid; break.i	0x1000; cmp.lt.unc	p00,p08,r3,r100; }
	{ Invalid; break.i	0x1000; cmp.lt.unc	p00,p08,r3,r100; }
	{ (p22) nop; Invalid; cmp.lt	p00,p00,r32,r0; }
	{ (p36) nop; Invalid; cmp.lt	p00,p00,r32,r0; }
	{ Invalid; break.i	0x1000; cmp.lt.unc	p00,p08,r3,r100; }
	{ (p56) nop; Invalid; cmp.lt	p00,p00,r32,r0; }
	{ Invalid; break.i	0x1000; cmp.lt.unc	p00,p08,r3,r100; }
	{ (p12) nop; break.i	0x1000; break.i	0x1000; }
	{ Invalid; Invalid; break.i	0x1000 }
	{ (p08) nop; nop; epc }
	{ nop; cmp.lt	p32,p08,r0,r6; (p01) cmp.eq	p46,p18,r32,r14 }
	{ (p54) nop; cmp.eq	p00,p00,r32,r0; Invalid; }
	{ nop; Invalid; cmp.lt	p00,p00,r32,r0 }
	{ Invalid; dep	r0,r32,r0,63,1; (p06) cmp.lt.unc	p00,p08,r3,r6; }
	{ Invalid; Invalid; break.i	0x1000; }
	{ (p01) nop; nop; rfi }
	{ cmp.lt	p00,p11,r1,r0; zxt4	r63,r13; break.i	0x1000 }
	{ cmpxchg4.acq	r0,[r0],r1; Invalid; break.i	0x1000 }
	{ (p56) nop; nop; zxt1	r10,r64 }
	{ nop; Invalid; break.i	0x1000 }
	{ (p53) nop; nop; zxt1	r10,r64 }
	{ nop; Invalid; break.i	0x1000 }
	{ (p10) nop; invala; nop }
	{ nop; br.cond.sptk.few	400000000022015C; Invalid }
	{ (p12) nop; break.i	0x1000; break.i	0x1000; }
	{ nop; Invalid; break.i	0x1000 }
	{ (p31) nop; invala; cmp.eq	p00,p00,r32,r0 }
	{ nop; Invalid; mov	pr,r32,0x0 }
	{ (p01) nop; (p02) cmp.lt	p00,p16,r67,r64; Invalid }

l400000000001D1B0:
	{ adds	r16,0x100,r12; addl	r14,8924,r1; adds	r15,0x110,r12; }
	{ ld8	r16,[r16]; nop.m	0x0; nop.i	0x0; }
	{ ld8	r15,[r15]; ld8.a	r35,[r16]; nop.i	0x0 }
	{ st8	[r15],r14; nop.i	0x0; cmp.eq	p06,p07,0x0,r35 }
	{ chk.a.clr	r35,4000000000021090; nop.m	0x0; nop.b	0x0 }

l400000000001D1F6:
	{ break.m	0x4000; nop; (p32) nop }

l400000000001D200:
	{ adds	r50,0x0,r35; (p06) br.cond.dpnt.few	400000000001E830; nop.b	0x0; }

l400000000001D20C:
	{ Invalid; break.i	0x1000; break.i	0x1000 }
	{ (p31) nop; cmp.eq	p10,p16,r67,r64; (p01) rfi }
	{ nop; cmp.lt	p32,p08,r0,r6; zxt4	r51,r12 }
	{ Invalid; cmp.eq.unc	p02,p08,r3,r102; Invalid }
	{ nop.m	0x80; cmp.eq	p00,p00,r32,r0; (p01) break.i	0x141E0 }
	{ cmp.eq	p00,p17,r1,r0; czx1.r	r107,r97; mov	pr,r32,0x0 }
	{ (p25) cmp.lt	p02,p11,r64,r33; (p01) cmp.lt	p51,p18,r64,r12; Invalid }

l400000000001D270:
	{ addl	r14,6476,r1; ld8	r14,[r14]; nop.i	0x0; }
	{ ld1	r15,[r14]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x73,r15; (p06) br.cond.dpnt.few	400000000001E4F0; }

l400000000001D2A0:
	{ addl	r14,23444,r1; nop.m	0x0; cmp.eq	p07,p06,0x0,r35; }
	{ nop.m	0x0; nop.m	0x0; (p07) addl	r35,324,r1; }

l400000000001D2C0:
	{ (p07) ld8	r35,[r35]; ld8	r50,[r14]; addl	r14,6476,r1; }

l400000000001D2C6:
	{ (p25) fwb; (p07) nop; break.i	0x80000 }
	{ Invalid; nop; nop }
	{ chk.a.nc	r0,3FFFFFFFFF01DAE6; nop; break.i	0x80000 }

l400000000001D2F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0; }

l400000000001D320:
	{ nop.m	0x0; addl	r35,6476,r1; nop.i	0x0; }
	{ ld8	r50,[r35]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x128,r12; nop.m	0x0; adds	r50,0x1,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ nop.m	0x0; adds	r1,0x128,r12; adds	r50,0x0,r8 }
	{ nop.m	0x0; ld8	r51,[r35]; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x128,r12; ld8	r14,[r35]; nop.i	0x0; }
	{ ld8	r1,[r1]; cmp.eq	p06,p07,0x0,r14; addl	r15,23444,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st8	[r8],r15; nop.i	0x0; (p06) br.cond.dpnt.few	400000000001D430; }

l400000000001D3D0:
	{ ld1	r15,[r14]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	400000000001D430; }

l400000000001D3F0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r15; (p06) br.cond.dptk.few	400000000001D450 }

l400000000001D400:
	{ adds	r14,0x1,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dpnt.few	400000000001D450 }

l400000000001D430:
	{ addl	r15,324,r1; addl	r14,6476,r1; nop.i	0x0 }
	{ ld8	r15,[r15]; st8	[r15],r14; nop.i	0x0 }

l400000000001D450:
	{ adds	r50,0x0,r0; adds	r41,0x0,r0; br.call.sptk.many	b0,fn400000000001A9C0; }
	{ adds	r1,0x128,r12; nop.m	0x0; adds	r14,0xF4,r12 }
	{ adds	r18,0x108,r12; nop.m	0x0; adds	r15,0x100,r12; }
	{ ld8	r1,[r1]; ld4.acq	r40,[r14]; nop.i	0x0; }
	{ addl	r14,8892,r1; ld4	r18,[r18]; addl	r44,148,r1; }
	{ nop.m	0x0; nop.m	0x0; cmp4.eq	p07,p06,r18,r40; }
	{ st8	[r8],r14; sxt4	r14,r40; (p07) br.cond.dpnt.few	400000000001D5E0; }

l400000000001D4C0:
	{ ld8	r15,[r15]; shladd	r14,r14,0x3,r15; nop.i	0x0; }
	{ nop.m	0x0; ld8	r50,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r50; nop.i	0x0; (p06) br.cond.dpnt.few	400000000001D5E0; }

l400000000001D4F0:
	{ ld1	r14,[r50]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x2D,r14; addl	r14,5628,r1; (p07) br.cond.dpnt.few	400000000001D5E0; }

l400000000001D510:
	{ nop.m	0x0; ld8	r43,[r14]; adds	r14,0x1,r50 }
	{ ld8	r44,[r44]; ld1	r38,[r14]; adds	r45,0xFFFFFFFFFFFFFFE0,r43 }
	{ adds	r46,0xFFFFFFFFFFFFFFE8,r43; nop.m	0x0; sxt1	r38,r38; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r38; (p07) br.cond.dpnt.few	400000000001E370; }

l400000000001D550:
	{ (p06) adds	r42,0x0,r41; nop.m	0x0; nop.i	0x0; }

l400000000001D556:
	{ break.m	0x4000; nop; break.i	0x80000 }

l400000000001D560:
	{ nop.m	0x0; adds	r36,0x0,r43; adds	r37,0x0,r41 }

l400000000001D562:
	{ Invalid; (p48) chk.s.i	r64,3FFFFFFFFF425602; Invalid }
	{ srlz.d; nop; Invalid }

l400000000001D580:
	{ ld1	r14,[r35]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r38; (p07) br.cond.dpnt.few	400000000001E1E0 }

l400000000001D5A0:
	{ adds	r36,0x20,r36; adds	r37,0x1,r37; adds	r14,0xFFFFFFFFFFFFFFE0,r36; }
	{ nop.m	0x0; ld8	r35,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	400000000001D580; }

l400000000001D5D0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r42; (p06) br.cond.spnt.few	40000000000209F0 }

l400000000001D5E0:
	{ addl	r15,6568,r1; nop.m	0x0; adds	r14,0xF4,r12; }
	{ ld4	r15,[r15]; st4.rel	[r40],r14; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r15; addl	r15,6572,r1; (p07) br.cond.dpnt.few	400000000001E890; }

l400000000001D610:
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p07) br.cond.dptk.few	400000000001E4C0 }

l400000000001D630:
	{ ld4.acq	r35,[r14]; addl	r14,6476,r1; adds	r18,0x108,r12 }
	{ addl	r47,8868,r1; addl	r46,8916,r1; addl	r44,8900,r1; }
	{ ld8	r15,[r14]; addl	r14,9036,r1; addl	r39,1,r0 }
	{ addl	r45,6564,r1; addl	r42,6612,r1; addl	r41,6608,r1; }
	{ nop.m	0x0; nop.m	0x0; addl	r40,6580,r1 }
	{ nop.m	0x0; ld4	r18,[r18]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,r18,r35; st8	[r15],r14; adds	r15,0x100,r12 }
	{ nop.m	0x0; sxt4	r14,r35; (p06) br.cond.dpnt.few	400000000001D820; }

l400000000001D6B0:
	{ ld8	r15,[r15]; shladd	r14,r14,0x3,r15; nop.i	0x0; }
	{ nop.m	0x0; ld8	r15,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r15; nop.i	0x0; (p06) br.cond.dpnt.few	400000000001D820; }

l400000000001D6E0:
	{ nop.m	0x0; ld1	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x2D,r14; }
	{ cmp4.eq.or.andcm	p07,p06,0x2B,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000001D820; }

l400000000001D710:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000001D740:
	{ adds	r35,0x1,r35; cmp4.eq	p07,p06,0x2D,r14; (p07) br.cond.dpnt.few	400000000001E430; }

l400000000001D750:
	{ cmp4.eq	p07,p06,0x2D,r14; adds	r37,0x0,r14; adds	r36,0x1,r15; }
	{ (p06) addl	r38,1,r0; nop.i	0x0; (p07) adds	r38,0x0,r0 }

l400000000001D766:
	{ chk.a.nc	f0,3FFFFFFFFF01DF66; (p19) mov.sptk	b0,r0,400000000001D866; nop }

l400000000001D770:
	{ ld1	r16,[r36],1; adds	r14,0x108,r12; sxt1	r16,r16; }
	{ adds	r15,0x0,r16; nop.m	0x0; cmp4.eq	p07,p06,0x0,r16 }
	{ adds	r43,0x0,r16; nop.m	0x0; (p06) br.cond.dpnt.few	400000000001E670; }

l400000000001D7A0:
	{ ld4	r14,[r14]; nop.m	0x0; adds	r15,0x100,r12; }
	{ cmp4.eq	p06,p07,r35,r14; sxt4	r14,r35; (p06) br.cond.dpnt.few	400000000001D820; }

l400000000001D7C0:
	{ ld8	r15,[r15]; shladd	r14,r14,0x3,r15; nop.i	0x0; }
	{ nop.m	0x0; ld8	r15,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r15; nop.i	0x0; (p06) br.cond.dpnt.few	400000000001D820; }

l400000000001D7F0:
	{ nop.m	0x0; ld1	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x2D,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x2B,r14; (p06) br.cond.dptk.few	400000000001D740 }

l400000000001D820:
	{ addl	r14,6564,r1; adds	r15,0xF4,r12; addl	r50,396,r1; }
	{ ld4	r14,[r14]; st4.rel	[r35],r15; nop.i	0x0 }
	{ ld8	r50,[r50]; cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; }
	{ (p07) addl	r14,6520,r1; (p07) ld4	r15,[r14]; nop.i	0x0; }

l400000000001D856:
	{ (p07) fwb; cmp4.ltu	p00,p00,0x0,r1; Invalid; }

l400000000001D85C:
	{ cmp4.eq.or.andcm	p00,p43,r1,r0; (p49) mov	pr,r35,0x88FE; (p48) cmp.lt.unc	p03,p08,r3,r100 }

l400000000001D866:
	{ mf.a; (p07) nop; (p32) nop; }

l400000000001D86C:
	{ (p60) cmp.lt	p01,p11,r50,r72; (p01) cmp.eq.unc	p00,p08,r3,r4; czx1.r	r64,r97; }
	{ nop; nop; zxt4	r0,r0 }

l400000000001D88C:
	{ setf.s	f0,r1; zxt1	r0,r64; break.i	0x1000 }

l400000000001D896:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ fwb; nop; (p32) brp.ret.sptk	b5,400000000001D8D6 }
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ (p07) fwb; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFCE11B6; nop; (p32) nop }

l400000000001D8E0:
	{ addl	r14,8900,r1; nop.m	0x0; addl	r15,1,r0; }
	{ nop.m	0x0; st4	[r15],r14; addl	r14,7392,r1 }
	{ addl	r15,1,r0; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; st4	[r15],r14; nop.i	0x0 }

l400000000001D920:
	{ addl	r14,6544,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000001D970 }

l400000000001D940:
	{ addl	r14,7344,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	400000000001F2E0 }

l400000000001D970:
	{ addl	r14,8868,r1; nop.m	0x0; adds	r16,0x100,r12; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; adds	r14,0xF4,r12; (p06) br.cond.dpnt.few	400000000001DA20; }

l400000000001D9A0:
	{ ld4.acq	r15,[r14]; ld8	r16,[r16]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r15,r15; nop.i	0x0; }
	{ shladd	r15,r15,0x3,r16; nop.m	0x0; addl	r16,8908,r1; }
	{ ld8	r15,[r15]; nop.m	0x0; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r15; st8	[r15],r16; nop.i	0x0 }
	{ (p06) ld4.acq	r15,[r14]; nop.m	0x0; (p07) br.cond.dpnt.few	400000000001F370; }

l400000000001D9F6:
	{ chk.a.nc	f0,3FFFFFFFFF01E1F6; nop; add	r0,r0,r32 }

l400000000001DA00:
	{ nop.m	0x0; (p06) adds	r15,0x1,r15; nop.i	0x0; }

l400000000001DA0C:
	{ Invalid; Invalid; break.i	0x1000 }

l400000000001DA16:
	{ break.m	0x4000; nop; (p32) nop }

l400000000001DA20:
	{ addl	r14,9036,r1; nop.m	0x0; nop.i	0x0; }

l400000000001DA22:
	{ (p25) break.m	0x488C0; break.i	0x20; clrrrb }

l400000000001DA26:
	{ break.m	0x4000; nop; nop }

l400000000001DA28:
	{ (p16) break.m	0x0; (p16) break.i	0x11000; (p56) break.i	0x8CC0 }

l400000000001DA2C:
	{ Invalid; Invalid; break.i	0x1000 }

l400000000001DA38:
	{ (p16) nop; (p09) dep	r0,r106,r2,63,5; Invalid }

l400000000001DA3E:
	{ nop; (p08) break.i	0x110210; (p32) break.i	0x101 }

l400000000001DA44:
	{ (p08) cmp.lt	p04,p04,r4,r0; break.i	0x100002; mov	pr,r0,0x20B0 }

l400000000001DA4A:
	{ (p01) sum	0x0; Invalid; (p08) mov	pr,0x1 }

l400000000001DA5A:
	{ sum	0x0; (p36) mov	pr,0x0; nop }
	{ (p01) sum	0x0; mov	pr,0x1; Invalid }
	{ (p27) break.m	0x117400; (p37) break.b	0x4700; (p08) break.b	0x1; }
	{ Invalid; (p38) nop; (p35) mov	pr,0x0 }
	{ Invalid; (p38) nop; (p35) mov	pr,0x0 }
	{ Invalid; (p42) mov	pr,0x0; nop }
	{ Invalid; (p42) mov	pr,0x0; nop; }
	{ (p01) sum	0x0; (p44) nop; (p08) nop; }
	{ (p01) sum	0x0; mov	pr,0x1; Invalid }
	{ (p31) break.m	0x101000; nop; (p08) nop; }
	{ (p01) sum	0x0; mov	pr,0x1; Invalid }
	{ (p27) break.m	0x100C00; (p37) break.b	0x0; break.b	0xD180; }
	{ (p02) loadrs; (p32) mf.a; (p02) break.i	0x9981 }
	{ (p02) sum	0x0; (p36) break.m	0x5A01; Invalid }
	{ (p02) setf.d	f0,r46; (p37) mov	pr,0x0; Invalid }
	{ (p02) sum	0x0; (p04) nop; (p32) mov	pr,0x0 }
	{ nop; (p45) nop; (p08) nop }
	{ (p01) sum	0x0; mov	pr,0x1; Invalid }
	{ (p27) chk.a.nc	r0,3FFFFFFFFF021C7A; nop; (p08) break.b	0x1; }
	{ Invalid; (p38) mov	pr,0x0; nop }
	{ (p01) sum	0x0; Invalid; (p50) mov	pr,0x1 }
	{ (p24) chk.a.nc	r0,3FFFFFFFFF01E06A; (p37) mov	pr,0x0; nop }
	{ (p01) sum	0x0; Invalid; (p35) mov	pr,0x1 }
	{ (p28) chk.a.nc	r0,3FFFFFFFFF01DE8A; (p37) mov	pr,0x0; break.i	0x120C }
	{ Invalid; (p38) nop; (p32) mov	pr,0x0 }
	{ Invalid; Invalid; Invalid }
	{ Invalid; (p46) nop; (p32) nop }
	{ (p01) sum	0x0; Invalid; (p51) break.i	0x598D }
	{ (p02) sum	0x0; (p04) break.m	0x198F; (p02) mov	pr,0x1 }
	{ cmpxchg2.acq.nta	r0,[r51],r42; Invalid; (p02) mov	pr,0x1 }
	{ addl	r28,-1569792,r0; (p07) nop; (p32) mov	pr,0x0 }
	{ (p24) chk.a.nc	r0,400000000001F28A; (p37) mov	pr,0x0; nop }
	{ (p01) sum	0x0; mov	pr,0x1; Invalid }
	{ (p27) nop; (p37) mov	pr,0x0; nop; }
	{ (p02) sum	0x0; (p04) nop; (p32) mov	pr,0x0 }
	{ setf.d	f0,r90; Invalid; (p02) nop }
	{ (p01) sum	0x0; (p44) nop; (p32) nop; }
	{ (p02) sum	0x0; (p36) nop; (p35) mov	pr,0x0 }
	{ Invalid; (p34) nop; (p35) mov	pr,0x0 }
	{ sum	0x0; (p04) mov	pr,0x1; mov	pr,0x0 }
	{ ld1	r0,[r41]; (p37) mov	pr,0x0; Invalid }
	{ (p02) sum	0x0; (p04) nop; (p32) mov	pr,0x0 }
	{ cmpxchg2.acq.nt1	r0,[r109],r70; (p37) mov	pr,0x0; Invalid }
	{ (p02) sum	0x0; (p04) nop; (p32) mov	pr,0x0 }
	{ cmpxchg2.acq.nt1	r0,[r98],r78; Invalid; (p02) nop }
	{ (p01) sum	0x0; (p44) nop; (p08) nop }
	{ (p01) sum	0x0; mov	pr,0x1; Invalid }
	{ (p27) chk.a.nc	r0,3FFFFFFFFF0210CA; (p33) bsw.0; (p02) bsw.0; }
	{ (p02) nop; (p42) break.i	0x5980; (p08) nop }
	{ Invalid; (p46) mov	pr,0x0; mov	pr,0x0; }
	{ sum	0x0; (p44) nop; (p32) nop }
	{ Invalid; (p06) nop; (p35) mov	pr,0x0; }
	{ setf.d	f0,r118; Invalid; (p02) mov	pr,0x1 }
	{ addl	r24,-1569280,r0; (p07) nop; (p32) mov	pr,0x0 }
	{ (p24) break.m	0x101400; Nyi; (p06) mov	pr,0x1 }
	{ Invalid; Invalid; (p43) mov	pr,0x1 }
	{ (p28) chk.a.nc	r0,3FFFFFFFFF01EBDA; (p05) nop; (p32) mov	pr,0x0 }
	{ ld1.nta	r0,[r57]; Invalid; (p02) mov	pr,0x19E0701 }
	{ (p02) nop; (p38) nop; (p32) nop }
	{ (p01) sum	0x0; Invalid; (p08) nop; }
	{ Invalid; (p38) mov	pr,0x0; nop }
	{ (p01) sum	0x0; (p12) nop; (p32) mov	pr,0x0; }
	{ break.m	0x2440; (p34) nop; (p35) mov	pr,0x0 }
	{ sum	0x0; (p36) mov	pr,0x19C0700; (p02) mov	pr,0x1 }
	{ Invalid; (p38) nop; (p33) mov	pr,0x0 }
	{ Invalid; (p38) nop; (p32) nop }
	{ (p01) sum	0x0; mov	pr,0x1; Invalid; }
	{ (p27) break.m	0x115800; (p37) break.b	0x0; nop; }
	{ (p02) sum	0x0; (p04) nop; (p32) mov	pr,0x0 }
	{ Invalid; Invalid; (p02) nop }
	{ (p01) sum	0x0; (p36) mov	pr,0x0; Invalid }
	{ (p02) sum	0x0; (p04) nop; (p32) mov	pr,0x0 }
	{ Invalid; Invalid; (p02) nop }
	{ (p01) sum	0x0; (p36) mov	pr,0x0; nop }
	{ (p02) sum	0x0; (p32) nop; (p35) mov	pr,0x0 }
	{ sum	0x0; (p36) mov	pr,0x0; nop }
	{ (p02) sum	0x0; (p04) nop; (p32) mov	pr,0x0 }
	{ ld1	r0,[r35]; Invalid; (p02) mov	pr,0x1 }
	{ Invalid; (p38) nop; (p32) nop }
	{ (p01) sum	0x0; Invalid; Invalid; }
	{ (p02) addl	r28,-1111040,r0; Invalid; mov	pr,0x0 }
	{ sum	0x0; (p32) mov	pr,0x0; nop }
	{ (p01) sum	0x0; (p32) nop; (p35) nop }
	{ (p25) break.m	0x100600; (p45) nop; (p08) nop; }
	{ (p01) sum	0x0; mov	pr,0x1; Invalid }
	{ (p31) chk.a.nc	r0,3FFFFFFFFF0219AA; nop; (p08) nop; }
	{ (p01) sum	0x0; (p04) mov	pr,0x1; Invalid }
	{ (p31) chk.a.nc	r0,3FFFFFFFFF0213CA; (p37) break.b	0x0; nop; }

l400000000001DFD0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r36; nop.i	0x0; }
	{ nop.m	0x0; (p06) addl	r14,1,r0; (p06) br.cond.dptk.few	400000000001E020; }

l400000000001DFEC:
	{ (p02) cmp.lt	p00,p11,r0,r33; zxt4	r46,r14; break.i	0x1000 }

l400000000001DFF0:
	{ addl	r14,7352,r1; nop.m	0x0; nop.i	0x0; }
	{ ld4	r14,[r14]; cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; }
	{ (p06) addl	r14,1,r0; nop.i	0x0; (p07) adds	r14,0x0,r0 }

l400000000001E016:
	{ chk.a.nc	f0,3FFFFFFFFF01E816; (p07) nop; nop }

l400000000001E020:
	{ addl	r16,7352,r1; nop.m	0x0; addl	r15,6552,r1; }
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; nop.i	0x0; }
	{ st4	[r14],r16; nop.i	0x0; (p07) br.cond.dpnt.few	400000000001EC80 }

l400000000001E060:
	{ addl	r14,8908,r1; adds	r15,0x108,r12; adds	r35,0xF4,r12 }
	{ adds	r53,0x0,r0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; adds	r14,0x100,r12; (p06) br.cond.dpnt.few	400000000001F5B0; }

l400000000001E0A0:
	{ ld8	r50,[r14]; ld4	r52,[r15]; nop.i	0x0; }
	{ ld4.acq	r51,[r35]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000021EC0; }
	{ adds	r1,0x128,r12; nop.m	0x0; addl	r16,2,r0; }
	{ ld8	r1,[r1]; st4.rel	[r8],r35; nop.i	0x0; }
	{ addl	r14,6472,r1; nop.m	0x0; addl	r15,6496,r1; }
	{ ld4	r14,[r14]; st4	[r16],r15; addl	r15,1,r0; }
	{ cmp4.eq	p06,p07,0x0,r14; addl	r14,8908,r1; (p07) br.cond.dpnt.few	400000000001ED30; }

l400000000001E110:
	{ nop.m	0x0; ld8	r50,[r14]; addl	r14,6488,r1; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,fn4000000000021C00 }

l400000000001E130:
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0; }

l400000000001E150:
	{ addl	r14,9044,r1; nop.m	0x0; nop.i	0x0; }
	{ ld4	r50,[r14]; nop.i	0x0; br.call.sptk.many	b0,exit_shell; }

l400000000001E170:
	{ addl	r51,372,r1; addl	r52,5,r0; adds	r50,0x0,r0; }
	{ ld8	r51,[r51]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x128,r12; adds	r50,0x0,r8; adds	r51,0x0,r35; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,report_error; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0 }

l400000000001E1D0:
	{ nop.m	0x0; addl	r50,2,r0; br.call.sptk.many	b0,fn400000000001B580; }

l400000000001E1E0:
	{ adds	r51,0x0,r35; adds	r50,0x0,r39; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x128,r12; nop.m	0x0; cmp4.eq	p07,p06,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dptk.few	400000000001D5A0 }

l400000000001E210:
	{ nop.m	0x0; sxt4	r14,r37; dep.z	r14,r14,5,59; }
	{ add	r16,r45,r14; adds	r15,0x8,r16; nop.i	0x0; }
	{ ld4	r15,[r15]; cmp4.eq	p07,p06,0x1,r15; nop.i	0x0; }
	{ (p07) adds	r16,0x10,r16; (p07) ld8	r14,[r16]; adds	r16,0x100,r12; }

l400000000001E246:
	{ (p07) fwb; (p08) cmp4.eq.or.andcm	p00,p02,r12,r2; (p01) nop; }

l400000000001E24C:
	{ Invalid; (p48) cmp.lt.unc	p03,p08,r3,r100; (p33) mov	pr,r3,0x8096 }

l400000000001E256:
	{ (p07) chk.a.clr	f46,3FFFFFFFFF01E336; nop; nop }

l400000000001E260:
	{ adds	r40,0x1,r40; ld8	r16,[r16]; adds	r14,0x10,r14; }
	{ nop.m	0x0; sxt4	r15,r40; shladd	r15,r15,0x3,r16; }
	{ nop.m	0x0; ld8	r15,[r15]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r15; nop.i	0x0; (p07) br.cond.spnt.few	400000000001E170; }

l400000000001E2A0:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ st8	[r15],r14; nop.m	0x0; nop.i	0x0 }

l400000000001E2C0:
	{ adds	r16,0x108,r12; nop.m	0x0; adds	r40,0x1,r40; }
	{ ld4	r16,[r16]; nop.m	0x0; sxt4	r14,r40; }
	{ cmp4.eq	p07,p06,r40,r16; adds	r16,0x100,r12; (p07) br.cond.dpnt.few	400000000001D5E0; }

l400000000001E2F0:
	{ ld8	r16,[r16]; shladd	r14,r14,0x3,r16; nop.i	0x0; }
	{ nop.m	0x0; ld8	r50,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r50; nop.i	0x0; (p06) br.cond.dpnt.few	400000000001D5E0; }

l400000000001E320:
	{ ld1	r14,[r50]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x2D,r14; adds	r14,0x1,r50; (p07) br.cond.dpnt.few	400000000001D5E0; }

l400000000001E340:
	{ nop.m	0x0; ld1	r38,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r38,r38; cmp4.eq	p07,p06,0x2D,r38; }
	{ nop.m	0x0; (p06) adds	r42,0x0,r41; (p06) br.cond.dptk.few	400000000001D560 }

l400000000001E36C:
	{ (p16) cmp.eq.unc	p62,p08,r63,r37; (p33) shladd	r64,r12,0x1,r64; (p04) nop }

l400000000001E370:
	{ adds	r15,0x2,r50; adds	r36,0x0,r43; adds	r37,0x0,r41 }
	{ adds	r35,0x0,r44; ld1	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; cmp4.eq	p06,p07,0x0,r15; }
	{ (p07) adds	r50,0x0,r14; (p06) adds	r42,0x0,r0; (p07) adds	r38,0x0,r15; }

l400000000001E3A6:
	{ (p21) chk.a.clr	f0,3FFFFFFFFF09E3A6; (p19) cmp.eq.or.andcm	p00,p02,r15,r0; (p33) nop; }

l400000000001E3AC:
	{ Invalid; (p20) nop }

l400000000001E3B0:
	{ (p07) addl	r42,1,r0; adds	r39,0x1,r50; br.cond.sptk.few	400000000001D580 }

l400000000001E3B6:
	{ Invalid; Invalid; (p32) br.call.sptk.few	b3,b0 }

l400000000001E3C0:
	{ ld4	r14,[r36]; addl	r50,332,r1; cmp4.eq	p07,p06,r14,r8 }
	{ addl	r14,6544,r1; ld8	r50,[r50]; nop.i	0x0; }
	{ (p06) addl	r8,1,r0; (p07) adds	r8,0x0,r0; nop.i	0x0; }

l400000000001E3E6:
	{ Invalid; nop; nop; }

l400000000001E3EC:
	{ Invalid; Invalid; break.i	0x1000 }
	{ (p32) nop; invala; Invalid }
	{ nop; Invalid; mov	pr,r32,0x0 }
	{ (p08) invala; break.i	0x1000; break.b	0x1000 }

l400000000001E420:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000001EC20 }

l400000000001E430:
	{ adds	r16,0x1,r15; ld1	r16,[r16]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r16,r16; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r16; nop.i	0x0; (p06) br.cond.dpnt.few	400000000001D820; }

l400000000001E460:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r16; (p06) br.cond.dptk.few	400000000001D750 }

l400000000001E470:
	{ adds	r16,0x2,r15; nop.m	0x0; adds	r37,0x0,r14; }
	{ ld1	r16,[r16]; nop.m	0x0; sxt1	r16,r16; }
	{ cmp4.eq	p06,p07,0x0,r16; nop.i	0x0; (p06) br.cond.dpnt.few	400000000001D820; }

l400000000001E4A0:
	{ cmp4.eq	p07,p06,0x2D,r14; adds	r36,0x1,r15; (p06) addl	r38,1,r0; }

l400000000001E4B0:
	{ nop.m	0x0; (p07) adds	r38,0x0,r0; br.cond.sptk.few	400000000001D770 }

l400000000001E4BC:
	{ (p22) cmpxchg4.acq	r126,[r36],r63; zxt4	r0,r0; break.i	0x1000 }

l400000000001E4C0:
	{ addl	r50,1,r0; nop.i	0x0; br.call.sptk.many	b0,show_shell_version; }
	{ adds	r1,0x128,r12; nop.m	0x0; adds	r50,0x0,r0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B580 }

l400000000001E4F0:
	{ adds	r15,0x1,r14; ld1	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x68,r15; nop.i	0x0; (p07) br.cond.dpnt.few	400000000001F550; }

l400000000001E520:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x75,r15; (p07) br.cond.dptk.few	400000000001D2A0 }

l400000000001E530:
	{ adds	r14,0x2,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x0,r14; }
	{ (p07) addl	r14,6604,r1; (p07) ld4	r15,[r14]; nop.i	0x0; }

l400000000001E556:
	{ (p07) fwb; nop; Invalid; }

l400000000001E55C:
	{ nop; cmp4.eq.or.andcm	p00,p32,r32,r0; zxt1	r96,r64 }

l400000000001E56C:
	{ Invalid; Invalid; break.i	0x1000 }

l400000000001E576:
	{ break.m	0x4000; nop; break.i	0x80000 }

l400000000001E580:
	{ nop.m	0x0; ld1	r15,[r8]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; cmp4.eq	p07,p06,0x2D,r15; }
	{ (p07) adds	r8,0x1,r8; (p07) st8	[r8],r14; addl	r14,6520,r1; }

l400000000001E5A6:
	{ mf.a; (p07) nop; break.i	0x80000; }

l400000000001E5AC:
	{ (p60) nop; cmp.eq	p00,p00,r32,r0; Invalid; }
	{ cmp.eq	p00,p11,r1,r0; zxt1	r96,r64; (p48) cmp.lt.unc	p03,p08,r3,r100 }
	{ (p38) cmp.lt	p01,p11,r50,r72; (p01) cmp.eq.unc	p00,p08,r3,r6; Invalid; }
	{ nop.m	0x80; cmp.eq	p00,p00,r32,r0; (p01) break.i	0x141E0 }
	{ invala; cmp.lt	p00,p00,r32,r0; (p48) mov	pr,r99,0xE6F8 }
	{ (p37) invala; break.i	0x1000; break.b	0x1000 }

l400000000001E600:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000001E4F0 }
400000000001E610 0B 70 30 03 45 24 00 00 00 02 00 00 00 00 04 00 .p0.E$..........
400000000001E620 09 00 00 00 01 00 E0 00 38 30 20 00 00 00 04 00 ........80 .....
400000000001E630 10 00 00 00 01 00 70 00 38 0C F2 03 30 0B 00 43 ......p.8...0..C
400000000001E640 11 00 00 00 01 00 00 00 00 02 00 00 C8 2C 00 50 .............,.P
400000000001E650 09 00 00 00 01 00 10 40 31 04 42 00 00 00 04 00 .......@1.B.....
400000000001E660 10 08 00 02 18 10 00 00 00 02 00 00 70 F4 FF 48 ............p..H

l400000000001E670:
	{ cmp4.eq	p06,p07,0x63,r15; nop.i	0x0; (p06) br.cond.dpnt.few	400000000001E990; }

l400000000001E680:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x63,r15; (p06) br.cond.dptk.few	400000000001E7F0; }

l400000000001E690:
	{ cmp4.eq	p06,p07,0x44,r15; nop.i	0x0; (p06) br.cond.dpnt.few	400000000001E980; }

l400000000001E6A0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x4F,r15; (p06) br.cond.dpnt.few	400000000001E740 }

l400000000001E6B0:
	{ adds	r51,0x0,r37; adds	r50,0x0,r43; br.call.sptk.many	b0,change_flag; }
	{ adds	r1,0x128,r12; nop.m	0x0; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.sptk.few	400000000001D770; }

l400000000001E6E0:
	{ addl	r51,388,r1; adds	r50,0x0,r0; addl	r52,5,r0; }
	{ ld8	r51,[r51]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x128,r12; nop.m	0x0; adds	r50,0x0,r8 }
	{ adds	r51,0x0,r37; nop.m	0x0; adds	r52,0x0,r43; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,report_error; }
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000020A60 }

l400000000001E740:
	{ adds	r15,0x100,r12; nop.m	0x0; sxt4	r14,r35; }
	{ ld8	r15,[r15]; shladd	r14,r14,0x3,r15; nop.i	0x0; }
	{ nop.m	0x0; ld8	r43,[r14]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r43; nop.i	0x0; (p07) br.cond.dpnt.few	400000000001F340; }

l400000000001E780:
	{ ld4	r14,[r42]; ld4	r15,[r41]; nop.i	0x0; }
	{ cmp4.lt	p06,p07,r15,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000001ED90; }

l400000000001E7A0:
	{ nop.m	0x0; ld4	r15,[r41]; adds	r35,0x1,r35 }
	{ ld8	r14,[r40]; nop.i	0x0; sxt4	r16,r15 }
	{ adds	r15,0x1,r15; nop.i	0x0; shladd	r14,r16,0x4,r14 }
	{ st4	[r15],r41; st8	[r14],r8,8; nop.i	0x0; }
	{ st4	[r37],r14; nop.i	0x0; br.cond.sptk.few	400000000001D770 }

l400000000001E7F0:
	{ cmp4.eq	p06,p07,0x6F,r15; nop.i	0x0; (p06) br.cond.dpnt.few	400000000001E9B0; }

l400000000001E800:
	{ cmp4.eq	p06,p07,0x73,r15; nop.i	0x0; (p06) br.cond.dpnt.few	400000000001E9A0; }

l400000000001E810:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x6C,r15; (p07) br.cond.dptk.few	400000000001E6B0 }

l400000000001E820:
	{ st4	[r39],r45; nop.i	0x0; br.cond.sptk.few	400000000001D770 }

l400000000001E830:
	{ addl	r15,324,r1; nop.m	0x0; addl	r14,6476,r1; }
	{ ld8	r15,[r15]; st8	[r15],r14; addl	r14,6476,r1; }
	{ ld8	r14,[r14]; ld1	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x73,r15; (p07) br.cond.dptk.few	400000000001D2A0 }

l400000000001E880:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000001E4F0 }

l400000000001E890:
	{ addl	r14,-10260,r1; nop.m	0x0; addl	r51,1,r0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r50,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn40000000000213C0; }
	{ adds	r1,0x128,r12; nop.m	0x0; adds	r50,0x0,r0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B580; }

l400000000001E8E0:
	{ addl	r14,8900,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000001D920 }

l400000000001E910:
	{ addl	r14,7392,r1; nop.m	0x0; addl	r15,1,r0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.cond.sptk.few	400000000001D920 }
400000000001E940 11 90 A5 01 00 24 30 6B 01 00 48 00 48 7B 05 50 .....$0k..H.H{.P
400000000001E950 09 08 A0 18 02 21 00 00 00 02 00 E0 11 00 00 90 .....!..........
400000000001E960 0B 08 00 02 18 10 E0 A0 07 64 48 00 00 00 04 00 .........dH.....
400000000001E970 10 00 3C 1C 90 11 00 00 00 02 00 00 A0 F5 FF 48 ..<............H

l400000000001E980:
	{ st4	[r39],r44; nop.i	0x0; br.cond.sptk.few	400000000001D770 }

l400000000001E990:
	{ st4	[r39],r47; nop.i	0x0; br.cond.sptk.few	400000000001D770 }

l400000000001E9A0:
	{ st4	[r39],r46; nop.i	0x0; br.cond.sptk.few	400000000001D770 }

l400000000001E9B0:
	{ adds	r16,0x100,r12; sxt4	r14,r35; adds	r50,0x0,r37; }
	{ ld8	r16,[r16]; shladd	r14,r14,0x3,r16; nop.i	0x0; }
	{ nop.m	0x0; ld8	r51,[r14]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r51; nop.i	0x0; (p07) br.cond.dpnt.few	400000000001F310; }

l400000000001E9F0:
	{ adds	r35,0x1,r35; nop.i	0x0; br.call.sptk.many	b0,set_minus_o_option; }
	{ adds	r1,0x128,r12; nop.m	0x0; cmp4.eq	p07,p06,0x0,r8; }
	{ ld8	r1,[r1]; (p06) br.cond.spnt.few	400000000001E1D0; br.cond.sptk.few	400000000001D770; }

l400000000001EA1C:
	{ (p43) nop; dep	r0,r32,r0,63,1; zxt4	r39,r0 }
400000000001EA20 09 00 00 00 01 00 20 E3 04 06 48 00 00 00 04 00 ...... ...H.....
400000000001EA30 11 90 01 64 18 10 00 00 00 02 00 00 98 46 04 50 ...d.........F.P
400000000001EA40 09 08 A0 18 02 21 00 00 00 02 00 60 04 40 00 84 .....!.....`.@..
400000000001EA50 0B 08 00 02 18 10 20 23 05 06 48 00 00 00 04 00 ...... #..H.....
400000000001EA60 11 90 01 64 18 10 00 00 00 02 00 00 68 46 04 50 ...d........hF.P
400000000001EA70 09 08 A0 18 02 21 50 02 20 00 42 C0 00 18 1D E4 .....!P. .B.....
400000000001EA80 11 08 00 02 18 10 00 00 00 02 00 03 70 1D 00 43 ............p..C
400000000001EA90 0B 70 00 46 00 10 00 00 00 02 00 C0 01 70 50 00 .p.F.........pP.
400000000001EAA0 11 00 00 00 01 00 70 28 3B 0C F3 03 60 17 00 43 ......p(;...`..C
400000000001EAB0 C8 40 00 00 00 21 00 00 00 02 00 00 00 00 04 00 .@...!..........
400000000001EAC0 09 70 10 03 32 24 00 00 00 02 00 E0 00 28 19 E4 .p..2$.......(..
400000000001EAD0 0B 78 00 1C 10 10 80 78 20 1C 40 00 00 00 04 00 .x.....x .@.....
400000000001EAE0 11 00 20 1C 90 11 40 02 20 00 C2 03 B0 16 00 43 .. ...@. ......C
400000000001EAF0 0B 70 00 4A 00 10 00 00 00 02 00 C0 01 70 50 00 .p.J.........pP.
400000000001EB00 11 00 00 00 01 00 70 A0 3B 0C F3 03 E0 08 00 43 ......p.;......C
400000000001EB10 08 70 A0 03 45 24 F0 08 00 00 48 80 14 00 00 90 .p..E$....H.....
400000000001EB20 0B 30 00 46 07 39 00 00 00 02 00 00 00 00 04 00 .0.F.9..........
400000000001EB30 11 00 3C 1C 90 11 00 00 00 02 00 03 30 00 00 43 ..<.........0..C
400000000001EB40 0B 70 00 46 00 10 00 00 00 02 00 C0 01 70 50 00 .p.F.........pP.
400000000001EB50 10 00 00 00 01 00 70 28 3B 0C F3 03 20 09 00 43 ......p(;... ..C
400000000001EB60 0B 70 00 00 00 21 40 22 39 00 40 C0 81 0E 14 91 .p...!@"9.@.....
400000000001EB70 09 00 00 00 01 00 00 00 00 02 00 C0 00 20 1D E6 ............. ..
400000000001EB80 EB 78 04 00 00 24 00 20 39 20 A3 C3 01 0D E0 90 .x...$. 9 ......
400000000001EB90 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000001EBA0 F0 00 3C 1C 90 11 00 00 00 02 00 00 B0 F1 FF 48 ..<............H
400000000001EBB0 09 18 31 03 02 24 30 A3 04 06 48 80 06 00 00 84 ..1..$0...H.....
400000000001EBC0 09 18 01 46 18 10 30 03 CC 30 20 00 00 00 04 00 ...F..0..0 .....
400000000001EBD0 11 90 01 46 00 21 00 00 00 02 00 00 F8 97 04 50 ...F.!.........P
400000000001EBE0 09 08 A0 18 02 21 00 00 00 02 00 40 06 18 01 84 .....!.....@....
400000000001EBF0 11 08 00 02 18 10 00 00 00 02 00 00 98 3C 04 50 .............<.P
400000000001EC00 09 00 00 00 01 00 10 40 31 04 42 00 00 00 04 00 .......@1.B.....
400000000001EC10 11 08 00 02 18 10 00 00 00 02 00 00 70 EF FF 48 ............p..H

l400000000001EC20:
	{ nop.m	0x0; addl	r50,340,r1; nop.i	0x0; }
	{ ld8	r50,[r50]; nop.i	0x0; br.call.sptk.many	b0,getenv; }
	{ adds	r1,0x128,r12; addl	r15,1,r0; cmp.eq	p07,p06,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p07) br.cond.dpnt.few	400000000001CD40; }

l400000000001EC60:
	{ nop.m	0x0; addl	r14,6456,r1; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.cond.sptk.few	400000000001CD40 }

l400000000001EC80:
	{ nop.m	0x0; addl	r14,6476,r1; nop.i	0x0; }
	{ ld8	r50,[r14]; nop.i	0x0; br.call.sptk.many	b0,maybe_make_restricted; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	400000000001E060; }

l400000000001ECC0:
	{ addl	r35,332,r1; addl	r51,404,r1; adds	r52,0x0,r0; }
	{ ld8	r35,[r35]; ld8	r51,[r51]; nop.i	0x0; }
	{ adds	r50,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r1,0x128,r12; nop.m	0x0; adds	r50,0x0,r35; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,sv_strict_posix; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	400000000001DFD0 }

l400000000001ED30:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000021B40; }
	{ adds	r1,0x128,r12; nop.m	0x0; addl	r15,1,r0; }
	{ ld8	r1,[r1]; addl	r14,8908,r1; nop.i	0x0; }
	{ nop.m	0x0; ld8	r50,[r14]; addl	r14,6488,r1; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,fn4000000000021C00; }
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000001E130 }

l400000000001ED90:
	{ adds	r14,0x8,r14; ld8	r50,[r40]; adds	r35,0x1,r35; }
	{ nop.m	0x0; sxt4	r51,r14; nop.i	0x0 }
	{ st4	[r14],r42; nop.m	0x0; nop.i	0x0; }
	{ shladd	r51,r51,0x4,r0; nop.i	0x0; br.call.sptk.many	b0,xrealloc; }
	{ ld4	r15,[r41]; adds	r1,0x128,r12; sxt4	r16,r15 }
	{ ld8	r1,[r1]; st8	[r8],r40; adds	r15,0x1,r15; }
	{ ld8	r14,[r40]; st4	[r15],r41; nop.i	0x0; }
	{ shladd	r14,r16,0x4,r14; st8	[r14],r8,8; nop.i	0x0; }
	{ st4	[r37],r14; nop.i	0x0; br.cond.sptk.few	400000000001D770 }
400000000001EE20 09 70 B0 03 39 24 00 00 00 02 00 E0 01 0F C8 90 .p..9$..........
400000000001EE30 09 00 00 00 01 00 F0 00 3C 20 20 00 00 00 04 00 ........<  .....
400000000001EE40 02 30 00 1E 87 39 00 00 00 02 00 00 00 00 04 00 .0...9..........
400000000001EE50 18 28 01 1C 10 10 00 00 38 20 A3 03 20 01 00 42 .(......8 .. ..B
400000000001EE60 0B 70 10 03 33 24 E0 00 38 20 20 00 00 00 04 00 .p..3$..8  .....
400000000001EE70 10 00 00 00 01 00 60 00 38 0E F3 03 E0 13 00 42 ......`.8......B
400000000001EE80 0B 70 E0 03 32 24 E0 00 38 20 20 00 00 00 04 00 .p..2$..8  .....
400000000001EE90 10 00 00 00 01 00 70 00 38 0C 73 03 C0 13 00 42 ......p.8.s....B
400000000001EEA0 0B 70 F0 02 33 24 E0 00 38 20 20 00 00 00 04 00 .p..3$..8  .....
400000000001EEB0 10 00 00 00 01 00 70 00 38 0C 73 03 A0 13 00 42 ......p.8.s....B
400000000001EEC0 09 70 30 03 45 24 00 00 00 02 00 40 C6 0D 0C 90 .p0.E$.....@....
400000000001EED0 0B 00 00 00 01 00 E0 00 38 30 20 00 00 00 04 00 ........80 .....
400000000001EEE0 11 30 00 1C 07 39 00 00 00 02 00 03 70 13 00 43 .0...9......p..C
400000000001EEF0 11 90 01 64 18 10 00 00 00 02 00 00 58 36 04 50 ...d........X6.P
400000000001EF00 09 08 A0 18 02 21 00 00 00 02 00 E0 00 40 18 E4 .....!.......@..
400000000001EF10 11 08 00 02 18 10 00 00 00 02 80 03 B0 16 00 43 ...............C
400000000001EF20 0B 70 50 03 37 24 00 00 00 02 00 00 00 00 04 00 .pP.7$..........
400000000001EF30 09 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
400000000001EF40 10 00 00 00 01 00 60 08 38 0E E3 03 80 19 00 43 ......`.8......C
400000000001EF50 0B 70 C0 03 32 24 E0 00 38 20 20 00 00 00 04 00 .p..2$..8  .....
400000000001EF60 10 00 00 00 01 00 70 00 38 0C F3 03 F0 12 00 41 ......p.8......A
400000000001EF70 11 90 01 00 00 21 00 00 00 02 00 00 18 61 06 50 .....!.......a.P
400000000001EF80 09 08 A0 18 02 21 00 00 00 02 00 60 04 40 00 84 .....!.....`.@..
400000000001EF90 09 08 00 02 18 10 00 00 00 02 00 00 00 00 04 00 ................
400000000001EFA0 0B 70 E0 03 32 24 E0 00 38 20 20 00 00 00 04 00 .p..2$..8  .....
400000000001EFB0 10 00 00 00 01 00 60 00 38 0E 73 03 90 11 00 42 ......`.8.s....B
400000000001EFC0 0B 70 E0 02 32 24 E0 00 38 20 20 00 00 00 04 00 .p..2$..8  .....
400000000001EFD0 10 00 00 00 01 00 70 00 38 0C 73 03 70 11 00 42 ......p.8.s.p..B
400000000001EFE0 09 70 10 03 33 24 00 00 00 02 00 00 02 0C CC 90 .p..3$..........
400000000001EFF0 09 78 00 1C 10 10 00 01 40 20 20 00 00 00 04 00 .x......@  .....
400000000001F000 09 78 04 1E 00 21 00 00 00 02 00 C0 00 80 1C E6 .x...!..........
400000000001F010 10 00 3C 1C 90 11 00 00 00 02 00 03 B0 1A 00 43 ..<............C

l400000000001F020:
	{ addl	r14,1,r0; nop.m	0x0; nop.i	0x0 }
	{ addl	r15,6512,r1; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p07) br.cond.dptk.few	40000000000203A0 }

l400000000001F050:
	{ addl	r15,6456,r1; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	4000000000020260 }

l400000000001F070:
	{ addl	r14,7344,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	400000000001F0D0 }

l400000000001F0A0:
	{ nop.m	0x0; addl	r14,6548,r1; nop.i	0x0; }
	{ ld4	r15,[r14]; adds	r16,0x1,r15; cmp4.eq	p07,p06,0x0,r15; }
	{ st4	[r16],r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000020670 }

l400000000001F0D0:
	{ adds	r50,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,set_job_control; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0; }

l400000000001F100:
	{ addl	r14,7404,r1; nop.m	0x0; nop.i	0x0; }
	{ ld4	r15,[r14]; nop.i	0x0; add	r15,r37,r15; }
	{ st4	[r15],r14; nop.m	0x0; nop.i	0x0 }

l400000000001F130:
	{ addl	r14,6588,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000001DFD0 }

l400000000001F150:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000001ECC0 }
400000000001F160 0B 70 00 03 32 24 E0 00 38 20 20 00 00 00 04 00 .p..2$..8  .....
400000000001F170 10 00 00 00 01 00 70 00 38 0C 73 03 D0 F4 FF 4A ......p.8.s....J
400000000001F180 09 70 D0 19 01 21 00 00 00 02 00 40 82 60 08 84 .p...!.....@.`..
400000000001F190 09 70 00 1C B0 10 20 01 48 20 20 00 00 00 04 00 .p.... .H  .....
400000000001F1A0 11 30 48 1C 87 38 E0 A0 06 8A 48 03 30 00 00 43 .0H..8....H.0..C
400000000001F1B0 0B 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
400000000001F1C0 10 00 00 00 01 00 60 00 38 0E 73 03 80 F4 FF 4A ......`.8.s....J
400000000001F1D0 0B 70 30 FA AF 27 E0 00 38 30 20 00 00 00 04 00 .p0..'..80 .....
400000000001F1E0 11 90 01 1C 18 10 00 00 00 02 00 00 E8 C9 FF 58 ...............X
400000000001F1F0 09 08 A0 18 02 21 00 00 00 02 00 40 06 40 00 84 .....!.....@.@..
400000000001F200 11 08 00 02 18 10 00 00 00 02 00 00 C8 CF FF 58 ...............X
400000000001F210 09 08 A0 18 02 21 00 00 00 02 00 C0 00 40 1C E6 .....!.......@..
400000000001F220 11 08 00 02 18 10 00 00 00 02 00 03 20 F4 FF 4A ............ ..J
400000000001F230 0B 70 90 FB AC 27 E0 00 38 30 20 00 00 00 04 00 .p...'..80 .....
400000000001F240 11 90 01 1C 18 10 00 00 00 02 00 00 88 C9 FF 58 ...............X
400000000001F250 09 08 A0 18 02 21 00 00 00 02 00 40 06 40 00 84 .....!.....@.@..
400000000001F260 11 08 00 02 18 10 00 00 00 02 00 00 68 CF FF 58 ............h..X
400000000001F270 09 08 A0 18 02 21 00 00 00 02 00 E0 00 40 18 E6 .....!.......@..
400000000001F280 11 08 00 02 18 10 00 00 00 02 80 03 C0 F3 FF 4A ...............J
400000000001F290 09 70 04 00 00 24 00 00 00 02 00 E0 01 0E C8 90 .p...$..........
400000000001F2A0 09 00 38 1E 90 11 00 00 00 02 00 E0 01 0F C8 90 ..8.............
400000000001F2B0 09 00 38 1E 90 11 00 00 00 02 00 E0 81 09 D0 90 ..8.............
400000000001F2C0 0B 00 00 00 01 00 00 70 3C 20 23 E0 41 0F C8 90 .......p< #.A...
400000000001F2D0 10 00 38 1E 90 11 00 00 00 02 00 00 00 E8 FF 48 ..8............H

l400000000001F2E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,disable_priv_mode; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	400000000001D970 }

l400000000001F310:
	{ addl	r50,-1,r0; adds	r51,0x0,r38; br.call.sptk.many	b0,list_minus_o_opts; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	400000000001D770 }

l400000000001F340:
	{ adds	r50,0x0,r0; adds	r51,0x0,r38; br.call.sptk.many	b0,shopt_listopt; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	400000000001D770; }

l400000000001F370:
	{ addl	r51,372,r1; addl	r52,5,r0; adds	r50,0x0,r0; }
	{ ld8	r51,[r51]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x128,r12; nop.m	0x0; adds	r50,0x0,r8; }
	{ ld8	r1,[r1]; addl	r51,260,r1; nop.i	0x0; }
	{ ld8	r51,[r51]; nop.i	0x0; br.call.sptk.many	b0,report_error; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	400000000001E1D0 }
400000000001F3E0 0B 70 04 4A 00 21 E0 00 38 00 20 00 00 00 04 00 .p.J.!..8. .....
400000000001F3F0 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
400000000001F400 10 00 00 00 01 00 70 00 38 0C 73 03 10 F7 FF 4A ......p.8.s....J
400000000001F410 03 70 00 46 00 10 F0 08 00 00 48 C0 01 70 50 00 .p.F......H..pP.
400000000001F420 11 38 90 1D 86 39 E0 40 07 8A C8 03 30 14 00 43 .8...9.@....0..C
400000000001F430 09 00 00 00 01 00 00 00 00 02 00 80 14 00 00 90 ................
400000000001F440 08 00 3C 1C 90 11 00 00 00 02 00 00 00 00 04 00 ..<.............
400000000001F450 0B 70 00 46 00 10 00 00 00 02 00 C0 01 70 50 00 .p.F.........pP.
400000000001F460 10 00 00 00 01 00 70 28 3B 0C 73 03 00 F7 FF 4A ......p(;.s....J
400000000001F470 09 98 F1 02 03 24 20 03 8C 00 42 80 56 00 00 90 .....$ ...B.V...
400000000001F480 11 98 01 66 18 10 00 00 00 02 00 00 A8 CB FF 58 ...f...........X
400000000001F490 09 08 A0 18 02 21 00 00 00 02 00 E0 00 40 18 E6 .....!.......@..
400000000001F4A0 11 08 00 02 18 10 00 00 00 02 00 03 C0 F6 FF 4A ...............J
400000000001F4B0 08 30 00 4A 07 39 00 00 00 02 00 60 46 0C 0C 90 .0.J.9.....`F...
400000000001F4C0 19 90 01 4A 00 21 00 00 00 02 00 03 A0 F6 FF 4B ...J.!.........K
400000000001F4D0 11 98 01 66 18 10 00 00 00 02 00 00 F8 AE FF 58 ...f...........X
400000000001F4E0 09 08 A0 18 02 21 00 00 00 02 00 E0 00 40 18 E4 .....!.......@..
400000000001F4F0 11 08 00 02 18 90 E1 08 00 00 C8 03 70 F6 FF 4B ............p..K
400000000001F500 09 20 91 1C 00 20 00 00 00 02 00 C0 81 0E 14 91 . ... ..........
400000000001F510 09 00 00 00 01 00 00 00 00 02 00 C0 00 20 1D E6 ............. ..
400000000001F520 EB 78 04 00 00 24 00 20 39 20 A3 C3 01 0D E0 90 .x...$. 9 ......
400000000001F530 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000001F540 F0 00 3C 1C 90 11 00 00 00 02 00 00 10 E8 FF 48 ..<............H

l400000000001F550:
	{ adds	r14,0x2,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	400000000001D2A0 }

l400000000001F580:
	{ addl	r14,6588,r1; ld4	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; adds	r15,0x1,r15; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.cond.sptk.few	400000000001D2A0 }

l400000000001F5B0:
	{ adds	r14,0xF4,r12; nop.m	0x0; adds	r16,0x108,r12; }
	{ ld4.acq	r15,[r14]; ld4	r16,[r16]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,r16,r15; addl	r15,8916,r1; (p06) br.cond.dpnt.few	400000000001F600; }

l400000000001F5E0:
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p07) br.cond.dpnt.few	400000000001F9C0 }

l400000000001F600:
	{ addl	r14,6516,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	400000000001F920 }

l400000000001F620:
	{ addl	r14,-10356,r1; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r50,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BBC0; }
	{ adds	r1,0x128,r12; nop.m	0x0; adds	r50,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,sh_unset_nodelay_mode; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0; }

l400000000001F680:
	{ addl	r14,6516,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	40000000000200D0 }

l400000000001F6A0:
	{ addl	r14,5636,r1; ld4	r50,[r14]; addl	r14,23444,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld8	r51,[r14]; nop.i	0x0; br.call.sptk.many	b0,with_input_from_buffered_stream; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0 }

l400000000001F6F0:
	{ adds	r14,0x100,r12; nop.m	0x0; adds	r35,0xF4,r12 }
	{ adds	r15,0x108,r12; nop.m	0x0; addl	r53,1,r0; }
	{ ld8	r50,[r14]; ld4	r52,[r15]; nop.i	0x0; }
	{ ld4.acq	r51,[r35]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000021EC0; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; st4.rel	[r8],r35; nop.i	0x0; }
	{ addl	r14,6472,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000001F7B0 }

l400000000001F770:
	{ adds	r14,0xF8,r12; ld4.acq	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	400000000001F7B0 }

l400000000001F790:
	{ addl	r14,6544,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	4000000000020950 }

l400000000001F7B0:
	{ addl	r14,6512,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	400000000001F810 }

l400000000001F7D0:
	{ addl	r15,1,r0; nop.m	0x0; addl	r14,6540,r1; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,reader_loop }

l400000000001F7F0:
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	400000000001E150 }

l400000000001F810:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,reset_mail_timer; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,init_mail_dates; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,bash_initialize_history; }
	{ adds	r1,0x128,r12; ld8	r1,[r1]; nop.i	0x0; }
	{ addl	r14,6540,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	400000000001F8C0 }

l400000000001F890:
	{ addl	r14,9148,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000209A0 }

l400000000001F8C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,get_tty_state; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0; }

l400000000001F8F0:
	{ addl	r15,1,r0; nop.m	0x0; addl	r14,6540,r1; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,reader_loop; }
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000001F7F0 }

l400000000001F920:
	{ addl	r14,-10356,r1; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r50,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BBC0; }
	{ adds	r1,0x128,r12; ld8	r1,[r1]; nop.i	0x0; }
	{ nop.m	0x0; addl	r14,5636,r1; nop.i	0x0; }
	{ st4	[r8],r14; nop.m	0x0; nop.i	0x0 }

l400000000001F970:
	{ addl	r14,6516,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; addl	r14,5636,r1; (p06) br.cond.spnt.few	400000000001F620; }

l400000000001F990:
	{ ld4	r50,[r14]; nop.i	0x0; br.call.sptk.many	b0,sh_unset_nodelay_mode; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	400000000001F680 }

l400000000001F9C0:
	{ ld4.acq	r14,[r14]; nop.m	0x0; adds	r18,0x100,r12; }
	{ ld8	r18,[r18]; sxt4	r14,r14; shladd	r14,r14,0x3,r18; }
	{ nop.m	0x0; ld8	r37,[r14]; nop.i	0x0; }
	{ adds	r50,0x0,r37; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x128,r12; nop.m	0x0; adds	r50,0x1,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x128,r12; adds	r50,0x0,r8; adds	r51,0x0,r37; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x128,r12; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r50,0x0,r8; nop.m	0x0; adds	r51,0x0,r0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B4E0; }
	{ adds	r1,0x128,r12; adds	r36,0x0,r8; cmp4.lt	p07,p06,r8,r0; }
	{ ld8	r1,[r1]; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000020EF0; }

l400000000001FA90:
	{ addl	r14,23444,r1; nop.m	0x0; addl	r38,8876,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld8	r50,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ ld8	r50,[r38]; adds	r1,0x128,r12; cmp.eq	p06,p07,0x0,r50 }
	{ ld8	r1,[r1]; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000020E80; }

l400000000001FAE0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x128,r12; nop.m	0x0; adds	r50,0x1,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ nop.m	0x0; adds	r1,0x128,r12; adds	r50,0x0,r8 }
	{ nop.m	0x0; ld8	r51,[r38]; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0; }

l400000000001FB60:
	{ addl	r37,8876,r1; nop.m	0x0; addl	r14,23444,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld8	r50,[r37]; st8	[r8],r14; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r50; nop.i	0x0; (p06) br.cond.dpnt.few	400000000001FBD0; }

l400000000001FBA0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x128,r12; st8	[r0],r37; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0; }

l400000000001FBD0:
	{ nop.m	0x0; addl	r50,532,r1; nop.i	0x0; }
	{ ld8	r50,[r50]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x128,r12; adds	r14,0x28,r8; cmp.eq	p06,p07,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000200C0; }

l400000000001FC10:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x2; (p06) br.cond.dptk.few	40000000000200C0; }

l400000000001FC30:
	{ nop.m	0x0; (p07) adds	r8,0x8,r8; nop.i	0x0; }

l400000000001FC3C:
	{ cmp4.eq.and	p00,p40,r1,r0; Invalid; break.i	0x1000 }

l400000000001FC46:
	{ break.m	0x4000; nop; break.i	0x80000 }

l400000000001FC50:
	{ nop.m	0x0; addl	r50,540,r1; nop.i	0x0; }
	{ ld8	r50,[r50]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x128,r12; adds	r14,0x28,r8; cmp.eq	p06,p07,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000200B0; }

l400000000001FC90:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x2; (p06) br.cond.dptk.few	40000000000200B0; }

l400000000001FCB0:
	{ nop.m	0x0; (p07) adds	r8,0x8,r8; nop.i	0x0; }

l400000000001FCBC:
	{ nop; Invalid; break.i	0x1000 }

l400000000001FCC6:
	{ break.m	0x4000; nop; break.i	0x80000 }

l400000000001FCD0:
	{ nop.m	0x0; addl	r50,548,r1; nop.i	0x0; }
	{ ld8	r50,[r50]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x128,r12; adds	r14,0x28,r8; cmp.eq	p06,p07,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000020150; }

l400000000001FD10:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x2; (p06) br.cond.dptk.few	4000000000020150 }

l400000000001FD30:
	{ adds	r8,0x8,r8; nop.m	0x0; adds	r50,0x0,r37 }
	{ addl	r51,1,r0; nop.m	0x0; adds	r52,0x0,r35; }
	{ ld8	r37,[r8]; nop.i	0x0; br.call.sptk.many	b0,array_rshift; }
	{ cmp.eq	p06,p07,0x0,r37; nop.m	0x0; adds	r1,0x128,r12; }
	{ ld8	r1,[r1]; (p06) br.cond.spnt.few	400000000001FE10; br.call.sptk.many	b0,executing_line_number; }

l400000000001FD7C:
	{ (p14) nop; invala; br.cond.sptk.few	400000000001FF7C }
	{ Invalid; Invalid; Invalid }
	{ (p41) nop; cmp.eq	p10,p16,r67,r64; (p04) epc }
	{ cmpxchg2.acq	r0,[r0],r1; (p06) nop; (p22) shladd	r0,r0,0x3,r0 }
	{ Invalid; Invalid; Invalid }
	{ (p32) nop; invala; dep	r0,r32,r0,63,1 }
	{ Invalid; Invalid; Invalid }
	{ (p16) nop; nop; zxt1	r10,r64 }
	{ nop; Invalid; break.i	0x1000 }
	{ Invalid; (p06) nop; (p22) dep	r0,r0,r0,62,3 }

l400000000001FE10:
	{ addl	r52,556,r1; addl	r51,1,r0; adds	r50,0x0,r38; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,array_rshift; }
	{ adds	r1,0x128,r12; nop.m	0x0; adds	r50,0x0,r36; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C1C0; }
	{ adds	r1,0x128,r12; adds	r50,0x0,r36; cmp4.eq	p07,p06,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dptk.few	4000000000020D10 }

l400000000001FE70:
	{ adds	r51,0x0,r0; addl	r52,1,r0; br.call.sptk.many	b0,fn400000000001AA20; }
	{ adds	r1,0x128,r12; cmp.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r8; nop.i	0x0 }
	{ adds	r50,0x0,r36; addl	r52,80,r0; adds	r51,0xA0,r12; }
	{ ld8	r1,[r1]; (p06) br.cond.dpnt.few	400000000001FF60; br.call.sptk.many	b0,fn400000000001A600; }

l400000000001FEAC:
	{ (p59) nop; invala; cmp.eq	p00,p00,r32,r0 }
	{ (p04) cmpxchg2.acq	r0,[r97],r6; zxt1	r8,r64; nop }
	{ Invalid; Invalid; Invalid }
	{ (p43) cmp.lt	p01,p17,r64,r32; czx1.r	r0,r97; break.b	0x1000 }

l400000000001FEE0:
	{ cmp4.eq	p06,p07,0x0,r8; nop.i	0x0; (p06) br.cond.dpnt.few	400000000001FF20; }

l400000000001FEF0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,check_binary_file; }
	{ adds	r1,0x128,r12; nop.m	0x0; cmp4.eq	p06,p07,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p07) br.cond.spnt.few	4000000000020B50 }

l400000000001FF20:
	{ adds	r50,0x0,r36; nop.m	0x0; adds	r51,0x0,r0 }
	{ adds	r52,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AA20; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0 }

l400000000001FF60:
	{ adds	r50,0x0,r36; nop.m	0x0; addl	r51,1,r0 }
	{ addl	r52,-1,r0; nop.m	0x0; br.call.sptk.many	b0,move_to_high_fd; }
	{ adds	r1,0x128,r12; adds	r50,0x0,r8; addl	r51,2,r0 }
	{ addl	r52,1,r0; ld8	r1,[r1]; nop.i	0x0; }
	{ nop.m	0x0; addl	r14,5636,r1; nop.i	0x0; }
	{ st4	[r8],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B7E0; }
	{ adds	r1,0x128,r12; ld8	r1,[r1]; nop.i	0x0; }
	{ addl	r14,7364,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000020060; }

l4000000000020000:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000021300; }
	{ adds	r1,0x128,r12; nop.m	0x0; addl	r14,1,r0; }
	{ nop.m	0x0; ld8	r1,[r1]; nop.i	0x0; }
	{ addl	r15,6496,r1; st4	[r14],r15; addl	r15,6512,r1; }
	{ st4	[r14],r15; addl	r15,6680,r1; nop.i	0x0 }
	{ nop.m	0x0; st4	[r14],r15; nop.i	0x0 }

l4000000000020060:
	{ adds	r50,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r14,0xF4,r12; nop.m	0x0; adds	r1,0x128,r12; }
	{ ld4.acq	r15,[r14]; ld8	r1,[r1]; nop.i	0x0; }
	{ nop.m	0x0; adds	r15,0x1,r15; nop.i	0x0; }
	{ st4.rel	[r15],r14; nop.i	0x0; br.cond.sptk.few	400000000001F970 }

l40000000000200B0:
	{ nop.m	0x0; adds	r37,0x0,r0; br.cond.sptk.few	400000000001FCD0 }

l40000000000200C0:
	{ nop.m	0x0; adds	r38,0x0,r0; br.cond.sptk.few	400000000001FC50 }

l40000000000200D0:
	{ addl	r14,6468,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; addl	r14,6556,r1; (p07) br.cond.dpnt.few	4000000000020F80; }

l40000000000200F0:
	{ ld8	r50,[r14]; nop.m	0x0; addl	r14,23444,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld8	r51,[r14]; nop.i	0x0; br.call.sptk.many	b0,with_input_from_stream; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	400000000001F6F0 }
4000000000020140 10 00 00 00 01 00 E0 00 00 00 42 00 F0 EE FF 48 ..........B....H

l4000000000020150:
	{ adds	r50,0x0,r37; nop.m	0x0; addl	r51,1,r0 }
	{ adds	r52,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,array_rshift; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	400000000001FE10 }
4000000000020190 0B 70 00 46 00 10 00 00 00 02 00 C0 01 70 50 00 .p.F.........pP.
40000000000201A0 10 00 00 00 01 00 70 28 3B 0C F3 03 E0 05 00 43 ......p(;......C
40000000000201B0 09 70 A0 03 45 24 00 00 00 02 00 80 04 00 00 84 .p..E$..........
40000000000201C0 0B 00 00 00 01 00 00 00 38 20 23 00 00 00 04 00 ........8 #.....
40000000000201D0 0B 70 00 46 00 10 00 00 00 02 00 C0 01 70 50 00 .p.F.........pP.
40000000000201E0 10 00 00 00 01 00 70 28 3B 0C 73 03 80 E9 FF 4A ......p(;.s....J
40000000000201F0 10 00 00 00 01 00 00 00 00 02 00 00 80 F2 FF 48 ...............H
4000000000020200 09 98 B1 02 03 24 00 00 00 02 00 40 06 18 01 84 .....$.....@....
4000000000020210 11 98 01 66 18 10 00 00 00 02 00 00 38 A3 FF 58 ...f........8..X
4000000000020220 09 08 A0 18 02 21 00 00 00 02 00 C0 00 40 1C E6 .....!.......@..
4000000000020230 09 08 00 02 18 10 00 00 00 02 00 03 11 00 00 90 ................
4000000000020240 10 00 00 00 01 C0 81 00 00 00 42 00 80 E8 FF 48 ..........B....H
4000000000020250 10 00 00 00 01 00 30 02 00 00 42 00 50 ED FF 48 ......0...B.P..H

l4000000000020260:
	{ addl	r15,6520,r1; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p07) br.cond.dptk.few	40000000000202D0; }

l4000000000020280:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000202D0 }

l4000000000020290:
	{ addl	r14,6596,r1; nop.m	0x0; addl	r16,6592,r1; }
	{ ld4	r15,[r14]; ld4	r16,[r16]; nop.i	0x0; }
	{ adds	r15,0x1,r15; nop.m	0x0; cmp4.eq	p07,p06,0x0,r16; }
	{ st4	[r15],r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000020530 }

l40000000000202D0:
	{ addl	r14,6588,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	400000000001F070 }

l40000000000202F0:
	{ addl	r14,6596,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	400000000001F0D0 }

l4000000000020310:
	{ addl	r50,492,r1; nop.m	0x0; addl	r51,1,r0; }
	{ ld8	r50,[r50]; nop.i	0x0; br.call.sptk.many	b0,maybe_execute_file; }
	{ adds	r1,0x128,r12; nop.m	0x0; addl	r51,1,r0; }
	{ ld8	r1,[r1]; addl	r14,5652,r1; nop.i	0x0; }
	{ ld8	r50,[r14]; nop.i	0x0; br.call.sptk.many	b0,maybe_execute_file; }
	{ adds	r1,0x128,r12; nop.m	0x0; adds	r50,0x0,r35; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,set_job_control; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	400000000001F100; }

l40000000000203A0:
	{ addl	r15,6604,r1; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	4000000000020430 }

l40000000000203C0:
	{ addl	r15,6520,r1; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p07) br.cond.dptk.few	4000000000020430 }

l40000000000203E0:
	{ addl	r15,6456,r1; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	4000000000020280 }

l4000000000020400:
	{ adds	r50,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,set_job_control; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	400000000001F100; }

l4000000000020430:
	{ addl	r14,6456,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; addl	r14,6588,r1; (p07) br.cond.dpnt.few	400000000001F100; }

l4000000000020450:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; addl	r14,7344,r1; (p06) br.cond.dpnt.few	400000000001F100; }

l4000000000020470:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; addl	r14,6548,r1; (p06) br.cond.dpnt.few	400000000001F100; }

l4000000000020490:
	{ ld4	r15,[r14]; adds	r16,0x1,r15; cmp4.eq	p07,p06,0x0,r15; }
	{ st4	[r16],r14; nop.i	0x0; (p06) br.cond.dptk.few	400000000001F100 }

l40000000000204B0:
	{ nop.m	0x0; addl	r50,300,r1; nop.i	0x0; }
	{ ld8	r50,[r50]; nop.i	0x0; br.call.sptk.many	b0,get_string_value; }
	{ adds	r1,0x128,r12; nop.m	0x0; adds	r50,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn40000000000221C0; }
	{ adds	r1,0x128,r12; ld8	r1,[r1]; nop.i	0x0; }
	{ addl	r14,7404,r1; nop.m	0x0; nop.i	0x0; }
	{ ld4	r15,[r14]; add	r15,r37,r15; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.cond.sptk.few	400000000001F130 }

l4000000000020530:
	{ addl	r50,500,r1; nop.m	0x0; addl	r51,1,r0; }
	{ ld8	r50,[r50]; nop.i	0x0; br.call.sptk.many	b0,maybe_execute_file; }
	{ adds	r1,0x128,r12; ld8	r1,[r1]; nop.i	0x0; }
	{ addl	r14,6588,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000206F0 }

l4000000000020580:
	{ addl	r50,508,r1; nop.m	0x0; addl	r51,1,r0; }
	{ ld8	r50,[r50]; nop.i	0x0; br.call.sptk.many	b0,maybe_execute_file; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	40000000000202D0; }
40000000000205C0 09 00 00 00 01 00 20 23 07 06 48 00 00 00 04 00 ...... #..H.....
40000000000205D0 11 90 01 64 18 10 00 00 00 02 00 00 78 1F 04 50 ...d........x..P
40000000000205E0 09 08 A0 18 02 21 00 00 00 02 00 E0 00 40 18 E4 .....!.......@..
40000000000205F0 11 08 00 02 18 10 00 00 00 02 00 03 30 E9 FF 4A ............0..J
4000000000020600 0B 70 30 FA AF 27 E0 00 38 30 20 00 00 00 04 00 .p0..'..80 .....
4000000000020610 11 90 01 1C 18 10 00 00 00 02 00 00 B8 B5 FF 58 ...............X
4000000000020620 09 08 A0 18 02 21 00 00 00 02 00 40 06 40 00 84 .....!.....@.@..
4000000000020630 11 08 00 02 18 10 00 00 00 02 00 00 98 B2 10 50 ...............P
4000000000020640 09 08 A0 18 02 21 00 00 00 02 00 E0 00 40 18 E6 .....!.......@..
4000000000020650 10 08 00 02 18 10 00 00 00 02 00 03 D0 E8 FF 4A ...............J
4000000000020660 11 00 00 00 01 00 00 00 00 02 00 00 F0 E8 FF 48 ...............H

l4000000000020670:
	{ nop.m	0x0; addl	r50,292,r1; nop.i	0x0; }
	{ ld8	r50,[r50]; nop.i	0x0; br.call.sptk.many	b0,get_string_value; }
	{ adds	r1,0x128,r12; nop.m	0x0; adds	r50,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn40000000000221C0; }
	{ adds	r1,0x128,r12; nop.m	0x0; adds	r50,0x0,r35; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,set_job_control; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	400000000001F100; }

l40000000000206F0:
	{ addl	r50,516,r1; nop.m	0x0; addl	r51,1,r0; }
	{ ld8	r50,[r50]; nop.i	0x0; br.call.sptk.many	b0,maybe_execute_file; }
	{ adds	r1,0x128,r12; nop.m	0x0; cmp4.eq	p07,p06,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dptk.few	40000000000202D0; }

l4000000000020730:
	{ addl	r50,524,r1; nop.m	0x0; addl	r51,1,r0; }
	{ ld8	r50,[r50]; nop.i	0x0; br.call.sptk.many	b0,maybe_execute_file; }
	{ adds	r1,0x128,r12; nop.m	0x0; cmp4.eq	p06,p07,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p07) br.cond.dptk.few	40000000000202D0 }

l4000000000020770:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000020580; }
4000000000020780 09 98 B1 02 03 24 20 03 8C 00 42 80 56 00 00 90 .....$ ...B.V...
4000000000020790 11 98 01 66 18 10 00 00 00 02 00 00 98 B8 FF 58 ...f...........X
40000000000207A0 09 08 A0 18 02 21 00 00 00 02 00 C0 00 40 1C E6 .....!.......@..
40000000000207B0 11 08 00 02 18 10 00 00 00 02 80 03 00 FA FF 4A ...............J
40000000000207C0 09 70 A0 03 45 24 F0 08 00 00 48 80 14 00 00 90 .p..E$....H.....
40000000000207D0 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000207E0 10 00 3C 1C 90 11 00 00 00 02 00 00 70 EC FF 48 ..<.........p..H
40000000000207F0 09 70 10 03 32 24 00 00 00 02 00 E0 00 40 18 E4 .p..2$.......@..
4000000000020800 09 00 00 00 01 00 40 02 38 20 20 00 00 00 04 00 ......@.8  .....
4000000000020810 11 00 90 1C 90 D1 41 02 00 00 C2 03 50 E3 FF 4B ......A.....P..K
4000000000020820 0B 70 00 4A 00 10 00 00 00 02 00 C0 01 70 50 00 .p.J.........pP.
4000000000020830 10 00 00 00 01 00 70 A0 3B 0C 73 03 E0 E2 FF 4A ......p.;.s....J
4000000000020840 10 00 00 00 01 00 00 00 00 02 00 00 A0 EB FF 48 ...............H
4000000000020850 09 98 D1 02 03 24 00 00 00 02 00 40 06 18 01 84 .....$.....@....
4000000000020860 11 98 01 66 18 10 00 00 00 02 00 00 E8 9C FF 58 ...f...........X
4000000000020870 09 08 A0 18 02 21 60 00 20 0E 73 E0 11 00 00 90 .....!`. .s.....
4000000000020880 03 08 00 02 18 90 41 0A 90 5C 40 C3 41 0C C8 90 ......A..\@.A...
4000000000020890 C9 00 90 1C 90 11 E0 40 07 8A 48 80 14 00 00 90 .......@..H.....
40000000000208A0 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000208B0 10 00 3C 1C 90 11 00 00 00 02 00 00 A0 EB FF 48 ..<............H
40000000000208C0 09 90 B1 03 03 24 00 00 00 02 00 60 16 00 00 90 .....$.....`....
40000000000208D0 11 90 01 64 18 10 00 00 00 02 00 00 F8 52 0D 50 ...d.........R.P
40000000000208E0 09 08 A0 18 02 21 00 00 00 02 00 60 16 00 00 90 .....!.....`....
40000000000208F0 0B 08 00 02 18 10 E0 A0 04 58 48 00 00 00 04 00 .........XH.....
4000000000020900 11 90 01 1C 18 10 00 00 00 02 00 00 C8 52 0D 50 .............R.P
4000000000020910 0B 08 A0 18 02 21 10 00 04 30 20 00 00 00 04 00 .....!...0 .....
4000000000020920 0B 70 B0 03 39 24 00 00 00 02 00 00 00 00 04 00 .p..9$..........
4000000000020930 0B 78 00 1C 10 10 F0 28 3D 00 40 00 00 00 04 00 .x.....(=.@.....
4000000000020940 10 00 3C 1C 90 11 00 00 00 02 00 00 F0 E7 FF 48 ..<............H

l4000000000020950:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000021B40; }
	{ adds	r1,0x128,r12; ld8	r1,[r1]; nop.i	0x0; }
	{ addl	r14,6512,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000001F7D0 }

l4000000000020990:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000001F810 }

l40000000000209A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,load_history; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,get_tty_state; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	400000000001F8F0; }

l40000000000209F0:
	{ addl	r51,380,r1; nop.m	0x0; addl	r52,5,r0 }
	{ adds	r50,0x0,r0; nop.m	0x0; sxt4	r40,r40; }
	{ ld8	r51,[r51]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r18,0x100,r12; adds	r1,0x128,r12; adds	r50,0x0,r8; }
	{ ld8	r18,[r18]; ld8	r1,[r1]; nop.i	0x0; }
	{ nop.m	0x0; shladd	r40,r40,0x3,r18; nop.i	0x0; }
	{ ld8	r51,[r40]; nop.i	0x0; br.call.sptk.many	b0,report_error; }

l4000000000020A60:
	{ adds	r1,0x128,r12; nop.m	0x0; adds	r51,0x0,r0; }
	{ ld8	r1,[r1]; addl	r14,-10652,r1; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r50,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn40000000000213C0; }
	{ adds	r1,0x128,r12; nop.m	0x0; addl	r50,2,r0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B580; }
	{ addl	r50,500,r1; nop.m	0x0; addl	r51,1,r0; }
	{ ld8	r50,[r50]; nop.i	0x0; br.call.sptk.many	b0,maybe_execute_file; }
	{ adds	r1,0x128,r12; ld8	r1,[r1]; nop.i	0x0; }
	{ addl	r14,6588,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000020BB0 }

l4000000000020B10:
	{ addl	r50,508,r1; nop.m	0x0; addl	r51,1,r0; }
	{ ld8	r50,[r50]; nop.i	0x0; br.call.sptk.many	b0,maybe_execute_file; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	400000000001F020; }

l4000000000020B50:
	{ addl	r51,572,r1; addl	r52,5,r0; adds	r50,0x0,r0; }
	{ ld8	r51,[r51]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x128,r12; adds	r50,0x0,r8; adds	r51,0x0,r35; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,internal_error; }
	{ adds	r1,0x128,r12; nop.m	0x0; addl	r50,126,r0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B580; }

l4000000000020BB0:
	{ addl	r50,516,r1; nop.m	0x0; addl	r51,1,r0; }
	{ ld8	r50,[r50]; nop.i	0x0; br.call.sptk.many	b0,maybe_execute_file; }
	{ adds	r1,0x128,r12; nop.m	0x0; cmp4.eq	p07,p06,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dptk.few	400000000001F020; }

l4000000000020BF0:
	{ addl	r50,524,r1; nop.m	0x0; addl	r51,1,r0; }
	{ ld8	r50,[r50]; nop.i	0x0; br.call.sptk.many	b0,maybe_execute_file; }
	{ adds	r1,0x128,r12; nop.m	0x0; cmp4.eq	p06,p07,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p07) br.cond.dptk.few	400000000001F020 }

l4000000000020C30:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000020B10 }

l4000000000020C40:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ adds	r1,0x128,r12; adds	r37,0x0,r8; addl	r50,1,r0 }
	{ ld4	r38,[r8]; adds	r51,0x0,r36; adds	r52,0x10,r12; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B3C0; }
	{ adds	r14,0x28,r12; adds	r1,0x128,r12; cmp4.eq	p07,p06,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000020CD0; }

l4000000000020CA0:
	{ ld4	r15,[r14]; nop.m	0x0; addl	r14,61440,r0; }
	{ and	r15,r14,r15; nop.m	0x0; addl	r14,16384,r0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r15; (p07) br.cond.dpnt.few	4000000000020E20 }

l4000000000020CD0:
	{ st4	[r38],r37; adds	r50,0x0,r35; br.call.sptk.many	b0,file_error; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0 }

l4000000000020D00:
	{ nop.m	0x0; addl	r50,126,r0; br.call.sptk.many	b0,fn400000000001B580; }

l4000000000020D10:
	{ addl	r37,5636,r1; nop.m	0x0; addl	r51,1,r0 }
	{ addl	r52,-1,r0; nop.m	0x0; br.call.sptk.many	b0,move_to_high_fd; }
	{ adds	r1,0x128,r12; adds	r36,0x0,r8; adds	r50,0x0,r8 }
	{ st4	[r8],r37; addl	r51,2,r0; addl	r52,1,r0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B7E0; }
	{ adds	r1,0x128,r12; ld8	r1,[r1]; nop.i	0x0; }
	{ addl	r14,6512,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	4000000000020060 }

l4000000000020D90:
	{ adds	r51,0x0,r0; adds	r50,0x0,r36; br.call.sptk.many	b0,fn400000000001AE60; }
	{ adds	r1,0x128,r12; nop.m	0x0; adds	r50,0x0,r36; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C340; }
	{ adds	r1,0x128,r12; adds	r50,0x0,r35; nop.i	0x0 }
	{ ld8	r1,[r1]; st4	[r0],r37; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r14,0xF4,r12; nop.m	0x0; adds	r1,0x128,r12; }
	{ ld4.acq	r15,[r14]; ld8	r1,[r1]; nop.i	0x0; }
	{ nop.m	0x0; adds	r15,0x1,r15; nop.i	0x0; }
	{ st4.rel	[r15],r14; nop.i	0x0; br.cond.sptk.few	400000000001F970 }

l4000000000020E20:
	{ addl	r51,564,r1; addl	r52,5,r0; adds	r50,0x0,r0; }
	{ ld8	r51,[r51]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x128,r12; adds	r50,0x0,r8; adds	r51,0x0,r35; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,internal_error; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	4000000000020D00 }

l4000000000020E80:
	{ adds	r50,0x0,r37; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x128,r12; nop.m	0x0; adds	r50,0x1,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x128,r12; adds	r50,0x0,r8; adds	r51,0x0,r37; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	400000000001FB60 }

l4000000000020EF0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ adds	r1,0x128,r12; ld4	r14,[r8]; adds	r39,0x0,r8; }
	{ ld8	r1,[r1]; cmp4.eq	p07,p06,0x2,r14; (p07) br.cond.dpnt.few	4000000000020FB0 }

l4000000000020F20:
	{ adds	r38,0x0,r35; nop.m	0x0; nop.i	0x0; }

l4000000000020F30:
	{ nop.m	0x0; adds	r50,0x0,r38; nop.i	0x0 }
	{ ld4	r35,[r39]; nop.m	0x0; br.call.sptk.many	b0,file_error; }
	{ cmp4.eq	p07,p06,0x2,r35; nop.m	0x0; adds	r1,0x128,r12; }
	{ ld8	r1,[r1]; nop.m	0x0; (p06) addl	r50,126,r0; }

l4000000000020F70:
	{ nop.m	0x0; (p07) addl	r50,127,r0; br.call.sptk.many	b0,fn400000000001B580; }

l4000000000020F7C:
	{ Invalid; break.m	0x1000; break.b	0x1000 }

l4000000000020F80:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,with_input_from_stdin; }
	{ nop.m	0x0; adds	r1,0x128,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	400000000001F6F0 }

l4000000000020FB0:
	{ adds	r50,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,absolute_program; }
	{ adds	r1,0x128,r12; nop.m	0x0; cmp4.eq	p07,p06,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dptk.few	4000000000020F20 }

l4000000000020FE0:
	{ ld4	r36,[r39]; adds	r50,0x0,r37; br.call.sptk.many	b0,find_path_file; }
	{ adds	r1,0x128,r12; nop.m	0x0; cmp.eq	p06,p07,0x0,r8 }
	{ adds	r38,0x0,r8; nop.m	0x0; adds	r50,0x0,r35; }
	{ ld8	r1,[r1]; (p06) br.cond.dpnt.few	4000000000021080; br.call.sptk.many	b0,fn400000000001A7E0; }

l400000000002101C:
	{ (p62) nop; ld4	r10,[r64]; nop }
	{ Invalid; Invalid; Invalid }
	{ (p37) cmp.lt.unc	p52,p09,r63,r44; nop; Invalid }
	{ nop; (p04) nop }

l400000000002105C:
	{ nop; Invalid; mov	pr,r32,0x0 }
	{ (p54) invala; break.i	0x1000; break.b	0x1000 }

l4000000000021070:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000001FA90 }

l4000000000021080:
	{ st4	[r36],r39; nop.i	0x0; br.cond.sptk.few	4000000000020F20; }

l4000000000021090:
	{ nop.m	0x0; ld8	r35,[r16]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r35; br.cond.sptk.few	400000000001D200; }
40000000000210B0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; _start: 40000000000210C0
_start proc
	{ alloc	r2,ar.pfs,0x7,0x0,0x0; movl	r3,0x9804C0270033F }
	{ adds	r34,0x10,r12; movl	r1,0x8000000000018564; }
	{ ld8	r33,[r34],8; mov.m	r10,BSP; mov	r9,ip; }
	{ mov.m	FPSR,r3; sub	r1,r9,r1; adds	r38,0x10,r12; }
	{ addl	r11,-9772,r1; addl	r32,-9676,r1; addl	r35,-9732,r1; }
	{ ld8	r3,[r11]; ld8	r32,[r32]; addl	r36,-10044,r1; }
	{ ld8	r35,[r35]; ld8	r36,[r36]; nop.i	0x0 }
	{ st8	[r10],r3; adds	r37,0x0,r8; br.call.sptk.few	b0,fn400000000001B6E0 }
	{ break.m	0x0; nop.i	0x0; nop.b	0x0; }
	{ nop.m	0x6; nop.i	0x7; nop.i	0x8 }
	{ nop.m	0x6; nop.i	0x7; nop.i	0x8 }
	{ nop.m	0x6; nop.i	0x7; nop.i	0x8 }
	{ alloc	r33,ar.pfs,0x3,0x0,0x3; addl	r14,-10436,r1; mov	r32,b0 }
	{ adds	r34,0x0,r1; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.spnt.few	40000000000211D0; }

l40000000000211B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B4C0; }
	{ adds	r1,0x0,r34; nop.m	0x0; nop.i	0x0 }

l40000000000211D0:
	{ nop.m	0x0; mov.i	ar.pfs,r33; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r32,40000000000211E0; br.ret	b0; }
40000000000211F0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
4000000000021200 00 18 15 08 80 05 00 62 07 56 48 20 04 00 C4 00 .......b.VH ....
4000000000021210 10 10 01 02 00 21 00 00 00 02 00 00 38 00 00 40 .....!......8..@
4000000000021220 09 00 3C 40 98 11 10 41 40 30 28 00 00 00 04 00 ..<@...A@0(.....
4000000000021230 10 08 00 20 18 10 60 88 04 80 03 00 68 00 80 10 ... ..`.....h...
4000000000021240 0B 78 00 40 18 10 00 79 88 00 40 E0 81 78 00 84 .x.@...y..@..x..
4000000000021250 01 80 00 20 18 10 00 08 05 80 03 00 30 02 AA 00 ... ........0...
4000000000021260 13 00 00 20 06 B8 01 E0 FF 7F 24 80 08 00 84 00 ... ......$.....
4000000000021270 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000021280 05 08 11 06 80 C5 FF FF FF FF 7F 60 C4 F3 D7 6C ...........`...l
4000000000021290 01 70 70 FA B0 27 30 1A 05 00 40 00 04 00 C4 00 .pp..'0...@.....
40000000000212A0 09 70 00 1C 18 10 F0 00 8C 30 20 00 00 00 18 E0 .p.......0 .....
40000000000212B0 10 30 00 1C 40 34 60 00 3C 80 68 83 08 00 84 00 .0..@4`.<.h.....
40000000000212C0 0A 78 20 1C 18 14 00 00 00 02 00 C0 F0 08 00 07 .x .............
40000000000212D0 19 10 01 02 00 21 10 00 38 30 20 00 68 00 80 10 .....!..80 .h...
40000000000212E0 00 08 00 44 00 21 00 00 05 80 03 00 10 02 AA 00 ...D.!..........
40000000000212F0 11 00 00 00 01 00 00 00 00 02 00 80 08 00 84 00 ................

;; fn4000000000021300: 4000000000021300
;;   Called from:
;;     400000000002000C (in main)
fn4000000000021300 proc
	{ alloc	r33,ar.pfs,0x4,0x0,0x3; mov	r32,b0; adds	r34,0x0,r1; }
	{ adds	r35,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,bash_history_reinit; }
	{ adds	r1,0x0,r34; nop.m	0x0; adds	r35,0x0,r0; }
	{ addl	r14,6456,r1; ld4	r15,[r14]; addl	r14,6516,r1; }
	{ st4	[r0],r14; nop.m	0x0; addl	r14,6496,r1; }
	{ st4	[r0],r14; nop.m	0x0; addl	r14,6512,r1; }
	{ st4	[r0],r14; nop.m	0x0; addl	r14,6680,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r15],r14; addl	r14,6468,r1; addl	r15,1,r0; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,set_job_control; }
	{ adds	r1,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ nop.m	0x0; mov.spnt	b0,r32,40000000000213B0; br.ret	b0; }

;; fn40000000000213C0: 40000000000213C0
;;   Called from:
;;     400000000001E8BC (in main)
;;     4000000000020A9C (in main)
fn40000000000213C0 proc
	{ alloc	r40,ar.pfs,0xF,0x0,0xA; cmp4.eq	p06,p07,0x0,r33; mov	r39,b7 }
	{ addl	r43,228,r1; adds	r41,0x0,r1; addl	r38,6476,r1; }
	{ (p07) adds	r33,0x0,r0; nop.m	0x0; adds	r42,0x0,r0 }

l40000000000213E6:
	{ break.m	0x4000; (p21) nop; nop }
	{ chk.a.nc	f0,3FFFFFFFFF021BF6; nop; add	r0,r0,r32 }

l4000000000021400:
	{ nop.m	0x0; (p06) adds	r33,0x1,r0; nop.i	0x0 }

l400000000002140C:
	{ ldfpd	f0,f1,[r0]; Invalid; break.i	0x1000 }
	{ (p58) nop; nop; (p05) nop }
	{ cmpxchg2.acq	r41,[r66],r0; (p05) nop; (p21) shladd	r0,r0,0x3,r0 }
	{ cmp.lt	p08,p17,r0,r66; break.x	0x10802D00A01000; }
	{ (p32) nop; shladd	r32,r10,0x1,r64; (p21) dep	r1,r0,r0,62,3 }
	{ nop; (p05) nop; }
	{ ldfps	f0,f1,[r0]; Invalid; break.i	0x1000 }
	{ (p55) nop; invala; br.cond.sptk.few	400000000002167C }
	{ ldfpd	f8,f0,[r66]; break.x	0x10802000A01000; }
	{ (p46) nop; nop; Invalid }
	{ (p58) nop; (p05) dep	r32,r11,r6,63,9; Invalid; }
	{ addp4	r0,r1,r0; zxt4	r43,r0; dep	r0,r32,r0,63,1 }

l40000000000214C0:
	{ addl	r44,172,r1; nop.m	0x0; adds	r34,0x20,r34 }
	{ adds	r42,0x0,r32; nop.m	0x0; addl	r43,1,r0; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ adds	r14,0xFFFFFFFFFFFFFFE0,r34; nop.m	0x0; adds	r1,0x0,r41; }
	{ nop.m	0x0; ld8	r45,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r45; (p06) br.cond.dptk.few	40000000000214C0 }

l4000000000021520:
	{ addl	r43,180,r1; addl	r35,6164,r1; addl	r44,5,r0 }
	{ adds	r42,0x0,r0; addl	r34,48,r0; adds	r36,0x0,r0; }
	{ ld8	r43,[r43]; nop.m	0x0; adds	r37,0x0,r0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r42,0x0,r8 }
	{ adds	r43,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C260; }
	{ adds	r1,0x0,r41; addl	r44,5,r0; adds	r42,0x0,r0; }
	{ nop.m	0x0; addl	r43,188,r1; nop.i	0x0; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r42,0x0,r8 }
	{ adds	r43,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C260; }
	{ ld8	r15,[r35]; nop.m	0x0; adds	r1,0x0,r41; }
	{ nop.m	0x0; ld8	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	4000000000021790; }

l4000000000021600:
	{ ld1	r16,[r14]; nop.m	0x0; sxt1	r16,r16; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x73,r16; (p07) br.cond.dpnt.few	40000000000217C0 }

l4000000000021620:
	{ ld8	r15,[r35]; adds	r14,0x30,r34; adds	r36,0x0,r34; }
	{ add	r15,r15,r34; nop.m	0x0; adds	r34,0x0,r14; }
	{ nop.m	0x0; ld8	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000021600; }

l4000000000021660:
	{ cmp.eq	p06,p07,0x0,r37; nop.m	0x0; adds	r42,0x0,r37 }
	{ addl	r43,91,r0; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000021790; }

l4000000000021680:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B680; }
	{ cmp.eq	p06,p07,0x0,r8; nop.m	0x0; adds	r1,0x0,r41; }
	{ (p06) adds	r8,0x0,r37; nop.i	0x0; adds	r14,0x1,r8; }

l40000000000216A6:
	{ break.m	0x4000; (p07) nop; break.i	0x80000 }
	{ break.m	0x4000; nop; (p48) nop }

l40000000000216C0:
	{ ld1	r15,[r14]; adds	r34,0x0,r14; adds	r14,0x1,r14; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2D,r15; (p06) br.cond.dptk.few	40000000000216C0 }

l40000000000216F0:
	{ adds	r42,0x0,r34; addl	r43,93,r0; br.call.sptk.many	b0,fn400000000001B680; }
	{ adds	r1,0x0,r41; nop.m	0x0; cmp.eq	p06,p07,0x0,r8 }
	{ addl	r44,5,r0; nop.m	0x0; adds	r42,0x0,r0; }
	{ addl	r43,196,r1; (p07) st1	[r0],r8; nop.i	0x0; }

l400000000002172C:
	{ ldfps	f0,f1,[r0]; Invalid; break.i	0x1000 }
	{ (p33) nop; ld4	r32,[r64]; nop }
	{ Invalid; Invalid; Invalid }
	{ (p07) nop; nop; br.cond.sptk.few	40000000004417FC }
	{ nop; break.x	0x8000001000; }
	{ (p03) nop; invala; break.b	0x1000 }
	{ Invalid; cmp.eq	p00,p00,r32,r0; mov	pr,r72,0x5040 }

l4000000000021790:
	{ nop.m	0x0; tbit.z	p07,p06,r33,0x0; (p07) br.cond.dpnt.few	40000000000218D0; }

l40000000000217A0:
	{ nop.m	0x0; mov.i	ar.pfs,r40; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000217B0; br.ret	b0 }

l40000000000217C0:
	{ adds	r16,0x1,r14; nop.m	0x0; adds	r17,0x2,r14; }
	{ nop.m	0x0; ld1	r16,[r16]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x65,r16; (p06) br.cond.dptk.few	4000000000021620 }

l40000000000217F0:
	{ ld1	r16,[r17]; adds	r15,0x20,r15; adds	r14,0x3,r14; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x74,r16; (p06) br.cond.dptk.few	4000000000021620 }

l4000000000021810:
	{ nop.m	0x0; ld1	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r14; nop.i	0x0; (p06) br.cond.spnt.few	4000000000021620; }

l4000000000021830:
	{ ld8	r42,[r15]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r41; adds	r42,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r14,[r35]; adds	r1,0x0,r41; adds	r42,0x0,r8; }
	{ add	r14,r14,r36; adds	r36,0x0,r34; adds	r14,0x20,r14; }
	{ ld8	r43,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ ld8	r15,[r35]; adds	r14,0x30,r34; adds	r1,0x0,r41 }
	{ adds	r37,0x0,r8; add	r15,r15,r34; adds	r34,0x0,r14; }
	{ nop.m	0x0; ld8	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000021600 }

l40000000000218C0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000021660 }

l40000000000218D0:
	{ addl	r43,204,r1; addl	r44,5,r0; adds	r42,0x0,r0; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ ld8	r45,[r38]; adds	r1,0x0,r41; adds	r42,0x0,r32 }
	{ addl	r43,1,r0; adds	r44,0x0,r8; br.call.sptk.many	b0,fn400000000001C040; }
	{ adds	r1,0x0,r41; addl	r44,5,r0; adds	r42,0x0,r0; }
	{ nop.m	0x0; addl	r43,212,r1; nop.i	0x0; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ ld8	r45,[r38]; adds	r1,0x0,r41; adds	r42,0x0,r32 }
	{ addl	r43,1,r0; adds	r44,0x0,r8; br.call.sptk.many	b0,fn400000000001C040; }
	{ adds	r1,0x0,r41; addl	r44,5,r0; adds	r42,0x0,r0; }
	{ nop.m	0x0; addl	r43,220,r1; nop.i	0x0; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r41; adds	r42,0x0,r32; nop.i	0x0 }
	{ addl	r43,1,r0; adds	r44,0x0,r8; br.call.sptk.many	b0,fn400000000001C040; }
	{ adds	r1,0x0,r41; nop.m	0x0; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000219C0; br.ret	b0 }

l40000000000219D0:
	{ addl	r43,156,r1; addl	r44,5,r0; adds	r42,0x0,r0; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r41; adds	r34,0x0,r8; br.call.sptk.many	b0,shell_version_string; }
	{ adds	r1,0x0,r41; adds	r42,0x0,r32; adds	r44,0x0,r34 }
	{ adds	r45,0x0,r8; addl	r43,1,r0; addl	r46,164,r1; }
	{ ld8	r46,[r46]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ adds	r1,0x0,r41; adds	r42,0x0,r0; addl	r44,5,r0; }
	{ addl	r43,228,r1; nop.m	0x0; addl	r38,6476,r1; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ nop.m	0x0; ld8	r45,[r38]; adds	r1,0x0,r41 }
	{ adds	r42,0x0,r32; addl	r43,1,r0; adds	r44,0x0,r8; }
	{ adds	r46,0x0,r45; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ adds	r1,0x0,r41; addl	r44,5,r0; adds	r42,0x0,r0; }
	{ nop.m	0x0; addl	r43,236,r1; nop.i	0x0; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r42,0x0,r8 }
	{ adds	r43,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C260; }
	{ nop.m	0x0; adds	r1,0x0,r41; nop.i	0x0; }
	{ addl	r45,148,r1; addl	r14,5620,r1; nop.i	0x0 }
	{ ld8	r45,[r45]; ld8	r34,[r14]; br.cond.sptk.few	40000000000214C0; }
4000000000021B10 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000021B20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000021B30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000021B40: 4000000000021B40
;;   Called from:
;;     400000000001ED3C (in main)
;;     400000000002095C (in main)
fn4000000000021B40 proc
	{ alloc	r35,ar.pfs,0x7,0x0,0x5; addl	r32,7404,r1; nop.b	0x0 }
	{ addl	r37,244,r1; mov	r34,b2; adds	r36,0x0,r1; }
	{ nop.m	0x0; nop.m	0x0; addl	r38,1,r0 }
	{ ld8	r37,[r37]; ld4	r33,[r32]; nop.i	0x0 }
	{ st4	[r0],r32; nop.m	0x0; br.call.sptk.many	b0,maybe_execute_file; }
	{ adds	r1,0x0,r36; ld4	r14,[r32]; nop.b	0x0 }
	{ addl	r16,1,r0; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ addl	r15,7340,r1; add	r14,r14,r33; mov.spnt	b0,r34,4000000000021BB0; }
	{ nop.m	0x0; st4	[r14],r32; nop.i	0x0; }
	{ st4	[r16],r15; nop.i	0x0; br.ret	b0; }
4000000000021BE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000021BF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000021C00: 4000000000021C00
;;   Called from:
;;     400000000001E12C (in main)
;;     400000000001ED7C (in main)
fn4000000000021C00 proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x4; adds	r16,0x8,r12; nop.b	0x0 }
	{ adds	r12,0xFFFFFFFFFFFFFFE0,r12; addl	r36,25252,r1; mov	r34,b2; }
	{ adds	r14,0x10,r12; st8.spill	[r1],r16; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; addl	r37,1,r0; }
	{ st8	[r32],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BD60; }
	{ adds	r1,0x28,r12; adds	r33,0x0,r8; cmp4.eq	p06,p07,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dptk.few	4000000000021D10 }

l4000000000021C70:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,unlink_fifo_list; }
	{ cmp4.eq	p06,p07,0x2,r33; nop.m	0x0; adds	r1,0x28,r12; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000021E30; }

l4000000000021CA0:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x2,r33; (p07) br.cond.dptk.few	4000000000021DE0; }

l4000000000021CB0:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x4,r33; (p07) br.cond.dptk.few	4000000000021E70 }

l4000000000021CC0:
	{ addl	r36,252,r1; nop.m	0x0; addl	r37,3,r0 }
	{ adds	r38,0x0,r33; nop.m	0x0; adds	r39,0x0,r0; }
	{ ld8	r36,[r36]; nop.i	0x0; br.call.sptk.many	b0,command_error; }
	{ nop.m	0x0; adds	r1,0x28,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0 }

l4000000000021D10:
	{ nop.m	0x0; adds	r14,0x10,r12; nop.i	0x0; }
	{ ld8	r36,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x28,r12; nop.m	0x0; adds	r36,0x1,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r14,0x10,r12; adds	r1,0x28,r12; adds	r36,0x0,r8; }
	{ nop.m	0x0; ld8	r37,[r14]; nop.i	0x0 }
	{ ld8	r1,[r1]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x28,r12; adds	r36,0x0,r8; addl	r38,4,r0; }
	{ ld8	r1,[r1]; addl	r37,260,r1; nop.i	0x0; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,parse_and_execute; }
	{ nop.m	0x0; adds	r1,0x28,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; mov.i	ar.pfs,r35; mov.spnt	b0,r34,4000000000021DC0 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0 }

l4000000000021DE0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x1,r33; (p07) br.cond.dptk.few	4000000000021CC0 }

l4000000000021DF0:
	{ addl	r14,9044,r1; addl	r15,127,r0; addl	r8,127,r0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r15],r14; mov.i	ar.pfs,r35; mov.spnt	b0,r34,4000000000021E10 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0 }

l4000000000021E30:
	{ addl	r14,9044,r1; addl	r15,1,r0; addl	r8,1,r0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r15],r14; mov.i	ar.pfs,r35; mov.spnt	b0,r34,4000000000021E50 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0 }

l4000000000021E70:
	{ addl	r14,9044,r1; nop.m	0x0; nop.i	0x0; }
	{ ld4	r8,[r14]; mov.i	ar.pfs,r35; mov.spnt	b0,r34,4000000000021E80 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0; }
4000000000021EA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000021EB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000021EC0: 4000000000021EC0
;;   Called from:
;;     400000000001E0BC (in main)
;;     400000000001F72C (in main)
fn4000000000021EC0 proc
	{ alloc	r40,ar.pfs,0xC,0x0,0xA; sub	r37,r34,r33,0x1; sxt4	r14,r33 }
	{ adds	r15,0x8,r32; cmp4.lt	p07,p06,r33,r34; adds	r41,0x0,r1; }
	{ addp4	r37,r37,r0; adds	r36,0x0,r0; nop.b	0x0 }
	{ shladd	r32,r14,0x3,r32; mov	r39,b7; (p06) adds	r34,0x0,r33; }

l4000000000021F00:
	{ nop.m	0x0; add	r37,r14,r37; (p06) br.cond.dpnt.few	4000000000022150; }

l4000000000021F10:
	{ shladd	r37,r37,0x3,r15; nop.m	0x0; nop.i	0x0; }

l4000000000021F20:
	{ ld8	r42,[r32],8; nop.i	0x0; br.call.sptk.many	b0,make_word; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r43,0x0,r36 }
	{ adds	r42,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,make_word_list; }
	{ nop.m	0x0; adds	r1,0x0,r41; adds	r36,0x0,r8 }
	{ nop.m	0x0; cmp.eq	p07,p06,r37,r32; (p06) br.cond.dptk.few	4000000000021F20; }

l4000000000021F70:
	{ cmp.eq	p06,p07,0x0,r8; nop.m	0x0; addl	r38,23444,r1 }
	{ adds	r42,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000022150; }

l4000000000021F90:
	{ ld8	r14,[r8]; nop.m	0x0; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000021FD0; }

l4000000000021FB0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,list_reverse; }
	{ nop.m	0x0; adds	r1,0x0,r41; adds	r36,0x0,r8; }

l4000000000021FD0:
	{ nop.m	0x0; adds	r37,0x8,r36; addl	r43,1,r0 }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	4000000000022170; }

l4000000000021FF0:
	{ nop.m	0x0; ld8	r14,[r37]; nop.i	0x0; }
	{ ld8	r42,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r41; adds	r42,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r14,[r37]; adds	r1,0x0,r41; adds	r42,0x0,r8; }
	{ ld8	r43,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r41; ld8	r42,[r38]; nop.i	0x0; }
	{ addl	r14,6476,r1; nop.m	0x0; cmp.eq	p06,p07,0x0,r42; }
	{ nop.m	0x0; st8	[r8],r14; nop.i	0x0 }
	{ nop.b	0x0; (p06) br.cond.dpnt.few	4000000000022090; br.call.sptk.many	b0,fn400000000001A7E0; }

l400000000002207C:
	{ (p59) nop; invala; break.b	0x1000 }
	{ nop; cmp.lt	p00,p00,r32,r0; Invalid }

l4000000000022090:
	{ nop.m	0x0; ld8	r14,[r37]; nop.i	0x0; }
	{ ld8	r42,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r41; adds	r42,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r14,[r37]; adds	r1,0x0,r41; adds	r42,0x0,r8; }
	{ ld8	r43,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ addl	r43,1,r0; st8	[r8],r38; adds	r1,0x0,r41; }
	{ ld8	r42,[r36]; nop.i	0x0; br.call.sptk.many	b0,remember_args; }
	{ nop.m	0x0; adds	r1,0x0,r41; nop.i	0x0 }
	{ ld8	r42,[r36]; nop.m	0x0; br.call.sptk.many	b0,push_args; }
	{ nop.m	0x0; adds	r1,0x0,r41; adds	r42,0x0,r36 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,dispose_words; }
	{ adds	r1,0x0,r41; nop.m	0x0; nop.i	0x0 }

l4000000000022150:
	{ adds	r8,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.spnt	b0,r39,4000000000022160; br.ret	b0; }

l4000000000022170:
	{ adds	r42,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,remember_args; }
	{ adds	r1,0x0,r41; adds	r42,0x0,r36; br.call.sptk.many	b0,push_args; }
	{ adds	r1,0x0,r41; adds	r42,0x0,r36; br.call.sptk.many	b0,dispose_words; }
	{ nop.m	0x0; adds	r1,0x0,r41; br.cond.sptk.few	4000000000022150; }
40000000000221B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000221C0: 40000000000221C0
;;   Called from:
;;     40000000000204EC (in main)
;;     40000000000206AC (in main)
fn40000000000221C0 proc
	{ alloc	r35,ar.pfs,0x7,0x0,0x5; mov	r34,b2; nop.i	0x0 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r36,0x0,r1; (p06) br.cond.dpnt.few	4000000000022200; }

l40000000000221E0:
	{ ld1	r14,[r32]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	4000000000022220 }

l4000000000022200:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000022210; br.ret	b0; }

l4000000000022220:
	{ adds	r37,0x0,r32; addl	r38,1,r0; br.call.sptk.many	b0,expand_string_unsplit_to_string; }
	{ adds	r1,0x0,r36; nop.m	0x0; cmp.eq	p06,p07,0x0,r8 }
	{ adds	r33,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000022200; }

l4000000000022250:
	{ ld1	r14,[r8]; adds	r37,0x0,r33; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000222B0; }

l4000000000022270:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r36; nop.m	0x0; nop.i	0x0 }

l4000000000022290:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000222A0; br.ret	b0; }

l40000000000222B0:
	{ addl	r38,1,r0; adds	r37,0x0,r8; br.call.sptk.many	b0,maybe_execute_file; }
	{ adds	r1,0x0,r36; adds	r37,0x0,r33; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r36; br.cond.sptk.few	4000000000022290; }
40000000000222E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000222F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; exit_shell: 4000000000022300
;;   Called from:
;;     400000000001E16C (in main)
;;     4000000000070E9C (in report_error)
;;     40000000000715CC (in parser_error)
;;     400000000007175C (in parser_error)
;;     400000000007185C (in parser_error)
;;     40000000000F863C (in exec_builtin)
exit_shell proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; addl	r14,-10260,r1; mov	r34,b2 }
	{ adds	r36,0x0,r1; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r37,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ adds	r1,0x0,r36; addl	r14,-10652,r1; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r37,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ adds	r1,0x0,r36; adds	r37,0x0,r0; br.call.sptk.many	b0,signal_is_trapped; }
	{ adds	r1,0x0,r36; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dpnt.few	40000000000224A0; }

l4000000000022380:
	{ addl	r33,6512,r1; nop.i	0x0; br.call.sptk.many	b0,unlink_fifo_list; }
	{ ld4	r14,[r33]; nop.m	0x0; adds	r1,0x0,r36; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	4000000000022480 }

l40000000000223B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,coproc_flush; }
	{ ld4	r14,[r33]; nop.m	0x0; adds	r1,0x0,r36; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000022420 }

l40000000000223E0:
	{ addl	r14,6520,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000022420 }

l4000000000022400:
	{ addl	r14,6508,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	4000000000022500; }

l4000000000022420:
	{ addl	r14,9028,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	4000000000022460 }

l4000000000022450:
	{ nop.m	0x0; adds	r37,0x0,r32; br.call.sptk.many	b0,fn400000000001B580; }

l4000000000022460:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,end_job_control; }
	{ adds	r1,0x0,r36; adds	r37,0x0,r32; br.call.sptk.many	b0,fn400000000001B580; }

l4000000000022480:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,maybe_save_shell_history; }
	{ nop.m	0x0; adds	r1,0x0,r36; br.cond.sptk.few	40000000000223B0 }

l40000000000224A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,run_exit_trap; }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r32,0x0,r8; }
	{ addl	r33,6512,r1; nop.i	0x0; br.call.sptk.many	b0,unlink_fifo_list; }
	{ ld4	r14,[r33]; nop.m	0x0; adds	r1,0x0,r36; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000223B0 }

l40000000000224F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000022480 }

l4000000000022500:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,hangup_all_jobs; }
	{ adds	r1,0x0,r36; addl	r14,9028,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000022450 }

l4000000000022540:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000022460; }
4000000000022550 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000022560 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000022570 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; sh_exit: 4000000000022580
;;   Called from:
;;     400000000007104C (in fatal_error)
sh_exit proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; mov	r33,b1; adds	r36,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B580; }
	{ nop.m	0x0; break.f	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

;; shell_is_restricted: 40000000000225C0
;;   Called from:
;;     40000000000225BC (in sh_exit)
shell_is_restricted proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x4; addl	r14,7352,r1; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	4000000000022630 }

l4000000000022600:
	{ addl	r8,1,r0; nop.m	0x0; nop.i	0x0 }

l4000000000022610:
	{ nop.m	0x0; mov.i	ar.pfs,r34; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r33,4000000000022620; br.ret	b0; }

l4000000000022630:
	{ adds	r36,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,base_pathname; }
	{ ld1	r14,[r8]; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r1,0x0,r35; adds	r8,0x0,r0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x2D,r14; (p07) adds	r36,0x1,r36; nop.i	0x0; }

l400000000002266C:
	{ cmp4.eq.and	p00,p43,r1,r0; Invalid; cmp4.eq.and	p00,p32,r32,r0 }

l4000000000022676:
	{ chk.a.nc	f0,3FFFFFFFFF022E76; (p07) nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r114,3FFFFFFFFFCE5766; nop; break.b	0x80000 }

l4000000000022690:
	{ nop.m	0x0; addl	r37,268,r1; nop.i	0x0; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r35; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	4000000000022600 }

l40000000000226C0:
	{ adds	r8,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000226D0; br.ret	b0; }
40000000000226E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000226F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; maybe_make_restricted: 4000000000022700
;;   Called from:
;;     400000000001EC9C (in main)
maybe_make_restricted proc
	{ alloc	r35,ar.pfs,0x7,0x0,0x5; addl	r33,7352,r1; nop.b	0x0 }
	{ adds	r36,0x0,r1; mov	r34,b2; adds	r37,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,base_pathname; }
	{ ld1	r15,[r8]; adds	r37,0x0,r8; adds	r1,0x0,r36 }
	{ adds	r8,0x0,r0; nop.m	0x0; sxt1	r15,r15 }
	{ nop.m	0x0; ld4	r14,[r33]; nop.i	0x0; }
	{ cmp4.eq	p09,p08,0x2D,r15; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dpnt.few	4000000000022800; }

l4000000000022770:
	{ (p09) adds	r37,0x1,r37; ld1	r14,[r37]; nop.i	0x0; }

l4000000000022776:
	{ (p07) fwb; mov	pr,0x4000; break.i	0x80000 }
	{ (p07) break.m	0x50700; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	f114,3FFFFFFFFFCE5876; mov	pr,0x4300003; break.b	0x80000 }

l40000000000227A0:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000227B0; br.ret	b0 }

l40000000000227C0:
	{ nop.m	0x0; addl	r38,268,r1; nop.i	0x0; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ cmp4.eq	p07,p06,0x0,r8; nop.m	0x0; adds	r1,0x0,r36; }
	{ nop.m	0x0; (p06) adds	r8,0x0,r0; (p06) br.cond.dpnt.few	40000000000227A0 }

l40000000000227FC:
	{ (p61) nop; nop; (p04) nop }

l4000000000022800:
	{ nop.m	0x0; addl	r37,276,r1; nop.i	0x0; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,set_var_read_only; }
	{ adds	r1,0x0,r36; addl	r37,284,r1; nop.i	0x0; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,set_var_read_only; }
	{ adds	r1,0x0,r36; addl	r37,292,r1; nop.i	0x0; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,set_var_read_only; }
	{ adds	r1,0x0,r36; addl	r37,300,r1; nop.i	0x0; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,set_var_read_only; }
	{ addl	r14,1,r0; addl	r8,1,r0; nop.b	0x0 }
	{ adds	r1,0x0,r36; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ st4	[r14],r33; mov.spnt	b0,r34,40000000000228A0; br.ret	b0; }
40000000000228B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; disable_priv_mode: 40000000000228C0
;;   Called from:
;;     400000000001F2EC (in main)
disable_priv_mode proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; addl	r33,-22276,r1; mov	r34,b2 }
	{ adds	r36,0x0,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; adds	r32,0x0,r33; nop.i	0x0; }
	{ ld4	r37,[r32],8; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BDC0; }
	{ nop.m	0x0; adds	r1,0x0,r36; nop.i	0x0 }
	{ ld4	r37,[r32]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B3A0; }
	{ adds	r14,0x0,r33; ld4	r16,[r32]; nop.b	0x0 }
	{ adds	r33,0x4,r33; adds	r1,0x0,r36; mov.i	ar.pfs,r35; }
	{ ld4	r15,[r14],12; mov.spnt	b0,r34,4000000000022940; nop.i	0x0 }
	{ st4	[r15],r33; st4	[r16],r14; br.ret	b0; }
4000000000022960 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000022970 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; unbind_args: 4000000000022980
;;   Called from:
;;     40000000000509BC (in shell_execve)
unbind_args proc
	{ alloc	r33,ar.pfs,0x5,0x0,0x3; mov	r32,b0; adds	r34,0x0,r1; }
	{ adds	r35,0x0,r0; addl	r36,1,r0; br.call.sptk.many	b0,remember_args; }
	{ adds	r1,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,pop_args; }
	{ adds	r1,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ nop.m	0x0; mov.spnt	b0,r32,40000000000229C0; br.ret	b0; }
40000000000229D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000229E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000229F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; unset_bash_input: 4000000000022A00
;;   Called from:
;;     40000000000509EC (in shell_execve)
;;     4000000000082E1C (in make_child)
;;     4000000000082E1C (in make_child)
unset_bash_input proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; mov	r34,b2; adds	r36,0x0,r1 }
	{ addl	r33,5636,r1; cmp4.eq	p06,p07,0x0,r32; (p07) br.cond.dptk.few	4000000000022AB0; }

l4000000000022A20:
	{ addl	r33,5636,r1; ld4	r37,[r33]; nop.i	0x0; }
	{ cmp4.lt	p07,p06,0x0,r37; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000022A90; }

l4000000000022A40:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,close_buffered_fd; }
	{ adds	r1,0x0,r36; nop.m	0x0; addl	r14,-1,r0; }
	{ addl	r15,22532,r1; st4	[r14],r33; nop.i	0x0; }
	{ nop.m	0x0; adds	r16,0x10,r15; nop.i	0x0; }
	{ st4	[r0],r15; st4	[r14],r16; nop.i	0x0 }

l4000000000022A90:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000022AA0; br.ret	b0 }

l4000000000022AB0:
	{ nop.m	0x0; ld4	r37,[r33]; nop.i	0x0; }
	{ cmp4.lt	p07,p06,r37,r0; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000022A90; }

l4000000000022AD0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,close_buffered_fd; }
	{ adds	r1,0x0,r36; addl	r14,-1,r0; addl	r15,22532,r1 }
	{ st4	[r14],r33; nop.m	0x0; nop.i	0x0; }
	{ adds	r16,0x10,r15; nop.i	0x0; nop.i	0x0 }
	{ st4	[r0],r15; st4	[r14],r16; br.cond.sptk.few	4000000000022A90; }
4000000000022B20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000022B30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; get_current_user_info: 4000000000022B40
;;   Called from:
;;     400000000006175C (in sh_get_home_dir)
;;     400000000006DE9C (in initialize_shell_variables)
;;     400000000006DF0C (in initialize_shell_variables)
;;     40000000000AB69C (in make_default_mailpath)
get_current_user_info proc
	{ alloc	r37,ar.pfs,0xA,0x0,0x7; addl	r32,-22276,r1; mov	r36,b4 }
	{ adds	r38,0x0,r1; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ adds	r33,0x10,r32; nop.m	0x0; mov.spnt	b0,r36,4000000000022B60; }
	{ nop.m	0x0; ld8	r14,[r33]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	4000000000022B90; br.ret	b0; }

l4000000000022B8C:
	{ cmp.eq	p00,p17,r33,r0; (p04) nop; break.i	0x1000 }

l4000000000022B90:
	{ ld4	r39,[r32]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A640; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r38; nop.i	0x0 }
	{ adds	r34,0x0,r8; adds	r35,0x0,r8; (p06) br.cond.dpnt.few	4000000000022E20; }

l4000000000022BC0:
	{ ld8	r39,[r8]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r38; adds	r39,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r40,[r35],40; nop.m	0x0; adds	r1,0x0,r38 }
	{ adds	r39,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ ld8	r39,[r35]; st8	[r8],r33; adds	r1,0x0,r38; }
	{ cmp.eq	p06,p07,0x0,r39; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000022C40; }

l4000000000022C20:
	{ ld1	r14,[r39]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	4000000000022D60 }

l4000000000022C40:
	{ addl	r39,8,r0; adds	r34,0x20,r34; br.call.sptk.many	b0,xmalloc; }
	{ addl	r15,47,r0; nop.m	0x0; adds	r14,0x0,r8 }
	{ addl	r16,98,r0; nop.m	0x0; adds	r1,0x0,r38; }
	{ st1	[r14],r1,1; st1	[r14],r1,1; addl	r16,105,r0; }
	{ st1	[r14],r1,1; nop.m	0x0; addl	r16,110,r0; }
	{ st1	[r14],r1,1; st1	[r14],r1,1; addl	r15,115,r0; }
	{ st1	[r14],r1,1; nop.m	0x0; addl	r15,104,r0; }
	{ st1	[r14],r1,1; st1	[r0],r14; adds	r14,0x18,r32 }
	{ adds	r32,0x20,r32; st8	[r8],r14; nop.i	0x0 }
	{ ld8	r39,[r34]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r38; adds	r39,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r38; nop.m	0x0; adds	r39,0x0,r8 }
	{ ld8	r40,[r34]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r38; st8	[r8],r32; nop.i	0x0 }

l4000000000022D20:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BD20; }
	{ adds	r1,0x0,r38; nop.m	0x0; nop.i	0x0 }

l4000000000022D40:
	{ nop.m	0x0; mov.i	ar.pfs,r37; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r36,4000000000022D50; br.ret	b0; }

l4000000000022D60:
	{ adds	r34,0x20,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r38; adds	r39,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r40,[r35]; nop.m	0x0; adds	r1,0x0,r38 }
	{ adds	r39,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r14,0x18,r32; nop.m	0x0; adds	r1,0x0,r38 }
	{ ld8	r39,[r34]; nop.m	0x0; adds	r32,0x20,r32; }
	{ st8	[r8],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r38; adds	r39,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r38; nop.m	0x0; adds	r39,0x0,r8 }
	{ ld8	r40,[r34]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; adds	r1,0x0,r38; nop.i	0x0 }
	{ st8	[r8],r32; nop.m	0x0; br.cond.sptk.few	4000000000022D20; }

l4000000000022E20:
	{ addl	r40,308,r1; nop.m	0x0; addl	r41,5,r0 }
	{ adds	r39,0x0,r0; nop.m	0x0; addl	r34,47,r0; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r38; nop.m	0x0; adds	r39,0x0,r8 }
	{ st8	[r8],r33; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r38; adds	r39,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r40,[r33]; nop.m	0x0; adds	r1,0x0,r38 }
	{ adds	r39,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r38; nop.m	0x0; addl	r39,8,r0 }
	{ st8	[r8],r33; nop.m	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r14,0x0,r8; addl	r16,98,r0; adds	r15,0x18,r32 }
	{ adds	r1,0x0,r38; addl	r39,2,r0; adds	r32,0x20,r32; }
	{ st1	[r14],r1,1; st1	[r14],r1,1; addl	r16,105,r0; }
	{ st1	[r14],r1,1; nop.m	0x0; addl	r16,110,r0; }
	{ st1	[r14],r1,1; nop.m	0x0; addl	r16,115,r0; }
	{ st1	[r14],r1,1; st1	[r14],r1,1; addl	r16,104,r0; }
	{ st1	[r14],r1,1; st1	[r0],r14; nop.i	0x0 }
	{ st8	[r8],r15; nop.m	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r14,0x0,r8; nop.m	0x0; adds	r1,0x0,r38; }
	{ st1	[r14],r1,1; st1	[r0],r14; nop.i	0x0 }
	{ st8	[r8],r32; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BD20; }
	{ nop.m	0x0; adds	r1,0x0,r38; br.cond.sptk.few	4000000000022D40; }
4000000000022F80 08 10 19 08 80 05 C0 00 30 7C 46 20 04 00 C4 00 ........0|F ....
4000000000022F90 09 70 30 02 33 24 30 02 04 00 42 00 C4 0F C8 90 .p0.3$0...B.....
4000000000022FA0 09 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
4000000000022FB0 11 38 00 1C 86 39 00 00 00 02 80 03 A0 02 00 43 .8...9.........C
4000000000022FC0 11 00 00 00 01 00 00 00 00 02 00 00 C8 D8 0C 50 ...............P
4000000000022FD0 11 08 00 46 00 21 00 00 00 02 00 00 B8 93 08 50 ...F.!.........P
4000000000022FE0 11 08 00 46 00 21 40 02 00 00 42 00 E8 22 09 50 ...F.!@...B..".P
4000000000022FF0 09 70 00 40 18 10 00 00 00 02 00 20 00 18 01 84 .p.@....... ....
4000000000023000 10 00 00 00 01 00 70 00 38 0C F2 03 70 03 00 43 ......p.8...p..C
4000000000023010 0B 70 C0 03 32 24 E0 00 38 20 20 00 00 00 04 00 .p..2$..8  .....
4000000000023020 10 00 00 00 01 00 60 00 38 0E F3 03 10 02 00 43 ......`.8......C
4000000000023030 09 00 00 00 01 00 00 82 05 72 48 00 00 00 04 00 .........rH.....
4000000000023040 11 00 00 00 01 00 00 00 00 02 00 00 08 E7 01 50 ...............P
4000000000023050 02 08 00 46 00 21 00 00 00 02 00 E0 C1 0D 14 91 ...F.!..........
4000000000023060 0B 70 00 40 10 10 00 00 00 02 00 E0 00 70 18 E6 .p.@.........p..
4000000000023070 10 20 01 1E 18 10 00 00 00 02 00 03 40 00 00 42 . ..........@..B
4000000000023080 0B 70 E0 02 39 24 00 00 00 02 00 00 00 00 04 00 .p..9$..........
4000000000023090 09 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
40000000000230A0 10 00 00 00 01 00 70 00 38 0C F3 03 A0 02 00 42 ......p.8......B
40000000000230B0 08 28 05 00 00 24 00 00 00 02 00 00 00 00 04 00 .(...$..........
40000000000230C0 11 00 00 00 01 00 00 00 00 02 00 00 C8 8C 04 50 ...............P
40000000000230D0 11 20 01 00 00 21 10 00 8C 00 42 00 38 C3 05 50 . ...!....B.8..P
40000000000230E0 11 08 00 46 00 21 00 00 00 02 00 00 A8 2B 00 50 ...F.!.......+.P
40000000000230F0 11 08 00 46 00 21 00 00 00 02 00 00 58 3A 05 50 ...F.!......X:.P
4000000000023100 09 70 00 40 10 10 00 00 00 02 00 20 00 18 01 84 .p.@....... ....
4000000000023110 10 00 00 00 01 00 70 00 38 0C 73 03 40 00 00 42 ......p.8.s.@..B
4000000000023120 0B 70 E0 02 39 24 00 00 00 02 00 00 00 00 04 00 .p..9$..........
4000000000023130 09 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
4000000000023140 10 00 00 00 01 00 70 00 38 0C F3 03 D0 01 00 42 ......p.8......B
4000000000023150 08 20 05 00 00 24 00 00 00 02 00 00 00 00 04 00 . ...$..........
4000000000023160 11 00 00 00 01 00 00 00 00 02 00 00 68 6A 0E 50 ............hj.P
4000000000023170 09 08 00 46 00 21 E0 00 80 20 20 00 00 00 04 00 ...F.!...  .....
4000000000023180 11 38 00 1C 86 39 E0 C0 05 72 48 03 80 00 00 43 .8...9...rH....C
4000000000023190 0B 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
40000000000231A0 11 38 00 1C 86 39 E0 80 04 66 48 03 60 00 00 43 .8...9...fH.`..C
40000000000231B0 0B 20 01 1C 10 10 70 00 90 0C 73 00 00 00 04 00 . ....p...s.....
40000000000231C0 09 00 00 00 01 80 41 0A 00 00 48 00 00 00 04 00 ......A...H.....
40000000000231D0 F1 20 01 00 00 21 00 00 00 02 00 00 F8 1B 0F 50 . ...!.........P
40000000000231E0 02 08 00 46 00 21 00 10 01 55 00 00 10 0A 00 07 ...F.!...U......
40000000000231F0 19 00 00 00 01 00 C0 00 30 04 42 80 08 00 84 00 ........0.B.....
4000000000023200 11 20 05 00 00 24 00 00 00 02 00 00 C8 1B 0F 50 . ...$.........P
4000000000023210 02 08 00 46 00 21 00 10 01 55 00 00 10 0A 00 07 ...F.!...U......
4000000000023220 19 00 00 00 01 00 C0 00 30 04 42 80 08 00 84 00 ........0.B.....
4000000000023230 11 00 00 00 01 00 00 00 00 02 00 00 18 F9 FF 58 ...............X
4000000000023240 11 00 00 00 01 00 10 00 8C 00 42 00 F0 FD FF 48 ..........B....H
4000000000023250 0B 70 90 FB AC 27 E0 00 38 30 20 00 00 00 04 00 .p...'..80 .....
4000000000023260 11 20 01 1C 18 10 00 00 00 02 00 00 68 67 10 50 . ..........hg.P
4000000000023270 0B 08 00 46 00 21 E0 60 F7 5F 4F 00 00 00 04 00 ...F.!.`._O.....
4000000000023280 09 00 00 00 01 00 E0 00 38 30 20 00 00 00 04 00 ........80 .....
4000000000023290 11 20 01 1C 18 10 00 00 00 02 00 00 38 67 10 50 . ..........8g.P
40000000000232A0 09 00 00 00 01 00 10 00 8C 00 42 00 00 00 04 00 ..........B.....
40000000000232B0 11 00 F1 03 32 24 00 00 00 02 00 00 D8 D5 0C 50 ....2$.........P
40000000000232C0 11 08 00 46 00 21 00 00 00 02 00 00 C8 90 08 50 ...F.!.........P
40000000000232D0 11 08 00 46 00 21 40 02 00 00 42 00 F8 1F 09 50 ...F.!@...B....P
40000000000232E0 09 70 00 40 18 10 00 00 00 02 00 20 00 18 01 84 .p.@....... ....
40000000000232F0 10 00 00 00 01 00 70 00 38 0C 72 03 20 FD FF 4A ......p.8.r. ..J
4000000000023300 10 00 00 00 01 00 00 00 00 02 00 00 70 00 00 40 ............p..@
4000000000023310 0B 70 40 02 33 24 40 02 38 20 20 00 00 00 04 00 .p@.3$@.8  .....
4000000000023320 0B 38 00 48 86 B9 41 0A 00 00 48 00 00 00 04 00 .8.H..A...H.....
4000000000023330 10 00 00 00 01 C0 41 02 00 00 42 00 30 FE FF 48 ......A...B.0..H
4000000000023340 0B 70 40 02 33 24 50 02 38 20 20 00 00 00 04 00 .p@.3$P.8  .....
4000000000023350 0B 38 00 4A 86 B9 51 0A 00 00 48 00 00 00 04 00 .8.J..Q...H.....
4000000000023360 11 00 00 00 01 C0 51 02 00 00 42 00 60 FD FF 48 ......Q...B.`..H
4000000000023370 11 28 FD 01 01 24 40 82 30 00 42 00 38 7F FF 58 .(...$@.0.B.8..X
4000000000023380 08 38 20 00 86 30 00 00 00 02 00 20 00 18 01 84 .8 ..0..... ....
4000000000023390 19 20 41 18 00 21 00 00 00 02 80 03 90 00 00 43 . A..!.........C
40000000000233A0 11 00 00 00 01 00 00 00 00 02 00 00 28 83 FF 58 ............(..X
40000000000233B0 11 08 00 46 00 21 40 0A 20 00 42 00 18 59 0C 50 ...F.!@. .B..Y.P
40000000000233C0 08 08 00 46 00 21 00 00 00 02 00 80 04 40 00 84 ...F.!.......@..
40000000000233D0 19 28 41 18 00 21 00 00 00 02 00 00 B8 7D FF 58 .(A..!.......}.X
40000000000233E0 09 08 00 46 00 21 00 40 80 30 23 00 00 00 04 00 ...F.!.@.0#.....
40000000000233F0 0B 70 C0 03 32 24 E0 00 38 20 20 00 00 00 04 00 .p..2$..8  .....
4000000000023400 10 00 00 00 01 00 60 00 38 0E 73 03 30 FC FF 4A ......`.8.s.0..J
4000000000023410 10 00 00 00 01 00 00 00 00 02 00 00 20 FE FF 48 ............ ..H
4000000000023420 09 00 00 00 01 00 E0 E0 05 04 48 00 00 00 04 00 ..........H.....
4000000000023430 0B 70 00 1C 18 10 00 70 80 30 23 C0 01 0F C8 90 .p.....p.0#.....
4000000000023440 09 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
4000000000023450 10 00 00 00 01 00 60 00 38 0E 73 03 E0 FB FF 4A ......`.8.s....J
4000000000023460 11 00 00 00 01 00 00 00 00 02 00 00 D0 FD FF 48 ...............H
4000000000023470 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
4000000000023480 08 08 19 06 80 05 40 A2 F4 C3 4F 00 04 00 C4 00 ......@...O.....
4000000000023490 02 10 01 02 00 21 00 00 00 02 00 A0 54 00 00 90 .....!......T...
40000000000234A0 19 18 01 00 00 21 40 02 90 30 20 00 C8 76 FF 58 .....!@..0 ..v.X
40000000000234B0 08 08 00 44 00 21 00 00 00 02 00 80 04 40 00 84 ...D.!.......@..
40000000000234C0 19 18 05 00 00 24 00 00 00 02 00 00 C8 86 FF 58 .....$.........X
40000000000234D0 0B 08 00 44 00 21 E0 60 F7 5F 4F 00 00 00 04 00 ...D.!.`._O.....
40000000000234E0 09 00 00 00 01 00 E0 00 38 30 20 00 00 00 04 00 ........80 .....
40000000000234F0 11 18 01 1C 18 10 00 00 00 02 00 00 98 71 FF 58 .............q.X
4000000000023500 11 08 00 44 00 21 00 00 00 02 00 00 88 51 0D 50 ...D.!.......Q.P
4000000000023510 11 08 00 44 00 21 30 1A 00 00 48 00 B8 0F 09 50 ...D.!0...H....P
4000000000023520 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
4000000000023530 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; parse_command: 4000000000023540
;;   Called from:
;;     400000000002396C (in read_command)
;;     40000000000F65AC (in parse_and_execute)
;;     40000000000F790C (in parse_string)
parse_command proc
	{ alloc	r34,ar.pfs,0x8,0x0,0x4; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ addl	r32,9000,r1; adds	r35,0x0,r1; mov	r33,b1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r0],r32; nop.i	0x0; br.call.sptk.many	b0,run_pending_traps; }
	{ adds	r1,0x0,r35; addl	r14,6516,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	4000000000023670 }

l40000000000235B0:
	{ addl	r14,22532,r1; nop.m	0x0; addl	r36,-3940,r1; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x3,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000023670; }

l40000000000235E0:
	{ ld8	r36,[r36]; nop.i	0x0; br.call.sptk.many	b0,get_string_value; }
	{ adds	r1,0x0,r35; nop.m	0x0; cmp.eq	p06,p07,0x0,r8 }
	{ adds	r36,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000023640; }

l4000000000023610:
	{ addl	r37,-3940,r1; nop.i	0x0; nop.i	0x0 }
	{ ld8	r37,[r37]; nop.m	0x0; br.call.sptk.many	b0,execute_variable_command; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0; }

l4000000000023640:
	{ addl	r14,8936,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2,r14; (p07) br.cond.dpnt.few	4000000000023720 }

l4000000000023670:
	{ addl	r14,8952,r1; nop.m	0x0; nop.i	0x0; }
	{ st4	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,yyparse; }
	{ ld4	r14,[r32]; nop.m	0x0; adds	r1,0x0,r35; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000236D0 }

l40000000000236B0:
	{ nop.m	0x0; mov.i	ar.pfs,r34; mov.spnt	b0,r33,40000000000236B0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000000236D0:
	{ nop.m	0x0; adds	r14,0x10,r12; nop.i	0x0; }
	{ st8	[r8],r14; nop.i	0x0; br.call.sptk.many	b0,gather_here_documents; }
	{ adds	r14,0x10,r12; nop.m	0x0; adds	r1,0x0,r35; }
	{ ld8	r8,[r14]; mov.i	ar.pfs,r34; mov.spnt	b0,r33,4000000000023700 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000023720:
	{ nop.m	0x0; addl	r36,-3932,r1; nop.i	0x0; }
	{ ld8	r36,[r36]; nop.i	0x0; br.call.sptk.many	b0,get_string_value; }
	{ adds	r1,0x0,r35; cmp.eq	p07,p06,0x0,r8; nop.i	0x0 }
	{ addl	r37,1,r0; adds	r39,0x0,r8; (p07) br.cond.dpnt.few	40000000000237F0; }

l4000000000023760:
	{ addl	r14,-10652,r1; nop.m	0x0; addl	r38,-3916,r1; }
	{ ld8	r14,[r14]; ld8	r38,[r38]; nop.i	0x0; }
	{ ld8	r36,[r14]; br.call.sptk.many	b0,fn400000000001C040; nop.b	0x0; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0; }

l40000000000237A0:
	{ addl	r14,8952,r1; nop.m	0x0; nop.i	0x0; }
	{ st4	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,yyparse; }
	{ ld4	r14,[r32]; nop.m	0x0; adds	r1,0x0,r35; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000236B0 }

l40000000000237E0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000236D0 }

l40000000000237F0:
	{ nop.m	0x0; addl	r36,-3924,r1; nop.i	0x0; }
	{ ld8	r36,[r36]; nop.i	0x0; br.call.sptk.many	b0,get_working_directory; }
	{ adds	r1,0x0,r35; addl	r37,1,r0; adds	r39,0x0,r8; }
	{ addl	r14,-10652,r1; nop.m	0x0; addl	r38,-3916,r1; }
	{ ld8	r14,[r14]; ld8	r38,[r38]; nop.i	0x0; }
	{ ld8	r36,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ nop.m	0x0; adds	r1,0x0,r35; br.cond.sptk.few	40000000000237A0; }
4000000000023860 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000023870 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; read_command: 4000000000023880
;;   Called from:
;;     4000000000023DFC (in reader_loop)
read_command proc
	{ alloc	r38,ar.pfs,0xB,0x0,0x8; addl	r32,6516,r1; nop.b	0x0 }
	{ adds	r39,0x0,r1; nop.m	0x0; mov	r37,b5; }
	{ nop.m	0x0; addl	r40,1,r0; br.call.sptk.many	b0,set_current_prompt_level; }
	{ adds	r1,0x0,r39; nop.i	0x0; addl	r15,6532,r1 }
	{ ld4	r14,[r32]; nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; }
	{ st8	[r0],r15; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000023A60 }

l40000000000238E0:
	{ adds	r36,0x0,r0; adds	r35,0x0,r0; adds	r33,0x0,r0 }

l40000000000238F0:
	{ addl	r14,7676,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4.acq	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p07) br.cond.dpnt.few	4000000000023A10 }

l4000000000023920:
	{ addl	r14,7684,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4.acq	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000239F0 }

l4000000000023950:
	{ addl	r14,8952,r1; nop.m	0x0; nop.i	0x0; }
	{ st4	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,parse_command; }
	{ ld4	r14,[r32]; nop.m	0x0; adds	r1,0x0,r39 }
	{ adds	r34,0x0,r8; nop.m	0x0; cmp.eq	p09,p08,0x0,r33; }
	{ cmp4.eq	p06,p07,0x0,r14; (p08) addl	r33,1,r0; (p06) br.cond.dpnt.few	40000000000239D0; }

l400000000002399C:
	{ (p02) cmp.lt	p00,p03,r64,r33; nop; (p04) nop }

l40000000000239A0:
	{ cmp4.lt	p06,p07,0x0,r35; (p09) adds	r33,0x0,r0; (p06) addl	r35,1,r0; }

l40000000000239AC:
	{ Invalid; Invalid; Invalid }

l40000000000239B0:
	{ (p07) adds	r35,0x0,r0; and	r33,r33,r35; nop.i	0x0; }

l40000000000239B6:
	{ Invalid; nop; break.b	0x80000 }
	{ (p03) chk.a.clr	f0,3FFFFFFFFFCE73D6; nop; nop }

l40000000000239D0:
	{ adds	r8,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000239E0; br.ret	b0; }

l40000000000239F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,throw_to_top_level; }
	{ nop.m	0x0; adds	r1,0x0,r39; br.cond.sptk.few	4000000000023950 }

l4000000000023A10:
	{ ld4.acq	r40,[r14]; nop.i	0x0; br.call.sptk.many	b0,termsig_handler; }
	{ adds	r1,0x0,r39; addl	r14,7684,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4.acq	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000023950 }

l4000000000023A50:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000239F0 }

l4000000000023A60:
	{ nop.m	0x0; addl	r40,-3908,r1; nop.i	0x0; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r14,0x8,r8; adds	r1,0x0,r39; cmp.eq	p06,p07,0x0,r8 }
	{ adds	r33,0x0,r8; addl	r42,10,r0; (p06) br.cond.dpnt.few	40000000000238E0; }

l4000000000023AA0:
	{ ld8	r40,[r14]; nop.m	0x0; adds	r41,0x0,r0; }
	{ cmp.eq	p06,p07,0x0,r40; (p06) adds	r36,0x0,r0; (p06) adds	r35,0x0,r0 }

l4000000000023ABC:
	{ rsm	0x308000; (p48) nop }

l4000000000023AC0:
	{ nop.b	0x0; (p06) br.cond.dpnt.few	40000000000238F0; br.call.sptk.many	b0,fn400000000001C2A0; }

l4000000000023ACC:
	{ (p63) nop; cmp.eq.unc	p32,p16,r9,r64; czx1.l	r0,r97 }
	{ ldfp8	f0,f1,[r0]; (p04) dep	r0,r2,r64,62,1; zxt1	r0,r64 }
	{ (p07) nop; (p04) nop; }

l4000000000023AFC:
	{ (p48) nop; Invalid; break.i	0x1000 }

l4000000000023B00:
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r40,0x0,r34; nop.m	0x0; br.call.sptk.many	b0,fn400000000001ACA0; }
	{ adds	r1,0x0,r39; addl	r14,7676,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4.acq	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	4000000000023920 }

l4000000000023B60:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000023A10 }

l4000000000023B70:
	{ adds	r40,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001ACA0; }
	{ adds	r1,0x0,r39; nop.m	0x0; addl	r40,14,r0 }
	{ adds	r41,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r8,0x0,r34; adds	r1,0x0,r39; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,4000000000023BB0; br.ret	b0; }

;; reader_loop: 4000000000023BC0
;;   Called from:
;;     400000000001F7EC (in main)
;;     400000000001F90C (in main)
reader_loop proc
	{ alloc	r34,ar.pfs,0x7,0x0,0x3; adds	r16,0x8,r12; nop.b	0x0 }
	{ adds	r12,0xFFFFFFFFFFFFFFD0,r12; addl	r15,6484,r1; mov	r33,b1; }
	{ st8.spill	[r1],r16; nop.m	0x0; nop.i	0x0 }
	{ addl	r16,6676,r1; adds	r14,0x10,r12; adds	r18,0x20,r12; }
	{ nop.m	0x0; st8.rel	[r0],r14; nop.i	0x0; }
	{ ld4	r17,[r15]; nop.i	0x0; adds	r19,0x1,r17 }
	{ ld4	r14,[r16]; st4	[r19],r18; nop.i	0x0 }
	{ st4	[r19],r15; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	4000000000024040; }

l4000000000023C40:
	{ addl	r35,25252,r1; nop.m	0x0; addl	r36,1,r0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BD60; }
	{ adds	r1,0x38,r12; nop.m	0x0; adds	r32,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,unlink_fifo_list; }
	{ adds	r1,0x38,r12; ld8	r1,[r1]; nop.i	0x0; }
	{ addl	r15,6512,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dpnt.few	40000000000240A0; }

l4000000000023CC0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r32; (p07) br.cond.dptk.few	4000000000023D80; }

l4000000000023CD0:
	{ adds	r14,0x20,r12; nop.m	0x0; cmp4.eq	p06,p07,0x2,r32; }
	{ ld4	r15,[r14]; nop.m	0x0; addl	r14,6484,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000024390; }

l4000000000023D10:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x2,r32; (p06) br.cond.dptk.few	4000000000024270; }

l4000000000023D20:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x1,r32; (p06) br.cond.dpnt.few	4000000000024280 }

l4000000000023D30:
	{ addl	r35,-3900,r1; nop.m	0x0; addl	r36,3,r0 }
	{ adds	r37,0x0,r32; nop.m	0x0; adds	r38,0x0,r0; }
	{ ld8	r35,[r35]; nop.i	0x0; br.call.sptk.many	b0,command_error; }
	{ nop.m	0x0; adds	r1,0x38,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0; }

l4000000000023D80:
	{ addl	r17,7140,r1; nop.m	0x0; addl	r18,6488,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld8	r14,[r17]; st4	[r0],r18; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000023DF0; }

l4000000000023DC0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,dispose_used_env_vars; }
	{ nop.m	0x0; adds	r1,0x38,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0 }

l4000000000023DF0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,read_command; }
	{ adds	r1,0x38,r12; nop.m	0x0; cmp4.eq	p07,p06,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dptk.few	4000000000024300; }

l4000000000023E20:
	{ addl	r15,6512,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000023E80 }

l4000000000023E50:
	{ addl	r16,7392,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r16]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000241A0 }

l4000000000023E80:
	{ addl	r15,6532,r1; adds	r16,0x10,r12; addl	r17,5644,r1; }
	{ nop.m	0x0; ld8	r14,[r15]; nop.i	0x0; }
	{ st8.rel	[r14],r16; cmp.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	4000000000023FD0; }

l4000000000023EB0:
	{ nop.m	0x0; st8	[r0],r15; nop.i	0x0 }
	{ addl	r15,9048,r1; ld8.acq	r35,[r16]; addl	r16,6488,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4	r14,[r17]; adds	r14,0x1,r14; nop.i	0x0 }
	{ st4	[r0],r15; addl	r15,1,r0; nop.i	0x0 }
	{ st4	[r14],r17; st4	[r15],r16; br.call.sptk.many	b0,execute_command; }
	{ adds	r1,0x38,r12; ld8	r1,[r1]; nop.i	0x0; }
	{ addl	r17,7676,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4.acq	r14,[r17]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	4000000000024140 }

l4000000000023F50:
	{ addl	r18,7684,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4.acq	r14,[r18]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	4000000000024110 }

l4000000000023F80:
	{ adds	r19,0x10,r12; ld8.acq	r14,[r19]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000023FD0; }

l4000000000023FA0:
	{ ld8.acq	r35,[r19]; nop.i	0x0; br.call.sptk.many	b0,dispose_command; }
	{ adds	r1,0x38,r12; nop.m	0x0; adds	r14,0x10,r12; }
	{ ld8	r1,[r1]; st8.rel	[r0],r14; nop.i	0x0; }

l4000000000023FD0:
	{ addl	r18,7388,r1; nop.m	0x0; nop.i	0x0; }
	{ ld4	r14,[r18]; cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; }
	{ (p06) addl	r14,6676,r1; (p07) addl	r19,6676,r1; (p06) addl	r15,-1,r0; }

l4000000000023FF6:
	{ Invalid; (p07) nop; break.b	0x80000; }

l4000000000023FFC:
	{ (p63) nop; break.i	0x1000; break.b	0x1000; }

l4000000000024000:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; (p06) st4	[r15],r14; nop.i	0x0 }

l400000000002401C:
	{ cmp4.eq.and	p00,p35,r1,r0; Invalid; cmp4.eq.and	p00,p00,r32,r0 }

l4000000000024026:
	{ chk.a.nc	r0,3FFFFFFFFF024826; (p07) nop; break.i	0x80000 }

l4000000000024030:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000023C40 }

l4000000000024040:
	{ addl	r14,6484,r1; nop.m	0x0; addl	r16,9044,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4	r15,[r14]; ld4	r8,[r16]; nop.i	0x0; }
	{ nop.m	0x0; adds	r15,0xFFFFFFFFFFFFFFFF,r15; nop.i	0x0; }
	{ st4	[r15],r14; mov.i	ar.pfs,r34; mov.spnt	b0,r33,4000000000024080 }
	{ nop.m	0x0; adds	r12,0x30,r12; br.ret	b0; }

l40000000000240A0:
	{ addl	r35,2,r0; nop.i	0x0; br.call.sptk.many	b0,signal_is_ignored; }
	{ adds	r1,0x38,r12; nop.m	0x0; cmp4.eq	p07,p06,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dptk.few	4000000000023CC0; }

l40000000000240D0:
	{ addl	r36,-10004,r1; nop.m	0x0; addl	r35,2,r0; }
	{ ld8	r36,[r36]; nop.i	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ nop.m	0x0; adds	r1,0x38,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	4000000000023CC0 }

l4000000000024110:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,throw_to_top_level; }
	{ nop.m	0x0; adds	r1,0x38,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	4000000000023F80 }

l4000000000024140:
	{ ld4.acq	r35,[r17]; nop.i	0x0; br.call.sptk.many	b0,termsig_handler; }
	{ adds	r1,0x38,r12; ld8	r1,[r1]; nop.i	0x0; }
	{ addl	r18,7684,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4.acq	r14,[r18]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000023F80 }

l4000000000024190:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000024110 }

l40000000000241A0:
	{ addl	r17,9044,r1; nop.m	0x0; addl	r18,6532,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; st4	[r0],r17; nop.i	0x0 }
	{ ld8	r35,[r18]; nop.m	0x0; br.call.sptk.many	b0,dispose_command; }
	{ nop.m	0x0; adds	r1,0x38,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; addl	r18,7388,r1; addl	r19,6532,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4	r14,[r18]; st8	[r0],r19; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; }
	{ (p06) addl	r14,6676,r1; (p07) addl	r19,6676,r1; (p06) addl	r15,-1,r0; }

l4000000000024236:
	{ Invalid; (p07) nop; break.b	0x80000; }

l400000000002423C:
	{ (p63) nop; break.i	0x1000; break.b	0x1000; }

l4000000000024240:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ (p06) st4	[r15],r14; (p07) ld4	r14,[r19]; nop.i	0x0; }

l4000000000024256:
	{ (p07) fwb; nop; add	r0,r0,r32; }

l400000000002425C:
	{ invala; cmp4.eq.and	p00,p00,r32,r0; Invalid }

l400000000002426C:
	{ (p46) invala; cmp.lt	p00,p00,r32,r0; nop }

l4000000000024270:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x4,r32; (p06) br.cond.dptk.few	4000000000023D30 }

l4000000000024280:
	{ addl	r16,7404,r1; adds	r17,0x10,r12; addl	r19,6676,r1; }
	{ nop.m	0x0; st8.rel	[r0],r17; addl	r17,7676,r1 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4	r14,[r16]; cmp4.eq	p06,p07,0x0,r14; addl	r14,-1,r0; }
	{ (p07) addl	r18,7148,r1; st4	[r14],r19; nop.i	0x0 }

l40000000000242C6:
	{ mf.a; nop; (p32) nop }
	{ break.m	0x4000; cmp.eq	p00,p00,r0,r1; (p01) nop }

l40000000000242E6:
	{ (p03) chk.a.clr	r0,3FFFFFFFFFCE7BC6; nop; break.i	0x80000 }

l40000000000242F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000024140 }

l4000000000024300:
	{ addl	r15,6516,r1; nop.m	0x0; addl	r18,7388,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4	r14,[r15]; nop.i	0x0; cmp4.eq	p07,p06,0x0,r14 }
	{ ld4	r14,[r18]; (p07) addl	r16,6676,r1; (p07) addl	r17,-1,r0; }

l400000000002433C:
	{ Invalid; br.cond	b0; Invalid }

l4000000000024340:
	{ nop.m	0x0; (p07) st4	[r17],r16; cmp4.eq	p07,p06,0x0,r14; }

l400000000002434C:
	{ cmp4.eq.and	p14,p09,r6,r115; (p01) nop; (p02) cmp4.eq.or.andcm	p37,p18,r0,r13 }

l4000000000024356:
	{ Invalid; (p07) nop; break.b	0x80000; }

l400000000002435C:
	{ (p63) nop; break.i	0x1000; break.b	0x1000; }

l4000000000024360:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ (p06) st4	[r15],r14; (p07) ld4	r14,[r19]; nop.i	0x0; }

l4000000000024376:
	{ (p07) fwb; nop; add	r0,r0,r32; }

l400000000002437C:
	{ invala; cmp4.eq.and	p00,p00,r32,r0; Invalid }

l400000000002438C:
	{ (p37) cmp.eq.unc	p63,p09,r63,r36; zxt4	r53,r17; break.b	0x1000 }

l4000000000024390:
	{ addl	r15,9044,r1; nop.m	0x0; addl	r16,9028,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4	r14,[r15]; cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; }
	{ nop.m	0x0; (p07) addl	r14,1,r0; nop.i	0x0; }

l40000000000243CC:
	{ Invalid; (p32) cmp.lt.unc	p35,p08,r3,r100; Invalid }

l40000000000243D6:
	{ (p07) fwb; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFCE7CC6; nop; (p16) nop }

l40000000000243F0:
	{ adds	r17,0x10,r12; addl	r18,6676,r1; addl	r19,-1,r0; }
	{ nop.m	0x0; st8.rel	[r0],r17; addl	r17,7676,r1 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r19],r18; ld4.acq	r14,[r17]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000023F50 }

l4000000000024440:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000024140 }

l4000000000024450:
	{ adds	r15,0x10,r12; ld8.acq	r14,[r15]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000023D80; }

l4000000000024470:
	{ ld8.acq	r35,[r15]; nop.i	0x0; br.call.sptk.many	b0,dispose_command; }
	{ adds	r1,0x38,r12; adds	r16,0x10,r12; nop.i	0x0 }
	{ ld8	r1,[r1]; st8.rel	[r0],r16; br.cond.sptk.few	4000000000023D80; }
40000000000244A0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000244B0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000244C0 09 78 F0 03 33 24 00 00 00 02 00 00 01 00 01 84 .x..3$..........
40000000000244D0 02 70 00 1E 10 10 00 00 00 02 00 00 F2 77 FC 8C .p...........w..
40000000000244E0 19 30 00 1C 87 39 E0 20 04 68 48 83 08 00 84 03 .0...9. .hH.....
40000000000244F0 00 00 00 00 01 00 10 01 40 2C 00 00 00 00 04 00 ........@,......
4000000000024500 09 70 00 1C 18 10 00 00 00 02 00 00 00 00 04 00 .p..............
4000000000024510 02 30 00 1C 07 39 10 71 44 00 40 00 00 00 04 00 .0...9.qD.@.....
4000000000024520 F9 00 40 1E 90 D1 01 00 45 00 23 80 08 00 84 00 ..@.....E.#.....
4000000000024530 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000024540 0B 78 10 02 B0 24 00 00 00 02 00 00 00 00 04 00 .x...$..........
4000000000024550 0B 78 40 1E 00 21 E0 00 3C 30 20 00 00 00 04 00 .x@..!..<0 .....
4000000000024560 11 80 04 1C 00 21 60 00 38 0E 72 03 50 00 00 41 .....!`.8.r.P..A
4000000000024570 09 00 00 00 01 00 E0 00 38 00 20 00 00 00 04 00 ........8. .....
4000000000024580 02 00 00 00 01 00 E0 00 38 28 00 00 01 70 40 00 ........8(...p@.
4000000000024590 19 30 00 1C 87 39 00 00 00 02 00 03 20 00 00 43 .0...9...... ..C
40000000000245A0 11 00 40 1E 98 11 00 00 00 02 00 80 08 00 84 00 ..@.............
40000000000245B0 11 00 00 00 01 00 80 F8 F3 FF 4F 80 08 00 84 00 ..........O.....
40000000000245C0 09 78 10 02 B0 24 00 00 00 02 00 00 01 00 01 84 .x...$..........
40000000000245D0 0B 00 00 00 01 00 F0 80 3C 00 42 00 00 00 04 00 ........<.B.....
40000000000245E0 09 00 00 00 01 00 E0 00 3C 30 20 00 00 00 04 00 ........<0 .....
40000000000245F0 02 70 FC 1D 3F 23 00 00 00 02 00 00 00 00 04 00 .p..?#..........
4000000000024600 19 00 38 1E 98 11 00 00 39 00 23 80 08 00 84 00 ..8.....9.#.....
4000000000024610 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000024620 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000024630 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000024640: 4000000000024640
;;   Called from:
;;     400000000002678C (in free_pushed_string_input)
;;     40000000000269BC (in reset_parser)
fn4000000000024640 proc
	{ alloc	r36,ar.pfs,0x7,0x0,0x6; addl	r34,6628,r1; nop.b	0x0 }
	{ adds	r37,0x0,r1; nop.m	0x0; mov	r35,b3; }
	{ nop.m	0x0; ld8	r32,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p07) br.cond.dpnt.few	4000000000024720; }

l4000000000024680:
	{ adds	r14,0x0,r32; ld8	r33,[r14],16; nop.i	0x0; }
	{ nop.m	0x0; ld8	r38,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r38; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000246D0; }

l40000000000246B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r37; nop.m	0x0; nop.i	0x0 }

l40000000000246D0:
	{ adds	r14,0x18,r32; adds	r38,0x0,r32; adds	r32,0x0,r33; }
	{ ld8	r14,[r14]; cmp.eq	p06,p07,0x0,r14; adds	r15,0x10,r14; }
	{ (p07) ld1	r14,[r15]; (p07) and	r14,0xFFFFFFFFFFFFFFFD,r14; nop.i	0x0; }

l40000000000246F6:
	{ Invalid; cmp4.eq	p00,p00,r0,r1; (p01) nop; }

l40000000000246FC:
	{ Invalid; Invalid; break.i	0x1000 }

l4000000000024706:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFCA7926; nop; br.call.spnt.few	b0,b0 }

l4000000000024720:
	{ st8	[r0],r34; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,4000000000024730; br.ret	b0; }

;; fn4000000000024740: 4000000000024740
;;   Called from:
;;     400000000003035C (in yyerror)
fn4000000000024740 proc
	{ alloc	r34,ar.pfs,0x8,0x0,0x5; addl	r32,6788,r1; nop.b	0x0 }
	{ adds	r35,0x0,r1; nop.m	0x0; mov	r33,b1; }
	{ ld8	r37,[r32]; mov	r36,LC; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r35; adds	r37,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r38,[r32]; nop.m	0x0; adds	r1,0x0,r35 }
	{ adds	r37,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r35; nop.m	0x0; adds	r32,0x0,r8 }
	{ adds	r37,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; sxt4	r14,r8; adds	r15,0xFFFFFFFFFFFFFFFF,r8 }
	{ adds	r1,0x0,r35; cmp4.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	4000000000024840; }

l40000000000247E0:
	{ add	r16,r32,r14; addp4	r15,r15,r0; adds	r14,0xFFFFFFFFFFFFFFFF,r14; }
	{ adds	r16,0xFFFFFFFFFFFFFFFF,r16; mov.i	LC,r15; add	r14,r32,r14; }
	{ ld1	r15,[r16]; nop.m	0x0; sxt1	r15,r15; }
	{ cmp4.eq	p07,p06,0xA,r15; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000024840; }

l4000000000024820:
	{ st1	[r14],r127,-1; nop.i	0x0; br.cloop.sptk.few	40000000000248A0; }

l4000000000024830:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000024840:
	{ addl	r14,6648,r1; addl	r38,-468,r1; adds	r39,0x0,r32; }
	{ nop.m	0x0; ld4	r37,[r14]; nop.i	0x0 }
	{ ld8	r38,[r38]; nop.m	0x0; br.call.sptk.many	b0,parser_error; }
	{ adds	r1,0x0,r35; adds	r37,0x0,r32; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r35; mov.i	ar.pfs,r34; mov.i	LC,r36; }
	{ nop.m	0x0; mov.spnt	b0,r33,4000000000024890; br.ret	b0 }

l40000000000248A0:
	{ ld1	r15,[r14]; nop.m	0x0; sxt1	r15,r15; }
	{ cmp4.eq	p06,p07,0xA,r15; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000024840; }

l40000000000248C0:
	{ st1	[r14],r127,-1; nop.i	0x0; br.cloop.sptk.few	40000000000248A0 }

l40000000000248D0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000024840; }
40000000000248E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000248F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000024900: 4000000000024900
;;   Called from:
;;     400000000002A35C (in fn4000000000029100)
;;     400000000002AC3C (in read_secondary_line)
fn4000000000024900 proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x4; addl	r32,-10652,r1; nop.b	0x0 }
	{ addl	r14,6748,r1; mov	r33,b1; adds	r35,0x0,r1; }
	{ ld8	r32,[r32]; ld8	r36,[r14]; nop.i	0x0; }
	{ ld8	r37,[r32]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C260; }
	{ nop.m	0x0; adds	r1,0x0,r35; nop.i	0x0 }
	{ ld8	r36,[r32]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ adds	r1,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,4000000000024970; br.ret	b0; }
4000000000024980 08 10 19 08 80 05 E0 20 04 60 49 20 04 00 C4 00 ....... .`I ....
4000000000024990 09 18 01 02 00 21 00 00 00 02 00 80 04 00 01 84 .....!..........
40000000000249A0 0B 00 00 00 01 00 E0 80 38 00 42 00 00 00 04 00 ........8.B.....
40000000000249B0 11 28 01 1C 18 10 00 00 00 02 00 00 58 BD 08 50 .(..........X..P
40000000000249C0 09 08 00 46 00 21 00 00 00 02 00 00 20 02 AA 00 ...F.!...... ...
40000000000249D0 11 00 00 00 01 00 00 08 05 80 03 80 08 00 84 00 ................
40000000000249E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000249F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000024A00 08 10 15 08 80 05 E0 20 04 60 49 00 44 0F C8 90 ....... .`I.D...
4000000000024A10 09 80 E0 03 3B 24 F0 A0 07 76 48 60 04 08 00 84 ....;$...vH`....
4000000000024A20 08 00 00 00 01 00 00 00 00 02 00 20 04 00 C4 00 ........... ....
4000000000024A30 0A 00 00 00 01 00 E0 80 38 00 42 00 00 00 04 00 ........8.B.....
4000000000024A40 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000024A50 09 00 00 00 01 00 E0 00 38 30 20 00 00 00 04 00 ........80 .....
4000000000024A60 11 30 00 1C 07 39 40 02 38 00 42 03 E0 00 00 41 .0...9@.8.B....A
4000000000024A70 0B 70 00 40 10 10 60 00 38 0E 73 00 00 00 04 00 .p.@..`.8.s.....
4000000000024A80 E9 88 00 20 10 D0 E1 00 3C 20 20 00 00 00 04 00 ... ....<  .....
4000000000024A90 E2 88 04 22 00 E1 E1 08 38 00 42 00 00 00 04 00 ..."....8.B.....
4000000000024AA0 F9 00 44 20 90 D1 01 70 3C 20 23 00 E8 B8 08 50 ..D ...p< #....P
4000000000024AB0 09 08 00 46 00 21 00 01 80 20 20 00 00 00 04 00 ...F.!...  .....
4000000000024AC0 08 78 E0 03 3B 24 00 00 00 02 00 C0 41 0F EC 90 .x..;$......A...
4000000000024AD0 19 30 00 20 87 39 00 00 00 02 00 03 50 00 00 43 .0. .9......P..C
4000000000024AE0 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000024AF0 09 88 00 1E 10 10 00 01 38 20 20 00 00 00 04 00 ........8  .....
4000000000024B00 09 88 FC 23 3F 23 00 00 00 02 00 00 F2 87 FC 8C ...#?#..........
4000000000024B10 08 00 44 1E 90 11 00 80 38 20 23 00 00 00 04 00 ..D.....8 #.....
4000000000024B20 01 00 00 00 01 00 00 10 01 55 00 00 00 00 04 00 .........U......
4000000000024B30 10 00 00 00 01 00 00 08 05 80 03 80 08 00 84 00 ................
4000000000024B40 09 40 FC F9 FF 27 00 00 00 02 00 00 20 02 AA 00 .@...'...... ...
4000000000024B50 11 00 00 00 01 00 00 08 05 80 03 80 08 00 84 00 ................
4000000000024B60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000024B70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000024B80 18 30 29 10 80 05 00 22 04 68 48 00 00 00 00 20 .0)....".hH.... 
4000000000024B90 01 08 F1 03 33 24 50 02 00 62 00 E0 04 08 00 84 ....3$P..b......
4000000000024BA0 09 00 00 00 01 00 E0 00 80 30 20 00 00 00 04 00 .........0 .....
4000000000024BB0 11 38 00 1C 06 39 80 02 38 00 C2 03 70 00 00 43 .8...9..8...p..C
4000000000024BC0 0B 78 00 42 10 10 00 00 00 02 00 00 02 78 58 00 .x.B.........xX.
4000000000024BD0 0B 70 38 20 00 20 80 00 38 00 20 00 00 00 04 00 .p8 . ..8. .....
4000000000024BE0 01 00 00 00 01 00 80 00 20 28 00 00 00 00 04 00 ........ (......
4000000000024BF0 10 00 00 00 01 00 70 00 20 0C 73 03 D0 02 00 43 ......p. .s....C
4000000000024C00 11 00 00 00 01 00 00 00 00 02 00 00 E8 5B FF 58 .............[.X
4000000000024C10 09 08 00 4E 00 21 00 00 80 30 23 00 00 00 04 00 ...N.!...0#.....
4000000000024C20 0B 70 D0 03 3C 24 00 00 00 02 00 00 00 00 04 00 .p..<$..........
4000000000024C30 09 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
4000000000024C40 11 38 00 1C 86 39 E0 60 07 5A C8 03 10 03 00 43 .8...9.`.Z.....C
4000000000024C50 0B 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
4000000000024C60 10 00 00 00 01 00 60 00 38 0E F3 03 30 03 00 43 ......`.8...0..C
4000000000024C70 11 40 09 00 00 24 00 00 00 02 00 00 18 B0 08 50 .@...$.........P
4000000000024C80 11 08 00 4E 00 21 70 00 20 0C F3 03 80 02 00 43 ...N.!p. ......C
4000000000024C90 09 00 00 00 01 80 21 E2 F5 69 4F 00 00 00 04 00 ......!..iO.....
4000000000024CA0 C8 10 01 44 18 10 00 00 00 02 00 00 00 00 04 00 ...D............
4000000000024CB0 09 70 30 02 34 24 10 A2 07 76 48 E0 11 00 00 90 .p0.4$...vH.....
4000000000024CC0 09 70 00 1C 18 10 00 00 00 02 00 00 00 00 04 00 .p..............
4000000000024CD0 02 38 00 1C 06 39 00 00 00 02 80 03 45 EB F3 9F .8...9......E...
4000000000024CE0 0B 00 3C 42 90 91 81 02 38 00 42 00 00 00 04 00 ..<B....8.B.....
4000000000024CF0 F1 40 01 50 18 10 00 00 00 02 00 00 58 63 FF 58 .@.P........Xc.X
4000000000024D00 08 00 00 00 01 00 10 00 9C 00 42 00 25 00 00 90 ..........B.%...
4000000000024D10 19 00 20 40 98 11 00 00 84 20 23 00 78 AF 08 50 .. @..... #.x..P
4000000000024D20 11 08 00 4E 00 21 60 00 20 0E F3 03 80 00 00 42 ...N.!`. ......B
4000000000024D30 08 70 E0 03 3B 24 00 00 00 02 00 00 C2 EB D3 9E .p..;$..........
4000000000024D40 09 40 09 00 00 24 00 00 00 02 00 20 05 10 01 84 .@...$..... ....
4000000000024D50 09 00 00 00 01 00 00 01 40 30 20 00 00 00 04 00 ........@0 .....
4000000000024D60 0B 30 40 44 07 38 F0 00 38 20 20 00 00 00 04 00 .0@D.8..8  .....
4000000000024D70 0A 78 FC 1F 3F 23 00 78 38 20 23 00 00 00 04 00 .x..?#.x8 #.....
4000000000024D80 17 00 00 00 00 88 01 10 00 80 21 00 88 FD 08 50 ..........!....P
4000000000024D90 09 08 00 4E 00 21 00 00 00 02 00 00 00 00 04 00 ...N.!..........
4000000000024DA0 09 10 01 40 18 10 10 E2 07 66 48 60 44 08 D0 90 ...@.....fH`D...
4000000000024DB0 09 30 00 44 07 39 00 00 00 02 00 00 05 10 01 84 .0.D.9..........
4000000000024DC0 D1 40 FC F9 FF 27 00 00 00 02 00 03 20 01 00 43 .@...'...... ..C
4000000000024DD0 11 00 00 42 90 11 00 00 00 02 00 00 F8 68 FF 58 ...B.........h.X
4000000000024DE0 08 48 09 10 00 21 00 00 00 02 00 80 04 40 00 84 .H...!.......@..
4000000000024DF0 09 08 00 4E 00 21 00 00 00 02 00 00 05 10 01 84 ...N.!..........
4000000000024E00 11 00 00 00 01 00 90 02 A4 2C 00 00 08 40 0C 50 .........,...@.P
4000000000024E10 10 00 00 00 01 00 E0 00 90 2C 00 00 00 00 00 20 .........,..... 
4000000000024E20 09 00 20 46 98 11 40 0A 90 00 42 20 00 38 01 84 .. F..@...B .8..
4000000000024E30 08 40 20 1C 00 20 E0 50 00 00 48 80 04 20 59 00 .@ .. .P..H.. Y.
4000000000024E40 0B 78 00 42 50 10 00 70 20 00 23 00 02 78 58 00 .x.BP..p .#..xX.
4000000000024E50 0B 70 00 46 18 10 E0 70 90 00 40 00 00 00 04 00 .p.F...p..@.....
4000000000024E60 0A 00 00 1C 80 11 E0 00 8C 30 20 00 00 00 04 00 .........0 .....
4000000000024E70 09 78 64 00 40 01 00 00 00 02 00 00 00 00 04 00 .xd.@...........
4000000000024E80 01 40 01 1C 00 21 E0 70 40 00 40 00 00 00 04 00 .@...!.p@.@.....
4000000000024E90 0B 40 00 1C 00 10 00 00 00 02 00 00 01 40 50 00 .@...........@P.
4000000000024EA0 11 00 00 00 01 00 70 00 20 0C F3 03 60 FD FF 4A ......p. ...`..J
4000000000024EB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000024EC0 08 78 04 1E 00 21 E0 E0 07 66 48 00 01 40 40 00 .x...!...fH..@@.
4000000000024ED0 0A 00 00 00 01 00 00 78 38 20 23 00 00 00 04 00 .......x8 #.....
4000000000024EE0 01 00 00 00 01 00 00 30 01 55 00 00 00 00 04 00 .......0.U......
4000000000024EF0 10 00 00 00 01 00 00 28 05 80 03 80 08 00 84 00 .......(........
4000000000024F00 09 70 E0 03 3B 24 90 62 F7 63 4F 00 25 00 00 90 .p..;$.b.cO.%...
4000000000024F10 09 00 00 00 01 00 90 02 A4 30 20 00 00 00 04 00 .........0 .....
4000000000024F20 0B 78 00 1C 10 10 F0 08 3C 00 42 00 00 00 04 00 .x......<.B.....
4000000000024F30 11 00 3C 1C 90 11 00 00 00 02 00 00 D8 FB 08 50 ..<............P
4000000000024F40 10 08 00 4E 00 21 20 02 20 00 42 00 70 FD FF 48 ...N.! . .B.p..H
4000000000024F50 11 00 00 00 01 00 00 00 00 02 00 00 78 07 0B 50 ............x..P
4000000000024F60 0B 08 00 4E 00 21 E0 60 07 5A 48 00 00 00 04 00 ...N.!.`.ZH.....
4000000000024F70 0B 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
4000000000024F80 10 00 00 00 01 00 60 00 38 0E 73 03 F0 FC FF 4A ......`.8.s....J
4000000000024F90 09 70 20 02 2E 24 00 00 00 02 00 20 05 00 00 84 .p ..$..... ....
4000000000024FA0 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000024FB0 11 40 01 1C 10 10 00 00 00 02 00 00 D8 A0 05 50 .@.............P
4000000000024FC0 11 08 00 4E 00 21 80 12 00 00 48 00 C8 AC 08 50 ...N.!....H....P
4000000000024FD0 03 08 00 4E 00 21 70 00 20 0C 73 43 C4 EB D3 9E ...N.!p. .sC....
4000000000024FE0 D0 10 01 44 18 10 00 00 00 02 00 03 D0 FC FF 4A ...D...........J
4000000000024FF0 10 00 00 00 01 00 00 00 00 02 00 00 10 FF FF 48 ...............H
4000000000025000 09 00 00 00 01 00 F0 00 84 20 20 00 00 00 04 00 .........  .....
4000000000025010 11 00 00 00 01 00 00 01 3C 2C 00 00 70 FE FF 48 ........<,..p..H
4000000000025020 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000025030 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000025040: 4000000000025040
;;   Called from:
;;     400000000003161C (in fn4000000000030880)
;;     4000000000031A3C (in fn4000000000030880)
;;     40000000000329CC (in fn4000000000030880)
;;     40000000000329CC (in fn4000000000030880)
;;     400000000003479C (in fn4000000000030880)
;;     4000000000034D2C (in fn4000000000030880)
;;     400000000003558C (in fn4000000000030880)
;;     4000000000035A6C (in fn4000000000030880)
fn4000000000025040 proc
	{ nop.m	0x0; addl	r14,264,r0; nop.i	0x0; }
	{ cmp4.eq	p06,p07,r14,r32; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000250E0; }

l4000000000025060:
	{ nop.m	0x0; cmp4.lt	p06,p07,r14,r32; (p07) br.cond.dptk.few	40000000000250F0 }

l4000000000025070:
	{ nop.m	0x0; addl	r14,280,r0; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r14,r32; (p07) br.cond.dptk.few	4000000000025170 }

l4000000000025090:
	{ nop.m	0x0; addl	r14,297,r0; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r14,r32; (p06) br.cond.dptk.few	40000000000252C0 }

l40000000000250B0:
	{ nop.m	0x0; addl	r14,295,r0; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r32,r14; (p07) br.cond.dptk.few	4000000000025360; }

l40000000000250D0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000250E0:
	{ nop.m	0x0; addl	r8,1,r0; br.ret	b0; }

l40000000000250F0:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x29,r32; (p06) br.cond.dptk.few	4000000000025220; }

l4000000000025100:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x27,r32; (p06) br.cond.dptk.few	40000000000250E0; }

l4000000000025110:
	{ cmp4.eq	p06,p07,0xA,r32; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000250E0; }

l4000000000025120:
	{ cmp4.eq	p06,p07,0x26,r32; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000250E0; }

l4000000000025130:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r32; (p06) br.cond.dptk.few	40000000000250E0 }

l4000000000025140:
	{ addl	r14,6740,r1; ld4	r15,[r14]; addl	r14,281,r0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r15; (p07) br.cond.dpnt.few	4000000000025280 }

l4000000000025160:
	{ nop.m	0x0; adds	r8,0x0,r0; br.ret	b0 }

l4000000000025170:
	{ nop.m	0x0; addl	r14,277,r0; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r32,r14; (p06) br.cond.dptk.few	40000000000250E0 }

l4000000000025190:
	{ nop.m	0x0; addl	r14,267,r0; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r32,r14; (p06) br.cond.dptk.few	4000000000025140 }

l40000000000251B0:
	{ nop.m	0x0; addl	r14,270,r0; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r14,r32; (p06) br.cond.dptk.few	40000000000250E0 }

l40000000000251D0:
	{ nop.m	0x0; addl	r14,272,r0; nop.i	0x0; }
	{ cmp4.eq	p06,p07,r14,r32; addl	r14,6740,r1; (p06) br.cond.dpnt.few	40000000000250E0; }

l40000000000251F0:
	{ ld4	r15,[r14]; nop.m	0x0; addl	r14,281,r0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r15; (p06) br.cond.dptk.few	4000000000025160 }

l4000000000025210:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000025280; }

l4000000000025220:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x7D,r32; (p06) br.cond.dptk.few	4000000000025310; }

l4000000000025230:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x7A,r32; (p06) br.cond.dptk.few	40000000000250E0; }

l4000000000025240:
	{ addl	r14,6740,r1; cmp4.eq	p06,p07,0x3B,r32; (p06) br.cond.dpnt.few	40000000000250E0; }

l4000000000025250:
	{ ld4	r15,[r14]; nop.m	0x0; addl	r14,281,r0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r15; (p06) br.cond.dptk.few	4000000000025160; }

l4000000000025270:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000025280:
	{ addl	r14,6732,r1; addl	r15,272,r0; adds	r8,0x0,r0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,r15,r14; addl	r15,271,r0; (p07) br.cond.dpnt.few	40000000000250E0; }

l40000000000252B0:
	{ cmp4.eq	p06,p07,r15,r14; (p06) br.cond.dpnt.few	40000000000250E0; br.ret	b0 }

l40000000000252BC:
	{ nop; cmp.lt	p00,p00,r32,r0; zxt4	r11,r0 }

l40000000000252C0:
	{ nop.m	0x0; addl	r14,303,r0; nop.i	0x0; }
	{ cmp4.eq	p06,p07,r14,r32; addl	r14,6740,r1; (p06) br.cond.dpnt.few	40000000000250E0; }

l40000000000252E0:
	{ ld4	r15,[r14]; nop.m	0x0; addl	r14,281,r0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r15; (p06) br.cond.dptk.few	4000000000025160 }

l4000000000025300:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000025280 }

l4000000000025310:
	{ nop.m	0x0; adds	r32,0xFFFFFFFFFFFFFEFE,r32; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x4,r32; (p07) br.cond.dptk.few	40000000000250E0 }

l4000000000025330:
	{ addl	r14,6740,r1; ld4	r15,[r14]; addl	r14,281,r0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r15; (p06) br.cond.dptk.few	4000000000025160 }

l4000000000025350:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000025280 }

l4000000000025360:
	{ nop.m	0x0; adds	r32,0xFFFFFFFFFFFFFEE0,r32; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x1,r32; (p07) br.cond.dptk.few	40000000000250E0 }

l4000000000025380:
	{ addl	r14,6740,r1; ld4	r15,[r14]; addl	r14,281,r0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r15; (p06) br.cond.dptk.few	4000000000025160 }

l40000000000253A0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000025280; }
40000000000253B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000253C0: 40000000000253C0
;;   Called from:
;;     400000000002594C (in fn4000000000025800)
;;     40000000000295AC (in fn4000000000029100)
;;     4000000000029A5C (in fn4000000000029100)
;;     4000000000029CBC (in fn4000000000029100)
;;     400000000002A1FC (in fn4000000000029100)
;;     400000000002A32C (in fn4000000000029100)
;;     400000000002A52C (in fn4000000000029100)
;;     400000000003E69C (in restore_input_line_state)
fn40000000000253C0 proc
	{ alloc	r42,ar.pfs,0x11,0x0,0xD; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r41,b1 }
	{ addl	r36,6788,r1; adds	r43,0x0,r1; addl	r38,6780,r1; }
	{ ld8	r14,[r36]; adds	r34,0x18,r12; mov	r44,LC }
	{ addl	r32,1,r0; adds	r35,0x0,r0; adds	r33,0x0,r0; }
	{ cmp.eq	p06,p07,0x0,r14; adds	r45,0x0,r14; (p06) br.cond.dpnt.few	4000000000025690; }

l4000000000025410:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ ld8	r45,[r38]; adds	r1,0x0,r43; adds	r37,0x0,r8; }
	{ cmp.eq	p06,p07,0x0,r45; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000025460; }

l4000000000025440:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r43; nop.m	0x0; nop.i	0x0 }

l4000000000025460:
	{ nop.m	0x0; adds	r45,0x1,r37; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r45,r45; br.call.sptk.many	b0,xmalloc; }
	{ adds	r14,0x10,r12; st8	[r8],r38; nop.i	0x0 }
	{ adds	r1,0x0,r43; cmp4.lt	p06,p07,0x0,r37; adds	r39,0x0,r8; }
	{ st8	[r0],r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000025690; }

l40000000000254B0:
	{ ld8	r38,[r36]; st8	[r0],r34; nop.i	0x0; }
	{ adds	r36,0x1,r38; ld1	r14,[r38]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r14; (p06) br.cond.dpnt.few	4000000000025760; }

l40000000000254F0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000025500:
	{ nop.m	0x0; sub	r47,r32,r33; sxt4	r46,r33 }
	{ adds	r45,0x0,r0; adds	r48,0x0,r34; adds	r40,0xFFFFFFFFFFFFFFFF,r32; }
	{ add	r46,r38,r46; sxt4	r47,r47; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ cmp.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; cmp.eq	p08,p09,0xFFFFFFFFFFFFFFFE,r8; adds	r1,0x0,r43 }
	{ adds	r14,0x0,r32; addl	r15,1,r0; cmp.eq.or.andcm	p07,p06,0x1,r8; }
	{ nop.m	0x0; (p07) adds	r33,0x0,r32; (p07) br.cond.dptk.few	40000000000255B0 }

l400000000002555C:
	{ (p03) cmp.eq	p00,p08,r0,r33; (p16) nop; zxt1	r4,r64 }

l4000000000025560:
	{ cmp.ltu	p07,p06,0x1,r8; adds	r17,0x10,r12; nop.i	0x0 }
	{ adds	r14,0x0,r32; adds	r15,0x0,r0; (p08) br.cond.dpnt.few	40000000000256C0; }

l4000000000025580:
	{ adds	r33,0x0,r32; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000256D0; }

l4000000000025590:
	{ nop.m	0x0; ld8	r16,[r34]; nop.i	0x0; }
	{ st8	[r16],r17; nop.m	0x0; nop.i	0x0 }

l40000000000255B0:
	{ add	r16,r39,r35; cmp4.lt	p06,p07,r14,r37; adds	r17,0x1,r32 }
	{ adds	r35,0x0,r32; st1	[r15],r16; adds	r16,0x10,r12 }
	{ adds	r32,0x0,r17; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000025690; }

l40000000000255E0:
	{ ld8	r15,[r16]; st8	[r15],r34; nop.i	0x0; }
	{ ld1	r15,[r36],1; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r15; (p06) br.cond.dptk.few	4000000000025500 }

l4000000000025610:
	{ nop.m	0x0; sxt4	r17,r14; nop.b	0x0 }
	{ adds	r16,0x0,r14; sub	r14,r37,r14,0x1; addl	r15,1,r0; }
	{ add	r39,r39,r17; nop.m	0x0; adds	r16,0x1,r16 }
	{ addp4	r14,r14,r0; movl	r17,0x803FFFFF80000000; }
	{ cmp4.eq	p06,p07,r17,r37; cmp4.lt	p08,p09,r37,r16; mov.i	LC,r14 }
	{ nop.b	0x0; (p08) br.cond.spnt.few	4000000000025770; (p06) br.cond.spnt.few	4000000000025770; }

l400000000002566C:
	{ (p08) nop; break.i	0x1000; break.b	0x1000 }

l4000000000025670:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000025680:
	{ st1	[r39],r1,1; nop.i	0x0; br.cloop.sptk.few	4000000000025680 }

l4000000000025690:
	{ nop.m	0x0; mov.i	ar.pfs,r42; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r44; mov.spnt	b0,r41,40000000000256A0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000256C0:
	{ adds	r14,0x0,r32; adds	r15,0x0,r0; br.cond.sptk.few	40000000000255B0; }

l40000000000256D0:
	{ sub	r15,r37,r40,0x1; movl	r16,0x803FFFFF80000000 }
	{ addl	r14,1,r0; cmp4.lt	p08,p09,r37,r32; sxt4	r40,r40; }
	{ addp4	r15,r15,r0; add	r39,r39,r40; cmp4.eq	p06,p07,r16,r37 }
	{ nop.b	0x0; (p08) br.cond.spnt.few	40000000000257B0; (p06) br.cond.spnt.few	40000000000257B0; }

l400000000002570C:
	{ (p05) nop.m	0x82000; break.i	0x1000; (p48) break.b	0x2A823 }

l4000000000025710:
	{ nop.m	0x0; mov.i	LC,r15; nop.i	0x0; }

l4000000000025720:
	{ st1	[r39],r1,1; nop.i	0x0; br.cloop.sptk.few	4000000000025720 }

l4000000000025730:
	{ nop.m	0x0; mov.i	ar.pfs,r42; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r44; mov.spnt	b0,r41,4000000000025740 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000025760:
	{ nop.m	0x0; adds	r14,0x0,r0; br.cond.sptk.few	4000000000025610 }

l4000000000025770:
	{ nop.m	0x0; mov.i	LC,0x0; nop.i	0x0 }
	{ st1	[r39],r1,1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.cloop.sptk.few	4000000000025680 }

l40000000000257A0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000025690; }

l40000000000257B0:
	{ nop.m	0x0; mov.i	LC,0x0; nop.i	0x0 }
	{ st1	[r39],r1,1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.cloop.sptk.few	4000000000025720 }

l40000000000257E0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000025730; }
40000000000257F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000025800: 4000000000025800
;;   Called from:
;;     4000000000035ADC (in fn4000000000030880)
;;     4000000000035C9C (in fn4000000000030880)
fn4000000000025800 proc
	{ alloc	r39,ar.pfs,0xA,0x0,0x9; nop.m	0x0; mov	r38,b6 }
	{ addl	r35,6824,r1; nop.m	0x0; adds	r40,0x0,r1; }
	{ addl	r41,48,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r40; cmp.eq	p06,p07,0x0,r34; adds	r16,0x10,r34 }
	{ adds	r18,0x8,r8; adds	r25,0x10,r8; adds	r24,0x20,r8; }
	{ addl	r15,6628,r1; addl	r14,6788,r1; addl	r37,6724,r1 }
	{ addl	r36,6828,r1; st4	[r33],r18; adds	r23,0x24,r8; }
	{ ld8	r17,[r15]; adds	r22,0x28,r8; adds	r21,0x18,r8 }
	{ adds	r41,0x0,r32; ld8	r20,[r14]; nop.i	0x0; }
	{ st8	[r17],r8; st8	[r8],r15; nop.i	0x0 }
	{ ld4	r19,[r35]; ld4	r18,[r37]; nop.i	0x0; }
	{ nop.m	0x0; ld4	r17,[r36]; nop.i	0x0 }
	{ st8	[r20],r25; st4	[r19],r24; nop.i	0x0; }
	{ st4	[r18],r23; st4	[r17],r22; nop.i	0x0; }
	{ st8	[r34],r21; st8	[r32],r14; nop.i	0x0; }
	{ (p07) ld1	r15,[r16]; (p07) or	r15,0x2,r15; nop.i	0x0; }

l40000000000258F6:
	{ Invalid; cmp4.eq	p00,p00,r0,r1; (p01) br.call.spnt.many	b0,b3; }

l40000000000258FC:
	{ Invalid; Invalid; break.i	0x1000 }

l4000000000025906:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; nop; nop }
	{ mf.a; nop; nop }
	{ break.m	0x4000; nop; Invalid }
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
4000000000025950 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
4000000000025960 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000025970 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000025980: 4000000000025980
;;   Called from:
;;     40000000000303EC (in yyerror)
;;     400000000003623C (in fn4000000000030880)
;;     4000000000036E4C (in fn4000000000036A40)
;;     4000000000036F1C (in fn4000000000036A40)
;;     400000000003723C (in fn4000000000036A40)
;;     400000000003745C (in fn4000000000036A40)
;;     400000000003783C (in fn4000000000036A40)
fn4000000000025980 proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; addl	r38,-21740,r1; nop.b	0x0 }
	{ adds	r36,0x0,r1; mov	r34,b2; adds	r37,0x0,r32; }
	{ nop.m	0x0; adds	r39,0x0,r0; br.call.sptk.many	b0,find_token_in_alist; }
	{ adds	r1,0x0,r36; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	40000000000259E0 }

l40000000000259C0:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000259D0; br.ret	b0 }

l40000000000259E0:
	{ addl	r38,-22236,r1; adds	r37,0x0,r32; adds	r39,0x0,r0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,find_token_in_alist; }
	{ adds	r1,0x0,r36; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000000259C0; }

l4000000000025A10:
	{ addl	r14,8996,r1; nop.m	0x0; nop.i	0x0; }
	{ ld4	r14,[r14]; adds	r14,0xFFFFFFFFFFFFFEE7,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x5,r14; (p06) br.cond.dptk.few	40000000000259C0 }

l4000000000025A40:
	{ addl	r15,20,r1; nop.m	0x0; addp4	r14,r14,r0; }
	{ ld8	r15,[r15]; shladd	r14,r14,0x3,r15; nop.i	0x0; }
	{ ld8	r15,[r14]; add	r14,r14,r15; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r14,4000000000025A70; br.cond	b6; }
4000000000025A80 09 70 B0 02 B0 24 00 00 00 02 00 C0 C4 EB F3 9F .p...$..........
4000000000025A90 0B 00 00 00 01 00 50 02 38 30 20 00 00 00 04 00 ......P.80 .....
4000000000025AA0 11 30 00 4A 07 39 00 00 00 02 00 03 20 FF FF 4B .0.J.9...... ..K
4000000000025AB0 11 30 01 4C 18 10 00 00 00 02 00 00 18 8D 06 50 .0.L...........P
4000000000025AC0 09 08 00 48 00 21 00 00 00 02 00 00 30 02 AA 00 ...H.!......0...
4000000000025AD0 10 00 00 00 01 00 00 10 05 80 03 80 08 00 84 00 ................
4000000000025AE0 0B 70 B0 02 B0 24 00 00 00 02 00 00 00 00 04 00 .p...$..........
4000000000025AF0 09 00 00 00 01 00 50 02 38 30 20 00 00 00 04 00 ......P.80 .....
4000000000025B00 11 30 00 4A 07 39 00 00 00 02 00 03 C0 FE FF 4B .0.J.9.........K
4000000000025B10 11 00 00 00 01 00 00 00 00 02 00 00 38 91 06 50 ............8..P
4000000000025B20 09 08 00 48 00 21 00 00 00 02 00 00 30 02 AA 00 ...H.!......0...
4000000000025B30 10 00 00 00 01 00 00 10 05 80 03 80 08 00 84 00 ................
4000000000025B40 0B 70 B0 02 B0 24 00 00 00 02 00 00 00 00 04 00 .p...$..........
4000000000025B50 09 00 00 00 01 00 50 02 38 20 20 00 00 00 04 00 ......P.8  .....
4000000000025B60 11 00 00 00 01 00 50 02 94 2C 00 00 68 3F 10 50 ......P..,..h?.P
4000000000025B70 09 08 00 48 00 21 00 00 00 02 00 00 30 02 AA 00 ...H.!......0...
4000000000025B80 10 00 00 00 01 00 00 10 05 80 03 80 08 00 84 00 ................
4000000000025B90 0B 08 B1 02 B0 24 00 00 00 02 00 00 00 00 04 00 .....$..........
4000000000025BA0 09 00 00 00 01 00 E0 00 84 30 20 00 00 00 04 00 .........0 .....
4000000000025BB0 11 30 00 1C 07 39 00 00 00 02 00 03 10 FE FF 4B .0...9.........K
4000000000025BC0 11 28 01 1C 18 10 00 00 00 02 00 00 08 5B FF 58 .(...........[.X
4000000000025BD0 11 08 00 48 00 21 50 0A 20 00 42 00 F8 30 0C 50 ...H.!P. .B..0.P
4000000000025BE0 09 70 00 42 18 10 10 00 90 00 42 A0 04 40 00 84 .p.B......B..@..
4000000000025BF0 11 30 01 1C 18 10 00 00 00 02 00 00 98 55 FF 58 .0...........U.X
4000000000025C00 09 08 00 48 00 21 00 00 00 02 00 00 30 02 AA 00 ...H.!......0...
4000000000025C10 11 00 00 00 01 00 00 10 05 80 03 80 08 00 84 00 ................
4000000000025C20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000025C30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; return_EOF: 4000000000025C40
return_EOF proc
	{ nop.m	0x0; addl	r8,-1,r0; br.ret	b0; }
4000000000025C50 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000025C60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000025C70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; initialize_bash_input: 4000000000025C80
initialize_bash_input proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; addl	r32,22532,r1; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; nop.i	0x0; }
	{ adds	r14,0x0,r32; st4	[r14],r8,8; nop.i	0x0; }
	{ nop.m	0x0; ld8	r36,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r36; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000025CF0; }

l4000000000025CD0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l4000000000025CF0:
	{ adds	r16,0x8,r32; adds	r15,0x10,r32; nop.b	0x0 }
	{ adds	r14,0x18,r32; adds	r32,0x20,r32; mov.i	ar.pfs,r34; }
	{ st8	[r0],r16; st8	[r0],r15; mov.spnt	b0,r33,4000000000025D10; }
	{ nop.m	0x0; st8	[r0],r14; nop.i	0x0 }
	{ st8	[r0],r32; nop.m	0x0; br.ret	b0; }

;; init_yy_io: 4000000000025D40
;;   Called from:
;;     4000000000025FEC (in with_input_from_stdin)
;;     400000000002607C (in with_input_from_string)
;;     40000000000260FC (in with_input_from_stream)
;;     40000000000263AC (in pop_stream)
;;     40000000000B1A3C (in with_input_from_buffered_stream)
init_yy_io proc
	{ alloc	r39,ar.pfs,0xB,0x0,0x9; addl	r37,22532,r1; nop.b	0x0 }
	{ adds	r40,0x0,r1; nop.m	0x0; mov	r38,b6; }
	{ nop.m	0x0; adds	r14,0x0,r37; nop.i	0x0; }
	{ st4	[r14],r8,8; ld8	r41,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r41; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000025DB0; }

l4000000000025D90:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r40; nop.m	0x0; nop.i	0x0 }

l4000000000025DB0:
	{ cmp.eq	p06,p07,0x0,r35; nop.m	0x0; adds	r41,0x0,r35; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000025E20; }

l4000000000025DC6:
	{ chk.a.nc	r0,3FFFFFFFFF0265C6; nop; break.i	0x80000 }

l4000000000025DD0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r40; adds	r41,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r41,0x0,r8 }
	{ adds	r42,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r40; nop.m	0x0; nop.i	0x0 }

l4000000000025E20:
	{ adds	r16,0x8,r37; adds	r15,0x10,r37; nop.b	0x0 }
	{ adds	r14,0x18,r37; adds	r37,0x20,r37; mov.i	ar.pfs,r39; }
	{ st8	[r8],r16; st8	[r36],r15; mov.spnt	b0,r38,4000000000025E40; }
	{ nop.m	0x0; st8	[r32],r14; nop.i	0x0 }
	{ st8	[r33],r37; nop.m	0x0; br.ret	b0; }
4000000000025E70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; yy_input_name: 4000000000025E80
;;   Called from:
;;     400000000007146C (in parser_error)
;;     40000000000DC11C (in localeexpand)
yy_input_name proc
	{ addl	r14,22532,r1; nop.m	0x0; nop.i	0x0; }
	{ adds	r14,0x8,r14; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r14; (p07) addl	r8,-444,r1; nop.i	0x0; }

l4000000000025EAC:
	{ nop; mov	pr,r32,0x0; zxt1	r64,r64 }

l4000000000025EBC:
	{ Invalid; Invalid; add	r0,r32,r0 }

l4000000000025EC6:
	{ break.m	0x4000; (p34) nop; break.i	0x80000 }
4000000000025ED0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000025EE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000025EF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; with_input_from_stdin: 4000000000025F00
;;   Called from:
;;     4000000000020F8C (in main)
with_input_from_stdin proc
	{ alloc	r33,ar.pfs,0x8,0x0,0x3; addl	r14,22532,r1; mov	r32,b0 }
	{ adds	r34,0x0,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x1,r14; addl	r14,6636,r1; (p06) br.cond.dpnt.few	4000000000026000; }

l4000000000025F40:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ adds	r15,0x8,r14; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	4000000000025FA0; }

l4000000000025F60:
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x1,r15; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000026000; }

l4000000000025F80:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ adds	r15,0x8,r14; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000025F60 }

l4000000000025FA0:
	{ addl	r35,12,r1; addl	r36,-500,r1; nop.i	0x0 }
	{ addl	r14,6660,r1; addl	r38,-436,r1; addl	r37,1,r0; }
	{ ld8	r35,[r35]; ld8	r36,[r36]; nop.i	0x0; }
	{ nop.m	0x0; ld8	r39,[r14]; nop.i	0x0 }
	{ ld8	r38,[r38]; nop.m	0x0; br.call.sptk.many	b0,init_yy_io; }
	{ adds	r1,0x0,r34; nop.m	0x0; nop.i	0x0 }

l4000000000026000:
	{ nop.m	0x0; mov.i	ar.pfs,r33; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r32,4000000000026010; br.ret	b0; }
4000000000026020 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000026030 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; with_input_from_string: 4000000000026040
;;   Called from:
;;     400000000003D84C (in parse_string_to_word_list)
;;     40000000000F642C (in parse_and_execute)
;;     40000000000F766C (in parse_string)
with_input_from_string proc
	{ alloc	r35,ar.pfs,0xA,0x0,0x5; addl	r37,-492,r1; mov	r34,b2 }
	{ addl	r38,-484,r1; adds	r36,0x0,r1; adds	r40,0x0,r33; }
	{ nop.m	0x0; ld8	r37,[r37]; addl	r39,3,r0 }
	{ adds	r41,0x0,r32; ld8	r38,[r38]; br.call.sptk.many	b0,init_yy_io; }
	{ adds	r1,0x0,r36; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000026090; br.ret	b0; }
40000000000260A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000260B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; with_input_from_stream: 40000000000260C0
;;   Called from:
;;     400000000002011C (in main)
with_input_from_stream proc
	{ alloc	r35,ar.pfs,0xA,0x0,0x5; addl	r37,4,r1; mov	r34,b2 }
	{ addl	r38,-4,r1; adds	r36,0x0,r1; adds	r40,0x0,r33; }
	{ nop.m	0x0; ld8	r37,[r37]; addl	r39,2,r0 }
	{ adds	r41,0x0,r32; ld8	r38,[r38]; br.call.sptk.many	b0,init_yy_io; }
	{ adds	r1,0x0,r36; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000026110; br.ret	b0; }
4000000000026120 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000026130 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; push_stream: 4000000000026140
;;   Called from:
;;     400000000003D80C (in parse_string_to_word_list)
;;     40000000000F637C (in parse_and_execute)
;;     40000000000F761C (in parse_string)
push_stream proc
	{ alloc	r37,ar.pfs,0xA,0x0,0x7; addl	r34,22532,r1; nop.b	0x0 }
	{ adds	r38,0x0,r1; nop.m	0x0; mov	r36,b4; }
	{ nop.m	0x0; addl	r39,64,r0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r38; adds	r35,0x38,r8; adds	r33,0x0,r8 }
	{ adds	r39,0x0,r34; adds	r40,0x8,r8; addl	r41,40,r0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,xbcopy; }
	{ nop.m	0x0; ld4	r14,[r34]; adds	r1,0x0,r38 }
	{ nop.m	0x0; st8	[r0],r35; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x4,r14; (p07) br.cond.dpnt.few	4000000000026240; }

l40000000000261D0:
	{ addl	r14,6636,r1; addl	r15,6648,r1; mov.i	ar.pfs,r37 }
	{ adds	r34,0x8,r34; adds	r18,0x30,r33; cmp4.eq	p06,p07,0x0,r32; }
	{ ld8	r16,[r14]; st8	[r0],r34; mov.spnt	b0,r36,40000000000261F0 }
	{ nop.m	0x0; ld4	r17,[r15]; nop.i	0x0; }
	{ st8	[r16],r33; st8	[r33],r14; addl	r14,6676,r1; }
	{ st4	[r17],r18; st4	[r0],r14; nop.i	0x0; }
	{ (p07) st4	[r0],r15; nop.i	0x0; br.ret	b0 }

l4000000000026236:
	{ break.m	0x4000; (p34) nop; (p32) nop }

l4000000000026240:
	{ adds	r14,0x10,r34; nop.m	0x0; adds	r40,0x0,r0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.lt	p06,p07,r14,r0; adds	r39,0x0,r14; (p06) br.cond.dpnt.few	40000000000261D0; }

l4000000000026270:
	{ adds	r34,0x8,r34; nop.i	0x0; br.call.sptk.many	b0,set_buffered_stream; }
	{ adds	r1,0x0,r38; adds	r18,0x30,r33; mov.i	ar.pfs,r37 }
	{ st8	[r0],r34; st8	[r8],r35; cmp4.eq	p06,p07,0x0,r32; }
	{ addl	r14,6636,r1; addl	r15,6648,r1; mov.spnt	b0,r36,40000000000262A0; }
	{ ld8	r16,[r14]; ld4	r17,[r15]; nop.i	0x0; }
	{ st8	[r16],r33; st8	[r33],r14; addl	r14,6676,r1; }
	{ st4	[r17],r18; st4	[r0],r14; nop.i	0x0; }
	{ (p07) st4	[r0],r15; nop.i	0x0; br.ret	b0; }

l40000000000262E6:
	{ break.m	0x4000; (p34) nop; break.i	0x80000 }
40000000000262F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; pop_stream: 4000000000026300
;;   Called from:
;;     400000000003D97C (in parse_string_to_word_list)
;;     400000000003DB4C (in parse_string_to_word_list)
pop_stream proc
	{ alloc	r37,ar.pfs,0xC,0x0,0x7; addl	r15,6636,r1; mov	r36,b4 }
	{ addl	r20,6676,r1; nop.m	0x0; adds	r38,0x0,r1; }
	{ ld8	r32,[r15]; cmp.eq	p07,p06,0x0,r32; adds	r19,0x28,r32 }
	{ adds	r18,0x8,r32; adds	r33,0x10,r32; adds	r17,0x18,r32; }
	{ (p07) addl	r15,1,r0; nop.m	0x0; (p07) addl	r14,6676,r1; }

l4000000000026346:
	{ chk.a.nc	f0,3FFFFFFFFF026B46; (p07) cmp4.eq.or.andcm	p20,p08,r1,r52; (p01) nop }

l4000000000026350:
	{ (p07) st4	[r15],r14; adds	r14,0x0,r32; (p07) br.cond.dpnt.few	4000000000026450; }

l4000000000026356:
	{ (p07) chk.a.clr	f0,3FFFFFFFFF0A6556; nop; nop }

l4000000000026360:
	{ ld8	r16,[r14],32; st4	[r0],r20; nop.i	0x0 }
	{ ld8	r40,[r19]; st8	[r16],r15; nop.i	0x0 }
	{ ld8	r39,[r14]; ld4	r41,[r18]; nop.i	0x0; }
	{ nop.m	0x0; ld8	r42,[r33]; nop.i	0x0 }
	{ ld8	r43,[r17]; nop.m	0x0; br.call.sptk.many	b0,init_yy_io; }
	{ adds	r1,0x0,r38; addl	r14,22532,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x4,r15; (p07) br.cond.dpnt.few	4000000000026470 }

l40000000000263E0:
	{ adds	r14,0x30,r32; ld8	r39,[r33]; nop.i	0x0; }
	{ ld4	r15,[r14]; cmp.eq	p06,p07,0x0,r39; addl	r14,6648,r1; }
	{ nop.m	0x0; st4	[r15],r14; nop.i	0x0 }
	{ nop.b	0x0; (p06) br.cond.dpnt.few	4000000000026430; br.call.sptk.many	b0,fn400000000001A7E0; }

l400000000002641C:
	{ (p30) nop; invala; break.b	0x1000 }
	{ Invalid; cmp.eq	p00,p00,r32,r0; zxt1	r0,r64 }

l4000000000026430:
	{ nop.m	0x0; adds	r39,0x0,r32; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r38; nop.m	0x0; nop.i	0x0 }

l4000000000026450:
	{ nop.m	0x0; mov.i	ar.pfs,r37; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r36,4000000000026460; br.ret	b0 }

l4000000000026470:
	{ adds	r34,0x10,r14; nop.m	0x0; addl	r14,9136,r1; }
	{ nop.m	0x0; ld4	r39,[r34]; nop.i	0x0; }
	{ cmp4.lt	p06,p07,r39,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000263E0; }

l40000000000264A0:
	{ nop.m	0x0; ld4	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; nop.i	0x0; }
	{ nop.m	0x0; (p06) adds	r35,0x38,r32; (p06) br.cond.dptk.few	4000000000026540; }

l40000000000264CC:
	{ (p04) nop; break.i	0x1000; cmp.lt.unc	p00,p08,r3,r100 }

l40000000000264D0:
	{ nop.m	0x0; st4	[r0],r14; addl	r14,5636,r1 }
	{ adds	r35,0x38,r32; addl	r40,2,r0; addl	r41,1,r0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.lt	p06,p07,r14,r0; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000026540; }

l4000000000026510:
	{ ld8	r15,[r35]; st4	[r14],r34; adds	r39,0x0,r14; }
	{ st4	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B7E0; }
	{ adds	r1,0x0,r38; ld4	r39,[r34]; nop.i	0x0 }

l4000000000026540:
	{ ld8	r40,[r35]; nop.i	0x0; br.call.sptk.many	b0,set_buffered_stream; }
	{ nop.m	0x0; adds	r1,0x0,r38; br.cond.sptk.few	40000000000263E0; }
4000000000026560 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000026570 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; stream_on_stack: 4000000000026580
stream_on_stack proc
	{ addl	r14,6636,r1; ld8	r14,[r14]; nop.i	0x0; }
	{ adds	r15,0x8,r14; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	40000000000265E0; }

l40000000000265A0:
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,r32,r15; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000265F0; }

l40000000000265C0:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ adds	r15,0x8,r14; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000265A0 }

l40000000000265E0:
	{ nop.m	0x0; adds	r8,0x0,r0; br.ret	b0; }

l40000000000265F0:
	{ nop.m	0x0; addl	r8,1,r0; br.ret	b0; }

;; save_token_state: 4000000000026600
;;   Called from:
;;     400000000003DCCC (in save_parser_state)
;;     40000000000AC8CC (in fn40000000000AC6C0)
;;     40000000000AF2DC (in run_pending_traps)
save_token_state proc
	{ alloc	r33,ar.pfs,0x4,0x0,0x3; mov	r32,b0; adds	r34,0x0,r1; }
	{ addl	r35,16,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r34; adds	r14,0x0,r8; nop.b	0x0 }
	{ adds	r15,0xC,r8; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ addl	r16,6740,r1; addl	r17,6732,r1; mov.spnt	b0,r32,4000000000026640; }
	{ ld4	r16,[r16]; ld4	r19,[r17]; adds	r17,0x8,r8; }
	{ st4	[r14],r4,4; nop.m	0x0; addl	r16,6736,r1; }
	{ nop.m	0x0; ld4	r18,[r16]; addl	r16,8996,r1 }
	{ st4	[r19],r14; nop.m	0x0; nop.i	0x0 }
	{ st4	[r18],r17; ld4	r16,[r16]; nop.i	0x0; }
	{ st4	[r16],r15; nop.i	0x0; br.ret	b0; }
40000000000266B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; restore_token_state: 40000000000266C0
;;   Called from:
;;     40000000000AC9CC (in fn40000000000AC6C0)
;;     40000000000ACC2C (in fn40000000000AC6C0)
;;     40000000000AF37C (in run_pending_traps)
restore_token_state proc
	{ adds	r14,0x0,r32; adds	r16,0x8,r32; nop.i	0x0 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r15,0xC,r32; (p06) br.ret	b0; }

l40000000000266E0:
	{ ld4	r18,[r14],4; ld4	r17,[r16]; nop.i	0x0; }
	{ nop.m	0x0; ld4	r16,[r14]; addl	r14,6740,r1 }
	{ ld4	r15,[r15]; st4	[r18],r14; addl	r14,6736,r1; }
	{ st4	[r17],r14; nop.m	0x0; addl	r14,6732,r1; }
	{ st4	[r16],r14; nop.m	0x0; addl	r14,8996,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.ret	b0; }
4000000000026750 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000026760 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000026770 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; free_pushed_string_input: 4000000000026780
;;   Called from:
;;     40000000000948FC (in command_substitute)
;;     40000000000A520C (in fn40000000000A1400)
free_pushed_string_input proc
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.many	fn4000000000024640; }
4000000000026790 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000267A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000267B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; gather_here_documents: 40000000000267C0
;;   Called from:
;;     40000000000236EC (in parse_command)
;;     4000000000035E0C (in fn4000000000030880)
gather_here_documents proc
	{ alloc	r39,ar.pfs,0xB,0x0,0x9; addl	r33,9000,r1; nop.b	0x0 }
	{ addl	r32,8944,r1; addl	r34,9324,r1; mov	r38,b6; }
	{ nop.m	0x0; adds	r40,0x0,r1; addl	r36,131072,r0 }
	{ addl	r37,-131073,r0; nop.m	0x0; addl	r35,6648,r1; }
	{ nop.m	0x0; ld4	r14,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000268B0; }

l4000000000026820:
	{ ld4	r16,[r32]; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000026840:
	{ nop.m	0x0; or	r16,r36,r16; nop.i	0x0 }
	{ ld8	r41,[r34],8; ld4	r42,[r35]; nop.i	0x0; }
	{ st4	[r16],r32; nop.i	0x0; br.call.sptk.many	b0,make_here_document; }
	{ nop.m	0x0; ld4	r15,[r32]; adds	r1,0x0,r40 }
	{ ld4	r14,[r33]; and	r15,r37,r15; adds	r14,0xFFFFFFFFFFFFFFFF,r14; }
	{ adds	r16,0x0,r15; st4	[r15],r32; nop.i	0x0 }
	{ st4	[r14],r33; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000026840 }

l40000000000268B0:
	{ nop.m	0x0; mov.i	ar.pfs,r39; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000268C0; br.ret	b0; }
40000000000268D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000268E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000268F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; reset_parser: 4000000000026900
;;   Called from:
;;     40000000000303AC (in yyerror)
;;     40000000000304FC (in yyerror)
;;     400000000003E79C (in xparse_dolparen)
;;     40000000000AEB2C (in run_exit_trap)
;;     40000000000B469C (in throw_to_top_level)
;;     40000000000F7A5C (in parse_string)
reset_parser proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; addl	r14,8944,r1; addl	r17,9308,r1 }
	{ addl	r16,6628,r1; adds	r36,0x0,r1; addl	r33,6788,r1; }
	{ nop.m	0x0; addl	r32,6756,r1; mov	r34,b2 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ adds	r17,0x8,r17; ld8	r16,[r16]; nop.i	0x0; }
	{ ld4	r15,[r14]; st4	[r0],r17; addl	r17,6816,r1 }
	{ st4	[r0],r14; nop.i	0x0; tbit.z	p06,p07,r15,0xC }
	{ nop.m	0x0; st4	[r0],r17; nop.i	0x0; }
	{ (p07) addl	r15,6772,r1; (p07) ld4	r17,[r15]; (p07) addl	r15,7664,r1; }

l4000000000026986:
	{ (p08) addp4	r0,0xFFFFFFFFFFFFF00F,r16; (p07) nop; break.b	0x80000; }

l400000000002698C:
	{ (p56) nop; break.i	0x1000; break.i	0x1000; }

l4000000000026990:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ (p07) st4	[r17],r15; cmp.eq	p06,p07,0x0,r16; (p06) br.cond.dpnt.few	40000000000269D0; }

l40000000000269A6:
	{ (p03) chk.a.clr	r0,3FFFFFFFFFCAA2A6; nop; break.i	0x80000 }

l40000000000269B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000024640; }
	{ adds	r1,0x0,r36; nop.m	0x0; nop.i	0x0 }

l40000000000269D0:
	{ nop.m	0x0; ld8	r14,[r33]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; adds	r37,0x0,r14; (p06) br.cond.dpnt.few	4000000000026A30; }

l40000000000269F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r36; st8	[r0],r33; nop.i	0x0; }
	{ addl	r14,6724,r1; st4	[r0],r14; addl	r14,6824,r1 }
	{ nop.m	0x0; st4	[r0],r14; nop.i	0x0 }

l4000000000026A30:
	{ nop.m	0x0; ld8	r37,[r32]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r37; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000026A70; }

l4000000000026A50:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r36; nop.m	0x0; nop.i	0x0; }

l4000000000026A70:
	{ addl	r15,8996,r1; addl	r14,10,r0; nop.b	0x0 }
	{ st8	[r0],r32; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; nop.m	0x0; mov.spnt	b0,r34,4000000000026A90; }
	{ st4	[r14],r15; nop.m	0x0; addl	r15,6740,r1; }
	{ st4	[r14],r15; nop.m	0x0; addl	r15,6728,r1; }
	{ st4	[r14],r15; nop.i	0x0; br.ret	b0; }
4000000000026AD0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000026AE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000026AF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; find_reserved_word: 4000000000026B00
;;   Called from:
;;     400000000010E8FC (in describe_command)
find_reserved_word proc
	{ alloc	r37,ar.pfs,0x9,0x0,0x7; addl	r14,-21740,r1; mov	r36,b4 }
	{ adds	r38,0x0,r1; nop.m	0x0; adds	r34,0x0,r0; }
	{ ld8	r40,[r14]; nop.m	0x0; addl	r14,5660,r1; }
	{ cmp.eq	p06,p07,0x0,r40; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000026BA0; }

l4000000000026B40:
	{ ld1	r35,[r32]; ld8	r33,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r35,r35; nop.i	0x0; }

l4000000000026B60:
	{ ld1	r14,[r40]; adds	r33,0x10,r33; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,r14,r35; adds	r14,0xFFFFFFFFFFFFFFF0,r33; (p07) br.cond.dpnt.few	4000000000026BD0; }

l4000000000026B80:
	{ ld8	r40,[r14]; nop.m	0x0; adds	r34,0x1,r34; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r40; (p06) br.cond.dptk.few	4000000000026B60 }

l4000000000026BA0:
	{ addl	r34,-1,r0; nop.m	0x0; nop.i	0x0; }

l4000000000026BB0:
	{ adds	r8,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,4000000000026BC0; br.ret	b0; }

l4000000000026BD0:
	{ adds	r39,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r14,0xFFFFFFFFFFFFFFF0,r33; nop.m	0x0; adds	r1,0x0,r38 }
	{ cmp4.eq	p06,p07,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000026BB0; }

l4000000000026C00:
	{ ld8	r40,[r14]; nop.m	0x0; adds	r34,0x1,r34; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r40; (p06) br.cond.dptk.few	4000000000026B60 }

l4000000000026C20:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000026BA0; }
4000000000026C30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; history_delimiting_chars: 4000000000026C40
;;   Called from:
;;     4000000000029B4C (in fn4000000000029100)
;;     40000000000C896C (in bash_add_history)
history_delimiting_chars proc
	{ alloc	r37,ar.pfs,0x9,0x0,0x7; addl	r14,8944,r1; mov	r36,b4 }
	{ adds	r38,0x0,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r33,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r33,0x11; (p07) br.cond.dptk.few	4000000000026D20 }

l4000000000026C80:
	{ addl	r14,9308,r1; addl	r8,-460,r1; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,4000000000026C90; adds	r14,0x8,r14; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; addl	r14,6844,r1; (p06) br.cond.dpnt.few	4000000000026E50; }

l4000000000026CC0:
	{ nop.m	0x0; ld4	r15,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r15; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000026E40; }

l4000000000026CE0:
	{ addl	r14,8952,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x2,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000026E50; }

l4000000000026D10:
	{ ld8	r8,[r8]; nop.i	0x0; br.ret	b0 }

l4000000000026D20:
	{ addl	r14,9308,r1; nop.m	0x0; addl	r35,6844,r1; }
	{ nop.m	0x0; st4	[r0],r35; nop.i	0x0; }
	{ adds	r14,0x8,r14; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; addl	r14,6732,r1; (p07) br.cond.dpnt.few	4000000000026E50; }

l4000000000026D60:
	{ nop.m	0x0; tbit.z	p07,p06,r33,0xD; (p06) br.cond.dpnt.few	4000000000026EC0; }

l4000000000026D70:
	{ ld4	r34,[r14]; nop.m	0x0; addl	r14,281,r0; }
	{ cmp4.eq	p07,p06,0x29,r34; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000026FB0; }

l4000000000026D90:
	{ cmp4.eq	p07,p06,r14,r34; addl	r14,8952,r1; (p07) br.cond.dpnt.few	4000000000027010; }

l4000000000026DA0:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,0x1,r14; (p06) br.cond.dpnt.few	4000000000026F00 }

l4000000000026DC0:
	{ addl	r14,6740,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0xA,r14; (p06) br.cond.dptk.few	4000000000026F00 }

l4000000000026DE0:
	{ addl	r40,-396,r1; nop.m	0x0; adds	r39,0x0,r32; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A3C0; }
	{ adds	r1,0x0,r38; cmp.eq	p06,p07,0x0,r8; nop.b	0x0 }
	{ addl	r14,1,r0; mov.i	ar.pfs,r37; (p06) br.cond.dpnt.few	4000000000026F00; }

l4000000000026E20:
	{ addl	r8,-428,r1; st4	[r14],r35; mov.spnt	b0,r36,4000000000026E20; }
	{ ld8	r8,[r8]; nop.i	0x0; br.ret	b0 }

l4000000000026E40:
	{ st4	[r0],r14; nop.m	0x0; nop.i	0x0; }

l4000000000026E50:
	{ addl	r8,-428,r1; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ ld8	r8,[r8]; mov.spnt	b0,r36,4000000000026E60; br.ret	b0 }

l4000000000026E70:
	{ addl	r14,6736,r1; nop.m	0x0; addl	r15,265,r0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,r15,r14; addl	r15,263,r0; (p07) br.cond.dpnt.few	4000000000027080; }

l4000000000026EA0:
	{ nop.m	0x0; cmp4.eq	p06,p07,r15,r14; (p07) br.cond.dptk.few	4000000000026F30; }

l4000000000026EB0:
	{ nop.m	0x0; tbit.z	p07,p06,r33,0x7; (p07) br.cond.dptk.few	4000000000026F30; }

l4000000000026EC0:
	{ nop.m	0x0; addl	r8,-420,r1; nop.i	0x0; }
	{ ld8	r8,[r8]; nop.m	0x0; nop.i	0x0 }

l4000000000026EE0:
	{ nop.m	0x0; mov.i	ar.pfs,r37; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r36,4000000000026EF0; br.ret	b0 }

l4000000000026F00:
	{ nop.m	0x0; addl	r14,281,r0; nop.i	0x0; }
	{ cmp4.eq	p07,p06,r14,r34; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000026E70; }

l4000000000026F20:
	{ nop.m	0x0; cmp4.eq	p06,p07,0xA,r34; (p06) br.cond.dpnt.few	4000000000026EC0 }

l4000000000026F30:
	{ nop.m	0x0; addl	r14,5668,r1; nop.i	0x0; }
	{ ld8	r15,[r14]; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000026F60:
	{ nop.m	0x0; ld4	r14,[r15],4; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000027060; }

l4000000000026F80:
	{ nop.m	0x0; cmp4.eq	p06,p07,r14,r34; (p07) br.cond.dptk.few	4000000000026F60 }

l4000000000026F90:
	{ nop.m	0x0; addl	r8,-420,r1; nop.i	0x0; }
	{ ld8	r8,[r8]; nop.i	0x0; br.cond.sptk.few	4000000000026EE0 }

l4000000000026FB0:
	{ addl	r14,6736,r1; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ ld4	r14,[r14]; nop.m	0x0; mov.spnt	b0,r36,4000000000026FC0; }
	{ cmp4.eq	p06,p07,0x28,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000026EC0; }

l4000000000026FE0:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x7; (p06) addl	r8,-404,r1; }

l4000000000026FF0:
	{ (p07) addl	r8,-420,r1; (p06) ld8	r8,[r8]; nop.i	0x0; }

l4000000000026FF6:
	{ (p04) fwb; cmp.eq	p00,p00,r0,r1; (p01) nop; }

l4000000000026FFC:
	{ Invalid; Invalid; add	r0,r32,r0 }

l4000000000027006:
	{ break.m	0x4000; (p34) nop; (p32) nop }

l4000000000027010:
	{ addl	r14,6736,r1; ld4	r15,[r14]; addl	r14,271,r0; }
	{ cmp4.eq	p06,p07,r14,r15; addl	r14,8952,r1; (p06) br.cond.dpnt.few	4000000000026EC0; }

l4000000000027030:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,0x1,r14; (p07) br.cond.dptk.few	4000000000026DC0 }

l4000000000027050:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000026F00 }

l4000000000027060:
	{ addl	r8,-404,r1; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ ld8	r8,[r8]; mov.spnt	b0,r36,4000000000027070; br.ret	b0 }

l4000000000027080:
	{ addl	r14,6724,r1; ld4	r16,[r14]; addl	r14,6788,r1; }
	{ ld8	r17,[r14]; sxt4	r16,r16; add	r14,r17,r16 }
	{ add	r15,r17,r16,0x1; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x20,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x9,r14; (p06) br.cond.dpnt.few	4000000000027110; }

l40000000000270D0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000270E0:
	{ sub	r16,r15,r17; ld1	r14,[r15],1; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x20,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x9,r14; (p06) br.cond.dptk.few	40000000000270E0; }

l4000000000027110:
	{ nop.m	0x0; addl	r8,-412,r1; cmp4.eq	p06,p07,0x69,r14 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000027160; }

l4000000000027130:
	{ ld8	r8,[r8]; nop.m	0x0; nop.i	0x0 }

l4000000000027140:
	{ nop.m	0x0; mov.i	ar.pfs,r37; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r36,4000000000027150; br.ret	b0 }

l4000000000027160:
	{ add	r16,r17,r16,0x1; nop.m	0x0; addl	r8,-412,r1; }
	{ ld1	r14,[r16]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x6E,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000026EC0; }

l4000000000027190:
	{ ld8	r8,[r8]; nop.i	0x0; br.cond.sptk.few	4000000000027140; }
40000000000271A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000271B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; get_current_prompt_level: 40000000000271C0
;;   Called from:
;;     40000000000F612C (in fn40000000000F5E00)
get_current_prompt_level proc
	{ addl	r14,8988,r1; nop.m	0x0; addl	r15,8964,r1; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000027220; }

l40000000000271F0:
	{ nop.m	0x0; ld8	r15,[r15]; nop.i	0x0; }
	{ cmp.eq	p07,p06,r15,r14; (p06) addl	r8,1,r0; nop.i	0x0; }

l400000000002720C:
	{ Invalid; mov	pr,r32,0x0; (p33) shladd	r0,r0,0x3,r0 }

l400000000002721C:
	{ Invalid; break.m	0x1000; (p17) shladd	r0,r0,0x3,r0 }

l4000000000027220:
	{ nop.m	0x0; addl	r8,1,r0; br.ret	b0; }
4000000000027230 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; set_current_prompt_level: 4000000000027240
;;   Called from:
;;     40000000000238AC (in read_command)
set_current_prompt_level proc
	{ cmp4.eq	p07,p06,0x2,r32; addl	r14,6684,r1; (p06) addl	r32,8972,r1; }

l4000000000027250:
	{ (p07) addl	r32,8964,r1; nop.m	0x0; nop.i	0x0; }

l4000000000027256:
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ mf.a; (p07) nop; break.i	0x80000 }
	{ (p07) fwb; nop; br.call.spnt.many	b0,b3 }
	{ break.m	0x4000; (p34) nop; break.i	0x80000 }
4000000000027290 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000272A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000272B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; decode_prompt_string: 40000000000272C0
;;   Called from:
;;     4000000000028F8C (in fn4000000000028E40)
;;     4000000000047D6C (in indirection_level_string)
decode_prompt_string proc
	{ alloc	r62,ar.pfs,0x26,0x0,0x20; adds	r12,0xFFFFFFFFFFFFEF60,r12; nop.b	0x0 }
	{ adds	r63,0x0,r1; addl	r41,5692,r1; mov	r61,b5; }
	{ addl	r14,48,r0; adds	r37,0x10A0,r12; addl	r64,48,r0 }
	{ adds	r36,0x109C,r12; addl	r45,92,r0; addl	r60,13,r0; }
	{ st4	[r14],r37; addl	r59,27,r0; addl	r58,7,r0 }
	{ addl	r54,1,r0; addl	r57,46,r0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r63; st4	[r0],r36; adds	r35,0x0,r8 }
	{ st1	[r0],r8; addl	r56,37,r0; addl	r55,88,r0; }
	{ addl	r14,-22276,r1; addl	r38,6456,r1; addl	r42,28,r1 }
	{ addl	r43,6468,r1; addl	r51,-10356,r1; addl	r50,5644,r1; }
	{ nop.m	0x0; addl	r46,6524,r1; addl	r49,6092,r1 }
	{ addl	r52,6088,r1; nop.m	0x0; addl	r48,6476,r1; }
	{ ld8	r42,[r42]; nop.m	0x0; adds	r53,0x4,r14 }
	{ adds	r44,0x10,r14; nop.m	0x0; nop.i	0x0; }
	{ ld8	r51,[r51]; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000273D0:
	{ adds	r33,0x0,r32; ld1	r14,[r33],1; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ adds	r34,0x0,r14; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	4000000000027550 }

l4000000000027400:
	{ nop.m	0x0; ld4	r15,[r38]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	4000000000027430; }

l4000000000027420:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x21,r34; (p07) br.cond.dpnt.few	40000000000276E0; }

l4000000000027430:
	{ cmp4.eq	p07,p06,0x5C,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000027780; }

l4000000000027440:
	{ ld4	r16,[r36]; ld4	r65,[r37]; nop.i	0x0; }
	{ nop.m	0x0; adds	r15,0x3,r16; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r15,r65; (p06) br.cond.dptk.few	40000000000274E0; }

l4000000000027470:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000027480:
	{ nop.m	0x0; adds	r65,0x30,r65; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r15,r65; (p06) br.cond.dptk.few	4000000000027480 }

l40000000000274A0:
	{ st4	[r65],r37; nop.m	0x0; adds	r64,0x0,r35 }
	{ nop.m	0x0; sxt4	r65,r65; br.call.sptk.many	b0,xrealloc; }
	{ adds	r1,0x0,r63; nop.m	0x0; adds	r35,0x0,r8 }
	{ ld4	r16,[r36]; nop.m	0x0; nop.i	0x0; }

l40000000000274E0:
	{ adds	r14,0x1,r16; sxt4	r16,r16; adds	r32,0x0,r33; }
	{ nop.m	0x0; sxt4	r15,r14; add	r16,r35,r16 }
	{ adds	r33,0x0,r32; add	r15,r35,r15; nop.i	0x0 }
	{ st1	[r34],r16; st4	[r14],r36; nop.i	0x0; }
	{ st1	[r0],r15; ld1	r14,[r33],1; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ adds	r34,0x0,r14; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000027400 }

l4000000000027550:
	{ nop.m	0x0; addl	r15,116,r1; addl	r33,9308,r1 }
	{ ld4	r18,[r41]; ld8	r15,[r15]; cmp4.eq	p07,p06,0x0,r18 }
	{ nop.m	0x0; adds	r14,0x0,r33; adds	r17,0xC,r33; }
	{ ld8	r16,[r15],8; ld8	r41,[r14],8; nop.i	0x0; }
	{ nop.m	0x0; ld8	r15,[r15]; nop.i	0x0 }
	{ st8	[r16],r33; ld4	r39,[r14]; nop.i	0x0; }
	{ ld4	r40,[r17]; st8	[r15],r14; nop.i	0x0 }
	{ st4	[r0],r14; addl	r14,6456,r1; (p06) br.cond.dpnt.few	40000000000275F0; }

l40000000000275D0:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	40000000000278A0 }

l40000000000275F0:
	{ addl	r38,9044,r1; addl	r37,5960,r1; nop.i	0x0 }
	{ addl	r65,1,r0; adds	r66,0x0,r0; adds	r64,0x0,r35; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r43,[r38]; nop.i	0x0 }
	{ ld4	r42,[r37]; nop.m	0x0; br.call.sptk.many	b0,expand_prompt_string; }
	{ adds	r1,0x0,r63; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r64,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r63; adds	r64,0x0,r36; br.call.sptk.many	b0,string_list; }
	{ adds	r1,0x0,r63; nop.m	0x0; adds	r34,0x0,r8 }
	{ adds	r64,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,dispose_words; }
	{ adds	r14,0x0,r33; adds	r33,0xC,r33; adds	r8,0x0,r34 }
	{ st4	[r43],r38; st4	[r42],r37; adds	r1,0x0,r63; }
	{ st8	[r14],r8,8; st4	[r40],r33; nop.i	0x0; }
	{ st4	[r39],r14; mov.i	ar.pfs,r62; mov.spnt	b0,r61,40000000000276C0 }
	{ nop.m	0x0; adds	r12,0x10A0,r12; br.ret	b0 }

l40000000000276E0:
	{ ld1	r39,[r33]; nop.m	0x0; sxt1	r39,r39; }
	{ cmp4.eq	p07,p06,0x21,r39; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000027920; }

l4000000000027700:
	{ adds	r32,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,history_number; }
	{ adds	r1,0x0,r63; sxt4	r64,r8; br.call.sptk.many	b0,itos; }
	{ nop.m	0x0; adds	r1,0x0,r63; adds	r34,0x0,r8; }
	{ adds	r65,0x0,r35; adds	r64,0x0,r34; nop.i	0x0 }
	{ adds	r66,0x0,r36; adds	r67,0x0,r37; br.call.sptk.many	b0,sub_append_string; }
	{ ld4	r15,[r36]; adds	r1,0x0,r63; adds	r35,0x0,r8; }
	{ nop.m	0x0; sxt4	r14,r15; add	r14,r8,r14; }
	{ st1	[r0],r14; nop.i	0x0; br.cond.sptk.few	40000000000273D0 }

l4000000000027780:
	{ ld1	r14,[r33]; nop.m	0x0; sxt1	r14,r14; }
	{ adds	r15,0xFFFFFFFFFFFFFFDF,r14; adds	r40,0x0,r14; adds	r39,0x0,r14; }
	{ nop.m	0x0; zxt1	r15,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x56,r15; (p07) br.cond.dptk.few	4000000000027870 }

l40000000000277C0:
	{ addl	r64,3,r0; adds	r32,0x0,r33; br.call.sptk.many	b0,xmalloc; }
	{ adds	r14,0x0,r8; adds	r15,0x2,r8; nop.i	0x0 }
	{ cmp4.eq	p06,p07,0x0,r39; adds	r1,0x0,r63; adds	r34,0x0,r8; }
	{ st1	[r14],r1,1; st1	[r0],r15; nop.i	0x0 }
	{ (p07) adds	r32,0x1,r32; st1	[r40],r14; nop.i	0x0; }

l4000000000027806:
	{ mf.a; nop; break.i	0x80000 }
	{ break.m	0x4000; nop; (p16) nop }
	{ Invalid; nop; (p32) nop }
	{ Invalid; (p32) nop; (p48) br.call.sptk.few	b3,b0 }
	{ Invalid; (p17) mov.sptk	b0,r8,4000000000027946; break.b	0x80000 }
	{ (p07) break.m	0x58780; (p07) nop; nop }
	{ break.m	0x4000; nop; (p48) nop }

l4000000000027870:
	{ shladd	r15,r15,0x3,r42; ld8	r16,[r15]; nop.i	0x0; }
	{ nop.m	0x0; add	r15,r15,r16; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r15,4000000000027890; br.cond	b6; }

l40000000000278A0:
	{ adds	r64,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,dequote_string; }
	{ adds	r1,0x0,r63; nop.m	0x0; adds	r34,0x0,r8 }
	{ adds	r64,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r14,0x0,r33; nop.m	0x0; adds	r33,0xC,r33 }
	{ adds	r8,0x0,r34; nop.m	0x0; adds	r1,0x0,r63; }
	{ st8	[r14],r8,8; st4	[r40],r33; nop.i	0x0; }
	{ st4	[r39],r14; mov.i	ar.pfs,r62; mov.spnt	b0,r61,4000000000027900 }
	{ nop.m	0x0; adds	r12,0x10A0,r12; br.ret	b0; }

l4000000000027920:
	{ addl	r64,2,r0; adds	r32,0x2,r32; br.call.sptk.many	b0,xmalloc; }
	{ adds	r15,0x0,r8; adds	r34,0x0,r8; adds	r1,0x0,r63 }
	{ adds	r65,0x0,r35; adds	r66,0x0,r36; adds	r67,0x0,r37; }
	{ st1	[r15],r1,1; nop.m	0x0; adds	r64,0x0,r34; }
	{ st1	[r0],r15; nop.i	0x0; br.call.sptk.many	b0,sub_append_string; }
	{ ld4	r15,[r36]; adds	r1,0x0,r63; adds	r35,0x0,r8; }
	{ nop.m	0x0; sxt4	r14,r15; add	r14,r8,r14; }
	{ st1	[r0],r14; nop.i	0x0; br.cond.sptk.few	40000000000273D0 }
40000000000279A0 09 00 02 58 18 10 00 00 00 02 00 00 04 08 01 84 ...X............
40000000000279B0 11 38 00 80 06 39 00 00 00 02 80 03 10 0F 00 43 .8...9.........C
40000000000279C0 11 00 00 00 01 00 00 00 00 02 00 00 08 3D FF 58 .............=.X
40000000000279D0 11 08 00 7E 00 21 00 0C 20 00 42 00 F8 12 0C 50 ...~.!.. .B....P
40000000000279E0 08 08 00 7E 00 21 00 00 00 02 00 00 08 40 00 84 ...~.!.......@..
40000000000279F0 19 08 02 58 18 10 00 00 00 02 00 00 98 37 FF 58 ...X.........7.X
4000000000027A00 08 00 00 00 01 00 10 00 FC 00 42 40 04 40 00 84 ..........B@.@..
4000000000027A10 09 00 00 00 01 00 60 00 9C 0E 73 00 00 00 04 00 ......`...s.....
4000000000027A20 10 00 00 00 01 C0 01 0A 80 00 42 00 00 FE FF 48 ..........B....H
4000000000027A30 11 00 02 5C 18 10 00 00 00 02 00 00 98 3C FF 58 ...\.........<.X
4000000000027A40 11 08 00 7E 00 21 00 0C 20 00 42 00 88 12 0C 50 ...~.!.. .B....P
4000000000027A50 08 08 00 7E 00 21 00 00 00 02 00 00 08 40 00 84 ...~.!.......@..
4000000000027A60 19 08 02 5C 18 10 00 00 00 02 00 00 28 37 FF 58 ...\........(7.X
4000000000027A70 08 08 00 7E 00 21 00 00 00 02 00 40 04 40 00 84 ...~.!.....@.@..
4000000000027A80 19 38 A0 51 86 39 00 00 00 02 80 03 70 0D 00 43 .8.Q.9......p..C
4000000000027A90 08 00 01 42 00 21 00 00 00 02 00 00 00 00 04 00 ...B.!..........
4000000000027AA0 09 00 00 00 01 00 60 00 9C 0E 73 00 00 00 04 00 ......`...s.....
4000000000027AB0 10 00 00 00 01 C0 01 0A 80 00 42 00 70 FD FF 48 ..........B.p..H
4000000000027AC0 11 00 42 00 00 24 00 00 00 02 00 00 08 12 0C 50 ..B..$.........P
4000000000027AD0 08 08 00 7E 00 21 70 B0 A3 0C 73 40 04 40 00 84 ...~.!p...s@.@..
4000000000027AE0 19 00 02 10 00 21 10 0C 00 00 C8 03 F0 0F 00 43 .....!.........C
4000000000027AF0 08 00 00 00 01 00 30 A4 F5 FB 4F 40 F8 E7 FF 9F ......0...O@....
4000000000027B00 09 20 02 62 18 10 50 04 D0 20 20 00 04 08 01 84 . .b..P..  .....
4000000000027B10 11 18 02 86 18 10 00 00 00 02 00 00 38 49 FF 58 ............8I.X
4000000000027B20 09 30 00 4E 87 39 00 00 00 02 00 20 00 F8 01 84 .0.N.9..... ....
4000000000027B30 10 00 00 00 01 C0 01 0A 80 00 42 00 F0 FC FF 48 ..........B....H
4000000000027B40 09 00 00 00 01 00 00 E4 F5 FB 4F 00 00 00 04 00 ..........O.....
4000000000027B50 11 00 02 80 18 10 00 00 00 02 00 00 78 B5 03 50 ............x..P
4000000000027B60 08 38 00 10 06 39 10 00 FC 00 42 00 08 61 00 84 .8...9....B..a..
4000000000027B70 19 08 02 10 00 21 20 FC 03 3E C8 03 C0 0F 00 43 .....! ..>.....C
4000000000027B80 11 00 00 00 01 00 00 00 00 02 00 00 A8 3D FF 58 .............=.X
4000000000027B90 09 00 00 00 01 00 10 00 FC 00 42 00 F1 07 7C 90 ..........B...|.
4000000000027BA0 00 00 00 00 01 00 E0 00 20 2C 00 E0 01 61 00 84 ........ ,...a..
4000000000027BB0 0B 38 5C 4F 86 39 E0 78 38 00 40 00 00 00 04 00 .8\O.9.x8.@.....
4000000000027BC0 10 00 00 1C 80 11 00 00 00 02 80 03 20 0B 00 43 ............ ..C
4000000000027BD0 11 00 42 18 00 21 00 00 00 02 00 00 38 93 01 50 ..B..!......8..P
4000000000027BE0 08 08 00 7E 00 21 00 84 30 00 42 00 00 00 04 00 ...~.!..0.B.....
4000000000027BF0 19 08 02 10 00 21 20 04 00 40 48 00 F8 3E FF 58 .....! ..@H..>.X
4000000000027C00 08 08 00 7E 00 21 00 00 00 02 00 00 00 00 04 00 ...~.!..........
4000000000027C10 11 00 42 18 00 21 10 FC 03 3E 48 00 78 94 01 50 ..B..!...>H.x..P
4000000000027C20 09 70 00 52 10 10 10 00 FC 00 42 00 08 61 00 84 .p.R......B..a..
4000000000027C30 11 38 00 1C 86 39 00 00 00 02 00 03 30 00 00 43 .8...9......0..C
4000000000027C40 09 00 00 00 01 00 E0 00 98 20 20 00 00 00 04 00 .........  .....
4000000000027C50 10 00 00 00 01 00 60 00 38 0E 73 03 20 0C 00 43 ......`.8.s. ..C
4000000000027C60 11 00 01 42 00 21 00 00 00 02 00 00 A8 A0 10 50 ...B.!.........P
4000000000027C70 10 08 00 7E 00 21 20 02 20 00 42 00 30 FE FF 48 ...~.! . .B.0..H
4000000000027C80 0B 70 00 56 10 10 60 00 38 0E 73 00 00 00 04 00 .p.V..`.8.s.....
4000000000027C90 11 00 00 00 01 C0 01 12 80 00 C2 03 40 F7 FF 4A ............@..J
4000000000027CA0 08 00 0E 00 00 24 00 00 00 02 00 E0 25 00 00 90 .....$......%...
4000000000027CB0 19 00 01 42 00 21 00 00 00 02 00 00 18 10 0C 50 ...B.!.........P
4000000000027CC0 08 10 01 10 00 21 00 09 00 00 48 C0 01 00 00 84 .....!....H.....
4000000000027CD0 09 78 08 00 00 24 10 00 FC 00 42 C0 B0 45 1D E6 .x...$....B..E..
4000000000027CE0 11 70 88 1C 00 20 00 11 41 00 40 03 90 10 00 43 .p... ..A.@....C
4000000000027CF0 08 00 3C 1C 80 11 00 00 40 00 23 00 00 00 04 00 ..<.....@.#.....
4000000000027D00 09 00 00 00 01 00 60 00 9C 0E 73 00 00 00 04 00 ......`...s.....
4000000000027D10 11 00 00 00 01 C0 01 0A 80 00 42 00 10 FB FF 48 ..........B....H
4000000000027D20 11 00 01 42 00 21 00 00 00 02 00 00 28 D1 05 50 ...B.!......(..P
4000000000027D30 11 08 00 7E 00 21 00 04 20 2C 00 00 98 1D 10 50 ...~.!.. ,.....P
4000000000027D40 08 00 00 00 01 00 10 00 FC 00 42 40 04 40 00 84 ..........B@.@..
4000000000027D50 09 00 00 00 01 00 60 00 9C 0E 73 00 00 00 04 00 ......`...s.....
4000000000027D60 11 00 00 00 01 C0 01 0A 80 00 42 00 C0 FA FF 48 ..........B....H
4000000000027D70 11 00 02 66 18 10 00 02 84 00 42 00 58 3E FF 58 ...f......B.X>.X
4000000000027D80 11 08 00 7E 00 21 00 04 20 00 42 00 88 38 FF 58 ...~.!.. .B..8.X
4000000000027D90 08 30 00 10 07 39 00 00 00 02 00 20 00 F8 01 84 .0...9..... ....
4000000000027DA0 19 00 02 10 00 21 00 00 00 02 00 03 E0 0C 00 43 .....!.........C
4000000000027DB0 11 00 00 00 01 00 00 00 00 02 00 00 58 90 01 50 ............X..P
4000000000027DC0 08 08 00 7E 00 21 00 00 00 02 00 40 04 40 00 84 ...~.!.....@.@..
4000000000027DD0 19 00 02 10 00 21 00 00 00 02 00 00 F8 38 FF 58 .....!.......8.X
4000000000027DE0 11 08 00 7E 00 21 00 0C 20 00 42 00 E8 0E 0C 50 ...~.!.. .B....P
4000000000027DF0 08 08 00 7E 00 21 00 00 00 02 00 20 08 10 01 84 ...~.!..... ....
4000000000027E00 19 00 02 10 00 21 00 00 00 02 00 00 88 33 FF 58 .....!.......3.X
4000000000027E10 08 00 00 00 01 00 10 00 FC 00 42 40 04 40 00 84 ..........B@.@..
4000000000027E20 09 00 00 00 01 00 60 00 9C 0E 73 00 00 00 04 00 ......`...s.....
4000000000027E30 10 00 00 00 01 C0 01 0A 80 00 42 00 F0 F9 FF 48 ..........B....H
4000000000027E40 11 00 0A 00 00 24 00 00 00 02 00 00 88 0E 0C 50 .....$.........P
4000000000027E50 09 38 84 51 86 39 10 00 FC 00 42 40 04 40 00 84 .8.Q.9....B@.@..
4000000000027E60 F1 00 E8 10 80 11 00 00 00 02 80 03 50 00 00 43 ............P..C
4000000000027E70 09 00 00 00 01 00 70 28 A3 0C 73 00 00 00 04 00 ......p(..s.....
4000000000027E80 F1 00 EC 10 80 11 00 00 00 02 80 03 30 00 00 43 ............0..C
4000000000027E90 09 00 00 00 01 00 70 90 A3 0C 73 00 00 00 04 00 ......p...s.....
4000000000027EA0 E8 00 F0 10 80 91 01 40 21 00 23 00 00 00 04 00 .......@!.#.....
4000000000027EB0 09 70 04 44 00 21 00 02 84 00 42 C0 00 38 1D E6 .p.D.!....B..8..
4000000000027EC0 11 00 00 1C 80 D1 01 0A 80 00 42 00 60 F9 FF 48 ..........B.`..H
4000000000027ED0 11 00 0E 00 00 24 00 02 84 00 42 00 F8 0D 0C 50 .....$....B....P
4000000000027EE0 08 78 00 56 10 10 E0 00 20 00 42 00 22 40 00 84 .x.V.... .B."@..
4000000000027EF0 03 08 00 7E 00 21 20 02 20 00 42 C0 00 78 1C E6 ...~.! . .B..x..
4000000000027F00 CB 78 34 00 00 E4 F1 50 00 00 48 00 00 00 04 00 .x4....P..H.....
4000000000027F10 0A 08 3C 1C 80 15 F0 00 AC 20 20 00 00 00 04 00 ..<......  .....
4000000000027F20 0B 00 00 20 80 11 60 00 3C 0E 73 00 00 00 04 00 ... ..`.<.s.....
4000000000027F30 CB 78 28 00 00 E4 F1 00 00 00 42 C0 00 38 1D E6 .x(.......B..8..
4000000000027F40 10 00 3C 1C 80 D1 01 0A 80 00 42 00 E0 F8 FF 48 ..<.......B....H
4000000000027F50 11 00 0E 00 00 24 00 00 00 02 00 00 78 0D 0C 50 .....$......x..P
4000000000027F60 09 70 00 52 10 10 10 00 FC 00 42 40 04 40 00 84 .p.R......B@.@..
4000000000027F70 10 00 00 00 01 00 70 00 38 0C 73 03 30 00 00 42 ......p.8.s.0..B
4000000000027F80 09 00 00 00 01 00 E0 00 98 20 20 00 00 00 04 00 .........  .....
4000000000027F90 10 00 00 00 01 00 60 00 38 0E 73 03 A0 06 00 42 ......`.8.s....B
4000000000027FA0 02 70 00 6A 10 10 F0 E0 F7 A3 4E C0 00 70 1C E6 .p.j......N..p..
4000000000027FB0 09 70 00 44 00 21 00 00 00 02 00 00 00 00 04 00 .p.D.!..........
4000000000027FC0 F0 08 B4 1C 80 15 00 00 00 02 80 03 90 06 00 42 ...............B
4000000000027FD0 02 78 8C 00 00 24 00 02 84 00 42 00 00 00 04 00 .x...$....B.....
4000000000027FE0 0A 08 3C 1C 80 15 00 00 38 00 23 00 00 00 04 00 ..<.....8.#.....
4000000000027FF0 09 00 00 00 01 00 60 00 9C 0E 73 00 00 00 04 00 ......`...s.....
4000000000028000 10 00 00 00 01 C0 01 0A 80 00 42 00 20 F8 FF 48 ..........B. ..H
4000000000028010 08 08 02 42 00 21 00 00 00 02 00 40 38 00 00 90 ...B.!.....@8...
4000000000028020 19 00 62 18 21 21 00 00 00 02 00 00 08 39 FF 58 ..b.!!.......9.X
4000000000028030 09 70 6C 18 21 21 10 00 FC 00 42 00 88 61 84 84 .pl.!!....B..a..
4000000000028040 11 00 00 1C 80 11 00 00 00 02 00 00 C8 71 0C 50 .............q.P
4000000000028050 08 08 00 7E 00 21 00 00 00 02 00 E0 05 40 00 84 ...~.!.......@..
4000000000028060 19 00 0E 00 00 24 00 00 00 02 00 00 68 0C 0C 50 .....$......h..P
4000000000028070 08 38 FC 5F 86 39 00 00 00 02 00 20 00 F8 01 84 .8._.9..... ....
4000000000028080 09 10 01 10 00 21 00 00 00 02 00 C0 01 40 00 84 .....!.......@..
4000000000028090 11 00 00 00 01 00 70 08 BC 8C 73 03 10 06 00 42 ......p...s....B
40000000000280A0 09 08 D8 1C 80 15 F0 10 20 00 42 E0 F0 7F 19 EE ........ .B.....
40000000000280B0 08 00 00 00 01 00 00 78 39 00 23 00 00 00 04 00 .......x9.#.....
40000000000280C0 18 00 00 1E 80 11 00 00 00 02 80 03 F0 0C 00 41 ...............A
40000000000280D0 0B 70 00 42 00 10 E0 80 3A 7E 46 00 00 00 04 00 .p.B....:~F.....
40000000000280E0 01 00 00 00 01 00 E0 00 38 20 00 00 00 00 04 00 ........8 ......
40000000000280F0 11 38 1C 1C 86 35 E0 10 80 00 C2 03 C0 0C 00 43 .8...5.........C
4000000000028100 0B 78 00 1C 00 10 F0 80 3E 7E 46 00 00 00 04 00 .x......>~F.....
4000000000028110 01 00 00 00 01 00 F0 00 3C 20 00 00 00 00 04 00 ........< ......
4000000000028120 11 30 1C 1E 87 35 00 00 00 02 00 03 50 00 00 43 .0...5......P..C
4000000000028130 0B 70 0C 40 00 21 F0 00 38 00 20 00 00 00 04 00 .p.@.!..8. .....
4000000000028140 09 00 00 00 01 00 F0 80 3E 7E 46 00 00 00 04 00 ........>~F.....
4000000000028150 03 00 00 00 01 00 F0 00 3C 20 00 E0 70 78 18 D6 ........< ..px..
4000000000028160 11 00 00 00 01 80 01 22 80 00 42 03 D0 F5 FF 4A ......."..B....J
4000000000028170 08 00 01 1C 00 21 10 04 8C 00 42 00 08 10 01 84 .....!....B.....
4000000000028180 19 10 02 48 00 21 30 04 94 00 42 00 48 F8 05 50 ...H.!0...B.H..P
4000000000028190 09 78 00 48 10 10 10 00 FC 00 42 60 04 40 00 84 .x.H......B`.@..
40000000000281A0 03 00 00 00 01 00 E0 00 3C 2C 00 C0 81 70 00 80 ........<,...p..
40000000000281B0 10 00 00 1C 80 11 00 00 00 02 00 00 20 F2 FF 48 ............ ..H
40000000000281C0 11 00 42 18 21 21 00 02 84 00 42 00 08 28 FF 58 ..B.!!....B..(.X
40000000000281D0 0B 08 00 7E 00 21 00 24 F4 FB 4F 00 00 00 04 00 ...~.!.$..O.....
40000000000281E0 11 00 02 80 18 10 00 00 00 02 00 00 A8 1A 04 50 ...............P
40000000000281F0 11 08 00 7E 00 21 00 84 30 42 42 00 38 34 FF 58 ...~.!..0BB.84.X
4000000000028200 08 38 90 51 86 39 10 00 FC 00 42 00 00 00 04 00 .8.Q.9....B.....
4000000000028210 19 18 02 10 00 21 00 84 30 40 C2 03 A0 09 00 43 .....!..0@.....C
4000000000028220 11 38 D0 51 86 39 00 00 00 02 80 03 00 0A 00 43 .8.Q.9.........C
4000000000028230 11 38 50 51 86 39 00 00 00 02 80 03 60 0A 00 43 .8PQ.9......`..C
4000000000028240 11 38 00 51 86 39 00 00 00 02 80 03 C0 0A 00 43 .8.Q.9.........C
4000000000028250 11 38 04 51 86 39 00 00 00 02 80 03 40 07 00 43 .8.Q.9......@..C
4000000000028260 0B 38 00 5E 86 F9 F1 80 30 40 42 03 F2 60 84 84 .8.^....0@B..`..
4000000000028270 E8 00 00 1E 80 91 01 00 40 00 23 00 00 00 04 00 ........@.#.....
4000000000028280 11 00 00 00 01 00 00 00 00 02 00 00 48 34 FF 58 ............H4.X
4000000000028290 11 08 00 7E 00 21 00 0C 20 00 42 00 38 0A 0C 50 ...~.!.. .B.8..P
40000000000282A0 08 08 00 7E 00 21 00 00 00 02 00 00 08 40 00 84 ...~.!.......@..
40000000000282B0 19 08 42 18 20 21 00 00 00 02 00 00 D8 2E FF 58 ..B. !.........X
40000000000282C0 09 30 00 4E 87 39 10 00 FC 00 42 40 04 40 00 84 .0.N.9....B@.@..
40000000000282D0 11 00 00 00 01 C0 01 0A 80 00 42 00 50 F5 FF 48 ..........B.P..H
40000000000282E0 0B 70 08 40 00 21 E0 00 38 00 20 00 00 00 04 00 .p.@.!..8. .....
40000000000282F0 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
4000000000028300 10 00 00 00 01 00 70 D8 3B 0C 73 03 C0 F4 FF 4A ......p.;.s....J
4000000000028310 11 00 42 18 21 21 20 1A 80 00 42 00 B8 26 FF 58 ..B.!! ...B..&.X
4000000000028320 11 08 00 7E 00 21 00 84 30 42 42 00 08 33 FF 58 ...~.!..0BB..3.X
4000000000028330 08 08 00 7E 00 21 00 00 00 02 00 00 05 40 00 84 ...~.!.......@..
4000000000028340 19 00 02 44 00 21 00 00 00 02 00 00 88 33 FF 58 ...D.!.......3.X
4000000000028350 11 08 00 7E 00 21 00 1C 20 00 42 00 78 09 0C 50 ...~.!.. .B.x..P
4000000000028360 09 70 00 44 00 10 10 00 FC 00 42 20 04 40 00 84 .p.D......B .@..
4000000000028370 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
4000000000028380 09 38 F4 1D 86 39 00 00 00 02 00 20 01 70 20 E6 .8...9..... .p .
4000000000028390 C2 80 04 00 00 24 F2 08 00 00 C8 03 02 00 00 84 .....$..........
40000000000283A0 2B 79 00 00 00 21 F0 78 40 18 40 00 02 40 00 84 +y...!.x@.@..@..
40000000000283B0 11 30 00 1E 87 39 F0 20 80 00 42 03 50 0A 00 43 .0...9. ..B.P..C
40000000000283C0 09 08 38 20 80 15 00 00 00 02 00 00 04 78 00 84 ..8 .........x..
40000000000283D0 09 70 04 1E 00 14 00 00 00 02 00 20 02 80 00 84 .p......... ....
40000000000283E0 03 00 00 00 01 00 E0 00 38 28 00 E0 00 70 18 E6 ........8(...p..
40000000000283F0 10 00 00 00 01 00 70 E8 3B 8C 73 03 D0 FF FF 4A ......p.;.s....J
4000000000028400 08 70 00 42 40 10 00 00 44 00 23 20 08 00 04 90 .p.B@...D.# ....
4000000000028410 09 10 02 42 00 21 30 04 A0 00 42 00 08 61 80 84 ...B.!0...B..a..
4000000000028420 09 70 00 42 00 11 F0 00 80 00 20 00 00 00 04 00 .p.B...... .....
4000000000028430 01 00 00 00 01 00 E0 00 38 28 00 E0 01 78 50 00 ........8(...xP.
4000000000028440 09 38 00 1C 86 39 00 00 00 02 00 E0 04 78 00 84 .8...9.......x..
4000000000028450 E9 70 00 42 00 21 00 00 00 02 80 E3 21 08 01 84 .p.B.!......!...
4000000000028460 EA 08 E0 1C 80 D5 01 B8 39 00 23 00 00 00 04 00 ........9.#.....
4000000000028470 F9 00 00 1E 80 11 00 00 00 02 00 00 38 31 FF 58 ............81.X
4000000000028480 08 08 00 7E 00 21 00 00 00 02 00 E0 05 40 00 84 ...~.!.......@..
4000000000028490 19 00 02 42 00 21 00 00 00 02 00 00 58 23 FF 58 ...B.!......X#.X
40000000000284A0 09 38 00 5E 86 39 10 00 FC 00 42 00 08 61 80 84 .8.^.9....B..a..
40000000000284B0 E9 70 40 18 20 21 00 00 00 02 00 E3 F1 60 84 84 .p@. !.......`..
40000000000284C0 08 00 00 00 01 C0 01 00 38 00 23 00 00 00 04 00 ........8.#.....
40000000000284D0 09 70 00 52 10 90 01 00 3C 00 23 00 00 00 04 00 .p.R....<.#.....
40000000000284E0 11 38 00 1C 86 39 00 00 00 02 00 03 30 00 00 43 .8...9......0..C
40000000000284F0 09 00 00 00 01 00 E0 00 98 20 20 00 00 00 04 00 .........  .....
4000000000028500 10 00 00 00 01 00 60 00 38 0E 73 03 80 FD FF 4B ......`.8.s....K
4000000000028510 11 00 00 00 01 00 00 00 00 02 00 00 F8 97 10 50 ...............P
4000000000028520 09 30 00 4E 87 39 10 00 FC 00 42 40 04 40 00 84 .0.N.9....B@.@..
4000000000028530 11 00 00 00 01 C0 01 0A 80 00 42 00 F0 F2 FF 48 ..........B....H
4000000000028540 09 70 00 64 10 10 00 00 00 02 00 00 04 08 01 84 .p.d............
4000000000028550 11 00 00 00 01 00 00 04 38 2C 00 00 78 15 10 50 ........8,..x..P
4000000000028560 09 30 00 4E 87 39 10 00 FC 00 42 40 04 40 00 84 .0.N.9....B@.@..
4000000000028570 11 00 00 00 01 C0 01 0A 80 00 42 00 B0 F2 FF 48 ..........B....H
4000000000028580 11 00 02 60 18 10 00 02 84 00 42 00 88 88 01 50 ...`......B....P
4000000000028590 08 08 00 7E 00 21 00 00 00 02 00 20 04 40 00 84 ...~.!..... .@..
40000000000285A0 19 00 02 10 00 21 00 00 00 02 00 00 28 31 FF 58 .....!......(1.X
40000000000285B0 11 08 00 7E 00 21 00 0C 20 00 42 00 18 07 0C 50 ...~.!.. .B....P
40000000000285C0 08 08 00 7E 00 21 00 00 00 02 00 00 08 40 00 84 ...~.!.......@..
40000000000285D0 19 08 02 42 00 21 00 00 00 02 00 00 B8 2B FF 58 ...B.!.......+.X
40000000000285E0 09 30 00 4E 87 39 10 00 FC 00 42 40 04 40 00 84 .0.N.9....B@.@..
40000000000285F0 11 00 00 00 01 C0 01 0A 80 00 42 00 30 F2 FF 48 ..........B.0..H
4000000000028600 11 00 01 42 00 21 00 00 00 02 00 00 C8 13 0A 50 ...B.!.........P
4000000000028610 11 08 00 7E 00 21 00 04 20 2C 00 00 B8 14 10 50 ...~.!.. ,.....P
4000000000028620 11 08 00 7E 00 21 20 02 20 00 42 00 30 F7 FF 48 ...~.! . .B.0..H
4000000000028630 09 78 F0 FB 51 27 00 00 00 02 00 C0 01 40 00 84 .x..Q'.......@..
4000000000028640 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000028650 09 78 10 1E 00 21 00 00 00 02 00 00 04 08 01 84 .x...!..........
4000000000028660 0B 78 00 1E 10 10 70 00 3C 0C 73 00 00 00 04 00 .x....p.<.s.....
4000000000028670 CB 78 90 00 00 E4 F1 18 01 00 48 00 00 00 04 00 .x........H.....
4000000000028680 09 00 00 00 01 00 10 78 38 00 2B 00 00 00 04 00 .......x8.+.....
4000000000028690 10 00 00 1C 80 11 00 00 00 02 00 00 60 F9 FF 48 ............`..H
40000000000286A0 0B 38 FC 5F 86 FB 11 68 39 00 AB 03 04 08 01 84 .8._...h9.......
40000000000286B0 F1 00 00 1C 80 11 00 00 00 02 80 03 80 F0 FF 4B ...............K
40000000000286C0 09 00 00 00 01 00 10 78 39 00 2B 00 00 00 04 00 .......x9.+.....
40000000000286D0 10 00 00 1C 80 11 00 00 00 02 00 00 00 FA FF 48 ...............H
40000000000286E0 09 00 00 00 01 00 00 24 F6 FB 4F 00 00 00 04 00 .......$..O.....
40000000000286F0 11 00 02 80 18 10 00 00 00 02 00 00 D8 A9 03 50 ...............P
4000000000028700 09 38 00 10 06 39 10 00 FC 00 42 00 08 40 00 84 .8...9....B..@..
4000000000028710 EB 80 40 18 00 E1 E1 00 40 00 20 00 02 61 00 84 ..@.....@. ..a..
4000000000028720 01 00 00 00 01 C0 E1 00 38 28 00 00 00 00 04 00 ........8(......
4000000000028730 F1 10 01 1C 00 21 00 00 00 02 80 03 40 00 00 43 .....!......@..C
4000000000028740 09 70 00 10 00 10 F0 00 40 00 20 00 00 00 04 00 .p......@. .....
4000000000028750 01 00 00 00 01 00 F0 00 3C 28 00 C0 01 70 50 00 ........<(...pP.
4000000000028760 11 10 01 1E 00 21 70 70 3C 0C F1 03 D0 01 00 43 .....!pp<......C
4000000000028770 10 00 00 00 01 00 70 78 89 0C F3 03 90 02 00 43 ......px.......C
4000000000028780 11 00 42 18 00 21 10 7C 01 00 48 00 28 37 FF 58 ..B..!.|..H.(7.X
4000000000028790 08 10 01 10 00 21 00 00 00 02 00 E0 00 40 18 E4 .....!.......@..
40000000000287A0 19 08 00 7E 00 21 00 00 00 02 80 03 70 F4 FF 4B ...~.!......p..K
40000000000287B0 11 00 02 44 00 21 00 00 00 02 00 00 18 2F FF 58 ...D.!......./.X
40000000000287C0 08 08 00 7E 00 21 00 84 30 00 42 20 18 10 01 84 ...~.!..0.B ....
40000000000287D0 19 10 02 10 00 21 30 04 00 40 48 00 98 2C FF 58 .....!0..@H..,.X
40000000000287E0 10 00 00 00 01 00 10 00 FC 00 42 00 30 F4 FF 48 ..........B.0..H
40000000000287F0 11 00 02 10 00 21 10 74 01 00 48 00 98 2E FF 58 .....!.t..H....X
4000000000028800 08 30 00 10 07 39 10 00 FC 00 42 20 08 18 01 84 .0...9....B ....
4000000000028810 09 00 02 44 00 21 20 04 90 00 42 60 08 28 01 84 ...D.! ...B`.(..
4000000000028820 D1 00 09 40 00 21 00 00 00 02 00 03 10 EF FF 4B ...@.!.........K
4000000000028830 11 00 00 10 80 11 00 12 80 00 42 00 98 F1 05 50 ..........B....P
4000000000028840 09 78 00 48 10 10 10 00 FC 00 42 60 04 40 00 84 .x.H......B`.@..
4000000000028850 03 00 00 00 01 00 E0 00 3C 2C 00 C0 81 70 00 80 ........<,...p..
4000000000028860 10 00 00 1C 80 11 00 00 00 02 00 00 70 EB FF 48 ............p..H
4000000000028870 11 00 01 42 00 21 00 00 00 02 00 00 58 2E FF 58 ...B.!......X..X
4000000000028880 11 08 00 7E 00 21 00 0C 20 00 42 00 48 04 0C 50 ...~.!.. .B.H..P
4000000000028890 08 08 00 7E 00 21 00 00 00 02 00 00 08 40 00 84 ...~.!.......@..
40000000000288A0 19 08 42 18 00 21 00 00 00 02 00 00 E8 28 FF 58 ..B..!.......(.X
40000000000288B0 10 08 00 7E 00 21 20 02 20 00 42 00 F0 F1 FF 48 ...~.! . .B....H
40000000000288C0 11 00 01 42 00 21 00 00 00 02 00 00 88 A2 FF 58 ...B.!.........X
40000000000288D0 08 00 00 00 01 00 10 00 FC 00 42 00 00 00 04 00 ..........B.....
40000000000288E0 19 00 02 58 18 10 00 00 00 02 00 00 E8 2D FF 58 ...X.........-.X
40000000000288F0 11 08 00 7E 00 21 00 0C 20 00 42 00 D8 03 0C 50 ...~.!.. .B....P
4000000000028900 08 08 00 7E 00 21 00 00 00 02 00 00 08 40 00 84 ...~.!.......@..
4000000000028910 19 08 02 58 18 10 00 00 00 02 00 00 78 28 FF 58 ...X........x(.X
4000000000028920 10 08 00 7E 00 21 20 02 20 00 42 00 F0 F0 FF 48 ...~.! . .B....H
4000000000028930 11 08 02 20 00 21 00 00 00 02 00 00 18 1C FF 58 ... .!.........X
4000000000028940 10 08 00 7E 00 21 60 00 20 0E F3 03 30 FE FF 4A ...~.!`. ...0..J
4000000000028950 11 00 42 18 00 21 00 00 00 02 00 00 B8 85 01 50 ..B..!.........P
4000000000028960 08 08 00 7E 00 21 00 84 30 00 42 00 00 00 04 00 ...~.!..0.B.....
4000000000028970 19 08 02 10 00 21 20 04 00 40 48 00 78 31 FF 58 .....! ..@H.x1.X
4000000000028980 11 00 00 00 01 00 10 00 FC 00 42 00 90 F2 FF 48 ..........B....H
4000000000028990 08 10 B2 FA FD 27 00 00 00 02 00 00 08 61 80 84 .....'.......a..
40000000000289A0 09 08 02 00 01 24 00 00 00 02 00 00 04 08 01 84 .....$..........
40000000000289B0 11 10 02 84 18 10 00 00 00 02 00 00 F8 2B FF 58 .............+.X
40000000000289C0 09 78 01 10 00 21 10 00 FC 00 42 00 08 61 80 84 .x...!....B..a..
40000000000289D0 09 00 00 00 01 00 70 00 BC 0C 73 00 00 00 04 00 ......p...s.....
40000000000289E0 E2 78 40 18 20 A1 01 79 30 42 42 00 00 00 04 00 .x@. ..y0BB.....
40000000000289F0 F8 00 00 1E 80 91 01 00 40 00 23 00 90 F8 FF 48 ........@.#....H
4000000000028A00 0B 78 44 18 00 21 E0 00 3C 00 20 00 00 00 04 00 .xD..!..<. .....
4000000000028A10 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
4000000000028A20 11 00 00 00 01 00 60 00 38 0E 73 03 F0 F1 FF 4A ......`.8.s....J
4000000000028A30 10 00 00 00 01 00 70 78 39 0C 73 03 50 FD FF 4A ......px9.s.P..J
4000000000028A40 0B 80 48 18 00 21 E0 00 40 00 20 00 00 00 04 00 ..H..!..@. .....
4000000000028A50 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
4000000000028A60 10 00 00 00 01 00 60 00 38 0E 73 03 B0 F1 FF 4A ......`.8.s....J
4000000000028A70 10 00 00 00 01 00 00 00 00 02 00 00 10 FD FF 48 ...............H
4000000000028A80 09 10 F1 FB FC 27 00 24 00 00 48 00 04 08 01 84 .....'.$..H.....
4000000000028A90 11 10 01 44 18 10 00 00 00 02 00 00 38 02 0C 50 ...D........8..P
4000000000028AA0 08 08 00 7E 00 21 00 00 00 02 00 20 08 10 01 84 ...~.!..... ....
4000000000028AB0 19 00 02 10 00 21 00 00 00 02 00 00 D8 26 FF 58 .....!.......&.X
4000000000028AC0 10 08 00 7E 00 21 20 02 20 00 42 00 60 F3 FF 48 ...~.! . .B.`..H
4000000000028AD0 11 08 02 62 18 10 00 12 80 00 42 00 B8 26 FF 58 ...b......B..&.X
4000000000028AE0 08 08 00 7E 00 21 10 04 8C 00 42 00 08 10 01 84 ...~.!....B.....
4000000000028AF0 19 10 02 48 00 21 30 04 94 00 42 00 D8 EE 05 50 ...H.!0...B....P
4000000000028B00 09 78 00 48 10 10 10 00 FC 00 42 60 04 40 00 84 .x.H......B`.@..
4000000000028B10 03 00 00 00 01 00 E0 00 3C 2C 00 C0 81 70 00 80 ........<,...p..
4000000000028B20 10 00 00 1C 80 11 00 00 00 02 00 00 B0 E8 FF 48 ...............H
4000000000028B30 11 08 02 00 20 24 00 00 00 02 00 00 18 2A FF 58 .... $.......*.X
4000000000028B40 09 38 00 10 06 39 10 00 FC 00 42 00 08 61 00 84 .8...9....B..a..
4000000000028B50 E9 70 40 18 00 21 00 00 00 02 80 03 11 00 00 90 .p@..!..........
4000000000028B60 F3 00 E4 1C 80 D1 01 20 F8 FF 25 00 68 2B FF 58 ....... ..%.h+.X
4000000000028B70 08 78 40 18 00 21 00 00 00 02 00 C0 01 40 58 00 .x@..!.......@X.
4000000000028B80 03 08 00 7E 00 21 70 B8 9E 0C 73 C0 F1 70 00 80 ...~.!p...s..p..
4000000000028B90 10 00 00 1C 80 11 00 00 00 02 00 03 40 F0 FF 4A ............@..J
4000000000028BA0 10 00 00 00 01 00 00 00 00 02 00 00 40 FB FF 48 ............@..H
4000000000028BB0 08 10 32 FA FD 27 00 00 00 02 00 00 08 61 80 84 ..2..'.......a..
4000000000028BC0 09 08 02 00 01 24 00 00 00 02 00 00 04 08 01 84 .....$..........
4000000000028BD0 11 10 02 84 18 10 00 00 00 02 00 00 D8 29 FF 58 .............).X
4000000000028BE0 09 78 01 10 00 21 10 00 FC 00 42 00 08 61 80 84 .x...!....B..a..
4000000000028BF0 09 00 00 00 01 00 70 00 BC 0C 73 00 00 00 04 00 ......p...s.....
4000000000028C00 E2 78 40 18 20 A1 01 79 30 42 42 00 00 00 04 00 .x@. ..y0BB.....
4000000000028C10 F8 00 00 1E 80 91 01 00 40 00 23 00 70 F6 FF 48 ........@.#.p..H
4000000000028C20 08 10 52 FA FD 27 00 00 00 02 00 00 08 61 80 84 ..R..'.......a..
4000000000028C30 09 08 02 00 01 24 00 00 00 02 00 00 04 08 01 84 .....$..........
4000000000028C40 11 10 02 84 18 10 00 00 00 02 00 00 68 29 FF 58 ............h).X
4000000000028C50 09 78 01 10 00 21 10 00 FC 00 42 00 08 61 80 84 .x...!....B..a..
4000000000028C60 09 00 00 00 01 00 70 00 BC 0C 73 00 00 00 04 00 ......p...s.....
4000000000028C70 E2 78 40 18 20 A1 01 79 30 42 42 00 00 00 04 00 .x@. ..y0BB.....
4000000000028C80 F8 00 00 1E 80 91 01 00 40 00 23 00 00 F6 FF 48 ........@.#....H
4000000000028C90 08 10 72 FA FD 27 00 00 00 02 00 00 08 61 80 84 ..r..'.......a..
4000000000028CA0 09 08 02 00 01 24 00 00 00 02 00 00 04 08 01 84 .....$..........
4000000000028CB0 11 10 02 84 18 10 00 00 00 02 00 00 F8 28 FF 58 .............(.X
4000000000028CC0 09 78 01 10 00 21 10 00 FC 00 42 00 08 61 80 84 .x...!....B..a..
4000000000028CD0 09 00 00 00 01 00 70 00 BC 0C 73 00 00 00 04 00 ......p...s.....
4000000000028CE0 E2 78 40 18 20 A1 01 79 30 42 42 00 00 00 04 00 .x@. ..y0BB.....
4000000000028CF0 F8 00 00 1E 80 91 01 00 40 00 23 00 90 F5 FF 48 ........@.#....H
4000000000028D00 08 10 92 FA FD 27 00 00 00 02 00 00 08 61 80 84 .....'.......a..
4000000000028D10 09 08 02 00 01 24 00 00 00 02 00 00 04 08 01 84 .....$..........
4000000000028D20 11 10 02 84 18 10 00 00 00 02 00 00 88 28 FF 58 .............(.X
4000000000028D30 09 78 01 10 00 21 10 00 FC 00 42 00 08 61 80 84 .x...!....B..a..
4000000000028D40 09 00 00 00 01 00 70 00 BC 0C 73 00 00 00 04 00 ......p...s.....
4000000000028D50 E2 78 40 18 20 A1 01 79 30 42 42 00 00 00 04 00 .x@. ..y0BB.....
4000000000028D60 F8 00 00 1E 80 91 01 00 40 00 23 00 20 F5 FF 48 ........@.#. ..H
4000000000028D70 08 80 08 00 00 24 E0 08 00 00 48 E0 11 00 00 90 .....$....H.....
4000000000028D80 09 00 D8 10 80 11 F0 0A 00 00 48 00 04 08 01 84 ..........H.....
4000000000028D90 02 70 88 1C 00 20 00 11 41 00 40 00 00 00 04 00 .p... ..A.@.....
4000000000028DA0 18 00 3C 1C 80 11 00 00 40 00 23 00 60 EF FF 48 ..<.....@.#.`..H
4000000000028DB0 08 08 02 46 00 21 00 04 88 00 42 40 08 20 01 84 ...F.!....B@. ..
4000000000028DC0 19 18 02 4A 00 21 00 02 84 00 42 00 08 EC 05 50 ...J.!....B....P
4000000000028DD0 09 78 00 48 10 10 10 00 FC 00 42 60 04 40 00 84 .x.H......B`.@..
4000000000028DE0 03 00 00 00 01 00 E0 00 3C 2C 00 C0 81 70 00 80 ........<,...p..
4000000000028DF0 10 00 00 1C 80 11 00 00 00 02 00 00 E0 E5 FF 48 ...............H
4000000000028E00 11 88 00 10 00 21 00 02 88 00 42 00 00 F6 FF 48 .....!....B....H
4000000000028E10 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000028E20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000028E30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000028E40: 4000000000028E40
;;   Called from:
;;     400000000002967C (in fn4000000000029100)
;;     400000000002A0AC (in fn4000000000029100)
;;     400000000002A0AC (in fn4000000000029100)
;;     400000000002AC0C (in read_secondary_line)
;;     400000000002B26C (in fn400000000002AC80)
;;     400000000002DD6C (in fn400000000002D840)
;;     400000000003178C (in fn4000000000030880)
;;     4000000000034E4C (in fn4000000000030880)
;;     40000000000369BC (in fn4000000000036900)
;;     400000000003CE2C (in yyparse)
fn4000000000028E40 proc
	{ alloc	r36,ar.pfs,0x7,0x0,0x6; addl	r14,6516,r1; mov	r35,b3 }
	{ adds	r37,0x0,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; addl	r14,6628,r1; (p06) br.cond.dpnt.few	4000000000028EC0; }

l4000000000028E80:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; adds	r14,0x18,r14; (p06) br.cond.dpnt.few	4000000000028EE0; }

l4000000000028EA0:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	4000000000028EE0 }

l4000000000028EC0:
	{ nop.m	0x0; mov.i	ar.pfs,r36; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r35,4000000000028ED0; br.ret	b0 }

l4000000000028EE0:
	{ addl	r38,-308,r1; addl	r34,8972,r1; addl	r32,6684,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }
	{ ld8	r38,[r38]; nop.m	0x0; br.call.sptk.many	b0,get_string_value; }
	{ adds	r1,0x0,r37; addl	r38,-300,r1; addl	r33,8964,r1 }
	{ st8	[r8],r34; nop.m	0x0; nop.i	0x0 }
	{ ld8	r38,[r38]; nop.m	0x0; br.call.sptk.many	b0,get_string_value; }
	{ ld8	r14,[r32]; adds	r1,0x0,r37; cmp.eq	p07,p06,0x0,r14 }
	{ st8	[r8],r33; nop.i	0x0; (p07) adds	r14,0x0,r34 }

l4000000000028F60:
	{ (p07) st8	[r34],r32; ld8	r38,[r14]; nop.i	0x0; }

l4000000000028F66:
	{ (p19) fwb; nop; (p48) nop }
	{ chk.a.nc	f0,3FFFFFFFFF029776; nop; break.i	0x80000 }

l4000000000028F80:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,decode_prompt_string; }
	{ nop.m	0x0; adds	r34,0x0,r8; adds	r1,0x0,r37 }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.spnt.few	40000000000290A0; }

l4000000000028FB0:
	{ addl	r15,6468,r1; ld8	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4	r16,[r15]; ld8	r15,[r14]; addl	r14,8988,r1 }
	{ st8	[r33],r32; nop.m	0x0; cmp4.eq	p07,p06,0x0,r16; }
	{ st8	[r15],r14; nop.i	0x0; (p06) br.cond.dptk.few	4000000000029060 }

l4000000000029000:
	{ addl	r32,6668,r1; ld8	r38,[r32]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r38; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000029040; }

l4000000000029020:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r37; nop.m	0x0; nop.i	0x0 }

l4000000000029040:
	{ st8	[r34],r32; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,4000000000029050; br.ret	b0 }

l4000000000029060:
	{ addl	r32,6748,r1; ld8	r38,[r32]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r38; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000029040; }

l4000000000029080:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r37; br.cond.sptk.few	4000000000029040 }

l40000000000290A0:
	{ addl	r38,1,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ nop.m	0x0; adds	r1,0x0,r37; adds	r34,0x0,r8 }
	{ nop.m	0x0; st1	[r0],r8; br.cond.sptk.few	4000000000028FB0; }
40000000000290D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000290E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000290F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000029100: 4000000000029100
;;   Called from:
;;     400000000002ACBC (in fn400000000002AC80)
;;     400000000002AEFC (in fn400000000002AC80)
;;     400000000002B91C (in fn400000000002AC80)
;;     400000000002BE1C (in fn400000000002AC80)
;;     400000000002CC0C (in fn400000000002AC80)
;;     400000000002DA6C (in fn400000000002D840)
;;     400000000002FC7C (in fn400000000002FC00)
;;     4000000000030B1C (in fn4000000000030880)
;;     4000000000030CBC (in fn4000000000030880)
;;     400000000003140C (in fn4000000000030880)
;;     4000000000032C2C (in fn4000000000030880)
;;     400000000003338C (in fn4000000000030880)
;;     400000000003344C (in fn4000000000030880)
;;     400000000003386C (in fn4000000000030880)
;;     4000000000034B8C (in fn4000000000030880)
;;     4000000000034C1C (in fn4000000000030880)
;;     400000000003531C (in fn4000000000030880)
;;     40000000000354CC (in fn4000000000030880)
;;     4000000000035D7C (in fn4000000000030880)
;;     4000000000035F0C (in fn4000000000030880)
;;     400000000003600C (in fn4000000000030880)
fn4000000000029100 proc
	{ alloc	r61,ar.pfs,0x23,0x0,0x1F; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r60,b4 }
	{ addl	r36,7676,r1; addl	r37,7684,r1; adds	r62,0x0,r1; }
	{ nop.m	0x0; ld4.acq	r14,[r36]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000029E80; }

l4000000000029140:
	{ nop.m	0x0; ld4.acq	r14,[r37]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	4000000000029E30 }

l4000000000029160:
	{ addl	r14,7680,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4.acq	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p07) br.cond.dpnt.few	4000000000029E00 }

l4000000000029190:
	{ addl	r14,6796,r1; addl	r35,6788,r1; addl	r39,6724,r1; }
	{ ld4	r46,[r14]; cmp4.eq	p06,p07,0x0,r46; nop.i	0x0; }
	{ (p07) st4	[r0],r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000029D60; }

l40000000000291B6:
	{ chk.a.nc	f0,3FFFFFFFFF0299B6; nop; break.i	0x80000 }

l40000000000291C0:
	{ nop.m	0x0; ld8	r14,[r35]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000002A390; }

l40000000000291E0:
	{ ld4	r15,[r39]; nop.m	0x0; sxt4	r16,r15; }
	{ add	r14,r14,r16; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000029240 }

l4000000000029220:
	{ addl	r34,6628,r1; ld8	r16,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r16; (p07) br.cond.dpnt.few	400000000002A390; }

l4000000000029240:
	{ cmp4.eq	p07,p06,0x0,r32; addl	r42,8944,r1; addl	r40,6516,r1 }
	{ addl	r45,22532,r1; addl	r38,6628,r1; addl	r48,6824,r1; }
	{ (p06) addl	r44,1,r0; addl	r47,6828,r1; addl	r49,6724,r1 }

l4000000000029266:
	{ Invalid; (p24) nop; break.b	0x80000 }
	{ Invalid; (p16) cmp.ne.or	p56,p08,r1,r51; (p01) nop.b	0xB }

l4000000000029286:
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ break.m	0x4000; break.i	0x4000; break.i	0x80000 }

l40000000000292A0:
	{ nop.m	0x0; zxt1	r14,r14; adds	r15,0x1,r15 }

l40000000000292A2:
	{ Invalid; (p32) nop; Invalid }
	{ Invalid; (p28) break.i	0x48660; Invalid }
	{ Invalid; (p32) nop; (p03) chk.s.i	r32,40000000002BD2C2 }

l40000000000292D0:
	{ (p09) st4	[r15],r39; nop.m	0x0; nop.i	0x0; }

l40000000000292D6:
	{ break.m	0x4000; Invalid; (p32) nop }

l40000000000292E0:
	{ cmp4.eq	p06,p07,0x5C,r14; addl	r34,6628,r1; (p06) addl	r15,1,r0; }

l40000000000292F0:
	{ (p07) adds	r15,0x0,r0; and	r15,r44,r15; nop.i	0x0; }

l40000000000292F6:
	{ Invalid; nop; nop }
	{ chk.a.nc	r0,3FFFFFFFFF029B06; nop; (p32) nop }

l4000000000029310:
	{ ld4	r14,[r39]; ld8	r16,[r35]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r15,r14; cmp4.lt	p09,p08,0x1,r14; }
	{ add	r16,r16,r15; ld1	r16,[r16]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r16,r16; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0xA,r16; (p06) br.cond.dpnt.few	4000000000029D50; (p08) br.cond.dpnt.few	40000000000293A0; }

l400000000002935C:
	{ (p02) cmp.lt	p00,p11,r64,r33; (p01) cmp.lt	p32,p08,r10,r6; (p33) epc }

l4000000000029360:
	{ ld8	r14,[r41]; add	r14,r14,r15; nop.i	0x0; }
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	4000000000029D50 }

l40000000000293A0:
	{ nop.m	0x0; ld4	r14,[r40]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000293E0 }

l40000000000293C0:
	{ ld4	r14,[r45]; adds	r14,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x1,r14; (p07) br.cond.dpnt.few	4000000000029670 }

l40000000000293E0:
	{ ld4	r15,[r33]; ld8	r14,[r38]; nop.i	0x0; }
	{ adds	r15,0x1,r15; adds	r16,0x18,r14; cmp.eq	p06,p07,0x0,r14; }
	{ st4	[r15],r33; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000296C0 }

l4000000000029410:
	{ nop.m	0x0; ld8	r14,[r16]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000296C0; }

l4000000000029430:
	{ ld4	r15,[r39]; ld8	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r16,r15; add	r16,r14,r16,0x1; }
	{ ld1	r16,[r16]; nop.m	0x0; sxt1	r16,r16; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r16; (p07) br.cond.dpnt.few	4000000000029610 }

l4000000000029470:
	{ ld8	r14,[r34]; nop.m	0x0; addl	r43,6828,r1; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000029DA0; }

l4000000000029490:
	{ nop.m	0x0; ld8	r15,[r35]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r15; adds	r63,0x0,r15; (p06) br.cond.dpnt.few	40000000000294D0; }

l40000000000294B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r62; ld8	r14,[r38]; nop.i	0x0; }

l40000000000294D0:
	{ adds	r15,0x24,r14; adds	r19,0x8,r14; adds	r63,0x0,r14 }
	{ adds	r16,0x10,r14; adds	r18,0x20,r14; adds	r17,0x28,r14; }
	{ ld4	r15,[r15]; ld8	r16,[r16]; nop.i	0x0; }
	{ st4	[r15],r39; ld4	r15,[r19]; nop.i	0x0 }
	{ st8	[r16],r35; ld4	r17,[r17]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r15; ld4	r15,[r42]; nop.i	0x0 }
	{ st4	[r17],r47; ld4	r18,[r18]; nop.i	0x0; }
	{ (p07) or	r15,0x2,r15; st4	[r18],r48; nop.i	0x0; }

l4000000000029546:
	{ mf.a; addl	r0,32768,r1; (p49) nop }

l4000000000029556:
	{ mf.a; nop; (p48) nop }
	{ (p07) fwb; nop; nop }
	{ Invalid; (p07) cmp4.eq.or	p16,p02,0xE,r0; (p33) cmp.ltu	p03,p00,r96,r3 }

l4000000000029586:
	{ Invalid; cmp4.eq	p00,p00,r0,r1; (p01) nop; }

l400000000002958C:
	{ Invalid; Invalid; break.i	0x1000 }

l4000000000029596:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; nop; break.i	0x80000 }
	{ (p07) fwb; mov	pr,0x4000; break.b	0x80000 }
	{ (p08) add	r0,r14,r22; (p08) nop; (p48) nop }
	{ (p07) fwb; nop; break.i	0x80000 }
	{ (p04) chk.s.m	r14,4000000000CEDDF6; nop; nop }

l4000000000029600:
	{ st4	[r17],r49; nop.i	0x0; br.cond.sptk.few	40000000000292E0 }

l4000000000029610:
	{ adds	r15,0x1,r15; addl	r34,6628,r1; sxt4	r16,r15 }
	{ st4	[r15],r49; adds	r15,0x1,r15; add	r14,r14,r16; }
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; zxt1	r14,r14; cmp4.eq	p08,p09,0x0,r14; }
	{ (p09) st4	[r15],r39; nop.i	0x0; (p09) br.cond.dptk.few	40000000000292E0 }

l4000000000029656:
	{ nop; nop; break.i	0x80000 }

l4000000000029660:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000029470 }

l4000000000029670:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000028E40; }
	{ nop.m	0x0; ld4	r15,[r33]; adds	r1,0x0,r62 }
	{ nop.m	0x0; ld8	r14,[r38]; nop.i	0x0; }
	{ adds	r15,0x1,r15; adds	r16,0x18,r14; cmp.eq	p06,p07,0x0,r14; }
	{ st4	[r15],r33; nop.i	0x0; (p07) br.cond.dptk.few	4000000000029410 }

l40000000000296C0:
	{ addl	r44,22532,r1; addl	r54,9308,r1; addl	r51,6512,r1 }
	{ addl	r50,6468,r1; addl	r49,6116,r1; addl	r42,7676,r1; }
	{ nop.m	0x0; addl	r45,6516,r1; addl	r59,-10356,r1 }
	{ addl	r48,8952,r1; addl	r55,9156,r1; addl	r52,8988,r1; }
	{ nop.m	0x0; addl	r43,6828,r1; addl	r40,6824,r1 }
	{ addl	r47,6720,r1; adds	r38,0x18,r44; addl	r57,-1,r0; }
	{ nop.m	0x0; adds	r56,0x8,r54; addl	r58,6788,r1 }
	{ addl	r53,6684,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }
	{ ld8	r59,[r59]; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000029780:
	{ nop.m	0x0; ld4.acq	r14,[r36]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	4000000000029F80 }

l40000000000297A0:
	{ nop.m	0x0; ld4.acq	r14,[r37]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	4000000000029ED0 }

l40000000000297C0:
	{ ld4	r14,[r51]; st4	[r0],r43; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	4000000000029F10 }

l40000000000297E0:
	{ ld4	r14,[r45]; nop.i	0x0; cmp4.eq	p07,p06,0x0,r14 }
	{ nop.m	0x0; ld4	r14,[r44]; (p07) br.cond.dptk.few	4000000000029820; }

l4000000000029800:
	{ nop.m	0x0; adds	r15,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x1,r15; (p07) br.cond.dpnt.few	4000000000029F10 }

l4000000000029820:
	{ nop.m	0x0; ld4	r15,[r50]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	4000000000029F50 }

l4000000000029840:
	{ nop.m	0x0; ld4	r15,[r45]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	4000000000029F50 }

l4000000000029860:
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r14; nop.m	0x0; adds	r34,0x0,r0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x1,r14; (p07) br.cond.dpnt.few	400000000002A350; }

l4000000000029880:
	{ adds	r41,0x0,r34; nop.m	0x0; nop.i	0x0 }

l4000000000029890:
	{ ld8	r8,[r38]; ld8	r14,[r8],8; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r14,40000000000298A0; nop.i	0x0 }
	{ ld8	r1,[r8]; nop.m	0x0; br.call.sptk.many	b0,b6; }
	{ ld4.acq	r14,[r36]; adds	r1,0x0,r62; adds	r33,0x0,r8; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000029FE0; }

l40000000000298E0:
	{ nop.m	0x0; ld4.acq	r14,[r37]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	4000000000029FC0; }

l4000000000029900:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r33; (p06) br.cond.dptk.few	4000000000029890 }

l4000000000029910:
	{ ld4	r16,[r40]; adds	r15,0x2,r34; adds	r17,0x0,r34; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r15,r16; nop.i	0x0; }
	{ (p07) ld8	r8,[r35]; nop.i	0x0; (p07) br.cond.dptk.few	40000000000299E0 }

l4000000000029936:
	{ chk.a.nc	f0,3FFFFFFFFF02A136; nop; (p32) nop }

l4000000000029940:
	{ adds	r14,0x0,r16; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000029960:
	{ nop.m	0x0; adds	r14,0x100,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r15,r14; (p06) br.cond.dptk.few	4000000000029960 }

l4000000000029980:
	{ nop.m	0x0; sub	r14,0x2,r16; adds	r16,0x100,r16 }
	{ ld8	r63,[r35]; add	r17,r17,r14; nop.i	0x0; }
	{ nop.m	0x0; extr	r17,r17,8,24; dep.z	r17,0x11,8,24; }
	{ nop.m	0x0; add	r64,r16,r17; nop.i	0x0; }
	{ st4	[r64],r40; sxt4	r64,r64; br.call.sptk.many	b0,xrealloc; }
	{ adds	r1,0x0,r62; st8	[r8],r35; nop.i	0x0 }

l40000000000299E0:
	{ add	r14,r8,r34; nop.m	0x0; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r33 }
	{ adds	r34,0x1,r34; nop.m	0x0; (p07) br.cond.dpnt.few	400000000002A0E0; }

l4000000000029A00:
	{ st1	[r33],r14; cmp4.eq	p07,p06,0xA,r33; (p06) br.cond.dptk.few	4000000000029880 }

l4000000000029A10:
	{ st1	[r0],r14; ld4	r14,[r48]; nop.i	0x0; }
	{ nop.m	0x0; adds	r14,0x1,r14; nop.i	0x0; }
	{ st4	[r14],r48; nop.m	0x0; nop.i	0x0 }

l4000000000029A40:
	{ nop.m	0x0; st4	[r0],r39; nop.i	0x0 }
	{ st4	[r41],r47; nop.m	0x0; br.call.sptk.many	b0,fn40000000000253C0; }
	{ nop.m	0x0; ld4	r14,[r49]; adds	r1,0x0,r62 }
	{ nop.m	0x0; ld8	r33,[r35]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	400000000002A040; }

l4000000000029A90:
	{ cmp.eq	p06,p07,0x0,r33; nop.i	0x0; (p06) br.cond.dpnt.few	400000000002A050; }

l4000000000029AA0:
	{ ld1	r14,[r33]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	400000000002A120 }

l4000000000029AC0:
	{ nop.m	0x0; ld4	r14,[r48]; nop.i	0x0; }
	{ cmp4.lt	p07,p06,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000029B80; }

l4000000000029AE0:
	{ ld4	r14,[r56]; nop.m	0x0; adds	r63,0x0,r33; }
	{ cmp4.eq	p06,p07,0x0,r14; sxt4	r14,r14; (p06) br.cond.dpnt.few	4000000000029B40; }

l4000000000029B00:
	{ ld8	r15,[r54]; add	r14,r15,r14; nop.i	0x0; }
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	400000000002A470 }

l4000000000029B40:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,history_delimiting_chars; }
	{ adds	r1,0x0,r62; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	4000000000029B80; }

l4000000000029B60:
	{ ld1	r14,[r8]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x3B,r14; (p07) br.cond.dpnt.few	400000000002A020 }

l4000000000029B80:
	{ addl	r14,7376,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000029C40 }

l4000000000029BB0:
	{ ld1	r14,[r33]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000029BF0; }

l4000000000029BD0:
	{ nop.m	0x0; ld4	r14,[r43]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r14; (p07) br.cond.dpnt.few	4000000000029CD0 }

l4000000000029BF0:
	{ addl	r14,-10652,r1; addl	r65,-292,r1; addl	r64,1,r0 }
	{ adds	r66,0x0,r33; ld8	r14,[r14]; nop.i	0x0 }
	{ ld8	r65,[r65]; nop.i	0x0; nop.i	0x0 }
	{ ld8	r63,[r14]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ adds	r1,0x0,r62; nop.m	0x0; nop.i	0x0 }

l4000000000029C40:
	{ nop.m	0x0; ld4	r14,[r43]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000029CD0; }

l4000000000029C60:
	{ ld4	r14,[r47]; ld4	r15,[r40]; nop.i	0x0; }
	{ adds	r16,0x2,r14; nop.m	0x0; sxt4	r14,r14; }
	{ cmp4.lt	p07,p06,r16,r15; nop.i	0x0; (p06) br.cond.dpnt.few	400000000002A4B0; }

l4000000000029C90:
	{ (p07) ld8	r8,[r35]; addl	r15,10,r0; add	r14,r8,r14; }

l4000000000029C96:
	{ Invalid; Invalid; (p16) br.call.spnt.many.clr	b0,b3 }
	{ break.m	0x4000; nop; nop }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; nop; (p48) nop }

l4000000000029CD0:
	{ ld4	r15,[r39]; cmp4.eq	p07,p06,0x0,r32; addl	r42,8944,r1 }
	{ addl	r40,6516,r1; addl	r45,22532,r1; addl	r38,6628,r1; }
	{ ld8	r14,[r35]; addl	r48,6824,r1; sxt4	r16,r15 }
	{ (p06) addl	r44,1,r0; addl	r47,6828,r1; addl	r49,6724,r1; }

l4000000000029D06:
	{ Invalid; (p24) nop; Invalid }
	{ Invalid; (p20) nop; break.i	0x80000; }

l4000000000029D1C:
	{ (p62) nop; nop; }
	{ (p60) cmp.lt	p01,p09,r51,r72; break.x	0x8000E00201000 }
	{ invala; cmp.lt	p00,p00,r32,r0; (p01) break.i	0x141C0 }
	{ (p43) cmp.lt.unc	p62,p09,r63,r36; zxt4	r23,r0; break.i	0x1000 }

l4000000000029D50:
	{ addl	r46,92,r0; nop.m	0x0; nop.i	0x0; }

l4000000000029D60:
	{ adds	r8,0x0,r46; mov.i	ar.pfs,r61; mov.spnt	b0,r60,4000000000029D60 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000029D80:
	{ addl	r43,6828,r1; (p09) adds	r46,0x0,r14; (p09) br.cond.spnt.few	4000000000029D60; }

l4000000000029D8C:
	{ (p63) nop; break.i	0x1000; break.i	0x1000 }

l4000000000029D90:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000029DA0:
	{ nop.m	0x0; ld4	r14,[r43]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r14; (p06) br.cond.dptk.few	4000000000029D60 }

l4000000000029DC0:
	{ ld4	r46,[r39]; cmp4.eq	p06,p07,0x0,r46; nop.i	0x0; }
	{ (p06) addl	r46,-1,r0; (p07) addl	r46,10,r0; nop.i	0x0; }

l4000000000029DD6:
	{ Invalid; Invalid; nop; }

l4000000000029DDC:
	{ Invalid; zxt1	r64,r64; (p16) break.i	0x2A80F }
	{ (p30) nop; add	r0,r32,r0; (p01) shladd	r4,r3,0x1,r64 }
	{ nop; break.m	0x1000; cmp.eq.unc	p00,p08,r3,r108 }

l4000000000029E00:
	{ nop.m	0x0; st4.rel	[r0],r14; adds	r63,0x0,r0 }
	{ adds	r64,0x0,r0; adds	r65,0x0,r0; br.call.sptk.many	b0,get_new_window_size; }
	{ nop.m	0x0; adds	r1,0x0,r62; br.cond.sptk.few	4000000000029190 }

l4000000000029E30:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,throw_to_top_level; }
	{ adds	r1,0x0,r62; addl	r14,7680,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4.acq	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	4000000000029190 }

l4000000000029E70:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000029E00 }

l4000000000029E80:
	{ ld4.acq	r63,[r36]; nop.i	0x0; br.call.sptk.many	b0,termsig_handler; }
	{ adds	r1,0x0,r62; addl	r37,7684,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4.acq	r14,[r37]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000029160 }

l4000000000029EC0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000029E30 }

l4000000000029ED0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,throw_to_top_level; }
	{ nop.m	0x0; ld4	r14,[r51]; adds	r1,0x0,r62 }
	{ nop.m	0x0; st4	[r0],r43; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	40000000000297E0 }

l4000000000029F10:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,notify_and_cleanup; }
	{ nop.m	0x0; ld4	r15,[r50]; adds	r1,0x0,r62 }
	{ nop.m	0x0; ld4	r14,[r44]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p07) br.cond.dptk.few	4000000000029840; }

l4000000000029F50:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2,r14; nop.i	0x0; }
	{ (p07) ld8	r63,[r59]; nop.i	0x0; (p07) br.call.dpnt.many	b0,fn400000000001BE00 }

l4000000000029F66:
	{ chk.a.nc	f0,3FFFFFFFFF02A766; (p32) nop; break.i	0x80000 }

l4000000000029F70:
	{ nop.m	0x0; adds	r34,0x0,r0; br.cond.sptk.few	4000000000029880; }

l4000000000029F80:
	{ ld4.acq	r63,[r42]; nop.i	0x0; br.call.sptk.many	b0,termsig_handler; }
	{ ld4.acq	r14,[r37]; nop.m	0x0; adds	r1,0x0,r62; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000297C0 }

l4000000000029FB0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000029ED0 }

l4000000000029FC0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,throw_to_top_level; }
	{ nop.m	0x0; adds	r1,0x0,r62; br.cond.sptk.few	4000000000029900 }

l4000000000029FE0:
	{ ld4.acq	r63,[r42]; nop.i	0x0; br.call.sptk.many	b0,termsig_handler; }
	{ ld4.acq	r14,[r37]; nop.m	0x0; adds	r1,0x0,r62; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000029900 }

l400000000002A010:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000029FC0 }

l400000000002A020:
	{ adds	r63,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,maybe_add_history; }
	{ adds	r1,0x0,r62; ld8	r33,[r35]; nop.i	0x0; }

l400000000002A040:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r33; (p07) br.cond.spnt.few	4000000000029B80 }

l400000000002A050:
	{ nop.m	0x0; ld4	r14,[r45]; nop.i	0x0 }
	{ st4	[r0],r40; st8	[r52],r53; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000029780 }

l400000000002A080:
	{ ld4	r14,[r44]; adds	r14,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x1,r14; (p06) br.cond.dptk.few	4000000000029780 }

l400000000002A0A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000028E40; }
	{ ld4.acq	r14,[r36]; nop.m	0x0; adds	r1,0x0,r62; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000297A0 }

l400000000002A0D0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000029F80 }

l400000000002A0E0:
	{ nop.m	0x0; ld4	r14,[r44]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x2,r14; sxt4	r14,r41; (p07) br.cond.dpnt.few	400000000002A290; }

l400000000002A100:
	{ cmp4.eq	p07,p06,0x0,r41; add	r8,r8,r14; nop.i	0x0 }
	{ (p07) st4	[r57],r43; st1	[r0],r8; br.cond.sptk.few	4000000000029A40 }

l400000000002A116:
	{ mf.a; nop; (p32) nop }

l400000000002A120:
	{ ld4	r14,[r56]; ld4	r41,[r55]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	400000000002A230 }

l400000000002A140:
	{ addl	r64,1,r0; nop.m	0x0; addl	r65,1,r0 }
	{ adds	r63,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,pre_process_line; }
	{ ld8	r33,[r35]; nop.m	0x0; adds	r34,0x0,r8 }
	{ adds	r1,0x0,r62; st4	[r41],r55; nop.i	0x0; }
	{ cmp.eq	p06,p07,r33,r8; nop.i	0x0; (p06) br.cond.dpnt.few	400000000002A040; }

l400000000002A190:
	{ adds	r63,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r34; adds	r1,0x0,r62 }
	{ st8	[r34],r58; adds	r63,0x0,r34; (p06) br.cond.dpnt.few	400000000002A2F0; }

l400000000002A1C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r14,0x0,r8; cmp4.eq	p07,p06,0x0,r8; nop.i	0x0 }
	{ adds	r1,0x0,r62; st4	[r8],r47; (p07) br.cond.dpnt.few	400000000002A300; }

l400000000002A1F0:
	{ st4	[r14],r40; nop.i	0x0; br.call.sptk.many	b0,fn40000000000253C0; }
	{ adds	r1,0x0,r62; ld8	r33,[r35]; nop.i	0x0; }

l400000000002A210:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r33; (p06) br.cond.sptk.few	400000000002A050 }

l400000000002A220:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000029B80 }

l400000000002A230:
	{ ld8	r15,[r54]; sxt4	r14,r14; add	r14,r15,r14; }
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x27,r14; (p07) addl	r14,9156,r1; (p07) addl	r15,1,r0; }

l400000000002A26C:
	{ nop; break.i	0x1000; break.b	0x1000; }

l400000000002A270:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ (p07) st4	[r15],r14; nop.i	0x0; br.cond.sptk.few	400000000002A140 }

l400000000002A286:
	{ break.m	0x4000; nop; (p32) nop }

l400000000002A290:
	{ adds	r14,0x10,r12; ld8	r63,[r59]; nop.i	0x0; }
	{ st8	[r8],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BE00; }
	{ adds	r14,0x10,r12; cmp4.eq	p07,p06,0x0,r41; adds	r1,0x0,r62; }
	{ nop.m	0x0; ld8	r8,[r14]; sxt4	r14,r41 }
	{ (p07) st4	[r57],r43; add	r8,r8,r14; nop.i	0x0; }

l400000000002A2D6:
	{ Invalid; nop; nop }
	{ break.m	0x4000; nop; nop }

l400000000002A2F0:
	{ st4	[r0],r47; nop.m	0x0; nop.i	0x0 }

l400000000002A300:
	{ ld4	r15,[r48]; nop.m	0x0; adds	r14,0x0,r0; }
	{ adds	r15,0xFFFFFFFFFFFFFFFF,r15; st4	[r14],r40; nop.i	0x0; }
	{ st4	[r15],r48; nop.i	0x0; br.call.sptk.many	b0,fn40000000000253C0; }
	{ nop.m	0x0; adds	r1,0x0,r62; nop.i	0x0 }
	{ ld8	r33,[r35]; nop.m	0x0; br.cond.sptk.few	400000000002A210 }

l400000000002A350:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000024900; }
	{ ld4	r14,[r44]; adds	r1,0x0,r62; cmp4.eq	p07,p06,0x2,r14; }
	{ (p07) ld8	r63,[r59]; nop.i	0x0; (p07) br.call.dpnt.many	b0,fn400000000001BE00; }

l400000000002A376:
	{ chk.a.nc	f0,3FFFFFFFFF02AB76; (p32) nop; break.i	0x80000 }

l400000000002A380:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000029F70 }

l400000000002A390:
	{ addl	r14,6648,r1; addl	r44,22532,r1; addl	r54,9308,r1 }
	{ addl	r51,6512,r1; addl	r50,6468,r1; addl	r49,6116,r1; }
	{ ld4	r15,[r14]; addl	r42,7676,r1; addl	r45,6516,r1 }
	{ addl	r59,-10356,r1; addl	r48,8952,r1; addl	r55,9156,r1; }
	{ nop.m	0x0; adds	r15,0x1,r15; addl	r52,8988,r1 }
	{ addl	r43,6828,r1; addl	r40,6824,r1; addl	r47,6720,r1; }
	{ nop.m	0x0; st4	[r15],r14; adds	r38,0x18,r44 }
	{ addl	r57,-1,r0; addl	r58,6788,r1; addl	r53,6684,r1; }
	{ nop.m	0x0; nop.m	0x0; adds	r56,0x8,r54 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld8	r59,[r59]; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000029780 }

l400000000002A470:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,maybe_add_history; }
	{ ld8	r33,[r58]; nop.m	0x0; adds	r1,0x0,r62; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r33; (p06) br.cond.sptk.few	400000000002A050 }

l400000000002A4A0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000029B80 }

l400000000002A4B0:
	{ adds	r16,0x2,r15; nop.m	0x0; addl	r14,6824,r1 }
	{ adds	r64,0x3,r15; ld8	r63,[r35]; nop.i	0x0; }
	{ st4	[r16],r14; sxt4	r64,r64; br.call.sptk.many	b0,xrealloc; }
	{ nop.m	0x0; adds	r1,0x0,r62; addl	r15,10,r0 }
	{ st8	[r8],r35; addl	r14,6720,r1; nop.i	0x0; }
	{ ld4	r14,[r14]; nop.m	0x0; sxt4	r14,r14; }
	{ add	r14,r8,r14; st1	[r14],r1,1; nop.i	0x0; }
	{ st1	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,fn40000000000253C0; }
	{ nop.m	0x0; adds	r1,0x0,r62; br.cond.sptk.few	4000000000029CD0; }

;; read_secondary_line: 400000000002A540
;;   Called from:
;;     400000000004426C (in make_here_document)
;;     40000000000443DC (in make_here_document)
read_secondary_line proc
	{ alloc	r50,ar.pfs,0x16,0x0,0x14; addl	r43,6516,r1; addl	r16,8964,r1 }
	{ addl	r15,6684,r1; addl	r37,22532,r1; adds	r51,0x0,r1; }
	{ nop.m	0x0; nop.m	0x0; mov	r49,b1 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }
	{ st8	[r16],r15; ld4	r14,[r43]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000002A5C0 }

l400000000002A5A0:
	{ ld4	r14,[r37]; adds	r14,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x1,r14; (p07) br.cond.dpnt.few	400000000002AC00 }

l400000000002A5C0:
	{ addl	r14,6468,r1; addl	r35,7676,r1; addl	r45,22532,r1 }
	{ addl	r36,7684,r1; adds	r38,0x0,r0; adds	r34,0x0,r0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; adds	r41,0x0,r35 }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000002A660 }

l400000000002A620:
	{ nop.m	0x0; ld4	r14,[r43]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000002A660 }

l400000000002A640:
	{ ld4	r14,[r37]; adds	r14,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x1,r14; (p07) br.cond.dpnt.few	400000000002AC20; }

l400000000002A660:
	{ cmp4.eq	p07,p06,0x0,r32; addl	r48,-10356,r1; adds	r37,0x18,r37 }
	{ adds	r47,0x20,r45; addl	r46,92,r0; addl	r40,6832,r1; }
	{ (p06) addl	r42,1,r0; addl	r39,6836,r1; addl	r44,6648,r1 }

l400000000002A686:
	{ Invalid; (p22) mov.dpnt	b0,r1,400000000002AAB6; br.call.sptk.few	b4,b0 }
	{ chk.a.nc	f0,3FFFFFFFFF02AE96; (p21) nop; break.i	0x80000 }

l400000000002A6A0:
	{ nop.m	0x0; ld4.acq	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	400000000002A8E0 }

l400000000002A6C0:
	{ nop.m	0x0; ld4.acq	r14,[r36]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.call.dpnt.many	b0,throw_to_top_level; }

l400000000002A6E0:
	{ ld8	r8,[r37]; ld8	r14,[r8],8; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r14,400000000002A6F0; nop.i	0x0 }
	{ ld8	r1,[r8]; nop.m	0x0; br.call.sptk.many	b0,b6; }
	{ nop.m	0x0; adds	r33,0x0,r8; adds	r1,0x0,r51 }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	400000000002A6A0; }

l400000000002A730:
	{ nop.m	0x0; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dpnt.few	400000000002A900 }

l400000000002A740:
	{ adds	r15,0x2,r34; ld4	r16,[r40]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r15,r16; (p06) br.cond.dptk.few	400000000002A800 }

l400000000002A760:
	{ adds	r14,0x0,r16; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000002A780:
	{ nop.m	0x0; adds	r14,0x80,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r15,r14; (p06) br.cond.dptk.few	400000000002A780 }

l400000000002A7A0:
	{ nop.m	0x0; sub	r53,0x2,r16; adds	r16,0x80,r16 }
	{ ld8	r52,[r39]; add	r53,r53,r34; nop.i	0x0; }
	{ nop.m	0x0; extr	r53,r53,7,25; dep.z	r53,0x35,7,25; }
	{ nop.m	0x0; add	r53,r16,r53; nop.i	0x0; }
	{ st4	[r53],r40; sxt4	r53,r53; br.call.sptk.many	b0,xrealloc; }
	{ adds	r1,0x0,r51; st8	[r8],r39; nop.i	0x0 }

l400000000002A800:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r38; (p07) br.cond.dptk.few	400000000002AA60; }

l400000000002A810:
	{ cmp4.eq	p06,p07,0x5C,r33; (p06) addl	r14,1,r0; nop.i	0x0; }

l400000000002A81C:
	{ cmp4.eq.and	p00,p43,r1,r0; (p01) cmp.lt	p00,p16,r0,r64; zxt1	r74,r3 }

l400000000002A826:
	{ Invalid; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFCEE116; nop; break.i	0x80000 }

l400000000002A840:
	{ nop.m	0x0; ld4.acq	r14,[r35]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000002A960; }

l400000000002A860:
	{ nop.m	0x0; ld4.acq	r14,[r36]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.call.dpnt.many	b0,throw_to_top_level; }

l400000000002A880:
	{ ld8	r8,[r37]; ld8	r14,[r8],8; nop.i	0x0; }
	{ ld8	r1,[r8]; mov.spnt	b6,r14,400000000002A890; br.call.sptk.many	b0,b6; }
	{ adds	r1,0x0,r51; cmp4.eq	p07,p06,0xA,r8; (p06) br.cond.dptk.few	400000000002A9D0 }

l400000000002A8B0:
	{ ld4	r14,[r44]; adds	r14,0x1,r14; nop.i	0x0; }
	{ st4	[r14],r44; ld4.acq	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000002A6C0; }

l400000000002A8E0:
	{ ld4.acq	r52,[r41]; nop.i	0x0; br.call.sptk.many	b0,termsig_handler; }
	{ nop.m	0x0; adds	r1,0x0,r51; br.cond.sptk.few	400000000002A6C0 }

l400000000002A900:
	{ nop.m	0x0; ld4	r14,[r43]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000002A940 }

l400000000002A920:
	{ nop.m	0x0; ld4	r14,[r45]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2,r14; (p07) br.cond.dpnt.few	400000000002AB60; }

l400000000002A940:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r34; (p06) br.cond.dpnt.few	400000000002AB80 }

l400000000002A950:
	{ nop.m	0x0; addl	r33,10,r0; br.cond.sptk.few	400000000002A740 }

l400000000002A960:
	{ ld4.acq	r52,[r41]; nop.i	0x0; br.call.sptk.many	b0,termsig_handler; }
	{ ld4.acq	r14,[r36]; nop.m	0x0; adds	r1,0x0,r51; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.call.dpnt.many	b0,throw_to_top_level; }

l400000000002A990:
	{ ld8	r8,[r37]; ld8	r14,[r8],8; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r14,400000000002A9A0; nop.i	0x0 }
	{ ld8	r1,[r8]; nop.m	0x0; br.call.sptk.many	b0,b6; }
	{ adds	r1,0x0,r51; cmp4.eq	p07,p06,0xA,r8; (p07) br.cond.dpnt.few	400000000002A8B0 }

l400000000002A9D0:
	{ ld8	r14,[r47]; adds	r52,0x0,r8; addl	r38,1,r0; }
	{ ld8	r15,[r14],8; nop.m	0x0; mov.spnt	b6,r15,400000000002A9E0 }
	{ ld8	r1,[r14]; nop.m	0x0; br.call.sptk.many	b0,b6; }
	{ nop.m	0x0; sxt4	r15,r34; nop.b	0x0 }
	{ ld8	r14,[r39]; adds	r1,0x0,r51; adds	r34,0x1,r34; }
	{ add	r14,r14,r15; st1	[r46],r14; nop.i	0x0; }
	{ nop.m	0x0; ld4.acq	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000002A6C0 }

l400000000002AA50:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000002A8E0; }

l400000000002AA60:
	{ nop.m	0x0; ld8	r14,[r39]; sxt4	r15,r34 }
	{ addl	r16,6836,r1; adds	r34,0x1,r34; cmp4.eq	p07,p06,0xA,r33; }
	{ add	r14,r14,r15; nop.m	0x0; adds	r38,0x0,r0; }
	{ st1	[r33],r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000002AAD0; }

l400000000002AAA0:
	{ nop.m	0x0; ld4.acq	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000002A6C0 }

l400000000002AAC0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000002A8E0 }

l400000000002AAD0:
	{ ld8	r33,[r16]; nop.m	0x0; sxt4	r14,r34; }
	{ add	r14,r33,r14; nop.m	0x0; cmp.eq	p06,p07,0x0,r33; }
	{ st1	[r0],r14; addl	r14,6116,r1; (p06) br.cond.spnt.few	400000000002AB40; }

l400000000002AB00:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; addl	r14,8944,r1; (p06) br.cond.dpnt.few	400000000002AB40; }

l400000000002AB20:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x11; (p07) br.cond.dpnt.few	400000000002ABA0 }

l400000000002AB40:
	{ adds	r8,0x0,r33; nop.m	0x0; mov.i	ar.pfs,r50; }
	{ nop.m	0x0; mov.spnt	b0,r49,400000000002AB50; br.ret	b0; }

l400000000002AB60:
	{ ld8	r52,[r48]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BE00; }
	{ adds	r1,0x0,r51; cmp4.eq	p06,p07,0x0,r34; (p07) br.cond.dptk.few	400000000002A950 }

l400000000002AB80:
	{ adds	r33,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r50; }
	{ adds	r8,0x0,r33; mov.spnt	b0,r49,400000000002AB90; br.ret	b0 }

l400000000002ABA0:
	{ addl	r14,8952,r1; nop.m	0x0; adds	r52,0x0,r33; }
	{ nop.m	0x0; ld4	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; adds	r15,0x1,r15; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,maybe_add_history; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r51; mov.i	ar.pfs,r50; }
	{ nop.m	0x0; mov.spnt	b0,r49,400000000002ABF0; br.ret	b0; }

l400000000002AC00:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000028E40; }
	{ nop.m	0x0; adds	r1,0x0,r51; br.cond.sptk.few	400000000002A5C0 }

l400000000002AC20:
	{ adds	r37,0x18,r37; nop.m	0x0; adds	r47,0x20,r45 }
	{ addl	r46,92,r0; nop.m	0x0; br.call.sptk.many	b0,fn4000000000024900; }
	{ adds	r1,0x0,r51; nop.m	0x0; cmp4.eq	p07,p06,0x0,r32; }
	{ addl	r48,-10356,r1; addl	r40,6832,r1; (p06) addl	r42,1,r0 }

l400000000002AC60:
	{ addl	r39,6836,r1; addl	r44,6648,r1; (p07) adds	r42,0x0,r0 }

l400000000002AC70:
	{ nop.m	0x0; ld8	r48,[r48]; br.cond.sptk.few	400000000002A6A0; }

;; fn400000000002AC80: 400000000002AC80
;;   Called from:
;;     400000000002CD9C (in fn400000000002AC80)
;;     400000000002CD9C (in fn400000000002AC80)
;;     400000000002FA9C (in fn400000000002D840)
;;     400000000003409C (in fn4000000000030880)
;;     400000000003457C (in fn4000000000030880)
fn400000000002AC80 proc
	{ alloc	r78,ar.pfs,0x36,0x0,0x31; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ addl	r69,6788,r1; mov	r80,pr; adds	r79,0x0,r1; }
	{ nop.m	0x0; mov	r77,b5; adds	r81,0x0,r0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn4000000000029100; }
	{ adds	r1,0x0,r79; ld8	r14,[r69]; nop.i	0x0; }
	{ addl	r15,6724,r1; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	400000000002B1C0; }

l400000000002ACE0:
	{ nop.m	0x0; ld4	r16,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r16; (p06) br.cond.dptk.few	400000000002B1C0 }

l400000000002AD00:
	{ adds	r16,0xFFFFFFFFFFFFFFFF,r16; nop.i	0x0; sxt4	r17,r16 }
	{ st4	[r16],r15; nop.i	0x0; add	r14,r14,r17; }
	{ st1	[r8],r14; nop.m	0x0; nop.i	0x0 }

l400000000002AD30:
	{ cmp4.eq	p09,p08,0x27,r32; cmp4.eq	p07,p06,0x28,r8; (p07) br.cond.dpnt.few	400000000002D2F0; }

l400000000002AD40:
	{ (p08) addl	r35,1,r0; cmp4.eq	p07,p06,0x22,r32; (p09) adds	r35,0x0,r0; }

l400000000002AD46:
	{ (p03) addl	r34,96672,r2; (p17) mov.sptk	b0,r0,400000000002AE46; break.b	0x80000 }

l400000000002AD50:
	{ nop.m	0x0; zxt1	r59,r35; tbit.z.or.andcm	p07,p06,r59,0x0; }
	{ nop.m	0x0; (p07) addl	r34,16,r0; (p07) br.cond.dptk.few	400000000002ADD0 }

l400000000002AD6C:
	{ (p03) cmp.lt	p00,p11,r0,r33; zxt4	r61,r12; break.b	0x1000 }

l400000000002AD70:
	{ addl	r14,6516,r1; nop.m	0x0; nop.i	0x0; }
	{ ld4	r14,[r14]; cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; }
	{ nop.m	0x0; (p06) addl	r34,50,r0; (p06) br.cond.dptk.few	400000000002ADD0 }

l400000000002AD9C:
	{ (p02) cmp.lt	p00,p11,r0,r33; zxt4	r56,r11; break.i	0x1000 }

l400000000002ADA0:
	{ addl	r14,5856,r1; nop.m	0x0; nop.i	0x0; }
	{ ld4	r34,[r14]; cmp4.eq	p07,p06,0x0,r34; nop.i	0x0; }
	{ (p06) addl	r34,50,r0; nop.i	0x0; (p07) addl	r34,48,r0 }

l400000000002ADC6:
	{ chk.a.nc	f0,3FFFFFFFFF02B5C6; (p17) nop; (p16) nop }

l400000000002ADD0:
	{ addl	r81,64,r0; addl	r37,-1,r0; adds	r54,0x0,r0 }
	{ adds	r58,0x0,r0; addl	r39,64,r0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r79; adds	r38,0x0,r8; addl	r40,1,r0 }
	{ adds	r36,0x0,r0; adds	r48,0x0,r0; cmp4.eq	p20,p21,0x0,r35; }
	{ addl	r71,9308,r1; addl	r14,6648,r1; addl	r55,6516,r1 }
	{ addl	r62,22532,r1; addl	r49,-18556,r1; addl	r47,256,r0; }
	{ nop.m	0x0; addl	r42,128,r0; addl	r45,512,r0 }
	{ addl	r70,-641,r0; addl	r65,-257,r0; addl	r43,132,r0; }
	{ adds	r64,0x8,r71; ld4	r73,[r14]; addl	r61,255,r0 }
	{ addl	r60,8192,r0; adds	r57,0x14,r12; addl	r44,6724,r1; }
	{ nop.m	0x0; adds	r71,0xC,r71; addl	r50,6780,r1 }
	{ addl	r67,1,r0; addl	r72,6812,r1; addl	r56,1024,r0; }
	{ nop.m	0x0; addl	r75,60,r0; addl	r76,45,r0 }
	{ addl	r74,6796,r1; addl	r66,512,r0; addl	r68,-1025,r0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }

l400000000002AEC0:
	{ (p20) adds	r81,0x0,r0; nop.i	0x0; (p20) br.cond.dpnt.few	400000000002AEF0; }

l400000000002AEC6:
	{ nop; nop; (p16) nop }

l400000000002AED0:
	{ and	r81,0xC,r34; cmp4.eq	p06,p07,0x0,r81; nop.i	0x0; }
	{ (p06) addl	r81,1,r0; nop.i	0x0; (p07) adds	r81,0x0,r0 }

l400000000002AEE6:
	{ addp4	r0,0xFFFFFFFFFFFFE000,r1; (p40) nop; break.i	0x80000 }

l400000000002AEF0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000029100; }
	{ cmp4.eq	p16,p17,0xA,r8; adds	r1,0x0,r79; nop.i	0x0 }
	{ adds	r35,0x0,r8; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dpnt.few	400000000002CC20; }

l400000000002AF20:
	{ nop.m	0x0; (p17) and	r14,r34,r42; (p16) br.cond.dpnt.few	400000000002B1E0; }

l400000000002AF2C:
	{ (p22) ld2.s	r0,[r33],r64; czx1.r	r64,r100; break.i	0x1000 }

l400000000002AF30:
	{ (p17) cmp4.eq	p18,p19,0x0,r14; nop.m	0x0; nop.i	0x0 }

l400000000002AF36:
	{ break.m	0x4000; nop; (p32) nop }

l400000000002AF40:
	{ cmp4.eq	p06,p07,0x29,r35; cmp4.eq	p08,p09,0x1,r40; (p18) br.cond.dptk.few	400000000002B040; }

l400000000002AF50:
	{ (p06) addl	r16,1,r0; (p08) addl	r14,1,r0; sxt4	r15,r37; }

l400000000002AF56:
	{ Invalid; (p07) cmp4.ltu	p00,p00,r37,r22; (p01) nop }

l400000000002AF5C:
	{ Invalid; (p02) cmp.lt	p00,p48,0x0,r64; (p01) cmp.eq	p00,p16,r0,r64; }

l400000000002AF66:
	{ Invalid; (p07) nop; (p32) nop }

l400000000002AF6C:
	{ (p19) cmp.lt	p15,p09,r0,r64; zxt1	r3,r3; break.i	0x1000; }
	{ Invalid; Invalid; nop }
	{ (p06) cmp.lt	p00,p17,r0,r33; czx1.r	r0,r97; mov	pr,r32,0x0 }

l400000000002AF90:
	{ cmp4.eq	p06,p07,0x0,r16; nop.i	0x0; (p06) br.cond.dpnt.few	400000000002CAA0; }

l400000000002AFA0:
	{ ld1	r14,[r15]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x9,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000002CAA0; }

l400000000002AFC0:
	{ (p06) adds	r14,0x1,r37; nop.m	0x0; sxt4	r15,r14; }

l400000000002AFC6:
	{ adds	r0,0xFFFFFFFFFFFFE000,r1; (p07) addl	r0,376846,r2; (p49) nop }

l400000000002AFD6:
	{ (p08) mov.m	KR0,0xF; mov	pr,0x4000; break.i	0x80000 }
	{ (p08) break.m	0x50800; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	f9,3FFFFFFFFFCEE8F6; Invalid; nop }

l400000000002B000:
	{ ld1	r16,[r15],1; adds	r14,0x1,r14; sxt1	r16,r16; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x9,r16; (p06) br.cond.dptk.few	400000000002B000 }

l400000000002B020:
	{ nop.m	0x0; sub	r15,r36,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r15,r51; (p07) br.cond.dpnt.few	400000000002B2F0; }

l400000000002B040:
	{ nop.m	0x0; and	r14,r43,r34; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000002B280 }

l400000000002B060:
	{ nop.m	0x0; adds	r41,0x1,r36; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r41,r39; (p06) br.cond.dptk.few	400000000002B0D0 }

l400000000002B080:
	{ sub	r14,r41,r39; adds	r39,0x40,r39; adds	r81,0x0,r38; }
	{ nop.m	0x0; extr	r14,r14,6,26; dep.z	r14,r14,6,26; }
	{ nop.m	0x0; add	r39,r39,r14; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r82,r39; br.call.sptk.many	b0,xrealloc; }
	{ nop.m	0x0; adds	r1,0x0,r79; adds	r38,0x0,r8 }

l400000000002B0D0:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x2; sxt4	r36,r36; }
	{ nop.m	0x0; add	r36,r38,r36; nop.i	0x0; }
	{ st1	[r35],r36; nop.i	0x0; (p06) br.cond.dptk.few	400000000002B120 }

l400000000002B100:
	{ nop.m	0x0; cmp4.eq	p07,p06,0xA,r35; nop.i	0x0; }
	{ (p07) and	r34,0xFFFFFFFFFFFFFFFB,r34; (p07) adds	r36,0x0,r41; (p07) br.cond.dpnt.few	400000000002B130; }

l400000000002B116:
	{ (p18) chk.a.clr	f0,3FFFFFFFFF0AB3A6; nop; nop; }

l400000000002B11C:
	{ (p01) addp4	r0,r64,r33; zxt1	r32,r64; break.i	0x1000 }

l400000000002B120:
	{ adds	r36,0x0,r41; nop.m	0x0; nop.i	0x0 }

l400000000002B130:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r40; (p06) br.cond.dptk.few	400000000002AEC0; }

l400000000002B140:
	{ cmp.eq	p06,p07,0x0,r48; adds	r81,0x0,r48; (p06) br.cond.dpnt.few	400000000002B170; }

l400000000002B150:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r79; nop.m	0x0; nop.i	0x0 }

l400000000002B170:
	{ nop.m	0x0; sxt4	r14,r36; cmp.eq	p06,p07,0x0,r33 }
	{ adds	r8,0x0,r38; add	r14,r38,r14; nop.i	0x0; }
	{ st1	[r0],r14; (p07) st4	[r36],r33; mov	pr,r80,0xFFFFFFFFFFFFFFFE; }

l400000000002B19C:
	{ Invalid; break.m	0x1000; (p32) break.f	0x2A813; }
	{ (p38) nop; add	r0,r32,r0; Invalid }
	{ nop; cmp.lt	p00,p00,r32,r0; zxt4	r35,r13 }

l400000000002B1C0:
	{ nop.m	0x0; addl	r14,6796,r1; nop.i	0x0; }
	{ st4	[r8],r14; nop.i	0x0; br.cond.sptk.few	400000000002AD30 }

l400000000002B1E0:
	{ nop.m	0x0; and	r14,r47,r34; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000002C5E0; }

l400000000002B200:
	{ cmp.eq	p06,p07,0x0,r48; cmp.eq	p18,p19,0x0,r42; (p06) br.cond.dpnt.few	400000000002C5E0; }

l400000000002B210:
	{ and	r34,r65,r34; adds	r37,0x1,r36; or	r34,r42,r34 }

l400000000002B220:
	{ nop.m	0x0; ld4	r14,[r55]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	400000000002AF40 }

l400000000002B240:
	{ ld4	r14,[r62]; adds	r14,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x1,r14; (p06) br.cond.dptk.few	400000000002AF40 }

l400000000002B260:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000028E40; }
	{ nop.m	0x0; adds	r1,0x0,r79; br.cond.sptk.few	400000000002AF40 }

l400000000002B280:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x3; (p06) br.cond.dptk.few	400000000002B390 }

l400000000002B290:
	{ (p16) addl	r14,1,r0; and	r34,0xFFFFFFFFFFFFFFF7,r34; (p17) adds	r14,0x0,r0; }

l400000000002B296:
	{ (p17) nop; (p07) nop; break.i	0x80000 }

l400000000002B2A0:
	{ nop.m	0x0; and	r14,r14,r59; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000002C760; }

l400000000002B2C0:
	{ nop.m	0x0; cmp4.lt	p07,p06,0x0,r36; nop.i	0x0; }
	{ (p07) adds	r36,0xFFFFFFFFFFFFFFFF,r36; cmp4.eq	p07,p06,0x0,r40; (p06) br.cond.dptk.few	400000000002AEC0 }

l400000000002B2D6:
	{ (p03) chk.a.clr	r0,3FFFFFFFFFCEE556; nop; break.b	0x80000 }

l400000000002B2E0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000002B140; }

l400000000002B2F0:
	{ nop.m	0x0; sxt4	r14,r14; cmp4.eq	p06,p07,0x0,r51 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dpnt.few	400000000002B360; }

l400000000002B310:
	{ add	r81,r38,r14; ld1	r15,[r48]; nop.i	0x0; }
	{ ld1	r14,[r81]; sxt1	r15,r15; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r15; (p06) br.cond.dptk.few	400000000002B040 }

l400000000002B340:
	{ adds	r82,0x0,r48; sxt4	r83,r51; br.call.sptk.many	b0,fn400000000001C020; }
	{ adds	r1,0x0,r79; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	400000000002B040 }

l400000000002B360:
	{ adds	r81,0x0,r48; and	r34,r70,r34; nop.i	0x0 }
	{ adds	r48,0x0,r0; addl	r37,-1,r0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r79; br.cond.sptk.few	400000000002B040 }

l400000000002B390:
	{ and	r46,r61,r35; nop.m	0x0; sxt4	r46,r46; }
	{ shladd	r14,r46,0x2,r49; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; and	r15,0x2,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	400000000002B590 }

l400000000002B3D0:
	{ nop.m	0x0; ld4	r16,[r44]; nop.i	0x0; }
	{ cmp4.lt	p07,p06,0x1,r16; sxt4	r16,r16; (p06) br.cond.dpnt.few	400000000002B430; }

l400000000002B3F0:
	{ ld8	r17,[r50]; add	r17,r17,r16; nop.i	0x0; }
	{ adds	r17,0xFFFFFFFFFFFFFFFF,r17; ld1	r16,[r17]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r16,r16; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r16; (p06) br.cond.dptk.few	400000000002B590 }

l400000000002B430:
	{ and	r34,r68,r34; nop.m	0x0; and	r14,r60,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; and	r14,r47,r34; (p06) br.cond.dptk.few	400000000002B5C0; }

l400000000002B450:
	{ nop.m	0x0; or	r16,r54,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r16; (p06) br.cond.dptk.few	400000000002B5C0 }

l400000000002B470:
	{ nop.m	0x0; ld4	r14,[r44]; nop.i	0x0; }
	{ cmp4.lt	p07,p06,0x1,r14; sxt4	r14,r14; (p06) br.cond.dpnt.few	400000000002B4D0; }

l400000000002B490:
	{ ld8	r15,[r50]; add	r15,r15,r14; nop.i	0x0; }
	{ adds	r15,0xFFFFFFFFFFFFFFFF,r15; ld1	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000002B7E0 }

l400000000002B4D0:
	{ nop.m	0x0; adds	r41,0x1,r36; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r41,r39; (p06) br.cond.dptk.few	400000000002B540 }

l400000000002B4F0:
	{ sub	r14,r41,r39; adds	r39,0x40,r39; adds	r81,0x0,r38; }
	{ nop.m	0x0; extr	r14,r14,6,26; dep.z	r14,r14,6,26; }
	{ nop.m	0x0; add	r39,r39,r14; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r82,r39; br.call.sptk.many	b0,xrealloc; }
	{ nop.m	0x0; adds	r1,0x0,r79; adds	r38,0x0,r8 }

l400000000002B540:
	{ nop.m	0x0; sxt4	r14,r36; nop.b	0x0 }
	{ adds	r54,0x0,r0; adds	r36,0x0,r41; cmp4.eq	p07,p06,0x0,r40; }
	{ nop.m	0x0; add	r14,r38,r14; nop.i	0x0; }
	{ st1	[r35],r14; nop.i	0x0; (p06) br.cond.dptk.few	400000000002AEC0 }

l400000000002B580:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000002B140 }

l400000000002B590:
	{ and	r16,r56,r34; and	r14,r60,r14; cmp4.eq	p06,p07,0x0,r16; }
	{ (p06) or	r34,r56,r34; (p07) adds	r58,0x1,r58; (p06) adds	r58,0x0,r0 }

l400000000002B5A6:
	{ (p29) chk.a.clr	r1,3FFFFFFFFF0AB946; (p29) nop; (p32) nop; }

l400000000002B5AC:
	{ Invalid; Invalid; Invalid }

l400000000002B5B0:
	{ cmp4.eq	p06,p07,0x0,r14; and	r14,r47,r34; (p07) br.cond.dptk.few	400000000002B450; }

l400000000002B5C0:
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000002B7E0; }

l400000000002B5D0:
	{ cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r37; nop.i	0x0; (p07) br.cond.dpnt.few	400000000002C940; }

l400000000002B5E0:
	{ cmp4.lt	p07,p06,r37,r0; nop.i	0x0; (p07) br.cond.dpnt.few	400000000002B7E0; }

l400000000002B5F0:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x3; (p07) br.cond.dptk.few	400000000002B7E0; }

l400000000002B600:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p07) br.cond.dptk.few	400000000002B7E0; }

l400000000002B610:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r48; (p07) br.cond.dpnt.few	400000000002D520 }

l400000000002B620:
	{ (p16) and	r34,r65,r34; (p16) adds	r37,0x1,r36; (p17) adds	r41,0x1,r36; }

l400000000002B626:
	{ Invalid; Invalid; Invalid }

l400000000002B62C:
	{ Invalid; Invalid; Invalid }

l400000000002B630:
	{ (p17) addl	r37,-1,r0; (p16) or	r34,r42,r34; (p16) adds	r41,0x0,r37 }

l400000000002B636:
	{ (p17) nop; break.x	0x2009402880000 }

l400000000002B63C:
	{ nop; (p01) nop; }

l400000000002B640:
	{ nop.m	0x0; and	r14,0x34,r34; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x20,r14; (p06) br.cond.dpnt.few	400000000002B800; }

l400000000002B660:
	{ nop.m	0x0; sxt4	r52,r36; nop.i	0x0 }

l400000000002B670:
	{ nop.m	0x0; and	r53,0x10,r34; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r53; (p06) br.cond.dptk.few	400000000002B9E0 }

l400000000002B690:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C3C0; }
	{ nop.m	0x0; sxt4	r14,r35; nop.i	0x0 }
	{ ld8	r15,[r8]; adds	r1,0x0,r79; shladd	r14,r14,0x1,r15; }
	{ ld2	r14,[r14]; and	r14,r66,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000002BB60 }

l400000000002B6E0:
	{ nop.m	0x0; ld4	r14,[r44]; nop.i	0x0; }
	{ cmp4.lt	p07,p06,0x1,r14; sxt4	r14,r14; (p06) br.cond.dpnt.few	400000000002B740; }

l400000000002B700:
	{ ld8	r15,[r50]; add	r14,r15,r14; nop.i	0x0; }
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000002BB60; }

l400000000002B740:
	{ nop.m	0x0; cmp4.lt	p06,p07,r41,r39; (p06) br.cond.dptk.few	400000000002B7A0 }

l400000000002B750:
	{ sub	r14,r41,r39; adds	r39,0x40,r39; adds	r81,0x0,r38; }
	{ nop.m	0x0; extr	r14,r14,6,26; dep.z	r14,r14,6,26; }
	{ nop.m	0x0; add	r39,r39,r14; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r82,r39; br.call.sptk.many	b0,xrealloc; }
	{ nop.m	0x0; adds	r1,0x0,r79; adds	r38,0x0,r8; }

l400000000002B7A0:
	{ add	r52,r38,r52; nop.m	0x0; adds	r54,0x1,r54 }
	{ adds	r36,0x0,r41; nop.m	0x0; cmp4.eq	p07,p06,0x0,r40; }
	{ st1	[r35],r52; nop.i	0x0; (p06) br.cond.dptk.few	400000000002AEC0 }

l400000000002B7D0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000002B140 }

l400000000002B7E0:
	{ and	r14,0x34,r34; nop.m	0x0; adds	r41,0x1,r36; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x20,r14; (p07) br.cond.dptk.few	400000000002B660 }

l400000000002B800:
	{ shladd	r14,r46,0x2,r49; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x0; (p06) br.cond.dptk.few	400000000002B830 }

l400000000002B820:
	{ nop.m	0x0; nop.i	0x0; (p17) br.cond.dptk.few	400000000002B660 }

l400000000002B830:
	{ nop.m	0x0; ld4	r14,[r44]; nop.i	0x0; }
	{ cmp4.lt	p07,p06,0x1,r14; sxt4	r14,r14; (p06) br.cond.dpnt.few	400000000002B890; }

l400000000002B850:
	{ ld8	r15,[r50]; add	r14,r15,r14; nop.i	0x0; }
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	400000000002B660; }

l400000000002B890:
	{ nop.m	0x0; cmp4.lt	p06,p07,r41,r39; (p06) br.cond.dptk.few	400000000002B8F0 }

l400000000002B8A0:
	{ sub	r14,r41,r39; adds	r39,0x40,r39; adds	r81,0x0,r38; }
	{ nop.m	0x0; extr	r14,r14,6,26; dep.z	r14,r14,6,26; }
	{ nop.m	0x0; add	r39,r39,r14; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r82,r39; br.call.sptk.many	b0,xrealloc; }
	{ nop.m	0x0; adds	r1,0x0,r79; adds	r38,0x0,r8 }

l400000000002B8F0:
	{ nop.m	0x0; sxt4	r52,r36; sxt1	r53,r35 }
	{ addl	r81,1,r0; add	r14,r38,r52; nop.i	0x0; }
	{ st1	[r53],r14; nop.i	0x0; br.call.sptk.many	b0,fn4000000000029100; }
	{ adds	r1,0x0,r79; cmp4.eq	p07,p06,r8,r35; (p07) br.cond.dpnt.few	400000000002CDB0; }

l400000000002B930:
	{ cmp4.eq	p06,p07,0x3B,r35; nop.i	0x0; (p16) br.cond.dpnt.few	400000000002CAD0; }

l400000000002B940:
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x26,r35; (p06) br.cond.dptk.few	400000000002CAD0; }

l400000000002B950:
	{ cmp4.eq	p07,p06,0x7C,r35; nop.i	0x0; (p07) br.cond.dpnt.few	400000000002CAD0; }

l400000000002B960:
	{ nop.m	0x0; ld8	r14,[r69]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000002D3D0; }

l400000000002B980:
	{ nop.m	0x0; ld4	r15,[r44]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	400000000002D3D0 }

l400000000002B9A0:
	{ adds	r15,0xFFFFFFFFFFFFFFFF,r15; and	r53,0x10,r34; sxt4	r16,r15 }
	{ st4	[r15],r44; cmp.eq	p06,p07,0x0,r53; add	r14,r14,r16; }
	{ st1	[r8],r14; nop.i	0x0; (p07) br.cond.dptk.few	400000000002B690; }

l400000000002B9D0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000002B9E0:
	{ nop.m	0x0; and	r14,0x24,r34; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x20,r14; (p07) br.cond.dpnt.few	400000000002BD30 }

l400000000002BA00:
	{ nop.m	0x0; and	r14,0x6,r34; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2,r14; (p07) br.cond.dpnt.few	400000000002C220; }

l400000000002BA20:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x7F,r35; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x1,r35; (p06) br.cond.dpnt.few	400000000002BE80 }

l400000000002BA40:
	{ nop.m	0x0; ld4	r14,[r44]; nop.i	0x0; }
	{ cmp4.lt	p07,p06,0x1,r14; sxt4	r14,r14; (p06) br.cond.dpnt.few	400000000002BAA0; }

l400000000002BA60:
	{ ld8	r15,[r50]; add	r15,r15,r14; nop.i	0x0; }
	{ adds	r15,0xFFFFFFFFFFFFFFFF,r15; ld1	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000002BE80 }

l400000000002BAA0:
	{ nop.m	0x0; adds	r36,0x2,r36; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r36,r39; (p06) br.cond.dptk.few	400000000002BB10 }

l400000000002BAC0:
	{ sub	r14,r36,r39; adds	r39,0x40,r39; adds	r81,0x0,r38; }
	{ nop.m	0x0; extr	r14,r14,6,26; dep.z	r14,r14,6,26; }
	{ nop.m	0x0; add	r39,r39,r14; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r82,r39; br.call.sptk.many	b0,xrealloc; }
	{ nop.m	0x0; adds	r1,0x0,r79; adds	r38,0x0,r8; }

l400000000002BB10:
	{ nop.m	0x0; sxt4	r41,r41; add	r52,r38,r52 }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r40; nop.b	0x0; }
	{ add	r41,r38,r41; st1	[r67],r52; nop.i	0x0; }
	{ st1	[r35],r41; nop.i	0x0; (p06) br.cond.dptk.few	400000000002AEC0 }

l400000000002BB50:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000002B140 }

l400000000002BB60:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x4,r54; (p07) br.cond.dpnt.few	400000000002C9A0; }

l400000000002BB70:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x1; (p06) br.cond.dptk.few	400000000002BB90; }

l400000000002BB80:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x23,r35; (p07) br.cond.dpnt.few	400000000002BC50; }

l400000000002BB90:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x6; (p06) br.cond.dptk.few	400000000002BCA0 }

l400000000002BBA0:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dpnt.few	400000000002BCA0 }

l400000000002BBB0:
	{ nop.m	0x0; ld4	r14,[r44]; nop.i	0x0; }
	{ cmp4.lt	p07,p06,0x1,r14; sxt4	r14,r14; (p06) br.cond.dpnt.few	400000000002BC10; }

l400000000002BBD0:
	{ ld8	r15,[r50]; add	r14,r15,r14; nop.i	0x0; }
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000002BCA0 }

l400000000002BC10:
	{ and	r34,0xFFFFFFFFFFFFFFEF,r34; nop.m	0x0; nop.i	0x0; }

l400000000002BC20:
	{ nop.m	0x0; and	r14,0x24,r34; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x20,r14; (p06) br.cond.dptk.few	400000000002BA00 }

l400000000002BC40:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000002BD30; }

l400000000002BC50:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r54; (p06) br.cond.dptk.few	400000000002D250 }

l400000000002BC60:
	{ nop.m	0x0; and	r14,r56,r34; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	400000000002D240; }

l400000000002BC80:
	{ nop.m	0x0; tbit.z	p07,p06,r34,0x6; (p06) br.cond.dptk.few	400000000002BBB0; }

l400000000002BC90:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000002BCA0:
	{ shladd	r46,r46,0x2,r49; ld4	r14,[r46]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x1; (p06) br.cond.dptk.few	400000000002B9E0 }

l400000000002BCC0:
	{ nop.m	0x0; ld4	r14,[r44]; nop.i	0x0; }
	{ cmp4.lt	p07,p06,0x1,r14; sxt4	r14,r14; (p06) br.cond.dpnt.few	400000000002BC10; }

l400000000002BCE0:
	{ ld8	r15,[r50]; add	r14,r15,r14; nop.i	0x0; }
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000002B9E0 }

l400000000002BD20:
	{ nop.m	0x0; and	r34,0xFFFFFFFFFFFFFFEF,r34; br.cond.sptk.few	400000000002BC20; }

l400000000002BD30:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x3C,r35; (p06) br.cond.dptk.few	400000000002BA00 }

l400000000002BD40:
	{ nop.m	0x0; ld4	r14,[r44]; nop.i	0x0; }
	{ cmp4.lt	p07,p06,0x1,r14; sxt4	r14,r14; (p06) br.cond.dpnt.few	400000000002BDA0; }

l400000000002BD60:
	{ ld8	r15,[r50]; add	r14,r15,r14; nop.i	0x0; }
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000002BE90; }

l400000000002BDA0:
	{ nop.m	0x0; cmp4.lt	p06,p07,r41,r39; (p06) br.cond.dptk.few	400000000002BE00 }

l400000000002BDB0:
	{ sub	r14,r41,r39; adds	r39,0x40,r39; adds	r81,0x0,r38; }
	{ nop.m	0x0; extr	r14,r14,6,26; dep.z	r14,r14,6,26; }
	{ nop.m	0x0; add	r39,r39,r14; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r82,r39; br.call.sptk.many	b0,xrealloc; }
	{ nop.m	0x0; adds	r1,0x0,r79; adds	r38,0x0,r8; }

l400000000002BE00:
	{ add	r52,r38,r52; nop.m	0x0; addl	r81,1,r0; }
	{ st1	[r75],r52; sxt4	r52,r41; br.call.sptk.many	b0,fn4000000000029100; }
	{ cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r8; nop.m	0x0; adds	r1,0x0,r79 }
	{ adds	r35,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	400000000002CC20; }

l400000000002BE40:
	{ cmp4.eq	p06,p07,0x3C,r8; nop.i	0x0; (p06) br.cond.dpnt.few	400000000002CB70; }

l400000000002BE50:
	{ cmp4.eq	p07,p06,0x7F,r35; adds	r36,0x0,r41; adds	r41,0x1,r41; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x1,r35; (p07) br.cond.dptk.few	400000000002BA40; }

l400000000002BE70:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000002BE80:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x29,r35; (p07) br.cond.dpnt.few	400000000002C310; }

l400000000002BE90:
	{ nop.m	0x0; tbit.z	p07,p06,r34,0x6; sxt1	r46,r35 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dpnt.few	400000000002BEC0; }

l400000000002BEB0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x28,r35; (p07) br.cond.dpnt.few	400000000002CEA0 }

l400000000002BEC0:
	{ nop.m	0x0; adds	r53,0x0,r36; adds	r36,0x0,r41; }

l400000000002BED0:
	{ nop.m	0x0; cmp4.lt	p06,p07,r41,r39; (p06) br.cond.dptk.few	400000000002BF30 }

l400000000002BEE0:
	{ sub	r14,r41,r39; adds	r39,0x40,r39; adds	r81,0x0,r38; }
	{ nop.m	0x0; extr	r14,r14,6,26; dep.z	r14,r14,6,26; }
	{ nop.m	0x0; add	r39,r39,r14; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r82,r39; br.call.sptk.many	b0,xrealloc; }
	{ nop.m	0x0; adds	r1,0x0,r79; adds	r38,0x0,r8; }

l400000000002BF30:
	{ cmp4.eq	p06,p07,0x0,r40; nop.m	0x0; add	r52,r38,r52; }
	{ st1	[r46],r52; nop.i	0x0; (p06) br.cond.dpnt.few	400000000002B140; }

l400000000002BF50:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5C,r35; (p07) br.cond.dpnt.few	400000000002C3B0 }

l400000000002BF60:
	{ nop.m	0x0; zxt1	r14,r35; shladd	r14,r14,0x2,r49; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x3; (p06) br.cond.dptk.few	400000000002BFF0 }

l400000000002BF90:
	{ nop.m	0x0; ld4	r14,[r44]; nop.i	0x0; }
	{ cmp4.lt	p07,p06,0x1,r14; sxt4	r14,r14; (p06) br.cond.dpnt.few	400000000002C420; }

l400000000002BFB0:
	{ ld8	r15,[r50]; add	r14,r15,r14; nop.i	0x0; }
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	400000000002C420; }

l400000000002BFF0:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x0; (p06) br.cond.dptk.few	400000000002C1F0; }

l400000000002C000:
	{ cmp4.eq	p06,p07,0x28,r35; nop.m	0x0; cmp4.eq	p08,p09,0x7B,r35; }
	{ (p07) adds	r14,0x0,r0; nop.m	0x0; (p08) addl	r15,1,r0; }

l400000000002C016:
	{ addl	r0,0,r1; (p07) dep	r1,r0,r0,35,9; (p50) nop }

l400000000002C020:
	{ (p09) adds	r15,0x0,r0; (p06) addl	r14,1,r0; or	r16,r15,r14; }

l400000000002C026:
	{ Invalid; (p08) nop; break.i	0x80000; }

l400000000002C02C:
	{ (p07) invala; Invalid; nop }
	{ (p10) nop; break.i	0x1000; Invalid }

l400000000002C040:
	{ nop.m	0x0; ld4	r16,[r44]; nop.i	0x0; }
	{ cmp4.lt	p07,p06,0x1,r16; sxt4	r16,r16; (p06) br.cond.dpnt.few	400000000002C0A0; }

l400000000002C060:
	{ ld8	r17,[r50]; add	r16,r17,r16; nop.i	0x0; }
	{ adds	r16,0xFFFFFFFFFFFFFFFF,r16; ld1	r16,[r16]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r16,r16; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r16; (p06) br.cond.dptk.few	400000000002C1F0; }

l400000000002C0A0:
	{ nop.m	0x0; tbit.z	p07,p06,r34,0x6; (p06) br.cond.dptk.few	400000000002CD80; }

l400000000002C0B0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r40,0xFFFFFFFFFFFFFFFF,r40; (p07) br.cond.dpnt.few	400000000002CD90 }

l400000000002C0CC:
	{ (p38) cmp.lt	p01,p17,r64,r33; czx1.r	r96,r97; br.cond	b0 }

l400000000002C0D0:
	{ cmp4.eq	p06,p07,0x0,r15; nop.i	0x0; (p07) br.cond.dpnt.few	400000000002D660; }

l400000000002C0E0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5B,r35; (p07) br.cond.dpnt.few	400000000002D4F0; }

l400000000002C0F0:
	{ cmp.eq	p07,p06,r72,r63; nop.i	0x0; (p07) br.cond.dpnt.few	400000000002D7F0; }

l400000000002C100:
	{ nop.m	0x0; ld4	r14,[r57]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000002C1C0 }

l400000000002C120:
	{ nop.m	0x0; add	r14,r14,r41; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r14,r39; (p06) br.cond.dptk.few	400000000002C190 }

l400000000002C140:
	{ sub	r14,r14,r39; adds	r39,0x40,r39; adds	r81,0x0,r38; }
	{ nop.m	0x0; extr	r14,r14,6,26; dep.z	r14,r14,6,26; }
	{ nop.m	0x0; add	r39,r39,r14; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r82,r39; br.call.sptk.many	b0,xrealloc; }
	{ nop.m	0x0; adds	r1,0x0,r79; adds	r38,0x0,r8 }

l400000000002C190:
	{ nop.m	0x0; sxt4	r81,r41; adds	r82,0x0,r63; }
	{ add	r81,r38,r81; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ ld4	r36,[r57]; adds	r1,0x0,r79; add	r36,r41,r36; }

l400000000002C1C0:
	{ cmp.eq	p06,p07,0x0,r63; nop.i	0x0; (p06) br.cond.dpnt.few	400000000002C1F0; }

l400000000002C1D0:
	{ nop.m	0x0; adds	r81,0x0,r63; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r79; nop.m	0x0; nop.i	0x0 }

l400000000002C1F0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x24,r35; (p07) br.cond.dpnt.few	400000000002C8C0; }

l400000000002C200:
	{ and	r34,0xFFFFFFFFFFFFFFFE,r34; cmp4.eq	p07,p06,0x0,r40; (p06) br.cond.dptk.few	400000000002AEC0 }

l400000000002C210:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000002B140; }

l400000000002C220:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x23,r35; (p06) br.cond.dptk.few	400000000002BA20 }

l400000000002C230:
	{ nop.m	0x0; and	r53,0x10,r34; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r53; (p07) br.cond.dptk.few	400000000002CF30 }

l400000000002C250:
	{ nop.m	0x0; and	r14,r56,r34; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000002C2F0; }

l400000000002C270:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r58; (p06) br.cond.dptk.few	400000000002C2F0 }

l400000000002C280:
	{ nop.m	0x0; ld4	r14,[r44]; nop.i	0x0; }
	{ cmp4.lt	p07,p06,0x1,r14; sxt4	r14,r14; (p06) br.cond.dpnt.few	400000000002C2E0; }

l400000000002C2A0:
	{ ld8	r15,[r50]; add	r14,r15,r14; nop.i	0x0; }
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000002C2F0 }

l400000000002C2E0:
	{ or	r34,0x4,r34; nop.m	0x0; nop.i	0x0 }

l400000000002C2F0:
	{ adds	r53,0x0,r36; nop.m	0x0; addl	r46,35,r0 }
	{ adds	r36,0x0,r41; addl	r35,35,r0; br.cond.sptk.few	400000000002BED0; }

l400000000002C310:
	{ nop.m	0x0; tbit.z	p07,p06,r34,0x6; (p06) adds	r53,0x0,r36 }

l400000000002C320:
	{ (p06) addl	r46,41,r0; (p06) adds	r36,0x0,r41; (p06) br.cond.dptk.few	400000000002BED0; }

l400000000002C326:
	{ (p18) chk.a.clr	r0,3FFFFFFFFF0AC5B6; nop; (p32) nop; }

l400000000002C32C:
	{ (p29) cmp.lt.unc	p63,p09,r63,r37; Invalid; Invalid }

l400000000002C330:
	{ ld4	r14,[r44]; nop.m	0x0; adds	r53,0x0,r36; }
	{ cmp4.lt	p07,p06,0x1,r14; sxt4	r14,r14; (p06) br.cond.dpnt.few	400000000002C390; }

l400000000002C350:
	{ ld8	r15,[r50]; add	r14,r15,r14; nop.i	0x0; }
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ (p06) addl	r46,41,r0; (p06) adds	r36,0x0,r41; (p06) br.cond.dptk.few	400000000002BED0; }

l400000000002C386:
	{ (p18) chk.a.clr	r0,3FFFFFFFFF0AC616; nop; break.i	0x80000; }

l400000000002C38C:
	{ (p26) nop; break.i	0x1000; Invalid }

l400000000002C390:
	{ nop.m	0x0; adds	r40,0xFFFFFFFFFFFFFFFF,r40; adds	r36,0x0,r41 }
	{ nop.m	0x0; addl	r46,41,r0; br.cond.sptk.few	400000000002BED0 }

l400000000002C3B0:
	{ nop.m	0x0; ld4	r14,[r44]; nop.i	0x0; }
	{ cmp4.lt	p07,p06,0x1,r14; sxt4	r14,r14; (p06) br.cond.dpnt.few	400000000002C410; }

l400000000002C3D0:
	{ ld8	r15,[r50]; add	r14,r15,r14; nop.i	0x0; }
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000002BF60 }

l400000000002C410:
	{ nop.m	0x0; or	r34,0x8,r34; br.cond.sptk.few	400000000002BF60 }

l400000000002C420:
	{ nop.m	0x0; ld4	r14,[r64]; addl	r41,9308,r1 }
	{ nop.m	0x0; ld4	r15,[r71]; nop.i	0x0; }
	{ nop.m	0x0; adds	r16,0x1,r14; sxt4	r14,r14; }
	{ cmp4.lt	p07,p06,r16,r15; nop.i	0x0; (p06) br.cond.dpnt.few	400000000002CCF0; }

l400000000002C460:
	{ (p07) ld8	r8,[r41]; tbit.z	p06,p07,r34,0x0; add	r8,r8,r14 }

l400000000002C466:
	{ (p03) mov.m	KR7,0x22; (p04) nop; (p32) nop }
	{ mf.a; nop; (p32) nop }
	{ Invalid; nop; nop }
	{ chk.a.nc	r0,3FFFFFFFFF02CC96; nop; (p48) nop }
