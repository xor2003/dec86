;;; Segment .text (400000000001C480)

l40000000000AC480:
	{ st4	[r17],r4,4; st8	[r16],r8,8; nop.i	0x0; }
	{ nop.m	0x0; st4	[r15],r4,4; nop.i	0x0 }
	{ st8	[r14],r8,8; nop.m	0x0; br.cloop.sptk.few	40000000000AC480 }

l40000000000AC4B0:
	{ adds	r34,0x88,r33; addl	r40,17,r0; nop.i	0x0 }
	{ adds	r41,0x0,r0; adds	r35,0x8,r32; br.call.sptk.many	b0,set_signal_handler; }
	{ nop.m	0x0; adds	r1,0x0,r38; adds	r41,0x0,r8 }
	{ st8	[r8],r34; addl	r40,17,r0; br.call.sptk.many	b0,set_signal_handler; }
	{ ld8	r14,[r34]; adds	r1,0x0,r38; adds	r34,0x10,r33 }
	{ addl	r40,2,r0; adds	r41,0x0,r0; cmp.eq	p06,p07,0x1,r14 }
	{ adds	r14,0x44,r32; ld4	r15,[r14]; adds	r14,0x44,r32; }
	{ (p06) or	r15,0x2,r15; or	r15,0xC,r15; nop.i	0x0; }

l40000000000AC526:
	{ Invalid; nop; br.call.spnt.many	b0,b3 }
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; (p20) nop; br.call.spnt.few	b0,b2 }
	{ Invalid; (p32) nop; (p32) nop }
	{ Invalid; (p17) nop; nop.b	0x6A }
	{ Invalid; (p20) nop; nop }
	{ Invalid; (p17) addl	r12,57632,r0; (p49) nop }

l40000000000AC596:
	{ Invalid; nop; br.call.spnt.many	b0,b3 }
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; (p20) nop; br.call.spnt.few	b0,b2 }
	{ Invalid; (p32) nop; (p16) nop }
	{ (p07) fwb; nop; (p48) nop }
	{ (p08) fwb; nop; (p32) nop }
	{ Invalid; nop; add	r0,r0,r32 }
	{ Invalid; nop; break.i	0x80000; }

l40000000000AC60C:
	{ (p18) nop; break.i	0x1000; zxt1	r1,r11 }
	{ cmp.lt	p00,p09,r1,r0; Invalid; Invalid }
	{ cmp.lt	p00,p19,r1,r0; mov	pr,r99,0xE680; (p16) addp4	r0,r0,r48 }

l40000000000AC63C:
	{ nop; (p04) invala; (p53) nop }

l40000000000AC640:
	{ adds	r33,0x78,r33; addl	r40,15,r0; adds	r41,0x0,r0 }
	{ adds	r34,0x3C,r32; adds	r32,0x3C,r32; br.call.sptk.many	b0,set_signal_handler; }
	{ nop.m	0x0; adds	r1,0x0,r38; adds	r41,0x0,r8 }
	{ st8	[r8],r33; addl	r40,15,r0; br.call.sptk.many	b0,set_signal_handler; }
	{ ld8	r14,[r33]; adds	r1,0x0,r38; mov.i	ar.pfs,r37; }
	{ cmp.eq	p06,p07,0x1,r14; ld4	r14,[r34]; mov.i	LC,r39; }
	{ (p06) or	r14,0x2,r14; mov.spnt	b0,r36,40000000000AC6A0; or	r14,0x4,r14; }

l40000000000AC6A6:
	{ Invalid; (p07) nop; nop }
	{ break.m	0x4000; (p34) nop; Invalid }

;; fn40000000000AC6C0: 40000000000AC6C0
;;   Called from:
;;     40000000000AEDBC (in run_debug_trap)
;;     40000000000AEF6C (in run_error_trap)
;;     40000000000AEFFC (in run_return_trap)
;;     40000000000AF06C (in run_interrupt_trap)
fn40000000000AC6C0 proc
	{ alloc	r38,ar.pfs,0xA,0x0,0x7; adds	r16,0x8,r12; nop.b	0x0 }
	{ adds	r12,0xFFFFFFFFFFFFFCE0,r12; addl	r17,24316,r1; mov	r37,b5; }
	{ st8.spill	[r1],r16; adds	r15,0x2E8,r12; addp4	r16,r32,r0 }
	{ adds	r14,0x2D0,r12; st8	[r33],r15; sxt4	r15,r16 }
	{ addl	r16,19268,r1; st4	[r32],r14; nop.i	0x0; }
	{ nop.m	0x0; shladd	r16,r15,0x2,r16; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r16]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x0; (p06) br.cond.dpnt.few	40000000000AC7A0; }

l40000000000AC740:
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x6; (p06) br.cond.dpnt.few	40000000000AC7A0; }

l40000000000AC750:
	{ nop.m	0x0; shladd	r15,r15,0x3,r17; adds	r17,0x2E0,r12; }
	{ ld8	r15,[r15]; st8	[r15],r17; addl	r15,-9668,r1; }
	{ ld8	r17,[r17]; ld8	r15,[r15]; nop.i	0x0; }
	{ cmp.eq	p06,p07,r15,r17; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000AC7A0; }

l40000000000AC790:
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x4; (p07) br.cond.dpnt.few	40000000000AC7D0 }

l40000000000AC7A0:
	{ adds	r34,0x0,r0; nop.m	0x0; nop.i	0x0; }

l40000000000AC7B0:
	{ adds	r8,0x0,r34; mov.i	ar.pfs,r38; mov.spnt	b0,r37,40000000000AC7B0 }
	{ nop.m	0x0; adds	r12,0x320,r12; br.ret	b0 }

l40000000000AC7D0:
	{ and	r14,0xFFFFFFFFFFFFFFDF,r14; adds	r39,0x0,r17; or	r14,0x10,r14; }
	{ st4	[r14],r16; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x328,r12; nop.m	0x0; adds	r39,0x1,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r16,0x2E0,r12; adds	r1,0x328,r12; adds	r39,0x0,r8; }
	{ nop.m	0x0; ld8	r40,[r16]; nop.i	0x0 }
	{ ld8	r1,[r1]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x328,r12; adds	r14,0x2D0,r12; adds	r17,0x310,r12; }
	{ ld8	r1,[r1]; st8	[r8],r17; nop.i	0x0 }
	{ ld4	r14,[r14]; adds	r16,0x1,r14; addl	r14,9044,r1; }
	{ nop.m	0x0; ld4	r15,[r14]; addl	r14,9124,r1; }
	{ nop.m	0x0; st4	[r16],r14; addl	r14,9128,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,save_pipestatus_array; }
	{ adds	r15,0x300,r12; adds	r1,0x328,r12; nop.i	0x0 }
	{ ld8	r1,[r1]; st8	[r8],r15; br.call.sptk.many	b0,save_token_state; }
	{ adds	r1,0x328,r12; adds	r17,0x2F0,r12; adds	r16,0x2F8,r12; }
	{ ld8	r1,[r1]; st8	[r8],r16; nop.i	0x0; }
	{ addl	r15,9032,r1; nop.m	0x0; addl	r14,7540,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4	r15,[r15]; ld8	r16,[r14]; nop.i	0x0 }
	{ st8	[r0],r14; st4	[r15],r17; adds	r15,0x308,r12; }
	{ ld4	r17,[r17]; st8	[r16],r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r17; (p07) br.cond.dpnt.few	40000000000ACD60; }

l40000000000AC950:
	{ (p06) adds	r36,0x0,r0; nop.m	0x0; nop.i	0x0 }

l40000000000AC956:
	{ break.m	0x4000; nop; (p48) nop }

l40000000000AC960:
	{ adds	r15,0x2D0,r12; ld4	r15,[r15]; nop.i	0x0; }
	{ and	r14,0xFFFFFFFFFFFFFFFD,r15; cmp4.eq	p06,p07,0x41,r14; nop.i	0x0; }
	{ nop.m	0x0; (p06) addl	r41,5,r0; (p06) br.cond.dptk.few	40000000000AC9B0 }

l40000000000AC98C:
	{ (p01) nop; cmp.eq	p00,p00,r32,r0; (p32) nop }

l40000000000AC990:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x42,r15; nop.i	0x0; }
	{ (p06) addl	r41,21,r0; nop.i	0x0; (p07) addl	r41,5,r0 }

l40000000000AC9A6:
	{ addp4	r0,0xFFFFFFFFFFFFE000,r1; (p20) nop; (p48) nop }

l40000000000AC9B0:
	{ cmp4.eq	p07,p06,0x0,r36; adds	r15,0x2F8,r12; (p07) br.cond.dpnt.few	40000000000ACBF0; }

l40000000000AC9C0:
	{ ld8	r39,[r15]; nop.i	0x0; br.call.sptk.many	b0,restore_token_state; }
	{ adds	r16,0x2F8,r12; adds	r1,0x328,r12; nop.i	0x0 }
	{ ld8	r39,[r16]; ld8	r1,[r1]; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x328,r12; nop.m	0x0; adds	r17,0x300,r12; }
	{ ld8	r1,[r1]; ld8	r39,[r17]; adds	r17,0x308,r12; }
	{ addl	r15,9128,r1; addl	r14,9044,r1; addl	r16,7540,r1 }
	{ ld8	r17,[r17]; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4	r15,[r15]; ld4	r34,[r14]; nop.i	0x0; }
	{ nop.m	0x0; st8	[r17],r16; nop.i	0x0 }
	{ st4	[r15],r14; nop.m	0x0; br.call.sptk.many	b0,restore_pipestatus_array; }
	{ adds	r1,0x328,r12; nop.m	0x0; adds	r14,0x2D0,r12; }
	{ ld8	r1,[r1]; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r35,r14; addl	r14,19268,r1 }
	{ nop.m	0x0; addl	r15,9124,r1; nop.b	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ shladd	r35,r35,0x2,r14; ld4	r14,[r35]; nop.i	0x0 }
	{ st4	[r0],r15; and	r15,0xFFFFFFFFFFFFFFEF,r14; tbit.z	p06,p07,r14,0x5; }
	{ st4	[r15],r35; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000ACBA0 }

l40000000000ACAF0:
	{ adds	r16,0x2F0,r12; ld4	r16,[r16]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r16; (p06) br.cond.dptk.few	40000000000AC7B0 }

l40000000000ACB10:
	{ addl	r14,9032,r1; nop.m	0x0; addl	r35,22740,r1 }
	{ adds	r39,0x10,r12; nop.m	0x0; addl	r41,704,r0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ adds	r40,0x0,r35; st4	[r16],r14; addl	r14,9012,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r34],r14; nop.i	0x0; br.call.sptk.many	b0,xbcopy; }
	{ adds	r1,0x328,r12; nop.m	0x0; cmp4.eq	p06,p07,0x0,r36; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.sptk.few	40000000000AC7B0 }

l40000000000ACB90:
	{ adds	r39,0x0,r35; addl	r40,1,r0; br.call.sptk.many	b0,fn400000000001BBE0 }

l40000000000ACBA0:
	{ nop.m	0x0; adds	r15,0x2E0,r12; nop.i	0x0; }
	{ ld8	r39,[r15]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ ld4	r14,[r35]; nop.m	0x0; adds	r1,0x328,r12; }
	{ and	r14,0xFFFFFFFFFFFFFFDF,r14; ld8	r1,[r1]; nop.i	0x0; }
	{ st4	[r14],r35; nop.i	0x0; br.cond.sptk.few	40000000000ACAF0 }

l40000000000ACBF0:
	{ adds	r17,0x310,r12; adds	r14,0x2E8,r12; nop.i	0x0 }
	{ ld8	r39,[r17]; ld8	r40,[r14]; br.call.sptk.many	b0,parse_and_execute; }
	{ adds	r15,0x2F8,r12; adds	r1,0x328,r12; nop.i	0x0 }
	{ ld8	r39,[r15]; ld8	r1,[r1]; br.call.sptk.many	b0,restore_token_state; }
	{ adds	r16,0x2F8,r12; adds	r1,0x328,r12; nop.i	0x0 }
	{ ld8	r39,[r16]; ld8	r1,[r1]; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x328,r12; nop.m	0x0; adds	r17,0x300,r12; }
	{ ld8	r1,[r1]; ld8	r39,[r17]; adds	r17,0x308,r12; }
	{ addl	r15,9128,r1; addl	r14,9044,r1; addl	r16,7540,r1 }
	{ ld8	r17,[r17]; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4	r15,[r15]; ld4	r34,[r14]; nop.i	0x0; }
	{ nop.m	0x0; st8	[r17],r16; nop.i	0x0 }
	{ st4	[r15],r14; nop.m	0x0; br.call.sptk.many	b0,restore_pipestatus_array; }
	{ adds	r1,0x328,r12; nop.m	0x0; adds	r14,0x2D0,r12; }
	{ ld8	r1,[r1]; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r35,r14; addl	r14,19268,r1 }
	{ nop.m	0x0; addl	r15,9124,r1; nop.b	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ shladd	r35,r35,0x2,r14; ld4	r14,[r35]; nop.i	0x0 }
	{ st4	[r0],r15; and	r15,0xFFFFFFFFFFFFFFEF,r14; tbit.z	p06,p07,r14,0x5; }
	{ st4	[r15],r35; nop.i	0x0; (p06) br.cond.dptk.few	40000000000ACAF0 }

l40000000000ACD50:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000ACBA0 }

l40000000000ACD60:
	{ addl	r34,22740,r1; adds	r40,0x10,r12; addl	r41,704,r0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ adds	r39,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,xbcopy; }
	{ adds	r1,0x328,r12; adds	r39,0x0,r34; addl	r40,1,r0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BD60; }
	{ adds	r1,0x328,r12; nop.m	0x0; adds	r36,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	40000000000AC960; }
40000000000ACDD0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000ACDE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000ACDF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000ACE00: 40000000000ACE00
;;   Called from:
;;     40000000000ACF7C (in fn40000000000ACF00)
;;     40000000000AD25C (in fn40000000000AD180)
;;     40000000000AE2EC (in restore_default_signal)
fn40000000000ACE00 proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; addl	r14,19268,r1; mov	r33,b1 }
	{ addl	r15,24316,r1; adds	r35,0x0,r1; sxt4	r32,r32; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ shladd	r14,r32,0x2,r14; nop.m	0x0; shladd	r32,r32,0x3,r15; }
	{ ld4	r14,[r14]; nop.m	0x0; tbit.z	p06,p07,r14,0x0 }
	{ addl	r14,-9668,r1; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000ACED0; }

l40000000000ACE60:
	{ nop.m	0x0; ld8	r36,[r32]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r36; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000ACED0; }

l40000000000ACE80:
	{ cmp.eq	p06,p07,0x1,r36; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000ACED0; }

l40000000000ACE90:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,r14,r36; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000ACED0; }

l40000000000ACEB0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l40000000000ACED0:
	{ nop.m	0x0; mov.i	ar.pfs,r34; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000ACEE0; br.ret	b0; }
40000000000ACEF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000ACF00: 40000000000ACF00
;;   Called from:
;;     40000000000AF9EC (in reset_signal_handlers)
;;     40000000000AFA2C (in restore_original_signals)
fn40000000000ACF00 proc
	{ alloc	r38,ar.pfs,0xB,0x0,0x9; addl	r36,19268,r1; nop.b	0x0 }
	{ addl	r15,-4388,r1; mov	r40,LC; adds	r39,0x0,r1; }
	{ nop.m	0x0; mov	r37,b5; addl	r33,1,r0 }
	{ ld8	r15,[r15]; cmp.eq	p06,p07,r15,r32; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r36]; nop.i	0x0; }
	{ and	r16,0xFFFFFFFFFFFFFFFE,r14; tbit.z	p09,p08,r14,0x0; (p09) br.cond.dptk.few	40000000000ACFB0; }

l40000000000ACF60:
	{ st4	[r16],r36; nop.m	0x0; adds	r41,0x0,r0 }
	{ nop.b	0x0; (p06) br.cond.dpnt.few	40000000000ACFB0; br.call.sptk.many	b0,fn40000000000ACE00; }

l40000000000ACF7C:
	{ (p52) nop; cmp.lt.unc	p32,p16,r9,r64; (p01) nop }
	{ nop; break.i	0x1000; break.i	0x1000 }
	{ nop; Invalid; break.i	0x1000 }
	{ cmp.lt	p00,p09,r1,r0; zxt4	r59,r11; break.i	0x1000 }

l40000000000ACFB0:
	{ addl	r14,5996,r1; nop.m	0x0; mov.i	LC,0x3F; }
	{ ld8	r35,[r14]; addl	r14,6004,r1; nop.i	0x0; }
	{ ld8	r34,[r14]; nop.m	0x0; nop.i	0x0; }

l40000000000ACFE0:
	{ ld4	r14,[r35],4; nop.m	0x0; adds	r41,0x0,r33; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x0; (p06) br.cond.dptk.few	40000000000AD140 }

l40000000000AD000:
	{ nop.m	0x0; ld8	r14,[r34]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x1,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000AD100; }

l40000000000AD020:
	{ ld8	r14,[r32],8; ld8	r1,[r32],-8; mov.spnt	b6,r14,40000000000AD020 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,b6; }
	{ adds	r1,0x0,r39; nop.m	0x0; nop.i	0x0 }

l40000000000AD050:
	{ adds	r33,0x1,r33; adds	r34,0x8,r34; br.cloop.sptk.few	40000000000ACFE0; }

l40000000000AD060:
	{ addl	r15,7340,r1; adds	r14,0x108,r36; nop.b	0x0 }
	{ adds	r17,0x104,r36; adds	r36,0x10C,r36; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.i	LC,r40; mov.spnt	b0,r37,40000000000AD080; }
	{ ld4	r16,[r15]; nop.m	0x0; addl	r15,7336,r1; }
	{ cmp4.eq	p07,p06,0x0,r16; nop.m	0x0; nop.i	0x0; }
	{ (p07) ld4	r18,[r17]; (p07) ld4	r16,[r36]; nop.i	0x0; }

l40000000000AD0B6:
	{ (p08) fwb; nop; (p48) cmp.ltu	p03,p04,r96,r3; }

l40000000000AD0BC:
	{ cmp.eq	p00,p09,r1,r0; (p01) dep	r96,r3,r4,49,9; (p34) mov	pr,r4,0x88BE }

l40000000000AD0CC:
	{ Invalid; (p32) mov	pr,r4,0x4648; cmp.eq	p04,p08,r9,r100 }

l40000000000AD0D0:
	{ (p07) st4	[r18],r17; (p07) st4	[r16],r36; cmp4.eq	p07,p06,0x0,r15; }

l40000000000AD0D6:
	{ Invalid; (p03) cmp4.eq.or	p00,p51,0xF,r6; (p49) cmp.ltu	p03,p04,r64,r3; }

l40000000000AD0DC:
	{ cmp4.eq.or.andcm	p15,p43,r6,r115; (p01) cmp4.ne.or.andcm	p00,p40,r3,r4; zxt2	r127,r11 }

l40000000000AD0E6:
	{ Invalid; cmp4.eq	p00,p00,r0,r1; (p01) br.call.spnt.many	b0,b3; }

l40000000000AD0EC:
	{ Invalid; Invalid; add	r0,r32,r0 }

l40000000000AD0F6:
	{ break.m	0x4000; (p34) nop; (p32) nop }

l40000000000AD100:
	{ addl	r42,1,r0; nop.m	0x0; adds	r33,0x1,r33 }
	{ adds	r34,0x8,r34; nop.m	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ nop.m	0x0; adds	r1,0x0,r39; br.cloop.sptk.few	40000000000ACFE0 }

l40000000000AD130:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000AD060 }

l40000000000AD140:
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x2; (p06) br.cond.dptk.few	40000000000AD050 }

l40000000000AD150:
	{ ld8	r14,[r32],8; nop.m	0x0; adds	r41,0x0,r33; }
	{ ld8	r1,[r32],-8; mov.spnt	b6,r14,40000000000AD160; br.call.sptk.many	b0,b6; }
	{ nop.m	0x0; adds	r1,0x0,r39; br.cond.sptk.few	40000000000AD050; }

;; fn40000000000AD180: 40000000000AD180
;;   Called from:
;;     40000000000ADAFC (in set_signal)
;;     40000000000ADBFC (in set_signal)
;;     40000000000ADCDC (in set_signal)
;;     40000000000ADD8C (in set_signal)
;;     40000000000AE25C (in restore_default_signal)
;;     40000000000AE3DC (in restore_default_signal)
;;     40000000000AE4FC (in set_impossible_sigchld_trap)
;;     40000000000AE6AC (in ignore_signal)
;;     40000000000AE75C (in ignore_signal)
;;     40000000000AF91C (in free_trap_strings)
fn40000000000AD180 proc
	{ alloc	r38,ar.pfs,0x9,0x0,0x8; addl	r36,19268,r1; mov	r37,b5 }
	{ adds	r39,0x0,r1; addl	r17,24316,r1; sxt4	r34,r32; }
	{ nop.m	0x0; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ shladd	r14,r34,0x2,r36; shladd	r15,r34,0x2,r36; mov.spnt	b0,r37,40000000000AD1B0; }
	{ ld4	r35,[r14]; nop.i	0x0; tbit.z	p07,p06,r35,0x4 }
	{ and	r16,0xFFFFFFFFFFFFFFBF,r35; or	r14,0x1,r35; (p07) br.cond.dpnt.few	40000000000AD250; }

l40000000000AD1E0:
	{ or	r16,0x1,r16; nop.m	0x0; cmp.eq	p07,p06,0x1,r33 }
	{ st4	[r14],r15; nop.m	0x0; nop.i	0x0; }
	{ adds	r14,0x0,r16; (p07) or	r35,0x41,r35; nop.i	0x0 }

l40000000000AD20C:
	{ nop; (p34) mov	pr,r68,0x8050; dep	r100,r3,r100,63,9 }

l40000000000AD21C:
	{ (p17) cmp4.eq.and	p36,p40,r17,r64; (p48) nop }

l40000000000AD226:
	{ mf.a; nop; nop; }

l40000000000AD22C:
	{ Invalid; (p16) cmp.eq	p40,p08,r4,r102; (p01) cmp.lt.unc	p08,p16,r67,r11 }
	{ Invalid; Invalid; add	r0,r32,r0 }

l40000000000AD246:
	{ break.m	0x4000; (p34) nop; nop }

l40000000000AD250:
	{ adds	r40,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn40000000000ACE00; }
	{ and	r16,0xFFFFFFFFFFFFFFBF,r35; shladd	r15,r34,0x2,r36; mov.i	ar.pfs,r38 }
	{ cmp.eq	p07,p06,0x1,r33; or	r14,0x1,r35; adds	r1,0x0,r39; }
	{ or	r16,0x1,r16; st4	[r14],r15; nop.b	0x0 }
	{ (p07) or	r35,0x41,r35; addl	r17,24316,r1; mov.spnt	b0,r37,40000000000AD290; }

l40000000000AD296:
	{ Invalid; nop; (p32) nop.b	0x10003 }
	{ break.m	0x4000; cmp4.ltu	p00,p00,r0,r1; (p01) addl	r96,12904,r3 }

l40000000000AD2B6:
	{ mf.a; cmp4.ltu	p00,p00,r0,r1; (p33) nop; }

l40000000000AD2BC:
	{ cmp4.eq.and	p00,p41,r1,r0; (p01) nop; (p34) dep	r40,r68,r4,62,1 }

l40000000000AD2C6:
	{ Invalid; (p17) nop; break.b	0x80000 }
	{ Invalid; (p03) nop; break.b	0x80000 }
	{ mf.a; cmp4.eq	p00,p00,r0,r1; (p01) nop }

l40000000000AD2F6:
	{ break.m	0x4000; (p34) nop; Invalid }
40000000000AD300 08 18 1D 0A 80 05 E0 A0 07 72 49 40 04 00 C4 00 .........rI@....
40000000000AD310 09 20 01 02 00 21 50 02 80 00 42 20 04 00 59 00 . ...!P...B ..Y.
40000000000AD320 0B 00 00 00 01 00 E0 08 39 24 40 00 00 00 04 00 ........9$@.....
40000000000AD330 11 30 01 1C 18 10 00 00 00 02 00 00 D8 77 00 50 .0...........w.P
40000000000AD340 08 08 00 48 00 21 00 00 00 02 00 A0 04 00 01 84 ...H.!..........
40000000000AD350 19 30 01 00 00 21 00 00 00 02 00 00 38 FE FF 58 .0...!......8..X
40000000000AD360 09 08 00 48 00 21 00 00 00 02 00 00 30 02 AA 00 ...H.!......0...
40000000000AD370 09 70 10 03 96 24 00 00 00 02 00 00 20 0A 00 07 .p...$...... ...
40000000000AD380 0B 00 00 00 01 00 10 0A 39 22 40 00 00 00 04 00 ........9"@.....
40000000000AD390 0B 70 00 42 10 10 E0 F0 3B 58 44 00 00 00 04 00 .p.B....;XD.....
40000000000AD3A0 11 00 38 42 90 11 00 00 00 02 00 80 08 00 84 00 ..8B............
40000000000AD3B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; signal_name: 40000000000AD3C0
;;   Called from:
;;     4000000000078F9C (in fn40000000000780C0)
;;     40000000000AF4FC (in run_pending_traps)
;;     40000000000AF4FC (in run_pending_traps)
;;     40000000000EFE9C (in display_signal_list)
;;     40000000000F012C (in display_signal_list)
;;     400000000010DC4C (in fn400000000010DBC0)
;;     400000000010DD6C (in fn400000000010DBC0)
signal_name proc
	{ alloc	r34,ar.pfs,0x7,0x0,0x4; addl	r14,-20604,r1; sxt4	r15,r32 }
	{ addl	r37,-4356,r1; adds	r35,0x0,r1; cmp4.ltu	p06,p07,0x43,r32; }
	{ nop.m	0x0; mov	r33,b1; adds	r36,0x0,r0 }
	{ addl	r38,5,r0; ld8	r37,[r37]; (p06) br.cond.dpnt.few	40000000000AD430; }

l40000000000AD400:
	{ shladd	r14,r15,0x3,r14; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ ld8	r8,[r14]; nop.m	0x0; mov.spnt	b0,r33,40000000000AD410; }
	{ cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	40000000000AD430; br.ret	b0; }

l40000000000AD42C:
	{ Invalid; break.m	0x1000; break.i	0x1000 }

l40000000000AD430:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000AD450; br.ret	b0; }
40000000000AD460 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000AD470 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; decode_signal: 40000000000AD480
;;   Called from:
;;     40000000000EFFFC (in display_signal_list)
;;     400000000010022C (in kill_builtin)
;;     400000000010046C (in kill_builtin)
;;     400000000010E1CC (in trap_builtin)
;;     400000000010E1CC (in trap_builtin)
;;     400000000010E2DC (in trap_builtin)
;;     400000000010E36C (in trap_builtin)
;;     400000000010E43C (in trap_builtin)
;;     400000000010E72C (in trap_builtin)
decode_signal proc
	{ alloc	r38,ar.pfs,0xD,0x0,0xA; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r40,pr }
	{ addl	r36,-20604,r1; adds	r39,0x0,r1; adds	r42,0x0,r32; }
	{ nop.m	0x0; mov	r37,b5; nop.i	0x0 }
	{ nop.m	0x0; adds	r43,0x10,r12; br.call.sptk.many	b0,legal_number; }
	{ nop.m	0x0; adds	r35,0x0,r0; mov	r41,LC }
	{ adds	r1,0x0,r39; adds	r14,0x10,r12; cmp4.eq	p06,p07,0x0,r8; }
	{ nop.m	0x0; tnat.z	p16,p17,r33; nop.i	0x0; }
	{ nop.m	0x0; tnat.z	p18,p19,r33; (p06) br.cond.dptk.few	40000000000AD550 }

l40000000000AD500:
	{ nop.m	0x0; ld8	r8,[r14]; nop.i	0x0; }
	{ cmp.ltu	p07,p06,0x40,r8; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000AD600; }

l40000000000AD520:
	{ nop.m	0x0; mov	pr,r40,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.i	LC,r41; mov.spnt	b0,r37,40000000000AD530 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000AD550:
	{ nop.m	0x0; st8	[r0],r14; mov.i	LC,0x43; }

l40000000000AD560:
	{ nop.m	0x0; ld8	r34,[r36],8; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r34; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000AD5E0; }

l40000000000AD580:
	{ ld1	r14,[r34]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000AD5E0; }

l40000000000AD5A0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x53,r14; (p06) br.cond.dpnt.few	40000000000AD630 }

l40000000000AD5B0:
	{ adds	r42,0x0,r32; adds	r43,0x0,r34; (p16) br.cond.dptk.few	40000000000AD6D0 }

l40000000000AD5C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B7C0; }
	{ adds	r1,0x0,r39; cmp4.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	40000000000AD6F0 }

l40000000000AD5E0:
	{ adds	r35,0x1,r35; nop.m	0x0; adds	r14,0x10,r12; }
	{ st8	[r35],r14; nop.i	0x0; br.cloop.sptk.few	40000000000AD560 }

l40000000000AD600:
	{ addl	r8,-1,r0; mov	pr,r40,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.i	LC,r41; mov.spnt	b0,r37,40000000000AD610 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000AD630:
	{ addl	r43,-4348,r1; adds	r42,0x0,r34; addl	r44,3,r0; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C020; }
	{ adds	r1,0x0,r39; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	40000000000AD5B0 }

l40000000000AD660:
	{ adds	r43,0x3,r34; adds	r42,0x0,r32; (p16) br.cond.dptk.few	40000000000AD720 }

l40000000000AD670:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B7C0; }
	{ nop.m	0x0; adds	r1,0x0,r39; cmp4.eq	p07,p06,0x0,r8 }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	40000000000AD6F0; (p19) br.cond.dptk.few	40000000000AD5B0 }

l40000000000AD69C:
	{ (p57) ldfp8	f127,f63,[r37]; zxt1	r96,r64; cmp.lt	p00,p00,r32,r0 }

l40000000000AD6A0:
	{ adds	r35,0x1,r35; nop.m	0x0; adds	r14,0x10,r12; }
	{ st8	[r35],r14; nop.i	0x0; br.cloop.sptk.few	40000000000AD560 }

l40000000000AD6C0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000AD600 }

l40000000000AD6D0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r39; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000000AD5E0; }

l40000000000AD6F0:
	{ adds	r8,0x0,r35; mov	pr,r40,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.i	LC,r41; mov.spnt	b0,r37,40000000000AD700 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000000AD720:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ nop.m	0x0; adds	r1,0x0,r39; cmp4.eq	p07,p06,0x0,r8 }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	40000000000AD6F0; (p18) br.cond.dptk.few	40000000000AD6A0 }

l40000000000AD74C:
	{ Invalid; break.i	0x1000; break.i	0x1000 }

l40000000000AD750:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000AD5B0; }
40000000000AD760 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000AD770 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; set_sigint_handler: 40000000000AD780
;;   Called from:
;;     400000000005073C (in shell_execve)
;;     40000000000948DC (in command_substitute)
;;     40000000000A52AC (in fn40000000000A1400)
set_sigint_handler proc
	{ alloc	r33,ar.pfs,0x5,0x0,0x3; addl	r14,19268,r1; mov	r32,b0 }
	{ adds	r34,0x0,r1; nop.m	0x0; addl	r36,-9964,r1; }
	{ nop.m	0x0; addl	r35,2,r0; adds	r14,0x8,r14; }
	{ ld4	r14,[r14]; nop.m	0x0; tbit.z	p07,p06,r14,0x1; }
	{ (p06) addl	r8,1,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000AD850; }

l40000000000AD7C6:
	{ chk.a.nc	r0,3FFFFFFFFF0ADFC6; nop; break.i	0x80000 }

l40000000000AD7D0:
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x6; (p07) br.cond.dpnt.few	40000000000AD870; }

l40000000000AD7E0:
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x0; addl	r14,6516,r1 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000AD8A0; }

l40000000000AD800:
	{ nop.m	0x0; ld8	r36,[r36]; nop.i	0x0; }
	{ ld4	r14,[r14]; cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; }
	{ (p07) addl	r36,-10004,r1; nop.i	0x0; nop.i	0x0 }

l40000000000AD826:
	{ break.m	0x4000; nop; (p01) nop }

l40000000000AD836:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; mov	pr,0x4000; break.i	0x80000 }

l40000000000AD850:
	{ nop.m	0x0; mov.i	ar.pfs,r33; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r32,40000000000AD860; br.ret	b0; }

l40000000000AD870:
	{ addl	r35,2,r0; addl	r36,1,r0; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ nop.m	0x0; mov.spnt	b0,r32,40000000000AD890; br.ret	b0 }

l40000000000AD8A0:
	{ addl	r36,-9628,r1; nop.m	0x0; addl	r35,2,r0; }
	{ ld8	r36,[r36]; nop.i	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ nop.m	0x0; mov.spnt	b0,r32,40000000000AD8D0; br.ret	b0; }
40000000000AD8E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000AD8F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; trap_to_sighandler: 40000000000AD900
;;   Called from:
;;     400000000007E79C (in fn400000000007D580)
trap_to_sighandler proc
	{ addl	r14,19268,r1; nop.m	0x0; sxt4	r32,r32; }
	{ nop.m	0x0; shladd	r32,r32,0x2,r14; nop.i	0x0; }
	{ ld4	r8,[r32]; nop.i	0x0; tbit.z	p06,p07,r8,0x0 }
	{ and	r14,0x42,r8; (p07) addl	r8,-9628,r1; nop.i	0x0; }

l40000000000AD93C:
	{ Invalid; (p01) mov	pr,r0,0x8400; (p01) cmp.eq	p00,p08,r2,r6 }

l40000000000AD946:
	{ Invalid; (p03) nop; add	r0,r0,r32; }

l40000000000AD94C:
	{ Invalid; mov	pr,r32,0x0; (p17) shladd	r0,r0,0x3,r0 }

l40000000000AD95C:
	{ nop; break.m	0x1000; break.i	0x1000 }
40000000000AD960 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000AD970 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; set_signal: 40000000000AD980
;;   Called from:
;;     40000000000ADDDC (in set_return_trap)
;;     40000000000ADE1C (in set_error_trap)
;;     40000000000ADE5C (in set_debug_trap)
;;     40000000000ADF1C (in maybe_set_sigchld_trap)
;;     400000000010E31C (in trap_builtin)
set_signal proc
	{ alloc	r38,ar.pfs,0xA,0x0,0x8; cmp4.eq	p08,p09,0x0,r32; nop.b	0x0 }
	{ cmp4.eq	p06,p07,0x41,r32; mov	r37,b5; adds	r39,0x0,r1; }
	{ (p08) addl	r14,1,r0; sxt4	r15,r32; adds	r34,0x0,r32; }

l40000000000AD9A6:
	{ (p07) break.m	0x59000; (p17) dep	r0,r32,r0,43,3; (p34) nop.b	0x3 }

l40000000000AD9B6:
	{ add	r0,r0,r1; (p17) nop; (p32) nop }
	{ (p07) chk.a.clr	r62,3FFFFFFFFF24D3C6; nop; (p48) nop }

l40000000000AD9D0:
	{ addl	r35,19268,r1; cmp4.ltu	p07,p06,0x1,r14; (p06) br.cond.dpnt.few	40000000000ADD20; }

l40000000000AD9E0:
	{ nop.m	0x0; shladd	r35,r15,0x2,r35; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x1; (p06) br.cond.dpnt.few	40000000000ADB80; }

l40000000000ADA10:
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x0; (p06) br.cond.dptk.few	40000000000ADA70 }

l40000000000ADA20:
	{ nop.m	0x0; addl	r36,23796,r1; nop.i	0x0; }
	{ nop.m	0x0; shladd	r36,r15,0x3,r36; addl	r15,-9668,r1; }
	{ ld8	r16,[r36]; ld8	r15,[r15]; nop.i	0x0; }
	{ cmp.eq	p07,p06,r15,r16; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000ADB00; }

l40000000000ADA60:
	{ nop.m	0x0; cmp.eq	p06,p07,0x1,r16; (p06) br.cond.dpnt.few	40000000000ADB80; }

l40000000000ADA70:
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x3; nop.i	0x0 }
	{ adds	r40,0x0,r33; adds	r32,0x0,r34; (p07) br.cond.dpnt.few	40000000000ADC70; }

l40000000000ADA90:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r39; adds	r40,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r41,0x0,r33 }
	{ adds	r40,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r39; adds	r33,0x0,r8; mov.spnt	b0,r37,40000000000ADAD0; }
	{ nop.m	0x0; mov.i	ar.pfs,r38; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000AD180; }

l40000000000ADB00:
	{ adds	r40,0x0,r32; adds	r41,0x0,r0; br.call.sptk.many	b0,set_signal_handler; }
	{ nop.m	0x0; adds	r1,0x0,r39; adds	r41,0x0,r8 }
	{ st8	[r8],r36; adds	r40,0x0,r32; br.call.sptk.many	b0,set_signal_handler; }
	{ ld8	r14,[r36]; adds	r1,0x0,r39; cmp.eq	p06,p07,0x1,r14 }
	{ nop.m	0x0; ld4	r14,[r35]; (p07) br.cond.dptk.few	40000000000ADA70; }

l40000000000ADB50:
	{ nop.m	0x0; or	r14,0x2,r14; nop.i	0x0; }
	{ st4	[r14],r35; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000ADB80:
	{ nop.m	0x0; mov.i	ar.pfs,r38; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000ADB90; br.ret	b0; }

l40000000000ADBA0:
	{ adds	r40,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r39; adds	r40,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r40,0x0,r8 }
	{ adds	r41,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r40,0x0,r32 }
	{ adds	r41,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn40000000000AD180; }
	{ adds	r1,0x0,r39; cmp4.eq	p07,p06,0x0,r35; (p07) br.cond.spnt.few	40000000000ADB80; }

l40000000000ADC10:
	{ addl	r14,6516,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000ADB80 }

l40000000000ADC40:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,initialize_terminating_signals; }
	{ adds	r1,0x0,r39; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000ADC60; br.ret	b0; }

l40000000000ADC70:
	{ addl	r41,1,r0; adds	r40,0x0,r34; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r39; adds	r40,0x0,r33; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r39; adds	r40,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r41,0x0,r33 }
	{ adds	r40,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r40,0x0,r34 }
	{ adds	r41,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn40000000000AD180; }
	{ adds	r1,0x0,r39; adds	r40,0x0,r34; addl	r41,-9628,r1; }
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r39; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000ADD10; br.ret	b0; }

l40000000000ADD20:
	{ adds	r40,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r39; adds	r40,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r41,0x0,r33 }
	{ adds	r40,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r39; adds	r33,0x0,r8; mov.spnt	b0,r37,40000000000ADD60; }
	{ nop.m	0x0; mov.i	ar.pfs,r38; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000AD180; }
40000000000ADD90 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000ADDA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000ADDB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; set_return_trap: 40000000000ADDC0
set_return_trap proc
	{ alloc	r16,ar.pfs,0x2,0x0,0x2; adds	r33,0x0,r32; addl	r32,67,r0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	set_signal; }
40000000000ADDE0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000ADDF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; set_error_trap: 40000000000ADE00
set_error_trap proc
	{ alloc	r16,ar.pfs,0x2,0x0,0x2; adds	r33,0x0,r32; addl	r32,66,r0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	set_signal; }
40000000000ADE20 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000ADE30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; set_debug_trap: 40000000000ADE40
set_debug_trap proc
	{ alloc	r16,ar.pfs,0x2,0x0,0x2; adds	r33,0x0,r32; addl	r32,65,r0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	set_signal; }
40000000000ADE60 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000ADE70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; maybe_set_sigchld_trap: 40000000000ADE80
maybe_set_sigchld_trap proc
	{ alloc	r16,ar.pfs,0x2,0x0,0x2; addl	r14,19268,r1; adds	r33,0x0,r32; }
	{ nop.m	0x0; adds	r14,0x44,r14; nop.i	0x0; }
	{ ld4	r14,[r14]; nop.m	0x0; tbit.z	p07,p06,r14,0x0 }
	{ addl	r14,24316,r1; nop.m	0x0; (p06) br.ret	b0; }

l40000000000ADEC0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ adds	r14,0x88,r14; ld8	r15,[r14]; addl	r14,-9668,r1; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r14,r15; (p06) br.ret	b0 }

l40000000000ADF00:
	{ nop.m	0x0; addl	r32,17,r0; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	set_signal; }
40000000000ADF20 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000ADF30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; get_all_original_signals: 40000000000ADF40
;;   Called from:
;;     400000000010E6CC (in trap_builtin)
get_all_original_signals proc
	{ alloc	r37,ar.pfs,0xA,0x0,0x8; addl	r14,6012,r1; nop.b	0x0 }
	{ addl	r35,-9668,r1; mov	r36,b4; adds	r38,0x0,r1; }
	{ ld8	r32,[r14]; addl	r14,6020,r1; nop.b	0x0 }
	{ addl	r33,1,r0; ld8	r35,[r35]; mov	r39,LC; }
	{ nop.m	0x0; ld8	r34,[r14]; mov.i	LC,0x3F; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000ADFA0:
	{ nop.m	0x0; ld8	r14,[r32]; nop.i	0x0; }
	{ cmp.eq	p06,p07,r35,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000AE000; }

l40000000000ADFC0:
	{ nop.m	0x0; adds	r33,0x1,r33; adds	r32,0x8,r32 }
	{ nop.m	0x0; adds	r34,0x4,r34; br.cloop.sptk.few	40000000000ADFA0 }

l40000000000ADFE0:
	{ nop.m	0x0; mov.i	ar.pfs,r37; mov.i	LC,r39; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000ADFF0; br.ret	b0; }

l40000000000AE000:
	{ adds	r40,0x0,r33; adds	r41,0x0,r0; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r38; st8	[r8],r32; adds	r40,0x0,r33 }
	{ adds	r41,0x0,r8; adds	r33,0x1,r33; br.call.sptk.many	b0,set_signal_handler; }
	{ ld8	r14,[r32]; adds	r1,0x0,r38; adds	r32,0x8,r32; }
	{ cmp.eq	p07,p06,0x1,r14; (p07) ld4	r14,[r34]; nop.i	0x0; }

l40000000000AE04C:
	{ nop; cmp4.eq.and	p00,p32,r32,r0; zxt1	r64,r11 }

l40000000000AE05C:
	{ Invalid; (p32) dep	r67,r8,r100,63,9; (p04) nop }

l40000000000AE066:
	{ Invalid; (p02) nop; break.i	0x80000 }

l40000000000AE070:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000ADFE0; }

;; set_original_signal: 40000000000AE080
set_original_signal proc
	{ addl	r15,23796,r1; nop.m	0x0; sxt4	r14,r32 }
	{ adds	r32,0xFFFFFFFFFFFFFFFF,r32; nop.m	0x0; addl	r17,-9668,r1; }
	{ nop.m	0x0; cmp4.ltu	p07,p06,0x3F,r32; (p07) br.ret	b0; }

l40000000000AE0B0:
	{ shladd	r15,r14,0x3,r15; ld8	r17,[r17]; nop.i	0x0; }
	{ nop.m	0x0; ld8	r16,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r17,r16; (p06) br.ret	b0; }

l40000000000AE0E0:
	{ cmp.eq	p07,p06,0x1,r33; st8	[r33],r15; nop.i	0x0; }
	{ (p07) addl	r15,19268,r1; nop.m	0x0; nop.i	0x0; }

l40000000000AE0F6:
	{ break.m	0x4000; cmp4.ltu	p00,p00,0x0,r1; (p33) cmp.eq.unc	p03,p04,r99,r35 }

l40000000000AE106:
	{ (p07) fwb; nop; Invalid; }

l40000000000AE10C:
	{ nop; cmp4.eq.or.andcm	p00,p32,r32,r0; zxt1	r96,r11 }

l40000000000AE11C:
	{ Invalid; Invalid; add	r0,r32,r0 }

l40000000000AE126:
	{ break.m	0x4000; (p34) nop; break.i	0x80000 }
40000000000AE130 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; restore_default_signal: 40000000000AE140
;;   Called from:
;;     40000000000AE4DC (in set_impossible_sigchld_trap)
;;     400000000010D28C (in source_builtin)
;;     400000000010E57C (in trap_builtin)
restore_default_signal proc
	{ alloc	r36,ar.pfs,0x8,0x0,0x6; cmp4.eq	p07,p06,0x41,r32; mov	r35,b3 }
	{ nop.m	0x0; adds	r37,0x0,r1; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x0,r32; (p07) br.cond.dptk.few	40000000000AE2A0 }

l40000000000AE170:
	{ nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFFBE,r32; nop.i	0x0; }
	{ cmp4.ltu	p06,p07,0x1,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000AE2A0; }

l40000000000AE190:
	{ nop.m	0x0; cmp4.lt	p07,p06,0x40,r32; (p07) br.cond.dptk.few	40000000000AE360 }

l40000000000AE1A0:
	{ addl	r34,23796,r1; sxt4	r33,r32; addl	r15,-9668,r1; }
	{ nop.m	0x0; ld8	r15,[r15]; nop.i	0x0; }
	{ shladd	r34,r33,0x3,r34; ld8	r14,[r34]; nop.i	0x0; }
	{ cmp.eq	p06,p07,r15,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000AE400; }

l40000000000AE1E0:
	{ addl	r34,19268,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; shladd	r14,r33,0x2,r34; nop.i	0x0; }
	{ ld4	r14,[r14]; nop.m	0x0; nop.i	0x0; }

l40000000000AE210:
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x1; nop.i	0x0 }
	{ adds	r38,0x0,r32; adds	r39,0x0,r0; (p06) br.cond.dpnt.few	40000000000AE280; }

l40000000000AE230:
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x0; (p06) br.cond.dpnt.few	40000000000AE280; }

l40000000000AE240:
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x3; (p07) br.cond.dpnt.few	40000000000AE390; }

l40000000000AE250:
	{ shladd	r33,r33,0x2,r34; nop.i	0x0; br.call.sptk.many	b0,fn40000000000AD180; }
	{ ld4	r14,[r33]; adds	r1,0x0,r37; and	r14,0xFFFFFFFFFFFFFFFE,r14 }
	{ nop.m	0x0; st4	[r14],r33; nop.i	0x0 }

l40000000000AE280:
	{ nop.m	0x0; mov.i	ar.pfs,r36; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000AE290; br.ret	b0 }

l40000000000AE2A0:
	{ addl	r34,19268,r1; sxt4	r33,r32; adds	r14,0xFFFFFFFFFFFFFFBF,r32; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x2,r14; (p06) br.cond.dpnt.few	40000000000AE2E0; }

l40000000000AE2C0:
	{ shladd	r14,r33,0x2,r34; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x4; (p06) br.cond.dptk.few	40000000000AE300 }

l40000000000AE2E0:
	{ nop.m	0x0; adds	r38,0x0,r32; br.call.sptk.many	b0,fn40000000000ACE00; }
	{ adds	r1,0x0,r37; nop.m	0x0; nop.i	0x0; }

l40000000000AE300:
	{ shladd	r34,r33,0x2,r34; addl	r15,24316,r1; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; ld4	r14,[r34]; mov.spnt	b0,r35,40000000000AE310 }
	{ nop.m	0x0; shladd	r33,r33,0x3,r15; tbit.z	p07,p06,r14,0x4 }
	{ and	r15,0xFFFFFFFFFFFFFFFE,r14; st4	[r15],r34; (p06) or	r15,0x20,r15 }

l40000000000AE340:
	{ nop.m	0x0; st8	[r0],r33; nop.i	0x0; }
	{ (p06) st4	[r15],r34; nop.i	0x0; br.ret	b0 }

l40000000000AE356:
	{ break.m	0x4000; (p34) nop; (p32) nop }

l40000000000AE360:
	{ addl	r34,19268,r1; nop.m	0x0; sxt4	r33,r32; }
	{ nop.m	0x0; shladd	r14,r33,0x2,r34; nop.i	0x0; }
	{ ld4	r14,[r14]; nop.i	0x0; br.cond.sptk.few	40000000000AE210; }

l40000000000AE390:
	{ addl	r14,23796,r1; nop.m	0x0; adds	r38,0x0,r32; }
	{ nop.m	0x0; shladd	r14,r33,0x3,r14; shladd	r33,r33,0x2,r34; }
	{ ld8	r39,[r14]; nop.i	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r38,0x0,r32 }
	{ adds	r39,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,fn40000000000AD180; }
	{ ld4	r14,[r33]; adds	r1,0x0,r37; and	r14,0xFFFFFFFFFFFFFFFE,r14; }
	{ st4	[r14],r33; nop.i	0x0; br.cond.sptk.few	40000000000AE280 }

l40000000000AE400:
	{ adds	r38,0x0,r32; adds	r39,0x0,r0; br.call.sptk.many	b0,set_signal_handler; }
	{ nop.m	0x0; adds	r1,0x0,r37; adds	r39,0x0,r8 }
	{ st8	[r8],r34; adds	r38,0x0,r32; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r37; ld8	r14,[r34]; nop.i	0x0; }
	{ addl	r34,19268,r1; nop.m	0x0; cmp.eq	p06,p07,0x1,r14; }
	{ nop.m	0x0; (p06) shladd	r15,r33,0x2,r34; (p07) shladd	r14,r33,0x2,r34; }

l40000000000AE45C:
	{ Invalid; (p02) cmp4.ne.and	p32,p40,r3,r4; (p01) rfi; }

l40000000000AE460:
	{ (p06) ld4	r16,[r15]; (p07) ld4	r14,[r14]; nop.i	0x0; }

l40000000000AE466:
	{ (p07) fwb; adds	r0,0x0,r1; (p01) nop; }

l40000000000AE46C:
	{ Invalid; zxt1	r0,r11; cmp4.eq.and	p00,p00,r32,r0 }

l40000000000AE476:
	{ chk.a.nc	r0,3FFFFFFFFF0AEC76; (p07) nop; add	r0,r0,r32 }

l40000000000AE480:
	{ nop.m	0x0; (p06) st4	[r16],r15; br.cond.sptk.few	40000000000AE210; }

l40000000000AE48C:
	{ (p44) nop; break.i	0x1000; break.b	0x1000 }
40000000000AE490 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000AE4A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000AE4B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; set_impossible_sigchld_trap: 40000000000AE4C0
;;   Called from:
;;     400000000007D46C (in run_sigchld_trap)
set_impossible_sigchld_trap proc
	{ alloc	r33,ar.pfs,0x5,0x0,0x3; mov	r32,b0; adds	r34,0x0,r1; }
	{ addl	r35,17,r0; nop.i	0x0; br.call.sptk.many	b0,restore_default_signal; }
	{ adds	r1,0x0,r34; addl	r35,17,r0; addl	r36,-9668,r1; }
	{ ld8	r36,[r36]; nop.i	0x0; br.call.sptk.many	b0,fn40000000000AD180; }
	{ adds	r1,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ addl	r14,19268,r1; nop.m	0x0; mov.spnt	b0,r32,40000000000AE510; }
	{ nop.m	0x0; adds	r14,0x44,r14; nop.i	0x0; }
	{ ld4	r15,[r14]; and	r15,0xFFFFFFFFFFFFFFFE,r15; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.ret	b0; }
40000000000AE550 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000AE560 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000AE570 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; ignore_signal: 40000000000AE580
;;   Called from:
;;     400000000010E55C (in trap_builtin)
ignore_signal proc
	{ alloc	r38,ar.pfs,0xA,0x0,0x8; cmp4.eq	p06,p07,0x0,r32; mov	r37,b5 }
	{ addl	r35,19268,r1; adds	r39,0x0,r1; sxt4	r34,r32; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x41,r32; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dptk.few	40000000000AE6B0 }

l40000000000AE5C0:
	{ nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFFBE,r32; nop.i	0x0; }
	{ cmp4.ltu	p06,p07,0x1,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000AE6B0; }

l40000000000AE5E0:
	{ nop.m	0x0; cmp4.lt	p07,p06,0x40,r32; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x0,r32; (p07) br.cond.dptk.few	40000000000AE640 }

l40000000000AE600:
	{ addl	r36,23796,r1; nop.m	0x0; addl	r15,-9668,r1; }
	{ nop.m	0x0; ld8	r15,[r15]; nop.i	0x0; }
	{ shladd	r36,r34,0x3,r36; ld8	r14,[r36]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,r15,r14; (p06) br.cond.dpnt.few	40000000000AE760 }

l40000000000AE640:
	{ nop.m	0x0; shladd	r34,r34,0x2,r35; nop.i	0x0; }
	{ ld4	r14,[r34]; nop.m	0x0; nop.i	0x0; }

l40000000000AE660:
	{ nop.m	0x0; and	r15,0x42,r14; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r15; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000AE700; }

l40000000000AE680:
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x3; (p07) br.cond.dpnt.few	40000000000AE720 }

l40000000000AE690:
	{ addl	r33,1,r0; mov.spnt	b0,r37,40000000000AE690; mov.i	ar.pfs,r38; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000AD180 }

l40000000000AE6B0:
	{ shladd	r14,r34,0x2,r35; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x6; (p07) br.cond.dpnt.few	40000000000AE690; }

l40000000000AE6D0:
	{ nop.m	0x0; cmp4.lt	p07,p06,0x40,r32; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x0,r32; (p06) br.cond.dptk.few	40000000000AE600 }

l40000000000AE6F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000AE640 }

l40000000000AE700:
	{ nop.m	0x0; mov.i	ar.pfs,r38; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000AE710; br.ret	b0; }

l40000000000AE720:
	{ adds	r40,0x0,r32; nop.m	0x0; addl	r41,1,r0 }
	{ addl	r33,1,r0; nop.m	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r39; mov.spnt	b0,r37,40000000000AE740; mov.i	ar.pfs,r38; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000AD180; }

l40000000000AE760:
	{ adds	r40,0x0,r32; nop.m	0x0; adds	r41,0x0,r0 }
	{ shladd	r34,r34,0x2,r35; nop.m	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ nop.m	0x0; adds	r1,0x0,r39; adds	r41,0x0,r8 }
	{ st8	[r8],r36; adds	r40,0x0,r32; br.call.sptk.many	b0,set_signal_handler; }
	{ ld8	r14,[r36]; adds	r1,0x0,r39; cmp.eq	p06,p07,0x1,r14; }
	{ (p06) ld4	r15,[r34]; (p07) ld4	r14,[r34]; nop.i	0x0; }

l40000000000AE7B6:
	{ (p07) fwb; adds	r0,0x0,r1; (p49) nop; }

l40000000000AE7BC:
	{ cmp4.eq.or.andcm	p00,p02,r1,r0; zxt1	r96,r11; cmp4.eq.and	p00,p00,r32,r0 }

l40000000000AE7C6:
	{ chk.a.nc	r0,3FFFFFFFFF0AEFC6; (p07) nop; add	r0,r0,r32 }

l40000000000AE7D0:
	{ nop.m	0x0; (p06) st4	[r15],r34; br.cond.sptk.few	40000000000AE660; }

l40000000000AE7DC:
	{ (p52) nop; break.i	0x1000; break.b	0x1000 }
40000000000AE7E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000AE7F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; run_exit_trap: 40000000000AE800
;;   Called from:
;;     40000000000224AC (in exit_shell)
;;     4000000000094D4C (in command_substitute)
;;     400000000009500C (in command_substitute)
;;     400000000009530C (in command_substitute)
;;     40000000000953CC (in command_substitute)
;;     40000000000AFB4C (in maybe_call_trap_handler)
;;     40000000000B4DDC (in termsig_handler)
;;     40000000000B4DDC (in termsig_handler)
;;     40000000000B4F7C (in termsig_handler)
run_exit_trap proc
	{ alloc	r36,ar.pfs,0x8,0x0,0x5; adds	r16,0x8,r12; adds	r12,0xFFFFFFFFFFFFFFD0,r12 }
	{ addl	r14,9044,r1; addl	r32,9128,r1; addl	r33,19268,r1; }
	{ nop.m	0x0; st8.spill	[r1],r16; mov	r35,b3 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ st4	[r14],r32; nop.i	0x0; br.call.sptk.many	b0,save_pipestatus_array; }
	{ ld4	r14,[r33]; adds	r1,0x38,r12; adds	r37,0x0,r8; }
	{ and	r14,0x51,r14; ld8	r1,[r1]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x1,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000AE8F0; }

l40000000000AE890:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,restore_pipestatus_array; }
	{ adds	r1,0x38,r12; ld4	r32,[r32]; adds	r14,0x10,r12 }
	{ nop.m	0x0; adds	r15,0x10,r12; nop.i	0x0; }
	{ st4	[r32],r14; ld8	r1,[r1]; nop.i	0x0; }
	{ ld4	r8,[r15]; mov.i	ar.pfs,r36; mov.spnt	b0,r35,40000000000AE8D0 }
	{ nop.m	0x0; adds	r12,0x30,r12; br.ret	b0 }

l40000000000AE8F0:
	{ addl	r34,24316,r1; nop.m	0x0; nop.i	0x0; }
	{ ld8	r37,[r34]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x38,r12; nop.m	0x0; adds	r37,0x1,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x38,r12; ld8	r38,[r34]; adds	r37,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x38,r12; adds	r14,0x18,r12; adds	r15,0x10,r12 }
	{ ld4	r32,[r32]; addl	r16,1,r0; addl	r38,1,r0; }
	{ ld8	r1,[r1]; st8	[r8],r14; nop.i	0x0 }
	{ st4	[r32],r15; ld4	r14,[r33]; nop.i	0x0; }
	{ addl	r15,9124,r1; and	r14,0xFFFFFFFFFFFFFFFE,r14; addl	r37,25252,r1; }
	{ nop.m	0x0; nop.m	0x0; or	r14,0x10,r14 }
	{ nop.m	0x0; st4	[r14],r33; nop.i	0x0; }
	{ st4	[r16],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BD60; }
	{ adds	r1,0x38,r12; adds	r14,0x20,r12; adds	r15,0x20,r12; }
	{ ld8	r1,[r1]; st4	[r8],r14; nop.i	0x0; }
	{ addl	r14,9032,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000AEBA0; }

l40000000000AEA20:
	{ (p06) adds	r8,0x0,r0; ld4	r15,[r15]; nop.i	0x0; }

l40000000000AEA26:
	{ (p07) fwb; nop; break.b	0x80000 }
	{ Invalid; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	f0,3FFFFFFFFFD71B26; nop; (p48) nop.b	0xC403 }

l40000000000AEA50:
	{ adds	r15,0x20,r12; nop.m	0x0; adds	r14,0x20,r12; }
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x4,r15; adds	r15,0x10,r12; (p07) br.cond.dpnt.few	40000000000AEC10; }

l40000000000AEA80:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x3,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000AEC10; }

l40000000000AEAA0:
	{ cmp4.eq	p06,p07,0x0,r8; (p07) addl	r14,9012,r1; nop.i	0x0; }

l40000000000AEAAC:
	{ cmp4.eq.and	p00,p11,r1,r0; zxt4	r42,r17; break.i	0x1000 }

l40000000000AEAB6:
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ (p07) fwb; Invalid; nop }
	{ Invalid; nop; break.i	0x80000 }
	{ mf.a; nop; break.i	0x80000 }

l40000000000AEAF0:
	{ nop.m	0x0; adds	r15,0x10,r12; nop.i	0x0; }
	{ ld4	r8,[r15]; mov.i	ar.pfs,r36; mov.spnt	b0,r35,40000000000AEB00 }
	{ nop.m	0x0; adds	r12,0x30,r12; br.ret	b0; }

l40000000000AEB20:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,reset_parser; }
	{ adds	r1,0x38,r12; adds	r14,0x18,r12; addl	r39,21,r0; }
	{ ld8	r1,[r1]; ld8	r37,[r14]; nop.i	0x0; }
	{ nop.m	0x0; addl	r38,-4340,r1; nop.i	0x0; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,parse_and_execute; }
	{ adds	r1,0x38,r12; ld8	r1,[r1]; nop.i	0x0; }
	{ addl	r14,9124,r1; nop.m	0x0; nop.i	0x0; }
	{ st4	[r0],r14; nop.i	0x0; br.cond.sptk.few	40000000000AEAF0 }

l40000000000AEBA0:
	{ addl	r37,22740,r1; nop.m	0x0; addl	r38,1,r0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BD60; }
	{ adds	r15,0x20,r12; nop.m	0x0; adds	r1,0x38,r12; }
	{ ld4	r15,[r15]; ld8	r1,[r1]; nop.i	0x0; }
	{ nop.m	0x0; or	r14,r15,r8; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000AEA50 }

l40000000000AEC00:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000AEB20 }

l40000000000AEC10:
	{ addl	r14,9044,r1; nop.m	0x0; adds	r15,0x10,r12; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4	r14,[r14]; st4	[r14],r15; addl	r14,9124,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r0],r14; nop.i	0x0; br.cond.sptk.few	40000000000AEAF0; }
40000000000AEC60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000AEC70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; run_trap_cleanup: 40000000000AEC80
;;   Called from:
;;     40000000000F626C (in parse_and_execute_cleanup)
run_trap_cleanup proc
	{ addl	r14,19268,r1; nop.m	0x0; sxt4	r32,r32; }
	{ nop.m	0x0; shladd	r32,r32,0x2,r14; nop.i	0x0; }
	{ ld4	r14,[r32]; and	r14,0xFFFFFFFFFFFFFFCF,r14; nop.i	0x0; }
	{ st4	[r14],r32; nop.i	0x0; br.ret	b0; }

;; run_debug_trap: 40000000000AECC0
;;   Called from:
;;     40000000000AFBAC (in maybe_call_trap_handler)
run_debug_trap proc
	{ alloc	r36,ar.pfs,0x8,0x0,0x6; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ addl	r14,19268,r1; mov	r35,b3; adds	r37,0x0,r1; }
	{ nop.m	0x0; adds	r14,0x104,r14; nop.i	0x0; }
	{ ld4	r14,[r14]; and	r14,0x51,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x1,r14; (p07) br.cond.dpnt.few	40000000000AED40; }

l40000000000AED10:
	{ (p06) adds	r32,0x0,r0; nop.m	0x0; nop.i	0x0; }

l40000000000AED16:
	{ break.m	0x4000; Invalid; nop }

l40000000000AED20:
	{ adds	r8,0x0,r32; mov.i	ar.pfs,r36; mov.spnt	b0,r35,40000000000AED20 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000AED40:
	{ addl	r33,7436,r1; nop.m	0x0; addl	r38,1,r0; }
	{ nop.m	0x0; ld4	r34,[r33]; nop.i	0x0 }
	{ st4	[r0],r33; nop.m	0x0; br.call.sptk.many	b0,save_pipeline; }
	{ adds	r38,0x10,r12; nop.m	0x0; addl	r39,1,r0 }
	{ adds	r1,0x0,r37; nop.m	0x0; br.call.sptk.many	b0,save_pgrp_pipe; }
	{ adds	r1,0x0,r37; nop.i	0x0; br.call.sptk.many	b0,stop_making_children; }
	{ adds	r1,0x0,r37; addl	r38,65,r0; addl	r39,-4332,r1; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn40000000000AC6C0; }
	{ addl	r38,1,r0; adds	r32,0x0,r8; nop.i	0x0 }
	{ adds	r1,0x0,r37; st4	[r34],r33; br.call.sptk.many	b0,restore_pipeline; }
	{ adds	r1,0x0,r37; nop.i	0x0; br.call.sptk.many	b0,close_pgrp_pipe; }
	{ adds	r1,0x0,r37; adds	r38,0x10,r12; br.call.sptk.many	b0,restore_pgrp_pipe; }
	{ ld4	r38,[r33]; adds	r1,0x0,r37; addl	r39,1,r0; }
	{ cmp4.lt	p07,p06,0x0,r38; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000AEE40; }

l40000000000AEE20:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,give_terminal_to; }
	{ adds	r1,0x0,r37; nop.m	0x0; nop.i	0x0 }

l40000000000AEE40:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,notify_and_cleanup; }
	{ adds	r1,0x0,r37; addl	r14,6472,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000AED20; }

l40000000000AEE80:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2,r32; (p06) br.cond.dptk.few	40000000000AED20 }

l40000000000AEE90:
	{ addl	r14,9032,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.sptk.few	40000000000AED20 }

l40000000000AEEC0:
	{ addl	r14,9012,r1; addl	r38,22740,r1; addl	r39,1,r0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r32],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BBE0; }
	{ nop.m	0x0; break.f	0x0; nop.i	0x0; }

;; run_error_trap: 40000000000AEF00
;;   Called from:
;;     40000000000AEEFC (in run_debug_trap)
;;     40000000000AFB7C (in maybe_call_trap_handler)
run_error_trap proc
	{ alloc	r16,ar.pfs,0x2,0x0,0x2; nop.m	0x0; addl	r14,19268,r1; }
	{ nop.m	0x0; adds	r14,0x108,r14; nop.i	0x0; }
	{ ld4	r14,[r14]; and	r14,0x51,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x1,r14; (p06) br.ret	b0 }

l40000000000AEF40:
	{ addl	r33,-4324,r1; nop.m	0x0; addl	r32,66,r0; }
	{ nop.m	0x0; ld8	r33,[r33]; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000AC6C0; }
40000000000AEF70 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; run_return_trap: 40000000000AEF80
;;   Called from:
;;     40000000000F5D6C (in source_file)
run_return_trap proc
	{ alloc	r35,ar.pfs,0x7,0x0,0x5; addl	r14,19268,r1; mov	r34,b2 }
	{ adds	r36,0x0,r1; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ adds	r14,0x10C,r14; nop.m	0x0; mov.spnt	b0,r34,40000000000AEFA0; }
	{ ld4	r14,[r14]; and	r14,0x51,r14; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x1,r14; (p07) br.cond.dpnt.few	40000000000AEFD0; br.ret	b0 }

l40000000000AEFCC:
	{ nop; (p04) cmp.lt	p53,p18,r64,r17; (p04) nop }

l40000000000AEFD0:
	{ addl	r32,9044,r1; addl	r38,-4316,r1; addl	r37,67,r0; }
	{ nop.m	0x0; ld8	r38,[r38]; nop.i	0x0; }
	{ ld4	r33,[r32]; nop.i	0x0; br.call.sptk.many	b0,fn40000000000AC6C0; }
	{ adds	r1,0x0,r36; st4	[r33],r32; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000AF010; br.ret	b0; }
40000000000AF020 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000AF030 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; run_interrupt_trap: 40000000000AF040
;;   Called from:
;;     40000000000AF58C (in run_pending_traps)
;;     40000000000AFBDC (in maybe_call_trap_handler)
;;     40000000000B45CC (in throw_to_top_level)
;;     40000000000B505C (in termsig_handler)
run_interrupt_trap proc
	{ alloc	r16,ar.pfs,0x2,0x0,0x2; nop.m	0x0; addl	r33,-4308,r1; }
	{ addl	r32,2,r0; ld8	r33,[r33]; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000AC6C0; }
40000000000AF070 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; run_pending_traps: 40000000000AF080
;;   Called from:
;;     400000000002357C (in parse_command)
;;     4000000000053D5C (in execute_command_internal)
;;     400000000005448C (in execute_command_internal)
;;     40000000000AF7BC (in trap_handler)
run_pending_traps proc
	{ alloc	r47,ar.pfs,0x15,0x0,0x12; adds	r12,0xFFFFFFFFFFFFFF00,r12; nop.b	0x0 }
	{ addl	r14,7624,r1; mov	r49,LC; adds	r48,0x0,r1; }
	{ ld4	r15,[r14]; nop.m	0x0; mov	r46,b6; }
	{ cmp4.eq	p06,p07,0x0,r15; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000AF0F0; }

l40000000000AF0C0:
	{ nop.m	0x0; mov.i	ar.pfs,r47; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r49; mov.spnt	b0,r46,40000000000AF0D0 }
	{ nop.m	0x0; adds	r12,0x100,r12; br.ret	b0 }

l40000000000AF0F0:
	{ addl	r42,9044,r1; nop.m	0x0; addl	r35,7540,r1 }
	{ st4	[r0],r14; nop.m	0x0; addl	r33,1,r0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4	r44,[r42]; nop.i	0x0; br.call.sptk.many	b0,save_pipestatus_array; }
	{ adds	r1,0x0,r48; adds	r45,0x0,r8; mov.i	LC,0x3F; }
	{ addl	r14,6028,r1; addl	r40,19268,r1; addl	r37,-9668,r1 }
	{ addl	r41,7684,r1; ld8	r32,[r14]; addl	r14,6036,r1 }
	{ nop.m	0x0; ld8	r34,[r14]; adds	r40,0x44,r40 }
	{ adds	r43,0x40,r32; ld8	r37,[r37]; nop.i	0x0; }
	{ adds	r39,0x80,r34; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000AF1A0:
	{ nop.m	0x0; ld4	r14,[r32]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000AF220; }

l40000000000AF1C0:
	{ nop.m	0x0; adds	r33,0x1,r33; adds	r32,0x4,r32 }
	{ nop.m	0x0; adds	r34,0x8,r34; br.cloop.sptk.few	40000000000AF1A0 }

l40000000000AF1E0:
	{ adds	r50,0x0,r45; nop.i	0x0; br.call.sptk.many	b0,restore_pipestatus_array; }
	{ adds	r1,0x0,r48; st4	[r44],r42; mov.i	ar.pfs,r47; }
	{ nop.m	0x0; mov.i	LC,r49; mov.spnt	b0,r46,40000000000AF200 }
	{ nop.m	0x0; adds	r12,0x100,r12; br.ret	b0; }

l40000000000AF220:
	{ adds	r50,0x90,r12; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r48; adds	r50,0x10,r12; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r48; nop.m	0x0; adds	r50,0x90,r12 }
	{ adds	r51,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B400; }
	{ adds	r1,0x0,r48; adds	r50,0x0,r0; nop.i	0x0 }
	{ adds	r51,0x90,r12; adds	r52,0x10,r12; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ cmp4.eq	p07,p06,0x2,r33; adds	r1,0x0,r48; (p07) br.cond.dpnt.few	40000000000AF580; }

l40000000000AF290:
	{ cmp4.eq	p07,p06,0x11,r33; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000AF400; }

l40000000000AF2A0:
	{ nop.m	0x0; ld8	r14,[r34]; nop.i	0x0; }
	{ cmp.ltu	p07,p06,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000AF460; }

l40000000000AF2C0:
	{ nop.m	0x0; cmp.eq	p07,p06,r37,r14; (p07) br.cond.dpnt.few	40000000000AF460 }

l40000000000AF2D0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,save_token_state; }
	{ adds	r1,0x0,r48; nop.m	0x0; adds	r36,0x0,r8 }
	{ ld8	r38,[r35]; st8	[r0],r35; nop.i	0x0; }
	{ ld8	r50,[r34]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r48; adds	r50,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r48; nop.m	0x0; adds	r50,0x0,r8 }
	{ ld8	r51,[r34]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r48; addl	r52,21,r0; adds	r50,0x0,r8; }
	{ nop.m	0x0; addl	r51,-4284,r1; nop.i	0x0; }
	{ ld8	r51,[r51]; nop.i	0x0; br.call.sptk.many	b0,parse_and_execute; }
	{ adds	r1,0x0,r48; adds	r50,0x0,r36; br.call.sptk.many	b0,restore_token_state; }
	{ adds	r1,0x0,r48; adds	r50,0x0,r36; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r48; st8	[r38],r35; nop.i	0x0 }

l40000000000AF3A0:
	{ nop.m	0x0; st4	[r0],r32; addl	r50,2,r0 }
	{ adds	r51,0x10,r12; adds	r52,0x0,r0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r48; nop.m	0x0; nop.i	0x0 }

l40000000000AF3D0:
	{ nop.m	0x0; adds	r33,0x1,r33; adds	r32,0x4,r32 }
	{ nop.m	0x0; adds	r34,0x8,r34; br.cloop.sptk.few	40000000000AF1A0 }

l40000000000AF3F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000AF1E0 }

l40000000000AF400:
	{ nop.m	0x0; ld8	r14,[r39]; nop.i	0x0; }
	{ cmp.eq	p06,p07,r37,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000AF460; }

l40000000000AF420:
	{ nop.m	0x0; ld4	r14,[r40]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x4; (p07) br.cond.dpnt.few	40000000000AF5D0; }

l40000000000AF440:
	{ nop.m	0x0; ld8	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp.ltu	p07,p06,0x1,r14; (p07) br.cond.dptk.few	40000000000AF2D0; }

l40000000000AF460:
	{ addl	r51,-4300,r1; addl	r52,5,r0; adds	r50,0x0,r0; }
	{ ld8	r51,[r51]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r48; adds	r50,0x0,r8; nop.i	0x0 }
	{ adds	r51,0x0,r33; ld8	r52,[r34]; br.call.sptk.many	b0,internal_warning; }
	{ ld8	r14,[r34]; nop.m	0x0; adds	r1,0x0,r48; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000AF3A0 }

l40000000000AF4C0:
	{ addl	r51,-4292,r1; addl	r52,5,r0; adds	r50,0x0,r0; }
	{ ld8	r51,[r51]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r48; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r50,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,signal_name; }
	{ adds	r50,0x0,r36; adds	r51,0x0,r33; nop.i	0x0 }
	{ adds	r52,0x0,r8; adds	r1,0x0,r48; br.call.sptk.many	b0,internal_warning; }
	{ adds	r1,0x0,r48; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B1A0; }
	{ adds	r1,0x0,r48; nop.m	0x0; adds	r51,0x0,r33 }
	{ adds	r50,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B520; }
	{ adds	r1,0x0,r48; st4	[r0],r32; addl	r50,2,r0 }
	{ adds	r51,0x10,r12; adds	r52,0x0,r0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ nop.m	0x0; adds	r1,0x0,r48; br.cond.sptk.few	40000000000AF3D0 }

l40000000000AF580:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,run_interrupt_trap; }
	{ adds	r1,0x0,r48; st4.rel	[r0],r41; addl	r50,2,r0 }
	{ st4	[r0],r32; adds	r51,0x10,r12; adds	r52,0x0,r0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ nop.m	0x0; adds	r1,0x0,r48; br.cond.sptk.few	40000000000AF3D0 }

l40000000000AF5D0:
	{ ld4	r50,[r43]; nop.i	0x0; br.call.sptk.many	b0,run_sigchld_trap; }
	{ adds	r1,0x0,r48; st4	[r0],r32; addl	r50,2,r0 }
	{ adds	r51,0x10,r12; adds	r52,0x0,r0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ nop.m	0x0; adds	r1,0x0,r48; br.cond.sptk.few	40000000000AF3D0; }
40000000000AF610 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000AF620 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000AF630 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; trap_handler: 40000000000AF640
;;   Called from:
;;     400000000007E2CC (in fn400000000007D580)
;;     40000000000AFAEC (in maybe_call_trap_handler)
trap_handler proc
	{ alloc	r37,ar.pfs,0xA,0x0,0x7; addl	r15,19268,r1; mov	r36,b4 }
	{ adds	r38,0x0,r1; sxt4	r14,r32; shladd	r33,r14,0x2,r0 }
	{ nop.m	0x0; add	r15,r15,r33; nop.i	0x0; }
	{ ld4	r15,[r15]; nop.m	0x0; tbit.z	p06,p07,r15,0x0 }
	{ addl	r15,24316,r1; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000AF7E0; }

l40000000000AF690:
	{ cmp4.lt	p06,p07,0x40,r32; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000AF800; }

l40000000000AF6A0:
	{ nop.m	0x0; shladd	r14,r14,0x3,r15; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000AF800; }

l40000000000AF6D0:
	{ cmp.eq	p07,p06,0x1,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000AF800; }

l40000000000AF6E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ adds	r1,0x0,r38; nop.m	0x0; addl	r17,1,r0 }
	{ ld4	r35,[r8]; adds	r34,0x0,r8; addl	r14,24860,r1 }
	{ addl	r16,7624,r1; nop.m	0x0; nop.i	0x0 }
	{ st4	[r17],r16; add	r33,r14,r33; addl	r14,7672,r1; }
	{ nop.m	0x0; ld4	r15,[r14]; nop.i	0x0 }
	{ ld4	r14,[r33]; adds	r14,0x1,r14; cmp4.eq	p06,p07,0x0,r15; }
	{ st4	[r14],r33; nop.i	0x0; (p06) br.cond.dptk.few	40000000000AF7D0 }

l40000000000AF760:
	{ addl	r14,8388,r1; nop.m	0x0; addl	r15,-9804,r1; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000AF7B0; }

l40000000000AF790:
	{ nop.m	0x0; ld8	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r15,r14; (p07) br.cond.spnt.few	40000000000AF860 }

l40000000000AF7B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,run_pending_traps; }
	{ adds	r1,0x0,r38; nop.m	0x0; nop.i	0x0 }

l40000000000AF7D0:
	{ st4	[r35],r34; nop.m	0x0; nop.i	0x0 }

l40000000000AF7E0:
	{ nop.m	0x0; mov.i	ar.pfs,r37; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000AF7F0; br.ret	b0 }

l40000000000AF800:
	{ addl	r40,-4276,r1; addl	r41,5,r0; adds	r39,0x0,r0; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r38; nop.m	0x0; adds	r39,0x0,r8 }
	{ adds	r40,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,programming_error; }
	{ adds	r1,0x0,r38; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000AF850; br.ret	b0 }

l40000000000AF860:
	{ addl	r14,9132,r1; addl	r39,25956,r1; addl	r40,1,r0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r32],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BBE0; }
	{ nop.m	0x0; break.f	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

;; free_trap_strings: 40000000000AF8C0
;;   Called from:
;;     40000000000AF8BC (in trap_handler)
;;     400000000010E48C (in trap_builtin)
;;     400000000010E48C (in trap_builtin)
;;     400000000010E48C (in trap_builtin)
free_trap_strings proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x6; addl	r32,19268,r1; mov	r34,b2 }
	{ nop.m	0x0; adds	r36,0x0,r1; nop.i	0x0; }
	{ adds	r33,0x0,r0; nop.m	0x0; mov	r37,LC }
	{ nop.m	0x0; nop.m	0x0; mov.i	LC,0x43; }

l40000000000AF900:
	{ adds	r38,0x0,r33; nop.m	0x0; adds	r39,0x0,r0 }
	{ adds	r33,0x1,r33; nop.m	0x0; br.call.sptk.many	b0,fn40000000000AD180; }
	{ ld4	r14,[r32]; adds	r1,0x0,r36; and	r14,0xFFFFFFFFFFFFFFFE,r14; }
	{ st4	[r32],r4,4; nop.i	0x0; br.cloop.sptk.few	40000000000AF900 }

l40000000000AF940:
	{ addl	r14,24316,r1; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; nop.m	0x0; mov.i	LC,r37; }
	{ adds	r17,0x218,r14; adds	r16,0x210,r14; nop.b	0x0 }
	{ adds	r15,0x208,r14; nop.m	0x0; mov.spnt	b0,r34,40000000000AF970; }
	{ st8	[r0],r14; st8	[r0],r17; nop.i	0x0; }
	{ nop.m	0x0; st8	[r0],r16; nop.i	0x0 }
	{ st8	[r0],r15; nop.m	0x0; br.ret	b0; }
40000000000AF9B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; reset_signal_handlers: 40000000000AF9C0
;;   Called from:
;;     400000000009486C (in command_substitute)
reset_signal_handlers proc
	{ alloc	r16,ar.pfs,0x1,0x0,0x1; nop.m	0x0; addl	r32,-4388,r1; }
	{ nop.m	0x0; ld8	r32,[r32]; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x1,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000ACF00; }
40000000000AF9F0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; restore_original_signals: 40000000000AFA00
;;   Called from:
;;     40000000000A521C (in fn40000000000A1400)
;;     40000000000F803C (in exec_builtin)
;;     40000000000F845C (in exec_builtin)
restore_original_signals proc
	{ alloc	r16,ar.pfs,0x1,0x0,0x1; nop.m	0x0; addl	r32,-4364,r1; }
	{ nop.m	0x0; ld8	r32,[r32]; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x1,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000ACF00; }
40000000000AFA30 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; maybe_call_trap_handler: 40000000000AFA40
;;   Called from:
;;     400000000007E57C (in fn400000000007D580)
maybe_call_trap_handler proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; addl	r14,19268,r1; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; sxt4	r15,r32; }
	{ nop.m	0x0; shladd	r14,r15,0x2,r14; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x0; (p06) br.cond.dpnt.few	40000000000AFB10; }

l40000000000AFA90:
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x6; (p06) br.cond.dpnt.few	40000000000AFB10; }

l40000000000AFAA0:
	{ cmp4.eq	p06,p07,0x2,r32; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000AFBD0; }

l40000000000AFAB0:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x2,r32; (p07) br.cond.dptk.few	40000000000AFB30; }

l40000000000AFAC0:
	{ cmp4.eq	p06,p07,0x41,r32; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000AFBA0; }

l40000000000AFAD0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x42,r32; (p06) br.cond.dpnt.few	40000000000AFB70 }

l40000000000AFAE0:
	{ adds	r36,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,trap_handler; }
	{ addl	r8,1,r0; adds	r1,0x0,r35; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000AFB00; br.ret	b0 }

l40000000000AFB10:
	{ adds	r8,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000AFB20; br.ret	b0 }

l40000000000AFB30:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r32; (p07) br.cond.dptk.few	40000000000AFAE0; }

l40000000000AFB40:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,run_exit_trap; }
	{ addl	r8,1,r0; adds	r1,0x0,r35; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000AFB60; br.ret	b0; }

l40000000000AFB70:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,run_error_trap; }
	{ addl	r8,1,r0; adds	r1,0x0,r35; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000AFB90; br.ret	b0; }

l40000000000AFBA0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,run_debug_trap; }
	{ addl	r8,1,r0; adds	r1,0x0,r35; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000AFBC0; br.ret	b0; }

l40000000000AFBD0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,run_interrupt_trap; }
	{ addl	r8,1,r0; adds	r1,0x0,r35; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000AFBF0; br.ret	b0; }

;; signal_is_trapped: 40000000000AFC00
;;   Called from:
;;     400000000002236C (in exit_shell)
;;     4000000000079F4C (in fn4000000000079240)
;;     400000000007E1DC (in fn400000000007D580)
;;     400000000007E52C (in fn400000000007D580)
;;     400000000007E72C (in fn400000000007D580)
;;     40000000000803AC (in wait_for)
;;     4000000000080CFC (in wait_for)
;;     40000000000B3FEC (in initialize_terminating_signals)
;;     40000000000B428C (in reset_terminating_signals)
;;     40000000000B48AC (in throw_to_top_level)
;;     40000000000B48AC (in throw_to_top_level)
;;     40000000000B4FEC (in termsig_handler)
;;     400000000010CFCC (in source_builtin)
;;     400000000010D31C (in source_builtin)
signal_is_trapped proc
	{ addl	r14,19268,r1; nop.m	0x0; sxt4	r32,r32; }
	{ nop.m	0x0; shladd	r32,r32,0x2,r14; nop.i	0x0; }
	{ nop.m	0x0; ld4	r8,[r32]; nop.i	0x0; }
	{ nop.m	0x0; and	r8,0x1,r8; br.ret	b0; }

;; signal_is_special: 40000000000AFC40
;;   Called from:
;;     40000000000B42EC (in reset_terminating_signals)
signal_is_special proc
	{ addl	r14,19268,r1; nop.m	0x0; sxt4	r32,r32; }
	{ nop.m	0x0; shladd	r32,r32,0x2,r14; nop.i	0x0; }
	{ nop.m	0x0; ld4	r8,[r32]; nop.i	0x0; }
	{ nop.m	0x0; and	r8,0x4,r8; br.ret	b0; }

;; signal_is_ignored: 40000000000AFC80
;;   Called from:
;;     40000000000240AC (in reader_loop)
;;     400000000010D18C (in source_builtin)
signal_is_ignored proc
	{ addl	r14,19268,r1; nop.m	0x0; sxt4	r32,r32; }
	{ nop.m	0x0; shladd	r32,r32,0x2,r14; nop.i	0x0; }
	{ nop.m	0x0; ld4	r8,[r32]; nop.i	0x0; }
	{ nop.m	0x0; and	r8,0x40,r8; br.ret	b0; }

;; signal_is_hard_ignored: 40000000000AFCC0
;;   Called from:
;;     400000000010DC1C (in fn400000000010DBC0)
;;     400000000010DF0C (in fn400000000010DBC0)
;;     400000000010DF3C (in fn400000000010DBC0)
signal_is_hard_ignored proc
	{ addl	r14,19268,r1; nop.m	0x0; sxt4	r32,r32; }
	{ nop.m	0x0; shladd	r32,r32,0x2,r14; nop.i	0x0; }
	{ nop.m	0x0; ld4	r8,[r32]; nop.i	0x0; }
	{ nop.m	0x0; and	r8,0x2,r8; br.ret	b0; }

;; set_signal_ignored: 40000000000AFD00
;;   Called from:
;;     400000000005016C (in setup_async_signals)
;;     400000000005019C (in setup_async_signals)
;;     40000000000B418C (in initialize_terminating_signals)
set_signal_ignored proc
	{ addl	r14,19268,r1; sxt4	r32,r32; addl	r16,23796,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ shladd	r14,r32,0x2,r14; shladd	r32,r32,0x3,r16; addl	r16,1,r0; }
	{ ld4	r15,[r14]; st8	[r16],r32; nop.i	0x0; }
	{ nop.m	0x0; or	r15,0x2,r15; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.ret	b0; }
40000000000AFD60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000AFD70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; signal_in_progress: 40000000000AFD80
signal_in_progress proc
	{ addl	r14,19268,r1; nop.m	0x0; sxt4	r32,r32; }
	{ nop.m	0x0; shladd	r32,r32,0x2,r14; nop.i	0x0; }
	{ nop.m	0x0; ld4	r8,[r32]; nop.i	0x0; }
	{ nop.m	0x0; and	r8,0x10,r8; br.ret	b0; }

;; buffered_ungetchar: 40000000000AFDC0
buffered_ungetchar proc
	{ addl	r14,7636,r1; nop.m	0x0; adds	r8,0x0,r32 }
	{ cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r32; nop.m	0x0; (p06) br.ret	b0; }

l40000000000AFDE0:
	{ ld8	r15,[r14]; nop.m	0x0; addl	r14,22532,r1; }
	{ nop.m	0x0; adds	r14,0x10,r14; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r14,r14; shladd	r14,r14,0x3,r15; }
	{ ld8	r14,[r14]; adds	r17,0x8,r14; adds	r14,0x28,r14; }
	{ ld8	r15,[r14]; cmp.eq	p06,p07,0x0,r15; adds	r16,0xFFFFFFFFFFFFFFFF,r15; }
	{ (p07) ld8	r15,[r17]; (p07) st8	[r16],r14; (p06) addl	r8,-1,r0; }

l40000000000AFE46:
	{ chk.a.nc	r16,3FFFFFFFFF97BF26; (p04) nop; cmp.lt	p00,p00,r0,r32; }

l40000000000AFE4C:
	{ (p63) nop; mov	pr,r32,0x0; (p50) epc; }

l40000000000AFE50:
	{ nop.m	0x0; (p07) add	r16,r15,r16; nop.i	0x0; }

l40000000000AFE5C:
	{ Invalid; Invalid; add	r0,r32,r0 }

l40000000000AFE66:
	{ break.m	0x4000; (p34) nop; break.i	0x80000 }
40000000000AFE70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; buffered_getchar: 40000000000AFE80
buffered_getchar proc
	{ alloc	r41,ar.pfs,0xE,0x0,0xB; addl	r34,7676,r1; mov	r40,b0 }
	{ adds	r42,0x0,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4.acq	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000AFF80 }

l40000000000AFEC0:
	{ addl	r14,7636,r1; nop.m	0x0; mov.i	ar.pfs,r41; }
	{ ld8	r15,[r14]; addl	r14,22532,r1; mov.spnt	b0,r40,40000000000AFED0; }
	{ nop.m	0x0; adds	r14,0x10,r14; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r14,r14; shladd	r14,r14,0x3,r15; }
	{ ld8	r32,[r14]; adds	r33,0x28,r32; adds	r35,0x18,r32; }
	{ ld8	r14,[r33]; ld8	r15,[r35]; nop.i	0x0; }
	{ cmp.eq	p06,p07,r15,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000AFFA0; }

l40000000000AFF40:
	{ cmp.eq	p07,p06,0x0,r15; adds	r15,0x1,r14; (p07) br.cond.dpnt.few	40000000000AFFA0; }

l40000000000AFF50:
	{ adds	r32,0x8,r32; ld8	r16,[r32]; nop.i	0x0; }
	{ add	r14,r16,r14; nop.i	0x0; nop.i	0x0 }
	{ ld1	r8,[r14]; st8	[r15],r33; br.ret	b0; }

l40000000000AFF80:
	{ ld4.acq	r43,[r34]; nop.i	0x0; br.call.sptk.many	b0,termsig_handler; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	40000000000AFEC0 }

l40000000000AFFA0:
	{ ld4.acq	r14,[r34]; nop.m	0x0; adds	r37,0x20,r32; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B0070; }

l40000000000AFFC0:
	{ ld4	r14,[r37]; and	r14,0x14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x10,r14; (p07) br.cond.dpnt.few	40000000000B00C0 }

l40000000000AFFE0:
	{ nop.m	0x0; adds	r34,0x8,r32; adds	r14,0x10,r32 }
	{ ld4	r43,[r32]; ld8	r44,[r34]; nop.i	0x0 }
	{ ld8	r45,[r14]; nop.m	0x0; br.call.sptk.many	b0,zread; }
	{ adds	r36,0x0,r8; nop.m	0x0; adds	r1,0x0,r42; }
	{ nop.m	0x0; cmp.lt	p06,p07,0x0,r36; (p07) br.cond.dpnt.few	40000000000B0200 }

l40000000000B0030:
	{ ld8	r14,[r34]; st8	[r0],r33; nop.b	0x0 }
	{ st8	[r36],r35; mov.i	ar.pfs,r41; mov.spnt	b0,r40,40000000000B0040; }
	{ ld1	r8,[r14]; nop.m	0x0; addl	r14,1,r0; }
	{ st8	[r14],r33; nop.i	0x0; br.ret	b0 }

l40000000000B0070:
	{ addl	r14,7676,r1; nop.m	0x0; adds	r37,0x20,r32; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4.acq	r43,[r14]; nop.i	0x0; br.call.sptk.many	b0,termsig_handler; }
	{ ld4	r14,[r37]; adds	r1,0x0,r42; and	r14,0x14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x10,r14; (p06) br.cond.dptk.few	40000000000AFFE0 }

l40000000000B00C0:
	{ adds	r34,0x0,r32; nop.m	0x0; adds	r44,0x0,r0 }
	{ addl	r45,1,r0; nop.m	0x0; adds	r38,0x10,r32; }
	{ ld4	r43,[r34],8; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AA20; }
	{ adds	r1,0x0,r42; nop.m	0x0; adds	r39,0x0,r8 }
	{ ld4	r43,[r32]; ld8	r44,[r34]; nop.i	0x0; }
	{ ld8	r45,[r38]; nop.i	0x0; br.call.sptk.many	b0,zread; }
	{ cmp.lt	p07,p06,0x0,r8; adds	r36,0x0,r8; adds	r1,0x0,r42 }
	{ adds	r44,0x0,r0; addl	r45,1,r0; (p06) br.cond.dpnt.few	40000000000B0200; }

l40000000000B0140:
	{ ld4	r43,[r32]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AA20; }
	{ sub	r8,r8,r39; nop.m	0x0; adds	r1,0x0,r42; }
	{ nop.m	0x0; cmp.lt	p07,p06,r36,r8; (p06) br.cond.dptk.few	40000000000B0030 }

l40000000000B0170:
	{ ld4	r43,[r32]; nop.m	0x0; adds	r44,0x0,r39 }
	{ adds	r45,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AA20; }
	{ ld4	r14,[r37]; addl	r15,1,r0; adds	r1,0x0,r42 }
	{ addl	r45,1,r0; ld4	r43,[r32]; nop.i	0x0; }
	{ nop.m	0x0; or	r14,0x4,r14; nop.i	0x0 }
	{ st8	[r15],r38; ld8	r44,[r34]; nop.i	0x0; }
	{ st4	[r14],r37; nop.i	0x0; br.call.sptk.many	b0,zread; }
	{ adds	r36,0x0,r8; nop.m	0x0; adds	r1,0x0,r42; }
	{ nop.m	0x0; cmp.lt	p06,p07,0x0,r36; (p06) br.cond.dptk.few	40000000000B0030; }

l40000000000B0200:
	{ ld8	r14,[r34]; st8	[r0],r35; nop.b	0x0 }
	{ cmp.eq	p07,p06,0x0,r36; addl	r8,-1,r0; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.spnt	b0,r40,40000000000B0220; nop.i	0x0; }
	{ st1	[r0],r14; ld4	r14,[r37]; nop.i	0x0; }
	{ (p07) or	r14,0x1,r14; (p06) or	r14,0x2,r14; nop.i	0x0; }

l40000000000B0246:
	{ Invalid; nop; nop; }

l40000000000B024C:
	{ Invalid; Invalid; add	r0,r32,r0 }
	{ nop; break.m	0x1000; break.i	0x1000 }
40000000000B0260 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B0270 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000B0280: 40000000000B0280
;;   Called from:
;;     40000000000B0B0C (in fd_to_buffered_stream)
;;     40000000000B0FCC (in duplicate_buffered_stream)
fn40000000000B0280 proc
	{ alloc	r37,ar.pfs,0x9,0x0,0x7; adds	r32,0x14,r32; mov	r36,b4 }
	{ addl	r34,7644,r1; addl	r35,7636,r1; adds	r38,0x0,r1; }
	{ nop.m	0x0; sxt4	r40,r32; nop.i	0x0 }
	{ ld4	r33,[r34]; st4	[r32],r34; nop.i	0x0; }
	{ ld8	r39,[r35]; shladd	r40,r40,0x3,r0; br.call.sptk.many	b0,xrealloc; }
	{ ld4	r16,[r34]; sxt4	r15,r33; adds	r1,0x0,r38 }
	{ st8	[r8],r35; sub	r17,r16,r33,0x1; shladd	r14,r15,0x3,r8 }
	{ cmp4.lt	p06,p07,r33,r16; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000B0340; }

l40000000000B0300:
	{ addp4	r17,r17,r0; add	r15,r15,r17; nop.i	0x0; }
	{ shladd	r15,r15,0x3,r8; nop.i	0x0; adds	r15,0x8,r15; }

l40000000000B0320:
	{ nop.m	0x0; st8	[r14],r8,8; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r15,r14; (p06) br.cond.dptk.few	40000000000B0320 }

l40000000000B0340:
	{ nop.m	0x0; mov.i	ar.pfs,r37; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000B0350; br.ret	b0; }
40000000000B0360 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B0370 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; getc_with_restart: 40000000000B0380
getc_with_restart proc
	{ alloc	r39,ar.pfs,0xC,0x0,0x9; addl	r34,7676,r1; mov	r38,b6 }
	{ adds	r40,0x0,r1; addl	r37,7628,r1; addl	r35,7632,r1; }
	{ nop.m	0x0; adds	r36,0x0,r34; nop.i	0x0; }
	{ nop.m	0x0; ld4.acq	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000B0630 }

l40000000000B03D0:
	{ ld4	r15,[r35]; ld4	r14,[r37]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,r15,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B04A0; }

l40000000000B03F0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	40000000000B04A0; }

l40000000000B0400:
	{ (p07) adds	r15,0x1,r14; nop.m	0x0; nop.i	0x0; }

l40000000000B0406:
	{ break.m	0x4000; nop; nop }
	{ Invalid; (p07) nop; break.b	0x80000 }
	{ Invalid; nop; nop }
	{ break.m	0x4000; mov	pr,0x4000; break.i	0x80000 }

l40000000000B0440:
	{ nop.m	0x0; mov.i	ar.pfs,r39; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000B0450; br.ret	b0; }

l40000000000B0460:
	{ adds	r41,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BBC0; }
	{ adds	r1,0x0,r40; adds	r41,0x0,r8; br.call.sptk.many	b0,sh_unset_nodelay_mode; }
	{ adds	r1,0x0,r40; cmp4.lt	p07,p06,r8,r0; (p07) br.cond.spnt.few	40000000000B0650; }

l40000000000B0490:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000B04A0:
	{ ld4.acq	r14,[r34]; nop.m	0x0; adds	r41,0x0,r32; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B0580; }

l40000000000B04C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BBC0; }
	{ adds	r1,0x0,r40; adds	r41,0x0,r8; addl	r43,128,r0; }
	{ nop.m	0x0; addl	r42,19540,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A600; }
	{ adds	r33,0x0,r8; nop.m	0x0; adds	r1,0x0,r40 }
	{ st4	[r8],r35; cmp4.lt	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	40000000000B05F0 }

l40000000000B0520:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ ld4	r14,[r8]; adds	r1,0x0,r40; cmp4.eq	p08,p09,0x0,r33; }
	{ cmp4.eq	p07,p06,0xB,r14; (p07) br.cond.dpnt.few	40000000000B0460; (p08) br.cond.dpnt.few	40000000000B0560; }

l40000000000B054C:
	{ (p01) invala; cmp.lt	p00,p00,r32,r0; mov	pr,r99,0xE682 }

l40000000000B0550:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x4,r14; (p06) br.cond.dptk.few	40000000000B04A0 }

l40000000000B0560:
	{ addl	r8,-1,r0; st4	[r0],r37; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000B0570; br.ret	b0; }

l40000000000B0580:
	{ ld4.acq	r41,[r36]; nop.i	0x0; br.call.sptk.many	b0,termsig_handler; }
	{ adds	r1,0x0,r40; adds	r41,0x0,r32; br.call.sptk.many	b0,fn400000000001BBC0; }
	{ adds	r1,0x0,r40; adds	r41,0x0,r8; addl	r43,128,r0; }
	{ nop.m	0x0; addl	r42,19540,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A600; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r33,0x0,r8 }
	{ st4	[r8],r35; cmp4.lt	p06,p07,0x0,r8; (p07) br.cond.dptk.few	40000000000B0520 }

l40000000000B05F0:
	{ addl	r15,1,r0; nop.m	0x0; adds	r14,0x0,r0; }
	{ st4	[r15],r37; addl	r15,19540,r1; sxt4	r14,r14; }
	{ nop.m	0x0; add	r14,r15,r14; nop.i	0x0; }
	{ ld1	r8,[r14]; nop.i	0x0; br.cond.sptk.few	40000000000B0440 }

l40000000000B0630:
	{ ld4.acq	r41,[r34]; nop.i	0x0; br.call.sptk.many	b0,termsig_handler; }
	{ nop.m	0x0; adds	r1,0x0,r40; br.cond.sptk.few	40000000000B03D0; }

l40000000000B0650:
	{ addl	r42,124,r1; addl	r43,5,r0; adds	r41,0x0,r0; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r33,0x0,r8 }
	{ adds	r41,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BBC0; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r42,0x0,r8 }
	{ adds	r41,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,sys_error; }
	{ addl	r8,-1,r0; adds	r1,0x0,r40; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000B06C0; br.ret	b0; }
40000000000B06D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B06E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B06F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; ungetc_with_restart: 40000000000B0700
ungetc_with_restart proc
	{ addl	r15,7628,r1; cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r32; adds	r8,0x0,r32; }
	{ ld4	r14,[r15]; nop.m	0x0; (p07) addl	r17,19540,r1; }

l40000000000B0720:
	{ adds	r16,0xFFFFFFFFFFFFFFFF,r14; cmp4.eq	p08,p09,0x0,r14; (p08) br.cond.dpnt.few	40000000000B0770; }

l40000000000B0730:
	{ nop.m	0x0; sxt4	r14,r16; nop.i	0x0 }
	{ nop.m	0x0; (p07) st4	[r16],r15; nop.i	0x0; }

l40000000000B074C:
	{ nop; cmp4.eq.and	p00,p32,r32,r0; zxt1	r68,r0 }

l40000000000B075C:
	{ Invalid; Invalid; add	r0,r32,r0 }

l40000000000B0766:
	{ break.m	0x4000; (p34) nop; break.i	0x80000 }

l40000000000B0770:
	{ nop.m	0x0; addl	r8,-1,r0; br.ret	b0; }

;; set_bash_input_fd: 40000000000B0780
set_bash_input_fd proc
	{ addl	r14,22532,r1; nop.m	0x0; nop.i	0x0; }
	{ ld4	r15,[r14]; cmp4.eq	p07,p06,0x4,r15; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r14,0x10,r14; nop.i	0x0; }

l40000000000B07AC:
	{ Invalid; cmp.lt.unc	p08,p08,r3,r100; (p01) mov	pr,r64,0x9078 }

l40000000000B07B6:
	{ (p07) chk.a.clr	f112,3FFFFFFFFF2C97C6; nop; break.i	0x80000 }

l40000000000B07C0:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; (p07) addl	r14,5636,r1; nop.i	0x0; }

l40000000000B07DC:
	{ nop; break.i	0x1000; break.i	0x1000 }
	{ Invalid; Invalid; break.i	0x1000 }

l40000000000B07F6:
	{ break.m	0x4000; nop; break.i	0x80000 }

l40000000000B0800:
	{ nop.m	0x0; adds	r8,0x0,r0; br.ret	b0; }

l40000000000B0802:
	{ Invalid; nop; Invalid }
40000000000B0810 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B0820 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B0830 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fd_is_bash_input: 40000000000B0840
;;   Called from:
;;     400000000010508C (in read_builtin)
fd_is_bash_input proc
	{ addl	r14,22532,r1; nop.m	0x0; adds	r8,0x0,r0; }
	{ nop.m	0x0; ld4	r15,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x4,r15; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B08E0; }

l40000000000B0870:
	{ addl	r14,6512,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.ret	b0 }

l40000000000B08A0:
	{ addl	r14,5636,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r32,r14; (p06) br.ret	b0; }

l40000000000B08D0:
	{ nop.m	0x0; addl	r8,1,r0; br.ret	b0 }

l40000000000B08E0:
	{ adds	r14,0x10,r14; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,r32,r14; addl	r14,6512,r1; (p06) br.cond.dpnt.few	40000000000B08D0; }

l40000000000B0900:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.ret	b0 }

l40000000000B0920:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000B08A0; }
40000000000B0930 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fd_to_buffered_stream: 40000000000B0940
;;   Called from:
;;     40000000000B0C6C (in open_buffered_stream)
;;     40000000000B108C (in duplicate_buffered_stream)
;;     40000000000B108C (in duplicate_buffered_stream)
;;     40000000000B175C (in save_bash_input)
;;     40000000000B19EC (in with_input_from_buffered_stream)
fd_to_buffered_stream proc
	{ alloc	r37,ar.pfs,0xA,0x0,0x7; adds	r12,0xFFFFFFFFFFFFFF70,r12; nop.b	0x0 }
	{ adds	r38,0x0,r1; mov	r36,b4; adds	r40,0x0,r32; }
	{ adds	r41,0x10,r12; addl	r39,1,r0; br.call.sptk.many	b0,fn400000000001B3C0; }
	{ cmp4.lt	p07,p06,r8,r0; adds	r1,0x0,r38; adds	r40,0x0,r0 }
	{ addl	r41,1,r0; adds	r39,0x0,r32; (p07) br.cond.dpnt.few	40000000000B0BA0; }

l40000000000B0990:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AA20; }
	{ cmp.lt	p06,p07,r8,r0; adds	r14,0x40,r12; adds	r1,0x0,r38; }
	{ (p06) addl	r34,1,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B0A00; }

l40000000000B09B6:
	{ chk.a.nc	r0,3FFFFFFFFF0B11B6; nop; (p32) nop }

l40000000000B09C0:
	{ addl	r34,8192,r0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.lt	p07,p06,r34,r14; (p06) adds	r34,0x0,r14; nop.i	0x0; }

l40000000000B09DC:
	{ nop; dep	r0,r32,r0,49,1; zxt4	r0,r16 }

l40000000000B09EC:
	{ cmp.lt	p00,p03,r1,r0; czx1.r	r64,r65; dep	r0,r32,r0,51,1 }
	{ Invalid; Invalid; Invalid }

l40000000000B0A00:
	{ adds	r39,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r38; nop.m	0x0; adds	r35,0x0,r8 }
	{ addl	r39,48,r0; nop.m	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r38; adds	r33,0x0,r8; sxt4	r20,r32; }
	{ addl	r14,7644,r1; addl	r16,7636,r1; nop.i	0x0 }
	{ adds	r15,0x20,r33; adds	r18,0x10,r33; adds	r17,0x28,r33; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.lt	p06,p07,r32,r14; adds	r14,0x0,r33; (p07) br.cond.dpnt.few	40000000000B0B00; }

l40000000000B0A80:
	{ ld8	r19,[r16]; cmp.eq	p07,p06,0x1,r34; adds	r16,0x18,r33; }
	{ shladd	r19,r20,0x3,r19; st8	[r33],r19; nop.i	0x0 }
	{ st4	[r14],r8,8; st8	[r35],r14; (p07) addl	r14,4,r0 }

l40000000000B0AB0:
	{ nop.m	0x0; st4	[r0],r15; nop.i	0x0; }
	{ st8	[r34],r18; st8	[r0],r17; nop.i	0x0; }
	{ st8	[r0],r16; (p07) st4	[r14],r15; nop.i	0x0 }

l40000000000B0ADC:
	{ Invalid; zxt1	r32,r64; (p16) break.i	0x2A809 }

l40000000000B0AE0:
	{ adds	r8,0x0,r33; mov.i	ar.pfs,r37; mov.spnt	b0,r36,40000000000B0AE0 }
	{ nop.m	0x0; adds	r12,0x90,r12; br.ret	b0; }

l40000000000B0B00:
	{ adds	r39,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn40000000000B0280; }
	{ adds	r1,0x0,r38; adds	r14,0x0,r33; sxt4	r20,r32 }
	{ cmp.eq	p07,p06,0x1,r34; adds	r15,0x20,r33; adds	r18,0x10,r33; }
	{ addl	r16,7636,r1; nop.m	0x0; adds	r17,0x28,r33; }
	{ ld8	r19,[r16]; adds	r16,0x18,r33; shladd	r19,r20,0x3,r19; }
	{ st8	[r33],r19; st4	[r14],r8,8; nop.i	0x0; }
	{ nop.m	0x0; st8	[r35],r14; (p07) addl	r14,4,r0 }

l40000000000B0B70:
	{ st4	[r0],r15; st8	[r34],r18; nop.i	0x0 }
	{ st8	[r0],r17; nop.i	0x0; nop.i	0x0 }
	{ st8	[r0],r16; (p07) st4	[r14],r15; br.cond.sptk.few	40000000000B0AE0 }

l40000000000B0B9C:
	{ (p58) cmp.eq.unc	p63,p17,r63,r36; (p04) nop; (p04) epc }

l40000000000B0BA0:
	{ adds	r39,0x0,r32; adds	r33,0x0,r0; br.call.sptk.many	b0,fn400000000001C340; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r38; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000B0BC0; nop.i	0x0 }
	{ adds	r12,0x90,r12; nop.m	0x0; br.ret	b0; }
40000000000B0BE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B0BF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; open_buffered_stream: 40000000000B0C00
open_buffered_stream proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x4; nop.m	0x0; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; adds	r36,0x0,r32; }
	{ adds	r37,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B4E0; }
	{ adds	r1,0x0,r35; cmp4.lt	p06,p07,r8,r0; nop.b	0x0 }
	{ adds	r32,0x0,r8; mov.spnt	b0,r33,40000000000B0C40; (p06) br.cond.dpnt.few	40000000000B0C70; }

l40000000000B0C50:
	{ nop.m	0x0; mov.i	ar.pfs,r34; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x1,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fd_to_buffered_stream }

l40000000000B0C70:
	{ adds	r8,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000B0C80; br.ret	b0; }
40000000000B0C90 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B0CA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B0CB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; free_buffered_stream: 40000000000B0CC0
;;   Called from:
;;     40000000000B0ECC (in duplicate_buffered_stream)
;;     40000000000B113C (in close_buffered_stream)
;;     40000000000B1596 (in save_bash_input)
free_buffered_stream proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; adds	r14,0x0,r32; mov	r34,b2 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r36,0x0,r1; (p06) br.cond.dpnt.few	40000000000B0D60; }

l40000000000B0CE0:
	{ ld4	r33,[r14],8; ld8	r37,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r37; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B0D20; }

l40000000000B0D00:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r36; nop.m	0x0; nop.i	0x0 }

l40000000000B0D20:
	{ adds	r37,0x0,r32; sxt4	r33,r33; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r36; addl	r14,7636,r1; nop.i	0x0; }
	{ ld8	r14,[r14]; nop.i	0x0; shladd	r33,r33,0x3,r14; }
	{ st8	[r0],r33; nop.m	0x0; nop.i	0x0 }

l40000000000B0D60:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000B0D70; br.ret	b0; }

;; duplicate_buffered_stream: 40000000000B0D80
duplicate_buffered_stream proc
	{ alloc	r41,ar.pfs,0xE,0x0,0xB; cmp4.eq	p06,p07,r33,r32; mov	r40,b0 }
	{ addl	r14,7644,r1; nop.m	0x0; adds	r42,0x0,r1; }
	{ (p06) adds	r33,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B0FA0; }

l40000000000B0DA6:
	{ chk.a.nc	r0,3FFFFFFFFF0B15A6; nop; (p48) nop }

l40000000000B0DB0:
	{ cmp4.lt	p07,p06,r33,r32; ld4	r14,[r14]; nop.i	0x0; }
	{ (p07) adds	r43,0x0,r32; (p06) adds	r43,0x0,r33; nop.i	0x0; }

l40000000000B0DC6:
	{ Invalid; nop; nop; }

l40000000000B0DCC:
	{ cmp.lt	p00,p17,r1,r0; (p48) cmp.lt.unc	p10,p24,r99,r33; (p01) mov	pr,r0,0x9242 }
	{ Invalid; cmp.eq	p00,p00,r32,r0; (p01) rfi }

l40000000000B0DE0:
	{ nop.m	0x0; ld4	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x4,r15; (p07) br.cond.dpnt.few	40000000000B1010; }

l40000000000B0E00:
	{ (p06) adds	r39,0x0,r0; nop.m	0x0; nop.i	0x0 }

l40000000000B0E06:
	{ break.m	0x4000; mov	pr,0x4000; nop }

l40000000000B0E10:
	{ addl	r36,7636,r1; sxt4	r35,r33; sxt4	r32,r32; }
	{ shladd	r35,r35,0x3,r0; ld8	r14,[r36]; nop.i	0x0; }
	{ add	r34,r14,r35; nop.m	0x0; shladd	r32,r32,0x3,r14; }
	{ nop.m	0x0; ld8	r43,[r34]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r43; adds	r15,0x8,r43; (p07) br.cond.dpnt.few	40000000000B0EE0; }

l40000000000B0E60:
	{ nop.m	0x0; ld8	r14,[r32]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; adds	r14,0x8,r14; (p06) br.cond.dpnt.few	40000000000B0EC0; }

l40000000000B0E80:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B0EC0; }

l40000000000B0EA0:
	{ ld8	r15,[r15]; cmp.eq	p07,p06,r15,r14; nop.i	0x0; }
	{ (p07) st8	[r0],r34; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B0EE0 }

l40000000000B0EB6:
	{ chk.a.nc	f0,3FFFFFFFFF0B16B6; nop; break.i	0x80000 }

l40000000000B0EC0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,free_buffered_stream; }
	{ adds	r1,0x0,r42; nop.m	0x0; nop.i	0x0 }

l40000000000B0EE0:
	{ ld8	r38,[r32]; nop.m	0x0; addl	r43,48,r0; }
	{ cmp.eq	p06,p07,0x0,r38; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B1040; }

l40000000000B0F00:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r42; adds	r37,0x0,r8; adds	r43,0x0,r38 }
	{ adds	r44,0x0,r8; addl	r45,48,r0; br.call.sptk.many	b0,xbcopy; }
	{ ld8	r14,[r36]; st8	[r37],r34; adds	r1,0x0,r42; }
	{ add	r14,r14,r35; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	40000000000B1070; }

l40000000000B0F60:
	{ st4	[r33],r14; cmp4.eq	p07,p06,0x0,r39; (p07) br.cond.dptk.few	40000000000B0FA0 }

l40000000000B0F70:
	{ adds	r14,0x20,r14; ld4	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; or	r15,0x8,r15; nop.i	0x0; }
	{ st4	[r15],r14; nop.m	0x0; nop.i	0x0 }

l40000000000B0FA0:
	{ adds	r8,0x0,r33; nop.m	0x0; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.spnt	b0,r40,40000000000B0FB0; br.ret	b0; }

l40000000000B0FC0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000B0280; }
	{ adds	r1,0x0,r42; addl	r14,22532,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x4,r15; nop.i	0x0; }
	{ nop.m	0x0; (p06) adds	r39,0x0,r0; (p06) br.cond.dptk.few	40000000000B0E10 }

l40000000000B100C:
	{ (p48) cmp.lt.unc	p63,p11,r63,r37; (p01) cmp.eq.unc	p04,p16,r3,r64; (p04) rfi }

l40000000000B1010:
	{ adds	r14,0x10,r14; ld4	r39,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,r39,r33; (p06) addl	r39,1,r0; nop.i	0x0; }

l40000000000B102C:
	{ invala; cmp4.eq.or.andcm	p00,p32,r32,r0; zxt1	r0,r64 }

l40000000000B103C:
	{ (p47) nop; zxt1	r0,r64; cmp.lt	p00,p00,r32,r0 }

l40000000000B1040:
	{ adds	r37,0x0,r0; nop.m	0x0; adds	r14,0x0,r34; }
	{ st8	[r37],r34; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	40000000000B0F60; }

l40000000000B1070:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r39; (p07) br.cond.dptk.few	40000000000B0FA0 }

l40000000000B1080:
	{ adds	r43,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,fd_to_buffered_stream; }
	{ ld8	r14,[r36]; adds	r1,0x0,r42; add	r35,r14,r35; }
	{ ld8	r14,[r35]; adds	r14,0x20,r14; nop.i	0x0; }
	{ ld4	r15,[r14]; or	r15,0x8,r15; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.cond.sptk.few	40000000000B0FA0; }
40000000000B10D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B10E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B10F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; close_buffered_stream: 40000000000B1100
;;   Called from:
;;     40000000000B126C (in close_buffered_fd)
close_buffered_stream proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; cmp.eq	p06,p07,0x0,r32; mov	r34,b2 }
	{ adds	r36,0x0,r1; nop.m	0x0; adds	r37,0x0,r32; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B1170; }

l40000000000B1126:
	{ chk.a.nc	r0,3FFFFFFFFF0B1926; nop; (p16) nop }

l40000000000B1130:
	{ ld4	r33,[r32]; nop.i	0x0; br.call.sptk.many	b0,free_buffered_stream; }
	{ nop.m	0x0; adds	r1,0x0,r36; adds	r37,0x0,r33 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C340; }
	{ adds	r1,0x0,r36; nop.m	0x0; nop.i	0x0 }

l40000000000B1170:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000B1180; br.ret	b0; }
40000000000B1190 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B11A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B11B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; close_buffered_fd: 40000000000B11C0
;;   Called from:
;;     4000000000022A4C (in unset_bash_input)
;;     4000000000022ADC (in unset_bash_input)
;;     40000000000B176C (in save_bash_input)
close_buffered_fd proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; addl	r14,7644,r1; mov	r33,b1 }
	{ adds	r35,0x0,r1; cmp4.lt	p07,p06,r32,r0; (p07) br.cond.dpnt.few	40000000000B12A0; }

l40000000000B11E0:
	{ ld4	r14,[r14]; adds	r36,0x0,r32; mov.i	ar.pfs,r34 }
	{ nop.m	0x0; sxt4	r15,r32; nop.b	0x0; }
	{ cmp4.lt	p07,p06,r32,r14; addl	r14,7636,r1; mov.spnt	b0,r33,40000000000B1200 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000B1270; }

l40000000000B1220:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ shladd	r15,r15,0x3,r14; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	40000000000B1270; }

l40000000000B1240:
	{ nop.m	0x0; ld8	r32,[r15]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r32; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B1270; }

l40000000000B1260:
	{ alloc	r2,ar.pfs,0x1,0x0,0x0; nop.i	0x0; br.cond.sptk.many	close_buffered_stream; }

l40000000000B1270:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C340; }
	{ adds	r14,0x0,r8; adds	r1,0x0,r35; mov.i	ar.pfs,r34; }
	{ adds	r8,0x0,r14; mov.spnt	b0,r33,40000000000B1290; br.ret	b0; }

l40000000000B12A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ addl	r14,-1,r0; addl	r15,9,r0; nop.b	0x0 }
	{ adds	r1,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; st4	[r15],r8; mov.spnt	b0,r33,40000000000B12D0 }
	{ nop.m	0x0; adds	r8,0x0,r14; br.ret	b0; }
40000000000B12F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; set_buffered_stream: 40000000000B1300
;;   Called from:
;;     400000000002627C (in push_stream)
;;     400000000002654C (in pop_stream)
set_buffered_stream proc
	{ addl	r14,7636,r1; nop.m	0x0; sxt4	r32,r32; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ shladd	r32,r32,0x3,r14; nop.i	0x0; nop.i	0x0 }
	{ ld8	r8,[r32]; st8	[r33],r32; br.ret	b0; }

;; sync_buffered_stream: 40000000000B1340
;;   Called from:
;;     400000000008284C (in make_child)
;;     40000000000B14DC (in save_bash_input)
;;     40000000000B196C (in check_bash_input)
;;     40000000001050BC (in read_builtin)
sync_buffered_stream proc
	{ alloc	r36,ar.pfs,0x9,0x0,0x6; addl	r14,7636,r1; mov	r35,b3 }
	{ adds	r37,0x0,r1; nop.m	0x0; sxt4	r32,r32; }
	{ ld8	r14,[r14]; nop.m	0x0; adds	r8,0x0,r0; }
	{ shladd	r32,r32,0x3,r14; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.spnt.few	40000000000B1440; }

l40000000000B1380:
	{ ld8	r14,[r32]; nop.i	0x0; adds	r33,0x18,r14 }
	{ adds	r34,0x28,r14; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.spnt.few	40000000000B1440; }

l40000000000B13A0:
	{ ld8	r39,[r33]; ld8	r15,[r34]; nop.i	0x0; }
	{ nop.m	0x0; sub	r39,r39,r15; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r39; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B1400; }

l40000000000B13D0:
	{ st8	[r0],r34; st8	[r0],r33; nop.i	0x0 }

l40000000000B13E0:
	{ nop.m	0x0; mov.i	ar.pfs,r36; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000B13F0; br.ret	b0; }

l40000000000B1400:
	{ ld4	r38,[r14]; nop.m	0x0; sub	r39,r0,r39 }
	{ addl	r40,1,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AA20; }
	{ adds	r1,0x0,r37; st8	[r0],r34; nop.i	0x0 }
	{ st8	[r0],r33; adds	r8,0x0,r0; br.cond.sptk.few	40000000000B13E0; }

l40000000000B1440:
	{ addl	r8,-1,r0; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000B1450; br.ret	b0; }
40000000000B1460 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B1470 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; save_bash_input: 40000000000B1480
;;   Called from:
;;     40000000000B191C (in check_bash_input)
save_bash_input proc
	{ alloc	r38,ar.pfs,0xB,0x0,0x8; addl	r35,7636,r1; mov	r37,b5 }
	{ adds	r39,0x0,r1; adds	r40,0x0,r32; sxt4	r14,r32; }
	{ ld8	r34,[r35]; shladd	r14,r14,0x3,r34; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B14F0; }

l40000000000B14D0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sync_buffered_stream; }
	{ adds	r1,0x0,r39; nop.m	0x0; nop.i	0x0 }

l40000000000B14F0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r33; (p07) br.cond.dpnt.few	40000000000B1680; }

l40000000000B1500:
	{ nop.m	0x0; sxt4	r36,r33; nop.b	0x0 }
	{ addl	r41,140,r1; addl	r42,5,r0; adds	r40,0x0,r0; }
	{ shladd	r36,r36,0x3,r0; add	r34,r34,r36; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r34]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B15B0; }

l40000000000B1550:
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r40,0x0,r8 }
	{ adds	r41,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,internal_error; }
	{ ld8	r14,[r35]; adds	r1,0x0,r39; add	r36,r14,r36; }
	{ ld8	r40,[r36]; br.call.sptk.many	b0,free_buffered_stream; nop.b	0x0; }
	{ adds	r1,0x0,r39; nop.m	0x0; nop.i	0x0; }

l40000000000B15B0:
	{ addl	r14,22532,r1; adds	r40,0x0,r33; addl	r41,2,r0 }
	{ addl	r42,1,r0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x4,r15; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B1740; }

l40000000000B15F0:
	{ addl	r14,9136,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r14]; nop.i	0x0; }
	{ adds	r15,0x1,r15; st4	[r15],r14; addl	r14,5636,r1; }
	{ nop.m	0x0; ld4	r15,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,r32,r15; nop.i	0x0; nop.i	0x0 }
	{ (p07) st4	[r33],r14; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B7E0; }

l40000000000B1646:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; nop; nop }

l40000000000B1660:
	{ adds	r8,0x0,r33; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000B1670; br.ret	b0; }

l40000000000B1680:
	{ adds	r40,0x0,r32; nop.m	0x0; adds	r41,0x0,r0 }
	{ addl	r42,10,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B7E0; }
	{ cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r8; adds	r1,0x0,r39; adds	r33,0x0,r8 }
	{ adds	r40,0x0,r32; addl	r41,1,r0; adds	r42,0x0,r0; }
	{ (p07) ld8	r34,[r35]; (p07) br.cond.spnt.few	40000000000B1500; br.call.sptk.many	b0,fn400000000001B7E0; }

l40000000000B16C6:
	{ sum	0x5FFFE4; (p32) nop; (p16) nop; }

l40000000000B16CC:
	{ (p09) nop; cmp.eq.unc	p32,p16,r9,r64; mov	pr,r66,0xE600 }
	{ (p60) nop; (p05) dep	r33,r32,r0,62,3; (p21) nop }

l40000000000B16E0:
	{ addl	r41,132,r1; addl	r42,5,r0; adds	r40,0x0,r0; }
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r40,0x0,r8 }
	{ adds	r41,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,sys_error; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r39; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000B1730; br.ret	b0 }

l40000000000B1740:
	{ adds	r14,0x10,r14; nop.m	0x0; adds	r40,0x0,r33; }
	{ st4	[r33],r14; nop.i	0x0; br.call.sptk.many	b0,fd_to_buffered_stream; }
	{ adds	r1,0x0,r39; adds	r40,0x0,r32; br.call.sptk.many	b0,close_buffered_fd; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r40,0x0,r33 }
	{ addl	r41,2,r0; addl	r42,1,r0; addl	r14,5636,r1; }
	{ nop.m	0x0; ld4	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r32,r15; nop.i	0x0; }
	{ (p07) st4	[r33],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B7E0; }

l40000000000B17B6:
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; nop; break.b	0x80000 }
40000000000B17D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B17E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B17F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; check_bash_input: 40000000000B1800
check_bash_input proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x4; addl	r14,22532,r1; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x4,r15; (p07) br.cond.dpnt.few	40000000000B18D0 }

l40000000000B1840:
	{ addl	r14,6512,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000B18A0 }

l40000000000B1870:
	{ addl	r14,5636,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,r14,r32; (p06) br.cond.dpnt.few	40000000000B18F0 }

l40000000000B18A0:
	{ adds	r8,0x0,r0; nop.m	0x0; nop.i	0x0 }

l40000000000B18B0:
	{ nop.m	0x0; mov.i	ar.pfs,r34; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000B18C0; br.ret	b0 }

l40000000000B18D0:
	{ adds	r14,0x10,r14; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,r14,r32; (p07) br.cond.dptk.few	40000000000B1840; }

l40000000000B18F0:
	{ cmp4.lt	p06,p07,0x0,r32; nop.m	0x0; adds	r36,0x0,r32 }
	{ addl	r37,-1,r0; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000B1950; }

l40000000000B1910:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,save_bash_input; }
	{ adds	r1,0x0,r35; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p06) br.cond.dptk.few	40000000000B18A0 }

l40000000000B1930:
	{ addl	r8,-1,r0; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000B1940; br.ret	b0 }

l40000000000B1950:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r32; (p06) br.cond.dptk.few	40000000000B18A0; }

l40000000000B1960:
	{ adds	r36,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,sync_buffered_stream; }
	{ adds	r1,0x0,r35; cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r8; adds	r8,0x0,r0 }
	{ nop.b	0x0; (p06) br.cond.dpnt.few	40000000000B1930; br.cond.sptk.few	40000000000B18B0; }

l40000000000B198C:
	{ (p57) nop; break.i	0x1000; break.b	0x1000 }
40000000000B1990 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B19A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B19B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; with_input_from_buffered_stream: 40000000000B19C0
;;   Called from:
;;     400000000001F6CC (in main)
with_input_from_buffered_stream proc
	{ alloc	r36,ar.pfs,0xB,0x0,0x6; adds	r38,0x0,r32; mov	r35,b3 }
	{ adds	r37,0x0,r1; adds	r34,0x0,r0; dep.z	r14,r38,32,32; }
	{ nop.m	0x0; mix4.l	r34,r34,r14; br.call.sptk.many	b0,fd_to_buffered_stream; }
	{ adds	r1,0x0,r37; cmp.eq	p07,p06,0x0,r8; addl	r40,4,r0 }
	{ adds	r41,0x0,r33; (p07) addl	r38,-9980,r1; addl	r39,-10028,r1; }

l40000000000B1A0C:
	{ (p42) cmp4.ne.and	p61,p09,r49,r79; (p04) nop }

l40000000000B1A16:
	{ (p19) fwb; (p21) nop; Invalid }
	{ (p19) fwb; nop; (p33) nop; }

l40000000000B1A2C:
	{ cmp4.eq.and	p00,p17,r1,r0; Invalid; break.i	0x1000 }

l40000000000B1A36:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ Invalid; (p34) break.i	0x84000; (p32) break.i	0x80001 }
40000000000B1A60 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000B1A70 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000B1A80 08 10 1D 08 80 05 E0 00 80 00 42 20 04 00 C4 00 ..........B ....
40000000000B1A90 09 18 01 02 00 21 00 00 00 02 00 A0 C4 00 01 84 .....!..........
40000000000B1AA0 0B 20 21 1C 18 14 60 02 38 20 20 00 00 00 04 00 . !...`.8  .....
40000000000B1AB0 11 00 00 00 01 00 60 02 98 2C 00 00 F8 8D F6 58 ......`..,.....X
40000000000B1AC0 09 08 00 46 00 21 00 00 00 02 00 00 20 02 AA 00 ...F.!...... ...
40000000000B1AD0 11 00 00 00 01 00 00 08 05 80 03 80 08 00 84 00 ................
40000000000B1AE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B1AF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000B1B00: 40000000000B1B00
;;   Called from:
;;     40000000000B1F9C (in run_unwind_frame)
;;     40000000000B222C (in run_unwind_protects)
fn40000000000B1B00 proc
	{ alloc	r39,ar.pfs,0xD,0x0,0xA; addl	r35,7652,r1; nop.b	0x0 }
	{ addl	r36,-4540,r1; mov	r41,pr; cmp.eq	p16,p17,0x0,r32; }
	{ ld8	r34,[r35]; adds	r37,0x0,r35; mov	r38,b6 }
	{ adds	r40,0x0,r1; ld8	r36,[r36]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r34; (p07) br.cond.dpnt.few	40000000000B1C00; }

l40000000000B1B50:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000B1B60:
	{ adds	r14,0x0,r34; nop.m	0x0; adds	r15,0x10,r34; }
	{ nop.m	0x0; ld8	r33,[r14],8; nop.i	0x0; }
	{ ld8	r8,[r14]; st8	[r33],r35; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r8; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B1C30; }

l40000000000B1BA0:
	{ cmp.eq	p07,p06,r36,r8; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B1CD0; }

l40000000000B1BB0:
	{ ld8	r14,[r8],8; ld8	r42,[r15]; nop.i	0x0; }
	{ ld8	r1,[r8]; mov.spnt	b6,r14,40000000000B1BC0; br.call.sptk.many	b0,b6; }
	{ adds	r1,0x0,r40; ld8	r33,[r37]; nop.i	0x0; }

l40000000000B1BE0:
	{ adds	r42,0x0,r34; adds	r34,0x0,r33; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r40; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	40000000000B1B60; }

l40000000000B1C00:
	{ cmp.eq	p07,p06,0x0,r32; mov.i	ar.pfs,r39; (p06) br.cond.dpnt.few	40000000000B1D40; }

l40000000000B1C10:
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000B1C10; nop.i	0x0; }
	{ nop.m	0x0; mov	pr,r41,0xFFFFFFFFFFFFFFFE; br.ret	b0 }

l40000000000B1C30:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dpnt.few	40000000000B1BE0; }

l40000000000B1C40:
	{ ld8	r42,[r15]; ld1	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r14; nop.i	0x0; }
	{ ld1	r14,[r42]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r15; (p06) br.cond.dptk.few	40000000000B1BE0 }

l40000000000B1C80:
	{ adds	r43,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r40; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000000B1BE0 }

l40000000000B1CA0:
	{ adds	r42,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r40; mov	pr,r41,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000B1CC0; br.ret	b0 }

l40000000000B1CD0:
	{ adds	r15,0x18,r34; adds	r14,0x10,r34; adds	r43,0x1C,r34; }
	{ ld4	r44,[r15]; ld8	r42,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r44,r44; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r42,0x0,r34 }
	{ adds	r34,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r40; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	40000000000B1B60 }

l40000000000B1D30:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000B1C00; }

l40000000000B1D40:
	{ addl	r42,-4532,r1; nop.m	0x0; adds	r43,0x0,r32; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,internal_warning; }
	{ adds	r1,0x0,r40; mov	pr,r41,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000B1D70; br.ret	b0; }

;; discard_unwind_frame: 40000000000B1D80
;;   Called from:
;;     400000000005B44C (in execute_shell_function)
;;     400000000005E65C (in execute_command)
;;     40000000000E625C (in gen_compspec_completions)
;;     40000000000FF4AC (in jobs_builtin)
;;     4000000000106D8C (in read_builtin)
;;     4000000000106E6C (in read_builtin)
discard_unwind_frame proc
	{ alloc	r39,ar.pfs,0xB,0x0,0x9; addl	r36,7672,r1; nop.b	0x0 }
	{ addl	r35,7652,r1; mov	r38,b6; adds	r40,0x0,r1; }
	{ nop.m	0x0; ld8	r33,[r35]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r33; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B1E60; }

l40000000000B1DC0:
	{ ld4	r37,[r36]; st4	[r0],r36; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000B1DE0:
	{ adds	r14,0x0,r33; ld8	r34,[r14],8; nop.i	0x0; }
	{ ld8	r14,[r14]; st8	[r34],r35; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000B1E80 }

l40000000000B1E10:
	{ adds	r41,0x0,r33; adds	r33,0x0,r34; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r40; cmp.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	40000000000B1DE0; }

l40000000000B1E30:
	{ addl	r41,-4524,r1; nop.m	0x0; adds	r42,0x0,r32; }
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,internal_warning; }
	{ adds	r1,0x0,r40; st4	[r37],r36; nop.i	0x0 }

l40000000000B1E60:
	{ nop.m	0x0; mov.i	ar.pfs,r39; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000B1E70; br.ret	b0 }

l40000000000B1E80:
	{ adds	r15,0x10,r33; ld1	r14,[r32]; nop.i	0x0; }
	{ ld8	r41,[r15]; nop.m	0x0; sxt1	r15,r14; }
	{ ld1	r14,[r41]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r15; (p06) br.cond.dptk.few	40000000000B1E10 }

l40000000000B1EC0:
	{ adds	r42,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r40; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000000B1E10 }

l40000000000B1EE0:
	{ adds	r41,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r40; nop.i	0x0 }
	{ st4	[r37],r36; nop.m	0x0; br.cond.sptk.few	40000000000B1E60; }
40000000000B1F10 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B1F20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B1F30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; run_unwind_frame: 40000000000B1F40
;;   Called from:
;;     400000000007D54C (in run_sigchld_trap)
;;     40000000000E9A8C (in bind_builtin)
;;     40000000000E9F9C (in bind_builtin)
;;     40000000000EA6AC (in bind_builtin)
;;     40000000000ED02C (in command_builtin)
;;     40000000000ED1DC (in command_builtin)
;;     40000000000F5AFC (in fn40000000000F4180)
;;     40000000000F62CC (in parse_and_execute_cleanup)
;;     40000000000F699C (in parse_and_execute)
;;     40000000000F69FC (in parse_and_execute)
;;     40000000000F6AFC (in parse_and_execute)
;;     40000000000F784C (in parse_string)
;;     40000000000F7AFC (in parse_string)
;;     40000000000FA92C (in fc_builtin)
;;     400000000010538C (in read_builtin)
;;     4000000000107E0C (in read_builtin)
;;     400000000010D026 (in source_builtin)
;;     400000000010D2DC (in source_builtin)
run_unwind_frame proc
	{ alloc	r36,ar.pfs,0x7,0x0,0x6; addl	r33,7672,r1; mov	r35,b3 }
	{ addl	r14,7652,r1; adds	r37,0x0,r1; adds	r38,0x0,r32; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B1FB0; }

l40000000000B1F80:
	{ nop.m	0x0; ld4	r34,[r33]; nop.i	0x0 }
	{ st4	[r0],r33; nop.m	0x0; br.call.sptk.many	b0,fn40000000000B1B00; }
	{ adds	r1,0x0,r37; st4	[r34],r33; nop.i	0x0 }

l40000000000B1FB0:
	{ nop.m	0x0; mov.i	ar.pfs,r36; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000B1FC0; br.ret	b0; }
40000000000B1FD0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B1FE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B1FF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; add_unwind_protect: 40000000000B2000
;;   Called from:
;;     400000000005B3EC (in execute_shell_function)
;;     400000000005E5EC (in execute_command)
;;     400000000007D42C (in run_sigchld_trap)
;;     400000000007D44C (in run_sigchld_trap)
;;     40000000000B20DC (in begin_unwind_frame)
;;     40000000000E61DC (in gen_compspec_completions)
;;     40000000000E61FC (in gen_compspec_completions)
;;     40000000000E621C (in gen_compspec_completions)
;;     40000000000ECE3C (in command_builtin)
;;     40000000000ED1AC (in command_builtin)
;;     40000000000F5F8C (in fn40000000000F5E00)
;;     40000000000F5FDC (in fn40000000000F5E00)
;;     40000000000F614C (in fn40000000000F5E00)
;;     40000000000F617C (in fn40000000000F5E00)
;;     40000000000F674C (in parse_and_execute)
;;     40000000000F678C (in parse_and_execute)
;;     40000000000FA88C (in fc_builtin)
;;     40000000000FA8BC (in fc_builtin)
;;     40000000000FF45C (in jobs_builtin)
;;     40000000001051DC (in read_builtin)
;;     400000000010586C (in read_builtin)
;;     40000000001058BC (in read_builtin)
;;     400000000010605C (in read_builtin)
;;     400000000010634C (in read_builtin)
;;     40000000001067BC (in read_builtin)
;;     40000000001067FC (in read_builtin)
;;     4000000000106EAC (in read_builtin)
;;     4000000000106FEC (in read_builtin)
;;     400000000010712C (in read_builtin)
;;     40000000001071DC (in read_builtin)
;;     400000000010CF0C (in source_builtin)
;;     400000000010CF5C (in source_builtin)
;;     400000000010D25C (in source_builtin)
;;     400000000010D27C (in source_builtin)
add_unwind_protect proc
	{ alloc	r37,ar.pfs,0x8,0x0,0x7; addl	r34,7672,r1; mov	r36,b4 }
	{ adds	r38,0x0,r1; nop.m	0x0; addl	r39,32,r0; }
	{ nop.m	0x0; ld4	r35,[r34]; nop.i	0x0 }
	{ st4	[r0],r34; nop.m	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r38; adds	r14,0x0,r8; nop.b	0x0 }
	{ adds	r16,0x10,r8; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ addl	r15,7652,r1; st8	[r33],r16; mov.spnt	b0,r36,40000000000B2060; }
	{ ld8	r17,[r15]; st8	[r8],r15; nop.i	0x0; }
	{ st8	[r14],r8,8; st4	[r35],r34; nop.i	0x0; }
	{ st8	[r32],r14; nop.i	0x0; br.ret	b0; }
40000000000B20A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B20B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; begin_unwind_frame: 40000000000B20C0
;;   Called from:
;;     400000000005B3CC (in execute_shell_function)
;;     400000000005E5CC (in execute_command)
;;     400000000007D32C (in run_sigchld_trap)
;;     40000000000E61BC (in gen_compspec_completions)
;;     40000000000E995C (in bind_builtin)
;;     40000000000EA13C (in bind_builtin)
;;     40000000000ECD8C (in command_builtin)
;;     40000000000ECD8C (in command_builtin)
;;     40000000000ED0DC (in command_builtin)
;;     40000000000F555C (in fn40000000000F4180)
;;     40000000000F5E2C (in fn40000000000F5E00)
;;     40000000000F671C (in parse_and_execute)
;;     40000000000FA85C (in fc_builtin)
;;     40000000000FF39C (in jobs_builtin)
;;     400000000010500C (in read_builtin)
;;     400000000010CEEC (in source_builtin)
begin_unwind_frame proc
	{ alloc	r16,ar.pfs,0x2,0x0,0x2; adds	r33,0x0,r32; adds	r32,0x0,r0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	add_unwind_protect; }
40000000000B20E0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000B20F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; remove_unwind_protect: 40000000000B2100
;;   Called from:
;;     400000000010631C (in read_builtin)
remove_unwind_protect proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; addl	r32,7672,r1; nop.b	0x0 }
	{ addl	r15,7652,r1; mov	r34,b2; adds	r36,0x0,r1; }
	{ nop.m	0x0; ld8	r14,[r15]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; adds	r37,0x0,r14; (p06) br.cond.dpnt.few	40000000000B2180; }

l40000000000B2140:
	{ ld4	r33,[r32]; st4	[r0],r32; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r36; st4	[r33],r32; nop.i	0x0 }

l40000000000B2180:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000B2190; br.ret	b0; }
40000000000B21A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B21B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; run_unwind_protects: 40000000000B21C0
;;   Called from:
;;     40000000000B440C (in top_level_cleanup)
;;     40000000000B46DC (in throw_to_top_level)
;;     40000000000B495C (in throw_to_top_level)
run_unwind_protects proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; addl	r32,7672,r1; nop.b	0x0 }
	{ addl	r14,7652,r1; mov	r34,b2; adds	r36,0x0,r1; }
	{ nop.m	0x0; nop.m	0x0; adds	r37,0x0,r0 }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B2240; }

l40000000000B2210:
	{ nop.m	0x0; ld4	r33,[r32]; nop.i	0x0 }
	{ st4	[r0],r32; nop.m	0x0; br.call.sptk.many	b0,fn40000000000B1B00; }
	{ adds	r1,0x0,r36; st4	[r33],r32; nop.i	0x0 }

l40000000000B2240:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000B2250; br.ret	b0; }
40000000000B2260 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B2270 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; clear_unwind_protect_list: 40000000000B2280
;;   Called from:
;;     400000000005069C (in shell_execve)
clear_unwind_protect_list proc
	{ alloc	r38,ar.pfs,0x9,0x0,0x8; addl	r34,7652,r1; mov	r37,b5 }
	{ addl	r35,7672,r1; adds	r39,0x0,r1; cmp4.eq	p09,p08,0x0,r32; }
	{ ld8	r40,[r34]; nop.m	0x0; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r40; (p06) br.cond.dpnt.few	40000000000B2330; (p09) br.cond.dptk.few	40000000000B2350 }

l40000000000B22BC:
	{ Invalid; Invalid; Invalid }

l40000000000B22C0:
	{ ld4	r36,[r35]; st4	[r0],r35; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000B22E0:
	{ nop.m	0x0; ld8	r33,[r40]; nop.i	0x0; }
	{ st8	[r33],r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r39; adds	r40,0x0,r33 }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	40000000000B22E0 }

l40000000000B2320:
	{ st8	[r0],r34; st4	[r36],r35; nop.i	0x0 }

l40000000000B2330:
	{ nop.m	0x0; mov.i	ar.pfs,r38; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000B2340; br.ret	b0 }

l40000000000B2350:
	{ addl	r35,7672,r1; st8	[r0],r34; nop.i	0x0; }
	{ nop.m	0x0; ld4	r36,[r35]; nop.i	0x0; }
	{ st4	[r36],r35; nop.i	0x0; br.cond.sptk.few	40000000000B2330; }

;; have_unwind_protects: 40000000000B2380
;;   Called from:
;;     40000000000F620C (in parse_and_execute_cleanup)
;;     40000000000F628C (in parse_and_execute_cleanup)
have_unwind_protects proc
	{ addl	r14,7652,r1; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r14; (p06) addl	r8,1,r0; nop.i	0x0; }

l40000000000B239C:
	{ Invalid; mov	pr,r32,0x0; (p01) shladd	r0,r0,0x1,r64 }

l40000000000B23AC:
	{ nop; break.m	0x1000; break.i	0x1000 }
40000000000B23B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; unwind_protect_mem: 40000000000B23C0
;;   Called from:
;;     400000000007D34C (in run_sigchld_trap)
;;     400000000007D36C (in run_sigchld_trap)
;;     400000000007D38C (in run_sigchld_trap)
;;     400000000007D3AC (in run_sigchld_trap)
;;     400000000007D3CC (in run_sigchld_trap)
;;     400000000007D3EC (in run_sigchld_trap)
;;     400000000007D40C (in run_sigchld_trap)
;;     40000000000E999C (in bind_builtin)
;;     40000000000EA16C (in bind_builtin)
;;     40000000000F558C (in fn40000000000F4180)
;;     40000000000F55BC (in fn40000000000F4180)
;;     40000000000F55FC (in fn40000000000F4180)
;;     40000000000F59FC (in fn40000000000F4180)
;;     40000000000F5A2C (in fn40000000000F4180)
;;     40000000000F5E4C (in fn40000000000F5E00)
;;     40000000000F5E6C (in fn40000000000F5E00)
;;     40000000000F5E8C (in fn40000000000F5E00)
;;     40000000000F5EAC (in fn40000000000F5E00)
;;     40000000000F5ECC (in fn40000000000F5E00)
;;     40000000000F5EEC (in fn40000000000F5E00)
;;     40000000000F5F0C (in fn40000000000F5E00)
;;     40000000000F5F3C (in fn40000000000F5E00)
;;     40000000000F606C (in fn40000000000F5E00)
;;     40000000000F60FC (in fn40000000000F5E00)
;;     40000000000FA8DC (in fc_builtin)
;;     40000000001056EC (in read_builtin)
;;     40000000001056EC (in read_builtin)
unwind_protect_mem proc
	{ alloc	r39,ar.pfs,0xC,0x0,0x9; addl	r35,7672,r1; mov	r38,b6 }
	{ adds	r41,0x1C,r33; addl	r36,7652,r1; adds	r40,0x0,r1; }
	{ nop.m	0x0; sxt4	r41,r41; nop.i	0x0 }
	{ ld4	r37,[r35]; st4	[r0],r35; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r40; ld8	r15,[r36]; adds	r14,0x0,r8 }
	{ adds	r17,0x10,r8; adds	r16,0x18,r8; adds	r34,0x0,r8; }
	{ st8	[r14],r8,8; addl	r15,-4540,r1; adds	r41,0x1C,r8 }
	{ adds	r42,0x0,r32; st8	[r32],r17; sxt4	r43,r33; }
	{ ld8	r15,[r15]; st4	[r33],r16; nop.i	0x0; }
	{ st8	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ adds	r1,0x0,r40; st8	[r34],r36; nop.b	0x0 }
	{ st4	[r37],r35; nop.m	0x0; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000B2480; br.ret	b0; }
40000000000B2490 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000B24A0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000B24B0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; fn40000000000B24C0: 40000000000B24C0
;;   Called from:
;;     40000000000B340C (in ignore_glob_matches)
fn40000000000B24C0 proc
	{ alloc	r36,ar.pfs,0x9,0x0,0x6; ld1	r14,[r32]; mov	r35,b3 }
	{ adds	r37,0x0,r1; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r14; (p07) br.cond.dpnt.few	40000000000B25B0 }

l40000000000B24F0:
	{ addl	r14,-20052,r1; nop.m	0x0; nop.i	0x0; }
	{ adds	r14,0x8,r14; ld8	r33,[r14]; addl	r14,7664,r1; }
	{ ld4	r34,[r14]; cmp4.eq	p06,p07,0x0,r34; nop.i	0x0; }
	{ (p06) addl	r34,1,r0; nop.i	0x0; (p07) addl	r34,33,r0; }

l40000000000B2526:
	{ chk.a.nc	f0,3FFFFFFFFF0B2D26; (p17) nop; break.i	0x80000 }

l40000000000B2530:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000B2540:
	{ ld8	r38,[r33]; nop.m	0x0; adds	r39,0x0,r32 }
	{ adds	r40,0x0,r34; nop.m	0x0; adds	r33,0x10,r33; }
	{ cmp.eq	p07,p06,0x0,r38; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B2670; }

l40000000000B2570:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strmatch; }
	{ adds	r1,0x0,r37; cmp4.eq	p07,p06,0x1,r8; (p07) br.cond.dptk.few	40000000000B2540 }

l40000000000B2590:
	{ adds	r8,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000B25A0; br.ret	b0 }

l40000000000B25B0:
	{ adds	r14,0x1,r32; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B2590; }

l40000000000B25E0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r14; (p06) br.cond.dptk.few	40000000000B24F0 }

l40000000000B25F0:
	{ adds	r14,0x2,r32; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; addl	r14,-20052,r1; (p06) br.cond.dpnt.few	40000000000B2590; }

l40000000000B2620:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ adds	r14,0x8,r14; ld8	r33,[r14]; addl	r14,7664,r1; }
	{ ld4	r34,[r14]; cmp4.eq	p06,p07,0x0,r34; nop.i	0x0; }
	{ nop.m	0x0; (p06) addl	r34,1,r0; nop.i	0x0; }

l40000000000B265C:
	{ invala; dep	r0,r32,r0,49,1; zxt4	r8,r0 }

l40000000000B266C:
	{ (p55) nop; zxt4	r0,r0; break.i	0x1000 }

l40000000000B2670:
	{ addl	r8,1,r0; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000B2680; br.ret	b0; }
40000000000B2690 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B26A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B26B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; unquoted_glob_pattern_p: 40000000000B26C0
;;   Called from:
;;     40000000000A804C (in fn40000000000A7940)
unquoted_glob_pattern_p proc
	{ alloc	r38,ar.pfs,0xC,0x0,0x8; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r37,b5 }
	{ addl	r35,-9996,r1; adds	r39,0x0,r1; adds	r40,0x0,r32; }
	{ adds	r34,0x18,r12; ld8	r35,[r35]; adds	r33,0x0,r0; }
	{ st8	[r0],r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; ld1	r14,[r32]; adds	r1,0x0,r39 }
	{ add	r36,r32,r8; nop.i	0x0; sxt1	r14,r14; }

l40000000000B2720:
	{ cmp4.eq	p07,p06,0x0,r14; adds	r15,0x1,r32; (p07) br.cond.dpnt.few	40000000000B2960; }

l40000000000B2730:
	{ cmp4.eq	p06,p07,0x3F,r14; adds	r16,0x0,r15; (p06) br.cond.dpnt.few	40000000000B28E0; }

l40000000000B2740:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x3F,r14; (p06) br.cond.dptk.few	40000000000B2840; }

l40000000000B2750:
	{ cmp4.eq	p06,p07,0x21,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B28C0; }

l40000000000B2760:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x21,r14; (p07) br.cond.dptk.few	40000000000B2930; }

l40000000000B2770:
	{ cmp4.eq	p06,p07,0x2A,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B28E0; }

l40000000000B2780:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2B,r14; (p06) br.cond.dpnt.few	40000000000B28C0; }

l40000000000B2790:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000B27A0:
	{ adds	r32,0xFFFFFFFFFFFFFFFF,r16; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r39; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	40000000000B2820; }

l40000000000B27C0:
	{ ld1	r14,[r32]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r35; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; adds	r14,0x0,r0; (p07) br.cond.dpnt.few	40000000000B2980; }

l40000000000B2810:
	{ add	r32,r32,r14; nop.m	0x0; nop.i	0x0; }

l40000000000B2820:
	{ adds	r32,0x1,r32; ld1	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; br.cond.sptk.few	40000000000B2720; }

l40000000000B2840:
	{ cmp4.eq	p06,p07,0x5B,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B2900; }

l40000000000B2850:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x5B,r14; (p07) br.cond.dptk.few	40000000000B28B0; }

l40000000000B2860:
	{ cmp4.eq	p06,p07,0x5C,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B2940; }

l40000000000B2870:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x5D,r14; (p07) br.cond.dptk.few	40000000000B27A0; }

l40000000000B2880:
	{ cmp4.eq	p07,p06,0x0,r33; adds	r32,0x0,r15; (p06) br.cond.dpnt.few	40000000000B28E0; }

l40000000000B2890:
	{ nop.m	0x0; ld1	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; br.cond.sptk.few	40000000000B2720; }

l40000000000B28B0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x40,r14; (p07) br.cond.dptk.few	40000000000B27A0 }

l40000000000B28C0:
	{ ld1	r14,[r15]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x28,r14; (p07) br.cond.dptk.few	40000000000B2920; }

l40000000000B28E0:
	{ addl	r8,1,r0; mov.i	ar.pfs,r38; mov.spnt	b0,r37,40000000000B28E0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000B2900:
	{ ld1	r14,[r15]; adds	r33,0x1,r33; adds	r32,0x0,r15; }
	{ nop.m	0x0; sxt1	r14,r14; br.cond.sptk.few	40000000000B2720 }

l40000000000B2920:
	{ nop.m	0x0; adds	r32,0x0,r15; br.cond.sptk.few	40000000000B2720; }

l40000000000B2930:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x1,r14; (p07) br.cond.dptk.few	40000000000B27A0 }

l40000000000B2940:
	{ ld1	r14,[r15]; adds	r16,0x2,r32; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	40000000000B27A0; }

l40000000000B2960:
	{ adds	r8,0x0,r0; mov.i	ar.pfs,r38; mov.spnt	b0,r37,40000000000B2960 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000000B2980:
	{ ld8	r14,[r34]; adds	r15,0x10,r12; adds	r41,0x0,r32 }
	{ sub	r42,r36,r32; adds	r40,0x0,r0; adds	r43,0x0,r34; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r15,0x10,r12; adds	r1,0x0,r39; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B2A00; }

l40000000000B29D0:
	{ ld8	r14,[r15]; nop.m	0x0; adds	r32,0x1,r32; }
	{ st8	[r14],r34; ld1	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; br.cond.sptk.few	40000000000B2720 }

l40000000000B2A00:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ (p07) adds	r14,0xFFFFFFFFFFFFFFFF,r8; nop.i	0x0; (p07) br.cond.spnt.few	40000000000B2810; }

l40000000000B2A16:
	{ chk.a.nc	f0,3FFFFFFFFF0B3216; nop; break.i	0x80000 }

l40000000000B2A20:
	{ nop.m	0x0; adds	r14,0x0,r0; br.cond.sptk.few	40000000000B2810; }
40000000000B2A30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; glob_char_p: 40000000000B2A40
;;   Called from:
;;     40000000000B2FAC (in quote_globbing_chars)
;;     40000000000BF5BC (in expand_compound_array_assignment)
glob_char_p proc
	{ ld1	r14,[r32]; addl	r16,1,r0; adds	r14,0xFFFFFFFFFFFFFFDF,r14; }
	{ nop.m	0x0; sxt1	r15,r14; zxt1	r14,r14; }
	{ nop.m	0x0; shl	r15,r16,r15; nop.i	0x0 }
	{ cmp4.ltu	p06,p07,0x3C,r14; nop.m	0x0; (p07) br.cond.dptk.few	40000000000B2A90 }

l40000000000B2A80:
	{ nop.m	0x0; adds	r8,0x0,r0; br.ret	b0; }

l40000000000B2A90:
	{ nop.m	0x0; movl	r14,0x40000200 }
	{ addl	r8,1,r0; movl	r16,0x80000401; }
	{ and	r14,r14,r15; nop.m	0x0; and	r15,r16,r15; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.ret	b0; }

l40000000000B2AD0:
	{ adds	r32,0x1,r32; cmp.eq	p07,p06,0x0,r15; (p07) br.cond.dptk.few	40000000000B2A80; }

l40000000000B2AE0:
	{ ld1	r8,[r32]; nop.m	0x0; sxt1	r8,r8; }
	{ cmp4.eq	p06,p07,0x28,r8; (p06) addl	r8,1,r0; nop.i	0x0; }

l40000000000B2AFC:
	{ Invalid; mov	pr,r32,0x0; (p01) shladd	r0,r0,0x1,r64 }

l40000000000B2B0C:
	{ nop; break.m	0x1000; break.i	0x1000 }
40000000000B2B10 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B2B20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B2B30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; quote_string_for_globbing: 40000000000B2B40
;;   Called from:
;;     40000000000A661C (in cond_expand_word)
;;     40000000000B365C (in shell_glob_filename)
quote_string_for_globbing proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; nop.m	0x0; mov	r34,b2 }
	{ adds	r36,0x0,r1; nop.m	0x0; adds	r37,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r36; adds	r37,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld1	r15,[r32]; adds	r1,0x0,r36; tbit.z	p07,p06,r33,0x0; }
	{ nop.m	0x0; sxt1	r15,r15; (p07) br.cond.dptk.few	40000000000B2BB0; }

l40000000000B2BA0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x7F,r15; (p07) br.cond.dpnt.few	40000000000B2E70; }

l40000000000B2BB0:
	{ cmp4.eq	p07,p06,0x0,r15; addl	r20,724,r1; tbit.z	p09,p08,r33,0x1 }
	{ adds	r17,0x0,r0; adds	r14,0x0,r0; addl	r19,92,r0; }
	{ (p07) adds	r16,0x0,r0; tbit.z	p10,p11,r33,0x2; (p07) br.cond.dpnt.few	40000000000B2CB0; }

l40000000000B2BD6:
	{ (p05) chk.a.nc	f4,3FFFFFFFFFAB85E6; nop; nop }

l40000000000B2BE0:
	{ adds	r16,0x0,r0; ld8	r20,[r20]; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000B2C00:
	{ cmp4.eq	p07,p06,0x1,r15; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B2CF0; }

l40000000000B2C10:
	{ cmp4.eq	p06,p07,0x5C,r15; sxt4	r17,r16; (p06) br.cond.dpnt.few	40000000000B2DF0; }

l40000000000B2C20:
	{ nop.m	0x0; sxt4	r15,r14; add	r17,r8,r17 }
	{ adds	r16,0x1,r16; add	r15,r32,r15; nop.i	0x0; }
	{ ld1	r15,[r15]; nop.i	0x0; sxt1	r15,r15; }
	{ st1	[r15],r17; nop.m	0x0; nop.i	0x0 }

l40000000000B2C60:
	{ adds	r14,0x1,r14; nop.m	0x0; sxt4	r17,r14; }
	{ add	r15,r32,r17; ld1	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	40000000000B2C00 }

l40000000000B2CA0:
	{ nop.m	0x0; sxt4	r16,r16; nop.i	0x0; }

l40000000000B2CB0:
	{ nop.m	0x0; add	r16,r8,r16; nop.i	0x0; }
	{ st1	[r0],r16; nop.m	0x0; nop.i	0x0 }

l40000000000B2CD0:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000B2CE0; br.ret	b0 }

l40000000000B2CF0:
	{ add	r17,r32,r17,0x1; ld1	r15,[r17]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; (p09) br.cond.dptk.few	40000000000B2D20; }

l40000000000B2D10:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2F,r15; (p06) br.cond.dpnt.few	40000000000B2C60; }

l40000000000B2D20:
	{ cmp4.eq	p06,p07,0x1,r15; (p06) br.cond.dpnt.few	40000000000B2D80; (p10) br.cond.dptk.few	40000000000B2D80 }

l40000000000B2D2C:
	{ (p03) cmp.eq	p00,p11,r0,r33; zxt2	r119,r79; cmp.eq	p00,p00,r32,r0 }

l40000000000B2D30:
	{ adds	r15,0xFFFFFFFFFFFFFFDC,r15; nop.m	0x0; zxt1	r15,r15; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x58,r15; (p06) br.cond.dptk.few	40000000000B2C60 }

l40000000000B2D50:
	{ shladd	r15,r15,0x3,r20; ld8	r17,[r15]; nop.i	0x0; }
	{ nop.m	0x0; add	r15,r15,r17; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r15,40000000000B2D70; br.cond	b6; }

l40000000000B2D80:
	{ nop.m	0x0; sxt4	r17,r16; adds	r14,0x1,r14 }
	{ adds	r16,0x1,r16; add	r17,r8,r17; sxt4	r15,r14; }
	{ st1	[r19],r17; add	r15,r32,r15; sxt4	r17,r16; }
	{ ld1	r15,[r15]; add	r17,r8,r17; sxt1	r15,r15; }
	{ cmp4.eq	p07,p06,0x0,r15; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B2CA0; }

l40000000000B2DD0:
	{ nop.m	0x0; adds	r16,0x1,r16; nop.i	0x0 }
	{ st1	[r15],r17; nop.m	0x0; br.cond.sptk.few	40000000000B2C60; }

l40000000000B2DF0:
	{ nop.m	0x0; sxt4	r18,r16; adds	r14,0x1,r14 }
	{ nop.m	0x0; adds	r16,0x1,r16; nop.b	0x0; }
	{ nop.m	0x0; sxt4	r17,r14; add	r18,r8,r18; }
	{ st1	[r15],r18; add	r15,r32,r17; sxt4	r17,r16; }
	{ ld1	r15,[r15]; add	r17,r8,r17; sxt1	r15,r15; }
	{ cmp4.eq	p07,p06,0x0,r15; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B2CA0; }

l40000000000B2E50:
	{ nop.m	0x0; adds	r16,0x1,r16; nop.i	0x0 }
	{ st1	[r15],r17; nop.m	0x0; br.cond.sptk.few	40000000000B2C60; }

l40000000000B2E70:
	{ adds	r14,0x1,r32; addl	r20,724,r1; tbit.z	p09,p08,r33,0x1 }
	{ adds	r17,0x0,r0; adds	r16,0x0,r0; addl	r19,92,r0; }
	{ ld1	r14,[r14]; tbit.z	p10,p11,r33,0x2; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.m	0x0; adds	r14,0x0,r0; }
	{ (p07) st1	[r0],r8; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B2CD0; }

l40000000000B2EB6:
	{ chk.a.nc	f0,3FFFFFFFFF0B36B6; nop; nop }

l40000000000B2EC0:
	{ ld8	r20,[r20]; nop.i	0x0; br.cond.sptk.few	40000000000B2C00; }
40000000000B2ED0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B2EE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B2EF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; quote_globbing_chars: 40000000000B2F00
;;   Called from:
;;     40000000000D9C4C (in strcreplace)
quote_globbing_chars proc
	{ alloc	r41,ar.pfs,0x10,0x0,0xC; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r43,LC }
	{ addl	r35,-9996,r1; adds	r42,0x0,r1; adds	r44,0x0,r32; }
	{ nop.m	0x0; adds	r36,0x18,r12; mov	r40,b0 }
	{ ld8	r35,[r35]; addl	r37,92,r0; adds	r34,0x0,r32; }
	{ st8	[r0],r36; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r42; nop.m	0x0; add	r39,r32,r8 }
	{ add	r44,r8,r8,0x1; nop.m	0x0; br.call.sptk.many	b0,xmalloc; }
	{ ld1	r14,[r32]; adds	r1,0x0,r42; adds	r38,0x0,r8 }
	{ adds	r33,0x0,r8; nop.m	0x0; sxt1	r14,r14; }

l40000000000B2F90:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000B30E0 }

l40000000000B2FA0:
	{ adds	r44,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,glob_char_p; }
	{ cmp4.eq	p06,p07,0x0,r8; nop.m	0x0; adds	r1,0x0,r42; }
	{ (p07) st1	[r33],r1,1; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }

l40000000000B2FC6:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ add	r0,r0,r1; (p03) nop; nop }
	{ chk.a.nc	r0,3FFFFFFFFF0B37E6; nop; (p32) nop }

l40000000000B2FF0:
	{ ld1	r14,[r34]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r15,r14,5,3; and	r16,0x1F,r14; }
	{ shladd	r15,r15,0x2,r35; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r15,r15,r16; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r15,0x0; (p07) br.cond.dpnt.few	40000000000B3160; }

l40000000000B3040:
	{ sub	r19,r34,r34,0x1; cmp.eq	p06,p07,0x0,r8; adds	r15,0x0,r34 }
	{ adds	r16,0x0,r33; adds	r17,0x1,r34; add	r18,r19,r8; }
	{ nop.m	0x0; mov.i	LC,r18; nop.i	0x0; }
	{ nop.m	0x0; (p07) mov.i	LC,r18; (p06) mov.i	LC,0x0 }

l40000000000B307C:
	{ nop; zxt1	r0,r64; add	r0,r32,r0 }

l40000000000B3080:
	{ adds	r33,0x0,r16; nop.m	0x0; adds	r44,0x1,r15; }
	{ st1	[r33],r1,1; nop.m	0x0; adds	r15,0x0,r44; }
	{ nop.m	0x0; adds	r16,0x0,r33; br.cloop.sptk.few	40000000000B3110; }

l40000000000B30B0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000B30C0:
	{ ld1	r14,[r44]; adds	r34,0x0,r44; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000B2FA0 }

l40000000000B30E0:
	{ adds	r8,0x0,r38; st1	[r0],r33; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.i	LC,r43; mov.spnt	b0,r40,40000000000B30F0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000B3110:
	{ ld1	r14,[r17],1; adds	r33,0x0,r16; adds	r44,0x1,r15; }
	{ nop.m	0x0; sxt1	r14,r14; adds	r15,0x0,r44; }
	{ nop.m	0x0; st1	[r33],r1,1; nop.i	0x0; }
	{ nop.m	0x0; adds	r16,0x0,r33; br.cloop.sptk.few	40000000000B3110 }

l40000000000B3150:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000B30C0 }

l40000000000B3160:
	{ ld8	r14,[r36]; adds	r15,0x10,r12; adds	r44,0x0,r0 }
	{ adds	r45,0x0,r34; sub	r46,r39,r34; adds	r47,0x0,r36; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r18,0x10,r12; adds	r1,0x0,r42; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B3250; }

l40000000000B31B0:
	{ ld8	r14,[r18]; nop.m	0x0; addl	r8,1,r0; }
	{ nop.m	0x0; st8	[r14],r36; nop.i	0x0 }
	{ ld1	r14,[r34]; nop.i	0x0; sxt1	r14,r14 }

l40000000000B31E0:
	{ sub	r19,r34,r34,0x1; cmp.eq	p06,p07,0x0,r8; adds	r15,0x0,r34 }
	{ adds	r16,0x0,r33; adds	r17,0x1,r34; add	r18,r19,r8; }
	{ nop.m	0x0; mov.i	LC,r18; (p07) mov.i	LC,r18; }

l40000000000B3210:
	{ nop.m	0x0; (p06) mov.i	LC,0x0; br.cond.sptk.few	40000000000B3080 }

l40000000000B321C:
	{ (p51) cmp.lt.unc	p63,p11,r63,r36; (p17) nop; (p32) nop }

l40000000000B3220:
	{ ld1	r14,[r34],1; st1	[r33],r1,1; nop.i	0x0; }
	{ nop.m	0x0; ld1	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; br.cond.sptk.few	40000000000B2F90 }

l40000000000B3250:
	{ cmp.eq	p06,p07,0x0,r8; (p07) ld1	r14,[r34]; nop.i	0x0; }

l40000000000B325C:
	{ Invalid; cmp4.eq.and	p00,p32,r32,r0; (p01) mov	pr,r3,0x80 }
	{ (p47) cmp.lt.unc	p63,p09,r127,r36; Invalid; break.i	0x1000 }

l40000000000B3270:
	{ ld1	r14,[r34]; nop.m	0x0; addl	r8,1,r0; }
	{ nop.m	0x0; sxt1	r14,r14; br.cond.sptk.few	40000000000B31E0; }
40000000000B3290 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B32A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B32B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; should_ignore_glob_matches: 40000000000B32C0
should_ignore_glob_matches proc
	{ addl	r14,-20052,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; adds	r14,0x10,r14; nop.i	0x0; }
	{ ld4	r8,[r14]; nop.i	0x0; br.ret	b0; }
40000000000B32F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; ignore_glob_matches: 40000000000B3300
;;   Called from:
;;     40000000000B37DC (in shell_glob_filename)
ignore_glob_matches proc
	{ alloc	r38,ar.pfs,0x9,0x0,0x8; addl	r14,-20052,r1; mov	r37,b5 }
	{ adds	r39,0x0,r1; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ adds	r14,0x10,r14; nop.m	0x0; mov.spnt	b0,r37,40000000000B3320; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000B3350; br.ret	b0 }

l40000000000B334C:
	{ cmp.eq	p00,p09,r33,r0; (p01) nop; (p05) cmp.lt	p00,p16,r0,r64 }

l40000000000B3350:
	{ ld8	r15,[r32]; adds	r40,0x0,r0; adds	r14,0x8,r32; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r15; nop.i	0x0; }
	{ nop.m	0x0; (p06) addl	r40,1,r0; (p06) br.cond.dpnt.few	40000000000B33B0; }

l40000000000B337C:
	{ (p02) cmp.eq	p00,p09,r64,r33; (p01) mov.i	KR6,0x3; break.i	0x1000 }

l40000000000B3380:
	{ ld8	r15,[r14],8; nop.m	0x0; adds	r40,0x1,r40; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	40000000000B3380 }

l40000000000B33A0:
	{ adds	r40,0x1,r40; nop.m	0x0; nop.i	0x0 }

l40000000000B33B0:
	{ adds	r33,0x8,r32; nop.m	0x0; adds	r35,0x0,r32 }
	{ adds	r34,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,strvec_create; }
	{ ld8	r40,[r32]; adds	r1,0x0,r39; adds	r36,0x0,r8; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r40; (p06) br.cond.dpnt.few	40000000000B3590; }

l40000000000B33F0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000B3400:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000B24C0; }
	{ nop.m	0x0; sxt4	r14,r34; nop.i	0x0 }
	{ adds	r1,0x0,r39; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	40000000000B3550; }

l40000000000B3430:
	{ shladd	r14,r14,0x3,r36; ld8	r15,[r35]; adds	r35,0x0,r33 }
	{ adds	r34,0x1,r34; st8	[r15],r14; nop.i	0x0; }
	{ nop.m	0x0; ld8	r40,[r33],8; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r40; (p06) br.cond.dptk.few	40000000000B3400; }

l40000000000B3470:
	{ nop.m	0x0; sxt4	r14,r34; nop.b	0x0 }
	{ cmp4.eq	p06,p07,0x0,r34; adds	r15,0x8,r36; adds	r16,0x0,r0; }
	{ nop.m	0x0; shladd	r14,r14,0x3,r36; nop.i	0x0; }
	{ st8	[r0],r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B35A0; }

l40000000000B34B0:
	{ nop.m	0x0; ld8	r14,[r36]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000B3510; }

l40000000000B34D0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000B34E0:
	{ add	r17,r32,r16; nop.m	0x0; sub	r16,r15,r36; }
	{ st8	[r14],r17; ld8	r14,[r15],8; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000B34E0 }

l40000000000B3510:
	{ add	r16,r32,r16; nop.m	0x0; adds	r40,0x0,r36; }
	{ st8	[r0],r16; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r39; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000B3540; br.ret	b0; }

l40000000000B3550:
	{ ld8	r40,[r35]; adds	r35,0x0,r33; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ ld8	r40,[r33],8; nop.m	0x0; adds	r1,0x0,r39; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r40; (p06) br.cond.dptk.few	40000000000B3400 }

l40000000000B3580:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000B3470 }

l40000000000B3590:
	{ st8	[r0],r8; nop.m	0x0; nop.i	0x0 }

l40000000000B35A0:
	{ st8	[r0],r32; adds	r40,0x0,r36; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r39; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000B35C0; br.ret	b0; }
40000000000B35D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B35E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B35F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; shell_glob_filename: 40000000000B3600
;;   Called from:
;;     40000000000A889C (in fn40000000000A7940)
;;     40000000000CC6CC (in command_word_completion_function)
shell_glob_filename proc
	{ alloc	r36,ar.pfs,0x8,0x0,0x6; addl	r14,9140,r1; mov	r35,b3 }
	{ adds	r37,0x0,r1; nop.m	0x0; adds	r38,0x0,r32; }
	{ nop.m	0x0; nop.m	0x0; addl	r39,2,r0; }
	{ ld4	r14,[r14]; cmp4.eq	p06,p07,0x0,r14; addl	r14,6372,r1; }
	{ nop.m	0x0; (p06) addl	r15,1,r0; (p07) adds	r15,0x0,r0; }

l40000000000B364C:
	{ Invalid; Invalid; break.i	0x1000; }

l40000000000B3650:
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,quote_string_for_globbing; }
	{ adds	r1,0x0,r37; adds	r34,0x0,r8; adds	r38,0x0,r8; }
	{ addl	r14,7660,r1; ld4	r39,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r39; (p07) addl	r39,1024,r0; nop.i	0x0; }

l40000000000B368C:
	{ cmp4.eq.or.andcm	p00,p17,r1,r0; zxt1	r0,r64; break.i	0x1000 }

l40000000000B3696:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ add	r0,r0,r1; (p16) nop; (p32) nop }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; (p03) nop; (p32) nop }
	{ chk.a.nc	r0,3FFFFFFFFF0B3ED6; nop; (p32) nop }

l40000000000B36E0:
	{ addl	r14,9284,r1; nop.m	0x0; nop.i	0x0; }
	{ cmp.eq	p06,p07,r14,r33; addl	r14,-20052,r1; (p06) br.cond.dpnt.few	40000000000B3770; }

l40000000000B3700:
	{ nop.m	0x0; adds	r14,0x10,r14; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B37D0; }

l40000000000B3730:
	{ nop.m	0x0; ld8	r14,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	40000000000B3790 }

l40000000000B3750:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strvec_sort; }
	{ adds	r1,0x0,r37; nop.m	0x0; nop.i	0x0 }

l40000000000B3770:
	{ adds	r8,0x0,r33; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000B3780; br.ret	b0 }

l40000000000B3790:
	{ nop.m	0x0; addl	r33,9284,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r37; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000B37C0; br.ret	b0; }

l40000000000B37D0:
	{ adds	r38,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,ignore_glob_matches; }
	{ ld8	r14,[r33]; adds	r1,0x0,r37; adds	r38,0x0,r33; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	40000000000B3750 }

l40000000000B3800:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000B3790; }
40000000000B3810 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B3820 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B3830 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; setup_ignore_patterns: 40000000000B3840
;;   Called from:
;;     40000000000B3DCC (in setup_glob_ignore)
;;     40000000000C9AAC (in setup_history_ignore)
setup_ignore_patterns proc
	{ alloc	r44,ar.pfs,0x13,0x0,0xF; adds	r45,0x0,r1; mov	r46,pr }
	{ adds	r35,0x18,r32; ld8	r47,[r32]; adds	r40,0x8,r32; }
	{ nop.m	0x0; mov	r43,b3; adds	r42,0x10,r32 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,get_string_value; }
	{ adds	r1,0x0,r45; nop.m	0x0; adds	r34,0x0,r8 }
	{ cmp.eq	p16,p17,0x0,r8; nop.m	0x0; (p16) br.cond.dpnt.few	40000000000B3D30; }

l40000000000B38A0:
	{ nop.m	0x0; ld8	r48,[r35]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r48; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B38F0; }

l40000000000B38C0:
	{ ld1	r14,[r48]; ld1	r15,[r8]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r15,r14; (p07) br.cond.dpnt.few	40000000000B3CF0 }

l40000000000B38F0:
	{ ld8	r33,[r40]; st4	[r0],r42; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r33; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B39A0; }

l40000000000B3910:
	{ nop.m	0x0; ld8	r47,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r47; (p06) br.cond.dpnt.few	40000000000B3980; }

l40000000000B3930:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000B3940:
	{ adds	r33,0x10,r33; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ ld8	r47,[r33]; nop.m	0x0; adds	r1,0x0,r45; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r47; (p06) br.cond.dptk.few	40000000000B3940 }

l40000000000B3970:
	{ ld8	r33,[r40]; nop.m	0x0; nop.i	0x0; }

l40000000000B3980:
	{ adds	r47,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r45; st8	[r0],r40; nop.i	0x0 }

l40000000000B39A0:
	{ nop.m	0x0; ld8	r14,[r35]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; adds	r47,0x0,r14; (p06) br.cond.dpnt.few	40000000000B39E0; }

l40000000000B39C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r45; st8	[r0],r35; nop.i	0x0 }

l40000000000B39E0:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dpnt.few	40000000000B3A10; }

l40000000000B39F0:
	{ ld1	r14,[r34]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000B3A30; }

l40000000000B3A10:
	{ nop.m	0x0; mov	pr,r46,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r44; }
	{ nop.m	0x0; mov.spnt	b0,r43,40000000000B3A20; br.ret	b0; }

l40000000000B3A30:
	{ adds	r47,0x0,r34; adds	r39,0x0,r0; adds	r33,0x0,r0 }
	{ adds	r41,0x0,r0; adds	r38,0x0,r0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r45; nop.m	0x0; adds	r47,0x1,r8 }
	{ adds	r32,0x20,r32; nop.m	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r45; nop.m	0x0; adds	r47,0x0,r8 }
	{ adds	r48,0x0,r34; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r45; st8	[r8],r35; nop.i	0x0; }

l40000000000B3AA0:
	{ nop.m	0x0; addl	r49,732,r1; sxt4	r14,r33 }
	{ addl	r50,17,r0; adds	r48,0x0,r33; adds	r47,0x0,r34; }
	{ add	r14,r34,r14; ld8	r49,[r49]; nop.i	0x0; }
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000B3C60 }

l40000000000B3AF0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,skip_to_delim; }
	{ adds	r1,0x0,r45; adds	r35,0x0,r8; adds	r47,0x0,r34 }
	{ adds	r48,0x0,r33; adds	r49,0x0,r8; br.call.sptk.many	b0,substring; }
	{ nop.m	0x0; sxt4	r14,r35; cmp.eq	p07,p06,0x0,r8 }
	{ adds	r1,0x0,r45; adds	r37,0x0,r8; (p07) br.cond.spnt.few	40000000000B3C60; }

l40000000000B3B40:
	{ add	r14,r34,r14; nop.m	0x0; adds	r38,0x1,r38; }
	{ ld1	r14,[r14]; cmp4.lt	p07,p06,r38,r41; sxt1	r14,r14 }
	{ (p07) ld8	r8,[r40]; cmp4.eq	p09,p08,0x3A,r14; nop.i	0x0; }

l40000000000B3B66:
	{ Invalid; nop; br.cond.sptk.few	40000000000C3B66 }
	{ (p17) chk.a.clr	r1,3FFFFFFFFF133DA6; br.call.sptk.few	b3,b0; nop.b	0x27109 }

l40000000000B3B7C:
	{ (p09) addp4	r0,r64,r33; zxt1	r98,r0; nop.b	0x1000 }

l40000000000B3B80:
	{ add	r36,r8,r39; nop.m	0x0; adds	r33,0x0,r35 }
	{ adds	r47,0x0,r37; adds	r39,0x10,r39; adds	r35,0x0,r36; }
	{ st8	[r35],r8,8; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; ld8	r14,[r32]; adds	r15,0xC,r36 }
	{ st4	[r8],r35; adds	r1,0x0,r45; adds	r47,0x0,r36; }
	{ st4	[r0],r15; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	40000000000B3AA0; }

l40000000000B3BE0:
	{ nop.m	0x0; ld8	r15,[r14],8; nop.i	0x0; }
	{ ld8	r1,[r14]; mov.spnt	b6,r15,40000000000B3BF0; br.call.sptk.many	b0,b6; }
	{ nop.m	0x0; adds	r1,0x0,r45; sxt4	r14,r33 }
	{ addl	r50,17,r0; adds	r48,0x0,r33; adds	r47,0x0,r34; }
	{ add	r14,r34,r14; nop.m	0x0; addl	r49,732,r1; }
	{ ld1	r14,[r14]; ld8	r49,[r49]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000B3AF0; }

l40000000000B3C60:
	{ ld8	r14,[r40]; mov	pr,r46,0xFFFFFFFFFFFFFFFE; sxt4	r15,r38; }
	{ shladd	r14,r15,0x4,r14; nop.m	0x0; mov.i	ar.pfs,r44; }
	{ nop.m	0x0; st8	[r0],r14; mov.spnt	b0,r43,40000000000B3C80 }
	{ nop.m	0x0; st4	[r38],r42; br.ret	b0 }

l40000000000B3CA0:
	{ adds	r41,0xA,r41; ld8	r47,[r40]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r48,r41; nop.i	0x0; }
	{ shladd	r48,r48,0x4,r0; nop.i	0x0; br.call.sptk.many	b0,xrealloc; }
	{ nop.m	0x0; adds	r1,0x0,r45; nop.i	0x0 }
	{ st8	[r8],r40; nop.m	0x0; br.cond.sptk.few	40000000000B3B80 }

l40000000000B3CF0:
	{ adds	r47,0x0,r8; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r45; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000000B38F0; }

l40000000000B3D10:
	{ nop.m	0x0; mov	pr,r46,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r44; }
	{ nop.m	0x0; mov.spnt	b0,r43,40000000000B3D20; br.ret	b0 }

l40000000000B3D30:
	{ adds	r35,0x18,r32; ld8	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	40000000000B38F0; }

l40000000000B3D50:
	{ nop.m	0x0; mov	pr,r46,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r44; }
	{ nop.m	0x0; mov.spnt	b0,r43,40000000000B3D60; br.ret	b0; }
40000000000B3D70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; setup_glob_ignore: 40000000000B3D80
;;   Called from:
;;     400000000005F5DC (in sv_globignore)
setup_glob_ignore proc
	{ alloc	r36,ar.pfs,0x7,0x0,0x6; addl	r33,-20052,r1; mov	r35,b3 }
	{ adds	r37,0x0,r1; nop.m	0x0; adds	r38,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,get_string_value; }
	{ adds	r1,0x0,r37; adds	r34,0x0,r8; nop.i	0x0 }
	{ adds	r38,0x0,r33; adds	r33,0x10,r33; br.call.sptk.many	b0,setup_ignore_patterns; }
	{ ld4	r14,[r33]; cmp.eq	p09,p08,0x0,r34; nop.b	0x0 }
	{ adds	r1,0x0,r37; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ cmp4.eq	p06,p07,0x0,r14; (p09) addl	r14,9140,r1; mov.spnt	b0,r35,40000000000B3DF0 }

l40000000000B3DFC:
	{ (p17) nop; break.i	0x1000; br.cond	b0 }
	{ (p01) nop; break.i	0x1000; break.b	0x1000 }

l40000000000B3E10:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ (p09) st4	[r0],r14; nop.i	0x0; br.ret	b0 }

l40000000000B3E26:
	{ break.m	0x4000; (p34) nop; (p32) nop }

l40000000000B3E30:
	{ addl	r14,9140,r1; addl	r15,1,r0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; nop.m	0x0; mov.spnt	b0,r35,40000000000B3E40; }
	{ st4	[r15],r14; nop.i	0x0; br.ret	b0; }
40000000000B3E60 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000B3E70 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; sigwinch_sighandler: 40000000000B3E80
sigwinch_sighandler proc
	{ addl	r15,1,r0; nop.m	0x0; addl	r14,7680,r1; }
	{ st4.rel	[r15],r14; nop.i	0x0; br.ret	b0; }
40000000000B3EA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B3EB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; initialize_terminating_signals: 40000000000B3EC0
;;   Called from:
;;     40000000000ADC4C (in set_signal)
;;     40000000000B545C (in initialize_signals)
;;     400000000010E6BC (in trap_builtin)
initialize_terminating_signals proc
	{ alloc	r41,ar.pfs,0xF,0x0,0xC; adds	r12,0xFFFFFFFFFFFFFEE0,r12; nop.b	0x0 }
	{ addl	r35,7688,r1; mov	r43,LC; adds	r42,0x0,r1; }
	{ ld4	r14,[r35]; nop.m	0x0; mov	r40,b0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B3F30; }

l40000000000B3F00:
	{ nop.m	0x0; mov.i	ar.pfs,r41; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r43; mov.spnt	b0,r40,40000000000B3F10 }
	{ nop.m	0x0; adds	r12,0x120,r12; br.ret	b0; }

l40000000000B3F30:
	{ addl	r14,-9964,r1; adds	r36,0xA0,r12; addl	r32,-20012,r1 }
	{ adds	r44,0xB0,r12; ld8	r14,[r14]; nop.i	0x0 }
	{ nop.m	0x0; st8	[r14],r36; adds	r14,0xA8,r12 }
	{ adds	r34,0x198,r32; nop.m	0x0; adds	r33,0x0,r32; }
	{ st8	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r42; adds	r44,0x20,r12; br.call.sptk.many	b0,fn400000000001BC20; }
	{ nop.m	0x0; adds	r1,0x0,r42; mov.i	LC,0x10; }

l40000000000B3FA0:
	{ ld4	r45,[r33],24; adds	r44,0xB0,r12; br.call.sptk.many	b0,fn400000000001B400; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cloop.sptk.few	40000000000B3FA0; }

l40000000000B3FC0:
	{ addl	r38,6512,r1; nop.m	0x0; adds	r37,0x18,r12; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }

l40000000000B3FE0:
	{ ld4	r44,[r32]; nop.i	0x0; br.call.sptk.many	b0,signal_is_trapped; }
	{ adds	r1,0x0,r42; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	40000000000B4050 }

l40000000000B4000:
	{ nop.m	0x0; adds	r32,0x18,r32; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r34,r32; (p06) br.cond.dptk.few	40000000000B3FE0 }

l40000000000B4020:
	{ addl	r14,1,r0; st4	[r14],r35; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.i	LC,r43; mov.spnt	b0,r40,40000000000B4030 }
	{ nop.m	0x0; adds	r12,0x120,r12; br.ret	b0; }

l40000000000B4050:
	{ adds	r33,0x0,r32; adds	r45,0x0,r36; adds	r46,0x10,r12; }
	{ ld4	r44,[r33],8; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C2E0; }
	{ adds	r18,0x10,r12; ld8	r15,[r37]; adds	r17,0x10,r32 }
	{ adds	r1,0x0,r42; ld4	r14,[r38]; nop.i	0x0; }
	{ ld8	r16,[r18]; st4	[r15],r17; cmp4.eq	p07,p06,0x0,r14; }
	{ st8	[r16],r33; nop.i	0x0; (p06) br.cond.dptk.few	40000000000B40D0 }

l40000000000B40B0:
	{ nop.m	0x0; ld8	r14,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x1,r14; (p07) br.cond.dpnt.few	40000000000B4160 }

l40000000000B40D0:
	{ nop.m	0x0; ld4	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x1B,r14; (p06) br.cond.dptk.few	40000000000B4000 }

l40000000000B40F0:
	{ ld8	r14,[r33]; nop.m	0x0; addl	r44,27,r0 }
	{ adds	r45,0x10,r12; nop.m	0x0; adds	r46,0x0,r0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B4000; }

l40000000000B4120:
	{ cmp.eq	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B4000; }

l40000000000B4130:
	{ adds	r32,0x18,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C2E0; }
	{ adds	r1,0x0,r42; cmp.eq	p07,p06,r34,r32; (p06) br.cond.dptk.few	40000000000B3FE0 }

l40000000000B4150:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000B4020 }

l40000000000B4160:
	{ ld4	r39,[r32]; adds	r45,0x0,r18; adds	r46,0x0,r36; }
	{ adds	r44,0x0,r39; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C2E0; }
	{ adds	r1,0x0,r42; adds	r44,0x0,r39; br.call.sptk.many	b0,set_signal_ignored; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	40000000000B40D0; }
40000000000B41A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B41B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; reset_terminating_signals: 40000000000B41C0
;;   Called from:
;;     40000000000A51FC (in fn40000000000A1400)
reset_terminating_signals proc
	{ alloc	r35,ar.pfs,0x9,0x0,0x6; adds	r12,0xFFFFFFFFFFFFFF70,r12; nop.b	0x0 }
	{ addl	r14,7688,r1; mov	r37,LC; adds	r36,0x0,r1; }
	{ ld4	r14,[r14]; nop.m	0x0; mov	r34,b2; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B4230; }

l40000000000B4200:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r37; mov.spnt	b0,r34,40000000000B4210 }
	{ nop.m	0x0; adds	r12,0x90,r12; br.ret	b0; }

l40000000000B4230:
	{ addl	r32,-20012,r1; adds	r33,0x18,r12; adds	r38,0x20,r12; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }
	{ st8	[r0],r33; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BC20; }
	{ nop.m	0x0; adds	r1,0x0,r36; mov.i	LC,0x10; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000B4280:
	{ ld4	r38,[r32]; nop.i	0x0; br.call.sptk.many	b0,signal_is_trapped; }
	{ adds	r1,0x0,r36; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	40000000000B42E0 }

l40000000000B42A0:
	{ nop.m	0x0; adds	r32,0x18,r32; br.cloop.sptk.few	40000000000B4280 }

l40000000000B42B0:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r37; mov.spnt	b0,r34,40000000000B42C0 }
	{ nop.m	0x0; adds	r12,0x90,r12; br.ret	b0; }

l40000000000B42E0:
	{ ld4	r38,[r32]; nop.i	0x0; br.call.sptk.many	b0,signal_is_special; }
	{ adds	r1,0x0,r36; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000000B42A0 }

l40000000000B4300:
	{ adds	r15,0x10,r32; adds	r14,0x8,r32; adds	r39,0x10,r12 }
	{ ld4	r38,[r32]; adds	r40,0x0,r0; adds	r32,0x18,r32; }
	{ ld4	r15,[r15]; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r15,r15; nop.i	0x0 }
	{ st8	[r14],r39; nop.m	0x0; nop.i	0x0; }
	{ st8	[r15],r33; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C2E0; }
	{ nop.m	0x0; adds	r1,0x0,r36; br.cloop.sptk.few	40000000000B4280 }

l40000000000B4370:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000B42B0; }

;; top_level_cleanup: 40000000000B4380
;;   Called from:
;;     40000000000644CC (in make_variable_value)
;;     4000000000074EFC (in fn4000000000074880)
;;     4000000000085E5C (in fn4000000000085DC0)
;;     40000000000C003C (in array_expand_index)
;;     40000000000EDA7C (in no_args)
;;     40000000000EEF6C (in get_numeric_arg)
top_level_cleanup proc
	{ alloc	r34,ar.pfs,0x4,0x0,0x4; addl	r32,8416,r1; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000B43F0; }

l40000000000B43C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,parse_and_execute_cleanup; }
	{ ld4	r14,[r32]; nop.m	0x0; adds	r1,0x0,r35; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000B43C0 }

l40000000000B43F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,unlink_fifo_list; }
	{ adds	r1,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,run_unwind_protects; }
	{ adds	r1,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ addl	r14,7028,r1; nop.m	0x0; mov.spnt	b0,r33,40000000000B4420; }
	{ nop.m	0x0; st4	[r0],r14; addl	r14,8360,r1; }
	{ nop.m	0x0; st4	[r0],r14; addl	r14,8356,r1; }
	{ nop.m	0x0; st4	[r0],r14; addl	r14,8364,r1; }
	{ nop.m	0x0; st4	[r0],r14; addl	r14,9032,r1; }
	{ nop.m	0x0; st4	[r0],r14; addl	r14,7044,r1; }
	{ nop.m	0x0; st4	[r0],r14; addl	r14,7048,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r0],r14; nop.i	0x0; br.ret	b0; }
40000000000B44B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; jump_to_top_level: 40000000000B44C0
;;   Called from:
;;     4000000000035EBC (in fn4000000000030880)
;;     4000000000035ECC (in fn4000000000030880)
;;     400000000003DC2C (in parse_string_to_word_list)
;;     400000000003DC2C (in parse_string_to_word_list)
;;     400000000003DC5C (in parse_string_to_word_list)
;;     400000000005B36C (in fn4000000000059C80)
;;     40000000000644DC (in make_variable_value)
;;     4000000000074F0C (in fn4000000000074880)
;;     400000000007588C (in fn4000000000074880)
;;     4000000000085E4C (in fn4000000000085DC0)
;;     4000000000085E6C (in fn4000000000085DC0)
;;     400000000009443C (in command_substitute)
;;     40000000000B47BC (in throw_to_top_level)
;;     40000000000B48CC (in throw_to_top_level)
;;     40000000000B48CC (in throw_to_top_level)
;;     40000000000B490C (in throw_to_top_level)
;;     40000000000C004C (in array_expand_index)
;;     40000000000EDA8C (in no_args)
;;     40000000000EEF7C (in get_numeric_arg)
;;     40000000000F499C (in fn40000000000F4180)
;;     40000000000F6A8C (in parse_and_execute)
;;     40000000000F6C0C (in parse_and_execute)
;;     40000000000F788C (in parse_string)
;;     40000000000F7B3C (in parse_string)
;;     40000000000F884C (in fn40000000000F8780)
;;     40000000000F8C3C (in fn40000000000F8780)
;;     400000000010D4EC (in source_builtin)
jump_to_top_level proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x4; addl	r36,25252,r1; mov	r33,b1 }
	{ nop.m	0x0; adds	r37,0x0,r32; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BBE0; }
	{ nop.m	0x0; break.f	0x0; nop.i	0x0; }

;; throw_to_top_level: 40000000000B4500
;;   Called from:
;;     40000000000239FC (in read_command)
;;     400000000002411C (in reader_loop)
;;     4000000000029E3C (in fn4000000000029100)
;;     4000000000029EDC (in fn4000000000029100)
;;     4000000000029FCC (in fn4000000000029100)
;;     400000000002A6DC (in read_secondary_line)
;;     400000000002A87C (in read_secondary_line)
;;     400000000002A98C (in read_secondary_line)
;;     400000000005446C (in execute_command_internal)
;;     400000000005E70C (in execute_command)
;;     400000000008062C (in wait_for)
;;     400000000008078C (in wait_for)
;;     4000000000081C3C (in wait_for_background_pids)
;;     400000000008296C (in make_child)
;;     40000000000B44FC (in jump_to_top_level)
;;     40000000000B4ACC (in sigint_sighandler)
;;     40000000000C644C (in brace_expand)
;;     40000000000DCE6C (in fn40000000000DCB80)
;;     40000000000EEDFC (in get_numeric_arg)
;;     40000000000F6BCC (in parse_and_execute)
;;     40000000000FA51C (in fc_builtin)
;;     40000000000FCC5C (in help_builtin)
;;     40000000000FCC5C (in help_builtin)
;;     40000000000FDBDC (in help_builtin)
;;     40000000000FEC6C (in history_builtin)
;;     40000000000FEC6C (in history_builtin)
;;     40000000001204AC (in glob_vector)
;;     400000000012171C (in glob_filename)
throw_to_top_level proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; addl	r14,7684,r1; mov	r34,b2 }
	{ addl	r32,8416,r1; nop.m	0x0; adds	r36,0x0,r1; }
	{ ld4.acq	r15,[r14]; addl	r16,128,r0; cmp4.eq	p06,p07,0x0,r15; }
	{ (p07) ld4.acq	r15,[r14]; (p07) addl	r33,1,r0; (p07) adds	r15,0xFFFFFFFFFFFFFFFF,r15 }

l40000000000B4536:
	{ Invalid; (p07) addl	r127,1041167,r3; Invalid; }

l40000000000B453C:
	{ (p63) nop; (p04) mov	pr,r0,0x8400; Invalid; }

l40000000000B4540:
	{ (p06) adds	r33,0x0,r0; (p07) st4.rel	[r15],r14; addl	r15,9044,r1; }

l40000000000B4546:
	{ Invalid; (p07) nop; break.i	0x80000; }

l40000000000B454C:
	{ (p42) nop; cmp.lt	p00,p00,r32,r0; Invalid; }
	{ cmp.eq	p00,p17,r1,r0; czx1.r	r64,r97; mov	pr,r32,0x0 }
	{ (p29) nop; break.i	0x1000; break.b	0x1000 }

l40000000000B4570:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4	r14,[r15]; cmp4.lt	p07,p06,r16,r14; addl	r16,128,r0; }
	{ (p07) adds	r17,0xFFFFFFFFFFFFFF80,r14; or	r14,r16,r14; addl	r16,9016,r1; }

l40000000000B4596:
	{ Invalid; (p08) nop; break.i	0x80000 }
	{ adds	r0,0xFFFFFFFFFFFFE000,r1; (p08) nop; break.i	0x80000 }

l40000000000B45B0:
	{ nop.m	0x0; st4	[r14],r15; nop.i	0x0; }
	{ st4	[r17],r16; nop.i	0x0; br.call.sptk.many	b0,run_interrupt_trap; }
	{ ld4	r14,[r32]; nop.m	0x0; adds	r1,0x0,r36; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000B4630; }

l40000000000B45F0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000B4600:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,parse_and_execute_cleanup; }
	{ ld4	r14,[r32]; nop.m	0x0; adds	r1,0x0,r36; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000B4600 }

l40000000000B4630:
	{ addl	r14,5896,r1; addl	r32,6516,r1; adds	r38,0x0,r0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4	r37,[r14]; nop.i	0x0; br.call.sptk.many	b0,give_terminal_to; }
	{ adds	r1,0x0,r36; addl	r37,2,r0; adds	r39,0x0,r0; }
	{ nop.m	0x0; addl	r38,25124,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,reset_parser; }
	{ ld4	r14,[r32]; nop.m	0x0; adds	r1,0x0,r36; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B4930; }

l40000000000B46C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,unlink_fifo_list; }
	{ adds	r1,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,run_unwind_protects; }
	{ adds	r1,0x0,r36; ld4	r14,[r32]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; addl	r14,8364,r1; addl	r15,7028,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r0],r14; nop.m	0x0; addl	r14,9032,r1 }
	{ st4	[r0],r15; nop.m	0x0; addl	r15,8360,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r0],r14; nop.m	0x0; addl	r14,7044,r1 }
	{ st4	[r0],r15; nop.m	0x0; addl	r15,8356,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; st4	[r0],r14; addl	r14,7048,r1 }
	{ st4	[r0],r15; nop.m	0x0; nop.i	0x0; }
	{ st4	[r0],r14; nop.i	0x0; (p07) br.cond.dptk.few	40000000000B4860 }

l40000000000B47A0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r33; (p06) br.cond.dpnt.few	40000000000B47C0 }

l40000000000B47B0:
	{ nop.m	0x0; addl	r37,2,r0; br.call.sptk.many	b0,jump_to_top_level }

l40000000000B47C0:
	{ addl	r14,-10260,r1; nop.m	0x0; addl	r32,-10652,r1; }
	{ ld8	r14,[r14]; ld8	r32,[r32]; nop.i	0x0; }
	{ ld8	r37,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ adds	r1,0x0,r36; nop.m	0x0; addl	r37,10,r0 }
	{ ld8	r38,[r32]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BD80; }
	{ nop.m	0x0; adds	r1,0x0,r36; nop.i	0x0 }
	{ ld8	r37,[r32]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ adds	r1,0x0,r36; addl	r14,6516,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.spnt.few	40000000000B47B0 }

l40000000000B4860:
	{ addl	r14,6512,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000B48D0; }

l40000000000B4890:
	{ cmp4.eq	p06,p07,0x0,r33; addl	r37,2,r0; (p06) br.cond.spnt.few	40000000000B48C0; }

l40000000000B48A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,signal_is_trapped; }
	{ adds	r1,0x0,r36; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000000B47B0 }

l40000000000B48C0:
	{ nop.m	0x0; addl	r37,3,r0; br.call.sptk.many	b0,jump_to_top_level; }

l40000000000B48D0:
	{ addl	r14,6540,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.sptk.few	40000000000B4890 }

l40000000000B4900:
	{ nop.m	0x0; addl	r37,2,r0; br.call.sptk.many	b0,jump_to_top_level; }

l40000000000B4910:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000B4920; br.ret	b0; }

l40000000000B4930:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,bashline_reset; }
	{ adds	r1,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,unlink_fifo_list; }
	{ adds	r1,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,run_unwind_protects; }
	{ adds	r1,0x0,r36; ld4	r14,[r32]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; addl	r14,8364,r1; addl	r15,7028,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r0],r14; nop.m	0x0; addl	r14,9032,r1 }
	{ st4	[r0],r15; nop.m	0x0; addl	r15,8360,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r0],r14; nop.m	0x0; addl	r14,7044,r1 }
	{ st4	[r0],r15; nop.m	0x0; addl	r15,8356,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; st4	[r0],r14; addl	r14,7048,r1 }
	{ st4	[r0],r15; nop.m	0x0; nop.i	0x0; }
	{ st4	[r0],r14; nop.i	0x0; (p06) br.cond.dptk.few	40000000000B47A0 }

l40000000000B4A20:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000B4860; }
40000000000B4A30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; sigint_sighandler: 40000000000B4A40
sigint_sighandler proc
	{ addl	r14,7684,r1; nop.m	0x0; addl	r15,7672,r1; }
	{ ld4.acq	r17,[r14]; ld4	r16,[r15]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r17; (p07) ld4.acq	r17,[r14]; nop.i	0x0; }

l40000000000B4A6C:
	{ nop; nop; zxt1	r32,r64 }

l40000000000B4A7C:
	{ Invalid; (p16) cmp.lt.unc	p04,p08,r3,r108; nop }

l40000000000B4A86:
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD78386; (p34) nop; break.i	0x80000 }

l40000000000B4A90:
	{ nop.m	0x0; addl	r14,9044,r1; adds	r32,0x80,r32 }
	{ st4	[r0],r15; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; st4	[r32],r14; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x1,0x0,0x0; nop.i	0x0; br.cond.sptk.many	throw_to_top_level; }
40000000000B4AD0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000B4AE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B4AF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; set_signal_handler: 40000000000B4B00
;;   Called from:
;;     4000000000023B0C (in read_command)
;;     4000000000023B9C (in read_command)
;;     40000000000240EC (in reader_loop)
;;     400000000005015C (in setup_async_signals)
;;     400000000005018C (in setup_async_signals)
;;     400000000007719C (in fn4000000000077140)
;;     400000000007C79C (in ignore_tty_job_signals)
;;     400000000007C7BC (in ignore_tty_job_signals)
;;     400000000007C7DC (in ignore_tty_job_signals)
;;     400000000007C81C (in default_tty_job_signals)
;;     400000000007C83C (in default_tty_job_signals)
;;     400000000007C85C (in default_tty_job_signals)
;;     400000000007EE8C (in initialize_job_signals)
;;     400000000007EEBC (in initialize_job_signals)
;;     400000000007EEEC (in initialize_job_signals)
;;     400000000007EF3C (in initialize_job_signals)
;;     400000000007EF5C (in initialize_job_signals)
;;     400000000007EF7C (in initialize_job_signals)
;;     400000000007EF9C (in initialize_job_signals)
;;     400000000007F58C (in initialize_job_control)
;;     400000000007F5CC (in initialize_job_control)
;;     400000000007F7DC (in initialize_job_control)
;;     400000000008040C (in wait_for)
;;     400000000008054C (in wait_for)
;;     400000000008057C (in wait_for)
;;     400000000008532C (in set_sigchld_handler)
;;     40000000000AC4CC (in initialize_traps)
;;     40000000000AC4EC (in initialize_traps)
;;     40000000000AC53C (in initialize_traps)
;;     40000000000AC55C (in initialize_traps)
;;     40000000000AC5AC (in initialize_traps)
;;     40000000000AC5CC (in initialize_traps)
;;     40000000000AC65C (in initialize_traps)
;;     40000000000AC67C (in initialize_traps)
;;     40000000000AD11C (in fn40000000000ACF00)
;;     40000000000AD83C (in set_sigint_handler)
;;     40000000000AD87C (in set_sigint_handler)
;;     40000000000AD8BC (in set_sigint_handler)
;;     40000000000ADB0C (in set_signal)
;;     40000000000ADB2C (in set_signal)
;;     40000000000ADC7C (in set_signal)
;;     40000000000ADCFC (in set_signal)
;;     40000000000AE00C (in get_all_original_signals)
;;     40000000000AE02C (in get_all_original_signals)
;;     40000000000AE3BC (in restore_default_signal)
;;     40000000000AE40C (in restore_default_signal)
;;     40000000000AE42C (in restore_default_signal)
;;     40000000000AE73C (in ignore_signal)
;;     40000000000AE77C (in ignore_signal)
;;     40000000000AE79C (in ignore_signal)
;;     40000000000B4BEC (in unset_sigwinch_handler)
;;     40000000000B4C2C (in set_sigwinch_handler)
;;     40000000000B4DFC (in termsig_handler)
;;     40000000000B4DFC (in termsig_handler)
;;     40000000000B4F9C (in termsig_handler)
;;     40000000000B537C (in initialize_signals)
;;     40000000000B53EC (in initialize_signals)
;;     40000000000B540C (in initialize_signals)
;;     40000000000B54EC (in initialize_signals)
;;     40000000001041AC (in fn4000000000104180)
;;     400000000010601C (in read_builtin)
;;     400000000010D52C (in source_builtin)
;;     400000000010D6EC (in suspend_builtin)
;;     400000000010D6EC (in suspend_builtin)
set_signal_handler proc
	{ alloc	r36,ar.pfs,0x9,0x0,0x6; adds	r12,0xFFFFFFFFFFFFFEE0,r12; nop.b	0x0 }
	{ cmp4.eq	p06,p07,0x11,r32; mov	r35,b3; adds	r37,0x0,r1; }
	{ (p07) adds	r14,0xA8,r12; (p06) movl	r15,0x10000000 }

l40000000000B4B26:
	{ adds	r0,0xFFFFFFFFFFFFE000,r0; Invalid; (p32) nop.b	0x8C408 }

l40000000000B4B30:
	{ adds	r34,0xA0,r12; adds	r38,0xB0,r12; (p06) adds	r14,0xA8,r12 }

l40000000000B4B40:
	{ st8	[r33],r34; (p07) st8	[r0],r14; nop.i	0x0 }

l40000000000B4B4C:
	{ Invalid; Invalid; break.i	0x1000 }

l40000000000B4B56:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; (p32) nop; (p16) nop }
	{ Invalid; nop; (p48) nop }
	{ Invalid; (p32) nop; (p32) nop }
	{ add	r0,r0,r1; Invalid; nop }
	{ break.m	0xAA024; nop; break.i	0x80000 }
	{ Invalid; (p34) nop; Invalid }

;; unset_sigwinch_handler: 40000000000B4BC0
unset_sigwinch_handler proc
	{ alloc	r16,ar.pfs,0x2,0x0,0x2; nop.m	0x0; addl	r14,7700,r1; }
	{ addl	r32,28,r0; ld8	r33,[r14]; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	set_signal_handler; }
40000000000B4BF0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; set_sigwinch_handler: 40000000000B4C00
;;   Called from:
;;     40000000000B541C (in initialize_signals)
set_sigwinch_handler proc
	{ alloc	r33,ar.pfs,0x5,0x0,0x3; addl	r36,-10052,r1; mov	r32,b0 }
	{ adds	r34,0x0,r1; nop.m	0x0; addl	r35,28,r0 }
	{ nop.m	0x0; ld8	r36,[r36]; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ addl	r14,7700,r1; nop.m	0x0; mov.spnt	b0,r32,40000000000B4C40; }
	{ st8	[r8],r14; nop.i	0x0; br.ret	b0; }
40000000000B4C60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B4C70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; termsig_handler: 40000000000B4C80
;;   Called from:
;;     4000000000023A1C (in read_command)
;;     400000000002414C (in reader_loop)
;;     4000000000029E8C (in fn4000000000029100)
;;     4000000000029F8C (in fn4000000000029100)
;;     4000000000029FEC (in fn4000000000029100)
;;     400000000002A8EC (in read_secondary_line)
;;     400000000002A96C (in read_secondary_line)
;;     400000000005044C (in shell_execve)
;;     40000000000544EC (in execute_command_internal)
;;     400000000005E73C (in execute_command)
;;     400000000007DADC (in fn400000000007D580)
;;     400000000007E63C (in fn400000000007D580)
;;     400000000008066C (in wait_for)
;;     40000000000807CC (in wait_for)
;;     40000000000808CC (in wait_for)
;;     4000000000080B4C (in wait_for)
;;     4000000000081C9C (in wait_for_background_pids)
;;     40000000000AFF8C (in buffered_getchar)
;;     40000000000B009C (in buffered_getchar)
;;     40000000000B058C (in getc_with_restart)
;;     40000000000B063C (in getc_with_restart)
;;     40000000000B51AC (in termsig_sighandler)
;;     40000000000C6406 (in brace_expand)
;;     40000000000DCF4C (in fn40000000000DCB80)
;;     40000000000FA54C (in fc_builtin)
;;     40000000000FCC2C (in help_builtin)
;;     40000000000FDBFC (in help_builtin)
;;     40000000000FEC3C (in history_builtin)
;;     40000000001204EC (in glob_vector)
;;     400000000012175C (in glob_filename)
termsig_handler proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x4; addl	r14,7692,r1; mov	r33,b1 }
	{ adds	r35,0x0,r1; ld4	r15,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r15; addl	r15,1,r0; (p06) br.cond.dpnt.few	40000000000B4E40; }

l40000000000B4CB0:
	{ st4	[r15],r14; addl	r14,7676,r1; cmp4.eq	p07,p06,0x2,r32; }
	{ st4.rel	[r0],r14; addl	r14,6512,r1; (p07) br.cond.dpnt.few	40000000000B4FE0; }

l40000000000B4CD0:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	40000000000B4D20; }

l40000000000B4CF0:
	{ cmp4.eq	p07,p06,0x6,r32; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B4D30; }

l40000000000B4D00:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,maybe_save_shell_history; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l40000000000B4D20:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x1,r32; (p07) br.cond.dpnt.few	40000000000B4E60 }

l40000000000B4D30:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,end_job_control; }
	{ adds	r1,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,unlink_fifo_list; }
	{ adds	r1,0x0,r35; addl	r14,7028,r1; nop.i	0x0; }
	{ nop.m	0x0; st4	[r0],r14; addl	r14,8360,r1; }
	{ nop.m	0x0; st4	[r0],r14; addl	r14,8356,r1; }
	{ nop.m	0x0; st4	[r0],r14; addl	r14,8364,r1; }
	{ nop.m	0x0; st4	[r0],r14; addl	r14,9032,r1; }
	{ nop.m	0x0; st4	[r0],r14; addl	r14,7044,r1; }
	{ nop.m	0x0; st4	[r0],r14; addl	r14,7048,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,run_exit_trap; }
	{ adds	r36,0x0,r32; nop.m	0x0; adds	r37,0x0,r0 }
	{ adds	r1,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B1A0; }
	{ adds	r1,0x0,r35; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r37,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B520; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l40000000000B4E40:
	{ nop.m	0x0; mov.i	ar.pfs,r34; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000B4E50; br.ret	b0 }

l40000000000B4E60:
	{ addl	r14,6516,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; addl	r14,9028,r1; (p06) br.cond.dpnt.few	40000000000B4EC0; }

l40000000000B4E90:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; and	r14,0x24,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000B4D30 }

l40000000000B4EC0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,hangup_all_jobs; }
	{ adds	r1,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,end_job_control; }
	{ adds	r1,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,unlink_fifo_list; }
	{ adds	r1,0x0,r35; addl	r14,7028,r1; nop.i	0x0; }
	{ nop.m	0x0; st4	[r0],r14; addl	r14,8360,r1; }
	{ nop.m	0x0; st4	[r0],r14; addl	r14,8356,r1; }
	{ nop.m	0x0; st4	[r0],r14; addl	r14,8364,r1; }
	{ nop.m	0x0; st4	[r0],r14; addl	r14,9032,r1; }
	{ nop.m	0x0; st4	[r0],r14; addl	r14,7044,r1; }
	{ nop.m	0x0; st4	[r0],r14; addl	r14,7048,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,run_exit_trap; }
	{ adds	r36,0x0,r32; nop.m	0x0; adds	r1,0x0,r35 }
	{ adds	r37,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B1A0; }
	{ adds	r1,0x0,r35; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r37,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B520; }
	{ nop.m	0x0; adds	r1,0x0,r35; br.cond.sptk.few	40000000000B4E40 }

l40000000000B4FE0:
	{ addl	r36,2,r0; nop.i	0x0; br.call.sptk.many	b0,signal_is_trapped; }
	{ adds	r1,0x0,r35; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dpnt.few	40000000000B5050; }

l40000000000B5000:
	{ addl	r14,6512,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	40000000000B4D30 }

l40000000000B5030:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,maybe_save_shell_history; }
	{ nop.m	0x0; adds	r1,0x0,r35; br.cond.sptk.few	40000000000B4D20 }

l40000000000B5050:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,run_interrupt_trap; }
	{ nop.m	0x0; adds	r1,0x0,r35; br.cond.sptk.few	40000000000B5000; }
40000000000B5070 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; termsig_sighandler: 40000000000B5080
termsig_sighandler proc
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r32; cmp4.ltu	p06,p07,0x1,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0xD,r32; (p07) br.cond.dptk.few	40000000000B51B0 }

l40000000000B50A0:
	{ nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFFF2,r32; nop.i	0x0; }
	{ cmp4.ltu	p06,p07,0x1,r14; adds	r14,0xFFFFFFFFFFFFFFE8,r32; (p07) br.cond.dpnt.few	40000000000B51B0; }

l40000000000B50C0:
	{ cmp4.ltu	p06,p07,0x1,r14; and	r14,0xFFFFFFFFFFFFFFEF,r32; (p07) br.cond.dpnt.few	40000000000B51B0; }

l40000000000B50D0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0xA,r14; (p07) br.cond.dptk.few	40000000000B51B0; }

l40000000000B50E0:
	{ addl	r15,7676,r1; cmp4.eq	p07,p06,0xC,r32; (p07) br.cond.dpnt.few	40000000000B51B0; }

l40000000000B50F0:
	{ ld4.acq	r14,[r15]; cmp4.eq	p06,p07,r14,r32; addl	r14,7668,r1; }
	{ (p06) st4.rel	[r32],r15; (p07) ld4	r16,[r14]; (p06) addl	r15,1,r0; }

l40000000000B5106:
	{ (p08) adds	r0,0xFFFFFFFFFFFFF00E,r16; (p07) nop; (p01) nop; }

l40000000000B510C:
	{ Invalid; Invalid; break.b	0x1000; }

l40000000000B5110:
	{ (p06) st4	[r15],r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B5140; }

l40000000000B5116:
	{ chk.a.nc	r0,3FFFFFFFFF0B5916; nop; nop }

l40000000000B5120:
	{ st4.rel	[r32],r15; cmp4.eq	p06,p07,0x0,r16; (p06) br.ret	b0; }

l40000000000B5130:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000B5140:
	{ addl	r15,6512,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p07) br.cond.dptk.few	40000000000B51F0 }

l40000000000B5170:
	{ addl	r15,9148,r1; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; st4	[r0],r15; nop.i	0x0 }

l40000000000B5190:
	{ nop.m	0x0; st4	[r0],r14; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x1,0x0,0x0; nop.i	0x0; br.cond.sptk.many	termsig_handler }

l40000000000B51B0:
	{ addl	r14,7668,r1; nop.m	0x0; addl	r15,7676,r1; }
	{ ld4	r16,[r14]; st4.rel	[r32],r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r16; (p07) br.cond.dptk.few	40000000000B5140 }

l40000000000B51E0:
	{ nop.m	0x0; nop.i	0x0; br.ret	b0 }

l40000000000B51F0:
	{ addl	r15,6516,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	40000000000B5170; }

l40000000000B5220:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x1,r32; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0xF,r32; (p06) br.cond.dptk.few	40000000000B5170 }

l40000000000B5240:
	{ addl	r15,6468,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	40000000000B5170 }

l40000000000B5270:
	{ addl	r15,-10404,r1; ld8	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r15,0x3; (p06) br.cond.dptk.few	40000000000B5190 }

l40000000000B52A0:
	{ addl	r15,9148,r1; nop.m	0x0; nop.i	0x0; }
	{ st4	[r0],r15; nop.i	0x0; br.cond.sptk.few	40000000000B5190; }

;; initialize_signals: 40000000000B52C0
;;   Called from:
;;     40000000000F825C (in exec_builtin)
initialize_signals proc
	{ alloc	r34,ar.pfs,0x7,0x0,0x4; addl	r32,6516,r1; nop.b	0x0 }
	{ addl	r36,25124,r1; adds	r35,0x0,r1; mov	r33,b1; }
	{ nop.m	0x0; ld4	r14,[r32]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B5450; }

l40000000000B5300:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r35; adds	r36,0x0,r0; adds	r37,0x0,r0; }
	{ nop.m	0x0; addl	r38,25124,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r35; addl	r37,17,r0; addl	r36,25124,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B700; }
	{ adds	r1,0x0,r35; nop.m	0x0; addl	r36,3,r0 }
	{ addl	r37,1,r0; nop.m	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ ld4	r14,[r32]; nop.m	0x0; adds	r1,0x0,r35; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000B53D0 }

l40000000000B53A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,initialize_job_signals; }
	{ adds	r1,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000B53C0; br.ret	b0 }

l40000000000B53D0:
	{ addl	r37,-10004,r1; nop.m	0x0; addl	r36,2,r0; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ addl	r36,15,r0; nop.m	0x0; addl	r37,1,r0 }
	{ adds	r1,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,set_sigwinch_handler; }
	{ adds	r1,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,initialize_job_signals; }
	{ adds	r1,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000B5440; br.ret	b0; }

l40000000000B5450:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,initialize_terminating_signals; }
	{ adds	r1,0x0,r35; addl	r36,25124,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r35; adds	r36,0x0,r0; adds	r37,0x0,r0; }
	{ nop.m	0x0; addl	r38,25124,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r35; addl	r37,17,r0; addl	r36,25124,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B700; }
	{ adds	r1,0x0,r35; nop.m	0x0; addl	r36,3,r0 }
	{ addl	r37,1,r0; nop.m	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ ld4	r14,[r32]; nop.m	0x0; adds	r1,0x0,r35; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000B53A0 }

l40000000000B5510:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000B53D0; }
40000000000B5520 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000B5530 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; fn40000000000B5540: 40000000000B5540
;;   Called from:
;;     400000000001C90C (in fn400000000001C8C0)
;;     40000000000B560C (in fn40000000000B55C0)
;;     40000000000B720C (in fn40000000000B7000)
;;     40000000000B720C (in fn40000000000B7000)
;;     40000000000B72AC (in fn40000000000B7000)
;;     40000000000B77BC (in fn40000000000B7680)
;;     40000000000B7BEC (in fn40000000000B7840)
;;     40000000000B7FDC (in fn40000000000B7CC0)
;;     40000000000B81AC (in fn40000000000B7CC0)
;;     40000000000B81EC (in fn40000000000B7CC0)
;;     40000000000B877C (in test_command)
;;     40000000000B8BCC (in test_command)
fn40000000000B5540 proc
	{ alloc	r35,ar.pfs,0x7,0x0,0x5; mov	r34,b2; nop.b	0x0 }
	{ adds	r36,0x0,r1; adds	r37,0x0,r32; adds	r38,0x0,r33; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,builtin_error; }
	{ adds	r1,0x0,r36; addl	r15,2,r0; addl	r38,1,r0; }
	{ addl	r37,19668,r1; addl	r14,7708,r1; nop.i	0x0 }
	{ nop.m	0x0; st4	[r15],r14; br.call.sptk.many	b0,fn400000000001BBE0; }
	{ nop.m	0x0; break.f	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

;; fn40000000000B55C0: 40000000000B55C0
;;   Called from:
;;     40000000000B55BC (in fn40000000000B5540)
;;     40000000000B74BC (in fn40000000000B7400)
;;     40000000000B7B6C (in fn40000000000B7840)
;;     40000000000B814C (in fn40000000000B7CC0)
;;     40000000000B815C (in fn40000000000B7CC0)
;;     40000000000B816C (in fn40000000000B7CC0)
;;     40000000000B8A7C (in test_command)
fn40000000000B55C0 proc
	{ alloc	r33,ar.pfs,0x6,0x0,0x3; addl	r36,-9252,r1; mov	r32,b0 }
	{ adds	r34,0x0,r1; ld8	r36,[r36]; adds	r35,0x0,r0 }
	{ addl	r37,5,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ nop.m	0x0; adds	r1,0x0,r34; adds	r35,0x0,r8 }
	{ nop.m	0x0; adds	r36,0x0,r0; br.call.sptk.many	b0,fn40000000000B5540; }
	{ nop.m	0x0; break.f	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

;; fn40000000000B5640: 40000000000B5640
;;   Called from:
;;     40000000000B5616 (in fn40000000000B55C0)
;;     40000000000B5840 (in fn40000000000B5840)
;;     40000000000B60DC (in binary_test)
;;     40000000000B610C (in binary_test)
;;     40000000000B624C (in binary_test)
fn40000000000B5640 proc
	{ alloc	r37,ar.pfs,0xB,0x0,0x7; adds	r12,0xFFFFFFFFFFFFFEE0,r12; nop.b	0x0 }
	{ adds	r38,0x0,r1; mov	r36,b4; adds	r39,0x0,r32; }
	{ adds	r40,0xA0,r12; nop.i	0x0; br.call.sptk.many	b0,sh_stat; }
	{ cmp4.lt	p07,p06,r8,r0; adds	r1,0x0,r38; adds	r35,0x0,r8 }
	{ adds	r39,0x0,r33; adds	r40,0x10,r12; (p07) br.cond.dpnt.few	fn40000000000B5840; }

;; fn40000000000B5690: 40000000000B5690
;;   Called from:
;;     40000000000B568C (in fn40000000000B5640)
;;     40000000000B568C (in fn40000000000B5640)
;;     40000000000B568C (in fn40000000000B5640)
;;     40000000000B568C (in fn40000000000B5640)
;;     40000000000B585C (in fn40000000000B5840)
;;     40000000000B5870 (in fn40000000000B5840)
fn40000000000B5690 proc
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_stat; }
	{ adds	r1,0x0,r38; cmp4.lt	p07,p06,r8,r0; (p07) br.cond.dpnt.few	40000000000B5760; }

l40000000000B56B0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x1,r34; (p06) br.cond.dpnt.few	40000000000B5780; }

l40000000000B56C0:
	{ cmp4.eq	p06,p07,0x2,r34; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B5800; }

l40000000000B56D0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r34; (p07) br.cond.dptk.few	40000000000B5740; }

l40000000000B56E0:
	{ cmp4.lt	p06,p07,r8,r35; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B57E0; }

l40000000000B56F0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	40000000000B5740 }

l40000000000B5700:
	{ adds	r14,0xE8,r12; ld8	r15,[r14]; adds	r14,0x58,r12; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.lt	p06,p07,r14,r15; (p06) br.cond.dpnt.few	40000000000B57E0; }

l40000000000B5730:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000B5740:
	{ adds	r8,0x0,r0; mov.i	ar.pfs,r37; mov.spnt	b0,r36,40000000000B5740 }
	{ nop.m	0x0; adds	r12,0x120,r12; br.ret	b0 }

l40000000000B5760:
	{ cmp4.eq	p06,p07,0x2,r34; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B5740; }

l40000000000B5770:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x1,r34; (p07) br.cond.dptk.few	40000000000B56C0; }

l40000000000B5780:
	{ cmp4.lt	p06,p07,r35,r8; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B57E0; }

l40000000000B5790:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	40000000000B5740 }

l40000000000B57A0:
	{ adds	r14,0xE8,r12; ld8	r15,[r14]; adds	r14,0x58,r12; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.lt	p06,p07,r15,r14; (p07) br.cond.dptk.few	40000000000B5740; }

l40000000000B57D0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000B57E0:
	{ addl	r8,1,r0; mov.i	ar.pfs,r37; mov.spnt	b0,r36,40000000000B57E0 }
	{ nop.m	0x0; adds	r12,0x120,r12; br.ret	b0; }

l40000000000B5800:
	{ adds	r39,0x0,r32; adds	r40,0x0,r33; nop.i	0x0 }
	{ adds	r41,0xA0,r12; adds	r42,0x10,r12; br.call.sptk.many	b0,same_file; }
	{ adds	r1,0x0,r38; mov.i	ar.pfs,r37; mov.spnt	b0,r36,40000000000B5820 }
	{ nop.m	0x0; adds	r12,0x120,r12; br.ret	b0; }

;; fn40000000000B5840: 40000000000B5840
;;   Called from:
;;     40000000000B568C (in fn40000000000B5640)
;;     40000000000B568C (in fn40000000000B5640)
fn40000000000B5840 proc
	{ cmp4.eq	p07,p06,0x2,r34; nop.m	0x0; adds	r39,0x0,r33 }
	{ adds	r40,0x10,r12; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000B5740; }

l40000000000B5860:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_stat; }
	{ nop.m	0x0; adds	r1,0x0,r38; br.cond.sptk.few	40000000000B56B0; }

l40000000000B5880:
	{ alloc	r39,ar.pfs,0xB,0x0,0x9; adds	r12,0xFFFFFFFFFFFFFFE0,r12; mov	r38,b6 }
	{ nop.m	0x0; adds	r40,0x0,r1; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r35,0x1; (p06) br.cond.dptk.few	40000000000B5920 }

l40000000000B58B0:
	{ adds	r37,0x20,r12; adds	r41,0x0,r32; adds	r36,0x18,r12; }
	{ adds	r42,0x0,r37; nop.i	0x0; br.call.sptk.many	b0,evalexp; }
	{ nop.m	0x0; ld4	r14,[r37]; adds	r1,0x0,r40 }
	{ nop.m	0x0; st8	[r8],r36; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dpnt.few	40000000000B59E0 }

l40000000000B5900:
	{ adds	r8,0x0,r0; mov.i	ar.pfs,r39; mov.spnt	b0,r38,40000000000B5900 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0; }

l40000000000B5920:
	{ adds	r36,0x18,r12; nop.m	0x0; adds	r41,0x0,r32; }
	{ adds	r42,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,legal_number; }
	{ cmp4.eq	p07,p06,0x0,r8; nop.m	0x0; adds	r1,0x0,r40; }
	{ (p07) adds	r41,0x0,r32; nop.i	0x0; (p07) br.call.spnt.many	b0,fn400000000001C8C0; }

l40000000000B5956:
	{ chk.a.nc	f0,3FFFFFFFFF0B6156; (p32) nop; (p16) nop }

l40000000000B5960:
	{ adds	r41,0x0,r33; adds	r42,0x10,r12; br.call.sptk.many	b0,legal_number; }
	{ cmp4.eq	p07,p06,0x0,r8; adds	r1,0x0,r40; (p07) br.cond.spnt.few	40000000000B5BC0; }

l40000000000B5980:
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x5,r34; (p06) br.cond.dptk.few	40000000000B5900 }

l40000000000B5990:
	{ addl	r14,-9180,r1; addp4	r34,r34,r0; adds	r15,0x10,r12 }
	{ ld8	r8,[r36]; ld8	r14,[r14]; nop.i	0x0; }
	{ shladd	r34,r34,0x3,r14; ld8	r14,[r34]; nop.i	0x0; }
	{ add	r34,r34,r14; ld8	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r34,40000000000B59D0; br.cond	b6; }

l40000000000B59E0:
	{ adds	r41,0x0,r33; adds	r42,0x0,r37; br.call.sptk.many	b0,evalexp; }
	{ ld4	r14,[r37]; adds	r15,0x10,r12; adds	r1,0x0,r40; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; nop.i	0x0 }
	{ st8	[r8],r15; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000B5900; }

l40000000000B5A20:
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x5,r34; (p06) br.cond.dptk.few	40000000000B5900 }

l40000000000B5A30:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000B5990; }
40000000000B5A40 0B 38 38 10 06 B0 E1 08 00 00 48 00 00 00 04 00 .88.......H.....
40000000000B5A50 09 00 00 00 01 C0 E1 00 00 00 42 00 00 00 04 00 ..........B.....
40000000000B5A60 02 40 00 1C 00 21 00 38 01 55 00 00 60 0A 00 07 .@...!.8.U..`...
40000000000B5A70 18 00 00 00 01 00 C0 00 31 00 42 80 08 00 84 00 ........1.B.....
40000000000B5A80 0B 30 38 10 07 B0 E1 08 00 00 48 00 00 00 04 00 .08.......H.....
40000000000B5A90 09 00 00 00 01 C0 E1 00 00 00 42 00 00 00 04 00 ..........B.....
40000000000B5AA0 02 40 00 1C 00 21 00 38 01 55 00 00 60 0A 00 07 .@...!.8.U..`...
40000000000B5AB0 18 00 00 00 01 00 C0 00 31 00 42 80 08 00 84 00 ........1.B.....
40000000000B5AC0 0B 30 20 1C 07 B0 E1 08 00 00 48 00 00 00 04 00 .0 .......H.....
40000000000B5AD0 09 00 00 00 01 C0 E1 00 00 00 42 00 00 00 04 00 ..........B.....
40000000000B5AE0 02 40 00 1C 00 21 00 38 01 55 00 00 60 0A 00 07 .@...!.8.U..`...
40000000000B5AF0 18 00 00 00 01 00 C0 00 31 00 42 80 08 00 84 00 ........1.B.....
40000000000B5B00 0B 38 38 10 06 B8 E1 08 00 00 48 00 00 00 04 00 .88.......H.....
40000000000B5B10 09 00 00 00 01 C0 E1 00 00 00 42 00 00 00 04 00 ..........B.....
40000000000B5B20 02 40 00 1C 00 21 00 38 01 55 00 00 60 0A 00 07 .@...!.8.U..`...
40000000000B5B30 18 00 00 00 01 00 C0 00 31 00 42 80 08 00 84 00 ........1.B.....
40000000000B5B40 0B 30 38 10 07 B8 E1 08 00 00 48 00 00 00 04 00 .08.......H.....
40000000000B5B50 09 00 00 00 01 C0 E1 00 00 00 42 00 00 00 04 00 ..........B.....
40000000000B5B60 02 40 00 1C 00 21 00 38 01 55 00 00 60 0A 00 07 .@...!.8.U..`...
40000000000B5B70 18 00 00 00 01 00 C0 00 31 00 42 80 08 00 84 00 ........1.B.....
40000000000B5B80 0B 38 20 1C 06 B0 E1 08 00 00 48 00 00 00 04 00 .8 .......H.....
40000000000B5B90 09 00 00 00 01 C0 E1 00 00 00 42 00 00 00 04 00 ..........B.....
40000000000B5BA0 02 40 00 1C 00 21 00 38 01 55 00 00 60 0A 00 07 .@...!.8.U..`...
40000000000B5BB0 19 00 00 00 01 00 C0 00 31 00 42 80 08 00 84 00 ........1.B.....

l40000000000B5BC0:
	{ nop.m	0x0; adds	r41,0x0,r33; br.call.sptk.many	b0,fn400000000001C8C0; }
	{ nop.m	0x0; break.f	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

;; binary_test: 40000000000B5C00
;;   Called from:
;;     40000000000B715C (in fn40000000000B7000)
binary_test proc
	{ alloc	r37,ar.pfs,0xA,0x0,0x7; ld1	r14,[r32]; mov	r36,b4 }
	{ adds	r38,0x0,r1; nop.m	0x0; and	r17,0x1,r35; }
	{ nop.m	0x0; sxt1	r14,r14; sxt1	r15,r14 }
	{ cmp4.eq	p07,p06,0x3D,r14; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000B5D50; }

l40000000000B5C40:
	{ nop.m	0x0; and	r15,0xFFFFFFFFFFFFFFFD,r15; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x3C,r15; adds	r15,0x1,r32; (p07) br.cond.dpnt.few	40000000000B5D10; }

l40000000000B5C60:
	{ ld1	r15,[r15]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	40000000000B5E00; }

l40000000000B5C80:
	{ adds	r32,0x2,r32; nop.m	0x0; cmp4.eq	p07,p06,0x21,r14; }
	{ nop.m	0x0; ld1	r16,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r16,r16; (p07) br.cond.dpnt.few	40000000000B5E90; }

l40000000000B5CB0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x74,r16; (p07) br.cond.dpnt.few	40000000000B5F40; }

l40000000000B5CC0:
	{ cmp4.eq	p07,p06,0x65,r15; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B5FA0; }

l40000000000B5CD0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x65,r16; (p07) br.cond.dpnt.few	40000000000B5FF0 }

l40000000000B5CE0:
	{ adds	r8,0x0,r0; nop.m	0x0; nop.i	0x0 }

l40000000000B5CF0:
	{ nop.m	0x0; mov.i	ar.pfs,r37; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000B5D00; br.ret	b0 }

l40000000000B5D10:
	{ adds	r32,0x2,r32; ld1	r15,[r15]; cmp4.eq	p07,p06,0x21,r14; }
	{ ld1	r16,[r32]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; sxt1	r16,r16; (p06) br.cond.dptk.few	40000000000B5CB0 }

l40000000000B5D40:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000B5E90 }

l40000000000B5D50:
	{ adds	r14,0x1,r32; ld1	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p07) br.cond.dptk.few	40000000000B5EE0; }

l40000000000B5D80:
	{ cmp4.eq	p06,p07,0x0,r17; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B6150; }

l40000000000B5D90:
	{ ld1	r15,[r33]; ld1	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r15,r14; (p06) br.cond.dptk.few	40000000000B5CE0 }

l40000000000B5DC0:
	{ adds	r39,0x0,r33; adds	r40,0x0,r34; br.call.sptk.many	b0,fn400000000001A540; }
	{ cmp4.eq	p06,p07,0x0,r8; adds	r1,0x0,r38; mov.i	ar.pfs,r37; }
	{ (p06) addl	r8,1,r0; nop.m	0x0; mov.spnt	b0,r36,40000000000B5DE0; }

l40000000000B5DE6:
	{ break.m	0x4000; nop; cmp.lt	p00,p00,r0,r32 }
	{ Invalid; (p34) nop; (p48) nop; }

l40000000000B5DFC:
	{ cmp.eq	p00,p08,r33,r0; (p01) cmp.lt	p39,p18,r96,r11; (p32) cmp.eq.unc	p15,p28,r99,r97 }

l40000000000B5E00:
	{ addl	r15,6044,r1; cmp4.eq	p06,p07,0x3E,r14; adds	r39,0x0,r33 }
	{ adds	r40,0x0,r34; nop.m	0x0; (p06) addl	r14,1,r0; }

l40000000000B5E20:
	{ (p07) adds	r14,0x0,r0; ld4	r15,[r15]; nop.i	0x0; }

l40000000000B5E26:
	{ (p07) fwb; nop; break.b	0x80000 }
	{ (p03) chk.a.clr	r40,3FFFFFFFFF978F26; nop; break.b	0x80000 }

l40000000000B5E40:
	{ nop.m	0x0; tbit.z	p06,p07,r35,0x2; (p06) br.cond.dptk.few	40000000000B6050; }

l40000000000B5E50:
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B6110; }

l40000000000B5E60:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B440; }
	{ adds	r1,0x0,r38; extr.u	r8,r8,31,1; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000B5E80; br.ret	b0 }

l40000000000B5E90:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x3D,r15; (p06) br.cond.dptk.few	40000000000B5CB0; }

l40000000000B5EA0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r16; (p07) br.cond.dptk.few	40000000000B62E0; }

l40000000000B5EB0:
	{ cmp4.eq	p06,p07,0x74,r16; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B5CE0; }

l40000000000B5EC0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x65,r16; (p06) br.cond.dptk.few	40000000000B5CE0 }

l40000000000B5ED0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000B5FF0; }

l40000000000B5EE0:
	{ adds	r32,0x2,r32; nop.m	0x0; cmp4.eq	p07,p06,0x3D,r15; }
	{ nop.m	0x0; ld1	r16,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r16,r16; (p06) br.cond.dptk.few	40000000000B5CB0; }

l40000000000B5F10:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r16; (p07) br.cond.dptk.few	40000000000B5D80; }

l40000000000B5F20:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x74,r16; (p06) br.cond.dptk.few	40000000000B5CC0; }

l40000000000B5F30:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000B5F40:
	{ cmp4.eq	p06,p07,0x6C,r15; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B6250; }

l40000000000B5F50:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x6C,r15; (p06) br.cond.dptk.few	40000000000B6090; }

l40000000000B5F60:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x67,r15; (p07) br.cond.dptk.few	40000000000B5CE0 }

l40000000000B5F70:
	{ adds	r32,0x0,r33; nop.m	0x0; mov.spnt	b0,r36,40000000000B5F70 }
	{ adds	r33,0x0,r34; addl	r34,3,r0; mov.i	ar.pfs,r37; }
	{ alloc	r2,ar.pfs,0x4,0x0,0x0; nop.i	0x0; br.cond.sptk.many	40000000000B5880 }

l40000000000B5FA0:
	{ cmp4.eq	p06,p07,0x66,r16; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B6220; }

l40000000000B5FB0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x71,r16; (p07) br.cond.dptk.few	40000000000B5CE0 }

l40000000000B5FC0:
	{ adds	r32,0x0,r33; nop.m	0x0; mov.spnt	b0,r36,40000000000B5FC0 }
	{ adds	r33,0x0,r34; adds	r34,0x0,r0; mov.i	ar.pfs,r37; }
	{ alloc	r2,ar.pfs,0x4,0x0,0x0; nop.i	0x0; br.cond.sptk.many	40000000000B5880 }

l40000000000B5FF0:
	{ cmp4.eq	p06,p07,0x6C,r15; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B6280; }

l40000000000B6000:
	{ cmp4.eq	p06,p07,0x6E,r15; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B62B0; }

l40000000000B6010:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x67,r15; (p07) br.cond.dptk.few	40000000000B5CE0 }

l40000000000B6020:
	{ adds	r32,0x0,r33; nop.m	0x0; mov.spnt	b0,r36,40000000000B6020 }
	{ adds	r33,0x0,r34; addl	r34,5,r0; mov.i	ar.pfs,r37; }
	{ alloc	r2,ar.pfs,0x4,0x0,0x0; nop.i	0x0; br.cond.sptk.many	40000000000B5880 }

l40000000000B6050:
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B61E0; }

l40000000000B6060:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r38; extr.u	r8,r8,31,1; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000B6080; br.ret	b0 }

l40000000000B6090:
	{ cmp4.eq	p06,p07,0x6E,r15; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B60E0; }

l40000000000B60A0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x6F,r15; (p07) br.cond.dptk.few	40000000000B5CE0 }

l40000000000B60B0:
	{ adds	r32,0x0,r33; nop.m	0x0; mov.spnt	b0,r36,40000000000B60B0 }
	{ adds	r33,0x0,r34; addl	r34,1,r0; mov.i	ar.pfs,r37; }
	{ alloc	r2,ar.pfs,0x4,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000B5640 }

l40000000000B60E0:
	{ adds	r32,0x0,r33; nop.m	0x0; mov.spnt	b0,r36,40000000000B60E0 }
	{ adds	r33,0x0,r34; adds	r34,0x0,r0; mov.i	ar.pfs,r37; }
	{ alloc	r2,ar.pfs,0x4,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000B5640; }

l40000000000B6110:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B440; }
	{ cmp4.lt	p06,p07,0x0,r8; adds	r1,0x0,r38; mov.i	ar.pfs,r37; }
	{ (p06) addl	r8,1,r0; nop.m	0x0; mov.spnt	b0,r36,40000000000B6130; }

l40000000000B6136:
	{ break.m	0x4000; nop; cmp.lt	p00,p00,r0,r32 }
	{ Invalid; (p34) nop; (p32) nop; }

l40000000000B614C:
	{ cmp.lt	p00,p09,r33,r0; (p01) cmp.eq	p60,p18,r96,r14; zxt1	r64,r64 }

l40000000000B6150:
	{ addl	r14,7664,r1; adds	r39,0x0,r34; adds	r40,0x0,r33; }
	{ nop.m	0x0; ld4	r15,[r14]; addl	r14,7036,r1; }
	{ nop.m	0x0; nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; }
	{ ld4	r14,[r14]; cmp4.eq	p08,p09,0x0,r14; (p06) adds	r14,0x0,r0; }

l40000000000B6190:
	{ (p07) addl	r14,32,r0; (p08) adds	r41,0x0,r0; (p09) addl	r41,16,r0; }

l40000000000B6196:
	{ (p20) addl	r0,24832,r0; (p20) nop; (p16) nop }

l40000000000B619C:
	{ (p08) nop; break.x	0x1007291CA01000; }

l40000000000B61A0:
	{ or	r41,r14,r41; nop.i	0x0; br.call.sptk.many	b0,strmatch; }
	{ cmp4.eq	p06,p07,0x0,r8; adds	r1,0x0,r38; mov.i	ar.pfs,r37; }
	{ (p06) addl	r8,1,r0; nop.m	0x0; mov.spnt	b0,r36,40000000000B61C0; }

l40000000000B61C6:
	{ break.m	0x4000; nop; cmp.lt	p00,p00,r0,r32 }
	{ Invalid; (p34) nop; break.i	0x80000; }

l40000000000B61DC:
	{ Invalid; break.m	0x1000; break.i	0x1000 }

l40000000000B61E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ cmp4.lt	p06,p07,0x0,r8; adds	r1,0x0,r38; mov.i	ar.pfs,r37; }
	{ (p06) addl	r8,1,r0; nop.m	0x0; mov.spnt	b0,r36,40000000000B6200; }

l40000000000B6206:
	{ break.m	0x4000; nop; cmp.lt	p00,p00,r0,r32 }
	{ Invalid; (p34) nop; nop; }

l40000000000B621C:
	{ nop; (p04) invala; break.i	0x1000 }

l40000000000B6220:
	{ adds	r32,0x0,r33; nop.m	0x0; mov.spnt	b0,r36,40000000000B6220 }
	{ adds	r33,0x0,r34; addl	r34,2,r0; mov.i	ar.pfs,r37; }
	{ alloc	r2,ar.pfs,0x4,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000B5640 }

l40000000000B6250:
	{ adds	r32,0x0,r33; nop.m	0x0; mov.spnt	b0,r36,40000000000B6250 }
	{ adds	r33,0x0,r34; addl	r34,2,r0; mov.i	ar.pfs,r37; }
	{ alloc	r2,ar.pfs,0x4,0x0,0x0; nop.i	0x0; br.cond.sptk.many	40000000000B5880 }

l40000000000B6280:
	{ adds	r32,0x0,r33; nop.m	0x0; mov.spnt	b0,r36,40000000000B6280 }
	{ adds	r33,0x0,r34; addl	r34,4,r0; mov.i	ar.pfs,r37; }
	{ alloc	r2,ar.pfs,0x4,0x0,0x0; nop.i	0x0; br.cond.sptk.many	40000000000B5880 }

l40000000000B62B0:
	{ adds	r32,0x0,r33; nop.m	0x0; mov.spnt	b0,r36,40000000000B62B0 }
	{ adds	r33,0x0,r34; addl	r34,1,r0; mov.i	ar.pfs,r37; }
	{ alloc	r2,ar.pfs,0x4,0x0,0x0; nop.i	0x0; br.cond.sptk.many	40000000000B5880 }

l40000000000B62E0:
	{ cmp4.eq	p06,p07,0x0,r17; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B6370; }

l40000000000B62F0:
	{ ld1	r15,[r33]; ld1	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r15,r14; nop.i	0x0; }
	{ nop.m	0x0; (p06) addl	r8,1,r0; (p06) br.cond.dptk.few	40000000000B5CF0 }

l40000000000B632C:
	{ (p14) cmp.eq.unc	p63,p17,r63,r37; zxt1	r32,r64; (p05) epc }

l40000000000B6330:
	{ adds	r39,0x0,r33; adds	r40,0x0,r34; br.call.sptk.many	b0,fn400000000001A540; }
	{ cmp4.eq	p07,p06,0x0,r8; adds	r1,0x0,r38; mov.i	ar.pfs,r37; }
	{ (p06) addl	r8,1,r0; nop.m	0x0; mov.spnt	b0,r36,40000000000B6350; }

l40000000000B6356:
	{ break.m	0x4000; nop; cmp.lt	p00,p00,r0,r32 }
	{ Invalid; (p34) nop; (p32) nop; }

l40000000000B636C:
	{ cmp.lt	p00,p09,r33,r0; (p01) cmp.eq	p60,p18,r96,r14; zxt1	r64,r64 }

l40000000000B6370:
	{ addl	r14,7664,r1; adds	r39,0x0,r34; adds	r40,0x0,r33; }
	{ nop.m	0x0; ld4	r15,[r14]; addl	r14,7036,r1; }
	{ nop.m	0x0; nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; }
	{ ld4	r14,[r14]; cmp4.eq	p08,p09,0x0,r14; (p06) adds	r14,0x0,r0; }

l40000000000B63B0:
	{ (p07) addl	r14,32,r0; (p08) adds	r41,0x0,r0; (p09) addl	r41,16,r0; }

l40000000000B63B6:
	{ (p20) addl	r0,24832,r0; (p20) nop; (p16) nop }

l40000000000B63BC:
	{ (p08) nop; break.x	0x1007291CA01000; }

l40000000000B63C0:
	{ or	r41,r14,r41; nop.i	0x0; br.call.sptk.many	b0,strmatch; }
	{ cmp4.eq	p07,p06,0x0,r8; adds	r1,0x0,r38; mov.i	ar.pfs,r37; }
	{ (p06) addl	r8,1,r0; nop.m	0x0; mov.spnt	b0,r36,40000000000B63E0; }

l40000000000B63E6:
	{ break.m	0x4000; nop; cmp.lt	p00,p00,r0,r32 }
	{ Invalid; (p34) nop; Invalid; }

l40000000000B63FC:
	{ ldfd	f0,[r0]; Invalid; zxt2	r24,r79 }

;; unary_test: 40000000000B6400
;;   Called from:
;;     40000000000B74FC (in fn40000000000B7400)
;;     40000000000B75BC (in fn40000000000B7400)
;;     40000000000B763C (in fn40000000000B7400)
unary_test proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; adds	r12,0xFFFFFFFFFFFFFF60,r12; nop.b	0x0 }
	{ adds	r32,0x1,r32; adds	r36,0x0,r1; mov	r34,b2; }
	{ ld1	r14,[r32]; adds	r14,0xFFFFFFFFFFFFFFB9,r14; nop.i	0x0; }
	{ nop.m	0x0; zxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x33,r14; (p06) br.cond.dptk.few	40000000000B6500 }

l40000000000B6450:
	{ addl	r15,-9172,r1; ld8	r15,[r15]; nop.i	0x0; }
	{ shladd	r14,r14,0x3,r15; ld8	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; add	r14,r14,r15; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r14,40000000000B6480; br.cond	b6; }
40000000000B6490 11 28 01 42 00 21 60 82 30 00 42 00 78 4D 07 50 .(.B.!`.0.B.xM.P
40000000000B64A0 11 08 00 48 00 21 60 00 20 0E F3 03 60 00 00 42 ...H.!`. ...`..B
40000000000B64B0 09 78 F0 FB 51 27 00 00 00 02 00 C0 C1 62 00 84 .x..Q'.......b..
40000000000B64C0 09 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
40000000000B64D0 0B 78 10 1E 00 21 F0 00 3C 20 20 00 00 00 04 00 .x...!..<  .....
40000000000B64E0 11 00 00 00 01 00 70 70 3C 0C F1 03 60 01 00 43 ......pp<...`..C
40000000000B64F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

l40000000000B6500:
	{ adds	r8,0x0,r0; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; mov.i	ar.pfs,r35; mov.spnt	b0,r34,40000000000B6510 }
	{ nop.m	0x0; adds	r12,0xA0,r12; br.ret	b0 }
40000000000B6530 0B 40 00 42 00 10 00 00 00 02 00 00 01 40 50 00 .@.B.........@P.
40000000000B6540 0B 30 00 10 87 B9 81 08 00 00 48 00 00 00 04 00 .0........H.....
40000000000B6550 E2 40 00 00 00 21 00 18 01 55 00 00 20 0A 00 07 .@...!...U.. ...
40000000000B6560 19 00 00 00 01 00 C0 00 31 02 42 80 08 00 84 00 ........1.B.....
40000000000B6570 11 28 01 42 00 21 60 0A 00 00 48 00 D8 4E 07 50 .(.B.!`...H..N.P
40000000000B6580 09 30 00 10 87 39 00 00 00 02 00 20 00 20 01 84 .0...9..... . ..
40000000000B6590 C2 40 04 00 00 24 00 00 00 02 80 03 01 00 00 84 .@...$..........
40000000000B65A0 02 00 00 00 01 00 00 18 01 55 00 00 20 0A 00 07 .........U.. ...
40000000000B65B0 19 00 00 00 01 00 C0 00 31 02 42 80 08 00 84 00 ........1.B.....
40000000000B65C0 11 28 01 42 00 21 60 12 00 00 48 00 88 4E 07 50 .(.B.!`...H..N.P
40000000000B65D0 03 30 00 10 87 39 10 00 90 00 42 03 11 00 00 90 .0...9....B.....
40000000000B65E0 10 00 00 00 01 C0 81 00 00 00 42 00 C0 FF FF 48 ..........B....H
40000000000B65F0 11 28 01 42 00 21 00 00 00 02 00 00 58 BF FA 58 .(.B.!......X..X
40000000000B6600 08 30 00 10 07 39 00 00 00 02 00 00 81 40 00 84 .0...9.......@..
40000000000B6610 19 08 00 48 00 21 00 00 00 02 00 03 F0 FE FF 4B ...H.!.........K
40000000000B6620 09 00 00 00 01 00 E0 00 20 30 20 00 00 00 04 00 ........ 0 .....
40000000000B6630 10 00 00 00 01 00 70 00 38 0C F2 03 D0 FE FF 4B ......p.8......K
40000000000B6640 08 40 04 00 00 24 00 00 00 02 00 00 00 00 04 00 .@...$..........
40000000000B6650 02 00 00 00 01 00 00 18 01 55 00 00 20 0A 00 07 .........U.. ...
40000000000B6660 19 00 00 00 01 00 C0 00 31 02 42 80 08 00 84 00 ........1.B.....
40000000000B6670 11 28 01 42 00 21 60 82 30 00 42 00 98 4B 07 50 .(.B.!`.0.B..K.P
40000000000B6680 10 08 00 48 00 21 70 00 20 0C 73 03 80 FE FF 4A ...H.!p. .s....J
40000000000B6690 09 70 A0 18 00 21 00 00 00 02 00 00 01 00 00 84 .p...!..........
40000000000B66A0 02 70 00 1C 10 10 00 00 00 02 00 E0 60 71 18 50 .p..........`q.P
40000000000B66B0 16 00 00 00 00 88 01 C8 FF FF 25 00 60 FE FF 48 ..........%.`..H
40000000000B66C0 11 28 01 42 00 21 60 02 31 02 42 00 C8 8D F8 58 .(.B.!`.1.B....X
40000000000B66D0 08 70 80 18 01 21 00 00 00 02 00 20 00 20 01 84 .p...!..... . ..
40000000000B66E0 19 30 00 10 87 39 00 00 00 02 00 03 20 FE FF 4B .0...9...... ..K
40000000000B66F0 0B 28 01 1C 18 10 00 00 00 02 00 C0 01 28 59 00 .(...........(Y.
40000000000B6700 10 00 00 00 01 00 70 70 94 0C 70 03 00 FE FF 4A ......pp..p....J
40000000000B6710 11 00 00 00 01 00 00 00 00 02 00 00 B8 5A F6 58 .............Z.X
40000000000B6720 03 38 00 10 86 39 10 00 90 00 42 03 11 00 00 90 .8...9....B.....
40000000000B6730 E2 40 00 00 00 21 00 18 01 55 00 00 20 0A 00 07 .@...!...U.. ...
40000000000B6740 19 00 00 00 01 00 C0 00 31 02 42 80 08 00 84 00 ........1.B.....
40000000000B6750 11 28 01 42 00 21 60 82 30 00 42 00 B8 4A 07 50 .(.B.!`.0.B..J.P
40000000000B6760 10 08 00 48 00 21 70 00 20 0C 73 03 A0 FD FF 4A ...H.!p. .s....J
40000000000B6770 09 70 00 19 00 21 00 00 00 02 00 00 11 00 00 90 .p...!..........
40000000000B6780 09 00 00 00 01 00 E0 00 38 30 20 00 00 00 04 00 ........80 .....
40000000000B6790 12 30 00 1C 07 F1 01 B8 FE FF 25 00 C0 FE FF 48 .0........%....H
40000000000B67A0 11 28 01 42 00 21 60 22 00 00 48 00 A8 4C 07 50 .(.B.!`"..H..L.P
40000000000B67B0 03 30 00 10 87 39 10 00 90 00 42 03 11 00 00 90 .0...9....B.....
40000000000B67C0 10 00 00 00 01 C0 81 00 00 00 42 00 E0 FD FF 48 ..........B....H
40000000000B67D0 11 28 01 42 00 21 60 82 30 00 42 00 38 4A 07 50 .(.B.!`.0.B.8J.P
40000000000B67E0 10 08 00 48 00 21 70 00 20 0C 73 03 20 FD FF 4A ...H.!p. .s. ..J
40000000000B67F0 09 70 A0 18 00 21 00 00 00 02 00 00 01 00 00 84 .p...!..........
40000000000B6800 09 78 00 1C 10 10 00 00 00 02 00 C0 01 00 80 97 .x..............
40000000000B6810 09 78 38 1E 0C 20 00 00 00 02 00 C0 01 00 80 90 .x8.. ..........
40000000000B6820 12 30 38 1E 87 B8 01 10 FF FF 25 00 F0 FC FF 48 .08.......%....H
40000000000B6830 11 28 01 42 00 21 00 00 00 02 00 00 98 25 05 50 .(.B.!.......%.P
40000000000B6840 03 30 04 10 87 39 10 00 90 00 42 03 11 00 00 90 .0...9....B.....
40000000000B6850 E2 40 00 00 00 21 00 18 01 55 00 00 20 0A 00 07 .@...!...U.. ...
40000000000B6860 18 00 00 00 01 00 C0 00 31 02 42 80 08 00 84 00 ........1.B.....
40000000000B6870 0B 40 00 42 00 10 00 00 00 02 00 00 01 40 50 00 .@.B.........@P.
40000000000B6880 0B 38 00 10 86 B9 81 08 00 00 48 00 00 00 04 00 .8........H.....
40000000000B6890 E2 40 00 00 00 21 00 18 01 55 00 00 20 0A 00 07 .@...!...U.. ...
40000000000B68A0 19 00 00 00 01 00 C0 00 31 02 42 80 08 00 84 00 ........1.B.....
40000000000B68B0 11 28 01 42 00 21 60 82 30 00 42 00 58 49 07 50 .(.B.!`.0.B.XI.P
40000000000B68C0 10 08 00 48 00 21 70 00 20 0C 73 03 40 FC FF 4A ...H.!p. .s.@..J
40000000000B68D0 09 70 A0 18 00 21 00 00 00 02 00 00 01 00 00 84 .p...!..........
40000000000B68E0 02 70 00 1C 10 10 00 00 00 02 00 E0 20 71 18 50 .p.......... q.P
40000000000B68F0 16 00 00 00 00 88 01 A8 FE FF 25 00 20 FC FF 48 ..........%. ..H
40000000000B6900 11 28 01 42 00 21 60 82 30 00 42 00 08 49 07 50 .(.B.!`.0.B..I.P
40000000000B6910 10 08 00 48 00 21 70 00 20 0C 73 03 F0 FB FF 4A ...H.!p. .s....J
40000000000B6920 09 70 A0 18 00 21 00 00 00 02 00 00 01 00 00 84 .p...!..........
40000000000B6930 02 70 00 1C 10 10 00 00 00 02 00 E0 40 71 18 50 .p..........@q.P
40000000000B6940 16 00 00 00 00 88 01 80 FE FF 25 00 D0 FB FF 48 ..........%....H
40000000000B6950 11 28 01 42 00 21 60 82 30 00 42 00 B8 48 07 50 .(.B.!`.0.B..H.P
40000000000B6960 08 70 A0 18 00 21 00 00 00 02 00 E0 80 00 18 C2 .p...!..........
40000000000B6970 19 08 00 48 00 21 00 00 00 02 80 03 90 FB FF 4B ...H.!.........K
40000000000B6980 03 40 00 1C 10 10 E0 00 00 C0 49 00 E1 40 30 80 .@........I..@0.
40000000000B6990 0B 30 00 10 87 B9 81 08 00 00 48 00 00 00 04 00 .0........H.....
40000000000B69A0 E2 40 00 00 00 21 00 18 01 55 00 00 20 0A 00 07 .@...!...U.. ...
40000000000B69B0 19 00 00 00 01 00 C0 00 31 02 42 80 08 00 84 00 ........1.B.....
40000000000B69C0 11 28 01 42 00 21 60 82 30 00 42 00 48 48 07 50 .(.B.!`.0.B.HH.P
40000000000B69D0 10 08 00 48 00 21 70 00 20 0C 73 03 30 FB FF 4A ...H.!p. .s.0..J
40000000000B69E0 09 70 A0 18 00 21 00 00 00 02 00 00 01 00 00 84 .p...!..........
40000000000B69F0 09 78 00 1C 10 10 00 00 00 02 00 C0 01 00 80 97 .x..............
40000000000B6A00 09 78 38 1E 0C 20 00 00 00 02 00 C0 01 00 00 92 .x8.. ..........
40000000000B6A10 12 30 38 1E 87 B8 01 18 FE FF 25 00 00 FB FF 48 .08.......%....H
40000000000B6A20 11 28 01 42 00 21 60 82 30 00 42 00 E8 47 07 50 .(.B.!`.0.B..G.P
40000000000B6A30 10 08 00 48 00 21 70 00 20 0C 73 03 D0 FA FF 4A ...H.!p. .s....J
40000000000B6A40 09 70 A0 18 00 21 00 00 00 02 00 00 01 00 00 84 .p...!..........
40000000000B6A50 09 78 00 1C 10 10 00 00 00 02 00 C0 01 00 80 97 .x..............
40000000000B6A60 09 78 38 1E 0C 20 00 00 00 02 00 C0 01 00 00 91 .x8.. ..........
40000000000B6A70 12 30 38 1E 87 B8 01 E8 FD FF 25 00 A0 FA FF 48 .08.......%....H
40000000000B6A80 11 28 01 42 00 21 60 82 30 00 42 00 88 47 07 50 .(.B.!`.0.B..G.P
40000000000B6A90 10 08 00 48 00 21 70 00 20 0C 73 03 70 FA FF 4A ...H.!p. .s.p..J
40000000000B6AA0 09 70 A0 18 00 21 00 00 00 02 00 00 01 00 00 84 .p...!..........
40000000000B6AB0 09 78 00 1C 10 10 00 00 00 02 00 C0 01 00 80 97 .x..............
40000000000B6AC0 09 78 38 1E 0C 20 00 00 00 02 00 C0 01 00 00 93 .x8.. ..........
40000000000B6AD0 12 30 38 1E 87 B8 01 B8 FD FF 25 00 40 FA FF 48 .08.......%.@..H
40000000000B6AE0 11 28 01 42 00 21 60 82 30 00 42 00 28 47 07 50 .(.B.!`.0.B.(G.P
40000000000B6AF0 03 30 00 10 87 39 10 00 90 00 42 03 11 00 00 90 .0...9....B.....
40000000000B6B00 E2 40 00 00 00 21 00 18 01 55 00 00 20 0A 00 07 .@...!...U.. ...
40000000000B6B10 19 00 00 00 01 00 C0 00 31 02 42 80 08 00 84 00 ........1.B.....
40000000000B6B20 11 28 01 42 00 21 60 82 30 00 42 00 E8 46 07 50 .(.B.!`.0.B..F.P
40000000000B6B30 10 08 00 48 00 21 70 00 20 0C 73 03 D0 F9 FF 4A ...H.!p. .s....J
40000000000B6B40 09 70 A0 18 00 21 00 00 00 02 00 00 01 00 00 84 .p...!..........
40000000000B6B50 09 78 00 1C 10 10 00 00 00 02 00 C0 01 00 80 97 .x..............
40000000000B6B60 09 78 38 1E 0C 20 00 00 00 02 00 C0 01 00 00 96 .x8.. ..........
40000000000B6B70 12 30 38 1E 87 B8 01 68 FD FF 25 00 A0 F9 FF 48 .08....h..%....H
40000000000B6B80 11 28 01 42 00 21 60 82 30 00 42 00 88 46 07 50 .(.B.!`.0.B..F.P
40000000000B6B90 10 08 00 48 00 21 70 00 20 0C 73 03 70 F9 FF 4A ...H.!p. .s.p..J
40000000000B6BA0 09 70 20 19 00 21 00 00 00 02 00 00 01 00 00 84 .p ..!..........
40000000000B6BB0 09 78 00 1C 18 10 00 00 00 02 00 C0 81 65 00 84 .x...........e..
40000000000B6BC0 09 00 00 00 01 00 E0 00 38 30 20 00 00 00 04 00 ........80 .....
40000000000B6BD0 12 38 38 1E 06 B0 01 38 FD FF 25 00 40 F9 FF 48 .88....8..%.@..H
40000000000B6BE0 0B 70 00 42 00 10 00 00 00 02 00 C0 01 70 50 00 .p.B.........pP.
40000000000B6BF0 10 00 00 00 01 00 60 00 38 0E 73 03 10 F9 FF 4A ......`.8.s....J
40000000000B6C00 08 28 05 00 00 24 00 00 00 02 00 C0 04 08 01 84 .(...$..........
40000000000B6C10 19 38 41 18 00 21 00 00 00 02 00 00 98 54 F6 58 .8A..!.......T.X
40000000000B6C20 08 70 A0 18 00 21 00 00 00 02 00 E0 00 40 18 E6 .p...!.......@..
40000000000B6C30 19 08 00 48 00 21 00 00 00 02 00 03 D0 F8 FF 4B ...H.!.........K
40000000000B6C40 09 40 00 1C 10 10 00 00 00 02 00 C0 01 00 80 97 .@..............
40000000000B6C50 03 40 38 10 0C 20 E0 00 00 80 4A C0 E0 40 1C E2 .@8.. ....J..@..
40000000000B6C60 09 00 00 00 01 80 81 08 00 00 48 00 00 00 04 00 ..........H.....
40000000000B6C70 E2 40 00 00 00 21 00 18 01 55 00 00 20 0A 00 07 .@...!...U.. ...
40000000000B6C80 19 00 00 00 01 00 C0 00 31 02 42 80 08 00 84 00 ........1.B.....
40000000000B6C90 11 28 01 42 00 21 60 82 30 00 42 00 78 45 07 50 .(.B.!`.0.B.xE.P
40000000000B6CA0 11 08 00 48 00 21 70 00 20 0C 73 03 60 F8 FF 4A ...H.!p. .s.`..J
40000000000B6CB0 09 78 F0 FB 51 27 E0 80 31 00 42 00 01 00 00 84 .x..Q'..1.B.....
40000000000B6CC0 09 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
40000000000B6CD0 0B 78 30 1E 00 21 F0 00 3C 20 20 00 00 00 04 00 .x0..!..<  .....
40000000000B6CE0 13 30 38 1E 87 B8 01 B0 FC FF 25 00 30 F8 FF 48 .08.......%.0..H
40000000000B6CF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; test_binop: 40000000000B6D00
;;   Called from:
;;     400000000003733C (in fn4000000000036A40)
;;     40000000000B710C (in fn40000000000B7000)
;;     40000000000B789C (in fn40000000000B7840)
;;     40000000000B802C (in fn40000000000B7CC0)
test_binop proc
	{ nop.m	0x0; ld1	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; sxt1	r15,r14 }
	{ cmp4.eq	p07,p06,0x3D,r14; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000B6D50; }

l40000000000B6D30:
	{ nop.m	0x0; and	r15,0xFFFFFFFFFFFFFFFD,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x3C,r15; (p07) br.cond.dpnt.few	40000000000B6D80 }

l40000000000B6D50:
	{ adds	r15,0x1,r32; ld1	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dpnt.few	40000000000B6EE0; }

l40000000000B6D80:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x21,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x3D,r14; (p06) br.cond.dptk.few	40000000000B6DD0 }

l40000000000B6DA0:
	{ adds	r15,0x1,r32; ld1	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x3D,r15; (p07) br.cond.dpnt.few	40000000000B6EF0; }

l40000000000B6DD0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r14; (p07) br.cond.dpnt.few	40000000000B6DF0 }

l40000000000B6DE0:
	{ nop.m	0x0; adds	r8,0x0,r0; br.ret	b0 }

l40000000000B6DF0:
	{ adds	r14,0x2,r32; adds	r15,0x3,r32; adds	r32,0x1,r32; }
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B6DE0; }

l40000000000B6E20:
	{ ld1	r15,[r15]; nop.m	0x0; sxt1	r15,r15; }
	{ cmp4.eq	p07,p06,0x0,r15; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B6DE0; }

l40000000000B6E40:
	{ cmp4.eq	p07,p06,0x74,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B6F90; }

l40000000000B6E50:
	{ ld1	r15,[r32]; nop.m	0x0; sxt1	r15,r15; }
	{ cmp4.eq	p07,p06,0x65,r15; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B6F40; }

l40000000000B6E70:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x65,r14; (p06) br.cond.dptk.few	40000000000B6DE0 }

l40000000000B6E80:
	{ adds	r15,0xFFFFFFFFFFFFFF99,r15; nop.m	0x0; zxt1	r14,r15; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x7,r14; (p06) br.cond.dptk.few	40000000000B6DE0 }

l40000000000B6EA0:
	{ addl	r14,1,r0; sxt1	r15,r15; shl	r15,r14,r15 }
	{ addl	r14,161,r0; and	r14,r14,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	40000000000B6DE0; }

l40000000000B6ED0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000B6EE0:
	{ nop.m	0x0; addl	r8,1,r0; br.ret	b0 }

l40000000000B6EF0:
	{ adds	r15,0x2,r32; ld1	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r15; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B6EE0; }

l40000000000B6F20:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r14; (p06) br.cond.dptk.few	40000000000B6DE0 }

l40000000000B6F30:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000B6DF0 }

l40000000000B6F40:
	{ adds	r14,0xFFFFFFFFFFFFFF9A,r14; nop.m	0x0; zxt1	r14,r14; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0xB,r14; (p06) br.cond.dptk.few	40000000000B6DE0 }

l40000000000B6F60:
	{ addl	r15,-9164,r1; nop.m	0x0; zxt1	r14,r14; }
	{ ld8	r15,[r15]; shladd	r14,r14,0x2,r15; nop.i	0x0; }
	{ ld4	r8,[r14]; nop.i	0x0; br.ret	b0 }

l40000000000B6F90:
	{ ld1	r14,[r32]; adds	r14,0xFFFFFFFFFFFFFF99,r14; nop.i	0x0; }
	{ nop.m	0x0; zxt1	r15,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x8,r15; (p06) br.cond.dptk.few	40000000000B6DE0 }

l40000000000B6FC0:
	{ addl	r15,1,r0; sxt1	r14,r14; shl	r15,r15,r14 }
	{ addl	r14,417,r0; and	r14,r14,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	40000000000B6DE0 }

l40000000000B6FF0:
	{ nop.m	0x0; addl	r8,1,r0; br.ret	b0; }

;; fn40000000000B7000: 40000000000B7000
;;   Called from:
;;     40000000000B7ACC (in fn40000000000B7840)
;;     40000000000B8126 (in fn40000000000B7CC0)
fn40000000000B7000 proc
	{ alloc	r37,ar.pfs,0xB,0x0,0x7; addl	r33,7728,r1; nop.b	0x0 }
	{ addl	r14,7716,r1; mov	r36,b4; adds	r38,0x0,r1; }
	{ ld8	r34,[r14]; ld4	r14,[r33]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r35,r14; adds	r14,0x1,r35; }
	{ shladd	r14,r14,0x3,r34; ld8	r32,[r14]; nop.i	0x0; }
	{ nop.m	0x0; ld1	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; sxt1	r15,r14 }
	{ cmp4.eq	p07,p06,0x3D,r14; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000B7190; }

l40000000000B7080:
	{ nop.m	0x0; and	r15,0xFFFFFFFFFFFFFFFD,r15; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x3C,r15; adds	r15,0x1,r32; (p06) br.cond.dpnt.few	40000000000B70C0; }

l40000000000B70A0:
	{ ld1	r15,[r15]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dpnt.few	40000000000B7120; }

l40000000000B70C0:
	{ cmp4.eq	p07,p06,0x21,r14; adds	r39,0x0,r32; (p07) br.cond.dpnt.few	40000000000B7210; }

l40000000000B70D0:
	{ cmp4.eq	p07,p06,0x2D,r14; adds	r14,0x3,r32; (p06) br.cond.spnt.few	40000000000B71D0; }

l40000000000B70E0:
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p06) br.cond.spnt.few	40000000000B71D0; }

l40000000000B7100:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,test_binop; }
	{ adds	r1,0x0,r38; cmp4.eq	p07,p06,0x0,r8; (p07) br.cond.spnt.few	40000000000B71D0 }

l40000000000B7120:
	{ adds	r14,0x2,r35; nop.m	0x0; shladd	r35,r35,0x3,r34 }
	{ adds	r39,0x0,r32; nop.m	0x0; adds	r42,0x0,r0; }
	{ shladd	r34,r14,0x3,r34; ld8	r40,[r35]; nop.i	0x0; }
	{ ld8	r41,[r34]; nop.i	0x0; br.call.sptk.many	b0,binary_test; }
	{ ld4	r14,[r33]; adds	r1,0x0,r38; mov.i	ar.pfs,r37; }
	{ adds	r14,0x3,r14; nop.m	0x0; mov.spnt	b0,r36,40000000000B7170; }
	{ st4	[r14],r33; nop.i	0x0; br.ret	b0 }

l40000000000B7190:
	{ adds	r14,0x1,r32; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B7120; }

l40000000000B71C0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x3D,r14; (p07) br.cond.dpnt.few	40000000000B72B0 }

l40000000000B71D0:
	{ addl	r40,-9236,r1; addl	r41,5,r0; adds	r39,0x0,r0; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ nop.m	0x0; adds	r1,0x0,r38; adds	r39,0x0,r8 }
	{ nop.m	0x0; adds	r40,0x0,r32; br.call.sptk.many	b0,fn40000000000B5540 }

l40000000000B7210:
	{ adds	r14,0x1,r32; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x3D,r14; (p06) br.cond.dptk.few	40000000000B71D0 }

l40000000000B7240:
	{ adds	r14,0x2,r32; addl	r40,-9236,r1; addl	r41,5,r0 }
	{ adds	r39,0x0,r0; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B7120; }

l40000000000B7280:
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ nop.m	0x0; adds	r1,0x0,r38; adds	r39,0x0,r8 }
	{ nop.m	0x0; adds	r40,0x0,r32; br.call.sptk.many	b0,fn40000000000B5540 }

l40000000000B72B0:
	{ adds	r14,0x2,r32; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	40000000000B71D0 }

l40000000000B72E0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000B7120; }
40000000000B72F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; test_unop: 40000000000B7300
;;   Called from:
;;     400000000003710C (in fn4000000000036A40)
;;     40000000000B745C (in fn40000000000B7400)
;;     40000000000B771C (in fn40000000000B7680)
;;     40000000000B80CC (in fn40000000000B7CC0)
test_unop proc
	{ ld1	r14,[r32]; adds	r8,0x0,r0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r14; (p06) br.ret	b0 }

l40000000000B7320:
	{ adds	r15,0x1,r32; adds	r32,0x2,r32; addl	r16,1,r0; }
	{ ld1	r14,[r32]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B73C0; }

l40000000000B7350:
	{ ld1	r14,[r15]; adds	r14,0xFFFFFFFFFFFFFFB9,r14; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r14; zxt1	r14,r14; }
	{ nop.m	0x0; shl	r15,r16,r15; nop.i	0x0 }
	{ cmp4.ltu	p06,p07,0x33,r14; nop.m	0x0; (p06) br.ret	b0 }

l40000000000B7390:
	{ nop.m	0x0; movl	r16,0xBFB93FC0011A1; }
	{ and	r15,r16,r15; cmp.eq	p07,p06,0x0,r15; nop.i	0x0; }
	{ nop.m	0x0; (p06) addl	r8,1,r0; br.ret	b0; }

l40000000000B73BC:
	{ Invalid; break.m	0x1000; (p01) shladd	r0,r0,0x1,r64 }

l40000000000B73C0:
	{ nop.m	0x0; adds	r8,0x0,r0; br.ret	b0; }
40000000000B73D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B73E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B73F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000B7400: 40000000000B7400
;;   Called from:
;;     40000000000B774C (in fn40000000000B7680)
;;     40000000000B8106 (in fn40000000000B7CC0)
fn40000000000B7400 proc
	{ alloc	r38,ar.pfs,0xA,0x0,0x8; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r37,b5 }
	{ addl	r33,7728,r1; addl	r36,7716,r1; adds	r39,0x0,r1; }
	{ ld4	r34,[r33]; ld8	r35,[r36]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r14,r34; shladd	r14,r14,0x3,r35; }
	{ nop.m	0x0; ld8	r32,[r14]; nop.i	0x0; }
	{ adds	r40,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,test_unop; }
	{ adds	r14,0x1,r32; nop.m	0x0; adds	r1,0x0,r39 }
	{ cmp4.eq	p07,p06,0x0,r8; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000B7580; }

l40000000000B7480:
	{ ld1	r14,[r14]; addl	r15,7724,r1; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x74,r14; adds	r14,0x1,r34; (p07) br.cond.dpnt.few	40000000000B7520; }

l40000000000B74A0:
	{ ld4	r15,[r15]; st4	[r14],r33; adds	r34,0x2,r34; }
	{ cmp4.lt	p06,p07,r14,r15; nop.i	0x0; (p07) br.call.spnt.many	b0,fn40000000000B55C0; }

l40000000000B74C0:
	{ nop.m	0x0; sxt4	r14,r34; adds	r40,0x0,r32 }
	{ st4	[r34],r33; adds	r14,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; }
	{ nop.m	0x0; shladd	r35,r14,0x3,r35; nop.i	0x0; }
	{ ld8	r41,[r35]; nop.i	0x0; br.call.sptk.many	b0,unary_test; }
	{ adds	r1,0x0,r39; mov.i	ar.pfs,r38; mov.spnt	b0,r37,40000000000B7500 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000000B7520:
	{ addl	r14,7724,r1; adds	r34,0x1,r34; adds	r41,0x10,r12; }
	{ ld4	r14,[r14]; st4	[r34],r33; nop.i	0x0; }
	{ cmp4.lt	p07,p06,r34,r14; sxt4	r34,r34; (p06) br.cond.dpnt.few	40000000000B75A0; }

l40000000000B7550:
	{ nop.m	0x0; shladd	r35,r34,0x3,r35; nop.i	0x0; }
	{ ld8	r40,[r35]; nop.i	0x0; br.call.sptk.many	b0,legal_number; }
	{ adds	r1,0x0,r39; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dpnt.few	40000000000B75E0; }

l40000000000B7580:
	{ adds	r8,0x0,r0; mov.i	ar.pfs,r38; mov.spnt	b0,r37,40000000000B7580 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000B75A0:
	{ addl	r41,-9228,r1; nop.m	0x0; adds	r40,0x0,r32; }
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,unary_test; }
	{ adds	r1,0x0,r39; mov.i	ar.pfs,r38; mov.spnt	b0,r37,40000000000B75C0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000B75E0:
	{ nop.m	0x0; ld4	r14,[r33]; adds	r40,0x0,r32 }
	{ nop.m	0x0; ld8	r15,[r36]; nop.i	0x0; }
	{ adds	r14,0x1,r14; nop.i	0x0; sxt4	r16,r14 }
	{ st4	[r14],r33; adds	r14,0xFFFFFFFFFFFFFFFF,r16; nop.i	0x0; }
	{ nop.m	0x0; shladd	r14,r14,0x3,r15; nop.i	0x0; }
	{ ld8	r41,[r14]; nop.i	0x0; br.call.sptk.many	b0,unary_test; }
	{ adds	r1,0x0,r39; mov.i	ar.pfs,r38; mov.spnt	b0,r37,40000000000B7640 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }
40000000000B7660 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B7670 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000B7680: 40000000000B7680
;;   Called from:
;;     40000000000B7B7C (in fn40000000000B7840)
;;     40000000000B896C (in test_command)
;;     40000000000B896C (in test_command)
fn40000000000B7680 proc
	{ alloc	r34,ar.pfs,0x7,0x0,0x4; addl	r14,7728,r1; mov	r33,b1 }
	{ adds	r35,0x0,r1; ld4	r16,[r14]; addl	r14,7716,r1; }
	{ ld8	r15,[r14]; sxt4	r16,r16; shladd	r32,r16,0x3,r15; }
	{ ld8	r36,[r32]; ld1	r14,[r36]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x21,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B7750; }

l40000000000B76E0:
	{ cmp4.eq	p07,p06,0x2D,r14; adds	r14,0x2,r36; (p06) br.cond.spnt.few	40000000000B7780; }

l40000000000B76F0:
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p06) br.cond.spnt.few	40000000000B7780; }

l40000000000B7710:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,test_unop; }
	{ adds	r1,0x0,r35; cmp4.eq	p06,p07,0x0,r8; mov.i	ar.pfs,r34 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.spnt.few	40000000000B7780; }

l40000000000B7740:
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000B7740; br.cond.sptk.many	fn40000000000B7400 }

l40000000000B7750:
	{ adds	r36,0x1,r36; ld1	r14,[r36]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000B77C0 }

l40000000000B7780:
	{ addl	r37,-9220,r1; adds	r36,0x0,r0; addl	r38,5,r0; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ nop.m	0x0; adds	r1,0x0,r35; adds	r36,0x0,r8 }
	{ nop.m	0x0; ld8	r37,[r32]; br.call.sptk.many	b0,fn40000000000B5540; }

l40000000000B77C0:
	{ adds	r16,0x1,r16; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ shladd	r15,r16,0x3,r15; nop.m	0x0; mov.spnt	b0,r33,40000000000B77D0; }
	{ ld8	r14,[r15]; ld1	r8,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r8,r8; cmp4.eq	p06,p07,0x0,r8; }
	{ nop.m	0x0; (p06) addl	r8,1,r0; nop.i	0x0; }

l40000000000B780C:
	{ Invalid; mov	pr,r32,0x0; (p01) shladd	r0,r0,0x1,r64 }

l40000000000B781C:
	{ nop; break.m	0x1000; break.i	0x1000 }
40000000000B7820 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B7830 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000B7840: 40000000000B7840
;;   Called from:
;;     40000000000B8A8C (in test_command)
;;     40000000000B8AEC (in test_command)
fn40000000000B7840 proc
	{ alloc	r39,ar.pfs,0xC,0x0,0x9; addl	r35,7728,r1; nop.b	0x0 }
	{ addl	r14,7716,r1; adds	r40,0x0,r1; mov	r38,b6; }
	{ ld4	r36,[r35]; ld8	r32,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r33,r36; adds	r37,0x1,r33; }
	{ shladd	r37,r37,0x3,r32; ld8	r34,[r37]; nop.i	0x0; }
	{ adds	r41,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,test_binop; }
	{ adds	r1,0x0,r40; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dpnt.few	40000000000B7AC0; }

l40000000000B78B0:
	{ ld1	r8,[r34]; nop.m	0x0; sxt1	r8,r8; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r8; (p07) br.cond.dpnt.few	40000000000B79A0 }

l40000000000B78D0:
	{ shladd	r14,r33,0x3,r32; nop.m	0x0; adds	r33,0x2,r33; }
	{ ld8	r15,[r14]; nop.m	0x0; shladd	r32,r33,0x3,r32; }
	{ ld1	r14,[r15]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x21,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B7B10; }

l40000000000B7910:
	{ cmp4.eq	p07,p06,0x28,r14; nop.i	0x0; (p06) br.cond.spnt.few	40000000000B7BB0; }

l40000000000B7920:
	{ ld8	r14,[r32]; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x29,r14; addl	r14,7724,r1; (p06) br.cond.spnt.few	40000000000B7BB0; }

l40000000000B7950:
	{ cmp4.eq	p07,p06,0x0,r8; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; (p06) addl	r8,1,r0; nop.i	0x0 }

l40000000000B796C:
	{ Invalid; Invalid; mov	pr,r32,0x0 }
	{ nop.m	0x8000; break.i	0x1000; (p48) break.i	0x2A809; }

l40000000000B7980:
	{ nop.m	0x0; mov.i	ar.pfs,r39; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000B7990; br.ret	b0 }

l40000000000B79A0:
	{ adds	r14,0x2,r34; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000B78D0 }

l40000000000B79D0:
	{ adds	r34,0x1,r34; ld1	r15,[r34]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ cmp4.eq	p08,p09,0x61,r15; cmp4.eq	p06,p07,0x6F,r15; (p08) addl	r14,1,r0; }

l40000000000B7A00:
	{ nop.m	0x0; (p09) adds	r14,0x0,r0; nop.i	0x0; }

l40000000000B7A0C:
	{ cmp.eq	p00,p17,r1,r0; (p01) cmp.lt.unc	p00,p16,r3,r64; (p08) mov	pr,r99,0xE580 }
	{ (p54) cmp.lt.unc	p63,p09,r63,r37; zxt1	r8,r4; cmp.lt	p00,p00,r32,r0 }

l40000000000B7A20:
	{ shladd	r14,r33,0x3,r32; nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; }
	{ ld8	r14,[r14]; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; (p07) br.cond.dpnt.few	40000000000B7BF0; }

l40000000000B7A50:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000B7C40 }

l40000000000B7A60:
	{ adds	r33,0x2,r33; shladd	r32,r33,0x3,r32; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r32]; nop.i	0x0; }
	{ ld1	r8,[r14]; addl	r14,7724,r1; sxt1	r8,r8 }
	{ ld4	r14,[r14]; nop.i	0x0; cmp4.eq	p07,p06,0x0,r8 }
	{ st4	[r14],r35; (p06) addl	r8,1,r0; nop.i	0x0; }

l40000000000B7AAC:
	{ invala; mov	pr,r32,0x0; zxt1	r0,r64 }

l40000000000B7ABC:
	{ Invalid; break.i	0x1000; break.b	0x1000 }

l40000000000B7AC0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000B7000; }
	{ adds	r1,0x0,r40; nop.m	0x0; mov.i	ar.pfs,r39; }
	{ addl	r14,7724,r1; nop.m	0x0; mov.spnt	b0,r38,40000000000B7AE0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ st4	[r14],r35; nop.i	0x0; br.ret	b0 }

l40000000000B7B10:
	{ adds	r15,0x1,r15; ld1	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000B7BB0 }

l40000000000B7B40:
	{ addl	r14,7724,r1; nop.m	0x0; adds	r36,0x1,r36; }
	{ ld4	r14,[r14]; st4	[r36],r35; nop.i	0x0; }
	{ cmp4.lt	p06,p07,r36,r14; nop.i	0x0; (p07) br.call.spnt.many	b0,fn40000000000B55C0; }

l40000000000B7B70:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000B7680; }
	{ cmp4.eq	p06,p07,0x0,r8; adds	r1,0x0,r40; mov.i	ar.pfs,r39; }
	{ (p06) addl	r8,1,r0; nop.m	0x0; mov.spnt	b0,r38,40000000000B7B90; }

l40000000000B7B96:
	{ break.m	0x4000; nop; cmp.lt	p00,p00,r0,r32 }
	{ Invalid; (p34) nop; (p32) nop; }

l40000000000B7BAC:
	{ cmpxchg2.acq	r0,[r0],r33; (p05) nop; (p05) nop }

l40000000000B7BB0:
	{ addl	r42,-9236,r1; adds	r41,0x0,r0; addl	r43,5,r0; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ nop.m	0x0; adds	r1,0x0,r40; adds	r41,0x0,r8 }
	{ nop.m	0x0; ld8	r42,[r37]; br.call.sptk.many	b0,fn40000000000B5540 }

l40000000000B7BF0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000B7C70 }

l40000000000B7C00:
	{ adds	r33,0x2,r33; shladd	r32,r33,0x3,r32; nop.i	0x0; }
	{ ld8	r14,[r32]; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000B7C70; }

l40000000000B7C40:
	{ addl	r14,7724,r1; nop.m	0x0; addl	r8,1,r0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ st4	[r14],r35; nop.i	0x0; br.cond.sptk.few	40000000000B7980 }

l40000000000B7C70:
	{ addl	r14,7724,r1; nop.m	0x0; adds	r8,0x0,r0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ st4	[r14],r35; nop.i	0x0; br.cond.sptk.few	40000000000B7980; }
40000000000B7CA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B7CB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000B7CC0: 40000000000B7CC0
;;   Called from:
;;     40000000000B7E5C (in fn40000000000B7CC0)
;;     40000000000B821C (in fn40000000000B8200)
fn40000000000B7CC0 proc
	{ alloc	r40,ar.pfs,0xE,0x0,0xB; addl	r14,7724,r1; mov	r42,LC }
	{ addl	r36,7728,r1; addl	r37,7716,r1; adds	r41,0x0,r1; }
	{ nop.m	0x0; ld4	r19,[r14]; mov	r39,b7 }
	{ ld4	r32,[r36]; ld8	r20,[r37]; adds	r21,0x1,r19; }

l40000000000B7D00:
	{ nop.m	0x0; sxt4	r14,r32; nop.i	0x0 }
	{ cmp4.lt	p06,p07,r32,r19; addl	r17,1,r0; (p07) br.cond.spnt.few	40000000000B8130; }

l40000000000B7D20:
	{ shladd	r35,r14,0x3,r20; ld8	r33,[r35]; nop.i	0x0; }
	{ adds	r15,0x1,r33; ld1	r34,[r33]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r34,r34; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x21,r34; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B7EA0; }

l40000000000B7D60:
	{ ld1	r15,[r15]; nop.m	0x0; sxt1	r15,r15; }
	{ cmp4.eq	p07,p06,0x0,r15; adds	r15,0x1,r32; (p06) br.cond.dpnt.few	40000000000B7FE0; }

l40000000000B7D80:
	{ adds	r14,0x2,r32; cmp4.lt	p06,p07,r15,r19; sxt4	r16,r15 }
	{ adds	r32,0x0,r15; nop.m	0x0; (p07) br.cond.spnt.few	40000000000B8160; }

l40000000000B7DA0:
	{ sub	r15,r21,r14,0x1; nop.m	0x0; shladd	r16,r16,0x3,r20; }
	{ addp4	r15,r15,r0; nop.i	0x0; mov.i	LC,r15; }

l40000000000B7DC0:
	{ ld8	r15,[r16],8; ld1	r18,[r15]; adds	r15,0x1,r15; }
	{ nop.m	0x0; sxt1	r18,r18; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x21,r18; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B7E40; }

l40000000000B7DF0:
	{ ld1	r15,[r15]; nop.m	0x0; sxt1	r15,r15; }
	{ cmp4.eq	p06,p07,0x0,r15; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B7E40; }

l40000000000B7E10:
	{ adds	r32,0x0,r14; cmp4.eq	p07,p06,r14,r19; nop.i	0x0 }
	{ sub	r17,0x1,r17; adds	r14,0x1,r14; (p07) br.cond.spnt.few	40000000000B8150; }

l40000000000B7E30:
	{ nop.m	0x0; nop.i	0x0; br.cloop.sptk.few	40000000000B7DC0 }

l40000000000B7E40:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r17; (p06) br.cond.dptk.few	40000000000B7D00 }

l40000000000B7E50:
	{ st4	[r32],r36; nop.i	0x0; br.call.sptk.many	b0,fn40000000000B7CC0; }
	{ cmp4.eq	p06,p07,0x0,r8; nop.m	0x0; adds	r1,0x0,r41; }
	{ (p06) addl	r8,1,r0; nop.i	0x0; (p07) adds	r8,0x0,r0 }

l40000000000B7E76:
	{ chk.a.nc	f0,3FFFFFFFFF0B8676; (p04) mov.sptk	b0,r0,40000000000B7F76; break.i	0x80000 }

l40000000000B7E80:
	{ nop.m	0x0; mov.i	ar.pfs,r40; mov.i	LC,r42; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000B7E90; br.ret	b0 }

l40000000000B7EA0:
	{ adds	r15,0x1,r33; st4	[r32],r36; nop.i	0x0 }
	{ cmp4.eq	p07,p06,0x28,r34; addl	r38,7728,r1; (p06) br.cond.dpnt.few	40000000000B7FF0; }

l40000000000B7EC0:
	{ ld1	r15,[r15]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	40000000000B7FF0 }

l40000000000B7EE0:
	{ adds	r32,0x1,r32; nop.m	0x0; cmp4.lt	p07,p06,r32,r19 }
	{ nop.m	0x0; st4	[r32],r38; (p06) br.cond.spnt.few	40000000000B8140; }

l40000000000B7F00:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000B83C0; }
	{ nop.m	0x0; ld4	r15,[r38]; adds	r1,0x0,r41 }
	{ ld8	r14,[r37]; nop.m	0x0; sxt4	r32,r15; }
	{ shladd	r32,r32,0x3,r14; ld8	r14,[r32]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.spnt.few	40000000000B8170; }

l40000000000B7F50:
	{ ld1	r16,[r14]; adds	r14,0x1,r14; sxt1	r16,r16; }
	{ cmp4.eq	p07,p06,0x29,r16; nop.i	0x0; (p06) br.cond.spnt.few	40000000000B7FA0; }

l40000000000B7F70:
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; (p06) adds	r15,0x1,r15; nop.i	0x0; }

l40000000000B7F8C:
	{ Invalid; Invalid; mov	pr,r32,0x0 }

l40000000000B7F96:
	{ chk.a.nc	r0,3FFFFFFFFF0B8796; nop; nop }

l40000000000B7FA0:
	{ addl	r44,-9204,r1; adds	r43,0x0,r0; addl	r45,5,r0; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ nop.m	0x0; adds	r1,0x0,r41; adds	r43,0x0,r8 }
	{ nop.m	0x0; ld8	r44,[r32]; br.call.sptk.many	b0,fn40000000000B5540 }

l40000000000B7FE0:
	{ st4	[r32],r36; nop.m	0x0; nop.i	0x0 }

l40000000000B7FF0:
	{ nop.m	0x0; adds	r15,0x2,r32; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r15,r19; (p06) br.cond.dptk.few	40000000000B8040 }

l40000000000B8010:
	{ adds	r14,0x1,r14; shladd	r20,r14,0x3,r20; nop.i	0x0; }
	{ ld8	r43,[r20]; nop.i	0x0; br.call.sptk.many	b0,test_binop; }
	{ adds	r1,0x0,r41; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dpnt.few	40000000000B8110; }

l40000000000B8040:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r34; (p07) br.cond.dpnt.few	40000000000B8090; }

l40000000000B8050:
	{ cmp4.eq	p07,p06,0x0,r34; adds	r32,0x1,r32; mov.i	ar.pfs,r40; }
	{ (p06) addl	r34,1,r0; st4	[r32],r36; mov.i	LC,r42; }

l40000000000B8066:
	{ mf.a; cmp4.ltu	p42,p00,r65,r42; (p33) nop }

l40000000000B8076:
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ Invalid; (p34) nop; (p32) nop }

l40000000000B8090:
	{ adds	r14,0x2,r33; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000B8050 }

l40000000000B80C0:
	{ adds	r43,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,test_unop; }
	{ adds	r1,0x0,r41; cmp4.eq	p06,p07,0x0,r8; mov.i	ar.pfs,r40 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.spnt.few	40000000000B81B0; }

l40000000000B80F0:
	{ nop.m	0x0; mov.i	LC,r42; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000B8100; br.cond.sptk.many	fn40000000000B7400 }

l40000000000B8110:
	{ nop.m	0x0; mov.i	ar.pfs,r40; mov.i	LC,r42; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000B8120; br.cond.sptk.many	fn40000000000B7000 }

l40000000000B8130:
	{ st4	[r32],r36; nop.m	0x0; nop.i	0x0; }

l40000000000B8140:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000B55C0; }

l40000000000B8150:
	{ st4	[r19],r36; nop.i	0x0; br.call.sptk.many	b0,fn40000000000B55C0; }

l40000000000B8160:
	{ st4	[r15],r36; nop.i	0x0; br.call.sptk.many	b0,fn40000000000B55C0 }

l40000000000B8170:
	{ addl	r44,-9212,r1; adds	r43,0x0,r0; addl	r45,5,r0; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ nop.m	0x0; adds	r1,0x0,r41; adds	r43,0x0,r8 }
	{ nop.m	0x0; adds	r44,0x0,r0; br.call.sptk.many	b0,fn40000000000B5540; }

l40000000000B81B0:
	{ addl	r44,-9220,r1; adds	r43,0x0,r0; addl	r45,5,r0; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ nop.m	0x0; adds	r1,0x0,r41; adds	r43,0x0,r8 }
	{ nop.m	0x0; ld8	r44,[r35]; br.call.sptk.many	b0,fn40000000000B5540; }
	{ nop.m	0x0; break.f	0x0; nop.i	0x0; }

;; fn40000000000B8200: 40000000000B8200
;;   Called from:
;;     40000000000B81FC (in fn40000000000B7CC0)
;;     40000000000B833C (in fn40000000000B8200)
;;     40000000000B83DC (in fn40000000000B83C0)
fn40000000000B8200 proc
	{ alloc	r34,ar.pfs,0x4,0x0,0x4; mov	r33,b1; adds	r35,0x0,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000B7CC0; }
	{ adds	r1,0x0,r35; adds	r32,0x0,r8; addl	r15,7728,r1 }
	{ addl	r16,7724,r1; ld4	r14,[r15]; nop.i	0x0 }
	{ ld4	r16,[r16]; nop.i	0x0; cmp4.lt	p07,p06,r14,r16 }
	{ addl	r16,7716,r1; sxt4	r17,r14; (p06) br.cond.dpnt.few	40000000000B82A0; }

l40000000000B8260:
	{ ld8	r16,[r16]; shladd	r17,r17,0x3,r16; nop.i	0x0; }
	{ ld8	r16,[r17]; ld1	r17,[r16]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r17,r17; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r17; (p07) br.cond.dpnt.few	40000000000B82C0 }

l40000000000B82A0:
	{ adds	r8,0x0,r32; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000B82B0; br.ret	b0 }

l40000000000B82C0:
	{ adds	r17,0x1,r16; ld1	r17,[r17]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r17,r17; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x61,r17; (p06) br.cond.dptk.few	40000000000B82A0 }

l40000000000B82F0:
	{ adds	r16,0x2,r16; ld1	r16,[r16]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r16,r16; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r16; (p06) br.cond.dptk.few	40000000000B82A0 }

l40000000000B8320:
	{ nop.m	0x0; adds	r14,0x1,r14; nop.i	0x0; }
	{ st4	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn40000000000B8200; }
	{ cmp4.eq	p07,p06,0x0,r32; cmp4.eq	p09,p08,0x0,r8; nop.b	0x0 }
	{ adds	r1,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ (p08) addl	r8,1,r0; (p06) addl	r32,1,r0; mov.spnt	b0,r33,40000000000B8360; }

l40000000000B8366:
	{ Invalid; dep	r33,r1,r64,39,4; (p02) cmp.eq.or.andcm	p02,p00,r0,r0; }

l40000000000B836C:
	{ (p16) chk.a.nc	r1,4000000000979F6C; (p01) mov	pr,r0,0x8400; (p04) epc }

l40000000000B8376:
	{ Invalid; (p16) nop; break.i	0x80000; }

l40000000000B837C:
	{ Invalid; (p01) nop }
	{ nop; break.m	0x1000; break.i	0x1000 }
40000000000B8390 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B83A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B83B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000B83C0: 40000000000B83C0
;;   Called from:
;;     40000000000B7F0C (in fn40000000000B7CC0)
;;     40000000000B84FC (in fn40000000000B83C0)
;;     40000000000B86DC (in test_command)
fn40000000000B83C0 proc
	{ alloc	r34,ar.pfs,0x4,0x0,0x4; mov	r33,b1; adds	r35,0x0,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000B8200; }
	{ adds	r1,0x0,r35; adds	r32,0x0,r8; addl	r15,7728,r1 }
	{ addl	r16,7724,r1; ld4	r14,[r15]; nop.i	0x0 }
	{ ld4	r16,[r16]; nop.i	0x0; cmp4.lt	p07,p06,r14,r16 }
	{ addl	r16,7716,r1; sxt4	r17,r14; (p06) br.cond.dpnt.few	40000000000B8460; }

l40000000000B8420:
	{ ld8	r16,[r16]; shladd	r17,r17,0x3,r16; nop.i	0x0; }
	{ ld8	r16,[r17]; ld1	r17,[r16]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r17,r17; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r17; (p07) br.cond.dpnt.few	40000000000B8480 }

l40000000000B8460:
	{ adds	r8,0x0,r32; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000B8470; br.ret	b0 }

l40000000000B8480:
	{ adds	r17,0x1,r16; ld1	r17,[r17]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r17,r17; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x6F,r17; (p06) br.cond.dptk.few	40000000000B8460 }

l40000000000B84B0:
	{ adds	r16,0x2,r16; ld1	r16,[r16]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r16,r16; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r16; (p06) br.cond.dptk.few	40000000000B8460 }

l40000000000B84E0:
	{ nop.m	0x0; adds	r14,0x1,r14; nop.i	0x0; }
	{ st4	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn40000000000B83C0; }
	{ or	r8,r32,r8; adds	r1,0x0,r35; mov.i	ar.pfs,r34; }
	{ cmp4.eq	p07,p06,0x0,r8; mov.spnt	b0,r33,40000000000B8510; (p06) addl	r32,1,r0; }

l40000000000B8520:
	{ nop.m	0x0; (p07) adds	r32,0x0,r0; nop.i	0x0; }

l40000000000B852C:
	{ Invalid; break.i	0x1000; (p01) shladd	r0,r8,0x1,r64 }
	{ shladdp4	r0,r33,0x1,r0; Invalid; zxt1	r2,r64 }

;; test_command: 40000000000B8540
;;   Called from:
;;     400000000010D86C (in test_builtin)
test_command proc
	{ alloc	r36,ar.pfs,0x8,0x0,0x5; adds	r16,0x8,r12; nop.b	0x0 }
	{ adds	r12,0xFFFFFFFFFFFFFFE0,r12; addl	r37,19668,r1; mov	r35,b3; }
	{ nop.m	0x0; adds	r14,0x10,r12; adds	r15,0x18,r12 }
	{ st8.spill	[r1],r16; nop.m	0x0; addl	r38,1,r0; }
	{ nop.m	0x0; st4	[r32],r14; nop.i	0x0 }
	{ st8	[r33],r15; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BD60; }
	{ adds	r1,0x28,r12; nop.m	0x0; cmp4.eq	p06,p07,0x0,r8; }
	{ ld8	r1,[r1]; (p07) addl	r14,7708,r1; nop.i	0x0; }

l40000000000B85BC:
	{ Invalid; Invalid; mov	pr,r32,0x0 }

l40000000000B85C6:
	{ chk.a.nc	f0,3FFFFFFFFF0B8DC6; nop; (p48) nop }

l40000000000B85D0:
	{ adds	r15,0x18,r12; nop.m	0x0; adds	r16,0x18,r12; }
	{ ld8	r15,[r15]; ld8	r16,[r16]; nop.i	0x0; }
	{ ld8	r14,[r15]; nop.m	0x0; addl	r15,7716,r1; }
	{ st8	[r16],r15; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	40000000000B8630; }

l40000000000B8610:
	{ ld1	r15,[r14]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5B,r15; (p07) br.cond.dpnt.few	40000000000B8830 }

l40000000000B8630:
	{ adds	r15,0x10,r12; adds	r16,0x10,r12; addl	r14,1,r0; }
	{ ld4	r15,[r15]; ld4	r16,[r16]; nop.i	0x0; }
	{ cmp4.lt	p06,p07,0x1,r15; nop.m	0x0; addl	r15,7724,r1; }
	{ st4	[r16],r15; nop.m	0x0; addl	r15,7728,r1; }
	{ st4	[r14],r15; adds	r15,0x10,r12; (p07) br.cond.spnt.few	40000000000B8B30; }

l40000000000B8680:
	{ ld4	r15,[r15]; adds	r14,0xFFFFFFFFFFFFFFFF,r15; addl	r15,7732,r1; }
	{ st4	[r0],r15; cmp4.eq	p06,p07,0x2,r14; (p06) br.cond.dpnt.few	40000000000B8960; }

l40000000000B86A0:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x2,r14; (p07) br.cond.dptk.few	40000000000B87A0; }

l40000000000B86B0:
	{ cmp4.eq	p06,p07,0x3,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B8AE0; }

l40000000000B86C0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x4,r14; (p06) br.cond.dpnt.few	40000000000B89E0 }

l40000000000B86D0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000B83C0; }
	{ adds	r1,0x28,r12; nop.m	0x0; adds	r15,0x10,r12; }
	{ ld8	r1,[r1]; addl	r14,7728,r1; nop.i	0x0; }
	{ ld4	r14,[r14]; st4	[r14],r15; addl	r14,7724,r1 }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0 }

l40000000000B8720:
	{ adds	r16,0x10,r12; addl	r38,-9188,r1; adds	r37,0x0,r0 }
	{ addl	r39,5,r0; ld4	r16,[r16]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,r14,r16; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B89A0; }

l40000000000B8750:
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x28,r12; adds	r37,0x0,r8; adds	r38,0x0,r0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn40000000000B5540; }

l40000000000B8780:
	{ nop.m	0x0; mov.i	ar.pfs,r36; mov.spnt	b0,r35,40000000000B8780 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0 }

l40000000000B87A0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x1,r14; (p07) br.cond.dptk.few	40000000000B86D0; }

l40000000000B87B0:
	{ nop.m	0x0; adds	r16,0x18,r12; nop.i	0x0; }
	{ ld8	r16,[r16]; adds	r14,0x8,r16; adds	r16,0x10,r12; }
	{ nop.m	0x0; ld8	r15,[r14]; addl	r14,7728,r1 }
	{ ld4	r16,[r16]; st4	[r16],r14; addl	r14,7724,r1; }
	{ ld1	r8,[r15]; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r8,r8; cmp4.eq	p07,p06,0x0,r8; }
	{ nop.m	0x0; (p06) addl	r8,1,r0; nop.i	0x0; }

l40000000000B881C:
	{ invala; mov	pr,r32,0x0; zxt1	r0,r64 }

l40000000000B882C:
	{ (p56) cmp.lt.unc	p63,p11,r63,r36; (p17) cmp.lt.unc	p00,p16,r3,r64; Invalid }

l40000000000B8830:
	{ adds	r14,0x1,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000B8630 }

l40000000000B8860:
	{ nop.m	0x0; adds	r14,0x10,r12; nop.i	0x0; }
	{ ld4	r14,[r14]; adds	r15,0xFFFFFFFFFFFFFFFF,r14; adds	r14,0x10,r12; }
	{ st4	[r15],r14; sxt4	r14,r15; shladd	r14,r14,0x3,r16; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B88F0; }

l40000000000B88B0:
	{ ld1	r15,[r14]; adds	r14,0x1,r14; sxt1	r15,r15; }
	{ cmp4.eq	p07,p06,0x5D,r15; nop.i	0x0; (p06) br.cond.spnt.few	40000000000B8B90; }

l40000000000B88D0:
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.spnt.few	40000000000B8B90 }

l40000000000B88F0:
	{ adds	r16,0x10,r12; adds	r15,0x10,r12; addl	r14,7724,r1; }
	{ nop.m	0x0; ld4	r16,[r16]; nop.i	0x0; }
	{ cmp4.lt	p06,p07,0x1,r16; nop.i	0x0; (p07) br.cond.spnt.few	40000000000B8B60; }

l40000000000B8920:
	{ ld4	r15,[r15]; st4	[r15],r14; addl	r15,1,r0 }
	{ addl	r14,7728,r1; st4	[r15],r14; adds	r15,0x10,r12; }
	{ ld4	r15,[r15]; adds	r14,0xFFFFFFFFFFFFFFFF,r15; addl	r15,7732,r1; }
	{ st4	[r0],r15; cmp4.eq	p06,p07,0x2,r14; (p07) br.cond.dptk.few	40000000000B86A0; }

l40000000000B8960:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000B7680; }
	{ adds	r1,0x28,r12; ld8	r1,[r1]; nop.i	0x0; }
	{ addl	r14,7724,r1; ld4	r15,[r14]; addl	r14,7728,r1 }
	{ nop.m	0x0; st4	[r15],r14; nop.i	0x0 }

l40000000000B89A0:
	{ cmp4.eq	p06,p07,0x0,r8; addl	r37,19668,r1; addl	r14,7708,r1 }
	{ addl	r38,1,r0; (p06) addl	r8,1,r0; nop.i	0x0 }

l40000000000B89BC:
	{ Invalid; mov	pr,r32,0x0; zxt1	r0,r64 }

l40000000000B89CC:
	{ invala; Invalid; break.i	0x1000 }
	{ Invalid; (p02) invala; (p02) rfi }

l40000000000B89E0:
	{ adds	r16,0x18,r12; ld8	r16,[r16]; nop.i	0x0; }
	{ adds	r14,0x8,r16; ld8	r14,[r14]; nop.i	0x0; }
	{ ld1	r15,[r14]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x21,r15; (p06) br.cond.dptk.few	40000000000B86D0 }

l40000000000B8A20:
	{ adds	r14,0x1,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000B86D0 }

l40000000000B8A50:
	{ adds	r14,0x10,r12; nop.m	0x0; addl	r34,7728,r1; }
	{ ld4	r14,[r14]; cmp4.eq	p07,p06,0x2,r14; addl	r14,2,r0; }
	{ st4	[r14],r34; nop.i	0x0; (p07) br.call.spnt.many	b0,fn40000000000B55C0; }

l40000000000B8A80:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000B7840; }
	{ adds	r1,0x28,r12; nop.m	0x0; adds	r14,0x10,r12 }
	{ ld4	r34,[r34]; nop.m	0x0; cmp4.eq	p06,p07,0x0,r8; }
	{ ld8	r1,[r1]; st4	[r34],r14; (p06) addl	r8,1,r0; }

l40000000000B8AC0:
	{ addl	r14,7724,r1; nop.m	0x0; (p07) adds	r8,0x0,r0; }

l40000000000B8AD0:
	{ ld4	r14,[r14]; nop.i	0x0; br.cond.sptk.few	40000000000B8720 }

l40000000000B8AE0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000B7840; }
	{ adds	r1,0x28,r12; nop.m	0x0; adds	r15,0x10,r12; }
	{ ld8	r1,[r1]; addl	r14,7728,r1; nop.i	0x0; }
	{ ld4	r14,[r14]; st4	[r14],r15; addl	r14,7724,r1; }
	{ ld4	r14,[r14]; nop.i	0x0; br.cond.sptk.few	40000000000B8720 }

l40000000000B8B30:
	{ addl	r37,19668,r1; addl	r15,7708,r1; addl	r38,1,r0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }
	{ st4	[r14],r15; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BBE0; }

l40000000000B8B60:
	{ addl	r37,19668,r1; addl	r15,1,r0; addl	r14,7708,r1 }
	{ addl	r38,1,r0; nop.m	0x0; nop.i	0x0 }
	{ st4	[r15],r14; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BBE0; }

l40000000000B8B90:
	{ addl	r38,-9196,r1; adds	r37,0x0,r0; addl	r39,5,r0; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x28,r12; adds	r37,0x0,r8; adds	r38,0x0,r0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn40000000000B5540; }
	{ nop.m	0x0; break.f	0x0; nop.i	0x0; }
	{ nop.m	0x6; nop.i	0x7; nop.i	0x8 }
	{ nop.m	0x6; nop.i	0x7; nop.i	0x8 }

;; shell_version_string: 40000000000B8C00
;;   Called from:
;;     40000000000219FC (in fn40000000000213C0)
;;     400000000006C51C (in initialize_shell_variables)
;;     40000000000B8BFC (in test_command)
;;     40000000000B8D3C (in show_shell_version)
shell_version_string proc
	{ alloc	r33,ar.pfs,0xB,0x0,0x3; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r32,b0 }
	{ addl	r35,20372,r1; addl	r8,20372,r1; adds	r34,0x0,r1; }
	{ nop.m	0x0; ld1	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B8C70; }

l40000000000B8C50:
	{ nop.m	0x0; mov.i	ar.pfs,r33; mov.spnt	b0,r32,40000000000B8C50 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000000B8C70:
	{ addl	r15,-8868,r1; adds	r14,0x10,r12; addl	r39,-8884,r1 }
	{ addl	r40,-8876,r1; addl	r36,32,r0; addl	r37,1,r0; }
	{ ld8	r15,[r15]; addl	r38,32,r0; addl	r41,45,r0 }
	{ addl	r42,1,r0; ld8	r39,[r39]; nop.i	0x0; }
	{ nop.m	0x0; st8	[r15],r14; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A3E0; }
	{ adds	r1,0x0,r34; addl	r8,20372,r1; nop.i	0x0; }
	{ nop.m	0x0; mov.i	ar.pfs,r33; mov.spnt	b0,r32,40000000000B8CE0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

;; show_shell_version: 40000000000B8D00
;;   Called from:
;;     400000000001E4CC (in main)
;;     40000000000FCAAC (in help_builtin)
;;     40000000000FD75C (in help_builtin)
show_shell_version proc
	{ alloc	r35,ar.pfs,0x9,0x0,0x5; addl	r38,-8860,r1; mov	r34,b2 }
	{ adds	r36,0x0,r1; nop.i	0x0; adds	r37,0x0,r0 }
	{ ld8	r38,[r38]; addl	r39,5,r0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; adds	r33,0x0,r8; br.call.sptk.many	b0,shell_version_string; }
	{ adds	r1,0x0,r36; nop.m	0x0; addl	r37,1,r0 }
	{ adds	r38,0x0,r33; adds	r39,0x0,r8; addl	r40,-8852,r1; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r36; cmp4.eq	p06,p07,0x0,r32; mov.i	ar.pfs,r35 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000B8DA0; }

l40000000000B8D90:
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000B8D90; br.ret	b0 }

l40000000000B8DA0:
	{ addl	r38,-8844,r1; addl	r39,5,r0; adds	r37,0x0,r0; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; adds	r37,0x0,r8; br.call.sptk.many	b0,fn400000000001B380; }
	{ adds	r1,0x0,r36; addl	r39,5,r0; adds	r37,0x0,r0; }
	{ nop.m	0x0; addl	r38,-8836,r1; nop.i	0x0; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; adds	r37,0x0,r8; br.call.sptk.many	b0,fn400000000001B380; }
	{ adds	r1,0x0,r36; addl	r39,5,r0; adds	r37,0x0,r0; }
	{ nop.m	0x0; addl	r38,-8828,r1; nop.i	0x0; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; nop.m	0x0; addl	r37,1,r0 }
	{ adds	r38,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r36; addl	r39,5,r0; adds	r37,0x0,r0; }
	{ nop.m	0x0; addl	r38,-8820,r1; nop.i	0x0; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; nop.m	0x0; addl	r37,1,r0 }
	{ adds	r38,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r36; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000B8EC0; br.ret	b0; }
40000000000B8ED0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000B8EE0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000B8EF0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; fn40000000000B8F00: 40000000000B8F00
;;   Called from:
;;     40000000000BA5CC (in alias_expand)
;;     40000000000BA7AC (in alias_expand)
fn40000000000B8F00 proc
	{ adds	r8,0x1,r33; nop.m	0x0; sxt4	r33,r33; }
	{ nop.m	0x0; sxt4	r14,r8; add	r33,r32,r33; }
	{ add	r14,r32,r14; ld1	r15,[r33]; nop.i	0x0; }
	{ ld1	r14,[r14]; sxt1	r15,r15; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.ret	b0; }

l40000000000B8F50:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000B8F60:
	{ cmp4.eq	p07,p06,0x5C,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B8FD0; }

l40000000000B8F70:
	{ cmp4.eq	p06,p07,r14,r15; nop.i	0x0; (p06) br.ret	b0; }

l40000000000B8F80:
	{ adds	r8,0x1,r8; nop.m	0x0; sxt4	r14,r8; }
	{ add	r14,r32,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000B8F60 }

l40000000000B8FC0:
	{ nop.m	0x0; nop.i	0x0; br.ret	b0 }

l40000000000B8FD0:
	{ adds	r8,0x1,r8; nop.m	0x0; sxt4	r14,r8; }
	{ add	r14,r32,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.ret	b0 }

l40000000000B9010:
	{ adds	r8,0x1,r8; nop.m	0x0; sxt4	r14,r8; }
	{ add	r14,r32,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000B8F60 }

l40000000000B9050:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000B8FC0; }
40000000000B9060 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B9070 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000B9080: 40000000000B9080
;;   Called from:
;;     40000000000B977C (in remove_alias)
fn40000000000B9080 proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; adds	r14,0x8,r32; mov	r33,b1 }
	{ nop.m	0x0; adds	r35,0x0,r1; nop.i	0x0; }
	{ ld8	r36,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r35; nop.i	0x0 }
	{ ld8	r36,[r32]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r35; adds	r36,0x0,r32; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000B90F0; br.ret	b0; }
40000000000B9100 08 18 1D 0A 80 05 E0 00 80 30 20 40 04 00 C4 00 .........0 @....
40000000000B9110 09 20 01 02 00 21 00 01 84 30 20 00 00 00 04 00 . ...!...0 .....
40000000000B9120 09 78 00 1C 18 10 E0 00 40 30 20 00 00 00 04 00 .x......@0 .....
40000000000B9130 09 30 01 1C 00 21 00 00 00 02 00 A0 04 78 00 84 .0...!.......x..
40000000000B9140 09 40 00 1E 00 10 E0 00 38 00 20 00 00 00 04 00 .@......8. .....
40000000000B9150 01 00 00 00 01 00 E0 00 38 28 00 00 01 40 50 00 ........8(...@P.
40000000000B9160 09 00 00 00 01 00 80 40 38 0A 40 00 00 00 04 00 .......@8.@.....
40000000000B9170 11 38 00 10 86 39 00 00 00 02 00 03 30 00 00 43 .8...9......0..C
40000000000B9180 11 00 00 00 01 00 00 00 00 02 00 00 C8 13 F6 58 ...............X
40000000000B9190 08 08 00 48 00 21 00 00 00 02 00 00 00 00 04 00 ...H.!..........
40000000000B91A0 01 00 00 00 01 00 00 18 01 55 00 00 00 00 04 00 .........U......
40000000000B91B0 11 00 00 00 01 00 00 10 05 80 03 80 08 00 84 00 ................

;; initialize_aliases: 40000000000B91C0
;;   Called from:
;;     40000000000B951C (in add_alias)
initialize_aliases proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; mov	r33,b1; addl	r32,7740,r1 }
	{ adds	r35,0x0,r1; ld8	r14,[r32]; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; mov.spnt	b0,r33,40000000000B91E0 }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	40000000000B9200; br.ret	b0; }

l40000000000B91FC:
	{ shladd	r0,r33,0x2,r0; (p04) invala.e	r4; break.i	0x1000 }

l40000000000B9200:
	{ addl	r36,16,r0; nop.i	0x0; br.call.sptk.many	b0,hash_create; }
	{ adds	r1,0x0,r35; st8	[r8],r32; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000B9220; br.ret	b0; }
40000000000B9230 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; find_alias: 40000000000B9240
;;   Called from:
;;     4000000000035B1C (in fn4000000000030880)
;;     40000000000B934C (in get_alias_value)
;;     40000000000B940C (in add_alias)
;;     40000000000B9B6C (in alias_expand_word)
;;     40000000000BA41C (in alias_expand)
;;     40000000000BA41C (in alias_expand)
;;     40000000000E948C (in alias_builtin)
;;     40000000000E97BC (in unalias_builtin)
;;     400000000010EF9C (in describe_command)
find_alias proc
	{ alloc	r34,ar.pfs,0x7,0x0,0x4; addl	r14,7740,r1; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; adds	r36,0x0,r32; }
	{ ld8	r14,[r14]; nop.m	0x0; adds	r38,0x0,r0; }
	{ cmp.eq	p07,p06,0x0,r14; adds	r37,0x0,r14; (p07) br.cond.dpnt.few	40000000000B92D0; }

l40000000000B9280:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,hash_search; }
	{ adds	r14,0x10,r8; cmp.eq	p06,p07,0x0,r8; nop.b	0x0 }
	{ adds	r1,0x0,r35; mov.i	ar.pfs,r34; (p06) br.cond.dpnt.few	40000000000B92D0; }

l40000000000B92B0:
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000B92B0; nop.i	0x0 }
	{ ld8	r8,[r14]; nop.m	0x0; br.ret	b0; }

l40000000000B92D0:
	{ adds	r8,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000B92E0; br.ret	b0; }
40000000000B92F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; get_alias_value: 40000000000B9300
get_alias_value proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; addl	r14,7740,r1; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; adds	r36,0x0,r32; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B9390; }

l40000000000B9340:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,find_alias; }
	{ adds	r14,0x8,r8; cmp.eq	p06,p07,0x0,r8; nop.b	0x0 }
	{ adds	r1,0x0,r35; mov.i	ar.pfs,r34; (p06) br.cond.dpnt.few	40000000000B9390; }

l40000000000B9370:
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000B9370; nop.i	0x0 }
	{ ld8	r8,[r14]; nop.m	0x0; br.ret	b0; }

l40000000000B9390:
	{ adds	r8,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000B93A0; br.ret	b0; }
40000000000B93B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; add_alias: 40000000000B93C0
;;   Called from:
;;     40000000000E960C (in alias_builtin)
add_alias proc
	{ alloc	r39,ar.pfs,0xC,0x0,0x9; addl	r36,7740,r1; mov	r38,b6 }
	{ adds	r40,0x0,r1; nop.m	0x0; adds	r41,0x0,r32; }
	{ nop.m	0x0; ld8	r14,[r36]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000B9510; }

l40000000000B9400:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,find_alias; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r35,0x8,r8; nop.i	0x0 }
	{ adds	r34,0x10,r8; adds	r1,0x0,r40; (p06) br.cond.spnt.few	40000000000B9530; }

l40000000000B9430:
	{ ld8	r41,[r35]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r40; adds	r41,0x0,r33; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r40; adds	r41,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r42,0x0,r33; nop.m	0x0; adds	r1,0x0,r40 }
	{ adds	r41,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ ld1	r14,[r34]; st8	[r8],r35; adds	r1,0x0,r40 }
	{ adds	r41,0x0,r33; and	r35,0xFFFFFFFFFFFFFFFE,r14; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r35,r35; nop.i	0x0; }
	{ st1	[r35],r34; or	r35,0x1,r35; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ add	r8,r33,r8; adds	r1,0x0,r40; mov.i	ar.pfs,r39; }
	{ adds	r33,0xFFFFFFFFFFFFFFFF,r8; nop.m	0x0; mov.spnt	b0,r38,40000000000B94D0; }
	{ ld1	r14,[r33]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x9,r14; cmp4.eq.or.andcm	p07,p06,0x20,r14; nop.i	0x0; }
	{ (p07) st1	[r35],r34; nop.i	0x0; br.ret	b0; }

l40000000000B9506:
	{ break.m	0x4000; (p34) nop; break.i	0x80000 }

l40000000000B9510:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,initialize_aliases; }
	{ adds	r1,0x0,r40; nop.m	0x0; nop.i	0x0 }

l40000000000B9530:
	{ addl	r41,24,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r34,0x0,r8 }
	{ adds	r41,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r40; adds	r41,0x1,r8; nop.i	0x0 }
	{ adds	r35,0x0,r34; adds	r37,0x10,r34; br.call.sptk.many	b0,xmalloc; }
	{ adds	r42,0x0,r32; nop.m	0x0; adds	r1,0x0,r40 }
	{ adds	r41,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r41,0x0,r33 }
	{ st8	[r35],r8,8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r40; adds	r41,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r42,0x0,r33; nop.m	0x0; adds	r1,0x0,r40 }
	{ adds	r41,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; adds	r1,0x0,r40; adds	r41,0x0,r33 }
	{ st8	[r8],r35; st1	[r0],r37; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ add	r8,r33,r8; adds	r1,0x0,r40; adds	r41,0x0,r32; }
	{ adds	r33,0xFFFFFFFFFFFFFFFF,r8; ld1	r14,[r33]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x9,r14; }
	{ cmp4.eq.or.andcm	p07,p06,0x20,r14; (p07) addl	r14,1,r0; nop.i	0x0; }

l40000000000B964C:
	{ Invalid; Invalid; break.i	0x1000 }

l40000000000B9656:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; (p32) nop; (p16) nop.b	0x28000 }
	{ break.m	0x4000; (p21) nop; (p16) nop }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ (p21) fwb; nop; (p48) nop }
	{ Invalid; (p32) nop; (p16) nop.b	0x28000 }
	{ break.m	0x4000; (p04) nop; (p16) nop }
	{ mf.a; nop; break.i	0x80000 }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ Invalid; (p34) nop; Invalid }

;; remove_alias: 40000000000B9700
;;   Called from:
;;     40000000000E97DC (in unalias_builtin)
remove_alias proc
	{ alloc	r36,ar.pfs,0x9,0x0,0x6; addl	r34,7740,r1; mov	r35,b3 }
	{ adds	r37,0x0,r1; nop.m	0x0; adds	r38,0x0,r32; }
	{ ld8	r14,[r34]; nop.m	0x0; adds	r40,0x0,r0; }
	{ cmp.eq	p07,p06,0x0,r14; adds	r39,0x0,r14; (p07) br.cond.dpnt.few	40000000000B9800; }

l40000000000B9740:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,hash_remove; }
	{ adds	r14,0x10,r8; cmp.eq	p06,p07,0x0,r8; nop.i	0x0 }
	{ adds	r33,0x0,r8; adds	r1,0x0,r37; (p06) br.cond.dpnt.few	40000000000B9800; }

l40000000000B9770:
	{ ld8	r38,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn40000000000B9080; }
	{ adds	r14,0x8,r33; nop.m	0x0; adds	r1,0x0,r37; }
	{ ld8	r38,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r37; adds	r38,0x0,r33; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r37; addl	r38,-18596,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,set_itemlist_dirty; }
	{ ld8	r14,[r34]; adds	r1,0x0,r37; mov.i	ar.pfs,r36; }
	{ adds	r14,0xC,r14; nop.m	0x0; mov.spnt	b0,r35,40000000000B97E0; }
	{ ld4	r8,[r14]; nop.i	0x0; br.ret	b0; }

l40000000000B9800:
	{ addl	r8,-1,r0; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000B9810; br.ret	b0; }
40000000000B9820 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B9830 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; delete_all_aliases: 40000000000B9840
;;   Called from:
;;     40000000000505BC (in shell_execve)
;;     40000000000E988C (in unalias_builtin)
delete_all_aliases proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x4; addl	r32,7740,r1; nop.b	0x0 }
	{ addl	r37,-3980,r1; mov	r33,b1; adds	r35,0x0,r1; }
	{ ld8	r14,[r32]; ld8	r37,[r37]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; adds	r36,0x0,r14; (p06) br.cond.dpnt.few	40000000000B98F0; }

l40000000000B9880:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,hash_flush; }
	{ nop.m	0x0; adds	r1,0x0,r35; nop.i	0x0 }
	{ ld8	r36,[r32]; nop.m	0x0; br.call.sptk.many	b0,hash_dispose; }
	{ adds	r1,0x0,r35; st8	[r0],r32; nop.i	0x0; }
	{ addl	r36,-18596,r1; nop.i	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,set_itemlist_dirty; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l40000000000B98F0:
	{ nop.m	0x0; mov.i	ar.pfs,r34; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000B9900; br.ret	b0; }
40000000000B9910 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B9920 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000B9930 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; all_aliases: 40000000000B9940
;;   Called from:
;;     40000000000CCABC (in command_word_completion_function)
;;     40000000000E92FC (in alias_builtin)
all_aliases proc
	{ alloc	r35,ar.pfs,0x9,0x0,0x5; addl	r32,7740,r1; mov	r34,b2 }
	{ adds	r36,0x0,r1; ld8	r14,[r32]; nop.i	0x0; }
	{ adds	r15,0xC,r14; cmp.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000B9B20; }

l40000000000B9970:
	{ nop.m	0x0; ld4	r14,[r15]; nop.i	0x0; }
	{ adds	r15,0x1,r14; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	40000000000B9B20; }

l40000000000B9990:
	{ nop.m	0x0; sxt4	r37,r15; nop.i	0x0; }
	{ shladd	r37,r37,0x3,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r14,[r32]; adds	r19,0x0,r0; adds	r16,0x0,r0 }
	{ adds	r18,0x0,r0; adds	r1,0x0,r36; adds	r33,0x0,r8; }
	{ adds	r15,0x8,r14; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,0x0,r15; (p07) br.cond.dpnt.few	40000000000B9AB0; }

l40000000000B99F0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000B9A00:
	{ ld8	r14,[r14]; sxt4	r15,r16; add	r14,r14,r19 }
	{ shladd	r15,r15,0x3,r33; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	40000000000B9A80; }

l40000000000B9A30:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000B9A40:
	{ adds	r17,0x10,r14; nop.m	0x0; adds	r16,0x1,r16; }
	{ ld8	r17,[r17]; st8	[r15],r8,8; nop.i	0x0; }
	{ st8	[r0],r15; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000B9A40 }

l40000000000B9A80:
	{ ld8	r14,[r32]; adds	r18,0x1,r18; adds	r19,0x8,r19; }
	{ adds	r15,0x8,r14; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r18,r15; (p06) br.cond.dptk.few	40000000000B9A00; }

l40000000000B9AB0:
	{ cmp.eq	p07,p06,0x0,r33; adds	r37,0x0,r33; (p07) br.cond.dpnt.few	40000000000B9B20; }

l40000000000B9AC0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strvec_len; }
	{ adds	r1,0x0,r36; nop.m	0x0; sxt4	r38,r8 }
	{ adds	r37,0x0,r33; addl	r39,8,r0; addl	r40,-3972,r1; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C000; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r36; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000B9B10; br.ret	b0 }

l40000000000B9B20:
	{ adds	r33,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ adds	r8,0x0,r33; mov.spnt	b0,r34,40000000000B9B30; br.ret	b0; }

;; alias_expand_word: 40000000000B9B40
alias_expand_word proc
	{ alloc	r35,ar.pfs,0x7,0x0,0x5; nop.m	0x0; mov	r34,b2 }
	{ adds	r36,0x0,r1; nop.m	0x0; adds	r37,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,find_alias; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r33,0x8,r8; adds	r1,0x0,r36; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B9BE0; }

l40000000000B9B86:
	{ chk.a.nc	r0,3FFFFFFFFF0BA386; nop; (p16) nop }

l40000000000B9B90:
	{ ld8	r37,[r33]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r36; adds	r37,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r37,0x0,r8 }
	{ ld8	r38,[r33]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r36; nop.m	0x0; nop.i	0x0 }

l40000000000B9BE0:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000B9BF0; br.ret	b0; }

;; alias_expand: 40000000000B9C00
alias_expand proc
	{ alloc	r49,ar.pfs,0x16,0x0,0x13; adds	r50,0x0,r1; mov	r48,b0 }
	{ addl	r41,7752,r1; adds	r51,0x0,r32; addl	r46,7748,r1; }
	{ adds	r37,0x0,r0; adds	r35,0x0,r0; adds	r44,0x0,r0 }
	{ addl	r45,1024,r0; adds	r47,0x0,r41; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r34,0x1,r8; adds	r1,0x0,r50; adds	r36,0x0,r0; }
	{ nop.m	0x0; sxt4	r33,r34; nop.i	0x0; }
	{ adds	r51,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r50; adds	r38,0x0,r8; nop.i	0x0 }
	{ adds	r51,0x0,r33; adds	r33,0x0,r35; br.call.sptk.many	b0,xmalloc; }
	{ add	r15,r32,r37; addl	r14,1,r0; adds	r39,0x0,r8 }
	{ adds	r37,0x0,r0; st1	[r0],r38; adds	r1,0x0,r50; }
	{ st4	[r14],r41; ld1.a	r14,[r15]; nop.i	0x0 }
	{ st1	[r0],r39; nop.m	0x0; adds	r43,0x0,r15; }
	{ ld1.c.clr	r14,[r15]; nop.m	0x0; sxt1	r14,r14; }
	{ adds	r52,0x0,r14; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	40000000000BA170; }

l40000000000B9CF0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000B9D00:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r36; (p06) br.cond.dptk.few	40000000000BA620; }

l40000000000B9D10:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x20,r52; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x9,r52; (p06) br.cond.dptk.few	40000000000BA670; }

l40000000000B9D30:
	{ cmp4.eq	p07,p06,0x5C,r52; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000BA6D0; }

l40000000000B9D40:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x22,r52; nop.i	0x0; }
	{ cmp4.eq.or.andcm	p07,p06,0x27,r52; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000BA7A0; }

l40000000000B9D60:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r37; (p06) br.cond.dptk.few	40000000000B9DC0 }

l40000000000B9D70:
	{ nop.m	0x0; addl	r51,-3964,r1; nop.i	0x0; }
	{ ld8	r51,[r51]; nop.i	0x0; br.call.sptk.many	b0,mbschr; }
	{ adds	r1,0x0,r50; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	40000000000B9E00; }

l40000000000B9DA0:
	{ ld4	r14,[r41]; nop.i	0x0; adds	r14,0x1,r14; }
	{ st4	[r14],r41; nop.m	0x0; nop.i	0x0 }

l40000000000B9DC0:
	{ adds	r33,0x1,r33; nop.m	0x0; sxt4	r15,r33; }
	{ add	r15,r32,r15; ld1	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ adds	r52,0x0,r14; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000B9D00; }

l40000000000B9E00:
	{ adds	r51,0x0,r38; cmp4.eq	p07,p06,r33,r35; (p07) br.cond.dpnt.few	40000000000BA150 }

l40000000000B9E10:
	{ sub	r35,r33,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ add	r14,r8,r35,0x1; adds	r1,0x0,r50; adds	r36,0x0,r8; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r14,r34; (p06) br.cond.dptk.few	40000000000B9EA0 }

l40000000000B9E40:
	{ adds	r15,0x32,r35; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000B9E60:
	{ nop.m	0x0; add	r34,r34,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r14,r34; (p06) br.cond.dptk.few	40000000000B9E60 }

l40000000000B9E80:
	{ adds	r51,0x0,r38; sxt4	r52,r34; br.call.sptk.many	b0,xrealloc; }
	{ nop.m	0x0; adds	r1,0x0,r50; adds	r38,0x0,r8 }

l40000000000B9EA0:
	{ nop.m	0x0; sxt4	r51,r36; nop.b	0x0 }
	{ adds	r52,0x0,r43; addl	r42,1,r0; sxt4	r53,r35; }
	{ add	r51,r38,r51; nop.m	0x0; sxt4	r40,r33 }
	{ add	r35,r36,r35; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B920; }
	{ add	r40,r32,r40; ld4	r14,[r41]; sxt4	r35,r35 }
	{ adds	r1,0x0,r50; cmp4.eq	p06,p07,0x0,r14; add	r35,r38,r35 }
	{ ld1.a	r52,[r40]; st1	[r0],r35; nop.i	0x0; }
	{ nop.m	0x0; ld1.c.clr	r52,[r40]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r52,r52; (p07) br.cond.dptk.few	40000000000BA1F0; }

l40000000000B9F30:
	{ nop.m	0x0; sxt1	r52,r52; adds	r42,0x0,r0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r52; (p07) br.cond.dpnt.few	40000000000BA1A0; }

l40000000000B9F50:
	{ (p06) st4	[r0],r47; nop.m	0x0; nop.i	0x0 }

l40000000000B9F56:
	{ break.m	0x4000; nop; (p48) nop }

l40000000000B9F60:
	{ adds	r35,0x0,r33; adds	r36,0x0,r0; sxt4	r37,r33; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000B9F80:
	{ adds	r53,0x0,r36; adds	r51,0x0,r39; nop.i	0x0 }
	{ adds	r52,0x0,r40; add	r36,r39,r36; br.call.sptk.many	b0,fn400000000001B920; }
	{ adds	r1,0x0,r50; adds	r51,0x0,r39; nop.i	0x0 }
	{ addl	r52,92,r0; st1	[r0],r36; br.call.sptk.many	b0,mbschr; }
	{ ld1	r14,[r39]; adds	r1,0x0,r50; cmp.eq	p07,p06,0x0,r8; }
	{ nop.m	0x0; sxt1	r14,r14; (p07) br.cond.dpnt.few	40000000000BA3B0; }

l40000000000B9FE0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000BA3E0; }

l40000000000B9FF0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000BA000:
	{ sub	r33,r35,r33; adds	r51,0x0,r38; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ add	r14,r8,r33,0x1; nop.m	0x0; adds	r1,0x0,r50 }
	{ adds	r36,0x0,r8; nop.m	0x0; add	r43,r8,r33; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r14,r34; (p07) br.cond.dptk.few	40000000000BA0A0 }

l40000000000BA040:
	{ adds	r15,0x32,r43; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000BA060:
	{ nop.m	0x0; add	r34,r34,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r14,r34; (p06) br.cond.dptk.few	40000000000BA060 }

l40000000000BA080:
	{ adds	r51,0x0,r38; sxt4	r52,r34; br.call.sptk.many	b0,xrealloc; }
	{ nop.m	0x0; adds	r1,0x0,r50; adds	r38,0x0,r8 }

l40000000000BA0A0:
	{ nop.m	0x0; sxt4	r51,r36; sxt4	r43,r43 }
	{ adds	r52,0x0,r40; adds	r44,0x0,r0; nop.b	0x0; }
	{ nop.m	0x0; sxt4	r53,r33; nop.i	0x0 }
	{ add	r51,r38,r51; add	r43,r38,r43; br.call.sptk.many	b0,fn400000000001B920; }
	{ adds	r1,0x0,r50; st1	[r0],r43; nop.i	0x0 }

l40000000000BA0F0:
	{ st4	[r0],r41; nop.m	0x0; nop.i	0x0 }

l40000000000BA100:
	{ add	r15,r32,r37; st1	[r0],r39; nop.i	0x0 }
	{ adds	r33,0x0,r35; adds	r37,0x0,r0; adds	r36,0x0,r0; }
	{ ld1	r14,[r15]; adds	r43,0x0,r15; sxt1	r14,r14; }
	{ adds	r52,0x0,r14; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	40000000000B9D00 }

l40000000000BA140:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000BA170 }

l40000000000BA150:
	{ ld1	r14,[r43]; adds	r33,0x0,r35; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000B9E10 }

l40000000000BA170:
	{ adds	r51,0x0,r39; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r8,0x0,r38; adds	r1,0x0,r50; mov.i	ar.pfs,r49; }
	{ nop.m	0x0; mov.spnt	b0,r48,40000000000BA190; br.ret	b0 }

l40000000000BA1A0:
	{ nop.m	0x0; addl	r51,-3964,r1; nop.i	0x0; }
	{ ld8	r51,[r51]; nop.i	0x0; br.call.sptk.many	b0,mbschr; }
	{ cmp.eq	p07,p06,0x0,r8; ld1	r14,[r40]; adds	r1,0x0,r50; }
	{ (p06) addl	r8,1,r0; nop.m	0x0; sxt1	r52,r14; }

l40000000000BA1D6:
	{ break.m	0x4000; (p26) cmp4.lt	p00,p00,0xE,r20; (p01) nop }

l40000000000BA1E6:
	{ break.m	0x4000; (p21) nop; break.i	0x80000 }

l40000000000BA1F0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x9,r52; adds	r35,0x0,r33 }
	{ st4	[r42],r41; cmp4.eq	p08,p09,0x0,r52; (p08) br.cond.spnt.few	40000000000B9F60; }

l40000000000BA210:
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x20,r52; (p07) br.cond.dpnt.few	40000000000BA340; }

l40000000000BA220:
	{ (p06) adds	r36,0x0,r40; nop.m	0x0; nop.i	0x0 }

l40000000000BA226:
	{ break.m	0x4000; nop; break.i	0x80000 }

l40000000000BA230:
	{ nop.m	0x0; addl	r51,-3956,r1; nop.i	0x0; }

l40000000000BA232:
	{ adds	r32,0xFFFFFFFFFFFFF800,r0; (p17) break.i	0x4FC3F; addl	r32,-1572352,r0 }
	{ (p48) break.m	0x2030C; nop; Invalid; }
	{ Invalid; nop.i	0xF20E2; Invalid }

l40000000000BA260:
	{ ld1	r14,[r36]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p09,p08,0x5C,r14; nop.m	0x0; cmp4.eq	p07,p06,0x22,r14; }
	{ nop.m	0x0; (p09) adds	r35,0x1,r35; cmp4.eq.or.andcm	p07,p06,0x27,r14 }

l40000000000BA28C:
	{ (p19) rsm	0x3CE30E; Invalid; (p16) nop }

l40000000000BA29C:
	{ (p25) ldfp8	f0,f64,[r33]; zxt1	r96,r64; Invalid }

l40000000000BA2A0:
	{ adds	r35,0x1,r35; nop.m	0x0; sxt4	r37,r35; }
	{ add	r36,r32,r37; ld1	r14,[r36]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r52,r14; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x20,r52; cmp4.eq	p08,p09,0x0,r52; (p08) br.cond.dpnt.few	40000000000BA300; }

l40000000000BA2E0:
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x9,r52; (p06) br.cond.dptk.few	40000000000BA230; }

l40000000000BA2F0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000BA300:
	{ sub	r14,r35,r33; cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r36,r14; (p07) br.cond.dptk.few	40000000000B9F80; }

l40000000000BA320:
	{ ld1	r14,[r36]; adds	r36,0x0,r0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000B9F80 }

l40000000000BA340:
	{ addl	r36,1,r0; adds	r51,0x0,r39; adds	r52,0x0,r40 }
	{ adds	r35,0x1,r35; adds	r53,0x0,r36; add	r36,r39,r36 }
	{ nop.m	0x0; sxt4	r37,r35; br.call.sptk.many	b0,fn400000000001B920; }
	{ adds	r1,0x0,r50; adds	r51,0x0,r39; nop.i	0x0 }
	{ addl	r52,92,r0; st1	[r0],r36; br.call.sptk.many	b0,mbschr; }
	{ ld1	r14,[r39]; adds	r1,0x0,r50; cmp.eq	p07,p06,0x0,r8; }
	{ nop.m	0x0; sxt1	r14,r14; (p06) br.cond.dptk.few	40000000000B9FE0; }

l40000000000BA3B0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000BA000 }

l40000000000BA3C0:
	{ nop.m	0x0; or	r42,r44,r42; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r42; (p06) br.cond.dpnt.few	40000000000BA6C0 }

l40000000000BA3E0:
	{ nop.m	0x0; ld4	r14,[r46]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000BA000; }

l40000000000BA400:
	{ (p07) adds	r42,0x0,r0; nop.m	0x0; nop.i	0x0 }

l40000000000BA406:
	{ break.m	0x4000; nop; (p48) nop }

l40000000000BA410:
	{ adds	r51,0x0,r39; nop.i	0x0; br.call.sptk.many	b0,find_alias; }

l40000000000BA412:
	{ (p48) break.m	0x42009; Invalid; (p28) nop; }
	{ break.m	0x720E2; mov	pr,0x20; Invalid }
	{ (p32) break.m	0x4200C; nop; Invalid }

l40000000000BA440:
	{ nop.m	0x0; ld8	r36,[r8]; nop.i	0x0; }
	{ adds	r51,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r50; nop.m	0x0; adds	r33,0x0,r8 }
	{ adds	r51,0x0,r38; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r15,0x3,r33; adds	r1,0x0,r50; adds	r40,0x0,r8; }
	{ nop.m	0x0; add	r15,r15,r8; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r15,r34; (p06) br.cond.dptk.few	40000000000BA500 }

l40000000000BA4B0:
	{ adds	r16,0x32,r33; nop.i	0x0; add	r14,r34,r16; }

l40000000000BA4C0:
	{ adds	r34,0x0,r14; nop.m	0x0; add	r14,r14,r16; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r15,r34; (p06) br.cond.dptk.few	40000000000BA4C0 }

l40000000000BA4E0:
	{ adds	r51,0x0,r38; sxt4	r52,r34; br.call.sptk.many	b0,xrealloc; }
	{ nop.m	0x0; adds	r1,0x0,r50; adds	r38,0x0,r8 }

l40000000000BA500:
	{ nop.m	0x0; sxt4	r51,r40; adds	r52,0x0,r36; }
	{ add	r51,r38,r51; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; sxt4	r14,r33; cmp4.eq	p07,p06,0x0,r33 }
	{ adds	r1,0x0,r50; (p06) addl	r33,1,r0; add	r36,r36,r14; }

l40000000000BA53C:
	{ (p18) nop; (p52) nop }

l40000000000BA546:
	{ Invalid; (p21) nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD7DFF6; nop; (p32) nop }

l40000000000BA560:
	{ ld1	r14,[r36]; nop.m	0x0; addl	r44,1,r0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x20,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x9,r14; (p06) br.cond.dptk.few	40000000000BA0F0 }

l40000000000BA590:
	{ ld4	r44,[r46]; st4	[r0],r41; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r44; (p06) addl	r44,1,r0; nop.i	0x0; }

l40000000000BA5AC:
	{ invala; nop; zxt1	r0,r64 }

l40000000000BA5BC:
	{ (p26) shladd	r127,r63,0x2,r36; (p06) nop; (p06) epc }

l40000000000BA5C0:
	{ adds	r52,0x0,r35; adds	r51,0x0,r32; br.call.sptk.many	b0,fn40000000000B8F00; }
	{ nop.m	0x0; adds	r1,0x0,r50; adds	r35,0x0,r8; }

l40000000000BA5E0:
	{ nop.m	0x0; sxt4	r37,r35; add	r36,r32,r37; }
	{ ld1	r14,[r36]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	40000000000BA2A0 }

l40000000000BA610:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000BA300 }

l40000000000BA620:
	{ adds	r33,0x1,r33; adds	r36,0x0,r0; sxt4	r15,r33; }
	{ add	r15,r32,r15; ld1	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ adds	r52,0x0,r14; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000B9D00 }

l40000000000BA660:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000B9E00 }

l40000000000BA670:
	{ adds	r33,0x1,r33; adds	r37,0x0,r0; sxt4	r15,r33; }
	{ add	r15,r32,r15; ld1	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ adds	r52,0x0,r14; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000B9D00 }

l40000000000BA6B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000B9E00 }

l40000000000BA6C0:
	{ nop.m	0x0; addl	r42,1,r0; br.cond.sptk.few	40000000000BA410 }

l40000000000BA6D0:
	{ adds	r15,0x1,r15; ld1	r40,[r15]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r40; zxt1	r40,r40; (p06) br.cond.dpnt.few	40000000000B9E00; }

l40000000000BA6F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C3C0; }
	{ ld8	r14,[r8]; adds	r1,0x0,r50; shladd	r40,r40,0x1,r14; }
	{ ld2	r14,[r40]; and	r14,r45,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; }
	{ nop.m	0x0; (p06) addl	r36,1,r0; (p06) br.cond.dptk.few	40000000000B9DC0 }

l40000000000BA73C:
	{ (p52) nop; zxt1	r32,r64; break.b	0x1000 }

l40000000000BA740:
	{ adds	r37,0x1,r37; nop.m	0x0; nop.i	0x0 }

l40000000000BA750:
	{ adds	r33,0x1,r33; nop.m	0x0; sxt4	r15,r33; }
	{ add	r15,r32,r15; ld1	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ adds	r52,0x0,r14; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000B9D00 }

l40000000000BA790:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000B9E00; }

l40000000000BA7A0:
	{ adds	r52,0x0,r33; adds	r51,0x0,r32; br.call.sptk.many	b0,fn40000000000B8F00; }
	{ nop.m	0x0; sxt4	r40,r8; adds	r1,0x0,r50 }
	{ adds	r33,0x0,r8; add	r40,r32,r40; nop.i	0x0; }
	{ ld1	r14,[r40]; adds	r40,0x1,r40; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000B9E00; }

l40000000000BA7F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C3C0; }
	{ nop.m	0x0; ld1	r15,[r40]; adds	r1,0x0,r50 }
	{ ld8	r14,[r8]; shladd	r14,r15,0x1,r14; nop.i	0x0; }
	{ ld2	r14,[r14]; and	r14,r45,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000B9DC0 }

l40000000000BA840:
	{ nop.m	0x0; adds	r37,0x1,r37; br.cond.sptk.few	40000000000BA750; }

l40000000000BA850:
	{ nop.m	0x0; sxt4	r37,r35; nop.i	0x0; }
	{ nop.m	0x0; add	r36,r32,r37; br.cond.sptk.few	40000000000BA300; }
40000000000BA870 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; array_walk: 40000000000BA880
array_walk proc
	{ alloc	r38,ar.pfs,0xA,0x0,0x8; adds	r14,0x10,r32; mov	r37,b5 }
	{ cmp.eq	p07,p06,0x0,r32; adds	r36,0x18,r32; (p07) br.cond.dpnt.few	40000000000BA960; }

l40000000000BA8A0:
	{ ld4	r14,[r14]; nop.m	0x0; adds	r39,0x0,r1; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BA960; }

l40000000000BA8C0:
	{ ld8	r14,[r36]; adds	r15,0x10,r14; nop.i	0x0; }
	{ nop.m	0x0; ld8	r35,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,r35,r14; (p06) br.cond.dpnt.few	40000000000BA960; }

l40000000000BA8F0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000BA900:
	{ ld8	r14,[r33],8; nop.m	0x0; adds	r40,0x0,r35 }
	{ adds	r41,0x0,r34; nop.m	0x0; adds	r35,0x10,r35; }
	{ ld8	r1,[r33],-8; mov.spnt	b6,r14,40000000000BA920; br.call.sptk.many	b0,b6; }
	{ adds	r1,0x0,r39; cmp4.lt	p06,p07,r8,r0; (p06) br.cond.dpnt.few	40000000000BA960; }

l40000000000BA940:
	{ ld8	r35,[r35]; ld8	r14,[r36]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r35,r14; (p06) br.cond.dptk.few	40000000000BA900 }

l40000000000BA960:
	{ nop.m	0x0; mov.i	ar.pfs,r38; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000BA970; br.ret	b0; }

;; array_quote: 40000000000BA980
;;   Called from:
;;     40000000000BD90C (in array_modcase)
;;     40000000000BDD5C (in array_patsub)
;;     40000000000BE1AC (in array_subrange)
array_quote proc
	{ alloc	r38,ar.pfs,0x9,0x0,0x8; adds	r36,0x18,r32; mov	r37,b5 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r15,0x10,r32; (p06) br.cond.dpnt.few	40000000000BAA90; }

l40000000000BA9A0:
	{ ld8	r14,[r36]; nop.m	0x0; adds	r39,0x0,r1; }
	{ cmp.eq	p06,p07,0x0,r14; adds	r16,0x10,r14; (p06) br.cond.dpnt.few	40000000000BAAB0; }

l40000000000BA9C0:
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r15; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BAAB0; }

l40000000000BA9E0:
	{ nop.m	0x0; ld8	r33,[r16]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r33,r14; (p07) br.cond.dpnt.few	40000000000BAA90; }

l40000000000BAA00:
	{ nop.m	0x0; adds	r34,0x8,r33; nop.i	0x0; }
	{ ld8	r40,[r34]; nop.i	0x0; br.call.sptk.many	b0,quote_string; }
	{ ld8	r40,[r34]; adds	r1,0x0,r39; adds	r35,0x0,r8; }
	{ cmp.eq	p06,p07,0x0,r40; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BAA60; }

l40000000000BAA40:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r39; nop.m	0x0; nop.i	0x0 }

l40000000000BAA60:
	{ adds	r33,0x10,r33; ld8	r14,[r36]; nop.i	0x0 }
	{ st8	[r35],r34; ld8	r33,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r33,r14; (p06) br.cond.dptk.few	40000000000BAA00 }

l40000000000BAA90:
	{ adds	r8,0x0,r32; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000BAAA0; br.ret	b0 }

l40000000000BAAB0:
	{ adds	r32,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ adds	r8,0x0,r32; mov.spnt	b0,r37,40000000000BAAC0; br.ret	b0; }
40000000000BAAD0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000BAAE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000BAAF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; array_quote_escapes: 40000000000BAB00
;;   Called from:
;;     40000000000BDA5C (in array_modcase)
;;     40000000000BDEAC (in array_patsub)
;;     40000000000BE35C (in array_subrange)
array_quote_escapes proc
	{ alloc	r38,ar.pfs,0x9,0x0,0x8; adds	r36,0x18,r32; mov	r37,b5 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r15,0x10,r32; (p06) br.cond.dpnt.few	40000000000BAC10; }

l40000000000BAB20:
	{ ld8	r14,[r36]; nop.m	0x0; adds	r39,0x0,r1; }
	{ cmp.eq	p06,p07,0x0,r14; adds	r16,0x10,r14; (p06) br.cond.dpnt.few	40000000000BAC30; }

l40000000000BAB40:
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r15; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BAC30; }

l40000000000BAB60:
	{ nop.m	0x0; ld8	r33,[r16]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r33,r14; (p07) br.cond.dpnt.few	40000000000BAC10; }

l40000000000BAB80:
	{ nop.m	0x0; adds	r34,0x8,r33; nop.i	0x0; }
	{ ld8	r40,[r34]; nop.i	0x0; br.call.sptk.many	b0,quote_escapes; }
	{ ld8	r40,[r34]; adds	r1,0x0,r39; adds	r35,0x0,r8; }
	{ cmp.eq	p06,p07,0x0,r40; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BABE0; }

l40000000000BABC0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r39; nop.m	0x0; nop.i	0x0 }

l40000000000BABE0:
	{ adds	r33,0x10,r33; ld8	r14,[r36]; nop.i	0x0 }
	{ st8	[r35],r34; ld8	r33,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r33,r14; (p06) br.cond.dptk.few	40000000000BAB80 }

l40000000000BAC10:
	{ adds	r8,0x0,r32; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000BAC20; br.ret	b0 }

l40000000000BAC30:
	{ adds	r32,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ adds	r8,0x0,r32; mov.spnt	b0,r37,40000000000BAC40; br.ret	b0; }
40000000000BAC50 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000BAC60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000BAC70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; array_dequote: 40000000000BAC80
array_dequote proc
	{ alloc	r38,ar.pfs,0x9,0x0,0x8; adds	r36,0x18,r32; mov	r37,b5 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r15,0x10,r32; (p06) br.cond.dpnt.few	40000000000BAD90; }

l40000000000BACA0:
	{ ld8	r14,[r36]; nop.m	0x0; adds	r39,0x0,r1; }
	{ cmp.eq	p06,p07,0x0,r14; adds	r16,0x10,r14; (p06) br.cond.dpnt.few	40000000000BADB0; }

l40000000000BACC0:
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r15; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BADB0; }

l40000000000BACE0:
	{ nop.m	0x0; ld8	r33,[r16]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r33,r14; (p07) br.cond.dpnt.few	40000000000BAD90; }

l40000000000BAD00:
	{ nop.m	0x0; adds	r34,0x8,r33; nop.i	0x0; }
	{ ld8	r40,[r34]; nop.i	0x0; br.call.sptk.many	b0,dequote_string; }
	{ ld8	r40,[r34]; adds	r1,0x0,r39; adds	r35,0x0,r8; }
	{ cmp.eq	p06,p07,0x0,r40; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BAD60; }

l40000000000BAD40:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r39; nop.m	0x0; nop.i	0x0 }

l40000000000BAD60:
	{ adds	r33,0x10,r33; ld8	r14,[r36]; nop.i	0x0 }
	{ st8	[r35],r34; ld8	r33,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r33,r14; (p06) br.cond.dptk.few	40000000000BAD00 }

l40000000000BAD90:
	{ adds	r8,0x0,r32; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000BADA0; br.ret	b0 }

l40000000000BADB0:
	{ adds	r32,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ adds	r8,0x0,r32; mov.spnt	b0,r37,40000000000BADC0; br.ret	b0; }
40000000000BADD0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000BADE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000BADF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; array_dequote_escapes: 40000000000BAE00
array_dequote_escapes proc
	{ alloc	r38,ar.pfs,0x9,0x0,0x8; adds	r36,0x18,r32; mov	r37,b5 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r15,0x10,r32; (p06) br.cond.dpnt.few	40000000000BAF10; }

l40000000000BAE20:
	{ ld8	r14,[r36]; nop.m	0x0; adds	r39,0x0,r1; }
	{ cmp.eq	p06,p07,0x0,r14; adds	r16,0x10,r14; (p06) br.cond.dpnt.few	40000000000BAF30; }

l40000000000BAE40:
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r15; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BAF30; }

l40000000000BAE60:
	{ nop.m	0x0; ld8	r33,[r16]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r33,r14; (p07) br.cond.dpnt.few	40000000000BAF10; }

l40000000000BAE80:
	{ nop.m	0x0; adds	r34,0x8,r33; nop.i	0x0; }
	{ ld8	r40,[r34]; nop.i	0x0; br.call.sptk.many	b0,dequote_escapes; }
	{ ld8	r40,[r34]; adds	r1,0x0,r39; adds	r35,0x0,r8; }
	{ cmp.eq	p06,p07,0x0,r40; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BAEE0; }

l40000000000BAEC0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r39; nop.m	0x0; nop.i	0x0 }

l40000000000BAEE0:
	{ adds	r33,0x10,r33; ld8	r14,[r36]; nop.i	0x0 }
	{ st8	[r35],r34; ld8	r33,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r33,r14; (p06) br.cond.dptk.few	40000000000BAE80 }

l40000000000BAF10:
	{ adds	r8,0x0,r32; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000BAF20; br.ret	b0 }

l40000000000BAF30:
	{ adds	r32,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ adds	r8,0x0,r32; mov.spnt	b0,r37,40000000000BAF40; br.ret	b0; }
40000000000BAF50 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000BAF60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000BAF70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; array_remove_quoted_nulls: 40000000000BAF80
;;   Called from:
;;     40000000000BDB0C (in array_modcase)
;;     40000000000BDF5C (in array_patsub)
;;     40000000000BE3CC (in array_subrange)
array_remove_quoted_nulls proc
	{ alloc	r37,ar.pfs,0x8,0x0,0x7; adds	r35,0x18,r32; mov	r36,b4 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r15,0x10,r32; (p06) br.cond.dpnt.few	40000000000BB050; }

l40000000000BAFA0:
	{ ld8	r14,[r35]; nop.m	0x0; adds	r38,0x0,r1; }
	{ cmp.eq	p06,p07,0x0,r14; adds	r16,0x10,r14; (p06) br.cond.dpnt.few	40000000000BB070; }

l40000000000BAFC0:
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r15; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BB070; }

l40000000000BAFE0:
	{ nop.m	0x0; ld8	r33,[r16]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r33,r14; (p07) br.cond.dpnt.few	40000000000BB050; }

l40000000000BB000:
	{ adds	r34,0x8,r33; nop.m	0x0; adds	r33,0x10,r33; }
	{ ld8	r39,[r34]; nop.i	0x0; br.call.sptk.many	b0,remove_quoted_nulls; }
	{ ld8	r14,[r35]; nop.m	0x0; adds	r1,0x0,r38 }
	{ st8	[r8],r34; ld8	r33,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r33,r14; (p06) br.cond.dptk.few	40000000000BB000 }

l40000000000BB050:
	{ adds	r8,0x0,r32; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000BB060; br.ret	b0 }

l40000000000BB070:
	{ adds	r32,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ adds	r8,0x0,r32; mov.spnt	b0,r36,40000000000BB080; br.ret	b0; }
40000000000BB090 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000BB0A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000BB0B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; array_create_element: 40000000000BB0C0
;;   Called from:
;;     40000000000BB24C (in array_rshift)
;;     40000000000BB49C (in array_create)
;;     40000000000BB58C (in array_slice)
;;     40000000000BB73C (in array_copy)
;;     40000000000BBE2C (in array_insert)
array_create_element proc
	{ alloc	r36,ar.pfs,0x8,0x0,0x6; mov	r35,b3; adds	r37,0x0,r1; }
	{ addl	r38,32,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ cmp.eq	p06,p07,0x0,r33; adds	r1,0x0,r37; adds	r34,0x0,r8 }
	{ adds	r38,0x0,r33; st8	[r32],r8; nop.i	0x0; }
	{ (p06) adds	r17,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BB160; }

l40000000000BB106:
	{ chk.a.nc	r0,3FFFFFFFFF0BB906; nop; break.i	0x80000 }

l40000000000BB110:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r37; adds	r38,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r38,0x0,r8 }
	{ adds	r39,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; adds	r1,0x0,r37; adds	r17,0x0,r8 }

l40000000000BB160:
	{ adds	r16,0x8,r34; adds	r15,0x18,r34; nop.b	0x0 }
	{ adds	r14,0x10,r34; adds	r8,0x0,r34; mov.i	ar.pfs,r36; }
	{ st8	[r17],r16; st8	[r0],r15; mov.spnt	b0,r35,40000000000BB180; }
	{ st8	[r0],r14; nop.i	0x0; br.ret	b0; }
40000000000BB1A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000BB1B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; array_rshift: 40000000000BB1C0
;;   Called from:
;;     400000000001FD5C (in main)
;;     400000000001FDCC (in main)
;;     400000000001FE2C (in main)
;;     400000000002016C (in main)
;;     400000000006AB0C (in push_args)
;;     400000000006AB5C (in push_args)
;;     40000000000BB41C (in array_shift_element)
;;     40000000000F4BEC (in fn40000000000F4180)
;;     40000000000F4C5C (in fn40000000000F4180)
;;     40000000000F4CAC (in fn40000000000F4180)
;;     40000000000F4D1C (in fn40000000000F4180)
;;     40000000000F4D1C (in fn40000000000F4180)
;;     40000000000F4D6C (in fn40000000000F4180)
;;     40000000000F4D6C (in fn40000000000F4180)
;;     40000000000F567C (in fn40000000000F4180)
;;     40000000000F56EC (in fn40000000000F4180)
;;     40000000000F573C (in fn40000000000F4180)
array_rshift proc
	{ alloc	r39,ar.pfs,0xB,0x0,0x9; cmp.eq	p06,p07,0x0,r32; nop.b	0x0 }
	{ adds	r36,0x10,r32; mov	r38,b6; adds	r40,0x0,r1; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BB370; }

l40000000000BB1E6:
	{ chk.a.nc	r0,3FFFFFFFFF0BB9E6; nop; break.i	0x80000 }

l40000000000BB1F0:
	{ nop.m	0x0; ld4	r8,[r36]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r8; (p07) br.cond.dptk.few	40000000000BB390; }

l40000000000BB210:
	{ adds	r37,0x18,r32; cmp4.lt	p07,p06,0x0,r33; nop.i	0x0 }
	{ adds	r41,0x0,r0; adds	r42,0x0,r34; (p06) br.cond.dpnt.few	40000000000BB370; }

l40000000000BB230:
	{ ld8	r15,[r37]; cmp.eq	p07,p06,0x0,r34; adds	r14,0x10,r15; }
	{ ld8	r35,[r14]; (p07) br.cond.dpnt.few	40000000000BB2E0; br.call.sptk.many	b0,array_create_element; }

l40000000000BB24C:
	{ (p52) cmp.lt.unc	p63,p08,r63,r44; (p01) invala; (p01) cmp.eq	p00,p08,r9,r4 }
	{ (p12) nop; zxt1	r0,r64; break.i	0x1000; }
	{ nop; (p02) nop; (p02) brp.sptk	b3,40000000000BB6CC; }
	{ (p08) cmp.lt	p14,p08,r0,r66; czx1.r	r0,r97; dep	r100,r4,r102,63,9 }
	{ (p08) nop; break.i	0x1000; Invalid }
	{ Invalid; (p04) cmp4.eq.or.andcm	p02,p48,r8,r64; Invalid }

l40000000000BB2A6:
	{ (p07) fwb; nop; br.call.spnt.many	b0,b3; }

l40000000000BB2AC:
	{ nop; Invalid; Invalid }
	{ nop; break.i	0x1000; Invalid }
	{ Invalid; Invalid; mov	pr,r32,0x0 }

l40000000000BB2D6:
	{ chk.a.nc	r0,3FFFFFFFFF0BBAD6; nop; break.i	0x80000 }

l40000000000BB2E0:
	{ nop.m	0x0; cmp.eq	p07,p06,r15,r35; (p07) br.cond.dpnt.few	40000000000BB330; }

l40000000000BB2F0:
	{ nop.m	0x0; sxt4	r33,r33; nop.i	0x0; }

l40000000000BB300:
	{ ld8	r14,[r35]; add	r14,r14,r33; nop.i	0x0; }
	{ st8	[r35],r16,16; ld8	r35,[r35]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r15,r35; (p06) br.cond.dptk.few	40000000000BB300 }

l40000000000BB330:
	{ adds	r15,0x18,r15; addl	r14,7756,r1; adds	r16,0x8,r32; }
	{ ld8	r17,[r15]; ld8	r15,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,r15,r32; ld8	r15,[r17]; nop.i	0x0; }
	{ st8	[r15],r16; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BB3C0 }

l40000000000BB370:
	{ nop.m	0x0; mov.i	ar.pfs,r39; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000BB380; br.ret	b0 }

l40000000000BB390:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r34; (p07) br.cond.dptk.few	40000000000BB210 }

l40000000000BB3A0:
	{ nop.m	0x0; mov.i	ar.pfs,r39; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000BB3B0; br.ret	b0 }

l40000000000BB3C0:
	{ st8	[r0],r14; addl	r14,7764,r1; mov.i	ar.pfs,r39; }
	{ st8	[r0],r14; mov.spnt	b0,r38,40000000000BB3D0; br.ret	b0; }
40000000000BB3E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000BB3F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; array_shift_element: 40000000000BB400
array_shift_element proc
	{ alloc	r16,ar.pfs,0x3,0x0,0x3; adds	r34,0x0,r33; addl	r33,1,r0; }
	{ alloc	r2,ar.pfs,0x3,0x0,0x0; nop.i	0x0; br.cond.sptk.many	array_rshift; }
40000000000BB420 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000BB430 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; array_create: 40000000000BB440
;;   Called from:
;;     4000000000067A8C (in make_new_array_variable)
;;     400000000006835C (in make_local_array_variable)
;;     40000000000BB51C (in array_slice)
;;     40000000000BB6AC (in array_copy)
;;     40000000000BC9AC (in array_from_word_list)
;;     40000000000BE8EC (in convert_var_to_array)
array_create proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x4; mov	r33,b1; adds	r35,0x0,r1; }
	{ addl	r36,32,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r14,0x0,r8; adds	r15,0x10,r8; adds	r1,0x0,r35 }
	{ adds	r32,0x0,r8; addl	r36,-1,r0; adds	r37,0x0,r0; }
	{ st4	[r14],r8,8; st4	[r0],r15; addl	r15,-1,r0; }
	{ st8	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,array_create_element; }
	{ adds	r14,0x0,r8; adds	r8,0x0,r32; nop.b	0x0 }
	{ adds	r32,0x18,r32; adds	r1,0x0,r35; mov.i	ar.pfs,r34; }
	{ adds	r16,0x10,r14; adds	r15,0x18,r14; mov.spnt	b0,r33,40000000000BB4C0; }
	{ st8	[r14],r16; st8	[r14],r15; nop.i	0x0; }
	{ st8	[r14],r32; nop.i	0x0; br.ret	b0; }
40000000000BB4F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; array_slice: 40000000000BB500
;;   Called from:
;;     40000000000BE17C (in array_subrange)
array_slice proc
	{ alloc	r40,ar.pfs,0xC,0x0,0xA; mov	r39,b7; adds	r41,0x0,r1; }
	{ adds	r36,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,array_create; }
	{ ld4	r15,[r32]; adds	r14,0x0,r33; adds	r37,0x18,r8 }
	{ adds	r1,0x0,r41; adds	r38,0x0,r8; cmp.eq	p06,p07,r34,r33; }
	{ st4	[r15],r8; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BB640; }

l40000000000BB550:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000BB560:
	{ adds	r15,0x8,r14; adds	r35,0x0,r14; adds	r36,0x1,r36; }
	{ nop.m	0x0; ld8	r42,[r35],16; nop.i	0x0 }
	{ ld8	r43,[r15]; nop.m	0x0; br.call.sptk.many	b0,array_create_element; }
	{ ld8	r14,[r37]; adds	r17,0x10,r8; adds	r19,0x18,r8 }
	{ adds	r1,0x0,r41; ld8	r20,[r8]; nop.i	0x0; }
	{ adds	r15,0x18,r14; ld8	r16,[r15]; nop.i	0x0; }
	{ adds	r18,0x10,r16; st8	[r16],r19; nop.i	0x0 }
	{ st8	[r8],r15; st8	[r8],r18; nop.i	0x0 }
	{ st8	[r14],r17; ld8	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r14,r34; (p06) br.cond.dptk.few	40000000000BB560 }

l40000000000BB600:
	{ adds	r15,0x10,r38; adds	r14,0x8,r38; nop.b	0x0 }
	{ adds	r8,0x0,r38; nop.m	0x0; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; st4	[r36],r15; nop.b	0x0 }
	{ st8	[r20],r14; mov.spnt	b0,r39,40000000000BB630; br.ret	b0 }

l40000000000BB640:
	{ adds	r20,0x0,r0; adds	r36,0x0,r0; mov.i	ar.pfs,r40 }
	{ adds	r15,0x10,r38; adds	r14,0x8,r38; adds	r8,0x0,r38; }
	{ nop.m	0x0; st4	[r36],r15; nop.b	0x0 }
	{ st8	[r20],r14; mov.spnt	b0,r39,40000000000BB670; br.ret	b0; }

;; array_copy: 40000000000BB680
;;   Called from:
;;     400000000006EE1C (in save_pipestatus_array)
;;     40000000000BD80C (in array_modcase)
;;     40000000000BDC4C (in array_patsub)
array_copy proc
	{ alloc	r38,ar.pfs,0xA,0x0,0x8; cmp.eq	p06,p07,0x0,r32; mov	r37,b5 }
	{ adds	r39,0x0,r1; nop.m	0x0; adds	r34,0x18,r32; }
	{ (p06) adds	r36,0x0,r0; (p06) br.cond.dpnt.few	40000000000BB7B0; br.call.sptk.many	b0,array_create; }

l40000000000BB6A6:
	{ Invalid; (p32) nop; (p32) nop; }

l40000000000BB6AC:
	{ (p45) cmp.lt.unc	p63,p08,r63,r44; (p01) invala; (p02) cmp.eq.unc	p00,p08,r8,r6 }
	{ nop; (p04) nop; (p02) nop; }
	{ (p12) nop; (p02) nop }
	{ Invalid; (p04) dep	r0,r2,r64,62,1; Invalid }
	{ nop; (p17) nop; Invalid }
	{ cmp.lt	p00,p09,r1,r0; Invalid; Invalid }
	{ Invalid; (p16) cmp.lt.unc	p36,p08,r3,r102; (p32) mov	pr,r100,0xE006 }
	{ (p05) cmp.eq	p00,p02,r64,r33; (p01) nop; zxt1	r64,r64 }

l40000000000BB720:
	{ adds	r15,0x8,r14; adds	r33,0x0,r14; nop.i	0x0 }
	{ ld8	r40,[r33],16; ld8	r41,[r15]; br.call.sptk.many	b0,array_create_element; }
	{ ld8	r14,[r35]; adds	r18,0x10,r8; adds	r20,0x18,r8 }
	{ adds	r1,0x0,r39; ld8	r17,[r34]; nop.i	0x0; }
	{ adds	r15,0x18,r14; ld8	r16,[r15]; nop.i	0x0; }
	{ adds	r19,0x10,r16; st8	[r16],r20; nop.i	0x0 }
	{ st8	[r8],r15; st8	[r8],r19; nop.i	0x0 }
	{ st8	[r14],r18; ld8	r14,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r14,r17; (p06) br.cond.dptk.few	40000000000BB720 }

l40000000000BB7B0:
	{ adds	r8,0x0,r36; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000BB7C0; br.ret	b0; }
40000000000BB7D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000BB7E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000BB7F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; array_dispose_element: 40000000000BB800
;;   Called from:
;;     400000000006AD4C (in pop_args)
;;     400000000006ADEC (in pop_args)
;;     400000000006AE5C (in pop_args)
;;     40000000000BB93C (in array_flush)
;;     40000000000BBBBC (in array_shift)
;;     40000000000BBD8C (in array_dispose)
;;     40000000000BC08C (in array_insert)
;;     40000000000C029C (in unbind_array_element)
;;     40000000000F4F6C (in fn40000000000F4180)
;;     40000000000F4FBC (in fn40000000000F4180)
;;     40000000000F509C (in fn40000000000F4180)
;;     40000000000F511C (in fn40000000000F4180)
;;     40000000000F516C (in fn40000000000F4180)
array_dispose_element proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; adds	r14,0x8,r32; mov	r33,b1 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r35,0x0,r1; (p06) br.cond.dpnt.few	40000000000BB880; }

l40000000000BB820:
	{ nop.m	0x0; ld8	r36,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r36; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BB860; }

l40000000000BB840:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l40000000000BB860:
	{ nop.m	0x0; adds	r36,0x0,r32; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l40000000000BB880:
	{ nop.m	0x0; mov.i	ar.pfs,r34; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000BB890; br.ret	b0; }
40000000000BB8A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000BB8B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; array_flush: 40000000000BB8C0
;;   Called from:
;;     400000000006EBBC (in set_pipestatus_array)
;;     40000000000BBCCC (in array_shift)
;;     40000000000BBD6C (in array_dispose)
;;     40000000000C0A5C (in assign_compound_array_list)
;;     400000000010170C (in mapfile_builtin)
;;     40000000001054BC (in read_builtin)
array_flush proc
	{ alloc	r36,ar.pfs,0x7,0x0,0x6; adds	r34,0x18,r32; mov	r35,b3 }
	{ cmp.eq	p07,p06,0x0,r32; adds	r37,0x0,r1; (p07) br.cond.dpnt.few	40000000000BB9D0; }

l40000000000BB8E0:
	{ ld8	r14,[r34]; adds	r15,0x10,r14; nop.i	0x0; }
	{ nop.m	0x0; ld8	r38,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,r38,r14; (p06) br.cond.dpnt.few	40000000000BB970; }

l40000000000BB910:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000BB920:
	{ nop.m	0x0; adds	r14,0x10,r38; nop.i	0x0; }
	{ ld8	r33,[r14]; nop.i	0x0; br.call.sptk.many	b0,array_dispose_element; }
	{ ld8	r14,[r34]; adds	r1,0x0,r37; adds	r38,0x0,r33; }
	{ nop.m	0x0; cmp.eq	p07,p06,r33,r14; (p06) br.cond.dptk.few	40000000000BB920 }

l40000000000BB960:
	{ adds	r15,0x10,r33; nop.m	0x0; nop.i	0x0; }

l40000000000BB970:
	{ nop.m	0x0; addl	r16,7756,r1; adds	r20,0x18,r14 }
	{ st8	[r14],r15; adds	r19,0x8,r32; adds	r18,0x10,r32; }
	{ ld8	r17,[r16]; st8	[r14],r20; addl	r14,-1,r0 }
	{ st4	[r0],r18; nop.i	0x0; cmp.eq	p07,p06,r17,r32 }
	{ st8	[r14],r19; nop.i	0x0; (p07) addl	r14,7764,r1 }

l40000000000BB9C0:
	{ (p07) st8	[r0],r16; (p07) st8	[r0],r14; nop.i	0x0 }

l40000000000BB9C6:
	{ mf.a; mov	pr,0x4000; break.i	0x80000; }

l40000000000BB9CC:
	{ nop.m	0x80; break.i	0x1000; break.i	0x2A809 }

l40000000000BB9D0:
	{ nop.m	0x0; mov.i	ar.pfs,r36; nop.i	0x0; }

l40000000000BB9D2:
	{ add	r32,r0,r0; (p04) break.i	0x550; Invalid }
	{ ldfe	f32,[r0]; (p20) nop; Invalid }
40000000000BB9F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; array_shift: 40000000000BBA00
;;   Called from:
;;     400000000006ACDC (in pop_args)
;;     400000000006ADDC (in pop_args)
;;     400000000006AE4C (in pop_args)
;;     40000000000BBD1C (in array_unshift_element)
;;     40000000000F4F4C (in fn40000000000F4180)
;;     40000000000F4F9C (in fn40000000000F4180)
;;     40000000000F507C (in fn40000000000F4180)
;;     40000000000F50FC (in fn40000000000F4180)
;;     40000000000F514C (in fn40000000000F4180)
array_shift proc
	{ alloc	r37,ar.pfs,0x9,0x0,0x8; adds	r18,0x10,r32; mov	r39,LC }
	{ addl	r14,7756,r1; cmp.eq	p07,p06,0x0,r32; cmp4.lt	p09,p08,0x0,r33; }
	{ nop.m	0x0; mov	r36,b4; adds	r38,0x0,r1 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000BBBE0; }

l40000000000BBA40:
	{ nop.m	0x0; ld4	r19,[r18]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r19; (p06) br.cond.dpnt.few	40000000000BBBE0; (p08) br.cond.dpnt.few	40000000000BBBE0; }

l40000000000BBA5C:
	{ (p12) cmp.eq	p00,p11,r64,r33; (p01) cmp.eq.unc	p00,p08,r3,r6; Invalid }

l40000000000BBA60:
	{ ld8	r15,[r14]; cmp.eq	p07,p06,r15,r32; adds	r15,0x18,r32; }
	{ (p07) st8	[r0],r14; ld8	r15,[r15]; (p07) addl	r14,7764,r1; }

l40000000000BBA76:
	{ (p07) chk.a.nc	f0,3FFFFFFFFF8C7B66; (p07) cmp4.ne.or	p20,p08,r1,r60; (p01) br.call.spnt.few	b0,b0 }

l40000000000BBA80:
	{ (p07) st8	[r0],r14; adds	r21,0x10,r15; adds	r14,0xFFFFFFFFFFFFFFFF,r33; }

l40000000000BBA86:
	{ Invalid; Invalid; br.call.sptk.few	b2,b0 }
	{ Invalid; nop; (p32) nop }
	{ (p03) chk.a.clr	f40,3FFFFFFFFFCBEB96; nop; break.b	0x80000 }

l40000000000BBAB0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000BBAC0:
	{ adds	r14,0x10,r14; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,r14,r15; (p06) br.cond.dpnt.few	40000000000BBC10; br.cloop.sptk.few	40000000000BBAC0 }

l40000000000BBADC:
	{ (p63) nop; zxt1	r70,r64; nop.b	0x1000 }

l40000000000BBAE0:
	{ adds	r16,0x18,r14; nop.m	0x0; sxt4	r17,r33; }
	{ ld8	r20,[r16]; st8	[r15],r16; nop.i	0x0; }
	{ nop.m	0x0; adds	r16,0x10,r20; nop.i	0x0; }
	{ st8	[r0],r16; st8	[r14],r21; nop.i	0x0; }

l40000000000BBB20:
	{ ld8	r16,[r14]; sub	r16,r16,r17; nop.i	0x0; }
	{ st8	[r14],r16,16; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r14,r15; (p06) br.cond.dptk.few	40000000000BBB20; }

l40000000000BBB50:
	{ nop.m	0x0; adds	r15,0x18,r15; tbit.z	p08,p09,r34,0x0 }
	{ sub	r33,r19,r33; adds	r32,0x8,r32; cmp.eq	p06,p07,0x0,r40; }
	{ nop.m	0x0; ld8	r14,[r15]; (p08) adds	r8,0x0,r40 }

l40000000000BBB80:
	{ st4	[r33],r18; ld8	r14,[r14]; nop.i	0x0; }
	{ st8	[r14],r32; (p08) br.cond.dpnt.few	40000000000BBBF0; (p06) br.cond.dpnt.few	40000000000BBBE0; }

l40000000000BBB9C:
	{ (p02) nop; cmp.lt	p00,p00,r32,r0; (p01) epc }

l40000000000BBBA0:
	{ nop.m	0x0; adds	r14,0x10,r40; nop.i	0x0; }
	{ ld8	r35,[r14]; nop.i	0x0; br.call.sptk.many	b0,array_dispose_element; }
	{ nop.m	0x0; adds	r1,0x0,r38; adds	r40,0x0,r35 }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	40000000000BBBA0 }

l40000000000BBBE0:
	{ adds	r8,0x0,r0; nop.m	0x0; nop.i	0x0 }

l40000000000BBBF0:
	{ nop.m	0x0; mov.i	ar.pfs,r37; mov.i	LC,r39; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000BBC00; br.ret	b0 }

l40000000000BBC10:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x0; nop.i	0x0 }
	{ nop.m	0x0; (p07) br.cond.dpnt.few	40000000000BBCC0; nop.b	0x0; }

l40000000000BBC2C:
	{ nop; zxt1	r0,r64; break.i	0x1000 }

l40000000000BBC36:
	{ break.m	0x4000; nop; nop }

l40000000000BBC40:
	{ adds	r16,0x10,r17; ld8	r14,[r16]; nop.i	0x0; }

l40000000000BBC42:
	{ Invalid; break.i	0x20304; sub	r32,r0,r0,0x1 }
	{ (p32) cmp.eq.and	p03,p48,r64,r16; (p49) cmp.eq.unc	p03,p01,r1,r92; Invalid }

l40000000000BBC60:
	{ adds	r14,0x18,r15; adds	r32,0x8,r32; nop.b	0x0 }
	{ st8	[r0],r16; adds	r8,0x0,r40; mov.i	ar.pfs,r37; }
	{ st8	[r15],r14; addl	r14,-1,r0; nop.b	0x0 }
	{ st8	[r15],r21; nop.m	0x0; mov.i	LC,r39; }
	{ nop.m	0x0; st8	[r14],r32; nop.b	0x0 }
	{ st4	[r0],r18; mov.spnt	b0,r36,40000000000BBCB0; br.ret	b0; }

l40000000000BBCC0:
	{ adds	r40,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,array_flush; }
	{ adds	r1,0x0,r38; adds	r8,0x0,r0; br.cond.sptk.few	40000000000BBBF0; }
40000000000BBCE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000BBCF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; array_unshift_element: 40000000000BBD00
array_unshift_element proc
	{ alloc	r16,ar.pfs,0x3,0x0,0x3; addl	r33,1,r0; adds	r34,0x0,r0; }
	{ alloc	r2,ar.pfs,0x3,0x0,0x0; nop.i	0x0; br.cond.sptk.many	array_shift; }
40000000000BBD20 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000BBD30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; array_dispose: 40000000000BBD40
;;   Called from:
;;     40000000000610CC (in fn4000000000060F80)
;;     400000000006BD0C (in makunbound)
;;     400000000006EF16 (in restore_pipestatus_array)
;;     40000000000BDA1C (in array_modcase)
;;     40000000000BDABC (in array_modcase)
;;     40000000000BDE6C (in array_patsub)
;;     40000000000BDF0C (in array_patsub)
;;     40000000000BE2AC (in array_subrange)
;;     40000000000BE3AC (in array_subrange)
array_dispose proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; cmp.eq	p06,p07,0x0,r32; mov	r33,b1 }
	{ adds	r35,0x0,r1; adds	r36,0x0,r32; (p06) br.cond.dpnt.few	40000000000BBDC0; }

l40000000000BBD60:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,array_flush; }
	{ adds	r14,0x18,r32; nop.m	0x0; adds	r1,0x0,r35; }
	{ ld8	r36,[r14]; nop.i	0x0; br.call.sptk.many	b0,array_dispose_element; }
	{ nop.m	0x0; adds	r1,0x0,r35; adds	r36,0x0,r32 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l40000000000BBDC0:
	{ nop.m	0x0; mov.i	ar.pfs,r34; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000BBDD0; br.ret	b0; }
40000000000BBDE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000BBDF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; array_insert: 40000000000BBE00
;;   Called from:
;;     400000000006723C (in fn4000000000066D40)
;;     400000000006C62C (in initialize_shell_variables)
;;     400000000006C64C (in initialize_shell_variables)
;;     400000000006C6AC (in initialize_shell_variables)
;;     400000000006C70C (in initialize_shell_variables)
;;     400000000006C73C (in initialize_shell_variables)
;;     400000000006C76C (in initialize_shell_variables)
;;     400000000006EA7C (in set_pipestatus_array)
;;     400000000006EB3C (in set_pipestatus_array)
;;     400000000006EC1C (in set_pipestatus_array)
;;     400000000006EC7C (in set_pipestatus_array)
;;     40000000000BC92C (in array_assign_list)
;;     40000000000BE7EC (in fn40000000000BE480)
;;     40000000000BE91C (in convert_var_to_array)
;;     40000000000BF2AC (in assign_array_var_from_word_list)
;;     40000000000C0A8C (in assign_compound_array_list)
;;     400000000012B13C (in sh_regmatch)
array_insert proc
	{ alloc	r38,ar.pfs,0xA,0x0,0x8; cmp.eq	p07,p06,0x0,r32; mov	r37,b5 }
	{ adds	r39,0x0,r1; adds	r40,0x0,r33; (p07) br.cond.dpnt.few	40000000000BC060; }

l40000000000BBE20:
	{ adds	r41,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,array_create_element; }
	{ adds	r14,0x8,r32; adds	r16,0x18,r32; adds	r1,0x0,r39 }
	{ adds	r40,0x0,r8; ld8	r15,[r14]; nop.i	0x0; }
	{ cmp.lt	p07,p06,r15,r33; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000BBFA0; }

l40000000000BBE60:
	{ ld8	r15,[r16]; adds	r14,0x10,r15; nop.i	0x0; }
	{ nop.m	0x0; ld8	r35,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,r35,r15; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BC040; }

l40000000000BBE90:
	{ nop.m	0x0; ld8	r14,[r35]; nop.i	0x0; }
	{ cmp.eq	p06,p07,r33,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BC080; }

l40000000000BBEB0:
	{ nop.m	0x0; cmp.lt	p06,p07,r33,r14; (p06) br.cond.dpnt.few	40000000000BBF10; }

l40000000000BBEC0:
	{ adds	r35,0x10,r35; ld8	r35,[r35]; nop.i	0x0; }
	{ cmp.eq	p07,p06,r35,r15; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000BC040; }

l40000000000BBEE0:
	{ nop.m	0x0; ld8	r14,[r35]; nop.i	0x0; }
	{ cmp.eq	p07,p06,r33,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000BC080; }

l40000000000BBF00:
	{ nop.m	0x0; cmp.lt	p07,p06,r33,r14; (p06) br.cond.dptk.few	40000000000BBEC0 }

l40000000000BBF10:
	{ adds	r15,0x18,r35; adds	r14,0x10,r32; addl	r19,7756,r1 }
	{ adds	r20,0x18,r40; adds	r18,0x10,r40; adds	r8,0x0,r0; }
	{ ld4	r17,[r14]; st8	[r32],r19; mov.i	ar.pfs,r38 }
	{ nop.m	0x0; ld8	r16,[r15]; nop.i	0x0; }
	{ st8	[r16],r20; adds	r19,0x10,r16; mov.spnt	b0,r37,40000000000BBF50 }
	{ adds	r17,0x1,r17; st8	[r40],r15; addl	r16,7764,r1; }
	{ st8	[r40],r19; st8	[r40],r16; nop.i	0x0; }
	{ nop.m	0x0; st8	[r35],r18; nop.i	0x0 }
	{ st4	[r17],r14; nop.m	0x0; br.ret	b0 }

l40000000000BBFA0:
	{ adds	r15,0x10,r32; ld8	r16,[r16]; mov.i	ar.pfs,r38 }
	{ addl	r17,7756,r1; adds	r22,0x18,r8; adds	r20,0x10,r8; }
	{ ld4	r18,[r15]; st8	[r32],r17; nop.b	0x0 }
	{ adds	r17,0x18,r16; adds	r8,0x0,r0; mov.spnt	b0,r37,40000000000BBFD0; }
	{ adds	r19,0x1,r18; nop.m	0x0; addl	r18,7764,r1; }
	{ st8	[r40],r18; ld8	r18,[r17]; nop.i	0x0; }
	{ adds	r21,0x10,r18; st8	[r18],r22; nop.i	0x0 }
	{ st8	[r40],r17; st8	[r40],r21; nop.i	0x0 }
	{ st8	[r16],r20; nop.i	0x0; nop.i	0x0 }
	{ st8	[r33],r14; st4	[r19],r15; br.ret	b0 }

l40000000000BC040:
	{ addl	r14,7756,r1; ld8	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r15,r32; (p07) br.cond.dpnt.few	40000000000BC160 }

l40000000000BC060:
	{ addl	r8,-1,r0; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000BC070; br.ret	b0; }

l40000000000BC080:
	{ adds	r36,0x8,r35; nop.i	0x0; br.call.sptk.many	b0,array_dispose_element; }
	{ nop.m	0x0; adds	r1,0x0,r39; nop.i	0x0 }
	{ ld8	r40,[r36]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ cmp.eq	p06,p07,0x0,r34; adds	r1,0x0,r39; adds	r40,0x0,r34; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BC120; }

l40000000000BC0C6:
	{ chk.a.nc	r0,3FFFFFFFFF0BC8C6; nop; break.i	0x80000 }

l40000000000BC0D0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r39; adds	r40,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r40,0x0,r8 }
	{ adds	r41,0x0,r34; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r39; nop.m	0x0; nop.i	0x0; }

l40000000000BC120:
	{ addl	r14,7756,r1; st8	[r8],r36; mov.i	ar.pfs,r38 }
	{ nop.m	0x0; adds	r8,0x0,r0; nop.i	0x0; }
	{ st8	[r32],r14; addl	r14,7764,r1; mov.spnt	b0,r37,40000000000BC140; }
	{ st8	[r35],r14; nop.i	0x0; br.ret	b0 }

l40000000000BC160:
	{ st8	[r0],r14; addl	r14,7764,r1; nop.b	0x0 }
	{ addl	r8,-1,r0; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ st8	[r0],r14; mov.spnt	b0,r37,40000000000BC180; br.ret	b0; }
40000000000BC190 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000BC1A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000BC1B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; array_remove: 40000000000BC1C0
;;   Called from:
;;     40000000000C026C (in unbind_array_element)
array_remove proc
	{ adds	r16,0x10,r32; nop.m	0x0; adds	r14,0x18,r32 }
	{ cmp.eq	p06,p07,0x0,r32; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000BC340; }

l40000000000BC1E0:
	{ nop.m	0x0; ld4	r17,[r16]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r17; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BC340; }

l40000000000BC200:
	{ ld8	r15,[r14]; adds	r14,0x10,r15; nop.i	0x0; }
	{ nop.m	0x0; ld8	r8,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,r8,r15; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BC340; }

l40000000000BC230:
	{ nop.m	0x0; ld8	r14,[r8]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,r33,r14; (p06) br.cond.dpnt.few	40000000000BC2A0; }

l40000000000BC250:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000BC260:
	{ adds	r8,0x10,r8; ld8	r8,[r8]; nop.i	0x0; }
	{ cmp.eq	p07,p06,r8,r15; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000BC340; }

l40000000000BC280:
	{ nop.m	0x0; ld8	r14,[r8]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r33,r14; (p06) br.cond.dptk.few	40000000000BC260 }

l40000000000BC2A0:
	{ adds	r14,0x10,r8; adds	r15,0x18,r8; nop.i	0x0 }
	{ adds	r18,0x8,r32; addl	r19,7756,r1; adds	r17,0xFFFFFFFFFFFFFFFF,r17; }
	{ ld8	r14,[r14]; ld8	r22,[r15]; nop.i	0x0; }
	{ adds	r23,0x18,r14; ld8	r21,[r18]; nop.i	0x0 }
	{ ld8	r20,[r19]; st8	[r22],r23; cmp.eq	p07,p06,r20,r32 }
	{ cmp.eq	p09,p08,r33,r21; ld8	r15,[r15]; nop.i	0x0 }
	{ (p07) st8	[r0],r19; adds	r20,0x10,r15; nop.i	0x0; }

l40000000000BC306:
	{ Invalid; nop; tbit.nz.or	p00,p38,r5,0x1 }
	{ (p07) fwb; nop; tbit.z.or	p32,p36,r4,0x2 }

l40000000000BC31C:
	{ Invalid; Invalid; (p32) cmp4.ne.and	p03,p40,r4,r102 }

l40000000000BC32C:
	{ Invalid; Invalid; add	r0,r32,r0; }

l40000000000BC330:
	{ (p07) st8	[r0],r14; nop.i	0x0; br.ret	b0; }

l40000000000BC336:
	{ break.m	0x4000; (p34) nop; break.i	0x80000 }

l40000000000BC340:
	{ nop.m	0x0; adds	r8,0x0,r0; br.ret	b0; }
40000000000BC350 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000BC360 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000BC370 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; array_reference: 40000000000BC380
;;   Called from:
;;     4000000000044C6C (in make_function_def)
;;     400000000006303C (in get_variable_value)
;;     400000000007076C (in get_name_for_error)
;;     400000000009D9EC (in fn400000000009A180)
;;     40000000000BE7BC (in fn40000000000BE480)
;;     40000000000C1B0C (in fn40000000000C14C0)
;;     40000000000EB01C (in caller_builtin)
;;     40000000000EB04C (in caller_builtin)
;;     40000000000EB07C (in caller_builtin)
;;     40000000000EB14C (in caller_builtin)
;;     40000000000EB16C (in caller_builtin)
array_reference proc
	{ adds	r14,0x10,r32; cmp.eq	p06,p07,0x0,r32; nop.i	0x0 }
	{ addl	r17,7764,r1; addl	r18,7756,r1; (p06) br.cond.dpnt.few	40000000000BC510; }

l40000000000BC3A0:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; adds	r14,0x8,r32; (p06) br.cond.dpnt.few	40000000000BC510; }

l40000000000BC3C0:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.lt	p06,p07,r14,r33; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BC510; }

l40000000000BC3E0:
	{ nop.m	0x0; ld8	r14,[r17]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BC420; }

l40000000000BC400:
	{ nop.m	0x0; ld8	r15,[r18]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r15,r32; (p07) br.cond.dpnt.few	40000000000BC520 }

l40000000000BC420:
	{ adds	r14,0x18,r32; ld8	r16,[r14]; nop.i	0x0; }
	{ nop.m	0x0; adds	r14,0x10,r16; nop.i	0x0; }
	{ ld8	r14,[r14]; nop.m	0x0; nop.i	0x0; }

l40000000000BC450:
	{ cmp.eq	p06,p07,r14,r16; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000BC4F0; }

l40000000000BC460:
	{ nop.m	0x0; ld8	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,r33,r15; (p06) br.cond.dpnt.few	40000000000BC4C0; }
