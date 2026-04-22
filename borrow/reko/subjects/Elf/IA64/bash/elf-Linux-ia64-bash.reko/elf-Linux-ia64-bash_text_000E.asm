;;; Segment .text (400000000001C480)

l40000000000FC4E0:
	{ addl	r40,6164,r1; cmp4.eq	p17,p16,0x0,r36; addl	r43,7676,r1 }
	{ addl	r46,7684,r1; addl	r48,7664,r1; addl	r36,-10260,r1; }
	{ nop.m	0x0; addl	r52,6060,r1; addl	r51,6052,r1 }
	{ cmp4.eq	p20,p21,0x0,r34; adds	r41,0x0,r0; cmp4.eq	p18,p19,0x0,r35; }
	{ nop.m	0x0; nop.m	0x0; adds	r50,0x0,r40 }
	{ adds	r34,0x90,r12; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld8	r36,[r36]; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }

l40000000000FC560:
	{ ld8	r14,[r33]; addl	r37,48,r0; adds	r39,0x0,r0; }
	{ nop.m	0x0; ld8	r42,[r14]; nop.i	0x0; }
	{ adds	r58,0x0,r42; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ ld8	r14,[r40]; sxt4	r45,r8; adds	r1,0x0,r55; }
	{ nop.m	0x0; ld8	r33,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r33; (p06) br.cond.dpnt.few	40000000000FCBE0; }

l40000000000FC5C0:
	{ nop.m	0x0; ld4.acq	r14,[r43]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000FCC20; }

l40000000000FC5E0:
	{ nop.m	0x0; ld4.acq	r14,[r46]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000FCC50 }

l40000000000FC600:
	{ adds	r58,0x0,r42; nop.m	0x0; adds	r59,0x0,r33 }
	{ adds	r60,0x0,r45; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C020; }
	{ adds	r1,0x0,r55; cmp4.eq	p07,p06,0x0,r8; (p07) br.cond.dptk.few	40000000000FC670 }

l40000000000FC630:
	{ ld4	r60,[r48]; adds	r58,0x0,r42; adds	r59,0x0,r33; }
	{ cmp4.eq	p06,p07,0x0,r60; (p07) addl	r60,32,r0; nop.i	0x0; }

l40000000000FC64C:
	{ pshladd2	r0,r1,1,r0; zxt1	r0,r64; break.i	0x1000 }

l40000000000FC656:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ (p03) chk.a.clr	f1,3FFFFFFFFFDBF6E6; nop; (p16) nop.b	0x2902A }

l40000000000FC670:
	{ adds	r41,0x1,r41; nop.i	0x0; (p16) br.cond.dpnt.few	40000000000FD2D0; }

l40000000000FC680:
	{ ld8	r14,[r40]; nop.i	0x0; (p18) br.cond.dptk.few	40000000000FD020; }

l40000000000FC690:
	{ add	r14,r14,r39; adds	r14,0x18,r14; nop.i	0x0; }
	{ nop.m	0x0; ld8	r44,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r44; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000FD570; }

l40000000000FC6C0:
	{ nop.m	0x0; ld8	r59,[r44]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r59; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000FC700; }

l40000000000FC6E0:
	{ ld1	r14,[r59]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2F,r14; (p07) br.cond.dpnt.few	40000000000FCCF0 }

l40000000000FC700:
	{ adds	r58,0x0,r0; nop.m	0x0; addl	r60,5,r0 }
	{ adds	r47,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r55; st8	[r8],r34; nop.i	0x0; }

l40000000000FC730:
	{ nop.m	0x0; addl	r58,-900,r1; nop.i	0x0; }
	{ ld8	r58,[r58]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B380; }
	{ adds	r1,0x0,r55; addl	r58,1,r0; addl	r60,4,r0 }
	{ adds	r62,0x0,r33; addl	r59,-892,r1; addl	r61,-884,r1; }
	{ nop.m	0x0; ld8	r59,[r59]; nop.i	0x0 }
	{ ld8	r61,[r61]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ ld8	r14,[r34]; nop.m	0x0; adds	r1,0x0,r55; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000FCDF0 }

l40000000000FC7B0:
	{ ld1	r58,[r14]; addl	r38,-10260,r1; sxt1	r58,r58; }
	{ cmp4.eq	p06,p07,0x0,r58; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000FCDF0; }

l40000000000FC7D0:
	{ addl	r33,1,r0; nop.m	0x0; adds	r35,0x0,r0 }
	{ ld8	r38,[r38]; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000FC800:
	{ ld8	r59,[r36]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AEC0; }
	{ ld8	r14,[r34]; adds	r16,0x1,r33; adds	r1,0x0,r55; }
	{ add	r15,r14,r35; add	r17,r14,r33; nop.i	0x0 }
	{ adds	r35,0x0,r33; cmp.eq	p08,p09,0x0,r14; adds	r33,0x0,r16; }
	{ ld1	r15,[r15]; nop.m	0x0; sxt1	r15,r15; }
	{ cmp4.eq	p06,p07,0xA,r15; (p06) br.cond.dpnt.few	40000000000FC880; (p08) br.cond.dpnt.few	40000000000FC880; }

l40000000000FC85C:
	{ (p01) cmp.lt	p00,p11,r64,r33; Invalid; br.cond.sptk.few	40000000000FCA5C }

l40000000000FC860:
	{ ld1	r14,[r17]; nop.m	0x0; sxt1	r58,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r58; (p06) br.cond.dptk.few	40000000000FC800 }

l40000000000FC880:
	{ addl	r58,10,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B900; }
	{ adds	r1,0x0,r55; addl	r58,-876,r1; nop.i	0x0; }
	{ ld8	r58,[r58]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B380; }
	{ ld8	r14,[r40]; nop.m	0x0; adds	r1,0x0,r55 }
	{ adds	r58,0x0,r0; addl	r60,5,r0; add	r14,r14,r39; }
	{ nop.m	0x0; adds	r14,0x20,r14; nop.i	0x0; }
	{ ld8	r59,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r55; addl	r60,4,r0; adds	r62,0x0,r8 }
	{ addl	r58,1,r0; addl	r59,-868,r1; addl	r61,-884,r1; }
	{ nop.m	0x0; ld8	r59,[r59]; nop.i	0x0 }
	{ ld8	r61,[r61]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r55; addl	r58,-860,r1; nop.i	0x0; }
	{ ld8	r58,[r58]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B380; }
	{ adds	r1,0x0,r55; cmp4.eq	p06,p07,0x0,r47; (p07) br.cond.dptk.few	40000000000FCEE0 }

l40000000000FC960:
	{ ld8	r59,[r44]; nop.m	0x0; adds	r33,0x8,r44; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r59; (p06) br.cond.dpnt.few	40000000000FC9F0; }

l40000000000FC980:
	{ adds	r58,0x0,r0; addl	r60,5,r0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r55; addl	r58,1,r0; addl	r60,4,r0 }
	{ adds	r62,0x0,r8; addl	r59,-820,r1; addl	r61,-884,r1; }
	{ nop.m	0x0; ld8	r59,[r59]; nop.i	0x0 }
	{ ld8	r61,[r61]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ ld8	r59,[r33],8; nop.m	0x0; adds	r1,0x0,r55; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r59; (p06) br.cond.dptk.few	40000000000FC980 }

l40000000000FC9F0:
	{ ld8	r59,[r38]; addl	r58,10,r0; br.call.sptk.many	b0,fn400000000001AEC0; }
	{ adds	r1,0x0,r55; addl	r58,-852,r1; nop.i	0x0; }
	{ ld8	r58,[r58]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B380; }
	{ adds	r1,0x0,r55; addl	r60,4,r0; addl	r58,1,r0; }
	{ addl	r59,-844,r1; addl	r61,-884,r1; nop.i	0x0 }
	{ ld8	r59,[r59]; ld8	r61,[r61]; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r55; addl	r58,-836,r1; nop.i	0x0; }
	{ ld8	r58,[r58]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B380; }
	{ adds	r1,0x0,r55; addl	r60,4,r0; addl	r58,1,r0; }
	{ addl	r59,-828,r1; addl	r61,-884,r1; nop.i	0x0 }
	{ ld8	r59,[r59]; ld8	r61,[r61]; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r55; adds	r58,0x0,r0; br.call.sptk.many	b0,show_shell_version; }
	{ adds	r1,0x0,r55; addl	r58,1,r0; addl	r60,4,r0; }
	{ addl	r61,-884,r1; addl	r59,-828,r1; nop.i	0x0 }
	{ ld8	r61,[r61]; ld8	r59,[r59]; br.call.sptk.many	b0,fn400000000001BB80; }
	{ nop.m	0x0; ld8	r59,[r52]; addl	r60,5,r0 }
	{ adds	r1,0x0,r55; adds	r58,0x0,r0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r55; adds	r58,0x0,r8; br.call.sptk.many	b0,fn400000000001B380; }
	{ adds	r1,0x0,r55; addl	r58,1,r0; addl	r60,4,r0; }
	{ addl	r61,-884,r1; addl	r59,-828,r1; nop.i	0x0 }
	{ ld8	r61,[r61]; ld8	r59,[r59]; br.call.sptk.many	b0,fn400000000001BB80; }
	{ nop.m	0x0; ld8	r59,[r51]; addl	r60,5,r0 }
	{ adds	r1,0x0,r55; adds	r58,0x0,r0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r55; adds	r58,0x0,r8; br.call.sptk.many	b0,fn400000000001B380; }
	{ nop.m	0x0; adds	r1,0x0,r55; nop.i	0x0 }
	{ ld8	r58,[r38]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ adds	r1,0x0,r55; cmp4.eq	p07,p06,0x0,r47; (p06) br.cond.dpnt.few	40000000000FCCC0 }

l40000000000FCBA0:
	{ ld8	r14,[r40]; nop.m	0x0; nop.i	0x0; }

l40000000000FCBB0:
	{ add	r14,r14,r37; adds	r15,0x30,r37; adds	r39,0x0,r37; }
	{ ld8	r33,[r14]; nop.m	0x0; adds	r37,0x0,r15; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	40000000000FC5C0 }

l40000000000FCBE0:
	{ ld8	r49,[r49]; cmp.eq	p07,p06,0x0,r49; adds	r33,0x8,r49 }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	40000000000FD650; br.cond.sptk.few	40000000000FC560 }

l40000000000FCBFC:
	{ (p11) invala; dep	r0,r32,r0,63,1; (p20) nop }

l40000000000FCC00:
	{ nop.m	0x0; addl	r34,1,r0; br.cond.sptk.few	40000000000FC2E0 }

l40000000000FCC10:
	{ nop.m	0x0; addl	r35,1,r0; br.cond.sptk.few	40000000000FC2E0 }

l40000000000FCC20:
	{ ld4.acq	r58,[r43]; nop.i	0x0; br.call.sptk.many	b0,termsig_handler; }
	{ ld4.acq	r14,[r46]; nop.m	0x0; adds	r1,0x0,r55; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000FC600 }

l40000000000FCC50:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,throw_to_top_level; }
	{ nop.m	0x0; adds	r1,0x0,r55; br.cond.sptk.few	40000000000FC600; }

l40000000000FCC70:
	{ nop.m	0x0; addl	r38,-10260,r1; nop.i	0x0; }
	{ ld8	r38,[r38]; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000FCCA0:
	{ ld8	r58,[r38]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ adds	r1,0x0,r55; cmp4.eq	p07,p06,0x0,r39; (p07) br.cond.dptk.few	40000000000FCBA0 }

l40000000000FCCC0:
	{ ld8	r58,[r34]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r55; nop.i	0x0 }
	{ ld8	r14,[r40]; nop.m	0x0; br.cond.sptk.few	40000000000FCBB0; }

l40000000000FCCF0:
	{ adds	r14,0x8,r44; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	40000000000FC700 }

l40000000000FCD10:
	{ adds	r58,0x0,r59; addl	r47,1,r0; br.call.sptk.many	b0,fn40000000000FC180; }
	{ cmp4.lt	p06,p07,r8,r0; adds	r35,0x0,r8; nop.i	0x0 }
	{ adds	r59,0x0,r34; adds	r1,0x0,r55; (p06) br.cond.dpnt.few	40000000000FD280; }

l40000000000FCD40:
	{ nop.m	0x0; adds	r58,0x0,r35; nop.i	0x0 }
	{ ld8	r60,[r44]; nop.m	0x0; br.call.sptk.many	b0,zmapfd; }
	{ adds	r1,0x0,r55; adds	r58,0x0,r35; br.call.sptk.many	b0,fn400000000001C340; }
	{ adds	r1,0x0,r55; addl	r58,-900,r1; nop.i	0x0; }
	{ ld8	r58,[r58]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B380; }
	{ adds	r1,0x0,r55; addl	r58,1,r0; addl	r60,4,r0 }
	{ adds	r62,0x0,r33; addl	r59,-892,r1; addl	r61,-884,r1; }
	{ nop.m	0x0; ld8	r59,[r59]; nop.i	0x0 }
	{ ld8	r61,[r61]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ ld8	r14,[r34]; nop.m	0x0; adds	r1,0x0,r55; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000FC7B0 }

l40000000000FCDF0:
	{ addl	r38,-10260,r1; nop.m	0x0; addl	r58,10,r0; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B900; }
	{ adds	r1,0x0,r55; addl	r58,-876,r1; nop.i	0x0; }
	{ ld8	r58,[r58]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B380; }
	{ ld8	r14,[r40]; nop.m	0x0; adds	r1,0x0,r55 }
	{ adds	r58,0x0,r0; addl	r60,5,r0; add	r14,r14,r39; }
	{ nop.m	0x0; adds	r14,0x20,r14; nop.i	0x0; }
	{ ld8	r59,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r55; addl	r60,4,r0; adds	r62,0x0,r8 }
	{ addl	r58,1,r0; addl	r59,-868,r1; addl	r61,-884,r1; }
	{ nop.m	0x0; ld8	r59,[r59]; nop.i	0x0 }
	{ ld8	r61,[r61]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r55; addl	r58,-860,r1; nop.i	0x0; }
	{ ld8	r58,[r58]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B380; }
	{ adds	r1,0x0,r55; cmp4.eq	p06,p07,0x0,r47; (p06) br.cond.dptk.few	40000000000FC960; }

l40000000000FCEE0:
	{ nop.m	0x0; ld8	r14,[r34]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000FC9F0; }

l40000000000FCF00:
	{ ld1	r58,[r14]; nop.m	0x0; sxt1	r58,r58; }
	{ cmp4.eq	p07,p06,0x0,r58; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000FC9F0; }

l40000000000FCF20:
	{ (p06) adds	r35,0x0,r0; nop.m	0x0; (p06) addl	r33,1,r0 }

l40000000000FCF26:
	{ adds	r0,0xFFFFFFFFFFFFE000,r1; (p16) nop; (p48) nop }

l40000000000FCF30:
	{ ld8	r59,[r38]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AEC0; }
	{ ld8	r14,[r34]; nop.m	0x0; adds	r1,0x0,r55; }
	{ add	r15,r14,r35; nop.m	0x0; adds	r35,0x0,r33; }
	{ ld1	r15,[r15]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0xA,r15; (p07) br.cond.dpnt.few	40000000000FD520; }

l40000000000FCF80:
	{ add	r15,r14,r33; nop.m	0x0; cmp.eq	p06,p07,0x0,r14 }
	{ adds	r33,0x1,r33; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000FC9F0; }

l40000000000FCFA0:
	{ ld1	r14,[r15]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x0,r14; adds	r58,0x0,r14; (p07) br.cond.dpnt.few	40000000000FC9F0; }

l40000000000FCFC0:
	{ ld8	r59,[r38]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AEC0; }
	{ ld8	r14,[r34]; nop.m	0x0; adds	r1,0x0,r55; }
	{ add	r15,r14,r35; nop.m	0x0; adds	r35,0x0,r33; }
	{ ld1	r15,[r15]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0xA,r15; (p06) br.cond.dptk.few	40000000000FCF80 }

l40000000000FD010:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000FD520 }

l40000000000FD020:
	{ add	r14,r14,r39; adds	r58,0x0,r0; addl	r60,5,r0; }
	{ nop.m	0x0; adds	r14,0x20,r14; nop.i	0x0; }
	{ ld8	r59,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r55; nop.m	0x0; addl	r58,1,r0 }
	{ adds	r60,0x0,r33; adds	r61,0x0,r8; addl	r59,-812,r1; }
	{ ld8	r59,[r59]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ nop.m	0x0; adds	r1,0x0,r55; nop.i	0x0 }
	{ ld8	r14,[r50]; nop.m	0x0; (p21) br.cond.dptk.few	40000000000FCBB0; }

l40000000000FD0A0:
	{ add	r39,r14,r39; adds	r39,0x18,r39; nop.i	0x0; }
	{ ld8	r35,[r39]; cmp.eq	p06,p07,0x0,r35; adds	r33,0x8,r35; }
	{ ld8	r59,[r35]; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000FD5B0; }

l40000000000FD0D0:
	{ cmp.eq	p06,p07,0x0,r59; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000FCBB0; }

l40000000000FD0E0:
	{ ld1	r14,[r59]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2F,r14; (p06) br.cond.dpnt.few	40000000000FD1F0; }

l40000000000FD100:
	{ adds	r58,0x0,r0; addl	r60,5,r0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r55; addl	r58,1,r0; addl	r60,4,r0 }
	{ adds	r62,0x0,r8; addl	r59,-820,r1; addl	r61,-884,r1; }
	{ nop.m	0x0; ld8	r59,[r59]; nop.i	0x0 }
	{ ld8	r61,[r61]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ ld8	r59,[r33],8; nop.m	0x0; adds	r1,0x0,r55; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r59; (p07) br.cond.dpnt.few	40000000000FCBA0 }

l40000000000FD170:
	{ adds	r58,0x0,r0; addl	r60,5,r0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r55; addl	r58,1,r0; addl	r60,4,r0 }
	{ adds	r62,0x0,r8; addl	r59,-820,r1; addl	r61,-884,r1; }
	{ nop.m	0x0; ld8	r59,[r59]; nop.i	0x0 }
	{ ld8	r61,[r61]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ ld8	r59,[r33],8; nop.m	0x0; adds	r1,0x0,r55; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r59; (p06) br.cond.dptk.few	40000000000FD100 }

l40000000000FD1E0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000FCBA0 }

l40000000000FD1F0:
	{ nop.m	0x0; ld8	r14,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000FD100 }

l40000000000FD210:
	{ adds	r58,0x0,r59; nop.i	0x0; br.call.sptk.many	b0,fn40000000000FC180; }
	{ cmp4.lt	p07,p06,r8,r0; adds	r1,0x0,r55; adds	r33,0x0,r8 }
	{ addl	r59,1,r0; adds	r58,0x0,r8; (p07) br.cond.dpnt.few	40000000000FD280; }

l40000000000FD240:
	{ ld8	r60,[r35]; nop.i	0x0; br.call.sptk.many	b0,zcatfd; }
	{ nop.m	0x0; adds	r1,0x0,r55; adds	r58,0x0,r33 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C340; }
	{ adds	r1,0x0,r55; nop.m	0x0; nop.i	0x0 }

l40000000000FD280:
	{ ld8	r14,[r50]; adds	r15,0x30,r37; adds	r39,0x0,r37; }
	{ add	r14,r14,r37; nop.m	0x0; adds	r37,0x0,r15; }
	{ nop.m	0x0; ld8	r33,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	40000000000FC5C0 }

l40000000000FD2C0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000FCBE0 }

l40000000000FD2D0:
	{ ld8	r14,[r40]; add	r14,r14,r39; nop.i	0x0; }
	{ adds	r14,0x18,r14; ld8	r35,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r35; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000FD590; }

l40000000000FD300:
	{ nop.m	0x0; ld8	r58,[r35]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r58; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000FD340; }

l40000000000FD320:
	{ ld1	r14,[r58]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2F,r14; (p07) br.cond.dpnt.few	40000000000FD490 }

l40000000000FD340:
	{ nop.m	0x0; st8	[r58],r34; adds	r39,0x0,r0 }

l40000000000FD350:
	{ addl	r59,-908,r1; nop.m	0x0; addl	r58,1,r0 }
	{ adds	r60,0x0,r33; nop.m	0x0; addl	r33,1,r0; }
	{ ld8	r59,[r59]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ ld8	r14,[r34]; nop.m	0x0; adds	r1,0x0,r55; }
	{ cmp.eq	p07,p06,0x0,r14; addl	r38,-10260,r1; (p07) br.cond.dpnt.few	40000000000FCC70; }

l40000000000FD3A0:
	{ ld1	r58,[r14]; nop.m	0x0; sxt1	r58,r58; }
	{ cmp4.eq	p06,p07,0x0,r58; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000FCC70; }

l40000000000FD3C0:
	{ adds	r35,0x0,r0; ld8	r38,[r38]; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000FD3E0:
	{ ld8	r59,[r36]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AEC0; }
	{ ld8	r14,[r34]; adds	r1,0x0,r55; adds	r16,0x1,r33; }
	{ add	r15,r14,r35; add	r17,r14,r33; nop.i	0x0 }
	{ adds	r35,0x0,r33; cmp.eq	p08,p09,0x0,r14; adds	r33,0x0,r16; }
	{ ld1	r15,[r15]; nop.m	0x0; sxt1	r15,r15; }
	{ cmp4.eq	p06,p07,0xA,r15; (p06) br.cond.dpnt.few	40000000000FCCA0; (p08) br.cond.dpnt.few	40000000000FCCA0; }

l40000000000FD43C:
	{ (p03) cmp.lt.unc	p63,p11,r127,r37; Invalid; br.cond.sptk.few	40000000000FD63C }

l40000000000FD440:
	{ ld1	r14,[r17]; nop.m	0x0; sxt1	r58,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r58; (p06) br.cond.dptk.few	40000000000FD3E0 }

l40000000000FD460:
	{ ld8	r58,[r38]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ adds	r1,0x0,r55; cmp4.eq	p07,p06,0x0,r39; (p07) br.cond.dptk.few	40000000000FCBA0 }

l40000000000FD480:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000FCCC0 }

l40000000000FD490:
	{ adds	r14,0x8,r35; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	40000000000FD340 }

l40000000000FD4B0:
	{ addl	r39,1,r0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000FC180; }
	{ adds	r38,0x0,r8; cmp4.lt	p06,p07,r8,r0; nop.i	0x0 }
	{ adds	r59,0x0,r34; adds	r1,0x0,r55; (p06) br.cond.dpnt.few	40000000000FD280; }

l40000000000FD4E0:
	{ nop.m	0x0; adds	r58,0x0,r38; nop.i	0x0 }
	{ ld8	r60,[r35]; nop.m	0x0; br.call.sptk.many	b0,zmapfd; }
	{ adds	r1,0x0,r55; adds	r58,0x0,r38; br.call.sptk.many	b0,fn400000000001C340; }
	{ nop.m	0x0; adds	r1,0x0,r55; br.cond.sptk.few	40000000000FD350; }

l40000000000FD520:
	{ addl	r59,-828,r1; nop.m	0x0; addl	r61,-884,r1 }
	{ addl	r58,1,r0; addl	r60,4,r0; nop.i	0x0 }
	{ ld8	r59,[r59]; ld8	r61,[r61]; br.call.sptk.many	b0,fn400000000001BB80; }
	{ nop.m	0x0; adds	r1,0x0,r55; nop.i	0x0 }
	{ ld8	r14,[r34]; nop.m	0x0; br.cond.sptk.few	40000000000FCF80 }

l40000000000FD570:
	{ adds	r8,0x0,r0; nop.m	0x0; adds	r47,0x0,r0; }
	{ st8	[r8],r34; nop.i	0x0; br.cond.sptk.few	40000000000FC730 }

l40000000000FD590:
	{ adds	r58,0x0,r0; nop.m	0x0; adds	r39,0x0,r0; }
	{ st8	[r58],r34; nop.i	0x0; br.cond.sptk.few	40000000000FD350 }

l40000000000FD5B0:
	{ cmp.eq	p07,p06,0x0,r59; adds	r58,0x0,r0; nop.i	0x0 }
	{ addl	r60,5,r0; addl	r33,8,r0; (p07) br.cond.spnt.few	40000000000FCBB0; }

l40000000000FD5D0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r55; addl	r58,1,r0; addl	r60,4,r0 }
	{ adds	r62,0x0,r8; addl	r59,-820,r1; addl	r61,-884,r1; }
	{ nop.m	0x0; ld8	r59,[r59]; nop.i	0x0 }
	{ ld8	r61,[r61]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ ld8	r59,[r33],8; nop.m	0x0; adds	r1,0x0,r55; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r59; (p06) br.cond.dptk.few	40000000000FD170 }

l40000000000FD640:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000FCBA0; }

l40000000000FD650:
	{ addl	r14,-10260,r1; cmp4.eq	p07,p06,0x0,r41; (p07) br.cond.dpnt.few	40000000000FD6D0; }

l40000000000FD660:
	{ ld8	r14,[r14]; nop.i	0x0; nop.i	0x0 }
	{ ld8	r58,[r14]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ adds	r1,0x0,r55; nop.m	0x0; nop.i	0x0 }

l40000000000FD690:
	{ adds	r8,0x0,r0; nop.m	0x0; nop.i	0x0 }

l40000000000FD6A0:
	{ nop.m	0x0; mov	pr,r56,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r54; }
	{ nop.m	0x0; mov.i	LC,r57; mov.spnt	b0,r53,40000000000FD6B0 }
	{ nop.m	0x0; adds	r12,0x90,r12; br.ret	b0 }

l40000000000FD6D0:
	{ addl	r59,-804,r1; adds	r58,0x0,r0; addl	r60,5,r0; }
	{ ld8	r59,[r59]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r55; adds	r58,0x0,r8; adds	r59,0x0,r42 }
	{ adds	r60,0x0,r42; adds	r61,0x0,r42; br.call.sptk.many	b0,builtin_error; }
	{ addl	r8,1,r0; adds	r1,0x0,r55; mov	pr,r56,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r54; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r57; mov.spnt	b0,r53,40000000000FD730 }
	{ nop.m	0x0; adds	r12,0x90,r12; br.ret	b0; }

l40000000000FD750:
	{ adds	r58,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,show_shell_version; }
	{ adds	r1,0x0,r55; addl	r60,5,r0; adds	r58,0x0,r0; }
	{ nop.m	0x0; addl	r59,-964,r1; nop.i	0x0; }
	{ ld8	r59,[r59]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r55; nop.m	0x0; addl	r58,1,r0 }
	{ adds	r59,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r55; addl	r58,-956,r1; nop.i	0x0; }
	{ ld8	r58,[r58]; nop.i	0x0; br.call.sptk.many	b0,get_string_value; }
	{ adds	r1,0x0,r55; nop.m	0x0; cmp.eq	p06,p07,0x0,r8 }
	{ adds	r58,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000FD810; }

l40000000000FD7F0:
	{ ld1	r14,[r8]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000FDC30 }

l40000000000FD810:
	{ addl	r35,40,r0; nop.m	0x0; nop.i	0x0; }

l40000000000FD820:
	{ addl	r43,6156,r1; addl	r42,7676,r1; adds	r41,0xFFFFFFFFFFFFFFFE,r35 }
	{ adds	r45,0xFFFFFFFFFFFFFFFF,r35; adds	r44,0xFFFFFFFFFFFFFFFD,r35; addl	r46,7684,r1; }
	{ nop.m	0x0; addl	r40,6164,r1; sxt4	r41,r41 }
	{ addl	r33,-10260,r1; adds	r36,0x0,r0; sxt4	r44,r44; }
	{ nop.m	0x0; sxt4	r45,r45; adds	r34,0x0,r0 }
	{ addl	r38,62,r0; ld4	r14,[r43]; nop.i	0x0; }
	{ nop.m	0x0; adds	r14,0x1,r14; nop.i	0x0; }
	{ nop.m	0x0; extr.u	r15,r14,31,1; add	r14,r15,r14; }
	{ nop.m	0x0; extr	r37,r14,1,31; adds	r14,0x10,r12; }
	{ cmp4.lt	p06,p07,0x0,r37; sxt4	r48,r37; add	r39,r14,r41 }
	{ add	r45,r14,r45; add	r47,r14,r44; (p07) br.cond.dpnt.few	40000000000FD690; }

l40000000000FD8D0:
	{ nop.m	0x0; nop.m	0x0; shladd	r48,r48,0x1,r48 }
	{ nop.m	0x0; shladd	r48,r48,0x4,r0; adds	r49,0x0,r42 }
	{ nop.m	0x0; ld8	r33,[r33]; nop.i	0x0; }
	{ nop.m	0x0; ld4.acq	r14,[r42]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000FDBF0 }

l40000000000FD920:
	{ nop.m	0x0; ld4.acq	r14,[r46]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000FDBD0 }

l40000000000FD940:
	{ ld8	r14,[r40]; nop.m	0x0; adds	r16,0x10,r12 }
	{ adds	r58,0x0,r0; nop.m	0x0; addl	r60,5,r0; }
	{ add	r14,r14,r36; adds	r15,0x10,r14; adds	r14,0x20,r14; }
	{ ld4	r15,[r15]; ld8.a	r59,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r15,0x0; (p06) addl	r15,42,r0; }

l40000000000FD990:
	{ (p07) addl	r15,32,r0; st1	[r15],r16; nop.i	0x0; }

l40000000000FD996:
	{ mf.a; nop; (p48) nop }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; (p29) nop; (p48) nop.b	0x800E }
	{ Invalid; (p32) nop; break.i	0x80000 }
	{ Invalid; (p29) nop; br.call.spnt.many	b0,b1 }
	{ mf.a; (p30) nop; break.i	0x80000 }
	{ Invalid; nop; (p48) br.call.sptk.few	b6,b0 }
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; (p07) nop; nop }
	{ Invalid; (p29) nop; nop }
	{ chk.a.nc	r0,3FFFFFFFFF0FE236; nop; (p32) nop }

l40000000000FDA40:
	{ cmp4.lt	p06,p07,r16,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000FDCA0; }

l40000000000FDA50:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ sub	r14,r35,r8,0x1; nop.m	0x0; adds	r1,0x0,r55 }
	{ cmp4.lt	p06,p07,r8,r35; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000FDAD0; }

l40000000000FDA80:
	{ addp4	r14,r14,r0; nop.i	0x0; mov.i	LC,r14; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000FDAA0:
	{ nop.m	0x0; addl	r58,32,r0; nop.i	0x0 }
	{ ld8	r59,[r33]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AEC0; }
	{ nop.m	0x0; adds	r1,0x0,r55; br.cloop.sptk.few	40000000000FDAA0 }

l40000000000FDAD0:
	{ add	r15,r36,r48; ld8	r14,[r40]; adds	r16,0x10,r12 }
	{ adds	r58,0x0,r0; addl	r60,5,r0; adds	r34,0x1,r34; }
	{ add	r14,r14,r15; nop.m	0x0; adds	r36,0x30,r36; }
	{ adds	r15,0x10,r14; nop.m	0x0; adds	r14,0x20,r14; }
	{ ld4	r15,[r15]; ld8.a	r59,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r15,0x0; (p06) addl	r15,32,r0; }

l40000000000FDB30:
	{ (p07) addl	r15,42,r0; st1	[r15],r16; nop.i	0x0; }

l40000000000FDB36:
	{ mf.a; nop; (p48) nop }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; (p29) nop; nop }
	{ Invalid; (p32) nop; (p16) nop.b	0x37000 }
	{ mf.a; nop; (p32) nop }
	{ mf.a; (p32) nop; (p16) nop }
	{ (p03) chk.a.clr	f37,3FFFFFFFFFD40DB6; nop; break.b	0x80000 }

l40000000000FDBA0:
	{ nop.m	0x0; ld4.acq	r14,[r42]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000FD920 }

l40000000000FDBC0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000FDBF0 }

l40000000000FDBD0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,throw_to_top_level; }
	{ nop.m	0x0; adds	r1,0x0,r55; br.cond.sptk.few	40000000000FD940 }

l40000000000FDBF0:
	{ ld4.acq	r58,[r49]; nop.i	0x0; br.call.sptk.many	b0,termsig_handler; }
	{ ld4.acq	r14,[r46]; nop.m	0x0; adds	r1,0x0,r55; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000FD940 }

l40000000000FDC20:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000FDBD0 }

l40000000000FDC30:
	{ adds	r59,0x0,r0; addl	r60,10,r0; br.call.sptk.many	b0,fn400000000001C2A0; }
	{ adds	r1,0x0,r55; cmp4.lt	p07,p06,0x0,r8; (p06) br.cond.sptk.few	40000000000FD810 }

l40000000000FDC50:
	{ nop.m	0x0; extr	r35,r8,1,31; addl	r14,128,r0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,r14,r35; nop.i	0x0; }
	{ nop.m	0x0; (p06) addl	r35,128,r0; (p06) br.cond.sptk.few	40000000000FD820; }

l40000000000FDC7C:
	{ (p29) nop; cmp.eq	p00,p00,r32,r0; (p48) nop }

l40000000000FDC80:
	{ nop.m	0x0; cmp4.lt	p07,p06,0x3,r35; nop.i	0x0; }
	{ nop.m	0x0; (p06) addl	r35,40,r0; br.cond.sptk.few	40000000000FD820 }

l40000000000FDC9C:
	{ (p28) cmpxchg4.acq	r127,[r36],r63; zxt4	r2,r0; break.b	0x1000 }

l40000000000FDCA0:
	{ addl	r58,10,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B900; }
	{ adds	r1,0x0,r55; adds	r8,0x0,r0; br.cond.sptk.few	40000000000FD6A0; }

;; history_builtin: 40000000000FDCC0
history_builtin proc
	{ alloc	r46,ar.pfs,0x17,0x0,0x11; adds	r12,0xFFFFFFFFFFFFFFE0,r12; nop.b	0x0 }
	{ addl	r34,-9324,r1; adds	r47,0x0,r1; mov	r48,pr; }
	{ nop.m	0x0; mov	r45,b5; nop.i	0x0 }
	{ ld8	r34,[r34]; adds	r33,0x0,r0; br.call.sptk.many	b0,reset_internal_getopt; }
	{ adds	r1,0x0,r47; addl	r36,128,r0; addl	r35,9252,r1 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ addl	r50,-9380,r1; nop.m	0x0; adds	r49,0x0,r32; }
	{ ld8	r50,[r50]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r47; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dpnt.few	40000000000FDE20 }

l40000000000FDD50:
	{ nop.m	0x0; adds	r8,0xFFFFFFFFFFFFFF9F,r8; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x16,r8; (p07) br.cond.dptk.few	40000000000FDDB0 }

l40000000000FDD70:
	{ addl	r33,258,r0; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r47; mov	pr,r48,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r46; mov.spnt	b0,r45,40000000000FDD90 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0 }

l40000000000FDDB0:
	{ addp4	r8,r8,r0; shladd	r8,r8,0x3,r34; nop.i	0x0; }
	{ ld8	r14,[r8]; add	r8,r8,r14; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r8,40000000000FDDD0; br.cond	b6; }
40000000000FDDE0 09 90 71 FB B6 27 10 03 80 00 42 20 44 08 B9 80 ..q..'....B D...
40000000000FDDF0 11 90 01 64 18 10 00 00 00 02 00 00 D8 C6 01 50 ...d...........P
40000000000FDE00 11 08 00 5E 00 21 70 F8 23 0C 77 03 50 FF FF 4A ...^.!p.#.w.P..J
40000000000FDE10 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

l40000000000FDE20:
	{ addl	r15,9268,r1; nop.m	0x0; and	r14,0xF,r33; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x2,r14; cmp4.eq	p09,p08,0x4,r14; }
	{ nop.m	0x0; (p06) addl	r16,1,r0; nop.i	0x0; }

l40000000000FDE4C:
	{ cmpxchg2.acq	r0,[r0],r1; (p04) mov	pr,r3,0x40C0; (p02) cmp.eq	p00,p16,0x0,r64 }

l40000000000FDE5C:
	{ cmp.eq	p00,p43,0x0,r72; (p01) cmp.eq	p00,p16,r0,r64; (p49) epc; }

l40000000000FDE60:
	{ (p09) adds	r15,0x0,r0; and	r15,r15,r16; nop.i	0x0; }

l40000000000FDE66:
	{ Invalid; nop; break.b	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFDC1766; nop; break.i	0x80000 }

l40000000000FDE80:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x8,r14; (p06) br.cond.dptk.few	40000000000FDF80 }

l40000000000FDE90:
	{ addl	r50,-9372,r1; nop.m	0x0; addl	r51,5,r0 }
	{ adds	r49,0x0,r0; nop.m	0x0; addl	r33,1,r0; }
	{ ld8	r50,[r50]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r47; adds	r49,0x0,r8; br.call.sptk.many	b0,builtin_error; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r47; mov	pr,r48,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r46; mov.spnt	b0,r45,40000000000FDEE0 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0 }
40000000000FDF00 11 00 00 00 01 00 10 82 84 5C 40 00 20 FE FF 48 .........\@. ..H
40000000000FDF10 11 00 00 00 01 00 10 12 84 5C 40 00 10 FE FF 48 .........\@....H
40000000000FDF20 11 00 00 00 01 00 10 02 85 5C 40 00 00 FE FF 48 .........\@....H
40000000000FDF30 11 00 00 00 01 00 10 42 84 5C 40 00 F0 FD FF 48 .......B.\@....H
40000000000FDF40 08 00 00 00 01 00 10 0A 91 1C 40 00 00 00 04 00 ..........@.....
40000000000FDF50 19 28 01 46 18 10 00 00 00 02 00 00 D0 FD FF 48 .(.F...........H
40000000000FDF60 11 00 00 00 01 00 10 02 86 5C 40 00 C0 FD FF 48 .........\@....H
40000000000FDF70 11 00 00 00 01 00 10 0A 84 5C 40 00 B0 FD FF 48 .........\@....H

l40000000000FDF80:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x6; (p07) br.cond.dpnt.few	40000000000FE2E0; }

l40000000000FDF90:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x4; (p07) br.cond.dptk.few	40000000000FE170; }

l40000000000FDFA0:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x5; (p06) br.cond.dptk.few	40000000000FE320; }

l40000000000FDFB0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r34; (p06) br.cond.dpnt.few	40000000000FE610 }

l40000000000FDFC0:
	{ addl	r14,9184,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	40000000000FE020 }

l40000000000FDFF0:
	{ addl	r14,9160,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000FE660 }

l40000000000FE020:
	{ addl	r37,-10260,r1; adds	r33,0x0,r0; nop.i	0x0 }
	{ adds	r35,0x20,r12; ld8	r37,[r37]; nop.i	0x0; }

l40000000000FE040:
	{ adds	r36,0x8,r34; nop.m	0x0; adds	r50,0x0,r35; }
	{ nop.m	0x0; ld8	r14,[r36]; nop.i	0x0; }
	{ ld8	r49,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C0E0; }
	{ cmp4.lt	p07,p06,r8,r0; adds	r1,0x0,r47; (p07) br.cond.dpnt.few	40000000000FE770; }

l40000000000FE080:
	{ nop.m	0x0; ld8	r49,[r35]; nop.i	0x0 }
	{ ld8	r50,[r37]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C260; }
	{ adds	r1,0x0,r47; nop.m	0x0; addl	r49,10,r0 }
	{ ld8	r50,[r37]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AEC0; }
	{ adds	r1,0x0,r47; nop.m	0x0; nop.i	0x0 }

l40000000000FE0D0:
	{ nop.m	0x0; ld8	r49,[r35]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r49; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000FE110; }

l40000000000FE0F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r47; nop.m	0x0; nop.i	0x0 }

l40000000000FE110:
	{ nop.m	0x0; ld8	r34,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	40000000000FE040 }

l40000000000FE130:
	{ ld8	r49,[r37]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r47; mov	pr,r48,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r46; mov.spnt	b0,r45,40000000000FE150 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0 }

l40000000000FE170:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r34; (p06) br.cond.dpnt.few	40000000000FE4C0 }

l40000000000FE180:
	{ addl	r35,9184,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r35]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; addl	r14,9160,r1; (p07) br.cond.dpnt.few	40000000000FE260; }

l40000000000FE1B0:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; addl	r14,8952,r1; (p06) br.cond.dpnt.few	40000000000FE240; }

l40000000000FE1D0:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.lt	p07,p06,0x0,r14; addl	r14,7772,r1; (p06) br.cond.dpnt.few	40000000000FE260; }

l40000000000FE1F0:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000FE260 }

l40000000000FE210:
	{ addl	r14,6108,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000FE260 }

l40000000000FE240:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,bash_delete_last_history; }
	{ adds	r1,0x0,r47; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	40000000000FE4C0 }

l40000000000FE260:
	{ adds	r49,0x0,r34; adds	r33,0x0,r0; br.call.sptk.many	b0,string_list; }
	{ adds	r1,0x0,r47; adds	r34,0x0,r8; nop.i	0x0 }
	{ addl	r50,1,r0; adds	r49,0x0,r8; br.call.sptk.many	b0,check_add_history; }
	{ addl	r14,1,r0; adds	r1,0x0,r47; adds	r49,0x0,r34; }
	{ st4	[r14],r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r47; mov	pr,r48,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r46; mov.spnt	b0,r45,40000000000FE2C0 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0; }

l40000000000FE2E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,bash_clear_history; }
	{ cmp.eq	p07,p06,0x0,r34; adds	r1,0x0,r47; (p07) br.cond.dpnt.few	40000000000FE4C0; }

l40000000000FE300:
	{ nop.m	0x0; tbit.z	p07,p06,r33,0x4; (p06) br.cond.dptk.few	40000000000FE180; }

l40000000000FE310:
	{ nop.m	0x0; tbit.z	p07,p06,r33,0x5; (p06) br.cond.dptk.few	40000000000FDFC0; }

l40000000000FE320:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x7; and	r14,0x4F,r33 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000FE4F0; }

l40000000000FE340:
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000FE830; }

l40000000000FE350:
	{ cmp.eq	p06,p07,0x0,r34; adds	r34,0x8,r34; (p06) br.cond.dpnt.few	40000000000FEDF0; }

l40000000000FE360:
	{ nop.m	0x0; ld8	r14,[r34]; nop.i	0x0; }
	{ ld8	r34,[r14]; nop.m	0x0; nop.i	0x0 }

l40000000000FE380:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x0; (p07) br.cond.dpnt.few	40000000000FE7D0; }

l40000000000FE390:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x2; (p07) br.cond.dpnt.few	40000000000FED50; }

l40000000000FE3A0:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x1; (p07) br.cond.dpnt.few	40000000000FED90; }

l40000000000FE3B0:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x3; (p06) br.cond.dptk.few	40000000000FE4C0 }

l40000000000FE3C0:
	{ addl	r35,9144,r1; nop.m	0x0; addl	r36,-10068,r1; }
	{ nop.m	0x0; ld8	r36,[r36]; nop.i	0x0; }
	{ nop.m	0x0; ld4	r38,[r35]; nop.i	0x0 }
	{ ld4	r37,[r36]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B7A0; }
	{ adds	r49,0x0,r34; ld4	r50,[r35]; nop.i	0x0 }
	{ addl	r51,-1,r0; adds	r1,0x0,r47; br.call.sptk.many	b0,fn400000000001ADC0; }
	{ adds	r1,0x0,r47; adds	r33,0x0,r8; br.call.sptk.many	b0,fn400000000001B7A0; }
	{ adds	r1,0x0,r47; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A700; }
	{ adds	r1,0x0,r47; st4	[r8],r35; nop.i	0x0; }
	{ addl	r14,9180,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000FEE20; }

l40000000000FE480:
	{ cmp4.eq	p07,p06,0x0,r33; (p06) addl	r33,1,r0; nop.i	0x0; }

l40000000000FE48C:
	{ nop; zxt1	r0,r64; (p01) cmp.eq	p32,p16,r8,r64 }

l40000000000FE496:
	{ Invalid; Invalid; break.i	0x80000 }
	{ break.m	0xAA02E; nop; break.i	0x80000 }
	{ Invalid; (p34) nop; (p16) nop }

l40000000000FE4C0:
	{ adds	r33,0x0,r0; adds	r8,0x0,r33; mov	pr,r48,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r46; mov.spnt	b0,r45,40000000000FE4D0 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0; }

l40000000000FE4F0:
	{ adds	r49,0x0,r37; adds	r50,0x10,r12; br.call.sptk.many	b0,legal_number; }
	{ adds	r1,0x0,r47; nop.m	0x0; adds	r14,0x10,r12 }
	{ cmp4.eq	p06,p07,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000FE590; }

l40000000000FE520:
	{ ld8	r49,[r14]; addl	r14,-10068,r1; addl	r34,-10380,r1; }
	{ ld8	r14,[r14]; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r15,r14; nop.i	0x0; }
	{ cmp.lt	p06,p07,r49,r15; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000FE590; }

l40000000000FE560:
	{ ld8	r34,[r34]; ld4	r15,[r34]; nop.i	0x0; }
	{ add	r15,r14,r15; nop.m	0x0; sxt4	r15,r15; }
	{ nop.m	0x0; cmp.lt	p07,p06,r15,r49; (p06) br.cond.dpnt.few	40000000000FE6B0 }

l40000000000FE590:
	{ addl	r50,-9356,r1; nop.m	0x0; addl	r51,5,r0 }
	{ adds	r49,0x0,r0; nop.m	0x0; addl	r33,1,r0; }
	{ ld8	r50,[r50]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r47; nop.m	0x0; adds	r50,0x0,r8 }
	{ adds	r49,0x0,r37; nop.m	0x0; br.call.sptk.many	b0,sh_erange; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r47; mov	pr,r48,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r46; mov.spnt	b0,r45,40000000000FE5F0 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0; }

l40000000000FE610:
	{ adds	r49,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,sh_chkwrite; }
	{ adds	r33,0x0,r8; nop.m	0x0; adds	r1,0x0,r47; }
	{ adds	r8,0x0,r33; mov	pr,r48,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r46; }
	{ nop.m	0x0; mov.spnt	b0,r45,40000000000FE640; nop.i	0x0 }
	{ adds	r12,0x20,r12; nop.m	0x0; br.ret	b0; }

l40000000000FE660:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,bash_delete_last_history; }
	{ adds	r1,0x0,r47; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	40000000000FE020 }

l40000000000FE680:
	{ addl	r33,1,r0; adds	r8,0x0,r33; mov	pr,r48,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r46; mov.spnt	b0,r45,40000000000FE690 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0; }

l40000000000FE6B0:
	{ sub	r49,r49,r14; nop.i	0x0; br.call.sptk.many	b0,bash_delete_histent; }
	{ adds	r1,0x0,r47; adds	r33,0x0,r8; br.call.sptk.many	b0,fn400000000001A700; }
	{ ld4	r49,[r34]; nop.m	0x0; adds	r1,0x0,r47; }
	{ cmp4.lt	p07,p06,r49,r8; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000FE740; }

l40000000000FE6F0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r33; nop.i	0x0; }
	{ (p06) addl	r33,1,r0; nop.i	0x0; (p07) adds	r33,0x0,r0; }

l40000000000FE706:
	{ addp4	r0,0xFFFFFFFFFFFFE000,r1; (p16) mov.sptk	b0,r0,40000000000FE806; nop }

l40000000000FE710:
	{ adds	r8,0x0,r33; mov	pr,r48,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r46; }
	{ nop.m	0x0; mov.spnt	b0,r45,40000000000FE720; nop.i	0x0 }
	{ adds	r12,0x20,r12; nop.m	0x0; br.ret	b0; }

l40000000000FE740:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BBA0; }
	{ cmp4.eq	p06,p07,0x0,r33; adds	r1,0x0,r47; (p06) addl	r33,1,r0; }

l40000000000FE760:
	{ nop.m	0x0; (p07) adds	r33,0x0,r0; br.cond.sptk.few	40000000000FE710; }

l40000000000FE76C:
	{ (p61) ld2	r127,[r36]; Invalid; nop }

l40000000000FE770:
	{ addl	r50,-9364,r1; nop.m	0x0; addl	r51,5,r0 }
	{ adds	r49,0x0,r0; nop.m	0x0; addl	r33,1,r0; }
	{ ld8	r50,[r50]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ ld8	r14,[r36]; adds	r1,0x0,r47; adds	r49,0x0,r8; }
	{ ld8	r50,[r14]; nop.i	0x0; br.call.sptk.many	b0,builtin_error; }
	{ nop.m	0x0; adds	r1,0x0,r47; br.cond.sptk.few	40000000000FE0D0 }

l40000000000FE7D0:
	{ adds	r49,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,maybe_append_history; }
	{ cmp4.eq	p07,p06,0x0,r8; adds	r1,0x0,r47; (p06) addl	r8,1,r0; }

l40000000000FE7F0:
	{ (p07) adds	r8,0x0,r0; nop.i	0x0; adds	r33,0x0,r8; }

l40000000000FE7F6:
	{ add	r0,r0,r1; (p16) mov.sptk	b0,r8,40000000000FE8F6; nop }

l40000000000FE800:
	{ adds	r8,0x0,r33; mov	pr,r48,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r46; }
	{ nop.m	0x0; mov.spnt	b0,r45,40000000000FE810; nop.i	0x0 }
	{ adds	r12,0x20,r12; nop.m	0x0; br.ret	b0; }

l40000000000FE830:
	{ adds	r33,0x18,r12; cmp.eq	p06,p07,0x0,r34; nop.i	0x0 }
	{ adds	r49,0x0,r34; adds	r50,0x0,r0; (p06) br.cond.dpnt.few	40000000000FEDD0; }

l40000000000FE850:
	{ adds	r51,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,get_numeric_arg; }
	{ cmp4.eq	p06,p07,0x0,r8; nop.m	0x0; adds	r1,0x0,r47; }
	{ (p06) addl	r49,1,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000FEB70; }

l40000000000FE876:
	{ chk.a.nc	r0,3FFFFFFFFF0FF076; nop; (p32) nop }

l40000000000FE880:
	{ ld8	r14,[r33]; cmp.lt	p07,p06,r14,r0; nop.i	0x0; }
	{ nop.m	0x0; (p07) sub	r14,r0,r14; nop.i	0x0; }

l40000000000FE89C:
	{ Invalid; Invalid; break.i	0x1000 }

l40000000000FE8A6:
	{ break.m	0x4000; nop; break.i	0x80000 }

l40000000000FE8B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B5C0; }
	{ adds	r1,0x0,r47; cmp.eq	p07,p06,0x0,r8; nop.i	0x0 }
	{ adds	r35,0x0,r8; adds	r15,0x8,r8; (p07) br.cond.dpnt.few	40000000000FEB60; }

l40000000000FE8E0:
	{ ld8	r14,[r8]; cmp.eq	p06,p07,0x0,r14; nop.i	0x0; }
	{ nop.m	0x0; (p06) adds	r14,0x0,r0; (p06) br.cond.dpnt.few	40000000000FE930; }

l40000000000FE8FC:
	{ (p02) cmp.lt	p00,p09,r64,r33; zxt1	r0,r64; break.i	0x1000 }

l40000000000FE900:
	{ adds	r14,0x0,r0; nop.m	0x0; nop.i	0x0; }

l40000000000FE910:
	{ ld8	r16,[r15],8; nop.m	0x0; adds	r14,0x1,r14; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r16; (p06) br.cond.dptk.few	40000000000FE910 }

l40000000000FE930:
	{ ld8	r33,[r33]; nop.m	0x0; sxt4	r15,r14; }
	{ cmp.lt	p06,p07,r33,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000FED40; }

l40000000000FE950:
	{ cmp.lt	p07,p06,r33,r15; nop.i	0x0; (p06) br.cond.dptk.few	40000000000FED40; }

l40000000000FE960:
	{ (p07) sub	r33,r14,r33; nop.i	0x0; sxt4	r34,r33; }

l40000000000FE966:
	{ chk.a.nc	f0,3FFFFFFFFF0FF166; (p17) cmp4.ltu	p00,p00,r33,r22; (p33) nop }

l40000000000FE976:
	{ break.m	0x4000; nop; (p16) nop }

l40000000000FE980:
	{ addl	r49,-9348,r1; add	r34,r35,r34; addl	r44,16191,r0; }
	{ ld8	r49,[r49]; nop.i	0x0; br.call.sptk.many	b0,get_string_value; }
	{ adds	r1,0x0,r47; ld8	r14,[r34]; adds	r37,0x0,r8 }
	{ nop.m	0x0; cmp.eq	p16,p17,0x0,r8; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; addl	r36,7676,r1; sxt4	r14,r33 }
	{ addl	r41,20404,r1; addl	r40,-10068,r1; (p06) br.cond.dpnt.few	40000000000FEB60; }

l40000000000FE9E0:
	{ adds	r14,0x1,r14; nop.m	0x0; addl	r38,7684,r1 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld8	r40,[r40]; shladd	r35,r14,0x3,r35; adds	r42,0x0,r36 }
	{ adds	r43,0x2,r41; nop.m	0x0; nop.i	0x0 }

l40000000000FEA20:
	{ nop.m	0x0; ld4.acq	r14,[r36]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000FEC30; }

l40000000000FEA40:
	{ nop.m	0x0; ld4.acq	r14,[r38]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000FEC60 }

l40000000000FEA60:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dpnt.few	40000000000FEA90; }

l40000000000FEA70:
	{ ld1	r14,[r37]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000FEC80 }

l40000000000FEA90:
	{ adds	r53,0x0,r0; nop.m	0x0; nop.i	0x0; }

l40000000000FEAA0:
	{ nop.m	0x0; ld8	r14,[r34]; cmp.eq	p07,p06,0x0,r53 }
	{ ld4	r15,[r40]; adds	r16,0x10,r14; add	r51,r33,r15; }
	{ ld8	r15,[r16]; cmp.eq	p08,p09,0x0,r15; nop.i	0x0; }
	{ nop.m	0x0; (p08) addl	r52,32,r0; nop.i	0x0; }

l40000000000FEADC:
	{ adds	r0,0x1881,r0; zxt4	r10,r0; mov	pr,r32,0x0 }

l40000000000FEAE6:
	{ chk.a.nc	f0,3FFFFFFFFF0FF2E6; nop; (p48) nop }

l40000000000FEAF0:
	{ ld1	r15,[r53]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	40000000000FEBC0 }

l40000000000FEB10:
	{ addl	r50,-9340,r1; adds	r34,0x0,r35; addl	r49,1,r0 }
	{ ld8	r54,[r14]; adds	r33,0x1,r33; adds	r35,0x8,r35; }
	{ ld8	r50,[r50]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ ld8	r14,[r34]; nop.m	0x0; adds	r1,0x0,r47; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000FEA20 }

l40000000000FEB60:
	{ adds	r49,0x0,r0; nop.m	0x0; nop.i	0x0 }

l40000000000FEB70:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_chkwrite; }
	{ adds	r33,0x0,r8; nop.m	0x0; adds	r1,0x0,r47; }
	{ adds	r8,0x0,r33; mov	pr,r48,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r46; }
	{ nop.m	0x0; mov.spnt	b0,r45,40000000000FEBA0; nop.i	0x0 }
	{ adds	r12,0x20,r12; nop.m	0x0; br.ret	b0 }

l40000000000FEBC0:
	{ addl	r53,-9388,r1; addl	r50,-9340,r1; adds	r34,0x0,r35 }
	{ ld8	r54,[r14]; addl	r49,1,r0; adds	r33,0x1,r33; }
	{ ld8	r53,[r53]; nop.m	0x0; adds	r35,0x8,r35 }
	{ ld8	r50,[r50]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ ld8	r14,[r34]; nop.m	0x0; adds	r1,0x0,r47; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000FEA20 }

l40000000000FEC20:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000FEB60 }

l40000000000FEC30:
	{ ld4.acq	r49,[r42]; nop.i	0x0; br.call.sptk.many	b0,termsig_handler; }
	{ ld4.acq	r14,[r38]; nop.m	0x0; adds	r1,0x0,r47; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000FEA60 }

l40000000000FEC60:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,throw_to_top_level; }
	{ nop.m	0x0; adds	r1,0x0,r47; br.cond.sptk.few	40000000000FEA60 }

l40000000000FEC80:
	{ ld8	r49,[r34]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BEC0; }
	{ adds	r1,0x0,r47; cmp.eq	p06,p07,0x0,r8; adds	r14,0x10,r12; }
	{ addl	r53,20404,r1; st8	[r8],r14; nop.i	0x0 }
	{ (p06) st2	[r44],r41; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000FECE0; }

l40000000000FECB6:
	{ chk.a.nc	f0,3FFFFFFFFF0FF4B6; nop; add	r0,r0,r32 }

l40000000000FECC0:
	{ nop.m	0x0; (p06) st1	[r0],r43; nop.i	0x0 }

l40000000000FECCC:
	{ nop; break.i	0x1000; break.i	0x1000 }
	{ (p46) nop; zxt1	r64,r64; break.b	0x1000 }

l40000000000FECE0:
	{ adds	r49,0x0,r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B620; }
	{ adds	r1,0x0,r47; nop.m	0x0; addl	r50,128,r0 }
	{ adds	r51,0x0,r37; adds	r52,0x0,r8; addl	r49,20404,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B5A0; }
	{ adds	r1,0x0,r47; addl	r53,20404,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000FEAA0 }

l40000000000FED40:
	{ adds	r34,0x0,r0; adds	r33,0x0,r0; br.cond.sptk.few	40000000000FE980; }

l40000000000FED50:
	{ adds	r49,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AAA0; }
	{ cmp4.eq	p07,p06,0x0,r8; adds	r1,0x0,r47; (p06) addl	r8,1,r0; }

l40000000000FED70:
	{ nop.m	0x0; (p07) adds	r8,0x0,r0; nop.i	0x0; }

l40000000000FED7C:
	{ invala; nop; zxt1	r0,r64 }
	{ (p20) nop; zxt1	r64,r64; break.i	0x1000 }

l40000000000FED90:
	{ adds	r49,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AC00; }
	{ cmp4.eq	p07,p06,0x0,r8; adds	r1,0x0,r47; (p06) addl	r8,1,r0; }

l40000000000FEDB0:
	{ nop.m	0x0; (p07) adds	r8,0x0,r0; nop.i	0x0; }

l40000000000FEDBC:
	{ invala; nop; zxt1	r0,r64 }
	{ (p18) nop; cmp.lt	p00,p00,r32,r0; Invalid }

l40000000000FEDD0:
	{ nop.m	0x0; addl	r14,-1,r0; nop.i	0x0; }
	{ st8	[r14],r33; nop.i	0x0; br.cond.sptk.few	40000000000FE8B0 }

l40000000000FEDF0:
	{ nop.m	0x0; addl	r49,-9332,r1; nop.i	0x0; }
	{ ld8	r49,[r49]; nop.i	0x0; br.call.sptk.many	b0,get_string_value; }
	{ adds	r1,0x0,r47; adds	r34,0x0,r8; br.cond.sptk.few	40000000000FE380; }

l40000000000FEE20:
	{ addl	r14,9148,r1; nop.m	0x0; sub	r16,r8,r38 }
	{ ld4	r15,[r36]; nop.m	0x0; cmp4.eq	p07,p06,0x0,r33; }
	{ nop.m	0x0; add	r16,r16,r15; (p06) addl	r33,1,r0; }

l40000000000FEE50:
	{ sub	r37,r16,r37; nop.m	0x0; (p07) adds	r33,0x0,r0; }

l40000000000FEE60:
	{ ld4	r15,[r14]; adds	r8,0x0,r33; add	r15,r37,r15; }
	{ st4	[r15],r14; mov	pr,r48,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r46; }
	{ nop.m	0x0; mov.spnt	b0,r45,40000000000FEE80; nop.i	0x0 }
	{ adds	r12,0x20,r12; nop.m	0x0; br.ret	b0; }
40000000000FEEA0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000FEEB0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; jobs_builtin: 40000000000FEEC0
jobs_builtin proc
	{ alloc	r40,ar.pfs,0xE,0x0,0xA; adds	r12,0xFFFFFFFFFFFFFF00,r12; nop.b	0x0 }
	{ adds	r41,0x0,r1; mov	r39,b7; adds	r36,0x0,r0 }
	{ adds	r35,0x0,r0; adds	r34,0x0,r0; br.call.sptk.many	b0,reset_internal_getopt; }
	{ adds	r1,0x0,r41; nop.i	0x0; addl	r33,-4476,r1; }
	{ ld8	r33,[r33]; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }
	{ addl	r43,-4508,r1; nop.m	0x0; adds	r42,0x0,r32; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r41; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dpnt.few	40000000000FF020 }

l40000000000FEF50:
	{ nop.m	0x0; adds	r8,0xFFFFFFFFFFFFFF94,r8; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0xC,r8; (p07) br.cond.dptk.few	40000000000FEFB0 }

l40000000000FEF70:
	{ nop.m	0x0; addl	r33,258,r0; br.call.sptk.many	b0,builtin_usage; }
	{ adds	r1,0x0,r41; nop.m	0x0; nop.i	0x0 }

l40000000000FEF90:
	{ adds	r8,0x0,r33; mov.i	ar.pfs,r40; mov.spnt	b0,r39,40000000000FEF90 }
	{ nop.m	0x0; adds	r12,0x100,r12; br.ret	b0 }

l40000000000FEFB0:
	{ addp4	r8,r8,r0; shladd	r8,r8,0x3,r33; nop.i	0x0; }
	{ ld8	r14,[r8]; add	r8,r8,r14; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r8,40000000000FEFD0; br.cond	b6; }
40000000000FEFE0 08 30 00 44 87 39 B0 22 F7 B9 4F 00 00 00 04 00 .0.D.9."..O.....
40000000000FEFF0 19 50 01 40 00 21 30 0A 8C 00 C2 03 00 06 00 43 .P.@.!0........C
40000000000FF000 11 58 01 56 18 10 00 00 00 02 00 00 C8 B4 01 50 .X.V...........P
40000000000FF010 11 08 00 52 00 21 70 F8 23 0C 77 03 40 FF FF 4A ...R.!p.#.w.@..J

l40000000000FF020:
	{ addl	r14,9268,r1; cmp4.eq	p06,p07,0x0,r35; addl	r35,7444,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld8	r33,[r14]; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000FF2D0; }

l40000000000FF050:
	{ cmp.eq	p07,p06,0x0,r33; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000FF660; }

l40000000000FF060:
	{ adds	r36,0x0,r0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000FF080:
	{ adds	r42,0x90,r12; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BC20; }
	{ addl	r43,17,r0; nop.m	0x0; adds	r1,0x0,r41 }
	{ adds	r42,0x90,r12; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B400; }
	{ adds	r1,0x0,r41; adds	r42,0x10,r12; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r43,0x90,r12; adds	r44,0x10,r12; nop.i	0x0 }
	{ adds	r1,0x0,r41; adds	r42,0x0,r0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r41; adds	r42,0x0,r33; br.call.sptk.many	b0,get_job_spec; }
	{ adds	r1,0x0,r41; cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r8; sxt4	r15,r8 }
	{ adds	r42,0x0,r0; adds	r43,0x0,r34; (p06) br.cond.dpnt.few	40000000000FF250; }

l40000000000FF110:
	{ ld8	r14,[r35]; adds	r44,0x0,r0; adds	r45,0x0,r8; }
	{ cmp.eq	p06,p07,0x0,r14; shladd	r14,r15,0x3,r14; (p06) br.cond.dpnt.few	40000000000FF250; }

l40000000000FF130:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000FF250; }

l40000000000FF150:
	{ cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFE,r8; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000FF180; }

l40000000000FF160:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,list_one_job; }
	{ adds	r1,0x0,r41; nop.m	0x0; nop.i	0x0 }

l40000000000FF180:
	{ addl	r42,2,r0; nop.m	0x0; adds	r43,0x10,r12 }
	{ adds	r44,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ ld8	r33,[r33]; nop.m	0x0; adds	r1,0x0,r41; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	40000000000FF080; }

l40000000000FF1C0:
	{ cmp4.eq	p07,p06,0x0,r36; (p06) addl	r36,1,r0; nop.i	0x0; }

l40000000000FF1CC:
	{ nop; (p04) nop; zxt1	r0,r64 }

l40000000000FF1D6:
	{ Invalid; Invalid; nop.b	0x21002 }
	{ break.m	0xAA028; nop; break.i	0x80000 }
	{ Invalid; (p34) nop; break.i	0x80000 }
40000000000FF200 11 00 00 00 01 00 40 12 00 00 48 00 20 FD FF 48 ......@...H. ..H
40000000000FF210 10 00 00 00 01 00 40 0A 00 00 48 00 10 FD FF 48 ......@...H....H
40000000000FF220 11 00 00 00 01 00 20 12 00 00 48 00 00 FD FF 48 ...... ...H....H
40000000000FF230 11 00 00 00 01 00 20 1A 00 00 48 00 F0 FC FF 48 ...... ...H....H
40000000000FF240 10 00 00 00 01 00 20 0A 00 00 48 00 E0 FC FF 48 ...... ...H....H

l40000000000FF250:
	{ adds	r14,0x8,r33; nop.m	0x0; adds	r36,0x1,r36; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r42,[r14]; nop.i	0x0; br.call.sptk.many	b0,sh_badjob; }
	{ adds	r1,0x0,r41; addl	r42,2,r0; nop.i	0x0 }
	{ adds	r43,0x10,r12; adds	r44,0x0,r0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ ld8	r33,[r33]; nop.m	0x0; adds	r1,0x0,r41; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	40000000000FF080 }

l40000000000FF2C0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000FF1C0; }

l40000000000FF2D0:
	{ addl	r36,-20676,r1; cmp.eq	p07,p06,0x0,r33; nop.i	0x0 }
	{ addl	r37,7444,r1; adds	r34,0x0,r33; (p07) br.cond.dpnt.few	40000000000FF380; }

l40000000000FF2F0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ adds	r36,0x1C,r36; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000FF320:
	{ adds	r35,0x8,r34; ld8	r14,[r35]; nop.i	0x0; }
	{ ld8	r14,[r14]; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x25,r14; (p06) br.cond.dpnt.few	40000000000FF4E0 }

l40000000000FF360:
	{ nop.m	0x0; ld8	r34,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	40000000000FF320 }

l40000000000FF380:
	{ nop.m	0x0; addl	r42,-4500,r1; nop.i	0x0; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,begin_unwind_frame; }
	{ adds	r1,0x0,r41; nop.i	0x0; br.call.sptk.many	b0,make_bare_simple_command; }
	{ adds	r35,0x18,r8; nop.m	0x0; adds	r34,0x0,r8 }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r42,0x0,r33; }
	{ ld8	r33,[r35]; nop.i	0x0; br.call.sptk.many	b0,copy_word_list; }
	{ adds	r14,0x8,r33; nop.m	0x0; adds	r15,0x4,r34 }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r43,0x0,r34; }
	{ st8	[r8],r14; ld4	r16,[r15]; addl	r42,-9796,r1; }
	{ nop.m	0x0; ld8	r14,[r35]; or	r17,0x20,r16 }
	{ ld8	r42,[r42]; adds	r18,0x10,r14; nop.i	0x0; }
	{ ld4	r16,[r14]; st8	[r0],r18; nop.i	0x0 }
	{ st4	[r17],r15; or	r16,0x20,r16; nop.i	0x0; }
	{ st4	[r16],r14; nop.i	0x0; br.call.sptk.many	b0,add_unwind_protect; }
	{ adds	r1,0x0,r41; adds	r42,0x0,r34; br.call.sptk.many	b0,execute_command; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r33,0x0,r8 }
	{ adds	r42,0x0,r34; nop.m	0x0; br.call.sptk.many	b0,dispose_command; }
	{ adds	r1,0x0,r41; addl	r42,-4500,r1; nop.i	0x0; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,discard_unwind_frame; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r41; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000FF4C0; nop.i	0x0 }
	{ adds	r12,0x100,r12; nop.m	0x0; br.ret	b0; }

l40000000000FF4E0:
	{ adds	r42,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,get_job_spec; }
	{ adds	r1,0x0,r41; cmp4.lt	p06,p07,r8,r0; (p06) br.cond.dpnt.few	40000000000FF360; }

l40000000000FF500:
	{ nop.m	0x0; ld4	r14,[r36]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r8,r14; (p06) br.cond.dptk.few	40000000000FF360 }

l40000000000FF520:
	{ nop.m	0x0; sxt4	r8,r8; nop.i	0x0 }
	{ ld8	r14,[r37]; shladd	r14,r8,0x3,r14; nop.i	0x0; }
	{ nop.m	0x0; ld8	r38,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r38; adds	r38,0x10,r38; (p06) br.cond.dpnt.few	40000000000FF360; }

l40000000000FF560:
	{ nop.m	0x0; ld8	r14,[r35]; nop.i	0x0; }
	{ ld8	r42,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; ld4	r42,[r38]; adds	r1,0x0,r41 }
	{ nop.m	0x0; ld8	r35,[r35]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r42,r42; br.call.sptk.many	b0,itos; }
	{ nop.m	0x0; ld8	r34,[r34]; adds	r1,0x0,r41 }
	{ nop.m	0x0; st8	[r8],r35; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	40000000000FF320 }

l40000000000FF5E0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000FF380 }
40000000000FF5F0 08 58 71 FB DC 27 00 00 00 02 00 80 55 00 00 90 .Xq..'......U...
40000000000FF600 09 50 01 00 00 21 00 00 00 02 00 20 14 00 00 90 .P...!..... ....
40000000000FF610 11 58 01 56 18 10 00 00 00 02 00 00 58 B5 F1 58 .X.V........X..X
40000000000FF620 11 08 00 52 00 21 A0 02 20 00 42 00 68 DF FE 58 ...R.!.. .B.h..X
40000000000FF630 09 40 00 42 00 21 10 00 A4 00 42 00 80 02 AA 00 .@.B.!....B.....
40000000000FF640 00 00 00 00 01 00 00 38 05 80 03 00 00 00 04 00 .......8........
40000000000FF650 18 60 00 18 02 21 00 00 00 02 00 80 08 00 84 00 .`...!..........

l40000000000FF660:
	{ cmp4.eq	p06,p07,0x1,r36; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000FF6E0; }

l40000000000FF670:
	{ cmp4.eq	p06,p07,0x2,r36; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000FF720; }

l40000000000FF680:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r36; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r33,0x0,r0; (p07) br.cond.dptk.few	40000000000FEF90 }

l40000000000FF69C:
	{ (p08) cmpxchg4.acq	r127,[r37],r63; zxt1	r64,r64; break.i	0x1000 }

l40000000000FF6A0:
	{ adds	r42,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,list_all_jobs; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r41; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000FF6C0; nop.i	0x0 }
	{ adds	r12,0x100,r12; nop.m	0x0; br.ret	b0; }

l40000000000FF6E0:
	{ adds	r42,0x0,r34; adds	r33,0x0,r0; br.call.sptk.many	b0,list_running_jobs; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r41; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000FF700; nop.i	0x0 }
	{ adds	r12,0x100,r12; nop.m	0x0; br.ret	b0; }

l40000000000FF720:
	{ adds	r42,0x0,r34; adds	r33,0x0,r0; br.call.sptk.many	b0,list_stopped_jobs; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r41; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000FF740; nop.i	0x0 }
	{ adds	r12,0x100,r12; nop.m	0x0; br.ret	b0; }
40000000000FF760 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000FF770 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; disown_builtin: 40000000000FF780
disown_builtin proc
	{ alloc	r42,ar.pfs,0x10,0x0,0xD; adds	r12,0xFFFFFFFFFFFFFEF0,r12; nop.b	0x0 }
	{ adds	r43,0x0,r1; nop.m	0x0; mov	r44,pr; }
	{ nop.m	0x0; mov	r41,b1; adds	r37,0x0,r0 }
	{ adds	r36,0x0,r0; adds	r35,0x0,r0; br.call.sptk.many	b0,reset_internal_getopt; }
	{ adds	r1,0x0,r43; nop.m	0x0; nop.i	0x0; }

l40000000000FF7D0:
	{ addl	r46,-4492,r1; nop.m	0x0; adds	r45,0x0,r32; }
	{ ld8	r46,[r46]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r43; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dpnt.few	40000000000FF8B0; }

l40000000000FF800:
	{ cmp4.eq	p06,p07,0x68,r8; addl	r34,258,r0; (p06) br.cond.dpnt.few	40000000000FFB40; }

l40000000000FF810:
	{ cmp4.eq	p06,p07,0x72,r8; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000FFB50; }

l40000000000FF820:
	{ cmp4.eq	p06,p07,0x61,r8; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000FF880; }

l40000000000FF830:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ adds	r1,0x0,r43; nop.m	0x0; nop.i	0x0 }

l40000000000FF850:
	{ adds	r8,0x0,r34; mov	pr,r44,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r42; }
	{ nop.m	0x0; mov.spnt	b0,r41,40000000000FF860; nop.i	0x0 }
	{ adds	r12,0x110,r12; nop.m	0x0; br.ret	b0 }

l40000000000FF880:
	{ addl	r46,-4492,r1; adds	r45,0x0,r32; addl	r37,1,r0; }
	{ ld8	r46,[r46]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r43; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p06) br.cond.dptk.few	40000000000FF800; }

l40000000000FF8B0:
	{ addl	r14,9268,r1; addl	r40,-20676,r1; addl	r39,7444,r1 }
	{ adds	r34,0x0,r0; adds	r38,0x110,r12; cmp4.eq	p18,p19,0x0,r35; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ adds	r40,0x1C,r40; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld8	r33,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p07) br.cond.dpnt.few	40000000000FFBE0; }

l40000000000FF910:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000FF920:
	{ adds	r45,0x90,r12; cmp.eq	p16,p17,0x0,r33; br.call.sptk.many	b0,fn400000000001BC20; }
	{ addl	r46,17,r0; nop.m	0x0; adds	r1,0x0,r43 }
	{ adds	r45,0x90,r12; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B400; }
	{ adds	r1,0x0,r43; adds	r45,0x10,r12; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r43; adds	r45,0x0,r0; nop.i	0x0 }
	{ adds	r46,0x90,r12; adds	r47,0x10,r12; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r14,0x8,r33; nop.m	0x0; adds	r1,0x0,r43 }
	{ adds	r46,0x0,r38; nop.m	0x0; (p16) br.cond.dpnt.few	40000000000FF9F0; }

l40000000000FF9A0:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r45,[r14]; nop.i	0x0; br.call.sptk.many	b0,legal_number; }
	{ adds	r1,0x0,r43; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	40000000000FF9F0 }

l40000000000FF9D0:
	{ ld8	r45,[r38]; nop.m	0x0; sxt4	r14,r45; }
	{ nop.m	0x0; cmp.eq	p07,p06,r14,r45; (p07) br.cond.dpnt.few	40000000000FFB60 }

l40000000000FF9F0:
	{ adds	r45,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,get_job_spec; }
	{ adds	r1,0x0,r43; cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r8; (p06) br.cond.dpnt.few	40000000000FFB80 }

l40000000000FFA10:
	{ nop.m	0x0; ld8	r14,[r39]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000FFB80; }

l40000000000FFA30:
	{ cmp4.lt	p06,p07,r8,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000FFB80; }

l40000000000FFA40:
	{ nop.m	0x0; ld4	r15,[r40]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r8,r15; (p06) br.cond.dptk.few	40000000000FFB80 }

l40000000000FFA60:
	{ nop.m	0x0; sxt4	r15,r8; shladd	r14,r15,0x3,r14; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000FFB80; }

l40000000000FFA90:
	{ adds	r45,0x0,r8; nop.i	0x0; (p19) br.call.dptk.many	b0,nohup_job; }

l40000000000FFAA0:
	{ nop.m	0x0; (p18) addl	r46,1,r0; (p18) br.call.dptk.many	b0,delete_job; }

l40000000000FFAAC:
	{ (p11) nop; invala; break.i	0x1000 }

l40000000000FFAB0:
	{ adds	r1,0x0,r43; nop.m	0x0; nop.i	0x0; }

l40000000000FFAC0:
	{ addl	r45,2,r0; nop.m	0x0; adds	r46,0x10,r12 }
	{ adds	r47,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r43; nop.i	0x0; (p16) br.cond.dpnt.few	40000000000FF850; }

l40000000000FFAF0:
	{ nop.m	0x0; ld8	r33,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.sptk.few	40000000000FF920; }

l40000000000FFB10:
	{ adds	r8,0x0,r34; mov	pr,r44,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r42; }
	{ nop.m	0x0; mov.spnt	b0,r41,40000000000FFB20; nop.i	0x0 }
	{ adds	r12,0x110,r12; nop.m	0x0; br.ret	b0 }

l40000000000FFB40:
	{ nop.m	0x0; addl	r35,1,r0; br.cond.sptk.few	40000000000FF7D0 }

l40000000000FFB50:
	{ nop.m	0x0; addl	r36,1,r0; br.cond.sptk.few	40000000000FF7D0; }

l40000000000FFB60:
	{ adds	r46,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,get_job_by_pid; }
	{ adds	r1,0x0,r43; cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dptk.few	40000000000FFA10; }

l40000000000FFB80:
	{ (p17) adds	r14,0x8,r33; (p16) addl	r46,-4484,r1; nop.i	0x0 }

l40000000000FFB86:
	{ Invalid; (p20) nop }

l40000000000FFB8C:
	{ nop; (p05) cmp.gt.or.andcm	p00,p16,r0,r64; (p21) dep	r1,r0,r0,62,3 }

l40000000000FFB96:
	{ Invalid; Invalid; Invalid }

l40000000000FFB9C:
	{ Invalid; Invalid; Invalid }

l40000000000FFBA6:
	{ (p23) fwb; (p20) nop }

l40000000000FFBAC:
	{ nop; Invalid; break.i	0x101000 }

l40000000000FFBB6:
	{ nop; (p32) nop; (p20) nop }

l40000000000FFBC0:
	{ (p16) adds	r1,0x0,r43; (p16) adds	r45,0x0,r8; br.call.sptk.many	b0,sh_badjob; }

l40000000000FFBC6:
	{ Invalid; Invalid; Invalid }

l40000000000FFBCC:
	{ (p62) invala; nop; zxt1	r96,r64 }
	{ (p55) nop; (p04) cmp.ge.and	p41,p16,r0,r3; Invalid }

l40000000000FFBE0:
	{ or	r37,r36,r37; (p18) cmp.eq.unc	p06,p00,r0,r0; (p19) cmp.eq.unc	p07,p00,r0,r0; }

l40000000000FFBEC:
	{ invala; break.m	0x1000; Invalid }

l40000000000FFBF0:
	{ nop.m	0x0; cmp4.eq	p08,p09,0x0,r37; (p08) br.cond.dptk.few	40000000000FF920 }

l40000000000FFC00:
	{ nop.m	0x0; adds	r45,0x0,r36; (p06) br.cond.dptk.few	40000000000FFC50 }

l40000000000FFC10:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,nohup_all_jobs; }
	{ adds	r8,0x0,r34; adds	r1,0x0,r43; mov	pr,r44,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r42; mov.spnt	b0,r41,40000000000FFC30 }
	{ nop.m	0x0; adds	r12,0x110,r12; br.ret	b0; }

l40000000000FFC50:
	{ adds	r34,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,delete_all_jobs; }
	{ adds	r8,0x0,r34; adds	r1,0x0,r43; mov	pr,r44,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r42; mov.spnt	b0,r41,40000000000FFC70 }
	{ nop.m	0x0; adds	r12,0x110,r12; br.ret	b0; }
40000000000FFC90 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000FFCA0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000FFCB0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; fn40000000000FFCC0: 40000000000FFCC0
;;   Called from:
;;     40000000001005CC (in kill_builtin)
;;     400000000010067C (in kill_builtin)
fn40000000000FFCC0 proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; nop.m	0x0; mov	r34,b2 }
	{ adds	r36,0x0,r1; nop.m	0x0; adds	r37,0x0,r33; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B4A0; }
	{ adds	r1,0x0,r36; cmp.eq	p07,p06,0x0,r8; nop.i	0x0 }
	{ adds	r39,0x0,r8; sxt4	r38,r32; (p07) br.cond.dpnt.few	40000000000FFD50; }

l40000000000FFD10:
	{ nop.m	0x0; addl	r37,948,r1; nop.i	0x0; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,builtin_error; }
	{ adds	r1,0x0,r36; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000FFD40; br.ret	b0 }

l40000000000FFD50:
	{ addl	r38,940,r1; adds	r37,0x0,r0; addl	r39,5,r0; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; adds	r39,0x0,r8; sxt4	r38,r32; }
	{ nop.m	0x0; addl	r37,948,r1; nop.i	0x0; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,builtin_error; }
	{ adds	r1,0x0,r36; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000FFDB0; br.ret	b0; }

;; kill_builtin: 40000000000FFDC0
kill_builtin proc
	{ alloc	r43,ar.pfs,0x10,0x0,0xD; adds	r12,0xFFFFFFFFFFFFFEF0,r12; nop.b	0x0 }
	{ addl	r14,6456,r1; mov	r42,b2; adds	r44,0x0,r1; }
	{ cmp.eq	p07,p06,0x0,r32; addl	r33,956,r1; adds	r34,0x0,r0 }
	{ adds	r38,0x0,r0; addl	r35,15,r0; (p07) br.cond.dpnt.few	40000000001006B0; }

l40000000000FFE00:
	{ nop.m	0x0; ld8	r33,[r33]; nop.i	0x0; }
	{ ld4	r36,[r14]; nop.m	0x0; adds	r14,0x8,r32; }
	{ ld8	r14,[r14]; nop.m	0x0; cmp4.eq	p07,p06,0x0,r36; }
	{ (p07) addl	r36,3,r0; ld8	r45,[r14]; (p06) addl	r36,2,r0; }

l40000000000FFE36:
	{ (p22) chk.a.nc	r0,3FFFFFFFFF90BF16; (p18) nop; (p48) br.call.sptk.few	b3,b0 }

l40000000000FFE40:
	{ ld1	r15,[r45]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r15; (p07) br.cond.dpnt.few	4000000000100140; }

l40000000000FFE60:
	{ addl	r40,-20676,r1; cmp4.eq	p06,p07,0x0,r38; addl	r41,7444,r1 }
	{ adds	r39,0x0,r0; adds	r37,0x110,r12; (p07) br.cond.dpnt.few	40000000001006F0; }

l40000000000FFE80:
	{ nop.m	0x0; nop.m	0x0; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r35 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000100720; }

l40000000000FFEA0:
	{ adds	r40,0x1C,r40; cmp.eq	p06,p07,0x0,r32; (p06) br.cond.dpnt.few	40000000001006B0; }

l40000000000FFEB0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000FFEC0:
	{ adds	r34,0x8,r32; ld8	r14,[r34]; nop.i	0x0; }
	{ ld8	r45,[r14]; ld1	r15,[r45]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; cmp4.eq	p07,p06,0x2D,r15 }
	{ adds	r14,0x0,r15; (p07) adds	r36,0x1,r45; cmp4.eq	p09,p08,0x0,r14; }

l40000000000FFEFC:
	{ cmp4.eq.or.andcm	p14,p35,r8,r115; (p01) nop; (p04) cmp4.eq.or.andcm	p32,p48,r11,r64; }

l40000000000FFF06:
	{ Invalid; (p07) nop; (p32) nop; }

l40000000000FFF0C:
	{ cmp.lt	p15,p17,r20,r0; czx1.r	r96,r97; mov	pr,r32,0x0; }
	{ (p29) cmp.eq	p00,p09,r64,r33; czx1.r	r73,r97; cmp.lt	p00,p00,0x20,r0 }

l40000000000FFF20:
	{ cmp4.eq	p07,p06,0x25,r14; nop.m	0x0; (p08) addl	r14,1,r0; }

l40000000000FFF30:
	{ (p06) addl	r15,1,r0; (p09) adds	r14,0x0,r0; (p07) adds	r15,0x0,r0; }

l40000000000FFF36:
	{ Invalid; (p07) nop; break.i	0x80000 }

l40000000000FFF3C:
	{ nop; cmp.lt	p00,p00,r32,r0; zxt1	r99,r3; }

l40000000000FFF40:
	{ nop.m	0x0; and	r14,r14,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	4000000000100350 }

l40000000000FFF60:
	{ ld1	r14,[r36]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000001003C0 }

l40000000000FFF80:
	{ adds	r45,0x90,r12; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BC20; }
	{ addl	r46,17,r0; nop.m	0x0; adds	r1,0x0,r44 }
	{ adds	r45,0x90,r12; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B400; }
	{ adds	r1,0x0,r44; adds	r45,0x10,r12; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r44; adds	r46,0x90,r12; nop.i	0x0 }
	{ adds	r47,0x10,r12; adds	r45,0x0,r0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r44; adds	r45,0x0,r32; br.call.sptk.many	b0,get_job_spec; }
	{ adds	r1,0x0,r44; cmp4.lt	p06,p07,r8,r0; (p06) br.cond.dpnt.few	40000000001004B0; }

l4000000000100000:
	{ nop.m	0x0; ld4	r14,[r40]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r8,r14; (p06) br.cond.dptk.few	40000000001004C0 }

l4000000000100020:
	{ nop.m	0x0; ld8	r14,[r41]; sxt4	r8,r8 }
	{ adds	r47,0x0,r0; addl	r45,2,r0; adds	r46,0x10,r12; }
	{ shladd	r14,r8,0x3,r14; ld8	r14,[r14]; nop.i	0x0; }
	{ adds	r15,0x18,r14; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	40000000001004C0; }

l4000000000100060:
	{ ld4	r15,[r15]; nop.m	0x0; tbit.z	p06,p07,r15,0x2; }
	{ (p06) adds	r14,0x8,r14; (p06) ld8	r14,[r14]; nop.i	0x0; }

l4000000000100076:
	{ (p07) fwb; cmp4.ltu	p00,p00,0x0,r1; (p33) nop; }

l400000000010007C:
	{ cmp4.eq.and	p00,p43,r1,r0; (p01) cmp4.ne.and	p04,p16,r3,r64; zxt1	r66,r64 }

l4000000000100086:
	{ Invalid; nop; (p32) nop; }

l400000000010008C:
	{ cmpxchg4.acq	r0,[r0],r1; Invalid; break.i	0x1000 }
	{ (p49) nop; nop; (p05) epc }
	{ cmp.lt	p00,p25,r1,r0; (p05) cmp.eq.unc	p32,p16,r8,r64; zxt4	r0,r0 }
	{ (p30) nop; cmp.eq	p00,p16,r11,r64; nop }
	{ (p38) nop; Invalid; Invalid }

l40000000001000D0:
	{ ld8	r32,[r32]; nop.m	0x0; adds	r39,0x1,r39; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p06) br.cond.dptk.few	40000000000FFEC0; }

l40000000001000F0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000100100:
	{ cmp4.eq	p06,p07,0x0,r39; (p06) addl	r39,1,r0; nop.i	0x0; }

l400000000010010C:
	{ nop; cmp4.eq.or.andcm	p00,p32,r32,r0; zxt1	r0,r64 }

l400000000010011C:
	{ Invalid; zxt1	r96,r64; (p48) break.i	0x2A80A }
	{ (p21) nop; add	r0,r32,r0; (p01) shladd	r4,r67,0x1,r64 }
	{ cmp.eq	p00,p11,r33,r0; (p33) cmp.eq	p32,p16,r11,r64; Invalid }

l4000000000100140:
	{ adds	r15,0x2,r45; ld1	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	40000000001001F0 }

l4000000000100170:
	{ adds	r15,0x1,r45; ld1	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; cmp4.eq	p07,p06,0x6C,r15; }
	{ nop.m	0x0; (p07) adds	r38,0x1,r38; nop.i	0x0 }

l400000000010019C:
	{ Invalid; Invalid; mov	pr,r32,0x0 }

l40000000001001A6:
	{ chk.a.nc	f0,3FFFFFFFFF1009A6; nop; break.i	0x80000 }

l40000000001001B0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x73,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x6E,r15; (p06) br.cond.dptk.few	4000000000100400; }

l40000000001001D0:
	{ cmp4.eq	p06,p07,0x2D,r15; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001007E0; }

l40000000001001E0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x3F,r15; (p06) br.cond.dpnt.few	40000000001007A0; }

l40000000001001F0:
	{ cmp4.eq	p07,p06,0x0,r34; nop.m	0x0; adds	r46,0x0,r36 }
	{ addl	r34,1,r0; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000FFE60; }

l4000000000100210:
	{ nop.m	0x0; adds	r33,0x1,r45; nop.i	0x0; }
	{ adds	r45,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,decode_signal; }
	{ adds	r1,0x0,r44; nop.m	0x0; adds	r35,0x0,r8 }
	{ ld8	r32,[r32]; nop.m	0x0; nop.i	0x0; }

l4000000000100250:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p07) br.cond.dpnt.few	40000000000FFE60 }

l4000000000100260:
	{ adds	r14,0x8,r32; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r45,[r14]; ld1	r15,[r45]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r15; (p06) br.cond.dptk.few	40000000000FFE60 }

l40000000001002A0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000100140 }

l40000000001002B0:
	{ adds	r46,0x0,r37; nop.i	0x0; br.call.sptk.many	b0,legal_number; }
	{ adds	r1,0x0,r44; cmp4.eq	p07,p06,0x0,r8; (p07) br.cond.dptk.few	40000000001002F0 }

l40000000001002D0:
	{ ld8	r38,[r37]; nop.m	0x0; sxt4	r15,r38; }
	{ nop.m	0x0; cmp.eq	p06,p07,r15,r38; (p06) br.cond.dpnt.few	4000000000100600 }

l40000000001002F0:
	{ ld8	r14,[r34]; ld8	r45,[r14]; nop.i	0x0; }
	{ ld1	r14,[r45]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x25,r14; nop.m	0x0; cmp4.eq	p09,p08,0x0,r14; }
	{ (p06) addl	r15,1,r0; nop.m	0x0; (p08) addl	r14,1,r0; }

l4000000000100326:
	{ Invalid; (p07) cmp4.eq.and	p01,p08,0x0,r0; (p49) nop }

l4000000000100330:
	{ (p07) adds	r15,0x0,r0; (p09) adds	r14,0x0,r0; and	r14,r14,r15; }

l4000000000100336:
	{ Invalid; (p07) nop; break.i	0x80000 }

l400000000010033C:
	{ (p07) invala; cmp.lt	p00,p00,r32,r0; mov	pr,r99,0xE680; }
	{ (p33) cmp.lt.unc	p63,p09,r63,r37; (p05) nop; (p05) cmp.eq	p00,p16,r0,r64 }

l4000000000100350:
	{ addl	r46,964,r1; adds	r45,0x0,r0; addl	r47,5,r0; }
	{ ld8	r46,[r46]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ ld8	r14,[r34]; adds	r1,0x0,r44; adds	r45,0x0,r8; }
	{ ld8	r46,[r14]; nop.i	0x0; br.call.sptk.many	b0,builtin_error; }
	{ ld8	r32,[r32]; nop.m	0x0; adds	r1,0x0,r44; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p06) br.cond.dptk.few	40000000000FFEC0 }

l40000000001003B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000100100 }

l40000000001003C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_badpid; }
	{ ld8	r32,[r32]; nop.m	0x0; adds	r1,0x0,r44; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p06) br.cond.dptk.few	40000000000FFEC0 }

l40000000001003F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000100100 }

l4000000000100400:
	{ nop.m	0x0; ld8	r37,[r32]; nop.i	0x0; }
	{ adds	r14,0x8,r37; cmp.eq	p06,p07,0x0,r37; (p06) br.cond.dpnt.few	40000000001007F0; }

l4000000000100420:
	{ ld8	r14,[r14]; ld8	r33,[r14]; nop.i	0x0; }
	{ ld1	r14,[r33]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x30,r14; (p07) br.cond.dpnt.few	4000000000100540 }

l4000000000100450:
	{ adds	r45,0x0,r33; nop.m	0x0; adds	r46,0x0,r36 }
	{ adds	r34,0x1,r34; nop.m	0x0; br.call.sptk.many	b0,decode_signal; }
	{ adds	r1,0x0,r44; nop.m	0x0; adds	r35,0x0,r8 }
	{ ld8	r32,[r37]; nop.m	0x0; nop.i	0x0; }

l4000000000100490:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p06) br.cond.dptk.few	4000000000100260 }

l40000000001004A0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000FFE60; }

l40000000001004B0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFE,r8; (p06) br.cond.sptk.few	40000000001004F0; }

l40000000001004C0:
	{ ld8	r14,[r34]; nop.i	0x0; nop.i	0x0 }
	{ ld8	r45,[r14]; nop.m	0x0; br.call.sptk.many	b0,sh_badjob; }
	{ adds	r1,0x0,r44; nop.m	0x0; nop.i	0x0 }

l40000000001004F0:
	{ addl	r45,2,r0; nop.m	0x0; adds	r46,0x10,r12 }
	{ adds	r47,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ ld8	r32,[r32]; nop.m	0x0; adds	r1,0x0,r44; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p06) br.cond.dptk.few	40000000000FFEC0 }

l4000000000100530:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000100100 }

l4000000000100540:
	{ adds	r14,0x1,r33; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	4000000000100450; }

l4000000000100570:
	{ (p06) adds	r35,0x0,r0; nop.m	0x0; nop.i	0x0 }

l4000000000100576:
	{ break.m	0x4000; nop; nop }
	{ Invalid; nop; break.i	0x80000 }

l4000000000100590:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ ld4	r46,[r8]; adds	r1,0x0,r44; adds	r45,0x0,r34; }
	{ cmp4.eq	p07,p06,0x16,r46; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000100760; }

l40000000001005C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000FFCC0; }
	{ ld8	r32,[r32]; nop.m	0x0; adds	r1,0x0,r44; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p06) br.cond.dptk.few	40000000000FFEC0 }

l40000000001005F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000100100; }

l4000000000100600:
	{ cmp4.lt	p07,p06,0xFFFFFFFFFFFFFFFE,r38; adds	r45,0x0,r38; adds	r46,0x0,r35; }
	{ nop.m	0x0; (p06) addl	r47,1,r0; nop.i	0x0; }

l400000000010061C:
	{ cmp4.eq.or.andcm	p00,p49,r1,r0; zxt1	r0,r64; break.i	0x1000 }

l4000000000100626:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ (p03) chk.a.clr	r8,3FFFFFFFFF943636; nop; break.b	0x80000 }

l4000000000100640:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ ld4	r46,[r8]; adds	r1,0x0,r44; adds	r45,0x0,r38; }
	{ cmp4.eq	p07,p06,0x16,r46; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000100760; }

l4000000000100670:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000FFCC0; }
	{ ld8	r32,[r32]; nop.m	0x0; adds	r1,0x0,r44; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p06) br.cond.dptk.few	40000000000FFEC0 }

l40000000001006A0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000100100 }

l40000000001006B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ addl	r8,1,r0; adds	r1,0x0,r44; mov.i	ar.pfs,r43; }
	{ nop.m	0x0; mov.spnt	b0,r42,40000000001006D0; nop.i	0x0 }
	{ adds	r12,0x110,r12; nop.m	0x0; br.ret	b0; }

l40000000001006F0:
	{ adds	r45,0x0,r32; adds	r46,0x0,r0; br.call.sptk.many	b0,display_signal_list; }
	{ adds	r1,0x0,r44; mov.i	ar.pfs,r43; mov.spnt	b0,r42,4000000000100700 }
	{ nop.m	0x0; adds	r12,0x110,r12; br.ret	b0; }

l4000000000100720:
	{ adds	r45,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,sh_invalidsig; }
	{ addl	r8,1,r0; adds	r1,0x0,r44; mov.i	ar.pfs,r43; }
	{ nop.m	0x0; mov.spnt	b0,r42,4000000000100740; nop.i	0x0 }
	{ adds	r12,0x110,r12; nop.m	0x0; br.ret	b0; }

l4000000000100760:
	{ adds	r45,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,sh_invalidsig; }
	{ ld8	r32,[r32]; nop.m	0x0; adds	r1,0x0,r44; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p06) br.cond.dptk.few	40000000000FFEC0 }

l4000000000100790:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000100100 }

l40000000001007A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ adds	r8,0x0,r0; adds	r1,0x0,r44; mov.i	ar.pfs,r43; }
	{ nop.m	0x0; mov.spnt	b0,r42,40000000001007C0; nop.i	0x0 }
	{ adds	r12,0x110,r12; nop.m	0x0; br.ret	b0 }

l40000000001007E0:
	{ ld8	r32,[r32]; nop.i	0x0; br.cond.sptk.few	40000000000FFE60; }

l40000000001007F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_needarg; }
	{ addl	r8,1,r0; adds	r1,0x0,r44; mov.i	ar.pfs,r43; }
	{ nop.m	0x0; mov.spnt	b0,r42,4000000000100810; nop.i	0x0 }
	{ adds	r12,0x110,r12; nop.m	0x0; br.ret	b0; }
4000000000100830 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; let_builtin: 4000000000100840
let_builtin proc
	{ alloc	r34,ar.pfs,0x7,0x0,0x4; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r33,b1 }
	{ adds	r14,0x8,r32; adds	r35,0x0,r1; cmp.eq	p06,p07,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000100A40; }

l4000000000100870:
	{ ld8	r14,[r14]; cmp.eq	p07,p06,0x0,r14; nop.i	0x0; }
	{ ld8	r36,[r14]; nop.i	0x0; (p07) br.cond.dpnt.few	40000000001008B0; }

l4000000000100890:
	{ ld1	r14,[r36]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r14; (p07) br.cond.dpnt.few	40000000001009C0 }

l40000000001008B0:
	{ adds	r37,0x10,r12; nop.i	0x0; br.call.sptk.many	b0,evalexp; }
	{ adds	r15,0x10,r12; nop.m	0x0; adds	r1,0x0,r35; }
	{ nop.m	0x0; ld4	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	4000000000100970; }

l40000000001008F0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000100900:
	{ nop.m	0x0; ld8	r32,[r32]; nop.i	0x0; }
	{ adds	r14,0x8,r32; cmp.eq	p07,p06,0x0,r32; (p07) br.cond.dpnt.few	4000000000100990; }

l4000000000100920:
	{ ld8	r14,[r14]; nop.m	0x0; adds	r37,0x10,r12; }
	{ ld8	r36,[r14]; nop.i	0x0; br.call.sptk.many	b0,evalexp; }
	{ adds	r15,0x10,r12; nop.m	0x0; adds	r1,0x0,r35; }
	{ nop.m	0x0; ld4	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	4000000000100900 }

l4000000000100970:
	{ addl	r8,1,r0; mov.i	ar.pfs,r34; mov.spnt	b0,r33,4000000000100970 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000100990:
	{ cmp.eq	p06,p07,0x0,r8; (p06) addl	r8,1,r0; nop.i	0x0; }

l400000000010099C:
	{ Invalid; zxt1	r0,r64; (p32) break.i	0x2A808 }

l40000000001009A6:
	{ break.m	0xAA022; nop; break.i	0x80000 }
	{ Invalid; (p34) nop; (p32) nop }

l40000000001009C0:
	{ adds	r14,0x2,r36; nop.m	0x0; adds	r15,0x1,r36; }
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000001008B0 }

l40000000001009F0:
	{ ld1	r14,[r15]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r14; (p06) br.cond.dptk.few	40000000001008B0 }

l4000000000100A10:
	{ nop.m	0x0; ld8	r32,[r32]; nop.i	0x0; }
	{ adds	r14,0x8,r32; cmp.eq	p06,p07,0x0,r32; (p07) br.cond.sptk.few	4000000000100920; }

l4000000000100A30:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000100A40:
	{ addl	r37,-8444,r1; addl	r38,5,r0; adds	r36,0x0,r0; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r35; adds	r36,0x0,r8; br.call.sptk.many	b0,builtin_error; }
	{ addl	r8,1,r0; adds	r1,0x0,r35; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,4000000000100A80; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0; }
4000000000100AA0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
4000000000100AB0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; mapfile_builtin: 4000000000100AC0
mapfile_builtin proc
	{ alloc	r49,ar.pfs,0x1C,0x0,0x14; adds	r12,0xFFFFFFFFFFFFFFE0,r12; nop.b	0x0 }
	{ adds	r50,0x0,r1; nop.m	0x0; mov	r51,pr; }
	{ adds	r45,0x0,r0; addl	r37,5000,r0; mov	r48,b0 }
	{ adds	r35,0x0,r0; adds	r40,0x0,r0; br.call.sptk.many	b0,reset_internal_getopt; }
	{ adds	r1,0x0,r50; adds	r36,0x0,r0; addl	r39,1,r0 }
	{ adds	r44,0x0,r0; adds	r33,0x20,r12; addp4	r41,0xFFFFFFFFFFFFFFFF,r0; }
	{ addl	r38,-4572,r1; nop.m	0x0; addl	r34,9252,r1; }
	{ ld8	r38,[r38]; nop.m	0x0; nop.i	0x0 }
	{ addl	r53,-4612,r1; nop.m	0x0; adds	r52,0x0,r32; }
	{ ld8	r53,[r53]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r50; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dpnt.few	4000000000100D60 }

l4000000000100B70:
	{ nop.m	0x0; adds	r8,0xFFFFFFFFFFFFFFBD,r8; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x32,r8; (p07) br.cond.dptk.few	4000000000100BD0 }

l4000000000100B90:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ addl	r8,258,r0; adds	r1,0x0,r50; mov	pr,r51,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r49; mov.spnt	b0,r48,4000000000100BB0 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0 }

l4000000000100BD0:
	{ addp4	r8,r8,r0; shladd	r8,r8,0x3,r38; nop.i	0x0; }
	{ ld8	r14,[r8]; add	r8,r8,r14; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r8,4000000000100BF0; br.cond	b6; }
4000000000100C00 09 50 91 02 48 24 40 03 88 30 20 A0 06 08 01 84 .P..H$@..0 .....
4000000000100C10 11 00 00 00 01 00 00 00 00 02 00 00 78 E8 F3 58 ............x..X
4000000000100C20 11 08 00 64 00 21 60 00 20 0E 73 03 F0 0B 00 43 ...d.!`. .s....C
4000000000100C30 0A 58 01 42 18 10 60 58 01 0E 60 C0 01 58 59 00 .X.B..`X..`..XY.
4000000000100C40 19 A0 01 56 00 21 C0 02 AC 00 42 03 D0 0B 00 43 ...V.!....B....C
4000000000100C50 11 30 38 56 07 38 00 00 00 02 80 03 C0 0B 00 43 .08V.8.........C
4000000000100C60 11 00 00 00 01 00 00 00 00 02 00 00 E8 F2 F3 58 ...............X
4000000000100C70 11 08 00 64 00 21 70 00 20 0C 73 03 D0 FE FF 4A ...d.!p. .s....J
4000000000100C80 09 A8 71 FB DB 27 60 2B 00 00 48 80 06 00 00 84 ..q..'`+..H.....
4000000000100C90 11 A8 01 6A 18 10 00 00 00 02 00 00 D8 9E F1 58 ...j...........X
4000000000100CA0 11 08 00 64 00 21 10 02 20 00 42 00 A8 AB F1 58 ...d.!.. .B....X
4000000000100CB0 08 00 00 00 01 00 10 00 C8 00 42 00 00 00 04 00 ..........B.....
4000000000100CC0 19 A0 01 10 10 10 00 00 00 02 00 00 E8 A7 F1 58 ...............X
4000000000100CD0 08 08 00 64 00 21 60 03 20 00 42 00 00 00 04 00 ...d.!`. .B.....
4000000000100CE0 19 A0 01 42 00 21 50 03 AC 00 42 00 A8 C8 FE 58 ...B.!P...B....X
4000000000100CF0 09 40 04 00 00 24 10 00 C8 00 42 E0 3F 83 7F 0B .@...$....B.?...
4000000000100D00 02 00 00 00 01 00 00 88 01 55 00 00 00 0B 00 07 .........U......
4000000000100D10 18 00 00 00 01 00 C0 00 31 00 42 80 08 00 84 00 ........1.B.....
4000000000100D20 09 A8 F1 FB DB 27 40 03 80 00 42 E0 24 38 B9 80 .....'@...B.$8..
4000000000100D30 11 A8 01 6A 18 10 00 00 00 02 00 00 98 97 01 50 ...j...........P
4000000000100D40 11 08 00 64 00 21 70 F8 23 0C 77 03 30 FE FF 4A ...d.!p.#.w.0..J
4000000000100D50 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

l4000000000100D60:
	{ addl	r14,9268,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; adds	r14,0x8,r14; (p06) br.cond.dpnt.few	4000000000101900; }

l4000000000100D90:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001018B0; }

l4000000000100DB0:
	{ nop.m	0x0; ld8	r33,[r14]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r33; adds	r52,0x0,r33; (p07) br.cond.dpnt.few	40000000001018B0; }

l4000000000100DD0:
	{ ld1	r14,[r33]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000101410; }

l4000000000100DF0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,legal_identifier; }
	{ adds	r1,0x0,r50; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	4000000000101120 }

l4000000000100E10:
	{ adds	r52,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,valid_array_reference; }
	{ adds	r1,0x0,r50; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	4000000000101120 }

l4000000000100E30:
	{ adds	r52,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,sh_invalidid; }
	{ addl	r8,1,r0; adds	r1,0x0,r50; mov	pr,r51,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r49; mov.spnt	b0,r48,4000000000100E50 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0 }
4000000000100E70 09 50 91 02 48 24 40 03 88 30 20 A0 06 08 01 84 .P..H$@..0 .....
4000000000100E80 11 00 00 00 01 00 00 00 00 02 00 00 08 E6 F3 58 ...............X
4000000000100E90 11 08 00 64 00 21 60 00 20 0E 73 03 50 00 00 43 ...d.!`. .s.P..C
4000000000100EA0 09 00 00 00 01 00 30 02 84 30 20 00 00 00 04 00 ......0..0 .....
4000000000100EB0 11 30 8C 00 07 30 E0 48 8D 18 40 03 30 00 00 43 .0...0.H..@.0..C
4000000000100EC0 11 00 00 00 01 00 60 70 8C 0E 70 03 80 FC FF 4A ......`p..p....J
4000000000100ED0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000100EE0 09 00 00 00 01 00 50 23 F7 B7 4F 00 00 00 04 00 ......P#..O.....
4000000000100EF0 08 A8 01 6A 18 10 00 00 00 02 00 00 00 00 04 00 ...j............
4000000000100F00 11 B0 15 00 00 24 40 03 00 00 42 00 68 9C F1 58 .....$@...B.h..X
4000000000100F10 08 08 00 64 00 21 00 00 00 02 00 80 06 40 00 84 ...d.!.......@..
4000000000100F20 19 A8 01 54 18 10 00 00 00 02 00 00 68 C6 FE 58 ...T........h..X
4000000000100F30 08 00 00 00 01 00 10 00 C8 00 42 00 11 00 00 90 ..........B.....
4000000000100F40 01 00 00 00 01 00 F0 9F C1 BF 05 00 00 00 04 00 ................
4000000000100F50 02 00 00 00 01 00 00 88 01 55 00 00 00 0B 00 07 .........U......
4000000000100F60 18 00 00 00 01 00 C0 00 31 00 42 80 08 00 84 00 ........1.B.....
4000000000100F70 09 50 91 02 48 24 40 03 88 30 20 A0 06 08 01 84 .P..H$@..0 .....
4000000000100F80 11 00 00 00 01 00 00 00 00 02 00 00 08 E5 F3 58 ...............X
4000000000100F90 11 08 00 64 00 21 60 00 20 0E 73 03 50 FF FF 4B ...d.!`. .s.P..K
4000000000100FA0 09 00 00 00 01 00 40 02 84 30 20 00 00 00 04 00 ......@..0 .....
4000000000100FB0 11 30 90 00 07 30 E0 48 91 18 40 03 30 FF FF 4B .0...0.H..@.0..K
4000000000100FC0 10 00 00 00 01 00 60 70 90 0E 70 03 80 FB FF 4A ......`p..p....J
4000000000100FD0 09 00 00 00 01 00 50 23 F7 B7 4F 00 00 00 04 00 ......P#..O.....
4000000000100FE0 11 A8 01 6A 18 10 00 00 00 02 00 00 20 FF FF 48 ...j........ ..H
4000000000100FF0 09 50 91 02 48 24 40 03 88 30 20 A0 06 08 01 84 .P..H$@..0 .....
4000000000101000 11 00 00 00 01 00 00 00 00 02 00 00 88 E4 F3 58 ...............X
4000000000101010 11 08 00 64 00 21 60 00 20 0E 73 03 40 00 00 43 ...d.!`. .s.@..C
4000000000101020 09 00 00 00 01 00 50 02 84 30 20 00 00 00 04 00 ......P..0 .....
4000000000101030 11 38 00 4A 06 31 E0 48 95 18 40 03 20 00 00 43 .8.J.1.H..@. ..C
4000000000101040 10 00 00 00 01 00 60 70 94 0E 70 03 00 FB FF 4A ......`p..p....J
4000000000101050 09 A8 D1 FB DB 27 60 2B 00 00 48 80 06 00 00 84 .....'`+..H.....
4000000000101060 11 A8 01 6A 18 10 00 00 00 02 00 00 08 9B F1 58 ...j...........X
4000000000101070 08 08 00 64 00 21 00 00 00 02 00 80 06 40 00 84 ...d.!.......@..
4000000000101080 19 A8 01 54 18 10 00 00 00 02 00 00 08 C5 FE 58 ...T...........X
4000000000101090 11 08 00 64 00 21 80 08 00 00 48 00 B0 FE FF 48 ...d.!....H....H
40000000001010A0 08 50 91 02 48 24 40 03 88 30 20 A0 06 08 01 84 .P..H$@..0 .....
40000000001010B0 09 00 00 00 01 00 70 F2 9F 58 44 00 00 00 04 00 ......p..XD.....
40000000001010C0 11 00 00 00 01 00 00 00 00 02 00 00 C8 E3 F3 58 ...............X
40000000001010D0 11 08 00 64 00 21 60 00 20 0E 73 03 F0 06 00 43 ...d.!`. .s....C
40000000001010E0 09 00 00 00 01 00 80 02 84 30 20 00 00 00 04 00 .........0 .....
40000000001010F0 11 30 A0 00 07 30 E0 48 A1 18 40 03 D0 06 00 43 .0...0.H..@....C
4000000000101100 12 30 38 50 07 F8 01 60 03 80 21 00 40 FA FF 48 .08P...`..!.@..H
4000000000101110 10 68 01 44 18 10 00 00 00 02 00 00 30 FA FF 48 .h.D........0..H

l4000000000101120:
	{ adds	r14,0x10,r12; nop.m	0x0; adds	r34,0x18,r12 }
	{ adds	r52,0x0,r33; addl	r53,1,r0; nop.i	0x0 }
	{ st8	[r0],r14; st8	[r0],r34; br.call.sptk.many	b0,find_or_make_array_variable; }
	{ adds	r14,0x28,r8; adds	r1,0x0,r50; cmp.eq	p06,p07,0x0,r8 }
	{ addl	r16,16386,r0; adds	r41,0x0,r8; (p06) br.cond.dpnt.few	4000000000101470; }

l4000000000101170:
	{ ld8	r15,[r14]; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; and	r15,r15,r16; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r15; (p07) br.cond.dptk.few	4000000000101860; }

l40000000001011A0:
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x2; adds	r52,0x0,r44 }
	{ adds	r53,0x0,r0; addl	r54,1,r0; (p07) br.cond.dpnt.few	4000000000101940; }

l40000000001011C0:
	{ nop.m	0x0; tbit.z	p06,p07,r39,0x0; (p07) br.cond.dpnt.few	40000000001016F0; }

l40000000001011D0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AA20; }
	{ nop.m	0x0; cmp.lt	p07,p06,r8,r0; adds	r1,0x0,r50 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000101750; }

l4000000000101200:
	{ (p06) adds	r38,0x0,r0; nop.m	0x0; nop.i	0x0 }

l4000000000101206:
	{ break.m	0x4000; nop; break.i	0x80000 }

l4000000000101210:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,zreset; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; adds	r1,0x0,r50 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	40000000001012B0; }

l4000000000101240:
	{ (p06) adds	r33,0x0,r0; nop.m	0x0; nop.i	0x0; }

l4000000000101246:
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ break.m	0x4000; nop; nop }

l4000000000101260:
	{ adds	r52,0x0,r44; adds	r53,0x0,r34; adds	r54,0x10,r12 }

l4000000000101262:
	{ chk.a.clr	r11,3FFFFFFFFF509662; Invalid; (p02) nop; }
	{ (p32) nop; (p16) nop; (p63) nop; }
	{ (p01) break.m	0x600E0; nop; Invalid }
	{ (p32) break.m	0x4200C; dep	r32,r0,r64,63,2; Invalid }

l40000000001012A0:
	{ nop.m	0x0; cmp.lt	p06,p07,r14,r35; (p06) br.cond.dptk.few	4000000000101260; }

l40000000001012B0:
	{ addl	r47,7672,r1; adds	r14,0x10,r12; cmp.eq	p07,p06,0x0,r45 }
	{ st8	[r0],r34; addl	r33,1,r0; cmp4.eq	p18,p19,0x0,r38; }
	{ nop.m	0x0; st8	[r0],r14; tnat.z	p21,p20,r39 }
	{ (p06) addl	r42,1,r0; cmp.eq	p16,p17,0x0,r36; (p07) adds	r42,0x0,r0; }

l40000000001012E6:
	{ (p08) chk.a.clr	f0,3FFFFFFFFFD89D26; (p21) mov.sptk	b0,r0,40000000001013E6; (p32) nop }

l40000000001012F0:
	{ ld4	r14,[r47]; nop.i	0x0; adds	r14,0x1,r14; }
	{ st4	[r14],r47; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000101320:
	{ adds	r52,0x0,r44; adds	r53,0x0,r34; nop.i	0x0 }
	{ adds	r54,0x10,r12; adds	r55,0x0,r38; br.call.sptk.many	b0,zgetline; }
	{ adds	r1,0x0,r50; cmp.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dpnt.few	4000000000101640; }

l4000000000101350:
	{ ld8	r35,[r34]; nop.i	0x0; (p20) br.cond.dpnt.few	40000000001014A0 }

l4000000000101360:
	{ cmp4.eq	p07,p06,0x0,r33; (p06) addl	r14,1,r0; nop.i	0x0; }

l400000000010136C:
	{ cmp4.eq.and	p00,p43,r1,r0; (p01) cmp.lt	p00,p16,r0,r64; zxt1	r74,r3 }

l4000000000101376:
	{ Invalid; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFDC4C66; nop; nop }

l4000000000101390:
	{ addp4	r52,r33,r0; adds	r53,0x0,r37; br.call.sptk.many	b0,fn4000000000137A00; }
	{ adds	r1,0x0,r50; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	4000000000101510 }

l40000000001013B0:
	{ adds	r52,0x0,r41; addp4	r53,r40,r0; adds	r54,0x0,r35 }
	{ adds	r55,0x0,r0; adds	r33,0x1,r33; br.call.sptk.many	b0,bind_array_element; }
	{ nop.m	0x0; adds	r1,0x0,r50; (p16) br.cond.dptk.few	4000000000101400 }

l40000000001013E0:
	{ nop.m	0x0; addp4	r14,r33,r0; nop.i	0x0; }
	{ nop.m	0x0; cmp.lt	p07,p06,r36,r14; (p07) br.cond.dpnt.few	4000000000101640 }

l4000000000101400:
	{ nop.m	0x0; adds	r40,0x1,r40; br.cond.sptk.few	4000000000101320 }

l4000000000101410:
	{ addl	r53,-4596,r1; addl	r54,5,r0; adds	r52,0x0,r0; }
	{ ld8	r53,[r53]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r50; adds	r52,0x0,r8; br.call.sptk.many	b0,builtin_error; }
	{ addl	r8,258,r0; adds	r1,0x0,r50; mov	pr,r51,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r49; mov.spnt	b0,r48,4000000000101450 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0 }

l4000000000101470:
	{ addl	r8,1,r0; mov	pr,r51,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r49; }
	{ nop.m	0x0; mov.spnt	b0,r48,4000000000101480; nop.i	0x0 }
	{ adds	r12,0x20,r12; nop.m	0x0; br.ret	b0; }

l40000000001014A0:
	{ adds	r52,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r50; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	4000000000101360; }

l40000000001014C0:
	{ nop.m	0x0; sxt4	r14,r8; adds	r14,0xFFFFFFFFFFFFFFFF,r14; }
	{ add	r14,r35,r14; ld1	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; cmp4.eq	p07,p06,0xA,r15; }
	{ nop.m	0x0; (p07) st1	[r0],r14; nop.i	0x0; }

l40000000001014FC:
	{ setf.s	f0,r1; Invalid; break.i	0x1000 }

l4000000000101506:
	{ break.m	0x4000; nop; nop }

l4000000000101510:
	{ adds	r52,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,sh_single_quote; }
	{ adds	r1,0x0,r50; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r52,0x0,r45; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r43,0x0,r8; nop.m	0x0; adds	r1,0x0,r50 }
	{ adds	r52,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ add	r8,r8,r43; adds	r1,0x0,r50; adds	r46,0xD,r8; }
	{ nop.m	0x0; addp4	r46,r46,r0; nop.i	0x0; }
	{ adds	r52,0x0,r46; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r50; adds	r59,0x0,r35; addl	r55,-1,r0 }
	{ adds	r57,0x0,r45; adds	r58,0x0,r40; adds	r53,0x0,r46; }
	{ addl	r56,-4580,r1; nop.m	0x0; adds	r43,0x0,r8 }
	{ addl	r54,1,r0; nop.m	0x0; adds	r52,0x0,r8; }
	{ ld8	r56,[r56]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A3E0; }
	{ adds	r1,0x0,r50; adds	r52,0x0,r35; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r52,0x0,r43; adds	r1,0x0,r50; nop.i	0x0 }
	{ adds	r53,0x0,r0; addl	r54,4,r0; br.call.sptk.many	b0,parse_and_execute; }
	{ adds	r1,0x0,r50; (p18) adds	r52,0x0,r44; (p18) br.call.dpnt.many	b0,zsyncfd; }

l400000000010161C:
	{ (p31) nop; nop; epc }

l4000000000101620:
	{ nop.m	0x0; (p18) adds	r1,0x0,r50; nop.i	0x0 }

l400000000010162C:
	{ ldfd	f0,[r0]; Invalid; break.i	0x1000 }
	{ (p44) shladd	r127,r63,0x2,r36; Invalid; break.i	0x1000 }

l4000000000101640:
	{ ld8	r52,[r34]; nop.i	0x0; br.call.sptk.many	b0,xfree; }
	{ adds	r1,0x0,r50; adds	r8,0x0,r0; (p18) br.cond.dpnt.few	40000000001016B0; }

l4000000000101660:
	{ ld4	r14,[r47]; nop.i	0x0; adds	r14,0xFFFFFFFFFFFFFFFF,r14; }
	{ st4	[r14],r47; nop.m	0x0; nop.i	0x0 }

l4000000000101680:
	{ nop.m	0x0; mov	pr,r51,0xFFFFFFFFFFFFFFFE; nop.i	0x0; }
	{ nop.m	0x0; mov.i	ar.pfs,r49; mov.spnt	b0,r48,4000000000101690 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0; }

l40000000001016B0:
	{ adds	r52,0x0,r44; nop.i	0x0; br.call.sptk.many	b0,zsyncfd; }
	{ ld4	r14,[r47]; adds	r1,0x0,r50; adds	r8,0x0,r0; }
	{ nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; }
	{ st4	[r14],r47; nop.i	0x0; br.cond.sptk.few	4000000000101680 }

l40000000001016F0:
	{ nop.m	0x0; adds	r14,0x8,r8; nop.i	0x0; }
	{ ld8	r52,[r14]; nop.i	0x0; br.call.sptk.many	b0,array_flush; }
	{ adds	r1,0x0,r50; adds	r52,0x0,r44; nop.i	0x0 }
	{ adds	r53,0x0,r0; addl	r54,1,r0; br.call.sptk.many	b0,fn400000000001AA20; }
	{ cmp.lt	p07,p06,r8,r0; nop.m	0x0; adds	r1,0x0,r50; }
	{ nop.m	0x0; (p06) adds	r38,0x0,r0; (p06) br.cond.dptk.few	4000000000101210 }

l400000000010174C:
	{ Invalid; break.i	0x1000; break.b	0x1000 }

l4000000000101750:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ ld4	r38,[r8]; adds	r1,0x0,r50; cmp4.eq	p06,p07,0x1D,r38; }
	{ nop.m	0x0; (p06) addl	r38,1,r0; nop.i	0x0; }

l400000000010177C:
	{ cmp4.eq.and	p00,p49,r1,r0; zxt1	r0,r64; break.i	0x1000 }

l4000000000101786:
	{ break.m	0x4000; (p32) nop; (p48) nop }
	{ add	r0,r0,r1; nop; add	r0,r0,r32 }
	{ (p16) chk.a.clr	r0,3FFFFFFFFF1817A6; nop; break.b	0x80000; }

l40000000001017AC:
	{ (p22) invala; break.i	0x1000; break.i	0x1000 }

l40000000001017B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000001012B0 }
40000000001017C0 09 A8 B1 FB DB 27 60 2B 00 00 48 80 06 00 00 84 .....'`+..H.....
40000000001017D0 11 A8 01 6A 18 10 00 00 00 02 00 00 98 93 F1 58 ...j...........X
40000000001017E0 08 08 00 64 00 21 00 00 00 02 00 80 06 40 00 84 ...d.!.......@..
40000000001017F0 19 A8 01 54 18 10 00 00 00 02 00 00 98 BD FE 58 ...T...........X
4000000000101800 11 08 00 64 00 21 80 08 00 00 48 00 40 F7 FF 48 ...d.!....H.@..H
4000000000101810 09 A8 51 FB DB 27 60 2B 00 00 48 80 06 00 00 84 ..Q..'`+..H.....
4000000000101820 11 A8 01 6A 18 10 00 00 00 02 00 00 48 93 F1 58 ...j........H..X
4000000000101830 08 08 00 64 00 21 00 00 00 02 00 80 06 40 00 84 ...d.!.......@..
4000000000101840 19 A8 01 54 18 10 00 00 00 02 00 00 48 BD FE 58 ...T........H..X
4000000000101850 10 08 00 64 00 21 80 08 00 00 48 00 F0 F6 FF 48 ...d.!....H....H

l4000000000101860:
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x1; (p06) br.cond.dptk.few	4000000000101470 }

l4000000000101870:
	{ adds	r52,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,err_readonly; }
	{ addl	r8,1,r0; adds	r1,0x0,r50; mov	pr,r51,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r49; mov.spnt	b0,r48,4000000000101890 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0 }

l40000000001018B0:
	{ nop.m	0x0; addl	r52,-4604,r1; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,builtin_error; }
	{ addl	r8,1,r0; adds	r1,0x0,r50; mov	pr,r51,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r49; mov.spnt	b0,r48,40000000001018E0 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0 }

l4000000000101900:
	{ addl	r33,-4660,r1; ld8	r33,[r33]; nop.i	0x0; }
	{ adds	r52,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,legal_identifier; }
	{ adds	r1,0x0,r50; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	4000000000101120 }

l4000000000101930:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000100E10; }

l4000000000101940:
	{ addl	r53,-4588,r1; addl	r54,5,r0; adds	r52,0x0,r0; }
	{ ld8	r53,[r53]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r50; nop.m	0x0; adds	r52,0x0,r8 }
	{ adds	r53,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,builtin_error; }
	{ addl	r8,1,r0; adds	r1,0x0,r50; mov	pr,r51,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r49; mov.spnt	b0,r48,4000000000101990 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0; }
40000000001019B0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; fn40000000001019C0: 40000000001019C0
;;   Called from:
;;     4000000000102F3C (in popd_builtin)
;;     4000000000102FEC (in fn4000000000102FC0)
fn40000000001019C0 proc
	{ alloc	r36,ar.pfs,0x8,0x0,0x6; nop.m	0x0; mov	r35,b3 }
	{ adds	r37,0x0,r1; nop.m	0x0; adds	r38,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,make_word; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r39,0x0,r0 }
	{ adds	r38,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,make_word_list; }
	{ adds	r1,0x0,r37; adds	r33,0x0,r8; addl	r38,588,r1; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,make_word; }
	{ adds	r39,0x0,r33; nop.m	0x0; adds	r1,0x0,r37 }
	{ adds	r38,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,make_word_list; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r33,0x0,r8 }
	{ adds	r38,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,cd_builtin; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r34,0x0,r8 }
	{ adds	r38,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,dispose_words; }
	{ adds	r8,0x0,r34; adds	r1,0x0,r37; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,4000000000101AA0; br.ret	b0; }
4000000000101AB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000101AC0: 4000000000101AC0
;;   Called from:
;;     4000000000101E5C (in dirs_builtin)
;;     4000000000103C4C (in get_dirstack_from_string)
;;     4000000000103DAC (in set_dirstack_element)
fn4000000000101AC0 proc
	{ cmp4.lt	p07,p06,0x0,r33; cmp.eq	p08,p09,0x0,r34; (p08) br.cond.dpnt.few	4000000000101AF0; }

l4000000000101AD0:
	{ (p06) addl	r14,2,r0; nop.i	0x0; (p07) addl	r14,1,r0; }

l4000000000101AD6:
	{ chk.a.nc	f0,3FFFFFFFFF1022D6; (p07) nop; nop }

l4000000000101AE0:
	{ st4	[r14],r34; nop.m	0x0; nop.i	0x0 }

l4000000000101AF0:
	{ cmp4.lt	p10,p11,0x0,r33; cmp.eq	p06,p07,0x0,r32; addl	r14,8428,r1; }
	{ (p10) addl	r33,1,r0; (p11) adds	r33,0x0,r0; nop.i	0x0; }

l4000000000101B06:
	{ Invalid; nop.b	0x4000; break.b	0x80000 }

l4000000000101B0C:
	{ Invalid; cmp.eq	p00,p00,r32,r0; mov	pr,r72,0x5940 }
	{ Invalid; Invalid; Invalid }

l4000000000101B20:
	{ ld4	r8,[r14]; nop.m	0x0; sxt4	r14,r8; }
	{ cmp.eq	p07,p06,r14,r32; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000101B90; }

l4000000000101B40:
	{ cmp.lt	p06,p07,r32,r0; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000101BC0; }

l4000000000101B50:
	{ cmp.lt	p06,p07,r14,r32; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000101BC0; }

l4000000000101B60:
	{ cmp4.eq	p06,p07,0x0,r33; (p07) sub	r8,r8,r32; nop.i	0x0; }

l4000000000101B6C:
	{ Invalid; mov	pr,r32,0x0; (p01) shladd	r0,r8,0x1,r64 }

l4000000000101B7C:
	{ Invalid; break.m	0x1000; (p01) shladd	r0,r0,0x1,r64 }

l4000000000101B80:
	{ nop.m	0x0; adds	r8,0x0,r0; br.ret	b0; }

l4000000000101B90:
	{ cmp4.eq	p06,p07,0x0,r33; adds	r8,0x0,r0; (p08) br.cond.dpnt.few	4000000000101B80; }

l4000000000101BA0:
	{ (p06) addl	r33,1,r0; (p07) addl	r33,2,r0; nop.i	0x0; }

l4000000000101BA6:
	{ Invalid; nop; br.call.spnt.few	b0,b0; }

l4000000000101BAC:
	{ Invalid; Invalid; add	r0,r32,r0 }
	{ Invalid; break.m	0x1000; (p49) shladd	r31,r127,0x4,r127 }

l4000000000101BC0:
	{ nop.m	0x0; addl	r8,-1,r0; br.ret	b0; }
4000000000101BD0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000101BE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000101BF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000101C00: 4000000000101C00
;;   Called from:
;;     400000000010263C (in dirs_builtin)
;;     4000000000102AAC (in popd_builtin)
;;     400000000010354C (in pushd_builtin)
fn4000000000101C00 proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; cmp4.eq	p07,p06,0x0,r32; nop.b	0x0 }
	{ addl	r38,604,r1; mov	r34,b2; adds	r36,0x0,r1; }
	{ addl	r39,5,r0; adds	r37,0x0,r0; (p07) br.cond.dpnt.few	4000000000101C80; }

l4000000000101C30:
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r37,0x0,r33 }
	{ adds	r38,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,sh_erange; }
	{ adds	r1,0x0,r36; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000101C70; br.ret	b0 }

l4000000000101C80:
	{ addl	r38,596,r1; nop.m	0x0; adds	r37,0x0,r0; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; adds	r37,0x0,r8; br.call.sptk.many	b0,builtin_error; }
	{ adds	r1,0x0,r36; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000101CC0; br.ret	b0; }
4000000000101CD0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000101CE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000101CF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; dirs_builtin: 4000000000101D00
;;   Called from:
;;     4000000000102DAC (in popd_builtin)
;;     4000000000102E7C (in popd_builtin)
;;     400000000010301C (in fn4000000000102FC0)
;;     400000000010377C (in pushd_builtin)
;;     4000000000103A9C (in pushd_builtin)
dirs_builtin proc
	{ alloc	r39,ar.pfs,0xF,0x0,0xB; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ addl	r34,612,r1; mov	r41,pr; adds	r40,0x0,r1; }
	{ adds	r35,0x18,r12; adds	r37,0x0,r0; addl	r8,-1,r0 }
	{ ld8	r34,[r34]; adds	r36,0x0,r0; cmp.eq	p06,p07,0x0,r32; }
	{ nop.m	0x0; mov	r42,LC; nop.i	0x0 }
	{ st4	[r0],r35; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; mov	r38,b6; (p06) br.cond.dpnt.few	4000000000102250; }

l4000000000101D70:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000101D80:
	{ adds	r33,0x8,r32; ld8	r14,[r33]; nop.i	0x0; }
	{ ld8	r43,[r14]; adds	r16,0x1,r43; nop.i	0x0; }
	{ ld1	r15,[r43]; nop.m	0x0; sxt1	r15,r15; }
	{ cmp4.eq	p07,p06,0x2D,r15; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000102020; }

l4000000000101DC0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2B,r15; (p06) br.cond.dpnt.few	40000000001021F0 }

l4000000000101DD0:
	{ adds	r34,0x0,r16; nop.m	0x0; adds	r44,0x10,r12 }
	{ adds	r43,0x0,r16; nop.m	0x0; br.call.sptk.many	b0,legal_number; }
	{ nop.m	0x0; adds	r1,0x0,r40; nop.i	0x0 }
	{ ld8	r14,[r33]; cmp4.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	4000000000102100; }

l4000000000101E10:
	{ ld8	r14,[r14]; adds	r15,0x10,r12; adds	r45,0x0,r35; }
	{ ld8	r43,[r15]; ld1	r44,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r44,r44; cmp4.eq	p07,p06,0x2B,r44; }
	{ nop.m	0x0; (p06) addl	r44,-1,r0; nop.i	0x0; }

l4000000000101E4C:
	{ Invalid; nop; zxt4	r0,r0 }

l4000000000101E5C:
	{ (p35) nop; invala; break.b	0x1000 }
	{ nop; break.i	0x1000; Invalid }

l4000000000101E70:
	{ nop.m	0x0; ld8	r32,[r32]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p06) br.cond.dptk.few	4000000000101D80; }

l4000000000101E90:
	{ nop.m	0x0; tbit.z	p07,p06,r36,0x3; (p06) br.cond.dpnt.few	4000000000102570; }

l4000000000101EA0:
	{ ld4	r14,[r35]; nop.m	0x0; addl	r15,8428,r1; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000102260; }

l4000000000101EC0:
	{ cmp4.lt	p07,p06,r8,r0; (p07) addl	r14,8428,r1; nop.i	0x0; }

l4000000000101ECC:
	{ setf.s	f0,r1; Invalid; mov	pr,r32,0x0 }

l4000000000101ED6:
	{ chk.a.nc	f0,3FFFFFFFFF1026D6; nop; break.i	0x80000 }

l4000000000101EE0:
	{ nop.m	0x0; ld4	r43,[r15]; nop.i	0x0; }
	{ cmp4.lt	p07,p06,r43,r8; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000102630; }

l4000000000101F00:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x1,r14; (p07) br.cond.dpnt.few	4000000000102510; }

l4000000000101F10:
	{ nop.m	0x0; tbit.z	p07,p06,r37,0x1; (p07) br.cond.dptk.few	4000000000102680; }

l4000000000101F20:
	{ addl	r14,8436,r1; sub	r33,r43,r8; tbit.z	p06,p07,r36,0x2 }
	{ addl	r44,652,r1; addl	r43,1,r0; sxt4	r8,r8; }
	{ ld8	r14,[r14]; nop.m	0x0; adds	r45,0x0,r33; }
	{ shladd	r14,r8,0x3,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001027E0; }

l4000000000101F60:
	{ nop.m	0x0; (p07) ld8	r46,[r14]; nop.i	0x0 }

l4000000000101F6C:
	{ shladdp4	r0,r1,0x2,r0; Invalid; break.i	0x1000 }
	{ (p32) nop; invala; break.b	0x1000 }
	{ cmp.lt	p00,p09,r1,r0; Invalid; nop }

l4000000000101F90:
	{ addl	r14,-10260,r1; nop.m	0x0; addl	r43,10,r0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r44,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AEC0; }
	{ nop.m	0x0; adds	r1,0x0,r40; adds	r43,0x0,r0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,sh_chkwrite; }
	{ adds	r1,0x0,r40; nop.m	0x0; nop.i	0x0 }

l4000000000101FF0:
	{ nop.m	0x0; mov	pr,r41,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.i	LC,r42; mov.spnt	b0,r38,4000000000102000 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000102020:
	{ adds	r15,0x2,r43; nop.m	0x0; adds	r16,0x1,r43; }
	{ ld1	r15,[r15]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	4000000000101DD0 }

l4000000000102050:
	{ ld1	r14,[r16]; nop.m	0x0; adds	r44,0x10,r12; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x6C,r14; }
	{ (p07) or	r36,0x4,r36; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000101E70; }

l4000000000102076:
	{ chk.a.nc	f0,3FFFFFFFFF102876; nop; (p32) nop }

l4000000000102080:
	{ cmp4.eq	p06,p07,0x63,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000102160; }

l4000000000102090:
	{ cmp4.eq	p06,p07,0x76,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000102190; }

l40000000001020A0:
	{ cmp4.eq	p06,p07,0x70,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001021C0; }

l40000000001020B0:
	{ cmp4.eq	p06,p07,0x2D,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000101E90; }

l40000000001020C0:
	{ adds	r34,0x0,r16; adds	r43,0x0,r16; br.call.sptk.many	b0,legal_number; }
	{ nop.m	0x0; adds	r1,0x0,r40; nop.i	0x0 }
	{ ld8	r14,[r33]; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	4000000000101E10; }

l40000000001020F0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000102100:
	{ ld8	r43,[r14]; nop.i	0x0; br.call.sptk.many	b0,sh_invalidnum; }
	{ adds	r1,0x0,r40; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ addl	r8,1,r0; adds	r1,0x0,r40; mov	pr,r41,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r39; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r42; mov.spnt	b0,r38,4000000000102140 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000102160:
	{ ld8	r32,[r32]; nop.m	0x0; or	r36,0x8,r36; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p06) br.cond.dptk.few	4000000000101D80 }

l4000000000102180:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000101E90 }

l4000000000102190:
	{ ld8	r32,[r32]; nop.m	0x0; or	r37,0x2,r37; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p06) br.cond.dptk.few	4000000000101D80 }

l40000000001021B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000101E90 }

l40000000001021C0:
	{ ld8	r32,[r32]; nop.m	0x0; or	r37,0x1,r37; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p06) br.cond.dptk.few	4000000000101D80 }

l40000000001021E0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000101E90 }

l40000000001021F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_invalidopt; }
	{ adds	r1,0x0,r40; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ addl	r8,1,r0; adds	r1,0x0,r40; mov	pr,r41,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r39; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r42; mov.spnt	b0,r38,4000000000102230 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000102250:
	{ nop.m	0x0; adds	r37,0x0,r0; adds	r36,0x0,r0; }

l4000000000102260:
	{ nop.m	0x0; addl	r43,636,r1; nop.i	0x0; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,get_working_directory; }
	{ nop.m	0x0; adds	r33,0x0,r8; adds	r1,0x0,r40 }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	40000000001028D0; }

l40000000001022A0:
	{ and	r36,0x4,r36; tbit.z	p06,p07,r37,0x1; (p06) br.cond.dptk.few	4000000000102740; }

l40000000001022B0:
	{ cmp.eq	p07,p06,0x0,r36; addl	r44,652,r1; nop.i	0x0 }
	{ addl	r43,1,r0; adds	r45,0x0,r0; (p07) br.cond.dpnt.few	4000000000102880; }

l40000000001022D0:
	{ nop.m	0x0; (p06) adds	r46,0x0,r33; nop.i	0x0 }

l40000000001022DC:
	{ shladdp4	r0,r1,0x2,r0; Invalid; break.i	0x1000 }
	{ (p05) nop; invala; break.i	0x1000 }
	{ ldf8	f0,[r0]; zxt1	r32,r64; nop }

l4000000000102300:
	{ adds	r43,0x0,r33; nop.m	0x0; cmp4.lt	p17,p16,0x1,r37 }
	{ cmp.eq	p18,p19,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r40; ld4	r14,[r35]; adds	r15,0x10,r12; }
	{ addl	r35,8428,r1; nop.m	0x0; cmp4.eq	p06,p07,0x0,r14 }
	{ addl	r34,8436,r1; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000101F90; }

l4000000000102350:
	{ ld4	r14,[r35]; adds	r14,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r14,r14; cmp.lt	p07,p06,r14,r0 }
	{ st8	[r14],r15; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000101F90; }

l4000000000102380:
	{ nop.m	0x0; tbit.z	p06,p07,r37,0x0; (p06) addl	r37,628,r1; }

l4000000000102390:
	{ (p07) addl	r37,620,r1; (p06) ld8	r37,[r37]; nop.i	0x0; }

l4000000000102396:
	{ (p18) fwb; cmp4.eq	p00,p00,r0,r1; (p17) br.call.sptk.few	b1,b0; }

l400000000010239C:
	{ nop; Invalid; break.i	0x101000 }

l40000000001023A6:
	{ nop; nop; break.i	0x80000 }

l40000000001023B0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000001023C0:
	{ ld4	r15,[r35]; nop.i	0x0; sub	r33,r15,r14 }
	{ ld8	r15,[r34]; shladd	r14,r14,0x3,r15; nop.i	0x0; }
	{ (p19) ld8	r46,[r14]; (p18) ld8	r43,[r14]; nop.i	0x0; }

l40000000001023E6:
	{ Invalid; Invalid; Invalid }

l40000000001023EC:
	{ Invalid; break.i	0x1000; chk.s.i	r32,3FFFFFFFFF1023EC }
	{ (p24) nop; invala; Invalid }

l4000000000102400:
	{ (p18) adds	r1,0x0,r40; nop.m	0x0; (p18) adds	r46,0x0,r8 }

l4000000000102406:
	{ nop; (p23) mov.sptk	b0,r8,4000000000102506; (p48) nop }

l4000000000102410:
	{ addl	r43,1,r0; adds	r45,0x0,r33; addl	r44,668,r1; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r15,0x10,r12; nop.m	0x0; adds	r1,0x0,r40; }
	{ ld8	r14,[r15]; adds	r14,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; }
	{ st8	[r14],r15; cmp.lt	p07,p06,r14,r0; (p07) br.cond.dpnt.few	4000000000101F90 }

l4000000000102460:
	{ nop.m	0x0; nop.i	0x0; (p17) br.cond.dptk.few	40000000001023C0 }

l4000000000102470:
	{ ld8	r15,[r34]; shladd	r14,r14,0x3,r15; nop.i	0x0; }
	{ (p19) ld8	r46,[r14]; (p18) ld8	r43,[r14]; nop.i	0x0; }

l4000000000102486:
	{ Invalid; Invalid; Invalid }

l400000000010248C:
	{ Invalid; break.i	0x1000; chk.s.i	r32,3FFFFFFFFF10248C }
	{ (p19) nop; invala; Invalid }

l40000000001024A0:
	{ (p18) adds	r1,0x0,r40; nop.m	0x0; (p18) adds	r46,0x0,r8 }

l40000000001024A6:
	{ nop; (p23) mov.sptk	b0,r8,40000000001025A6; (p48) nop }

l40000000001024B0:
	{ addl	r43,1,r0; adds	r45,0x0,r37; addl	r44,676,r1; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r15,0x10,r12; nop.m	0x0; adds	r1,0x0,r40; }
	{ ld8	r14,[r15]; adds	r14,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; }
	{ st8	[r14],r15; cmp.lt	p07,p06,r14,r0; (p06) br.cond.dptk.few	4000000000102460 }

l4000000000102500:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000101F90; }

l4000000000102510:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	4000000000101F10 }

l4000000000102520:
	{ nop.m	0x0; addl	r43,636,r1; nop.i	0x0; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,get_working_directory; }
	{ nop.m	0x0; adds	r1,0x0,r40; adds	r33,0x0,r8 }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000001022A0 }

l4000000000102560:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000001028D0; }

l4000000000102570:
	{ addl	r35,8428,r1; ld4	r14,[r35]; nop.i	0x0; }
	{ cmp4.lt	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000001025F0; }

l4000000000102590:
	{ (p06) addl	r15,8436,r1; nop.m	0x0; (p06) adds	r14,0xFFFFFFFFFFFFFFFF,r14; }

l4000000000102596:
	{ chk.a.nc	r0,3FFFFFFFFF102D96; (p07) addl	r127,1008398,r3; (p33) nop }

l40000000001025A0:
	{ (p06) ld8	r34,[r15]; nop.m	0x0; (p06) addp4	r14,r14,r0; }

l40000000001025A6:
	{ chk.a.nc	r0,3FFFFFFFFF102DA6; (p07) nop; add	r0,r0,r32 }

l40000000001025B0:
	{ nop.m	0x0; (p06) adds	r33,0x8,r34; (p06) mov.i	LC,r14; }

l40000000001025BC:
	{ (p07) ldf8	f65,[r0]; Invalid; dep	r0,r32,r0,63,1 }

l40000000001025C0:
	{ ld8	r43,[r34]; nop.m	0x0; adds	r34,0x0,r33 }
	{ adds	r33,0x8,r33; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r40; br.cloop.sptk.few	40000000001025C0 }

l40000000001025F0:
	{ adds	r8,0x0,r0; st4	[r0],r35; mov	pr,r41,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r39; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r42; mov.spnt	b0,r38,4000000000102610 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l4000000000102630:
	{ adds	r44,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn4000000000101C00; }
	{ addl	r8,1,r0; adds	r1,0x0,r40; mov	pr,r41,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r39; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r42; mov.spnt	b0,r38,4000000000102660 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000102680:
	{ addl	r14,8436,r1; tbit.z	p06,p07,r36,0x2; sxt4	r8,r8 }
	{ addl	r44,660,r1; addl	r43,1,r0; nop.b	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ shladd	r14,r8,0x3,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000102790; }

l40000000001026C0:
	{ nop.m	0x0; (p07) ld8	r45,[r14]; nop.i	0x0 }

l40000000001026CC:
	{ shladdp4	r0,r1,0x2,r0; Invalid; break.i	0x1000 }
	{ (p37) nop; invala; break.b	0x1000 }
	{ cmp.lt	p00,p09,r1,r0; Invalid; nop }

l40000000001026F0:
	{ addl	r14,-10260,r1; nop.m	0x0; addl	r43,10,r0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r44,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AEC0; }
	{ adds	r1,0x0,r40; adds	r43,0x0,r0; br.call.sptk.many	b0,sh_chkwrite; }
	{ nop.m	0x0; adds	r1,0x0,r40; br.cond.sptk.few	4000000000101FF0; }

l4000000000102740:
	{ cmp.eq	p07,p06,0x0,r36; nop.m	0x0; addl	r44,660,r1 }
	{ addl	r43,1,r0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000102830; }

l4000000000102760:
	{ nop.m	0x0; (p06) adds	r45,0x0,r33; nop.i	0x0 }

l400000000010276C:
	{ shladdp4	r0,r1,0x2,r0; Invalid; break.i	0x1000 }
	{ (p32) invala; nop; epc }
	{ (p28) ldfps	f127,f63,[r36]; Invalid; break.i	0x1000 }

l4000000000102790:
	{ ld8	r43,[r14]; nop.i	0x0; br.call.sptk.many	b0,polite_directory_format; }
	{ adds	r1,0x0,r40; adds	r45,0x0,r8; addl	r43,1,r0; }
	{ nop.m	0x0; addl	r44,660,r1; nop.i	0x0; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ nop.m	0x0; adds	r1,0x0,r40; br.cond.sptk.few	40000000001026F0 }

l40000000001027E0:
	{ ld8	r43,[r14]; nop.i	0x0; br.call.sptk.many	b0,polite_directory_format; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r46,0x0,r8 }
	{ addl	r43,1,r0; adds	r45,0x0,r33; addl	r44,652,r1; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ nop.m	0x0; adds	r1,0x0,r40; br.cond.sptk.few	4000000000101F90 }

l4000000000102830:
	{ adds	r43,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,polite_directory_format; }
	{ adds	r1,0x0,r40; adds	r45,0x0,r8; addl	r43,1,r0; }
	{ nop.m	0x0; addl	r44,660,r1; nop.i	0x0; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ nop.m	0x0; adds	r1,0x0,r40; br.cond.sptk.few	4000000000102300 }

l4000000000102880:
	{ adds	r43,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,polite_directory_format; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r46,0x0,r8 }
	{ addl	r43,1,r0; adds	r45,0x0,r0; addl	r44,652,r1; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ nop.m	0x0; adds	r1,0x0,r40; br.cond.sptk.few	4000000000102300; }

l40000000001028D0:
	{ addl	r44,644,r1; nop.m	0x0; addl	r45,5,r0 }
	{ adds	r43,0x0,r0; nop.m	0x0; and	r36,0x4,r36; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r40; adds	r43,0x0,r8; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r40; adds	r43,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r33,0x0,r8 }
	{ addl	r45,5,r0; adds	r43,0x0,r0; addl	r44,644,r1; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r43,0x0,r33 }
	{ adds	r44,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; adds	r1,0x0,r40; nop.b	0x0 }
	{ adds	r33,0x0,r8; tbit.z	p06,p07,r37,0x1; (p06) br.cond.dptk.few	4000000000102740 }

l4000000000102990:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000001022B0; }
40000000001029A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001029B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; popd_builtin: 40000000001029C0
popd_builtin proc
	{ alloc	r39,ar.pfs,0xB,0x0,0x9; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r38,b6 }
	{ adds	r40,0x0,r1; cmp.eq	p06,p07,0x0,r32; adds	r14,0x10,r12 }
	{ adds	r15,0x0,r0; addl	r16,43,r0; adds	r35,0x0,r0; }
	{ st8	[r0],r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000102EC0; }

l4000000000102A00:
	{ adds	r34,0x8,r32; nop.m	0x0; addl	r36,8428,r1; }
	{ ld8	r14,[r34]; ld8	r14,[r14]; nop.i	0x0; }
	{ ld1	r33,[r14]; nop.m	0x0; sxt1	r33,r33; }
	{ cmp4.eq	p07,p06,0x2D,r33; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000102AE0; }

l4000000000102A40:
	{ cmp4.eq	p06,p07,0x2B,r33; adds	r16,0x10,r12; (p06) br.cond.dpnt.few	4000000000102BF0; }

l4000000000102A50:
	{ ld4	r34,[r36]; ld8	r14,[r16]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r16,r34; nop.i	0x0; }
	{ nop.m	0x0; cmp.lt	p06,p07,r16,r14; (p07) br.cond.dptk.few	4000000000102CA0; }

l4000000000102A80:
	{ cmp.eq	p07,p06,0x0,r15; adds	r41,0x0,r34; (p07) addl	r42,612,r1; }

l4000000000102A90:
	{ nop.m	0x0; (p06) adds	r42,0x0,r15; nop.i	0x0; }

l4000000000102A9C:
	{ getf.s	r0,f1; Invalid; break.i	0x1000 }

l4000000000102AA6:
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; Invalid; break.b	0x80000 }

l4000000000102AC0:
	{ nop.m	0x0; mov.i	ar.pfs,r39; mov.spnt	b0,r38,4000000000102AC0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000102AE0:
	{ adds	r17,0x2,r14; nop.m	0x0; adds	r41,0x1,r14; }
	{ ld1	r17,[r17]; nop.m	0x0; sxt1	r17,r17; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r17; (p06) br.cond.dptk.few	4000000000102B40 }

l4000000000102B10:
	{ ld1	r14,[r41]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x6E,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000102C70; }

l4000000000102B30:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r14; (p07) br.cond.dpnt.few	4000000000102BA0 }

l4000000000102B40:
	{ adds	r42,0x10,r12; nop.i	0x0; br.call.sptk.many	b0,legal_number; }
	{ nop.m	0x0; adds	r1,0x0,r40; nop.i	0x0 }
	{ ld8	r14,[r34]; cmp4.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	4000000000102C20; }

l4000000000102B70:
	{ nop.m	0x0; ld8	r32,[r32]; adds	r16,0x0,r33 }
	{ nop.m	0x0; ld8	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p06) br.cond.dptk.few	4000000000102A00 }

l4000000000102BA0:
	{ addl	r36,8428,r1; adds	r17,0x10,r12; adds	r33,0x0,r16; }
	{ ld4	r34,[r36]; ld8	r14,[r17]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r16,r34; nop.i	0x0; }
	{ nop.m	0x0; cmp.lt	p06,p07,r16,r14; (p06) br.cond.dptk.few	4000000000102A80 }

l4000000000102BE0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000102CA0 }

l4000000000102BF0:
	{ adds	r41,0x1,r14; adds	r42,0x10,r12; br.call.sptk.many	b0,legal_number; }
	{ nop.m	0x0; adds	r1,0x0,r40; nop.i	0x0 }
	{ ld8	r14,[r34]; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	4000000000102B70; }

l4000000000102C20:
	{ ld8	r41,[r14]; nop.i	0x0; br.call.sptk.many	b0,sh_invalidnum; }
	{ adds	r1,0x0,r40; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ addl	r8,1,r0; adds	r1,0x0,r40; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,4000000000102C50; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l4000000000102C70:
	{ ld8	r32,[r32]; nop.m	0x0; addl	r35,1,r0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p06) br.cond.dptk.few	4000000000102A00 }

l4000000000102C90:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000102BA0; }

l4000000000102CA0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	4000000000102DE0; }

l4000000000102CB0:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	4000000000102A80; }

l4000000000102CC0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2B,r33; (p06) br.cond.dpnt.few	4000000000102EB0; }

l4000000000102CD0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000102CE0:
	{ cmp4.eq	p07,p06,0x2D,r33; adds	r33,0x0,r14; (p07) br.cond.dpnt.few	4000000000102E90; }

l4000000000102CF0:
	{ addl	r14,8436,r1; nop.m	0x0; sxt4	r35,r33; }
	{ ld8	r37,[r14]; shladd	r14,r35,0x3,r37; nop.i	0x0; }
	{ ld8	r41,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r17,0xFFFFFFFFFFFFFFFE,r34; nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFFFF,r34 }
	{ adds	r15,0x10,r37; nop.m	0x0; adds	r1,0x0,r40; }
	{ sub	r17,r17,r33; st4	[r14],r36; nop.i	0x0 }
	{ cmp4.lt	p06,p07,r33,r14; adds	r14,0x1,r35; (p07) br.cond.dpnt.few	4000000000102DA0; }

l4000000000102D60:
	{ addp4	r17,r17,r0; nop.m	0x0; shladd	r14,r14,0x3,r37; }
	{ add	r17,r35,r17; nop.i	0x0; shladd	r17,r17,0x3,r15; }

l4000000000102D80:
	{ ld8	r16,[r14],8; adds	r15,0xFFFFFFFFFFFFFFF0,r14; cmp.eq	p07,p06,r17,r14; }
	{ st8	[r16],r15; nop.i	0x0; (p06) br.cond.dptk.few	4000000000102D80 }

l4000000000102DA0:
	{ adds	r41,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,dirs_builtin; }
	{ nop.m	0x0; adds	r1,0x0,r40; adds	r8,0x0,r0 }

l4000000000102DC0:
	{ nop.m	0x0; mov.i	ar.pfs,r39; mov.spnt	b0,r38,4000000000102DC0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000102DE0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2B,r33; (p06) br.cond.dptk.few	4000000000102CE0; }

l4000000000102DF0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	4000000000102EB0; }

l4000000000102E00:
	{ addl	r33,8436,r1; nop.m	0x0; adds	r34,0xFFFFFFFFFFFFFFFF,r34 }
	{ cmp4.eq	p07,p06,0x0,r35; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000102F10; }

l4000000000102E20:
	{ nop.m	0x0; sxt4	r15,r34; nop.i	0x0 }
	{ ld8	r14,[r33]; st4	[r34],r36; nop.i	0x0; }
	{ shladd	r14,r15,0x3,r14; nop.i	0x0; nop.i	0x0 }
	{ ld8	r41,[r14]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r40; nop.m	0x0; nop.i	0x0 }

l4000000000102E70:
	{ adds	r41,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,dirs_builtin; }
	{ adds	r1,0x0,r40; adds	r8,0x0,r0; br.cond.sptk.few	4000000000102DC0 }

l4000000000102E90:
	{ nop.m	0x0; cmp.eq	p07,p06,r14,r16; adds	r33,0x0,r14 }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	4000000000102E00; br.cond.sptk.few	4000000000102CF0; }

l4000000000102EAC:
	{ Invalid; nop; (p36) epc }

l4000000000102EB0:
	{ nop.m	0x0; sub	r33,r34,r14; br.cond.sptk.few	4000000000102CF0; }

l4000000000102EC0:
	{ addl	r36,8428,r1; adds	r14,0x0,r0; nop.i	0x0 }
	{ adds	r35,0x0,r0; addl	r33,43,r0; adds	r15,0x0,r0; }
	{ ld4	r34,[r36]; nop.m	0x0; sxt4	r16,r34; }
	{ nop.m	0x0; cmp.lt	p06,p07,r16,r14; (p06) br.cond.dptk.few	4000000000102A80 }

l4000000000102F00:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000102CA0 }

l4000000000102F10:
	{ adds	r16,0xFFFFFFFFFFFFFFFF,r16; ld8	r14,[r33]; nop.i	0x0; }
	{ nop.m	0x0; shladd	r14,r16,0x3,r14; nop.i	0x0; }
	{ ld8	r41,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn40000000001019C0; }
	{ adds	r1,0x0,r40; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.sptk.few	4000000000102AC0 }

l4000000000102F50:
	{ ld4	r34,[r36]; ld8	r14,[r33]; nop.i	0x0; }
	{ adds	r34,0xFFFFFFFFFFFFFFFF,r34; nop.i	0x0; sxt4	r15,r34 }
	{ st4	[r34],r36; shladd	r14,r15,0x3,r14; nop.i	0x0; }
	{ ld8	r41,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r40; br.cond.sptk.few	4000000000102E70; }
4000000000102FA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000102FB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000102FC0: 4000000000102FC0
;;   Called from:
;;     40000000001034BC (in pushd_builtin)
;;     40000000001039EC (in pushd_builtin)
fn4000000000102FC0 proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; cmp.eq	p06,p07,0x0,r32; mov	r34,b2 }
	{ adds	r36,0x0,r1; nop.m	0x0; adds	r37,0x0,r32; }
	{ (p06) addl	r33,1,r0; (p06) br.cond.dpnt.few	4000000000103030; br.call.sptk.many	b0,fn40000000001019C0; }

l4000000000102FE6:
	{ Invalid; (p32) nop; (p48) nop; }

l4000000000102FEC:
	{ (p15) cmp.eq.unc	p61,p08,r63,r44; nop; zxt1	r0,r64 }
	{ nop; (p04) nop; (p04) mov	pr,r0,0x8400 }
	{ Invalid; break.i	0x1000; break.b	0x1000 }

l4000000000103010:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,dirs_builtin; }
	{ adds	r1,0x0,r36; nop.m	0x0; nop.i	0x0 }

l4000000000103030:
	{ adds	r8,0x0,r33; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000103040; br.ret	b0; }
4000000000103050 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000103060 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000103070 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; pushd_builtin: 4000000000103080
pushd_builtin proc
	{ alloc	r39,ar.pfs,0xD,0x0,0xA; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r41,LC }
	{ adds	r14,0x8,r32; adds	r40,0x0,r1; cmp.eq	p06,p07,0x0,r32; }
	{ nop.m	0x0; mov	r38,b6; (p06) br.cond.dpnt.few	4000000000103420; }

l40000000001030B0:
	{ ld8	r14,[r14]; cmp.eq	p06,p07,0x0,r14; nop.i	0x0; }
	{ ld8	r14,[r14]; ld1	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; (p06) br.cond.dpnt.few	4000000000103600; }

l40000000001030E0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r15; (p07) br.cond.dpnt.few	40000000001033A0 }

l40000000001030F0:
	{ adds	r33,0x0,r32; adds	r34,0x0,r0; addl	r35,8428,r1; }

l4000000000103100:
	{ nop.m	0x0; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000103230; }

l4000000000103110:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2B,r15; (p06) br.cond.dpnt.few	4000000000103B30; }

l4000000000103120:
	{ nop.m	0x0; tbit.z	p07,p06,r34,0x1; nop.i	0x0 }
	{ nop.m	0x0; (p06) br.cond.dpnt.few	4000000000103620; nop.b	0x0; }

l400000000010313C:
	{ nop; zxt1	r0,r64; break.i	0x1000 }

l4000000000103146:
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ break.m	0x4000; nop; (p32) nop }

l4000000000103160:
	{ addl	r42,692,r1; nop.m	0x0; and	r34,0x1,r34; }

l4000000000103162:
	{ (p22) break.m	0x480A0; nop; (p32) br.call.sptk.few	b0,400000000021B212; }
	{ (p32) break.m	0x2030A; nop; (p02) nop; }
	{ break.m	0x720E2; zxt1	r32,r0; nop }
	{ break.m	0x42002; dep	r32,r0,r64,63,2; Invalid; }

l40000000001031A0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	40000000001036B0; }

l40000000001031B0:
	{ cmp4.eq	p06,p07,0x0,r36; (p06) adds	r42,0x0,r33; nop.i	0x0; }

l40000000001031BC:
	{ getf.s	r0,f1; zxt1	r0,r64; break.i	0x1000 }

l40000000001031C6:
	{ break.m	0x4000; (p32) nop; (p48) nop }
	{ add	r0,r0,r1; nop; (p32) nop }
	{ chk.a.nc	f0,3FFFFFFFFF1039E6; nop; (p48) nop }

l40000000001031F0:
	{ addl	r35,1,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r40; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.i	LC,r41; mov.spnt	b0,r38,4000000000103210 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l4000000000103230:
	{ adds	r15,0x2,r14; adds	r42,0x1,r14; adds	r43,0x10,r12; }
	{ ld1	r15,[r15]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	4000000000103380 }

l4000000000103260:
	{ nop.m	0x0; ld1	r14,[r42]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x6E,r14; }
	{ (p07) or	r34,0x1,r34; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000103330; }

l4000000000103286:
	{ chk.a.nc	f0,3FFFFFFFFF103A86; nop; break.i	0x80000 }

l4000000000103290:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2D,r14; (p06) br.cond.dpnt.few	4000000000103580; }

l40000000001032A0:
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000103120; }

l40000000001032B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,legal_number; }
	{ adds	r16,0x10,r12; nop.m	0x0; adds	r1,0x0,r40 }
	{ cmp4.eq	p06,p07,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000103AC0; }

l40000000001032E0:
	{ ld4	r42,[r35]; ld8	r14,[r16]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r15,r42; sub	r14,r15,r14 }
	{ nop.m	0x0; st8	[r14],r16; nop.i	0x0 }

l4000000000103310:
	{ cmp.lt	p06,p07,r15,r14; or	r34,0x2,r34; (p06) br.cond.dpnt.few	4000000000103520; }

l4000000000103320:
	{ nop.m	0x0; cmp.lt	p07,p06,r14,r0; (p07) br.cond.dpnt.few	4000000000103520 }

l4000000000103330:
	{ nop.m	0x0; ld8	r33,[r33]; nop.i	0x0; }
	{ adds	r14,0x8,r33; cmp.eq	p06,p07,0x0,r33; (p06) br.cond.dpnt.few	40000000001035A0; }

l4000000000103350:
	{ ld8	r14,[r14]; ld8	r14,[r14]; nop.i	0x0; }
	{ ld1	r15,[r14]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r15; br.cond.sptk.few	4000000000103100 }

l4000000000103380:
	{ adds	r42,0x1,r14; ld1	r14,[r42]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; br.cond.sptk.few	40000000001032A0; }

l40000000001033A0:
	{ adds	r16,0x2,r14; ld1	r16,[r16]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r16,r16; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p09,p08,0x0,r16; (p08) br.cond.dptk.few	40000000001030F0 }

l40000000001033D0:
	{ adds	r16,0x1,r14; ld1	r16,[r16]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r16,r16; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p09,p08,0x2D,r16; (p08) br.cond.dptk.few	40000000001030F0 }

l4000000000103400:
	{ ld8	r33,[r32]; cmp.eq	p07,p06,0x0,r33; nop.i	0x0; }
	{ (p06) addl	r36,1,r0; (p06) adds	r34,0x0,r0; (p06) br.cond.sptk.few	4000000000103160; }

l4000000000103416:
	{ (p17) chk.a.clr	r0,3FFFFFFFFF183416; nop; (p16) nop; }

l400000000010341C:
	{ (p42) nop; zxt4	r59,r16; br.cond.sptk.few	400000000010361C }

l4000000000103420:
	{ addl	r33,8428,r1; nop.m	0x0; addl	r42,692,r1; }
	{ nop.m	0x0; ld4	r14,[r33]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000001037D0; }

l4000000000103450:
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,get_working_directory; }
	{ adds	r1,0x0,r40; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	40000000001039B0; }

l4000000000103470:
	{ ld4	r15,[r33]; nop.m	0x0; addl	r14,8436,r1; }
	{ adds	r15,0xFFFFFFFFFFFFFFFF,r15; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r15,r15; shladd	r14,r15,0x3,r14; }
	{ ld8	r33,[r14]; st8	[r8],r14; nop.i	0x0; }

l40000000001034B0:
	{ adds	r42,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,fn4000000000102FC0; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r42,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r40; nop.m	0x0; nop.i	0x0 }

l40000000001034F0:
	{ adds	r8,0x0,r35; mov.i	ar.pfs,r39; mov.i	LC,r41; }
	{ nop.m	0x0; mov.spnt	b0,r38,4000000000103500; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l4000000000103520:
	{ adds	r33,0x8,r33; nop.m	0x0; addl	r35,1,r0; }
	{ nop.m	0x0; ld8	r14,[r33]; nop.i	0x0; }
	{ ld8	r43,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000101C00; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r40; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.i	LC,r41; mov.spnt	b0,r38,4000000000103560 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000103580:
	{ ld8	r33,[r33]; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000001035A0:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x1; adds	r36,0x0,r0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000103620; }

l40000000001035C0:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	4000000000103160 }

l40000000001035D0:
	{ adds	r35,0x0,r0; adds	r8,0x0,r35; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.i	LC,r41; mov.spnt	b0,r38,40000000001035E0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000103600:
	{ cmp4.eq	p07,p06,0x2D,r15; nop.m	0x0; adds	r33,0x0,r32 }
	{ adds	r34,0x0,r0; addl	r35,8428,r1; br.cond.sptk.few	4000000000103100 }

l4000000000103620:
	{ nop.m	0x0; addl	r42,692,r1; nop.i	0x0; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,get_working_directory; }
	{ adds	r15,0x10,r12; adds	r1,0x0,r40; adds	r33,0x0,r8; }
	{ nop.m	0x0; ld8	r14,[r15]; nop.i	0x0; }
	{ adds	r17,0x0,r14; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000103840; }

l4000000000103670:
	{ nop.m	0x0; tbit.z	p07,p06,r34,0x0; nop.i	0x0 }
	{ adds	r42,0x0,r33; adds	r35,0x0,r0; (p07) br.cond.dpnt.few	40000000001034B0; }

l4000000000103690:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r40; br.cond.sptk.few	40000000001034F0 }

l40000000001036B0:
	{ adds	r33,0x8,r33; ld8	r14,[r33]; nop.i	0x0; }
	{ ld8	r42,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r40; adds	r42,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r14,[r33]; adds	r1,0x0,r40; adds	r42,0x0,r8; }
	{ ld8	r43,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; adds	r1,0x0,r40; adds	r36,0x0,r8; }

l4000000000103710:
	{ addl	r33,8428,r1; addl	r15,8444,r1; adds	r42,0x0,r0; }
	{ ld4	r14,[r33]; ld4	r16,[r15]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,r16,r14; sxt4	r16,r14; (p06) br.cond.dpnt.few	4000000000103A30; }

l4000000000103740:
	{ addl	r15,8436,r1; nop.m	0x0; adds	r14,0x1,r14; }
	{ ld8	r8,[r15]; st4	[r14],r33; nop.i	0x0; }
	{ nop.m	0x0; shladd	r15,r16,0x3,r8; nop.i	0x0; }
	{ st8	[r36],r15; nop.i	0x0; br.call.sptk.many	b0,dirs_builtin; }
	{ adds	r1,0x0,r40; cmp4.eq	p06,p07,0x0,r34; (p06) br.cond.dptk.few	40000000001035D0 }

l4000000000103790:
	{ adds	r42,0x0,r35; adds	r35,0x0,r0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r40; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.i	LC,r41; mov.spnt	b0,r38,40000000001037B0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000001037D0:
	{ addl	r43,684,r1; nop.m	0x0; addl	r44,5,r0 }
	{ adds	r42,0x0,r0; nop.m	0x0; addl	r35,1,r0; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r40; adds	r42,0x0,r8; br.call.sptk.many	b0,builtin_error; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r40; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.i	LC,r41; mov.spnt	b0,r38,4000000000103820 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000103840:
	{ addl	r14,8428,r1; ld4	r15,[r14]; addl	r14,8436,r1; }
	{ nop.m	0x0; adds	r18,0xFFFFFFFFFFFFFFFE,r15; sxt4	r15,r15 }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp4.lt	p08,p09,r18,r0; sxt4	r21,r18; adds	r20,0xFFFFFFFFFFFFFFFF,r15; }
	{ (p08) adds	r19,0x0,r18; adds	r21,0x1,r21; shladd	r20,r20,0x3,r14; }

l4000000000103886:
	{ Invalid; (p10) dep	r20,r14,r18,35,1; (p50) nop }

l4000000000103896:
	{ Invalid; Invalid; (p48) nop.b	0x13024 }
	{ add	r0,r0,r1; (p09) nop; break.i	0x80000 }
	{ break.m	0x4000; nop; (p48) nop }

l40000000001038C0:
	{ addp4	r15,r18,r0; nop.m	0x0; adds	r14,0x0,r21 }
	{ ld8	r36,[r20]; nop.m	0x0; (p08) br.cond.dpnt.few	4000000000103920; }

l40000000001038E0:
	{ nop.m	0x0; mov.i	LC,r15; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000103900:
	{ adds	r15,0xFFFFFFFFFFFFFFF8,r14; ld8	r16,[r15]; nop.i	0x0; }
	{ st8	[r16],r14; adds	r14,0x0,r15; br.cloop.sptk.few	4000000000103900 }

l4000000000103920:
	{ adds	r17,0xFFFFFFFFFFFFFFFF,r17; st8	[r33],r19; adds	r33,0x0,r36; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r17; (p06) br.cond.dptk.few	40000000001038C0; }

l4000000000103940:
	{ adds	r16,0x10,r12; tbit.z	p07,p06,r34,0x0; adds	r42,0x0,r36 }
	{ adds	r35,0x0,r0; st8	[r0],r16; nop.i	0x0 }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	40000000001039E0; br.call.sptk.many	b0,fn400000000001A7E0; }

l400000000010396C:
	{ (p52) nop; invala; break.i	0x1000 }
	{ Invalid; zxt1	r96,r64; (p48) break.i	0x2A809 }

l4000000000103980:
	{ adds	r8,0x0,r35; mov.i	ar.pfs,r39; mov.i	LC,r41; }
	{ nop.m	0x0; mov.spnt	b0,r38,4000000000103990; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l40000000001039B0:
	{ addl	r35,1,r0; adds	r8,0x0,r35; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.i	LC,r41; mov.spnt	b0,r38,40000000001039C0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000001039E0:
	{ adds	r42,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,fn4000000000102FC0; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r42,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r40; br.cond.sptk.few	4000000000103980 }

l4000000000103A20:
	{ nop.m	0x0; adds	r36,0x0,r35; br.cond.sptk.few	4000000000103710; }

l4000000000103A30:
	{ addl	r37,8436,r1; adds	r43,0xA,r14; nop.i	0x0 }
	{ st4	[r43],r15; ld8	r42,[r37]; br.call.sptk.many	b0,strvec_resize; }
	{ ld4	r14,[r33]; nop.m	0x0; adds	r1,0x0,r40 }
	{ st8	[r8],r37; nop.m	0x0; adds	r42,0x0,r0; }
	{ nop.m	0x0; sxt4	r16,r14; adds	r14,0x1,r14; }
	{ shladd	r15,r16,0x3,r8; st4	[r14],r33; nop.i	0x0; }
	{ st8	[r36],r15; nop.i	0x0; br.call.sptk.many	b0,dirs_builtin; }
	{ adds	r1,0x0,r40; cmp4.eq	p06,p07,0x0,r34; (p06) br.cond.dptk.few	40000000001035D0 }

l4000000000103AB0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000103790 }

l4000000000103AC0:
	{ adds	r33,0x8,r33; nop.m	0x0; addl	r35,1,r0; }
	{ nop.m	0x0; ld8	r14,[r33]; nop.i	0x0; }
	{ ld8	r42,[r14]; nop.i	0x0; br.call.sptk.many	b0,sh_invalidnum; }
	{ adds	r1,0x0,r40; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r40; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.i	LC,r41; mov.spnt	b0,r38,4000000000103B10 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l4000000000103B30:
	{ adds	r42,0x1,r14; adds	r43,0x10,r12; br.call.sptk.many	b0,legal_number; }
	{ adds	r15,0x10,r12; nop.m	0x0; adds	r1,0x0,r40 }
	{ cmp4.eq	p06,p07,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000103AC0; }

l4000000000103B60:
	{ ld4	r42,[r35]; ld8	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r15,r42; br.cond.sptk.few	4000000000103310; }

;; get_dirstack_from_string: 4000000000103B80
get_dirstack_from_string proc
	{ alloc	r36,ar.pfs,0x9,0x0,0x6; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r35,b3 }
	{ ld1	r15,[r32]; adds	r37,0x0,r1; adds	r38,0x0,r32; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ cmp4.eq	p08,p09,0x2D,r15; cmp4.eq	p06,p07,0x2B,r15; (p08) addl	r14,1,r0; }

l4000000000103BC0:
	{ (p09) adds	r14,0x0,r0; adds	r34,0x0,r14; cmp.ne.or.andcm	p06,p07,0x0,r14; }

l4000000000103BC6:
	{ Invalid; (p35) nop; cmp.lt	p00,p00,r0,r32 }
	{ (p17) chk.a.clr	f1,3FFFFFFFFF303BD6; nop; (p32) nop; }

l4000000000103BDC:
	{ (p01) cmp.lt	p00,p09,r0,r33; czx1.r	r64,r97; Invalid }

l4000000000103BE0:
	{ cmp4.eq	p06,p07,0x0,r34; nop.m	0x0; adds	r38,0x1,r32; }
	{ (p06) addl	r34,1,r0; nop.i	0x0; (p07) addl	r34,-1,r0 }

l4000000000103BF6:
	{ chk.a.nc	f0,3FFFFFFFFF1043F6; (p17) nop; (p48) nop }

l4000000000103C00:
	{ adds	r39,0x10,r12; adds	r33,0x18,r12; br.call.sptk.many	b0,legal_number; }
	{ cmp4.eq	p07,p06,0x0,r8; adds	r14,0x10,r12; adds	r1,0x0,r37 }
	{ adds	r39,0x0,r34; adds	r40,0x0,r33; (p07) br.cond.dpnt.few	4000000000103D40; }

l4000000000103C30:
	{ nop.m	0x0; ld8	r38,[r14]; nop.i	0x0 }
	{ st4	[r0],r33; nop.m	0x0; br.call.sptk.many	b0,fn4000000000101AC0; }
	{ ld4	r14,[r33]; nop.m	0x0; adds	r1,0x0,r37; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000103D00; }

l4000000000103C70:
	{ addl	r15,8428,r1; cmp4.lt	p06,p07,r8,r0; (p06) br.cond.dpnt.few	4000000000103D40; }

l4000000000103C80:
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ cmp4.lt	p06,p07,r15,r8; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000103D40; }

l4000000000103CA0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x1,r14; (p07) br.cond.dpnt.few	4000000000103CF0 }

l4000000000103CB0:
	{ addl	r14,8436,r1; nop.m	0x0; sxt4	r8,r8; }
	{ ld8	r14,[r14]; shladd	r8,r8,0x3,r14; nop.i	0x0; }
	{ ld8	r8,[r8]; mov.i	ar.pfs,r36; mov.spnt	b0,r35,4000000000103CD0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000103CF0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	4000000000103CB0; }

l4000000000103D00:
	{ nop.m	0x0; addl	r38,700,r1; nop.i	0x0; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,get_string_value; }
	{ adds	r1,0x0,r37; mov.i	ar.pfs,r36; mov.spnt	b0,r35,4000000000103D20 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000103D40:
	{ adds	r8,0x0,r0; mov.i	ar.pfs,r36; mov.spnt	b0,r35,4000000000103D40 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }
4000000000103D60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000103D70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; set_dirstack_element: 4000000000103D80
set_dirstack_element proc
	{ alloc	r37,ar.pfs,0xA,0x0,0x7; mov	r36,b4; nop.b	0x0 }
	{ adds	r38,0x0,r1; adds	r40,0x0,r33; adds	r39,0x0,r32; }
	{ adds	r41,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000101AC0; }
	{ adds	r1,0x0,r38; nop.m	0x0; cmp.eq	p06,p07,0x0,r32; }
	{ addl	r14,8428,r1; tbit.nz.or.andcm	p06,p07,r8,0x1F; (p06) br.cond.dpnt.few	4000000000103DF0; }

l4000000000103DD0:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r14,r8; (p07) br.cond.dpnt.few	4000000000103E10 }

l4000000000103DF0:
	{ nop.m	0x0; mov.i	ar.pfs,r37; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r36,4000000000103E00; br.ret	b0 }

l4000000000103E10:
	{ addl	r14,8436,r1; nop.m	0x0; sxt4	r8,r8; }
	{ ld8	r14,[r14]; shladd	r35,r8,0x3,r14; nop.i	0x0; }
	{ ld8	r39,[r35]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r38; adds	r39,0x0,r34; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r38; adds	r39,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r38; nop.m	0x0; adds	r39,0x0,r8 }
	{ adds	r40,0x0,r34; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r38; st8	[r8],r35; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,4000000000103E90; br.ret	b0; }
4000000000103EA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000103EB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; get_directory_stack: 4000000000103EC0
get_directory_stack proc
	{ alloc	r39,ar.pfs,0xC,0x0,0xA; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r41,pr }
	{ addl	r36,8428,r1; addl	r37,8436,r1; adds	r40,0x0,r1; }
	{ ld4	r14,[r36]; adds	r35,0x0,r0; nop.b	0x0 }
	{ adds	r34,0x0,r0; adds	r33,0x0,r0; tnat.z	p16,p17,r32; }
	{ cmp4.lt	p07,p06,0x0,r14; nop.m	0x0; mov	r38,b6; }
	{ nop.m	0x0; (p06) adds	r35,0x0,r0; (p06) br.cond.dpnt.few	4000000000103FA0; }

l4000000000103F1C:
	{ (p04) cmp.lt	p00,p09,r64,r33; Invalid; nop.b	0x1000 }

l4000000000103F20:
	{ ld8	r14,[r37]; nop.m	0x0; adds	r33,0x1,r33; }
	{ add	r14,r14,r34; nop.m	0x0; adds	r34,0x8,r34; }
	{ ld8	r42,[r14]; nop.i	0x0; (p17) br.call.dpnt.many	b0,polite_directory_format; }

l4000000000103F50:
	{ (p17) adds	r1,0x0,r40; (p17) adds	r42,0x0,r8; br.call.sptk.many	b0,make_word; }

l4000000000103F56:
	{ Invalid; (p48) nop }

l4000000000103F5C:
	{ (p31) ldf8	f125,[r44]; (p05) invala; nop.b	0x1000 }
	{ cmpxchg8.acq	r40,[r66],r0; zxt1	r0,r64; break.i	0x1000 }
	{ (p38) cmp.lt.unc	p61,p09,r60,r44; (p01) nop; nop }
	{ invala; (p16) nop }
	{ (p60) nop; dep	r0,r32,r0,63,1; (p05) nop }

l4000000000103FA0:
	{ nop.m	0x0; addl	r42,716,r1; nop.i	0x0; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,get_working_directory; }
	{ adds	r33,0x0,r8; cmp.eq	p06,p07,0x0,r8; nop.i	0x0 }
	{ adds	r1,0x0,r40; adds	r42,0x0,r8; (p06) br.cond.dpnt.few	4000000000104120; }

l4000000000103FE0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,polite_directory_format; }
	{ cmp.eq	p06,p07,r33,r8; adds	r34,0x0,r8; nop.i	0x0 }
	{ adds	r1,0x0,r40; adds	r42,0x0,r33; (p06) br.cond.dpnt.few	4000000000104090; }

l4000000000104010:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r40; adds	r42,0x0,r34; br.call.sptk.many	b0,make_word; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r42,0x0,r8 }
	{ adds	r43,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,make_word_list; }
	{ adds	r1,0x0,r40; nop.m	0x0; nop.i	0x0 }

l4000000000104060:
	{ nop.m	0x0; mov	pr,r41,0xFFFFFFFFFFFFFFFE; nop.i	0x0; }
	{ nop.m	0x0; mov.i	ar.pfs,r39; mov.spnt	b0,r38,4000000000104070 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l4000000000104090:
	{ adds	r42,0x0,r8; nop.i	0x0; br.call.sptk.many	b0,make_word; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r43,0x0,r35 }
	{ adds	r42,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,make_word_list; }
	{ adds	r14,0x10,r12; adds	r1,0x0,r40; adds	r42,0x0,r34; }
	{ st8	[r8],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r14,0x10,r12; nop.m	0x0; adds	r1,0x0,r40; }
	{ ld8	r8,[r14]; mov	pr,r41,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,4000000000104100; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l4000000000104120:
	{ nop.m	0x0; addl	r42,708,r1; nop.i	0x0; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,make_word; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r42,0x0,r8 }
	{ adds	r43,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,make_word_list; }
	{ nop.m	0x0; adds	r1,0x0,r40; br.cond.sptk.few	4000000000104060; }
4000000000104170 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; fn4000000000104180: 4000000000104180
;;   Called from:
;;     4000000000106C6C (in read_builtin)
fn4000000000104180 proc
	{ alloc	r33,ar.pfs,0x5,0x0,0x3; addl	r14,8460,r1; mov	r32,b0 }
	{ nop.m	0x0; adds	r34,0x0,r1; nop.i	0x0; }
	{ ld8	r36,[r14]; addl	r35,14,r0; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r34; nop.m	0x0; adds	r35,0x0,r0 }
	{ adds	r36,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,falarm; }
	{ adds	r1,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ nop.m	0x0; mov.spnt	b0,r32,40000000001041E0; br.ret	b0; }
40000000001041F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000104200: 4000000000104200
;;   Called from:
;;     4000000000106D3C (in read_builtin)
fn4000000000104200 proc
	{ alloc	r33,ar.pfs,0x3,0x0,0x3; mov	r32,b0; adds	r34,0x0,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C100; }
	{ adds	r1,0x0,r34; adds	r15,0xD0,r8; mov.i	ar.pfs,r33; }
	{ addl	r16,8476,r1; addl	r14,8508,r1; mov.spnt	b0,r32,4000000000104230; }
	{ nop.m	0x0; ld4	r17,[r16]; addl	r16,8492,r1 }
	{ nop.m	0x0; ld1	r14,[r14]; nop.i	0x0; }
	{ shladd	r14,r14,0x4,r8; ld4	r16,[r16]; nop.i	0x0 }
	{ st1	[r17],r15; addl	r15,8484,r1; adds	r8,0xD8,r8; }
	{ nop.m	0x0; st1	[r14],r8,8; addl	r16,8500,r1 }
	{ nop.m	0x0; ld8	r15,[r15]; nop.i	0x0; }
	{ ld8	r16,[r16]; st8	[r15],r8; nop.i	0x0; }
	{ st8	[r16],r14; nop.i	0x0; br.ret	b0; }
40000000001042C0 18 20 1D 0C 80 05 00 22 06 84 48 00 00 00 00 20 . ....."..H.... 
40000000001042D0 09 28 01 02 00 21 00 00 00 02 00 60 04 00 C4 00 .(...!.....`....
40000000001042E0 0B 40 00 40 18 10 60 00 20 0E 72 00 00 00 04 00 .@.@..`. .r.....
40000000001042F0 D1 10 01 00 00 21 00 00 00 02 00 03 40 00 00 43 .....!......@..C
4000000000104300 09 00 00 00 01 00 E0 40 20 30 28 00 00 00 04 00 .......@ 0(.....
4000000000104310 11 08 00 10 18 10 60 70 04 80 03 00 68 00 80 10 ......`p....h...
4000000000104320 09 00 00 00 01 00 10 00 94 00 42 40 04 40 00 84 ..........B@.@..
4000000000104330 09 00 00 00 01 00 10 62 06 84 48 00 00 00 04 00 .......b..H.....
4000000000104340 0B 70 00 42 18 10 60 00 38 0E 72 C0 04 70 00 84 .p.B..`.8.r..p..
4000000000104350 D1 40 00 00 00 21 00 00 00 02 00 03 60 00 00 43 .@...!......`..C
4000000000104360 11 00 00 00 01 00 00 00 00 02 00 00 08 61 F1 58 .............a.X
4000000000104370 08 08 00 4A 00 21 F0 00 80 30 20 00 00 00 04 00 ...J.!...0 .....
4000000000104380 09 00 00 42 98 11 00 00 80 30 23 00 00 00 04 00 ...B.....0#.....
4000000000104390 0A 70 B0 FB AD 27 E0 00 38 30 20 00 00 00 04 00 .p...'..80 .....
40000000001043A0 0A 00 00 00 01 00 00 78 38 30 23 00 00 00 04 00 .......x80#.....
40000000001043B0 09 40 88 10 0E 20 00 00 00 02 00 00 40 02 AA 00 .@... ......@...
40000000001043C0 03 38 00 10 86 39 00 18 05 80 03 03 11 00 00 90 .8...9..........
40000000001043D0 11 00 00 00 01 C0 81 00 00 00 42 80 08 00 84 00 ..........B.....
40000000001043E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001043F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000104400: 4000000000104400
;;   Called from:
;;     400000000010767C (in read_builtin)
;;     400000000010782C (in read_builtin)
;;     4000000000107A5C (in read_builtin)
;;     4000000000107ABC (in read_builtin)
;;     400000000010808C (in read_builtin)
;;     40000000001082EC (in read_builtin)
fn4000000000104400 proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; adds	r36,0x0,r1; mov	r34,b2 }
	{ nop.m	0x0; adds	r37,0x0,r32; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,valid_array_reference; }
	{ adds	r1,0x0,r36; adds	r37,0x0,r32; adds	r38,0x0,r33 }
	{ adds	r39,0x0,r0; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000001044F0 }

l4000000000104450:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r1,0x0,r36; nop.m	0x0; nop.i	0x0 }

l4000000000104470:
	{ adds	r14,0x28,r8; nop.m	0x0; cmp.eq	p07,p06,0x0,r8 }
	{ addl	r15,16386,r0; nop.m	0x0; (p07) br.cond.dpnt.few	40000000001044D0; }

l4000000000104490:
	{ ld8	r14,[r14]; and	r14,r14,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000001044D0 }

l40000000001044B0:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000001044C0; br.ret	b0 }

l40000000001044D0:
	{ adds	r8,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000001044E0; br.ret	b0; }

l40000000001044F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,assign_array_element; }
	{ nop.m	0x0; adds	r1,0x0,r36; br.cond.sptk.few	4000000000104470; }
4000000000104510 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000104520 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000104530 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000104540: 4000000000104540
;;   Called from:
;;     4000000000106DFC (in read_builtin)
fn4000000000104540 proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x4; mov	r33,b1; adds	r14,0x8,r32 }
	{ adds	r35,0x0,r1; ld4	r36,[r32]; nop.b	0x0; }
	{ ld8	r37,[r14]; nop.i	0x0; br.call.sptk.many	b0,ttsetattr; }
	{ adds	r1,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,4000000000104580; br.ret	b0; }
4000000000104590 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001045A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001045B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001045C0 09 08 15 06 80 05 30 A2 05 40 49 00 04 00 C4 00 ......0..@I.....
40000000001045D0 11 00 00 00 01 00 40 0A 00 00 48 00 18 76 F1 58 ......@...H..v.X
40000000001045E0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000001045F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000104600 0B 70 B0 FB AC 27 E0 00 38 30 20 00 00 00 04 00 .p...'..80 .....
4000000000104610 09 00 00 00 01 00 F0 00 38 30 20 00 00 00 04 00 ........80 .....
4000000000104620 10 00 00 00 01 00 70 00 3C 0C 72 83 08 00 84 02 ......p.<.r.....
4000000000104630 0B 78 50 02 42 24 F0 00 3C 30 20 00 00 00 04 00 .xP.B$..<0 .....
4000000000104640 09 00 00 00 01 00 60 00 3C 0E 72 00 00 00 04 00 ......`.<.r.....
4000000000104650 F1 00 3C 1C 98 11 00 00 00 02 00 80 08 00 84 00 ..<.............
4000000000104660 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000104670 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; read_builtin: 4000000000104680
read_builtin proc
	{ alloc	r72,ar.pfs,0x2E,0x0,0x2A; adds	r16,0x0,r12; nop.b	0x0 }
	{ adds	r12,0xFFFFFFFFFFFFFE00,r12; mov	r17,LC; addl	r34,8452,r1; }
	{ adds	r14,0x1E0,r12; adds	r15,0x1D8,r12; nop.b	0x0 }
	{ adds	r19,0x1B4,r12; adds	r20,0x1D4,r12; mov	r73,pr; }
	{ st8	[r0],r14; addl	r14,10,r0; mov	r71,b7 }
	{ st8	[r0],r15; adds	r39,0x0,r34; adds	r40,0x0,r0; }
	{ st4	[r0],r19; st4	[r0],r20; nop.i	0x0 }
	{ addl	r37,1,r0; adds	r36,0x160,r12; addl	r41,-1,r0; }
	{ st8	[r16],r8,8; nop.m	0x0; adds	r17,0x1D0,r12; }
	{ nop.m	0x0; st8.spill	[r1],r16; adds	r16,0x1B8,r12 }
	{ st1	[r14],r34; st8	[r0],r16; nop.i	0x0 }
	{ st4	[r0],r17; nop.m	0x0; br.call.sptk.many	b0,reset_internal_getopt; }
	{ adds	r1,0x208,r12; adds	r14,0x180,r12; adds	r15,0x1B0,r12 }
	{ adds	r16,0x184,r12; adds	r17,0x1C0,r12; adds	r19,0x1E8,r12; }
	{ nop.m	0x0; ld8	r1,[r1]; nop.i	0x0 }
	{ st4	[r0],r14; st4	[r0],r15; nop.i	0x0; }
	{ addl	r33,-6268,r1; addl	r35,-6212,r1; addl	r34,9252,r1 }
	{ st4	[r0],r16; st4	[r0],r17; nop.i	0x0; }
	{ st4	[r0],r19; ld8	r33,[r33]; nop.i	0x0 }
	{ ld8	r35,[r35]; nop.m	0x0; nop.i	0x0; }
	{ adds	r74,0x0,r32; adds	r75,0x0,r33; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x208,r12; nop.m	0x0; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000104AA0 }

l40000000001047F0:
	{ nop.m	0x0; adds	r8,0xFFFFFFFFFFFFFFB2,r8; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x27,r8; (p07) br.cond.dptk.few	4000000000104870 }

l4000000000104810:
	{ addl	r33,258,r0; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ adds	r1,0x208,r12; adds	r8,0x0,r33; adds	r18,0x200,r12; }
	{ nop.m	0x0; ld8	r1,[r1]; mov	pr,r73,0xFFFFFFFFFFFFFFFE }
	{ ld8	r19,[r18]; nop.m	0x0; mov.i	ar.pfs,r72; }
	{ nop.m	0x0; mov.i	LC,r19; mov.spnt	b0,r71,4000000000104850 }
	{ nop.m	0x0; adds	r12,0x200,r12; br.ret	b0 }

l4000000000104870:
	{ addp4	r8,r8,r0; shladd	r8,r8,0x3,r35; nop.i	0x0; }
	{ ld8	r14,[r8]; add	r8,r8,r14; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r8,4000000000104890; br.cond	b6; }
40000000001048A0 09 A0 00 19 03 21 00 48 9D 00 23 00 00 00 04 00 .....!.H..#.....
40000000001048B0 08 00 94 28 90 11 00 00 00 02 00 00 00 00 04 00 ...(............
40000000001048C0 11 50 02 44 18 10 B0 04 90 00 42 00 C8 AB F3 58 .P.D......B....X
40000000001048D0 09 08 20 18 04 21 60 00 20 0E 73 E0 01 60 0C 84 .. ..!`. .s..`..
40000000001048E0 11 08 00 02 18 10 00 00 00 02 00 03 50 00 00 43 ............P..C
40000000001048F0 09 00 00 00 01 00 E0 00 90 30 20 00 00 00 04 00 .........0 .....
4000000000104900 11 80 38 00 08 20 60 70 00 0E 60 03 30 00 00 43 ..8.. `p..`.0..C
4000000000104910 09 00 38 1E 90 11 00 00 00 02 00 E0 01 80 58 00 ..8...........X.
4000000000104920 10 00 00 00 01 00 60 78 38 0E 70 03 A0 FE FF 4A ......`x8.p....J
4000000000104930 09 70 90 02 48 24 00 00 00 02 00 20 14 00 00 90 .p..H$..... ....
4000000000104940 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000104950 11 50 02 1C 18 10 00 00 00 02 00 00 38 95 FE 58 .P..........8..X
4000000000104960 09 08 20 18 04 21 80 00 84 00 42 40 02 60 10 84 .. ..!....B@.`..
4000000000104970 08 00 00 00 01 00 10 00 04 30 20 E0 9F 84 7F 0B .........0 .....
4000000000104980 0B 98 00 24 18 10 00 00 00 02 00 00 80 04 AA 00 ...$............
4000000000104990 02 00 00 00 01 00 00 98 04 55 00 00 70 0C 00 07 .........U..p...
40000000001049A0 19 00 00 00 01 00 C0 00 30 08 42 80 08 00 84 00 ........0.B.....
40000000001049B0 08 00 00 00 01 00 A0 04 88 30 20 60 09 67 08 84 .........0 `.g..
40000000001049C0 19 60 A2 19 02 21 80 02 94 00 42 00 88 0B 03 50 .`...!....B....P
40000000001049D0 08 08 20 18 04 21 F0 80 33 04 42 C0 00 40 1C E6 .. ..!..3.B..@..
40000000001049E0 09 80 A0 19 02 21 10 A1 31 06 42 60 02 65 0C 84 .....!..1.B`.e..
40000000001049F0 08 08 00 02 18 10 00 00 00 02 00 40 09 00 01 84 ...........@....
4000000000104A00 19 58 02 42 00 21 00 00 00 02 00 03 50 32 00 43 .X.B.!......P2.C
4000000000104A10 09 00 00 00 01 00 E0 00 3C 30 20 00 00 00 04 00 ........<0 .....
4000000000104A20 11 30 38 00 07 30 00 00 00 02 00 03 30 32 00 43 .08..0......02.C
4000000000104A30 09 00 00 00 01 00 F0 00 40 30 20 00 00 00 04 00 ........@0 .....
4000000000104A40 11 38 3C 00 06 30 00 00 00 02 80 03 10 32 00 43 .8<..0.......2.C
4000000000104A50 08 00 00 00 01 00 00 70 44 20 23 00 00 00 04 00 .......pD #.....
4000000000104A60 19 00 3C 26 90 11 00 00 00 02 00 00 68 5A 01 50 ..<&........hZ.P
4000000000104A70 09 08 20 18 04 21 00 00 00 02 00 E0 F0 47 18 EE .. ..!.......G..
4000000000104A80 11 08 00 02 18 10 00 00 00 02 00 03 70 FD FF 4A ............p..J
4000000000104A90 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

l4000000000104AA0:
	{ addl	r14,9268,r1; adds	r16,0x1D4,r12; nop.i	0x0 }
	{ adds	r17,0x1B8,r12; adds	r19,0x188,r12; cmp4.eq	p06,p07,0x0,r40; }
	{ nop.m	0x0; ld4	r34,[r16]; nop.i	0x0; }
	{ ld8	r33,[r17]; ld8	r14,[r14]; nop.i	0x0; }
	{ st8	[r14],r19; nop.i	0x0; (p06) br.cond.dptk.few	4000000000104E30 }

l4000000000104AF0:
	{ adds	r20,0x1B4,r12; ld4	r20,[r20]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r20; (p06) br.cond.dptk.few	4000000000104E30 }

l4000000000104B10:
	{ adds	r14,0x1D0,r12; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000104E30 }

l4000000000104B30:
	{ nop.m	0x0; adds	r15,0x184,r12; nop.i	0x0; }
	{ ld4	r74,[r15]; nop.i	0x0; br.call.sptk.many	b0,input_avail; }
	{ cmp4.eq	p06,p07,0x0,r8; adds	r1,0x208,r12; adds	r18,0x200,r12; }
	{ (p06) addl	r8,1,r0; ld8	r1,[r1]; nop.i	0x0; }

l4000000000104B66:
	{ fwb; cmp4.ltu	p00,p00,0x0,r1; (p01) nop.b	0x2 }

l4000000000104B76:
	{ Invalid; nop; nop.b	0x21002 }
	{ Invalid; (p63) mov	pr,0xB7F849; break.b	0x80000 }
	{ break.m	0xAA048; Invalid; break.i	0x80000 }
	{ break.m	0xAA093; nop; break.i	0x80000 }
	{ Invalid; (p34) nop; break.i	0x80000 }
4000000000104BC0 09 00 00 00 01 00 F0 A0 32 06 42 00 00 00 04 00 ........2.B.....
4000000000104BD0 10 00 94 1E 90 11 00 00 00 02 00 00 F0 FB FF 48 ...............H
4000000000104BE0 11 50 02 44 18 10 B0 04 90 00 42 00 A8 A8 F3 58 .P.D......B....X
4000000000104BF0 09 08 20 18 04 21 60 00 20 0E 73 C0 41 60 0C 84 .. ..!`. .s.A`..
4000000000104C00 11 08 00 02 18 10 00 00 00 02 00 03 80 2F 00 43 ............./.C
4000000000104C10 02 30 01 48 18 10 00 00 00 02 00 E0 61 02 20 80 .0.H........a. .
4000000000104C20 19 30 98 00 07 30 A0 04 98 00 42 03 60 2F 00 43 .0...0....B.`/.C
4000000000104C30 09 00 98 1C 90 11 00 00 00 02 00 C0 01 78 58 00 .............xX.
4000000000104C40 11 30 38 4C 07 38 00 00 00 02 80 03 40 2F 00 43 .08L.8......@/.C
4000000000104C50 11 00 00 00 01 00 00 00 00 02 00 00 F8 B2 F3 58 ...............X
4000000000104C60 09 08 20 18 04 21 00 00 00 02 00 E0 00 40 18 E6 .. ..!.......@..
4000000000104C70 11 08 00 02 18 10 00 00 00 02 00 03 50 FB FF 4A ............P..J
4000000000104C80 08 58 F2 FB CE 27 00 00 00 02 00 80 59 00 00 90 .X...'......Y...
4000000000104C90 09 50 02 00 00 21 00 00 00 02 00 20 14 00 00 90 .P...!..... ....
4000000000104CA0 11 58 02 96 18 10 00 00 00 02 00 00 C8 5E F1 58 .X...........^.X
4000000000104CB0 09 08 20 18 04 21 00 00 00 02 00 40 04 40 00 84 .. ..!.....@.@..
4000000000104CC0 11 08 00 02 18 10 00 00 00 02 00 00 88 6B F1 58 .............k.X
4000000000104CD0 09 08 20 18 04 21 A0 04 20 20 20 00 00 00 04 00 .. ..!..   .....
4000000000104CE0 11 08 00 02 18 10 00 00 00 02 00 00 C8 67 F1 58 .............g.X
4000000000104CF0 08 08 20 18 04 21 00 00 00 02 00 80 09 40 00 84 .. ..!.......@..
4000000000104D00 09 50 02 44 00 21 00 00 00 02 00 60 09 30 01 84 .P.D.!.....`.0..
4000000000104D10 11 08 00 02 18 10 00 00 00 02 00 00 78 88 FE 58 ............x..X
4000000000104D20 09 08 20 18 04 21 80 00 84 00 42 40 02 60 10 84 .. ..!....B@.`..
4000000000104D30 08 00 00 00 01 00 10 00 04 30 20 E0 9F 84 7F 0B .........0 .....
4000000000104D40 0B 98 00 24 18 10 00 00 00 02 00 00 80 04 AA 00 ...$............
4000000000104D50 02 00 00 00 01 00 00 98 04 55 00 00 70 0C 00 07 .........U..p...
4000000000104D60 19 00 00 00 01 00 C0 00 30 08 42 80 08 00 84 00 ........0.B.....
4000000000104D70 09 98 00 44 18 10 00 00 00 02 00 20 02 66 0C 84 ...D....... .f..
4000000000104D80 10 00 4C 22 98 11 00 00 00 02 00 00 40 FA FF 48 ..L"........@..H
4000000000104D90 09 00 00 00 01 00 E0 40 33 06 42 00 00 00 04 00 .......@3.B.....
4000000000104DA0 10 00 94 1C 90 11 00 00 00 02 00 00 20 FA FF 48 ............ ..H
4000000000104DB0 09 78 00 44 18 10 00 00 00 02 00 C0 81 63 0C 84 .x.D.........c..
4000000000104DC0 10 00 3C 1C 98 11 00 00 00 02 00 00 00 FA FF 48 ..<............H
4000000000104DD0 09 00 00 00 01 00 00 81 31 06 42 00 00 00 04 00 ........1.B.....
4000000000104DE0 10 00 94 20 90 11 00 00 00 02 00 00 E0 F9 FF 48 ... ...........H
4000000000104DF0 0B 70 00 44 18 10 E0 00 38 00 20 00 00 00 04 00 .p.D....8. .....
4000000000104E00 10 00 38 4E 80 11 00 00 00 02 00 00 C0 F9 FF 48 ..8N...........H
4000000000104E10 09 70 00 44 18 10 00 00 00 02 00 80 82 65 0C 84 .p.D.........e..
4000000000104E20 10 00 38 28 98 11 00 00 00 02 00 00 A0 F9 FF 48 ..8(...........H

l4000000000104E30:
	{ adds	r14,0x1C0,r12; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; (p07) addl	r14,8452,r1; (p07) addl	r15,-1,r0; }

l4000000000104E4C:
	{ Invalid; Invalid; break.b	0x1000; }

l4000000000104E50:
	{ (p07) st1	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,getifs; }

l4000000000104E56:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; (p04) nop; (p48) nop.b	0x8CE03 }
	{ Invalid; (p08) nop; break.i	0x80000 }
	{ (p08) addl	r0,282641,r0; (p09) nop; (p16) br.call.sptk.few	b0,b0 }

l4000000000104E90:
	{ ld8	r1,[r1]; cmp4.eq	p07,p06,0x0,r17; (p08) addl	r19,-6300,r1 }

l4000000000104EA0:
	{ adds	r17,0x190,r12; nop.i	0x0; (p06) addl	r20,-6300,r1 }

l4000000000104EB0:
	{ (p08) ld8	r19,[r19]; (p06) ld8	r20,[r20]; nop.i	0x0; }

l4000000000104EB6:
	{ (p10) fwb; cmp.ltu	p00,p00,0x0,r1; (p01) nop; }

l4000000000104EBC:
	{ nop; (p02) cmp.lt.unc	p32,p16,r4,r64; Invalid }

l4000000000104EC6:
	{ (p07) fwb; nop; nop }
	{ Invalid; (p07) nop; (p32) nop }
	{ break.m	0x4000; (p07) nop; (p32) nop }
	{ chk.a.nc	r0,3FFFFFFFFF1056F6; nop; nop }

l4000000000104F00:
	{ st4	[r0],r16; st4	[r0],r17; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000104F20:
	{ cmp4.eq	p06,p07,0x1,r14; nop.m	0x0; adds	r19,0x190,r12 }
	{ cmp4.eq	p08,p09,0x7F,r14; st8	[r15],r18; nop.i	0x0; }
	{ (p06) addl	r17,1,r0; ld4	r19,[r19]; (p08) addl	r14,1,r0 }

l4000000000104F46:
	{ (p09) nop; (p07) nop; Invalid }

l4000000000104F50:
	{ ld1	r16,[r15],1; (p07) adds	r17,0x0,r0; (p09) adds	r14,0x0,r0; }

l4000000000104F5C:
	{ Invalid; zxt1	r36,r3; nop; }

l4000000000104F60:
	{ or	r20,r19,r17; nop.m	0x0; adds	r19,0x190,r12; }
	{ st4	[r20],r19; nop.m	0x0; adds	r20,0x1A0,r12; }
	{ nop.m	0x0; ld4	r20,[r20]; nop.i	0x0; }
	{ or	r17,r20,r14; sxt1	r14,r16; adds	r20,0x1A0,r12; }
	{ st4	[r17],r20; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000104F20 }

l4000000000104FB0:
	{ addl	r74,112,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x208,r12; adds	r14,0x158,r12; cmp4.eq	p07,p06,0x0,r40; }
	{ nop.m	0x0; ld8	r1,[r1]; nop.i	0x0 }
	{ st8	[r8],r14; st1	[r0],r8; (p07) br.cond.dpnt.few	40000000001061F0; }

l4000000000104FF0:
	{ nop.m	0x0; addl	r74,-6252,r1; nop.i	0x0; }
	{ ld8	r74,[r74]; nop.i	0x0; br.call.sptk.many	b0,begin_unwind_frame; }
	{ adds	r1,0x208,r12; ld8	r1,[r1]; nop.i	0x0; }
	{ addl	r14,6516,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	40000000001050E0 }

l4000000000105050:
	{ addl	r35,5636,r1; nop.m	0x0; adds	r17,0x184,r12; }
	{ nop.m	0x0; ld4	r14,[r35]; nop.i	0x0; }
	{ cmp4.lt	p06,p07,r14,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001050E0; }

l4000000000105080:
	{ ld4	r74,[r17]; nop.i	0x0; br.call.sptk.many	b0,fd_is_bash_input; }
	{ adds	r1,0x208,r12; nop.m	0x0; cmp4.eq	p06,p07,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dptk.few	40000000001050E0 }

l40000000001050B0:
	{ ld4	r74,[r35]; nop.i	0x0; br.call.sptk.many	b0,sync_buffered_stream; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0; }

l40000000001050E0:
	{ nop.m	0x0; adds	r14,0x184,r12; nop.i	0x0; }
	{ ld4	r74,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C1C0; }
	{ addp4	r16,r8,r0; adds	r1,0x208,r12; adds	r15,0x1EC,r12; }
	{ cmp4.eq	p07,p06,0x0,r16; ld8	r1,[r1]; nop.i	0x0 }
	{ st4	[r8],r15; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000106140; }

l4000000000105130:
	{ nop.m	0x0; (p06) adds	r16,0x1F8,r12; nop.i	0x0; }

l400000000010513C:
	{ Invalid; Invalid; break.i	0x1000 }

l4000000000105146:
	{ break.m	0x4000; nop; break.i	0x80000 }

l4000000000105150:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p07) br.cond.dpnt.few	4000000000106AB0 }

l4000000000105160:
	{ adds	r20,0x1EC,r12; ld4	r20,[r20]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r20; (p06) br.cond.dptk.few	4000000000105FB0 }

l4000000000105180:
	{ adds	r14,0x1B0,r12; addl	r74,-9884,r1; nop.i	0x0 }
	{ addl	r16,1,r0; adds	r15,0x1B0,r12; adds	r75,0x0,r0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000105200; }

l40000000001051C0:
	{ nop.m	0x0; st4	[r16],r15; nop.i	0x0 }
	{ ld8	r74,[r74]; nop.m	0x0; br.call.sptk.many	b0,add_unwind_protect; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0 }

l4000000000105200:
	{ adds	r17,0x1B4,r12; nop.m	0x0; adds	r19,0x1D0,r12; }
	{ nop.m	0x0; ld4	r17,[r17]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r17; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000105250; }

l4000000000105230:
	{ nop.m	0x0; ld4	r19,[r19]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r19; (p06) br.cond.dptk.few	4000000000105640 }

l4000000000105250:
	{ adds	r20,0x184,r12; addl	r74,1,r0; adds	r76,0x10,r12; }
	{ ld4	r75,[r20]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B3C0; }
	{ adds	r1,0x208,r12; adds	r14,0x28,r12; cmp4.lt	p06,p07,r8,r0; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000105640; }

l4000000000105290:
	{ ld4	r15,[r14]; nop.m	0x0; addl	r14,61440,r0; }
	{ and	r15,r14,r15; nop.m	0x0; addl	r14,32768,r0; }
	{ cmp4.eq	p06,p07,r14,r15; adds	r14,0x1B4,r12; (p06) br.cond.dpnt.few	4000000000105640; }

l40000000001052C0:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	4000000000107150 }

l40000000001052E0:
	{ addl	r74,20532,r1; nop.m	0x0; addl	r75,1,r0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BD60; }
	{ adds	r1,0x208,r12; nop.m	0x0; cmp4.eq	p06,p07,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dptk.few	4000000000106000 }

l4000000000105320:
	{ adds	r34,0x158,r12; addl	r74,1,r0; adds	r55,0x0,r0 }
	{ addl	r33,142,r0; ld8	r14,[r34]; nop.i	0x0; }
	{ st1	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x208,r12; nop.m	0x0; adds	r35,0x0,r8; }
	{ ld8	r1,[r1]; st1	[r0],r8; nop.i	0x0; }
	{ nop.m	0x0; addl	r74,-6252,r1; nop.i	0x0; }
	{ ld8	r74,[r74]; nop.i	0x0; br.call.sptk.many	b0,run_unwind_frame; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; st8	[r35],r34; nop.i	0x0; }

l40000000001053B0:
	{ addl	r15,7672,r1; addl	r14,7668,r1; adds	r20,0x1D8,r12; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld8	r20,[r20]; nop.i	0x0; }
	{ ld4	r16,[r14]; cmp.eq	p06,p07,0x0,r20; adds	r74,0x0,r20 }
	{ ld4	r17,[r15]; adds	r17,0xFFFFFFFFFFFFFFFF,r17; adds	r16,0xFFFFFFFFFFFFFFFF,r16; }
	{ st4	[r17],r15; st4	[r16],r14; nop.i	0x0 }
	{ nop.b	0x0; (p06) br.cond.dpnt.few	4000000000107410; br.call.sptk.many	b0,legal_identifier; }

l400000000010541C:
	{ (p17) nop; invala; Invalid }
	{ cmp.eq	p08,p09,r6,r115; zxt1	r22,r64; nop }
	{ nop; nop; br.cond	b0; }
	{ (p55) cmpxchg4.acq	r4,[r33],r64; Invalid; break.i	0x1000 }

l4000000000105450:
	{ ld8	r74,[r15]; nop.i	0x0; br.call.sptk.many	b0,find_or_make_array_variable; }
	{ adds	r1,0x208,r12; nop.m	0x0; adds	r14,0x28,r8 }
	{ cmp.eq	p07,p06,0x0,r8; nop.m	0x0; adds	r34,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000108430; }

l4000000000105490:
	{ ld4	r14,[r14]; nop.m	0x0; tbit.z	p06,p07,r14,0x6 }
	{ adds	r14,0x8,r8; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000106B40; }

l40000000001054B0:
	{ ld8	r74,[r14]; nop.i	0x0; br.call.sptk.many	b0,array_flush; }
	{ adds	r17,0x1F0,r12; nop.m	0x0; adds	r14,0x158,r12 }
	{ adds	r1,0x208,r12; nop.m	0x0; adds	r76,0x0,r0; }
	{ ld8	r1,[r1]; ld8	r74,[r14]; nop.i	0x0; }
	{ ld8	r75,[r17]; nop.i	0x0; br.call.sptk.many	b0,list_string; }
	{ adds	r1,0x208,r12; nop.m	0x0; cmp.eq	p06,p07,0x0,r8 }
	{ adds	r35,0x0,r8; nop.m	0x0; adds	r74,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001055C0; }

l4000000000105530:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r55; (p06) br.cond.dptk.few	4000000000107EC0 }

l4000000000105540:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,dequote_list; }
	{ adds	r1,0x208,r12; nop.m	0x0; adds	r75,0x0,r35 }
	{ adds	r76,0x0,r0; nop.m	0x0; adds	r74,0x0,r34; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,assign_array_var_from_word_list; }
	{ adds	r1,0x208,r12; nop.m	0x0; adds	r74,0x0,r35; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,dispose_words; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0 }

l40000000001055C0:
	{ nop.m	0x0; adds	r14,0x158,r12; nop.i	0x0; }
	{ ld8	r74,[r14]; nop.i	0x0; br.call.sptk.many	b0,xfree; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0 }

l4000000000105600:
	{ adds	r8,0x0,r33; adds	r18,0x200,r12; mov	pr,r73,0xFFFFFFFFFFFFFFFE; }
	{ ld8	r19,[r18]; mov.i	ar.pfs,r72; mov.i	LC,r19; }
	{ nop.m	0x0; mov.spnt	b0,r71,4000000000105620; nop.i	0x0 }
	{ adds	r12,0x200,r12; nop.m	0x0; br.ret	b0; }

l4000000000105640:
	{ adds	r17,0x180,r12; adds	r19,0x1B4,r12; adds	r20,0x1D0,r12; }
	{ nop.m	0x0; ld4	r17,[r17]; nop.i	0x0 }
	{ st4	[r0],r19; st4	[r0],r20; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,0x0,r17; (p07) br.cond.dpnt.few	4000000000106670 }

l4000000000105680:
	{ adds	r19,0x1B0,r12; ld4	r19,[r19]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r19; (p06) br.cond.dptk.few	4000000000106110 }

l40000000001056A0:
	{ adds	r20,0x180,r12; addl	r33,-10548,r1; addl	r75,4,r0; }
	{ nop.m	0x0; ld4	r20,[r20]; nop.i	0x0; }
	{ cmp4.lt	p07,p06,0x0,r20; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000105720; }

l40000000001056D0:
	{ nop.m	0x0; ld8	r33,[r33]; nop.i	0x0; }
	{ adds	r74,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,unwind_protect_mem; }
	{ adds	r14,0x180,r12; adds	r1,0x208,r12; nop.i	0x0 }
	{ ld4	r14,[r14]; ld8	r1,[r1]; nop.i	0x0; }
	{ st4	[r14],r33; nop.m	0x0; nop.i	0x0 }

l4000000000105720:
	{ addl	r14,8452,r1; nop.m	0x0; adds	r34,0x0,r0; }
	{ ld1	r33,[r14]; nop.m	0x0; addl	r14,7796,r1; }
	{ cmp4.eq	p06,p07,0xA,r33; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000106130; }

l4000000000105750:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000107010; }

l4000000000105770:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C100; }
	{ nop.m	0x0; adds	r1,0x208,r12; zxt1	r16,r33 }
	{ adds	r14,0xD0,r8; adds	r15,0xD8,r8; adds	r75,0x0,r0; }
	{ ld8	r1,[r1]; nop.m	0x0; shladd	r8,r16,0x4,r8 }
	{ ld1	r19,[r14]; st1	[r0],r14; nop.i	0x0; }
	{ addl	r16,-10524,r1; adds	r14,0x0,r8; nop.b	0x0 }
	{ ld8	r18,[r15]; sxt1	r19,r19; addl	r74,-9132,r1; }
	{ nop.m	0x0; ld8	r16,[r16]; nop.i	0x0 }
	{ ld1	r17,[r14],8; st1	[r0],r8; nop.i	0x0; }
	{ st8	[r16],r15; addl	r16,8476,r1; sxt1	r17,r17 }
	{ ld8	r74,[r74]; st4	[r19],r16; addl	r16,8484,r1 }
	{ ld8	r15,[r14]; st8	[r18],r16; addl	r16,8492,r1; }
	{ st4	[r17],r16; nop.m	0x0; addl	r16,8500,r1; }
	{ st8	[r15],r16; nop.m	0x0; addl	r15,-10532,r1; }
	{ ld8	r15,[r15]; st8	[r15],r14; addl	r14,8508,r1; }
	{ st1	[r33],r14; nop.i	0x0; br.call.sptk.many	b0,add_unwind_protect; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000001058A0:
	{ addl	r74,-9884,r1; adds	r14,0x158,r12; nop.i	0x0 }
	{ ld8	r75,[r14]; ld8	r74,[r74]; br.call.sptk.many	b0,add_unwind_protect; }
	{ adds	r1,0x208,r12; nop.m	0x0; adds	r20,0x180,r12; }
	{ ld8	r1,[r1]; ld4	r20,[r20]; nop.i	0x0; }
	{ addl	r14,7668,r1; addl	r15,7672,r1; cmp4.lt	p07,p06,0x0,r20; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4	r16,[r14]; ld4	r17,[r15]; nop.i	0x0; }
	{ adds	r16,0x1,r16; nop.m	0x0; adds	r17,0x1,r17; }
	{ nop.m	0x0; st4	[r16],r14; adds	r14,0x1EC,r12 }
	{ st4	[r17],r15; adds	r15,0x1C0,r12; (p06) br.cond.dpnt.few	4000000000106860; }

l4000000000105940:
	{ ld4	r14,[r14]; ld4	r15,[r15]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; tbit.z.or.andcm	p07,p06,r15,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dptk.few	40000000001068B0; }

l4000000000105970:
	{ (p06) addl	r61,2,r0; nop.m	0x0; nop.i	0x0 }

l4000000000105976:
	{ break.m	0x4000; nop; (p16) nop }

l4000000000105980:
	{ adds	r17,0x1B8,r12; nop.m	0x0; adds	r19,0x1B0,r12; }
	{ nop.m	0x0; ld8	r17,[r17]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r17; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001059D0; }

l40000000001059B0:
	{ nop.m	0x0; ld4	r19,[r19]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r19; (p07) br.cond.dpnt.few	40000000001068C0 }

l40000000001059D0:
	{ adds	r14,0x1B8,r12; adds	r15,0x1EC,r12; adds	r17,0x1B0,r12 }
	{ adds	r19,0x1E0,r12; adds	r20,0x180,r12; adds	r16,0x1E8,r12; }
	{ ld8	r14,[r14]; addl	r60,7796,r1; addl	r58,-10644,r1 }
	{ addl	r64,-10516,r1; addl	r68,-6388,r1; addl	r52,-10652,r1; }
	{ cmp.eq	p07,p06,0x0,r14; ld4	r15,[r15]; addl	r70,-6244,r1 }
	{ addl	r57,-9884,r1; addl	r62,6516,r1; adds	r46,0x0,r0; }
	{ cmp4.eq	p31,p30,0x0,r15; (p06) adds	r65,0x0,r14; adds	r15,0x1A0,r12 }

l4000000000105A3C:
	{ (p16) cmp.lt	p12,p09,r3,r66; zxt1	r4,r64; (p02) dep	r0,r4,r4,63,9; }
	{ nop; (p02) movl	r32,0x27CEFB92010404; }

l4000000000105A56:
	{ Invalid; (p25) nop; (p16) nop.b	0xB }
	{ Invalid; (p16) nop; (p48) br.call.sptk.few	b4,b0 }
	{ Invalid; (p19) nop; nop }
	{ Invalid; (p29) nop; nop }
	{ Invalid; (p26) nop; (p16) nop }
	{ Invalid; (p11) nop; (p32) nop }
	{ Invalid; (p33) nop; nop }
	{ Invalid; (p09) nop; (p48) br.call.sptk.few	b3,b0 }
	{ Invalid; (p22) nop; (p16) nop.b	0xC30C }
	{ Invalid; (p24) cmp.ne.or	p60,p02,r12,r2; (p17) nop }

l4000000000105AF6:
	{ Invalid; (p31) nop; nop }
	{ Invalid; (p47) nop; break.b	0x80000 }
	{ break.m	0x4000; (p33) nop; break.i	0x80000 }
	{ (p29) fwb; nop; nop }
	{ (p34) fwb; nop; nop }
	{ (p35) fwb; nop; (p16) nop }
	{ break.m	0x4000; nop; break.i	0x80000 }

l4000000000105B60:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dptk.few	4000000000105EA0; }

l4000000000105B70:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000105B80:
	{ nop.m	0x0; sxt4	r14,r46; cmp.eq	p06,p07,0x0,r42 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dpnt.few	40000000001064D0; }

l4000000000105BA0:
	{ add	r14,r42,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001064A0; }

l4000000000105BD0:
	{ nop.m	0x0; st1	[r14],r36; (p07) adds	r46,0x1,r46 }

l4000000000105BE0:
	{ nop.m	0x0; adds	r14,0x4,r34; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r14,r40; (p07) br.cond.dpnt.few	40000000001062E0; }

l4000000000105C00:
	{ ld1	r14,[r36]; nop.m	0x0; cmp4.eq	p06,p07,0x0,r33; }
	{ nop.m	0x0; sxt1	r14,r14; (p06) br.cond.dptk.few	4000000000106370; }

l4000000000105C20:
	{ nop.m	0x0; cmp4.eq	p07,p06,0xA,r14; (p07) br.cond.dpnt.few	4000000000106470 }

l4000000000105C30:
	{ nop.m	0x0; sxt4	r16,r34; nop.i	0x0 }
	{ ld8	r15,[r37]; adds	r34,0x1,r34; add	r15,r15,r16; }
	{ st1	[r14],r15; nop.i	0x0; (p18) br.cond.dpnt.few	4000000000106460 }

l4000000000105C60:
	{ nop.m	0x0; sxt4	r50,r34; nop.i	0x0 }
	{ adds	r33,0x119,r12; addl	r35,1,r0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x208,r12; cmp.ltu	p07,p06,0x1,r8; nop.b	0x0 }
	{ adds	r47,0x0,r33; nop.m	0x0; mov.i	LC,0x10; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000105E50; }

l4000000000105CB0:
	{ ld8	r14,[r37]; ld1.a	r15,[r36]; nop.i	0x0; }
	{ add	r14,r14,r50; ld8.a	r54,[r37]; nop.i	0x0; }
	{ nop.m	0x0; st1	[r0],r14; nop.i	0x0 }
	{ st8	[r0],r39; ld1.c.clr	r15,[r36]; nop.i	0x0 }
	{ ld8.c.clr	r54,[r37]; st1	[r15],r49; nop.i	0x0 }

l4000000000105D00:
	{ ld8	r15,[r39]; adds	r74,0x178,r12; adds	r75,0x0,r49 }
	{ adds	r76,0x0,r35; adds	r77,0x0,r39; adds	r41,0x0,r35; }
	{ st8	[r15],r44; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r1,0x208,r12; nop.m	0x0; cmp.eq	p07,p06,0xFFFFFFFFFFFFFFFE,r8 }
	{ (p21) adds	r14,0x184,r12; nop.m	0x0; (p21) addl	r76,1,r0; }

l4000000000105D46:
	{ nop; (p38) nop; (p16) nop }

l4000000000105D50:
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001072F0; }

l4000000000105D60:
	{ nop.m	0x0; ld8	r15,[r44]; (p21) adds	r75,0x0,r48 }

l4000000000105D70:
	{ nop.m	0x0; (p21) ld4	r74,[r14]; nop.i	0x0; }

l4000000000105D7C:
	{ Invalid; Invalid; mov	pr,0xC001000 }
	{ (p58) cmp4.le.or.andcm	p07,p09,r0,r41; (p01) invala; nop }

l4000000000105D90:
	{ (p20) adds	r15,0x184,r12; nop.m	0x0; (p20) adds	r75,0x0,r48; }

l4000000000105D96:
	{ nop; (p37) nop; (p37) nop }

l4000000000105DA0:
	{ (p20) ld4	r74,[r15]; nop.i	0x0; (p20) br.call.dptk.many	b0,zreadc; }

l4000000000105DA6:
	{ nop; (p32) nop; (p16) nop }

l4000000000105DB0:
	{ adds	r1,0x208,r12; nop.m	0x0; cmp4.lt	p06,p07,r8,r0; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001072F0; }

l4000000000105DD0:
	{ ld1	r15,[r48]; adds	r41,0x1,r35; adds	r35,0x1,r35; }
	{ st1	[r47],r1,1; nop.i	0x0; br.cloop.sptk.few	4000000000105D00 }

l4000000000105DF0:
	{ sub	r15,r41,r56,0x1; cmp4.lt	p07,p06,0x1,r41; add	r14,r54,r50; }
	{ addp4	r15,r15,r0; nop.m	0x0; mov.i	LC,r15; }
	{ nop.m	0x0; (p07) mov.i	LC,r15; (p06) mov.i	LC,0x0; }

l4000000000105E1C:
	{ nop; cmp.eq	p00,p00,r32,r0; (p17) mov.i	KR0,0x8 }

l4000000000105E20:
	{ nop.m	0x0; ld1	r15,[r33],1; nop.i	0x0; }
	{ st1	[r14],r1,1; nop.i	0x0; br.cloop.sptk.few	4000000000105E20 }

l4000000000105E40:
	{ adds	r41,0xFFFFFFFFFFFFFFFF,r41; nop.i	0x0; add	r34,r34,r41 }

l4000000000105E50:
	{ adds	r14,0x180,r12; nop.m	0x0; adds	r38,0x1,r38; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r38,r14; (p06) br.cond.dpnt.few	4000000000106BE0 }

l4000000000105E80:
	{ adds	r33,0x0,r43; nop.m	0x0; nop.i	0x0 }

l4000000000105E90:
	{ nop.m	0x0; nop.i	0x0; (p17) br.cond.dptk.few	4000000000105B80; }

l4000000000105EA0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r45; (p06) br.cond.dptk.few	4000000000105F20; }

l4000000000105EB0:
	{ cmp.eq	p07,p06,0x0,r51; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000107200; }

l4000000000105EC0:
	{ nop.m	0x0; (p06) adds	r74,0x0,r51; nop.i	0x0 }

l4000000000105ECC:
	{ nop; Invalid; break.i	0x1000 }

l4000000000105ED6:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ (p37) fwb; nop; (p16) nop }
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; nop; (p16) br.call.sptk.few	b0,b0 }
	{ break.m	0x4000; nop; nop }

l4000000000105F20:
	{ adds	r16,0x184,r12; nop.m	0x0; adds	r75,0x0,r36 }
	{ nop.b	0x0; (p22) br.cond.dpnt.few	4000000000107390; (p26) br.cond.dpnt.few	4000000000107340; }

l4000000000105F3C:
	{ (p32) cmpxchg4.acq	r2,[r33],r64; Invalid; break.b	0x1000 }

l4000000000105F40:
	{ ld4	r74,[r16]; nop.i	0x0; br.call.sptk.many	b0,zreadc; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0 }

l4000000000105F70:
	{ cmp4.lt	p07,p06,0x0,r8; nop.m	0x0; adds	r14,0x4,r34 }
	{ adds	r45,0x0,r43; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000107D10; }

l4000000000105F90:
	{ nop.m	0x0; cmp4.lt	p06,p07,r14,r40; (p06) br.cond.dptk.few	4000000000105C00 }

l4000000000105FA0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000001062E0 }

l4000000000105FB0:
	{ nop.m	0x0; adds	r20,0x1E0,r12; nop.i	0x0; }
	{ st8	[r0],r20; nop.m	0x0; nop.i	0x0 }

l4000000000105FD0:
	{ adds	r15,0x1B0,r12; adds	r16,0x1D4,r12; adds	r17,0x1B8,r12; }
	{ st4	[r0],r15; st4	[r0],r16; nop.i	0x0; }
	{ st8	[r0],r17; nop.i	0x0; br.cond.sptk.few	4000000000105200 }

l4000000000106000:
	{ addl	r75,-6372,r1; nop.m	0x0; addl	r74,14,r0; }
	{ ld8	r75,[r75]; nop.i	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x208,r12; nop.m	0x0; adds	r75,0x0,r0; }
	{ ld8	r1,[r1]; addl	r14,8460,r1; addl	r74,-9140,r1; }
	{ nop.m	0x0; st8	[r8],r14; nop.i	0x0 }
	{ ld8	r74,[r74]; nop.m	0x0; br.call.sptk.many	b0,add_unwind_protect; }
	{ adds	r14,0x1B0,r12; nop.m	0x0; adds	r1,0x208,r12 }
	{ adds	r15,0x1B4,r12; nop.m	0x0; adds	r16,0x1D0,r12; }
	{ ld4	r14,[r14]; ld8	r1,[r1]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000106E90; }

l40000000001060A0:
	{ nop.m	0x0; ld4	r74,[r15]; nop.i	0x0 }
	{ ld4	r75,[r16]; nop.m	0x0; br.call.sptk.many	b0,falarm; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0 }

l40000000001060E0:
	{ adds	r17,0x180,r12; ld4	r17,[r17]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,0x0,r17; (p06) br.cond.dptk.few	4000000000105680 }

l4000000000106100:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000106670 }

l4000000000106110:
	{ adds	r15,0x1EC,r12; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p07) br.cond.dpnt.few	4000000000106F00 }

l4000000000106130:
	{ nop.m	0x0; adds	r34,0x0,r0; br.cond.sptk.few	40000000001058A0 }

l4000000000106140:
	{ adds	r17,0x184,r12; adds	r75,0x0,r0; addl	r76,1,r0; }
	{ ld4	r74,[r17]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AA20; }
	{ cmp.lt	p07,p06,r8,r0; nop.m	0x0; adds	r1,0x208,r12; }
	{ (p06) adds	r17,0x1F8,r12; ld8	r1,[r1]; nop.i	0x0; }

l4000000000106176:
	{ fwb; nop; (p01) br.call.spnt.few	b0,b0 }

l4000000000106186:
	{ chk.a.nc	r0,3FFFFFFFFF106986; nop; break.i	0x80000 }

l4000000000106190:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ ld4	r14,[r8]; adds	r1,0x208,r12; adds	r15,0x1F8,r12; }
	{ cmp4.eq	p06,p07,0x1D,r14; ld8	r1,[r1]; nop.i	0x0; }
	{ (p06) addl	r14,1,r0; (p07) adds	r14,0x0,r0; cmp.eq	p07,p06,0x0,r33; }

l40000000001061C6:
	{ Invalid; (p03) nop; nop; }

l40000000001061CC:
	{ invala; Invalid; mov	pr,r32,0x0 }
	{ (p60) invala; break.i	0x1000; break.b	0x1000 }

l40000000001061E0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000106AB0 }

l40000000001061F0:
	{ nop.m	0x0; addl	r74,-6260,r1; nop.i	0x0; }
	{ ld8	r74,[r74]; nop.i	0x0; br.call.sptk.many	b0,get_string_value; }
	{ adds	r14,0x150,r12; cmp.eq	p06,p07,0x0,r8; adds	r1,0x208,r12 }
	{ adds	r74,0x0,r8; adds	r75,0x170,r12; adds	r76,0x168,r12; }
	{ ld8	r1,[r1]; st8	[r8],r14; nop.i	0x0 }
	{ nop.b	0x0; (p06) br.cond.dpnt.few	4000000000104FF0; br.call.sptk.many	b0,uconvert; }

l400000000010624C:
	{ (p24) nop; invala; cmp.lt	p00,p00,r32,r0 }
	{ nop; Invalid; mov	pr,r32,0x0 }
	{ (p39) cmp.eq	p03,p08,r0,r33; zxt1	r28,r64; (p02) nop }

l4000000000106270:
	{ adds	r15,0x170,r12; adds	r16,0x168,r12; adds	r17,0x1D0,r12 }
	{ adds	r19,0x1B4,r12; ld8	r14,[r15]; nop.i	0x0; }
	{ cmp.lt	p06,p07,r14,r0; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000108370; }

l40000000001062A0:
	{ ld8	r15,[r16]; cmp.lt	p06,p07,r15,r0; nop.i	0x0; }
	{ (p06) st4	[r0],r17; (p07) st4	[r15],r17; nop.i	0x0; }

l40000000001062B6:
	{ mf.a; nop; add	r0,r0,r32; }

l40000000001062BC:
	{ nop; mov	pr,r32,0x0; Invalid }

l40000000001062CC:
	{ Invalid; Invalid; break.i	0x1000 }

l40000000001062D6:
	{ break.m	0x4000; nop; nop }

l40000000001062E0:
	{ adds	r40,0x80,r40; ld8	r74,[r37]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r75,r40; br.call.sptk.many	b0,xrealloc; }
	{ adds	r1,0x208,r12; ld8	r1,[r1]; nop.i	0x0 }
	{ st8	[r8],r37; nop.m	0x0; br.call.sptk.many	b0,remove_unwind_protect; }
	{ nop.m	0x0; adds	r1,0x208,r12; adds	r74,0x0,r57 }
	{ nop.m	0x0; ld8	r75,[r37]; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,add_unwind_protect; }
	{ adds	r1,0x208,r12; ld1	r14,[r36]; cmp4.eq	p06,p07,0x0,r33; }
	{ ld8	r1,[r1]; sxt1	r14,r14; (p07) br.cond.dptk.few	4000000000105C20; }

l4000000000106370:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5C,r14; (p07) br.cond.dpnt.few	4000000000107290 }

l4000000000106380:
	{ ld1	r15,[r53]; nop.m	0x0; zxt1	r16,r14; }
	{ cmp.eq	p06,p07,r15,r16; (p06) br.cond.dpnt.few	4000000000106BE0; (p24) br.cond.dptk.few	40000000001063B0; }

l400000000010639C:
	{ (p01) invala; cmp.lt	p00,p00,r32,r0; (p16) mov	pr,r99,0xE680 }

l40000000001063A0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x1,r14; (p06) br.cond.dpnt.few	40000000001063D0 }

l40000000001063B0:
	{ nop.m	0x0; nop.i	0x0; (p28) br.cond.dptk.few	4000000000105C30; }

l40000000001063C0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x7F,r14; (p06) br.cond.dptk.few	4000000000105C30 }

l40000000001063D0:
	{ nop.m	0x0; sxt4	r15,r34; nop.b	0x0 }
	{ ld8	r14,[r37]; adds	r34,0x1,r34; adds	r55,0x1,r55; }
	{ add	r14,r14,r15; nop.m	0x0; sxt4	r16,r34 }
	{ ld8.a	r15,[r37]; nop.m	0x0; adds	r34,0x1,r34; }
	{ nop.m	0x0; st1	[r63],r14; nop.i	0x0; }
	{ ld1	r14,[r36]; ld8.c.clr	r15,[r37]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; add	r15,r15,r16; }
	{ st1	[r14],r15; nop.i	0x0; (p19) br.cond.dptk.few	4000000000105C60; }

l4000000000106450:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000106460:
	{ adds	r38,0x1,r38; adds	r33,0x0,r43; br.cond.sptk.few	4000000000105E90 }

l4000000000106470:
	{ ld4	r14,[r62]; nop.m	0x0; adds	r34,0xFFFFFFFFFFFFFFFF,r34; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000105E80 }

l4000000000106490:
	{ (p30) addl	r45,1,r0; adds	r33,0x0,r66; br.cond.sptk.few	4000000000105B60 }

l4000000000106496:
	{ Invalid; nop; (p32) nop.b	0x2A012 }

l40000000001064A0:
	{ adds	r74,0x0,r42; nop.i	0x0; br.call.sptk.many	b0,xfree; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0 }

l40000000001064D0:
	{ nop.m	0x0; ld4	r14,[r60]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	4000000000106640 }

l40000000001064F0:
	{ nop.m	0x0; ld8	r14,[r58]; (p35) adds	r19,0x1E0,r12 }

l4000000000106500:
	{ adds	r74,0x0,r65; st8	[r0],r58; adds	r46,0x0,r56; }
	{ (p35) ld8	r19,[r19]; st8	[r14],r59; nop.i	0x0 }

l4000000000106516:
	{ mf.a; cmp4.ltu	p00,p00,r0,r1; (p40) cmp.ltu	p03,p06,r0,r16 }

l4000000000106526:
	{ mf.a; Invalid; cmp.lt	p00,p00,r0,r32 }

l400000000010652C:
	{ nop; nop; Invalid }

l400000000010653C:
	{ chk.s.m	r1,4000000000F4653C; Invalid; break.i	0x1000 }

l4000000000106546:
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ Invalid; nop; (p48) nop }
	{ mf.a; (p37) nop; nop }
	{ fwb; nop; Invalid }
	{ Invalid; (p32) nop; (p16) nop; }

l400000000010658C:
	{ (p10) nop; invala; nop }
	{ (p01) nop; (p05) invala; dep	r0,r32,r0,63,1; }
	{ nop; ldf8	f32,[r6]; (p09) break.i	0x16960; }
	{ (p02) cmp.eq.unc	p05,p08,r63,r44; (p17) cmp.lt	p32,p16,r10,r64; (p01) nop }
	{ nop; nop; }
	{ nop; (p05) nop; }
	{ nop; nop; Invalid; }
	{ cmp.eq	p00,p09,r1,r0; zxt1	r98,r0; Invalid }
	{ Invalid; Invalid; mov	pr,r32,0x0 }
	{ (p54) cmp.lt	p02,p11,r64,r32; Invalid; Invalid }

l4000000000106620:
	{ ld1	r14,[r8]; nop.m	0x0; sxt1	r14,r14; }
	{ st1	[r14],r36; nop.i	0x0; br.cond.sptk.few	4000000000105BE0 }

l4000000000106640:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,initialize_readline; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	40000000001064F0; }

l4000000000106670:
	{ addl	r14,8452,r1; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0xA,r14; (p07) br.cond.dptk.few	4000000000105680 }

l4000000000106690:
	{ adds	r15,0x1D4,r12; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; nop.i	0x0; }
	{ nop.m	0x0; (p06) adds	r34,0x0,r0; (p06) br.cond.dptk.few	40000000001067E0 }

l40000000001066BC:
	{ (p09) nop; (p02) nop; Invalid }

l40000000001066C0:
	{ adds	r16,0x184,r12; adds	r33,0xDC,r12; adds	r14,0x130,r12; }
	{ ld4	r74,[r16]; nop.m	0x0; adds	r75,0x0,r33; }
	{ st4	[r74],r14; nop.i	0x0; br.call.sptk.many	b0,ttgetattr; }
	{ adds	r14,0x138,r12; adds	r1,0x208,r12; addl	r76,60,r0 }
	{ adds	r74,0xA0,r12; adds	r75,0x0,r33; nop.i	0x0 }
	{ ld8	r1,[r1]; st8	[r33],r14; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ adds	r19,0x184,r12; adds	r1,0x208,r12; adds	r75,0xA0,r12; }
	{ nop.m	0x0; ld8	r1,[r1]; nop.i	0x0 }
	{ ld4	r74,[r19]; nop.m	0x0; br.call.sptk.many	b0,ttfd_noecho; }
	{ adds	r1,0x208,r12; adds	r34,0x0,r8; cmp4.lt	p07,p06,r8,r0; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dptk.few	40000000001067A0 }

l4000000000106770:
	{ addl	r74,1,r0; nop.i	0x0; br.call.sptk.many	b0,sh_ttyerror; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0; }

l40000000001067A0:
	{ addl	r74,-6380,r1; nop.m	0x0; adds	r75,0x130,r12; }
	{ ld8	r74,[r74]; nop.i	0x0; br.call.sptk.many	b0,add_unwind_protect; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0; }

l40000000001067E0:
	{ addl	r74,-9884,r1; adds	r14,0x158,r12; nop.i	0x0 }
	{ ld8	r75,[r14]; ld8	r74,[r74]; br.call.sptk.many	b0,add_unwind_protect; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; addl	r15,7672,r1; addl	r14,7668,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4	r17,[r15]; ld4	r16,[r14]; nop.i	0x0; }
	{ adds	r17,0x1,r17; nop.m	0x0; adds	r16,0x1,r16; }
	{ st4	[r17],r15; st4	[r16],r14; nop.i	0x0 }

l4000000000106860:
	{ addl	r14,8452,r1; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0xA,r14; (p06) br.cond.dptk.few	40000000001068B0 }

l4000000000106880:
	{ adds	r16,0x1F8,r12; ld4	r16,[r16]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r16; nop.i	0x0; }
	{ nop.m	0x0; (p06) adds	r61,0x0,r0; (p06) br.cond.dptk.few	4000000000105980; }

l40000000001068AC:
	{ (p07) invala; nop; zxt4	r0,r0 }

l40000000001068B0:
	{ nop.m	0x0; addl	r61,1,r0; br.cond.sptk.few	4000000000105980 }

l40000000001068C0:
	{ addl	r33,-10652,r1; adds	r74,0x0,r17; adds	r46,0x0,r0 }
	{ adds	r42,0x0,r0; adds	r51,0x0,r0; adds	r45,0x0,r0; }
	{ ld8	r33,[r33]; adds	r55,0x0,r0; addl	r40,112,r0 }
	{ adds	r38,0x0,r0; addl	r56,1,r0; adds	r36,0x17D,r12; }
	{ cmp4.eq	p22,p23,0x1,r61; adds	r43,0x0,r0; cmp4.eq	p26,p27,0x2,r61 }
	{ adds	r37,0x158,r12; adds	r39,0x148,r12; adds	r44,0x140,r12; }
	{ ld8	r75,[r33]; adds	r49,0x118,r12; cmp4.eq	p20,p21,0x0,r61 }
	{ adds	r48,0x17C,r12; addl	r63,1,r0; br.call.sptk.many	b0,fn400000000001C260; }
	{ adds	r1,0x208,r12; ld8	r74,[r33]; adds	r66,0x0,r0 }
	{ nop.m	0x0; adds	r33,0x0,r0; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ adds	r14,0x1B8,r12; adds	r15,0x1EC,r12; adds	r1,0x208,r12 }
	{ adds	r17,0x1B0,r12; adds	r19,0x1E0,r12; adds	r20,0x180,r12; }
	{ nop.m	0x0; ld8	r14,[r14]; adds	r16,0x1E8,r12 }
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r14; ld8	r1,[r1]; cmp4.eq	p31,p30,0x0,r15 }
	{ adds	r15,0x1A0,r12; ld4	r16,[r16]; nop.i	0x0; }
	{ (p06) adds	r65,0x0,r14; adds	r14,0x190,r12; addl	r60,7796,r1 }

l40000000001069D6:
	{ Invalid; (p30) nop; (p16) nop }
	{ Invalid; (p32) cmp.ne.or	p44,p15,r125,r45; (p17) nop }

l40000000001069F6:
	{ (p09) fwb; (p34) nop; nop }
	{ Invalid; (p28) nop; nop }
	{ Invalid; (p08) nop; (p32) nop }
	{ Invalid; (p26) nop; (p32) br.call.sptk.few	b3,b0 }
	{ Invalid; (p33) nop; nop }
	{ Invalid; (p47) nop; break.b	0x80000 }
	{ Invalid; (p12) cmp.eq.or	p00,p51,0xE,r24; (p17) br.call.sptk.few	b0,b0 }

l4000000000106A66:
	{ add	r0,r0,r1; (p14) nop; (p32) nop }
	{ (p32) fwb; nop; nop }
	{ (p26) fwb; Invalid; (p32) nop }
	{ break.m	0x4000; nop; (p16) nop }
	{ break.m	0x4000; nop; (p48) nop }

l4000000000106AB0:
	{ adds	r19,0x1B0,r12; ld4	r19,[r19]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r19; (p06) br.cond.dptk.few	4000000000105160; }

l4000000000106AD0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r34; (p07) br.cond.dptk.few	4000000000105FD0 }

l4000000000106AE0:
	{ adds	r17,0x1EC,r12; ld4	r17,[r17]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r17; (p07) br.cond.dptk.few	4000000000105200 }

l4000000000106B00:
	{ adds	r14,0x1E0,r12; adds	r15,0x1B0,r12; adds	r16,0x1D4,r12 }
	{ adds	r17,0x1B8,r12; st8	[r0],r14; nop.i	0x0 }
	{ st4	[r0],r15; nop.i	0x0; nop.i	0x0 }
	{ st4	[r0],r16; st8	[r0],r17; br.cond.sptk.few	4000000000105200 }

l4000000000106B40:
	{ addl	r75,-6228,r1; nop.m	0x0; addl	r76,5,r0 }
	{ adds	r74,0x0,r0; nop.m	0x0; addl	r33,1,r0; }
	{ ld8	r75,[r75]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r16,0x1D8,r12; adds	r1,0x208,r12; adds	r74,0x0,r8; }
	{ nop.m	0x0; ld8	r75,[r16]; nop.i	0x0 }
	{ ld8	r1,[r1]; nop.m	0x0; br.call.sptk.many	b0,builtin_error; }
	{ adds	r14,0x158,r12; adds	r1,0x208,r12; nop.i	0x0 }
	{ ld8	r1,[r1]; ld8	r74,[r14]; br.call.sptk.many	b0,xfree; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	4000000000105600 }

l4000000000106BE0:
	{ adds	r14,0x158,r12; sxt4	r34,r34; adds	r33,0x0,r0; }
	{ ld8	r14,[r14]; nop.i	0x0; add	r14,r14,r34; }
	{ st1	[r0],r14; nop.m	0x0; nop.i	0x0 }

l4000000000106C10:
	{ adds	r17,0x1B4,r12; nop.m	0x0; adds	r19,0x1D0,r12; }
	{ nop.m	0x0; ld4	r17,[r17]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r17; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000106C60; }

l4000000000106C40:
	{ nop.m	0x0; ld4	r19,[r19]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r19; (p06) br.cond.dptk.few	4000000000106C90 }

l4000000000106C60:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000104180; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0 }

l4000000000106C90:
	{ adds	r20,0x180,r12; ld4	r20,[r20]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,0x0,r20; (p07) br.cond.dpnt.few	4000000000106DB0 }

l4000000000106CB0:
	{ adds	r14,0x1B0,r12; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000001073D0 }

l4000000000106CD0:
	{ adds	r15,0x180,r12; nop.m	0x0; adds	r74,0x0,r0; }
	{ ld4	r15,[r15]; cmp4.lt	p07,p06,0x0,r15; nop.i	0x0; }
	{ nop.m	0x0; (p07) addl	r14,-10548,r1; nop.i	0x0; }

l4000000000106CFC:
	{ cmp4.eq.and	p00,p43,r1,r0; (p01) mov	pr,r3,0x4080; cmp.lt.unc	p00,p08,r3,r100 }

l4000000000106D06:
	{ mf.a; (p07) nop; break.i	0x80000; }

l4000000000106D0C:
	{ (p02) nop; cmp.lt	p00,p00,r32,r0; Invalid; }
	{ cmp.eq	p00,p17,r1,r0; czx1.r	r66,r65; mov	pr,r32,0x0 }
	{ Invalid; break.i	0x1000; break.i	0x1000 }

l4000000000106D30:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000104200; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0 }

l4000000000106D60:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r61; (p07) br.cond.dpnt.few	4000000000106E20; }

l4000000000106D70:
	{ nop.m	0x0; addl	r74,-6252,r1; nop.i	0x0; }
	{ ld8	r74,[r74]; nop.i	0x0; br.call.sptk.many	b0,discard_unwind_frame; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	40000000001053B0; }

l4000000000106DB0:
	{ addl	r14,8452,r1; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0xA,r14; (p07) br.cond.dptk.few	4000000000106CB0 }

l4000000000106DD0:
	{ adds	r17,0x1D4,r12; ld4	r17,[r17]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r17; (p07) br.cond.dptk.few	4000000000106D60 }

l4000000000106DF0:
	{ adds	r74,0x130,r12; nop.i	0x0; br.call.sptk.many	b0,fn4000000000104540; }
	{ adds	r1,0x208,r12; nop.m	0x0; cmp4.eq	p07,p06,0x0,r61; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dptk.few	4000000000106D70 }

l4000000000106E20:
	{ nop.m	0x0; adds	r19,0x184,r12; nop.i	0x0; }
	{ ld4	r74,[r19]; nop.i	0x0; br.call.sptk.many	b0,zsyncfd; }
	{ adds	r1,0x208,r12; ld8	r1,[r1]; nop.i	0x0; }
	{ nop.m	0x0; addl	r74,-6252,r1; nop.i	0x0; }
	{ ld8	r74,[r74]; nop.i	0x0; br.call.sptk.many	b0,discard_unwind_frame; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	40000000001053B0; }

l4000000000106E90:
	{ addl	r74,-6364,r1; nop.m	0x0; adds	r75,0x0,r0; }
	{ ld8	r74,[r74]; nop.i	0x0; br.call.sptk.many	b0,add_unwind_protect; }
	{ adds	r15,0x1B4,r12; adds	r16,0x1D0,r12; adds	r1,0x208,r12; }
	{ ld8	r1,[r1]; ld4	r74,[r15]; nop.i	0x0; }
	{ ld4	r75,[r16]; nop.i	0x0; br.call.sptk.many	b0,falarm; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	40000000001060E0 }

l4000000000106F00:
	{ adds	r16,0x184,r12; adds	r33,0xDC,r12; adds	r14,0x130,r12; }
	{ ld4	r74,[r16]; nop.m	0x0; adds	r75,0x0,r33; }
	{ st4	[r74],r14; nop.i	0x0; br.call.sptk.many	b0,ttgetattr; }
	{ adds	r14,0x138,r12; adds	r1,0x208,r12; adds	r74,0xA0,r12 }
	{ adds	r75,0x0,r33; addl	r76,60,r0; nop.i	0x0 }
	{ ld8	r1,[r1]; st8	[r33],r14; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ adds	r19,0x1D4,r12; nop.m	0x0; adds	r1,0x208,r12; }
	{ ld4	r19,[r19]; ld8	r1,[r1]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r19; (p06) br.cond.dptk.few	4000000000107FD0 }

l4000000000106F90:
	{ adds	r20,0x184,r12; nop.m	0x0; adds	r75,0xA0,r12; }
	{ ld4	r74,[r20]; nop.i	0x0; br.call.sptk.many	b0,ttfd_cbreak; }
	{ adds	r1,0x208,r12; nop.m	0x0; adds	r34,0x0,r8; }
	{ ld8	r1,[r1]; cmp4.lt	p07,p06,r34,r0; (p07) br.cond.dpnt.few	40000000001071A0; }

l4000000000106FD0:
	{ addl	r74,-6380,r1; nop.m	0x0; adds	r75,0x130,r12; }
	{ ld8	r74,[r74]; nop.i	0x0; br.call.sptk.many	b0,add_unwind_protect; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	40000000001058A0 }

l4000000000107010:
	{ adds	r34,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,initialize_readline; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C100; }
	{ nop.m	0x0; adds	r1,0x208,r12; zxt1	r16,r33 }
	{ adds	r14,0xD0,r8; adds	r15,0xD8,r8; adds	r75,0x0,r0; }
	{ ld8	r1,[r1]; nop.m	0x0; shladd	r8,r16,0x4,r8 }
	{ ld1	r19,[r14]; st1	[r0],r14; nop.i	0x0; }
	{ addl	r16,-10524,r1; adds	r14,0x0,r8; nop.b	0x0 }
	{ ld8	r18,[r15]; sxt1	r19,r19; addl	r74,-9132,r1; }
	{ nop.m	0x0; ld8	r16,[r16]; nop.i	0x0 }
	{ ld1	r17,[r14],8; st1	[r0],r8; nop.i	0x0; }
	{ st8	[r16],r15; addl	r16,8476,r1; sxt1	r17,r17 }
	{ ld8	r74,[r74]; st4	[r19],r16; addl	r16,8484,r1 }
	{ ld8	r15,[r14]; st8	[r18],r16; addl	r16,8492,r1; }
	{ st4	[r17],r16; nop.m	0x0; addl	r16,8500,r1; }
	{ st8	[r15],r16; nop.m	0x0; addl	r15,-10532,r1; }
	{ ld8	r15,[r15]; st8	[r15],r14; addl	r14,8508,r1; }
	{ st1	[r33],r14; nop.i	0x0; br.call.sptk.many	b0,add_unwind_protect; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	40000000001058A0 }

l4000000000107150:
	{ adds	r15,0x1D0,r12; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p07) br.cond.sptk.few	40000000001052E0 }

l4000000000107170:
	{ adds	r17,0x180,r12; ld4	r17,[r17]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,0x0,r17; (p06) br.cond.dptk.few	4000000000105680 }

l4000000000107190:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000106670 }

l40000000001071A0:
	{ addl	r74,1,r0; nop.i	0x0; br.call.sptk.many	b0,sh_ttyerror; }
	{ adds	r1,0x208,r12; nop.m	0x0; adds	r75,0x130,r12; }
	{ ld8	r1,[r1]; addl	r74,-6380,r1; nop.i	0x0; }
	{ ld8	r74,[r74]; nop.i	0x0; br.call.sptk.many	b0,add_unwind_protect; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	40000000001058A0 }

l4000000000107200:
	{ adds	r74,0x0,r70; nop.i	0x0; br.call.sptk.many	b0,get_string_value; }
	{ adds	r1,0x208,r12; nop.m	0x0; cmp.eq	p07,p06,0x0,r8 }
	{ ld8	r75,[r52]; nop.m	0x0; adds	r51,0x0,r8; }
	{ ld8	r1,[r1]; (p06) adds	r74,0x0,r8; (p07) addl	r74,-6300,r1; }

l400000000010723C:
	{ (p50) getf.s	r125,f78; (p09) nop; break.i	0x1000; }

l4000000000107240:
	{ (p07) ld8	r74,[r74]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C260; }

l4000000000107246:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ (p37) fwb; nop; (p16) nop }
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; nop; (p16) br.call.sptk.few	b0,b0 }
	{ break.m	0x4000; nop; break.i	0x80000 }

l4000000000107290:
	{ nop.m	0x0; nop.i	0x0; (p32) br.cond.dptk.few	4000000000106380 }

l40000000001072A0:
	{ nop.m	0x0; (p24) adds	r33,0x0,r56; (p24) br.cond.dptk.few	4000000000105B60 }

l40000000001072AC:
	{ (p06) invala; cmp.eq	p00,p00,r32,r0; (p01) break.i	0x16440 }

l40000000001072B0:
	{ nop.m	0x0; sxt4	r15,r34; nop.b	0x0 }
	{ ld8	r14,[r37]; adds	r55,0x1,r55; adds	r34,0x1,r34; }
	{ add	r14,r14,r15; nop.m	0x0; adds	r33,0x0,r56; }
	{ st1	[r63],r14; nop.i	0x0; br.cond.sptk.few	4000000000105B60 }

l40000000001072F0:
	{ sub	r15,r41,r56,0x1; nop.m	0x0; cmp4.eq	p07,p06,0x1,r35 }
	{ add	r14,r54,r50; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000105E40; }

l4000000000107310:
	{ addp4	r15,r15,r0; nop.m	0x0; cmp4.lt	p07,p06,0x1,r41; }
	{ nop.m	0x0; mov.i	LC,r15; (p07) mov.i	LC,r15; }

l4000000000107330:
	{ nop.m	0x0; (p06) mov.i	LC,0x0; br.cond.sptk.few	4000000000105E20 }

l400000000010733C:
	{ (p23) cmp.lt.unc	p61,p09,r63,r36; (p01) shladd	r0,r99,0x1,r64; nop }

l4000000000107340:
	{ adds	r14,0x180,r12; adds	r20,0x184,r12; adds	r75,0x0,r36; }
	{ ld4	r14,[r14]; ld4	r74,[r20]; nop.i	0x0; }
	{ sub	r76,r14,r38; nop.i	0x0; br.call.sptk.many	b0,zreadcn; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	4000000000105F70 }

l4000000000107390:
	{ adds	r15,0x184,r12; adds	r75,0x0,r36; addl	r76,1,r0; }
	{ ld4	r74,[r15]; nop.i	0x0; br.call.sptk.many	b0,zread; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	4000000000105F70 }

l40000000001073D0:
	{ adds	r16,0x1EC,r12; ld4	r16,[r16]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r16; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000106DF0; }

l40000000001073F0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r61; (p06) br.cond.dptk.few	4000000000106D70 }

l4000000000107400:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000106E20 }

l4000000000107410:
	{ adds	r19,0x188,r12; adds	r20,0x1F0,r12; adds	r15,0x158,r12 }
	{ addl	r17,23540,r1; ld8	r19,[r19]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r19; nop.i	0x0; (p07) br.cond.dpnt.few	40000000001080B0; }

l4000000000107440:
	{ ld8	r20,[r20]; ld8	r42,[r15]; nop.i	0x0; }
	{ adds	r15,0x0,r42; ld1	r14,[r20]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	40000000001084B0; }

l4000000000107480:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000001074A0:
	{ adds	r16,0x0,r15; ld1	r14,[r15],1; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x20,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x9,r14; (p06) br.cond.dptk.few	40000000001074E0; }

l40000000001074D0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0xA,r14; (p06) br.cond.dpnt.few	4000000000107510 }

l40000000001074E0:
	{ nop.m	0x0; zxt1	r14,r14; add	r14,r17,r14; }
	{ nop.m	0x0; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000001074A0 }

l4000000000107510:
	{ adds	r15,0x188,r12; adds	r37,0x158,r12; addl	r40,-6300,r1 }
	{ adds	r39,0x150,r12; cmp4.eq	p16,p17,0x0,r55; addl	r38,-4097,r0; }
	{ nop.m	0x0; ld8	r15,[r15]; nop.i	0x0; }
	{ ld8	r14,[r15]; st8	[r16],r37; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	4000000000107750; }

l4000000000107560:
	{ ld8	r40,[r40]; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000107580:
	{ adds	r16,0x188,r12; ld8	r16,[r16]; nop.i	0x0; }
	{ adds	r14,0x8,r16; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; ld8	r34,[r14]; nop.i	0x0; }
	{ adds	r74,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,legal_identifier; }
	{ adds	r1,0x208,r12; nop.m	0x0; cmp4.eq	p07,p06,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000107970 }

l40000000001075E0:
	{ ld8	r14,[r37]; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000107A50 }

l4000000000107610:
	{ adds	r14,0x1F0,r12; adds	r76,0x0,r39; adds	r74,0x0,r37; }
	{ ld8	r75,[r14]; nop.i	0x0; br.call.sptk.many	b0,get_word_from_string; }
	{ adds	r1,0x208,r12; cmp.eq	p06,p07,0x0,r8; nop.i	0x0 }
	{ adds	r36,0x0,r8; adds	r74,0x0,r34; adds	r75,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000107A50; }

l4000000000107660:
	{ nop.m	0x0; ld8	r14,[r39]; nop.i	0x0; }
	{ st1	[r0],r14; (p17) br.cond.dpnt.few	4000000000107A80; br.call.sptk.many	b0,fn4000000000104400; }

l400000000010767C:
	{ (p44) nop; ldfs	f2,[r65]; (p04) br.cond.sptk.few	400000000052769C }
	{ nop; nop; break.i	0x1000; }
	{ (p10) nop; nop; epc }
	{ nop; Invalid; break.i	0x1000 }
	{ cmp.eq	p00,p08,r1,r0; czx1.r	r96,r65; dep	r0,r32,r0,63,1 }

l40000000001076C0:
	{ cmp.eq	p07,p06,0x0,r35; nop.m	0x0; adds	r74,0x0,r34 }
	{ adds	r35,0x28,r35; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000107E60; }

l40000000001076E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,stupidly_hack_special_variables; }
	{ adds	r15,0x188,r12; ld4	r14,[r35]; adds	r1,0x208,r12; }
	{ ld8	r15,[r15]; ld8	r1,[r1]; nop.i	0x0; }
	{ ld8	r16,[r15]; nop.m	0x0; adds	r15,0x188,r12; }
	{ st8	[r16],r15; nop.m	0x0; and	r15,r38,r14; }
	{ ld8	r14,[r16]; st4	[r15],r35; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000107580 }

l4000000000107750:
	{ adds	r19,0x188,r12; ld8	r19,[r19]; nop.i	0x0; }
	{ adds	r34,0x8,r19; ld8	r14,[r34]; nop.i	0x0; }
	{ ld8	r74,[r14]; nop.i	0x0; br.call.sptk.many	b0,legal_identifier; }
	{ adds	r1,0x208,r12; nop.m	0x0; cmp4.eq	p07,p06,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p07) br.cond.dpnt.few	40000000001079D0 }

l40000000001077A0:
	{ adds	r36,0x158,r12; nop.m	0x0; adds	r35,0x0,r0; }
	{ ld8	r34,[r36]; ld1	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000001081E0; }

l40000000001077E0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r55; (p07) br.cond.dptk.few	4000000000108020 }

l40000000001077F0:
	{ adds	r16,0x188,r12; ld8	r16,[r16]; nop.i	0x0; }
	{ adds	r14,0x8,r16; ld8	r14,[r14]; nop.i	0x0 }
	{ nop.m	0x0; ld8	r74,[r14]; nop.i	0x0 }

l4000000000107820:
	{ adds	r75,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn4000000000104400; }
	{ adds	r1,0x208,r12; nop.m	0x0; adds	r34,0x0,r8; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0 }

l4000000000107850:
	{ cmp.eq	p06,p07,0x0,r34; adds	r19,0x188,r12; adds	r34,0x28,r34; }
	{ (p06) addl	r33,1,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001078D0; }

l4000000000107866:
	{ chk.a.nc	r0,3FFFFFFFFF108066; nop; (p48) nop }

l4000000000107870:
	{ ld8	r19,[r19]; adds	r14,0x8,r19; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r74,[r14]; nop.i	0x0; br.call.sptk.many	b0,stupidly_hack_special_variables; }
	{ ld4	r14,[r34]; addl	r15,-4097,r0; adds	r1,0x208,r12; }
	{ nop.m	0x0; and	r14,r15,r14; nop.i	0x0 }
	{ ld8	r1,[r1]; st4	[r14],r34; nop.i	0x0 }

l40000000001078D0:
	{ cmp.eq	p06,p07,0x0,r35; adds	r74,0x0,r35; (p06) br.cond.dpnt.few	4000000000107910; }

l40000000001078E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0 }

l4000000000107910:
	{ adds	r74,0x0,r42; nop.i	0x0; br.call.sptk.many	b0,xfree; }
	{ adds	r1,0x208,r12; adds	r8,0x0,r33; adds	r18,0x200,r12; }
	{ nop.m	0x0; ld8	r1,[r1]; mov	pr,r73,0xFFFFFFFFFFFFFFFE }
	{ ld8	r19,[r18]; nop.m	0x0; mov.i	ar.pfs,r72; }
	{ nop.m	0x0; mov.i	LC,r19; mov.spnt	b0,r71,4000000000107950 }
	{ nop.m	0x0; adds	r12,0x200,r12; br.ret	b0; }

l4000000000107970:
	{ adds	r74,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,valid_array_reference; }
	{ adds	r1,0x208,r12; nop.m	0x0; cmp4.eq	p07,p06,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dptk.few	40000000001075E0 }

l40000000001079A0:
	{ adds	r74,0x0,r34; addl	r33,1,r0; br.call.sptk.many	b0,sh_invalidid; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	4000000000107910 }

l40000000001079D0:
	{ nop.m	0x0; ld8	r14,[r34]; nop.i	0x0; }
	{ ld8	r74,[r14]; nop.i	0x0; br.call.sptk.many	b0,valid_array_reference; }
	{ adds	r1,0x208,r12; nop.m	0x0; cmp4.eq	p07,p06,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dptk.few	40000000001077A0 }

l4000000000107A10:
	{ ld8	r14,[r34]; nop.m	0x0; addl	r33,1,r0; }
	{ ld8	r74,[r14]; nop.i	0x0; br.call.sptk.many	b0,sh_invalidid; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	4000000000107910 }

l4000000000107A50:
	{ adds	r74,0x0,r34; adds	r75,0x0,r40; br.call.sptk.many	b0,fn4000000000104400; }
	{ adds	r1,0x208,r12; nop.m	0x0; adds	r35,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	40000000001076C0 }

l4000000000107A80:
	{ adds	r74,0x0,r8; nop.i	0x0; br.call.sptk.many	b0,dequote_string; }
	{ adds	r1,0x208,r12; nop.m	0x0; adds	r75,0x0,r8 }
	{ adds	r41,0x0,r8; nop.m	0x0; adds	r74,0x0,r34; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000104400; }
	{ adds	r1,0x208,r12; adds	r35,0x0,r8; adds	r74,0x0,r41; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,xfree; }
	{ adds	r1,0x208,r12; nop.m	0x0; adds	r74,0x0,r36; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	40000000001076C0 }

l4000000000107B20:
	{ adds	r14,0x1D8,r12; nop.m	0x0; addl	r33,1,r0; }
	{ ld8	r74,[r14]; nop.i	0x0; br.call.sptk.many	b0,sh_invalidid; }
	{ adds	r14,0x158,r12; adds	r1,0x208,r12; nop.i	0x0 }
	{ ld8	r1,[r1]; ld8	r74,[r14]; br.call.sptk.many	b0,xfree; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	4000000000105600; }
4000000000107B80 08 58 D2 FB CE 27 00 00 00 02 00 40 09 00 00 84 .X...'.....@....
4000000000107B90 09 60 16 00 00 24 00 00 00 02 00 20 14 00 00 90 .`...$..... ....
4000000000107BA0 11 58 02 96 18 10 00 00 00 02 00 00 C8 2F F1 58 .X.........../.X
4000000000107BB0 09 08 20 18 04 21 00 00 00 02 00 40 09 40 00 84 .. ..!.....@.@..
4000000000107BC0 0B 08 00 02 18 10 E0 20 05 90 48 00 00 00 04 00 ....... ..H.....
4000000000107BD0 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000107BE0 11 58 02 1C 18 10 00 00 00 02 00 00 A8 59 FE 58 .X...........Y.X
4000000000107BF0 09 00 00 00 01 00 10 40 30 08 42 00 00 00 04 00 .......@0.B.....
4000000000107C00 08 08 00 02 18 10 00 00 00 02 00 00 00 00 04 00 ................
4000000000107C10 09 40 00 42 00 21 20 01 30 08 42 E0 9F 84 7F 0B .@.B.! .0.B.....
4000000000107C20 03 98 00 24 18 10 00 40 02 55 00 00 30 09 AA 00 ...$...@.U..0...
4000000000107C30 00 00 00 00 01 00 00 38 06 80 03 00 00 00 04 00 .......8........
4000000000107C40 18 60 00 18 04 21 00 00 00 02 00 80 08 00 84 00 .`...!..........
4000000000107C50 08 58 B2 FB CE 27 00 00 00 02 00 80 59 00 00 90 .X...'......Y...
4000000000107C60 09 50 02 00 00 21 00 00 00 02 00 20 14 00 00 90 .P...!..... ....
4000000000107C70 11 58 02 96 18 10 00 00 00 02 00 00 F8 2E F1 58 .X.............X
4000000000107C80 09 08 20 18 04 21 00 00 00 02 00 40 09 40 00 84 .. ..!.....@.@..
4000000000107C90 0B 08 00 02 18 10 E0 20 05 90 48 00 00 00 04 00 ....... ..H.....
4000000000107CA0 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000107CB0 11 58 02 1C 18 10 00 00 00 02 00 00 D8 58 FE 58 .X...........X.X
4000000000107CC0 09 00 00 00 01 00 10 40 30 08 42 00 00 00 04 00 .......@0.B.....
4000000000107CD0 10 08 00 02 18 10 00 00 00 02 00 00 40 FF FF 48 ............@..H

l4000000000107CE0:
	{ adds	r14,0x158,r12; sxt4	r34,r34; addl	r33,1,r0; }
	{ ld8	r14,[r14]; add	r14,r14,r34; nop.i	0x0; }
	{ st1	[r0],r14; nop.i	0x0; br.cond.sptk.few	4000000000106C10 }

l4000000000107D10:
	{ adds	r14,0x158,r12; sxt4	r34,r34; cmp4.lt	p07,p06,r8,r0; }
	{ ld8	r14,[r14]; (p06) addl	r33,1,r0; add	r14,r14,r34; }

l4000000000107D2C:
	{ (p07) invala; Invalid; mov	pr,r32,0x0; }
	{ (p55) ldf8	f125,[r37]; Invalid; add	r0,r32,r0 }

l4000000000107D40:
	{ addl	r75,-6236,r1; nop.m	0x0; addl	r76,5,r0 }
	{ adds	r74,0x0,r0; nop.m	0x0; addl	r33,1,r0; }
	{ ld8	r75,[r75]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x208,r12; nop.m	0x0; adds	r34,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ adds	r1,0x208,r12; ld4	r74,[r8]; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B4A0; }
	{ adds	r16,0x184,r12; nop.m	0x0; adds	r1,0x208,r12 }
	{ adds	r76,0x0,r8; adds	r74,0x0,r34; nop.i	0x0 }
	{ ld4	r75,[r16]; ld8	r1,[r1]; br.call.sptk.many	b0,builtin_error; }
	{ adds	r1,0x208,r12; ld8	r1,[r1]; nop.i	0x0; }
	{ nop.m	0x0; addl	r74,-6252,r1; nop.i	0x0; }
	{ ld8	r74,[r74]; nop.i	0x0; br.call.sptk.many	b0,run_unwind_frame; }
	{ adds	r1,0x208,r12; adds	r8,0x0,r33; adds	r18,0x200,r12; }
	{ nop.m	0x0; ld8	r1,[r1]; mov	pr,r73,0xFFFFFFFFFFFFFFFE }
	{ ld8	r19,[r18]; nop.m	0x0; mov.i	ar.pfs,r72; }
	{ nop.m	0x0; mov.i	LC,r19; mov.spnt	b0,r71,4000000000107E40 }
	{ nop.m	0x0; adds	r12,0x200,r12; br.ret	b0; }

l4000000000107E60:
	{ adds	r74,0x0,r42; addl	r33,1,r0; br.call.sptk.many	b0,xfree; }
	{ adds	r1,0x208,r12; adds	r8,0x0,r33; adds	r18,0x200,r12; }
	{ nop.m	0x0; ld8	r1,[r1]; mov	pr,r73,0xFFFFFFFFFFFFFFFE }
	{ ld8	r19,[r18]; nop.m	0x0; mov.i	ar.pfs,r72; }
	{ nop.m	0x0; mov.i	LC,r19; mov.spnt	b0,r71,4000000000107EA0 }
	{ nop.m	0x0; adds	r12,0x200,r12; br.ret	b0; }

l4000000000107EC0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,word_list_remove_quoted_nulls; }
	{ adds	r1,0x208,r12; nop.m	0x0; adds	r75,0x0,r35 }
	{ adds	r76,0x0,r0; nop.m	0x0; adds	r74,0x0,r34; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,assign_array_var_from_word_list; }
	{ adds	r1,0x208,r12; nop.m	0x0; adds	r74,0x0,r35; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,dispose_words; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	40000000001055C0 }

l4000000000107F40:
	{ adds	r20,0x1D0,r12; adds	r14,0x1B4,r12; nop.i	0x0 }
	{ st4	[r0],r20; st4	[r0],r14; br.cond.sptk.few	4000000000104FF0 }

l4000000000107F60:
	{ adds	r14,0x1A0,r12; adds	r15,0x190,r12; addl	r74,112,r0; }
	{ nop.m	0x0; st4	[r0],r14; nop.i	0x0 }
	{ st4	[r0],r15; nop.m	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x208,r12; adds	r14,0x158,r12; cmp4.eq	p07,p06,0x0,r40; }
	{ nop.m	0x0; ld8	r1,[r1]; nop.i	0x0 }
	{ st8	[r8],r14; st1	[r0],r8; (p06) br.cond.dptk.few	4000000000104FF0 }

l4000000000107FC0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000001061F0 }

l4000000000107FD0:
	{ adds	r14,0x184,r12; nop.m	0x0; adds	r75,0xA0,r12; }
	{ ld4	r74,[r14]; nop.i	0x0; br.call.sptk.many	b0,ttfd_onechar; }
	{ adds	r1,0x208,r12; nop.m	0x0; adds	r34,0x0,r8; }
	{ ld8	r1,[r1]; cmp4.lt	p07,p06,r34,r0; (p06) br.cond.dptk.few	4000000000106FD0 }

l4000000000108010:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000001071A0; }

l4000000000108020:
	{ adds	r17,0x188,r12; nop.m	0x0; cmp.eq	p07,p06,0x0,r34; }
	{ ld8	r17,[r17]; adds	r14,0x8,r17; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r74,[r14]; nop.i	0x0; (p06) br.cond.dptk.few	4000000000107820 }

l4000000000108060:
	{ nop.m	0x0; addl	r34,-6300,r1; nop.i	0x0; }
	{ ld8	r34,[r34]; nop.m	0x0; nop.i	0x0; }

l4000000000108080:
	{ adds	r75,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn4000000000104400; }
	{ adds	r1,0x208,r12; nop.m	0x0; adds	r34,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	4000000000107850 }

l40000000001080B0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r55; (p06) br.cond.dptk.few	4000000000108390 }

l40000000001080C0:
	{ nop.m	0x0; adds	r14,0x158,r12; nop.i	0x0; }
	{ ld8	r74,[r14]; nop.i	0x0; br.call.sptk.many	b0,dequote_string; }
	{ adds	r1,0x208,r12; adds	r75,0x0,r8; adds	r76,0x0,r0 }
	{ adds	r34,0x0,r8; ld8	r1,[r1]; nop.i	0x0; }
	{ nop.m	0x0; addl	r74,-6220,r1; nop.i	0x0; }
	{ ld8	r74,[r74]; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r1,0x208,r12; adds	r35,0x0,r8; adds	r74,0x0,r34; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r14,0x28,r35; adds	r16,0x158,r12; adds	r1,0x208,r12; }
	{ ld4	r15,[r14]; ld8	r74,[r16]; addl	r16,-4097,r0; }
	{ and	r15,r16,r15; ld8	r1,[r1]; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0 }

l40000000001081A0:
	{ adds	r8,0x0,r33; adds	r18,0x200,r12; mov	pr,r73,0xFFFFFFFFFFFFFFFE; }
	{ ld8	r19,[r18]; mov.i	ar.pfs,r72; mov.i	LC,r19; }
	{ nop.m	0x0; mov.spnt	b0,r71,40000000001081C0; nop.i	0x0 }
	{ adds	r12,0x200,r12; nop.m	0x0; br.ret	b0; }

l40000000001081E0:
	{ adds	r14,0x1F0,r12; adds	r74,0x0,r36; adds	r76,0x150,r12; }
	{ ld8	r75,[r14]; nop.i	0x0; br.call.sptk.many	b0,get_word_from_string; }
	{ ld8	r14,[r36]; adds	r1,0x208,r12; adds	r35,0x0,r8; }
	{ ld8	r1,[r1]; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000108330; }

l4000000000108240:
	{ nop.m	0x0; (p07) st8	[r8],r36; (p07) adds	r34,0x0,r8 }

l400000000010824C:
	{ Invalid; nop }

l4000000000108250:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r55; (p06) br.cond.dptk.few	4000000000108020; }

l4000000000108260:
	{ cmp.eq	p06,p07,0x0,r34; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000108470; }

l4000000000108270:
	{ ld1	r14,[r34]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000001077F0 }

l4000000000108290:
	{ adds	r74,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,dequote_string; }
	{ adds	r16,0x188,r12; nop.m	0x0; adds	r1,0x208,r12 }
	{ adds	r36,0x0,r8; nop.m	0x0; adds	r75,0x0,r8; }
	{ ld8	r16,[r16]; ld8	r1,[r1]; nop.i	0x0; }
	{ adds	r14,0x8,r16; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r74,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000104400; }
	{ adds	r1,0x208,r12; adds	r34,0x0,r8; adds	r74,0x0,r36; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,xfree; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	4000000000107850 }

l4000000000108330:
	{ adds	r15,0x1F0,r12; adds	r74,0x0,r34; adds	r76,0x0,r55; }
	{ ld8	r75,[r15]; nop.i	0x0; br.call.sptk.many	b0,strip_trailing_ifs_whitespace; }
	{ adds	r1,0x208,r12; adds	r34,0x0,r8; nop.i	0x0 }
	{ ld8	r1,[r1]; st8	[r8],r36; br.cond.sptk.few	4000000000108250 }

l4000000000108370:
	{ adds	r15,0x1D0,r12; adds	r16,0x1B4,r12; nop.i	0x0 }
	{ st4	[r0],r15; st4	[r0],r16; br.cond.sptk.few	4000000000104FF0 }

l4000000000108390:
	{ adds	r14,0x158,r12; addl	r74,-6220,r1; adds	r76,0x0,r0; }
	{ nop.m	0x0; ld8	r75,[r14]; nop.i	0x0 }
	{ ld8	r74,[r74]; nop.m	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r35,0x0,r8; adds	r16,0x158,r12; adds	r1,0x208,r12; }
	{ adds	r14,0x28,r35; ld8	r74,[r16]; addl	r16,-4097,r0 }
	{ ld8	r1,[r1]; ld4	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; and	r15,r16,r15; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	40000000001081A0 }

l4000000000108430:
	{ adds	r14,0x158,r12; nop.m	0x0; addl	r33,1,r0; }
	{ ld8	r74,[r14]; nop.i	0x0; br.call.sptk.many	b0,xfree; }
	{ nop.m	0x0; adds	r1,0x208,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	4000000000105600; }

l4000000000108470:
	{ adds	r15,0x188,r12; nop.m	0x0; addl	r34,-6300,r1; }
	{ ld8	r15,[r15]; ld8	r34,[r34]; nop.i	0x0; }
	{ adds	r14,0x8,r15; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r74,[r14]; nop.i	0x0; br.cond.sptk.few	4000000000108080 }

l40000000001084B0:
	{ nop.m	0x0; adds	r16,0x0,r42; br.cond.sptk.few	4000000000107510; }

;; return_builtin: 40000000001084C0
return_builtin proc
	{ alloc	r34,ar.pfs,0x7,0x0,0x4; nop.m	0x0; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; adds	r36,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,no_options; }
	{ cmp4.eq	p07,p06,0x0,r8; adds	r1,0x0,r35; mov.i	ar.pfs,r34 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000108520; }

l4000000000108510:
	{ (p06) addl	r8,258,r0; mov.spnt	b0,r33,4000000000108510; br.ret	b0 }

l4000000000108516:
	{ Invalid; (p34) nop; (p32) nop }

l4000000000108520:
	{ addl	r14,9268,r1; nop.m	0x0; nop.i	0x0; }
	{ ld8	r36,[r14]; nop.i	0x0; br.call.sptk.many	b0,get_exitstat; }
	{ adds	r1,0x0,r35; addl	r14,9032,r1; addl	r15,9012,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4	r14,[r14]; st4	[r8],r15; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; (p07) addl	r36,22740,r1; (p07) addl	r37,1,r0; }

l400000000010857C:
	{ Invalid; Invalid; Invalid }

l4000000000108580:
	{ nop.m	0x0; nop.i	0x0; (p07) br.call.spnt.many	b0,fn400000000001BBE0; }

l4000000000108590:
	{ addl	r37,756,r1; addl	r38,5,r0; adds	r36,0x0,r0; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r35; adds	r36,0x0,r8; br.call.sptk.many	b0,builtin_error; }
	{ addl	r8,1,r0; adds	r1,0x0,r35; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000001085D0; br.ret	b0; }
40000000001085E0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000001085F0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
4000000000108600 08 10 1D 08 80 05 60 68 81 0E 73 C0 81 0B C8 90 ......`h..s.....
4000000000108610 09 20 D1 FA BC 27 50 E2 F5 79 4F 60 04 08 00 84 . ...'P..yO`....
4000000000108620 08 00 00 00 01 80 01 0A 00 00 48 20 04 00 C4 00 ..........H ....
4000000000108630 09 30 01 00 00 21 40 02 90 30 20 00 00 00 04 00 .0...!@..0 .....
4000000000108640 EA 00 01 00 00 21 00 00 00 02 00 E0 00 00 19 E4 .....!..........
4000000000108650 19 00 00 00 01 00 00 00 39 20 A3 03 60 00 00 43 ........9 ..`..C
4000000000108660 11 28 01 4A 18 10 00 00 00 02 00 00 68 FD F5 58 .(.J........h..X
4000000000108670 0B 08 00 46 00 21 40 A2 F5 79 4F 00 00 00 04 00 ...F.!@..yO.....
4000000000108680 11 20 01 48 18 10 00 00 00 02 00 00 08 A2 F5 58 . .H...........X
4000000000108690 09 40 00 00 00 21 10 00 8C 00 42 00 20 02 AA 00 .@...!....B. ...
40000000001086A0 11 00 00 00 01 00 00 08 05 80 03 80 08 00 84 00 ................
40000000001086B0 11 00 00 00 01 00 00 00 00 02 00 00 98 36 F6 58 .............6.X
40000000001086C0 0B 08 00 46 00 21 40 A2 F5 79 4F 00 00 00 04 00 ...F.!@..yO.....
40000000001086D0 11 20 01 48 18 10 00 00 00 02 00 00 B8 A1 F5 58 . .H...........X
40000000001086E0 09 40 00 00 00 21 10 00 8C 00 42 00 20 02 AA 00 .@...!....B. ...
40000000001086F0 11 00 00 00 01 00 00 08 05 80 03 80 08 00 84 00 ................
4000000000108700 08 18 21 0A 80 05 10 02 07 66 48 40 04 00 C4 00 ..!......fH@....
4000000000108710 09 30 B4 40 87 39 50 22 F6 79 4F 80 04 08 00 84 .0.@.9P".yO.....
4000000000108720 08 00 00 00 01 00 00 00 00 02 00 03 14 00 00 90 ................
4000000000108730 0B 28 01 4A 18 D0 01 02 00 00 42 00 00 00 04 00 .(.J......B.....
4000000000108740 11 00 80 42 90 11 00 00 00 02 00 00 08 36 F6 58 ...B.........6.X
4000000000108750 09 08 00 48 00 21 E0 00 84 20 20 00 00 00 04 00 ...H.!...  .....
4000000000108760 09 30 00 1C 87 39 00 00 00 02 00 A0 C4 EC F3 9E .0...9..........
4000000000108770 13 28 01 4A 18 D0 01 28 00 80 21 00 D8 35 F6 58 .(.J...(..!..5.X
4000000000108780 0B 08 00 48 00 21 50 62 F6 79 4F 00 00 00 04 00 ...H.!Pb.yO.....
4000000000108790 11 28 01 4A 18 10 00 00 00 02 00 00 F8 A1 F5 58 .(.J...........X
40000000001087A0 09 40 00 00 00 21 10 00 90 00 42 00 30 02 AA 00 .@...!....B.0...
40000000001087B0 10 00 00 00 01 00 00 10 05 80 03 80 08 00 84 00 ................
40000000001087C0 09 30 51 FB BC 27 00 00 00 02 00 E0 04 00 00 84 .0Q..'..........
40000000001087D0 11 30 01 4C 18 10 00 00 00 02 00 00 F8 FB F5 58 .0.L...........X
40000000001087E0 0B 08 00 48 00 21 50 62 F6 79 4F 00 00 00 04 00 ...H.!Pb.yO.....
40000000001087F0 11 28 01 4A 18 10 00 00 00 02 00 00 98 A1 F5 58 .(.J...........X
4000000000108800 09 40 00 00 00 21 10 00 90 00 42 00 30 02 AA 00 .@...!....B.0...
4000000000108810 11 00 00 00 01 00 00 10 05 80 03 80 08 00 84 00 ................
4000000000108820 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000108830 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000108840 18 18 15 0A 80 05 10 02 07 5E 48 00 00 00 00 20 .........^H.... 
4000000000108850 09 38 B4 40 86 39 40 02 04 00 42 40 04 00 C4 00 .8.@.9@...B@....
4000000000108860 11 00 00 00 01 00 00 00 00 02 80 03 50 00 00 43 ............P..C
4000000000108870 13 00 00 42 90 11 00 CC F8 7D 2C 00 00 00 00 20 ...B.....},.... 
4000000000108880 08 08 00 48 00 21 00 00 00 02 00 00 00 00 04 00 ...H.!..........
4000000000108890 09 40 00 42 10 10 00 00 00 02 00 00 30 02 AA 00 .@.B........0...
40000000001088A0 10 40 04 10 25 20 00 10 05 80 03 80 08 00 84 00 .@..% ..........
40000000001088B0 09 00 00 00 01 00 E0 08 00 00 48 00 00 00 04 00 ..........H.....
40000000001088C0 11 00 38 42 90 11 00 00 00 02 00 00 88 F1 FB 58 ..8B...........X
40000000001088D0 0B 08 00 48 00 21 E0 E0 05 8E 48 00 00 00 04 00 ...H.!....H.....
40000000001088E0 0B 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
40000000001088F0 10 00 00 00 01 00 70 00 38 0C 73 03 A0 FF FF 4A ......p.8.s....J
4000000000108900 11 00 00 00 01 00 00 00 00 02 00 00 08 F2 FB 58 ...............X
4000000000108910 09 40 00 42 10 10 10 00 90 00 42 00 30 02 AA 00 .@.B......B.0...
4000000000108920 11 40 04 10 25 20 00 10 05 80 03 80 08 00 84 00 .@..% ..........
4000000000108930 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000108940 08 18 1D 0A 80 05 E0 E0 F6 5F 4F 40 04 00 C4 00 ........._O@....
4000000000108950 19 20 01 02 00 21 70 68 81 0C F3 03 70 01 00 43 . ...!ph....p..C
4000000000108960 0B 70 00 1C 18 10 E0 00 38 20 20 00 00 00 04 00 .p......8  .....
4000000000108970 09 38 04 1C 86 39 E0 00 84 00 20 00 00 00 04 00 .8...9.... .....
4000000000108980 11 00 00 00 01 00 E0 00 38 28 00 03 60 00 00 42 ........8(..`..B
4000000000108990 10 00 00 00 01 00 60 28 3B 0E 73 03 60 00 00 43 ......`(;.s.`..C
40000000001089A0 09 70 10 03 32 24 00 00 00 02 00 00 30 02 AA 00 .p..2$......0...
40000000001089B0 09 00 00 00 01 00 00 00 00 02 00 00 20 0A 00 07 ............ ...
40000000001089C0 09 00 00 00 01 00 80 00 38 20 20 00 00 00 04 00 ........8  .....
40000000001089D0 10 00 00 00 01 00 80 08 20 4A 40 80 08 00 84 00 ........ J@.....
40000000001089E0 11 00 00 00 01 00 60 B0 3B 0E F3 03 C0 FF FF 4A ......`.;......J
40000000001089F0 09 70 D0 03 32 24 F0 08 00 00 48 00 01 00 00 84 .p..2$....H.....
4000000000108A00 0B 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
4000000000108A10 11 30 00 1C 87 39 E0 20 06 64 C8 03 50 00 00 43 .0...9. .d..P..C
4000000000108A20 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000108A30 08 00 3C 1C 90 11 00 00 00 02 00 00 00 00 04 00 ..<.............
4000000000108A40 01 00 00 00 01 00 00 18 01 55 00 00 00 00 04 00 .........U......
4000000000108A50 10 00 00 00 01 00 00 10 05 80 03 80 08 00 84 00 ................
4000000000108A60 09 70 30 FA AF 27 00 00 00 02 00 C0 44 EE F3 9E .p0..'......D...
4000000000108A70 09 70 00 1C 18 10 60 02 98 30 20 00 00 00 04 00 .p....`..0 .....
4000000000108A80 11 28 01 1C 18 10 00 00 00 02 00 00 48 D6 F1 58 .(..........H..X
4000000000108A90 09 08 00 48 00 21 F0 08 00 00 48 00 01 00 00 84 ...H.!....H.....
4000000000108AA0 0B 70 10 03 32 24 00 00 00 02 00 00 00 00 04 00 .p..2$..........
4000000000108AB0 10 00 3C 1C 90 11 00 00 00 02 00 00 90 FF FF 48 ..<............H
4000000000108AC0 09 28 71 FB BC 27 00 00 00 02 00 C0 04 08 01 84 .(q..'..........
4000000000108AD0 11 28 01 4A 18 10 00 00 00 02 00 00 58 1D F1 58 .(.J........X..X
4000000000108AE0 03 08 00 48 00 21 80 08 00 00 48 C0 41 0F C8 90 ...H.!....H.A...
4000000000108AF0 0B 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
4000000000108B00 11 30 00 1C 87 39 E0 20 06 64 C8 03 50 00 00 43 .0...9. .d..P..C
4000000000108B10 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000108B20 08 00 00 1C 90 11 00 00 00 02 00 00 00 00 04 00 ................
4000000000108B30 01 00 00 00 01 00 00 18 01 55 00 00 00 00 04 00 .........U......
4000000000108B40 11 00 00 00 01 00 00 10 05 80 03 80 08 00 84 00 ................
4000000000108B50 11 00 00 00 01 00 00 00 00 02 00 00 B8 D3 F1 58 ...............X
4000000000108B60 03 08 00 48 00 21 80 08 00 00 48 C0 41 0C C8 90 ...H.!....H.A...
4000000000108B70 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000108B80 11 00 00 1C 90 11 00 00 00 02 00 00 B0 FF FF 48 ...............H
4000000000108B90 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000108BA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000108BB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000108BC0: 4000000000108BC0
;;   Called from:
;;     400000000010910C (in list_minus_o_opts)
;;     40000000001091CC (in list_minus_o_opts)
fn4000000000108BC0 proc
	{ alloc	r36,ar.pfs,0xA,0x0,0x6; nop.m	0x0; mov	r35,b3 }
	{ adds	r37,0x0,r1; cmp4.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	4000000000108C50; }

l4000000000108BE0:
	{ cmp4.eq	p06,p07,0x0,r33; nop.m	0x0; addl	r39,-8580,r1 }
	{ addl	r38,1,r0; nop.m	0x0; adds	r40,0x0,r32; }
	{ (p07) addl	r41,-8596,r1; ld8	r39,[r39]; nop.i	0x0; }

l4000000000108C06:
	{ (p19) fwb; addl	r0,49152,r1; Invalid }

l4000000000108C16:
	{ (p20) fwb; nop; (p17) br.call.sptk.few	b2,b0; }

l4000000000108C1C:
	{ nop; Invalid; break.i	0x1000 }

l4000000000108C26:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ Invalid; (p34) nop; (p32) nop }

l4000000000108C50:
	{ cmp4.eq	p06,p07,0x0,r33; addl	r39,-8572,r1; addl	r38,1,r0 }
	{ adds	r41,0x0,r32; ld8	r39,[r39]; (p06) addl	r40,43,r0; }

l4000000000108C70:
	{ (p07) addl	r40,45,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB80; }

l4000000000108C76:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ Invalid; (p34) nop; break.i	0x80000 }
4000000000108CA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000108CB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000108CC0 03 70 00 40 00 10 80 00 00 00 42 C0 01 70 50 00 .p.@......B..pP.
4000000000108CD0 11 38 94 1D 86 39 E0 20 06 64 C8 03 70 00 00 43 .8...9. .d..p..C
4000000000108CE0 0B 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
4000000000108CF0 10 00 00 00 01 00 70 00 38 0C 73 83 08 00 84 02 ......p.8.s.....
4000000000108D00 0B 70 70 FB AF 27 E0 00 38 30 20 00 00 00 04 00 .pp..'..80 .....
4000000000108D10 0B 40 00 1C 10 10 60 00 20 0E 73 00 00 00 04 00 .@....`. .s.....
4000000000108D20 09 00 00 00 01 80 81 08 00 00 48 00 00 00 04 00 ..........H.....
4000000000108D30 11 00 00 00 01 C0 81 00 00 00 42 80 08 00 84 00 ..........B.....
4000000000108D40 09 70 10 03 32 24 00 00 00 02 00 00 01 00 00 84 .p..2$..........
4000000000108D50 0B 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
4000000000108D60 10 00 00 00 01 00 70 00 38 0C 73 83 08 00 84 02 ......p.8.s.....
4000000000108D70 0B 70 70 FB AF 27 E0 00 38 30 20 00 00 00 04 00 .pp..'..80 .....
4000000000108D80 0B 40 00 1C 10 10 60 08 20 0E 73 00 00 00 04 00 .@....`. .s.....
4000000000108D90 09 00 00 00 01 80 81 08 00 00 48 00 00 00 04 00 ..........H.....
4000000000108DA0 11 00 00 00 01 C0 81 00 00 00 42 80 08 00 84 00 ..........B.....
4000000000108DB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; minus_o_option_value: 4000000000108DC0
;;   Called from:
;;     400000000011479C (in shopt_builtin)
minus_o_option_value proc
	{ alloc	r37,ar.pfs,0x9,0x0,0x7; addl	r40,-8564,r1; mov	r36,b4 }
	{ ld1	r35,[r32]; addl	r14,6196,r1; adds	r38,0x0,r1; }
	{ adds	r34,0x0,r0; ld8	r40,[r40]; sxt1	r35,r35 }
	{ ld8	r33,[r14]; nop.m	0x0; nop.i	0x0; }

l4000000000108E00:
	{ ld1	r14,[r40]; adds	r33,0x28,r33; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r35; (p07) br.cond.dpnt.few	4000000000108E70 }

l4000000000108E20:
	{ adds	r14,0xFFFFFFFFFFFFFFD8,r33; nop.m	0x0; adds	r34,0x1,r34; }
	{ nop.m	0x0; ld8	r40,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r40; (p06) br.cond.dptk.few	4000000000108E00 }

l4000000000108E50:
	{ addl	r8,-1,r0; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,4000000000108E60; br.ret	b0; }

l4000000000108E70:
	{ adds	r39,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r38; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	4000000000108E20; }

l4000000000108E90:
	{ addl	r14,-25004,r1; sxt4	r34,r34; adds	r39,0x0,r32; }
	{ shladd	r34,r34,0x2,r34; nop.m	0x0; nop.i	0x0; }
	{ shladd	r14,r34,0x3,r14; adds	r15,0x8,r14; adds	r16,0x20,r14; }
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r15; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000108F40; }

l4000000000108EE0:
	{ nop.m	0x0; ld8	r8,[r16]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r8; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000108F80; }

l4000000000108F00:
	{ ld8	r14,[r8],8; nop.m	0x0; mov.spnt	b6,r14,4000000000108F00 }
	{ ld8	r1,[r8]; nop.m	0x0; br.call.sptk.many	b0,b6; }
	{ adds	r1,0x0,r38; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,4000000000108F30; br.ret	b0; }

l4000000000108F40:
	{ adds	r39,0x0,r15; nop.i	0x0; br.call.sptk.many	b0,find_flag; }
	{ cmp.eq	p07,p06,0x0,r8; adds	r1,0x0,r38; mov.i	ar.pfs,r37 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000108E50; }

l4000000000108F70:
	{ (p06) ld4	r8,[r8]; mov.spnt	b0,r36,4000000000108F70; br.ret	b0 }

l4000000000108F76:
	{ Invalid; (p34) nop; (p32) nop }

l4000000000108F80:
	{ adds	r14,0x10,r14; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ ld8	r14,[r14]; nop.m	0x0; mov.spnt	b0,r36,4000000000108F90; }
	{ ld4	r8,[r14]; nop.i	0x0; br.ret	b0; }
4000000000108FB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; list_minus_o_opts: 4000000000108FC0
;;   Called from:
;;     400000000001F31C (in main)
;;     400000000010A11C (in set_builtin)
;;     400000000010A13C (in set_builtin)
;;     400000000011490C (in shopt_builtin)
;;     4000000000114BFC (in shopt_builtin)
list_minus_o_opts proc
	{ alloc	r37,ar.pfs,0xB,0x0,0x8; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r36,b4 }
	{ addl	r35,-8564,r1; addl	r14,6204,r1; adds	r38,0x0,r1; }
	{ nop.m	0x0; mov	r39,pr; nop.b	0x0 }
	{ ld8	r35,[r35]; ld8	r34,[r14]; cmp4.eq	p16,p17,0xFFFFFFFFFFFFFFFF,r32; }

l4000000000109000:
	{ ld4	r40,[r34]; nop.m	0x0; adds	r14,0x18,r34; }
	{ cmp4.eq	p06,p07,0x0,r40; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000109150; }

l4000000000109020:
	{ ld8	r8,[r14]; nop.m	0x0; adds	r40,0x0,r35; }
	{ cmp.eq	p06,p07,0x0,r8; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000109210; }

l4000000000109040:
	{ ld8	r14,[r8],8; ld8	r1,[r8]; mov.spnt	b6,r14,4000000000109040 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,b6; }
	{ adds	r1,0x0,r38; nop.m	0x0; nop.i	0x0 }

l4000000000109070:
	{ adds	r14,0x10,r12; nop.m	0x0; cmp4.eq	p07,p06,r32,r8; }
	{ st4	[r8],r14; (p16) br.cond.dpnt.few	40000000001090F0; (p07) br.cond.dpnt.few	40000000001090F0 }

l400000000010908C:
	{ (p03) cmpxchg2.acq.nt1	r0,[r33],r64; (p04) cmp.lt.unc	p10,p16,r8,r64; (p01) nop }

l4000000000109090:
	{ adds	r34,0x28,r34; adds	r14,0xFFFFFFFFFFFFFFF8,r34; nop.i	0x0; }
	{ nop.m	0x0; ld8	r35,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	4000000000109000; }

l40000000001090C0:
	{ nop.m	0x0; mov	pr,r39,0xFFFFFFFFFFFFFFFE; nop.i	0x0; }
	{ nop.m	0x0; mov.i	ar.pfs,r37; mov.spnt	b0,r36,40000000001090D0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000001090F0:
	{ adds	r40,0x0,r35; adds	r34,0x28,r34; nop.i	0x0 }
	{ adds	r41,0x0,r8; adds	r42,0x0,r33; br.call.sptk.many	b0,fn4000000000108BC0; }
	{ adds	r14,0xFFFFFFFFFFFFFFF8,r34; nop.m	0x0; adds	r1,0x0,r38; }
	{ nop.m	0x0; ld8	r35,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	4000000000109000 }

l4000000000109140:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000001090C0 }

l4000000000109150:
	{ nop.m	0x0; adds	r14,0x10,r12; nop.i	0x0; }
	{ st4	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,find_flag; }
	{ cmp.eq	p06,p07,0x0,r8; nop.m	0x0; adds	r1,0x0,r38; }
	{ nop.m	0x0; (p07) ld4	r41,[r8]; nop.i	0x0; }

l400000000010918C:
	{ nop; zxt1	r0,r64; break.i	0x101000 }

l4000000000109196:
	{ nop; nop; break.i	0x80000 }

l40000000001091A0:
	{ nop.m	0x0; cmp4.eq	p06,p07,r41,r32; (p07) br.cond.dptk.few	4000000000109090 }

l40000000001091B0:
	{ adds	r40,0x0,r35; nop.m	0x0; adds	r34,0x28,r34 }
	{ adds	r42,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,fn4000000000108BC0; }
	{ adds	r14,0xFFFFFFFFFFFFFFF8,r34; nop.m	0x0; adds	r1,0x0,r38; }
	{ nop.m	0x0; ld8	r35,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	4000000000109000 }

l4000000000109200:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000001090C0 }

l4000000000109210:
	{ adds	r14,0x8,r34; ld8	r14,[r14]; nop.i	0x0; }
	{ ld4	r8,[r14]; nop.i	0x0; br.cond.sptk.few	4000000000109070; }
4000000000109230 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; get_minus_o_opts: 4000000000109240
get_minus_o_opts proc
	{ alloc	r33,ar.pfs,0x4,0x0,0x3; adds	r34,0x0,r1; mov	r32,b0; }
	{ addl	r35,29,r0; nop.i	0x0; br.call.sptk.many	b0,strvec_create; }
	{ adds	r1,0x0,r34; adds	r18,0x0,r8; adds	r17,0x0,r8 }
	{ adds	r16,0x0,r0; addl	r15,-8564,r1; addl	r14,6212,r1; }
	{ ld8	r15,[r15]; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000001092A0:
	{ adds	r14,0x28,r14; st8	[r17],r8,8; adds	r16,0x1,r16; }
	{ adds	r15,0xFFFFFFFFFFFFFFD8,r14; ld8	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	40000000001092A0 }

l40000000001092D0:
	{ adds	r8,0x0,r18; mov.i	ar.pfs,r33; sxt4	r16,r16; }
	{ shladd	r18,r16,0x3,r18; nop.m	0x0; mov.spnt	b0,r32,40000000001092E0; }
	{ st8	[r0],r18; nop.i	0x0; br.ret	b0; }

;; set_minus_o_option: 4000000000109300
;;   Called from:
;;     400000000001E9FC (in main)
;;     4000000000109B2C (in parse_shellopts)
;;     400000000010A00C (in set_builtin)
;;     40000000001146EC (in shopt_builtin)
set_minus_o_option proc
	{ alloc	r38,ar.pfs,0xA,0x0,0x8; addl	r41,-8564,r1; mov	r37,b5 }
	{ ld1	r36,[r33]; addl	r14,6220,r1; adds	r39,0x0,r1; }
	{ ld8	r41,[r41]; adds	r35,0x0,r0; sxt1	r36,r36 }
	{ ld8	r34,[r14]; nop.m	0x0; nop.i	0x0; }

l4000000000109340:
	{ ld1	r14,[r41]; adds	r34,0x28,r34; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r36; (p07) br.cond.dpnt.few	40000000001093D0 }

l4000000000109360:
	{ adds	r14,0xFFFFFFFFFFFFFFD8,r34; nop.m	0x0; adds	r35,0x1,r35; }
	{ nop.m	0x0; ld8	r41,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r41; (p06) br.cond.dptk.few	4000000000109340 }

l4000000000109390:
	{ adds	r40,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,sh_invalidoptname; }
	{ nop.m	0x0; adds	r1,0x0,r39; addl	r14,258,r0; }

l40000000001093B0:
	{ adds	r8,0x0,r14; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000001093C0; br.ret	b0; }

l40000000001093D0:
	{ adds	r40,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r39; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	4000000000109360; }

l40000000001093F0:
	{ nop.m	0x0; sxt4	r35,r35; nop.b	0x0 }
	{ addl	r15,-25004,r1; adds	r40,0x0,r32; adds	r41,0x0,r33; }
	{ shladd	r35,r35,0x2,r35; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; shladd	r14,r35,0x3,r0; nop.i	0x0; }
	{ add	r16,r15,r14; adds	r17,0x8,r16; adds	r15,0x18,r16; }
	{ nop.m	0x0; ld4	r14,[r17]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001094C0; }

l4000000000109460:
	{ nop.m	0x0; ld8	r8,[r15]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r8; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000109520; }

l4000000000109480:
	{ ld8	r14,[r8],8; nop.m	0x0; mov.spnt	b6,r14,4000000000109480 }
	{ ld8	r1,[r8]; nop.m	0x0; br.call.sptk.many	b0,b6; }
	{ adds	r14,0x0,r0; adds	r1,0x0,r39; mov.i	ar.pfs,r38; }
	{ adds	r8,0x0,r14; mov.spnt	b0,r37,40000000001094B0; br.ret	b0; }

l40000000001094C0:
	{ adds	r40,0x0,r14; adds	r41,0x0,r32; br.call.sptk.many	b0,change_flag; }
	{ nop.m	0x0; adds	r1,0x0,r39; adds	r14,0x0,r0 }
	{ nop.m	0x0; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p06) br.cond.dptk.few	40000000001093B0 }

l40000000001094F0:
	{ adds	r40,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,sh_invalidoptname; }
	{ addl	r14,1,r0; adds	r1,0x0,r39; mov.i	ar.pfs,r38; }
	{ adds	r8,0x0,r14; mov.spnt	b0,r37,4000000000109510; br.ret	b0 }

l4000000000109520:
	{ adds	r16,0x10,r16; cmp4.eq	p06,p07,0x2D,r32; nop.b	0x0 }
	{ adds	r14,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ ld8	r15,[r16]; (p06) addl	r32,1,r0; nop.b	0x0 }

l400000000010954C:
	{ Invalid; zxt1	r64,r64; (p16) mov	pr,r0,0x752 }
	{ Invalid; nop }

l4000000000109560:
	{ st4	[r32],r15; nop.i	0x0; br.ret	b0; }
4000000000109570 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; set_shellopts: 4000000000109580
;;   Called from:
;;     400000000006291C (in sv_strict_posix)
;;     400000000006295C (in sv_strict_posix)
;;     4000000000062A6C (in sv_ignoreeof)
;;     4000000000109BFC (in initialize_shell_options)
;;     4000000000109D2C (in initialize_shell_options)
;;     400000000010A0AC (in set_builtin)
;;     400000000010A33C (in set_builtin)
;;     400000000011471C (in shopt_builtin)
set_shellopts proc
	{ alloc	r39,ar.pfs,0xC,0x0,0x9; adds	r12,0xFFFFFFFFFFFFFFE0,r12; mov	r38,b6 }
	{ addl	r33,-8564,r1; addl	r14,6228,r1; adds	r40,0x0,r1; }
	{ adds	r35,0x10,r12; ld8	r33,[r33]; adds	r36,0x0,r0 }
	{ addl	r37,1,r0; ld8	r32,[r14]; nop.i	0x0; }
	{ adds	r34,0x0,r35; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000001095E0:
	{ ld4	r14,[r32]; nop.m	0x0; adds	r15,0x18,r32 }
	{ st1	[r0],r34; nop.m	0x0; adds	r41,0x0,r33; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000109930; }

l4000000000109610:
	{ nop.m	0x0; ld8	r8,[r15]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r8; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001099B0; }

l4000000000109630:
	{ nop.m	0x0; ld8	r14,[r8],8; nop.i	0x0; }
	{ ld8	r1,[r8]; mov.spnt	b6,r14,4000000000109640; br.call.sptk.many	b0,b6; }
	{ cmp4.eq	p07,p06,0x0,r8; adds	r41,0x0,r33; adds	r1,0x0,r40; }
	{ (p06) addl	r8,1,r0; (p07) adds	r8,0x0,r0; nop.i	0x0; }

l4000000000109666:
	{ Invalid; nop; break.i	0x80000; }

l400000000010966C:
	{ invala; cmp.lt	p00,p00,r32,r0; mov	pr,r98,0xE600 }
	{ Invalid; break.i	0x1000; break.b	0x1000 }

l4000000000109680:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r40; st1	[r37],r34; add	r36,r8,r36,0x1 }

l40000000001096A0:
	{ adds	r14,0x20,r32; adds	r34,0x1,r34; adds	r32,0x28,r32; }
	{ nop.m	0x0; ld8	r33,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	40000000001095E0 }

l40000000001096D0:
	{ addl	r33,-8564,r1; nop.m	0x0; adds	r41,0x1,r36 }
	{ adds	r34,0x0,r0; nop.m	0x0; addl	r37,58,r0; }
	{ ld8	r33,[r33]; sxt4	r41,r41; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r40; adds	r36,0x0,r8; addl	r14,6236,r1 }
	{ nop.m	0x0; ld8	r32,[r14]; nop.i	0x0; }

l4000000000109720:
	{ ld1	r14,[r35],1; adds	r32,0x28,r32; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; adds	r14,0xFFFFFFFFFFFFFFD8,r32; (p07) br.cond.dpnt.few	40000000001098A0; }

l4000000000109740:
	{ nop.m	0x0; ld8	r33,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	4000000000109720; }

l4000000000109760:
	{ cmp4.eq	p06,p07,0x0,r34; addl	r41,-8556,r1; (p07) adds	r14,0xFFFFFFFFFFFFFFFF,r34 }

l4000000000109770:
	{ ld8	r41,[r41]; nop.m	0x0; sxt4	r14,r14; }
	{ (p06) adds	r14,0x0,r0; add	r14,r36,r14; nop.i	0x0; }

l4000000000109786:
	{ Invalid; nop; nop }
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ Invalid; nop; (p32) nop }
	{ (p21) chk.a.clr	r0,3FFFFFFFFF1897B6; nop; br.call.sptk.few	b0,b0 }

l40000000001097C0:
	{ ld4	r32,[r8]; nop.m	0x0; addl	r41,-8556,r1; }
	{ and	r14,0xFFFFFFFFFFFFFFFD,r32; ld8	r41,[r41]; nop.i	0x0; }
	{ st4	[r14],r8; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r1,0x0,r40; adds	r8,0x28,r8; addl	r15,7412,r1 }
	{ ld4	r14,[r8]; nop.m	0x0; nop.i	0x0; }
	{ ld4	r16,[r15]; or	r15,0x2,r14; cmp4.eq	p07,p06,0x0,r16 }
	{ st4	[r15],r8; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000109870; }

l4000000000109830:
	{ nop.m	0x0; tbit.z	p07,p06,r32,0x0; (p06) br.cond.dpnt.few	4000000000109870; }

l4000000000109840:
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x0; (p07) and	r14,0xFFFFFFFFFFFFFFFE,r14; }

l4000000000109850:
	{ nop.m	0x0; (p07) or	r14,0x2,r14; nop.i	0x0; }

l400000000010985C:
	{ Invalid; Invalid; break.i	0x1000 }

l4000000000109866:
	{ break.m	0x4000; nop; (p16) nop }

l4000000000109870:
	{ adds	r41,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }

l4000000000109872:
	{ break.m	0x42009; nop; (p30) break.i	0x12C788; }

l4000000000109876:
	{ break.m	0x4000; Invalid; (p16) nop }

l4000000000109878:
	{ (p16) nop; Invalid; (p32) nop }

l400000000010987C:
	{ (p59) nop; invala; (p48) break.b	0x2A809 }

l400000000010987E:
	{ (p07) ld1	r75,[r4]; (p01) mov	pr,0x3800210; (p42) nop; }

l4000000000109882:
	{ cmp.eq	p10,p00,r64,r16; (p04) cmp.lt.unc	p16,p00,r10,r0; Invalid }

l4000000000109884:
	{ (p08) ld1.c.clr	r4,[r28],128; Invalid; (p14) break.i	0xC0 }

l400000000010988A:
	{ nop; (p32) mov	pr,0x1; Invalid }

l400000000010988C:
	{ (p19) nop; add	r0,r32,r0; (p01) shladd	r8,r3,0x1,r64 }

l400000000010988E:
	{ (p56) break.m	0x300; (p04) nop; Invalid }

l4000000000109892:
	{ Invalid; (p04) nop; break.i	0x80420 }

l4000000000109894:
	{ srlz.i; (p08) break.i	0x108804; (p01) break.i	0x8; }

l400000000010989A:
	{ Invalid; (p04) mov	pr,0x0; nop }

l40000000001098A0:
	{ nop.m	0x0; sxt4	r41,r34; adds	r42,0x0,r33; }
	{ add	r41,r36,r41; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r40; adds	r41,0x0,r33; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ add	r8,r34,r8; nop.m	0x0; adds	r1,0x0,r40; }
	{ nop.m	0x0; sxt4	r14,r8; adds	r34,0x1,r8; }
	{ add	r14,r36,r14; st1	[r37],r14; adds	r14,0xFFFFFFFFFFFFFFD8,r32; }
	{ nop.m	0x0; ld8	r33,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	4000000000109720 }

l4000000000109920:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000109760 }

l4000000000109930:
	{ adds	r41,0x0,r14; nop.i	0x0; br.call.sptk.many	b0,find_flag; }
	{ adds	r1,0x0,r40; nop.m	0x0; cmp.eq	p06,p07,0x0,r8 }
	{ adds	r41,0x0,r33; nop.m	0x0; (p06) br.cond.dpnt.few	40000000001096A0; }

l4000000000109960:
	{ nop.m	0x0; ld4	r14,[r8]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000001096A0 }

l4000000000109980:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; adds	r1,0x0,r40; nop.i	0x0 }
	{ st1	[r37],r34; add	r36,r8,r36,0x1; br.cond.sptk.few	40000000001096A0 }

l40000000001099B0:
	{ adds	r14,0x8,r32; nop.m	0x0; adds	r41,0x0,r33; }
	{ ld8	r14,[r14]; ld4	r8,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r8; (p06) addl	r8,1,r0; nop.i	0x0; }

l40000000001099DC:
	{ nop; mov	pr,r32,0x0; zxt1	r0,r64 }

l40000000001099EC:
	{ invala; cmp.lt	p00,p00,r32,r0; mov	pr,r98,0xE600 }
	{ (p37) invala; break.i	0x1000; break.b	0x1000 }

l4000000000109A00:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000109680 }

l4000000000109A10:
	{ addl	r41,-8556,r1; adds	r42,0x0,r36; adds	r43,0x0,r0; }
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r1,0x0,r40; adds	r8,0x28,r8; addl	r15,7412,r1 }
	{ ld4	r14,[r8]; nop.m	0x0; nop.i	0x0; }
	{ ld4	r16,[r15]; or	r15,0x2,r14; cmp4.eq	p07,p06,0x0,r16 }
	{ st4	[r15],r8; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000109870; }

l4000000000109A70:
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x0; (p07) and	r14,0xFFFFFFFFFFFFFFFE,r14; }

l4000000000109A80:
	{ nop.m	0x0; (p07) or	r14,0x2,r14; nop.i	0x0; }

l4000000000109A8C:
	{ Invalid; Invalid; break.i	0x1000 }

l4000000000109A96:
	{ break.m	0x4000; nop; break.i	0x80000 }
4000000000109AA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000109AB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; parse_shellopts: 4000000000109AC0
;;   Called from:
;;     4000000000109CFC (in initialize_shell_options)
parse_shellopts proc
	{ alloc	r35,ar.pfs,0x7,0x0,0x5; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r34,b2 }
	{ adds	r36,0x0,r1; nop.m	0x0; adds	r37,0x0,r32; }
	{ adds	r14,0x10,r12; nop.m	0x0; adds	r38,0x10,r12; }
	{ st4	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,extract_colon_unit; }
	{ adds	r33,0x0,r8; nop.m	0x0; adds	r38,0x0,r8 }
	{ adds	r1,0x0,r36; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	4000000000109B80; }

l4000000000109B20:
	{ addl	r37,45,r0; nop.i	0x0; br.call.sptk.many	b0,set_minus_o_option; }
	{ adds	r37,0x0,r33; adds	r1,0x0,r36; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r38,0x10,r12 }
	{ adds	r37,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,extract_colon_unit; }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r33,0x0,r8 }
	{ adds	r38,0x0,r8; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	4000000000109B20 }

l4000000000109B80:
	{ nop.m	0x0; mov.i	ar.pfs,r35; mov.spnt	b0,r34,4000000000109B80 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }
4000000000109BA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000109BB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; initialize_shell_options: 4000000000109BC0
initialize_shell_options proc
	{ alloc	r35,ar.pfs,0x7,0x0,0x5; nop.m	0x0; mov	r34,b2 }
	{ adds	r36,0x0,r1; cmp4.eq	p06,p07,0x0,r32; (p06) br.cond.dpnt.few	4000000000109C00; }

l4000000000109BE0:
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000109BE0; mov.i	ar.pfs,r35; }
	{ alloc	r2,ar.pfs,0x1,0x0,0x0; nop.i	0x0; br.cond.sptk.many	set_shellopts }

l4000000000109C00:
	{ nop.m	0x0; addl	r37,-8556,r1; nop.i	0x0; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r14,0x28,r8; nop.m	0x0; adds	r1,0x0,r36 }
	{ cmp.eq	p06,p07,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000109BE0; }

l4000000000109C40:
	{ nop.m	0x0; ld4	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r15,0xF; (p06) br.cond.dpnt.few	4000000000109BE0; }

l4000000000109C60:
	{ ld8	r14,[r14]; and	r14,0x44,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000109BE0 }

l4000000000109C80:
	{ nop.m	0x0; adds	r33,0x8,r8; nop.i	0x0; }
	{ ld8	r37,[r33]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r36; adds	r37,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r38,[r33]; nop.m	0x0; adds	r1,0x0,r36 }
	{ adds	r37,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r37,0x0,r8; nop.i	0x0 }
	{ adds	r1,0x0,r36; adds	r33,0x0,r8; (p06) br.cond.spnt.few	4000000000109BE0; }

l4000000000109CF0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,parse_shellopts; }
	{ adds	r1,0x0,r36; adds	r37,0x0,r33; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r36; mov.spnt	b0,r34,4000000000109D10; mov.i	ar.pfs,r35; }
	{ alloc	r2,ar.pfs,0x1,0x0,0x0; nop.i	0x0; br.cond.sptk.many	set_shellopts; }
4000000000109D30 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; reset_shell_options: 4000000000109D40
;;   Called from:
;;     400000000005062C (in shell_execve)
reset_shell_options proc
	{ addl	r15,6112,r1; nop.m	0x0; addl	r14,1,r0; }
	{ nop.m	0x0; st4	[r14],r15; addl	r15,6116,r1; }
	{ nop.m	0x0; st4	[r14],r15; addl	r14,6624,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r0],r14; nop.i	0x0; br.ret	b0; }
4000000000109D90 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000109DA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000109DB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; set_builtin: 4000000000109DC0
;;   Called from:
;;     40000000000F229C (in fn40000000000F0900)
set_builtin proc
	{ alloc	r41,ar.pfs,0xD,0x0,0xB; adds	r12,0xFFFFFFFFFFFFFFE0,r12; nop.b	0x0 }
	{ cmp.eq	p07,p06,0x0,r32; adds	r42,0x0,r1; mov	r40,b0; }
	{ (p07) br.cond.dpnt.few	400000000010A1B0; nop.b	0x0; br.call.sptk.many	b0,reset_internal_getopt; }

l4000000000109DE6:
	{ invala; (p32) nop; (p16) nop }
	{ break.m	0x4000; nop; nop }

l4000000000109E00:
	{ addl	r44,-20708,r1; nop.m	0x0; adds	r43,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; adds	r1,0x0,r42; (p07) br.cond.dpnt.few	4000000000109EB0; }

l4000000000109E30:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x3F,r8; (p07) br.cond.dptk.few	4000000000109E00 }

l4000000000109E40:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ adds	r1,0x0,r42; addl	r14,9260,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r8,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x3F,r8; nop.i	0x0; }
	{ (p06) addl	r8,258,r0; nop.i	0x0; (p07) adds	r8,0x0,r0 }

l4000000000109E86:
	{ chk.a.nc	f0,3FFFFFFFFF10A686; Invalid; break.i	0x80000 }

l4000000000109E90:
	{ nop.m	0x0; mov.i	ar.pfs,r41; mov.spnt	b0,r40,4000000000109E90 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0 }

l4000000000109EB0:
	{ nop.m	0x0; adds	r39,0x0,r0; adds	r36,0x0,r0 }

l4000000000109EC0:
	{ adds	r14,0x8,r32; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r14,[r14]; adds	r34,0x1,r14; nop.i	0x0; }
	{ ld1	r35,[r14]; nop.m	0x0; sxt1	r35,r35; }
	{ cmp4.eq	p07,p06,0x2D,r35; nop.m	0x0; cmp4.eq	p08,p09,0x2B,r35 }
	{ adds	r38,0x0,r35; nop.m	0x0; (p07) br.cond.dpnt.few	400000000010A290; }

l4000000000109F10:
	{ cmp4.eq	p06,p07,0x0,r35; (p08) addl	r15,1,r0; (p06) br.cond.dpnt.few	400000000010A420; }

l4000000000109F1C:
	{ (p40) cmp.eq	p00,p41,0x40,r33; zxt1	r0,r64; Invalid }

l4000000000109F20:
	{ (p09) adds	r15,0x0,r0; nop.m	0x0; cmp4.eq	p06,p07,0x2D,r35; }

l4000000000109F26:
	{ break.m	0x4000; (p03) nop; (p16) nop }
	{ (p35) chk.a.clr	f0,3FFFFFFFFFDAD826; nop; (p32) nop }

l4000000000109F40:
	{ ld1	r14,[r34],1; nop.m	0x0; sxt1	r43,r14; }
	{ adds	r33,0x0,r43; cmp4.eq	p07,p06,0x0,r43; (p07) br.cond.dpnt.few	400000000010A040; }

l4000000000109F60:
	{ cmp4.eq	p07,p06,0x3F,r33; nop.i	0x0; (p07) br.cond.dpnt.few	400000000010A160; }

l4000000000109F70:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x6F,r33; (p06) br.cond.dptk.few	400000000010A0E0 }

l4000000000109F80:
	{ nop.m	0x0; ld8	r33,[r32]; nop.i	0x0; }
	{ adds	r14,0x8,r33; cmp.eq	p07,p06,0x0,r33; (p07) br.cond.dpnt.few	400000000010A130; }

l4000000000109FA0:
	{ ld8	r14,[r14]; ld8	r44,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r44; nop.i	0x0; (p06) br.cond.dpnt.few	400000000010A110; }

l4000000000109FC0:
	{ ld1	r15,[r44]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	400000000010A110; }

l4000000000109FE0:
	{ cmp4.eq	p06,p07,0x2D,r15; adds	r43,0x0,r35; (p06) br.cond.dpnt.few	400000000010A110; }

l4000000000109FF0:
	{ cmp4.eq	p07,p06,0x2B,r15; nop.i	0x0; (p07) br.cond.dpnt.few	400000000010A110; }

l400000000010A000:
	{ adds	r32,0x0,r33; addl	r36,1,r0; br.call.sptk.many	b0,set_minus_o_option; }
	{ adds	r1,0x0,r42; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dpnt.few	400000000010A090; }

l400000000010A020:
	{ ld1	r14,[r34],1; nop.m	0x0; sxt1	r43,r14; }
	{ adds	r33,0x0,r43; cmp4.eq	p07,p06,0x0,r43; (p06) br.cond.dptk.few	4000000000109F60; }

l400000000010A040:
	{ nop.m	0x0; ld8	r32,[r32]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p06) br.cond.dptk.few	4000000000109EC0; }

l400000000010A060:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r36; nop.i	0x0; }
	{ nop.m	0x0; (p06) adds	r8,0x0,r39; (p06) br.cond.dptk.few	4000000000109E90; }

l400000000010A07C:
	{ (p49) nop; zxt1	r96,r64; break.i	0x1000 }

l400000000010A080:
	{ adds	r8,0x0,r39; nop.m	0x0; nop.i	0x0 }

l400000000010A090:
	{ nop.m	0x0; adds	r14,0x20,r12; nop.i	0x0; }
	{ st8	[r8],r14; nop.i	0x0; br.call.sptk.many	b0,set_shellopts; }
	{ adds	r14,0x20,r12; nop.m	0x0; adds	r1,0x0,r42; }
	{ ld8	r8,[r14]; mov.i	ar.pfs,r41; mov.spnt	b0,r40,400000000010A0C0 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0; }

l400000000010A0E0:
	{ adds	r44,0x0,r35; addl	r36,1,r0; br.call.sptk.many	b0,change_flag; }
	{ nop.m	0x0; adds	r1,0x0,r42; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8 }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	400000000010A2E0; br.cond.sptk.few	4000000000109F40 }

l400000000010A10C:
	{ (p50) ldfps	f127,f63,[r36]; (p53) shladd	r31,r127,0x4,r127; zxt1	r32,r64 }

l400000000010A110:
	{ addl	r43,-1,r0; adds	r44,0x0,r37; br.call.sptk.many	b0,list_minus_o_opts; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	4000000000109F40 }

l400000000010A130:
	{ adds	r44,0x0,r37; addl	r43,-1,r0; br.call.sptk.many	b0,list_minus_o_opts; }
	{ adds	r1,0x0,r42; adds	r43,0x0,r39; br.call.sptk.many	b0,sh_chkwrite; }
	{ adds	r1,0x0,r42; adds	r39,0x0,r8; br.cond.sptk.few	4000000000109F40 }

l400000000010A160:
	{ adds	r14,0x20,r12; nop.m	0x0; adds	r8,0x0,r0; }
	{ st8	[r8],r14; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ adds	r14,0x20,r12; nop.m	0x0; adds	r1,0x0,r42; }
	{ ld8	r8,[r14]; mov.i	ar.pfs,r41; mov.spnt	b0,r40,400000000010A190 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0; }

l400000000010A1B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,all_shell_variables; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r42; nop.i	0x0 }
	{ adds	r33,0x0,r8; adds	r43,0x0,r8; (p06) br.cond.dpnt.few	400000000010A220; }

l400000000010A1E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,print_var_list; }
	{ nop.m	0x0; adds	r1,0x0,r42; adds	r43,0x0,r33 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r42; nop.m	0x0; nop.i	0x0; }

l400000000010A220:
	{ addl	r14,6456,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	400000000010A370 }

l400000000010A250:
	{ nop.m	0x0; adds	r43,0x0,r0; br.call.sptk.many	b0,sh_chkwrite; }
	{ adds	r1,0x0,r42; nop.m	0x0; nop.i	0x0 }

l400000000010A270:
	{ nop.m	0x0; mov.i	ar.pfs,r41; mov.spnt	b0,r40,400000000010A270 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0 }

l400000000010A290:
	{ adds	r34,0x1,r14; ld1	r15,[r34]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r15; nop.i	0x0; (p06) br.cond.dpnt.few	400000000010A480; }

l400000000010A2C0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r15; (p07) br.cond.dpnt.few	400000000010A3E0 }

l400000000010A2D0:
	{ addl	r35,45,r0; adds	r37,0x0,r0; br.cond.sptk.few	4000000000109F40 }

l400000000010A2E0:
	{ adds	r14,0x10,r12; addl	r8,1,r0; adds	r15,0x12,r12; }
	{ adds	r43,0x0,r14; st1	[r14],r1,1; nop.i	0x0 }
	{ st1	[r0],r15; st1	[r33],r14; adds	r14,0x20,r12; }
	{ st8	[r8],r14; nop.i	0x0; br.call.sptk.many	b0,sh_invalidopt; }
	{ adds	r1,0x0,r42; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ adds	r1,0x0,r42; nop.i	0x0; br.call.sptk.many	b0,set_shellopts; }
	{ adds	r14,0x20,r12; nop.m	0x0; adds	r1,0x0,r42; }
	{ ld8	r8,[r14]; mov.i	ar.pfs,r41; mov.spnt	b0,r40,400000000010A350 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0; }

l400000000010A370:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,all_shell_functions; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r33,0x0,r8; nop.i	0x0 }
	{ adds	r1,0x0,r42; adds	r43,0x0,r8; (p06) br.cond.dpnt.few	400000000010A250; }

l400000000010A3A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,print_func_list; }
	{ adds	r1,0x0,r42; adds	r43,0x0,r33; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r42; adds	r43,0x0,r0; br.call.sptk.many	b0,sh_chkwrite; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	400000000010A270 }

l400000000010A3E0:
	{ adds	r14,0x2,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	400000000010A2D0 }

l400000000010A410:
	{ ld8	r32,[r32]; nop.m	0x0; nop.i	0x0; }

l400000000010A420:
	{ nop.m	0x0; adds	r43,0x0,r32; addl	r44,1,r0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,remember_args; }
	{ adds	r1,0x0,r42; nop.m	0x0; nop.i	0x0 }

l400000000010A450:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r36; nop.i	0x0; }
	{ nop.m	0x0; (p06) adds	r8,0x0,r39; (p06) br.cond.dptk.few	4000000000109E90 }

l400000000010A46C:
	{ (p17) invala; break.i	0x1000; break.b	0x1000 }

l400000000010A470:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000010A080 }

l400000000010A480:
	{ ld8	r32,[r32]; nop.m	0x0; addl	r43,120,r0 }
	{ addl	r44,43,r0; nop.m	0x0; br.call.sptk.many	b0,change_flag; }
	{ adds	r1,0x0,r42; nop.m	0x0; addl	r43,118,r0 }
	{ addl	r44,43,r0; nop.m	0x0; br.call.sptk.many	b0,change_flag; }
	{ adds	r1,0x0,r42; cmp.eq	p07,p06,0x0,r32; (p07) br.cond.sptk.few	400000000010A080 }

l400000000010A4D0:
	{ adds	r43,0x0,r32; nop.m	0x0; addl	r44,1,r0 }
	{ addl	r36,1,r0; nop.m	0x0; br.call.sptk.many	b0,remember_args; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	400000000010A450; }

;; unset_builtin: 400000000010A500
unset_builtin proc
	{ alloc	r43,ar.pfs,0x11,0x0,0xE; adds	r44,0x0,r1; mov	r45,pr; }
	{ nop.m	0x0; mov	r42,b2; adds	r34,0x0,r0 }
	{ adds	r33,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,reset_internal_getopt; }
	{ adds	r1,0x0,r44; nop.m	0x0; nop.i	0x0; }

l400000000010A540:
	{ addl	r47,-8532,r1; nop.m	0x0; adds	r46,0x0,r32; }
	{ ld8	r47,[r47]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r44; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dpnt.few	400000000010A600; }

l400000000010A570:
	{ cmp4.eq	p06,p07,0x66,r8; nop.i	0x0; (p06) br.cond.dpnt.few	400000000010A8A0; }

l400000000010A580:
	{ cmp4.eq	p06,p07,0x76,r8; nop.i	0x0; (p06) br.cond.dpnt.few	400000000010A5D0; }

l400000000010A590:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ nop.m	0x0; adds	r1,0x0,r44; addl	r8,258,r0 }

l400000000010A5B0:
	{ nop.m	0x0; mov	pr,r45,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r43; }
	{ nop.m	0x0; mov.spnt	b0,r42,400000000010A5C0; br.ret	b0 }

l400000000010A5D0:
	{ addl	r47,-8532,r1; adds	r46,0x0,r32; addl	r34,1,r0; }
	{ ld8	r47,[r47]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r44; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p06) br.cond.dptk.few	400000000010A570; }

l400000000010A600:
	{ addl	r15,9268,r1; cmp4.eq	p18,p19,0x0,r33; and	r14,r33,r34 }
	{ xor	r36,0x1,r33; addl	r38,6456,r1; cmp4.eq	p21,p20,0x0,r34; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p18) addl	r41,-8540,r1 }

l400000000010A630:
	{ adds	r35,0x0,r0; cmp4.eq	p17,p16,0x0,r33; (p06) br.cond.dpnt.few	400000000010AC30; }

l400000000010A640:
	{ (p19) addl	r41,-8548,r1; nop.m	0x0; addl	r40,8192,r0 }

l400000000010A646:
	{ break.m	0x4000; (p20) nop; break.i	0x80000 }
	{ (p18) break.m	0x41200; nop; (p32) addl	r8,864,r3 }
	{ Invalid; Invalid; Invalid }

l400000000010A66C:
	{ nop; Invalid; cmp.eq	p00,p00,r32,r0 }

l400000000010A676:
	{ add	r0,r0,r1; (p03) nop; cmp.lt	p00,p00,r0,r32 }
	{ (p04) chk.a.clr	f0,3FFFFFFFFF18A686; nop; break.i	0x80000; }

l400000000010A68C:
	{ (p57) nop; break.i	0x1000; break.b	0x1000 }

l400000000010A690:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000010A6A0:
	{ adds	r14,0x8,r34; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r33,[r14]; nop.i	0x0; (p17) br.cond.dpnt.few	400000000010AA10; }

l400000000010A6C0:
	{ adds	r46,0x0,r33; ld4	r14,[r38]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	400000000010A700 }

l400000000010A6E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,legal_identifier; }
	{ adds	r1,0x0,r44; cmp4.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	400000000010A8B0 }

l400000000010A700:
	{ nop.m	0x0; adds	r46,0x0,r33; adds	r37,0x0,r0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,find_function; }
	{ adds	r1,0x0,r44; nop.m	0x0; nop.i	0x0 }

l400000000010A730:
	{ cmp.eq	p07,p06,0x0,r8; (p06) addl	r15,1,r0; nop.i	0x0; }

l400000000010A73C:
	{ nop; cmp4.eq.or.andcm	p00,p32,r32,r0; zxt1	r0,r64 }

l400000000010A74C:
	{ Invalid; cmp.lt	p00,p00,r32,r0; (p01) break.i	0x101E0 }
	{ (p18) invala; cmp.lt	p00,p00,r32,r0; mov	pr,r100,0xE600 }
	{ Invalid; (p02) cmp.eq	p10,p16,r2,r64; Invalid }

l400000000010A770:
	{ adds	r16,0x28,r8; ld4	r15,[r16]; nop.i	0x0; }
	{ nop.m	0x0; and	r17,r40,r15; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r17; nop.i	0x0; (p07) br.cond.dpnt.few	400000000010A8F0; }

l400000000010A7A0:
	{ nop.m	0x0; tbit.z	p06,p07,r15,0x1; (p07) br.cond.dpnt.few	400000000010A990 }

l400000000010A7B0:
	{ nop.m	0x0; and	r14,r37,r14; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000010AAC0; }

l400000000010A7D0:
	{ ld8	r14,[r16]; and	r14,0x44,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	400000000010AB70 }

l400000000010A7F0:
	{ addl	r47,-8500,r1; nop.m	0x0; addl	r48,5,r0 }
	{ adds	r46,0x0,r0; nop.m	0x0; adds	r35,0x1,r35; }
	{ ld8	r47,[r47]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r44; nop.m	0x0; adds	r46,0x0,r8 }
	{ adds	r47,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,builtin_error; }
	{ adds	r1,0x0,r44; ld8	r34,[r34]; nop.i	0x0; }

l400000000010A850:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	400000000010A6A0; }

l400000000010A860:
	{ cmp4.eq	p07,p06,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r43; }
	{ (p06) addl	r35,1,r0; nop.m	0x0; mov.spnt	b0,r42,400000000010A870; }

l400000000010A876:
	{ break.m	0x4000; cmp4.ltu	p42,p03,r1,r64; (p49) nop }

l400000000010A886:
	{ add	r0,r0,r1; (p63) nop; break.i	0x80000 }
	{ Invalid; (p34) nop; break.i	0x80000 }

l400000000010A8A0:
	{ nop.m	0x0; addl	r33,1,r0; br.cond.sptk.few	400000000010A540; }

l400000000010A8B0:
	{ adds	r46,0x0,r33; adds	r35,0x1,r35; br.call.sptk.many	b0,sh_invalidid; }
	{ ld8	r34,[r34]; nop.m	0x0; adds	r1,0x0,r44; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	400000000010A6A0 }

l400000000010A8E0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000010A860 }

l400000000010A8F0:
	{ addl	r47,-8516,r1; nop.m	0x0; addl	r48,5,r0 }
	{ adds	r46,0x0,r0; nop.m	0x0; adds	r35,0x1,r35; }
	{ ld8	r47,[r47]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r44; nop.m	0x0; adds	r46,0x0,r8 }
	{ adds	r47,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,builtin_error; }
	{ nop.m	0x0; adds	r1,0x0,r44; nop.i	0x0 }
	{ ld8	r34,[r34]; nop.m	0x0; br.cond.sptk.few	400000000010A850 }

l400000000010A960:
	{ adds	r16,0x28,r8; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dpnt.few	400000000010AAC0; }

l400000000010A970:
	{ nop.m	0x0; ld4	r15,[r16]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r15,0x1; (p06) br.cond.dptk.few	400000000010A7B0 }

l400000000010A990:
	{ addl	r47,-8508,r1; nop.m	0x0; adds	r46,0x0,r0 }
	{ addl	r48,5,r0; nop.m	0x0; adds	r35,0x1,r35; }
	{ ld8	r47,[r47]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r44; adds	r46,0x0,r8; nop.i	0x0 }
	{ adds	r47,0x0,r33; adds	r48,0x0,r41; br.call.sptk.many	b0,builtin_error; }
	{ ld8	r34,[r34]; nop.m	0x0; adds	r1,0x0,r44; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	400000000010A6A0 }

l400000000010AA00:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000010A860 }

l400000000010AA10:
	{ adds	r46,0x0,r33; adds	r37,0x0,r0; br.call.sptk.many	b0,valid_array_reference; }
	{ adds	r46,0x0,r33; nop.m	0x0; addl	r47,91,r0 }
	{ adds	r1,0x0,r44; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	400000000010AA70 }

l400000000010AA40:
	{ addl	r37,1,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B680; }
	{ adds	r39,0x0,r8; nop.m	0x0; adds	r1,0x0,r44; }
	{ st1	[r39],r1,1; nop.m	0x0; nop.i	0x0 }

l400000000010AA70:
	{ adds	r46,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,legal_identifier; }
	{ cmp4.eq	p06,p07,0x0,r8; nop.m	0x0; adds	r1,0x0,r44 }
	{ adds	r46,0x0,r33; nop.m	0x0; (p06) br.cond.dpnt.few	400000000010A8B0; }

l400000000010AAA0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ nop.m	0x0; adds	r1,0x0,r44; br.cond.sptk.few	400000000010A730 }

l400000000010AAC0:
	{ nop.m	0x0; adds	r46,0x0,r33; (p18) br.cond.dptk.few	400000000010ABF0 }

l400000000010AAD0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,unbind_func; }
	{ cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r8; nop.m	0x0; adds	r1,0x0,r44; }
	{ (p06) addl	r8,1,r0; nop.i	0x0; (p07) adds	r8,0x0,r0; }

l400000000010AAF6:
	{ chk.a.nc	f0,3FFFFFFFFF10B2F6; (p04) nop; break.i	0x80000 }

l400000000010AB00:
	{ nop.m	0x0; and	r8,r8,r36; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	400000000010ABA0; (p21) br.cond.dpnt.few	400000000010ABC0 }

l400000000010AB1C:
	{ Invalid; cmp.lt	p00,p00,r32,r0; (p05) epc }

l400000000010AB20:
	{ nop.m	0x0; adds	r46,0x0,r33; br.call.sptk.many	b0,stupidly_hack_special_variables; }
	{ adds	r1,0x0,r44; nop.m	0x0; nop.i	0x0 }

l400000000010AB40:
	{ ld8	r34,[r34]; nop.m	0x0; nop.i	0x0; }

l400000000010AB50:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	400000000010A6A0 }

l400000000010AB60:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000010A860 }

l400000000010AB70:
	{ adds	r46,0x0,r8; adds	r47,0x0,r39; br.call.sptk.many	b0,unbind_array_element; }
	{ cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; nop.m	0x0; adds	r1,0x0,r44; }
	{ (p07) adds	r35,0x1,r35; (p07) addl	r8,1,r0; (p07) br.cond.dpnt.few	400000000010AB00 }

l400000000010AB96:
	{ (p04) chk.a.clr	f1,3FFFFFFFFF30AB96; nop; break.i	0x80000; }

l400000000010AB9C:
	{ Invalid; break.i	0x1000; br.cond	b0 }

l400000000010ABA0:
	{ nop.m	0x0; nop.i	0x0; (p17) br.cond.spnt.few	400000000010AB20; }

l400000000010ABB0:
	{ ld8	r34,[r34]; nop.i	0x0; br.cond.sptk.few	400000000010AB50 }

l400000000010ABC0:
	{ adds	r46,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,unbind_func; }
	{ adds	r1,0x0,r44; adds	r46,0x0,r33; br.call.sptk.many	b0,stupidly_hack_special_variables; }
	{ nop.m	0x0; adds	r1,0x0,r44; br.cond.sptk.few	400000000010AB40 }

l400000000010ABF0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,unbind_variable; }
	{ cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r8; adds	r1,0x0,r44; tbit.z.or.andcm	p07,p06,r36,0x0 }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	400000000010AB20; (p20) br.cond.dptk.few	400000000010AB20 }

l400000000010AC1C:
	{ (p56) invala; break.i	0x1000; break.b	0x1000 }

l400000000010AC20:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000010ABC0 }

l400000000010AC30:
	{ addl	r47,-8524,r1; addl	r48,5,r0; adds	r46,0x0,r0; }
	{ ld8	r47,[r47]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r44; adds	r46,0x0,r8; br.call.sptk.many	b0,builtin_error; }
	{ addl	r8,1,r0; adds	r1,0x0,r44; mov	pr,r45,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r43; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r42,400000000010AC80; br.ret	b0; }
400000000010AC90 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
400000000010ACA0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
400000000010ACB0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; show_var_attributes: 400000000010ACC0
;;   Called from:
;;     400000000010B69C (in show_all_var_attributes)
;;     400000000010B85C (in show_name_attributes)
;;     400000000010C59C (in set_or_show_attributes)
show_var_attributes proc
	{ alloc	r39,ar.pfs,0xD,0x0,0x9; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r38,b6 }
	{ cmp4.eq	p06,p07,0x0,r33; adds	r40,0x0,r1; adds	r36,0x28,r32; }
	{ nop.m	0x0; (p07) adds	r33,0x0,r0; nop.i	0x0; }

l400000000010ACEC:
	{ invala; nop; (p20) mov	pr,r0,0x8400 }

l400000000010ACFC:
	{ (p02) nop; zxt4	r46,r12; break.i	0x1000 }

l400000000010AD00:
	{ addl	r37,6456,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r37]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	400000000010B140 }

l400000000010AD30:
	{ ld4	r14,[r36]; nop.m	0x0; tbit.z	p06,p07,r14,0x2; }
	{ (p07) adds	r16,0x10,r12; (p07) addl	r15,97,r0; nop.b	0x0 }

l400000000010AD46:
	{ Invalid; cmp4.ltu	p00,p16,r0,r0; (p49) nop.b	0x28; }

l400000000010AD4C:
	{ setf.exp	f0,r0; zxt4	r0,r0; break.i	0x1000 }

l400000000010AD56:
	{ break.m	0x4000; (p04) cmp4.ltu	p08,p40,r14,r9; (p01) addl	r96,77827,r0 }

l400000000010AD66:
	{ Invalid; Invalid; Invalid; }

l400000000010AD6C:
	{ (p06) break.m	0xA038E; cmp4.eq.or.andcm	p00,p32,r32,r0; (p01) mov	pr,r72,0xC0 }
	{ (p08) setf.exp	f12,r0; (p20) cmp4.ne.or.andcm	p32,p48,r8,r64; (p01) mov	pr,r3,0x80C8 }

l400000000010AD80:
	{ (p07) adds	r35,0x1,r35; (p07) add	r15,r16,r15; (p07) addl	r16,65,r0; }

l400000000010AD86:
	{ (p07) chk.a.clr	f16,3FFFFFFFFF10AE76; (p08) cmp.ne.and	p01,p08,0x0,r0; (p01) br.call.spnt.few	b0,b4; }

l400000000010AD8C:
	{ Invalid; Invalid; Invalid }

l400000000010AD90:
	{ (p07) st1	[r16],r15; tbit.z	p06,p07,r14,0x3; sxt4	r15,r35 }

l400000000010AD96:
	{ (p03) addp4	r6,0xFFFFFFFFFFFFF40E,r7; (p07) cmp.lt	p00,p00,0x23,r22; (p01) cmp.eq.or.andcm	p04,p00,r4,r3 }

l400000000010ADA6:
	{ Invalid; (p07) cmp.eq.or	p16,p00,0xF,r0; Invalid; }

l400000000010ADAC:
	{ Invalid; (p34) mov	pr,r0,0x9032; cmp.eq.unc	p36,p40,0x3,r96; }

l400000000010ADB0:
	{ (p07) addl	r16,102,r0; (p07) st1	[r16],r15; sxt4	r15,r35 }

l400000000010ADB6:
	{ addl	r16,20879,r0; (p07) dep	r0,r35,r22,47,1; (p02) nop; }

l400000000010ADBC:
	{ chk.a.nc	r35,400000000098AF1C; (p02) nop; (p20) cmp.eq.unc	p32,p48,0x8,r64; }

l400000000010ADC6:
	{ (p17) addl	r1,24867,r0; (p07) br.call.dpnt.few.clr	b0,400000000010AEB6; nop }

l400000000010ADCC:
	{ (p08) chk.a.nc	r15,4000000000BEADCC; Invalid; Invalid; }

l400000000010ADD0:
	{ (p09) addl	r16,105,r0; (p09) st1	[r16],r15; tbit.z	p08,p09,r14,0x1; }

l400000000010ADD6:
	{ mf.a; Invalid; dep	r0,r0,r32,63,1 }

l400000000010ADDC:
	{ (p01) break.m	0xA048E; cmp.eq	p00,p32,0x20,r0; Invalid; }
	{ (p08) ldfp8.c.nc	f12,f0,[r66]; (p20) cmp.eq.unc	p32,p48,0x8,r64; Invalid }

l400000000010ADF0:
	{ (p09) adds	r35,0x1,r35; (p09) add	r15,r16,r15; (p09) addl	r16,114,r0; }

l400000000010ADF6:
	{ (p07) chk.s	f15,400000000010AEF6; (p08) br.wexit.spnt.many.clr	400000000030ADF6; (p02) br.call.spnt.few	b0,b4 }

l400000000010ADFC:
	{ (p57) chk.a.nc	r0,40000000009AEDFC; Invalid; (p33) cmp.eq.unc	p03,p42,0x23,r2 }

l400000000010AE00:
	{ (p09) st1	[r16],r15; tbit.z	p08,p09,r14,0x7; sxt4	r15,r35 }

l400000000010AE06:
	{ (p04) addl	r14,152590,r1; (p07) dep	r0,r35,r22,47,1; (p02) nop }

l400000000010AE16:
	{ (p17) addl	r1,24867,r0; (p07) br.call.dpnt.few.clr	b0,400000000010AF06; nop }

l400000000010AE1C:
	{ (p08) chk.a.nc	r15,4000000000BEAE1C; Invalid; Invalid; }

l400000000010AE20:
	{ (p09) addl	r16,116,r0; (p09) st1	[r16],r15; tbit.z	p08,p09,r14,0x0; }

l400000000010AE26:
	{ mf.a; Invalid; dep	r0,r0,r32,63,1 }

l400000000010AE2C:
	{ break.m	0xA048E; cmp.eq	p00,p32,0x20,r0; Invalid; }
	{ (p08) ldfp8.c.nc	f12,f0,[r66]; (p20) cmp.eq.unc	p32,p48,0x8,r64; Invalid }

l400000000010AE40:
	{ (p09) adds	r35,0x1,r35; (p09) add	r15,r16,r15; (p09) addl	r16,120,r0; }

l400000000010AE46:
	{ (p07) chk.s	f15,400000000010AF46; (p08) br.cond.spnt.many.clr	400000000030AE46; (p02) br.call.spnt.few	b0,b4 }

l400000000010AE4C:
	{ (p60) chk.a.nc	r0,40000000009AEE4C; Invalid; (p01) cmp.eq.unc	p05,p42,0x23,r2 }

l400000000010AE50:
	{ (p09) st1	[r16],r15; tbit.z	p08,p09,r14,0xA; sxt4	r15,r35 }

l400000000010AE56:
	{ (p04) addl	r20,152590,r1; (p07) dep	r0,r35,r22,47,1; (p02) nop }

l400000000010AE66:
	{ (p17) addl	r1,24867,r0; (p07) br.call.dpnt.few.clr	b0,400000000010AF56; nop }

l400000000010AE6C:
	{ (p08) chk.a.nc	r15,4000000000BEAE6C; Invalid; Invalid; }

l400000000010AE70:
	{ (p09) addl	r16,99,r0; (p09) st1	[r16],r15; tbit.z	p08,p09,r14,0x9; }

l400000000010AE76:
	{ mf.a; Invalid; dep	r0,r0,r32,63,1 }

l400000000010AE7C:
	{ (p09) break.m	0xA048E; cmp.eq	p00,p32,0x20,r0; Invalid; }
	{ (p08) ldfp8.c.nc	f12,f0,[r66]; (p20) cmp.eq.unc	p32,p48,0x8,r64; Invalid }

l400000000010AE90:
	{ (p09) adds	r35,0x1,r35; (p09) add	r15,r16,r15; (p09) addl	r16,108,r0; }

l400000000010AE96:
	{ (p07) chk.s	f15,400000000010AF96; nop; (p02) br.call.spnt.few	b0,b4 }

l400000000010AE9C:
	{ (p54) chk.a.nc	r0,4000000000D2EE9C; Invalid; Invalid }

l400000000010AEA0:
	{ (p09) st1	[r16],r15; tbit.z	p08,p09,r14,0x8; (p08) br.cond.dptk.few	400000000010AEE0 }

l400000000010AEA6:
	{ (p04) nop; Invalid; break.i	0x80000 }

l400000000010AEB0:
	{ nop.m	0x0; sxt4	r14,r35; nop.i	0x0 }
	{ adds	r15,0x10,r12; adds	r35,0x1,r35; add	r14,r15,r14 }
	{ addl	r15,117,r0; st1	[r15],r14; nop.i	0x0 }

l400000000010AEE0:
	{ nop.m	0x0; sxt4	r14,r35; adds	r15,0x10,r12; }
	{ nop.m	0x0; add	r14,r15,r14; nop.i	0x0; }
	{ st1	[r0],r14; nop.i	0x0; (p06) br.cond.dptk.few	400000000010B200 }

l400000000010AF10:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	400000000010B200; }

l400000000010AF20:
	{ nop.m	0x0; addl	r37,6456,r1; tbit.z	p07,p06,r33,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dpnt.few	400000000010B250; }

l400000000010AF40:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }

l400000000010AF50:
	{ ld4	r14,[r37]; cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r34,0x0,r0; (p07) br.cond.dptk.few	400000000010B460; }

l400000000010AF6C:
	{ (p40) cmp.lt	p00,p08,r0,r33; zxt1	r2,r64; nop }

l400000000010AF70:
	{ adds	r14,0x8,r32; nop.m	0x0; addl	r43,3,r0 }
	{ ld8	r41,[r32]; nop.m	0x0; addl	r34,1,r0; }
	{ ld8	r42,[r14]; nop.i	0x0; br.call.sptk.many	b0,named_function_string; }
	{ adds	r1,0x0,r40; adds	r41,0x0,r8; br.call.sptk.many	b0,fn400000000001B380; }
	{ ld4	r14,[r37]; nop.m	0x0; adds	r1,0x0,r40; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dpnt.few	400000000010B460; }

l400000000010AFD0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000010AFE0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r35; (p07) br.cond.dpnt.few	400000000010B2E0 }

l400000000010AFF0:
	{ addl	r43,-1148,r1; addl	r42,-1140,r1; addl	r41,1,r0; }
	{ nop.m	0x0; ld8	r43,[r43]; nop.i	0x0 }
	{ ld8	r42,[r42]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r40; nop.m	0x0; nop.i	0x0 }

l400000000010B030:
	{ nop.m	0x0; ld4	r14,[r36]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x2; (p07) br.cond.dpnt.few	400000000010B420; }

l400000000010B050:
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x6; (p07) br.cond.dpnt.few	400000000010B500; }

l400000000010B060:
	{ cmp4.eq	p07,p06,0x0,r34; nop.i	0x0; (p06) br.cond.dpnt.few	400000000010B3E0; }

l400000000010B070:
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x3; (p06) br.cond.dptk.few	400000000010B310; }

l400000000010B080:
	{ nop.m	0x0; tbit.z	p07,p06,r33,0x0; (p06) br.cond.dptk.few	400000000010B0C0 }

l400000000010B090:
	{ addl	r14,6456,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	400000000010B3E0 }

l400000000010B0C0:
	{ nop.m	0x0; adds	r14,0x8,r32; addl	r43,3,r0 }
	{ nop.m	0x0; ld8	r41,[r32]; nop.i	0x0; }
	{ ld8	r42,[r14]; nop.i	0x0; br.call.sptk.many	b0,named_function_string; }
	{ nop.m	0x0; adds	r1,0x0,r40; adds	r41,0x0,r8 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B380; }
	{ adds	r1,0x0,r40; nop.m	0x0; nop.i	0x0 }

l400000000010B120:
	{ adds	r8,0x0,r0; mov.i	ar.pfs,r39; mov.spnt	b0,r38,400000000010B120 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l400000000010B140:
	{ ld4	r14,[r36]; nop.m	0x0; tbit.z	p06,p07,r14,0x2; }
	{ (p07) adds	r16,0x10,r12; (p07) addl	r15,97,r0; (p07) addl	r35,1,r0; }

l400000000010B156:
	{ Invalid; (p17) cmp4.eq.or	p01,p08,r0,r0; Invalid; }

l400000000010B15C:
	{ Invalid; Invalid; Invalid }

l400000000010B160:
	{ (p07) st1	[r15],r16; (p06) adds	r35,0x0,r0; tbit.z	p06,p07,r14,0x6; }

l400000000010B166:
	{ Invalid; Invalid; Invalid; }

l400000000010B16C:
	{ (p06) break.m	0xA038E; cmp4.eq.or.andcm	p00,p32,r32,r0; (p01) mov	pr,r72,0xC0 }
	{ (p08) setf.exp	f12,r0; (p20) cmp4.ne.or.andcm	p32,p48,r8,r64; (p01) mov	pr,r3,0x80C8 }

l400000000010B180:
	{ (p07) adds	r35,0x1,r35; (p07) add	r15,r16,r15; (p07) addl	r16,65,r0; }

l400000000010B186:
	{ (p07) chk.a.clr	f16,3FFFFFFFFF10B276; (p08) cmp4.ne.or.andcm	p01,p08,r0,r0; (p01) br.call.spnt.few	b0,b4; }

l400000000010B18C:
	{ Invalid; Invalid; (p32) nop }

l400000000010B190:
	{ (p07) st1	[r16],r15; tbit.z	p06,p07,r14,0x3; (p06) br.cond.dptk.few	400000000010B4B0; }

l400000000010B196:
	{ (p03) chk.a.nc	r6,3FFFFFFFFFB0EA76; nop; break.i	0x80000 }

l400000000010B1A0:
	{ nop.m	0x0; sxt4	r15,r35; nop.b	0x0 }
	{ adds	r35,0x1,r35; adds	r16,0x10,r12; cmp4.eq	p06,p07,0x0,r34; }
	{ nop.m	0x0; sxt4	r14,r35; add	r15,r16,r15; }
	{ add	r14,r16,r14; addl	r16,102,r0; nop.i	0x0 }
	{ st1	[r16],r15; st1	[r0],r14; (p06) br.cond.dptk.few	400000000010AF50; }

l400000000010B1F0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000010B200:
	{ nop.m	0x0; tbit.z	p07,p06,r33,0x0; (p06) br.cond.dptk.few	400000000010AFE0 }

l400000000010B210:
	{ addl	r37,6456,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r37]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	400000000010AFE0 }

l400000000010B240:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000010B460 }

l400000000010B250:
	{ nop.m	0x0; adds	r14,0x8,r32; addl	r43,3,r0 }
	{ nop.m	0x0; ld8	r41,[r32]; nop.i	0x0; }
	{ ld8	r42,[r14]; nop.i	0x0; br.call.sptk.many	b0,named_function_string; }
	{ adds	r1,0x0,r40; adds	r41,0x0,r8; br.call.sptk.many	b0,fn400000000001B380; }
	{ adds	r15,0x10,r12; nop.m	0x0; adds	r1,0x0,r40 }
	{ cmp4.eq	p07,p06,0x1,r35; nop.m	0x0; (p06) br.cond.spnt.few	400000000010B580; }

l400000000010B2B0:
	{ ld1	r14,[r15]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x66,r14; (p06) br.cond.dpnt.few	400000000010B120; }

l400000000010B2D0:
	{ (p07) addl	r34,1,r0; nop.m	0x0; nop.i	0x0; }

l400000000010B2D6:
	{ break.m	0x4000; nop; (p32) nop }

l400000000010B2E0:
	{ addl	r42,-1140,r1; adds	r43,0x10,r12; addl	r41,1,r0; }

l400000000010B2E2:
	{ Invalid; (p02) nop; br.call.sptk.few	b0,40000000002242E2; }
	{ (p32) break.m	0x2030A; nop; Invalid; }
	{ invala; nop; (p58) break.i	0x247FF }

l400000000010B310:
	{ nop.m	0x0; tbit.z	p07,p06,r14,0xC; adds	r14,0x8,r32 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dpnt.few	400000000010B3E0; }

l400000000010B330:
	{ nop.m	0x0; ld8	r41,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r41; nop.i	0x0; (p06) br.cond.dpnt.few	400000000010B3E0; }

l400000000010B350:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_double_quote; }
	{ nop.m	0x0; adds	r1,0x0,r40; adds	r35,0x0,r8 }
	{ ld8	r43,[r32]; adds	r44,0x0,r8; addl	r41,1,r0; }
	{ nop.m	0x0; addl	r42,-1116,r1; nop.i	0x0; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r40; adds	r41,0x0,r35; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r8,0x0,r0; adds	r1,0x0,r40; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,400000000010B3C0; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0; }

l400000000010B3E0:
	{ ld8	r41,[r32]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B380; }
	{ adds	r8,0x0,r0; adds	r1,0x0,r40; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,400000000010B400; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0; }

l400000000010B420:
	{ adds	r41,0x0,r32; addl	r42,1,r0; br.call.sptk.many	b0,print_array_assignment; }
	{ adds	r8,0x0,r0; adds	r1,0x0,r40; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,400000000010B440; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l400000000010B460:
	{ addl	r41,1,r0; cmp4.eq	p06,p07,0x0,r35; (p06) br.cond.dptk.few	400000000010B540; }

l400000000010B470:
	{ addl	r14,9036,r1; addl	r42,-1132,r1; adds	r44,0x10,r12; }
	{ nop.m	0x0; ld8	r42,[r42]; nop.i	0x0; }
	{ ld8	r43,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ nop.m	0x0; adds	r1,0x0,r40; br.cond.sptk.few	400000000010B030 }

l400000000010B4B0:
	{ nop.m	0x0; sxt4	r14,r35; adds	r15,0x10,r12; }
	{ nop.m	0x0; add	r14,r15,r14; nop.i	0x0; }
	{ st1	[r0],r14; ld4	r14,[r37]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	400000000010AFE0 }

l400000000010B4F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000010B460 }

l400000000010B500:
	{ adds	r41,0x0,r32; addl	r42,1,r0; br.call.sptk.many	b0,print_assoc_assignment; }
	{ adds	r8,0x0,r0; adds	r1,0x0,r40; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,400000000010B520; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l400000000010B540:
	{ addl	r14,9036,r1; nop.m	0x0; addl	r42,-1124,r1; }
	{ nop.m	0x0; ld8	r42,[r42]; nop.i	0x0; }
	{ ld8	r43,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ nop.m	0x0; adds	r1,0x0,r40; br.cond.sptk.few	400000000010B030 }

l400000000010B580:
	{ addl	r34,1,r0; cmp4.eq	p06,p07,0x0,r35; (p06) br.cond.dptk.few	400000000010AFF0 }

l400000000010B590:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000010B2E0; }
400000000010B5A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000010B5B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; show_all_var_attributes: 400000000010B5C0
;;   Called from:
;;     40000000000F19AC (in fn40000000000F0900)
show_all_var_attributes proc
	{ alloc	r40,ar.pfs,0xD,0x0,0xA; nop.m	0x0; mov	r39,b7 }
	{ adds	r41,0x0,r1; cmp4.eq	p06,p07,0x0,r32; (p06) br.cond.dptk.few	400000000010B730; }

l400000000010B5E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,all_shell_variables; }
	{ nop.m	0x0; adds	r1,0x0,r41; adds	r38,0x0,r8; }

l400000000010B600:
	{ cmp.eq	p06,p07,0x0,r38; adds	r34,0x8,r38; addl	r37,8388,r1 }
	{ addl	r35,-9924,r1; addl	r36,-9868,r1; (p06) adds	r34,0x0,r0 }

l400000000010B620:
	{ nop.m	0x0; ld8	r35,[r35]; (p06) br.cond.dpnt.few	400000000010B710; }

l400000000010B630:
	{ ld8	r36,[r36]; ld8	r42,[r38]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r42; (p07) br.cond.dpnt.few	400000000010B6E0; }

l400000000010B650:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000010B660:
	{ ld8	r14,[r37]; cmp.eq	p08,p09,r35,r14; cmp.eq	p06,p07,r36,r14; }
	{ (p08) addl	r43,1,r0; nop.i	0x0; (p08) br.cond.dpnt.few	400000000010B690; }

l400000000010B676:
	{ Invalid; adds	r2,0x1080,r64; (p49) nop }

l400000000010B680:
	{ (p06) addl	r43,1,r0; nop.i	0x0; (p07) adds	r43,0x0,r0 }

l400000000010B686:
	{ addp4	r0,0xFFFFFFFFFFFFE000,r1; (p21) nop; nop }

l400000000010B690:
	{ adds	r44,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,show_var_attributes; }
	{ adds	r1,0x0,r41; adds	r42,0x0,r0; br.call.sptk.many	b0,sh_chkwrite; }
	{ adds	r1,0x0,r41; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dpnt.few	400000000010B750; }

l400000000010B6C0:
	{ nop.m	0x0; ld8	r42,[r34],8; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r42; (p06) br.cond.dptk.few	400000000010B660 }

l400000000010B6E0:
	{ nop.m	0x0; adds	r42,0x0,r38; adds	r34,0x0,r0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r41; nop.m	0x0; nop.i	0x0 }

l400000000010B710:
	{ adds	r8,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.spnt	b0,r39,400000000010B720; br.ret	b0; }

l400000000010B730:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,all_shell_functions; }
	{ adds	r1,0x0,r41; adds	r38,0x0,r8; br.cond.sptk.few	400000000010B600; }

l400000000010B750:
	{ adds	r42,0x0,r38; addl	r34,1,r0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r41; br.cond.sptk.few	400000000010B710; }
400000000010B770 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; show_name_attributes: 400000000010B780
;;   Called from:
;;     40000000000F0B6C (in fn40000000000F0900)
show_name_attributes proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; nop.m	0x0; mov	r34,b2 }
	{ adds	r36,0x0,r1; nop.m	0x0; adds	r37,0x0,r32; }
	{ addl	r38,1,r0; nop.i	0x0; br.call.sptk.many	b0,find_variable_internal; }
	{ adds	r14,0x28,r8; nop.m	0x0; adds	r1,0x0,r36 }
	{ cmp.eq	p06,p07,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	400000000010B880; }

l400000000010B7D0:
	{ ld4	r14,[r14]; addl	r15,-9924,r1; addl	r38,-9868,r1; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0xC; addl	r14,8388,r1 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dpnt.few	400000000010B880; }

l400000000010B800:
	{ nop.m	0x0; ld8	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; ld8	r38,[r38]; nop.i	0x0; }
	{ ld8	r14,[r14]; cmp.eq	p08,p09,r15,r14; cmp.eq	p06,p07,r38,r14; }
	{ (p08) addl	r38,1,r0; nop.i	0x0; (p08) br.cond.dpnt.few	400000000010B850; }

l400000000010B836:
	{ Invalid; adds	r2,0x1080,r64; (p33) nop }

l400000000010B840:
	{ (p06) addl	r38,1,r0; nop.i	0x0; (p07) adds	r38,0x0,r0 }

l400000000010B846:
	{ chk.a.nc	f0,3FFFFFFFFF10C046; (p19) nop; (p16) nop }

l400000000010B850:
	{ adds	r37,0x0,r8; adds	r39,0x0,r33; br.call.sptk.many	b0,show_var_attributes; }
	{ adds	r8,0x0,r0; adds	r1,0x0,r36; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,400000000010B870; br.ret	b0 }

l400000000010B880:
	{ addl	r8,1,r0; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,400000000010B890; br.ret	b0; }
400000000010B8A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000010B8B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; set_var_attribute: 400000000010B8C0
;;   Called from:
;;     400000000010C13C (in set_or_show_attributes)
;;     400000000010C31C (in set_or_show_attributes)
set_var_attribute proc
	{ alloc	r40,ar.pfs,0xD,0x0,0xA; mov	r39,b7; adds	r41,0x0,r1 }
	{ adds	r42,0x0,r32; cmp4.eq	p06,p07,0x0,r34; (p06) br.cond.dptk.few	400000000010B9A0; }

l400000000010B8E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ cmp.eq	p07,p06,0x0,r8; adds	r8,0x28,r8; nop.i	0x0 }
	{ adds	r1,0x0,r41; andcm	r15,0xFFFFFFFFFFFFFFFF,r33; (p07) br.cond.dpnt.few	400000000010B980; }

l400000000010B910:
	{ ld4	r14,[r8]; and	r15,r14,r15; nop.i	0x0; }
	{ adds	r14,0x0,r15; st4	[r15],r8; nop.i	0x0; }

l400000000010B930:
	{ or	r33,r33,r14; nop.m	0x0; addl	r14,5780,r1; }
	{ nop.m	0x0; tbit.z	p07,p06,r33,0x0; (p07) br.cond.dpnt.few	400000000010B980; }

l400000000010B950:
	{ nop.m	0x0; ld4	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; adds	r15,0x1,r15; nop.i	0x0; }
	{ st4	[r15],r14; nop.m	0x0; nop.i	0x0 }

l400000000010B980:
	{ nop.m	0x0; mov.i	ar.pfs,r40; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r39,400000000010B990; br.ret	b0; }

l400000000010B9A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,find_tempenv_variable; }
	{ adds	r37,0x28,r8; adds	r1,0x0,r41; nop.i	0x0 }
	{ cmp.eq	p06,p07,0x0,r8; adds	r36,0x0,r8; (p06) br.cond.dpnt.few	400000000010BB70; }

l400000000010B9D0:
	{ nop.m	0x0; ld4	r14,[r37]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x14; (p06) br.cond.dptk.few	400000000010BB70 }

l400000000010B9F0:
	{ adds	r35,0x8,r8; ld8	r42,[r35]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r42; nop.i	0x0; (p06) br.cond.dpnt.few	400000000010BC10; }

l400000000010BA10:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r41; adds	r42,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r43,[r35]; nop.m	0x0; adds	r1,0x0,r41 }
	{ adds	r42,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r38,0x0,r8; nop.m	0x0; adds	r44,0x0,r0 }
	{ adds	r1,0x0,r41; ld8	r42,[r36]; nop.i	0x0; }
	{ adds	r43,0x0,r38; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ ld4	r15,[r37]; adds	r35,0x28,r8; addl	r17,-1048577,r0 }
	{ adds	r8,0x2C,r8; movl	r16,0x200000; }
	{ ld4	r14,[r35]; and	r15,r17,r15; adds	r1,0x0,r41 }
	{ ld4	r17,[r8]; or	r14,r14,r15; cmp4.eq	p06,p07,0x0,r17 }
	{ ld8	r42,[r36]; st4	[r14],r35; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r37]; nop.i	0x0; }
	{ or	r14,r16,r14; st4	[r14],r37; adds	r15,0x0,r14; }
	{ (p07) ld4	r14,[r35]; (p07) or	r16,r16,r14; nop.i	0x0; }

l400000000010BAF6:
	{ Invalid; cmp4.ltu	p00,p00,0x0,r1; (p01) cmp.eq.or	p00,p36,r100,r8; }

l400000000010BAFC:
	{ Invalid; cmp4.ne.or.andcm	p36,p40,r8,r100; Invalid }

l400000000010BB06:
	{ (p07) fwb; nop; break.b	0x80000; }

l400000000010BB0C:
	{ nop; cmp.eq	p00,p00,r32,r0; zxt1	r104,r3 }
	{ Invalid; Invalid; break.i	0x1000 }
	{ (p29) nop; ld4	r32,[r64]; zxt1	r64,r64 }
	{ (p37) nop; cmp.eq	p32,p16,r10,r64; (p01) rfi }
	{ cmp.eq	p00,p02,r1,r0; zxt1	r104,r3; cmp.lt	p00,p00,r32,r0 }

l400000000010BB50:
	{ or	r15,r33,r15; nop.i	0x0; adds	r14,0x0,r15 }
	{ nop.m	0x0; st4	[r15],r35; br.cond.sptk.few	400000000010B930 }

l400000000010BB70:
	{ adds	r42,0x0,r32; adds	r43,0x0,r0; br.call.sptk.many	b0,find_variable_internal; }
	{ adds	r14,0x2C,r8; adds	r1,0x0,r41; nop.i	0x0 }
	{ cmp.eq	p07,p06,0x0,r8; adds	r35,0x28,r8; (p07) br.cond.dpnt.few	400000000010BD30; }

l400000000010BBA0:
	{ ld4	r14,[r14]; cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; }
	{ (p06) ld4	r15,[r35]; nop.i	0x0; (p06) br.cond.dptk.few	400000000010BB50; }

l400000000010BBB6:
	{ chk.a.nc	r0,3FFFFFFFFF10C3B6; mov	pr,0xCAFFFFA; (p32) nop }

l400000000010BBC0:
	{ ld4	r14,[r35]; movl	r15,0x200000; }
	{ nop.m	0x0; or	r14,r15,r14; nop.i	0x0; }
	{ adds	r15,0x0,r14; st4	[r14],r35; nop.i	0x0; }
	{ or	r15,r33,r15; nop.i	0x0; adds	r14,0x0,r15 }
	{ nop.m	0x0; st4	[r15],r35; br.cond.sptk.few	400000000010B930 }

l400000000010BC10:
	{ addl	r42,1,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r38,0x0,r8; adds	r44,0x0,r0; adds	r1,0x0,r41 }
	{ st1	[r0],r8; nop.m	0x0; adds	r43,0x0,r38 }
	{ nop.m	0x0; ld8	r42,[r36]; br.call.sptk.many	b0,bind_variable; }
	{ ld4	r15,[r37]; adds	r35,0x28,r8; addl	r17,-1048577,r0 }
	{ adds	r8,0x2C,r8; movl	r16,0x200000; }
	{ ld4	r14,[r35]; and	r15,r17,r15; adds	r1,0x0,r41 }
	{ ld4	r17,[r8]; or	r14,r14,r15; cmp4.eq	p06,p07,0x0,r17 }
	{ ld8	r42,[r36]; st4	[r14],r35; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r37]; nop.i	0x0; }
	{ or	r14,r16,r14; st4	[r14],r37; adds	r15,0x0,r14; }
	{ (p07) ld4	r14,[r35]; (p07) or	r16,r16,r14; nop.i	0x0; }

l400000000010BCC6:
	{ Invalid; cmp4.ltu	p00,p00,0x0,r1; (p01) cmp.eq.or	p00,p36,r100,r8; }

l400000000010BCCC:
	{ Invalid; cmp4.ne.or.andcm	p36,p40,r8,r100; Invalid }

l400000000010BCD6:
	{ (p07) fwb; nop; break.b	0x80000; }

l400000000010BCDC:
	{ nop; cmp.eq	p00,p00,r32,r0; zxt1	r104,r3 }
	{ Invalid; Invalid; break.i	0x1000 }
	{ (p14) nop; ld4	r32,[r64]; (p05) epc }
	{ (p23) nop; nop; zxt1	r32,r64 }
	{ cmp.eq	p00,p24,r1,r0; Invalid; break.i	0x1000 }
	{ (p49) ld2	r127,[r36]; zxt1	r0,r64; nop }

l400000000010BD30:
	{ adds	r42,0x0,r32; nop.m	0x0; adds	r43,0x0,r0 }
	{ adds	r44,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r35,0x28,r8; addl	r15,4096,r0; adds	r1,0x0,r41; }
	{ ld4	r14,[r35]; or	r14,r15,r14; nop.i	0x0; }
	{ adds	r15,0x0,r14; st4	[r14],r35; nop.i	0x0; }
	{ or	r15,r33,r15; nop.i	0x0; adds	r14,0x0,r15 }
	{ nop.m	0x0; st4	[r15],r35; br.cond.sptk.few	400000000010B930; }
400000000010BDA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000010BDB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; set_or_show_attributes: 400000000010BDC0
;;   Called from:
;;     40000000000F168C (in fn40000000000F0900)
;;     400000000010C75C (in readonly_builtin)
;;     400000000010C79C (in export_builtin)
set_or_show_attributes proc
	{ alloc	r50,ar.pfs,0x18,0x0,0x15; adds	r51,0x0,r1; mov	r52,pr; }
	{ adds	r38,0x0,r0; mov	r49,b1; adds	r36,0x0,r0 }
	{ adds	r39,0x0,r0; adds	r37,0x0,r0; br.call.sptk.many	b0,reset_internal_getopt; }
	{ adds	r1,0x0,r51; nop.i	0x0; addl	r35,-1076,r1; }
	{ ld8	r35,[r35]; nop.m	0x0; nop.i	0x0 }
	{ addl	r54,-1108,r1; nop.m	0x0; adds	r53,0x0,r32; }
	{ ld8	r54,[r54]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r51; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dpnt.few	400000000010BF00 }

l400000000010BE40:
	{ nop.m	0x0; adds	r8,0xFFFFFFFFFFFFFFBF,r8; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x2F,r8; (p07) br.cond.dptk.few	400000000010BEA0 }

l400000000010BE60:
	{ nop.m	0x0; addl	r35,258,r0; br.call.sptk.many	b0,builtin_usage; }
	{ adds	r1,0x0,r51; nop.m	0x0; nop.i	0x0 }

l400000000010BE80:
	{ adds	r8,0x0,r35; mov	pr,r52,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r50; }
	{ nop.m	0x0; mov.spnt	b0,r49,400000000010BE90; br.ret	b0 }

l400000000010BEA0:
	{ addp4	r8,r8,r0; shladd	r8,r8,0x3,r35; nop.i	0x0; }
	{ ld8	r14,[r8]; add	r8,r8,r14; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r8,400000000010BEC0; br.cond	b6; }
400000000010BED0 09 B0 B1 FA F7 27 50 03 80 00 42 A0 14 00 00 90 .....'P...B.....
400000000010BEE0 11 B0 01 6C 18 10 00 00 00 02 00 00 E8 E5 00 50 ...l...........P
400000000010BEF0 11 08 00 66 00 21 70 F8 23 0C 77 03 50 FF FF 4A ...f.!p.#.w.P..J

l400000000010BF00:
	{ addl	r14,9268,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld8	r35,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r35; nop.i	0x0; (p06) br.cond.dpnt.few	400000000010C3F0; }

l400000000010BF30:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x0; (p07) addl	r14,5780,r1 }

l400000000010BF40:
	{ (p07) addl	r15,1,r0; nop.m	0x0; nop.i	0x0; }

l400000000010BF46:
	{ break.m	0x4000; cmp4.eq	p00,p00,r0,r1; (p01) nop }

l400000000010BF56:
	{ (p03) chk.a.clr	r0,3FFFFFFFFFDCF9A6; Invalid; break.i	0x80000 }

l400000000010BF60:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x1; (p07) and	r33,0xFFFFFFFFFFFFFFFD,r33 }

l400000000010BF70:
	{ or	r38,r36,r38; adds	r42,0x0,r0; adds	r47,0x0,r0 }
	{ cmp4.eq	p16,p17,0x0,r39; addl	r45,61,r0; cmp4.eq	p22,p23,0x0,r36; }
	{ nop.m	0x0; cmp4.eq	p24,p25,0x0,r38; addl	r48,43,r0 }
	{ nop.m	0x0; cmp4.eq	p19,p18,0x0,r37; andcm	r44,0xFFFFFFFFFFFFFFFF,r33; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000010BFC0:
	{ adds	r14,0x8,r35; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; ld8	r36,[r14]; nop.i	0x0; }
	{ nop.m	0x0; adds	r53,0x0,r36; (p16) br.cond.dptk.few	400000000010C0E0 }

l400000000010BFF0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,find_function; }
	{ cmp.eq	p07,p06,0x0,r8; nop.m	0x0; adds	r8,0x28,r8 }
	{ adds	r1,0x0,r51; nop.m	0x0; (p07) br.cond.dpnt.few	400000000010C370; }

l400000000010C020:
	{ ld4	r14,[r8]; ld8	r35,[r35]; nop.i	0x0; }
	{ (p19) or	r14,r14,r33; cmp.eq	p07,p06,0x0,r35; (p18) and	r14,r14,r44; }

l400000000010C036:
	{ (p03) nop; (p07) nop; br.call.spnt.many	b0,b3 }

l400000000010C040:
	{ st4	[r14],r8; nop.i	0x0; (p06) br.cond.dptk.few	400000000010BFC0 }

l400000000010C050:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r42; nop.i	0x0; }
	{ nop.m	0x0; (p06) addl	r35,260,r0; (p06) br.cond.dptk.few	400000000010BE80 }

l400000000010C06C:
	{ (p49) cmp.eq.unc	p63,p09,r63,r37; czx1.r	r96,r97; break.i	0x1000 }

l400000000010C070:
	{ cmp4.eq	p07,p06,0x0,r47; nop.m	0x0; mov.i	ar.pfs,r50; }
	{ (p06) addl	r47,1,r0; nop.m	0x0; mov.spnt	b0,r49,400000000010C080; }

l400000000010C086:
	{ break.m	0x4000; cmp4.lt	p49,p03,0x1,r64; (p49) nop }

l400000000010C096:
	{ (p63) sub	r52,r112,r95; (p17) nop; break.b	0x80000 }
	{ Invalid; (p34) nop; break.i	0x80000 }
400000000010C0B0 10 00 00 00 01 00 70 0A 00 00 48 00 60 FD FF 48 ......p...H.`..H
400000000010C0C0 10 00 00 00 01 00 40 0A 00 00 48 00 50 FD FF 48 ......@...H.P..H
400000000010C0D0 11 00 00 00 01 00 60 0A 00 00 48 00 40 FD FF 48 ......`...H.@..H

l400000000010C0E0:
	{ adds	r54,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,assignment; }
	{ adds	r1,0x0,r51; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	400000000010C180 }

l400000000010C100:
	{ adds	r53,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,legal_identifier; }
	{ cmp4.eq	p06,p07,0x0,r8; adds	r53,0x0,r36; adds	r54,0x0,r33 }
	{ adds	r55,0x0,r37; adds	r1,0x0,r51; (p06) br.cond.dpnt.few	400000000010C6E0; }

l400000000010C130:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,set_var_attribute; }
	{ adds	r1,0x0,r51; nop.m	0x0; nop.i	0x0 }

l400000000010C150:
	{ nop.m	0x0; ld8	r35,[r35]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	400000000010BFC0 }

l400000000010C170:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000010C050 }

l400000000010C180:
	{ nop.m	0x0; sxt4	r8,r8; nop.i	0x0; }
	{ add	r39,r36,r8; nop.m	0x0; adds	r8,0xFFFFFFFFFFFFFFFF,r8; }
	{ add	r40,r36,r8; st1	[r0],r39; nop.i	0x0; }
	{ ld1	r14,[r40]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x2B,r14; (p07) addl	r41,1,r0; nop.i	0x0 }

l400000000010C1CC:
	{ Invalid; Invalid; mov	pr,r32,0x0 }

l400000000010C1D6:
	{ chk.a.nc	f0,3FFFFFFFFF10C9D6; nop; (p16) nop }

l400000000010C1E0:
	{ adds	r41,0x0,r0; nop.m	0x0; nop.i	0x0; }

l400000000010C1F0:
	{ adds	r53,0x0,r36; cmp4.eq	p20,p21,0x0,r41; br.call.sptk.many	b0,legal_identifier; }
	{ adds	r1,0x0,r51; cmp4.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	400000000010C6A0; }

l400000000010C210:
	{ (p23) addl	r53,-1092,r1; st1	[r45],r39; nop.i	0x0 }

l400000000010C216:
	{ mf.a; Invalid; (p05) nop }

l400000000010C226:
	{ nop; addl	r17,1052800,r0; (p21) nop }

l400000000010C230:
	{ (p22) addl	r53,-1084,r1; ld8	r46,[r35]; nop.i	0x0 }

l400000000010C236:
	{ (p23) fwb; nop; cmp.eq.or	p00,p38,r96,r8 }
	{ Invalid; Invalid; Invalid }

l400000000010C24C:
	{ nop; Invalid; break.i	0x1000 }

l400000000010C256:
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ Invalid; nop; (p48) nop.b	0x800A }
	{ Invalid; (p32) nop; (p16) nop.b	0x33000 }
	{ add	r0,r0,r1; (p20) nop; (p16) nop }
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ add	r0,r0,r1; nop; (p16) nop }
	{ mf.a; cmp4.eq	p00,p00,r0,r1; (p33) nop }

l400000000010C2C6:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; (p32) nop; (p16) nop.b	0x33000 }
	{ mf.a; tbit.z	p00,p00,r1,0x0; (p05) nop }

l400000000010C2F6:
	{ break.m	0x4000; nop; (p16) nop }

l400000000010C300:
	{ adds	r53,0x0,r36; nop.m	0x0; adds	r54,0x0,r33 }
	{ adds	r55,0x0,r37; nop.m	0x0; br.call.sptk.many	b0,set_var_attribute; }
	{ nop.m	0x0; adds	r1,0x0,r51; br.cond.sptk.few	400000000010C150 }

l400000000010C330:
	{ adds	r53,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,do_assignment_no_expand; }
	{ cmp4.eq	p07,p06,0x0,r8; st1	[r0],r39; adds	r1,0x0,r51 }
	{ nop.m	0x0; (p21) st1	[r0],r40; nop.i	0x0; }

l400000000010C35C:
	{ invala; dep	r0,r32,r0,49,1; zxt1	r64,r64 }

l400000000010C36C:
	{ (p61) cmp.lt.unc	p63,p08,r63,r36; Invalid; cmp.eq	p00,p00,r32,r0 }

l400000000010C370:
	{ addl	r54,-1100,r1; nop.m	0x0; addl	r55,5,r0 }
	{ adds	r53,0x0,r0; nop.m	0x0; adds	r47,0x1,r47; }
	{ ld8	r54,[r54]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r51; nop.m	0x0; adds	r53,0x0,r8 }
	{ adds	r54,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,builtin_error; }
	{ ld8	r35,[r35]; nop.m	0x0; adds	r1,0x0,r51; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	400000000010BFC0 }

l400000000010C3E0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000010C050 }

l400000000010C3F0:
	{ and	r14,0x8,r33; or	r39,r39,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r39; (p06) br.cond.dptk.few	400000000010C650 }

l400000000010C410:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,all_shell_functions; }
	{ cmp4.eq	p06,p07,0x8,r33; nop.m	0x0; adds	r1,0x0,r51 }
	{ adds	r40,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	400000000010C470; }

l400000000010C440:
	{ (p07) and	r33,0xFFFFFFFFFFFFFFF7,r33; nop.m	0x0; nop.i	0x0; }

l400000000010C446:
	{ break.m	0x4000; nop; break.i	0x80000 }

l400000000010C450:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x2; (p06) br.cond.dpnt.few	400000000010C670; }

l400000000010C460:
	{ cmp4.eq	p06,p07,0x4,r33; adds	r36,0x1,r36; (p07) and	r33,0xFFFFFFFFFFFFFFFB,r33 }

l400000000010C470:
	{ cmp.eq	p06,p07,0x0,r40; addl	r39,8388,r1; addl	r37,-9924,r1 }
	{ addl	r41,-9868,r1; cmp4.eq	p19,p18,0x0,r36; cmp4.eq	p16,p17,0x0,r38; }
	{ (p06) adds	r35,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	400000000010BE80; }
