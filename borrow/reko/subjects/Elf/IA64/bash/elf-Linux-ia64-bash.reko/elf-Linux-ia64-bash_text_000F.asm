;;; Segment .text (400000000001C480)

l400000000010C496:
	{ chk.a.nc	r0,3FFFFFFFFF10CC96; nop; (p16) nop }

l400000000010C4A0:
	{ ld8	r53,[r40]; nop.m	0x0; adds	r35,0x8,r40; }
	{ cmp.eq	p07,p06,0x0,r53; nop.i	0x0; (p07) br.cond.dpnt.few	400000000010C630; }

l400000000010C4C0:
	{ nop.m	0x0; ld8	r37,[r37]; nop.i	0x0; }
	{ ld8	r41,[r41]; nop.m	0x0; nop.i	0x0; }

l400000000010C4E0:
	{ nop.m	0x0; adds	r14,0x28,r53; nop.i	0x0; }
	{ ld4	r14,[r14]; nop.i	0x0; (p19) br.cond.dptk.few	400000000010C510; }

l400000000010C500:
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x2; (p07) br.cond.dptk.few	400000000010C610 }

l400000000010C510:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dptk.few	400000000010C530; }

l400000000010C520:
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x6; (p06) br.cond.dptk.few	400000000010C610 }

l400000000010C530:
	{ nop.m	0x0; and	r14,r33,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000010C610 }

l400000000010C550:
	{ ld8	r14,[r39]; cmp.eq	p06,p07,r37,r14; nop.i	0x0; }
	{ (p06) addl	r54,1,r0; nop.i	0x0; (p06) br.cond.dpnt.few	400000000010C590; }

l400000000010C566:
	{ chk.a.nc	r0,3FFFFFFFFF10CD66; nop; (p32) nop }

l400000000010C570:
	{ cmp.eq	p06,p07,r41,r14; (p06) addl	r14,1,r0; nop.i	0x0; }

l400000000010C57C:
	{ cmp4.eq.and	p00,p34,r1,r0; zxt1	r0,r64; cmp.lt	p00,p00,r32,r0 }

l400000000010C586:
	{ break.m	0x4000; (p27) nop; (p48) nop }

l400000000010C590:
	{ adds	r55,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,show_var_attributes; }
	{ adds	r1,0x0,r51; adds	r53,0x0,r0; br.call.sptk.many	b0,sh_chkwrite; }
	{ adds	r1,0x0,r51; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	400000000010C610 }

l400000000010C5C0:
	{ nop.m	0x0; adds	r53,0x0,r40; addl	r35,1,r0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r51; nop.m	0x0; nop.i	0x0 }

l400000000010C5F0:
	{ adds	r8,0x0,r35; mov	pr,r52,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r50; }
	{ nop.m	0x0; mov.spnt	b0,r49,400000000010C600; br.ret	b0 }

l400000000010C610:
	{ nop.m	0x0; ld8	r53,[r35],8; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r53; (p06) br.cond.dptk.few	400000000010C4E0 }

l400000000010C630:
	{ adds	r53,0x0,r40; adds	r35,0x0,r0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r51; br.cond.sptk.few	400000000010C5F0 }

l400000000010C650:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,all_shell_variables; }
	{ adds	r1,0x0,r51; adds	r40,0x0,r8; br.cond.sptk.few	400000000010C450 }

l400000000010C670:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x6; (p06) br.cond.dpnt.few	400000000010C470; }

l400000000010C680:
	{ cmp4.eq	p06,p07,0x40,r33; nop.m	0x0; adds	r38,0x1,r38; }
	{ nop.m	0x0; (p07) and	r33,0xFFFFFFFFFFFFFFBF,r33; br.cond.sptk.few	400000000010C470 }

l400000000010C69C:
	{ (p47) nop; (p06) dep	r0,r9,r64,62,1; zxt1	r64,r64 }

l400000000010C6A0:
	{ adds	r53,0x0,r36; adds	r42,0x1,r42; br.call.sptk.many	b0,sh_invalidid; }
	{ ld8	r35,[r35]; nop.m	0x0; adds	r1,0x0,r51; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	400000000010BFC0 }

l400000000010C6D0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000010C050 }

l400000000010C6E0:
	{ adds	r53,0x0,r36; adds	r47,0x1,r47; br.call.sptk.many	b0,sh_invalidid; }
	{ ld8	r35,[r35]; nop.m	0x0; adds	r1,0x0,r51; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	400000000010BFC0 }

l400000000010C710:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000010C050; }
400000000010C720 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000010C730 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; readonly_builtin: 400000000010C740
readonly_builtin proc
	{ alloc	r16,ar.pfs,0x3,0x0,0x3; addl	r33,2,r0; adds	r34,0x0,r0; }
	{ alloc	r2,ar.pfs,0x3,0x0,0x0; nop.i	0x0; br.cond.sptk.many	set_or_show_attributes; }
400000000010C760 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
400000000010C770 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; export_builtin: 400000000010C780
export_builtin proc
	{ alloc	r16,ar.pfs,0x3,0x0,0x3; addl	r33,1,r0; adds	r34,0x0,r0; }
	{ alloc	r2,ar.pfs,0x3,0x0,0x0; nop.i	0x0; br.cond.sptk.many	set_or_show_attributes; }
400000000010C7A0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
400000000010C7B0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; shift_builtin: 400000000010C7C0
shift_builtin proc
	{ alloc	r41,ar.pfs,0xF,0x0,0xC; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r40,b0 }
	{ adds	r42,0x0,r1; nop.m	0x0; adds	r44,0x0,r32; }
	{ adds	r45,0x0,r0; adds	r46,0x10,r12; mov	r43,LC }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,get_numeric_arg; }
	{ adds	r15,0x10,r12; nop.m	0x0; adds	r1,0x0,r42 }
	{ cmp4.eq	p07,p06,0x0,r8; nop.m	0x0; (p07) br.cond.dpnt.few	400000000010C930; }

l400000000010C820:
	{ nop.m	0x0; ld8	r14,[r15]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000010C960; }

l400000000010C840:
	{ cmp.lt	p07,p06,r14,r0; nop.i	0x0; (p07) br.cond.dpnt.few	400000000010C8C0; }

l400000000010C850:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,number_of_args; }
	{ adds	r15,0x10,r12; sxt4	r8,r8; adds	r1,0x0,r42; }
	{ nop.m	0x0; ld8	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp.lt	p06,p07,r8,r14; (p07) br.cond.dptk.few	400000000010C990 }

l400000000010C890:
	{ addl	r14,9244,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	400000000010C930; }

l400000000010C8C0:
	{ cmp.eq	p06,p07,0x0,r32; addl	r45,-8436,r1; addl	r46,5,r0 }
	{ adds	r44,0x0,r0; (p07) adds	r32,0x8,r32; (p06) adds	r33,0x0,r0 }

l400000000010C8DC:
	{ nop; (p01) nop }

l400000000010C8E0:
	{ ld8	r45,[r45]; (p07) ld8	r14,[r32]; nop.i	0x0; }

l400000000010C8EC:
	{ nop; Invalid; break.i	0x1000 }

l400000000010C8F6:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; (p22) nop; (p16) nop }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; Invalid; nop }

l400000000010C930:
	{ addl	r8,1,r0; mov.i	ar.pfs,r41; mov.i	LC,r43; }
	{ nop.m	0x0; mov.spnt	b0,r40,400000000010C940; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l400000000010C960:
	{ adds	r8,0x0,r0; mov.i	ar.pfs,r41; mov.i	LC,r43; }
	{ nop.m	0x0; mov.spnt	b0,r40,400000000010C970; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l400000000010C990:
	{ addl	r39,23444,r1; addl	r34,7132,r1; addl	r38,6244,r1 }
	{ addl	r36,6252,r1; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; adds	r37,0x8,r39; adds	r39,0x48,r39; }

l400000000010C9C0:
	{ adds	r15,0xFFFFFFFFFFFFFFFF,r14; cmp.lt	p06,p07,0x0,r14; adds	r14,0x10,r12; }
	{ st8	[r15],r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000010C960; }

l400000000010C9E0:
	{ nop.m	0x0; ld8	r44,[r37]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r44; nop.i	0x0; (p06) br.cond.dpnt.few	400000000010CA20; }

l400000000010CA00:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r42; nop.m	0x0; nop.i	0x0 }

l400000000010CA20:
	{ ld8	r15,[r38]; nop.m	0x0; mov.i	LC,0x7 }
	{ ld8	r14,[r36]; nop.m	0x0; nop.i	0x0; }

l400000000010CA40:
	{ nop.m	0x0; ld8	r16,[r15],8; nop.i	0x0; }
	{ st8	[r14],r8,8; nop.i	0x0; br.cloop.sptk.few	400000000010CA40 }

l400000000010CA60:
	{ ld8	r33,[r34]; cmp.eq	p06,p07,0x0,r33; adds	r35,0x8,r33; }
	{ (p06) st8	[r0],r39; nop.i	0x0; (p06) br.cond.dpnt.few	400000000010CB20; }

l400000000010CA76:
	{ chk.a.nc	r0,3FFFFFFFFF10D276; nop; break.i	0x80000 }

l400000000010CA80:
	{ nop.m	0x0; ld8	r14,[r35]; nop.i	0x0; }
	{ ld8	r44,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r42; adds	r44,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r14,[r35]; adds	r1,0x0,r42; adds	r44,0x0,r8; }
	{ ld8	r45,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ ld8	r14,[r34]; st8	[r8],r39; adds	r1,0x0,r42 }
	{ adds	r44,0x0,r33; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; st8	[r14],r34; nop.i	0x0 }
	{ st8	[r0],r33; nop.m	0x0; br.call.sptk.many	b0,dispose_words; }
	{ adds	r1,0x0,r42; nop.m	0x0; nop.i	0x0 }

l400000000010CB20:
	{ nop.m	0x0; adds	r15,0x10,r12; nop.i	0x0; }
	{ ld8	r14,[r15]; nop.i	0x0; br.cond.sptk.few	400000000010C9C0; }
400000000010CB40 08 08 0D 06 80 05 E0 60 07 6E 48 00 04 00 C4 00 .......`.nH.....
400000000010CB50 0B 10 01 02 00 21 00 00 00 02 00 00 00 00 04 00 .....!..........
400000000010CB60 09 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
400000000010CB70 10 00 00 00 01 00 70 00 38 0C 73 03 30 00 00 42 ......p.8.s.0..B
400000000010CB80 11 00 00 00 01 00 00 00 00 02 00 00 08 1E FE 58 ...............X
400000000010CB90 10 08 00 44 00 21 60 20 20 0E A8 03 C0 00 00 43 ...D.!`  ......C
400000000010CBA0 11 00 00 00 01 00 00 00 00 02 00 00 E8 DA F5 58 ...............X
400000000010CBB0 0B 08 00 44 00 21 E0 40 06 64 48 00 00 00 04 00 ...D.!.@.dH.....
400000000010CBC0 0B 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
400000000010CBD0 10 00 00 00 01 00 60 00 38 0E F3 03 40 00 00 43 ......`.8...@..C
400000000010CBE0 11 00 00 00 01 00 00 00 00 02 00 00 E8 1D FE 58 ...............X
400000000010CBF0 09 08 00 44 00 21 00 00 00 02 00 00 10 02 AA 00 ...D.!..........
400000000010CC00 11 00 00 00 01 00 00 00 05 80 03 80 08 00 84 00 ................
400000000010CC10 11 00 00 00 01 00 00 00 00 02 00 00 B8 DF F5 58 ...............X
400000000010CC20 11 08 00 44 00 21 00 00 00 02 00 00 A8 1D FE 58 ...D.!.........X
400000000010CC30 09 08 00 44 00 21 00 00 00 02 00 00 10 02 AA 00 ...D.!..........
400000000010CC40 11 00 00 00 01 00 00 00 05 80 03 80 08 00 84 00 ................
400000000010CC50 11 00 00 00 01 00 00 00 00 02 00 00 78 DC F5 58 ............x..X
400000000010CC60 0B 08 00 44 00 21 E0 40 06 64 48 00 00 00 04 00 ...D.!.@.dH.....
400000000010CC70 0B 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
400000000010CC80 10 00 00 00 01 00 60 00 38 0E 73 03 60 FF FF 4A ......`.8.s.`..J
400000000010CC90 11 00 00 00 01 00 00 00 00 02 00 00 80 FF FF 48 ...............H
400000000010CCA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000010CCB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; source_builtin: 400000000010CCC0
source_builtin proc
	{ alloc	r38,ar.pfs,0xB,0x0,0x8; nop.m	0x0; mov	r37,b5 }
	{ adds	r39,0x0,r1; nop.m	0x0; adds	r40,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,no_options; }
	{ cmp4.eq	p07,p06,0x0,r8; adds	r1,0x0,r39; mov.i	ar.pfs,r38 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	400000000010CD30; }

l400000000010CD10:
	{ (p06) addl	r33,258,r0; nop.m	0x0; mov.spnt	b0,r37,400000000010CD10; }

l400000000010CD16:
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ Invalid; (p34) nop; break.i	0x80000 }

l400000000010CD30:
	{ nop.m	0x0; addl	r14,9268,r1; nop.i	0x0; }
	{ nop.m	0x0; ld8	r33,[r14]; addl	r14,7352,r1; }
	{ cmp.eq	p07,p06,0x0,r33; adds	r35,0x8,r33; (p07) br.cond.dpnt.few	400000000010D3F0; }

l400000000010CD60:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000010CE00 }

l400000000010CD80:
	{ ld8	r14,[r35]; nop.m	0x0; addl	r41,47,r0; }
	{ nop.m	0x0; ld8	r34,[r14]; nop.i	0x0; }
	{ adds	r40,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B680; }
	{ cmp.eq	p06,p07,0x0,r8; nop.m	0x0; adds	r1,0x0,r39 }
	{ adds	r40,0x0,r34; nop.m	0x0; (p06) br.cond.dpnt.few	400000000010CE20; }

l400000000010CDD0:
	{ addl	r33,1,r0; nop.i	0x0; br.call.sptk.many	b0,sh_restricted; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r39; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,400000000010CDF0; br.ret	b0 }

l400000000010CE00:
	{ nop.m	0x0; ld8	r14,[r35]; nop.i	0x0; }
	{ ld8	r34,[r14]; nop.m	0x0; nop.i	0x0; }

l400000000010CE20:
	{ addl	r36,6456,r1; adds	r40,0x0,r34; addl	r41,47,r0; }
	{ nop.m	0x0; ld4	r14,[r36]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000010D060; }

l400000000010CE50:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B680; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r39; (p06) br.cond.dpnt.few	400000000010D060; }

l400000000010CE70:
	{ (p07) adds	r40,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }

l400000000010CE76:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; (p32) nop; (p32) nop }
	{ Invalid; (p20) nop; (p16) br.call.sptk.few	b2,b0 }
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; (p17) nop; break.b	0x80000 }

l400000000010CEC0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r34; (p06) br.cond.dpnt.few	400000000010D0A0 }

l400000000010CED0:
	{ nop.m	0x0; addl	r40,-756,r1; nop.i	0x0; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,begin_unwind_frame; }
	{ adds	r1,0x0,r39; adds	r41,0x0,r34; addl	r40,-9884,r1; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,add_unwind_protect; }
	{ ld8	r14,[r33]; nop.m	0x0; adds	r1,0x0,r39; }
	{ cmp.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000010CFB0; }

l400000000010CF30:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,push_dollar_vars; }
	{ adds	r1,0x0,r39; adds	r41,0x0,r0; addl	r40,-780,r1; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,add_unwind_protect; }
	{ adds	r1,0x0,r39; ld8	r40,[r33]; addl	r41,1,r0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,remember_args; }
	{ adds	r1,0x0,r39; addl	r14,6472,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	400000000010D2F0 }

l400000000010CFB0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,set_dollar_vars_unchanged; }
	{ adds	r1,0x0,r39; addl	r40,65,r0; br.call.sptk.many	b0,signal_is_trapped; }
	{ adds	r1,0x0,r39; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dpnt.few	400000000010D180 }

l400000000010CFE0:
	{ ld8	r14,[r33]; adds	r40,0x0,r34; cmp.eq	p07,p06,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r41,1,r0; nop.i	0x0; }

l400000000010CFFC:
	{ nop; zxt1	r0,r64; break.i	0x1000 }

l400000000010D006:
	{ break.m	0x4000; Invalid; (p16) nop }
	{ Invalid; (p20) nop; br.call.sptk.few	b2,b0 }
	{ (p32) flushrs; nop; (p16) nop }
	{ break.m	0x4000; nop; nop }

l400000000010D040:
	{ adds	r8,0x0,r33; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,400000000010D050; br.ret	b0; }

l400000000010D060:
	{ adds	r40,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,absolute_pathname; }
	{ adds	r1,0x0,r39; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dpnt.few	400000000010D460; }

l400000000010D080:
	{ addl	r14,6264,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dpnt.few	400000000010D3A0 }

l400000000010D0A0:
	{ addl	r14,6260,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	400000000010D340 }

l400000000010D0C0:
	{ addl	r41,-764,r1; adds	r40,0x0,r0; addl	r42,5,r0; }
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ ld8	r14,[r35]; adds	r1,0x0,r39; adds	r40,0x0,r8; }
	{ ld8	r41,[r14]; nop.i	0x0; br.call.sptk.many	b0,builtin_error; }
	{ adds	r1,0x0,r39; ld4	r14,[r36]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; addl	r14,6512,r1; (p06) br.cond.dpnt.few	400000000010D160; }

l400000000010D120:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; addl	r14,7032,r1; (p06) br.cond.dpnt.few	400000000010D160; }

l400000000010D140:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.spnt.few	400000000010D4C0 }

l400000000010D160:
	{ addl	r33,1,r0; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ adds	r8,0x0,r33; mov.spnt	b0,r37,400000000010D170; br.ret	b0; }

l400000000010D180:
	{ addl	r40,65,r0; nop.i	0x0; br.call.sptk.many	b0,signal_is_ignored; }
	{ adds	r1,0x0,r39; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	400000000010CFE0; }

l400000000010D1A0:
	{ addl	r14,24316,r1; nop.m	0x0; nop.i	0x0; }
	{ adds	r14,0x208,r14; ld8	r35,[r14]; addl	r14,7340,r1; }
	{ cmp.eq	p06,p07,0x0,r35; nop.i	0x0; (p06) br.cond.spnt.few	400000000010CFE0; }

l400000000010D1D0:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	400000000010CFE0 }

l400000000010D1F0:
	{ adds	r40,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r39; adds	r40,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r41,0x0,r35 }
	{ adds	r40,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r39; adds	r35,0x0,r8; adds	r41,0x0,r8; }
	{ nop.m	0x0; addl	r40,-9884,r1; nop.i	0x0; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,add_unwind_protect; }
	{ adds	r1,0x0,r39; adds	r41,0x0,r35; addl	r40,-9692,r1; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,add_unwind_protect; }
	{ adds	r1,0x0,r39; addl	r40,65,r0; br.call.sptk.many	b0,restore_default_signal; }
	{ ld8	r14,[r33]; adds	r1,0x0,r39; adds	r40,0x0,r34; }
	{ cmp.eq	p07,p06,0x0,r14; (p06) addl	r41,1,r0; nop.i	0x0; }

l400000000010D2AC:
	{ nop; zxt1	r0,r64; break.i	0x1000 }

l400000000010D2B6:
	{ break.m	0x4000; Invalid; (p16) nop }
	{ Invalid; (p20) nop; br.call.sptk.few	b2,b0 }
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; nop; br.call.sptk.few	b2,b0 }

l400000000010D2F0:
	{ ld8	r40,[r33]; nop.i	0x0; br.call.sptk.many	b0,push_args; }
	{ adds	r1,0x0,r39; nop.i	0x0; br.call.sptk.many	b0,set_dollar_vars_unchanged; }
	{ adds	r1,0x0,r39; addl	r40,65,r0; br.call.sptk.many	b0,signal_is_trapped; }
	{ adds	r1,0x0,r39; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	400000000010CFE0 }

l400000000010D330:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000010D180 }

l400000000010D340:
	{ nop.m	0x0; ld8	r14,[r35]; nop.i	0x0; }
	{ ld8	r40,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r39; adds	r40,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r14,[r35]; adds	r1,0x0,r39; adds	r40,0x0,r8; }
	{ ld8	r41,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r39; adds	r34,0x0,r8; br.cond.sptk.few	400000000010CED0 }

l400000000010D3A0:
	{ nop.m	0x0; ld8	r14,[r35]; nop.i	0x0; }
	{ ld8	r40,[r14]; nop.i	0x0; br.call.sptk.many	b0,find_path_file; }
	{ adds	r34,0x0,r8; nop.m	0x0; adds	r1,0x0,r39; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r34; (p07) br.cond.dptk.few	400000000010CED0 }

l400000000010D3E0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000010D0A0 }

l400000000010D3F0:
	{ addl	r41,-772,r1; nop.m	0x0; addl	r42,5,r0 }
	{ adds	r40,0x0,r0; nop.m	0x0; addl	r33,258,r0; }
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r39; adds	r40,0x0,r8; br.call.sptk.many	b0,builtin_error; }
	{ adds	r1,0x0,r39; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r39; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,400000000010D450; br.ret	b0 }

l400000000010D460:
	{ nop.m	0x0; ld8	r14,[r35]; nop.i	0x0; }
	{ ld8	r40,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r39; adds	r40,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r14,[r35]; adds	r1,0x0,r39; adds	r40,0x0,r8; }
	{ ld8	r41,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r39; adds	r34,0x0,r8; br.cond.sptk.few	400000000010CEC0; }

l400000000010D4C0:
	{ addl	r14,9044,r1; addl	r15,1,r0; addl	r40,3,r0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,jump_to_top_level; }
	{ nop.m	0x0; break.f	0x0; nop.i	0x0; }
	{ alloc	r33,ar.pfs,0x5,0x0,0x3; addl	r14,8532,r1; mov	r32,b0 }
	{ adds	r34,0x0,r1; nop.m	0x0; addl	r35,18,r0 }
	{ nop.m	0x0; ld8	r36,[r14]; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ nop.m	0x0; mov.spnt	b0,r32,400000000010D540; br.ret	b0; }
400000000010D550 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000010D560 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000010D570 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; suspend_builtin: 400000000010D580
suspend_builtin proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; adds	r36,0x0,r1; mov	r34,b2; }
	{ adds	r33,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,reset_internal_getopt; }
	{ adds	r1,0x0,r36; adds	r37,0x0,r32; addl	r38,-2052,r1; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r36; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dpnt.few	400000000010D650; }

l400000000010D5D0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000010D5E0:
	{ cmp4.eq	p06,p07,0x66,r8; nop.i	0x0; (p06) br.cond.dpnt.few	400000000010D620; }

l400000000010D5F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ addl	r8,258,r0; adds	r1,0x0,r36; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,400000000010D610; br.ret	b0 }

l400000000010D620:
	{ addl	r38,-2052,r1; adds	r37,0x0,r32; adds	r33,0x1,r33; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r36; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p06) br.cond.dptk.few	400000000010D5E0; }

l400000000010D650:
	{ addl	r14,5868,r1; addl	r15,9268,r1; cmp4.eq	p09,p08,0x0,r33; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4	r14,[r14]; ld8	r37,[r15]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	400000000010D750; (p08) br.cond.dptk.few	400000000010D6D0 }

l400000000010D68C:
	{ Invalid; break.i	0x1000; break.b	0x1000 }

l400000000010D690:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,no_args; }
	{ adds	r1,0x0,r36; addl	r14,6520,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	400000000010D7A0 }

l400000000010D6D0:
	{ addl	r38,-9020,r1; nop.m	0x0; addl	r37,18,r0; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r36; nop.m	0x0; addl	r38,19,r0; }
	{ addl	r14,8532,r1; st8	[r8],r14; addl	r14,5896,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4	r37,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001ACE0; }
	{ adds	r8,0x0,r0; adds	r1,0x0,r36; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,400000000010D740; br.ret	b0 }

l400000000010D750:
	{ addl	r38,-2044,r1; addl	r39,5,r0; adds	r37,0x0,r0; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; adds	r37,0x0,r8; br.call.sptk.many	b0,sh_nojobs; }
	{ addl	r8,1,r0; adds	r1,0x0,r36; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,400000000010D790; br.ret	b0 }

l400000000010D7A0:
	{ addl	r38,-2036,r1; addl	r39,5,r0; adds	r37,0x0,r0; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; adds	r37,0x0,r8; br.call.sptk.many	b0,builtin_error; }
	{ addl	r8,1,r0; adds	r1,0x0,r36; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,400000000010D7E0; br.ret	b0; }
400000000010D7F0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; test_builtin: 400000000010D800
test_builtin proc
	{ alloc	r36,ar.pfs,0x9,0x0,0x6; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r35,b3 }
	{ cmp.eq	p07,p06,0x0,r32; adds	r37,0x0,r1; adds	r38,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; (p07) br.cond.dpnt.few	400000000010D8C0; }

l400000000010D830:
	{ adds	r39,0x10,r12; nop.i	0x0; br.call.sptk.many	b0,make_builtin_argv; }
	{ adds	r14,0x10,r12; nop.m	0x0; adds	r1,0x0,r37 }
	{ adds	r34,0x0,r8; nop.m	0x0; adds	r39,0x0,r8; }
	{ ld4	r38,[r14]; nop.i	0x0; br.call.sptk.many	b0,test_command; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r33,0x0,r8 }
	{ adds	r38,0x0,r34; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r37; nop.m	0x0; nop.i	0x0 }

l400000000010D8A0:
	{ adds	r8,0x0,r33; mov.i	ar.pfs,r36; mov.spnt	b0,r35,400000000010D8A0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l400000000010D8C0:
	{ addl	r14,9036,r1; nop.m	0x0; addl	r33,1,r0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ ld1	r15,[r14]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5B,r15; (p06) br.cond.dptk.few	400000000010D8A0 }

l400000000010D900:
	{ adds	r14,0x1,r14; addl	r39,-9012,r1; addl	r40,5,r0 }
	{ adds	r38,0x0,r0; ld1	r14,[r14]; nop.i	0x0 }
	{ ld8	r39,[r39]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	400000000010D8A0 }

l400000000010D940:
	{ addl	r33,2,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r37; adds	r38,0x0,r8; br.call.sptk.many	b0,builtin_error; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r37; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,400000000010D970; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0; }
400000000010D990 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
400000000010D9A0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
400000000010D9B0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; times_builtin: 400000000010D9C0
times_builtin proc
	{ alloc	r35,ar.pfs,0x7,0x0,0x5; adds	r12,0xFFFFFFFFFFFFFEE0,r12; nop.b	0x0 }
	{ adds	r36,0x0,r1; mov	r34,b2; adds	r37,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,no_options; }
	{ addl	r14,258,r0; nop.m	0x0; cmp4.eq	p07,p06,0x0,r8 }
	{ adds	r1,0x0,r36; nop.m	0x0; (p07) br.cond.dpnt.few	400000000010DA30; }

l400000000010DA10:
	{ adds	r8,0x0,r14; mov.i	ar.pfs,r35; mov.spnt	b0,r34,400000000010DA10 }
	{ nop.m	0x0; adds	r12,0x120,r12; br.ret	b0; }

l400000000010DA30:
	{ addl	r33,-10260,r1; adds	r38,0xA0,r12; adds	r37,0x0,r0; }
	{ ld8	r33,[r33]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BF40; }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r38,0x10,r12 }
	{ addl	r37,-1,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BF40; }
	{ adds	r1,0x0,r36; ld8	r37,[r33]; adds	r38,0xA0,r12 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,print_timeval; }
	{ adds	r1,0x0,r36; ld8	r38,[r33]; addl	r37,32,r0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AEC0; }
	{ adds	r1,0x0,r36; ld8	r37,[r33]; adds	r38,0xB0,r12 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,print_timeval; }
	{ adds	r1,0x0,r36; ld8	r38,[r33]; addl	r37,10,r0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AEC0; }
	{ adds	r1,0x0,r36; ld8	r37,[r33]; adds	r38,0x10,r12 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,print_timeval; }
	{ adds	r1,0x0,r36; ld8	r38,[r33]; addl	r37,32,r0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AEC0; }
	{ adds	r1,0x0,r36; ld8	r37,[r33]; adds	r38,0x20,r12 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,print_timeval; }
	{ adds	r1,0x0,r36; ld8	r38,[r33]; addl	r37,10,r0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AEC0; }
	{ adds	r1,0x0,r36; adds	r37,0x0,r0; br.call.sptk.many	b0,sh_chkwrite; }
	{ adds	r14,0x0,r8; nop.m	0x0; adds	r1,0x0,r36; }
	{ adds	r8,0x0,r14; mov.i	ar.pfs,r35; mov.spnt	b0,r34,400000000010DB90 }
	{ nop.m	0x0; adds	r12,0x120,r12; br.ret	b0; }
400000000010DBB0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; fn400000000010DBC0: 400000000010DBC0
;;   Called from:
;;     400000000010E75C (in trap_builtin)
;;     400000000010E7EC (in trap_builtin)
fn400000000010DBC0 proc
	{ alloc	r36,ar.pfs,0xA,0x0,0x6; addl	r14,24316,r1; mov	r35,b3 }
	{ adds	r37,0x0,r1; adds	r38,0x0,r32; sxt4	r15,r32; }
	{ nop.m	0x0; shladd	r14,r15,0x3,r14; nop.i	0x0; }
	{ nop.m	0x0; ld8	r33,[r14]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r33; nop.i	0x0; (p07) br.cond.dpnt.few	400000000010DF00; }

l400000000010DC10:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,signal_is_hard_ignored; }
	{ adds	r1,0x0,r37; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	400000000010DD30 }

l400000000010DC30:
	{ adds	r33,0x0,r0; nop.m	0x0; nop.i	0x0 }

l400000000010DC40:
	{ adds	r38,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,signal_name; }
	{ ld1	r14,[r8]; adds	r1,0x0,r37; adds	r34,0x0,r8; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x53,r14; (p07) br.cond.dpnt.few	400000000010DDA0; }

l400000000010DC80:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x75,r14; (p07) br.cond.dpnt.few	400000000010DE80; }

l400000000010DC90:
	{ cmp.eq	p07,p06,0x0,r33; addl	r39,-4428,r1; addl	r38,1,r0 }
	{ adds	r41,0x0,r34; (p07) addl	r40,-4468,r1; nop.i	0x0 }

l400000000010DCAC:
	{ cmp.eq	p00,p11,r1,r0; (p04) mov	pr,r9,0x40C0; zxt1	r32,r64 }

l400000000010DCBC:
	{ Invalid; Invalid; Invalid }

l400000000010DCC6:
	{ (p32) flushrs; nop; (p16) nop }
	{ break.m	0x4000; nop; (p32) nop }

l400000000010DCE0:
	{ cmp.eq	p06,p07,0x0,r33; adds	r38,0x0,r33; (p06) br.cond.dpnt.few	400000000010DD10; }

l400000000010DCF0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r37; nop.m	0x0; nop.i	0x0 }

l400000000010DD10:
	{ nop.m	0x0; mov.i	ar.pfs,r36; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r35,400000000010DD20; br.ret	b0 }

l400000000010DD30:
	{ nop.m	0x0; cmp.eq	p06,p07,0x1,r33; (p06) br.cond.dpnt.few	400000000010DC30; }

l400000000010DD40:
	{ adds	r38,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,sh_single_quote; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r33,0x0,r8 }
	{ adds	r38,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,signal_name; }
	{ ld1	r14,[r8]; adds	r1,0x0,r37; adds	r34,0x0,r8; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x53,r14; (p06) br.cond.dptk.few	400000000010DC80 }

l400000000010DDA0:
	{ addl	r39,-4460,r1; addl	r40,7,r0; adds	r38,0x0,r8; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C020; }
	{ adds	r1,0x0,r37; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	400000000010DEB0; }

l400000000010DDD0:
	{ addl	r14,6456,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	400000000010DC90 }

l400000000010DE00:
	{ addl	r39,-4436,r1; addl	r40,3,r0; adds	r38,0x0,r34; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C020; }
	{ adds	r1,0x0,r37; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	400000000010DC90; }

l400000000010DE30:
	{ cmp.eq	p07,p06,0x0,r33; addl	r39,-4428,r1; addl	r38,1,r0 }
	{ adds	r41,0x3,r34; (p07) addl	r40,-4468,r1; nop.i	0x0 }

l400000000010DE4C:
	{ cmp.eq	p00,p11,r1,r0; (p04) mov	pr,r9,0x40C0; zxt1	r32,r64 }

l400000000010DE5C:
	{ Invalid; Invalid; break.i	0x1000 }

l400000000010DE66:
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; nop; (p48) nop }

l400000000010DE80:
	{ addl	r39,-4452,r1; addl	r40,7,r0; adds	r38,0x0,r8; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C020; }
	{ adds	r1,0x0,r37; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	400000000010DC90; }

l400000000010DEB0:
	{ cmp.eq	p07,p06,0x0,r33; addl	r39,-4444,r1; addl	r38,1,r0 }
	{ adds	r41,0x0,r32; (p07) addl	r40,-4468,r1; nop.i	0x0 }

l400000000010DECC:
	{ cmp.eq	p00,p11,r1,r0; (p04) mov	pr,r9,0x40C0; zxt1	r32,r64 }

l400000000010DEDC:
	{ Invalid; Invalid; break.i	0x1000 }

l400000000010DEE6:
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; nop; break.b	0x80000 }

l400000000010DF00:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,signal_is_hard_ignored; }
	{ cmp4.eq	p07,p06,0x0,r8; nop.m	0x0; adds	r1,0x0,r37 }
	{ adds	r38,0x0,r32; nop.m	0x0; (p07) br.cond.dpnt.few	400000000010DD10; }

l400000000010DF30:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,signal_is_hard_ignored; }
	{ adds	r1,0x0,r37; cmp4.eq	p07,p06,0x0,r8; (p07) br.cond.dptk.few	400000000010DD40 }

l400000000010DF50:
	{ nop.m	0x0; adds	r33,0x0,r0; br.cond.sptk.few	400000000010DC40; }
400000000010DF60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000010DF70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; trap_builtin: 400000000010DF80
trap_builtin proc
	{ alloc	r41,ar.pfs,0xF,0x0,0xD; mov	r44,LC; adds	r42,0x0,r1; }
	{ nop.m	0x0; mov	r43,pr; adds	r34,0x0,r0 }
	{ adds	r33,0x0,r0; nop.m	0x0; mov	r40,b0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,reset_internal_getopt; }
	{ adds	r1,0x0,r42; nop.m	0x0; nop.i	0x0; }

l400000000010DFD0:
	{ addl	r46,-4420,r1; nop.m	0x0; adds	r45,0x0,r32; }
	{ ld8	r46,[r46]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r42; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dpnt.few	400000000010E0A0; }

l400000000010E000:
	{ cmp4.eq	p06,p07,0x6C,r8; nop.i	0x0; (p06) br.cond.dpnt.few	400000000010E3C0; }

l400000000010E010:
	{ cmp4.eq	p06,p07,0x70,r8; nop.i	0x0; (p06) br.cond.dpnt.few	400000000010E070; }

l400000000010E020:
	{ nop.m	0x0; addl	r34,258,r0; br.call.sptk.many	b0,builtin_usage; }
	{ adds	r1,0x0,r42; nop.m	0x0; nop.i	0x0 }

l400000000010E040:
	{ adds	r8,0x0,r34; nop.m	0x0; mov	pr,r43,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r41; mov.i	LC,r44; }
	{ nop.m	0x0; mov.spnt	b0,r40,400000000010E060; br.ret	b0 }

l400000000010E070:
	{ addl	r46,-4420,r1; adds	r45,0x0,r32; adds	r34,0x1,r34; }
	{ ld8	r46,[r46]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r42; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p06) br.cond.dptk.few	400000000010E000; }

l400000000010E0A0:
	{ addl	r14,9268,r1; cmp4.eq	p06,p07,0x0,r33; (p07) br.cond.dpnt.few	400000000010E660; }

l400000000010E0B0:
	{ nop.m	0x0; nop.m	0x0; cmp4.eq	p07,p06,0x0,r34; }
	{ ld8	r33,[r14]; cmp.eq	p08,p09,0x0,r33; adds	r36,0x8,r33; }
	{ (p08) addl	r14,1,r0; (p09) adds	r14,0x0,r0; nop.i	0x0; }

l400000000010E0D6:
	{ Invalid; nop; (p48) nop }

l400000000010E0DC:
	{ ldfps	f0,f1,[r0]; (p04) cmp.lt.unc	p00,p16,r3,r64; (p08) mov	pr,r99,0xE580 }
	{ (p46) cmp.lt	p00,p11,r64,r33; (p01) nop; (p04) rfi }

l400000000010E0F0:
	{ ld8	r14,[r36]; ld8	r37,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r37; nop.i	0x0; (p06) br.cond.dpnt.few	400000000010E3D0; }

l400000000010E110:
	{ ld1	r14,[r37]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	400000000010E410 }

l400000000010E130:
	{ addl	r14,6456,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	400000000010E3D0 }

l400000000010E160:
	{ ld1	r14,[r37]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000010E3D0; }

l400000000010E180:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r14; (p06) br.cond.dptk.few	400000000010E1C0 }

l400000000010E190:
	{ adds	r14,0x1,r37; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000010E3D0 }

l400000000010E1C0:
	{ adds	r45,0x0,r37; addl	r46,3,r0; br.call.sptk.many	b0,decode_signal; }
	{ adds	r1,0x0,r42; cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r8; (p06) br.cond.dpnt.few	400000000010E3D0; }

l400000000010E1E0:
	{ nop.m	0x0; ld8	r14,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	400000000010E450; }

l400000000010E200:
	{ (p07) adds	r33,0x0,r14; nop.m	0x0; nop.i	0x0 }

l400000000010E206:
	{ break.m	0x4000; nop; break.i	0x80000 }

l400000000010E210:
	{ nop.m	0x0; ld1	r14,[r37]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ (p06) addl	r35,2,r0; (p06) adds	r36,0x8,r33; (p06) br.cond.dptk.few	400000000010E260 }

l400000000010E236:
	{ (p18) chk.a.clr	r8,3FFFFFFFFF18E446; nop; break.i	0x80000; }

l400000000010E23C:
	{ Invalid; cmp.eq	p00,p00,r32,r0; (p16) nop }

l400000000010E240:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r14; (p07) br.cond.dpnt.few	400000000010E4D0; }

l400000000010E250:
	{ nop.m	0x0; adds	r35,0x0,r0; adds	r36,0x8,r33 }

l400000000010E260:
	{ addl	r34,9028,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x7; (p07) br.cond.dpnt.few	400000000010E480 }

l400000000010E290:
	{ addl	r39,-4404,r1; addl	r38,6516,r1; nop.i	0x0 }
	{ adds	r34,0x0,r0; cmp4.eq	p16,p17,0x1,r35; cmp4.eq	p18,p19,0x2,r35; }
	{ ld8	r39,[r39]; nop.m	0x0; nop.i	0x0 }

l400000000010E2C0:
	{ ld8	r14,[r36]; nop.m	0x0; addl	r46,3,r0; }
	{ ld8	r45,[r14]; nop.i	0x0; br.call.sptk.many	b0,decode_signal; }
	{ nop.m	0x0; adds	r35,0x0,r8; adds	r1,0x0,r42 }
	{ nop.m	0x0; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dpnt.few	400000000010E390; }

l400000000010E300:
	{ nop.m	0x0; adds	r45,0x0,r8; adds	r46,0x0,r37 }
	{ (p16) br.cond.dpnt.few	400000000010E570; (p18) br.cond.dpnt.few	400000000010E550; br.call.sptk.many	b0,set_signal; }

l400000000010E316:
	{ Invalid; (p16) nop }

l400000000010E31C:
	{ (p51) nop; invala; break.b	0x1000 }
	{ nop; Invalid; cmp.lt	p00,p00,r32,r0 }

l400000000010E330:
	{ ld8	r33,[r33]; nop.m	0x0; addl	r46,3,r0; }
	{ adds	r36,0x8,r33; cmp.eq	p07,p06,0x0,r33; (p07) br.cond.dpnt.few	400000000010E040; }

l400000000010E350:
	{ nop.m	0x0; ld8	r14,[r36]; nop.i	0x0; }
	{ ld8	r45,[r14]; nop.i	0x0; br.call.sptk.many	b0,decode_signal; }
	{ nop.m	0x0; adds	r1,0x0,r42; adds	r35,0x0,r8 }
	{ nop.m	0x0; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p06) br.cond.dptk.few	400000000010E300 }

l400000000010E390:
	{ ld8	r14,[r36]; nop.m	0x0; addl	r34,1,r0; }
	{ ld8	r45,[r14]; nop.i	0x0; br.call.sptk.many	b0,sh_invalidsig; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	400000000010E330 }

l400000000010E3C0:
	{ nop.m	0x0; adds	r33,0x1,r33; br.cond.sptk.few	400000000010DFD0; }

l400000000010E3D0:
	{ nop.m	0x0; ld8	r33,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	400000000010E210 }

l400000000010E3F0:
	{ addl	r34,258,r0; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	400000000010E040 }

l400000000010E410:
	{ adds	r45,0x0,r37; nop.i	0x0; br.call.sptk.many	b0,all_digits; }
	{ adds	r1,0x0,r42; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	400000000010E130 }

l400000000010E430:
	{ adds	r45,0x0,r37; addl	r46,3,r0; br.call.sptk.many	b0,decode_signal; }
	{ adds	r1,0x0,r42; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dpnt.few	400000000010E130; }

l400000000010E450:
	{ addl	r34,9028,r1; nop.m	0x0; addl	r35,1,r0; }
	{ nop.m	0x0; ld4	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x7; (p06) br.cond.dptk.few	400000000010E290 }

l400000000010E480:
	{ cmp4.eq	p16,p17,0x1,r35; cmp4.eq	p18,p19,0x2,r35; br.call.sptk.many	b0,free_trap_strings; }
	{ ld4	r14,[r34]; adds	r1,0x0,r42; addl	r15,-129,r0; }
	{ and	r14,r15,r14; addl	r39,-4404,r1; addl	r38,6516,r1; }
	{ st4	[r14],r34; ld8	r39,[r39]; adds	r34,0x0,r0 }
	{ nop.m	0x0; nop.m	0x0; br.cond.sptk.few	400000000010E2C0 }

l400000000010E4D0:
	{ adds	r14,0x1,r37; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dptk.few	400000000010E250; }

l400000000010E500:
	{ nop.m	0x0; (p06) addl	r35,1,r0; (p06) adds	r36,0x8,r33 }

l400000000010E50C:
	{ (p04) cmpxchg2.acq.nt1	r33,[r66],r0; break.x	0x12230188801000 }

l400000000010E510:
	{ addl	r34,9028,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x7; (p06) br.cond.dptk.few	400000000010E290 }

l400000000010E540:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000010E480 }

l400000000010E550:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,ignore_signal; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	400000000010E330 }

l400000000010E570:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,restore_default_signal; }
	{ adds	r1,0x0,r42; cmp4.ltu	p06,p07,0x16,r35; (p06) br.cond.dptk.few	400000000010E330 }

l400000000010E590:
	{ addp4	r14,r35,r0; shladd	r14,r14,0x3,r39; nop.i	0x0; }
	{ ld8	r15,[r14]; add	r14,r14,r15; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r14,400000000010E5B0; br.cond	b6; }
400000000010E5C0 09 00 00 00 01 00 E0 00 98 20 20 00 00 00 04 00 .........  .....
400000000010E5D0 10 00 00 00 01 00 60 00 38 0E 73 03 60 FD FF 4A ......`.8.s.`..J
400000000010E5E0 11 68 01 46 00 21 E0 0A 00 00 48 00 28 65 FA 58 .h.F.!....H.(e.X
400000000010E5F0 10 00 00 00 01 00 10 00 A8 00 42 00 40 FD FF 48 ..........B.@..H
400000000010E600 11 68 0D 00 00 24 E0 0A 00 00 48 00 08 65 FA 58 .h...$....H..e.X
400000000010E610 10 00 00 00 01 00 10 00 A8 00 42 00 20 FD FF 48 ..........B. ..H
400000000010E620 03 70 00 4C 10 10 D0 12 00 00 48 C0 00 70 1C E6 .p.L......H..p..
400000000010E630 EB 70 B1 FB B1 A7 E1 A2 F4 65 4F 00 00 00 04 00 .p.......eO.....
400000000010E640 11 70 01 5C 18 10 00 00 00 02 00 00 C8 64 FA 58 .p.\.........d.X
400000000010E650 10 00 00 00 01 00 10 00 A8 00 42 00 E0 FC FF 48 ..........B....H

l400000000010E660:
	{ addl	r46,1,r0; adds	r45,0x0,r0; br.call.sptk.many	b0,display_signal_list; }
	{ adds	r1,0x0,r42; adds	r45,0x0,r8; br.call.sptk.many	b0,sh_chkwrite; }
	{ adds	r34,0x0,r8; adds	r1,0x0,r42; mov	pr,r43,0xFFFFFFFFFFFFFFFE; }
	{ adds	r8,0x0,r34; mov.i	ar.pfs,r41; mov.i	LC,r44; }
	{ nop.m	0x0; mov.spnt	b0,r40,400000000010E6A0; br.ret	b0; }

l400000000010E6B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,initialize_terminating_signals; }
	{ adds	r1,0x0,r42; nop.i	0x0; br.call.sptk.many	b0,get_all_original_signals; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r35; adds	r1,0x0,r42 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	400000000010E7D0; }

l400000000010E6F0:
	{ (p06) adds	r35,0x0,r0; nop.m	0x0; nop.i	0x0; }

l400000000010E6F6:
	{ break.m	0x4000; nop; (p32) nop }

l400000000010E700:
	{ adds	r34,0x8,r33; nop.m	0x0; addl	r46,3,r0; }

l400000000010E702:
	{ (p17) break.m	0x42008; nop; Invalid; }
	{ Invalid; (p32) break.i	0x20308; nop }
	{ (p32) break.m	0x20303; cmp.ltu	p32,p00,r0,r0; (p26) nop; }
	{ (p15) break.m	0x770C2; fmerge.s	f32,f0,f0; nop }
	{ break.m	0x42002; cmp.eq	p32,p01,r0,r96; Invalid; }

l400000000010E750:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000010DBC0; }
	{ ld8	r33,[r33]; nop.m	0x0; adds	r1,0x0,r42; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	400000000010E700 }

l400000000010E780:
	{ adds	r45,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,sh_chkwrite; }
	{ nop.m	0x0; adds	r1,0x0,r42; adds	r34,0x0,r8; }

l400000000010E7A0:
	{ adds	r8,0x0,r34; nop.m	0x0; mov	pr,r43,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r41; mov.i	LC,r44; }
	{ nop.m	0x0; mov.spnt	b0,r40,400000000010E7C0; br.ret	b0 }

l400000000010E7D0:
	{ nop.m	0x0; adds	r33,0x0,r0; mov.i	LC,0x43; }

l400000000010E7E0:
	{ adds	r45,0x0,r33; adds	r33,0x1,r33; br.call.sptk.many	b0,fn400000000010DBC0; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cloop.sptk.few	400000000010E7E0 }

l400000000010E800:
	{ nop.m	0x0; adds	r35,0x0,r0; nop.i	0x0; }
	{ adds	r45,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,sh_chkwrite; }
	{ adds	r1,0x0,r42; adds	r34,0x0,r8; br.cond.sptk.few	400000000010E7A0; }

l400000000010E830:
	{ ld8	r14,[r34]; nop.m	0x0; addl	r35,1,r0; }
	{ ld8	r45,[r14]; nop.i	0x0; br.call.sptk.many	b0,sh_invalidsig; }
	{ ld8	r33,[r33]; nop.m	0x0; adds	r1,0x0,r42; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	400000000010E700 }

l400000000010E870:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000010E780; }

;; describe_command: 400000000010E880
;;   Called from:
;;     40000000000ECFAC (in command_builtin)
;;     400000000010F8EC (in type_builtin)
describe_command proc
	{ alloc	r41,ar.pfs,0x10,0x0,0xC; and	r36,0x20,r33; mov	r43,pr }
	{ adds	r42,0x0,r1; and	r34,0x1,r33; mov	r40,b0 }
	{ nop.m	0x0; cmp4.eq	p17,p16,0x0,r36; (p16) br.cond.dptk.few	400000000010EAF0 }

l400000000010E8B0:
	{ addl	r14,6680,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	400000000010EF90 }

l400000000010E8E0:
	{ adds	r35,0x0,r0; nop.m	0x0; nop.i	0x0 }

l400000000010E8F0:
	{ adds	r44,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,find_reserved_word; }
	{ cmp4.lt	p07,p06,r8,r0; adds	r1,0x0,r42; (p07) br.cond.dpnt.few	400000000010E960; }

l400000000010E910:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x3; (p07) br.cond.dpnt.few	400000000010F130; }

l400000000010E920:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x1; (p07) br.cond.dpnt.few	400000000010F390; }

l400000000010E930:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x2; (p07) br.cond.dpnt.few	400000000010F230; }

l400000000010E940:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r34; (p06) br.cond.dpnt.few	400000000010ED40; }

l400000000010E950:
	{ (p07) addl	r35,1,r0; nop.m	0x0; nop.i	0x0; }

l400000000010E956:
	{ break.m	0x4000; nop; break.i	0x80000 }

l400000000010E960:
	{ nop.m	0x0; and	r14,0x60,r33; nop.i	0x0; }

l400000000010E962:
	{ Invalid; (p28) break.i	0x40588; Invalid }

l400000000010E966:
	{ Invalid; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	f0,3FFFFFFFFFDD1A56; nop; break.b	0x80000 }

l400000000010E980:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dptk.few	400000000010E9F0 }

l400000000010E990:
	{ adds	r44,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,find_shell_builtin; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r42; (p06) br.cond.dpnt.few	400000000010E9F0; }

l400000000010E9B0:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x3; (p07) br.cond.dpnt.few	400000000010F180; }

l400000000010E9C0:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x1; (p07) br.cond.dpnt.few	400000000010F010; }

l400000000010E9D0:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x2; (p07) br.cond.dpnt.few	400000000010F1F0; }

l400000000010E9E0:
	{ addl	r35,1,r0; cmp4.eq	p06,p07,0x0,r34; (p06) br.cond.dpnt.few	400000000010ED40 }

l400000000010E9F0:
	{ adds	r44,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,absolute_program; }
	{ adds	r1,0x0,r42; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dpnt.few	400000000010EEF0; }

l400000000010EA10:
	{ nop.m	0x0; cmp4.eq	p16,p17,0x0,r34; cmp4.eq	p06,p07,0x0,r36 }
	{ nop.b	0x0; (p16) br.cond.dpnt.few	400000000010EA30; (p06) br.cond.dptk.few	400000000010EBA0 }

l400000000010EA2C:
	{ (p12) shladd	r0,r0,0x2,r33; zxt1	r0,r64; break.i	0x1000 }

l400000000010EA30:
	{ adds	r44,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,phash_search; }
	{ cmp.eq	p06,p07,0x0,r8; nop.m	0x0; adds	r1,0x0,r42 }
	{ adds	r36,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	400000000010EBA0; }

l400000000010EA60:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x3; nop.i	0x0 }
	{ adds	r44,0x0,r36; addl	r35,1,r0; (p07) br.cond.dpnt.few	400000000010F1B0; }

l400000000010EA80:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x1; and	r33,0x14,r33 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	400000000010F060; }

l400000000010EAA0:
	{ cmp4.eq	p06,p07,0x0,r33; nop.i	0x0; (p07) br.cond.dpnt.few	400000000010F100; }

l400000000010EAB0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r42; nop.m	0x0; nop.i	0x0 }

l400000000010EAD0:
	{ adds	r8,0x0,r35; mov	pr,r43,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.spnt	b0,r40,400000000010EAE0; br.ret	b0 }

l400000000010EAF0:
	{ and	r14,0x60,r33; nop.m	0x0; adds	r35,0x0,r0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	400000000010E980 }

l400000000010EB10:
	{ adds	r44,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,find_function; }
	{ cmp.eq	p06,p07,0x0,r8; nop.m	0x0; adds	r1,0x0,r42 }
	{ adds	r37,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	400000000010E980; }

l400000000010EB40:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x3; (p07) br.cond.dpnt.few	400000000010F0D0; }

l400000000010EB50:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x1; (p07) br.cond.dpnt.few	400000000010F300; }

l400000000010EB60:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x2; (p07) br.cond.dpnt.few	400000000010F210; }

l400000000010EB70:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r34; addl	r35,1,r0 }
	{ nop.b	0x0; (p06) br.cond.dpnt.few	400000000010ED40; (p16) br.cond.dptk.few	400000000010E9F0 }

l400000000010EB8C:
	{ (p51) invala; break.i	0x1000; break.b	0x1000 }

l400000000010EB90:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000010E990 }

l400000000010EBA0:
	{ and	r15,0x16,r33; and	r14,0x14,r33; tnat.z	p22,p23,r33 }
	{ addl	r38,6456,r1; adds	r36,0x0,r0; cmp4.eq	p19,p18,0x0,r34; }
	{ (p22) addl	r39,2,r0; cmp4.eq	p26,p27,0x0,r15; tnat.z	p20,p21,r33 }

l400000000010EBC6:
	{ Invalid; (p10) nop; nop }
	{ break.m	0x4000; nop; cmp.lt	p00,p00,r0,r32 }
	{ Invalid; Invalid; Invalid }

l400000000010EBEC:
	{ (p01) nop; break.i	0x1000; break.i	0x1000; }
	{ shladd	r0,r1,0x2,r0; zxt1	r0,r64; chk.s.i	r32,3FFFFFFFFF90EBFC }

l400000000010EC00:
	{ adds	r44,0x0,r32; nop.i	0x0; (p19) br.call.dptk.many	b0,find_user_command; }

l400000000010EC10:
	{ (p18) addl	r45,8,r0; (p18) adds	r46,0x0,r36; (p18) br.call.dptk.many	b0,user_command_matches; }

l400000000010EC16:
	{ (p23) nop; (p16) nop }

l400000000010EC1C:
	{ (p15) nop; invala; Invalid }

l400000000010EC20:
	{ adds	r1,0x0,r42; nop.m	0x0; cmp.eq	p06,p07,0x0,r8 }
	{ adds	r34,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	400000000010EAD0; }

l400000000010EC40:
	{ ld1	r37,[r8]; ld1	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r37,r37; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r37; (p07) br.cond.dpnt.few	400000000010ED70 }

l400000000010EC70:
	{ nop.m	0x0; ld4	r14,[r38]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	400000000010ED90 }

l400000000010EC90:
	{ nop.m	0x0; nop.i	0x0; (p22) br.cond.dptk.few	400000000010ECE0; }

l400000000010ECA0:
	{ cmp4.eq	p06,p07,0x2F,r37; nop.i	0x0; (p06) br.cond.dpnt.few	400000000010ECE0; }

l400000000010ECB0:
	{ adds	r45,0x0,r34; nop.m	0x0; adds	r44,0x0,r0 }
	{ addl	r46,6,r0; nop.m	0x0; br.call.sptk.many	b0,sh_makepath; }
	{ nop.m	0x0; adds	r1,0x0,r42; adds	r34,0x0,r8; }

l400000000010ECE0:
	{ nop.m	0x0; adds	r36,0x1,r36; (p21) br.cond.dpnt.few	400000000010EE00; }

l400000000010ECF0:
	{ (p25) adds	r44,0x0,r34; nop.m	0x0; addl	r35,1,r0 }

l400000000010ECF6:
	{ add	r0,r0,r1; (p17) nop; dep	r0,r0,r0,31,1 }
	{ Invalid; Invalid; Invalid }

l400000000010ED0C:
	{ (p52) nop; shladd	r64,r10,0x1,r64; zxt1	r64,r64 }

l400000000010ED10:
	{ (p25) adds	r1,0x0,r42; adds	r44,0x0,r34; br.call.sptk.many	b0,fn400000000001A7E0; }

l400000000010ED16:
	{ Invalid; (p32) nop; break.i	0x80000 }
	{ nop; nop; break.b	0x80000 }

l400000000010ED30:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000010ED40:
	{ addl	r35,1,r0; nop.m	0x0; nop.i	0x0; }

l400000000010ED50:
	{ adds	r8,0x0,r35; mov	pr,r43,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.spnt	b0,r40,400000000010ED60; br.ret	b0; }

l400000000010ED70:
	{ adds	r44,0x0,r8; adds	r45,0x0,r32; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r42; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	400000000010EC70 }

l400000000010ED90:
	{ adds	r44,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,file_status; }
	{ adds	r1,0x0,r42; tbit.z	p07,p06,r8,0x1; (p07) br.cond.dpnt.few	400000000010EED0; }

l400000000010EDB0:
	{ ld1	r14,[r34]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x2F,r14; (p06) br.cond.dpnt.few	400000000010ECE0; (p26) br.cond.dptk.few	400000000010ECE0 }

l400000000010EDCC:
	{ (p57) nop; (p05) shladd	r64,r8,0x1,r64; zxt1	r0,r64 }

l400000000010EDD0:
	{ adds	r45,0x0,r34; adds	r44,0x0,r0; nop.i	0x0 }
	{ adds	r46,0x0,r39; adds	r36,0x1,r36; br.call.sptk.many	b0,sh_makepath; }
	{ adds	r1,0x0,r42; adds	r34,0x0,r8; (p20) br.cond.dptk.few	400000000010ECF0; }

l400000000010EE00:
	{ addl	r44,1100,r1; nop.m	0x0; addl	r35,1,r0; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B380; }
	{ adds	r1,0x0,r42; adds	r44,0x0,r34; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r42; (p17) br.cond.dptk.few	400000000010EC00 }

l400000000010EE40:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000010ED40; }

l400000000010EE50:
	{ addl	r45,1108,r1; nop.m	0x0; adds	r44,0x0,r0 }
	{ addl	r46,5,r0; nop.m	0x0; addl	r35,1,r0; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r46,0x0,r32; adds	r45,0x0,r8; adds	r47,0x0,r34 }
	{ adds	r1,0x0,r42; addl	r44,1,r0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r42; adds	r44,0x0,r34; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r42; (p17) br.cond.dptk.few	400000000010EC00 }

l400000000010EEC0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000010ED40 }

l400000000010EED0:
	{ adds	r44,0x0,r34; adds	r34,0x0,r0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r42; (p16) br.cond.dpnt.few	400000000010EAD0; br.cond.sptk.few	400000000010ECE0 }

l400000000010EEEC:
	{ (p48) shladd	r127,r63,0x2,r36; zxt1	r0,r64; break.i	0x1000 }

l400000000010EEF0:
	{ adds	r44,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,file_status; }
	{ adds	r1,0x0,r42; tbit.z	p06,p07,r8,0x1; (p06) br.cond.dptk.few	400000000010EA10; }

l400000000010EF10:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x3; (p07) br.cond.dpnt.few	400000000010F4B0; }

l400000000010EF20:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x1; and	r33,0x14,r33 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	400000000010F500; }

l400000000010EF40:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r33; (p06) br.cond.dptk.few	400000000010ED40 }

l400000000010EF50:
	{ adds	r44,0x0,r32; addl	r35,1,r0; br.call.sptk.many	b0,fn400000000001B380; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r42; mov	pr,r43,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r41; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r40,400000000010EF80; br.ret	b0; }

l400000000010EF90:
	{ adds	r44,0x0,r32; cmp4.eq	p19,p18,0x0,r34; br.call.sptk.many	b0,find_alias; }
	{ cmp.eq	p06,p07,0x0,r8; nop.m	0x0; adds	r1,0x0,r42 }
	{ adds	r35,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	400000000010E8E0; }

l400000000010EFC0:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x3; (p07) br.cond.dpnt.few	400000000010F400; }

l400000000010EFD0:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x1; (p07) br.cond.dpnt.few	400000000010F440; }

l400000000010EFE0:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x2; (p18) addl	r35,1,r0 }

l400000000010EFF0:
	{ nop.b	0x0; (p07) br.cond.dpnt.few	400000000010F270; (p18) br.cond.dptk.few	400000000010E8F0; }

l400000000010EFFC:
	{ (p08) invala; nop; zxt4	r0,r0 }

l400000000010F000:
	{ nop.m	0x0; addl	r35,1,r0; br.cond.sptk.few	400000000010ED50 }

l400000000010F010:
	{ addl	r45,1092,r1; adds	r44,0x0,r0; addl	r46,5,r0; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r42; addl	r44,1,r0; nop.i	0x0 }
	{ adds	r45,0x0,r8; adds	r46,0x0,r32; br.call.sptk.many	b0,fn400000000001BB80; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	400000000010E9E0; }

l400000000010F060:
	{ addl	r45,1116,r1; nop.m	0x0; adds	r44,0x0,r0 }
	{ addl	r46,5,r0; nop.m	0x0; addl	r35,1,r0; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r42; adds	r45,0x0,r8; adds	r46,0x0,r32 }
	{ adds	r47,0x0,r36; addl	r44,1,r0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r42; adds	r44,0x0,r36; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	400000000010EAD0; }

l400000000010F0D0:
	{ nop.m	0x0; addl	r44,1068,r1; nop.i	0x0; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B380; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	400000000010EB70 }

l400000000010F100:
	{ adds	r44,0x0,r8; addl	r35,1,r0; br.call.sptk.many	b0,fn400000000001B380; }
	{ adds	r1,0x0,r42; adds	r44,0x0,r36; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	400000000010EAD0; }

l400000000010F130:
	{ nop.m	0x0; addl	r44,1052,r1; nop.i	0x0; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B380; }
	{ cmp4.eq	p06,p07,0x0,r34; nop.m	0x0; adds	r1,0x0,r42; }
	{ nop.m	0x0; (p07) addl	r35,1,r0; (p07) br.cond.dptk.few	400000000010E960 }

l400000000010F16C:
	{ invala; break.i	0x1000; break.i	0x1000 }

l400000000010F170:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000010ED40 }

l400000000010F180:
	{ nop.m	0x0; addl	r44,1084,r1; nop.i	0x0; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B380; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	400000000010E9E0; }

l400000000010F1B0:
	{ addl	r44,1100,r1; nop.m	0x0; addl	r35,1,r0; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B380; }
	{ adds	r1,0x0,r42; adds	r44,0x0,r36; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	400000000010EAD0 }

l400000000010F1F0:
	{ adds	r44,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B380; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	400000000010E9E0 }

l400000000010F210:
	{ adds	r44,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B380; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	400000000010EB70 }

l400000000010F230:
	{ adds	r44,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B380; }
	{ cmp4.eq	p06,p07,0x0,r34; nop.m	0x0; adds	r1,0x0,r42; }
	{ nop.m	0x0; (p07) addl	r35,1,r0; (p07) br.cond.dptk.few	400000000010E960 }

l400000000010F25C:
	{ Invalid; break.i	0x1000; break.b	0x1000 }

l400000000010F260:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000010ED40; }

l400000000010F270:
	{ adds	r35,0x8,r8; nop.m	0x0; cmp4.eq	p19,p18,0x0,r34; }
	{ ld8	r44,[r35]; nop.i	0x0; br.call.sptk.many	b0,sh_single_quote; }
	{ adds	r1,0x0,r42; adds	r35,0x0,r8; adds	r46,0x0,r32 }
	{ adds	r47,0x0,r8; addl	r44,1,r0; addl	r45,1044,r1; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r42; nop.m	0x0; adds	r44,0x0,r35 }
	{ (p18) addl	r35,1,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }

l400000000010F2D6:
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ nop; nop; break.b	0x80000 }

l400000000010F2F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000010F000; }

l400000000010F300:
	{ addl	r45,1076,r1; nop.m	0x0; adds	r44,0x0,r0 }
	{ addl	r46,5,r0; nop.m	0x0; adds	r37,0x8,r37; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r42; adds	r46,0x0,r32; nop.i	0x0 }
	{ addl	r44,1,r0; adds	r45,0x0,r8; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r42; addl	r46,3,r0; nop.i	0x0 }
	{ adds	r44,0x0,r32; ld8	r45,[r37]; br.call.sptk.many	b0,named_function_string; }
	{ adds	r1,0x0,r42; adds	r44,0x0,r8; br.call.sptk.many	b0,fn400000000001B380; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	400000000010EB70; }

l400000000010F390:
	{ addl	r45,1060,r1; adds	r44,0x0,r0; addl	r46,5,r0; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r42; addl	r44,1,r0; nop.i	0x0 }
	{ adds	r45,0x0,r8; adds	r46,0x0,r32; br.call.sptk.many	b0,fn400000000001BB80; }
	{ cmp4.eq	p06,p07,0x0,r34; nop.m	0x0; adds	r1,0x0,r42; }
	{ nop.m	0x0; (p07) addl	r35,1,r0; (p07) br.cond.dptk.few	400000000010E960 }

l400000000010F3EC:
	{ (p44) invala; break.i	0x1000; break.i	0x1000 }

l400000000010F3F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000010ED40 }

l400000000010F400:
	{ addl	r44,1028,r1; nop.m	0x0; cmp4.eq	p19,p18,0x0,r34; }
	{ ld8	r44,[r44]; (p18) addl	r35,1,r0; br.call.sptk.many	b0,fn400000000001B380; }

l400000000010F41C:
	{ (p59) invala; nop; epc }
	{ Invalid; break.i	0x1000; break.b	0x1000 }

l400000000010F430:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000010F000; }

l400000000010F440:
	{ addl	r45,1036,r1; adds	r35,0x8,r35; nop.i	0x0 }
	{ adds	r44,0x0,r0; addl	r46,5,r0; cmp4.eq	p19,p18,0x0,r34; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r42; ld8	r47,[r35]; addl	r44,1,r0 }
	{ adds	r45,0x0,r8; adds	r46,0x0,r32; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r42; (p18) addl	r35,1,r0; (p18) br.cond.dptk.few	400000000010E8F0 }

l400000000010F49C:
	{ Invalid; break.i	0x1000; break.i	0x1000 }

l400000000010F4A0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000010F000; }

l400000000010F4B0:
	{ addl	r44,1100,r1; nop.m	0x0; addl	r35,1,r0; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B380; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r42; mov	pr,r43,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r41; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r40,400000000010F4F0; br.ret	b0 }

l400000000010F500:
	{ addl	r45,1108,r1; nop.m	0x0; adds	r44,0x0,r0 }
	{ addl	r46,5,r0; nop.m	0x0; addl	r35,1,r0; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r42; adds	r46,0x0,r32; addl	r44,1,r0 }
	{ adds	r45,0x0,r8; adds	r47,0x0,r32; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r42; mov	pr,r43,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r41; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r40,400000000010F570; br.ret	b0; }

;; type_builtin: 400000000010F580
type_builtin proc
	{ alloc	r40,ar.pfs,0xD,0x0,0xB; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r42,pr }
	{ adds	r41,0x0,r1; cmp.eq	p06,p07,0x0,r32; adds	r33,0x0,r32; }
	{ addl	r36,116,r0; addl	r38,97,r0; nop.b	0x0 }
	{ addl	r37,112,r0; mov	r39,b7; (p06) adds	r8,0x0,r0; }

l400000000010F5C0:
	{ nop.m	0x0; nop.i	0x0; (p06) br.cond.dpnt.few	400000000010F7E0; }

l400000000010F5D0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000010F5E0:
	{ adds	r35,0x8,r33; ld8	r14,[r35]; nop.i	0x0; }
	{ ld8	r15,[r14]; adds	r34,0x1,r15; nop.i	0x0; }
	{ ld1	r14,[r15]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x2D,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000010F740; }

l400000000010F620:
	{ ld1	r14,[r34]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x74,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000010FA30; }

l400000000010F640:
	{ cmp4.eq	p07,p06,0x2D,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000010FAC0; }

l400000000010F650:
	{ cmp4.eq	p07,p06,0x70,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000010FB90; }

l400000000010F660:
	{ cmp4.eq	p07,p06,0x61,r14; adds	r14,0x2,r15; (p06) br.cond.dpnt.few	400000000010F720; }

l400000000010F670:
	{ nop.m	0x0; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x6C,r14; (p06) br.cond.dptk.few	400000000010F720 }

l400000000010F690:
	{ adds	r14,0x3,r15; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x6C,r14; (p06) br.cond.dptk.few	400000000010F720 }

l400000000010F6B0:
	{ adds	r15,0x4,r15; ld1	r14,[r15]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.spnt.few	400000000010F720; }

l400000000010F6D0:
	{ ld8.a	r14,[r35]; st1	[r38],r34; nop.i	0x0; }
	{ ld8.c.clr	r14,[r35]; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; adds	r14,0x2,r14; nop.i	0x0; }
	{ st1	[r0],r14; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000010F720:
	{ nop.m	0x0; ld8	r33,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	400000000010F5E0 }

l400000000010F740:
	{ addl	r34,1172,r1; addl	r33,2,r0; nop.i	0x0 }
	{ ld8	r34,[r34]; nop.m	0x0; br.call.sptk.many	b0,reset_internal_getopt; }
	{ adds	r1,0x0,r41; nop.m	0x0; nop.i	0x0; }
	{ addl	r44,1164,r1; nop.m	0x0; adds	r43,0x0,r32; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r41; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dpnt.few	400000000010F880 }

l400000000010F7A0:
	{ nop.m	0x0; adds	r8,0xFFFFFFFFFFFFFFB0,r8; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x24,r8; (p07) br.cond.dptk.few	400000000010F810 }

l400000000010F7C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ nop.m	0x0; adds	r1,0x0,r41; addl	r8,258,r0 }

l400000000010F7E0:
	{ nop.m	0x0; mov	pr,r42,0xFFFFFFFFFFFFFFFE; nop.i	0x0; }
	{ nop.m	0x0; mov.i	ar.pfs,r40; mov.spnt	b0,r39,400000000010F7F0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l400000000010F810:
	{ addp4	r8,r8,r0; shladd	r8,r8,0x3,r34; nop.i	0x0; }
	{ ld8	r14,[r8]; add	r8,r8,r14; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r8,400000000010F830; br.cond	b6; }
400000000010F840 09 60 31 02 09 24 10 6A 87 58 44 60 05 00 01 84 .`1..$.j.XD`....
400000000010F850 11 60 01 58 18 10 10 42 84 5C 40 00 78 AC 00 50 .`.X...B.\@.x..P
400000000010F860 11 08 00 52 00 21 70 F8 23 0C 77 03 40 FF FF 4A ...R.!p.#.w.@..J
400000000010F870 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

l400000000010F880:
	{ addl	r14,9268,r1; nop.m	0x0; adds	r35,0x0,r0; }
	{ nop.m	0x0; ld8	r34,[r14]; and	r14,0x18,r33; }
	{ cmp.eq	p06,p07,0x0,r34; nop.m	0x0; cmp4.eq	p17,p16,0x0,r14; }
	{ nop.m	0x0; (p06) adds	r43,0x0,r0; (p06) br.cond.dpnt.few	400000000010F990; }

l400000000010F8BC:
	{ Invalid; zxt1	r66,r64; add	r0,r32,r0 }

l400000000010F8C0:
	{ adds	r36,0x8,r34; nop.m	0x0; adds	r44,0x0,r33; }
	{ nop.m	0x0; ld8	r14,[r36]; nop.i	0x0; }
	{ ld8	r43,[r14]; nop.i	0x0; br.call.sptk.many	b0,describe_command; }
	{ adds	r1,0x0,r41; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	400000000010F940 }

l400000000010F900:
	{ (p17) ld8	r14,[r36]; (p17) ld8	r43,[r14]; (p17) adds	r14,0x10,r12; }

l400000000010F906:
	{ Invalid; Invalid; Invalid }

l400000000010F90C:
	{ (p08) srlz.i; Invalid; Invalid; }

l400000000010F910:
	{ (p17) st8	[r8],r14; nop.i	0x0; (p17) br.call.dpnt.many	b0,sh_notfound; }

l400000000010F916:
	{ nop; (p32) extr.u	r55,r127,30,46; (p36) nop }

l400000000010F920:
	{ (p17) adds	r14,0x10,r12; nop.m	0x0; (p17) adds	r1,0x0,r41; }

l400000000010F926:
	{ nop; dep.z	r0,0x29,63,3; (p04) nop }

l400000000010F930:
	{ (p17) ld8	r8,[r14]; nop.m	0x0; nop.i	0x0; }

l400000000010F936:
	{ break.m	0x4000; nop; (p32) nop }

l400000000010F940:
	{ cmp4.eq	p06,p07,0x0,r8; ld8	r34,[r34]; nop.i	0x0; }

l400000000010F942:
	{ fwb; (p32) break.i	0x20308; dep	r32,r0,r96,60,3 }

l400000000010F946:
	{ (p17) fwb; addl	r0,49152,r1; (p01) cmp.eq	p34,p00,0x0,r0 }

l400000000010F94E:
	{ sum	0x81960; nop }
	{ (p32) break.m	0x23C; (p04) nop; Invalid; }
	{ Invalid; Invalid; Invalid }
	{ nop.m	0x31C40; (p04) nop }
	{ (p32) break.m	0x230; (p04) break.i	0x0; (p04) cmp4.eq	p00,p30,0xFFFFFFFFFFFFFF80,r0; }

l400000000010F990:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_chkwrite; }
	{ adds	r1,0x0,r41; mov	pr,r42,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.spnt	b0,r39,400000000010F9B0; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }
400000000010F9D0 09 00 00 00 01 00 10 AA 87 58 44 00 00 00 04 00 .........XD.....
400000000010F9E0 11 00 00 00 01 00 10 82 84 5C 40 00 90 FD FF 48 .........\@....H
400000000010F9F0 11 00 00 00 01 00 10 02 86 5C 40 00 80 FD FF 48 .........\@....H
400000000010FA00 11 00 00 00 01 00 10 0A 84 5C 40 00 70 FD FF 48 .........\@.p..H
400000000010FA10 09 00 00 00 01 00 10 AA 87 58 44 00 00 00 04 00 .........XD.....
400000000010FA20 10 00 00 00 01 00 10 82 85 5C 40 00 50 FD FF 48 .........\@.P..H

l400000000010FA30:
	{ addl	r44,1124,r1; nop.m	0x0; adds	r43,0x0,r34; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r41; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	400000000010F720 }

l400000000010FA60:
	{ ld8.a	r14,[r35]; st1	[r36],r34; nop.i	0x0; }
	{ ld8.c.clr	r14,[r35]; ld8	r14,[r14]; nop.i	0x0; }
	{ adds	r14,0x2,r14; st1	[r0],r14; nop.i	0x0; }
	{ nop.m	0x0; ld8	r33,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	400000000010F5E0 }

l400000000010FAB0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000010F740 }

l400000000010FAC0:
	{ addl	r44,1132,r1; nop.m	0x0; adds	r43,0x0,r34; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r41; cmp4.eq	p07,p06,0x0,r8; (p07) br.cond.dptk.few	400000000010FA60; }

l400000000010FAF0:
	{ addl	r44,1148,r1; nop.m	0x0; adds	r43,0x0,r34; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r41; cmp4.eq	p07,p06,0x0,r8; (p07) br.cond.dptk.few	400000000010FBC0; }

l400000000010FB20:
	{ addl	r44,1156,r1; nop.m	0x0; adds	r43,0x0,r34; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r41; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	400000000010F720 }

l400000000010FB50:
	{ ld8.a	r14,[r35]; st1	[r38],r34; nop.i	0x0; }
	{ ld8.c.clr	r14,[r35]; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; adds	r14,0x2,r14; nop.i	0x0; }
	{ st1	[r0],r14; nop.i	0x0; br.cond.sptk.few	400000000010F720 }

l400000000010FB90:
	{ addl	r44,1140,r1; nop.m	0x0; adds	r43,0x0,r34; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r41; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	400000000010F720 }

l400000000010FBC0:
	{ ld8.a	r14,[r35]; st1	[r37],r34; nop.i	0x0; }
	{ ld8.c.clr	r14,[r35]; ld8	r14,[r14]; nop.i	0x0; }
	{ adds	r14,0x2,r14; st1	[r0],r14; nop.i	0x0; }
	{ nop.m	0x0; ld8	r33,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	400000000010F5E0 }

l400000000010FC10:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000010F740; }
400000000010FC20 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
400000000010FC30 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; fn400000000010FC40: 400000000010FC40
;;   Called from:
;;     40000000001103E6 (in ulimit_builtin)
;;     4000000000110C9C (in ulimit_builtin)
fn400000000010FC40 proc
	{ alloc	r38,ar.pfs,0xE,0x0,0x8; adds	r12,0xFFFFFFFFFFFFFFC0,r12; mov	r37,b5 }
	{ addl	r35,-5940,r1; adds	r39,0x0,r1; sxt4	r32,r32; }
	{ ld8	r35,[r35]; dep.z	r14,r32,5,59; add	r14,r35,r14; }
	{ adds	r14,0x8,r14; ld4	r36,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFE,r36; (p07) br.cond.dpnt.few	400000000010FDE0; }

l400000000010FC90:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r34; (p06) br.cond.dptk.few	400000000010FD70 }

l400000000010FCA0:
	{ addl	r16,-5940,r1; addl	r43,-6116,r1; dep.z	r14,r32,5,59 }
	{ adds	r40,0x10,r12; addl	r41,1,r0; addl	r42,64,r0; }
	{ add	r15,r35,r14; ld8	r16,[r16]; nop.i	0x0; }
	{ adds	r15,0x18,r15; nop.m	0x0; add	r14,r16,r14; }
	{ nop.m	0x0; ld8	r44,[r15]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r44; nop.i	0x0; (p06) br.cond.dpnt.few	400000000010FE20; }

l400000000010FD00:
	{ ld8	r43,[r43]; nop.m	0x0; dep.z	r32,r32,5,59 }
	{ ld4	r45,[r14]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C440; }
	{ adds	r1,0x0,r39; add	r35,r35,r32; addl	r40,1,r0 }
	{ adds	r43,0x10,r12; addl	r41,-6100,r1; adds	r35,0x10,r35; }
	{ nop.m	0x0; ld8	r41,[r41]; nop.i	0x0 }
	{ ld8	r42,[r35]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r39; nop.m	0x0; nop.i	0x0 }

l400000000010FD70:
	{ cmp.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r33; nop.m	0x0; sxt4	r41,r36 }
	{ adds	r40,0x0,r33; nop.m	0x0; (p07) br.cond.dpnt.few	400000000010FE90; }

l400000000010FD90:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000137B00; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r40,0x0,r8 }
	{ addl	r41,1,r0; nop.m	0x0; br.call.sptk.many	b0,print_rlimtype; }
	{ adds	r1,0x0,r39; mov.i	ar.pfs,r38; mov.spnt	b0,r37,400000000010FDC0 }
	{ nop.m	0x0; adds	r12,0x40,r12; br.ret	b0 }

l400000000010FDE0:
	{ addl	r14,6456,r1; nop.m	0x0; nop.i	0x0; }
	{ ld4	r36,[r14]; cmp4.eq	p06,p07,0x0,r36; nop.i	0x0; }
	{ nop.m	0x0; (p06) addl	r36,1024,r0; nop.i	0x0; }

l400000000010FE0C:
	{ invala; nop; zxt4	r0,r1 }

l400000000010FE1C:
	{ (p52) ldfp8	f127,f63,[r36]; (p05) shladd	r41,r31,0x4,r116; Invalid }

l400000000010FE20:
	{ addl	r43,-6108,r1; ld4	r44,[r14]; dep.z	r32,r32,5,59; }
	{ ld8	r43,[r43]; add	r35,r35,r32; br.call.sptk.many	b0,fn400000000001C440; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r35,0x10,r35 }
	{ addl	r40,1,r0; nop.m	0x0; adds	r43,0x10,r12; }
	{ addl	r41,-6100,r1; ld8	r42,[r35]; nop.i	0x0; }
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ nop.m	0x0; adds	r1,0x0,r39; br.cond.sptk.few	400000000010FD70; }

l400000000010FE90:
	{ nop.m	0x0; addl	r40,-6092,r1; nop.i	0x0; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B380; }
	{ adds	r1,0x0,r39; mov.i	ar.pfs,r38; mov.spnt	b0,r37,400000000010FEB0 }
	{ nop.m	0x0; adds	r12,0x40,r12; br.ret	b0; }
400000000010FED0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000010FEE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000010FEF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn400000000010FF00: 400000000010FF00
;;   Called from:
;;     40000000001103BC (in ulimit_builtin)
;;     4000000000110A4C (in ulimit_builtin)
;;     4000000000110C4C (in ulimit_builtin)
;;     4000000000110F3C (in ulimit_builtin)
fn400000000010FF00 proc
	{ alloc	r36,ar.pfs,0x8,0x0,0x6; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r35,b3 }
	{ addl	r14,-5940,r1; adds	r37,0x0,r1; sxt4	r32,r32; }
	{ ld8	r14,[r14]; nop.m	0x0; dep.z	r32,r32,5,59; }
	{ add	r32,r14,r32; addl	r14,255,r0; adds	r32,0x4,r32; }
	{ nop.m	0x0; ld4	r38,[r32]; nop.i	0x0; }
	{ cmp4.lt	p07,p06,r14,r38; addl	r14,257,r0; (p06) br.cond.dpnt.few	4000000000110000; }

l400000000010FF60:
	{ cmp4.eq	p06,p07,r14,r38; nop.i	0x0; (p06) br.cond.dpnt.few	400000000010FFC0; }

l400000000010FF70:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ addl	r14,-1,r0; addl	r15,22,r0; adds	r1,0x0,r37; }
	{ st4	[r15],r8; adds	r8,0x0,r14; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,400000000010FFA0; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l400000000010FFC0:
	{ addl	r15,4096,r0; nop.m	0x0; adds	r14,0x0,r0; }
	{ st8	[r15],r34; adds	r8,0x0,r14; nop.b	0x0 }
	{ st8	[r15],r33; mov.i	ar.pfs,r36; mov.spnt	b0,r35,400000000010FFE0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l4000000000110000:
	{ adds	r39,0x10,r12; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AD40; }
	{ adds	r15,0x10,r12; cmp4.lt	p06,p07,r8,r0; adds	r1,0x0,r37; }
	{ (p07) ld8	r16,[r15],8; nop.m	0x0; (p07) adds	r14,0x0,r0; }

l4000000000110026:
	{ chk.a.nc	f0,3FFFFFFFFF110826; (p07) nop; cmp.lt	p00,p00,r0,r32 }

l4000000000110030:
	{ nop.m	0x0; (p07) ld8	r15,[r15]; (p06) addl	r14,-1,r0 }

l400000000011003C:
	{ (p63) nop; mov	pr,r32,0x0; rfi; }

l4000000000110040:
	{ nop.m	0x0; (p07) st8	[r16],r33; nop.i	0x0; }

l400000000011004C:
	{ nop; (p01) mov	pr,r3,0x8480; Invalid }

l400000000011005C:
	{ (p18) break.m	0x1540; break.i	0x1000; (p48) break.i	0xC0028 }
	{ shladdp4	r0,r1,0x2,r0; zxt1	r4,r64; add	r0,r32,r0 }
	{ nop; Invalid; zxt2	r24,r79 }

;; ulimit_builtin: 4000000000110080
ulimit_builtin proc
	{ alloc	r53,ar.pfs,0x1B,0x0,0x18; adds	r12,0xFFFFFFFFFFFFFFE0,r12; nop.b	0x0 }
	{ addl	r14,21236,r1; mov	r55,pr; adds	r54,0x0,r1; }
	{ nop.m	0x0; addl	r15,99,r0; nop.b	0x0 }
	{ addl	r19,59,r0; mov	r52,b4; adds	r18,0x0,r14; }
	{ ld1	r16,[r14]; adds	r14,0x2,r14; sxt1	r16,r16; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r16; (p06) br.cond.dptk.few	4000000000110190 }

l40000000001100E0:
	{ addl	r16,97,r0; st1	[r18],r1,1; addl	r16,72,r0; }
	{ st1	[r16],r14; nop.m	0x0; addl	r14,6276,r1; }
	{ ld8	r17,[r14]; nop.m	0x0; addl	r14,6268,r1; }
	{ ld8	r16,[r14]; addl	r14,83,r0; nop.i	0x0; }
	{ st1	[r14],r18; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000110140:
	{ adds	r17,0x20,r17; adds	r14,0x0,r16; adds	r16,0x2,r16; }
	{ adds	r18,0xFFFFFFFFFFFFFFE0,r17; st1	[r14],r1,1; nop.i	0x0; }
	{ ld4	r15,[r18]; st1	[r19],r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,0x0,r15; (p06) br.cond.dptk.few	4000000000110140 }

l4000000000110180:
	{ st1	[r0],r16; nop.m	0x0; nop.i	0x0 }

l4000000000110190:
	{ addl	r36,8540,r1; addl	r34,8556,r1; addl	r39,9252,r1 }
	{ adds	r37,0x0,r0; adds	r35,0x0,r0; addl	r38,8548,r1; }
	{ ld4	r14,[r36]; nop.m	0x0; adds	r41,0x0,r36 }
	{ adds	r40,0x0,r34; nop.m	0x0; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000110530; }

l40000000001101E0:
	{ st4	[r0],r34; br.call.sptk.many	b0,reset_internal_getopt; nop.b	0x0; }
	{ adds	r1,0x0,r54; nop.m	0x0; nop.i	0x0; }

l4000000000110200:
	{ addl	r57,21236,r1; nop.m	0x0; adds	r56,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ nop.m	0x0; adds	r33,0x0,r8; adds	r1,0x0,r54 }
	{ nop.m	0x0; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dpnt.few	4000000000110340; }

l4000000000110240:
	{ cmp4.eq	p06,p07,0x53,r33; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000110520; }

l4000000000110250:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x53,r33; (p06) br.cond.dptk.few	4000000000110480; }

l4000000000110260:
	{ cmp4.eq	p06,p07,0x3F,r33; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001104E0; }

l4000000000110270:
	{ cmp4.eq	p06,p07,0x48,r33; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000110470; }

l4000000000110280:
	{ ld4	r15,[r36]; ld4	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r14,r15; (p06) br.cond.dpnt.few	4000000000110590; }

l40000000001102A0:
	{ (p07) ld8	r8,[r38]; nop.m	0x0; nop.i	0x0; }

l40000000001102A6:
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ break.m	0x4000; break.i	0x4000; break.i	0x80000 }

l40000000001102C0:
	{ nop.m	0x0; sxt4	r16,r14; nop.i	0x0 }
	{ ld8	r15,[r39]; adds	r14,0x1,r14; shladd	r8,r16,0x4,r8 }
	{ st4	[r14],r34; st4	[r8],r8,8; nop.i	0x0 }
	{ nop.m	0x0; st8	[r15],r8; nop.i	0x0 }

l4000000000110300:
	{ addl	r57,21236,r1; nop.m	0x0; adds	r56,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ nop.m	0x0; adds	r1,0x0,r54; adds	r33,0x0,r8 }
	{ nop.m	0x0; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p06) br.cond.dptk.few	4000000000110240; }

l4000000000110340:
	{ addl	r14,9268,r1; nop.m	0x0; cmp4.eq	p06,p07,0x0,r37; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld8	r14,[r14]; nop.i	0x0; (p06) br.cond.dptk.few	40000000001106E0; }

l4000000000110370:
	{ cmp4.eq	p07,p06,0x0,r35; addl	r14,6276,r1; adds	r34,0x0,r0 }
	{ adds	r37,0x28,r12; adds	r36,0x20,r12; (p07) addl	r35,2,r0 }

l4000000000110390:
	{ ld8	r33,[r14]; nop.i	0x0; tnat.z	p16,p17,r35; }

l40000000001103A0:
	{ adds	r56,0x0,r34; nop.m	0x0; adds	r57,0x0,r37 }
	{ adds	r58,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,fn400000000010FF00; }
	{ adds	r1,0x0,r54; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	4000000000110620 }

l40000000001103D0:
	{ (p17) ld8	r57,[r37]; adds	r56,0x0,r34; addl	r58,1,r0; }

l40000000001103D6:
	{ Invalid; (p29) nop; (p20) nop }

l40000000001103E6:
	{ (p32) flushrs; nop; (p16) nop }
	{ break.m	0x4000; Invalid; (p16) nop }

l4000000000110400:
	{ adds	r33,0x20,r33; adds	r34,0x1,r34; adds	r14,0xFFFFFFFFFFFFFFE0,r33; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000001103A0 }

l4000000000110430:
	{ adds	r56,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,sh_chkwrite; }
	{ adds	r1,0x0,r54; mov	pr,r55,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r53; }
	{ nop.m	0x0; mov.spnt	b0,r52,4000000000110450; nop.i	0x0 }
	{ adds	r12,0x20,r12; nop.m	0x0; br.ret	b0 }

l4000000000110470:
	{ nop.m	0x0; or	r35,0x1,r35; br.cond.sptk.few	4000000000110200 }

l4000000000110480:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x61,r33; nop.i	0x0; }
	{ (p06) adds	r37,0x1,r37; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000110200; }

l4000000000110496:
	{ chk.a.nc	r0,3FFFFFFFFF110C96; nop; (p32) nop }

l40000000001104A0:
	{ ld4	r14,[r34]; ld4	r15,[r36]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r14,r15; nop.i	0x0; }
	{ (p07) ld8	r8,[r38]; nop.i	0x0; (p07) br.cond.dptk.few	40000000001102C0 }

l40000000001104C6:
	{ chk.a.nc	f0,3FFFFFFFFF110CC6; nop; break.i	0x80000 }

l40000000001104D0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000110590 }

l40000000001104E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ addl	r8,258,r0; adds	r1,0x0,r54; mov	pr,r55,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r53; mov.spnt	b0,r52,4000000000110500 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0 }

l4000000000110520:
	{ nop.m	0x0; or	r35,0x2,r35; br.cond.sptk.few	4000000000110200 }

l4000000000110530:
	{ addl	r14,16,r0; nop.m	0x0; addl	r56,256,r0; }
	{ st4	[r14],r36; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r54; st4	[r0],r34; nop.i	0x0; }
	{ addl	r14,8548,r1; nop.m	0x0; addl	r38,8548,r1; }
	{ st8	[r8],r14; nop.i	0x0; br.call.sptk.many	b0,reset_internal_getopt; }
	{ nop.m	0x0; adds	r1,0x0,r54; br.cond.sptk.few	4000000000110200 }

l4000000000110590:
	{ shladd	r15,r15,0x1,r0; ld8	r56,[r38]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r57,r15; nop.i	0x0 }
	{ st4	[r15],r41; nop.m	0x0; nop.i	0x0; }
	{ shladd	r57,r57,0x4,r0; nop.i	0x0; br.call.sptk.many	b0,xrealloc; }
	{ ld4	r14,[r40]; st8	[r8],r38; adds	r1,0x0,r54 }
	{ ld8	r15,[r39]; nop.i	0x0; sxt4	r16,r14 }
	{ adds	r14,0x1,r14; nop.i	0x0; shladd	r8,r16,0x4,r8 }
	{ st4	[r14],r34; st4	[r8],r8,8; nop.i	0x0; }
	{ st8	[r15],r8; nop.i	0x0; br.cond.sptk.few	4000000000110300 }

l4000000000110620:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ ld4	r14,[r8]; adds	r15,0xFFFFFFFFFFFFFFF0,r33; adds	r1,0x0,r54; }
	{ cmp4.eq	p06,p07,0x16,r14; adds	r56,0x0,r14; (p06) br.cond.dpnt.few	4000000000110400; }

l4000000000110650:
	{ ld8	r38,[r15]; nop.m	0x0; adds	r33,0x20,r33 }
	{ adds	r34,0x1,r34; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B4A0; }
	{ adds	r1,0x0,r54; adds	r57,0x0,r38; adds	r58,0x0,r8; }
	{ nop.m	0x0; addl	r56,-6084,r1; nop.i	0x0; }
	{ ld8	r56,[r56]; nop.i	0x0; br.call.sptk.many	b0,builtin_error; }
	{ adds	r14,0xFFFFFFFFFFFFFFE0,r33; nop.m	0x0; adds	r1,0x0,r54; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000001103A0 }

l40000000001106D0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000110430 }

l40000000001106E0:
	{ nop.m	0x0; ld4	r21,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r21; (p06) br.cond.dptk.few	4000000000110820; }

l4000000000110700:
	{ cmp.eq	p06,p07,0x0,r14; addl	r43,8548,r1; nop.i	0x0 }
	{ addl	r15,102,r0; addl	r16,102,r0; addl	r21,1,r0; }
	{ (p07) adds	r14,0x8,r14; ld8	r19,[r43]; nop.i	0x0; }

l4000000000110726:
	{ (p09) fwb; cmp4.ltu	p00,p00,0x0,r1; (p33) br.call.sptk.few	b3,b0 }

l4000000000110736:
	{ adds	r15,0xFFFFFFFFFFFFF193,r16; (p07) cmp4.eq.or	p00,p02,r0,r0; (p49) nop }

l4000000000110740:
	{ (p07) ld8	r15,[r14]; nop.m	0x0; adds	r14,0x8,r19; }

l4000000000110746:
	{ break.m	0x4000; (p07) nop; nop }
	{ Invalid; nop; nop }
	{ break.m	0x4000; nop; nop }

l4000000000110770:
	{ addl	r20,6276,r1; cmp4.eq	p06,p07,0x63,r16; adds	r33,0x0,r19 }
	{ adds	r18,0x10,r19; adds	r17,0x0,r0; (p06) br.cond.dpnt.few	40000000001107D0; }

l4000000000110790:
	{ (p07) ld8	r14,[r20]; nop.m	0x0; nop.i	0x0; }

l4000000000110796:
	{ break.m	0x4000; nop; (p48) nop }

l40000000001107A0:
	{ ld4	r15,[r14]; nop.m	0x0; adds	r14,0x20,r14; }

l40000000001107A2:
	{ (p32) break.m	0x20203; mov	pr,r0,0x40; (p36) nop }
	{ (p48) break.m	0x630E3; nop; Invalid }

l40000000001107C0:
	{ nop.m	0x0; cmp4.eq	p06,p07,r15,r16; (p07) br.cond.dptk.few	40000000001107A0 }

l40000000001107D0:
	{ adds	r17,0x1,r17; nop.m	0x0; adds	r33,0x0,r18; }
	{ cmp4.lt	p06,p07,r17,r21; nop.i	0x0; (p07) br.cond.dpnt.few	40000000001108F0; }

l40000000001107F0:
	{ ld4	r16,[r18],16; cmp4.eq	p06,p07,0x63,r16; nop.i	0x0; }
	{ (p07) ld8	r14,[r20]; nop.i	0x0; (p07) br.cond.dptk.few	40000000001107A0 }

l4000000000110806:
	{ chk.a.nc	f0,3FFFFFFFFF111006; nop; break.i	0x80000 }

l4000000000110810:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000001107D0 }

l4000000000110820:
	{ cmp4.lt	p06,p07,0x0,r21; (p06) addl	r43,8548,r1; nop.i	0x0; }

l400000000011082C:
	{ nop; nop; Invalid }

l400000000011083C:
	{ Invalid; Invalid; mov	pr,r32,0x0 }

l4000000000110846:
	{ chk.a.nc	r0,3FFFFFFFFF111046; Invalid; nop }

l4000000000110850:
	{ adds	r8,0x0,r0; mov	pr,r55,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r53; }
	{ nop.m	0x0; mov.spnt	b0,r52,4000000000110860; nop.i	0x0 }
	{ adds	r12,0x20,r12; nop.m	0x0; br.ret	b0 }

l4000000000110880:
	{ addl	r57,-6076,r1; addl	r58,5,r0; adds	r56,0x0,r0; }
	{ ld8	r57,[r57]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r54; nop.m	0x0; adds	r56,0x0,r8 }
	{ ld4	r57,[r33]; nop.m	0x0; br.call.sptk.many	b0,builtin_error; }
	{ addl	r8,258,r0; adds	r1,0x0,r54; mov	pr,r55,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r53; mov.spnt	b0,r52,40000000001108D0 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0 }

l40000000001108F0:
	{ cmp4.eq	p17,p16,0x0,r35; and	r14,0x2,r35; addl	r48,-22276,r1 }
	{ addl	r46,-5940,r1; addl	r50,6456,r1; adds	r39,0x0,r0; }
	{ (p17) addl	r35,3,r0; (p17) addl	r14,2,r0; adds	r40,0x0,r0 }

l4000000000110916:
	{ Invalid; break.x	0x2000002880000 }

l400000000011091C:
	{ nop; (p04) nop; }
	{ (p16) cmp.eq	p12,p08,r0,r66; (p38) nop }
	{ Invalid; Invalid; Invalid }
	{ Invalid; Invalid; Invalid }
	{ cmp.lt	p47,p09,r20,r115; Invalid; dep	r0,r32,r0,63,1 }
	{ nop; break.i	0x1000; break.i	0x1000 }
	{ nop; cmp.lt	p00,p00,r32,r0; zxt1	r100,r0 }

l4000000000110980:
	{ nop.m	0x0; add	r14,r19,r39; nop.i	0x0; }
	{ ld4	r16,[r14],8; ld8	r35,[r14]; cmp4.eq	p06,p07,0x63,r16; }
	{ cmp.eq	p09,p08,0x0,r35; (p06) adds	r33,0x0,r0; (p08) addl	r38,1,r0; }

l40000000001109AC:
	{ Invalid; Invalid; Invalid }

l40000000001109B0:
	{ (p09) adds	r38,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000110A10; }

l40000000001109B6:
	{ chk.a.nc	r0,3FFFFFFFFF1111B6; nop; break.i	0x80000 }

l40000000001109C0:
	{ nop.m	0x0; ld8	r14,[r42]; adds	r33,0x0,r0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000001109E0:
	{ ld4	r15,[r14]; adds	r33,0x1,r33; adds	r14,0x20,r14; }
	{ cmp4.lt	p06,p07,0x0,r15; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000110CE0; }

l4000000000110A00:
	{ nop.m	0x0; cmp4.eq	p06,p07,r15,r16; (p07) br.cond.dptk.few	40000000001109E0 }

l4000000000110A10:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dptk.few	4000000000110C30; }

l4000000000110A20:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r38; (p07) br.cond.dptk.few	4000000000110F20 }

l4000000000110A30:
	{ adds	r56,0x0,r33; nop.m	0x0; adds	r57,0x0,r37 }
	{ adds	r58,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,fn400000000010FF00; }
	{ adds	r1,0x0,r54; cmp4.lt	p06,p07,r8,r0; (p06) br.cond.dpnt.few	4000000000110F50; }

l4000000000110A60:
	{ ld1	r14,[r35]; addl	r57,-6092,r1; adds	r56,0x0,r35; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x68,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000110E60; }

l4000000000110A90:
	{ cmp4.eq	p07,p06,0x73,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000110EB0; }

l4000000000110AA0:
	{ cmp4.eq	p07,p06,0x75,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000110CF0; }

l4000000000110AB0:
	{ ld8	r57,[r57]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r54; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	4000000000110CF0; }

l4000000000110AD0:
	{ addl	r38,-5940,r1; addl	r41,-1,r0; sxt4	r33,r33 }
	{ nop.m	0x0; ld8	r38,[r38]; nop.i	0x0 }

l4000000000110AF0:
	{ nop.m	0x0; dep.z	r14,0x21,5,59; add	r14,r38,r14; }
	{ adds	r14,0x4,r14; ld4	r35,[r14]; nop.i	0x0; }
	{ cmp4.lt	p07,p06,r45,r35; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000111010; }

l4000000000110B20:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ adds	r1,0x0,r54; addl	r14,22,r0; nop.i	0x0 }
	{ addl	r58,5,r0; adds	r34,0x0,r8; adds	r56,0x0,r0; }
	{ addl	r57,-6044,r1; st4	[r14],r8; nop.i	0x0; }
	{ ld8	r57,[r57]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ nop.m	0x0; dep.z	r14,0x21,5,59; adds	r1,0x0,r54 }
	{ adds	r35,0x0,r8; ld4	r56,[r34]; nop.b	0x0; }
	{ add	r14,r38,r14; adds	r14,0x10,r14; nop.i	0x0; }
	{ ld8	r33,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B4A0; }
	{ adds	r1,0x0,r54; adds	r56,0x0,r35; nop.i	0x0 }
	{ adds	r57,0x0,r33; adds	r58,0x0,r8; br.call.sptk.many	b0,builtin_error; }
	{ adds	r1,0x0,r54; nop.m	0x0; nop.i	0x0 }

l4000000000110BE0:
	{ addl	r8,1,r0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000110C00:
	{ nop.m	0x0; mov	pr,r55,0xFFFFFFFFFFFFFFFE; nop.i	0x0; }
	{ nop.m	0x0; mov.i	ar.pfs,r53; mov.spnt	b0,r52,4000000000110C10 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0; }

l4000000000110C30:
	{ adds	r56,0x0,r33; nop.m	0x0; adds	r57,0x0,r37 }
	{ adds	r58,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,fn400000000010FF00; }
	{ cmp4.lt	p07,p06,r8,r0; adds	r1,0x0,r54; (p07) br.cond.dpnt.few	4000000000110F50; }

l4000000000110C60:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r38; (p06) br.cond.dptk.few	4000000000110A60; }

l4000000000110C70:
	{ cmp4.lt	p06,p07,0x1,r41; (p19) ld8	r57,[r37]; adds	r56,0x0,r33; }

l4000000000110C7C:
	{ Invalid; Invalid; Invalid }

l4000000000110C86:
	{ chk.a.nc	r0,3FFFFFFFFF111486; (p29) nop; cmp.lt	p00,p00,r0,r32 }

l4000000000110C90:
	{ nop.m	0x0; (p07) adds	r58,0x0,r0; br.call.sptk.many	b0,fn400000000010FC40; }

l4000000000110C9C:
	{ (p61) nop; invala; break.b	0x1000 }
	{ nop; (p21) nop; (p05) cmp.eq.unc	p00,p08,r8,r4 }

l4000000000110CB0:
	{ adds	r40,0x1,r40; ld4	r41,[r34]; adds	r39,0x10,r39; }
	{ cmp4.lt	p06,p07,r40,r41; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000110850; }

l4000000000110CD0:
	{ ld8	r19,[r43]; nop.i	0x0; br.cond.sptk.few	4000000000110980 }

l4000000000110CE0:
	{ nop.m	0x0; addl	r33,-1,r0; br.cond.sptk.few	4000000000110A10; }

l4000000000110CF0:
	{ adds	r56,0x0,r35; sxt4	r33,r33; br.call.sptk.many	b0,all_digits; }
	{ cmp4.eq	p06,p07,0x0,r8; nop.m	0x0; adds	r1,0x0,r54 }
	{ adds	r56,0x0,r35; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000110F00; }

l4000000000110D20:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,string_to_rlimtype; }
	{ nop.m	0x0; dep.z	r14,0x21,5,59; adds	r1,0x0,r54 }
	{ adds	r44,0x0,r8; add	r14,r46,r14; addl	r38,-5940,r1; }
	{ adds	r14,0x8,r14; ld8	r38,[r38]; nop.i	0x0; }
	{ nop.m	0x0; ld4	r57,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFE,r57; (p06) br.cond.dpnt.few	4000000000110E30; }

l4000000000110D80:
	{ nop.m	0x0; sxt4	r57,r57; nop.i	0x0; }

l4000000000110D90:
	{ setf.sig	f6,r57; setf.sig	f7,r44; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; xma.l	f6,f6,f7,f0; }
	{ nop.m	0x0; getf.sig	r41,f6; nop.i	0x0; }
	{ getf.sig	r56,f6; nop.i	0x0; br.call.sptk.many	b0,fn4000000000137B00; }
	{ adds	r1,0x0,r54; cmp.eq	p06,p07,r8,r44; (p06) br.cond.dptk.few	4000000000110AF0; }

l4000000000110DE0:
	{ addl	r57,-6052,r1; addl	r58,5,r0; adds	r56,0x0,r0; }
	{ ld8	r57,[r57]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r54; nop.m	0x0; adds	r57,0x0,r8 }
	{ adds	r56,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,sh_erange; }
	{ adds	r1,0x0,r54; addl	r8,1,r0; br.cond.sptk.few	4000000000110C00 }

l4000000000110E30:
	{ ld4	r57,[r50]; cmp4.eq	p06,p07,0x0,r57; nop.i	0x0; }
	{ nop.m	0x0; (p06) addl	r57,1024,r0; nop.i	0x0; }

l4000000000110E4C:
	{ Invalid; nop; zxt4	r0,r1 }

l4000000000110E5C:
	{ (p58) nop; Invalid; break.i	0x1000 }

l4000000000110E60:
	{ addl	r57,-6068,r1; nop.m	0x0; adds	r56,0x0,r35; }
	{ ld8	r57,[r57]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r54; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	4000000000110CF0; }

l4000000000110E90:
	{ addl	r38,-5940,r1; ld8	r41,[r36]; sxt4	r33,r33; }
	{ ld8	r38,[r38]; nop.i	0x0; br.cond.sptk.few	4000000000110AF0 }

l4000000000110EB0:
	{ addl	r57,-6060,r1; nop.m	0x0; adds	r56,0x0,r35; }
	{ ld8	r57,[r57]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r54; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	4000000000110CF0; }

l4000000000110EE0:
	{ addl	r38,-5940,r1; ld8	r41,[r37]; sxt4	r33,r33; }
	{ ld8	r38,[r38]; nop.i	0x0; br.cond.sptk.few	4000000000110AF0 }

l4000000000110F00:
	{ adds	r56,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,sh_invalidnum; }
	{ adds	r1,0x0,r54; addl	r8,1,r0; br.cond.sptk.few	4000000000110C00 }

l4000000000110F20:
	{ adds	r57,0x0,r37; nop.m	0x0; adds	r58,0x0,r36 }
	{ adds	r56,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,fn400000000010FF00; }
	{ adds	r1,0x0,r54; cmp4.lt	p06,p07,r8,r0; (p07) br.cond.dptk.few	4000000000110C70; }

l4000000000110F50:
	{ addl	r57,-6084,r1; addl	r58,5,r0; adds	r56,0x0,r0; }
	{ ld8	r57,[r57]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r54; sxt4	r14,r33; adds	r34,0x0,r8; }
	{ addl	r15,-5940,r1; nop.m	0x0; dep.z	r14,r14,5,59; }
	{ nop.m	0x0; ld8	r15,[r15]; nop.i	0x0; }
	{ add	r14,r15,r14; nop.i	0x0; adds	r14,0x10,r14; }
	{ ld8	r33,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ nop.m	0x0; adds	r1,0x0,r54; nop.i	0x0 }
	{ ld4	r56,[r8]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B4A0; }
	{ adds	r1,0x0,r54; adds	r58,0x0,r8; nop.i	0x0 }
	{ adds	r56,0x0,r34; adds	r57,0x0,r33; br.call.sptk.many	b0,builtin_error; }
	{ adds	r1,0x0,r54; addl	r8,1,r0; br.cond.sptk.few	4000000000110C00 }

l4000000000111010:
	{ adds	r56,0x0,r35; adds	r57,0x10,r12; br.call.sptk.many	b0,fn400000000001AD40; }
	{ adds	r1,0x0,r54; cmp4.lt	p06,p07,r8,r0; (p06) br.cond.dpnt.few	40000000001110B0; }

l4000000000111030:
	{ nop.m	0x0; ld4	r14,[r48]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000111060; }

l4000000000111050:
	{ nop.m	0x0; cmp.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r41; (p07) br.cond.dpnt.few	4000000000111160 }

l4000000000111060:
	{ adds	r14,0x0,r47; nop.m	0x0; nop.i	0x0; }

l4000000000111070:
	{ cmp4.eq	p06,p07,0x0,r14; nop.m	0x0; (p23) adds	r15,0x10,r12 }

l4000000000111080:
	{ adds	r56,0x0,r35; adds	r57,0x10,r12; nop.i	0x0 }
	{ (p07) st8	[r41],r51; (p23) st8	[r41],r15; br.call.sptk.many	b0,fn400000000001B300; }

l4000000000111096:
	{ mf.a; (p16) nop; }

l400000000011109C:
	{ (p19) nop; cmp.eq.unc	p00,p16,r13,r64; nop }
	{ Invalid; break.i	0x1000; break.b	0x1000 }

l40000000001110B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ adds	r1,0x0,r54; nop.m	0x0; adds	r34,0x0,r8 }
	{ addl	r58,5,r0; adds	r56,0x0,r0; addl	r57,-6044,r1; }
	{ ld8	r57,[r57]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ nop.m	0x0; dep.z	r14,0x21,5,59; adds	r1,0x0,r54 }
	{ adds	r35,0x0,r8; ld4	r56,[r34]; nop.b	0x0; }
	{ add	r14,r38,r14; adds	r14,0x10,r14; nop.i	0x0; }
	{ ld8	r33,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B4A0; }
	{ adds	r1,0x0,r54; adds	r56,0x0,r35; nop.i	0x0 }
	{ adds	r57,0x0,r33; adds	r58,0x0,r8; br.call.sptk.many	b0,builtin_error; }
	{ nop.m	0x0; adds	r1,0x0,r54; br.cond.sptk.few	4000000000110BE0 }

l4000000000111160:
	{ nop.m	0x0; (p20) addl	r14,1,r0; (p20) br.cond.dptk.few	4000000000111070; }

l400000000011116C:
	{ (p56) nop; (p02) cmp.eq	p04,p16,r3,r64; (p01) rfi }

l4000000000111170:
	{ adds	r16,0x10,r12; ld8	r15,[r51]; nop.i	0x0 }
	{ adds	r14,0x0,r0; adds	r56,0x0,r35; adds	r57,0x10,r12; }
	{ nop.m	0x0; ld8	r41,[r16]; nop.i	0x0; }
	{ cmp.ltu	p07,p06,r15,r41; (p06) adds	r41,0x0,r15; (p23) adds	r15,0x10,r12; }

l40000000001111AC:
	{ (p08) nop; (p53) cmp.lt	p31,p19,r127,r127; czx1.r	r64,r97; }

l40000000001111B0:
	{ (p07) addl	r41,-1,r0; cmp4.eq	p06,p07,0x0,r14; nop.i	0x0 }

l40000000001111B6:
	{ Invalid; nop; (p01) cmp.eq.or	p32,p38,r106,r12 }

l40000000001111C6:
	{ mf.a; (p16) nop; }

l40000000001111CC:
	{ (p10) nop; cmp.eq.unc	p00,p16,r13,r64; mov	pr,r64,0xC204 }
	{ Invalid; break.i	0x1000; break.i	0x1000 }

l40000000001111E0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000001110B0; }
40000000001111F0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; fn4000000000111200: 4000000000111200
;;   Called from:
;;     4000000000111BCC (in umask_builtin)
;;     4000000000111D0C (in umask_builtin)
fn4000000000111200 proc
	{ alloc	r34,ar.pfs,0x9,0x0,0x4; adds	r12,0xFFFFFFFFFFFFFFF0,r12; tbit.z	p07,p06,r32,0x8 }
	{ addl	r37,-8996,r1; nop.m	0x0; adds	r35,0x0,r1; }
	{ (p07) addl	r15,114,r0; (p07) adds	r38,0x18,r12; nop.b	0x0 }

l4000000000111226:
	{ Invalid; cmp4.lt	p00,p16,r0,r0; (p33) nop; }

l400000000011122C:
	{ cmp4.eq.and	p00,p33,r0,r16; (p17) nop; (p04) add	r0,r32,r12 }

l4000000000111236:
	{ (p16) break.m	0xC4000; (p18) nop; Invalid }

l4000000000111246:
	{ Invalid; addl	r0,18432,r0; (p33) nop; }

l400000000011124C:
	{ cmp4.eq.and	p00,p09,r0,r16; (p01) nop; (p04) cmp.eq	p32,p08,r9,r6 }

l4000000000111256:
	{ Invalid; Invalid; Invalid }
	{ (p07) chk.a.nc	f0,3FFFFFFFFF11C346; (p08) nop; Invalid; }

l4000000000111270:
	{ nop.m	0x0; (p07) adds	r14,0x1,r14; nop.b	0x0; }

l400000000011127C:
	{ cmp4.eq.or.andcm	p00,p43,r0,r16; (p33) mov	pr,r3,0x80D2; cmp.eq.unc	p36,p08,r3,r96 }

l4000000000111286:
	{ Invalid; Invalid; cmp.lt	p00,p00,r0,r32; }

l400000000011128C:
	{ (p06) break.m	0xA0320; cmp4.eq.or.andcm	p00,p32,r32,r0; (p01) mov	pr,r67,0x80 }
	{ (p60) cmp4.eq.and	p00,p43,r0,r72; (p17) cmp4.ne.or.andcm	p00,p48,r3,r64; (p33) cmp.lt.unc	p41,p16,r3,r0 }

l40000000001112A0:
	{ (p07) adds	r14,0x1,r14; (p07) add	r15,r38,r15; sxt4	r14,r14; }

l40000000001112A6:
	{ Invalid; (p07) cmp4.lt	p00,p00,r14,r22; (p01) br.call.spnt.few	b0,b4; }

l40000000001112AC:
	{ Invalid; cmp.eq.unc	p36,p08,r3,r96; (p32) cmp.lt	p02,p10,r72,r1; }

l40000000001112B6:
	{ (p03) mov.m	KR6,0x20; (p07) cmp.eq.or	p38,p00,r14,r0; (p49) nop.b	0xE43 }

l40000000001112C6:
	{ addp4	r0,0xFFFFFFFFFFFFE000,r1; (p19) nop; nop }

l40000000001112D0:
	{ st1	[r0],r14; nop.m	0x0; (p07) addl	r14,1,r0; }

l40000000001112E0:
	{ (p07) st1	[r15],r39; (p06) adds	r39,0x14,r12; nop.b	0x0 }

l40000000001112E6:
	{ Invalid; adds	r0,0x800,r0; (p33) nop.b	0x3; }

l40000000001112EC:
	{ cmp4.eq.and	p00,p02,r0,r16; (p01) cmp.eq	p00,p16,r0,r64; cmp4.eq.or.andcm	p02,p42,r72,r1 }

l40000000001112F6:
	{ (p03) addp4	r8,0xFFFFFFFFFFFFF420,r6; (p07) cmp4.ltu	p00,p00,r14,r22; (p01) nop.b	0xEE4 }

l4000000000111306:
	{ chk.a.nc	f0,3FFFFFFFFF111B06; (p07) cmp4.eq.or	p01,p02,0xE,r0; (p49) cmp.eq.unc	p35,p00,r105,r3 }

l4000000000111310:
	{ (p07) add	r15,r39,r15; (p07) st1	[r16],r15; tbit.z	p07,p06,r32,0x3; }

l4000000000111316:
	{ Invalid; Invalid; cmp.lt	p00,p00,r0,r32; }

l400000000011131C:
	{ (p03) break.m	0xA0320; cmp4.eq.or.andcm	p00,p32,r32,r0; (p01) mov	pr,r67,0x80 }
	{ (p60) cmp4.eq.and	p00,p43,r0,r72; (p17) cmp4.ne.or.andcm	p00,p48,r3,r64; (p49) cmp.lt.unc	p41,p16,r3,r0 }

l4000000000111330:
	{ (p07) adds	r14,0x1,r14; (p07) add	r15,r39,r15; sxt4	r14,r14; }

l4000000000111336:
	{ Invalid; (p07) cmp4.lt	p00,p00,r14,r22; (p01) br.call.spnt.few	b0,b4; }

l400000000011133C:
	{ Invalid; cmp.eq.unc	p36,p08,r3,r96; cmp.lt	p01,p10,r72,r1; }

l4000000000111346:
	{ (p03) mov.m	KR6,0x20; (p07) cmp.eq.or	p39,p00,r14,r0; (p01) nop.b	0xC204 }

l4000000000111356:
	{ addp4	r0,0xFFFFFFFFFFFFE000,r1; (p07) nop; nop }

l4000000000111360:
	{ st1	[r0],r14; nop.m	0x0; (p07) addl	r14,1,r0; }

l4000000000111370:
	{ (p07) st1	[r15],r16; (p06) adds	r14,0x0,r0; tbit.z	p07,p06,r32,0x1; }

l4000000000111376:
	{ Invalid; Invalid; cmp.lt	p00,p00,r0,r32; }

l400000000011137C:
	{ (p01) break.m	0xA0320; cmp4.eq.or.andcm	p00,p32,r32,r0; (p01) mov	pr,r67,0x80 }
	{ (p08) cmp4.eq.and	p12,p43,r0,r66; (p17) cmp4.ne.or.andcm	p00,p48,r3,r64; (p01) mov	pr,r3,0x80C8 }

l4000000000111390:
	{ (p07) adds	r14,0x1,r14; (p07) add	r15,r16,r15; (p07) addl	r16,119,r0; }

l4000000000111396:
	{ (p07) chk.a.clr	f16,3FFFFFFFFF111486; (p08) cmp.ne.and	p55,p08,0x0,r0; (p01) br.call.spnt.few	b0,b4; }

l400000000011139C:
	{ Invalid; Invalid; Invalid }

l40000000001113A0:
	{ (p07) st1	[r16],r15; tbit.z	p07,p06,r32,0x0; sxt4	r15,r14 }

l40000000001113A6:
	{ (p03) addp4	r0,0xFFFFFFFFFFFFF420,r6; (p07) cmp4.ltu	p00,p00,r14,r22; (p01) nop.b	0xC204 }

l40000000001113B6:
	{ chk.a.nc	f0,3FFFFFFFFF111BB6; (p07) cmp4.eq.or	p01,p02,r14,r0; (p49) cmp.eq	p03,p00,r100,r3 }

l40000000001113C0:
	{ (p07) add	r15,r16,r15; (p07) addl	r16,120,r0; sxt4	r14,r14; }

l40000000001113C6:
	{ Invalid; (p07) cmp4.ltu	p00,p00,r14,r22; (p01) nop; }

l40000000001113CC:
	{ Invalid; Invalid; cmp.eq	p00,p00,r32,r0; }

l40000000001113D6:
	{ add	r0,r0,r1; (p07) nop; (p32) nop }
	{ break.m	0x4000; (p20) nop; nop }
	{ break.m	0x4000; Invalid; (p16) nop }
	{ break.m	0xAA022; nop; break.i	0x80000 }
	{ Invalid; (p34) nop; break.i	0x80000 }
4000000000111420 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000111430 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; parse_symbolic_mode: 4000000000111440
;;   Called from:
;;     4000000000111B6C (in umask_builtin)
parse_symbolic_mode proc
	{ alloc	r45,ar.pfs,0x12,0x0,0xF; mov	r44,b4; adds	r46,0x0,r1; }
	{ addl	r40,448,r0; addl	r42,1,r0; addl	r39,146,r0 }
	{ addl	r38,292,r0; movl	r43,0x280000000000; }
	{ adds	r35,0x0,r0; nop.m	0x0; nop.i	0x0; }

l4000000000111480:
	{ ld1	r48,[r32]; addl	r47,-8988,r1; sxt1	r48,r48 }
	{ nop.m	0x0; ld8	r47,[r47]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r48; (p06) br.cond.dpnt.few	4000000000111550 }

l40000000001114B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,mbschr; }
	{ adds	r1,0x0,r46; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	4000000000111620; }

l40000000001114D0:
	{ ld1	r14,[r32],1; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x67,r14; nop.m	0x0; cmp4.eq	p08,p09,0x61,r14; }
	{ (p06) or	r35,0x38,r35; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000111480; }

l40000000001114F6:
	{ chk.a.nc	r0,3FFFFFFFFF111CF6; nop; break.i	0x80000 }

l4000000000111500:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x67,r14; (p06) br.cond.dptk.few	40000000001115E0 }

l4000000000111510:
	{ ld1	r48,[r32]; addl	r47,-8988,r1; (p08) addl	r35,511,r0; }

l4000000000111520:
	{ nop.m	0x0; sxt1	r48,r48; nop.i	0x0 }
	{ ld8	r47,[r47]; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r48; (p07) br.cond.dptk.few	40000000001114B0 }

l4000000000111550:
	{ adds	r41,0x0,r0; nop.m	0x0; nop.i	0x0 }

l4000000000111560:
	{ addl	r48,-8980,r1; nop.m	0x0; addl	r49,5,r0 }
	{ adds	r47,0x0,r0; nop.m	0x0; addl	r33,-1,r0; }
	{ ld8	r48,[r48]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r46; nop.m	0x0; adds	r47,0x0,r8 }
	{ adds	r48,0x0,r41; nop.m	0x0; br.call.sptk.many	b0,builtin_error; }
	{ adds	r1,0x0,r46; nop.m	0x0; nop.i	0x0 }

l40000000001115C0:
	{ adds	r8,0x0,r33; nop.m	0x0; mov.i	ar.pfs,r45; }
	{ nop.m	0x0; mov.spnt	b0,r44,40000000001115D0; br.ret	b0 }

l40000000001115E0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x6F,r14; nop.i	0x0; }
	{ (p06) or	r35,0x7,r35; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000111480; }

l40000000001115F6:
	{ chk.a.nc	r0,3FFFFFFFFF111DF6; nop; break.i	0x80000 }

l4000000000111600:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x75,r14; nop.i	0x0; }
	{ nop.m	0x0; (p06) or	r35,r40,r35; br.cond.sptk.few	4000000000111480 }

l400000000011161C:
	{ (p51) cmpxchg2.acq.nt1	r127,[r36],r63; (p04) nop; (p20) nop }

l4000000000111620:
	{ adds	r34,0x0,r32; ld1	r37,[r34],1; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r37,r37; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r37; zxt1	r14,r37 }
	{ adds	r41,0x0,r37; nop.m	0x0; shl	r15,r42,r15 }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x3D,r14; (p06) br.cond.dptk.few	4000000000111560; }

l4000000000111670:
	{ and	r15,r43,r15; nop.m	0x0; adds	r36,0x0,r0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r15; (p07) br.cond.dptk.few	4000000000111560; }

l4000000000111690:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000001116A0:
	{ ld1	r48,[r34]; addl	r47,-8972,r1; sxt1	r48,r48 }
	{ nop.m	0x0; ld8	r47,[r47]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r48; (p06) br.cond.dpnt.few	4000000000111780 }

l40000000001116D0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,mbschr; }
	{ adds	r1,0x0,r46; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	4000000000111830; }

l40000000001116F0:
	{ ld1	r14,[r34],1; nop.m	0x0; addl	r47,-8972,r1; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x77,r14; }
	{ (p06) or	r36,r39,r36; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001116A0; }

l4000000000111716:
	{ chk.a.nc	r0,3FFFFFFFFF111F16; nop; break.i	0x80000 }

l4000000000111720:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x78,r14; nop.i	0x0; }
	{ (p06) or	r36,0x49,r36; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001116A0; }

l4000000000111736:
	{ chk.a.nc	r0,3FFFFFFFFF111F36; nop; break.i	0x80000 }

l4000000000111740:
	{ nop.m	0x0; ld1	r48,[r34]; cmp4.eq	p06,p07,0x72,r14 }
	{ nop.m	0x0; ld8	r47,[r47]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r48,r48; (p06) or	r36,r38,r36; }

l4000000000111770:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r48; (p07) br.cond.dptk.few	40000000001116D0 }

l4000000000111780:
	{ addl	r14,1,r0; nop.m	0x0; nop.i	0x0; }

l4000000000111790:
	{ cmp4.eq	p06,p07,0x0,r35; cmp4.eq	p08,p09,0x2D,r37; (p07) and	r36,r35,r36; }

l40000000001117A0:
	{ nop.m	0x0; (p08) andcm	r36,0xFFFFFFFFFFFFFFFF,r36; nop.i	0x0; }

l40000000001117AC:
	{ nop; zxt1	r8,r3; Invalid }

l40000000001117B6:
	{ Invalid; nop; nop }

l40000000001117C0:
	{ cmp4.eq	p08,p09,0x3D,r37; nop.i	0x0; (p08) br.cond.dpnt.few	4000000000111800; }

l40000000001117D0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2B,r37; (p06) br.cond.dpnt.few	4000000000111820; }

l40000000001117E0:
	{ cmp4.eq	p07,p06,0x0,r14; adds	r32,0x1,r34; adds	r35,0x0,r0 }
	{ nop.b	0x0; (p06) br.cond.dpnt.few	40000000001115C0; br.cond.sptk.few	4000000000111480; }

l40000000001117FC:
	{ (p36) nop; nop; (p52) nop }

l4000000000111800:
	{ nop.m	0x0; (p07) andcm	r35,0xFFFFFFFFFFFFFFFF,r35; nop.i	0x0; }

l400000000011180C:
	{ nop; Invalid; nop }

l4000000000111816:
	{ add	r0,r0,r1; (p16) nop; break.i	0x80000 }

l4000000000111820:
	{ nop.m	0x0; or	r33,r36,r33; br.cond.sptk.few	40000000001117E0 }

l4000000000111830:
	{ ld1	r14,[r34]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p08,p09,0x0,r14; cmp4.eq	p06,p07,0x2C,r14; (p08) addl	r15,1,r0; }

l4000000000111850:
	{ nop.m	0x0; (p09) adds	r15,0x0,r0; nop.i	0x0; }

l400000000011185C:
	{ cmp.lt	p00,p16,r1,r0; (p01) cmp.lt.unc	p32,p16,r3,r64; (p08) mov	pr,r99,0xE5C0 }
	{ (p57) nop; Invalid; nop.b	0x1000 }

l4000000000111870:
	{ addl	r48,-8964,r1; nop.m	0x0; addl	r49,5,r0 }
	{ adds	r47,0x0,r0; nop.m	0x0; addl	r33,-1,r0; }
	{ ld8	r48,[r48]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ ld1	r14,[r34]; adds	r1,0x0,r46; adds	r47,0x0,r8; }
	{ nop.m	0x0; sxt1	r48,r14; br.call.sptk.many	b0,builtin_error; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r46; mov.i	ar.pfs,r45; }
	{ nop.m	0x0; mov.spnt	b0,r44,40000000001118D0; br.ret	b0; }
40000000001118E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001118F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; umask_builtin: 4000000000111900
umask_builtin proc
	{ alloc	r39,ar.pfs,0xD,0x0,0xA; adds	r40,0x0,r1; mov	r41,pr; }
	{ nop.m	0x0; mov	r38,b6; adds	r34,0x0,r0 }
	{ adds	r33,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,reset_internal_getopt; }
	{ adds	r1,0x0,r40; nop.m	0x0; nop.i	0x0; }

l4000000000111940:
	{ addl	r43,-8940,r1; nop.m	0x0; adds	r42,0x0,r32; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r40; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dpnt.few	4000000000111A00; }

l4000000000111970:
	{ cmp4.eq	p06,p07,0x53,r8; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000111B00; }

l4000000000111980:
	{ cmp4.eq	p06,p07,0x70,r8; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001119D0; }

l4000000000111990:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ addl	r8,258,r0; adds	r1,0x0,r40; mov	pr,r41,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r39; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000001119C0; br.ret	b0 }

l40000000001119D0:
	{ addl	r43,-8940,r1; adds	r42,0x0,r32; adds	r34,0x1,r34; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r40; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p06) br.cond.dptk.few	4000000000111970; }

l4000000000111A00:
	{ addl	r14,9268,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ adds	r35,0x8,r14; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	4000000000111C70; }

l4000000000111A30:
	{ ld8	r14,[r35]; ld8	r42,[r14]; nop.i	0x0; }
	{ ld1	r14,[r42]; adds	r14,0xFFFFFFFFFFFFFFD0,r14; nop.i	0x0; }
	{ nop.m	0x0; zxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x9,r14; (p06) br.cond.dptk.few	4000000000111B10 }

l4000000000111A70:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,read_octal; }
	{ adds	r34,0x0,r8; nop.m	0x0; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8 }
	{ adds	r1,0x0,r40; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000111BF0; }

l4000000000111AA0:
	{ adds	r42,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C1E0; }
	{ adds	r1,0x0,r40; cmp4.eq	p06,p07,0x0,r33; (p07) br.cond.dpnt.few	4000000000111BC0 }

l4000000000111AC0:
	{ nop.m	0x0; adds	r42,0x0,r0; br.call.sptk.many	b0,sh_chkwrite; }
	{ adds	r1,0x0,r40; nop.m	0x0; nop.i	0x0 }

l4000000000111AE0:
	{ nop.m	0x0; mov	pr,r41,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,4000000000111AF0; br.ret	b0 }

l4000000000111B00:
	{ nop.m	0x0; adds	r33,0x1,r33; br.cond.sptk.few	4000000000111940; }

l4000000000111B10:
	{ addl	r42,18,r0; addl	r37,511,r0; br.call.sptk.many	b0,fn400000000001C1E0; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r42,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C1E0; }
	{ ld8	r14,[r35]; andcm	r43,0xFFFFFFFFFFFFFFFF,r36; adds	r1,0x0,r40; }
	{ nop.m	0x0; and	r43,r37,r43; nop.i	0x0; }
	{ ld8	r42,[r14]; nop.i	0x0; br.call.sptk.many	b0,parse_symbolic_mode; }
	{ cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r8; nop.m	0x0; andcm	r8,0xFFFFFFFFFFFFFFFF,r8 }
	{ adds	r1,0x0,r40; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000111D50; }

l4000000000111B90:
	{ nop.m	0x0; and	r34,r37,r8; nop.i	0x0; }
	{ adds	r42,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C1E0; }
	{ adds	r1,0x0,r40; cmp4.eq	p06,p07,0x0,r33; (p06) br.cond.dptk.few	4000000000111AC0 }

l4000000000111BC0:
	{ adds	r42,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn4000000000111200; }
	{ adds	r1,0x0,r40; adds	r42,0x0,r0; br.call.sptk.many	b0,sh_chkwrite; }
	{ nop.m	0x0; adds	r1,0x0,r40; br.cond.sptk.few	4000000000111AE0; }

l4000000000111BF0:
	{ ld8	r14,[r35]; addl	r43,-8932,r1; addl	r44,5,r0 }
	{ adds	r42,0x0,r0; ld8	r43,[r43]; nop.i	0x0; }
	{ ld8	r33,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r43,0x0,r8 }
	{ adds	r42,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,sh_erange; }
	{ addl	r8,1,r0; adds	r1,0x0,r40; mov	pr,r41,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r39; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r38,4000000000111C60; br.ret	b0; }

l4000000000111C70:
	{ addl	r42,18,r0; cmp4.eq	p16,p17,0x0,r33; br.call.sptk.many	b0,fn400000000001C1E0; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r42,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C1E0; }
	{ adds	r1,0x0,r40; cmp4.eq	p06,p07,0x0,r34; (p06) br.cond.dptk.few	4000000000111D00; }

l4000000000111CB0:
	{ addl	r43,-8924,r1; (p17) addl	r44,-8956,r1; addl	r42,1,r0; }

l4000000000111CBC:
	{ Invalid; Invalid; Invalid }

l4000000000111CC6:
	{ (p21) fwb; dep	r0,r0,r1,47,1; (p04) br.call.sptk.few	b3,b0 }

l4000000000111CD6:
	{ break.m	0x4000; nop; (p04) nop }

l4000000000111CE6:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; nop; (p36) nop }

l4000000000111D00:
	{ (p17) adds	r42,0x0,r35; nop.i	0x0; (p17) br.call.dptk.many	b0,fn4000000000111200; }

l4000000000111D06:
	{ nop; (p32) nop; (p52) nop }

l4000000000111D10:
	{ (p16) addl	r43,-8916,r1; (p16) addl	r42,1,r0; (p16) addp4	r44,r35,r0; }

l4000000000111D16:
	{ (p21) nop; (p52) nop }

l4000000000111D1C:
	{ Invalid; Invalid; Invalid }

l4000000000111D20:
	{ (p16) ld8	r43,[r43]; nop.i	0x0; (p16) br.call.dptk.many	b0,fn400000000001BB80; }

l4000000000111D26:
	{ nop; (p32) nop; (p16) nop }

l4000000000111D30:
	{ adds	r1,0x0,r40; adds	r42,0x0,r0; br.call.sptk.many	b0,sh_chkwrite; }
	{ nop.m	0x0; adds	r1,0x0,r40; br.cond.sptk.few	4000000000111AE0 }

l4000000000111D50:
	{ addl	r8,1,r0; mov	pr,r41,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,4000000000111D60; br.ret	b0; }
4000000000111D70 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; wait_builtin: 4000000000111D80
wait_builtin proc
	{ alloc	r40,ar.pfs,0xC,0x0,0x9; adds	r16,0x8,r12; nop.b	0x0 }
	{ adds	r12,0xFFFFFFFFFFFFFED0,r12; mov	r39,b7; adds	r41,0x0,r32; }
	{ st8.spill	[r1],r16; nop.i	0x0; br.call.sptk.many	b0,no_options; }
	{ adds	r1,0x138,r12; addl	r14,258,r0; cmp4.eq	p07,p06,0x0,r8; }
	{ ld8	r1,[r1]; adds	r8,0x0,r14; (p07) br.cond.dpnt.few	4000000000111DF0; }

l4000000000111DD0:
	{ nop.m	0x0; mov.i	ar.pfs,r40; mov.spnt	b0,r39,4000000000111DD0 }
	{ nop.m	0x0; adds	r12,0x130,r12; br.ret	b0; }

l4000000000111DF0:
	{ addl	r14,7672,r1; addl	r16,9268,r1; nop.i	0x0 }
	{ adds	r17,0x120,r12; addl	r41,25956,r1; addl	r42,1,r0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r14]; nop.i	0x0 }
	{ ld8	r16,[r16]; st8	[r16],r17; adds	r16,0x1,r15 }
	{ adds	r17,0x118,r12; st4.rel	[r15],r17; nop.i	0x0 }
	{ st4	[r16],r14; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BD60; }
	{ adds	r1,0x138,r12; adds	r14,0x120,r12; cmp4.eq	p06,p07,0x0,r8 }
	{ addl	r35,1,r0; adds	r34,0x110,r12; addl	r36,127,r0; }
	{ ld8	r1,[r1]; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000112360; }

l4000000000111E90:
	{ nop.m	0x0; addl	r37,-20676,r1; addl	r38,7444,r1 }
	{ ld8	r14,[r14]; nop.m	0x0; cmp.eq	p07,p06,0x0,r14 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	40000000001123C0; }

l4000000000111EC0:
	{ adds	r37,0x1C,r37; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000111EE0:
	{ adds	r15,0x120,r12; ld8	r15,[r15]; nop.i	0x0; }
	{ adds	r14,0x8,r15; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r33,[r14]; adds	r41,0x0,r33; nop.i	0x0; }
	{ ld1	r14,[r33]; nop.m	0x0; sxt1	r14,r14; }
	{ adds	r15,0xFFFFFFFFFFFFFFD0,r14; nop.m	0x0; zxt1	r15,r15; }
	{ cmp4.ltu	p06,p07,0x9,r15; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000112010; }

l4000000000111F40:
	{ cmp4.eq	p07,p06,0x25,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000001120C0; }

l4000000000111F50:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_badpid; }
	{ adds	r15,0x120,r12; adds	r1,0x138,r12; adds	r14,0x0,r35; }
	{ ld8	r15,[r15]; ld8	r1,[r1]; nop.i	0x0; }
	{ ld8	r16,[r15]; adds	r15,0x120,r12; nop.i	0x0; }
	{ st8	[r16],r15; nop.m	0x0; nop.i	0x0 }

l4000000000111FA0:
	{ adds	r17,0x120,r12; ld8	r17,[r17]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r17; (p06) br.cond.dptk.few	4000000000111EE0 }

l4000000000111FC0:
	{ adds	r15,0x118,r12; ld4.acq	r16,[r15]; addl	r15,7672,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r16],r15; nop.m	0x0; nop.i	0x0 }

l4000000000111FF0:
	{ adds	r8,0x0,r14; mov.i	ar.pfs,r40; mov.spnt	b0,r39,4000000000111FF0 }
	{ nop.m	0x0; adds	r12,0x130,r12; br.ret	b0; }

l4000000000112010:
	{ adds	r42,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,legal_number; }
	{ adds	r1,0x138,r12; nop.m	0x0; cmp4.eq	p06,p07,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000112410; }

l4000000000112040:
	{ nop.m	0x0; ld8	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r15,r14; adds	r41,0x0,r14; }
	{ cmp.eq	p07,p06,r15,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000112410; }

l4000000000112070:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,wait_for_single_pid; }
	{ adds	r15,0x120,r12; adds	r1,0x138,r12; adds	r14,0x0,r8; }
	{ ld8	r15,[r15]; ld8	r1,[r1]; nop.i	0x0; }
	{ ld8	r16,[r15]; nop.m	0x0; adds	r15,0x120,r12; }
	{ st8	[r16],r15; nop.i	0x0; br.cond.sptk.few	4000000000111FA0 }

l40000000001120C0:
	{ adds	r41,0x90,r12; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x138,r12; addl	r42,17,r0; adds	r41,0x90,r12; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B400; }
	{ adds	r1,0x138,r12; nop.m	0x0; adds	r41,0x10,r12; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x138,r12; nop.m	0x0; adds	r42,0x90,r12 }
	{ adds	r43,0x10,r12; nop.m	0x0; adds	r41,0x0,r0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r14,0x120,r12; adds	r1,0x138,r12; nop.i	0x0 }
	{ ld8	r1,[r1]; ld8	r41,[r14]; br.call.sptk.many	b0,get_job_spec; }
	{ adds	r1,0x138,r12; nop.m	0x0; cmp4.lt	p06,p07,r8,r0 }
	{ adds	r33,0x0,r8; nop.m	0x0; sxt4	r15,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000112260; }

l4000000000112190:
	{ nop.m	0x0; ld4	r14,[r37]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r8,r14; (p06) br.cond.dptk.few	4000000000112280 }

l40000000001121B0:
	{ ld8	r14,[r38]; nop.m	0x0; adds	r42,0x10,r12 }
	{ adds	r43,0x0,r0; addl	r41,2,r0; shladd	r15,r15,0x3,r14; }
	{ nop.m	0x0; ld8	r14,[r15]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000112280; }

l40000000001121F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x138,r12; nop.m	0x0; adds	r41,0x0,r33; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,wait_for_job; }
	{ adds	r15,0x120,r12; adds	r1,0x138,r12; adds	r14,0x0,r8; }
	{ ld8	r15,[r15]; ld8	r1,[r1]; nop.i	0x0; }
	{ ld8	r16,[r15]; nop.m	0x0; adds	r15,0x120,r12; }
	{ st8	[r16],r15; nop.i	0x0; br.cond.sptk.few	4000000000111FA0 }

l4000000000112260:
	{ nop.m	0x0; cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFE,r8; (p06) br.cond.sptk.few	40000000001122D0; }

l4000000000112270:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000112280:
	{ adds	r15,0x120,r12; ld8	r15,[r15]; nop.i	0x0; }
	{ adds	r14,0x8,r15; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r41,[r14]; nop.i	0x0; br.call.sptk.many	b0,sh_badjob; }
	{ nop.m	0x0; adds	r1,0x138,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0 }

l40000000001122D0:
	{ addl	r41,2,r0; nop.m	0x0; adds	r42,0x10,r12 }
	{ adds	r43,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r16,0x120,r12; adds	r1,0x138,r12; adds	r14,0x0,r36; }
	{ ld8	r16,[r16]; ld8	r1,[r1]; nop.i	0x0; }
	{ ld8	r17,[r16]; nop.m	0x0; adds	r16,0x120,r12; }
	{ st8	[r17],r16; nop.m	0x0; adds	r17,0x120,r12; }
	{ nop.m	0x0; ld8	r17,[r17]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r17; (p06) br.cond.dptk.few	4000000000111EE0 }

l4000000000112350:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000111FC0 }

l4000000000112360:
	{ addl	r14,9132,r1; nop.m	0x0; adds	r15,0x118,r12; }
	{ nop.m	0x0; ld4.acq	r16,[r15]; addl	r15,7672,r1; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ adds	r14,0x80,r14; st4	[r16],r15; nop.i	0x0; }
	{ adds	r8,0x0,r14; mov.i	ar.pfs,r40; mov.spnt	b0,r39,40000000001123A0 }
	{ nop.m	0x0; adds	r12,0x130,r12; br.ret	b0; }

l40000000001123C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,wait_for_background_pids; }
	{ adds	r1,0x138,r12; adds	r15,0x118,r12; adds	r14,0x0,r0; }
	{ ld8	r1,[r1]; ld4.acq	r16,[r15]; nop.i	0x0; }
	{ addl	r15,7672,r1; nop.m	0x0; nop.i	0x0; }
	{ st4	[r16],r15; nop.i	0x0; br.cond.sptk.few	4000000000111FF0 }

l4000000000112410:
	{ adds	r41,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,sh_badpid; }
	{ adds	r1,0x138,r12; adds	r15,0x118,r12; addl	r14,1,r0; }
	{ ld8	r1,[r1]; ld4.acq	r16,[r15]; nop.i	0x0; }
	{ addl	r15,7672,r1; nop.m	0x0; nop.i	0x0; }
	{ st4	[r16],r15; nop.i	0x0; br.cond.sptk.few	4000000000111FF0; }
4000000000112460 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
4000000000112470 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; fn4000000000112480: 4000000000112480
;;   Called from:
;;     400000000011291C (in getopts_builtin)
;;     4000000000112CEC (in getopts_builtin)
;;     4000000000112D9C (in getopts_builtin)
;;     4000000000112E0C (in getopts_builtin)
;;     4000000000112EFC (in getopts_builtin)
fn4000000000112480 proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; adds	r36,0x0,r1; mov	r34,b2 }
	{ nop.m	0x0; adds	r37,0x0,r32; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,legal_identifier; }
	{ adds	r37,0x0,r32; adds	r38,0x0,r33; adds	r39,0x0,r0 }
	{ adds	r1,0x0,r36; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	4000000000112530 }

l40000000001124D0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r14,0x28,r8; cmp.eq	p06,p07,0x0,r8; nop.i	0x0 }
	{ adds	r1,0x0,r36; addl	r15,16386,r0; (p06) br.cond.dpnt.few	4000000000112560; }

l4000000000112500:
	{ ld8	r14,[r14]; addl	r8,2,r0; mov.i	ar.pfs,r35; }
	{ and	r14,r14,r15; nop.m	0x0; mov.spnt	b0,r34,4000000000112510; }
	{ cmp.eq	p09,p08,0x0,r14; (p09) br.cond.dpnt.few	4000000000112560; br.ret	b0; }

l400000000011252C:
	{ nop; (p04) invala; break.i	0x1000 }

l4000000000112530:
	{ adds	r37,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,sh_invalidid; }
	{ addl	r8,1,r0; adds	r1,0x0,r36; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000112550; br.ret	b0 }

l4000000000112560:
	{ (p06) addl	r8,1,r0; nop.m	0x0; mov.i	ar.pfs,r35; }

l4000000000112566:
	{ break.m	0x4000; cmp4.eq	p35,p00,r64,r42; (p01) nop }

l4000000000112576:
	{ Invalid; (p34) nop; break.i	0x80000 }

;; getopts_reset: 4000000000112580
;;   Called from:
;;     40000000000633FC (in sv_optind)
;;     400000000006C36C (in initialize_shell_variables)
getopts_reset proc
	{ nop.m	0x0; addl	r14,8664,r1; nop.i	0x0; }
	{ nop.m	0x0; st4	[r32],r14; addl	r14,8660,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r0],r14; nop.i	0x0; br.ret	b0; }

;; getopts_builtin: 40000000001125C0
getopts_builtin proc
	{ alloc	r42,ar.pfs,0x11,0x0,0xE; adds	r12,0xFFFFFFFFFFFFFFE0,r12; mov	r44,pr }
	{ cmp.eq	p07,p06,0x0,r32; nop.m	0x0; adds	r43,0x0,r1; }
	{ nop.m	0x0; mov	r41,b1; mov	r45,LC }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	4000000000112630; br.call.sptk.many	b0,reset_internal_getopt; }

l40000000001125FC:
	{ (p04) nop; cmp.lt.unc	p32,p16,r10,r64; Invalid }
	{ (p46) cmp.eq.unc	p61,p17,r108,r79; break.x	0x80C2F00A01000; }
	{ (p53) nop; cmp.eq.unc	p32,p16,r10,r64; (p48) nop }
	{ (p03) nop; zxt4	r0,r0; break.i	0x1000 }

l4000000000112630:
	{ addl	r33,258,r0; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r43; mov	pr,r44,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r42; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r45; mov.spnt	b0,r41,4000000000112660 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0; }

l4000000000112680:
	{ addl	r14,9268,r1; nop.m	0x0; adds	r33,0x20,r12; }
	{ nop.m	0x0; nop.m	0x0; adds	r47,0x0,r33; }
	{ ld8	r46,[r14]; nop.i	0x0; br.call.sptk.many	b0,make_builtin_argv; }
	{ ld4	r14,[r33]; adds	r15,0x8,r8; adds	r1,0x0,r43 }
	{ adds	r35,0x0,r8; adds	r34,0x10,r8; cmp4.lt	p06,p07,0x2,r14 }
	{ adds	r33,0xFFFFFFFFFFFFFFFE,r14; adds	r46,0x0,r34; (p07) br.cond.dpnt.few	4000000000112980; }

l40000000001126E0:
	{ ld8	r36,[r15]; ld8	r38,[r34]; nop.i	0x0; }
	{ nop.m	0x0; ld1	r14,[r36]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x3A,r14; }
	{ (p06) addl	r14,1,r0; (p07) adds	r14,0x0,r0; cmp4.eq	p06,p07,0x1,r33; }

l4000000000112716:
	{ Invalid; (p03) nop; shr	r4,r35,r64; }

l400000000011271C:
	{ Invalid; (p02) cmp.le.and	p00,p60,r0,r68; Invalid }

l400000000011272C:
	{ Invalid; Invalid; Invalid }

l4000000000112730:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ (p17) ld4	r40,[r14]; (p17) st4	[r0],r14; nop.i	0x0 }

l4000000000112746:
	{ mf.a; nop }

l400000000011274C:
	{ rsm	0x200080; mov	pr,r0,0x2000; Invalid }

l400000000011275C:
	{ (p39) nop; nop; Invalid }
	{ cmp.eq	p33,p03,r0,r66; (p06) nop; }
	{ Invalid; cmp.lt	p00,p00,r32,r0; Invalid; }
	{ Invalid; Invalid; break.i	0x1000 }
	{ (p47) nop; invala; nop.b	0x1000 }
	{ nop; break.x	0x8CC224A001000 }
	{ cmp.lt	p00,p08,r1,r0; zxt4	r54,r16; dep	r0,r32,r0,29,1 }

l40000000001127C0:
	{ addl	r14,8664,r1; nop.m	0x0; (p17) addl	r18,6340,r1 }

l40000000001127D0:
	{ adds	r17,0x1E,r12; nop.m	0x0; addl	r16,15,r0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4	r15,[r14]; movl	r14,0x26666666666667 }
	{ (p17) st4	[r40],r18; setf.sig	f6,r14; adds	r14,0x30,r15 }

l4000000000112806:
	{ (p03) srlz.i; (p07) nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r9,3FFFFFFFFF9D6106; nop; (p48) nop }

l4000000000112820:
	{ adds	r15,0x1E,r12; nop.m	0x0; addl	r47,14,r0; }
	{ st1	[r14],r15; adds	r14,0x1F,r12; nop.i	0x0; }
	{ st1	[r0],r14; nop.m	0x0; nop.i	0x0 }

l4000000000112850:
	{ addl	r46,-2460,r1; adds	r14,0x10,r12; adds	r48,0x0,r0; }
	{ nop.m	0x0; add	r47,r14,r47; nop.i	0x0 }
	{ ld8	r46,[r46]; nop.m	0x0; br.call.sptk.many	b0,bind_variable; }
	{ cmp4.eq	p07,p06,0x3F,r33; adds	r1,0x0,r43; (p07) br.cond.dpnt.few	4000000000112C70; }

l4000000000112890:
	{ cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r33; addl	r14,8668,r1; (p07) br.cond.dpnt.few	4000000000112EC0; }

l40000000001128A0:
	{ cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFE,r33; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000112DF0; }

l40000000001128B0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFD,r33; (p07) br.cond.dpnt.few	4000000000112CC0; }

l40000000001128C0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }

l40000000001128D0:
	{ addl	r46,-2452,r1; ld8	r47,[r14]; adds	r48,0x0,r0; }
	{ ld8	r46,[r46]; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r47,0x24,r12; nop.m	0x0; adds	r14,0x25,r12 }
	{ adds	r1,0x0,r43; adds	r46,0x0,r38; nop.i	0x0 }
	{ st1	[r33],r47; st1	[r0],r14; br.call.sptk.many	b0,fn4000000000112480; }
	{ adds	r1,0x0,r43; nop.m	0x0; adds	r33,0x0,r8 }
	{ adds	r46,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r43; nop.m	0x0; nop.i	0x0 }

l4000000000112950:
	{ adds	r8,0x0,r33; mov	pr,r44,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r42; }
	{ nop.m	0x0; mov.i	LC,r45; mov.spnt	b0,r41,4000000000112960 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0; }

l4000000000112980:
	{ addl	r33,258,r0; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ adds	r1,0x0,r43; adds	r46,0x0,r35; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r43; br.cond.sptk.few	4000000000112950; }

l40000000001129B0:
	{ addl	r39,7132,r1; addl	r34,23444,r1; nop.b	0x0 }
	{ adds	r46,0x0,r0; nop.m	0x0; mov.i	LC,0x9; }
	{ nop.m	0x0; ld8	r15,[r39]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r15; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000112F20; }

l40000000001129F0:
	{ nop.m	0x0; nop.i	0x0; adds	r16,0x0,r34; }

l4000000000112A00:
	{ nop.m	0x0; ld8	r17,[r16],8; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r17; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000112A40; }

l4000000000112A20:
	{ nop.m	0x0; adds	r46,0x1,r46; br.cloop.sptk.few	4000000000112A00; }

l4000000000112A30:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000112A40:
	{ ld8	r15,[r15]; nop.m	0x0; adds	r46,0x1,r46; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	4000000000112A40 }

l4000000000112A60:
	{ adds	r46,0x1,r46; adds	r33,0x0,r0; br.call.sptk.many	b0,strvec_create; }
	{ nop.m	0x0; adds	r1,0x0,r43; nop.b	0x0 }
	{ adds	r37,0x0,r8; adds	r15,0x0,r8; mov.i	LC,0x9; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000112AA0:
	{ nop.m	0x0; ld8	r14,[r34],8; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000112E80; }

l4000000000112AC0:
	{ st8	[r15],r8,8; adds	r33,0x1,r33; br.cloop.sptk.few	4000000000112AA0; }

l4000000000112AD0:
	{ nop.m	0x0; sxt4	r15,r33; nop.b	0x0 }
	{ ld8	r14,[r39]; nop.m	0x0; addl	r16,80,r0; }
	{ shladd	r15,r15,0x3,r37; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	4000000000112B50; }

l4000000000112B00:
	{ adds	r16,0x8,r14; nop.m	0x0; adds	r33,0x1,r33; }
	{ ld8	r16,[r16]; ld8	r16,[r16]; nop.i	0x0; }
	{ st8	[r15],r8,8; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000112B00 }

l4000000000112B40:
	{ nop.m	0x0; sxt4	r16,r33; shladd	r16,r16,0x3,r0; }

l4000000000112B50:
	{ add	r16,r37,r16; nop.m	0x0; adds	r46,0x0,r37; }
	{ st8	[r0],r16; nop.i	0x0; br.call.sptk.many	b0,sh_getopt_restore_state; }
	{ adds	r1,0x0,r43; adds	r46,0x0,r33; nop.i	0x0 }
	{ adds	r47,0x0,r37; adds	r48,0x0,r36; br.call.sptk.many	b0,sh_getopt; }
	{ adds	r1,0x0,r43; nop.m	0x0; adds	r33,0x0,r8 }
	{ adds	r46,0x0,r37; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r43; br.cond.sptk.few	40000000001127C0 }

l4000000000112BC0:
	{ nop.m	0x0; adds	r14,0x1F,r12; nop.i	0x0; }
	{ st1	[r0],r14; nop.m	0x0; nop.i	0x0; }

l4000000000112BE0:
	{ nop.m	0x0; sxt4	r14,r15; adds	r16,0xFFFFFFFFFFFFFFFF,r16; }
	{ setf.sig	f7,r14; nop.m	0x0; extr.u	r18,r14,63,1; }
	{ nop.m	0x0; nop.m	0x0; xma.h	f7,f7,f6,f0; }
	{ getf.sig	r15,f7; nop.m	0x0; extr	r15,r15,2,62; }
	{ sub	r15,r15,r18; shladd	r18,r15,0x2,r15; cmp4.eq	p07,p06,0x0,r15; }
	{ shladd	r18,r18,0x1,r0; sub	r14,r14,r18; nop.i	0x0; }
	{ nop.m	0x0; adds	r14,0x30,r14; nop.i	0x0; }
	{ st1	[r17],r127,-1; nop.i	0x0; (p06) br.cond.dptk.few	4000000000112BE0 }

l4000000000112C60:
	{ nop.m	0x0; sxt4	r47,r16; br.cond.sptk.few	4000000000112850 }

l4000000000112C70:
	{ addl	r14,8668,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld8	r15,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r15; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000112DF0; }

l4000000000112CA0:
	{ ld1	r15,[r15]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p07) br.cond.dptk.few	40000000001128D0 }

l4000000000112CC0:
	{ nop.m	0x0; adds	r46,0x0,r38; (p16) br.cond.dptk.few	4000000000112D80 }

l4000000000112CD0:
	{ nop.m	0x0; addl	r47,-2436,r1; nop.i	0x0; }
	{ ld8	r47,[r47]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000112480; }
	{ adds	r1,0x0,r43; adds	r14,0x24,r12; adds	r16,0x25,r12 }
	{ adds	r33,0x0,r8; adds	r48,0x0,r0; addl	r15,6336,r1 }
	{ addl	r46,-2452,r1; st1	[r0],r16; adds	r47,0x0,r14; }
	{ nop.m	0x0; ld8	r46,[r46]; nop.i	0x0; }
	{ ld4	r15,[r15]; nop.i	0x0; nop.i	0x0 }
	{ st1	[r15],r14; nop.m	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r1,0x0,r43; nop.m	0x0; nop.i	0x0 }

l4000000000112D60:
	{ adds	r46,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r43; br.cond.sptk.few	4000000000112950; }

l4000000000112D80:
	{ nop.m	0x0; addl	r47,-2444,r1; nop.i	0x0; }
	{ ld8	r47,[r47]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000112480; }
	{ nop.m	0x0; adds	r1,0x0,r43; adds	r33,0x0,r8; }

l4000000000112DB0:
	{ nop.m	0x0; addl	r46,-2452,r1; nop.i	0x0; }
	{ ld8	r46,[r46]; nop.i	0x0; br.call.sptk.many	b0,unbind_variable; }
	{ adds	r1,0x0,r43; adds	r46,0x0,r35; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r43; br.cond.sptk.few	4000000000112950; }

l4000000000112DF0:
	{ addl	r47,-2444,r1; nop.m	0x0; adds	r46,0x0,r38; }
	{ ld8	r47,[r47]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000112480; }
	{ adds	r1,0x0,r43; adds	r33,0x0,r8; (p16) br.cond.dptk.few	4000000000112DB0; }

l4000000000112E20:
	{ addl	r15,6336,r1; adds	r14,0x24,r12; nop.i	0x0 }
	{ adds	r16,0x25,r12; addl	r46,-2452,r1; adds	r48,0x0,r0; }
	{ nop.m	0x0; st1	[r0],r16; adds	r47,0x0,r14 }
	{ ld8	r46,[r46]; ld4	r15,[r15]; nop.i	0x0; }
	{ st1	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ nop.m	0x0; adds	r1,0x0,r43; br.cond.sptk.few	4000000000112D60 }

l4000000000112E80:
	{ nop.m	0x0; sxt4	r16,r33; nop.b	0x0 }
	{ ld8	r14,[r39]; sxt4	r15,r33; shladd	r16,r16,0x3,r0 }
	{ shladd	r15,r15,0x3,r37; cmp.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	4000000000112B00 }

l4000000000112EB0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000112B50 }

l4000000000112EC0:
	{ addl	r46,-2452,r1; nop.m	0x0; addl	r33,1,r0; }
	{ ld8	r46,[r46]; nop.i	0x0; br.call.sptk.many	b0,unbind_variable; }
	{ adds	r1,0x0,r43; adds	r46,0x0,r38; addl	r47,-2444,r1; }
	{ ld8	r47,[r47]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000112480; }
	{ adds	r1,0x0,r43; adds	r46,0x0,r35; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r43; br.cond.sptk.few	4000000000112950; }

l4000000000112F20:
	{ addl	r14,23444,r1; adds	r33,0x0,r0; mov.i	LC,0x9 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }

l4000000000112F40:
	{ nop.m	0x0; ld8	r15,[r14],8; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r15; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000112F70; }

l4000000000112F60:
	{ nop.m	0x0; adds	r33,0x1,r33; br.cloop.sptk.few	4000000000112F40 }

l4000000000112F70:
	{ nop.m	0x0; addl	r46,23444,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_getopt_restore_state; }
	{ adds	r1,0x0,r43; adds	r46,0x0,r33; adds	r48,0x0,r36; }
	{ nop.m	0x0; addl	r47,23444,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_getopt; }
	{ adds	r1,0x0,r43; adds	r33,0x0,r8; br.cond.sptk.few	40000000001127C0; }
4000000000112FD0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
4000000000112FE0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
4000000000112FF0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; set_login_shell: 4000000000113000
;;   Called from:
;;     400000000001D89C (in main)
set_login_shell proc
	{ addl	r14,6520,r1; nop.m	0x0; adds	r8,0x0,r0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; addl	r14,8572,r1; (p06) addl	r15,1,r0; }

l4000000000113030:
	{ nop.m	0x0; (p07) adds	r15,0x0,r0; nop.i	0x0; }

l400000000011303C:
	{ Invalid; Invalid; add	r0,r32,r0 }
	{ nop; break.m	0x1000; break.i	0x1000 }
4000000000113050 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000113060 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000113070 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000113080 18 10 15 08 80 05 00 E2 05 62 48 00 00 00 00 20 .........bH.... 
4000000000113090 01 78 D0 02 39 24 10 02 00 62 00 60 04 08 00 84 .x..9$...b.`....
40000000001130A0 09 70 00 40 10 10 80 00 00 00 42 00 20 02 AA 00 .p.@......B. ...
40000000001130B0 11 38 FC 1D 86 3B 00 08 05 80 83 03 30 00 00 43 .8...;......0..C
40000000001130C0 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001130D0 10 00 38 1E 90 11 00 00 00 02 00 80 08 00 84 00 ..8.............
40000000001130E0 0B 70 30 03 32 24 00 00 00 02 00 00 00 00 04 00 .p0.2$..........
40000000001130F0 11 20 01 1C 18 10 00 00 00 02 00 00 D8 F4 F0 58 . .............X
4000000000113100 18 08 00 46 00 21 E0 00 20 00 42 00 00 00 00 20 ...F.!.. .B.... 
4000000000113110 01 00 20 40 90 11 00 10 01 55 00 00 01 00 00 84 .. @.....U......
4000000000113120 09 78 D0 02 39 24 00 00 00 02 00 00 10 0A 00 07 .x..9$..........
4000000000113130 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000113140 11 00 38 1E 90 11 00 00 00 02 00 80 08 00 84 00 ..8.............
4000000000113150 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000113160 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000113170 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000113180 01 08 0D 06 80 05 00 02 00 62 00 40 04 08 00 84 .........b.@....
4000000000113190 11 00 00 00 01 00 00 00 00 02 00 00 F8 63 FF 58 .............c.X
40000000001131A0 09 40 00 00 00 21 10 00 88 00 42 00 10 02 AA 00 .@...!....B.....
40000000001131B0 11 00 00 00 01 00 00 00 05 80 03 80 08 00 84 00 ................
40000000001131C0 08 18 19 0A 80 05 00 00 00 02 00 40 04 00 C4 00 ...........@....
40000000001131D0 09 20 01 02 00 21 00 00 00 02 00 A0 04 08 01 84 . ...!..........
40000000001131E0 11 00 00 00 01 00 00 00 00 02 00 00 68 20 FC 58 ............h .X
40000000001131F0 09 08 00 48 00 21 00 00 00 02 00 00 30 02 AA 00 ...H.!......0...
4000000000113200 11 00 00 00 01 00 00 10 05 80 03 80 08 00 84 00 ................
4000000000113210 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000113220 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000113230 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000113240 01 08 0D 06 80 05 00 02 00 62 00 40 04 08 00 84 .........b.@....
4000000000113250 11 00 00 00 01 00 00 00 00 02 00 00 78 56 FC 58 ............xV.X
4000000000113260 09 40 00 00 00 21 10 00 88 00 42 00 10 02 AA 00 .@...!....B.....
4000000000113270 11 00 00 00 01 00 00 00 05 80 03 80 08 00 84 00 ................

;; fn4000000000113280: 4000000000113280
;;   Called from:
;;     4000000000113BEC (in shopt_listopt)
;;     400000000011416C (in fn4000000000114100)
;;     400000000011458C (in shopt_builtin)
;;     4000000000114D0C (in parse_bashopts)
fn4000000000113280 proc
	{ alloc	r37,ar.pfs,0x9,0x0,0x7; addl	r40,-5932,r1; mov	r36,b4 }
	{ ld1	r35,[r32]; addl	r14,6284,r1; adds	r38,0x0,r1; }
	{ adds	r34,0x0,r0; ld8	r40,[r40]; sxt1	r35,r35 }
	{ ld8	r33,[r14]; nop.m	0x0; nop.i	0x0; }

l40000000001132C0:
	{ ld1	r14,[r40]; adds	r33,0x18,r33; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,r14,r35; adds	r14,0xFFFFFFFFFFFFFFE8,r33; (p07) br.cond.dpnt.few	4000000000113330; }

l40000000001132E0:
	{ ld8	r40,[r14]; nop.m	0x0; adds	r34,0x1,r34; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r40; (p06) br.cond.dptk.few	40000000001132C0 }

l4000000000113300:
	{ addl	r34,-1,r0; nop.m	0x0; nop.i	0x0; }

l4000000000113310:
	{ adds	r8,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,4000000000113320; br.ret	b0; }

l4000000000113330:
	{ adds	r39,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r14,0xFFFFFFFFFFFFFFE8,r33; nop.m	0x0; adds	r1,0x0,r38 }
	{ cmp4.eq	p06,p07,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000113310; }

l4000000000113360:
	{ ld8	r40,[r14]; nop.m	0x0; adds	r34,0x1,r34; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r40; (p06) br.cond.dptk.few	40000000001132C0 }

l4000000000113380:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000113300; }
4000000000113390 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001133A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001133B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000001133C0: 40000000001133C0
;;   Called from:
;;     4000000000113CCC (in shopt_listopt)
;;     400000000011427C (in fn4000000000114100)
;;     4000000000114A1C (in shopt_builtin)
fn40000000001133C0 proc
	{ alloc	r34,ar.pfs,0x7,0x0,0x4; addl	r37,-5924,r1; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.i	0x0; addl	r38,5,r0 }
	{ adds	r36,0x0,r0; ld8	r37,[r37]; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r35; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r37,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,builtin_error; }
	{ adds	r1,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,4000000000113420; br.ret	b0; }
4000000000113430 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000113440: 4000000000113440
;;   Called from:
;;     400000000011383C (in fn40000000001137C0)
;;     4000000000113C5C (in shopt_listopt)
;;     40000000001145EC (in shopt_builtin)
;;     4000000000114BCC (in shopt_builtin)
fn4000000000113440 proc
	{ alloc	r36,ar.pfs,0xA,0x0,0x6; mov	r35,b3; adds	r37,0x0,r1; }
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x4; (p06) br.cond.dptk.few	40000000001134D0; }

l4000000000113460:
	{ cmp4.eq	p06,p07,0x0,r33; nop.m	0x0; addl	r39,-5884,r1 }
	{ addl	r38,1,r0; nop.m	0x0; adds	r41,0x0,r32; }
	{ (p07) addl	r40,-5916,r1; ld8	r39,[r39]; nop.i	0x0; }

l4000000000113486:
	{ (p19) fwb; addl	r0,49152,r1; Invalid }

l4000000000113496:
	{ (p20) fwb; nop; (p01) nop; }

l400000000011349C:
	{ Invalid; Invalid; break.i	0x1000 }

l40000000001134A6:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ Invalid; (p34) nop; (p32) nop }

l40000000001134D0:
	{ cmp4.eq	p06,p07,0x0,r33; nop.m	0x0; addl	r39,-5876,r1 }
	{ addl	r38,1,r0; nop.m	0x0; adds	r40,0x0,r32; }
	{ (p07) addl	r41,-5900,r1; ld8	r39,[r39]; nop.i	0x0; }

l40000000001134F6:
	{ (p19) fwb; addl	r0,49152,r1; Invalid }

l4000000000113506:
	{ (p20) fwb; nop; (p17) br.call.sptk.few	b2,b0; }

l400000000011350C:
	{ nop; Invalid; break.i	0x1000 }

l4000000000113516:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ Invalid; (p34) nop; break.i	0x80000 }
4000000000113540 10 00 00 00 01 00 60 00 84 0E 73 03 50 00 00 42 ......`...s.P..B
4000000000113550 0B 70 18 40 00 21 E0 00 38 00 20 00 00 00 04 00 .p.@.!..8. .....
4000000000113560 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
4000000000113570 11 38 CC 1C 86 39 00 00 00 02 80 03 10 01 00 43 .8...9.........C
4000000000113580 10 00 00 00 01 00 60 A0 39 0E 73 03 A0 01 00 43 ......`.9.s....C
4000000000113590 0B 70 C0 03 42 24 E0 00 38 20 20 00 00 00 04 00 .p..B$..8  .....
40000000001135A0 11 30 00 1C 87 39 00 00 00 02 80 03 80 00 00 43 .0...9.........C
40000000001135B0 09 00 00 00 01 80 E1 A0 07 84 48 00 00 00 04 00 ..........H.....
40000000001135C0 C9 70 00 1C 10 10 00 00 00 02 00 00 00 00 04 00 .p..............
40000000001135D0 10 00 00 00 01 00 60 00 38 0E F3 03 80 00 00 43 ......`.8......C
40000000001135E0 09 70 E0 03 42 24 00 00 00 02 00 00 01 00 00 84 .p..B$..........
40000000001135F0 0B 70 00 1C 10 10 60 00 38 0E 73 C0 C1 09 BC 90 .p....`.8.s.....
4000000000113600 03 00 00 00 01 C0 F1 40 01 00 48 E3 A1 02 00 90 .......@..H.....
4000000000113610 10 00 3C 1C 90 11 00 00 00 02 00 80 08 00 84 00 ..<.............
4000000000113620 09 70 70 02 2F 24 F0 F8 00 00 48 00 01 00 00 84 .pp./$....H.....
4000000000113630 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000113640 10 00 3C 1C 90 11 00 00 00 02 00 80 08 00 84 00 ..<.............
4000000000113650 09 70 70 02 2F 24 F0 00 01 00 48 00 01 00 00 84 .pp./$....H.....
4000000000113660 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000113670 10 00 3C 1C 90 11 00 00 00 02 00 80 08 00 84 00 ..<.............
4000000000113680 0B 00 1D 40 00 21 E0 00 80 00 20 00 00 00 04 00 ...@.!.... .....
4000000000113690 03 00 00 00 01 00 E0 00 38 28 00 E0 10 73 18 E6 ........8(...s..
40000000001136A0 EB 70 E0 03 42 E4 01 00 38 20 A3 C3 41 0F 08 91 .p..B...8 ..A...
40000000001136B0 F1 00 00 1C 90 11 00 00 00 02 80 03 E0 FE FF 4B ...............K
40000000001136C0 10 00 00 00 01 00 60 90 39 0E F3 03 D0 FE FF 4A ......`.9......J
40000000001136D0 0B 70 E0 03 42 24 00 00 38 20 23 C0 01 0F 08 91 .p..B$..8 #.....
40000000001136E0 09 00 00 1C 90 11 00 00 00 02 00 C0 41 0F 08 91 ............A...
40000000001136F0 09 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
4000000000113700 10 00 00 00 01 00 60 00 38 0E 73 03 E0 FE FF 4A ......`.8.s....J
4000000000113710 10 00 00 00 01 00 00 00 00 02 00 00 40 FF FF 48 ............@..H
4000000000113720 0B 00 1D 40 00 21 E0 00 80 00 20 00 00 00 04 00 ...@.!.... .....
4000000000113730 03 00 00 00 01 00 E0 00 38 28 00 E0 00 73 18 E6 ........8(...s..
4000000000113740 EB 70 D0 03 42 E4 01 00 38 20 A3 C3 01 0F 08 91 .p..B...8 ......
4000000000113750 F1 00 00 1C 90 11 E0 80 07 84 C8 03 90 FE FF 4B ...............K
4000000000113760 0B 70 00 1C 10 10 60 00 38 0E 73 00 00 00 04 00 .p....`.8.s.....
4000000000113770 09 00 00 00 01 80 E1 A0 07 84 48 00 00 00 04 00 ..........H.....
4000000000113780 D0 70 00 1C 10 10 00 00 00 02 00 03 50 FE FF 4A .p..........P..J
4000000000113790 11 00 00 00 01 00 00 00 00 02 00 00 90 FE FF 48 ...............H
40000000001137A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001137B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000001137C0: 40000000001137C0
;;   Called from:
;;     4000000000113CBC (in shopt_listopt)
;;     4000000000114C4C (in shopt_builtin)
fn40000000001137C0 proc
	{ alloc	r35,ar.pfs,0x9,0x0,0x6; addl	r38,-5932,r1; nop.b	0x0 }
	{ addl	r14,6292,r1; mov	r34,b2; adds	r36,0x0,r1; }
	{ nop.m	0x0; mov	r37,pr; nop.i	0x0 }
	{ ld8	r38,[r38]; ld8	r33,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tnat.z	p17,p16,r32; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000113820:
	{ ld8	r14,[r33]; (p17) adds	r40,0x0,r32; adds	r33,0x18,r33; }

l400000000011382C:
	{ (p12) cmp.eq	p33,p17,r0,r66; nop }
	{ (p32) cmp.lt.unc	p63,p09,r127,r45; Invalid; nop }

l4000000000113840:
	{ adds	r14,0xFFFFFFFFFFFFFFF8,r33; nop.m	0x0; (p17) adds	r1,0x0,r36; }

l4000000000113850:
	{ nop.m	0x0; ld8	r38,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r38; (p06) br.cond.dptk.few	4000000000113820 }

l4000000000113870:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_chkwrite; }
	{ adds	r1,0x0,r36; mov	pr,r37,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000113890; br.ret	b0; }
40000000001138A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001138B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; reset_shopt_options: 40000000001138C0
;;   Called from:
;;     400000000005063C (in shell_execve)
reset_shopt_options proc
	{ addl	r16,9140,r1; addl	r14,1,r0; addl	r15,6520,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; st4	[r0],r16; addl	r16,9100,r1 }
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; st4	[r0],r16; addl	r16,9120,r1; }
	{ nop.m	0x0; st4	[r0],r16; addl	r16,9236,r1; }
	{ nop.m	0x0; st4	[r0],r16; addl	r16,9244,r1; }
	{ nop.m	0x0; st4	[r0],r16; addl	r16,9240,r1; }
	{ nop.m	0x0; st4	[r0],r16; addl	r16,9072,r1; }
	{ nop.m	0x0; st4	[r0],r16; addl	r16,6680,r1; }
	{ nop.m	0x0; st4	[r0],r16; addl	r16,8368,r1; }
	{ nop.m	0x0; st4	[r0],r16; addl	r16,9204,r1; }
	{ nop.m	0x0; st4	[r0],r16; addl	r16,5692,r1; }
	{ nop.m	0x0; st4	[r14],r16; addl	r16,6264,r1; }
	{ nop.m	0x0; st4	[r14],r16; addl	r16,7664,r1; }
	{ nop.m	0x0; st4	[r0],r16; addl	r16,9180,r1; }
	{ nop.m	0x0; st4	[r0],r16; addl	r16,9164,r1; }
	{ nop.m	0x0; st4	[r0],r16; addl	r16,6108,r1; }
	{ nop.m	0x0; st4	[r14],r16; addl	r16,9172,r1; }
	{ nop.m	0x0; st4	[r0],r16; addl	r16,9152,r1; }
	{ nop.m	0x0; st4	[r0],r16; addl	r16,6136,r1; }
	{ nop.m	0x0; st4	[r14],r16; addl	r14,8572,r1; }
	{ st4	[r15],r14; nop.i	0x0; br.ret	b0; }
4000000000113A30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; get_shopt_options: 4000000000113A40
get_shopt_options proc
	{ alloc	r38,ar.pfs,0xA,0x0,0x8; addl	r32,-5932,r1; mov	r37,b5 }
	{ adds	r39,0x0,r1; ld8	r32,[r32]; addl	r40,45,r0 }
	{ adds	r34,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,strvec_create; }
	{ adds	r1,0x0,r39; adds	r36,0x0,r8; nop.i	0x0 }
	{ adds	r35,0x0,r8; addl	r8,6,r0; adds	r34,0x1,r34; }
	{ addl	r14,6300,r1; nop.m	0x0; adds	r40,0x1,r8; }
	{ ld8	r33,[r14]; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r39; adds	r41,0x0,r32; nop.i	0x0 }
	{ adds	r33,0x18,r33; adds	r40,0x0,r8; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r14,0xFFFFFFFFFFFFFFE8,r33; st8	[r35],r8,8; adds	r1,0x0,r39; }
	{ nop.m	0x0; ld8	r32,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r32; (p06) br.cond.dpnt.few	4000000000113B80; }

l4000000000113B00:
	{ adds	r40,0x0,r32; nop.m	0x0; adds	r33,0x18,r33 }
	{ adds	r34,0x1,r34; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r39; adds	r40,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r41,0x0,r32 }
	{ adds	r40,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r14,0xFFFFFFFFFFFFFFE8,r33; st8	[r35],r8,8; adds	r1,0x0,r39; }
	{ nop.m	0x0; ld8	r32,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r32; (p07) br.cond.dptk.few	4000000000113B00 }

l4000000000113B80:
	{ adds	r8,0x0,r36; mov.i	ar.pfs,r38; sxt4	r34,r34; }
	{ shladd	r36,r34,0x3,r36; nop.m	0x0; mov.spnt	b0,r37,4000000000113B90; }
	{ st8	[r0],r36; nop.i	0x0; br.ret	b0; }
4000000000113BB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; shopt_listopt: 4000000000113BC0
;;   Called from:
;;     400000000001F34C (in main)
shopt_listopt proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; cmp.eq	p07,p06,0x0,r32; mov	r34,b2 }
	{ adds	r36,0x0,r1; adds	r37,0x0,r32; (p07) br.cond.dpnt.few	4000000000113C90; }

l4000000000113BE0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000113280; }
	{ adds	r1,0x0,r36; cmp4.eq	p07,p08,0x0,r33; adds	r37,0x0,r32; }
	{ addl	r14,-23884,r1; (p07) adds	r39,0x1,r0; (p08) adds	r39,0x0,r0 }

l4000000000113C0C:
	{ cmp.eq	p00,p17,r0,r66; (p01) nop }

l4000000000113C10:
	{ cmp4.lt	p07,p06,r8,r0; sxt4	r8,r8; (p07) br.cond.dpnt.few	4000000000113CC0; }

l4000000000113C20:
	{ nop.m	0x0; shladd	r8,r8,0x1,r8; tbit.z	p09,p08,r39,0x0; }
	{ adds	r14,0x8,r14; (p09) addl	r39,16,r0; shladd	r8,r8,0x3,r14 }

l4000000000113C3C:
	{ (p04) cmp.eq	p14,p11,0x12,r64; (p04) cmp.lt	p00,p16,r0,r64; Invalid; }

l4000000000113C46:
	{ (p07) fwb; nop; (p32) nop }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; (p32) nop; (p16) nop.b	0x24000 }
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ Invalid; (p34) nop; (p32) nop }

l4000000000113C90:
	{ cmp4.eq	p06,p07,0x0,r33; nop.m	0x0; mov.spnt	b0,r34,4000000000113C90; }
	{ (p07) addl	r32,16,r0; mov.i	ar.pfs,r35; (p06) adds	r32,0x0,r0; }

l4000000000113CA6:
	{ chk.a.nc	r35,3FFFFFFFFF1290A6; (p16) nop; Invalid }

l4000000000113CB0:
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000001137C0; }

l4000000000113CC0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000001133C0; }
	{ addl	r8,1,r0; adds	r1,0x0,r36; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000113CE0; br.ret	b0; }
4000000000113CF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; set_bashopts: 4000000000113D00
;;   Called from:
;;     400000000011424C (in fn4000000000114100)
;;     4000000000114DF6 (in initialize_bashopts)
;;     4000000000114F20 (in initialize_bashopts)
set_bashopts proc
	{ alloc	r39,ar.pfs,0xC,0x0,0x9; adds	r12,0xFFFFFFFFFFFFFFD0,r12; mov	r38,b6 }
	{ addl	r41,-5932,r1; addl	r14,6308,r1; adds	r40,0x0,r1; }
	{ adds	r34,0x10,r12; ld8	r41,[r41]; adds	r35,0x0,r0 }
	{ addl	r36,1,r0; ld8	r32,[r14]; nop.i	0x0; }
	{ adds	r33,0x0,r34; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000113D60:
	{ ld8	r14,[r32]; st1	[r0],r33; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000113DB0 }

l4000000000113D90:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r40; st1	[r36],r33; add	r35,r8,r35,0x1 }

l4000000000113DB0:
	{ adds	r14,0x10,r32; adds	r33,0x1,r33; adds	r32,0x18,r32; }
	{ nop.m	0x0; ld8	r41,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r41; (p06) br.cond.dptk.few	4000000000113D60 }

l4000000000113DE0:
	{ addl	r33,-5932,r1; nop.m	0x0; adds	r41,0x1,r35 }
	{ adds	r36,0x0,r0; nop.m	0x0; addl	r37,58,r0; }
	{ ld8	r33,[r33]; sxt4	r41,r41; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r40; adds	r35,0x0,r8; addl	r14,6316,r1 }
	{ nop.m	0x0; ld8	r32,[r14]; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000113E40:
	{ ld1	r14,[r34],1; adds	r32,0x18,r32; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; adds	r14,0xFFFFFFFFFFFFFFE8,r32; (p07) br.cond.dpnt.few	4000000000113FC0; }

l4000000000113E60:
	{ nop.m	0x0; ld8	r33,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	4000000000113E40; }

l4000000000113E80:
	{ cmp4.eq	p06,p07,0x0,r36; addl	r41,-5868,r1; (p07) adds	r14,0xFFFFFFFFFFFFFFFF,r36 }

l4000000000113E90:
	{ ld8	r41,[r41]; nop.m	0x0; sxt4	r14,r14; }
	{ (p06) adds	r14,0x0,r0; add	r14,r35,r14; nop.i	0x0; }

l4000000000113EA6:
	{ Invalid; nop; nop }
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ Invalid; nop; (p32) nop }
	{ (p21) chk.a.clr	r0,3FFFFFFFFF193ED6; nop; br.call.sptk.few	b0,b0 }

l4000000000113EE0:
	{ ld4	r32,[r8]; nop.m	0x0; addl	r41,-5868,r1; }
	{ and	r14,0xFFFFFFFFFFFFFFFD,r32; ld8	r41,[r41]; nop.i	0x0; }
	{ st4	[r14],r8; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r1,0x0,r40; adds	r8,0x28,r8; addl	r15,7412,r1 }
	{ ld4	r14,[r8]; nop.m	0x0; nop.i	0x0; }
	{ ld4	r16,[r15]; or	r15,0x2,r14; cmp4.eq	p07,p06,0x0,r16 }
	{ st4	[r15],r8; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000113F90; }

l4000000000113F50:
	{ nop.m	0x0; tbit.z	p07,p06,r32,0x0; (p06) br.cond.dpnt.few	4000000000113F90; }

l4000000000113F60:
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x0; (p07) and	r14,0xFFFFFFFFFFFFFFFE,r14; }

l4000000000113F70:
	{ nop.m	0x0; (p07) or	r14,0x2,r14; nop.i	0x0; }

l4000000000113F7C:
	{ Invalid; Invalid; break.i	0x1000 }

l4000000000113F86:
	{ break.m	0x4000; nop; (p16) nop }

l4000000000113F90:
	{ adds	r41,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }

l4000000000113F92:
	{ (p48) break.m	0x42008; nop; (p16) break.i	0x12C783; }

l4000000000113F96:
	{ break.m	0x4000; Invalid; (p16) nop }

l4000000000113F98:
	{ (p16) nop; Invalid; (p32) nop }

l4000000000113F9C:
	{ (p02) nop; invala; (p48) break.b	0x2A809 }

l4000000000113F9E:
	{ (p07) ld1	r75,[r4]; (p01) mov	pr,0x3800210; (p42) nop }

l4000000000113FA2:
	{ cmp.eq	p10,p00,r64,r16; (p04) cmp.lt.unc	p16,p00,r10,r0; Invalid }

l4000000000113FAE:
	{ (p56) break.m	0x300; (p04) nop; Invalid }

l4000000000113FB4:
	{ srlz.i; (p08) break.i	0x108804; (p01) break.i	0x8; }

l4000000000113FBA:
	{ Invalid; (p04) mov	pr,0x0; nop }

l4000000000113FC0:
	{ nop.m	0x0; sxt4	r41,r36; adds	r42,0x0,r33; }
	{ add	r41,r35,r41; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r40; adds	r41,0x0,r33; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ add	r8,r36,r8; nop.m	0x0; adds	r1,0x0,r40; }
	{ nop.m	0x0; sxt4	r14,r8; adds	r36,0x1,r8; }
	{ add	r14,r35,r14; st1	[r37],r14; adds	r14,0xFFFFFFFFFFFFFFE8,r32; }
	{ nop.m	0x0; ld8	r33,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	4000000000113E40 }

l4000000000114040:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000113E80 }

l4000000000114050:
	{ addl	r41,-5868,r1; adds	r42,0x0,r35; adds	r43,0x0,r0; }
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r1,0x0,r40; adds	r8,0x28,r8; addl	r15,7412,r1 }
	{ ld4	r14,[r8]; nop.m	0x0; nop.i	0x0; }
	{ ld4	r16,[r15]; or	r15,0x2,r14; cmp4.eq	p07,p06,0x0,r16 }
	{ st4	[r15],r8; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000113F90; }

l40000000001140B0:
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x0; (p07) and	r14,0xFFFFFFFFFFFFFFFE,r14; }

l40000000001140C0:
	{ nop.m	0x0; (p07) or	r14,0x2,r14; nop.i	0x0; }

l40000000001140CC:
	{ Invalid; Invalid; break.i	0x1000 }

l40000000001140D6:
	{ break.m	0x4000; nop; break.i	0x80000 }
40000000001140E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001140F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000114100: 4000000000114100
;;   Called from:
;;     400000000011432C (in shopt_setopt)
;;     40000000001148AC (in shopt_builtin)
fn4000000000114100 proc
	{ alloc	r39,ar.pfs,0xB,0x0,0x9; addl	r35,-23884,r1; nop.b	0x0 }
	{ cmp.eq	p06,p07,0x0,r33; mov	r38,b6; adds	r40,0x0,r1; }
	{ nop.m	0x0; nop.m	0x0; adds	r37,0x0,r0; }
	{ adds	r36,0x8,r35; (p06) adds	r37,0x0,r0; (p06) br.cond.dpnt.few	4000000000114240; }

l400000000011413C:
	{ (p08) cmp.lt	p00,p11,r64,r33; (p01) cmp.lt	p34,p16,r8,r64; (p01) rfi }

l4000000000114140:
	{ adds	r14,0x8,r33; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; ld8	r34,[r14]; nop.i	0x0; }
	{ adds	r41,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn4000000000113280; }
	{ nop.m	0x0; sxt4	r14,r8; adds	r1,0x0,r40 }
	{ cmp4.lt	p07,p06,r8,r0; adds	r42,0x0,r32; (p07) br.cond.dpnt.few	4000000000114270; }

l4000000000114190:
	{ nop.m	0x0; shladd	r14,r14,0x1,r14; nop.i	0x0; }
	{ shladd	r14,r14,0x3,r0; add	r15,r35,r14; add	r14,r36,r14; }
	{ ld8	r16,[r14]; nop.m	0x0; adds	r14,0x10,r15; }
	{ nop.m	0x0; ld8	r8,[r14]; nop.i	0x0; }
	{ st4	[r32],r16; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	4000000000114220; }

l40000000001141E0:
	{ ld8	r14,[r8],8; ld8	r41,[r15]; nop.i	0x0; }
	{ nop.m	0x0; ld8	r1,[r8]; mov.spnt	b6,r14,40000000001141F0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,b6; }
	{ adds	r1,0x0,r40; nop.m	0x0; nop.i	0x0 }

l4000000000114220:
	{ nop.m	0x0; ld8	r33,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	4000000000114140 }

l4000000000114240:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,set_bashopts; }
	{ adds	r8,0x0,r37; adds	r1,0x0,r40; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,4000000000114260; br.ret	b0; }

l4000000000114270:
	{ adds	r41,0x0,r34; addl	r37,1,r0; br.call.sptk.many	b0,fn40000000001133C0; }
	{ ld8	r33,[r33]; nop.m	0x0; adds	r1,0x0,r40; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	4000000000114140 }

l40000000001142A0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000114240; }
40000000001142B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; shopt_setopt: 40000000001142C0
shopt_setopt proc
	{ alloc	r37,ar.pfs,0x9,0x0,0x7; nop.m	0x0; mov	r36,b4 }
	{ adds	r38,0x0,r1; nop.m	0x0; adds	r39,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,make_word; }
	{ adds	r1,0x0,r38; nop.m	0x0; adds	r39,0x0,r8 }
	{ adds	r40,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,make_word_list; }
	{ adds	r1,0x0,r38; adds	r34,0x0,r8; nop.i	0x0 }
	{ adds	r39,0x0,r33; adds	r40,0x0,r8; br.call.sptk.many	b0,fn4000000000114100; }
	{ adds	r1,0x0,r38; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r39,0x0,r34; nop.m	0x0; br.call.sptk.many	b0,dispose_words; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r38; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,4000000000114360; br.ret	b0; }
4000000000114370 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; shopt_builtin: 4000000000114380
shopt_builtin proc
	{ alloc	r39,ar.pfs,0xE,0x0,0xA; addl	r35,-2428,r1; nop.b	0x0 }
	{ adds	r40,0x0,r1; mov	r41,pr; mov	r38,b6 }
	{ ld8	r35,[r35]; adds	r34,0x0,r0; br.call.sptk.many	b0,reset_internal_getopt; }
	{ adds	r1,0x0,r40; nop.m	0x0; nop.i	0x0; }
	{ addl	r43,-5860,r1; nop.m	0x0; adds	r42,0x0,r32; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r40; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dpnt.few	40000000001144C0 }

l40000000001143F0:
	{ nop.m	0x0; adds	r8,0xFFFFFFFFFFFFFF91,r8; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x6,r8; (p07) br.cond.dptk.few	4000000000114450 }

l4000000000114410:
	{ addl	r35,258,r0; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r40; mov	pr,r41,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r39; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r38,4000000000114440; br.ret	b0 }

l4000000000114450:
	{ addp4	r8,r8,r0; shladd	r8,r8,0x3,r35; nop.i	0x0; }
	{ ld8	r14,[r8]; add	r8,r8,r14; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r8,4000000000114470; br.cond	b6; }
4000000000114480 09 58 71 FA D2 27 A0 02 80 00 42 40 24 10 B9 80 .Xq..'....B@$...
4000000000114490 11 58 01 56 18 10 00 00 00 02 00 00 38 60 00 50 .X.V........8`.P
40000000001144A0 11 08 00 50 00 21 70 F8 23 0C 77 03 50 FF FF 4A ...P.!p.#.w.P..J
40000000001144B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

l40000000001144C0:
	{ addl	r15,9268,r1; nop.m	0x0; and	r14,0x3,r34; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x3,r14; (p07) br.cond.dpnt.few	4000000000114A50; }

l40000000001144E0:
	{ ld8	r33,[r15]; nop.m	0x0; and	r15,0xB,r34; }
	{ cmp4.eq	p07,p06,0x8,r15; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000114750; }

l4000000000114500:
	{ cmp.eq	p06,p07,0x0,r33; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000114AC0; }

l4000000000114510:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x3; (p07) br.cond.dptk.few	4000000000114690; }

l4000000000114520:
	{ addl	r37,-23884,r1; cmp4.eq	p06,p07,0x0,r14; nop.b	0x0 }
	{ adds	r36,0x0,r0; tnat.z	p17,p16,r34; (p07) br.cond.dpnt.few	4000000000114880; }

l4000000000114540:
	{ nop.m	0x0; nop.i	0x0; adds	r37,0x8,r37; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000114560:
	{ adds	r14,0x8,r33; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; ld8	r35,[r14]; nop.i	0x0; }
	{ adds	r42,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn4000000000113280; }
	{ cmp4.lt	p07,p06,r8,r0; sxt4	r8,r8; adds	r1,0x0,r40 }
	{ (p17) adds	r42,0x0,r35; (p17) adds	r44,0x0,r34; (p07) br.cond.dpnt.few	4000000000114A10; }

l40000000001145A6:
	{ (p22) chk.a.clr	f0,3FFFFFFFFF1947C6; nop }

l40000000001145AC:
	{ Invalid; zxt1	r2,r4; (p01) epc }

l40000000001145B0:
	{ shladd	r8,r8,0x1,r8; shladd	r8,r8,0x3,r37; nop.i	0x0; }
	{ ld8	r14,[r8]; ld4	r43,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r43; nop.i	0x0; }
	{ (p06) addl	r36,1,r0; nop.i	0x0; (p17) br.call.dpnt.many	b0,fn4000000000113440; }

l40000000001145E6:
	{ nop; (p32) nop; (p16) nop }

l40000000001145F0:
	{ ld8	r33,[r33]; nop.m	0x0; (p17) adds	r1,0x0,r40; }

l4000000000114600:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	4000000000114560 }

l4000000000114610:
	{ adds	r42,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,sh_chkwrite; }
	{ nop.m	0x0; adds	r1,0x0,r40; adds	r35,0x0,r8; }

l4000000000114630:
	{ adds	r8,0x0,r35; mov	pr,r41,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,4000000000114640; br.ret	b0 }
4000000000114650 11 00 00 00 01 00 20 0A 88 5C 40 00 70 FD FF 48 ...... ..\@.p..H
4000000000114660 11 00 00 00 01 00 20 22 88 5C 40 00 60 FD FF 48 ...... ".\@.`..H
4000000000114670 11 00 00 00 01 00 20 82 88 5C 40 00 50 FD FF 48 ...... ..\@.P..H
4000000000114680 11 00 00 00 01 00 20 42 88 5C 40 00 40 FD FF 48 ...... B.\@.@..H

l4000000000114690:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x0; adds	r35,0x0,r0; }
	{ (p06) addl	r34,43,r0; nop.m	0x0; (p07) addl	r34,45,r0; }

l40000000001146A6:
	{ chk.a.nc	f0,3FFFFFFFFF114EA6; (p17) nop; break.i	0x80000 }

l40000000001146B0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000001146C0:
	{ adds	r14,0x8,r33; nop.m	0x0; adds	r42,0x0,r34; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r43,[r14]; nop.i	0x0; br.call.sptk.many	b0,set_minus_o_option; }
	{ ld8	r33,[r33]; cmp4.eq	p06,p07,0x1,r8; adds	r1,0x0,r40; }
	{ (p06) addl	r35,1,r0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	40000000001146C0 }

l4000000000114706:
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD97916; nop; break.b	0x80000 }

l4000000000114710:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,set_shellopts; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r40; mov	pr,r41,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r39; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r38,4000000000114740; br.ret	b0 }

l4000000000114750:
	{ cmp.eq	p07,p06,0x0,r33; nop.i	0x0; (p07) br.cond.dpnt.few	40000000001148B0; }

l4000000000114760:
	{ (p06) adds	r36,0x0,r0; (p06) tnat.z	p17,p16,r34; (p06) tnat.z	p18,p19,r34; }

l4000000000114766:
	{ (p08) chk.a.nc	r4,3FFFFFFFFFB1C986; (p09) nop; break.b	0x80000; }

l400000000011476C:
	{ (p04) nop; break.i	0x1000; break.i	0x1000 }

l4000000000114770:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000114780:
	{ adds	r35,0x8,r33; ld8	r14,[r35]; nop.i	0x0; }
	{ ld8	r42,[r14]; nop.i	0x0; br.call.sptk.many	b0,minus_o_option_value; }
	{ cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; adds	r1,0x0,r40; (p07) br.cond.dpnt.few	40000000001149C0; }

l40000000001147B0:
	{ cmp4.eq	p06,p07,0x0,r8; nop.m	0x0; (p06) adds	r44,0x1,r0 }

l40000000001147C0:
	{ nop.m	0x0; (p06) addl	r36,1,r0; (p16) br.cond.dptk.few	4000000000114840; }

l40000000001147CC:
	{ (p04) nop; zxt1	r0,r64; break.i	0x1000 }

l40000000001147D0:
	{ (p07) adds	r44,0x0,r0; nop.m	0x0; nop.i	0x0 }

l40000000001147D6:
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ nop; nop; (p32) nop }

l40000000001147F0:
	{ ld8	r14,[r35]; addl	r43,-5844,r1; (p06) addl	r44,43,r0 }

l4000000000114800:
	{ addl	r42,1,r0; (p07) addl	r44,45,r0; nop.i	0x0 }

l400000000011480C:
	{ ldfe.nt1	f0,[r0]; Invalid; break.i	0x1000 }
	{ nop; Invalid; break.i	0x1000 }
	{ (p27) nop; invala; break.i	0x1000 }
	{ nop; nop; Invalid }

l4000000000114840:
	{ nop.m	0x0; ld8	r33,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	4000000000114780 }

l4000000000114860:
	{ adds	r42,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,sh_chkwrite; }
	{ adds	r1,0x0,r40; adds	r35,0x0,r8; br.cond.sptk.few	4000000000114630 }

l4000000000114880:
	{ and	r32,0x1,r34; nop.m	0x0; mov	pr,r41,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.spnt	b0,r38,4000000000114890; mov.i	ar.pfs,r39; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn4000000000114100 }

l40000000001148B0:
	{ nop.m	0x0; tbit.z	p07,p06,r34,0x2; (p07) br.cond.dpnt.few	4000000000114900; }

l40000000001148C0:
	{ adds	r42,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,sh_chkwrite; }
	{ nop.m	0x0; adds	r1,0x0,r40; adds	r35,0x0,r8; }

l40000000001148E0:
	{ adds	r8,0x0,r35; mov	pr,r41,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000001148F0; br.ret	b0; }

l4000000000114900:
	{ and	r43,0x10,r34; addl	r42,-1,r0; br.call.sptk.many	b0,list_minus_o_opts; }
	{ adds	r1,0x0,r40; adds	r42,0x0,r0; br.call.sptk.many	b0,sh_chkwrite; }
	{ adds	r1,0x0,r40; adds	r35,0x0,r8; br.cond.sptk.few	40000000001148E0; }

l4000000000114930:
	{ nop.m	0x0; tbit.z	p07,p06,r44,0x0; nop.b	0x0 }
	{ ld8	r14,[r35]; addl	r43,-5876,r1; addl	r42,1,r0; }
	{ (p07) addl	r45,-5900,r1; ld8	r43,[r43]; nop.i	0x0; }

l4000000000114956:
	{ (p21) fwb; addl	r0,16384,r1; (p17) nop }

l4000000000114966:
	{ (p22) fwb; nop; cmp.lt	p00,p00,r0,r32 }
	{ (p22) fwb; nop; (p17) br.call.sptk.few	b3,b0; }

l400000000011497C:
	{ nop; Invalid; break.i	0x1000 }

l4000000000114986:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ add	r0,r0,r1; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD97BB6; nop; break.b	0x80000 }

l40000000001149B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000114860 }

l40000000001149C0:
	{ ld8	r14,[r35]; nop.m	0x0; addl	r36,1,r0; }
	{ ld8	r42,[r14]; nop.i	0x0; br.call.sptk.many	b0,sh_invalidoptname; }
	{ ld8	r33,[r33]; nop.m	0x0; adds	r1,0x0,r40; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	4000000000114780 }

l4000000000114A00:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000114860 }

l4000000000114A10:
	{ adds	r42,0x0,r35; addl	r36,1,r0; br.call.sptk.many	b0,fn40000000001133C0; }
	{ ld8	r33,[r33]; nop.m	0x0; adds	r1,0x0,r40; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	4000000000114560 }

l4000000000114A40:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000114610 }

l4000000000114A50:
	{ addl	r43,-5852,r1; nop.m	0x0; addl	r44,5,r0 }
	{ adds	r42,0x0,r0; nop.m	0x0; addl	r35,1,r0; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r40; adds	r42,0x0,r8; br.call.sptk.many	b0,builtin_error; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r40; mov	pr,r41,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r39; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r38,4000000000114AB0; br.ret	b0 }

l4000000000114AC0:
	{ nop.m	0x0; tbit.z	p07,p06,r34,0x3; nop.i	0x0 }
	{ addl	r42,-5932,r1; and	r36,0x1,r34; (p06) br.cond.dpnt.few	4000000000114BE0; }

l4000000000114AE0:
	{ cmp4.eq	p07,p06,0x0,r14; addl	r14,6324,r1; tnat.z	p17,p16,r34 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.spnt.few	4000000000114C20; }

l4000000000114B00:
	{ ld8	r42,[r42]; ld8	r35,[r14]; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000114B20:
	{ ld8	r14,[r35]; (p16) br.cond.dptk.few	4000000000114B50; nop.b	0x0; }

l4000000000114B2C:
	{ cmp.lt	p00,p09,r0,r16; Invalid; break.i	0x1000 }
	{ invala; cmp.eq	p00,p00,r32,r0; (p32) mov	pr,r73,0xE206 }
	{ (p04) ldfp8	f0,f64,[r33]; (p04) cmp.lt.unc	p38,p16,r8,r64; zxt2	r126,r79 }

l4000000000114B50:
	{ adds	r35,0x18,r35; adds	r14,0xFFFFFFFFFFFFFFF8,r35; nop.i	0x0; }
	{ nop.m	0x0; ld8	r42,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r42; (p06) br.cond.dptk.few	4000000000114B20 }

l4000000000114B80:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_chkwrite; }
	{ adds	r35,0x0,r8; adds	r1,0x0,r40; mov	pr,r41,0xFFFFFFFFFFFFFFFE; }
	{ adds	r8,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,4000000000114BB0; br.ret	b0; }

l4000000000114BC0:
	{ adds	r43,0x0,r36; adds	r44,0x0,r34; br.call.sptk.many	b0,fn4000000000113440; }
	{ nop.m	0x0; adds	r1,0x0,r40; br.cond.sptk.few	4000000000114B50 }

l4000000000114BE0:
	{ nop.m	0x0; tbit.z	p07,p06,r34,0x2; (p06) br.cond.dptk.few	40000000001148C0 }

l4000000000114BF0:
	{ and	r42,0x1,r34; and	r43,0x10,r34; br.call.sptk.many	b0,list_minus_o_opts; }
	{ adds	r1,0x0,r40; adds	r42,0x0,r0; br.call.sptk.many	b0,sh_chkwrite; }
	{ adds	r1,0x0,r40; adds	r35,0x0,r8; br.cond.sptk.few	40000000001148E0 }

l4000000000114C20:
	{ adds	r32,0x0,r34; nop.m	0x0; mov	pr,r41,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.spnt	b0,r38,4000000000114C30; mov.i	ar.pfs,r39; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000001137C0; }
4000000000114C50 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
4000000000114C60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000114C70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; parse_bashopts: 4000000000114C80
;;   Called from:
;;     4000000000114EFC (in initialize_bashopts)
parse_bashopts proc
	{ alloc	r37,ar.pfs,0x9,0x0,0x7; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r36,b4 }
	{ addl	r34,-23884,r1; adds	r39,0x0,r32; adds	r38,0x0,r1; }
	{ adds	r14,0x10,r12; nop.m	0x0; adds	r40,0x10,r12 }
	{ nop.m	0x0; addl	r35,1,r0; nop.i	0x0; }
	{ st4	[r0],r14; adds	r34,0x8,r34; br.call.sptk.many	b0,extract_colon_unit; }
	{ adds	r33,0x0,r8; nop.m	0x0; adds	r39,0x0,r8 }
	{ adds	r1,0x0,r38; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	4000000000114D90; }

l4000000000114CF0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000114D00:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000113280; }
	{ cmp4.lt	p06,p07,r8,r0; nop.m	0x0; sxt4	r14,r8 }
	{ adds	r39,0x0,r33; adds	r1,0x0,r38; (p07) shladd	r14,r14,0x1,r14; }

l4000000000114D30:
	{ (p07) shladd	r14,r14,0x3,r34; (p07) ld8	r14,[r14]; nop.i	0x0; }

l4000000000114D36:
	{ (p07) fwb; cmp4.eq	p00,p00,r0,r1; (p01) nop; }

l4000000000114D3C:
	{ Invalid; Invalid; break.i	0x1000 }

l4000000000114D46:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ add	r0,r0,r1; (p19) nop; nop }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ add	r0,r0,r1; (p16) nop; (p48) nop }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD97E06; Invalid; break.b	0x80000 }

l4000000000114D90:
	{ nop.m	0x0; mov.i	ar.pfs,r37; mov.spnt	b0,r36,4000000000114D90 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }
4000000000114DB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; initialize_bashopts: 4000000000114DC0
initialize_bashopts proc
	{ alloc	r35,ar.pfs,0x7,0x0,0x5; nop.m	0x0; mov	r34,b2 }
	{ adds	r36,0x0,r1; cmp4.eq	p06,p07,0x0,r32; (p06) br.cond.dpnt.few	4000000000114E00; }

l4000000000114DE0:
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000114DE0; mov.i	ar.pfs,r35; }
	{ alloc	r2,ar.pfs,0x1,0x0,0x0; nop.i	0x0; br.cond.sptk.many	set_bashopts }

l4000000000114E00:
	{ nop.m	0x0; addl	r37,-5868,r1; nop.i	0x0; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r14,0x28,r8; nop.m	0x0; adds	r1,0x0,r36 }
	{ cmp.eq	p06,p07,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000114DE0; }

l4000000000114E40:
	{ nop.m	0x0; ld4	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r15,0xF; (p06) br.cond.dpnt.few	4000000000114DE0; }

l4000000000114E60:
	{ ld8	r14,[r14]; and	r14,0x44,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000114DE0 }

l4000000000114E80:
	{ nop.m	0x0; adds	r33,0x8,r8; nop.i	0x0; }
	{ ld8	r37,[r33]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r36; adds	r37,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r38,[r33]; nop.m	0x0; adds	r1,0x0,r36 }
	{ adds	r37,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r37,0x0,r8; nop.i	0x0 }
	{ adds	r1,0x0,r36; adds	r33,0x0,r8; (p06) br.cond.spnt.few	4000000000114DE0; }

l4000000000114EF0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,parse_bashopts; }
	{ adds	r1,0x0,r36; adds	r37,0x0,r33; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r36; mov.spnt	b0,r34,4000000000114F10; mov.i	ar.pfs,r35; }
	{ alloc	r2,ar.pfs,0x1,0x0,0x0; nop.i	0x0; br.cond.sptk.many	set_bashopts; }
4000000000114F30 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; fn4000000000114F40: 4000000000114F40
;;   Called from:
;;     40000000001172DC (in printf_builtin)
fn4000000000114F40 proc
	{ alloc	r40,ar.pfs,0xF,0x0,0xC; mov	r42,pr; nop.b	0x0 }
	{ cmp.eq	p16,p17,0x0,r34; adds	r36,0x0,r32; adds	r41,0x0,r1; }
	{ (p17) addl	r14,1,r0; nop.m	0x0; mov	r43,LC; }

l4000000000114F66:
	{ add	r0,r0,r1; (p21) extr.u	r0,r50,32,1; (p04) nop }

l4000000000114F76:
	{ add	r0,r0,r1; Invalid; (p32) nop }
	{ break.m	0x4000; (p07) nop; nop }
	{ Invalid; (p08) nop; (p32) nop.b	0xE009 }
	{ add	r0,r0,r1; (p07) nop; break.i	0x80000 }
	{ (p03) chk.a.clr	f86,3FFFFFFFFFBD88A6; nop; (p32) nop }

l4000000000114FC0:
	{ addl	r14,92,r0; adds	r8,0x0,r0; mov	pr,r42,0xFFFFFFFFFFFFFFFE; }
	{ st1	[r14],r33; mov.i	ar.pfs,r40; mov.i	LC,r43; }
	{ nop.m	0x0; mov.spnt	b0,r39,4000000000114FE0; br.ret	b0 }

l4000000000114FF0:
	{ addl	r17,-628,r1; ld8	r17,[r17]; nop.i	0x0; }
	{ shladd	r15,r15,0x3,r17; ld8	r17,[r15]; nop.i	0x0; }
	{ nop.m	0x0; add	r15,r15,r17; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r15,4000000000115020; br.cond	b6; }
4000000000115030 11 00 00 00 01 00 70 00 8C 0C 72 03 90 FF FF 4A ......p...r....J
4000000000115040 E9 00 38 42 80 11 00 00 00 02 00 00 00 00 04 00 ..8B............
4000000000115050 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000115060 09 40 20 40 05 20 00 00 00 02 00 00 00 00 04 00 .@ @. ..........
4000000000115070 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000115080 03 00 00 00 01 00 F0 57 C1 BF 05 00 80 02 AA 00 .......W........
4000000000115090 01 00 00 00 01 00 00 58 05 55 00 00 00 00 04 00 .......X.U......
40000000001150A0 10 00 00 00 01 00 00 38 05 80 03 80 08 00 84 00 .......8........
40000000001150B0 08 00 00 00 01 00 70 00 8C 0C 72 C0 01 75 FC 8C ......p...r..u..
40000000001150C0 0B 78 00 48 00 90 31 0A 00 00 48 E0 01 78 50 00 .x.H..1...H..xP.
40000000001150D0 E9 18 01 00 00 21 60 00 38 0E 73 E0 01 7D FC 8C .....!`.8.s..}..
40000000001150E0 CB 80 04 00 00 E4 01 01 00 00 42 00 00 00 04 00 ..........B.....
40000000001150F0 02 18 41 46 0C 20 00 01 3C 20 00 60 14 18 01 84 ..AF. ..< .`....
4000000000115100 19 30 1C 20 87 35 00 11 80 00 42 03 60 00 00 43 .0. .5....B.`..C
4000000000115110 03 18 0D 46 2C 20 00 00 00 02 00 00 30 0A AA 00 ...F, ......0...
4000000000115120 09 40 00 20 00 21 10 09 40 00 28 C0 E1 78 48 80 .@. .!..@.(..xH.
4000000000115130 03 00 00 00 01 00 F0 00 44 28 00 E0 01 7D FC 8C ........D(...}..
4000000000115140 01 00 00 00 01 00 10 01 3C 20 00 00 00 00 04 00 ........< ......
4000000000115150 12 30 1C 22 87 B5 01 08 00 80 21 A0 D0 FF FF 48 .0."......!....H
4000000000115160 08 00 38 42 80 11 00 00 00 02 00 00 00 00 04 00 ..8B............
4000000000115170 11 00 00 00 01 00 80 40 80 0A 40 00 10 FF FF 48 .......@..@....H
4000000000115180 09 70 6C 00 00 24 00 00 00 02 00 00 81 00 15 80 .pl..$..........
4000000000115190 10 00 38 42 80 11 00 00 00 02 00 00 F0 FE FF 48 ..8B...........H
40000000001151A0 09 00 00 00 01 00 E0 E0 02 00 48 00 00 00 04 00 ..........H.....
40000000001151B0 10 00 38 42 80 11 00 00 00 02 00 00 C0 FF FF 48 ..8B...........H
40000000001151C0 0B 38 D4 1D 86 B9 51 42 00 00 48 00 00 00 04 00 .8....QB..H.....
40000000001151D0 F1 28 11 00 00 24 00 00 00 02 00 00 F8 71 F0 58 .(...$.......q.X
40000000001151E0 08 80 80 48 05 20 10 00 A4 00 42 A0 04 28 59 00 ...H. ....B..(Y.
40000000001151F0 09 A0 00 10 18 10 F0 00 90 00 42 80 05 00 00 84 ..........B.....
4000000000115200 03 80 40 4A 01 20 30 01 00 40 48 00 00 09 AA 00 ..@J. 0..@H.....
4000000000115210 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000115220 09 28 01 1E 00 21 10 09 3C 00 28 00 00 00 04 00 .(...!..<.(.....
4000000000115230 03 00 00 00 01 00 10 01 44 28 00 00 02 88 40 00 ........D(....@.
4000000000115240 0B 90 40 28 10 20 20 01 48 10 20 00 00 00 04 00 ..@(.  .H. .....
4000000000115250 09 00 00 00 01 00 20 99 48 18 40 00 00 00 04 00 ...... .H.@.....
4000000000115260 13 30 00 24 87 B9 01 08 00 80 21 A0 A0 00 00 40 .0.$......!....@
4000000000115270 11 38 90 4A 06 38 E0 F8 03 02 C8 03 90 03 00 43 .8.J.8.........C
4000000000115280 09 00 00 00 01 00 60 70 B0 0E 68 00 00 00 04 00 ......`p..h.....
4000000000115290 F0 00 B0 42 80 D1 81 00 94 00 C2 03 D0 FD FF 4A ...B...........J
40000000001152A0 11 68 01 42 00 21 00 00 00 02 00 00 E8 1E 02 50 .h.B.!.........P
40000000001152B0 00 00 00 00 01 00 E0 00 20 2C 00 08 01 28 01 84 ........ ,...(..
40000000001152C0 0B 08 00 52 00 21 10 0A 39 00 40 00 00 00 04 00 ...R.!..9.@.....
40000000001152D0 11 00 00 42 80 11 00 00 00 02 00 08 90 FD FF 4B ...B...........K
40000000001152E0 09 00 20 44 90 11 00 00 00 02 00 00 01 28 01 84 .. D.........(..
40000000001152F0 10 00 00 00 01 00 80 40 80 0A 40 00 90 FD FF 48 .......@..@....H
4000000000115300 03 90 7C 20 3F 23 C0 62 01 26 40 40 02 90 40 00 ..| ?#.b.&@@..@.
4000000000115310 0B 30 14 24 87 F5 11 49 45 7E 46 00 00 00 04 00 .0.$...IE~F.....
4000000000115320 10 00 00 00 01 C0 11 01 44 2C 80 03 40 00 00 42 ........D,..@..B
4000000000115330 0B 80 FC 20 3F 23 00 00 00 02 00 00 02 80 40 00 ... ?#........@.
4000000000115340 0B 30 14 20 87 F5 11 49 46 7E 46 00 00 00 04 00 .0. ...IF~F.....
4000000000115350 C3 88 40 23 3F 23 00 00 00 02 00 20 02 88 58 00 ..@#?#..... ..X.
4000000000115360 10 00 00 00 01 00 C0 8A B0 00 40 00 C0 FE FF 48 ..........@....H
4000000000115370 09 70 1C 00 00 24 00 00 00 02 00 00 81 00 15 80 .p...$..........
4000000000115380 10 00 38 42 80 11 00 00 00 02 00 00 00 FD FF 48 ..8B...........H
4000000000115390 09 70 20 00 00 24 00 00 00 02 00 00 81 00 15 80 .p ..$..........
40000000001153A0 10 00 38 42 80 11 00 00 00 02 00 00 E0 FC FF 48 ..8B...........H
40000000001153B0 08 70 04 00 00 24 00 00 00 02 00 C0 00 18 1D E4 .p...$..........
40000000001153C0 19 40 20 40 05 20 00 00 00 02 00 03 00 FC FF 4B .@ @. .........K
40000000001153D0 10 00 38 46 90 11 00 00 00 02 00 00 B0 FC FF 48 ..8F...........H
40000000001153E0 09 70 30 00 00 24 00 00 00 02 00 00 81 00 15 80 .p0..$..........
40000000001153F0 10 00 38 42 80 11 00 00 00 02 00 00 90 FC FF 48 ..8B...........H
4000000000115400 09 70 28 00 00 24 00 00 00 02 00 00 81 00 15 80 .p(..$..........
4000000000115410 10 00 38 42 80 11 00 00 00 02 00 00 70 FC FF 48 ..8B........p..H
4000000000115420 09 70 34 00 00 24 00 00 00 02 00 00 81 00 15 80 .p4..$..........
4000000000115430 10 00 38 42 80 11 00 00 00 02 00 00 50 FC FF 48 ..8B........P..H
4000000000115440 09 70 24 00 00 24 00 00 00 02 00 00 81 00 15 80 .p$..$..........
4000000000115450 10 00 38 42 80 11 00 00 00 02 00 00 30 FC FF 48 ..8B........0..H
4000000000115460 09 70 2C 00 00 24 00 00 00 02 00 00 81 00 15 80 .p,..$..........
4000000000115470 10 00 38 42 80 11 00 00 00 02 00 00 10 FC FF 48 ..8B...........H
4000000000115480 11 00 00 00 01 00 00 00 00 02 00 00 48 6F F0 58 ............Ho.X
4000000000115490 08 08 00 52 00 21 E0 00 90 00 42 A0 42 00 01 84 ...R.!....B.B...
40000000001154A0 09 A0 00 10 18 10 20 01 00 00 42 60 02 00 80 90 ...... ...B`....
40000000001154B0 09 40 00 1C 00 21 00 09 38 00 28 00 00 00 04 00 .@...!..8.(.....
40000000001154C0 03 00 00 00 01 00 00 01 40 28 00 E0 01 80 40 00 ........@(....@.
40000000001154D0 0B 88 3C 28 10 20 10 01 44 10 20 00 00 00 04 00 ..<(. ..D. .....
40000000001154E0 09 00 00 00 01 00 10 99 44 18 40 00 00 00 04 00 ........D.@.....
40000000001154F0 11 30 00 22 87 39 10 F9 3C 7E 46 03 80 00 00 43 .0.".9..<~F....C
4000000000115500 11 38 54 1C 06 38 10 01 44 20 80 03 70 00 00 43 .8T..8..D ..p..C
4000000000115510 09 30 14 22 87 35 00 00 00 02 00 40 22 01 4C 80 .0.".5.....@".L.
4000000000115520 10 00 00 00 01 C0 01 49 41 7E C6 03 40 00 00 42 .......IA~..@..B
4000000000115530 09 00 00 00 01 00 F0 F8 3D 7E 46 00 00 00 04 00 ........=~F.....
4000000000115540 03 00 00 00 01 00 F0 00 3C 20 00 C0 50 78 1C D6 ........< ..Px..
4000000000115550 E3 80 24 21 3F 23 00 00 00 02 00 03 02 85 FC 8C ..$!?#..........
4000000000115560 10 00 00 00 01 00 20 91 40 00 40 00 50 FF FF 48 ...... .@.@.P..H
4000000000115570 09 00 00 00 01 00 70 20 21 0C 70 00 00 00 04 00 ......p !.p.....
4000000000115580 D0 00 48 42 80 11 00 00 00 02 00 03 E0 FA FF 4A ..HB...........J
4000000000115590 09 68 91 FA FA 27 E0 2A 00 00 48 80 05 00 00 84 .h...'.*..H.....
40000000001155A0 11 68 01 5A 18 10 00 00 00 02 00 00 C8 55 F0 58 .h.Z.........U.X
40000000001155B0 11 08 00 52 00 21 C0 02 20 00 42 00 D8 7F FD 58 ...R.!.. .B....X
40000000001155C0 18 70 70 01 00 24 80 00 00 00 42 00 00 00 00 20 .pp..$....B.... 
40000000001155D0 09 08 00 52 00 21 00 00 00 02 00 E0 AF 82 7F 0B ...R.!..........
40000000001155E0 03 00 38 42 80 11 00 40 01 55 00 00 B0 0A AA 00 ..8B...@.U......
40000000001155F0 10 00 00 00 01 00 00 38 05 80 03 80 08 00 84 00 .......8........
4000000000115600 09 68 B1 FA FA 27 E0 2A 00 00 48 80 05 00 00 84 .h...'.*..H.....
4000000000115610 11 68 01 5A 18 10 00 00 00 02 00 00 58 55 F0 58 .h.Z........XU.X
4000000000115620 08 08 00 52 00 21 00 00 00 02 00 80 05 40 00 84 ...R.!.......@..
4000000000115630 19 68 01 4C 00 21 00 00 00 02 00 00 58 7F FD 58 .h.L.!......X..X
4000000000115640 18 70 70 01 00 24 80 00 00 00 42 00 00 00 00 20 .pp..$....B.... 
4000000000115650 09 08 00 52 00 21 00 00 00 02 00 E0 AF 82 7F 0B ...R.!..........
4000000000115660 03 00 38 42 80 11 00 40 01 55 00 00 B0 0A AA 00 ..8B...@.U......
4000000000115670 11 00 00 00 01 00 00 38 05 80 03 80 08 00 84 00 .......8........

;; fn4000000000115680: 4000000000115680
;;   Called from:
;;     4000000000115D4C (in fn4000000000115B40)
;;     4000000000115E1C (in fn4000000000115D80)
;;     4000000000115E6C (in fn4000000000115D80)
fn4000000000115680 proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; addl	r38,-716,r1; mov	r34,b2 }
	{ adds	r36,0x0,r1; ld8	r38,[r38]; addl	r39,5,r0 }
	{ adds	r37,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r33,0x0,r8 }
	{ addl	r37,34,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B4A0; }
	{ adds	r1,0x0,r36; adds	r37,0x0,r33; nop.i	0x0 }
	{ adds	r38,0x0,r32; adds	r39,0x0,r8; br.call.sptk.many	b0,builtin_error; }
	{ adds	r1,0x0,r36; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000115700; br.ret	b0; }
4000000000115710 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000115720 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000115730 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000115740 08 60 55 1E 80 05 00 41 30 00 42 20 02 60 00 84 .`U....A0.B .`..
4000000000115750 09 60 00 19 3F 23 80 62 05 86 48 20 45 0A 0C 91 .`..?#.b..H E...
4000000000115760 18 70 01 48 22 04 00 3F 41 B2 2F 00 00 00 00 20 .p.H"..?A./.... 
4000000000115770 09 50 71 02 43 24 D0 02 04 00 42 60 05 00 C4 00 .Pq.C$....B`....
4000000000115780 08 80 9B 22 D9 17 00 2F 41 B2 2F 20 16 00 00 90 ...".../A./ ....
4000000000115790 09 90 FD F9 FF 27 30 03 80 00 42 80 86 61 00 84 .....'0...B..a..
40000000001157A0 09 80 93 22 D9 17 00 1F 41 B2 2F 00 00 00 04 00 ..."....A./.....
40000000001157B0 08 78 00 50 50 10 00 10 45 B0 23 00 00 00 04 00 .x.PP...E.#.....
40000000001157C0 0A 00 84 20 D8 11 F0 00 A0 20 22 00 00 00 04 00 ... ..... ".....
40000000001157D0 02 78 01 52 18 10 00 00 00 02 00 C0 01 78 58 00 .x.R.........xX.
40000000001157E0 09 00 00 00 01 00 00 03 A8 30 20 00 00 00 04 00 .........0 .....
40000000001157F0 11 78 BD 1C 00 20 00 83 39 0A 40 00 58 62 F0 58 .x... ..9.@.Xb.X
4000000000115800 08 00 00 00 01 00 E0 00 A0 20 20 20 00 68 01 84 .........   .h..
4000000000115810 0B 78 00 54 18 10 E0 40 38 00 40 00 00 00 04 00 .x.T...@8.@.....
4000000000115820 0B 80 05 1C 00 21 00 00 00 02 00 00 06 80 59 00 .....!........Y.
4000000000115830 11 30 C0 1E 07 34 F0 00 38 2C 80 03 50 00 00 43 .0...4..8,..P..C
4000000000115840 09 80 00 52 18 10 00 70 A0 20 23 00 00 00 04 00 ...R...p. #.....
4000000000115850 0B 70 40 1E 00 20 00 00 38 00 23 00 C0 02 AA 00 .p@.. ..8.#.....
4000000000115860 00 00 00 00 01 00 00 58 05 80 03 00 00 00 04 00 .......X........
4000000000115870 18 00 B8 48 2A 04 C0 00 32 00 42 80 08 00 84 00 ...H*...2.B.....
4000000000115880 09 80 FD 60 00 21 F0 02 A4 30 20 00 00 00 04 00 ...`.!...0 .....
4000000000115890 0A 70 00 61 2C 22 00 00 00 02 00 00 06 70 00 84 .p.a,".......p..
40000000001158A0 19 00 00 00 01 00 00 70 A8 30 23 00 68 35 FD 58 .......p.0#.h5.X
40000000001158B0 08 78 00 50 10 10 10 00 B4 00 42 20 16 00 00 90 .x.P......B ....
40000000001158C0 09 00 20 52 98 11 20 FB F3 FF 4F 60 06 00 01 84 .. R.. ...O`....
40000000001158D0 10 00 00 00 01 00 E0 00 3C 2C 00 00 00 00 00 20 ........<,..... 
40000000001158E0 09 80 01 54 18 10 00 00 00 02 00 80 86 61 00 84 ...T.........a..
40000000001158F0 11 78 21 1C 00 20 00 83 39 0A 40 00 58 61 F0 58 .x!.. ..9.@.Xa.X
4000000000115900 08 00 00 00 01 00 E0 00 A0 20 20 20 00 68 01 84 .........   .h..
4000000000115910 09 00 00 00 01 00 00 01 A4 30 20 00 00 00 04 00 .........0 .....
4000000000115920 02 70 20 1C 00 20 00 00 00 02 00 E0 01 70 58 00 .p .. .......pX.
4000000000115930 0B 00 38 50 90 11 E0 80 3C 00 40 00 00 00 04 00 ..8P....<.@.....
4000000000115940 02 00 00 1C 80 11 00 60 01 55 00 00 B0 0A 00 07 .......`.U......
4000000000115950 19 00 B8 48 2A 04 C0 00 32 00 42 80 08 00 84 00 ...H*...2.B.....
4000000000115960 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000115970 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000115980: 4000000000115980
;;   Called from:
;;     4000000000115CAC (in fn4000000000115B40)
fn4000000000115980 proc
	{ alloc	r37,ar.pfs,0xA,0x0,0x7; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ addl	r33,8636,r1; mov	r36,b4; adds	r38,0x0,r1; }
	{ ld8	r34,[r33]; nop.m	0x0; adds	r14,0x10,r12; }
	{ adds	r32,0x8,r34; st8	[r0],r14; nop.i	0x0; }
	{ ld8	r14,[r32]; ld8	r39,[r14]; nop.i	0x0; }
	{ adds	r39,0x1,r39; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r38; adds	r35,0x0,r8; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r38; nop.m	0x0; cmp.ltu	p07,p06,0x1,r8 }
	{ adds	r40,0x0,r35; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000115AE0; }

l4000000000115A10:
	{ ld8	r14,[r32]; ld8	r39,[r14]; nop.i	0x0; }
	{ adds	r39,0x1,r39; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AF80; }
	{ nop.m	0x0; sxt4	r8,r8; nop.b	0x0 }
	{ adds	r1,0x0,r38; adds	r39,0x18,r12; adds	r41,0x0,r35; }
	{ cmp.ltu	p07,p06,0x1,r8; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000115AE0; }

l4000000000115A60:
	{ ld8	r14,[r32]; ld8	r40,[r14]; nop.i	0x0; }
	{ adds	r40,0x1,r40; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C420; }
	{ adds	r14,0x18,r12; nop.m	0x0; adds	r1,0x0,r38; }
	{ ld4	r8,[r14]; ld8	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r8,r8; nop.i	0x0 }
	{ st8	[r14],r33; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,4000000000115AC0; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l4000000000115AE0:
	{ ld8	r14,[r32]; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; adds	r14,0x1,r14; nop.i	0x0; }
	{ ld1	r8,[r14]; ld8	r14,[r34]; nop.i	0x0; }
	{ st8	[r14],r33; mov.i	ar.pfs,r37; mov.spnt	b0,r36,4000000000115B10 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }
4000000000115B30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000115B40: 4000000000115B40
;;   Called from:
;;     4000000000115DAC (in fn4000000000115D80)
fn4000000000115B40 proc
	{ alloc	r38,ar.pfs,0xC,0x0,0x8; adds	r12,0xFFFFFFFFFFFFFFE0,r12; nop.b	0x0 }
	{ addl	r33,8636,r1; mov	r37,b5; adds	r39,0x0,r1; }
	{ ld8	r32,[r33]; adds	r35,0x8,r32; cmp.eq	p06,p07,0x0,r32; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000115C80; }

l4000000000115B76:
	{ chk.a.nc	r0,3FFFFFFFFF116376; nop; (p32) nop }

l4000000000115B80:
	{ ld8	r14,[r35]; ld8	r34,[r14]; nop.i	0x0; }
	{ nop.m	0x0; ld1	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x22,r14; }
	{ cmp4.eq.or.andcm	p07,p06,0x27,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000115CA0; }

l4000000000115BC0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ adds	r1,0x0,r39; adds	r36,0x0,r8; adds	r40,0x0,r34 }
	{ adds	r41,0x10,r12; adds	r42,0x0,r0; adds	r43,0x0,r0; }
	{ st4	[r0],r8; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A520; }
	{ adds	r15,0x10,r12; nop.m	0x0; adds	r1,0x0,r39; }
	{ ld8	r14,[r15]; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000115CD0; }

l4000000000115C40:
	{ nop.m	0x0; ld4	r14,[r36]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x22,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000115D30; }

l4000000000115C60:
	{ nop.m	0x0; ld8	r14,[r32]; nop.i	0x0; }
	{ st8	[r14],r33; nop.m	0x0; nop.i	0x0 }

l4000000000115C80:
	{ nop.m	0x0; mov.i	ar.pfs,r38; mov.spnt	b0,r37,4000000000115C80 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0; }

l4000000000115CA0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000115980; }
	{ adds	r1,0x0,r39; mov.i	ar.pfs,r38; mov.spnt	b0,r37,4000000000115CB0 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0 }

l4000000000115CD0:
	{ ld8	r14,[r35]; ld8	r40,[r14]; adds	r14,0x20,r12; }
	{ st8	[r8],r14; nop.i	0x0; br.call.sptk.many	b0,sh_invalidnum; }
	{ adds	r1,0x0,r39; ld8	r32,[r33]; addl	r15,1,r0; }
	{ addl	r14,8580,r1; st4	[r15],r14; adds	r15,0x20,r12 }
	{ ld8	r14,[r32]; nop.i	0x0; nop.i	0x0 }
	{ ld8	r8,[r15]; st8	[r14],r33; br.cond.sptk.few	4000000000115C80 }

l4000000000115D30:
	{ ld8	r14,[r35]; ld8	r40,[r14]; adds	r14,0x20,r12; }
	{ st8	[r8],r14; nop.i	0x0; br.call.sptk.many	b0,fn4000000000115680; }
	{ ld8	r32,[r33]; adds	r15,0x20,r12; adds	r1,0x0,r39; }
	{ ld8	r8,[r15]; ld8	r14,[r32]; nop.i	0x0; }
	{ st8	[r14],r33; nop.i	0x0; br.cond.sptk.few	4000000000115C80; }

;; fn4000000000115D80: 4000000000115D80
;;   Called from:
;;     40000000001185FC (in printf_builtin)
;;     400000000011920C (in printf_builtin)
fn4000000000115D80 proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; mov	r34,b2; adds	r36,0x0,r1; }
	{ nop.m	0x0; movl	r32,0x7FFFFFFF }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn4000000000115B40; }
	{ cmp.lt	p07,p06,r32,r8; adds	r1,0x0,r36; mov.i	ar.pfs,r35 }
	{ nop.m	0x0; movl	r33,0x803FFFFF80000000; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000115DD0; (p07) br.cond.dpnt.few	4000000000115E40; }

l4000000000115DE0:
	{ cmp.lt	p06,p07,r8,r33; (p06) br.cond.dpnt.few	4000000000115DF0; br.ret	b0 }

l4000000000115DEC:
	{ cmp.lt	p00,p11,r33,r0; (p01) cmp.lt	p47,p18,r96,r16; Invalid }

l4000000000115DF0:
	{ addl	r14,8636,r1; ld8	r14,[r14]; nop.i	0x0; }
	{ adds	r14,0x8,r14; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r37,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000115680; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r36; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000115E30; br.ret	b0 }

l4000000000115E40:
	{ addl	r14,8636,r1; ld8	r14,[r14]; nop.i	0x0; }
	{ adds	r14,0x8,r14; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r37,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000115680; }
	{ adds	r8,0x0,r32; adds	r1,0x0,r36; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000115E80; br.ret	b0; }
4000000000115E90 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000115EA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000115EB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000115EC0 08 38 31 12 80 05 00 00 00 02 00 C0 04 00 C4 00 .81.............
4000000000115ED0 09 40 01 02 00 21 00 00 00 02 00 20 05 00 01 84 .@...!..... ....
4000000000115EE0 11 00 00 00 01 00 00 00 00 02 00 00 E8 57 F0 58 .............W.X
4000000000115EF0 08 08 00 50 00 21 00 11 20 00 42 60 04 40 00 84 ...P.!.. .B`.@..
4000000000115F00 02 28 05 10 00 21 A0 02 80 00 42 C0 41 0C 0C 91 .(...!....B.A...
4000000000115F10 0B 20 FD 47 3F 23 F0 00 38 30 20 60 05 20 01 84 . .G?#..80 `. ..
4000000000115F20 11 30 3C 20 07 34 00 00 00 02 00 03 90 00 00 43 .0< .4.........C
4000000000115F30 E9 70 30 03 43 24 00 00 00 02 00 00 04 22 01 80 .p0.C$......."..
4000000000115F40 E2 10 01 1C 18 10 00 00 00 02 00 20 05 10 01 84 ........... ....
4000000000115F50 19 18 89 46 00 20 50 12 95 00 40 00 58 49 F0 58 ...F. P...@.XI.X
4000000000115F60 18 78 00 42 00 10 E0 10 91 00 40 00 00 00 00 20 .x.B......@.... 
4000000000115F70 09 40 00 44 00 21 10 00 A0 00 42 00 70 02 AA 00 .@.D.!....B.p...
4000000000115F80 09 00 3C 1C 80 11 00 00 00 02 00 00 60 0A 00 07 ..<.........`...
4000000000115F90 09 70 00 40 00 10 00 00 94 00 23 00 00 00 04 00 .p.@......#.....
4000000000115FA0 10 00 38 46 80 11 00 00 00 02 00 80 08 00 84 00 ..8F............
4000000000115FB0 09 80 04 10 08 21 F0 00 F0 F1 4F 80 C4 0C 0C 91 .....!....O.....
4000000000115FC0 09 78 3C 20 0C 20 90 02 90 30 20 00 00 00 04 00 .x< . ...0 .....
4000000000115FD0 08 00 00 00 01 00 A0 02 3C 00 42 00 00 00 04 00 ........<.B.....
4000000000115FE0 19 00 3C 1C 98 11 00 00 00 02 00 00 28 2E FD 58 ..<.........(..X
4000000000115FF0 08 10 01 10 00 21 00 40 90 30 23 00 00 00 04 00 .....!.@.0#.....
4000000000116000 09 20 FD 47 3F 23 10 00 A0 00 42 40 05 00 01 84 . .G?#....B@....
4000000000116010 08 48 01 44 00 21 B0 02 90 00 42 00 04 22 01 80 .H.D.!....B.."..
4000000000116020 19 18 89 46 00 20 50 12 95 00 40 00 88 48 F0 58 ...F. P...@..H.X
4000000000116030 18 78 00 42 00 10 E0 10 91 00 40 00 00 00 00 20 .x.B......@.... 
4000000000116040 09 40 00 44 00 21 10 00 A0 00 42 00 70 02 AA 00 .@.D.!....B.p...
4000000000116050 09 00 3C 1C 80 11 00 00 00 02 00 00 60 0A 00 07 ..<.........`...
4000000000116060 02 70 00 40 00 10 00 00 00 02 00 00 00 00 04 00 .p.@............
4000000000116070 19 00 38 46 80 11 00 00 94 00 23 80 08 00 84 00 ..8F......#.....

;; fn4000000000116080: 4000000000116080
;;   Called from:
;;     400000000011873C (in printf_builtin)
;;     4000000000118E8C (in printf_builtin)
;;     4000000000118FAC (in printf_builtin)
;;     4000000000118FFC (in printf_builtin)
fn4000000000116080 proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; nop.m	0x0; mov	r34,b2 }
	{ adds	r36,0x0,r1; nop.m	0x0; adds	r37,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,valid_array_reference; }
	{ cmp4.eq	p07,p06,0x0,r8; adds	r1,0x0,r36; adds	r37,0x0,r32 }
	{ adds	r38,0x0,r33; adds	r39,0x0,r0; (p07) br.cond.dpnt.few	4000000000116100; }

l40000000001160D0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,assign_array_element; }
	{ adds	r1,0x0,r36; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000001160F0; br.ret	b0; }

l4000000000116100:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r1,0x0,r36; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000116120; br.ret	b0; }
4000000000116130 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000116140: 4000000000116140
;;   Called from:
;;     4000000000116D5C (in printf_builtin)
;;     400000000011736C (in printf_builtin)
;;     400000000011853C (in printf_builtin)
fn4000000000116140 proc
	{ alloc	r36,ar.pfs,0x8,0x0,0x6; addl	r33,8620,r1; nop.b	0x0 }
	{ addl	r14,8604,r1; mov	r35,b3; adds	r37,0x0,r1; }
	{ nop.m	0x0; ld4	r15,[r33]; mov.i	ar.pfs,r36 }
	{ ld8	r16,[r14]; adds	r39,0x2,r15; mov.spnt	b0,r35,4000000000116170; }
	{ nop.m	0x0; sxt4	r39,r39; cmp.ltu	p07,p06,r39,r16 }
	{ adds	r16,0x1,r15; sxt4	r15,r15; (p06) br.cond.dpnt.few	40000000001161F0; }

l40000000001161A0:
	{ (p07) addl	r14,8612,r1; nop.m	0x0; sxt4	r18,r16 }

l40000000001161A6:
	{ break.m	0x4000; (p09) nop; (p16) nop }
	{ mf.a; cmp.ltu	p00,p00,0x0,r1; (p33) nop }

l40000000001161C6:
	{ Invalid; Invalid; (p32) nop }
	{ break.m	0x4000; nop; nop }
	{ mf.a; (p34) nop; (p48) nop }

l40000000001161F0:
	{ adds	r39,0x3F,r39; nop.m	0x0; addl	r34,8612,r1; }
	{ and	r39,0xFFFFFFFFFFFFFFC0,r39; ld8	r38,[r34]; nop.i	0x0; }
	{ st8	[r39],r14; nop.i	0x0; br.call.sptk.many	b0,xrealloc; }
	{ ld4	r15,[r33]; adds	r14,0x0,r8; mov.i	ar.pfs,r36 }
	{ st8	[r8],r34; ld1	r17,[r32]; adds	r1,0x0,r37; }
	{ adds	r16,0x1,r15; adds	r8,0x0,r14; mov.spnt	b0,r35,4000000000116240 }
	{ nop.m	0x0; sxt4	r15,r15; sxt4	r18,r16 }
	{ add	r15,r14,r15; st4	[r16],r33; nop.i	0x0; }
	{ add	r14,r14,r18; st1	[r17],r15; nop.i	0x0; }
	{ st1	[r0],r14; nop.i	0x0; br.ret	b0; }
4000000000116290 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001162A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001162B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001162C0 08 68 4D 22 80 05 C0 80 33 7E 46 E0 05 00 CC 00 .hM"....3~F.....
40000000001162D0 09 28 01 40 00 10 10 E3 F5 F5 4F C0 05 08 00 84 .(.@......O.....
40000000001162E0 00 00 00 00 01 00 C0 02 00 62 00 A0 04 28 51 00 .........b...(Q.
40000000001162F0 19 88 01 62 18 10 90 02 00 00 42 00 00 00 00 20 ...b......B.... 
4000000000116300 09 38 94 4A 86 39 00 00 00 02 00 00 06 08 CA 00 .8.J.9..........
4000000000116310 EB 00 05 40 00 E1 51 02 80 00 20 00 14 00 01 84 ...@..Q... .....
4000000000116320 01 00 00 00 01 C0 51 02 94 28 00 E0 F4 07 FD 8C ......Q..(......
4000000000116330 11 90 01 4A 00 21 00 00 00 02 00 00 58 53 F0 58 ...J.!......XS.X
4000000000116340 08 00 00 00 01 00 60 68 95 0E 73 20 00 70 01 84 ......`h..s .p..
4000000000116350 19 00 00 00 01 00 90 00 20 10 F2 04 70 00 00 43 ........ ...p..C
4000000000116360 09 28 05 40 00 14 10 E3 F5 F5 4F 23 15 00 00 90 .(.@......O#....
4000000000116370 10 00 00 00 01 00 50 02 94 28 00 00 00 00 00 20 ......P..(..... 
4000000000116380 09 88 01 62 18 10 00 00 00 02 00 E0 F4 07 FD 8C ...b............
4000000000116390 11 90 01 4A 00 21 00 00 00 02 00 00 F8 52 F0 58 ...J.!.......R.X
40000000001163A0 08 00 00 00 01 00 10 00 B8 00 42 C0 D0 2A 1D E6 ..........B..*..
40000000001163B0 19 00 00 00 01 00 90 00 20 10 72 04 B0 FF FF 4A ........ .r....J
40000000001163C0 08 70 40 4B 3F 23 00 00 00 02 00 E0 A0 2A 19 E6 .p@K?#.......*..
40000000001163D0 19 78 04 40 00 21 00 00 00 02 80 03 30 05 00 43 .x.@.!......0..C
40000000001163E0 03 18 01 1C 00 21 E0 00 38 20 00 C0 90 70 1C D6 .....!..8 ...p..
40000000001163F0 10 00 00 00 01 80 31 02 00 00 42 03 90 00 00 42 ......1...B....B
4000000000116400 03 28 01 40 00 10 70 02 80 00 42 A0 04 28 51 00 .(.@..p...B..(Q.
4000000000116410 0B 70 40 4B 3F 23 00 00 00 02 00 00 02 70 40 00 .p@K?#.......p@.
4000000000116420 11 00 00 00 01 00 60 48 40 0E 6B 03 60 00 00 43 ......`H@.k.`..C
4000000000116430 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000116440 09 38 01 1E 00 21 50 0A 3C 00 28 60 34 1A 45 80 .8...!P.<.(`4.E.
4000000000116450 01 00 00 00 01 00 50 02 94 28 00 60 34 72 40 80 ......P..(.`4r@.
4000000000116460 0B 70 40 4B 3F 23 00 00 00 02 00 00 02 70 40 00 .p@K?#.......p@.
4000000000116470 11 00 00 00 01 00 70 48 40 0C 6B 03 D0 FF FF 4A ......pH@.k....J
4000000000116480 11 00 00 00 01 00 70 70 95 0C F3 03 70 03 00 43 ......pp....p..C
4000000000116490 C9 20 01 44 00 21 00 00 00 02 00 00 00 00 04 00 . .D.!..........
40000000001164A0 08 18 8D 48 05 20 60 00 A4 0E 73 40 C5 EE BF 9E ...H. `...s@....
40000000001164B0 09 28 D1 02 43 24 70 8A 30 00 42 00 C5 08 0C 91 .(..C$p.0.B.....
40000000001164C0 08 00 00 00 01 00 90 18 01 10 61 60 05 02 00 90 ..........a`....
40000000001164D0 0B 50 01 54 18 10 62 02 8C 00 42 00 00 00 04 00 .P.T..b...B.....
40000000001164E0 2B 31 01 00 00 21 E0 F8 9B 7E C6 C3 04 30 15 80 +1...!...~...0..
40000000001164F0 10 00 00 00 01 C0 11 01 98 20 F3 03 B0 00 00 42 ......... .....B
4000000000116500 08 00 00 00 01 00 70 00 98 0C 63 C0 E1 00 20 80 ......p...c... .
4000000000116510 19 00 00 00 01 00 00 00 00 02 00 03 50 04 00 41 ............P..A
4000000000116520 01 00 00 00 01 C0 01 70 04 55 00 00 00 00 04 00 .......p.U......
4000000000116530 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000116540 08 78 00 4A 18 10 00 00 00 02 00 20 06 61 00 84 .x.J....... .a..
4000000000116550 09 00 00 4E 80 11 E0 00 A0 20 20 00 00 00 04 00 ...N.....  .....
4000000000116560 09 78 04 1E 00 21 00 58 C5 00 23 C0 00 70 1C E6 .x...!.X..#..p..
4000000000116570 10 00 3C 4A 98 11 00 00 00 02 00 03 40 02 00 42 ..<J........@..B
4000000000116580 11 30 FD 4D 3F 23 00 00 00 02 00 00 C8 FB FF 58 .0.M?#.........X
4000000000116590 11 88 00 4C 90 39 10 00 B8 00 42 A0 B0 FF FF 48 ...L.9....B....H
40000000001165A0 08 70 FC 49 3F 23 60 00 90 0E 63 E0 14 61 00 84 .p.I?#`...c..a..
40000000001165B0 19 28 D1 02 43 24 80 62 04 86 C8 03 A0 00 00 43 .(..C$.b.......C
40000000001165C0 03 70 38 00 08 20 00 00 00 02 00 03 E0 08 AA 00 .p8.. ..........
40000000001165D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001165E0 08 78 00 4A 18 10 00 00 00 02 00 20 06 61 00 84 .x.J....... .a..
40000000001165F0 09 00 00 4E 80 11 E0 08 84 00 28 00 00 00 04 00 ...N......(.....
4000000000116600 00 00 00 00 01 00 E0 00 38 28 00 00 12 78 00 84 ........8(...x..
4000000000116610 0A 78 00 50 10 10 00 80 94 30 23 00 00 00 04 00 .x.P.....0#.....
4000000000116620 18 00 38 62 80 11 60 00 3C 0E 73 03 50 01 00 42 ..8b..`.<.s.P..B
4000000000116630 11 00 00 00 01 00 00 00 00 02 00 00 18 FB FF 58 ...............X
4000000000116640 11 00 00 00 01 00 10 00 B8 00 42 A0 A0 FF FF 48 ..........B....H
4000000000116650 08 30 FD 4D 2D 22 50 A2 05 86 48 E0 14 61 00 84 .0.M-"P...H..a..
4000000000116660 19 40 31 02 43 24 90 02 01 00 C8 08 80 00 00 43 .@1.C$.........C
4000000000116670 03 30 99 00 08 20 00 00 00 02 00 00 60 0A AA 00 .0... ......`...
4000000000116680 08 78 00 4A 18 10 00 00 00 02 00 20 06 61 00 84 .x.J....... .a..
4000000000116690 09 00 00 4E 80 11 E0 00 A0 20 20 00 00 00 04 00 ...N.....  .....
40000000001166A0 09 78 04 1E 00 21 00 48 C5 00 23 C0 00 70 1C E6 .x...!.H..#..p..
40000000001166B0 10 00 3C 4A 98 11 00 00 00 02 00 03 80 00 00 42 ..<J...........B
40000000001166C0 11 00 00 00 01 00 00 00 00 02 00 00 88 FA FF 58 ...............X
40000000001166D0 10 00 00 00 01 00 10 00 B8 00 42 A0 B0 FF FF 48 ..........B....H
40000000001166E0 11 88 01 54 18 10 00 00 00 02 00 00 88 42 F0 58 ...T.........B.X
40000000001166F0 03 38 00 10 86 39 10 00 B8 00 42 03 F1 E7 FF 9F .8...9....B.....
4000000000116700 E3 40 00 00 00 21 F0 7F C1 BF 05 00 D0 02 AA 00 .@...!..........
4000000000116710 02 00 00 00 01 00 00 80 05 55 00 00 C0 0A 00 07 .........U......
4000000000116720 19 00 00 00 01 00 C0 80 30 00 42 80 08 00 84 00 ........0.B.....
4000000000116730 08 00 00 00 01 00 10 03 01 00 48 00 00 00 04 00 ..........H.....
4000000000116740 19 90 01 54 18 10 00 00 00 02 00 00 88 47 F0 58 ...T.........G.X
4000000000116750 10 00 00 00 01 00 10 00 B8 00 42 A0 30 FF FF 48 ..........B.0..H
4000000000116760 10 00 00 00 01 00 00 00 00 02 00 00 80 FF FF 48 ...............H
4000000000116770 08 00 00 00 01 00 10 03 38 00 42 00 00 00 04 00 ........8.B.....
4000000000116780 19 90 01 54 18 10 00 00 00 02 00 00 48 47 F0 58 ...T........HG.X
4000000000116790 10 00 00 00 01 00 10 00 B8 00 42 A0 50 FE FF 48 ..........B.P..H
40000000001167A0 10 00 00 00 01 00 00 00 00 02 00 00 B0 FE FF 48 ...............H
40000000001167B0 08 30 FD 4D 3F 23 00 00 00 02 00 20 06 02 00 90 .0.M?#..... ....
40000000001167C0 19 90 01 54 18 10 00 00 00 02 00 00 08 47 F0 58 ...T.........G.X
40000000001167D0 10 88 00 4C 90 39 10 00 B8 00 42 A0 70 FD FF 48 ...L.9....B.p..H
40000000001167E0 10 00 00 00 01 00 00 00 00 02 00 00 C0 FD FF 48 ...............H
40000000001167F0 09 70 04 4E 00 21 00 11 9C 00 42 E0 34 38 01 84 .p.N.!....B.48..
4000000000116800 0B 70 00 1C 00 10 00 00 00 02 00 C0 01 70 50 00 .p...........pP.
4000000000116810 11 78 40 1D 3F 23 60 50 39 0E 73 03 B0 00 00 43 .x@.?#`P9.s....C
4000000000116820 01 00 00 00 01 00 E0 00 3C 20 00 80 04 10 01 84 ........< ......
4000000000116830 10 00 00 00 01 00 60 48 38 0E 6B 03 70 FC FF 4A ......`H8.k.p..J
4000000000116840 03 70 00 20 00 10 40 02 3C 00 42 C0 01 70 50 00 .p. ..@.<.B..pP.
4000000000116850 0B 70 40 1D 3F 23 00 00 00 02 00 E0 01 70 40 00 .p@.?#.......p@.
4000000000116860 11 00 00 00 01 00 60 48 3C 0E 6B 03 60 00 00 43 ......`H<.k.`..C
4000000000116870 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000116880 09 78 04 4E 00 14 00 00 00 02 00 80 44 22 45 80 .x.N........D"E.
4000000000116890 01 00 00 00 01 00 F0 00 3C 28 00 80 44 72 40 80 ........<(..Dr@.
40000000001168A0 0B 70 40 1F 3F 23 00 00 00 02 00 E0 01 70 40 00 .p@.?#.......p@.
40000000001168B0 11 00 00 00 01 00 70 48 3C 0C 6B 03 D0 FF FF 4A ......pH<.k....J
40000000001168C0 09 38 88 48 86 30 00 00 00 02 00 C0 F1 27 B5 88 .8.H.0.......'..
40000000001168D0 C3 78 04 00 00 24 E0 F0 39 00 A9 E3 01 00 00 84 .x...$..9.......
40000000001168E0 0B 70 38 1E 0C 20 60 00 38 0E 73 00 00 00 04 00 .p8.. `.8.s.....
40000000001168F0 10 00 00 00 01 80 41 02 88 00 42 00 B0 FB FF 48 ......A...B....H
4000000000116900 09 30 8C 00 87 30 00 00 00 02 00 E0 04 00 01 84 .0...0..........
4000000000116910 E8 28 01 40 00 90 31 02 8C 0A 40 23 15 00 00 90 .(.@..1...@#....
4000000000116920 CB 70 00 40 00 10 00 00 00 02 80 A3 04 28 51 00 .p.@.........(Q.
4000000000116930 03 00 00 00 01 80 51 02 38 28 00 E0 E0 2A 19 E6 ......Q.8(...*..
4000000000116940 10 00 00 00 01 80 41 02 88 00 42 03 60 FB FF 4A ......A...B.`..J
4000000000116950 11 00 00 00 01 00 00 00 00 02 00 00 A0 FE FF 48 ...............H
4000000000116960 08 70 FC 49 3F 23 60 00 90 0E 63 40 C5 EE BF 9E .p.I?#`...c@....
4000000000116970 09 88 00 4C 90 39 70 8A 30 00 42 A0 44 0B 0C 91 ...L.9p.0.B.D...
4000000000116980 09 70 38 00 08 20 A0 02 A8 30 20 00 C5 08 0C 91 .p8.. ...0 .....
4000000000116990 10 00 00 00 01 80 01 70 04 55 00 03 50 FC FF 4A .......p.U..P..J
40000000001169A0 11 00 00 00 01 00 00 00 00 02 00 00 B0 FC FF 48 ...............H
40000000001169B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; printf_builtin: 40000000001169C0
printf_builtin proc
	{ alloc	r73,ar.pfs,0x31,0x0,0x2B; adds	r16,0x0,r12; adds	r12,0xFFFFFFFFFFFFFEB0,r12 }
	{ addl	r46,8580,r1; addl	r45,8584,r1; addl	r34,8588,r1; }
	{ addl	r36,9252,r1; stf.spill	[r16],f2; nop.b	0x0 }
	{ adds	r74,0x0,r1; mov	r72,b0; addl	r33,8596,r1; }
	{ st4	[r0],r46; st4	[r0],r45; nop.i	0x0 }
	{ nop.m	0x0; addl	r39,1,r0; addl	r40,16,r0; }
	{ st4	[r0],r34; nop.i	0x0; br.call.sptk.many	b0,reset_internal_getopt; }
	{ adds	r1,0x0,r74; adds	r75,0x0,r32; addl	r76,-692,r1 }
	{ addl	r35,8604,r1; addl	r38,8612,r1; addl	r37,8620,r1; }
	{ ld8	r76,[r76]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r74; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dpnt.few	4000000000116B80; }

l4000000000116A70:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000116A80:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x76,r8; (p06) br.cond.dpnt.few	4000000000116AD0 }

l4000000000116A90:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ nop.m	0x0; adds	r1,0x0,r74; addl	r8,258,r0 }

l4000000000116AB0:
	{ adds	r17,0x150,r12; mov.i	ar.pfs,r73; mov.spnt	b0,r72,4000000000116AB0 }
	{ ldf.fill	f2,[r17]; adds	r12,0x150,r12; br.ret	b0 }

l4000000000116AD0:
	{ nop.m	0x0; ld8	r75,[r36]; nop.i	0x0; }
	{ st8	[r75],r33; nop.i	0x0; br.call.sptk.many	b0,legal_identifier; }
	{ adds	r1,0x0,r74; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	4000000000116FC0 }

l4000000000116B00:
	{ ld8	r14,[r35]; st4	[r39],r34; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000117030; }

l4000000000116B20:
	{ (p07) ld8	r8,[r38]; st4	[r0],r37; nop.i	0x0; }

l4000000000116B26:
	{ mf.a; nop; break.i	0x80000 }
	{ Invalid; cmp.ltu	p00,p00,r0,r1; (p01) nop }

l4000000000116B46:
	{ break.m	0x4000; nop; nop }

l4000000000116B50:
	{ addl	r76,-692,r1; nop.m	0x0; adds	r75,0x0,r32; }
	{ ld8	r76,[r76]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r74; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p06) br.cond.dptk.few	4000000000116A80; }

l4000000000116B80:
	{ addl	r14,9268,r1; addl	r58,7668,r1; addl	r50,8636,r1 }
	{ adds	r62,0x20,r12; addl	r43,-10260,r1; addl	r63,-620,r1; }
	{ nop.m	0x0; addl	r67,8892,r1; adds	r39,0x11,r12 }
	{ addl	r35,8628,r1; adds	r61,0x0,r50; addl	r64,39,r0; }
	{ adds	r69,0x8,r62; adds	r52,0xC0,r12; addl	r68,115,r0 }
	{ addl	r66,37,r0; addl	r65,88,r0; adds	r40,0x90,r12; }
	{ nop.m	0x0; ld8	r48,[r14]; adds	r55,0x98,r12 }
	{ adds	r54,0xA0,r12; adds	r53,0xA8,r12; adds	r41,0xC8,r12; }
	{ adds	r14,0x8,r48; cmp.eq	p07,p06,0x0,r48; (p07) br.cond.dpnt.few	4000000000116A90; }

l4000000000116C10:
	{ ld8	r14,[r14]; ld8	r49,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r49; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000118580; }

l4000000000116C30:
	{ ld1	r14,[r49]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000118580; }

l4000000000116C50:
	{ nop.m	0x0; ld8	r15,[r48]; nop.i	0x0; }
	{ st8	[r15],r50; ld8	r43,[r43]; nop.i	0x0 }
	{ ld8	r63,[r63]; ld4	r14,[r58]; nop.i	0x0 }
	{ nop.m	0x0; nop.i	0x0; adds	r14,0x1,r14; }
	{ st4	[r14],r58; nop.m	0x0; nop.i	0x0 }

l4000000000116CA0:
	{ ld1	r14,[r49]; st8	[r0],r35; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	4000000000116DA0; }

l4000000000116CD0:
	{ (p06) adds	r42,0x0,r49; nop.m	0x0; nop.i	0x0; }

l4000000000116CD6:
	{ break.m	0x4000; nop; (p48) nop }

l4000000000116CE0:
	{ cmp4.eq	p07,p06,0x5C,r14; adds	r17,0x10,r12; (p07) br.cond.dpnt.few	40000000001172A0; }

l4000000000116CE2:
	{ (p43) chk.a.nc	r67,40000000005252F2; (p02) add	r3,r64,r112,0x1; nop }

l4000000000116CF0:
	{ cmp4.eq	p06,p07,0x25,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001170B0; }

l4000000000116D00:
	{ ld8	r16,[r35]; st1	[r14],r17; nop.i	0x0 }
	{ st1	[r0],r39; ld4	r15,[r34]; nop.i	0x0; }
	{ adds	r16,0x1,r16; nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; }
	{ st8	[r16],r35; nop.i	0x0; (p06) br.cond.dptk.few	4000000000117070 }

l4000000000116D40:
	{ nop.m	0x0; adds	r75,0x0,r17; adds	r42,0x1,r42 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn4000000000116140; }
	{ adds	r1,0x0,r74; nop.m	0x0; nop.i	0x0 }

l4000000000116D70:
	{ adds	r36,0x0,r42; ld1	r14,[r36]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000116CE0 }

l4000000000116DA0:
	{ ld8	r75,[r43]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A960; }
	{ adds	r1,0x0,r74; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dpnt.few	4000000000119CA0; }

l4000000000116DC0:
	{ nop.m	0x0; ld8	r14,[r50]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000116E00; }

l4000000000116DE0:
	{ nop.m	0x0; ld8	r15,[r48]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r15,r14; (p06) br.cond.dptk.few	4000000000116CA0 }

l4000000000116E00:
	{ ld4	r14,[r46]; cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; }
	{ nop.m	0x0; (p07) addl	r14,1,r0; nop.i	0x0; }

l4000000000116E1C:
	{ Invalid; Invalid; break.i	0x1000 }

l4000000000116E26:
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ (p07) fwb; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	f0,3FFFFFFFFFDDA726; addl	r26,1052804,r0; (p17) nop }

l4000000000116E50:
	{ (p06) addl	r33,8612,r1; nop.m	0x0; nop.i	0x0 }

l4000000000116E56:
	{ break.m	0x4000; nop; (p48) nop }
	{ add	r0,r0,r1; (p07) nop; break.i	0x80000 }
	{ (p07) fwb; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	f15,3FFFFFFFFFB19F66; nop; (p32) brp.sptk	b7,4000000000116F06 }

l4000000000116E90:
	{ addl	r34,8604,r1; nop.m	0x0; addl	r15,4096,r0; }
	{ nop.m	0x0; ld8	r14,[r34]; nop.i	0x0; }
	{ cmp.ltu	p07,p06,r15,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000119C00; }

l4000000000116EC0:
	{ ld8	r14,[r33]; ld8.a	r75,[r43]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; (p07) st1	[r0],r14; nop.i	0x0; }

l4000000000116EDC:
	{ cmp.lt	p00,p09,r1,r0; (p01) nop; Invalid }
	{ nop; cmp.lt	p00,p00,r32,r0; zxt2	r95,r79 }
	{ Invalid; Invalid; break.i	0x1000 }
	{ (p60) nop; nop; zxt1	r64,r64 }
	{ ldfpd	f0,f1,[r0]; Invalid; break.i	0x1000 }
	{ (p18) cmp.lt	p07,p09,r60,r44; flushrs; nop }
	{ Invalid; Invalid; mov	pr,r32,0x0 }

l4000000000116F46:
	{ chk.a.nc	r0,3FFFFFFFFF117746; nop; break.i	0x80000 }

l4000000000116F50:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_wrerror; }
	{ adds	r1,0x0,r74; addl	r14,-10260,r1; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r75,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BE00; }
	{ nop.m	0x0; adds	r1,0x0,r74; addl	r8,1,r0 }

l4000000000116FA0:
	{ adds	r17,0x150,r12; mov.i	ar.pfs,r73; mov.spnt	b0,r72,4000000000116FA0 }
	{ ldf.fill	f2,[r17]; adds	r12,0x150,r12; br.ret	b0; }

l4000000000116FC0:
	{ ld8	r75,[r33]; nop.i	0x0; br.call.sptk.many	b0,valid_array_reference; }
	{ adds	r1,0x0,r74; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	4000000000116B00; }

l4000000000116FE0:
	{ nop.m	0x0; addl	r14,8596,r1; nop.i	0x0; }
	{ ld8	r75,[r14]; nop.i	0x0; br.call.sptk.many	b0,sh_invalidid; }
	{ addl	r8,258,r0; adds	r1,0x0,r74; nop.b	0x0 }
	{ adds	r17,0x150,r12; mov.i	ar.pfs,r73; mov.spnt	b0,r72,4000000000117010 }
	{ ldf.fill	f2,[r17]; adds	r12,0x150,r12; br.ret	b0; }

l4000000000117030:
	{ st8	[r40],r35; addl	r75,16,r0; br.call.sptk.many	b0,xmalloc; }
	{ cmp.eq	p06,p07,0x0,r8; nop.m	0x0; adds	r1,0x0,r74 }
	{ st8	[r8],r38; st4	[r0],r37; nop.i	0x0; }
	{ (p07) st1	[r0],r8; nop.i	0x0; br.cond.sptk.few	4000000000116B50 }

l4000000000117066:
	{ break.m	0x4000; nop; break.i	0x80000 }

l4000000000117070:
	{ nop.m	0x0; ld1	r75,[r42]; adds	r42,0x1,r42 }
	{ nop.m	0x0; ld8	r76,[r43]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r75,r75; br.call.sptk.many	b0,fn400000000001AEC0; }
	{ nop.m	0x0; adds	r1,0x0,r74; br.cond.sptk.few	4000000000116D70 }

l40000000001170B0:
	{ adds	r44,0x1,r42; ld1	r36,[r44]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r36,r36; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x25,r36; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001184E0; }

l40000000001170E0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r36; (p07) br.cond.dpnt.few	4000000000117160; }

l40000000001170F0:
	{ adds	r33,0x0,r44; nop.m	0x0; nop.i	0x0; }

l4000000000117100:
	{ addl	r75,-708,r1; nop.m	0x0; adds	r76,0x0,r36; }
	{ ld8	r75,[r75]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B680; }
	{ adds	r1,0x0,r74; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	4000000000117420; }

l4000000000117130:
	{ adds	r33,0x1,r33; ld1	r36,[r33]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r36,r36; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r36; (p06) br.cond.dptk.few	4000000000117100 }

l4000000000117160:
	{ addl	r76,-676,r1; addl	r77,5,r0; adds	r75,0x0,r0; }
	{ ld8	r76,[r76]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r74; nop.m	0x0; adds	r75,0x0,r8 }
	{ adds	r76,0x0,r42; nop.m	0x0; br.call.sptk.many	b0,builtin_error; }
	{ adds	r1,0x0,r74; ld4	r14,[r34]; addl	r15,4096,r0; }
	{ addl	r35,8644,r1; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	4000000000118720; }

l40000000001171C0:
	{ ld8	r14,[r35]; nop.m	0x0; (p06) addl	r33,8612,r1; }

l40000000001171D0:
	{ nop.m	0x0; cmp.ltu	p07,p06,r15,r14; (p07) br.cond.dpnt.few	4000000000119060 }

l40000000001171E0:
	{ addl	r34,8604,r1; nop.m	0x0; addl	r15,4096,r0; }
	{ nop.m	0x0; ld8	r14,[r34]; nop.i	0x0; }
	{ cmp.ltu	p07,p06,r15,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000119B70; }

l4000000000117210:
	{ ld8	r14,[r33]; ld8.a	r75,[r43]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; (p07) st1	[r0],r14; nop.i	0x0; }

l400000000011722C:
	{ cmp.lt	p00,p09,r1,r0; (p01) nop; Invalid }
	{ nop; cmp.lt	p00,p00,r32,r0; zxt2	r95,r79 }
	{ Invalid; Invalid; break.i	0x1000 }
	{ (p33) nop; nop; epc }
	{ ldfpd	f0,f1,[r0]; Invalid; break.i	0x1000 }
	{ (p55) nop; cmp.eq.unc	p00,p16,r18,r64; nop }
	{ (p38) invala; break.i	0x1000; (p17) nop }

l4000000000117290:
	{ nop.m	0x0; addl	r8,1,r0; br.cond.sptk.few	4000000000116FA0 }

l40000000001172A0:
	{ adds	r42,0x1,r42; st8	[r0],r40; adds	r76,0x0,r40 }
	{ st8	[r0],r55; adds	r77,0x0,r41; adds	r78,0x0,r0; }
	{ adds	r75,0x0,r42; st8	[r0],r54; nop.i	0x0 }
	{ st1	[r0],r53; nop.m	0x0; br.call.sptk.many	b0,fn4000000000114F40; }
	{ ld4	r14,[r41]; sxt4	r8,r8; adds	r1,0x0,r74; }
	{ cmp4.lt	p06,p07,0x0,r14; add	r42,r42,r8; (p07) br.cond.dpnt.few	4000000000116D70; }

l4000000000117300:
	{ nop.m	0x0; (p06) adds	r33,0x0,r40; nop.i	0x0 }

l400000000011730C:
	{ cmp.lt	p00,p09,r1,r0; Invalid; Invalid }
	{ cmp.eq	p00,p08,r1,r0; (p17) nop; (p25) mov.i	KR0,0x8 }
	{ cmp.lt	p00,p02,r1,r0; Invalid; nop }
	{ nop; (p48) cmp.eq.unc	p35,p08,r8,r102; (p01) cmp.lt	p04,p16,r3,r64; }
	{ Invalid; Invalid; mov	pr,r32,0x0 }
	{ (p04) ldfps	f0,f0,[r33]; zxt1	r96,r64; break.b	0x1000 }

l4000000000117360:
	{ adds	r75,0x0,r15; nop.i	0x0; br.call.sptk.many	b0,fn4000000000116140; }
	{ sub	r15,r33,r40; ld4	r14,[r41]; adds	r1,0x0,r74; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r15,r14; (p07) br.cond.dpnt.few	4000000000116D70 }

l4000000000117390:
	{ ld8	r14,[r35]; st1	[r0],r39; nop.i	0x0 }
	{ ld1	r75,[r33],1; adds	r15,0x1,r14; sxt1	r75,r75 }
	{ nop.m	0x0; ld4	r14,[r34]; nop.i	0x0; }
	{ st8	[r15],r35; adds	r15,0x10,r12; cmp4.eq	p06,p07,0x0,r14; }
	{ st1	[r75],r15; nop.i	0x0; (p07) br.cond.dptk.few	4000000000117360 }

l40000000001173E0:
	{ ld8	r76,[r43]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AEC0; }
	{ sub	r15,r33,r40; ld4	r14,[r41]; adds	r1,0x0,r74; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r15,r14; (p06) br.cond.dptk.few	4000000000117390 }

l4000000000117410:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000116D70; }

l4000000000117420:
	{ cmp4.eq	p06,p07,0x2A,r36; adds	r37,0x0,r33; (p06) br.cond.dpnt.few	40000000001185E0; }

l4000000000117430:
	{ ld1	r14,[r33]; nop.m	0x0; sxt1	r38,r14; }
	{ adds	r14,0xFFFFFFFFFFFFFFD0,r38; nop.m	0x0; zxt1	r14,r14; }
	{ nop.m	0x0; cmp4.ltu	p07,p06,0x9,r14; (p07) br.cond.spnt.few	40000000001174C0; }

l4000000000117460:
	{ (p06) adds	r14,0x1,r33; nop.m	0x0; nop.i	0x0; }

l4000000000117466:
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ break.m	0x4000; nop; (p32) nop }

l4000000000117480:
	{ ld1	r38,[r14]; adds	r33,0x0,r14; adds	r14,0x1,r14; }

l4000000000117482:
	{ (p32) invala; (p32) nop; (p32) break.i	0xC2003; }
	{ Invalid; (p32) mov	pr,r5,0x8012; (p42) break.i	0xC67E9 }
	{ Invalid; (p48) break.i	0x203; Invalid }
	{ nop; (p49) nop; Invalid }

l40000000001174C0:
	{ nop.m	0x0; adds	r56,0x0,r0; adds	r51,0x0,r0; }

l40000000001174D0:
	{ adds	r14,0x1,r33; cmp4.eq	p07,p06,0x2E,r38; (p06) br.cond.dpnt.few	40000000001175A0; }

l40000000001174E0:
	{ ld1	r15,[r14]; nop.m	0x0; sxt1	r38,r15; }
	{ cmp4.eq	p07,p06,0x2A,r38; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000119200; }

l4000000000117500:
	{ cmp4.eq	p06,p07,0x2D,r38; (p06) adds	r14,0x2,r33; nop.i	0x0; }

l400000000011750C:
	{ nop; cmp4.eq.or.andcm	p00,p00,r32,r0; Invalid }

l400000000011751C:
	{ Invalid; cmp4.eq.and	p00,p00,r32,r0; (p04) cmp.eq.unc	p32,p00,r3,r5 }
	{ Invalid; cmp.eq	p00,p00,r32,r0; (p01) cmp.lt.unc	p32,p00,r3,r4; }
	{ (p04) nop; (p04) cmp.lt.unc	p00,p16,r3,r64; (p17) epc }

l4000000000117546:
	{ (p07) chk.a.clr	r1,3FFFFFFFFF197626; nop; break.i	0x80000 }

l4000000000117550:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000117560:
	{ ld1	r38,[r14]; adds	r33,0x0,r14; adds	r14,0x1,r14; }
	{ nop.m	0x0; sxt1	r38,r38; adds	r15,0xFFFFFFFFFFFFFFD0,r38; }
	{ nop.m	0x0; zxt1	r15,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p07,p06,0x9,r15; (p06) br.cond.dptk.few	4000000000117560 }

l40000000001175A0:
	{ nop.m	0x0; adds	r60,0x0,r0; adds	r59,0x0,r0; }

l40000000001175B0:
	{ cmp4.eq	p07,p06,0x0,r38; addl	r75,-684,r1; nop.i	0x0 }
	{ adds	r37,0x0,r38; adds	r36,0x0,r33; (p07) br.cond.dpnt.few	4000000000117160; }

l40000000001175D0:
	{ nop.m	0x0; adds	r76,0x0,r37; nop.i	0x0 }
	{ ld8	r75,[r75]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B680; }
	{ adds	r1,0x0,r74; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	4000000000117650; }

l4000000000117600:
	{ adds	r36,0x1,r36; nop.m	0x0; addl	r75,-684,r1; }
	{ ld1	r37,[r36]; nop.m	0x0; sxt1	r37,r37; }
	{ cmp4.eq	p07,p06,0x0,r37; adds	r76,0x0,r37; (p07) br.cond.dpnt.few	4000000000117160; }

l4000000000117630:
	{ ld8	r75,[r75]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B680; }
	{ adds	r1,0x0,r74; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	4000000000117600 }

l4000000000117650:
	{ nop.m	0x0; adds	r47,0x1,r33; adds	r14,0xFFFFFFFFFFFFFFD8,r37 }
	{ st1	[r37],r33; ld1	r57,[r47]; zxt1	r14,r14 }
	{ st1	[r0],r47; nop.i	0x0; sxt1	r57,r57 }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x50,r14; (p07) br.cond.dptk.few	40000000001177D0 }

l4000000000117690:
	{ addl	r76,-636,r1; addl	r77,5,r0; adds	r75,0x0,r0; }
	{ ld8	r76,[r76]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r74; nop.m	0x0; adds	r75,0x0,r8 }
	{ adds	r76,0x0,r37; nop.m	0x0; br.call.sptk.many	b0,builtin_error; }
	{ adds	r1,0x0,r74; ld4	r14,[r34]; addl	r15,4096,r0; }
	{ addl	r34,8644,r1; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	4000000000118E70; }

l40000000001176F0:
	{ ld8	r14,[r34]; nop.m	0x0; (p06) addl	r33,8612,r1; }

l4000000000117700:
	{ nop.m	0x0; cmp.ltu	p07,p06,r15,r14; (p07) br.cond.dpnt.few	4000000000118E30 }

l4000000000117710:
	{ addl	r34,8604,r1; nop.m	0x0; addl	r15,4096,r0; }
	{ nop.m	0x0; ld8	r14,[r34]; nop.i	0x0; }
	{ cmp.ltu	p07,p06,r15,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000119230; }

l4000000000117740:
	{ ld8	r14,[r33]; ld8.a	r75,[r43]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; (p07) st1	[r0],r14; nop.i	0x0; }

l400000000011775C:
	{ cmp.lt	p00,p09,r1,r0; (p01) nop; Invalid }
	{ nop; cmp.lt	p00,p00,r32,r0; zxt2	r95,r79 }
	{ Invalid; Invalid; break.i	0x1000 }
	{ (p56) nop; nop; zxt1	r64,r64 }
	{ ldfpd	f0,f1,[r0]; Invalid; break.i	0x1000 }
	{ (p14) nop; cmp.lt.unc	p00,p16,r18,r64; mov	pr,r98,0xE600 }
	{ (p61) invala; break.i	0x1000; zxt4	r0,r0 }

l40000000001177C0:
	{ nop.m	0x0; addl	r8,1,r0; br.cond.sptk.few	4000000000116FA0 }

l40000000001177D0:
	{ shladd	r14,r14,0x3,r63; ld8	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; add	r14,r14,r15; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r14,40000000001177F0; br.cond	b6; }
4000000000117800 09 70 00 64 18 10 B0 04 AC 30 20 00 00 00 04 00 .p.d.....0 .....
4000000000117810 0A 30 00 1C 07 F9 F1 40 38 00 42 A3 44 EC EB 9F .0.....@8.B.D...
4000000000117820 EA 70 00 1C 18 D0 F1 00 3C 30 20 00 00 00 04 00 .p......<0 .....
4000000000117830 E9 00 38 7A 98 91 51 02 94 30 20 00 00 00 04 00 ..8z..Q..0 .....
4000000000117840 F1 28 01 1E 18 10 00 00 00 02 00 00 C8 45 F0 58 .(...........E.X
4000000000117850 02 70 E0 78 0C 20 10 00 28 01 42 C0 00 70 1C E6 .p.x. ..(.B..p..
4000000000117860 19 00 00 00 01 00 E0 00 88 20 20 03 70 03 00 42 .........  .p..B
4000000000117870 10 00 00 00 01 00 60 00 38 0E 73 03 40 0E 00 42 ......`.8.s.@..B
4000000000117880 08 58 02 54 00 21 C0 04 CC 00 42 00 00 00 04 00 .X.T.!....B.....
4000000000117890 19 68 02 76 00 21 E0 04 94 00 42 00 B8 DE FF 58 .h.v.!....B....X
40000000001178A0 00 70 00 46 18 10 80 00 20 2C 00 20 00 50 02 84 .p.F.... ,. .P..
40000000001178B0 0B 58 02 56 18 10 E0 40 38 00 40 00 00 00 04 00 .X.V...@8.@.....
40000000001178C0 11 00 38 46 98 11 00 00 00 02 00 00 A8 30 F0 58 ..8F.........0.X
40000000001178D0 11 08 00 94 00 21 60 00 20 0E F3 03 80 F6 FF 4B .....!`. ......K
40000000001178E0 08 20 05 48 00 21 00 30 85 00 23 00 00 00 04 00 . .H.!.0..#.....
40000000001178F0 02 00 E4 5E 80 11 00 00 00 02 00 40 05 20 01 84 ...^.......@. ..
4000000000117900 0B 70 00 48 00 10 00 00 00 02 00 C0 01 70 50 00 .p.H.........pP.
4000000000117910 10 00 00 00 01 00 70 00 38 0C 73 03 D0 F3 FF 4A ......p.8.s....J
4000000000117920 10 00 00 00 01 00 00 00 00 02 00 00 80 F4 FF 48 ...............H
4000000000117930 09 00 00 00 01 00 E0 00 C8 30 20 00 00 00 04 00 .........0 .....
4000000000117940 11 78 20 1C 00 21 60 00 38 0E 72 03 80 1D 00 43 .x ..!`.8.r....C
4000000000117950 09 78 00 1E 18 10 E0 00 38 30 20 00 00 00 04 00 .x......80 .....
4000000000117960 0B 00 38 7A 98 11 50 02 3C 30 20 00 00 00 04 00 ..8z..P.<0 .....
4000000000117970 11 30 00 4A 07 39 00 00 00 02 00 03 30 00 00 43 .0.J.9......0..C
4000000000117980 0B 70 00 4A 00 10 00 00 00 02 00 C0 01 70 50 00 .p.J.........pP.
4000000000117990 10 00 00 00 01 00 70 00 38 0C F3 03 60 15 00 43 ......p.8...`..C
40000000001179A0 11 58 02 4A 00 21 00 00 00 02 00 00 E8 B5 01 50 .X.J.!.........P
40000000001179B0 08 00 00 00 01 00 10 00 28 01 42 60 09 28 01 84 ........(.B`.(..
40000000001179C0 18 00 00 00 01 00 60 00 20 0E 73 03 30 12 00 42 ......`. .s.0..B
40000000001179D0 11 60 02 00 00 21 D0 04 00 00 42 00 B8 B1 01 50 .`...!....B....P
40000000001179E0 09 00 00 00 01 00 10 00 28 01 42 A0 04 40 00 84 ........(.B..@..
40000000001179F0 11 30 00 4A 07 39 B0 04 94 00 42 03 F0 FE FF 4B .0.J.9....B....K
4000000000117A00 11 00 00 00 01 00 00 00 00 02 00 00 C8 3C F0 58 .............<.X
4000000000117A10 08 30 00 10 87 39 10 00 28 01 42 60 09 50 01 84 .0...9..(.B`.P..
4000000000117A20 19 60 02 4A 00 21 D0 04 20 00 42 03 30 00 00 43 .`.J.!.. .B.0..C
4000000000117A30 11 70 02 66 00 21 F0 04 EC 00 42 00 98 E8 FF 58 .p.f.!....B....X
4000000000117A40 10 08 00 94 00 21 70 40 00 0C E1 03 F0 14 00 43 .....!p@.......C
4000000000117A50 11 58 02 4A 00 21 40 0A 90 00 42 00 98 2D F0 58 .X.J.!@...B..-.X
4000000000117A60 08 08 00 94 00 21 00 30 85 00 23 40 05 20 01 84 .....!.0..#@. ..
4000000000117A70 18 00 00 00 01 00 00 C8 BD 00 23 00 90 FE FF 48 ..........#....H
4000000000117A80 09 00 00 00 01 00 E0 00 C8 30 20 00 00 00 04 00 .........0 .....
4000000000117A90 11 78 20 1C 00 21 60 00 38 0E 72 03 70 1C 00 43 .x ..!`.8.r.p..C
4000000000117AA0 09 78 00 1E 18 10 E0 00 38 30 20 00 00 00 04 00 .x......80 .....
4000000000117AB0 0B 00 38 7A 98 11 50 02 3C 30 20 00 00 00 04 00 ..8z..P.<0 .....
4000000000117AC0 11 30 00 4A 07 39 00 00 00 02 00 03 20 FE FF 4B .0.J.9...... ..K
4000000000117AD0 0B 70 00 4A 00 10 00 00 00 02 00 C0 01 70 50 00 .p.J.........pP.
4000000000117AE0 10 00 00 00 01 00 60 00 38 0E 73 03 00 FE FF 4A ......`.8.s....J
4000000000117AF0 11 58 02 4A 00 21 40 0A 90 00 42 00 58 7B F2 58 .X.J.!@...B.X{.X
4000000000117B00 08 30 00 10 87 39 10 00 28 01 42 00 00 00 04 00 .0...9..(.B.....
4000000000117B10 19 58 02 4A 00 21 A0 02 90 00 42 03 00 22 00 43 .X.J.!....B..".C
4000000000117B20 11 60 02 46 18 10 00 00 00 02 00 00 68 0E F5 58 .`.F........h..X
4000000000117B30 08 00 00 00 01 00 10 00 28 01 42 00 00 00 04 00 ........(.B.....
4000000000117B40 18 00 98 42 80 11 00 C8 BD 00 23 00 C0 FD FF 48 ...B......#....H
4000000000117B50 11 00 00 00 01 00 00 00 00 02 00 00 F8 DF FF 58 ...............X
4000000000117B60 09 00 00 00 01 00 10 00 28 01 42 A0 04 40 00 84 ........(.B..@..
4000000000117B70 09 60 D2 FB FA 27 00 00 00 02 00 60 09 50 01 84 .`...'.....`.P..
4000000000117B80 11 60 02 98 18 10 00 00 00 02 00 00 48 E3 FF 58 .`..........H..X
4000000000117B90 08 00 00 00 01 00 10 00 28 01 42 40 05 40 00 84 ........(.B@.@..
4000000000117BA0 11 58 02 56 18 10 00 00 00 02 00 00 68 42 F0 58 .X.V........hB.X
4000000000117BB0 02 70 E0 78 0C 20 10 00 28 01 42 C0 00 70 1C E6 .p.x. ..(.B..p..
4000000000117BC0 19 00 00 00 01 00 E0 00 88 20 A0 03 B0 FC FF 4A ......... .....J
4000000000117BD0 11 00 00 00 01 00 60 00 E0 0E 73 03 50 0A 00 42 ......`...s.P..B
4000000000117BE0 10 00 00 00 01 00 60 00 38 0E 73 03 A0 0F 00 42 ......`.8.s....B
4000000000117BF0 08 58 02 54 00 21 00 00 00 02 00 80 09 98 01 84 .X.T.!..........
4000000000117C00 19 68 02 4A 00 21 00 00 00 02 00 00 48 DB FF 58 .h.J.!......H..X
4000000000117C10 00 70 00 46 18 10 80 00 20 2C 00 20 00 50 02 84 .p.F.... ,. .P..
4000000000117C20 0B 58 02 56 18 10 E0 40 38 00 40 00 00 00 04 00 .X.V...@8.@.....
4000000000117C30 11 00 38 46 98 11 00 00 00 02 00 00 38 2D F0 58 ..8F........8-.X
4000000000117C40 10 08 00 94 00 21 60 00 20 0E 73 03 A0 FC FF 4A .....!`. .s....J
4000000000117C50 10 00 00 00 01 00 00 00 00 02 00 00 00 F3 FF 48 ...............H
4000000000117C60 09 70 00 64 18 10 B0 04 AC 30 20 00 00 00 04 00 .p.d.....0 .....
4000000000117C70 09 00 00 00 01 00 60 00 38 0E 72 00 00 00 04 00 ......`.8.r.....
4000000000117C80 E9 78 20 1C 00 E1 E1 00 38 30 20 A3 04 00 00 84 .x .....80 .....
4000000000117C90 E9 78 00 1E 18 D0 01 70 F4 30 23 00 00 00 04 00 .x.....p.0#.....
4000000000117CA0 EB 70 00 1E 18 D0 51 02 38 00 20 00 00 00 04 00 .p....Q.8. .....
4000000000117CB0 11 00 00 00 01 C0 51 02 94 28 00 00 58 41 F0 58 ......Q..(..XA.X
4000000000117CC0 02 70 E0 78 0C 20 10 00 28 01 42 C0 00 70 1C E6 .p.x. ..(.B..p..
4000000000117CD0 19 00 00 00 01 00 E0 00 88 20 A0 03 D0 0A 00 42 ......... .....B
4000000000117CE0 11 00 00 00 01 00 60 00 E0 0E 73 03 20 16 00 42 ......`...s. ..B
4000000000117CF0 10 00 00 00 01 00 60 00 38 0E 73 03 70 1B 00 42 ......`.8.s.p..B
4000000000117D00 08 58 02 54 00 21 00 00 00 02 00 80 09 98 01 84 .X.T.!..........
4000000000117D10 19 68 02 4A 00 21 00 00 00 02 00 00 38 DA FF 58 .h.J.!......8..X
4000000000117D20 00 70 00 46 18 10 80 00 20 2C 00 20 00 50 02 84 .p.F.... ,. .P..
4000000000117D30 0B 58 02 56 18 10 E0 40 38 00 40 00 00 00 04 00 .X.V...@8.@.....
4000000000117D40 11 00 38 46 98 11 00 00 00 02 00 00 28 2C F0 58 ..8F........(,.X
4000000000117D50 10 08 00 94 00 21 60 00 20 0E 73 03 90 FB FF 4A .....!`. .s....J
4000000000117D60 10 00 00 00 01 00 00 00 00 02 00 00 F0 F1 FF 48 ...............H
4000000000117D70 09 00 00 00 01 00 E0 00 C8 30 20 00 00 00 04 00 .........0 .....
4000000000117D80 11 78 20 1C 00 21 60 00 38 0E 72 03 60 FB FF 4B .x ..!`.8.r.`..K
4000000000117D90 09 78 00 1E 18 10 E0 00 38 30 20 00 00 00 04 00 .x......80 .....
4000000000117DA0 0B 00 38 7A 98 11 50 02 3C 30 20 00 00 00 04 00 ..8z..P.<0 .....
4000000000117DB0 11 58 02 4A 00 21 00 00 00 02 00 00 18 39 F0 58 .X.J.!.......9.X
4000000000117DC0 09 30 00 4A 07 39 00 00 00 02 00 20 00 50 02 84 .0.J.9..... .P..
4000000000117DD0 10 00 00 00 01 00 60 00 20 8E 73 03 10 FB FF 4A ......`. .s....J
4000000000117DE0 09 00 00 00 01 00 B0 0C 20 00 42 00 00 00 04 00 ........ .B.....
4000000000117DF0 11 00 00 00 01 00 B0 04 2C 2D 00 00 D8 0E FD 58 ........,-.....X
4000000000117E00 09 08 00 94 00 21 80 03 20 00 42 80 05 40 00 84 .....!.. .B..@..
4000000000117E10 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000117E20 0B 70 00 4A 00 10 00 00 00 02 00 C0 01 70 50 00 .p.J.........pP.
4000000000117E30 11 38 00 1C 86 39 00 00 00 02 80 03 40 00 00 43 .8...9......@..C
4000000000117E40 10 28 05 4A 00 21 70 E0 3A 0C F3 03 B0 0E 00 43 .(.J.!p.:......C
4000000000117E50 09 08 38 58 80 15 00 00 00 02 00 00 00 00 04 00 ..8X............
4000000000117E60 11 00 00 00 01 00 60 00 94 0E F2 03 C0 FF FF 4A ......`........J
4000000000117E70 08 38 00 70 06 39 00 00 00 02 00 A0 C9 C2 15 80 .8.p.9..........
4000000000117E80 19 00 00 58 80 11 00 00 00 02 80 03 60 FA FF 49 ...X........`..I
4000000000117E90 C8 28 01 00 00 21 00 00 00 02 00 00 00 00 04 00 .(...!..........
4000000000117EA0 08 30 00 9A 87 39 B0 04 A8 00 42 80 09 C0 01 84 .0...9....B.....
4000000000117EB0 19 70 02 66 00 21 F0 04 EC 00 42 03 30 00 00 43 .p.f.!....B.0..C
4000000000117EC0 11 00 00 00 01 00 00 00 00 02 00 00 08 E4 FF 58 ...............X
4000000000117ED0 10 08 00 94 00 21 70 40 00 0C E1 03 B0 12 00 43 .....!p@.......C
4000000000117EE0 11 58 02 70 00 21 40 0A 90 00 42 00 08 29 F0 58 .X.p.!@...B..).X
4000000000117EF0 08 08 00 94 00 21 00 00 00 02 00 E0 00 28 19 E6 .....!.......(..
4000000000117F00 19 50 01 48 00 21 00 00 00 02 00 03 30 EF FF 4B .P.H.!......0..K
4000000000117F10 08 00 00 00 01 00 00 30 85 00 23 00 00 00 04 00 .......0..#.....
4000000000117F20 18 00 E4 5E 80 11 00 00 00 02 00 00 E0 F9 FF 48 ...^...........H
4000000000117F30 0B 60 01 64 18 10 60 00 B0 0E 72 C0 88 60 01 84 .`.d..`...r..`..
4000000000117F40 D1 28 01 00 00 21 00 00 00 02 00 03 30 FC FF 4B .(...!......0..K
4000000000117F50 0B 70 00 8C 18 10 50 02 38 30 20 00 00 00 04 00 .p....P.80 .....
4000000000117F60 09 00 00 00 01 00 E0 00 94 00 20 00 00 00 04 00 .......... .....
4000000000117F70 03 00 00 00 01 00 E0 00 38 28 00 E0 20 72 18 E6 ........8(.. r..
4000000000117F80 11 38 9C 1C C6 39 00 00 00 02 80 03 90 0C 00 43 .8...9.........C
4000000000117F90 11 00 00 00 01 00 00 00 00 02 00 00 B8 38 F0 58 .............8.X
4000000000117FA0 08 08 00 94 00 21 70 04 20 00 42 60 09 28 01 84 .....!p. .B`.(..
4000000000117FB0 09 00 00 10 90 11 C0 84 31 02 42 A0 09 00 00 84 ........1.B.....
4000000000117FC0 11 70 02 00 00 21 00 00 00 02 00 00 68 2D F0 58 .p...!......h-.X
4000000000117FD0 09 78 C0 18 01 21 10 00 28 01 42 A0 04 40 00 84 .x...!..(.B..@..
4000000000117FE0 0B 70 00 1E 18 10 E0 00 38 00 20 00 00 00 04 00 .p......8. .....
4000000000117FF0 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
4000000000118000 11 30 00 1C 87 39 00 00 00 02 80 03 20 16 00 43 .0...9...... ..C
4000000000118010 09 00 00 00 01 00 E0 00 1C 21 20 00 00 00 04 00 .........! .....
4000000000118020 11 38 88 1C 86 39 00 00 00 02 80 03 C0 10 00 43 .8...9.........C
4000000000118030 09 00 00 00 01 00 E0 00 B0 30 20 00 00 00 04 00 .........0 .....
4000000000118040 08 00 38 64 98 11 00 00 00 02 00 00 00 00 04 00 ..8d............
4000000000118050 09 60 D2 FB FA 27 00 00 00 02 00 60 09 50 01 84 .`...'.....`.P..
4000000000118060 11 60 02 98 18 10 00 00 00 02 00 00 68 DE FF 58 .`..........h..X
4000000000118070 10 08 00 94 00 21 A0 02 20 00 42 00 30 FB FF 48 .....!.. .B.0..H
4000000000118080 0B 28 01 64 18 10 60 00 94 0E 72 80 85 28 01 84 .(.d..`...r..(..
4000000000118090 1D 00 00 00 01 80 21 00 00 20 00 03 10 01 00 43 ......!.. .....C
40000000001180A0 0B 70 00 58 18 10 60 04 38 30 20 00 00 00 04 00 .p.X..`.80 .....
40000000001180B0 09 00 00 00 01 00 E0 00 18 01 20 00 00 00 04 00 .......... .....
40000000001180C0 03 00 00 00 01 00 E0 00 38 28 00 E0 20 72 18 E6 ........8(.. r..
40000000001180D0 11 38 9C 1C C6 39 00 00 00 02 80 03 90 0B 00 43 .8...9.........C
40000000001180E0 11 00 00 00 01 00 00 00 00 02 00 00 68 37 F0 58 ............h7.X
40000000001180F0 08 00 00 00 01 00 10 00 28 01 42 E0 08 40 00 84 ........(.B..@..
4000000000118100 09 00 00 10 90 11 B0 04 18 01 42 80 09 63 04 84 ..........B..c..
4000000000118110 11 00 00 00 01 00 00 00 00 02 00 00 78 29 F0 58 ............x).X
4000000000118120 0F 78 C0 18 01 21 10 00 28 01 42 40 80 40 40 00 .x...!..(.B@.@@.
4000000000118130 0B 70 00 1E 18 10 E0 00 38 00 20 00 00 00 04 00 .p......8. .....
4000000000118140 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
4000000000118150 11 30 00 1C 87 39 00 00 00 02 80 03 20 15 00 43 .0...9...... ..C
4000000000118160 09 00 00 00 01 00 E0 00 1C 21 20 00 00 00 04 00 .........! .....
4000000000118170 11 38 88 1C 86 39 00 00 00 02 80 03 C0 0F 00 43 .8...9.........C
4000000000118180 09 00 00 00 01 00 E0 00 94 30 20 00 00 00 04 00 .........0 .....
4000000000118190 08 00 38 64 98 11 00 00 00 02 00 00 00 00 04 00 ..8d............
40000000001181A0 09 60 F2 FB FA 27 00 00 00 02 00 60 09 50 01 84 .`...'.....`.P..
40000000001181B0 11 60 02 98 18 10 00 00 00 02 00 00 18 DD FF 58 .`.............X
40000000001181C0 08 08 00 94 00 21 00 00 00 02 00 A0 04 40 00 84 .....!.......@..
40000000001181D0 19 58 02 56 18 10 00 00 00 02 00 00 38 3C F0 58 .X.V........8<.X
40000000001181E0 02 70 E0 78 0C 20 10 00 28 01 42 C0 00 70 1C E6 .p.x. ..(.B..p..
40000000001181F0 19 00 00 00 01 00 E0 00 88 20 A0 03 30 06 00 42 ......... ..0..B
4000000000118200 11 00 00 00 01 00 60 00 E0 0E 73 03 90 11 00 42 ......`...s....B
4000000000118210 10 00 00 00 01 00 60 00 38 0E 73 03 C0 15 00 42 ......`.8.s....B
4000000000118220 08 80 C0 19 01 21 10 C1 33 02 42 60 09 28 01 84 .....!..3.B`.(..
4000000000118230 0B 60 02 66 00 21 00 10 40 00 33 00 00 00 04 00 .`.f.!..@.3.....
4000000000118240 08 00 00 00 01 00 D0 04 40 30 20 00 00 00 04 00 ........@0 .....
4000000000118250 19 70 02 22 18 10 00 00 00 02 00 00 F8 D4 FF 58 .p."...........X
4000000000118260 00 70 00 46 18 10 80 00 20 2C 00 20 00 50 02 84 .p.F.... ,. .P..
4000000000118270 0B 58 02 56 18 10 E0 40 38 00 40 00 00 00 04 00 .X.V...@8.@.....
4000000000118280 11 00 38 46 98 11 00 00 00 02 00 00 E8 26 F0 58 ..8F.........&.X
4000000000118290 10 08 00 94 00 21 60 00 20 0E 73 03 50 F6 FF 4A .....!`. .s.P..J
40000000001182A0 10 00 00 00 01 00 00 00 00 02 00 00 B0 EC FF 48 ...............H
40000000001182B0 08 58 02 48 00 21 00 C8 BD 00 23 80 14 20 01 84 .X.H.!....#.. ..
40000000001182C0 19 00 00 00 01 00 00 00 00 02 00 00 08 34 F0 58 .............4.X
40000000001182D0 11 08 00 94 00 21 B0 1C 20 00 42 00 F8 09 FD 58 .....!.. .B....X
40000000001182E0 08 70 00 48 00 10 00 00 00 02 00 20 00 50 02 84 .p.H....... .P..
40000000001182F0 09 28 01 10 00 21 00 00 00 02 00 20 12 00 00 90 .(...!..... ....
4000000000118300 03 00 00 00 01 00 E0 00 38 28 00 C0 00 70 1C E6 ........8(...p..
4000000000118310 11 00 00 00 01 80 01 01 20 00 42 03 A0 00 00 43 ........ .B....C
4000000000118320 09 78 00 10 00 21 00 00 00 02 00 00 00 00 04 00 .x...!..........
4000000000118330 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000118340 09 38 A0 1C 86 39 00 00 00 02 00 00 02 78 00 84 .8...9.......x..
4000000000118350 F1 88 04 22 00 21 00 00 00 02 80 03 20 00 00 43 ...".!...... ..C
4000000000118360 03 38 A4 1C 86 39 00 00 00 02 80 23 F2 8F FC 8C .8...9.....#....
4000000000118370 11 30 00 22 87 39 00 00 00 02 00 03 40 00 00 43 .0.".9......@..C
4000000000118380 09 08 38 1E 80 15 00 00 00 02 00 80 14 20 01 84 ..8.......... ..
4000000000118390 03 70 00 48 00 10 00 01 3C 00 42 C0 01 70 50 00 .p.H....<.B..pP.
40000000001183A0 10 00 00 00 01 00 70 00 38 0C 73 03 A0 FF FF 4A ......p.8.s....J
40000000001183B0 08 00 00 00 01 00 40 0A 90 00 42 80 49 EE EB 9F ......@...B.I...
40000000001183C0 09 00 00 20 80 11 D0 2C 00 00 48 60 09 00 00 84 ... ...,..H`....
40000000001183D0 0B 70 00 48 00 10 00 00 00 02 00 C0 01 70 50 00 .p.H.........pP.
40000000001183E0 11 30 50 1D 87 39 00 00 00 02 00 03 E0 04 00 43 .0P..9.........C
40000000001183F0 11 60 02 98 18 10 00 00 00 02 00 00 78 27 F0 58 .`..........x'.X
4000000000118400 09 70 00 48 00 10 B0 04 20 00 42 20 00 50 02 84 .p.H.... .B .P..
4000000000118410 11 00 00 00 01 00 C0 04 38 28 00 00 78 52 FD 58 ........8(..xR.X
4000000000118420 11 08 00 94 00 21 B0 04 94 00 42 00 C8 23 F0 58 .....!....B..#.X
4000000000118430 08 70 00 46 18 10 10 81 30 00 42 20 00 50 02 84 .p.F....0.B .P..
4000000000118440 09 78 00 54 00 10 00 00 9C 00 23 00 00 00 04 00 .x.T......#.....
4000000000118450 08 00 00 00 01 00 00 09 38 00 42 00 00 00 04 00 ........8.B.....
4000000000118460 09 70 00 44 10 10 00 78 44 00 23 00 00 00 04 00 .p.D...xD.#.....
4000000000118470 10 00 40 46 98 11 60 00 38 0E 73 03 50 0E 00 42 ..@F..`.8.s.P..B
4000000000118480 08 20 01 54 00 21 00 00 00 02 00 60 09 88 00 84 . .T.!.....`....
4000000000118490 19 50 01 58 00 21 00 00 00 02 00 00 B8 DC FF 58 .P.X.!.........X
40000000001184A0 09 00 00 00 01 00 10 00 28 01 42 80 14 20 01 84 ........(.B.. ..
40000000001184B0 0B 70 00 48 00 10 00 00 00 02 00 C0 01 70 50 00 .p.H.........pP.
40000000001184C0 10 00 00 00 01 00 70 00 38 0C 73 03 20 E8 FF 4A ......p.8.s. ..J
40000000001184D0 10 00 00 00 01 00 00 00 00 02 00 00 D0 E8 FF 48 ...............H

l40000000001184E0:
	{ ld8	r16,[r35]; nop.m	0x0; adds	r17,0x10,r12 }
	{ st1	[r0],r39; ld4	r15,[r34]; nop.i	0x0; }
	{ adds	r16,0x1,r16; st1	[r14],r17; cmp4.eq	p06,p07,0x0,r15; }
	{ st8	[r16],r35; nop.i	0x0; (p06) br.cond.dptk.few	40000000001185B0 }

l4000000000118520:
	{ adds	r75,0x0,r17; nop.m	0x0; adds	r42,0x2,r42 }
	{ adds	r36,0x1,r44; nop.m	0x0; br.call.sptk.many	b0,fn4000000000116140; }
	{ adds	r1,0x0,r74; nop.m	0x0; nop.i	0x0 }

l4000000000118550:
	{ ld1	r14,[r36]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000116CE0 }

l4000000000118570:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000116DA0 }

l4000000000118580:
	{ adds	r8,0x0,r0; adds	r17,0x150,r12; mov.i	ar.pfs,r73; }
	{ nop.m	0x0; mov.spnt	b0,r72,4000000000118590; nop.i	0x0 }
	{ ldf.fill	f2,[r17]; adds	r12,0x150,r12; br.ret	b0; }

l40000000001185B0:
	{ addl	r75,37,r0; ld8	r76,[r43]; nop.i	0x0 }
	{ adds	r42,0x2,r42; adds	r36,0x1,r44; br.call.sptk.many	b0,fn400000000001AEC0; }
	{ nop.m	0x0; adds	r1,0x0,r74; br.cond.sptk.few	4000000000118550 }

l40000000001185E0:
	{ adds	r37,0x1,r37; nop.m	0x0; adds	r33,0x1,r33 }
	{ addl	r56,1,r0; nop.m	0x0; br.call.sptk.many	b0,fn4000000000115D80; }
	{ ld1	r38,[r37]; adds	r1,0x0,r74; adds	r51,0x0,r8; }
	{ nop.m	0x0; sxt1	r38,r38; br.cond.sptk.few	40000000001174D0 }
4000000000118620 11 00 00 00 01 00 60 00 F0 0E 73 03 F0 04 00 42 ......`...s....B
4000000000118630 10 00 00 00 01 00 60 00 38 0E 73 03 80 0F 00 42 ......`.8.s....B
4000000000118640 08 58 02 54 00 21 00 00 00 02 00 80 09 D8 01 84 .X.T.!..........
4000000000118650 19 68 02 4A 00 21 00 00 00 02 00 00 F8 D0 FF 58 .h.J.!.........X
4000000000118660 00 70 00 46 18 10 80 00 20 2C 00 20 00 50 02 84 .p.F.... ,. .P..
4000000000118670 0B 58 02 56 18 10 E0 40 38 00 40 00 00 00 04 00 .X.V...@8.@.....
4000000000118680 11 00 38 46 98 11 00 00 00 02 00 00 E8 22 F0 58 ..8F.........".X
4000000000118690 10 08 00 94 00 21 60 00 20 0E 73 03 50 F2 FF 4A .....!`. .s.P..J
40000000001186A0 10 00 00 00 01 00 00 00 00 02 00 00 B0 E8 FF 48 ...............H
40000000001186B0 08 58 06 00 00 24 C0 04 A8 00 42 A0 09 98 01 84 .X...$....B.....
40000000001186C0 19 70 02 76 00 21 F0 04 94 00 42 00 C8 34 F0 58 .p.v.!....B..4.X
40000000001186D0 00 70 00 46 18 10 80 00 20 2C 00 20 00 50 02 84 .p.F.... ,. .P..
40000000001186E0 0B 58 02 56 18 10 E0 40 38 00 40 00 00 00 04 00 .X.V...@8.@.....
40000000001186F0 11 00 38 46 98 11 00 00 00 02 00 00 78 22 F0 58 ..8F........x".X
4000000000118700 10 08 00 94 00 21 60 00 20 0E 73 03 E0 F1 FF 4A .....!`. .s....J
4000000000118710 11 00 00 00 01 00 00 00 00 02 00 00 40 E8 FF 48 ............@..H

l4000000000118720:
	{ addl	r34,8596,r1; addl	r33,8612,r1; nop.i	0x0 }
	{ ld8	r75,[r34]; ld8	r76,[r33]; br.call.sptk.many	b0,fn4000000000116080; }
	{ nop.m	0x0; adds	r1,0x0,r74; nop.i	0x0 }
	{ ld8	r75,[r34]; nop.m	0x0; br.call.sptk.many	b0,stupidly_hack_special_variables; }
	{ adds	r1,0x0,r74; addl	r15,4096,r0; addl	r35,8644,r1; }
	{ nop.m	0x0; ld8	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; cmp.ltu	p07,p06,r15,r14; (p06) br.cond.dptk.few	40000000001171E0 }

l4000000000118790:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000119060; }
40000000001187A0 10 00 00 00 01 00 60 00 38 0E 73 03 30 0D 00 42 ......`.8.s.0..B
40000000001187B0 08 58 02 54 00 21 C0 04 CC 00 42 00 00 00 04 00 .X.T.!....B.....
40000000001187C0 19 68 02 76 00 21 E0 04 94 00 42 00 88 CF FF 58 .h.v.!....B....X
40000000001187D0 00 70 00 46 18 10 80 00 20 2C 00 20 00 50 02 84 .p.F.... ,. .P..
40000000001187E0 0B 58 02 56 18 10 E0 40 38 00 40 00 00 00 04 00 .X.V...@8.@.....
40000000001187F0 11 00 38 46 98 11 00 00 00 02 00 00 78 21 F0 58 ..8F........x!.X
4000000000118800 10 08 00 94 00 21 60 00 20 0E 73 03 E0 F0 FF 4A .....!`. .s....J
4000000000118810 11 00 00 00 01 00 00 00 00 02 00 00 40 E7 FF 48 ............@..H
4000000000118820 10 00 00 00 01 00 60 00 38 0E 73 03 20 0C 00 42 ......`.8.s. ..B
4000000000118830 08 80 40 19 01 21 10 C1 32 02 42 00 00 00 04 00 ..@..!..2.B.....
4000000000118840 09 58 02 4A 00 21 C0 04 CC 00 42 A0 09 D8 01 84 .X.J.!....B.....
4000000000118850 0A 00 08 20 80 19 F0 04 40 30 20 00 00 00 04 00 ... ....@0 .....
4000000000118860 19 80 02 22 18 10 00 00 00 02 00 00 E8 CE FF 58 ..."...........X
4000000000118870 00 70 00 46 18 10 80 00 20 2C 00 20 00 50 02 84 .p.F.... ,. .P..
4000000000118880 0B 58 02 56 18 10 E0 40 38 00 40 00 00 00 04 00 .X.V...@8.@.....
4000000000118890 11 00 38 46 98 11 00 00 00 02 00 00 D8 20 F0 58 ..8F......... .X
40000000001188A0 10 08 00 94 00 21 60 00 20 0E 73 03 40 F0 FF 4A .....!`. .s.@..J
40000000001188B0 10 00 00 00 01 00 00 00 00 02 00 00 A0 E6 FF 48 ...............H
40000000001188C0 0B 70 00 4A 00 10 00 00 00 02 00 C0 01 70 50 00 .p.J.........pP.
40000000001188D0 0B 38 00 1C 86 F9 E1 00 94 00 C2 E3 21 28 01 84 .8..........!(..
40000000001188E0 EA 08 08 1D 80 D5 01 08 3A 00 23 00 00 00 04 00 ........:.#.....
40000000001188F0 F9 00 00 1E 80 11 00 00 00 02 00 00 58 D2 FF 58 ............X..X
4000000000118900 11 38 FC 11 06 3B 10 00 28 01 C2 03 B0 11 00 43 .8...;..(......C
4000000000118910 09 00 00 00 01 00 70 F0 23 0C 76 00 00 00 04 00 ......p.#.v.....
4000000000118920 E9 70 00 86 18 D0 F1 C0 31 02 42 03 82 63 04 84 .p......1.B..c..
4000000000118930 E8 00 38 1E 98 91 01 40 40 30 23 00 00 00 04 00 ..8....@@0#.....
4000000000118940 09 00 00 00 01 00 B0 64 F7 F5 4F 00 00 00 04 00 .......d..O.....
4000000000118950 11 58 02 96 18 10 00 00 00 02 00 00 38 13 F5 58 .X..........8..X
4000000000118960 11 08 00 94 00 21 B0 C4 31 02 42 00 C8 2C F0 58 .....!..1.B..,.X
4000000000118970 08 60 02 00 01 24 D0 04 94 00 42 C0 09 40 00 84 .`...$....B..@..
4000000000118980 19 08 00 94 00 21 B0 84 30 00 42 00 28 2C F0 58 .....!..0.B.(,.X
4000000000118990 08 08 00 94 00 21 00 00 00 02 00 80 05 40 00 84 .....!.......@..
40000000001189A0 19 58 02 4A 00 21 00 00 00 02 00 00 48 1E F0 58 .X.J.!......H..X
40000000001189B0 09 38 00 58 86 39 10 00 28 01 42 60 09 61 00 84 .8.X.9..(.B`.a..
40000000001189C0 E9 88 40 18 00 21 00 00 00 02 00 C3 F1 60 04 84 ..@..!.......`..
40000000001189D0 E9 00 00 22 80 91 01 00 38 00 23 00 00 00 04 00 ..."....8.#.....
40000000001189E0 08 00 00 00 01 00 00 20 86 00 23 00 00 00 04 00 ....... ..#.....
40000000001189F0 19 00 00 5E 80 11 00 00 00 02 00 00 D8 2C F0 58 ...^.........,.X
4000000000118A00 08 30 00 10 87 39 10 00 28 01 42 60 09 50 01 84 .0...9..(.B`.P..
4000000000118A10 19 60 42 18 00 21 D0 04 20 00 42 03 D0 EE FF 4B .`B..!.. .B....K
4000000000118A20 11 70 02 66 00 21 F0 04 EC 00 42 00 A8 D8 FF 58 .p.f.!....B....X
4000000000118A30 10 08 00 94 00 21 70 40 00 0C 61 03 B0 EE FF 4A .....!p@..a....J
4000000000118A40 11 00 00 00 01 00 00 00 00 02 00 00 48 5C FD 58 ............H\.X
4000000000118A50 08 00 00 00 01 00 10 00 28 01 42 00 00 00 04 00 ........(.B.....
4000000000118A60 19 58 02 56 18 10 00 00 00 02 00 00 A8 33 F0 58 .X.V.........3.X
4000000000118A70 09 70 00 44 10 10 00 00 00 02 00 20 00 50 02 84 .p.D....... .P..
4000000000118A80 10 00 00 00 01 00 60 00 38 0E F3 03 10 05 00 43 ......`.8......C

l4000000000118A90:
	{ addl	r33,8612,r1; nop.m	0x0; nop.i	0x0 }

l4000000000118AA0:
	{ addl	r35,8644,r1; nop.m	0x0; addl	r15,4096,r0; }
	{ nop.m	0x0; ld8	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; cmp.ltu	p07,p06,r15,r14; (p06) br.cond.dptk.few	4000000000117710 }

l4000000000118AD0:
	{ nop.m	0x0; addl	r34,8652,r1; nop.i	0x0; }
	{ ld8	r75,[r34]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r74; nop.i	0x0 }
	{ st8	[r0],r35; st8	[r0],r34; br.cond.sptk.few	4000000000117710 }
4000000000118B10 10 00 00 00 01 00 60 00 38 0E 73 03 30 0A 00 42 ......`.8.s.0..B
4000000000118B20 11 58 02 54 00 21 C0 04 94 00 42 00 28 CC FF 58 .X.T.!....B.(..X
4000000000118B30 00 70 00 46 18 10 80 00 20 2C 00 20 00 50 02 84 .p.F.... ,. .P..
4000000000118B40 0B 58 02 56 18 10 E0 40 38 00 40 00 00 00 04 00 .X.V...@8.@.....
4000000000118B50 11 00 38 46 98 11 00 00 00 02 00 00 18 1E F0 58 ..8F...........X
4000000000118B60 10 08 00 94 00 21 60 00 20 0E 73 03 80 ED FF 4A .....!`. .s....J
4000000000118B70 10 00 00 00 01 00 00 00 00 02 00 00 E0 E3 FF 48 ...............H
4000000000118B80 08 58 06 00 00 24 C0 04 A8 00 42 00 00 00 04 00 .X...$....B.....
4000000000118B90 19 68 02 66 00 21 E0 04 94 00 42 00 F8 2F F0 58 .h.f.!....B../.X
4000000000118BA0 00 70 00 46 18 10 80 00 20 2C 00 20 00 50 02 84 .p.F.... ,. .P..
4000000000118BB0 0B 58 02 56 18 10 E0 40 38 00 40 00 00 00 04 00 .X.V...@8.@.....
4000000000118BC0 11 00 38 46 98 11 00 00 00 02 00 00 A8 1D F0 58 ..8F...........X
4000000000118BD0 10 08 00 94 00 21 60 00 20 0E 73 03 10 ED FF 4A .....!`. .s....J
4000000000118BE0 10 00 00 00 01 00 00 00 00 02 00 00 70 E3 FF 48 ............p..H
4000000000118BF0 11 00 00 00 01 00 00 00 00 02 00 00 18 8F 01 50 ...............P
4000000000118C00 10 08 00 94 00 21 50 02 20 00 42 00 F0 ED FF 48 .....!P. .B....H
4000000000118C10 11 00 00 00 01 00 00 00 00 02 00 00 78 CD FF 58 ............x..X
4000000000118C20 09 08 00 94 00 21 B0 04 A8 00 42 A0 04 40 00 84 .....!....B..@..
4000000000118C30 09 00 00 00 01 00 C0 A4 F7 F5 4F 00 00 00 04 00 ..........O.....
4000000000118C40 11 60 02 98 18 10 00 00 00 02 00 00 88 D2 FF 58 .`.............X
4000000000118C50 10 08 00 94 00 21 A0 02 20 00 42 00 50 EF FF 48 .....!.. .B.P..H
4000000000118C60 11 00 00 00 01 00 00 00 00 02 00 00 28 CD FF 58 ............(..X
4000000000118C70 09 30 20 00 E1 18 10 00 28 01 42 60 09 50 01 84 .0 .....(.B`.P..
4000000000118C80 0B 60 F2 FB FA 27 C0 04 30 31 20 00 00 00 04 00 .`...'..01 .....
4000000000118C90 1D 00 00 00 01 00 20 30 00 38 00 00 38 D2 FF 58 ...... 0.8..8..X
4000000000118CA0 08 08 00 94 00 21 00 00 00 02 00 A0 04 40 00 84 .....!.......@..
4000000000118CB0 19 58 02 56 18 10 00 00 00 02 00 00 58 31 F0 58 .X.V........X1.X
4000000000118CC0 02 70 E0 78 0C 20 10 00 28 01 42 C0 00 70 1C E6 .p.x. ..(.B..p..
4000000000118CD0 18 00 00 00 01 00 E0 00 88 20 20 03 30 F5 FF 4A .........  .0..J
4000000000118CE0 10 00 00 00 01 00 00 00 00 02 00 00 40 FB FF 48 ............@..H
4000000000118CF0 0B 78 00 4A 00 10 00 00 00 02 00 E0 01 78 50 00 .x.J.........xP.
4000000000118D00 10 00 00 00 01 00 70 00 3C 0C F3 03 50 F1 FF 4A ......p.<...P..J
4000000000118D10 08 70 10 19 01 21 F0 80 30 00 42 00 82 61 00 84 .p...!..0.B..a..
4000000000118D20 09 58 02 4A 00 21 00 00 F8 30 23 A0 09 A0 01 84 .X.J.!...0#.....
4000000000118D30 08 00 00 1C 90 11 00 00 3C 30 23 80 09 78 00 84 ........<0#..x..
4000000000118D40 0A 70 02 1C 00 21 00 00 40 30 23 00 00 00 04 00 .p...!..@0#.....
4000000000118D50 19 00 00 8A 80 11 00 00 00 02 00 00 F8 C1 FF 58 ...............X
4000000000118D60 18 88 10 19 01 21 10 00 28 01 42 00 00 00 00 20 .....!..(.B.... 
4000000000118D70 01 90 40 18 00 21 80 00 20 2C 00 E0 01 60 01 84 ..@..!.. ,...`..
4000000000118D80 09 70 00 22 10 10 00 00 00 02 00 A0 54 42 00 80 .p."........TB..
4000000000118D90 11 38 00 1C 86 39 00 00 00 02 00 03 C0 0F 00 43 .8...9.........C
4000000000118DA0 09 00 00 00 01 00 E0 00 D0 20 20 00 00 00 04 00 .........  .....
4000000000118DB0 11 38 00 1C 86 31 E0 00 48 00 42 03 B0 F0 FF 4B .8...1..H.B....K
4000000000118DC0 0B 80 04 1C 00 14 10 80 3C 00 2B 20 E2 90 14 80 ........<.+ ....
4000000000118DD0 09 80 00 68 10 10 00 00 00 02 00 80 05 78 00 84 ...h.........x..
4000000000118DE0 11 30 44 20 87 30 00 00 00 02 80 03 80 F0 FF 4B .0D .0.........K
4000000000118DF0 0B 80 04 1C 00 14 10 80 3C 00 2B 20 E2 90 14 80 ........<.+ ....
4000000000118E00 09 80 00 68 10 10 00 00 00 02 00 80 05 78 00 84 ...h.........x..
4000000000118E10 10 00 00 00 01 00 60 88 40 0E 61 03 B0 FF FF 4A ......`.@.a....J
4000000000118E20 10 00 00 00 01 00 00 00 00 02 00 00 40 F0 FF 48 ............@..H

l4000000000118E30:
	{ nop.m	0x0; addl	r35,8652,r1; nop.i	0x0; }
	{ ld8	r75,[r35]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r74; nop.i	0x0 }
	{ st8	[r0],r34; st8	[r0],r35; br.cond.sptk.few	4000000000117710; }

l4000000000118E70:
	{ addl	r34,8596,r1; addl	r33,8612,r1; nop.i	0x0 }
	{ ld8	r75,[r34]; ld8	r76,[r33]; br.call.sptk.many	b0,fn4000000000116080; }
	{ nop.m	0x0; adds	r1,0x0,r74; nop.i	0x0 }
	{ ld8	r75,[r34]; nop.m	0x0; br.call.sptk.many	b0,stupidly_hack_special_variables; }
	{ adds	r1,0x0,r74; addl	r15,4096,r0; addl	r34,8644,r1; }
	{ nop.m	0x0; ld8	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp.ltu	p07,p06,r15,r14; (p06) br.cond.dptk.few	4000000000117710 }

l4000000000118EE0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000118E30 }
4000000000118EF0 11 58 0E 00 00 24 00 00 00 02 00 00 D8 FD FC 58 .X...$.........X
4000000000118F00 09 70 00 10 00 21 10 00 28 01 42 A0 04 40 00 84 .p...!..(.B..@..
4000000000118F10 0B 08 00 1D 80 15 10 00 3A 00 2B 00 00 00 04 00 ........:.+.....
4000000000118F20 10 00 00 1C 80 11 00 00 00 02 00 00 D0 EA FF 48 ...............H
4000000000118F30 11 00 00 00 01 00 00 00 00 02 00 00 58 57 FD 58 ............XW.X
4000000000118F40 08 00 00 00 01 00 10 00 28 01 42 00 00 00 04 00 ........(.B.....
4000000000118F50 19 58 02 56 18 10 00 00 00 02 00 00 B8 2E F0 58 .X.V...........X
4000000000118F60 11 08 00 94 00 21 B0 04 94 00 42 00 88 18 F0 58 .....!....B....X
4000000000118F70 09 70 00 44 10 10 00 00 00 02 00 20 00 50 02 84 .p.D....... .P..
4000000000118F80 10 00 00 00 01 00 60 00 38 0E 73 03 10 FB FF 4A ......`.8.s....J

l4000000000118F90:
	{ addl	r34,8596,r1; addl	r33,8612,r1; nop.i	0x0 }
	{ ld8	r75,[r34]; ld8	r76,[r33]; br.call.sptk.many	b0,fn4000000000116080; }
	{ nop.m	0x0; adds	r1,0x0,r74; nop.i	0x0 }
	{ ld8	r75,[r34]; nop.m	0x0; br.call.sptk.many	b0,stupidly_hack_special_variables; }
	{ nop.m	0x0; adds	r1,0x0,r74; br.cond.sptk.few	4000000000118AA0; }

l4000000000118FE0:
	{ addl	r34,8596,r1; addl	r33,8612,r1; nop.i	0x0 }
	{ ld8	r75,[r34]; ld8	r76,[r33]; br.call.sptk.many	b0,fn4000000000116080; }
	{ nop.m	0x0; adds	r1,0x0,r74; nop.i	0x0 }
	{ ld8	r75,[r34]; nop.m	0x0; br.call.sptk.many	b0,stupidly_hack_special_variables; }
	{ adds	r1,0x0,r74; addl	r15,4096,r0; addl	r35,8644,r1; }
	{ nop.m	0x0; ld8	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; cmp.ltu	p07,p06,r15,r14; (p06) br.cond.dptk.few	4000000000116E90 }

l4000000000119050:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000001190A0 }

l4000000000119060:
	{ nop.m	0x0; addl	r34,8652,r1; nop.i	0x0; }
	{ ld8	r75,[r34]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r74; nop.i	0x0 }
	{ st8	[r0],r35; st8	[r0],r34; br.cond.sptk.few	40000000001171E0; }

l40000000001190A0:
	{ nop.m	0x0; addl	r34,8652,r1; nop.i	0x0; }
	{ ld8	r75,[r34]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r74; nop.i	0x0 }
	{ st8	[r0],r35; st8	[r0],r34; br.cond.sptk.few	4000000000116E90 }
40000000001190E0 09 00 00 00 01 00 E0 00 18 31 20 00 00 00 04 00 .........1 .....
40000000001190F0 11 58 02 1C 18 10 00 00 00 02 00 00 98 C5 FF 58 .X.............X
4000000000119100 09 60 01 7A 18 10 00 00 00 02 00 20 00 50 02 84 .`.z....... .P..
4000000000119110 09 00 00 00 01 00 E0 00 B0 30 20 00 00 00 04 00 .........0 .....
4000000000119120 10 00 38 64 98 11 00 00 00 02 00 00 30 EF FF 48 ..8d........0..H
4000000000119130 09 00 00 00 01 00 E0 00 B0 30 20 00 00 00 04 00 .........0 .....
4000000000119140 11 58 02 1C 18 10 00 00 00 02 00 00 48 C5 FF 58 .X..........H..X
4000000000119150 09 28 01 7A 18 10 00 00 00 02 00 20 00 50 02 84 .(.z....... .P..
4000000000119160 09 00 00 00 01 00 E0 00 94 30 20 00 00 00 04 00 .........0 .....
4000000000119170 10 00 38 64 98 11 00 00 00 02 00 00 30 F0 FF 48 ..8d........0..H
4000000000119180 11 00 00 00 01 00 00 00 00 02 00 00 08 55 FD 58 .............U.X
4000000000119190 08 00 00 00 01 00 10 00 28 01 42 00 00 00 04 00 ........(.B.....
40000000001191A0 19 58 02 56 18 10 00 00 00 02 00 00 68 2C F0 58 .X.V........h,.X
40000000001191B0 09 70 04 00 00 24 10 00 28 01 42 60 09 C0 01 84 .p...$..(.B`....
40000000001191C0 11 00 38 5A 90 11 00 00 00 02 00 00 28 16 F0 58 ..8Z........(..X
40000000001191D0 03 70 00 44 10 10 10 00 28 01 42 C0 00 70 1C E6 .p.D....(.B..p..
40000000001191E0 10 00 00 00 01 80 11 22 05 86 48 03 80 DC FF 4A ......."..H....J
40000000001191F0 11 00 00 00 01 00 00 00 00 02 00 00 F0 FD FF 48 ...............H

l4000000000119200:
	{ adds	r33,0x2,r33; addl	r60,1,r0; br.call.sptk.many	b0,fn4000000000115D80; }
	{ ld1	r38,[r33]; adds	r1,0x0,r74; adds	r59,0x0,r8; }
	{ nop.m	0x0; sxt1	r38,r38; br.cond.sptk.few	40000000001175B0 }

l4000000000119230:
	{ ld8	r75,[r33]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ ld4	r14,[r58]; st8	[r0],r34; adds	r1,0x0,r74 }
	{ st8	[r0],r33; ld8	r75,[r43]; nop.i	0x0; }
	{ nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; }
	{ st4	[r14],r58; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ nop.m	0x0; adds	r1,0x0,r74; nop.i	0x0 }
	{ ld8	r75,[r43]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A960; }
	{ adds	r1,0x0,r74; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	40000000001177C0 }

l40000000001192B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000116F50 }
40000000001192C0 08 70 00 54 00 10 40 02 A8 00 42 40 05 60 01 84 .p.T..@...B@.`..
40000000001192D0 0A 60 02 56 18 10 00 00 00 02 00 60 09 70 50 00 .`.V.......`.pP.
40000000001192E0 19 20 05 48 00 21 00 00 00 02 00 00 E8 1B F0 58 . .H.!.........X
40000000001192F0 10 00 00 00 01 00 10 00 28 01 42 00 C0 F1 FF 48 ........(.B....H
4000000000119300 11 00 00 00 01 00 60 00 F0 0E 73 03 D0 05 00 42 ......`...s....B
4000000000119310 10 00 00 00 01 00 60 00 38 0E 73 03 30 06 00 42 ......`.8.s.0..B
4000000000119320 08 58 02 54 00 21 00 00 00 02 00 80 09 D8 01 84 .X.T.!..........
4000000000119330 19 68 02 4A 00 21 00 00 00 02 00 00 18 C4 FF 58 .h.J.!.........X
4000000000119340 00 70 00 46 18 10 80 00 20 2C 00 20 00 50 02 84 .p.F.... ,. .P..
4000000000119350 0B 58 02 56 18 10 E0 40 38 00 40 00 00 00 04 00 .X.V...@8.@.....
4000000000119360 11 00 38 46 98 11 00 00 00 02 00 00 08 16 F0 58 ..8F...........X
4000000000119370 10 08 00 94 00 21 60 00 20 0E 73 03 70 E5 FF 4A .....!`. .s.p..J
4000000000119380 11 00 00 00 01 00 00 00 00 02 00 00 D0 DB FF 48 ...............H
4000000000119390 11 00 00 00 01 00 60 00 F0 0E 73 03 B0 03 00 42 ......`...s....B
40000000001193A0 10 00 00 00 01 00 60 00 38 0E 73 03 80 06 00 42 ......`.8.s....B
40000000001193B0 08 80 40 18 02 21 10 C1 30 04 42 60 09 28 01 84 ..@..!..0.B`.(..
40000000001193C0 0B 60 02 76 00 21 00 10 40 00 33 00 00 00 04 00 .`.v.!..@.3.....
40000000001193D0 08 00 00 00 01 00 D0 04 40 30 20 00 00 00 04 00 ........@0 .....
40000000001193E0 19 70 02 22 18 10 00 00 00 02 00 00 68 C3 FF 58 .p."........h..X
40000000001193F0 00 70 00 46 18 10 80 00 20 2C 00 20 00 50 02 84 .p.F.... ,. .P..
4000000000119400 0B 58 02 56 18 10 E0 40 38 00 40 00 00 00 04 00 .X.V...@8.@.....
4000000000119410 11 00 38 46 98 11 00 00 00 02 00 00 58 15 F0 58 ..8F........X..X
4000000000119420 10 08 00 94 00 21 60 00 20 0E 73 03 C0 E4 FF 4A .....!`. .s....J
4000000000119430 10 00 00 00 01 00 00 00 00 02 00 00 20 DB FF 48 ............ ..H
4000000000119440 08 70 80 19 01 21 F0 40 33 02 42 60 19 00 00 90 .p...!.@3.B`....
4000000000119450 09 60 02 4A 00 21 D0 04 CC 00 42 C0 09 D8 01 84 .`.J.!....B.....
4000000000119460 0A 00 08 1C 80 19 F0 04 38 30 20 00 00 00 04 00 ........80 .....
4000000000119470 19 80 02 1E 18 10 00 00 00 02 00 00 18 27 F0 58 .............'.X
4000000000119480 00 70 00 46 18 10 80 00 20 2C 00 20 00 50 02 84 .p.F.... ,. .P..
4000000000119490 0B 58 02 56 18 10 E0 40 38 00 40 00 00 00 04 00 .X.V...@8.@.....
40000000001194A0 11 00 38 46 98 11 00 00 00 02 00 00 C8 14 F0 58 ..8F...........X
40000000001194B0 10 08 00 94 00 21 60 00 20 0E 73 03 30 E4 FF 4A .....!`. .s.0..J
40000000001194C0 10 00 00 00 01 00 00 00 00 02 00 00 90 DA FF 48 ...............H
40000000001194D0 08 58 06 00 00 24 C0 04 A8 00 42 A0 09 98 01 84 .X...$....B.....
40000000001194E0 19 70 02 76 00 21 F0 04 94 00 42 00 A8 26 F0 58 .p.v.!....B..&.X
40000000001194F0 00 70 00 46 18 10 80 00 20 2C 00 20 00 50 02 84 .p.F.... ,. .P..
4000000000119500 0B 58 02 56 18 10 E0 40 38 00 40 00 00 00 04 00 .X.V...@8.@.....
4000000000119510 11 00 38 46 98 11 00 00 00 02 00 00 58 14 F0 58 ..8F........X..X
4000000000119520 10 08 00 94 00 21 60 00 20 0E 73 03 C0 E3 FF 4A .....!`. .s....J
4000000000119530 10 00 00 00 01 00 00 00 00 02 00 00 20 DA FF 48 ............ ..H
4000000000119540 08 58 06 00 00 24 00 00 00 02 00 80 09 50 01 84 .X...$.......P..
4000000000119550 19 68 02 4A 00 21 00 00 00 02 00 00 38 26 F0 58 .h.J.!......8&.X
4000000000119560 00 70 00 46 18 10 80 00 20 2C 00 20 00 50 02 84 .p.F.... ,. .P..
4000000000119570 0B 58 02 56 18 10 E0 40 38 00 40 00 00 00 04 00 .X.V...@8.@.....
4000000000119580 11 00 38 46 98 11 00 00 00 02 00 00 E8 13 F0 58 ..8F...........X
4000000000119590 10 08 00 94 00 21 60 00 20 0E 73 03 50 E3 FF 4A .....!`. .s.P..J
40000000001195A0 10 00 00 00 01 00 00 00 00 02 00 00 B0 D9 FF 48 ...............H
40000000001195B0 08 58 06 00 00 24 C0 04 A8 00 42 00 00 00 04 00 .X...$....B.....
40000000001195C0 19 68 02 76 00 21 E0 04 94 00 42 00 C8 25 F0 58 .h.v.!....B..%.X
40000000001195D0 00 70 00 46 18 10 80 00 20 2C 00 20 00 50 02 84 .p.F.... ,. .P..
40000000001195E0 0B 58 02 56 18 10 E0 40 38 00 40 00 00 00 04 00 .X.V...@8.@.....
40000000001195F0 11 00 38 46 98 11 00 00 00 02 00 00 78 13 F0 58 ..8F........x..X
4000000000119600 10 08 00 94 00 21 60 00 20 0E 73 03 E0 E2 FF 4A .....!`. .s....J
4000000000119610 10 00 00 00 01 00 00 00 00 02 00 00 40 D9 FF 48 ............@..H
4000000000119620 09 70 00 8C 18 10 00 00 00 02 00 A0 04 00 00 84 .p..............
4000000000119630 11 58 02 1C 18 10 00 00 00 02 00 00 58 48 FD 58 .X..........XH.X
4000000000119640 09 60 01 7A 18 10 E0 08 00 00 48 20 00 50 02 84 .`.z......H .P..
4000000000119650 0B 00 38 5C 90 11 E0 00 B0 30 20 00 00 00 04 00 ..8\.....0 .....
4000000000119660 10 00 38 64 98 11 00 00 00 02 00 00 F0 E9 FF 48 ..8d...........H
4000000000119670 0F 70 00 58 18 10 00 00 00 02 00 40 00 00 40 00 .p.X.......@..@.
4000000000119680 11 58 02 1C 18 10 00 00 00 02 00 00 08 48 FD 58 .X...........H.X
4000000000119690 09 28 01 7A 18 10 E0 08 00 00 48 20 00 50 02 84 .(.z......H .P..
40000000001196A0 0B 00 38 5C 90 11 E0 00 94 30 20 00 00 00 04 00 ..8\.....0 .....
40000000001196B0 10 00 38 64 98 11 00 00 00 02 00 00 F0 EA FF 48 ..8d...........H
40000000001196C0 0B 28 11 FB FA 27 50 02 94 30 20 00 00 00 04 00 .(...'P..0 .....
40000000001196D0 0B 70 00 4A 00 10 00 00 00 02 00 C0 01 70 50 00 .p.J.........pP.
40000000001196E0 10 00 00 00 01 00 70 00 38 0C 73 03 C0 E2 FF 4A ......p.8.s....J
40000000001196F0 10 00 00 00 01 00 00 00 00 02 00 00 00 F8 FF 48 ...............H
4000000000119700 0B 28 11 FB FA 27 50 02 94 30 20 00 00 00 04 00 .(...'P..0 .....
4000000000119710 0B 70 00 4A 00 10 00 00 00 02 00 C0 01 70 50 00 .p.J.........pP.
4000000000119720 10 00 00 00 01 00 60 00 38 0E 73 03 C0 E1 FF 4A ......`.8.s....J
4000000000119730 11 00 00 00 01 00 00 00 00 02 00 00 C0 E3 FF 48 ...............H
4000000000119740 10 00 00 00 01 00 60 00 38 0E 73 03 A0 03 00 42 ......`.8.s....B
4000000000119750 09 80 C0 18 02 21 10 C1 31 04 42 60 09 28 01 84 .....!..1.B`.(..
4000000000119760 0A 00 08 20 80 19 D0 04 40 30 20 00 00 00 04 00 ... ....@0 .....
4000000000119770 19 70 02 22 18 10 00 00 00 02 00 00 D8 BF FF 58 .p."...........X
4000000000119780 00 70 00 46 18 10 80 00 20 2C 00 20 00 50 02 84 .p.F.... ,. .P..
4000000000119790 0B 58 02 56 18 10 E0 40 38 00 40 00 00 00 04 00 .X.V...@8.@.....
40000000001197A0 11 00 38 46 98 11 00 00 00 02 00 00 C8 11 F0 58 ..8F...........X
40000000001197B0 10 08 00 94 00 21 60 00 20 0E 73 03 30 E1 FF 4A .....!`. .s.0..J
40000000001197C0 10 00 00 00 01 00 00 00 00 02 00 00 90 D7 FF 48 ...............H
40000000001197D0 08 70 00 18 02 21 F0 40 30 04 42 00 00 00 04 00 .p...!.@0.B.....
40000000001197E0 09 58 06 00 00 24 C0 04 94 00 42 A0 09 98 01 84 .X...$....B.....
40000000001197F0 0A 00 08 1C 80 19 F0 04 38 30 20 00 00 00 04 00 ........80 .....
4000000000119800 19 80 02 1E 18 10 00 00 00 02 00 00 88 23 F0 58 .............#.X
4000000000119810 00 70 00 46 18 10 80 00 20 2C 00 20 00 50 02 84 .p.F.... ,. .P..
4000000000119820 0B 58 02 56 18 10 E0 40 38 00 40 00 00 00 04 00 .X.V...@8.@.....
4000000000119830 11 00 38 46 98 11 00 00 00 02 00 00 38 11 F0 58 ..8F........8..X
4000000000119840 10 08 00 94 00 21 60 00 20 0E 73 03 A0 E0 FF 4A .....!`. .s....J
4000000000119850 10 00 00 00 01 00 00 00 00 02 00 00 00 D7 FF 48 ...............H
4000000000119860 08 58 06 00 00 24 C0 04 A8 00 42 00 00 00 04 00 .X...$....B.....
4000000000119870 19 68 02 66 00 21 E0 04 94 00 42 00 18 23 F0 58 .h.f.!....B..#.X
4000000000119880 00 70 00 46 18 10 80 00 20 2C 00 20 00 50 02 84 .p.F.... ,. .P..
4000000000119890 0B 58 02 56 18 10 E0 40 38 00 40 00 00 00 04 00 .X.V...@8.@.....
40000000001198A0 11 00 38 46 98 11 00 00 00 02 00 00 C8 10 F0 58 ..8F...........X
40000000001198B0 10 08 00 94 00 21 60 00 20 0E 73 03 30 E0 FF 4A .....!`. .s.0..J
40000000001198C0 11 00 00 00 01 00 00 00 00 02 00 00 90 D6 FF 48 ...............H
40000000001198D0 10 00 00 00 01 00 60 00 38 0E 73 03 E0 00 00 42 ......`.8.s....B
40000000001198E0 11 58 02 54 00 21 C0 04 94 00 42 00 68 BE FF 58 .X.T.!....B.h..X
40000000001198F0 00 70 00 46 18 10 80 00 20 2C 00 20 00 50 02 84 .p.F.... ,. .P..
4000000000119900 0B 58 02 56 18 10 E0 40 38 00 40 00 00 00 04 00 .X.V...@8.@.....
4000000000119910 11 00 38 46 98 11 00 00 00 02 00 00 58 10 F0 58 ..8F........X..X
4000000000119920 10 08 00 94 00 21 60 00 20 0E 73 03 C0 DF FF 4A .....!`. .s....J
4000000000119930 10 00 00 00 01 00 00 00 00 02 00 00 20 D6 FF 48 ............ ..H
4000000000119940 08 58 06 00 00 24 C0 04 A8 00 42 00 00 00 04 00 .X...$....B.....
4000000000119950 19 68 02 76 00 21 E0 04 94 00 42 00 38 22 F0 58 .h.v.!....B.8".X
4000000000119960 00 70 00 46 18 10 80 00 20 2C 00 20 00 50 02 84 .p.F.... ,. .P..
4000000000119970 0B 58 02 56 18 10 E0 40 38 00 40 00 00 00 04 00 .X.V...@8.@.....
4000000000119980 11 00 38 46 98 11 00 00 00 02 00 00 E8 0F F0 58 ..8F...........X
4000000000119990 10 08 00 94 00 21 60 00 20 0E 73 03 50 DF FF 4A .....!`. .s.P..J
40000000001199A0 10 00 00 00 01 00 00 00 00 02 00 00 B0 D5 FF 48 ...............H
40000000001199B0 08 58 06 00 00 24 00 00 00 02 00 80 09 50 01 84 .X...$.......P..
40000000001199C0 19 68 02 4A 00 21 00 00 00 02 00 00 C8 21 F0 58 .h.J.!.......!.X
40000000001199D0 00 70 00 46 18 10 80 00 20 2C 00 20 00 50 02 84 .p.F.... ,. .P..
40000000001199E0 0B 58 02 56 18 10 E0 40 38 00 40 00 00 00 04 00 .X.V...@8.@.....
40000000001199F0 11 00 38 46 98 11 00 00 00 02 00 00 78 0F F0 58 ..8F........x..X
4000000000119A00 10 08 00 94 00 21 60 00 20 0E 73 03 E0 DE FF 4A .....!`. .s....J
4000000000119A10 10 00 00 00 01 00 00 00 00 02 00 00 40 D5 FF 48 ............@..H
4000000000119A20 08 70 80 18 02 21 F0 40 31 04 42 00 00 00 04 00 .p...!.@1.B.....
4000000000119A30 09 58 06 00 00 24 C0 04 94 00 42 A0 09 D8 01 84 .X...$....B.....
4000000000119A40 0A 00 08 1C 80 19 F0 04 38 30 20 00 00 00 04 00 ........80 .....
4000000000119A50 19 80 02 1E 18 10 00 00 00 02 00 00 38 21 F0 58 ............8!.X
4000000000119A60 00 70 00 46 18 10 80 00 20 2C 00 20 00 50 02 84 .p.F.... ,. .P..
4000000000119A70 0B 58 02 56 18 10 E0 40 38 00 40 00 00 00 04 00 .X.V...@8.@.....
4000000000119A80 11 00 38 46 98 11 00 00 00 02 00 00 E8 0E F0 58 ..8F...........X
4000000000119A90 10 08 00 94 00 21 60 00 20 0E 73 03 50 DE FF 4A .....!`. .s.P..J
4000000000119AA0 10 00 00 00 01 00 00 00 00 02 00 00 B0 D4 FF 48 ...............H
4000000000119AB0 11 58 02 00 00 21 00 00 00 02 00 00 18 0F F0 58 .X...!.........X
4000000000119AC0 09 70 E0 18 01 21 00 00 00 02 00 20 00 50 02 84 .p...!..... .P..
4000000000119AD0 10 00 20 1C 98 11 00 00 00 02 00 00 70 EE FF 48 .. .........p..H
4000000000119AE0 08 70 00 19 02 21 F0 40 32 04 42 60 19 00 00 90 .p...!.@2.B`....
4000000000119AF0 0B 60 02 4A 00 21 00 10 38 00 33 00 00 00 04 00 .`.J.!..8.3.....
4000000000119B00 08 00 00 00 01 00 D0 04 38 30 20 00 00 00 04 00 ........80 .....
4000000000119B10 19 70 02 1E 18 10 00 00 00 02 00 00 78 20 F0 58 .p..........x .X
4000000000119B20 00 70 00 46 18 10 80 00 20 2C 00 20 00 50 02 84 .p.F.... ,. .P..
4000000000119B30 0B 58 02 56 18 10 E0 40 38 00 40 00 00 00 04 00 .X.V...@8.@.....
4000000000119B40 11 00 38 46 98 11 00 00 00 02 00 00 28 0E F0 58 ..8F........(..X
4000000000119B50 10 08 00 94 00 21 60 00 20 0E 73 03 90 DD FF 4A .....!`. .s....J
4000000000119B60 10 00 00 00 01 00 00 00 00 02 00 00 F0 D3 FF 48 ...............H

l4000000000119B70:
	{ ld8	r75,[r33]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ ld4	r14,[r58]; st8	[r0],r34; adds	r1,0x0,r74 }
	{ st8	[r0],r33; ld8	r75,[r43]; nop.i	0x0; }
	{ nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; }
	{ st4	[r14],r58; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ nop.m	0x0; adds	r1,0x0,r74; nop.i	0x0 }
	{ ld8	r75,[r43]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A960; }
	{ adds	r1,0x0,r74; cmp4.eq	p07,p06,0x0,r8; (p07) br.cond.dptk.few	4000000000117290 }

l4000000000119BF0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000116F50 }

l4000000000119C00:
	{ ld8	r75,[r33]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ ld4	r14,[r58]; st8	[r0],r34; adds	r1,0x0,r74 }
	{ st8	[r0],r33; ld8	r75,[r43]; nop.i	0x0; }
	{ nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; }
	{ st4	[r14],r58; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ nop.m	0x0; adds	r1,0x0,r74; nop.i	0x0 }
	{ ld8	r75,[r43]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A960; }
	{ cmp4.eq	p06,p07,0x0,r8; nop.m	0x0; adds	r1,0x0,r74; }
	{ (p06) ld4	r8,[r45]; nop.i	0x0; (p06) br.cond.dptk.few	4000000000116AB0 }

l4000000000119C86:
	{ chk.a.nc	r0,3FFFFFFFFF11A486; nop; break.i	0x80000 }

l4000000000119C90:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000116F50 }

l4000000000119CA0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_wrerror; }
	{ adds	r1,0x0,r74; addl	r14,-10260,r1; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r75,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BE00; }
	{ ld4	r14,[r34]; nop.m	0x0; adds	r1,0x0,r74; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000118A90 }

l4000000000119D00:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000118F90 }
4000000000119D10 11 00 00 00 01 00 00 00 00 02 00 00 F8 40 FD 58 .............@.X
4000000000119D20 09 08 00 94 00 21 E0 00 88 20 20 00 00 00 04 00 .....!...  .....
4000000000119D30 08 00 00 00 01 00 60 00 38 0E 73 20 44 0A 0C 91 ......`.8.s D...
4000000000119D40 17 00 00 00 00 C8 01 28 F9 FF 25 00 60 ED FF 48 .......(..%.`..H
4000000000119D50 08 00 00 00 01 00 00 00 B0 00 23 E0 00 C0 19 E4 ..........#.....
4000000000119D60 19 68 B2 70 05 20 50 0A 00 00 C8 03 D0 D0 FF 49 .h.p. P........I
4000000000119D70 11 00 00 00 01 00 00 00 00 02 00 00 30 E1 FF 48 ............0..H

;; sh_getopt: 4000000000119D80
;;   Called from:
;;     400000000011279C (in getopts_builtin)
;;     4000000000112B8C (in getopts_builtin)
;;     4000000000112FBC (in getopts_builtin)
sh_getopt proc
	{ alloc	r43,ar.pfs,0x12,0x0,0xD; addl	r36,8664,r1; mov	r42,b2 }
	{ addl	r39,8668,r1; adds	r44,0x0,r1; addl	r37,8676,r1; }
	{ ld4	r14,[r36]; st8	[r0],r39; nop.i	0x0; }
	{ cmp4.lt	p07,p06,r14,r32; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011A250; }

l4000000000119DC0:
	{ cmp4.lt	p07,p06,r14,r0; nop.i	0x0; (p07) br.cond.dpnt.few	400000000011A250; }

l4000000000119DD0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	4000000000119F50 }

l4000000000119DE0:
	{ nop.m	0x0; ld8	r38,[r37]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r38; nop.i	0x0; (p06) br.cond.spnt.few	4000000000119F80; }

l4000000000119E00:
	{ ld1	r40,[r38]; nop.m	0x0; sxt1	r40,r40; }
	{ adds	r35,0x0,r40; cmp4.eq	p07,p06,0x0,r40; (p07) br.cond.dptk.few	4000000000119F80 }

l4000000000119E20:
	{ addl	r14,8688,r1; nop.m	0x0; adds	r38,0x1,r38; }
	{ ld4	r15,[r14]; st8	[r38],r37; nop.i	0x0; }
	{ nop.m	0x0; adds	r15,0x1,r15; nop.i	0x0; }
	{ st4	[r15],r14; nop.m	0x0; nop.i	0x0; }

l4000000000119E60:
	{ addl	r41,6336,r1; nop.m	0x0; adds	r45,0x0,r34 }
	{ adds	r46,0x0,r40; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B680; }
	{ adds	r1,0x0,r44; st4	[r40],r41; cmp.eq	p06,p07,0x0,r38 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000119FE0; }

l4000000000119EA0:
	{ ld1	r14,[r38]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	4000000000119FE0; }

l4000000000119EC0:
	{ cmp4.eq	p06,p07,0x3A,r35; nop.m	0x0; cmp.eq	p08,p09,0x0,r8; }
	{ (p06) addl	r15,1,r0; (p08) addl	r14,1,r0; (p07) adds	r15,0x0,r0 }

l4000000000119ED6:
	{ Invalid; (p07) dep	r0,r0,r0,35,2; (p34) nop }

l4000000000119EDC:
	{ cmp.lt	p00,p43,0x0,r66; (p01) cmp.lt	p00,p16,r0,r64; (p33) cmp.eq.unc	p35,p16,r67,r3; }

l4000000000119EE0:
	{ (p09) adds	r14,0x0,r0; or	r14,r14,r15; addl	r15,8660,r1; }

l4000000000119EE6:
	{ Invalid; (p07) nop; nop }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD9D7D6; nop; (p32) nop }

l4000000000119F00:
	{ addl	r14,6340,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	400000000011A160; }

l4000000000119F20:
	{ (p06) addl	r8,63,r0; nop.m	0x0; nop.i	0x0 }

l4000000000119F26:
	{ break.m	0x4000; mov	pr,0x4000; break.i	0x80000 }

l4000000000119F30:
	{ nop.m	0x0; mov.i	ar.pfs,r43; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r42,4000000000119F40; br.ret	b0 }

l4000000000119F50:
	{ nop.m	0x0; addl	r14,1,r0; cmp4.lt	p07,p06,0x1,r32 }
	{ nop.m	0x0; st8	[r0],r37; nop.i	0x0; }
	{ st4	[r14],r36; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000119FC0 }

l4000000000119F80:
	{ nop.m	0x0; sxt4	r15,r14; shladd	r15,r15,0x3,r33; }
	{ ld8	r38,[r15]; ld1	r15,[r38]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r15; (p07) br.cond.dpnt.few	400000000011A0F0 }

l4000000000119FC0:
	{ addl	r8,-1,r0; nop.m	0x0; mov.i	ar.pfs,r43; }
	{ nop.m	0x0; mov.spnt	b0,r42,4000000000119FD0; br.ret	b0 }

l4000000000119FE0:
	{ ld4	r14,[r36]; cmp4.eq	p06,p07,0x3A,r35; cmp.eq	p08,p09,0x0,r8 }
	{ st8	[r0],r37; adds	r14,0x1,r14; (p06) addl	r15,1,r0; }

l400000000011A000:
	{ st4	[r14],r36; (p07) adds	r15,0x0,r0; (p08) addl	r14,1,r0; }

l400000000011A00C:
	{ cmp.lt	p00,p43,0x0,r72; (p01) cmp.lt	p00,p16,r0,r64; Invalid; }

l400000000011A010:
	{ (p09) adds	r14,0x0,r0; or	r14,r14,r15; addl	r15,8660,r1; }

l400000000011A016:
	{ Invalid; (p07) nop; nop }
	{ (p03) chk.a.clr	f0,3FFFFFFFFFD9D906; nop; nop }

l400000000011A030:
	{ adds	r8,0x1,r8; ld1	r14,[r8]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x3A,r14; }
	{ nop.m	0x0; (p07) adds	r8,0x0,r35; (p07) br.cond.dptk.few	4000000000119F30 }

l400000000011A05C:
	{ (p55) nop; cmp.lt	p00,p00,r32,r0; Invalid }

l400000000011A060:
	{ nop.m	0x0; ld8	r14,[r37]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011A1F0; }

l400000000011A080:
	{ ld1	r15,[r14]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	400000000011A1F0 }

l400000000011A0A0:
	{ ld4	r15,[r36]; st8	[r14],r39; adds	r8,0x0,r35 }
	{ st8	[r0],r37; nop.i	0x0; adds	r15,0x1,r15; }
	{ st4	[r15],r36; nop.m	0x0; nop.i	0x0 }

l400000000011A0D0:
	{ nop.m	0x0; mov.i	ar.pfs,r43; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r42,400000000011A0E0; br.ret	b0 }

l400000000011A0F0:
	{ adds	r15,0x1,r38; ld1	r35,[r15]; addl	r15,8684,r1; }
	{ nop.m	0x0; sxt1	r35,r35; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x2D,r35; adds	r40,0x0,r35; (p07) br.cond.dpnt.few	400000000011A3C0; }

l400000000011A120:
	{ cmp4.eq	p06,p07,0x0,r35; adds	r38,0x2,r38; (p06) br.cond.dpnt.few	4000000000119FC0; }

l400000000011A130:
	{ st4	[r14],r15; nop.m	0x0; addl	r15,2,r0 }
	{ addl	r14,8688,r1; st8	[r38],r37; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.cond.sptk.few	4000000000119E60 }

l400000000011A160:
	{ addl	r14,-10652,r1; nop.m	0x0; addl	r46,-5556,r1 }
	{ addl	r47,5,r0; nop.m	0x0; adds	r45,0x0,r0; }
	{ ld8	r14,[r14]; ld8	r46,[r46]; nop.i	0x0; }
	{ ld8	r35,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r44; adds	r45,0x0,r35; addl	r46,1,r0 }
	{ adds	r47,0x0,r8; ld8	r48,[r33]; adds	r49,0x0,r40; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ addl	r8,63,r0; adds	r1,0x0,r44; mov.i	ar.pfs,r43; }
	{ nop.m	0x0; mov.spnt	b0,r42,400000000011A1E0; br.ret	b0 }

l400000000011A1F0:
	{ ld4	r14,[r36]; addl	r16,8664,r1; sxt4	r15,r14 }
	{ cmp4.eq	p07,p06,r32,r14; adds	r14,0x1,r14; (p07) br.cond.dpnt.few	400000000011A270; }

l400000000011A210:
	{ nop.m	0x0; shladd	r33,r15,0x3,r33; adds	r8,0x0,r35 }
	{ nop.m	0x0; st8	[r0],r37; nop.i	0x0; }
	{ ld8	r15,[r33]; st4	[r14],r16; nop.i	0x0; }
	{ st8	[r15],r39; nop.i	0x0; br.cond.sptk.few	400000000011A0D0 }

l400000000011A250:
	{ addl	r8,-1,r0; st4	[r32],r36; mov.i	ar.pfs,r43; }
	{ nop.m	0x0; mov.spnt	b0,r42,400000000011A260; br.ret	b0 }

l400000000011A270:
	{ addl	r14,6340,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; addl	r14,-5540,r1; (p07) br.cond.dpnt.few	400000000011A2F0; }

l400000000011A290:
	{ ld1.a	r35,[r34]; st4	[r40],r41; nop.i	0x0 }
	{ ld8	r14,[r14]; st8	[r14],r39; nop.i	0x0; }
	{ nop.m	0x0; ld1.c.clr	r35,[r34]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r35,r35; cmp4.eq	p07,p06,0x3A,r35; }
	{ (p06) addl	r8,63,r0; nop.i	0x0; (p07) addl	r8,58,r0 }

l400000000011A2D6:
	{ chk.a.nc	f0,3FFFFFFFFF11AAD6; (p04) nop; nop }

l400000000011A2E0:
	{ st8	[r0],r37; nop.i	0x0; br.cond.sptk.few	400000000011A0D0 }

l400000000011A2F0:
	{ addl	r14,-10652,r1; nop.m	0x0; addl	r46,-5548,r1 }
	{ addl	r47,5,r0; nop.m	0x0; adds	r45,0x0,r0; }
	{ ld8	r14,[r14]; ld8	r46,[r46]; nop.i	0x0; }
	{ ld8	r35,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r44; adds	r45,0x0,r35; addl	r46,1,r0 }
	{ adds	r47,0x0,r8; ld8	r48,[r33]; adds	r49,0x0,r40; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ adds	r1,0x0,r44; ld1.a	r35,[r34]; nop.i	0x0 }
	{ st4	[r40],r41; addl	r14,-5540,r1; nop.i	0x0; }
	{ ld8	r14,[r14]; st8	[r14],r39; nop.i	0x0; }
	{ ld1.c.clr	r35,[r34]; nop.m	0x0; sxt1	r35,r35; }
	{ cmp4.eq	p07,p06,0x3A,r35; (p06) addl	r8,63,r0; nop.i	0x0; }

l400000000011A3AC:
	{ invala; mov	pr,r32,0x0; zxt4	r14,r0 }

l400000000011A3BC:
	{ (p57) cmp.lt.unc	p63,p09,r63,r36; zxt1	r64,r64; break.b	0x1000 }

l400000000011A3C0:
	{ adds	r38,0x2,r38; nop.m	0x0; adds	r40,0x0,r35; }
	{ ld1	r15,[r38]; nop.m	0x0; sxt1	r15,r15; }
	{ cmp4.eq	p07,p06,0x0,r15; nop.m	0x0; addl	r15,8684,r1; }
	{ (p07) adds	r14,0x1,r14; nop.m	0x0; (p07) addl	r8,-1,r0; }

l400000000011A3F6:
	{ chk.a.nc	f0,3FFFFFFFFF11ABF6; (p04) cmp4.ne.or.andcm	p63,p15,r124,r127; (p01) nop }

l400000000011A400:
	{ (p07) st4	[r14],r36; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000119F30; }

l400000000011A406:
	{ chk.a.nc	f0,3FFFFFFFFF11AC06; nop; nop }

l400000000011A410:
	{ st4	[r14],r15; nop.m	0x0; addl	r15,2,r0 }
	{ addl	r14,8688,r1; st8	[r38],r37; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.cond.sptk.few	4000000000119E60; }

;; sh_getopt_restore_state: 400000000011A440
;;   Called from:
;;     400000000011275C (in getopts_builtin)
;;     4000000000112B6C (in getopts_builtin)
;;     4000000000112F8C (in getopts_builtin)
sh_getopt_restore_state proc
	{ addl	r14,8676,r1; ld8	r15,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r15; (p07) addl	r15,8684,r1; nop.i	0x0; }

l400000000011A45C:
	{ Invalid; (p02) cmp4.ne.or.andcm	p32,p40,r3,r4; (p01) mov	pr,r96,0x9178 }

l400000000011A466:
	{ (p07) chk.a.clr	f112,3FFFFFFFFF33BC76; (p08) cmp4.ltu	p00,p00,0x10,r22; Invalid; }

l400000000011A46C:
	{ cmp4.eq.or.andcm	p16,p43,r22,r0; (p01) mov	pr,r3,0x40C0; (p04) cmp4.eq.or.andcm	p04,p48,r72,r4 }

l400000000011A476:
	{ Invalid; (p07) cmp4.ltu	p00,p00,0xF,r22; (p01) cmp.ltu	p04,p06,r0,r8; }

l400000000011A47C:
	{ Invalid; (p02) cmp4.eq.or.andcm	p00,p40,r8,r6; zxt1	r100,r0; }

l400000000011A486:
	{ Invalid; cmp4.eq	p00,p00,r0,r1; (p01) br.call.spnt.many	b0,b3; }

l400000000011A48C:
	{ Invalid; Invalid; add	r0,r32,r0 }

l400000000011A496:
	{ break.m	0x4000; (p34) break.i	0x84000; (p32) break.i	0x80001 }
400000000011A4A0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
400000000011A4B0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; internal_getopt: 400000000011A4C0
;;   Called from:
;;     40000000000E920C (in alias_builtin)
;;     40000000000E970C (in unalias_builtin)
;;     40000000000E9A1C (in bind_builtin)
;;     40000000000EBE1C (in cd_builtin)
;;     40000000000EC6FC (in pwd_builtin)
;;     40000000000EC79C (in pwd_builtin)
;;     40000000000ECC5C (in command_builtin)
;;     40000000000ECCFC (in command_builtin)
;;     40000000000EDAFC (in no_options)
;;     40000000000F09BC (in fn40000000000F0900)
;;     40000000000F2D3C (in enable_builtin)
;;     40000000000F7CBC (in exec_builtin)
;;     40000000000F7D5C (in exec_builtin)
;;     40000000000F94EC (in fc_builtin)
;;     40000000000FB6EC (in hash_builtin)
;;     40000000000FC2FC (in help_builtin)
;;     40000000000FC3AC (in help_builtin)
;;     40000000000FDD3C (in history_builtin)
;;     40000000000FEF3C (in jobs_builtin)
;;     40000000000FF7EC (in disown_builtin)
;;     40000000000FF89C (in disown_builtin)
;;     4000000000100B5C (in mapfile_builtin)
;;     40000000001047CC (in read_builtin)
;;     4000000000109E1C (in set_builtin)
;;     400000000010A55C (in unset_builtin)
;;     400000000010A5EC (in unset_builtin)
;;     400000000010BE2C (in set_or_show_attributes)
;;     400000000010D5BC (in suspend_builtin)
;;     400000000010D63C (in suspend_builtin)
;;     400000000010DFEC (in trap_builtin)
;;     400000000010E08C (in trap_builtin)
;;     400000000010F78C (in type_builtin)
;;     400000000011021C (in ulimit_builtin)
;;     400000000011031C (in ulimit_builtin)
;;     400000000011195C (in umask_builtin)
;;     40000000001119EC (in umask_builtin)
;;     400000000011261C (in getopts_builtin)
;;     40000000001143DC (in shopt_builtin)
;;     4000000000116A5C (in printf_builtin)
;;     4000000000116B6C (in printf_builtin)
;;     400000000011B13C (in fn400000000011B040)
;;     400000000011E30C (in compopt_builtin)
;;     400000000011E3DC (in compopt_builtin)
internal_getopt proc
	{ alloc	r42,ar.pfs,0xF,0x0,0xD; ld1	r14,[r33]; mov	r44,pr }
	{ addl	r35,8708,r1; adds	r43,0x0,r1; addl	r37,8692,r1; }
	{ nop.m	0x0; mov	r41,b1; sxt1	r14,r14 }
	{ addl	r38,1,r0; cmp4.eq	p06,p07,0x2B,r14; nop.i	0x0; }
	{ nop.m	0x0; (p06) addl	r14,1,r0; nop.i	0x0; }

l400000000011A50C:
	{ cmp4.eq.and	p00,p49,r1,r0; (p01) cmp.eq	p00,p16,r0,r64; mov	pr,r72,0xE400 }

l400000000011A516:
	{ (p03) chk.a.clr	f0,3FFFFFFFFFD9D716; nop; nop }

l400000000011A520:
	{ cmp.eq	p16,p17,0x0,r14; nop.m	0x0; addl	r14,8700,r1; }
	{ ld8	r15,[r14]; nop.m	0x0; (p17) adds	r33,0x1,r33; }

l400000000011A540:
	{ cmp.eq	p07,p06,r15,r32; addl	r15,1,r0; (p07) br.cond.dpnt.few	400000000011A9C0; }

l400000000011A550:
	{ nop.m	0x0; st4	[r15],r35; addl	r15,9268,r1 }
	{ st8	[r32],r14; nop.m	0x0; nop.i	0x0 }
	{ st8	[r32],r37; st8	[r0],r15; nop.i	0x0 }

l400000000011A580:
	{ adds	r15,0x8,r32; ld8	r15,[r15]; nop.i	0x0; }
	{ ld8	r36,[r15]; adds	r16,0x1,r36; nop.i	0x0; }
	{ ld1	r15,[r36]; nop.m	0x0; sxt1	r15,r15; }
	{ cmp4.eq	p06,p07,0x2D,r15; (p06) br.cond.dpnt.few	400000000011AC10; (p16) br.cond.dpnt.few	400000000011AA20; }

l400000000011A5BC:
	{ (p35) cmp.lt	p00,p17,r64,r33; czx1.r	r106,r97; br.cond	b0 }

l400000000011A5C0:
	{ cmp4.eq	p06,p07,0x2B,r15; nop.i	0x0; (p07) br.cond.dpnt.few	400000000011AA20; }

l400000000011A5D0:
	{ ld1	r16,[r16]; nop.m	0x0; sxt1	r16,r16; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r16; (p06) br.cond.dpnt.few	400000000011AA20; }

l400000000011A5F0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000011A600:
	{ addl	r14,9276,r1; nop.m	0x0; nop.i	0x0; }
	{ st4	[r15],r14; nop.m	0x0; addl	r14,6348,r1; }
	{ st1	[r15],r14; nop.m	0x0; nop.i	0x0 }

l400000000011A630:
	{ nop.m	0x0; sxt4	r39,r38; adds	r45,0x0,r33 }
	{ adds	r38,0x1,r38; add	r14,r36,r39; nop.i	0x0; }
	{ ld1	r46,[r14]; addl	r14,9260,r1; sxt1	r46,r46 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x3A,r46; adds	r34,0x0,r46; adds	r40,0x0,r46; }
	{ st4	[r46],r14; (p06) br.cond.dpnt.few	400000000011A810; br.call.sptk.many	b0,fn400000000001B680; }

l400000000011A68C:
	{ cmp.eq	p02,p08,r60,r44; flushrs; break.i	0x1000 }
	{ nop; zxt1	r96,r64; br.cond	b0; }
	{ (p11) cmp.lt	p00,p11,r64,r33; Invalid; Invalid }

l400000000011A6B0:
	{ ld1	r14,[r8]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x3A,r14; nop.m	0x0; cmp4.eq	p09,p08,0x3B,r14 }
	{ nop.b	0x0; (p06) br.cond.dpnt.few	400000000011A780; (p09) br.cond.dpnt.few	400000000011A780; }

l400000000011A6DC:
	{ (p05) cmp.eq	p00,p17,r64,r33; (p48) cmp.lt.unc	p08,p28,r67,r97; (p01) br.cond	b1 }

l400000000011A6E0:
	{ cmp4.eq	p07,p06,0x23,r14; sxt4	r14,r38; (p07) br.cond.dpnt.few	400000000011AAC0; }

l400000000011A6F0:
	{ add	r36,r36,r14; st4	[r38],r35; nop.i	0x0; }
	{ ld1	r14,[r36]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	400000000011A740 }

l400000000011A720:
	{ ld8	r14,[r32]; addl	r16,1,r0; addl	r15,8708,r1; }
	{ st4	[r16],r15; st8	[r14],r37; nop.i	0x0 }

l400000000011A740:
	{ addl	r14,9252,r1; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; st8	[r0],r14; nop.i	0x0 }

l400000000011A760:
	{ adds	r8,0x0,r34; mov	pr,r44,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r42; }
	{ nop.m	0x0; mov.spnt	b0,r41,400000000011A770; br.ret	b0 }

l400000000011A780:
	{ add	r36,r36,r39,0x1; ld1	r15,[r36]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p08,p09,0x0,r15; (p08) br.cond.dptk.few	400000000011A930 }

l400000000011A7B0:
	{ addl	r15,9252,r1; ld8	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; st8	[r14],r37; addl	r14,1,r0; }
	{ nop.m	0x0; st4	[r14],r35; nop.i	0x0; }
	{ st8	[r36],r15; nop.m	0x0; nop.i	0x0 }

l400000000011A7F0:
	{ adds	r8,0x0,r34; mov	pr,r44,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r42; }
	{ nop.m	0x0; mov.spnt	b0,r41,400000000011A800; br.ret	b0 }

l400000000011A810:
	{ nop.m	0x0; addl	r45,6349,r1; nop.i	0x0; }
	{ st1	[r45],r127,-1; nop.i	0x0; br.call.sptk.many	b0,sh_invalidopt; }
	{ nop.m	0x0; ld8	r14,[r37]; adds	r1,0x0,r43 }
	{ ld4	r15,[r35]; adds	r16,0x8,r14; adds	r15,0x1,r15; }
	{ ld8	r17,[r16]; st4	[r15],r35; sxt4	r16,r15; }
	{ ld8	r15,[r17]; add	r15,r15,r16; nop.i	0x0; }
	{ ld1	r15,[r15]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	400000000011AA70 }

l400000000011A890:
	{ ld8	r14,[r14]; addl	r15,8692,r1; addl	r16,1,r0; }
	{ st8	[r14],r15; addl	r15,8708,r1; cmp.eq	p06,p07,0x0,r14; }
	{ st4	[r16],r15; addl	r15,9252,r1; (p06) addl	r34,63,r0; }

l400000000011A8C0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st8	[r0],r15; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011A760; }

l400000000011A8E0:
	{ ld8	r15,[r14]; addl	r14,9268,r1; addl	r34,63,r0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st8	[r15],r14; nop.m	0x0; nop.i	0x0 }

l400000000011A910:
	{ adds	r8,0x0,r34; mov	pr,r44,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r42; }
	{ nop.m	0x0; mov.spnt	b0,r41,400000000011A920; br.ret	b0 }

l400000000011A930:
	{ ld8	r15,[r32]; adds	r16,0x8,r15; cmp.eq	p08,p09,0x0,r15 }
	{ nop.b	0x0; (p08) br.cond.dpnt.few	400000000011AD10; (p06) br.cond.dpnt.few	400000000011A980; }

l400000000011A94C:
	{ (p02) nop; (p02) nop; Invalid }

l400000000011A950:
	{ ld8	r17,[r16]; ld8	r17,[r17]; nop.i	0x0; }
	{ ld1	r18,[r17]; nop.m	0x0; sxt1	r18,r18; }
	{ cmp4.eq	p06,p07,0x2D,r18; (p06) br.cond.dpnt.few	400000000011ACE0; (p17) br.cond.dptk.few	400000000011ACD0 }

l400000000011A97C:
	{ (p27) nop; (p02) cmp.lt	p00,p08,r4,r6; Invalid }

l400000000011A980:
	{ ld8	r16,[r16]; ld8	r14,[r15]; nop.i	0x0; }
	{ ld8	r15,[r16]; st8	[r14],r37; addl	r14,9252,r1; }
	{ nop.m	0x0; st8	[r15],r14; addl	r14,1,r0; }
	{ st4	[r14],r35; nop.i	0x0; br.cond.sptk.few	400000000011A7F0 }

l400000000011A9C0:
	{ ld4	r38,[r35]; ld8	r32,[r37]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x1,r38; (p07) adds	r14,0x8,r32; nop.i	0x0; }

l400000000011A9DC:
	{ nop; cmp4.eq.and	p00,p32,r32,r0; Invalid }

l400000000011A9EC:
	{ nop; Invalid; mov	pr,r32,0x0 }

l400000000011A9F6:
	{ chk.a.nc	f0,3FFFFFFFFF11B1F6; nop; break.i	0x80000 }

l400000000011AA00:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r32; (p07) br.cond.spnt.few	400000000011A580; }

l400000000011AA10:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000011AA20:
	{ st8	[r0],r14; addl	r14,9268,r1; nop.b	0x0 }
	{ addl	r34,-1,r0; nop.m	0x0; mov	pr,r44,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; adds	r8,0x0,r34; mov.i	ar.pfs,r42; }
	{ nop.m	0x0; mov.spnt	b0,r41,400000000011AA50; nop.i	0x0; }
	{ st8	[r32],r14; nop.i	0x0; br.ret	b0 }

l400000000011AA70:
	{ addl	r15,9252,r1; nop.m	0x0; addl	r34,63,r0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st8	[r0],r15; ld8	r15,[r14]; addl	r14,9268,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st8	[r15],r14; nop.i	0x0; br.cond.sptk.few	400000000011A910 }

l400000000011AAC0:
	{ add	r36,r36,r39,0x1; ld1	r14,[r36]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000011AB60 }

l400000000011AAF0:
	{ adds	r14,0xFFFFFFFFFFFFFFD0,r14; nop.m	0x0; zxt1	r14,r14; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x9,r14; (p06) br.cond.dptk.few	400000000011A740; }

l400000000011AB10:
	{ addl	r15,9252,r1; ld8	r14,[r32]; nop.b	0x0 }
	{ adds	r8,0x0,r34; nop.m	0x0; mov	pr,r44,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; st8	[r14],r37; mov.i	ar.pfs,r42; }
	{ nop.m	0x0; mov.spnt	b0,r41,400000000011AB40; nop.i	0x0; }
	{ st8	[r36],r15; nop.i	0x0; br.ret	b0 }

l400000000011AB60:
	{ ld8	r14,[r32]; nop.m	0x0; adds	r46,0x0,r0; }
	{ cmp.eq	p06,p07,0x0,r14; adds	r14,0x8,r14; (p06) br.cond.dpnt.few	400000000011ABB0; }

l400000000011AB80:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r45,[r14]; nop.i	0x0; br.call.sptk.many	b0,legal_number; }
	{ adds	r1,0x0,r43; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dpnt.few	400000000011AD50; }

l400000000011ABB0:
	{ addl	r45,6349,r1; nop.m	0x0; addl	r34,63,r0; }
	{ st1	[r45],r127,-1; nop.i	0x0; br.call.sptk.many	b0,sh_neednumarg; }
	{ addl	r14,1,r0; nop.m	0x0; adds	r1,0x0,r43; }
	{ st4	[r14],r35; nop.m	0x0; nop.i	0x0 }

l400000000011ABF0:
	{ addl	r14,9252,r1; nop.m	0x0; nop.i	0x0; }
	{ st8	[r0],r14; nop.i	0x0; br.cond.sptk.few	400000000011A760 }

l400000000011AC10:
	{ adds	r16,0x1,r36; ld1	r16,[r16]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r16,r16; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r16; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011AA20; }

l400000000011AC40:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r16; (p06) br.cond.dptk.few	400000000011A600 }

l400000000011AC50:
	{ adds	r16,0x2,r36; ld1	r16,[r16]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r16,r16; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r16; (p06) br.cond.dptk.few	400000000011A600; }

l400000000011AC80:
	{ st8	[r0],r14; addl	r14,9268,r1; nop.b	0x0 }
	{ ld8	r15,[r32]; addl	r34,-1,r0; mov	pr,r44,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; adds	r8,0x0,r34; mov.i	ar.pfs,r42; }
	{ nop.m	0x0; mov.spnt	b0,r41,400000000011ACB0; nop.i	0x0; }
	{ st8	[r15],r14; nop.i	0x0; br.ret	b0 }

l400000000011ACD0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2B,r18; (p06) br.cond.dptk.few	400000000011A980 }

l400000000011ACE0:
	{ adds	r17,0x1,r17; ld1	r17,[r17]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r17,r17; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r17; (p07) br.cond.dptk.few	400000000011A980; }

l400000000011AD10:
	{ cmp4.eq	p07,p06,0x3B,r14; addl	r45,6349,r1; (p07) br.cond.dpnt.few	400000000011ADC0; }

l400000000011AD20:
	{ st1	[r45],r127,-1; addl	r34,63,r0; br.call.sptk.many	b0,sh_needarg; }
	{ addl	r14,1,r0; nop.m	0x0; adds	r1,0x0,r43; }
	{ st4	[r14],r35; nop.i	0x0; br.cond.sptk.few	400000000011ABF0 }

l400000000011AD50:
	{ ld8	r14,[r37]; adds	r8,0x0,r34; mov	pr,r44,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r42; nop.i	0x0; }
	{ ld8	r14,[r14]; mov.spnt	b0,r41,400000000011AD70; adds	r15,0x8,r14; }
	{ ld8	r15,[r15]; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r15,[r15]; st8	[r14],r37; addl	r14,9252,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st8	[r15],r14; nop.i	0x0; br.ret	b0 }

l400000000011ADC0:
	{ addl	r14,9252,r1; st8	[r15],r37; nop.i	0x0; }
	{ nop.m	0x0; st8	[r0],r14; addl	r14,1,r0; }
	{ st4	[r14],r35; nop.i	0x0; br.cond.sptk.few	400000000011A7F0 }

l400000000011ADF0:
	{ addl	r14,9252,r1; addl	r34,-1,r0; mov	pr,r44,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; adds	r8,0x0,r34; mov.i	ar.pfs,r42; }
	{ nop.m	0x0; mov.spnt	b0,r41,400000000011AE10; nop.i	0x0; }
	{ st8	[r0],r14; nop.m	0x0; addl	r14,9268,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st8	[r0],r14; nop.i	0x0; br.ret	b0; }
400000000011AE50 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000011AE60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000011AE70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; reset_internal_getopt: 400000000011AE80
;;   Called from:
;;     40000000000E91DC (in alias_builtin)
;;     40000000000E96DC (in unalias_builtin)
;;     40000000000E99EC (in bind_builtin)
;;     40000000000EA1BC (in bind_builtin)
;;     40000000000EBDE6 (in cd_builtin)
;;     40000000000EC6CC (in pwd_builtin)
;;     40000000000ECC2C (in command_builtin)
;;     40000000000EDADC (in no_options)
;;     40000000000F097C (in fn40000000000F0900)
;;     40000000000F2CFC (in enable_builtin)
;;     40000000000F7C86 (in exec_builtin)
;;     40000000000F941C (in fc_builtin)
;;     40000000000FB6AC (in hash_builtin)
;;     40000000000FC2C6 (in help_builtin)
;;     40000000000FDCFC (in history_builtin)
;;     40000000000FEEEC (in jobs_builtin)
;;     40000000000FF7BC (in disown_builtin)
;;     4000000000100AFC (in mapfile_builtin)
;;     400000000010473C (in read_builtin)
;;     4000000000109DEC (in set_builtin)
;;     400000000010A52C (in unset_builtin)
;;     400000000010BDEC (in set_or_show_attributes)
;;     400000000010D59C (in suspend_builtin)
;;     400000000010DFBC (in trap_builtin)
;;     400000000010F75C (in type_builtin)
;;     40000000001101E6 (in ulimit_builtin)
;;     400000000011057C (in ulimit_builtin)
;;     400000000011192C (in umask_builtin)
;;     40000000001125FC (in getopts_builtin)
;;     40000000001143AC (in shopt_builtin)
;;     4000000000116A2C (in printf_builtin)
;;     400000000011B07C (in fn400000000011B040)
;;     400000000011E2D6 (in compopt_builtin)
reset_internal_getopt proc
	{ addl	r14,9268,r1; nop.m	0x0; addl	r15,1,r0; }
	{ nop.m	0x0; st8	[r0],r14; addl	r14,8692,r1; }
	{ st8	[r0],r14; nop.m	0x0; addl	r14,8700,r1; }
	{ st8	[r0],r14; nop.m	0x0; addl	r14,8708,r1; }
	{ st4	[r15],r14; nop.i	0x0; br.ret	b0; }
400000000011AED0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
400000000011AEE0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
400000000011AEF0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; fn400000000011AF00: 400000000011AF00
;;   Called from:
;;     400000000011E58C (in compopt_builtin)
fn400000000011AF00 proc
	{ alloc	r37,ar.pfs,0x9,0x0,0x7; addl	r40,-3884,r1; mov	r36,b4 }
	{ ld1	r35,[r32]; addl	r14,6356,r1; adds	r38,0x0,r1; }
	{ adds	r34,0x0,r0; ld8	r40,[r40]; sxt1	r35,r35 }
	{ ld8	r33,[r14]; nop.m	0x0; nop.i	0x0; }

l400000000011AF40:
	{ ld1	r14,[r40]; adds	r33,0x10,r33; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,r14,r35; adds	r14,0xFFFFFFFFFFFFFFF0,r33; (p07) br.cond.dpnt.few	400000000011AFB0; }

l400000000011AF60:
	{ ld8	r40,[r14]; nop.m	0x0; adds	r34,0x1,r34; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r40; (p06) br.cond.dptk.few	400000000011AF40 }

l400000000011AF80:
	{ addl	r34,-1,r0; nop.m	0x0; nop.i	0x0; }

l400000000011AF90:
	{ adds	r8,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,400000000011AFA0; br.ret	b0; }

l400000000011AFB0:
	{ adds	r39,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r14,0xFFFFFFFFFFFFFFF0,r33; nop.m	0x0; adds	r1,0x0,r38 }
	{ cmp4.eq	p06,p07,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	400000000011AF90; }

l400000000011AFE0:
	{ ld8	r40,[r14]; nop.m	0x0; adds	r34,0x1,r34; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r40; (p06) br.cond.dptk.few	400000000011AF40 }

l400000000011B000:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011AF80; }
400000000011B010 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000011B020 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000011B030 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn400000000011B040: 400000000011B040
;;   Called from:
;;     400000000011D01C (in complete_builtin)
;;     400000000011D9EC (in compgen_builtin)
fn400000000011B040 proc
	{ alloc	r67,ar.pfs,0x29,0x0,0x26; adds	r68,0x0,r1; mov	r69,pr }
	{ adds	r60,0xC,r33; cmp.eq	p16,p17,0x0,r33; adds	r57,0x8,r33; }
	{ addl	r43,1,r0; addl	r54,131072,r0; mov	r66,b2 }
	{ addl	r52,32768,r0; addl	r50,16384,r0; br.call.sptk.many	b0,reset_internal_getopt; }
	{ adds	r1,0x0,r68; adds	r70,0x0,r32; addl	r48,2048,r0 }
	{ addl	r47,512,r0; movl	r51,0x800000; }
	{ addl	r40,-3388,r1; addl	r41,9252,r1; addl	r65,-3372,r1 }
	{ addl	r53,-3380,r1; addl	r71,-3836,r1; addl	r64,8732,r1; }
	{ addl	r63,8756,r1; addl	r62,8740,r1; addl	r61,8748,r1 }
	{ addl	r59,8764,r1; addl	r58,8724,r1; addl	r56,8716,r1; }
	{ addl	r55,6364,r1; ld8	r40,[r40]; addl	r46,256,r0 }
	{ adds	r45,0x4,r33; movl	r49,0x400000; }
	{ nop.m	0x0; adds	r44,0x0,r0; adds	r38,0x0,r0 }
	{ adds	r36,0x0,r0; ld8	r65,[r65]; nop.i	0x0; }
	{ nop.m	0x0; ld8	r53,[r53]; nop.i	0x0 }
	{ ld8	r71,[r71]; nop.m	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r68; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dpnt.few	400000000011B230; }

l400000000011B150:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; adds	r8,0xFFFFFFFFFFFFFFBF,r8; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x35,r8; (p07) br.cond.dptk.few	400000000011B1C0 }

l400000000011B180:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ nop.m	0x0; adds	r1,0x0,r68; addl	r8,258,r0 }
	{ nop.m	0x0; mov	pr,r69,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r67; }
	{ nop.m	0x0; mov.spnt	b0,r66,400000000011B1B0; br.ret	b0 }

l400000000011B1C0:
	{ addp4	r8,r8,r0; shladd	r8,r8,0x3,r40; nop.i	0x0; }
	{ ld8	r14,[r8]; add	r8,r8,r14; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r8,400000000011B1E0; br.cond	b6; }
400000000011B1F0 09 00 00 00 01 00 60 9A 99 1C 40 80 14 00 00 90 ......`...@.....
400000000011B200 09 38 12 FA E2 27 00 00 00 02 00 C0 08 00 01 84 .8...'..........
400000000011B210 11 38 02 8E 18 10 00 00 00 02 00 00 B8 F2 FF 58 .8.............X
400000000011B220 11 08 00 88 00 21 70 F8 23 0C 77 03 40 FF FF 4A .....!p.#.w.@..J

l400000000011B230:
	{ st8	[r38],r34; xor	r8,0x1,r36; nop.b	0x0 }
	{ st8	[r44],r35; mov	pr,r69,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r67; }
	{ nop.m	0x0; mov.spnt	b0,r66,400000000011B250; br.ret	b0 }
400000000011B260 11 30 C5 4C 0E 20 40 0A 00 00 48 00 A0 FF FF 48 .0.L. @...H....H
400000000011B270 11 30 D9 4C 0E 20 40 0A 00 00 48 00 90 FF FF 48 .0.L. @...H....H
400000000011B280 11 20 05 00 00 24 00 00 00 02 00 08 D0 03 00 43 . ...$.........C
400000000011B290 10 00 AC 5A 90 11 00 00 00 02 00 00 70 FF FF 48 ...Z........p..H
400000000011B2A0 11 20 05 00 00 24 00 00 00 02 00 08 A0 04 00 43 . ...$.........C
400000000011B2B0 10 00 AC 42 90 11 00 00 00 02 00 00 50 FF FF 48 ...B........P..H
400000000011B2C0 09 00 00 00 01 00 40 02 A4 30 20 00 00 00 04 00 ......@..0 .....
400000000011B2D0 11 30 02 48 00 21 00 00 00 02 00 00 38 FC FF 58 .0.H.!......8..X
400000000011B2E0 00 00 00 00 01 00 E0 00 20 2C 00 00 00 00 04 00 ........ ,......
400000000011B2F0 19 08 00 88 00 21 70 40 00 0C E1 03 10 04 00 43 .....!p@.......C
400000000011B300 03 70 38 6A 13 20 40 0A 00 00 48 C0 81 70 00 84 .p8j. @...H..p..
400000000011B310 0B 70 00 1C 10 10 00 00 00 02 00 C0 01 70 58 00 .p...........pX.
400000000011B320 10 00 00 00 01 00 C0 72 B0 1C 40 00 E0 FE FF 48 .......r..@....H
400000000011B330 11 30 D1 4C 0E 20 40 0A 00 00 48 00 D0 FE FF 48 .0.L. @...H....H
400000000011B340 11 30 C9 4C 0E 20 40 0A 00 00 48 00 C0 FE FF 48 .0.L. @...H....H
400000000011B350 11 30 C1 4C 0E 20 40 0A 00 00 48 00 B0 FE FF 48 .0.L. @...H....H
400000000011B360 11 30 BD 4C 0E 20 40 0A 00 00 48 00 A0 FE FF 48 .0.L. @...H....H
400000000011B370 11 30 B9 4C 0E 20 40 0A 00 00 48 00 90 FE FF 48 .0.L. @...H....H
400000000011B380 11 30 81 4C 2E 20 40 0A 00 00 48 00 80 FE FF 48 .0.L. @...H....H
400000000011B390 11 30 41 4C 2E 20 40 0A 00 00 48 00 70 FE FF 48 .0AL. @...H.p..H
400000000011B3A0 11 30 21 4C 2E 20 40 0A 00 00 48 00 60 FE FF 48 .0!L. @...H.`..H
400000000011B3B0 11 30 05 4C 2E 20 40 0A 00 00 48 00 50 FE FF 48 .0.L. @...H.P..H
400000000011B3C0 09 70 00 52 18 10 00 00 00 02 00 80 14 00 00 90 .p.R............
400000000011B3D0 10 00 38 80 98 11 00 00 00 02 00 00 30 FE FF 48 ..8.........0..H
400000000011B3E0 09 70 00 52 18 10 00 00 00 02 00 80 14 00 00 90 .p.R............
400000000011B3F0 10 00 38 7E 98 11 00 00 00 02 00 00 10 FE FF 48 ..8~...........H
400000000011B400 09 70 00 52 18 10 00 00 00 02 00 80 14 00 00 90 .p.R............
400000000011B410 10 00 38 7C 98 11 00 00 00 02 00 00 F0 FD FF 48 ..8|...........H
400000000011B420 09 70 00 52 18 10 00 00 00 02 00 80 14 00 00 90 .p.R............
400000000011B430 10 00 38 7A 98 11 00 00 00 02 00 00 D0 FD FF 48 ..8z...........H
400000000011B440 09 70 00 52 18 10 00 00 00 02 00 80 14 00 00 90 .p.R............
400000000011B450 10 00 38 76 98 11 00 00 00 02 00 00 B0 FD FF 48 ..8v...........H
400000000011B460 09 70 00 52 18 10 00 00 00 02 00 80 14 00 00 90 .p.R............
400000000011B470 10 00 38 74 98 11 00 00 00 02 00 00 90 FD FF 48 ..8t...........H
400000000011B480 11 20 05 00 00 24 00 00 00 02 00 08 50 02 00 43 . ...$......P..C
400000000011B490 10 00 AC 78 90 11 00 00 00 02 00 00 70 FD FF 48 ...x........p..H
400000000011B4A0 11 20 05 00 00 24 00 00 00 02 00 08 00 02 00 43 . ...$.........C
400000000011B4B0 10 00 AC 72 90 11 00 00 00 02 00 00 50 FD FF 48 ...r........P..H
400000000011B4C0 09 70 00 52 18 10 00 00 00 02 00 80 14 00 00 90 .p.R............
400000000011B4D0 10 00 38 70 98 11 00 00 00 02 00 00 30 FD FF 48 ..8p........0..H
400000000011B4E0 08 50 01 52 18 10 70 E4 F6 C3 4F A0 04 00 00 84 .P.R..p...O.....
400000000011B4F0 0B 20 01 6E 18 10 70 04 1C 31 20 00 00 00 04 00 . .n..p..1 .....
400000000011B500 03 38 01 54 00 10 00 00 00 02 00 E0 04 38 51 00 .8.T.........8Q.
400000000011B510 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000011B520 0B 70 00 8E 00 10 00 00 00 02 00 C0 01 70 50 00 .p...........pP.
400000000011B530 10 00 00 00 01 00 70 70 9C 0C F1 03 C0 00 00 43 ......pp.......C
400000000011B540 03 20 41 48 00 21 50 0A 94 00 42 C0 01 27 FD 8C . AH.!P...B..'..
400000000011B550 09 00 00 00 01 00 70 04 38 30 20 00 00 00 04 00 ......p.80 .....
400000000011B560 10 00 00 00 01 00 70 00 1C 0D 72 03 C0 FF FF 4A ......p...r....J
400000000011B570 09 38 32 FA E2 27 80 2C 00 00 48 C0 08 00 00 84 .82..'.,..H.....
400000000011B580 11 38 02 8E 18 10 00 00 00 02 00 00 E8 F5 EF 58 .8.............X
400000000011B590 03 08 00 88 00 21 60 04 20 00 42 C0 41 0A 20 91 .....!`. .B.A. .
400000000011B5A0 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000011B5B0 11 38 02 1C 18 10 00 00 00 02 00 00 D8 1F FD 58 .8.............X
400000000011B5C0 09 40 08 00 02 24 10 00 10 01 42 E0 5F 84 7F 0B .@...$....B._...
400000000011B5D0 01 00 00 00 01 00 00 18 02 55 00 00 00 00 04 00 .........U......
400000000011B5E0 11 00 00 00 01 00 00 10 06 80 03 80 08 00 84 00 ................
400000000011B5F0 11 30 02 54 00 21 00 00 00 02 00 00 58 EF EF 58 .0.T.!......X..X
400000000011B600 10 08 00 88 00 21 60 00 20 0E F3 03 40 FF FF 4A .....!`. ...@..J
400000000011B610 01 00 00 00 01 00 E0 00 94 2C 00 80 14 00 00 90 .........,......
400000000011B620 03 70 38 82 13 20 00 00 00 02 00 C0 81 70 00 84 .p8.. .......p..
400000000011B630 0B 70 00 1C 10 10 00 00 00 02 00 C0 01 70 58 00 .p...........pX.
400000000011B640 10 00 00 00 01 00 60 72 98 1C 40 00 C0 FB FF 48 ......`r..@....H
400000000011B650 02 30 92 FB E1 27 00 00 00 02 00 00 00 00 04 00 .0...'..........
400000000011B660 19 30 02 8C 18 10 00 00 00 02 00 00 A8 26 FD 58 .0...........&.X
400000000011B670 08 08 00 88 00 21 00 00 00 02 00 00 00 00 04 00 .....!..........
400000000011B680 11 00 00 00 01 00 00 00 00 02 00 00 48 21 FD 58 ............H!.X
400000000011B690 11 08 00 88 00 21 80 10 00 04 48 00 10 FB FF 48 .....!....H....H
400000000011B6A0 09 00 00 00 01 00 60 A4 F7 C3 4F 00 00 00 04 00 ......`...O.....
400000000011B6B0 11 30 02 8C 18 10 00 00 00 02 00 00 58 26 FD 58 .0..........X&.X
400000000011B6C0 11 00 00 00 01 00 10 00 10 01 42 00 C0 FF FF 48 ..........B....H
400000000011B6D0 09 00 00 00 01 00 60 E4 F7 C3 4F 00 00 00 04 00 ......`...O.....
400000000011B6E0 11 30 02 8C 18 10 00 00 00 02 00 00 28 26 FD 58 .0..........(&.X
400000000011B6F0 10 00 00 00 01 00 10 00 10 01 42 00 90 FF FF 48 ..........B....H
400000000011B700 11 30 02 48 00 21 00 00 00 02 00 00 88 26 FD 58 .0.H.!.......&.X
400000000011B710 09 40 08 00 02 24 10 00 10 01 42 E0 5F 84 7F 0B .@...$....B._...
400000000011B720 01 00 00 00 01 00 00 18 02 55 00 00 00 00 04 00 .........U......
400000000011B730 10 00 00 00 01 00 00 10 06 80 03 80 08 00 84 00 ................
400000000011B740 09 00 00 00 01 00 60 64 F7 C3 4F 00 00 00 04 00 ......`d..O.....
400000000011B750 11 30 02 8C 18 10 00 00 00 02 00 00 B8 25 FD 58 .0...........%.X
400000000011B760 11 00 00 00 01 00 10 00 10 01 42 00 20 FF FF 48 ..........B. ..H
400000000011B770 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn400000000011B780: 400000000011B780
;;   Called from:
;;     400000000011C99C (in fn400000000011C900)
fn400000000011B780 proc
	{ alloc	r36,ar.pfs,0xA,0x0,0x6; addl	r39,-3820,r1; nop.b	0x0 }
	{ adds	r37,0x0,r1; mov	r35,b3; addl	r38,1,r0 }
	{ ld8	r39,[r39]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r14,0x10,r33; nop.m	0x0; adds	r1,0x0,r37; }
	{ nop.m	0x0; ld8	r34,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x5; (p07) br.cond.dpnt.few	400000000011C750; }

l400000000011B7E0:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x1; (p07) br.cond.dpnt.few	400000000011C700; }

l400000000011B7F0:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x3; (p07) br.cond.dpnt.few	400000000011C6B0; }

l400000000011B800:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x2; (p07) br.cond.dpnt.few	400000000011C660; }

l400000000011B810:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x4; (p07) br.cond.dpnt.few	400000000011C610; }

l400000000011B820:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x6; (p07) br.cond.dpnt.few	400000000011C5A0 }

l400000000011B830:
	{ adds	r14,0x8,r33; ld8	r34,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x0; (p07) br.cond.dpnt.few	400000000011C550; }

l400000000011B850:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x3; (p07) br.cond.dpnt.few	400000000011C500; }

l400000000011B860:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x4; (p07) br.cond.dpnt.few	400000000011C4B0; }

l400000000011B870:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x5; (p07) br.cond.dpnt.few	400000000011C460; }

l400000000011B880:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x8; (p07) br.cond.dpnt.few	400000000011C410; }

l400000000011B890:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x9; (p07) br.cond.dpnt.few	400000000011C3C0; }

l400000000011B8A0:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0xB; (p07) br.cond.dpnt.few	400000000011C370; }

l400000000011B8B0:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0xE; (p07) br.cond.dpnt.few	400000000011C320; }

l400000000011B8C0:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0xF; (p07) br.cond.dpnt.few	400000000011C2D0; }

l400000000011B8D0:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x11; (p07) br.cond.dpnt.few	400000000011C280; }

l400000000011B8E0:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x16; (p07) br.cond.dpnt.few	400000000011C230; }

l400000000011B8F0:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x17; (p07) br.cond.dpnt.few	400000000011C1E0; }

l400000000011B900:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x1; (p07) br.cond.dpnt.few	400000000011C190; }

l400000000011B910:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x2; (p07) br.cond.dpnt.few	400000000011C140; }

l400000000011B920:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x6; (p07) br.cond.dpnt.few	400000000011C0F0; }

l400000000011B930:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x7; (p07) br.cond.dpnt.few	400000000011C0A0; }

l400000000011B940:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0xA; (p07) br.cond.dpnt.few	400000000011C050; }

l400000000011B950:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0xC; (p07) br.cond.dpnt.few	400000000011C000; }

l400000000011B960:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0xD; (p07) br.cond.dpnt.few	400000000011BFB0; }

l400000000011B970:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x10; (p07) br.cond.dpnt.few	400000000011BF60; }

l400000000011B980:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x12; (p07) br.cond.dpnt.few	400000000011BF10; }

l400000000011B990:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x13; (p07) br.cond.dpnt.few	400000000011BEC0; }

l400000000011B9A0:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x14; (p07) br.cond.dpnt.few	400000000011BE70; }

l400000000011B9B0:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x15; (p07) br.cond.dpnt.few	400000000011BE30 }

l400000000011B9C0:
	{ adds	r14,0x18,r33; ld8	r38,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r38; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011BA60; }

l400000000011B9E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_single_quote; }
	{ adds	r1,0x0,r37; adds	r34,0x0,r8; adds	r41,0x0,r8 }
	{ addl	r38,1,r0; addl	r39,-3556,r1; addl	r40,-3548,r1; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ nop.m	0x0; adds	r1,0x0,r37; adds	r38,0x0,r34 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r37; nop.m	0x0; nop.i	0x0 }

l400000000011BA60:
	{ adds	r14,0x20,r33; ld8	r38,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r38; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011BB00; }

l400000000011BA80:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_single_quote; }
	{ adds	r1,0x0,r37; adds	r34,0x0,r8; adds	r41,0x0,r8 }
	{ addl	r38,1,r0; addl	r39,-3556,r1; addl	r40,-3540,r1; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ nop.m	0x0; adds	r1,0x0,r37; adds	r38,0x0,r34 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r37; nop.m	0x0; nop.i	0x0 }

l400000000011BB00:
	{ adds	r14,0x28,r33; ld8	r38,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r38; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011BBA0; }

l400000000011BB20:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_single_quote; }
	{ adds	r1,0x0,r37; adds	r34,0x0,r8; adds	r41,0x0,r8 }
	{ addl	r38,1,r0; addl	r39,-3556,r1; addl	r40,-3532,r1; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ nop.m	0x0; adds	r1,0x0,r37; adds	r38,0x0,r34 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r37; nop.m	0x0; nop.i	0x0 }

l400000000011BBA0:
	{ adds	r14,0x30,r33; ld8	r38,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r38; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011BC40; }

l400000000011BBC0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_single_quote; }
	{ adds	r1,0x0,r37; adds	r34,0x0,r8; adds	r41,0x0,r8 }
	{ addl	r38,1,r0; addl	r39,-3556,r1; addl	r40,-3524,r1; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ nop.m	0x0; adds	r1,0x0,r37; adds	r38,0x0,r34 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r37; nop.m	0x0; nop.i	0x0 }

l400000000011BC40:
	{ adds	r14,0x50,r33; ld8	r38,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r38; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011BCE0; }

l400000000011BC60:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_single_quote; }
	{ adds	r1,0x0,r37; adds	r34,0x0,r8; adds	r41,0x0,r8 }
	{ addl	r38,1,r0; addl	r39,-3556,r1; addl	r40,-3516,r1; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ nop.m	0x0; adds	r1,0x0,r37; adds	r38,0x0,r34 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r37; nop.m	0x0; nop.i	0x0 }

l400000000011BCE0:
	{ adds	r14,0x40,r33; ld8	r38,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r38; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011BD80; }

l400000000011BD00:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_single_quote; }
	{ adds	r1,0x0,r37; adds	r34,0x0,r8; adds	r41,0x0,r8 }
	{ addl	r38,1,r0; addl	r39,-3556,r1; addl	r40,-3508,r1; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ nop.m	0x0; adds	r1,0x0,r37; adds	r38,0x0,r34 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r37; nop.m	0x0; nop.i	0x0; }

l400000000011BD80:
	{ adds	r33,0x38,r33; addl	r39,-3556,r1; addl	r40,-3500,r1 }
	{ addl	r38,1,r0; ld8	r41,[r33]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r41; nop.i	0x0; (p06) br.cond.dpnt.few	400000000011BDE0; }

l400000000011BDB0:
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; nop.m	0x0; nop.i	0x0 }

l400000000011BDE0:
	{ ld1	r14,[r32]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5F,r14; (p07) br.cond.dpnt.few	400000000011C7A0 }

l400000000011BE00:
	{ adds	r38,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B380; }
	{ adds	r8,0x0,r0; adds	r1,0x0,r37; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,400000000011BE20; br.ret	b0 }

l400000000011BE30:
	{ addl	r39,-3660,r1; addl	r40,-3564,r1; addl	r38,1,r0; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ nop.m	0x0; adds	r1,0x0,r37; br.cond.sptk.few	400000000011B9C0; }

l400000000011BE70:
	{ addl	r39,-3660,r1; addl	r40,-3572,r1; addl	r38,1,r0; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; tbit.z	p06,p07,r34,0x15; (p06) br.cond.dptk.few	400000000011B9C0 }

l400000000011BEB0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011BE30; }

l400000000011BEC0:
	{ addl	r39,-3660,r1; addl	r40,-3580,r1; addl	r38,1,r0; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; tbit.z	p06,p07,r34,0x14; (p06) br.cond.dptk.few	400000000011B9B0 }

l400000000011BF00:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011BE70; }

l400000000011BF10:
	{ addl	r39,-3660,r1; addl	r40,-3588,r1; addl	r38,1,r0; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; tbit.z	p06,p07,r34,0x13; (p06) br.cond.dptk.few	400000000011B9A0 }

l400000000011BF50:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011BEC0; }

l400000000011BF60:
	{ addl	r39,-3660,r1; addl	r40,-3596,r1; addl	r38,1,r0; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; tbit.z	p06,p07,r34,0x12; (p06) br.cond.dptk.few	400000000011B990 }

l400000000011BFA0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011BF10; }

l400000000011BFB0:
	{ addl	r39,-3660,r1; addl	r40,-3604,r1; addl	r38,1,r0; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; tbit.z	p06,p07,r34,0x10; (p06) br.cond.dptk.few	400000000011B980 }

l400000000011BFF0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011BF60; }

l400000000011C000:
	{ addl	r39,-3660,r1; addl	r40,-3612,r1; addl	r38,1,r0; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; tbit.z	p06,p07,r34,0xD; (p06) br.cond.dptk.few	400000000011B970 }

l400000000011C040:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011BFB0; }

l400000000011C050:
	{ addl	r39,-3660,r1; addl	r40,-3620,r1; addl	r38,1,r0; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; tbit.z	p06,p07,r34,0xC; (p06) br.cond.dptk.few	400000000011B960 }

l400000000011C090:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011C000; }

l400000000011C0A0:
	{ addl	r39,-3660,r1; addl	r40,-3628,r1; addl	r38,1,r0; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; tbit.z	p06,p07,r34,0xA; (p06) br.cond.dptk.few	400000000011B950 }

l400000000011C0E0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011C050; }

l400000000011C0F0:
	{ addl	r39,-3660,r1; addl	r40,-3636,r1; addl	r38,1,r0; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; tbit.z	p06,p07,r34,0x7; (p06) br.cond.dptk.few	400000000011B940 }

l400000000011C130:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011C0A0; }

l400000000011C140:
	{ addl	r39,-3660,r1; addl	r40,-3644,r1; addl	r38,1,r0; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; tbit.z	p06,p07,r34,0x6; (p06) br.cond.dptk.few	400000000011B930 }

l400000000011C180:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011C0F0; }

l400000000011C190:
	{ addl	r39,-3660,r1; addl	r40,-3652,r1; addl	r38,1,r0; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; tbit.z	p06,p07,r34,0x2; (p06) br.cond.dptk.few	400000000011B920 }

l400000000011C1D0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011C140; }

l400000000011C1E0:
	{ addl	r39,-3764,r1; addl	r40,-3668,r1; addl	r38,1,r0; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; tbit.z	p06,p07,r34,0x1; (p06) br.cond.dptk.few	400000000011B910 }

l400000000011C220:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011C190; }

l400000000011C230:
	{ addl	r39,-3764,r1; addl	r40,-3676,r1; addl	r38,1,r0; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; tbit.z	p06,p07,r34,0x17; (p06) br.cond.dptk.few	400000000011B900 }

l400000000011C270:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011C1E0; }

l400000000011C280:
	{ addl	r39,-3764,r1; addl	r40,-3684,r1; addl	r38,1,r0; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; tbit.z	p06,p07,r34,0x16; (p06) br.cond.dptk.few	400000000011B8F0 }

l400000000011C2C0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011C230; }

l400000000011C2D0:
	{ addl	r39,-3764,r1; addl	r40,-3692,r1; addl	r38,1,r0; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; tbit.z	p06,p07,r34,0x11; (p06) br.cond.dptk.few	400000000011B8E0 }

l400000000011C310:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011C280; }

l400000000011C320:
	{ addl	r39,-3764,r1; addl	r40,-3700,r1; addl	r38,1,r0; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; tbit.z	p06,p07,r34,0xF; (p06) br.cond.dptk.few	400000000011B8D0 }

l400000000011C360:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011C2D0; }

l400000000011C370:
	{ addl	r39,-3764,r1; addl	r40,-3708,r1; addl	r38,1,r0; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; tbit.z	p06,p07,r34,0xE; (p06) br.cond.dptk.few	400000000011B8C0 }

l400000000011C3B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011C320; }

l400000000011C3C0:
	{ addl	r39,-3764,r1; addl	r40,-3716,r1; addl	r38,1,r0; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; tbit.z	p06,p07,r34,0xB; (p06) br.cond.dptk.few	400000000011B8B0 }

l400000000011C400:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011C370; }

l400000000011C410:
	{ addl	r39,-3764,r1; addl	r40,-3724,r1; addl	r38,1,r0; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; tbit.z	p06,p07,r34,0x9; (p06) br.cond.dptk.few	400000000011B8A0 }

l400000000011C450:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000011C3C0; }

l400000000011C460:
	{ addl	r39,-3764,r1; addl	r40,-3732,r1; addl	r38,1,r0; }
	{ nop.m	0x0; ld8	r39,[r39]; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; tbit.z	p06,p07,r34,0x8; (p06) br.cond.dptk.few	400000000011B890 }
