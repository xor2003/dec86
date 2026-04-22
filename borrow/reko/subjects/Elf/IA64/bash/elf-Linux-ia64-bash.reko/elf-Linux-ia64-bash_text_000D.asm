;;; Segment .text (400000000001C480)

l40000000000EC490:
	{ adds	r43,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn40000000000EBA40; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	40000000000EC210 }

l40000000000EC4B0:
	{ adds	r43,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,get_string_value; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r42; adds	r33,0x0,r8 }
	{ adds	r43,0x0,r8; adds	r44,0x0,r34; (p06) br.cond.dpnt.few	40000000000EC260; }

l40000000000EC4E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000EB300; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r8; adds	r1,0x0,r42 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dptk.few	40000000000EC260; }

l40000000000EC510:
	{ (p07) adds	r43,0x0,r33; nop.m	0x0; nop.i	0x0 }

l40000000000EC516:
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; nop; (p48) nop }

l40000000000EC540:
	{ addl	r43,1260,r1; nop.m	0x0; adds	r37,0x0,r0; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,get_string_value; }
	{ adds	r1,0x0,r42; cmp.eq	p07,p06,0x0,r8; adds	r35,0x0,r8; }
	{ (p07) addl	r44,1268,r1; nop.m	0x0; adds	r43,0x0,r35; }

l40000000000EC576:
	{ add	r0,r0,r1; (p21) cmp4.eq.or.andcm	p00,p02,r35,r0; (p01) nop }

l40000000000EC586:
	{ chk.a.nc	f0,3FFFFFFFFF0ECD86; nop; nop }

l40000000000EC590:
	{ adds	r44,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn40000000000EB300; }
	{ adds	r1,0x0,r42; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	40000000000EC250 }

l40000000000EC5B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000EC1D0; }

l40000000000EC5C0:
	{ cmp4.eq	p06,p07,0x0,r39; adds	r43,0x0,r36; (p06) br.cond.dpnt.few	40000000000EC620; }

l40000000000EC5D0:
	{ cmp4.eq	p07,p06,0x0,r34; (p07) addl	r14,8380,r1; nop.i	0x0; }

l40000000000EC5DC:
	{ Invalid; nop; Invalid }

l40000000000EC5EC:
	{ cmp.lt	p00,p17,r1,r0; czx1.r	r96,r65; mov	pr,r32,0x0 }
	{ Invalid; break.i	0x1000; break.b	0x1000 }

l40000000000EC600:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B380; }
	{ adds	r1,0x0,r42; nop.m	0x0; nop.i	0x0 }

l40000000000EC620:
	{ adds	r43,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r42; adds	r43,0x0,r34; br.call.sptk.many	b0,fn40000000000EBA40; }
	{ adds	r1,0x0,r42; mov.i	ar.pfs,r41; mov.spnt	b0,r40,40000000000EC640 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }
40000000000EC660 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000EC670 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; pwd_builtin: 40000000000EC680
pwd_builtin proc
	{ alloc	r38,ar.pfs,0xC,0x0,0x8; addl	r14,7360,r1; nop.b	0x0 }
	{ addl	r33,8376,r1; adds	r39,0x0,r1; mov	r37,b5; }
	{ nop.m	0x0; adds	r34,0x0,r0; addl	r35,1,r0; }
	{ ld4	r14,[r14]; nop.i	0x0; nop.i	0x0 }
	{ st4	[r14],r33; nop.m	0x0; br.call.sptk.many	b0,reset_internal_getopt; }
	{ adds	r1,0x0,r39; nop.m	0x0; nop.i	0x0; }

l40000000000EC6E0:
	{ addl	r41,1252,r1; nop.m	0x0; adds	r40,0x0,r32; }
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r39; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dpnt.few	40000000000EC7B0; }

l40000000000EC710:
	{ cmp4.eq	p06,p07,0x4C,r8; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000EC950; }

l40000000000EC720:
	{ cmp4.eq	p06,p07,0x50,r8; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000EC770; }

l40000000000EC730:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ nop.m	0x0; adds	r1,0x0,r39; addl	r8,1,r0 }

l40000000000EC750:
	{ nop.m	0x0; mov.i	ar.pfs,r38; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000EC760; br.ret	b0 }

l40000000000EC770:
	{ addl	r41,1252,r1; st4	[r35],r33; adds	r40,0x0,r32 }
	{ nop.m	0x0; addl	r34,1,r0; nop.i	0x0; }
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r39; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p06) br.cond.dptk.few	40000000000EC710; }

l40000000000EC7B0:
	{ addl	r36,8380,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld8	r35,[r36]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r35; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000ECA50; }

l40000000000EC7E0:
	{ nop.m	0x0; ld4	r14,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000EC970; }

l40000000000EC800:
	{ (p06) adds	r41,0x0,r35; nop.m	0x0; nop.i	0x0 }

l40000000000EC806:
	{ break.m	0x4000; nop; (p32) nop }

l40000000000EC810:
	{ addl	r14,6456,r1; nop.m	0x0; nop.i	0x0; }

l40000000000EC812:
	{ (p23) break.m	0x48640; break.i	0x20; Invalid }
	{ Invalid; (p32) break.i	0x20203; Invalid }
	{ Invalid; (p32) add	r99,r97,r124,0x1; (p03) nop }

l40000000000EC840:
	{ cmp.eq	p06,p07,0x0,r35; nop.m	0x0; adds	r40,0x0,r35; }
	{ (p06) addl	r8,1,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000EC750; }

l40000000000EC856:
	{ chk.a.nc	r0,3FFFFFFFFF0ED056; nop; break.i	0x80000 }

l40000000000EC860:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B380; }
	{ adds	r1,0x0,r39; addl	r14,6456,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000EC960; }

l40000000000EC8A0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r34; (p06) br.cond.dptk.few	40000000000EC960 }

l40000000000EC8B0:
	{ adds	r40,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn40000000000EB900; }
	{ nop.m	0x0; adds	r1,0x0,r39; adds	r33,0x0,r8; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000EC8E0:
	{ ld8	r14,[r36]; nop.m	0x0; adds	r40,0x0,r35; }
	{ cmp.eq	p06,p07,r14,r35; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000EC920; }

l40000000000EC900:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r39; nop.m	0x0; nop.i	0x0 }

l40000000000EC920:
	{ adds	r40,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,sh_chkwrite; }
	{ adds	r1,0x0,r39; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000EC940; br.ret	b0 }

l40000000000EC950:
	{ st4	[r0],r33; nop.i	0x0; br.cond.sptk.few	40000000000EC6E0 }

l40000000000EC960:
	{ nop.m	0x0; adds	r33,0x0,r0; br.cond.sptk.few	40000000000EC8E0; }

l40000000000EC970:
	{ adds	r40,0x0,r35; adds	r41,0x0,r0; br.call.sptk.many	b0,sh_physpath; }
	{ nop.m	0x0; adds	r1,0x0,r39; adds	r35,0x0,r8 }

l40000000000EC990:
	{ nop.m	0x0; ld8	r41,[r36]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r41; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000EC810; }

l40000000000EC9B0:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	40000000000EC810 }

l40000000000EC9C0:
	{ nop.m	0x0; addl	r40,1300,r1; nop.i	0x0; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,fn40000000000EB240; }
	{ adds	r1,0x0,r39; adds	r35,0x0,r8; br.cond.sptk.few	40000000000EC840; }

l40000000000EC9F0:
	{ addl	r40,1308,r1; adds	r42,0x0,r0; adds	r43,0x0,r0; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,same_file; }
	{ adds	r1,0x0,r39; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	40000000000EC840; }

l40000000000ECA20:
	{ nop.m	0x0; addl	r40,1300,r1; nop.i	0x0; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,fn40000000000EB240; }
	{ adds	r1,0x0,r39; adds	r35,0x0,r8; br.cond.sptk.few	40000000000EC840; }

l40000000000ECA50:
	{ nop.m	0x0; addl	r40,1300,r1; nop.i	0x0; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,get_working_directory; }
	{ adds	r1,0x0,r39; adds	r35,0x0,r8; br.cond.sptk.few	40000000000EC990; }

;; colon_builtin: 40000000000ECA80
colon_builtin proc
	{ nop.m	0x0; adds	r8,0x0,r0; br.ret	b0; }
40000000000ECA90 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000ECAA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000ECAB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; false_builtin: 40000000000ECAC0
false_builtin proc
	{ nop.m	0x0; addl	r8,1,r0; br.ret	b0; }
40000000000ECAD0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000ECAE0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000ECAF0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000ECB00 08 10 1D 08 80 05 60 00 80 0E 72 20 04 00 C4 00 ......`...r ....
40000000000ECB10 09 20 91 FB CF 27 30 02 04 00 42 A0 04 00 01 84 . ...'0...B.....
40000000000ECB20 08 30 01 00 00 21 40 02 90 30 20 00 00 00 04 00 .0...!@..0 .....
40000000000ECB30 17 00 00 00 00 88 01 30 00 80 21 00 98 B8 F7 58 .......0..!....X
40000000000ECB40 11 08 00 46 00 21 40 02 80 00 42 00 A8 DC F2 58 ...F.!@...B....X
40000000000ECB50 0B 08 00 46 00 21 40 22 F7 9F 4F 00 00 00 04 00 ...F.!@"..O.....
40000000000ECB60 11 20 01 48 18 10 00 00 00 02 00 00 68 E3 F7 58 . .H........h..X
40000000000ECB70 09 08 00 46 00 21 00 00 00 02 00 00 20 02 AA 00 ...F.!...... ...
40000000000ECB80 10 00 00 00 01 00 00 08 05 80 03 80 08 00 84 00 ................
40000000000ECB90 09 00 00 00 01 00 40 22 F7 9F 4F 00 00 00 04 00 ......@"..O.....
40000000000ECBA0 11 20 01 48 18 10 00 00 00 02 00 00 A8 F1 F7 58 . .H...........X
40000000000ECBB0 0B 08 00 46 00 21 40 22 F7 9F 4F 00 00 00 04 00 ...F.!@"..O.....
40000000000ECBC0 11 20 01 48 18 10 00 00 00 02 00 00 08 E3 F7 58 . .H...........X
40000000000ECBD0 09 08 00 46 00 21 00 00 00 02 00 00 20 02 AA 00 ...F.!...... ...
40000000000ECBE0 11 00 00 00 01 00 00 08 05 80 03 80 08 00 84 00 ................
40000000000ECBF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; command_builtin: 40000000000ECC00
command_builtin proc
	{ alloc	r39,ar.pfs,0xC,0x0,0x9; adds	r40,0x0,r1; mov	r38,b6; }
	{ nop.m	0x0; adds	r35,0x0,r0; adds	r34,0x0,r0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,reset_internal_getopt; }
	{ adds	r1,0x0,r40; nop.m	0x0; nop.i	0x0; }

l40000000000ECC40:
	{ addl	r42,-6164,r1; nop.m	0x0; adds	r41,0x0,r32; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r40; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dpnt.few	40000000000ECD10; }

l40000000000ECC70:
	{ cmp4.eq	p06,p07,0x70,r8; addl	r33,258,r0; (p06) br.cond.dpnt.few	40000000000ED070; }

l40000000000ECC80:
	{ cmp4.eq	p06,p07,0x76,r8; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000ED080; }

l40000000000ECC90:
	{ cmp4.eq	p06,p07,0x56,r8; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000ECCE0; }

l40000000000ECCA0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ adds	r1,0x0,r40; nop.m	0x0; nop.i	0x0 }

l40000000000ECCC0:
	{ adds	r8,0x0,r33; nop.m	0x0; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000ECCD0; br.ret	b0 }

l40000000000ECCE0:
	{ addl	r42,-6164,r1; adds	r41,0x0,r32; addl	r34,130,r0; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r40; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p06) br.cond.dptk.few	40000000000ECC70; }

l40000000000ECD10:
	{ addl	r14,9268,r1; nop.m	0x0; addl	r41,-6140,r1; }
	{ nop.m	0x0; ld8	r33,[r14]; addl	r14,7352,r1; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r33; nop.i	0x0; }
	{ (p06) adds	r33,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000ECCC0; }

l40000000000ECD46:
	{ chk.a.nc	r0,3FFFFFFFFF0ED546; nop; (p32) nop }

l40000000000ECD50:
	{ cmp4.eq	p06,p07,0x0,r35; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000ED0C0; }

l40000000000ECD60:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000ED200; }

l40000000000ECD80:
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,begin_unwind_frame; }
	{ adds	r1,0x0,r40; addl	r41,-6172,r1; nop.i	0x0; }
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,get_string_value; }
	{ adds	r35,0x0,r8; nop.m	0x0; cmp.eq	p07,p06,0x0,r8 }
	{ adds	r1,0x0,r40; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000ECE20; }

l40000000000ECDD0:
	{ adds	r41,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r40; adds	r41,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r42,0x0,r35 }
	{ adds	r41,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; adds	r1,0x0,r40; adds	r35,0x0,r8; }

l40000000000ECE20:
	{ addl	r41,-6124,r1; nop.m	0x0; adds	r42,0x0,r35; }
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,add_unwind_protect; }
	{ adds	r1,0x0,r40; adds	r41,0x0,r0; nop.i	0x0 }
	{ adds	r42,0x0,r0; adds	r43,0x0,r0; br.call.sptk.many	b0,fn400000000001A8C0; }
	{ nop.m	0x0; adds	r36,0x0,r8; adds	r1,0x0,r40 }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	40000000000ED240 }

l40000000000ECE80:
	{ adds	r41,0x2,r8; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r40; adds	r35,0x0,r8; adds	r41,0x0,r0 }
	{ st1	[r0],r8; adds	r42,0x0,r8; adds	r43,0x0,r36; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A8C0; }
	{ adds	r1,0x0,r40; nop.m	0x0; nop.i	0x0; }

l40000000000ECED0:
	{ addl	r41,-6172,r1; adds	r42,0x0,r35; adds	r43,0x0,r0; }
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r1,0x0,r40; addl	r41,-6172,r1; nop.i	0x0; }
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,stupidly_hack_special_variables; }
	{ nop.m	0x0; adds	r1,0x0,r40; adds	r41,0x0,r35 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r40; nop.m	0x0; nop.i	0x0 }

l40000000000ECF40:
	{ cmp4.eq	p06,p07,0x0,r34; adds	r36,0x0,r0; (p06) br.cond.dpnt.few	40000000000ED0F0; }

l40000000000ECF50:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x4,r34; nop.i	0x0; }
	{ (p06) addl	r37,1,r0; nop.i	0x0; (p07) adds	r37,0x0,r0; }

l40000000000ECF66:
	{ addp4	r0,0xFFFFFFFFFFFFE000,r1; (p18) nop; break.i	0x80000 }

l40000000000ECF70:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000ECF80:
	{ adds	r35,0x8,r33; nop.m	0x0; adds	r42,0x0,r34; }
	{ nop.m	0x0; ld8	r14,[r35]; nop.i	0x0; }
	{ ld8	r41,[r14]; nop.i	0x0; br.call.sptk.many	b0,describe_command; }
	{ cmp4.eq	p06,p07,0x0,r8; adds	r1,0x0,r40; add	r36,r36,r8; }
	{ (p06) addl	r14,1,r0; (p07) adds	r14,0x0,r0; nop.i	0x0; }

l40000000000ECFC6:
	{ Invalid; nop; break.i	0x80000; }

l40000000000ECFCC:
	{ nop; cmp.lt	p00,p00,r32,r0; zxt1	r35,r3 }
	{ invala; cmp.lt	p00,p00,r32,r0; mov	pr,r99,0xE680 }
	{ (p05) nop; nop; (p04) rfi }

l40000000000ECFF0:
	{ nop.m	0x0; ld8	r33,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	40000000000ECF80 }

l40000000000ED010:
	{ nop.m	0x0; addl	r41,-6140,r1; nop.i	0x0; }
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,run_unwind_frame; }
	{ cmp4.eq	p06,p07,0x0,r36; adds	r1,0x0,r40; mov.i	ar.pfs,r39; }
	{ (p06) addl	r36,1,r0; mov.spnt	b0,r38,40000000000ED040; (p07) adds	r36,0x0,r0; }

l40000000000ED046:
	{ chk.a.nc	f38,3FFFFFFFFF1CD056; (p18) nop; break.i	0x80000 }

l40000000000ED050:
	{ nop.m	0x0; adds	r33,0x0,r36; nop.i	0x0; }
	{ nop.m	0x0; adds	r8,0x0,r33; br.ret	b0 }

l40000000000ED070:
	{ nop.m	0x0; addl	r35,1,r0; br.cond.sptk.few	40000000000ECC40 }

l40000000000ED080:
	{ nop.m	0x0; addl	r34,4,r0; br.cond.sptk.few	40000000000ECC40; }

l40000000000ED090:
	{ nop.m	0x0; ld8	r14,[r35]; nop.i	0x0; }
	{ ld8	r41,[r14]; nop.i	0x0; br.call.sptk.many	b0,sh_notfound; }
	{ nop.m	0x0; adds	r1,0x0,r40; br.cond.sptk.few	40000000000ECFF0; }

l40000000000ED0C0:
	{ nop.m	0x0; addl	r41,-6140,r1; nop.i	0x0; }
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,begin_unwind_frame; }
	{ nop.m	0x0; adds	r1,0x0,r40; br.cond.sptk.few	40000000000ECF40 }

l40000000000ED0F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,make_bare_simple_command; }
	{ adds	r35,0x18,r8; nop.m	0x0; adds	r34,0x0,r8 }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r41,0x0,r33; }
	{ ld8	r33,[r35]; nop.i	0x0; br.call.sptk.many	b0,copy_word_list; }
	{ adds	r14,0x8,r33; adds	r16,0x4,r34; nop.i	0x0 }
	{ addl	r15,2096,r0; adds	r1,0x0,r40; adds	r42,0x0,r34; }
	{ st8	[r8],r14; ld4	r17,[r16]; addl	r41,-9796,r1; }
	{ nop.m	0x0; ld8	r14,[r35]; or	r18,r15,r17 }
	{ ld8	r41,[r41]; adds	r19,0x10,r14; nop.i	0x0; }
	{ ld4	r17,[r14]; st8	[r0],r19; nop.i	0x0 }
	{ st4	[r18],r16; or	r15,r15,r17; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,add_unwind_protect; }
	{ adds	r1,0x0,r40; adds	r41,0x0,r34; br.call.sptk.many	b0,execute_command; }
	{ adds	r1,0x0,r40; adds	r33,0x0,r8; addl	r41,-6140,r1; }
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,run_unwind_frame; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r40; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000ED1F0; br.ret	b0 }

l40000000000ED200:
	{ addl	r41,-6156,r1; nop.m	0x0; addl	r33,1,r0; }
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,sh_restricted; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r40; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000ED230; br.ret	b0; }

l40000000000ED240:
	{ addl	r41,30,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r40; adds	r41,0x0,r8; addl	r43,30,r0; }
	{ nop.m	0x0; addl	r42,-6148,r1; nop.i	0x0; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ nop.m	0x0; adds	r1,0x0,r40; adds	r35,0x0,r8 }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000000ECED0; }

l40000000000ED2A0:
	{ addl	r41,-6172,r1; addl	r42,-6132,r1; adds	r43,0x0,r0; }
	{ nop.m	0x0; ld8	r42,[r42]; nop.i	0x0 }
	{ ld8	r41,[r41]; nop.m	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r1,0x0,r40; addl	r41,-6172,r1; nop.i	0x0; }
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,stupidly_hack_special_variables; }
	{ nop.m	0x0; adds	r1,0x0,r40; br.cond.sptk.few	40000000000ECF40; }
40000000000ED300 08 18 1D 0A 80 05 E0 00 80 30 20 40 04 00 C4 00 .........0 @....
40000000000ED310 09 20 01 02 00 21 F0 00 84 30 20 00 00 00 04 00 . ...!...0 .....
40000000000ED320 09 28 01 1C 00 21 00 00 00 02 00 C0 04 78 00 84 .(...!.......x..
40000000000ED330 09 40 00 1C 00 10 E0 00 3C 00 20 00 00 00 04 00 .@......<. .....
40000000000ED340 01 00 00 00 01 00 E0 00 38 28 00 00 01 40 50 00 ........8(...@P.
40000000000ED350 09 00 00 00 01 00 80 40 38 0A 40 00 00 00 04 00 .......@8.@.....
40000000000ED360 11 38 00 10 86 39 00 00 00 02 00 03 30 00 00 43 .8...9......0..C
40000000000ED370 11 00 00 00 01 00 00 00 00 02 00 00 D8 D1 F2 58 ...............X
40000000000ED380 08 08 00 48 00 21 00 00 00 02 00 00 00 00 04 00 ...H.!..........
40000000000ED390 01 00 00 00 01 00 00 18 01 55 00 00 00 00 04 00 .........U......
40000000000ED3A0 11 00 00 00 01 00 00 10 05 80 03 80 08 00 84 00 ................
40000000000ED3B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000ED3C0: 40000000000ED3C0
;;   Called from:
;;     40000000000ED5FC (in builtin_error)
;;     40000000000ED6EC (in builtin_warning)
fn40000000000ED3C0 proc
	{ alloc	r36,ar.pfs,0xA,0x0,0x6; addl	r32,-10652,r1; nop.b	0x0 }
	{ adds	r37,0x0,r1; nop.m	0x0; mov	r35,b3; }
	{ ld8	r32,[r32]; nop.i	0x0; br.call.sptk.many	b0,get_name_for_error; }
	{ adds	r1,0x0,r37; adds	r41,0x0,r8; addl	r39,1,r0; }
	{ addl	r40,-2820,r1; ld8	r38,[r32]; nop.i	0x0; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ adds	r1,0x0,r37; addl	r14,6512,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000ED500 }

l40000000000ED450:
	{ addl	r14,9036,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld8	r41,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r41; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000ED4A0; }

l40000000000ED480:
	{ ld1	r14,[r41]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000ED4C0 }

l40000000000ED4A0:
	{ nop.m	0x0; mov.i	ar.pfs,r36; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000ED4B0; br.ret	b0 }

l40000000000ED4C0:
	{ addl	r40,-2820,r1; ld8	r38,[r32]; addl	r39,1,r0; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ adds	r1,0x0,r37; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000ED4F0; br.ret	b0 }

l40000000000ED500:
	{ addl	r39,-2812,r1; nop.m	0x0; addl	r40,5,r0 }
	{ ld8	r33,[r32]; nop.m	0x0; adds	r38,0x0,r0; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r37; adds	r34,0x0,r8; br.call.sptk.many	b0,executing_line_number; }
	{ adds	r1,0x0,r37; adds	r38,0x0,r33; addl	r39,1,r0 }
	{ adds	r40,0x0,r34; adds	r41,0x0,r8; br.call.sptk.many	b0,fn400000000001C040; }
	{ nop.m	0x0; adds	r1,0x0,r37; br.cond.sptk.few	40000000000ED450; }
40000000000ED570 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; builtin_error: 40000000000ED580
;;   Called from:
;;     40000000000B556C (in fn40000000000B5540)
;;     40000000000C034C (in unbind_array_element)
;;     40000000000C03BC (in unbind_array_element)
;;     40000000000C828C (in maybe_append_history)
;;     40000000000CA89C (in fn40000000000CA6C0)
;;     40000000000CAA2C (in fn40000000000CA6C0)
;;     40000000000CAA2C (in fn40000000000CA6C0)
;;     40000000000D8C0C (in bind_keyseq_to_unix_command)
;;     40000000000E958C (in alias_builtin)
;;     40000000000EA48C (in bind_builtin)
;;     40000000000EA4EC (in bind_builtin)
;;     40000000000EA54C (in bind_builtin)
;;     40000000000EA5BC (in bind_builtin)
;;     40000000000EA68C (in bind_builtin)
;;     40000000000EA7AC (in fn40000000000EA700)
;;     40000000000EC34C (in cd_builtin)
;;     40000000000EC42C (in cd_builtin)
;;     40000000000EDA6C (in no_args)
;;     40000000000EDBEC (in sh_needarg)
;;     40000000000EDC6C (in sh_neednumarg)
;;     40000000000EDCEC (in sh_notfound)
;;     40000000000EDD6C (in sh_invalidopt)
;;     40000000000EDDEC (in sh_invalidoptname)
;;     40000000000EDE6C (in sh_invalidid)
;;     40000000000EDF0C (in sh_invalidnum)
;;     40000000000EDFCC (in sh_invalidnum)
;;     40000000000EE02C (in sh_invalidnum)
;;     40000000000EE0AC (in sh_invalidsig)
;;     40000000000EE12C (in sh_badpid)
;;     40000000000EE1AC (in sh_readonly)
;;     40000000000EE24C (in sh_erange)
;;     40000000000EE29C (in sh_erange)
;;     40000000000EE2FC (in sh_erange)
;;     40000000000EE34C (in sh_erange)
;;     40000000000EE3EC (in sh_badjob)
;;     40000000000EE46C (in sh_nojobs)
;;     40000000000EE4BC (in sh_nojobs)
;;     40000000000EE56C (in sh_restricted)
;;     40000000000EE5BC (in sh_restricted)
;;     40000000000EE66C (in sh_notbuiltin)
;;     40000000000EE70C (in sh_wrerror)
;;     40000000000EE7EC (in sh_ttyerror)
;;     40000000000EF94C (in get_job_by_name)
;;     40000000000F149C (in fn40000000000F0900)
;;     40000000000F1DCC (in fn40000000000F0900)
;;     40000000000F1E2C (in fn40000000000F0900)
;;     40000000000F216C (in fn40000000000F0900)
;;     40000000000F21AC (in fn40000000000F0900)
;;     40000000000F24AC (in local_builtin)
;;     40000000000F3B2C (in enable_builtin)
;;     40000000000F3BDC (in enable_builtin)
;;     40000000000F3C4C (in enable_builtin)
;;     40000000000F3FCC (in enable_builtin)
;;     40000000000F815C (in exec_builtin)
;;     40000000000F85EC (in exec_builtin)
;;     40000000000F8D0C (in logout_builtin)
;;     40000000000FA02C (in fc_builtin)
;;     40000000000FAA9C (in fc_builtin)
;;     40000000000FB00C (in fn40000000000FAD40)
;;     40000000000FB97C (in hash_builtin)
;;     40000000000FBA7C (in hash_builtin)
;;     40000000000FC24C (in fn40000000000FC180)
;;     40000000000FD70C (in help_builtin)
;;     40000000000FDECC (in history_builtin)
;;     40000000000FE7BC (in history_builtin)
;;     40000000000FFD2C (in fn40000000000FFCC0)
;;     40000000000FFD9C (in fn40000000000FFCC0)
;;     400000000010038C (in kill_builtin)
;;     4000000000100A6C (in let_builtin)
;;     400000000010143C (in mapfile_builtin)
;;     40000000001018CC (in mapfile_builtin)
;;     400000000010197C (in mapfile_builtin)
;;     4000000000101CAC (in fn4000000000101C00)
;;     400000000010380C (in pushd_builtin)
;;     4000000000106B9C (in read_builtin)
;;     4000000000107DDC (in read_builtin)
;;     40000000001085BC (in return_builtin)
;;     400000000010A83C (in unset_builtin)
;;     400000000010A93C (in unset_builtin)
;;     400000000010A9DC (in unset_builtin)
;;     400000000010A9DC (in unset_builtin)
;;     400000000010AC5C (in unset_builtin)
;;     400000000010C3BC (in set_or_show_attributes)
;;     400000000010D0FC (in source_builtin)
;;     400000000010D0FC (in source_builtin)
;;     400000000010D42C (in source_builtin)
;;     400000000010D7CC (in suspend_builtin)
;;     400000000010D95C (in test_builtin)
;;     400000000011069C (in ulimit_builtin)
;;     40000000001108BC (in ulimit_builtin)
;;     4000000000110BCC (in ulimit_builtin)
;;     4000000000110FFC (in ulimit_builtin)
;;     4000000000110FFC (in ulimit_builtin)
;;     400000000011114C (in ulimit_builtin)
;;     40000000001115AC (in parse_symbolic_mode)
;;     40000000001118BC (in parse_symbolic_mode)
;;     400000000011340C (in fn40000000001133C0)
;;     4000000000114A8C (in shopt_builtin)
;;     40000000001156EC (in fn4000000000115680)
;;     400000000011719C (in printf_builtin)
;;     40000000001176CC (in printf_builtin)
;;     400000000011CA3C (in fn400000000011C900)
;;     400000000011CB7C (in fn400000000011CA80)
;;     400000000011DACC (in compgen_builtin)
;;     400000000011DB3C (in compgen_builtin)
;;     400000000011E62C (in compopt_builtin)
;;     400000000011E92C (in compopt_builtin)
builtin_error proc
	{ alloc	r42,ar.pfs,0x11,0x0,0xD; adds	r16,0x8,r12; adds	r17,0x0,r12 }
	{ adds	r12,0xFFFFFFFFFFFFFFC0,r12; addl	r40,-10652,r1; adds	r43,0x0,r1; }
	{ mov.m	r44,UNAT; st8.spill	[r16],r112,-16; nop.b	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; mov	r41,b1; }
	{ st8.spill	[r17],r112,-16; st8.spill	[r16],r112,-16; nop.i	0x0; }
	{ st8.spill	[r17],r112,-16; st8.spill	[r16],r112,-16; nop.i	0x0; }
	{ nop.m	0x0; st8.spill	[r34],r17; nop.i	0x0 }
	{ st8.spill	[r33],r16; nop.m	0x0; br.call.sptk.many	b0,fn40000000000ED3C0; }
	{ adds	r1,0x0,r43; ld8	r45,[r40]; adds	r47,0x0,r32 }
	{ adds	r48,0x18,r12; addl	r46,1,r0; br.call.sptk.many	b0,fn400000000001A560; }
	{ adds	r1,0x0,r43; nop.m	0x0; addl	r45,10,r0 }
	{ ld8	r46,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BD80; }
	{ nop.m	0x0; adds	r1,0x0,r43; mov.i	ar.pfs,r42 }
	{ mov.m	UNAT,r44; nop.i	0x0; mov.spnt	b0,r41,40000000000ED650 }
	{ nop.m	0x0; adds	r12,0x40,r12; br.ret	b0; }
40000000000ED670 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; builtin_warning: 40000000000ED680
;;   Called from:
;;     40000000000EA1FC (in bind_builtin)
builtin_warning proc
	{ alloc	r43,ar.pfs,0x12,0x0,0xE; adds	r16,0x8,r12; adds	r17,0x0,r12 }
	{ adds	r12,0xFFFFFFFFFFFFFFC0,r12; addl	r40,-10652,r1; adds	r44,0x0,r1; }
	{ mov.m	r45,UNAT; st8.spill	[r16],r112,-16; mov	r42,b2 }
	{ ld8	r40,[r40]; st8.spill	[r17],r112,-16; nop.i	0x0 }
	{ st8.spill	[r16],r112,-16; st8.spill	[r17],r112,-16; nop.i	0x0 }
	{ st8.spill	[r16],r112,-16; st8.spill	[r34],r17; nop.i	0x0 }
	{ st8.spill	[r33],r16; nop.m	0x0; br.call.sptk.many	b0,fn40000000000ED3C0; }
	{ adds	r1,0x0,r44; ld8	r41,[r40]; addl	r48,5,r0 }
	{ adds	r46,0x0,r0; addl	r47,-2804,r1; nop.i	0x0; }
	{ ld8	r47,[r47]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r44; adds	r46,0x0,r41; nop.i	0x0 }
	{ addl	r47,1,r0; adds	r48,0x0,r8; br.call.sptk.many	b0,fn400000000001C040; }
	{ adds	r1,0x0,r44; ld8	r46,[r40]; adds	r48,0x0,r32 }
	{ adds	r49,0x18,r12; addl	r47,1,r0; br.call.sptk.many	b0,fn400000000001A560; }
	{ adds	r1,0x0,r44; nop.m	0x0; addl	r46,10,r0 }
	{ ld8	r47,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BD80; }
	{ nop.m	0x0; adds	r1,0x0,r44; mov.i	ar.pfs,r43 }
	{ mov.m	UNAT,r45; nop.i	0x0; mov.spnt	b0,r42,40000000000ED790 }
	{ nop.m	0x0; adds	r12,0x40,r12; br.ret	b0; }
40000000000ED7B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; builtin_usage: 40000000000ED7C0
;;   Called from:
;;     40000000000E924C (in alias_builtin)
;;     40000000000E973C (in unalias_builtin)
;;     40000000000E9A5C (in bind_builtin)
;;     40000000000EB12C (in caller_builtin)
;;     40000000000EBE6C (in cd_builtin)
;;     40000000000EC73C (in pwd_builtin)
;;     40000000000ECCAC (in command_builtin)
;;     40000000000EDB2C (in no_options)
;;     40000000000F0A1C (in fn40000000000F0900)
;;     40000000000F2D7C (in enable_builtin)
;;     40000000000F7D0C (in exec_builtin)
;;     40000000000F952C (in fc_builtin)
;;     40000000000FB72C (in hash_builtin)
;;     40000000000FC34C (in help_builtin)
;;     40000000000FDD7C (in history_builtin)
;;     40000000000FEF7C (in jobs_builtin)
;;     40000000000FF83C (in disown_builtin)
;;     40000000001006BC (in kill_builtin)
;;     40000000001007AC (in kill_builtin)
;;     4000000000100B9C (in mapfile_builtin)
;;     400000000010211C (in dirs_builtin)
;;     400000000010220C (in dirs_builtin)
;;     4000000000102C3C (in popd_builtin)
;;     4000000000102C3C (in popd_builtin)
;;     4000000000103AFC (in pushd_builtin)
;;     400000000010481C (in read_builtin)
;;     4000000000109E4C (in set_builtin)
;;     400000000010A17C (in set_builtin)
;;     400000000010A32C (in set_builtin)
;;     400000000010A59C (in unset_builtin)
;;     400000000010BE6C (in set_or_show_attributes)
;;     400000000010D43C (in source_builtin)
;;     400000000010D5FC (in suspend_builtin)
;;     400000000010E02C (in trap_builtin)
;;     400000000010E3FC (in trap_builtin)
;;     400000000010F7CC (in type_builtin)
;;     40000000001104EC (in ulimit_builtin)
;;     400000000011199C (in umask_builtin)
;;     400000000011263C (in getopts_builtin)
;;     400000000011298C (in getopts_builtin)
;;     400000000011441C (in shopt_builtin)
;;     4000000000116A9C (in printf_builtin)
;;     400000000011B18C (in fn400000000011B040)
;;     400000000011D81C (in complete_builtin)
;;     400000000011E38C (in compopt_builtin)
builtin_usage proc
	{ alloc	r36,ar.pfs,0xA,0x0,0x6; addl	r33,9036,r1; nop.b	0x0 }
	{ addl	r32,-10652,r1; mov	r35,b3; adds	r37,0x0,r1; }
	{ nop.m	0x0; ld8	r32,[r32]; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r33]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000ED830; }

l40000000000ED810:
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000ED8E0 }

l40000000000ED830:
	{ addl	r14,9228,r1; ld8	r33,[r32]; addl	r40,5,r0 }
	{ adds	r38,0x0,r0; nop.m	0x0; nop.i	0x0; }
	{ ld8	r14,[r14]; adds	r14,0x20,r14; nop.i	0x0; }
	{ ld8	r39,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r38,0x0,r33 }
	{ addl	r39,1,r0; adds	r41,0x0,r8; addl	r40,-2788,r1; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ nop.m	0x0; adds	r1,0x0,r37; nop.i	0x0 }
	{ ld8	r38,[r32]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ adds	r1,0x0,r37; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000ED8D0; br.ret	b0 }

l40000000000ED8E0:
	{ addl	r32,-10652,r1; nop.m	0x0; addl	r39,-2796,r1 }
	{ addl	r40,5,r0; nop.m	0x0; adds	r38,0x0,r0; }
	{ ld8	r32,[r32]; ld8	r39,[r39]; nop.i	0x0; }
	{ ld8	r34,[r32]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ ld8	r41,[r33]; adds	r1,0x0,r37; adds	r38,0x0,r34 }
	{ addl	r39,1,r0; adds	r40,0x0,r8; br.call.sptk.many	b0,fn400000000001C040; }
	{ adds	r1,0x0,r37; ld8	r33,[r32]; addl	r40,5,r0 }
	{ adds	r38,0x0,r0; addl	r14,9228,r1; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; adds	r14,0x20,r14; nop.i	0x0; }
	{ ld8	r39,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r38,0x0,r33 }
	{ addl	r39,1,r0; adds	r41,0x0,r8; addl	r40,-2788,r1; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ nop.m	0x0; adds	r1,0x0,r37; nop.i	0x0 }
	{ ld8	r38,[r32]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ adds	r1,0x0,r37; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000ED9F0; br.ret	b0; }

;; no_args: 40000000000EDA00
;;   Called from:
;;     40000000000EEE1C (in get_numeric_arg)
;;     40000000000EF1BC (in get_exitstat)
;;     400000000010D69C (in suspend_builtin)
;;     400000000010D69C (in suspend_builtin)
no_args proc
	{ alloc	r34,ar.pfs,0x7,0x0,0x4; mov	r33,b1; nop.i	0x0 }
	{ adds	r35,0x0,r1; cmp.eq	p06,p07,0x0,r32; (p07) br.cond.spnt.few	40000000000EDA40; }

l40000000000EDA20:
	{ nop.m	0x0; mov.i	ar.pfs,r34; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000EDA30; br.ret	b0 }

l40000000000EDA40:
	{ addl	r37,-2780,r1; addl	r38,5,r0; adds	r36,0x0,r0; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r35; adds	r36,0x0,r8; br.call.sptk.many	b0,builtin_error; }
	{ adds	r1,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,top_level_cleanup; }
	{ adds	r1,0x0,r35; addl	r36,2,r0; br.call.sptk.many	b0,jump_to_top_level; }
	{ nop.m	0x0; break.f	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

;; no_options: 40000000000EDAC0
;;   Called from:
;;     40000000000EABAC (in builtin_builtin)
;;     40000000000EAF3C (in caller_builtin)
;;     40000000000EDABC (in no_args)
;;     40000000000F406C (in eval_builtin)
;;     40000000000FB18C (in fg_builtin)
;;     40000000000FB41C (in bg_builtin)
;;     40000000001084EC (in return_builtin)
;;     400000000010CCEC (in source_builtin)
;;     400000000010D9EC (in times_builtin)
;;     4000000000111DAC (in wait_builtin)
no_options proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x4; mov	r33,b1; adds	r35,0x0,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,reset_internal_getopt; }
	{ adds	r1,0x0,r35; adds	r36,0x0,r32; addl	r37,-2772,r1; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r8; nop.m	0x0; adds	r1,0x0,r35; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000EDB40; }

l40000000000EDB16:
	{ chk.a.nc	r0,3FFFFFFFFF0EE316; nop; break.i	0x80000 }

l40000000000EDB20:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ nop.m	0x0; adds	r1,0x0,r35; addl	r8,1,r0 }

l40000000000EDB40:
	{ nop.m	0x0; mov.i	ar.pfs,r34; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000EDB50; br.ret	b0; }
40000000000EDB60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000EDB70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; sh_needarg: 40000000000EDB80
;;   Called from:
;;     40000000000FBE4C (in hash_builtin)
;;     40000000001007FC (in kill_builtin)
;;     400000000011AD2C (in internal_getopt)
sh_needarg proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; mov	r34,b2; nop.b	0x0 }
	{ addl	r38,-2764,r1; adds	r36,0x0,r1; adds	r33,0x0,r32; }
	{ adds	r37,0x0,r0; nop.m	0x0; addl	r39,5,r0 }
	{ ld8	r38,[r38]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; adds	r32,0x0,r8; mov.spnt	b0,r34,40000000000EDBC0; }
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	builtin_error; }
40000000000EDBF0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; sh_neednumarg: 40000000000EDC00
;;   Called from:
;;     40000000000EEDCC (in get_numeric_arg)
;;     40000000000EEF0C (in get_numeric_arg)
;;     40000000000EEF0C (in get_numeric_arg)
;;     40000000000EF06C (in get_exitstat)
;;     40000000000EF16C (in get_exitstat)
;;     400000000011ABCC (in internal_getopt)
sh_neednumarg proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; mov	r34,b2; nop.b	0x0 }
	{ addl	r38,-2756,r1; adds	r36,0x0,r1; adds	r33,0x0,r32; }
	{ adds	r37,0x0,r0; nop.m	0x0; addl	r39,5,r0 }
	{ ld8	r38,[r38]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; adds	r32,0x0,r8; mov.spnt	b0,r34,40000000000EDC40; }
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	builtin_error; }
40000000000EDC70 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; sh_notfound: 40000000000EDC80
;;   Called from:
;;     40000000000E95CC (in alias_builtin)
;;     40000000000E984C (in unalias_builtin)
;;     40000000000ED0AC (in command_builtin)
;;     40000000000F114C (in fn40000000000F0900)
;;     40000000000F861C (in exec_builtin)
;;     40000000000FBBAC (in hash_builtin)
;;     40000000000FBC9C (in hash_builtin)
;;     40000000000FC0BC (in hash_builtin)
;;     40000000000FC13C (in hash_builtin)
;;     400000000010F91C (in type_builtin)
sh_notfound proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; mov	r34,b2; nop.b	0x0 }
	{ addl	r38,-2748,r1; adds	r36,0x0,r1; adds	r33,0x0,r32; }
	{ adds	r37,0x0,r0; nop.m	0x0; addl	r39,5,r0 }
	{ ld8	r38,[r38]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; adds	r32,0x0,r8; mov.spnt	b0,r34,40000000000EDCC0; }
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	builtin_error; }
40000000000EDCF0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; sh_invalidopt: 40000000000EDD00
;;   Called from:
;;     40000000001021FC (in dirs_builtin)
;;     400000000010A31C (in set_builtin)
;;     400000000011A82C (in internal_getopt)
sh_invalidopt proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; mov	r34,b2; nop.b	0x0 }
	{ addl	r38,-2740,r1; adds	r36,0x0,r1; adds	r33,0x0,r32; }
	{ adds	r37,0x0,r0; nop.m	0x0; addl	r39,5,r0 }
	{ ld8	r38,[r38]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; adds	r32,0x0,r8; mov.spnt	b0,r34,40000000000EDD40; }
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	builtin_error; }
40000000000EDD70 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; sh_invalidoptname: 40000000000EDD80
;;   Called from:
;;     400000000010939C (in set_minus_o_option)
;;     40000000001094FC (in set_minus_o_option)
;;     40000000001149DC (in shopt_builtin)
;;     400000000011E96C (in compopt_builtin)
sh_invalidoptname proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; mov	r34,b2; nop.b	0x0 }
	{ addl	r38,-2732,r1; adds	r36,0x0,r1; adds	r33,0x0,r32; }
	{ adds	r37,0x0,r0; nop.m	0x0; addl	r39,5,r0 }
	{ ld8	r38,[r38]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; adds	r32,0x0,r8; mov.spnt	b0,r34,40000000000EDDC0; }
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	builtin_error; }
40000000000EDDF0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; sh_invalidid: 40000000000EDE00
;;   Called from:
;;     40000000000F14EC (in fn40000000000F0900)
;;     4000000000100E3C (in mapfile_builtin)
;;     40000000001079AC (in read_builtin)
;;     4000000000107A2C (in read_builtin)
;;     4000000000107B3C (in read_builtin)
;;     400000000010A8BC (in unset_builtin)
;;     400000000010C6AC (in set_or_show_attributes)
;;     400000000010C6EC (in set_or_show_attributes)
;;     400000000011253C (in fn4000000000112480)
;;     4000000000116FFC (in printf_builtin)
sh_invalidid proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; mov	r34,b2; nop.b	0x0 }
	{ addl	r38,-2724,r1; adds	r36,0x0,r1; adds	r33,0x0,r32; }
	{ adds	r37,0x0,r0; nop.m	0x0; addl	r39,5,r0 }
	{ ld8	r38,[r38]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; adds	r32,0x0,r8; mov.spnt	b0,r34,40000000000EDE40; }
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	builtin_error; }
40000000000EDE70 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; sh_invalidnum: 40000000000EDE80
;;   Called from:
;;     40000000000EB11C (in caller_builtin)
;;     400000000010210C (in dirs_builtin)
;;     4000000000102C2C (in popd_builtin)
;;     4000000000102C2C (in popd_builtin)
;;     4000000000103AEC (in pushd_builtin)
;;     4000000000110F0C (in ulimit_builtin)
;;     4000000000115CEC (in fn4000000000115B40)
sh_invalidnum proc
	{ alloc	r36,ar.pfs,0x9,0x0,0x6; ld1	r14,[r32]; mov	r35,b3 }
	{ adds	r37,0x0,r1; adds	r33,0x0,r32; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x30,r14; (p07) br.cond.dpnt.few	40000000000EDF10 }

l40000000000EDEB0:
	{ addl	r39,-2700,r1; adds	r38,0x0,r0; addl	r40,5,r0; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r37; adds	r34,0x0,r8; mov.spnt	b0,r35,40000000000EDED0; }
	{ addl	r32,-2692,r1; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; ld8	r32,[r32]; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x3,0x0,0x0; nop.i	0x0; br.cond.sptk.many	builtin_error; }

l40000000000EDF10:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C3C0; }
	{ adds	r14,0x1,r32; ld8	r15,[r8]; adds	r1,0x0,r37; }
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ shladd	r15,r14,0x1,r15; nop.m	0x0; cmp4.eq	p09,p08,0x78,r14; }
	{ ld2	r15,[r15]; nop.i	0x0; tbit.z	p06,p07,r15,0xB }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	40000000000EDFD0; (p08) br.cond.dptk.few	40000000000EDEB0 }

l40000000000EDF6C:
	{ (p58) cmp.eq.unc	p63,p09,r63,r37; (p04) cmp.lt	p59,p19,r95,r122; (p04) epc }

l40000000000EDF70:
	{ addl	r39,-2708,r1; adds	r38,0x0,r0; addl	r40,5,r0; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r37; adds	r34,0x0,r8; mov.spnt	b0,r35,40000000000EDF90; }
	{ addl	r32,-2692,r1; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; ld8	r32,[r32]; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x3,0x0,0x0; nop.i	0x0; br.cond.sptk.many	builtin_error }

l40000000000EDFD0:
	{ addl	r39,-2716,r1; adds	r38,0x0,r0; addl	r40,5,r0; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r37; adds	r34,0x0,r8; mov.spnt	b0,r35,40000000000EDFF0; }
	{ addl	r32,-2692,r1; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; ld8	r32,[r32]; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x3,0x0,0x0; nop.i	0x0; br.cond.sptk.many	builtin_error; }
40000000000EE030 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; sh_invalidsig: 40000000000EE040
;;   Called from:
;;     40000000000F007C (in display_signal_list)
;;     400000000010072C (in kill_builtin)
;;     400000000010076C (in kill_builtin)
;;     400000000010E3AC (in trap_builtin)
;;     400000000010E84C (in trap_builtin)
sh_invalidsig proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; mov	r34,b2; nop.b	0x0 }
	{ addl	r38,-2684,r1; adds	r36,0x0,r1; adds	r33,0x0,r32; }
	{ adds	r37,0x0,r0; nop.m	0x0; addl	r39,5,r0 }
	{ ld8	r38,[r38]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; adds	r32,0x0,r8; mov.spnt	b0,r34,40000000000EE080; }
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	builtin_error; }
40000000000EE0B0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; sh_badpid: 40000000000EE0C0
;;   Called from:
;;     40000000001003CC (in kill_builtin)
;;     4000000000111F5C (in wait_builtin)
;;     400000000011241C (in wait_builtin)
sh_badpid proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; mov	r34,b2; nop.b	0x0 }
	{ addl	r38,-2676,r1; adds	r36,0x0,r1; adds	r33,0x0,r32; }
	{ adds	r37,0x0,r0; nop.m	0x0; addl	r39,5,r0 }
	{ ld8	r38,[r38]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; adds	r32,0x0,r8; mov.spnt	b0,r34,40000000000EE100; }
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	builtin_error; }
40000000000EE130 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; sh_readonly: 40000000000EE140
;;   Called from:
;;     4000000000067FEC (in make_local_variable)
;;     40000000000F174C (in fn40000000000F0900)
;;     40000000000F176C (in fn40000000000F0900)
sh_readonly proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; mov	r34,b2; nop.b	0x0 }
	{ addl	r38,-2668,r1; adds	r36,0x0,r1; adds	r33,0x0,r32; }
	{ adds	r37,0x0,r0; nop.m	0x0; addl	r39,5,r0 }
	{ ld8	r38,[r38]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; adds	r32,0x0,r8; mov.spnt	b0,r34,40000000000EE180; }
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	builtin_error; }
40000000000EE1B0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; sh_erange: 40000000000EE1C0
;;   Called from:
;;     40000000000EA96C (in break_builtin)
;;     40000000000EAB2C (in continue_builtin)
;;     40000000000FA67C (in fc_builtin)
;;     40000000000FE5DC (in history_builtin)
;;     4000000000101C5C (in fn4000000000101C00)
;;     400000000010C91C (in shift_builtin)
;;     4000000000110E1C (in ulimit_builtin)
;;     4000000000111C3C (in umask_builtin)
sh_erange proc
	{ alloc	r36,ar.pfs,0x9,0x0,0x6; cmp.eq	p06,p07,0x0,r32; mov	r35,b3 }
	{ addl	r39,-2660,r1; adds	r37,0x0,r1; adds	r34,0x0,r33; }
	{ adds	r38,0x0,r0; nop.m	0x0; addl	r40,5,r0 }
	{ ld8	r39,[r39]; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000EE2A0; }

l40000000000EE200:
	{ adds	r33,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r37; adds	r32,0x0,r8; nop.b	0x0 }
	{ cmp.eq	p07,p06,0x0,r34; mov.spnt	b0,r35,40000000000EE220; (p07) br.cond.dpnt.few	40000000000EE250; }

l40000000000EE230:
	{ nop.m	0x0; mov.i	ar.pfs,r36; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x3,0x0,0x0; nop.i	0x0; br.cond.sptk.many	builtin_error }

l40000000000EE250:
	{ addl	r39,-2652,r1; adds	r38,0x0,r0; addl	r40,5,r0; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r37; adds	r34,0x0,r8; mov.spnt	b0,r35,40000000000EE270; }
	{ nop.m	0x0; mov.i	ar.pfs,r36; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x3,0x0,0x0; nop.i	0x0; br.cond.sptk.many	builtin_error }

l40000000000EE2A0:
	{ addl	r39,-2644,r1; adds	r38,0x0,r0; addl	r40,5,r0; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ cmp.eq	p07,p06,0x0,r33; adds	r1,0x0,r37; nop.b	0x0 }
	{ adds	r32,0x0,r8; adds	r33,0x0,r34; mov.spnt	b0,r35,40000000000EE2D0; }
	{ nop.m	0x0; mov.i	ar.pfs,r36; (p07) br.cond.dpnt.few	40000000000EE300; }

l40000000000EE2F0:
	{ alloc	r2,ar.pfs,0x3,0x0,0x0; nop.i	0x0; br.cond.sptk.many	builtin_error }

l40000000000EE300:
	{ addl	r39,-2652,r1; adds	r38,0x0,r0; addl	r40,5,r0; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r34,0x0,r8; adds	r1,0x0,r37; mov.spnt	b0,r35,40000000000EE320; }
	{ adds	r33,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ alloc	r2,ar.pfs,0x3,0x0,0x0; nop.i	0x0; br.cond.sptk.many	builtin_error; }
40000000000EE350 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000EE360 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000EE370 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; sh_badjob: 40000000000EE380
;;   Called from:
;;     40000000000FAF8C (in fn40000000000FAD40)
;;     40000000000FB12C (in fn40000000000FAD40)
;;     40000000000FF27C (in jobs_builtin)
;;     40000000000FFBCC (in disown_builtin)
;;     40000000000FFBCC (in disown_builtin)
;;     40000000001004DC (in kill_builtin)
;;     40000000001004DC (in kill_builtin)
;;     40000000001122AC (in wait_builtin)
sh_badjob proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; mov	r34,b2; nop.b	0x0 }
	{ addl	r38,-2636,r1; adds	r36,0x0,r1; adds	r33,0x0,r32; }
	{ adds	r37,0x0,r0; nop.m	0x0; addl	r39,5,r0 }
	{ ld8	r38,[r38]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; adds	r32,0x0,r8; mov.spnt	b0,r34,40000000000EE3C0; }
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	builtin_error; }
40000000000EE3F0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; sh_nojobs: 40000000000EE400
;;   Called from:
;;     40000000000FB2CC (in fg_builtin)
;;     40000000000FB50C (in bg_builtin)
;;     400000000010D77C (in suspend_builtin)
sh_nojobs proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; cmp.eq	p06,p07,0x0,r32; mov	r34,b2 }
	{ addl	r38,-2628,r1; adds	r36,0x0,r1; (p06) br.cond.dpnt.few	40000000000EE470; }

l40000000000EE420:
	{ nop.m	0x0; adds	r37,0x0,r0; addl	r39,5,r0 }
	{ ld8	r38,[r38]; adds	r33,0x0,r32; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; adds	r32,0x0,r8; mov.spnt	b0,r34,40000000000EE440; }
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	builtin_error }

l40000000000EE470:
	{ addl	r38,-2620,r1; adds	r37,0x0,r0; addl	r39,5,r0; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; adds	r32,0x0,r8; mov.spnt	b0,r34,40000000000EE490; }
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	builtin_error; }
40000000000EE4C0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000EE4D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000EE4E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000EE4F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; sh_restricted: 40000000000EE500
;;   Called from:
;;     40000000000EBEDC (in cd_builtin)
;;     40000000000ED21C (in command_builtin)
;;     40000000000F38AC (in enable_builtin)
;;     40000000000F3E3C (in enable_builtin)
;;     40000000000F831C (in exec_builtin)
;;     40000000000FB8CC (in hash_builtin)
;;     400000000010CDDC (in source_builtin)
sh_restricted proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; cmp.eq	p06,p07,0x0,r32; mov	r34,b2 }
	{ addl	r38,-2612,r1; adds	r36,0x0,r1; (p06) br.cond.dpnt.few	40000000000EE570; }

l40000000000EE520:
	{ nop.m	0x0; adds	r37,0x0,r0; addl	r39,5,r0 }
	{ ld8	r38,[r38]; adds	r33,0x0,r32; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; adds	r32,0x0,r8; mov.spnt	b0,r34,40000000000EE540; }
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	builtin_error }

l40000000000EE570:
	{ addl	r38,-2604,r1; adds	r37,0x0,r0; addl	r39,5,r0; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; adds	r32,0x0,r8; mov.spnt	b0,r34,40000000000EE590; }
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	builtin_error; }
40000000000EE5C0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000EE5D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000EE5E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000EE5F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; sh_notbuiltin: 40000000000EE600
;;   Called from:
;;     40000000000EACCC (in builtin_builtin)
;;     40000000000F3E6C (in enable_builtin)
;;     40000000000F3F5C (in enable_builtin)
sh_notbuiltin proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; mov	r34,b2; nop.b	0x0 }
	{ addl	r38,-2596,r1; adds	r36,0x0,r1; adds	r33,0x0,r32; }
	{ adds	r37,0x0,r0; nop.m	0x0; addl	r39,5,r0 }
	{ ld8	r38,[r38]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; adds	r32,0x0,r8; mov.spnt	b0,r34,40000000000EE640; }
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	builtin_error; }
40000000000EE670 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; sh_wrerror: 40000000000EE680
;;   Called from:
;;     40000000000EE88C (in sh_chkwrite)
;;     40000000000FABAC (in fc_builtin)
;;     4000000000116F5C (in printf_builtin)
;;     4000000000119CAC (in printf_builtin)
sh_wrerror proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; addl	r38,-2588,r1; mov	r34,b2 }
	{ adds	r36,0x0,r1; ld8	r38,[r38]; addl	r39,5,r0 }
	{ adds	r37,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; adds	r32,0x0,r8; br.call.sptk.many	b0,fn400000000001B840; }
	{ nop.m	0x0; adds	r1,0x0,r36; nop.i	0x0 }
	{ ld4	r37,[r8]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B4A0; }
	{ adds	r1,0x0,r36; adds	r33,0x0,r8; mov.spnt	b0,r34,40000000000EE6E0; }
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	builtin_error; }
40000000000EE710 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000EE720 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000EE730 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; sh_ttyerror: 40000000000EE740
;;   Called from:
;;     400000000010677C (in read_builtin)
;;     40000000001071AC (in read_builtin)
sh_ttyerror proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; addl	r38,-2572,r1; nop.b	0x0 }
	{ cmp4.eq	p06,p07,0x0,r32; mov	r34,b2; adds	r36,0x0,r1; }
	{ ld8	r38,[r38]; addl	r39,5,r0; adds	r37,0x0,r0; }
	{ nop.m	0x0; (p07) addl	r38,-2580,r1; nop.i	0x0; }

l40000000000EE77C:
	{ cmp4.eq.and	p00,p49,r1,r0; Invalid; break.i	0x1000 }

l40000000000EE786:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; (p32) nop; break.i	0x80000 }
	{ Invalid; nop; (p16) br.call.sptk.few	b1,b0 }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; mov	pr,0x7000A2; break.b	0x80000 }
	{ break.m	0xAA023; nop; Invalid }
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
40000000000EE7F0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; sh_chkwrite: 40000000000EE800
;;   Called from:
;;     40000000000E964C (in alias_builtin)
;;     40000000000E9A9C (in bind_builtin)
;;     40000000000E9FAC (in bind_builtin)
;;     40000000000EA6BC (in bind_builtin)
;;     40000000000EBA6C (in fn40000000000EBA40)
;;     40000000000EC92C (in pwd_builtin)
;;     40000000000F0BBC (in fn40000000000F0900)
;;     40000000000F140C (in fn40000000000F0900)
;;     40000000000F16AC (in fn40000000000F0900)
;;     40000000000F172C (in fn40000000000F0900)
;;     40000000000F18AC (in fn40000000000F0900)
;;     40000000000F19BC (in fn40000000000F0900)
;;     40000000000F2A4C (in echo_builtin)
;;     40000000000F2B4C (in echo_builtin)
;;     40000000000FAA0C (in fc_builtin)
;;     40000000000FE61C (in history_builtin)
;;     40000000000FEB7C (in history_builtin)
;;     4000000000101FDC (in dirs_builtin)
;;     400000000010272C (in dirs_builtin)
;;     400000000010A14C (in set_builtin)
;;     400000000010A25C (in set_builtin)
;;     400000000010A3CC (in set_builtin)
;;     400000000010B6AC (in show_all_var_attributes)
;;     400000000010C5AC (in set_or_show_attributes)
;;     400000000010DB7C (in times_builtin)
;;     400000000010E67C (in trap_builtin)
;;     400000000010E78C (in trap_builtin)
;;     400000000010E81C (in trap_builtin)
;;     400000000010F99C (in type_builtin)
;;     400000000011043C (in ulimit_builtin)
;;     4000000000111ACC (in umask_builtin)
;;     4000000000111ACC (in umask_builtin)
;;     4000000000111BDC (in umask_builtin)
;;     4000000000111D3C (in umask_builtin)
;;     400000000011387C (in fn40000000001137C0)
;;     4000000000113C6C (in shopt_listopt)
;;     400000000011461C (in shopt_builtin)
;;     400000000011486C (in shopt_builtin)
;;     400000000011486C (in shopt_builtin)
;;     40000000001148CC (in shopt_builtin)
;;     40000000001148CC (in shopt_builtin)
;;     400000000011491C (in shopt_builtin)
;;     4000000000114B8C (in shopt_builtin)
;;     4000000000114C0C (in shopt_builtin)
;;     400000000011C9CC (in fn400000000011C900)
;;     400000000011E69C (in compopt_builtin)
sh_chkwrite proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; addl	r33,-10260,r1; mov	r34,b2 }
	{ adds	r36,0x0,r1; ld8	r33,[r33]; nop.i	0x0; }
	{ ld8	r37,[r33]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ nop.m	0x0; adds	r1,0x0,r36; nop.i	0x0 }
	{ ld8	r37,[r33]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A960; }
	{ adds	r1,0x0,r36; cmp4.eq	p06,p07,0x0,r8; mov.i	ar.pfs,r35 }
	{ adds	r8,0x0,r32; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000EE880; }

l40000000000EE870:
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000EE870; br.ret	b0; }

l40000000000EE880:
	{ addl	r32,1,r0; nop.i	0x0; br.call.sptk.many	b0,sh_wrerror; }
	{ nop.m	0x0; adds	r1,0x0,r36; nop.i	0x0 }
	{ ld8	r37,[r33]; nop.m	0x0; br.call.sptk.many	b0,fpurge; }
	{ nop.m	0x0; adds	r1,0x0,r36; nop.i	0x0 }
	{ ld8	r37,[r33]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BE00; }
	{ adds	r8,0x0,r32; adds	r1,0x0,r36; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000EE8E0; br.ret	b0; }
40000000000EE8F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; make_builtin_argv: 40000000000EE900
;;   Called from:
;;     400000000010D83C (in test_builtin)
;;     40000000001126AC (in getopts_builtin)
make_builtin_argv proc
	{ alloc	r35,ar.pfs,0x9,0x0,0x5; mov	r34,b2; nop.b	0x0 }
	{ adds	r36,0x0,r1; adds	r37,0x0,r32; adds	r40,0x0,r33; }
	{ adds	r38,0x0,r0; addl	r39,1,r0; br.call.sptk.many	b0,strvec_from_word_list; }
	{ adds	r1,0x0,r36; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ addl	r14,9036,r1; nop.m	0x0; mov.spnt	b0,r34,40000000000EE940; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ st8	[r14],r8; nop.i	0x0; br.ret	b0; }
40000000000EE970 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; dollar_vars_changed: 40000000000EE980
dollar_vars_changed proc
	{ nop.m	0x0; addl	r14,8404,r1; nop.i	0x0; }
	{ ld4	r8,[r14]; nop.i	0x0; br.ret	b0; }
40000000000EE9A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000EE9B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; set_dollar_vars_unchanged: 40000000000EE9C0
;;   Called from:
;;     400000000006A7AC (in pop_dollar_vars)
;;     400000000010CFBC (in source_builtin)
;;     400000000010D30C (in source_builtin)
set_dollar_vars_unchanged proc
	{ nop.m	0x0; addl	r14,8404,r1; nop.i	0x0; }
	{ st4	[r0],r14; nop.i	0x0; br.ret	b0; }
40000000000EE9E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000EE9F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; set_dollar_vars_changed: 40000000000EEA00
;;   Called from:
;;     40000000000EECE6 (in remember_args)
set_dollar_vars_changed proc
	{ addl	r15,7148,r1; nop.m	0x0; addl	r14,8404,r1; }
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r15; (p07) ld4	r15,[r14]; nop.i	0x0; }

l40000000000EEA2C:
	{ nop; cmp4.eq.or.andcm	p00,p32,r32,r0; zxt1	r96,r11 }

l40000000000EEA3C:
	{ Invalid; (p48) cmp.eq.unc	p03,p08,r3,r100; (p01) nop }

l40000000000EEA46:
	{ (p07) chk.a.clr	f68,3FFFFFFFFF30F256; (p34) nop; br.call.sptk.few	b4,b0 }

l40000000000EEA50:
	{ ld8	r16,[r15]; nop.m	0x0; addl	r15,-9844,r1; }
	{ ld8	r15,[r15]; cmp.eq	p07,p06,r15,r16; nop.i	0x0; }
	{ (p07) addl	r14,8404,r1; (p07) ld4	r15,[r14]; nop.i	0x0; }

l40000000000EEA76:
	{ (p07) fwb; addl	r0,49152,r1; Invalid; }

l40000000000EEA7C:
	{ cmp4.eq.or.andcm	p00,p11,r1,r0; (p01) cmp4.ne.or.andcm	p00,p40,r3,r4; zxt1	r97,r11 }

l40000000000EEA86:
	{ Invalid; nop; Invalid; }

l40000000000EEA8C:
	{ nop; cmp4.eq.or.andcm	p00,p00,r32,r0; zxt1	r96,r11 }

l40000000000EEA9C:
	{ Invalid; Invalid; add	r0,r32,r0 }
	{ nop; break.m	0x1000; break.i	0x1000 }
40000000000EEAB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; remember_args: 40000000000EEAC0
;;   Called from:
;;     40000000000220FC (in fn4000000000021EC0)
;;     400000000002217C (in fn4000000000021EC0)
;;     400000000002299C (in unbind_args)
;;     400000000006A72C (in pop_dollar_vars)
;;     400000000010A43C (in set_builtin)
;;     400000000010A4EC (in set_builtin)
;;     400000000010CF7C (in source_builtin)
remember_args proc
	{ alloc	r39,ar.pfs,0xC,0x0,0xA; cmp4.eq	p07,p06,0x0,r33; nop.b	0x0 }
	{ addl	r14,6172,r1; mov	r38,b6; adds	r40,0x0,r1; }
	{ (p06) addl	r33,1,r0; ld8	r34,[r14]; mov	r41,LC; }

l40000000000EEAE6:
	{ Invalid; (p20) cmp4.lt	p00,p00,0x41,r50; (p17) nop }

l40000000000EEAF6:
	{ break.m	0x2A088; Invalid; (p48) nop }

l40000000000EEB00:
	{ cmp.eq	p07,p06,0x0,r32; adds	r35,0x8,r32; (p06) addl	r14,1,r0; }

l40000000000EEB10:
	{ (p07) adds	r14,0x0,r0; or	r15,r36,r14; adds	r37,0x0,r14; }

l40000000000EEB16:
	{ Invalid; (p18) nop; break.b	0x80000 }
	{ (p03) chk.a.clr	f0,3FFFFFFFFFDB1C16; nop; break.b	0x80000 }

l40000000000EEB30:
	{ nop.m	0x0; ld8	r15,[r34]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r15; adds	r42,0x0,r15; (p06) br.cond.dpnt.few	40000000000EEB70; }

l40000000000EEB50:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r40; st8	[r0],r34; nop.i	0x0 }

l40000000000EEB70:
	{ cmp4.eq	p06,p07,0x0,r37; nop.i	0x0; (p06) br.cond.spnt.few	40000000000EEC50; }

l40000000000EEB80:
	{ nop.m	0x0; ld8	r14,[r35]; nop.i	0x0; }
	{ ld8	r42,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r40; adds	r42,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r14,[r35]; adds	r1,0x0,r40; adds	r42,0x0,r8; }
	{ ld8	r43,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ st8	[r8],r34; adds	r1,0x0,r40; adds	r34,0x8,r34; }
	{ ld8	r32,[r32]; cmp.eq	p07,p06,0x0,r32; nop.i	0x0; }
	{ nop.m	0x0; (p06) addl	r14,1,r0; nop.i	0x0; }

l40000000000EEBFC:
	{ Invalid; cmp4.eq.and	p00,p32,r32,r0; (p01) nop }

l40000000000EEC0C:
	{ Invalid; cmp.lt	p00,p00,r32,r0; (p01) add	r64,r3,r4 }

l40000000000EEC10:
	{ nop.m	0x0; zxt1	r14,r14; or	r36,r36,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r36; (p06) br.cond.dpnt.few	40000000000EEC80 }

l40000000000EEC30:
	{ nop.m	0x0; mov.i	ar.pfs,r39; mov.i	LC,r41; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000EEC40; br.ret	b0 }

l40000000000EEC50:
	{ nop.m	0x0; adds	r14,0x0,r0; adds	r32,0x0,r0 }
	{ nop.m	0x0; adds	r34,0x8,r34; br.cloop.sptk.few	40000000000EEB00 }

l40000000000EEC70:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000EEC10; }

l40000000000EEC80:
	{ addl	r34,7132,r1; nop.m	0x0; nop.i	0x0; }
	{ ld8	r42,[r34]; nop.i	0x0; br.call.sptk.many	b0,dispose_words; }
	{ adds	r1,0x0,r40; adds	r42,0x0,r32; br.call.sptk.many	b0,copy_word_list; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000EECB0; adds	r1,0x0,r40 }
	{ cmp4.eq	p06,p07,0x0,r33; st8	[r8],r34; (p06) br.cond.spnt.few	40000000000EEC30; }

l40000000000EECD0:
	{ nop.m	0x0; mov.i	ar.pfs,r39; mov.i	LC,r41; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	set_dollar_vars_changed; }
40000000000EECF0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; get_numeric_arg: 40000000000EED00
;;   Called from:
;;     40000000000EA88C (in break_builtin)
;;     40000000000EAA4C (in continue_builtin)
;;     40000000000FE85C (in history_builtin)
;;     400000000010C7FC (in shift_builtin)
get_numeric_arg proc
	{ alloc	r37,ar.pfs,0x9,0x0,0x7; cmp.eq	p06,p07,0x0,r34; nop.b	0x0 }
	{ adds	r35,0x8,r32; mov	r36,b4; adds	r38,0x0,r1; }
	{ nop.m	0x0; (p07) addl	r14,1,r0; nop.i	0x0; }

l40000000000EED2C:
	{ Invalid; (p32) cmp.lt.unc	p03,p08,r8,r102; mov	pr,r104,0xE400 }

l40000000000EED36:
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD72736; nop; (p32) nop }

l40000000000EED40:
	{ ld8	r14,[r35]; cmp.eq	p07,p06,0x0,r14; nop.i	0x0; }
	{ ld8	r39,[r14]; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000EEEE0; }

l40000000000EED60:
	{ ld1	r14,[r39]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r14; (p07) br.cond.dpnt.few	40000000000EEE40 }

l40000000000EED80:
	{ adds	r40,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,legal_number; }
	{ adds	r1,0x0,r38; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000000EEE10 }

l40000000000EEDA0:
	{ ld8	r14,[r35]; ld8	r39,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r39; nop.i	0x0; (p06) br.cond.spnt.few	40000000000EEEF0; }

l40000000000EEDC0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_neednumarg; }
	{ adds	r1,0x0,r38; cmp4.eq	p06,p07,0x0,r33; (p06) br.cond.dpnt.few	40000000000EEF20; }

l40000000000EEDE0:
	{ cmp4.eq	p07,p06,0x1,r33; nop.i	0x0; (p06) br.cond.spnt.few	40000000000EEF60; }

l40000000000EEDF0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,throw_to_top_level; }
	{ adds	r1,0x0,r38; nop.m	0x0; nop.i	0x0 }

l40000000000EEE10:
	{ ld8	r39,[r32]; nop.i	0x0; br.call.sptk.many	b0,no_args; }
	{ addl	r8,1,r0; adds	r1,0x0,r38; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000EEE30; br.ret	b0 }

l40000000000EEE40:
	{ adds	r14,0x2,r39; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000EED80 }

l40000000000EEE70:
	{ adds	r14,0x1,r39; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r14; (p06) br.cond.dptk.few	40000000000EED80 }

l40000000000EEEA0:
	{ nop.m	0x0; ld8	r32,[r32]; nop.i	0x0; }
	{ adds	r35,0x8,r32; cmp.eq	p06,p07,0x0,r32; (p06) br.cond.spnt.few	40000000000EEF40; }

l40000000000EEEC0:
	{ nop.m	0x0; ld8	r14,[r35]; nop.i	0x0; }
	{ ld8	r39,[r14]; nop.m	0x0; nop.i	0x0; }

l40000000000EEEE0:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r39; (p06) br.cond.spnt.few	40000000000EED80 }

l40000000000EEEF0:
	{ nop.m	0x0; addl	r39,-2564,r1; nop.i	0x0; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,sh_neednumarg; }
	{ adds	r1,0x0,r38; cmp4.eq	p06,p07,0x0,r33; (p07) br.cond.dptk.few	40000000000EEDE0 }

l40000000000EEF20:
	{ adds	r8,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000EEF30; br.ret	b0 }

l40000000000EEF40:
	{ addl	r8,1,r0; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000EEF50; br.ret	b0; }

l40000000000EEF60:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,top_level_cleanup; }
	{ adds	r1,0x0,r38; addl	r39,2,r0; br.call.sptk.many	b0,jump_to_top_level; }
	{ nop.m	0x0; break.f	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

;; get_exitstat: 40000000000EEFC0
;;   Called from:
;;     40000000000EEFBC (in get_numeric_arg)
;;     40000000000F880C (in fn40000000000F8780)
;;     400000000010853C (in return_builtin)
get_exitstat proc
	{ alloc	r35,ar.pfs,0x7,0x0,0x5; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r34,b2 }
	{ adds	r33,0x8,r32; cmp.eq	p06,p07,0x0,r32; (p06) br.cond.dpnt.few	40000000000EF180; }

l40000000000EEFE0:
	{ ld8	r14,[r33]; adds	r36,0x0,r1; cmp.eq	p06,p07,0x0,r14; }
	{ ld8	r37,[r14]; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000EF140; }

l40000000000EF000:
	{ ld1	r14,[r37]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r14; (p07) br.cond.dpnt.few	40000000000EF0A0 }

l40000000000EF020:
	{ adds	r38,0x10,r12; nop.i	0x0; br.call.sptk.many	b0,legal_number; }
	{ adds	r1,0x0,r36; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dpnt.few	40000000000EF1B0; }

l40000000000EF040:
	{ ld8	r14,[r33]; ld8	r37,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r37; nop.i	0x0; (p06) br.cond.spnt.few	40000000000EF150; }

l40000000000EF060:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_neednumarg; }
	{ nop.m	0x0; adds	r1,0x0,r36; addl	r8,255,r0 }

l40000000000EF080:
	{ nop.m	0x0; mov.i	ar.pfs,r35; mov.spnt	b0,r34,40000000000EF080 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000EF0A0:
	{ adds	r14,0x2,r37; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000EF020 }

l40000000000EF0D0:
	{ adds	r14,0x1,r37; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r14; (p06) br.cond.dptk.few	40000000000EF020 }

l40000000000EF100:
	{ nop.m	0x0; ld8	r32,[r32]; nop.i	0x0; }
	{ adds	r33,0x8,r32; cmp.eq	p06,p07,0x0,r32; (p06) br.cond.spnt.few	40000000000EF180; }

l40000000000EF120:
	{ nop.m	0x0; ld8	r14,[r33]; nop.i	0x0; }
	{ ld8	r37,[r14]; nop.m	0x0; nop.i	0x0; }

l40000000000EF140:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r37; (p06) br.cond.spnt.few	40000000000EF020 }

l40000000000EF150:
	{ nop.m	0x0; addl	r37,-2564,r1; nop.i	0x0; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,sh_neednumarg; }
	{ adds	r1,0x0,r36; addl	r8,255,r0; br.cond.sptk.few	40000000000EF080; }

l40000000000EF180:
	{ addl	r14,9044,r1; nop.m	0x0; nop.i	0x0; }
	{ ld4	r8,[r14]; mov.i	ar.pfs,r35; mov.spnt	b0,r34,40000000000EF190 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000000EF1B0:
	{ ld8	r37,[r32]; nop.i	0x0; br.call.sptk.many	b0,no_args; }
	{ adds	r14,0x10,r12; nop.m	0x0; adds	r1,0x0,r36; }
	{ ld1	r8,[r14]; mov.i	ar.pfs,r35; mov.spnt	b0,r34,40000000000EF1D0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }
40000000000EF1F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; read_octal: 40000000000EF200
;;   Called from:
;;     4000000000111A7C (in umask_builtin)
;;     4000000000111A7C (in umask_builtin)
read_octal proc
	{ adds	r8,0x0,r0; addl	r18,511,r0; adds	r14,0x0,r32; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000EF220:
	{ sub	r19,r14,r32; ld1	r16,[r14],1; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r16,r16; adds	r15,0xFFFFFFFFFFFFFFD0,r16; }
	{ nop.m	0x0; zxt1	r17,r15; nop.i	0x0; }
	{ cmp4.ltu	p07,p06,0x7,r17; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000EF290; }

l40000000000EF260:
	{ nop.m	0x0; shladd	r8,r8,0x3,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r18,r8; (p07) br.cond.dptk.few	40000000000EF220 }

l40000000000EF280:
	{ nop.m	0x0; addl	r8,-1,r0; br.ret	b0; }

l40000000000EF290:
	{ cmp4.eq	p07,p06,0x0,r16; cmp4.eq	p08,p09,0x0,r19; (p08) br.cond.dptk.few	40000000000EF280; }

l40000000000EF2A0:
	{ nop.m	0x0; (p06) addl	r8,-1,r0; br.ret	b0; }

l40000000000EF2AC:
	{ nop; break.m	0x1000; break.i	0x1000 }
40000000000EF2B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; get_working_directory: 40000000000EF2C0
;;   Called from:
;;     400000000002380C (in parse_command)
;;     4000000000068D3C (in set_pwd)
;;     400000000008446C (in stop_pipeline)
;;     40000000000EB2AC (in fn40000000000EB240)
;;     40000000000EB67C (in fn40000000000EB300)
;;     40000000000EBD3C (in fn40000000000EBA40)
;;     40000000000ECA6C (in pwd_builtin)
;;     400000000010227C (in dirs_builtin)
;;     400000000010253C (in dirs_builtin)
;;     400000000010317C (in pushd_builtin)
;;     400000000010345C (in pushd_builtin)
;;     400000000010345C (in pushd_builtin)
;;     400000000010363C (in pushd_builtin)
;;     4000000000103FBC (in get_directory_stack)
;;     400000000012CB6C (in sh_makepath)
;;     400000000012DFDC (in sh_realpath)
get_working_directory proc
	{ alloc	r37,ar.pfs,0xD,0x0,0x7; addl	r14,7360,r1; nop.b	0x0 }
	{ addl	r33,8380,r1; mov	r36,b4; adds	r38,0x0,r1; }
	{ nop.m	0x0; ld8	r39,[r33]; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000EF3F0; }

l40000000000EF310:
	{ cmp.eq	p06,p07,0x0,r39; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000EF340; }

l40000000000EF320:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r38; nop.m	0x0; nop.i	0x0 }

l40000000000EF340:
	{ st8	[r0],r33; nop.m	0x0; nop.i	0x0 }

l40000000000EF350:
	{ adds	r40,0x0,r0; adds	r39,0x0,r0; br.call.sptk.many	b0,fn400000000001B540; }
	{ cmp.eq	p07,p06,0x0,r8; adds	r1,0x0,r38; nop.i	0x0 }
	{ adds	r39,0x0,r8; st8	[r8],r33; (p07) br.cond.spnt.few	40000000000EF450; }

l40000000000EF380:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r38; adds	r39,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r38; nop.m	0x0; adds	r39,0x0,r8 }
	{ ld8	r40,[r33]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r38; nop.m	0x0; nop.i	0x0 }

l40000000000EF3D0:
	{ nop.m	0x0; mov.i	ar.pfs,r37; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000EF3E0; br.ret	b0 }

l40000000000EF3F0:
	{ cmp.eq	p07,p06,0x0,r39; nop.i	0x0; (p07) br.cond.spnt.few	40000000000EF350; }

l40000000000EF400:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r38; adds	r39,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r38; nop.m	0x0; adds	r39,0x0,r8 }
	{ ld8	r40,[r33]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; adds	r1,0x0,r38; br.cond.sptk.few	40000000000EF3D0; }

l40000000000EF450:
	{ addl	r14,-10652,r1; addl	r40,-2556,r1; addl	r41,5,r0; }
	{ ld8	r14,[r14]; ld8	r40,[r40]; nop.i	0x0; }
	{ ld8	r33,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r38; nop.m	0x0; adds	r34,0x0,r8 }
	{ cmp.eq	p06,p07,0x0,r32; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000EF4C0; }

l40000000000EF4A0:
	{ ld1	r14,[r32]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dpnt.few	40000000000EF4E0 }

l40000000000EF4C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,get_name_for_error; }
	{ nop.m	0x0; adds	r1,0x0,r38; adds	r32,0x0,r8; }

l40000000000EF4E0:
	{ addl	r14,5732,r1; addl	r41,5,r0; adds	r39,0x0,r0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld8	r40,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r38; adds	r35,0x0,r8; br.call.sptk.many	b0,fn400000000001B840; }
	{ nop.m	0x0; adds	r1,0x0,r38; nop.i	0x0 }
	{ ld4	r39,[r8]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B4A0; }
	{ adds	r1,0x0,r38; adds	r39,0x0,r33; addl	r40,1,r0 }
	{ adds	r41,0x0,r34; adds	r42,0x0,r32; adds	r43,0x0,r35; }
	{ adds	r44,0x0,r8; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ adds	r8,0x0,r0; adds	r1,0x0,r38; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000EF580; br.ret	b0; }
40000000000EF590 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000EF5A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000EF5B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; set_working_directory: 40000000000EF5C0
;;   Called from:
;;     4000000000068EAC (in set_pwd)
;;     4000000000068F8C (in set_pwd)
;;     40000000000EB56C (in fn40000000000EB300)
;;     40000000000EB8BC (in fn40000000000EB300)
set_working_directory proc
	{ alloc	r35,ar.pfs,0x7,0x0,0x5; addl	r33,8380,r1; nop.b	0x0 }
	{ adds	r36,0x0,r1; nop.m	0x0; mov	r34,b2; }
	{ nop.m	0x0; ld8	r37,[r33]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r37; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000EF620; }

l40000000000EF600:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r36; nop.m	0x0; nop.i	0x0 }

l40000000000EF620:
	{ adds	r37,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r36; adds	r37,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r37,0x0,r8 }
	{ adds	r38,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r36; st8	[r8],r33; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000EF670; br.ret	b0; }

;; get_job_by_name: 40000000000EF680
;;   Called from:
;;     40000000000EFBF6 (in get_job_spec)
;;     40000000000EFD9C (in get_job_spec)
get_job_by_name proc
	{ alloc	r42,ar.pfs,0x10,0x0,0xD; nop.m	0x0; mov	r44,pr }
	{ adds	r43,0x0,r1; adds	r45,0x0,r32; mov	r41,b1 }
	{ addl	r38,-1,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r43; nop.m	0x0; tnat.z	p22,p23,r33 }
	{ cmp4.eq	p24,p25,0x0,r8; nop.m	0x0; sxt4	r40,r8; }
	{ addl	r14,-20676,r1; addl	r15,7444,r1; tnat.z	p16,p17,r33; }
	{ nop.m	0x0; nop.m	0x0; tnat.z	p19,p18,r33; }
	{ adds	r14,0x1C,r14; nop.m	0x0; tnat.z	p20,p21,r33; }
	{ ld4	r35,[r14]; adds	r35,0xFFFFFFFFFFFFFFFF,r35; nop.i	0x0; }
	{ cmp4.lt	p06,p07,r35,r0; sxt4	r14,r35; (p06) br.cond.dpnt.few	40000000000EFAC0; }

l40000000000EF720:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld8	r39,[r15]; nop.i	0x0; shladd	r39,r14,0x3,r39; }

l40000000000EF740:
	{ ld8	r14,[r39],-8; adds	r15,0x14,r14; cmp.eq	p06,p07,0x0,r14 }
	{ nop.b	0x0; (p06) br.cond.dpnt.few	40000000000EF780; (p22) br.cond.dptk.few	40000000000EF7D0; }

l40000000000EF75C:
	{ (p04) nop; cmp.eq	p00,p00,r32,r0; Invalid }

l40000000000EF760:
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2,r15; (p07) br.cond.dpnt.few	40000000000EF7D0 }

l40000000000EF780:
	{ nop.m	0x0; adds	r35,0xFFFFFFFFFFFFFFFF,r35; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r35; (p06) br.cond.dptk.few	40000000000EF740 }

l40000000000EF7A0:
	{ adds	r35,0x0,r38; nop.m	0x0; nop.i	0x0; }

l40000000000EF7B0:
	{ adds	r8,0x0,r35; mov	pr,r44,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r42; }
	{ nop.m	0x0; mov.spnt	b0,r41,40000000000EF7C0; br.ret	b0 }

l40000000000EF7D0:
	{ adds	r14,0x8,r14; ld8	r37,[r14]; nop.i	0x0; }
	{ nop.m	0x0; adds	r34,0x0,r37; nop.i	0x0; }
	{ nop.m	0x0; adds	r14,0x18,r34; (p16) br.cond.dptk.few	40000000000EF890; }

l40000000000EF800:
	{ nop.m	0x0; ld8	r36,[r14]; nop.i	0x0; }
	{ adds	r45,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r43; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	40000000000EF8C0 }

l40000000000EF830:
	{ ld1	r15,[r36]; ld1	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r15,r14; (p07) br.cond.dpnt.few	40000000000EF980 }

l40000000000EF860:
	{ ld8	r34,[r34]; nop.m	0x0; nop.i	0x0; }

l40000000000EF870:
	{ nop.m	0x0; cmp.eq	p07,p06,r37,r34; adds	r14,0x18,r34 }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	40000000000EF780; (p17) br.cond.dptk.few	40000000000EF800 }

l40000000000EF88C:
	{ Invalid; break.i	0x1000; mov	pr,0x8001000 }

l40000000000EF890:
	{ nop.m	0x0; nop.i	0x0; (p20) br.cond.dptk.few	40000000000EF9C0; }

l40000000000EF8A0:
	{ ld8	r45,[r14]; adds	r46,0x0,r32; br.call.sptk.many	b0,fn400000000001AEA0; }
	{ adds	r1,0x0,r43; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	40000000000EF860; }

l40000000000EF8C0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r38; adds	r38,0x0,r35 }
	{ nop.b	0x0; (p18) br.cond.dpnt.few	40000000000EF7B0; (p06) br.cond.dptk.few	40000000000EF870 }

l40000000000EF8DC:
	{ (p61) cmp.lt.unc	p63,p08,r63,r37; (p01) cmp.lt	p49,p18,r32,r16; Invalid }

l40000000000EF8E0:
	{ addl	r14,8388,r1; addl	r46,-2548,r1; nop.i	0x0 }
	{ addl	r47,5,r0; adds	r45,0x0,r0; addl	r35,-2,r0; }
	{ ld8	r14,[r14]; ld8	r46,[r46]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000EFA40; }

l40000000000EF920:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r43; nop.m	0x0; adds	r45,0x0,r8 }
	{ adds	r46,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,builtin_error; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r43; mov	pr,r44,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r42; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r41,40000000000EF970; br.ret	b0; }

l40000000000EF980:
	{ adds	r45,0x0,r36; nop.m	0x0; adds	r46,0x0,r32 }
	{ nop.m	0x0; sxt4	r47,r8; br.call.sptk.many	b0,fn400000000001C020; }
	{ adds	r1,0x0,r43; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	40000000000EF8C0 }

l40000000000EF9B0:
	{ ld8	r34,[r34]; nop.i	0x0; br.cond.sptk.few	40000000000EF870; }

l40000000000EF9C0:
	{ nop.m	0x0; adds	r14,0x18,r34; (p24) br.cond.dptk.few	40000000000EF8C0; }

l40000000000EF9D0:
	{ ld8	r45,[r14]; ld1	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r14; nop.i	0x0; }
	{ ld1	r14,[r45]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r15; (p06) br.cond.dptk.few	40000000000EF860 }

l40000000000EFA10:
	{ adds	r46,0x0,r32; adds	r47,0x0,r40; br.call.sptk.many	b0,fn400000000001C020; }
	{ adds	r1,0x0,r43; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	40000000000EF8C0 }

l40000000000EFA30:
	{ ld8	r34,[r34]; nop.i	0x0; br.cond.sptk.few	40000000000EF870; }

l40000000000EFA40:
	{ addl	r46,-2548,r1; nop.m	0x0; addl	r47,5,r0 }
	{ adds	r45,0x0,r0; nop.m	0x0; addl	r35,-2,r0; }
	{ ld8	r46,[r46]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r43; nop.m	0x0; adds	r45,0x0,r8 }
	{ adds	r46,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,report_error; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r43; mov	pr,r44,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r42; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r41,40000000000EFAB0; br.ret	b0 }

l40000000000EFAC0:
	{ addl	r35,-1,r0; nop.m	0x0; mov	pr,r44,0xFFFFFFFFFFFFFFFE; }
	{ adds	r8,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r42; }
	{ nop.m	0x0; mov.spnt	b0,r41,40000000000EFAE0; br.ret	b0; }
40000000000EFAF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; get_job_spec: 40000000000EFB00
;;   Called from:
;;     40000000000FADCC (in fn40000000000FAD40)
;;     40000000000FF0EC (in jobs_builtin)
;;     40000000000FF4EC (in jobs_builtin)
;;     40000000000FF9FC (in disown_builtin)
;;     40000000000FFFEC (in kill_builtin)
;;     400000000011215C (in wait_builtin)
get_job_spec proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; cmp.eq	p07,p06,0x0,r32; nop.b	0x0 }
	{ adds	r32,0x8,r32; mov	r34,b2; (p07) br.cond.dpnt.few	40000000000EFC10; }

l40000000000EFB20:
	{ ld8	r14,[r32]; nop.m	0x0; adds	r36,0x0,r1; }
	{ ld8	r32,[r14]; ld1	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000EFD50; }

l40000000000EFB60:
	{ cmp4.eq	p07,p06,0x25,r14; (p07) adds	r32,0x1,r32; nop.i	0x0; }

l40000000000EFB6C:
	{ cmp4.eq.and	p00,p43,r1,r0; Invalid; cmp4.eq.and	p00,p32,r32,r0 }

l40000000000EFB76:
	{ chk.a.nc	f0,3FFFFFFFFF0F0376; (p07) nop; (p48) nop }
	{ add	r0,r0,r1; (p07) nop; break.i	0x80000 }
	{ (p03) chk.a.clr	f9,3FFFFFFFFFBB3486; nop; (p32) nop }

l40000000000EFBA0:
	{ cmp4.eq	p06,p07,0x2B,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000EFC10; }

l40000000000EFBB0:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x2B,r14; (p07) br.cond.dptk.few	40000000000EFC00; }

l40000000000EFBC0:
	{ cmp4.eq	p06,p07,0x2D,r14; adds	r33,0x0,r0; (p06) br.cond.dpnt.few	40000000000EFCC0; }

l40000000000EFBD0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x3F,r14; (p06) br.cond.dpnt.few	40000000000EFD70 }

l40000000000EFBE0:
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000EFBE0; mov.i	ar.pfs,r35; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	get_job_by_name }

l40000000000EFC00:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	40000000000EFCA0 }

l40000000000EFC10:
	{ addl	r14,-20676,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; adds	r14,0x30,r14; nop.i	0x0; }
	{ ld4	r8,[r14]; nop.m	0x0; nop.i	0x0 }

l40000000000EFC40:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000EFC50; br.ret	b0; }

l40000000000EFC60:
	{ adds	r37,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,all_digits; }
	{ adds	r1,0x0,r36; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dpnt.few	40000000000EFCF0; }

l40000000000EFC80:
	{ nop.m	0x0; ld1	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; br.cond.sptk.few	40000000000EFBA0; }

l40000000000EFCA0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x25,r14; adds	r33,0x0,r0 }
	{ nop.b	0x0; (p06) br.cond.dpnt.few	40000000000EFC10; br.cond.sptk.few	40000000000EFBE0 }

l40000000000EFCBC:
	{ (p57) cmp.lt.unc	p63,p09,r63,r36; Invalid; break.b	0x1000 }

l40000000000EFCC0:
	{ addl	r14,-20676,r1; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000EFCD0; adds	r14,0x34,r14; }
	{ ld4	r8,[r14]; nop.i	0x0; br.ret	b0; }

l40000000000EFCF0:
	{ adds	r37,0x0,r32; nop.m	0x0; adds	r38,0x0,r0 }
	{ addl	r39,10,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C2A0; }
	{ adds	r1,0x0,r36; addl	r14,-20676,r1; nop.i	0x0; }
	{ nop.m	0x0; adds	r14,0x1C,r14; nop.i	0x0; }
	{ ld4	r14,[r14]; cmp4.lt	p06,p07,r14,r8; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r8,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dptk.few	40000000000EFC40; }

l40000000000EFD4C:
	{ (p56) nop; Invalid; break.i	0x1000 }

l40000000000EFD50:
	{ addl	r8,-1,r0; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000EFD60; br.ret	b0; }

l40000000000EFD70:
	{ adds	r32,0x1,r32; addl	r33,2,r0; mov.spnt	b0,r34,40000000000EFD70; }
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	get_job_by_name; }
40000000000EFDA0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000EFDB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; display_signal_list: 40000000000EFDC0
;;   Called from:
;;     40000000001006FC (in kill_builtin)
;;     400000000010E66C (in trap_builtin)
display_signal_list proc
	{ alloc	r41,ar.pfs,0x11,0x0,0xD; adds	r12,0xFFFFFFFFFFFFFFF0,r12; addl	r39,-9572,r1 }
	{ addl	r37,6456,r1; addl	r38,8388,r1; adds	r42,0x0,r1; }
	{ adds	r35,0x0,r0; addl	r36,128,r0; nop.b	0x0 }
	{ ld8	r39,[r39]; nop.m	0x0; mov	r43,pr; }
	{ nop.m	0x0; mov	r44,LC; cmp.eq	p07,p06,0x0,r32; }
	{ nop.m	0x0; mov	r40,b0; (p07) br.cond.dpnt.few	40000000000F00F0; }

l40000000000EFE20:
	{ adds	r34,0x8,r32; nop.m	0x0; adds	r46,0x10,r12; }
	{ nop.m	0x0; ld8	r14,[r34]; nop.i	0x0; }
	{ ld8	r45,[r14]; nop.i	0x0; br.call.sptk.many	b0,legal_number; }
	{ adds	r1,0x0,r42; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	40000000000EFFA0 }

l40000000000EFE60:
	{ adds	r14,0x10,r12; ld8	r45,[r14]; nop.i	0x0; }
	{ cmp.lt	p07,p06,r36,r45; (p07) adds	r45,0xFFFFFFFFFFFFFF80,r45; nop.i	0x0; }

l40000000000EFE7C:
	{ Invalid; (p16) cmp.eq.unc	p11,p08,r3,r102; mov	pr,r75,0xD460 }

l40000000000EFE86:
	{ (p03) chk.a.clr	f64,3FFFFFFFFFB73156; nop; break.b	0x80000 }

l40000000000EFE90:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,signal_name; }
	{ ld1	r14,[r8]; adds	r1,0x0,r42; adds	r34,0x0,r8; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x53,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000F00B0; }

l40000000000EFED0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x55,r14; (p07) br.cond.dpnt.few	40000000000EFF60 }

l40000000000EFEE0:
	{ ld8	r14,[r38]; cmp.eq	p07,p06,r39,r14; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r34,0x3,r34; nop.i	0x0; }

l40000000000EFEFC:
	{ nop; zxt1	r64,r64; break.i	0x1000 }
	{ (p36) nop; invala; Invalid }
	{ Invalid; cmp.eq	p00,p00,r32,r0; mov	pr,r72,0xE400 }

l40000000000EFF20:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p06) br.cond.dptk.few	40000000000EFE20; }

l40000000000EFF30:
	{ adds	r8,0x0,r35; mov	pr,r43,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.i	LC,r44; mov.spnt	b0,r40,40000000000EFF40 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000EFF60:
	{ addl	r46,-2524,r1; adds	r45,0x0,r8; addl	r47,7,r0; }
	{ ld8	r46,[r46]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C020; }
	{ adds	r1,0x0,r42; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000000EFEE0 }

l40000000000EFF90:
	{ ld8	r32,[r32]; nop.i	0x0; br.cond.sptk.few	40000000000EFF20 }

l40000000000EFFA0:
	{ ld4	r14,[r37]; nop.m	0x0; addl	r46,3,r0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000EFFE0 }

l40000000000EFFC0:
	{ ld8	r46,[r38]; cmp.eq	p07,p06,r39,r46; nop.i	0x0; }
	{ (p06) addl	r46,3,r0; nop.i	0x0; (p07) addl	r46,2,r0 }

l40000000000EFFD6:
	{ chk.a.nc	f0,3FFFFFFFFF0F07D6; (p23) nop; break.i	0x80000 }

l40000000000EFFE0:
	{ nop.m	0x0; ld8	r14,[r34]; nop.i	0x0; }
	{ ld8	r45,[r14]; nop.i	0x0; br.call.sptk.many	b0,decode_signal; }
	{ adds	r1,0x0,r42; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; nop.i	0x0 }
	{ addl	r45,1,r0; adds	r47,0x0,r8; (p07) br.cond.dpnt.few	40000000000F0060; }

l40000000000F0020:
	{ nop.m	0x0; addl	r46,-2492,r1; nop.i	0x0; }
	{ ld8	r46,[r46]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ nop.m	0x0; adds	r1,0x0,r42; nop.i	0x0 }
	{ ld8	r32,[r32]; nop.m	0x0; br.cond.sptk.few	40000000000EFF20 }

l40000000000F0060:
	{ ld8	r14,[r34]; nop.m	0x0; addl	r35,1,r0; }
	{ ld8	r45,[r14]; nop.i	0x0; br.call.sptk.many	b0,sh_invalidsig; }
	{ ld8	r32,[r32]; nop.m	0x0; adds	r1,0x0,r42; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p06) br.cond.dptk.few	40000000000EFE20 }

l40000000000F00A0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000EFF30 }

l40000000000F00B0:
	{ addl	r46,-2532,r1; adds	r45,0x0,r8; addl	r47,7,r0; }
	{ ld8	r46,[r46]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C020; }
	{ adds	r1,0x0,r42; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	40000000000EFEE0 }

l40000000000F00E0:
	{ ld8	r32,[r32]; nop.i	0x0; br.cond.sptk.few	40000000000EFF20 }

l40000000000F00F0:
	{ nop.m	0x0; adds	r36,0x0,r0; nop.b	0x0 }
	{ addl	r34,1,r0; cmp4.eq	p19,p18,0x0,r33; mov.i	LC,0x3F; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000F0120:
	{ adds	r45,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,signal_name; }
	{ ld1	r14,[r8]; adds	r1,0x0,r42; adds	r35,0x0,r8; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p17,p16,0x53,r14; cmp4.eq	p07,p06,0x55,r14 }
	{ nop.b	0x0; (p17) br.cond.dpnt.few	40000000000F0400; (p07) br.cond.dpnt.few	40000000000F02C0 }

l40000000000F016C:
	{ (p11) nop; cmp.lt	p00,p00,r32,r0; (p01) cmp.lt	p32,p08,r9,r4 }

l40000000000F0170:
	{ nop.m	0x0; ld4	r14,[r37]; addl	r46,-2500,r1 }
	{ adds	r47,0x0,r34; adds	r48,0x0,r35; addl	r45,1,r0; }
	{ nop.m	0x0; ld8	r46,[r46]; cmp4.eq	p06,p07,0x0,r14 }
	{ nop.b	0x0; (p06) br.cond.dpnt.few	40000000000F03A0; (p18) br.cond.dptk.few	40000000000F03A0; }

l40000000000F01AC:
	{ (p16) cmp.eq	p00,p08,r0,r33; cmp.lt.unc	p16,p28,r72,r97; Invalid }

l40000000000F01B0:
	{ cmp4.eq	p07,p06,0x40,r34; addl	r46,-2508,r1; nop.i	0x0 }
	{ addl	r45,1,r0; adds	r47,0x0,r35; (p17) br.cond.dpnt.few	40000000000F0310; }

l40000000000F01D0:
	{ (p07) addl	r48,-2772,r1; ld8	r46,[r46]; nop.i	0x0; }

l40000000000F01D6:
	{ (p23) fwb; addl	r0,49152,r1; (p01) cmp4.eq.or.andcm	p12,p59,0x25,r31 }

l40000000000F01E6:
	{ (p24) fwb; nop; (p01) nop; }

l40000000000F01EC:
	{ Invalid; Invalid; Invalid }

l40000000000F01F6:
	{ (p32) flushrs; nop; (p16) nop }
	{ break.m	0x4000; nop; break.i	0x80000 }

l40000000000F0210:
	{ nop.m	0x0; adds	r34,0x1,r34; br.cloop.sptk.few	40000000000F0120 }

l40000000000F0220:
	{ nop.m	0x0; ld4	r14,[r37]; cmp4.eq	p10,p11,0x0,r33 }
	{ adds	r35,0x0,r0; cmp4.eq	p08,p09,0x0,r36; addl	r45,10,r0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000F0260 }

l40000000000F0250:
	{ nop.m	0x0; nop.i	0x0; (p10) br.cond.dpnt.few	40000000000F0270 }

l40000000000F0260:
	{ nop.m	0x0; nop.i	0x0; (p08) br.cond.dptk.few	40000000000EFF30 }

l40000000000F0270:
	{ adds	r35,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B900; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r42; mov	pr,r43,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r41; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r44; mov.spnt	b0,r40,40000000000F02A0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000F02C0:
	{ addl	r46,-2524,r1; adds	r45,0x0,r8; addl	r47,7,r0; }
	{ ld8	r46,[r46]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C020; }
	{ adds	r1,0x0,r42; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	40000000000F0170 }

l40000000000F02F0:
	{ nop.m	0x0; adds	r34,0x1,r34; br.cloop.sptk.few	40000000000F0120 }

l40000000000F0300:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000F0220; }

l40000000000F0310:
	{ addl	r46,-2516,r1; adds	r45,0x0,r35; addl	r47,3,r0; }
	{ ld8	r46,[r46]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C020; }
	{ cmp4.eq	p07,p06,0x0,r8; adds	r1,0x0,r42; addl	r45,1,r0; }
	{ (p07) adds	r35,0x3,r35; cmp4.eq	p07,p06,0x40,r34; addl	r46,-2508,r1; }

l40000000000F0346:
	{ Invalid; (p23) nop; Invalid }
	{ Invalid; (p23) nop; (p32) addl	r11,131904,r3; }

l40000000000F035C:
	{ cmp.lt	p35,p11,r0,r66; (p06) nop; }

l40000000000F036C:
	{ nop; mov	pr,r32,0x0; Invalid }

l40000000000F037C:
	{ Invalid; Invalid; break.i	0x1000 }

l40000000000F0386:
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; nop; nop.b	0x24029 }

l40000000000F03A0:
	{ adds	r36,0x1,r36; adds	r34,0x1,r34; br.call.sptk.many	b0,fn400000000001BB80; }
	{ cmp4.lt	p06,p07,0x4,r36; nop.m	0x0; adds	r1,0x0,r42; }
	{ (p06) adds	r36,0x0,r0; nop.m	0x0; (p07) addl	r45,9,r0; }

l40000000000F03C6:
	{ addp4	r0,0xFFFFFFFFFFFFE000,r1; (p22) nop; (p17) nop }

l40000000000F03D0:
	{ (p06) addl	r45,10,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B900; }

l40000000000F03D6:
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; (p02) nop; break.b	0x80000 }

l40000000000F03F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000F0220; }

l40000000000F0400:
	{ addl	r46,-2532,r1; adds	r45,0x0,r8; addl	r47,7,r0; }
	{ ld8	r46,[r46]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C020; }
	{ adds	r1,0x0,r42; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	40000000000F02F0 }

l40000000000F0430:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000F0170; }

;; builtin_address_internal: 40000000000F0440
;;   Called from:
;;     40000000000F062C (in find_shell_builtin)
;;     40000000000F06EC (in builtin_address)
;;     40000000000F07AC (in find_special_builtin)
;;     40000000000F2F2C (in enable_builtin)
;;     40000000000F37BC (in enable_builtin)
;;     40000000000F3CCC (in enable_builtin)
builtin_address_internal proc
	{ alloc	r41,ar.pfs,0xD,0x0,0xB; addl	r14,6156,r1; mov	r40,b0 }
	{ adds	r42,0x0,r1; nop.m	0x0; adds	r36,0x0,r0; }
	{ ld4	r35,[r14]; addl	r14,6164,r1; adds	r35,0xFFFFFFFFFFFFFFFF,r35; }
	{ cmp4.lt	p07,p06,r35,r0; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000F0560; }

l40000000000F0480:
	{ nop.m	0x0; ld1	r38,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r38,r38; nop.i	0x0; }
	{ ld8	r39,[r14]; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000F04C0:
	{ add	r34,r36,r35; adds	r44,0x0,r32; extr	r34,r34,1,31; }
	{ nop.m	0x0; sxt4	r8,r34; shladd	r8,r8,0x1,r8; }
	{ shladd	r37,r8,0x4,r39; ld8	r14,[r37]; nop.i	0x0; }
	{ adds	r43,0x0,r14; ld1	r8,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r8,r8; sub	r8,r8,r38; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000000F0540 }

l40000000000F0520:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r42; cmp4.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	40000000000F0580; }

l40000000000F0540:
	{ cmp4.lt	p07,p06,0x0,r8; (p06) adds	r36,0x1,r34; (p07) adds	r35,0xFFFFFFFFFFFFFFFF,r34; }

l40000000000F054C:
	{ Invalid; Invalid; Invalid }

l40000000000F0550:
	{ nop.m	0x0; cmp4.lt	p07,p06,r35,r36; (p06) br.cond.dptk.few	40000000000F04C0 }

l40000000000F0560:
	{ adds	r37,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r41; }
	{ adds	r8,0x0,r37; mov.spnt	b0,r40,40000000000F0570; br.ret	b0; }

l40000000000F0580:
	{ adds	r14,0x8,r37; adds	r15,0x10,r37; nop.b	0x0 }
	{ adds	r8,0x0,r37; nop.m	0x0; mov.i	ar.pfs,r41; }
	{ ld8	r14,[r14]; nop.m	0x0; mov.spnt	b0,r40,40000000000F05A0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F0560; }

l40000000000F05C0:
	{ nop.m	0x0; ld4	r14,[r15]; nop.i	0x0; }
	{ and	r15,0x1,r14; tbit.z	p07,p06,r14,0x1; (p06) br.cond.dpnt.few	40000000000F0560; }

l40000000000F05E0:
	{ nop.m	0x0; or	r15,r33,r15; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r15; (p07) br.cond.dpnt.few	40000000000F0560; br.ret	b0; }

l40000000000F05FC:
	{ ld2	r0,[r0]; Invalid; nop }

;; find_shell_builtin: 40000000000F0600
;;   Called from:
;;     40000000000A81FC (in fn40000000000A7940)
;;     40000000000A81FC (in fn40000000000A7940)
;;     40000000000EAC4C (in builtin_builtin)
;;     40000000000FBC0C (in hash_builtin)
;;     400000000010E99C (in describe_command)
;;     400000000010E99C (in describe_command)
find_shell_builtin proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x4; nop.m	0x0; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; adds	r36,0x0,r32; }
	{ adds	r37,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,builtin_address_internal; }
	{ adds	r1,0x0,r35; adds	r15,0x8,r8; nop.b	0x0 }
	{ cmp.eq	p06,p07,0x0,r8; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ addl	r14,9228,r1; nop.m	0x0; mov.spnt	b0,r33,40000000000F0650; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st8	[r8],r14; (p07) ld8	r8,[r15]; nop.i	0x0; }

l40000000000F067C:
	{ Invalid; mov	pr,r32,0x0; (p01) shladd	r0,r0,0x1,r64 }

l40000000000F068C:
	{ nop; break.m	0x1000; break.i	0x1000 }
40000000000F0690 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000F06A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000F06B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; builtin_address: 40000000000F06C0
builtin_address proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x4; nop.m	0x0; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; adds	r36,0x0,r32; }
	{ addl	r37,1,r0; nop.i	0x0; br.call.sptk.many	b0,builtin_address_internal; }
	{ adds	r1,0x0,r35; adds	r15,0x8,r8; nop.b	0x0 }
	{ cmp.eq	p06,p07,0x0,r8; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ addl	r14,9228,r1; nop.m	0x0; mov.spnt	b0,r33,40000000000F0710; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st8	[r8],r14; (p07) ld8	r8,[r15]; nop.i	0x0; }

l40000000000F073C:
	{ Invalid; mov	pr,r32,0x0; (p01) shladd	r0,r0,0x1,r64 }

l40000000000F074C:
	{ nop; break.m	0x1000; break.i	0x1000 }
40000000000F0750 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000F0760 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000F0770 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; find_special_builtin: 40000000000F0780
find_special_builtin proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x4; nop.m	0x0; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; adds	r36,0x0,r32; }
	{ adds	r37,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,builtin_address_internal; }
	{ adds	r1,0x0,r35; adds	r15,0x10,r8; nop.b	0x0 }
	{ cmp.eq	p06,p07,0x0,r8; adds	r16,0x8,r8; mov.i	ar.pfs,r34; }
	{ addl	r14,9228,r1; nop.m	0x0; mov.spnt	b0,r33,40000000000F07D0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st8	[r8],r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F0830; }

l40000000000F0800:
	{ nop.m	0x0; ld4	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x3; (p06) br.cond.dpnt.few	40000000000F0830; }

l40000000000F0820:
	{ (p07) ld8	r8,[r16]; nop.i	0x0; br.ret	b0; }

l40000000000F0826:
	{ break.m	0x4000; (p34) nop; nop }

l40000000000F0830:
	{ adds	r8,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000F0840; br.ret	b0; }
40000000000F0850 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000F0860 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000F0870 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; initialize_shell_builtins: 40000000000F0880
;;   Called from:
;;     40000000000F3AAC (in enable_builtin)
initialize_shell_builtins proc
	{ alloc	r33,ar.pfs,0x7,0x0,0x3; addl	r14,6156,r1; mov	r32,b0 }
	{ addl	r38,-2828,r1; nop.m	0x0; adds	r34,0x0,r1; }
	{ nop.m	0x0; nop.m	0x0; addl	r37,48,r0 }
	{ ld8	r38,[r38]; ld4	r36,[r14]; addl	r14,6164,r1; }
	{ nop.m	0x0; nop.m	0x0; sxt4	r36,r36; }
	{ ld8	r35,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C000; }
	{ adds	r1,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ nop.m	0x0; mov.spnt	b0,r32,40000000000F08F0; br.ret	b0; }

;; fn40000000000F0900: 40000000000F0900
;;   Called from:
;;     40000000000F241C (in declare_builtin)
;;     40000000000F24EC (in local_builtin)
fn40000000000F0900 proc
	{ alloc	r63,ar.pfs,0x27,0x0,0x22; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r65,pr }
	{ addl	r35,9276,r1; addl	r36,-8308,r1; adds	r64,0x0,r1; }
	{ adds	r34,0x10,r12; nop.m	0x0; mov	r62,b6 }
	{ adds	r38,0x0,r0; adds	r37,0x0,r0; adds	r39,0x0,r0; }
	{ st4	[r34],r4,4; ld8	r36,[r36]; addl	r45,256,r0 }
	{ addl	r48,1536,r0; addl	r44,512,r0; addl	r47,1280,r0; }
	{ st4	[r0],r34; addl	r43,1024,r0; addl	r46,768,r0 }
	{ addl	r41,1,r0; addl	r40,128,r0; br.call.sptk.many	b0,reset_internal_getopt; }
	{ adds	r1,0x0,r64; cmp4.eq	p17,p16,0x0,r33; addl	r42,5780,r1 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ addl	r67,-8372,r1; nop.m	0x0; adds	r66,0x0,r32; }
	{ ld8	r67,[r67]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r64; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dpnt.few	40000000000F0AE0 }

l40000000000F09D0:
	{ ld4	r14,[r35]; adds	r8,0xFFFFFFFFFFFFFFBF,r8; cmp4.eq	p07,p06,0x2B,r14; }
	{ (p07) adds	r14,0x10,r12; (p06) ld4	r15,[r34]; nop.i	0x0; }

l40000000000F09E6:
	{ (p07) fwb; nop; Invalid; }

l40000000000F09EC:
	{ nop; cmp4.eq.or.andcm	p00,p32,r32,r0; (p01) cmp4.ne.and	p00,p08,r3,r4 }

l40000000000F09FC:
	{ nop; cmp.lt	p00,p00,r32,r0; (p48) mov	pr,r98,0xD61A; }

l40000000000F0A00:
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x37,r8; (p07) br.cond.dptk.few	40000000000F0A60 }

l40000000000F0A10:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ nop.m	0x0; adds	r1,0x0,r64; addl	r8,258,r0 }

l40000000000F0A30:
	{ nop.m	0x0; mov	pr,r65,0xFFFFFFFFFFFFFFFE; nop.i	0x0; }
	{ nop.m	0x0; mov.i	ar.pfs,r63; mov.spnt	b0,r62,40000000000F0A40 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000F0A60:
	{ addp4	r8,r8,r0; shladd	r8,r8,0x3,r36; nop.i	0x0; }
	{ ld8	r16,[r8]; add	r8,r8,r16; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r8,40000000000F0A80; br.cond	b6; }
40000000000F0A90 08 78 04 1E 2E 20 00 00 00 02 00 60 C8 EC FB 9E .x... .....`....
40000000000F0AA0 02 00 A4 54 90 11 20 04 80 00 42 00 00 00 04 00 ...T.. ...B.....
40000000000F0AB0 19 00 3C 1C 90 11 30 04 0C 31 20 00 18 9A 02 50 ..<...0..1 ....P
40000000000F0AC0 11 08 00 80 00 21 70 F8 23 0C 77 03 10 FF FF 4A .....!p.#.w....J
40000000000F0AD0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

l40000000000F0AE0:
	{ addl	r14,9268,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld8	r35,[r14]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r35; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000F1630; }

l40000000000F0B10:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r39; (p06) br.cond.dptk.few	40000000000F0DC0 }

l40000000000F0B20:
	{ adds	r36,0x0,r0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000F0B40:
	{ adds	r34,0x8,r35; nop.m	0x0; adds	r67,0x0,r37; }
	{ nop.m	0x0; ld8	r14,[r34]; nop.i	0x0; }
	{ ld8	r66,[r14]; nop.i	0x0; br.call.sptk.many	b0,show_name_attributes; }
	{ adds	r1,0x0,r64; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dpnt.few	40000000000F1130; }

l40000000000F0B80:
	{ nop.m	0x0; ld8	r35,[r35]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	40000000000F0B40; }

l40000000000F0BA0:
	{ cmp4.eq	p07,p06,0x0,r36; (p06) addl	r66,1,r0; nop.i	0x0; }

l40000000000F0BAC:
	{ getf.s	r0,f1; zxt1	r0,r64; break.i	0x1000 }

l40000000000F0BB6:
	{ break.m	0x4000; Invalid; (p16) nop }
	{ (p63) rum	0x17F841; break.i	0xAA03F; break.b	0x80000 }
	{ Invalid; nop; nop }
	{ break.m	0x4000; (p34) nop; (p48) nop }
40000000000F0BF0 09 78 B4 1E 0E 20 00 00 00 02 00 E0 20 72 18 E0 .x... ...... r..
40000000000F0C00 09 00 3C 1C 90 11 00 00 00 02 80 E3 01 61 00 84 ..<..........a..
40000000000F0C10 EB 70 00 1E 10 D0 E1 80 39 1C 40 00 00 00 04 00 .p......9.@.....
40000000000F0C20 F0 00 38 1E 90 11 00 00 00 02 00 00 80 FD FF 48 ..8............H
40000000000F0C30 09 00 00 00 01 00 F0 40 3D 1C 40 00 00 00 04 00 .......@=.@.....
40000000000F0C40 10 00 3C 1C 90 11 00 00 00 02 00 00 60 FD FF 48 ..<.........`..H
40000000000F0C50 09 00 00 00 01 00 F0 10 3C 5C 40 00 00 00 04 00 ........<\@.....
40000000000F0C60 10 00 3C 1C 90 11 00 00 00 02 00 00 40 FD FF 48 ..<.........@..H
40000000000F0C70 10 00 00 00 01 40 74 0A 9C 00 42 00 30 FD FF 48 .....@t...B.0..H
40000000000F0C80 09 38 88 1C 06 38 00 00 00 02 00 E0 C1 7A 38 80 .8...8.......z8.
40000000000F0C90 09 00 3C 1C 90 11 00 00 00 02 80 23 02 61 00 84 ..<........#.a..
40000000000F0CA0 EB 70 00 22 10 D0 E1 78 39 1C 40 00 00 00 04 00 .p."...x9.@.....
40000000000F0CB0 F0 00 38 22 90 11 00 00 00 02 00 00 F0 FC FF 48 ..8"...........H
40000000000F0CC0 09 00 00 00 01 00 F0 80 3C 5C 40 00 00 00 04 00 ........<\@.....
40000000000F0CD0 10 00 3C 1C 90 11 00 00 00 02 00 00 D0 FC FF 48 ..<............H
40000000000F0CE0 09 00 00 00 01 00 60 10 39 0E 70 00 00 00 04 00 ......`.9.p.....
40000000000F0CF0 10 00 00 00 01 80 61 0A 00 00 48 00 B0 FC FF 48 ......a...H....H
40000000000F0D00 09 00 00 00 01 00 F0 40 3C 5C 40 00 00 00 04 00 .......@<\@.....
40000000000F0D10 10 00 3C 1C 90 11 00 00 00 02 00 00 90 FC FF 48 ..<............H
40000000000F0D20 09 78 AC 1E 0E 20 00 00 00 02 00 E0 20 72 18 E0 .x... ...... r..
40000000000F0D30 09 00 3C 1C 90 11 00 00 00 02 80 E3 01 61 00 84 ..<..........a..
40000000000F0D40 EB 70 00 1E 10 D0 E1 70 39 1C 40 00 00 00 04 00 .p.....p9.@.....
40000000000F0D50 F0 00 38 1E 90 11 00 00 00 02 00 00 50 FC FF 48 ..8.........P..H
40000000000F0D60 09 00 00 00 01 00 F0 20 3C 5C 40 00 00 00 04 00 ....... <\@.....
40000000000F0D70 10 00 3C 1C 90 11 00 00 00 02 00 00 30 FC FF 48 ..<.........0..H
40000000000F0D80 09 78 20 1E 2E 20 00 00 00 02 00 A0 14 28 01 84 .x .. .......(..
40000000000F0D90 10 00 3C 1C 90 11 00 00 00 02 00 00 10 FC FF 48 ..<............H
40000000000F0DA0 09 00 00 00 01 00 F0 00 3E 5C 40 00 00 00 04 00 ........>\@.....
40000000000F0DB0 10 00 3C 1C 90 11 00 00 00 02 00 00 F0 FB FF 48 ..<............H

l40000000000F0DC0:
	{ addl	r40,6456,r1; addl	r43,7148,r1; addl	r61,6472,r1 }
	{ adds	r44,0x0,r0; adds	r46,0x0,r0; cmp4.eq	p20,p21,0x0,r38; }
	{ addl	r58,4096,r0; nop.m	0x0; addl	r52,16386,r0 }
	{ addl	r55,1048576,r0; movl	r57,0x200000; }
	{ nop.m	0x0; addl	r60,-1048577,r0; addl	r59,48,r0 }
	{ addl	r56,91,r0; cmp4.eq	p22,p23,0x0,r37; cmp4.eq	p19,p18,0x0,r38; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000F0E40:
	{ adds	r36,0x8,r35; ld8	r14,[r36]; nop.i	0x0; }
	{ ld8	r66,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r64; adds	r66,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r14,[r36]; adds	r1,0x0,r64; adds	r66,0x0,r8; }
	{ ld8	r67,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r64; adds	r36,0x0,r8; nop.i	0x0 }
	{ adds	r66,0x0,r8; adds	r67,0x0,r0; br.call.sptk.many	b0,assignment; }
	{ nop.m	0x0; adds	r1,0x0,r64; adds	r38,0x0,r8 }
	{ nop.m	0x0; cmp4.eq	p16,p17,0x0,r8; (p17) br.cond.dptk.few	40000000000F1180 }

l40000000000F0ED0:
	{ addl	r67,91,r0; adds	r66,0x0,r36; br.call.sptk.many	b0,fn400000000001B680; }
	{ cmp.eq	p07,p06,0x0,r8; adds	r66,0x0,r36; nop.i	0x0 }
	{ adds	r1,0x0,r64; adds	r37,0x0,r8; (p07) br.cond.dpnt.few	40000000000F23C0; }

l40000000000F0F00:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,valid_array_reference; }
	{ adds	r1,0x0,r64; cmp4.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	40000000000F14E0; }

l40000000000F0F20:
	{ nop.m	0x0; addl	r51,-8380,r1; adds	r48,0x0,r0 }
	{ st1	[r0],r37; adds	r42,0x0,r37; addl	r39,1,r0; }
	{ ld8	r51,[r51]; nop.m	0x0; nop.i	0x0 }

l40000000000F0F50:
	{ nop.m	0x0; ld4	r14,[r40]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F0F90; }

l40000000000F0F70:
	{ nop.m	0x0; ld4	r37,[r34]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r37,0x3; (p06) br.cond.dptk.few	40000000000F0FC0 }

l40000000000F0F90:
	{ adds	r66,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,legal_identifier; }
	{ adds	r1,0x0,r64; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	40000000000F14E0; }

l40000000000F0FB0:
	{ ld4	r37,[r34]; nop.i	0x0; tbit.z	p07,p06,r37,0x3 }

l40000000000F0FC0:
	{ nop.m	0x0; ld4	r14,[r43]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p08,p09,0x0,r14; (p09) br.cond.dptk.few	40000000000F1250 }

l40000000000F0FE0:
	{ nop.m	0x0; nop.i	0x0; (p07) br.cond.dptk.few	40000000000F1500; }

l40000000000F0FF0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000F1000:
	{ adds	r66,0x0,r36; (p17) br.cond.dpnt.few	40000000000F2180; br.call.sptk.many	b0,find_function; }

l40000000000F100C:
	{ (p58) cmp.lt.unc	p35,p08,r61,r44; cmp.lt	p00,p28,r98,r65; zxt1	r10,r64 }
	{ nop; nop; (p02) cmp.lt	p04,p16,r3,r64 }
	{ cmp4.eq.and	p08,p17,r0,r66; break.x	0x10802E02A01000 }

l40000000000F1036:
	{ chk.a.nc	r0,3FFFFFFFFF0F1836; nop; (p48) nop }

l40000000000F1040:
	{ ld4	r15,[r14]; ld4	r16,[r17]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r15,0x1; (p06) br.cond.dptk.few	40000000000F1070; }

l40000000000F1060:
	{ nop.m	0x0; tbit.z	p06,p07,r16,0x1; (p07) br.cond.dpnt.few	40000000000F1450; }

l40000000000F1070:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x8,r37; (p07) br.cond.dpnt.few	40000000000F13B0 }

l40000000000F1080:
	{ andcm	r16,0xFFFFFFFFFFFFFFFF,r16; or	r15,r15,r37; and	r15,r15,r16 }
	{ nop.m	0x0; st4	[r15],r14; nop.i	0x0 }

l40000000000F10A0:
	{ adds	r66,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r64; ld8	r35,[r35]; nop.i	0x0; }

l40000000000F10C0:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	40000000000F0E40; }

l40000000000F10D0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r44; nop.i	0x0; }
	{ nop.m	0x0; (p06) addl	r8,260,r0; (p06) br.cond.dptk.few	40000000000F0A30 }

l40000000000F10EC:
	{ (p10) cmp.eq.unc	p63,p11,r63,r37; cmp4.ne.and	p00,p28,r75,r97; (p21) nop }

l40000000000F10F0:
	{ cmp4.eq	p07,p06,0x0,r46; (p06) addl	r46,1,r0; nop.i	0x0; }

l40000000000F10FC:
	{ cmp4.eq.and	p00,p43,r1,r0; zxt1	r0,r64; (p01) cmp.eq.unc	p00,p16,r11,r64 }

l40000000000F1106:
	{ Invalid; Invalid; break.i	0x80000 }
	{ break.m	0xAA03F; nop; break.i	0x80000 }
	{ Invalid; (p34) nop; (p32) nop }

l40000000000F1130:
	{ ld8	r14,[r34]; nop.m	0x0; adds	r36,0x1,r36; }
	{ ld8	r66,[r14]; nop.i	0x0; br.call.sptk.many	b0,sh_notfound; }
	{ ld8	r35,[r35]; nop.m	0x0; adds	r1,0x0,r64; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	40000000000F0B40 }

l40000000000F1170:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000F0BA0 }

l40000000000F1180:
	{ nop.m	0x0; sxt4	r14,r8; nop.i	0x0; }
	{ adds	r15,0xFFFFFFFFFFFFFFFF,r14; nop.m	0x0; add	r16,r36,r14; }
	{ add	r15,r36,r15; st1	[r0],r16; nop.i	0x0; }
	{ ld1	r16,[r15]; nop.m	0x0; sxt1	r16,r16; }
	{ cmp4.eq	p07,p06,0x2B,r16; (p07) addl	r48,1,r0; nop.i	0x0 }

l40000000000F11CC:
	{ Invalid; Invalid; mov	pr,r32,0x0 }

l40000000000F11D6:
	{ chk.a.nc	f0,3FFFFFFFFF0F19D6; nop; nop }

l40000000000F11E0:
	{ adds	r48,0x0,r0; nop.m	0x0; nop.i	0x0 }

l40000000000F11F0:
	{ add	r51,r36,r14,0x1; nop.m	0x0; addl	r67,91,r0 }
	{ adds	r66,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B680; }
	{ cmp.eq	p07,p06,0x0,r8; adds	r37,0x0,r8; adds	r1,0x0,r64; }
	{ (p07) adds	r39,0x0,r0; (p07) adds	r42,0x0,r0; (p07) br.cond.dpnt.few	40000000000F0F50; }

l40000000000F1226:
	{ (p21) chk.a.clr	f0,3FFFFFFFFF171226; nop; break.i	0x80000; }

l40000000000F122C:
	{ (p41) nop; break.i	0x1000; br.cond.sptk.few	40000000003212BC }

l40000000000F1230:
	{ nop.m	0x0; st1	[r0],r37; adds	r42,0x0,r37 }
	{ nop.m	0x0; addl	r39,1,r0; br.cond.sptk.few	40000000000F0F50 }

l40000000000F1250:
	{ nop.m	0x0; nop.i	0x0; (p18) br.cond.dptk.few	40000000000F0FE0 }

l40000000000F1260:
	{ nop.m	0x0; nop.i	0x0; (p06) br.cond.dptk.few	40000000000F1000 }

l40000000000F1270:
	{ and	r14,0x4,r37; nop.m	0x0; tbit.z	p06,p07,r37,0x6 }
	{ adds	r66,0x0,r36; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000F15F0; }

l40000000000F1290:
	{ nop.m	0x0; or	r14,r39,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000F15B0 }

l40000000000F12B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,make_local_array_variable; }
	{ adds	r50,0x0,r8; nop.m	0x0; adds	r1,0x0,r64; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r50; (p07) br.cond.dpnt.few	40000000000F18C0 }

l40000000000F12E0:
	{ nop.m	0x0; adds	r49,0x28,r50; nop.i	0x0; }
	{ ld4	r41,[r49]; nop.m	0x0; nop.i	0x0; }

l40000000000F1300:
	{ nop.m	0x0; tbit.z	p06,p07,r41,0x1; (p06) br.cond.dptk.few	40000000000F1330 }

l40000000000F1310:
	{ adds	r15,0x10,r12; ld4	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p08,p09,r14,0x1; (p09) br.cond.dpnt.few	40000000000F1740 }

l40000000000F1330:
	{ ld8	r47,[r49]; and	r15,r52,r47; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p08,p09,0x0,r15; (p08) br.cond.dptk.few	40000000000F19D0 }

l40000000000F1350:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dptk.few	40000000000F19D0 }

l40000000000F1360:
	{ adds	r66,0x0,r36; (p07) br.cond.dpnt.few	40000000000F1760; br.call.sptk.many	b0,fn400000000001A7E0; }

l40000000000F136C:
	{ (p36) addp4	r82,r60,r44; (p21) invala; nop }
	{ ldfp8	f64,f0,[r66]; Invalid; break.i	0x1000 }
	{ invala; cmp.eq	p00,p00,r32,r0; mov	pr,r72,0xE4C0 }

l40000000000F1390:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	40000000000F0E40 }

l40000000000F13A0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000F10D0; }

l40000000000F13B0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r16; (p06) br.cond.dptk.few	40000000000F1080 }

l40000000000F13C0:
	{ nop.m	0x0; nop.i	0x0; (p22) br.cond.dptk.few	40000000000F16F0 }

l40000000000F13D0:
	{ ld4	r14,[r61]; ld8	r66,[r38]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000F1900; }

l40000000000F13F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B380; }
	{ adds	r1,0x0,r64; adds	r66,0x0,r46; br.call.sptk.many	b0,sh_chkwrite; }
	{ nop.m	0x0; adds	r1,0x0,r64; adds	r46,0x0,r8 }

l40000000000F1420:
	{ adds	r66,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r64; nop.i	0x0 }
	{ ld8	r35,[r35]; nop.m	0x0; br.cond.sptk.few	40000000000F10C0; }

l40000000000F1450:
	{ addl	r67,-8356,r1; nop.m	0x0; addl	r68,5,r0 }
	{ adds	r66,0x0,r0; nop.m	0x0; adds	r46,0x1,r46; }
	{ ld8	r67,[r67]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ nop.m	0x0; adds	r1,0x0,r64; adds	r66,0x0,r8 }
	{ nop.m	0x0; adds	r67,0x0,r36; br.call.sptk.many	b0,builtin_error; }

l40000000000F14A0:
	{ adds	r1,0x0,r64; nop.m	0x0; nop.i	0x0 }

l40000000000F14B0:
	{ adds	r66,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r64; nop.i	0x0 }
	{ ld8	r35,[r35]; nop.m	0x0; br.cond.sptk.few	40000000000F10C0 }

l40000000000F14E0:
	{ adds	r66,0x0,r36; adds	r44,0x1,r44; br.call.sptk.many	b0,sh_invalidid; }
	{ nop.m	0x0; adds	r1,0x0,r64; br.cond.sptk.few	40000000000F14B0 }

l40000000000F1500:
	{ adds	r66,0x0,r36; nop.i	0x0; (p21) br.call.dptk.many	b0,find_global_variable; }

l40000000000F1510:
	{ nop.m	0x0; nop.i	0x0; (p20) br.call.dptk.many	b0,find_variable; }

l40000000000F1520:
	{ adds	r1,0x0,r64; cmp.eq	p06,p07,0x0,r8; nop.i	0x0 }
	{ adds	r50,0x0,r8; adds	r66,0x0,r36; (p07) br.cond.spnt.few	40000000000F12E0; }

l40000000000F1540:
	{ and	r14,0x4,r37; tbit.z	p06,p07,r37,0x6; (p07) br.cond.dpnt.few	40000000000F21F0; }

l40000000000F1550:
	{ nop.m	0x0; or	r14,r39,r14; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000F2250; (p16) br.cond.dptk.few	40000000000F17A0 }

l40000000000F156C:
	{ (p18) ldfp8	f0,f0,[r33]; Invalid; add	r0,r32,r0 }

l40000000000F1570:
	{ addl	r67,-8380,r1; nop.m	0x0; adds	r68,0x0,r0; }
	{ ld8	r67,[r67]; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r50,0x0,r8; adds	r1,0x0,r64; adds	r49,0x28,r50; }
	{ ld4	r41,[r49]; nop.i	0x0; br.cond.sptk.few	40000000000F1300 }

l40000000000F15B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,make_local_variable; }
	{ adds	r50,0x0,r8; nop.m	0x0; adds	r1,0x0,r64; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r50; (p06) br.cond.dptk.few	40000000000F12E0 }

l40000000000F15E0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000F18C0 }

l40000000000F15F0:
	{ adds	r66,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,make_local_assoc_variable; }
	{ adds	r50,0x0,r8; nop.m	0x0; adds	r1,0x0,r64; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r50; (p06) br.cond.dptk.few	40000000000F12E0 }

l40000000000F1620:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000F18C0; }

l40000000000F1630:
	{ cmp4.eq	p06,p07,0x0,r33; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000F17F0; }

l40000000000F1640:
	{ ld4	r67,[r34]; cmp4.eq	p06,p07,0x0,r39; (p06) br.cond.dptk.few	40000000000F2280; }

l40000000000F1650:
	{ nop.m	0x0; and	r14,0xFFFFFFFFFFFFFFF7,r67; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000F1990 }

l40000000000F1670:
	{ nop.m	0x0; adds	r66,0x0,r0; adds	r68,0x0,r37 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,set_or_show_attributes; }
	{ adds	r1,0x0,r64; nop.m	0x0; nop.i	0x0 }

l40000000000F16A0:
	{ nop.m	0x0; adds	r66,0x0,r0; br.call.sptk.many	b0,sh_chkwrite; }
	{ adds	r1,0x0,r64; nop.m	0x0; nop.i	0x0 }

l40000000000F16C0:
	{ nop.m	0x0; mov	pr,r65,0xFFFFFFFFFFFFFFFE; nop.i	0x0; }
	{ nop.m	0x0; mov.i	ar.pfs,r63; mov.spnt	b0,r62,40000000000F16D0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000F16F0:
	{ adds	r38,0x8,r38; addl	r68,3,r0; adds	r66,0x0,r36; }
	{ ld8	r67,[r38]; nop.i	0x0; br.call.sptk.many	b0,named_function_string; }
	{ adds	r1,0x0,r64; adds	r66,0x0,r8; br.call.sptk.many	b0,fn400000000001B380; }
	{ adds	r1,0x0,r64; adds	r66,0x0,r46; br.call.sptk.many	b0,sh_chkwrite; }
	{ adds	r1,0x0,r64; adds	r46,0x0,r8; br.cond.sptk.few	40000000000F1420; }

l40000000000F1740:
	{ adds	r66,0x0,r36; adds	r46,0x1,r46; br.call.sptk.many	b0,sh_readonly; }
	{ nop.m	0x0; adds	r1,0x0,r64; br.cond.sptk.few	40000000000F14B0 }

l40000000000F1760:
	{ adds	r66,0x0,r36; adds	r44,0x1,r44; br.call.sptk.many	b0,sh_readonly; }
	{ adds	r1,0x0,r64; adds	r66,0x0,r36; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r64; nop.i	0x0 }
	{ ld8	r35,[r35]; nop.m	0x0; br.cond.sptk.few	40000000000F1390 }

l40000000000F17A0:
	{ adds	r67,0x0,r0; adds	r68,0x0,r0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r49,0x28,r8; adds	r1,0x0,r64; adds	r50,0x0,r8; }
	{ nop.m	0x0; ld4	r14,[r49]; nop.i	0x0; }
	{ or	r14,r58,r14; nop.i	0x0; adds	r41,0x0,r14 }
	{ nop.m	0x0; st4	[r14],r49; br.cond.sptk.few	40000000000F1300 }

l40000000000F17F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,all_local_variables; }
	{ adds	r1,0x0,r64; nop.m	0x0; cmp.eq	p06,p07,0x0,r8 }
	{ adds	r35,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000F16A0; }

l40000000000F1820:
	{ nop.m	0x0; ld8	r66,[r8]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r66; (p07) br.cond.dpnt.few	40000000000F1890; }

l40000000000F1840:
	{ (p06) adds	r34,0x8,r8; nop.m	0x0; nop.i	0x0; }

l40000000000F1846:
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ break.m	0x4000; nop; break.i	0x80000 }

l40000000000F1860:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,print_assignment; }

l40000000000F1862:
	{ break.m	0x20; cmp.ltu	p32,p00,r0,r0; (p04) nop }
	{ (p33) break.m	0x28308; zxt1	r32,r0; Invalid }
	{ Invalid; (p32) cmp.lt.unc	p16,p01,r65,r92; (p63) nop }

l40000000000F1890:
	{ adds	r66,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r64; adds	r66,0x0,r0; br.call.sptk.many	b0,sh_chkwrite; }
	{ nop.m	0x0; adds	r1,0x0,r64; br.cond.sptk.few	40000000000F16C0 }

l40000000000F18C0:
	{ adds	r66,0x0,r36; adds	r46,0x1,r46; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ ld8	r35,[r35]; nop.m	0x0; adds	r1,0x0,r64; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	40000000000F0E40 }

l40000000000F18F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000F10D0 }

l40000000000F1900:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,find_function_def; }
	{ adds	r1,0x0,r64; cmp.eq	p06,p07,0x0,r8; adds	r14,0x4,r8 }
	{ adds	r8,0x18,r8; addl	r66,1,r0; (p06) br.cond.dpnt.few	40000000000F2380; }

l40000000000F1930:
	{ addl	r67,-8348,r1; ld8	r68,[r38]; nop.i	0x0 }
	{ ld4	r69,[r14]; ld8	r67,[r67]; nop.i	0x0 }
	{ ld8	r70,[r8]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r64; adds	r66,0x0,r36; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r64; nop.i	0x0 }
	{ ld8	r35,[r35]; nop.m	0x0; br.cond.sptk.few	40000000000F10C0 }

l40000000000F1990:
	{ cmp4.eq	p06,p07,0x0,r67; adds	r67,0x0,r37; (p06) addl	r66,1,r0; }

l40000000000F19A0:
	{ (p07) adds	r66,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,show_all_var_attributes; }

l40000000000F19A6:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; (p32) nop; break.i	0x80000 }
	{ Invalid; nop; break.b	0x80000 }

l40000000000F19D0:
	{ nop.m	0x0; cmp4.eq	p25,p24,0x0,r39; (p24) br.cond.dptk.few	40000000000F1A20 }

l40000000000F19E0:
	{ nop.m	0x0; and	r14,0x44,r37; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000F1A20 }

l40000000000F1A00:
	{ nop.m	0x0; and	r14,0x44,r47; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000F1D70; }

l40000000000F1A20:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dptk.few	40000000000F1D70; }

l40000000000F1A30:
	{ cmp.eq	p07,p06,0x0,r51; (p07) ld1	r14,[r51]; (p07) adds	r8,0x0,r0; }

l40000000000F1A3C:
	{ Invalid; nop; (p05) mov	pr,r3,0x80; }

l40000000000F1A40:
	{ nop.m	0x0; sxt1	r45,r14; (p07) br.cond.dpnt.few	40000000000F1B00; }

l40000000000F1A50:
	{ ld1	r45,[r51]; nop.m	0x0; sxt1	r45,r45; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r45; (p06) br.cond.dptk.few	40000000000F1FE0 }

l40000000000F1A70:
	{ adds	r14,0x1,r51; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r8,1,r0; (p06) br.cond.dptk.few	40000000000F1B00 }

l40000000000F1A9C:
	{ (p03) cmp.lt	p00,p11,r0,r33; (p33) cmp.lt.unc	p32,p16,r12,r64; (p01) rfi }

l40000000000F1AA0:
	{ adds	r14,0x2,r51; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r8,2,r0; (p06) br.cond.dptk.few	40000000000F1B00 }

l40000000000F1ACC:
	{ Invalid; dep	r0,r32,r0,63,1; zxt1	r96,r64 }

l40000000000F1AD0:
	{ nop.m	0x0; adds	r66,0x0,r51; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r64; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000F1B00:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x28,r45; (p06) br.cond.dptk.few	40000000000F1FE0 }

l40000000000F1B10:
	{ nop.m	0x0; sxt4	r14,r8; add	r14,r51,r14; }
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r14; ld1	r53,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r53,r53; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x29,r53; (p06) adds	r54,0x0,r0; (p06) addl	r53,1,r0; }

l40000000000F1B4C:
	{ nop; Invalid; Invalid }

l40000000000F1B50:
	{ nop.m	0x0; (p07) addl	r54,1,r0; (p07) adds	r53,0x0,r0; }

l40000000000F1B5C:
	{ Invalid; Invalid; Invalid }

l40000000000F1B60:
	{ adds	r17,0x10,r12; ld4	r45,[r17]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r45,0x2; (p06) br.cond.dptk.few	40000000000F1B90; }

l40000000000F1B80:
	{ nop.m	0x0; tbit.z	p07,p06,r41,0x2; (p06) br.cond.dptk.few	40000000000F1D80; }

l40000000000F1B90:
	{ nop.m	0x0; tbit.z	p06,p07,r45,0x6; (p06) br.cond.dptk.few	40000000000F1BB0; }

l40000000000F1BA0:
	{ nop.m	0x0; tbit.z	p06,p07,r41,0x6; (p07) br.cond.dptk.few	40000000000F1D80; }

l40000000000F1BB0:
	{ nop.m	0x0; tbit.z	p06,p07,r37,0x2; (p06) br.cond.dptk.few	40000000000F1BD0 }

l40000000000F1BC0:
	{ nop.m	0x0; tbit.z	p08,p09,r41,0x6; (p09) br.cond.dpnt.few	40000000000F1DE0; }

l40000000000F1BD0:
	{ nop.m	0x0; tbit.z	p08,p09,r37,0x6; (p09) br.cond.dptk.few	40000000000F1FF0 }

l40000000000F1BE0:
	{ nop.m	0x0; nop.i	0x0; (p24) br.cond.dptk.few	40000000000F1F90 }

l40000000000F1BF0:
	{ nop.m	0x0; nop.i	0x0; (p07) br.cond.dptk.few	40000000000F1F90; }

l40000000000F1C00:
	{ cmp4.eq	p07,p06,0x0,r38; andcm	r45,0xFFFFFFFFFFFFFFFF,r45; or	r41,r37,r41; }
	{ (p06) addl	r38,1,r0; and	r41,r45,r41; (p07) adds	r38,0x0,r0 }

l40000000000F1C16:
	{ (p20) chk.a.clr	f45,3FFFFFFFFF0F7EA6; (p19) nop; br.call.spnt.few	b0,b2 }

l40000000000F1C20:
	{ st4	[r41],r49; and	r54,r54,r38; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r54; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000F2040; }

l40000000000F1C40:
	{ cmp.eq	p07,p06,0x0,r42; (p06) addl	r14,1,r0; nop.i	0x0; }

l40000000000F1C4C:
	{ cmp4.eq.and	p00,p43,r1,r0; (p01) cmp.lt	p00,p16,r0,r64; zxt1	r77,r3 }

l40000000000F1C56:
	{ Invalid; nop; (p32) nop }
	{ chk.a.nc	f0,3FFFFFFFFF0F2466; nop; break.i	0x80000 }

l40000000000F1C70:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r53; (p06) br.cond.dptk.few	40000000000F2070; }

l40000000000F1C80:
	{ nop.m	0x0; tbit.z	p06,p07,r41,0x6; (p06) br.cond.dptk.few	40000000000F2220 }

l40000000000F1C90:
	{ addl	r66,2,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r14,0x0,r8; adds	r1,0x0,r64; adds	r68,0x0,r8 }
	{ adds	r66,0x0,r50; adds	r67,0x0,r36; adds	r69,0x0,r51; }
	{ st1	[r14],r1,1; adds	r70,0x0,r48; nop.i	0x0 }
	{ st1	[r0],r14; nop.m	0x0; br.call.sptk.many	b0,bind_assoc_variable; }
	{ adds	r1,0x0,r64; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000F1D00:
	{ nop.m	0x0; and	r14,0x3,r37; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000F1D50 }

l40000000000F1D20:
	{ adds	r49,0x28,r50; ld4	r14,[r49]; nop.i	0x0; }
	{ nop.m	0x0; and	r14,r55,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000F1E40 }

l40000000000F1D50:
	{ nop.m	0x0; adds	r66,0x0,r36; br.call.sptk.many	b0,stupidly_hack_special_variables }

l40000000000F1D60:
	{ nop.m	0x0; adds	r1,0x0,r64; br.cond.sptk.few	40000000000F14B0 }

l40000000000F1D70:
	{ adds	r53,0x0,r0; adds	r54,0x0,r0; br.cond.sptk.few	40000000000F1B60; }

l40000000000F1D80:
	{ addl	r67,-8340,r1; nop.m	0x0; addl	r68,5,r0 }
	{ adds	r66,0x0,r0; nop.m	0x0; adds	r46,0x1,r46; }
	{ ld8	r67,[r67]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r64; nop.m	0x0; adds	r66,0x0,r8 }
	{ adds	r67,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,builtin_error; }
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000F14A0 }

l40000000000F1DE0:
	{ addl	r67,-8332,r1; nop.m	0x0; addl	r68,5,r0 }
	{ adds	r66,0x0,r0; nop.m	0x0; adds	r46,0x1,r46; }
	{ ld8	r67,[r67]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r64; nop.m	0x0; adds	r66,0x0,r8 }
	{ adds	r67,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,builtin_error; }
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000F14A0 }

l40000000000F1E40:
	{ ld8	r66,[r50]; adds	r37,0x8,r50; br.call.sptk.many	b0,find_tempenv_variable; }
	{ adds	r1,0x0,r64; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	40000000000F1F60; }

l40000000000F1E60:
	{ nop.m	0x0; ld8	r66,[r37]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r66; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F22D0; }

l40000000000F1E80:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r64; adds	r66,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r67,[r37]; nop.m	0x0; adds	r1,0x0,r64 }
	{ adds	r66,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r37,0x0,r8; nop.m	0x0; adds	r1,0x0,r64 }
	{ ld8	r66,[r50]; nop.m	0x0; adds	r68,0x0,r0; }
	{ adds	r67,0x0,r37; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ nop.m	0x0; ld4	r16,[r49]; adds	r14,0x28,r8 }
	{ adds	r8,0x2C,r8; adds	r1,0x0,r64; adds	r66,0x0,r37; }
	{ nop.m	0x0; ld4	r15,[r14]; and	r16,r60,r16 }
	{ ld4	r17,[r8]; or	r15,r15,r16; cmp4.lt	p07,p06,0x0,r17; }
	{ st4	[r15],r14; (p07) or	r15,r57,r15; nop.i	0x0 }

l40000000000F1F3C:
	{ Invalid; Invalid; break.i	0x1000 }

l40000000000F1F46:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; Invalid; (p32) nop }

l40000000000F1F60:
	{ ld4	r14,[r49]; adds	r66,0x0,r36; or	r14,r57,r14; }
	{ st4	[r14],r49; nop.i	0x0; br.call.sptk.many	b0,stupidly_hack_special_variables; }
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000F1D60 }

l40000000000F1F90:
	{ nop.m	0x0; and	r47,0x44,r47; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r47; (p06) br.cond.dptk.few	40000000000F1C00 }

l40000000000F1FB0:
	{ adds	r66,0x0,r50; nop.i	0x0; br.call.sptk.many	b0,convert_var_to_array; }
	{ adds	r49,0x28,r8; adds	r1,0x0,r64; adds	r50,0x0,r8; }
	{ ld4	r41,[r49]; nop.i	0x0; br.cond.sptk.few	40000000000F1C00 }

l40000000000F1FE0:
	{ addl	r53,1,r0; adds	r54,0x0,r0; br.cond.sptk.few	40000000000F1B60; }

l40000000000F1FF0:
	{ nop.m	0x0; tbit.z	p06,p07,r41,0x2; (p07) br.cond.dpnt.few	40000000000F2120; }

l40000000000F2000:
	{ nop.m	0x0; tbit.z	p07,p06,r41,0x6; (p06) br.cond.dptk.few	40000000000F1C00 }

l40000000000F2010:
	{ adds	r66,0x0,r50; nop.i	0x0; br.call.sptk.many	b0,convert_var_to_assoc; }
	{ adds	r49,0x28,r8; adds	r1,0x0,r64; adds	r50,0x0,r8; }
	{ ld4	r41,[r49]; nop.i	0x0; br.cond.sptk.few	40000000000F1C00 }

l40000000000F2040:
	{ adds	r66,0x0,r50; nop.m	0x0; adds	r67,0x0,r51 }
	{ adds	r68,0x0,r48; nop.m	0x0; br.call.sptk.many	b0,assign_array_var_from_string; }
	{ nop.m	0x0; adds	r1,0x0,r64; br.cond.sptk.few	40000000000F1D00 }

l40000000000F2070:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r38; (p06) br.cond.dptk.few	40000000000F1D00 }

l40000000000F2080:
	{ adds	r66,0x0,r50; nop.m	0x0; adds	r67,0x0,r51 }
	{ adds	r68,0x0,r48; nop.m	0x0; br.call.sptk.many	b0,bind_variable_value; }
	{ nop.m	0x0; adds	r1,0x0,r64; br.cond.sptk.few	40000000000F1D00 }

l40000000000F20B0:
	{ nop.m	0x0; st1	[r56],r42; adds	r66,0x0,r36 }
	{ adds	r67,0x0,r51; adds	r68,0x0,r0; br.call.sptk.many	b0,assign_array_element; }
	{ adds	r1,0x0,r64; nop.m	0x0; adds	r50,0x0,r8 }
	{ st1	[r0],r42; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000000F1D00 }

l40000000000F20F0:
	{ adds	r66,0x0,r36; adds	r44,0x1,r44; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r64; nop.i	0x0 }
	{ ld8	r35,[r35]; nop.m	0x0; br.cond.sptk.few	40000000000F1390; }

l40000000000F2120:
	{ addl	r67,-8324,r1; nop.m	0x0; addl	r68,5,r0 }
	{ adds	r66,0x0,r0; nop.m	0x0; adds	r46,0x1,r46; }
	{ ld8	r67,[r67]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r64; nop.m	0x0; adds	r66,0x0,r8 }
	{ adds	r67,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,builtin_error; }
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000F14A0 }

l40000000000F2180:
	{ addl	r67,-8364,r1; addl	r68,5,r0; adds	r66,0x0,r0; }
	{ ld8	r67,[r67]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r64; adds	r66,0x0,r8; br.call.sptk.many	b0,builtin_error; }
	{ adds	r1,0x0,r64; adds	r66,0x0,r36; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ addl	r8,1,r0; adds	r1,0x0,r64; mov	pr,r65,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r63; mov.spnt	b0,r62,40000000000F21D0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000000F21F0:
	{ adds	r66,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,make_new_assoc_variable; }
	{ adds	r49,0x28,r8; adds	r1,0x0,r64; adds	r50,0x0,r8; }
	{ ld4	r41,[r49]; nop.i	0x0; br.cond.sptk.few	40000000000F1300 }

l40000000000F2220:
	{ adds	r66,0x0,r36; adds	r67,0x0,r0; nop.i	0x0 }
	{ adds	r68,0x0,r51; adds	r69,0x0,r48; br.call.sptk.many	b0,bind_array_variable; }
	{ nop.m	0x0; adds	r1,0x0,r64; br.cond.sptk.few	40000000000F1D00 }

l40000000000F2250:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,make_new_array_variable; }
	{ adds	r49,0x28,r8; adds	r1,0x0,r64; adds	r50,0x0,r8; }
	{ ld4	r41,[r49]; nop.i	0x0; br.cond.sptk.few	40000000000F1300 }

l40000000000F2280:
	{ cmp4.eq	p07,p06,0x0,r67; adds	r66,0x0,r0; (p06) br.cond.dpnt.few	40000000000F1670; }

l40000000000F2290:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,set_builtin; }
	{ adds	r1,0x0,r64; mov	pr,r65,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r63; }
	{ nop.m	0x0; mov.spnt	b0,r62,40000000000F22B0; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0; }

l40000000000F22D0:
	{ addl	r66,1,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r37,0x0,r8; nop.m	0x0; adds	r1,0x0,r64 }
	{ adds	r68,0x0,r0; st1	[r0],r8; nop.i	0x0; }
	{ ld8	r66,[r50]; adds	r67,0x0,r37; br.call.sptk.many	b0,bind_variable; }
	{ nop.m	0x0; ld4	r16,[r49]; adds	r14,0x28,r8 }
	{ adds	r8,0x2C,r8; adds	r1,0x0,r64; adds	r66,0x0,r37; }
	{ nop.m	0x0; ld4	r15,[r14]; and	r16,r60,r16 }
	{ ld4	r17,[r8]; or	r15,r15,r16; cmp4.lt	p07,p06,0x0,r17; }
	{ st4	[r15],r14; nop.m	0x0; (p07) or	r15,r57,r15; }

l40000000000F2360:
	{ (p07) st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }

l40000000000F2366:
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; nop; (p32) br.call.sptk.few	b0,b0 }

l40000000000F2380:
	{ ld8	r66,[r38]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B380; }
	{ adds	r1,0x0,r64; adds	r66,0x0,r36; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r64; nop.i	0x0 }
	{ ld8	r35,[r35]; nop.m	0x0; br.cond.sptk.few	40000000000F10C0; }

l40000000000F23C0:
	{ addl	r51,-8380,r1; nop.m	0x0; adds	r48,0x0,r0 }
	{ adds	r39,0x0,r0; nop.m	0x0; adds	r42,0x0,r0; }
	{ ld8	r51,[r51]; nop.i	0x0; br.cond.sptk.few	40000000000F0F50; }
40000000000F23F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; declare_builtin: 40000000000F2400
;;   Called from:
;;     40000000000A851C (in fn40000000000A7940)
;;     400000000010C29C (in set_or_show_attributes)
declare_builtin proc
	{ alloc	r16,ar.pfs,0x2,0x0,0x2; adds	r33,0x0,r0; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000F0900; }
40000000000F2420 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000F2430 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; local_builtin: 40000000000F2440
local_builtin proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; addl	r14,7148,r1; nop.b	0x0 }
	{ addl	r38,-8316,r1; mov	r34,b2; adds	r36,0x0,r1; }
	{ nop.m	0x0; addl	r39,5,r0; adds	r37,0x0,r0 }
	{ ld8	r38,[r38]; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000F24D0; }

l40000000000F2490:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; adds	r37,0x0,r8; br.call.sptk.many	b0,builtin_error; }
	{ addl	r8,1,r0; adds	r1,0x0,r36; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000F24C0; br.ret	b0; }

l40000000000F24D0:
	{ addl	r33,1,r0; mov.spnt	b0,r34,40000000000F24D0; mov.i	ar.pfs,r35; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000F0900; }
40000000000F24F0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; echo_builtin: 40000000000F2500
echo_builtin proc
	{ alloc	r42,ar.pfs,0x12,0x0,0xD; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r44,pr }
	{ addl	r14,6456,r1; addl	r15,8408,r1; adds	r43,0x0,r1; }
	{ nop.m	0x0; nop.m	0x0; mov	r41,b1 }
	{ ld4	r38,[r15]; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	40000000000F2560; }

l40000000000F2550:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r38; (p06) br.cond.dptk.few	40000000000F2BC0; }

l40000000000F2560:
	{ adds	r36,0x8,r32; cmp.eq	p06,p07,0x0,r32; nop.i	0x0 }
	{ addl	r39,1,r0; adds	r35,0x14,r12; (p06) br.cond.dpnt.few	40000000000F2A90; }

l40000000000F2580:
	{ ld8	r14,[r36]; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F2C40; }

l40000000000F25A0:
	{ ld1	r15,[r14]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2D,r15; (p07) br.cond.dpnt.few	40000000000F2740 }

l40000000000F25C0:
	{ adds	r40,0x1,r14; adds	r37,0x2,r14; addl	r33,1,r0 }
	{ st4	[r0],r35; ld1	r14,[r40]; adds	r34,0x0,r37; }
	{ nop.m	0x0; sxt1	r46,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r46; (p06) br.cond.dpnt.few	40000000000F2740; }

l40000000000F2600:
	{ nop.m	0x0; addl	r45,-2484,r1; nop.i	0x0; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B680; }
	{ adds	r1,0x0,r43; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	40000000000F2740; }

l40000000000F2630:
	{ st4	[r33],r35; nop.m	0x0; adds	r33,0x1,r33; }
	{ ld1	r46,[r34],1; nop.m	0x0; sxt1	r46,r46; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r46; (p06) br.cond.dptk.few	40000000000F2600 }

l40000000000F2660:
	{ ld1	r14,[r40]; adds	r15,0x0,r37; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F2740; }

l40000000000F2680:
	{ st4	[r14],r35; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000F26E0; }

l40000000000F2690:
	{ cmp4.eq	p06,p07,0x65,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F2BA0; }

l40000000000F26A0:
	{ cmp4.eq	p06,p07,0x6E,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F2B80; }

l40000000000F26B0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x45,r14; (p07) br.cond.dptk.few	40000000000F2740 }

l40000000000F26C0:
	{ ld1	r14,[r15],1; adds	r38,0x0,r0; sxt1	r14,r14; }

l40000000000F26D0:
	{ st4	[r14],r35; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000F2690 }

l40000000000F26E0:
	{ nop.m	0x0; ld8	r32,[r32]; nop.i	0x0; }
	{ adds	r36,0x8,r32; cmp.eq	p06,p07,0x0,r32; (p06) br.cond.dpnt.few	40000000000F2AA0; }

l40000000000F2700:
	{ ld8	r14,[r36]; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F2740; }

l40000000000F2720:
	{ ld1	r15,[r14]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2D,r15; (p06) br.cond.dptk.few	40000000000F25C0; }

l40000000000F2740:
	{ addl	r34,-10260,r1; addl	r37,7668,r1; cmp4.eq	p16,p17,0x0,r38; }
	{ ld8	r34,[r34]; nop.m	0x0; nop.i	0x0; }
	{ ld8	r45,[r34]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BE00; }
	{ ld4	r14,[r37]; adds	r1,0x0,r43; adds	r14,0x1,r14 }
	{ nop.m	0x0; st4	[r14],r37; nop.i	0x0 }

l40000000000F2790:
	{ adds	r14,0x10,r12; st4	[r0],r35; nop.i	0x0; }
	{ nop.m	0x0; st4	[r0],r14; nop.i	0x0 }
	{ ld8	r14,[r36]; nop.m	0x0; (p16) br.cond.dptk.few	40000000000F29D0; }

l40000000000F27C0:
	{ nop.m	0x0; ld8	r33,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r33; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F2A80; }

l40000000000F27E0:
	{ ld1	r14,[r33]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000F2A80 }

l40000000000F2800:
	{ adds	r14,0x1,r33; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r46,1,r0; (p06) br.cond.dptk.few	40000000000F2880 }

l40000000000F282C:
	{ (p03) cmp.lt	p00,p11,r0,r33; (p33) cmp.lt	p32,p16,r8,r64; Invalid }

l40000000000F2830:
	{ adds	r14,0x2,r33; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r46,2,r0; (p06) br.cond.dptk.few	40000000000F2880 }

l40000000000F285C:
	{ (p01) nop; zxt1	r32,r64; break.b	0x1000 }

l40000000000F2860:
	{ adds	r45,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; adds	r1,0x0,r43; adds	r46,0x0,r8; }

l40000000000F2880:
	{ adds	r45,0x0,r33; addl	r47,1,r0; nop.i	0x0 }
	{ adds	r48,0x0,r35; adds	r49,0x10,r12; br.call.sptk.many	b0,ansicstr; }
	{ adds	r15,0x10,r12; adds	r33,0x0,r8; adds	r1,0x0,r43 }
	{ cmp.eq	p07,p06,0x0,r8; adds	r36,0x0,r8; (p07) br.cond.dpnt.few	40000000000F2950; }

l40000000000F28C0:
	{ nop.m	0x0; ld4	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,0x0,r14; (p06) br.cond.dpnt.few	40000000000F2930; }

l40000000000F28E0:
	{ ld1	r14,[r33],1; ld8	r46,[r34]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r45,r14; br.call.sptk.many	b0,fn400000000001AEC0; }
	{ adds	r15,0x10,r12; nop.m	0x0; adds	r1,0x0,r43; }
	{ ld4	r14,[r15]; adds	r14,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; }
	{ st4	[r14],r15; cmp4.lt	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000F28E0 }

l40000000000F2930:
	{ nop.m	0x0; adds	r45,0x0,r36; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r43; nop.m	0x0; nop.i	0x0 }

l40000000000F2950:
	{ nop.m	0x0; ld4	r14,[r35]; addl	r45,32,r0 }
	{ nop.m	0x0; ld8	r32,[r32]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000F2A30; }

l40000000000F2980:
	{ cmp.eq	p06,p07,0x0,r32; adds	r36,0x8,r32; (p06) br.cond.dpnt.few	40000000000F2B00; }

l40000000000F2990:
	{ ld8	r46,[r34]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AEC0; }
	{ nop.m	0x0; adds	r14,0x10,r12; adds	r1,0x0,r43 }
	{ st4	[r0],r35; nop.i	0x0; nop.i	0x0 }
	{ st4	[r0],r14; ld8	r14,[r36]; (p17) br.cond.dptk.few	40000000000F27C0; }

l40000000000F29D0:
	{ ld8	r47,[r14]; addl	r46,-2476,r1; addl	r45,1,r0; }
	{ cmp.eq	p07,p06,0x0,r47; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000F2950; }

l40000000000F29F0:
	{ ld8	r46,[r46]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ ld4	r14,[r35]; nop.m	0x0; adds	r1,0x0,r43 }
	{ addl	r45,32,r0; ld8	r32,[r32]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000F2980 }

l40000000000F2A30:
	{ ld4	r14,[r37]; adds	r45,0x0,r0; adds	r14,0xFFFFFFFFFFFFFFFF,r14; }
	{ st4	[r14],r37; nop.i	0x0; br.call.sptk.many	b0,sh_chkwrite; }
	{ adds	r1,0x0,r43; mov	pr,r44,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r42; }
	{ nop.m	0x0; mov.spnt	b0,r41,40000000000F2A60; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l40000000000F2A80:
	{ nop.m	0x0; adds	r46,0x0,r0; br.cond.sptk.few	40000000000F2880 }

l40000000000F2A90:
	{ addl	r39,1,r0; nop.m	0x0; nop.i	0x0 }

l40000000000F2AA0:
	{ addl	r34,-10260,r1; nop.m	0x0; addl	r37,7668,r1; }
	{ ld8	r34,[r34]; nop.m	0x0; nop.i	0x0; }
	{ ld8	r45,[r34]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BE00; }
	{ ld4	r14,[r37]; adds	r1,0x0,r43; adds	r14,0x1,r14 }
	{ nop.m	0x0; st4	[r14],r37; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000F2B00:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r39; (p06) br.cond.dpnt.few	40000000000F2A30 }

l40000000000F2B10:
	{ ld8	r46,[r34]; addl	r45,10,r0; br.call.sptk.many	b0,fn400000000001AEC0; }
	{ ld4	r14,[r37]; adds	r1,0x0,r43; adds	r45,0x0,r0; }
	{ nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; }
	{ st4	[r14],r37; nop.i	0x0; br.call.sptk.many	b0,sh_chkwrite; }
	{ adds	r1,0x0,r43; mov	pr,r44,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r42; }
	{ nop.m	0x0; mov.spnt	b0,r41,40000000000F2B60; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l40000000000F2B80:
	{ ld1	r14,[r15],1; nop.m	0x0; adds	r39,0x0,r0; }
	{ nop.m	0x0; sxt1	r14,r14; br.cond.sptk.few	40000000000F26D0; }

l40000000000F2BA0:
	{ ld1	r14,[r15],1; nop.m	0x0; addl	r38,1,r0; }
	{ nop.m	0x0; sxt1	r14,r14; br.cond.sptk.few	40000000000F26D0 }

l40000000000F2BC0:
	{ addl	r34,-10260,r1; nop.m	0x0; addl	r37,7668,r1; }
	{ ld8	r34,[r34]; nop.m	0x0; nop.i	0x0; }
	{ ld8	r45,[r34]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BE00; }
	{ ld4	r14,[r37]; adds	r1,0x0,r43; cmp.eq	p07,p06,0x0,r32; }
	{ nop.m	0x0; adds	r14,0x1,r14; nop.i	0x0; }
	{ st4	[r14],r37; nop.i	0x0; (p07) br.cond.sptk.few	40000000000F2B10 }

l40000000000F2C20:
	{ addl	r39,1,r0; nop.m	0x0; adds	r36,0x8,r32 }
	{ adds	r35,0x14,r12; cmp.eq	p17,p16,r0,r0; br.cond.sptk.few	40000000000F2790; }

l40000000000F2C40:
	{ addl	r34,-10260,r1; addl	r37,7668,r1; nop.i	0x0 }
	{ addl	r39,1,r0; adds	r35,0x14,r12; cmp4.eq	p16,p17,0x0,r38; }
	{ ld8	r34,[r34]; nop.m	0x0; nop.i	0x0; }
	{ ld8	r45,[r34]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BE00; }
	{ ld4	r14,[r37]; adds	r1,0x0,r43; adds	r14,0x1,r14; }
	{ st4	[r14],r37; nop.i	0x0; br.cond.sptk.few	40000000000F2790; }
40000000000F2CA0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000F2CB0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; enable_builtin: 40000000000F2CC0
enable_builtin proc
	{ alloc	r49,ar.pfs,0x19,0x0,0x15; nop.m	0x0; mov	r52,LC }
	{ addl	r34,-9260,r1; adds	r50,0x0,r1; mov	r51,pr }
	{ ld8	r34,[r34]; nop.m	0x0; adds	r33,0x0,r0; }
	{ nop.m	0x0; mov	r48,b0; br.call.sptk.many	b0,reset_internal_getopt; }
	{ adds	r1,0x0,r50; nop.i	0x0; addl	r35,9252,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }
	{ addl	r54,-9316,r1; nop.m	0x0; adds	r53,0x0,r32; }
	{ ld8	r54,[r54]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r50; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dpnt.few	40000000000F2E20 }

l40000000000F2D50:
	{ nop.m	0x0; adds	r8,0xFFFFFFFFFFFFFF9F,r8; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x12,r8; (p07) br.cond.dptk.few	40000000000F2DB0 }

l40000000000F2D70:
	{ addl	r35,258,r0; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r50; mov	pr,r51,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r49; mov.i	LC,r52; }
	{ nop.m	0x0; mov.spnt	b0,r48,40000000000F2DA0; br.ret	b0 }

l40000000000F2DB0:
	{ addp4	r8,r8,r0; shladd	r8,r8,0x3,r34; nop.i	0x0; }
	{ ld8	r14,[r8]; add	r8,r8,r14; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r8,40000000000F2DD0; br.cond	b6; }
40000000000F2DE0 09 B0 71 FA B7 27 50 03 80 00 42 20 04 0A B9 80 ..q..'P...B ....
40000000000F2DF0 11 B0 01 6C 18 10 00 00 00 02 00 00 D8 76 02 50 ...l.........v.P
40000000000F2E00 11 08 00 64 00 21 70 F8 23 0C 77 03 50 FF FF 4A ...d.!p.#.w.P..J
40000000000F2E10 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

l40000000000F2E20:
	{ addl	r36,7352,r1; nop.m	0x0; addl	r15,9268,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4	r14,[r36]; ld8	r34,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000F2E80 }

l40000000000F2E60:
	{ nop.m	0x0; and	r14,0x6,r33; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000F38A0; }

l40000000000F2E80:
	{ cmp.eq	p06,p07,0x0,r34; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F3200; }

l40000000000F2E90:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x4; (p07) br.cond.dptk.few	40000000000F3200; }

l40000000000F2EA0:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x2; (p07) br.cond.dptk.few	40000000000F3570; }

l40000000000F2EB0:
	{ adds	r35,0x0,r0; tbit.z	p06,p07,r33,0x1; (p06) br.cond.dptk.few	40000000000F3C90 }

l40000000000F2EC0:
	{ addl	r37,6156,r1; addl	r42,-17532,r1; nop.i	0x0 }
	{ addl	r41,6164,r1; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000F2F00:
	{ adds	r14,0x8,r34; nop.m	0x0; addl	r54,1,r0; }
	{ ld8	r14,[r14]; ld8	r38,[r14]; nop.i	0x0; }
	{ adds	r53,0x0,r38; nop.i	0x0; br.call.sptk.many	b0,builtin_address_internal; }
	{ adds	r14,0x10,r8; adds	r1,0x0,r50; cmp.eq	p07,p06,0x0,r8 }
	{ adds	r33,0x0,r8; adds	r19,0x0,r0; (p07) br.cond.dpnt.few	40000000000F3F50; }

l40000000000F2F50:
	{ ld4	r14,[r14]; addl	r36,6164,r1; tbit.z	p06,p07,r14,0x2 }
	{ adds	r14,0x28,r8; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000F3C00; }

l40000000000F2F70:
	{ ld4	r18,[r37]; ld8	r53,[r14]; nop.i	0x0; }
	{ adds	r15,0xFFFFFFFFFFFFFFFF,r18; cmp4.lt	p07,p06,0x0,r18; (p06) br.cond.dpnt.few	40000000000F3EA0; }

l40000000000F2F90:
	{ addp4	r15,r15,r0; ld8	r20,[r41]; nop.i	0x0 }
	{ nop.m	0x0; adds	r17,0x58,r20; shladd	r15,r15,0x1,r15 }
	{ adds	r14,0x28,r20; nop.i	0x0; shladd	r17,r15,0x4,r17; }

l40000000000F2FC0:
	{ ld8	r15,[r14]; adds	r14,0x30,r14; cmp.eq	p07,p06,r15,r53; }
	{ (p07) adds	r19,0x1,r19; cmp.eq	p07,p06,r17,r14; (p06) br.cond.dptk.few	40000000000F2FC0; }

l40000000000F2FD6:
	{ (p03) chk.a.clr	r17,3FFFFFFFFFCF60B6; nop; nop }

l40000000000F2FE0:
	{ sub	r20,r33,r20; nop.m	0x0; cmp4.eq	p07,p06,0x1,r19 }
	{ shladd	r18,r18,0x1,r18; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000F3470; }

l40000000000F3000:
	{ nop.m	0x0; extr	r20,r20,4,60; shladd	r53,r18,0x4,r0; }
	{ shladd	r14,r20,0x2,r20; sxt4	r53,r53; shladd	r14,r14,0x4,r14; }
	{ nop.m	0x0; dep.z	r15,r14,8,56; add	r14,r14,r15; }
	{ nop.m	0x0; dep.z	r38,r14,16,48; add	r14,r14,r38; }
	{ shladd	r38,r14,0x1,r20; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ cmp4.eq	p06,p07,0x0,r38; nop.m	0x0; adds	r1,0x0,r50 }
	{ adds	r33,0x0,r8; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000F3520; }

l40000000000F3070:
	{ nop.m	0x0; (p06) adds	r40,0x0,r0; (p06) adds	r39,0x0,r0; }

l40000000000F307C:
	{ nop; (p17) nop }

l40000000000F3080:
	{ ld4	r16,[r37]; adds	r14,0x1,r39; add	r53,r33,r40 }
	{ ld8	r54,[r36]; sub	r38,r16,r38; shladd	r14,r14,0x1,r14; }
	{ nop.m	0x0; sxt4	r38,r38; shladd	r54,r14,0x4,r54; }
	{ nop.m	0x0; shladd	r55,r38,0x1,r38; nop.i	0x0; }
	{ shladd	r55,r55,0x4,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ ld8	r53,[r36]; nop.m	0x0; adds	r1,0x0,r50; }
	{ cmp.eq	p06,p07,r42,r53; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F3110; }

l40000000000F30F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r50; nop.m	0x0; nop.i	0x0 }

l40000000000F3110:
	{ ld4	r14,[r37]; st8	[r33],r36; nop.i	0x0 }
	{ ld8	r34,[r34]; adds	r14,0xFFFFFFFFFFFFFFFF,r14; cmp.eq	p07,p06,0x0,r34; }
	{ st4	[r14],r37; nop.i	0x0; (p06) br.cond.dptk.few	40000000000F2F00 }

l40000000000F3140:
	{ addl	r53,-18716,r1; nop.i	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,set_itemlist_dirty; }
	{ adds	r1,0x0,r50; nop.m	0x0; nop.i	0x0 }

l40000000000F3170:
	{ adds	r8,0x0,r35; nop.m	0x0; mov	pr,r51,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r49; mov.i	LC,r52; }
	{ nop.m	0x0; mov.spnt	b0,r48,40000000000F3190; br.ret	b0 }
40000000000F31A0 11 00 00 00 01 00 10 82 84 5C 40 00 80 FB FF 48 .........\@....H
40000000000F31B0 11 00 00 00 01 00 10 42 84 5C 40 00 70 FB FF 48 .......B.\@.p..H
40000000000F31C0 08 00 00 00 01 00 10 22 84 5C 40 00 00 00 04 00 .......".\@.....
40000000000F31D0 19 28 01 46 18 10 00 00 00 02 00 00 50 FB FF 48 .(.F........P..H
40000000000F31E0 11 00 00 00 01 00 10 12 84 5C 40 00 40 FB FF 48 .........\@.@..H
40000000000F31F0 11 00 00 00 01 00 10 0A 84 5C 40 00 30 FB FF 48 .........\@.0..H

l40000000000F3200:
	{ nop.m	0x0; tbit.z	p07,p06,r33,0x0; nop.i	0x0; }
	{ nop.m	0x0; (p06) addl	r14,3,r0; (p06) br.cond.dptk.few	40000000000F3240 }

l40000000000F321C:
	{ (p01) nop.m	0x84000; cmp.lt	p00,p00,r32,r0; (p32) nop }

l40000000000F3220:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x3; nop.i	0x0; }
	{ (p06) addl	r14,1,r0; nop.i	0x0; (p07) addl	r14,2,r0 }

l40000000000F3236:
	{ chk.a.nc	f0,3FFFFFFFFF0F3A36; (p07) nop; break.i	0x80000 }

l40000000000F3240:
	{ nop.m	0x0; addl	r35,6156,r1; tbit.z	p06,p07,r33,0x5 }
	{ addl	r36,6164,r1; adds	r34,0x0,r0; adds	r33,0x0,r0; }
	{ nop.m	0x0; (p07) or	r14,0x4,r14; tnat.z	p16,p17,r14; }

l40000000000F326C:
	{ (p02) cmp.eq	p14,p09,r17,r40; Invalid; dep	r0,r32,r0,63,1 }
	{ nop; cmp.lt	p00,p00,r32,r0; shladdp4	r96,r99,0x1,r97 }
	{ (p01) nop; break.i	0x1000; mov	pr,r32,0x0 }
	{ (p10) nop; break.i	0x1000; break.b	0x1000 }

l40000000000F32A0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000F32C0:
	{ ld8	r14,[r36]; add	r14,r14,r34; nop.i	0x0; }
	{ adds	r15,0x8,r14; ld8	r15,[r15]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r15; adds	r15,0x10,r14; (p06) br.cond.dpnt.few	40000000000F33C0; }

l40000000000F32F0:
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r15,0x1; (p06) br.cond.dptk.few	40000000000F33C0 }

l40000000000F3310:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dptk.few	40000000000F3330; }

l40000000000F3320:
	{ nop.m	0x0; tbit.z	p06,p07,r15,0x3; (p06) br.cond.dptk.few	40000000000F33C0 }

l40000000000F3330:
	{ nop.m	0x0; nop.i	0x0; (p18) br.cond.dptk.few	40000000000F3350; }

l40000000000F3340:
	{ nop.m	0x0; tbit.z	p06,p07,r15,0x0; (p07) br.cond.dpnt.few	40000000000F3410 }

l40000000000F3350:
	{ nop.m	0x0; nop.i	0x0; (p20) br.cond.dptk.few	40000000000F33C0; }

l40000000000F3360:
	{ nop.m	0x0; tbit.z	p07,p06,r15,0x0; (p06) br.cond.dptk.few	40000000000F33C0 }

l40000000000F3370:
	{ nop.m	0x0; addl	r54,-9300,r1; addl	r53,1,r0 }
	{ ld8	r55,[r14]; nop.i	0x0; nop.i	0x0 }
	{ ld8	r54,[r54]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r50; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000F33C0:
	{ adds	r33,0x1,r33; ld4	r14,[r35]; adds	r34,0x30,r34; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r33,r14; (p06) br.cond.dptk.few	40000000000F32C0; }

l40000000000F33E0:
	{ adds	r35,0x0,r0; nop.m	0x0; mov	pr,r51,0xFFFFFFFFFFFFFFFE; }
	{ adds	r8,0x0,r35; mov.i	ar.pfs,r49; mov.i	LC,r52; }
	{ nop.m	0x0; mov.spnt	b0,r48,40000000000F3400; br.ret	b0 }

l40000000000F3410:
	{ addl	r54,-9308,r1; ld8	r55,[r14]; nop.i	0x0 }
	{ addl	r53,1,r0; adds	r33,0x1,r33; adds	r34,0x30,r34; }
	{ ld8	r54,[r54]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ ld4	r14,[r35]; nop.m	0x0; adds	r1,0x0,r50; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r33,r14; (p06) br.cond.dptk.few	40000000000F32C0 }

l40000000000F3460:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000F33E0 }

l40000000000F3470:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AC60; }
	{ adds	r1,0x0,r50; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dpnt.few	40000000000F3F70; }

l40000000000F3490:
	{ ld8	r20,[r41]; ld4	r18,[r37]; nop.i	0x0; }
	{ sub	r20,r33,r20; nop.m	0x0; shladd	r18,r18,0x1,r18; }
	{ nop.m	0x0; extr	r20,r20,4,60; shladd	r53,r18,0x4,r0; }
	{ shladd	r14,r20,0x2,r20; sxt4	r53,r53; shladd	r14,r14,0x4,r14; }
	{ nop.m	0x0; dep.z	r15,r14,8,56; add	r14,r14,r15; }
	{ nop.m	0x0; dep.z	r38,r14,16,48; add	r14,r14,r38; }
	{ shladd	r38,r14,0x1,r20; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ cmp4.eq	p06,p07,0x0,r38; adds	r1,0x0,r50; adds	r33,0x0,r8; }
	{ (p06) adds	r40,0x0,r0; (p06) adds	r39,0x0,r0; (p06) br.cond.dptk.few	40000000000F3080; }

l40000000000F3516:
	{ (p19) chk.a.clr	r0,3FFFFFFFFF173516; Invalid; break.b	0x80000; }

l40000000000F351C:
	{ (p27) break.m	0x95FFF; cmp.eq	p00,p00,r32,r0; Invalid }

l40000000000F3520:
	{ nop.m	0x0; sxt4	r39,r38; adds	r53,0x0,r8 }
	{ ld8	r54,[r36]; shladd	r40,r39,0x1,r39; nop.i	0x0; }
	{ nop.m	0x0; shladd	r40,r40,0x4,r0; nop.i	0x0; }
	{ adds	r55,0x0,r40; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ nop.m	0x0; adds	r1,0x0,r50; br.cond.sptk.few	40000000000F3080 }

l40000000000F3570:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x3; adds	r53,0x0,r37 }
	{ nop.m	0x0; addl	r54,1,r0; nop.b	0x0; }
	{ (p07) addl	r35,2,r0; (p06) addl	r35,1,r0; tbit.z	p06,p07,r33,0x5; }

l40000000000F3596:
	{ Invalid; (p03) cmp4.eq	p10,p40,r33,r7; (p49) nop; }

l40000000000F359C:
	{ (p05) setf.s	f33,r7; zxt1	r97,r11; break.i	0x1000 }

l40000000000F35A6:
	{ break.m	0x4000; (p32) nop; (p48) nop }
	{ break.m	0x4000; (p19) nop; (p16) nop }
	{ chk.a.nc	f0,3FFFFFFFFF0F3DC6; nop; add	r0,r0,r32 }

l40000000000F35D0:
	{ nop.m	0x0; (p06) adds	r14,0x0,r34; (p06) adds	r15,0x0,r0; }

l40000000000F35DC:
	{ cmp.lt	p00,p09,r0,r66; Invalid; cmp.eq	p00,p00,r32,r0; }

l40000000000F35E0:
	{ ld8	r14,[r14]; nop.m	0x0; adds	r15,0x1,r15; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000F35E0 }

l40000000000F3600:
	{ adds	r46,0x0,r0; adds	r40,0x0,r0; sxt4	r53,r15 }
	{ addl	r45,95,r0; addl	r44,115,r0; addl	r39,116,r0; }
	{ shladd	r53,r53,0x3,r0; addl	r43,114,r0; tnat.z	p16,p17,r35 }
	{ addl	r42,117,r0; addl	r41,99,r0; br.call.sptk.many	b0,xmalloc; }
	{ nop.m	0x0; adds	r1,0x0,r50; adds	r47,0x0,r8; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000F3660:
	{ adds	r14,0x8,r34; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; ld8	r36,[r14]; nop.i	0x0; }
	{ adds	r53,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r53,0x8,r8; adds	r35,0x0,r8; adds	r1,0x0,r50; }
	{ nop.m	0x0; sxt4	r53,r53; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r50; adds	r33,0x0,r8; nop.i	0x0 }
	{ adds	r53,0x0,r8; adds	r54,0x0,r36; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; sxt4	r14,r35; nop.b	0x0 }
	{ adds	r54,0x0,r33; adds	r1,0x0,r50; adds	r53,0x0,r38; }
	{ add	r14,r33,r14; st1	[r14],r1,1; nop.i	0x0; }
	{ st1	[r14],r1,1; st1	[r14],r1,1; nop.i	0x0; }
	{ st1	[r14],r1,1; st1	[r14],r1,1; nop.i	0x0; }
	{ st1	[r14],r1,1; st1	[r14],r1,1; nop.i	0x0; }
	{ st1	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B820; }
	{ cmp.eq	p07,p06,0x0,r8; adds	r35,0x0,r8; nop.i	0x0 }
	{ adds	r1,0x0,r50; adds	r53,0x0,r33; (p07) br.cond.dpnt.few	40000000000F3B90; }

l40000000000F3760:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r14,0x10,r35; adds	r1,0x0,r50; adds	r53,0x0,r36 }
	{ addl	r54,1,r0; ld4	r15,[r14]; nop.i	0x0; }
	{ and	r15,0xFFFFFFFFFFFFFFFB,r15; st4	[r15],r14; (p17) or	r15,0x8,r15; }

l40000000000F37A0:
	{ (p17) st4	[r15],r14; nop.m	0x0; adds	r14,0x28,r35; }

l40000000000F37A6:
	{ break.m	0x4000; (p07) nop; nop }
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ Invalid; (p26) nop; (p32) nop.b	0x2300D }
	{ (p27) chk.a.clr	r48,3FFFFFFFFF2F37D6; nop; break.b	0x80000 }

l40000000000F37E0:
	{ nop.m	0x0; adds	r40,0x1,r40; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ adds	r1,0x0,r50; nop.m	0x0; nop.i	0x0 }

l40000000000F3800:
	{ nop.m	0x0; ld8	r34,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	40000000000F3660 }

l40000000000F3820:
	{ or	r40,r46,r40; adds	r53,0x0,r47; adds	r35,0x0,r0; }
	{ cmp4.eq	p07,p06,0x0,r40; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000F3FE0; }

l40000000000F3840:
	{ cmp4.eq	p06,p07,0x0,r46; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000F38E0; }

l40000000000F3850:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r50; nop.m	0x0; nop.i	0x0; }

l40000000000F3870:
	{ nop.m	0x0; addl	r53,-18716,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,set_itemlist_dirty; }
	{ nop.m	0x0; adds	r1,0x0,r50; br.cond.sptk.few	40000000000F3170 }

l40000000000F38A0:
	{ adds	r53,0x0,r0; addl	r35,1,r0; br.call.sptk.many	b0,sh_restricted; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r50; mov	pr,r51,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r49; mov.i	LC,r52; }
	{ nop.m	0x0; mov.spnt	b0,r48,40000000000F38D0; br.ret	b0 }

l40000000000F38E0:
	{ addl	r35,6156,r1; addl	r36,6164,r1; adds	r34,0x0,r47 }
	{ adds	r33,0x0,r0; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; ld4	r38,[r35]; nop.i	0x0; }
	{ add	r38,r46,r38; adds	r14,0x1,r38; nop.i	0x0; }
	{ shladd	r14,r14,0x1,r14; shladd	r53,r14,0x4,r0; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r53,r53; br.call.sptk.many	b0,xmalloc; }
	{ ld4	r15,[r35]; adds	r1,0x0,r50; adds	r37,0x0,r8 }
	{ adds	r53,0x0,r8; ld8	r54,[r36]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r14,r15; shladd	r55,r14,0x1,r14; }
	{ shladd	r55,r55,0x4,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r46; cmp4.lt	p07,p06,0x0,r46; adds	r1,0x0,r50; }
	{ addp4	r14,r14,r0; nop.m	0x0; mov.i	LC,r14; }
	{ nop.m	0x0; (p07) mov.i	LC,r14; (p06) mov.i	LC,0x0; }

l40000000000F39AC:
	{ nop; break.i	0x1000; break.i	0x1000 }

l40000000000F39B0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000F39C0:
	{ nop.m	0x0; ld4	r14,[r35]; addl	r55,48,r0 }
	{ ld8	r54,[r34],8; add	r14,r33,r14; adds	r33,0x1,r33; }
	{ nop.m	0x0; sxt4	r14,r14; shladd	r53,r14,0x1,r14; }
	{ shladd	r53,r53,0x4,r37; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ nop.m	0x0; adds	r1,0x0,r50; br.cloop.sptk.few	40000000000F39C0; }

l40000000000F3A10:
	{ nop.m	0x0; sxt4	r15,r38; addl	r14,-17532,r1 }
	{ ld8	r53,[r36]; shladd	r15,r15,0x1,r15; nop.i	0x0 }
	{ nop.m	0x0; shladd	r15,r15,0x4,r37; cmp.eq	p06,p07,r14,r53; }
	{ adds	r14,0x0,r15; nop.m	0x0; adds	r15,0x10,r15; }
	{ st8	[r14],r8,8; st4	[r0],r15; nop.i	0x0; }
	{ nop.m	0x0; st8	[r0],r14; nop.i	0x0 }
	{ nop.b	0x0; (p06) br.cond.dpnt.few	40000000000F3A90; br.call.sptk.many	b0,fn400000000001A7E0; }

l40000000000F3A7C:
	{ (p43) nop; invala; break.b	0x1000 }
	{ nop; Invalid; (p16) nop }

l40000000000F3A90:
	{ st4	[r38],r35; st8	[r37],r36; adds	r35,0x0,r0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,initialize_shell_builtins; }
	{ adds	r1,0x0,r50; adds	r53,0x0,r47; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r50; br.cond.sptk.few	40000000000F3870; }

l40000000000F3AD0:
	{ addl	r54,-9292,r1; nop.m	0x0; adds	r53,0x0,r0 }
	{ addl	r55,5,r0; nop.m	0x0; addl	r35,1,r0; }
	{ ld8	r54,[r54]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r50; adds	r33,0x0,r8; br.call.sptk.many	b0,fn400000000001AE00; }
	{ adds	r1,0x0,r50; adds	r53,0x0,r33; nop.i	0x0 }
	{ adds	r54,0x0,r37; adds	r55,0x0,r8; br.call.sptk.many	b0,builtin_error; }
	{ adds	r1,0x0,r50; addl	r53,-18716,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,set_itemlist_dirty; }
	{ nop.m	0x0; adds	r1,0x0,r50; br.cond.sptk.few	40000000000F3170 }

l40000000000F3B60:
	{ nop.m	0x0; sxt4	r14,r46; adds	r46,0x1,r46; }
	{ nop.m	0x0; shladd	r14,r14,0x3,r47; nop.i	0x0; }
	{ st8	[r35],r14; nop.i	0x0; br.cond.sptk.few	40000000000F3800 }

l40000000000F3B90:
	{ addl	r54,-9284,r1; adds	r53,0x0,r0; addl	r55,5,r0; }
	{ ld8	r54,[r54]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r50; adds	r35,0x0,r8; br.call.sptk.many	b0,fn400000000001AE00; }
	{ adds	r1,0x0,r50; adds	r53,0x0,r35; adds	r54,0x0,r33 }
	{ adds	r55,0x0,r37; adds	r56,0x0,r8; br.call.sptk.many	b0,builtin_error; }
	{ adds	r1,0x0,r50; adds	r53,0x0,r33; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r50; br.cond.sptk.few	40000000000F3800; }

l40000000000F3C00:
	{ addl	r54,-9276,r1; nop.m	0x0; addl	r55,5,r0 }
	{ adds	r53,0x0,r0; nop.m	0x0; addl	r35,1,r0; }
	{ ld8	r54,[r54]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r50; nop.m	0x0; adds	r53,0x0,r8 }
	{ adds	r54,0x0,r38; nop.m	0x0; br.call.sptk.many	b0,builtin_error; }
	{ adds	r1,0x0,r50; nop.m	0x0; nop.i	0x0 }

l40000000000F3C60:
	{ nop.m	0x0; ld8	r34,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	40000000000F2F00 }

l40000000000F3C80:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000F3140 }

l40000000000F3C90:
	{ nop.m	0x0; tnat.z	p16,p17,r33; nop.i	0x0; }

l40000000000F3CA0:
	{ adds	r37,0x8,r34; nop.m	0x0; addl	r54,1,r0; }
	{ nop.m	0x0; ld8	r14,[r37]; nop.i	0x0; }
	{ ld8	r53,[r14]; nop.i	0x0; br.call.sptk.many	b0,builtin_address_internal; }
	{ nop.m	0x0; adds	r1,0x0,r50; cmp.eq	p06,p07,0x0,r8 }
	{ nop.b	0x0; (p06) br.cond.dpnt.few	40000000000F3E50; (p16) br.cond.dptk.few	40000000000F3DB0; }

l40000000000F3CEC:
	{ (p06) nop; zxt1	r4,r64; Invalid }

l40000000000F3CF0:
	{ adds	r8,0x10,r8; nop.m	0x0; addl	r53,-18876,r1; }
	{ ld4	r14,[r8]; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; and	r14,0xFFFFFFFFFFFFFFFE,r14; nop.i	0x0; }
	{ st4	[r14],r8; nop.i	0x0; br.call.sptk.many	b0,set_itemlist_dirty; }
	{ adds	r1,0x0,r50; addl	r53,-18836,r1; nop.i	0x0; }
	{ nop.m	0x0; br.call.sptk.many	b0,set_itemlist_dirty; nop.b	0x0; }
	{ adds	r1,0x0,r50; nop.m	0x0; nop.i	0x0 }

l40000000000F3D60:
	{ nop.m	0x0; ld8	r34,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	40000000000F3CA0; }

l40000000000F3D80:
	{ adds	r8,0x0,r35; nop.m	0x0; mov	pr,r51,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r49; mov.i	LC,r52; }
	{ nop.m	0x0; mov.spnt	b0,r48,40000000000F3DA0; br.ret	b0 }

l40000000000F3DB0:
	{ ld4	r14,[r36]; adds	r8,0x10,r8; cmp4.eq	p06,p07,0x0,r14 }
	{ nop.m	0x0; ld4	r14,[r8]; (p06) br.cond.dptk.few	40000000000F3DE0; }

l40000000000F3DD0:
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x0; (p07) br.cond.dpnt.few	40000000000F3E30 }

l40000000000F3DE0:
	{ or	r14,0x1,r14; addl	r53,-18876,r1; nop.i	0x0 }
	{ st4	[r14],r8; nop.m	0x0; br.call.sptk.many	b0,set_itemlist_dirty; }
	{ adds	r1,0x0,r50; addl	r53,-18836,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,set_itemlist_dirty; }
	{ nop.m	0x0; adds	r1,0x0,r50; br.cond.sptk.few	40000000000F3D60 }

l40000000000F3E30:
	{ nop.m	0x0; adds	r53,0x0,r0; br.call.sptk.many	b0,sh_restricted; }
	{ adds	r1,0x0,r50; nop.m	0x0; nop.i	0x0 }

l40000000000F3E50:
	{ ld8	r14,[r37]; nop.m	0x0; addl	r35,1,r0; }
	{ ld8	r53,[r14]; nop.i	0x0; br.call.sptk.many	b0,sh_notbuiltin; }
	{ ld8	r34,[r34]; nop.m	0x0; adds	r1,0x0,r50; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	40000000000F3CA0 }

l40000000000F3E90:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000F3D80 }

l40000000000F3EA0:
	{ ld8	r20,[r41]; shladd	r18,r18,0x1,r18; addl	r36,6164,r1; }
	{ nop.m	0x0; sub	r20,r33,r20; shladd	r53,r18,0x4,r0 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; extr	r20,r20,4,60; sxt4	r53,r53; }
	{ shladd	r14,r20,0x2,r20; shladd	r14,r14,0x4,r14; nop.i	0x0; }
	{ nop.m	0x0; dep.z	r15,r14,8,56; add	r14,r14,r15; }
	{ nop.m	0x0; dep.z	r38,r14,16,48; add	r14,r14,r38; }
	{ shladd	r38,r14,0x1,r20; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ cmp4.eq	p06,p07,0x0,r38; adds	r1,0x0,r50; adds	r33,0x0,r8; }
	{ (p06) adds	r40,0x0,r0; (p06) adds	r39,0x0,r0; (p06) br.cond.dptk.few	40000000000F3080 }

l40000000000F3F36:
	{ (p19) chk.a.clr	r0,3FFFFFFFFF173F36; nop; break.b	0x80000; }

l40000000000F3F3C:
	{ (p10) invala; break.i	0x1000; break.b	0x1000 }

l40000000000F3F40:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000F3520 }

l40000000000F3F50:
	{ adds	r53,0x0,r38; addl	r35,1,r0; br.call.sptk.many	b0,sh_notbuiltin; }
	{ nop.m	0x0; adds	r1,0x0,r50; br.cond.sptk.few	40000000000F3C60; }

l40000000000F3F70:
	{ addl	r54,-9268,r1; nop.m	0x0; adds	r53,0x0,r0 }
	{ addl	r55,5,r0; nop.m	0x0; addl	r35,1,r0; }
	{ ld8	r54,[r54]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r50; adds	r33,0x0,r8; br.call.sptk.many	b0,fn400000000001AE00; }
	{ adds	r1,0x0,r50; adds	r53,0x0,r33; nop.i	0x0 }
	{ adds	r54,0x0,r38; adds	r55,0x0,r8; br.call.sptk.many	b0,builtin_error; }
	{ nop.m	0x0; adds	r1,0x0,r50; br.cond.sptk.few	40000000000F3C60 }

l40000000000F3FE0:
	{ adds	r53,0x0,r47; addl	r35,1,r0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r50; adds	r53,0x0,r38; br.call.sptk.many	b0,fn400000000001AC60; }
	{ adds	r1,0x0,r50; addl	r53,-18716,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,set_itemlist_dirty; }
	{ nop.m	0x0; adds	r1,0x0,r50; br.cond.sptk.few	40000000000F3170; }
40000000000F4030 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; eval_builtin: 40000000000F4040
eval_builtin proc
	{ alloc	r34,ar.pfs,0x7,0x0,0x4; adds	r35,0x0,r1; mov	r33,b1 }
	{ nop.m	0x0; adds	r36,0x0,r32; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,no_options; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r8; adds	r1,0x0,r35 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000F40C0; }

l40000000000F4090:
	{ (p06) addl	r8,258,r0; nop.m	0x0; nop.i	0x0 }

l40000000000F4096:
	{ break.m	0x4000; mov	pr,0x4000; break.i	0x80000 }

l40000000000F40A0:
	{ nop.m	0x0; mov.i	ar.pfs,r34; nop.i	0x0; }

l40000000000F40A2:
	{ ld1	r32,[r0]; (p04) break.i	0x550; Invalid }

l40000000000F40A6:
	{ break.m	0xAA022; nop; break.i	0x80000 }

l40000000000F40A8:
	{ (p40) break.m	0xA; (p16) break.i	0x10000; break.i	0x100008; }
	{ nop; break.x	0x18058042012240; }

l40000000000F40C0:
	{ addl	r14,9268,r1; nop.m	0x0; nop.i	0x0; }
	{ ld8	r14,[r14]; cmp.eq	p06,p07,0x0,r14; adds	r36,0x0,r14; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F40A0; }

l40000000000F40E6:
	{ chk.a.nc	r0,3FFFFFFFFF0F48E6; nop; break.i	0x80000 }

l40000000000F40F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,string_list; }
	{ adds	r1,0x0,r35; adds	r36,0x0,r8; addl	r38,4,r0; }
	{ nop.m	0x0; addl	r37,-4396,r1; nop.i	0x0; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,parse_and_execute; }
	{ adds	r1,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000F4140; br.ret	b0; }
40000000000F4150 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000F4160 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000F4170 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; fn40000000000F4180: 40000000000F4180
;;   Called from:
;;     40000000000F5C1C (in maybe_execute_file)
;;     40000000000F5C9C (in fc_execute_file)
;;     40000000000F5D5C (in source_file)
fn40000000000F4180 proc
	{ alloc	r43,ar.pfs,0x10,0x0,0xD; adds	r16,0x8,r12; nop.b	0x0 }
	{ adds	r12,0xFFFFFFFFFFFFFC10,r12; addl	r45,-1068,r1; mov	r44,pr; }
	{ adds	r14,0x378,r12; nop.m	0x0; mov	r42,b2 }
	{ st8.spill	[r1],r16; ld8	r45,[r45]; nop.i	0x0; }
	{ st8	[r32],r14; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x3F8,r12; nop.m	0x0; adds	r15,0x370,r12 }
	{ adds	r14,0x28,r8; cmp.eq	p06,p07,0x0,r8; nop.i	0x0 }
	{ ld8	r1,[r1]; st8	[r8],r15; (p06) br.cond.dpnt.few	40000000000F4780; }

l40000000000F4200:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x2; (p06) br.cond.dptk.few	40000000000F4780; }

l40000000000F4220:
	{ nop.m	0x0; (p07) adds	r14,0x8,r8; nop.i	0x0; }

l40000000000F422C:
	{ nop; Invalid; break.i	0x1000 }

l40000000000F4236:
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ Invalid; nop; (p16) br.call.sptk.few	b3,b0 }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; (p03) nop; (p16) nop }
	{ chk.a.nc	r0,3FFFFFFFFF0F4A76; nop; (p32) nop }

l40000000000F4280:
	{ adds	r14,0x28,r8; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x2; (p07) br.cond.dptk.few	40000000000F4AB0; }

l40000000000F42A0:
	{ nop.m	0x0; (p06) adds	r15,0x380,r12; nop.i	0x0; }

l40000000000F42AC:
	{ Invalid; Invalid; break.i	0x1000 }

l40000000000F42B6:
	{ break.m	0x4000; nop; break.i	0x80000 }

l40000000000F42C0:
	{ nop.m	0x0; addl	r45,-1052,r1; nop.i	0x0; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x3F8,r12; nop.m	0x0; cmp.eq	p06,p07,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F4800 }

l40000000000F4300:
	{ adds	r14,0x28,r8; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x2; (p07) br.cond.dptk.few	40000000000F4A80; }

l40000000000F4320:
	{ nop.m	0x0; (p06) adds	r14,0x388,r12; nop.i	0x0; }

l40000000000F432C:
	{ Invalid; Invalid; break.i	0x1000 }

l40000000000F4336:
	{ break.m	0x4000; nop; break.i	0x80000 }

l40000000000F4340:
	{ nop.m	0x0; addl	r45,-1044,r1; nop.i	0x0; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x3F8,r12; nop.m	0x0; cmp.eq	p06,p07,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F4840 }

l40000000000F4380:
	{ adds	r14,0x28,r8; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x2; (p07) br.cond.dptk.few	40000000000F4A50; }

l40000000000F43A0:
	{ nop.m	0x0; (p06) adds	r18,0x3A0,r12; nop.i	0x0; }

l40000000000F43AC:
	{ Invalid; Invalid; break.i	0x1000 }

l40000000000F43B6:
	{ break.m	0x4000; nop; break.i	0x80000 }

l40000000000F43C0:
	{ nop.m	0x0; addl	r45,-1036,r1; nop.i	0x0; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x3F8,r12; nop.m	0x0; cmp.eq	p06,p07,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F4880 }

l40000000000F4400:
	{ adds	r14,0x28,r8; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x2; (p07) br.cond.dptk.few	40000000000F4A20; }

l40000000000F4420:
	{ nop.m	0x0; (p06) adds	r16,0x3A8,r12; nop.i	0x0; }

l40000000000F442C:
	{ Invalid; Invalid; break.i	0x1000 }

l40000000000F4436:
	{ break.m	0x4000; nop; (p32) nop }

l40000000000F4440:
	{ adds	r18,0x378,r12; nop.m	0x0; adds	r46,0x0,r0; }
	{ ld8	r45,[r18]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B4E0; }
	{ adds	r1,0x3F8,r12; adds	r34,0x0,r8; cmp4.lt	p07,p06,r8,r0; }
	{ ld8	r1,[r1]; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000F48E0 }

l40000000000F4480:
	{ addl	r45,1,r0; nop.m	0x0; adds	r46,0x0,r8 }
	{ adds	r47,0x2D0,r12; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B3C0; }
	{ and	r16,0x2,r33; cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r8; adds	r1,0x3F8,r12 }
	{ adds	r15,0x390,r12; adds	r14,0x2E8,r12; addp4	r18,r16,r0 }
	{ ld8	r1,[r1]; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000F48E0; }

l40000000000F44D0:
	{ cmp4.eq	p06,p07,0x0,r18; st4	[r16],r15; nop.i	0x0 }
	{ ld4	r15,[r14]; nop.m	0x0; addl	r14,61440,r0; }
	{ (p06) addl	r39,-9724,r1; and	r14,r14,r15; addl	r15,16384,r0; }

l40000000000F44F6:
	{ Invalid; (p07) cmp4.eq.or	p00,p09,0x0,r0; (p49) nop }

l40000000000F4506:
	{ (p19) fwb; cmp4.eq	p00,p00,r0,r1; (p49) br.call.sptk.few	b1,b0; }

l40000000000F450C:
	{ cmp4.eq.or.andcm	p00,p49,r1,r0; (p04) cmp.eq.unc	p32,p08,r9,r6; (p48) mov	pr,r67,0xE286 }

l40000000000F4516:
	{ (p03) chk.a.clr	f15,3FFFFFFFFFD375F6; nop; break.b	0x80000 }

l40000000000F4520:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x7; (p06) br.cond.dptk.few	40000000000F51F0 }

l40000000000F4530:
	{ nop.m	0x0; addl	r15,32768,r0; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,r15,r14; (p07) br.cond.dptk.few	40000000000F5790 }

l40000000000F4550:
	{ nop.m	0x0; adds	r14,0x300,r12; nop.i	0x0; }
	{ ld8	r15,[r14]; adds	r45,0x1,r15; adds	r35,0x0,r15; }
	{ nop.m	0x0; cmp.ltu	p06,p07,r45,r15; (p06) br.cond.dpnt.few	40000000000F5440; }

l40000000000F4580:
	{ cmp.lt	p06,p07,r15,r0; adds	r36,0x360,r12; (p06) br.cond.dpnt.few	40000000000F5230; }

l40000000000F4590:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x3F8,r12; nop.m	0x0; adds	r47,0x0,r35 }
	{ adds	r46,0x0,r8; adds	r45,0x0,r34; nop.i	0x0 }
	{ ld8	r1,[r1]; st8	[r8],r36; br.call.sptk.many	b0,fn400000000001A600; }
	{ adds	r1,0x3F8,r12; cmp.lt	p06,p07,r8,r0; adds	r35,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F5B20; }

l40000000000F45F0:
	{ ld8	r14,[r36]; add	r14,r14,r8; nop.i	0x0; }
	{ st1	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ adds	r1,0x3F8,r12; nop.m	0x0; adds	r36,0x0,r8 }
	{ ld4	r38,[r8]; nop.m	0x0; adds	r45,0x0,r34; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C340; }
	{ nop.m	0x0; adds	r1,0x3F8,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; st4	[r38],r36; nop.i	0x0 }

l40000000000F4660:
	{ cmp.eq	p07,p06,0x0,r35; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000F5A60; }

l40000000000F4670:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x6; (p07) br.cond.dpnt.few	40000000000F58C0 }

l40000000000F4680:
	{ adds	r38,0x360,r12; ld8	r36,[r38]; nop.i	0x0; }
	{ adds	r45,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x3F8,r12; nop.m	0x0; sxt4	r8,r8; }
	{ ld8	r1,[r1]; cmp.lt	p06,p07,r8,r35; (p07) br.cond.dptk.few	40000000000F5500 }

l40000000000F46C0:
	{ addl	r34,1,r0; adds	r15,0x390,r12; adds	r47,0x0,r0 }
	{ adds	r40,0x0,r0; addl	r41,256,r0; adds	r14,0xFFFFFFFFFFFFFFFF,r34 }
	{ ld4	r15,[r15]; add	r45,r36,r14; cmp4.eq	p16,p17,0x0,r15; }
	{ ld1	r14,[r45]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000F5320; }

l40000000000F4710:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000F4720:
	{ adds	r47,0x0,r34; nop.m	0x0; adds	r34,0x1,r34; }
	{ cmp.lt	p07,p06,r47,r35; adds	r14,0xFFFFFFFFFFFFFFFF,r34; (p06) br.cond.dpnt.few	40000000000F5500; }

l40000000000F4740:
	{ ld8	r36,[r38]; add	r45,r36,r14; nop.i	0x0; }
	{ ld1	r14,[r45]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000F4720 }

l40000000000F4770:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000F5320 }

l40000000000F4780:
	{ addl	r45,-1060,r1; nop.m	0x0; adds	r37,0x0,r0; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x3F8,r12; nop.m	0x0; cmp.eq	p06,p07,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p07) br.cond.dptk.few	40000000000F4280; }

l40000000000F47C0:
	{ addl	r45,-1052,r1; adds	r14,0x380,r12; nop.i	0x0 }
	{ st8	[r0],r14; ld8	r45,[r45]; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x3F8,r12; nop.m	0x0; cmp.eq	p06,p07,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p07) br.cond.dptk.few	40000000000F4300; }

l40000000000F4800:
	{ adds	r18,0x388,r12; addl	r45,-1044,r1; nop.i	0x0 }
	{ st8	[r0],r18; ld8	r45,[r45]; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x3F8,r12; nop.m	0x0; cmp.eq	p06,p07,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p07) br.cond.dptk.few	40000000000F4380; }

l40000000000F4840:
	{ adds	r16,0x3A0,r12; addl	r45,-1036,r1; nop.i	0x0 }
	{ st8	[r0],r16; ld8	r45,[r45]; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x3F8,r12; nop.m	0x0; cmp.eq	p06,p07,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p07) br.cond.dptk.few	40000000000F4400; }

l40000000000F4880:
	{ adds	r15,0x3A8,r12; adds	r18,0x378,r12; adds	r46,0x0,r0; }
	{ nop.m	0x0; st8	[r0],r15; nop.i	0x0 }
	{ ld8	r45,[r18]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B4E0; }
	{ adds	r1,0x3F8,r12; adds	r34,0x0,r8; cmp4.lt	p07,p06,r8,r0; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dptk.few	40000000000F4480; }

l40000000000F48D0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000F48E0:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x0; (p06) br.cond.dpnt.few	40000000000F4920 }

l40000000000F48F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ adds	r1,0x3F8,r12; ld4	r14,[r8]; nop.i	0x0; }
	{ ld8	r1,[r1]; cmp4.eq	p06,p07,0x2,r14; (p06) br.cond.dpnt.few	40000000000F4960 }

l40000000000F4920:
	{ nop.m	0x0; adds	r14,0x378,r12; nop.i	0x0; }
	{ ld8	r45,[r14]; nop.i	0x0; br.call.sptk.many	b0,file_error; }
	{ nop.m	0x0; adds	r1,0x3F8,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0 }

l40000000000F4960:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x4; nop.i	0x0; }
	{ (p07) addl	r14,9044,r1; (p07) addl	r15,1,r0; (p07) addl	r45,3,r0; }

l40000000000F4976:
	{ Invalid; (p22) nop; break.b	0x80000; }

l40000000000F497C:
	{ Invalid; Invalid; Invalid }

l40000000000F4980:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ (p07) st4	[r15],r14; nop.i	0x0; (p07) br.call.spnt.many	b0,jump_to_top_level; }

l40000000000F4996:
	{ chk.a.nc	f0,3FFFFFFFFF0F5196; (p32) nop; break.i	0x80000 }

l40000000000F49A0:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x1; (p07) br.cond.dpnt.few	40000000000F51C0; }

l40000000000F49B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ ld4	r34,[r8]; nop.m	0x0; adds	r1,0x3F8,r12; }
	{ cmp4.eq	p07,p06,0x2,r34; ld8	r1,[r1]; nop.i	0x0; }
	{ (p06) addl	r34,-1,r0; nop.i	0x0; (p07) adds	r34,0x0,r0; }

l40000000000F49E6:
	{ chk.a.nc	f0,3FFFFFFFFF0F51E6; (p17) mov.sptk	b0,r0,40000000000F4AE6; nop }

l40000000000F49F0:
	{ adds	r8,0x0,r34; mov	pr,r44,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r43; }
	{ nop.m	0x0; mov.spnt	b0,r42,40000000000F4A00; nop.i	0x0 }
	{ adds	r12,0x3F0,r12; nop.m	0x0; br.ret	b0; }

l40000000000F4A20:
	{ adds	r8,0x8,r8; nop.m	0x0; adds	r14,0x3A8,r12; }
	{ nop.m	0x0; ld8	r8,[r8]; nop.i	0x0; }
	{ st8	[r8],r14; nop.i	0x0; br.cond.sptk.few	40000000000F4440 }

l40000000000F4A50:
	{ adds	r8,0x8,r8; nop.m	0x0; adds	r15,0x3A0,r12; }
	{ nop.m	0x0; ld8	r8,[r8]; nop.i	0x0; }
	{ st8	[r8],r15; nop.i	0x0; br.cond.sptk.few	40000000000F43C0 }

l40000000000F4A80:
	{ adds	r8,0x8,r8; nop.m	0x0; adds	r16,0x388,r12; }
	{ nop.m	0x0; ld8	r8,[r8]; nop.i	0x0; }
	{ st8	[r8],r16; nop.i	0x0; br.cond.sptk.few	40000000000F4340 }

l40000000000F4AB0:
	{ adds	r8,0x8,r8; nop.m	0x0; adds	r18,0x380,r12; }
	{ nop.m	0x0; ld8	r8,[r8]; nop.i	0x0; }
	{ st8	[r8],r18; nop.i	0x0; br.cond.sptk.few	40000000000F42C0 }

l40000000000F4AE0:
	{ addl	r45,22740,r1; and	r15,0x8,r33; adds	r14,0x3D0,r12 }
	{ adds	r46,0x10,r12; addl	r47,704,r0; nop.i	0x0 }
	{ st4	[r15],r14; nop.m	0x0; br.call.sptk.many	b0,xbcopy; }
	{ adds	r16,0x3D0,r12; nop.m	0x0; adds	r1,0x3F8,r12; }
	{ ld4	r16,[r16]; ld8	r1,[r1]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r16; (p06) br.cond.dptk.few	40000000000F4B80 }

l40000000000F4B40:
	{ nop.m	0x0; addl	r14,6516,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r14]; adds	r14,0x368,r12; }
	{ st4.rel	[r15],r14; addl	r14,6516,r1; nop.i	0x0 }
	{ nop.m	0x0; st4	[r0],r14; nop.i	0x0 }

l40000000000F4B80:
	{ addl	r15,9032,r1; nop.m	0x0; addl	r14,8412,r1 }
	{ adds	r18,0x378,r12; nop.m	0x0; addl	r46,1,r0; }
	{ nop.m	0x0; ld4	r16,[r14]; nop.i	0x0; }
	{ adds	r16,0x1,r16; ld8	r47,[r18]; adds	r18,0x380,r12; }
	{ ld4	r17,[r15]; st4	[r16],r14; nop.i	0x0 }
	{ ld8	r45,[r18]; adds	r17,0x1,r17; nop.i	0x0; }
	{ st4	[r17],r15; nop.i	0x0; br.call.sptk.many	b0,array_rshift; }
	{ nop.m	0x0; adds	r1,0x3F8,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,executing_line_number; }
	{ adds	r1,0x3F8,r12; nop.m	0x0; sxt4	r45,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,itos; }
	{ adds	r14,0x388,r12; adds	r1,0x3F8,r12; addl	r46,1,r0 }
	{ adds	r47,0x0,r8; adds	r34,0x0,r8; nop.i	0x0 }
	{ ld8	r45,[r14]; ld8	r1,[r1]; br.call.sptk.many	b0,array_rshift; }
	{ adds	r1,0x3F8,r12; nop.m	0x0; adds	r45,0x0,r34; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x3F8,r12; adds	r45,0x0,r37; addl	r46,1,r0; }
	{ ld8	r1,[r1]; addl	r47,-988,r1; nop.i	0x0; }
	{ ld8	r47,[r47]; nop.i	0x0; br.call.sptk.many	b0,array_rshift; }
	{ addl	r14,256,r0; adds	r1,0x3F8,r12; adds	r15,0x3C0,r12; }
	{ and	r16,r14,r33; ld8	r1,[r1]; nop.i	0x0; }
	{ addp4	r18,r16,r0; st4	[r16],r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r18; (p06) br.cond.dptk.few	40000000000F4D90 }

l40000000000F4CF0:
	{ adds	r14,0x3A0,r12; adds	r15,0x378,r12; addl	r46,1,r0; }
	{ nop.m	0x0; ld8	r45,[r14]; nop.i	0x0 }
	{ ld8	r47,[r15]; nop.m	0x0; br.call.sptk.many	b0,array_rshift; }
	{ adds	r47,0x36C,r12; addl	r14,49,r0; nop.i	0x0 }
	{ adds	r16,0x3A8,r12; adds	r1,0x3F8,r12; addl	r46,1,r0; }
	{ st1	[r14],r47; nop.m	0x0; adds	r14,0x36D,r12 }
	{ ld8	r1,[r1]; ld8	r45,[r16]; nop.i	0x0; }
	{ st1	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,array_rshift; }
	{ nop.m	0x0; adds	r1,0x3F8,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0; }

l40000000000F4D90:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x5; nop.b	0x0 }
	{ addl	r45,22740,r1; adds	r18,0x3E0,r12; addl	r46,1,r0; }
	{ (p06) addl	r14,20,r0; nop.m	0x0; nop.i	0x0; }

l40000000000F4DB6:
	{ break.m	0x4000; nop; cmp.lt	p00,p00,r0,r32 }
	{ Invalid; nop; nop; }

l40000000000F4DCC:
	{ Invalid; Invalid; break.i	0x1000 }
	{ (p60) nop; invala; Invalid }
	{ nop; Invalid; mov	pr,r32,0x0 }
	{ Invalid; break.i	0x1000; break.b	0x1000 }

l40000000000F4E00:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,parse_and_execute_cleanup; }
	{ adds	r1,0x3F8,r12; ld8	r1,[r1]; nop.i	0x0; }
	{ addl	r14,9012,r1; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; ld4	r34,[r14]; nop.i	0x0 }

l40000000000F4E40:
	{ adds	r16,0x3B0,r12; adds	r18,0x3D0,r12; nop.i	0x0 }
	{ addl	r46,22740,r1; adds	r45,0x10,r12; addl	r47,704,r0; }
	{ nop.m	0x0; ld4	r16,[r16]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r16; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000F5AE0; }

l40000000000F4E80:
	{ ld4	r18,[r18]; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r18; nop.i	0x0; }
	{ (p07) adds	r14,0x368,r12; (p07) ld4.acq	r15,[r14]; (p07) addl	r14,6516,r1; }

l40000000000F4EA6:
	{ (p07) chk.a.nc	f0,3FFFFFFFFF94CF86; (p07) nop; break.b	0x80000; }

l40000000000F4EAC:
	{ (p58) nop; break.i	0x1000; break.i	0x1000; }

l40000000000F4EB0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ (p07) st4	[r15],r14; addl	r15,9032,r1; addl	r14,8412,r1; }

l40000000000F4EC6:
	{ Invalid; (p07) nop; break.b	0x80000 }
	{ (p08) fwb; nop; nop }
	{ (p08) fwb; nop; br.call.spnt.few	b0,b4 }
	{ Invalid; nop; br.call.spnt.few	b0,b4 }
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; nop; (p16) br.call.sptk.few	b0,b0 }
	{ break.m	0x4000; nop; (p32) nop }

l40000000000F4F30:
	{ adds	r14,0x380,r12; addl	r46,1,r0; adds	r47,0x0,r0; }
	{ ld8	r45,[r14]; nop.i	0x0; br.call.sptk.many	b0,array_shift; }
	{ adds	r1,0x3F8,r12; nop.m	0x0; adds	r45,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,array_dispose_element; }
	{ adds	r15,0x388,r12; nop.m	0x0; adds	r1,0x3F8,r12 }
	{ addl	r46,1,r0; adds	r47,0x0,r0; nop.i	0x0 }
	{ ld8	r45,[r15]; ld8	r1,[r1]; br.call.sptk.many	b0,array_shift; }
	{ adds	r1,0x3F8,r12; nop.m	0x0; adds	r45,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,array_dispose_element; }
	{ adds	r1,0x3F8,r12; ld8	r1,[r1]; nop.i	0x0; }
	{ nop.m	0x0; addl	r45,-1068,r1; nop.i	0x0; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x3F8,r12; adds	r14,0x28,r8; cmp.eq	p06,p07,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F5040; }

l40000000000F5010:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x2; (p07) adds	r14,0x8,r8; }

l40000000000F5030:
	{ (p07) ld8	r45,[r14]; nop.i	0x0; (p07) br.cond.dptk.few	40000000000F5050; }

l40000000000F5036:
	{ chk.a.nc	f0,3FFFFFFFFF0F5836; nop; (p16) nop }

l40000000000F5040:
	{ adds	r45,0x0,r0; nop.m	0x0; nop.i	0x0 }

l40000000000F5050:
	{ adds	r16,0x370,r12; ld8	r16,[r16]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r16,r8; (p06) br.cond.dptk.few	40000000000F50C0 }

l40000000000F5070:
	{ addl	r46,1,r0; adds	r47,0x0,r0; br.call.sptk.many	b0,array_shift; }
	{ adds	r1,0x3F8,r12; nop.m	0x0; adds	r45,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,array_dispose_element; }
	{ nop.m	0x0; adds	r1,0x3F8,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0; }

l40000000000F50C0:
	{ adds	r18,0x3C0,r12; ld4	r18,[r18]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r18; (p06) br.cond.dptk.few	40000000000F5190 }

l40000000000F50E0:
	{ adds	r14,0x3A8,r12; addl	r46,1,r0; adds	r47,0x0,r0; }
	{ ld8	r45,[r14]; nop.i	0x0; br.call.sptk.many	b0,array_shift; }
	{ adds	r1,0x3F8,r12; nop.m	0x0; adds	r45,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,array_dispose_element; }
	{ adds	r15,0x3A0,r12; nop.m	0x0; adds	r1,0x3F8,r12 }
	{ addl	r46,1,r0; adds	r47,0x0,r0; nop.i	0x0 }
	{ ld8	r45,[r15]; ld8	r1,[r1]; br.call.sptk.many	b0,array_shift; }
	{ adds	r1,0x3F8,r12; nop.m	0x0; adds	r45,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,array_dispose_element; }
	{ nop.m	0x0; adds	r1,0x3F8,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0 }

l40000000000F5190:
	{ adds	r16,0x390,r12; ld4	r16,[r16]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r16; (p07) br.cond.dptk.few	40000000000F49F0; }

l40000000000F51B0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000F51C0:
	{ addl	r34,1,r0; adds	r8,0x0,r34; mov	pr,r44,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r43; mov.spnt	b0,r42,40000000000F51D0 }
	{ nop.m	0x0; adds	r12,0x3F0,r12; br.ret	b0; }

l40000000000F51F0:
	{ adds	r15,0x300,r12; nop.m	0x0; addl	r16,32768,r0; }
	{ ld8	r15,[r15]; adds	r45,0x1,r15; adds	r35,0x0,r15; }
	{ cmp.ltu	p07,p06,r45,r15; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000F5440; }

l40000000000F5220:
	{ nop.m	0x0; cmp4.eq	p07,p06,r16,r14; (p07) br.cond.dpnt.few	40000000000F4580 }

l40000000000F5230:
	{ adds	r46,0x360,r12; nop.m	0x0; adds	r45,0x0,r34 }
	{ adds	r47,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,zmapfd; }
	{ adds	r1,0x3F8,r12; nop.m	0x0; sxt4	r35,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ adds	r1,0x3F8,r12; nop.m	0x0; adds	r36,0x0,r8 }
	{ ld4	r38,[r8]; nop.m	0x0; adds	r45,0x0,r34; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C340; }
	{ adds	r1,0x3F8,r12; cmp.lt	p07,p06,r35,r0; nop.i	0x0 }
	{ ld8	r1,[r1]; st4	[r38],r36; (p06) br.cond.dptk.few	40000000000F4660 }

l40000000000F52C0:
	{ nop.m	0x0; adds	r14,0x360,r12; nop.i	0x0; }
	{ ld8	r45,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x3F8,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0 }

l40000000000F5300:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x0; (p07) br.cond.dptk.few	40000000000F48F0 }

l40000000000F5310:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000F4920 }

l40000000000F5320:
	{ sub	r47,r35,r47; nop.m	0x0; add	r46,r36,r34 }
	{ adds	r35,0xFFFFFFFFFFFFFFFF,r35; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7C0; }
	{ nop.m	0x0; adds	r1,0x3F8,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; (p16) br.cond.dptk.few	40000000000F4720 }

l40000000000F5360:
	{ nop.m	0x0; adds	r40,0x1,r40; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r41,r40; (p06) br.cond.dptk.few	40000000000F4720 }

l40000000000F5380:
	{ adds	r14,0x360,r12; nop.m	0x0; addl	r34,126,r0; }
	{ ld8	r45,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x3F8,r12; addl	r47,5,r0; adds	r45,0x0,r0; }
	{ ld8	r1,[r1]; addl	r46,-1004,r1; nop.i	0x0; }
	{ ld8	r46,[r46]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ ld8	r14,[r39],8; adds	r16,0x378,r12; adds	r45,0x0,r8; }
	{ ld8	r1,[r39],-8; nop.m	0x0; mov.spnt	b6,r14,40000000000F53E0 }
	{ ld8	r46,[r16]; nop.m	0x0; br.call.sptk.many	b0,b6; }
	{ adds	r1,0x3F8,r12; nop.m	0x0; adds	r8,0x0,r34; }
	{ ld8	r1,[r1]; mov	pr,r44,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r43; }
	{ nop.m	0x0; mov.spnt	b0,r42,40000000000F5420; nop.i	0x0 }
	{ adds	r12,0x3F0,r12; nop.m	0x0; br.ret	b0 }

l40000000000F5440:
	{ addl	r46,-1012,r1; adds	r45,0x0,r0; addl	r47,5,r0; }
	{ ld8	r46,[r46]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r16,0x378,r12; nop.m	0x0; adds	r45,0x0,r8; }
	{ ld8	r46,[r16]; nop.m	0x0; nop.i	0x0 }

l40000000000F5480:
	{ nop.m	0x0; ld8	r14,[r39],8; nop.i	0x0; }
	{ ld8	r1,[r39],-8; mov.spnt	b6,r14,40000000000F5490; br.call.sptk.many	b0,b6; }
	{ adds	r15,0x390,r12; nop.m	0x0; adds	r1,0x3F8,r12; }
	{ ld4	r15,[r15]; ld8	r1,[r1]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p06) br.cond.dpnt.few	40000000000F51C0 }

l40000000000F54D0:
	{ addl	r34,-1,r0; adds	r8,0x0,r34; mov	pr,r44,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r43; mov.spnt	b0,r42,40000000000F54E0 }
	{ nop.m	0x0; adds	r12,0x3F0,r12; br.ret	b0; }

l40000000000F5500:
	{ and	r18,0x4,r33; nop.m	0x0; adds	r16,0x3B0,r12; }
	{ addp4	r14,r18,r0; st4	[r18],r16; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	40000000000F4AE0 }

l40000000000F5530:
	{ and	r16,0x8,r33; adds	r15,0x3D0,r12; addl	r45,-996,r1; }
	{ nop.m	0x0; st4	[r16],r15; nop.i	0x0 }
	{ ld8	r45,[r45]; nop.m	0x0; br.call.sptk.many	b0,begin_unwind_frame; }
	{ adds	r1,0x3F8,r12; nop.m	0x0; addl	r46,4,r0; }
	{ ld8	r1,[r1]; addl	r45,9032,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,unwind_protect_mem; }
	{ adds	r1,0x3F8,r12; nop.m	0x0; addl	r46,704,r0; }
	{ ld8	r1,[r1]; addl	r45,22740,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,unwind_protect_mem; }
	{ adds	r18,0x3D0,r12; adds	r1,0x3F8,r12; addl	r46,4,r0; }
	{ ld4	r18,[r18]; ld8	r1,[r1]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r18; addl	r45,8412,r1; (p07) br.cond.dpnt.few	40000000000F59E0; }

l40000000000F55F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,unwind_protect_mem; }
	{ adds	r1,0x3F8,r12; adds	r18,0x378,r12; addl	r46,1,r0; }
	{ ld8	r1,[r1]; ld8	r47,[r18]; adds	r18,0x380,r12; }
	{ nop.m	0x0; addl	r15,9032,r1; addl	r14,8412,r1 }
	{ ld8	r45,[r18]; nop.m	0x0; nop.i	0x0 }
	{ ld4	r16,[r14]; adds	r16,0x1,r16; nop.i	0x0; }
	{ ld4	r17,[r15]; st4	[r16],r14; nop.i	0x0; }
	{ nop.m	0x0; adds	r17,0x1,r17; nop.i	0x0; }
	{ st4	[r17],r15; nop.i	0x0; br.call.sptk.many	b0,array_rshift; }
	{ nop.m	0x0; adds	r1,0x3F8,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,executing_line_number; }
	{ adds	r1,0x3F8,r12; nop.m	0x0; sxt4	r45,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,itos; }
	{ adds	r14,0x388,r12; adds	r1,0x3F8,r12; addl	r46,1,r0 }
	{ adds	r47,0x0,r8; adds	r34,0x0,r8; nop.i	0x0 }
	{ ld8	r45,[r14]; ld8	r1,[r1]; br.call.sptk.many	b0,array_rshift; }
	{ adds	r1,0x3F8,r12; nop.m	0x0; adds	r45,0x0,r34; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x3F8,r12; adds	r45,0x0,r37; addl	r46,1,r0; }
	{ ld8	r1,[r1]; addl	r47,-988,r1; nop.i	0x0; }
	{ ld8	r47,[r47]; nop.i	0x0; br.call.sptk.many	b0,array_rshift; }
	{ addl	r14,256,r0; adds	r1,0x3F8,r12; adds	r15,0x3C0,r12; }
	{ and	r16,r14,r33; ld8	r1,[r1]; nop.i	0x0; }
	{ addp4	r18,r16,r0; st4	[r16],r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r18; (p06) br.cond.dptk.few	40000000000F4D90 }

l40000000000F5780:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000F4CF0 }

l40000000000F5790:
	{ addl	r46,-1020,r1; addl	r47,5,r0; adds	r45,0x0,r0; }
	{ ld8	r46,[r46]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r16,0x378,r12; nop.m	0x0; adds	r45,0x0,r8; }
	{ ld8	r46,[r16]; nop.i	0x0; br.cond.sptk.few	40000000000F5480; }

l40000000000F57D0:
	{ addl	r46,-1028,r1; addl	r47,5,r0; adds	r45,0x0,r0; }
	{ ld8	r46,[r46]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r14,0x378,r12; nop.m	0x0; adds	r45,0x0,r8; }
	{ ld8	r46,[r14]; ld8	r14,[r39],8; nop.i	0x0; }
	{ ld8	r1,[r39],-8; mov.spnt	b6,r14,40000000000F5810; br.call.sptk.many	b0,b6; }
	{ adds	r15,0x390,r12; nop.m	0x0; adds	r1,0x3F8,r12; }
	{ ld4	r15,[r15]; ld8	r1,[r1]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p07) br.cond.dptk.few	40000000000F54D0 }

l40000000000F5850:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000F51C0 }

l40000000000F5860:
	{ adds	r14,0x378,r12; nop.m	0x0; adds	r15,0x3E0,r12; }
	{ nop.m	0x0; ld8	r46,[r14]; adds	r14,0x360,r12 }
	{ nop.m	0x0; ld4	r47,[r15]; nop.i	0x0; }
	{ ld8	r45,[r14]; nop.i	0x0; br.call.sptk.many	b0,parse_and_execute; }
	{ adds	r1,0x3F8,r12; nop.m	0x0; adds	r34,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	40000000000F4E40 }

l40000000000F58C0:
	{ cmp.lt	p06,p07,0x4F,r35; nop.m	0x0; adds	r34,0x360,r12; }
	{ (p07) adds	r46,0x0,r35; ld8	r45,[r34]; nop.i	0x0; }

l40000000000F58D6:
	{ (p22) fwb; nop; (p33) nop.b	0xA0B }

l40000000000F58E6:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; (p03) nop; (p16) nop }
	{ chk.a.nc	r0,3FFFFFFFFF0F6106; nop; (p16) nop }

l40000000000F5910:
	{ ld8	r45,[r34]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x3F8,r12; addl	r47,5,r0; adds	r45,0x0,r0; }
	{ ld8	r1,[r1]; addl	r46,-1004,r1; nop.i	0x0; }
	{ ld8	r46,[r46]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r14,0x378,r12; nop.m	0x0; adds	r45,0x0,r8; }
	{ ld8	r46,[r14]; ld8	r14,[r39],8; nop.i	0x0; }
	{ ld8	r1,[r39],-8; mov.spnt	b6,r14,40000000000F5970; br.call.sptk.many	b0,b6; }
	{ adds	r15,0x390,r12; nop.m	0x0; adds	r1,0x3F8,r12; }
	{ ld4	r15,[r15]; ld8	r1,[r1]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p07) br.cond.dptk.few	40000000000F54D0 }

l40000000000F59B0:
	{ addl	r34,126,r0; adds	r8,0x0,r34; mov	pr,r44,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r43; mov.spnt	b0,r42,40000000000F59C0 }
	{ nop.m	0x0; adds	r12,0x3F0,r12; br.ret	b0 }

l40000000000F59E0:
	{ addl	r45,6516,r1; nop.m	0x0; addl	r46,4,r0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,unwind_protect_mem; }
	{ adds	r1,0x3F8,r12; nop.m	0x0; addl	r46,4,r0; }
	{ nop.m	0x0; ld8	r1,[r1]; nop.i	0x0; }
	{ addl	r45,8412,r1; nop.i	0x0; br.call.sptk.many	b0,unwind_protect_mem; }
	{ adds	r1,0x3F8,r12; ld8	r1,[r1]; nop.i	0x0; }
	{ addl	r14,6516,r1; nop.m	0x0; nop.i	0x0; }
	{ st4	[r0],r14; nop.i	0x0; br.cond.sptk.few	40000000000F4B80 }

l40000000000F5A60:
	{ nop.m	0x0; adds	r14,0x360,r12; nop.i	0x0; }
	{ ld8	r45,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r16,0x390,r12; nop.m	0x0; adds	r1,0x3F8,r12; }
	{ ld4	r16,[r16]; ld8	r1,[r1]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r16; (p06) addl	r34,1,r0; nop.i	0x0; }

l40000000000F5AAC:
	{ getf.exp	r0,f1; zxt1	r0,r64; (p01) cmp.eq.unc	p00,p16,r8,r64 }

l40000000000F5AB6:
	{ Invalid; Invalid; break.i	0x80000 }
	{ break.m	0xAA02B; nop; break.i	0x80000 }
	{ Invalid; (p34) nop; break.i	0x80000 }

l40000000000F5AE0:
	{ nop.m	0x0; addl	r45,-996,r1; nop.i	0x0; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,run_unwind_frame; }
	{ nop.m	0x0; adds	r1,0x3F8,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	40000000000F4F30 }

l40000000000F5B20:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ adds	r1,0x3F8,r12; nop.m	0x0; adds	r35,0x0,r8 }
	{ ld4	r36,[r8]; nop.m	0x0; adds	r45,0x0,r34; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C340; }
	{ adds	r14,0x360,r12; nop.m	0x0; adds	r1,0x3F8,r12; }
	{ ld8	r1,[r1]; st4	[r36],r35; nop.i	0x0 }
	{ ld8	r45,[r14]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x3F8,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.cond.sptk.few	40000000000F5300; }
40000000000F5BB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; maybe_execute_file: 40000000000F5BC0
;;   Called from:
;;     400000000002032C (in main)
;;     400000000002035C (in main)
;;     400000000002054C (in main)
;;     400000000002059C (in main)
;;     400000000002070C (in main)
;;     400000000002074C (in main)
;;     4000000000020ADC (in main)
;;     4000000000020B2C (in main)
;;     4000000000020BCC (in main)
;;     4000000000020C0C (in main)
;;     4000000000021B8C (in fn4000000000021B40)
;;     40000000000222BC (in fn40000000000221C0)
;;     40000000000F873C (in bash_logout)
;;     40000000000F875C (in bash_logout)
maybe_execute_file proc
	{ alloc	r37,ar.pfs,0x9,0x0,0x7; nop.m	0x0; mov	r36,b4 }
	{ adds	r38,0x0,r1; nop.m	0x0; adds	r39,0x0,r32; }
	{ adds	r40,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,bash_tilde_expand; }
	{ cmp4.eq	p07,p06,0x0,r33; nop.m	0x0; adds	r1,0x0,r38 }
	{ adds	r34,0x0,r8; adds	r39,0x0,r8; (p06) addl	r40,9,r0; }

l40000000000F5C10:
	{ (p07) addl	r40,1,r0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000F4180; }

l40000000000F5C16:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ add	r0,r0,r1; (p17) nop; (p48) nop }
	{ break.m	0x4000; (p32) nop; nop }
	{ Invalid; nop; break.b	0x80000 }
	{ Invalid; (p34) nop; break.i	0x80000 }
40000000000F5C60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000F5C70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fc_execute_file: 40000000000F5C80
;;   Called from:
;;     40000000000FA90C (in fc_builtin)
fc_execute_file proc
	{ alloc	r16,ar.pfs,0x2,0x0,0x2; addl	r33,161,r0; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000F4180; }
40000000000F5CA0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000F5CB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; source_file: 40000000000F5CC0
;;   Called from:
;;     400000000010D00C (in source_builtin)
;;     400000000010D2BC (in source_builtin)
source_file proc
	{ alloc	r36,ar.pfs,0x8,0x0,0x6; addl	r14,6456,r1; mov	r35,b3 }
	{ cmp4.eq	p07,p06,0x0,r33; adds	r37,0x0,r1; adds	r38,0x0,r32; }
	{ nop.m	0x0; (p06) addl	r39,270,r0; (p07) addl	r39,14,r0; }

l40000000000F5CEC:
	{ (p07) nop; (p01) nop }

l40000000000F5CF0:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; addl	r14,6512,r1; (p06) br.cond.dpnt.few	40000000000F5D50; }

l40000000000F5D10:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; addl	r14,7032,r1; (p06) br.cond.dpnt.few	40000000000F5D50; }

l40000000000F5D30:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) or	r39,0x10,r39 }

l40000000000F5D50:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000F4180; }
	{ adds	r1,0x0,r37; adds	r34,0x0,r8; br.call.sptk.many	b0,run_return_trap; }
	{ adds	r8,0x0,r34; adds	r1,0x0,r37; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000F5D80; br.ret	b0; }
40000000000F5D90 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000F5DA0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000F5DB0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000F5DC0 09 00 00 00 01 00 E0 00 07 5E 48 00 00 00 04 00 .........^H.....
40000000000F5DD0 0B 00 00 00 01 00 F0 00 38 20 20 C0 41 0E BC 90 ........8  .A...
40000000000F5DE0 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000F5DF0 11 00 3C 1C 90 11 00 00 00 02 00 80 08 00 84 00 ..<.............

;; fn40000000000F5E00: 40000000000F5E00
;;   Called from:
;;     40000000000F633C (in parse_and_execute)
;;     40000000000F75EC (in parse_string)
fn40000000000F5E00 proc
	{ alloc	r37,ar.pfs,0xA,0x0,0x8; nop.m	0x0; mov	r39,pr }
	{ adds	r38,0x0,r1; nop.m	0x0; adds	r40,0x0,r34; }
	{ nop.m	0x0; mov	r36,b4; br.call.sptk.many	b0,begin_unwind_frame; }
	{ adds	r1,0x0,r38; nop.m	0x0; addl	r41,4,r0; }
	{ addl	r40,8416,r1; nop.i	0x0; br.call.sptk.many	b0,unwind_protect_mem; }
	{ adds	r1,0x0,r38; addl	r41,704,r0; addl	r40,25252,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,unwind_protect_mem; }
	{ adds	r1,0x0,r38; addl	r41,4,r0; addl	r40,6484,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,unwind_protect_mem; }
	{ adds	r1,0x0,r38; addl	r41,4,r0; addl	r40,6648,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,unwind_protect_mem; }
	{ adds	r1,0x0,r38; addl	r41,4,r0; addl	r40,8364,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,unwind_protect_mem; }
	{ adds	r1,0x0,r38; addl	r41,4,r0; addl	r40,7048,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,unwind_protect_mem; }
	{ adds	r1,0x0,r38; addl	r41,4,r0; addl	r40,7044,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,unwind_protect_mem; }
	{ and	r14,0x3,r33; nop.m	0x0; adds	r1,0x0,r38; }
	{ cmp4.eq	p16,p17,0x0,r14; (p17) addl	r40,6516,r1; (p17) addl	r41,4,r0; }

l40000000000F5F2C:
	{ Invalid; nop; }

l40000000000F5F30:
	{ nop.m	0x0; nop.i	0x0; (p17) br.call.dpnt.many	b0,unwind_protect_mem; }

l40000000000F5F40:
	{ (p17) adds	r1,0x0,r38; addl	r14,8416,r1; nop.i	0x0; }

l40000000000F5F46:
	{ Invalid; nop; break.i	0x80000 }
	{ (p07) fwb; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFDB9046; nop; nop }

l40000000000F5F70:
	{ addl	r40,-8428,r1; nop.m	0x0; adds	r41,0x0,r0; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,add_unwind_protect; }
	{ adds	r1,0x0,r38; addl	r35,6512,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dpnt.few	40000000000F60E0 }

l40000000000F5FC0:
	{ addl	r40,-9684,r1; nop.m	0x0; adds	r41,0x0,r0; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,add_unwind_protect; }
	{ cmp.eq	p06,p07,0x0,r32; adds	r1,0x0,r38; (p06) br.cond.dpnt.few	40000000000F6000; }

l40000000000F5FF0:
	{ nop.m	0x0; tbit.z	p07,p06,r33,0x3; (p07) br.cond.dpnt.few	40000000000F6160; }

l40000000000F6000:
	{ (p17) addl	r14,6516,r1; (p17) andcm	r15,0x1,r33; tbit.z	p06,p07,r33,0x2; }

l40000000000F6006:
	{ Invalid; Invalid; Invalid }

l40000000000F600C:
	{ (p02) nop; break.i	0x1000; break.i	0x1000 }
	{ srlz.d; Invalid; mov	pr,r32,0x0 }

l40000000000F6026:
	{ chk.a.nc	f0,3FFFFFFFFF0F6826; Invalid; break.i	0x80000 }

l40000000000F6030:
	{ nop.m	0x0; mov	pr,r39,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000F6040; br.ret	b0 }

l40000000000F6050:
	{ addl	r40,6116,r1; nop.m	0x0; addl	r41,4,r0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,unwind_protect_mem; }
	{ adds	r1,0x0,r38; addl	r35,6512,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	40000000000F5FC0 }

l40000000000F60A0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000F60E0 }

l40000000000F60B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,bash_history_disable; }
	{ adds	r1,0x0,r38; mov	pr,r39,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000F60D0; br.ret	b0 }

l40000000000F60E0:
	{ addl	r40,9156,r1; nop.m	0x0; addl	r41,4,r0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,unwind_protect_mem; }
	{ ld4	r14,[r35]; nop.m	0x0; adds	r1,0x0,r38; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.spnt.few	40000000000F5FC0; }

l40000000000F6120:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,get_current_prompt_level; }
	{ adds	r1,0x0,r38; adds	r41,0x0,r8; addl	r40,-9836,r1; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,add_unwind_protect; }
	{ nop.m	0x0; adds	r1,0x0,r38; br.cond.sptk.few	40000000000F5FC0; }

l40000000000F6160:
	{ addl	r40,-9884,r1; nop.m	0x0; adds	r41,0x0,r32; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,add_unwind_protect; }
	{ adds	r1,0x0,r38; (p17) andcm	r15,0x1,r33; tbit.z	p06,p07,r33,0x2; }

l40000000000F618C:
	{ (p02) cmp.gt	p33,p43,r0,r40; zxt4	r61,r12; break.i	0x1000 }

l40000000000F6196:
	{ break.m	0x4000; nop; (p04) nop }

l40000000000F61A6:
	{ chk.a.nc	r0,3FFFFFFFFF0F69A6; nop; break.i	0x80000 }

l40000000000F61B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000F60B0; }

;; parse_and_execute_cleanup: 40000000000F61C0
;;   Called from:
;;     40000000000B43CC (in top_level_cleanup)
;;     40000000000B460C (in throw_to_top_level)
;;     40000000000F4E0C (in fn40000000000F4180)
parse_and_execute_cleanup proc
	{ alloc	r33,ar.pfs,0x4,0x0,0x3; addl	r14,9124,r1; nop.b	0x0 }
	{ adds	r34,0x0,r1; nop.m	0x0; mov	r32,b0; }
	{ nop.m	0x0; ld4	r35,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r35; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000F6260; }

l40000000000F6200:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,have_unwind_protects; }
	{ adds	r1,0x0,r34; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dpnt.few	40000000000F62B0; }

l40000000000F6220:
	{ nop.m	0x0; (p06) addl	r14,8416,r1; nop.i	0x0; }

l40000000000F622C:
	{ Invalid; Invalid; break.i	0x1000 }

l40000000000F6236:
	{ break.m	0x4000; mov	pr,0x4000; break.i	0x80000 }

l40000000000F6240:
	{ nop.m	0x0; mov.i	ar.pfs,r33; nop.i	0x0; }

l40000000000F6242:
	{ nop; (p04) break.i	0x550; Invalid }

l40000000000F6246:
	{ break.m	0xAA021; nop; break.i	0x80000 }

l40000000000F6248:
	{ (p40) break.m	0xA; (p16) break.i	0x11000; break.i	0x8; }
	{ nop; break.x	0xC0880420119FA; }

l40000000000F6260:
	{ adds	r35,0xFFFFFFFFFFFFFFFF,r35; nop.i	0x0; br.call.sptk.many	b0,run_trap_cleanup; }
	{ adds	r1,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,unfreeze_jobs_list; }
	{ adds	r1,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,have_unwind_protects; }
	{ adds	r1,0x0,r34; cmp4.eq	p06,p07,0x0,r8; (p06) addl	r14,8416,r1; }

l40000000000F62A0:
	{ (p06) st4	[r0],r14; nop.i	0x0; (p06) br.cond.dptk.few	40000000000F6240 }

l40000000000F62A6:
	{ chk.a.nc	r0,3FFFFFFFFF0F6AA6; nop; break.i	0x80000 }

l40000000000F62B0:
	{ nop.m	0x0; addl	r35,-8420,r1; nop.i	0x0; }
	{ ld8	r35,[r35]; nop.i	0x0; br.call.sptk.many	b0,run_unwind_frame; }
	{ adds	r1,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ nop.m	0x0; mov.spnt	b0,r32,40000000000F62E0; br.ret	b0; }
40000000000F62F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; parse_and_execute: 40000000000F6300
;;   Called from:
;;     4000000000021DAC (in fn4000000000021C00)
;;     400000000003E31C (in execute_variable_command)
;;     400000000003E43C (in execute_variable_command)
;;     400000000006D13C (in initialize_shell_variables)
;;     400000000007D51C (in run_sigchld_trap)
;;     4000000000094CFC (in command_substitute)
;;     40000000000A53EC (in fn40000000000A1400)
;;     40000000000ACC0C (in fn40000000000AC6C0)
;;     40000000000AEB6C (in run_exit_trap)
;;     40000000000AF36C (in run_pending_traps)
;;     40000000000F412C (in eval_builtin)
;;     40000000000F589C (in fn40000000000F4180)
;;     40000000000F9C0C (in fc_builtin)
;;     40000000000FA1AC (in fc_builtin)
;;     40000000000FA81C (in fc_builtin)
;;     400000000010160C (in mapfile_builtin)
parse_and_execute proc
	{ alloc	r41,ar.pfs,0xF,0x0,0xA; adds	r16,0x8,r12; nop.b	0x0 }
	{ adds	r12,0xFFFFFFFFFFFFFFD0,r12; addl	r44,-8420,r1; mov	r40,b0; }
	{ st8.spill	[r1],r16; ld8	r44,[r44]; adds	r43,0x0,r34 }
	{ adds	r42,0x0,r32; adds	r36,0x1C,r12; br.call.sptk.many	b0,fn40000000000F5E00; }
	{ adds	r1,0x38,r12; nop.m	0x0; and	r42,0x10,r34; }
	{ ld8	r1,[r1]; adds	r35,0x0,r42; addl	r14,8416,r1; }
	{ ld4	r15,[r14]; adds	r15,0x1,r15; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,push_stream; }
	{ adds	r1,0x38,r12; cmp4.eq	p07,p06,0x0,r35; adds	r42,0x0,r32 }
	{ st4.rel	[r0],r36; adds	r43,0x0,r33; adds	r35,0x0,r0; }
	{ ld8	r1,[r1]; (p07) addl	r14,6648,r1; nop.i	0x0; }

l40000000000F63AC:
	{ Invalid; cmp4.eq.or.andcm	p00,p32,r32,r0; Invalid }

l40000000000F63BC:
	{ nop; cmp4.eq.or.andcm	p00,p32,r32,r0; zxt2	r127,r79 }

l40000000000F63CC:
	{ Invalid; (p48) cmp.lt.unc	p03,p08,r3,r100; zxt4	r53,r12 }

l40000000000F63D6:
	{ Invalid; nop; (p48) nop }
	{ add	r0,r0,r1; (p03) nop; break.i	0x80000 }
	{ adds	r0,0xFFFFFFFFFFFFF18F,r48; (p07) cmp4.eq.or	p01,p02,0x0,r0; (p49) nop }

l40000000000F6400:
	{ (p07) adds	r15,0x0,r0; ld4	r16,[r14]; nop.i	0x0; }

l40000000000F6406:
	{ (p08) fwb; nop; nop }
	{ mf.a; (p07) nop; nop }
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; nop; (p16) br.call.sptk.few	b0,b0 }
	{ break.m	0x4000; nop; (p48) nop }

l40000000000F6450:
	{ addl	r15,6180,r1; nop.m	0x0; adds	r16,0x10,r12 }
	{ addl	r42,25252,r1; nop.m	0x0; addl	r43,1,r0; }
	{ ld8	r15,[r15]; ld8	r14,[r15]; addl	r15,7684,r1; }
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000F69E0; }

l40000000000F64A0:
	{ nop.m	0x0; st8.rel	[r0],r16; nop.i	0x0; }
	{ nop.m	0x0; ld4.acq	r14,[r15]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000F7120; }

l40000000000F64D0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BD60; }
	{ cmp4.eq	p06,p07,0x0,r8; nop.m	0x0; adds	r1,0x38,r12 }
	{ adds	r35,0x0,r8; nop.m	0x0; adds	r16,0x1C,r12; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F65A0; }

l40000000000F6510:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2,r8; nop.i	0x0 }
	{ st4.rel	[r0],r16; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000F6AC0; }

l40000000000F6530:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x2,r8; (p06) br.cond.dptk.few	40000000000F6950; }

l40000000000F6540:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x1,r8; (p06) br.cond.dpnt.few	40000000000F6960 }

l40000000000F6550:
	{ addl	r42,-8404,r1; nop.m	0x0; addl	r43,3,r0 }
	{ adds	r44,0x0,r35; nop.m	0x0; adds	r45,0x0,r0; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,command_error; }
	{ nop.m	0x0; adds	r1,0x38,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0 }

l40000000000F65A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,parse_command; }
	{ adds	r1,0x38,r12; adds	r14,0x20,r12; cmp4.eq	p07,p06,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F7290; }

l40000000000F65D0:
	{ ld1	r15,[r14]; nop.m	0x0; addl	r16,6512,r1; }
	{ nop.m	0x0; tbit.z	p07,p06,r15,0x0; (p06) br.cond.dpnt.few	40000000000F6640; }

l40000000000F65F0:
	{ nop.m	0x0; ld4	r14,[r16]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000F66A0 }

l40000000000F6610:
	{ addl	r15,7392,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000F66A0 }

l40000000000F6640:
	{ addl	r14,6532,r1; nop.m	0x0; adds	r16,0x18,r12; }
	{ nop.m	0x0; st4.rel	[r0],r16; nop.i	0x0; }
	{ ld8	r42,[r14]; nop.i	0x0; br.call.sptk.many	b0,dispose_command; }
	{ adds	r1,0x38,r12; ld8	r1,[r1]; nop.i	0x0; }
	{ addl	r15,6532,r1; nop.m	0x0; nop.i	0x0; }
	{ st8	[r0],r15; nop.i	0x0; br.cond.sptk.few	40000000000F6450 }

l40000000000F66A0:
	{ addl	r16,6532,r1; adds	r15,0x10,r12; addl	r42,32,r0; }
	{ nop.m	0x0; ld8	r14,[r16]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; nop.i	0x0 }
	{ st8.rel	[r14],r15; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000F6450; }

l40000000000F66E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,new_fd_bitmap; }
	{ adds	r1,0x38,r12; nop.m	0x0; adds	r36,0x0,r8; }
	{ ld8	r1,[r1]; addl	r42,-8412,r1; nop.i	0x0; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,begin_unwind_frame; }
	{ adds	r1,0x38,r12; nop.m	0x0; adds	r43,0x0,r36; }
	{ ld8	r1,[r1]; addl	r42,-9764,r1; nop.i	0x0; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,add_unwind_protect; }
	{ adds	r1,0x38,r12; nop.m	0x0; adds	r16,0x10,r12; }
	{ ld8	r1,[r1]; ld8.acq	r43,[r16]; nop.i	0x0; }
	{ nop.m	0x0; addl	r42,-9796,r1; nop.i	0x0; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,add_unwind_protect; }
	{ nop.m	0x0; adds	r1,0x38,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; addl	r15,9028,r1; addl	r16,6532,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4	r14,[r15]; st8	[r0],r16; nop.i	0x0; }
	{ nop.m	0x0; and	r14,0x4,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000F6850 }

l40000000000F67F0:
	{ addl	r16,7044,r1; nop.m	0x0; nop.i	0x0; }
	{ ld4	r15,[r16]; cmp4.eq	p06,p07,0x0,r15; nop.i	0x0; }
	{ (p07) adds	r16,0x10,r12; (p07) ld8.acq	r15,[r16]; nop.i	0x0; }

l40000000000F6816:
	{ Invalid; cmp4.ltu	p00,p00,0x0,r1; Invalid; }

l40000000000F681C:
	{ cmp4.eq.or.andcm	p00,p43,r1,r0; (p01) mov	pr,r3,0x84C2; Invalid }

l40000000000F6826:
	{ (p08) fwb; nop; cmp.lt	p00,p00,r0,r32; }

l40000000000F682C:
	{ nop; mov	pr,r32,0x0; zxt1	r2,r11 }

l40000000000F683C:
	{ Invalid; Invalid; break.i	0x1000 }

l40000000000F6846:
	{ break.m	0x4000; nop; nop }

l40000000000F6850:
	{ addl	r16,6496,r1; nop.m	0x0; nop.i	0x0; }

l40000000000F6852:
	{ (p28) break.m	0x48640; break.i	0x20; Invalid }

l40000000000F6856:
	{ break.m	0x4000; nop; break.i	0x80000 }

l40000000000F6858:
	{ (p16) break.m	0x0; (p16) break.i	0x9000; Invalid }

l40000000000F685C:
	{ nop; cmp.eq	p00,p00,r32,r0; Invalid }
	{ invala; cmp.eq	p00,p00,r32,r0; (p32) mov	pr,r67,0xE6C0 }
	{ (p30) cmp.lt	p00,p08,r64,r33; (p01) nop; (p05) epc }
	{ Invalid; (p53) nop; (p53) cmp.lt	p31,p19,r127,r127 }
	{ cmpxchg4.acq	r36,[r66],r0; break.x	0x85C0E00A01000; }
	{ (p29) cmp.eq	p58,p09,r61,r44; (p01) invala; (p02) nop }
	{ (p28) nop; nop; Invalid }
	{ cmpxchg4.acq	r0,[r0],r1; Invalid; break.i	0x1000 }
	{ (p55) nop; invala; br.cond.sptk.few	40000000000F6ADC }
	{ nop; break.x	0x80C0100001000; }
	{ (p62) nop; nop; rfi }
	{ nop; dep	r0,r32,r0,63,1; Invalid }
	{ cmpxchg4.acq	r0,[r0],r1; Invalid; break.i	0x1000 }
	{ (p35) nop; nop; zxt1	r14,r64 }
	{ nop; Invalid; break.i	0x1000 }
	{ Invalid; cmp.lt	p00,p00,r32,r0; nop }

l40000000000F6950:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x4,r8; (p06) br.cond.dptk.few	40000000000F6550; }

l40000000000F6960:
	{ adds	r15,0x10,r12; nop.m	0x0; addl	r42,-8412,r1; }
	{ nop.m	0x0; ld8.acq	r14,[r15]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F69C0; }

l40000000000F6990:
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,run_unwind_frame; }
	{ nop.m	0x0; adds	r1,0x38,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0 }

l40000000000F69C0:
	{ addl	r15,1,r0; nop.m	0x0; adds	r14,0x1C,r12; }
	{ st4.rel	[r15],r14; nop.m	0x0; nop.i	0x0 }

l40000000000F69E0:
	{ nop.m	0x0; addl	r42,-8420,r1; nop.i	0x0; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,run_unwind_frame; }
	{ adds	r1,0x38,r12; ld8	r1,[r1]; nop.i	0x0; }
	{ addl	r14,7684,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4.acq	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000F6A60 }

l40000000000F6A40:
	{ addl	r14,8416,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000F6B90 }

l40000000000F6A60:
	{ adds	r14,0x1C,r12; ld4.acq	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; }
	{ (p07) adds	r42,0x0,r35; nop.i	0x0; (p07) br.call.spnt.many	b0,jump_to_top_level; }

l40000000000F6A86:
	{ chk.a.nc	f0,3FFFFFFFFF0F7286; (p32) nop; break.i	0x80000 }

l40000000000F6A90:
	{ nop.m	0x0; adds	r14,0x18,r12; nop.i	0x0; }
	{ ld4.acq	r8,[r14]; mov.i	ar.pfs,r41; mov.spnt	b0,r40,40000000000F6AA0 }
	{ nop.m	0x0; adds	r12,0x30,r12; br.ret	b0; }

l40000000000F6AC0:
	{ adds	r16,0x10,r12; nop.m	0x0; addl	r42,-8412,r1; }
	{ nop.m	0x0; ld8.acq	r14,[r16]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F6B20; }

l40000000000F6AF0:
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,run_unwind_frame; }
	{ nop.m	0x0; adds	r1,0x38,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0; }

l40000000000F6B20:
	{ addl	r16,9028,r1; nop.m	0x0; addl	r14,1,r0; }
	{ nop.m	0x0; ld4	r15,[r16]; addl	r16,9044,r1; }
	{ nop.m	0x0; nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; }
	{ st4	[r14],r16; nop.m	0x0; adds	r16,0x18,r12; }
	{ st4.rel	[r14],r16; nop.i	0x0; (p06) br.cond.dptk.few	40000000000F6450 }

l40000000000F6B70:
	{ nop.m	0x0; adds	r15,0x1C,r12; nop.i	0x0; }
	{ st4.rel	[r14],r15; nop.i	0x0; br.cond.sptk.few	40000000000F69E0 }

l40000000000F6B90:
	{ nop.m	0x0; addl	r14,6512,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r14]; addl	r14,6516,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,throw_to_top_level; }
	{ adds	r14,0x1C,r12; nop.m	0x0; adds	r1,0x38,r12; }
	{ ld4.acq	r14,[r14]; ld8	r1,[r1]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; }
	{ (p07) adds	r42,0x0,r35; nop.i	0x0; (p07) br.call.spnt.many	b0,jump_to_top_level; }

l40000000000F6C06:
	{ chk.a.nc	f0,3FFFFFFFFF0F7406; (p32) nop; break.i	0x80000 }

l40000000000F6C10:
	{ nop.m	0x0; adds	r14,0x18,r12; nop.i	0x0; }
	{ ld4.acq	r8,[r14]; mov.i	ar.pfs,r41; mov.spnt	b0,r40,40000000000F6C20 }
	{ nop.m	0x0; adds	r12,0x30,r12; br.ret	b0 }
40000000000F6C40 0B 80 80 03 41 24 F0 00 40 20 20 00 00 00 04 00 ....A$..@  .....
40000000000F6C50 11 00 00 00 01 00 70 08 3C 0C F3 03 F0 04 00 43 ......p.<......C
40000000000F6C60 10 00 00 00 01 00 60 00 38 0E 73 03 20 FC FF 4A ......`.8.s. ..J
40000000000F6C70 0B 78 90 02 30 24 F0 00 3C 30 20 00 00 00 04 00 .x..0$..<0 .....
40000000000F6C80 0B 70 00 1E 18 10 E0 00 38 00 20 00 00 00 04 00 .p......8. .....
40000000000F6C90 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
40000000000F6CA0 10 00 00 00 01 00 70 00 38 0C 73 03 E0 FB FF 4A ......p.8.s....J
40000000000F6CB0 0B 80 40 18 00 21 E0 00 40 70 21 00 00 00 04 00 ..@..!..@p!.....
40000000000F6CC0 09 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
40000000000F6CD0 10 00 00 00 01 00 70 20 38 0C 73 03 B0 FB FF 4A ......p 8.s....J
40000000000F6CE0 0B 70 00 20 B8 10 E0 80 38 00 42 00 00 00 04 00 .p. ....8.B.....
40000000000F6CF0 09 00 00 00 01 00 E0 00 38 30 20 00 00 00 04 00 ........80 .....
40000000000F6D00 10 00 00 00 01 00 70 00 38 0C 72 03 80 FB FF 4A ......p.8.r....J
40000000000F6D10 03 70 00 20 B8 10 F0 00 00 02 48 C0 41 70 00 84 .p. ......H.Ap..
40000000000F6D20 0B 70 00 1C 10 10 E0 70 3C 18 40 00 00 00 04 00 .p.....p<.@.....
40000000000F6D30 10 00 00 00 01 00 70 00 38 0C 73 03 50 FB FF 4A ......p.8.s.P..J
40000000000F6D40 0B 70 00 20 B8 10 E0 C0 38 00 42 00 00 00 04 00 .p. ....8.B.....
40000000000F6D50 0B 70 00 1C 18 10 E0 40 38 00 42 00 00 00 04 00 .p.....@8.B.....
40000000000F6D60 09 00 00 00 01 00 E0 00 38 30 20 00 00 00 04 00 ........80 .....
40000000000F6D70 10 00 00 00 01 00 70 00 38 0C 72 03 10 FB FF 4A ......p.8.r....J
40000000000F6D80 0B 70 00 20 B8 10 E0 C0 38 00 42 00 00 00 04 00 .p. ....8.B.....
40000000000F6D90 0B 70 00 1C 18 10 E0 80 38 00 42 00 00 00 04 00 .p......8.B.....
40000000000F6DA0 09 00 00 00 01 00 E0 00 38 30 20 00 00 00 04 00 ........80 .....
40000000000F6DB0 11 30 00 1C 07 39 00 00 00 02 00 03 D0 FA FF 4B .0...9.........K
40000000000F6DC0 0B 70 00 20 B8 10 E0 C0 38 00 42 00 00 00 04 00 .p. ....8.B.....
40000000000F6DD0 0B 70 00 1C 18 10 E0 80 38 00 42 00 00 00 04 00 .p......8.B.....
40000000000F6DE0 0B 70 00 1C 18 10 E0 00 38 30 20 00 00 00 04 00 .p......80 .....
40000000000F6DF0 10 00 00 00 01 00 70 00 38 0C 72 03 90 FA FF 4A ......p.8.r....J
40000000000F6E00 0B 70 00 20 B8 10 E0 C0 38 00 42 00 00 00 04 00 .p. ....8.B.....
40000000000F6E10 0B 70 00 1C 18 10 E0 80 38 00 42 00 00 00 04 00 .p......8.B.....
40000000000F6E20 0B 70 00 1C 18 10 E0 C0 38 00 42 00 00 00 04 00 .p......8.B.....
40000000000F6E30 09 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
40000000000F6E40 10 00 00 00 01 00 70 08 38 0C 73 03 40 FA FF 4A ......p.8.s.@..J
40000000000F6E50 03 70 00 20 B8 10 00 C1 05 64 48 C0 81 71 00 84 .p. .....dH..q..
40000000000F6E60 0B 70 00 1C 18 10 E0 80 38 00 42 00 00 00 04 00 .p......8.B.....
40000000000F6E70 0B 30 01 1C 18 10 E0 C0 98 00 42 00 00 00 04 00 .0........B.....
40000000000F6E80 0B 70 00 1C 10 10 70 08 38 0C 73 00 00 00 04 00 .p....p.8.s.....
40000000000F6E90 D1 30 FD F9 FF 27 00 00 00 02 00 03 F0 01 00 43 .0...'.........C
40000000000F6EA0 0B 00 00 00 01 00 E0 00 40 20 20 00 00 00 04 00 ........@  .....
40000000000F6EB0 10 00 00 00 01 00 60 00 38 0E 73 03 60 00 00 42 ......`.8.s.`..B
40000000000F6EC0 0B 78 C0 03 32 24 00 00 00 02 00 00 00 00 04 00 .x..2$..........
40000000000F6ED0 0B 70 00 1E 10 10 70 00 38 0C 73 00 00 00 04 00 .p....p.8.s.....
40000000000F6EE0 EB 80 A0 03 39 24 00 00 00 02 00 00 00 00 04 00 ....9$..........
40000000000F6EF0 E3 70 00 20 10 10 00 00 00 02 80 C3 11 70 00 84 .p. .........p..
40000000000F6F00 E8 00 38 20 90 11 00 00 00 02 00 00 00 00 04 00 ..8 ............
40000000000F6F10 09 00 00 00 01 00 E0 00 99 00 42 00 00 00 04 00 ..........B.....
40000000000F6F20 11 50 01 1C 18 10 00 00 00 02 00 00 A8 74 FE 58 .P...........t.X
40000000000F6F30 09 08 E0 18 00 21 00 00 00 02 00 A0 04 40 00 84 .....!.......@..
40000000000F6F40 0B 08 00 02 18 10 F0 C0 05 64 48 00 00 00 04 00 .........dH.....
40000000000F6F50 0B 00 00 00 01 00 E0 00 3C 20 20 00 00 00 04 00 ........<  .....
40000000000F6F60 10 00 00 00 01 00 60 00 38 0E 73 03 60 00 00 42 ......`.8.s.`..B
40000000000F6F70 0B 80 C0 03 32 24 00 00 00 02 00 00 00 00 04 00 ....2$..........
40000000000F6F80 0B 70 00 20 10 10 70 00 38 0C 73 00 00 00 04 00 .p. ..p.8.s.....
40000000000F6F90 EB 78 A0 03 39 24 00 00 00 02 00 00 00 00 04 00 .x..9$..........
40000000000F6FA0 E3 70 00 1E 10 10 00 00 00 02 80 C3 F1 77 FC 8C .p...........w..
40000000000F6FB0 E8 00 38 1E 90 11 00 00 00 02 00 00 00 00 04 00 ..8.............
40000000000F6FC0 08 38 00 4A 06 39 00 00 00 02 00 40 05 28 01 84 .8.J.9.....@.(..
40000000000F6FD0 19 58 01 00 00 21 00 00 00 02 80 03 40 05 00 41 .X...!......@..A
40000000000F6FE0 11 00 00 00 01 00 00 00 00 02 00 00 08 45 F2 58 .............E.X
40000000000F6FF0 08 08 E0 18 00 21 70 40 00 0C 61 60 15 00 00 90 .....!p@..a`....
40000000000F7000 09 60 01 4A 00 21 70 02 20 00 42 40 05 40 00 84 .`.J.!p. .B@.@..
40000000000F7010 13 08 00 02 18 D0 01 58 02 80 21 00 38 DC 03 50 .......X..!.8..P
40000000000F7020 09 08 E0 18 00 21 60 02 20 00 42 40 05 28 01 84 .....!`. .B@.(..
40000000000F7030 11 08 00 02 18 10 00 00 00 02 00 00 B8 37 F2 58 .............7.X
40000000000F7040 09 08 E0 18 00 21 00 00 00 02 00 40 05 38 01 84 .....!.....@.8..
40000000000F7050 11 08 00 02 18 10 00 00 00 02 00 00 F8 52 F2 58 .............R.X
40000000000F7060 09 00 00 00 01 00 10 C0 31 00 42 00 00 00 04 00 ........1.B.....
40000000000F7070 08 08 00 02 18 10 00 00 00 02 00 00 00 00 04 00 ................
40000000000F7080 09 80 60 18 00 21 00 00 00 02 00 C0 E4 33 01 52 ..`..!.......3.R
40000000000F7090 09 00 98 20 B0 11 00 00 00 02 00 00 02 61 00 84 ... .........a..
40000000000F70A0 11 50 01 20 B8 10 00 00 00 02 00 00 28 4F F5 58 .P. ........(O.X
40000000000F70B0 09 08 E0 18 00 21 00 00 00 02 00 40 05 20 01 84 .....!.....@. ..
40000000000F70C0 11 08 00 02 18 10 00 00 00 02 00 00 08 60 F5 58 .............`.X
40000000000F70D0 0B 08 E0 18 00 21 10 00 04 30 20 00 00 00 04 00 .....!...0 .....
40000000000F70E0 09 00 00 00 01 00 A0 22 F5 7D 4F 00 00 00 04 00 .......".}O.....
40000000000F70F0 11 50 01 54 18 10 00 00 00 02 00 00 98 AC FB 58 .P.T...........X
40000000000F7100 09 00 00 00 01 00 10 C0 31 00 42 00 00 00 04 00 ........1.B.....
40000000000F7110 10 08 00 02 18 10 00 00 00 02 00 00 40 F3 FF 48 ............@..H

l40000000000F7120:
	{ addl	r15,1,r0; nop.m	0x0; adds	r14,0x18,r12; }
	{ st4.rel	[r15],r14; nop.i	0x0; br.cond.sptk.few	40000000000F69E0 }
40000000000F7140 0B 80 90 02 47 24 00 00 00 02 00 00 00 00 04 00 ....G$..........
40000000000F7150 09 00 00 00 01 00 F0 00 40 20 20 00 00 00 04 00 ........@  .....
40000000000F7160 10 00 00 00 01 00 70 00 3C 0C 73 03 00 FB FF 4A ......p.<.s....J
40000000000F7170 0B 80 90 02 30 24 00 01 40 30 20 00 00 00 04 00 ....0$..@0 .....
40000000000F7180 0B 78 00 20 18 10 F0 00 3C 00 20 00 00 00 04 00 .x. ....<. .....
40000000000F7190 01 00 00 00 01 00 F0 00 3C 28 00 00 00 00 04 00 ........<(......
40000000000F71A0 10 00 00 00 01 00 70 00 3C 0C 73 03 C0 FA FF 4A ......p.<.s....J
40000000000F71B0 0B 80 40 18 00 21 F0 00 40 70 21 00 00 00 04 00 ..@..!..@p!.....
40000000000F71C0 09 00 00 00 01 00 F0 00 3C 20 20 00 00 00 04 00 ........<  .....
40000000000F71D0 10 00 00 00 01 00 70 20 3C 0C 73 03 90 FA FF 4A ......p <.s....J
40000000000F71E0 11 50 01 00 00 21 00 00 00 02 00 00 28 8A FB 58 .P...!......(..X
40000000000F71F0 09 08 E0 18 00 21 00 00 00 02 00 E0 00 40 18 E6 .....!.......@..
40000000000F7200 10 08 00 02 18 10 00 00 00 02 00 03 40 00 00 42 ............@..B
40000000000F7210 0B 78 40 18 00 21 E0 00 3C 70 21 00 00 00 04 00 .x@..!..<p!.....
40000000000F7220 0B 70 40 1C 00 21 E0 00 38 30 20 00 00 00 04 00 .p@..!..80 .....
40000000000F7230 10 00 00 00 01 00 70 00 38 0C F2 03 A0 01 00 43 ......p.8......C
40000000000F7240 09 78 80 03 32 24 00 00 00 02 00 00 42 0C 18 91 .x..2$......B...
40000000000F7250 0B 00 00 00 01 00 E0 00 3C 20 20 00 00 00 04 00 ........<  .....
40000000000F7260 11 38 08 1C 86 39 00 00 00 02 00 03 20 F6 FF 49 .8...9...... ..I
40000000000F7270 0B 00 00 00 01 00 E0 00 40 20 20 00 00 00 04 00 ........@  .....
40000000000F7280 11 00 00 00 01 00 E0 20 38 58 40 00 E0 F9 FF 48 ....... 8X@....H

l40000000000F7290:
	{ addl	r14,6512,r1; addl	r16,1,r0; adds	r15,0x18,r12; }
	{ nop.m	0x0; st4.rel	[r16],r15; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000F69E0 }

l40000000000F72D0:
	{ addl	r14,8388,r1; nop.m	0x0; addl	r15,-9916,r1; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F69E0; }

l40000000000F7300:
	{ nop.m	0x0; ld8	r15,[r15]; nop.i	0x0; }
	{ cmp.eq	p06,p07,r15,r14; addl	r15,-9860,r1; (p06) br.cond.dpnt.few	40000000000F7340; }

l40000000000F7320:
	{ nop.m	0x0; ld8	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r15,r14; (p06) br.cond.dptk.few	40000000000F69E0 }

l40000000000F7340:
	{ addl	r14,9044,r1; nop.m	0x0; addl	r16,257,r0; }
	{ nop.m	0x0; ld4	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r16,r15; (p06) br.cond.dptk.few	40000000000F69E0 }

l40000000000F7370:
	{ addl	r15,6456,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	40000000000F69E0 }

l40000000000F73A0:
	{ adds	r15,0x1C,r12; addl	r16,1,r0; addl	r35,4,r0; }
	{ st4.rel	[r16],r15; nop.m	0x0; addl	r15,2,r0; }
	{ st4	[r15],r14; nop.i	0x0; br.cond.sptk.few	40000000000F69E0 }
40000000000F73D0 0B 70 00 1E B8 10 E0 C0 38 00 42 00 00 00 04 00 .p......8.B.....
40000000000F73E0 0B 70 00 1C 18 10 E0 80 38 00 42 00 00 00 04 00 .p......8.B.....
40000000000F73F0 09 00 00 00 01 00 E0 00 38 30 20 00 00 00 04 00 ........80 .....
40000000000F7400 10 00 00 00 01 00 70 00 38 0C 72 03 40 FE FF 4A ......p.8.r.@..J
40000000000F7410 03 70 00 1E B8 10 00 01 00 02 48 C0 41 70 00 84 .p........H.Ap..
40000000000F7420 0B 70 00 1C 10 10 E0 70 40 18 40 00 00 00 04 00 .p.....p@.@.....
40000000000F7430 10 00 00 00 01 00 70 00 38 0C 73 03 10 FE FF 4A ......p.8.s....J
40000000000F7440 0B 70 00 1E B8 10 E0 20 38 00 42 00 00 00 04 00 .p..... 8.B.....
40000000000F7450 0B 70 00 1C 10 10 00 00 00 02 00 E0 40 70 18 50 .p..........@p.P
40000000000F7460 E9 80 40 18 00 E1 F1 00 3C 70 21 00 00 00 04 00 ..@.....<p!.....
40000000000F7470 E2 70 00 20 B8 D0 F1 20 3C 00 C2 C3 81 71 00 84 .p. ... <....q..
40000000000F7480 EB 80 00 1E 10 D0 E1 00 38 30 A0 23 02 84 B8 80 ........80.#....
40000000000F7490 E9 80 00 1C 10 D0 01 88 3C 20 23 00 00 00 04 00 ........< #.....
40000000000F74A0 09 00 00 00 01 C0 01 01 42 5C 40 00 00 00 04 00 ........B\@.....
40000000000F74B0 F0 00 40 1C 90 11 00 00 00 02 00 00 90 FD FF 48 ..@............H
40000000000F74C0 11 50 01 4A 00 21 60 FA F3 FF 4F 00 08 9A F7 58 .P.J.!`...O....X
40000000000F74D0 09 08 E0 18 00 21 00 00 00 02 00 40 05 28 01 84 .....!.....@.(..
40000000000F74E0 11 08 00 02 18 10 00 00 00 02 00 00 08 33 F2 58 .............3.X
40000000000F74F0 09 00 00 00 01 00 10 C0 31 00 42 00 00 00 04 00 ........1.B.....
40000000000F7500 10 08 00 02 18 10 00 00 00 02 00 00 80 FB FF 48 ...............H
40000000000F7510 08 50 01 4C 00 21 00 00 00 02 00 60 F5 E7 FF 9F .P.L.!.....`....
40000000000F7520 19 30 FD F9 FF 27 00 00 00 02 00 00 E8 98 FE 58 .0...'.........X
40000000000F7530 09 00 00 00 01 00 10 C0 31 00 42 00 00 00 04 00 ........1.B.....
40000000000F7540 11 08 00 02 18 10 00 00 00 02 00 00 40 FB FF 48 ............@..H
40000000000F7550 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000F7560 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000F7570 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; parse_string: 40000000000F7580
;;   Called from:
;;     400000000003E77C (in xparse_dolparen)
parse_string proc
	{ alloc	r40,ar.pfs,0xD,0x0,0x9; adds	r16,0x8,r12; nop.b	0x0 }
	{ adds	r12,0xFFFFFFFFFFFFFFB0,r12; addl	r43,-8396,r1; mov	r39,b7; }
	{ st8.spill	[r1],r16; adds	r14,0x20,r12; adds	r15,0x30,r12 }
	{ adds	r16,0x28,r12; ld8	r43,[r43]; addp4	r42,r34,r0; }
	{ st8	[r32],r14; st4	[r34],r15; nop.i	0x0 }
	{ adds	r41,0x0,r32; adds	r37,0x18,r12; adds	r36,0x0,r0; }
	{ st8	[r35],r16; nop.i	0x0; br.call.sptk.many	b0,fn40000000000F5E00; }
	{ adds	r1,0x58,r12; nop.m	0x0; adds	r41,0x0,r0; }
	{ ld8	r1,[r1]; addl	r38,6532,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,push_stream; }
	{ adds	r14,0x20,r12; adds	r15,0x40,r12; adds	r1,0x58,r12 }
	{ adds	r42,0x0,r33; ld8	r16,[r38]; nop.i	0x0 }
	{ ld8	r1,[r1]; st4.rel	[r0],r37; nop.i	0x0; }
	{ nop.m	0x0; ld8	r41,[r14]; nop.i	0x0 }
	{ st8	[r16],r15; nop.m	0x0; br.call.sptk.many	b0,with_input_from_string; }
	{ nop.m	0x0; adds	r1,0x58,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0; }

l40000000000F7690:
	{ addl	r15,6188,r1; addl	r41,25252,r1; addl	r42,1,r0; }
	{ ld8	r15,[r15]; ld8	r14,[r15]; nop.i	0x0; }
	{ ld1	r15,[r14]; nop.m	0x0; sxt1	r15,r15; }
	{ cmp4.eq	p07,p06,0x0,r15; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000F77D0; }

l40000000000F76D0:
	{ adds	r14,0x10,r12; nop.m	0x0; nop.i	0x0; }
	{ st8.rel	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BD60; }
	{ cmp4.eq	p06,p07,0x0,r8; adds	r1,0x58,r12; nop.i	0x0 }
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r8; adds	r15,0x18,r12; adds	r36,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F7900; }

l40000000000F7720:
	{ st4.rel	[r0],r15; cmp4.ltu	p06,p07,0x3,r14; (p06) br.cond.dptk.few	40000000000F78B0 }

l40000000000F7730:
	{ adds	r16,0x10,r12; ld8.acq	r14,[r16]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F7780; }

l40000000000F7750:
	{ ld8.acq	r41,[r16]; nop.i	0x0; br.call.sptk.many	b0,dispose_command; }
	{ nop.m	0x0; adds	r1,0x58,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0 }

l40000000000F7780:
	{ addl	r15,1,r0; nop.m	0x0; adds	r14,0x18,r12; }
	{ st4.rel	[r15],r14; nop.m	0x0; nop.i	0x0 }

l40000000000F77A0:
	{ addl	r14,22532,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; adds	r14,0x10,r14; nop.i	0x0; }
	{ ld8	r14,[r14]; nop.m	0x0; nop.i	0x0 }

l40000000000F77D0:
	{ adds	r15,0x28,r12; adds	r16,0x20,r12; addl	r41,-8396,r1; }
	{ ld8	r15,[r15]; ld4	r16,[r16]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r15; addl	r15,6532,r1; sub	r37,r14,r16 }
	{ adds	r16,0x40,r12; ld8	r41,[r41]; nop.i	0x0; }
	{ nop.m	0x0; ld8	r16,[r16]; nop.i	0x0; }
	{ st8	[r16],r15; nop.m	0x0; (p07) adds	r15,0x28,r12; }

l40000000000F7830:
	{ nop.m	0x0; (p07) ld8	r15,[r15]; nop.i	0x0; }

l40000000000F783C:
	{ Invalid; Invalid; break.i	0x1000 }

l40000000000F7846:
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ add	r0,r0,r1; nop; (p32) nop }
	{ fwb; nop; break.b	0x80000 }
	{ Invalid; cmp4.eq	p00,p00,r0,r1; (p17) nop }

l40000000000F7886:
	{ chk.a.nc	f0,3FFFFFFFFF0F8086; Invalid; nop }

l40000000000F7890:
	{ adds	r8,0x0,r37; mov.i	ar.pfs,r40; mov.spnt	b0,r39,40000000000F7890 }
	{ nop.m	0x0; adds	r12,0x50,r12; br.ret	b0 }

l40000000000F78B0:
	{ addl	r41,-8388,r1; nop.m	0x0; addl	r42,3,r0 }
	{ adds	r43,0x0,r8; nop.m	0x0; adds	r44,0x0,r0; }
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,command_error; }
	{ nop.m	0x0; adds	r1,0x58,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0 }

l40000000000F7900:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,parse_command; }
	{ adds	r1,0x58,r12; nop.m	0x0; cmp4.eq	p07,p06,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F7A00; }

l40000000000F7930:
	{ addl	r14,6532,r1; nop.m	0x0; nop.i	0x0; }
	{ ld8	r41,[r14]; nop.i	0x0; br.call.sptk.many	b0,dispose_command; }
	{ nop.m	0x0; adds	r1,0x58,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; addl	r15,8996,r1; addl	r16,6532,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4	r14,[r15]; st8	[r0],r16; addl	r15,304,r0 }
	{ nop.m	0x0; addl	r16,8956,r1; nop.i	0x0; }
	{ cmp4.eq	p07,p06,r15,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000F77A0; }

l40000000000F79B0:
	{ nop.m	0x0; ld4	r15,[r16]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r15,r14; (p06) br.cond.dptk.few	40000000000F7690 }

l40000000000F79D0:
	{ addl	r14,22532,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; adds	r14,0x10,r14; nop.i	0x0; }
	{ ld8	r14,[r14]; nop.i	0x0; br.cond.sptk.few	40000000000F77D0; }

l40000000000F7A00:
	{ adds	r16,0x30,r12; addl	r15,1,r0; adds	r14,0x18,r12; }
	{ nop.m	0x0; ld4	r16,[r16]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r16,0x6; (p06) br.cond.dpnt.few	40000000000F7A50; }

l40000000000F7A30:
	{ nop.m	0x0; addl	r36,2,r0; nop.i	0x0 }
	{ st4.rel	[r15],r14; nop.m	0x0; br.cond.sptk.few	40000000000F77A0 }

l40000000000F7A50:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,reset_parser; }
	{ adds	r1,0x58,r12; adds	r15,0x28,r12; adds	r16,0x20,r12; }
	{ ld8	r1,[r1]; ld8	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; addl	r14,22532,r1; cmp.eq	p06,p07,0x0,r15 }
	{ ld4	r16,[r16]; addl	r15,6532,r1; addl	r41,-8396,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ adds	r14,0x10,r14; ld8	r41,[r41]; nop.i	0x0; }
	{ ld8	r14,[r14]; sub	r37,r14,r16; adds	r16,0x40,r12; }
	{ ld8	r16,[r16]; st8	[r16],r15; (p07) adds	r15,0x28,r12; }

l40000000000F7AE0:
	{ nop.m	0x0; (p07) ld8	r15,[r15]; nop.i	0x0; }

l40000000000F7AEC:
	{ Invalid; Invalid; break.i	0x1000 }

l40000000000F7AF6:
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ add	r0,r0,r1; nop; (p32) nop }
	{ fwb; nop; break.b	0x80000 }
	{ Invalid; cmp4.eq	p00,p00,r0,r1; (p17) nop }

l40000000000F7B36:
	{ chk.a.nc	f0,3FFFFFFFFF0F8336; Invalid; nop }

l40000000000F7B40:
	{ adds	r8,0x0,r37; mov.i	ar.pfs,r40; mov.spnt	b0,r39,40000000000F7B40 }
	{ nop.m	0x0; adds	r12,0x50,r12; br.ret	b0; }
40000000000F7B60 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000F7B70 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; fn40000000000F7B80: 40000000000F7B80
;;   Called from:
;;     40000000000F7F2C (in exec_builtin)
;;     40000000000F84AC (in exec_builtin)
fn40000000000F7B80 proc
	{ alloc	r35,ar.pfs,0x7,0x0,0x5; nop.m	0x0; mov	r34,b2 }
	{ adds	r36,0x0,r1; nop.m	0x0; adds	r37,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r36; adds	r37,0x2,r8; br.call.sptk.many	b0,xmalloc; }
	{ addl	r14,45,r0; adds	r37,0x0,r8; nop.i	0x0 }
	{ adds	r1,0x0,r36; adds	r33,0x0,r8; adds	r38,0x0,r32; }
	{ st1	[r37],r1,1; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r36; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000F7C00; br.ret	b0; }
40000000000F7C10 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000F7C20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000F7C30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; exec_builtin: 40000000000F7C40
exec_builtin proc
	{ alloc	r40,ar.pfs,0xF,0x0,0xB; addl	r33,8876,r1; nop.b	0x0 }
	{ addl	r37,9252,r1; adds	r41,0x0,r1; mov	r42,pr; }
	{ nop.m	0x0; adds	r34,0x0,r0; mov	r39,b7 }
	{ adds	r36,0x0,r0; nop.m	0x0; adds	r35,0x0,r0; }
	{ st8	[r0],r33; br.call.sptk.many	b0,reset_internal_getopt; nop.b	0x0; }
	{ adds	r1,0x0,r41; nop.m	0x0; nop.i	0x0; }

l40000000000F7CA0:
	{ addl	r44,-748,r1; nop.m	0x0; adds	r43,0x0,r32; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r41; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dpnt.few	40000000000F7D70; }

l40000000000F7CD0:
	{ cmp4.eq	p06,p07,0x63,r8; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F82F0; }

l40000000000F7CE0:
	{ cmp4.eq	p06,p07,0x6C,r8; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F7D40; }

l40000000000F7CF0:
	{ cmp4.eq	p06,p07,0x61,r8; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F8300; }

l40000000000F7D00:
	{ nop.m	0x0; addl	r33,258,r0; br.call.sptk.many	b0,builtin_usage; }
	{ adds	r1,0x0,r41; nop.m	0x0; nop.i	0x0 }

l40000000000F7D20:
	{ adds	r8,0x0,r33; mov	pr,r42,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000F7D30; br.ret	b0 }

l40000000000F7D40:
	{ addl	r44,-748,r1; adds	r43,0x0,r32; addl	r36,1,r0; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r41; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p06) br.cond.dptk.few	40000000000F7CD0; }

l40000000000F7D70:
	{ addl	r37,7068,r1; nop.m	0x0; addl	r14,9268,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld8	r43,[r37]; nop.i	0x0 }
	{ ld8	r38,[r14]; nop.m	0x0; br.call.sptk.many	b0,dispose_redirects; }
	{ adds	r1,0x0,r41; st8	[r0],r37; cmp.eq	p06,p07,0x0,r38 }
	{ adds	r43,0x0,r38; addl	r44,1,r0; (p06) br.cond.dpnt.few	40000000000F8520; }

l40000000000F7DD0:
	{ addl	r14,7352,r1; adds	r45,0x0,r0; adds	r46,0x0,r0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000F8310; }

l40000000000F7E00:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strvec_from_word_list; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r37,0x0,r8 }
	{ ld8	r43,[r8]; nop.m	0x0; br.call.sptk.many	b0,absolute_program; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r8; adds	r1,0x0,r41 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000F8400; }

l40000000000F7E50:
	{ (p07) ld8	r38,[r37]; nop.m	0x0; nop.i	0x0; }

l40000000000F7E56:
	{ break.m	0x4000; nop; (p48) nop }

l40000000000F7E60:
	{ cmp.eq	p07,p06,0x0,r38; adds	r43,0x0,r38; (p07) br.cond.dpnt.few	40000000000F8550; }

l40000000000F7E70:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,full_pathname; }
	{ adds	r1,0x0,r41; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	40000000000F7EE0; }

l40000000000F7E90:
	{ ld8	r14,[r37]; cmp.eq	p06,p07,r14,r38; nop.i	0x0; }
	{ (p06) adds	r38,0x0,r8; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F7EE0; }

l40000000000F7EA6:
	{ chk.a.nc	r0,3FFFFFFFFF0F86A6; nop; break.i	0x80000 }

l40000000000F7EB0:
	{ nop.m	0x0; adds	r43,0x0,r38; adds	r38,0x0,r8 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r41; nop.m	0x0; nop.i	0x0 }

l40000000000F7EE0:
	{ cmp.eq	p06,p07,0x0,r34; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F8490; }

l40000000000F7EF0:
	{ ld8	r43,[r37]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r41; adds	r43,0x0,r34 }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r36; (p06) br.cond.dptk.few	40000000000F8350 }

l40000000000F7F20:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000F7B80; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r43,0x0,r8 }
	{ st8	[r8],r37; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r41; adds	r43,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r43,0x0,r8 }
	{ ld8	r44,[r37]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r41; st8	[r8],r33; nop.i	0x0 }

l40000000000F7F90:
	{ nop.m	0x0; cmp4.eq	p17,p16,0x0,r35; nop.i	0x0; }
	{ (p17) addl	r43,-1,r0; (p16) adds	r33,0x0,r0; (p17) br.call.dpnt.many	b0,adjust_shell_level; }

l40000000000F7FA6:
	{ Invalid; Invalid; Invalid }

l40000000000F7FAC:
	{ (p03) nop; invala; Invalid }

l40000000000F7FB0:
	{ (p17) adds	r1,0x0,r41; nop.i	0x0; (p17) br.call.dpnt.many	b0,maybe_make_export_env; }

l40000000000F7FB6:
	{ nop; (p32) shrp	r113,r98,r125,45; (p20) nop }

l40000000000F7FC0:
	{ (p17) adds	r1,0x0,r41; (p17) addl	r14,7116,r1; addl	r34,9028,r1; }

l40000000000F7FC6:
	{ Invalid; break.x	0x88C0622280000 }

l40000000000F7FCC:
	{ (p34) nop; break.x	0x8000001000 }
	{ nop; Invalid; cmp.lt	p00,p00,r32,r0 }

l40000000000F7FE6:
	{ break.m	0x4000; (p07) nop; break.i	0x80000 }
	{ (p07) fwb; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFDBB8E6; nop; break.i	0x80000 }

l40000000000F8010:
	{ nop.m	0x0; ld4	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000F8440 }

l40000000000F8030:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,restore_original_signals; }
	{ ld4	r14,[r34]; nop.m	0x0; adds	r1,0x0,r41; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000F8420 }

l40000000000F8060:
	{ adds	r43,0x0,r38; nop.m	0x0; adds	r45,0x0,r33 }
	{ adds	r44,0x0,r37; nop.m	0x0; br.call.sptk.many	b0,shell_execve; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r33,0x0,r8 }
	{ (p17) addl	r43,1,r0; nop.m	0x0; (p17) br.call.dpnt.many	b0,adjust_shell_level; }

l40000000000F8096:
	{ nop; (p32) nop; (p32) nop }

l40000000000F80A0:
	{ cmp4.eq	p06,p07,0x7F,r33; nop.m	0x0; (p17) adds	r1,0x0,r41 }

l40000000000F80B0:
	{ adds	r43,0x0,r38; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000F8170; }

l40000000000F80C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,executable_file; }
	{ adds	r1,0x0,r41; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000000F84F0; }

l40000000000F80E0:
	{ addl	r44,-740,r1; nop.m	0x0; addl	r45,5,r0 }
	{ adds	r43,0x0,r0; nop.m	0x0; addl	r33,126,r0; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r41; adds	r35,0x0,r8; br.call.sptk.many	b0,fn400000000001B840; }
	{ nop.m	0x0; adds	r1,0x0,r41; nop.i	0x0 }
	{ ld4	r43,[r8]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B4A0; }
	{ adds	r1,0x0,r41; adds	r43,0x0,r35; nop.i	0x0 }
	{ adds	r44,0x0,r38; adds	r45,0x0,r8; br.call.sptk.many	b0,builtin_error; }
	{ adds	r1,0x0,r41; nop.m	0x0; nop.i	0x0 }

l40000000000F8170:
	{ nop.m	0x0; adds	r43,0x0,r38; adds	r37,0x0,r0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r41; nop.m	0x0; nop.i	0x0 }

l40000000000F81A0:
	{ nop.m	0x0; ld4	r14,[r34]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; addl	r14,6516,r1; (p06) br.cond.spnt.few	40000000000F8630; }

l40000000000F81C0:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000F8210 }

l40000000000F81E0:
	{ addl	r14,9240,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.spnt.few	40000000000F8630; }

l40000000000F8210:
	{ cmp.eq	p06,p07,0x0,r37; adds	r43,0x0,r37; (p06) br.cond.dpnt.few	40000000000F8240; }

l40000000000F8220:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strvec_dispose; }
	{ adds	r1,0x0,r41; nop.m	0x0; nop.i	0x0 }

l40000000000F8240:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,initialize_traps; }
	{ adds	r1,0x0,r41; addl	r43,1,r0; br.call.sptk.many	b0,initialize_signals; }
	{ adds	r1,0x0,r41; addl	r14,6512,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; addl	r14,5868,r1; (p06) br.cond.dpnt.few	40000000000F82B0; }

l40000000000F8290:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000F7D20 }

l40000000000F82B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,restart_job_control; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r41; mov	pr,r42,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r40; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000F82E0; br.ret	b0 }

l40000000000F82F0:
	{ nop.m	0x0; addl	r35,1,r0; br.cond.sptk.few	40000000000F7CA0 }

l40000000000F8300:
	{ ld8	r34,[r37]; nop.i	0x0; br.cond.sptk.few	40000000000F7CA0; }

l40000000000F8310:
	{ adds	r43,0x0,r0; addl	r33,1,r0; br.call.sptk.many	b0,sh_restricted; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r41; mov	pr,r42,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r40; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000F8340; br.ret	b0; }

l40000000000F8350:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r41; adds	r43,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r44,0x0,r34; nop.m	0x0; adds	r1,0x0,r41 }
	{ adds	r43,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r43,0x0,r8 }
	{ st8	[r8],r37; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r41; adds	r43,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r43,0x0,r8 }
	{ ld8	r44,[r37]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; adds	r1,0x0,r41; nop.i	0x0 }
	{ st8	[r8],r33; nop.m	0x0; br.cond.sptk.few	40000000000F7F90 }

l40000000000F8400:
	{ ld8	r43,[r37]; nop.i	0x0; br.call.sptk.many	b0,search_for_command; }
	{ adds	r1,0x0,r41; adds	r38,0x0,r8; br.cond.sptk.few	40000000000F7E60 }

l40000000000F8420:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,end_job_control; }
	{ nop.m	0x0; adds	r1,0x0,r41; br.cond.sptk.few	40000000000F8060 }

l40000000000F8440:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,maybe_save_shell_history; }
	{ adds	r1,0x0,r41; nop.i	0x0; br.call.sptk.many	b0,restore_original_signals; }
	{ ld4	r14,[r34]; nop.m	0x0; adds	r1,0x0,r41; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000F8060 }

l40000000000F8480:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000F8420; }

l40000000000F8490:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r36; (p06) br.cond.dptk.few	40000000000F7F90 }

l40000000000F84A0:
	{ ld8	r43,[r37]; nop.i	0x0; br.call.sptk.many	b0,fn40000000000F7B80; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r33,0x0,r8 }
	{ ld8	r43,[r37]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r41; nop.i	0x0 }
	{ st8	[r33],r37; nop.m	0x0; br.cond.sptk.few	40000000000F7F90 }

l40000000000F84F0:
	{ adds	r43,0x0,r38; adds	r37,0x0,r0; br.call.sptk.many	b0,file_error; }
	{ adds	r1,0x0,r41; adds	r43,0x0,r38; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r41; br.cond.sptk.few	40000000000F81A0 }

l40000000000F8520:
	{ adds	r33,0x0,r0; nop.m	0x0; mov	pr,r42,0xFFFFFFFFFFFFFFFE; }
	{ adds	r8,0x0,r33; nop.m	0x0; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000F8540; br.ret	b0; }

l40000000000F8550:
	{ ld8	r43,[r37]; nop.i	0x0; br.call.sptk.many	b0,file_isdir; }
	{ adds	r1,0x0,r41; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	40000000000F8600; }

l40000000000F8570:
	{ addl	r44,-740,r1; nop.m	0x0; addl	r45,5,r0 }
	{ adds	r43,0x0,r0; nop.m	0x0; addl	r33,126,r0; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r36,0x0,r8 }
	{ ld8	r35,[r37]; addl	r43,21,r0; addl	r34,9028,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B4A0; }
	{ adds	r1,0x0,r41; adds	r43,0x0,r36; nop.i	0x0 }
	{ adds	r44,0x0,r35; adds	r45,0x0,r8; br.call.sptk.many	b0,builtin_error; }
	{ nop.m	0x0; adds	r1,0x0,r41; br.cond.sptk.few	40000000000F81A0; }

l40000000000F8600:
	{ addl	r34,9028,r1; ld8	r43,[r37]; addl	r33,127,r0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_notfound; }
	{ nop.m	0x0; adds	r1,0x0,r41; br.cond.sptk.few	40000000000F81A0 }

l40000000000F8630:
	{ nop.m	0x0; adds	r43,0x0,r33; br.call.sptk.many	b0,exit_shell; }
	{ nop.m	0x0; break.f	0x0; nop.i	0x0; }
	{ nop.m	0x6; nop.i	0x7; nop.i	0x8 }
	{ nop.m	0x6; nop.i	0x7; nop.i	0x8 }
	{ nop.m	0x6; nop.i	0x7; nop.i	0x8 }

;; bash_logout: 40000000000F8680
;;   Called from:
;;     40000000000F867C (in exec_builtin)
;;     40000000000F881C (in fn40000000000F8780)
;;     40000000000F8C0C (in fn40000000000F8780)
bash_logout proc
	{ alloc	r33,ar.pfs,0x5,0x0,0x3; addl	r15,6520,r1; nop.b	0x0 }
	{ addl	r14,8420,r1; mov	r32,b0; adds	r34,0x0,r1; }
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r15; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000F8700; }

l40000000000F86C0:
	{ ld4	r15,[r14]; adds	r16,0x1,r15; cmp4.eq	p07,p06,0x0,r15; }
	{ st4	[r16],r14; addl	r14,9028,r1; (p06) br.cond.dpnt.few	40000000000F8700; }

l40000000000F86E0:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000F8720 }

l40000000000F8700:
	{ nop.m	0x0; mov.i	ar.pfs,r33; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r32,40000000000F8710; br.ret	b0 }

l40000000000F8720:
	{ addl	r35,-8300,r1; nop.m	0x0; addl	r36,1,r0; }
	{ ld8	r35,[r35]; nop.i	0x0; br.call.sptk.many	b0,maybe_execute_file; }
	{ adds	r1,0x0,r34; addl	r36,1,r0; addl	r35,-8292,r1; }
	{ ld8	r35,[r35]; nop.i	0x0; br.call.sptk.many	b0,maybe_execute_file; }
	{ adds	r1,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ nop.m	0x0; mov.spnt	b0,r32,40000000000F8770; br.ret	b0; }

;; fn40000000000F8780: 40000000000F8780
;;   Called from:
;;     40000000000F8CDC (in logout_builtin)
;;     40000000000F8E26 (in exit_builtin)
fn40000000000F8780 proc
	{ alloc	r38,ar.pfs,0xC,0x0,0x9; addl	r14,6516,r1; mov	r40,LC }
	{ adds	r39,0x0,r1; nop.m	0x0; mov	r37,b5; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	40000000000F8850 }

l40000000000F87C0:
	{ addl	r14,9124,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x1,r14; (p06) br.cond.dptk.few	40000000000F8800; }

l40000000000F87F0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r32; (p06) br.cond.dpnt.few	40000000000F8BF0 }

l40000000000F8800:
	{ adds	r41,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,get_exitstat; }
	{ adds	r1,0x0,r39; adds	r33,0x0,r8; br.call.sptk.many	b0,bash_logout; }
	{ adds	r1,0x0,r39; addl	r41,3,r0; addl	r14,9044,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r33],r14; nop.i	0x0; br.call.sptk.many	b0,jump_to_top_level }

l40000000000F8850:
	{ addl	r35,8396,r1; addl	r34,-9972,r1; nop.i	0x0 }
	{ addl	r15,-9876,r1; addl	r33,6504,r1; adds	r18,0x0,r0; }
	{ nop.m	0x0; ld8	r34,[r34]; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r35]; nop.i	0x0; }
	{ cmp.eq	p06,p07,r34,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F87C0; }

l40000000000F88A0:
	{ nop.m	0x0; ld8	r15,[r15]; nop.i	0x0; }
	{ cmp.eq	p06,p07,r15,r14; addl	r15,-9716,r1; (p06) br.cond.dpnt.few	40000000000F87C0; }

l40000000000F88C0:
	{ ld8	r15,[r15]; nop.i	0x0; cmp.eq	p06,p07,r15,r14 }
	{ addl	r14,-20676,r1; addl	r15,7444,r1; (p06) br.cond.dpnt.few	40000000000F87C0; }

l40000000000F88E0:
	{ nop.m	0x0; adds	r14,0x1C,r14; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.lt	p07,p06,0x0,r14; adds	r14,0xFFFFFFFFFFFFFFFF,r14; (p06) br.cond.dpnt.few	40000000000F87C0; }

l40000000000F8910:
	{ nop.m	0x0; nop.m	0x0; addp4	r14,r14,r0 }
	{ nop.m	0x0; nop.m	0x0; mov.i	LC,r14; }
	{ ld4	r17,[r33]; ld8	r16,[r15]; nop.i	0x0; }
	{ nop.m	0x0; adds	r15,0x8,r16; cmp4.eq	p10,p11,0x0,r17; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000F8960:
	{ ld8	r14,[r16]; nop.m	0x0; adds	r16,0x0,r15; }
	{ adds	r17,0x14,r14; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	40000000000F89A0; }

l40000000000F8980:
	{ ld4	r17,[r17]; cmp4.eq	p08,p09,0x2,r17; nop.i	0x0; }
	{ nop.m	0x0; (p08) addl	r18,2,r0; (p08) br.cond.dpnt.few	40000000000F8A00 }

l40000000000F899C:
	{ Invalid; break.i	0x1000; break.b	0x1000 }

l40000000000F89A0:
	{ nop.m	0x0; nop.i	0x0; (p10) br.cond.dptk.few	40000000000F8A00; }

l40000000000F89B0:
	{ nop.m	0x0; cmp4.eq	p09,p08,0x0,r18; (p08) br.cond.dptk.few	40000000000F8A00 }

l40000000000F89C0:
	{ adds	r14,0x14,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F8A00; }

l40000000000F89D0:
	{ ld4	r18,[r14]; cmp4.eq	p06,p07,0x1,r18; nop.i	0x0; }
	{ (p06) addl	r18,1,r0; nop.i	0x0; (p07) adds	r18,0x0,r0; }

l40000000000F89E6:
	{ chk.a.nc	f0,3FFFFFFFFF0F91E6; (p09) nop; break.i	0x80000 }

l40000000000F89F0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000F8A00:
	{ nop.m	0x0; nop.i	0x0; br.cloop.sptk.few	40000000000F8AF0; }

l40000000000F8A10:
	{ cmp4.eq	p07,p06,0x2,r18; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000F8B60; }

l40000000000F8A20:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x1,r18; (p06) br.cond.dptk.few	40000000000F87C0 }

l40000000000F8A30:
	{ addl	r14,-10652,r1; nop.m	0x0; addl	r42,-8276,r1 }
	{ addl	r43,5,r0; nop.m	0x0; adds	r41,0x0,r0; }
	{ ld8	r14,[r14]; ld8	r42,[r42]; nop.i	0x0; }
	{ ld8	r36,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r39; adds	r41,0x0,r36; nop.i	0x0 }
	{ addl	r42,1,r0; adds	r43,0x0,r8; br.call.sptk.many	b0,fn400000000001C040; }
	{ ld4	r14,[r33]; nop.m	0x0; adds	r1,0x0,r39; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000F8B00 }

l40000000000F8AB0:
	{ addl	r14,8388,r1; addl	r8,1,r0; nop.b	0x0 }
	{ st8	[r34],r35; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.i	LC,r40; mov.spnt	b0,r37,40000000000F8AD0; }
	{ st8	[r34],r14; nop.i	0x0; br.ret	b0 }

l40000000000F8AF0:
	{ nop.m	0x0; adds	r15,0x8,r15; br.cond.sptk.few	40000000000F8960; }

l40000000000F8B00:
	{ adds	r41,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,list_all_jobs; }
	{ adds	r1,0x0,r39; addl	r8,1,r0; nop.b	0x0 }
	{ st8	[r34],r35; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ addl	r14,8388,r1; nop.m	0x0; mov.i	LC,r40; }
	{ nop.m	0x0; nop.m	0x0; mov.spnt	b0,r37,40000000000F8B40; }
	{ st8	[r34],r14; nop.i	0x0; br.ret	b0 }

l40000000000F8B60:
	{ addl	r14,-10652,r1; nop.m	0x0; addl	r42,-8284,r1 }
	{ addl	r43,5,r0; nop.m	0x0; adds	r41,0x0,r0; }
	{ ld8	r14,[r14]; ld8	r42,[r42]; nop.i	0x0; }
	{ ld8	r36,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r39; adds	r41,0x0,r36; nop.i	0x0 }
	{ addl	r42,1,r0; adds	r43,0x0,r8; br.call.sptk.many	b0,fn400000000001C040; }
	{ ld4	r14,[r33]; nop.m	0x0; adds	r1,0x0,r39; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000F8AB0 }

l40000000000F8BE0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000F8B00 }

l40000000000F8BF0:
	{ addl	r14,9128,r1; nop.m	0x0; nop.i	0x0; }
	{ ld4	r33,[r14]; nop.i	0x0; br.call.sptk.many	b0,bash_logout; }
	{ adds	r1,0x0,r39; addl	r41,3,r0; addl	r14,9044,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r33],r14; nop.i	0x0; br.call.sptk.many	b0,jump_to_top_level; }
	{ nop.m	0x0; break.f	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

;; logout_builtin: 40000000000F8C80
;;   Called from:
;;     40000000000F8C7C (in fn40000000000F8780)
logout_builtin proc
	{ alloc	r34,ar.pfs,0x7,0x0,0x4; addl	r14,6520,r1; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000F8CA0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000F8CE0; }

l40000000000F8CD0:
	{ alloc	r2,ar.pfs,0x1,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000F8780 }

l40000000000F8CE0:
	{ addl	r37,-8268,r1; addl	r38,5,r0; adds	r36,0x0,r0; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r35; adds	r36,0x0,r8; br.call.sptk.many	b0,builtin_error; }
	{ addl	r8,1,r0; adds	r1,0x0,r35; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000F8D20; br.ret	b0; }
40000000000F8D30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; exit_builtin: 40000000000F8D40
exit_builtin proc
	{ alloc	r36,ar.pfs,0x9,0x0,0x6; addl	r14,6516,r1; mov	r35,b3 }
	{ addl	r33,-10652,r1; addl	r40,-8260,r1; adds	r37,0x0,r1; }
	{ nop.m	0x0; nop.m	0x0; addl	r39,1,r0 }
	{ ld8	r33,[r33]; ld8	r40,[r40]; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; addl	r14,6520,r1; (p06) br.cond.dpnt.few	40000000000F8E10; }

l40000000000F8DA0:
	{ nop.m	0x0; ld8	r34,[r33]; nop.i	0x0; }
	{ adds	r38,0x0,r34; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000F8E30; }

l40000000000F8DD0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ nop.m	0x0; adds	r1,0x0,r37; nop.i	0x0 }
	{ ld8	r38,[r33]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ adds	r1,0x0,r37; nop.m	0x0; nop.i	0x0 }

l40000000000F8E10:
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000F8E10; mov.i	ar.pfs,r36; }
	{ alloc	r2,ar.pfs,0x1,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000F8780 }

l40000000000F8E30:
	{ addl	r39,-8252,r1; adds	r38,0x0,r0; addl	r40,5,r0; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r37; adds	r40,0x0,r8; nop.i	0x0 }
	{ adds	r38,0x0,r34; addl	r39,1,r0; br.call.sptk.many	b0,fn400000000001C040; }
	{ nop.m	0x0; adds	r1,0x0,r37; nop.i	0x0 }
	{ ld8	r38,[r33]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ nop.m	0x0; adds	r1,0x0,r37; br.cond.sptk.few	40000000000F8E10; }
40000000000F8EA0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000F8EB0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; fn40000000000F8EC0: 40000000000F8EC0
;;   Called from:
;;     40000000000F987C (in fc_builtin)
;;     40000000000F9E0C (in fc_builtin)
;;     40000000000F9E5C (in fc_builtin)
fn40000000000F8EC0 proc
	{ alloc	r38,ar.pfs,0xC,0x0,0x9; ld8	r16,[r33]; nop.b	0x0 }
	{ adds	r15,0x8,r33; mov	r40,LC; adds	r39,0x0,r1; }
	{ adds	r14,0x0,r0; cmp.eq	p06,p07,0x0,r16; mov	r37,b5; }
	{ nop.m	0x0; (p06) adds	r14,0x0,r0; (p06) br.cond.dpnt.few	40000000000F8F20; }

l40000000000F8EFC:
	{ (p01) nop; (p02) mov.i	KR6,0x3; Invalid }

l40000000000F8F00:
	{ ld8	r16,[r15],8; nop.m	0x0; adds	r14,0x1,r14; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r16; (p06) br.cond.dptk.few	40000000000F8F00 }

l40000000000F8F20:
	{ addl	r15,6116,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	40000000000F8FB0 }

l40000000000F8F50:
	{ addl	r15,9028,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r15,0x2; (p07) br.cond.dptk.few	40000000000F9170 }

l40000000000F8F80:
	{ addl	r15,6112,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	40000000000F9170 }

l40000000000F8FB0:
	{ addl	r15,9160,r1; nop.m	0x0; addl	r36,1,r0; }
	{ nop.m	0x0; nop.m	0x0; sub	r36,r14,r36; }
	{ ld4	r15,[r15]; sub	r36,r36,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r36,r14; (p07) br.cond.dpnt.few	40000000000F91B0; }

l40000000000F8FF0:
	{ nop.m	0x0; cmp4.lt	p06,p07,r36,r0; (p06) br.cond.spnt.few	40000000000F9100; }

l40000000000F9000:
	{ cmp.eq	p06,p07,0x0,r32; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F9330; }

l40000000000F9010:
	{ ld1	r14,[r32]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x2D,r14; nop.m	0x0; adds	r35,0x0,r14 }
	{ adds	r14,0xFFFFFFFFFFFFFFD0,r14; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000F92D0; }

l40000000000F9040:
	{ nop.m	0x0; zxt1	r14,r14; (p06) adds	r41,0x0,r32 }

l40000000000F9050:
	{ nop.m	0x0; (p06) addl	r34,1,r0; nop.b	0x0; }

l40000000000F905C:
	{ invala; cmp.lt	p00,p00,r32,r0; (p16) mov	pr,r99,0xD684 }
	{ (p14) nop; (p05) dep	r0,r8,r64,62,1; zxt1	r0,r64 }

l40000000000F9070:
	{ adds	r41,0x0,r32; adds	r34,0x0,r36; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; sxt4	r15,r36; adds	r1,0x0,r39 }
	{ cmp4.eq	p06,p07,0x0,r8; addp4	r14,r34,r0; (p06) br.cond.dpnt.few	40000000000F9330; }

l40000000000F90A0:
	{ shladd	r33,r15,0x3,r33; mov.i	LC,r14; sxt4	r36,r8; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000F90C0:
	{ ld8	r14,[r33],-8; ld8	r42,[r14]; nop.i	0x0; }
	{ ld1	r14,[r42]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r35; (p07) br.cond.dpnt.few	40000000000F9130 }

l40000000000F90F0:
	{ nop.m	0x0; adds	r34,0xFFFFFFFFFFFFFFFF,r34; br.cloop.sptk.few	40000000000F90C0 }

l40000000000F9100:
	{ addl	r8,-1,r0; nop.m	0x0; nop.i	0x0 }

l40000000000F9110:
	{ nop.m	0x0; mov.i	ar.pfs,r38; mov.i	LC,r40; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000F9120; br.ret	b0; }

l40000000000F9130:
	{ adds	r41,0x0,r32; adds	r43,0x0,r36; br.call.sptk.many	b0,fn400000000001C020; }
	{ adds	r1,0x0,r39; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	40000000000F90F0 }

l40000000000F9150:
	{ adds	r8,0x0,r34; mov.i	ar.pfs,r38; mov.i	LC,r40; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000F9160; br.ret	b0 }

l40000000000F9170:
	{ addl	r15,9160,r1; nop.m	0x0; adds	r36,0x0,r0; }
	{ nop.m	0x0; nop.m	0x0; sub	r36,r14,r36; }
	{ ld4	r15,[r15]; sub	r36,r36,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r36,r14; (p06) br.cond.dptk.few	40000000000F8FF0 }

l40000000000F91B0:
	{ nop.m	0x0; sxt4	r14,r36; shladd	r14,r14,0x3,r0; }
	{ add	r15,r33,r14; ld8	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	40000000000F9000 }

l40000000000F91E0:
	{ addp4	r15,r36,r0; adds	r14,0xFFFFFFFFFFFFFFF8,r14; adds	r36,0xFFFFFFFFFFFFFFFF,r36; }
	{ add	r14,r33,r14; nop.m	0x0; mov.i	LC,r15; }
	{ nop.m	0x0; nop.i	0x0; br.cloop.sptk.few	40000000000F9350 }

l40000000000F9210:
	{ nop.m	0x0; addl	r8,-1,r0; br.cond.sptk.few	40000000000F9110 }

l40000000000F9220:
	{ adds	r42,0x0,r0; addl	r43,10,r0; br.call.sptk.many	b0,fn400000000001C2A0; }
	{ setf.sig	f6,r34; setf.sig	f7,r8; adds	r1,0x0,r39; }
	{ nop.m	0x0; nop.m	0x0; xma.l	f6,f6,f7,f0; }
	{ nop.m	0x0; getf.sig	r8,f6; nop.i	0x0; }
	{ cmp4.lt	p07,p06,r8,r0; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000F9390; }

l40000000000F9270:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	40000000000F9330 }

l40000000000F9280:
	{ addl	r14,-10068,r1; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ ld8	r14,[r14]; mov.i	LC,r40; mov.spnt	b0,r37,40000000000F9290; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ sub	r8,r8,r14; nop.i	0x0; cmp4.lt	p07,p06,r8,r36; }
	{ nop.m	0x0; (p06) adds	r8,0x0,r36; br.ret	b0 }

l40000000000F92CC:
	{ nop; (p21) invala; dep	r0,r32,r0,63,1 }

l40000000000F92D0:
	{ adds	r41,0x1,r32; nop.m	0x0; addl	r34,-1,r0; }
	{ cmp.eq	p06,p07,0x0,r41; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F9070; }

l40000000000F92F0:
	{ ld1	r14,[r41]; nop.m	0x0; sxt1	r14,r14; }
	{ adds	r14,0xFFFFFFFFFFFFFFD0,r14; nop.m	0x0; zxt1	r14,r14; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x9,r14; (p06) br.cond.dptk.few	40000000000F9070 }

l40000000000F9320:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000F9220 }

l40000000000F9330:
	{ adds	r8,0x0,r36; mov.i	ar.pfs,r38; mov.i	LC,r40; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000F9340; br.ret	b0 }

l40000000000F9350:
	{ nop.m	0x0; ld8	r15,[r14],-8; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r15; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000F9000; }

l40000000000F9370:
	{ nop.m	0x0; adds	r36,0xFFFFFFFFFFFFFFFF,r36; br.cloop.sptk.few	40000000000F9350 }

l40000000000F9380:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000F9210; }

l40000000000F9390:
	{ add	r8,r36,r8,0x1; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ cmp4.lt	p07,p06,r8,r0; nop.m	0x0; mov.i	LC,r40; }
	{ (p07) adds	r8,0x0,r0; mov.spnt	b0,r37,40000000000F93B0; br.ret	b0; }

l40000000000F93B6:
	{ Invalid; (p34) nop; Invalid }

;; fc_builtin: 40000000000F93C0
fc_builtin proc
	{ alloc	r45,ar.pfs,0x17,0x0,0x11; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r48,LC }
	{ addl	r34,8692,r1; nop.m	0x0; adds	r46,0x0,r1; }
	{ nop.m	0x0; adds	r37,0x0,r0; mov	r47,pr }
	{ adds	r39,0x0,r0; adds	r36,0x0,r0; adds	r40,0x0,r0; }
	{ nop.m	0x0; mov	r44,b4; addl	r38,1,r0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,reset_internal_getopt; }
	{ adds	r1,0x0,r46; st8	[r32],r34; adds	r14,0x0,r32; }
	{ addl	r33,9268,r1; addl	r35,-2308,r1; nop.i	0x0 }
	{ addl	r41,9252,r1; nop.m	0x0; nop.i	0x0 }
	{ ld8	r35,[r35]; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; st8	[r14],r33; cmp.eq	p07,p06,0x0,r14 }
	{ adds	r14,0x8,r14; adds	r50,0x0,r0; (p07) br.cond.dpnt.few	40000000000F94D0; }

l40000000000F9480:
	{ ld8	r14,[r14]; ld8	r49,[r14]; nop.i	0x0; }
	{ nop.m	0x0; ld1	r14,[r49]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x2D,r14; }
	{ (p07) adds	r49,0x1,r49; nop.i	0x0; br.call.sptk.many	b0,legal_number; }

l40000000000F94B6:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ (p03) chk.a.clr	f0,3FFFFFFFFFDBCD46; nop; (p32) nop }

l40000000000F94D0:
	{ addl	r50,-2396,r1; nop.m	0x0; adds	r49,0x0,r32; }
	{ ld8	r50,[r50]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; nop.m	0x0; adds	r8,0xFFFFFFFFFFFFFF9B,r8 }
	{ adds	r1,0x0,r46; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000F9640; }

l40000000000F9510:
	{ nop.m	0x0; cmp4.ltu	p06,p07,0xE,r8; (p07) br.cond.dptk.few	40000000000F9570 }

l40000000000F9520:
	{ nop.m	0x0; addl	r33,258,r0; br.call.sptk.many	b0,builtin_usage; }
	{ adds	r1,0x0,r46; nop.m	0x0; nop.i	0x0 }

l40000000000F9540:
	{ adds	r8,0x0,r33; mov	pr,r47,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r45; }
	{ nop.m	0x0; mov.i	LC,r48; mov.spnt	b0,r44,40000000000F9550 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000F9570:
	{ addp4	r8,r8,r0; shladd	r8,r8,0x3,r35; nop.i	0x0; }
	{ ld8	r14,[r8]; add	r8,r8,r14; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r8,40000000000F9590; br.cond	b6; }
40000000000F95A0 08 00 00 00 01 00 70 0A 00 00 48 00 00 00 04 00 ......p...H.....
40000000000F95B0 19 70 00 44 18 10 00 00 00 02 00 00 B0 FE FF 48 .p.D...........H
40000000000F95C0 08 00 00 00 01 00 80 0A 00 00 48 00 00 00 04 00 ..........H.....
40000000000F95D0 19 70 00 44 18 10 00 00 00 02 00 00 90 FE FF 48 .p.D...........H
40000000000F95E0 08 00 00 00 01 00 60 02 00 00 42 00 00 00 04 00 ......`...B.....
40000000000F95F0 19 70 00 44 18 10 00 00 00 02 00 00 70 FE FF 48 .p.D........p..H
40000000000F9600 08 00 00 00 01 00 40 0A 00 00 48 00 00 00 04 00 ......@...H.....
40000000000F9610 19 70 00 44 18 10 00 00 00 02 00 00 50 FE FF 48 .p.D........P..H
40000000000F9620 08 00 00 00 01 00 50 02 A4 30 20 00 00 00 04 00 ......P..0 .....
40000000000F9630 19 70 00 44 18 10 00 00 00 02 00 00 30 FE FF 48 .p.D........0..H

l40000000000F9640:
	{ ld8	r35,[r33]; cmp.eq	p16,p17,0x0,r37; (p16) br.cond.dpnt.few	40000000000F9670; }

l40000000000F9650:
	{ ld1	r14,[r37]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r14; (p07) br.cond.dpnt.few	40000000000FA0B0; }

l40000000000F9670:
	{ cmp4.eq	p07,p06,0x0,r39; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000F9C50; }

l40000000000F9680:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p07) br.cond.dpnt.few	40000000000FA5A0; }

l40000000000F9690:
	{ (p06) adds	r38,0x0,r0; nop.m	0x0; nop.i	0x0; }

l40000000000F9696:
	{ break.m	0x4000; nop; nop }

l40000000000F96A0:
	{ adds	r36,0x8,r35; nop.m	0x0; addl	r50,61,r0; }

l40000000000F96A2:
	{ (p49) break.m	0x42008; nop; Invalid; }
	{ Invalid; break.i	0x20309; sub	r32,r0,r32,0x1 }
	{ (p32) break.m	0x20303; addl	r32,0,r0; (p63) nop; }
	{ invala; break.i	0x42002; Invalid }
	{ (p32) chk.a.nc	r11,3FFFFFFFFF501AE2; (p03) nop; Invalid }

l40000000000F96F0:
	{ st1	[r33],r1,1; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r14,[r36]; adds	r37,0x0,r8; adds	r34,0x0,r8 }
	{ adds	r1,0x0,r46; st8	[r37],r8,8; nop.i	0x0; }
	{ ld8	r49,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r46; adds	r49,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r14,[r36]; adds	r1,0x0,r46; adds	r49,0x0,r8; }
	{ ld8	r50,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r46; nop.m	0x0; adds	r49,0x0,r33 }
	{ st8	[r8],r37; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r46; adds	r49,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r46; nop.m	0x0; adds	r49,0x0,r8 }
	{ adds	r50,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ cmp.eq	p06,p07,0x0,r38; ld8	r35,[r35]; adds	r14,0x10,r34 }
	{ nop.m	0x0; adds	r1,0x0,r46; nop.i	0x0; }
	{ (p07) st8	[r38],r34; st8	[r8],r14; adds	r38,0x0,r34 }

l40000000000F97D6:
	{ mf.a; (p19) nop; break.i	0x80000 }
	{ (p08) nop; nop; (p32) nop }

l40000000000F97F0:
	{ ld8	r14,[r38]; nop.m	0x0; adds	r49,0x0,r38; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F9830; }

l40000000000F9810:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,list_reverse; }
	{ nop.m	0x0; adds	r1,0x0,r46; adds	r38,0x0,r8 }

l40000000000F9830:
	{ (p17) adds	r35,0x8,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B5C0; }

l40000000000F9836:
	{ break.m	0x4000; (p32) tbit.z.unc	p25,p44,r60,0x21; (p36) nop }

l40000000000F9846:
	{ Invalid; (p16) nop; nop }

l40000000000F9856:
	{ Invalid; Invalid; Invalid }

l40000000000F985C:
	{ cmp.lt	p00,p17,r1,r0; dep	r32,r104,r65,62,13; (p06) mov	pr,r8,0x8440 }

l40000000000F9860:
	{ cmp.eq	p06,p07,0x0,r33; adds	r50,0x0,r33; (p06) br.cond.dpnt.few	40000000000FAA70; }

l40000000000F9862:
	{ (p16) chk.a.nc	r104,3FFFFFFFFF907C72; (p16) nop; Invalid }

l40000000000F9870:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000F8EC0; }
	{ cmp4.lt	p06,p07,r8,r0; nop.m	0x0; sxt4	r8,r8 }
	{ adds	r1,0x0,r46; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000FAA70; }

l40000000000F98A0:
	{ shladd	r33,r8,0x3,r33; ld8	r14,[r33]; nop.i	0x0; }
	{ ld8	r49,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r46; adds	r49,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r14,[r33]; nop.m	0x0; adds	r1,0x0,r46 }
	{ adds	r49,0x0,r8; nop.m	0x0; adds	r33,0x0,r38; }
	{ ld8	r50,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ cmp.eq	p07,p06,0x0,r8; adds	r1,0x0,r46; nop.i	0x0 }
	{ adds	r36,0x0,r8; adds	r49,0x0,r8; (p07) br.cond.spnt.few	40000000000FAA70; }

l40000000000F9920:
	{ cmp.eq	p06,p07,0x0,r38; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000FA970; }

l40000000000F9930:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r46; adds	r49,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r46; nop.m	0x0; adds	r49,0x0,r8 }
	{ adds	r50,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; adds	r1,0x0,r46; adds	r34,0x0,r8; }

l40000000000F9980:
	{ adds	r15,0x8,r33; nop.m	0x0; adds	r14,0x10,r33 }
	{ adds	r49,0x0,r34; addl	r52,1,r0; nop.i	0x0 }
	{ ld8	r50,[r15]; ld8	r51,[r14]; br.call.sptk.many	b0,strsub; }
	{ adds	r1,0x0,r46; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r49,0x0,r34; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ ld8	r33,[r33]; adds	r1,0x0,r46; adds	r34,0x0,r35; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	40000000000F9980 }

l40000000000F99F0:
	{ nop.m	0x0; adds	r49,0x0,r36; adds	r33,0x0,r38 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r46; nop.m	0x0; nop.i	0x0; }

l40000000000F9A20:
	{ adds	r14,0x0,r33; ld8	r34,[r14],8; nop.i	0x0; }
	{ nop.m	0x0; ld8	r49,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r49; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F9A70; }

l40000000000F9A50:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r46; nop.m	0x0; nop.i	0x0 }

l40000000000F9A70:
	{ adds	r14,0x10,r33; ld8	r49,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r49; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F9AB0; }

l40000000000F9A90:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r46; nop.m	0x0; nop.i	0x0 }

l40000000000F9AB0:
	{ adds	r49,0x0,r33; adds	r33,0x0,r34; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r46; cmp.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	40000000000F9A20; }

l40000000000F9AD0:
	{ addl	r14,-10652,r1; nop.m	0x0; addl	r51,-2380,r1 }
	{ addl	r50,1,r0; nop.m	0x0; adds	r52,0x0,r35; }
	{ ld8	r14,[r14]; ld8	r51,[r51]; nop.i	0x0; }
	{ ld8	r49,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ cmp.eq	p06,p07,0x0,r35; nop.m	0x0; adds	r1,0x0,r46; }
	{ nop.m	0x0; (p06) adds	r36,0x0,r0; (p06) br.cond.dpnt.few	40000000000F9BF0; }

l40000000000F9B2C:
	{ Invalid; zxt1	r96,r64; break.b	0x1000 }

l40000000000F9B30:
	{ adds	r36,0x0,r35; nop.m	0x0; nop.i	0x0; }

l40000000000F9B40:
	{ ld1	r14,[r36]; adds	r49,0x0,r36; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F9BF0; }

l40000000000F9B60:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; sxt4	r8,r8; adds	r1,0x0,r46; }
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r8; nop.i	0x0; add	r14,r36,r14; }
	{ ld1	r15,[r14]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0xA,r15; (p06) br.cond.dpnt.few	40000000000FA160 }

l40000000000F9BB0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,bash_delete_last_history; }
	{ nop.m	0x0; adds	r1,0x0,r46; adds	r49,0x0,r36 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,maybe_add_history; }
	{ adds	r1,0x0,r46; nop.m	0x0; nop.i	0x0; }

l40000000000F9BF0:
	{ addl	r50,-2372,r1; adds	r49,0x0,r36; addl	r51,4,r0; }
	{ ld8	r50,[r50]; nop.i	0x0; br.call.sptk.many	b0,parse_and_execute; }
	{ nop.m	0x0; adds	r1,0x0,r46; adds	r33,0x0,r8; }

l40000000000F9C20:
	{ adds	r8,0x0,r33; mov	pr,r47,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r45; }
	{ nop.m	0x0; mov.i	LC,r48; mov.spnt	b0,r44,40000000000F9C30 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000000F9C50:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B5C0; }
	{ cmp.eq	p06,p07,0x0,r8; nop.m	0x0; adds	r1,0x0,r46 }
	{ adds	r39,0x0,r8; nop.m	0x0; adds	r15,0x8,r8; }
	{ (p06) adds	r33,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000F9540; }

l40000000000F9C86:
	{ chk.a.nc	r0,3FFFFFFFFF0FA486; nop; (p32) nop }

l40000000000F9C90:
	{ ld8	r14,[r8]; cmp.eq	p06,p07,0x0,r14; nop.i	0x0; }
	{ nop.m	0x0; (p06) adds	r14,0x0,r0; (p06) br.cond.dpnt.few	40000000000F9CE0; }

l40000000000F9CAC:
	{ (p02) cmp.lt	p00,p09,r64,r33; zxt1	r0,r64; break.i	0x1000 }

l40000000000F9CB0:
	{ adds	r14,0x0,r0; nop.m	0x0; nop.i	0x0; }

l40000000000F9CC0:
	{ ld8	r16,[r15],8; nop.m	0x0; adds	r14,0x1,r14; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r16; (p06) br.cond.dptk.few	40000000000F9CC0 }

l40000000000F9CE0:
	{ addl	r43,6116,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r43]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	40000000000F9D70 }

l40000000000F9D10:
	{ addl	r15,9028,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r15,0x2; (p07) br.cond.dptk.few	40000000000FA590 }

l40000000000F9D40:
	{ addl	r15,6112,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	40000000000FA590 }

l40000000000F9D70:
	{ addl	r33,1,r0; nop.m	0x0; nop.i	0x0; }

l40000000000F9D80:
	{ addl	r34,9160,r1; nop.m	0x0; sub	r33,r14,r33; }
	{ nop.m	0x0; ld4	r15,[r34]; nop.i	0x0; }
	{ nop.m	0x0; sub	r33,r33,r15; nop.i	0x0; }
	{ cmp4.eq	p07,p06,r33,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000FA5D0; }

l40000000000F9DC0:
	{ nop.m	0x0; cmp4.lt	p07,p06,r33,r0; (p07) br.cond.dpnt.few	40000000000FA630; }

l40000000000F9DD0:
	{ adds	r14,0x8,r35; nop.m	0x0; cmp.eq	p06,p07,0x0,r35 }
	{ adds	r50,0x0,r39; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000FA1C0; }

l40000000000F9DF0:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r49,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn40000000000F8EC0; }
	{ ld8	r14,[r35]; nop.m	0x0; adds	r1,0x0,r46 }
	{ adds	r42,0x0,r8; nop.m	0x0; adds	r50,0x0,r39; }
	{ cmp.eq	p06,p07,0x0,r14; adds	r14,0x8,r14; (p06) br.cond.dpnt.few	40000000000FAA50; }

l40000000000F9E40:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r49,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn40000000000F8EC0; }
	{ cmp4.eq	p06,p07,0x0,r36; nop.m	0x0; adds	r1,0x0,r46 }
	{ adds	r41,0x0,r8; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000FA200; }

l40000000000F9E80:
	{ (p06) ld4	r15,[r34]; nop.m	0x0; nop.i	0x0; }

l40000000000F9E86:
	{ break.m	0x4000; nop; break.i	0x80000 }

l40000000000F9E90:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	40000000000FA200 }

l40000000000F9EA0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,bash_delete_last_history; }
	{ cmp4.eq	p06,p07,r33,r41; cmp4.eq	p08,p09,r41,r42; adds	r1,0x0,r46; }
	{ (p06) addl	r15,1,r0; nop.m	0x0; (p08) addl	r14,1,r0; }

l40000000000F9EC6:
	{ Invalid; (p07) cmp4.eq.and	p01,p08,0x0,r0; (p49) nop }

l40000000000F9ED0:
	{ (p07) adds	r15,0x0,r0; (p09) adds	r14,0x0,r0; and	r14,r14,r15; }

l40000000000F9ED6:
	{ Invalid; (p07) nop; break.i	0x80000 }

l40000000000F9EDC:
	{ (p07) invala; cmp.lt	p00,p00,r32,r0; mov	pr,r99,0xE680; }
	{ Invalid; cmp.lt	p00,p00,r32,r0; (p01) cmp.lt	p32,p00,r72,r5 }

l40000000000F9EF0:
	{ nop.m	0x0; sxt4	r14,r33; shladd	r14,r14,0x3,r39; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000FA200 }

l40000000000F9F20:
	{ nop.m	0x0; adds	r41,0xFFFFFFFFFFFFFFFF,r41; nop.i	0x0; }
	{ cmp4.lt	p07,p06,r41,r0; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000FA630; }

l40000000000F9F40:
	{ nop.m	0x0; (p06) adds	r42,0x0,r41; (p06) cmp.eq	p18,p19,r0,r0 }

l40000000000F9F4C:
	{ nop; (p06) dep	r51,r63,r123,62,4; (p22) nop }

l40000000000F9F50:
	{ addl	r49,-2356,r1; addl	r50,5,r0; adds	r51,0x10,r12; }
	{ ld8	r49,[r49]; nop.i	0x0; br.call.sptk.many	b0,sh_mktmpfp; }
	{ cmp.eq	p07,p06,0x0,r8; adds	r1,0x0,r46; adds	r35,0x0,r8; }
	{ nop.m	0x0; (p06) adds	r38,0x0,r0; (p06) br.cond.dptk.few	40000000000FA270 }

l40000000000F9F8C:
	{ (p23) cmpxchg2.acq	r0,[r33],r0; (p06) nop; (p22) nop }

l40000000000F9F90:
	{ addl	r50,-2348,r1; addl	r51,5,r0; adds	r49,0x0,r0; }
	{ ld8	r50,[r50]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r14,0x10,r12; adds	r1,0x0,r46; adds	r34,0x0,r8; }
	{ ld8	r33,[r14]; cmp.eq	p07,p06,0x0,r33; nop.i	0x0; }
	{ nop.m	0x0; (p07) addl	r33,-2420,r1; nop.i	0x0; }

l40000000000F9FDC:
	{ nop; Invalid; break.i	0x1000 }

l40000000000F9FE6:
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; nop; (p16) br.call.sptk.few	b4,b0 }
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ Invalid; nop; (p16) nop.b	0x2200C }
	{ Invalid; (p32) nop; (p32) nop.b	0xC203 }
	{ add	r0,r0,r1; nop; break.i	0x80000 }
	{ (p24) fwb; nop; nop }
	{ chk.a.nc	r0,3FFFFFFFFF0FA856; nop; break.i	0x80000 }

l40000000000FA060:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r46; mov	pr,r47,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r45; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r48; mov.spnt	b0,r44,40000000000FA090 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000FA0B0:
	{ adds	r14,0x1,r37; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000F9670; }

l40000000000FA0E0:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; nop.i	0x0; }
	{ nop.m	0x0; (p06) adds	r38,0x0,r0; (p06) br.cond.dptk.few	40000000000F96A0 }

l40000000000FA0FC:
	{ Invalid; break.i	0x1000; break.b	0x1000 }

l40000000000FA100:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000FA5A0; }

l40000000000FA110:
	{ cmp.eq	p16,p17,0x0,r35; cmp.eq	p06,p07,0x0,r38; (p07) br.cond.dptk.few	40000000000F97F0; }

l40000000000FA120:
	{ (p17) adds	r35,0x8,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B5C0; }

l40000000000FA126:
	{ break.m	0x4000; (p32) tbit.z.unc	p10,p44,r60,0x21; (p36) nop }

l40000000000FA136:
	{ add	r0,r0,r1; nop; (p16) nop }
	{ nop; (p24) nop; (p20) nop }

l40000000000FA150:
	{ (p17) ld8	r49,[r14]; nop.i	0x0; br.cond.sptk.few	40000000000F9860; }

l40000000000FA156:
	{ break.m	0x4000; nop; nop }

l40000000000FA160:
	{ st1	[r0],r14; addl	r50,-2372,r1; adds	r49,0x0,r36 }
	{ addl	r51,4,r0; ld1	r14,[r36]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p06) br.cond.spnt.few	40000000000F9BB0; }

l40000000000FA1A0:
	{ ld8	r50,[r50]; nop.i	0x0; br.call.sptk.many	b0,parse_and_execute; }
	{ adds	r1,0x0,r46; adds	r33,0x0,r8; br.cond.sptk.few	40000000000F9C20 }

l40000000000FA1C0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r36; (p06) br.cond.dptk.few	40000000000FAC00; }

l40000000000FA1D0:
	{ adds	r14,0xFFFFFFFFFFFFFFF1,r33; cmp4.lt	p07,p06,r14,r0; nop.i	0x0; }
	{ (p06) adds	r42,0x0,r14; nop.i	0x0; (p07) adds	r42,0x0,r0 }

l40000000000FA1E6:
	{ chk.a.nc	f0,3FFFFFFFFF0FA9E6; (p21) nop; (p16) nop }

l40000000000FA1F0:
	{ adds	r41,0x0,r33; nop.m	0x0; nop.i	0x0; }

l40000000000FA200:
	{ or	r14,r41,r42; nop.m	0x0; cmp4.eq	p18,p19,0x0,r36; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x1F; (p06) br.cond.dpnt.few	40000000000FA630; }

l40000000000FA220:
	{ nop.m	0x0; cmp4.lt	p06,p07,r41,r42; nop.i	0x0; }
	{ (p06) adds	r14,0x0,r42; (p06) adds	r42,0x0,r41; (p06) addl	r40,1,r0; }

l40000000000FA236:
	{ (p21) chk.a.clr	r0,3FFFFFFFFF17A4C6; (p20) nop; (p17) nop; }

l40000000000FA23C:
	{ Invalid; Invalid; Invalid }

l40000000000FA240:
	{ (p06) adds	r41,0x0,r14; addl	r14,-10260,r1; (p18) br.cond.dpnt.few	40000000000F9F50; }

l40000000000FA246:
	{ (p07) nop; nop; break.i	0x80000 }

l40000000000FA250:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r35,[r14]; nop.m	0x0; nop.i	0x0 }

l40000000000FA270:
	{ cmp4.eq	p20,p21,0x0,r40; (p21) adds	r33,0x0,r41; nop.i	0x0; }

l40000000000FA27C:
	{ Invalid; nop; (p04) mov	pr,0xA100540 }

l40000000000FA28C:
	{ (p13) nop; break.i	0x1000; break.b	0x1000 }

l40000000000FA290:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000FA2A0:
	{ nop.m	0x0; cmp4.lt	p07,p06,r33,r42; nop.i	0x0; }
	{ (p06) addl	r14,1,r0; nop.i	0x0; (p07) adds	r14,0x0,r0; }

l40000000000FA2B6:
	{ chk.a.nc	f0,3FFFFFFFFF0FAAB6; (p07) nop; (p48) nop }

l40000000000FA2C0:
	{ cmp4.eq	p07,p06,0x0,r14; addl	r14,7676,r1; (p07) br.cond.dpnt.few	40000000000FA6F0; }

l40000000000FA2D0:
	{ nop.m	0x0; ld4.acq	r15,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r15; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000FA540; }

l40000000000FA2F0:
	{ addl	r14,7684,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4.acq	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000FA510; }

l40000000000FA320:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r38; (p07) br.cond.dpnt.few	40000000000FA450; }

l40000000000FA330:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r36; (p07) br.cond.dptk.few	40000000000FA4A0 }

l40000000000FA340:
	{ nop.m	0x0; addl	r14,6456,r1; sxt4	r34,r33 }
	{ addl	r51,-2332,r1; adds	r49,0x0,r35; addl	r50,1,r0; }
	{ nop.m	0x0; nop.m	0x0; shladd	r34,r34,0x3,r39; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000FA6C0; }

l40000000000FA390:
	{ nop.m	0x0; ld8	r14,[r34]; (p20) adds	r33,0x1,r33 }

l40000000000FA3A0:
	{ ld8	r51,[r51]; adds	r14,0x10,r14; (p21) adds	r33,0xFFFFFFFFFFFFFFFF,r33; }

l40000000000FA3B0:
	{ ld8	r52,[r14]; cmp.eq	p06,p07,0x0,r52; nop.i	0x0; }
	{ nop.m	0x0; (p06) addl	r52,32,r0; nop.i	0x0; }

l40000000000FA3CC:
	{ nop; zxt4	r10,r0; break.i	0x1000 }

l40000000000FA3D6:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; (p24) nop; (p32) nop }
	{ Invalid; nop; break.b	0x80000 }
	{ (p25) fwb; nop; br.call.sptk.few	b5,b0 }
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ nop; nop; Invalid }

l40000000000FA430:
	{ cmp4.lt	p07,p06,r41,r33; (p06) addl	r14,1,r0; nop.i	0x0; }

l40000000000FA43C:
	{ Invalid; cmp4.eq.and	p00,p32,r32,r0; zxt1	r0,r64 }

l40000000000FA44C:
	{ (p52) cmp.lt.unc	p63,p08,r63,r36; (p01) nop; (p06) nop }

l40000000000FA450:
	{ addl	r14,-10068,r1; addl	r51,-2340,r1; adds	r49,0x0,r35 }
	{ addl	r50,1,r0; ld8	r14,[r14]; nop.i	0x0 }
	{ ld8	r51,[r51]; ld4	r52,[r14]; nop.i	0x0; }
	{ add	r52,r33,r52; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ adds	r1,0x0,r46; cmp4.eq	p07,p06,0x0,r36; (p06) br.cond.dptk.few	40000000000FA340 }

l40000000000FA4A0:
	{ nop.m	0x0; sxt4	r34,r33; shladd	r34,r34,0x3,r39; }

l40000000000FA4B0:
	{ nop.m	0x0; ld8	r14,[r34]; addl	r51,-2380,r1 }
	{ adds	r49,0x0,r35; addl	r50,1,r0; (p21) adds	r33,0xFFFFFFFFFFFFFFFF,r33; }

l40000000000FA4D0:
	{ ld8	r51,[r51]; nop.m	0x0; (p20) adds	r33,0x1,r33; }

l40000000000FA4E0:
	{ ld8	r52,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ nop.m	0x0; adds	r1,0x0,r46; (p20) br.cond.dptk.few	40000000000FA430 }

l40000000000FA500:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000FA2A0 }

l40000000000FA510:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,throw_to_top_level; }
	{ adds	r1,0x0,r46; cmp4.eq	p06,p07,0x0,r38; (p06) br.cond.dptk.few	40000000000FA330 }

l40000000000FA530:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000FA450 }

l40000000000FA540:
	{ ld4.acq	r49,[r14]; nop.i	0x0; br.call.sptk.many	b0,termsig_handler; }
	{ adds	r1,0x0,r46; addl	r14,7684,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4.acq	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000FA320 }

l40000000000FA580:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000FA510 }

l40000000000FA590:
	{ nop.m	0x0; adds	r33,0x0,r0; br.cond.sptk.few	40000000000F9D80 }

l40000000000FA5A0:
	{ adds	r38,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B5C0; }
	{ nop.m	0x0; adds	r1,0x0,r46; adds	r33,0x0,r8 }
	{ nop.m	0x0; adds	r49,0x0,r0; br.cond.sptk.few	40000000000F9860; }

l40000000000FA5D0:
	{ nop.m	0x0; sxt4	r14,r33; shladd	r14,r14,0x3,r0; }
	{ add	r16,r39,r14; ld8	r16,[r16]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r16; (p06) br.cond.dptk.few	40000000000F9DD0 }

l40000000000FA600:
	{ addp4	r16,r33,r0; adds	r14,0xFFFFFFFFFFFFFFF8,r14; adds	r33,0xFFFFFFFFFFFFFFFF,r33; }
	{ add	r14,r39,r14; nop.m	0x0; mov.i	LC,r16; }
	{ nop.m	0x0; nop.i	0x0; br.cloop.sptk.few	40000000000FA9C0 }

l40000000000FA630:
	{ addl	r50,-2364,r1; nop.m	0x0; addl	r51,5,r0 }
	{ adds	r49,0x0,r0; nop.m	0x0; addl	r33,1,r0; }
	{ ld8	r50,[r50]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r46; nop.m	0x0; adds	r50,0x0,r8 }
	{ adds	r49,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,sh_erange; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r46; mov	pr,r47,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r45; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r48; mov.spnt	b0,r44,40000000000FA6A0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000000FA6C0:
	{ addl	r49,9,r0; nop.m	0x0; adds	r50,0x0,r35 }
	{ nop.m	0x0; sxt4	r34,r33; br.call.sptk.many	b0,fn400000000001BD80; }
	{ adds	r1,0x0,r46; shladd	r34,r34,0x3,r39; br.cond.sptk.few	40000000000FA4B0 }

l40000000000FA6F0:
	{ adds	r49,0x0,r35; (p19) br.cond.dpnt.few	40000000000FAA00; br.call.sptk.many	b0,fn400000000001A680; }

l40000000000FA6FC:
	{ (p60) nop; nop; (p06) epc }
	{ (p19) cmp.lt.unc	p00,p08,r60,r44; flushrs; nop }
	{ nop; zxt1	r96,r64; mov	pr,r32,0x0 }
	{ Invalid; break.i	0x1000; break.i	0x1000 }

l40000000000FA730:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BE40; }
	{ adds	r1,0x0,r46; nop.m	0x0; adds	r49,0x0,r37 }
	{ nop.b	0x0; (p16) br.cond.dpnt.few	40000000000FACA0; br.call.sptk.many	b0,fn400000000001B6C0; }

l40000000000FA75C:
	{ (p59) cmp.lt.unc	p01,p09,r60,r44; (p01) nop; (p04) brp.sptk	b2,40000000000FA75C }
	{ nop; Invalid; break.i	0x1000 }
	{ (p58) nop; (p22) invala; nop.b	0x1000 }
	{ nop; zxt1	r32,r64; break.i	0x1000 }
	{ (p41) nop; nop; (p04) brp.sptk	b2,40000000000FA79C }
	{ Invalid; Invalid; Invalid }
	{ Invalid; Invalid; Invalid }

l40000000000FA7C0:
	{ adds	r14,0x10,r12; addl	r52,-2324,r1; addl	r34,1,r0; }
	{ nop.m	0x0; ld8	r54,[r14]; nop.i	0x0 }
	{ ld8	r52,[r52]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C440; }
	{ adds	r1,0x0,r46; addl	r51,4,r0; adds	r49,0x0,r33; }
	{ nop.m	0x0; addl	r50,-2372,r1; nop.i	0x0; }
	{ ld8	r50,[r50]; nop.i	0x0; br.call.sptk.many	b0,parse_and_execute; }
	{ adds	r1,0x0,r46; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dpnt.few	40000000000FAC20; }

l40000000000FA830:
	{ nop.m	0x0; addl	r49,-2316,r1; addl	r33,7376,r1 }
	{ st4	[r34],r43; nop.m	0x0; nop.i	0x0 }
	{ ld8	r49,[r49]; nop.m	0x0; br.call.sptk.many	b0,begin_unwind_frame; }
	{ adds	r1,0x0,r46; nop.m	0x0; adds	r14,0x10,r12; }
	{ addl	r49,-9884,r1; ld8	r50,[r14]; nop.i	0x0; }
	{ ld8	r49,[r49]; nop.i	0x0; br.call.sptk.many	b0,add_unwind_protect; }
	{ adds	r1,0x0,r46; nop.m	0x0; adds	r14,0x10,r12; }
	{ addl	r49,-10500,r1; ld8	r50,[r14]; nop.i	0x0; }
	{ ld8	r49,[r49]; nop.i	0x0; br.call.sptk.many	b0,add_unwind_protect; }
	{ addl	r50,4,r0; nop.m	0x0; adds	r1,0x0,r46 }
	{ adds	r49,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,unwind_protect_mem; }
	{ nop.m	0x0; adds	r14,0x10,r12; adds	r1,0x0,r46 }
	{ nop.m	0x0; st4	[r34],r33; nop.i	0x0; }
	{ ld8	r49,[r14]; nop.i	0x0; br.call.sptk.many	b0,fc_execute_file; }
	{ adds	r1,0x0,r46; adds	r33,0x0,r8; addl	r49,-2316,r1; }
	{ ld8	r49,[r49]; nop.i	0x0; br.call.sptk.many	b0,run_unwind_frame; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r46; mov	pr,r47,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r45; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r48; mov.spnt	b0,r44,40000000000FA950 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000FA970:
	{ addl	r14,-10652,r1; nop.m	0x0; addl	r51,-2380,r1 }
	{ addl	r50,1,r0; nop.m	0x0; adds	r52,0x0,r8; }
	{ ld8	r14,[r14]; ld8	r51,[r51]; nop.i	0x0; }
	{ ld8	r49,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ nop.m	0x0; adds	r1,0x0,r46; br.cond.sptk.few	40000000000F9B40 }

l40000000000FA9C0:
	{ nop.m	0x0; ld8	r16,[r14],-8; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r16; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000F9DD0; }

l40000000000FA9E0:
	{ nop.m	0x0; adds	r33,0xFFFFFFFFFFFFFFFF,r33; br.cloop.sptk.few	40000000000FA9C0 }

l40000000000FA9F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000FA630 }

l40000000000FAA00:
	{ adds	r49,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,sh_chkwrite; }
	{ adds	r33,0x0,r8; nop.m	0x0; adds	r1,0x0,r46; }
	{ adds	r8,0x0,r33; mov	pr,r47,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r45; }
	{ nop.m	0x0; mov.i	LC,r48; mov.spnt	b0,r44,40000000000FAA30 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000FAA50:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r36; (p06) br.cond.dptk.few	40000000000FA1F0 }

l40000000000FAA60:
	{ ld4	r15,[r34]; adds	r41,0x0,r42; br.cond.sptk.few	40000000000F9E90 }

l40000000000FAA70:
	{ addl	r50,-2388,r1; addl	r51,5,r0; adds	r49,0x0,r0; }
	{ ld8	r50,[r50]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r46; adds	r49,0x0,r8; br.call.sptk.many	b0,builtin_error; }
	{ adds	r1,0x0,r46; cmp.eq	p07,p06,0x0,r38; (p06) br.cond.dptk.few	40000000000FAB50 }

l40000000000FAAB0:
	{ addl	r33,1,r0; adds	r8,0x0,r33; mov	pr,r47,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r45; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r48; mov.spnt	b0,r44,40000000000FAAD0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000FAAF0:
	{ adds	r14,0x10,r38; ld8	r49,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r49; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000FAB30; }

l40000000000FAB10:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r46; nop.m	0x0; nop.i	0x0 }

l40000000000FAB30:
	{ adds	r49,0x0,r38; adds	r38,0x0,r33; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r46; cmp.eq	p07,p06,0x0,r33; (p07) br.cond.dpnt.few	40000000000FAAB0 }

l40000000000FAB50:
	{ adds	r14,0x0,r38; ld8	r33,[r14],8; nop.i	0x0; }
	{ nop.m	0x0; ld8	r49,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r49; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000FAAF0; }

l40000000000FAB80:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r46; br.cond.sptk.few	40000000000FAAF0 }

l40000000000FABA0:
	{ addl	r33,1,r0; nop.i	0x0; br.call.sptk.many	b0,sh_wrerror; }
	{ adds	r1,0x0,r46; adds	r49,0x0,r35; br.call.sptk.many	b0,fn400000000001BE40; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r46; mov	pr,r47,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r45; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r48; mov.spnt	b0,r44,40000000000FABE0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000FAC00:
	{ nop.m	0x0; adds	r42,0x0,r33; nop.i	0x0; }
	{ nop.m	0x0; adds	r41,0x0,r42; br.cond.sptk.few	40000000000F9E90 }

l40000000000FAC20:
	{ adds	r14,0x10,r12; nop.m	0x0; addl	r33,1,r0; }
	{ ld8	r49,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B200; }
	{ adds	r14,0x10,r12; nop.m	0x0; adds	r1,0x0,r46; }
	{ ld8	r49,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r46; mov	pr,r47,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r45; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r48; mov.spnt	b0,r44,40000000000FAC80 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000000FACA0:
	{ adds	r14,0x10,r12; ld8	r49,[r14]; addl	r14,6456,r1; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; (p06) addl	r34,-2404,r1; nop.i	0x0; }

l40000000000FACCC:
	{ getf.exp	r0,f1; (p04) dep	r37,r63,r123,50,4; Invalid }

l40000000000FACD6:
	{ (p17) fwb; cmp4.eq	p00,p00,r0,r1; (p33) nop; }

l40000000000FACDC:
	{ getf.s	r0,f1; Invalid; break.i	0x1000 }

l40000000000FACE6:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; (p32) nop; (p16) nop.b	0x2E000 }
	{ Invalid; (p24) nop; (p32) nop.b	0x2C }
	{ Invalid; (p26) nop; break.b	0x80000 }
	{ break.m	0x4000; Invalid; (p32) break.i	0x80001 }
40000000000FAD30 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; fn40000000000FAD40: 40000000000FAD40
;;   Called from:
;;     40000000000FB2BC (in fg_builtin)
;;     40000000000FB33C (in fg_builtin)
;;     40000000000FB48C (in bg_builtin)
fn40000000000FAD40 proc
	{ alloc	r37,ar.pfs,0xA,0x0,0x7; adds	r12,0xFFFFFFFFFFFFFF00,r12; nop.b	0x0 }
	{ adds	r38,0x0,r1; nop.m	0x0; mov	r36,b4; }
	{ adds	r39,0x90,r12; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BC20; }
	{ addl	r40,17,r0; nop.m	0x0; adds	r1,0x0,r38 }
	{ adds	r39,0x90,r12; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B400; }
	{ adds	r1,0x0,r38; adds	r39,0x10,r12; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r38; adds	r40,0x90,r12; nop.i	0x0 }
	{ adds	r41,0x10,r12; adds	r39,0x0,r0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r38; adds	r39,0x0,r32; br.call.sptk.many	b0,get_job_spec; }
	{ adds	r1,0x0,r38; nop.m	0x0; cmp4.lt	p06,p07,r8,r0 }
	{ adds	r34,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000FAF40; }

l40000000000FADF0:
	{ addl	r14,-20676,r1; nop.m	0x0; nop.i	0x0; }
	{ adds	r14,0x1C,r14; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r8,r14; (p06) br.cond.dptk.few	40000000000FAF60 }

l40000000000FAE20:
	{ addl	r14,7444,r1; nop.m	0x0; sxt4	r15,r8; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ shladd	r14,r15,0x3,r14; ld8	r14,[r14]; nop.i	0x0; }
	{ adds	r15,0x18,r14; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	40000000000FAF60; }

l40000000000FAE60:
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r15,0x2; (p07) br.cond.dpnt.few	40000000000FAFD0; }

l40000000000FAE80:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	40000000000FB090 }

l40000000000FAE90:
	{ addl	r35,5872,r1; adds	r14,0x10,r14; adds	r39,0x0,r8 }
	{ adds	r40,0x0,r0; nop.m	0x0; nop.i	0x0 }
	{ ld4	r14,[r14]; ld4	r34,[r35]; nop.i	0x0 }
	{ st4	[r14],r35; nop.m	0x0; br.call.sptk.many	b0,start_job; }
	{ adds	r1,0x0,r38; cmp4.lt	p07,p06,r8,r0; (p06) br.cond.dptk.few	40000000000FB040 }

l40000000000FAEE0:
	{ st4	[r34],r35; nop.m	0x0; nop.i	0x0 }

l40000000000FAEF0:
	{ addl	r39,2,r0; adds	r40,0x10,r12; nop.i	0x0 }
	{ adds	r41,0x0,r0; addl	r34,1,r0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r38; nop.m	0x0; nop.i	0x0 }

l40000000000FAF20:
	{ adds	r8,0x0,r34; mov.i	ar.pfs,r37; mov.spnt	b0,r36,40000000000FAF20 }
	{ nop.m	0x0; adds	r12,0x100,r12; br.ret	b0 }

l40000000000FAF40:
	{ nop.m	0x0; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFE,r8; (p07) br.cond.dptk.few	40000000000FAEF0; }

l40000000000FAF50:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000FAF60:
	{ cmp.eq	p06,p07,0x0,r32; adds	r32,0x8,r32; (p06) br.cond.dpnt.few	40000000000FB100; }

l40000000000FAF70:
	{ ld8	r14,[r32]; nop.i	0x0; nop.i	0x0 }
	{ ld8	r39,[r14]; nop.m	0x0; br.call.sptk.many	b0,sh_badjob; }
	{ adds	r1,0x0,r38; nop.m	0x0; nop.i	0x0 }

l40000000000FAFA0:
	{ addl	r39,2,r0; adds	r40,0x10,r12; nop.i	0x0 }
	{ adds	r41,0x0,r0; addl	r34,1,r0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ nop.m	0x0; adds	r1,0x0,r38; br.cond.sptk.few	40000000000FAF20; }

l40000000000FAFD0:
	{ addl	r40,-9148,r1; addl	r41,5,r0; adds	r39,0x0,r0; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r38; adds	r39,0x0,r8; nop.i	0x0 }
	{ adds	r40,0x1,r34; addl	r34,1,r0; br.call.sptk.many	b0,builtin_error; }
	{ adds	r1,0x0,r38; addl	r39,2,r0; nop.i	0x0 }
	{ adds	r40,0x10,r12; adds	r41,0x0,r0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ nop.m	0x0; adds	r1,0x0,r38; br.cond.sptk.few	40000000000FAF20 }

l40000000000FB040:
	{ addl	r39,2,r0; adds	r40,0x10,r12; nop.i	0x0 }
	{ adds	r41,0x0,r0; adds	r34,0x0,r0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r8,0x0,r34; adds	r1,0x0,r38; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000FB070; nop.i	0x0 }
	{ adds	r12,0x100,r12; nop.m	0x0; br.ret	b0; }

l40000000000FB090:
	{ adds	r40,0x0,r33; adds	r39,0x0,r8; br.call.sptk.many	b0,start_job; }
	{ cmp4.lt	p07,p06,r8,r0; adds	r1,0x0,r38; adds	r34,0x0,r8 }
	{ addl	r39,2,r0; adds	r40,0x10,r12; (p07) br.cond.dpnt.few	40000000000FAEF0; }

l40000000000FB0C0:
	{ adds	r41,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r8,0x0,r34; adds	r1,0x0,r38; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000FB0E0; nop.i	0x0 }
	{ adds	r12,0x100,r12; nop.m	0x0; br.ret	b0 }

l40000000000FB100:
	{ addl	r40,-9156,r1; addl	r41,5,r0; adds	r39,0x0,r0; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r38; adds	r39,0x0,r8; br.call.sptk.many	b0,sh_badjob; }
	{ nop.m	0x0; adds	r1,0x0,r38; br.cond.sptk.few	40000000000FAFA0; }

;; fg_builtin: 40000000000FB140
fg_builtin proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; addl	r14,5868,r1; mov	r34,b2 }
	{ adds	r36,0x0,r1; nop.m	0x0; adds	r37,0x0,r32; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000FB2C0; }

l40000000000FB180:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,no_options; }
	{ cmp4.eq	p07,p06,0x0,r8; nop.m	0x0; mov.i	ar.pfs,r35 }
	{ adds	r1,0x0,r36; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000FB1D0; }

l40000000000FB1B0:
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000FB1B0; nop.i	0x0 }
	{ (p06) addl	r8,258,r0; nop.m	0x0; br.ret	b0 }

l40000000000FB1C6:
	{ break.m	0x4000; (p34) nop; (p32) nop }

l40000000000FB1D0:
	{ addl	r14,9268,r1; nop.m	0x0; nop.i	0x0; }
	{ ld8	r32,[r14]; cmp.eq	p06,p07,0x0,r32; nop.i	0x0; }
	{ (p06) addl	r33,1,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000FB2A0; }

l40000000000FB1F6:
	{ chk.a.nc	r0,3FFFFFFFFF0FB9F6; nop; break.i	0x80000 }

l40000000000FB200:
	{ nop.m	0x0; ld8	r15,[r32]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r15; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000FB340; }

l40000000000FB220:
	{ nop.m	0x0; ld8	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000FB260; }

l40000000000FB240:
	{ adds	r15,0x0,r14; ld8	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000FB240 }

l40000000000FB260:
	{ adds	r15,0x8,r15; nop.m	0x0; addl	r33,1,r0; }
	{ ld8	r14,[r15]; ld8	r14,[r14]; nop.i	0x0; }
	{ ld1	r15,[r14]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x26,r15; (p06) br.cond.dpnt.few	40000000000FB2F0 }

l40000000000FB2A0:
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000FB2A0; mov.i	ar.pfs,r35; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000FAD40; }

l40000000000FB2C0:
	{ adds	r37,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,sh_nojobs; }
	{ addl	r8,1,r0; adds	r1,0x0,r36; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000FB2E0; br.ret	b0; }

l40000000000FB2F0:
	{ adds	r14,0x1,r14; nop.m	0x0; mov.spnt	b0,r34,40000000000FB2F0; }
	{ ld1	r33,[r14]; mov.i	ar.pfs,r35; sxt1	r33,r33; }
	{ cmp4.eq	p07,p06,0x0,r33; (p06) addl	r33,1,r0; nop.i	0x0; }

l40000000000FB31C:
	{ nop; nop; zxt1	r0,r64 }

l40000000000FB32C:
	{ ld4	r0,[r0]; Invalid; break.i	0x1000 }
	{ (p16) cmp.eq.unc	p63,p03,r63,r36; (p01) nop; Invalid }

l40000000000FB340:
	{ adds	r15,0x0,r32; addl	r33,1,r0; adds	r15,0x8,r15; }
	{ ld8	r14,[r15]; ld8	r14,[r14]; nop.i	0x0; }
	{ ld1	r15,[r14]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x26,r15; (p07) br.cond.dptk.few	40000000000FB2A0 }

l40000000000FB380:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000FB2F0; }
40000000000FB390 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000FB3A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000FB3B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; bg_builtin: 40000000000FB3C0
bg_builtin proc
	{ alloc	r36,ar.pfs,0x8,0x0,0x6; addl	r14,5868,r1; nop.b	0x0 }
	{ adds	r37,0x0,r1; mov	r35,b3; adds	r38,0x0,r32; }
	{ nop.m	0x0; nop.m	0x0; addl	r34,258,r0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000FB500; }

l40000000000FB410:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,no_options; }
	{ adds	r1,0x0,r37; cmp4.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	40000000000FB450 }

l40000000000FB430:
	{ adds	r8,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000FB440; br.ret	b0 }

l40000000000FB450:
	{ addl	r14,9268,r1; adds	r34,0x0,r0; nop.i	0x0 }
	{ nop.m	0x0; ld8	r33,[r14]; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000FB480:
	{ adds	r38,0x0,r33; adds	r39,0x0,r0; br.call.sptk.many	b0,fn40000000000FAD40; }
	{ cmp4.eq	p07,p08,0x1,r8; adds	r1,0x0,r37; (p07) adds	r8,0x1,r0; }

l40000000000FB4A0:
	{ (p08) adds	r8,0x0,r0; cmp.eq	p06,p07,0x0,r33; tbit.z	p09,p08,r8,0x0; }

l40000000000FB4A6:
	{ Invalid; (p04) nop; (p34) nop }

l40000000000FB4B6:
	{ chk.a.nc	r0,3FFFFFFFFF0FBCB6; nop; break.i	0x80000 }

l40000000000FB4C0:
	{ nop.m	0x0; ld8	r33,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.sptk.few	40000000000FB480 }

l40000000000FB4E0:
	{ adds	r8,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000FB4F0; br.ret	b0; }

l40000000000FB500:
	{ adds	r38,0x0,r0; addl	r34,1,r0; br.call.sptk.many	b0,sh_nojobs; }
	{ adds	r8,0x0,r34; adds	r1,0x0,r37; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000FB520; br.ret	b0; }
40000000000FB530 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000FB540 08 10 21 08 80 05 E0 80 80 00 42 20 04 00 C4 00 ..!.......B ....
40000000000FB550 09 28 B1 FB D0 27 00 E2 80 00 42 60 04 08 00 84 .(...'....B`....
40000000000FB560 08 00 00 00 01 00 E0 00 38 30 20 80 14 00 00 90 ........80 .....
40000000000FB570 0B 28 01 4A 18 10 60 02 80 20 20 00 00 00 04 00 .(.J..`..  .....
40000000000FB580 11 38 01 1C 18 10 00 00 00 02 00 00 08 06 F2 58 .8.............X
40000000000FB590 09 40 00 00 00 21 10 00 8C 00 42 00 20 02 AA 00 .@...!....B. ...
40000000000FB5A0 11 00 00 00 01 00 00 08 05 80 03 80 08 00 84 00 ................
40000000000FB5B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000FB5C0 08 10 21 08 80 05 E0 80 80 00 42 20 04 00 C4 00 ..!.......B ....
40000000000FB5D0 09 28 D1 FB D0 27 00 42 80 00 42 60 04 08 00 84 .(...'.B..B`....
40000000000FB5E0 08 00 00 00 01 00 E0 00 38 30 20 80 14 00 00 90 ........80 .....
40000000000FB5F0 0B 28 01 4A 18 10 70 02 80 30 20 00 00 00 04 00 .(.J..p..0 .....
40000000000FB600 11 30 01 1C 18 10 00 00 00 02 00 00 88 05 F2 58 .0.............X
40000000000FB610 09 40 00 00 00 21 10 00 8C 00 42 00 20 02 AA 00 .@...!....B. ...
40000000000FB620 11 00 00 00 01 00 00 08 05 80 03 80 08 00 84 00 ................
40000000000FB630 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; hash_builtin: 40000000000FB640
hash_builtin proc
	{ alloc	r41,ar.pfs,0x10,0x0,0xC; addl	r14,5864,r1; mov	r43,pr }
	{ nop.m	0x0; adds	r42,0x0,r1; nop.i	0x0; }
	{ nop.m	0x0; adds	r35,0x0,r0; mov	r40,b0 }
	{ adds	r37,0x0,r0; adds	r38,0x0,r0; adds	r34,0x0,r0; }
	{ adds	r36,0x0,r0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000FB940; }

l40000000000FB6A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,reset_internal_getopt; }
	{ adds	r1,0x0,r42; addl	r33,-5948,r1; addl	r39,9252,r1; }
	{ ld8	r33,[r33]; nop.m	0x0; nop.i	0x0 }
	{ addl	r45,-6012,r1; nop.m	0x0; adds	r44,0x0,r32; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r42; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dpnt.few	40000000000FB7C0 }

l40000000000FB700:
	{ nop.m	0x0; adds	r8,0xFFFFFFFFFFFFFF9C,r8; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x10,r8; (p07) br.cond.dptk.few	40000000000FB760 }

l40000000000FB720:
	{ nop.m	0x0; addl	r33,258,r0; br.call.sptk.many	b0,builtin_usage; }
	{ adds	r1,0x0,r42; nop.m	0x0; nop.i	0x0 }

l40000000000FB740:
	{ adds	r8,0x0,r33; mov	pr,r43,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.spnt	b0,r40,40000000000FB750; br.ret	b0 }

l40000000000FB760:
	{ addp4	r8,r8,r0; shladd	r8,r8,0x3,r33; nop.i	0x0; }
	{ ld8	r14,[r8]; add	r8,r8,r14; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r8,40000000000FB780; br.cond	b6; }
40000000000FB790 09 68 11 FA D1 27 C0 02 80 00 42 40 14 00 00 90 .h...'....B@....
40000000000FB7A0 11 68 01 5A 18 10 00 00 00 02 00 00 28 ED 01 50 .h.Z........(..P
40000000000FB7B0 11 08 00 54 00 21 70 F8 23 0C 77 03 50 FF FF 4A ...T.!p.#.w.P..J

l40000000000FB7C0:
	{ addl	r14,9268,r1; nop.m	0x0; adds	r33,0x0,r34; }
	{ nop.m	0x0; ld8	r34,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r34; (p06) addl	r14,1,r0; nop.i	0x0; }

l40000000000FB7EC:
	{ cmp4.eq.and	p00,p43,r1,r0; (p01) cmp.eq	p00,p16,r0,r64; zxt1	r72,r3 }

l40000000000FB7F6:
	{ Invalid; nop; nop }
	{ chk.a.nc	f0,3FFFFFFFFF0FC006; nop; (p32) nop }

l40000000000FB810:
	{ cmp4.eq	p06,p07,0x0,r36; (p06) addl	r15,1,r0; nop.i	0x0; }

l40000000000FB81C:
	{ cmp4.eq.or.andcm	p00,p43,r1,r0; (p01) cmp.lt	p00,p16,r0,r64; zxt1	r67,r3 }

l40000000000FB826:
	{ Invalid; nop; Invalid }
	{ chk.a.nc	f77,3FFFFFFFFF95B836; nop; (p32) nop }

l40000000000FB83C:
	{ (p22) cmp.lt	p00,p17,r64,r33; (p01) cmp.lt	p46,p18,r32,r14; nop }

l40000000000FB840:
	{ addl	r14,7352,r1; cmp4.eq	p06,p07,0x0,r33; (p07) br.cond.dpnt.few	40000000000FBF40; }

l40000000000FB850:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000FB9B0; }

l40000000000FB870:
	{ cmp.eq	p06,p07,0x0,r35; adds	r44,0x0,r35; nop.i	0x0 }
	{ addl	r45,47,r0; addl	r33,1,r0; (p06) br.cond.dpnt.few	40000000000FB9B0; }

l40000000000FB890:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B680; }
	{ cmp.eq	p07,p06,0x0,r8; nop.m	0x0; adds	r1,0x0,r42 }
	{ adds	r44,0x0,r35; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000FB9B0; }

l40000000000FB8C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_restricted; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r42; mov	pr,r43,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r41; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r40,40000000000FB8F0; br.ret	b0 }
40000000000FB900 10 00 00 00 01 00 40 0A 00 00 48 00 D0 FD FF 48 ......@...H....H
40000000000FB910 10 18 01 4E 18 10 00 00 00 02 00 00 C0 FD FF 48 ...N...........H
40000000000FB920 10 00 00 00 01 00 60 0A 00 00 48 00 B0 FD FF 48 ......`...H....H
40000000000FB930 10 00 00 00 01 00 50 0A 00 00 48 00 A0 FD FF 48 ......P...H....H

l40000000000FB940:
	{ addl	r45,-6020,r1; nop.m	0x0; addl	r46,5,r0 }
	{ adds	r44,0x0,r0; nop.m	0x0; addl	r33,1,r0; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r42; adds	r44,0x0,r8; br.call.sptk.many	b0,builtin_error; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r42; mov	pr,r43,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r41; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r40,40000000000FB9A0; br.ret	b0 }

l40000000000FB9B0:
	{ addl	r38,8268,r1; adds	r33,0x0,r0; cmp.eq	p07,p06,0x0,r34 }
	{ cmp.eq	p16,p17,0x0,r35; cmp4.eq	p18,p19,0x0,r37; (p07) br.cond.dpnt.few	40000000000FBAB0; }

l40000000000FB9D0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }

l40000000000FB9E0:
	{ adds	r14,0x8,r34; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; ld8	r36,[r14]; nop.i	0x0; }
	{ adds	r44,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,absolute_program; }
	{ adds	r1,0x0,r42; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000000FBA90 }

l40000000000FBA20:
	{ adds	r44,0x0,r35; (p16) br.cond.dpnt.few	40000000000FBB70; br.call.sptk.many	b0,is_directory; }

l40000000000FBA2C:
	{ (p07) nop; cmp.lt.unc	p00,p16,r10,r64; mov	pr,r98,0xE600 }
	{ (p07) shladd	r0,r0,0x2,r33; (p21) nop; (p20) nop }

l40000000000FBA40:
	{ addl	r44,21,r0; addl	r33,1,r0; br.call.sptk.many	b0,fn400000000001B4A0; }
	{ adds	r1,0x0,r42; adds	r45,0x0,r35; adds	r46,0x0,r8; }
	{ addl	r44,-5972,r1; nop.i	0x0; nop.i	0x0 }
	{ ld8	r44,[r44]; nop.m	0x0; br.call.sptk.many	b0,builtin_error; }
	{ adds	r1,0x0,r42; nop.m	0x0; nop.i	0x0 }

l40000000000FBA90:
	{ nop.m	0x0; ld8	r34,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	40000000000FB9E0 }

l40000000000FBAB0:
	{ addl	r14,-10260,r1; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r44,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r42; mov	pr,r43,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r41; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r40,40000000000FBAF0; br.ret	b0; }

l40000000000FBB00:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,phash_flush; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	40000000000FB840 }

l40000000000FBB20:
	{ adds	r44,0x0,r36; adds	r45,0x0,r35; nop.i	0x0 }
	{ adds	r46,0x0,r0; adds	r47,0x0,r0; br.call.sptk.many	b0,phash_insert; }
	{ ld8	r34,[r34]; nop.m	0x0; adds	r1,0x0,r42; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	40000000000FB9E0 }

l40000000000FBB60:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000FBAB0 }

l40000000000FBB70:
	{ nop.m	0x0; adds	r44,0x0,r36; (p18) br.cond.dptk.few	40000000000FBBE0 }

l40000000000FBB80:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,phash_remove; }
	{ adds	r1,0x0,r42; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	40000000000FBA90 }

l40000000000FBBA0:
	{ adds	r44,0x0,r36; addl	r33,1,r0; br.call.sptk.many	b0,sh_notfound; }
	{ ld8	r34,[r34]; nop.m	0x0; adds	r1,0x0,r42; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	40000000000FB9E0 }

l40000000000FBBD0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000FBAB0 }

l40000000000FBBE0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,find_function; }
	{ adds	r1,0x0,r42; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000000FBA90 }

l40000000000FBC00:
	{ adds	r44,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,find_shell_builtin; }
	{ adds	r1,0x0,r42; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000000FBA90 }

l40000000000FBC20:
	{ adds	r44,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,phash_remove; }
	{ adds	r1,0x0,r42; adds	r44,0x0,r36; br.call.sptk.many	b0,find_user_command; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r42; nop.i	0x0 }
	{ adds	r39,0x0,r8; adds	r44,0x0,r8; (p06) br.cond.dpnt.few	40000000000FC130; }

l40000000000FBC60:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,executable_file; }
	{ cmp4.eq	p06,p07,0x0,r8; nop.m	0x0; adds	r1,0x0,r42 }
	{ adds	r44,0x0,r36; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000FC0D0; }

l40000000000FBC90:
	{ addl	r33,1,r0; nop.i	0x0; br.call.sptk.many	b0,sh_notfound; }
	{ nop.m	0x0; adds	r1,0x0,r42; adds	r44,0x0,r39 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r42; nop.m	0x0; nop.i	0x0 }

l40000000000FBCD0:
	{ nop.m	0x0; ld8	r34,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	40000000000FB9E0 }

l40000000000FBCF0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000FBAB0 }

l40000000000FBD00:
	{ addl	r33,7596,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld8	r44,[r33]; nop.i	0x0; }
	{ adds	r14,0xC,r44; cmp.eq	p06,p07,0x0,r44; (p06) br.cond.dpnt.few	40000000000FBE80; }

l40000000000FBD30:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000FBE80; }

l40000000000FBD50:
	{ cmp4.eq	p07,p06,0x0,r38; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000FBDB0; }

l40000000000FBD60:
	{ (p06) addl	r45,-5956,r1; adds	r33,0x0,r0; nop.i	0x0 }

l40000000000FBD66:
	{ Invalid; nop; (p17) br.call.sptk.few	b3,b0 }

l40000000000FBD76:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; Invalid; nop }

l40000000000FBD90:
	{ adds	r8,0x0,r33; mov	pr,r43,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.spnt	b0,r40,40000000000FBDA0; br.ret	b0 }

l40000000000FBDB0:
	{ addl	r45,-5996,r1; addl	r46,5,r0; adds	r44,0x0,r0; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r42; nop.m	0x0; addl	r44,1,r0 }
	{ adds	r45,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r42; ld8	r44,[r33]; adds	r33,0x0,r0; }
	{ nop.m	0x0; addl	r45,-5964,r1; nop.i	0x0; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,hash_walk; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	40000000000FBD90; }

l40000000000FBE30:
	{ addl	r44,-6004,r1; nop.m	0x0; addl	r33,1,r0; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,sh_needarg; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r42; mov	pr,r43,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r41; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r40,40000000000FBE70; br.ret	b0 }

l40000000000FBE80:
	{ addl	r14,6456,r1; nop.m	0x0; nop.i	0x0; }
	{ ld4	r14,[r14]; cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r33,0x0,r0; (p07) br.cond.dptk.few	40000000000FB740; }

l40000000000FBEAC:
	{ (p05) nop; Invalid; add	r0,r32,r0 }

l40000000000FBEB0:
	{ addl	r45,-5988,r1; nop.m	0x0; adds	r44,0x0,r0 }
	{ addl	r46,5,r0; nop.m	0x0; adds	r33,0x0,r0; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r42; addl	r44,1,r0; adds	r45,0x0,r8; }
	{ addl	r14,9036,r1; nop.m	0x0; nop.i	0x0; }
	{ ld8	r46,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r42; mov	pr,r43,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r41; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r40,40000000000FBF30; br.ret	b0 }

l40000000000FBF40:
	{ nop.m	0x0; ld8	r14,[r34]; addl	r33,1,r0 }
	{ cmp4.eq	p18,p19,0x0,r38; nop.i	0x0; cmp.eq	p16,p17,0x0,r14; }

l40000000000FBF60:
	{ adds	r36,0x8,r34; ld8	r14,[r36]; nop.i	0x0; }
	{ ld8	r44,[r14]; nop.i	0x0; br.call.sptk.many	b0,phash_search; }
	{ adds	r1,0x0,r42; cmp.eq	p07,p06,0x0,r8; nop.i	0x0 }
	{ adds	r35,0x0,r8; (p17) addl	r44,1,r0; (p07) br.cond.dpnt.few	40000000000FC0A0; }

l40000000000FBF9C:
	{ Invalid; break.i	0x1000; br.cond	b0 }

l40000000000FBFA0:
	{ nop.m	0x0; nop.i	0x0; (p19) br.cond.dpnt.few	40000000000FC060; }

l40000000000FBFB0:
	{ (p17) ld8	r14,[r36]; nop.m	0x0; (p17) addl	r45,-5980,r1; }

l40000000000FBFB6:
	{ nop; (p22) nop; dep	r0,r0,r32,63,1 }

l40000000000FBFC0:
	{ nop.m	0x0; (p17) ld8	r45,[r45]; nop.i	0x0; }

l40000000000FBFCC:
	{ cmp.gt	p00,p49,r0,r0; Invalid; Invalid }

l40000000000FBFD6:
	{ nop; (p32) nop; dep	r0,r0,r32,63,1 }

l40000000000FBFE0:
	{ nop.m	0x0; (p17) adds	r1,0x0,r42; adds	r44,0x0,r35 }

l40000000000FBFEC:
	{ nop; break.x	0x8000001000; }
	{ (p28) nop; invala; break.b	0x1000 }
	{ nop; dep	r0,r32,r0,63,1; Invalid }

l40000000000FC010:
	{ nop.m	0x0; ld8	r34,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	40000000000FBF60; }

l40000000000FC030:
	{ xor	r33,0x1,r33; nop.m	0x0; mov	pr,r43,0xFFFFFFFFFFFFFFFE; }
	{ adds	r8,0x0,r33; nop.m	0x0; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.spnt	b0,r40,40000000000FC050; br.ret	b0 }

l40000000000FC060:
	{ ld8	r14,[r36]; addl	r45,-6028,r1; addl	r44,1,r0 }
	{ adds	r46,0x0,r8; ld8	r45,[r45]; nop.i	0x0; }
	{ ld8	r47,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	40000000000FC010 }

l40000000000FC0A0:
	{ ld8	r14,[r36]; nop.m	0x0; adds	r33,0x0,r0; }
	{ ld8	r44,[r14]; nop.i	0x0; br.call.sptk.many	b0,sh_notfound; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	40000000000FC010 }

l40000000000FC0D0:
	{ adds	r45,0x0,r39; ld4	r46,[r38]; nop.i	0x0 }
	{ adds	r47,0x0,r0; adds	r44,0x0,r36; br.call.sptk.many	b0,phash_insert; }
	{ adds	r1,0x0,r42; adds	r44,0x0,r39; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ ld8	r34,[r34]; nop.m	0x0; adds	r1,0x0,r42; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	40000000000FB9E0 }

l40000000000FC120:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000FBAB0 }

l40000000000FC130:
	{ adds	r44,0x0,r36; addl	r33,1,r0; br.call.sptk.many	b0,sh_notfound; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	40000000000FBCD0; }
40000000000FC150 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000FC160 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000FC170 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; fn40000000000FC180: 40000000000FC180
;;   Called from:
;;     40000000000FCD1C (in help_builtin)
;;     40000000000FD21C (in help_builtin)
;;     40000000000FD4BC (in help_builtin)
fn40000000000FC180 proc
	{ alloc	r36,ar.pfs,0x9,0x0,0x6; nop.m	0x0; mov	r35,b3 }
	{ adds	r37,0x0,r1; nop.m	0x0; adds	r38,0x0,r32; }
	{ adds	r39,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B4E0; }
	{ adds	r33,0x0,r8; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; nop.b	0x0 }
	{ adds	r1,0x0,r37; mov.i	ar.pfs,r36; (p07) br.cond.spnt.few	40000000000FC1E0; }

l40000000000FC1D0:
	{ adds	r8,0x0,r33; mov.spnt	b0,r35,40000000000FC1D0; br.ret	b0 }

l40000000000FC1E0:
	{ addl	r39,-980,r1; addl	r40,5,r0; adds	r38,0x0,r0; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r37; adds	r34,0x0,r8; br.call.sptk.many	b0,fn400000000001B840; }
	{ nop.m	0x0; adds	r1,0x0,r37; nop.i	0x0 }
	{ ld4	r38,[r8]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B4A0; }
	{ adds	r1,0x0,r37; adds	r40,0x0,r8; nop.i	0x0 }
	{ adds	r38,0x0,r34; adds	r39,0x0,r32; br.call.sptk.many	b0,builtin_error; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r37; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000FC260; br.ret	b0; }
40000000000FC270 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; help_builtin: 40000000000FC280
help_builtin proc
	{ alloc	r54,ar.pfs,0x1F,0x0,0x1A; adds	r12,0xFFFFFFFFFFFFFF70,r12; mov	r57,LC }
	{ adds	r55,0x0,r1; nop.i	0x0; mov	r56,pr }
	{ adds	r35,0x0,r0; adds	r36,0x0,r0; adds	r34,0x0,r0; }
	{ nop.m	0x0; mov	r53,b5; nop.i	0x0 }
	{ nop.m	0x0; br.call.sptk.many	b0,reset_internal_getopt; nop.b	0x0; }
	{ adds	r1,0x0,r55; nop.m	0x0; nop.i	0x0; }

l40000000000FC2E0:
	{ addl	r59,-972,r1; nop.m	0x0; adds	r58,0x0,r32; }
	{ ld8	r59,[r59]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r55; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dpnt.few	40000000000FC3C0; }

l40000000000FC310:
	{ cmp4.eq	p06,p07,0x6D,r8; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000FCC10; }

l40000000000FC320:
	{ cmp4.eq	p06,p07,0x73,r8; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000FCC00; }

l40000000000FC330:
	{ cmp4.eq	p06,p07,0x64,r8; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000FC390; }

l40000000000FC340:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ addl	r8,258,r0; adds	r1,0x0,r55; mov	pr,r56,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r54; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r57; mov.spnt	b0,r53,40000000000FC370 }
	{ nop.m	0x0; adds	r12,0x90,r12; br.ret	b0 }

l40000000000FC390:
	{ addl	r59,-972,r1; adds	r58,0x0,r32; addl	r36,1,r0; }
	{ ld8	r59,[r59]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r55; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p06) br.cond.dptk.few	40000000000FC310; }

l40000000000FC3C0:
	{ addl	r14,9268,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld8	r49,[r14]; nop.i	0x0; }
	{ adds	r33,0x8,r49; cmp.eq	p07,p06,0x0,r49; (p07) br.cond.dpnt.few	40000000000FD750; }

l40000000000FC3F0:
	{ nop.m	0x0; ld8	r14,[r33]; nop.i	0x0; }
	{ ld8	r58,[r14]; nop.i	0x0; br.call.sptk.many	b0,glob_pattern_p; }
	{ adds	r1,0x0,r55; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	40000000000FC4E0; }

l40000000000FC420:
	{ ld8	r61,[r49]; addl	r60,-932,r1; addl	r59,-940,r1 }
	{ addl	r62,5,r0; adds	r58,0x0,r0; cmp.eq	p06,p07,0x0,r61 }
	{ ld8	r60,[r60]; ld8	r59,[r59]; nop.i	0x0; }
	{ nop.m	0x0; (p06) addl	r61,1,r0; nop.i	0x0; }

l40000000000FC45C:
	{ nop; zxt4	r0,r0; break.i	0x1000 }

l40000000000FC466:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; (p29) nop; (p48) nop }
	{ break.m	0x4000; Invalid; (p16) nop }
	{ Invalid; (p29) nop; (p48) nop }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; nop; (p32) nop }
	{ (p32) flushrs; nop; (p16) nop }
	{ break.m	0x4000; nop; nop }
