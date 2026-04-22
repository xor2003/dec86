;;; Segment .text (400000000001C480)

l40000000000DC480:
	{ adds	r8,0x0,r33; mov.i	ar.pfs,r35; mov.spnt	b0,r34,40000000000DC480 }
	{ nop.m	0x0; adds	r12,0x90,r12; br.ret	b0; }

l40000000000DC4A0:
	{ adds	r37,0x0,r32; addl	r38,1,r0; br.call.sptk.many	b0,fn400000000001AB80; }
	{ cmp4.eq	p06,p07,0x0,r8; nop.m	0x0; adds	r1,0x0,r36 }
	{ adds	r37,0x0,r32; addl	r38,4,r0; (p07) addl	r33,1,r0; }

l40000000000DC4D0:
	{ (p06) addl	r33,3,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB80; }

l40000000000DC4D6:
	{ break.m	0x4000; Invalid; (p48) nop }
	{ Invalid; Invalid; nop.b	0x21002 }

l40000000000DC4F0:
	{ adds	r8,0x0,r33; mov.i	ar.pfs,r35; mov.spnt	b0,r34,40000000000DC4F0 }
	{ nop.m	0x0; adds	r12,0x90,r12; br.ret	b0; }
40000000000DC510 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000DC520 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000DC530 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000DC540: 40000000000DC540
;;   Called from:
;;     40000000000DCFBC (in fn40000000000DCB80)
;;     40000000000DD76C (in user_command_matches)
fn40000000000DC540 proc
	{ alloc	r35,ar.pfs,0x7,0x0,0x5; nop.m	0x0; mov	r34,b2 }
	{ adds	r36,0x0,r1; nop.m	0x0; adds	r37,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,file_status; }
	{ nop.m	0x0; tbit.z	p06,p07,r8,0x0; nop.i	0x0 }
	{ adds	r1,0x0,r36; adds	r37,0x0,r32; (p06) br.cond.dpnt.few	40000000000DC620; }

l40000000000DC590:
	{ nop.m	0x0; tbit.z	p07,p06,r33,0x0; (p06) br.cond.dpnt.few	40000000000DC5C0; }

l40000000000DC5A0:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x3; (p06) br.cond.dpnt.few	40000000000DC620; }

l40000000000DC5B0:
	{ nop.m	0x0; tbit.z	p06,p07,r8,0x1; (p06) br.cond.dpnt.few	40000000000DC620 }

l40000000000DC5C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r36; adds	r37,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r37,0x0,r8 }
	{ adds	r38,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r36; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000DC610; br.ret	b0 }

l40000000000DC620:
	{ adds	r8,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000DC630; br.ret	b0; }

;; fn40000000000DC640: 40000000000DC640
;;   Called from:
;;     40000000000DCD9C (in fn40000000000DCB80)
;;     40000000000DD93C (in user_command_matches)
fn40000000000DC640 proc
	{ alloc	r41,ar.pfs,0x10,0x0,0xC; ld1	r14,[r33]; mov	r43,pr }
	{ nop.m	0x0; adds	r42,0x0,r1; nop.i	0x0; }
	{ nop.m	0x0; mov	r40,b0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x7E,r14; (p07) br.cond.dpnt.few	40000000000DC9C0; }

l40000000000DC680:
	{ (p06) adds	r36,0x0,r33; nop.m	0x0; nop.i	0x0 }

l40000000000DC686:
	{ break.m	0x4000; nop; (p16) nop }

l40000000000DC690:
	{ addl	r37,8268,r1; ld4	r14,[r37]; nop.i	0x0; }

l40000000000DC692:
	{ Invalid; (p16) break.i	0x20209; clrrrb; }
	{ Invalid; (p32) nop; Invalid }

l40000000000DC6B0:
	{ ld1	r14,[r36]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r14; (p07) br.cond.dpnt.few	40000000000DC9E0 }

l40000000000DC6D0:
	{ adds	r45,0x0,r32; nop.m	0x0; adds	r46,0x0,r0 }
	{ adds	r44,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,sh_makepath; }
	{ adds	r1,0x0,r42; nop.m	0x0; adds	r37,0x0,r8 }
	{ adds	r44,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,file_status; }
	{ cmp.eq	p06,p07,r36,r33; adds	r1,0x0,r42; nop.i	0x0 }
	{ adds	r38,0x0,r8; adds	r44,0x0,r36; (p06) br.cond.dpnt.few	40000000000DC750; }

l40000000000DC730:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r42; nop.m	0x0; nop.i	0x0 }

l40000000000DC750:
	{ nop.m	0x0; tbit.z	p07,p06,r38,0x0; (p07) br.cond.dpnt.few	40000000000DC8C0; }

l40000000000DC760:
	{ nop.m	0x0; tbit.z	p07,p06,r34,0x0; (p06) br.cond.dpnt.few	40000000000DC820; }

l40000000000DC770:
	{ nop.m	0x0; tnat.z	p16,p17,r34; (p17) br.cond.dptk.few	40000000000DC840 }

l40000000000DC780:
	{ and	r36,0xC,r34; tbit.z	p06,p07,r38,0x1; (p06) br.cond.dptk.few	40000000000DC870; }

l40000000000DC790:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r36; (p06) br.cond.dptk.few	40000000000DC870; }

l40000000000DC7A0:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x5; (p06) br.cond.dptk.few	40000000000DC7C0; }

l40000000000DC7B0:
	{ nop.m	0x0; tbit.z	p07,p06,r38,0x4; (p06) br.cond.dptk.few	40000000000DC870 }

l40000000000DC7C0:
	{ addl	r36,8276,r1; ld8	r44,[r36]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r44; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000DC800; }

l40000000000DC7E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r42; nop.m	0x0; nop.i	0x0 }

l40000000000DC800:
	{ st8	[r0],r36; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000DC820:
	{ adds	r8,0x0,r37; mov	pr,r43,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.spnt	b0,r40,40000000000DC830; br.ret	b0 }

l40000000000DC840:
	{ nop.m	0x0; tbit.z	p07,p06,r38,0x6; and	r36,0xC,r34 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000DC820; }

l40000000000DC860:
	{ nop.m	0x0; tbit.z	p06,p07,r38,0x1; (p07) br.cond.dptk.few	40000000000DC790; }

l40000000000DC870:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x2; (p07) br.cond.dptk.few	40000000000DC910; }

l40000000000DC880:
	{ cmp4.eq	p07,p06,0x0,r36; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000DC8C0; }

l40000000000DC890:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x5; (p07) br.cond.dptk.few	40000000000DC990; }

l40000000000DC8A0:
	{ nop.m	0x0; tbit.z	p07,p06,r38,0x6; nop.i	0x0 }
	{ nop.b	0x0; (p16) br.cond.dpnt.few	40000000000DC820; (p06) br.cond.dptk.few	40000000000DC820 }

l40000000000DC8BC:
	{ (p59) nop; add	r0,r32,r0; Invalid }

l40000000000DC8C0:
	{ nop.m	0x0; adds	r44,0x0,r37; adds	r37,0x0,r0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r42; nop.m	0x0; nop.i	0x0 }

l40000000000DC8F0:
	{ adds	r8,0x0,r37; mov	pr,r43,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.spnt	b0,r40,40000000000DC900; br.ret	b0 }

l40000000000DC910:
	{ addl	r39,8276,r1; ld8	r14,[r39]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000DC880 }

l40000000000DC930:
	{ adds	r44,0x0,r37; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r42; adds	r44,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r42; nop.m	0x0; adds	r44,0x0,r8 }
	{ adds	r45,0x0,r37; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; adds	r1,0x0,r42; nop.i	0x0 }
	{ st8	[r8],r39; nop.m	0x0; br.cond.sptk.few	40000000000DC880 }

l40000000000DC990:
	{ nop.m	0x0; tbit.z	p07,p06,r38,0x4; (p07) br.cond.dptk.few	40000000000DC8A0 }

l40000000000DC9A0:
	{ adds	r44,0x0,r37; adds	r37,0x0,r0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	40000000000DC8F0 }

l40000000000DC9C0:
	{ adds	r44,0x0,r33; adds	r45,0x0,r0; br.call.sptk.many	b0,bash_tilde_expand; }
	{ adds	r1,0x0,r42; adds	r36,0x0,r8; br.cond.sptk.few	40000000000DC690; }

l40000000000DC9E0:
	{ addl	r44,-4380,r1; nop.m	0x0; adds	r45,0x0,r36 }
	{ adds	r46,0x0,r35; nop.m	0x0; adds	r47,0x0,r0; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,same_file; }
	{ nop.m	0x0; adds	r1,0x0,r42; nop.i	0x0 }
	{ st4	[r8],r37; nop.m	0x0; br.cond.sptk.few	40000000000DC6D0; }
40000000000DCA30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; executable_file: 40000000000DCA40
;;   Called from:
;;     400000000005028C (in shell_execve)
;;     40000000000A98FC (in phash_search)
;;     40000000000A99BC (in phash_search)
;;     40000000000CCDFC (in command_word_completion_function)
;;     40000000000F80CC (in exec_builtin)
;;     40000000000FBC6C (in hash_builtin)
executable_file proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; nop.m	0x0; mov	r34,b2 }
	{ adds	r36,0x0,r1; nop.m	0x0; adds	r37,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,file_status; }
	{ adds	r33,0x0,r8; nop.m	0x0; adds	r1,0x0,r36; }
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x4; (p06) br.cond.dpnt.few	40000000000DCAC0; }

l40000000000DCA90:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ addl	r14,21,r0; nop.m	0x0; adds	r1,0x0,r36; }
	{ st4	[r14],r8; nop.m	0x0; nop.i	0x0 }

l40000000000DCAC0:
	{ and	r33,0x12,r33; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ cmp4.eq	p06,p07,0x2,r33; mov.spnt	b0,r34,40000000000DCAD0; (p06) addl	r8,1,r0; }

l40000000000DCAE0:
	{ nop.m	0x0; (p07) adds	r8,0x0,r0; br.ret	b0; }

l40000000000DCAEC:
	{ nop; break.m	0x1000; break.i	0x1000 }
40000000000DCAF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; is_directory: 40000000000DCB00
;;   Called from:
;;     40000000000DCDEC (in fn40000000000DCB80)
;;     40000000000DCEEC (in fn40000000000DCB80)
;;     40000000000FBA2C (in hash_builtin)
is_directory proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; nop.m	0x0; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; adds	r36,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,file_status; }
	{ adds	r1,0x0,r35; and	r8,0x10,r8; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000DCB40; br.ret	b0; }
40000000000DCB50 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000DCB60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000DCB70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000DCB80: 40000000000DCB80
;;   Called from:
;;     40000000000DD106 (in fn40000000000DD000)
;;     40000000000DD306 (in search_for_command)
fn40000000000DCB80 proc
	{ alloc	r42,ar.pfs,0x10,0x0,0xC; adds	r12,0xFFFFFFFFFFFFFF60,r12; mov	r41,b1 }
	{ addl	r14,8268,r1; adds	r43,0x0,r1; adds	r44,0x0,r32; }
	{ st4	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,absolute_program; }
	{ cmp4.eq	p06,p07,0x0,r8; nop.m	0x0; adds	r1,0x0,r43 }
	{ adds	r44,0x0,r32; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000DCFB0; }

l40000000000DCBD0:
	{ cmp.eq	p06,p07,0x0,r33; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000DCC00; }

l40000000000DCBE0:
	{ ld1	r14,[r33]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dpnt.few	40000000000DCC70 }

l40000000000DCC00:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r43; adds	r44,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r43; nop.m	0x0; adds	r44,0x0,r8 }
	{ adds	r45,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; adds	r1,0x0,r43; adds	r36,0x0,r8; }

l40000000000DCC50:
	{ adds	r8,0x0,r36; mov.i	ar.pfs,r42; mov.spnt	b0,r41,40000000000DCC50 }
	{ nop.m	0x0; adds	r12,0xA0,r12; br.ret	b0; }

l40000000000DCC70:
	{ addl	r40,8276,r1; addl	r45,-4380,r1; addl	r38,7676,r1 }
	{ addl	r39,7684,r1; adds	r37,0xA0,r12; addl	r44,1,r0; }
	{ adds	r46,0x10,r12; st8	[r0],r40; nop.i	0x0 }
	{ ld8	r45,[r45]; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AFE0; }
	{ adds	r1,0x0,r43; st4	[r0],r37; adds	r14,0x0,r0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000DCCE0:
	{ nop.m	0x0; sxt4	r14,r14; add	r14,r33,r14; }
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000DCEC0; }

l40000000000DCD10:
	{ nop.m	0x0; ld4.acq	r14,[r38]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000DCF40; }

l40000000000DCD30:
	{ nop.m	0x0; ld4.acq	r14,[r39]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000DCE60 }

l40000000000DCD50:
	{ adds	r44,0x0,r33; adds	r45,0x0,r37; br.call.sptk.many	b0,fn40000000000DC300; }
	{ adds	r46,0x0,r34; adds	r35,0x0,r8; adds	r45,0x0,r8 }
	{ adds	r47,0x10,r12; adds	r44,0x0,r32; adds	r1,0x0,r43; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	40000000000DCEC0 }

l40000000000DCD90:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000DC640; }
	{ adds	r1,0x0,r43; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r44,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ cmp.eq	p06,p07,0x0,r36; nop.m	0x0; adds	r1,0x0,r43 }
	{ adds	r44,0x0,r36; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000DCFA0; }

l40000000000DCDE0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,is_directory; }
	{ adds	r1,0x0,r43; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dpnt.few	40000000000DCF80; }

l40000000000DCE00:
	{ nop.m	0x0; ld8	r44,[r40]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r44; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000DCC50; }

l40000000000DCE20:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r8,0x0,r36; adds	r1,0x0,r43; mov.i	ar.pfs,r42; }
	{ nop.m	0x0; mov.spnt	b0,r41,40000000000DCE40; nop.i	0x0 }
	{ adds	r12,0xA0,r12; nop.m	0x0; br.ret	b0; }

l40000000000DCE60:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,throw_to_top_level; }
	{ adds	r1,0x0,r43; nop.m	0x0; adds	r44,0x0,r33 }
	{ adds	r45,0x0,r37; nop.m	0x0; br.call.sptk.many	b0,fn40000000000DC300; }
	{ adds	r1,0x0,r43; adds	r35,0x0,r8; adds	r45,0x0,r8 }
	{ adds	r46,0x0,r34; adds	r47,0x10,r12; adds	r44,0x0,r32; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000000DCD90; }

l40000000000DCEC0:
	{ ld8	r36,[r40]; nop.m	0x0; tbit.z	p08,p09,r34,0x5; }
	{ cmp.eq	p07,p06,0x0,r36; (p07) br.cond.dpnt.few	40000000000DCC50; (p08) br.cond.dptk.few	40000000000DCC50 }

l40000000000DCEDC:
	{ (p44) shladd	r127,r63,0x2,r37; zxt1	r0,r64; break.i	0x1000 }

l40000000000DCEE0:
	{ adds	r44,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,is_directory; }
	{ adds	r1,0x0,r43; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	40000000000DCC50 }

l40000000000DCF00:
	{ adds	r44,0x0,r36; adds	r36,0x0,r0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r43; adds	r8,0x0,r36; addl	r14,8276,r1; }
	{ st8	[r0],r14; mov.i	ar.pfs,r42; mov.spnt	b0,r41,40000000000DCF20 }
	{ nop.m	0x0; adds	r12,0xA0,r12; br.ret	b0; }

l40000000000DCF40:
	{ ld4.acq	r44,[r38]; nop.i	0x0; br.call.sptk.many	b0,termsig_handler; }
	{ ld4.acq	r14,[r39]; nop.m	0x0; adds	r1,0x0,r43; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000DCD50 }

l40000000000DCF70:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000DCE60 }

l40000000000DCF80:
	{ nop.m	0x0; adds	r44,0x0,r36; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r43; nop.m	0x0; nop.i	0x0 }

l40000000000DCFA0:
	{ ld4	r14,[r37]; nop.i	0x0; br.cond.sptk.few	40000000000DCCE0 }

l40000000000DCFB0:
	{ adds	r45,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn40000000000DC540; }
	{ adds	r36,0x0,r8; nop.m	0x0; adds	r1,0x0,r43; }
	{ adds	r8,0x0,r36; mov.i	ar.pfs,r42; mov.spnt	b0,r41,40000000000DCFD0 }
	{ nop.m	0x0; adds	r12,0xA0,r12; br.ret	b0; }
40000000000DCFF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000DD000: 40000000000DD000
;;   Called from:
;;     40000000000DD1DC (in find_user_command)
;;     40000000000DD21C (in find_path_file)
fn40000000000DD000 proc
	{ alloc	r37,ar.pfs,0x9,0x0,0x7; addl	r39,-4372,r1; mov	r36,b4 }
	{ adds	r38,0x0,r1; adds	r35,0x0,r32; adds	r34,0x0,r33; }
	{ ld8	r39,[r39]; addl	r40,1,r0; br.call.sptk.many	b0,find_variable_internal; }
	{ adds	r14,0x8,r8; adds	r1,0x0,r38; nop.i	0x0 }
	{ adds	r39,0x0,r32; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	40000000000DD090; }

l40000000000DD050:
	{ nop.m	0x0; ld8	r33,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r33; nop.i	0x0; (p06) br.cond.spnt.few	40000000000DD090; }

l40000000000DD070:
	{ ld1	r15,[r33]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p06) br.cond.dpnt.few	40000000000DD0F0 }

l40000000000DD090:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r38; adds	r39,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r38; nop.m	0x0; adds	r39,0x0,r8 }
	{ adds	r40,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r38; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000DD0E0; br.ret	b0; }

l40000000000DD0F0:
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000DD0F0; mov.i	ar.pfs,r37; }
	{ alloc	r2,ar.pfs,0x3,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000DCB80; }
40000000000DD110 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000DD120 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000DD130 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; executable_or_directory: 40000000000DD140
;;   Called from:
;;     40000000000CC7AC (in command_word_completion_function)
;;     40000000000CD4AC (in command_word_completion_function)
;;     40000000000CD4AC (in command_word_completion_function)
executable_or_directory proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; nop.m	0x0; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; adds	r36,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,file_status; }
	{ and	r8,0x12,r8; adds	r1,0x0,r35; mov.i	ar.pfs,r34; }
	{ cmp4.eq	p07,p06,0x0,r8; mov.spnt	b0,r33,40000000000DD180; (p06) addl	r8,1,r0; }

l40000000000DD190:
	{ nop.m	0x0; (p07) adds	r8,0x0,r0; br.ret	b0; }

l40000000000DD19C:
	{ nop; break.m	0x1000; break.i	0x1000 }
40000000000DD1A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000DD1B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; find_user_command: 40000000000DD1C0
;;   Called from:
;;     400000000006C43C (in initialize_shell_variables)
;;     40000000000FBC3C (in hash_builtin)
;;     400000000010EC0C (in describe_command)
find_user_command proc
	{ alloc	r16,ar.pfs,0x2,0x0,0x2; addl	r33,36,r0; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000DD000; }
40000000000DD1E0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000DD1F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; find_path_file: 40000000000DD200
;;   Called from:
;;     4000000000020FEC (in main)
;;     400000000010D3BC (in source_builtin)
find_path_file proc
	{ alloc	r16,ar.pfs,0x2,0x0,0x2; addl	r33,64,r0; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000DD000; }
40000000000DD220 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000DD230 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; search_for_command: 40000000000DD240
;;   Called from:
;;     40000000000F840C (in exec_builtin)
search_for_command proc
	{ alloc	r36,ar.pfs,0xA,0x0,0x6; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ addl	r38,-4372,r1; adds	r37,0x0,r1; mov	r35,b3; }
	{ ld8	r38,[r38]; addl	r39,1,r0; br.call.sptk.many	b0,find_variable_internal; }
	{ adds	r14,0x28,r8; adds	r1,0x0,r37; nop.i	0x0 }
	{ adds	r33,0x0,r8; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	40000000000DD380; }

l40000000000DD290:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x14; (p07) br.cond.dptk.few	40000000000DD380 }

l40000000000DD2B0:
	{ addl	r34,1,r0; nop.m	0x0; nop.i	0x0 }

l40000000000DD2C0:
	{ adds	r38,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,absolute_program; }
	{ cmp4.eq	p07,p06,0x0,r8; adds	r1,0x0,r37; (p06) br.cond.dpnt.few	40000000000DD580; }

l40000000000DD2E0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r34; (p06) br.cond.dptk.few	40000000000DD4E0 }

l40000000000DD2F0:
	{ adds	r33,0x8,r33; adds	r38,0x0,r32; addl	r40,36,r0; }
	{ ld8	r39,[r33]; br.call.sptk.many	b0,fn40000000000DCB80; nop.b	0x0; }
	{ adds	r1,0x0,r37; nop.m	0x0; nop.i	0x0; }
	{ addl	r14,5864,r1; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	40000000000DD360; }

l40000000000DD330:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000DD360; }

l40000000000DD350:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r34; (p07) br.cond.dpnt.few	40000000000DD520 }

l40000000000DD360:
	{ nop.m	0x0; mov.i	ar.pfs,r36; mov.spnt	b0,r35,40000000000DD360 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000000DD380:
	{ adds	r38,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,absolute_program; }
	{ cmp4.eq	p07,p06,0x0,r8; nop.m	0x0; adds	r1,0x0,r37; }
	{ (p06) adds	r34,0x0,r0; (p06) adds	r33,0x0,r0; (p06) br.cond.dptk.few	40000000000DD2C0 }

l40000000000DD3A6:
	{ (p16) chk.a.clr	r0,3FFFFFFFFF15D3A6; nop; (p32) nop.b	0x20009; }

l40000000000DD3AC:
	{ (p57) cmp.lt.unc	p63,p17,r63,r37; zxt1	r0,r64; break.i	0x1000 }

l40000000000DD3B0:
	{ adds	r38,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,phash_search; }
	{ adds	r1,0x0,r37; nop.m	0x0; cmp.eq	p06,p07,0x0,r8 }
	{ adds	r33,0x0,r8; nop.m	0x0; (p06) br.cond.spnt.few	40000000000DD4A0; }

l40000000000DD3E0:
	{ addl	r14,6456,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; addl	r14,9204,r1; (p06) br.cond.dpnt.few	40000000000DD430; }

l40000000000DD410:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000DD500 }

l40000000000DD430:
	{ adds	r38,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,file_status; }
	{ and	r8,0x3,r8; adds	r1,0x0,r37; adds	r38,0x0,r32; }
	{ cmp4.eq	p06,p07,0x3,r8; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000DD500; }

l40000000000DD460:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,phash_remove; }
	{ nop.m	0x0; adds	r1,0x0,r37; adds	r38,0x0,r33 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r37; nop.m	0x0; nop.i	0x0 }

l40000000000DD4A0:
	{ adds	r38,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,absolute_program; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r8; adds	r1,0x0,r37 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000DD580; }

l40000000000DD4D0:
	{ (p07) adds	r34,0x0,r0; nop.m	0x0; nop.i	0x0; }

l40000000000DD4D6:
	{ break.m	0x4000; nop; (p32) nop }

l40000000000DD4E0:
	{ adds	r38,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,find_user_command; }

l40000000000DD4E2:
	{ break.m	0x42008; cmp.ltu	p32,p00,r0,r0; Invalid; }

l40000000000DD4E6:
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; Invalid; nop.b	0x21002 }

l40000000000DD500:
	{ adds	r8,0x0,r33; mov.i	ar.pfs,r36; mov.spnt	b0,r35,40000000000DD500 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000DD520:
	{ addl	r14,8268,r1; adds	r39,0x0,r8; adds	r38,0x0,r32 }
	{ addl	r41,1,r0; ld4	r40,[r14]; adds	r14,0x10,r12; }
	{ st8	[r8],r14; nop.i	0x0; br.call.sptk.many	b0,phash_insert; }
	{ adds	r14,0x10,r12; nop.m	0x0; adds	r1,0x0,r37; }
	{ ld8	r8,[r14]; mov.i	ar.pfs,r36; mov.spnt	b0,r35,40000000000DD560 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000000DD580:
	{ adds	r38,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r37; adds	r38,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r38,0x0,r8 }
	{ adds	r39,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r37; mov.i	ar.pfs,r36; mov.spnt	b0,r35,40000000000DD5C0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }
40000000000DD5E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000DD5F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; user_command_matches: 40000000000DD600
;;   Called from:
;;     400000000010EC1C (in describe_command)
user_command_matches proc
	{ alloc	r46,ar.pfs,0x15,0x0,0x11; adds	r12,0xFFFFFFFFFFFFFF60,r12; nop.b	0x0 }
	{ addl	r37,8296,r1; mov	r48,LC; adds	r47,0x0,r1; }
	{ nop.m	0x0; mov	r45,b5; addl	r41,8284,r1 }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r34; (p06) br.cond.dptk.few	40000000000DD6B0; }

l40000000000DD640:
	{ ld4	r14,[r37]; ld8	r16,[r41]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r15,r14; adds	r14,0x1,r14; }
	{ shladd	r15,r15,0x3,r0; add	r15,r16,r15; nop.i	0x0; }
	{ ld8	r8,[r15]; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ (p07) st4	[r14],r37; mov.i	ar.pfs,r46; mov.i	LC,r48; }

l40000000000DD686:
	{ break.m	0xAA02E; break.i	0xAA0B0; break.i	0x80000 }
	{ Invalid; nop; nop }
	{ break.m	0x4000; (p34) nop; (p32) nop }

l40000000000DD6B0:
	{ addl	r42,8292,r1; ld8	r14,[r41]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000DDA70; }

l40000000000DD6D0:
	{ nop.m	0x0; ld4	r14,[r42]; nop.i	0x0; }
	{ cmp4.lt	p06,p07,0x0,r14; adds	r16,0xFFFFFFFFFFFFFFFF,r14; (p07) br.cond.dpnt.few	40000000000DD720; }

l40000000000DD6F0:
	{ (p06) ld8	r15,[r41]; nop.m	0x0; (p06) addp4	r16,r16,r0; }

l40000000000DD6F6:
	{ chk.a.nc	r0,3FFFFFFFFF0DDEF6; (p08) nop; add	r0,r0,r32 }

l40000000000DD700:
	{ nop.m	0x0; (p06) adds	r14,0x8,r15; (p06) mov.i	LC,r16; }

l40000000000DD70C:
	{ Invalid; cmp.eq.unc	p32,p08,r3,r102; (p01) nop }

l40000000000DD710:
	{ st8	[r0],r15; adds	r15,0x0,r14; br.cloop.sptk.few	40000000000DD7F0; }

l40000000000DD720:
	{ addl	r37,8296,r1; nop.m	0x0; adds	r49,0x0,r32; }
	{ st4	[r0],r37; nop.i	0x0; br.call.sptk.many	b0,absolute_program; }
	{ adds	r49,0x0,r32; nop.m	0x0; adds	r50,0x0,r33 }
	{ adds	r1,0x0,r47; cmp4.eq	p07,p06,0x0,r8; (p07) br.cond.dptk.few	40000000000DD820 }

l40000000000DD760:
	{ ld8	r35,[r41]; nop.i	0x0; br.call.sptk.many	b0,fn40000000000DC540; }
	{ ld8	r14,[r41]; adds	r1,0x0,r47; adds	r14,0x8,r14 }
	{ st8	[r8],r35; st8	[r0],r14; nop.i	0x0 }

l40000000000DD790:
	{ ld8	r16,[r41]; adds	r15,0x0,r0; adds	r14,0x0,r0 }
	{ st4	[r0],r37; add	r15,r16,r15; adds	r14,0x1,r14; }
	{ ld8	r8,[r15]; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ (p07) st4	[r14],r37; mov.i	ar.pfs,r46; mov.i	LC,r48; }

l40000000000DD7C6:
	{ break.m	0xAA02E; break.i	0xAA0B0; break.i	0x80000 }
	{ Invalid; nop; nop }
	{ break.m	0x4000; (p34) nop; (p32) nop }

l40000000000DD7F0:
	{ adds	r14,0x8,r14; st8	[r0],r15; nop.i	0x0; }
	{ nop.m	0x0; adds	r15,0x0,r14; br.cloop.sptk.few	40000000000DD7F0 }

l40000000000DD810:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000DD720 }

l40000000000DD820:
	{ addl	r14,8268,r1; addl	r40,8276,r1; addl	r50,-4380,r1 }
	{ adds	r51,0x10,r12; addl	r49,1,r0; adds	r38,0xA0,r12; }
	{ ld8	r50,[r50]; st4	[r0],r14; nop.i	0x0 }
	{ st8	[r0],r40; adds	r43,0x0,r37; br.call.sptk.many	b0,fn400000000001AFE0; }
	{ adds	r1,0x0,r47; addl	r49,-4372,r1; nop.i	0x0; }
	{ ld8	r49,[r49]; nop.i	0x0; br.call.sptk.many	b0,get_string_value; }
	{ nop.m	0x0; adds	r1,0x0,r47; adds	r39,0x0,r8 }
	{ st4	[r0],r38; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.spnt.few	40000000000DD790; }

l40000000000DD8A0:
	{ addl	r44,8292,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000DD8C0:
	{ ld4	r15,[r38]; adds	r49,0x0,r39; adds	r50,0x0,r38; }
	{ nop.m	0x0; sxt4	r14,r15; add	r14,r39,r14; }
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000DD790; }

l40000000000DD900:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000DC300; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r47; adds	r50,0x0,r8 }
	{ adds	r35,0x0,r8; adds	r51,0x0,r33; (p06) br.cond.dpnt.few	40000000000DD790; }

l40000000000DD930:
	{ adds	r52,0x10,r12; adds	r49,0x0,r32; br.call.sptk.many	b0,fn40000000000DC640; }
	{ adds	r1,0x0,r47; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r49,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r47; cmp.eq	p06,p07,0x0,r36; (p06) br.cond.dpnt.few	40000000000DD8C0; }

l40000000000DD970:
	{ ld4	r50,[r37]; ld4	r16,[r42]; nop.i	0x0; }
	{ nop.m	0x0; adds	r14,0x1,r50; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,r16,r14; (p06) br.cond.dpnt.few	40000000000DDA20; }

l40000000000DD9A0:
	{ (p07) ld8	r8,[r41]; nop.m	0x0; nop.i	0x0 }

l40000000000DD9A6:
	{ break.m	0x4000; break.i	0x4000; break.i	0x80000 }

l40000000000DD9B0:
	{ nop.m	0x0; sxt4	r15,r50; sxt4	r17,r14 }

l40000000000DD9B2:
	{ Invalid; Invalid; Invalid }

l40000000000DD9B6:
	{ (p07) add	r0,r50,r22; (p08) nop; (p16) br.call.sptk.few	b4,b0 }
	{ mf.a; nop; (p48) nop }
	{ Invalid; (p04) nop; nop }
	{ mf.a; nop; add	r0,r0,r0 }
	{ Invalid; (p32) nop; (p16) nop; }

l40000000000DD9FC:
	{ (p47) nop; invala; break.b	0x1000 }
	{ invala; Invalid; break.i	0x1000 }

l40000000000DDA10:
	{ st8	[r0],r40; nop.i	0x0; br.cond.sptk.few	40000000000DD8C0 }

l40000000000DDA20:
	{ adds	r14,0xB,r50; ld8	r49,[r41]; adds	r50,0xC,r50; }
	{ st4	[r14],r44; nop.i	0x0; br.call.sptk.many	b0,strvec_resize; }
	{ nop.m	0x0; ld4	r50,[r43]; adds	r1,0x0,r47 }
	{ nop.m	0x0; st8	[r8],r41; nop.i	0x0; }
	{ nop.m	0x0; adds	r14,0x1,r50; br.cond.sptk.few	40000000000DD9B0; }

l40000000000DDA70:
	{ addl	r14,5,r0; nop.m	0x0; addl	r49,5,r0; }
	{ st4	[r14],r42; nop.i	0x0; br.call.sptk.many	b0,strvec_create; }
	{ ld4	r14,[r42]; st8	[r8],r41; adds	r1,0x0,r47; }
	{ cmp4.lt	p06,p07,0x0,r14; nop.m	0x0; adds	r16,0xFFFFFFFFFFFFFFFF,r14; }
	{ (p06) ld8	r15,[r41]; nop.m	0x0; (p06) addp4	r16,r16,r0; }

l40000000000DDAB6:
	{ chk.a.nc	r0,3FFFFFFFFF0DE2B6; (p08) nop; (p33) nop }

l40000000000DDAC0:
	{ (p06) adds	r14,0x8,r15; (p06) mov.i	LC,r16; (p06) br.cond.dptk.few	40000000000DD710 }

l40000000000DDAC6:
	{ chk.a.nc	r16,3FFFFFFFFF0F2ED6; nop; break.i	0x80000; }

l40000000000DDACC:
	{ Invalid; break.i	0x1000; break.b	0x1000 }

l40000000000DDAD0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000DD720; }
40000000000DDAE0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000DDAF0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000DDB00 08 10 21 08 80 05 E0 A0 07 80 48 20 04 00 C4 00 ..!.......H ....
40000000000DDB10 09 18 01 02 00 21 00 00 00 02 00 80 04 02 20 80 .....!........ .
40000000000DDB20 09 00 00 1C 90 11 50 4A 00 00 48 E0 04 00 00 84 ......PJ..H.....
40000000000DDB30 11 30 01 1C 18 10 00 00 00 02 00 00 98 6C F6 58 .0...........l.X
40000000000DDB40 08 08 00 46 00 21 E0 00 20 00 42 00 20 02 AA 00 ...F.!.. .B. ...
40000000000DDB50 09 00 00 00 01 00 80 00 00 00 42 00 00 00 04 00 ..........B.....
40000000000DDB60 09 80 70 02 37 24 F0 A0 38 00 42 00 10 0A 00 07 ..p.7$..8.B.....
40000000000DDB70 09 00 00 00 01 00 20 01 3C 20 20 00 00 00 04 00 ...... .<  .....
40000000000DDB80 0A 90 20 24 2E 20 10 01 40 30 20 00 00 00 04 00 .. $. ..@0 .....
40000000000DDB90 02 00 48 1E 90 11 00 00 00 02 00 00 00 00 04 00 ..H.............
40000000000DDBA0 19 00 44 1C 98 11 00 70 40 30 23 80 08 00 84 00 ..D....p@0#.....
40000000000DDBB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000DDBC0 08 18 1D 0A 80 05 00 42 80 00 42 40 04 00 C4 00 .......B..B@....
40000000000DDBD0 09 20 01 02 00 21 00 00 00 02 00 C0 04 08 59 00 . ...!........Y.
40000000000DDBE0 09 00 00 00 01 00 E0 00 80 30 20 00 00 00 04 00 .........0 .....
40000000000DDBF0 11 28 01 1C 18 10 00 00 00 02 00 00 98 AD F8 58 .(.............X
40000000000DDC00 08 78 A0 10 00 21 10 00 90 00 42 00 30 02 AA 00 .x...!....B.0...
40000000000DDC10 19 38 00 10 06 39 00 11 00 00 C9 03 40 00 00 41 .8...9......@..A
40000000000DDC20 09 78 00 1E 18 10 E0 00 00 00 42 00 20 0A 00 07 .x........B. ...
40000000000DDC30 09 78 3C 20 0C 20 00 00 00 02 00 00 01 70 00 84 .x< . .......p..
40000000000DDC40 12 38 00 1E 06 B9 01 08 00 80 21 80 08 00 84 00 .8........!.....
40000000000DDC50 09 70 EC F9 FF 27 00 00 00 02 00 00 30 02 AA 00 .p...'......0...
40000000000DDC60 11 40 00 1C 00 21 00 10 05 80 03 80 08 00 84 00 .@...!..........
40000000000DDC70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000DDC80 18 58 45 1A 80 05 70 48 88 0C 63 00 00 00 00 20 .XE...pH..c.... 
40000000000DDC90 01 60 01 02 00 21 A0 02 00 62 00 A0 05 00 01 84 .`...!...b......
40000000000DDCA0 E9 78 05 44 00 21 00 00 00 02 00 C0 05 00 00 84 .x.D.!..........
40000000000DDCB0 D1 78 29 00 00 24 00 00 00 02 00 00 38 DB F3 58 .x)..$......8..X
40000000000DDCC0 08 00 00 00 01 00 30 02 20 00 42 20 00 60 01 84 ......0. .B .`..
40000000000DDCD0 18 00 00 00 01 00 70 40 00 0C E1 03 C0 03 00 43 ......p@.......C
40000000000DDCE0 08 28 01 00 00 21 D0 02 80 00 42 00 00 00 04 00 .(...!....B.....
40000000000DDCF0 19 70 05 00 00 24 F0 02 00 00 42 00 F8 DA F3 58 .p...$....B....X
40000000000DDD00 08 00 00 00 01 00 10 00 B0 00 42 C0 31 FA 7C 53 ..........B.1.|S
40000000000DDD10 09 40 01 10 00 21 E0 4A 00 00 48 00 06 00 00 84 .@...!.J..H.....
40000000000DDD20 02 20 D1 03 40 24 00 00 00 02 00 A0 54 72 50 7C . ..@$......TrP|
40000000000DDD30 0B 00 00 48 90 11 F0 02 90 30 20 00 00 00 04 00 ...H.....0 .....
40000000000DDD40 11 68 01 4A 00 21 00 00 00 02 00 00 88 6A F6 58 .h.J.!.......j.X
40000000000DDD50 08 70 50 10 00 21 10 00 B0 00 42 C0 04 40 00 84 .pP..!....B..@..
40000000000DDD60 0B 68 01 10 00 21 F0 00 38 20 20 00 00 00 04 00 .h...!..8  .....
40000000000DDD70 09 00 00 00 01 00 F0 40 3C 5C 40 00 00 00 04 00 .......@<\@.....
40000000000DDD80 11 00 3C 1C 90 11 00 00 00 02 00 00 08 18 F9 58 ..<............X
40000000000DDD90 08 00 00 00 01 00 10 00 B0 00 42 C0 01 FA 7C 53 ..........B...|S
40000000000DDDA0 09 38 01 10 00 21 00 18 91 20 23 E0 00 00 19 E6 .8...!... #.....
40000000000DDDB0 01 00 00 00 01 00 50 2A 39 28 3E 00 00 00 04 00 ......P*9(>.....
40000000000DDDC0 10 00 00 00 01 00 D0 02 94 00 C2 03 80 01 00 42 ...............B
40000000000DDDD0 08 70 1D 00 00 24 F0 02 90 30 20 00 06 00 00 84 .p...$...0 .....
40000000000DDDE0 19 00 00 00 01 00 00 00 00 02 00 00 E8 69 F6 58 .............i.X
40000000000DDDF0 08 30 00 50 87 39 80 10 80 12 63 C0 41 41 00 84 .0.P.9....c.AA..
40000000000DDE00 0A 08 00 58 00 21 12 09 00 00 48 43 12 00 00 90 ...X.!....HC....
40000000000DDE10 0B 80 00 1C 10 50 12 01 00 00 C2 43 02 00 00 84 .....P.....C....
40000000000DDE20 02 90 44 24 0C 20 10 41 40 5C 40 00 01 90 24 E6 ..D$. .A@\@...$.
40000000000DDE30 19 00 44 1C 90 11 00 00 00 02 00 04 30 00 00 41 ..D.........0..A
40000000000DDE40 03 48 24 46 88 31 00 00 00 02 80 04 82 82 B8 80 .H$F.1..........
40000000000DDE50 28 01 40 1C 90 11 00 00 00 02 00 00 00 00 04 00 (.@.............
40000000000DDE60 08 80 70 02 37 24 90 A2 04 6E 48 60 91 08 29 E6 ..p.7$...nH`..).
40000000000DDE70 09 40 24 40 89 31 00 30 21 30 23 00 00 00 04 00 .@$@.1.0!0#.....
40000000000DDE80 08 00 00 00 01 00 12 09 00 00 48 25 14 00 00 90 ..........H%....
40000000000DDE90 0B 00 00 00 01 40 12 01 00 00 C2 25 04 00 00 84 .....@.....%....
40000000000DDEA0 08 00 00 00 01 00 20 01 40 30 20 20 14 09 31 80 ...... .@0  ..1.
40000000000DDEB0 0A 88 00 52 18 10 80 00 84 12 73 00 00 00 04 00 ...R......s.....
40000000000DDEC0 09 00 48 4C 98 11 00 40 40 30 23 00 00 00 04 00 ..HL...@@0#.....
40000000000DDED0 08 00 44 4E 98 11 00 38 A5 30 23 00 00 00 04 00 ..DN...8.0#.....
40000000000DDEE0 16 00 00 00 00 08 02 08 00 80 A0 03 00 01 00 43 ...............C
40000000000DDEF0 09 38 08 40 86 31 00 00 00 02 00 00 B0 02 AA 00 .8.@.1..........
40000000000DDF00 11 30 02 50 C7 39 00 50 05 80 03 03 50 01 00 43 .0.P.9.P....P..C
40000000000DDF10 09 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
40000000000DDF20 11 00 00 00 01 00 60 50 38 0E A8 03 30 01 00 43 ......`P8...0..C
40000000000DDF30 11 00 00 00 01 80 81 00 00 00 42 80 08 00 84 00 ..........B.....
40000000000DDF40 08 70 19 00 00 24 F0 02 90 30 20 00 06 00 00 84 .p...$...0 .....
40000000000DDF50 19 00 00 00 01 00 00 00 00 02 00 00 78 68 F6 58 ............xh.X
40000000000DDF60 08 00 00 00 01 00 10 00 B0 00 42 C0 41 41 00 84 ..........B.AA..
40000000000DDF70 0A 00 98 10 98 11 10 E1 04 6E 48 00 42 09 DC 90 .........nH.B...
40000000000DDF80 0A A0 00 1C 10 10 00 00 00 02 00 80 82 A0 B8 80 ................
40000000000DDF90 0B 00 00 00 01 00 00 A0 38 20 23 00 00 00 04 00 ........8 #.....
40000000000DDFA0 09 98 00 22 18 10 20 01 40 30 20 00 00 00 04 00 ...".. .@0 .....
40000000000DDFB0 09 00 4C 4C 98 11 00 40 44 30 23 00 00 00 04 00 ..LL...@D0#.....
40000000000DDFC0 08 00 00 00 01 00 00 90 9C 30 23 00 00 00 04 00 .........0#.....
40000000000DDFD0 18 00 9C 20 98 11 00 00 00 02 00 00 20 FF FF 48 ... ........ ..H
40000000000DDFE0 08 00 8C 48 90 11 00 00 00 02 00 A0 05 28 01 84 ...H.........(..
40000000000DDFF0 09 70 1D 00 00 24 00 00 00 02 00 00 06 00 00 84 .p...$..........
40000000000DE000 11 78 01 48 18 10 00 00 00 02 00 00 C8 67 F6 58 .x.H.........g.X
40000000000DE010 09 70 50 10 00 21 00 01 A4 30 20 20 00 60 01 84 .pP..!...0  .`..
40000000000DE020 08 78 00 1C 10 10 00 80 20 30 23 00 00 00 04 00 .x...... 0#.....
40000000000DE030 03 00 20 52 98 11 00 00 00 02 00 E0 81 78 B8 80 .. R.........x..
40000000000DE040 08 00 3C 1C 90 11 00 00 00 02 00 00 00 00 04 00 ..<.............
40000000000DE050 08 68 01 46 00 21 00 00 00 02 00 C0 25 00 00 90 .h.F.!......%...
40000000000DE060 19 78 05 00 00 24 00 00 00 02 00 00 88 D7 F3 58 .x...$.........X
40000000000DE070 09 40 00 00 00 21 10 00 B0 00 42 00 B0 02 AA 00 .@...!....B.....
40000000000DE080 11 00 00 00 01 00 00 50 05 80 03 80 08 00 84 00 .......P........
40000000000DE090 08 68 01 40 00 21 00 00 00 02 00 C0 05 00 00 84 .h.@.!..........
40000000000DE0A0 19 78 29 00 00 24 00 00 00 02 00 00 48 D7 F3 58 .x)..$......H..X
40000000000DE0B0 08 00 00 00 01 00 10 00 B0 00 42 60 04 40 00 84 ..........B`.@..
40000000000DE0C0 19 00 00 00 01 00 70 40 00 0C 61 03 20 FC FF 4A ......p@..a. ..J
40000000000DE0D0 09 70 71 FB B8 27 F0 2A 00 00 48 A0 05 00 00 84 .pq..'.*..H.....
40000000000DE0E0 11 70 01 5C 18 10 00 00 00 02 00 00 88 CA F3 58 .p.\...........X
40000000000DE0F0 11 08 00 58 00 21 D0 02 20 00 42 00 D8 31 F9 58 ...X.!.. .B..1.X
40000000000DE100 09 40 FC F9 FF 27 10 00 B0 00 42 00 B0 02 AA 00 .@...'....B.....
40000000000DE110 11 00 00 00 01 00 00 50 05 80 03 80 08 00 84 00 .......P........
40000000000DE120 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000DE130 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000DE140 18 38 35 12 80 05 C0 00 33 7A 46 00 00 00 00 20 .85.....3zF.... 
40000000000DE150 01 40 01 02 00 21 60 02 00 62 00 40 05 00 01 84 .@...!`..b.@....
40000000000DE160 11 48 05 00 00 24 B0 02 31 02 42 00 88 CE F3 58 .H...$..1.B....X
40000000000DE170 10 08 00 50 00 21 70 00 20 0C 73 03 40 01 00 42 ...P.!p. .s.@..B
40000000000DE180 08 28 E1 18 01 21 30 02 00 C0 4B 80 04 00 00 94 .(...!0...K.....
40000000000DE190 09 50 FD F9 FB 27 90 02 80 00 42 60 65 03 0C 90 .P...'....B`e...
40000000000DE1A0 03 70 00 4A 10 10 A0 52 85 18 40 C0 31 72 30 80 .p.J...R..@.1r0.
40000000000DE1B0 11 38 90 1C 86 38 00 00 00 02 80 03 80 01 00 43 .8...8.........C
40000000000DE1C0 11 00 00 00 01 00 00 00 00 02 00 00 28 D3 F3 58 ............(..X
40000000000DE1D0 08 10 01 10 00 21 60 40 00 0E 61 20 00 40 01 84 .....!`@..a .@..
40000000000DE1E0 19 48 05 00 00 24 B0 82 30 00 42 03 20 01 00 43 .H...$..0.B. ..C
40000000000DE1F0 11 50 01 44 00 21 00 00 00 02 00 00 D8 D1 F3 58 .P.D.!.........X
40000000000DE200 08 70 A0 18 00 21 10 00 A0 00 42 C0 00 40 1C E6 .p...!....B..@..
40000000000DE210 19 48 01 40 00 21 B0 02 31 02 C2 03 50 01 00 43 .H.@.!..1...P..C
40000000000DE220 09 70 00 1C 10 10 C0 82 30 00 42 40 05 00 01 84 .p......0.B@....
40000000000DE230 09 00 00 00 01 00 E0 18 39 18 40 00 00 00 04 00 ........9.@.....
40000000000DE240 11 30 90 1C 87 38 00 00 00 02 00 03 20 01 00 43 .0...8...... ..C
40000000000DE250 0B 70 00 4A 10 10 30 1A 39 18 40 00 00 00 04 00 .p.J..0.9.@.....
40000000000DE260 11 30 90 46 87 38 00 00 00 02 00 03 00 01 00 43 .0.F.8.........C
40000000000DE270 11 00 00 00 01 00 00 00 00 02 00 00 58 1F F6 58 ............X..X
40000000000DE280 10 08 00 50 00 21 60 00 20 0E 73 03 E0 00 00 43 ...P.!`. .s....C
40000000000DE290 02 40 00 44 00 21 00 38 01 55 00 00 60 0A 00 07 .@.D.!.8.U..`...
40000000000DE2A0 18 00 00 00 01 00 C0 00 31 04 42 80 08 00 84 00 ........1.B.....
40000000000DE2B0 08 70 FC F9 FB 27 00 00 00 02 00 40 05 00 04 90 .p...'.....@....
40000000000DE2C0 03 48 01 40 00 21 B0 B2 01 06 48 20 E4 08 31 80 .H.@.!....H ..1.
40000000000DE2D0 11 50 A9 42 0E 20 00 00 00 02 00 00 18 D2 F3 58 .P.B. .........X
40000000000DE2E0 08 00 00 00 01 00 10 00 A0 00 42 40 04 40 00 84 ..........B@.@..
40000000000DE2F0 18 00 00 00 01 00 70 40 00 0C 61 03 A0 FF FF 4A ......p@..a....J
40000000000DE300 11 00 00 00 01 00 00 00 00 02 00 00 48 D5 F3 58 ............H..X
40000000000DE310 09 70 00 10 10 10 00 00 00 02 00 20 00 40 01 84 .p......... .@..
40000000000DE320 10 00 00 00 01 00 70 88 38 0C 73 03 70 FF FF 4A ......p.8.s.p..J
40000000000DE330 09 00 00 00 01 00 20 F2 F3 FF 4F 00 00 00 04 00 ...... ...O.....
40000000000DE340 02 40 00 44 00 21 00 38 01 55 00 00 60 0A 00 07 .@.D.!.8.U..`...
40000000000DE350 19 00 00 00 01 00 C0 00 31 04 42 80 08 00 84 00 ........1.B.....
40000000000DE360 11 48 01 44 00 21 20 F2 F3 FF 4F 00 E8 DF F3 58 .H.D.! ...O....X
40000000000DE370 11 08 00 50 00 21 00 00 00 02 00 00 D8 D4 F3 58 ...P.!.........X
40000000000DE380 09 70 44 00 00 24 00 00 00 02 00 20 00 40 01 84 .pD..$..... .@..
40000000000DE390 09 00 38 10 90 11 80 00 88 00 42 00 70 02 AA 00 ..8.......B.p...
40000000000DE3A0 00 00 00 00 01 00 00 30 05 80 03 00 00 00 04 00 .......0........
40000000000DE3B0 19 60 80 18 02 21 00 00 00 02 00 80 08 00 84 00 .`...!..........

;; redirection_expand: 40000000000DE3C0
;;   Called from:
;;     40000000000DE6BC (in fn40000000000DE580)
;;     40000000000E100C (in redirection_error)
;;     40000000000E11EC (in redirection_error)
redirection_expand proc
	{ alloc	r38,ar.pfs,0xA,0x0,0x8; addl	r34,9208,r1; mov	r37,b5 }
	{ adds	r39,0x0,r1; nop.m	0x0; adds	r40,0x0,r32; }
	{ nop.m	0x0; adds	r36,0x0,r0; br.call.sptk.many	b0,copy_word; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r14,0x8,r8 }
	{ adds	r41,0x0,r0; adds	r40,0x0,r8; addl	r15,6456,r1; }
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r15; (p07) ld4	r15,[r14]; nop.i	0x0; }

l40000000000DE42C:
	{ nop; cmp4.eq.or.andcm	p00,p32,r32,r0; zxt1	r100,r11 }

l40000000000DE43C:
	{ Invalid; Invalid; break.i	0x1000 }

l40000000000DE446:
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ add	r0,r0,r1; nop; (p48) nop }
	{ break.m	0x4000; (p20) nop; nop }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; nop; nop.b	0x2300A }
	{ mf.a; (p32) nop; (p32) nop }
	{ Invalid; (p20) nop; (p01) nop.b	0x9 }

l40000000000DE4B6:
	{ chk.a.nc	r0,3FFFFFFFFF0DECB6; nop; break.i	0x80000 }

l40000000000DE4C0:
	{ nop.m	0x0; ld8	r14,[r33]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000DE520; }

l40000000000DE4E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,dispose_words; }
	{ adds	r1,0x0,r39; nop.m	0x0; nop.i	0x0 }

l40000000000DE500:
	{ adds	r8,0x0,r36; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000DE510; br.ret	b0; }

l40000000000DE520:
	{ adds	r40,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,string_list; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r40,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,dispose_words; }
	{ nop.m	0x0; adds	r1,0x0,r39; br.cond.sptk.few	40000000000DE500; }
40000000000DE560 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000DE570 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000DE580: 40000000000DE580
;;   Called from:
;;     40000000000E172C (in do_redirections)
fn40000000000DE580 proc
	{ alloc	r45,ar.pfs,0x15,0x0,0x11; adds	r46,0x0,r12; adds	r12,0xFFFFFFFFFFFFFFE0,r12 }
	{ adds	r37,0x14,r32; adds	r16,0x18,r32; adds	r14,0x20,r32; }
	{ ld4	r34,[r16]; mov	r48,pr; adds	r38,0x8,r32 }
	{ adds	r47,0x0,r1; ld4	r15,[r37]; nop.b	0x0; }
	{ nop.m	0x0; ld8	r35,[r14]; tbit.z	p06,p07,r15,0x3 }
	{ cmp4.eq	p16,p17,0x11,r34; ld4	r40,[r14]; adds	r14,0xFFFFFFFFFFFFFFF3,r34; }
	{ (p07) or	r33,0x8,r33; cmp4.ltu	p07,p06,0x1,r14; mov	r44,b4 }

l40000000000DE5E6:
	{ Invalid; (p22) nop; break.b	0x80000 }
	{ (p18) fwb; nop; (p36) nop }
	{ chk.a.nc	r0,3FFFFFFFFF0DEE06; nop; (p48) nop }

l40000000000DE610:
	{ cmp4.eq	p07,p06,0x12,r34; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000DE6B0; }

l40000000000DE620:
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x13,r34; (p07) br.cond.dptk.few	40000000000DE670 }

l40000000000DE630:
	{ adds	r35,0x0,r0; nop.m	0x0; nop.i	0x0; }
	{ adds	r8,0x0,r35; mov	pr,r48,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r45; }
	{ nop.m	0x0; mov.spnt	b0,r44,40000000000DE650; nop.i	0x0 }
	{ adds	r12,0x0,r46; nop.m	0x0; br.ret	b0 }

l40000000000DE670:
	{ addl	r14,-9036,r1; nop.m	0x0; addp4	r15,r34,r0; }
	{ ld8	r14,[r14]; shladd	r14,r15,0x3,r14; nop.i	0x0; }
	{ ld8	r15,[r14]; add	r14,r14,r15; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r14,40000000000DE6A0; br.cond	b6; }

l40000000000DE6B0:
	{ adds	r49,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,redirection_expand; }
	{ adds	r1,0x0,r47; nop.m	0x0; cmp.eq	p07,p06,0x0,r8 }
	{ adds	r35,0x0,r8; nop.m	0x0; (p07) br.cond.spnt.few	40000000000DFE40; }

l40000000000DE6E0:
	{ ld1	r14,[r8]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r14; (p06) br.cond.dptk.few	40000000000DE730 }

l40000000000DE700:
	{ adds	r14,0x1,r8; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000DF220 }

l40000000000DE730:
	{ adds	r49,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,all_digits; }
	{ cmp4.eq	p06,p07,0x0,r8; adds	r14,0x10,r32; nop.i	0x0 }
	{ adds	r1,0x0,r47; adds	r49,0x0,r35; (p07) br.cond.dpnt.few	40000000000DF4C0; }

l40000000000DE760:
	{ cmp4.eq	p07,p06,0xE,r34; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000DF970; }

l40000000000DE770:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x0; (p06) br.cond.dpnt.few	40000000000DF970; }

l40000000000DE790:
	{ cmp4.eq	p07,p06,0x1,r36; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000DF970; }

l40000000000DE7A0:
	{ ld8	r36,[r38]; nop.i	0x0; br.call.sptk.many	b0,make_bare_word; }
	{ adds	r1,0x0,r47; adds	r49,0x0,r36; addl	r50,10,r0 }
	{ adds	r51,0x0,r8; adds	r52,0x0,r0; addl	r14,8308,r1; }
	{ st8	[r8],r14; nop.i	0x0; br.call.sptk.many	b0,make_redirection; }
	{ nop.m	0x0; adds	r1,0x0,r47; adds	r39,0x0,r8; }

l40000000000DE7F0:
	{ adds	r40,0x18,r39; adds	r49,0x0,r35; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ ld4	r34,[r40]; nop.m	0x0; adds	r1,0x0,r47; }
	{ cmp4.eq	p07,p06,0xA,r34; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000DF2C0; }

l40000000000DE820:
	{ nop.m	0x0; (p06) adds	r36,0x20,r39; nop.i	0x0; }

l40000000000DE82C:
	{ nop; Invalid; break.i	0x1000 }

l40000000000DE836:
	{ break.m	0x4000; nop; (p32) nop }

l40000000000DE840:
	{ adds	r14,0x14,r39; nop.m	0x0; adds	r15,0x8,r39 }
	{ ld4	r40,[r36]; nop.m	0x0; adds	r49,0x0,r39; }
	{ ld4	r14,[r14]; ld4	r36,[r15]; nop.i	0x0; }
	{ st4	[r14],r37; br.call.sptk.many	b0,dispose_redirects; nop.b	0x0; }
	{ adds	r1,0x0,r47; nop.m	0x0; nop.i	0x0 }

l40000000000DE890:
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x13,r34; (p06) br.cond.dptk.few	40000000000DE630 }

l40000000000DE8A0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000DE670; }
40000000000DE8B0 11 00 41 40 00 21 60 00 84 0E 28 03 80 FD FF 4B ..A@.!`...(....K
40000000000DE8C0 09 00 00 00 01 00 E0 00 80 20 20 00 00 00 04 00 .........  .....
40000000000DE8D0 11 00 00 00 01 00 60 00 38 0E A8 03 70 14 00 43 ......`.8...p..C
40000000000DE8E0 10 00 00 00 01 00 60 10 84 0E 28 03 D0 0A 00 42 ......`...(....B
40000000000DE8F0 08 88 01 48 00 21 00 00 00 02 00 40 16 00 00 90 ...H.!.....@....
40000000000DE900 19 98 01 00 00 21 00 00 00 02 00 00 E8 CE F3 58 .....!.........X
40000000000DE910 08 30 FC 11 87 3B 10 00 BC 00 42 20 06 20 01 84 .0...;....B . ..
40000000000DE920 19 90 25 00 00 24 30 FB F3 FF 4F 03 90 0A 00 43 ..%..$0...O....C
40000000000DE930 11 00 00 00 01 00 00 00 00 02 00 00 58 F3 FF 58 ............X..X
40000000000DE940 11 08 00 5E 00 21 70 40 00 0C 61 03 70 0A 00 42 ...^.!p@..a.p..B
40000000000DE950 10 00 00 00 01 00 60 20 01 0E 61 03 30 00 00 43 ......` ..a.0..C
40000000000DE960 11 00 00 00 01 00 10 03 90 00 42 00 E8 D9 F3 58 ..........B....X
40000000000DE970 09 08 00 5E 00 21 00 00 00 02 00 00 00 00 04 00 ...^.!..........
40000000000DE980 09 70 50 03 46 24 00 00 00 02 00 E0 11 00 00 90 .pP.F$..........
40000000000DE990 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000DE9A0 11 00 3C 1C 90 11 00 00 00 02 00 00 A8 CE F3 58 ..<............X
40000000000DE9B0 09 18 01 10 10 10 00 00 00 02 00 20 00 78 01 84 ........... .x..
40000000000DE9C0 10 00 00 00 01 00 70 00 8C 0C 73 03 80 FC FF 4A ......p...s....J
40000000000DE9D0 0B 18 59 00 00 24 80 00 8C 00 42 E0 0F 83 7F 0B ..Y..$....B.....
40000000000DE9E0 02 00 00 00 01 00 00 68 01 55 00 00 C0 0A 00 07 .......h.U......
40000000000DE9F0 18 00 00 00 01 00 C0 00 B8 00 42 80 08 00 84 00 ..........B.....
40000000000DEA00 10 00 00 00 01 00 60 00 84 0E 28 03 30 FC FF 4A ......`...(.0..J
40000000000DEA10 0B 28 41 40 00 21 E0 00 94 20 20 00 00 00 04 00 .(A@.!...  .....
40000000000DEA20 11 00 00 00 01 00 60 00 38 0E A8 03 D0 15 00 43 ......`.8......C
40000000000DEA30 11 38 90 50 86 38 00 00 00 02 80 03 00 FC FF 4B .8.P.8.........K
40000000000DEA40 10 00 00 00 01 00 60 10 84 0E A8 03 70 16 00 43 ......`.....p..C
40000000000DEA50 11 88 01 48 00 21 00 00 00 02 00 00 B8 2D FD 58 ...H.!.......-.X
40000000000DEA60 09 70 00 4A 10 10 00 00 00 02 00 20 00 78 01 84 .p.J....... .x..
40000000000DEA70 10 00 00 00 01 00 60 00 38 0E 28 03 60 12 00 42 ......`.8.(.`..B
40000000000DEA80 11 88 01 40 00 21 20 03 90 00 42 00 48 F1 FF 58 ...@.! ...B.H..X
40000000000DEA90 11 38 20 00 86 30 10 00 BC 00 C2 03 60 1D 00 43 .8 ..0......`..C
40000000000DEAA0 09 00 00 00 01 00 70 78 88 0C 73 00 00 00 04 00 ......px..s.....
40000000000DEAB0 10 00 00 00 01 00 70 30 88 8C F3 03 30 17 00 43 ......p0....0..C
40000000000DEAC0 08 88 01 50 00 21 00 00 00 02 00 40 16 00 00 90 ...P.!.....@....
40000000000DEAD0 19 98 01 00 00 21 00 00 00 02 00 00 18 CD F3 58 .....!.........X
40000000000DEAE0 11 30 04 10 87 39 10 00 BC 00 42 03 30 00 00 43 .0...9....B.0..C
40000000000DEAF0 11 30 04 50 87 31 00 00 00 02 80 03 50 19 00 43 .0.P.1......P..C
40000000000DEB00 11 00 00 00 01 00 60 20 84 0E 28 03 60 00 00 42 ......` ..(.`..B
40000000000DEB10 10 00 00 00 01 00 70 10 90 0C 63 03 50 00 00 42 ......p...c.P..B
40000000000DEB20 08 88 01 48 00 21 00 00 00 02 00 40 26 00 00 90 ...H.!.....@&...
40000000000DEB30 19 98 05 00 00 24 00 00 00 02 00 00 B8 CC F3 58 .....$.........X
40000000000DEB40 09 08 00 5E 00 21 00 00 00 02 00 00 00 00 04 00 ...^.!..........
40000000000DEB50 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000DEB60 04 00 00 00 01 00 00 28 00 00 00 C0 01 00 00 60 .......(.......`
40000000000DEB70 0B 78 00 4A 18 10 F0 70 3C 18 40 00 00 00 04 00 .x.J...p<.@.....
40000000000DEB80 10 00 00 00 01 00 70 70 3C 0C F0 03 80 16 00 43 ......pp<......C
40000000000DEB90 09 00 00 00 01 00 20 8A 8B 7E 46 00 00 00 04 00 ...... ..~F.....
40000000000DEBA0 10 00 00 00 01 00 60 08 88 0E 6B 03 90 FA FF 4A ......`...k....J
40000000000DEBB0 11 88 01 50 00 21 30 02 00 00 42 00 98 90 F6 58 ...P.!0...B....X
40000000000DEBC0 11 08 00 5E 00 21 10 03 A0 00 42 00 88 D7 F3 58 ...^.!....B....X
40000000000DEBD0 11 08 00 5E 00 21 10 03 A0 00 42 00 B8 11 F7 58 ...^.!....B....X
40000000000DEBE0 09 40 00 46 00 21 10 00 BC 00 42 E0 0F 83 7F 0B .@.F.!....B.....
40000000000DEBF0 02 00 00 00 01 00 00 68 01 55 00 00 C0 0A 00 07 .......h.U......
40000000000DEC00 18 00 00 00 01 00 C0 00 B8 00 42 80 08 00 84 00 ..........B.....
40000000000DEC10 0B 38 E1 02 32 24 00 00 00 02 00 00 00 00 04 00 .8..2$..........
40000000000DEC20 09 00 00 00 01 00 E0 00 9C 20 20 00 00 00 04 00 .........  .....
40000000000DEC30 10 00 00 00 01 00 60 00 38 0E 73 03 60 00 00 42 ......`.8.s.`..B
40000000000DEC40 0B 70 C0 03 32 24 00 00 00 02 00 00 00 00 04 00 .p..2$..........
40000000000DEC50 0B 70 00 1C 10 10 70 00 38 0C 73 00 00 00 04 00 .p....p.8.s.....
40000000000DEC60 EB 70 20 46 00 E1 91 02 38 20 20 00 00 00 04 00 .p F....8  .....
40000000000DEC70 09 00 00 00 01 C0 F1 00 A5 5C 40 00 00 00 04 00 .........\@.....
40000000000DEC80 E8 00 3C 1C 90 11 00 00 00 02 00 00 00 00 04 00 ..<.............
40000000000DEC90 11 88 01 46 00 21 00 00 00 02 00 00 38 F7 FF 58 ...F.!......8..X
40000000000DECA0 09 70 00 4E 10 10 10 00 BC 00 42 C0 04 40 00 84 .p.N......B..@..
40000000000DECB0 10 00 00 00 01 00 60 00 38 0E 73 03 50 00 00 42 ......`.8.s.P..B
40000000000DECC0 0B 70 C0 03 32 24 00 00 00 02 00 00 00 00 04 00 .p..2$..........
40000000000DECD0 0B 70 00 1C 10 10 70 00 38 0C 73 00 00 00 04 00 .p....p.8.s.....
40000000000DECE0 09 00 00 00 01 C0 31 42 8C 00 42 00 00 00 04 00 ......1B..B.....
40000000000DECF0 E8 00 A4 46 90 11 00 00 00 02 00 00 00 00 04 00 ...F............
40000000000DED00 11 70 E0 02 39 24 60 00 98 0E 72 03 40 11 00 41 .p..9$`...r.@..A
40000000000DED10 0B 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
40000000000DED20 11 30 00 1C 87 39 00 00 00 02 00 03 70 00 00 43 .0...9......p..C
40000000000DED30 09 00 00 00 01 00 60 00 88 0E 73 00 00 00 04 00 ......`...s.....
40000000000DED40 11 30 2C 44 C7 39 00 00 00 02 00 03 90 17 00 43 .0,D.9.........C
40000000000DED50 09 00 00 00 01 00 60 50 88 0E 73 00 00 00 04 00 ......`P..s.....
40000000000DED60 11 30 0C 44 C7 39 00 00 00 02 00 03 70 17 00 43 .0.D.9......p..C
40000000000DED70 09 00 00 00 01 00 70 60 88 0C 73 00 00 00 04 00 ......p`..s.....
40000000000DED80 10 00 00 00 01 00 70 98 88 8C F3 03 50 17 00 43 ......p.....P..C
40000000000DED90 08 90 F1 FA 67 27 30 02 94 20 20 20 06 30 01 84 ....g'0..   .0..
40000000000DEDA0 09 00 00 00 01 00 30 0B 00 00 48 00 00 00 04 00 ......0...H.....
40000000000DEDB0 11 00 00 00 01 00 00 00 00 02 00 00 18 A2 FF 58 ...............X
40000000000DEDC0 08 08 00 5E 00 21 60 40 00 0E 61 00 00 00 04 00 ...^.!`@..a.....
40000000000DEDD0 19 88 01 4C 00 21 20 03 8C 00 C2 03 E0 0B 00 43 ...L.! ........C
40000000000DEDE0 0B 70 60 03 39 24 00 00 00 02 00 00 00 00 04 00 .p`.9$..........
40000000000DEDF0 09 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
40000000000DEE00 11 00 00 00 01 00 60 00 38 0E 73 03 30 00 00 42 ......`.8.s.0..B
40000000000DEE10 09 00 00 00 01 00 70 50 88 0C 73 00 00 00 04 00 ......pP..s.....
40000000000DEE20 10 00 00 00 01 00 70 00 88 8C F3 03 D0 15 00 43 ......p........C
40000000000DEE30 11 98 D9 00 03 24 00 00 00 02 00 00 B8 C6 F3 58 .....$.........X
40000000000DEE40 08 00 00 00 01 00 10 00 BC 00 42 60 04 40 00 84 ..........B`.@..
40000000000DEE50 11 88 01 4C 00 21 00 00 00 02 00 00 98 B9 F3 58 ...L.!.........X
40000000000DEE60 11 08 00 5E 00 21 60 F0 8F 0E 77 03 E0 F7 FF 4B ...^.!`...w....K
40000000000DEE70 00 00 00 00 01 00 20 01 84 26 28 E0 30 02 18 C2 ...... ..&(.0...
40000000000DEE80 19 00 00 00 01 00 00 00 00 02 80 03 C0 0D 00 43 ...............C
40000000000DEE90 10 00 00 00 01 80 04 19 91 22 71 09 10 0D 00 42 ........."q....B
40000000000DEEA0 0B 28 41 40 00 21 E0 00 94 20 20 00 00 00 04 00 .(A@.!...  .....
40000000000DEEB0 11 00 00 00 01 00 60 00 38 0E A8 03 C0 13 00 43 ......`.8......C
40000000000DEEC0 00 00 00 00 01 00 60 10 84 0E 28 20 06 20 01 84 ......`...( . ..
40000000000DEED0 19 90 05 00 00 24 30 03 00 00 42 03 50 0B 00 43 .....$0...B.P..C
40000000000DEEE0 13 80 8C 48 91 38 04 50 0D 80 21 00 08 C9 F3 58 ...H.8.P..!....X
40000000000DEEF0 08 30 FC 11 87 3B 10 00 BC 00 42 20 06 20 01 84 .0...;....B . ..
40000000000DEF00 19 90 01 44 00 21 30 FB F3 FF 4F 03 80 1A 00 43 ...D.!0...O....C
40000000000DEF10 11 00 00 00 01 00 00 00 00 02 00 00 78 ED FF 58 ............x..X
40000000000DEF20 08 08 00 5E 00 21 00 00 00 02 00 00 00 00 04 00 ...^.!..........
40000000000DEF30 10 00 00 00 01 00 70 40 00 0C 61 03 F0 0A 00 42 ......p@..a....B
40000000000DEF40 09 70 00 4A 10 10 00 00 00 02 00 20 06 18 01 84 .p.J....... ....
40000000000DEF50 10 00 00 00 01 00 60 00 38 0E A8 03 E0 18 00 43 ......`.8......C
40000000000DEF60 11 00 00 00 01 00 00 00 00 02 00 00 E8 D3 F3 58 ...............X
40000000000DEF70 11 00 00 00 01 00 10 00 BC 00 42 00 10 FA FF 48 ..........B....H
40000000000DEF80 08 30 00 46 07 39 60 C2 BB 7E 46 00 00 00 04 00 .0.F.9`..~F.....
40000000000DEF90 19 88 91 FB B8 27 20 2B 00 00 48 03 A0 F6 FF 4B .....' +..H....K
40000000000DEFA0 08 00 00 00 01 00 30 03 98 00 42 00 00 00 04 00 ......0...B.....
40000000000DEFB0 19 88 01 62 18 10 00 00 00 02 00 00 58 F7 04 50 ...b........X..P
40000000000DEFC0 08 38 20 00 86 30 00 00 00 02 00 A0 04 40 00 84 .8 ..0.......@..
40000000000DEFD0 19 08 00 5E 00 21 00 00 00 02 80 03 C0 18 00 43 ...^.!.........C
40000000000DEFE0 11 00 00 00 01 00 00 00 00 02 00 00 68 C8 F3 58 ............h..X
40000000000DEFF0 08 00 00 00 01 00 70 02 8C 30 20 60 84 18 01 84 ......p..0 `....
40000000000DF000 09 00 00 10 90 11 10 00 BC 00 42 00 05 40 00 84 ..........B..@..
40000000000DF010 11 30 00 4E 07 39 00 00 00 02 00 03 50 06 00 43 .0.N.9......P..C
40000000000DF020 11 30 14 44 87 39 00 00 00 02 00 03 F0 14 00 43 .0.D.9.........C
40000000000DF030 09 00 00 00 01 00 E0 00 8C 20 20 00 00 00 04 00 .........  .....
40000000000DF040 10 00 00 00 01 00 60 10 38 0E A8 03 30 0E 00 42 ......`.8...0..B
40000000000DF050 08 18 E1 03 47 24 E0 08 00 00 48 20 06 38 01 84 ....G$....H .8..
40000000000DF060 0B 90 09 00 00 24 00 00 00 02 00 00 00 00 04 00 .....$..........
40000000000DF070 11 00 38 46 90 11 00 00 00 02 00 00 18 B0 FB 58 ..8F...........X
40000000000DF080 08 30 00 10 07 39 10 00 BC 00 42 60 05 40 00 84 .0...9....B`.@..
40000000000DF090 19 00 00 46 90 11 10 03 94 00 42 03 D0 05 00 43 ...F......B....C
40000000000DF0A0 11 00 00 00 01 00 00 00 00 02 00 00 08 B4 F3 58 ...............X
40000000000DF0B0 08 08 00 5E 00 21 60 40 00 0E 61 00 00 00 04 00 ...^.!`@..a.....
40000000000DF0C0 19 18 01 10 00 21 10 03 20 00 42 03 50 19 00 43 .....!.. .B.P..C
40000000000DF0D0 09 00 00 00 01 00 20 63 F7 71 4F 00 00 00 04 00 ...... c.qO.....
40000000000DF0E0 11 90 01 64 18 10 00 00 00 02 00 00 28 B3 F3 58 ...d........(..X
40000000000DF0F0 08 70 20 56 00 21 10 00 BC 00 42 00 00 00 04 00 .p V.!....B.....
40000000000DF100 19 30 00 10 07 39 70 02 20 00 42 03 F0 18 00 43 .0...9p. .B....C
40000000000DF110 09 70 00 1C 18 10 00 00 A0 20 23 60 04 58 01 84 .p....... #`.X..
40000000000DF120 09 00 00 00 01 00 90 02 38 30 20 00 00 00 04 00 ........80 .....
40000000000DF130 11 88 01 52 00 21 00 00 00 02 00 00 98 C5 F3 58 ...R.!.........X
40000000000DF140 09 00 00 00 01 00 10 00 BC 00 42 40 05 40 00 84 ..........B@.@..
40000000000DF150 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000DF160 00 00 00 00 01 00 20 03 A8 2C 00 60 16 00 00 90 ...... ..,.`....
40000000000DF170 19 A0 01 4E 00 21 10 03 A4 00 42 00 98 BE F3 58 ...N.!....B....X
40000000000DF180 11 08 00 5E 00 21 10 03 9C 00 42 00 E8 B7 F3 58 ...^.!....B....X
40000000000DF190 11 08 00 5E 00 21 60 00 20 0E F3 03 60 04 00 43 ...^.!`. ...`..C
40000000000DF1A0 09 00 00 00 01 00 30 02 8C 30 20 00 00 00 04 00 ......0..0 .....
40000000000DF1B0 11 70 20 46 00 21 70 00 8C 0C F2 03 F0 19 00 43 .p F.!p........C
40000000000DF1C0 0B 70 00 1C 18 10 90 02 38 30 20 00 00 00 04 00 .p......80 .....
40000000000DF1D0 11 88 01 52 00 21 00 00 00 02 00 00 F8 C4 F3 58 ...R.!.........X
40000000000DF1E0 08 30 8C 56 07 38 10 00 BC 00 42 40 05 40 00 84 .0.V.8....B@.@..
40000000000DF1F0 19 88 81 00 00 24 20 03 9C 00 42 03 70 FF FF 4B .....$ ...B.p..K
40000000000DF200 11 00 00 00 01 00 00 00 00 02 00 00 C8 BC F3 58 ...............X
40000000000DF210 11 00 00 00 01 00 10 00 BC 00 42 00 50 FF FF 48 ..........B.P..H

l40000000000DF220:
	{ addl	r14,8308,r1; ld8	r36,[r38]; addl	r50,9,r0 }
	{ adds	r52,0x0,r0; st4	[r0],r14; adds	r49,0x0,r36; }
	{ ld8	r51,[r14]; nop.i	0x0; br.call.sptk.many	b0,make_redirection; }
	{ adds	r39,0x0,r8; nop.m	0x0; adds	r1,0x0,r47 }
	{ adds	r49,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r40,0x18,r39; nop.m	0x0; adds	r1,0x0,r47; }
	{ ld4	r34,[r40]; cmp4.eq	p07,p06,0xA,r34; nop.i	0x0; }
	{ nop.m	0x0; (p06) adds	r36,0x20,r39; nop.i	0x0; }

l40000000000DF29C:
	{ nop; Invalid; mov	pr,r32,0x0 }

l40000000000DF2A6:
	{ chk.a.nc	r0,3FFFFFFFFF0DFAA6; nop; break.i	0x80000 }

l40000000000DF2B0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000DF2C0:
	{ adds	r12,0xFFFFFFFFFFFFFFE0,r12; adds	r36,0x20,r39; addl	r51,16,r0; }
	{ adds	r35,0x10,r12; ld8	r49,[r36]; nop.i	0x0; }
	{ adds	r50,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,xbcopy; }
	{ ld8	r34,[r36]; nop.m	0x0; adds	r1,0x0,r47; }
	{ ld8	r49,[r34]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; adds	r8,0x1F,r8; adds	r1,0x0,r47 }
	{ ld8.a	r50,[r34]; and	r14,0xFFFFFFFFFFFFFFF0,r8; nop.i	0x0; }
	{ sub	r12,r12,r14; adds	r49,0x10,r12; nop.i	0x0; }
	{ nop.m	0x0; st8	[r49],r35; nop.i	0x0; }
	{ ld8.c.clr	r50,[r34]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r14,0x14,r39; adds	r15,0x8,r39; adds	r1,0x0,r47 }
	{ ld4	r34,[r40]; ld4	r40,[r36]; adds	r49,0x0,r39; }
	{ ld4	r14,[r14]; ld4	r36,[r15]; nop.i	0x0; }
	{ st4	[r14],r37; nop.i	0x0; br.call.sptk.many	b0,dispose_redirects; }
	{ nop.m	0x0; adds	r1,0x0,r47; br.cond.sptk.few	40000000000DE890 }
40000000000DF3B0 11 88 01 48 00 21 00 00 00 02 00 00 D8 09 F7 58 ...H.!.........X
40000000000DF3C0 11 08 00 5E 00 21 10 03 90 00 42 00 88 88 F6 58 ...^.!....B....X
40000000000DF3D0 11 08 00 5E 00 21 10 03 90 00 42 00 38 24 FD 58 ...^.!....B.8$.X
40000000000DF3E0 11 08 00 5E 00 21 10 03 90 00 42 00 E8 1D FD 58 ...^.!....B....X
40000000000DF3F0 11 08 00 5E 00 21 70 40 00 0C 61 03 40 F2 FF 4A ...^.!p@..a.@..J
40000000000DF400 11 00 00 00 01 00 60 30 84 0E 28 03 30 F2 FF 4B ......`0..(.0..K
40000000000DF410 11 00 00 00 01 00 00 00 00 02 00 00 38 C4 F3 58 ............8..X
40000000000DF420 09 70 00 10 10 10 10 00 BC 00 42 E0 11 00 00 90 .p........B.....
40000000000DF430 09 00 00 00 01 00 70 E0 38 0C 73 00 00 00 04 00 ......p.8.s.....
40000000000DF440 11 38 14 1C C6 39 E0 A0 06 8C 48 03 F0 F1 FF 4B .8...9....H....K
40000000000DF450 09 00 00 00 01 00 30 02 20 A0 20 00 00 00 04 00 ......0. . .....
40000000000DF460 0B 30 00 46 87 39 00 78 38 20 23 00 00 00 04 00 .0.F.9.x8 #.....
40000000000DF470 10 18 45 06 40 01 00 00 00 02 00 00 00 00 00 20 ..E.@.......... 
40000000000DF480 10 00 00 00 01 00 00 00 00 02 00 03 50 F5 FF 4A ............P..J
40000000000DF490 03 40 00 46 00 21 F0 87 C1 BF 05 00 D0 02 AA 00 .@.F.!..........
40000000000DF4A0 00 00 00 00 01 00 00 60 05 80 03 00 00 00 04 00 .......`........
40000000000DF4B0 19 60 00 5C 00 21 00 00 00 02 00 80 08 00 84 00 .`.\.!..........

l40000000000DF4C0:
	{ ld8	r36,[r38]; nop.m	0x0; adds	r49,0x0,r35 }
	{ adds	r50,0x0,r46; nop.m	0x0; br.call.sptk.many	b0,legal_number; }
	{ adds	r1,0x0,r47; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	40000000000DF520 }

l40000000000DF4F0:
	{ ld8	r15,[r46]; nop.m	0x0; sxt4	r14,r15; }
	{ cmp.eq	p07,p06,r14,r15; (p07) addl	r14,8308,r1; nop.i	0x0; }

l40000000000DF50C:
	{ Invalid; Invalid; mov	pr,r32,0x0 }

l40000000000DF516:
	{ chk.a.nc	f0,3FFFFFFFFF0DFD16; nop; (p32) nop }

l40000000000DF520:
	{ addl	r14,8308,r1; nop.m	0x0; addl	r15,-1,r0; }
	{ st4	[r15],r14; nop.m	0x0; nop.i	0x0 }

l40000000000DF540:
	{ cmp4.eq	p06,p07,0xE,r34; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E0920; }

l40000000000DF550:
	{ nop.m	0x0; cmp4.ltu	p06,p07,0xE,r34; (p07) br.cond.dptk.few	40000000000DFC90; }

l40000000000DF560:
	{ cmp4.eq	p06,p07,0x12,r34; (p16) br.cond.dpnt.few	40000000000E0950; (p07) br.cond.dptk.few	40000000000DE7F0 }

l40000000000DF56C:
	{ (p20) nop; nop; (p06) br.cond.sptk.few	40000000004FF5FC }

l40000000000DF570:
	{ nop.m	0x0; adds	r49,0x0,r36; addl	r50,16,r0 }
	{ ld8	r51,[r14]; adds	r52,0x0,r0; br.call.sptk.many	b0,make_redirection; }
	{ nop.m	0x0; adds	r1,0x0,r47; adds	r39,0x0,r8; }

l40000000000DF5A0:
	{ adds	r40,0x18,r39; adds	r49,0x0,r35; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ ld4	r34,[r40]; adds	r1,0x0,r47; cmp4.eq	p07,p06,0xA,r34; }
	{ nop.m	0x0; (p06) adds	r36,0x20,r39; nop.i	0x0; }

l40000000000DF5CC:
	{ nop; Invalid; mov	pr,r32,0x0 }

l40000000000DF5D6:
	{ chk.a.nc	r0,3FFFFFFFFF0DFDD6; nop; break.i	0x80000 }

l40000000000DF5E0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000DF2C0 }
40000000000DF5F0 09 48 01 50 10 10 00 00 00 02 00 20 06 38 01 84 .H.P....... .8..
40000000000DF600 0B 80 00 52 91 39 94 E2 00 00 48 28 02 00 40 E0 ...R.9....H(..@.
40000000000DF610 11 00 A4 50 90 11 00 00 00 02 00 00 38 C8 F3 58 ...P........8..X
40000000000DF620 08 00 00 00 01 00 10 00 BC 00 42 20 06 58 01 84 ..........B .X..
40000000000DF630 19 00 00 00 01 00 00 00 00 02 00 00 98 C5 F6 58 ...............X
40000000000DF640 08 08 00 5E 00 21 00 00 00 02 00 00 00 00 04 00 ...^.!..........
40000000000DF650 10 00 00 00 01 00 00 00 00 02 80 08 70 10 00 43 ............p..C
40000000000DF660 08 90 01 00 00 21 00 00 00 02 00 60 06 00 0C 90 .....!.....`....
40000000000DF670 19 88 01 4C 18 10 00 00 00 02 00 00 78 BE F3 58 ...L........x..X
40000000000DF680 08 38 20 00 86 30 10 00 BC 00 42 00 00 00 04 00 .8 ..0....B.....
40000000000DF690 19 38 01 10 00 21 10 03 94 00 C2 03 E0 15 00 43 .8...!.........C
40000000000DF6A0 11 28 41 40 00 21 00 00 00 02 00 00 A8 CC F3 58 .(A@.!.........X
40000000000DF6B0 08 00 00 00 01 00 10 00 BC 00 42 00 00 00 04 00 ..........B.....
40000000000DF6C0 19 88 01 4C 18 10 00 00 00 02 00 00 48 BB F3 58 ...L........H..X
40000000000DF6D0 11 38 20 00 86 30 10 00 BC 00 C2 03 20 16 00 43 .8 ..0...... ..C
40000000000DF6E0 11 88 01 4C 18 10 00 00 00 02 00 00 08 B1 F3 58 ...L...........X
40000000000DF6F0 09 70 00 4A 10 10 00 00 00 02 00 20 00 78 01 84 .p.J....... .x..
40000000000DF700 11 00 00 00 01 00 60 00 38 0E A8 03 10 08 00 43 ......`.8......C
40000000000DF710 01 00 00 00 01 00 70 00 84 0C 28 00 00 00 04 00 ......p...(.....
40000000000DF720 10 00 00 00 01 C0 01 39 91 22 F1 03 00 02 00 42 .......9.".....B
40000000000DF730 00 00 00 00 01 00 60 10 84 0E 28 20 06 20 01 84 ......`...( . ..
40000000000DF740 19 90 05 00 00 24 30 03 00 00 42 03 20 01 00 43 .....$0...B. ..C
40000000000DF750 13 80 9C 48 91 38 04 D8 08 80 21 00 98 C0 F3 58 ...H.8....!....X
40000000000DF760 08 30 FC 11 87 3B 10 00 BC 00 42 20 06 20 01 84 .0...;....B . ..
40000000000DF770 19 90 01 44 00 21 30 FB F3 FF 4F 03 90 11 00 43 ...D.!0...O....C
40000000000DF780 11 00 00 00 01 00 00 00 00 02 00 00 08 E5 FF 58 ...............X
40000000000DF790 08 08 00 5E 00 21 00 00 00 02 00 00 00 00 04 00 ...^.!..........
40000000000DF7A0 10 00 00 00 01 00 70 40 00 0C 61 03 C0 00 00 42 ......p@..a....B
40000000000DF7B0 09 70 00 4A 10 10 00 00 00 02 00 20 06 38 01 84 .p.J....... .8..
40000000000DF7C0 11 00 00 00 01 00 60 00 38 0E A8 03 B0 0F 00 43 ......`.8......C
40000000000DF7D0 11 00 00 00 01 00 00 00 00 02 00 00 78 CB F3 58 ............x..X
40000000000DF7E0 08 00 00 00 01 00 10 00 BC 00 42 E0 11 00 00 90 ..........B.....
40000000000DF7F0 0B 18 01 50 50 10 E0 A0 06 8C 48 E0 00 18 19 E6 ...PP.....H.....
40000000000DF800 0B 00 00 00 01 00 00 78 38 20 23 00 00 00 04 00 .......x8 #.....
40000000000DF810 10 18 65 05 40 01 00 00 00 02 00 00 00 00 00 20 ..e.@.......... 
40000000000DF820 10 00 00 00 01 00 00 00 00 02 80 03 B0 F1 FF 4B ...............K
40000000000DF830 03 40 00 46 00 21 F0 87 C1 BF 05 00 D0 02 AA 00 .@.F.!..........
40000000000DF840 00 00 00 00 01 00 00 60 05 80 03 00 00 00 04 00 .......`........
40000000000DF850 19 60 00 5C 00 21 00 00 00 02 00 80 08 00 84 00 .`.\.!..........
40000000000DF860 11 88 01 48 00 21 00 00 00 02 00 00 A8 1F FD 58 ...H.!.........X
40000000000DF870 08 70 00 4A 10 10 00 00 00 02 00 20 00 78 01 84 .p.J....... .x..
40000000000DF880 09 88 01 4E 00 21 00 00 00 02 00 40 06 20 01 84 ...N.!.....@. ..
40000000000DF890 11 00 00 00 01 00 60 00 38 0E A8 03 E0 0A 00 43 ......`.8......C
40000000000DF8A0 13 80 9C 48 91 38 04 10 00 80 21 00 C8 B5 F3 58 ...H.8....!....X
40000000000DF8B0 10 08 00 5E 00 21 70 40 00 0C E1 03 A0 0F 00 43 ...^.!p@.......C
40000000000DF8C0 11 88 01 4E 00 21 20 03 90 00 42 00 C8 14 FD 58 ...N.! ...B....X
40000000000DF8D0 11 08 00 5E 00 21 60 20 84 0E 28 03 50 00 00 42 ...^.!` ..(.P..B
40000000000DF8E0 10 00 00 00 01 00 70 10 90 0C 63 03 40 00 00 42 ......p...c.@..B
40000000000DF8F0 08 88 01 48 00 21 00 00 00 02 00 40 26 00 00 90 ...H.!.....@&...
40000000000DF900 19 98 05 00 00 24 00 00 00 02 00 00 E8 BE F3 58 .....$.........X
40000000000DF910 09 08 00 5E 00 21 00 00 00 02 00 00 00 00 04 00 ...^.!..........
40000000000DF920 08 88 01 4E 00 21 00 00 00 02 00 60 04 00 00 84 ...N.!.....`....
40000000000DF930 17 00 00 00 00 08 04 80 F6 FF 25 00 98 18 FD 58 ..........%....X
40000000000DF940 09 40 00 46 00 21 10 00 BC 00 42 E0 0F 83 7F 0B .@.F.!....B.....
40000000000DF950 02 00 00 00 01 00 00 68 01 55 00 00 C0 0A 00 07 .......h.U......
40000000000DF960 19 00 00 00 01 00 C0 00 B8 00 42 80 08 00 84 00 ..........B.....

l40000000000DF970:
	{ adds	r49,0x0,r35; addl	r35,-1,r0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r47; mov	pr,r48,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r45; mov.spnt	b0,r44,40000000000DF990 }
	{ nop.m	0x0; adds	r12,0x0,r46; br.ret	b0 }
40000000000DF9B0 0B 40 EC 11 3F 23 60 08 20 0E 6B 00 00 00 04 00 .@..?#`. .k.....
40000000000DF9C0 10 00 00 00 01 80 31 FA F3 FF 4F 03 90 F4 FF 4A ......1...O....J
40000000000DF9D0 11 88 01 4C 00 21 00 00 00 02 00 00 F8 BF 04 50 ...L.!.........P
40000000000DF9E0 08 08 00 5E 00 21 00 00 00 02 00 60 04 40 00 84 ...^.!.....`.@..
40000000000DF9F0 19 88 01 4C 00 21 00 00 00 02 00 00 F8 AD F3 58 ...L.!.........X
40000000000DFA00 10 08 00 5E 00 21 60 F0 8F 0E F7 03 70 F4 FF 4A ...^.!`.....p..J
40000000000DFA10 10 00 00 00 01 00 00 00 00 02 00 00 30 EC FF 48 ............0..H
40000000000DFA20 11 88 01 48 00 21 00 00 00 02 00 00 E8 1D FD 58 ...H.!.........X
40000000000DFA30 11 38 04 48 86 39 10 00 BC 00 C2 03 D0 11 00 43 .8.H.9.........C
40000000000DFA40 10 00 00 00 01 00 70 10 90 0C 73 03 80 00 00 42 ......p...s....B
40000000000DFA50 0B 30 91 FB AC 27 60 02 98 30 20 00 00 00 04 00 .0...'`..0 .....
40000000000DFA60 11 88 01 4C 18 10 00 00 00 02 00 00 68 C1 F3 58 ...L........h..X
40000000000DFA70 10 08 00 5E 00 21 70 10 20 0C 73 03 50 00 00 42 ...^.!p. .s.P..B
40000000000DFA80 11 88 01 4C 18 10 00 00 00 02 00 00 08 AC F3 58 ...L...........X
40000000000DFA90 08 00 00 00 01 00 10 00 BC 00 42 00 00 00 04 00 ..........B.....
40000000000DFAA0 19 88 01 4C 18 10 00 00 00 02 00 00 E8 56 05 50 ...L.........V.P
40000000000DFAB0 09 08 00 5E 00 21 00 00 00 02 00 00 00 00 04 00 ...^.!..........
40000000000DFAC0 09 70 00 4A 10 10 10 03 8C 00 42 40 06 20 01 84 .p.J......B@. ..
40000000000DFAD0 11 00 00 00 01 00 60 00 38 0E A8 03 70 0F 00 43 ......`.8...p..C
40000000000DFAE0 13 80 8C 48 91 38 04 10 00 80 21 00 88 B3 F3 58 ...H.8....!....X
40000000000DFAF0 11 08 00 5E 00 21 70 40 00 0C E1 03 50 01 00 43 ...^.!p@....P..C
40000000000DFB00 09 00 00 00 01 00 70 58 88 0C 73 00 00 00 04 00 ......pX..s.....
40000000000DFB10 10 00 00 00 01 00 70 08 88 8C 73 03 40 00 00 42 ......p...s.@..B
40000000000DFB20 08 00 00 00 01 00 10 03 8C 00 42 40 06 20 01 84 ..........B@. ..
40000000000DFB30 19 00 00 00 01 00 00 00 00 02 00 00 58 12 FD 58 ............X..X
40000000000DFB40 08 08 00 5E 00 21 00 00 00 02 00 00 00 00 04 00 ...^.!..........
40000000000DFB50 11 00 00 00 01 00 60 20 84 0E 28 03 50 00 00 42 ......` ..(.P..B
40000000000DFB60 10 00 00 00 01 00 70 10 90 0C 63 03 40 00 00 42 ......p...c.@..B
40000000000DFB70 08 88 01 48 00 21 00 00 00 02 00 40 26 00 00 90 ...H.!.....@&...
40000000000DFB80 19 98 05 00 00 24 00 00 00 02 00 00 68 BC F3 58 .....$......h..X
40000000000DFB90 09 08 00 5E 00 21 00 00 00 02 00 00 00 00 04 00 ...^.!..........
40000000000DFBA0 11 70 FC 45 3F 23 10 03 8C 00 42 08 50 00 00 43 .p.E?#....B.P..C
40000000000DFBB0 09 00 00 00 01 00 70 08 38 0C 6B 00 00 00 04 00 ......p.8.k.....
40000000000DFBC0 10 00 00 00 01 00 60 58 88 8E F3 03 60 01 00 42 ......`X....`..B
40000000000DFBD0 11 00 00 00 01 00 00 00 00 02 00 00 F8 15 FD 58 ...............X
40000000000DFBE0 08 08 00 5E 00 21 00 00 00 02 00 00 00 00 04 00 ...^.!..........
40000000000DFBF0 09 30 28 44 87 39 10 0B 00 00 48 40 26 00 00 90 .0(D.9....H@&...
40000000000DFC00 13 30 4C 44 C7 F9 01 18 F5 FF 25 09 30 EA FF 4B .0LD......%.0..K
40000000000DFC10 11 00 00 00 01 00 60 10 84 0E A8 03 60 08 00 43 ......`.....`..C
40000000000DFC20 11 00 00 00 01 00 00 00 00 02 00 00 48 B2 F3 58 ............H..X
40000000000DFC30 11 08 00 5E 00 21 70 40 00 0C 61 03 00 EA FF 4A ...^.!p@..a....J
40000000000DFC40 11 00 00 00 01 00 00 00 00 02 00 00 08 BC F3 58 ...............X
40000000000DFC50 09 18 01 10 10 10 00 00 00 02 00 20 00 78 01 84 ........... .x..
40000000000DFC60 03 40 00 46 00 21 F0 87 C1 BF 05 00 D0 02 AA 00 .@.F.!..........
40000000000DFC70 00 00 00 00 01 00 00 60 05 80 03 00 00 00 04 00 .......`........
40000000000DFC80 18 60 00 5C 00 21 00 00 00 02 00 80 08 00 84 00 .`.\.!..........

l40000000000DFC90:
	{ nop.m	0x0; cmp4.eq	p06,p07,0xD,r34; (p07) br.cond.dptk.few	40000000000DE7F0; }

l40000000000DFCA0:
	{ nop.m	0x0; adds	r49,0x0,r36; addl	r50,6,r0 }
	{ ld8	r51,[r14]; adds	r52,0x0,r0; br.call.sptk.many	b0,make_redirection; }
	{ adds	r1,0x0,r47; adds	r39,0x0,r8; br.cond.sptk.few	40000000000DF5A0 }
40000000000DFCD0 11 88 01 50 00 21 20 03 90 00 42 00 98 B1 F3 58 ...P.! ...B....X
40000000000DFCE0 11 38 20 00 86 30 10 00 BC 00 C2 03 60 FF FF 4B .8 ..0......`..K
40000000000DFCF0 09 00 00 00 01 00 70 78 88 0C 73 00 00 00 04 00 ......px..s.....
40000000000DFD00 10 00 00 00 01 00 70 30 88 8C 73 03 C0 ED FF 4A ......p0..s....J
40000000000DFD10 10 00 00 00 01 00 00 00 00 02 00 00 D0 04 00 40 ...............@
40000000000DFD20 11 00 00 00 01 00 00 00 00 02 00 00 28 C6 F3 58 ............(..X
40000000000DFD30 10 00 00 00 01 00 10 00 BC 00 42 00 C0 FE FF 48 ..........B....H
40000000000DFD40 09 00 00 00 01 00 E0 00 98 30 20 00 00 00 04 00 .........0 .....
40000000000DFD50 11 88 01 1C 18 10 00 00 00 02 00 00 F8 27 F8 58 .............'.X
40000000000DFD60 08 70 A0 10 00 21 10 00 BC 00 42 00 00 00 04 00 .p...!....B.....
40000000000DFD70 19 30 00 10 07 39 10 03 20 00 42 03 D0 00 00 41 .0...9.. .B....A
40000000000DFD80 09 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
40000000000DFD90 11 00 00 00 01 00 70 C0 38 0C 28 03 B0 00 00 43 ......p.8.(....C
40000000000DFDA0 11 00 00 00 01 00 00 00 00 02 00 00 28 32 F8 58 ............(2.X
40000000000DFDB0 08 08 00 5E 00 21 60 00 20 0E 72 00 00 00 04 00 ...^.!`. .r.....
40000000000DFDC0 19 88 01 10 00 21 20 83 BB 7E 46 03 80 00 00 41 .....! ..~F....A
40000000000DFDD0 0B 70 00 10 00 10 00 00 00 02 00 C0 01 70 50 00 .p...........pP.
40000000000DFDE0 11 30 00 1C 87 39 00 00 00 02 00 03 60 00 00 43 .0...9......`..C
40000000000DFDF0 11 00 00 00 01 00 00 00 00 02 00 00 98 F6 F5 58 ...............X
40000000000DFE00 08 70 C0 5D 3F 23 00 00 00 02 00 20 00 78 01 84 .p.]?#..... .x..
40000000000DFE10 19 30 20 00 87 30 00 00 00 02 00 03 30 00 00 43 .0 ..0......0..C
40000000000DFE20 09 00 00 00 01 00 40 02 38 20 20 00 00 00 04 00 ......@.8  .....
40000000000DFE30 10 00 00 00 01 00 60 20 01 0E E1 03 B0 EA FF 48 ......` .......H

l40000000000DFE40:
	{ addl	r35,-1,r0; adds	r8,0x0,r35; mov	pr,r48,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r45; mov.spnt	b0,r44,40000000000DFE50 }
	{ nop.m	0x0; adds	r12,0x0,r46; br.ret	b0; }
40000000000DFE70 11 88 01 4E 00 21 00 00 00 02 00 00 58 B8 F3 58 ...N.!......X..X
40000000000DFE80 10 00 00 00 01 00 30 02 20 2C 00 00 00 00 00 20 ......0. ,..... 
40000000000DFE90 09 08 00 5E 00 21 10 03 94 00 42 40 06 38 01 84 ...^.!....B@.8..
40000000000DFEA0 11 98 01 46 00 21 00 00 00 02 00 00 A8 B8 F3 58 ...F.!.........X
40000000000DFEB0 11 08 00 5E 00 21 60 40 8C 0E E0 03 B0 F7 FF 4B ...^.!`@.......K
40000000000DFEC0 0B 48 01 50 10 10 00 01 A4 22 73 00 00 00 04 00 .H.P....."s.....
40000000000DFED0 09 4A 71 00 00 24 00 00 00 02 00 28 02 00 40 E0 .Jq..$.....(..@.
40000000000DFEE0 08 00 A4 50 90 11 00 00 00 02 00 00 00 00 04 00 ...P............
40000000000DFEF0 10 00 00 00 01 00 00 00 00 02 00 08 70 F7 FF 4A ............p..J
40000000000DFF00 10 00 00 00 01 00 00 00 00 02 00 00 C0 07 00 40 ...............@
40000000000DFF10 08 88 01 4E 00 21 00 00 00 02 00 40 06 00 00 84 ...N.!.....@....
40000000000DFF20 19 98 29 00 00 24 00 00 00 02 00 00 C8 B8 F3 58 ..)..$.........X
40000000000DFF30 08 18 01 50 10 10 00 00 00 02 00 20 00 78 01 84 ...P....... .x..
40000000000DFF40 19 20 01 10 00 21 70 40 00 0C 61 03 D0 F7 FF 4A . ...!p@..a....J
40000000000DFF50 09 90 71 FB B8 27 30 2B 00 00 48 20 06 00 00 84 ..q..'0+..H ....
40000000000DFF60 11 90 01 64 18 10 00 00 00 02 00 00 08 AC F3 58 ...d...........X
40000000000DFF70 11 08 00 5E 00 21 10 03 20 00 42 00 58 13 F9 58 ...^.!.. .B.X..X
40000000000DFF80 11 08 00 5E 00 21 10 03 9C 00 42 00 C8 C3 F3 58 ...^.!....B....X
40000000000DFF90 09 08 00 5E 00 21 F0 08 00 00 48 E0 00 18 19 E6 ...^.!....H.....
40000000000DFFA0 0B 70 50 03 46 24 00 00 00 02 00 00 00 00 04 00 .pP.F$..........
40000000000DFFB0 10 00 3C 1C 90 11 00 00 00 02 80 03 20 EA FF 4B ..<......... ..K
40000000000DFFC0 03 40 00 46 00 21 F0 87 C1 BF 05 00 D0 02 AA 00 .@.F.!..........
40000000000DFFD0 00 00 00 00 01 00 00 60 05 80 03 00 00 00 04 00 .......`........
40000000000DFFE0 19 60 00 5C 00 21 00 00 00 02 00 80 08 00 84 00 .`.\.!..........
40000000000DFFF0 08 88 01 50 00 21 00 00 00 02 00 40 06 00 00 84 ...P.!.....@....
40000000000E0000 19 98 29 00 00 24 00 00 00 02 00 00 E8 B7 F3 58 ..)..$.........X
40000000000E0010 11 08 00 5E 00 21 40 02 20 00 42 00 38 B8 F3 58 ...^.!@. .B.8..X
40000000000E0020 08 00 00 00 01 00 30 02 20 20 20 20 00 78 01 84 ......0.    .x..
40000000000E0030 19 00 00 00 01 00 70 20 01 0C 61 03 00 EA FF 4A ......p ..a....J
40000000000E0040 09 90 71 FB B8 27 30 2B 00 00 48 20 06 00 00 84 ..q..'0+..H ....
40000000000E0050 11 90 01 64 18 10 00 00 00 02 00 00 18 AB F3 58 ...d...........X
40000000000E0060 11 08 00 5E 00 21 10 03 20 00 42 00 68 12 F9 58 ...^.!.. .B.h..X
40000000000E0070 09 08 00 5E 00 21 F0 08 00 00 48 E0 00 18 19 E6 ...^.!....H.....
40000000000E0080 0B 70 50 03 46 24 00 00 00 02 00 00 00 00 04 00 .pP.F$..........
40000000000E0090 10 00 3C 1C 90 11 00 00 00 02 00 03 30 FF FF 4A ..<.........0..J
40000000000E00A0 10 00 00 00 01 00 00 00 00 02 00 00 30 E9 FF 48 ............0..H
40000000000E00B0 08 88 01 48 00 21 00 00 00 02 00 40 16 00 00 90 ...H.!.....@....
40000000000E00C0 19 98 01 00 00 21 00 00 00 02 00 00 28 B7 F3 58 .....!......(..X
40000000000E00D0 08 30 FC 11 87 3B 10 00 BC 00 42 20 06 20 01 84 .0...;....B . ..
40000000000E00E0 19 90 01 44 00 21 30 03 A0 00 42 03 30 0A 00 43 ...D.!0...B.0..C
40000000000E00F0 11 00 00 00 01 00 00 00 00 02 00 00 98 DB FF 58 ...............X
40000000000E0100 08 08 00 5E 00 21 00 00 00 02 00 00 00 00 04 00 ...^.!..........
40000000000E0110 11 38 20 00 86 30 E0 88 8B 7E C6 03 20 0A 00 43 .8 ..0...~.. ..C
40000000000E0120 10 00 00 00 01 00 70 08 38 0C EB 03 30 E9 FF 4A ......p.8...0..J
40000000000E0130 08 88 01 48 00 21 00 00 00 02 00 40 16 00 00 90 ...H.!.....@....
40000000000E0140 19 98 01 00 00 21 00 00 00 02 00 00 A8 B6 F3 58 .....!.........X
40000000000E0150 08 30 FC 11 87 3B 10 00 BC 00 42 20 06 40 01 84 .0...;....B .@..
40000000000E0160 19 90 25 00 00 24 30 FB F3 FF 4F 03 F0 E8 FF 4B ..%..$0...O....K
40000000000E0170 11 00 00 00 01 00 00 00 00 02 00 00 18 DB FF 58 ...............X
40000000000E0180 08 38 20 00 86 30 00 00 00 02 00 20 00 78 01 84 .8 ..0..... .x..
40000000000E0190 19 88 01 48 00 21 00 00 00 02 80 03 F0 E7 FF 4B ...H.!.........K
40000000000E01A0 11 00 00 00 01 00 00 00 00 02 00 00 68 16 FD 58 ............h..X
40000000000E01B0 09 70 00 4A 10 10 00 00 00 02 00 20 00 78 01 84 .p.J....... .x..
40000000000E01C0 10 00 00 00 01 00 60 00 38 0E 28 03 10 FB FF 4A ......`.8.(....J
40000000000E01D0 10 00 00 00 01 00 00 00 00 02 00 00 B0 E8 FF 48 ...............H
40000000000E01E0 11 88 01 50 00 21 20 03 90 00 42 00 A8 0B FD 58 ...P.! ...B....X
40000000000E01F0 10 00 00 00 01 00 10 00 BC 00 42 00 D0 E8 FF 48 ..........B....H
40000000000E0200 09 30 08 48 87 31 00 00 00 02 00 00 91 40 25 C6 .0.H.1.......@%.
40000000000E0210 C9 78 04 00 00 24 00 00 00 02 00 C4 11 00 00 90 .x...$..........
40000000000E0220 E3 78 00 00 00 61 E2 00 00 00 42 C0 E1 78 30 80 .x...a....B..x0.
40000000000E0230 10 00 00 00 01 00 60 00 38 0E 73 03 60 E9 FF 4A ......`.8.s.`..J
40000000000E0240 08 88 01 48 00 21 00 00 00 02 00 40 26 00 00 90 ...H.!.....@&...
40000000000E0250 19 98 01 00 00 21 00 00 00 02 00 00 98 B5 F3 58 .....!.........X
40000000000E0260 10 00 00 00 01 00 10 00 BC 00 42 00 30 E9 FF 48 ..........B.0..H
40000000000E0270 08 88 01 46 00 21 00 00 00 02 00 40 06 00 00 84 ...F.!.....@....
40000000000E0280 19 98 29 00 00 24 00 00 00 02 00 00 68 B5 F3 58 ..)..$......h..X
40000000000E0290 11 08 00 5E 00 21 40 02 20 00 42 00 B8 B5 F3 58 ...^.!@. .B....X
40000000000E02A0 08 00 00 00 01 00 60 02 20 20 20 20 00 78 01 84 ......`.    .x..
40000000000E02B0 19 00 00 00 01 00 70 20 01 0C 61 03 10 EC FF 4A ......p ..a....J
40000000000E02C0 09 90 71 FB B8 27 30 2B 00 00 48 20 06 00 00 84 ..q..'0+..H ....
40000000000E02D0 11 90 01 64 18 10 00 00 00 02 00 00 98 A8 F3 58 ...d...........X
40000000000E02E0 11 08 00 5E 00 21 10 03 20 00 42 00 E8 0F F9 58 ...^.!.. .B....X
40000000000E02F0 11 08 00 5E 00 21 10 03 8C 00 42 00 58 C0 F3 58 ...^.!....B.X..X
40000000000E0300 09 08 00 5E 00 21 70 00 98 0C 73 E0 11 00 00 90 ...^.!p...s.....
40000000000E0310 09 70 50 03 46 24 00 00 00 02 00 63 04 30 01 84 .pP.F$.....c.0..
40000000000E0320 09 00 00 00 01 00 00 00 00 02 00 00 01 18 01 84 ................
40000000000E0330 11 00 3C 1C 90 11 00 00 00 02 80 03 A0 E6 FF 4B ..<............K
40000000000E0340 01 00 00 00 01 00 F0 87 C1 BF 05 00 00 00 04 00 ................
40000000000E0350 02 00 00 00 01 00 00 68 01 55 00 00 C0 0A 00 07 .......h.U......
40000000000E0360 19 00 00 00 01 00 C0 00 B8 00 42 80 08 00 84 00 ..........B.....
40000000000E0370 11 88 01 40 00 21 20 03 90 00 42 00 58 D8 FF 58 ...@.! ...B.X..X
40000000000E0380 09 38 20 00 86 30 00 00 00 02 00 20 00 78 01 84 .8 ..0..... .x..
40000000000E0390 10 00 00 00 01 80 01 39 91 22 71 03 30 F5 FF 4A .......9."q.0..J
40000000000E03A0 11 88 01 48 00 21 30 02 20 00 42 00 A8 BF F3 58 ...H.!0. .B....X
40000000000E03B0 11 08 00 5E 00 21 10 03 9C 00 42 00 98 BF F3 58 ...^.!....B....X
40000000000E03C0 09 40 00 46 00 21 10 00 BC 00 42 E0 0F 83 7F 0B .@.F.!....B.....
40000000000E03D0 02 00 00 00 01 00 00 68 01 55 00 00 C0 0A 00 07 .......h.U......
40000000000E03E0 19 00 00 00 01 00 C0 00 B8 00 42 80 08 00 84 00 ..........B.....
40000000000E03F0 11 00 00 00 01 00 00 00 00 02 00 00 58 DD FF 58 ............X..X
40000000000E0400 08 30 F8 11 87 3B 10 00 BC 00 42 00 00 00 04 00 .0...;....B.....
40000000000E0410 19 18 01 10 00 21 10 03 98 00 42 03 30 09 00 43 .....!....B.0..C
40000000000E0420 11 00 00 00 01 00 00 00 00 02 00 00 C8 A3 F3 58 ...............X
40000000000E0430 10 00 00 00 01 00 10 00 BC 00 42 00 40 EA FF 48 ..........B.@..H
40000000000E0440 11 00 00 00 01 00 70 30 84 0C 28 03 D0 E6 FF 4A ......p0..(....J
40000000000E0450 10 00 00 00 01 00 60 20 84 0E 28 03 10 E7 FF 4A ......` ..(....J
40000000000E0460 10 00 00 00 01 00 00 00 00 02 00 00 B0 E6 FF 48 ...............H
40000000000E0470 08 88 09 00 00 24 00 00 00 02 00 40 06 10 01 84 .....$.....@....
40000000000E0480 19 98 FD F9 FF 27 00 00 00 02 00 00 08 D8 FF 58 .....'.........X
40000000000E0490 08 08 00 5E 00 21 00 00 00 02 00 20 16 00 00 90 ...^.!..... ....
40000000000E04A0 19 90 09 00 00 24 00 00 00 02 00 00 C8 A9 F3 58 .....$.........X
40000000000E04B0 10 08 00 5E 00 21 70 40 00 0C 61 03 80 E1 FF 4A ...^.!p@..a....J
40000000000E04C0 10 00 00 00 01 00 00 00 00 02 00 00 80 F7 FF 48 ...............H
40000000000E04D0 11 88 01 4C 00 21 30 EA F3 FF 4F 00 18 A3 F3 58 ...L.!0...O....X
40000000000E04E0 09 40 00 46 00 21 10 00 BC 00 42 E0 0F 83 7F 0B .@.F.!....B.....
40000000000E04F0 02 00 00 00 01 00 00 68 01 55 00 00 C0 0A 00 07 .......h.U......
40000000000E0500 18 00 00 00 01 00 C0 00 B8 00 42 80 08 00 84 00 ..........B.....
40000000000E0510 08 48 E1 03 47 24 E0 08 00 00 48 20 06 38 01 84 .H..G$....H .8..
40000000000E0520 0B 90 01 00 00 21 00 00 00 02 00 00 00 00 04 00 .....!..........
40000000000E0530 11 00 38 52 90 11 00 00 00 02 00 00 18 73 FC 58 ..8R.........s.X
40000000000E0540 08 08 00 5E 00 21 00 00 A4 20 23 00 00 00 04 00 ...^.!... #.....
40000000000E0550 19 18 01 10 00 21 00 01 20 22 72 08 50 04 00 43 .....!.. "r.P..C
40000000000E0560 0B 70 00 10 00 10 00 00 00 02 00 C0 01 70 50 00 .p...........pP.
40000000000E0570 10 00 00 00 01 00 60 00 38 0E 73 03 30 04 00 42 ......`.8.s.0..B
40000000000E0580 0B 70 04 10 00 21 E0 00 38 00 20 00 00 00 04 00 .p...!..8. .....
40000000000E0590 03 00 00 00 01 00 E0 00 38 28 00 C0 00 70 1C E6 ........8(...p..
40000000000E05A0 D0 98 05 00 00 A4 A1 0A 00 00 48 03 60 00 00 42 ..........H.`..B
40000000000E05B0 0B 70 08 10 00 21 E0 00 38 00 20 00 00 00 04 00 .p...!..8. .....
40000000000E05C0 03 00 00 00 01 00 E0 00 38 28 00 C0 00 70 1C E6 ........8(...p..
40000000000E05D0 D0 98 09 00 00 A4 A1 12 00 00 48 03 30 00 00 42 ..........H.0..B
40000000000E05E0 11 88 01 10 00 21 00 00 00 02 00 00 E8 B0 F3 58 .....!.........X
40000000000E05F0 08 08 00 5E 00 21 A0 02 20 00 42 60 06 40 58 00 ...^.!.. .B`.@X.
40000000000E0600 11 88 01 4A 00 21 20 03 8C 00 42 00 48 B1 F3 58 ...J.! ...B.H..X
40000000000E0610 08 00 00 00 01 00 10 00 BC 00 42 E0 04 40 00 84 ..........B..@..
40000000000E0620 19 00 00 00 01 00 70 40 A8 0C 71 03 60 00 00 42 ......p@..q.`..B
40000000000E0630 08 90 D1 FB B8 27 00 00 00 02 00 20 06 28 01 84 .....'..... .(..
40000000000E0640 09 98 05 00 00 24 00 00 00 02 00 40 15 00 00 90 .....$.....@....
40000000000E0650 11 90 01 64 18 10 00 00 00 02 00 00 F8 B0 F3 58 ...d...........X
40000000000E0660 09 00 00 00 01 00 10 00 BC 00 42 E0 04 40 00 84 ..........B..@..
40000000000E0670 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E0680 11 48 01 50 10 50 14 03 8C 00 C2 08 68 A1 F3 5A .H.P.P......h..Z
40000000000E0690 31 0A 00 5E 00 21 60 50 9D 0E 71 03 D0 EF FF 4B 1..^.!`P..q....K
40000000000E06A0 11 00 00 00 01 00 00 01 A4 22 F3 08 B0 EF FF 4A .........".....J
40000000000E06B0 08 4A 71 00 00 24 00 00 00 02 00 00 00 00 04 00 .Jq..$..........
40000000000E06C0 11 88 01 4A 00 21 00 00 00 02 00 00 88 BC F3 58 ...J.!.........X
40000000000E06D0 08 00 00 00 01 00 10 00 BC 00 42 00 00 00 04 00 ..........B.....
40000000000E06E0 19 88 01 4C 18 10 00 00 00 02 00 00 28 AB F3 58 ...L........(..X
40000000000E06F0 08 00 00 00 01 00 10 00 BC 00 42 00 00 00 04 00 ..........B.....
40000000000E0700 19 88 01 4C 18 10 00 00 00 02 00 00 E8 A0 F3 58 ...L...........X
40000000000E0710 09 08 00 5E 00 21 00 48 A1 20 23 00 00 00 04 00 ...^.!.H. #.....
40000000000E0720 09 70 B0 03 40 24 00 00 00 02 00 60 C4 E7 FF 9F .p..@$.....`....
40000000000E0730 09 00 A4 1C 90 11 00 00 00 02 00 00 00 00 04 00 ................
40000000000E0740 03 40 00 46 00 21 F0 87 C1 BF 05 00 D0 02 AA 00 .@.F.!..........
40000000000E0750 00 00 00 00 01 00 00 60 05 80 03 00 00 00 04 00 .......`........
40000000000E0760 19 60 00 5C 00 21 00 00 00 02 00 80 08 00 84 00 .`.\.!..........
40000000000E0770 11 88 01 48 00 21 00 00 00 02 00 00 D8 BB F3 58 ...H.!.........X
40000000000E0780 11 08 00 5E 00 21 10 03 9C 00 42 00 C8 BB F3 58 ...^.!....B....X
40000000000E0790 08 00 00 00 01 00 10 00 BC 00 42 E0 11 00 00 90 ..........B.....
40000000000E07A0 0B 18 01 50 50 10 E0 A0 06 8C 48 E0 00 18 19 E6 ...PP.....H.....
40000000000E07B0 0B 00 00 00 01 00 00 78 38 20 23 00 00 00 04 00 .......x8 #.....
40000000000E07C0 10 18 81 01 40 01 00 00 00 02 00 00 00 00 00 20 ....@.......... 
40000000000E07D0 12 00 00 00 01 80 01 30 F8 7F 25 00 00 00 00 20 .......0..%.... 
40000000000E07E0 10 00 00 00 01 00 00 00 00 02 00 00 F0 E1 FF 48 ...............H
40000000000E07F0 11 18 01 10 00 21 10 03 90 00 42 00 58 BB F3 58 .....!....B.X..X
40000000000E0800 09 40 00 46 00 21 10 00 BC 00 42 E0 0F 83 7F 0B .@.F.!....B.....
40000000000E0810 02 00 00 00 01 00 00 68 01 55 00 00 C0 0A 00 07 .......h.U......
40000000000E0820 19 00 00 00 01 00 C0 00 B8 00 42 80 08 00 84 00 ..........B.....
40000000000E0830 11 88 01 48 00 21 00 00 00 02 00 00 18 BB F3 58 ...H.!.........X
40000000000E0840 11 08 00 5E 00 21 10 03 8C 00 42 00 20 E7 FF 48 ...^.!....B. ..H
40000000000E0850 11 18 01 50 10 10 10 03 9C 00 42 00 F8 BA F3 58 ...P......B....X
40000000000E0860 09 40 00 46 00 21 10 00 BC 00 42 E0 0F 83 7F 0B .@.F.!....B.....
40000000000E0870 02 00 00 00 01 00 00 68 01 55 00 00 C0 0A 00 07 .......h.U......
40000000000E0880 18 00 00 00 01 00 C0 00 B8 00 42 80 08 00 84 00 ..........B.....
40000000000E0890 09 88 01 4C 18 10 00 00 00 02 00 60 C4 E7 FF 9F ...L.......`....
40000000000E08A0 11 30 00 62 07 39 00 00 00 02 00 03 30 02 00 43 .0.b.9......0..C
40000000000E08B0 11 00 00 00 01 00 00 00 00 02 00 00 38 9F F3 58 ............8..X
40000000000E08C0 11 08 00 5E 00 21 00 00 00 02 00 00 88 AF F3 58 ...^.!.........X
40000000000E08D0 09 08 00 5E 00 21 90 02 20 20 20 00 00 00 04 00 ...^.!..   .....
40000000000E08E0 09 00 00 00 01 00 E0 60 07 80 48 00 00 00 04 00 .......`..H.....
40000000000E08F0 10 00 A4 1C 90 11 00 00 00 02 00 00 50 FE FF 48 ............P..H
40000000000E0900 11 88 01 48 00 21 00 00 00 02 00 00 08 D2 FF 58 ...H.!.........X
40000000000E0910 10 00 00 00 01 00 10 00 BC 00 42 00 90 EE FF 48 ..........B....H

l40000000000E0920:
	{ nop.m	0x0; adds	r49,0x0,r36; addl	r50,7,r0 }
	{ ld8	r51,[r14]; adds	r52,0x0,r0; br.call.sptk.many	b0,make_redirection; }
	{ adds	r1,0x0,r47; adds	r39,0x0,r8; br.cond.sptk.few	40000000000DF5A0 }

l40000000000E0950:
	{ nop.m	0x0; adds	r49,0x0,r36; addl	r50,15,r0 }
	{ ld8	r51,[r14]; adds	r52,0x0,r0; br.call.sptk.many	b0,make_redirection; }
	{ adds	r1,0x0,r47; adds	r39,0x0,r8; br.cond.sptk.few	40000000000DF5A0 }
40000000000E0980 11 88 01 48 00 21 00 00 00 02 00 00 88 D1 FF 58 ...H.!.........X
40000000000E0990 10 00 00 00 01 00 10 00 BC 00 42 00 A0 E5 FF 48 ..........B....H
40000000000E09A0 08 98 01 00 00 21 A0 02 00 00 42 00 00 00 04 00 .....!....B.....
40000000000E09B0 19 88 01 4A 00 21 20 03 8C 00 42 00 98 AD F3 58 ...J.! ...B....X
40000000000E09C0 08 00 00 00 01 00 10 00 BC 00 42 E0 04 40 00 84 ..........B..@..
40000000000E09D0 18 00 00 00 01 00 70 40 A8 0C 71 03 B0 FC FF 4A ......p@..q....J
40000000000E09E0 10 00 00 00 01 00 00 00 00 02 00 00 50 FC FF 48 ............P..H
40000000000E09F0 11 00 00 00 01 00 10 03 8C 00 42 00 58 B9 F3 58 ..........B.X..X
40000000000E0A00 08 08 00 5E 00 21 00 00 00 02 00 00 00 00 04 00 ...^.!..........
40000000000E0A10 09 00 00 00 01 00 90 02 A0 20 20 00 00 00 04 00 .........  .....
40000000000E0A20 10 00 00 00 01 00 00 01 A4 22 73 08 40 EC FF 4A ........."s.@..J
40000000000E0A30 10 00 00 00 01 00 00 00 00 02 00 00 90 FC FF 48 ...............H
40000000000E0A40 11 88 01 40 00 21 20 03 90 00 42 00 88 D1 FF 58 ...@.! ...B....X
40000000000E0A50 09 38 20 00 86 30 50 02 20 00 42 20 00 78 01 84 .8 ..0P. .B .x..
40000000000E0A60 10 00 00 00 01 80 01 19 91 22 71 03 A0 F0 FF 4A ........."q....J
40000000000E0A70 11 88 01 48 00 21 00 00 00 02 00 00 D8 B8 F3 58 ...H.!.........X
40000000000E0A80 08 08 00 5E 00 21 00 00 00 02 00 20 06 18 01 84 ...^.!..... ....
40000000000E0A90 19 18 01 4A 00 21 00 00 00 02 00 00 B8 B8 F3 58 ...J.!.........X
40000000000E0AA0 09 40 00 46 00 21 10 00 BC 00 42 E0 0F 83 7F 0B .@.F.!....B.....
40000000000E0AB0 02 00 00 00 01 00 00 68 01 55 00 00 C0 0A 00 07 .......h.U......
40000000000E0AC0 19 00 00 00 01 00 C0 00 B8 00 42 80 08 00 84 00 ..........B.....
40000000000E0AD0 11 18 F1 F9 FF 27 00 00 00 02 00 00 78 AD F3 58 .....'......x..X
40000000000E0AE0 09 08 00 5E 00 21 90 02 20 20 20 00 00 00 04 00 ...^.!..   .....
40000000000E0AF0 09 00 00 00 01 00 E0 60 07 80 48 00 00 00 04 00 .......`..H.....
40000000000E0B00 10 00 A4 1C 90 11 00 00 00 02 00 00 40 FC FF 48 ............@..H
40000000000E0B10 11 00 00 00 01 00 00 00 00 02 00 00 F8 CF FF 58 ...............X
40000000000E0B20 10 00 00 00 01 00 10 00 BC 00 42 00 F0 F5 FF 48 ..........B....H
40000000000E0B30 02 70 00 4A 10 10 F0 08 00 00 48 C0 00 70 1C 50 .p.J......H..p.P
40000000000E0B40 19 70 50 03 46 24 00 00 00 02 80 03 20 DE FF 4B .pP.F$...... ..K
40000000000E0B50 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E0B60 11 00 3C 1C 90 11 00 00 00 02 00 00 E8 AC F3 58 ..<............X
40000000000E0B70 09 18 01 10 10 10 00 00 00 02 00 20 00 78 01 84 ........... .x..
40000000000E0B80 10 00 00 00 01 00 70 00 8C 0C 73 03 C0 DA FF 4A ......p...s....J
40000000000E0B90 10 00 00 00 01 00 00 00 00 02 00 00 40 DE FF 48 ............@..H
40000000000E0BA0 11 88 01 56 00 21 00 00 00 02 00 00 28 B0 F6 58 ...V.!......(..X
40000000000E0BB0 11 08 00 5E 00 21 10 03 9C 00 42 00 98 B2 F3 58 ...^.!....B....X
40000000000E0BC0 11 08 00 5E 00 21 60 00 20 0E 73 03 A0 EA FF 4B ...^.!`. .s....K
40000000000E0BD0 09 00 00 00 01 00 90 02 A0 20 20 00 00 00 04 00 .........  .....
40000000000E0BE0 0B 80 00 52 91 39 94 E2 00 00 48 28 02 00 40 E0 ...R.9....H(..@.
40000000000E0BF0 10 00 A4 50 90 11 00 00 00 02 00 00 00 F3 FF 48 ...P...........H
40000000000E0C00 0B 30 B1 FB AF 27 60 02 98 30 20 00 00 00 04 00 .0...'`..0 .....
40000000000E0C10 11 88 01 4C 18 10 00 00 00 02 00 00 B8 AF F3 58 ...L...........X
40000000000E0C20 10 08 00 5E 00 21 60 08 20 0E F3 03 A0 EE FF 4A ...^.!`. ......J
40000000000E0C30 11 88 01 4C 18 10 00 00 00 02 00 00 58 9A F3 58 ...L........X..X
40000000000E0C40 08 00 00 00 01 00 10 00 BC 00 42 00 00 00 04 00 ..........B.....
40000000000E0C50 19 88 01 4C 18 10 00 00 00 02 00 00 38 45 05 50 ...L........8E.P
40000000000E0C60 10 00 00 00 01 00 10 00 BC 00 42 00 60 EE FF 48 ..........B.`..H
40000000000E0C70 08 48 01 50 10 10 00 00 00 02 00 60 C4 E7 FF 9F .H.P.......`....
40000000000E0C80 19 88 01 4C 18 10 00 00 00 02 00 00 88 A5 F3 58 ...L...........X
40000000000E0C90 08 00 00 00 01 00 10 00 BC 00 42 00 00 00 04 00 ..........B.....
40000000000E0CA0 19 88 01 4C 18 10 00 00 00 02 00 00 48 9B F3 58 ...L........H..X
40000000000E0CB0 11 08 00 5E 00 21 10 03 94 00 42 00 98 B6 F3 58 ...^.!....B....X
40000000000E0CC0 09 08 00 5E 00 21 00 48 A1 20 23 00 00 00 04 00 ...^.!.H. #.....
40000000000E0CD0 09 00 00 00 01 00 E0 60 07 80 48 00 00 00 04 00 .......`..H.....
40000000000E0CE0 10 00 A4 1C 90 11 00 00 00 02 00 00 60 FA FF 48 ............`..H
40000000000E0CF0 11 48 01 50 10 10 10 03 9C 00 42 00 58 B6 F3 58 .H.P......B.X..X
40000000000E0D00 08 00 00 00 01 00 10 00 BC 00 42 00 00 00 04 00 ..........B.....
40000000000E0D10 19 88 01 4C 18 10 00 00 00 02 00 00 D8 9A F3 58 ...L...........X
40000000000E0D20 08 00 00 00 01 00 10 00 BC 00 42 00 00 00 04 00 ..........B.....
40000000000E0D30 18 00 A4 50 90 11 00 00 00 02 00 00 F0 F9 FF 48 ...P...........H
40000000000E0D40 11 88 01 4C 00 21 00 00 00 02 00 00 A8 9A F3 58 ...L.!.........X
40000000000E0D50 09 40 00 46 00 21 10 00 BC 00 42 E0 0F 83 7F 0B .@.F.!....B.....
40000000000E0D60 02 00 00 00 01 00 00 68 01 55 00 00 C0 0A 00 07 .......h.U......
40000000000E0D70 18 00 00 00 01 00 C0 00 B8 00 42 80 08 00 84 00 ..........B.....
40000000000E0D80 09 00 00 00 01 00 30 02 20 20 20 00 00 00 04 00 ......0.   .....
40000000000E0D90 10 00 00 00 01 00 60 00 8C 0E 73 00 F0 E6 FF 48 ......`...s....H
40000000000E0DA0 09 00 00 00 01 00 30 02 A0 20 20 00 00 00 04 00 ......0..  .....
40000000000E0DB0 10 00 00 00 01 00 70 00 8C 0C 73 00 70 EA FF 48 ......p...s.p..H
40000000000E0DC0 09 00 00 00 01 00 30 02 A0 20 20 00 00 00 04 00 ......0..  .....
40000000000E0DD0 11 00 00 00 01 00 70 00 8C 0C 73 00 00 FA FF 48 ......p...s....H
40000000000E0DE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E0DF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; redirection_error: 40000000000E0E00
;;   Called from:
;;     40000000000E179C (in do_redirections)
redirection_error proc
	{ alloc	r38,ar.pfs,0xB,0x0,0x8; adds	r14,0x10,r32; mov	r37,b5 }
	{ adds	r39,0x0,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x0; adds	r14,0x8,r32 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000E10B0; }

l40000000000E0E40:
	{ ld4	r40,[r14]; nop.m	0x0; adds	r14,0x18,r32; }
	{ cmp4.lt	p07,p06,r40,r0; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000E1570; }

l40000000000E0E60:
	{ ld4	r14,[r14]; cmp4.eq	p07,p06,0x9,r33; (p07) br.cond.dpnt.few	40000000000E1400; }

l40000000000E0E70:
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x13,r14; (p07) br.cond.dptk.few	40000000000E0F90 }

l40000000000E0E80:
	{ adds	r32,0x20,r32; ld4	r40,[r32]; nop.i	0x0; }
	{ cmp4.lt	p06,p07,r40,r0; sxt4	r40,r40; (p06) br.cond.dpnt.few	40000000000E1220; }

l40000000000E0EA0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,itos; }
	{ adds	r1,0x0,r39; adds	r34,0x0,r8; adds	r35,0x0,r8 }

l40000000000E0EC0:
	{ nop.m	0x0; adds	r14,0x5,r33; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x4,r14; (p07) br.cond.dptk.few	40000000000E1060; }

l40000000000E0EE0:
	{ adds	r40,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B4A0; }
	{ adds	r1,0x0,r39; adds	r41,0x0,r35; adds	r42,0x0,r8; }
	{ addl	r40,-9044,r1; nop.i	0x0; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,internal_error; }
	{ adds	r1,0x0,r39; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000E0F40:
	{ cmp.eq	p06,p07,0x0,r34; adds	r40,0x0,r34; (p06) br.cond.dpnt.few	40000000000E0F70; }

l40000000000E0F50:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r39; nop.m	0x0; nop.i	0x0 }

l40000000000E0F70:
	{ nop.m	0x0; mov.i	ar.pfs,r38; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000E0F80; br.ret	b0 }

l40000000000E0F90:
	{ addl	r15,1,r0; sxt4	r14,r14; shl	r14,r15,r14 }
	{ addl	r15,949263,r0; and	r14,r15,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	40000000000E0E80 }

l40000000000E0FC0:
	{ addl	r35,6456,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000E1180; }

l40000000000E0FF0:
	{ (p07) adds	r32,0x20,r32; nop.m	0x0; nop.i	0x0; }

l40000000000E0FF6:
	{ break.m	0x4000; nop; nop }
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ Invalid; (p17) nop; break.b	0x80000 }
	{ (p03) chk.a.clr	f0,3FFFFFFFFFDA4906; nop; (p48) nop }

l40000000000E1030:
	{ cmp.eq	p07,p06,0x0,r34; (p07) ld8	r14,[r32]; nop.i	0x0; }

l40000000000E103C:
	{ setf.s	f0,r1; (p04) cmp.lt.unc	p00,p08,r3,r6; (p17) mov	pr,r8,0x8442 }

l40000000000E1046:
	{ (p07) chk.a.clr	f5,3FFFFFFFFF161256; nop; (p48) nop }

l40000000000E1050:
	{ adds	r35,0x0,r34; cmp4.ltu	p06,p07,0x4,r14; (p06) br.cond.dptk.few	40000000000E0EE0 }

l40000000000E1060:
	{ addl	r15,-9028,r1; addp4	r14,r14,r0; addl	r42,5,r0 }
	{ adds	r40,0x0,r0; ld8	r15,[r15]; nop.i	0x0; }
	{ shladd	r14,r14,0x3,r15; ld8	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; add	r14,r14,r15; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r14,40000000000E10A0; br.cond	b6; }

l40000000000E10B0:
	{ adds	r32,0x8,r32; nop.m	0x0; adds	r34,0x0,r0; }
	{ nop.m	0x0; ld8	r14,[r32]; nop.i	0x0; }
	{ ld8	r40,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r39; adds	r40,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r14,[r32]; adds	r1,0x0,r39; adds	r40,0x0,r8; }
	{ ld8	r41,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r14,0x5,r33; adds	r1,0x0,r39; adds	r35,0x0,r8; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x4,r14; (p06) br.cond.dptk.few	40000000000E0EE0 }

l40000000000E1130:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E1060 }

l40000000000E1140:
	{ addl	r14,6512,r1; nop.m	0x0; nop.i	0x0; }
	{ ld4	r14,[r14]; cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; }
	{ (p07) ld8	r14,[r32]; (p07) adds	r14,0x8,r14; nop.i	0x0; }

l40000000000E1166:
	{ Invalid; cmp.eq	p00,p00,r0,r1; (p01) nop; }

l40000000000E116C:
	{ Invalid; Invalid; break.i	0x1000 }

l40000000000E1176:
	{ break.m	0x4000; nop; (p32) nop }

l40000000000E1180:
	{ addl	r14,6512,r1; nop.m	0x0; adds	r32,0x20,r32; }
	{ nop.m	0x0; ld8.a	r40,[r32]; nop.i	0x0; }
	{ ld4	r14,[r14]; cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; }
	{ (p07) ld8	r14,[r32]; (p07) adds	r14,0x8,r14; nop.i	0x0; }

l40000000000E11B6:
	{ Invalid; cmp4.ltu	p00,p00,0x0,r1; (p01) cmp.ltu	p09,p04,r64,r3; }

l40000000000E11BC:
	{ nop; (p04) cmp4.ne.or.andcm	p00,p40,r3,r4; zxt1	r8,r11 }

l40000000000E11C6:
	{ Invalid; nop; Invalid; }

l40000000000E11CC:
	{ nop; mov	pr,r32,0x0; Invalid }

l40000000000E11DC:
	{ Invalid; Invalid; break.i	0x1000 }
	{ (p15) cmp.lt.unc	p58,p09,r63,r44; (p01) nop; dep	r96,r9,r64,62,1 }
	{ invala; nop }
	{ (p49) invala; break.i	0x1000; break.b	0x1000 }

l40000000000E1210:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E1140 }

l40000000000E1220:
	{ addl	r35,-9092,r1; adds	r14,0x5,r33; adds	r34,0x0,r0; }
	{ ld8	r35,[r35]; cmp4.ltu	p06,p07,0x4,r14; (p06) br.cond.dptk.few	40000000000E0EE0 }

l40000000000E1240:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E1060 }
40000000000E1250 09 00 00 00 01 00 90 62 F4 73 4F 00 00 00 04 00 .......b.sO.....
40000000000E1260 11 48 01 52 18 10 00 00 00 02 00 00 08 99 F3 58 .H.R...........X
40000000000E1270 08 08 00 4E 00 21 00 00 00 02 00 00 05 40 00 84 ...N.!.......@..
40000000000E1280 19 48 01 46 00 21 00 00 00 02 00 00 08 FE F8 58 .H.F.!.........X
40000000000E1290 11 00 00 00 01 00 10 00 9C 00 42 00 B0 FC FF 48 ..........B....H
40000000000E12A0 09 00 00 00 01 00 90 A2 F4 73 4F 00 00 00 04 00 .........sO.....
40000000000E12B0 11 48 01 52 18 10 00 00 00 02 00 00 B8 98 F3 58 .H.R...........X
40000000000E12C0 08 08 00 4E 00 21 00 00 00 02 00 00 05 40 00 84 ...N.!.......@..
40000000000E12D0 19 48 01 46 00 21 00 00 00 02 00 00 B8 FD F8 58 .H.F.!.........X
40000000000E12E0 11 00 00 00 01 00 10 00 9C 00 42 00 60 FC FF 48 ..........B.`..H
40000000000E12F0 09 00 00 00 01 00 90 E2 F4 73 4F 00 00 00 04 00 .........sO.....
40000000000E1300 11 48 01 52 18 10 00 00 00 02 00 00 68 98 F3 58 .H.R........h..X
40000000000E1310 03 08 00 4E 00 21 30 02 20 00 42 C0 C1 0E 00 91 ...N.!0. .B.....
40000000000E1320 11 40 01 1C 10 10 00 00 00 02 00 00 88 A1 F3 58 .@.............X
40000000000E1330 08 08 00 4E 00 21 00 00 00 02 00 00 05 18 01 84 ...N.!..........
40000000000E1340 19 48 01 10 00 21 00 00 00 02 00 00 48 FD F8 58 .H...!......H..X
40000000000E1350 11 00 00 00 01 00 10 00 9C 00 42 00 F0 FB FF 48 ..........B....H
40000000000E1360 09 00 00 00 01 00 90 22 F5 73 4F 00 00 00 04 00 .......".sO.....
40000000000E1370 11 48 01 52 18 10 00 00 00 02 00 00 F8 97 F3 58 .H.R...........X
40000000000E1380 08 08 00 4E 00 21 00 00 00 02 00 00 05 40 00 84 ...N.!.......@..
40000000000E1390 19 48 01 46 00 21 00 00 00 02 00 00 F8 FC F8 58 .H.F.!.........X
40000000000E13A0 11 00 00 00 01 00 10 00 9C 00 42 00 A0 FB FF 48 ..........B....H
40000000000E13B0 09 00 00 00 01 00 90 22 F4 73 4F 00 00 00 04 00 .......".sO.....
40000000000E13C0 11 48 01 52 18 10 00 00 00 02 00 00 A8 97 F3 58 .H.R...........X
40000000000E13D0 08 08 00 4E 00 21 00 00 00 02 00 00 05 40 00 84 ...N.!.......@..
40000000000E13E0 19 48 01 46 00 21 00 00 00 02 00 00 A8 FC F8 58 .H.F.!.........X
40000000000E13F0 10 00 00 00 01 00 10 00 9C 00 42 00 50 FB FF 48 ..........B.P..H

l40000000000E1400:
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x10,r14; (p06) br.cond.dptk.few	40000000000E1500 }

l40000000000E1410:
	{ addl	r15,1,r0; sxt4	r14,r14; shl	r14,r15,r14 }
	{ addl	r15,98496,r0; and	r15,r15,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	40000000000E14E0; }

l40000000000E1440:
	{ nop.m	0x0; tbit.z	p07,p06,r14,0xE; (p06) br.cond.dptk.few	40000000000E15D0; }

l40000000000E1450:
	{ nop.m	0x0; tbit.z	p07,p06,r14,0xD; (p07) br.cond.dptk.few	40000000000E1500; }

l40000000000E1460:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r40; (p06) br.cond.dpnt.few	40000000000E1500 }

l40000000000E1470:
	{ adds	r32,0x20,r32; adds	r40,0x0,r33; adds	r34,0x0,r0; }
	{ nop.m	0x0; ld8	r14,[r32]; nop.i	0x0; }
	{ ld8	r35,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B4A0; }
	{ adds	r1,0x0,r39; adds	r41,0x0,r35; adds	r42,0x0,r8; }
	{ nop.m	0x0; addl	r40,-9044,r1; nop.i	0x0; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,internal_error; }
	{ nop.m	0x0; adds	r1,0x0,r39; br.cond.sptk.few	40000000000E0F40 }

l40000000000E14E0:
	{ nop.m	0x0; adds	r32,0x20,r32; nop.i	0x0; }
	{ ld4	r40,[r32]; nop.m	0x0; nop.i	0x0; }

l40000000000E1500:
	{ nop.m	0x0; sxt4	r40,r40; br.call.sptk.many	b0,itos; }
	{ adds	r1,0x0,r39; adds	r34,0x0,r8; adds	r35,0x0,r8 }

l40000000000E1520:
	{ adds	r40,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B4A0; }
	{ adds	r1,0x0,r39; adds	r41,0x0,r35; adds	r42,0x0,r8; }
	{ nop.m	0x0; addl	r40,-9044,r1; nop.i	0x0; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,internal_error; }
	{ nop.m	0x0; adds	r1,0x0,r39; br.cond.sptk.few	40000000000E0F40; }

l40000000000E1570:
	{ addl	r41,-9092,r1; nop.m	0x0; adds	r40,0x0,r0 }
	{ addl	r42,5,r0; nop.m	0x0; adds	r34,0x0,r0; }
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r14,0x5,r33; adds	r1,0x0,r39; adds	r35,0x0,r8; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x4,r14; (p06) br.cond.dptk.few	40000000000E0EE0 }

l40000000000E15C0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E1060; }

l40000000000E15D0:
	{ cmp4.eq	p06,p07,0x1,r40; sxt4	r40,r40; (p06) br.cond.dpnt.few	40000000000E1470; }

l40000000000E15E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,itos; }
	{ nop.m	0x0; adds	r1,0x0,r39; adds	r34,0x0,r8 }
	{ nop.m	0x0; adds	r35,0x0,r8; br.cond.sptk.few	40000000000E1520; }
40000000000E1610 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E1620 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E1630 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; do_redirections: 40000000000E1640
do_redirections proc
	{ alloc	r37,ar.pfs,0x9,0x0,0x7; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r36,b4 }
	{ addl	r35,7068,r1; adds	r38,0x0,r1; adds	r34,0x0,r32; }
	{ nop.m	0x0; tbit.z	p07,p06,r33,0x1; (p07) br.cond.dptk.few	40000000000E1700; }

l40000000000E1670:
	{ nop.m	0x0; ld8	r14,[r35]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; adds	r39,0x0,r14; (p06) br.cond.dpnt.few	40000000000E16B0; }

l40000000000E1690:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,dispose_redirects; }
	{ adds	r1,0x0,r38; st8	[r0],r35; nop.i	0x0; }

l40000000000E16B0:
	{ addl	r14,7060,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E1700; }

l40000000000E16E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,dispose_exec_redirects; }
	{ adds	r1,0x0,r38; nop.m	0x0; nop.i	0x0 }

l40000000000E1700:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p07) br.cond.dpnt.few	40000000000E1760; }

l40000000000E1710:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000E1720:
	{ adds	r39,0x0,r34; adds	r40,0x0,r33; br.call.sptk.many	b0,fn40000000000DE580; }
	{ adds	r1,0x0,r38; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dpnt.few	40000000000E1780; }

l40000000000E1740:
	{ nop.m	0x0; ld8	r34,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	40000000000E1720 }

l40000000000E1760:
	{ adds	r8,0x0,r0; mov.i	ar.pfs,r37; mov.spnt	b0,r36,40000000000E1760 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000000E1780:
	{ adds	r14,0x10,r12; adds	r40,0x0,r8; adds	r39,0x0,r34; }
	{ st8	[r8],r14; nop.i	0x0; br.call.sptk.many	b0,redirection_error; }
	{ adds	r14,0x10,r12; nop.m	0x0; adds	r1,0x0,r38; }
	{ ld8	r8,[r14]; mov.i	ar.pfs,r37; mov.spnt	b0,r36,40000000000E17B0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }
40000000000E17D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E17E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E17F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; stdin_redirects: 40000000000E1800
stdin_redirects proc
	{ adds	r8,0x0,r0; addl	r19,1,r0; addl	r20,2358,r0 }
	{ addl	r21,8768,r0; adds	r14,0x0,r32; cmp.eq	p06,p07,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E1960; }

l40000000000E1830:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000E1840:
	{ adds	r15,0x10,r14; adds	r17,0x18,r14; adds	r16,0x8,r14; }
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r15,0x0; (p06) br.cond.dptk.few	40000000000E1910 }

l40000000000E1870:
	{ ld4	r15,[r17]; ld4	r17,[r16]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r16,r15; nop.i	0x0 }
	{ cmp4.ltu	p06,p07,0xD,r15; nop.m	0x0; (p06) br.cond.dptk.few	40000000000E1940; }

l40000000000E18A0:
	{ nop.m	0x0; shl	r16,r19,r16; addl	r15,1,r0; }
	{ and	r18,r20,r16; nop.m	0x0; and	r16,r21,r16; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r18; (p06) br.cond.dptk.few	40000000000E1900; }

l40000000000E18D0:
	{ cmp4.eq	p06,p07,0x0,r17; cmp.eq	p09,p08,0x0,r16; (p09) br.cond.dptk.few	40000000000E1940; }

l40000000000E18E0:
	{ nop.m	0x0; (p06) addl	r17,1,r0; nop.i	0x0; }

l40000000000E18EC:
	{ nop; zxt1	r0,r64; cmp.eq	p00,p00,r32,r0 }

l40000000000E18F6:
	{ add	r0,r0,r1; (p07) nop; nop }

l40000000000E1900:
	{ add	r8,r8,r15; nop.m	0x0; nop.i	0x0 }

l40000000000E1910:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000E1840 }

l40000000000E1930:
	{ nop.m	0x0; nop.i	0x0; br.ret	b0 }

l40000000000E1940:
	{ nop.m	0x0; adds	r15,0x0,r0; nop.i	0x0; }
	{ nop.m	0x0; add	r8,r8,r15; br.cond.sptk.few	40000000000E1910; }

l40000000000E1960:
	{ nop.m	0x0; adds	r8,0x0,r0; br.ret	b0; }
40000000000E1970 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000E1980 08 20 21 0E 80 05 F0 A0 F4 AD 4E C0 04 08 CA 00 . !.......N.....
40000000000E1990 09 00 00 00 01 00 50 02 04 00 42 00 00 00 04 00 ......P...B.....
40000000000E19A0 09 00 00 00 01 00 10 02 00 00 42 60 04 00 C4 00 ..........B`....
40000000000E19B0 09 00 00 00 01 00 E0 00 3C 30 20 00 00 00 04 00 ........<0 .....
40000000000E19C0 11 00 00 00 01 00 60 00 38 0E 72 03 30 01 00 43 ......`.8.r.0..C
40000000000E19D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E19E0 0B 08 05 42 00 21 00 00 00 02 00 40 04 08 59 00 ...B.!.....@..Y.
40000000000E19F0 0B 70 88 1E 13 20 E0 00 38 30 20 00 00 00 04 00 .p... ..80 .....
40000000000E1A00 10 00 00 00 01 00 70 00 38 0C 72 03 E0 FF FF 4A ......p.8.r....J
40000000000E1A10 11 38 01 42 00 21 00 00 00 02 00 00 38 D1 04 50 .8.B.!......8..P
40000000000E1A20 09 08 00 4A 00 21 00 F9 87 7E 46 C0 01 00 00 84 ...J.!...~F.....
40000000000E1A30 09 78 50 FA 56 27 00 00 00 02 00 00 02 01 20 80 .xP.V'........ .
40000000000E1A40 09 00 00 00 01 00 00 00 00 02 00 00 00 09 AA 00 ................
40000000000E1A50 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E1A60 09 80 00 10 18 10 10 81 3C 30 28 00 00 00 04 00 ........<0(.....
40000000000E1A70 09 80 40 1C 00 20 00 00 00 02 00 C0 81 70 00 84 ..@.. .......p..
40000000000E1A80 10 00 44 20 98 11 00 00 00 02 00 A0 E0 FF FF 48 ..D ...........H
40000000000E1A90 18 70 00 10 00 21 F0 00 80 20 20 00 00 00 00 20 .p...!...  .... 
40000000000E1AA0 09 10 89 00 12 20 00 00 00 02 00 00 40 02 AA 00 ..... ......@...
40000000000E1AB0 09 80 30 1C 18 14 F0 00 3D 5C 40 00 60 0A AA 00 ..0.....=\@.`...
40000000000E1AC0 09 10 41 44 00 20 00 08 39 20 23 00 30 0A 00 07 ..AD. ..9 #.0...
40000000000E1AD0 09 00 00 44 98 11 00 79 80 20 2B 00 00 00 04 00 ...D...y. +.....
40000000000E1AE0 11 00 20 40 98 11 80 00 00 00 42 80 08 00 84 00 .. @......B.....
40000000000E1AF0 08 38 01 00 00 21 00 00 00 02 00 40 04 00 00 84 .8...!.....@....
40000000000E1B00 19 08 01 00 00 21 00 00 00 02 00 00 48 D0 04 50 .....!......H..P
40000000000E1B10 18 70 00 10 00 21 F0 00 80 20 20 00 00 00 00 20 .p...!...  .... 
40000000000E1B20 09 08 00 4A 00 21 00 00 00 02 00 00 40 02 AA 00 ...J.!......@...
40000000000E1B30 09 80 30 1C 18 14 F0 00 3D 5C 40 00 60 0A AA 00 ..0.....=\@.`...
40000000000E1B40 09 10 41 44 00 20 00 08 39 20 23 00 30 0A 00 07 ..AD. ..9 #.0...
40000000000E1B50 09 00 00 44 98 11 00 79 80 20 2B 00 00 00 04 00 ...D...y. +.....
40000000000E1B60 11 00 20 40 98 11 80 00 00 00 42 80 08 00 84 00 .. @......B.....
40000000000E1B70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E1B80 08 18 19 0A 80 05 10 62 04 60 48 40 04 00 C4 00 .......b.`H@....
40000000000E1B90 0B 20 01 02 00 21 00 00 00 02 00 00 00 00 04 00 . ...!..........
40000000000E1BA0 11 28 01 42 10 10 00 00 00 02 00 00 A8 CF 04 50 .(.B...........P
40000000000E1BB0 08 78 00 42 10 10 10 00 90 00 42 C0 01 00 00 84 .x.B......B.....
40000000000E1BC0 02 80 00 00 00 21 60 01 20 00 42 A0 F2 7F FC 8C .....!`. .B.....
40000000000E1BD0 19 A0 50 02 30 24 70 00 3C 0C 63 03 50 01 00 43 ..P.0$p.<.c.P..C
40000000000E1BE0 09 A8 54 00 08 20 00 00 00 02 00 00 00 00 04 00 ..T.. ..........
40000000000E1BF0 09 00 00 00 01 00 50 09 54 00 42 00 00 00 04 00 ......P.T.B.....
40000000000E1C00 03 A8 54 2A 10 20 00 00 00 02 00 A0 52 01 4C 80 ..T*. ......R.L.
40000000000E1C10 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E1C20 02 78 00 28 18 10 30 01 40 2C 00 E0 F1 70 00 80 .x.(..0.@,...p..
40000000000E1C30 0A 70 C0 1C 00 21 10 41 3C 00 42 40 02 79 00 84 .p...!.A<.B@.y..
40000000000E1C40 0B 38 54 1C 06 38 10 01 44 30 20 00 00 00 04 00 .8T..8..D0 .....
40000000000E1C50 11 40 00 22 09 39 00 00 00 02 00 04 50 00 00 43 .@.".9......P..C
40000000000E1C60 0B 88 00 24 10 10 00 00 00 02 00 00 01 88 24 50 ...$..........$P
40000000000E1C70 08 00 00 00 01 40 12 01 58 30 A0 04 12 80 00 84 .....@..X0......
40000000000E1C80 23 79 00 1E 18 10 00 00 00 02 80 64 32 89 48 80 #y.........d2.H.
40000000000E1C90 28 01 3C 26 98 11 00 00 00 02 00 00 00 00 04 00 (.<&............
40000000000E1CA0 10 00 00 00 01 00 00 00 00 02 00 03 80 FF FF 4A ...............J
40000000000E1CB0 18 70 00 2C 00 21 F0 00 80 20 20 00 00 00 00 20 .p.,.!...  .... 
40000000000E1CC0 01 40 00 00 00 21 00 18 01 55 00 20 02 80 58 00 .@...!...U. ..X.
40000000000E1CD0 18 90 30 1C 18 14 10 89 00 24 40 00 00 00 00 20 ..0......$@.... 
40000000000E1CE0 09 78 80 1E 2E 20 00 00 00 02 00 00 20 0A 00 07 .x... ...... ...
40000000000E1CF0 09 88 48 22 00 20 00 80 38 20 23 00 00 00 04 00 ..H". ..8 #.....
40000000000E1D00 09 00 00 22 98 11 00 79 80 20 2B 00 00 00 04 00 ..."...y. +.....
40000000000E1D10 10 00 58 40 98 11 00 00 00 02 00 80 08 00 84 00 ..X@............
40000000000E1D20 08 70 00 2C 00 21 F0 00 80 20 20 00 30 02 AA 00 .p.,.!...  .0...
40000000000E1D30 09 88 00 00 00 21 00 01 00 00 42 00 01 00 00 84 .....!....B.....
40000000000E1D40 09 90 30 1C 18 14 F0 00 3D 5C 40 00 20 0A 00 07 ..0.....=\@. ...
40000000000E1D50 09 88 48 22 00 20 00 80 38 20 23 00 00 00 04 00 ..H". ..8 #.....
40000000000E1D60 09 00 00 22 98 11 00 79 80 20 2B 00 00 00 04 00 ..."...y. +.....
40000000000E1D70 11 00 58 40 98 11 00 00 00 02 00 80 08 00 84 00 ..X@............
40000000000E1D80 08 18 19 0A 80 05 10 62 04 60 48 40 04 00 C4 00 .......b.`H@....
40000000000E1D90 0B 20 01 02 00 21 00 00 00 02 00 00 00 00 04 00 . ...!..........
40000000000E1DA0 11 28 01 42 10 10 00 00 00 02 00 00 A8 CD 04 50 .(.B...........P
40000000000E1DB0 08 78 00 42 10 10 10 00 90 00 42 C0 01 00 00 84 .x.B......B.....
40000000000E1DC0 02 80 00 00 00 21 60 01 20 00 42 A0 F2 7F FC 8C .....!`. .B.....
40000000000E1DD0 19 A0 50 02 30 24 70 00 3C 0C 63 03 50 01 00 43 ..P.0$p.<.c.P..C
40000000000E1DE0 09 A8 54 00 08 20 00 00 00 02 00 00 00 00 04 00 ..T.. ..........
40000000000E1DF0 09 00 00 00 01 00 50 09 54 00 42 00 00 00 04 00 ......P.T.B.....
40000000000E1E00 03 A8 54 2A 10 20 00 00 00 02 00 A0 52 01 4C 80 ..T*. ......R.L.
40000000000E1E10 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E1E20 02 78 00 28 18 10 30 01 40 2C 00 E0 F1 70 00 80 .x.(..0.@,...p..
40000000000E1E30 0A 70 C0 1C 00 21 10 41 3C 00 42 40 02 79 00 84 .p...!.A<.B@.y..
40000000000E1E40 0B 38 54 1C 06 38 10 01 44 30 20 00 00 00 04 00 .8T..8..D0 .....
40000000000E1E50 11 40 00 22 09 39 00 00 00 02 00 04 50 00 00 43 .@.".9......P..C
40000000000E1E60 0B 88 00 24 10 10 00 00 00 02 00 20 01 88 20 50 ...$....... .. P
40000000000E1E70 08 00 00 00 01 40 12 01 58 30 A0 04 12 80 00 84 .....@..X0......
40000000000E1E80 23 79 00 1E 18 10 00 00 00 02 80 64 32 89 48 80 #y.........d2.H.
40000000000E1E90 28 01 3C 26 98 11 00 00 00 02 00 00 00 00 04 00 (.<&............
40000000000E1EA0 10 00 00 00 01 00 00 00 00 02 00 03 80 FF FF 4A ...............J
40000000000E1EB0 18 70 00 2C 00 21 F0 00 80 20 20 00 00 00 00 20 .p.,.!...  .... 
40000000000E1EC0 01 40 00 00 00 21 00 18 01 55 00 20 02 80 58 00 .@...!...U. ..X.
40000000000E1ED0 18 90 30 1C 18 14 10 89 00 24 40 00 00 00 00 20 ..0......$@.... 
40000000000E1EE0 09 78 80 1E 2E 20 00 00 00 02 00 00 20 0A 00 07 .x... ...... ...
40000000000E1EF0 09 88 48 22 00 20 00 80 38 20 23 00 00 00 04 00 ..H". ..8 #.....
40000000000E1F00 09 00 00 22 98 11 00 79 80 20 2B 00 00 00 04 00 ..."...y. +.....
40000000000E1F10 10 00 58 40 98 11 00 00 00 02 00 80 08 00 84 00 ..X@............
40000000000E1F20 08 70 00 2C 00 21 F0 00 80 20 20 00 30 02 AA 00 .p.,.!...  .0...
40000000000E1F30 09 88 00 00 00 21 00 01 00 00 42 00 01 00 00 84 .....!....B.....
40000000000E1F40 09 90 30 1C 18 14 F0 00 3D 5C 40 00 20 0A 00 07 ..0.....=\@. ...
40000000000E1F50 09 88 48 22 00 20 00 80 38 20 23 00 00 00 04 00 ..H". ..8 #.....
40000000000E1F60 09 00 00 22 98 11 00 79 80 20 2B 00 00 00 04 00 ..."...y. +.....
40000000000E1F70 11 00 58 40 98 11 00 00 00 02 00 80 08 00 84 00 ..X@............
40000000000E1F80 08 18 19 0A 80 05 10 62 04 60 48 40 04 00 C4 00 .......b.`H@....
40000000000E1F90 0B 20 01 02 00 21 00 00 00 02 00 00 00 00 04 00 . ...!..........
40000000000E1FA0 11 28 01 42 10 10 00 00 00 02 00 00 A8 CB 04 50 .(.B...........P
40000000000E1FB0 08 80 00 42 10 10 10 00 90 00 42 C0 01 00 00 84 ...B......B.....
40000000000E1FC0 02 78 00 00 00 21 30 01 20 00 42 A0 F2 87 FC 8C .x...!0. .B.....
40000000000E1FD0 19 A0 50 02 30 24 70 00 40 0C 63 03 20 01 00 43 ..P.0$p.@.c. ..C
40000000000E1FE0 09 A8 54 00 08 20 00 00 00 02 00 00 00 00 04 00 ..T.. ..........
40000000000E1FF0 09 00 00 00 01 00 50 09 54 00 42 00 00 00 04 00 ......P.T.B.....
40000000000E2000 03 A8 54 2A 10 20 00 00 00 02 00 A0 52 01 4C 80 ..T*. ......R.L.
40000000000E2010 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2020 02 80 00 28 18 10 20 01 3C 2C 00 00 02 71 00 80 ...(.. .<,...q..
40000000000E2030 0B 70 C0 1C 00 21 10 41 40 00 42 E0 50 71 18 E0 .p...!.A@.B.Pq..
40000000000E2040 0B 88 00 22 18 10 80 00 44 12 72 00 00 00 04 00 ..."....D.r.....
40000000000E2050 08 00 00 00 01 40 12 01 4C 30 A0 E4 11 78 00 84 .....@..L0...x..
40000000000E2060 2B 81 00 20 18 50 22 91 44 24 40 00 00 00 04 00 +.. .P".D$@.....
40000000000E2070 30 01 40 24 98 11 00 00 00 02 00 03 B0 FF FF 4A 0.@$...........J
40000000000E2080 18 70 00 26 00 21 00 01 80 20 20 00 00 00 00 20 .p.&.!...  .... 
40000000000E2090 01 40 00 00 00 21 00 18 01 55 00 20 02 78 58 00 .@...!...U. .xX.
40000000000E20A0 18 90 30 1C 18 14 10 89 00 24 40 00 00 00 00 20 ..0......$@.... 
40000000000E20B0 09 80 80 20 2E 20 00 00 00 02 00 00 20 0A 00 07 ... . ...... ...
40000000000E20C0 09 88 48 22 00 20 00 78 38 20 23 00 00 00 04 00 ..H". .x8 #.....
40000000000E20D0 09 00 00 22 98 11 00 81 80 20 2B 00 00 00 04 00 ..."..... +.....
40000000000E20E0 10 00 4C 40 98 11 00 00 00 02 00 80 08 00 84 00 ..L@............
40000000000E20F0 08 70 00 26 00 21 00 01 80 20 20 00 30 02 AA 00 .p.&.!...  .0...
40000000000E2100 09 88 00 00 00 21 F0 00 00 00 42 00 01 00 00 84 .....!....B.....
40000000000E2110 09 90 30 1C 18 14 00 01 41 5C 40 00 20 0A 00 07 ..0.....A\@. ...
40000000000E2120 09 88 48 22 00 20 00 78 38 20 23 00 00 00 04 00 ..H". .x8 #.....
40000000000E2130 09 00 00 22 98 11 00 81 80 20 2B 00 00 00 04 00 ..."..... +.....
40000000000E2140 11 00 4C 40 98 11 00 00 00 02 00 80 08 00 84 00 ..L@............
40000000000E2150 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2160 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2170 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2180 08 58 3D 1A 80 05 E0 40 84 30 28 40 05 00 C4 00 .X=....@.0(@....
40000000000E2190 02 60 01 02 00 21 00 00 00 02 00 C0 E0 08 00 07 .`...!..........
40000000000E21A0 19 08 E0 43 19 16 40 02 00 00 42 00 68 00 80 10 ...C..@...B.h...
40000000000E21B0 08 28 21 10 00 21 10 00 B0 00 42 00 00 00 04 00 .(!..!....B.....
40000000000E21C0 19 30 00 10 07 39 30 02 20 00 42 03 F0 01 00 43 .0...90. .B....C
40000000000E21D0 09 70 00 4A 00 21 F0 00 20 30 20 00 00 00 04 00 .p.J.!.. 0 .....
40000000000E21E0 11 00 00 00 01 00 70 00 3C 0C F2 03 70 01 00 43 ......p.<...p..C
40000000000E21F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2200 09 40 39 46 05 20 F0 40 38 30 28 80 14 20 01 84 .@9F. .@80(.. ..
40000000000E2210 10 00 00 00 01 00 70 00 3C 0C 72 03 F0 FF FF 4A ......p.<.r....J
40000000000E2220 08 48 FD 49 3F 23 00 00 00 02 00 A0 15 20 01 84 .H.I?#....... ..
40000000000E2230 19 10 01 46 00 21 00 00 00 02 00 00 18 C9 04 50 ...F.!.........P
40000000000E2240 08 48 A5 00 08 20 10 00 B0 00 42 00 00 00 04 00 .H... ....B.....
40000000000E2250 03 38 01 10 00 21 00 00 00 02 00 20 95 2A 49 80 .8...!..... .*I.
40000000000E2260 08 28 89 46 05 20 00 00 00 02 00 C0 04 10 01 84 .(.F. ..........
40000000000E2270 09 78 20 44 18 14 E0 00 9C 30 20 00 00 00 04 00 .x D.....0 .....
40000000000E2280 09 00 00 00 01 00 50 72 94 00 40 00 00 00 04 00 ......Pr..@.....
40000000000E2290 11 68 01 1E 18 10 00 00 00 02 00 00 38 94 F3 58 .h..........8..X
40000000000E22A0 11 08 00 58 00 21 D0 0A 20 00 42 00 28 6A 00 50 ...X.!.. .B.(j.P
40000000000E22B0 09 70 00 4C 18 10 10 00 B0 00 42 A0 05 40 00 84 .p.L......B..@..
40000000000E22C0 11 70 01 1C 18 10 00 00 00 02 00 00 C8 8E F3 58 .p.............X
40000000000E22D0 08 00 00 00 01 00 10 00 B0 00 42 E0 90 12 19 E0 ..........B.....
40000000000E22E0 18 00 00 00 01 00 00 40 94 30 23 03 80 FF FF 4A .......@.0#....J
40000000000E22F0 09 70 00 4E 00 21 00 00 00 02 00 00 04 01 01 84 .p.N.!..........
40000000000E2300 09 00 00 00 01 00 F0 60 38 30 28 00 00 00 04 00 .......`80(.....
40000000000E2310 09 40 3D 50 00 20 00 20 39 20 23 00 00 00 04 00 .@=P. . 9 #.....
40000000000E2320 08 00 00 50 98 11 00 38 81 30 23 00 00 00 04 00 ...P...8.0#.....
40000000000E2330 01 00 00 00 01 00 00 58 01 55 00 00 00 00 04 00 .......X.U......
40000000000E2340 11 00 00 00 01 00 00 50 05 80 03 80 08 00 84 00 .......P........
40000000000E2350 08 68 05 00 00 24 80 02 00 00 42 00 00 00 04 00 .h...$....B.....
40000000000E2360 19 20 01 00 00 21 00 82 80 00 42 00 E8 C7 04 50 . ...!....B....P
40000000000E2370 03 38 01 10 00 21 10 00 B0 00 42 C0 01 38 01 84 .8...!....B..8..
40000000000E2380 02 78 30 1C 18 14 00 00 00 02 00 00 F5 40 01 80 .x0..........@..
40000000000E2390 02 00 90 1C 90 11 00 00 00 02 00 00 00 00 04 00 ................
40000000000E23A0 18 00 00 50 98 11 00 38 81 30 23 00 90 FF FF 48 ...P...8.0#....H
40000000000E23B0 09 00 41 40 00 21 00 00 00 02 00 00 B0 02 AA 00 ..A@.!..........
40000000000E23C0 11 00 00 40 98 11 00 50 05 80 03 80 08 00 84 00 ...@...P........
40000000000E23D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E23E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E23F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2400 10 10 19 08 80 05 10 02 00 62 00 00 00 00 00 20 .........b..... 
40000000000E2410 09 28 F1 FB B4 27 30 02 04 00 42 80 04 00 01 84 .(...'0...B.....
40000000000E2420 11 28 01 4A 18 10 00 00 00 02 00 00 68 FD FF 58 .(.J........h..X
40000000000E2430 09 40 00 00 00 21 10 00 8C 00 42 00 20 02 AA 00 .@...!....B. ...
40000000000E2440 11 00 00 00 01 00 00 08 05 80 03 80 08 00 84 00 ................
40000000000E2450 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2460 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2470 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2480 10 10 19 08 80 05 10 02 00 62 00 00 00 00 00 20 .........b..... 
40000000000E2490 09 28 91 FA B2 27 30 02 04 00 42 80 04 00 01 84 .(...'0...B.....
40000000000E24A0 11 28 01 4A 18 10 00 00 00 02 00 00 E8 FC FF 58 .(.J...........X
40000000000E24B0 09 40 00 00 00 21 10 00 8C 00 42 00 20 02 AA 00 .@...!....B. ...
40000000000E24C0 11 00 00 00 01 00 00 08 05 80 03 80 08 00 84 00 ................
40000000000E24D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E24E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E24F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2500 10 10 19 08 80 05 10 02 00 62 00 00 00 00 00 20 .........b..... 
40000000000E2510 09 28 71 FA B4 27 30 02 04 00 42 80 04 00 01 84 .(q..'0...B.....
40000000000E2520 11 28 01 4A 18 10 00 00 00 02 00 00 68 FC FF 58 .(.J........h..X
40000000000E2530 09 40 00 00 00 21 10 00 8C 00 42 00 20 02 AA 00 .@...!....B. ...
40000000000E2540 11 00 00 00 01 00 00 08 05 80 03 80 08 00 84 00 ................
40000000000E2550 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2560 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2570 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2580 10 10 19 08 80 05 10 02 00 62 00 00 00 00 00 20 .........b..... 
40000000000E2590 09 28 91 FA B3 27 30 02 04 00 42 80 04 00 01 84 .(...'0...B.....
40000000000E25A0 11 28 01 4A 18 10 00 00 00 02 00 00 E8 FB FF 58 .(.J...........X
40000000000E25B0 09 40 04 00 00 24 10 00 8C 00 42 00 20 02 AA 00 .@...$....B. ...
40000000000E25C0 11 00 00 00 01 00 00 08 05 80 03 80 08 00 84 00 ................
40000000000E25D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E25E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E25F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2600 10 50 3D 1A 80 05 C0 02 00 66 00 00 00 00 00 20 .P=......f..... 
40000000000E2610 09 40 04 42 89 39 B0 02 04 00 42 C0 00 08 1D E6 .@.B.9....B.....
40000000000E2620 00 00 00 00 01 00 90 02 00 62 00 00 00 00 04 00 .........b......
40000000000E2630 19 30 05 00 00 24 00 00 00 02 00 03 20 00 00 42 .0...$...... ..B
40000000000E2640 02 31 09 00 00 24 00 00 00 02 80 C4 F4 E7 FF 9F .1...$..........
40000000000E2650 09 10 F1 FA 5E 27 30 A2 04 74 48 00 F2 0F 45 EE ....^'0..tH...E.
40000000000E2660 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2670 09 00 00 00 01 00 20 E2 88 00 42 00 00 00 04 00 ...... ...B.....
40000000000E2680 11 68 01 44 10 10 00 00 00 02 00 00 C8 C4 04 50 .h.D...........P
40000000000E2690 08 70 00 44 10 10 00 00 00 02 00 E0 C4 40 00 84 .p.D.........@..
40000000000E26A0 09 08 00 56 00 21 00 00 00 02 00 00 05 40 00 84 ...V.!.......@..
40000000000E26B0 02 70 FC 1D 3F 23 00 00 00 02 00 40 04 70 58 00 .p..?#.....@.pX.
40000000000E26C0 19 78 38 00 08 20 70 70 00 0C E1 03 C0 00 00 43 .x8.. pp.......C
40000000000E26D0 09 20 89 1E 05 20 00 00 00 02 00 40 24 02 48 80 . ... .....@$.H.
40000000000E26E0 03 20 91 00 12 20 00 00 00 02 00 80 84 27 FD 8C . ... .......'..
40000000000E26F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2700 0B 70 00 46 18 10 E0 70 88 00 40 00 00 00 04 00 .p.F...p..@.....
40000000000E2710 02 70 00 1C 18 10 00 00 00 02 00 E0 81 70 00 84 .p...........p..
40000000000E2720 19 80 50 1C 00 21 60 00 38 0E 72 03 40 00 00 43 ..P..!`.8.r.@..C
40000000000E2730 11 78 00 1E 18 10 00 00 00 02 00 08 80 00 00 43 .x.............C
40000000000E2740 09 00 00 00 01 00 E0 00 40 20 20 00 00 00 04 00 ........@  .....
40000000000E2750 10 00 00 00 01 00 70 30 39 0C F1 03 60 00 00 43 ......p09...`..C
40000000000E2760 09 00 00 00 01 00 20 C2 8B 7E 46 00 00 00 04 00 ...... ..~F.....
40000000000E2770 11 00 00 00 01 00 70 20 89 0C 70 03 90 FF FF 4A ......p ..p....J
40000000000E2780 09 00 41 40 00 21 80 00 00 00 42 E0 CF 82 7F 0B ..A@.!....B.....
40000000000E2790 09 00 A0 40 98 11 00 00 00 02 00 00 A0 02 AA 00 ...@............
40000000000E27A0 10 00 00 00 01 00 00 48 05 80 03 80 08 00 84 00 .......H........
40000000000E27B0 09 00 00 00 01 00 50 C2 3C 00 42 00 00 00 04 00 ......P.<.B.....
40000000000E27C0 11 68 01 4A 18 10 00 00 00 02 00 00 08 8F F3 58 .h.J...........X
40000000000E27D0 11 08 00 56 00 21 D0 0A 20 00 42 00 F8 64 00 50 ...V.!.. .B..d.P
40000000000E27E0 08 08 00 56 00 21 00 00 00 02 00 A0 05 40 00 84 ...V.!.......@..
40000000000E27F0 19 70 01 4A 18 10 00 00 00 02 00 00 98 89 F3 58 .p.J...........X
40000000000E2800 09 70 00 10 00 10 10 00 AC 00 42 E0 11 40 00 84 .p........B..@..
40000000000E2810 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
40000000000E2820 11 30 00 1C 87 39 00 00 00 02 00 03 B0 00 00 43 .0...9.........C
40000000000E2830 11 30 80 1C 87 39 00 00 00 02 00 03 00 01 00 43 .0...9.........C
40000000000E2840 11 30 24 1C 87 39 00 00 00 02 00 03 F0 00 00 43 .0$..9.........C
40000000000E2850 11 00 00 00 01 00 60 50 38 0E 73 03 E0 00 00 43 ......`P8.s....C
40000000000E2860 09 80 00 1E 00 21 E0 08 3C 00 28 00 00 00 04 00 .....!..<.(.....
40000000000E2870 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
40000000000E2880 11 30 00 1C 87 39 00 00 00 02 00 03 50 00 00 43 .0...9......P..C
40000000000E2890 11 30 80 1C 87 39 00 00 00 02 00 03 30 00 00 43 .0...9......0..C
40000000000E28A0 11 30 24 1C 87 39 00 00 00 02 00 03 20 00 00 43 .0$..9...... ..C
40000000000E28B0 10 00 00 00 01 00 70 50 38 0C 73 03 B0 FF FF 4A ......pP8.s....J
40000000000E28C0 08 00 00 20 80 11 00 00 00 02 00 00 00 00 04 00 ... ............
40000000000E28D0 08 00 00 00 01 00 E0 00 9C 20 20 40 84 17 FD 8C .........  @....
40000000000E28E0 0A 78 00 50 18 10 00 00 00 02 00 00 02 70 58 00 .x.P.........pX.
40000000000E28F0 09 70 04 1C 00 21 00 00 00 02 00 E0 40 12 19 E0 .p...!......@...
40000000000E2900 02 78 40 1E 12 20 00 00 00 02 00 00 00 00 04 00 .x@.. ..........
40000000000E2910 18 00 20 1E 98 11 00 70 9C 20 23 03 F0 FD FF 4A .. ....p. #....J
40000000000E2920 10 00 00 00 01 00 00 00 00 02 00 00 60 FE FF 48 ............`..H
40000000000E2930 09 00 00 00 01 00 00 01 20 00 42 00 00 00 04 00 ........ .B.....
40000000000E2940 11 00 00 20 80 11 00 00 00 02 00 00 90 FF FF 48 ... ...........H
40000000000E2950 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2960 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2970 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2980 0B 80 08 04 80 05 10 0A 00 00 48 00 00 00 04 00 ..........H.....
40000000000E2990 11 10 08 00 80 05 00 00 00 02 00 00 78 FC FF 48 ............x..H
40000000000E29A0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000E29B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E29C0 0B 80 08 04 80 05 10 02 00 00 42 00 00 00 04 00 ..........B.....
40000000000E29D0 11 10 08 00 80 05 00 00 00 02 00 00 38 FC FF 48 ............8..H
40000000000E29E0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000E29F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2A00 0B 80 08 04 80 05 10 FA F3 FF 4F 00 00 00 04 00 ..........O.....
40000000000E2A10 11 10 08 00 80 05 00 00 00 02 00 00 F8 FB FF 48 ...............H
40000000000E2A20 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000E2A30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2A40 01 20 1D 0C 80 05 30 02 00 62 00 A0 04 08 00 84 . ....0..b......
40000000000E2A50 11 30 01 00 00 21 00 00 00 02 00 00 F8 C0 04 50 .0...!.........P
40000000000E2A60 09 08 00 4A 00 21 10 02 20 00 42 40 04 40 00 84 ...J.!.. .B@.@..
40000000000E2A70 0B 30 11 FA 5F 27 00 00 00 02 00 00 00 00 04 00 .0.._'..........
40000000000E2A80 11 60 98 42 98 15 00 00 00 02 00 00 C8 D7 04 50 .`.B...........P
40000000000E2A90 18 70 00 40 10 10 00 40 84 20 23 00 00 00 00 20 .p.@...@. #.... 
40000000000E2AA0 09 08 00 4A 00 21 80 00 00 00 42 00 40 02 AA 00 ...J.!....B.@...
40000000000E2AB0 09 70 40 1C 2E 20 00 00 00 02 00 00 30 0A 00 07 .p@.. ......0...
40000000000E2AC0 09 00 00 00 01 00 00 71 80 20 2B 00 00 00 04 00 .......q. +.....
40000000000E2AD0 11 00 88 40 98 11 00 00 00 02 00 80 08 00 84 00 ...@............
40000000000E2AE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2AF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2B00 01 20 1D 0C 80 05 30 02 00 62 00 A0 04 08 00 84 . ....0..b......
40000000000E2B10 11 30 01 00 00 21 00 00 00 02 00 00 38 C0 04 50 .0...!......8..P
40000000000E2B20 11 10 01 10 00 21 10 00 94 00 42 00 28 0F 03 50 .....!....B.(..P
40000000000E2B30 09 08 01 44 00 21 10 00 94 00 42 C0 04 40 00 84 ...D.!....B..@..
40000000000E2B40 11 60 20 42 98 15 00 00 00 02 00 00 08 D7 04 50 .` B...........P
40000000000E2B50 08 00 00 00 01 00 E0 00 80 20 20 E0 01 01 01 84 .........  .....
40000000000E2B60 09 00 20 42 90 11 10 00 94 00 42 00 01 00 00 84 .. B......B.....
40000000000E2B70 09 70 80 1C 2E 20 00 10 3D 30 23 00 40 02 AA 00 .p... ..=0#.@...
40000000000E2B80 11 00 38 40 90 11 00 18 05 80 03 80 08 00 84 00 ..8@............
40000000000E2B90 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2BA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2BB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2BC0 01 20 1D 0C 80 05 30 02 00 62 00 A0 04 08 00 84 . ....0..b......
40000000000E2BD0 11 30 01 00 00 21 00 00 00 02 00 00 78 BF 04 50 .0...!......x..P
40000000000E2BE0 11 10 01 10 00 21 10 00 94 00 42 00 68 66 02 50 .....!....B.hf.P
40000000000E2BF0 09 08 01 44 00 21 10 00 94 00 42 C0 04 40 00 84 ...D.!....B..@..
40000000000E2C00 11 60 20 42 98 15 00 00 00 02 00 00 48 D6 04 50 .` B........H..P
40000000000E2C10 08 00 00 00 01 00 E0 00 80 20 20 E0 01 01 01 84 .........  .....
40000000000E2C20 09 00 20 42 90 11 10 00 94 00 42 00 01 00 00 84 .. B......B.....
40000000000E2C30 09 70 80 1C 2E 20 00 10 3D 30 23 00 40 02 AA 00 .p... ..=0#.@...
40000000000E2C40 11 00 38 40 90 11 00 18 05 80 03 80 08 00 84 00 ..8@............
40000000000E2C50 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2C60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2C70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2C80 01 18 19 0A 80 05 20 02 00 62 00 80 04 08 00 84 ...... ..b......
40000000000E2C90 11 28 01 00 00 21 00 00 00 02 00 00 B8 BE 04 50 .(...!.........P
40000000000E2CA0 11 08 00 48 00 21 10 02 20 00 42 00 A8 40 FF 58 ...H.!.. .B..@.X
40000000000E2CB0 08 30 00 10 07 39 00 00 00 02 00 20 00 20 01 84 .0...9..... . ..
40000000000E2CC0 09 00 20 42 98 11 00 00 00 02 00 A0 04 40 00 84 .. B.........@..
40000000000E2CD0 D1 70 00 00 00 21 00 00 00 02 00 03 30 00 00 43 .p...!......0..C
40000000000E2CE0 11 00 00 00 01 00 00 00 00 02 00 00 68 D5 04 50 ............h..P
40000000000E2CF0 08 00 00 00 01 00 10 00 90 00 42 C0 01 40 00 84 ..........B..@..
40000000000E2D00 08 78 00 40 10 10 20 61 84 00 42 00 30 02 AA 00 .x.@.. a..B.0...
40000000000E2D10 09 88 20 42 00 21 00 81 80 00 42 00 01 00 00 84 .. B.!....B.....
40000000000E2D20 18 78 C0 1E 2E 20 00 70 48 20 23 00 00 00 00 20 .x... .pH #.... 
40000000000E2D30 02 00 38 22 90 11 00 10 05 80 03 00 00 00 04 00 ..8"............
40000000000E2D40 19 00 84 20 98 11 00 78 80 20 23 80 08 00 84 00 ... ...x. #.....
40000000000E2D50 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2D60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2D70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E2D80 01 20 1D 0C 80 05 30 02 00 62 00 A0 04 08 00 84 . ....0..b......
40000000000E2D90 11 00 00 00 01 00 00 00 00 02 00 00 B8 7B F3 58 .............{.X
40000000000E2DA0 08 08 00 4A 00 21 00 00 00 02 00 40 04 40 00 84 ...J.!.....@.@..
40000000000E2DB0 19 30 01 00 00 21 00 00 00 02 00 00 98 BD 04 50 .0...!.........P
40000000000E2DC0 08 70 00 10 00 21 10 02 20 00 42 20 00 28 01 84 .p...!.. .B .(..
40000000000E2DD0 0B 30 01 44 00 21 80 10 39 30 2B 00 00 00 04 00 .0.D.!..90+.....
40000000000E2DE0 11 00 00 1C 90 11 00 00 00 02 00 00 68 D4 04 50 ............h..P
40000000000E2DF0 18 70 00 40 10 10 F0 60 84 00 42 00 00 00 00 20 .p.@...`..B.... 
40000000000E2E00 09 08 00 4A 00 21 00 00 00 02 00 00 40 02 AA 00 ...J.!......@...
40000000000E2E10 08 70 80 1C 2E 20 00 40 3C 20 23 00 30 0A 00 07 .p... .@< #.0...
40000000000E2E20 0B 40 00 00 00 21 00 71 80 20 2B 00 00 00 04 00 .@...!.q. +.....
40000000000E2E30 11 00 84 40 98 11 00 00 00 02 00 80 08 00 84 00 ...@............
40000000000E2E40 01 48 35 16 80 05 80 02 00 62 00 40 05 08 00 84 .H5......b.@....
40000000000E2E50 11 18 01 00 00 21 00 00 00 02 00 00 F8 6A FD 58 .....!.......j.X
40000000000E2E60 08 20 21 10 00 21 10 00 A8 00 42 00 00 00 04 00 . !..!....B.....
40000000000E2E70 19 30 00 10 07 39 20 02 20 00 42 03 30 02 00 43 .0...9 . .B.0..C
40000000000E2E80 09 70 00 48 00 21 F0 00 20 30 20 00 00 00 04 00 .p.H.!.. 0 .....
40000000000E2E90 11 00 00 00 01 00 70 00 3C 0C F2 03 90 01 00 43 ......p.<......C
40000000000E2EA0 09 30 39 44 05 20 F0 40 38 30 28 60 14 18 01 84 .09D. .@80(`....
40000000000E2EB0 10 00 00 00 01 00 70 00 3C 0C 72 03 F0 FF FF 4A ......p.<.r....J
40000000000E2EC0 08 38 FD 47 3F 23 00 00 00 02 00 60 15 18 01 84 .8.G?#.....`....
40000000000E2ED0 19 08 01 44 00 21 00 00 00 02 00 00 78 BC 04 50 ...D.!......x..P
40000000000E2EE0 08 38 9D 00 08 20 10 00 A8 00 42 00 00 00 04 00 .8... ....B.....
40000000000E2EF0 03 28 01 10 00 21 00 00 00 02 00 E0 74 22 49 80 .(...!......t"I.
40000000000E2F00 08 00 00 00 01 00 E0 00 84 30 20 80 14 12 15 80 .........0 .....
40000000000E2F10 0B 78 00 4A 18 10 40 7A 90 00 40 00 00 00 04 00 .x.J..@z..@.....
40000000000E2F20 0B 70 00 1C 18 10 60 00 38 0E 72 60 05 70 00 84 .p....`.8.r`.p..
40000000000E2F30 D1 40 00 00 00 21 00 00 00 02 00 03 60 00 00 43 .@...!......`..C
40000000000E2F40 11 00 00 00 01 00 00 00 00 02 00 00 88 87 F3 58 ...............X
40000000000E2F50 11 08 00 54 00 21 B0 0A 20 00 42 00 78 5D 00 50 ...T.!.. .B.x].P
40000000000E2F60 09 70 00 42 18 10 10 00 A8 00 42 60 05 40 00 84 .p.B......B`.@..
40000000000E2F70 13 60 01 1C 18 10 00 0C C1 79 2C 00 00 00 00 20 .`.......y,.... 
40000000000E2F80 08 08 00 54 00 21 00 00 00 02 00 00 00 00 04 00 ...T.!..........
40000000000E2F90 09 08 21 42 00 21 00 40 90 30 23 00 00 00 04 00 ..!B.!.@.0#.....
40000000000E2FA0 10 00 00 00 01 00 70 38 85 0C 70 03 60 FF FF 4A ......p8..p.`..J
40000000000E2FB0 08 70 00 4A 00 21 F0 40 94 00 42 00 04 01 01 84 .p.J.!.@..B.....
40000000000E2FC0 0B 40 04 00 00 24 00 61 38 30 28 00 00 00 04 00 .@...$.a80(.....
40000000000E2FD0 09 00 00 00 01 00 60 82 98 00 40 00 00 00 04 00 ......`...@.....
40000000000E2FE0 09 00 00 4C 98 11 00 18 39 20 23 00 00 00 04 00 ...L....9 #.....
40000000000E2FF0 08 00 8C 1E 90 11 00 28 81 30 23 00 00 00 04 00 .......(.0#.....
40000000000E3000 01 00 00 00 01 00 00 48 01 55 00 00 00 00 04 00 .......H.U......
40000000000E3010 11 00 00 00 01 00 00 40 05 80 03 80 08 00 84 00 .......@........
40000000000E3020 08 58 05 00 00 24 60 02 00 00 42 00 00 00 04 00 .X...$`...B.....
40000000000E3030 19 18 01 00 00 21 00 82 80 00 42 00 18 BB 04 50 .....!....B....P
40000000000E3040 09 28 01 10 00 21 10 00 A8 00 42 00 11 00 00 90 .(...!....B.....
40000000000E3050 09 70 00 4A 00 21 00 00 00 02 00 E0 81 28 01 84 .p.J.!.......(..
40000000000E3060 0B 80 30 1C 18 14 60 82 98 00 40 00 00 00 04 00 ..0...`...@.....
40000000000E3070 09 00 00 4C 98 11 00 18 39 20 23 00 00 00 04 00 ...L....9 #.....
40000000000E3080 08 00 00 00 01 00 00 18 3D 20 23 00 00 00 04 00 ........= #.....
40000000000E3090 18 00 94 40 98 11 00 00 00 02 00 00 70 FF FF 48 ...@........p..H
40000000000E30A0 09 00 41 40 00 21 80 00 00 00 42 00 90 02 AA 00 ..A@.!....B.....
40000000000E30B0 11 00 00 40 98 11 00 40 05 80 03 80 08 00 84 00 ...@...@........

;; fn40000000000E30C0: 40000000000E30C0
;;   Called from:
;;     40000000000E62DC (in gen_compspec_completions)
;;     40000000000E685C (in gen_compspec_completions)
;;     40000000000E741C (in gen_compspec_completions)
fn40000000000E30C0 proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; addl	r36,-612,r1; mov	r33,b1 }
	{ nop.m	0x0; adds	r35,0x0,r1; nop.i	0x0; }
	{ ld8	r36,[r36]; nop.i	0x0; br.call.sptk.many	b0,unbind_variable; }
	{ adds	r1,0x0,r35; addl	r36,-604,r1; nop.i	0x0; }
	{ ld8	r36,[r36]; nop.i	0x0; br.call.sptk.many	b0,unbind_variable; }
	{ adds	r1,0x0,r35; addl	r36,-596,r1; nop.i	0x0; }
	{ ld8	r36,[r36]; nop.i	0x0; br.call.sptk.many	b0,unbind_variable; }
	{ adds	r1,0x0,r35; addl	r36,-588,r1; nop.i	0x0; }
	{ ld8	r36,[r36]; nop.i	0x0; br.call.sptk.many	b0,unbind_variable; }
	{ adds	r1,0x0,r35; addl	r36,-580,r1; nop.i	0x0; }
	{ ld8	r36,[r36]; nop.i	0x0; br.call.sptk.many	b0,unbind_variable; }
	{ adds	r1,0x0,r35; addl	r36,-572,r1; nop.i	0x0; }
	{ ld8	r36,[r36]; nop.i	0x0; br.call.sptk.many	b0,unbind_variable; }
	{ cmp4.eq	p06,p07,0x0,r32; adds	r1,0x0,r35; mov.i	ar.pfs,r34; }
	{ (p07) addl	r14,5780,r1; (p07) addl	r15,1,r0; mov.spnt	b0,r33,40000000000E31A0; }

l40000000000E31A6:
	{ Invalid; nop; break.b	0x80000; }

l40000000000E31AC:
	{ (p16) nop; break.i	0x1000; break.b	0x1000 }
	{ Invalid; Invalid; add	r0,r32,r0 }

l40000000000E31C6:
	{ break.m	0x4000; (p34) nop; break.i	0x80000 }
40000000000E31D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E31E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E31F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000E3200: 40000000000E3200
;;   Called from:
;;     40000000000E615C (in gen_compspec_completions)
;;     40000000000E645C (in gen_compspec_completions)
fn40000000000E3200 proc
	{ alloc	r39,ar.pfs,0xD,0x0,0xA; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r41,pr }
	{ addl	r42,-612,r1; adds	r40,0x0,r1; cmp4.eq	p17,p16,0x0,r36; }
	{ nop.m	0x0; mov	r38,b6; nop.b	0x0 }
	{ ld8	r42,[r42]; adds	r43,0x0,r32; adds	r44,0x0,r0; }
	{ (p16) addl	r37,1,r0; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }

l40000000000E3246:
	{ break.m	0x4000; (p32) nop; (p48) shr.u	r1,r66,r0 }
	{ Invalid; Invalid; Invalid }

l40000000000E325C:
	{ (p06) nop; (p05) nop; }
	{ cmp4.eq.and	p33,p11,r22,r0; (p01) nop; }

l40000000000E3276:
	{ Invalid; nop; (p32) nop; }

l40000000000E327C:
	{ cmp.lt	p00,p11,r1,r0; (p33) cmp.lt	p35,p16,r9,r3; czx1.r	r64,r97 }
	{ Invalid; (p01) cmp4.eq.and	p10,p48,r2,r64; Invalid }

l40000000000E3296:
	{ (p07) fwb; nop; cmp.lt	p00,p00,r0,r32; }

l40000000000E329C:
	{ nop; cmp4.eq.and	p00,p32,r32,r0; zxt1	r64,r11 }

l40000000000E32AC:
	{ Invalid; Invalid; break.i	0x1000 }

l40000000000E32B6:
	{ break.m	0x4000; Invalid; (p16) nop }
	{ Invalid; (p21) nop; (p32) br.call.sptk.few	b2,b0 }
	{ break.m	0x4000; (p32) nop; (p48) nop }
	{ add	r0,r0,r1; mov.sptk	b0,r40,40000000000E33E6; nop }
	{ (p21) chk.a.clr	r16,3FFFFFFFFF1633B6; (p07) cmp4.eq.or	p01,p08,0x0,r0; (p33) nop.b	0x3 }

l40000000000E3300:
	{ (p07) adds	r14,0x0,r0; and	r14,r14,r37; nop.i	0x0; }

l40000000000E3306:
	{ Invalid; nop; (p32) nop }
	{ Invalid; nop; cmp.lt	p00,p00,r0,r32; }

l40000000000E331C:
	{ nop; cmp4.eq.and	p00,p32,r32,r0; Invalid }

l40000000000E332C:
	{ cmp4.eq.and	p00,p43,r1,r0; (p17) mov	pr,r67,0x8080; (p32) cmp.lt	p03,p08,r2,r100 }

l40000000000E3336:
	{ mf.a; (p07) nop; (p32) nop; }

l40000000000E333C:
	{ (p22) cmp.lt.unc	p61,p11,r46,r79; (p01) dep	r64,r3,r6,63,9; Invalid; }
	{ Invalid; dep	r0,r32,r0,63,1; (p05) break.i	0x16540 }
	{ (p55) nop; ldfs	f0,[r64]; (p05) br.cond.sptk.few	400000000050337C }
	{ (p22) cmpxchg4.acq	r125,[r79],r123; break.x	0x80C2A00A01000; }
	{ (p34) cmp.eq	p10,p08,r62,r44; flushrs; nop.b	0x1000 }
	{ nop; (p05) shladd	r4,r3,0x1,r64; (p05) cmp4.eq.and	p03,p18,r0,r0 }
	{ cmp4.eq.and	p00,p43,r0,r72; (p01) cmp.lt	p00,p16,r0,r64; (p33) epc; }

l40000000000E33A0:
	{ (p07) adds	r14,0x0,r0; and	r14,r14,r37; nop.i	0x0; }

l40000000000E33A6:
	{ Invalid; nop; (p32) nop }
	{ Invalid; nop; cmp.lt	p00,p00,r0,r32; }

l40000000000E33BC:
	{ nop; cmp4.eq.and	p00,p32,r32,r0; Invalid }

l40000000000E33CC:
	{ cmp4.eq.and	p00,p43,r1,r0; (p17) mov	pr,r67,0x8080; (p32) cmp.lt	p03,p08,r2,r100 }

l40000000000E33D6:
	{ mf.a; (p07) nop; (p32) nop; }

l40000000000E33DC:
	{ (p26) cmp.lt.unc	p61,p11,r47,r79; (p01) dep	r64,r3,r6,63,9; Invalid; }
	{ Invalid; dep	r0,r32,r0,63,1; (p05) break.i	0x16540 }
	{ (p50) nop; ldfs	f0,[r64]; (p05) br.cond.sptk.few	400000000050341C }
	{ (p26) cmpxchg4.acq	r125,[r79],r123; break.x	0x80C2A00A01000; }
	{ (p29) cmp.eq	p10,p03,r62,r44; nop; Invalid }
	{ cmp4.eq.and	p00,p43,r0,r72; (p01) nop; (p36) epc; }

l40000000000E3430:
	{ (p07) adds	r14,0x0,r0; and	r37,r14,r37; nop.i	0x0; }

l40000000000E3436:
	{ Invalid; nop; break.b	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFDA6E96; nop; nop }

l40000000000E3450:
	{ adds	r8,0x28,r8; ld4	r14,[r8]; nop.i	0x0; }
	{ nop.m	0x0; or	r14,0x1,r14; nop.i	0x0; }
	{ st4	[r14],r8; nop.m	0x0; nop.i	0x0 }

l40000000000E3480:
	{ addl	r14,5780,r1; nop.m	0x0; addl	r15,1,r0; }
	{ nop.m	0x0; st4	[r15],r14; mov	pr,r41,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r39; mov.spnt	b0,r38,40000000000E34A0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000E34C0:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dptk.few	40000000000E3480 }

l40000000000E34D0:
	{ nop.m	0x0; addl	r42,-580,r1; nop.i	0x0; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r15,0x28,r8; nop.m	0x0; adds	r1,0x0,r40 }
	{ cmp.eq	p07,p06,0x0,r8; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000E36B0; }

l40000000000E3510:
	{ nop.m	0x0; ld4	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x1; (p07) and	r16,0xFFFFFFFFFFFFFFFD,r14; }

l40000000000E3530:
	{ (p07) adds	r14,0x0,r16; (p07) st4	[r16],r15; nop.i	0x0; }

l40000000000E3536:
	{ mf.a; nop; break.i	0x80000; }

l40000000000E353C:
	{ invala; cmp.eq	p00,p00,r32,r0; mov	pr,r67,0x5082 }
	{ (p06) ld2	r0,[r33]; zxt1	r0,r64; nop }

l40000000000E3550:
	{ adds	r42,0x0,r8; nop.m	0x0; adds	r43,0x0,r34 }
	{ adds	r44,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,assign_array_var_from_word_list; }
	{ adds	r8,0x28,r8; addl	r15,-4097,r0; adds	r1,0x0,r40 }
	{ adds	r43,0x10,r12; addl	r44,12,r0; sxt4	r42,r35; }
	{ ld4	r14,[r8]; and	r14,r15,r14; nop.i	0x0; }
	{ st4	[r14],r8; nop.i	0x0; br.call.sptk.many	b0,inttostr; }
	{ adds	r1,0x0,r40; adds	r43,0x0,r8; addl	r42,-572,r1; }
	{ ld8	r42,[r42]; br.call.sptk.many	b0,bind_int_variable; nop.b	0x0; }
	{ adds	r1,0x0,r40; nop.m	0x0; nop.i	0x0 }

l40000000000E35E0:
	{ nop.m	0x0; mov	pr,r41,0xFFFFFFFFFFFFFFFE; nop.i	0x0; }
	{ nop.m	0x0; mov.i	ar.pfs,r39; mov.spnt	b0,r38,40000000000E35F0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000000E3610:
	{ adds	r42,0x0,r8; nop.i	0x0; br.call.sptk.many	b0,convert_var_to_array; }
	{ adds	r1,0x0,r40; adds	r43,0x0,r34; nop.i	0x0 }
	{ adds	r42,0x0,r8; adds	r44,0x0,r0; br.call.sptk.many	b0,assign_array_var_from_word_list; }
	{ adds	r8,0x28,r8; addl	r15,-4097,r0; adds	r1,0x0,r40 }
	{ adds	r43,0x10,r12; addl	r44,12,r0; sxt4	r42,r35; }
	{ ld4	r14,[r8]; and	r14,r15,r14; nop.i	0x0; }
	{ st4	[r14],r8; nop.i	0x0; br.call.sptk.many	b0,inttostr; }
	{ adds	r1,0x0,r40; adds	r43,0x0,r8; addl	r42,-572,r1; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,bind_int_variable; }
	{ nop.m	0x0; adds	r1,0x0,r40; br.cond.sptk.few	40000000000E35E0; }

l40000000000E36B0:
	{ nop.m	0x0; addl	r42,-580,r1; nop.i	0x0; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,make_new_array_variable; }
	{ adds	r15,0x28,r8; nop.m	0x0; adds	r1,0x0,r40; }
	{ nop.m	0x0; ld4	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x1; (p07) and	r16,0xFFFFFFFFFFFFFFFD,r14; }

l40000000000E3700:
	{ (p07) adds	r14,0x0,r16; (p07) st4	[r16],r15; nop.i	0x0; }

l40000000000E3706:
	{ mf.a; nop; break.i	0x80000; }

l40000000000E370C:
	{ invala; cmp.eq	p00,p00,r32,r0; mov	pr,r67,0x5082 }
	{ Invalid; break.i	0x1000; break.i	0x1000 }

l40000000000E3720:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E3610; }
40000000000E3730 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000E3740: 40000000000E3740
;;   Called from:
;;     40000000000E617C (in gen_compspec_completions)
;;     40000000000E648C (in gen_compspec_completions)
fn40000000000E3740 proc
	{ alloc	r40,ar.pfs,0xD,0x0,0xB; nop.m	0x0; mov	r39,b7 }
	{ adds	r41,0x0,r1; nop.m	0x0; adds	r43,0x0,r32; }
	{ nop.m	0x0; mov	r42,LC; br.call.sptk.many	b0,make_word; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r43,0x0,r8 }
	{ adds	r44,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,make_word_list; }
	{ adds	r14,0x8,r34; adds	r1,0x0,r41; nop.i	0x0 }
	{ adds	r36,0x0,r8; cmp.eq	p06,p07,0x0,r34; (p06) br.cond.dpnt.few	40000000000E3940; }

l40000000000E37B0:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; adds	r43,0x0,r14; (p06) br.cond.dpnt.few	40000000000E3A50; }

l40000000000E37D0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,copy_word; }

l40000000000E37E0:
	{ adds	r44,0x0,r0; nop.m	0x0; adds	r1,0x0,r41 }
	{ adds	r43,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,make_word_list; }
	{ adds	r1,0x0,r41; adds	r38,0x0,r8; nop.i	0x0 }
	{ adds	r43,0x0,r33; st8	[r8],r36; br.call.sptk.many	b0,make_word; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r43,0x0,r8 }
	{ adds	r44,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,make_word_list; }
	{ adds	r15,0xFFFFFFFFFFFFFFFD,r35; adds	r14,0x0,r34; adds	r35,0xFFFFFFFFFFFFFFFF,r35 }
	{ adds	r1,0x0,r41; st8	[r8],r38; adds	r37,0x0,r8; }
	{ nop.m	0x0; addp4	r15,r15,r0; cmp4.lt	p07,p06,0x1,r35 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000E3A80; }

l40000000000E3880:
	{ nop.m	0x0; mov.i	LC,r15; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000E38A0:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	40000000000E39E0; br.cloop.sptk.few	40000000000E38A0 }

l40000000000E38BC:
	{ (p63) cmp.lt.unc	p63,p11,r63,r36; (p01) nop; (p05) rfi }

l40000000000E38C0:
	{ adds	r14,0x8,r14; ld8	r43,[r14]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r43; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000E39E0; }

l40000000000E38E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,copy_word; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r43,0x0,r8 }
	{ adds	r44,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,make_word_list; }
	{ adds	r1,0x0,r41; st8	[r8],r37; mov.i	ar.pfs,r40 }
	{ adds	r8,0x0,r36; nop.m	0x0; mov.i	LC,r42; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000E3930; br.ret	b0 }

l40000000000E3940:
	{ nop.m	0x0; addl	r43,-564,r1; nop.i	0x0; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,make_word; }
	{ adds	r44,0x0,r0; nop.m	0x0; adds	r1,0x0,r41 }
	{ adds	r43,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,make_word_list; }
	{ adds	r1,0x0,r41; adds	r38,0x0,r8; nop.i	0x0 }
	{ adds	r43,0x0,r33; st8	[r8],r36; br.call.sptk.many	b0,make_word; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r43,0x0,r8 }
	{ adds	r44,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,make_word_list; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r37,0x0,r8 }
	{ st8	[r8],r38; nop.m	0x0; nop.i	0x0; }

l40000000000E39E0:
	{ nop.m	0x0; addl	r43,-564,r1; nop.i	0x0; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,make_word; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r43,0x0,r8 }
	{ adds	r44,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,make_word_list; }
	{ adds	r1,0x0,r41; st8	[r8],r37; mov.i	ar.pfs,r40 }
	{ adds	r8,0x0,r36; nop.m	0x0; mov.i	LC,r42; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000E3A40; br.ret	b0 }

l40000000000E3A50:
	{ nop.m	0x0; addl	r43,-564,r1; nop.i	0x0; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,make_word; }
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E37E0 }

l40000000000E3A80:
	{ nop.m	0x0; adds	r14,0x0,r34; br.cond.sptk.few	40000000000E38C0; }
40000000000E3A90 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E3AA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E3AB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E3AC0 18 20 21 0C 80 05 20 E2 07 80 48 00 00 00 00 20 . !... ...H.... 
40000000000E3AD0 09 30 00 42 87 39 50 02 04 00 42 60 04 00 C4 00 .0.B.9P...B`....
40000000000E3AE0 09 00 00 00 01 C0 E1 00 88 00 42 00 00 00 04 00 ..........B.....
40000000000E3AF0 F1 30 01 1C 18 10 00 00 00 02 80 03 00 01 00 43 .0.............C
40000000000E3B00 09 00 00 00 01 00 60 02 88 30 20 00 00 00 04 00 ......`..0 .....
40000000000E3B10 11 30 00 4C 07 39 00 00 00 02 00 03 30 00 00 43 .0.L.9......0..C
40000000000E3B20 11 00 00 00 01 00 00 00 00 02 00 00 C8 6C F3 58 .............l.X
40000000000E3B30 09 08 00 4A 00 21 00 00 00 02 00 00 00 00 04 00 ...J.!..........
40000000000E3B40 09 70 70 FB AE 27 00 00 00 02 00 C0 04 00 01 84 .pp..'..........
40000000000E3B50 0B 70 00 1C 18 10 E0 00 38 20 20 00 00 00 04 00 .p......8  .....
40000000000E3B60 00 00 00 00 01 00 60 E0 38 0E 28 C0 C1 EB C3 9E ......`.8.(.....
40000000000E3B70 19 00 00 00 01 00 00 00 00 02 00 03 B0 00 00 43 ...............C
40000000000E3B80 0B 70 00 1C 18 10 80 00 38 30 20 C0 41 EB B7 9E .p......80 .A...
40000000000E3B90 11 30 00 10 07 39 00 00 00 02 00 03 90 00 00 43 .0...9.........C
40000000000E3BA0 09 00 00 00 01 00 E0 00 38 30 20 00 00 00 04 00 ........80 .....
40000000000E3BB0 09 38 01 1C 10 10 E0 40 20 30 28 00 00 00 04 00 .8.....@ 0(.....
40000000000E3BC0 11 08 00 10 18 10 60 70 04 80 03 00 68 00 80 10 ......`p....h...
40000000000E3BD0 08 08 00 4A 00 21 00 00 00 02 00 C0 04 40 00 84 ...J.!.......@..
40000000000E3BE0 08 00 20 44 98 11 00 00 00 02 00 00 00 00 04 00 .. D............
40000000000E3BF0 11 38 01 42 00 21 00 00 00 02 00 00 98 70 F3 58 .8.B.!.......p.X
40000000000E3C00 09 08 00 4A 00 21 00 00 00 02 00 00 40 02 AA 00 ...J.!......@...
40000000000E3C10 11 00 00 00 01 00 00 18 05 80 03 80 08 00 84 00 ................
40000000000E3C20 11 00 00 00 01 00 00 00 00 02 00 00 A8 7A F3 58 .............z.X
40000000000E3C30 11 08 00 4A 00 21 60 0A 20 00 42 00 98 50 00 50 ...J.!`. .B..P.P
40000000000E3C40 08 08 00 4A 00 21 00 00 00 02 00 E0 04 00 01 84 ...J.!..........
40000000000E3C50 19 30 01 10 00 21 00 00 00 02 00 00 38 75 F3 58 .0...!......8u.X
40000000000E3C60 08 00 00 00 01 00 10 00 94 00 42 C0 04 40 00 84 ..........B..@..
40000000000E3C70 19 00 20 44 98 11 70 02 84 00 42 00 18 70 F3 58 .. D..p...B..p.X
40000000000E3C80 09 08 00 4A 00 21 00 00 00 02 00 00 40 02 AA 00 ...J.!......@...
40000000000E3C90 11 00 00 00 01 00 00 18 05 80 03 80 08 00 84 00 ................
40000000000E3CA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E3CB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; set_itemlist_dirty: 40000000000E3CC0
;;   Called from:
;;     400000000006498C (in bind_function)
;;     4000000000064DEC (in unbind_func)
;;     40000000000B96DC (in add_alias)
;;     40000000000B97CC (in remove_alias)
;;     40000000000B98DC (in delete_all_aliases)
;;     40000000000F315C (in enable_builtin)
;;     40000000000F388C (in enable_builtin)
;;     40000000000F3B4C (in enable_builtin)
;;     40000000000F3D2C (in enable_builtin)
;;     40000000000F3D46 (in enable_builtin)
;;     40000000000F3DFC (in enable_builtin)
;;     40000000000F3E1C (in enable_builtin)
;;     40000000000F401C (in enable_builtin)
set_itemlist_dirty proc
	{ ld4	r14,[r32]; or	r14,0x2,r14; nop.i	0x0; }
	{ st4	[r14],r32; nop.i	0x0; br.ret	b0; }
40000000000E3CE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E3CF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; initialize_itemlist: 40000000000E3D00
initialize_itemlist proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; adds	r14,0x8,r32; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; adds	r36,0x0,r32; }
	{ ld8	r8,[r14]; ld8	r14,[r8],8; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r14,40000000000E3D30; nop.i	0x0 }
	{ ld8	r1,[r8]; nop.m	0x0; br.call.sptk.many	b0,b6; }
	{ ld4	r14,[r32]; adds	r1,0x0,r35; mov.i	ar.pfs,r34; }
	{ and	r14,0xFFFFFFFFFFFFFFFD,r14; mov.spnt	b0,r33,40000000000E3D60; or	r14,0x4,r14; }
	{ st4	[r14],r32; nop.i	0x0; br.ret	b0; }

;; clean_itemlist: 40000000000E3D80
;;   Called from:
;;     40000000000E436C (in fn40000000000E3EC0)
clean_itemlist proc
	{ alloc	r36,ar.pfs,0x7,0x0,0x6; adds	r34,0x10,r32; mov	r35,b3 }
	{ adds	r37,0x0,r1; ld8	r33,[r34]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r33; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E3E00; }

l40000000000E3DB0:
	{ ld4	r14,[r32]; and	r15,0x30,r14; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r15; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000E3E60; }

l40000000000E3DD0:
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x4; (p07) br.cond.dpnt.few	40000000000E3E30 }

l40000000000E3DE0:
	{ nop.m	0x0; adds	r38,0x0,r33; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r37; nop.m	0x0; nop.i	0x0 }

l40000000000E3E00:
	{ ld4	r14,[r32]; st8	[r0],r34; mov.i	ar.pfs,r36; }
	{ and	r14,0xFFFFFFFFFFFFFFC9,r14; nop.m	0x0; mov.spnt	b0,r35,40000000000E3E10; }
	{ st4	[r14],r32; nop.i	0x0; br.ret	b0; }

l40000000000E3E30:
	{ ld8	r38,[r33]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r37; adds	r38,0x0,r33; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r37; br.cond.sptk.few	40000000000E3E00 }

l40000000000E3E60:
	{ ld8	r38,[r33]; nop.i	0x0; br.call.sptk.many	b0,strvec_flush; }
	{ ld4	r14,[r32]; nop.m	0x0; adds	r1,0x0,r37; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x4; (p06) br.cond.dptk.few	40000000000E3DE0 }

l40000000000E3E90:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E3E30; }
40000000000E3EA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E3EB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000E3EC0: 40000000000E3EC0
;;   Called from:
;;     40000000000E513C (in fn40000000000E4B40)
;;     40000000000E51CC (in fn40000000000E4B40)
;;     40000000000E525C (in fn40000000000E4B40)
;;     40000000000E52EC (in fn40000000000E4B40)
;;     40000000000E537C (in fn40000000000E4B40)
;;     40000000000E540C (in fn40000000000E4B40)
;;     40000000000E549C (in fn40000000000E4B40)
;;     40000000000E552C (in fn40000000000E4B40)
;;     40000000000E55BC (in fn40000000000E4B40)
;;     40000000000E564C (in fn40000000000E4B40)
;;     40000000000E56DC (in fn40000000000E4B40)
;;     40000000000E576C (in fn40000000000E4B40)
;;     40000000000E57FC (in fn40000000000E4B40)
;;     40000000000E588C (in fn40000000000E4B40)
;;     40000000000E591C (in fn40000000000E4B40)
;;     40000000000E59AC (in fn40000000000E4B40)
;;     40000000000E5A3C (in fn40000000000E4B40)
fn40000000000E3EC0 proc
	{ alloc	r45,ar.pfs,0x13,0x0,0x10; ld8	r14,[r32]; mov	r47,pr }
	{ adds	r46,0x0,r1; and	r14,0x7,r14; mov	r44,b4; }
	{ cmp.eq	p07,p06,0x4,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000E3F20; }

l40000000000E3EF0:
	{ ld4	r14,[r32]; and	r15,0x3,r14; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r15; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000E4360; }

l40000000000E3F10:
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x2; (p07) br.cond.dpnt.few	40000000000E42F0 }

l40000000000E3F20:
	{ nop.m	0x0; adds	r32,0x10,r32; nop.i	0x0; }
	{ ld8	r14,[r32]; cmp.eq	p06,p07,0x0,r14; adds	r14,0xC,r14; }
	{ (p06) adds	r42,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E41D0; }

l40000000000E3F46:
	{ chk.a.nc	r0,3FFFFFFFFF0E4746; nop; break.i	0x80000 }

l40000000000E3F50:
	{ nop.m	0x0; ld4	r48,[r14]; nop.i	0x0; }
	{ adds	r48,0x1,r48; nop.i	0x0; br.call.sptk.many	b0,strlist_create; }
	{ nop.m	0x0; adds	r1,0x0,r46; adds	r42,0x0,r8 }
	{ ld8	r38,[r32]; adds	r48,0x0,r33; br.call.sptk.many	b0,bash_dequote_text; }
	{ adds	r1,0x0,r46; nop.m	0x0; adds	r41,0x0,r8 }
	{ cmp.eq	p18,p19,0x0,r8; nop.m	0x0; (p18) br.cond.dpnt.few	40000000000E41F0; }

l40000000000E3FB0:
	{ ld1	r14,[r8]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000E41F0 }

l40000000000E3FD0:
	{ adds	r14,0x1,r8; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r8,1,r0; (p06) br.cond.dptk.few	40000000000E4040 }

l40000000000E3FFC:
	{ (p02) cmp.lt	p00,p11,r0,r33; (p33) cmp.lt	p32,p16,r10,r64; (p01) rfi }

l40000000000E4000:
	{ adds	r14,0x2,r41; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	40000000000E43A0; }

l40000000000E4030:
	{ (p06) addl	r8,2,r0; nop.m	0x0; nop.i	0x0; }

l40000000000E4036:
	{ break.m	0x4000; nop; (p48) nop }

l40000000000E4040:
	{ adds	r39,0xC,r38; adds	r34,0x0,r0; adds	r36,0x0,r0 }

l40000000000E4042:
	{ (p33) fwb; chk.s.i	r64,3FFFFFFFFF0EC042; br.call.sptk.few	b0,b0; }

l40000000000E4046:
	{ Invalid; (p18) nop; (p48) nop }

l40000000000E4048:
	{ sum	0x100840; mov	pr,0x1809840; chk.s.i	r16,40000000001E6048 }

l40000000000E4058:
	{ (p01) rum	0xC0E64; (p33) break.i	0x9005; Invalid }
	{ (p04) break.m	0x404; (p16) break.f	0x11000; nop }
	{ (p33) chk.a.clr	r97,3FFFFFFFFF4E4DF8; break.m	0x430; nop }
	{ (p36) break.m	0x5; Invalid; (p24) break.b	0x80C2 }
	{ (p16) chk.a.clr	r0,4000000000CE6098; nop; (p08) mov	pr,0x4010002 }
	{ (p05) break.m	0x406; Invalid; (p60) break.i	0x80C0 }
	{ Invalid; czx1.r	r4,r2; (p20) break.i	0x1C832 }
	{ (p16) nop; Invalid; break.i	0x10800 }
	{ Invalid; break.i	0x11430; break.i	0x8 }
	{ (p16) cmp4.eq.or	p00,p40,0x0,r0; Invalid; (p56) mov	pr,r16,0xFFFFFFFFFFFF0004 }
	{ (p01) nop; Invalid; Invalid }
	{ (p05) ssm	0x840; (p01) ldfd.s	f64,[r0],80; (p08) break.b	0x10002 }
	{ (p16) break.m	0x0; (p16) mov	pr,r32,0x2000; (p56) break.i	0x80C0 }
	{ (p16) cmp.eq.and	p00,p40,r0,r0; Invalid; (p56) break.i	0x10802 }
	{ (p16) break.m	0x0; (p16) break.i	0x8000; dep	r8,r0,r0,63,1 }
	{ Invalid; (p04) mov	pr,0x9809840; Invalid }
	{ Invalid; (p04) break.f	0x10840; br.call.sptk.few	b0,b0 }
	{ (p49) nop; (p63) break.m	0x24AF; nop; }
	{ Invalid; Invalid; (p40) break.b	0x10802 }
	{ (p16) nop; (p05) nop; (p56) break.i	0xA0C0 }
	{ (p16) cmp.eq	p00,p01,0x0,r112; (p01) nop; (p57) break.i	0x8C80 }
	{ (p01) break.m	0x466; (p16) break.f	0x17000; br.call.sptk.few	b0,b0 }
	{ addl	r48,-2089976,r0; Invalid; (p56) break.i	0x10802 }
	{ (p16) break.m	0x0; Invalid; Invalid }

l40000000000E41D0:
	{ adds	r8,0x0,r42; mov	pr,r47,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r45; }
	{ nop.m	0x0; mov.spnt	b0,r44,40000000000E41E0; br.ret	b0 }

l40000000000E41F0:
	{ nop.m	0x0; adds	r8,0x0,r0; br.cond.sptk.few	40000000000E4040 }
40000000000E4200 09 78 3C 44 00 20 E0 00 A4 00 20 00 00 00 04 00 .x<D. .... .....
40000000000E4210 09 28 01 1E 18 10 00 00 00 02 00 00 02 70 50 00 .(...........pP.
40000000000E4220 0B 70 00 4A 00 10 00 00 00 02 00 C0 01 70 50 00 .p.J.........pP.
40000000000E4230 10 00 00 00 01 00 70 70 40 0C 71 03 20 FF FF 4A ......pp@.q. ..J
40000000000E4240 08 80 01 4A 00 21 00 00 00 02 00 20 06 48 01 84 ...J.!..... .H..
40000000000E4250 19 90 01 56 00 21 00 00 00 02 00 00 D8 7D F3 58 ...V.!.......}.X
40000000000E4260 00 00 00 00 01 00 E0 00 90 2C 00 20 00 70 01 84 .........,. .p..
40000000000E4270 18 00 00 00 01 00 60 00 20 0E F3 03 E0 FE FF 4A ......`. ......J
40000000000E4280 09 40 01 54 18 10 00 00 00 02 00 00 06 28 01 84 .@.T.........(..
40000000000E4290 11 40 39 50 12 20 00 00 00 02 00 00 38 74 F3 58 .@9P. ......8t.X
40000000000E42A0 11 08 00 5C 00 21 00 0B 20 00 42 00 28 4A 00 50 ...\.!.. .B.(J.P
40000000000E42B0 09 70 00 4C 18 10 10 00 B8 00 42 00 06 40 00 84 .p.L......B..@..
40000000000E42C0 09 00 00 00 01 00 E0 70 88 00 40 00 00 00 04 00 .......p..@.....
40000000000E42D0 11 88 01 1C 18 10 00 00 00 02 00 00 B8 6E F3 58 .............n.X
40000000000E42E0 10 00 00 00 01 00 10 00 B8 00 42 00 60 FE FF 48 ..........B.`..H

l40000000000E42F0:
	{ adds	r14,0x8,r32; nop.m	0x0; adds	r48,0x0,r32; }
	{ ld8	r8,[r14]; ld8	r14,[r8],8; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r14,40000000000E4310; nop.i	0x0 }
	{ ld8	r1,[r8]; nop.m	0x0; br.call.sptk.many	b0,b6; }
	{ ld4	r14,[r32]; adds	r1,0x0,r46; and	r14,0xFFFFFFFFFFFFFFFD,r14; }
	{ nop.m	0x0; or	r14,0x4,r14; nop.i	0x0; }
	{ st4	[r14],r32; nop.i	0x0; br.cond.sptk.few	40000000000E3F20 }

l40000000000E4360:
	{ adds	r48,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,clean_itemlist; }
	{ ld4	r14,[r32]; nop.m	0x0; adds	r1,0x0,r46; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x2; (p06) br.cond.dptk.few	40000000000E3F20 }

l40000000000E4390:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E42F0 }

l40000000000E43A0:
	{ adds	r48,0x0,r41; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; adds	r1,0x0,r46; br.cond.sptk.few	40000000000E4040 }
40000000000E43C0 11 78 00 00 00 21 40 02 00 00 42 00 C0 FD FF 48 .x...!@...B....H
40000000000E43D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E43E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E43F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; filter_stringlist: 40000000000E4400
;;   Called from:
;;     40000000000E699C (in gen_compspec_completions)
;;     40000000000E699C (in gen_compspec_completions)
filter_stringlist proc
	{ alloc	r46,ar.pfs,0x14,0x0,0x10; adds	r37,0xC,r32; mov	r45,b5 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r14,0x0,r33; (p06) br.cond.dpnt.few	40000000000E4710; }

l40000000000E4420:
	{ ld8	r15,[r32]; cmp.eq	p07,p06,0x0,r33; adds	r47,0x0,r1; }
	{ cmp.eq	p08,p09,0x0,r15; (p07) adds	r44,0x0,r0; (p08) br.cond.dpnt.few	40000000000E4710; }

l40000000000E443C:
	{ (p23) nop; cmp.eq	p00,p00,r32,r0; Invalid }

l40000000000E4440:
	{ nop.m	0x0; ld4	r15,[r37]; nop.i	0x0; }
	{ cmp4.eq	p08,p09,0x0,r15; nop.i	0x0; (p08) br.cond.dpnt.few	40000000000E4710; }

l40000000000E4460:
	{ nop.m	0x0; (p07) ld1	r14,[r33]; nop.i	0x0; }

l40000000000E446C:
	{ Invalid; cmp4.eq.or.andcm	p00,p32,r32,r0; (p04) mov	pr,r3,0x80 }
	{ (p05) cmp.eq	p00,p11,r64,r33; Invalid; Invalid }

l40000000000E4480:
	{ ld1	r15,[r33]; nop.m	0x0; sxt1	r15,r15; }
	{ adds	r39,0x0,r15; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dpnt.few	40000000000E4800; }

l40000000000E44A0:
	{ cmp4.eq	p07,p06,0x5C,r15; nop.m	0x0; adds	r16,0x0,r14; }
	{ (p07) adds	r16,0x1,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000E44D0; }

l40000000000E44B6:
	{ chk.a.nc	f0,3FFFFFFFFF0E4CB6; nop; break.i	0x80000 }

l40000000000E44C0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x26,r15; (p06) br.cond.dpnt.few	40000000000E4790 }

l40000000000E44D0:
	{ nop.m	0x0; adds	r14,0x1,r16; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E4510; }

l40000000000E44F0:
	{ ld1	r15,[r14]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	40000000000E44A0 }

l40000000000E4510:
	{ adds	r44,0x0,r33; nop.m	0x0; nop.i	0x0; }

l40000000000E4520:
	{ cmp4.eq	p06,p07,0x21,r39; adds	r38,0x0,r44; adds	r40,0x0,r0; }
	{ (p06) addl	r39,1,r0; (p07) adds	r39,0x0,r0; nop.i	0x0; }

l40000000000E4536:
	{ Invalid; nop; Invalid; }

l40000000000E453C:
	{ cmp.lt	p00,p11,r1,r0; cmp4.ne.and	p32,p60,r105,r97; (p20) mov	pr,r11,0x8400 }

l40000000000E454C:
	{ Invalid; Invalid; Invalid }

l40000000000E4550:
	{ adds	r14,0x8,r32; addl	r41,7664,r1; xor	r40,0x1,r40 }
	{ adds	r35,0x0,r0; adds	r36,0x0,r0; zxt1	r39,r39; }
	{ ld4	r48,[r14]; nop.m	0x0; and	r40,0x1,r40 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,strlist_create; }
	{ ld4	r14,[r37]; nop.m	0x0; adds	r1,0x0,r47 }
	{ adds	r43,0x0,r8; nop.m	0x0; adds	r42,0xC,r8; }
	{ nop.m	0x0; cmp4.lt	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000E46B0; }

l40000000000E45C0:
	{ nop.m	0x0; ld4	r50,[r41]; adds	r48,0x0,r38 }
	{ ld8	r14,[r32]; add	r14,r14,r35; cmp4.eq	p06,p07,0x0,r50; }
	{ ld8	r49,[r14]; nop.m	0x0; (p07) addl	r50,32,r0; }

l40000000000E45F0:
	{ (p06) adds	r50,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,strmatch; }

l40000000000E45F6:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; nop; (p34) nop }

l40000000000E4616:
	{ (p03) chk.a.nc	r0,3FFFFFFFFFC07886; shrp	r18,r0,r64,33; (p34) nop.b	0x3 }

l40000000000E4620:
	{ (p09) adds	r14,0x0,r0; and	r14,r40,r14; nop.i	0x0; }

l40000000000E4626:
	{ Invalid; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	f0,3FFFFFFFFFDA7F16; nop; break.i	0x80000 }

l40000000000E4640:
	{ nop.m	0x0; ld4	r14,[r42]; adds	r36,0x1,r36 }
	{ ld8	r15,[r32]; add	r16,r15,r35; sxt4	r17,r14 }
	{ ld8	r15,[r43]; adds	r14,0x1,r14; adds	r35,0x8,r35; }
	{ ld8	r16,[r16]; nop.m	0x0; shladd	r15,r17,0x3,r15; }
	{ st8	[r16],r15; st4	[r14],r42; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r37]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r36,r14; (p06) br.cond.dptk.few	40000000000E45C0; }

l40000000000E46B0:
	{ ld4	r15,[r42]; cmp.eq	p07,p06,r33,r44; adds	r48,0x0,r44 }
	{ adds	r32,0x0,r43; ld8	r14,[r43]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r15,r15; shladd	r14,r15,0x3,r14; }
	{ nop.m	0x0; st8	[r0],r14; nop.i	0x0 }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	40000000000E4710; br.call.sptk.many	b0,fn400000000001A7E0; }

l40000000000E46FC:
	{ (p07) nop; invala; break.b	0x1000 }
	{ nop; zxt1	r0,r64; break.i	0x1000 }

l40000000000E4710:
	{ adds	r8,0x0,r32; nop.m	0x0; mov.i	ar.pfs,r46; }
	{ nop.m	0x0; mov.spnt	b0,r45,40000000000E4720; br.ret	b0 }

l40000000000E4730:
	{ ld8	r14,[r32]; nop.m	0x0; adds	r36,0x1,r36; }
	{ add	r14,r14,r35; nop.m	0x0; adds	r35,0x8,r35; }
	{ ld8	r48,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ ld4	r14,[r37]; nop.m	0x0; adds	r1,0x0,r47; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r36,r14; (p06) br.cond.dptk.few	40000000000E45C0 }

l40000000000E4780:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E46B0 }

l40000000000E4790:
	{ adds	r48,0x0,r33; addl	r49,38,r0; adds	r50,0x0,r34 }
	{ addl	r51,1,r0; adds	r40,0x0,r0; br.call.sptk.many	b0,strcreplace; }
	{ ld1	r39,[r8]; adds	r44,0x0,r8; adds	r1,0x0,r47; }
	{ nop.m	0x0; sxt1	r39,r39; adds	r38,0x0,r44; }
	{ cmp4.eq	p06,p07,0x21,r39; (p06) addl	r39,1,r0; nop.i	0x0; }

l40000000000E47DC:
	{ cmp4.eq.or.andcm	p00,p43,r1,r0; (p04) cmp.lt	p00,p16,r0,r64; czx1.r	r96,r97 }

l40000000000E47E6:
	{ Invalid; cmp4.eq	p00,p00,r0,r1; (p33) cmp.eq.or.andcm	p41,p00,r0,r11 }

l40000000000E47F6:
	{ Invalid; nop; (p32) nop; }

l40000000000E47FC:
	{ (p43) cmp.lt.unc	p63,p08,r63,r36; (p01) nop; zxt4	r60,r14 }

l40000000000E4800:
	{ adds	r14,0x8,r32; addl	r41,7664,r1; adds	r40,0x0,r0 }
	{ adds	r39,0x0,r0; adds	r44,0x0,r33; adds	r38,0x0,r33; }
	{ nop.m	0x0; xor	r40,0x1,r40; adds	r35,0x0,r0 }
	{ adds	r36,0x0,r0; ld4	r48,[r14]; br.call.sptk.many	b0,strlist_create; }
	{ ld4	r14,[r37]; adds	r1,0x0,r47; zxt1	r39,r39 }
	{ adds	r43,0x0,r8; adds	r42,0xC,r8; and	r40,0x1,r40; }
	{ nop.m	0x0; cmp4.lt	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000E45C0 }

l40000000000E4870:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E46B0; }

;; completions_to_stringlist: 40000000000E4880
;;   Called from:
;;     40000000000E4D3C (in fn40000000000E4B40)
;;     40000000000E4DEC (in fn40000000000E4B40)
;;     40000000000E4E9C (in fn40000000000E4B40)
;;     40000000000E4F4C (in fn40000000000E4B40)
;;     40000000000E4FFC (in fn40000000000E4B40)
;;     40000000000E50AC (in fn40000000000E4B40)
;;     400000000011E18C (in compgen_builtin)
;;     400000000011E22C (in compgen_builtin)
completions_to_stringlist proc
	{ alloc	r40,ar.pfs,0xC,0x0,0xA; cmp.eq	p06,p07,0x0,r32; mov	r39,b7 }
	{ adds	r41,0x0,r1; adds	r42,0x0,r32; (p06) br.cond.dpnt.few	40000000000E4A50; }

l40000000000E48A0:
	{ sub	r36,0xFFFFFFFFFFFFFFF8,r32; nop.i	0x0; br.call.sptk.many	b0,strvec_len; }
	{ adds	r38,0x0,r8; nop.m	0x0; adds	r1,0x0,r41 }
	{ adds	r42,0x1,r8; nop.m	0x0; br.call.sptk.many	b0,strlist_create; }
	{ adds	r37,0xFFFFFFFFFFFFFFFE,r38; adds	r14,0x8,r32; adds	r15,0x10,r32 }
	{ ld8	r42,[r32]; adds	r1,0x0,r41; adds	r35,0x0,r8; }
	{ addp4	r37,r37,r0; cmp4.lt	p08,p09,0x1,r38; nop.i	0x0 }
	{ cmp.eq	p06,p07,0x0,r42; adds	r33,0x0,r14; (p06) br.cond.dpnt.few	40000000000E4A30; }

l40000000000E4910:
	{ shladd	r37,r37,0x3,r15; ld8	r14,[r14]; (p09) adds	r16,0x0,r0 }

l40000000000E4920:
	{ nop.m	0x0; (p09) adds	r38,0x0,r0; nop.i	0x0; }

l40000000000E492C:
	{ cmp.lt	p00,p19,r1,r0; mov	pr,r99,0xE480; Invalid }

l40000000000E493C:
	{ (p07) nop; cmp.lt	p00,p00,r32,r0; (p01) dep	r32,r8,r6,63,9 }

l40000000000E4940:
	{ nop.m	0x0; ld8	r14,[r33]; add	r34,r36,r33 }
	{ nop.m	0x0; ld8	r15,[r35]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; adds	r42,0x0,r14; add	r34,r15,r34; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E49D0; }

l40000000000E4976:
	{ chk.a.nc	r0,3FFFFFFFFF0E5176; nop; break.i	0x80000 }

l40000000000E4980:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r41; adds	r42,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r42,0x0,r8 }
	{ ld8	r43,[r33]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r41; nop.m	0x0; nop.i	0x0 }

l40000000000E49D0:
	{ adds	r33,0x8,r33; st8	[r8],r34; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r37,r33; (p06) br.cond.dptk.few	40000000000E4940 }

l40000000000E49F0:
	{ adds	r38,0xFFFFFFFFFFFFFFFF,r38; nop.i	0x0; sxt4	r16,r38; }
	{ shladd	r16,r16,0x3,r0; nop.m	0x0; nop.i	0x0 }

l40000000000E4A10:
	{ ld8	r14,[r35]; adds	r15,0xC,r35; add	r14,r14,r16 }
	{ st4	[r38],r15; st8	[r0],r14; nop.i	0x0 }

l40000000000E4A30:
	{ adds	r8,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000E4A40; br.ret	b0; }

l40000000000E4A50:
	{ addl	r42,1,r0; nop.i	0x0; br.call.sptk.many	b0,strlist_create; }
	{ adds	r35,0x0,r8; adds	r1,0x0,r41; mov.i	ar.pfs,r40; }
	{ adds	r8,0x0,r35; mov.spnt	b0,r39,40000000000E4A70; br.ret	b0; }

l40000000000E4A80:
	{ adds	r33,0x0,r8; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r41; ld8	r34,[r33],12; adds	r42,0x1,r8 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r42,0x0,r8 }
	{ ld8	r43,[r32]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ ld8.a	r14,[r35]; st8	[r8],r34; mov.i	ar.pfs,r40 }
	{ addl	r15,1,r0; adds	r8,0x0,r35; adds	r1,0x0,r41; }
	{ ld8.c.clr	r14,[r35]; st4	[r15],r33; mov.spnt	b0,r39,40000000000E4AF0; }
	{ nop.m	0x0; adds	r14,0x8,r14; nop.i	0x0; }
	{ st8	[r0],r14; nop.i	0x0; br.ret	b0; }
40000000000E4B20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E4B30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000E4B40: 40000000000E4B40
;;   Called from:
;;     40000000000E5AFC (in gen_compspec_completions)
;;     40000000000E6DEC (in gen_compspec_completions)
;;     40000000000E738C (in gen_compspec_completions)
fn40000000000E4B40 proc
	{ alloc	r39,ar.pfs,0xB,0x0,0x9; adds	r32,0x8,r32; mov	r38,b6 }
	{ adds	r40,0x0,r1; ld8	r34,[r32]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r34,0x0; (p06) br.cond.dpnt.few	40000000000E5A20; }

l40000000000E4B70:
	{ adds	r35,0x0,r0; tbit.z	p06,p07,r34,0x1; (p07) br.cond.dpnt.few	40000000000E5990; }

l40000000000E4B80:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x2; (p07) br.cond.dpnt.few	40000000000E5900; }

l40000000000E4B90:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x3; (p07) br.cond.dpnt.few	40000000000E5870; }

l40000000000E4BA0:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x6; (p07) br.cond.dpnt.few	40000000000E57E0; }

l40000000000E4BB0:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x7; (p07) br.cond.dpnt.few	40000000000E5750; }

l40000000000E4BC0:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x8; (p07) br.cond.dpnt.few	40000000000E56C0; }

l40000000000E4BD0:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0xA; (p07) br.cond.dpnt.few	40000000000E5630; }

l40000000000E4BE0:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0xD; (p07) br.cond.dpnt.few	40000000000E55A0; }

l40000000000E4BF0:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0xE; (p07) br.cond.dpnt.few	40000000000E5510; }

l40000000000E4C00:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0xF; (p07) br.cond.dpnt.few	40000000000E5480; }

l40000000000E4C10:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x10; (p07) br.cond.dpnt.few	40000000000E53F0; }

l40000000000E4C20:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x12; (p07) br.cond.dpnt.few	40000000000E5360; }

l40000000000E4C30:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x13; (p07) br.cond.dpnt.few	40000000000E52D0; }

l40000000000E4C40:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x14; (p07) br.cond.dpnt.few	40000000000E5240; }

l40000000000E4C50:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x15; (p07) br.cond.dpnt.few	40000000000E51B0; }

l40000000000E4C60:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x17; (p07) br.cond.dpnt.few	40000000000E5120; }

l40000000000E4C70:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x4; (p07) br.cond.dpnt.few	40000000000E5070; }

l40000000000E4C80:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x9; (p07) br.cond.dpnt.few	40000000000E4FC0; }

l40000000000E4C90:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x16; (p07) br.cond.dpnt.few	40000000000E4F10; }

l40000000000E4CA0:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0xB; (p07) br.cond.dpnt.few	40000000000E4E60; }

l40000000000E4CB0:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x11; (p07) br.cond.dpnt.few	40000000000E4DB0; }

l40000000000E4CC0:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x5; (p07) br.cond.dpnt.few	40000000000E4CF0 }

l40000000000E4CD0:
	{ adds	r8,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000E4CE0; br.ret	b0 }

l40000000000E4CF0:
	{ addl	r14,-10492,r1; addl	r15,1,r0; adds	r41,0x0,r33; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,bash_directory_completion_matches; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r41,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,completions_to_stringlist; }
	{ adds	r1,0x0,r40; adds	r42,0x0,r8; nop.i	0x0 }
	{ adds	r34,0x0,r8; adds	r41,0x0,r35; br.call.sptk.many	b0,strlist_append; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r41,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,strvec_dispose; }
	{ adds	r1,0x0,r40; adds	r41,0x0,r34; br.call.sptk.many	b0,strlist_dispose; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r40; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000E4DA0; br.ret	b0 }

l40000000000E4DB0:
	{ addl	r42,-9612,r1; nop.m	0x0; adds	r41,0x0,r33; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A860; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r37,0x0,r8 }
	{ adds	r41,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,completions_to_stringlist; }
	{ adds	r41,0x0,r35; adds	r42,0x0,r8; nop.i	0x0 }
	{ adds	r1,0x0,r40; adds	r36,0x0,r8; br.call.sptk.many	b0,strlist_append; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r41,0x0,r37; nop.m	0x0; br.call.sptk.many	b0,strvec_dispose; }
	{ adds	r1,0x0,r40; adds	r41,0x0,r36; br.call.sptk.many	b0,strlist_dispose; }
	{ adds	r1,0x0,r40; tbit.z	p06,p07,r34,0x5; (p06) br.cond.dptk.few	40000000000E4CD0 }

l40000000000E4E50:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E4CF0; }

l40000000000E4E60:
	{ addl	r42,-9596,r1; nop.m	0x0; adds	r41,0x0,r33; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A860; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r37,0x0,r8 }
	{ adds	r41,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,completions_to_stringlist; }
	{ adds	r41,0x0,r35; adds	r42,0x0,r8; nop.i	0x0 }
	{ adds	r1,0x0,r40; adds	r36,0x0,r8; br.call.sptk.many	b0,strlist_append; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r41,0x0,r37; nop.m	0x0; br.call.sptk.many	b0,strvec_dispose; }
	{ adds	r1,0x0,r40; adds	r41,0x0,r36; br.call.sptk.many	b0,strlist_dispose; }
	{ adds	r1,0x0,r40; tbit.z	p06,p07,r34,0x11; (p06) br.cond.dptk.few	40000000000E4CC0 }

l40000000000E4F00:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E4DB0; }

l40000000000E4F10:
	{ addl	r42,-10308,r1; nop.m	0x0; adds	r41,0x0,r33; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A860; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r37,0x0,r8 }
	{ adds	r41,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,completions_to_stringlist; }
	{ adds	r41,0x0,r35; adds	r42,0x0,r8; nop.i	0x0 }
	{ adds	r1,0x0,r40; adds	r36,0x0,r8; br.call.sptk.many	b0,strlist_append; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r41,0x0,r37; nop.m	0x0; br.call.sptk.many	b0,strvec_dispose; }
	{ adds	r1,0x0,r40; adds	r41,0x0,r36; br.call.sptk.many	b0,strlist_dispose; }
	{ adds	r1,0x0,r40; tbit.z	p06,p07,r34,0xB; (p06) br.cond.dptk.few	40000000000E4CB0 }

l40000000000E4FB0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E4E60; }

l40000000000E4FC0:
	{ addl	r42,-508,r1; nop.m	0x0; adds	r41,0x0,r33; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A860; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r37,0x0,r8 }
	{ adds	r41,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,completions_to_stringlist; }
	{ adds	r41,0x0,r35; adds	r42,0x0,r8; nop.i	0x0 }
	{ adds	r1,0x0,r40; adds	r36,0x0,r8; br.call.sptk.many	b0,strlist_append; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r41,0x0,r37; nop.m	0x0; br.call.sptk.many	b0,strvec_dispose; }
	{ adds	r1,0x0,r40; adds	r41,0x0,r36; br.call.sptk.many	b0,strlist_dispose; }
	{ adds	r1,0x0,r40; tbit.z	p06,p07,r34,0x16; (p06) br.cond.dptk.few	40000000000E4CA0 }

l40000000000E5060:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E4F10; }

l40000000000E5070:
	{ addl	r42,-10036,r1; nop.m	0x0; adds	r41,0x0,r33; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A860; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r37,0x0,r8 }
	{ adds	r41,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,completions_to_stringlist; }
	{ adds	r41,0x0,r35; adds	r42,0x0,r8; nop.i	0x0 }
	{ adds	r1,0x0,r40; adds	r36,0x0,r8; br.call.sptk.many	b0,strlist_append; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r41,0x0,r37; nop.m	0x0; br.call.sptk.many	b0,strvec_dispose; }
	{ adds	r1,0x0,r40; adds	r41,0x0,r36; br.call.sptk.many	b0,strlist_dispose; }
	{ adds	r1,0x0,r40; tbit.z	p06,p07,r34,0x9; (p06) br.cond.dptk.few	40000000000E4C90 }

l40000000000E5110:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E4FC0; }

l40000000000E5120:
	{ addl	r41,-19476,r1; nop.m	0x0; adds	r42,0x0,r33; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000E3EC0; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r40; adds	r36,0x0,r8 }
	{ adds	r41,0x0,r35; adds	r42,0x0,r8; (p06) br.cond.dpnt.few	40000000000E4C70; }

l40000000000E5160:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strlist_append; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r41,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,strlist_dispose; }
	{ adds	r1,0x0,r40; tbit.z	p06,p07,r34,0x4; (p06) br.cond.dptk.few	40000000000E4C80 }

l40000000000E51A0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E5070; }

l40000000000E51B0:
	{ addl	r41,-19396,r1; nop.m	0x0; adds	r42,0x0,r33; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000E3EC0; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r40; adds	r36,0x0,r8 }
	{ adds	r41,0x0,r35; adds	r42,0x0,r8; (p06) br.cond.dpnt.few	40000000000E4C60; }

l40000000000E51F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strlist_append; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r41,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,strlist_dispose; }
	{ adds	r1,0x0,r40; tbit.z	p06,p07,r34,0x17; (p06) br.cond.dptk.few	40000000000E4C70 }

l40000000000E5230:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E5120; }

l40000000000E5240:
	{ addl	r41,-19356,r1; nop.m	0x0; adds	r42,0x0,r33; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000E3EC0; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r40; adds	r36,0x0,r8 }
	{ adds	r41,0x0,r35; adds	r42,0x0,r8; (p06) br.cond.dpnt.few	40000000000E4C50; }

l40000000000E5280:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strlist_append; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r41,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,strlist_dispose; }
	{ adds	r1,0x0,r40; tbit.z	p06,p07,r34,0x15; (p06) br.cond.dptk.few	40000000000E4C60 }

l40000000000E52C0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E51B0; }

l40000000000E52D0:
	{ addl	r41,-19316,r1; nop.m	0x0; adds	r42,0x0,r33; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000E3EC0; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r40; adds	r36,0x0,r8 }
	{ adds	r41,0x0,r35; adds	r42,0x0,r8; (p06) br.cond.dpnt.few	40000000000E4C40; }

l40000000000E5310:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strlist_append; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r41,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,strlist_dispose; }
	{ adds	r1,0x0,r40; tbit.z	p06,p07,r34,0x14; (p06) br.cond.dptk.few	40000000000E4C50 }

l40000000000E5350:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E5240; }

l40000000000E5360:
	{ addl	r41,-19276,r1; nop.m	0x0; adds	r42,0x0,r33; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000E3EC0; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r40; adds	r36,0x0,r8 }
	{ adds	r41,0x0,r35; adds	r42,0x0,r8; (p06) br.cond.dpnt.few	40000000000E4C30; }

l40000000000E53A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strlist_append; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r41,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,strlist_dispose; }
	{ adds	r1,0x0,r40; tbit.z	p06,p07,r34,0x13; (p06) br.cond.dptk.few	40000000000E4C40 }

l40000000000E53E0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E52D0; }

l40000000000E53F0:
	{ addl	r41,-19196,r1; nop.m	0x0; adds	r42,0x0,r33; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000E3EC0; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r40; adds	r36,0x0,r8 }
	{ adds	r41,0x0,r35; adds	r42,0x0,r8; (p06) br.cond.dpnt.few	40000000000E4C20; }

l40000000000E5430:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strlist_append; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r41,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,strlist_dispose; }
	{ adds	r1,0x0,r40; tbit.z	p06,p07,r34,0x12; (p06) br.cond.dptk.few	40000000000E4C30 }

l40000000000E5470:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E5360; }

l40000000000E5480:
	{ addl	r41,-19156,r1; nop.m	0x0; adds	r42,0x0,r33; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000E3EC0; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r40; adds	r36,0x0,r8 }
	{ adds	r41,0x0,r35; adds	r42,0x0,r8; (p06) br.cond.dpnt.few	40000000000E4C10; }

l40000000000E54C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strlist_append; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r41,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,strlist_dispose; }
	{ adds	r1,0x0,r40; tbit.z	p06,p07,r34,0x10; (p06) br.cond.dptk.few	40000000000E4C20 }

l40000000000E5500:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E53F0; }

l40000000000E5510:
	{ addl	r41,-19116,r1; nop.m	0x0; adds	r42,0x0,r33; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000E3EC0; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r40; adds	r36,0x0,r8 }
	{ adds	r41,0x0,r35; adds	r42,0x0,r8; (p06) br.cond.dpnt.few	40000000000E4C00; }

l40000000000E5550:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strlist_append; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r41,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,strlist_dispose; }
	{ adds	r1,0x0,r40; tbit.z	p06,p07,r34,0xF; (p06) br.cond.dptk.few	40000000000E4C10 }

l40000000000E5590:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E5480; }

l40000000000E55A0:
	{ addl	r41,-19036,r1; nop.m	0x0; adds	r42,0x0,r33; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000E3EC0; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r40; adds	r36,0x0,r8 }
	{ adds	r41,0x0,r35; adds	r42,0x0,r8; (p06) br.cond.dpnt.few	40000000000E4BF0; }

l40000000000E55E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strlist_append; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r41,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,strlist_dispose; }
	{ adds	r1,0x0,r40; tbit.z	p06,p07,r34,0xE; (p06) br.cond.dptk.few	40000000000E4C00 }

l40000000000E5620:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E5510; }

l40000000000E5630:
	{ addl	r41,-18996,r1; nop.m	0x0; adds	r42,0x0,r33; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000E3EC0; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r40; adds	r36,0x0,r8 }
	{ adds	r41,0x0,r35; adds	r42,0x0,r8; (p06) br.cond.dpnt.few	40000000000E4BE0; }

l40000000000E5670:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strlist_append; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r41,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,strlist_dispose; }
	{ adds	r1,0x0,r40; tbit.z	p06,p07,r34,0xD; (p06) br.cond.dptk.few	40000000000E4BF0 }

l40000000000E56B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E55A0; }

l40000000000E56C0:
	{ addl	r41,-18916,r1; nop.m	0x0; adds	r42,0x0,r33; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000E3EC0; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r40; adds	r36,0x0,r8 }
	{ adds	r41,0x0,r35; adds	r42,0x0,r8; (p06) br.cond.dpnt.few	40000000000E4BD0; }

l40000000000E5700:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strlist_append; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r41,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,strlist_dispose; }
	{ adds	r1,0x0,r40; tbit.z	p06,p07,r34,0xA; (p06) br.cond.dptk.few	40000000000E4BE0 }

l40000000000E5740:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E5630; }

l40000000000E5750:
	{ addl	r41,-18876,r1; nop.m	0x0; adds	r42,0x0,r33; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000E3EC0; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r40; adds	r36,0x0,r8 }
	{ adds	r41,0x0,r35; adds	r42,0x0,r8; (p06) br.cond.dpnt.few	40000000000E4BC0; }

l40000000000E5790:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strlist_append; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r41,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,strlist_dispose; }
	{ adds	r1,0x0,r40; tbit.z	p06,p07,r34,0x8; (p06) br.cond.dptk.few	40000000000E4BD0 }

l40000000000E57D0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E56C0; }

l40000000000E57E0:
	{ addl	r41,-18836,r1; nop.m	0x0; adds	r42,0x0,r33; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000E3EC0; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r40; adds	r36,0x0,r8 }
	{ adds	r41,0x0,r35; adds	r42,0x0,r8; (p06) br.cond.dpnt.few	40000000000E4BB0; }

l40000000000E5820:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strlist_append; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r41,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,strlist_dispose; }
	{ adds	r1,0x0,r40; tbit.z	p06,p07,r34,0x7; (p06) br.cond.dptk.few	40000000000E4BC0 }

l40000000000E5860:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E5750; }

l40000000000E5870:
	{ addl	r41,-18716,r1; nop.m	0x0; adds	r42,0x0,r33; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000E3EC0; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r40; adds	r36,0x0,r8 }
	{ adds	r41,0x0,r35; adds	r42,0x0,r8; (p06) br.cond.dpnt.few	40000000000E4BA0; }

l40000000000E58B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strlist_append; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r41,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,strlist_dispose; }
	{ adds	r1,0x0,r40; tbit.z	p06,p07,r34,0x6; (p06) br.cond.dptk.few	40000000000E4BB0 }

l40000000000E58F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E57E0; }

l40000000000E5900:
	{ addl	r41,-18676,r1; nop.m	0x0; adds	r42,0x0,r33; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000E3EC0; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r40; adds	r36,0x0,r8 }
	{ adds	r41,0x0,r35; adds	r42,0x0,r8; (p06) br.cond.dpnt.few	40000000000E4B90; }

l40000000000E5940:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strlist_append; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r41,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,strlist_dispose; }
	{ adds	r1,0x0,r40; tbit.z	p06,p07,r34,0x3; (p06) br.cond.dptk.few	40000000000E4BA0 }

l40000000000E5980:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E5870; }

l40000000000E5990:
	{ addl	r41,-18636,r1; nop.m	0x0; adds	r42,0x0,r33; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000E3EC0; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r40; adds	r36,0x0,r8 }
	{ adds	r41,0x0,r35; adds	r42,0x0,r8; (p06) br.cond.dpnt.few	40000000000E4B80; }

l40000000000E59D0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strlist_append; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r41,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,strlist_dispose; }
	{ adds	r1,0x0,r40; tbit.z	p06,p07,r34,0x2; (p06) br.cond.dptk.few	40000000000E4B90 }

l40000000000E5A10:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E5900; }

l40000000000E5A20:
	{ addl	r41,-18596,r1; nop.m	0x0; adds	r42,0x0,r33; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000E3EC0; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r40; adds	r36,0x0,r8 }
	{ adds	r42,0x0,r8; adds	r41,0x0,r0; (p06) br.cond.dpnt.few	40000000000E4B70; }

l40000000000E5A60:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strlist_append; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r41,0x0,r36; nop.m	0x0; br.call.sptk.many	b0,strlist_dispose; }
	{ adds	r1,0x0,r40; tbit.z	p06,p07,r34,0x1; (p06) br.cond.dptk.few	40000000000E4B80 }

l40000000000E5AA0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E5990; }
40000000000E5AB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; gen_compspec_completions: 40000000000E5AC0
;;   Called from:
;;     40000000000E763C (in fn40000000000E7500)
;;     400000000011DF3C (in compgen_builtin)
gen_compspec_completions proc
	{ alloc	r54,ar.pfs,0x20,0x0,0x19; adds	r12,0xFFFFFFFFFFFFFF90,r12; mov	r56,pr }
	{ adds	r55,0x0,r1; adds	r58,0x0,r34; adds	r39,0x18,r32; }
	{ nop.m	0x0; mov	r53,b5; adds	r57,0x0,r32 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn40000000000E4B40; }
	{ ld8	r14,[r39]; nop.m	0x0; adds	r44,0x0,r8 }
	{ adds	r1,0x0,r55; nop.m	0x0; adds	r57,0x0,r0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E5C40; }

l40000000000E5B30:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strlist_create; }
	{ nop.m	0x0; adds	r1,0x0,r55; adds	r38,0x0,r8 }
	{ ld8	r57,[r39]; adds	r58,0x0,r0; br.call.sptk.many	b0,glob_filename; }
	{ adds	r1,0x0,r55; st8	[r8],r38; adds	r57,0x0,r8; }
	{ addl	r14,9284,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r14,r8; nop.i	0x0; }
	{ (p07) st8	[r0],r38; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000E5BE0; }

l40000000000E5B96:
	{ chk.a.nc	f0,3FFFFFFFFF0E6396; nop; (p32) nop }

l40000000000E5BA0:
	{ cmp.eq	p06,p07,0x0,r8; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E5BE0; }

l40000000000E5BB0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strvec_len; }
	{ adds	r15,0x8,r38; adds	r14,0xC,r38; adds	r1,0x0,r55; }
	{ st4	[r8],r15; st4	[r8],r14; nop.i	0x0 }

l40000000000E5BE0:
	{ adds	r57,0x0,r44; adds	r58,0x0,r38; br.call.sptk.many	b0,strlist_append; }
	{ adds	r1,0x0,r55; nop.m	0x0; adds	r44,0x0,r8 }
	{ adds	r57,0x0,r38; nop.m	0x0; br.call.sptk.many	b0,strlist_dispose; }
	{ adds	r1,0x0,r55; addl	r15,1,r0; addl	r14,-10172,r1; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ st4	[r15],r14; nop.m	0x0; nop.i	0x0 }

l40000000000E5C40:
	{ adds	r14,0x20,r32; ld8	r38,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r38; adds	r57,0x0,r38; (p06) br.cond.dpnt.few	40000000000E6000; }

l40000000000E5C60:
	{ ld1	r14,[r38]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E6000; }

l40000000000E5C80:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r59,0x0,r0; adds	r58,0x0,r8; addl	r60,-1,r0 }
	{ adds	r61,0x0,r0; adds	r62,0x0,r0; adds	r63,0x0,r0; }
	{ adds	r57,0x0,r38; adds	r1,0x0,r55; br.call.sptk.many	b0,split_at_delims; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r55; nop.i	0x0 }
	{ adds	r38,0x0,r8; adds	r57,0x0,r8; (p06) br.cond.dpnt.few	40000000000E6000; }

l40000000000E5CE0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,expand_words_shellexp; }
	{ adds	r1,0x0,r55; nop.m	0x0; adds	r46,0x0,r8 }
	{ adds	r57,0x0,r38; nop.m	0x0; br.call.sptk.many	b0,dispose_words; }
	{ adds	r1,0x0,r55; adds	r57,0x0,r46; br.call.sptk.many	b0,list_length; }
	{ adds	r1,0x0,r55; adds	r57,0x1,r8; br.call.sptk.many	b0,strlist_create; }
	{ adds	r1,0x0,r55; nop.m	0x0; adds	r45,0x0,r8 }
	{ adds	r57,0x0,r34; nop.m	0x0; br.call.sptk.many	b0,bash_dequote_text; }
	{ adds	r1,0x0,r55; nop.m	0x0; adds	r43,0x0,r8 }
	{ cmp.eq	p18,p19,0x0,r8; nop.m	0x0; (p18) br.cond.dpnt.few	40000000000E6E70; }

l40000000000E5D70:
	{ ld1	r14,[r8]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000E6E70 }

l40000000000E5D90:
	{ adds	r14,0x1,r8; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r8,1,r0; (p06) br.cond.dptk.few	40000000000E5E20 }

l40000000000E5DBC:
	{ (p03) cmp.lt	p00,p11,r0,r33; (p33) cmp.lt.unc	p32,p16,r10,r64; (p01) rfi }

l40000000000E5DC0:
	{ adds	r14,0x2,r43; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r8,2,r0; (p06) br.cond.dptk.few	40000000000E5E20 }

l40000000000E5DEC:
	{ Invalid; nop; zxt1	r96,r64 }

l40000000000E5DF0:
	{ nop.m	0x0; adds	r57,0x0,r43; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r55; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000E5E20:
	{ adds	r38,0x0,r46; adds	r40,0x0,r0; nop.b	0x0 }
	{ cmp4.eq	p17,p16,0x0,r8; sxt4	r47,r8; cmp.eq	p06,p07,0x0,r46; }
	{ nop.m	0x0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E7470; }

l40000000000E5E50:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000E5E60:
	{ nop.m	0x0; sxt4	r14,r40; nop.i	0x0 }
	{ adds	r39,0x8,r38; nop.m	0x0; (p16) br.cond.dptk.few	40000000000E6E80; }

l40000000000E5E80:
	{ ld8	r15,[r39]; ld8	r42,[r45]; nop.i	0x0; }
	{ nop.m	0x0; shladd	r42,r14,0x3,r42; nop.i	0x0; }
	{ ld8	r41,[r15]; cmp.eq	p07,p06,0x0,r41; adds	r57,0x0,r41; }
	{ (p07) adds	r8,0x0,r0; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000E5F10; }

l40000000000E5EB6:
	{ chk.a.nc	f0,3FFFFFFFFF0E66B6; nop; break.i	0x80000 }

l40000000000E5EC0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r55; adds	r57,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r14,[r39]; adds	r1,0x0,r55; adds	r57,0x0,r8; }
	{ ld8	r58,[r14]; br.call.sptk.many	b0,fn400000000001B180; nop.b	0x0; }
	{ adds	r1,0x0,r55; nop.m	0x0; nop.i	0x0 }

l40000000000E5F10:
	{ nop.m	0x0; st8	[r8],r42; adds	r40,0x1,r40 }

l40000000000E5F20:
	{ nop.m	0x0; ld8	r38,[r38]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r38; (p06) br.cond.dptk.few	40000000000E5E60 }

l40000000000E5F40:
	{ nop.m	0x0; sxt4	r16,r40; shladd	r16,r16,0x3,r0 }

l40000000000E5F50:
	{ adds	r14,0x0,r45; nop.m	0x0; adds	r57,0x0,r46; }
	{ nop.m	0x0; ld8	r15,[r14],12; nop.i	0x0; }
	{ add	r15,r15,r16; st4	[r40],r14; nop.i	0x0; }
	{ st8	[r0],r15; nop.i	0x0; br.call.sptk.many	b0,dispose_words; }
	{ adds	r1,0x0,r55; nop.m	0x0; adds	r57,0x0,r43 }
	{ nop.b	0x0; (p18) br.cond.dpnt.few	40000000000E5FC0; br.call.sptk.many	b0,fn400000000001A7E0; }

l40000000000E5FAC:
	{ (p02) nop; invala; break.i	0x1000 }
	{ nop; (p07) dep	r0,r11,r64,62,1; zxt1	r32,r64 }

l40000000000E5FC0:
	{ adds	r57,0x0,r44; adds	r58,0x0,r45; br.call.sptk.many	b0,strlist_append; }
	{ adds	r1,0x0,r55; nop.m	0x0; adds	r44,0x0,r8 }
	{ adds	r57,0x0,r45; nop.m	0x0; br.call.sptk.many	b0,strlist_dispose; }
	{ adds	r1,0x0,r55; nop.m	0x0; nop.i	0x0 }

l40000000000E6000:
	{ adds	r46,0x40,r32; nop.m	0x0; adds	r50,0x38,r32; }
	{ nop.m	0x0; ld8	r14,[r46]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000E6D00 }

l40000000000E6030:
	{ addl	r14,-10540,r1; addl	r40,-10252,r1; nop.i	0x0 }
	{ adds	r58,0x0,r35; adds	r59,0x0,r36; adds	r39,0x70,r12; }
	{ ld8	r14,[r14]; ld8	r40,[r40]; nop.i	0x0; }
	{ ld8	r57,[r14]; nop.i	0x0; br.call.sptk.many	b0,substring; }
	{ adds	r1,0x0,r55; ld4	r60,[r40]; adds	r62,0x74,r12 }
	{ adds	r63,0x0,r39; adds	r48,0x0,r8; addl	r61,4,r0; }
	{ addl	r14,-10460,r1; sub	r60,r60,r35; adds	r57,0x0,r8 }
	{ sub	r58,r36,r35; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r59,[r14]; nop.i	0x0; br.call.sptk.many	b0,split_at_delims; }
	{ ld8	r38,[r50]; adds	r47,0x0,r8; adds	r1,0x0,r55; }
	{ cmp.eq	p07,p06,0x0,r38; nop.m	0x0; adds	r57,0x0,r38; }
	{ (p07) ld8	r14,[r46]; nop.m	0x0; (p07) adds	r51,0x0,r0 }

l40000000000E60E6:
	{ addp4	r0,0xFFFFFFFFFFFFE000,r1; (p25) nop; (p01) nop }

l40000000000E60F0:
	{ (p07) addl	r52,1,r0; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000E6420; }

l40000000000E60F6:
	{ chk.a.nc	f0,3FFFFFFFFF0E68F6; nop; (p32) nop }

l40000000000E6100:
	{ ld4	r58,[r40]; ld4	r41,[r39]; nop.i	0x0; }
	{ sub	r43,r58,r35; nop.i	0x0; br.call.sptk.many	b0,find_function; }
	{ cmp.eq	p07,p06,0x0,r8; adds	r42,0x0,r8; adds	r1,0x0,r55 }
	{ adds	r61,0x0,r0; adds	r60,0xFFFFFFFFFFFFFFFF,r41; (p07) br.cond.dpnt.few	40000000000E6B80; }

l40000000000E6140:
	{ adds	r57,0x0,r48; nop.m	0x0; adds	r58,0x0,r43 }
	{ adds	r59,0x0,r47; nop.m	0x0; br.call.sptk.many	b0,fn40000000000E3200; }
	{ adds	r60,0x0,r41; adds	r59,0x0,r47; adds	r58,0x0,r34 }
	{ adds	r57,0x0,r38; adds	r1,0x0,r55; br.call.sptk.many	b0,fn40000000000E3740; }
	{ adds	r1,0x0,r55; nop.m	0x0; adds	r38,0x0,r8 }
	{ adds	r57,0x10,r12; nop.m	0x0; br.call.sptk.many	b0,save_parser_state; }
	{ adds	r1,0x0,r55; addl	r57,-548,r1; nop.i	0x0; }
	{ ld8	r57,[r57]; nop.i	0x0; br.call.sptk.many	b0,begin_unwind_frame; }
	{ adds	r1,0x0,r55; adds	r58,0x10,r12; addl	r57,-9660,r1; }
	{ ld8	r57,[r57]; nop.i	0x0; br.call.sptk.many	b0,add_unwind_protect; }
	{ adds	r1,0x0,r55; adds	r58,0x0,r38; addl	r57,-9740,r1; }
	{ ld8	r57,[r57]; nop.i	0x0; br.call.sptk.many	b0,add_unwind_protect; }
	{ adds	r1,0x0,r55; adds	r58,0x0,r0; addl	r57,-516,r1; }
	{ ld8	r57,[r57]; nop.i	0x0; br.call.sptk.many	b0,add_unwind_protect; }
	{ adds	r58,0x0,r38; nop.m	0x0; adds	r1,0x0,r55 }
	{ adds	r57,0x0,r42; nop.m	0x0; br.call.sptk.many	b0,execute_shell_function; }
	{ adds	r1,0x0,r55; adds	r41,0x0,r8; addl	r57,-548,r1; }
	{ ld8	r57,[r57]; nop.i	0x0; br.call.sptk.many	b0,discard_unwind_frame; }
	{ adds	r1,0x0,r55; adds	r57,0x10,r12; br.call.sptk.many	b0,restore_parser_state; }
	{ cmp4.eq	p09,p08,0x7F,r41; nop.m	0x0; cmp4.eq	p07,p06,0x7C,r41 }
	{ adds	r57,0x0,r38; adds	r1,0x0,r55; (p08) addl	r14,1,r0; }

l40000000000E6290:
	{ (p09) adds	r14,0x0,r0; adds	r41,0x0,r14; nop.i	0x0; }

l40000000000E6296:
	{ Invalid; nop; Invalid }
	{ Invalid; cmp4.eq	p00,p00,r0,r1; (p17) nop; }

l40000000000E62AC:
	{ nop; zxt1	r74,r3; break.i	0x1000 }

l40000000000E62B6:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ add	r0,r0,r1; (p28) nop; nop }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; nop; (p16) br.call.sptk.few	b6,b0 }
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ Invalid; nop; nop }
	{ (p08) chk.a.clr	r127,3FFFFFFFFF4D62D6; nop; (p48) nop }

l40000000000E6320:
	{ ld4	r15,[r14]; nop.m	0x0; tbit.z	p07,p06,r15,0x2 }
	{ and	r15,r16,r15; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000E6F70; }

l40000000000E6340:
	{ adds	r8,0x8,r8; st4	[r15],r14; nop.i	0x0; }
	{ ld8	r38,[r8]; nop.i	0x0; (p17) br.cond.dptk.few	40000000000E6C30 }

l40000000000E6360:
	{ addl	r57,-540,r1; adds	r42,0x0,r0; nop.i	0x0 }
	{ ld8	r57,[r57]; nop.m	0x0; br.call.sptk.many	b0,unbind_variable; }
	{ adds	r1,0x0,r55; nop.m	0x0; nop.i	0x0 }

l40000000000E6390:
	{ nop.m	0x0; (p17) addl	r51,256,r0; (p17) adds	r52,0x0,r41 }

l40000000000E639C:
	{ Invalid; Invalid; Invalid }

l40000000000E63A0:
	{ nop.m	0x0; nop.m	0x0; (p16) br.cond.dpnt.few	40000000000E6C00; }

l40000000000E63B0:
	{ (p17) and	r51,r51,r41; nop.m	0x0; nop.i	0x0 }

l40000000000E63B6:
	{ break.m	0x4000; nop; break.i	0x80000 }

l40000000000E63C0:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r42; (p07) br.cond.dpnt.few	40000000000E6410 }

l40000000000E63D0:
	{ adds	r57,0x0,r44; adds	r58,0x0,r42; br.call.sptk.many	b0,strlist_append; }
	{ adds	r1,0x0,r55; nop.m	0x0; adds	r44,0x0,r8 }
	{ adds	r57,0x0,r42; nop.m	0x0; br.call.sptk.many	b0,strlist_dispose; }
	{ adds	r1,0x0,r55; nop.m	0x0; nop.i	0x0 }

l40000000000E6410:
	{ ld8	r14,[r46]; nop.m	0x0; nop.i	0x0; }

l40000000000E6420:
	{ cmp.eq	p06,p07,0x0,r14; addl	r61,1,r0; nop.i	0x0 }
	{ adds	r57,0x0,r48; adds	r59,0x0,r47; (p06) br.cond.dpnt.few	40000000000E7440; }

l40000000000E6440:
	{ ld4	r38,[r39]; ld4	r58,[r40]; nop.i	0x0; }
	{ adds	r60,0x0,r38; sub	r58,r58,r35; br.call.sptk.many	b0,fn40000000000E3200; }
	{ nop.m	0x0; adds	r60,0x0,r38; adds	r1,0x0,r55 }
	{ ld8	r57,[r46]; adds	r58,0x0,r34; adds	r59,0x0,r47; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000E3740; }
	{ adds	r49,0x0,r8; nop.m	0x0; adds	r1,0x0,r55 }
	{ ld8	r57,[r46]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ ld8	r39,[r49]; nop.m	0x0; adds	r38,0x1,r8 }
	{ adds	r1,0x0,r55; nop.m	0x0; adds	r42,0x0,r8; }
	{ adds	r40,0x0,r38; cmp.eq	p06,p07,0x0,r39; (p06) br.cond.dpnt.few	40000000000E65E0; }

l40000000000E64E0:
	{ adds	r14,0x8,r39; nop.m	0x0; addl	r8,3,r0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r57,[r14]; cmp.eq	p06,p07,0x0,r57; adds	r17,0x1,r57; }
	{ (p06) addl	r8,3,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E65C0; }

l40000000000E6516:
	{ chk.a.nc	r0,3FFFFFFFFF0E6D16; nop; nop }

l40000000000E6520:
	{ ld1	r16,[r57]; nop.m	0x0; sxt1	r16,r16; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r16; (p06) br.cond.dptk.few	40000000000E65C0 }

l40000000000E6540:
	{ ld1	r16,[r17]; adds	r18,0x2,r57; addl	r8,4,r0; }
	{ nop.m	0x0; sxt1	r16,r16; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r16; (p06) br.cond.dptk.few	40000000000E65C0 }

l40000000000E6570:
	{ ld1	r16,[r18]; addl	r8,5,r0; sxt1	r14,r16; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000E65C0 }

l40000000000E6590:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; adds	r1,0x0,r55; adds	r8,0x3,r8; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000E65C0:
	{ ld8	r39,[r39]; nop.m	0x0; add	r40,r8,r40; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r39; (p06) br.cond.dptk.few	40000000000E64E0 }

l40000000000E65E0:
	{ adds	r57,0x3,r40; nop.m	0x0; sxt4	r42,r42 }
	{ addl	r45,32,r0; nop.m	0x0; adds	r40,0x2,r40; }
	{ nop.m	0x0; sxt4	r57,r57; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r55; adds	r41,0x0,r8; nop.i	0x0 }
	{ adds	r57,0x0,r8; ld8	r58,[r46]; br.call.sptk.many	b0,fn400000000001B180; }
	{ add	r42,r41,r42; nop.m	0x0; addl	r14,32,r0 }
	{ ld8.a	r39,[r49]; nop.m	0x0; adds	r1,0x0,r55; }
	{ nop.m	0x0; st1	[r14],r42; cmp.eq	p06,p07,0x0,r39 }
	{ nop.m	0x0; chk.a.clr	r39,40000000000E74C0; nop.b	0x0 }

l40000000000E666C:
	{ Invalid; break.i	0x1000; mov	pr,r32,0x0 }

l40000000000E6670:
	{ nop.m	0x0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E67D0; }

l40000000000E6680:
	{ adds	r14,0x8,r39; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r14,[r14]; cmp.eq	p07,p06,0x0,r14; nop.i	0x0; }
	{ (p07) addl	r57,-564,r1; (p06) adds	r57,0x0,r14; nop.i	0x0; }

l40000000000E66A6:
	{ Invalid; cmp4.eq	p00,p00,r0,r1; (p17) br.call.sptk.few	b6,b0; }

l40000000000E66AC:
	{ nop; Invalid; break.i	0x1000 }

l40000000000E66B6:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; (p21) nop; (p16) nop }
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ Invalid; (p28) mov.sptk	b0,r41,40000000000E67E6; (p16) nop.b	0x37000 }
	{ Invalid; (p07) nop; nop }
	{ (p03) chk.a.clr	r14,3FFFFFFFFF92A186; Invalid; break.i	0x80000 }

l40000000000E6710:
	{ nop.m	0x0; extr	r40,r16,6,26; dep.z	r40,r40,6,26; }
	{ nop.m	0x0; add	r40,r15,r40; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r58,r40; br.call.sptk.many	b0,xrealloc; }
	{ nop.m	0x0; adds	r1,0x0,r55; adds	r41,0x0,r8 }

l40000000000E6750:
	{ nop.m	0x0; sxt4	r57,r38; adds	r58,0x0,r42 }
	{ nop.m	0x0; add	r38,r38,r43; nop.b	0x0; }
	{ add	r57,r41,r57; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ ld8	r14,[r39]; sxt4	r15,r38; adds	r1,0x0,r55 }
	{ adds	r57,0x0,r42; cmp.eq	p06,p07,0x0,r14; add	r15,r41,r15; }
	{ (p07) st1	[r45],r15; (p07) adds	r38,0x1,r38; br.call.sptk.many	b0,fn400000000001A7E0; }

l40000000000E67A6:
	{ Invalid; (p32) nop; (p48) nop; }

l40000000000E67AC:
	{ (p02) cmp.eq.unc	p40,p09,r60,r44; (p04) nop; nop }
	{ invala; cmp.eq	p00,p00,r32,r0; mov	pr,r73,0xE4C0 }
	{ (p54) break.m	0x95FFF; cmp.lt	p00,p00,r32,r0; (p04) dep	r64,r73,r5,63,1 }

l40000000000E67D0:
	{ nop.m	0x0; sxt4	r38,r38; adds	r58,0x0,r0 }
	{ adds	r57,0x0,r41; add	r38,r41,r38; nop.i	0x0; }
	{ st1	[r0],r38; nop.i	0x0; br.call.sptk.many	b0,command_substitute; }
	{ cmp.eq	p06,p07,0x0,r8; nop.m	0x0; adds	r57,0x0,r8 }
	{ adds	r1,0x0,r55; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000E73E0; }

l40000000000E6820:
	{ ld8	r40,[r8]; nop.i	0x0; br.call.sptk.many	b0,dispose_word_desc; }
	{ adds	r1,0x0,r55; adds	r57,0x0,r49; br.call.sptk.many	b0,dispose_words; }
	{ adds	r1,0x0,r55; adds	r57,0x0,r41; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r55; addl	r57,1,r0; br.call.sptk.many	b0,fn40000000000E30C0; }
	{ adds	r1,0x0,r55; nop.m	0x0; cmp.eq	p06,p07,0x0,r40 }
	{ adds	r57,0x0,r40; nop.m	0x0; (p06) br.cond.spnt.few	40000000000E68C0; }

l40000000000E6880:
	{ ld1	r14,[r40]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E6FD0; }

l40000000000E68A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r55; nop.m	0x0; nop.i	0x0 }

l40000000000E68C0:
	{ nop.m	0x0; ld8	r14,[r46]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p07) br.cond.spnt.few	40000000000E7440; }

l40000000000E68E0:
	{ cmp.eq	p06,p07,0x0,r47; adds	r57,0x0,r47; (p06) br.cond.dpnt.few	40000000000E6910; }

l40000000000E68F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,dispose_words; }
	{ adds	r1,0x0,r55; nop.m	0x0; nop.i	0x0 }

l40000000000E6910:
	{ cmp.eq	p06,p07,0x0,r48; adds	r57,0x0,r48; (p06) br.cond.dpnt.few	40000000000E6940; }

l40000000000E6920:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r55; nop.m	0x0; nop.i	0x0 }

l40000000000E6940:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r37; nop.i	0x0; }
	{ (p07) st4	[r52],r37; cmp4.eq	p06,p07,0x0,r51; (p07) br.cond.dpnt.few	40000000000E6D40 }

l40000000000E6956:
	{ (p03) chk.a.clr	f0,3FFFFFFFFFDAA486; nop; (p32) nop }

l40000000000E6960:
	{ adds	r14,0x50,r32; adds	r57,0x0,r44; adds	r59,0x0,r34; }
	{ nop.m	0x0; ld8	r58,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r58; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E6A60; }

l40000000000E6990:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,filter_stringlist; }
	{ cmp.eq	p09,p08,0x0,r44; cmp.eq	p07,p06,r8,r44; adds	r38,0x0,r8 }
	{ adds	r1,0x0,r55; (p06) addl	r15,1,r0; (p08) addl	r14,1,r0; }

l40000000000E69BC:
	{ cmp4.eq.or.andcm	p00,p35,r0,r72; (p01) cmp.lt	p00,p48,0x0,r64; Invalid; }

l40000000000E69C0:
	{ (p07) adds	r15,0x0,r0; (p09) adds	r14,0x0,r0; and	r14,r14,r15; }

l40000000000E69C6:
	{ Invalid; (p07) nop; break.i	0x80000 }

l40000000000E69CC:
	{ (p07) nop; cmp.lt	p00,p00,r32,r0; czx1.r	r64,r97; }
	{ Invalid; padd2	r0,r32,r0; (p05) mov	pr,r2,0x8400 }

l40000000000E69EC:
	{ (p04) nop; nop; Invalid }

l40000000000E69F0:
	{ nop.m	0x0; ld8	r57,[r44]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r57; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E6A30; }

l40000000000E6A10:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r55; nop.m	0x0; nop.i	0x0 }

l40000000000E6A30:
	{ nop.m	0x0; adds	r57,0x0,r44; adds	r44,0x0,r38 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r55; nop.m	0x0; nop.i	0x0 }

l40000000000E6A60:
	{ adds	r14,0x28,r32; nop.m	0x0; adds	r57,0x0,r44; }
	{ ld8	r58,[r14]; adds	r14,0x30,r32; cmp.eq	p06,p07,0x0,r58 }
	{ ld8	r59,[r14]; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000E6D80; }

l40000000000E6A90:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strlist_prefix_suffix; }
	{ nop.m	0x0; adds	r1,0x0,r55; adds	r44,0x0,r8; }

l40000000000E6AB0:
	{ adds	r14,0xC,r44; nop.m	0x0; adds	r32,0x10,r32 }
	{ cmp.eq	p06,p07,0x0,r44; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000E6AF0; }

l40000000000E6AD0:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000E6B50 }

l40000000000E6AF0:
	{ nop.m	0x0; ld8	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x3; (p07) br.cond.dpnt.few	40000000000E7350; }

l40000000000E6B10:
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x6; (p07) br.cond.dpnt.few	40000000000E6DB0; }

l40000000000E6B20:
	{ adds	r8,0x0,r44; mov	pr,r56,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r54; }
	{ nop.m	0x0; mov.spnt	b0,r53,40000000000E6B30; nop.i	0x0 }
	{ adds	r12,0x70,r12; nop.m	0x0; br.ret	b0 }

l40000000000E6B50:
	{ nop.m	0x0; ld8	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x6; (p06) br.cond.dptk.few	40000000000E6B20 }

l40000000000E6B70:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E6DB0 }

l40000000000E6B80:
	{ addl	r58,-556,r1; addl	r59,5,r0; adds	r57,0x0,r0; }
	{ ld8	r58,[r58]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r58,0x0,r38; nop.m	0x0; adds	r57,0x0,r8 }
	{ adds	r1,0x0,r55; nop.m	0x0; br.call.sptk.many	b0,internal_error; }
	{ adds	r1,0x0,r55; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB60; }
	{ nop.m	0x0; adds	r1,0x0,r55; br.call.sptk.many	b0,fn400000000001BA20; }
	{ adds	r1,0x0,r55; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000E6C00:
	{ nop.m	0x0; adds	r51,0x0,r0; addl	r52,1,r0 }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r42; (p06) br.cond.dptk.few	40000000000E63D0 }

l40000000000E6C20:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E6410; }

l40000000000E6C30:
	{ nop.m	0x0; tbit.z	p07,p06,r41,0x8; (p06) br.cond.dptk.few	40000000000E6360; }

l40000000000E6C40:
	{ adds	r43,0x10,r38; cmp.eq	p06,p07,0x0,r38; (p06) br.cond.dpnt.few	40000000000E6360; }

l40000000000E6C50:
	{ nop.m	0x0; ld4	r14,[r43]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000E6360 }

l40000000000E6C70:
	{ adds	r57,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,strlist_create; }
	{ adds	r1,0x0,r55; nop.m	0x0; adds	r42,0x0,r8 }
	{ adds	r57,0x0,r38; nop.m	0x0; br.call.sptk.many	b0,array_to_argv; }
	{ adds	r1,0x0,r55; nop.m	0x0; adds	r14,0x0,r42 }
	{ ld4	r15,[r43]; nop.m	0x0; adds	r16,0xC,r42; }
	{ nop.m	0x0; st8	[r14],r8,8; addl	r57,-540,r1 }
	{ st4	[r15],r16; st4	[r15],r14; nop.i	0x0 }
	{ ld8	r57,[r57]; nop.m	0x0; br.call.sptk.many	b0,unbind_variable; }
	{ nop.m	0x0; adds	r1,0x0,r55; br.cond.sptk.few	40000000000E6390 }

l40000000000E6D00:
	{ nop.m	0x0; ld8	r14,[r50]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	40000000000E6030; }

l40000000000E6D20:
	{ cmp.eq	p06,p07,0x0,r37; adds	r51,0x0,r0; addl	r52,1,r0; }
	{ (p07) st4	[r52],r37; cmp4.eq	p06,p07,0x0,r51; (p06) br.cond.dptk.few	40000000000E6960 }

l40000000000E6D36:
	{ (p03) chk.a.clr	r0,3FFFFFFFFFDAA866; nop; (p16) nop }

l40000000000E6D40:
	{ adds	r57,0x0,r44; adds	r44,0x0,r0; br.call.sptk.many	b0,strlist_dispose; }
	{ adds	r8,0x0,r44; adds	r1,0x0,r55; mov	pr,r56,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r54; mov.spnt	b0,r53,40000000000E6D60 }
	{ nop.m	0x0; adds	r12,0x70,r12; br.ret	b0 }

l40000000000E6D80:
	{ cmp.eq	p06,p07,0x0,r59; adds	r57,0x0,r44; (p06) br.cond.dpnt.few	40000000000E6AB0; }

l40000000000E6D90:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strlist_prefix_suffix; }
	{ adds	r1,0x0,r55; adds	r44,0x0,r8; br.cond.sptk.few	40000000000E6AB0 }

l40000000000E6DB0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,compspec_create; }
	{ addl	r15,32,r0; adds	r14,0x8,r8; adds	r1,0x0,r55 }
	{ adds	r38,0x0,r8; adds	r58,0x0,r34; adds	r57,0x0,r8; }
	{ st8	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,fn40000000000E4B40; }
	{ adds	r1,0x0,r55; adds	r58,0x0,r8; nop.i	0x0 }
	{ adds	r39,0x0,r8; adds	r57,0x0,r44; br.call.sptk.many	b0,strlist_append; }
	{ adds	r1,0x0,r55; nop.m	0x0; adds	r44,0x0,r8 }
	{ adds	r57,0x0,r39; nop.m	0x0; br.call.sptk.many	b0,strlist_dispose; }
	{ adds	r1,0x0,r55; adds	r57,0x0,r38; br.call.sptk.many	b0,compspec_dispose; }
	{ adds	r8,0x0,r44; adds	r1,0x0,r55; mov	pr,r56,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r54; mov.spnt	b0,r53,40000000000E6E50 }
	{ nop.m	0x0; adds	r12,0x70,r12; br.ret	b0 }

l40000000000E6E70:
	{ nop.m	0x0; adds	r8,0x0,r0; br.cond.sptk.few	40000000000E5E20 }

l40000000000E6E80:
	{ ld8	r15,[r39]; ld1	r14,[r43]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r16,r14; nop.i	0x0; }
	{ ld8	r41,[r15]; ld1	r14,[r41]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r16; (p06) br.cond.dptk.few	40000000000E5F20 }

l40000000000E6ED0:
	{ adds	r57,0x0,r41; nop.m	0x0; adds	r58,0x0,r43 }
	{ adds	r59,0x0,r47; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C020; }
	{ nop.m	0x0; sxt4	r14,r40; adds	r1,0x0,r55 }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	40000000000E5F20 }

l40000000000E6F10:
	{ ld8	r42,[r45]; nop.m	0x0; adds	r57,0x0,r41; }
	{ shladd	r42,r14,0x3,r42; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r55; adds	r57,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r14,[r39]; adds	r1,0x0,r55; adds	r57,0x0,r8; }
	{ ld8	r58,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; adds	r1,0x0,r55; br.cond.sptk.few	40000000000E5F10 }

l40000000000E6F70:
	{ adds	r57,0x0,r8; cmp4.eq	p16,p17,0x0,r41; br.call.sptk.many	b0,convert_var_to_array; }
	{ adds	r14,0x28,r8; addl	r16,-4097,r0; adds	r8,0x8,r8 }
	{ adds	r1,0x0,r55; ld4	r15,[r14]; nop.i	0x0 }
	{ ld8	r38,[r8]; and	r15,r16,r15; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; (p16) br.cond.dptk.few	40000000000E6360 }

l40000000000E6FC0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E6C30 }

l40000000000E6FD0:
	{ addl	r57,16,r0; nop.i	0x0; br.call.sptk.many	b0,strlist_create; }
	{ ld1	r14,[r40]; adds	r58,0x0,r0; adds	r45,0x8,r8 }
	{ adds	r1,0x0,r55; adds	r43,0x0,r8; adds	r41,0xC,r8; }
	{ nop.m	0x0; sxt1	r14,r14; sxt4	r15,r58; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	40000000000E7170; }

l40000000000E7020:
	{ cmp4.eq	p07,p06,0xA,r14; nop.m	0x0; (p07) adds	r38,0x0,r58 }

l40000000000E7030:
	{ nop.m	0x0; (p07) add	r39,r40,r15; (p07) br.cond.dpnt.few	40000000000E70B0; }

l40000000000E703C:
	{ (p04) cmp.lt	p00,p09,r64,r33; zxt1	r64,r64; break.i	0x1000 }

l40000000000E7040:
	{ adds	r38,0x0,r58; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000E7060:
	{ cmp4.eq	p07,p06,0x5C,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000E7220; }

l40000000000E7070:
	{ adds	r38,0x1,r38; nop.m	0x0; sxt4	r15,r38; }
	{ add	r39,r40,r15; ld1	r14,[r39]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x0,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0xA,r14; (p06) br.cond.dptk.few	40000000000E7060 }

l40000000000E70B0:
	{ adds	r57,0x0,r40; adds	r59,0x0,r38; br.call.sptk.many	b0,substring; }
	{ ld4	r58,[r45]; nop.m	0x0; adds	r1,0x0,r55 }
	{ adds	r42,0x0,r8; ld4	r14,[r41]; nop.i	0x0; }
	{ adds	r16,0xFFFFFFFFFFFFFFFF,r58; cmp4.lt	p06,p07,r14,r16; sxt4	r16,r14 }
	{ adds	r14,0x1,r14; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000E72A0; }

l40000000000E7100:
	{ ld8	r15,[r43]; shladd	r15,r16,0x3,r15; nop.i	0x0; }
	{ st8	[r42],r15; st4	[r14],r41; nop.i	0x0; }
	{ ld1	r14,[r39]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0xA,r14; (p07) br.cond.dpnt.few	40000000000E7310 }

l40000000000E7140:
	{ adds	r58,0x0,r38; nop.m	0x0; nop.i	0x0; }

l40000000000E7150:
	{ nop.m	0x0; sxt4	r15,r58; nop.i	0x0 }
	{ cmp4.eq	p06,p07,0x0,r14; nop.m	0x0; (p07) br.cond.dptk.few	40000000000E7020; }

l40000000000E7170:
	{ nop.m	0x0; ld4	r15,[r41]; adds	r57,0x0,r40 }
	{ nop.m	0x0; ld8	r14,[r43]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r15,r15; shladd	r14,r15,0x3,r14; }
	{ st8	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r57,0x0,r44; nop.m	0x0; adds	r1,0x0,r55 }
	{ adds	r58,0x0,r43; nop.m	0x0; br.call.sptk.many	b0,strlist_append; }
	{ adds	r1,0x0,r55; nop.m	0x0; adds	r44,0x0,r8 }
	{ adds	r57,0x0,r43; nop.m	0x0; br.call.sptk.many	b0,strlist_dispose; }
	{ ld8	r14,[r46]; nop.m	0x0; adds	r1,0x0,r55; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.sptk.few	40000000000E68E0 }

l40000000000E7210:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E7440 }

l40000000000E7220:
	{ add	r15,r40,r15,0x1; ld1	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0xA,r14; }
	{ (p07) adds	r38,0x1,r38; adds	r38,0x1,r38; nop.i	0x0; }

l40000000000E7246:
	{ Invalid; Invalid; break.i	0x80000 }
	{ (p07) add	r0,r38,r22; (p19) nop; break.b	0x80000 }
	{ (p07) fwb; Invalid; break.i	0x80000 }
	{ (p07) add	r0,r14,r20; (p03) nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r10,3FFFFFFFFFDCA366; nop; break.b	0x80000 }

l40000000000E7290:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E70B0 }

l40000000000E72A0:
	{ adds	r57,0x0,r43; adds	r58,0x10,r58; br.call.sptk.many	b0,strlist_resize; }
	{ nop.m	0x0; ld4	r14,[r41]; adds	r1,0x0,r55 }
	{ ld8	r15,[r43]; nop.i	0x0; sxt4	r16,r14 }
	{ adds	r14,0x1,r14; shladd	r15,r16,0x3,r15; nop.i	0x0; }
	{ st8	[r42],r15; st4	[r14],r41; nop.i	0x0; }
	{ ld1	r14,[r39]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0xA,r14; (p06) br.cond.dptk.few	40000000000E7140 }

l40000000000E7310:
	{ nop.m	0x0; sxt4	r15,r38; add	r15,r40,r15,0x1; }

l40000000000E7320:
	{ ld1	r14,[r15],1; nop.m	0x0; adds	r38,0x1,r38; }
	{ nop.m	0x0; sxt1	r14,r14; adds	r58,0x0,r38; }
	{ cmp4.eq	p06,p07,0xA,r14; (p06) br.cond.dpnt.few	40000000000E7320; br.cond.sptk.few	40000000000E7150 }

l40000000000E734C:
	{ Invalid; break.i	0x1000; break.b	0x1000 }

l40000000000E7350:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,compspec_create; }
	{ addl	r15,32,r0; adds	r14,0x8,r8; adds	r1,0x0,r55 }
	{ adds	r38,0x0,r8; adds	r58,0x0,r34; adds	r57,0x0,r8; }
	{ st8	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,fn40000000000E4B40; }
	{ adds	r1,0x0,r55; nop.m	0x0; adds	r44,0x0,r8 }
	{ adds	r57,0x0,r38; nop.m	0x0; br.call.sptk.many	b0,compspec_dispose; }
	{ adds	r8,0x0,r44; adds	r1,0x0,r55; mov	pr,r56,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r54; mov.spnt	b0,r53,40000000000E73C0 }
	{ nop.m	0x0; adds	r12,0x70,r12; br.ret	b0; }

l40000000000E73E0:
	{ adds	r57,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,dispose_word_desc; }
	{ adds	r1,0x0,r55; adds	r57,0x0,r49; br.call.sptk.many	b0,dispose_words; }
	{ adds	r1,0x0,r55; adds	r57,0x0,r41; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r55; addl	r57,1,r0; br.call.sptk.many	b0,fn40000000000E30C0; }
	{ ld8	r14,[r46]; nop.m	0x0; adds	r1,0x0,r55; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.sptk.few	40000000000E68E0; }

l40000000000E7440:
	{ nop.m	0x0; ld8	r14,[r50]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; (p07) br.cond.sptk.few	40000000000E68E0 }

l40000000000E7460:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E6940 }

l40000000000E7470:
	{ adds	r16,0x0,r0; adds	r40,0x0,r0; br.cond.sptk.few	40000000000E5F50 }

l40000000000E7480:
	{ cmp4.eq	p16,p17,0x0,r41; nop.m	0x0; adds	r42,0x0,r0; }
	{ (p17) addl	r51,256,r0; nop.m	0x0; (p17) adds	r52,0x0,r41; }

l40000000000E7496:
	{ nop; (p26) nop; dep	r0,r0,r32,63,1 }

l40000000000E74A0:
	{ nop.m	0x0; (p17) and	r51,r51,r41; (p17) br.cond.dptk.few	40000000000E63C0 }

l40000000000E74AC:
	{ (p57) invala; break.i	0x1000; break.i	0x1000 }

l40000000000E74B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E6C00 }

l40000000000E74C0:
	{ nop.m	0x0; ld8	r39,[r49]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r39; br.cond.sptk.few	40000000000E6670; }
40000000000E74E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E74F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000E7500: 40000000000E7500
;;   Called from:
;;     40000000000E795C (in programmable_completions)
;;     40000000000E7A1C (in programmable_completions)
;;     40000000000E7BAC (in programmable_completions)
fn40000000000E7500 proc
	{ alloc	r47,ar.pfs,0x17,0x0,0x11; nop.m	0x0; mov	r46,b6 }
	{ adds	r48,0x0,r1; nop.m	0x0; adds	r49,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,progcomp_search; }
	{ adds	r1,0x0,r48; nop.m	0x0; cmp.eq	p06,p07,0x0,r8 }
	{ adds	r40,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000E7750; }

l40000000000E7550:
	{ nop.m	0x0; ld8	r49,[r39]; nop.i	0x0; }
	{ cmp.eq	p06,p07,r8,r49; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E7750; }

l40000000000E7570:
	{ cmp.eq	p06,p07,0x0,r49; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E75A0; }

l40000000000E7580:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,compspec_dispose; }
	{ adds	r1,0x0,r48; nop.m	0x0; nop.i	0x0; }

l40000000000E75A0:
	{ ld4	r14,[r40]; nop.m	0x0; addl	r42,9220,r1 }
	{ addl	r41,9212,r1; adds	r49,0x0,r40; adds	r14,0x1,r14 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; st4	[r14],r40; nop.i	0x0 }
	{ st8	[r40],r39; nop.m	0x0; br.call.sptk.many	b0,compspec_copy; }
	{ adds	r1,0x0,r48; adds	r40,0x0,r8; adds	r49,0x0,r8 }
	{ ld8	r45,[r42]; adds	r50,0x0,r33; adds	r51,0x0,r34; }
	{ ld8	r44,[r41]; adds	r52,0x0,r35; adds	r53,0x0,r36 }
	{ st8	[r8],r42; st8	[r33],r41; adds	r54,0x0,r37; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,gen_compspec_completions; }
	{ cmp.eq	p06,p07,0x0,r38; st8	[r45],r42; adds	r1,0x0,r48 }
	{ st8	[r44],r41; adds	r43,0x0,r8; (p06) br.cond.dpnt.few	40000000000E7700; }

l40000000000E7660:
	{ cmp.eq	p06,p07,0x0,r37; nop.m	0x0; adds	r49,0x0,r40; }
	{ (p07) ld4	r14,[r37]; (p07) adds	r15,0x10,r40; (p07) addl	r16,-257,r0; }

l40000000000E7676:
	{ (p07) chk.a.clr	f16,3FFFFFFFFF1678F6; (p08) chk.s.i	r124,40000000004E6666; Invalid; }

l40000000000E767C:
	{ (p63) break.m	0x3FEFC; Invalid; (p01) nop }

l40000000000E7680:
	{ nop.m	0x0; (p07) extr.u	r14,r14,8,1; nop.i	0x0 }

l40000000000E768C:
	{ cmp4.eq.or.andcm	p00,p43,r1,r0; (p01) cmp4.ne.and	p32,p08,r3,r6; zxt1	r0,r64 }

l40000000000E7696:
	{ Invalid; nop; cmp.ne.or	p00,p36,r67,r9; }

l40000000000E769C:
	{ Invalid; (p32) cmp4.ne.and	p03,p40,r9,r100; Invalid }

l40000000000E76AC:
	{ cmp4.eq.and	p00,p43,r1,r0; (p01) cmp4.ne.and	p04,p48,r3,r3; zxt1	r67,r3 }

l40000000000E76B6:
	{ Invalid; cmp4.eq	p00,p00,0x0,r1; (p01) nop; }

l40000000000E76BC:
	{ Invalid; Invalid; (p08) mov.i	KR0,0x0 }

l40000000000E76C6:
	{ (p32) mov.m	KR0,0x0; nop; (p16) nop }
	{ break.m	0x4000; nop; nop }

l40000000000E76E0:
	{ adds	r8,0x0,r43; nop.m	0x0; mov.i	ar.pfs,r47; }
	{ nop.m	0x0; mov.spnt	b0,r46,40000000000E76F0; br.ret	b0 }

l40000000000E7700:
	{ cmp.eq	p06,p07,0x0,r37; nop.m	0x0; adds	r49,0x0,r40; }
	{ (p07) ld4	r14,[r37]; (p07) adds	r15,0x10,r40; (p07) addl	r16,-257,r0; }

l40000000000E7716:
	{ (p07) chk.a.clr	f16,3FFFFFFFFF167996; (p08) cmp4.ne.and	p63,p15,0x7C,r125; Invalid; }

l40000000000E771C:
	{ (p63) cmp4.ne.or.andcm	p60,p35,r125,r79; Invalid; Invalid }

l40000000000E7720:
	{ (p07) ld8	r15,[r15]; (p07) and	r14,r16,r14; (p07) or	r14,r15,r14; }

l40000000000E7726:
	{ (p07) chk.a.clr	f16,3FFFFFFFFF0ED806; (p07) cmp4.eq.or.andcm	p15,p00,r14,r14; (p01) nop; }

l40000000000E772C:
	{ Invalid; Invalid; break.b	0x1000; }

l40000000000E7730:
	{ (p07) st4	[r14],r37; nop.i	0x0; br.call.sptk.many	b0,compspec_dispose; }

l40000000000E7736:
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; nop; (p48) nop.b	0xA }

l40000000000E7750:
	{ adds	r43,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r47; }
	{ adds	r8,0x0,r43; mov.spnt	b0,r46,40000000000E7760; br.ret	b0; }
40000000000E7770 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; pcomp_set_readline_variables: 40000000000E7780
;;   Called from:
;;     400000000011E51C (in compopt_builtin)
;;     400000000011E51C (in compopt_builtin)
;;     400000000011E53C (in compopt_builtin)
;;     400000000011E53C (in compopt_builtin)
pcomp_set_readline_variables proc
	{ nop.m	0x0; tbit.z	p06,p07,r32,0x2; (p07) addl	r14,-10172,r1; }

l40000000000E7790:
	{ (p07) ld8	r14,[r14]; (p07) st4	[r33],r14; tbit.z	p06,p07,r32,0x4; }

l40000000000E7796:
	{ mf.a; (p03) cmp4.ltu	p08,p40,0x20,r7; (p33) cmp4.eq.or.andcm	p03,p44,0x29,r63; }

l40000000000E779C:
	{ (p04) cmp4.eq.and	p32,p43,r7,r40; (p01) cmp4.eq.and	p41,p51,r63,r108; Invalid }

l40000000000E77A6:
	{ (p07) fwb; cmp4.eq	p00,p00,r0,r1; (p01) nop; }

l40000000000E77AC:
	{ Invalid; Invalid; add	r0,r32,r0 }

l40000000000E77B6:
	{ break.m	0x4000; (p34) nop; (p48) nop }

;; pcomp_set_compspec_options: 40000000000E77C0
;;   Called from:
;;     400000000011E4DC (in compopt_builtin)
;;     400000000011E4DC (in compopt_builtin)
;;     400000000011E4FC (in compopt_builtin)
;;     400000000011E4FC (in compopt_builtin)
;;     400000000011E80C (in compopt_builtin)
;;     400000000011E82C (in compopt_builtin)
pcomp_set_compspec_options proc
	{ cmp.eq	p07,p06,0x0,r32; nop.m	0x0; andcm	r15,0xFFFFFFFFFFFFFFFF,r33 }
	{ adds	r14,0x10,r32; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000E7830; }

l40000000000E77E0:
	{ cmp4.eq	p06,p07,0x0,r34; nop.m	0x0; sxt4	r15,r15; }
	{ (p07) adds	r32,0x0,r14; (p06) ld8	r16,[r14]; sxt4	r33,r33; }

l40000000000E77F6:
	{ (p08) addp4	r0,0xFFFFFFFFFFFFF00E,r24; (p16) cmp4.ltu	p00,p00,r33,r22; (p33) nop; }

l40000000000E77FC:
	{ cmp4.eq.and	p33,p41,r22,r0; nop }

l40000000000E7806:
	{ adds	r0,0xFFFFFFFFFFFFE000,r1; (p07) cmp.eq.and	p16,p00,0xF,r12; (p33) nop }

l40000000000E7810:
	{ (p07) or	r14,r14,r33; nop.i	0x0; nop.i	0x0 }

l40000000000E7816:
	{ break.m	0x4000; nop; (p01) addl	r64,144131,r0 }

l40000000000E7826:
	{ mf.a; (p34) nop; (p32) nop; }

l40000000000E782C:
	{ cmp.lt	p00,p09,r33,r0; (p01) invala.e	r33; cmp.eq	p00,p00,r32,r0 }

l40000000000E7830:
	{ addl	r14,9220,r1; nop.m	0x0; sxt4	r15,r15; }
	{ nop.m	0x0; ld8	r32,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r32; adds	r14,0x10,r32; (p06) br.ret	b0; }

l40000000000E7860:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r34; nop.i	0x0; }
	{ (p07) adds	r32,0x0,r14; (p06) ld8	r16,[r14]; sxt4	r33,r33; }

l40000000000E7876:
	{ (p08) addp4	r0,0xFFFFFFFFFFFFF00E,r24; (p16) cmp4.ltu	p00,p00,r33,r22; (p33) nop; }

l40000000000E787C:
	{ cmp4.eq.and	p33,p41,r22,r0; nop }

l40000000000E7886:
	{ adds	r0,0xFFFFFFFFFFFFE000,r1; (p07) cmp.eq.and	p16,p00,0xF,r12; (p33) nop }

l40000000000E7890:
	{ (p07) or	r14,r14,r33; nop.i	0x0; nop.i	0x0 }

l40000000000E7896:
	{ break.m	0x4000; nop; (p01) addl	r64,144131,r0 }

l40000000000E78A6:
	{ mf.a; (p34) nop; break.i	0x80000; }

l40000000000E78AC:
	{ nop; break.m	0x1000; break.i	0x1000 }
40000000000E78B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; programmable_completions: 40000000000E78C0
programmable_completions proc
	{ alloc	r40,ar.pfs,0x13,0x0,0xB; adds	r12,0xFFFFFFFFFFFFFFE0,r12; mov	r39,b7 }
	{ nop.m	0x0; adds	r41,0x0,r1; nop.i	0x0; }
	{ adds	r38,0x10,r12; adds	r37,0x18,r12; mov	r42,LC; }
	{ st8	[r38],r12,12; mov.i	LC,0x20; nop.i	0x0; }
	{ st4	[r0],r38; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000E7920:
	{ adds	r43,0x0,r32; adds	r44,0x0,r32; adds	r45,0x0,r33 }
	{ adds	r46,0x0,r34; adds	r47,0x0,r35; adds	r48,0x0,r38; }
	{ adds	r49,0x0,r37; nop.m	0x0; adds	r50,0x10,r12 }
	{ st4	[r0],r37; nop.m	0x0; br.call.sptk.many	b0,fn40000000000E7500; }
	{ ld4	r14,[r38]; nop.m	0x0; adds	r43,0x0,r32 }
	{ addl	r44,47,r0; nop.m	0x0; adds	r1,0x0,r41; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000E7A30 }

l40000000000E7990:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BEA0; }
	{ adds	r43,0x1,r8; nop.m	0x0; adds	r1,0x0,r41 }
	{ cmp.eq	p07,p06,0x0,r8; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000E79E0; }

l40000000000E79C0:
	{ ld1	r14,[r43]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000E7B80 }

l40000000000E79E0:
	{ addl	r43,-532,r1; adds	r44,0x0,r32; adds	r45,0x0,r33 }
	{ adds	r46,0x0,r34; adds	r47,0x0,r35; adds	r48,0x0,r38; }
	{ ld8	r43,[r43]; nop.m	0x0; adds	r49,0x0,r37 }
	{ adds	r50,0x10,r12; nop.m	0x0; br.call.sptk.many	b0,fn40000000000E7500; }
	{ adds	r1,0x0,r41; nop.m	0x0; nop.i	0x0 }

l40000000000E7A30:
	{ nop.m	0x0; nop.i	0x0; br.cloop.sptk.few	40000000000E7B50; }

l40000000000E7A40:
	{ addl	r43,-524,r1; adds	r14,0x20,r12; adds	r44,0x0,r32; }
	{ nop.m	0x0; st8	[r8],r14; nop.i	0x0 }
	{ ld8	r43,[r43]; nop.m	0x0; br.call.sptk.many	b0,internal_warning; }
	{ adds	r14,0x20,r12; nop.m	0x0; adds	r1,0x0,r41; }
	{ ld8	r8,[r14]; nop.m	0x0; nop.i	0x0; }

l40000000000E7A90:
	{ cmp.eq	p06,p07,0x0,r8; nop.m	0x0; adds	r43,0x0,r8; }
	{ (p06) adds	r37,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E7AD0; }

l40000000000E7AA6:
	{ chk.a.nc	r0,3FFFFFFFFF0E82A6; nop; (p16) nop }

l40000000000E7AB0:
	{ ld8	r37,[r8]; br.call.sptk.many	b0,fn400000000001A7E0; nop.b	0x0; }
	{ adds	r1,0x0,r41; nop.m	0x0; nop.i	0x0 }

l40000000000E7AD0:
	{ adds	r14,0x10,r12; nop.m	0x0; cmp.eq	p06,p07,0x0,r36; }
	{ ld8	r43,[r14]; (p07) ld4	r14,[r38]; nop.i	0x0; }

l40000000000E7AEC:
	{ Invalid; (p32) cmp.lt	p03,p08,r9,r100; mov	pr,r106,0xE4C0 }

l40000000000E7AF6:
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD6B5A6; nop; break.i	0x80000 }

l40000000000E7B00:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,compspec_dispose; }
	{ adds	r1,0x0,r41; nop.m	0x0; nop.i	0x0 }

l40000000000E7B20:
	{ adds	r8,0x0,r37; mov.i	ar.pfs,r40; mov.i	LC,r42; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000E7B30; nop.i	0x0 }
	{ adds	r12,0x20,r12; nop.m	0x0; br.ret	b0 }

l40000000000E7B50:
	{ nop.m	0x0; ld4	r14,[r37]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000E7920 }

l40000000000E7B70:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E7A90 }

l40000000000E7B80:
	{ adds	r44,0x0,r32; adds	r45,0x0,r33; adds	r46,0x0,r34 }
	{ adds	r47,0x0,r35; adds	r48,0x0,r38; adds	r49,0x0,r37; }
	{ adds	r50,0x10,r12; nop.i	0x0; br.call.sptk.many	b0,fn40000000000E7500; }
	{ ld4	r14,[r38]; nop.m	0x0; adds	r1,0x0,r41; }
	{ cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.spnt.few	40000000000E79E0; br.cloop.sptk.few	40000000000E7B50 }

l40000000000E7BCC:
	{ Invalid; break.i	0x1000; break.b	0x1000 }

l40000000000E7BD0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E7A40; }
40000000000E7BE0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000E7BF0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; compspec_create: 40000000000E7C00
;;   Called from:
;;     40000000000E6DBC (in gen_compspec_completions)
;;     40000000000E735C (in gen_compspec_completions)
;;     400000000011D3AC (in complete_builtin)
;;     400000000011DB5C (in compgen_builtin)
compspec_create proc
	{ alloc	r33,ar.pfs,0x4,0x0,0x3; mov	r32,b0; adds	r34,0x0,r1; }
	{ addl	r35,88,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r15,0x0,r8; adds	r23,0x10,r8; adds	r22,0x18,r8 }
	{ adds	r21,0x20,r8; adds	r20,0x28,r8; adds	r19,0x30,r8; }
	{ st4	[r15],r8,8; adds	r18,0x38,r8; adds	r17,0x40,r8 }
	{ adds	r16,0x48,r8; adds	r14,0x50,r8; adds	r1,0x0,r34; }
	{ st8	[r0],r23; st8	[r0],r15; mov.i	ar.pfs,r33; }
	{ st8	[r0],r22; st8	[r0],r21; mov.spnt	b0,r32,40000000000E7C70; }
	{ st8	[r0],r20; st8	[r0],r19; nop.i	0x0; }
	{ st8	[r0],r18; st8	[r0],r17; nop.i	0x0; }
	{ nop.m	0x0; st8	[r0],r16; nop.i	0x0 }
	{ st8	[r0],r14; nop.m	0x0; br.ret	b0; }

;; compspec_dispose: 40000000000E7CC0
;;   Called from:
;;     40000000000E6E3C (in gen_compspec_completions)
;;     40000000000E73AC (in gen_compspec_completions)
;;     40000000000E758C (in fn40000000000E7500)
;;     40000000000E76C6 (in fn40000000000E7500)
;;     40000000000E773C (in fn40000000000E7500)
;;     40000000000E7B0C (in programmable_completions)
;;     40000000000E86FC (in progcomp_remove)
;;     40000000000E882C (in progcomp_insert)
;;     400000000011DFFC (in compgen_builtin)
;;     400000000011E0CC (in compgen_builtin)
compspec_dispose proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; ld4	r14,[r32]; mov	r33,b1 }
	{ nop.m	0x0; adds	r35,0x0,r1; nop.i	0x0; }
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r14; st4	[r14],r32; cmp4.eq	p07,p06,0x0,r14 }
	{ adds	r14,0x18,r32; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000E7F20; }

l40000000000E7D00:
	{ nop.m	0x0; ld8	r36,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r36; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E7D40; }

l40000000000E7D20:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l40000000000E7D40:
	{ adds	r14,0x20,r32; ld8	r36,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r36; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E7D80; }

l40000000000E7D60:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l40000000000E7D80:
	{ adds	r14,0x28,r32; ld8	r36,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r36; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E7DC0; }

l40000000000E7DA0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l40000000000E7DC0:
	{ adds	r14,0x30,r32; ld8	r36,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r36; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E7E00; }

l40000000000E7DE0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l40000000000E7E00:
	{ adds	r14,0x38,r32; ld8	r36,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r36; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E7E40; }

l40000000000E7E20:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l40000000000E7E40:
	{ adds	r14,0x40,r32; ld8	r36,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r36; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E7E80; }

l40000000000E7E60:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l40000000000E7E80:
	{ adds	r14,0x48,r32; ld8	r36,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r36; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E7EC0; }

l40000000000E7EA0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l40000000000E7EC0:
	{ adds	r14,0x50,r32; ld8	r36,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r36; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E7F00; }

l40000000000E7EE0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l40000000000E7F00:
	{ nop.m	0x0; adds	r36,0x0,r32; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l40000000000E7F20:
	{ nop.m	0x0; mov.i	ar.pfs,r34; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000E7F30; br.ret	b0; }
40000000000E7F40 11 10 04 00 80 05 00 00 00 02 00 00 88 FD FF 48 ...............H
40000000000E7F50 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000E7F60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E7F70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; compspec_copy: 40000000000E7F80
;;   Called from:
;;     40000000000E75EC (in fn40000000000E7500)
compspec_copy proc
	{ alloc	r36,ar.pfs,0x8,0x0,0x6; adds	r37,0x0,r1; mov	r35,b3 }
	{ nop.m	0x0; adds	r34,0x18,r32; nop.i	0x0; }
	{ addl	r38,88,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r38,[r34]; adds	r15,0x0,r32; adds	r14,0x0,r8 }
	{ adds	r16,0x10,r32; adds	r17,0x10,r8; adds	r33,0x0,r8; }
	{ cmp.eq	p06,p07,0x0,r38; ld4	r18,[r15],8; adds	r1,0x0,r37 }
	{ nop.m	0x0; ld8	r16,[r16]; nop.i	0x0; }
	{ st4	[r14],r8,8; ld8	r15,[r15]; (p06) adds	r8,0x0,r0 }

l40000000000E8000:
	{ nop.m	0x0; st8	[r16],r17; nop.i	0x0; }
	{ st8	[r15],r14; (p06) br.cond.dpnt.few	40000000000E8060; br.call.sptk.many	b0,fn400000000001B6C0; }

l40000000000E801C:
	{ (p53) nop; cmp.lt	p32,p16,r9,r64; (p20) epc }
	{ (p37) nop; invala; cmp.lt	p00,p00,r32,r0 }
	{ cmp.eq	p08,p25,r0,r66; break.x	0x80C2200801000 }
	{ (p10) nop; invala; break.i	0x1000 }
	{ cmpxchg2.acq	r0,[r0],r1; zxt1	r8,r64; cmp.lt	p00,p00,r32,r0 }

l40000000000E8060:
	{ adds	r34,0x20,r32; nop.m	0x0; adds	r14,0x18,r33; }
	{ ld8	r38,[r34]; st8	[r8],r14; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r38; nop.i	0x0; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E80F0; }

l40000000000E8096:
	{ chk.a.nc	r0,3FFFFFFFFF0E8896; nop; break.i	0x80000 }

l40000000000E80A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r37; adds	r38,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r38,0x0,r8 }
	{ ld8	r39,[r34]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r37; nop.m	0x0; nop.i	0x0 }

l40000000000E80F0:
	{ adds	r34,0x28,r32; nop.m	0x0; adds	r14,0x20,r33; }
	{ ld8	r38,[r34]; st8	[r8],r14; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r38; nop.i	0x0; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E8180; }

l40000000000E8126:
	{ chk.a.nc	r0,3FFFFFFFFF0E8926; nop; break.i	0x80000 }

l40000000000E8130:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r37; adds	r38,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r38,0x0,r8 }
	{ ld8	r39,[r34]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r37; nop.m	0x0; nop.i	0x0 }

l40000000000E8180:
	{ adds	r34,0x30,r32; nop.m	0x0; adds	r14,0x28,r33; }
	{ ld8	r38,[r34]; st8	[r8],r14; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r38; nop.i	0x0; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E8210; }

l40000000000E81B6:
	{ chk.a.nc	r0,3FFFFFFFFF0E89B6; nop; break.i	0x80000 }

l40000000000E81C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r37; adds	r38,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r38,0x0,r8 }
	{ ld8	r39,[r34]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r37; nop.m	0x0; nop.i	0x0 }

l40000000000E8210:
	{ adds	r34,0x38,r32; nop.m	0x0; adds	r14,0x30,r33; }
	{ ld8	r38,[r34]; st8	[r8],r14; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r38; nop.i	0x0; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E82A0; }

l40000000000E8246:
	{ chk.a.nc	r0,3FFFFFFFFF0E8A46; nop; break.i	0x80000 }

l40000000000E8250:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r37; adds	r38,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r38,0x0,r8 }
	{ ld8	r39,[r34]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r37; nop.m	0x0; nop.i	0x0 }

l40000000000E82A0:
	{ adds	r34,0x40,r32; nop.m	0x0; adds	r14,0x38,r33; }
	{ ld8	r38,[r34]; st8	[r8],r14; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r38; nop.i	0x0; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E8330; }

l40000000000E82D6:
	{ chk.a.nc	r0,3FFFFFFFFF0E8AD6; nop; break.i	0x80000 }

l40000000000E82E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r37; adds	r38,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r38,0x0,r8 }
	{ ld8	r39,[r34]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r37; nop.m	0x0; nop.i	0x0 }

l40000000000E8330:
	{ adds	r34,0x48,r32; nop.m	0x0; adds	r14,0x40,r33; }
	{ ld8	r38,[r34]; st8	[r8],r14; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r38; nop.i	0x0; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E83C0; }

l40000000000E8366:
	{ chk.a.nc	r0,3FFFFFFFFF0E8B66; nop; break.i	0x80000 }

l40000000000E8370:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r37; adds	r38,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r38,0x0,r8 }
	{ ld8	r39,[r34]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r37; nop.m	0x0; nop.i	0x0 }

l40000000000E83C0:
	{ adds	r32,0x50,r32; nop.m	0x0; adds	r14,0x48,r33; }
	{ ld8	r38,[r32]; st8	[r8],r14; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r38; nop.i	0x0; }
	{ (p06) adds	r15,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E8450; }

l40000000000E83F6:
	{ chk.a.nc	r0,3FFFFFFFFF0E8BF6; nop; break.i	0x80000 }

l40000000000E8400:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r37; adds	r38,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r38,0x0,r8 }
	{ ld8	r39,[r32]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; adds	r1,0x0,r37; adds	r15,0x0,r8 }

l40000000000E8450:
	{ adds	r14,0x50,r33; adds	r8,0x0,r33; mov.i	ar.pfs,r36; }
	{ st8	[r15],r14; mov.spnt	b0,r35,40000000000E8460; br.ret	b0; }
40000000000E8470 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; progcomp_create: 40000000000E8480
;;   Called from:
;;     40000000000E88DC (in progcomp_insert)
progcomp_create proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; mov	r33,b1; addl	r32,8324,r1 }
	{ adds	r35,0x0,r1; ld8	r14,[r32]; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; mov.spnt	b0,r33,40000000000E84A0 }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	40000000000E84C0; br.ret	b0; }

l40000000000E84BC:
	{ shladd	r0,r33,0x2,r0; (p04) invala.e	r8; break.i	0x1000 }

l40000000000E84C0:
	{ addl	r36,32,r0; nop.i	0x0; br.call.sptk.many	b0,hash_create; }
	{ adds	r1,0x0,r35; st8	[r8],r32; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000E84E0; br.ret	b0; }
40000000000E84F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; progcomp_size: 40000000000E8500
progcomp_size proc
	{ nop.m	0x0; addl	r14,8324,r1; nop.i	0x0; }
	{ ld8	r14,[r14]; cmp.eq	p06,p07,0x0,r14; adds	r15,0xC,r14; }
	{ nop.m	0x0; (p07) ld4	r8,[r15]; nop.i	0x0; }

l40000000000E852C:
	{ Invalid; mov	pr,r32,0x0; (p01) shladd	r0,r0,0x1,r64 }

l40000000000E853C:
	{ nop; (p20) cmp.lt.unc	p33,p02,r0,r96; zxt4	r33,r16 }

;; progcomp_flush: 40000000000E8540
;;   Called from:
;;     400000000011D8EC (in complete_builtin)
progcomp_flush proc
	{ alloc	r33,ar.pfs,0x5,0x0,0x3; addl	r14,8324,r1; nop.b	0x0 }
	{ addl	r36,-3404,r1; mov	r32,b0; adds	r34,0x0,r1; }
	{ ld8	r35,[r14]; ld8	r36,[r36]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r35; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E85A0; }

l40000000000E8580:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,hash_flush; }
	{ adds	r1,0x0,r34; nop.m	0x0; nop.i	0x0 }

l40000000000E85A0:
	{ nop.m	0x0; mov.i	ar.pfs,r33; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r32,40000000000E85B0; br.ret	b0; }

;; progcomp_dispose: 40000000000E85C0
progcomp_dispose proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; addl	r32,8324,r1; mov	r33,b1 }
	{ adds	r35,0x0,r1; ld8	r36,[r32]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r36; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E8610; }

l40000000000E85F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,hash_dispose; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l40000000000E8610:
	{ st8	[r0],r32; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000E8620; br.ret	b0; }
40000000000E8630 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; progcomp_remove: 40000000000E8640
;;   Called from:
;;     400000000011CADC (in fn400000000011CA80)
progcomp_remove proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; addl	r14,8324,r1; mov	r34,b2 }
	{ adds	r36,0x0,r1; nop.m	0x0; adds	r37,0x0,r32; }
	{ ld8	r14,[r14]; nop.m	0x0; adds	r39,0x0,r0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.m	0x0; adds	r38,0x0,r14; }
	{ (p06) addl	r8,1,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E8750; }

l40000000000E8686:
	{ chk.a.nc	r0,3FFFFFFFFF0E8E86; nop; break.i	0x80000 }

l40000000000E8690:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,hash_remove; }
	{ cmp.eq	p06,p07,0x0,r8; nop.m	0x0; adds	r14,0x10,r8 }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r33,0x0,r8; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E8750; }

l40000000000E86C6:
	{ chk.a.nc	r0,3FFFFFFFFF0E8EC6; nop; break.i	0x80000 }

l40000000000E86D0:
	{ nop.m	0x0; ld8	r37,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r37; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E8710; }

l40000000000E86F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,compspec_dispose; }
	{ adds	r1,0x0,r36; nop.m	0x0; nop.i	0x0 }

l40000000000E8710:
	{ nop.m	0x0; adds	r14,0x8,r33; nop.i	0x0; }
	{ ld8	r37,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r36; adds	r37,0x0,r33; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r36; addl	r8,1,r0 }

l40000000000E8750:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000E8760; br.ret	b0; }
40000000000E8770 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; progcomp_insert: 40000000000E8780
;;   Called from:
;;     400000000011D7AC (in complete_builtin)
progcomp_insert proc
	{ alloc	r37,ar.pfs,0xA,0x0,0x7; addl	r34,8324,r1; mov	r36,b4 }
	{ adds	r38,0x0,r1; cmp.eq	p07,p06,0x0,r33; (p07) br.cond.dpnt.few	40000000000E8900; }

l40000000000E87A0:
	{ nop.m	0x0; ld8	r40,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r40; (p07) br.cond.dpnt.few	40000000000E88D0 }

l40000000000E87C0:
	{ ld4	r14,[r33]; adds	r41,0x0,r0; adds	r39,0x0,r32; }
	{ nop.m	0x0; adds	r14,0x1,r14; nop.i	0x0; }
	{ st4	[r14],r33; nop.i	0x0; br.call.sptk.many	b0,hash_insert; }
	{ adds	r34,0x10,r8; adds	r1,0x0,r38; adds	r35,0x0,r8; }
	{ nop.m	0x0; ld8	r39,[r34]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r39; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E8860; }

l40000000000E8820:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,compspec_dispose; }
	{ addl	r8,1,r0; adds	r1,0x0,r38; nop.b	0x0 }
	{ st8	[r33],r34; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000E8850; br.ret	b0; }

l40000000000E8860:
	{ adds	r39,0x0,r32; adds	r35,0x8,r35; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r38; adds	r39,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r38; nop.m	0x0; adds	r39,0x0,r8 }
	{ adds	r40,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r38; st8	[r8],r35; nop.b	0x0 }
	{ st8	[r33],r34; addl	r8,1,r0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000E88C0; br.ret	b0; }

l40000000000E88D0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,progcomp_create; }
	{ nop.m	0x0; adds	r1,0x0,r38; nop.i	0x0 }
	{ ld8	r40,[r34]; nop.m	0x0; br.cond.sptk.few	40000000000E87C0; }

l40000000000E8900:
	{ addl	r40,-3396,r1; addl	r41,5,r0; adds	r39,0x0,r0; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r38; nop.m	0x0; adds	r40,0x0,r32 }
	{ adds	r39,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,programming_error; }
	{ ld8	r40,[r34]; nop.m	0x0; adds	r1,0x0,r38; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r40; (p06) br.cond.dptk.few	40000000000E87C0 }

l40000000000E8960:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E88D0; }
40000000000E8970 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; progcomp_search: 40000000000E8980
;;   Called from:
;;     40000000000E752C (in fn40000000000E7500)
;;     400000000011C95C (in fn400000000011C900)
;;     400000000011E79C (in compopt_builtin)
progcomp_search proc
	{ alloc	r34,ar.pfs,0x7,0x0,0x4; addl	r14,8324,r1; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; adds	r36,0x0,r32; }
	{ ld8	r14,[r14]; nop.m	0x0; adds	r38,0x0,r0; }
	{ cmp.eq	p07,p06,0x0,r14; adds	r37,0x0,r14; (p07) br.cond.dpnt.few	40000000000E8A10; }

l40000000000E89C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,hash_search; }
	{ adds	r14,0x10,r8; cmp.eq	p06,p07,0x0,r8; nop.b	0x0 }
	{ adds	r1,0x0,r35; mov.i	ar.pfs,r34; (p06) br.cond.dpnt.few	40000000000E8A10; }

l40000000000E89F0:
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000E89F0; nop.i	0x0 }
	{ ld8	r8,[r14]; nop.m	0x0; br.ret	b0; }

l40000000000E8A10:
	{ adds	r8,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000E8A20; br.ret	b0; }
40000000000E8A30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; progcomp_walk: 40000000000E8A40
;;   Called from:
;;     400000000011D32C (in complete_builtin)
progcomp_walk proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x4; addl	r14,8324,r1; mov	r33,b1 }
	{ cmp.eq	p08,p09,0x0,r32; nop.m	0x0; adds	r35,0x0,r1; }
	{ ld8	r36,[r14]; adds	r14,0xC,r36; cmp.eq	p06,p07,0x0,r36 }
	{ nop.b	0x0; (p06) br.cond.dpnt.few	40000000000E8AA0; (p08) br.cond.dpnt.few	40000000000E8AA0; }

l40000000000E8A7C:
	{ (p01) nop; cmp.lt	p00,p00,r32,r0; (p01) rfi }

l40000000000E8A80:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000E8AC0 }

l40000000000E8AA0:
	{ nop.m	0x0; mov.i	ar.pfs,r34; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000E8AB0; br.ret	b0; }

l40000000000E8AC0:
	{ adds	r37,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,hash_walk; }
	{ adds	r1,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000E8AE0; br.ret	b0; }
40000000000E8AF0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; fn40000000000E8B00: 40000000000E8B00
;;   Called from:
;;     40000000000E8DBC (in xmalloc)
;;     40000000000E8F2C (in xrealloc)
fn40000000000E8B00 proc
	{ alloc	r37,ar.pfs,0xB,0x0,0x7; addl	r35,8332,r1; mov	r36,b4 }
	{ adds	r38,0x0,r1; nop.m	0x0; addl	r34,8340,r1; }
	{ ld4	r14,[r35]; nop.m	0x0; adds	r39,0x0,r0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000E8BD0; }

l40000000000E8B40:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BF20; }
	{ adds	r1,0x0,r38; ld8	r34,[r34]; adds	r39,0x0,r0 }
	{ addl	r41,5,r0; addl	r14,8348,r1; sub	r34,r8,r34 }
	{ addl	r40,1316,r1; st8	[r34],r14; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r38; adds	r39,0x0,r8; adds	r40,0x0,r32 }
	{ adds	r41,0x0,r33; adds	r42,0x0,r34; br.call.sptk.many	b0,fatal_error; }
	{ adds	r1,0x0,r38; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000E8BC0; br.ret	b0; }

l40000000000E8BD0:
	{ adds	r39,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BF20; }
	{ addl	r14,1,r0; nop.m	0x0; adds	r1,0x0,r38 }
	{ st8	[r8],r34; nop.m	0x0; adds	r39,0x0,r0; }
	{ st4	[r14],r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BF20; }
	{ adds	r1,0x0,r38; ld8	r34,[r34]; adds	r39,0x0,r0 }
	{ addl	r41,5,r0; addl	r14,8348,r1; sub	r34,r8,r34 }
	{ addl	r40,1316,r1; st8	[r34],r14; nop.i	0x0 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r38; adds	r39,0x0,r8; adds	r40,0x0,r32 }
	{ adds	r41,0x0,r33; adds	r42,0x0,r34; br.call.sptk.many	b0,fatal_error; }
	{ adds	r1,0x0,r38; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000E8C80; br.ret	b0; }
40000000000E8C90 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E8CA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E8CB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; xmalloc: 40000000000E8CC0
;;   Called from:
;;     400000000001D35C (in main)
;;     400000000001FA1C (in main)
;;     400000000001FB0C (in main)
;;     4000000000020EAC (in main)
;;     400000000002184C (in fn40000000000213C0)
;;     4000000000021D4C (in fn4000000000021C00)
;;     400000000002201C (in fn4000000000021EC0)
;;     40000000000220BC (in fn4000000000021EC0)
;;     4000000000022BDC (in get_current_user_info)
;;     4000000000022C4C (in get_current_user_info)
;;     4000000000022CEC (in get_current_user_info)
;;     4000000000022D7C (in get_current_user_info)
;;     4000000000022DDC (in get_current_user_info)
;;     4000000000022E7C (in get_current_user_info)
;;     4000000000022EBC (in get_current_user_info)
;;     4000000000022F3C (in get_current_user_info)
;;     400000000002477C (in fn4000000000024740)
;;     400000000002547C (in fn40000000000253C0)
;;     400000000002582C (in fn4000000000025800)
;;     4000000000025DEC (in init_yy_io)
;;     400000000002616C (in push_stream)
;;     400000000002661C (in save_token_state)
;;     400000000002731C (in decode_prompt_string)
;;     40000000000277CC (in decode_prompt_string)
;;     400000000002792C (in decode_prompt_string)
;;     40000000000290AC (in fn4000000000028E40)
;;     400000000002ADEC (in fn400000000002AC80)
;;     400000000002D91C (in fn400000000002D840)
;;     400000000002DBEC (in fn400000000002D840)
;;     400000000002FD3C (in fn400000000002FC00)
;;     400000000002FEBC (in fn400000000002FC00)
;;     400000000003026C (in yyerror)
;;     400000000003075C (in yyerror)
;;     4000000000031AFC (in fn4000000000030880)
;;     4000000000031B2C (in fn4000000000030880)
;;     40000000000320FC (in fn4000000000030880)
;;     400000000003212C (in fn4000000000030880)
;;     4000000000033EDC (in fn4000000000030880)
;;     4000000000033EDC (in fn4000000000030880)
;;     4000000000035BAC (in fn4000000000030880)
;;     40000000000367AC (in fn4000000000030880)
;;     40000000000367DC (in fn4000000000030880)
;;     400000000003686C (in fn4000000000030880)
;;     400000000003689C (in fn4000000000030880)
;;     400000000003DEAC (in save_parser_state)
;;     400000000003E28C (in execute_variable_command)
;;     400000000003E2DC (in execute_variable_command)
;;     400000000003E3FC (in execute_variable_command)
;;     400000000003E57C (in save_input_line_state)
;;     400000000003E8AC (in xparse_dolparen)
;;     4000000000040D9C (in make_absolute)
;;     400000000004170C (in extract_colon_unit)
;;     4000000000041A4C (in bash_tilde_find_word)
;;     4000000000041ACC (in bash_tilde_find_word)
;;     4000000000041B4C (in bash_tilde_find_word)
;;     4000000000041DFC (in bash_tilde_expand)
;;     4000000000041EDC (in full_pathname)
;;     400000000004245C (in get_group_array)
;;     40000000000425DC (in cmd_init)
;;     400000000004261C (in cmd_init)
;;     400000000004272C (in alloc_word_desc)
;;     40000000000427DC (in make_bare_word)
;;     400000000004282C (in make_bare_word)
;;     4000000000042CEC (in make_word_list)
;;     4000000000042E1C (in make_command)
;;     4000000000042EAC (in command_connect)
;;     4000000000042F6C (in make_for_command)
;;     400000000004302C (in make_select_command)
;;     400000000004328C (in make_arith_for_command)
;;     40000000000436AC (in make_group_command)
;;     400000000004372C (in make_case_command)
;;     400000000004381C (in make_pattern_list)
;;     400000000004392C (in make_if_command)
;;     40000000000439EC (in make_while_command)
;;     4000000000043AAC (in make_until_command)
;;     4000000000043B5C (in make_arith_command)
;;     4000000000043B7C (in make_arith_command)
;;     4000000000043C5C (in make_cond_node)
;;     4000000000043D1C (in make_cond_command)
;;     4000000000043DDC (in make_bare_simple_command)
;;     4000000000043DFC (in make_bare_simple_command)
;;     400000000004472C (in make_here_document)
;;     400000000004475C (in make_here_document)
;;     40000000000447EC (in make_redirection)
;;     4000000000044B6C (in make_function_def)
;;     4000000000044D2C (in make_subshell_command)
;;     4000000000044DEC (in make_coproc_command)
;;     4000000000044E2C (in make_coproc_command)
;;     400000000004544C (in fn4000000000045380)
;;     400000000004EE5C (in new_fd_bitmap)
;;     400000000004EEBC (in new_fd_bitmap)
;;     400000000004F3EC (in coproc_alloc)
;;     400000000004F85C (in coproc_setvars)
;;     400000000004FE1C (in coproc_unsetvars)
;;     400000000005F71C (in fn400000000005F700)
;;     400000000005F74C (in fn400000000005F700)
;;     400000000005F85C (in fn400000000005F840)
;;     400000000005F88C (in fn400000000005F840)
;;     400000000006130C (in fn4000000000061240)
;;     400000000006139C (in fn4000000000061240)
;;     40000000000615BC (in fn4000000000061240)
;;     40000000000616CC (in fn4000000000061240)
;;     4000000000063E2C (in make_variable_value)
;;     4000000000063EAC (in make_variable_value)
;;     400000000006414C (in make_variable_value)
;;     400000000006436C (in make_variable_value)
;;     40000000000643EC (in make_variable_value)
;;     400000000006442C (in make_variable_value)
;;     40000000000644EC (in make_variable_value)
;;     40000000000649CC (in bind_function)
;;     4000000000064B6C (in bind_function_def)
;;     400000000006626C (in add_or_supercede_exported_var)
;;     40000000000662DC (in add_or_supercede_exported_var)
;;     40000000000666FC (in update_export_env_inplace)
;;     40000000000667AC (in update_export_env_inplace)
;;     400000000006689C (in new_var_context)
;;     40000000000668EC (in new_var_context)
;;     4000000000066BFC (in fn4000000000066B80)
;;     4000000000066C9C (in fn4000000000066B80)
;;     4000000000066FEC (in fn4000000000066D40)
;;     4000000000066FEC (in fn4000000000066D40)
;;     40000000000672DC (in fn4000000000066D40)
;;     400000000006803C (in make_local_variable)
;;     40000000000684BC (in bind_variable)
;;     400000000006BA9C (in makunbound)
;;     400000000006BA9C (in makunbound)
;;     400000000006BC4C (in makunbound)
;;     400000000006BFBC (in initialize_shell_variables)
;;     400000000006D0CC (in initialize_shell_variables)
;;     400000000006D33C (in initialize_shell_variables)
;;     400000000006D67C (in initialize_shell_variables)
;;     400000000006D67C (in initialize_shell_variables)
;;     400000000006DA2C (in initialize_shell_variables)
;;     400000000006DECC (in initialize_shell_variables)
;;     400000000006E16C (in assign_in_env)
;;     400000000006E3BC (in assign_in_env)
;;     400000000006E6EC (in assign_in_env)
;;     400000000006F31C (in copy_redirect)
;;     400000000006F4DC (in copy_redirect)
;;     400000000006F6EC (in copy_command)
;;     400000000007051C (in copy_function_def_contents)
;;     400000000007059C (in copy_function_def)
;;     400000000007204C (in fn4000000000071E00)
;;     400000000007204C (in fn4000000000071FC0)
;;     4000000000073C1C (in fn4000000000073B40)
;;     4000000000073ECC (in fn4000000000073B40)
;;     400000000007436C (in fn40000000000741C0)
;;     40000000000744DC (in fn40000000000741C0)
;;     4000000000074BFC (in fn4000000000074880)
;;     400000000007686C (in which_set_flags)
;;     400000000007B83C (in delete_job)
;;     400000000007BEAC (in append_process)
;;     400000000007D2EC (in run_sigchld_trap)
;;     400000000007D4CC (in run_sigchld_trap)
;;     400000000008364C (in stop_pipeline)
;;     40000000000838DC (in stop_pipeline)
;;     4000000000083AEC (in stop_pipeline)
;;     4000000000083DFC (in stop_pipeline)
;;     400000000008448C (in stop_pipeline)
;;     400000000008600C (in fn4000000000085EA6)
;;     40000000000863EC (in fn4000000000085EA6)
;;     400000000008674C (in fn4000000000085EA6)
;;     4000000000086D2C (in fn4000000000086900)
;;     400000000008B3DC (in fn400000000008A3C0)
;;     400000000008B7FC (in fn400000000008B740)
;;     400000000008DD5C (in split_at_delims)
;;     400000000008E9CC (in string_list_internal)
;;     400000000008EBBC (in string_list_internal)
;;     400000000008ECAC (in ifs_firstchar)
;;     400000000008FDCC (in get_dollar_var_value)
;;     400000000008FEAC (in get_dollar_var_value)
;;     400000000009007C (in remove_backslashes)
;;     400000000009024C (in quote_escapes)
;;     40000000000904CC (in quote_escapes)
;;     400000000009068C (in quote_escapes)
;;     40000000000907AC (in dequote_escapes)
;;     4000000000090CBC (in quote_string)
;;     4000000000090F1C (in quote_string)
;;     400000000009146C (in dequote_string)
;;     40000000000929DC (in list_string)
;;     400000000009322C (in list_string)
;;     400000000009391C (in copy_fifo_list)
;;     400000000009567C (in pat_subst)
;;     400000000009609C (in pat_subst)
;;     400000000009609C (in pat_subst)
;;     400000000009682C (in pat_subst)
;;     4000000000096C2C (in pat_subst)
;;     4000000000096E7C (in string_quote_removal)
;;     400000000009777C (in fn4000000000097540)
;;     400000000009919C (in fn4000000000099100)
;;     400000000009920C (in fn4000000000099100)
;;     400000000009947C (in fn4000000000099100)
;;     400000000009A2CC (in fn400000000009A180)
;;     40000000000A145C (in fn40000000000A1400)
;;     40000000000A182C (in fn40000000000A1400)
;;     40000000000A1CEC (in fn40000000000A1400)
;;     40000000000A206C (in fn40000000000A1400)
;;     40000000000A283C (in fn40000000000A1400)
;;     40000000000A330C (in fn40000000000A1400)
;;     40000000000A390C (in fn40000000000A1400)
;;     40000000000A3AEC (in fn40000000000A1400)
;;     40000000000A3CCC (in fn40000000000A1400)
;;     40000000000A3E5C (in fn40000000000A1400)
;;     40000000000A43EC (in fn40000000000A1400)
;;     40000000000A456C (in fn40000000000A1400)
;;     40000000000A470C (in fn40000000000A1400)
;;     40000000000A483C (in fn40000000000A1400)
;;     40000000000A49DC (in fn40000000000A1400)
;;     40000000000A4EAC (in fn40000000000A1400)
;;     40000000000A543C (in fn40000000000A1400)
;;     40000000000A592C (in expand_prompt_string)
;;     40000000000A5F7C (in fn40000000000A5B80)
;;     40000000000A636C (in fn40000000000A5B80)
;;     40000000000A644C (in fn40000000000A5B80)
;;     40000000000A64BC (in fn40000000000A5B80)
;;     40000000000A677C (in expand_string_assignment)
;;     40000000000A6A9C (in fn40000000000A6A40)
;;     40000000000A8B9C (in fn40000000000A7940)
;;     40000000000A955C (in phash_insert)
;;     40000000000A962C (in phash_insert)
;;     40000000000A967C (in phash_insert)
;;     40000000000A96AC (in phash_insert)
;;     40000000000A98AC (in phash_search)
;;     40000000000A997C (in phash_search)
;;     40000000000A9A2C (in phash_search)
;;     40000000000A9B1C (in hash_create)
;;     40000000000A9B4C (in hash_create)
;;     40000000000A9C3C (in hash_create)
;;     40000000000A9DDC (in hash_copy)
;;     40000000000A9E1C (in hash_copy)
;;     40000000000A9EAC (in hash_copy)
;;     40000000000A9FBC (in hash_copy)
;;     40000000000AA38C (in hash_search)
;;     40000000000AA86C (in hash_insert)
;;     40000000000AB00C (in fn40000000000AAEC0)
;;     40000000000AB05C (in fn40000000000AAEC0)
;;     40000000000AB6DC (in make_default_mailpath)
;;     40000000000ABBEC (in check_mail)
;;     40000000000AC80C (in fn40000000000AC6C0)
;;     40000000000ADAAC (in set_signal)
;;     40000000000ADBBC (in set_signal)
;;     40000000000ADC9C (in set_signal)
;;     40000000000ADD3C (in set_signal)
;;     40000000000AE92C (in run_exit_trap)
;;     40000000000AF31C (in run_pending_traps)
;;     40000000000B0A0C (in fd_to_buffered_stream)
;;     40000000000B0A2C (in fd_to_buffered_stream)
;;     40000000000B0F0C (in duplicate_buffered_stream)
;;     40000000000B203C (in add_unwind_protect)
;;     40000000000B23FC (in unwind_protect_mem)
;;     40000000000B2B7C (in quote_string_for_globbing)
;;     40000000000B2F6C (in quote_globbing_chars)
;;     40000000000B3A6C (in setup_ignore_patterns)
;;     40000000000B945C (in add_alias)
;;     40000000000B953C (in add_alias)
;;     40000000000B957C (in add_alias)
;;     40000000000B95CC (in add_alias)
;;     40000000000B966C (in add_alias)
;;     40000000000B99AC (in all_aliases)
;;     40000000000B9BAC (in alias_expand_word)
;;     40000000000B9C6C (in alias_expand)
;;     40000000000B9C8C (in alias_expand)
;;     40000000000BB0DC (in array_create_element)
;;     40000000000BB12C (in array_create_element)
;;     40000000000BB45C (in array_create)
;;     40000000000BC0EC (in array_insert)
;;     40000000000BCAEC (in array_to_argv)
;;     40000000000BCC3C (in array_to_assign)
;;     40000000000BD6AC (in array_to_string)
;;     40000000000BD6EC (in array_to_string)
;;     40000000000BE4AC (in fn40000000000BE480)
;;     40000000000BE4DC (in fn40000000000BE480)
;;     40000000000BE58C (in fn40000000000BE480)
;;     40000000000BE80C (in fn40000000000BE480)
;;     40000000000BEA9C (in convert_var_to_assoc)
;;     40000000000BF54C (in expand_compound_array_assignment)
;;     40000000000BFEEC (in array_expand_index)
;;     40000000000C0FAC (in array_variable_name)
;;     40000000000C258C (in assoc_insert)
;;     40000000000C2FBC (in assoc_to_assign)
;;     40000000000C3BCC (in assoc_to_string)
;;     40000000000C3D7C (in assoc_to_string)
;;     40000000000C47AC (in fn40000000000C46C0)
;;     40000000000C486C (in fn40000000000C46C0)
;;     40000000000C54AC (in brace_expand)
;;     40000000000C550C (in brace_expand)
;;     40000000000C5BEC (in brace_expand)
;;     40000000000C64DC (in brace_expand)
;;     40000000000C873C (in bash_add_history)
;;     40000000000C908C (in check_add_history)
;;     40000000000C9C8C (in fn40000000000C9C40)
;;     40000000000CADCC (in fn40000000000CAD40)
;;     40000000000CAEFC (in fn40000000000CAD40)
;;     40000000000CB12C (in fn40000000000CAD40)
;;     40000000000CB28C (in fn40000000000CAD40)
;;     40000000000CC4EC (in command_word_completion_function)
;;     40000000000CC62C (in command_word_completion_function)
;;     40000000000CC8BC (in command_word_completion_function)
;;     40000000000CCD8C (in command_word_completion_function)
;;     40000000000CD24C (in command_word_completion_function)
;;     40000000000CD24C (in command_word_completion_function)
;;     40000000000CD2FC (in command_word_completion_function)
;;     40000000000CD2FC (in command_word_completion_function)
;;     40000000000CD44C (in command_word_completion_function)
;;     40000000000CD6DC (in command_word_completion_function)
;;     40000000000CDBDC (in command_word_completion_function)
;;     40000000000CDC9C (in command_word_completion_function)
;;     40000000000CE03C (in command_word_completion_function)
;;     40000000000CEF8C (in fn40000000000CE980)
;;     40000000000CF0BC (in fn40000000000CE980)
;;     40000000000D507C (in reset_completer_word_break_chars)
;;     40000000000D519C (in reset_completer_word_break_chars)
;;     40000000000D53BC (in enable_hostname_completion)
;;     40000000000D54BC (in enable_hostname_completion)
;;     40000000000D559C (in enable_hostname_completion)
;;     40000000000D6C7C (in bash_re_edit)
;;     40000000000D832C (in bash_servicename_completion_function)
;;     40000000000D852C (in bash_servicename_completion_function)
;;     40000000000D85AC (in bash_servicename_completion_function)
;;     40000000000D85AC (in bash_servicename_completion_function)
;;     40000000000D86CC (in bash_groupname_completion_function)
;;     40000000000D882C (in bash_groupname_completion_function)
;;     40000000000D91FC (in find_token_in_alist)
;;     40000000000D942C (in substring)
;;     40000000000D981C (in strsub)
;;     40000000000D997C (in strcreplace)
;;     40000000000DA1AC (in set_default_locale)
;;     40000000000DA45C (in set_default_locale_vars)
;;     40000000000DA54C (in set_default_locale_vars)
;;     40000000000DAC4C (in set_lang)
;;     40000000000DAD0C (in set_lang)
;;     40000000000DAEEC (in set_locale_var)
;;     40000000000DAFBC (in set_locale_var)
;;     40000000000DB0DC (in set_locale_var)
;;     40000000000DB4CC (in set_locale_var)
;;     40000000000DBA1C (in localetrans)
;;     40000000000DBAFC (in localetrans)
;;     40000000000DBB9C (in localetrans)
;;     40000000000DBC3C (in localetrans)
;;     40000000000DBD5C (in mk_msgstr)
;;     40000000000DBF2C (in mk_msgstr)
;;     40000000000DBFBC (in localeexpand)
;;     40000000000DC39C (in fn40000000000DC300)
;;     40000000000DC5DC (in fn40000000000DC540)
;;     40000000000DC94C (in fn40000000000DC640)
;;     40000000000DCC1C (in fn40000000000DCB80)
;;     40000000000DD0AC (in fn40000000000DD000)
;;     40000000000DD59C (in search_for_command)
;;     40000000000E10EC (in redirection_error)
;;     40000000000E499C (in completions_to_stringlist)
;;     40000000000E4AAC (in completions_to_stringlist)
;;     40000000000E5EDC (in gen_compspec_completions)
;;     40000000000E660C (in gen_compspec_completions)
;;     40000000000E660C (in gen_compspec_completions)
;;     40000000000E6F3C (in gen_compspec_completions)
;;     40000000000E7C1C (in compspec_create)
;;     40000000000E7FAC (in compspec_copy)
;;     40000000000E802C (in compspec_copy)
;;     40000000000E80BC (in compspec_copy)
;;     40000000000E814C (in compspec_copy)
;;     40000000000E81DC (in compspec_copy)
;;     40000000000E826C (in compspec_copy)
;;     40000000000E82FC (in compspec_copy)
;;     40000000000E838C (in compspec_copy)
;;     40000000000E841C (in compspec_copy)
;;     40000000000E887C (in progcomp_insert)
;;     40000000000ECDEC (in command_builtin)
;;     40000000000ECDEC (in command_builtin)
;;     40000000000ECE8C (in command_builtin)
;;     40000000000ED24C (in command_builtin)
;;     40000000000EEBAC (in remember_args)
;;     40000000000EF39C (in get_working_directory)
;;     40000000000EF41C (in get_working_directory)
;;     40000000000EF63C (in set_working_directory)
;;     40000000000F0E6C (in fn40000000000F0900)
;;     40000000000F1C9C (in fn40000000000F0900)
;;     40000000000F1E9C (in fn40000000000F0900)
;;     40000000000F22DC (in fn40000000000F0900)
;;     40000000000F304C (in enable_builtin)
;;     40000000000F34FC (in enable_builtin)
;;     40000000000F363C (in enable_builtin)
;;     40000000000F36AC (in enable_builtin)
;;     40000000000F393C (in enable_builtin)
;;     40000000000F3F1C (in enable_builtin)
;;     40000000000F459C (in fn40000000000F4180)
;;     40000000000F7BBC (in fn40000000000F7B80)
;;     40000000000F7F5C (in exec_builtin)
;;     40000000000F836C (in exec_builtin)
;;     40000000000F83BC (in exec_builtin)
;;     40000000000F96FC (in fc_builtin)
;;     40000000000F973C (in fc_builtin)
;;     40000000000F978C (in fc_builtin)
;;     40000000000F98CC (in fc_builtin)
;;     40000000000F994C (in fc_builtin)
;;     40000000000FA79C (in fc_builtin)
;;     40000000000FACFC (in fc_builtin)
;;     400000000010158C (in mapfile_builtin)
;;     400000000010291C (in dirs_builtin)
;;     40000000001036DC (in pushd_builtin)
;;     4000000000103E5C (in set_dirstack_element)
;;     4000000000104FBC (in read_builtin)
;;     400000000010534C (in read_builtin)
;;     4000000000107F8C (in read_builtin)
;;     40000000001096FC (in set_shellopts)
;;     4000000000109CAC (in initialize_shell_options)
;;     400000000010BA2C (in set_var_attribute)
;;     400000000010BC1C (in set_var_attribute)
;;     400000000010CAAC (in shift_builtin)
;;     400000000010CE8C (in source_builtin)
;;     400000000010D20C (in source_builtin)
;;     400000000010D36C (in source_builtin)
;;     400000000010D48C (in source_builtin)
;;     400000000011054C (in ulimit_builtin)
;;     4000000000113AAC (in get_shopt_options)
;;     4000000000113B2C (in get_shopt_options)
;;     4000000000113E0C (in set_bashopts)
;;     4000000000114EAC (in initialize_bashopts)
;;     400000000011703C (in printf_builtin)
;;     400000000011D41C (in complete_builtin)
;;     400000000011D49C (in complete_builtin)
;;     400000000011D51C (in complete_builtin)
;;     400000000011D59C (in complete_builtin)
;;     400000000011D61C (in complete_builtin)
;;     400000000011D69C (in complete_builtin)
;;     400000000011D71C (in complete_builtin)
;;     400000000011DBCC (in compgen_builtin)
;;     400000000011DC4C (in compgen_builtin)
;;     400000000011DCCC (in compgen_builtin)
;;     400000000011DD4C (in compgen_builtin)
;;     400000000011DDCC (in compgen_builtin)
;;     400000000011DE4C (in compgen_builtin)
;;     400000000011DECC (in compgen_builtin)
;;     40000000001290FC (in getenv)
;;     400000000012946C (in putenv)
;;     4000000000129B2C (in itos)
;;     4000000000129C6C (in uitos)
;;     400000000012BA0C (in netopen)
;;     400000000012C9CC (in sh_makepath)
;;     400000000012CBEC (in sh_makepath)
;;     400000000012CC4C (in sh_makepath)
;;     400000000012CE9C (in sh_canonpath)
;;     400000000012D58C (in sh_physpath)
;;     400000000012D5CC (in sh_physpath)
;;     400000000012DBFC (in sh_physpath)
;;     400000000012E12C (in sh_realpath)
;;     400000000012E4EC (in sh_mktmpname)
;;     400000000012E72C (in sh_mktmpfd)
;;     400000000012EB5C (in strlist_create)
;;     400000000012F17C (in strlist_copy)
;;     400000000012F37C (in strlist_merge)
;;     400000000012F47C (in strlist_merge)
;;     400000000012F67C (in strlist_append)
;;     400000000012FA0C (in strlist_prefix_suffix)
;;     400000000012FF0C (in strlist_from_word_list)
;;     400000000013016C (in strvec_create)
;;     400000000013064C (in strvec_copy)
;;     400000000013069C (in strvec_copy)
;;     400000000013084C (in strvec_from_word_list)
;;     400000000013093C (in strvec_from_word_list)
;;     400000000013144C (in sh_single_quote)
;;     400000000013160C (in sh_double_quote)
;;     400000000013183C (in sh_mkdoublequoted)
;;     400000000013197C (in sh_un_double_quote)
;;     4000000000131B3C (in sh_backslash_quote)
;;     4000000000131D3C (in sh_backslash_quote_for_double_quotes)
;;     40000000001320DC (in ansicstr)
;;     4000000000132BFC (in ansic_quote)
;;     40000000001330CC (in ansiexpand)
;;     4000000000134D7C (in zmapfd)
;;     4000000000135C9C (in sh_modcase)
;;     4000000000135D8C (in sh_modcase)
xmalloc proc
	{ alloc	r35,ar.pfs,0x7,0x0,0x5; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r34,b2 }
	{ addl	r33,8332,r1; adds	r36,0x0,r1; adds	r37,0x0,r32; }
	{ nop.m	0x0; ld4	r14,[r33]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000E8D40; }

l40000000000E8D00:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B340; }
	{ adds	r1,0x0,r36; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	40000000000E8D90 }

l40000000000E8D20:
	{ nop.m	0x0; mov.i	ar.pfs,r35; mov.spnt	b0,r34,40000000000E8D20 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000000E8D40:
	{ adds	r37,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BF20; }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r37,0x0,r32; }
	{ addl	r14,8340,r1; st8	[r8],r14; addl	r14,1,r0; }
	{ st4	[r14],r33; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B340; }
	{ adds	r1,0x0,r36; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000000E8D20; }

l40000000000E8D90:
	{ adds	r14,0x10,r12; addl	r37,1324,r1; adds	r38,0x0,r32; }
	{ nop.m	0x0; st8	[r8],r14; nop.i	0x0 }
	{ ld8	r37,[r37]; nop.m	0x0; br.call.sptk.many	b0,fn40000000000E8B00; }
	{ adds	r14,0x10,r12; nop.m	0x0; adds	r1,0x0,r36; }
	{ ld8	r8,[r14]; mov.i	ar.pfs,r35; mov.spnt	b0,r34,40000000000E8DD0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }
40000000000E8DF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; xrealloc: 40000000000E8E00
;;   Called from:
;;     400000000001EDCC (in main)
;;     40000000000274BC (in decode_prompt_string)
;;     40000000000299CC (in fn4000000000029100)
;;     400000000002A4DC (in fn4000000000029100)
;;     400000000002A7EC (in read_secondary_line)
;;     400000000002B0BC (in fn400000000002AC80)
;;     400000000002B52C (in fn400000000002AC80)
;;     400000000002B78C (in fn400000000002AC80)
;;     400000000002B8DC (in fn400000000002AC80)
;;     400000000002BAFC (in fn400000000002AC80)
;;     400000000002BDEC (in fn400000000002AC80)
;;     400000000002BF1C (in fn400000000002AC80)
;;     400000000002C17C (in fn400000000002AC80)
;;     400000000002C58C (in fn400000000002AC80)
;;     400000000002C7BC (in fn400000000002AC80)
;;     400000000002CBCC (in fn400000000002AC80)
;;     400000000002CD0C (in fn400000000002AC80)
;;     400000000002CE3C (in fn400000000002AC80)
;;     400000000002D79C (in fn400000000002AC80)
;;     400000000002DB0C (in fn400000000002D840)
;;     400000000002DFCC (in fn400000000002D840)
;;     400000000002E1FC (in fn400000000002D840)
;;     400000000002E1FC (in fn400000000002D840)
;;     400000000002E52C (in fn400000000002D840)
;;     400000000002E79C (in fn400000000002D840)
;;     400000000002F19C (in fn400000000002D840)
;;     400000000002F3BC (in fn400000000002D840)
;;     400000000002F4CC (in fn400000000002D840)
;;     400000000003135C (in fn4000000000030880)
;;     40000000000317CC (in fn4000000000030880)
;;     4000000000032EFC (in fn4000000000030880)
;;     4000000000032FCC (in fn4000000000030880)
;;     400000000003327C (in fn4000000000030880)
;;     40000000000336FC (in fn4000000000030880)
;;     40000000000337CC (in fn4000000000030880)
;;     4000000000033CDC (in fn4000000000030880)
;;     4000000000033FAC (in fn4000000000030880)
;;     400000000003419C (in fn4000000000030880)
;;     400000000003447C (in fn4000000000030880)
;;     400000000003451C (in fn4000000000030880)
;;     40000000000345CC (in fn4000000000030880)
;;     400000000003496C (in fn4000000000030880)
;;     400000000003524C (in fn4000000000030880)
;;     400000000003E9EC (in fn400000000003E980)
;;     400000000004438C (in make_here_document)
;;     400000000004540C (in fn4000000000045380)
;;     400000000004610C (in fn4000000000045FC0)
;;     4000000000050BDC (in shell_execve)
;;     4000000000060EBC (in fn4000000000060B00)
;;     400000000006A4DC (in push_dollar_vars)
;;     400000000007480C (in fn40000000000741C0)
;;     4000000000077DEC (in fn4000000000077C00)
;;     400000000008421C (in stop_pipeline)
;;     4000000000087BAC (in sub_append_string)
;;     40000000000942AC (in command_substitute)
;;     4000000000095D1C (in pat_subst)
;;     400000000009659C (in pat_subst)
;;     400000000009666C (in pat_subst)
;;     40000000000A1BBC (in fn40000000000A1400)
;;     40000000000A295C (in fn40000000000A1400)
;;     40000000000A30AC (in fn40000000000A1400)
;;     40000000000A4ACC (in fn40000000000A1400)
;;     40000000000AAFEC (in fn40000000000AAEC0)
;;     40000000000B02CC (in fn40000000000B0280)
;;     40000000000B3CCC (in setup_ignore_patterns)
;;     40000000000B9E8C (in alias_expand)
;;     40000000000BA08C (in alias_expand)
;;     40000000000BA4EC (in alias_expand)
;;     40000000000BD15C (in array_to_assign)
;;     40000000000BD20C (in array_to_assign)
;;     40000000000BD58C (in array_to_string)
;;     40000000000BDB7C (in array_modcase)
;;     40000000000BDFCC (in array_patsub)
;;     40000000000BE43C (in array_subrange)
;;     40000000000C362C (in assoc_to_assign)
;;     40000000000C420C (in assoc_modcase)
;;     40000000000C465C (in assoc_patsub)
;;     40000000000D961C (in strsub)
;;     40000000000D97EC (in strsub)
;;     40000000000D9A2C (in strcreplace)
;;     40000000000D9B8C (in strcreplace)
;;     40000000000D9CCC (in strcreplace)
;;     40000000000E673C (in gen_compspec_completions)
;;     40000000001062FC (in read_builtin)
;;     40000000001065BC (in read_builtin)
;;     40000000001105CC (in ulimit_builtin)
;;     400000000011621C (in fn4000000000116140)
;;     400000000012B30C (in sh_stat)
;;     40000000001301EC (in strvec_resize)
;;     4000000000134E2C (in zmapfd)
;;     4000000000134F0C (in zmapfd)
;;     400000000013538C (in zgetline)
xrealloc proc
	{ alloc	r36,ar.pfs,0x8,0x0,0x6; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ addl	r34,8332,r1; mov	r35,b3; adds	r37,0x0,r1; }
	{ nop.m	0x0; ld4	r14,[r34]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000E8E90; }

l40000000000E8E40:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r32; (p06) br.cond.dpnt.few	40000000000E8ED0 }

l40000000000E8E50:
	{ adds	r38,0x0,r32; adds	r39,0x0,r33; br.call.sptk.many	b0,fn400000000001AD60; }
	{ adds	r1,0x0,r37; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	40000000000E8F00 }

l40000000000E8E70:
	{ nop.m	0x0; mov.i	ar.pfs,r36; mov.spnt	b0,r35,40000000000E8E70 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000000E8E90:
	{ adds	r38,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BF20; }
	{ adds	r1,0x0,r37; nop.m	0x0; cmp.eq	p06,p07,0x0,r32; }
	{ addl	r14,8340,r1; st8	[r8],r14; addl	r14,1,r0; }
	{ st4	[r14],r34; nop.i	0x0; (p07) br.cond.dptk.few	40000000000E8E50 }

l40000000000E8ED0:
	{ adds	r38,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B340; }
	{ adds	r1,0x0,r37; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000000E8E70; }

l40000000000E8EF0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000E8F00:
	{ adds	r14,0x10,r12; addl	r38,1332,r1; adds	r39,0x0,r33; }
	{ nop.m	0x0; st8	[r8],r14; nop.i	0x0 }
	{ ld8	r38,[r38]; nop.m	0x0; br.call.sptk.many	b0,fn40000000000E8B00; }
	{ adds	r14,0x10,r12; nop.m	0x0; adds	r1,0x0,r37; }
	{ ld8	r8,[r14]; mov.i	ar.pfs,r36; mov.spnt	b0,r35,40000000000E8F40 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }
40000000000E8F60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E8F70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; xfree: 40000000000E8F80
;;   Called from:
;;     400000000002CFFC (in fn400000000002AC80)
;;     400000000002D1DC (in fn400000000002AC80)
;;     400000000002EA5C (in fn400000000002D840)
;;     400000000002F7DC (in fn400000000002D840)
;;     400000000004B86C (in dispose_word)
;;     400000000004BB7C (in dispose_word_desc)
;;     400000000004BD9C (in dispose_words)
;;     400000000010164C (in mapfile_builtin)
;;     40000000001055DC (in read_builtin)
;;     40000000001064AC (in read_builtin)
;;     4000000000106BBC (in read_builtin)
;;     400000000010791C (in read_builtin)
;;     4000000000107ADC (in read_builtin)
;;     4000000000107B5C (in read_builtin)
;;     4000000000107E6C (in read_builtin)
;;     400000000010830C (in read_builtin)
;;     400000000010844C (in read_builtin)
xfree proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; cmp.eq	p06,p07,0x0,r32; mov	r33,b1 }
	{ adds	r35,0x0,r1; adds	r36,0x0,r32; (p06) br.cond.dpnt.few	40000000000E8FC0; }

l40000000000E8FA0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l40000000000E8FC0:
	{ nop.m	0x0; mov.i	ar.pfs,r34; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000E8FD0; br.ret	b0; }
40000000000E8FE0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000E8FF0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; fn40000000000E9000: 40000000000E9000
;;   Called from:
;;     40000000000E934C (in alias_builtin)
;;     40000000000E94BC (in alias_builtin)
fn40000000000E9000 proc
	{ alloc	r36,ar.pfs,0xA,0x0,0x6; adds	r14,0x8,r32; mov	r35,b3 }
	{ nop.m	0x0; adds	r37,0x0,r1; nop.i	0x0; }
	{ ld8	r38,[r14]; nop.i	0x0; br.call.sptk.many	b0,sh_single_quote; }
	{ adds	r1,0x0,r37; adds	r34,0x0,r8; tbit.z	p06,p07,r33,0x0 }
	{ addl	r38,1,r0; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000E90D0; }

l40000000000E9050:
	{ addl	r39,-9476,r1; ld8	r40,[r32]; adds	r41,0x0,r34; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; adds	r38,0x0,r34; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r37; addl	r14,-10260,r1; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r38,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ adds	r1,0x0,r37; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000E90C0; br.ret	b0 }

l40000000000E90D0:
	{ addl	r39,-9484,r1; nop.m	0x0; addl	r38,1,r0; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; ld8	r40,[r32]; adds	r41,0x0,r34 }
	{ addl	r38,1,r0; addl	r39,-9476,r1; nop.i	0x0; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r37; adds	r38,0x0,r34; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r37; addl	r14,-10260,r1; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r38,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ adds	r1,0x0,r37; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000E9170; br.ret	b0; }

;; alias_builtin: 40000000000E9180
alias_builtin proc
	{ alloc	r39,ar.pfs,0xC,0x0,0x9; addl	r14,6456,r1; nop.b	0x0 }
	{ adds	r40,0x0,r1; nop.m	0x0; mov	r38,b6; }
	{ nop.m	0x0; nop.m	0x0; adds	r33,0x0,r0; }
	{ ld4	r36,[r14]; cmp4.eq	p06,p07,0x0,r36; nop.i	0x0; }
	{ nop.m	0x0; (p06) addl	r36,1,r0; nop.i	0x0; }

l40000000000E91CC:
	{ Invalid; nop; zxt1	r0,r64 }

l40000000000E91DC:
	{ (p37) nop; invala; break.b	0x1000 }
	{ cmpxchg2.acq	r0,[r0],r1; Invalid; nop }

l40000000000E91F0:
	{ addl	r42,-9468,r1; nop.m	0x0; adds	r41,0x0,r32; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; adds	r1,0x0,r40; (p07) br.cond.dpnt.few	40000000000E9270; }

l40000000000E9220:
	{ cmp4.eq	p06,p07,0x70,r8; nop.m	0x0; addl	r33,1,r0 }
	{ addl	r36,1,r0; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000E91F0; }

l40000000000E9240:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ addl	r8,258,r0; adds	r1,0x0,r40; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000E9260; br.ret	b0 }

l40000000000E9270:
	{ addl	r14,9268,r1; nop.m	0x0; and	r15,0x1,r33; }
	{ nop.m	0x0; ld8	r34,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r34; (p06) addl	r14,1,r0; nop.i	0x0; }

l40000000000E929C:
	{ cmp4.eq.and	p00,p43,r1,r0; (p01) cmp.eq	p00,p16,r0,r64; (p49) nop }

l40000000000E92A6:
	{ Invalid; (p18) nop; break.b	0x80000 }
	{ (p03) chk.a.clr	f0,3FFFFFFFFFDAC3A6; nop; (p32) nop }

l40000000000E92C0:
	{ addl	r14,7740,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000E9670; }

l40000000000E92F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,all_aliases; }
	{ adds	r1,0x0,r40; cmp.eq	p06,p07,0x0,r8; nop.i	0x0 }
	{ adds	r33,0x8,r8; adds	r35,0x0,r8; (p06) br.cond.dpnt.few	40000000000E9670; }

l40000000000E9320:
	{ nop.m	0x0; ld8	r41,[r8]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r41; (p07) br.cond.dpnt.few	40000000000E9370; }

l40000000000E9340:
	{ adds	r42,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,fn40000000000E9000; }
	{ ld8	r41,[r33],8; nop.m	0x0; adds	r1,0x0,r40; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r41; (p06) br.cond.dptk.few	40000000000E9340 }

l40000000000E9370:
	{ adds	r41,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r40; cmp4.eq	p07,p06,0x0,r37; (p06) br.cond.dpnt.few	40000000000E9640 }

l40000000000E9390:
	{ adds	r37,0x0,r0; nop.m	0x0; nop.i	0x0; }

l40000000000E93A0:
	{ adds	r14,0x8,r34; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r35,[r14]; ld1	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.m	0x0; cmp4.eq	p09,p08,0x3D,r14; }
	{ (p06) addl	r15,1,r0; (p08) addl	r14,1,r0; (p07) adds	r15,0x0,r0 }

l40000000000E93E6:
	{ Invalid; (p07) dep	r0,r0,r0,35,2; (p34) nop }

l40000000000E93EC:
	{ cmp.lt	p00,p43,0x0,r66; (p01) cmp.lt	p00,p16,r0,r64; (p33) cmp.eq.unc	p35,p16,r3,r3; }

l40000000000E93F0:
	{ (p09) adds	r14,0x0,r0; and	r14,r14,r15; adds	r15,0x1,r35; }

l40000000000E93F6:
	{ Invalid; (p07) nop; (p32) nop }
	{ (p07) chk.a.clr	r1,3FFFFFFFFF2E9406; nop; break.i	0x80000 }

l40000000000E9410:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000E9420:
	{ adds	r18,0x0,r15; ld1	r16,[r15],1; adds	r33,0x1,r14 }
	{ nop.m	0x0; adds	r17,0x0,r14; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r16,r16; adds	r14,0x0,r33; }
	{ cmp4.eq	p07,p06,0x3D,r16; (p06) cmp.eq.unc	p08,p00,r0,r0; (p07) cmp.eq.unc	p09,p00,r0,r0; }

l40000000000E945C:
	{ Invalid; nop; Invalid; }

l40000000000E9460:
	{ nop.m	0x0; cmp4.eq.or.andcm	p09,p08,0x0,r16; (p08) br.cond.dptk.few	40000000000E9420; }

l40000000000E9470:
	{ cmp4.eq	p08,p09,0x0,r17; (p08) br.cond.dpnt.few	40000000000E9480; (p07) br.cond.dpnt.few	40000000000E9510 }

l40000000000E947C:
	{ (p05) nop; zxt1	r96,r64; break.i	0x1000 }

l40000000000E9480:
	{ adds	r41,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,find_alias; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r40; nop.i	0x0 }
	{ adds	r41,0x0,r8; adds	r42,0x0,r36; (p06) br.cond.dpnt.few	40000000000E95C0; }

l40000000000E94B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000E9000; }
	{ ld8	r34,[r34]; nop.m	0x0; adds	r1,0x0,r40; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	40000000000E93A0; }

l40000000000E94E0:
	{ cmp4.eq	p07,p06,0x0,r37; nop.m	0x0; mov.i	ar.pfs,r39; }
	{ (p06) addl	r37,1,r0; mov.spnt	b0,r38,40000000000E94F0; (p07) adds	r37,0x0,r0; }

l40000000000E94F6:
	{ addp4	r38,0xFFFFFFFFFFFFE181,r64; (p18) nop; break.i	0x80000 }

l40000000000E9500:
	{ nop.m	0x0; adds	r8,0x0,r37; br.ret	b0; }

l40000000000E9510:
	{ adds	r41,0x0,r35; st1	[r0],r18; adds	r42,0x0,r0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,legal_alias_name; }
	{ addl	r43,5,r0; nop.m	0x0; adds	r1,0x0,r40 }
	{ adds	r41,0x0,r35; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000000E9600; }

l40000000000E9550:
	{ addl	r42,-9460,r1; adds	r41,0x0,r0; adds	r37,0x1,r37; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r41,0x0,r8 }
	{ adds	r42,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,builtin_error; }
	{ ld8	r34,[r34]; nop.m	0x0; adds	r1,0x0,r40; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	40000000000E93A0 }

l40000000000E95B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E94E0 }

l40000000000E95C0:
	{ adds	r41,0x0,r35; adds	r37,0x1,r37; br.call.sptk.many	b0,sh_notfound; }
	{ ld8	r34,[r34]; nop.m	0x0; adds	r1,0x0,r40; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	40000000000E93A0 }

l40000000000E95F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E94E0 }

l40000000000E9600:
	{ add	r42,r35,r33; nop.i	0x0; br.call.sptk.many	b0,add_alias; }
	{ ld8	r34,[r34]; nop.m	0x0; adds	r1,0x0,r40; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	40000000000E93A0 }

l40000000000E9630:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E94E0 }

l40000000000E9640:
	{ adds	r41,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,sh_chkwrite; }
	{ adds	r1,0x0,r40; nop.m	0x0; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000E9660; br.ret	b0 }

l40000000000E9670:
	{ adds	r8,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000E9680; br.ret	b0; }
40000000000E9690 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E96A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000E96B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; unalias_builtin: 40000000000E96C0
unalias_builtin proc
	{ alloc	r37,ar.pfs,0x9,0x0,0x7; adds	r38,0x0,r1; mov	r36,b4; }
	{ nop.m	0x0; adds	r34,0x0,r0; br.call.sptk.many	b0,reset_internal_getopt; }
	{ adds	r1,0x0,r38; nop.m	0x0; nop.i	0x0; }

l40000000000E96F0:
	{ addl	r40,-9452,r1; nop.m	0x0; adds	r39,0x0,r32; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; adds	r1,0x0,r38; (p07) br.cond.dpnt.few	40000000000E9760; }

l40000000000E9720:
	{ addl	r34,1,r0; cmp4.eq	p06,p07,0x61,r8; (p06) br.cond.dpnt.few	40000000000E96F0 }

l40000000000E9730:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ addl	r8,258,r0; adds	r1,0x0,r38; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000E9750; br.ret	b0 }

l40000000000E9760:
	{ addl	r14,9268,r1; cmp4.eq	p06,p07,0x0,r34; (p07) br.cond.dpnt.few	40000000000E9880; }

l40000000000E9770:
	{ nop.m	0x0; ld8	r33,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p07) br.cond.dpnt.few	40000000000E9730; }

l40000000000E9790:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000E97A0:
	{ adds	r35,0x8,r33; ld8	r14,[r35]; nop.i	0x0; }
	{ ld8	r39,[r14]; nop.i	0x0; br.call.sptk.many	b0,find_alias; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r38; (p06) br.cond.dpnt.few	40000000000E9830; }

l40000000000E97D0:
	{ ld8	r39,[r8]; nop.i	0x0; br.call.sptk.many	b0,remove_alias; }
	{ ld8	r33,[r33]; nop.m	0x0; adds	r1,0x0,r38; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	40000000000E97A0; }

l40000000000E9800:
	{ cmp4.eq	p07,p06,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ (p06) addl	r34,1,r0; mov.spnt	b0,r36,40000000000E9810; (p07) adds	r34,0x0,r0; }

l40000000000E9816:
	{ chk.a.nc	f36,3FFFFFFFFF1C9826; (p17) nop; break.i	0x80000 }

l40000000000E9820:
	{ nop.m	0x0; adds	r8,0x0,r34; br.ret	b0 }

l40000000000E9830:
	{ ld8	r14,[r35]; nop.m	0x0; adds	r34,0x1,r34; }
	{ ld8	r39,[r14]; nop.i	0x0; br.call.sptk.many	b0,sh_notfound; }
	{ ld8	r33,[r33]; nop.m	0x0; adds	r1,0x0,r38; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	40000000000E97A0 }

l40000000000E9870:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E9800 }

l40000000000E9880:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,delete_all_aliases; }
	{ adds	r8,0x0,r0; adds	r1,0x0,r38; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000E98A0; br.ret	b0; }
40000000000E98B0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; bind_builtin: 40000000000E98C0
bind_builtin proc
	{ alloc	r50,ar.pfs,0x19,0x0,0x15; addl	r14,6468,r1; mov	r52,LC }
	{ adds	r51,0x0,r1; nop.m	0x0; mov	r49,b1; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; addl	r14,7796,r1; (p07) br.cond.dpnt.few	40000000000EA1D0; }

l40000000000E9900:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000EA0E0 }

l40000000000E9920:
	{ addl	r53,-7732,r1; adds	r40,0x0,r0; adds	r41,0x0,r0 }
	{ adds	r37,0x0,r0; adds	r39,0x0,r0; adds	r38,0x0,r0; }
	{ ld8	r53,[r53]; adds	r33,0x0,r0; addl	r47,4096,r0 }
	{ addl	r46,1024,r0; addl	r45,512,r0; br.call.sptk.many	b0,begin_unwind_frame; }
	{ adds	r1,0x0,r51; addl	r54,8,r0; addl	r44,128,r0 }
	{ addl	r43,256,r0; addl	r42,2048,r0; addl	r36,-10700,r1; }
	{ nop.m	0x0; ld8	r36,[r36]; nop.i	0x0; }
	{ adds	r53,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,unwind_protect_mem; }
	{ adds	r1,0x0,r51; addl	r14,-10260,r1; addl	r34,-7652,r1 }
	{ addl	r35,9252,r1; ld8	r14,[r14]; nop.i	0x0 }
	{ ld8	r34,[r34]; nop.m	0x0; nop.i	0x0; }
	{ ld8	r14,[r14]; nop.i	0x0; nop.i	0x0 }
	{ st8	[r14],r36; nop.m	0x0; br.call.sptk.many	b0,reset_internal_getopt; }
	{ adds	r1,0x0,r51; nop.m	0x0; nop.i	0x0; }

l40000000000E9A00:
	{ addl	r54,-7724,r1; nop.m	0x0; adds	r53,0x0,r32; }
	{ ld8	r54,[r54]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ adds	r1,0x0,r51; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p07) br.cond.dpnt.few	40000000000E9B40 }

l40000000000E9A30:
	{ nop.m	0x0; adds	r8,0xFFFFFFFFFFFFFFB0,r8; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x28,r8; (p07) br.cond.dptk.few	40000000000E9AC0 }

l40000000000E9A50:
	{ nop.m	0x0; addl	r35,258,r0; br.call.sptk.many	b0,builtin_usage; }
	{ adds	r1,0x0,r51; nop.m	0x0; nop.i	0x0; }

l40000000000E9A70:
	{ nop.m	0x0; addl	r53,-7732,r1; nop.i	0x0; }
	{ ld8	r53,[r53]; nop.i	0x0; br.call.sptk.many	b0,run_unwind_frame; }
	{ adds	r1,0x0,r51; adds	r53,0x0,r35; br.call.sptk.many	b0,sh_chkwrite; }
	{ adds	r1,0x0,r51; mov.i	ar.pfs,r50; mov.i	LC,r52; }
	{ nop.m	0x0; mov.spnt	b0,r49,40000000000E9AB0; br.ret	b0 }

l40000000000E9AC0:
	{ addp4	r8,r8,r0; shladd	r8,r8,0x3,r34; nop.i	0x0; }
	{ ld8	r14,[r8]; add	r8,r8,r14; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r8,40000000000E9AE0; br.cond	b6; }
40000000000E9AF0 08 B0 51 FB C3 27 00 03 8C 30 20 A0 06 00 01 84 ..Q..'...0 .....
40000000000E9B00 09 00 00 00 01 00 10 7A 85 1C 40 00 00 00 04 00 .......z..@.....
40000000000E9B10 11 B0 01 6C 18 10 00 00 00 02 00 00 B8 09 03 50 ...l...........P
40000000000E9B20 11 08 00 66 00 21 70 F8 23 0C 77 03 10 FF FF 4A ...f.!p.#.w....J
40000000000E9B30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

l40000000000E9B40:
	{ addl	r14,9268,r1; nop.m	0x0; tbit.z	p06,p07,r33,0x5; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld8	r34,[r14]; nop.i	0x0; (p06) br.cond.dptk.few	40000000000EA240 }

l40000000000E9B70:
	{ cmp.eq	p06,p07,0x0,r39; adds	r53,0x0,r39; (p06) br.cond.dpnt.few	40000000000EA240; }

l40000000000E9B80:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BDA0; }
	{ cmp.eq	p07,p06,0x0,r8; nop.m	0x0; adds	r1,0x0,r51 }
	{ adds	r35,0x0,r8; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000EA640; }

l40000000000E9BB0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C100; }
	{ adds	r1,0x0,r51; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r53,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AA00; }
	{ adds	r1,0x0,r51; tbit.z	p06,p07,r33,0x0; (p07) br.cond.dpnt.few	40000000000EA340; }

l40000000000E9BF0:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x1; (p07) br.cond.dpnt.few	40000000000EA310; }

l40000000000E9C00:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x7; (p07) br.cond.dpnt.few	40000000000EA2E0; }

l40000000000E9C10:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x9; (p07) br.cond.dpnt.few	40000000000EA2B0; }

l40000000000E9C20:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0xA; (p07) br.cond.dpnt.few	40000000000EA3A0; }

l40000000000E9C30:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x3; (p07) br.cond.dpnt.few	40000000000EA280; }

l40000000000E9C40:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x8; (p07) br.cond.dpnt.few	40000000000EA370; }

l40000000000E9C50:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x2; (p06) br.cond.dptk.few	40000000000E9C90; }

l40000000000E9C60:
	{ cmp.eq	p06,p07,0x0,r38; adds	r53,0x0,r38; (p06) br.cond.dpnt.few	40000000000E9C90; }

l40000000000E9C70:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A900; }
	{ adds	r1,0x0,r51; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dpnt.few	40000000000EA410; }

l40000000000E9C90:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x4; (p06) br.cond.dptk.few	40000000000EA260; }

l40000000000E9CA0:
	{ cmp.eq	p06,p07,0x0,r37; adds	r53,0x0,r37; (p06) br.cond.dpnt.few	40000000000EA260; }

l40000000000E9CB0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B560; }
	{ cmp.eq	p07,p06,0x0,r8; nop.m	0x0; adds	r1,0x0,r51 }
	{ adds	r53,0x0,r8; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000EA570; }

l40000000000E9CE0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BD00; }
	{ adds	r1,0x0,r51; cmp.eq	p07,p06,0x0,r8; adds	r53,0x0,r0 }
	{ adds	r38,0x0,r8; addl	r55,5,r0; (p07) br.cond.dpnt.few	40000000000EA5E0; }

l40000000000E9D10:
	{ addl	r54,-7684,r1; nop.m	0x0; adds	r35,0x0,r8; }
	{ ld8	r54,[r54]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r51; adds	r55,0x0,r37; addl	r53,1,r0 }
	{ adds	r54,0x0,r8; adds	r37,0x28,r38; br.call.sptk.many	b0,fn400000000001BB80; }
	{ nop.m	0x0; adds	r1,0x0,r51; mov.i	LC,0x4; }

l40000000000E9D60:
	{ ld8	r55,[r35],8; addl	r54,-7676,r1; addl	r53,1,r0; }
	{ cmp.eq	p07,p06,0x0,r55; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000E9E10; }

l40000000000E9D80:
	{ ld8	r56,[r35]; ld8	r54,[r54]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r56; (p07) addl	r56,-7756,r1; nop.i	0x0; }

l40000000000E9D9C:
	{ Invalid; (p07) mov	pr,r127,0x9F5E; Invalid }

l40000000000E9DA6:
	{ (p28) fwb; nop; (p01) nop; }

l40000000000E9DAC:
	{ Invalid; Invalid; break.i	0x1000 }

l40000000000E9DB6:
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; (p02) nop; (p32) br.call.sptk.few	b3,b0 }

l40000000000E9DD0:
	{ ld8	r14,[r37]; nop.m	0x0; addl	r53,-7668,r1; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000E9E10; }

l40000000000E9DF0:
	{ ld8	r53,[r53]; br.call.sptk.many	b0,fn400000000001B380; nop.b	0x0; }
	{ adds	r1,0x0,r51; nop.m	0x0; nop.i	0x0 }

l40000000000E9E10:
	{ adds	r53,0x0,r38; adds	r35,0x0,r0; br.call.sptk.many	b0,strvec_dispose; }
	{ adds	r1,0x0,r51; tbit.z	p06,p07,r33,0xB; (p06) br.cond.dptk.few	40000000000E9EB0; }

l40000000000E9E30:
	{ cmp.eq	p06,p07,0x0,r41; adds	r53,0x0,r41; (p06) br.cond.dpnt.few	40000000000E9EB0; }

l40000000000E9E40:
	{ adds	r35,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B560; }
	{ cmp.eq	p07,p06,0x0,r8; nop.m	0x0; adds	r1,0x0,r51 }
	{ adds	r37,0x0,r8; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000EA500; }

l40000000000E9E70:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C100; }
	{ adds	r1,0x0,r51; nop.m	0x0; adds	r53,0x0,r37 }
	{ adds	r54,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BA60; }
	{ adds	r1,0x0,r51; nop.m	0x0; nop.i	0x0 }

l40000000000E9EB0:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x6; (p06) br.cond.dptk.few	40000000000E9F00; }

l40000000000E9EC0:
	{ cmp.eq	p06,p07,0x0,r40; nop.m	0x0; adds	r53,0x0,r40 }
	{ adds	r54,0x0,r0; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000E9F00; }

l40000000000E9EE0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A6A0; }
	{ adds	r1,0x0,r51; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dpnt.few	40000000000EA4A0; }

l40000000000E9F00:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0xC; (p07) br.cond.dpnt.few	40000000000EA3D0; }

l40000000000E9F10:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r34; (p06) br.cond.dpnt.few	40000000000E9F60; }

l40000000000E9F20:
	{ adds	r14,0x8,r34; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r53,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A980; }
	{ ld8	r34,[r34]; nop.m	0x0; adds	r1,0x0,r51; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	40000000000E9F20; }

l40000000000E9F60:
	{ cmp.eq	p06,p07,0x0,r36; adds	r53,0x0,r36; (p06) br.cond.spnt.few	40000000000E9A70; }

l40000000000E9F70:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AA00; }
	{ adds	r1,0x0,r51; addl	r53,-7732,r1; nop.i	0x0; }
	{ ld8	r53,[r53]; nop.i	0x0; br.call.sptk.many	b0,run_unwind_frame; }
	{ adds	r1,0x0,r51; adds	r53,0x0,r35; br.call.sptk.many	b0,sh_chkwrite; }
	{ adds	r1,0x0,r51; mov.i	ar.pfs,r50; mov.i	LC,r52; }
	{ nop.m	0x0; mov.spnt	b0,r49,40000000000E9FC0; br.ret	b0 }
40000000000E9FD0 11 00 00 00 01 00 10 42 84 5C 40 00 30 FA FF 48 .......B.\@.0..H
40000000000E9FE0 08 00 00 00 01 00 10 52 85 1C 40 00 00 00 04 00 .......R..@.....
40000000000E9FF0 19 48 01 46 18 10 00 00 00 02 00 00 10 FA FF 48 .H.F...........H
40000000000EA000 11 00 00 00 01 00 10 6A 85 1C 40 00 00 FA FF 48 .......j..@....H
40000000000EA010 08 00 00 00 01 00 10 02 86 5C 40 00 00 00 04 00 .........\@.....
40000000000EA020 19 40 01 46 18 10 00 00 00 02 00 00 E0 F9 FF 48 .@.F...........H
40000000000EA030 08 00 00 00 01 00 10 82 84 5C 40 00 00 00 04 00 .........\@.....
40000000000EA040 19 28 01 46 18 10 00 00 00 02 00 00 C0 F9 FF 48 .(.F...........H
40000000000EA050 11 00 00 00 01 00 10 12 84 5C 40 00 B0 F9 FF 48 .........\@....H
40000000000EA060 08 00 00 00 01 00 10 02 85 5C 40 00 00 00 04 00 .........\@.....
40000000000EA070 19 38 01 46 18 10 00 00 00 02 00 00 90 F9 FF 48 .8.F...........H
40000000000EA080 11 00 00 00 01 00 10 0A 84 5C 40 00 80 F9 FF 48 .........\@....H
40000000000EA090 08 00 00 00 01 00 10 22 84 5C 40 00 00 00 04 00 .......".\@.....
40000000000EA0A0 19 30 01 46 18 10 00 00 00 02 00 00 60 F9 FF 48 .0.F........`..H
40000000000EA0B0 11 00 00 00 01 00 10 5A 85 1C 40 00 50 F9 FF 48 .......Z..@.P..H
40000000000EA0C0 11 00 00 00 01 00 10 72 85 1C 40 00 40 F9 FF 48 .......r..@.@..H
40000000000EA0D0 10 00 00 00 01 00 10 0A B1 1C 40 00 30 F9 FF 48 ..........@.0..H

l40000000000EA0E0:
	{ adds	r40,0x0,r0; adds	r41,0x0,r0; adds	r37,0x0,r0 }
	{ adds	r39,0x0,r0; adds	r38,0x0,r0; br.call.sptk.many	b0,initialize_readline; }
	{ adds	r1,0x0,r51; adds	r33,0x0,r0; addl	r47,4096,r0 }
	{ addl	r46,1024,r0; addl	r45,512,r0; addl	r44,128,r0; }
	{ addl	r53,-7732,r1; addl	r43,256,r0; addl	r42,2048,r0; }
	{ ld8	r53,[r53]; nop.i	0x0; br.call.sptk.many	b0,begin_unwind_frame; }
	{ adds	r1,0x0,r51; addl	r54,8,r0; addl	r36,-10700,r1; }
	{ nop.m	0x0; ld8	r36,[r36]; nop.i	0x0; }
	{ adds	r53,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,unwind_protect_mem; }
	{ nop.m	0x0; adds	r1,0x0,r51; nop.i	0x0; }
	{ addl	r14,-10260,r1; addl	r34,-7652,r1; addl	r35,9252,r1; }
	{ ld8	r14,[r14]; ld8	r34,[r34]; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ st8	[r14],r36; nop.i	0x0; br.call.sptk.many	b0,reset_internal_getopt; }
	{ nop.m	0x0; adds	r1,0x0,r51; br.cond.sptk.few	40000000000E9A00; }

l40000000000EA1D0:
	{ addl	r54,-7740,r1; addl	r55,5,r0; adds	r53,0x0,r0; }
	{ ld8	r54,[r54]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r51; adds	r53,0x0,r8; br.call.sptk.many	b0,builtin_warning; }
	{ adds	r1,0x0,r51; addl	r14,7796,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000E9920 }

l40000000000EA230:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000EA0E0; }

l40000000000EA240:
	{ adds	r36,0x0,r0; tbit.z	p06,p07,r33,0x0; (p06) br.cond.dptk.few	40000000000E9BF0 }

l40000000000EA250:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000EA340; }

l40000000000EA260:
	{ adds	r35,0x0,r0; tbit.z	p06,p07,r33,0xB; (p06) br.cond.dptk.few	40000000000E9EB0 }

l40000000000EA270:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E9E30 }

l40000000000EA280:
	{ addl	r53,1,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AE40; }
	{ adds	r1,0x0,r51; tbit.z	p06,p07,r33,0x8; (p06) br.cond.dptk.few	40000000000E9C50 }

l40000000000EA2A0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000EA370 }

l40000000000EA2B0:
	{ addl	r53,1,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B160; }
	{ adds	r1,0x0,r51; tbit.z	p06,p07,r33,0xA; (p06) br.cond.dptk.few	40000000000E9C30 }

l40000000000EA2D0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000EA3A0 }

l40000000000EA2E0:
	{ adds	r53,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BAA0; }
	{ adds	r1,0x0,r51; tbit.z	p06,p07,r33,0x9; (p06) br.cond.dptk.few	40000000000E9C20 }

l40000000000EA300:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000EA2B0 }

l40000000000EA310:
	{ addl	r53,1,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BAA0; }
	{ adds	r1,0x0,r51; tbit.z	p06,p07,r33,0x7; (p06) br.cond.dptk.few	40000000000E9C10 }

l40000000000EA330:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000EA2E0 }

l40000000000EA340:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B260; }
	{ adds	r1,0x0,r51; tbit.z	p06,p07,r33,0x1; (p06) br.cond.dptk.few	40000000000E9C00 }

l40000000000EA360:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000EA310 }

l40000000000EA370:
	{ adds	r53,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AE40; }
	{ adds	r1,0x0,r51; tbit.z	p06,p07,r33,0x2; (p06) br.cond.dptk.few	40000000000E9C90 }

l40000000000EA390:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E9C60 }

l40000000000EA3A0:
	{ adds	r53,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B160; }
	{ adds	r1,0x0,r51; tbit.z	p06,p07,r33,0x3; (p06) br.cond.dptk.few	40000000000E9C40 }

l40000000000EA3C0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000EA280 }

l40000000000EA3D0:
	{ adds	r53,0x0,r48; nop.i	0x0; br.call.sptk.many	b0,bind_keyseq_to_unix_command; }
	{ nop.m	0x0; adds	r1,0x0,r51; adds	r35,0x0,r8 }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r34; (p07) br.cond.dptk.few	40000000000E9F20 }

l40000000000EA400:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E9F60; }

l40000000000EA410:
	{ addl	r54,-7708,r1; nop.m	0x0; addl	r55,5,r0 }
	{ adds	r53,0x0,r0; nop.m	0x0; addl	r35,1,r0; }
	{ ld8	r54,[r54]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r51; adds	r33,0x0,r8; br.call.sptk.many	b0,fn400000000001B840; }
	{ nop.m	0x0; adds	r1,0x0,r51; nop.i	0x0 }
	{ ld4	r53,[r8]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B4A0; }
	{ adds	r1,0x0,r51; adds	r53,0x0,r33; nop.i	0x0 }
	{ adds	r54,0x0,r38; adds	r55,0x0,r8; br.call.sptk.many	b0,builtin_error; }
	{ nop.m	0x0; adds	r1,0x0,r51; br.cond.sptk.few	40000000000E9F60; }

l40000000000EA4A0:
	{ addl	r54,-7660,r1; nop.m	0x0; addl	r55,5,r0 }
	{ adds	r53,0x0,r0; nop.m	0x0; addl	r35,1,r0; }
	{ ld8	r54,[r54]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r51; nop.m	0x0; adds	r53,0x0,r8 }
	{ adds	r54,0x0,r40; nop.m	0x0; br.call.sptk.many	b0,builtin_error; }
	{ nop.m	0x0; adds	r1,0x0,r51; br.cond.sptk.few	40000000000E9F60; }

l40000000000EA500:
	{ addl	r54,-7700,r1; nop.m	0x0; addl	r55,5,r0 }
	{ adds	r53,0x0,r0; nop.m	0x0; addl	r35,1,r0; }
	{ ld8	r54,[r54]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r51; nop.m	0x0; adds	r53,0x0,r8 }
	{ adds	r54,0x0,r41; nop.m	0x0; br.call.sptk.many	b0,builtin_error; }
	{ adds	r1,0x0,r51; tbit.z	p06,p07,r33,0x6; (p06) br.cond.dptk.few	40000000000E9F00 }

l40000000000EA560:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E9EC0; }

l40000000000EA570:
	{ addl	r54,-7700,r1; nop.m	0x0; addl	r55,5,r0 }
	{ adds	r53,0x0,r0; nop.m	0x0; addl	r35,1,r0; }
	{ ld8	r54,[r54]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r51; nop.m	0x0; adds	r53,0x0,r8 }
	{ adds	r54,0x0,r37; nop.m	0x0; br.call.sptk.many	b0,builtin_error; }
	{ adds	r1,0x0,r51; tbit.z	p06,p07,r33,0xB; (p06) br.cond.dptk.few	40000000000E9EB0 }

l40000000000EA5D0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E9E30; }

l40000000000EA5E0:
	{ addl	r54,-7692,r1; addl	r55,5,r0; addl	r35,1,r0; }
	{ ld8	r54,[r54]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r51; addl	r53,1,r0; nop.i	0x0 }
	{ adds	r54,0x0,r8; adds	r55,0x0,r37; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r51; tbit.z	p06,p07,r33,0xB; (p06) br.cond.dptk.few	40000000000E9EB0 }

l40000000000EA630:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000E9E30; }

l40000000000EA640:
	{ addl	r54,-7716,r1; nop.m	0x0; addl	r55,5,r0 }
	{ adds	r53,0x0,r0; nop.m	0x0; addl	r35,1,r0; }
	{ ld8	r54,[r54]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r54,0x0,r39; nop.m	0x0; adds	r53,0x0,r8 }
	{ adds	r1,0x0,r51; nop.m	0x0; br.call.sptk.many	b0,builtin_error; }
	{ adds	r1,0x0,r51; addl	r53,-7732,r1; nop.i	0x0; }
	{ ld8	r53,[r53]; nop.i	0x0; br.call.sptk.many	b0,run_unwind_frame; }
	{ adds	r1,0x0,r51; adds	r53,0x0,r35; br.call.sptk.many	b0,sh_chkwrite; }
	{ adds	r1,0x0,r51; mov.i	ar.pfs,r50; mov.i	LC,r52; }
	{ nop.m	0x0; mov.spnt	b0,r49,40000000000EA6D0; br.ret	b0; }
40000000000EA6E0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000EA6F0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; fn40000000000EA700: 40000000000EA700
;;   Called from:
;;     40000000000EA82C (in break_builtin)
;;     40000000000EA9EC (in continue_builtin)
fn40000000000EA700 proc
	{ alloc	r34,ar.pfs,0x7,0x0,0x4; addl	r32,8364,r1; nop.b	0x0 }
	{ addl	r14,6456,r1; mov	r33,b1; adds	r35,0x0,r1; }
	{ nop.m	0x0; ld4	r8,[r32]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r8; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000EA760; }

l40000000000EA740:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000EA780 }

l40000000000EA760:
	{ nop.m	0x0; mov.i	ar.pfs,r34; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000EA770; br.ret	b0 }

l40000000000EA780:
	{ addl	r37,-9436,r1; addl	r38,5,r0; adds	r36,0x0,r0; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r35; adds	r36,0x0,r8; br.call.sptk.many	b0,builtin_error; }
	{ ld4	r8,[r32]; adds	r1,0x0,r35; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000EA7C0; br.ret	b0; }
40000000000EA7D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000EA7E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000EA7F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; break_builtin: 40000000000EA800
break_builtin proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ adds	r36,0x0,r1; nop.m	0x0; mov	r34,b2; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000EA700; }
	{ adds	r14,0x0,r0; nop.m	0x0; cmp4.eq	p06,p07,0x0,r8 }
	{ adds	r1,0x0,r36; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000EA870; }

l40000000000EA850:
	{ adds	r8,0x0,r14; mov.i	ar.pfs,r35; mov.spnt	b0,r34,40000000000EA850 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000000EA870:
	{ adds	r37,0x0,r32; nop.m	0x0; adds	r39,0x10,r12 }
	{ addl	r38,1,r0; nop.m	0x0; br.call.sptk.many	b0,get_numeric_arg; }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r14,0x10,r12; }
	{ ld8	r15,[r14]; nop.m	0x0; addl	r16,8364,r1 }
	{ adds	r14,0x0,r0; nop.m	0x0; addl	r17,8360,r1; }
	{ cmp.lt	p06,p07,0x0,r15; adds	r8,0x0,r14; (p07) br.cond.dpnt.few	40000000000EA910; }

l40000000000EA8D0:
	{ ld4	r16,[r16]; nop.m	0x0; sxt4	r16,r16; }
	{ cmp.lt	p07,p06,r15,r16; (p06) adds	r15,0x0,r16; nop.i	0x0; }

l40000000000EA8EC:
	{ Invalid; Invalid; (p48) break.i	0x2A808 }
	{ (p17) nop; add	r0,r32,r0; (p01) shladd	r4,r3,0x1,r64 }
	{ nop; (p04) invala; cmp.lt	p00,p00,r32,r0 }

l40000000000EA910:
	{ adds	r32,0x8,r32; nop.m	0x0; addl	r38,-9428,r1 }
	{ addl	r39,5,r0; nop.m	0x0; adds	r37,0x0,r0; }
	{ ld8	r14,[r32]; ld8	r38,[r38]; nop.i	0x0; }
	{ ld8	r33,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r38,0x0,r8 }
	{ adds	r37,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,sh_erange; }
	{ adds	r1,0x0,r36; addl	r14,1,r0; addl	r15,8364,r1 }
	{ adds	r8,0x0,r14; ld4	r16,[r15]; addl	r15,8360,r1; }
	{ st4	[r16],r15; mov.i	ar.pfs,r35; mov.spnt	b0,r34,40000000000EA990 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }
40000000000EA9B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; continue_builtin: 40000000000EA9C0
continue_builtin proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ adds	r36,0x0,r1; nop.m	0x0; mov	r34,b2; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000EA700; }
	{ adds	r14,0x0,r0; nop.m	0x0; cmp4.eq	p06,p07,0x0,r8 }
	{ adds	r1,0x0,r36; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000EAA30; }

l40000000000EAA10:
	{ adds	r8,0x0,r14; mov.i	ar.pfs,r35; mov.spnt	b0,r34,40000000000EAA10 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l40000000000EAA30:
	{ adds	r37,0x0,r32; nop.m	0x0; adds	r39,0x10,r12 }
	{ addl	r38,1,r0; nop.m	0x0; br.call.sptk.many	b0,get_numeric_arg; }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r14,0x10,r12; }
	{ ld8	r15,[r14]; nop.m	0x0; addl	r16,8364,r1 }
	{ adds	r14,0x0,r0; nop.m	0x0; addl	r17,8356,r1; }
	{ cmp.lt	p06,p07,0x0,r15; adds	r8,0x0,r14; (p07) br.cond.dpnt.few	40000000000EAAD0; }

l40000000000EAA90:
	{ ld4	r16,[r16]; nop.m	0x0; sxt4	r16,r16; }
	{ cmp.lt	p07,p06,r15,r16; (p06) adds	r15,0x0,r16; nop.i	0x0; }

l40000000000EAAAC:
	{ Invalid; Invalid; (p48) break.i	0x2A808 }
	{ (p17) nop; add	r0,r32,r0; (p01) shladd	r4,r3,0x1,r64 }
	{ nop; (p04) invala; cmp.lt	p00,p00,r32,r0 }

l40000000000EAAD0:
	{ adds	r32,0x8,r32; nop.m	0x0; addl	r38,-9428,r1 }
	{ addl	r39,5,r0; nop.m	0x0; adds	r37,0x0,r0; }
	{ ld8	r14,[r32]; ld8	r38,[r38]; nop.i	0x0; }
	{ ld8	r33,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r38,0x0,r8 }
	{ adds	r37,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,sh_erange; }
	{ adds	r1,0x0,r36; addl	r14,1,r0; addl	r15,8364,r1 }
	{ adds	r8,0x0,r14; ld4	r16,[r15]; addl	r15,8360,r1; }
	{ st4	[r16],r15; mov.i	ar.pfs,r35; mov.spnt	b0,r34,40000000000EAB50 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }
40000000000EAB70 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; builtin_builtin: 40000000000EAB80
builtin_builtin proc
	{ alloc	r36,ar.pfs,0x7,0x0,0x6; adds	r37,0x0,r1; mov	r35,b3 }
	{ nop.m	0x0; adds	r38,0x0,r32; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,no_options; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r8; adds	r1,0x0,r37 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000EAC00; }

l40000000000EABD0:
	{ (p06) addl	r8,258,r0; nop.m	0x0; nop.i	0x0 }

l40000000000EABD6:
	{ break.m	0x4000; mov	pr,0x4000; break.i	0x80000 }

l40000000000EABE0:
	{ nop.m	0x0; mov.i	ar.pfs,r36; nop.i	0x0; }

l40000000000EABE2:
	{ add	r32,r0,r0; (p04) break.i	0x550; Invalid }

l40000000000EABE6:
	{ break.m	0xAA024; nop; break.i	0x80000 }

l40000000000EABE8:
	{ (p40) break.m	0xA; (p16) break.i	0x10000; nop; }
	{ nop; break.x	0x18058042012240; }

l40000000000EAC00:
	{ addl	r14,9268,r1; nop.m	0x0; nop.i	0x0; }
	{ ld8	r33,[r14]; cmp.eq	p06,p07,0x0,r33; adds	r14,0x8,r33; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000EABE0; }

l40000000000EAC26:
	{ chk.a.nc	r0,3FFFFFFFFF0EB426; nop; (p32) nop }

l40000000000EAC30:
	{ ld8	r14,[r14]; ld8	r34,[r14]; nop.i	0x0; }
	{ adds	r38,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,find_shell_builtin; }
	{ adds	r1,0x0,r37; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	40000000000EACC0; }

l40000000000EAC60:
	{ addl	r14,9036,r1; ld8	r38,[r33]; nop.i	0x0; }
	{ nop.m	0x0; st8	[r34],r14; nop.i	0x0; }
	{ ld8	r14,[r8],8; nop.m	0x0; mov.spnt	b6,r14,40000000000EAC80 }
	{ ld8	r1,[r8]; nop.m	0x0; br.call.sptk.many	b0,b6; }
	{ adds	r1,0x0,r37; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000EACB0; br.ret	b0; }

l40000000000EACC0:
	{ adds	r38,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,sh_notbuiltin; }
	{ addl	r8,1,r0; adds	r1,0x0,r37; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000EACE0; br.ret	b0; }
40000000000EACF0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; caller_builtin: 40000000000EAD00
caller_builtin proc
	{ alloc	r38,ar.pfs,0xD,0x0,0x8; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ addl	r40,-1220,r1; adds	r39,0x0,r1; mov	r37,b5; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r14,0x28,r8; nop.m	0x0; cmp.eq	p06,p07,0x0,r8 }
	{ adds	r1,0x0,r39; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000EAF20; }

l40000000000EAD50:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x2; (p06) br.cond.dptk.few	40000000000EAF20; }

l40000000000EAD70:
	{ nop.m	0x0; (p07) adds	r8,0x8,r8; nop.i	0x0; }

l40000000000EAD7C:
	{ nop; Invalid; break.i	0x1000 }

l40000000000EAD86:
	{ break.m	0x4000; nop; break.i	0x80000 }

l40000000000EAD90:
	{ nop.m	0x0; addl	r40,-1212,r1; nop.i	0x0; }

l40000000000EAD92:
	{ padd4	r32,r0,r0; (p24) break.i	0x4FEDF; dep	r32,r0,r32,63,5 }
	{ break.m	0x2030A; tbit.z	p32,p00,r0,0x0; Invalid; }
	{ (p05) break.m	0x42002; chk.s.i	r0,40000000008EAFB2; Invalid }
	{ (p48) break.m	0x42009; nop; Invalid }

l40000000000EADD0:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x2; (p06) br.cond.dptk.few	40000000000EAF10; }

l40000000000EADF0:
	{ nop.m	0x0; (p07) adds	r8,0x8,r8; nop.i	0x0; }

l40000000000EADFC:
	{ nop; Invalid; break.i	0x1000 }

l40000000000EAE06:
	{ break.m	0x4000; nop; break.i	0x80000 }

l40000000000EAE10:
	{ nop.m	0x0; addl	r40,-1204,r1; nop.i	0x0; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r14,0x28,r8; nop.m	0x0; adds	r1,0x0,r39 }
	{ cmp.eq	p07,p06,0x0,r8; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000EAEE0; }

l40000000000EAE50:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x2; (p06) br.cond.dptk.few	40000000000EAEE0 }

l40000000000EAE70:
	{ adds	r8,0x8,r8; ld8	r34,[r8]; nop.i	0x0; }
	{ adds	r14,0x10,r34; cmp.eq	p06,p07,0x0,r34; (p06) br.cond.spnt.few	40000000000EAEE0; }

l40000000000EAE90:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; adds	r14,0x10,r33; (p06) br.cond.dpnt.few	40000000000EAEE0; }

l40000000000EAEB0:
	{ cmp.eq	p06,p07,0x0,r33; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000EAEE0; }

l40000000000EAEC0:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000EAF30 }

l40000000000EAEE0:
	{ addl	r8,1,r0; nop.m	0x0; nop.i	0x0 }

l40000000000EAEF0:
	{ nop.m	0x0; mov.i	ar.pfs,r38; mov.spnt	b0,r37,40000000000EAEF0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000EAF10:
	{ nop.m	0x0; adds	r33,0x0,r0; br.cond.sptk.few	40000000000EAE10 }

l40000000000EAF20:
	{ nop.m	0x0; adds	r35,0x0,r0; br.cond.sptk.few	40000000000EAD90; }

l40000000000EAF30:
	{ adds	r40,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,no_options; }
	{ cmp4.eq	p07,p06,0x0,r8; nop.m	0x0; adds	r1,0x0,r39; }
	{ nop.m	0x0; (p06) addl	r8,258,r0; (p06) br.cond.dptk.few	40000000000EAEF0 }

l40000000000EAF5C:
	{ (p61) cmp.lt.unc	p63,p09,r63,r37; zxt4	r45,r18; cmp.eq	p00,p00,r32,r0 }

l40000000000EAF60:
	{ addl	r14,9268,r1; nop.m	0x0; adds	r15,0x10,r35; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000EB140; }

l40000000000EAF90:
	{ cmp.eq	p06,p07,0x0,r35; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000EAEE0; }

l40000000000EAFA0:
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	40000000000EAEE0 }

l40000000000EAFC0:
	{ adds	r36,0x8,r14; nop.m	0x0; adds	r41,0x10,r12; }
	{ nop.m	0x0; ld8	r14,[r36]; nop.i	0x0; }
	{ ld8	r40,[r14]; nop.i	0x0; br.call.sptk.many	b0,legal_number; }
	{ adds	r1,0x0,r39; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	40000000000EB100 }

l40000000000EB000:
	{ adds	r14,0x10,r12; nop.m	0x0; adds	r40,0x0,r34; }
	{ ld8	r41,[r14]; nop.i	0x0; br.call.sptk.many	b0,array_reference; }
	{ adds	r14,0x10,r12; adds	r34,0x0,r8; adds	r1,0x0,r39 }
	{ adds	r40,0x0,r33; ld8	r41,[r14]; nop.i	0x0; }
	{ adds	r41,0x1,r41; nop.i	0x0; br.call.sptk.many	b0,array_reference; }
	{ adds	r14,0x10,r12; adds	r33,0x0,r8; adds	r1,0x0,r39 }
	{ adds	r40,0x0,r35; ld8	r41,[r14]; nop.i	0x0; }
	{ adds	r41,0x1,r41; nop.i	0x0; br.call.sptk.many	b0,array_reference; }
	{ cmp.eq	p06,p07,0x0,r34; adds	r1,0x0,r39; addl	r40,1,r0 }
	{ adds	r42,0x0,r34; adds	r43,0x0,r8; adds	r44,0x0,r33; }
	{ cmp.eq.or.andcm	p06,p07,0x0,r33; addl	r41,-1188,r1; (p06) br.cond.dpnt.few	40000000000EAEE0; }

l40000000000EB0B0:
	{ cmp.eq	p06,p07,0x0,r8; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000EAEE0; }

l40000000000EB0C0:
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r8,0x0,r0; adds	r1,0x0,r39; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,40000000000EB0E0; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l40000000000EB100:
	{ nop.m	0x0; ld8	r14,[r36]; nop.i	0x0; }
	{ ld8	r40,[r14]; nop.i	0x0; br.call.sptk.many	b0,sh_invalidnum; }
	{ adds	r1,0x0,r39; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ adds	r1,0x0,r39; addl	r8,1,r0; br.cond.sptk.few	40000000000EAEF0 }

l40000000000EB140:
	{ adds	r40,0x0,r34; adds	r41,0x0,r0; br.call.sptk.many	b0,array_reference; }
	{ adds	r1,0x0,r39; adds	r34,0x0,r8; nop.i	0x0 }
	{ adds	r40,0x0,r33; addl	r41,1,r0; br.call.sptk.many	b0,array_reference; }
	{ cmp.eq	p07,p06,0x0,r8; adds	r1,0x0,r39; addl	r40,1,r0; }
	{ (p07) adds	r43,0x0,r0; addl	r41,-1196,r1; (p06) adds	r43,0x1,r0 }

l40000000000EB186:
	{ Invalid; (p21) nop; nop }

l40000000000EB190:
	{ cmp.eq	p07,p06,0x0,r34; ld8	r41,[r41]; nop.i	0x0; }
	{ (p07) adds	r42,0x0,r0; (p06) adds	r42,0x1,r0; tbit.z	p07,p06,r43,0x0; }

l40000000000EB1A6:
	{ Invalid; (p03) cmp4.ltu	p00,p40,0x2B,r6; (p49) nop; }

l40000000000EB1AC:
	{ setf.exp	f43,r6; (p05) nop; zxt1	r0,r64 }

l40000000000EB1B6:
	{ Invalid; cmp4.lt	p00,p00,0x0,r1; (p49) br.call.sptk.few	b2,b0; }

l40000000000EB1BC:
	{ setf.sig	f0,r1; (p05) cmp.eq.unc	p32,p08,r10,r6; dep	r64,r74,r1,49,11 }

l40000000000EB1C6:
	{ (p03) chk.a.nc	f0,3FFFFFFFFFAEE466; (p21) nop; Invalid }

l40000000000EB1D0:
	{ nop.m	0x0; (p06) adds	r42,0x0,r34; nop.i	0x0; }

l40000000000EB1DC:
	{ getf.s	r0,f1; Invalid; break.i	0x1000 }

l40000000000EB1E6:
	{ break.m	0x4000; (p32) nop; nop }
	{ Invalid; break.i	0xAA026; break.b	0x80000 }
	{ Invalid; nop; nop }
	{ break.m	0x4000; (p34) break.i	0x84000; (p32) break.i	0x80001 }
40000000000EB220 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000EB230 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; fn40000000000EB240: 40000000000EB240
;;   Called from:
;;     40000000000EB61C (in fn40000000000EB300)
;;     40000000000EB85C (in fn40000000000EB300)
;;     40000000000EC9DC (in pwd_builtin)
;;     40000000000ECA3C (in pwd_builtin)
fn40000000000EB240 proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; addl	r33,8380,r1; nop.b	0x0 }
	{ adds	r36,0x0,r1; nop.m	0x0; mov	r34,b2; }
	{ nop.m	0x0; ld8	r37,[r33]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r37; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000EB2A0; }

l40000000000EB280:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r36; nop.m	0x0; nop.i	0x0 }

l40000000000EB2A0:
	{ st8	[r0],r33; adds	r37,0x0,r32; br.call.sptk.many	b0,get_working_directory; }
	{ adds	r1,0x0,r36; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000EB2C0; br.ret	b0; }
40000000000EB2D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000EB2E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000EB2F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000EB300: 40000000000EB300
;;   Called from:
;;     40000000000EC14C (in cd_builtin)
;;     40000000000EC1BC (in cd_builtin)
;;     40000000000EC2AC (in cd_builtin)
;;     40000000000EC4EC (in cd_builtin)
;;     40000000000EC59C (in cd_builtin)
fn40000000000EB300 proc
	{ alloc	r39,ar.pfs,0xC,0x0,0xA; addl	r34,8380,r1; mov	r41,pr }
	{ adds	r40,0x0,r1; cmp4.eq	p16,p17,0x0,r33; adds	r42,0x0,r32; }
	{ nop.m	0x0; nop.m	0x0; mov	r38,b6; }
	{ nop.m	0x0; ld8	r43,[r34]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r43; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000EB660; }

l40000000000EB350:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,make_absolute; }
	{ adds	r1,0x0,r40; adds	r35,0x0,r8; nop.i	0x0 }
	{ adds	r42,0x0,r8; (p17) adds	r43,0x0,r0; (p17) br.call.dptk.many	b0,sh_physpath; }

l40000000000EB37C:
	{ (p14) ldfps	f4,f1,[r41],8; (p53) invala.e	r0; break.b	0x101000 }

l40000000000EB380:
	{ (p16) addl	r43,3,r0; nop.i	0x0; (p16) br.call.dptk.many	b0,sh_canonpath; }

l40000000000EB386:
	{ nop; (p32) nop; (p16) nop }

l40000000000EB390:
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r34,0x0,r8 }
	{ adds	r42,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; adds	r1,0x0,r40; adds	r37,0x0,r8 }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r34; (p06) br.cond.dpnt.few	40000000000EB760 }

l40000000000EB3D0:
	{ ld1	r14,[r34]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; (p06) adds	r42,0x0,r34; (p07) adds	r36,0x0,r0 }

l40000000000EB3EC:
	{ Invalid; nop }

l40000000000EB3F0:
	{ (p06) adds	r34,0x0,r35; nop.m	0x0; (p07) adds	r42,0x0,r35 }

l40000000000EB3F6:
	{ chk.a.nc	f0,3FFFFFFFFF0EBBF6; (p21) nop; add	r0,r0,r32 }

l40000000000EB400:
	{ nop.m	0x0; (p06) addl	r36,1,r0; br.call.sptk.many	b0,fn400000000001A7E0; }

l40000000000EB40C:
	{ (p31) nop; invala; break.i	0x1000 }
	{ cmp.lt	p00,p11,r1,r0; zxt4	r46,r12; break.i	0x1000 }

l40000000000EB420:
	{ addl	r14,6456,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000EB510 }

l40000000000EB450:
	{ (p16) addl	r14,1,r0; (p17) adds	r14,0x0,r0; nop.i	0x0; }

l40000000000EB456:
	{ Invalid; break.x	0x20000080000 }

l40000000000EB45C:
	{ nop; cmp.lt	p00,p00,r32,r0; zxt1	r73,r3 }
	{ invala; cmp.lt	p00,p00,r32,r0; mov	pr,r99,0xE680 }
	{ Invalid; break.i	0x1000; break.i	0x1000 }

l40000000000EB480:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ ld4	r14,[r8]; adds	r1,0x0,r40; adds	r35,0x0,r8; }
	{ cmp4.eq	p07,p06,0x24,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000EB5C0; }

l40000000000EB4B0:
	{ cmp4.eq	p06,p07,0x2,r14; nop.i	0x0; (p07) addl	r14,20,r0; }

l40000000000EB4C0:
	{ (p07) st4	[r14],r8; nop.m	0x0; nop.i	0x0 }

l40000000000EB4C6:
	{ break.m	0x4000; nop; (p32) nop }

l40000000000EB4D0:
	{ adds	r42,0x0,r34; adds	r35,0x0,r0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r40; mov	pr,r41,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r39; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000EB500; br.ret	b0 }

l40000000000EB510:
	{ cmp4.eq	p07,p06,0x0,r33; adds	r42,0x0,r32; (p07) br.cond.dpnt.few	40000000000EB770; }

l40000000000EB520:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AEE0; }
	{ adds	r1,0x0,r40; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	40000000000EB4D0; }

l40000000000EB540:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r36; (p07) br.cond.spnt.few	40000000000EB600; }

l40000000000EB550:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000EB560:
	{ adds	r42,0x0,r34; addl	r35,1,r0; br.call.sptk.many	b0,set_working_directory; }
	{ nop.m	0x0; adds	r1,0x0,r40; adds	r42,0x0,r34 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r40; nop.m	0x0; nop.i	0x0 }

l40000000000EB5A0:
	{ adds	r8,0x0,r35; mov	pr,r41,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000EB5B0; br.ret	b0 }

l40000000000EB5C0:
	{ nop.m	0x0; addl	r14,4096,r0; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r14,r37; (p06) br.cond.dptk.few	40000000000EB4D0 }

l40000000000EB5E0:
	{ adds	r42,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AEE0; }
	{ adds	r1,0x0,r40; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	40000000000EB7C0; }

l40000000000EB600:
	{ addl	r42,1204,r1; nop.m	0x0; addl	r35,1,r0; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,fn40000000000EB240; }
	{ cmp.eq	p07,p06,0x0,r8; nop.m	0x0; adds	r1,0x0,r40 }
	{ adds	r42,0x0,r34; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000EB560; }

l40000000000EB640:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r40; br.cond.sptk.few	40000000000EB5A0; }

l40000000000EB660:
	{ nop.m	0x0; addl	r42,1196,r1; nop.i	0x0; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,get_working_directory; }
	{ cmp.eq	p07,p06,0x0,r8; nop.m	0x0; adds	r1,0x0,r40 }
	{ adds	r42,0x0,r8; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000EB6C0; }

l40000000000EB6A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r40; nop.m	0x0; nop.i	0x0 }

l40000000000EB6C0:
	{ ld8	r43,[r34]; nop.m	0x0; cmp4.eq	p16,p17,0x0,r33 }
	{ adds	r42,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,make_absolute; }
	{ adds	r1,0x0,r40; adds	r35,0x0,r8; nop.i	0x0 }
	{ adds	r42,0x0,r8; (p17) adds	r43,0x0,r0; (p17) br.call.dptk.many	b0,sh_physpath; }

l40000000000EB6FC:
	{ (p50) ldfps	f3,f1,[r41],8; (p53) invala.e	r0; break.b	0x101000 }

l40000000000EB700:
	{ (p16) addl	r43,3,r0; nop.i	0x0; (p16) br.call.dptk.many	b0,sh_canonpath; }

l40000000000EB706:
	{ nop; (p32) nop; (p16) nop }

l40000000000EB710:
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r34,0x0,r8 }
	{ adds	r42,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; adds	r1,0x0,r40; adds	r37,0x0,r8 }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r34; (p07) br.cond.dptk.few	40000000000EB3D0; }

l40000000000EB750:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000EB760:
	{ adds	r34,0x0,r35; addl	r36,1,r0; br.cond.sptk.few	40000000000EB420; }

l40000000000EB770:
	{ adds	r42,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AEE0; }
	{ adds	r1,0x0,r40; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	40000000000EB540 }

l40000000000EB790:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ nop.m	0x0; adds	r1,0x0,r40; adds	r35,0x0,r8; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000EB7C0:
	{ ld4	r36,[r35]; adds	r42,0x0,r32; br.call.sptk.many	b0,fn400000000001AEE0; }
	{ cmp4.eq	p07,p06,0x0,r8; nop.m	0x0; adds	r1,0x0,r40 }
	{ adds	r42,0x0,r34; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000EB840; }

l40000000000EB7F0:
	{ nop.m	0x0; (p06) st4	[r36],r35; (p06) adds	r35,0x0,r0 }

l40000000000EB7FC:
	{ nop; break.x	0x8000001000 }

l40000000000EB800:
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r40; nop.m	0x0; nop.i	0x0 }

l40000000000EB820:
	{ adds	r8,0x0,r35; mov	pr,r41,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000EB830; br.ret	b0 }

l40000000000EB840:
	{ addl	r42,1204,r1; nop.m	0x0; addl	r35,1,r0; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,fn40000000000EB240; }
	{ cmp.eq	p07,p06,0x0,r8; nop.m	0x0; adds	r1,0x0,r40 }
	{ adds	r42,0x0,r8; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000EB8B0; }

l40000000000EB880:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r40; adds	r42,0x0,r34; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r40; br.cond.sptk.few	40000000000EB820 }

l40000000000EB8B0:
	{ adds	r42,0x0,r34; addl	r35,1,r0; br.call.sptk.many	b0,set_working_directory; }
	{ adds	r1,0x0,r40; adds	r42,0x0,r34; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r40; br.cond.sptk.few	40000000000EB820; }
40000000000EB8E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000EB8F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000EB900: 40000000000EB900
;;   Called from:
;;     40000000000EC8BC (in pwd_builtin)
;;     40000000000EC8BC (in pwd_builtin)
fn40000000000EB900 proc
	{ alloc	r36,ar.pfs,0x9,0x0,0x6; cmp.eq	p07,p06,0x0,r32; mov	r35,b3 }
	{ addl	r33,5780,r1; addl	r38,1220,r1; adds	r37,0x0,r1; }
	{ (p07) addl	r32,1212,r1; nop.m	0x0; adds	r40,0x0,r0 }

l40000000000EB926:
	{ break.m	0x4000; (p20) nop; (p32) cmp.ltu	p09,p06,r64,r9 }
	{ (p16) fwb; nop; (p32) nop; }

l40000000000EB93C:
	{ cmpxchg4.acq	r0,[r0],r1; (p04) cmp.eq	p32,p08,r8,r4; zxt1	r0,r64 }
	{ (p20) cmp.lt.unc	p57,p08,r61,r44; flushrs; (p01) nop }
	{ cmp.eq	p37,p25,r0,r66; zxt4	r1,r0; (p05) mov	pr,r8,0x8400 }
	{ (p05) cmp.lt	p00,p03,r64,r33; (p01) cmp.lt	p00,p08,r2,r4; Invalid }

l40000000000EB970:
	{ ld4	r14,[r8]; addl	r38,1228,r1; tbit.z	p07,p06,r14,0x1; }
	{ (p06) addl	r8,1,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000EB9F0; }

l40000000000EB986:
	{ chk.a.nc	r0,3FFFFFFFFF0EC186; nop; (p48) nop }

l40000000000EB990:
	{ cmp4.eq	p07,p06,0x0,r34; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000EBA10; }

l40000000000EB9A0:
	{ nop.m	0x0; ld4	r15,[r33]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r15; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000EBA10; }

l40000000000EB9C0:
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x0; (p06) br.cond.dpnt.few	40000000000EBA10; }

l40000000000EB9D0:
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,update_export_env_inplace; }
	{ adds	r1,0x0,r37; st4	[r0],r33; adds	r8,0x0,r0 }

l40000000000EB9F0:
	{ nop.m	0x0; mov.i	ar.pfs,r36; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000EBA00; br.ret	b0 }

l40000000000EBA10:
	{ adds	r8,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000EBA20; br.ret	b0; }
40000000000EBA30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000EBA40: 40000000000EBA40
;;   Called from:
;;     40000000000EC1FC (in cd_builtin)
;;     40000000000EC49C (in cd_builtin)
;;     40000000000EC63C (in cd_builtin)
fn40000000000EBA40 proc
	{ alloc	r40,ar.pfs,0xD,0x0,0xA; addl	r35,8380,r1; nop.b	0x0 }
	{ adds	r41,0x0,r1; nop.m	0x0; mov	r39,b7; }
	{ nop.m	0x0; adds	r42,0x0,r0; br.call.sptk.many	b0,sh_chkwrite; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r33,0x0,r8; }
	{ nop.m	0x0; ld8	r34,[r35]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r34; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000EBD20; }

l40000000000EBAA0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r32; (p07) br.cond.dpnt.few	40000000000EBC20 }

l40000000000EBAB0:
	{ addl	r36,5780,r1; nop.m	0x0; addl	r42,1220,r1; }
	{ nop.m	0x0; ld8	r42,[r42]; nop.i	0x0; }
	{ ld4	r38,[r36]; nop.i	0x0; br.call.sptk.many	b0,get_string_value; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r37,0x0,r8 }
	{ adds	r43,0x0,r8; adds	r44,0x0,r0; addl	r42,1236,r1; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r14,0x28,r8; nop.m	0x0; cmp.eq	p06,p07,0x0,r8 }
	{ adds	r1,0x0,r41; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000EBB50; }

l40000000000EBB30:
	{ ld4	r14,[r14]; nop.i	0x0; tbit.z	p07,p06,r14,0x1; }
	{ (p06) addl	r33,1,r0; nop.m	0x0; nop.i	0x0 }

l40000000000EBB46:
	{ break.m	0x4000; nop; break.i	0x80000 }

l40000000000EBB50:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r38; (p06) br.cond.dptk.few	40000000000EBB80 }

l40000000000EBB52:
	{ Invalid; (p32) nop; Invalid }

l40000000000EBB56:
	{ (p03) chk.a.clr	r0,3FFFFFFFFFDAEDB6; nop; break.b	0x80000 }

l40000000000EBB5C:
	{ (p01) nop; cmp.lt	p00,p00,r32,r0; (p01) rfi }

l40000000000EBB6C:
	{ invala; cmp.lt	p00,p00,r32,r0; mov	pr,r99,0xE680 }

l40000000000EBB7C:
	{ (p06) cmpxchg4.acq	r0,[r33],r0; zxt1	r64,r64; break.b	0x1000 }

l40000000000EBB86:
	{ break.m	0x4000; Invalid; (p32) nop }
	{ chk.a.clr	r0,3FFFFFFFFF16BE26; (p04) cmp4.eq.and	p01,p02,0x0,r0; (p01) nop.b	0x2 }
	{ Invalid; (p04) nop; break.b	0x80000 }
	{ (p16) chk.a.clr	f1,3FFFFFFFFF2EBBB6; br.call.dptk.few	b3,b0; (p32) br.call.sptk.few	b3,b0 }
	{ break.m	0x4000; (p21) nop; (p48) nop }
	{ chk.a.nc	f0,3FFFFFFFFF0EC3D6; nop; break.i	0x80000 }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; nop; nop }
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ Invalid; (p34) nop; (p32) nop }

l40000000000EBC20:
	{ adds	r42,0x0,r34; adds	r43,0x0,r0; br.call.sptk.many	b0,sh_physpath; }
	{ adds	r1,0x0,r41; adds	r34,0x0,r8; br.cond.sptk.few	40000000000EBAB0 }
40000000000EBC40 0B 40 A0 10 00 21 E0 00 20 20 20 00 00 00 04 00 .@...!..   .....
40000000000EBC50 10 00 00 00 01 00 60 00 38 0E 28 03 30 FF FF 4A ......`.8.(.0..J
40000000000EBC60 09 50 71 03 09 24 B0 3A 00 00 48 80 05 28 01 84 .Pq..$.:..H..(..
40000000000EBC70 11 50 01 54 18 10 00 00 00 02 00 00 98 A9 F7 58 .P.T...........X
40000000000EBC80 03 08 00 52 00 21 A0 02 88 00 42 C0 41 09 B4 90 ...R.!....B.A...
40000000000EBC90 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000EBCA0 11 00 00 1C 90 11 00 00 00 02 00 00 68 FC FF 58 ............h..X
40000000000EBCB0 03 30 04 10 87 39 10 00 A4 00 42 03 11 00 00 84 .0...9....B.....
40000000000EBCC0 E3 40 00 00 00 21 70 00 88 0C 72 20 01 40 20 50 .@...!p...r .@ P
40000000000EBCD0 11 00 00 00 01 00 12 0A 00 00 48 03 F0 FE FF 4A ..........H....J
40000000000EBCE0 09 70 D0 02 41 24 00 00 00 02 00 00 80 02 AA 00 .p..A$..........
40000000000EBCF0 03 70 00 1C 10 10 00 38 05 80 03 E0 00 70 18 E6 .p.....8.....p..
40000000000EBD00 09 00 00 00 01 80 11 0A 00 00 48 00 00 00 04 00 ..........H.....
40000000000EBD10 10 00 00 00 01 00 80 00 84 00 42 80 08 00 84 00 ..........B.....

l40000000000EBD20:
	{ nop.m	0x0; addl	r42,1204,r1; nop.i	0x0; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,get_working_directory; }
	{ adds	r1,0x0,r41; adds	r34,0x0,r8; br.cond.sptk.few	40000000000EBAB0; }
40000000000EBD50 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000EBD60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000EBD70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; cd_builtin: 40000000000EBD80
;;   Called from:
;;     4000000000101A6C (in fn40000000001019C0)
;;     40000000001031CC (in pushd_builtin)
cd_builtin proc
	{ alloc	r41,ar.pfs,0xE,0x0,0xB; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r40,b0 }
	{ addl	r14,7352,r1; adds	r42,0x0,r1; addl	r33,8372,r1; }
	{ nop.m	0x0; nop.m	0x0; addl	r35,1,r0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; addl	r14,7360,r1; (p07) br.cond.dpnt.few	40000000000EBED0; }

l40000000000EBDD0:
	{ nop.m	0x0; st4	[r0],r33; nop.i	0x0; }
	{ ld4	r34,[r14]; br.call.sptk.many	b0,reset_internal_getopt; nop.b	0x0; }
	{ adds	r1,0x0,r42; nop.m	0x0; nop.i	0x0; }

l40000000000EBE00:
	{ addl	r44,1252,r1; nop.m	0x0; adds	r43,0x0,r32; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,internal_getopt; }
	{ cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; adds	r1,0x0,r42; (p07) br.cond.dpnt.few	40000000000EBF10; }

l40000000000EBE30:
	{ cmp4.eq	p06,p07,0x50,r8; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000EBEB0; }

l40000000000EBE40:
	{ cmp4.eq	p06,p07,0x65,r8; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000EBEC0; }

l40000000000EBE50:
	{ cmp4.eq	p06,p07,0x4C,r8; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000EBEA0; }

l40000000000EBE60:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,builtin_usage; }
	{ addl	r8,1,r0; adds	r1,0x0,r42; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.spnt	b0,r40,40000000000EBE80; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l40000000000EBEA0:
	{ nop.m	0x0; adds	r34,0x0,r0; br.cond.sptk.few	40000000000EBE00; }

l40000000000EBEB0:
	{ nop.m	0x0; addl	r34,1,r0; br.cond.sptk.few	40000000000EBE00 }

l40000000000EBEC0:
	{ st4	[r35],r33; nop.i	0x0; br.cond.sptk.few	40000000000EBE00 }

l40000000000EBED0:
	{ adds	r43,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,sh_restricted; }
	{ addl	r8,1,r0; adds	r1,0x0,r42; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.spnt	b0,r40,40000000000EBEF0; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l40000000000EBF10:
	{ nop.m	0x0; addl	r14,9236,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r37,[r14]; addl	r14,6516,r1; }
	{ nop.m	0x0; cmp4.eq	p09,p08,0x0,r37; (p08) addl	r37,1,r0; }

l40000000000EBF40:
	{ ld4	r15,[r14]; addl	r14,9268,r1; (p09) adds	r37,0x0,r0; }

l40000000000EBF50:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) adds	r16,0x0,r0; }

l40000000000EBF60:
	{ ld8	r14,[r14]; nop.i	0x0; (p06) br.cond.dptk.few	40000000000EBFA0 }

l40000000000EBF70:
	{ addl	r15,8368,r1; ld4	r16,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r16; nop.i	0x0; }
	{ (p06) adds	r16,0x0,r0; nop.i	0x0; (p07) addl	r16,2,r0; }

l40000000000EBF96:
	{ chk.a.nc	f0,3FFFFFFFFF0EC796; (p08) nop; (p48) nop }

l40000000000EBFA0:
	{ ld4	r15,[r33]; nop.m	0x0; or	r37,r16,r37; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p07) br.cond.dptk.few	40000000000EC230; }

l40000000000EBFC0:
	{ adds	r33,0x8,r14; cmp.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000EC540; }

l40000000000EBFD0:
	{ ld8	r14,[r33]; ld8	r43,[r14]; nop.i	0x0; }
	{ ld1	r14,[r43]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2D,r14; (p07) br.cond.dpnt.few	40000000000EC380 }

l40000000000EC000:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,absolute_pathname; }
	{ adds	r1,0x0,r42; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	40000000000EC190; }

l40000000000EC020:
	{ addl	r14,7344,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000EC190 }

l40000000000EC050:
	{ nop.m	0x0; addl	r43,1284,r1; nop.i	0x0; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,get_string_value; }
	{ adds	r1,0x0,r42; nop.m	0x0; cmp.eq	p06,p07,0x0,r8 }
	{ adds	r38,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000EC190; }

l40000000000EC090:
	{ ld8	r14,[r33]; ld8	r35,[r14]; adds	r14,0x10,r12 }
	{ nop.m	0x0; st4	[r0],r14; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000EC0C0:
	{ adds	r43,0x0,r38; adds	r44,0x10,r12; br.call.sptk.many	b0,extract_colon_unit; }
	{ adds	r33,0x0,r8; cmp.eq	p07,p06,0x0,r8; adds	r1,0x0,r42 }
	{ addl	r45,1,r0; adds	r44,0x0,r35; (p07) br.cond.dpnt.few	40000000000EC1B0; }

l40000000000EC0F0:
	{ ld1	r14,[r33]; adds	r43,0x0,r33; sxt1	r14,r14; }
	{ adds	r39,0x0,r14; nop.i	0x0; br.call.sptk.many	b0,sh_makepath; }
	{ adds	r1,0x0,r42; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r43,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r42; nop.m	0x0; adds	r43,0x0,r36 }
	{ adds	r44,0x0,r34; nop.m	0x0; br.call.sptk.many	b0,fn40000000000EB300; }
	{ cmp4.eq	p06,p07,0x0,r8; nop.m	0x0; adds	r1,0x0,r42 }
	{ adds	r43,0x0,r36; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000EC5C0; }

l40000000000EC170:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	40000000000EC0C0 }

l40000000000EC190:
	{ nop.m	0x0; ld8	r14,[r33]; nop.i	0x0; }
	{ ld8	r35,[r14]; nop.m	0x0; nop.i	0x0; }

l40000000000EC1B0:
	{ adds	r43,0x0,r35; adds	r44,0x0,r34; br.call.sptk.many	b0,fn40000000000EB300; }
	{ adds	r1,0x0,r42; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	40000000000EC250; }

l40000000000EC1D0:
	{ nop.m	0x0; tbit.z	p06,p07,r37,0x2; adds	r43,0x0,r34 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000EC460; }

l40000000000EC1F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000EBA40; }
	{ adds	r1,0x0,r42; nop.m	0x0; nop.i	0x0 }

l40000000000EC210:
	{ nop.m	0x0; mov.i	ar.pfs,r41; mov.spnt	b0,r40,40000000000EC210 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000EC230:
	{ cmp4.eq	p07,p06,0x0,r34; (p07) addl	r15,8372,r1; nop.i	0x0; }

l40000000000EC23C:
	{ Invalid; Invalid; break.i	0x1000 }

l40000000000EC246:
	{ break.m	0x4000; nop; break.i	0x80000 }

l40000000000EC250:
	{ nop.m	0x0; tbit.z	p06,p07,r37,0x0; (p07) br.cond.dpnt.few	40000000000EC4B0; }

l40000000000EC260:
	{ nop.m	0x0; tbit.z	p06,p07,r37,0x1; (p06) br.cond.dptk.few	40000000000EC2F0 }

l40000000000EC270:
	{ adds	r43,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,dirspell; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r42; adds	r33,0x0,r8 }
	{ adds	r43,0x0,r8; adds	r44,0x0,r34; (p06) br.cond.dpnt.few	40000000000EC2F0; }

l40000000000EC2A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000EB300; }
	{ cmp4.eq	p06,p07,0x0,r8; nop.m	0x0; adds	r1,0x0,r42 }
	{ adds	r43,0x0,r33; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000EC470; }

l40000000000EC2D0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r42; nop.m	0x0; nop.i	0x0 }

l40000000000EC2F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ nop.m	0x0; adds	r1,0x0,r42; nop.i	0x0 }
	{ ld4	r43,[r8]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B4A0; }
	{ adds	r1,0x0,r42; adds	r45,0x0,r8; adds	r44,0x0,r35; }
	{ nop.m	0x0; addl	r43,1292,r1; nop.i	0x0; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,builtin_error; }
	{ addl	r8,1,r0; adds	r1,0x0,r42; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.spnt	b0,r40,40000000000EC360; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l40000000000EC380:
	{ adds	r14,0x1,r43; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000EC000 }

l40000000000EC3B0:
	{ nop.m	0x0; addl	r43,1236,r1; nop.i	0x0; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,get_string_value; }
	{ cmp.eq	p07,p06,0x0,r8; adds	r1,0x0,r42; adds	r35,0x0,r8; }
	{ nop.m	0x0; (p06) addl	r37,4,r0; (p06) br.cond.dptk.few	40000000000EC1B0 }

l40000000000EC3EC:
	{ (p46) nop; add	r0,r32,r0; (p05) nop }

l40000000000EC3F0:
	{ nop.m	0x0; addl	r44,1276,r1; nop.i	0x0; }
	{ ld8	r44,[r44]; nop.m	0x0; nop.i	0x0 }

l40000000000EC410:
	{ addl	r45,5,r0; adds	r43,0x0,r0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r42; adds	r43,0x0,r8; br.call.sptk.many	b0,builtin_error; }
	{ addl	r8,1,r0; adds	r1,0x0,r42; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.spnt	b0,r40,40000000000EC440; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l40000000000EC460:
	{ adds	r43,0x0,r35; nop.m	0x0; nop.i	0x0; }

l40000000000EC470:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B380; }
	{ adds	r1,0x0,r42; nop.m	0x0; nop.i	0x0 }
