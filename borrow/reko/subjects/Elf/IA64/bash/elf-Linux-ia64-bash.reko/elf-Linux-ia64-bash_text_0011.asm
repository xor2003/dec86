;;; Segment .text (400000000001C480)

l400000000012C480:
	{ nop.m	0x0; (p06) sub	r40,r40,r14; br.cloop.sptk.few	400000000012C440; }

l400000000012C48C:
	{ (p62) nop; cmp.lt	p00,p00,r32,r0; czx1.r	r0,r65 }

l400000000012C490:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r40; nop.i	0x0; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	400000000012C4D0; }

l400000000012C4A6:
	{ chk.a.nc	r0,3FFFFFFFFF12CCA6; nop; break.i	0x80000 }

l400000000012C4B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000137910; }
	{ adds	r1,0x0,r37; nop.m	0x0; nop.i	0x0 }

l400000000012C4D0:
	{ nop.m	0x0; mov.i	ar.pfs,r36; mov.i	LC,r38; }
	{ nop.m	0x0; mov.spnt	b0,r35,400000000012C4E0; br.ret	b0; }
400000000012C4F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; timeval_to_secs: 400000000012C500
timeval_to_secs proc
	{ ld8	r14,[r32],8; movl	r15,0x1BDE82D7B634DB }
	{ addl	r18,1000,r0; st8	[r14],r33; adds	r19,0x1,r14 }
	{ nop.m	0x0; setf.sig	f7,r15; nop.i	0x0; }
	{ ld8	r14,[r32]; setf.sig	f6,r14; extr.u	r16,r14,63,1; }
	{ nop.m	0x0; nop.m	0x0; xma.h	f6,f6,f7,f0; }
	{ getf.sig	r15,f6; nop.m	0x0; extr.u	r15,r15,18,46; }
	{ sub	r15,r15,r16; nop.m	0x0; dep.z	r16,0xF,5,59; }
	{ sub	r16,r16,r15; nop.m	0x0; dep.z	r17,r16,6,58; }
	{ sub	r16,r17,r16; shladd	r15,r16,0x3,r15; nop.i	0x0; }
	{ nop.m	0x0; dep.z	r15,0xF,6,58; nop.i	0x0; }
	{ sub	r15,r14,r15; movl	r14,0x49BA5E353F7CF; }
	{ nop.m	0x0; sxt4	r15,r15; nop.i	0x0 }
	{ setf.sig	f7,r14; setf.sig	f6,r15; extr.u	r16,r15,63,1; }
	{ nop.m	0x0; nop.m	0x0; xma.h	f6,f6,f7,f0; }
	{ getf.sig	r14,f6; nop.m	0x0; extr	r14,r14,7,57; }
	{ sub	r14,r14,r16; nop.i	0x0; dep.z	r17,r14,5,59 }
	{ adds	r16,0x1,r14; sub	r17,r17,r14; cmp4.eq	p07,p06,r18,r16; }
	{ shladd	r17,r17,0x2,r14; shladd	r17,r17,0x3,r0; nop.i	0x0; }
	{ sub	r15,r15,r17; addl	r17,499,r0; cmp4.lt	p08,p09,r17,r15; }
	{ (p09) st4	[r14],r34; nop.i	0x0; (p09) br.ret	b0 }

l400000000012C636:
	{ nop; (p34) nop; cmp.eq.or	p00,p36,r68,r8 }

l400000000012C640:
	{ st4	[r16],r34; (p07) st8	[r19],r33; nop.i	0x0; }

l400000000012C64C:
	{ Invalid; Invalid; add	r0,r32,r0 }

l400000000012C656:
	{ break.m	0x4000; (p34) nop; break.i	0x80000 }
400000000012C660 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012C670 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; print_timeval: 400000000012C680
;;   Called from:
;;     400000000010DA8C (in times_builtin)
;;     400000000010DACC (in times_builtin)
;;     400000000010DB0C (in times_builtin)
;;     400000000010DB4C (in times_builtin)
print_timeval proc
	{ alloc	r35,ar.pfs,0xB,0x0,0x5; ld8	r14,[r33],8; mov	r34,b2 }
	{ addl	r39,-4668,r1; adds	r36,0x0,r1; adds	r37,0x0,r32; }
	{ ld8	r15,[r33]; movl	r16,0x1BDE82D7B634DB }
	{ addl	r38,1,r0; ld8	r39,[r39]; nop.i	0x0; }
	{ setf.sig	f7,r16; setf.sig	f6,r15; extr.u	r17,r15,63,1; }
	{ nop.m	0x0; nop.m	0x0; xma.h	f6,f6,f7,f0; }
	{ getf.sig	r16,f6; nop.m	0x0; extr.u	r16,r16,18,46; }
	{ sub	r16,r16,r17; nop.m	0x0; dep.z	r17,r16,5,59; }
	{ sub	r17,r17,r16; nop.m	0x0; dep.z	r18,0x11,6,58; }
	{ sub	r17,r18,r17; shladd	r16,r17,0x3,r16; nop.i	0x0; }
	{ nop.m	0x0; dep.z	r16,r16,6,58; nop.i	0x0; }
	{ sub	r16,r15,r16; movl	r15,0x49BA5E353F7CF; }
	{ nop.m	0x0; sxt4	r16,r16; nop.i	0x0 }
	{ setf.sig	f7,r15; setf.sig	f6,r16; extr.u	r17,r16,63,1; }
	{ nop.m	0x0; nop.m	0x0; xma.h	f6,f6,f7,f0; }
	{ nop.m	0x0; getf.sig	r15,f6; nop.i	0x0; }
	{ nop.m	0x0; extr	r15,r15,7,57; sub	r15,r15,r17; }
	{ nop.m	0x0; dep.z	r17,0xF,5,59; adds	r42,0x0,r15; }
	{ sub	r17,r17,r15; shladd	r15,r17,0x2,r15; addl	r17,499,r0; }
	{ shladd	r15,r15,0x3,r0; sub	r16,r16,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r17,r16; (p06) br.cond.dptk.few	400000000012C7F0 }

l400000000012C7D0:
	{ adds	r42,0x1,r42; addl	r15,1000,r0; cmp4.eq	p07,p06,r15,r42; }
	{ nop.m	0x0; (p07) adds	r14,0x1,r14; (p07) adds	r42,0x0,r0; }

l400000000012C7EC:
	{ sum	0x108000; (p17) nop; }

l400000000012C7F0:
	{ nop.m	0x0; movl	r15,0x8008888888888889 }
	{ setf.sig	f6,r14; nop.m	0x0; extr.u	r16,r14,63,1; }
	{ nop.m	0x0; setf.sig	f7,r15; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; xma.h	f6,f6,f7,f0; }
	{ getf.sig	r15,f6; add	r15,r15,r14; nop.i	0x0; }
	{ nop.m	0x0; extr	r15,r15,5,59; sub	r15,r15,r16; }
	{ shladd	r41,r15,0x4,r0; adds	r40,0x0,r15; sub	r15,r41,r15; }
	{ nop.m	0x0; shladd	r41,r15,0x2,r0; nop.i	0x0; }
	{ sub	r41,r14,r41; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ adds	r1,0x0,r36; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,400000000012C890; br.ret	b0; }
400000000012C8A0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
400000000012C8B0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; sh_makepath: 400000000012C8C0
;;   Called from:
;;     4000000000040D5C (in make_absolute)
;;     4000000000041F4C (in full_pathname)
;;     40000000000CDF2C (in command_word_completion_function)
;;     40000000000DC6EC (in fn40000000000DC640)
;;     40000000000EC10C (in cd_builtin)
;;     400000000010ECCC (in describe_command)
;;     400000000010EDEC (in describe_command)
;;     400000000010EDEC (in describe_command)
;;     400000000011FD6C (in glob_vector)
;;     400000000012E00C (in sh_realpath)
sh_makepath proc
	{ alloc	r38,ar.pfs,0xA,0x0,0x8; mov	r37,b5; nop.i	0x0 }
	{ adds	r39,0x0,r1; cmp.eq	p06,p07,0x0,r32; (p06) br.cond.dpnt.few	400000000012CB40; }

l400000000012C8E0:
	{ ld1	r14,[r32]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	400000000012CB40; }

l400000000012C900:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x3; (p06) br.cond.dptk.few	400000000012C920; }

l400000000012C910:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r14; (p07) br.cond.dpnt.few	400000000012CCB0; }

l400000000012C920:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x0; (p06) br.cond.dptk.few	400000000012C940; }

l400000000012C930:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x7E,r14; (p07) br.cond.dpnt.few	400000000012CD40 }

l400000000012C940:
	{ adds	r35,0x0,r32; nop.m	0x0; nop.i	0x0; }

l400000000012C950:
	{ adds	r40,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; adds	r1,0x0,r39; adds	r36,0x0,r8 }

l400000000012C970:
	{ adds	r40,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r39; tbit.z	p06,p07,r34,0x2; (p06) br.cond.dptk.few	400000000012C9B0 }

l400000000012C990:
	{ ld1	r14,[r33]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r14; (p07) br.cond.dpnt.few	400000000012CC80 }

l400000000012C9B0:
	{ adds	r14,0x2,r8; add	r40,r14,r36; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r40,r40; br.call.sptk.many	b0,xmalloc; }
	{ nop.m	0x0; ld1	r15,[r35]; adds	r17,0x0,r8 }
	{ adds	r16,0x1,r35; adds	r1,0x0,r39; adds	r36,0x0,r8; }
	{ nop.m	0x0; sxt1	r15,r15; cmp4.eq	p06,p07,0x0,r15; }
	{ nop.m	0x0; (p06) adds	r14,0x0,r8; (p06) br.cond.dpnt.few	400000000012CAA0; }

l400000000012CA0C:
	{ (p05) nop; break.i	0x1000; break.i	0x1000 }

l400000000012CA10:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000012CA20:
	{ adds	r14,0x0,r17; nop.m	0x0; adds	r18,0x0,r16; }
	{ st1	[r14],r1,1; ld1	r15,[r16],1; adds	r17,0x0,r14; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	400000000012CA20; }

l400000000012CA60:
	{ adds	r15,0xFFFFFFFFFFFFFFFF,r18; cmp.ltu	p07,p06,r35,r18; (p06) br.cond.dpnt.few	400000000012CAA0; }

l400000000012CA70:
	{ ld1	r15,[r15]; nop.m	0x0; sxt1	r15,r15; }
	{ cmp4.eq	p06,p07,0x2F,r15; nop.i	0x0; (p07) addl	r15,47,r0; }

l400000000012CA90:
	{ (p07) st1	[r14],r1,1; nop.m	0x0; nop.i	0x0; }

l400000000012CA96:
	{ break.m	0x4000; nop; (p48) nop }

l400000000012CAA0:
	{ ld1	r15,[r33],1; nop.m	0x0; sxt1	r15,r15; }

l400000000012CAA2:
	{ (p16) break.m	0x28008; (p48) nop }

l400000000012CAA6:
	{ add	r0,r0,r1; (p07) nop; (p16) nop }

l400000000012CAA8:
	{ (p16) cmp.eq	p00,p01,r0,r112; (p01) pshr4	r5,r4,r32; czx1.r	r0,r2 }

l400000000012CAB2:
	{ Invalid; (p48) fselect	f67,f92,f1,f97; brp.dpnt	400000000012D2A2 }
	{ (p29) break.m	0x4FEDF; chk.s.i	r0,400000000092CCC2; (p52) br.cond.sptk.many	40000000002CAAD2 }
	{ (p48) break.m	0x42008; nop; Invalid; }
	{ Invalid; (p32) break.i	0x20303; nop }
	{ (p49) break.m	0x700E8; nop; clrrrb }
	{ break.m	0x20; cmp.ltu	p32,p00,r0,r0; Invalid }
	{ (p48) break.m	0x42009; break.i	0x20; dep	r32,r0,r32,63,3 }
	{ break.m	0x42009; cmp.lt	p32,p00,r0,r0; Invalid }
	{ nop; (p20) nop; Invalid }

l400000000012CB40:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x1; (p06) br.cond.dptk.few	400000000012CC40 }

l400000000012CB50:
	{ nop.m	0x0; addl	r40,-1164,r1; nop.i	0x0; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,get_working_directory; }
	{ nop.m	0x0; adds	r1,0x0,r39; adds	r35,0x0,r8 }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	400000000012C950; }

l400000000012CB90:
	{ nop.m	0x0; addl	r40,-1156,r1; nop.i	0x0; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,get_string_value; }
	{ cmp.eq	p07,p06,0x0,r8; adds	r1,0x0,r39; nop.i	0x0 }
	{ adds	r35,0x0,r8; adds	r40,0x0,r8; (p07) br.cond.dpnt.few	400000000012CC40; }

l400000000012CBD0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r39; adds	r40,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r41,0x0,r35 }
	{ adds	r40,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; adds	r1,0x0,r39; adds	r35,0x0,r8 }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; (p07) br.cond.spnt.few	400000000012C950; }

l400000000012CC30:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000012CC40:
	{ addl	r40,2,r0; addl	r36,1,r0; br.call.sptk.many	b0,xmalloc; }
	{ addl	r15,46,r0; adds	r14,0x0,r8; adds	r1,0x0,r39 }
	{ adds	r35,0x0,r8; st1	[r14],r1,1; nop.i	0x0; }
	{ st1	[r0],r14; nop.i	0x0; br.cond.sptk.few	400000000012C970 }

l400000000012CC80:
	{ adds	r14,0x1,r33; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x2F,r14; }
	{ (p07) adds	r33,0x2,r33; (p07) adds	r8,0xFFFFFFFFFFFFFFFE,r8; br.cond.sptk.few	400000000012C9B0 }

l400000000012CCA6:
	{ Invalid; nop; (p32) nop; }

l400000000012CCAC:
	{ (p40) cmp.lt.unc	p63,p11,r63,r36; (p17) cmp.lt	p00,p16,r8,r64; (p01) rfi }

l400000000012CCB0:
	{ adds	r14,0x1,r32; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000012CD20; }

l400000000012CCE0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2F,r14; (p06) br.cond.dptk.few	400000000012C940 }

l400000000012CCF0:
	{ adds	r14,0x2,r32; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	400000000012C940 }

l400000000012CD20:
	{ addl	r35,-1172,r1; nop.m	0x0; adds	r36,0x0,r0; }
	{ ld8	r35,[r35]; nop.i	0x0; br.cond.sptk.few	400000000012C970 }

l400000000012CD40:
	{ adds	r40,0x0,r32; adds	r41,0x0,r0; br.call.sptk.many	b0,bash_tilde_expand; }
	{ adds	r35,0x0,r8; nop.m	0x0; adds	r1,0x0,r39; }
	{ adds	r40,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r39; adds	r36,0x0,r8; br.cond.sptk.few	400000000012C970; }

;; fn400000000012CD80: 400000000012CD80
;;   Called from:
;;     400000000012D24C (in sh_canonpath)
;;     400000000012D45C (in sh_canonpath)
fn400000000012CD80 proc
	{ alloc	r34,ar.pfs,0x7,0x0,0x4; adds	r12,0xFFFFFFFFFFFFFF70,r12; mov	r33,b1 }
	{ nop.m	0x0; adds	r35,0x0,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ adds	r1,0x0,r35; addl	r36,1,r0; adds	r37,0x0,r32 }
	{ adds	r38,0x10,r12; st4	[r0],r8; br.call.sptk.many	b0,fn400000000001AFE0; }
	{ nop.m	0x0; adds	r1,0x0,r35; adds	r14,0x0,r0 }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	400000000012CE20; }

l400000000012CDF0:
	{ adds	r14,0x28,r12; ld4	r15,[r14]; addl	r14,61440,r0; }
	{ and	r14,r14,r15; addl	r15,16384,r0; cmp4.eq	p06,p07,r15,r14; }
	{ (p06) addl	r14,1,r0; nop.i	0x0; (p07) adds	r14,0x0,r0; }

l400000000012CE16:
	{ chk.a.nc	f0,3FFFFFFFFF12D616; Invalid; nop }

l400000000012CE20:
	{ adds	r8,0x0,r14; mov.i	ar.pfs,r34; mov.spnt	b0,r33,400000000012CE20 }
	{ nop.m	0x0; adds	r12,0x90,r12; br.ret	b0; }

;; sh_canonpath: 400000000012CE40
;;   Called from:
;;     400000000006DFBC (in initialize_shell_variables)
;;     40000000000EB38C (in fn40000000000EB300)
;;     40000000000EB70C (in fn40000000000EB300)
sh_canonpath proc
	{ alloc	r46,ar.pfs,0x14,0x0,0x12; and	r40,0x8,r33; mov	r48,pr }
	{ adds	r47,0x0,r1; nop.m	0x0; adds	r38,0x0,r32; }
	{ cmp4.eq	p19,p18,0x0,r40; nop.m	0x0; mov	r45,b5 }
	{ adds	r42,0x0,r0; nop.m	0x0; addl	r43,46,r0; }
	{ (p19) adds	r50,0x0,r32; mov	r49,LC; (p19) br.call.dpnt.many	b0,fn400000000001B6C0; }

l400000000012CE86:
	{ (p24) nop; (p32) cmp4.eq	p04,p45,r93,r123; Invalid }

l400000000012CE90:
	{ (p19) adds	r1,0x0,r47; (p19) adds	r50,0x1,r8; (p19) br.call.dpnt.many	b0,xmalloc; }

l400000000012CE96:
	{ (p25) nop; (p20) nop }

l400000000012CE9C:
	{ (p49) nop; invala; br.cond.spnt.few	3FFFFFFFFF92D09C }

l400000000012CEA0:
	{ (p19) adds	r1,0x0,r47; nop.m	0x0; (p19) adds	r50,0x0,r8 }

l400000000012CEA6:
	{ nop; (p25) nop; (p52) nop }

l400000000012CEB0:
	{ (p19) adds	r51,0x0,r32; nop.m	0x0; (p19) br.call.dpnt.many	b0,fn400000000001B180; }

l400000000012CEB6:
	{ nop; (p32) nop; (p32) nop }

l400000000012CEC0:
	{ ld1	r14,[r32]; nop.m	0x0; (p19) adds	r38,0x0,r8 }

l400000000012CED0:
	{ adds	r16,0x1,r32; (p19) adds	r1,0x0,r47; sxt1	r14,r14 }

l400000000012CEDC:
	{ cmp.eq	p14,p03,r20,r0; (p17) shladd	r64,r9,0x1,r64; (p04) cmp.lt.unc	p00,p16,r9,r64; }
	{ (p23) cmp4.eq.and	p14,p11,r7,r115; (p17) cmp4.eq.and	p00,p50,r0,r0; (p01) epc }

l400000000012CEF6:
	{ Invalid; nop; break.i	0x80000; }

l400000000012CEFC:
	{ invala; cmp.lt	p00,p00,r32,r0; mov	pr,r99,0xE680 }
	{ (p02) nop; (p02) addp4	r0,r4,r0; (p04) nop }

l400000000012CF10:
	{ ld1	r16,[r16]; adds	r36,0x0,r0; addl	r43,47,r0; }
	{ nop.m	0x0; sxt1	r16,r16; add	r36,r15,r36; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2F,r16; (p07) br.cond.dpnt.few	400000000012D3F0 }

l400000000012CF40:
	{ ld1	r15,[r36]; cmp4.eq	p23,p22,0x0,r14; adds	r41,0x0,r36 }
	{ adds	r34,0x0,r36; adds	r35,0x0,r36; addl	r37,47,r0; }
	{ nop.m	0x0; tnat.z	p17,p16,r33; sxt1	r15,r15 }
	{ nop.m	0x0; addl	r44,46,r0; nop.b	0x0; }
	{ nop.m	0x0; tnat.z	p20,p21,r33; adds	r14,0x0,r15; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000012CFA0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	400000000012D0D0; }

l400000000012CFB0:
	{ cmp4.eq	p07,p06,0x2F,r14; (p07) adds	r35,0x1,r35; nop.i	0x0; }

l400000000012CFBC:
	{ nop; cmp4.eq.and	p00,p32,r32,r0; Invalid }

l400000000012CFCC:
	{ Invalid; cmp4.eq.and	p00,p32,r32,r0; (p01) mov	pr,r3,0x80 }
	{ Invalid; cmp.eq	p00,p00,r32,r0; (p32) nop }

l400000000012CFE0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r14; (p07) br.cond.dpnt.few	400000000012D140; }

l400000000012CFF0:
	{ cmp.eq	p06,p07,r36,r34; nop.i	0x0; (p06) br.cond.dpnt.few	400000000012D040; }

l400000000012D000:
	{ ld1.a	r14,[r35]; st1	[r34],r1,1; nop.i	0x0; }
	{ nop.m	0x0; ld1.c.clr	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x0,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x2F,r14; (p07) br.cond.dpnt.few	400000000012D0A0 }

l400000000012D040:
	{ nop.m	0x0; adds	r16,0x0,r34; adds	r15,0x1,r35; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000012D060:
	{ st1	[r16],r1,1; nop.m	0x0; adds	r35,0x0,r15; }
	{ ld1	r14,[r15],1; nop.m	0x0; adds	r34,0x0,r16; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x0,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x2F,r14; (p06) br.cond.dptk.few	400000000012D060 }

l400000000012D0A0:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dpnt.few	400000000012D220; }

l400000000012D0B0:
	{ ld1	r14,[r35]; nop.i	0x0; sxt1	r14,r14; }

l400000000012D0C0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	400000000012CFB0; }

l400000000012D0D0:
	{ cmp.eq	p07,p06,r38,r34; ld1.a	r14,[r38]; nop.i	0x0; }
	{ (p07) st1	[r34],r1,1; st1	[r0],r34; nop.i	0x0; }

l400000000012D0E6:
	{ mf.a; nop; (p32) nop }
	{ break.m	0x4000; (p07) nop; break.i	0x80000 }
	{ (p03) chk.a.clr	f47,3FFFFFFFFFDF01E6; nop; nop.b	0x26002 }

l400000000012D110:
	{ adds	r8,0x0,r38; nop.m	0x0; mov	pr,r48,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r46; mov.i	LC,r49; }
	{ nop.m	0x0; mov.spnt	b0,r45,400000000012D130; br.ret	b0 }

l400000000012D140:
	{ adds	r17,0x1,r35; ld1	r16,[r17]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r16,r16; cmp4.eq	p06,p07,0x2F,r16; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x0,r16; nop.i	0x0; }
	{ (p06) adds	r35,0x0,r17; (p06) adds	r14,0x0,r16; (p06) br.cond.dptk.few	400000000012CFA0 }

l400000000012D176:
	{ (p07) chk.a.clr	r0,3FFFFFFFFF1AD276; nop; break.i	0x80000; }

l400000000012D17C:
	{ Invalid; cmp.eq	p00,p00,r32,r0; (p32) nop }

l400000000012D180:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r16; (p06) br.cond.dptk.few	400000000012CFF0; }

l400000000012D190:
	{ adds	r39,0x2,r35; ld1	r15,[r39]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; cmp4.eq	p06,p07,0x2F,r15; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x0,r15; (p07) br.cond.dptk.few	400000000012CFF0; }

l400000000012D1C0:
	{ nop.m	0x0; cmp.ltu	p07,p06,r41,r34; (p06) br.cond.dptk.few	400000000012D290 }

l400000000012D1D0:
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r34; nop.i	0x0; (p21) br.cond.dpnt.few	400000000012D440; }

l400000000012D1E0:
	{ sub	r15,r14,r41; nop.i	0x0; mov.i	LC,r15; }

l400000000012D1F0:
	{ nop.m	0x0; adds	r34,0x0,r14; br.cloop.sptk.few	400000000012D2F0 }

l400000000012D200:
	{ ld1	r14,[r39]; nop.m	0x0; adds	r35,0x0,r39; }
	{ nop.m	0x0; sxt1	r14,r14; br.cond.sptk.few	400000000012CFA0; }

l400000000012D220:
	{ nop.m	0x0; ld1	r14,[r34]; adds	r50,0x0,r38 }
	{ st1	[r0],r34; nop.m	0x0; sxt1	r14,r14; }
	{ adds	r39,0x0,r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000012CD80; }
	{ adds	r1,0x0,r47; cmp4.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	400000000012D4A0; }

l400000000012D260:
	{ ld1.a	r14,[r35]; st1	[r39],r34; nop.i	0x0; }
	{ nop.m	0x0; ld1.c.clr	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; br.cond.sptk.few	400000000012D0C0; }

l400000000012D290:
	{ (p22) adds	r14,0x0,r15; (p22) adds	r35,0x0,r39; (p22) br.cond.dptk.few	400000000012CFA0; }

l400000000012D296:
	{ Invalid; Invalid; Invalid }

l400000000012D29C:
	{ (p40) cmp.lt.unc	p63,p09,r63,r37; czx1.r	r73,r1; nop }

l400000000012D2A0:
	{ cmp.eq	p06,p07,r36,r34; nop.m	0x0; adds	r35,0x0,r39; }
	{ (p07) st1	[r34],r1,1; adds	r14,0x0,r34; adds	r34,0x2,r34; }

l400000000012D2B6:
	{ Invalid; (p17) nop; (p16) nop }
	{ add	r0,r0,r1; (p20) nop; nop }
	{ (p07) fwb; nop; break.i	0x80000 }
	{ (p07) break.m	0x50700; Invalid; (p48) nop }

l400000000012D2F0:
	{ ld1	r15,[r14]; adds	r14,0xFFFFFFFFFFFFFFFF,r14; sxt1	r15,r15; }
	{ cmp4.eq	p07,p06,0x2F,r15; nop.i	0x0; (p07) br.cond.dpnt.few	400000000012D200; }

l400000000012D310:
	{ nop.m	0x0; adds	r34,0x0,r14; br.cloop.sptk.few	400000000012D2F0 }

l400000000012D320:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000012D200 }

l400000000012D330:
	{ adds	r51,0x1,r38; ld1	r14,[r51]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2F,r14; (p06) br.cond.dptk.few	400000000012D110 }

l400000000012D360:
	{ adds	r14,0x2,r38; nop.m	0x0; cmp4.eq	p09,p08,0x0,r42; }
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x2F,r14; (p06) br.cond.dpnt.few	400000000012D110; (p08) br.cond.dptk.few	400000000012D110; }

l400000000012D38C:
	{ (p44) nop; cmp.eq	p00,p00,r32,r0; nop }

l400000000012D390:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; }
	{ (p07) st1	[r0],r51; nop.i	0x0; (p07) br.cond.dptk.few	400000000012D110 }

l400000000012D3A6:
	{ chk.a.nc	f0,3FFFFFFFFF12DBA6; nop; (p32) nop }

l400000000012D3B0:
	{ adds	r50,0x0,r38; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r8,0x0,r38; adds	r1,0x0,r47; mov	pr,r48,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r46; mov.i	LC,r49; }
	{ nop.m	0x0; mov.spnt	b0,r45,400000000012D3E0; br.ret	b0 }

l400000000012D3F0:
	{ adds	r32,0x2,r32; nop.m	0x0; addl	r43,47,r0; }
	{ ld1	r36,[r32]; nop.m	0x0; sxt1	r36,r36; }
	{ cmp4.eq	p06,p07,0x2F,r36; (p06) adds	r36,0x0,r0; (p06) adds	r42,0x0,r0; }

l400000000012D41C:
	{ nop; nop; }

l400000000012D420:
	{ (p07) addl	r36,1,r0; nop.m	0x0; (p07) addl	r42,1,r0; }

l400000000012D426:
	{ chk.a.nc	f0,3FFFFFFFFF12DC26; (p21) nop; break.i	0x80000 }

l400000000012D430:
	{ nop.m	0x0; add	r36,r15,r36; br.cond.sptk.few	400000000012CF40 }

l400000000012D440:
	{ ld1	r35,[r34]; nop.m	0x0; adds	r50,0x0,r38 }
	{ st1	[r0],r34; nop.m	0x0; br.call.sptk.many	b0,fn400000000012CD80; }
	{ nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFFFF,r34; sxt1	r35,r35 }
	{ adds	r1,0x0,r47; cmp4.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	400000000012D4E0; }

l400000000012D480:
	{ sub	r15,r14,r41; st1	[r35],r34; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r15; br.cond.sptk.few	400000000012D1F0 }

l400000000012D4A0:
	{ nop.m	0x0; nop.i	0x0; (p19) br.cond.dpnt.few	400000000012D4F0 }

l400000000012D4B0:
	{ adds	r38,0x0,r0; nop.m	0x0; mov	pr,r48,0xFFFFFFFFFFFFFFFE; }
	{ adds	r8,0x0,r38; mov.i	ar.pfs,r46; mov.i	LC,r49; }
	{ nop.m	0x0; mov.spnt	b0,r45,400000000012D4D0; br.ret	b0 }

l400000000012D4E0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r40; (p07) br.cond.dptk.few	400000000012D4B0; }

l400000000012D4F0:
	{ adds	r50,0x0,r38; adds	r38,0x0,r0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r8,0x0,r38; adds	r1,0x0,r47; mov	pr,r48,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r46; mov.i	LC,r49; }
	{ nop.m	0x0; mov.spnt	b0,r45,400000000012D520; br.ret	b0; }
400000000012D530 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; sh_physpath: 400000000012D540
;;   Called from:
;;     40000000000EB37C (in fn40000000000EB300)
;;     40000000000EB6FC (in fn40000000000EB300)
;;     40000000000EBC2C (in fn40000000000EBA40)
;;     40000000000EC97C (in pwd_builtin)
;;     400000000012E04C (in sh_realpath)
sh_physpath proc
	{ alloc	r48,ar.pfs,0x16,0x0,0x13; addl	r17,-8208,r0; nop.i	0x0; }
	{ add	r12,r12,r17; adds	r49,0x0,r1; mov	r47,b7 }
	{ adds	r51,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r49; adds	r33,0x0,r8; nop.b	0x0 }
	{ addl	r51,4097,r0; mov	r50,LC; br.call.sptk.many	b0,xmalloc; }
	{ addl	r14,4095,r0; adds	r1,0x0,r49; adds	r35,0x0,r8; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r14,r33; (p06) br.cond.dptk.few	400000000012DBF0 }

l400000000012D5B0:
	{ adds	r51,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r49; adds	r51,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r49; nop.m	0x0; adds	r51,0x0,r8 }
	{ adds	r52,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r36,0x0,r8; nop.m	0x0; adds	r1,0x0,r49; }
	{ ld1	r14,[r36]; adds	r38,0x1,r36; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2F,r14; (p07) br.cond.dpnt.few	400000000012DC50 }

l400000000012D620:
	{ nop.m	0x0; adds	r17,0x0,r0; adds	r44,0x0,r0; }

l400000000012D630:
	{ add	r17,r38,r17; nop.m	0x0; adds	r16,0x0,r38; }
	{ sub	r18,r17,r36; cmp.ltu	p07,p06,r36,r17; (p06) br.cond.dpnt.few	400000000012DD80; }

l400000000012D650:
	{ add	r18,r35,r18; adds	r15,0x0,r35; sub	r18,r18,r35,0x1 }
	{ st1	[r15],r1,1; nop.m	0x0; mov.i	LC,r18; }
	{ nop.m	0x0; nop.i	0x0; br.cloop.sptk.few	400000000012D8C0; }

l400000000012D680:
	{ sub	r14,r17,r38; sub	r34,0x1,r38; adds	r42,0x0,r0 }
	{ addl	r39,4095,r0; addl	r40,47,r0; sub	r45,0x1,r38; }
	{ add	r17,r17,r34; add	r14,r36,r14,0x1; adds	r46,0x2,r36; }
	{ ld1	r14,[r14]; add	r37,r35,r17; add	r34,r36,r17; }
	{ nop.m	0x0; sxt1	r14,r14; adds	r41,0x0,r37; }

l400000000012D6D0:
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000012DDB0; }

l400000000012D6E0:
	{ cmp4.eq	p07,p06,0x2F,r14; (p07) adds	r34,0x1,r34; nop.i	0x0; }

l400000000012D6EC:
	{ nop; cmp4.eq.and	p00,p32,r32,r0; Invalid }

l400000000012D6FC:
	{ Invalid; cmp4.eq.and	p00,p32,r32,r0; (p01) mov	pr,r3,0x80 }
	{ Invalid; cmp.eq	p00,p00,r32,r0; (p32) nop }

l400000000012D710:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r14; (p07) br.cond.dpnt.few	400000000012D8F0; }

l400000000012D720:
	{ adds	r33,0x0,r37; cmp.eq	p06,p07,r41,r37; (p06) br.cond.dpnt.few	400000000012D790; }

l400000000012D730:
	{ ld1.a	r14,[r34]; st1	[r33],r1,1; nop.i	0x0; }
	{ ld1.c.clr	r14,[r34]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.m	0x0; cmp4.eq	p09,p08,0x2F,r14; }
	{ (p06) addl	r16,1,r0; nop.m	0x0; (p08) addl	r15,1,r0; }

l400000000012D766:
	{ addl	r0,0,r1; (p07) cmp4.eq.and	p01,p08,0x0,r0; (p01) nop }

l400000000012D770:
	{ (p07) adds	r16,0x0,r0; (p09) adds	r15,0x0,r0; and	r15,r15,r16; }

l400000000012D776:
	{ Invalid; (p07) nop.b	0x3080F; break.b	0x80000 }

l400000000012D77C:
	{ (p07) invala; cmp.lt	p00,p00,r32,r0; nop; }
	{ (p19) cmp.eq	p00,p08,r64,r33; (p01) nop; (p20) nop }

l400000000012D790:
	{ adds	r15,0x0,r33; sub	r33,r33,r35; addl	r19,4096,r0 }
	{ adds	r16,0x1,r34; sub	r18,r35,r15; cmp.lt	p07,p06,r39,r33 }
	{ adds	r17,0x1,r33; nop.m	0x0; (p07) br.cond.dpnt.few	400000000012D820; }

l400000000012D7C0:
	{ adds	r18,0xFFF,r18; cmp.lt	p06,p07,r19,r17; mov.i	LC,r18; }
	{ nop.m	0x0; (p07) mov.i	LC,r18; (p06) mov.i	LC,0x0; }

l400000000012D7DC:
	{ nop; Invalid; dep	r0,r32,r0,63,1 }

l400000000012D7E0:
	{ st1	[r15],r1,1; nop.m	0x0; adds	r34,0x0,r16; }
	{ ld1	r14,[r16],1; nop.m	0x0; adds	r33,0x0,r15; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x0,r14; }
	{ cmp4.eq.or.andcm	p07,p06,0x2F,r14; (p07) br.cond.dpnt.few	400000000012D9E0; br.cloop.sptk.few	400000000012D7E0 }

l400000000012D81C:
	{ Invalid; break.i	0x1000; break.b	0x1000 }

l400000000012D820:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ addl	r14,36,r0; nop.m	0x0; adds	r1,0x0,r49; }
	{ st4	[r14],r8; nop.m	0x0; nop.i	0x0 }

l400000000012D850:
	{ adds	r51,0x0,r35; adds	r35,0x0,r0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r49; adds	r51,0x0,r36 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r49; nop.m	0x0; nop.i	0x0 }

l400000000012D890:
	{ adds	r8,0x0,r35; mov.i	ar.pfs,r48; mov.i	LC,r50; }
	{ nop.m	0x0; mov.spnt	b0,r47,400000000012D8A0; addl	r19,8208,r0; }
	{ nop.m	0x0; add	r12,r12,r19; br.ret	b0 }

l400000000012D8C0:
	{ ld1	r14,[r16],1; nop.m	0x0; sxt1	r14,r14; }
	{ st1	[r15],r1,1; nop.i	0x0; br.cloop.sptk.few	400000000012D8C0 }

l400000000012D8E0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000012D680 }

l400000000012D8F0:
	{ adds	r17,0x1,r34; ld1	r16,[r17]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r16,r16; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x2F,r16; adds	r15,0x0,r16; cmp4.eq.or.andcm	p06,p07,0x0,r16; }
	{ (p06) adds	r34,0x0,r17; (p06) adds	r14,0x0,r16; (p06) br.cond.dptk.few	400000000012D6D0 }

l400000000012D926:
	{ (p07) chk.a.clr	r0,3FFFFFFFFF1ADA26; nop; break.i	0x80000; }

l400000000012D92C:
	{ Invalid; cmp.eq	p00,p00,r32,r0; (p32) nop }

l400000000012D930:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r16; (p06) br.cond.dptk.few	400000000012D720; }

l400000000012D940:
	{ adds	r16,0x2,r34; ld1	r17,[r16]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r17,r17; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x2F,r17; nop.m	0x0; adds	r15,0x0,r17; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x0,r17; (p07) br.cond.dptk.few	400000000012D720; }

l400000000012D980:
	{ cmp.ltu	p07,p06,r41,r37; nop.m	0x0; adds	r34,0x0,r16; }
	{ nop.m	0x0; (p06) adds	r14,0x0,r17; (p06) br.cond.dptk.few	400000000012D6D0; }

l400000000012D99C:
	{ (p42) cmp.lt.unc	p63,p11,r63,r37; zxt2	r63,r79; (p34) nop }

l400000000012D9A0:
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r37; sub	r16,r14,r41; adds	r37,0x0,r14; }
	{ nop.m	0x0; mov.i	LC,r16; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.cloop.sptk.few	400000000012DEC0 }

l400000000012D9D0:
	{ nop.m	0x0; adds	r14,0x0,r15; br.cond.sptk.few	400000000012D6D0 }

l400000000012D9E0:
	{ nop.m	0x0; adds	r52,0x10,r12; addl	r53,4096,r0 }
	{ st1	[r0],r33; adds	r51,0x0,r35; br.call.sptk.many	b0,fn400000000001B100; }
	{ adds	r1,0x0,r49; cmp4.lt	p07,p06,r8,r0; nop.i	0x0 }
	{ adds	r15,0x10,r12; adds	r51,0x0,r34; (p07) br.cond.dpnt.few	400000000012DCB0; }

l400000000012DA20:
	{ adds	r42,0x1,r42; nop.m	0x0; sxt4	r33,r8; }
	{ cmp4.lt	p07,p06,0x14,r42; add	r14,r15,r33; (p07) br.cond.dpnt.few	400000000012DF20; }

l400000000012DA40:
	{ st1	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r14,0x2,r33; adds	r1,0x0,r49; adds	r43,0x0,r8 }
	{ adds	r51,0x1011,r12; adds	r52,0x10,r12; addl	r53,4097,r0; }
	{ nop.m	0x0; add	r14,r14,r8; nop.i	0x0; }
	{ cmp.ltu	p07,p06,r39,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000012D820; }

l400000000012DA90:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BAE0; }
	{ adds	r17,0x1011,r12; nop.m	0x0; adds	r52,0x0,r34 }
	{ adds	r1,0x0,r49; adds	r53,0x1,r43; add	r51,r17,r33; }
	{ st1	[r40],r51; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ adds	r1,0x0,r49; nop.m	0x0; adds	r51,0x0,r36 }
	{ adds	r52,0x1011,r12; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r15,0x10,r12; nop.m	0x0; adds	r1,0x0,r49; }
	{ ld1	r14,[r15]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x2F,r14; ld1	r14,[r36]; nop.i	0x0; }
	{ (p07) adds	r34,0x0,r36; sxt1	r14,r14; (p07) br.cond.dptk.few	400000000012D6D0; }

l400000000012DB26:
	{ (p07) chk.a.nc	f0,3FFFFFFFFF137C06; mov	pr,0x4AFFFBB; break.i	0x80000; }

l400000000012DB30:
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2F,r14; (p07) br.cond.dpnt.few	400000000012DD30 }

l400000000012DB50:
	{ nop.m	0x0; adds	r17,0x0,r0; adds	r44,0x0,r0; }

l400000000012DB60:
	{ add	r17,r38,r17; nop.m	0x0; adds	r16,0x0,r38; }
	{ sub	r18,r17,r36; cmp.ltu	p07,p06,r36,r17; (p06) br.cond.dpnt.few	400000000012DF00; }

l400000000012DB80:
	{ add	r18,r35,r18; adds	r15,0x0,r35; sub	r18,r18,r35,0x1 }
	{ st1	[r15],r1,1; nop.m	0x0; mov.i	LC,r18; }
	{ nop.m	0x0; nop.i	0x0; br.cloop.sptk.few	400000000012DD00 }

l400000000012DBB0:
	{ sub	r14,r17,r38; nop.m	0x0; add	r17,r17,r45; }
	{ add	r14,r36,r14,0x1; add	r37,r35,r17; add	r34,r36,r17; }
	{ ld1	r14,[r14]; nop.m	0x0; adds	r41,0x0,r37; }
	{ nop.m	0x0; sxt1	r14,r14; br.cond.sptk.few	400000000012D6D0 }

l400000000012DBF0:
	{ addl	r51,4097,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r49; adds	r36,0x0,r8; nop.i	0x0 }
	{ adds	r51,0x0,r8; adds	r52,0x0,r32; br.call.sptk.many	b0,fn400000000001B180; }
	{ ld1	r14,[r36]; adds	r1,0x0,r49; adds	r38,0x1,r36; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2F,r14; (p06) br.cond.dptk.few	400000000012D620 }

l400000000012DC50:
	{ ld1	r15,[r38]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2F,r15; (p06) br.cond.dptk.few	400000000012D620 }

l400000000012DC70:
	{ adds	r15,0x2,r36; ld1	r17,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r17,r17; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x2F,r17; (p06) adds	r44,0x0,r0; (p06) adds	r17,0x0,r0; }

l400000000012DC9C:
	{ nop; (p21) nop; zxt4	r0,r0 }

l400000000012DCA0:
	{ (p07) addl	r44,1,r0; (p07) addl	r17,1,r0; br.cond.sptk.few	400000000012D630 }

l400000000012DCA6:
	{ Invalid; nop; (p16) nop.b	0x21009; }

l400000000012DCAC:
	{ (p12) nop; zxt1	r32,r64; break.b	0x1000 }

l400000000012DCB0:
	{ adds	r37,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ ld4	r14,[r8]; nop.m	0x0; adds	r1,0x0,r49; }
	{ cmp4.eq	p07,p06,0x16,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000012D850; }

l400000000012DCE0:
	{ nop.m	0x0; ld1	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; br.cond.sptk.few	400000000012D6D0; }

l400000000012DD00:
	{ ld1	r14,[r16],1; nop.m	0x0; sxt1	r14,r14; }
	{ st1	[r15],r1,1; nop.i	0x0; br.cloop.sptk.few	400000000012DD00 }

l400000000012DD20:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000012DBB0; }

l400000000012DD30:
	{ ld1	r15,[r38]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2F,r15; (p06) br.cond.dptk.few	400000000012DB50 }

l400000000012DD50:
	{ ld1	r17,[r46]; nop.m	0x0; sxt1	r17,r17; }
	{ cmp4.eq	p06,p07,0x2F,r17; (p06) adds	r44,0x0,r0; (p06) adds	r17,0x0,r0; }

l400000000012DD6C:
	{ nop; (p21) nop; zxt4	r0,r0 }

l400000000012DD70:
	{ (p07) addl	r44,1,r0; (p07) addl	r17,1,r0; br.cond.sptk.few	400000000012DB60 }

l400000000012DD76:
	{ Invalid; nop; (p16) nop.b	0x23009; }

l400000000012DD7C:
	{ (p47) nop; (p04) dep	r96,r8,r64,62,1; (p04) br.cond.sptk.few	400000000054DE0C }

l400000000012DD80:
	{ adds	r37,0x0,r35; adds	r34,0x0,r36; adds	r42,0x0,r0 }
	{ addl	r39,4095,r0; addl	r40,47,r0; sub	r45,0x1,r38; }
	{ adds	r41,0x0,r37; adds	r46,0x2,r36; br.cond.sptk.few	400000000012D6D0 }

l400000000012DDB0:
	{ nop.m	0x0; adds	r51,0x0,r36; nop.i	0x0 }
	{ st1	[r0],r37; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ ld1	r14,[r35]; adds	r1,0x0,r49; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2F,r14; (p06) br.cond.dptk.few	400000000012D890 }

l400000000012DDF0:
	{ adds	r52,0x1,r35; ld1	r14,[r52]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2F,r14; (p06) br.cond.dptk.few	400000000012D890 }

l400000000012DE20:
	{ adds	r14,0x2,r35; nop.m	0x0; cmp4.eq	p09,p08,0x0,r44; }
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x2F,r14; (p06) br.cond.dpnt.few	400000000012D890; (p08) br.cond.dptk.few	400000000012D890; }

l400000000012DE4C:
	{ (p18) nop; cmp.eq	p00,p00,r32,r0; nop }

l400000000012DE50:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; }
	{ (p07) st1	[r0],r52; nop.i	0x0; (p07) br.cond.dptk.few	400000000012D890 }

l400000000012DE66:
	{ chk.a.nc	f0,3FFFFFFFFF12E666; nop; (p48) nop }

l400000000012DE70:
	{ adds	r51,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r8,0x0,r35; adds	r1,0x0,r49; mov.i	ar.pfs,r48; }
	{ nop.m	0x0; mov.i	LC,r50; mov.spnt	b0,r47,400000000012DE90; }
	{ nop.m	0x0; addl	r19,8208,r0; nop.i	0x0; }
	{ nop.m	0x0; add	r12,r12,r19; br.ret	b0 }

l400000000012DEC0:
	{ ld1	r16,[r14]; adds	r14,0xFFFFFFFFFFFFFFFF,r14; sxt1	r16,r16; }
	{ cmp4.eq	p07,p06,0x2F,r16; nop.i	0x0; (p07) br.cond.dpnt.few	400000000012D9D0; }

l400000000012DEE0:
	{ nop.m	0x0; adds	r37,0x0,r14; br.cloop.sptk.few	400000000012DEC0 }

l400000000012DEF0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000012D9D0; }

l400000000012DF00:
	{ nop.m	0x0; adds	r41,0x0,r35; adds	r37,0x0,r35 }
	{ nop.m	0x0; adds	r34,0x0,r36; br.cond.sptk.few	400000000012D6D0 }

l400000000012DF20:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ addl	r14,40,r0; nop.m	0x0; adds	r1,0x0,r49 }
	{ adds	r51,0x0,r35; nop.m	0x0; adds	r35,0x0,r0; }
	{ st4	[r14],r8; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r49; adds	r51,0x0,r36; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r49; br.cond.sptk.few	400000000012D890; }

;; sh_realpath: 400000000012DF80
sh_realpath proc
	{ alloc	r37,ar.pfs,0xA,0x0,0x7; mov	r36,b4; adds	r38,0x0,r1 }
	{ cmp.eq	p06,p07,0x0,r32; addl	r39,-9004,r1; (p06) br.cond.dpnt.few	400000000012E1B0; }

l400000000012DFA0:
	{ ld1	r14,[r32]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000012E160; }

l400000000012DFC0:
	{ cmp4.eq	p06,p07,0x2F,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000012E110; }

l400000000012DFD0:
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,get_working_directory; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r38; adds	r34,0x0,r8 }
	{ adds	r40,0x0,r8; adds	r41,0x0,r0; (p06) br.cond.dpnt.few	400000000012E0F0; }

l400000000012E000:
	{ adds	r39,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,sh_makepath; }
	{ adds	r1,0x0,r38; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r39,0x0,r34; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r38; nop.m	0x0; nop.i	0x0 }

l400000000012E040:
	{ adds	r40,0x0,r0; adds	r39,0x0,r35; br.call.sptk.many	b0,sh_physpath; }
	{ adds	r1,0x0,r38; nop.m	0x0; adds	r34,0x0,r8 }
	{ adds	r39,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ cmp.eq	p06,p07,0x0,r33; adds	r1,0x0,r38; adds	r40,0x0,r34 }
	{ adds	r39,0x0,r33; addl	r41,4095,r0; (p06) br.cond.dpnt.few	400000000012E0F0; }

l400000000012E090:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r34; nop.i	0x0; }
	{ (p06) st1	[r0],r33; (p06) br.cond.dpnt.few	400000000012E0F0; br.call.sptk.many	b0,fn400000000001B920; }

l400000000012E0A6:
	{ Invalid; (p32) nop; (p32) nop; }

l400000000012E0AC:
	{ (p04) cmp.lt.unc	p27,p08,r59,r44; (p49) invala; nop }
	{ cmp.eq	p38,p02,r0,r66; (p04) dep	r64,r8,r64,62,1; zxt1	r32,r64 }
	{ nop; Invalid; break.i	0x1000 }
	{ (p56) nop; invala; break.b	0x1000 }
	{ nop; zxt1	r64,r64; break.i	0x1000 }

l400000000012E0F0:
	{ adds	r8,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,400000000012E100; br.ret	b0; }

l400000000012E110:
	{ adds	r39,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r38; adds	r39,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r38; nop.m	0x0; adds	r39,0x0,r8 }
	{ adds	r40,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r38; adds	r35,0x0,r8; br.cond.sptk.few	400000000012E040 }

l400000000012E160:
	{ adds	r34,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ addl	r14,2,r0; nop.m	0x0; adds	r1,0x0,r38; }
	{ st4	[r14],r8; nop.m	0x0; nop.i	0x0 }

l400000000012E190:
	{ adds	r8,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,400000000012E1A0; br.ret	b0; }

l400000000012E1B0:
	{ adds	r34,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ addl	r14,22,r0; nop.m	0x0; adds	r1,0x0,r38; }
	{ st4	[r14],r8; nop.i	0x0; br.cond.sptk.few	400000000012E190; }
400000000012E1E0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
400000000012E1F0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; fn400000000012E200: 400000000012E200
;;   Called from:
;;     400000000012E50C (in sh_mktmpname)
;;     400000000012E74C (in sh_mktmpfd)
fn400000000012E200 proc
	{ alloc	r36,ar.pfs,0x8,0x0,0x6; mov	r35,b3; adds	r37,0x0,r1; }
	{ nop.m	0x0; tbit.z	p06,p07,r32,0x0; (p07) br.cond.dpnt.few	400000000012E280 }

l400000000012E220:
	{ addl	r34,8836,r1; ld8	r33,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p07) br.cond.dpnt.few	400000000012E380 }

l400000000012E240:
	{ addl	r34,6444,r1; ld4	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r14; (p07) br.cond.dpnt.few	400000000012E340 }

l400000000012E260:
	{ adds	r8,0x0,r33; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,400000000012E270; br.ret	b0 }

l400000000012E280:
	{ nop.m	0x0; addl	r38,-5724,r1; nop.i	0x0; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,get_string_value; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r38,0x0,r8; nop.i	0x0 }
	{ adds	r1,0x0,r37; adds	r33,0x0,r8; (p06) br.cond.spnt.few	400000000012E220; }

l400000000012E2C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,file_iswdir; }
	{ adds	r1,0x0,r37; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	400000000012E220 }

l400000000012E2E0:
	{ adds	r38,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ addl	r14,4096,r0; nop.m	0x0; adds	r1,0x0,r37; }
	{ nop.m	0x0; cmp.ltu	p06,p07,r14,r8; (p07) br.cond.dptk.few	400000000012E240 }

l400000000012E310:
	{ addl	r34,8836,r1; ld8	r33,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	400000000012E240 }

l400000000012E330:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000012E380 }

l400000000012E340:
	{ adds	r38,0x0,r33; addl	r39,3,r0; br.call.sptk.many	b0,fn400000000001A440; }
	{ adds	r1,0x0,r37; st4	[r8],r34; mov.i	ar.pfs,r36 }
	{ nop.m	0x0; adds	r8,0x0,r33; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r35,400000000012E370; br.ret	b0 }

l400000000012E380:
	{ addl	r33,-5716,r1; ld8	r33,[r33]; nop.i	0x0; }
	{ st8	[r33],r34; adds	r38,0x0,r33; br.call.sptk.many	b0,file_iswdir; }
	{ adds	r1,0x0,r37; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	400000000012E3F0; }

l400000000012E3B0:
	{ ld8	r33,[r34]; nop.m	0x0; addl	r34,6444,r1; }
	{ nop.m	0x0; ld4	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r14; (p06) br.cond.dptk.few	400000000012E260 }

l400000000012E3E0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000012E340 }

l400000000012E3F0:
	{ st8	[r33],r34; adds	r38,0x0,r33; br.call.sptk.many	b0,file_iswdir; }
	{ adds	r1,0x0,r37; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	400000000012E3B0; }

l400000000012E410:
	{ addl	r38,-5708,r1; ld8	r38,[r38]; nop.i	0x0; }
	{ st8	[r38],r34; nop.i	0x0; br.call.sptk.many	b0,file_iswdir; }
	{ adds	r1,0x0,r37; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	400000000012E3B0; }

l400000000012E440:
	{ addl	r38,-5700,r1; ld8	r38,[r38]; nop.i	0x0; }
	{ st8	[r38],r34; nop.i	0x0; br.call.sptk.many	b0,file_iswdir; }
	{ adds	r1,0x0,r37; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dpnt.few	400000000012E3B0; }

l400000000012E470:
	{ nop.m	0x0; addl	r33,-5732,r1; nop.i	0x0; }
	{ ld8	r33,[r33]; st8	[r33],r34; addl	r34,6444,r1; }
	{ nop.m	0x0; ld4	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r14; (p06) br.cond.dptk.few	400000000012E260 }

l400000000012E4B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000012E340; }

;; sh_mktmpname: 400000000012E4C0
sh_mktmpname proc
	{ alloc	r44,ar.pfs,0x16,0x0,0xF; adds	r12,0xFFFFFFFFFFFFFF70,r12; mov	r46,pr }
	{ adds	r45,0x0,r1; nop.m	0x0; mov	r43,b3 }
	{ addl	r47,4097,r0; nop.m	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r47,0x0,r33; adds	r1,0x0,r45; nop.i	0x0 }
	{ adds	r34,0x0,r8; and	r33,0x4,r33; br.call.sptk.many	b0,fn400000000012E200; }
	{ adds	r1,0x0,r45; adds	r47,0x0,r8; nop.i	0x0 }
	{ adds	r38,0x0,r8; cmp4.eq	p16,p17,0x0,r33; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r45; cmp.eq	p07,p06,0x0,r32; adds	r39,0x1,r8; }
	{ addl	r41,9064,r1; (p07) addl	r32,-5692,r1; addl	r35,6436,r1 }

l400000000012E54C:
	{ Invalid; break.x	0x12190158A01000 }
	{ Invalid; break.x	0x80C2000801000 }

l400000000012E560:
	{ (p07) ld8	r32,[r32]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }

l400000000012E566:
	{ break.m	0x4000; Invalid; (p16) nop }
	{ Invalid; (p18) nop; (p32) nop }

l400000000012E580:
	{ ld8	r14,[r35]; nop.m	0x0; adds	r47,0x0,r0; }
	{ shladd	r36,r14,0x1,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A9C0; }
	{ ld4	r15,[r41]; nop.m	0x0; adds	r1,0x0,r45; }
	{ nop.m	0x0; sxt4	r14,r15; xor	r36,r36,r14; }
	{ xor	r36,r8,r36; nop.i	0x0; (p17) br.call.dpnt.many	b0,get_random_number; }

l400000000012E5D0:
	{ (p16) ld4	r15,[r37]; (p17) adds	r1,0x0,r45; sxt4	r8,r8 }

l400000000012E5D6:
	{ Invalid; Invalid; Invalid }

l400000000012E5DC:
	{ cmp.eq	p08,p09,r22,r0; zxt1	r64,r64; (p22) nop; }
	{ (p63) epc; break.b	0x101000; (p01) break.b	0x161E0 }
	{ nop; (p18) dep	r96,r3,r64,62,1; (p06) nop }

l400000000012E606:
	{ Invalid; (p25) nop; (p32) nop }
	{ mf.a; (p32) nop }

l400000000012E61C:
	{ ld1.nt1	r0,[r0]; (p06) addp4	r64,r12,r6; (p06) nop }
	{ Invalid; Invalid; Invalid }
	{ (p48) nop; cmp.lt	p00,p00,r32,r0; (p01) nop }
	{ cmp.eq	p45,p09,r0,r66; zxt4	r0,r0; (p06) nop }
	{ Invalid; Invalid; Invalid }
	{ (p63) cmp.lt	p14,p03,r63,r70; (p32) cmp.eq.unc	p07,p26,r99,r97; Invalid; }
	{ Invalid; Invalid; break.i	0x1000; }

l400000000012E680:
	{ (p07) st1	[r0],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C0A0; }

l400000000012E686:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ (p03) chk.a.clr	r8,3FFFFFFFFF971696; nop; break.b	0x80000 }

l400000000012E6A0:
	{ nop.m	0x0; ld4	r14,[r42]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2,r14; (p06) br.cond.dptk.few	400000000012E580; }

l400000000012E6C0:
	{ adds	r8,0x0,r34; mov	pr,r46,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r44; }
	{ nop.m	0x0; mov.spnt	b0,r43,400000000012E6D0; nop.i	0x0 }
	{ adds	r12,0x90,r12; nop.m	0x0; br.ret	b0; }
400000000012E6F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; sh_mktmpfd: 400000000012E700
;;   Called from:
;;     400000000012EA2C (in sh_mktmpfp)
sh_mktmpfd proc
	{ alloc	r45,ar.pfs,0x17,0x0,0x10; mov	r47,pr; adds	r46,0x0,r1; }
	{ nop.m	0x0; mov	r44,b4; addl	r48,4097,r0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r46; adds	r48,0x0,r33; nop.b	0x0 }
	{ adds	r35,0x0,r8; tnat.z	p16,p17,r33; br.call.sptk.many	b0,fn400000000012E200; }
	{ adds	r1,0x0,r46; nop.m	0x0; adds	r39,0x0,r8 }
	{ adds	r48,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r46; cmp.eq	p07,p06,0x0,r32; tbit.z	p08,p09,r33,0x1 }
	{ nop.m	0x0; adds	r41,0x1,r8; nop.i	0x0; }
	{ (p07) addl	r32,-5692,r1; addl	r42,9064,r1; addl	r36,6436,r1 }

l400000000012E796:
	{ Invalid; (p18) nop; (p50) nop }

l400000000012E7A6:
	{ Invalid; (p19) nop; dep	r0,r0,r32,63,1 }
	{ (p21) chk.a.clr	r66,3FFFFFFFFF330FB6; (p16) br.call.dpnt.few.clr	b0,b0; Invalid }

l400000000012E7BC:
	{ Invalid; (p04) nop }

l400000000012E7C0:
	{ nop.m	0x0; (p07) ld8	r32,[r32]; nop.i	0x0; }

l400000000012E7CC:
	{ nop; break.i	0x1000; break.i	0x1000 }
	{ cmp.lt	p00,p09,r1,r0; Invalid; break.i	0x1000 }

l400000000012E7E0:
	{ ld8	r14,[r36]; nop.m	0x0; adds	r48,0x0,r0; }

l400000000012E7E2:
	{ break.m	0x20309; Invalid; nop }
	{ (p01) break.m	0x40200; nop; brp.sptk	400000000012EF52; }
	{ (p32) break.m	0x2020A; zxt1	r32,r0; (p32) break.i	0xC200B }
	{ Invalid; (p48) nop; (p36) nop }
	{ (p17) break.m	0x401E9; tbit.z	p32,p04,r32,0x0; (p45) pshr4.u	r25,r11,31; }

l400000000012E830:
	{ (p16) ld4	r15,[r38]; (p17) adds	r1,0x0,r46; sxt4	r8,r8 }

l400000000012E836:
	{ Invalid; Invalid; Invalid }

l400000000012E83C:
	{ Invalid; (p06) nop; zxt1	r0,r64; }
	{ Invalid; Invalid; Invalid }
	{ nop; (p18) nop; (p06) nop }

l400000000012E866:
	{ Invalid; (p24) nop; (p32) nop }
	{ mf.a; (p48) nop }

l400000000012E87C:
	{ ldfe.nt1	f0,[r0]; (p06) dep	r96,r12,r6,63,9; (p54) cmp.lt	p31,p19,r127,r127 }
	{ Invalid; Invalid; Invalid }
	{ (p29) nop; cmp.lt	p00,p00,r32,r0; (p01) nop }
	{ nop; (p06) nop; (p06) dep	r96,r10,r64,62,1 }
	{ Invalid; Invalid; Invalid }
	{ (p63) cmp.lt	p14,p03,r63,r70; (p32) cmp.eq.unc	p07,p26,r99,r97; Invalid; }
	{ Invalid; Invalid; break.b	0x1000; }

l400000000012E8E0:
	{ (p07) st1	[r0],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B4E0; }

l400000000012E8E6:
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ add	r0,r0,r1; nop; (p16) nop }
	{ chk.a.nc	f0,3FFFFFFFFF12F106; nop; break.i	0x80000 }

l400000000012E910:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ ld4	r14,[r8]; nop.m	0x0; adds	r1,0x0,r46; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x11,r14; (p06) br.cond.dptk.few	400000000012E7E0; }

l400000000012E940:
	{ cmp.eq	p07,p06,0x0,r34; adds	r8,0x0,r37; mov.i	ar.pfs,r45 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	400000000012E990; }

l400000000012E960:
	{ nop.m	0x0; mov.spnt	b0,r44,400000000012E960; nop.i	0x0 }
	{ (p06) st8	[r35],r34; nop.m	0x0; nop.i	0x0; }

l400000000012E976:
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ (p63) rum	0x17F82F; (p34) nop; nop.b	0x2300C }

l400000000012E990:
	{ adds	r48,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r8,0x0,r37; adds	r1,0x0,r46; mov	pr,r47,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r45; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r44,400000000012E9C0; br.ret	b0; }
400000000012E9D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012E9E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012E9F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; sh_mktmpfp: 400000000012EA00
;;   Called from:
;;     40000000000F9F6C (in fc_builtin)
sh_mktmpfp proc
	{ alloc	r38,ar.pfs,0xB,0x0,0x8; adds	r41,0x0,r33; mov	r37,b5 }
	{ adds	r39,0x0,r1; adds	r42,0x0,r34; adds	r40,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_mktmpfd; }
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x1; nop.b	0x0 }
	{ adds	r1,0x0,r39; adds	r35,0x0,r8; adds	r40,0x0,r8; }
	{ nop.m	0x0; (p06) adds	r41,0x1,r0; nop.i	0x0; }

l400000000012EA5C:
	{ nop; (p05) cmp.lt	p00,p16,r0,r64; mov	pr,r96,0xC204 }

l400000000012EA66:
	{ (p03) chk.a.clr	r8,3FFFFFFFFF972266; Invalid; break.i	0x80000 }

l400000000012EA70:
	{ nop.m	0x0; tbit.z	p07,p06,r41,0x0; (p07) addl	r41,-5676,r1; }

l400000000012EA80:
	{ (p06) addl	r41,-5668,r1; (p07) ld8	r41,[r41]; nop.i	0x0; }

l400000000012EA86:
	{ (p20) fwb; nop; (p17) br.call.sptk.few	b2,b0; }

l400000000012EA8C:
	{ nop; Invalid; break.i	0x1000 }

l400000000012EA96:
	{ break.m	0x4000; (p32) nop; nop }
	{ Invalid; nop; (p16) nop.b	0x27000 }
	{ chk.a.nc	f38,3FFFFFFFFF143EB6; nop; nop }

l400000000012EAC0:
	{ adds	r8,0x0,r36; mov.spnt	b0,r37,400000000012EAC0; br.ret	b0; }

l400000000012EAD0:
	{ adds	r40,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C340; }
	{ adds	r8,0x0,r36; adds	r1,0x0,r39; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,400000000012EAF0; br.ret	b0 }

l400000000012EB00:
	{ adds	r36,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ adds	r8,0x0,r36; mov.spnt	b0,r37,400000000012EB10; br.ret	b0; }
400000000012EB20 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
400000000012EB30 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; strlist_create: 400000000012EB40
;;   Called from:
;;     40000000000E3F6C (in fn40000000000E3EC0)
;;     40000000000E458C (in filter_stringlist)
;;     40000000000E483C (in filter_stringlist)
;;     40000000000E48CC (in completions_to_stringlist)
;;     40000000000E4A5C (in completions_to_stringlist)
;;     40000000000E5B3C (in gen_compspec_completions)
;;     40000000000E5D2C (in gen_compspec_completions)
;;     40000000000E6C7C (in gen_compspec_completions)
;;     40000000000E6FDC (in gen_compspec_completions)
;;     400000000012EDFC (in strlist_resize)
;;     400000000012F0CC (in strlist_copy)
;;     400000000012F2EC (in strlist_merge)
strlist_create proc
	{ alloc	r35,ar.pfs,0x7,0x0,0x6; adds	r36,0x0,r1; mov	r34,b2; }
	{ addl	r38,16,r0; mov	r37,LC; br.call.sptk.many	b0,xmalloc; }
	{ cmp4.eq	p06,p07,0x0,r32; adds	r14,0x0,r8; nop.i	0x0 }
	{ adds	r1,0x0,r36; adds	r33,0x0,r8; (p07) br.cond.dpnt.few	400000000012EBD0; }

l400000000012EB80:
	{ nop.m	0x0; (p06) st8	[r14],r8,8; nop.i	0x0; }

l400000000012EB8C:
	{ Invalid; Invalid; break.i	0x1000 }

l400000000012EB96:
	{ break.m	0x4000; nop; (p32) nop }

l400000000012EBA0:
	{ adds	r14,0xC,r33; adds	r8,0x0,r33; mov.i	ar.pfs,r35; }
	{ st4	[r0],r14; nop.m	0x0; mov.i	LC,r37; }
	{ nop.m	0x0; mov.spnt	b0,r34,400000000012EBC0; br.ret	b0; }

l400000000012EBD0:
	{ adds	r38,0x1,r32; nop.i	0x0; br.call.sptk.many	b0,strvec_create; }
	{ adds	r15,0x0,r33; adds	r14,0x0,r0; nop.i	0x0 }
	{ adds	r16,0xFFFFFFFFFFFFFFFF,r32; adds	r1,0x0,r36; cmp4.lt	p06,p07,0x0,r32; }
	{ st8	[r15],r8,8; nop.m	0x0; addp4	r16,r16,r0 }
	{ add	r8,r8,r14; nop.m	0x0; adds	r14,0x8,r14; }
	{ st4	[r32],r15; mov.i	LC,r16; (p07) br.cond.dpnt.few	400000000012EBA0; }

l400000000012EC30:
	{ st8	[r0],r8; nop.i	0x0; br.cloop.sptk.few	400000000012EC70; }

l400000000012EC40:
	{ adds	r14,0xC,r33; adds	r8,0x0,r33; mov.i	ar.pfs,r35; }
	{ st4	[r0],r14; nop.m	0x0; mov.i	LC,r37; }
	{ nop.m	0x0; mov.spnt	b0,r34,400000000012EC60; br.ret	b0 }

l400000000012EC70:
	{ ld8	r8,[r33]; add	r8,r8,r14; adds	r14,0x8,r14; }
	{ st8	[r0],r8; nop.i	0x0; br.cloop.sptk.few	400000000012EC70 }

l400000000012EC90:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000012EC40; }
400000000012ECA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012ECB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; strlist_resize: 400000000012ECC0
;;   Called from:
;;     40000000000E72AC (in gen_compspec_completions)
;;     400000000012F5EC (in strlist_append)
strlist_resize proc
	{ alloc	r36,ar.pfs,0x8,0x0,0x6; adds	r34,0x8,r32; mov	r35,b3 }
	{ cmp.eq	p07,p06,0x0,r32; adds	r37,0x0,r1; (p07) br.cond.dpnt.few	400000000012EDE0; }

l400000000012ECE0:
	{ ld4	r14,[r34]; adds	r8,0x0,r32; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r14,r33; mov.spnt	b0,r35,400000000012ECF0 }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	400000000012ED10; br.ret	b0; }

l400000000012ED0C:
	{ cmp.lt	p00,p17,r33,r0; (p04) cmp.eq	p00,p08,r8,r6; zxt1	r32,r64 }

l400000000012ED10:
	{ ld8	r38,[r32]; adds	r39,0x1,r33; br.call.sptk.many	b0,strvec_resize; }
	{ ld4	r14,[r34]; st8	[r8],r32; adds	r1,0x0,r37; }
	{ cmp4.lt	p07,p06,r33,r14; nop.m	0x0; sub	r15,r33,r14 }
	{ nop.m	0x0; sxt4	r16,r14; (p07) br.cond.dpnt.few	400000000012EDC0; }

l400000000012ED50:
	{ (p06) addp4	r15,r15,r0; nop.m	0x0; (p06) shladd	r14,r16,0x3,r0; }

l400000000012ED56:
	{ chk.a.nc	r0,3FFFFFFFFF12F556; (p07) addl	r16,286720,r2; (p49) nop }

l400000000012ED60:
	{ (p06) add	r15,r16,r15,0x1; add	r8,r8,r14; adds	r14,0x8,r14; }

l400000000012ED66:
	{ Invalid; (p07) addl	r8,24846,r0; (p49) nop }

l400000000012ED76:
	{ mf.a; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r15,3FFFFFFFFFD32666; nop; break.i	0x80000 }

l400000000012ED90:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000012EDA0:
	{ ld8	r8,[r32]; add	r8,r8,r14; adds	r14,0x8,r14; }
	{ st8	[r0],r8; cmp.eq	p06,p07,r15,r14; (p07) br.cond.dptk.few	400000000012EDA0 }

l400000000012EDC0:
	{ adds	r8,0x0,r32; st4	[r33],r34; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,400000000012EDD0; br.ret	b0; }

l400000000012EDE0:
	{ adds	r32,0x0,r33; mov.spnt	b0,r35,400000000012EDE0; mov.i	ar.pfs,r36; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	strlist_create; }
400000000012EE00 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
400000000012EE10 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012EE20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012EE30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; strlist_flush: 400000000012EE40
strlist_flush proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; mov	r33,b1; nop.i	0x0 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r35,0x0,r1; (p06) br.cond.dpnt.few	400000000012EEA0; }

l400000000012EE60:
	{ ld8	r14,[r32]; nop.m	0x0; adds	r32,0xC,r32; }
	{ cmp.eq	p06,p07,0x0,r14; adds	r36,0x0,r14; (p06) br.cond.dpnt.few	400000000012EEA0; }

l400000000012EE80:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strvec_flush; }
	{ adds	r1,0x0,r35; st4	[r0],r32; nop.i	0x0 }

l400000000012EEA0:
	{ nop.m	0x0; mov.i	ar.pfs,r34; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r33,400000000012EEB0; br.ret	b0; }

;; strlist_dispose: 400000000012EEC0
;;   Called from:
;;     40000000000E4D8C (in fn40000000000E4B40)
;;     40000000000E4E3C (in fn40000000000E4B40)
;;     40000000000E4EEC (in fn40000000000E4B40)
;;     40000000000E4F9C (in fn40000000000E4B40)
;;     40000000000E504C (in fn40000000000E4B40)
;;     40000000000E50FC (in fn40000000000E4B40)
;;     40000000000E518C (in fn40000000000E4B40)
;;     40000000000E521C (in fn40000000000E4B40)
;;     40000000000E52AC (in fn40000000000E4B40)
;;     40000000000E533C (in fn40000000000E4B40)
;;     40000000000E53CC (in fn40000000000E4B40)
;;     40000000000E545C (in fn40000000000E4B40)
;;     40000000000E54EC (in fn40000000000E4B40)
;;     40000000000E557C (in fn40000000000E4B40)
;;     40000000000E560C (in fn40000000000E4B40)
;;     40000000000E569C (in fn40000000000E4B40)
;;     40000000000E572C (in fn40000000000E4B40)
;;     40000000000E57BC (in fn40000000000E4B40)
;;     40000000000E584C (in fn40000000000E4B40)
;;     40000000000E58DC (in fn40000000000E4B40)
;;     40000000000E596C (in fn40000000000E4B40)
;;     40000000000E59FC (in fn40000000000E4B40)
;;     40000000000E5A8C (in fn40000000000E4B40)
;;     40000000000E5C0C (in gen_compspec_completions)
;;     40000000000E5FEC (in gen_compspec_completions)
;;     40000000000E63FC (in gen_compspec_completions)
;;     40000000000E6D4C (in gen_compspec_completions)
;;     40000000000E6E2C (in gen_compspec_completions)
;;     40000000000E71EC (in gen_compspec_completions)
;;     400000000011DFDC (in compgen_builtin)
;;     400000000011E13C (in compgen_builtin)
strlist_dispose proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; mov	r33,b1; nop.i	0x0 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r35,0x0,r1; (p06) br.cond.dpnt.few	400000000012EF40; }

l400000000012EEE0:
	{ nop.m	0x0; ld8	r36,[r32]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r36; nop.i	0x0; (p06) br.cond.dpnt.few	400000000012EF20; }

l400000000012EF00:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strvec_dispose; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l400000000012EF20:
	{ nop.m	0x0; adds	r36,0x0,r32; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l400000000012EF40:
	{ nop.m	0x0; mov.i	ar.pfs,r34; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r33,400000000012EF50; br.ret	b0; }
400000000012EF60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012EF70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; strlist_remove: 400000000012EF80
strlist_remove proc
	{ alloc	r36,ar.pfs,0x8,0x0,0x6; mov	r35,b3; adds	r34,0xC,r32 }
	{ cmp.eq	p07,p06,0x0,r32; adds	r37,0x0,r1; (p07) br.cond.dpnt.few	400000000012EFE0; }

l400000000012EFA0:
	{ nop.m	0x0; ld8	r38,[r32]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r38; nop.i	0x0; (p06) br.cond.dpnt.few	400000000012EFE0; }

l400000000012EFC0:
	{ nop.m	0x0; ld4	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	400000000012F000 }

l400000000012EFE0:
	{ adds	r8,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,400000000012EFF0; br.ret	b0; }

l400000000012F000:
	{ adds	r39,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,strvec_remove; }
	{ adds	r1,0x0,r37; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	400000000012EFE0 }

l400000000012F020:
	{ ld4	r14,[r34]; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r14; nop.m	0x0; mov.spnt	b0,r35,400000000012F030; }
	{ st4	[r14],r34; nop.i	0x0; br.ret	b0; }
400000000012F050 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012F060 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012F070 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; strlist_copy: 400000000012F080
;;   Called from:
;;     400000000012F75C (in strlist_append)
strlist_copy proc
	{ alloc	r39,ar.pfs,0xB,0x0,0x9; cmp.eq	p06,p07,0x0,r32; nop.b	0x0 }
	{ adds	r37,0x8,r32; mov	r38,b6; adds	r40,0x0,r1; }
	{ (p06) adds	r36,0x0,r0; nop.m	0x0; adds	r33,0x0,r0 }

l400000000012F0A6:
	{ add	r0,r0,r1; (p16) nop; (p32) nop }
	{ chk.a.nc	r0,3FFFFFFFFF12F8B6; nop; (p16) nop }

l400000000012F0C0:
	{ ld4	r41,[r37]; nop.i	0x0; br.call.sptk.many	b0,strlist_create; }
	{ ld8	r15,[r32]; nop.m	0x0; adds	r1,0x0,r40 }
	{ adds	r36,0x0,r8; ld4	r14,[r37]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r15; nop.i	0x0; (p07) br.cond.dpnt.few	400000000012F200; }

l400000000012F100:
	{ nop.m	0x0; cmp4.lt	p07,p06,0x0,r14; (p06) br.cond.dpnt.few	400000000012F200; }

l400000000012F110:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000012F120:
	{ add	r15,r15,r33; ld8	r16,[r36]; nop.i	0x0; }
	{ ld8	r14,[r15]; nop.m	0x0; add	r35,r16,r33; }
	{ cmp.eq	p06,p07,0x0,r14; nop.m	0x0; adds	r41,0x0,r14; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	400000000012F1C0; }

l400000000012F156:
	{ chk.a.nc	r0,3FFFFFFFFF12F956; nop; break.i	0x80000 }

l400000000012F160:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r40; adds	r41,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r14,[r32]; adds	r1,0x0,r40; adds	r41,0x0,r8; }
	{ add	r14,r14,r33; nop.i	0x0; nop.i	0x0 }
	{ ld8	r42,[r14]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r40; nop.m	0x0; nop.i	0x0 }

l400000000012F1C0:
	{ ld4	r14,[r37]; nop.m	0x0; adds	r34,0x1,r34 }
	{ st8	[r8],r35; nop.m	0x0; adds	r33,0x8,r33; }
	{ cmp4.lt	p07,p06,r34,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000012F200; }

l400000000012F1F0:
	{ ld8	r15,[r32]; nop.i	0x0; br.cond.sptk.few	400000000012F120 }

l400000000012F200:
	{ adds	r32,0xC,r32; ld8	r16,[r36]; adds	r18,0x8,r36 }
	{ adds	r17,0xC,r36; ld4	r15,[r32]; nop.i	0x0 }
	{ st4	[r14],r18; cmp.eq	p06,p07,0x0,r16; sxt4	r14,r15 }
	{ st4	[r15],r17; nop.i	0x0; (p07) shladd	r16,r14,0x3,r16; }

l400000000012F240:
	{ (p07) st8	[r0],r16; nop.m	0x0; nop.i	0x0 }

l400000000012F246:
	{ break.m	0x4000; nop; nop }

l400000000012F250:
	{ adds	r8,0x0,r36; nop.m	0x0; mov.i	ar.pfs,r39; }

l400000000012F252:
	{ break.m	0x42009; cmp.eq	p32,p00,r0,r0; Invalid }
	{ cmp.lt	p32,p00,r0,r0; (p20) nop; Invalid }
400000000012F270 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; strlist_merge: 400000000012F280
strlist_merge proc
	{ alloc	r42,ar.pfs,0xF,0x0,0xD; cmp.eq	p06,p07,0x0,r32; nop.b	0x0 }
	{ adds	r14,0xC,r32; adds	r43,0x0,r1; mov	r41,b1; }
	{ (p07) ld4	r37,[r14]; adds	r14,0xC,r33; nop.b	0x0 }

l400000000012F2A6:
	{ Invalid; nop; (p32) nop }
	{ break.m	0x4000; (p22) addl	r0,802881,r2; (p17) nop }

l400000000012F2C6:
	{ break.m	0x4000; (p03) cmp4.eq.or	p00,p50,0x21,r7; (p49) addl	r9,576,r3 }

l400000000012F2D6:
	{ Invalid; nop; (p16) nop.b	0xA74AB; }

l400000000012F2DC:
	{ nop; zxt1	r105,r0; break.i	0x1000 }
	{ (p03) cmp.lt.unc	p63,p08,r63,r44; (p49) nop; zxt1	r96,r64 }
	{ ldfpd	f0,f1,[r0]; (p04) cmp.eq	p00,p16,r2,r64; mov	pr,r73,0xC640 }
	{ (p17) cmp.lt	p00,p03,r64,r33; zxt1	r3,r2; break.b	0x1000 }

l400000000012F310:
	{ addp4	r14,r14,r0; nop.i	0x0; mov.i	LC,r14; }

l400000000012F320:
	{ ld8	r15,[r32]; ld8	r14,[r35]; nop.i	0x0; }
	{ add	r15,r15,r34; nop.m	0x0; add	r36,r14,r34; }
	{ ld8	r14,[r15]; cmp.eq	p06,p07,0x0,r14; adds	r45,0x0,r14; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	400000000012F3C0; }

l400000000012F356:
	{ chk.a.nc	r0,3FFFFFFFFF12FB56; nop; break.i	0x80000 }

l400000000012F360:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r43; adds	r45,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r14,[r32]; adds	r1,0x0,r43; adds	r45,0x0,r8; }
	{ add	r14,r14,r34; nop.i	0x0; nop.i	0x0 }
	{ ld8	r46,[r14]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r43; nop.m	0x0; nop.i	0x0 }

l400000000012F3C0:
	{ st8	[r8],r36; adds	r34,0x8,r34; br.cloop.sptk.few	400000000012F320 }

l400000000012F3D0:
	{ nop.m	0x0; sxt4	r14,r37; nop.i	0x0 }
	{ adds	r38,0x0,r37; nop.i	0x0; shladd	r14,r14,0x3,r0 }

l400000000012F3F0:
	{ nop.m	0x0; adds	r40,0xFFFFFFFFFFFFFFFF,r39; sxt4	r37,r38 }
	{ cmp4.lt	p07,p06,0x0,r39; adds	r34,0x0,r0; (p06) br.cond.dpnt.few	400000000012F4F0; }

l400000000012F410:
	{ shladd	r37,r37,0x3,r0; addp4	r14,r40,r0; mov.i	LC,r14; }

l400000000012F420:
	{ nop.m	0x0; ld8	r15,[r33]; add	r36,r34,r37 }
	{ ld8	r14,[r35]; add	r15,r15,r34; add	r36,r14,r36; }
	{ ld8	r14,[r15]; cmp.eq	p06,p07,0x0,r14; adds	r45,0x0,r14; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	400000000012F4C0; }

l400000000012F456:
	{ chk.a.nc	r0,3FFFFFFFFF12FC56; nop; break.i	0x80000 }

l400000000012F460:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r43; adds	r45,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r14,[r33]; adds	r1,0x0,r43; adds	r45,0x0,r8; }
	{ add	r14,r14,r34; nop.i	0x0; nop.i	0x0 }
	{ ld8	r46,[r14]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r43; nop.m	0x0; nop.i	0x0 }

l400000000012F4C0:
	{ st8	[r8],r36; adds	r34,0x8,r34; br.cloop.sptk.few	400000000012F420 }

l400000000012F4D0:
	{ add	r38,r38,r40,0x1; nop.i	0x0; sxt4	r14,r38; }
	{ shladd	r14,r14,0x3,r0; nop.m	0x0; nop.i	0x0 }

l400000000012F4F0:
	{ ld8	r16,[r35]; adds	r15,0xC,r35; nop.b	0x0 }
	{ adds	r8,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r42; }
	{ add	r14,r16,r14; st4	[r38],r15; mov.i	LC,r44; }
	{ st8	[r0],r14; mov.spnt	b0,r41,400000000012F520; br.ret	b0 }

l400000000012F530:
	{ adds	r14,0x0,r0; adds	r38,0x0,r0; br.cond.sptk.few	400000000012F3F0; }

;; strlist_append: 400000000012F540
;;   Called from:
;;     40000000000E4D5C (in fn40000000000E4B40)
;;     40000000000E4E0C (in fn40000000000E4B40)
;;     40000000000E4EBC (in fn40000000000E4B40)
;;     40000000000E4F6C (in fn40000000000E4B40)
;;     40000000000E501C (in fn40000000000E4B40)
;;     40000000000E50CC (in fn40000000000E4B40)
;;     40000000000E516C (in fn40000000000E4B40)
;;     40000000000E51FC (in fn40000000000E4B40)
;;     40000000000E528C (in fn40000000000E4B40)
;;     40000000000E531C (in fn40000000000E4B40)
;;     40000000000E53AC (in fn40000000000E4B40)
;;     40000000000E543C (in fn40000000000E4B40)
;;     40000000000E54CC (in fn40000000000E4B40)
;;     40000000000E555C (in fn40000000000E4B40)
;;     40000000000E55EC (in fn40000000000E4B40)
;;     40000000000E567C (in fn40000000000E4B40)
;;     40000000000E570C (in fn40000000000E4B40)
;;     40000000000E579C (in fn40000000000E4B40)
;;     40000000000E582C (in fn40000000000E4B40)
;;     40000000000E58BC (in fn40000000000E4B40)
;;     40000000000E594C (in fn40000000000E4B40)
;;     40000000000E59DC (in fn40000000000E4B40)
;;     40000000000E5A6C (in fn40000000000E4B40)
;;     40000000000E5BEC (in gen_compspec_completions)
;;     40000000000E5FCC (in gen_compspec_completions)
;;     40000000000E63DC (in gen_compspec_completions)
;;     40000000000E6E0C (in gen_compspec_completions)
;;     40000000000E71CC (in gen_compspec_completions)
strlist_append proc
	{ alloc	r40,ar.pfs,0xD,0x0,0xB; cmp.eq	p07,p06,0x0,r32; mov	r42,LC }
	{ adds	r15,0xC,r33; adds	r14,0xC,r32; adds	r41,0x0,r1; }
	{ nop.m	0x0; mov	r39,b7; (p07) br.cond.dpnt.few	400000000012F730; }

l400000000012F570:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r33; nop.i	0x0 }
	{ ld4	r37,[r14]; nop.m	0x0; (p06) br.cond.dpnt.few	400000000012F5B0; }

l400000000012F590:
	{ nop.m	0x0; ld4	r35,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r35; (p07) br.cond.dpnt.few	400000000012F5D0 }

l400000000012F5B0:
	{ adds	r8,0x0,r32; mov.i	ar.pfs,r40; mov.i	LC,r42; }
	{ nop.m	0x0; mov.spnt	b0,r39,400000000012F5C0; br.ret	b0; }

l400000000012F5D0:
	{ adds	r43,0x0,r32; adds	r38,0xFFFFFFFFFFFFFFFF,r35; add	r44,r37,r35,0x1 }
	{ adds	r34,0x0,r0; sxt4	r36,r37; br.call.sptk.many	b0,strlist_resize; }
	{ addp4	r14,r38,r0; shladd	r36,r36,0x3,r0; adds	r1,0x0,r41 }
	{ adds	r32,0x0,r8; cmp4.lt	p07,p06,0x0,r35; (p06) br.cond.dpnt.few	400000000012F6E0; }

l400000000012F610:
	{ nop.m	0x0; mov.i	LC,r14; nop.i	0x0; }

l400000000012F620:
	{ nop.m	0x0; ld8	r15,[r33]; add	r35,r34,r36 }
	{ ld8	r14,[r32]; add	r15,r15,r34; add	r35,r14,r35; }
	{ ld8	r14,[r15]; cmp.eq	p06,p07,0x0,r14; adds	r43,0x0,r14; }
	{ (p06) adds	r8,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	400000000012F6C0; }

l400000000012F656:
	{ chk.a.nc	r0,3FFFFFFFFF12FE56; nop; break.i	0x80000 }

l400000000012F660:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r41; adds	r43,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r14,[r33]; adds	r1,0x0,r41; adds	r43,0x0,r8; }
	{ add	r14,r14,r34; nop.i	0x0; nop.i	0x0 }
	{ ld8	r44,[r14]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r41; nop.m	0x0; nop.i	0x0 }

l400000000012F6C0:
	{ st8	[r8],r35; adds	r34,0x8,r34; br.cloop.sptk.few	400000000012F620 }

l400000000012F6D0:
	{ add	r37,r37,r38,0x1; nop.m	0x0; nop.i	0x0; }

l400000000012F6E0:
	{ adds	r14,0x0,r32; adds	r8,0x0,r32; mov.i	ar.pfs,r40 }
	{ nop.m	0x0; sxt4	r16,r37; nop.b	0x0; }
	{ ld8	r15,[r14],12; nop.m	0x0; mov.i	LC,r42; }
	{ shladd	r15,r16,0x3,r15; mov.spnt	b0,r39,400000000012F710; nop.i	0x0 }
	{ st8	[r0],r15; st4	[r37],r14; br.ret	b0 }

l400000000012F730:
	{ cmp.eq	p06,p07,0x0,r33; mov.spnt	b0,r39,400000000012F730; (p06) br.cond.dpnt.few	400000000012F5B0; }

l400000000012F740:
	{ adds	r32,0x0,r33; mov.i	ar.pfs,r40; mov.i	LC,r42; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	strlist_copy; }
400000000012F760 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
400000000012F770 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; strlist_prefix_suffix: 400000000012F780
;;   Called from:
;;     40000000000E6A9C (in gen_compspec_completions)
;;     40000000000E6D9C (in gen_compspec_completions)
strlist_prefix_suffix proc
	{ alloc	r44,ar.pfs,0x11,0x0,0xF; mov	r46,pr; nop.b	0x0 }
	{ cmp.eq	p07,p06,0x0,r32; adds	r39,0xC,r32; adds	r45,0x0,r1; }
	{ nop.m	0x0; mov	r43,b3; (p07) br.cond.dpnt.few	400000000012FAF0; }

l400000000012F7B0:
	{ nop.m	0x0; ld8	r36,[r32]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r36; nop.i	0x0; (p06) br.cond.dpnt.few	400000000012FAF0; }

l400000000012F7D0:
	{ nop.m	0x0; ld4	r35,[r39]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r35; nop.i	0x0; (p06) br.cond.dpnt.few	400000000012FAF0; }

l400000000012F7F0:
	{ cmp.eq	p06,p07,0x0,r33; nop.i	0x0; (p06) br.cond.dpnt.few	400000000012FB20; }

l400000000012F800:
	{ ld1	r14,[r33]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000012FB20 }

l400000000012F820:
	{ adds	r14,0x1,r33; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	400000000012FB80; }

l400000000012F850:
	{ (p06) addl	r40,1,r0; nop.m	0x0; nop.i	0x0 }

l400000000012F856:
	{ break.m	0x4000; nop; (p32) nop }

l400000000012F860:
	{ cmp.eq	p06,p07,0x0,r34; nop.i	0x0; (p06) br.cond.dpnt.few	400000000012FB10; }

l400000000012F870:
	{ ld1	r14,[r34]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000012FB10 }

l400000000012F890:
	{ adds	r14,0x1,r34; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	400000000012FB30; }

l400000000012F8C0:
	{ (p06) addl	r41,1,r0; nop.m	0x0; nop.i	0x0; }

l400000000012F8C6:
	{ break.m	0x4000; nop; break.i	0x80000 }

l400000000012F8D0:
	{ nop.m	0x0; or	r14,r40,r41; sxt4	r42,r40 }
	{ adds	r37,0x0,r0; cmp4.eq	p18,p19,0x0,r40; cmp4.eq	p16,p17,0x0,r41; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000012FAF0; }

l400000000012F900:
	{ cmp4.lt	p07,p06,0x0,r35; adds	r35,0x0,r0; (p06) br.cond.dpnt.few	400000000012FAF0; }

l400000000012F910:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000012F920:
	{ nop.m	0x0; add	r36,r36,r35; nop.i	0x0; }
	{ ld8	r47,[r36]; cmp.eq	p06,p07,0x0,r47; adds	r15,0x1,r47; }
	{ (p06) adds	r38,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	400000000012F9E0; }

l400000000012F946:
	{ chk.a.nc	r0,3FFFFFFFFF130146; Invalid; (p32) nop }

l400000000012F950:
	{ ld1	r14,[r47]; adds	r38,0x0,r0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000012F9E0 }

l400000000012F970:
	{ ld1	r14,[r15]; adds	r16,0x2,r47; addl	r38,1,r0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000012F9E0 }

l400000000012F9A0:
	{ ld1	r14,[r16]; addl	r38,2,r0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000012F9E0 }

l400000000012F9C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; adds	r1,0x0,r45; adds	r38,0x0,r8; }

l400000000012F9E0:
	{ add	r47,r40,r38; sxt4	r38,r38; adds	r37,0x1,r37; }
	{ add	r47,r41,r47; adds	r47,0x2,r47; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r47,r47; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r45; adds	r36,0x0,r8; nop.i	0x0 }
	{ (p19) adds	r47,0x0,r8; (p19) adds	r48,0x0,r33; (p19) br.call.dpnt.many	b0,fn400000000001B180; }

l400000000012FA26:
	{ (p24) nop; (p32) nop }

l400000000012FA2C:
	{ (p59) cmp.lt.unc	p22,p09,r123,r45; (p01) cmp.eq	p00,p08,r8,r6; (p05) nop }

l400000000012FA30:
	{ ld8	r14,[r32]; add	r47,r36,r42; (p19) adds	r1,0x0,r45; }

l400000000012FA40:
	{ nop.m	0x0; add	r14,r14,r35; nop.i	0x0; }
	{ ld8	r48,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ (p17) add	r47,r38,r42; adds	r1,0x0,r45; (p17) adds	r48,0x0,r34; }

l400000000012FA66:
	{ nop; (p24) nop; (p52) nop.b	0x2F48B }

l400000000012FA70:
	{ (p17) add	r47,r36,r47; nop.i	0x0; (p17) br.call.dpnt.many	b0,fn400000000001B180; }

l400000000012FA76:
	{ nop; Invalid; (p32) tbit.z	p03,p06,r8,0x0 }

l400000000012FA80:
	{ ld8	r14,[r32]; (p17) adds	r1,0x0,r45; add	r14,r14,r35; }

l400000000012FA8C:
	{ (p07) cmp.eq	p35,p17,r0,r64; Invalid; break.i	0x1000; }
	{ (p42) nop; cmp.eq	p00,p00,r32,r0; (p01) nop }
	{ nop; cmp.lt	p00,p00,r32,r0; Invalid }
	{ cmp.eq	p00,p09,r1,r0; (p49) cmp.eq.unc	p35,p16,r8,r0; (p16) nop }
	{ Invalid; break.x	0x8CC0F48001000 }
	{ (p01) shladd	r0,r64,0x1,r33; Invalid; break.i	0x1000 }

l400000000012FAE0:
	{ ld8	r36,[r32]; nop.i	0x0; br.cond.sptk.few	400000000012F920 }

l400000000012FAF0:
	{ adds	r8,0x0,r32; mov	pr,r46,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r44; }
	{ nop.m	0x0; mov.spnt	b0,r43,400000000012FB00; br.ret	b0 }

l400000000012FB10:
	{ nop.m	0x0; adds	r41,0x0,r0; br.cond.sptk.few	400000000012F8D0 }

l400000000012FB20:
	{ nop.m	0x0; adds	r40,0x0,r0; br.cond.sptk.few	400000000012F860 }

l400000000012FB30:
	{ adds	r14,0x2,r34; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r41,2,r0; (p06) br.cond.dptk.few	400000000012F8D0 }

l400000000012FB5C:
	{ (p44) cmp.eq.unc	p63,p17,r63,r37; zxt1	r64,r64; break.i	0x1000 }

l400000000012FB60:
	{ adds	r47,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r45; adds	r41,0x0,r8; br.cond.sptk.few	400000000012F8D0 }

l400000000012FB80:
	{ adds	r14,0x2,r33; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r40,2,r0; (p06) br.cond.dptk.few	400000000012F860 }

l400000000012FBAC:
	{ (p38) cmp.eq.unc	p63,p17,r63,r37; zxt1	r32,r64; break.i	0x1000 }

l400000000012FBB0:
	{ adds	r47,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r45; adds	r40,0x0,r8; br.cond.sptk.few	400000000012F860; }
400000000012FBD0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012FBE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012FBF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; strlist_print: 400000000012FC00
;;   Called from:
;;     400000000011E12C (in compgen_builtin)
strlist_print proc
	{ alloc	r38,ar.pfs,0xC,0x0,0x8; cmp.eq	p09,p08,0x0,r33; mov	r37,b5 }
	{ adds	r36,0xC,r32; cmp.eq	p07,p06,0x0,r32; adds	r39,0x0,r1; }
	{ (p09) addl	r33,1340,r1; nop.m	0x0; adds	r35,0x0,r0 }

l400000000012FC26:
	{ add	r0,r0,r1; (p17) nop; (p32) nop }
	{ chk.a.nc	f0,3FFFFFFFFF130436; nop; (p18) nop }

l400000000012FC40:
	{ (p08) adds	r33,0x0,r33; ld4	r14,[r36]; nop.i	0x0; }

l400000000012FC46:
	{ (p07) fwb; nop; (p18) nop }

l400000000012FC56:
	{ (p03) chk.a.clr	r0,3FFFFFFFFF9F2D36; nop; break.b	0x80000 }

l400000000012FC60:
	{ nop.m	0x0; ld8	r14,[r32]; addl	r41,1348,r1 }
	{ addl	r40,1,r0; adds	r42,0x0,r33; adds	r34,0x1,r34; }
	{ add	r14,r14,r35; ld8	r41,[r41]; adds	r35,0x8,r35; }
	{ ld8	r43,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ ld4	r14,[r36]; nop.m	0x0; adds	r1,0x0,r39; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r34,r14; (p06) br.cond.dptk.few	400000000012FC60 }

l400000000012FCC0:
	{ nop.m	0x0; mov.i	ar.pfs,r38; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r37,400000000012FCD0; br.ret	b0; }
400000000012FCE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012FCF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; strlist_walk: 400000000012FD00
strlist_walk proc
	{ alloc	r38,ar.pfs,0x9,0x0,0x8; adds	r36,0xC,r32; mov	r37,b5 }
	{ cmp.eq	p07,p06,0x0,r32; adds	r39,0x0,r1; (p07) br.cond.dpnt.few	400000000012FDD0; }

l400000000012FD20:
	{ nop.m	0x0; adds	r34,0x0,r0; adds	r35,0x0,r0 }
	{ nop.m	0x0; ld4	r14,[r36]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,0x0,r14; (p06) br.cond.dpnt.few	400000000012FDD0; }

l400000000012FD50:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000012FD60:
	{ ld8	r14,[r32]; nop.m	0x0; adds	r35,0x1,r35; }
	{ add	r14,r14,r34; nop.m	0x0; adds	r34,0x8,r34; }
	{ ld8	r40,[r14]; ld8	r14,[r33],8; nop.i	0x0; }
	{ ld8	r1,[r33],-8; mov.spnt	b6,r14,400000000012FD90; br.call.sptk.many	b0,b6; }
	{ adds	r1,0x0,r39; cmp4.lt	p06,p07,r8,r0; (p06) br.cond.dpnt.few	400000000012FDD0; }

l400000000012FDB0:
	{ nop.m	0x0; ld4	r14,[r36]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r35,r14; (p06) br.cond.dptk.few	400000000012FD60 }

l400000000012FDD0:
	{ nop.m	0x0; mov.i	ar.pfs,r38; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r37,400000000012FDE0; br.ret	b0; }
400000000012FDF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; strlist_sort: 400000000012FE00
strlist_sort proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; adds	r14,0xC,r32; mov	r33,b1 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r35,0x0,r1; (p06) br.cond.dpnt.few	400000000012FE80; }

l400000000012FE20:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000012FE80; }

l400000000012FE40:
	{ nop.m	0x0; ld8	r36,[r32]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r36; nop.i	0x0; (p06) br.cond.dpnt.few	400000000012FE80; }

l400000000012FE60:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strvec_sort; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l400000000012FE80:
	{ nop.m	0x0; mov.i	ar.pfs,r34; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r33,400000000012FE90; br.ret	b0; }
400000000012FEA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000012FEB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; strlist_from_word_list: 400000000012FEC0
strlist_from_word_list proc
	{ alloc	r39,ar.pfs,0xD,0x0,0x9; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r38,b6 }
	{ cmp.eq	p07,p06,0x0,r32; adds	r40,0x0,r1; (p07) br.cond.dpnt.few	400000000012FFB0; }

l400000000012FEE0:
	{ adds	r41,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,list_length; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r37,0x0,r8 }
	{ addl	r41,16,r0; nop.m	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r40; adds	r36,0x0,r8; adds	r43,0x0,r34 }
	{ adds	r41,0x0,r32; adds	r42,0x0,r33; adds	r44,0x10,r12; }
	{ add	r34,r37,r34; nop.i	0x0; br.call.sptk.many	b0,strvec_from_word_list; }
	{ adds	r14,0x0,r36; nop.m	0x0; adds	r16,0x10,r12 }
	{ cmp.eq	p06,p07,0x0,r35; nop.m	0x0; adds	r1,0x0,r40; }
	{ ld4	r15,[r16]; st8	[r14],r8,8; nop.i	0x0 }
	{ adds	r16,0xC,r36; st4	[r15],r16; nop.i	0x0 }
	{ st4	[r34],r14; (p07) st4	[r15],r35; nop.i	0x0 }

l400000000012FF8C:
	{ Invalid; zxt1	r0,r64; (p48) break.i	0x2A809 }

l400000000012FF90:
	{ adds	r8,0x0,r36; mov.i	ar.pfs,r39; mov.spnt	b0,r38,400000000012FF90 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l400000000012FFB0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r35; nop.i	0x0; }
	{ (p06) adds	r36,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	400000000012FF90; }

l400000000012FFC6:
	{ chk.a.nc	r0,3FFFFFFFFF1307C6; nop; nop }

l400000000012FFD0:
	{ adds	r36,0x0,r0; st4	[r0],r35; nop.i	0x0; }
	{ adds	r8,0x0,r36; mov.i	ar.pfs,r39; mov.spnt	b0,r38,400000000012FFE0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

;; strlist_to_word_list: 4000000000130000
strlist_to_word_list proc
	{ alloc	r36,ar.pfs,0x9,0x0,0x6; cmp.eq	p06,p07,0x0,r32; mov	r35,b3 }
	{ adds	r37,0x0,r1; adds	r39,0x0,r33; (p06) br.cond.dpnt.few	4000000000130070; }

l4000000000130020:
	{ ld8	r38,[r32]; nop.m	0x0; adds	r40,0x0,r34; }
	{ cmp.eq	p06,p07,0x0,r38; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000130070; }

l4000000000130040:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strvec_to_word_list; }
	{ adds	r1,0x0,r37; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,4000000000130060; br.ret	b0 }

l4000000000130070:
	{ adds	r8,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,4000000000130080; br.ret	b0; }
4000000000130090 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000001300A0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000001300B0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; strvec_strcmp: 40000000001300C0
strvec_strcmp proc
	{ alloc	r35,ar.pfs,0x7,0x0,0x5; mov	r34,b2; adds	r36,0x0,r1 }
	{ ld8	r37,[r32]; ld8	r38,[r33]; nop.b	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B440; }
	{ adds	r1,0x0,r36; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000130100; br.ret	b0; }
4000000000130110 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000130120 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000130130 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; strvec_create: 4000000000130140
;;   Called from:
;;     40000000000417DC (in tilde_initialize)
;;     400000000004183C (in tilde_initialize)
;;     400000000004189C (in tilde_initialize)
;;     40000000000418EC (in tilde_initialize)
;;     400000000004220C (in get_group_list)
;;     400000000006127C (in fn4000000000061240)
;;     400000000006B61C (in fn400000000006B5C0)
;;     40000000000B33CC (in ignore_glob_matches)
;;     40000000000BCA4C (in array_to_argv)
;;     40000000000C62DC (in brace_expand)
;;     40000000000C9F9C (in fn40000000000C9F00)
;;     40000000000CA2CC (in fn40000000000C9F00)
;;     40000000000DDA8C (in user_command_matches)
;;     400000000010925C (in get_minus_o_opts)
;;     4000000000112A6C (in getopts_builtin)
;;     4000000000113A6C (in get_shopt_options)
;;     400000000012EBDC (in strlist_create)
strvec_create proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; mov	r33,b1; sxt4	r36,r32 }
	{ nop.m	0x0; adds	r35,0x0,r1; nop.b	0x0; }
	{ shladd	r36,r36,0x3,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,4000000000130180; br.ret	b0; }
4000000000130190 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001301A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001301B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; strvec_resize: 40000000001301C0
;;   Called from:
;;     400000000005076C (in shell_execve)
;;     400000000006636C (in add_or_supercede_exported_var)
;;     400000000006655C (in fn4000000000066400)
;;     4000000000069A3C (in maybe_make_export_env)
;;     40000000000C5E9C (in brace_expand)
;;     40000000000CF06C (in fn40000000000CE980)
;;     40000000000DDA3C (in user_command_matches)
;;     4000000000103A4C (in pushd_builtin)
;;     400000000012ED1C (in strlist_resize)
strvec_resize proc
	{ alloc	r35,ar.pfs,0x7,0x0,0x5; mov	r34,b2; sxt4	r38,r33 }
	{ adds	r36,0x0,r1; adds	r37,0x0,r32; nop.b	0x0; }
	{ shladd	r38,r38,0x3,r0; nop.i	0x0; br.call.sptk.many	b0,xrealloc; }
	{ adds	r1,0x0,r36; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000130200; br.ret	b0; }
4000000000130210 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000130220 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000130230 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; strvec_len: 4000000000130240
;;   Called from:
;;     400000000005074C (in shell_execve)
;;     400000000006126C (in fn4000000000061240)
;;     40000000000654EC (in sort_variables)
;;     40000000000B9ACC (in all_aliases)
;;     40000000000C471C (in fn40000000000C46C0)
;;     40000000000C473C (in fn40000000000C46C0)
;;     40000000000C5E4C (in brace_expand)
;;     40000000000C5E6C (in brace_expand)
;;     40000000000E48AC (in completions_to_stringlist)
;;     40000000000E5BBC (in gen_compspec_completions)
strvec_len proc
	{ ld8	r14,[r32]; adds	r8,0x0,r0; adds	r32,0x8,r32; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	4000000000130290; }

l4000000000130260:
	{ ld8	r14,[r32],8; nop.m	0x0; adds	r8,0x1,r8; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000130260 }

l4000000000130280:
	{ nop.m	0x0; nop.i	0x0; br.ret	b0; }

l4000000000130290:
	{ nop.m	0x0; adds	r8,0x0,r0; br.ret	b0; }
40000000001302A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001302B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; strvec_flush: 40000000001302C0
;;   Called from:
;;     400000000006972C (in maybe_make_export_env)
;;     40000000000E3E6C (in clean_itemlist)
;;     400000000012EE8C (in strlist_flush)
;;     40000000001303AC (in strvec_dispose)
strvec_flush proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; mov	r34,b2; cmp.eq	p07,p06,0x0,r32 }
	{ adds	r36,0x0,r1; adds	r33,0x8,r32; (p07) br.cond.dpnt.few	4000000000130330; }

l40000000001302E0:
	{ nop.m	0x0; ld8	r37,[r32]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r37; (p06) br.cond.dpnt.few	4000000000130330; }

l4000000000130300:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ ld8	r37,[r33],8; nop.m	0x0; adds	r1,0x0,r36; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r37; (p06) br.cond.dptk.few	4000000000130300 }

l4000000000130330:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000130340; br.ret	b0; }
4000000000130350 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000130360 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000130370 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; strvec_dispose: 4000000000130380
;;   Called from:
;;     400000000006B75C (in fn400000000006B5C0)
;;     40000000000A80CC (in fn40000000000A7940)
;;     40000000000A89BC (in fn40000000000A7940)
;;     40000000000C660C (in brace_expand)
;;     40000000000C660C (in brace_expand)
;;     40000000000C666C (in brace_expand)
;;     40000000000C666C (in brace_expand)
;;     40000000000D738C (in bash_default_completion)
;;     40000000000E4D7C (in fn40000000000E4B40)
;;     40000000000E4E2C (in fn40000000000E4B40)
;;     40000000000E4EDC (in fn40000000000E4B40)
;;     40000000000E4F8C (in fn40000000000E4B40)
;;     40000000000E503C (in fn40000000000E4B40)
;;     40000000000E50EC (in fn40000000000E4B40)
;;     40000000000E9E1C (in bind_builtin)
;;     40000000000F822C (in exec_builtin)
;;     400000000011E1AC (in compgen_builtin)
;;     400000000011E24C (in compgen_builtin)
;;     400000000012EF0C (in strlist_dispose)
strvec_dispose proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; cmp.eq	p06,p07,0x0,r32; mov	r33,b1 }
	{ adds	r35,0x0,r1; adds	r36,0x0,r32; (p06) br.cond.dpnt.few	40000000001303E0; }

l40000000001303A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strvec_flush; }
	{ nop.m	0x0; adds	r1,0x0,r35; adds	r36,0x0,r32 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l40000000001303E0:
	{ nop.m	0x0; mov.i	ar.pfs,r34; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000001303F0; br.ret	b0; }

;; strvec_remove: 4000000000130400
;;   Called from:
;;     400000000012F00C (in strlist_remove)
strvec_remove proc
	{ alloc	r39,ar.pfs,0xB,0x0,0x9; mov	r38,b6; cmp.eq	p06,p07,0x0,r32 }
	{ adds	r40,0x0,r1; adds	r36,0x8,r32; (p06) br.cond.dpnt.few	40000000001304A0; }

l4000000000130420:
	{ ld8	r34,[r32]; nop.m	0x0; adds	r35,0x0,r0; }
	{ cmp.eq	p06,p07,0x0,r34; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001304A0; }

l4000000000130440:
	{ ld1	r37,[r33]; nop.i	0x0; sxt1	r37,r37; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000130460:
	{ ld1	r14,[r34]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r37; (p07) br.cond.dpnt.few	40000000001304C0 }

l4000000000130480:
	{ ld8	r34,[r36],8; nop.m	0x0; adds	r35,0x1,r35; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	4000000000130460 }

l40000000001304A0:
	{ adds	r8,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000001304B0; br.ret	b0; }

l40000000001304C0:
	{ adds	r42,0x0,r34; adds	r41,0x0,r33; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r40; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	4000000000130480 }

l40000000001304E0:
	{ nop.m	0x0; sxt4	r35,r35; nop.i	0x0; }
	{ shladd	r14,r35,0x3,r32; nop.m	0x0; adds	r35,0x1,r35; }
	{ ld8	r17,[r14]; adds	r16,0x0,r35; shladd	r15,r35,0x3,r32; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r17; (p07) br.cond.dpnt.few	4000000000130570; }

l4000000000130520:
	{ shladd	r17,r35,0x3,r32; nop.m	0x0; adds	r16,0x1,r16; }
	{ ld8	r17,[r17]; nop.m	0x0; adds	r35,0x0,r16; }
	{ st8	[r17],r14; adds	r14,0x0,r15; adds	r15,0x8,r15; }
	{ nop.m	0x0; ld8	r17,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r17; (p06) br.cond.dptk.few	4000000000130520 }

l4000000000130570:
	{ adds	r41,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ addl	r8,1,r0; adds	r1,0x0,r40; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,4000000000130590; br.ret	b0; }
40000000001305A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001305B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; strvec_copy: 40000000001305C0
;;   Called from:
;;     40000000000C495C (in fn40000000000C46C0)
;;     40000000000C499C (in fn40000000000C46C0)
strvec_copy proc
	{ alloc	r38,ar.pfs,0xA,0x0,0x8; ld8	r16,[r32]; nop.b	0x0 }
	{ adds	r15,0x8,r32; mov	r37,b5; adds	r39,0x0,r1; }
	{ cmp.eq	p06,p07,0x0,r16; nop.m	0x0; adds	r14,0x0,r0; }
	{ nop.m	0x0; (p06) addl	r40,8,r0; (p06) br.cond.dpnt.few	4000000000130640; }

l40000000001305FC:
	{ (p02) nop; (p02) mov.i	KR6,0x3; Invalid }

l4000000000130600:
	{ ld8	r16,[r15],8; nop.m	0x0; adds	r14,0x1,r14; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r16; (p06) br.cond.dptk.few	4000000000130600 }

l4000000000130620:
	{ adds	r40,0x1,r14; nop.i	0x0; sxt4	r40,r40; }
	{ shladd	r40,r40,0x3,r0; nop.m	0x0; nop.i	0x0 }

l4000000000130640:
	{ adds	r33,0x8,r32; adds	r34,0x0,r32; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r40,[r32]; nop.m	0x0; adds	r14,0x0,r0 }
	{ adds	r1,0x0,r39; adds	r36,0x0,r8; cmp.eq	p06,p07,0x0,r40; }
	{ nop.m	0x0; (p06) adds	r14,0x0,r0; (p06) br.cond.dpnt.few	40000000001306F0; }

l400000000013067C:
	{ (p04) ldfps	f0,f64,[r33]; zxt1	r73,r0; break.i	0x1000 }

l4000000000130680:
	{ add	r35,r36,r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r39; adds	r40,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ nop.m	0x0; adds	r1,0x0,r39; adds	r40,0x0,r8 }
	{ ld8	r41,[r34]; adds	r34,0x0,r33; br.call.sptk.many	b0,fn400000000001B180; }
	{ st8	[r8],r35; sub	r14,r33,r32; adds	r1,0x0,r39; }
	{ nop.m	0x0; ld8	r40,[r33],8; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r40; (p06) br.cond.dptk.few	4000000000130680 }

l40000000001306F0:
	{ add	r14,r36,r14; adds	r8,0x0,r36; mov.i	ar.pfs,r38; }
	{ st8	[r0],r14; mov.spnt	b0,r37,4000000000130700; br.ret	b0; }
4000000000130710 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000130720 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000130730 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; strvec_sort: 4000000000130740
;;   Called from:
;;     40000000000B375C (in shell_glob_filename)
;;     400000000012FE6C (in strlist_sort)
strvec_sort proc
	{ alloc	r34,ar.pfs,0x8,0x0,0x4; ld8	r15,[r32]; mov	r33,b1 }
	{ adds	r14,0x8,r32; adds	r35,0x0,r1; adds	r36,0x0,r32; }
	{ addl	r37,1,r0; nop.m	0x0; cmp.eq	p06,p07,0x0,r15; }
	{ (p06) adds	r37,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001307C0; }

l4000000000130776:
	{ chk.a.nc	r0,3FFFFFFFFF130F76; nop; nop }

l4000000000130780:
	{ adds	r16,0x1,r37; ld8	r15,[r14],8; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r15; (p07) br.cond.dpnt.few	40000000001307C0; }

l40000000001307A0:
	{ ld8	r15,[r14],8; nop.m	0x0; adds	r37,0x0,r16; }
	{ adds	r16,0x1,r37; cmp.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	40000000001307A0 }

l40000000001307C0:
	{ addl	r39,-9852,r1; nop.m	0x0; addl	r38,8,r0; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C000; }
	{ adds	r1,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000001307F0; br.ret	b0; }

;; strvec_from_word_list: 4000000000130800
;;   Called from:
;;     40000000000EE92C (in make_builtin_argv)
;;     40000000000F7E0C (in exec_builtin)
;;     40000000000F7E0C (in exec_builtin)
;;     400000000012FF3C (in strlist_from_word_list)
strvec_from_word_list proc
	{ alloc	r41,ar.pfs,0xE,0x0,0xC; nop.m	0x0; mov	r43,pr }
	{ adds	r42,0x0,r1; nop.m	0x0; adds	r44,0x0,r32; }
	{ nop.m	0x0; mov	r40,b0; br.call.sptk.many	b0,list_length; }
	{ add	r8,r8,r34,0x1; adds	r1,0x0,r42; sxt4	r44,r8; }
	{ shladd	r44,r44,0x3,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r15,0xFFFFFFFFFFFFFFFF,r34; cmp4.lt	p06,p07,0x0,r34; adds	r14,0x0,r8 }
	{ adds	r1,0x0,r42; adds	r39,0x0,r8; (p07) br.cond.dpnt.few	40000000001308C0; }

l4000000000130870:
	{ nop.m	0x0; (p06) addp4	r15,r15,r0; nop.i	0x0; }

l400000000013087C:
	{ cmp4.eq.or.andcm	p00,p03,r1,r0; zxt1	r3,r4; cmp4.eq.or.andcm	p00,p00,r32,r0 }

l4000000000130886:
	{ adds	r0,0xFFFFFFFFFFFFE000,r1; (p07) nop; break.i	0x80000 }

l4000000000130890:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000001308A0:
	{ nop.m	0x0; st8	[r14],r8,8; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r15,r14; (p06) br.cond.dptk.few	40000000001308A0; }

l40000000001308C0:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; sxt4	r37,r34 }
	{ cmp4.eq	p16,p17,0x0,r33; adds	r36,0x0,r34; (p07) br.cond.dpnt.few	40000000001309A0; }

l40000000001308E0:
	{ (p06) shladd	r37,r37,0x3,r39; nop.m	0x0; nop.i	0x0; }

l40000000001308E6:
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ break.m	0x4000; Invalid; (p32) nop }

l4000000000130900:
	{ adds	r14,0x8,r32; adds	r36,0x1,r36; (p17) adds	r38,0x0,r14; }

l4000000000130910:
	{ nop.m	0x0; (p17) ld8	r14,[r38]; nop.i	0x0; }

l400000000013091C:
	{ Invalid; Invalid; Invalid }

l4000000000130926:
	{ nop; (p32) nop; (p20) nop }

l4000000000130930:
	{ (p17) adds	r1,0x0,r42; (p17) adds	r44,0x1,r8; (p17) br.call.dpnt.many	b0,xmalloc; }

l4000000000130936:
	{ (p22) nop; (p36) nop }

l400000000013093C:
	{ (p28) cmp.le.and	p48,p41,r0,r45; (p01) nop; Invalid }

l4000000000130940:
	{ (p17) ld8	r14,[r38]; (p17) adds	r1,0x0,r42; (p17) adds	r44,0x0,r8; }

l4000000000130946:
	{ Invalid; Invalid; Invalid }

l400000000013094C:
	{ nop; nop; }

l4000000000130950:
	{ (p17) ld8	r45,[r14]; nop.i	0x0; (p17) br.call.dpnt.many	b0,fn400000000001B180; }

l4000000000130956:
	{ nop; (p32) nop; (p36) nop }

l4000000000130960:
	{ (p16) ld8	r14,[r14]; nop.m	0x0; (p17) adds	r1,0x0,r42; }

l4000000000130966:
	{ nop; nop; (p04) nop }

l4000000000130970:
	{ (p16) ld8	r8,[r14]; st8	[r37],r8,8; nop.i	0x0; }

l4000000000130976:
	{ Invalid; nop; break.i	0x80000 }
	{ (p16) fwb; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFDB3B96; nop; nop }

l40000000001309A0:
	{ cmp.eq	p06,p07,0x0,r35; adds	r8,0x0,r39; mov.i	ar.pfs,r41 }
	{ nop.m	0x0; sxt4	r14,r36; nop.b	0x0; }
	{ shladd	r39,r14,0x3,r39; nop.m	0x0; mov.spnt	b0,r40,40000000001309C0; }
	{ nop.m	0x0; st8	[r0],r39; nop.b	0x0 }
	{ (p07) st4	[r36],r35; mov	pr,r43,0xFFFFFFFFFFFFFFFE; br.ret	b0; }

l40000000001309E6:
	{ (p63) rum	0x17F82B; (p34) nop; break.b	0x80000 }
40000000001309F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; strvec_to_word_list: 4000000000130A00
;;   Called from:
;;     400000000013004C (in strlist_to_word_list)
strvec_to_word_list proc
	{ alloc	r39,ar.pfs,0xC,0x0,0xA; adds	r17,0x8,r32; mov	r41,pr }
	{ adds	r40,0x0,r1; cmp.eq	p07,p06,0x0,r32; mov	r38,b6 }
	{ adds	r14,0x0,r0; adds	r15,0x0,r17; (p07) br.cond.dpnt.few	4000000000130C30; }

l4000000000130A30:
	{ nop.m	0x0; ld8	r16,[r32]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r16; (p06) br.cond.dpnt.few	4000000000130C30; }

l4000000000130A50:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000130A60:
	{ ld8	r16,[r15],8; nop.m	0x0; adds	r14,0x1,r14; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r16; (p06) br.cond.dptk.few	4000000000130A60; }

l4000000000130A80:
	{ sub	r37,r14,r34,0x1; sxt4	r15,r34; adds	r36,0x0,r0 }
	{ cmp4.eq	p16,p17,0x0,r33; cmp4.lt	p07,p06,r34,r14; (p06) br.cond.dpnt.few	4000000000130C30; }

l4000000000130AA0:
	{ addp4	r37,r37,r0; nop.m	0x0; shladd	r32,r15,0x3,r32; }
	{ add	r37,r15,r37; nop.i	0x0; shladd	r37,r37,0x3,r17; }

l4000000000130AC0:
	{ nop.m	0x0; addl	r42,-8244,r1; nop.i	0x0; }
	{ ld8	r42,[r42]; nop.i	0x0; (p16) br.cond.dptk.few	4000000000130BA0; }

l4000000000130AE0:
	{ ld8	r42,[r32]; adds	r32,0x8,r32; br.call.sptk.many	b0,make_bare_word; }
	{ adds	r35,0x0,r8; adds	r1,0x0,r40; adds	r43,0x0,r36; }
	{ adds	r42,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,make_word_list; }
	{ nop.m	0x0; adds	r1,0x0,r40; adds	r36,0x0,r8 }
	{ nop.m	0x0; cmp.eq	p07,p06,r37,r32; (p06) br.cond.dptk.few	4000000000130AC0; }

l4000000000130B30:
	{ cmp.eq	p06,p07,0x0,r8; adds	r42,0x0,r8; (p06) br.cond.dpnt.few	4000000000130C30; }

l4000000000130B40:
	{ nop.m	0x0; ld8	r14,[r8]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000130B80; }

l4000000000130B60:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,list_reverse; }
	{ nop.m	0x0; adds	r1,0x0,r40; adds	r36,0x0,r8; }

l4000000000130B80:
	{ adds	r8,0x0,r36; mov	pr,r41,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,4000000000130B90; br.ret	b0; }

l4000000000130BA0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,make_bare_word; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r35,0x0,r8 }
	{ ld8	r42,[r8]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; ld8	r14,[r32]; adds	r1,0x0,r40 }
	{ adds	r32,0x8,r32; adds	r43,0x0,r36; adds	r42,0x0,r35; }
	{ st8	[r14],r35; nop.i	0x0; br.call.sptk.many	b0,make_word_list; }
	{ nop.m	0x0; adds	r1,0x0,r40; adds	r36,0x0,r8 }
	{ nop.m	0x0; cmp.eq	p07,p06,r37,r32; (p06) br.cond.dptk.few	4000000000130AC0 }

l4000000000130C20:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000130B30; }

l4000000000130C30:
	{ adds	r36,0x0,r0; nop.m	0x0; mov	pr,r41,0xFFFFFFFFFFFFFFFE; }
	{ adds	r8,0x0,r36; nop.m	0x0; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,4000000000130C50; br.ret	b0; }
4000000000130C60 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
4000000000130C70 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; spname: 4000000000130C80
;;   Called from:
;;     400000000013138C (in dirspell)
spname proc
	{ alloc	r48,ar.pfs,0x15,0x0,0x12; addl	r17,-8208,r0; nop.i	0x0; }
	{ nop.m	0x0; add	r12,r12,r17; mov	r47,b7 }
	{ adds	r49,0x0,r1; adds	r40,0x0,r33; adds	r38,0x0,r32; }
	{ addl	r14,8209,r0; adds	r46,0x11,r12; nop.i	0x0 }
	{ adds	r41,0x1011,r12; nop.i	0x0; add	r43,r12,r14; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000130CE0:
	{ ld1	r14,[r38]; adds	r15,0x1,r38; adds	r16,0x0,r41; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x2F,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001311E0; }

l4000000000130D10:
	{ ld1.a	r14,[r38]; st1	[r0],r40; nop.i	0x0; }
	{ ld1.c.clr	r14,[r38]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001311F0; }

l4000000000130D40:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2F,r14; (p07) br.cond.dpnt.few	4000000000130DA0; }

l4000000000130D50:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000130D60:
	{ cmp.ltu	p07,p06,r16,r43; nop.m	0x0; adds	r38,0x0,r15; }
	{ (p07) st1	[r16],r1,1; ld1	r14,[r15],1; nop.i	0x0; }

l4000000000130D76:
	{ (p07) mov.m	KR0,0xF; Invalid; break.i	0x80000 }
	{ (p07) add	r0,r14,r20; (p03) nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFE13E76; nop; (p32) br.call.sptk.few	b4,b0 }

l4000000000130DA0:
	{ ld1	r50,[r33]; st1	[r0],r16; addl	r42,3,r0; }
	{ nop.m	0x0; sxt1	r50,r50; cmp4.eq	p06,p07,0x0,r50; }
	{ (p06) addl	r50,-1252,r1; (p07) adds	r50,0x0,r33; nop.i	0x0; }

l4000000000130DC6:
	{ Invalid; nop; (p33) nop; }

l4000000000130DCC:
	{ nop; Invalid; break.i	0x1000 }

l4000000000130DD6:
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; nop; break.b	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFDB4676; nop; (p32) nop }

l4000000000130E00:
	{ adds	r50,0x0,r39; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BC60; }
	{ adds	r37,0x13,r8; adds	r1,0x0,r49; cmp.eq	p07,p06,0x0,r8 }
	{ adds	r16,0x14,r8; adds	r15,0x1012,r12; (p07) br.cond.dpnt.few	4000000000130F20; }

l4000000000130E30:
	{ ld1	r14,[r37]; ld1	r34,[r41]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; sxt1	r34,r34; }
	{ cmp4.eq	p07,p06,r34,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000131020; }

l4000000000130E60:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	4000000000130ED0; }

l4000000000130E70:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000130E80:
	{ adds	r36,0x0,r16; nop.m	0x0; adds	r35,0x0,r15 }
	{ ld1	r14,[r16],1; ld1	r34,[r15],1; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; sxt1	r34,r34; }
	{ cmp4.eq	p06,p07,r34,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000131040; }

l4000000000130EC0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	4000000000130E80 }

l4000000000130ED0:
	{ nop.m	0x0; adds	r14,0x0,r0; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r42,r14; (p06) br.cond.dptk.few	4000000000130E00 }

l4000000000130EF0:
	{ adds	r42,0x0,r14; adds	r50,0x10,r12; nop.i	0x0 }
	{ adds	r51,0x0,r37; addl	r52,4097,r0; br.call.sptk.many	b0,fn400000000001BAE0; }
	{ adds	r1,0x0,r49; cmp4.eq	p06,p07,0x0,r42; (p07) br.cond.dptk.few	4000000000130E00 }

l4000000000130F20:
	{ adds	r50,0x0,r39; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C300; }
	{ adds	r15,0x10,r12; adds	r1,0x0,r49; cmp4.eq	p08,p09,0x3,r42; }
	{ ld1	r14,[r15]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r14; (p07) br.cond.dpnt.few	4000000000130FD0; }

l4000000000130F60:
	{ cmp4.eq	p06,p07,0x0,r14; adds	r16,0x0,r46; (p08) br.cond.spnt.few	4000000000130FF0; }

l4000000000130F70:
	{ st1	[r14],r40; adds	r14,0x1,r40; (p06) br.cond.dpnt.few	4000000000130CE0; }

l4000000000130F80:
	{ ld1	r15,[r16],1; adds	r40,0x0,r14; sxt1	r15,r15; }
	{ st1	[r14],r1,1; cmp4.eq	p07,p06,0x0,r15; (p07) br.cond.dpnt.few	4000000000130CE0; }

l4000000000130FA0:
	{ ld1	r15,[r16],1; adds	r40,0x0,r14; sxt1	r15,r15; }
	{ st1	[r14],r1,1; cmp4.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	4000000000130F80 }

l4000000000130FC0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000130CE0 }

l4000000000130FD0:
	{ ld1	r15,[r46]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p07) br.cond.dptk.few	4000000000130F60 }

l4000000000130FF0:
	{ addl	r8,-1,r0; nop.m	0x0; mov.i	ar.pfs,r48; }
	{ nop.m	0x0; mov.spnt	b0,r47,4000000000131000; addl	r19,8208,r0; }
	{ nop.m	0x0; add	r12,r12,r19; br.ret	b0 }

l4000000000131020:
	{ nop.m	0x0; adds	r36,0x0,r37; adds	r35,0x0,r41; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000131040:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000131140; }

l4000000000131050:
	{ adds	r44,0x1,r36; cmp4.eq	p07,p06,0x0,r34; (p07) br.cond.dptk.few	4000000000131110; }

l4000000000131060:
	{ ld1	r15,[r44]; adds	r45,0x1,r35; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	40000000001310C0 }

l4000000000131080:
	{ ld1	r16,[r45]; nop.m	0x0; sxt1	r16,r16; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r16; (p06) br.cond.dptk.few	40000000001310C0; }

l40000000001310A0:
	{ nop.m	0x0; cmp4.eq	p07,p06,r16,r14; (p07) br.cond.dpnt.few	4000000000131180; }

l40000000001310B0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000001310C0:
	{ adds	r51,0x0,r45; adds	r50,0x0,r44; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r49; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dpnt.few	4000000000131110 }

l40000000001310E0:
	{ addl	r14,2,r0; nop.m	0x0; nop.i	0x0; }

l40000000001310F0:
	{ nop.m	0x0; cmp4.lt	p06,p07,r42,r14; (p06) br.cond.dptk.few	4000000000130E00 }

l4000000000131100:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000130EF0 }

l4000000000131110:
	{ adds	r50,0x0,r44; adds	r51,0x0,r35; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r49; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	40000000001310E0; }

l4000000000131130:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000131140:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r34; (p06) br.cond.dptk.few	4000000000130E00 }

l4000000000131150:
	{ adds	r50,0x0,r36; adds	r51,0x1,r35; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r49; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	4000000000130E00 }

l4000000000131170:
	{ nop.m	0x0; addl	r14,2,r0; br.cond.sptk.few	40000000001310F0; }

l4000000000131180:
	{ nop.m	0x0; cmp4.eq	p07,p06,r15,r34; (p06) br.cond.dptk.few	40000000001310C0 }

l4000000000131190:
	{ adds	r50,0x2,r36; adds	r51,0x2,r35; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r49; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	40000000001310C0 }

l40000000001311B0:
	{ nop.m	0x0; addl	r14,1,r0; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r42,r14; (p06) br.cond.dptk.few	4000000000130E00 }

l40000000001311D0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000130EF0 }

l40000000001311E0:
	{ st1	[r40],r1,1; adds	r38,0x1,r38; br.cond.sptk.few	4000000000130CE0 }

l40000000001311F0:
	{ adds	r15,0x1,r32; adds	r14,0x1,r33; adds	r50,0x0,r32 }
	{ adds	r51,0x0,r33; ld1	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r15; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000131290; }

l4000000000131230:
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000131290; }

l4000000000131250:
	{ ld1	r14,[r32]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x2E,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000131290; }

l4000000000131270:
	{ ld1	r14,[r33]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2E,r14; (p06) br.cond.dpnt.few	4000000000130FF0 }

l4000000000131290:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ cmp4.eq	p07,p06,0x0,r8; nop.m	0x0; adds	r1,0x0,r49; }
	{ (p06) addl	r8,1,r0; (p07) adds	r8,0x0,r0; mov.i	ar.pfs,r48; }

l40000000001312B6:
	{ Invalid; Invalid; break.i	0x80000; }

l40000000001312BC:
	{ Invalid; break.i	0x1000; (p48) nop }
	{ Invalid; add	r0,r32,r0; (p01) shladd	r99,r4,0x1,r0 }
	{ nop; break.m	0x1000; break.i	0x1000 }
40000000001312E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001312F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; dirspell: 4000000000131300
;;   Called from:
;;     40000000000EC27C (in cd_builtin)
dirspell proc
	{ alloc	r35,ar.pfs,0x7,0x0,0x5; nop.m	0x0; mov	r34,b2 }
	{ adds	r36,0x0,r1; nop.m	0x0; adds	r37,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ shladd	r8,r8,0x1,r8; adds	r1,0x0,r36; adds	r37,0x1,r8; }
	{ nop.m	0x0; extr	r37,r37,1,63; adds	r37,0x1,r37; }
	{ nop.m	0x0; sxt4	r37,r37; br.call.sptk.many	b0,fn400000000001B340; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r33,0x0,r8; adds	r1,0x0,r36 }
	{ adds	r37,0x0,r32; adds	r38,0x0,r8; (p06) br.cond.dpnt.few	40000000001313E0; }

l4000000000131380:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,spname; }
	{ nop.m	0x0; adds	r37,0x0,r33; adds	r1,0x0,r36 }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x1,r8; (p07) br.cond.dptk.few	40000000001313E0 }

l40000000001313B0:
	{ nop.m	0x0; adds	r33,0x0,r0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r36; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000001313E0:
	{ adds	r8,0x0,r33; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000001313F0; br.ret	b0; }

;; sh_single_quote: 4000000000131400
;;   Called from:
;;     400000000002D1EC (in fn400000000002AC80)
;;     400000000002F7FC (in fn400000000002D840)
;;     40000000000346DC (in fn4000000000030880)
;;     40000000000346DC (in fn4000000000030880)
;;     400000000004832C (in xtrace_print_assignment)
;;     400000000004864C (in xtrace_print_word_list)
;;     400000000006195C (in print_var_value)
;;     40000000000BD2EC (in array_to_assign)
;;     40000000000C370C (in assoc_to_assign)
;;     40000000000E66BC (in gen_compspec_completions)
;;     40000000000E902C (in fn40000000000E9000)
;;     400000000010151C (in mapfile_builtin)
;;     400000000010DD4C (in fn400000000010DBC0)
;;     400000000010F28C (in describe_command)
;;     400000000011B9EC (in fn400000000011B780)
;;     400000000011BA8C (in fn400000000011B780)
;;     400000000011BB2C (in fn400000000011B780)
;;     400000000011BBCC (in fn400000000011B780)
;;     400000000011BC6C (in fn400000000011B780)
;;     400000000011BD0C (in fn400000000011B780)
sh_single_quote proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x5; adds	r37,0x0,r32; mov	r33,b1 }
	{ nop.m	0x0; adds	r35,0x0,r1; nop.i	0x0; }
	{ nop.m	0x0; mov	r36,LC; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ shladd	r37,r8,0x2,r0; nop.m	0x0; adds	r1,0x0,r35; }
	{ adds	r37,0x3,r37; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ addl	r15,39,r0; adds	r14,0x0,r8; adds	r1,0x0,r35 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r17,0x1,r32; addl	r20,92,r0; }
	{ st1	[r14],r1,1; nop.m	0x0; sub	r18,r0,r17 }
	{ addl	r21,39,r0; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000131500; }

l4000000000131490:
	{ ld1	r16,[r32]; mov.i	LC,r18; sxt1	r16,r16; }
	{ cmp4.eq	p06,p07,0x0,r16; adds	r15,0x0,r16; (p06) br.cond.dpnt.few	4000000000131500; }

l40000000001314B0:
	{ cmp4.eq	p06,p07,0x27,r16; st1	[r15],r14; nop.i	0x0; }
	{ (p06) adds	r19,0x1,r14; (p06) adds	r18,0x2,r14; (p06) adds	r15,0x3,r14 }

l40000000001314C6:
	{ Invalid; (p07) cmp.eq.or	p03,p02,0xE,r0; (p33) nop; }

l40000000001314CC:
	{ (p01) cmp4.eq.and	p14,p42,r0,r66; (p17) mov	pr,r3,0x8480; Invalid; }

l40000000001314D0:
	{ (p07) adds	r14,0x1,r14; (p06) st1	[r20],r19; (p06) adds	r14,0x4,r14 }

l40000000001314D6:
	{ chk.a.nc	r20,3FFFFFFFFF9F1606; (p07) nop; add	r0,r0,r32; }

l40000000001314DC:
	{ (p02) nop; mov	pr,r32,0x0; Invalid; }

l40000000001314E0:
	{ nop.m	0x0; (p06) st1	[r16],r18; nop.i	0x0; }

l40000000001314EC:
	{ Invalid; Invalid; nop }

l40000000001314F6:
	{ add	r0,r0,r1; (p02) nop; (p48) nop }

l4000000000131500:
	{ addl	r15,39,r0; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ st1	[r14],r1,1; nop.m	0x0; mov.i	LC,r36; }
	{ st1	[r0],r14; mov.spnt	b0,r33,4000000000131520; br.ret	b0 }

l4000000000131530:
	{ ld1	r16,[r17],1; nop.m	0x0; sxt1	r16,r16; }
	{ cmp4.eq	p07,p06,0x0,r16; adds	r15,0x0,r16; (p07) br.cond.dpnt.few	4000000000131500; }

l4000000000131550:
	{ cmp4.eq	p06,p07,0x27,r16; st1	[r15],r14; nop.i	0x0; }
	{ (p06) adds	r19,0x1,r14; (p06) adds	r18,0x2,r14; (p06) adds	r15,0x3,r14 }

l4000000000131566:
	{ Invalid; (p07) cmp.eq.or	p03,p02,0xE,r0; (p33) nop; }

l400000000013156C:
	{ (p01) cmp4.eq.and	p14,p42,r0,r66; (p17) mov	pr,r3,0x8480; Invalid; }

l4000000000131570:
	{ (p07) adds	r14,0x1,r14; (p06) st1	[r20],r19; (p06) adds	r14,0x4,r14 }

l4000000000131576:
	{ chk.a.nc	r20,3FFFFFFFFF9F16A6; (p07) nop; add	r0,r0,r32; }

l400000000013157C:
	{ (p02) nop; mov	pr,r32,0x0; Invalid; }

l4000000000131580:
	{ nop.m	0x0; (p06) st1	[r16],r18; nop.i	0x0; }

l400000000013158C:
	{ Invalid; Invalid; nop }

l4000000000131596:
	{ add	r0,r0,r1; (p02) nop; break.i	0x80000 }

l40000000001315A0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000131500; }
40000000001315B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; sh_double_quote: 40000000001315C0
;;   Called from:
;;     40000000000BCCCC (in array_to_assign)
;;     40000000000C30BC (in assoc_to_assign)
;;     40000000000C35EC (in assoc_to_assign)
;;     400000000010B35C (in show_var_attributes)
sh_double_quote proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x5; adds	r37,0x0,r32; mov	r33,b1 }
	{ nop.m	0x0; adds	r35,0x0,r1; nop.i	0x0; }
	{ nop.m	0x0; mov	r36,LC; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ shladd	r37,r8,0x1,r0; nop.m	0x0; adds	r1,0x0,r35; }
	{ adds	r37,0x3,r37; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ addl	r14,34,r0; adds	r15,0x0,r8; adds	r1,0x0,r35 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r17,0x1,r32; addl	r21,1,r0; }
	{ nop.m	0x0; st1	[r15],r1,1; sub	r18,r0,r17 }
	{ addl	r19,-18556,r1; addl	r20,92,r0; (p06) br.cond.dpnt.few	4000000000131700; }

l4000000000131650:
	{ nop.m	0x0; ld1	r16,[r32]; mov.i	LC,r18 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r16,r16; zxt1	r14,r16; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.m	0x0; sxt4	r18,r14 }
	{ cmp4.eq	p10,p11,0xA,r14; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000131700; }

l40000000001316A0:
	{ shladd	r18,r18,0x2,r19; nop.m	0x0; cmp4.eq	p07,p06,0x7F,r14; }
	{ cmp4.eq.or.andcm	p07,p06,0x1,r14; ld4	r14,[r18]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p08,p09,r14,0x6; (p08) br.cond.dptk.few	40000000001317A0; }

l40000000001316D0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000001316E0:
	{ nop.m	0x0; (p11) st1	[r15],r1,1; nop.i	0x0; }

l40000000001316EC:
	{ nop; Invalid; nop }
	{ (p02) cmp.lt	p00,p09,r0,r32; zxt4	r8,r0; break.i	0x1000 }

l4000000000131700:
	{ addl	r14,34,r0; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ st1	[r15],r1,1; nop.m	0x0; mov.i	LC,r36; }
	{ st1	[r0],r15; mov.spnt	b0,r33,4000000000131720; br.ret	b0 }

l4000000000131730:
	{ nop.m	0x0; ld1	r16,[r17],1; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r16,r16; zxt1	r14,r16; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.m	0x0; sxt4	r18,r14 }
	{ cmp4.eq	p10,p11,0xA,r14; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000131700; }

l4000000000131770:
	{ shladd	r18,r18,0x2,r19; nop.m	0x0; cmp4.eq	p07,p06,0x7F,r14; }
	{ cmp4.eq.or.andcm	p07,p06,0x1,r14; ld4	r14,[r18]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p08,p09,r14,0x6; (p09) br.cond.dptk.few	40000000001316E0 }

l40000000001317A0:
	{ nop.m	0x0; (p07) st1	[r15],r1,1; nop.i	0x0; }

l40000000001317AC:
	{ nop; Invalid; nop }
	{ Invalid; break.i	0x1000; break.i	0x1000 }

l40000000001317C0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000131700; }
40000000001317D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001317E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001317F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; sh_mkdoublequoted: 4000000000131800
;;   Called from:
;;     400000000002D02C (in fn400000000002AC80)
;;     400000000002EA8C (in fn400000000002D840)
;;     400000000003439C (in fn4000000000030880)
sh_mkdoublequoted proc
	{ alloc	r36,ar.pfs,0x7,0x0,0x6; cmp4.eq	p07,p06,0x0,r34; nop.b	0x0 }
	{ add	r38,r33,r33,0x1; mov	r35,b3; adds	r37,0x0,r1; }
	{ nop.m	0x0; (p07) adds	r38,0x3,r33; nop.i	0x0; }

l400000000013182C:
	{ Invalid; cmp.lt	p00,p00,r32,r0; (p04) break.i	0x164C0 }
	{ (p36) cmp.lt.unc	p46,p08,r62,r44; (p33) cmp.eq	p08,p18,r0,r0; (p01) epc }
	{ nop; czx1.r	r64,r98; (p02) nop }
	{ nop; (p32) cmp.lt.unc	p35,p10,r3,r96; Invalid }
	{ nop.m	0x80; cmp.lt	p00,p00,r32,r0; (p01) break.i	0x141C0 }
	{ Invalid; cmp.lt	p00,p00,r32,r0; mov	pr,r99,0xE680 }
	{ (p04) nop; break.i	0x1000; break.i	0x1000 }

l4000000000131890:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.i	0x0; (p08) br.cond.dptk.few	40000000001318D0; }

l40000000001318B0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x22,r14; nop.i	0x0; }
	{ (p07) st1	[r15],r1,1; nop.m	0x0; nop.i	0x0 }

l40000000001318C6:
	{ break.m	0x4000; nop; (p32) nop }

l40000000001318D0:
	{ ld1	r14,[r32],1; st1	[r15],r1,1; nop.i	0x0; }

l40000000001318D2:
	{ cmp.lt	p08,p16,r0,r10; nop }

l40000000001318D6:
	{ Invalid; nop; (p32) br.call.sptk.few	b3,b0 }

l40000000001318D8:
	{ (p01) break.m	0x560; (p16) nop; break.b	0x8002 }

l40000000001318DE:
	{ break.m	0xE0160; (p04) nop }

l40000000001318E4:
	{ break.m	0x100002; nop; break.i	0x80 }

l40000000001318EE:
	{ (p02) break.m	0x200; Invalid; Invalid }

l40000000001318F4:
	{ nop; (p12) nop; Invalid; }

l40000000001318FE:
	{ Invalid; Invalid; Invalid }

l4000000000131900:
	{ addl	r14,34,r0; nop.m	0x0; mov.i	ar.pfs,r36; }

l4000000000131904:
	{ (p32) break.m	0x100004; Invalid; (p01) nop }

l4000000000131908:
	{ Invalid; Invalid; (p60) break.i	0xAC00 }
	{ (p16) nop; break.i	0x11070; (p60) break.i	0x8C00 }
	{ (p16) nop; (p16) break.i	0x8008; break.i	0x8 }
4000000000131930 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; sh_un_double_quote: 4000000000131940
sh_un_double_quote proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; nop.m	0x0; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; adds	r36,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r35; adds	r36,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r35; cmp.eq	p06,p07,0x0,r32; adds	r14,0x0,r32 }
	{ adds	r17,0x0,r8; adds	r18,0x0,r0; (p06) br.cond.dpnt.few	4000000000131AC0; }

l40000000001319A0:
	{ ld1	r16,[r32]; addl	r19,-18556,r1; sxt1	r16,r16 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ adds	r15,0x0,r16; cmp4.eq	p06,p07,0x0,r16; (p06) br.cond.dpnt.few	4000000000131AC0; }

l40000000001319D0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000001319E0:
	{ cmp4.eq	p06,p07,0x0,r18; (p07) st1	[r17],r1,1; (p07) adds	r18,0x0,r0 }

l40000000001319EC:
	{ nop; cmp4.eq.and	p00,p32,r32,r0; (p17) mov	pr,r3,0x8480 }

l40000000001319F0:
	{ nop.m	0x0; (p07) adds	r14,0x1,r14; (p07) br.cond.dptk.few	4000000000131A30; }

l40000000001319FC:
	{ (p02) nop; cmp.lt	p00,p00,r32,r0; (p17) cmp.eq.unc	p00,p16,r3,r64 }

l4000000000131A00:
	{ nop.m	0x0; adds	r14,0x1,r14; cmp4.eq	p07,p06,0x5C,r16 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000131A80; }

l4000000000131A20:
	{ st1	[r17],r1,1; nop.m	0x0; nop.i	0x0 }

l4000000000131A30:
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000131A60; }

l4000000000131A40:
	{ ld1	r16,[r14]; nop.m	0x0; sxt1	r16,r16; }
	{ adds	r15,0x0,r16; cmp4.eq	p07,p06,0x0,r16; (p06) br.cond.dptk.few	40000000001319E0 }

l4000000000131A60:
	{ st1	[r0],r17; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,4000000000131A70; br.ret	b0 }

l4000000000131A80:
	{ ld1	r16,[r14]; shladd	r16,r16,0x2,r19; nop.i	0x0; }
	{ ld4	r16,[r16]; nop.m	0x0; tbit.z	p07,p06,r16,0x6; }
	{ nop.m	0x0; (p06) addl	r18,1,r0; (p06) br.cond.dptk.few	4000000000131A30 }

l4000000000131AAC:
	{ (p60) nop; Invalid; break.b	0x1000 }

l4000000000131AB0:
	{ st1	[r17],r1,1; nop.i	0x0; br.cond.sptk.few	4000000000131A30; }

l4000000000131AC0:
	{ adds	r17,0x0,r8; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ st1	[r0],r17; mov.spnt	b0,r33,4000000000131AD0; br.ret	b0; }
4000000000131AE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000131AF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; sh_backslash_quote: 4000000000131B00
sh_backslash_quote proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x5; nop.m	0x0; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; adds	r37,0x0,r32; }
	{ nop.m	0x0; mov	r36,LC; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r35; add	r37,r8,r8,0x1; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r35; cmp.eq	p06,p07,0x0,r32; andcm	r17,0xFFFFFFFFFFFFFFFF,r32 }
	{ adds	r15,0x0,r32; adds	r16,0x0,r8; (p06) br.cond.dpnt.few	4000000000131CC0; }

l4000000000131B60:
	{ ld1	r14,[r32]; addl	r19,-796,r1; nop.b	0x0 }
	{ addl	r20,92,r0; mov.i	LC,r17; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	4000000000131CC0; }

l4000000000131B90:
	{ ld8	r19,[r19]; nop.m	0x0; nop.i	0x0; }

l4000000000131BA0:
	{ adds	r17,0xFFFFFFFFFFFFFFF7,r14; nop.m	0x0; zxt1	r17,r17; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x74,r17; (p06) br.cond.dptk.few	4000000000131C10 }

l4000000000131BC0:
	{ shladd	r17,r17,0x3,r19; ld8	r18,[r17]; nop.i	0x0; }
	{ nop.m	0x0; add	r17,r17,r18; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r17,4000000000131BE0; br.cond	b6; }
4000000000131BF0 09 00 00 00 01 00 70 00 3D 0C 70 00 00 00 04 00 ......p.=.p.....
4000000000131C00 E9 08 50 20 80 15 00 00 00 02 00 00 00 00 04 00 ..P ............

l4000000000131C10:
	{ st1	[r16],r1,1; adds	r15,0x1,r15; br.cloop.sptk.few	4000000000131C40; }

l4000000000131C20:
	{ st1	[r0],r16; mov.i	ar.pfs,r34; mov.i	LC,r36; }
	{ nop.m	0x0; mov.spnt	b0,r33,4000000000131C30; br.ret	b0 }

l4000000000131C40:
	{ ld1	r14,[r15]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000131BA0 }

l4000000000131C60:
	{ st1	[r0],r16; mov.i	ar.pfs,r34; mov.i	LC,r36; }
	{ nop.m	0x0; mov.spnt	b0,r33,4000000000131C70; br.ret	b0 }
4000000000131C80 09 88 00 20 00 21 F0 08 3C 00 42 00 22 80 00 84 ... .!..<.B."...
4000000000131C90 09 00 00 00 01 00 10 A0 44 00 2B 00 00 00 04 00 ........D.+.....
4000000000131CA0 10 00 38 22 80 11 00 00 00 02 00 A0 A0 FF FF 48 ..8"...........H
4000000000131CB0 10 00 00 00 01 00 00 00 00 02 00 00 70 FF FF 48 ............p..H

l4000000000131CC0:
	{ adds	r16,0x0,r8; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ st1	[r0],r16; nop.m	0x0; mov.i	LC,r36; }
	{ nop.m	0x0; mov.spnt	b0,r33,4000000000131CE0; br.ret	b0; }
4000000000131CF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; sh_backslash_quote_for_double_quotes: 4000000000131D00
sh_backslash_quote_for_double_quotes proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x5; nop.m	0x0; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; adds	r37,0x0,r32; }
	{ nop.m	0x0; mov	r36,LC; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r35; add	r37,r8,r8,0x1; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r35; cmp.eq	p06,p07,0x0,r32; adds	r17,0x1,r32 }
	{ adds	r15,0x0,r8; addl	r21,1,r0; (p06) br.cond.dpnt.few	4000000000131E90; }

l4000000000131D60:
	{ ld1	r16,[r32]; sub	r14,r0,r17; addl	r19,-18556,r1 }
	{ addl	r20,92,r0; nop.m	0x0; sxt1	r16,r16 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r14; zxt1	r14,r16; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	4000000000131E90; }

l4000000000131DB0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; sxt4	r18,r14; cmp4.eq	p07,p06,0x7F,r14; }
	{ shladd	r18,r18,0x2,r19; nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x1,r14; }
	{ ld4	r14,[r18]; nop.m	0x0; tbit.z	p08,p09,r14,0x6; }
	{ (p09) st1	[r15],r1,1; nop.i	0x0; (p09) br.cond.dptk.few	4000000000131E10; }

l4000000000131DF6:
	{ nop; cmp4.ltu	p02,p33,r0,r0; (p17) nop }

l4000000000131E00:
	{ (p07) st1	[r15],r1,1; nop.m	0x0; nop.i	0x0; }

l4000000000131E06:
	{ break.m	0x4000; nop; (p16) nop }

l4000000000131E10:
	{ st1	[r15],r1,1; nop.i	0x0; br.cloop.sptk.few	4000000000131E40; }

l4000000000131E12:
	{ (p50) break.m	0x2B003; nop; break.i	0xA0000 }

l4000000000131E16:
	{ add	r0,r0,r1; Invalid; nop }

l4000000000131E18:
	{ (p16) srlz.d; break.i	0x3400; (p60) nop }

l4000000000131E28:
	{ (p40) nop; (p40) break.i	0x1000A; break.i	0x100008; }

l4000000000131E2E:
	{ (p05) break.m	0x200; Invalid; Invalid }

l4000000000131E34:
	{ rum	0x10000; (p14) break.i	0x108800; (p01) break.i	0x48; }

l4000000000131E40:
	{ nop.m	0x0; ld1	r16,[r17],1; nop.i	0x0; }

l4000000000131E44:
	{ Invalid; (p32) break.i	0x100002; break.i	0x18; }
	{ nop; Invalid; break.i	0x80; }
	{ nop; (p12) nop; (p21) nop; }
	{ (p12) ld1.c.clr	r2,[r8],128; Invalid; (p01) break.i	0x80 }
	{ rum	0x10000; (p14) break.i	0x108800; (p01) nop; }

l4000000000131E90:
	{ adds	r15,0x0,r8; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ st1	[r0],r15; nop.m	0x0; mov.i	LC,r36; }
	{ nop.m	0x0; mov.spnt	b0,r33,4000000000131EB0; br.ret	b0; }

;; sh_contains_shell_metas: 4000000000131EC0
;;   Called from:
;;     40000000000482FC (in xtrace_print_assignment)
;;     400000000004861C (in xtrace_print_word_list)
;;     40000000000617FC (in print_var_value)
;;     40000000000C305C (in assoc_to_assign)
sh_contains_shell_metas proc
	{ cmp.eq	p06,p07,0x0,r32; mov	r2,LC; addl	r17,-788,r1 }
	{ andcm	r16,0xFFFFFFFFFFFFFFFF,r32; adds	r14,0x0,r32; (p06) br.cond.dpnt.few	4000000000131FB0; }

l4000000000131EE0:
	{ ld1	r15,[r32]; mov.i	LC,r16; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dpnt.few	4000000000131FB0; }

l4000000000131F00:
	{ ld8	r17,[r17]; nop.m	0x0; nop.i	0x0 }

l4000000000131F10:
	{ adds	r15,0xFFFFFFFFFFFFFFF7,r15; nop.m	0x0; zxt1	r15,r15; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x75,r15; (p06) br.cond.dptk.few	4000000000131FA0 }

l4000000000131F30:
	{ shladd	r15,r15,0x3,r17; ld8	r16,[r15]; nop.i	0x0; }
	{ nop.m	0x0; add	r15,r15,r16; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r15,4000000000131F50; br.cond	b6; }
4000000000131F60 11 78 FC 1D 3F 23 60 00 39 0E 70 03 C0 00 00 43 .x..?#`.9.p....C
4000000000131F70 0B 78 00 1E 00 10 00 00 00 02 00 E0 01 78 50 00 .x...........xP.
4000000000131F80 11 30 F4 1E 87 39 00 00 00 02 00 03 A0 00 00 43 .0...9.........C
4000000000131F90 10 00 00 00 01 00 60 D0 3D 0E 73 03 90 00 00 43 ......`.=.s....C

l4000000000131FA0:
	{ nop.m	0x0; adds	r14,0x1,r14; br.cloop.sptk.few	4000000000131FD0 }

l4000000000131FB0:
	{ adds	r8,0x0,r0; nop.m	0x0; nop.i	0x0; }

l4000000000131FC0:
	{ nop.m	0x0; mov.i	LC,r2; br.ret	b0 }

l4000000000131FD0:
	{ ld1	r15,[r14]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	4000000000131F10 }

l4000000000131FF0:
	{ nop.m	0x0; adds	r8,0x0,r0; br.cond.sptk.few	4000000000131FC0; }
4000000000132000 11 00 00 00 01 00 60 00 39 0E F0 03 A0 FF FF 4A ......`.9......J
4000000000132010 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000132020 11 40 04 00 00 24 00 10 04 55 00 80 08 00 84 00 .@...$...U......
4000000000132030 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; ansicstr: 4000000000132040
;;   Called from:
;;     40000000000F289C (in echo_builtin)
;;     40000000001331BC (in ansiexpand)
ansicstr proc
	{ alloc	r52,ar.pfs,0x1A,0x0,0x18; mov	r54,pr; nop.b	0x0 }
	{ cmp.eq	p06,p07,0x0,r32; shladd	r56,r33,0x2,r0; addl	r43,1180,r1; }
	{ adds	r53,0x0,r1; adds	r56,0x1,r56; mov	r51,b3 }
	{ addl	r44,1,r0; addl	r46,92,r0; cmp.eq	p18,p19,0x0,r35; }
	{ addl	r49,512,r0; addl	r48,383,r0; mov	r55,LC }
	{ addl	r41,4096,r0; sxt4	r56,r56; (p06) br.cond.dpnt.few	40000000001322C0; }

l40000000001320A0:
	{ ld1	r14,[r32]; addl	r47,255,r0; addl	r45,255,r0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001322C0; }

l40000000001320D0:
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r53; adds	r40,0x0,r8; adds	r37,0x0,r8; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000132100:
	{ ld1	r14,[r32]; adds	r15,0x1,r32; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000132150; }

l4000000000132120:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5C,r14; (p07) br.cond.dpnt.few	40000000001321B0 }

l4000000000132130:
	{ adds	r32,0x0,r15; st1	[r37],r1,1; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r32; (p07) br.cond.dptk.few	4000000000132100; }

l4000000000132150:
	{ st1	[r0],r37; nop.m	0x0; sub	r37,r37,r40 }
	{ cmp.eq	p06,p07,0x0,r36; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000132180; }

l4000000000132170:
	{ st4	[r37],r36; nop.m	0x0; nop.i	0x0 }

l4000000000132180:
	{ adds	r8,0x0,r40; nop.m	0x0; mov	pr,r54,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r52; mov.i	LC,r55; }
	{ nop.m	0x0; mov.spnt	b0,r51,40000000001321A0; br.ret	b0 }

l40000000001321B0:
	{ ld1	r16,[r15]; nop.m	0x0; sxt1	r16,r16; }
	{ adds	r38,0x0,r16; cmp4.eq	p07,p06,0x0,r16; (p07) br.cond.dptk.few	4000000000132130 }

l40000000001321D0:
	{ adds	r14,0xFFFFFFFFFFFFFFDE,r16; adds	r39,0x2,r32; adds	r50,0x0,r16; }
	{ nop.m	0x0; zxt1	r14,r14; adds	r42,0x0,r39; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x56,r14; (p07) br.cond.dptk.few	4000000000132290; }

l4000000000132200:
	{ nop.m	0x0; tbit.z	p06,p07,r34,0x2; (p07) br.cond.dptk.few	4000000000132220 }

l4000000000132210:
	{ st1	[r37],r1,1; nop.m	0x0; nop.i	0x0 }

l4000000000132220:
	{ adds	r32,0x0,r39; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; tnat.z	p16,p17,r34; nop.i	0x0 }
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dptk.few	4000000000132270; }

l4000000000132250:
	{ cmp4.eq	p07,p06,0x7F,r50; nop.i	0x0; cmp4.eq.or.andcm	p07,p06,0x1,r50; }
	{ (p07) st1	[r37],r1,1; nop.m	0x0; nop.i	0x0; }

l4000000000132266:
	{ break.m	0x4000; nop; (p16) nop }

l4000000000132270:
	{ st1	[r37],r1,1; cmp.eq	p06,p07,0x0,r32; (p07) br.cond.dptk.few	4000000000132100 }

l4000000000132272:
	{ Invalid; nop; (p61) clrrrb }

l4000000000132276:
	{ (p03) chk.a.clr	f0,3FFFFFFFFFDB5C76; nop; break.i	0x80000 }

l400000000013227C:
	{ (p52) invala; break.i	0x1000; break.b	0x1000 }
	{ (p54) cmp.lt.unc	p63,p11,r63,r36; (p33) cmp.eq.unc	p35,p16,r74,r4; (p01) rfi }

l4000000000132290:
	{ shladd	r14,r14,0x3,r43; ld8	r15,[r14]; nop.i	0x0; }

l4000000000132292:
	{ Invalid; (p32) break.m	0x20303; cover }
	{ cmp4.eq.and	p32,p32,r0,r0; (p49) break.i	0x40003; Invalid }
	{ cmp.eq.and	p32,p32,r0,r0; (p17) cmp.lt	p00,p00,r112,r0; dep	r0,r8,r32,63,3 }

l40000000001322C0:
	{ adds	r40,0x0,r0; nop.m	0x0; mov	pr,r54,0xFFFFFFFFFFFFFFFE; }
	{ adds	r8,0x0,r40; mov.i	ar.pfs,r52; mov.i	LC,r55; }
	{ nop.m	0x0; mov.spnt	b0,r51,40000000001322E0; br.ret	b0 }
40000000001322F0 18 00 01 4E 00 21 60 42 00 00 48 00 00 00 00 20 ...N.!`B..H.... 
4000000000132300 10 90 21 00 00 24 00 11 88 22 28 00 40 FF FF 48 ..!..$..."(.@..H
4000000000132310 00 00 00 00 01 00 60 00 88 0E 28 00 00 00 04 00 ......`...(.....
4000000000132320 16 00 00 00 00 C8 04 08 04 80 A1 03 E0 FE FF 4A ...............J
4000000000132330 0B 70 00 4E 00 10 00 00 00 02 00 C0 01 70 50 00 .p.N.........pP.
4000000000132340 10 50 01 1C 00 21 70 00 38 0C F3 03 C0 FE FF 4A .P...!p.8......J
4000000000132350 18 00 00 00 01 00 20 03 38 00 42 00 00 00 00 20 ...... .8.B.... 
4000000000132360 11 30 0D 40 00 21 00 11 88 22 28 08 20 00 00 42 .0.@.!..."(. ..B
4000000000132370 10 00 00 00 01 00 70 E0 3A 0C F3 03 20 07 00 43 ......p.:... ..C
4000000000132380 11 00 00 00 01 00 70 02 A8 28 00 00 48 A0 EE 58 ......p..(..H..X
4000000000132390 03 70 00 10 18 10 10 00 D4 00 42 C0 71 72 40 80 .p........B.qr@.
40000000001323A0 0B 70 00 1C 08 10 E0 88 39 18 40 00 00 00 04 00 .p......9.@.....
40000000001323B0 10 00 00 00 01 00 60 00 38 0E 73 03 60 07 00 42 ......`.8.s.`..B
40000000001323C0 0B 50 01 54 01 21 60 80 A9 0E 69 00 00 00 04 00 .P.T.!`...i.....
40000000001323D0 10 00 00 00 01 80 01 01 C8 00 42 03 40 00 00 42 ..........B.@..B
40000000001323E0 11 00 00 00 01 00 00 00 00 02 00 00 68 7F EE 58 ............h..X
40000000001323F0 02 70 00 10 18 10 10 00 D4 00 42 E0 74 72 44 80 .p........B.trD.
4000000000132400 0B 00 00 00 01 00 00 01 9C 20 20 00 00 00 04 00 .........  .....
4000000000132410 09 90 7D 20 2C 20 00 00 00 02 00 00 04 30 01 84 ..} , .......0..
4000000000132420 11 00 00 00 01 00 60 02 C8 00 42 00 20 FE FF 48 ......`...B. ..H
4000000000132430 18 00 01 4E 00 21 60 62 00 00 48 00 00 00 00 20 ...N.!`b..H.... 
4000000000132440 11 90 31 00 00 24 00 11 88 22 28 00 00 FE FF 48 ..1..$..."(....H
4000000000132450 18 00 01 4E 00 21 60 52 00 00 48 00 00 00 00 20 ...N.!`R..H.... 
4000000000132460 11 90 29 00 00 24 00 11 88 22 28 00 E0 FD FF 48 ..)..$..."(....H
4000000000132470 18 00 01 4E 00 21 60 6A 00 00 48 00 00 00 00 20 ...N.!`j..H.... 
4000000000132480 11 90 35 00 00 24 00 11 88 22 28 00 C0 FD FF 48 ..5..$..."(....H
4000000000132490 18 00 01 4E 00 21 60 4A 00 00 48 00 00 00 00 20 ...N.!`J..H.... 
40000000001324A0 11 90 25 00 00 24 00 11 88 22 28 00 A0 FD FF 48 ..%..$..."(....H
40000000001324B0 18 00 01 4E 00 21 60 5A 00 00 48 00 00 00 00 20 ...N.!`Z..H.... 
40000000001324C0 10 90 2D 00 00 24 00 11 88 22 28 00 80 FD FF 48 ..-..$..."(....H
40000000001324D0 09 38 01 4E 00 10 00 00 00 02 00 E0 20 10 19 50 .8.N........ ..P
40000000001324E0 11 00 00 00 01 00 70 02 9C 28 80 03 40 00 00 42 ......p..(..@..B
40000000001324F0 0B 38 EC 4F 86 F9 A1 1A 80 00 C2 43 04 11 B9 80 .8.O.......C....
4000000000132500 E3 70 00 54 00 10 00 00 00 02 80 C3 01 70 50 00 .p.T.........pP.
4000000000132510 E8 38 01 1C 00 21 00 00 00 02 00 00 00 00 04 00 .8...!..........
4000000000132520 11 00 00 00 01 00 00 00 00 02 00 00 A8 9E EE 58 ...............X
4000000000132530 08 00 00 00 01 00 10 00 D4 00 42 00 00 00 04 00 ..........B.....
4000000000132540 08 90 00 10 18 10 10 11 00 00 48 00 02 00 00 84 ..........H.....
4000000000132550 01 00 00 00 01 00 E0 00 9C 20 00 00 04 50 01 84 ......... ...P..
4000000000132560 09 00 00 00 01 00 F0 70 48 20 40 00 00 00 04 00 .......pH @.....
4000000000132570 0B 78 00 1E 08 10 F0 48 3D 18 40 00 00 00 04 00 .x.....H=.@.....
4000000000132580 11 30 00 1E 87 39 F0 F8 38 7E 46 03 90 03 00 43 .0...9..8~F....C
4000000000132590 11 38 00 22 86 39 F0 00 3C 20 80 03 00 04 00 43 .8.".9..< .....C
40000000001325A0 09 30 14 1E 87 35 00 00 00 02 00 00 02 01 4C 80 .0...5........L.
40000000001325B0 10 00 00 00 01 C0 71 4A 9D 7E C6 03 40 00 00 42 ......qJ.~..@..B
40000000001325C0 09 00 00 00 01 00 E0 F8 39 7E 46 00 00 00 04 00 ........9~F.....
40000000001325D0 03 00 00 00 01 00 E0 00 38 20 00 C0 50 70 1C D6 ........8 ..Pp..
40000000001325E0 E3 38 25 4F 3F 23 00 00 00 02 00 E3 04 3D FD 8C .8%O?#.......=..
40000000001325F0 09 50 05 54 00 21 00 81 9C 00 40 20 F2 8F FC 8C .P.T.!....@ ....
4000000000132600 09 00 00 00 01 00 70 02 A8 00 20 00 00 00 04 00 ......p... .....
4000000000132610 10 00 00 00 01 00 70 02 9C 28 00 00 40 FF FF 48 ......p..(..@..H
4000000000132620 10 00 00 00 01 00 70 00 88 0C A8 03 00 FC FF 4A ......p........J
4000000000132630 11 08 B8 4A 80 15 00 00 00 02 00 00 F0 FB FF 48 ...J...........H
4000000000132640 11 00 00 00 01 00 60 00 88 0E 28 03 10 01 00 43 ......`...(....C
4000000000132650 09 00 00 00 01 00 60 80 41 0E 73 00 00 00 04 00 ......`.A.s.....
4000000000132660 C2 88 04 00 00 24 00 00 00 02 80 23 02 00 00 84 .....$.....#....
4000000000132670 09 70 00 4E 00 10 00 00 00 02 00 00 02 95 FD 8C .p.N............
4000000000132680 03 00 00 00 01 00 E0 00 38 28 00 C0 01 75 FC 8C ........8(...u..
4000000000132690 03 00 00 00 01 00 F0 00 38 20 00 C0 70 78 1C D6 ........8 ..px..
40000000001326A0 D1 00 01 4E 00 21 00 00 00 02 00 03 80 00 00 43 ...N.!.........C
40000000001326B0 09 78 0C 40 00 21 00 00 00 02 00 20 12 88 00 84 .x.@.!..... ....
40000000001326C0 09 88 44 00 08 20 00 00 00 02 00 E0 74 7A 14 80 ..D.. ......tz..
40000000001326D0 03 88 9C 22 01 20 00 00 00 02 00 00 10 09 AA 00 ...". ..........
40000000001326E0 09 00 01 1E 00 21 10 09 3C 00 28 00 02 71 48 80 .....!..<.(..qH.
40000000001326F0 03 00 00 00 01 00 E0 00 44 28 00 C0 01 75 FC 8C ........D(...u..
4000000000132700 01 00 00 00 01 00 10 01 38 20 00 00 00 00 04 00 ........8 ......
4000000000132710 12 30 1C 22 87 B5 01 08 00 80 21 A0 D0 FF FF 48 .0."......!....H
4000000000132720 09 90 B5 20 0C 20 00 00 00 02 00 00 22 10 45 50 ... . ......".EP
4000000000132730 10 00 00 00 01 00 60 02 C8 28 00 00 10 FB FF 48 ......`..(.....H
4000000000132740 10 00 00 00 01 00 60 00 88 0E A8 03 D0 FA FF 4A ......`........J
4000000000132750 11 00 00 00 01 00 10 01 00 00 42 00 20 FF FF 48 ..........B. ..H
4000000000132760 18 00 01 4E 00 21 60 DA 00 00 48 00 00 00 00 20 ...N.!`...H.... 
4000000000132770 11 90 6D 00 00 24 00 11 88 22 28 00 D0 FA FF 48 ..m..$..."(....H
4000000000132780 11 88 D4 21 90 39 00 00 00 02 00 00 48 9C EE 58 ...!.9......H..X
4000000000132790 08 8A 20 00 00 24 00 00 00 02 00 20 00 A8 01 84 .. ..$..... ....
40000000001327A0 03 98 00 10 18 10 80 03 00 00 C2 28 42 00 00 90 ...........(B...
40000000001327B0 03 00 00 00 01 00 E0 00 44 2C 00 00 E0 08 AA 00 ........D,......
40000000001327C0 09 00 01 4E 00 21 F0 08 9C 00 28 00 00 00 04 00 ...N.!....(.....
40000000001327D0 03 00 00 00 01 00 F0 00 3C 28 00 C0 01 78 40 00 ........<(...x@.
40000000001327E0 0B 90 38 26 10 20 20 01 48 10 20 00 00 00 04 00 ..8&.  .H. .....
40000000001327F0 09 00 00 00 01 00 20 49 49 18 40 00 00 00 04 00 ...... II.@.....
4000000000132800 11 30 00 24 87 39 00 00 00 02 00 03 20 00 00 43 .0.$.9...... ..C
4000000000132810 10 00 00 00 01 00 10 F9 47 7E 46 A0 70 00 00 40 ........G~F.p..@
4000000000132820 0B 72 20 00 00 64 E4 20 00 00 48 00 00 00 04 00 .r ..d. ..H.....
4000000000132830 0A 38 44 1C 86 38 00 00 00 02 80 03 22 10 45 50 .8D..8......".EP
4000000000132840 F9 08 B8 4A 80 15 00 00 00 02 80 03 00 FA FF 4B ...J...........K
4000000000132850 08 30 BC 70 07 34 20 03 E0 00 42 00 22 10 45 50 .0.p.4 ...B.".EP
4000000000132860 11 00 00 00 01 00 60 02 E0 28 00 03 60 02 00 43 ......`..(..`..C
4000000000132870 10 00 00 00 01 00 00 00 00 02 00 00 D0 F9 FF 48 ...............H
4000000000132880 03 90 7C 1C 3F 23 80 C3 01 26 40 40 02 90 40 00 ..|.?#...&@@..@.
4000000000132890 0B 30 14 24 87 F5 F1 48 3D 7E 46 00 00 00 04 00 .0.$...H=~F.....
40000000001328A0 10 00 00 00 01 C0 F1 00 3C 2C 80 03 40 00 00 42 ........<,..@..B
40000000001328B0 0B 70 FC 1C 3F 23 00 00 00 02 00 C0 01 70 40 00 .p..?#.......p@.
40000000001328C0 0B 30 14 1C 87 F5 F1 48 3E 7E 46 00 00 00 04 00 .0.....H>~F.....
40000000001328D0 C3 78 40 1F 3F 23 00 00 00 02 00 E0 01 78 58 00 .x@.?#.......xX.
40000000001328E0 10 00 00 00 01 00 80 7B E0 00 40 00 E0 FE FF 48 .......{..@....H
40000000001328F0 18 00 01 4E 00 21 60 3A 00 00 48 00 00 00 00 20 ...N.!`:..H.... 
4000000000132900 10 90 1D 00 00 24 00 11 88 22 28 00 40 F9 FF 48 .....$..."(.@..H
4000000000132910 11 00 00 00 01 00 70 40 88 0C A8 03 40 00 00 42 ......p@....@..B
4000000000132920 09 90 B5 20 0C 20 60 E8 9F 0E 73 40 F4 16 B1 88 ... . `...s@....
4000000000132930 08 00 00 00 01 80 01 0A 80 00 42 C0 04 90 51 00 ..........B...Q.
4000000000132940 10 00 00 00 01 00 00 11 88 22 28 00 00 F9 FF 48 ........."(....H
4000000000132950 09 00 00 00 01 00 60 10 44 0E 73 00 00 00 04 00 ......`.D.s.....
4000000000132960 D1 08 B8 4A 80 95 21 C3 03 00 48 03 D0 F8 FF 4B ...J..!...H....K
4000000000132970 09 90 B5 20 0C 20 00 00 00 02 00 00 22 10 45 50 ... . ......".EP
4000000000132980 10 00 00 00 01 00 60 02 C8 28 00 00 C0 F8 FF 48 ......`..(.....H
4000000000132990 10 00 00 00 01 00 70 40 88 0C A8 03 E0 FF FF 4A ......p@.......J
40000000001329A0 09 78 04 54 00 21 00 00 00 02 00 00 00 00 04 00 .x.T.!..........
40000000001329B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001329C0 09 88 7C 1C 3F 23 00 00 00 02 00 00 02 01 4C 80 ..|.?#........L.
40000000001329D0 03 00 00 00 01 00 10 01 44 20 00 C0 50 88 1C D6 ........D ..P...
40000000001329E0 11 00 00 00 01 C0 E1 48 9D 7E C6 03 40 00 00 42 .......H.~..@..B
40000000001329F0 09 00 00 00 01 00 E0 F8 39 7E 46 00 00 00 04 00 ........9~F.....
4000000000132A00 03 00 00 00 01 00 E0 00 38 20 00 C0 50 70 1C D6 ........8 ..Pp..
4000000000132A10 E3 70 24 4F 3F 23 00 00 00 02 00 C3 01 3D FD 8C .p$O?#.......=..
4000000000132A20 09 00 01 1E 00 21 70 0A 3C 00 28 00 02 71 00 80 .....!p.<.(..q..
4000000000132A30 03 00 00 00 01 00 70 02 9C 28 00 C0 01 38 41 00 ......p..(...8A.
4000000000132A40 0B 88 38 24 10 20 10 01 44 10 20 00 00 00 04 00 ..8$. ..D. .....
4000000000132A50 09 00 00 00 01 00 10 49 45 18 40 00 00 00 04 00 .......IE.@.....
4000000000132A60 11 00 00 00 01 00 70 00 44 0C 73 03 60 FF FF 4A ......p.D.s.`..J
4000000000132A70 09 90 B5 20 0C 20 60 E8 9F 0E 73 40 F4 16 B1 88 ... . `...s@....
4000000000132A80 D1 00 05 40 00 21 60 02 C8 28 00 00 C0 FE FF 48 ...@.!`..(.....H
4000000000132A90 09 00 00 00 01 00 E0 00 98 00 20 00 00 00 04 00 .......... .....
4000000000132AA0 03 00 00 00 01 00 E0 00 38 28 00 E0 C0 75 18 E6 ........8(...u..
4000000000132AB0 10 00 00 00 01 C0 61 22 80 00 42 00 D0 F8 FF 48 ......a"..B....H
4000000000132AC0 11 C8 01 4A 00 21 00 00 00 02 00 00 C8 46 00 50 ...J.!.......F.P
4000000000132AD0 00 00 00 00 01 00 80 00 20 2C 00 20 00 A8 01 84 ........ ,. ....
4000000000132AE0 19 00 00 00 01 00 60 00 80 0E 72 00 00 00 00 20 ......`...r.... 
4000000000132AF0 10 00 00 00 01 00 50 2A 21 00 C0 03 10 F6 FF 4A ......P*!......J
4000000000132B00 10 00 00 00 01 00 00 00 00 02 00 00 50 F6 FF 48 ............P..H
4000000000132B10 09 80 7C 4E 2C 20 00 00 00 02 00 00 04 30 01 84 ..|N, .......0..
4000000000132B20 10 90 01 20 00 21 60 02 40 00 42 00 20 F7 FF 48 ... .!`.@.B. ..H
4000000000132B30 09 70 04 00 00 24 00 00 00 02 00 C0 00 20 1D E4 .p...$....... ..
4000000000132B40 08 00 38 46 90 11 00 00 94 00 23 A0 54 42 15 80 ..8F......#.TB..
4000000000132B50 19 00 00 00 01 00 00 00 00 02 00 03 30 F6 FF 4B ............0..K
4000000000132B60 11 00 94 48 90 11 00 00 00 02 00 00 20 F6 FF 48 ...H........ ..H
4000000000132B70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; ansic_quote: 4000000000132B80
;;   Called from:
;;     40000000000307AC (in yyerror)
;;     400000000004843C (in xtrace_print_assignment)
;;     400000000004882C (in xtrace_print_word_list)
;;     40000000000618CC (in print_var_value)
ansic_quote proc
	{ alloc	r44,ar.pfs,0xF,0x0,0xE; mov	r43,b3; cmp.eq	p06,p07,0x0,r32 }
	{ adds	r45,0x0,r1; adds	r46,0x0,r32; (p06) br.cond.dpnt.few	4000000000132F50; }

l4000000000132BA0:
	{ ld1	r14,[r32]; addl	r42,16384,r0; addl	r39,92,r0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000132F50; }

l4000000000132BD0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r8,0x1,r8; adds	r1,0x0,r45; shladd	r46,r8,0x2,r0; }
	{ nop.m	0x0; sxt4	r46,r46; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r45; adds	r14,0x0,r8; addl	r15,36,r0 }
	{ ld1.a	r35,[r32]; adds	r40,0x0,r8; adds	r36,0x2,r8; }
	{ st1	[r14],r1,1; addl	r15,39,r0; addl	r41,1188,r1; }
	{ st1	[r15],r14; ld1.c.clr	r35,[r32]; adds	r32,0x1,r32; }
	{ nop.m	0x0; sxt1	r35,r35; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r35; (p06) br.cond.dpnt.few	4000000000132D80; }

l4000000000132C60:
	{ ld8	r41,[r41]; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000132C80:
	{ nop.m	0x0; zxt1	r38,r35; nop.i	0x0; }
	{ adds	r14,0xFFFFFFFFFFFFFFF9,r38; adds	r37,0x0,r38; zxt1	r14,r14; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x55,r14; (p07) br.cond.dptk.few	4000000000132DE0 }

l4000000000132CB0:
	{ nop.m	0x0; zxt1	r37,r37; br.call.sptk.many	b0,fn400000000001C3C0; }
	{ ld8	r14,[r8]; adds	r1,0x0,r45; shladd	r37,r37,0x1,r14; }
	{ ld2	r14,[r37]; and	r14,r42,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000132E30 }

l4000000000132CF0:
	{ nop.m	0x0; adds	r14,0x0,r36; extr.u	r17,r38,3,3 }
	{ and	r35,0x7,r35; adds	r16,0x2,r36; extr	r38,r38,6,58; }
	{ st1	[r14],r1,1; adds	r15,0x3,r36; adds	r35,0x30,r35 }
	{ adds	r38,0x30,r38; adds	r17,0x30,r17; adds	r36,0x4,r36; }
	{ st1	[r38],r14; st1	[r17],r16; nop.i	0x0; }
	{ st1	[r35],r15; ld1	r35,[r32],1; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r35,r35; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	4000000000132C80; }

l4000000000132D70:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000132D80:
	{ addl	r14,39,r0; nop.m	0x0; cmp.eq	p06,p07,0x0,r34; }
	{ st1	[r36],r1,1; st1	[r0],r36; sub	r36,r36,r40 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000132DC0; }

l4000000000132DB0:
	{ st4	[r36],r34; nop.m	0x0; nop.i	0x0 }

l4000000000132DC0:
	{ adds	r8,0x0,r40; nop.m	0x0; mov.i	ar.pfs,r44; }
	{ nop.m	0x0; mov.spnt	b0,r43,4000000000132DD0; br.ret	b0 }

l4000000000132DE0:
	{ shladd	r14,r14,0x3,r41; ld8	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; add	r14,r14,r15; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r14,4000000000132E00; br.cond	b6; }
4000000000132E10 08 18 C9 01 00 24 00 00 00 02 00 00 00 00 04 00 .....$..........
4000000000132E20 09 08 9C 48 80 15 00 00 00 02 00 00 00 00 04 00 ...H............

l4000000000132E30:
	{ st1	[r36],r1,1; ld1	r35,[r32],1; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r35,r35; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	4000000000132C80 }

l4000000000132E60:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000132D80 }
4000000000132E70 08 00 00 00 01 00 30 2A 02 00 48 00 00 00 04 00 ......0*..H.....
4000000000132E80 19 08 9C 48 80 15 00 00 00 02 00 00 B0 FF FF 48 ...H...........H
4000000000132E90 08 00 00 00 01 00 30 32 03 00 48 00 00 00 04 00 ......02..H.....
4000000000132EA0 19 08 9C 48 80 15 00 00 00 02 00 00 90 FF FF 48 ...H...........H
4000000000132EB0 08 00 00 00 01 00 30 B2 03 00 48 00 00 00 04 00 ......0...H.....
4000000000132EC0 19 08 9C 48 80 15 00 00 00 02 00 00 70 FF FF 48 ...H........p..H
4000000000132ED0 08 00 00 00 01 00 30 72 03 00 48 00 00 00 04 00 ......0r..H.....
4000000000132EE0 19 08 9C 48 80 15 00 00 00 02 00 00 50 FF FF 48 ...H........P..H
4000000000132EF0 08 00 00 00 01 00 30 A2 03 00 48 00 00 00 04 00 ......0...H.....
4000000000132F00 19 08 9C 48 80 15 00 00 00 02 00 00 30 FF FF 48 ...H........0..H
4000000000132F10 08 00 00 00 01 00 30 12 03 00 48 00 00 00 04 00 ......0...H.....
4000000000132F20 19 08 9C 48 80 15 00 00 00 02 00 00 10 FF FF 48 ...H...........H
4000000000132F30 08 00 00 00 01 00 30 0A 03 00 48 00 00 00 04 00 ......0...H.....
4000000000132F40 18 08 9C 48 80 15 00 00 00 02 00 00 F0 FE FF 48 ...H...........H

l4000000000132F50:
	{ adds	r40,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r44; }
	{ adds	r8,0x0,r40; mov.spnt	b0,r43,4000000000132F60; br.ret	b0; }
4000000000132F70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; ansic_shouldquote: 4000000000132F80
;;   Called from:
;;     400000000003041C (in yyerror)
;;     40000000000483FC (in xtrace_print_assignment)
;;     400000000004871C (in xtrace_print_word_list)
;;     400000000006188C (in print_var_value)
ansic_shouldquote proc
	{ alloc	r35,ar.pfs,0x5,0x0,0x5; mov	r34,b2; nop.i	0x0 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r36,0x0,r1; (p06) br.cond.dpnt.few	4000000000133030; }

l4000000000132FA0:
	{ ld1	r33,[r32]; nop.m	0x0; adds	r32,0x1,r32; }
	{ cmp4.eq	p06,p07,0x0,r33; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000133030; }

l4000000000132FC0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C3C0; }
	{ adds	r1,0x0,r36; ld8	r16,[r8]; addl	r15,16384,r0; }

l4000000000132FE0:
	{ nop.m	0x0; zxt1	r33,r33; shladd	r33,r33,0x1,r16; }
	{ ld2	r14,[r33]; and	r14,r15,r14; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000133050; }

l4000000000133010:
	{ nop.m	0x0; ld1	r33,[r32],1; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	4000000000132FE0 }

l4000000000133030:
	{ adds	r8,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000133040; br.ret	b0 }

l4000000000133050:
	{ addl	r8,1,r0; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000133060; br.ret	b0; }
4000000000133070 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; ansiexpand: 4000000000133080
;;   Called from:
;;     400000000002D1BC (in fn400000000002AC80)
;;     400000000002F7BC (in fn400000000002D840)
;;     40000000000346AC (in fn4000000000030880)
;;     40000000000346AC (in fn4000000000030880)
ansiexpand proc
	{ alloc	r39,ar.pfs,0xF,0x0,0xA; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ sub	r37,r34,r33; adds	r40,0x0,r1; mov	r38,b6; }
	{ adds	r42,0x1,r37; adds	r37,0xFFFFFFFFFFFFFFFF,r37; mov	r41,LC; }
	{ nop.m	0x0; sxt4	r42,r42; addp4	r37,r37,r0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r14,0x0,r8; adds	r1,0x0,r40; mov.i	LC,r37 }
	{ adds	r36,0x0,r8; cmp4.lt	p07,p06,r33,r34; sxt4	r15,r33; }
	{ nop.m	0x0; add	r32,r32,r15; (p06) br.cond.dpnt.few	4000000000133220; }

l4000000000133100:
	{ nop.m	0x0; ld1	r15,[r32],1; nop.i	0x0; }
	{ st1	[r14],r1,1; nop.i	0x0; br.cloop.sptk.few	4000000000133100 }

l4000000000133120:
	{ sub	r43,r34,r33; nop.i	0x0; sxt4	r14,r43; }

l4000000000133130:
	{ add	r14,r36,r14; cmp.eq	p06,p07,0x0,r35; adds	r8,0x0,r36; }
	{ st1	[r0],r14; nop.m	0x0; (p06) adds	r8,0x0,r36; }

l4000000000133150:
	{ ld1	r14,[r36]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p08,p09,0x0,r14; nop.i	0x0; (p09) br.cond.dpnt.few	40000000001331A0; }

l4000000000133170:
	{ (p07) st4	[r0],r35; mov.i	ar.pfs,r39; mov.i	LC,r41; }

l4000000000133176:
	{ break.m	0xAA027; break.i	0xAA0A9; break.i	0x80000 }
	{ Invalid; nop; nop }
	{ break.m	0x4000; (p34) nop; nop }

l40000000001331A0:
	{ addl	r44,2,r0; adds	r45,0x0,r0; nop.i	0x0 }
	{ adds	r46,0x0,r35; adds	r42,0x0,r36; br.call.sptk.many	b0,ansicstr; }
	{ adds	r14,0x10,r12; adds	r1,0x0,r40; adds	r42,0x0,r36; }
	{ st8	[r8],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r14,0x10,r12; nop.m	0x0; adds	r1,0x0,r40; }
	{ ld8	r8,[r14]; mov.i	ar.pfs,r39; mov.i	LC,r41; }
	{ nop.m	0x0; mov.spnt	b0,r38,4000000000133200; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l4000000000133220:
	{ adds	r14,0x0,r0; adds	r43,0x0,r0; br.cond.sptk.few	4000000000133130; }
4000000000133230 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; mailstat: 4000000000133240
;;   Called from:
;;     40000000000AAD8C (in fn40000000000AAD40)
;;     40000000000AB18C (in fn40000000000AAEC0)
;;     40000000000ABD1C (in check_mail)
;;     40000000000ABE1C (in check_mail)
;;     40000000000ABF4C (in check_mail)
mailstat proc
	{ alloc	r51,ar.pfs,0x1B,0x0,0x15; addl	r17,-16672,r0; nop.i	0x0; }
	{ nop.m	0x0; add	r12,r12,r17; mov	r50,b2 }
	{ adds	r52,0x0,r1; adds	r54,0x0,r32; adds	r55,0x0,r33; }
	{ addl	r53,1,r0; nop.m	0x0; addl	r35,61440,r0 }
	{ addl	r36,16384,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AFE0; }
	{ adds	r14,0x18,r33; adds	r1,0x0,r52; nop.i	0x0 }
	{ adds	r34,0x0,r8; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dpnt.few	40000000001332D0; }

l40000000001332B0:
	{ ld4	r37,[r14]; and	r14,r35,r37; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,r36,r14; (p06) br.cond.dpnt.few	4000000000133300 }

l40000000001332D0:
	{ adds	r8,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r51; }
	{ nop.m	0x0; mov.spnt	b0,r50,40000000001332E0; addl	r19,16672,r0; }
	{ nop.m	0x0; add	r12,r12,r19; br.ret	b0; }

l4000000000133300:
	{ adds	r53,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ addl	r14,8187,r0; nop.m	0x0; adds	r1,0x0,r52 }
	{ adds	r54,0x0,r33; nop.m	0x0; addl	r55,144,r0; }
	{ cmp.ltu	p07,p06,r14,r8; addl	r14,16544,r0; (p07) br.cond.dpnt.few	4000000000133910; }

l4000000000133340:
	{ add	r53,r12,r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ adds	r1,0x0,r52; addl	r15,8208,r0; nop.i	0x0 }
	{ addl	r54,1,r0; addl	r55,8192,r0; adds	r57,0x0,r32; }
	{ addl	r56,-6348,r1; nop.m	0x0; add	r53,r12,r15; }
	{ ld8	r56,[r56]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C440; }
	{ addl	r16,8208,r0; nop.m	0x0; addl	r17,16400,r0 }
	{ adds	r1,0x0,r52; nop.m	0x0; addl	r53,1,r0; }
	{ add	r54,r12,r16; add	r55,r12,r17; br.call.sptk.many	b0,fn400000000001AFE0; }
	{ addl	r15,16424,r0; nop.m	0x0; adds	r1,0x0,r52 }
	{ cmp4.eq	p07,p06,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	40000000001332D0; }

l40000000001333E0:
	{ add	r15,r15,r12; ld4	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; and	r14,r35,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r36,r14; (p06) br.cond.dptk.few	40000000001332D0 }

l4000000000133410:
	{ addl	r16,8208,r0; addl	r56,-6340,r1; addl	r54,1,r0 }
	{ addl	r55,8192,r0; adds	r57,0x0,r32; add	r53,r12,r16 }
	{ ld8	r56,[r56]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C440; }
	{ addl	r14,16400,r0; nop.m	0x0; addl	r17,8208,r0 }
	{ adds	r1,0x0,r52; nop.m	0x0; addl	r53,1,r0; }
	{ add	r55,r12,r14; add	r54,r12,r17; br.call.sptk.many	b0,fn400000000001AFE0; }
	{ addl	r15,16424,r0; nop.m	0x0; adds	r1,0x0,r52 }
	{ cmp4.eq	p07,p06,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	40000000001332D0; }

l4000000000133490:
	{ add	r15,r15,r12; ld4	r14,[r15]; addl	r15,16384,r0; }
	{ nop.m	0x0; and	r14,r35,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r15,r14; (p06) br.cond.dptk.few	40000000001332D0 }

l40000000001334C0:
	{ addl	r16,8208,r0; addl	r56,-6332,r1; addl	r54,1,r0 }
	{ addl	r55,8192,r0; adds	r57,0x0,r32; add	r53,r12,r16 }
	{ ld8	r56,[r56]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C440; }
	{ addl	r14,16400,r0; nop.m	0x0; addl	r17,8208,r0 }
	{ adds	r1,0x0,r52; nop.m	0x0; addl	r53,1,r0; }
	{ add	r55,r12,r14; add	r54,r12,r17; br.call.sptk.many	b0,fn400000000001AFE0; }
	{ addl	r15,16424,r0; nop.m	0x0; adds	r1,0x0,r52 }
	{ cmp4.eq	p07,p06,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	40000000001332D0; }

l4000000000133540:
	{ nop.m	0x0; add	r15,r15,r12; nop.i	0x0; }
	{ ld4	r14,[r15]; and	r35,r35,r14; addl	r14,16384,r0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r35; (p06) br.cond.dptk.few	40000000001332D0 }

l4000000000133570:
	{ addl	r14,21540,r1; addl	r17,16400,r0; addl	r16,16472,r0; }
	{ nop.m	0x0; add	r17,r17,r12; add	r44,r12,r16; }
	{ ld8	r16,[r17]; ld8	r45,[r44]; nop.i	0x0; }
	{ nop.m	0x0; ld8	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r15,r16; (p07) br.cond.dpnt.few	4000000000133830 }

l40000000001335C0:
	{ addl	r53,21540,r1; addl	r14,16400,r0; addl	r55,144,r0 }
	{ adds	r46,0x0,r0; adds	r43,0x0,r0; adds	r41,0x0,r0; }
	{ add	r54,r12,r14; nop.m	0x0; adds	r42,0x0,r0 }
	{ adds	r40,0x0,r0; addl	r39,8191,r0; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ adds	r1,0x0,r52; addl	r15,16448,r0; addl	r16,16456,r0; }
	{ addl	r58,-6356,r1; add	r49,r12,r15; nop.i	0x0 }
	{ add	r48,r12,r16; ld8	r58,[r58]; nop.i	0x0 }

l4000000000133630:
	{ addl	r17,8208,r0; addl	r56,-6324,r1; adds	r57,0x0,r32 }
	{ addl	r54,1,r0; addl	r55,8192,r0; add	r53,r12,r17 }
	{ ld8	r56,[r56]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C440; }
	{ adds	r1,0x0,r52; addl	r14,8208,r0; nop.i	0x0 }
	{ addl	r54,1,r0; addl	r55,8192,r0; adds	r53,0x10,r12; }
	{ addl	r56,-6316,r1; nop.m	0x0; add	r57,r12,r14; }
	{ ld8	r56,[r56]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C440; }
	{ adds	r1,0x0,r52; adds	r53,0x10,r12; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ addl	r15,8208,r0; adds	r1,0x0,r52; adds	r38,0x0,r8; }
	{ add	r53,r12,r15; sxt4	r38,r38; br.call.sptk.many	b0,fn400000000001C3E0; }
	{ adds	r14,0x10,r12; adds	r36,0x0,r8; nop.i	0x0 }
	{ adds	r1,0x0,r52; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	40000000001332D0; }

l40000000001336F0:
	{ add	r47,r14,r38; nop.m	0x0; nop.i	0x0; }

l4000000000133700:
	{ adds	r53,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BC60; }
	{ adds	r35,0x13,r8; nop.m	0x0; adds	r1,0x0,r52 }
	{ cmp.eq	p07,p06,0x0,r8; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000133960; }

l4000000000133730:
	{ ld1	r14,[r35]; adds	r53,0x0,r35; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x2E,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000133700; }

l4000000000133750:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ add	r14,r8,r38; nop.m	0x0; adds	r1,0x0,r52; }
	{ nop.m	0x0; cmp.ltu	p06,p07,r39,r14; (p06) br.cond.dptk.few	4000000000133700 }

l4000000000133780:
	{ adds	r53,0x0,r47; nop.m	0x0; adds	r54,0x0,r35 }
	{ adds	r55,0x1,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ addl	r16,16400,r0; nop.m	0x0; adds	r1,0x0,r52 }
	{ addl	r53,1,r0; nop.m	0x0; adds	r54,0x10,r12; }
	{ add	r55,r12,r16; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AFE0; }
	{ adds	r1,0x0,r52; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	4000000000133700 }

l40000000001337E0:
	{ nop.m	0x0; ld8	r14,[r48]; adds	r42,0x1,r42 }
	{ ld8	r15,[r44]; nop.i	0x0; cmp.lt	p07,p06,r41,r14 }
	{ ld8	r16,[r49]; cmp.lt	p11,p10,r40,r15; cmp.eq	p08,p09,r15,r14; }
	{ (p11) adds	r40,0x0,r15; add	r43,r43,r16; (p08) br.cond.dpnt.few	4000000000133700; }

l4000000000133816:
	{ (p21) chk.s.m	r16,4000000000133AC6; nop; Invalid }

l4000000000133820:
	{ nop.m	0x0; (p07) adds	r41,0x0,r14; br.cond.sptk.few	4000000000133700 }

l400000000013382C:
	{ (p55) nop; (p02) cmp.eq	p06,p18,r0,r32; zxt1	r66,r64 }

l4000000000133830:
	{ addl	r17,16408,r0; adds	r15,0x8,r14; add	r16,r12,r17 }
	{ ld8	r15,[r15]; ld8	r16,[r16]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r15,r16; (p06) br.cond.dptk.few	40000000001335C0 }

l4000000000133860:
	{ addl	r17,16456,r0; adds	r15,0x38,r14; add	r16,r12,r17 }
	{ ld8	r15,[r15]; ld8	r16,[r16]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r15,r16; (p06) br.cond.dptk.few	40000000001335C0 }

l4000000000133890:
	{ adds	r14,0x48,r14; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r14,r45; (p06) br.cond.dptk.few	40000000001335C0 }

l40000000001338B0:
	{ addl	r54,21684,r1; adds	r53,0x0,r33; addl	r55,144,r0; }
	{ nop.m	0x0; br.call.sptk.many	b0,fn400000000001A8A0; nop.b	0x0; }
	{ adds	r1,0x0,r52; nop.m	0x0; nop.i	0x0 }

l40000000001338E0:
	{ adds	r8,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r51; }
	{ nop.m	0x0; mov.spnt	b0,r50,40000000001338F0; addl	r19,16672,r0; }
	{ nop.m	0x0; add	r12,r12,r19; br.ret	b0; }

l4000000000133910:
	{ addl	r34,-1,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ addl	r14,36,r0; nop.m	0x0; adds	r1,0x0,r52; }
	{ st4	[r14],r8; adds	r8,0x0,r34; mov.i	ar.pfs,r51; }
	{ nop.m	0x0; mov.spnt	b0,r50,4000000000133940; addl	r19,16672,r0; }
	{ nop.m	0x0; add	r12,r12,r19; br.ret	b0; }

l4000000000133960:
	{ adds	r53,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C300; }
	{ adds	r1,0x0,r52; cmp4.eq	p07,p06,0x1,r46; addl	r17,16616,r0 }
	{ addl	r46,1,r0; addl	r15,-16385,r0; addl	r16,16544,r0; }
	{ addl	r58,-6308,r1; add	r14,r12,r17; and	r15,r15,r37 }
	{ addl	r17,16560,r0; add	r54,r12,r16; addl	r16,1,r0; }
	{ ld8	r58,[r58]; nop.m	0x0; addl	r53,21684,r1 }
	{ addl	r55,144,r0; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000133630; }

l40000000001339D0:
	{ cmp.eq	p07,p06,0x0,r40; nop.m	0x0; nop.i	0x0; }
	{ (p07) st8	[r45],r14; (p06) st8	[r40],r14; addl	r14,32768,r0; }

l40000000001339E6:
	{ mf.a; (p07) nop; (p48) nop; }

l40000000001339EC:
	{ cmp.eq	p00,p09,r0,r74; (p33) cmp.lt.unc	p35,p16,r67,r3; (p01) nop; }
	{ Invalid; Invalid; (p02) cmp.lt	p20,p18,r32,r32 }
	{ Invalid; zxt4	r4,r32; (p48) cmp.lt.unc	p10,p08,r3,r102; }
	{ (p06) nop; Invalid; cmp.eq	p00,p00,r32,r0; }
	{ (p44) cmp.lt	p00,p11,r1,r73; zxt1	r99,r0; (p16) cmp.lt.unc	p10,p08,r3,r102; }
	{ Invalid; Invalid; break.i	0x1000; }
	{ (p51) nop; nop; (p06) cmp.eq	p32,p16,r8,r64 }
	{ Invalid; Invalid; Invalid }
	{ Invalid; break.i	0x1000; break.i	0x1000 }
	{ Invalid; nop; epc }
	{ (p51) cmp.lt.unc	p63,p00,r63,r36; cmp.eq	p00,p00,r32,r0; break.i	0x1000 }
4000000000133A90 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
4000000000133AA0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
4000000000133AB0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; fmtulong: 4000000000133AC0
;;   Called from:
;;     40000000000689BC (in bind_var_to_int)
fmtulong proc
	{ alloc	r40,ar.pfs,0xE,0x0,0xB; nop.m	0x0; mov	r42,pr }
	{ adds	r41,0x0,r1; nop.m	0x0; cmp4.eq	p06,p07,0x0,r33; }
	{ nop.m	0x0; mov	r39,b7; (p06) br.cond.dptk.few	4000000000133EB0 }

l4000000000133AF0:
	{ nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFFFE,r33; nop.i	0x0; }
	{ cmp4.ltu	p07,p06,0x3E,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000133F60; }

l4000000000133B10:
	{ nop.m	0x0; tbit.z	p07,p06,r36,0x3; (p06) br.cond.dptk.few	4000000000133B40; }

l4000000000133B20:
	{ nop.m	0x0; cmp.lt	p07,p06,r32,r0; nop.i	0x0; }
	{ (p07) sub	r32,r0,r32; (p07) addl	r38,45,r0; (p07) br.cond.dpnt.few	4000000000133B50; }

l4000000000133B36:
	{ (p19) chk.a.clr	f45,3FFFFFFFFF333B36; nop; (p32) nop; }

l4000000000133B3C:
	{ (p01) cmp.lt	p00,p08,r64,r33; zxt1	r0,r64; break.i	0x1000 }

l4000000000133B40:
	{ adds	r38,0x0,r0; nop.m	0x0; nop.i	0x0 }

l4000000000133B50:
	{ adds	r35,0xFFFFFFFFFFFFFFFE,r35; cmp4.eq	p16,p17,0x8,r33; cmp4.lt	p06,p07,0x8,r33; }
	{ add	r34,r34,r35; adds	r14,0x1,r34; nop.i	0x0; }
	{ st1	[r0],r14; (p16) br.cond.dpnt.few	4000000000133D40; (p07) br.cond.dptk.few	4000000000133ED0 }

l4000000000133B7C:
	{ (p27) cmp.lt	p00,p17,r0,r33; czx1.r	r34,r97; mov	pr,r32,0x0 }

l4000000000133B80:
	{ cmp4.eq	p06,p07,0xA,r33; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000133FF0; }

l4000000000133B90:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x10,r33; (p06) br.cond.dpnt.few	40000000001341B0 }

l4000000000133BA0:
	{ nop.m	0x0; sxt4	r37,r33; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000133BC0:
	{ adds	r43,0x0,r32; adds	r44,0x0,r37; br.call.sptk.many	b0,fn4000000000137BF0; }
	{ nop.m	0x0; adds	r1,0x0,r41; adds	r14,0x30,r8 }
	{ nop.m	0x0; cmp.ltu	p06,p07,0x9,r8; (p07) br.cond.dptk.few	40000000001342B0; }

l4000000000133BF0:
	{ adds	r14,0x57,r8; cmp.ltu	p06,p07,0x23,r8; (p07) br.cond.dptk.few	40000000001342B0; }

l4000000000133C00:
	{ cmp.ltu	p08,p09,0x3D,r8; adds	r15,0x1D,r8; cmp.eq	p07,p06,0x3E,r8; }
	{ nop.m	0x0; sxt1	r14,r15; (p09) br.cond.dptk.few	4000000000133C30; }

l4000000000133C20:
	{ (p06) addl	r14,95,r0; nop.i	0x0; (p07) addl	r14,64,r0; }

l4000000000133C26:
	{ chk.a.nc	f0,3FFFFFFFFF134426; (p07) nop; (p48) nop }

l4000000000133C30:
	{ st1	[r34],r127,-1; nop.m	0x0; adds	r43,0x0,r32 }
	{ adds	r44,0x0,r37; nop.m	0x0; br.call.sptk.many	b0,fn4000000000137B00; }
	{ adds	r32,0x0,r8; adds	r8,0x0,r34; adds	r1,0x0,r41; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p06) br.cond.dptk.few	4000000000133BC0; }

l4000000000133C70:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000133C80:
	{ nop.m	0x0; tbit.z	p06,p07,r36,0x0; (p06) br.cond.dptk.few	4000000000133DC0; }

l4000000000133C90:
	{ cmp4.eq	p06,p07,0x10,r33; (p06) addl	r14,1,r0; nop.i	0x0; }

l4000000000133C9C:
	{ nop; cmp4.eq.and	p00,p32,r32,r0; zxt1	r0,r64 }

l4000000000133CAC:
	{ invala; break.i	0x1000; Invalid }
	{ (p08) cmp.lt	p00,p17,r0,r33; cmp.lt.unc	p00,p28,r99,r97; (p17) nop }

l4000000000133CC0:
	{ cmp4.eq	p06,p07,0x0,r14; adds	r14,0x1,r8; (p07) br.cond.dpnt.few	4000000000134310; }

l4000000000133CD0:
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x30,r14; nop.i	0x0; (p07) addl	r14,48,r0; }

l4000000000133CF0:
	{ (p07) st1	[r8],r127,-1; nop.m	0x0; nop.i	0x0 }

l4000000000133CF6:
	{ break.m	0x4000; nop; (p32) nop }

l4000000000133D00:
	{ cmp4.eq	p06,p07,0x0,r38; (p07) addl	r14,45,r0; nop.i	0x0; }

l4000000000133D0C:
	{ cmp4.eq.or.andcm	p00,p35,r1,r0; Invalid; dep	r0,r32,r0,63,1 }

l4000000000133D16:
	{ break.m	0x4000; (p17) mov.sptk	b1,r8,4000000000133E16; nop }

l4000000000133D20:
	{ adds	r8,0x0,r34; mov	pr,r42,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.spnt	b0,r39,4000000000133D30; br.ret	b0 }

l4000000000133D40:
	{ and	r14,0x7,r32; extr	r32,r32,3,61; adds	r14,0x30,r14 }
	{ cmp.eq	p07,p06,0x0,r32; st1	[r34],r127,-1; nop.i	0x0; }
	{ adds	r8,0x0,r34; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000133C80; }

l4000000000133D70:
	{ and	r14,0x7,r32; nop.m	0x0; extr	r32,r32,3,61; }
	{ adds	r14,0x30,r14; cmp.eq	p07,p06,0x0,r32; nop.i	0x0 }
	{ st1	[r34],r127,-1; nop.m	0x0; (p06) br.cond.dptk.few	4000000000133D40; }

l4000000000133DA0:
	{ adds	r8,0x0,r34; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000133C80 }

l4000000000133DC0:
	{ nop.m	0x0; tbit.z	p06,p07,r36,0x1; (p06) br.cond.dptk.few	4000000000133D00; }

l4000000000133DD0:
	{ cmp4.eq	p06,p07,0xA,r33; movl	r15,0x26666666666667 }
	{ addl	r17,35,r0; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000133D00; }

l4000000000133DF0:
	{ cmp4.lt	p06,p07,0xA,r33; nop.m	0x0; sxt4	r33,r33 }
	{ setf.sig	f7,r15; nop.m	0x0; adds	r14,0x0,r8; }
	{ setf.sig	f6,r33; nop.m	0x0; extr.u	r16,r33,63,1 }
	{ st1	[r14],r127,-1; nop.m	0x0; (p07) adds	r8,0xFFFFFFFFFFFFFFFE,r8; }

l4000000000133E30:
	{ nop.m	0x0; nop.m	0x0; xma.h	f6,f6,f7,f0; }
	{ getf.sig	r15,f6; nop.m	0x0; extr	r15,r15,2,62; }
	{ sub	r15,r15,r16; shladd	r16,r15,0x2,r15; (p06) adds	r15,0x30,r15; }

l4000000000133E60:
	{ shladd	r16,r16,0x1,r0; sub	r33,r33,r16; nop.i	0x0; }
	{ adds	r33,0x30,r33; st1	[r33],r14; (p06) adds	r14,0xFFFFFFFFFFFFFFFE,r8 }

l4000000000133E80:
	{ (p06) adds	r8,0xFFFFFFFFFFFFFFFD,r8; (p06) st1	[r15],r14; cmp4.eq	p06,p07,0x0,r38; }

l4000000000133E86:
	{ mf.a; (p03) cmp4.eq.or	p00,p51,0x26,r7; (p33) cmp.eq	p35,p00,0xB,r0; }

l4000000000133E8C:
	{ cmp4.eq.and	p38,p43,r7,r115; (p17) cmp4.eq.or.andcm	p11,p50,r0,r0; Invalid }

l4000000000133E96:
	{ Invalid; nop; break.b	0x80000; }

l4000000000133E9C:
	{ invala; dep	r0,r32,r0,63,1; zxt1	r0,r64 }
	{ (p52) nop; (p36) cmp.eq	p02,p18,r0,r0; (p32) mov	pr,r73,0x5002 }

l4000000000133EB0:
	{ addl	r33,10,r0; tbit.z	p07,p06,r36,0x3; (p06) br.cond.dptk.few	4000000000133B40 }

l4000000000133EC0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000133B20; }

l4000000000133ED0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2,r33; (p07) br.cond.dptk.few	4000000000133BA0; }

l4000000000133EE0:
	{ and	r14,0x1,r32; extr	r32,r32,1,63; adds	r14,0x30,r14 }
	{ cmp.eq	p07,p06,0x0,r32; st1	[r34],r127,-1; nop.i	0x0; }
	{ adds	r8,0x0,r34; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000133C80; }

l4000000000133F10:
	{ and	r14,0x1,r32; nop.m	0x0; extr	r32,r32,1,63; }
	{ adds	r14,0x30,r14; cmp.eq	p07,p06,0x0,r32; nop.i	0x0 }
	{ st1	[r34],r127,-1; nop.m	0x0; (p06) br.cond.dptk.few	4000000000133EE0; }

l4000000000133F40:
	{ adds	r8,0x0,r34; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000133C80 }

l4000000000133F60:
	{ addl	r44,-2900,r1; addl	r45,5,r0; adds	r43,0x0,r0; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r45,0xFFFFFFFFFFFFFFFF,r35; adds	r1,0x0,r41; adds	r43,0x0,r34 }
	{ adds	r44,0x0,r8; add	r35,r34,r35; br.call.sptk.many	b0,fn400000000001B920; }
	{ nop.m	0x0; adds	r1,0x0,r41; nop.i	0x0 }
	{ st1	[r0],r35; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ addl	r14,22,r0; adds	r1,0x0,r41; mov	pr,r42,0xFFFFFFFFFFFFFFFE; }
	{ st4	[r14],r8; mov.i	ar.pfs,r40; adds	r8,0x0,r34; }
	{ nop.m	0x0; mov.spnt	b0,r39,4000000000133FE0; br.ret	b0 }

l4000000000133FF0:
	{ cmp.ltu	p06,p07,0x9,r32; (p07) adds	r8,0x0,r34; (p07) adds	r32,0x30,r32; }

l4000000000133FFC:
	{ (p24) cmp4.eq.or.andcm	p32,p48,r0,r66; nop }

l4000000000134000:
	{ (p07) st1	[r8],r127,-1; nop.i	0x0; (p07) br.cond.dptk.few	4000000000133C80 }

l4000000000134006:
	{ chk.a.nc	f0,3FFFFFFFFF134806; nop; break.i	0x80000 }

l4000000000134010:
	{ nop.m	0x0; cmp.lt	p07,p06,r32,r0; nop.i	0x0; }
	{ nop.m	0x0; (p07) movl	r14,0x800CCCCCCCCCCCCD }

l4000000000134030:
	{ (p07) setf.sig	f6,r32; (p07) setf.sig	f7,r14; nop.i	0x0; }

l4000000000134036:
	{ (p03) srlz.i; nop; break.b	0x80000; }

l400000000013403C:
	{ Invalid; break.i	0x1000; cmp4.eq.and	p00,p32,r32,r0 }
	{ cmp4.eq.and	p06,p43,r7,r118; Invalid; cmp4.eq.and	p00,p32,r32,r0 }

l4000000000134050:
	{ (p07) getf.sig	r14,f6; nop.m	0x0; (p07) extr	r14,r14,3,61; }

l4000000000134056:
	{ chk.a.nc	f0,3FFFFFFFFF134856; (p07) cmp4.ltu	p06,p41,0xE,r60; (p49) cmp.eq.unc	p03,p04,r67,r35 }

l4000000000134060:
	{ (p07) shladd	r15,r14,0x2,r14; (p07) shladd	r15,r15,0x1,r0; nop.i	0x0; }

l4000000000134066:
	{ Invalid; cmp4.lt	p00,p00,0x0,r1; Invalid; }

l400000000013406C:
	{ cmp4.eq.or.andcm	p00,p35,r1,r0; (p01) mov	pr,r35,0x80D0; (p04) cmp4.ne.and	p00,p48,r3,r64 }

l4000000000134076:
	{ (p16) chk.a.clr	f0,3FFFFFFFFF1B4156; (p07) cmp.ge.and	p48,p02,r0,r0; (p49) dep	r95,r67,r40,33,0; }

l400000000013407C:
	{ (p24) cmp4.eq.or.andcm	p15,p36,r0,r66; (p47) cmp.lt.unc	p03,p43,0xFFFFFFFFFFFFFFA8,r96; (p12) cmp.lt	p51,p25,r102,r76; }

l4000000000134080:
	{ (p07) st1	[r34],r127,-1; movl	r14,0x26666666666667 }

l4000000000134086:
	{ Invalid; Invalid; Invalid }
	{ (p03) srlz.i; nop; (p48) nop }

l40000000001340A0:
	{ setf.sig	f7,r32; nop.m	0x0; extr.u	r15,r32,63,1; }
	{ nop.m	0x0; nop.m	0x0; xma.h	f7,f7,f6,f0; }
	{ getf.sig	r14,f7; nop.m	0x0; extr	r14,r14,2,62; }
	{ sub	r14,r14,r15; shladd	r15,r14,0x2,r14; nop.i	0x0; }
	{ shladd	r15,r15,0x1,r0; sub	r15,r32,r15; adds	r32,0x0,r14; }
	{ setf.sig	f7,r32; nop.m	0x0; adds	r14,0x30,r15 }
	{ cmp.eq	p07,p06,0x0,r32; nop.m	0x0; extr.u	r15,r32,63,1; }
	{ nop.m	0x0; st1	[r34],r127,-1; nop.i	0x0; }
	{ adds	r8,0x0,r34; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000133C80; }

l4000000000134130:
	{ nop.m	0x0; nop.m	0x0; xma.h	f7,f7,f6,f0; }
	{ getf.sig	r14,f7; nop.m	0x0; extr	r14,r14,2,62; }
	{ sub	r14,r14,r15; shladd	r15,r14,0x2,r14; nop.i	0x0; }
	{ shladd	r15,r15,0x1,r0; sub	r15,r32,r15; adds	r32,0x0,r14; }
	{ adds	r14,0x30,r15; cmp.eq	p07,p06,0x0,r32; nop.i	0x0 }
	{ st1	[r34],r127,-1; nop.m	0x0; (p06) br.cond.dptk.few	40000000001340A0; }

l4000000000134190:
	{ adds	r8,0x0,r34; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000133C80 }

l40000000001341B0:
	{ addl	r17,-2892,r1; addl	r16,-2884,r1; tbit.z	p08,p09,r36,0x2; }
	{ ld8	r17,[r17]; ld8	r16,[r16]; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000001341E0:
	{ and	r14,0xF,r32; nop.m	0x0; extr	r32,r32,4,60; }
	{ adds	r15,0x0,r14; (p08) add	r14,r17,r14; cmp.eq	p07,p06,0x0,r32; }

l40000000001341FC:
	{ cmp.eq	p32,p41,0x6,r114; (p01) cmp.lt.unc	p04,p16,0x3,r0; Invalid }

l4000000000134206:
	{ (p07) fwb; shrp	r0,r0,r1,0; (p34) nop }

l400000000013420C:
	{ cmp.lt	p00,p43,0x1,r0; Invalid; cmp.lt	p00,p00,r32,r0 }

l4000000000134216:
	{ break.m	0x4000; (p07) nop; break.i	0x80000 }
	{ Invalid; nop; nop.b	0x22002 }
	{ chk.a.nc	f0,3FFFFFFFFF134A36; Invalid; (p32) nop }

l4000000000134240:
	{ and	r14,0xF,r32; extr	r32,r32,4,60; adds	r15,0x0,r14 }
	{ (p08) add	r14,r17,r14; cmp.eq	p07,p06,0x0,r32; (p09) add	r15,r16,r14 }

l4000000000134256:
	{ (p03) addl	r0,96544,r2; (p07) nop; (p34) br.call.sptk.few	b3,4000000000135E56 }

l4000000000134260:
	{ (p08) ld1	r14,[r14]; (p09) ld1	r14,[r15]; nop.i	0x0; }

l4000000000134266:
	{ (p07) fwb; Invalid; break.i	0x80000 }

l400000000013426C:
	{ Invalid; cmp.lt	p00,p00,r32,r0; (p01) break.i	0x141C0 }
	{ cmp.eq	p00,p25,r1,r0; Invalid; mov	pr,r32,0x0 }
	{ (p59) nop; zxt1	r64,r64; break.i	0x1000 }

l4000000000134290:
	{ adds	r8,0x0,r34; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000133C80 }

l40000000001342B0:
	{ nop.m	0x0; sxt1	r14,r14; adds	r43,0x0,r32 }
	{ nop.m	0x0; adds	r44,0x0,r37; nop.b	0x0; }
	{ st1	[r34],r127,-1; nop.i	0x0; br.call.sptk.many	b0,fn4000000000137B00; }
	{ adds	r32,0x0,r8; adds	r8,0x0,r34; adds	r1,0x0,r41; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p06) br.cond.dptk.few	4000000000133BC0 }

l4000000000134300:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000133C80; }

l4000000000134310:
	{ nop.m	0x0; tbit.z	p06,p07,r36,0x2; nop.b	0x0 }
	{ adds	r14,0x0,r8; addl	r15,48,r0; adds	r8,0xFFFFFFFFFFFFFFFE,r8; }
	{ (p06) addl	r36,120,r0; (p07) addl	r36,88,r0; cmp4.eq	p06,p07,0x0,r38; }

l4000000000134336:
	{ Invalid; (p03) nop; (p48) nop; }

l400000000013433C:
	{ cmp.eq	p38,p11,r7,r115; Invalid; (p48) cmp4.ne.and	p03,p40,r3,r96 }
	{ (p22) nop; cmp4.eq.or.andcm	p00,p32,r32,r0; (p47) nop; }

l4000000000134350:
	{ nop.m	0x0; (p07) st1	[r8],r127,-1; nop.i	0x0; }

l400000000013435C:
	{ Invalid; dep	r0,r32,r0,63,1; zxt1	r0,r64 }
	{ (p14) cmp.lt.unc	p63,p00,r63,r36; cmp.eq	p00,p00,r32,r0; break.i	0x1000 }
4000000000134370 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; fmtumax: 4000000000134380
;;   Called from:
;;     4000000000071FFC (in fn4000000000071E00)
;;     4000000000071FFC (in fn4000000000071FC0)
;;     4000000000129A6C (in inttostr)
;;     4000000000129AFC (in itos)
;;     4000000000129BAC (in uinttostr)
;;     4000000000129C3C (in uitos)
fmtumax proc
	{ alloc	r40,ar.pfs,0xE,0x0,0xB; nop.m	0x0; mov	r42,pr }
	{ adds	r41,0x0,r1; nop.m	0x0; cmp4.eq	p06,p07,0x0,r33; }
	{ nop.m	0x0; mov	r39,b7; (p06) br.cond.dptk.few	4000000000134770 }

l40000000001343B0:
	{ nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFFFE,r33; nop.i	0x0; }
	{ cmp4.ltu	p07,p06,0x3E,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000134820; }

l40000000001343D0:
	{ nop.m	0x0; tbit.z	p07,p06,r36,0x3; (p06) br.cond.dptk.few	4000000000134400; }

l40000000001343E0:
	{ nop.m	0x0; cmp.lt	p07,p06,r32,r0; nop.i	0x0; }
	{ (p07) sub	r32,r0,r32; (p07) addl	r38,45,r0; (p07) br.cond.dpnt.few	4000000000134410; }

l40000000001343F6:
	{ (p19) chk.a.clr	f45,3FFFFFFFFF3343F6; nop; (p32) nop; }

l40000000001343FC:
	{ (p01) cmp.lt	p00,p08,r64,r33; zxt1	r0,r64; break.i	0x1000 }

l4000000000134400:
	{ adds	r38,0x0,r0; nop.m	0x0; nop.i	0x0 }

l4000000000134410:
	{ adds	r35,0xFFFFFFFFFFFFFFFE,r35; cmp4.eq	p16,p17,0x8,r33; cmp4.lt	p06,p07,0x8,r33; }
	{ add	r34,r34,r35; adds	r14,0x1,r34; nop.i	0x0; }
	{ st1	[r0],r14; (p16) br.cond.dpnt.few	4000000000134600; (p07) br.cond.dptk.few	4000000000134790 }

l400000000013443C:
	{ (p27) cmp.lt	p00,p17,r0,r33; czx1.r	r34,r97; mov	pr,r32,0x0 }

l4000000000134440:
	{ cmp4.eq	p06,p07,0xA,r33; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001348B0; }

l4000000000134450:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x10,r33; (p06) br.cond.dpnt.few	4000000000134A70 }

l4000000000134460:
	{ nop.m	0x0; sxt4	r37,r33; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000134480:
	{ adds	r43,0x0,r32; adds	r44,0x0,r37; br.call.sptk.many	b0,fn4000000000137BF0; }
	{ nop.m	0x0; adds	r1,0x0,r41; adds	r14,0x30,r8 }
	{ nop.m	0x0; cmp.ltu	p06,p07,0x9,r8; (p07) br.cond.dptk.few	4000000000134B70; }

l40000000001344B0:
	{ adds	r14,0x57,r8; cmp.ltu	p06,p07,0x23,r8; (p07) br.cond.dptk.few	4000000000134B70; }

l40000000001344C0:
	{ cmp.ltu	p08,p09,0x3D,r8; adds	r15,0x1D,r8; cmp.eq	p07,p06,0x3E,r8; }
	{ nop.m	0x0; sxt1	r14,r15; (p09) br.cond.dptk.few	40000000001344F0; }

l40000000001344E0:
	{ (p06) addl	r14,95,r0; nop.i	0x0; (p07) addl	r14,64,r0; }

l40000000001344E6:
	{ chk.a.nc	f0,3FFFFFFFFF134CE6; (p07) nop; (p48) nop }

l40000000001344F0:
	{ st1	[r34],r127,-1; nop.m	0x0; adds	r43,0x0,r32 }
	{ adds	r44,0x0,r37; nop.m	0x0; br.call.sptk.many	b0,fn4000000000137B00; }
	{ adds	r32,0x0,r8; adds	r8,0x0,r34; adds	r1,0x0,r41; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p06) br.cond.dptk.few	4000000000134480; }

l4000000000134530:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000134540:
	{ nop.m	0x0; tbit.z	p06,p07,r36,0x0; (p06) br.cond.dptk.few	4000000000134680; }

l4000000000134550:
	{ cmp4.eq	p06,p07,0x10,r33; (p06) addl	r14,1,r0; nop.i	0x0; }

l400000000013455C:
	{ nop; cmp4.eq.and	p00,p32,r32,r0; zxt1	r0,r64 }

l400000000013456C:
	{ invala; break.i	0x1000; Invalid }
	{ (p08) cmp.lt	p00,p17,r0,r33; cmp.lt.unc	p00,p28,r99,r97; (p17) nop }

l4000000000134580:
	{ cmp4.eq	p06,p07,0x0,r14; adds	r14,0x1,r8; (p07) br.cond.dpnt.few	4000000000134BD0; }

l4000000000134590:
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x30,r14; nop.i	0x0; (p07) addl	r14,48,r0; }

l40000000001345B0:
	{ (p07) st1	[r8],r127,-1; nop.m	0x0; nop.i	0x0 }

l40000000001345B6:
	{ break.m	0x4000; nop; (p32) nop }

l40000000001345C0:
	{ cmp4.eq	p06,p07,0x0,r38; (p07) addl	r14,45,r0; nop.i	0x0; }

l40000000001345CC:
	{ cmp4.eq.or.andcm	p00,p35,r1,r0; Invalid; dep	r0,r32,r0,63,1 }

l40000000001345D6:
	{ break.m	0x4000; (p17) mov.sptk	b1,r8,40000000001346D6; nop }

l40000000001345E0:
	{ adds	r8,0x0,r34; mov	pr,r42,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000001345F0; br.ret	b0 }

l4000000000134600:
	{ and	r14,0x7,r32; extr	r32,r32,3,61; adds	r14,0x30,r14 }
	{ cmp.eq	p07,p06,0x0,r32; st1	[r34],r127,-1; nop.i	0x0; }
	{ adds	r8,0x0,r34; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000134540; }

l4000000000134630:
	{ and	r14,0x7,r32; nop.m	0x0; extr	r32,r32,3,61; }
	{ adds	r14,0x30,r14; cmp.eq	p07,p06,0x0,r32; nop.i	0x0 }
	{ st1	[r34],r127,-1; nop.m	0x0; (p06) br.cond.dptk.few	4000000000134600; }

l4000000000134660:
	{ adds	r8,0x0,r34; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000134540 }

l4000000000134680:
	{ nop.m	0x0; tbit.z	p06,p07,r36,0x1; (p06) br.cond.dptk.few	40000000001345C0; }

l4000000000134690:
	{ cmp4.eq	p06,p07,0xA,r33; movl	r15,0x26666666666667 }
	{ addl	r17,35,r0; nop.m	0x0; (p06) br.cond.dpnt.few	40000000001345C0; }

l40000000001346B0:
	{ cmp4.lt	p06,p07,0xA,r33; nop.m	0x0; sxt4	r33,r33 }
	{ setf.sig	f7,r15; nop.m	0x0; adds	r14,0x0,r8; }
	{ setf.sig	f6,r33; nop.m	0x0; extr.u	r16,r33,63,1 }
	{ st1	[r14],r127,-1; nop.m	0x0; (p07) adds	r8,0xFFFFFFFFFFFFFFFE,r8; }

l40000000001346F0:
	{ nop.m	0x0; nop.m	0x0; xma.h	f6,f6,f7,f0; }
	{ getf.sig	r15,f6; nop.m	0x0; extr	r15,r15,2,62; }
	{ sub	r15,r15,r16; shladd	r16,r15,0x2,r15; (p06) adds	r15,0x30,r15; }

l4000000000134720:
	{ shladd	r16,r16,0x1,r0; sub	r33,r33,r16; nop.i	0x0; }
	{ adds	r33,0x30,r33; st1	[r33],r14; (p06) adds	r14,0xFFFFFFFFFFFFFFFE,r8 }

l4000000000134740:
	{ (p06) adds	r8,0xFFFFFFFFFFFFFFFD,r8; (p06) st1	[r15],r14; cmp4.eq	p06,p07,0x0,r38; }

l4000000000134746:
	{ mf.a; (p03) cmp4.eq.or	p00,p51,0x26,r7; (p33) cmp.eq	p35,p00,0xB,r0; }

l400000000013474C:
	{ cmp4.eq.and	p38,p43,r7,r115; (p17) cmp4.eq.or.andcm	p11,p50,r0,r0; Invalid }

l4000000000134756:
	{ Invalid; nop; break.b	0x80000; }

l400000000013475C:
	{ invala; dep	r0,r32,r0,63,1; zxt1	r0,r64 }
	{ (p52) nop; (p36) cmp.eq	p02,p18,r0,r0; (p32) mov	pr,r73,0x5002 }

l4000000000134770:
	{ addl	r33,10,r0; tbit.z	p07,p06,r36,0x3; (p06) br.cond.dptk.few	4000000000134400 }

l4000000000134780:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000001343E0; }

l4000000000134790:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2,r33; (p07) br.cond.dptk.few	4000000000134460; }

l40000000001347A0:
	{ and	r14,0x1,r32; extr	r32,r32,1,63; adds	r14,0x30,r14 }
	{ cmp.eq	p07,p06,0x0,r32; st1	[r34],r127,-1; nop.i	0x0; }
	{ adds	r8,0x0,r34; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000134540; }

l40000000001347D0:
	{ and	r14,0x1,r32; nop.m	0x0; extr	r32,r32,1,63; }
	{ adds	r14,0x30,r14; cmp.eq	p07,p06,0x0,r32; nop.i	0x0 }
	{ st1	[r34],r127,-1; nop.m	0x0; (p06) br.cond.dptk.few	40000000001347A0; }

l4000000000134800:
	{ adds	r8,0x0,r34; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000134540 }

l4000000000134820:
	{ addl	r44,-4564,r1; addl	r45,5,r0; adds	r43,0x0,r0; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r45,0xFFFFFFFFFFFFFFFF,r35; adds	r1,0x0,r41; adds	r43,0x0,r34 }
	{ adds	r44,0x0,r8; add	r35,r34,r35; br.call.sptk.many	b0,fn400000000001B920; }
	{ nop.m	0x0; adds	r1,0x0,r41; nop.i	0x0 }
	{ st1	[r0],r35; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ addl	r14,22,r0; adds	r1,0x0,r41; mov	pr,r42,0xFFFFFFFFFFFFFFFE; }
	{ st4	[r14],r8; mov.i	ar.pfs,r40; adds	r8,0x0,r34; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000001348A0; br.ret	b0 }

l40000000001348B0:
	{ cmp.ltu	p06,p07,0x9,r32; (p07) adds	r8,0x0,r34; (p07) adds	r32,0x30,r32; }

l40000000001348BC:
	{ (p24) cmp4.eq.or.andcm	p32,p48,r0,r66; nop }

l40000000001348C0:
	{ (p07) st1	[r8],r127,-1; nop.i	0x0; (p07) br.cond.dptk.few	4000000000134540 }

l40000000001348C6:
	{ chk.a.nc	f0,3FFFFFFFFF1350C6; nop; break.i	0x80000 }

l40000000001348D0:
	{ nop.m	0x0; cmp.lt	p07,p06,r32,r0; nop.i	0x0; }
	{ nop.m	0x0; (p07) movl	r14,0x800CCCCCCCCCCCCD }

l40000000001348F0:
	{ (p07) setf.sig	f6,r32; (p07) setf.sig	f7,r14; nop.i	0x0; }

l40000000001348F6:
	{ (p03) srlz.i; nop; break.b	0x80000; }

l40000000001348FC:
	{ Invalid; break.i	0x1000; cmp4.eq.and	p00,p32,r32,r0 }
	{ cmp4.eq.and	p06,p43,r7,r118; Invalid; cmp4.eq.and	p00,p32,r32,r0 }

l4000000000134910:
	{ (p07) getf.sig	r14,f6; nop.m	0x0; (p07) extr	r14,r14,3,61; }

l4000000000134916:
	{ chk.a.nc	f0,3FFFFFFFFF135116; (p07) cmp4.ltu	p06,p41,0xE,r60; (p49) cmp.eq.unc	p03,p04,r67,r35 }

l4000000000134920:
	{ (p07) shladd	r15,r14,0x2,r14; (p07) shladd	r15,r15,0x1,r0; nop.i	0x0; }

l4000000000134926:
	{ Invalid; cmp4.lt	p00,p00,0x0,r1; Invalid; }

l400000000013492C:
	{ cmp4.eq.or.andcm	p00,p35,r1,r0; (p01) mov	pr,r35,0x80D0; (p04) cmp4.ne.and	p00,p48,r3,r64 }

l4000000000134936:
	{ (p16) chk.a.clr	f0,3FFFFFFFFF1B4A16; (p07) cmp.ge.and	p48,p02,r0,r0; (p49) dep	r95,r67,r40,33,0; }

l400000000013493C:
	{ (p24) cmp4.eq.or.andcm	p15,p36,r0,r66; (p47) cmp.lt.unc	p03,p43,0xFFFFFFFFFFFFFFA8,r96; (p12) cmp.lt	p51,p25,r102,r76; }

l4000000000134940:
	{ (p07) st1	[r34],r127,-1; movl	r14,0x26666666666667 }

l4000000000134946:
	{ Invalid; Invalid; Invalid }
	{ (p03) srlz.i; nop; (p48) nop }

l4000000000134960:
	{ setf.sig	f7,r32; nop.m	0x0; extr.u	r15,r32,63,1; }
	{ nop.m	0x0; nop.m	0x0; xma.h	f7,f7,f6,f0; }
	{ getf.sig	r14,f7; nop.m	0x0; extr	r14,r14,2,62; }
	{ sub	r14,r14,r15; shladd	r15,r14,0x2,r14; nop.i	0x0; }
	{ shladd	r15,r15,0x1,r0; sub	r15,r32,r15; adds	r32,0x0,r14; }
	{ setf.sig	f7,r32; nop.m	0x0; adds	r14,0x30,r15 }
	{ cmp.eq	p07,p06,0x0,r32; nop.m	0x0; extr.u	r15,r32,63,1; }
	{ nop.m	0x0; st1	[r34],r127,-1; nop.i	0x0; }
	{ adds	r8,0x0,r34; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000134540; }

l40000000001349F0:
	{ nop.m	0x0; nop.m	0x0; xma.h	f7,f7,f6,f0; }
	{ getf.sig	r14,f7; nop.m	0x0; extr	r14,r14,2,62; }
	{ sub	r14,r14,r15; shladd	r15,r14,0x2,r14; nop.i	0x0; }
	{ shladd	r15,r15,0x1,r0; sub	r15,r32,r15; adds	r32,0x0,r14; }
	{ adds	r14,0x30,r15; cmp.eq	p07,p06,0x0,r32; nop.i	0x0 }
	{ st1	[r34],r127,-1; nop.m	0x0; (p06) br.cond.dptk.few	4000000000134960; }

l4000000000134A50:
	{ adds	r8,0x0,r34; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000134540 }

l4000000000134A70:
	{ addl	r17,-4556,r1; addl	r16,-4548,r1; tbit.z	p08,p09,r36,0x2; }
	{ ld8	r17,[r17]; ld8	r16,[r16]; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000134AA0:
	{ and	r14,0xF,r32; nop.m	0x0; extr	r32,r32,4,60; }
	{ adds	r15,0x0,r14; (p08) add	r14,r17,r14; cmp.eq	p07,p06,0x0,r32; }

l4000000000134ABC:
	{ cmp.eq	p32,p41,0x6,r114; (p01) cmp.lt.unc	p04,p16,0x3,r0; Invalid }

l4000000000134AC6:
	{ (p07) fwb; shrp	r0,r0,r1,0; (p34) nop }

l4000000000134ACC:
	{ cmp.lt	p00,p43,0x1,r0; Invalid; cmp.lt	p00,p00,r32,r0 }

l4000000000134AD6:
	{ break.m	0x4000; (p07) nop; break.i	0x80000 }
	{ Invalid; nop; nop.b	0x22002 }
	{ chk.a.nc	f0,3FFFFFFFFF1352F6; Invalid; (p32) nop }

l4000000000134B00:
	{ and	r14,0xF,r32; extr	r32,r32,4,60; adds	r15,0x0,r14 }
	{ (p08) add	r14,r17,r14; cmp.eq	p07,p06,0x0,r32; (p09) add	r15,r16,r14 }

l4000000000134B16:
	{ (p03) addl	r0,96544,r2; (p07) nop; (p34) br.call.sptk.few	b3,4000000000136716 }

l4000000000134B20:
	{ (p08) ld1	r14,[r14]; (p09) ld1	r14,[r15]; nop.i	0x0; }

l4000000000134B26:
	{ (p07) fwb; Invalid; break.i	0x80000 }

l4000000000134B2C:
	{ Invalid; cmp.lt	p00,p00,r32,r0; (p01) break.i	0x141C0 }
	{ cmp.eq	p00,p25,r1,r0; Invalid; mov	pr,r32,0x0 }
	{ (p59) nop; zxt1	r64,r64; break.i	0x1000 }

l4000000000134B50:
	{ adds	r8,0x0,r34; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000134540 }

l4000000000134B70:
	{ nop.m	0x0; sxt1	r14,r14; adds	r43,0x0,r32 }
	{ nop.m	0x0; adds	r44,0x0,r37; nop.b	0x0; }
	{ st1	[r34],r127,-1; nop.i	0x0; br.call.sptk.many	b0,fn4000000000137B00; }
	{ adds	r32,0x0,r8; adds	r8,0x0,r34; adds	r1,0x0,r41; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p06) br.cond.dptk.few	4000000000134480 }

l4000000000134BC0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000134540; }

l4000000000134BD0:
	{ nop.m	0x0; tbit.z	p06,p07,r36,0x2; nop.b	0x0 }
	{ adds	r14,0x0,r8; addl	r15,48,r0; adds	r8,0xFFFFFFFFFFFFFFFE,r8; }
	{ (p06) addl	r36,120,r0; (p07) addl	r36,88,r0; cmp4.eq	p06,p07,0x0,r38; }

l4000000000134BF6:
	{ Invalid; (p03) nop; (p48) nop; }

l4000000000134BFC:
	{ cmp.eq	p38,p11,r7,r115; Invalid; (p48) cmp4.ne.and	p03,p40,r3,r96 }
	{ (p22) nop; cmp4.eq.or.andcm	p00,p32,r32,r0; (p47) nop; }

l4000000000134C10:
	{ nop.m	0x0; (p07) st1	[r8],r127,-1; nop.i	0x0; }

l4000000000134C1C:
	{ Invalid; dep	r0,r32,r0,63,1; zxt1	r0,r64 }
	{ (p14) cmp.lt.unc	p63,p00,r63,r36; cmp.eq	p00,p00,r32,r0; break.i	0x1000 }
4000000000134C30 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; zcatfd: 4000000000134C40
;;   Called from:
;;     40000000000FD24C (in help_builtin)
zcatfd proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; adds	r12,0xFFFFFFFFFFFFFF80,r12; mov	r34,b2 }
	{ adds	r36,0x0,r1; nop.m	0x0; nop.i	0x0; }

l4000000000134C60:
	{ adds	r37,0x0,r32; nop.m	0x0; adds	r38,0x10,r12 }
	{ addl	r39,128,r0; nop.m	0x0; br.call.sptk.many	b0,zread; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r36; adds	r37,0x0,r33 }
	{ adds	r38,0x10,r12; adds	r39,0x0,r8; (p06) br.cond.dpnt.few	4000000000134CF0; }

l4000000000134CA0:
	{ cmp.lt	p07,p06,r8,r0; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000134CD0; }

l4000000000134CB0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,zwrite; }
	{ adds	r1,0x0,r36; cmp4.lt	p06,p07,r8,r0; (p07) br.cond.dptk.few	4000000000134C60 }

l4000000000134CD0:
	{ addl	r8,-1,r0; mov.i	ar.pfs,r35; mov.spnt	b0,r34,4000000000134CD0 }
	{ nop.m	0x0; adds	r12,0x80,r12; br.ret	b0 }

l4000000000134CF0:
	{ adds	r8,0x0,r0; mov.i	ar.pfs,r35; mov.spnt	b0,r34,4000000000134CF0 }
	{ nop.m	0x0; adds	r12,0x80,r12; br.ret	b0; }
4000000000134D10 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
4000000000134D20 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
4000000000134D30 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; zmapfd: 4000000000134D40
;;   Called from:
;;     40000000000F524C (in fn40000000000F4180)
;;     40000000000F524C (in fn40000000000F4180)
;;     40000000000FCD5C (in help_builtin)
;;     40000000000FD4FC (in help_builtin)
zmapfd proc
	{ alloc	r40,ar.pfs,0xE,0x0,0xB; adds	r12,0xFFFFFFFFFFFFFF80,r12; mov	r42,pr }
	{ nop.m	0x0; adds	r41,0x0,r1; nop.i	0x0; }
	{ nop.m	0x0; mov	r39,b7; addl	r43,64,r0 }
	{ adds	r36,0x0,r0; addl	r35,64,r0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r41; adds	r38,0x0,r8; adds	r43,0x0,r32 }
	{ adds	r44,0x10,r12; addl	r45,128,r0; sxt4	r37,r36; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,zread; }
	{ adds	r43,0x0,r38; adds	r34,0x0,r8; add	r15,r37,r8 }
	{ adds	r1,0x0,r41; adds	r17,0x80,r35; sxt4	r14,r35; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	4000000000134EB0; }

l4000000000134DE0:
	{ sub	r16,r15,r14; cmp.lt	p07,p06,r8,r0; (p07) br.cond.dpnt.few	4000000000134F80; }

l4000000000134DF0:
	{ nop.m	0x0; extr	r16,r16,7,57; nop.i	0x0 }
	{ cmp.lt	p06,p07,r15,r14; nop.m	0x0; (p06) br.cond.dptk.few	4000000000134E40; }

l4000000000134E10:
	{ nop.m	0x0; dep.z	r16,r16,7,25; add	r35,r17,r16; }
	{ nop.m	0x0; sxt4	r44,r35; br.call.sptk.many	b0,xrealloc; }
	{ nop.m	0x0; adds	r1,0x0,r41; adds	r38,0x0,r8; }

l4000000000134E40:
	{ add	r43,r38,r37; adds	r45,0x0,r34; nop.i	0x0 }
	{ add	r36,r36,r34; adds	r44,0x10,r12; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ adds	r1,0x0,r41; sxt4	r37,r36; adds	r43,0x0,r32 }
	{ adds	r44,0x10,r12; addl	r45,128,r0; br.call.sptk.many	b0,zread; }
	{ adds	r1,0x0,r41; adds	r34,0x0,r8; adds	r17,0x80,r35 }
	{ add	r15,r37,r8; adds	r43,0x0,r38; sxt4	r14,r35; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	4000000000134DE0 }

l4000000000134EB0:
	{ nop.m	0x0; adds	r34,0x0,r36; cmp.eq	p16,p17,0x0,r33 }

l4000000000134EC0:
	{ adds	r14,0x1,r36; adds	r15,0x80,r35; adds	r43,0x0,r38; }
	{ sub	r16,r14,r35; cmp4.lt	p06,p07,r14,r35; (p06) br.cond.dptk.few	4000000000134F20; }

l4000000000134EE0:
	{ nop.m	0x0; extr	r14,r16,7,25; dep.z	r14,r14,7,25; }
	{ nop.m	0x0; add	r44,r15,r14; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r44,r44; br.call.sptk.many	b0,xrealloc; }
	{ nop.m	0x0; adds	r1,0x0,r41; adds	r38,0x0,r8; }

l4000000000134F20:
	{ nop.m	0x0; sxt4	r36,r36; (p16) adds	r43,0x0,r38; }

l4000000000134F30:
	{ add	r36,r38,r36; nop.i	0x0; nop.i	0x0 }
	{ st1	[r0],r36; (p17) st8	[r38],r33; (p16) br.call.dpnt.many	b0,fn400000000001A7E0; }

l4000000000134F4C:
	{ (p05) nop; (p01) nop; cmp.eq	p32,p16,r10,r64 }

l4000000000134F50:
	{ adds	r8,0x0,r34; (p16) adds	r1,0x0,r41; mov	pr,r42,0xFFFFFFFFFFFFFFFE; }

l4000000000134F5C:
	{ Invalid; break.m	0x1000; break.f	0x2A80A; }
	{ (p19) nop; add	r0,r32,r0; Invalid }
	{ Invalid; Invalid; Invalid }

l4000000000134F80:
	{ cmp.eq	p16,p17,0x0,r33; addl	r34,-1,r0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r41; nop.i	0x0 }
	{ (p17) st8	[r0],r33; nop.m	0x0; (p17) br.cond.dptk.few	4000000000134EC0 }

l4000000000134FA6:
	{ nop; nop; break.i	0x80000 }

l4000000000134FB0:
	{ nop.m	0x0; addl	r34,-1,r0; br.cond.sptk.few	4000000000134EC0; }

;; get_new_window_size: 4000000000134FC0
;;   Called from:
;;     4000000000029E1C (in fn4000000000029100)
;;     400000000007C95C (in get_tty_state)
;;     4000000000080EEC (in wait_for)
get_new_window_size proc
	{ alloc	r37,ar.pfs,0xA,0x0,0x7; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ addl	r14,5900,r1; mov	r36,b4; adds	r38,0x0,r1; }
	{ nop.m	0x0; ld4	r39,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r39; (p07) br.cond.dpnt.few	40000000001350C0; }

l4000000000135000:
	{ cmp4.lt	p07,p06,r39,r0; addl	r40,21523,r0; nop.i	0x0 }
	{ adds	r41,0x10,r12; adds	r35,0x12,r12; (p07) br.cond.dpnt.few	40000000001350A0; }

l4000000000135020:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B020; }
	{ adds	r14,0x10,r12; nop.m	0x0; adds	r1,0x0,r38 }
	{ cmp4.eq	p07,p06,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	40000000001350A0; }

l4000000000135050:
	{ nop.m	0x0; ld2	r39,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r39; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001350A0; }

l4000000000135070:
	{ nop.m	0x0; ld2	r40,[r35]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r40; (p07) br.cond.dpnt.few	40000000001350F0; }

l4000000000135090:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000001350A0:
	{ nop.m	0x0; mov.i	ar.pfs,r37; mov.spnt	b0,r36,40000000001350A0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000001350C0:
	{ addl	r14,-10652,r1; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r39,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BBC0; }
	{ adds	r1,0x0,r38; adds	r39,0x0,r8; br.cond.sptk.few	4000000000135000 }

l40000000001350F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_set_lines_and_columns; }
	{ nop.m	0x0; adds	r15,0x10,r12; adds	r1,0x0,r38 }
	{ nop.m	0x0; ld2	r40,[r35]; nop.i	0x0; }
	{ ld2	r39,[r15]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BAC0; }
	{ cmp.eq	p06,p07,0x0,r33; adds	r1,0x0,r38; (p07) adds	r15,0x10,r12; }

l4000000000135140:
	{ (p07) ld2	r14,[r15]; (p07) st4	[r14],r33; cmp.eq	p06,p07,0x0,r34; }

l4000000000135146:
	{ mf.a; (p03) nop; cmp.lt	p00,p00,r0,r32; }

l400000000013514C:
	{ nop; cmp4.eq.and	p00,p32,r32,r0; Invalid }

l400000000013515C:
	{ Invalid; Invalid; (p16) break.i	0x2A809 }

l4000000000135166:
	{ break.m	0xAA025; nop; break.i	0x80000 }
	{ Invalid; (p34) nop; Invalid }

;; fpurge: 4000000000135180
;;   Called from:
;;     40000000000EE8AC (in sh_chkwrite)
fpurge proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; nop.m	0x0; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; adds	r36,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C200; }
	{ adds	r8,0x0,r0; adds	r1,0x0,r35; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000001351C0; br.ret	b0; }
40000000001351D0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000001351E0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000001351F0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; zgetline: 4000000000135200
;;   Called from:
;;     400000000010127C (in mapfile_builtin)
;;     400000000010133C (in mapfile_builtin)
zgetline proc
	{ alloc	r41,ar.pfs,0xF,0x0,0xC; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r43,pr }
	{ cmp.eq	p06,p07,0x0,r33; adds	r42,0x0,r1; cmp4.eq	p16,p17,0x0,r35; }
	{ nop.m	0x0; mov	r40,b0; nop.i	0x0 }
	{ cmp.eq.or.andcm	p06,p07,0x0,r34; adds	r36,0x0,r0; (p06) br.cond.dpnt.few	4000000000135460; }

l4000000000135240:
	{ nop.m	0x0; ld8	r38,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r38; (p07) br.cond.dpnt.few	4000000000135440; }

l4000000000135260:
	{ (p17) addl	r46,1,r0; adds	r44,0x0,r32; nop.i	0x0 }

l4000000000135266:
	{ Invalid; nop; (p16) nop }
	{ (p18) nop; (p32) nop; break.b	0x80000 }

l4000000000135280:
	{ nop.m	0x0; nop.i	0x0; (p16) br.call.dptk.many	b0,zreadc; }

l4000000000135290:
	{ adds	r1,0x0,r42; nop.m	0x0; cmp4.lt	p06,p07,0x0,r8 }
	{ adds	r15,0x2,r36; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000135490; }

l40000000001352B0:
	{ nop.m	0x0; ld8	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp.ltu	p06,p07,r15,r14; (p06) br.cond.dptk.few	40000000001353C0; }

l40000000001352D0:
	{ shladd	r39,r14,0x1,r0; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000135370; }

l40000000001352E0:
	{ nop.m	0x0; cmp.ltu	p07,p06,r14,r39; (p07) br.cond.spnt.few	4000000000135380 }

l40000000001352F0:
	{ ld8	r15,[r33]; ld8.a	r37,[r34]; nop.i	0x0; }
	{ add	r14,r15,r14; adds	r14,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; }
	{ st1	[r0],r14; ld8.c.clr	r37,[r34]; nop.i	0x0; }
	{ nop.m	0x0; adds	r37,0xFFFFFFFFFFFFFFFE,r37; nop.i	0x0; }
	{ adds	r37,0xFFFFFFFFFFFFFFFF,r37; nop.i	0x0; sxt4	r8,r37; }

l4000000000135340:
	{ nop.m	0x0; mov	pr,r43,0xFFFFFFFFFFFFFFFE; nop.i	0x0; }
	{ nop.m	0x0; mov.i	ar.pfs,r41; mov.spnt	b0,r40,4000000000135350 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000135370:
	{ addl	r39,16,r0; nop.m	0x0; nop.i	0x0; }

l4000000000135380:
	{ ld8	r44,[r33]; adds	r45,0x0,r39; br.call.sptk.many	b0,xrealloc; }
	{ adds	r1,0x0,r42; nop.m	0x0; cmp.eq	p06,p07,0x0,r8 }
	{ adds	r38,0x0,r8; nop.m	0x0; (p06) br.cond.spnt.few	40000000001354F0; }

l40000000001353B0:
	{ st8	[r8],r33; st8	[r39],r34; nop.i	0x0 }

l40000000001353C0:
	{ adds	r16,0x10,r12; add	r15,r38,r36; adds	r37,0x1,r36 }
	{ adds	r36,0x1,r36; ld1	r14,[r16]; nop.i	0x0; }
	{ st1	[r14],r15; ld1	r14,[r16]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0xA,r14; (p06) br.cond.dptk.few	4000000000135260 }

l4000000000135410:
	{ nop.m	0x0; sxt4	r14,r37; adds	r37,0xFFFFFFFFFFFFFFFF,r37; }
	{ add	r38,r38,r14; nop.m	0x0; sxt4	r8,r37; }
	{ st1	[r0],r38; nop.i	0x0; br.cond.sptk.few	4000000000135340 }

l4000000000135440:
	{ nop.m	0x0; ld8	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	4000000000135260; }

l4000000000135460:
	{ addl	r8,-1,r0; mov	pr,r43,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.spnt	b0,r40,4000000000135470; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l4000000000135490:
	{ cmp4.lt	p06,p07,0x0,r36; cmp.eq	p09,p08,0x0,r38; sxt4	r15,r36 }
	{ adds	r37,0xFFFFFFFFFFFFFFFF,r37; nop.i	0x0; (p06) addl	r16,1,r0 }

l40000000001354B0:
	{ (p08) addl	r14,1,r0; add	r15,r38,r15; sxt4	r8,r37; }

l40000000001354B6:
	{ Invalid; (p04) cmp4.lt	p00,p00,0x25,r22; nop }

l40000000001354C6:
	{ Invalid; (p07) nop; break.i	0x80000 }

l40000000001354CC:
	{ (p07) nop; cmp.lt	p00,p00,r32,r0; czx1.r	r64,r97; }
	{ Invalid; Invalid; break.i	0x1000 }

l40000000001354E6:
	{ break.m	0x4000; nop; (p32) nop }

l40000000001354F0:
	{ ld8	r14,[r34]; nop.m	0x0; adds	r37,0xFFFFFFFFFFFFFFFF,r37; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; sxt4	r8,r37 }
	{ nop.b	0x0; (p07) br.cond.spnt.few	40000000001352F0; br.cond.sptk.few	4000000000135340; }

l400000000013551C:
	{ (p49) cmp.lt.unc	p63,p00,r63,r36; cmp.eq	p00,p00,r32,r0; break.b	0x1000 }
4000000000135520 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
4000000000135530 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; uconvert: 4000000000135540
;;   Called from:
;;     400000000010624C (in read_builtin)
uconvert proc
	{ nop.m	0x0; mov	r2,LC; cmp.eq	p06,p07,0x0,r32 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dpnt.few	40000000001358C0; }

l4000000000135560:
	{ ld1	r14,[r32]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p08,p09,0x2D,r14; cmp4.eq	p06,p07,0x2B,r14; (p08) addl	r15,1,r0; }

l4000000000135580:
	{ nop.m	0x0; (p09) adds	r15,0x0,r0; nop.i	0x0; }

l400000000013558C:
	{ nop; (p02) cmp.lt.unc	p32,p16,r3,r64; (p08) mov	pr,r99,0xE5C0 }
	{ (p09) cmp.lt	p00,p03,r0,r33; czx1.r	r96,r97; Invalid }

l40000000001355A0:
	{ cmp4.eq	p06,p07,0x0,r15; adds	r32,0x1,r32; (p06) addl	r21,1,r0; }

l40000000001355B0:
	{ (p07) addl	r21,-1,r0; cmp.eq	p06,p07,0x0,r32; (p06) br.cond.spnt.few	4000000000135A60; }

l40000000001355B6:
	{ (p03) chk.a.clr	r0,3FFFFFFFFFDB8FB6; Invalid; (p32) nop }

l40000000001355C0:
	{ ld1	r14,[r32]; nop.i	0x0; sxt1	r14,r14; }

l40000000001355D0:
	{ cmp4.eq	p06,p07,0x0,r14; adds	r17,0xFFFFFFFFFFFFFFD0,r14; (p06) br.cond.dpnt.few	4000000000135A60; }

l40000000001355E0:
	{ cmp4.eq	p06,p07,0x2E,r14; zxt1	r14,r17; (p06) br.cond.dpnt.few	4000000000135790; }

l40000000001355F0:
	{ cmp4.ltu	p06,p07,0x9,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000135940; }

l4000000000135600:
	{ (p07) adds	r16,0x1,r32; nop.m	0x0; (p07) adds	r15,0x0,r0; }

l4000000000135606:
	{ addp4	r0,0xFFFFFFFFFFFFE000,r1; (p07) cmp4.eq.and	p00,p02,0x0,r0; (p33) nop }

l4000000000135610:
	{ (p07) sub	r14,r0,r16; nop.i	0x0; (p07) mov.i	LC,r14; }

l4000000000135616:
	{ chk.a.nc	f0,3FFFFFFFFF135E16; break.i	0xAA08E; break.i	0x80000 }

l4000000000135620:
	{ nop.m	0x0; sxt4	r17,r17; shladd	r15,r15,0x2,r15 }
	{ nop.m	0x0; adds	r32,0x0,r16; nop.b	0x0; }
	{ nop.m	0x0; shladd	r15,r15,0x1,r17; br.cloop.sptk.few	40000000001356D0 }

l4000000000135650:
	{ cmp.eq	p06,p07,0x0,r33; nop.m	0x0; sxt4	r21,r21; }
	{ (p07) setf.sig	f6,r21; (p07) setf.sig	f7,r15; nop.i	0x0; }

l4000000000135666:
	{ (p03) srlz.i; nop; break.b	0x80000; }

l400000000013566C:
	{ Invalid; break.i	0x1000; cmp4.eq.and	p00,p32,r32,r0 }
	{ nop; (p34) mov	pr,r32,0x4302; (p16) cmp.eq	p37,p08,r8,r102 }

l4000000000135680:
	{ (p07) getf.sig	r21,f6; (p07) st8	[r21],r33; cmp.eq	p07,p06,0x0,r34 }

l4000000000135686:
	{ Invalid; (p03) nop; add	r0,r0,r32; }

l400000000013568C:
	{ loadrs; mov	pr,r32,0x0; Invalid }

l400000000013569C:
	{ nop; zxt4	r0,r0; break.i	0x1000 }

l40000000001356A0:
	{ addl	r8,1,r0; nop.m	0x0; nop.i	0x0 }

l40000000001356A2:
	{ break.m	0x48000; nop }

l40000000001356B0:
	{ nop.m	0x0; mov.i	LC,r2; br.ret	b0 }

l40000000001356B2:
	{ ld1	r32,[r0]; (p16) nop; Invalid }

l40000000001356C0:
	{ nop.m	0x0; addl	r21,1,r0; br.cond.sptk.few	40000000001355D0 }

l40000000001356D0:
	{ ld1	r14,[r16],1; nop.m	0x0; sxt1	r14,r14; }
	{ adds	r17,0xFFFFFFFFFFFFFFD0,r14; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	4000000000135650; }

l40000000001356F0:
	{ nop.m	0x0; zxt1	r18,r17; cmp4.eq	p06,p07,0x2E,r14 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dpnt.few	40000000001357A0; }

l4000000000135710:
	{ nop.m	0x0; cmp4.ltu	p07,p06,0x9,r18; (p06) br.cond.dptk.few	4000000000135620; }

l4000000000135720:
	{ cmp.eq	p06,p07,0x0,r33; nop.m	0x0; sxt4	r21,r21; }
	{ (p07) setf.sig	f6,r21; (p07) setf.sig	f7,r15; nop.i	0x0; }

l4000000000135736:
	{ (p03) srlz.i; nop; break.b	0x80000; }

l400000000013573C:
	{ Invalid; break.i	0x1000; cmp4.eq.and	p00,p32,r32,r0 }
	{ nop; (p34) mov	pr,r32,0x4302; (p16) cmp.eq	p37,p08,r8,r102 }

l4000000000135750:
	{ (p07) getf.sig	r21,f6; (p07) st8	[r21],r33; cmp.eq	p07,p06,0x0,r34; }

l4000000000135756:
	{ Invalid; (p03) nop; (p01) addl	r0,144192,r0; }

l400000000013575C:
	{ Invalid; mov	pr,r8,0x4680; (p01) mov	pr,r0,0x8400 }

l4000000000135766:
	{ (p04) chk.a.clr	r0,3FFFFFFFFF1B5766; nop; nop; }

l400000000013576C:
	{ (p58) nop; zxt1	r0,r64; break.b	0x1000 }

l4000000000135770:
	{ adds	r8,0x0,r0; nop.m	0x0; nop.i	0x0 }

l4000000000135780:
	{ nop.m	0x0; mov.i	LC,r2; br.ret	b0 }

l4000000000135790:
	{ adds	r15,0x0,r0; nop.m	0x0; nop.i	0x0; }

l40000000001357A0:
	{ nop.m	0x0; adds	r18,0x1,r32; nop.b	0x0 }
	{ adds	r14,0x0,r0; adds	r19,0x0,r0; mov.i	LC,0x5; }

l40000000001357C0:
	{ ld1	r16,[r18],1; shladd	r20,r14,0x2,r14; sxt1	r16,r16; }
	{ adds	r17,0xFFFFFFFFFFFFFFD0,r16; cmp4.eq	p07,p06,0x0,r16; (p07) br.cond.dpnt.few	40000000001359A0; }

l40000000001357E0:
	{ nop.m	0x0; zxt1	r16,r17; sxt4	r17,r17 }
	{ nop.m	0x0; adds	r19,0x1,r19; nop.b	0x0; }
	{ cmp4.ltu	p07,p06,0x9,r16; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000135A10; }

l4000000000135810:
	{ nop.m	0x0; shladd	r14,r20,0x1,r17; br.cloop.sptk.few	40000000001357C0 }

l4000000000135820:
	{ adds	r32,0x7,r32; ld1	r16,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r16,r16; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,0x34,r16; (p06) br.cond.dptk.few	4000000000135920; }

l4000000000135850:
	{ cmp.eq	p06,p07,0x0,r33; addl	r8,1,r0; mov.i	LC,r2 }
	{ nop.m	0x0; sxt4	r21,r21; nop.b	0x0; }
	{ (p07) setf.sig	f6,r21; (p07) setf.sig	f7,r15; nop.i	0x0; }

l4000000000135876:
	{ (p03) srlz.i; nop; break.b	0x80000; }

l400000000013587C:
	{ Invalid; break.i	0x1000; cmp4.eq.and	p00,p32,r32,r0 }
	{ nop; nop; Invalid }

l4000000000135890:
	{ nop.m	0x0; (p07) getf.sig	r21,f6; nop.i	0x0; }

l400000000013589C:
	{ Invalid; (p16) cmp.lt	p37,p08,r8,r102; mov	pr,r104,0xE480 }

l40000000001358A6:
	{ (p03) chk.a.clr	r0,3FFFFFFFFFDB92C6; nop; nop }

l40000000001358B0:
	{ st8	[r14],r34; nop.i	0x0; br.ret	b0 }

l40000000001358C0:
	{ addl	r21,1,r0; cmp.eq	p06,p07,0x0,r33; adds	r15,0x0,r0; }
	{ nop.m	0x0; sxt4	r21,r21; nop.i	0x0 }
	{ (p07) setf.sig	f7,r15; (p07) setf.sig	f6,r21; nop.i	0x0; }

l40000000001358E6:
	{ (p03) srlz.i; nop; break.i	0x80000; }

l40000000001358EC:
	{ Invalid; break.i	0x1000; cmp4.eq.and	p00,p32,r32,r0 }
	{ nop; (p34) mov	pr,r32,0x4302; (p16) cmp.eq	p37,p08,r8,r102 }

l4000000000135900:
	{ (p07) getf.sig	r21,f6; (p07) st8	[r21],r33; cmp.eq	p07,p06,0x0,r34; }

l4000000000135906:
	{ Invalid; (p03) nop; (p01) nop; }

l400000000013590C:
	{ Invalid; Invalid; break.i	0x1000 }

l4000000000135916:
	{ break.m	0x4000; nop; break.i	0x80000 }

l4000000000135920:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x39,r16; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r14,0x1,r14; br.cond.sptk.few	4000000000135850 }

l400000000013593C:
	{ (p57) cmp.lt.unc	p63,p01,r63,r36; nop; (p02) cmp.eq	p32,p00,r69,r5 }

l4000000000135940:
	{ cmp.eq	p06,p07,0x0,r33; sxt4	r21,r21; adds	r15,0x0,r0; }
	{ (p07) setf.sig	f6,r21; (p07) setf.sig	f7,r15; nop.i	0x0; }

l4000000000135956:
	{ (p03) srlz.i; nop; break.b	0x80000; }

l400000000013595C:
	{ Invalid; break.i	0x1000; cmp4.eq.and	p00,p32,r32,r0 }
	{ nop; (p34) mov	pr,r32,0x4302; (p16) cmp.eq	p37,p08,r8,r102 }

l4000000000135970:
	{ (p07) getf.sig	r21,f6; (p07) st8	[r21],r33; cmp.eq	p07,p06,0x0,r34; }

l4000000000135976:
	{ Invalid; (p03) nop; (p01) addl	r0,144192,r0; }

l400000000013597C:
	{ Invalid; mov	pr,r8,0x4680; (p01) mov	pr,r0,0x8400 }

l4000000000135986:
	{ (p04) chk.a.clr	r0,3FFFFFFFFF1B5986; nop; break.i	0x80000; }

l400000000013598C:
	{ (p41) invala; break.i	0x1000; break.b	0x1000 }

l4000000000135990:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000135770 }

l40000000001359A0:
	{ nop.m	0x0; addl	r16,-1180,r1; sxt4	r19,r19 }
	{ setf.sig	f6,r14; ld8	r16,[r16]; nop.i	0x0; }
	{ shladd	r16,r19,0x2,r16; ld4	r16,[r16]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r16,r16; nop.i	0x0; }
	{ nop.m	0x0; setf.sig	f7,r16; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; xma.l	f6,f6,f7,f0; }
	{ getf.sig	r14,f6; nop.i	0x0; br.cond.sptk.few	4000000000135850 }

l4000000000135A10:
	{ cmp.eq	p06,p07,0x0,r33; sxt4	r21,r21; adds	r8,0x0,r0; }
	{ (p07) setf.sig	f6,r21; (p07) setf.sig	f7,r15; nop.i	0x0; }

l4000000000135A26:
	{ (p03) srlz.i; nop; break.b	0x80000; }

l4000000000135A2C:
	{ Invalid; break.i	0x1000; cmp4.eq.and	p00,p32,r32,r0 }
	{ cmp4.eq.or.andcm	p06,p43,r7,r116; (p33) mov	pr,r32,0x4302; (p48) cmp.lt	p35,p08,r8,r102 }

l4000000000135A40:
	{ (p07) getf.sig	r15,f6; (p07) st8	[r15],r33; cmp.eq	p06,p07,0x0,r34; }

l4000000000135A46:
	{ mf.a; (p03) cmp.eq.or.andcm	p00,p50,r34,r7; (p01) nop; }

l4000000000135A4C:
	{ Invalid; Invalid; break.i	0x1000 }

l4000000000135A56:
	{ break.m	0x4000; mov	pr,0x48FFFD3; (p32) nop }

l4000000000135A60:
	{ cmp.eq	p06,p07,0x0,r33; sxt4	r21,r21; adds	r15,0x0,r0; }
	{ (p07) setf.sig	f6,r21; (p07) setf.sig	f7,r15; nop.i	0x0; }

l4000000000135A76:
	{ (p03) srlz.i; nop; break.b	0x80000; }

l4000000000135A7C:
	{ Invalid; break.i	0x1000; cmp4.eq.and	p00,p32,r32,r0 }
	{ nop; (p34) mov	pr,r32,0x4302; (p16) cmp.eq	p37,p08,r8,r102 }

l4000000000135A90:
	{ (p07) getf.sig	r21,f6; (p07) st8	[r21],r33; cmp.eq	p07,p06,0x0,r34; }

l4000000000135A96:
	{ Invalid; (p03) nop; (p01) nop; }

l4000000000135A9C:
	{ Invalid; Invalid; break.i	0x1000 }

l4000000000135AA6:
	{ break.m	0x4000; Invalid; (p32) break.i	0x80001 }
4000000000135AB0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; falarm: 4000000000135AC0
;;   Called from:
;;     40000000001041CC (in fn4000000000104180)
;;     40000000001060BC (in read_builtin)
;;     4000000000106EDC (in read_builtin)
falarm proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; adds	r12,0xFFFFFFFFFFFFFFC0,r12; mov	r34,b2 }
	{ addp4	r32,r32,r0; addp4	r33,r33,r0; adds	r36,0x0,r1; }
	{ adds	r14,0x38,r12; adds	r38,0x30,r12; adds	r37,0x0,r0 }
	{ adds	r39,0x10,r12; st8	[r0],r14; adds	r14,0x40,r12 }
	{ st8	[r0],r38; st8	[r32],r14; adds	r14,0x48,r12; }
	{ st8	[r33],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A420; }
	{ addl	r14,-1,r0; nop.m	0x0; cmp4.lt	p06,p07,r8,r0 }
	{ adds	r1,0x0,r36; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000135B70; }

l4000000000135B40:
	{ nop.m	0x0; adds	r14,0x28,r12; nop.i	0x0; }
	{ ld8	r14,[r14]; cmp.eq	p07,p06,0x0,r14; adds	r14,0x20,r12; }
	{ ld8	r14,[r14]; nop.i	0x0; (p06) adds	r14,0x1,r14; }

l4000000000135B70:
	{ adds	r8,0x0,r14; mov.i	ar.pfs,r35; mov.spnt	b0,r34,4000000000135B70 }
	{ nop.m	0x0; adds	r12,0x40,r12; br.ret	b0; }
4000000000135B90 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000135BA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000135BB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fsleep: 4000000000135BC0
fsleep proc
	{ alloc	r35,ar.pfs,0xA,0x0,0x5; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r34,b2 }
	{ addp4	r32,r32,r0; addp4	r33,r33,r0; adds	r36,0x0,r1; }
	{ adds	r14,0x10,r12; adds	r37,0x0,r0; adds	r38,0x0,r0 }
	{ adds	r39,0x0,r0; adds	r40,0x0,r0; adds	r41,0x10,r12; }
	{ nop.m	0x0; st8	[r14],r8,8; nop.i	0x0; }
	{ st8	[r33],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB00; }
	{ adds	r1,0x0,r36; mov.i	ar.pfs,r35; mov.spnt	b0,r34,4000000000135C20 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

;; sh_modcase: 4000000000135C40
;;   Called from:
;;     4000000000063F2C (in make_variable_value)
;;     40000000000BD87C (in array_modcase)
;;     40000000000C3EFC (in assoc_modcase)
sh_modcase proc
	{ alloc	r61,ar.pfs,0x24,0x0,0x20; adds	r12,0xFFFFFFFFFFFFFFB0,r12; mov	r63,pr }
	{ adds	r62,0x0,r1; cmp.eq	p06,p07,0x0,r32; mov	r60,b4 }
	{ addl	r64,1,r0; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000135C90; }

l4000000000135C70:
	{ ld1	r14,[r32]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dpnt.few	4000000000135CF0 }

l4000000000135C90:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r62; nop.m	0x0; adds	r36,0x0,r8 }
	{ st1	[r0],r8; nop.m	0x0; nop.i	0x0; }

l4000000000135CC0:
	{ adds	r8,0x0,r36; mov	pr,r63,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r61; }
	{ nop.m	0x0; mov.spnt	b0,r60,4000000000135CD0; nop.i	0x0 }
	{ adds	r12,0x50,r12; nop.m	0x0; br.ret	b0; }

l4000000000135CF0:
	{ adds	r43,0x44,r12; adds	r46,0x48,r12; adds	r64,0x0,r32 }
	{ addl	r48,-4097,r0; adds	r42,0x0,r0; adds	r35,0x0,r0; }
	{ st4	[r0],r43; st4	[r0],r46; and	r48,r48,r34 }
	{ adds	r40,0x50,r12; adds	r47,0x24,r12; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r62; adds	r64,0x1,r8; adds	r41,0x0,r8 }
	{ adds	r50,0x28,r12; adds	r49,0x4C,r12; cmp.eq	p17,p16,0x0,r33; }
	{ addl	r44,-9996,r1; adds	r53,0x34,r12; sxt4	r64,r64 }
	{ adds	r54,0x38,r12; adds	r51,0x2C,r12; adds	r52,0x30,r12; }
	{ ld8	r44,[r44]; addl	r57,512,r0; addl	r59,383,r0 }
	{ addl	r58,256,r0; adds	r55,0x3C,r12; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r62; adds	r36,0x0,r8; adds	r64,0x0,r8 }
	{ adds	r65,0x0,r32; adds	r56,0x40,r12; br.call.sptk.many	b0,fn400000000001B180; }
	{ addl	r14,4096,r0; cmp4.eq	p18,p19,0x4,r48; cmp4.eq	p23,p22,0x8,r48 }
	{ cmp4.eq	p25,p24,0x40,r48; cmp4.eq	p29,p28,0x10,r48; adds	r1,0x0,r62; }
	{ and	r34,r14,r34; nop.m	0x0; addl	r14,128,r0 }
	{ cmp4.lt	p07,p06,0x0,r41; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000135CC0; }

l4000000000135DF0:
	{ nop.m	0x0; cmp4.eq	p27,p26,r14,r48; cmp4.eq	p20,p21,0x0,r34; }

l4000000000135E00:
	{ nop.m	0x0; sxt4	r37,r35; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ cmp.eq	p07,p06,0x1,r8; adds	r1,0x0,r62; (p07) add	r14,r36,r37; }

l4000000000135E20:
	{ nop.m	0x0; (p07) ld1	r64,[r14]; nop.i	0x0; }

l4000000000135E2C:
	{ Invalid; mov	pr,r32,0x0; (p08) mov	pr,r16,0x0 }
	{ Invalid; zxt1	r0,r64; break.i	0x1000 }

l4000000000135E40:
	{ adds	r64,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ add	r15,r36,r37; adds	r14,0xFFFFFFFFFFFFFFFF,r8; adds	r1,0x0,r62; }
	{ cmp4.lt	p06,p07,r35,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001365F0; }

l4000000000135E70:
	{ ld1	r14,[r15]; nop.i	0x0; sxt1	r14,r14; }
	{ adds	r64,0x0,r14; nop.m	0x0; nop.i	0x0; }

l4000000000135E90:
	{ st4	[r64],r40; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B860; }
	{ adds	r1,0x0,r62; cmp4.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	4000000000136680 }

l4000000000135EB0:
	{ nop.m	0x0; (p17) br.cond.dpnt.few	4000000000135FC0; br.call.sptk.many	b0,fn400000000001B0C0; }

l4000000000135EBC:
	{ (p16) nop; (p08) invala; nop.b	0x1000 }
	{ cmp.eq	p62,p25,r0,r66; Invalid; mov	pr,r32,0x0 }
	{ (p09) cmp.lt	p01,p11,r64,r33; Invalid; Invalid }

l4000000000135EE0:
	{ ld1	r14,[r65]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r44; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000136450; }

l4000000000135F30:
	{ (p06) addl	r39,1,r0; nop.m	0x0; nop.i	0x0; }

l4000000000135F36:
	{ break.m	0x4000; nop; (p48) nop }

l4000000000135F40:
	{ add	r39,r39,r35; adds	r64,0x0,r36; adds	r65,0x0,r35; }
	{ adds	r66,0x0,r39; nop.i	0x0; br.call.sptk.many	b0,substring; }
	{ adds	r1,0x0,r62; adds	r38,0x0,r8; adds	r64,0x0,r33 }
	{ adds	r65,0x0,r8; addl	r66,32,r0; br.call.sptk.many	b0,strmatch; }
	{ adds	r1,0x0,r62; nop.m	0x0; adds	r45,0x0,r8 }
	{ adds	r64,0x0,r38; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r62; cmp4.eq	p06,p07,0x1,r45; (p06) br.cond.dpnt.few	4000000000136190; }

l4000000000135FB0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000135FC0:
	{ (p18) br.cond.dpnt.few	4000000000136900; (p23) br.cond.dpnt.few	4000000000136970; (p25) br.cond.dpnt.few	4000000000136A40; }

l4000000000135FC6:
	{ nop; (p06) nop; }

l4000000000135FCC:
	{ (p20) chk.a.clr	r1,3FFFFFFFFFF06BCC; Invalid; Invalid }

l4000000000135FD0:
	{ (p27) br.cond.dpnt.few	4000000000136A70; nop.b	0x0; (p29) br.cond.dpnt.few	4000000000136AF0; }

l4000000000135FD6:
	{ nop; nop; (p55) nop }

l4000000000135FE0:
	{ (p28) adds	r39,0x0,r48; nop.m	0x0; nop.i	0x0; }

l4000000000135FE6:
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ break.m	0x4000; nop; break.i	0x80000 }

l4000000000136000:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ ld4	r38,[r40]; nop.m	0x0; cmp.eq	p07,p06,0x1,r8 }
	{ adds	r1,0x0,r62; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000136050; }

l4000000000136030:
	{ nop.m	0x0; and	r14,0xFFFFFFFFFFFFFF80,r38; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dpnt.few	40000000001361C0; }

l4000000000136050:
	{ cmp4.eq	p06,p07,0x2,r39; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001369A0; }

l4000000000136060:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x2,r39; (p06) br.cond.dptk.few	4000000000136880; }

l4000000000136070:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x1,r39; (p06) br.cond.dpnt.few	4000000000136550 }

l4000000000136080:
	{ nop.m	0x0; add	r14,r36,r37; nop.i	0x0; }
	{ st1	[r38],r14; nop.m	0x0; nop.i	0x0 }

l40000000001360A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r62; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	4000000000136380 }

l40000000001360C0:
	{ add	r65,r36,r37; ld1	r14,[r65]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r44; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	40000000001363B0; }

l4000000000136120:
	{ (p06) addl	r14,1,r0; nop.m	0x0; nop.i	0x0; }

l4000000000136126:
	{ break.m	0x4000; nop; break.i	0x80000 }

l4000000000136130:
	{ nop.m	0x0; add	r35,r14,r35; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r35,r41; (p06) br.cond.dptk.few	4000000000135E00; }

l4000000000136150:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000136160:
	{ adds	r8,0x0,r36; mov	pr,r63,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r61; }
	{ nop.m	0x0; mov.spnt	b0,r60,4000000000136170; nop.i	0x0 }
	{ adds	r12,0x50,r12; nop.m	0x0; br.ret	b0 }

l4000000000136190:
	{ adds	r35,0x0,r39; nop.m	0x0; addl	r42,1,r0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r35,r41; (p06) br.cond.dptk.few	4000000000135E00 }

l40000000001361B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000136160 }

l40000000001361C0:
	{ add	r38,r32,r37; nop.m	0x0; sub	r66,r41,r35 }
	{ adds	r64,0x0,r40; nop.m	0x0; adds	r67,0x0,r43; }
	{ adds	r65,0x0,r38; sxt4	r66,r66; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r1,0x0,r62; cmp.ltu	p06,p07,0x1,r14; }
	{ (p07) ld1	r14,[r38]; nop.m	0x0; sxt1	r14,r14; }

l4000000000136206:
	{ chk.a.nc	f0,3FFFFFFFFF136A06; (p07) cmp4.eq	p00,p00,r14,r20; (p01) nop }

l4000000000136216:
	{ chk.a.nc	f0,3FFFFFFFFF136A16; nop; break.i	0x80000 }

l4000000000136220:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r8; nop.i	0x0; }
	{ (p07) st4	[r0],r40; nop.m	0x0; nop.i	0x0 }

l4000000000136236:
	{ break.m	0x4000; nop; (p32) nop }

l4000000000136240:
	{ cmp4.eq	p06,p07,0x2,r39; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000136BD0; }

l4000000000136242:
	{ (p48) break.m	0x730E9; nop; Invalid }

l4000000000136246:
	{ chk.a.nc	r0,3FFFFFFFFF136A46; nop; break.i	0x80000 }

l4000000000136248:
	{ (p16) nop; break.i	0x11430; nop }

l400000000013624C:
	{ Invalid; cmp.lt	p00,p00,r32,r0; (p32) nop }

l400000000013624E:
	{ (p24) break.m	0x228; (p04) nop; mov	r24,ip }

l400000000013625C:
	{ (p06) cmp.lt	p01,p17,r0,r33; czx1.r	r100,r97; mov	pr,r32,0x0 }

l400000000013625E:
	{ (p16) nop; (p29) break.i	0x398; Invalid }

l4000000000136262:
	{ (p50) break.m	0x730E9; dep	r32,r0,r64,63,2; Invalid }

l4000000000136266:
	{ chk.a.nc	r0,3FFFFFFFFF136A66; nop; break.i	0x80000 }

l4000000000136268:
	{ (p16) fwb; break.i	0x10430; czx1.l	r8,r0 }

l400000000013626C:
	{ (p01) invala; cmp.lt	p00,p00,r32,r0; mov	pr,r105,0xE6D0 }

l400000000013626E:
	{ (p24) break.m	0x208; (p04) nop; (p29) nop }

l4000000000136272:
	{ Invalid; (p52) nop; Invalid }

l400000000013627C:
	{ (p49) nop; cmp.lt	p00,p00,r32,r0; (p04) rfi }

l400000000013627E:
	{ Invalid; Invalid; Invalid }

l4000000000136282:
	{ Invalid; break.i	0x2020A; Invalid }

l4000000000136284:
	{ nop; break.i	0x100002; dep	r8,r1,r64,15,1; }

l4000000000136288:
	{ (p05) break.m	0x404; Invalid; (p24) break.i	0x10802 }

l400000000013628C:
	{ Invalid; zxt1	r64,r64; break.i	0x1000 }

l400000000013628E:
	{ nop; (p04) nop }
	{ (p07) break.m	0x10B; (p04) nop; (p01) nop }

l40000000001362A2:
	{ invala; (p32) nop; Invalid }
	{ Invalid; nop; Invalid }
	{ break.m	0x20; tbit.z	p32,p00,r0,0x0; Invalid }
	{ invala; (p32) nop; nop }
	{ (p20) break.m	0x710F0; Invalid; (p02) br.call.sptk.few	b3,b0 }
	{ (p48) break.m	0x4200A; nop; Invalid }
	{ break.m	0x20; tbit.z	p32,p00,r0,0x0; Invalid }
	{ Invalid; nop; Invalid }
	{ (p32) addl	r15,262208,r0; (p20) nop; (p02) nop }
	{ (p02) cmp4.eq.or.andcm	p03,p33,r64,r112; (p33) break.i	0x40010; Invalid }
	{ (p32) break.m	0x23003; cmp.ltu	p32,p00,r0,r0; Invalid }
	{ (p32) break.m	0x4200F; nop; Invalid }
	{ (p32) nop; cmp.lt.unc	p02,p01,r65,r122; Invalid }
	{ break.m	0x20; break.i	0x20; nop }

l4000000000136380:
	{ adds	r35,0x1,r35; nop.m	0x0; nop.i	0x0; }

l4000000000136390:
	{ nop.m	0x0; cmp4.lt	p06,p07,r35,r41; (p06) br.cond.dptk.few	4000000000135E00 }

l40000000001363A0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000136160 }

l40000000001363B0:
	{ ld4	r15,[r43]; sub	r66,r41,r35; adds	r64,0x0,r0 }
	{ adds	r67,0x0,r43; ld4	r14,[r46]; nop.i	0x0; }
	{ st4	[r15],r51; st4	[r14],r52; sxt4	r66,r66 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; nop.m	0x0; adds	r1,0x0,r62; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000136CC0; }

l4000000000136410:
	{ adds	r35,0x1,r35; ld4	r15,[r51]; nop.i	0x0 }
	{ ld4	r14,[r52]; st4	[r15],r43; nop.i	0x0 }
	{ st4	[r14],r46; cmp4.lt	p06,p07,r35,r41; (p06) br.cond.dptk.few	4000000000135E00 }

l4000000000136440:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000136160 }

l4000000000136450:
	{ ld4	r15,[r43]; sub	r66,r41,r35; adds	r67,0x0,r43 }
	{ adds	r64,0x0,r0; ld4	r14,[r46]; nop.i	0x0; }
	{ st4	[r15],r53; st4	[r14],r54; sxt4	r66,r66 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; nop.m	0x0; adds	r1,0x0,r62 }
	{ adds	r64,0x0,r36; nop.m	0x0; adds	r65,0x0,r35; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001367D0; }

l40000000001364C0:
	{ nop.m	0x0; ld4	r15,[r53]; adds	r39,0x1,r35 }
	{ ld4	r14,[r54]; st4	[r15],r43; nop.i	0x0 }
	{ st4	[r14],r46; adds	r66,0x0,r39; br.call.sptk.many	b0,substring; }
	{ adds	r1,0x0,r62; adds	r38,0x0,r8; adds	r64,0x0,r33 }
	{ adds	r65,0x0,r8; addl	r66,32,r0; br.call.sptk.many	b0,strmatch; }
	{ adds	r1,0x0,r62; nop.m	0x0; adds	r45,0x0,r8 }
	{ adds	r64,0x0,r38; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r62; cmp4.eq	p06,p07,0x1,r45; (p07) br.cond.dptk.few	4000000000135FC0 }

l4000000000136540:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000136190 }

l4000000000136550:
	{ nop.m	0x0; sxt4	r39,r38; br.call.sptk.many	b0,fn400000000001C3C0; }
	{ ld8	r14,[r8]; adds	r1,0x0,r62; shladd	r14,r39,0x1,r14; }
	{ ld2	r14,[r14]; and	r14,r58,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000136080 }

l4000000000136590:
	{ nop.m	0x0; adds	r14,0x80,r38; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,r59,r14; (p06) br.cond.dptk.few	4000000000136080 }

l40000000001365B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C3A0; }
	{ ld8	r14,[r8]; adds	r1,0x0,r62; shladd	r39,r39,0x2,r14 }
	{ add	r14,r36,r37; ld4	r38,[r39]; nop.i	0x0; }
	{ st1	[r38],r14; nop.i	0x0; br.cond.sptk.few	40000000001360A0 }

l40000000001365F0:
	{ sub	r66,r8,r35; adds	r64,0x0,r49; sxt4	r37,r35 }
	{ st4	[r0],r47; st4	[r0],r50; adds	r67,0x0,r47; }
	{ add	r38,r36,r37; nop.m	0x0; sxt4	r66,r66; }
	{ adds	r65,0x0,r38; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r8,0xFFFFFFFFFFFFFFFF,r8; adds	r1,0x0,r62; cmp.ltu	p07,p06,0xFFFFFFFFFFFFFFFC,r8; }
	{ (p07) ld1	r64,[r38]; nop.m	0x0; sxt1	r64,r64; }

l4000000000136646:
	{ chk.a.nc	f0,3FFFFFFFFF136E46; (p32) nop; add	r0,r0,r32 }
	{ (p32) fwb; nop; nop; }

l400000000013665C:
	{ Invalid; Invalid; break.i	0x1000 }
	{ (p16) nop; cmp.eq.unc	p00,p16,r15,r64; mov	pr,r66,0xE600 }
	{ Invalid; break.i	0x1000; break.i	0x1000 }

l4000000000136680:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ add	r65,r36,r37; nop.m	0x0; adds	r1,0x0,r62 }
	{ cmp.ltu	p07,p06,0x1,r8; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000136960; }

l40000000001366B0:
	{ ld1	r14,[r65]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r44; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000136740; }

l4000000000136700:
	{ (p06) addl	r14,1,r0; nop.m	0x0; nop.i	0x0; }

l4000000000136706:
	{ break.m	0x4000; nop; break.i	0x80000 }

l4000000000136710:
	{ nop.m	0x0; add	r35,r14,r35; adds	r42,0x0,r0; }

l4000000000136720:
	{ nop.m	0x0; cmp4.lt	p06,p07,r35,r41; (p06) br.cond.dptk.few	4000000000135E00 }

l4000000000136730:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000136160 }

l4000000000136740:
	{ ld4	r15,[r43]; sub	r66,r41,r35; adds	r64,0x0,r0 }
	{ adds	r67,0x0,r43; ld4	r14,[r46]; adds	r42,0x0,r0; }
	{ st4	[r15],r55; st4	[r14],r56; sxt4	r66,r66 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; nop.m	0x0; adds	r1,0x0,r62; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000136930; }

l40000000001367A0:
	{ nop.m	0x0; ld4	r15,[r55]; adds	r35,0x1,r35 }
	{ ld4	r14,[r56]; nop.i	0x0; nop.i	0x0 }
	{ st4	[r15],r43; st4	[r14],r46; br.cond.sptk.few	4000000000136720 }

l40000000001367D0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r39,0x0,r8; (p07) br.cond.spnt.few	4000000000135F40; }

l40000000001367EC:
	{ (p59) nop; break.i	0x1000; break.i	0x1000 }

l40000000001367F0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000136800:
	{ adds	r39,0x1,r35; adds	r64,0x0,r36; adds	r65,0x0,r35; }
	{ adds	r66,0x0,r39; nop.i	0x0; br.call.sptk.many	b0,substring; }
	{ adds	r1,0x0,r62; adds	r38,0x0,r8; adds	r64,0x0,r33 }
	{ adds	r65,0x0,r8; addl	r66,32,r0; br.call.sptk.many	b0,strmatch; }
	{ adds	r1,0x0,r62; nop.m	0x0; adds	r45,0x0,r8 }
	{ adds	r64,0x0,r38; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r62; cmp4.eq	p06,p07,0x1,r45; (p07) br.cond.dptk.few	4000000000135FC0 }

l4000000000136870:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000136190; }

l4000000000136880:
	{ cmp4.eq	p06,p07,0x10,r39; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001368A0; }

l4000000000136890:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x20,r39; (p07) br.cond.dptk.few	4000000000136080 }

l40000000001368A0:
	{ adds	r64,0x0,r38; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B780; }
	{ nop.m	0x0; adds	r1,0x0,r62; adds	r64,0x0,r38 }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	4000000000136AA0 }

l40000000001368D0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A760; }
	{ add	r14,r36,r37; adds	r38,0x0,r8; adds	r1,0x0,r62; }
	{ st1	[r38],r14; nop.i	0x0; br.cond.sptk.few	40000000001360A0 }

l4000000000136900:
	{ (p21) cmp4.eq	p07,p06,0x0,r42; addl	r42,1,r0; (p20) cmp4.lt	p06,p07,0x0,r35; }

l4000000000136906:
	{ (p21) nop; (p03) nop; add	r0,r0,r32 }

l4000000000136910:
	{ nop.m	0x0; (p06) addl	r39,1,r0; nop.i	0x0; }

l400000000013691C:
	{ invala; cmp4.eq.or.andcm	p00,p32,r32,r0; zxt4	r0,r0 }

l400000000013692C:
	{ (p55) nop; cmp.lt	p00,p00,r32,r0; czx1.r	r0,r65 }

l4000000000136930:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r14,0x0,r8; (p07) br.cond.spnt.few	4000000000136710; }

l400000000013694C:
	{ (p46) nop; break.i	0x1000; break.b	0x1000 }

l4000000000136950:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000136960:
	{ adds	r35,0x1,r35; adds	r42,0x0,r0; br.cond.sptk.few	4000000000136720; }

l4000000000136970:
	{ (p21) cmp4.eq	p07,p06,0x0,r42; addl	r42,1,r0; (p20) cmp4.lt	p06,p07,0x0,r35; }

l4000000000136976:
	{ (p21) nop; (p03) nop; add	r0,r0,r32 }

l4000000000136980:
	{ nop.m	0x0; (p06) addl	r39,2,r0; nop.i	0x0; }

l400000000013698C:
	{ Invalid; cmp4.eq.or.andcm	p00,p32,r32,r0; zxt4	r0,r0 }

l400000000013699C:
	{ Invalid; cmp.eq	p00,p00,r32,r0; (p04) break.b	0x164C0 }

l40000000001369A0:
	{ nop.m	0x0; sxt4	r39,r38; br.call.sptk.many	b0,fn400000000001C3C0; }
	{ ld8	r14,[r8]; adds	r1,0x0,r62; shladd	r14,r39,0x1,r14; }
	{ ld2	r14,[r14]; and	r14,r57,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000136080 }

l40000000001369E0:
	{ nop.m	0x0; adds	r14,0x80,r38; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,r59,r14; (p06) br.cond.dptk.few	4000000000136080 }

l4000000000136A00:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A340; }
	{ ld8	r14,[r8]; adds	r1,0x0,r62; shladd	r39,r39,0x2,r14 }
	{ add	r14,r36,r37; ld4	r38,[r39]; nop.i	0x0; }
	{ st1	[r38],r14; nop.i	0x0; br.cond.sptk.few	40000000001360A0 }

l4000000000136A40:
	{ (p21) cmp4.eq	p07,p06,0x0,r42; addl	r42,1,r0; (p20) cmp4.lt	p06,p07,0x0,r35; }

l4000000000136A46:
	{ (p21) nop; (p03) nop; add	r0,r0,r32 }

l4000000000136A50:
	{ nop.m	0x0; (p06) adds	r39,0x0,r0; nop.i	0x0; }

l4000000000136A5C:
	{ invala; cmp4.eq.or.andcm	p00,p32,r32,r0; zxt4	r0,r0 }

l4000000000136A6C:
	{ (p45) cmp4.le.and	p62,p35,r0,r36; dep	r64,r106,r97,62,13; (p21) cmp4.gt.or.andcm	p00,p18,r0,r0 }

l4000000000136A70:
	{ (p21) cmp4.eq	p06,p07,0x0,r42; addl	r42,1,r0; (p20) cmp4.lt	p07,p06,0x0,r35; }

l4000000000136A76:
	{ (p21) nop; (p03) nop; add	r0,r0,r32 }

l4000000000136A80:
	{ nop.m	0x0; (p06) addl	r39,1,r0; nop.i	0x0; }

l4000000000136A8C:
	{ invala; cmp4.eq.or.andcm	p00,p32,r32,r0; zxt1	r0,r64 }

l4000000000136A9C:
	{ Invalid; break.i	0x1000; break.b	0x1000 }

l4000000000136AA0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A4E0; }
	{ adds	r1,0x0,r62; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	4000000000136080 }

l4000000000136AC0:
	{ adds	r64,0x0,r38; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C220; }
	{ add	r14,r36,r37; adds	r38,0x0,r8; adds	r1,0x0,r62; }
	{ st1	[r38],r14; nop.i	0x0; br.cond.sptk.few	40000000001360A0 }

l4000000000136AF0:
	{ cmp4.eq	p06,p07,0x0,r42; addl	r42,1,r0; (p06) addl	r39,16,r0; }

l4000000000136B00:
	{ nop.m	0x0; (p07) adds	r39,0x0,r0; br.cond.sptk.few	4000000000136000; }

l4000000000136B0C:
	{ (p40) invala; cmp.lt	p00,p00,r32,r0; (p16) mov	pr,r105,0xE6C0 }
4000000000136B10 10 00 00 00 01 00 60 08 9C 0E F3 03 90 F5 FF 4A ......`........J
4000000000136B20 11 00 00 00 01 00 00 00 00 02 00 00 A8 58 EE 58 .............X.X
4000000000136B30 08 00 00 00 01 00 60 02 A0 20 20 20 00 F0 01 84 ......`..   ....
4000000000136B40 0B 70 00 10 18 10 00 00 00 02 00 E0 04 30 59 00 .p...........0Y.
4000000000136B50 0B 70 9C 1C 10 20 E0 00 38 10 20 00 00 00 04 00 .p... ..8. .....
4000000000136B60 09 00 00 00 01 00 E0 D0 39 18 40 00 00 00 04 00 ........9.@.....
4000000000136B70 10 00 00 00 01 00 60 00 38 0E 73 03 30 F5 FF 4A ......`.8.s.0..J
4000000000136B80 09 00 00 00 01 00 E0 00 98 02 42 00 00 00 04 00 ..........B.....
4000000000136B90 10 00 00 00 01 00 60 D8 39 0E 69 03 10 F5 FF 4A ......`.9.i....J
4000000000136BA0 11 00 00 00 01 00 00 00 00 02 00 00 08 58 EE 58 .............X.X
4000000000136BB0 03 70 00 10 18 10 10 00 F8 00 42 E0 74 72 44 80 .p........B.trD.
4000000000136BC0 10 08 02 4E 10 10 00 00 00 02 00 00 20 F7 FF 48 ...N........ ..H
4000000000136BD0 11 00 00 00 01 00 00 00 00 02 00 00 F8 57 EE 58 .............W.X
4000000000136BE0 08 00 00 00 01 00 60 02 A0 20 20 20 00 F0 01 84 ......`..   ....
4000000000136BF0 0B 70 00 10 18 10 00 00 00 02 00 E0 04 30 59 00 .p...........0Y.
4000000000136C00 0B 70 9C 1C 10 20 E0 00 38 10 20 00 00 00 04 00 .p... ..8. .....
4000000000136C10 09 00 00 00 01 00 E0 C8 39 18 40 00 00 00 04 00 ........9.@.....
4000000000136C20 10 00 00 00 01 00 60 00 38 0E 73 03 80 F4 FF 4A ......`.8.s....J
4000000000136C30 09 00 00 00 01 00 E0 00 98 02 42 00 00 00 04 00 ..........B.....
4000000000136C40 10 00 00 00 01 00 60 D8 39 0E 69 03 60 F4 FF 4A ......`.9.i.`..J
4000000000136C50 11 00 00 00 01 00 00 00 00 02 00 00 F8 36 EE 58 .............6.X
4000000000136C60 03 70 00 10 18 10 10 00 F8 00 42 E0 74 72 44 80 .p........B.trD.
4000000000136C70 10 08 02 4E 10 10 00 00 00 02 00 00 70 F6 FF 48 ...N........p..H
4000000000136C80 11 00 00 00 01 00 00 00 00 02 00 00 68 38 EE 58 ............h8.X
4000000000136C90 10 08 00 7C 00 21 60 00 20 0E 73 03 10 F4 FF 4A ...|.!`. .s....J
4000000000136CA0 11 00 02 4C 00 21 00 00 00 02 00 00 88 55 EE 58 ...L.!.......U.X
4000000000136CB0 10 08 00 7C 00 21 10 04 20 00 42 00 30 F6 FF 48 ...|.!.. .B.0..H

l4000000000136CC0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ (p07) adds	r14,0x0,r8; nop.i	0x0; (p07) br.cond.spnt.few	4000000000136130; }

l4000000000136CD6:
	{ chk.a.nc	f0,3FFFFFFFFF1374D6; nop; break.i	0x80000 }

l4000000000136CE0:
	{ nop.m	0x0; adds	r35,0x1,r35; br.cond.sptk.few	4000000000136390; }
4000000000136CF0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; input_avail: 4000000000136D00
;;   Called from:
;;     4000000000104B4C (in read_builtin)
input_avail proc
	{ alloc	r36,ar.pfs,0xC,0x0,0x7; adds	r12,0xFFFFFFFFFFFFFEF0,r12; nop.b	0x0 }
	{ adds	r37,0x0,r1; mov	r38,LC; cmp4.lt	p06,p07,r32,r0; }
	{ nop.m	0x0; adds	r14,0x90,r12; mov	r35,b3 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000136EA0; }

l4000000000136D40:
	{ nop.m	0x0; mov.i	LC,0xF; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000136D60:
	{ st8	[r14],r8,8; nop.i	0x0; br.cloop.sptk.few	4000000000136D60; }

l4000000000136D70:
	{ nop.m	0x0; adds	r14,0x10,r12; mov.i	LC,0xF; }

l4000000000136D80:
	{ st8	[r14],r8,8; nop.i	0x0; br.cloop.sptk.few	4000000000136D80 }

l4000000000136D90:
	{ nop.m	0x0; sxt4	r34,r32; addl	r33,1,r0; }
	{ adds	r39,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001ADE0; }
	{ and	r15,0x3F,r32; nop.m	0x0; adds	r14,0x90,r12 }
	{ adds	r1,0x0,r37; adds	r39,0x0,r34; shladd	r8,r8,0x3,r14; }
	{ nop.m	0x0; ld8	r14,[r8]; nop.i	0x0; }
	{ nop.m	0x0; shl	r33,r33,r15; or	r14,r33,r14; }
	{ st8	[r14],r8; nop.i	0x0; br.call.sptk.many	b0,fn400000000001ADE0; }
	{ adds	r14,0x10,r12; adds	r43,0x110,r12; adds	r15,0x118,r12 }
	{ adds	r1,0x0,r37; adds	r39,0x1,r32; adds	r40,0x90,r12; }
	{ nop.m	0x0; shladd	r8,r8,0x3,r14; adds	r41,0x0,r0 }
	{ st8	[r0],r43; st8	[r0],r15; adds	r42,0x10,r12; }
	{ ld8	r14,[r8]; or	r14,r33,r14; nop.i	0x0; }
	{ st8	[r14],r8; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB00; }
	{ cmp4.lt	p06,p07,0x0,r8; adds	r1,0x0,r37; (p06) addl	r8,1,r0; }

l4000000000136E70:
	{ (p07) adds	r8,0x0,r0; mov.i	ar.pfs,r36; mov.i	LC,r38; }

l4000000000136E76:
	{ break.m	0xAA024; break.i	0xAA0A6; break.i	0x80000 }
	{ Invalid; nop; nop }
	{ break.m	0x4000; Invalid; nop }

l4000000000136EA0:
	{ addl	r8,-1,r0; mov.i	ar.pfs,r36; mov.i	LC,r38; }
	{ nop.m	0x0; mov.spnt	b0,r35,4000000000136EB0; nop.i	0x0 }
	{ adds	r12,0x110,r12; nop.m	0x0; br.ret	b0; }
4000000000136ED0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
4000000000136EE0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
4000000000136EF0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; fnx_tofs: 4000000000136F00
fnx_tofs proc
	{ nop.m	0x0; adds	r8,0x0,r32; br.ret	b0; }
4000000000136F10 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000136F20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000136F30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fnx_fromfs: 4000000000136F40
;;   Called from:
;;     400000000012092C (in glob_vector)
;;     400000000012092C (in glob_vector)
fnx_fromfs proc
	{ nop.m	0x0; adds	r8,0x0,r32; br.ret	b0; }
4000000000136F50 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
4000000000136F60 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
4000000000136F70 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; u32tochar: 4000000000136F80
u32tochar proc
	{ nop.m	0x0; sxt4	r32,r32; nop.b	0x0 }
	{ addl	r15,255,r0; addl	r14,1,r0; addl	r8,1,r0; }
	{ nop.m	0x0; cmp.ltu	p07,p06,r15,r32; nop.i	0x0; }
	{ (p06) st1	[r32],r33; nop.i	0x0; (p06) br.cond.dptk.few	4000000000137000 }

l4000000000136FB6:
	{ chk.a.nc	r0,3FFFFFFFFF1377B6; nop; (p32) nop }

l4000000000136FC0:
	{ addl	r14,65535,r0; adds	r15,0x0,r33; extr	r16,r32,8,56; }
	{ nop.m	0x0; cmp.ltu	p07,p06,r14,r32; (p07) br.cond.dptk.few	4000000000137020 }

l4000000000136FE0:
	{ nop.m	0x0; st1	[r15],r1,1; addl	r14,2,r0 }
	{ addl	r8,2,r0; st1	[r32],r15; nop.i	0x0 }

l4000000000137000:
	{ nop.m	0x0; add	r33,r33,r14; nop.i	0x0; }
	{ st1	[r0],r33; nop.i	0x0; br.ret	b0 }

l4000000000137020:
	{ adds	r15,0x0,r33; addl	r14,4,r0; extr.u	r18,r32,24,40 }
	{ adds	r17,0x2,r33; adds	r16,0x3,r33; extr.u	r19,r32,16,48; }
	{ st1	[r15],r1,1; add	r33,r33,r14; extr	r18,r32,8,56 }
	{ addl	r8,4,r0; st1	[r32],r16; nop.i	0x0; }
	{ st1	[r19],r15; st1	[r18],r17; nop.i	0x0; }
	{ st1	[r0],r33; nop.i	0x0; br.ret	b0; }

;; u32toutf8: 4000000000137080
u32toutf8 proc
	{ cmp4.lt	p07,p06,0x7F,r32; addl	r14,1,r0; addl	r8,1,r0; }
	{ (p06) st1	[r32],r33; nop.i	0x0; (p06) br.cond.dptk.few	4000000000137100 }

l4000000000137096:
	{ chk.a.nc	r0,3FFFFFFFFF137896; nop; (p32) nop }

l40000000001370A0:
	{ addl	r14,2047,r0; adds	r15,0x0,r33; nop.b	0x0 }
	{ and	r16,0x3F,r32; nop.m	0x0; extr	r17,r32,6,26; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r14,r32; (p07) br.cond.dptk.few	4000000000137120 }

l40000000001370D0:
	{ or	r17,0xFFFFFFFFFFFFFFC0,r17; nop.m	0x0; or	r16,0xFFFFFFFFFFFFFF80,r16 }
	{ addl	r14,2,r0; addl	r8,2,r0; nop.i	0x0 }
	{ st1	[r15],r1,1; st1	[r16],r15; nop.i	0x0 }

l4000000000137100:
	{ nop.m	0x0; add	r33,r33,r14; nop.i	0x0; }
	{ st1	[r0],r33; nop.i	0x0; br.ret	b0 }

l4000000000137120:
	{ adds	r15,0x0,r33; and	r17,0x3F,r32; extr	r18,r32,12,20 }
	{ addl	r14,3,r0; adds	r16,0x2,r33; addl	r8,3,r0; }
	{ or	r18,0xFFFFFFFFFFFFFFE0,r18; extr.u	r32,r32,6,6; or	r17,0xFFFFFFFFFFFFFF80,r17 }
	{ add	r33,r33,r14; st1	[r15],r1,1; or	r32,0xFFFFFFFFFFFFFF80,r32 }
	{ st1	[r17],r16; nop.i	0x0; nop.i	0x0 }
	{ st1	[r32],r15; st1	[r0],r33; br.ret	b0; }

;; u32cconv: 4000000000137180
u32cconv proc
	{ alloc	r35,ar.pfs,0x7,0x0,0x5; mov	r34,b2; nop.b	0x0 }
	{ adds	r36,0x0,r1; adds	r37,0x0,r33; adds	r38,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A5A0; }
	{ adds	r1,0x0,r36; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000001371C0; br.ret	b0; }
40000000001371D0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000001371E0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000001371F0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; mbstrlen: 4000000000137200
mbstrlen proc
	{ alloc	r37,ar.pfs,0xB,0x0,0x7; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ addl	r34,-9996,r1; adds	r38,0x0,r1; mov	r36,b4; }
	{ adds	r14,0x10,r12; nop.m	0x0; adds	r35,0x18,r12 }
	{ ld8	r34,[r34]; nop.m	0x0; adds	r33,0x0,r0; }
	{ st8	[r0],r14; ld1	r14,[r32]; nop.i	0x0 }
	{ st8	[r0],r35; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000001372F0; }

l4000000000137270:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000137280:
	{ nop.m	0x0; extr.u	r15,r14,5,3; and	r14,0x1F,r14 }
	{ addl	r8,1,r0; shladd	r15,r15,0x2,r34; nop.i	0x0; }
	{ ld4	r15,[r15]; nop.m	0x0; shr.u	r15,r15,r14; }
	{ nop.m	0x0; tbit.z	p07,p06,r15,0x0; (p07) br.cond.dpnt.few	4000000000137310; }

l40000000001372C0:
	{ add	r32,r32,r8; nop.m	0x0; adds	r33,0x1,r33; }
	{ ld1	r14,[r32]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	4000000000137280 }

l40000000001372F0:
	{ adds	r8,0x0,r33; mov.i	ar.pfs,r37; mov.spnt	b0,r36,40000000001372F0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l4000000000137310:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r38; adds	r39,0x0,r0; adds	r40,0x0,r32 }
	{ adds	r41,0x0,r8; adds	r42,0x0,r35; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; cmp.eq	p07,p06,0x0,r8; nop.i	0x0 }
	{ adds	r15,0x10,r12; adds	r1,0x0,r38; (p07) br.cond.dpnt.few	40000000001372F0; }

l4000000000137360:
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.spnt.few	4000000000137390; }

l4000000000137370:
	{ ld8	r14,[r15]; nop.m	0x0; addl	r8,1,r0; }
	{ st8	[r14],r35; nop.m	0x0; nop.i	0x0 }

l4000000000137390:
	{ ld8	r14,[r35]; add	r32,r32,r8; adds	r15,0x10,r12 }
	{ adds	r33,0x1,r33; st8	[r14],r15; nop.i	0x0 }
	{ ld1	r14,[r32]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	4000000000137280 }

l40000000001373D0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000001372F0; }
40000000001373E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000001373F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; mbsmbchar: 4000000000137400
;;   Called from:
;;     4000000000095E7C (in pat_subst)
;;     4000000000095E7C (in pat_subst)
;;     400000000009647C (in pat_subst)
;;     40000000001272EC (in xstrmatch)
;;     40000000001274AC (in xstrmatch)
mbsmbchar proc
	{ alloc	r35,ar.pfs,0x9,0x0,0x5; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ addl	r33,-9996,r1; adds	r36,0x0,r1; mov	r34,b2; }
	{ adds	r14,0x10,r12; ld8	r33,[r33]; nop.i	0x0; }
	{ st8	[r0],r14; ld1	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000001374D0; }

l4000000000137460:
	{ nop.m	0x0; extr.u	r15,r14,5,3; and	r14,0x1F,r14; }
	{ nop.m	0x0; shladd	r15,r15,0x2,r33; nop.i	0x0; }
	{ ld4	r15,[r15]; nop.m	0x0; shr.u	r15,r15,r14; }
	{ nop.m	0x0; tbit.z	p06,p07,r15,0x0; (p06) br.cond.dpnt.few	4000000000137500 }

l40000000001374A0:
	{ adds	r32,0x1,r32; ld1	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000137460 }

l40000000001374D0:
	{ adds	r32,0x0,r0; nop.m	0x0; nop.i	0x0; }

l40000000001374E0:
	{ adds	r8,0x0,r32; mov.i	ar.pfs,r35; mov.spnt	b0,r34,40000000001374E0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l4000000000137500:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r36; adds	r38,0x0,r32; adds	r37,0x0,r0 }
	{ adds	r39,0x0,r8; adds	r40,0x10,r12; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; nop.m	0x0; cmp.eq	p06,p07,0x0,r8 }
	{ adds	r1,0x0,r36; nop.m	0x0; (p06) br.cond.dpnt.few	40000000001374D0; }

l4000000000137550:
	{ cmp.ltu	p07,p06,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000001374A0; }

l4000000000137560:
	{ cmp.eq	p06,p07,0x1,r8; nop.i	0x0; (p07) br.cond.dpnt.few	40000000001374E0; }

l4000000000137570:
	{ adds	r32,0x1,r32; ld1	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000137460 }

l40000000001375A0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000001374D0; }
40000000001375B0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; mbschr: 40000000001375C0
;;   Called from:
;;     40000000000305FC (in yyerror)
;;     4000000000040CAC (in absolute_program)
;;     4000000000075F1C (in fn4000000000074880)
;;     4000000000086DFC (in fn4000000000086900)
;;     4000000000086DFC (in fn4000000000086900)
;;     4000000000086E7C (in fn4000000000086900)
;;     4000000000088C7C (in fn4000000000088B40)
;;     400000000008C47C (in skip_to_delim)
;;     400000000008CAEC (in skip_to_delim)
;;     400000000008CC2C (in skip_to_delim)
;;     400000000008DF2C (in split_at_delims)
;;     400000000008E2EC (in split_at_delims)
;;     400000000008E48C (in split_at_delims)
;;     400000000008E50C (in split_at_delims)
;;     400000000008E66C (in split_at_delims)
;;     40000000000992CC (in fn4000000000099100)
;;     400000000009968C (in fn4000000000099100)
;;     40000000000A7A7C (in fn40000000000A7940)
;;     40000000000B9D8C (in alias_expand)
;;     40000000000B9FBC (in alias_expand)
;;     40000000000BA1BC (in alias_expand)
;;     40000000000BA24C (in alias_expand)
;;     40000000000BA38C (in alias_expand)
;;     40000000000BA38C (in alias_expand)
;;     40000000000BF4EC (in expand_compound_array_assignment)
;;     40000000000BFCEC (in valid_array_reference)
;;     40000000000C0E6C (in array_variable_name)
;;     40000000000D740C (in bash_default_completion)
;;     40000000000DA0AC (in fn40000000000D9F00)
;;     40000000001114BC (in parse_symbolic_mode)
;;     40000000001116DC (in parse_symbolic_mode)
mbschr proc
	{ alloc	r37,ar.pfs,0xB,0x0,0x7; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r36,b4 }
	{ adds	r38,0x0,r1; nop.m	0x0; zxt1	r14,r33; }
	{ nop.m	0x0; cmp4.ltu	p07,p06,0x2F,r14; (p07) br.cond.dpnt.few	4000000000137630 }

l40000000001375F0:
	{ adds	r39,0x0,r32; adds	r40,0x0,r33; br.call.sptk.many	b0,fn400000000001B680; }
	{ nop.m	0x0; adds	r1,0x0,r38; adds	r34,0x0,r8; }

l4000000000137610:
	{ adds	r8,0x0,r34; mov.i	ar.pfs,r37; mov.spnt	b0,r36,4000000000137610 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l4000000000137630:
	{ adds	r34,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ cmp.ltu	p07,p06,0x1,r8; adds	r14,0x10,r12; nop.i	0x0 }
	{ adds	r1,0x0,r38; adds	r39,0x0,r32; (p06) br.cond.dpnt.few	40000000001375F0; }

l4000000000137660:
	{ st8	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; adds	r35,0x0,r8; adds	r1,0x0,r38 }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	4000000000137710; }

l4000000000137690:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000001376A0:
	{ adds	r40,0x0,r34; adds	r41,0x0,r35; nop.i	0x0 }
	{ adds	r39,0x0,r0; adds	r42,0x10,r12; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r8; adds	r1,0x0,r38; cmp.eq	p09,p08,0x1,r8; }
	{ nop.m	0x0; cmp.ltu	p06,p07,0xFFFFFFFFFFFFFFFC,r14; (p07) br.cond.dptk.few	4000000000137740 }

l40000000001376E0:
	{ ld1	r14,[r34]; nop.m	0x0; addl	r8,1,r0; }
	{ sub	r35,r35,r8; cmp4.eq	p06,p07,r14,r33; (p06) br.cond.dpnt.few	4000000000137610; }

l4000000000137700:
	{ add	r34,r34,r8; cmp.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	40000000001376A0; }

l4000000000137710:
	{ nop.m	0x0; adds	r34,0x0,r0; nop.i	0x0; }
	{ adds	r8,0x0,r34; mov.i	ar.pfs,r37; mov.spnt	b0,r36,4000000000137720 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000137740:
	{ nop.m	0x0; nop.i	0x0; (p09) br.cond.spnt.few	40000000001376E0; }

l4000000000137750:
	{ sub	r35,r35,r8; nop.m	0x0; add	r34,r34,r8; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	40000000001376A0 }

l4000000000137770:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000137710; }

;; zwrite: 4000000000137780
;;   Called from:
;;     4000000000134CBC (in zcatfd)
zwrite proc
	{ alloc	r40,ar.pfs,0xD,0x0,0xA; adds	r41,0x0,r1; mov	r39,b7 }
	{ adds	r38,0x0,r34; adds	r35,0x0,r34; sxt4	r36,r34; }
	{ adds	r37,0x0,r0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000001377C0:
	{ adds	r43,0x0,r33; nop.m	0x0; adds	r44,0x0,r36 }
	{ adds	r42,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B740; }
	{ nop.m	0x0; sxt4	r14,r8; adds	r1,0x0,r41 }
	{ nop.m	0x0; cmp4.lt	p07,p06,0x0,r8; (p06) br.cond.dpnt.few	4000000000137860; }

l4000000000137800:
	{ sub	r35,r35,r8; add	r33,r33,r14; adds	r42,0x0,r32; }
	{ cmp4.lt	p07,p06,0x0,r35; nop.m	0x0; sxt4	r36,r35 }
	{ adds	r43,0x0,r33; nop.m	0x0; (p06) br.cond.dpnt.few	40000000001378A0; }

l4000000000137830:
	{ adds	r44,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B740; }
	{ nop.m	0x0; adds	r1,0x0,r41; sxt4	r14,r8 }
	{ nop.m	0x0; cmp4.lt	p07,p06,0x0,r8; (p07) br.cond.dptk.few	4000000000137800; }

l4000000000137860:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000001378C0 }

l4000000000137870:
	{ nop.m	0x0; adds	r37,0x1,r37; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,0x3,r37; (p06) br.cond.dptk.few	40000000001377C0 }

l4000000000137890:
	{ sub	r38,r34,r35; nop.m	0x0; nop.i	0x0; }

l40000000001378A0:
	{ adds	r8,0x0,r38; nop.m	0x0; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000001378B0; br.ret	b0; }

l40000000001378C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ ld4	r14,[r8]; nop.m	0x0; adds	r1,0x0,r41; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x4,r14; (p06) br.cond.dptk.few	40000000001377C0 }

l40000000001378F0:
	{ addl	r38,-1,r0; nop.m	0x0; mov.i	ar.pfs,r40; }
	{ adds	r8,0x0,r38; mov.spnt	b0,r39,4000000000137900; br.ret	b0; }

;; fn4000000000137910: 4000000000137910
;;   Called from:
;;     4000000000072D7C (in fn4000000000072B40)
;;     40000000000740BC (in fn4000000000073B40)
;;     400000000012C4BC (in timeval_to_cpu)
fn4000000000137910 proc
	{ setf.sig	f8,r32; setf.sig	f9,r33; cmp.eq.unc	p07,p00,0x0,r33; }
	{ nop.m	0x0; fcvt.xf	f8,f8; nop.i	0x0 }
	{ nop.m	0x0; fcvt.xf	f9,f9; (p07) break.i	0x1; }

l4000000000137940:
	{ nop.m	0x0; frcpa	f10,p09,f8,f9; nop.i	0x0; }
	{ nop.m	0x0; (p06) fpma.s1	f11,f9,f10,f1; nop.i	0x0 }
	{ nop.m	0x0; (p06) fma.s1	f12,f8,f10,f0; nop.i	0x0; }
	{ nop.m	0x0; (p06) fma.s1	f13,f11,f11,f0; nop.i	0x0 }
	{ nop.m	0x0; (p06) fma.s1	f12,f11,f12,f12; nop.i	0x0; }
	{ nop.m	0x0; (p06) fma.s1	f10,f11,f10,f10; nop.i	0x0 }
	{ nop.m	0x0; (p06) fma.s1	f11,f13,f12,f12; nop.i	0x0; }
	{ nop.m	0x0; (p06) fma.s1	f10,f13,f10,f10; nop.i	0x0 }
	{ nop.m	0x0; (p06) fpma.s1	f12,f9,f11,f8; nop.i	0x0; }
	{ nop.m	0x0; (p06) fma.s1	f10,f12,f10,f11; nop.i	0x0; }
	{ nop.m	0x0; fcvt.fx.trunc.s1	f10,f10; nop.i	0x0; }
	{ getf.sig	r8,f10; nop.i	0x0; br.ret	b0; }

;; fn4000000000137A00: 4000000000137A00
;;   Called from:
;;     4000000000072C7C (in fn4000000000072B40)
;;     400000000007406C (in fn4000000000073B40)
;;     400000000010139C (in mapfile_builtin)
fn4000000000137A00 proc
	{ setf.sig	f14,r32; setf.sig	f9,r33; cmp.eq.unc	p07,p00,0x0,r33; }
	{ nop.m	0x0; fcvt.xf	f8,f14; nop.i	0x0 }
	{ nop.m	0x0; fcvt.xf	f9,f9; (p07) break.i	0x1; }

l4000000000137A30:
	{ nop.m	0x0; frcpa	f10,p09,f8,f9; nop.i	0x0; }
	{ nop.m	0x0; (p06) fma.s1	f12,f8,f10,f0; nop.i	0x0 }

l4000000000137A4C:
	{ Invalid; nop; czx1.l	r32,r34 }
	{ flushrs; padd2	r0,r32,r0; zxt1	r99,r35 }
	{ Invalid; nop; zxt1	r96,r34 }
	{ flushrs; dep	r0,r32,r0,51,1; zxt1	r98,r34 }
	{ Invalid; nop; zxt1	r35,r35 }
	{ nop; (p04) dep	r32,r40,r1,50,1; zxt1	r34,r34 }
	{ Invalid; padd2	r0,r32,r0; czx1.l	r34,r34 }
	{ nop; (p17) dep	r8,r32,r56,51,13; zxt1	r2,r34 }
	{ Invalid; dep	r0,r32,r0,63,1; (p33) break.i	0x9A002 }
	{ Invalid; dep	r0,r32,r0,63,1; czx2.r	r67,r2 }
	{ Invalid; Invalid; add	r0,r32,r0 }
	{ nop; (p01) nop; (p17) cmp.eq	p08,p12,r32,r56 }

;; fn4000000000137B00: 4000000000137B00
;;   Called from:
;;     400000000010FD9C (in fn400000000010FC40)
;;     4000000000110DCC (in ulimit_builtin)
;;     4000000000133C4C (in fmtulong)
;;     40000000001342DC (in fmtulong)
;;     400000000013450C (in fmtumax)
;;     4000000000134B9C (in fmtumax)
fn4000000000137B00 proc
	{ setf.sig	f8,r32; setf.sig	f9,r33; cmp.eq.unc	p07,p00,0x0,r33; }
	{ nop.m	0x0; fma.s1	f8,f8,f1,f0; nop.i	0x0 }
	{ nop.m	0x0; fma.s1	f9,f9,f1,f0; (p07) break.i	0x1; }

l4000000000137B30:
	{ nop.m	0x0; frcpa	f10,p09,f8,f9; nop.i	0x0; }
	{ nop.m	0x0; (p06) fpma.s1	f11,f9,f10,f1; nop.i	0x0 }
	{ nop.m	0x0; (p06) fma.s1	f12,f8,f10,f0; nop.i	0x0; }
	{ nop.m	0x0; (p06) fma.s1	f13,f11,f11,f0; nop.i	0x0 }
	{ nop.m	0x0; (p06) fma.s1	f12,f11,f12,f12; nop.i	0x0; }
	{ nop.m	0x0; (p06) fma.s1	f10,f11,f10,f10; nop.i	0x0 }
	{ nop.m	0x0; (p06) fma.s1	f11,f13,f12,f12; nop.i	0x0; }
	{ nop.m	0x0; (p06) fma.s1	f10,f13,f10,f10; nop.i	0x0 }
	{ nop.m	0x0; (p06) fpma.s1	f12,f9,f11,f8; nop.i	0x0; }
	{ nop.m	0x0; (p06) fma.s1	f10,f12,f10,f11; nop.i	0x0; }
	{ nop.m	0x0; fcvt.fxu.trunc.s1	f10,f10; nop.i	0x0; }
	{ getf.sig	r8,f10; nop.i	0x0; br.ret	b0; }

;; fn4000000000137BF0: 4000000000137BF0
;;   Called from:
;;     4000000000133BCC (in fmtulong)
;;     400000000013448C (in fmtumax)
fn4000000000137BF0 proc
	{ setf.sig	f14,r32; setf.sig	f9,r33; cmp.eq.unc	p07,p00,0x0,r33; }
	{ nop.m	0x0; fma.s1	f8,f14,f1,f0; nop.i	0x0 }
	{ nop.m	0x0; fma.s1	f9,f9,f1,f0; (p07) break.i	0x1; }

l4000000000137C20:
	{ nop.m	0x0; frcpa	f10,p09,f8,f9; nop.i	0x0; }
	{ nop.m	0x0; (p06) fma.s1	f12,f8,f10,f0; nop.i	0x0 }

l4000000000137C3C:
	{ Invalid; nop; czx1.l	r32,r34 }
	{ flushrs; padd2	r0,r32,r0; zxt1	r99,r35 }
	{ Invalid; nop; zxt1	r96,r34 }
	{ flushrs; dep	r0,r32,r0,51,1; zxt1	r98,r34 }
	{ Invalid; nop; zxt1	r35,r35 }
	{ nop; (p04) dep	r32,r40,r1,50,1; zxt1	r34,r34 }
	{ Invalid; padd2	r0,r32,r0; czx1.l	r34,r34 }
	{ nop; (p17) dep	r8,r32,r56,51,13; zxt1	r2,r34 }
	{ Invalid; dep	r0,r32,r0,63,1; (p33) break.i	0x9B002 }
	{ Invalid; dep	r0,r32,r0,63,1; czx2.r	r67,r2 }
	{ Invalid; Invalid; add	r0,r32,r0 }
	{ cmp.lt	p00,p00,r33,r0; cmp.eq	p00,p00,r32,r0; break.i	0x1000 }
	{ nop; Invalid; (p04) cmp.lt	p00,p00,r32,r12; }

;; __libc_csu_init: 4000000000137D00
__libc_csu_init proc
	{ alloc	r37,ar.pfs,0xB,0x0,0x8; mov	r36,b4; adds	r38,0x0,r1; }
	{ nop.m	0x0; mov	r39,LC; br.call.sptk.many	b0,_init; }
	{ adds	r1,0x0,r38; addl	r35,-25956,r1; addl	r14,-25932,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; sub	r14,r14,r35; nop.i	0x0; }
	{ nop.m	0x0; extr	r14,r14,3,61; adds	r15,0xFFFFFFFFFFFFFFFF,r14 }
	{ cmp.eq	p07,p06,0x0,r14; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000137DD0; }

l4000000000137D70:
	{ nop.m	0x0; mov.i	LC,r15; nop.i	0x0; }

l4000000000137D80:
	{ ld8	r14,[r35],8; adds	r40,0x0,r32; adds	r41,0x0,r33 }
	{ adds	r42,0x0,r34; ld8	r15,[r14],8; nop.i	0x0; }
	{ ld8	r1,[r14]; mov.spnt	b6,r15,4000000000137DA0; br.call.sptk.many	b0,b6; }
	{ nop.m	0x0; nop.i	0x0; br.cloop.sptk.few	4000000000137D80; }

l4000000000137DC0:
	{ adds	r1,0x0,r38; nop.m	0x0; nop.i	0x0 }

l4000000000137DD0:
	{ nop.m	0x0; mov.i	ar.pfs,r37; mov.i	LC,r39; }
	{ nop.m	0x0; mov.spnt	b0,r36,4000000000137DE0; br.ret	b0; }
4000000000137DF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; __libc_csu_fini: 4000000000137E00
__libc_csu_fini proc
	{ nop.m	0x0; nop.i	0x0; br.ret	b0; }
4000000000137E10 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
4000000000137E20 05 10 15 0A 80 C5 FF FF FF FF 7F 00 44 F7 AF 6E ............D..n
4000000000137E30 0B 00 81 02 00 20 30 C2 83 32 2C 20 04 00 C4 00 ..... 0..2, ....
4000000000137E40 10 30 FC 47 00 3B 40 02 04 00 42 03 40 00 00 41 .0.G.;@...B.@..A
4000000000137E50 0A 78 20 46 18 14 10 00 8C 30 20 C0 F0 08 00 07 .x F.....0 .....
4000000000137E60 11 18 E1 41 19 16 00 00 00 02 00 00 68 00 80 10 ...A........h...
4000000000137E70 10 00 FC 47 06 3B 00 00 00 02 00 03 E0 FF FF 48 ...G.;.........H
4000000000137E80 00 08 00 46 00 21 00 08 05 80 03 00 20 02 AA 00 ...F.!...... ...
4000000000137E90 11 00 00 00 01 00 00 00 00 02 00 80 08 00 84 00 ................
