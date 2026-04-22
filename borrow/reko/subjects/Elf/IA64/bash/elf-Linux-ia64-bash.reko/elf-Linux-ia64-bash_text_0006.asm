;;; Segment .text (400000000001C480)

l400000000007C4B0:
	{ adds	r38,0x90,r12; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r38,0x90,r12 }
	{ addl	r39,17,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B400; }
	{ adds	r1,0x0,r37; adds	r38,0x10,r12; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r37; adds	r39,0x90,r12; nop.i	0x0 }
	{ adds	r40,0x10,r12; adds	r38,0x0,r0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r37; adds	r38,0x0,r32; nop.i	0x0 }
	{ adds	r39,0x0,r0; adds	r40,0x0,r0; br.call.sptk.many	b0,fn4000000000076C40; }
	{ adds	r1,0x0,r37; adds	r34,0x0,r8; addl	r38,2,r0 }
	{ adds	r39,0x10,r12; adds	r40,0x0,r0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r8,0x0,r34; adds	r1,0x0,r37; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,400000000007C560; nop.i	0x0 }
	{ adds	r12,0x100,r12; nop.m	0x0; br.ret	b0; }

;; describe_pid: 400000000007C580
describe_pid proc
	{ alloc	r34,ar.pfs,0x9,0x0,0x4; adds	r12,0xFFFFFFFFFFFFFF00,r12; nop.b	0x0 }
	{ adds	r35,0x0,r1; nop.m	0x0; mov	r33,b1; }
	{ adds	r36,0x90,r12; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r35; nop.m	0x0; adds	r36,0x90,r12 }
	{ addl	r37,17,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B400; }
	{ adds	r1,0x0,r35; adds	r36,0x10,r12; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r35; adds	r37,0x90,r12; nop.i	0x0 }
	{ adds	r38,0x10,r12; adds	r36,0x0,r0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r35; adds	r36,0x0,r32; nop.i	0x0 }
	{ adds	r37,0x0,r0; adds	r38,0x0,r0; br.call.sptk.many	b0,fn4000000000076C40; }
	{ adds	r1,0x0,r35; cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r8; sxt4	r40,r32 }
	{ adds	r39,0x1,r8; addl	r37,1,r0; (p06) br.cond.dpnt.few	400000000007C6B0; }

l400000000007C640:
	{ addl	r14,-10652,r1; nop.m	0x0; addl	r38,-8012,r1; }
	{ ld8	r14,[r14]; ld8	r38,[r38]; nop.i	0x0; }
	{ ld8	r36,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ adds	r1,0x0,r35; addl	r36,2,r0; nop.i	0x0 }
	{ adds	r37,0x10,r12; adds	r38,0x0,r0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r35; mov.i	ar.pfs,r34; mov.spnt	b0,r33,400000000007C690 }
	{ nop.m	0x0; adds	r12,0x100,r12; br.ret	b0 }

l400000000007C6B0:
	{ addl	r37,-8004,r1; addl	r38,5,r0; adds	r36,0x0,r0; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r35; nop.m	0x0; adds	r36,0x0,r8 }
	{ nop.m	0x0; sxt4	r37,r32; br.call.sptk.many	b0,programming_error; }
	{ adds	r1,0x0,r35; addl	r36,2,r0; nop.i	0x0 }
	{ adds	r37,0x10,r12; adds	r38,0x0,r0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r35; mov.i	ar.pfs,r34; mov.spnt	b0,r33,400000000007C710 }
	{ nop.m	0x0; adds	r12,0x100,r12; br.ret	b0; }
400000000007C730 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; list_one_job: 400000000007C740
;;   Called from:
;;     40000000000FF16C (in jobs_builtin)
list_one_job proc
	{ addl	r14,-10260,r1; nop.m	0x0; adds	r32,0x0,r35; }
	{ ld8	r14,[r14]; ld8	r34,[r14]; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x4,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000780C0; }
400000000007C770 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; ignore_tty_job_signals: 400000000007C780
;;   Called from:
;;     40000000000833BC (in make_child)
ignore_tty_job_signals proc
	{ alloc	r33,ar.pfs,0x5,0x0,0x3; mov	r32,b0; adds	r34,0x0,r1; }
	{ addl	r35,20,r0; addl	r36,1,r0; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r34; nop.m	0x0; addl	r35,21,r0 }
	{ addl	r36,1,r0; nop.m	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r34; nop.m	0x0; addl	r35,22,r0 }
	{ addl	r36,1,r0; nop.m	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ nop.m	0x0; mov.spnt	b0,r32,400000000007C7F0; br.ret	b0; }

;; default_tty_job_signals: 400000000007C800
;;   Called from:
;;     4000000000082EDC (in make_child)
;;     4000000000082EDC (in make_child)
;;     400000000008313C (in make_child)
default_tty_job_signals proc
	{ alloc	r33,ar.pfs,0x5,0x0,0x3; mov	r32,b0; adds	r34,0x0,r1; }
	{ addl	r35,20,r0; adds	r36,0x0,r0; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r34; nop.m	0x0; addl	r35,21,r0 }
	{ adds	r36,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r34; nop.m	0x0; addl	r35,22,r0 }
	{ adds	r36,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ nop.m	0x0; mov.spnt	b0,r32,400000000007C870; br.ret	b0; }

;; get_tty_state: 400000000007C880
;;   Called from:
;;     400000000001F8CC (in main)
;;     40000000000209CC (in main)
;;     400000000007F9FC (in initialize_job_control)
;;     4000000000080E9C (in wait_for)
;;     40000000000823CC (in start_job)
;;     40000000000823CC (in start_job)
get_tty_state proc
	{ alloc	r33,ar.pfs,0x6,0x0,0x3; addl	r14,5900,r1; mov	r32,b0 }
	{ adds	r34,0x0,r1; ld4	r35,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r35; (p07) br.cond.dpnt.few	400000000007C970 }

l400000000007C8B0:
	{ nop.m	0x0; addl	r36,19084,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C400; }
	{ adds	r1,0x0,r34; nop.m	0x0; cmp4.lt	p06,p07,r8,r0 }
	{ adds	r8,0x0,r0; nop.m	0x0; (p06) br.cond.dpnt.few	400000000007C9C0; }

l400000000007C8F0:
	{ addl	r14,9072,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	400000000007C940 }

l400000000007C920:
	{ nop.m	0x0; mov.i	ar.pfs,r33; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r32,400000000007C930; br.ret	b0; }

l400000000007C940:
	{ adds	r35,0x0,r0; nop.m	0x0; adds	r36,0x0,r0 }
	{ adds	r37,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,get_new_window_size; }
	{ adds	r1,0x0,r34; adds	r8,0x0,r0; br.cond.sptk.few	400000000007C920; }

l400000000007C970:
	{ addl	r14,-10652,r1; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r35,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BBC0; }
	{ adds	r1,0x0,r34; adds	r35,0x0,r8; nop.i	0x0 }
	{ cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; adds	r8,0x0,r0; (p06) br.cond.spnt.few	400000000007C8B0; }

l400000000007C9B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000007C920 }

l400000000007C9C0:
	{ addl	r8,-1,r0; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ nop.m	0x0; mov.spnt	b0,r32,400000000007C9D0; br.ret	b0; }
400000000007C9E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007C9F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; set_tty_state: 400000000007CA00
;;   Called from:
;;     4000000000080BDC (in wait_for)
;;     400000000008231C (in start_job)
set_tty_state proc
	{ alloc	r34,ar.pfs,0x8,0x0,0x4; addl	r14,5900,r1; mov	r33,b1 }
	{ adds	r35,0x0,r1; ld4	r32,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r32; (p07) br.cond.dpnt.few	400000000007CB30 }

l400000000007CA30:
	{ addl	r38,19084,r1; adds	r36,0x0,r32; addl	r37,1,r0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B1E0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r8,r0; adds	r8,0x0,r0 }
	{ nop.m	0x0; adds	r1,0x0,r35; (p07) br.cond.dpnt.few	400000000007CA90 }

l400000000007CA70:
	{ nop.m	0x0; mov.i	ar.pfs,r34; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r33,400000000007CA80; br.ret	b0 }

l400000000007CA90:
	{ addl	r14,6516,r1; nop.m	0x0; addl	r8,-1,r0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000007CA70 }

l400000000007CAC0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B1A0; }
	{ adds	r1,0x0,r35; sxt4	r37,r8; adds	r39,0x0,r32; }
	{ addl	r14,7124,r1; nop.m	0x0; addl	r36,-7996,r1; }
	{ nop.m	0x0; ld8	r36,[r36]; nop.i	0x0; }
	{ ld4	r38,[r14]; nop.i	0x0; br.call.sptk.many	b0,sys_error; }
	{ addl	r8,-1,r0; adds	r1,0x0,r35; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,400000000007CB20; br.ret	b0 }

l400000000007CB30:
	{ addl	r14,-10652,r1; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r36,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BBC0; }
	{ adds	r1,0x0,r35; adds	r32,0x0,r8; nop.i	0x0 }
	{ cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; adds	r8,0x0,r0; (p06) br.cond.spnt.few	400000000007CA30; }

l400000000007CB70:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000007CA70; }

;; job_exit_status: 400000000007CB80
;;   Called from:
;;     40000000000801CC (in wait_for)
job_exit_status proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; nop.m	0x0; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; adds	r36,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000077E80; }
	{ adds	r1,0x0,r35; adds	r32,0x0,r8; mov.spnt	b0,r33,400000000007CBB0; }
	{ nop.m	0x0; mov.i	ar.pfs,r34; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x1,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn4000000000077B80; }
400000000007CBE0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
400000000007CBF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; job_exit_signal: 400000000007CC00
;;   Called from:
;;     40000000000801EC (in wait_for)
job_exit_signal proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; nop.m	0x0; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; adds	r36,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000077E80; }
	{ and	r14,0x7F,r8; adds	r1,0x0,r35; mov.i	ar.pfs,r34; }
	{ adds	r8,0x1,r14; mov.spnt	b0,r33,400000000007CC40; extr.u	r8,r8,1,7; }
	{ cmp4.lt	p06,p07,0x0,r8; (p06) adds	r8,0x0,r14; nop.i	0x0; }

l400000000007CC5C:
	{ Invalid; mov	pr,r32,0x0; (p01) shladd	r0,r0,0x1,r64 }

l400000000007CC6C:
	{ nop; break.m	0x1000; break.i	0x1000 }
400000000007CC70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; kill_pid: 400000000007CC80
;;   Called from:
;;     40000000001000BC (in kill_builtin)
;;     400000000010062C (in kill_builtin)
kill_pid proc
	{ alloc	r42,ar.pfs,0x10,0x0,0xD; adds	r12,0xFFFFFFFFFFFFFEF0,r12; mov	r44,pr }
	{ cmp4.lt	p06,p07,0xFFFFFFFFFFFFFFFE,r32; adds	r43,0x0,r1; adds	r46,0x0,r33; }
	{ (p07) sub	r32,r0,r32; nop.m	0x0; mov	r41,b1 }

l400000000007CCA6:
	{ add	r0,r0,r1; (p20) nop; (p49) nop }

l400000000007CCB6:
	{ chk.a.nc	f0,3FFFFFFFFF07D4B6; nop; (p32) nop }

l400000000007CCC0:
	{ cmp4.eq	p06,p07,0x0,r34; adds	r45,0x0,r32; (p07) br.cond.dpnt.few	400000000007CD20; }

l400000000007CCD0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B520; }
	{ adds	r35,0x0,r8; nop.m	0x0; adds	r1,0x0,r43; }
	{ adds	r8,0x0,r35; mov	pr,r44,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r42; }
	{ nop.m	0x0; mov.spnt	b0,r41,400000000007CD00; nop.i	0x0 }
	{ adds	r12,0x110,r12; nop.m	0x0; br.ret	b0 }

l400000000007CD20:
	{ adds	r35,0x0,r0; nop.m	0x0; nop.i	0x0; }

l400000000007CD30:
	{ adds	r45,0x90,r12; adds	r37,0x110,r12; br.call.sptk.many	b0,fn400000000001BC20; }
	{ addl	r46,17,r0; nop.m	0x0; adds	r1,0x0,r43 }
	{ adds	r45,0x90,r12; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B400; }
	{ adds	r1,0x0,r43; adds	r45,0x10,r12; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r43; adds	r45,0x0,r0; nop.i	0x0 }
	{ adds	r46,0x90,r12; adds	r47,0x10,r12; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r43; adds	r45,0x0,r32; nop.i	0x0 }
	{ adds	r46,0x0,r0; adds	r47,0x0,r37; br.call.sptk.many	b0,fn4000000000076DC0; }
	{ adds	r1,0x0,r43; ld4	r14,[r37]; adds	r36,0x0,r8; }
	{ addl	r38,7444,r1; nop.m	0x0; cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r14 }
	{ nop.m	0x0; sxt4	r14,r14; (p06) br.cond.dpnt.few	400000000007D0D0; }

l400000000007CDE0:
	{ ld8	r15,[r38]; cmp4.eq	p06,p07,0x0,r35; shladd	r15,r14,0x3,r15; }
	{ ld8	r14,[r15]; adds	r15,0x18,r14; nop.i	0x0; }
	{ ld4	r16,[r15]; and	r16,0xFFFFFFFFFFFFFFFD,r16; nop.i	0x0; }
	{ st4	[r16],r15; nop.i	0x0; (p06) br.cond.dptk.few	400000000007CF30 }

l400000000007CE20:
	{ adds	r14,0x10,r14; ld4	r45,[r14]; addl	r14,5896,r1; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r45; (p07) br.cond.dpnt.few	400000000007D0D0 }

l400000000007CE50:
	{ adds	r46,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,fn400000000001ACE0; }
	{ adds	r1,0x0,r43; nop.m	0x0; adds	r35,0x0,r8 }
	{ cmp.eq	p06,p07,0x0,r36; nop.m	0x0; (p06) br.cond.dpnt.few	400000000007CED0; }

l400000000007CE80:
	{ ld4	r45,[r37]; ld8	r14,[r38]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r15,r45; shladd	r14,r15,0x3,r14; }
	{ ld8	r14,[r14]; adds	r15,0x14,r14; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2,r15; (p07) br.cond.dpnt.few	400000000007D110 }

l400000000007CED0:
	{ addl	r45,2,r0; nop.m	0x0; adds	r46,0x10,r12 }
	{ adds	r47,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r43; nop.m	0x0; nop.i	0x0 }

l400000000007CF00:
	{ adds	r8,0x0,r35; mov	pr,r44,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r42; }
	{ nop.m	0x0; mov.spnt	b0,r41,400000000007CF10; nop.i	0x0 }
	{ adds	r12,0x110,r12; nop.m	0x0; br.ret	b0 }

l400000000007CF30:
	{ adds	r15,0x10,r14; cmp4.eq	p17,p16,0x1,r33; adds	r14,0x8,r14 }
	{ addl	r40,255,r0; ld4	r45,[r15]; addl	r15,5896,r1 }
	{ cmp4.eq.or.andcm	p17,p16,0xF,r33; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r15,r45; (p06) br.cond.dpnt.few	400000000007CE50; }

l400000000007CF70:
	{ ld8	r35,[r14]; nop.m	0x0; nop.i	0x0; }

l400000000007CF80:
	{ adds	r36,0x10,r35; nop.m	0x0; adds	r15,0xC,r35; }
	{ nop.m	0x0; ld4	r14,[r36]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000007D050; }

l400000000007CFB0:
	{ ld4	r14,[r15]; and	r14,r40,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x7F,r14; (p06) br.cond.dpnt.few	400000000007D050 }

l400000000007CFD0:
	{ ld4	r16,[r37]; ld8	r14,[r38]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r15,r16; shladd	r14,r15,0x3,r14; }
	{ ld8	r14,[r14]; adds	r14,0x8,r14; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r35,r14; (p06) br.cond.dptk.few	400000000007CF80 }

l400000000007D020:
	{ addl	r45,2,r0; adds	r46,0x10,r12; nop.i	0x0 }
	{ adds	r47,0x0,r0; adds	r35,0x0,r0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ nop.m	0x0; adds	r1,0x0,r43; br.cond.sptk.few	400000000007CF00 }

l400000000007D050:
	{ adds	r39,0x8,r35; nop.m	0x0; adds	r46,0x0,r33; }
	{ ld4	r45,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B520; }
	{ ld4	r14,[r36]; nop.m	0x0; adds	r1,0x0,r43; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	400000000007D0C0 }

l400000000007D090:
	{ nop.m	0x0; (p17) ld4	r45,[r39]; (p17) addl	r46,18,r0 }

l400000000007D09C:
	{ (p09) nop; nop; }

l400000000007D0A0:
	{ nop.m	0x0; nop.m	0x0; (p17) br.call.dpnt.many	b0,fn400000000001B520; }

l400000000007D0B0:
	{ (p17) adds	r1,0x0,r43; nop.m	0x0; nop.i	0x0 }

l400000000007D0B6:
	{ break.m	0x4000; nop; (p48) nop }

l400000000007D0C0:
	{ ld8	r35,[r35]; nop.i	0x0; br.cond.sptk.few	400000000007CFD0 }

l400000000007D0C2:
	{ (p48) break.m	0x20308; nop; (p62) nop; }

l400000000007D0C6:
	{ break.m	0x4000; nop; (p16) nop }

l400000000007D0C8:
	{ (p16) nop; (p63) mov	pr,0x681148F; mov	pr,0x7010802 }

l400000000007D0CC:
	{ (p56) nop; (p05) cmp.lt	p00,p16,r8,r64; (p05) epc }

l400000000007D0CE:
	{ Invalid; Invalid; Invalid }

l400000000007D0D0:
	{ adds	r45,0x0,r32; adds	r46,0x0,r33; br.call.sptk.many	b0,fn400000000001ACE0; }

l400000000007D0D2:
	{ Invalid; (p16) nop; Invalid; }

l400000000007D0D4:
	{ Invalid; (p08) nop; (p49) shrp	r66,r0,r1,0 }

l400000000007D0D6:
	{ Invalid; (p32) nop; (p16) nop }

l400000000007D0D8:
	{ (p04) ldfd	f64,[r0],16; (p44) nop }

l400000000007D0DC:
	{ (p32) nop; ldfs	f96,[r64]; Invalid }

l400000000007D0E2:
	{ (p48) srlz.d; dep	r2,r64,r16,18,1; Invalid }
	{ Invalid; nop; Invalid; }
	{ invala; (p48) break.i	0x4200A; Invalid }

l400000000007D110:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x1,r33; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0xF,r33; (p07) br.cond.dpnt.few	400000000007D1D0; }

l400000000007D130:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x12,r33; (p06) br.cond.dptk.few	400000000007CED0 }

l400000000007D140:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000077080; }
	{ ld4	r15,[r37]; adds	r1,0x0,r43; addl	r45,2,r0 }
	{ adds	r46,0x10,r12; ld8	r14,[r38]; adds	r47,0x0,r0; }
	{ nop.m	0x0; sxt4	r15,r15; shladd	r14,r15,0x3,r14; }
	{ ld8	r14,[r14]; adds	r14,0x18,r14; nop.i	0x0; }
	{ ld4	r15,[r14]; and	r15,0xFFFFFFFFFFFFFFFE,r15; nop.i	0x0; }
	{ nop.m	0x0; or	r15,0x2,r15; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ nop.m	0x0; adds	r1,0x0,r43; br.cond.sptk.few	400000000007CF00 }

l400000000007D1D0:
	{ adds	r14,0x10,r14; nop.m	0x0; addl	r46,18,r0; }
	{ ld4	r45,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001ACE0; }
	{ adds	r1,0x0,r43; ld4	r45,[r37]; nop.i	0x0; }
	{ addl	r14,7444,r1; nop.m	0x0; sxt4	r15,r45; }
	{ ld8	r14,[r14]; shladd	r14,r15,0x3,r14; nop.i	0x0; }
	{ ld8	r14,[r14]; adds	r14,0x14,r14; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2,r14; (p07) br.cond.sptk.few	400000000007D130 }

l400000000007D250:
	{ addl	r45,2,r0; nop.m	0x0; adds	r46,0x10,r12 }
	{ adds	r47,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ nop.m	0x0; adds	r1,0x0,r43; br.cond.sptk.few	400000000007CF00; }

;; run_sigchld_trap: 400000000007D280
;;   Called from:
;;     400000000007E3FC (in fn400000000007D580)
;;     40000000000AF5DC (in run_pending_traps)
run_sigchld_trap proc
	{ alloc	r40,ar.pfs,0xE,0x0,0xB; addl	r33,24316,r1; addl	r38,7540,r1 }
	{ addl	r34,7672,r1; adds	r41,0x0,r1; addl	r36,7464,r1; }
	{ nop.m	0x0; mov	r39,b7; addl	r37,7428,r1 }
	{ addl	r35,1,r0; nop.m	0x0; nop.b	0x0; }
	{ adds	r33,0x88,r33; nop.m	0x0; mov	r42,LC; }
	{ ld8	r43,[r33]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r41; adds	r43,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r44,[r33]; nop.m	0x0; adds	r1,0x0,r41 }
	{ adds	r43,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r41; adds	r33,0x0,r8; addl	r43,-7988,r1; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,begin_unwind_frame; }
	{ adds	r1,0x0,r41; addl	r44,4,r0; addl	r43,9044,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,unwind_protect_mem; }
	{ adds	r1,0x0,r41; addl	r44,4,r0; addl	r43,9016,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,unwind_protect_mem; }
	{ adds	r1,0x0,r41; nop.m	0x0; addl	r44,4,r0; }
	{ addl	r43,5876,r1; nop.i	0x0; br.call.sptk.many	b0,unwind_protect_mem; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r43,0x0,r34 }
	{ addl	r44,4,r0; nop.m	0x0; br.call.sptk.many	b0,unwind_protect_mem; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r43,0x0,r36 }
	{ addl	r44,4,r0; nop.m	0x0; br.call.sptk.many	b0,unwind_protect_mem; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r43,0x0,r37 }
	{ addl	r44,8,r0; nop.m	0x0; br.call.sptk.many	b0,unwind_protect_mem; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r43,0x0,r38 }
	{ addl	r44,8,r0; nop.m	0x0; br.call.sptk.many	b0,unwind_protect_mem; }
	{ adds	r1,0x0,r41; adds	r44,0x0,r33; addl	r43,-9884,r1; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,add_unwind_protect; }
	{ adds	r1,0x0,r41; adds	r44,0x0,r33; addl	r43,-9932,r1; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,add_unwind_protect; }
	{ adds	r1,0x0,r41; st8	[r0],r38; nop.i	0x0 }
	{ st8	[r0],r37; nop.m	0x0; br.call.sptk.many	b0,set_impossible_sigchld_trap; }
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r32; cmp4.lt	p06,p07,0x0,r32; adds	r1,0x0,r41; }
	{ addp4	r15,r14,r0; nop.m	0x0; addl	r14,1,r0; }
	{ st4	[r14],r36; (p06) mov.i	LC,r15; (p07) br.cond.dpnt.few	400000000007D530; }

l400000000007D49C:
	{ (p05) nop; nop; zxt1	r32,r64 }

l400000000007D4A0:
	{ nop.m	0x0; adds	r43,0x0,r33; nop.i	0x0 }
	{ st4	[r35],r34; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r41; adds	r43,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r43,0x0,r8 }
	{ adds	r44,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r41; adds	r43,0x0,r8; addl	r45,20,r0; }
	{ nop.m	0x0; addl	r44,-7980,r1; nop.i	0x0; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,parse_and_execute; }
	{ nop.m	0x0; adds	r1,0x0,r41; br.cloop.sptk.few	400000000007D4A0; }

l400000000007D530:
	{ nop.m	0x0; addl	r43,-7988,r1; nop.i	0x0; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,run_unwind_frame; }
	{ adds	r1,0x0,r41; mov.i	ar.pfs,r40; mov.i	LC,r42; }
	{ nop.m	0x0; mov.spnt	b0,r39,400000000007D560; br.ret	b0; }
400000000007D570 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn400000000007D580: 400000000007D580
;;   Called from:
;;     400000000007EA5C (in fn400000000007E8C0)
;;     400000000008068C (in wait_for)
;;     4000000000082D4C (in make_child)
fn400000000007D580 proc
	{ alloc	r70,ar.pfs,0x2C,0x0,0x29; adds	r12,0xFFFFFFFFFFFFFFF0,r12; addl	r36,7468,r1 }
	{ addl	r43,-20676,r1; addl	r38,7676,r1; addl	r40,5912,r1; }
	{ nop.m	0x0; addl	r48,9028,r1; addl	r53,6516,r1 }
	{ addl	r62,6512,r1; addl	r65,-9940,r1; addl	r64,-9628,r1; }
	{ ld4	r14,[r36]; addl	r63,9044,r1; nop.b	0x0 }
	{ addl	r58,8364,r1; addl	r67,8360,r1; mov	r69,b5; }
	{ nop.m	0x0; adds	r45,0xC,r43; mov	r72,pr }
	{ adds	r56,0x2C,r43; adds	r44,0x18,r43; adds	r71,0x0,r1; }
	{ adds	r41,0x0,r0; addl	r51,-1,r0; adds	r46,0x0,r0 }
	{ addl	r39,5868,r1; cmp4.eq	p07,p06,0x0,r14; cmp4.eq	p19,p18,0x1,r32; }
	{ adds	r35,0x14,r12; cmp4.eq	p21,p20,0x0,r32; adds	r47,0x0,r38 }
	{ nop.m	0x0; addl	r54,7472,r1; adds	r61,0x0,r40; }
	{ adds	r52,0x0,r36; addl	r42,65535,r0; addl	r50,7444,r1 }
	{ addl	r37,255,r0; nop.m	0x0; addl	r55,65280,r0; }
	{ addl	r60,4,r0; addl	r57,7476,r1; addl	r59,7464,r1 }
	{ nop.m	0x0; addl	r66,5916,r1; adds	r43,0x8,r43; }
	{ nop.m	0x0; ld8	r65,[r65]; nop.i	0x0 }
	{ ld8	r64,[r64]; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000007D6C0:
	{ nop.m	0x0; ld4	r14,[r39]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p08,p09,0x0,r14; (p08) br.cond.dptk.few	400000000007DC00 }

l400000000007D6E0:
	{ nop.m	0x0; ld4	r14,[r48]; nop.i	0x0; }
	{ cmp4.eq	p09,p08,0x0,r14; nop.i	0x0; (p08) br.cond.dptk.few	400000000007DC00; }

l400000000007D700:
	{ (p09) ld4	r33,[r40]; nop.i	0x0; (p09) or	r33,0x2,r33 }

l400000000007D706:
	{ addl	r0,16384,r1; (p16) nop; break.i	0x80000 }

l400000000007D710:
	{ nop.m	0x0; nop.i	0x0; (p06) br.cond.dptk.few	400000000007D730 }

l400000000007D720:
	{ nop.m	0x0; nop.i	0x0; (p20) br.cond.dptk.few	400000000007D740; }

l400000000007D730:
	{ or	r33,0x1,r33; nop.m	0x0; nop.i	0x0 }

l400000000007D740:
	{ nop.m	0x0; ld4.acq	r14,[r38]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	400000000007DAD0; (p19) br.cond.dpnt.few	400000000007DAF0 }

l400000000007D75C:
	{ (p29) nop; Invalid; dep	r0,r32,r0,63,1 }

l400000000007D760:
	{ addl	r73,-1,r0; nop.m	0x0; adds	r74,0x0,r35 }
	{ adds	r75,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B220; }
	{ ld4	r14,[r40]; nop.m	0x0; adds	r1,0x0,r71 }
	{ adds	r34,0x0,r8; nop.m	0x0; cmp4.lt	p17,p16,r8,r0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000007D7C0 }

l400000000007D7B0:
	{ nop.m	0x0; nop.i	0x0; (p17) br.cond.dpnt.few	400000000007DC10 }

l400000000007D7C0:
	{ nop.m	0x0; ld4	r14,[r36]; nop.i	0x0; }
	{ cmp4.lt	p07,p06,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000007D800; }

l400000000007D7E0:
	{ nop.m	0x0; tbit.z	p06,p07,r33,0x0; (p07) adds	r14,0xFFFFFFFFFFFFFFFF,r14 }

l400000000007D7F0:
	{ nop.m	0x0; (p07) st4	[r14],r52; nop.i	0x0 }

l400000000007D7FC:
	{ invala; break.i	0x1000; Invalid }

l400000000007D800:
	{ nop.m	0x0; nop.i	0x0; (p17) br.cond.dpnt.few	400000000007DB90 }

l400000000007D802:
	{ break.m	0x20; nop; Invalid }

l400000000007D806:
	{ nop; nop; break.i	0x80000 }

l400000000007D808:
	{ (p16) chk.a.nc	f0,3FFFFFFFFF47FA08; break.i	0x9430; Invalid }

l400000000007D80C:
	{ (p28) nop; cmp.lt	p00,p00,r32,r0; (p01) rfi }

l400000000007D80E:
	{ (p24) break.m	0x128; (p04) nop; (p01) break.i	0x10B }

l400000000007D812:
	{ Invalid; (p32) break.i	0x21609; Invalid }

l400000000007D81C:
	{ Invalid; cmp.lt	p00,p00,r32,r0; mov	pr,r99,0xE680 }
	{ (p26) cmp.eq	p00,p08,r64,r33; nop; (p09) epc }
	{ cmpxchg8.acq	r0,[r0],r1; (p25) nop; (p09) mov	pr,r3,0x8408 }
	{ (p11) cmp.lt	p00,p11,r64,r33; (p01) cmp.lt.unc	p32,p08,r8,r4; czx1.r	r74,r33 }
	{ cmp4.eq.and	p00,p35,r1,r0; (p01) nop; (p21) cmp4.eq.and	p32,p48,r10,r64 }
	{ Invalid; Invalid; break.b	0x1000; }
	{ (p42) cmp.lt.unc	p50,p08,r63,r44; (p01) nop; epc }
	{ nop; (p04) cmp.lt	p00,p16,r2,r64; mov	pr,r98,0xE400 }
	{ (p63) nop; cmp.lt	p00,p00,r32,r0; Invalid }
	{ Invalid; cmp.lt	p00,p00,r32,r0; (p32) mov	pr,r104,0xE286 }
	{ (p02) nop; nop; (p04) rfi }
	{ cmp.lt	p00,p17,r1,r0; (p01) cmp.lt	p34,p16,r8,r64; mov	pr,r104,0xE440 }
	{ (p61) nop; cmp.lt	p00,p00,r32,r0; Invalid }
	{ invala; cmp.eq	p00,p00,r32,r0; (p32) mov	pr,r72,0xE286 }
	{ (p62) nop; nop; (p09) epc }
	{ cmpxchg8.acq	r0,[r0],r1; Invalid; break.i	0x1000 }
	{ (p51) cmp.eq	p35,p08,r63,r44; (p01) nop; break.b	0x1000 }
	{ (p06) nop; zxt1	r36,r64; nop }
	{ cmp.lt.unc	p07,p09,r0,r66; czx1.r	r106,r33; Invalid }
	{ cmp4.eq.and	p00,p03,r1,r0; zxt4	r0,r0; cmp4.eq.and	p00,p32,r32,r0 }
	{ invala; (p32) cmp.lt	p35,p08,r8,r100; mov	pr,r99,0xE480; }
	{ (p24) cmp.lt	p00,p11,r0,r33; (p01) nop; Invalid }
	{ cmp.eq	p00,p17,r1,r0; (p02) cmp.lt.unc	p32,p16,r4,r64; (p48) mov	pr,r100,0xEEFE }
	{ (p26) nop; break.i	0x1000; break.i	0x1000 }
	{ nop; cmp.lt	p00,p00,r32,r0; Invalid }

l400000000007D9A0:
	{ nop.m	0x0; ld4	r14,[r36]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	400000000007D9D0 }

l400000000007D9C0:
	{ nop.m	0x0; nop.i	0x0; (p20) br.cond.dpnt.few	400000000007D9E0 }

l400000000007D9D0:
	{ nop.m	0x0; cmp4.lt	p08,p09,0x0,r34; (p08) br.cond.dptk.few	400000000007D6C0; }

l400000000007D9E0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r46; (p06) br.cond.dptk.few	400000000007DA20; }

l400000000007D9F0:
	{ cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r51; adds	r73,0x0,r51; (p06) br.cond.dpnt.few	400000000007E3B0; }

l400000000007DA00:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000007A300; }
	{ adds	r1,0x0,r71; nop.m	0x0; nop.i	0x0 }

l400000000007DA20:
	{ nop.m	0x0; ld4	r14,[r39]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dpnt.few	400000000007E1D0 }

l400000000007DA40:
	{ addl	r14,7408,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000007DAA0 }

l400000000007DA70:
	{ addl	r14,6516,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	400000000007E370; }

l400000000007DAA0:
	{ adds	r8,0x0,r41; mov	pr,r72,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r70; }
	{ nop.m	0x0; mov.spnt	b0,r69,400000000007DAB0; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0; }

l400000000007DAD0:
	{ ld4.acq	r73,[r47]; nop.i	0x0; br.call.sptk.many	b0,termsig_handler; }
	{ nop.m	0x0; adds	r1,0x0,r71; (p18) br.cond.dptk.few	400000000007D760 }

l400000000007DAF0:
	{ nop.m	0x0; ld4	r14,[r54]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	400000000007D760; }

l400000000007DB10:
	{ nop.m	0x0; tbit.z	p07,p06,r33,0x0; (p06) br.cond.dptk.few	400000000007D760 }

l400000000007DB20:
	{ addl	r74,-7972,r1; nop.m	0x0; addl	r75,5,r0 }
	{ adds	r73,0x0,r0; nop.m	0x0; or	r33,0x1,r33; }
	{ ld8	r74,[r74]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r71; adds	r73,0x0,r8; br.call.sptk.many	b0,internal_warning; }
	{ nop.m	0x0; adds	r1,0x0,r71; br.cond.sptk.few	400000000007D760 }
400000000007DB70 11 48 02 5E B0 10 00 00 00 02 00 00 18 71 03 50 .H.^.........q.P
400000000007DB80 10 00 00 00 01 00 10 00 1C 01 42 00 B0 FC FF 48 ..........B....H
400000000007DB90 11 00 00 00 01 00 00 00 00 02 00 00 B8 DC F9 58 ...............X
400000000007DBA0 09 70 00 10 10 10 00 00 00 02 00 20 00 38 02 84 .p......... .8..
400000000007DBB0 11 00 00 00 01 00 70 50 38 0C 73 03 60 FC FF 4A ......pP8.s.`..J
400000000007DBC0 10 00 00 00 01 00 60 00 A4 0E F3 03 20 FE FF 4A ......`..... ..J
400000000007DBD0 0B 48 FD F9 FF 27 80 00 A4 00 42 E0 8F 84 7F 0B .H...'....B.....
400000000007DBE0 02 00 00 00 01 00 00 30 02 55 00 00 50 0C 00 07 .......0.U..P...
400000000007DBF0 18 00 00 00 01 00 C0 80 30 00 42 80 08 00 84 00 ........0.B.....

l400000000007DC00:
	{ nop.m	0x0; adds	r33,0x0,r0; br.cond.sptk.few	400000000007D710; }

l400000000007DC10:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ ld4	r14,[r8]; nop.m	0x0; adds	r1,0x0,r71; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x16,r14; (p06) br.cond.dptk.few	400000000007D7C0; }

l400000000007DC40:
	{ (p07) st4	[r0],r61; nop.m	0x0; nop.i	0x0 }

l400000000007DC46:
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ break.m	0x4000; nop; (p32) nop }
400000000007DC60 09 70 00 58 10 10 00 00 00 02 00 E0 01 61 00 84 .p.X.........a..
400000000007DC70 09 98 00 1E 10 10 00 00 00 02 00 C0 11 70 00 84 .............p..
400000000007DC80 08 00 38 58 90 11 00 00 00 02 00 C0 F0 9F 1C EE ..8X............
400000000007DC90 19 B8 00 26 00 21 00 00 00 02 00 03 10 FD FF 4B ...&.!.........K
400000000007DCA0 03 70 00 5A 10 10 00 00 00 02 00 C0 11 70 00 84 .p.Z.........p..
400000000007DCB0 08 00 38 5A 90 11 00 00 00 02 00 00 00 00 04 00 ..8Z............
400000000007DCC0 08 80 00 6A 10 10 40 01 00 00 42 20 06 98 58 00 ...j..@...B ..X.
400000000007DCD0 09 B0 00 00 00 21 90 01 C8 30 20 E0 01 00 00 84 .....!...0 .....
400000000007DCE0 08 00 00 00 01 00 10 8B 01 24 40 00 01 80 24 E6 .........$@...$.
400000000007DCF0 0B 70 00 4E 10 10 00 C9 C4 00 40 40 01 70 2C E6 .p.N......@@.p,.
400000000007DD00 0B A8 00 20 18 10 80 C1 54 00 42 C0 81 A8 00 84 ... ....T.B.....
400000000007DD10 09 D0 00 30 10 10 10 02 38 30 20 00 00 00 04 00 ...0....80 .....
400000000007DD20 09 80 F4 35 2C 22 E0 00 84 00 42 00 00 00 04 00 ...5,"....B.....
400000000007DD30 09 00 40 30 90 11 00 00 00 02 00 00 00 00 04 00 ..@0............
400000000007DD40 09 88 40 1C 00 21 00 00 00 02 00 00 C2 70 00 84 ..@..!.......p..
400000000007DD50 09 88 00 22 10 10 00 01 40 20 20 00 00 00 04 00 ..."....@  .....
400000000007DD60 09 30 04 22 87 39 00 00 00 02 00 20 52 82 30 80 .0.".9..... R.0.
400000000007DD70 CB 90 04 00 00 E4 21 01 00 00 42 E0 F0 8F 18 E6 ......!...B.....
400000000007DD80 11 78 3C 24 0E 20 00 00 00 02 80 03 50 02 00 43 .x<$. ......P..C
400000000007DD90 09 00 00 00 01 00 E0 00 38 30 20 00 00 00 04 00 ........80 .....
400000000007DDA0 11 00 00 00 01 00 70 70 84 0C 70 03 A0 FF FF 4A ......pp..p....J
400000000007DDB0 11 00 00 00 01 00 60 00 3C 0E F3 03 50 03 00 42 ......`.<...P..B
400000000007DDC0 09 00 00 00 01 00 70 00 58 0C 73 00 00 00 04 00 ......p.X.s.....
400000000007DDD0 11 00 00 00 01 80 51 A1 54 00 42 03 70 03 00 42 ......Q.T.B.p..B
400000000007DDE0 09 70 00 70 10 10 10 41 55 00 42 00 42 A9 00 84 .p.p...AU.B.B...
400000000007DDF0 08 00 00 00 01 00 F0 08 38 00 42 00 00 00 04 00 ........8.B.....
400000000007DE00 09 70 00 22 18 10 00 E0 41 20 23 00 00 00 04 00 .p."....A #.....
400000000007DE10 11 00 3C 70 90 11 60 00 38 0E 72 03 A0 00 00 43 ..<p..`.8.r....C
400000000007DE20 09 78 20 1C 18 14 00 00 00 02 00 A0 02 AB 00 84 .x .............
400000000007DE30 08 08 00 1C 18 10 00 00 00 02 00 C0 F0 08 00 07 ................
400000000007DE40 19 48 02 2A 18 10 00 00 00 02 00 00 68 00 80 10 .H.*........h...
400000000007DE50 03 C8 00 64 18 10 10 00 1C 01 42 C0 91 89 01 80 ...d......B.....
400000000007DE60 09 A8 00 1C 58 10 F0 00 38 30 20 00 00 00 04 00 ....X...80 .....
400000000007DE70 0B 78 A0 1E 00 21 00 00 3C 30 23 00 00 00 04 00 .x...!..<0#.....
400000000007DE80 0B A8 00 1C 18 11 E0 A0 54 00 42 00 00 00 04 00 ........T.B.....
400000000007DE90 09 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
400000000007DEA0 10 00 00 00 01 00 60 20 38 0E F3 03 C0 08 00 41 ......` 8......A
400000000007DEB0 09 70 00 72 10 10 00 00 00 02 00 80 48 0B E8 90 .p.r........H...
400000000007DEC0 10 00 00 00 01 00 70 00 38 0C F3 03 90 04 00 42 ......p.8......B
400000000007DED0 09 70 00 7C 10 10 00 00 00 02 00 20 C4 08 01 84 .p.|....... ....
400000000007DEE0 09 30 00 1C 87 39 E0 00 84 20 20 00 00 00 04 00 .0...9...  .....
400000000007DEF0 11 00 00 00 01 00 E0 F8 3B 58 C0 03 30 00 00 42 ........;X..0..B
400000000007DF00 0B 78 04 1C 00 21 00 00 00 02 00 E0 31 78 18 52 .x...!......1x.R
400000000007DF10 11 00 00 00 01 00 60 00 3C 0E E3 03 00 05 00 43 ......`.<......C
400000000007DF20 08 30 08 1C 87 39 00 00 00 02 00 C0 01 61 00 84 .0...9.......a..
400000000007DF30 19 78 00 00 00 21 00 00 00 02 00 03 E0 03 00 43 .x...!.........C
400000000007DF40 09 B8 00 1C 10 10 00 00 00 02 00 00 00 00 04 00 ................

l400000000007DF50:
	{ nop.m	0x0; sxt4	r14,r23; shladd	r25,r14,0x3,r25; }
	{ ld8	r14,[r25]; nop.i	0x0; adds	r14,0x14,r14; }
	{ ld4	r14,[r14]; nop.m	0x0; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x2,r14; nop.m	0x0; add	r46,r46,r15; }
	{ nop.m	0x0; (p06) adds	r51,0x0,r23; (p06) br.cond.dpnt.few	400000000007D9A0 }

l400000000007DF9C:
	{ Invalid; cmp.eq	p00,p00,r32,r0; nop }

l400000000007DFA0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x4,r14; (p06) br.cond.dptk.few	400000000007D9A0; }

l400000000007DFB0:
	{ nop.m	0x0; cmp4.eq	p06,p07,r23,r51; nop.i	0x0; }
	{ nop.m	0x0; (p06) addl	r51,-1,r0; br.cond.sptk.few	400000000007D9A0 }

l400000000007DFCC:
	{ (p15) invala; break.i	0x1000; Invalid }
400000000007DFD0 10 00 00 00 01 00 00 00 00 02 00 04 80 00 00 42 ...............B
400000000007DFE0 10 00 00 00 01 00 00 00 00 02 00 05 70 00 00 42 ............p..B
400000000007DFF0 03 80 DC 20 0C 20 60 09 00 00 48 00 02 81 1C 52 ... . `...H....R
400000000007E000 0B 30 50 20 87 B9 01 09 00 00 48 00 00 00 04 00 .0P ......H.....
400000000007E010 E2 80 00 00 00 21 00 00 00 02 00 80 42 81 38 80 .....!......B.8.
400000000007E020 09 00 00 00 01 00 E0 00 38 30 20 00 00 00 04 00 ........80 .....
400000000007E030 10 00 00 00 01 00 70 70 84 0C 70 03 10 FD FF 4A ......pp..p....J
400000000007E040 10 00 00 00 01 00 00 00 00 02 00 00 70 FD FF 48 ............p..H
400000000007E050 09 80 00 00 00 21 00 00 00 02 00 C0 12 00 00 90 .....!..........
400000000007E060 10 00 00 00 01 00 40 A1 40 1C 40 00 C0 FF FF 48 ......@.@.@....H
400000000007E070 08 00 00 00 01 00 90 04 88 00 42 00 00 00 04 00 ..........B.....
400000000007E080 19 50 02 46 10 10 00 00 00 02 00 00 08 17 FD 58 .P.F...........X
400000000007E090 03 70 00 46 10 10 10 00 1C 01 42 C0 F1 77 B0 80 .p.F......B..w..
400000000007E0A0 10 00 00 00 01 00 60 00 38 0E 73 03 40 00 00 42 ......`.8.s.@..B
400000000007E0B0 0B 70 04 1C 00 21 00 00 00 02 00 C0 31 70 18 52 .p...!......1p.R
400000000007E0C0 11 00 00 00 01 00 70 00 38 0C 63 03 E0 F8 FF 4B ......p.8.c....K
400000000007E0D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007E0E0 0B 70 00 5A 10 10 E0 08 38 00 42 00 00 00 04 00 .p.Z....8.B.....
400000000007E0F0 10 00 38 5A 90 11 00 00 00 02 00 00 B0 F8 FF 48 ..8Z...........H
400000000007E100 0B A8 50 2A 00 21 E0 00 54 20 20 00 00 00 04 00 ..P*.!..T  .....
400000000007E110 11 00 00 00 01 00 70 10 38 0C 73 03 90 FE FF 4A ......p.8.s....J
400000000007E120 0B 30 00 2C 87 B9 E1 08 00 00 48 00 00 00 04 00 .0.,......H.....
400000000007E130 D0 00 38 2A 90 11 00 00 00 02 00 03 60 00 00 42 ..8*........`..B
400000000007E140 09 D0 F0 35 2C 22 E0 10 00 00 48 C0 00 A0 1C E6 ...5,"....H.....
400000000007E150 08 00 00 00 01 00 00 70 54 20 23 00 00 00 04 00 .......pT #.....
400000000007E160 18 00 68 30 90 11 00 00 00 02 00 03 30 00 00 42 ..h0........0..B
400000000007E170 03 70 00 74 10 10 00 00 00 02 00 C0 00 70 1C E6 .p.t.........p..
400000000007E180 E8 00 38 86 90 11 00 00 00 02 00 00 00 00 04 00 ..8.............
400000000007E190 09 00 00 00 01 00 F0 08 00 00 48 E0 02 98 00 84 ..........H.....
400000000007E1A0 03 00 00 00 01 00 E0 00 5C 2C 00 20 E3 C8 48 80 ........\,. ..H.
400000000007E1B0 0B 70 00 32 18 10 E0 A0 38 00 42 00 00 00 04 00 .p.2....8.B.....
400000000007E1C0 10 70 00 1C 10 10 00 00 00 02 00 00 C0 FD FF 48 .p.............H

l400000000007E1D0:
	{ addl	r73,17,r0; nop.i	0x0; br.call.sptk.many	b0,signal_is_trapped; }
	{ adds	r1,0x0,r71; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	400000000007DA40; }

l400000000007E1F0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r41; (p06) br.cond.dptk.few	400000000007DA40 }

l400000000007E200:
	{ addl	r14,24316,r1; nop.m	0x0; addl	r15,-9804,r1; }
	{ nop.m	0x0; adds	r14,0x88,r14; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x1,r14; addl	r14,6456,r1; (p06) br.cond.dpnt.few	400000000007DA40; }

l400000000007E240:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; addl	r14,8388,r1; (p06) br.cond.dpnt.few	400000000007E3F0; }

l400000000007E260:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000007E3F0; }

l400000000007E280:
	{ nop.m	0x0; ld8	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r15,r14; (p06) br.cond.sptk.few	400000000007E3F0 }

l400000000007E2A0:
	{ addl	r14,7672,r1; nop.m	0x0; addl	r73,17,r0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,trap_handler; }
	{ adds	r1,0x0,r71; addl	r15,17,r0; addl	r74,1,r0; }
	{ addl	r14,9132,r1; nop.m	0x0; addl	r73,25956,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BBE0 }
	{ add	r49,r25,r49; ld8	r14,[r49]; nop.i	0x0; }
	{ adds	r14,0x18,r14; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; and	r14,0x5,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x1,r14; (p06) br.cond.dpnt.few	400000000007E520 }

l400000000007E350:
	{ nop.m	0x0; adds	r15,0x10,r12; nop.i	0x0; }
	{ ld4	r23,[r15]; adds	r15,0x0,r0; br.cond.sptk.few	400000000007DF50 }

l400000000007E370:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000079240; }
	{ adds	r8,0x0,r41; adds	r1,0x0,r71; mov	pr,r72,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r70; mov.spnt	b0,r69,400000000007E390 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l400000000007E3B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000007A5C0; }
	{ ld4	r14,[r39]; nop.m	0x0; adds	r1,0x0,r71; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	400000000007DA40 }

l400000000007E3E0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000007E1D0 }

l400000000007E3F0:
	{ adds	r73,0x0,r41; nop.i	0x0; br.call.sptk.many	b0,run_sigchld_trap; }
	{ nop.m	0x0; adds	r1,0x0,r71; br.cond.sptk.few	400000000007DA40 }
400000000007E410 0B A8 60 2A 00 21 F0 00 54 20 20 00 00 00 04 00 ..`*.!..T  .....
400000000007E420 10 00 00 00 01 00 60 00 3C 0E 28 03 00 FB FF 4A ......`.<.(....J
400000000007E430 11 48 0A 00 00 24 00 00 00 02 00 00 D8 17 03 50 .H...$.........P
400000000007E440 11 08 00 8E 00 21 60 00 20 0E F3 03 30 02 00 43 .....!`. ...0..C
400000000007E450 0B 70 00 88 10 10 70 00 38 0C 73 00 00 00 04 00 .p....p.8.s.....
400000000007E460 C9 70 00 42 10 90 91 01 C8 30 20 00 00 00 04 00 .p.B.....0 .....
400000000007E470 11 00 00 00 01 80 E1 F8 3B 58 40 03 B0 FA FF 48 ........;X@....H

l400000000007E480:
	{ adds	r15,0x10,r12; ld8	r14,[r50]; nop.i	0x0; }
	{ ld4	r23,[r15]; nop.m	0x0; nop.i	0x0; }

l400000000007E4A0:
	{ nop.m	0x0; sxt4	r16,r23; adds	r15,0x0,r0; }
	{ nop.m	0x0; shladd	r14,r16,0x3,r14; nop.i	0x0; }
	{ ld8	r14,[r14]; adds	r14,0x14,r14; nop.i	0x0; }
	{ ld4	r14,[r14]; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2,r14; add	r46,r46,r15 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dptk.few	400000000007DFA0; }

l400000000007E500:
	{ (p06) adds	r51,0x0,r23; nop.m	0x0; nop.i	0x0 }

l400000000007E506:
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ break.m	0x4000; nop; nop }

l400000000007E520:
	{ st4	[r0],r57; addl	r73,2,r0; br.call.sptk.many	b0,signal_is_trapped; }
	{ adds	r1,0x0,r71; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	400000000007E560 }

l400000000007E540:
	{ ld4	r73,[r33]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000077B80; }
	{ adds	r1,0x0,r71; st4	[r8],r63; nop.i	0x0 }

l400000000007E560:
	{ addl	r14,1,r0; ld4	r33,[r59]; addl	r73,2,r0; }
	{ st4	[r14],r59; nop.i	0x0; br.call.sptk.many	b0,maybe_call_trap_handler; }
	{ nop.m	0x0; adds	r1,0x0,r71; nop.i	0x0 }
	{ st4	[r33],r59; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	400000000007E650 }

l400000000007E5A0:
	{ nop.m	0x0; ld8	r33,[r66]; nop.i	0x0; }
	{ cmp.eq	p07,p06,r65,r33; nop.i	0x0; (p07) br.cond.dpnt.few	400000000007E480; }

l400000000007E5C0:
	{ cmp.eq	p07,p06,r64,r33; nop.i	0x0; (p07) br.cond.dpnt.few	400000000007E720; }

l400000000007E5D0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000077140; }
	{ adds	r1,0x0,r71; cmp.eq	p07,p06,0x0,r33; (p07) br.cond.dpnt.few	400000000007E630; }

l400000000007E5F0:
	{ cmp.eq	p07,p06,0x1,r33; addl	r73,2,r0; (p07) br.cond.dpnt.few	400000000007E480; }

l400000000007E600:
	{ nop.m	0x0; ld8	r14,[r33],8; nop.i	0x0; }
	{ ld8	r1,[r33],-8; mov.spnt	b6,r14,400000000007E610; br.call.sptk.many	b0,b6; }
	{ nop.m	0x0; adds	r1,0x0,r71; br.cond.sptk.few	400000000007E480 }

l400000000007E630:
	{ nop.m	0x0; addl	r73,2,r0; br.call.sptk.many	b0,termsig_handler; }
	{ adds	r1,0x0,r71; nop.m	0x0; nop.i	0x0 }

l400000000007E650:
	{ adds	r14,0x10,r12; nop.i	0x0; nop.i	0x0 }
	{ ld4	r23,[r14]; ld8	r14,[r50]; br.cond.sptk.few	400000000007E4A0 }
400000000007E670 08 00 00 00 01 00 90 04 84 20 20 00 00 00 04 00 .........  .....
400000000007E680 19 00 00 88 90 11 00 00 00 02 00 00 08 95 FF 58 ...............X
400000000007E690 08 70 04 00 00 24 10 02 EC 20 20 00 00 00 04 00 .p...$...  .....
400000000007E6A0 09 08 00 8E 00 21 00 40 FC 20 23 20 29 00 00 90 .....!.@. # )...
400000000007E6B0 11 00 38 76 90 11 00 00 00 02 00 00 98 13 03 50 ..8v...........P
400000000007E6C0 08 70 40 18 00 21 00 00 00 02 00 20 00 38 02 84 .p@..!..... .8..
400000000007E6D0 09 00 84 76 90 11 00 00 00 02 00 E0 01 00 00 84 ...v............
400000000007E6E0 09 B8 00 1C 10 10 E0 00 C8 30 20 00 00 00 04 00 .........0 .....
400000000007E6F0 03 00 00 00 01 00 00 01 5C 2C 00 C0 01 71 48 80 ........\,...qH.
400000000007E700 0B 70 00 1C 18 10 E0 A0 38 00 42 00 00 00 04 00 .p......8.B.....
400000000007E710 10 70 00 1C 10 10 00 00 00 02 00 00 D0 FD FF 48 .p.............H

l400000000007E720:
	{ addl	r73,2,r0; nop.i	0x0; br.call.sptk.many	b0,signal_is_trapped; }
	{ cmp4.eq	p07,p06,0x0,r8; adds	r1,0x0,r71; (p07) br.cond.dpnt.few	400000000007E790; }

l400000000007E740:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000077140; }
	{ nop.m	0x0; adds	r1,0x0,r71; br.cond.sptk.few	400000000007E5F0 }
400000000007E760 09 70 40 18 00 21 00 00 00 02 00 E0 01 00 00 84 .p@..!..........
400000000007E770 09 00 00 00 01 00 30 01 38 20 20 00 00 00 04 00 ......0.8  .....
400000000007E780 10 00 00 00 01 00 70 01 4C 00 42 00 20 FA FF 48 ......p.L.B. ..H

l400000000007E790:
	{ addl	r73,2,r0; nop.i	0x0; br.call.sptk.many	b0,trap_to_sighandler; }
	{ adds	r1,0x0,r71; adds	r33,0x0,r8; br.call.sptk.many	b0,fn4000000000077140; }
	{ adds	r1,0x0,r71; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	400000000007E5F0 }

l400000000007E7C0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000007E630; }
400000000007E7D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007E7E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007E7F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007E800 01 18 19 0A 80 05 20 02 00 62 00 80 04 08 00 84 ...... ..b......
400000000007E810 11 00 00 00 01 00 00 00 00 02 00 00 38 D0 F9 58 ............8..X
400000000007E820 18 08 00 48 00 21 00 02 20 00 42 00 00 00 00 20 ...H.!.. .B.... 
400000000007E830 09 08 01 10 10 10 00 00 00 02 00 00 30 02 AA 00 ............0...
400000000007E840 09 70 B0 02 3A 24 00 81 05 74 48 00 20 0A 00 07 .p..:$...tH. ...
400000000007E850 09 78 00 1C 10 10 00 01 40 20 20 00 00 00 04 00 .x......@  .....
400000000007E860 09 78 04 1E 00 21 00 00 00 02 00 E0 00 80 18 E6 .x...!..........
400000000007E870 11 00 3C 1C 90 11 00 00 00 02 80 03 20 00 00 43 ..<......... ..C
400000000007E880 11 00 84 40 90 11 00 00 00 02 00 80 08 00 84 00 ...@............
400000000007E890 11 28 01 00 00 21 00 00 00 02 00 00 F8 EC FF 58 .(...!.........X
400000000007E8A0 09 08 00 48 00 21 00 08 81 20 23 00 30 02 AA 00 ...H.!... #.0...
400000000007E8B0 11 00 00 00 01 00 00 10 05 80 03 80 08 00 84 00 ................

;; fn400000000007E8C0: 400000000007E8C0
;;   Called from:
;;     400000000007EB3C (in reap_dead_jobs)
;;     400000000007EC5C (in notify_and_cleanup)
;;     400000000007EC9C (in list_all_jobs)
;;     400000000007ED1C (in list_running_jobs)
;;     400000000007ED9C (in list_stopped_jobs)
;;     40000000000815CC (in wait_for_single_pid)
;;     40000000000818CC (in wait_for_background_pids)
;;     40000000000834BC (in stop_pipeline)
fn400000000007E8C0 proc
	{ alloc	r41,ar.pfs,0xD,0x0,0xB; addl	r36,-20676,r1; nop.b	0x0 }
	{ addl	r15,7464,r1; mov	r40,b0; addl	r37,7472,r1; }
	{ nop.m	0x0; addl	r38,7468,r1; adds	r34,0x0,r0 }
	{ adds	r33,0x0,r0; addl	r35,7444,r1; adds	r42,0x0,r1; }
	{ adds	r36,0x1C,r36; ld4	r14,[r36]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000007EA60; }

l400000000007E920:
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r15; nop.i	0x0; (p06) br.cond.dpnt.few	400000000007EA60; }

l400000000007E940:
	{ nop.m	0x0; ld4	r15,[r37]; cmp4.lt	p06,p07,0x0,r14 }
	{ ld4	r39,[r38]; adds	r15,0x1,r15; nop.i	0x0; }
	{ st4	[r15],r37; nop.i	0x0; (p07) br.cond.dpnt.few	400000000007E9F0; }

l400000000007E970:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000007E980:
	{ ld8	r14,[r35]; add	r14,r14,r34; adds	r34,0x8,r34; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ adds	r15,0x14,r14; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	400000000007E9D0; }

l400000000007E9B0:
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x4,r15; (p07) br.cond.dpnt.few	400000000007EA80 }

l400000000007E9D0:
	{ adds	r33,0x1,r33; ld4	r14,[r36]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r33,r14; (p06) br.cond.dptk.few	400000000007E980 }

l400000000007E9F0:
	{ adds	r32,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,coproc_reap; }
	{ ld4	r14,[r37]; adds	r1,0x0,r42; mov.spnt	b0,r40,400000000007EA00; }
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r14; nop.m	0x0; mov.i	ar.pfs,r41; }
	{ st4	[r14],r37; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	400000000007EA60; }

l400000000007EA30:
	{ nop.m	0x0; ld4	r14,[r38]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,r14,r39; nop.i	0x0; (p06) br.cond.dpnt.few	400000000007EA60; }

l400000000007EA50:
	{ alloc	r2,ar.pfs,0x1,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn400000000007D580 }

l400000000007EA60:
	{ nop.m	0x0; mov.i	ar.pfs,r41; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r40,400000000007EA70; br.ret	b0 }

l400000000007EA80:
	{ adds	r14,0x18,r14; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x1; (p06) br.cond.dptk.few	400000000007E9D0 }

l400000000007EAA0:
	{ adds	r43,0x0,r33; nop.m	0x0; adds	r44,0x0,r0 }
	{ adds	r33,0x1,r33; nop.m	0x0; br.call.sptk.many	b0,delete_job; }
	{ ld4	r14,[r36]; nop.m	0x0; adds	r1,0x0,r42; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r33,r14; (p06) br.cond.dptk.few	400000000007E980 }

l400000000007EAE0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000007E9F0; }
400000000007EAF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; reap_dead_jobs: 400000000007EB00
;;   Called from:
;;     4000000000083CEC (in stop_pipeline)
reap_dead_jobs proc
	{ alloc	r33,ar.pfs,0x4,0x0,0x3; mov	r32,b0; adds	r34,0x0,r1; }
	{ adds	r35,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000007A7C0; }
	{ adds	r1,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ nop.m	0x0; mov.spnt	b0,r32,400000000007EB30; br.cond.sptk.many	fn400000000007E8C0; }
400000000007EB40 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
400000000007EB50 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007EB60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007EB70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; notify_and_cleanup: 400000000007EB80
;;   Called from:
;;     4000000000029F1C (in fn4000000000029100)
;;     4000000000029F1C (in fn4000000000029100)
;;     40000000000804AC (in wait_for)
;;     40000000000804AC (in wait_for)
;;     4000000000080B2C (in wait_for)
;;     40000000000AEE4C (in run_debug_trap)
notify_and_cleanup proc
	{ alloc	r33,ar.pfs,0x3,0x0,0x3; addl	r14,7464,r1; mov	r32,b0 }
	{ adds	r34,0x0,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; addl	r14,6516,r1; (p06) br.cond.dpnt.few	400000000007EC60; }

l400000000007EBB0:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; addl	r14,6512,r1; (p06) br.cond.dpnt.few	400000000007EC20; }

l400000000007EBD0:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000007EC20 }

l400000000007EBF0:
	{ addl	r14,8412,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000007EC40 }

l400000000007EC20:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000079240; }
	{ adds	r1,0x0,r34; nop.m	0x0; nop.i	0x0 }

l400000000007EC40:
	{ nop.m	0x0; mov.i	ar.pfs,r33; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r32,400000000007EC50; br.cond.sptk.many	fn400000000007E8C0 }

l400000000007EC60:
	{ nop.m	0x0; mov.i	ar.pfs,r33; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r32,400000000007EC70; br.ret	b0; }

;; list_all_jobs: 400000000007EC80
;;   Called from:
;;     40000000000F8B0C (in fn40000000000F8780)
;;     40000000000FF6AC (in jobs_builtin)
list_all_jobs proc
	{ alloc	r35,ar.pfs,0x5,0x0,0x5; mov	r34,b2; adds	r36,0x0,r1; }
	{ addl	r33,-1,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000007E8C0; }
	{ adds	r1,0x0,r36; mov.spnt	b0,r34,400000000007ECA0; mov.i	ar.pfs,r35; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn400000000007A100; }
400000000007ECC0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
400000000007ECD0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007ECE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007ECF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; list_running_jobs: 400000000007ED00
;;   Called from:
;;     40000000000FF6EC (in jobs_builtin)
list_running_jobs proc
	{ alloc	r35,ar.pfs,0x5,0x0,0x5; mov	r34,b2; adds	r36,0x0,r1; }
	{ addl	r33,1,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000007E8C0; }
	{ adds	r1,0x0,r36; mov.spnt	b0,r34,400000000007ED20; mov.i	ar.pfs,r35; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn400000000007A100; }
400000000007ED40 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
400000000007ED50 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007ED60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007ED70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; list_stopped_jobs: 400000000007ED80
;;   Called from:
;;     40000000000FF72C (in jobs_builtin)
list_stopped_jobs proc
	{ alloc	r35,ar.pfs,0x5,0x0,0x5; mov	r34,b2; adds	r36,0x0,r1; }
	{ addl	r33,2,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000007E8C0; }
	{ adds	r1,0x0,r36; mov.spnt	b0,r34,400000000007EDA0; mov.i	ar.pfs,r35; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn400000000007A100; }
400000000007EDC0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
400000000007EDD0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007EDE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007EDF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; initialize_job_signals: 400000000007EE00
;;   Called from:
;;     40000000000B53AC (in initialize_signals)
;;     40000000000B542C (in initialize_signals)
initialize_job_signals proc
	{ alloc	r33,ar.pfs,0x5,0x0,0x3; addl	r14,6516,r1; mov	r32,b0 }
	{ adds	r34,0x0,r1; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ nop.m	0x0; mov.spnt	b0,r32,400000000007EE20; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; addl	r14,5868,r1; (p07) br.cond.dpnt.few	400000000007EF20; }

l400000000007EE50:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	400000000007EE70; br.ret	b0 }

l400000000007EE6C:
	{ Invalid; (p04) invala.e	f45; nop }

l400000000007EE70:
	{ addl	r36,-7628,r1; nop.m	0x0; addl	r35,20,r0; }
	{ ld8	r36,[r36]; nop.i	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r34; nop.m	0x0; addl	r35,21,r0; }
	{ addl	r14,7516,r1; addl	r36,-7628,r1; nop.i	0x0 }
	{ ld8	r36,[r36]; st8	[r8],r14; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r34; nop.m	0x0; addl	r35,22,r0; }
	{ addl	r14,7524,r1; addl	r36,-7628,r1; nop.i	0x0 }
	{ ld8	r36,[r36]; st8	[r8],r14; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ addl	r14,7484,r1; nop.m	0x0; mov.spnt	b0,r32,400000000007EF00; }
	{ st8	[r8],r14; nop.i	0x0; br.ret	b0 }

l400000000007EF20:
	{ addl	r36,-10004,r1; nop.m	0x0; addl	r35,2,r0; }
	{ ld8	r36,[r36]; nop.i	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r34; nop.m	0x0; addl	r35,20,r0 }
	{ addl	r36,1,r0; nop.m	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r34; nop.m	0x0; addl	r35,22,r0 }
	{ addl	r36,1,r0; nop.m	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r34; nop.m	0x0; addl	r35,21,r0 }
	{ addl	r36,1,r0; nop.m	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ nop.m	0x0; mov.spnt	b0,r32,400000000007EFB0; br.ret	b0; }
400000000007EFC0 01 08 15 06 80 05 00 02 00 62 00 40 04 08 00 84 .........b.@....
400000000007EFD0 11 00 00 00 01 00 00 00 00 02 00 00 38 FE FF 58 ............8..X
400000000007EFE0 03 08 00 44 00 21 30 92 00 00 48 C0 C1 0E E8 90 ...D.!0...H.....
400000000007EFF0 11 20 01 1C 18 10 00 00 00 02 00 00 18 5B 03 50 . ...........[.P
400000000007F000 11 08 00 44 00 21 00 00 00 02 00 00 A8 C1 F9 58 ...D.!.........X
400000000007F010 08 08 00 44 00 21 00 00 00 02 00 60 04 40 00 84 ...D.!.....`.@..
400000000007F020 19 20 49 00 00 24 00 00 00 02 00 00 08 C5 F9 58 . I..$.........X
400000000007F030 09 08 00 44 00 21 00 00 00 02 00 00 10 02 AA 00 ...D.!..........
400000000007F040 11 00 00 00 01 00 00 00 05 80 03 80 08 00 84 00 ................
400000000007F050 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007F060 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007F070 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; give_terminal_to: 400000000007F080
;;   Called from:
;;     4000000000070B0C (in programming_error)
;;     400000000007F6DC (in initialize_job_control)
;;     40000000000802AC (in wait_for)
;;     40000000000809AC (in wait_for)
;;     4000000000080E2C (in wait_for)
;;     400000000008245C (in start_job)
;;     400000000008245C (in start_job)
;;     400000000008336C (in make_child)
;;     40000000000846AC (in stop_pipeline)
;;     400000000008525C (in end_job_control)
;;     400000000009541C (in command_substitute)
;;     40000000000AEE2C (in run_debug_trap)
;;     40000000000B465C (in throw_to_top_level)
give_terminal_to proc
	{ alloc	r37,ar.pfs,0xA,0x0,0x7; adds	r12,0xFFFFFFFFFFFFFF00,r12; nop.b	0x0 }
	{ addl	r14,5868,r1; mov	r36,b4; adds	r38,0x0,r1; }
	{ ld4	r14,[r14]; adds	r8,0x0,r0; or	r33,r14,r33; }
	{ cmp4.eq	p06,p07,0x0,r33; nop.i	0x0; (p07) br.cond.dpnt.few	400000000007F0E0; }

l400000000007F0C0:
	{ nop.m	0x0; mov.i	ar.pfs,r37; mov.spnt	b0,r36,400000000007F0C0 }
	{ nop.m	0x0; adds	r12,0x100,r12; br.ret	b0; }

l400000000007F0E0:
	{ adds	r39,0x90,r12; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r38; nop.m	0x0; adds	r39,0x90,r12 }
	{ addl	r40,22,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B400; }
	{ adds	r1,0x0,r38; nop.m	0x0; adds	r39,0x90,r12 }
	{ addl	r40,21,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B400; }
	{ adds	r1,0x0,r38; nop.m	0x0; adds	r39,0x90,r12 }
	{ addl	r40,20,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B400; }
	{ adds	r1,0x0,r38; nop.m	0x0; adds	r39,0x90,r12 }
	{ addl	r40,17,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B400; }
	{ adds	r1,0x0,r38; adds	r39,0x10,r12; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r41,0x10,r12; adds	r1,0x0,r38; nop.i	0x0 }
	{ adds	r40,0x90,r12; adds	r39,0x0,r0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r38; adds	r40,0x0,r32; addl	r14,5900,r1; }
	{ ld4	r39,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AAC0; }
	{ adds	r1,0x0,r38; cmp4.lt	p07,p06,r8,r0; addl	r39,2,r0 }
	{ adds	r40,0x10,r12; adds	r41,0x0,r0; (p07) br.cond.dpnt.few	400000000007F230; }

l400000000007F1E0:
	{ nop.m	0x0; addl	r14,5892,r1; nop.i	0x0; }
	{ st4	[r32],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r8,0x0,r0; adds	r1,0x0,r38; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,400000000007F210; nop.i	0x0 }
	{ adds	r12,0x100,r12; nop.m	0x0; br.ret	b0; }

l400000000007F230:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ adds	r1,0x0,r38; adds	r34,0x0,r8; addl	r39,2,r0 }
	{ ld4	r35,[r8]; adds	r40,0x10,r12; adds	r41,0x0,r0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ addl	r8,-1,r0; adds	r1,0x0,r38; nop.b	0x0 }
	{ st4	[r35],r34; mov.i	ar.pfs,r37; mov.spnt	b0,r36,400000000007F280 }
	{ nop.m	0x0; adds	r12,0x100,r12; br.ret	b0; }
400000000007F2A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007F2B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007F2C0 08 10 19 08 80 05 E0 E0 06 74 48 20 04 00 C4 00 .........tH ....
400000000007F2D0 09 00 00 00 01 00 30 02 04 00 42 00 00 00 04 00 ......0...B.....
400000000007F2E0 11 28 01 1C 18 10 40 A2 00 00 48 00 28 58 03 50 .(....@...H.(X.P
400000000007F2F0 03 08 00 46 00 21 40 B2 00 00 48 C0 C1 0B E8 90 ...F.!@...H.....
400000000007F300 11 28 01 1C 18 10 00 00 00 02 00 00 08 58 03 50 .(...........X.P
400000000007F310 03 08 00 46 00 21 40 AA 00 00 48 C0 41 0E E8 90 ...F.!@...H.A...
400000000007F320 11 28 01 1C 18 10 00 00 00 02 00 00 E8 57 03 50 .(...........W.P
400000000007F330 03 08 00 46 00 21 40 92 00 00 48 A0 C4 EE 23 9F ...F.!@...H...#.
400000000007F340 11 28 01 4A 18 10 00 00 00 02 00 00 C8 57 03 50 .(.J.........W.P
400000000007F350 09 08 00 46 00 21 00 00 00 02 00 A0 04 00 00 84 ...F.!..........
400000000007F360 0B 70 20 02 2E 24 40 02 38 20 20 C0 C1 0E E8 90 .p ..$@.8  .....
400000000007F370 11 00 20 1C 98 11 00 00 00 02 00 00 18 FD FF 58 .. ............X
400000000007F380 11 08 00 46 00 21 00 00 00 02 00 00 28 BE F9 58 ...F.!......(..X
400000000007F390 08 08 00 46 00 21 00 00 00 02 00 80 04 40 00 84 ...F.!.......@..
400000000007F3A0 19 28 01 40 00 21 00 00 00 02 00 00 88 C1 F9 58 .(.@.!.........X
400000000007F3B0 09 08 00 46 00 21 00 00 00 02 00 00 20 02 AA 00 ...F.!...... ...
400000000007F3C0 11 00 00 00 01 00 00 08 05 80 03 80 08 00 84 00 ................
400000000007F3D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007F3E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007F3F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; initialize_job_control: 400000000007F400
;;   Called from:
;;     40000000000852E6 (in restart_job_control)
initialize_job_control proc
	{ alloc	r42,ar.pfs,0xF,0x0,0xC; adds	r43,0x0,r1; mov	r41,b1 }
	{ nop.m	0x0; addl	r32,5896,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B060; }
	{ adds	r1,0x0,r43; st4	[r8],r32; nop.i	0x0 }
	{ cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; addl	r15,-1,r0; (p07) br.cond.spnt.few	400000000007FDC0; }

l400000000007F450:
	{ addl	r35,6516,r1; addl	r33,5900,r1; addl	r36,-10652,r1; }
	{ nop.m	0x0; ld4	r14,[r35]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; addl	r14,7364,r1; (p07) br.cond.dpnt.few	400000000007FBB0; }

l400000000007F480:
	{ nop.m	0x0; st4	[r15],r33; nop.i	0x0 }
	{ ld8	r36,[r36]; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dpnt.few	400000000007FAB0 }

l400000000007F4B0:
	{ ld8	r44,[r36]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BBC0; }
	{ adds	r1,0x0,r43; adds	r44,0x0,r8; br.call.sptk.many	b0,fn400000000001A4A0; }
	{ nop.m	0x0; adds	r1,0x0,r43; adds	r44,0x0,r8 }
	{ st4	[r8],r33; addl	r45,1,r0; addl	r46,-1,r0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,move_to_high_fd; }
	{ adds	r1,0x0,r43; ld4	r14,[r32]; adds	r44,0x0,r8 }
	{ st4	[r8],r33; addl	r34,5900,r1; addl	r38,5896,r1 }
	{ addl	r37,5892,r1; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	400000000007FA40 }

l400000000007F530:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B640; }
	{ adds	r1,0x0,r43; st4	[r8],r37; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8 }
	{ addl	r44,21,r0; adds	r45,0x0,r0; (p07) br.cond.dpnt.few	400000000007FCD0; }

l400000000007F560:
	{ nop.m	0x0; ld4	r14,[r32]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,r14,r8; nop.i	0x0; (p06) br.cond.dpnt.few	400000000007F5F0; }

l400000000007F580:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r43; adds	r34,0x0,r8; nop.i	0x0 }
	{ adds	r44,0x0,r0; addl	r45,21,r0; br.call.sptk.many	b0,fn400000000001B520; }
	{ adds	r1,0x0,r43; nop.m	0x0; addl	r44,21,r0 }
	{ adds	r45,0x0,r34; nop.m	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ nop.m	0x0; adds	r1,0x0,r43; nop.i	0x0 }
	{ ld4	r44,[r33]; nop.m	0x0; br.cond.sptk.few	400000000007F530; }

l400000000007F5F0:
	{ addl	r38,5888,r1; ld4	r14,[r32]; addl	r39,5896,r1 }
	{ nop.m	0x0; addl	r40,-1,r0; nop.i	0x0; }
	{ st4	[r14],r38; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B1A0; }
	{ nop.m	0x0; ld4	r14,[r38]; adds	r1,0x0,r43 }
	{ nop.m	0x0; st4	[r8],r32; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,r14,r8; (p06) br.cond.dpnt.few	400000000007F8C0 }

l400000000007F650:
	{ adds	r44,0x0,r0; adds	r45,0x0,r8; br.call.sptk.many	b0,fn400000000001BDE0; }
	{ adds	r1,0x0,r43; cmp4.lt	p06,p07,r8,r0; nop.i	0x0 }
	{ addl	r15,1,r0; adds	r45,0x0,r0; (p06) br.cond.dpnt.few	400000000007F870; }

l400000000007F680:
	{ nop.m	0x0; addl	r34,5868,r1; nop.i	0x0 }
	{ ld4	r44,[r39]; ld4	r14,[r38]; nop.i	0x0; }
	{ st4	[r15],r34; cmp4.eq	p07,p06,r14,r44; (p07) br.cond.spnt.few	400000000007F8E0; }

l400000000007F6B0:
	{ nop.m	0x0; ld4	r14,[r37]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,r44,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000007F8E0; }

l400000000007F6D0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,give_terminal_to; }
	{ adds	r1,0x0,r43; cmp4.lt	p07,p06,r8,r0; nop.i	0x0 }
	{ addl	r46,5,r0; adds	r44,0x0,r0; (p07) br.cond.dpnt.few	400000000007FD50; }

l400000000007F700:
	{ ld4	r14,[r34]; nop.m	0x0; addl	r45,-7932,r1; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p06) br.cond.spnt.few	400000000007F8E0; }

l400000000007F720:
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ nop.m	0x0; adds	r1,0x0,r43; adds	r44,0x0,r8 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,internal_error; }
	{ adds	r1,0x0,r43; nop.m	0x0; nop.i	0x0; }

l400000000007F760:
	{ ld8	r44,[r36]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BBC0; }
	{ ld4	r44,[r33]; nop.m	0x0; adds	r1,0x0,r43 }
	{ addl	r45,2,r0; nop.m	0x0; addl	r46,1,r0; }
	{ cmp4.eq	p06,p07,r44,r8; nop.i	0x0; (p06) br.cond.dpnt.few	400000000007F7C0; }

l400000000007F7A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B7E0; }
	{ adds	r1,0x0,r43; nop.m	0x0; nop.i	0x0; }

l400000000007F7C0:
	{ addl	r45,-7644,r1; nop.m	0x0; addl	r44,17,r0; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ ld4	r45,[r34]; adds	r1,0x0,r43; addl	r44,109,r0; }
	{ cmp4.eq	p06,p07,0x0,r45; (p06) addl	r45,43,r0; nop.i	0x0; }

l400000000007F7FC:
	{ nop; zxt4	r11,r0; break.i	0x1000 }

l400000000007F806:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ (p07) fwb; nop; nop }
	{ (p03) chk.a.clr	f0,3FFFFFFFFFD43106; nop; break.i	0x80000 }

l400000000007F830:
	{ nop.m	0x0; ld8	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; cmp.lt	p06,p07,r14,r0; (p06) br.cond.dpnt.few	400000000007FC20 }

l400000000007F850:
	{ ld4	r8,[r34]; nop.m	0x0; mov.i	ar.pfs,r42; }
	{ nop.m	0x0; mov.spnt	b0,r41,400000000007F860; br.ret	b0 }

l400000000007F870:
	{ addl	r45,-7948,r1; addl	r46,5,r0; adds	r44,0x0,r0; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r43; adds	r44,0x0,r8; br.call.sptk.many	b0,sys_error; }
	{ ld4	r14,[r38]; nop.m	0x0; adds	r1,0x0,r43; }
	{ st4	[r14],r39; nop.m	0x0; nop.i	0x0; }

l400000000007F8C0:
	{ addl	r34,5868,r1; nop.m	0x0; addl	r14,1,r0; }
	{ st4	[r14],r34; nop.m	0x0; nop.i	0x0 }

l400000000007F8E0:
	{ ld4	r44,[r33]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B640; }
	{ adds	r1,0x0,r43; nop.m	0x0; cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r8 }
	{ adds	r37,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	400000000007F930; }

l400000000007F910:
	{ nop.m	0x0; ld4	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,r14,r8; (p06) br.cond.dpnt.few	400000000007FB50; }

l400000000007F930:
	{ cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r40; nop.i	0x0; (p06) br.cond.dpnt.few	400000000007F960; }

l400000000007F940:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ adds	r1,0x0,r43; st4	[r40],r8; nop.i	0x0; }

l400000000007F960:
	{ addl	r45,-7940,r1; addl	r46,5,r0; adds	r44,0x0,r0; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r43; nop.m	0x0; adds	r44,0x0,r8 }
	{ adds	r45,0x0,r37; nop.m	0x0; br.call.sptk.many	b0,sys_error; }
	{ adds	r1,0x0,r43; nop.m	0x0; addl	r46,5,r0 }
	{ st4	[r0],r34; adds	r44,0x0,r0; addl	r45,-7932,r1; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r43; adds	r44,0x0,r8; br.call.sptk.many	b0,internal_error; }
	{ nop.m	0x0; adds	r1,0x0,r43; br.cond.sptk.few	400000000007F760 }

l400000000007F9F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,get_tty_state; }
	{ adds	r1,0x0,r43; addl	r32,-20676,r1; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; cmp.lt	p06,p07,r14,r0; (p07) br.cond.dptk.few	400000000007F850 }

l400000000007FA30:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000007FC20 }

l400000000007FA40:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B1A0; }
	{ adds	r1,0x0,r43; adds	r44,0x0,r0; nop.i	0x0 }
	{ adds	r45,0x0,r8; st4	[r8],r38; br.call.sptk.many	b0,fn400000000001BDE0; }
	{ adds	r1,0x0,r43; ld4	r44,[r34]; nop.i	0x0 }
	{ ld4	r45,[r38]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AAC0; }
	{ nop.m	0x0; adds	r1,0x0,r43; nop.i	0x0 }
	{ ld4	r44,[r34]; nop.m	0x0; br.cond.sptk.few	400000000007F530; }

l400000000007FAB0:
	{ ld8	r44,[r36]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BBC0; }
	{ adds	r1,0x0,r43; adds	r44,0x0,r8; br.call.sptk.many	b0,fn400000000001C1C0; }
	{ cmp4.eq	p06,p07,0x0,r8; adds	r1,0x0,r43; (p06) br.cond.dpnt.few	400000000007FC70; }

l400000000007FAE0:
	{ nop.m	0x0; (p07) ld4	r44,[r33]; nop.i	0x0; }

l400000000007FAEC:
	{ invala; cmp.lt	p00,p00,r32,r0; (p48) mov	pr,r107,0xEE3E }
	{ (p14) nop; (p21) cmp.lt	p00,p18,r0,r0; Invalid }

l400000000007FB00:
	{ addl	r45,1,r0; addl	r46,-1,r0; br.call.sptk.many	b0,move_to_high_fd; }
	{ adds	r1,0x0,r43; ld4	r14,[r32]; adds	r44,0x0,r8 }
	{ st4	[r8],r33; addl	r34,5900,r1; addl	r38,5896,r1 }
	{ addl	r37,5892,r1; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	400000000007F530 }

l400000000007FB40:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000007FA40; }

l400000000007FB50:
	{ nop.m	0x0; ld4	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.sptk.few	400000000007F760 }

l400000000007FB70:
	{ addl	r45,-7932,r1; addl	r46,5,r0; adds	r44,0x0,r0; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r43; adds	r44,0x0,r8; br.call.sptk.many	b0,internal_error; }
	{ nop.m	0x0; adds	r1,0x0,r43; br.cond.sptk.few	400000000007F760; }

l400000000007FBB0:
	{ addl	r36,-10652,r1; addl	r34,5868,r1; nop.i	0x0 }
	{ addl	r14,5888,r1; addl	r15,-1,r0; addl	r33,5900,r1; }
	{ nop.m	0x0; ld8	r36,[r36]; nop.i	0x0 }
	{ st4	[r0],r34; st4	[r15],r14; nop.i	0x0; }
	{ ld8	r44,[r36]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BBC0; }
	{ nop.m	0x0; adds	r1,0x0,r43; nop.i	0x0 }
	{ st4	[r8],r33; nop.m	0x0; br.cond.sptk.few	400000000007F760 }

l400000000007FC20:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,getmaxchild; }
	{ cmp.lt	p07,p06,r8,r0; st8	[r8],r32; nop.b	0x0 }
	{ adds	r1,0x0,r43; ld4	r8,[r34]; mov.i	ar.pfs,r42; }
	{ (p07) addl	r14,32,r0; nop.m	0x0; mov.spnt	b0,r41,400000000007FC50; }

l400000000007FC56:
	{ break.m	0x4000; cmp.eq	p41,p03,r1,r64; (p01) nop }

l400000000007FC66:
	{ break.m	0x4000; (p34) nop; nop }

l400000000007FC70:
	{ addl	r44,-7956,r1; nop.m	0x0; addl	r45,2050,r0; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B4E0; }
	{ nop.m	0x0; adds	r44,0x0,r8; adds	r1,0x0,r43 }
	{ nop.m	0x0; st4	[r8],r33; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r44; (p07) br.cond.sptk.few	400000000007FB00 }

l400000000007FCC0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000007F4B0 }

l400000000007FCD0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ adds	r1,0x0,r43; ld4	r14,[r32]; nop.i	0x0 }
	{ ld4	r40,[r8]; addl	r38,5888,r1; addl	r39,5896,r1; }
	{ st4	[r14],r38; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B1A0; }
	{ nop.m	0x0; ld4	r14,[r38]; adds	r1,0x0,r43 }
	{ nop.m	0x0; st4	[r8],r32; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,r14,r8; (p07) br.cond.dptk.few	400000000007F650 }

l400000000007FD40:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000007F8C0 }

l400000000007FD50:
	{ ld4	r45,[r38]; adds	r44,0x0,r0; br.call.sptk.many	b0,fn400000000001BDE0; }
	{ adds	r1,0x0,r43; ld4	r14,[r38]; nop.i	0x0 }
	{ addl	r46,5,r0; st4	[r0],r34; adds	r44,0x0,r0; }
	{ addl	r45,-7932,r1; st4	[r14],r39; nop.i	0x0; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r43; adds	r44,0x0,r8; br.call.sptk.many	b0,internal_error; }
	{ nop.m	0x0; adds	r1,0x0,r43; br.cond.sptk.few	400000000007F760; }

l400000000007FDC0:
	{ addl	r45,-7964,r1; addl	r46,5,r0; adds	r44,0x0,r0; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r43; adds	r44,0x0,r8; br.call.sptk.many	b0,sys_error; }
	{ adds	r1,0x0,r43; addl	r44,1,r0; br.call.sptk.many	b0,fn400000000001B580; }
	{ nop.m	0x0; break.f	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

;; wait_for: 400000000007FE40
;;   Called from:
;;     400000000007FE3C (in initialize_job_control)
;;     400000000008118C (in wait_for_job)
;;     400000000008142C (in wait_for_single_pid)
;;     40000000000822DC (in start_job)
;;     40000000000946DC (in command_substitute)
;;     4000000000094EDC (in command_substitute)
;;     400000000009520C (in command_substitute)
;;     400000000009557C (in command_substitute)
wait_for proc
	{ alloc	r52,ar.pfs,0x1A,0x0,0x17; adds	r12,0xFFFFFFFFFFFFFF00,r12; mov	r54,pr }
	{ adds	r53,0x0,r1; addl	r40,5868,r1; addl	r44,7476,r1; }
	{ nop.m	0x0; mov	r51,b3; adds	r55,0x90,r12 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BC20; }
	{ addl	r56,17,r0; nop.m	0x0; adds	r1,0x0,r53 }
	{ adds	r55,0x90,r12; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B400; }
	{ adds	r1,0x0,r53; adds	r55,0x10,r12; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r53; adds	r55,0x0,r0; nop.i	0x0 }
	{ adds	r56,0x90,r12; adds	r57,0x10,r12; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ nop.m	0x0; adds	r1,0x0,r53; nop.i	0x0 }
	{ ld4	r14,[r40]; st4	[r0],r44; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; addl	r14,9028,r1; (p06) br.cond.dpnt.few	4000000000080530; }

l400000000007FF00:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x2; (p06) br.cond.dptk.few	4000000000080530 }

l400000000007FF20:
	{ addl	r38,6516,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r38]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000805C0 }

l400000000007FF50:
	{ nop.m	0x0; addl	r37,7676,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }

l400000000007FF70:
	{ nop.m	0x0; ld4.acq	r14,[r37]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000808A0 }

l400000000007FF90:
	{ addl	r14,-20676,r1; addl	r49,8388,r1; addl	r47,-9804,r1 }
	{ addl	r41,7676,r1; addl	r43,7684,r1; addl	r33,-1,r0; }
	{ nop.m	0x0; addl	r39,7472,r1; addl	r42,1,r0 }
	{ addl	r36,7444,r1; nop.m	0x0; addl	r50,4,r0; }
	{ adds	r48,0x8,r14; ld8	r47,[r47]; adds	r46,0xC,r14 }
	{ adds	r45,0x2C,r14; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }

l4000000000080000:
	{ adds	r55,0x0,r32; nop.m	0x0; adds	r56,0x0,r0 }
	{ adds	r57,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,fn4000000000076DC0; }
	{ cmp.eq	p07,p06,0x0,r8; adds	r35,0x10,r8; adds	r1,0x0,r53 }
	{ adds	r34,0x0,r8; sxt4	r15,r33; (p07) br.cond.dpnt.few	4000000000080990; }

l4000000000080040:
	{ cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r33; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000080800; }

l4000000000080050:
	{ nop.m	0x0; ld4	r14,[r35]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000080680; }

l4000000000080070:
	{ ld8	r14,[r36]; shladd	r14,r15,0x3,r14; nop.i	0x0; }
	{ ld8	r14,[r14]; adds	r14,0x14,r14; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x1,r14; (p07) br.cond.dpnt.few	4000000000080680; }

l40000000000800B0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000800C0:
	{ nop.m	0x0; ld4	r14,[r38]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	4000000000080140 }

l40000000000800E0:
	{ nop.m	0x0; ld4	r14,[r40]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000080140 }

l4000000000080100:
	{ nop.m	0x0; ld4.acq	r14,[r37]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000807C0; }

l4000000000080120:
	{ nop.m	0x0; ld4.acq	r14,[r43]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	4000000000080780; }

l4000000000080140:
	{ nop.m	0x0; ld4.acq	r14,[r37]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	4000000000080660 }

l4000000000080160:
	{ ld4	r14,[r35]; cmp4.eq	p16,p17,0xFFFFFFFFFFFFFFFF,r33; sxt4	r15,r33; }
	{ cmp4.eq	p06,p07,0x1,r14; (p06) br.cond.dpnt.few	4000000000080000; (p16) br.cond.dpnt.few	4000000000080A60; }

l400000000008017C:
	{ (p07) cmp.lt	p01,p11,r64,r33; (p01) cmp.lt	p00,p08,r9,r6; (p49) epc }

l4000000000080180:
	{ ld8	r14,[r36]; shladd	r14,r15,0x3,r14; nop.i	0x0; }
	{ ld8	r14,[r14]; adds	r14,0x14,r14; nop.i	0x0; }
	{ nop.m	0x0; ld4	r35,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x1,r35; (p06) br.cond.dptk.few	4000000000080000 }

l40000000000801C0:
	{ adds	r55,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,job_exit_status; }
	{ adds	r1,0x0,r53; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r55,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,job_exit_signal; }
	{ adds	r1,0x0,r53; adds	r15,0xC,r34; cmp4.eq	p07,p06,0x2,r35; }
	{ addl	r14,9016,r1; nop.m	0x0; nop.i	0x0; }
	{ st4	[r8],r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000080950; }

l4000000000080220:
	{ ld4	r34,[r15]; nop.m	0x0; zxt1	r14,r34; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x7F,r14; (p07) br.cond.dpnt.few	4000000000080970 }

l4000000000080240:
	{ addl	r35,7444,r1; sxt4	r34,r33; (p16) br.cond.dpnt.few	4000000000080E10; }

l4000000000080250:
	{ shladd	r34,r34,0x3,r0; ld8	r14,[r35]; nop.i	0x0; }
	{ add	r14,r14,r34; ld8	r14,[r14]; nop.i	0x0; }
	{ adds	r14,0x18,r14; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x2; (p07) br.cond.dptk.few	40000000000802C0 }

l4000000000080290:
	{ addl	r14,5896,r1; adds	r56,0x0,r0; nop.i	0x0 }
	{ ld4	r55,[r14]; nop.m	0x0; br.call.sptk.many	b0,give_terminal_to; }
	{ adds	r1,0x0,r53; nop.m	0x0; nop.i	0x0; }

l40000000000802C0:
	{ addl	r14,6512,r1; nop.m	0x0; nop.i	0x0; }
	{ ld4	r14,[r14]; cmp4.eq	p06,p07,0x0,r14; addl	r14,9028,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4	r14,[r14]; nop.i	0x0; (p06) br.cond.dptk.few	4000000000080310; }

l4000000000080300:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	4000000000080B90 }

l4000000000080310:
	{ nop.m	0x0; and	r14,0x14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	4000000000080460 }

l4000000000080330:
	{ nop.m	0x0; ld4	r14,[r44]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	4000000000080460 }

l4000000000080350:
	{ adds	r55,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,fn4000000000076FC0; }
	{ and	r8,0x7F,r8; adds	r1,0x0,r53; adds	r14,0x1,r8; }
	{ nop.m	0x0; extr.u	r14,r14,1,7; nop.i	0x0; }
	{ cmp4.lt	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000080460; }

l4000000000080390:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2,r8; (p07) br.cond.dptk.few	4000000000080460 }

l40000000000803A0:
	{ addl	r55,2,r0; nop.i	0x0; br.call.sptk.many	b0,signal_is_trapped; }
	{ adds	r1,0x0,r53; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	4000000000080460 }

l40000000000803C0:
	{ adds	r57,0x0,r0; nop.m	0x0; addl	r55,2,r0 }
	{ adds	r56,0x10,r12; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r53; nop.i	0x0; br.call.sptk.many	b0,fn4000000000077140; }
	{ addl	r55,2,r0; nop.m	0x0; adds	r56,0x0,r0 }
	{ adds	r1,0x0,r53; nop.m	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r53; cmp.eq	p07,p06,0x1,r8; addl	r14,5916,r1; }
	{ st8	[r8],r14; (p07) br.cond.dpnt.few	4000000000080FF0; br.call.sptk.many	b0,fn400000000001B1A0; }

l400000000008042C:
	{ (p44) nop; invala; cmp.eq	p00,p00,r32,r0 }
	{ Invalid; Invalid; Invalid }
	{ (p07) nop; invala; break.i	0x1000 }
	{ cmp.lt	p00,p03,r1,r0; Invalid; dep	r0,r32,r0,63,1 }

l4000000000080460:
	{ ld8	r14,[r35]; nop.i	0x0; add	r34,r14,r34; }
	{ ld8	r14,[r34]; nop.m	0x0; nop.i	0x0; }

l4000000000080480:
	{ adds	r15,0x14,r14; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x4,r15; (p07) br.cond.dpnt.few	4000000000080AF0 }

l40000000000804A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,notify_and_cleanup; }
	{ adds	r1,0x0,r53; nop.m	0x0; nop.i	0x0 }

l40000000000804C0:
	{ addl	r55,2,r0; nop.m	0x0; adds	r56,0x10,r12 }
	{ adds	r57,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ nop.m	0x0; adds	r1,0x0,r53; br.call.sptk.many	b0,fn4000000000077140; }
	{ adds	r1,0x0,r53; nop.m	0x0; nop.i	0x0 }

l4000000000080500:
	{ adds	r8,0x0,r36; mov	pr,r54,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r52; }
	{ nop.m	0x0; mov.spnt	b0,r51,4000000000080510; nop.i	0x0 }
	{ adds	r12,0x100,r12; nop.m	0x0; br.ret	b0 }

l4000000000080530:
	{ addl	r56,-7788,r1; nop.m	0x0; addl	r55,2,r0; }
	{ ld8	r56,[r56]; nop.i	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r53; cmp.eq	p07,p06,0x1,r8; addl	r14,5916,r1; }
	{ st8	[r8],r14; nop.i	0x0; (p06) br.cond.dptk.few	400000000007FF20 }

l4000000000080570:
	{ addl	r55,2,r0; addl	r56,1,r0; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r53; addl	r38,6516,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r38]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	400000000007FF50; }

l40000000000805B0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000805C0:
	{ ld4	r14,[r40]; nop.m	0x0; addl	r37,7676,r1; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	400000000007FF70; }

l40000000000805E0:
	{ nop.m	0x0; ld4.acq	r14,[r37]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; addl	r14,7684,r1; (p07) br.cond.dpnt.few	4000000000080B40; }

l4000000000080600:
	{ nop.m	0x0; ld4.acq	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000007FF70 }

l4000000000080620:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,throw_to_top_level; }
	{ ld4.acq	r14,[r37]; nop.m	0x0; adds	r1,0x0,r53; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000007FF90 }

l4000000000080650:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000808A0 }

l4000000000080660:
	{ ld4.acq	r55,[r41]; nop.i	0x0; br.call.sptk.many	b0,termsig_handler; }
	{ nop.m	0x0; adds	r1,0x0,r53; br.cond.sptk.few	4000000000080160 }

l4000000000080680:
	{ st4	[r42],r39; addl	r55,1,r0; br.call.sptk.many	b0,fn400000000007D580; }
	{ nop.m	0x0; adds	r1,0x0,r53; nop.i	0x0 }
	{ st4	[r0],r39; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p06) br.cond.dptk.few	40000000000800C0 }

l40000000000806B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ ld4	r15,[r8]; nop.m	0x0; adds	r1,0x0,r53; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0xA,r15; (p06) br.cond.dptk.few	40000000000800C0 }

l40000000000806E0:
	{ ld8	r14,[r49]; nop.m	0x0; sxt4	r17,r33; }
	{ cmp.eq	p06,p07,r47,r14; adds	r14,0xC,r34; (p06) br.cond.dpnt.few	4000000000080F10; }

l4000000000080700:
	{ st4	[r0],r14; st4	[r0],r35; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r33; }
	{ st4	[r0],r48; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000800C0; }

l4000000000080720:
	{ ld8	r14,[r36]; ld4	r15,[r46]; nop.i	0x0; }
	{ nop.m	0x0; shladd	r17,r17,0x3,r14; adds	r16,0x1,r15 }
	{ ld4	r14,[r45]; ld8	r15,[r17]; adds	r14,0x1,r14 }
	{ nop.m	0x0; st4	[r16],r46; nop.i	0x0; }
	{ adds	r15,0x14,r15; nop.i	0x0; nop.i	0x0 }
	{ st4	[r50],r15; st4	[r14],r45; br.cond.sptk.few	40000000000800C0 }

l4000000000080780:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,throw_to_top_level; }
	{ ld4.acq	r14,[r37]; nop.m	0x0; adds	r1,0x0,r53; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000080160 }

l40000000000807B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000080660 }

l40000000000807C0:
	{ ld4.acq	r55,[r41]; nop.i	0x0; br.call.sptk.many	b0,termsig_handler; }
	{ ld4.acq	r14,[r43]; nop.m	0x0; adds	r1,0x0,r53; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000080140 }

l40000000000807F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000080780 }

l4000000000080800:
	{ adds	r55,0x0,r32; nop.m	0x0; adds	r56,0x0,r0 }
	{ adds	r57,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,fn4000000000076C40; }
	{ ld4	r14,[r35]; adds	r33,0x0,r8; adds	r1,0x0,r53; }
	{ cmp4.eq	p06,p07,0x1,r14; sxt4	r15,r33; (p06) br.cond.dpnt.few	4000000000080680; }

l4000000000080840:
	{ cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r8; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000800C0; }

l4000000000080850:
	{ ld8	r14,[r36]; shladd	r14,r15,0x3,r14; nop.i	0x0; }
	{ ld8	r14,[r14]; adds	r14,0x14,r14; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x1,r14; (p06) br.cond.dptk.few	40000000000800C0 }

l4000000000080890:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000080680 }

l40000000000808A0:
	{ addl	r14,7676,r1; addl	r33,-1,r0; addl	r42,1,r0 }
	{ addl	r50,4,r0; nop.m	0x0; nop.i	0x0; }
	{ ld4.acq	r55,[r14]; nop.i	0x0; br.call.sptk.many	b0,termsig_handler; }
	{ nop.m	0x0; adds	r1,0x0,r53; nop.i	0x0; }
	{ addl	r14,-20676,r1; addl	r49,8388,r1; addl	r47,-9804,r1 }
	{ addl	r41,7676,r1; addl	r43,7684,r1; addl	r39,7472,r1; }
	{ nop.m	0x0; nop.m	0x0; addl	r36,7444,r1 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ adds	r48,0x8,r14; ld8	r47,[r47]; adds	r46,0xC,r14 }
	{ adds	r45,0x2C,r14; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000080000 }

l4000000000080950:
	{ nop.m	0x0; adds	r34,0xC,r34; nop.i	0x0; }
	{ ld4	r34,[r34]; nop.m	0x0; nop.i	0x0; }

l4000000000080970:
	{ nop.m	0x0; extr.u	r34,r34,8,8; nop.i	0x0; }
	{ nop.m	0x0; adds	r36,0x80,r34; br.cond.sptk.few	4000000000080240; }

l4000000000080990:
	{ addl	r14,5896,r1; adds	r56,0x0,r0; addl	r36,127,r0; }
	{ ld4	r55,[r14]; nop.i	0x0; br.call.sptk.many	b0,give_terminal_to; }
	{ adds	r1,0x0,r53; adds	r56,0x10,r12; nop.i	0x0 }
	{ addl	r55,2,r0; adds	r57,0x0,r0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r53; addl	r57,5,r0; adds	r55,0x0,r0; }
	{ nop.m	0x0; addl	r56,-7924,r1; nop.i	0x0; }
	{ ld8	r56,[r56]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r53; nop.m	0x0; adds	r55,0x0,r8 }
	{ nop.m	0x0; sxt4	r56,r32; br.call.sptk.many	b0,internal_error; }
	{ adds	r1,0x0,r53; nop.i	0x0; br.call.sptk.many	b0,fn4000000000077140; }
	{ adds	r8,0x0,r36; adds	r1,0x0,r53; mov	pr,r54,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r52; mov.spnt	b0,r51,4000000000080A40 }
	{ nop.m	0x0; adds	r12,0x100,r12; br.ret	b0 }

l4000000000080A60:
	{ adds	r34,0xC,r34; ld4	r34,[r34]; nop.i	0x0; }
	{ adds	r55,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn4000000000077B80; }
	{ and	r14,0x7F,r34; adds	r1,0x0,r53; adds	r36,0x0,r8; }
	{ adds	r15,0x1,r14; nop.m	0x0; extr.u	r15,r15,1,7; }
	{ cmp4.lt	p06,p07,0x0,r15; nop.m	0x0; addl	r15,9016,r1; }
	{ nop.m	0x0; (p06) st4	[r14],r15; zxt1	r14,r34 }

l4000000000080ABC:
	{ nop; mov	pr,r32,0x0; Invalid; }

l4000000000080ACC:
	{ invala; cmp.eq	p00,p00,r32,r0; (p48) mov	pr,r67,0xE6BE }
	{ (p59) invala; break.i	0x1000; break.b	0x1000 }

l4000000000080AE0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000080970 }

l4000000000080AF0:
	{ adds	r14,0x18,r14; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x0; (p06) br.cond.dptk.few	40000000000804A0 }

l4000000000080B10:
	{ adds	r55,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,fn4000000000077C00; }
	{ adds	r1,0x0,r53; nop.i	0x0; br.call.sptk.many	b0,notify_and_cleanup; }
	{ nop.m	0x0; adds	r1,0x0,r53; br.cond.sptk.few	40000000000804C0 }

l4000000000080B40:
	{ ld4.acq	r55,[r37]; nop.i	0x0; br.call.sptk.many	b0,termsig_handler; }
	{ adds	r1,0x0,r53; addl	r14,7684,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4.acq	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000007FF70 }

l4000000000080B80:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000080620 }

l4000000000080B90:
	{ adds	r55,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,fn4000000000076FC0; }
	{ and	r37,0x7F,r8; adds	r1,0x0,r53; adds	r38,0x1,r37; }
	{ nop.m	0x0; extr.u	r38,r38,1,7; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,0x0,r38; (p07) br.cond.dpnt.few	4000000000080E70 }

l4000000000080BD0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,set_tty_state; }
	{ adds	r1,0x0,r53; addl	r14,9072,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	4000000000080EB0 }

l4000000000080C10:
	{ addl	r14,-20676,r1; nop.m	0x0; nop.i	0x0; }
	{ adds	r14,0x30,r14; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,r33,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000080ED0; }

l4000000000080C40:
	{ ld8	r14,[r35]; add	r14,r14,r34; nop.i	0x0; }
	{ ld8	r14,[r14]; adds	r15,0x18,r14; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r15,0x0; (p07) br.cond.dptk.few	4000000000080ED0 }

l4000000000080C80:
	{ nop.m	0x0; ld4	r15,[r40]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	4000000000080480 }

l4000000000080CA0:
	{ adds	r15,0x18,r14; ld8	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; and	r15,0x5,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x5,r15; (p06) br.cond.dptk.few	4000000000080480; }

l4000000000080CD0:
	{ cmp4.lt	p07,p06,0x0,r38; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000080480; }

l4000000000080CE0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2,r37; (p06) br.cond.dptk.few	4000000000080480 }

l4000000000080CF0:
	{ addl	r55,2,r0; nop.i	0x0; br.call.sptk.many	b0,signal_is_trapped; }
	{ adds	r1,0x0,r53; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dpnt.few	4000000000080F50; }

l4000000000080D10:
	{ addl	r14,8364,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000080DA0 }

l4000000000080D40:
	{ addl	r14,6044,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,0x20,r14; (p06) br.cond.dptk.few	4000000000080F50 }

l4000000000080D70:
	{ addl	r14,7048,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000080F50 }

l4000000000080DA0:
	{ addl	r15,7684,r1; ld8	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; add	r34,r14,r34; }
	{ ld8	r14,[r34]; ld4.acq	r16,[r15]; nop.i	0x0; }
	{ adds	r16,0x1,r16; st4.rel	[r16],r15; adds	r15,0x14,r14; }
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x4,r15; (p06) br.cond.dptk.few	40000000000804A0 }

l4000000000080E00:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000080AF0 }

l4000000000080E10:
	{ addl	r14,5896,r1; nop.m	0x0; adds	r56,0x0,r0; }
	{ ld4	r55,[r14]; nop.i	0x0; br.call.sptk.many	b0,give_terminal_to; }
	{ adds	r1,0x0,r53; addl	r55,2,r0; nop.i	0x0 }
	{ adds	r56,0x10,r12; adds	r57,0x0,r0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r53; nop.i	0x0; br.call.sptk.many	b0,fn4000000000077140; }
	{ nop.m	0x0; adds	r1,0x0,r53; br.cond.sptk.few	4000000000080500 }

l4000000000080E70:
	{ nop.m	0x0; zxt1	r8,r8; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x7F,r8; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000080BD0; }

l4000000000080E90:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,get_tty_state; }
	{ adds	r1,0x0,r53; nop.m	0x0; nop.i	0x0 }

l4000000000080EB0:
	{ ld8	r14,[r35]; add	r14,r14,r34; nop.i	0x0; }
	{ ld8	r14,[r14]; nop.i	0x0; br.cond.sptk.few	4000000000080C80 }

l4000000000080ED0:
	{ adds	r55,0x0,r0; nop.m	0x0; adds	r56,0x0,r0 }
	{ adds	r57,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,get_new_window_size; }
	{ ld8	r14,[r35]; adds	r1,0x0,r53; add	r14,r14,r34; }
	{ ld8	r14,[r14]; nop.i	0x0; br.cond.sptk.few	4000000000080C80 }

l4000000000080F10:
	{ addl	r55,2,r0; adds	r56,0x10,r12; nop.i	0x0 }
	{ adds	r57,0x0,r0; addl	r36,-1,r0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r53; nop.i	0x0; br.call.sptk.many	b0,fn4000000000077140; }
	{ nop.m	0x0; adds	r1,0x0,r53; br.cond.sptk.few	4000000000080500; }

l4000000000080F50:
	{ addl	r37,-10260,r1; nop.m	0x0; addl	r55,10,r0; }
	{ nop.m	0x0; ld8	r37,[r37]; nop.i	0x0; }
	{ ld8	r56,[r37]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AEC0; }
	{ nop.m	0x0; adds	r1,0x0,r53; nop.i	0x0 }
	{ ld8	r55,[r37]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ ld8	r14,[r35]; adds	r1,0x0,r53; add	r34,r14,r34; }
	{ ld8	r14,[r34]; adds	r15,0x14,r14; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x4,r15; (p06) br.cond.dptk.few	40000000000804A0 }

l4000000000080FE0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000080AF0 }

l4000000000080FF0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000077140; }
	{ ld8	r14,[r35]; adds	r1,0x0,r53; add	r34,r14,r34; }
	{ ld8	r14,[r34]; adds	r15,0x14,r14; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x4,r15; (p06) br.cond.dptk.few	40000000000804A0 }

l4000000000081040:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000080AF0; }
4000000000081050 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000081060 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000081070 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; wait_for_job: 4000000000081080
;;   Called from:
;;     400000000011221C (in wait_builtin)
wait_for_job proc
	{ alloc	r37,ar.pfs,0xA,0x0,0x7; adds	r12,0xFFFFFFFFFFFFFF00,r12; mov	r36,b4 }
	{ adds	r38,0x0,r1; addl	r33,7444,r1; sxt4	r34,r32; }
	{ adds	r39,0x90,r12; shladd	r34,r34,0x3,r0; br.call.sptk.many	b0,fn400000000001BC20; }
	{ addl	r40,17,r0; nop.m	0x0; adds	r1,0x0,r38 }
	{ adds	r39,0x90,r12; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B400; }
	{ adds	r1,0x0,r38; adds	r39,0x10,r12; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r38; adds	r40,0x90,r12; nop.i	0x0 }
	{ adds	r41,0x10,r12; adds	r39,0x0,r0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ ld8	r14,[r33]; adds	r1,0x0,r38; add	r14,r14,r34; }
	{ ld8	r14,[r14]; adds	r14,0x14,r14; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2,r14; (p07) br.cond.dpnt.few	40000000000812D0 }

l4000000000081140:
	{ adds	r39,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn4000000000079140; }
	{ adds	r8,0x8,r8; adds	r41,0x0,r0; nop.i	0x0 }
	{ adds	r40,0x10,r12; adds	r1,0x0,r38; addl	r39,2,r0; }
	{ ld4	r35,[r8]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r39,0x0,r35; adds	r1,0x0,r38; br.call.sptk.many	b0,wait_for; }
	{ adds	r1,0x0,r38; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r39,0x90,r12; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BC20; }
	{ addl	r40,17,r0; nop.m	0x0; adds	r1,0x0,r38 }
	{ adds	r39,0x90,r12; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B400; }
	{ adds	r1,0x0,r38; adds	r39,0x10,r12; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r38; adds	r39,0x0,r0; nop.i	0x0 }
	{ adds	r40,0x90,r12; adds	r41,0x10,r12; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r38; cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r32; (p06) br.cond.dpnt.few	4000000000081280; }

l4000000000081210:
	{ ld8	r14,[r33]; add	r34,r14,r34; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r34]; nop.i	0x0; }
	{ adds	r15,0x14,r14; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	4000000000081280; }

l4000000000081240:
	{ ld4	r15,[r15]; cmp4.eq	p07,p06,0x4,r15; nop.i	0x0; }
	{ (p07) adds	r14,0x18,r14; (p07) ld4	r15,[r14]; nop.i	0x0; }

l4000000000081256:
	{ (p07) fwb; nop; Invalid; }

l400000000008125C:
	{ nop; cmp4.eq.or.andcm	p00,p32,r32,r0; zxt1	r96,r11 }

l400000000008126C:
	{ Invalid; Invalid; break.i	0x1000 }

l4000000000081276:
	{ break.m	0x4000; nop; (p48) nop }

l4000000000081280:
	{ addl	r39,2,r0; nop.m	0x0; adds	r40,0x10,r12 }

l4000000000081282:
	{ break.m	0x48000; Invalid; (p02) dep	r3,r64,r48,31,7; }
	{ break.m	0x42000; Invalid; (p40) dep	r76,r15,r43,63,3; }
	{ (p48) invala; (p32) nop; (p04) break.i	0x550 }
	{ add	r32,r0,r0; (p20) break.i	0x3800; nop }
	{ break.m	0x42043; nop; dep	r32,r8,r32,63,3 }

l40000000000812D0:
	{ addl	r40,-7916,r1; addl	r41,5,r0; adds	r39,0x0,r0; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r38; nop.m	0x0; adds	r39,0x0,r8 }
	{ adds	r40,0x1,r32; nop.m	0x0; br.call.sptk.many	b0,internal_warning; }
	{ nop.m	0x0; adds	r1,0x0,r38; br.cond.sptk.few	4000000000081140; }
4000000000081320 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000081330 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; wait_for_single_pid: 4000000000081340
;;   Called from:
;;     40000000000819DC (in wait_for_background_pids)
;;     40000000000819DC (in wait_for_background_pids)
;;     4000000000081C6C (in wait_for_background_pids)
;;     400000000011207C (in wait_builtin)
wait_for_single_pid proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; adds	r12,0xFFFFFFFFFFFFFF00,r12; nop.b	0x0 }
	{ adds	r36,0x0,r1; nop.m	0x0; mov	r34,b2; }
	{ adds	r37,0x90,r12; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BC20; }
	{ addl	r38,17,r0; nop.m	0x0; adds	r1,0x0,r36 }
	{ adds	r37,0x90,r12; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B400; }
	{ adds	r1,0x0,r36; adds	r37,0x10,r12; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r36; adds	r38,0x90,r12; nop.i	0x0 }
	{ adds	r39,0x10,r12; adds	r37,0x0,r0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r36; adds	r37,0x0,r32; nop.i	0x0 }
	{ adds	r38,0x0,r0; adds	r39,0x0,r0; br.call.sptk.many	b0,fn4000000000076DC0; }
	{ adds	r39,0x0,r0; adds	r38,0x10,r12; adds	r33,0x0,r8 }
	{ adds	r1,0x0,r36; addl	r37,2,r0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ cmp.eq	p07,p06,0x0,r33; nop.m	0x0; adds	r1,0x0,r36 }
	{ adds	r37,0x0,r32; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000081610; }

l4000000000081420:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,wait_for; }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r33,0x0,r8 }
	{ adds	r37,0x90,r12; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BC20; }
	{ addl	r38,17,r0; nop.m	0x0; adds	r1,0x0,r36 }
	{ adds	r37,0x90,r12; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B400; }
	{ adds	r1,0x0,r36; adds	r37,0x10,r12; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r36; adds	r38,0x90,r12; nop.i	0x0 }
	{ adds	r39,0x10,r12; adds	r37,0x0,r0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r36; adds	r37,0x0,r32; nop.i	0x0 }
	{ adds	r38,0x0,r0; adds	r39,0x0,r0; br.call.sptk.many	b0,fn4000000000076C40; }
	{ adds	r1,0x0,r36; adds	r38,0x10,r12; adds	r39,0x0,r0 }
	{ addl	r37,2,r0; cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r8; sxt4	r14,r8; }
	{ addl	r15,7444,r1; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000081560; }

l40000000000814F0:
	{ ld8	r15,[r15]; shladd	r14,r14,0x3,r15; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ adds	r15,0x14,r14; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	4000000000081560; }

l4000000000081520:
	{ ld4	r15,[r15]; cmp4.eq	p07,p06,0x4,r15; nop.i	0x0; }
	{ (p07) adds	r14,0x18,r14; (p07) ld4	r15,[r14]; nop.i	0x0; }

l4000000000081536:
	{ (p07) fwb; nop; Invalid; }

l400000000008153C:
	{ nop; cmp4.eq.or.andcm	p00,p32,r32,r0; zxt1	r96,r11 }

l400000000008154C:
	{ Invalid; Invalid; break.i	0x1000 }

l4000000000081556:
	{ break.m	0x4000; nop; break.i	0x80000 }

l4000000000081560:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }

l4000000000081562:
	{ break.m	0x20; cmp.ltu	p32,p00,r0,r0; Invalid }
	{ Invalid; (p23) break.i	0x48640; Invalid }
	{ Invalid; (p32) break.i	0x20203; Invalid }
	{ Invalid; (p32) nop; dep	r0,r48,r72,63,1 }

l40000000000815A0:
	{ adds	r8,0x0,r33; mov.i	ar.pfs,r35; mov.spnt	b0,r34,40000000000815A0 }
	{ nop.m	0x0; adds	r12,0x100,r12; br.ret	b0; }

l40000000000815C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000007E8C0; }
	{ adds	r1,0x0,r36; adds	r37,0x0,r32; br.call.sptk.many	b0,fn40000000000775C0; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r36; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000815F0; nop.i	0x0 }
	{ adds	r12,0x100,r12; nop.m	0x0; br.ret	b0 }

l4000000000081610:
	{ addl	r14,14900,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ adds	r15,0x8,r14; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	40000000000816C0; }

l4000000000081640:
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,r15,r32; (p06) br.cond.dpnt.few	40000000000816A0; }

l4000000000081660:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ adds	r15,0x8,r14; cmp.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000816C0; }

l4000000000081680:
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r15,r32; (p06) br.cond.dptk.few	4000000000081660 }

l40000000000816A0:
	{ adds	r14,0xC,r14; ld4	r33,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r33,r0; (p06) br.cond.sptk.few	40000000000815A0; }

l40000000000816C0:
	{ addl	r38,-7908,r1; nop.m	0x0; addl	r39,5,r0 }
	{ adds	r37,0x0,r0; nop.m	0x0; addl	r33,127,r0; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r37,0x0,r8 }
	{ nop.m	0x0; sxt4	r38,r32; br.call.sptk.many	b0,internal_error; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r36; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000081720; nop.i	0x0 }
	{ adds	r12,0x100,r12; nop.m	0x0; br.ret	b0; }

;; wait_for_background_pids: 4000000000081740
;;   Called from:
;;     40000000001123CC (in wait_builtin)
wait_for_background_pids proc
	{ alloc	r42,ar.pfs,0x10,0x0,0xD; adds	r12,0xFFFFFFFFFFFFFE00,r12; mov	r44,LC }
	{ addl	r35,-20676,r1; addl	r34,7676,r1; addl	r37,7684,r1; }
	{ nop.m	0x0; adds	r43,0x0,r1; mov	r41,b1 }
	{ addl	r36,7444,r1; nop.m	0x0; addl	r39,4,r0; }
	{ adds	r38,0x2C,r35; nop.m	0x0; nop.i	0x0 }
	{ adds	r35,0x1C,r35; nop.m	0x0; adds	r40,0x0,r38; }

l40000000000817A0:
	{ adds	r45,0x190,r12; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BC20; }
	{ addl	r46,17,r0; nop.m	0x0; adds	r1,0x0,r43 }
	{ adds	r45,0x190,r12; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B400; }
	{ adds	r1,0x0,r43; adds	r45,0x110,r12; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r43; adds	r45,0x0,r0; nop.i	0x0 }
	{ adds	r46,0x190,r12; adds	r47,0x110,r12; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ ld4	r14,[r35]; nop.m	0x0; adds	r1,0x0,r43; }
	{ nop.m	0x0; cmp4.lt	p07,p06,0x0,r14; (p06) br.cond.dpnt.few	4000000000081BB0 }

l4000000000081820:
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r14; ld8	r15,[r36]; adds	r45,0x0,r0; }
	{ addp4	r14,r14,r0; nop.i	0x0; mov.i	LC,r14; }

l4000000000081840:
	{ nop.m	0x0; ld8	r14,[r15],8; nop.i	0x0; }
	{ adds	r16,0x14,r14; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	4000000000081880; }

l4000000000081860:
	{ nop.m	0x0; ld4	r16,[r16]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x1,r16; (p07) br.cond.dpnt.few	4000000000081910 }

l4000000000081880:
	{ nop.m	0x0; adds	r45,0x1,r45; br.cloop.sptk.few	4000000000081840; }

l4000000000081890:
	{ adds	r46,0x110,r12; nop.m	0x0; adds	r47,0x0,r0 }
	{ addl	r45,2,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ addl	r45,1,r0; adds	r1,0x0,r43; br.call.sptk.many	b0,fn400000000007A7C0; }
	{ adds	r1,0x0,r43; nop.i	0x0; br.call.sptk.many	b0,fn400000000007E8C0; }
	{ adds	r1,0x0,r43; nop.i	0x0; br.call.sptk.many	b0,fn4000000000077500; }
	{ adds	r1,0x0,r43; mov.i	ar.pfs,r42; mov.i	LC,r44; }
	{ nop.m	0x0; mov.spnt	b0,r41,40000000000818F0; nop.i	0x0 }
	{ adds	r12,0x200,r12; nop.m	0x0; br.ret	b0 }

l4000000000081910:
	{ adds	r14,0x18,r14; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x0; (p07) br.cond.dptk.few	4000000000081880 }

l4000000000081930:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000079140; }
	{ adds	r8,0x8,r8; adds	r1,0x0,r43; nop.i	0x0 }
	{ adds	r47,0x0,r0; adds	r46,0x110,r12; addl	r45,2,r0; }
	{ ld4	r33,[r8]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ ld4.acq	r14,[r34]; nop.m	0x0; adds	r1,0x0,r43; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	4000000000081C90 }

l4000000000081990:
	{ nop.m	0x0; ld4.acq	r14,[r37]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	4000000000081C30 }

l40000000000819B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ adds	r1,0x0,r43; adds	r32,0x0,r8; nop.i	0x0 }
	{ adds	r45,0x0,r33; st4	[r0],r8; br.call.sptk.many	b0,wait_for_single_pid; }
	{ adds	r1,0x0,r43; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p06) br.cond.dptk.few	40000000000817A0 }

l40000000000819F0:
	{ nop.m	0x0; ld4	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0xA,r14; (p06) br.cond.dptk.few	40000000000817A0 }

l4000000000081A10:
	{ nop.m	0x0; ld4	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000817A0 }

l4000000000081A30:
	{ adds	r45,0x90,r12; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BC20; }
	{ addl	r46,17,r0; nop.m	0x0; adds	r1,0x0,r43 }
	{ adds	r45,0x90,r12; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B400; }
	{ adds	r1,0x0,r43; adds	r45,0x10,r12; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r43; adds	r45,0x0,r0; nop.i	0x0 }
	{ adds	r46,0x90,r12; adds	r47,0x10,r12; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ ld4	r14,[r35]; nop.m	0x0; adds	r1,0x0,r43; }
	{ cmp4.lt	p06,p07,0x0,r14; adds	r14,0xFFFFFFFFFFFFFFFF,r14; (p07) br.cond.dpnt.few	4000000000081B10; }

l4000000000081AB0:
	{ nop.m	0x0; ld8	r16,[r36]; addp4	r15,r14,r0 }
	{ ld4	r17,[r38]; adds	r14,0x8,r16; mov.i	LC,r15; }

l4000000000081AD0:
	{ ld8	r15,[r16]; adds	r16,0x0,r14; adds	r14,0x8,r14; }
	{ cmp.eq	p06,p07,0x0,r15; nop.m	0x0; adds	r18,0x14,r15; }
	{ (p07) st4	[r39],r18; (p07) adds	r17,0x1,r17; br.cloop.sptk.few	4000000000081AD0; }

l4000000000081AF6:
	{ Invalid; (p02) nop; br.call.spnt.few	b0,b4; }

l4000000000081AFC:
	{ (p63) nop; Invalid; break.i	0x1000 }

l4000000000081B00:
	{ st4	[r17],r40; nop.m	0x0; nop.i	0x0 }

l4000000000081B10:
	{ adds	r47,0x0,r0; nop.m	0x0; adds	r46,0x10,r12 }
	{ addl	r45,2,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r43; adds	r45,0x190,r12; br.call.sptk.many	b0,fn400000000001BC20; }
	{ addl	r46,17,r0; nop.m	0x0; adds	r1,0x0,r43 }
	{ adds	r45,0x190,r12; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B400; }
	{ adds	r1,0x0,r43; adds	r45,0x110,r12; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r43; adds	r45,0x0,r0; nop.i	0x0 }
	{ adds	r46,0x190,r12; adds	r47,0x110,r12; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ ld4	r14,[r35]; nop.m	0x0; adds	r1,0x0,r43; }
	{ nop.m	0x0; cmp4.lt	p07,p06,0x0,r14; (p07) br.cond.dptk.few	4000000000081820; }

l4000000000081BB0:
	{ cmp4.eq	p07,p06,0x0,r14; adds	r45,0x0,r0; (p07) br.cond.spnt.few	4000000000081890; }

l4000000000081BC0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000079140; }
	{ adds	r8,0x8,r8; adds	r1,0x0,r43; nop.i	0x0 }
	{ adds	r47,0x0,r0; adds	r46,0x110,r12; addl	r45,2,r0; }
	{ ld4	r33,[r8]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ ld4.acq	r14,[r34]; nop.m	0x0; adds	r1,0x0,r43; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000081990 }

l4000000000081C20:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000081C90 }

l4000000000081C30:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,throw_to_top_level; }
	{ adds	r1,0x0,r43; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ adds	r1,0x0,r43; adds	r32,0x0,r8; nop.i	0x0 }
	{ adds	r45,0x0,r33; st4	[r0],r8; br.call.sptk.many	b0,wait_for_single_pid; }
	{ adds	r1,0x0,r43; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p06) br.cond.dptk.few	40000000000817A0 }

l4000000000081C80:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000819F0 }

l4000000000081C90:
	{ ld4.acq	r45,[r34]; nop.i	0x0; br.call.sptk.many	b0,termsig_handler; }
	{ ld4.acq	r14,[r37]; nop.m	0x0; adds	r1,0x0,r43; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000819B0 }

l4000000000081CC0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000081C30; }
4000000000081CD0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000081CE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000081CF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; start_job: 4000000000081D00
;;   Called from:
;;     40000000000FAECC (in fn40000000000FAD40)
;;     40000000000FB09C (in fn40000000000FAD40)
start_job proc
	{ alloc	r41,ar.pfs,0x10,0x0,0xC; adds	r12,0xFFFFFFFFFFFFFF00,r12; mov	r43,pr }
	{ adds	r42,0x0,r1; addl	r36,7444,r1; sxt4	r35,r32; }
	{ nop.m	0x0; mov	r40,b0; adds	r44,0x90,r12 }
	{ shladd	r35,r35,0x3,r0; cmp4.eq	p16,p17,0x0,r33; br.call.sptk.many	b0,fn400000000001BC20; }
	{ addl	r45,17,r0; adds	r1,0x0,r42; nop.i	0x0 }
	{ adds	r44,0x90,r12; (p17) adds	r37,0x0,r0; br.call.sptk.many	b0,fn400000000001B400; }

l4000000000081D5C:
	{ (p53) nop; invala; Invalid }
	{ (p08) nop; break.x	0x12000002801000; }

l4000000000081D76:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; nop; (p16) nop }
	{ Invalid; Invalid; (p32) nop }
	{ Invalid; (p07) nop; (p32) br.call.sptk.few	b3,b0 }
	{ Invalid; nop; break.i	0x80000 }
	{ (p07) fwb; nop; (p48) nop }
	{ chk.a.nc	f0,3FFFFFFFFF0825D6; nop; (p32) nop }

l4000000000081DE0:
	{ cmp4.eq	p06,p07,0x1,r14; (p06) addl	r14,1,r0; nop.i	0x0; }

l4000000000081DEC:
	{ cmp4.eq.and	p00,p43,r1,r0; (p01) cmp.lt	p00,p16,r0,r64; (p04) cmp.lt.unc	p00,p16,r3,r64 }

l4000000000081DF6:
	{ Invalid; (p07) nop; (p32) nop }
	{ chk.a.nc	f0,3FFFFFFFFF082606; nop; break.i	0x80000 }

l4000000000081E10:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000773C0; }
	{ ld8	r14,[r36]; adds	r1,0x0,r42; adds	r39,0x0,r8; }
	{ nop.m	0x0; add	r14,r14,r35; nop.i	0x0; }
	{ ld8	r15,[r14]; adds	r14,0x18,r15; adds	r15,0x8,r15; }
	{ ld4	r16,[r14]; and	r16,0xFFFFFFFFFFFFFFFD,r16; nop.i	0x0; }
	{ st4	[r16],r14; addl	r14,6456,r1; (p17) br.cond.dpnt.few	40000000000824F0; }

l4000000000081E70:
	{ nop.m	0x0; ld8	r34,[r15]; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	4000000000082230 }

l4000000000081EA0:
	{ addl	r14,-20676,r1; nop.m	0x0; addl	r45,-7852,r1 }
	{ addl	r44,1,r0; nop.m	0x0; adds	r46,0x1,r32; }
	{ nop.m	0x0; adds	r15,0x30,r14; adds	r14,0x34,r14; }
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,r32,r15; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000082620; }

l4000000000081EF0:
	{ ld4	r47,[r14]; ld8	r45,[r45]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,r32,r47; (p06) addl	r47,-7892,r1; nop.i	0x0; }

l4000000000081F0C:
	{ cmp4.eq.or.andcm	p00,p43,r1,r0; (p05) cmp4.eq.or.andcm	p45,p19,r95,r112; Invalid }

l4000000000081F16:
	{ (p23) fwb; cmp4.eq	p00,p00,r0,r1; (p49) br.call.sptk.few	b3,b0; }

l4000000000081F1C:
	{ cmp4.eq.or.andcm	p00,p49,r1,r0; Invalid; break.i	0x1000 }

l4000000000081F26:
	{ break.m	0x4000; Invalid; (p32) nop }
	{ Invalid; (p07) mov.sptk	b6,r35,4000000000081F36; (p32) br.call.sptk.few	b3,b0 }
	{ break.m	0x4000; (p07) nop; (p32) nop }
	{ break.m	0x4000; nop; (p48) nop }

l4000000000081F60:
	{ ld8	r47,[r34]; nop.m	0x0; adds	r15,0x18,r34 }
	{ addl	r45,-7844,r1; addl	r44,1,r0; cmp.eq	p06,p07,r14,r47 }
	{ ld8	r15,[r15]; ld8	r45,[r45]; nop.i	0x0; }
	{ (p07) addl	r47,-7876,r1; (p06) addl	r47,-8196,r1; nop.i	0x0; }

l4000000000081F96:
	{ Invalid; cmp4.ltu	p00,p00,0x0,r1; Invalid; }

l4000000000081F9C:
	{ cmp4.eq.or.andcm	p00,p43,r1,r0; (p05) cmp4.ne.or.andcm	p32,p08,r11,r6; (p05) cmp.eq.unc	p32,p08,r11,r6 }

l4000000000081FA6:
	{ Invalid; (p03) cmp4.eq.or	p00,p50,0xF,r6; Invalid; }

l4000000000081FAC:
	{ cmp4.eq.and	p15,p43,r6,r114; (p05) cmp4.eq.and	p63,p19,r127,r111; zxt1	r96,r64 }

l4000000000081FB6:
	{ Invalid; cmp4.eq	p00,p00,r0,r1; (p33) nop; }

l4000000000081FBC:
	{ cmp4.eq.and	p00,p49,r1,r0; Invalid; break.i	0x1000 }

l4000000000081FC6:
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; nop; (p32) nop }
	{ Invalid; nop; (p48) nop }
	{ Invalid; nop; break.i	0x80000 }
	{ (p07) fwb; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r34,3FFFFFFFFFC850F6; nop; nop }

l4000000000082020:
	{ cmp4.eq	p06,p07,0x0,r37; adds	r44,0x0,r39; (p07) br.cond.dpnt.few	4000000000082470; }

l4000000000082030:
	{ nop.m	0x0; ld8	r34,[r15]; nop.i	0x0; }
	{ adds	r45,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r42; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dpnt.few	4000000000082350 }

l4000000000082060:
	{ cmp4.eq	p19,p18,0x0,r38; addl	r44,10,r0; br.call.sptk.many	b0,fn400000000001B900; }
	{ adds	r1,0x0,r42; (p19) adds	r44,0x0,r32; (p19) br.call.dpnt.many	b0,fn4000000000077080; }

l400000000008207C:
	{ invala; nop; nop }

l4000000000082080:
	{ nop.m	0x0; (p19) adds	r1,0x0,r42; (p17) br.cond.dpnt.few	40000000000823C0 }

l400000000008208C:
	{ (p26) cmp.lt	p00,p11,r64,r33; (p01) cmp.lt	p00,p08,r9,r6; zxt1	r99,r0 }

l4000000000082090:
	{ ld8	r14,[r36]; add	r14,r14,r35; nop.i	0x0; }
	{ ld8	r14,[r14]; adds	r14,0x18,r14; nop.i	0x0; }
	{ ld4	r15,[r14]; nop.i	0x0; and	r15,0xFFFFFFFFFFFFFFFE,r15; }
	{ st4	[r15],r14; nop.m	0x0; nop.i	0x0 }

l40000000000820D0:
	{ (p19) ld8	r14,[r36]; (p19) addl	r45,18,r0; adds	r34,0x0,r0; }

l40000000000820D6:
	{ Invalid; Invalid; Invalid }

l40000000000820DC:
	{ nop; (p36) nop }

l40000000000820EC:
	{ cmp.ge.or.andcm	p00,p43,r0,r0; (p01) cmp.lt.and	p32,p40,r0,r6; (p01) cmp.lt.or.andcm	p38,p48,r0,r64 }

l40000000000820F6:
	{ (p07) nop; (p04) nop }

l40000000000820FC:
	{ Invalid; Invalid; Invalid; }

l4000000000082100:
	{ (p19) ld4	r16,[r14]; (p19) ld4	r44,[r15]; nop.i	0x0; }

l4000000000082106:
	{ (p22) fwb; nop }

l400000000008210C:
	{ nop; chk.s.i	r32,3FFFFFFFFF88210C; zxt1	r0,r11 }

l400000000008211C:
	{ Invalid; Invalid; chk.s.i	r32,3FFFFFFFFF88211C }

l4000000000082126:
	{ nop; (p32) cmp4.eq	p60,p45,0x31,r126; (p20) nop }

l4000000000082130:
	{ (p19) adds	r1,0x0,r42; (p17) br.cond.dpnt.few	4000000000082290; br.call.sptk.many	b0,fn400000000007A5C0; }

l4000000000082136:
	{ Invalid; (p16) nop }

l400000000008213C:
	{ (p36) nop; shladd	r64,r10,0x1,r64; (p37) nop }
	{ nop; (p05) cmp.lt	p04,p16,r3,r64; zxt1	r0,r64 }
	{ (p43) nop; invala; break.b	0x1000 }
	{ Invalid; (p01) cmp.eq.unc	p00,p16,r8,r64; (p63) nop.i	0xDFE0A }

l4000000000082170:
	{ adds	r8,0x0,r34; mov	pr,r43,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.spnt	b0,r40,4000000000082180; nop.i	0x0 }
	{ adds	r12,0x100,r12; nop.m	0x0; br.ret	b0 }

l40000000000821A0:
	{ addl	r45,-7860,r1; nop.m	0x0; adds	r44,0x0,r0 }
	{ addl	r46,5,r0; nop.m	0x0; adds	r34,0x0,r0; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r42; adds	r44,0x0,r8; adds	r46,0x1,r32; }
	{ addl	r14,9036,r1; nop.m	0x0; nop.i	0x0; }
	{ ld8	r45,[r14]; nop.i	0x0; br.call.sptk.many	b0,internal_error; }
	{ adds	r1,0x0,r42; addl	r44,2,r0; nop.i	0x0 }
	{ adds	r45,0x10,r12; adds	r46,0x0,r0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	4000000000082170; }

l4000000000082230:
	{ addl	r47,-7884,r1; nop.m	0x0; addl	r45,-7852,r1 }
	{ addl	r44,1,r0; adds	r46,0x1,r32; nop.i	0x0 }
	{ ld8	r47,[r47]; ld8	r45,[r45]; br.call.sptk.many	b0,fn400000000001BB80; }
	{ ld8	r14,[r36]; adds	r1,0x0,r42; add	r14,r14,r35; }
	{ ld8	r14,[r14]; adds	r14,0x8,r14; nop.i	0x0; }
	{ ld8	r14,[r14]; nop.i	0x0; br.cond.sptk.few	4000000000081F60 }

l4000000000082290:
	{ adds	r44,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn4000000000079140; }
	{ adds	r8,0x8,r8; adds	r45,0x10,r12; nop.i	0x0 }
	{ adds	r1,0x0,r42; adds	r46,0x0,r0; addl	r44,2,r0; }
	{ ld4	r34,[r8]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r42; adds	r44,0x0,r34; br.call.sptk.many	b0,wait_for; }
	{ adds	r1,0x0,r42; adds	r34,0x0,r8; addl	r46,60,r0; }
	{ addl	r44,19084,r1; addl	r45,19144,r1; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ adds	r1,0x0,r42; nop.i	0x0; br.call.sptk.many	b0,set_tty_state; }
	{ adds	r8,0x0,r34; adds	r1,0x0,r42; mov	pr,r43,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r41; mov.spnt	b0,r40,4000000000082330 }
	{ nop.m	0x0; adds	r12,0x100,r12; br.ret	b0; }

l4000000000082350:
	{ adds	r44,0x0,r34; cmp4.eq	p19,p18,0x0,r38; br.call.sptk.many	b0,polite_directory_format; }
	{ adds	r1,0x0,r42; adds	r46,0x0,r8; addl	r44,1,r0; }
	{ nop.m	0x0; addl	r45,-7836,r1; nop.i	0x0; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ addl	r44,10,r0; adds	r1,0x0,r42; br.call.sptk.many	b0,fn400000000001B900; }
	{ adds	r1,0x0,r42; (p19) adds	r44,0x0,r32; (p19) br.call.dpnt.many	b0,fn4000000000077080; }

l40000000000823AC:
	{ (p39) invala; nop; zxt1	r64,r64 }

l40000000000823B0:
	{ nop.m	0x0; (p19) adds	r1,0x0,r42; (p16) br.cond.dptk.few	4000000000082090 }

l40000000000823BC:
	{ Invalid; break.i	0x1000; break.i	0x1000 }

l40000000000823C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,get_tty_state; }
	{ adds	r1,0x0,r42; nop.m	0x0; addl	r46,60,r0; }
	{ addl	r44,19144,r1; addl	r45,19084,r1; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ ld8	r14,[r36]; adds	r1,0x0,r42; add	r14,r14,r35; }
	{ ld8	r14,[r14]; adds	r15,0x18,r14; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r15,0x2; (p06) br.cond.dptk.few	40000000000820D0 }

l4000000000082440:
	{ adds	r14,0x10,r14; nop.m	0x0; adds	r45,0x0,r0; }
	{ ld4	r44,[r14]; nop.i	0x0; br.call.sptk.many	b0,give_terminal_to; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	40000000000820D0; }

l4000000000082470:
	{ addl	r45,-8084,r1; nop.m	0x0; addl	r44,1,r0; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r42; adds	r44,0x0,r39; addl	r14,7444,r1; }
	{ ld8	r14,[r14]; add	r14,r14,r35; nop.i	0x0; }
	{ ld8	r15,[r14]; ld8	r34,[r15]; nop.i	0x0; }
	{ adds	r45,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r42; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	4000000000082060 }

l40000000000824E0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000082350 }

l40000000000824F0:
	{ adds	r44,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000007A300; }
	{ ld8	r14,[r36]; adds	r1,0x0,r42; addl	r44,1,r0; }
	{ add	r14,r14,r35; nop.m	0x0; addl	r45,-7844,r1; }
	{ ld8	r14,[r14]; ld8	r45,[r45]; nop.i	0x0; }
	{ adds	r15,0x18,r14; nop.m	0x0; adds	r14,0x8,r14; }
	{ ld8	r34,[r14]; ld4	r16,[r15]; nop.i	0x0; }
	{ adds	r14,0x0,r34; nop.m	0x0; or	r16,0x1,r16; }
	{ ld8	r47,[r34]; st4	[r16],r15; adds	r15,0x18,r34; }
	{ cmp.eq	p06,p07,r14,r47; ld8	r15,[r15]; nop.i	0x0; }
	{ (p07) addl	r47,-7876,r1; (p06) addl	r47,-8196,r1; nop.i	0x0; }

l4000000000082586:
	{ Invalid; cmp4.ltu	p00,p00,0x0,r1; Invalid; }

l400000000008258C:
	{ cmp4.eq.or.andcm	p00,p43,r1,r0; (p05) cmp4.ne.or.andcm	p32,p08,r11,r6; (p05) cmp.eq.unc	p32,p08,r11,r6 }

l4000000000082596:
	{ Invalid; (p03) cmp4.eq.or	p00,p50,0xF,r6; Invalid; }

l400000000008259C:
	{ cmp4.eq.and	p15,p43,r6,r114; (p05) cmp4.eq.and	p63,p19,r127,r111; zxt1	r96,r64 }

l40000000000825A6:
	{ Invalid; cmp4.eq	p00,p00,r0,r1; (p33) nop; }

l40000000000825AC:
	{ cmp4.eq.and	p00,p49,r1,r0; Invalid; break.i	0x1000 }

l40000000000825B6:
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; nop; (p32) nop }
	{ Invalid; nop; (p48) nop }
	{ Invalid; nop; break.i	0x80000 }
	{ (p07) fwb; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r34,3FFFFFFFFFC856E6; nop; break.b	0x80000 }

l4000000000082610:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000082020 }

l4000000000082620:
	{ addl	r47,-7900,r1; nop.m	0x0; addl	r45,-7852,r1 }
	{ addl	r44,1,r0; adds	r46,0x1,r32; nop.i	0x0 }
	{ ld8	r47,[r47]; ld8	r45,[r45]; br.call.sptk.many	b0,fn400000000001BB80; }
	{ ld8	r14,[r36]; adds	r1,0x0,r42; add	r14,r14,r35; }
	{ ld8	r14,[r14]; adds	r14,0x8,r14; nop.i	0x0; }
	{ ld8	r14,[r14]; nop.i	0x0; br.cond.sptk.few	4000000000081F60 }

l4000000000082680:
	{ addl	r45,-7868,r1; nop.m	0x0; addl	r46,5,r0 }
	{ adds	r44,0x0,r0; nop.m	0x0; addl	r34,-1,r0; }
	{ ld8	r45,[r45]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r42; adds	r44,0x0,r8; addl	r14,9036,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld8	r45,[r14]; nop.i	0x0; br.call.sptk.many	b0,internal_error; }
	{ adds	r1,0x0,r42; addl	r44,2,r0; nop.i	0x0 }
	{ adds	r45,0x10,r12; adds	r46,0x0,r0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	4000000000082170; }
4000000000082710 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000082720 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000082730 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; make_child: 4000000000082740
;;   Called from:
;;     400000000009403C (in command_substitute)
;;     40000000000A2A3C (in fn40000000000A1400)
make_child proc
	{ alloc	r38,ar.pfs,0xC,0x0,0x9; adds	r12,0xFFFFFFFFFFFFFEF0,r12; nop.b	0x0 }
	{ adds	r39,0x0,r1; nop.m	0x0; mov	r37,b5; }
	{ adds	r41,0x90,r12; nop.m	0x0; mov	r40,LC }
	{ addl	r34,1,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r41,0x90,r12 }
	{ addl	r42,17,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B400; }
	{ addl	r42,2,r0; nop.m	0x0; adds	r1,0x0,r39 }
	{ adds	r41,0x90,r12; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B400; }
	{ adds	r1,0x0,r39; adds	r41,0x10,r12; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r41,0x0,r0; adds	r1,0x0,r39; nop.i	0x0 }
	{ adds	r42,0x90,r12; adds	r43,0x10,r12; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r39; nop.i	0x0; br.call.sptk.many	b0,making_children; }
	{ adds	r1,0x0,r39; cmp4.eq	p08,p09,0x0,r33; addl	r14,5636,r1; }
	{ nop.m	0x0; ld4	r41,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r41; (p06) br.cond.dpnt.few	4000000000082860; (p08) br.cond.dpnt.few	4000000000082840; }

l400000000008282C:
	{ (p01) invala; cmp.eq	p00,p00,r32,r0; mov	pr,r74,0xC640 }

l4000000000082830:
	{ nop.m	0x0; cmp4.lt	p07,p06,0x0,r41; (p06) br.cond.dpnt.few	4000000000082860 }

l4000000000082840:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sync_buffered_stream; }
	{ adds	r1,0x0,r39; nop.m	0x0; nop.i	0x0 }

l4000000000082860:
	{ nop.m	0x0; mov.i	LC,0x4; br.call.sptk.many	b0,fn400000000001BCE0; }
	{ nop.m	0x0; adds	r1,0x0,r39; adds	r35,0x0,r8 }
	{ nop.m	0x0; cmp4.lt	p07,p06,r8,r0; (p06) br.cond.dpnt.few	4000000000082DD0; }

l4000000000082890:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000828A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ ld4	r14,[r8]; adds	r1,0x0,r39; adds	r41,0x0,r0; }
	{ cmp4.eq	p07,p06,0xB,r14; (p06) br.cond.dpnt.few	40000000000828D0; br.cloop.sptk.few	4000000000082D40 }

l40000000000828CC:
	{ (p36) nop; Invalid; dep	r0,r32,r0,63,1 }

l40000000000828D0:
	{ addl	r41,-7804,r1; nop.m	0x0; addl	r34,7428,r1; }
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,sys_error; }
	{ adds	r1,0x0,r39; nop.i	0x0; br.call.sptk.many	b0,terminate_current_pipeline; }
	{ ld8	r14,[r34]; nop.m	0x0; adds	r1,0x0,r39; }
	{ cmp.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000082940; }

l4000000000082920:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,kill_current_pipeline; }
	{ adds	r1,0x0,r39; nop.m	0x0; nop.i	0x0; }

l4000000000082940:
	{ addl	r14,9044,r1; nop.m	0x0; addl	r15,126,r0; }
	{ nop.m	0x0; nop.i	0x0; nop.i	0x0 }
	{ st4	[r15],r14; nop.m	0x0; br.call.sptk.many	b0,throw_to_top_level; }
	{ adds	r1,0x0,r39; nop.m	0x0; nop.i	0x0; }

l4000000000082980:
	{ addl	r15,5904,r1; ld4	r14,[r15]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r14; nop.m	0x0; (p07) addl	r36,5908,r1 }

l40000000000829A0:
	{ nop.m	0x0; (p07) st4	[r35],r15; (p07) br.cond.dpnt.few	4000000000082A00; }

l40000000000829AC:
	{ Invalid; (p04) cmp.eq	p37,p18,r64,r11; Invalid }

l40000000000829B0:
	{ addl	r36,5908,r1; ld4	r15,[r36]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r15; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000083170; }

l40000000000829D0:
	{ cmp4.eq	p07,p06,0x0,r15; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000082A00; }

l40000000000829E0:
	{ cmp4.lt	p06,p07,r35,r14; nop.i	0x0; (p07) addl	r14,1,r0; }

l40000000000829F0:
	{ (p07) st4	[r14],r36; nop.m	0x0; nop.i	0x0 }

l40000000000829F6:
	{ break.m	0x4000; nop; (p32) nop }

l4000000000082A00:
	{ addl	r14,5868,r1; ld4	r14,[r14]; nop.i	0x0; }

l4000000000082A02:
	{ Invalid; (p32) break.i	0x20203; nop }

l4000000000082A06:
	{ (p07) fwb; nop; (p32) nop }

l4000000000082A0C:
	{ cmp.lt	p00,p17,r1,r0; cmp.lt.unc	p00,p28,r99,r97; (p01) mov	pr,r64,0x9046 }

l4000000000082A16:
	{ (p07) chk.a.clr	r12,3FFFFFFFFF29FA26; Invalid; (p32) nop }

l4000000000082A1C:
	{ (p50) cmpxchg1.acq.nt1	r0,[r33],r0; (p05) nop; (p05) cmp.eq.unc	p32,p16,r8,r64 }

l4000000000082A22:
	{ Invalid; (p48) chk.s.i	r64,4000000000C8AAA2; Invalid; }

l4000000000082A28:
	{ (p04) ld1	r64,[r112]; (p37) nop; (p57) mov	pr,0x50E8C80 }

l4000000000082A2C:
	{ Invalid; (p48) dep	r72,r3,r100,49,9; zxt1	r96,r64 }
	{ (p29) nop; nop; (p05) nop }
	{ (p20) nop; (p02) cmp.lt.unc	p00,p08,r8,r6; (p01) cmp.eq	p00,p16,r2,r64 }
	{ (p12) cmpxchg2.acq	r8,[r66],r0; (p02) nop; (p02) nop; }
	{ nop; break.i	0x1000; (p01) cmp.eq.unc	p04,p10,r3,r102 }
	{ loadrs; Invalid; (p48) cmp4.ne.or.andcm	p08,p08,r3,r100 }
	{ cmp.lt	p16,p09,r0,r66; zxt4	r0,r0; Invalid; }
	{ nop; Invalid; Invalid }
	{ Invalid; Invalid; mov	pr,r32,0x0 }
	{ (p03) nop; cmp.lt	p00,p00,r32,r0; Invalid }
	{ Invalid; cmp.eq	p00,p00,r32,r0; (p32) mov	pr,r68,0xE006 }
	{ (p01) cmp.eq	p00,p11,r64,r33; (p01) cmp.lt.unc	p00,p16,r3,r64; (p01) rfi }
	{ invala; cmp.eq	p00,p00,r32,r0; (p32) mov	pr,r68,0xE006 }
	{ (p63) nop; Invalid; break.b	0x1000 }
	{ cmp.lt	p00,p08,r1,r0; czx1.r	r32,r97; nop }
	{ cmpxchg1.acq.nt1	r35,[r66],r0; (p05) nop; }
	{ Invalid; (p48) cmp.lt.unc	p08,p08,r3,r100; Invalid; }
	{ cmp.eq	p00,p17,r1,r0; czx1.l	r64,r97; mov	pr,r32,0x0 }
	{ Invalid; break.i	0x1000; break.i	0x1000 }
	{ (p07) nop; cmp.eq.unc	p32,p16,r9,r64; Invalid }
	{ cmpxchg8.acq	r8,[r0],r22; (p04) nop; (p05) mov	pr,r0,0x8400; }
	{ (p06) cmp.lt	p00,p09,r64,r33; (p01) dep	r37,r64,r14,62,3; nop }
	{ Invalid; Invalid; Invalid }
	{ cmp.lt	p00,p11,r1,r0; (p01) cmp.lt.unc	p00,p08,r3,r6; zxt1	r69,r64 }
	{ nop; cmp.lt	p00,p00,r32,r0; Invalid }
	{ cmp.eq	p00,p17,r1,r0; czx1.r	r65,r97; mov	pr,r32,0x0 }
	{ (p46) cmpxchg4.acq	r0,[r33],r64; Invalid; break.b	0x1000 }
	{ (p60) nop; nop; (p05) epc }
	{ cmpxchg8.acq	r0,[r0],r1; (p05) nop; zxt1	r64,r64 }
	{ (p44) cmp.eq.unc	p28,p09,r63,r44; (p01) invala; nop.b	0x1000 }
	{ cmp.lt	p39,p11,r0,r66; (p01) cmp.lt.unc	p32,p08,r3,r6; czx1.r	r64,r65 }
	{ nop; cmp4.eq.and	p00,p32,r32,r0; zxt1	r66,r64 }
	{ Invalid; Invalid; break.i	0x1000 }
	{ cmpxchg2.acq.nt1	r0,[r0],r1; Invalid; break.i	0x1000 }
	{ cmp.eq	p00,p10,r1,r0; zxt1	r67,r64; (p02) cmp.eq.unc	p32,p08,r3,r4 }
	{ (p26) cmp.lt	p01,p11,r116,r72; Invalid; break.i	0x1000; }
	{ cmp.eq	p00,p11,r1,r0; (p01) cmp.eq.unc	p36,p16,r3,r64; Invalid }
	{ cmp.eq	p00,p11,r1,r0; zxt1	r100,r0; cmp.eq	p00,p00,r32,r0 }
	{ invala; cmp.lt	p00,p00,r32,r0; (p48) mov	pr,r99,0xC086; }
	{ (p26) cmp.lt	p00,p08,r64,r33; (p01) dep	r69,r8,r64,62,1; (p04) nop }
	{ (p58) nop; (p37) dep	r0,r0,r0,62,3; (p05) nop }
	{ nop; (p48) nop; }
	{ cmp.eq	p00,p11,r1,r0; Invalid; (p18) cmp.eq	p00,p16,r4,r64 }
	{ nop; break.i	0x1000; rfi; }
	{ nop; Invalid; break.i	0x1000 }
	{ (p14) nop; invala; break.b	0x1000 }
	{ Invalid; zxt1	r96,r64; (p32) break.i	0x2A809 }
	{ (p20) break.m	0x1541; break.i	0x1000; (p16) break.i	0xC0029 }
	{ shladdp4	r0,r1,0x2,r0; zxt1	r4,r64; add	r0,r32,r0 }
	{ Invalid; break.m	0x1000; break.i	0x1000 }

l4000000000082D40:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000007D580; }
	{ adds	r1,0x0,r39; addl	r41,-7828,r1; nop.i	0x0; }
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,sys_error; }
	{ adds	r41,0x0,r34; nop.m	0x0; adds	r1,0x0,r39 }
	{ shladd	r34,r34,0x1,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AB20; }
	{ cmp4.eq	p07,p06,0x0,r8; adds	r1,0x0,r39; (p06) br.cond.dpnt.few	40000000000828D0; }

l4000000000082DA0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BCE0; }
	{ nop.m	0x0; adds	r1,0x0,r39; adds	r35,0x0,r8 }
	{ nop.m	0x0; cmp4.lt	p07,p06,r8,r0; (p07) br.cond.dptk.few	40000000000828A0; }

l4000000000082DD0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ nop.m	0x0; (p07) addl	r34,7428,r1; (p07) br.cond.dptk.few	4000000000082980 }

l4000000000082DEC:
	{ Invalid; break.i	0x1000; break.i	0x1000 }

l4000000000082DF0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B1A0; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r34,0x0,r8 }
	{ adds	r41,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,unset_bash_input; }
	{ adds	r1,0x0,r39; addl	r41,2,r0; adds	r43,0x0,r0; }
	{ nop.m	0x0; addl	r42,25124,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r39; addl	r14,5868,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000083100 }

l4000000000082E80:
	{ addl	r35,7436,r1; nop.m	0x0; addl	r36,5896,r1; }
	{ ld4	r14,[r35]; ld4	r15,[r36]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; }
	{ (p07) adds	r14,0x0,r34; (p07) st4	[r34],r35; nop.i	0x0; }

l4000000000082EB6:
	{ mf.a; nop; (p48) nop; }

l4000000000082EBC:
	{ cmp.eq	p00,p17,r1,r0; czx1.r	r99,r33; mov	pr,r32,0x0 }
	{ Invalid; break.i	0x1000; break.b	0x1000 }

l4000000000082ED0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,default_tty_job_signals; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r41,0x0,r34 }
	{ ld4	r42,[r35]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BDE0; }
	{ adds	r1,0x0,r39; cmp4.lt	p07,p06,r8,r0; (p07) br.cond.dpnt.few	4000000000083300; }

l4000000000082F10:
	{ ld4	r41,[r35]; cmp4.eq	p06,p07,0x0,r33; (p07) br.cond.dptk.few	4000000000082F60 }

l4000000000082F20:
	{ nop.m	0x0; ld4	r14,[r36]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,r14,r41; addl	r14,9028,r1; (p06) br.cond.dpnt.few	4000000000082F60; }

l4000000000082F40:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x0; (p07) br.cond.dpnt.few	4000000000083360; }

l4000000000082F60:
	{ nop.m	0x0; cmp4.eq	p07,p06,r41,r34; (p07) br.cond.dpnt.few	4000000000083220 }

l4000000000082F70:
	{ nop.m	0x0; addl	r41,5880,r1; adds	r35,0x0,r0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,sh_closepipe; }
	{ adds	r1,0x0,r39; nop.m	0x0; nop.i	0x0 }

l4000000000082FA0:
	{ adds	r8,0x0,r35; mov.i	ar.pfs,r38; mov.i	LC,r40; }
	{ nop.m	0x0; mov.spnt	b0,r37,4000000000082FB0; nop.i	0x0 }
	{ adds	r12,0x110,r12; nop.m	0x0; br.ret	b0; }
4000000000082FD0 11 48 01 46 00 21 00 00 00 02 00 00 F8 45 FF 58 .H.F.!.......E.X
4000000000082FE0 08 70 50 44 00 21 20 42 88 00 42 20 00 38 01 84 .pPD.! B..B .8..
4000000000082FF0 09 48 09 00 00 24 A0 82 30 00 42 60 05 00 00 84 .H...$..0.B`....
4000000000083000 08 00 00 00 01 00 00 01 38 20 20 20 42 0F B4 90 ........8   B...
4000000000083010 0A 78 00 44 10 10 00 09 40 00 42 E0 11 78 00 84 .x.D....@.B..x..
4000000000083020 0A 00 8C 22 90 11 00 80 38 20 23 00 00 00 04 00 ..."....8 #.....
4000000000083030 19 00 3C 44 90 11 00 00 00 02 00 00 98 76 F9 58 ..<D.........v.X
4000000000083040 10 00 00 00 01 00 10 00 9C 00 42 00 D0 FC FF 48 ..........B....H
4000000000083050 03 78 00 1C 10 10 90 02 01 00 48 E0 00 78 18 E6 .x........H..x..
4000000000083060 EB 78 20 02 2E E4 F1 00 3C 20 20 00 00 00 04 00 .x .....<  .....
4000000000083070 F1 00 3C 1C 90 11 00 00 00 02 00 00 58 5C 06 50 ..<.........X\.P
4000000000083080 08 80 00 44 18 10 E0 00 20 00 42 E0 81 41 00 84 ...D.... .B..A..
4000000000083090 09 90 30 10 00 21 10 81 20 00 42 20 00 38 01 84 ..0..!.. .B .8..
40000000000830A0 08 00 00 00 01 00 80 80 38 30 2B E0 00 80 18 E4 ........80+.....
40000000000830B0 09 00 00 00 01 00 00 40 88 30 23 00 00 00 04 00 .......@.0#.....
40000000000830C0 09 00 8C 1C 90 D1 01 40 20 30 23 C0 11 00 00 90 .......@ 0#.....
40000000000830D0 09 00 80 1E 98 11 00 00 48 20 23 E3 01 80 00 84 ........H #.....
40000000000830E0 10 00 38 22 90 11 00 00 00 02 00 03 E0 F9 FF 4A ..8"...........J
40000000000830F0 10 00 00 00 01 00 00 00 00 02 00 00 20 FA FF 48 ............ ..H

l4000000000083100:
	{ addl	r14,7436,r1; nop.m	0x0; adds	r35,0x0,r0; }
	{ ld4	r15,[r14]; cmp4.eq	p07,p06,0x0,r15; nop.i	0x0; }
	{ (p07) addl	r15,5896,r1; (p07) ld4	r15,[r15]; nop.i	0x0; }

l4000000000083126:
	{ (p07) fwb; cmp4.eq	p00,p00,r0,r1; (p01) br.call.spnt.many	b0,b3; }

l400000000008312C:
	{ Invalid; Invalid; break.i	0x1000 }

l4000000000083136:
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; nop; (p16) nop }
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; nop; break.b	0x80000 }

l4000000000083170:
	{ nop.m	0x0; cmp4.lt	p07,p06,r35,r14; nop.i	0x0; }
	{ (p07) st4	[r0],r36; nop.i	0x0; br.cond.sptk.few	4000000000082A00 }

l4000000000083186:
	{ break.m	0x4000; nop; (p16) nop }
4000000000083190 11 48 01 10 00 21 A0 12 00 00 48 00 78 82 FF 58 .H...!....H.x..X
40000000000831A0 0B 08 00 4E 00 21 20 E2 F5 BD 4E 00 00 00 04 00 ...N.! ...N.....
40000000000831B0 0B 00 00 00 01 00 F0 60 88 00 42 00 00 00 04 00 .......`..B.....
40000000000831C0 08 00 00 00 01 00 00 01 3C 20 20 E0 41 0B D0 91 ........<  .A...
40000000000831D0 0B 70 00 44 18 10 00 00 00 02 00 00 00 00 04 00 .p.D............
40000000000831E0 0B 78 40 1E 00 21 F0 00 3C 20 20 00 00 00 04 00 .x@..!..<  .....
40000000000831F0 0B 78 40 1E 00 20 00 00 00 02 00 E0 01 78 58 00 .x@.. .......xX.
4000000000083200 10 00 00 00 01 00 60 78 38 0E 60 03 A0 FA FF 4A ......`x8.`....J
4000000000083210 10 00 00 00 01 00 00 00 00 02 00 00 C0 FD FF 48 ...............H

l4000000000083220:
	{ addl	r34,5884,r1; ld4	r41,[r34]; nop.i	0x0; }
	{ cmp4.lt	p06,p07,r41,r0; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000083270; }

l4000000000083240:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C340; }
	{ addl	r14,-1,r0; nop.m	0x0; adds	r1,0x0,r39; }
	{ st4	[r14],r34; nop.m	0x0; nop.i	0x0 }

l4000000000083270:
	{ addl	r34,5880,r1; ld4	r41,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r41,r0; (p06) br.cond.dpnt.few	4000000000082F70; }

l4000000000083290:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000832A0:
	{ adds	r42,0x110,r12; addl	r43,1,r0; br.call.sptk.many	b0,fn400000000001A600; }
	{ cmp.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; adds	r1,0x0,r39; (p06) br.cond.dpnt.few	4000000000082F70; }

l40000000000832C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ ld4	r14,[r8]; nop.m	0x0; adds	r1,0x0,r39; }
	{ cmp4.eq	p07,p06,0x4,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000082F70; }

l40000000000832F0:
	{ ld4	r41,[r34]; nop.i	0x0; br.cond.sptk.few	40000000000832A0; }

l4000000000083300:
	{ addl	r42,-7820,r1; adds	r41,0x0,r0; addl	r43,5,r0; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r39; adds	r41,0x0,r8; sxt4	r42,r34; }
	{ addl	r14,7436,r1; ld4	r43,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r43,r43; br.call.sptk.many	b0,sys_error; }
	{ nop.m	0x0; adds	r1,0x0,r39; br.cond.sptk.few	4000000000082F10 }

l4000000000083360:
	{ adds	r42,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,give_terminal_to; }
	{ adds	r1,0x0,r39; addl	r14,7436,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r41,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r41,r34; (p06) br.cond.dptk.few	4000000000082F70 }

l40000000000833A0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000083220 }

l40000000000833B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,ignore_tty_job_signals; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r41,0x0,r34 }
	{ ld4	r42,[r35]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BDE0; }
	{ adds	r1,0x0,r39; cmp4.lt	p07,p06,r8,r0; (p06) br.cond.dptk.few	4000000000082F10 }

l40000000000833F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000083300; }

;; stop_pipeline: 4000000000083400
stop_pipeline proc
	{ alloc	r44,ar.pfs,0x12,0x0,0xF; adds	r12,0xFFFFFFFFFFFFFE00,r12; nop.b	0x0 }
	{ addl	r37,-20676,r1; adds	r45,0x0,r1; mov	r43,b3; }
	{ nop.m	0x0; adds	r47,0x190,r12; mov	r46,LC }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BC20; }
	{ addl	r48,17,r0; adds	r1,0x0,r45; nop.i	0x0 }
	{ adds	r47,0x190,r12; adds	r34,0x1C,r37; br.call.sptk.many	b0,fn400000000001B400; }
	{ adds	r1,0x0,r45; adds	r47,0x110,r12; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r48,0x190,r12; adds	r49,0x110,r12; nop.i	0x0 }
	{ adds	r1,0x0,r45; adds	r47,0x0,r0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ nop.m	0x0; adds	r1,0x0,r45; nop.i	0x0; }
	{ addl	r47,5880,r1; nop.i	0x0; br.call.sptk.many	b0,sh_closepipe; }
	{ adds	r1,0x0,r45; nop.i	0x0; br.call.sptk.many	b0,fn400000000007E8C0; }
	{ adds	r1,0x0,r45; ld4	r14,[r34]; nop.i	0x0; }
	{ addl	r15,6516,r1; nop.m	0x0; cmp4.eq	p07,p06,0x0,r14 }
	{ addl	r35,7444,r1; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000083AD0; }

l40000000000834F0:
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p07) br.cond.dptk.few	4000000000083BA0; }

l4000000000083510:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000083520:
	{ nop.m	0x0; sxt4	r15,r14; nop.b	0x0 }
	{ ld8	r16,[r35]; adds	r18,0xFFFFFFFFFFFFFFFF,r14; adds	r34,0x0,r14; }
	{ adds	r17,0xFFFFFFFFFFFFFFFF,r15; adds	r15,0xFFFFFFFFFFFFFFFE,r15; addp4	r18,r18,r0; }
	{ shladd	r17,r17,0x3,r16; shladd	r15,r15,0x3,r16; mov.i	LC,r18; }
	{ nop.m	0x0; ld8	r16,[r17]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r16; (p06) br.cond.dpnt.few	40000000000846F0; }

l4000000000083580:
	{ nop.m	0x0; adds	r34,0xFFFFFFFFFFFFFFFF,r34; br.cloop.sptk.few	40000000000842B0 }

l4000000000083590:
	{ cmp4.eq	p09,p08,0x0,r14; nop.m	0x0; nop.i	0x0 }

l40000000000835A0:
	{ addl	r14,6512,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000083600 }

l40000000000835D0:
	{ addl	r14,9028,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000841C0 }

l4000000000083600:
	{ nop.m	0x0; nop.i	0x0; (p09) br.cond.dpnt.few	4000000000083CA0 }

l4000000000083610:
	{ addl	r39,7428,r1; addl	r47,56,r0; addl	r35,1,r0; }
	{ ld8	r14,[r39]; nop.m	0x0; adds	r35,0x1,r35; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000084890; }

l4000000000083640:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r36,0x0,r8; ld8	r8,[r39]; adds	r1,0x0,r45; }
	{ nop.m	0x0; ld8	r16,[r8]; nop.i	0x0; }
	{ cmp.eq	p06,p07,r16,r8; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000084390; }

l4000000000083680:
	{ nop.m	0x0; ld8	r14,[r16]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r14,r8; (p07) br.cond.dpnt.few	40000000000836D0; }

l40000000000836A0:
	{ adds	r16,0x0,r14; nop.m	0x0; adds	r35,0x1,r35; }
	{ nop.m	0x0; ld8	r14,[r16]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r14,r8; (p06) br.cond.dptk.few	40000000000836A0 }

l40000000000836D0:
	{ ld8.a	r14,[r8]; st8	[r0],r16; adds	r47,0x0,r8; }
	{ ld8.c.clr	r14,[r8]; cmp.eq	p06,p07,0x0,r14; nop.i	0x0; }
	{ (p06) adds	r14,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000083720; }

l40000000000836F6:
	{ chk.a.nc	r0,3FFFFFFFFF083EF6; nop; break.i	0x80000 }

l4000000000083700:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,list_reverse; }
	{ adds	r1,0x0,r45; ld8	r14,[r8]; nop.i	0x0; }

l4000000000083720:
	{ adds	r16,0x8,r36; adds	r18,0x0,r8; cmp.eq	p06,p07,0x0,r14; }
	{ st8	[r8],r16; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000083760; }

l4000000000083740:
	{ adds	r18,0x0,r14; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	4000000000083740 }

l4000000000083760:
	{ addl	r41,5868,r1; addl	r19,7436,r1; adds	r38,0x18,r36 }
	{ adds	r42,0x10,r36; adds	r14,0x0,r8; adds	r17,0x0,r0; }
	{ ld4	r22,[r41]; adds	r16,0x0,r0; addl	r20,255,r0 }
	{ ld4	r21,[r19]; st8	[r8],r18; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r22; nop.i	0x0 }
	{ st4	[r0],r38; st8	[r0],r39; nop.i	0x0; }
	{ (p07) addl	r18,4,r0; st4	[r21],r42; nop.i	0x0 }

l40000000000837C6:
	{ mf.a; nop; cmp.eq.or	p00,p36,r96,r4 }
	{ mf.a; nop; break.i	0x80000; }

l40000000000837DC:
	{ nop; nop; (p02) dep	r67,r3,r64,62,1 }

l40000000000837E0:
	{ nop.m	0x0; adds	r19,0xC,r14; adds	r18,0x10,r14 }

l40000000000837E2:
	{ adds	r32,0x1800,r0; Invalid; Invalid }
	{ (p32) chk.a.nc	r3,4000000000887852; (p32) cmp.eq.and	p04,p48,r4,r8; (p01) addl	r66,-65279,r0 }
	{ (p48) nop; (p32) adds	r36,0x1862,r28; (p50) addl	r4,1843459,r0 }
	{ chk.a.nc	r0,400000000091C812; (p63) nop }

l4000000000083816:
	{ Invalid; (p04) mov.spnt.imp	b7,r19,4000000000083196; nop }

l400000000008381C:
	{ Invalid; (p02) dep	r68,r68,r3,46,1; (p18) br.cond.sptk.few.clr	4000000000D0381C; }

l400000000008382C:
	{ invala; nop; (p18) mov	pr,r68,0x8088 }

l4000000000083830:
	{ nop.m	0x0; or	r17,r17,r18; (p06) br.cond.dptk.few	40000000000837E0 }

l4000000000083840:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r16; nop.i	0x0; }
	{ nop.m	0x0; (p06) addl	r17,1,r0; (p06) br.cond.dptk.few	4000000000083880; }

l400000000008385C:
	{ (p01) nop; cmp.lt	p00,p00,r32,r0; nop }

l4000000000083860:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r17; nop.i	0x0; }
	{ (p06) addl	r17,4,r0; nop.i	0x0; (p07) addl	r17,2,r0 }

l4000000000083876:
	{ addp4	r0,0xFFFFFFFFFFFFE000,r1; Invalid; (p48) nop }

l4000000000083880:
	{ addl	r47,-8228,r1; adds	r40,0x14,r36; nop.i	0x0 }
	{ st4	[r17],r40; ld8	r47,[r47]; br.call.sptk.many	b0,get_string_value; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r45; nop.i	0x0 }
	{ adds	r39,0x0,r8; adds	r47,0x0,r8; (p06) br.cond.dpnt.few	4000000000084450; }

l40000000000838C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r45; adds	r47,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r45; nop.m	0x0; adds	r47,0x0,r8 }
	{ adds	r48,0x0,r39; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r45; nop.m	0x0; nop.i	0x0; }

l4000000000083910:
	{ addl	r15,7444,r1; adds	r14,0x0,r36; sxt4	r18,r34 }
	{ adds	r19,0x28,r36; nop.m	0x0; adds	r17,0x30,r36; }
	{ ld8	r16,[r15]; st8	[r14],r32,32; nop.i	0x0 }
	{ st8	[r0],r19; ld4	r15,[r40]; nop.i	0x0; }
	{ shladd	r16,r18,0x3,r16; st8	[r33],r14; nop.i	0x0 }
	{ st8	[r0],r17; nop.m	0x0; cmp4.eq	p06,p07,0x4,r15; }
	{ st8	[r36],r16; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000843A0 }

l4000000000083980:
	{ adds	r15,0x10,r37; adds	r14,0x28,r37; nop.i	0x0 }
	{ adds	r19,0x20,r37; adds	r18,0x38,r37; cmp4.eq	p07,p06,0x0,r32; }
	{ ld4	r17,[r15]; st4	[r34],r19; nop.i	0x0 }
	{ st8	[r36],r18; ld4	r16,[r14]; nop.i	0x0; }
	{ add	r17,r17,r35; adds	r16,0x1,r16; nop.i	0x0 }
	{ st4	[r17],r15; st4	[r16],r14; (p06) br.cond.dptk.few	4000000000084510 }

l40000000000839E0:
	{ ld4	r14,[r38]; ld4	r15,[r41]; nop.i	0x0; }
	{ or	r14,0x1,r14; nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; }
	{ st4	[r14],r38; nop.i	0x0; (p06) br.cond.dptk.few	4000000000083A60 }

l4000000000083A10:
	{ nop.m	0x0; ld4	r35,[r42]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r35; (p06) br.cond.dptk.few	4000000000083A60 }

l4000000000083A30:
	{ addl	r14,9028,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x0; (p07) br.cond.dpnt.few	4000000000084620; }

l4000000000083A60:
	{ addl	r14,7420,r1; nop.m	0x0; addl	r47,2,r0 }
	{ adds	r48,0x110,r12; adds	r49,0x0,r0; nop.i	0x0 }
	{ st4	[r0],r14; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r45; nop.m	0x0; nop.i	0x0 }

l4000000000083AA0:
	{ adds	r8,0x0,r34; mov.i	ar.pfs,r44; mov.i	LC,r46; }
	{ nop.m	0x0; mov.spnt	b0,r43,4000000000083AB0; nop.i	0x0 }
	{ adds	r12,0x200,r12; nop.m	0x0; br.ret	b0 }

l4000000000083AD0:
	{ addl	r14,8,r0; addl	r35,7444,r1; addl	r47,64,r0; }
	{ st4	[r14],r34; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ ld4	r14,[r34]; adds	r1,0x0,r45; adds	r15,0x0,r0 }
	{ st8	[r8],r35; cmp4.lt	p06,p07,0x0,r14; adds	r16,0xFFFFFFFFFFFFFFFF,r14; }
	{ nop.m	0x0; (p06) addp4	r16,r16,r0; nop.i	0x0; }

l4000000000083B1C:
	{ invala; mov	pr,r32,0x0; mov	pr,r80,0x48 }

l4000000000083B2C:
	{ (p62) cmp.eq	p00,p08,r0,r33; (p01) dep	r61,r64,r12,62,3; (p02) epc }

l4000000000083B30:
	{ addl	r15,6516,r1; adds	r18,0x28,r37; nop.i	0x0 }
	{ adds	r17,0x20,r37; adds	r16,0x24,r37; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; st4	[r0],r18; nop.i	0x0 }
	{ st4	[r0],r17; st4	[r0],r16; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p09,p08,0x0,r15; (p08) br.cond.dptk.few	4000000000084370; }

l4000000000083B90:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000083BA0:
	{ adds	r15,0x20,r37; nop.m	0x0; addl	r35,7444,r1; }
	{ ld4	r34,[r15]; cmp4.eq	p06,p07,0x0,r34; nop.i	0x0; }
	{ (p07) adds	r34,0x1,r34; nop.i	0x0; sxt4	r16,r34 }

l4000000000083BC6:
	{ break.m	0x4000; (p08) nop; (p48) nop }
	{ (p08) chk.a.clr	r14,3FFFFFFFFF085DF6; nop; (p48) br.call.sptk.few	b3,b0 }

l4000000000083BE0:
	{ ld8	r15,[r35]; adds	r18,0x1,r16; addp4	r17,r17,r0; }
	{ shladd	r16,r16,0x3,r15; mov.i	LC,r17; shladd	r15,r18,0x3,r15; }
	{ ld8	r16,[r16]; cmp.eq	p06,p07,0x0,r16; nop.i	0x0; }
	{ (p06) cmp.eq	p08,p09,r0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000835A0; }

l4000000000083C16:
	{ chk.a.nc	r0,3FFFFFFFFF084416; nop; break.i	0x80000 }

l4000000000083C20:
	{ nop.m	0x0; adds	r34,0x1,r34; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p09,p08,r14,r34; br.cloop.sptk.few	4000000000083C50; }

l4000000000083C40:
	{ nop.m	0x0; cmp.eq	p09,p08,r0,r0; br.cond.sptk.few	40000000000835A0 }

l4000000000083C50:
	{ nop.m	0x0; ld8	r16,[r15],8; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r16; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000835A0; }

l4000000000083C70:
	{ nop.m	0x0; adds	r34,0x1,r34; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p09,p08,r14,r34; br.cloop.sptk.few	4000000000083C50 }

l4000000000083C90:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000083C40 }

l4000000000083CA0:
	{ nop.m	0x0; addl	r14,4095,r0; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r14,r34; (p06) br.cond.dptk.few	40000000000841E0 }

l4000000000083CC0:
	{ addl	r14,7464,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000841E0 }

l4000000000083CE0:
	{ adds	r34,0x1C,r37; nop.i	0x0; br.call.sptk.many	b0,reap_dead_jobs; }
	{ adds	r14,0x28,r37; adds	r1,0x0,r45; adds	r47,0x90,r12; }
	{ ld4	r14,[r14]; nop.i	0x0; extr.u	r15,r14,31,1 }
	{ adds	r16,0x7,r14; nop.m	0x0; extr.u	r15,r15,61,3; }
	{ add	r14,r14,r15; nop.m	0x0; extr.u	r17,r16,31,1; }
	{ nop.m	0x0; extr.u	r17,r17,61,3; and	r14,0x7,r14; }
	{ sub	r14,r14,r15; add	r16,r17,r16; extr	r39,r16,3,29 }
	{ cmp4.lt	p06,p07,0x4,r14; cmp4.eq.or.andcm	p06,p07,0x0,r14; shladd	r39,r39,0x3,r0; }
	{ (p06) adds	r39,0x8,r39; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BC20; }

l4000000000083D66:
	{ break.m	0x4000; (p32) nop; nop }
	{ add	r0,r0,r1; nop; (p48) nop }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; (p32) nop; (p16) nop.b	0x2D000 }
	{ Invalid; nop; nop.b	0x8C20C }
	{ Invalid; (p32) nop; br.call.sptk.few	b5,b0 }
	{ Invalid; Invalid; nop }
	{ Invalid; (p17) nop; (p33) br.call.sptk.few	b1,b0 }

l4000000000083DE0:
	{ (p06) ld8	r38,[r35]; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000083E20; }

l4000000000083DE6:
	{ chk.a.nc	r0,3FFFFFFFFF0845E6; nop; (p48) nop }

l4000000000083DF0:
	{ addl	r35,7444,r1; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r45; nop.m	0x0; adds	r38,0x0,r8 }
	{ ld4	r20,[r34]; nop.m	0x0; nop.i	0x0; }

l4000000000083E20:
	{ adds	r16,0x2C,r37; adds	r15,0xC,r37; adds	r14,0x34,r37 }
	{ cmp4.lt	p07,p06,0x0,r20; adds	r24,0x0,r0; adds	r23,0x0,r0; }
	{ nop.m	0x0; st4	[r0],r16; adds	r16,0x30,r37 }
	{ st4	[r0],r15; addl	r36,-1,r0; (p06) br.cond.dpnt.few	4000000000084800; }

l4000000000083E60:
	{ adds	r15,0x0,r0; ld4	r22,[r16]; addl	r34,-1,r0 }
	{ adds	r16,0x0,r0; ld4	r21,[r14]; nop.i	0x0; }

l4000000000083E80:
	{ shladd	r17,r15,0x3,r0; ld8	r18,[r35]; sxt4	r19,r16 }
	{ cmp4.eq	p09,p08,r22,r15; cmp4.eq	p11,p10,r15,r21; add	r18,r18,r17 }
	{ shladd	r19,r19,0x3,r38; ld8	r18,[r18]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r18; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000083F70; }

l4000000000083EC0:
	{ ld8.a	r14,[r35]; st8	[r18],r19; nop.i	0x0 }
	{ (p11) adds	r36,0x0,r16; (p09) adds	r34,0x0,r16; adds	r16,0x1,r16; }

l4000000000083ED6:
	{ Invalid; (p08) nop; (p32) nop }

l4000000000083EDC:
	{ cmp.lt	p16,p11,r0,r66; Invalid; (p33) epc }
	{ cmp.lt	p00,p11,r1,r0; (p01) nop; zxt1	r69,r64 }
	{ nop; nop; Invalid }
	{ invala; cmp.eq	p00,p00,r32,r0; mov	pr,r68,0xE642 }
	{ (p03) cmp.lt	p00,p09,r0,r33; zxt1	r66,r64; (p19) nop }

l4000000000083F20:
	{ adds	r14,0x8,r14; adds	r24,0x1,r24; adds	r17,0x0,r0; }
	{ ld8	r18,[r14]; nop.i	0x0; adds	r14,0x0,r18; }

l4000000000083F40:
	{ ld8	r14,[r14]; nop.m	0x0; adds	r17,0x1,r17; }
	{ nop.m	0x0; cmp.eq	p07,p06,r14,r18; (p06) br.cond.dptk.few	4000000000083F40 }

l4000000000083F60:
	{ add	r23,r23,r17; nop.m	0x0; nop.i	0x0 }

l4000000000083F70:
	{ nop.m	0x0; adds	r15,0x1,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r15,r20; (p06) br.cond.dptk.few	4000000000083E80; }

l4000000000083F90:
	{ adds	r18,0x2C,r37; sub	r20,r39,r16,0x1; adds	r15,0xC,r37 }
	{ adds	r14,0x24,r37; cmp4.eq	p06,p07,0x0,r16; adds	r17,0xFFFFFFFFFFFFFFFF,r16; }
	{ st4	[r24],r18; addp4	r20,r20,r0; sxt4	r18,r16 }
	{ st4	[r23],r15; (p06) adds	r17,0x0,r0; adds	r15,0x8,r38; }

l4000000000083FCC:
	{ (p04) nop; cmp.lt.unc	p00,p08,r3,r100; cmp.lt.unc	p36,p24,r105,r33; }
	{ (p09) cmp.lt	p38,p09,r18,r64; (p02) nop; (p02) nop; }
	{ (p14) nop; dep	r0,r32,r0,63,1; zxt1	r4,r0 }
	{ nop; Invalid; Invalid }
	{ invala; (p48) cmp4.ne.or.andcm	p41,p08,r4,r100; (p33) mov	pr,r67,0x80C8 }

l400000000008401C:
	{ (p59) nop; cmp.eq	p00,p00,r32,r0; Invalid }

l4000000000084020:
	{ nop.m	0x0; ld8	r47,[r35]; nop.i	0x0; }
	{ cmp.eq	p07,p06,r47,r38; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000084070; }

l4000000000084040:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r45; nop.i	0x0; addl	r14,7444,r1; }
	{ st8	[r38],r14; nop.m	0x0; nop.i	0x0 }

l4000000000084070:
	{ adds	r14,0x30,r37; nop.m	0x0; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r34; }
	{ (p07) ld4	r34,[r14]; (p06) st4	[r34],r14; cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r36; }

l4000000000084086:
	{ mf.a; (p03) cmp.ne.or	p63,p55,0x24,r7; (p33) cmp.eq.or.andcm	p03,p00,r45,r9; }

l400000000008408C:
	{ (p63) cmp4.eq.and	p36,p42,r7,r119; (p01) mov	pr,r9,0x845A; Invalid }

l4000000000084096:
	{ mf.a; (p07) nop; (p32) nop; }

l400000000008409C:
	{ (p26) cmp.lt	p37,p25,r0,r66; czx2.r	r95,r97; mov	pr,r32,0x0; }
	{ (p03) cmp.eq	p00,p09,r64,r33; Invalid; cmp.lt	p00,p00,r32,r0 }

l40000000000840B0:
	{ ld4	r15,[r14]; nop.m	0x0; adds	r14,0x20,r37; }
	{ cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r15; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000084100; }

l40000000000840D0:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r14,r34; (p06) br.cond.dptk.few	4000000000084100; }

l40000000000840F0:
	{ nop.m	0x0; cmp4.lt	p07,p06,r14,r15; (p06) br.cond.dpnt.few	4000000000084120 }

l4000000000084100:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000007A5C0; }
	{ adds	r1,0x0,r45; nop.m	0x0; nop.i	0x0 }

l4000000000084120:
	{ addl	r47,2,r0; nop.m	0x0; adds	r48,0x10,r12 }
	{ adds	r49,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r14,0x20,r37; nop.m	0x0; adds	r1,0x0,r45; }
	{ nop.m	0x0; ld4	r34,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	4000000000084190 }

l4000000000084170:
	{ ld8	r14,[r35]; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	40000000000847C0 }

l4000000000084190:
	{ adds	r14,0x1C,r37; nop.m	0x0; adds	r34,0x1,r34; }
	{ ld4	r14,[r14]; nop.i	0x0; cmp4.eq	p09,p08,r14,r34; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000841C0:
	{ nop.m	0x0; nop.i	0x0; (p08) br.cond.sptk.few	4000000000083610; }

l40000000000841D0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000841E0:
	{ adds	r14,0x8,r34; addl	r35,7444,r1; adds	r36,0x1C,r37; }
	{ nop.m	0x0; sxt4	r48,r14; nop.i	0x0 }
	{ st4	[r14],r36; ld8	r47,[r35]; nop.i	0x0; }
	{ shladd	r48,r48,0x3,r0; nop.i	0x0; br.call.sptk.many	b0,xrealloc; }
	{ ld4	r16,[r36]; sxt4	r15,r34; adds	r1,0x0,r45 }
	{ st8	[r8],r35; sub	r17,r16,r34,0x1; shladd	r14,r15,0x3,r0 }
	{ cmp4.lt	p07,p06,r34,r16; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000083610; }

l4000000000084250:
	{ nop.m	0x0; addp4	r17,r17,r0; nop.i	0x0; }
	{ add	r15,r15,r17,0x1; nop.i	0x0; shladd	r15,r15,0x3,r0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000084280:
	{ add	r8,r8,r14; nop.m	0x0; adds	r14,0x8,r14; }
	{ st8	[r0],r8; cmp.eq	p06,p07,r15,r14; (p06) br.cond.dpnt.few	4000000000083610; }

l40000000000842A0:
	{ ld8	r8,[r35]; nop.i	0x0; br.cond.sptk.few	4000000000084280 }

l40000000000842B0:
	{ nop.m	0x0; ld8	r16,[r15],-8; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r16; (p07) br.cond.dptk.few	4000000000083580 }

l40000000000842D0:
	{ nop.m	0x0; cmp4.eq	p09,p08,r14,r34; br.cond.sptk.few	40000000000835A0 }

l40000000000842E0:
	{ ld8	r8,[r35]; nop.m	0x0; nop.i	0x0; }

l40000000000842F0:
	{ add	r8,r8,r15; nop.m	0x0; adds	r15,0x8,r15; }
	{ st8	[r0],r8; nop.i	0x0; br.cloop.sptk.few	40000000000842E0 }

l4000000000084310:
	{ addl	r15,6516,r1; adds	r18,0x28,r37; nop.i	0x0 }
	{ adds	r17,0x20,r37; adds	r16,0x24,r37; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; st4	[r0],r18; nop.i	0x0 }
	{ st4	[r0],r17; st4	[r0],r16; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p09,p08,0x0,r15; (p09) br.cond.dptk.few	4000000000083BA0 }

l4000000000084370:
	{ nop.m	0x0; nop.i	0x0; (p07) br.cond.dptk.few	4000000000083520; }

l4000000000084380:
	{ adds	r34,0x0,r0; cmp.eq	p09,p08,r0,r0; br.cond.sptk.few	40000000000835A0 }

l4000000000084390:
	{ adds	r16,0x0,r8; addl	r35,1,r0; br.cond.sptk.few	40000000000836D0 }

l40000000000843A0:
	{ ld4	r14,[r38]; adds	r15,0xC,r37; tbit.z	p07,p06,r14,0x0 }
	{ adds	r14,0x2C,r37; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000843F0; }

l40000000000843C0:
	{ ld4	r17,[r15]; ld4	r16,[r14]; nop.i	0x0; }
	{ add	r17,r17,r35; adds	r16,0x1,r16; nop.i	0x0 }
	{ st4	[r17],r15; st4	[r16],r14; br.cond.sptk.few	4000000000083980 }

l40000000000843F0:
	{ adds	r47,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn4000000000077C00; }
	{ ld4	r14,[r40]; adds	r15,0xC,r37; adds	r1,0x0,r45; }
	{ cmp4.eq	p06,p07,0x4,r14; adds	r14,0x2C,r37; (p07) br.cond.spnt.few	4000000000083980; }

l4000000000084420:
	{ ld4	r17,[r15]; ld4	r16,[r14]; nop.i	0x0; }
	{ add	r17,r17,r35; adds	r16,0x1,r16; nop.i	0x0 }
	{ st4	[r17],r15; st4	[r16],r14; br.cond.sptk.few	4000000000083980 }

l4000000000084450:
	{ nop.m	0x0; addl	r47,-7796,r1; nop.i	0x0; }
	{ ld8	r47,[r47]; nop.i	0x0; br.call.sptk.many	b0,get_working_directory; }
	{ adds	r1,0x0,r45; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	4000000000083910 }

l4000000000084480:
	{ addl	r47,10,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ addl	r16,60,r0; adds	r14,0x0,r8; addl	r15,110,r0 }
	{ adds	r1,0x0,r45; st1	[r14],r1,1; addl	r16,117,r0; }
	{ st1	[r14],r1,1; nop.m	0x0; addl	r16,107,r0; }
	{ st1	[r14],r1,1; st1	[r14],r1,1; addl	r16,111,r0; }
	{ st1	[r14],r1,1; st1	[r14],r1,1; addl	r16,119,r0; }
	{ st1	[r14],r1,1; st1	[r14],r1,1; addl	r15,62,r0; }
	{ nop.m	0x0; st1	[r14],r1,1; nop.i	0x0; }
	{ st1	[r0],r14; nop.i	0x0; br.cond.sptk.few	4000000000083910 }

l4000000000084510:
	{ addl	r15,-20676,r1; cmp.eq	p06,p07,0x0,r36; (p06) br.cond.dpnt.few	40000000000845A0; }

l4000000000084520:
	{ ld4	r14,[r38]; nop.m	0x0; nop.i	0x0; }
	{ and	r14,0xFFFFFFFFFFFFFFFE,r14; adds	r15,0x40,r15; or	r14,0x20,r14; }
	{ nop.m	0x0; st4	[r14],r38; nop.i	0x0 }
	{ st8	[r36],r15; nop.m	0x0; br.call.sptk.many	b0,fn400000000007A5C0; }
	{ adds	r1,0x0,r45; nop.m	0x0; addl	r47,2,r0 }
	{ adds	r48,0x110,r12; adds	r49,0x0,r0; addl	r14,7420,r1; }
	{ st4	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ nop.m	0x0; adds	r1,0x0,r45; br.cond.sptk.few	4000000000083AA0 }

l40000000000845A0:
	{ adds	r37,0x30,r37; nop.i	0x0; br.call.sptk.many	b0,fn400000000007A5C0; }
	{ adds	r1,0x0,r45; nop.m	0x0; addl	r47,2,r0 }
	{ adds	r48,0x110,r12; adds	r49,0x0,r0; addl	r14,7420,r1; }
	{ st4	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r45; ld4	r34,[r37]; nop.i	0x0; }

l40000000000845F0:
	{ adds	r8,0x0,r34; mov.i	ar.pfs,r44; mov.i	LC,r46; }
	{ nop.m	0x0; mov.spnt	b0,r43,4000000000084600; nop.i	0x0 }
	{ adds	r12,0x200,r12; nop.m	0x0; br.ret	b0 }

l4000000000084620:
	{ addl	r14,5896,r1; ld4	r37,[r14]; addl	r14,5900,r1; }
	{ ld4	r47,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B640; }
	{ nop.m	0x0; adds	r1,0x0,r45; adds	r36,0x0,r8 }
	{ nop.m	0x0; cmp4.lt	p07,p06,r8,r0; (p07) br.cond.dpnt.few	4000000000084700; }

l4000000000084660:
	{ cmp4.eq	p07,p06,r36,r35; adds	r47,0x0,r35; adds	r48,0x0,r0; }
	{ nop.m	0x0; (p07) addl	r14,5892,r1; nop.i	0x0; }

l400000000008467C:
	{ Invalid; Invalid; mov	pr,r32,0x0 }

l4000000000084686:
	{ chk.a.nc	f0,3FFFFFFFFF084E86; nop; (p48) nop }

l4000000000084690:
	{ cmp4.eq	p07,p06,r36,r37; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000083A60; }

l40000000000846A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,give_terminal_to; }
	{ adds	r1,0x0,r45; nop.m	0x0; addl	r47,2,r0 }
	{ adds	r48,0x110,r12; adds	r49,0x0,r0; addl	r14,7420,r1; }
	{ st4	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ nop.m	0x0; adds	r1,0x0,r45; br.cond.sptk.few	4000000000083AA0 }

l40000000000846F0:
	{ adds	r34,0x0,r14; cmp.eq	p09,p08,r0,r0; br.cond.sptk.few	40000000000835A0 }

l4000000000084700:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ ld4	r14,[r8]; nop.m	0x0; adds	r1,0x0,r45; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x19,r14; (p07) br.cond.dptk.few	4000000000084660 }

l4000000000084730:
	{ addl	r14,7420,r1; nop.m	0x0; addl	r47,2,r0 }
	{ adds	r48,0x110,r12; nop.m	0x0; adds	r49,0x0,r0; }
	{ st4	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ nop.m	0x0; adds	r1,0x0,r45; br.cond.sptk.few	4000000000083AA0 }

l4000000000084770:
	{ nop.m	0x0; st8	[r14],r8,8; nop.i	0x0; }
	{ cmp.eq	p07,p06,r15,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000084020; }

l4000000000084790:
	{ nop.m	0x0; st8	[r14],r8,8; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r15,r14; (p06) br.cond.dptk.few	4000000000084770 }

l40000000000847B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000084020 }

l40000000000847C0:
	{ addl	r14,-20676,r1; nop.m	0x0; nop.i	0x0; }
	{ adds	r14,0x1C,r14; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p09,p08,0x0,r14; (p08) br.cond.sptk.few	4000000000083610 }

l40000000000847F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000841E0 }

l4000000000084800:
	{ adds	r16,0x0,r0; adds	r14,0x24,r37; adds	r15,0x8,r38 }
	{ adds	r17,0x0,r0; adds	r22,0x20,r37; adds	r21,0x28,r37; }
	{ sub	r20,r39,r16,0x1; st4	[r0],r14; sxt4	r18,r16 }
	{ cmp4.lt	p06,p07,r16,r39; adds	r19,0x1C,r37; addl	r36,-1,r0; }
	{ addp4	r20,r20,r0; shladd	r14,r18,0x3,r38; addl	r34,-1,r0 }
	{ st4	[r17],r22; st4	[r16],r21; nop.i	0x0; }
	{ add	r18,r18,r20; st4	[r39],r19; nop.i	0x0; }
	{ nop.m	0x0; (p06) shladd	r15,r18,0x3,r15; (p06) br.cond.dptk.few	4000000000084770 }

l400000000008487C:
	{ (p56) invala; break.i	0x1000; break.i	0x1000 }

l4000000000084880:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000084020 }

l4000000000084890:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r32; (p07) br.cond.dptk.few	40000000000845A0 }

l40000000000848A0:
	{ addl	r14,7420,r1; addl	r47,2,r0; nop.i	0x0 }
	{ adds	r48,0x110,r12; adds	r49,0x0,r0; adds	r37,0x30,r37; }
	{ st4	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ nop.m	0x0; adds	r1,0x0,r45; nop.i	0x0 }
	{ ld4	r34,[r37]; nop.m	0x0; br.cond.sptk.few	40000000000845F0; }
40000000000848F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; delete_all_jobs: 4000000000084900
;;   Called from:
;;     400000000008511C (in without_job_control)
;;     40000000000FFC5C (in disown_builtin)
delete_all_jobs proc
	{ alloc	r39,ar.pfs,0xD,0x0,0xA; adds	r12,0xFFFFFFFFFFFFFF00,r12; mov	r41,pr }
	{ addl	r37,-20676,r1; adds	r40,0x0,r1; addl	r35,7444,r1; }
	{ nop.m	0x0; mov	r38,b6; nop.i	0x0 }
	{ nop.m	0x0; adds	r42,0x90,r12; br.call.sptk.many	b0,fn400000000001BC20; }
	{ addl	r43,17,r0; adds	r1,0x0,r40; adds	r42,0x90,r12 }
	{ adds	r36,0x1C,r37; adds	r34,0x0,r0; br.call.sptk.many	b0,fn400000000001B400; }
	{ adds	r1,0x0,r40; adds	r42,0x10,r12; nop.i	0x0 }
	{ adds	r33,0x0,r0; cmp4.eq	p16,p17,0x0,r32; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r40; adds	r42,0x0,r0; nop.i	0x0 }
	{ adds	r43,0x90,r12; adds	r44,0x10,r12; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ ld4	r14,[r36]; addl	r15,-1,r0; adds	r17,0x34,r37 }
	{ adds	r16,0x30,r37; adds	r1,0x0,r40; cmp4.eq	p09,p08,0x0,r32; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000084B20; }

l40000000000849D0:
	{ nop.m	0x0; st4	[r15],r17; nop.i	0x0 }
	{ st4	[r15],r16; cmp4.lt	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	4000000000084A80; }

l40000000000849F0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000084A00:
	{ ld8	r14,[r35]; adds	r42,0x0,r33; addl	r43,1,r0 }
	{ adds	r33,0x1,r33; add	r14,r14,r34; adds	r34,0x8,r34; }
	{ ld8	r14,[r14]; adds	r15,0x14,r14; cmp.eq	p06,p07,0x0,r14 }
	{ nop.b	0x0; (p06) br.cond.dpnt.few	4000000000084A60; (p16) br.cond.dpnt.few	4000000000084AE0; }

l4000000000084A3C:
	{ (p05) nop; cmp.lt	p00,p00,r32,r0; (p01) rfi }

l4000000000084A40:
	{ nop.m	0x0; ld4	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x1,r14; (p07) br.cond.dpnt.few	4000000000084AE0 }

l4000000000084A60:
	{ nop.m	0x0; ld4	r14,[r36]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r33,r14; (p06) br.cond.dptk.few	4000000000084A00 }

l4000000000084A80:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dpnt.few	4000000000084BA0 }

l4000000000084A90:
	{ addl	r42,2,r0; nop.m	0x0; adds	r43,0x10,r12 }
	{ adds	r44,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r40; mov	pr,r41,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,4000000000084AC0; nop.i	0x0 }
	{ adds	r12,0x100,r12; nop.m	0x0; br.ret	b0; }

l4000000000084AE0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,delete_job; }
	{ ld4	r14,[r36]; nop.m	0x0; adds	r1,0x0,r40; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r33,r14; (p06) br.cond.dptk.few	4000000000084A00 }

l4000000000084B10:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000084A80 }

l4000000000084B20:
	{ nop.m	0x0; nop.i	0x0; (p08) br.cond.dptk.few	4000000000084A90 }

l4000000000084B30:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000077500; }
	{ adds	r1,0x0,r40; nop.m	0x0; nop.i	0x0 }

l4000000000084B50:
	{ addl	r42,2,r0; nop.m	0x0; adds	r43,0x10,r12 }
	{ adds	r44,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r40; mov	pr,r41,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,4000000000084B80; nop.i	0x0 }
	{ adds	r12,0x100,r12; nop.m	0x0; br.ret	b0 }

l4000000000084BA0:
	{ nop.m	0x0; addl	r14,7444,r1; nop.i	0x0; }
	{ ld8	r42,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r16,0x1C,r37; adds	r15,0x28,r37; nop.i	0x0 }
	{ adds	r14,0x20,r37; adds	r37,0x24,r37; adds	r1,0x0,r40; }
	{ st4	[r0],r16; st4	[r0],r15; nop.i	0x0; }
	{ nop.m	0x0; st4	[r0],r14; nop.i	0x0 }
	{ st4	[r0],r37; nop.m	0x0; br.call.sptk.many	b0,fn4000000000077500; }
	{ nop.m	0x0; adds	r1,0x0,r40; br.cond.sptk.few	4000000000084B50; }
4000000000084C20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000084C30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; nohup_all_jobs: 4000000000084C40
;;   Called from:
;;     40000000000FFC1C (in disown_builtin)
nohup_all_jobs proc
	{ alloc	r34,ar.pfs,0x8,0x0,0x5; adds	r12,0xFFFFFFFFFFFFFF00,r12; nop.b	0x0 }
	{ adds	r35,0x0,r1; nop.m	0x0; mov	r33,b1; }
	{ adds	r37,0x90,r12; mov	r36,LC; br.call.sptk.many	b0,fn400000000001BC20; }
	{ addl	r38,17,r0; nop.m	0x0; adds	r1,0x0,r35 }
	{ adds	r37,0x90,r12; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B400; }
	{ adds	r1,0x0,r35; adds	r37,0x10,r12; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r35; adds	r37,0x0,r0; nop.i	0x0 }
	{ adds	r38,0x90,r12; adds	r39,0x10,r12; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r35; cmp4.eq	p06,p07,0x0,r32; addl	r14,-20676,r1; }
	{ nop.m	0x0; adds	r14,0x1C,r14; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p09,p08,0x0,r14; adds	r15,0xFFFFFFFFFFFFFFFF,r14; (p09) br.cond.dpnt.few	4000000000084DA0; }

l4000000000084D00:
	{ cmp4.lt	p09,p08,0x0,r14; nop.m	0x0; addl	r14,7444,r1 }
	{ addp4	r15,r15,r0; nop.m	0x0; (p08) br.cond.dpnt.few	4000000000084DA0; }

l4000000000084D20:
	{ ld8	r16,[r14]; mov.i	LC,r15; adds	r15,0x8,r16; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000084D40:
	{ ld8	r14,[r16]; adds	r16,0x0,r15; adds	r15,0x8,r15; }
	{ adds	r17,0x18,r14; adds	r18,0x14,r14; cmp.eq	p08,p09,0x0,r14 }
	{ nop.b	0x0; (p08) br.cond.dpnt.few	4000000000084D90; (p07) br.cond.dptk.few	4000000000084DF0; }

l4000000000084D6C:
	{ (p04) cmp.lt	p00,p03,r0,r33; Invalid; Invalid }

l4000000000084D70:
	{ ld4	r14,[r17]; nop.i	0x0; or	r14,0x8,r14; }
	{ st4	[r14],r17; nop.m	0x0; nop.i	0x0 }

l4000000000084D90:
	{ nop.m	0x0; nop.i	0x0; br.cloop.sptk.few	4000000000084D40 }

l4000000000084DA0:
	{ addl	r37,2,r0; nop.m	0x0; adds	r38,0x10,r12 }
	{ adds	r39,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r35; mov.i	ar.pfs,r34; mov.i	LC,r36; }
	{ nop.m	0x0; mov.spnt	b0,r33,4000000000084DD0; nop.i	0x0 }
	{ adds	r12,0x100,r12; nop.m	0x0; br.ret	b0 }

l4000000000084DF0:
	{ nop.m	0x0; ld4	r14,[r18]; nop.i	0x0; }
	{ cmp4.eq	p09,p08,0x1,r14; (p09) br.cond.dpnt.few	4000000000084D70; br.cloop.sptk.few	4000000000084D40 }

l4000000000084E0C:
	{ Invalid; break.i	0x1000; break.i	0x1000 }

l4000000000084E10:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000084DA0; }
4000000000084E20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000084E30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; count_all_jobs: 4000000000084E40
count_all_jobs proc
	{ alloc	r34,ar.pfs,0x8,0x0,0x5; adds	r12,0xFFFFFFFFFFFFFF00,r12; nop.b	0x0 }
	{ adds	r35,0x0,r1; nop.m	0x0; mov	r33,b1; }
	{ adds	r37,0x90,r12; adds	r32,0x0,r0; mov	r36,LC }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BC20; }
	{ addl	r38,17,r0; nop.m	0x0; adds	r1,0x0,r35 }
	{ adds	r37,0x90,r12; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B400; }
	{ adds	r1,0x0,r35; adds	r37,0x10,r12; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r35; adds	r37,0x0,r0; nop.i	0x0 }
	{ adds	r38,0x90,r12; adds	r39,0x10,r12; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r35; addl	r14,-20676,r1; nop.i	0x0; }
	{ nop.m	0x0; adds	r14,0x1C,r14; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.lt	p07,p06,0x0,r14; adds	r15,0xFFFFFFFFFFFFFFFF,r14; addl	r14,7444,r1; }
	{ (p06) adds	r32,0x0,r0; addp4	r15,r15,r0; (p06) br.cond.dpnt.few	4000000000084F90; }

l4000000000084F16:
	{ (p07) chk.a.clr	r15,3FFFFFFFFF088F16; Invalid; br.call.sptk.few	b4,b0 }

l4000000000084F20:
	{ ld8	r16,[r14]; mov.i	LC,r15; adds	r14,0x8,r16; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000084F40:
	{ ld8	r15,[r16]; adds	r16,0x0,r14; adds	r14,0x8,r14; }
	{ adds	r17,0x14,r15; cmp.eq	p06,p07,0x0,r15; (p06) br.cond.dpnt.few	4000000000084F80; }

l4000000000084F60:
	{ nop.m	0x0; ld4	r15,[r17]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x4,r15; nop.i	0x0; (p07) adds	r32,0x1,r32 }

l4000000000084F80:
	{ nop.m	0x0; nop.i	0x0; br.cloop.sptk.few	4000000000084F40 }

l4000000000084F90:
	{ addl	r37,2,r0; nop.m	0x0; adds	r38,0x10,r12 }
	{ adds	r39,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r8,0x0,r32; adds	r1,0x0,r35; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.i	LC,r36; mov.spnt	b0,r33,4000000000084FC0 }
	{ nop.m	0x0; adds	r12,0x100,r12; br.ret	b0; }
4000000000084FE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000084FF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; freeze_jobs_list: 4000000000085000
freeze_jobs_list proc
	{ addl	r15,1,r0; nop.m	0x0; addl	r14,7464,r1; }
	{ st4	[r15],r14; nop.i	0x0; br.ret	b0; }
4000000000085020 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000085030 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; unfreeze_jobs_list: 4000000000085040
;;   Called from:
;;     40000000000F627C (in parse_and_execute_cleanup)
unfreeze_jobs_list proc
	{ nop.m	0x0; addl	r14,7464,r1; nop.i	0x0; }
	{ st4	[r0],r14; nop.i	0x0; br.ret	b0; }
4000000000085060 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000085070 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; set_job_control: 4000000000085080
;;   Called from:
;;     400000000001F0DC (in main)
;;     400000000002037C (in main)
;;     400000000002040C (in main)
;;     40000000000206CC (in main)
;;     400000000002139C (in fn4000000000021300)
;;     40000000000A52BC (in fn40000000000A1400)
set_job_control proc
	{ addl	r14,5868,r1; nop.m	0x0; cmp4.eq	p06,p07,0x0,r32; }
	{ ld4	r8,[r14]; st4	[r32],r14; (p07) addl	r14,7436,r1; }

l40000000000850A0:
	{ cmp4.eq	p08,p09,r32,r8; nop.i	0x0; (p08) br.ret	b0; }

l40000000000850B0:
	{ (p07) st4	[r0],r14; nop.i	0x0; br.ret	b0; }

l40000000000850B6:
	{ break.m	0x4000; (p34) nop; Invalid }

;; without_job_control: 40000000000850C0
;;   Called from:
;;     40000000000505EC (in shell_execve)
without_job_control proc
	{ alloc	r33,ar.pfs,0x4,0x0,0x3; addl	r14,7420,r1; mov	r32,b0 }
	{ nop.m	0x0; adds	r34,0x0,r1; nop.i	0x0; }
	{ st4	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,start_pipeline; }
	{ nop.m	0x0; adds	r1,0x0,r34; nop.i	0x0; }
	{ addl	r35,5880,r1; nop.i	0x0; br.call.sptk.many	b0,sh_closepipe; }
	{ adds	r1,0x0,r34; adds	r35,0x0,r0; br.call.sptk.many	b0,delete_all_jobs; }
	{ adds	r1,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ addl	r14,5868,r1; nop.m	0x0; mov.spnt	b0,r32,4000000000085130; }
	{ st4	[r0],r14; nop.i	0x0; br.ret	b0; }
4000000000085150 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000085160 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000085170 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; end_job_control: 4000000000085180
;;   Called from:
;;     400000000002246C (in exit_shell)
;;     40000000000B4D3C (in termsig_handler)
;;     40000000000B4D3C (in termsig_handler)
;;     40000000000B4EDC (in termsig_handler)
;;     40000000000F842C (in exec_builtin)
end_job_control proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x4; addl	r14,6512,r1; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; addl	r32,5888,r1; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	4000000000085220 }

l40000000000851C0:
	{ ld4	r37,[r32]; nop.m	0x0; adds	r36,0x0,r0; }
	{ cmp4.lt	p06,p07,r37,r0; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000085200; }

l40000000000851E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BDE0; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l4000000000085200:
	{ nop.m	0x0; mov.i	ar.pfs,r34; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r33,4000000000085210; br.ret	b0; }

l4000000000085220:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,terminate_stopped_jobs; }
	{ ld4	r36,[r32]; adds	r1,0x0,r35; addl	r37,1,r0; }
	{ cmp4.lt	p07,p06,r36,r0; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000085200; }

l4000000000085250:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,give_terminal_to; }
	{ nop.m	0x0; adds	r1,0x0,r35; br.cond.sptk.few	40000000000851C0; }
4000000000085270 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; restart_job_control: 4000000000085280
;;   Called from:
;;     40000000000F82BC (in exec_builtin)
restart_job_control proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; addl	r14,5900,r1; mov	r33,b1 }
	{ adds	r35,0x0,r1; ld4	r36,[r14]; adds	r32,0x0,r0; }
	{ cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r36; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000852D0; }

l40000000000852B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C340; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l40000000000852D0:
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000852D0; mov.i	ar.pfs,r34; }
	{ alloc	r2,ar.pfs,0x1,0x0,0x0; nop.i	0x0; br.cond.sptk.many	initialize_job_control; }
40000000000852F0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; set_sigchld_handler: 4000000000085300
;;   Called from:
;;     40000000000505FC (in shell_execve)
;;     400000000009406C (in command_substitute)
;;     400000000009489C (in command_substitute)
;;     40000000000A2A6C (in fn40000000000A1400)
;;     40000000000A526C (in fn40000000000A1400)
set_sigchld_handler proc
	{ alloc	r33,ar.pfs,0x5,0x0,0x3; nop.m	0x0; mov	r32,b0 }
	{ addl	r36,-7644,r1; adds	r34,0x0,r1; addl	r35,17,r0 }
	{ ld8	r36,[r36]; nop.m	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ nop.m	0x0; mov.spnt	b0,r32,4000000000085340; br.ret	b0; }
4000000000085350 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000085360 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000085370 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; close_pgrp_pipe: 4000000000085380
;;   Called from:
;;     40000000000940CC (in command_substitute)
;;     40000000000A2ACC (in fn40000000000A1400)
;;     40000000000AEDEC (in run_debug_trap)
close_pgrp_pipe proc
	{ alloc	r33,ar.pfs,0x4,0x0,0x3; nop.m	0x0; mov	r32,b0 }
	{ adds	r34,0x0,r1; nop.m	0x0; addl	r35,5880,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_closepipe; }
	{ adds	r1,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ nop.m	0x0; mov.spnt	b0,r32,40000000000853C0; br.ret	b0; }
40000000000853D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000853E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000853F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; save_pgrp_pipe: 4000000000085400
;;   Called from:
;;     40000000000AED8C (in run_debug_trap)
save_pgrp_pipe proc
	{ addl	r15,5880,r1; addl	r16,-1,r0; cmp4.eq	p06,p07,0x0,r33; }
	{ adds	r14,0x0,r15; ld4	r17,[r14],4; nop.i	0x0; }
	{ st4	[r32],r4,4; ld4	r17,[r14]; nop.i	0x0; }
	{ st4	[r17],r32; (p07) st4	[r16],r14; nop.i	0x0; }

l400000000008543C:
	{ Invalid; Invalid; add	r0,r32,r0 }

l4000000000085446:
	{ break.m	0x4000; (p34) nop; break.i	0x80000 }
4000000000085450 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000085460 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000085470 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; restore_pgrp_pipe: 4000000000085480
;;   Called from:
;;     40000000000AEDFC (in run_debug_trap)
restore_pgrp_pipe proc
	{ ld4	r15,[r32],4; nop.m	0x0; addl	r14,5880,r1; }
	{ st4	[r14],r4,4; ld4	r15,[r32]; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.ret	b0; }
40000000000854B0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000854C0 00 28 25 0E 80 05 40 02 00 62 00 00 00 00 04 00 .(%...@..b......
40000000000854D0 19 38 00 40 06 39 60 02 04 00 C2 03 D0 02 00 43 .8.@.9`........C
40000000000854E0 0B 70 00 40 00 10 00 00 00 02 00 C0 01 70 50 00 .p.@.........pP.
40000000000854F0 11 38 00 1D 86 39 00 00 00 02 80 03 80 00 00 43 .8...9.........C
4000000000085500 11 38 A8 1C 86 39 E0 08 80 00 42 03 A0 00 00 43 .8...9....B....C
4000000000085510 0B 70 00 1C 00 10 00 00 00 02 00 C0 01 70 50 00 .p...........pP.
4000000000085520 11 00 00 00 01 00 70 00 38 0C 73 03 80 00 00 42 ......p.8.s....B
4000000000085530 11 00 00 00 01 00 70 00 84 0C 73 03 70 00 00 42 ......p...s.p..B
4000000000085540 10 00 00 00 01 00 60 00 8C 0E 72 03 C0 01 00 43 ......`...r....C
4000000000085550 09 70 04 00 00 24 80 08 00 00 48 00 50 02 AA 00 .p...$....H.P...
4000000000085560 10 00 38 46 90 11 00 20 05 80 03 80 08 00 84 00 ..8F... ........
4000000000085570 0B 70 04 40 00 21 E0 00 38 00 20 00 00 00 04 00 .p.@.!..8. .....
4000000000085580 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
4000000000085590 11 00 00 00 01 00 70 00 38 0C F3 03 20 01 00 42 ......p.8... ..B
40000000000855A0 11 38 01 40 00 21 00 00 00 02 00 00 28 A7 03 50 .8.@.!......(..P
40000000000855B0 10 08 00 4C 00 21 60 00 20 0E F3 03 40 00 00 43 ...L.!`. ...@..C
40000000000855C0 08 40 00 00 00 21 00 00 00 02 00 00 00 00 04 00 .@...!..........
40000000000855D0 01 00 00 00 01 00 00 28 01 55 00 00 00 00 04 00 .......(.U......
40000000000855E0 11 00 00 00 01 00 00 20 05 80 03 80 08 00 84 00 ....... ........
40000000000855F0 11 38 01 40 00 21 80 DA 02 00 48 00 D8 1F 0B 50 .8.@.!....H....P
4000000000085600 08 70 04 10 00 21 00 00 00 02 00 20 00 30 01 84 .p...!..... .0..
4000000000085610 19 30 00 10 07 39 00 00 00 02 00 03 B0 FF FF 4B .0...9.........K
4000000000085620 0B 70 00 1C 00 10 00 00 00 02 00 C0 01 70 50 00 .p...........pP.
4000000000085630 11 38 00 1D 86 39 00 00 00 02 80 03 F0 00 00 43 .8...9.........C
4000000000085640 10 00 00 00 01 00 70 50 39 0C 73 03 80 FF FF 4A ......pP9.s....J
4000000000085650 0B 40 08 10 00 21 E0 00 20 00 20 00 00 00 04 00 .@...!.. . .....
4000000000085660 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
4000000000085670 11 00 00 00 01 00 70 E8 3A 0C 73 03 50 FF FF 4A ......p.:.s.P..J
4000000000085680 11 38 00 42 86 39 00 00 00 02 00 03 40 FF FF 4B .8.B.9......@..K
4000000000085690 10 00 00 00 01 00 60 00 8C 0E F2 03 C0 FE FF 4A ......`........J
40000000000856A0 10 00 00 00 01 00 00 00 00 02 00 00 60 00 00 40 ............`..@
40000000000856B0 09 00 00 00 01 00 10 1A 84 58 40 00 00 00 04 00 .........X@.....
40000000000856C0 11 00 00 00 01 00 60 00 84 0E 73 03 30 00 00 42 ......`...s.0..B
40000000000856D0 03 30 00 44 07 39 00 00 00 02 80 C3 11 00 00 90 .0.D.9..........
40000000000856E0 E8 00 38 44 90 11 00 00 00 02 00 00 00 00 04 00 ..8D............
40000000000856F0 10 00 00 00 01 00 70 00 8C 0C 72 03 60 FE FF 4A ......p...r.`..J
4000000000085700 09 40 04 00 00 24 00 00 00 02 00 00 50 02 AA 00 .@...$......P...
4000000000085710 10 00 00 00 01 00 00 20 05 80 03 80 08 00 84 00 ....... ........
4000000000085720 0B 40 08 10 00 21 E0 00 20 00 20 00 00 00 04 00 .@...!.. . .....
4000000000085730 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
4000000000085740 10 00 00 00 01 00 70 E8 3A 0C 73 03 80 FE FF 4A ......p.:.s....J
4000000000085750 09 00 00 00 01 00 10 1A 84 58 40 00 00 00 04 00 .........X@.....
4000000000085760 11 00 00 00 01 00 60 00 84 0E 73 03 E0 FD FF 4A ......`...s....J
4000000000085770 11 30 00 44 07 39 E0 08 00 00 48 03 D0 FD FF 4B .0.D.9....H....K
4000000000085780 10 00 38 44 90 11 60 00 8C 0E F2 03 D0 FD FF 4A ..8D..`........J
4000000000085790 11 00 00 00 01 00 00 00 00 02 00 00 70 FF FF 48 ............p..H
40000000000857A0 09 30 00 44 07 39 00 00 00 02 00 00 01 00 00 84 .0.D.9..........
40000000000857B0 E9 00 00 44 90 11 00 00 00 02 00 E0 00 18 19 E4 ...D............
40000000000857C0 D1 00 00 46 90 11 00 00 00 02 00 00 10 FE FF 48 ...F...........H
40000000000857D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000857E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000857F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000085800 00 40 35 14 80 05 70 02 00 62 00 00 00 00 04 00 .@5...p..b......
4000000000085810 19 48 01 02 00 21 60 00 80 0E 72 03 10 01 00 43 .H...!`...r....C
4000000000085820 0B 70 00 40 00 10 00 00 00 02 00 C0 01 70 50 00 .p.@.........pP.
4000000000085830 10 00 00 00 01 00 60 00 38 0E 73 03 F0 00 00 42 ......`.8.s....B
4000000000085840 0B 70 04 40 00 21 E0 00 38 00 20 00 00 00 04 00 .p.@.!..8. .....
4000000000085850 03 00 00 00 01 00 E0 00 38 28 00 C0 00 70 1C E6 ........8(...p..
4000000000085860 10 00 00 00 01 80 81 08 00 00 48 03 50 00 00 42 ..........H.P..B
4000000000085870 0B 70 08 40 00 21 E0 00 38 00 20 00 00 00 04 00 .p.@.!..8. .....
4000000000085880 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
4000000000085890 11 00 00 00 01 00 60 00 38 0E F3 03 A0 03 00 42 ......`.8......B
40000000000858A0 C9 40 08 00 00 24 00 00 00 02 00 00 00 00 04 00 .@...$..........
40000000000858B0 11 30 81 10 00 20 60 10 88 0E 73 03 90 00 00 43 .0... `...s....C
40000000000858C0 11 00 00 00 01 00 60 10 88 0E E3 03 50 01 00 42 ......`.....P..B
40000000000858D0 11 30 0C 44 87 39 00 00 00 02 00 03 C0 02 00 43 .0.D.9.........C
40000000000858E0 10 00 00 00 01 00 60 20 88 0E 73 03 10 02 00 43 ......` ..s....C
40000000000858F0 08 40 00 40 00 21 00 00 00 02 00 00 00 00 04 00 .@.@.!..........
4000000000085900 01 00 00 00 01 00 00 40 01 55 00 00 00 00 04 00 .......@.U......
4000000000085910 10 00 00 00 01 00 00 38 05 80 03 80 08 00 84 00 .......8........
4000000000085920 09 40 00 00 00 21 00 00 00 02 00 C0 20 10 1D E6 .@...!...... ...
4000000000085930 11 00 00 00 01 00 60 02 21 00 C0 03 90 FF FF 4A ......`.!......J
4000000000085940 08 20 C1 03 3B 24 00 00 00 02 00 E0 60 02 19 D0 . ..;$......`...
4000000000085950 19 18 01 40 00 21 00 00 00 02 80 03 A0 FF FF 4B ...@.!.........K
4000000000085960 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000085970 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000085980 08 60 01 48 50 10 A0 02 84 00 42 60 05 00 01 84 .`.HP.....B`....
4000000000085990 09 28 01 46 00 10 00 00 8C 00 23 00 00 00 04 00 .(.F......#.....
40000000000859A0 03 60 01 48 10 11 50 02 94 28 00 C0 00 60 1D E6 .`.H..P..(...`..
40000000000859B0 09 00 00 00 01 C0 C1 02 01 00 48 00 00 00 04 00 ..........H.....
40000000000859C0 D1 60 01 00 00 21 00 00 00 02 00 00 88 C2 09 50 .`...!.........P
40000000000859D0 11 08 00 52 00 21 60 08 20 0E F3 03 80 02 00 43 ...R.!`. ......C
40000000000859E0 09 00 00 00 01 00 10 28 8D 00 2B 00 00 00 04 00 .......(..+.....
40000000000859F0 10 00 00 00 01 00 70 30 8D 0C 68 03 90 FF FF 4A ......p0..h....J
4000000000085A00 11 00 00 00 01 00 80 00 80 00 42 00 00 FF FF 48 ..........B....H
4000000000085A10 11 00 00 00 01 00 60 08 88 0E F3 03 E0 FE FF 4A ......`........J
4000000000085A20 08 20 C1 03 3B 24 00 00 00 02 00 C0 60 02 1D D0 . ..;$......`...
4000000000085A30 19 18 01 4C 00 21 00 00 00 02 00 03 C0 FE FF 4B ...L.!.........K
4000000000085A40 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000085A50 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000085A60 08 60 01 48 50 10 A0 02 84 00 42 60 05 00 01 84 .`.HP.....B`....
4000000000085A70 09 28 01 46 00 10 00 00 8C 00 23 00 00 00 04 00 .(.F......#.....
4000000000085A80 03 60 01 48 10 11 50 02 94 28 00 C0 00 60 1D E6 .`.H..P..(...`..
4000000000085A90 09 00 00 00 01 C0 C1 02 01 00 48 00 00 00 04 00 ..........H.....
4000000000085AA0 D1 60 01 00 00 21 00 00 00 02 00 00 A8 C1 09 50 .`...!.........P
4000000000085AB0 11 08 00 52 00 21 60 08 20 0E F3 03 A0 01 00 43 ...R.!`. ......C
4000000000085AC0 09 00 00 00 01 00 F0 2F 8D 02 2F 00 00 00 04 00 ......./../.....
4000000000085AD0 10 00 00 00 01 00 70 18 81 0C 68 03 90 FF FF 4A ......p...h....J
4000000000085AE0 11 00 00 00 01 00 80 00 80 00 42 00 20 FE FF 48 ..........B. ..H
4000000000085AF0 08 20 C1 03 3B 24 00 00 00 02 00 E0 60 02 19 D0 . ..;$......`...
4000000000085B00 19 18 01 4C 00 21 00 00 00 02 80 03 F0 FD FF 4B ...L.!.........K
4000000000085B10 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000085B20 09 60 01 48 10 10 B0 02 8C 00 42 40 05 08 01 84 .`.H......B@....
4000000000085B30 0B 30 00 58 87 F9 C1 02 01 00 48 00 00 00 04 00 .0.X......H.....
4000000000085B40 D1 60 01 00 00 21 00 00 00 02 00 00 08 C1 09 50 .`...!.........P
4000000000085B50 11 08 00 52 00 21 60 08 20 0E F3 03 F0 01 00 43 ...R.!`. ......C
4000000000085B60 09 00 00 00 01 00 30 FA 8F 7E 46 00 00 00 04 00 ......0..~F.....
4000000000085B70 10 00 00 00 01 00 70 18 81 0C 68 03 B0 FF FF 4A ......p...h....J
4000000000085B80 11 00 00 00 01 00 80 00 80 00 42 00 80 FD FF 48 ..........B....H
4000000000085B90 08 20 C1 03 3B 24 00 00 00 02 00 E0 60 02 19 D0 . ..;$......`...
4000000000085BA0 19 28 01 40 00 21 00 00 00 02 80 03 50 FD FF 4B .(.@.!......P..K
4000000000085BB0 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000085BC0 09 60 01 48 10 10 B0 02 94 00 42 40 05 08 01 84 .`.H......B@....
4000000000085BD0 0B 30 00 58 87 F9 C1 02 01 00 48 00 00 00 04 00 .0.X......H.....
4000000000085BE0 D1 60 01 00 00 21 00 00 00 02 00 00 68 C0 09 50 .`...!......h..P
4000000000085BF0 11 08 00 52 00 21 60 08 20 0E F3 03 D0 00 00 43 ...R.!`. ......C
4000000000085C00 09 00 00 00 01 00 50 0A 94 00 42 00 00 00 04 00 ......P...B.....
4000000000085C10 10 00 00 00 01 00 70 30 95 0C 68 03 B0 FF FF 4A ......p0..h....J
4000000000085C20 10 00 00 00 01 00 80 00 80 00 42 00 E0 FC FF 48 ..........B....H
4000000000085C30 11 50 01 40 00 21 00 00 00 02 00 00 98 5A F9 58 .P.@.!.......Z.X
4000000000085C40 10 08 00 52 00 21 80 00 20 2C 00 00 70 FC FF 48 ...R.!.. ,..p..H
4000000000085C50 08 00 00 00 01 00 A0 02 8C 00 42 00 00 00 04 00 ..........B.....
4000000000085C60 19 00 94 46 80 11 00 00 00 02 00 00 68 5A F9 58 ...F........hZ.X
4000000000085C70 11 08 00 52 00 21 A0 0A 20 00 42 00 58 30 06 50 ...R.!.. .B.X0.P
4000000000085C80 08 08 00 52 00 21 00 00 00 02 00 40 05 40 00 84 ...R.!.....@.@..
4000000000085C90 19 58 01 46 00 21 00 00 00 02 00 00 F8 54 F9 58 .X.F.!.......T.X
4000000000085CA0 09 08 00 52 00 21 00 00 00 02 00 00 80 02 AA 00 ...R.!..........
4000000000085CB0 11 00 00 00 01 00 00 38 05 80 03 80 08 00 84 00 .......8........
4000000000085CC0 08 18 01 4A 00 10 00 00 00 02 00 40 05 00 01 84 ...J.......@....
4000000000085CD0 19 00 00 4A 80 11 00 00 00 02 00 00 F8 59 F9 58 ...J.........Y.X
4000000000085CE0 08 08 00 52 00 21 00 00 00 02 00 40 15 40 00 84 ...R.!.....@.@..
4000000000085CF0 11 00 00 00 01 00 30 02 8C 28 00 00 D8 2F 06 50 ......0..(.../.P
4000000000085D00 08 08 00 52 00 21 00 00 00 02 00 40 05 40 00 84 ...R.!.....@.@..
4000000000085D10 19 58 01 40 00 21 00 00 00 02 00 00 78 54 F9 58 .X.@.!......xT.X
4000000000085D20 09 08 00 52 00 21 00 18 95 00 23 00 80 02 AA 00 ...R.!....#.....
4000000000085D30 11 00 00 00 01 00 00 38 05 80 03 80 08 00 84 00 .......8........
4000000000085D40 08 20 01 46 00 10 00 00 00 02 00 40 05 00 01 84 . .F.......@....
4000000000085D50 19 00 00 46 80 11 00 00 00 02 00 00 78 59 F9 58 ...F........xY.X
4000000000085D60 08 08 00 52 00 21 00 00 00 02 00 40 15 40 00 84 ...R.!.....@.@..
4000000000085D70 11 00 00 00 01 00 40 02 90 28 00 00 58 2F 06 50 ......@..(..X/.P
4000000000085D80 08 08 00 52 00 21 00 00 00 02 00 40 05 40 00 84 ...R.!.....@.@..
4000000000085D90 19 58 01 40 00 21 00 00 00 02 00 00 F8 53 F9 58 .X.@.!.......S.X
4000000000085DA0 09 08 00 52 00 21 00 20 8D 00 23 00 80 02 AA 00 ...R.!. ..#.....
4000000000085DB0 11 00 00 00 01 00 00 38 05 80 03 80 08 00 84 00 .......8........

;; fn4000000000085DC0: 4000000000085DC0
;;   Called from:
;;     4000000000089D8C (in fn4000000000089000)
;;     400000000008B4BC (in fn400000000008A3C0)
;;     40000000000A5C4C (in fn40000000000A5B80)
;;     40000000000A5C8C (in fn40000000000A5B80)
;;     40000000000A882C (in fn40000000000A7940)
;;     40000000000A888C (in fn40000000000A7940)
;;     40000000000A8D7C (in fn40000000000A7940)
;;     40000000000A8D7C (in fn40000000000A7940)
;;     40000000000A8DEC (in fn40000000000A7940)
;;     40000000000A8F6C (in fn40000000000A7940)
fn4000000000085DC0 proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; addl	r14,9044,r1; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; nop.i	0x0; }
	{ ld4	r36,[r14]; nop.i	0x0; br.call.sptk.many	b0,set_pipestatus_from_exit; }
	{ adds	r1,0x0,r35; adds	r36,0x0,r32; addl	r15,7556,r1 }
	{ addl	r14,8416,r1; st4	[r0],r15; addl	r15,9208,r1 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4	r14,[r14]; st4	[r0],r15; addl	r15,9116,r1 }
	{ cmp4.eq	p07,p06,0x0,r14; nop.m	0x0; nop.i	0x0; }
	{ st4	[r0],r15; (p07) br.cond.dpnt.few	4000000000085E50; br.call.sptk.many	b0,jump_to_top_level; }

l4000000000085E4C:
	{ Invalid; break.m	0x1000; break.i	0x1000 }

l4000000000085E50:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,top_level_cleanup; }
	{ adds	r1,0x0,r35; adds	r36,0x0,r32; br.call.sptk.many	b0,jump_to_top_level; }
	{ nop.m	0x0; break.f	0x0; nop.i	0x0; }

;; fn4000000000085E80: 4000000000085E80
;;   Called from:
;;     40000000000964CC (in pat_subst)
fn4000000000085E80 proc
	{ alloc	r43,ar.pfs,0x11,0x0,0xE; nop.m	0x0; mov	r45,pr }
	{ cmp.eq	p07,p06,0x0,r33; nop.m	0x0; adds	r44,0x0,r1; }
	{ (p07) ld1	r14,[r33]; mov	r42,b2; (p07) adds	r8,0x0,r0; }

;; fn4000000000085EA6: 4000000000085EA6
;;   Called from:
;;     4000000000085E94 (in fn4000000000085DC0)
;;     4000000000085EA0 (in fn4000000000085E80)
;;     4000000000085EA0 (in fn4000000000085E80)
;;     4000000000085EA0 (in fn4000000000085DC0)
fn4000000000085EA6 proc
	{ (p21) chk.a.nc	f0,3FFFFFFFFF09E6A6; (p04) nop; cmp.lt	p00,p00,r0,r32 }

l4000000000085EB0:
	{ nop.m	0x0; sxt1	r37,r14; (p07) br.cond.dpnt.few	4000000000085F60; }

l4000000000085EC0:
	{ ld1	r37,[r33]; nop.m	0x0; sxt1	r37,r37; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r37; (p06) br.cond.dptk.few	40000000000863D0 }

l4000000000085EE0:
	{ adds	r15,0x1,r33; ld1	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r8,1,r0; (p06) br.cond.dptk.few	4000000000085F60 }

l4000000000085F0C:
	{ (p03) cmp.lt	p00,p11,r0,r33; (p33) cmp.lt	p32,p16,r8,r64; Invalid }

l4000000000085F10:
	{ adds	r14,0x2,r33; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r8,2,r0; (p06) br.cond.dptk.few	4000000000085F60 }

l4000000000085F3C:
	{ Invalid; cmp.lt	p00,p00,r32,r0; (p05) epc }

l4000000000085F40:
	{ nop.m	0x0; adds	r46,0x0,r33; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r44; nop.m	0x0; nop.i	0x0; }

l4000000000085F60:
	{ adds	r15,0x1,r33; nop.m	0x0; cmp4.eq	p06,p07,0x2A,r37 }
	{ addl	r39,7664,r1; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000086730; }

l4000000000085F80:
	{ ld1	r14,[r15]; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x28,r14; (p07) br.cond.dpnt.few	40000000000866F0 }

l4000000000085FB0:
	{ nop.m	0x0; sxt4	r14,r8; adds	r46,0x3,r8; }
	{ add	r14,r33,r14; sxt4	r46,r46; adds	r14,0xFFFFFFFFFFFFFFFF,r14; }
	{ nop.m	0x0; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x2A,r14; }
	{ nop.m	0x0; (p06) adds	r37,0x0,r33; (p06) br.cond.dpnt.few	4000000000086120 }

l4000000000085FFC:
	{ Invalid; break.i	0x1000; break.b	0x1000 }

l4000000000086000:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ ld1	r14,[r33]; adds	r1,0x0,r44; adds	r37,0x0,r8; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2A,r14; (p07) br.cond.dpnt.few	4000000000086420 }

l4000000000086040:
	{ adds	r17,0x0,r37; nop.m	0x0; addl	r14,42,r0; }
	{ st1	[r17],r1,1; ld1	r14,[r33]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x0,r14; }
	{ (p06) adds	r15,0x1,r33; (p07) adds	r18,0x0,r33; (p07) br.cond.dpnt.few	40000000000860D0 }

l4000000000086076:
	{ (p09) chk.a.clr	f0,3FFFFFFFFF106286; nop; nop; }

l400000000008607C:
	{ (p03) nop; zxt1	r32,r64; break.i	0x1000 }

l4000000000086080:
	{ adds	r16,0x0,r17; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000860A0:
	{ st1	[r16],r1,1; nop.m	0x0; adds	r18,0x0,r15; }
	{ ld1	r14,[r15],1; adds	r17,0x0,r16; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	40000000000860A0 }

l40000000000860D0:
	{ adds	r18,0xFFFFFFFFFFFFFFFF,r18; ld1	r14,[r18]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2A,r14; (p07) br.cond.dpnt.few	4000000000086470 }

l4000000000086100:
	{ addl	r14,42,r0; st1	[r17],r1,1; nop.i	0x0 }
	{ nop.m	0x0; st1	[r0],r17; nop.i	0x0 }

l4000000000086120:
	{ ld4	r48,[r39]; adds	r46,0x0,r37; adds	r47,0x0,r32; }
	{ cmp4.eq	p06,p07,0x0,r48; (p07) addl	r48,32,r0; nop.i	0x0; }

l400000000008613C:
	{ Invalid; zxt1	r0,r64; break.i	0x1000 }

l4000000000086146:
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ Invalid; nop; (p32) nop.b	0x8009 }
	{ (p23) chk.a.clr	r0,3FFFFFFFFF1063B6; nop; break.i	0x80000 }

l4000000000086170:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r44; nop.m	0x0; nop.i	0x0 }

l4000000000086190:
	{ cmp4.eq	p07,p06,0x1,r38; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000863A0; }

l40000000000861A0:
	{ cmp.eq	p06,p07,0x0,r32; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000864B0; }

l40000000000861B0:
	{ ld1	r14,[r32]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000864B0 }

l40000000000861D0:
	{ adds	r14,0x1,r32; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	40000000000866A0; }

l4000000000086200:
	{ (p06) addl	r37,1,r0; nop.m	0x0; nop.i	0x0; }

l4000000000086206:
	{ break.m	0x4000; nop; (p32) nop }

l4000000000086210:
	{ adds	r46,0x0,r33; nop.m	0x0; adds	r47,0x0,r37 }

l4000000000086212:
	{ (p16) break.m	0x42008; mov	pr,r0,0xFFFFFFFFFFFF8040; (p16) dep	r9,r64,r48,31,7; }
	{ (p20) break.m	0x40009; tbit.z	p32,p00,r0,0x0; Invalid; }
	{ invala; mov	pr,0x804200B; Invalid }
	{ nop; (p32) nop; (p05) nop }

l4000000000086250:
	{ cmp4.eq	p06,p07,0x2,r34; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000865F0; }

l4000000000086260:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r34; (p07) br.cond.dptk.few	40000000000863A0; }

l4000000000086270:
	{ cmp.ltu	p06,p07,r41,r32; sxt4	r14,r8; adds	r38,0x0,r32 }
	{ cmp4.eq	p18,p19,0xFFFFFFFFFFFFFFFF,r8; cmp4.eq	p17,p16,0xFFFFFFFFFFFFFFFF,r8; (p06) br.cond.dpnt.few	40000000000863A0; }

l4000000000086290:
	{ add	r32,r32,r14; nop.m	0x0; nop.i	0x0 }

l40000000000862A0:
	{ adds	r46,0x0,r33; adds	r47,0x0,r38; br.call.sptk.many	b0,match_pattern_char; }
	{ adds	r1,0x0,r44; cmp4.eq	p07,p06,0x0,r8; (p07) br.cond.dptk.few	4000000000086380; }

l40000000000862C0:
	{ cmp.ltu	p06,p07,r41,r32; nop.m	0x0; adds	r37,0x0,r32 }
	{ nop.b	0x0; (p18) br.cond.dpnt.few	4000000000086840; (p06) br.cond.dpnt.few	40000000000863A0; }

l40000000000862DC:
	{ Invalid; cmp.lt	p00,p00,r32,r0; (p16) nop }

l40000000000862E0:
	{ nop.m	0x0; cmp.ltu	p06,p07,r37,r38; (p06) br.cond.dpnt.few	4000000000086380; }

l40000000000862F0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000086300:
	{ ld1	r14,[r37]; nop.m	0x0; adds	r46,0x0,r33 }
	{ st1	[r0],r37; nop.m	0x0; adds	r47,0x0,r38; }
	{ ld4	r48,[r39]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r48; adds	r40,0x0,r14; (p07) addl	r48,32,r0; }

l4000000000086340:
	{ (p06) adds	r48,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,strmatch; }

l4000000000086346:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ (p03) chk.a.clr	f0,3FFFFFFFFFD493D6; nop; (p48) br.call.dpnt.few.clr	b7,b2 }

l4000000000086360:
	{ st1	[r37],r127,-1; nop.i	0x0; (p16) br.cond.dpnt.few	4000000000086380; }

l4000000000086370:
	{ nop.m	0x0; cmp.ltu	p07,p06,r37,r38; (p06) br.cond.dptk.few	4000000000086300; }

l4000000000086380:
	{ adds	r38,0x1,r38; nop.m	0x0; adds	r32,0x1,r32; }
	{ nop.m	0x0; cmp.ltu	p07,p06,r41,r38; (p06) br.cond.dptk.few	40000000000862A0; }

l40000000000863A0:
	{ adds	r8,0x0,r0; nop.m	0x0; nop.i	0x0; }

l40000000000863B0:
	{ nop.m	0x0; mov	pr,r45,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r43; }
	{ nop.m	0x0; mov.spnt	b0,r42,40000000000863C0; br.ret	b0 }

l40000000000863D0:
	{ addl	r39,7664,r1; nop.m	0x0; addl	r46,3,r0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ ld1	r14,[r33]; adds	r1,0x0,r44; adds	r37,0x0,r8; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2A,r14; (p06) br.cond.dptk.few	4000000000086040 }

l4000000000086420:
	{ adds	r15,0x1,r33; ld1	r16,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r16,r16; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x28,r16; (p07) br.cond.dpnt.few	4000000000086790 }

l4000000000086450:
	{ nop.m	0x0; adds	r17,0x0,r37; nop.i	0x0; }
	{ nop.m	0x0; adds	r16,0x0,r17; br.cond.sptk.few	40000000000860A0 }

l4000000000086470:
	{ adds	r14,0xFFFFFFFFFFFFFFFE,r17; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x5C,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000086100; }

l40000000000864A0:
	{ st1	[r0],r17; nop.i	0x0; br.cond.sptk.few	4000000000086120 }

l40000000000864B0:
	{ adds	r37,0x0,r0; nop.m	0x0; adds	r46,0x0,r33; }
	{ adds	r47,0x0,r37; add	r41,r32,r37; br.call.sptk.many	b0,umatchlen; }
	{ nop.m	0x0; adds	r40,0x0,r8; adds	r1,0x0,r44 }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x1,r34; (p07) br.cond.dptk.few	4000000000086250; }

l40000000000864F0:
	{ adds	r46,0x0,r33; nop.m	0x0; adds	r47,0x0,r32 }
	{ cmp4.eq	p17,p16,0xFFFFFFFFFFFFFFFF,r40; nop.m	0x0; br.call.sptk.many	b0,match_pattern_char; }
	{ cmp4.eq	p06,p07,0x0,r8; adds	r1,0x0,r44; (p06) br.cond.dpnt.few	40000000000863A0; }

l4000000000086520:
	{ cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r40; nop.m	0x0; sxt4	r37,r40; }
	{ (p07) add	r37,r32,r37; (p06) adds	r37,0x0,r41; nop.i	0x0; }

l4000000000086536:
	{ Invalid; nop; break.b	0x80000; }

l400000000008653C:
	{ Invalid; cmp.lt	p00,p00,r32,r0; (p16) mov	pr,r104,0xD012 }
	{ (p51) nop; break.i	0x1000; break.i	0x1000 }

l4000000000086550:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000086560:
	{ ld4.a	r48,[r39]; adds	r46,0x0,r33; adds	r47,0x0,r32 }
	{ ld1	r38,[r37]; st1	[r0],r37; nop.i	0x0; }
	{ ld4.c.clr	r48,[r39]; sxt1	r38,r38; cmp4.eq	p06,p07,0x0,r48; }
	{ nop.m	0x0; (p07) addl	r48,32,r0; nop.i	0x0; }

l400000000008659C:
	{ Invalid; zxt1	r0,r64; break.i	0x1000 }

l40000000000865A6:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ (p03) chk.a.clr	f0,3FFFFFFFFFD49636; nop; (p48) br.call.dpnt.many.clr	b7,b1 }

l40000000000865C0:
	{ st1	[r37],r127,-1; nop.i	0x0; (p16) br.cond.dpnt.few	40000000000863A0; }

l40000000000865D0:
	{ nop.m	0x0; cmp.ltu	p07,p06,r37,r32; (p06) br.cond.dptk.few	4000000000086560 }

l40000000000865E0:
	{ nop.m	0x0; adds	r8,0x0,r0; br.cond.sptk.few	40000000000863B0; }

l40000000000865F0:
	{ cmp4.eq	p17,p16,0xFFFFFFFFFFFFFFFF,r8; nop.m	0x0; sxt4	r37,r8; }
	{ sub	r37,r0,r37; add	r37,r41,r37; nop.i	0x0; }
	{ nop.m	0x0; cmp.ltu	p06,p07,r41,r37; (p06) br.cond.dpnt.few	40000000000863A0; }

l4000000000086620:
	{ ld4	r48,[r39]; adds	r47,0x0,r37; adds	r46,0x0,r33; }
	{ cmp4.eq	p06,p07,0x0,r48; (p07) addl	r48,32,r0; nop.i	0x0; }

l400000000008663C:
	{ Invalid; zxt1	r0,r64; break.i	0x1000 }

l4000000000086646:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ add	r0,r0,r1; (p03) nop; cmp.gt	p00,p00,r0,r0 }
	{ nop; nop; break.i	0x80000; }

l400000000008666C:
	{ (p42) nop; nop; zxt1	r32,r64 }

l4000000000086670:
	{ nop.m	0x0; adds	r37,0x1,r37; nop.i	0x0; }
	{ nop.m	0x0; cmp.ltu	p07,p06,r41,r37; (p06) br.cond.dptk.few	4000000000086620 }

l4000000000086690:
	{ nop.m	0x0; adds	r8,0x0,r0; br.cond.sptk.few	40000000000863B0 }

l40000000000866A0:
	{ adds	r14,0x2,r32; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r37,2,r0; (p06) br.cond.dptk.few	4000000000086210 }

l40000000000866CC:
	{ (p26) cmp.lt.unc	p63,p17,r63,r37; zxt1	r0,r64; break.b	0x1000 }

l40000000000866D0:
	{ adds	r46,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r44; sxt4	r37,r8; br.cond.sptk.few	4000000000086210 }

l40000000000866F0:
	{ nop.m	0x0; ld4	r14,[r39]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000085FB0 }

l4000000000086710:
	{ nop.m	0x0; adds	r46,0x3,r8; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r46,r46; br.cond.sptk.few	4000000000086000; }

l4000000000086730:
	{ addl	r39,7664,r1; nop.m	0x0; adds	r46,0x3,r8; }
	{ nop.m	0x0; sxt4	r46,r46; br.call.sptk.many	b0,xmalloc; }
	{ ld1	r14,[r33]; adds	r1,0x0,r44; adds	r37,0x0,r8; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2A,r14; (p06) br.cond.dptk.few	4000000000086040 }

l4000000000086780:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000086420 }

l4000000000086790:
	{ nop.m	0x0; ld4	r16,[r39]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r16; (p06) br.cond.dptk.few	4000000000086450 }

l40000000000867B0:
	{ adds	r17,0x0,r37; nop.m	0x0; addl	r14,42,r0; }
	{ st1	[r17],r1,1; ld1	r14,[r33]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x0,r14; }
	{ (p07) adds	r18,0x0,r33; (p06) adds	r15,0x1,r33; (p06) br.cond.dptk.few	4000000000086080 }

l40000000000867E6:
	{ (p07) chk.a.clr	r1,3FFFFFFFFF1069F6; nop; break.b	0x80000; }

l40000000000867EC:
	{ (p05) invala; break.i	0x1000; break.i	0x1000 }

l40000000000867F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000860D0 }

l4000000000086800:
	{ st1	[r40],r37; addl	r8,1,r0; nop.b	0x0 }
	{ st8	[r38],r35; nop.m	0x0; mov	pr,r45,0xFFFFFFFFFFFFFFFE; }
	{ st8	[r37],r36; nop.m	0x0; mov.i	ar.pfs,r43; }
	{ nop.m	0x0; mov.spnt	b0,r42,4000000000086830; br.ret	b0 }

l4000000000086840:
	{ nop.m	0x0; adds	r37,0x0,r41; nop.i	0x0; }
	{ nop.m	0x0; cmp.ltu	p06,p07,r37,r38; (p07) br.cond.dptk.few	4000000000086300 }

l4000000000086860:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000086380; }

l4000000000086870:
	{ st8	[r37],r35; addl	r8,1,r0; nop.b	0x0 }
	{ st8	[r41],r36; mov	pr,r45,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r43; }
	{ nop.m	0x0; mov.spnt	b0,r42,4000000000086890; br.ret	b0 }

l40000000000868A0:
	{ st1	[r38],r37; addl	r8,1,r0; nop.b	0x0 }
	{ st8	[r32],r35; nop.m	0x0; mov	pr,r45,0xFFFFFFFFFFFFFFFE; }
	{ st8	[r37],r36; nop.m	0x0; mov.i	ar.pfs,r43; }
	{ nop.m	0x0; mov.spnt	b0,r42,40000000000868D0; br.ret	b0; }
40000000000868E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000868F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000086900: 4000000000086900
;;   Called from:
;;     400000000008F22C (in get_word_from_string)
;;     40000000000928EC (in list_string)
fn4000000000086900 proc
	{ alloc	r49,ar.pfs,0x18,0x0,0x14; adds	r12,0xFFFFFFFFFFFFFFD0,r12; nop.b	0x0 }
	{ addl	r44,-9996,r1; ld1	r14,[r35]; mov	r51,pr; }
	{ adds	r45,0x28,r12; adds	r50,0x0,r1; sxt1	r14,r14 }
	{ adds	r43,0x0,r0; adds	r47,0x1,r35; adds	r46,0x20,r12; }
	{ nop.m	0x0; mov	r48,b0; nop.b	0x0 }
	{ st8	[r0],r45; ld8	r44,[r44]; adds	r42,0x30,r12; }
	{ nop.m	0x0; tnat.z	p17,p16,r36; nop.i	0x0 }
	{ cmp4.eq	p07,p06,0x27,r14; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000086EA0 }

l4000000000086980:
	{ nop.m	0x0; ld4	r39,[r34]; tnat.z	p19,p18,r36; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000869A0:
	{ nop.m	0x0; sxt4	r40,r39; add	r37,r32,r40; }
	{ ld1	r38,[r37]; nop.m	0x0; sxt1	r38,r38; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r38; (p07) br.cond.dpnt.few	4000000000086BA0 }

l40000000000869D0:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dptk.few	4000000000086C90; }

l40000000000869E0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x1,r38; (p07) br.cond.dpnt.few	4000000000086CD0 }

l40000000000869F0:
	{ sub	r41,r33,r40; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ cmp.ltu	p07,p06,0x1,r8; adds	r1,0x0,r50; nop.i	0x0 }
	{ adds	r52,0x0,r37; adds	r53,0x0,r41; (p06) br.cond.dpnt.few	4000000000086DD0; }

l4000000000086A20:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AF80; }
	{ nop.m	0x0; adds	r1,0x0,r50; sxt4	r8,r8 }
	{ adds	r52,0x0,r42; adds	r53,0x0,r37; adds	r54,0x0,r41; }
	{ cmp.ltu	p07,p06,0x1,r8; nop.i	0x0; (p06) br.cond.spnt.few	4000000000086DD0; }

l4000000000086A60:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C420; }
	{ nop.m	0x0; sxt4	r8,r8; adds	r1,0x0,r50 }
	{ adds	r52,0x0,r43; adds	r14,0x2,r8; nop.i	0x0; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000086E20; }

l4000000000086AA0:
	{ cmp.eq	p07,p06,0x0,r43; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000086CE0; }

l4000000000086AB0:
	{ ld4	r53,[r42]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BCC0; }
	{ adds	r1,0x0,r50; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dpnt.few	4000000000086BA0 }

l4000000000086AD0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r50; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	4000000000086DC0; }

l4000000000086AF0:
	{ ld1	r14,[r37]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r44; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000086C20; }

l4000000000086B40:
	{ (p06) addl	r14,1,r0; nop.m	0x0; nop.i	0x0; }

l4000000000086B46:
	{ break.m	0x4000; nop; (p48) nop }

l4000000000086B50:
	{ add	r39,r14,r39; nop.m	0x0; sxt4	r40,r39; }
	{ add	r37,r32,r40; ld1	r38,[r37]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r38,r38; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r38; (p06) br.cond.dptk.few	40000000000869D0; }

l4000000000086B90:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000086BA0:
	{ cmp.eq	p06,p07,0x0,r43; adds	r52,0x0,r43; (p06) br.cond.dpnt.few	4000000000086BD0; }

l4000000000086BB0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r50; nop.m	0x0; nop.i	0x0 }

l4000000000086BD0:
	{ adds	r52,0x0,r32; ld4	r53,[r34]; adds	r54,0x0,r39 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,substring; }
	{ adds	r1,0x0,r50; st4	[r39],r34; mov	pr,r51,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r49; mov.spnt	b0,r48,4000000000086C00 }
	{ nop.m	0x0; adds	r12,0x30,r12; br.ret	b0 }

l4000000000086C20:
	{ nop.m	0x0; ld8	r14,[r45]; adds	r52,0x0,r0 }
	{ adds	r53,0x0,r37; sub	r54,r33,r40; adds	r55,0x0,r45; }
	{ st8	[r14],r46; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; nop.m	0x0; adds	r1,0x0,r50; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000086D90; }

l4000000000086C70:
	{ ld8	r14,[r46]; nop.m	0x0; adds	r39,0x1,r39; }
	{ st8	[r14],r45; nop.i	0x0; br.cond.sptk.few	40000000000869A0 }

l4000000000086C90:
	{ cmp4.eq	p07,p06,0x1,r38; (p18) br.cond.dpnt.few	40000000000869F0; (p06) br.cond.dptk.few	40000000000869F0 }

l4000000000086C9C:
	{ (p43) cmp.lt.unc	p63,p11,r63,r37; (p17) cmp.lt	p32,p16,r9,r64; Invalid }

l4000000000086CA0:
	{ adds	r14,0x1,r37; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x7F,r14; (p06) br.cond.dptk.few	40000000000869F0 }

l4000000000086CD0:
	{ nop.m	0x0; adds	r39,0x2,r39; br.cond.sptk.few	40000000000869A0 }

l4000000000086CE0:
	{ adds	r52,0x0,r0; nop.m	0x0; adds	r53,0x0,r35 }
	{ adds	r54,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BEE0; }
	{ cmp.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r8; nop.m	0x0; adds	r1,0x0,r50; }
	{ (p07) adds	r38,0x1,r8; nop.m	0x0; (p06) addl	r52,4,r0; }

l4000000000086D16:
	{ chk.a.nc	r0,3FFFFFFFFF087516; (p26) cmp4.eq.or.andcm	p04,p08,r0,r0; (p01) nop }

l4000000000086D20:
	{ (p07) shladd	r52,r38,0x2,r0; (p06) addl	r38,1,r0; br.call.sptk.many	b0,xmalloc; }

l4000000000086D26:
	{ Invalid; (p32) nop; (p16) nop; }

l4000000000086D2C:
	{ (p61) nop; ldfs	f64,[r64]; (p05) shladd	r0,r2,0x1,r64 }
	{ Invalid; Invalid; Invalid }
	{ (p13) nop; invala; add	r0,r32,r0 }
	{ Invalid; Invalid; Invalid }
	{ (p59) nop; cmp.eq.unc	p00,p16,r12,r64; mov	pr,r66,0xE400 }
	{ Invalid; break.i	0x1000; break.i	0x1000 }

l4000000000086D80:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000086BA0; }

l4000000000086D90:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r14,0x0,r8; (p07) br.cond.spnt.few	4000000000086B50; }

l4000000000086DAC:
	{ (p45) nop; break.i	0x1000; break.b	0x1000 }

l4000000000086DB0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000086DC0:
	{ nop.m	0x0; adds	r39,0x1,r39; br.cond.sptk.few	40000000000869A0; }

l4000000000086DD0:
	{ ld1	r14,[r35]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,r14,r38; (p06) br.cond.dpnt.few	4000000000086E40 }

l4000000000086DF0:
	{ adds	r52,0x0,r35; adds	r53,0x0,r38; br.call.sptk.many	b0,mbschr; }
	{ adds	r1,0x0,r50; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dptk.few	4000000000086AD0 }

l4000000000086E10:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000086BA0 }

l4000000000086E20:
	{ ld1	r14,[r35]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r38; (p06) br.cond.dptk.few	4000000000086DF0; }

l4000000000086E40:
	{ ld1	r14,[r47]; adds	r52,0x0,r35; adds	r53,0x0,r38; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000086BA0; }

l4000000000086E70:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,mbschr; }
	{ adds	r1,0x0,r50; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dptk.few	4000000000086AD0 }

l4000000000086E90:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000086BA0 }

l4000000000086EA0:
	{ ld1	r14,[r47]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000086980 }

l4000000000086EC0:
	{ nop.m	0x0; adds	r41,0x18,r12; nop.i	0x0; }
	{ st8	[r0],r41; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ ld4	r37,[r34]; cmp.ltu	p06,p07,0x1,r8; adds	r1,0x0,r50; }
	{ nop.m	0x0; sxt4	r39,r37; (p07) adds	r42,0x0,r0 }

l4000000000086F00:
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000086F40; }

l4000000000086F10:
	{ nop.m	0x0; sxt4	r39,r37; nop.i	0x0; }
	{ add	r52,r32,r39; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; adds	r1,0x0,r50; add	r42,r8,r39; }

l4000000000086F40:
	{ nop.m	0x0; addl	r40,-9996,r1; nop.i	0x0; }
	{ ld8	r40,[r40]; nop.m	0x0; nop.i	0x0; }

l4000000000086F60:
	{ add	r38,r32,r39; ld1	r14,[r38]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x0,r14; }
	{ cmp4.eq.or.andcm	p07,p06,0x27,r14; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000870C0; }

l4000000000086F90:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r50; nop.m	0x0; cmp.ltu	p07,p06,0x1,r8 }
	{ addl	r17,1,r0; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000870A0; }

l4000000000086FC0:
	{ ld1	r14,[r38]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r40; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x0; (p07) br.cond.dpnt.few	4000000000087030; }

l4000000000087010:
	{ nop.m	0x0; add	r37,r17,r37; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r39,r37; br.cond.sptk.few	4000000000086F60; }

l4000000000087030:
	{ ld8	r14,[r41]; adds	r15,0x10,r12; sub	r54,r42,r39 }
	{ adds	r52,0x0,r0; adds	r53,0x0,r38; adds	r55,0x0,r41; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r15,0x10,r12; adds	r1,0x0,r50; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000087130; }

l4000000000087080:
	{ adds	r37,0x1,r37; ld8	r14,[r15]; nop.i	0x0; }
	{ st8	[r14],r41; sxt4	r39,r37; br.cond.sptk.few	4000000000086F60 }

l40000000000870A0:
	{ nop.m	0x0; adds	r37,0x1,r37; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r39,r37; br.cond.sptk.few	4000000000086F60 }

l40000000000870C0:
	{ adds	r54,0x0,r37; nop.m	0x0; adds	r52,0x0,r32 }
	{ ld4	r53,[r34]; nop.m	0x0; br.call.sptk.many	b0,substring; }
	{ ld1	r14,[r38]; adds	r1,0x0,r50; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; (p07) adds	r37,0x1,r37; nop.i	0x0; }

l40000000000870FC:
	{ nop; zxt2	r63,r79; (p16) cmp.eq.unc	p09,p08,r8,r100 }
	{ Invalid; Invalid; Invalid }
	{ (p24) nop; add	r0,r32,r0; (p01) shladd	r12,r3,0x1,r64 }
	{ invala; cmp.lt	p00,p00,r32,r0; mov	pr,r98,0xE400 }

l4000000000087130:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.sptk.few	40000000000870A0 }

l4000000000087140:
	{ adds	r17,0x0,r8; add	r37,r17,r37; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r39,r37; br.cond.sptk.few	4000000000086F60; }
4000000000087160 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000087170 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000087180 08 60 4D 1E 80 05 C0 00 33 7E 46 C0 05 08 CA 00 .`M.....3~F.....
4000000000087190 09 30 00 40 07 39 00 00 00 02 00 A0 05 08 00 84 .0.@.9..........
40000000000871A0 11 00 00 00 01 00 B0 02 00 62 00 03 C0 00 00 43 .........b.....C
40000000000871B0 0B 70 00 40 00 10 00 00 00 02 00 C0 01 70 50 00 .p.@.........pP.
40000000000871C0 11 30 00 1C 87 39 00 00 00 02 00 03 40 00 00 43 .0...9......@..C
40000000000871D0 11 30 00 42 07 39 00 00 00 02 00 03 30 00 00 43 .0.B.9......0..C
40000000000871E0 0B 70 00 42 00 10 00 00 00 02 00 C0 01 70 50 00 .p.B.........pP.
40000000000871F0 10 00 00 00 01 00 70 00 38 0C 73 03 A0 00 00 43 ......p.8.s....C
4000000000087200 11 78 01 40 00 21 00 00 00 02 00 00 C8 44 F9 58 .x.@.!.......D.X
4000000000087210 11 08 00 5A 00 21 F0 0A 20 00 42 00 B8 1A 06 50 ...Z.!.. .B....P
4000000000087220 08 08 00 5A 00 21 00 00 00 02 00 E0 05 40 00 84 ...Z.!.......@..
4000000000087230 19 80 01 40 00 21 00 00 00 02 00 00 58 3F F9 58 ...@.!......X?.X
4000000000087240 08 08 00 5A 00 21 00 00 00 02 00 00 00 00 04 00 ...Z.!..........
4000000000087250 09 00 01 10 00 21 00 00 00 02 00 00 00 00 04 00 .....!..........
4000000000087260 03 40 00 40 00 21 00 60 01 55 00 00 E0 0A AA 00 .@.@.!.`.U......
4000000000087270 00 00 00 00 01 00 00 58 05 80 03 00 00 00 04 00 .......X........
4000000000087280 19 60 80 18 00 21 00 00 00 02 00 80 08 00 84 00 .`...!..........
4000000000087290 11 40 61 18 00 21 90 02 31 00 42 00 38 3E F9 58 .@a..!..1.B.8>.X
40000000000872A0 08 38 04 10 06 35 10 00 B4 00 42 00 06 00 00 84 .8...5....B.....
40000000000872B0 19 88 01 42 00 21 F0 02 A0 00 42 03 70 01 00 43 ...B.!....B.p..C
40000000000872C0 11 00 00 00 01 00 00 00 00 02 00 00 08 06 0A 50 ...............P
40000000000872D0 08 38 FC 11 06 3B 10 00 B4 00 42 00 06 00 00 84 .8...;....B.....
40000000000872E0 19 88 01 40 00 21 F0 02 A4 00 C2 03 40 01 00 43 ...@.!......@..C
40000000000872F0 11 00 00 00 01 00 00 00 00 02 00 00 D8 05 0A 50 ...............P
4000000000087300 11 38 FC 11 06 3B 10 00 B4 00 C2 03 00 01 00 43 .8...;.........C
4000000000087310 08 30 08 44 87 39 30 02 A4 30 20 00 00 00 04 00 .0.D.90..0 .....
4000000000087320 19 20 01 50 18 10 00 00 00 02 00 03 80 04 00 43 . .P...........C
4000000000087330 11 00 00 00 01 00 60 10 88 0E E3 03 30 01 00 42 ......`.....0..B
4000000000087340 11 30 0C 44 87 39 00 00 00 02 00 03 A0 03 00 43 .0.D.9.........C
4000000000087350 10 00 00 00 01 00 60 20 88 0E 73 03 E0 02 00 43 ......` ..s....C
4000000000087360 09 00 00 00 01 00 E0 40 31 00 42 00 00 00 04 00 .......@1.B.....
4000000000087370 08 00 8C 1C 98 11 00 00 00 02 00 00 00 00 04 00 ................
4000000000087380 11 78 01 46 00 21 00 00 00 02 00 00 68 34 F9 58 .x.F.!......h4.X
4000000000087390 08 00 00 00 01 00 10 00 B4 00 42 00 00 00 04 00 ..........B.....
40000000000873A0 19 78 01 50 18 10 00 00 00 02 00 00 48 34 F9 58 .x.P........H4.X
40000000000873B0 11 08 00 5A 00 21 F0 02 80 00 42 00 18 43 F9 58 ...Z.!....B..C.X
40000000000873C0 11 08 00 5A 00 21 F0 0A 20 00 42 00 08 19 06 50 ...Z.!.. .B....P
40000000000873D0 08 08 00 5A 00 21 00 00 00 02 00 E0 05 40 00 84 ...Z.!.......@..
40000000000873E0 19 80 01 40 00 21 00 00 00 02 00 00 A8 3D F9 58 ...@.!.......=.X
40000000000873F0 10 00 00 00 01 00 10 00 B4 00 42 00 60 FE FF 48 ..........B.`..H
4000000000087400 13 78 01 50 18 10 00 F4 99 7C 2C 00 00 00 00 20 .x.P.....|,.... 
4000000000087410 08 08 00 5A 00 21 00 00 00 02 00 00 00 00 04 00 ...Z.!..........
4000000000087420 08 78 01 40 00 21 00 00 00 02 00 00 06 08 01 84 .x.@.!..........
4000000000087430 19 88 01 44 00 21 00 00 00 02 00 00 D8 E3 FF 58 ...D.!.........X
4000000000087440 11 08 00 5A 00 21 70 40 80 0C F0 03 C0 FD FF 4B ...Z.!p@.......K
4000000000087450 10 00 00 00 01 00 00 02 20 00 42 00 10 FE FF 48 ........ .B....H
4000000000087460 11 00 00 00 01 00 60 08 88 0E F3 03 00 FF FF 4A ......`........J
4000000000087470 00 00 00 00 01 00 60 02 20 2C 00 A0 04 0F EC 90 ......`. ,......
4000000000087480 19 30 20 00 87 30 80 40 00 10 40 03 E0 FE FF 4B .0 ..0.@..@....K
4000000000087490 08 30 99 00 11 20 00 00 00 02 00 00 80 08 AA 00 .0... ..........
40000000000874A0 0B 00 00 00 01 00 00 00 00 02 00 C0 34 32 01 80 ............42..
40000000000874B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000874C0 08 88 01 4A 50 10 F0 02 90 00 42 00 06 18 01 84 ...JP.....B.....
40000000000874D0 09 38 01 4C 10 10 00 00 98 20 23 00 00 00 04 00 .8.L..... #.....
40000000000874E0 0B 88 01 4A 10 11 60 00 C4 0E 73 00 00 00 04 00 ...J..`...s.....
40000000000874F0 09 00 00 00 01 C0 11 03 01 00 48 00 00 00 04 00 ..........H.....
4000000000087500 D1 88 01 00 00 21 00 00 00 02 00 00 08 A8 09 50 .....!.........P
4000000000087510 11 08 00 5A 00 21 60 08 20 0E F3 03 30 04 00 43 ...Z.!`. ...0..C
4000000000087520 10 E0 9F 4C 91 17 00 00 00 02 00 A0 A0 FF FF 48 ...L...........H
4000000000087530 09 70 00 52 18 10 00 00 00 02 00 00 00 00 04 00 .p.R............
4000000000087540 09 38 8C 1C 06 38 50 42 31 00 42 E0 05 70 00 84 .8...8PB1.B..p..
4000000000087550 13 00 8C 4A 98 D1 01 18 FF FF 24 00 98 32 F9 58 ...J......$..2.X
4000000000087560 08 00 00 00 01 00 10 00 B4 00 42 00 00 00 04 00 ..........B.....
4000000000087570 19 78 01 50 18 10 00 00 00 02 00 00 78 32 F9 58 .x.P........x2.X
4000000000087580 11 08 00 5A 00 21 F0 02 80 00 42 00 48 41 F9 58 ...Z.!....B.HA.X
4000000000087590 08 08 00 5A 00 21 00 00 00 02 00 80 04 40 00 84 ...Z.!.......@..
40000000000875A0 19 78 05 10 00 21 00 00 00 02 00 00 28 17 06 50 .x...!......(..P
40000000000875B0 08 70 40 18 00 21 00 02 20 00 42 20 00 68 01 84 .p@..!.. .B .h..
40000000000875C0 09 80 01 4A 00 21 10 03 90 00 42 E0 05 40 00 84 ...J.!....B..@..
40000000000875D0 11 00 00 1C 98 11 20 03 38 00 42 00 D8 31 F9 58 ...... .8.B..1.X
40000000000875E0 09 40 80 10 00 20 10 00 B4 00 42 E0 05 18 01 84 .@... ....B.....
40000000000875F0 11 00 00 10 80 11 00 00 00 02 00 00 F8 31 F9 58 .............1.X
4000000000087600 09 40 00 40 00 21 10 00 B4 00 42 00 C0 02 AA 00 .@.@.!....B.....
4000000000087610 02 00 00 00 01 00 00 70 05 55 00 00 B0 0A 00 07 .......p.U......
4000000000087620 18 00 00 00 01 00 C0 00 31 00 42 80 08 00 84 00 ........1.B.....
4000000000087630 08 30 20 00 87 30 E0 F8 23 7E 46 C0 04 40 58 00 .0 ..0..#~F..@X.
4000000000087640 19 28 C1 03 3B 24 80 40 00 10 40 03 20 FD FF 4B .(..;$.@..@. ..K
4000000000087650 10 00 00 00 01 00 00 40 04 55 00 00 00 00 00 20 .......@.U..... 
4000000000087660 09 38 F8 1D 86 33 00 00 00 02 00 C0 64 1A 45 80 .8...3......d.E.
4000000000087670 03 00 00 00 01 C0 01 40 04 55 00 03 00 08 2A 00 .......@.U....*.
4000000000087680 09 88 01 4A 10 10 00 03 98 00 42 E0 05 20 01 84 ...J......B.. ..
4000000000087690 0B 30 00 62 87 F9 11 03 01 00 48 00 00 00 04 00 .0.b......H.....
40000000000876A0 D1 88 01 00 00 21 00 00 00 02 00 00 68 A6 09 50 .....!......h..P
40000000000876B0 11 08 00 5A 00 21 60 08 20 0E F3 03 10 02 00 43 ...Z.!`. ......C
40000000000876C0 10 00 00 00 01 00 60 E2 9B 7E 46 A0 C0 FF FF 48 ......`..~F....H
40000000000876D0 11 70 00 52 18 10 00 00 00 02 00 00 70 FE FF 48 .p.R........p..H
40000000000876E0 18 28 C1 03 3B 24 60 0A 00 00 48 00 00 00 00 20 .(..;$`...H.... 
40000000000876F0 09 38 01 00 00 21 00 00 00 02 00 00 80 08 AA 00 .8...!..........
4000000000087700 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000087710 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000087720 09 88 01 4A 10 10 70 3A 8D 22 40 E0 05 20 01 84 ...J..p:."@.. ..
4000000000087730 03 30 00 62 87 39 00 03 9C 00 C2 23 06 02 00 90 .0.b.9.....#....
4000000000087740 D1 88 01 00 00 21 00 00 00 02 00 00 C8 A5 09 50 .....!.........P
4000000000087750 08 08 00 5A 00 21 00 00 00 02 00 C0 10 40 1C E6 ...Z.!.......@..
4000000000087760 19 70 04 4C 00 21 00 00 00 02 80 03 A0 01 00 43 .p.L.!.........C
4000000000087770 10 00 00 00 01 00 70 02 98 00 42 A0 20 00 00 40 ......p...B. ..@
4000000000087780 11 70 00 52 18 10 00 00 00 02 00 00 C0 FD FF 48 .p.R...........H
4000000000087790 10 00 00 00 01 00 60 02 38 00 42 00 90 FF FF 48 ......`.8.B....H
40000000000877A0 18 28 C1 03 3B 24 70 0A 00 00 48 00 00 00 00 20 .(..;$p...H.... 
40000000000877B0 09 70 00 00 00 21 00 00 00 02 00 00 80 08 AA 00 .p...!..........
40000000000877C0 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000877D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000877E0 08 88 01 4A 50 10 00 00 00 02 00 C0 E4 18 45 80 ...JP.........E.
40000000000877F0 09 78 01 48 00 21 00 00 00 02 00 00 06 18 01 84 .x.H.!..........
4000000000087800 08 50 01 4C 10 10 00 00 98 20 23 C0 00 88 1D E6 .P.L..... #.....
4000000000087810 09 88 59 00 40 01 00 00 00 02 00 00 00 00 04 00 ..Y.@...........
4000000000087820 E1 88 81 00 00 24 00 00 00 02 00 00 00 00 04 00 .....$..........
4000000000087830 D1 88 01 00 00 21 00 00 00 02 00 00 D8 A4 09 50 .....!.........P
4000000000087840 08 08 00 5A 00 21 60 08 20 0E 73 00 00 00 04 00 ...Z.!`. .s.....
4000000000087850 19 78 04 4E 00 21 E0 00 9C 00 C2 03 40 00 00 43 .x.N.!......@..C
4000000000087860 10 00 A8 4C 90 11 00 00 00 02 00 A0 20 00 00 40 ...L........ ..@
4000000000087870 10 70 00 52 18 10 00 00 00 02 00 00 D0 FC FF 48 .p.R...........H
4000000000087880 10 00 00 00 01 00 70 02 3C 00 42 00 60 FF FF 48 ......p.<.B.`..H
4000000000087890 11 00 A8 4C 90 11 F0 02 98 00 42 00 B8 49 F9 58 ...L......B..I.X
40000000000878A0 08 00 00 00 01 00 10 00 B4 00 42 60 04 40 00 84 ..........B`.@..
40000000000878B0 19 00 00 00 01 00 E0 00 A4 30 20 00 90 FC FF 48 .........0 ....H
40000000000878C0 08 20 01 4C 10 10 00 00 00 02 00 E0 05 18 01 84 . .L............
40000000000878D0 19 00 00 4C 90 11 00 00 00 02 00 00 78 49 F9 58 ...L........xI.X
40000000000878E0 08 08 00 5A 00 21 00 00 00 02 00 60 04 40 00 84 ...Z.!.....`.@..
40000000000878F0 19 00 90 4C 90 11 E0 00 A4 30 20 00 50 FC FF 48 ...L.....0 .P..H
4000000000087900 08 20 01 4E 10 10 00 00 00 02 00 E0 05 18 01 84 . .N............
4000000000087910 19 00 00 4E 90 11 00 00 00 02 00 00 38 49 F9 58 ...N........8I.X
4000000000087920 08 08 00 5A 00 21 00 00 00 02 00 60 04 40 00 84 ...Z.!.....`.@..
4000000000087930 18 00 90 4E 90 11 E0 00 A4 30 20 00 10 FC FF 48 ...N.....0 ....H
4000000000087940 11 00 9C 4C 90 11 F0 02 98 00 42 00 08 49 F9 58 ...L......B..I.X
4000000000087950 08 00 00 00 01 00 10 00 B4 00 42 60 04 40 00 84 ..........B`.@..
4000000000087960 18 00 00 00 01 00 E0 00 A4 30 20 00 E0 FB FF 48 .........0 ....H
4000000000087970 09 00 00 00 01 00 10 03 94 20 20 00 00 00 04 00 .........  .....
4000000000087980 11 00 00 00 01 00 60 00 C4 0E 73 00 A0 FE FF 48 ......`...s....H
4000000000087990 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000879A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000879B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; sub_append_string: 40000000000879C0
;;   Called from:
;;     400000000002774C (in decode_prompt_string)
;;     400000000002783C (in decode_prompt_string)
;;     400000000002796C (in decode_prompt_string)
sub_append_string proc
	{ alloc	r39,ar.pfs,0xC,0x0,0x9; mov	r38,b6; nop.i	0x0 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r40,0x0,r1; (p06) br.cond.dpnt.few	4000000000087B40; }

l40000000000879E0:
	{ nop.m	0x0; ld1	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ (p06) adds	r37,0x0,r0; (p06) adds	r36,0x0,r0; (p06) br.cond.dptk.few	4000000000087AA0 }

l4000000000087A06:
	{ (p18) chk.a.clr	r0,3FFFFFFFFF107A06; nop; (p32) nop; }

l4000000000087A0C:
	{ (p05) cmp.lt	p00,p11,r0,r33; (p17) cmp.lt	p00,p16,r8,r64; Invalid }

l4000000000087A10:
	{ adds	r14,0x1,r32; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ (p06) addl	r37,1,r0; (p06) addl	r36,1,r0; (p06) br.cond.dptk.few	4000000000087AA0 }

l4000000000087A36:
	{ (p18) chk.a.clr	r1,3FFFFFFFFF287A36; nop; (p32) nop; }

l4000000000087A3C:
	{ (p03) cmp.lt	p00,p11,r0,r33; (p33) cmp.lt	p00,p16,r8,r64; (p01) rfi }

l4000000000087A40:
	{ adds	r14,0x2,r32; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ (p06) addl	r37,2,r0; (p06) addl	r36,2,r0; (p06) br.cond.dptk.few	4000000000087AA0 }

l4000000000087A66:
	{ (p18) chk.a.clr	r2,3FFFFFFFFF287A66; nop; (p16) nop; }

l4000000000087A6C:
	{ (p02) nop; zxt1	r0,r64; break.i	0x1000 }

l4000000000087A70:
	{ adds	r41,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r40; adds	r36,0x0,r8; sxt4	r37,r8; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000087AA0:
	{ ld4	r41,[r34]; adds	r42,0x0,r32; adds	r43,0x0,r37 }
	{ ld4	r14,[r35]; sub	r14,r14,r41; nop.i	0x0; }
	{ cmp4.lt	p06,p07,r36,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000087B60; }

l4000000000087AD0:
	{ nop.m	0x0; sxt4	r41,r41; nop.i	0x0; }
	{ add	r41,r33,r41; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ ld4	r14,[r34]; adds	r1,0x0,r40; adds	r41,0x0,r32; }
	{ add	r36,r36,r14; nop.i	0x0; sxt4	r14,r36 }
	{ st4	[r36],r34; add	r14,r33,r14; nop.i	0x0; }
	{ st1	[r0],r14; br.call.sptk.many	b0,fn400000000001A7E0; nop.b	0x0; }
	{ adds	r1,0x0,r40; nop.m	0x0; nop.i	0x0 }

l4000000000087B40:
	{ adds	r8,0x0,r33; nop.m	0x0; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,4000000000087B50; br.ret	b0 }

l4000000000087B60:
	{ add	r14,r36,r41; adds	r41,0x0,r33; extr.u	r15,r14,31,1 }
	{ adds	r42,0x80,r14; nop.m	0x0; extr.u	r15,r15,57,7; }
	{ add	r14,r14,r15; and	r14,0x7F,r14; nop.i	0x0; }
	{ sub	r15,r14,r15; sub	r42,r42,r15; nop.i	0x0; }
	{ st4	[r42],r35; sxt4	r42,r42; br.call.sptk.many	b0,xrealloc; }
	{ ld4	r41,[r34]; adds	r33,0x0,r8; adds	r1,0x0,r40 }
	{ adds	r42,0x0,r32; adds	r43,0x0,r37; sxt4	r41,r41; }
	{ add	r41,r33,r41; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ ld4	r14,[r34]; adds	r1,0x0,r40; adds	r41,0x0,r32; }
	{ add	r36,r36,r14; nop.i	0x0; sxt4	r14,r36 }
	{ st4	[r36],r34; add	r14,r33,r14; nop.i	0x0; }
	{ st1	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r40; br.cond.sptk.few	4000000000087B40; }
4000000000087C30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; extract_array_assignment_list: 4000000000087C40
;;   Called from:
;;     400000000009993C (in fn4000000000099100)
;;     40000000000BF79C (in expand_compound_array_assignment)
extract_array_assignment_list proc
	{ alloc	r36,ar.pfs,0x9,0x0,0x6; nop.m	0x0; mov	r35,b3 }
	{ adds	r37,0x0,r1; nop.m	0x0; adds	r38,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; sxt4	r14,r8; nop.b	0x0 }
	{ adds	r38,0x0,r32; adds	r34,0xFFFFFFFFFFFFFFFF,r8; adds	r8,0x0,r0; }
	{ add	r32,r32,r14; adds	r1,0x0,r37; adds	r40,0x0,r34; }
	{ adds	r32,0xFFFFFFFFFFFFFFFF,r32; ld1	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x29,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000087CF0; }

l4000000000087CD0:
	{ ld4	r39,[r33]; nop.i	0x0; br.call.sptk.many	b0,substring; }
	{ adds	r1,0x0,r37; st4	[r34],r33; nop.i	0x0 }

l4000000000087CF0:
	{ nop.m	0x0; mov.i	ar.pfs,r36; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r35,4000000000087D00; br.ret	b0; }
4000000000087D10 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000087D20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000087D30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; de_backslash: 4000000000087D40
;;   Called from:
;;     40000000000A35AC (in fn40000000000A1400)
de_backslash proc
	{ alloc	r39,ar.pfs,0xE,0x0,0xA; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r38,b6 }
	{ addl	r36,-9996,r1; adds	r40,0x0,r1; adds	r42,0x0,r32; }
	{ adds	r37,0x18,r12; adds	r33,0x0,r0; nop.b	0x0 }
	{ ld8	r36,[r36]; mov	r41,LC; adds	r34,0x0,r0; }
	{ st8	[r0],r37; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; sxt4	r14,r33; adds	r35,0x0,r8 }
	{ nop.m	0x0; adds	r1,0x0,r40; nop.b	0x0; }
	{ nop.m	0x0; cmp.ltu	p06,p07,r14,r35; (p07) br.cond.dpnt.few	4000000000087F90; }

l4000000000087DC0:
	{ add	r14,r32,r14; ld1	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5C,r15; (p07) br.cond.dpnt.few	4000000000087FD0 }

l4000000000087DF0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r40; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	4000000000088040 }

l4000000000087E10:
	{ nop.m	0x0; sxt4	r44,r33; add	r43,r32,r44; }
	{ ld1	r14,[r43]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r36; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000088050; }

l4000000000087E70:
	{ (p06) addl	r18,1,r0; nop.m	0x0; nop.i	0x0; }

l4000000000087E76:
	{ break.m	0x4000; nop; (p32) nop }

l4000000000087E80:
	{ add	r18,r18,r33; nop.m	0x0; nop.i	0x0 }

l4000000000087E82:
	{ (p18) break.m	0x40008; break.m	0x20; Invalid }

l4000000000087E88:
	{ (p16) break.m	0x0; (p16) break.i	0x9000; nop }

l4000000000087E90:
	{ nop.m	0x0; cmp4.lt	p07,p06,r34,r33; nop.i	0x0; }
	{ nop.m	0x0; (p06) adds	r34,0x0,r18; (p06) br.cond.dptk.few	4000000000087F70; }

l4000000000087EAC:
	{ (p06) nop; (p50) nop; Invalid }

l4000000000087EB0:
	{ andcm	r17,0xFFFFFFFFFFFFFFFF,r34; adds	r19,0x1,r33; sxt4	r15,r33 }
	{ adds	r14,0x0,r34; nop.m	0x0; sxt4	r16,r34; }
	{ sub	r17,r17,r33; cmp4.lt	p08,p09,r18,r19; add	r15,r32,r15 }
	{ add	r16,r32,r16; movl	r19,0x803FFFFF80000000; }
	{ add	r17,r17,r18; nop.m	0x0; cmp4.eq	p06,p07,r19,r18 }
	{ nop.b	0x0; (p08) br.cond.spnt.few	4000000000088100; (p06) br.cond.spnt.few	4000000000088100; }

l4000000000087F0C:
	{ (p16) nop; nop; zxt1	r68,r0 }

l4000000000087F10:
	{ nop.m	0x0; add	r17,r17,r34; nop.i	0x0; }
	{ addp4	r17,r17,r0; nop.i	0x0; mov.i	LC,r17; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000087F40:
	{ ld1	r17,[r15],1; nop.m	0x0; adds	r14,0x1,r14; }
	{ st1	[r16],r1,1; nop.i	0x0; br.cloop.sptk.few	4000000000087F40 }

l4000000000087F60:
	{ adds	r34,0x0,r14; nop.m	0x0; nop.i	0x0 }

l4000000000087F70:
	{ adds	r33,0x0,r18; nop.m	0x0; sxt4	r14,r33; }
	{ nop.m	0x0; cmp.ltu	p06,p07,r14,r35; (p06) br.cond.dptk.few	4000000000087DC0 }

l4000000000087F90:
	{ nop.m	0x0; sxt4	r34,r34; adds	r8,0x0,r32; }
	{ add	r32,r32,r34; st1	[r0],r32; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.i	LC,r41; mov.spnt	b0,r38,4000000000087FB0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000087FD0:
	{ adds	r14,0x1,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x60,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x5C,r14; (p06) br.cond.dptk.few	4000000000088010; }

l4000000000088000:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x24,r14; (p06) br.cond.dptk.few	4000000000087DF0 }

l4000000000088010:
	{ adds	r33,0x1,r33; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r40; cmp.ltu	p07,p06,0x1,r8; (p07) br.cond.dptk.few	4000000000087E10; }

l4000000000088030:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000088040:
	{ nop.m	0x0; adds	r18,0x1,r33; br.cond.sptk.few	4000000000087E90 }

l4000000000088050:
	{ nop.m	0x0; ld8	r14,[r37]; adds	r15,0x10,r12 }
	{ adds	r42,0x0,r0; sub	r44,r35,r44; adds	r45,0x0,r37; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; nop.m	0x0; adds	r15,0x10,r12 }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r18,0x1,r33; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000880D0; }

l40000000000880B0:
	{ nop.m	0x0; ld8	r14,[r15]; nop.i	0x0; }
	{ st8	[r14],r37; nop.i	0x0; br.cond.sptk.few	4000000000087E90 }

l40000000000880D0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ (p07) adds	r18,0x0,r8; nop.i	0x0; (p07) br.cond.spnt.few	4000000000087E80; }

l40000000000880E6:
	{ chk.a.nc	f0,3FFFFFFFFF0888E6; nop; break.i	0x80000 }

l40000000000880F0:
	{ nop.m	0x0; adds	r18,0x1,r33; br.cond.sptk.few	4000000000087E90 }

l4000000000088100:
	{ ld1	r17,[r15],1; mov.i	LC,0x0; adds	r14,0x1,r14; }
	{ st1	[r16],r1,1; nop.i	0x0; br.cloop.sptk.few	4000000000087F40 }

l4000000000088120:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000087F60; }
4000000000088130 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; skipsubscript: 4000000000088140
;;   Called from:
;;     400000000003FCEC (in assignment)
;;     400000000003FCEC (in assignment)
;;     400000000007540C (in fn4000000000074880)
;;     4000000000088EBC (in fn4000000000088B40)
;;     40000000000BF97C (in expand_compound_array_assignment)
;;     40000000000BFD8C (in valid_array_reference)
;;     40000000000C00AC (in unbind_array_element)
;;     40000000000C06CC (in assign_compound_array_list)
;;     40000000000C0E9C (in array_variable_name)
skipsubscript proc
	{ alloc	r45,ar.pfs,0x16,0x0,0x10; adds	r12,0xFFFFFFFFFFFFFFC0,r12; mov	r47,pr }
	{ adds	r35,0x1,r33; addl	r41,7548,r1; sxt4	r33,r33; }
	{ adds	r39,0x38,r12; adds	r46,0x0,r1; nop.b	0x0 }
	{ add	r48,r32,r33; mov	r44,b4; addl	r43,1,r0; }
	{ st8	[r0],r39; adds	r40,0x0,r0; tnat.z	p17,p16,r34 }
	{ adds	r38,0x0,r0; sxt4	r37,r35; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r46; addl	r14,1,r0; add	r33,r8,r33; }
	{ nop.m	0x0; addl	r42,-9996,r1; nop.i	0x0 }
	{ st4	[r14],r41; ld8	r42,[r42]; nop.i	0x0 }

l40000000000881D0:
	{ add	r36,r32,r37; ld1	r15,[r36]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r15; adds	r14,0x0,r15; (p07) br.cond.dpnt.few	4000000000088630; }

l4000000000088200:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r38; (p06) br.cond.dptk.few	40000000000882B0 }

l4000000000088210:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r46; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	40000000000884C0; }

l4000000000088230:
	{ ld1	r14,[r36]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r42; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000088520; }

l4000000000088280:
	{ (p06) addl	r14,1,r0; nop.m	0x0; nop.i	0x0; }

l4000000000088286:
	{ break.m	0x4000; nop; (p48) nop }

l4000000000088290:
	{ add	r35,r14,r35; nop.m	0x0; adds	r38,0x0,r0; }
	{ nop.m	0x0; sxt4	r37,r35; br.cond.sptk.few	40000000000881D0 }

l40000000000882B0:
	{ cmp4.eq	p07,p06,0x5C,r14; (p07) adds	r35,0x1,r35; (p07) addl	r38,1,r0; }

l40000000000882BC:
	{ Invalid; Invalid; Invalid }

l40000000000882C0:
	{ nop.m	0x0; sxt4	r37,r35; (p07) br.cond.dpnt.few	40000000000881D0; }

l40000000000882D0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r40; (p06) br.cond.dptk.few	40000000000883A0; }

l40000000000882E0:
	{ cmp4.eq	p07,p06,0x60,r14; (p06) addl	r14,1,r0; nop.i	0x0; }

l40000000000882EC:
	{ nop; cmp4.eq.and	p00,p32,r32,r0; zxt1	r0,r64 }

l40000000000882FC:
	{ Invalid; zxt1	r64,r64; break.i	0x1000 }
	{ (p46) nop; cmp.eq.unc	p00,p16,r11,r64; (p16) mov	pr,r66,0xD400 }
	{ (p15) cmp.lt	p00,p11,r64,r33; Invalid; Invalid }

l4000000000088320:
	{ ld1	r14,[r36]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r42; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x0; (p07) br.cond.dpnt.few	4000000000088590 }

l4000000000088370:
	{ addl	r14,1,r0; nop.m	0x0; nop.i	0x0; }

l4000000000088380:
	{ nop.m	0x0; add	r35,r14,r35; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r37,r35; br.cond.sptk.few	40000000000881D0 }

l40000000000883A0:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dptk.few	4000000000088600 }

l40000000000883B0:
	{ cmp4.eq	p07,p06,0x60,r14; cmp4.eq	p08,p09,0x27,r14; (p07) adds	r35,0x1,r35 }

l40000000000883C0:
	{ (p07) addl	r40,1,r0; (p08) addl	r15,1,r0; sxt4	r37,r35 }

l40000000000883C6:
	{ Invalid; brp.dptk	40000000000873C6; (p50) nop.b	0x3 }

l40000000000883CC:
	{ cmp.eq	p35,p57,0x16,r0; nop }

l40000000000883D6:
	{ chk.a.nc	f0,3FFFFFFFFF088BD6; nop; (p48) nop }

l40000000000883E0:
	{ cmp4.eq	p07,p06,0x5B,r14; (p07) adds	r35,0x1,r35; (p07) adds	r43,0x1,r43; }

l40000000000883EC:
	{ Invalid; Invalid; Invalid }

l40000000000883F0:
	{ nop.m	0x0; sxt4	r37,r35; (p07) br.cond.dpnt.few	40000000000881D0; }

l4000000000088400:
	{ cmp4.eq	p06,p07,0x5D,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000088610; }

l4000000000088410:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x22,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp.ne.or.andcm	p06,p07,0x0,r15; (p07) br.cond.dptk.few	40000000000888B0; }

l4000000000088430:
	{ cmp4.eq	p06,p07,0x0,r15; adds	r48,0x0,r32; adds	r49,0x0,r33; }
	{ (p07) adds	r35,0x1,r35; nop.m	0x0; (p07) adds	r14,0x18,r12; }

l4000000000088446:
	{ chk.a.nc	f0,3FFFFFFFFF088C46; (p07) cmp.eq.or	p24,p02,r12,r0; (p01) nop }

l4000000000088450:
	{ (p07) st8	[r0],r14; nop.m	0x0; adds	r50,0x1,r35 }

l4000000000088456:
	{ break.m	0x4000; (p25) nop; cmp.gt	p00,p00,r0,r0 }
	{ Invalid; (p32) nop; break.i	0x80000; }

l400000000008846C:
	{ (p11) nop; nop; nop }
	{ invala; break.x	0x8000016100 }
	{ (p42) nop; cmp.lt	p00,p00,r32,r0; nop }

l4000000000088490:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r14,0x0,r8; (p07) br.cond.spnt.few	4000000000088290; }

l40000000000884AC:
	{ (p47) nop; break.i	0x1000; break.b	0x1000 }

l40000000000884B0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000884C0:
	{ adds	r35,0x1,r35; nop.m	0x0; adds	r38,0x0,r0; }
	{ nop.m	0x0; sxt4	r37,r35; br.cond.sptk.few	40000000000881D0 }

l40000000000884E0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r14,0x0,r8; (p07) br.cond.spnt.few	4000000000088380; }

l40000000000884FC:
	{ (p52) nop; nop; (p20) epc }

l4000000000088500:
	{ nop.m	0x0; adds	r35,0x1,r35; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r37,r35; br.cond.sptk.few	40000000000881D0; }

l4000000000088520:
	{ ld8	r14,[r39]; adds	r15,0x30,r12; sub	r50,r33,r37 }
	{ adds	r48,0x0,r0; adds	r49,0x0,r36; adds	r51,0x0,r39; }
	{ st8	[r14],r15; adds	r38,0x0,r0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r16,0x30,r12; adds	r1,0x0,r46; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000088490; }

l4000000000088570:
	{ ld8	r14,[r16]; nop.m	0x0; adds	r35,0x1,r35; }
	{ st8	[r14],r39; sxt4	r37,r35; br.cond.sptk.few	40000000000881D0; }

l4000000000088590:
	{ ld8	r14,[r39]; adds	r15,0x28,r12; sub	r50,r33,r37 }
	{ adds	r48,0x0,r0; adds	r49,0x0,r36; adds	r51,0x0,r39; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r16,0x28,r12; adds	r1,0x0,r46; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000884E0; }

l40000000000885E0:
	{ ld8	r14,[r16]; nop.m	0x0; adds	r35,0x1,r35; }
	{ st8	[r14],r39; sxt4	r37,r35; br.cond.sptk.few	40000000000881D0 }

l4000000000088600:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x5D,r14; (p07) br.cond.dptk.few	40000000000887D0 }

l4000000000088610:
	{ nop.m	0x0; adds	r43,0xFFFFFFFFFFFFFFFF,r43; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r43; (p07) br.cond.dptk.few	4000000000088500; }

l4000000000088630:
	{ adds	r8,0x0,r35; st4	[r0],r41; mov	pr,r47,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r45; mov.spnt	b0,r44,4000000000088640 }
	{ nop.m	0x0; adds	r12,0x40,r12; br.ret	b0; }

l4000000000088660:
	{ adds	r15,0x18,r12; adds	r16,0x10,r12; nop.i	0x0 }
	{ adds	r48,0x0,r0; adds	r49,0x0,r36; sub	r50,r33,r37; }
	{ ld8	r14,[r15]; nop.m	0x0; adds	r51,0x0,r15; }
	{ st8	[r14],r16; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; nop.m	0x0; adds	r15,0x10,r12 }
	{ adds	r1,0x0,r46; nop.m	0x0; adds	r16,0x18,r12; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000088AF0; }

l40000000000886D0:
	{ ld8	r14,[r15]; nop.m	0x0; adds	r35,0x1,r35; }
	{ st8	[r14],r16; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000088700:
	{ nop.m	0x0; sxt4	r37,r35; add	r36,r32,r37; }
	{ nop.m	0x0; ld1	r14,[r36]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x0,r14; }
	{ cmp4.eq.or.andcm	p07,p06,0x27,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000088A20; }

l4000000000088740:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r46; nop.m	0x0; cmp.ltu	p07,p06,0x1,r8 }
	{ addl	r17,1,r0; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000088A10; }

l4000000000088770:
	{ ld1	r14,[r36]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r42; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x0; (p07) br.cond.dpnt.few	4000000000088660; }

l40000000000887C0:
	{ nop.m	0x0; add	r35,r17,r35; br.cond.sptk.few	4000000000088700 }

l40000000000887D0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r46; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	4000000000088500; }

l40000000000887F0:
	{ ld1	r14,[r36]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r42; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x0; (p06) br.cond.dptk.few	4000000000088370 }

l4000000000088840:
	{ ld8	r14,[r39]; adds	r15,0x20,r12; sub	r50,r33,r37 }
	{ adds	r48,0x0,r0; adds	r49,0x0,r36; adds	r51,0x0,r39; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r16,0x20,r12; adds	r1,0x0,r46; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000884E0; }

l4000000000088890:
	{ ld8	r14,[r16]; nop.m	0x0; adds	r35,0x1,r35; }
	{ st8	[r14],r39; sxt4	r37,r35; br.cond.sptk.few	40000000000881D0 }

l40000000000888B0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x24,r14; (p06) br.cond.dptk.few	40000000000887D0 }

l40000000000888C0:
	{ adds	r14,0x1,r36; ld1	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ cmp4.eq	p08,p09,0x28,r15; cmp4.eq	p06,p07,0x7B,r15; (p08) addl	r14,1,r0; }

l40000000000888F0:
	{ nop.m	0x0; (p09) adds	r14,0x0,r0; nop.i	0x0; }

l40000000000888FC:
	{ cmp.eq	p00,p16,r1,r0; (p01) cmp.lt.unc	p00,p16,r3,r64; (p08) mov	pr,r99,0xE580 }
	{ (p54) ldf8	f127,[r37]; zxt1	r96,r64; (p02) epc }

l4000000000088910:
	{ adds	r35,0x2,r35; adds	r16,0x40,r12; adds	r48,0x0,r32 }
	{ adds	r49,0x40,r12; adds	r50,0x0,r0; addl	r51,1,r0; }
	{ nop.m	0x0; sxt4	r14,r35; nop.i	0x0 }
	{ st4	[r35],r16; add	r14,r32,r14; nop.i	0x0; }
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000088630; }

l4000000000088970:
	{ cmp4.eq	p06,p07,0x0,r15; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000088A50; }

l4000000000088980:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000089000; }
	{ adds	r14,0x40,r12; nop.m	0x0; adds	r1,0x0,r46; }
	{ ld4	r35,[r14]; nop.m	0x0; sxt4	r14,r35; }
	{ add	r14,r32,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	4000000000088500; }

l40000000000889E0:
	{ adds	r8,0x0,r35; st4	[r0],r41; mov	pr,r47,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r45; mov.spnt	b0,r44,40000000000889F0 }
	{ nop.m	0x0; adds	r12,0x40,r12; br.ret	b0 }

l4000000000088A10:
	{ nop.m	0x0; adds	r35,0x1,r35; br.cond.sptk.few	4000000000088700 }

l4000000000088A20:
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000881D0; }

l4000000000088A30:
	{ nop.m	0x0; adds	r35,0x1,r35; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r37,r35; br.cond.sptk.few	40000000000881D0 }

l4000000000088A50:
	{ addl	r50,-6844,r1; nop.m	0x0; addl	r51,-6836,r1 }
	{ addl	r52,-6828,r1; nop.m	0x0; addl	r53,9,r0; }
	{ ld8	r50,[r50]; ld8	r51,[r51]; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,fn400000000008A3C0; }
	{ adds	r14,0x40,r12; nop.m	0x0; adds	r1,0x0,r46; }
	{ ld4	r35,[r14]; nop.m	0x0; sxt4	r14,r35; }
	{ add	r14,r32,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000889E0 }

l4000000000088AE0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000088500; }

l4000000000088AF0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.sptk.few	4000000000088A10 }

l4000000000088B00:
	{ nop.m	0x0; adds	r17,0x0,r8; nop.i	0x0; }
	{ nop.m	0x0; add	r35,r17,r35; br.cond.sptk.few	4000000000088700; }
4000000000088B20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000088B30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000088B40: 4000000000088B40
;;   Called from:
;;     40000000000899FC (in fn4000000000089000)
;;     400000000008B35C (in fn400000000008A3C0)
;;     40000000000A250C (in fn40000000000A1400)
fn4000000000088B40 proc
	{ alloc	r43,ar.pfs,0x12,0x0,0xE; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r45,pr }
	{ adds	r44,0x0,r1; adds	r39,0x18,r12; mov	r42,b2; }
	{ st8	[r0],r39; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ ld4	r36,[r33]; cmp.ltu	p06,p07,0x1,r8; adds	r1,0x0,r44; }
	{ nop.m	0x0; sxt4	r37,r36; (p07) adds	r40,0x0,r0 }

l4000000000088B90:
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000088BD0; }

l4000000000088BA0:
	{ nop.m	0x0; sxt4	r37,r36; nop.i	0x0; }
	{ add	r46,r32,r37; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; adds	r1,0x0,r44; add	r40,r8,r37; }

l4000000000088BD0:
	{ nop.m	0x0; addl	r38,-9996,r1; tnat.z	p16,p17,r35 }
	{ adds	r41,0x1,r34; ld8	r38,[r38]; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000088C00:
	{ add	r14,r32,r37; ld1	r47,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r47,r47; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r47; (p07) br.cond.dpnt.few	4000000000088D60; }

l4000000000088C30:
	{ cmp4.eq	p07,p06,0x5C,r47; (p07) br.cond.dpnt.few	4000000000088F40; (p16) br.cond.dptk.few	4000000000088C50; }

l4000000000088C3C:
	{ (p01) invala; cmp.eq	p00,p00,r32,r0; (p48) mov	pr,r75,0xE6EC }

l4000000000088C40:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5B,r47; (p07) br.cond.dpnt.few	4000000000088EA0 }

l4000000000088C50:
	{ ld1	r14,[r34]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r47; (p07) br.cond.dpnt.few	4000000000088E20 }

l4000000000088C70:
	{ adds	r46,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,mbschr; }
	{ adds	r1,0x0,r44; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dpnt.few	4000000000088E40 }

l4000000000088C90:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r44; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	4000000000088F20 }

l4000000000088CB0:
	{ nop.m	0x0; sxt4	r48,r36; add	r47,r32,r48; }
	{ ld1	r14,[r47]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r38; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000088DB0; }

l4000000000088D10:
	{ (p06) addl	r14,1,r0; nop.m	0x0; nop.i	0x0; }

l4000000000088D16:
	{ break.m	0x4000; nop; nop }

l4000000000088D20:
	{ add	r36,r14,r36; nop.m	0x0; sxt4	r37,r36; }
	{ add	r14,r32,r37; ld1	r47,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r47,r47; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r47; (p06) br.cond.dptk.few	4000000000088C30; }

l4000000000088D60:
	{ nop.m	0x0; tbit.z	p07,p06,r35,0x2; (p07) br.cond.dptk.few	4000000000088E40; }

l4000000000088D70:
	{ nop.m	0x0; (p06) st4	[r36],r33; (p06) addl	r8,7552,r1 }

l4000000000088D7C:
	{ nop.m	0x21D81; cmp.eq	p00,p00,r32,r0; (p31) nop.i	0xDFE0B; }

l4000000000088D80:
	{ nop.m	0x0; mov	pr,r45,0xFFFFFFFFFFFFFFFE; nop.i	0x0; }
	{ nop.m	0x0; mov.i	ar.pfs,r43; mov.spnt	b0,r42,4000000000088D90 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l4000000000088DB0:
	{ nop.m	0x0; ld8	r14,[r39]; adds	r15,0x10,r12 }
	{ adds	r46,0x0,r0; sub	r48,r40,r48; adds	r49,0x0,r39; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r15,0x10,r12; adds	r1,0x0,r44; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000088FC0; }

l4000000000088E00:
	{ adds	r36,0x1,r36; ld8	r14,[r15]; nop.i	0x0; }
	{ st8	[r14],r39; sxt4	r37,r36; br.cond.sptk.few	4000000000088C00 }

l4000000000088E20:
	{ ld1	r14,[r41]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	4000000000088C70; }

l4000000000088E40:
	{ nop.m	0x0; tbit.z	p07,p06,r35,0x0; adds	r8,0x0,r0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000088F80; }

l4000000000088E60:
	{ st4	[r36],r33; nop.m	0x0; nop.i	0x0 }

l4000000000088E70:
	{ nop.m	0x0; mov	pr,r45,0xFFFFFFFFFFFFFFFE; nop.i	0x0; }
	{ nop.m	0x0; mov.i	ar.pfs,r43; mov.spnt	b0,r42,4000000000088E80 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l4000000000088EA0:
	{ adds	r47,0x0,r36; nop.m	0x0; adds	r46,0x0,r32 }
	{ adds	r48,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,skipsubscript; }
	{ nop.m	0x0; sxt4	r14,r8; adds	r1,0x0,r44; }
	{ add	r14,r32,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x5D,r14; }
	{ (p06) adds	r36,0x0,r8; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }

l4000000000088EF6:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ (p03) chk.a.clr	f1,3FFFFFFFFFB0BF86; nop; break.b	0x80000 }

l4000000000088F10:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000088F20:
	{ nop.m	0x0; adds	r36,0x1,r36; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r37,r36; br.cond.sptk.few	4000000000088C00 }

l4000000000088F40:
	{ adds	r14,0x1,r14; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000088D60; }

l4000000000088F70:
	{ nop.m	0x0; adds	r36,0x1,r36; br.cond.sptk.few	4000000000088C90; }

l4000000000088F80:
	{ adds	r46,0x0,r32; ld4	r47,[r33]; adds	r48,0x0,r36 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,substring; }
	{ nop.m	0x0; adds	r1,0x0,r44; nop.i	0x0 }
	{ st4	[r36],r33; nop.m	0x0; br.cond.sptk.few	4000000000088E70 }

l4000000000088FC0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ (p07) adds	r14,0x0,r8; nop.i	0x0; (p07) br.cond.spnt.few	4000000000088D20; }

l4000000000088FD6:
	{ chk.a.nc	f0,3FFFFFFFFF0897D6; nop; break.i	0x80000 }

l4000000000088FE0:
	{ nop.m	0x0; adds	r36,0x1,r36; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r37,r36; br.cond.sptk.few	4000000000088C00; }

;; fn4000000000089000: 4000000000089000
;;   Called from:
;;     400000000008898C (in skipsubscript)
;;     400000000008A33C (in fn4000000000089DC0)
;;     400000000008BDDC (in fn400000000008B740)
;;     400000000008CA5C (in skip_to_delim)
fn4000000000089000 proc
	{ alloc	r53,ar.pfs,0x1C,0x0,0x18; adds	r12,0xFFFFFFFFFFFFFFC0,r12; mov	r55,pr }
	{ ld4	r36,[r33]; adds	r54,0x0,r1; and	r34,0x3,r34; }
	{ adds	r43,0x38,r12; mov	r52,b4; sxt4	r45,r36 }
	{ cmp4.eq	p16,p17,0x0,r34; nop.m	0x0; add	r56,r32,r45 }
	{ nop.m	0x0; st8	[r0],r43; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; tbit.z	p06,p07,r35,0x9; adds	r1,0x0,r54 }
	{ add	r45,r8,r45; (p06) addl	r44,1,r0; nop.i	0x0; }

l400000000008906C:
	{ invala; nop; zxt4	r1,r0 }

l400000000008907C:
	{ Invalid; cmp.lt	p00,p00,r32,r0; nop }

l4000000000089080:
	{ nop.m	0x0; tbit.z	p06,p07,r35,0x8; (p07) addl	r44,64,r0 }

l4000000000089090:
	{ addl	r40,-9996,r1; addl	r48,6456,r1; addl	r49,6044,r1 }
	{ addl	r42,1,r0; adds	r39,0x0,r0; adds	r46,0x40,r12; }
	{ ld8	r40,[r40]; adds	r41,0x18,r12; or	r50,0x1,r35 }
	{ adds	r47,0x30,r12; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }

l40000000000890E0:
	{ nop.m	0x0; sxt4	r38,r36; add	r37,r32,r38; }
	{ nop.m	0x0; ld1	r15,[r37]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; adds	r14,0x0,r15 }
	{ adds	r51,0x0,r15; cmp4.eq	p07,p06,0x0,r15; (p07) br.cond.dpnt.few	4000000000089380; }

l4000000000089120:
	{ cmp4.eq	p06,p07,0x0,r39; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000895B0; }

l4000000000089130:
	{ cmp4.eq	p07,p06,0x5C,r14; cmp4.eq.or.andcm	p07,p06,0x1,r14; nop.i	0x0; }
	{ (p07) adds	r36,0x1,r36; (p07) addl	r39,1,r0; (p07) br.cond.dptk.few	40000000000890E0 }

l4000000000089146:
	{ (p19) chk.a.clr	f1,3FFFFFFFFF289146; nop; break.b	0x80000; }

l400000000008914C:
	{ (p61) nop; nop; (p01) cmp.eq.unc	p09,p28,r3,r98 }

l4000000000089150:
	{ nop.m	0x0; cmp4.eq	p09,p08,0x24,r14; cmp4.eq	p07,p06,0x7D,r51 }
	{ nop.b	0x0; (p09) br.cond.dpnt.few	40000000000893D0; (p07) br.cond.dpnt.few	4000000000089410; }

l400000000008916C:
	{ (p21) cmp.eq	p00,p19,r64,r33; mov	pr,r76,0xE6F0; (p32) nop }

l4000000000089170:
	{ cmp4.eq	p07,p06,0x60,r51; (p07) br.cond.dpnt.few	40000000000899D0; (p09) br.cond.dpnt.few	4000000000089480; }

l400000000008917C:
	{ (p24) cmp.eq	p00,p17,r64,r33; czx1.r	r104,r97; br.cond	b0 }

l4000000000089180:
	{ cmp4.eq	p07,p06,0x22,r51; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000089A20; }

l4000000000089190:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x27,r51; (p06) br.cond.dptk.few	40000000000896F0 }

l40000000000891A0:
	{ nop.m	0x0; ld4	r14,[r48]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000089200; }

l40000000000891C0:
	{ nop.m	0x0; ld4	r14,[r49]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,0x29,r14; (p06) br.cond.dptk.few	4000000000089200; }

l40000000000891E0:
	{ cmp4.eq	p06,p07,0x40,r44; (p06) br.cond.dpnt.few	4000000000089200; (p17) br.cond.dpnt.few	4000000000089B80; }

l40000000000891EC:
	{ (p13) nop; break.i	0x1000; break.i	0x1000 }

l40000000000891F0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000089200:
	{ adds	r36,0x1,r36; st8	[r0],r41; nop.i	0x0; }
	{ st4	[r36],r46; nop.m	0x0; nop.i	0x0; }

l4000000000089220:
	{ nop.m	0x0; sxt4	r38,r36; add	r37,r32,r38; }
	{ nop.m	0x0; ld1	r14,[r37]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x0,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x27,r14; (p07) br.cond.dpnt.few	4000000000089320 }

l4000000000089260:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r54; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	40000000000895A0; }

l4000000000089280:
	{ ld1	r14,[r37]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r40; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000089500; }

l40000000000892D0:
	{ (p06) addl	r14,1,r0; nop.m	0x0; nop.i	0x0; }

l40000000000892D6:
	{ break.m	0x4000; nop; nop }

l40000000000892E0:
	{ add	r36,r14,r36; nop.m	0x0; sxt4	r38,r36; }
	{ add	r37,r32,r38; ld1	r14,[r37]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x0,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x27,r14; (p06) br.cond.dptk.few	4000000000089260; }

l4000000000089320:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	40000000000890E0 }

l4000000000089330:
	{ adds	r36,0x1,r36; nop.m	0x0; nop.i	0x0; }

l4000000000089340:
	{ nop.m	0x0; sxt4	r38,r36; add	r37,r32,r38; }
	{ nop.m	0x0; ld1	r15,[r37]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; adds	r14,0x0,r15 }
	{ adds	r51,0x0,r15; cmp4.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	4000000000089120; }

l4000000000089380:
	{ addl	r14,7548,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.spnt.few	4000000000089D10; }

l40000000000893A0:
	{ (p06) adds	r8,0x0,r0; (p06) st4	[r36],r33; mov	pr,r55,0xFFFFFFFFFFFFFFFE; }

l40000000000893A6:
	{ Invalid; Invalid; break.i	0x80000; }

l40000000000893AC:
	{ Invalid; Invalid; Invalid }
	{ (p26) nop; add	r0,r32,r0; (p01) shladd	r16,r3,0x1,r64 }
	{ Invalid; (p18) invala; Invalid }

l40000000000893D0:
	{ adds	r16,0x1,r37; ld1	r16,[r16]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r16,r16; cmp4.eq	p07,p06,0x7B,r16; }
	{ (p07) adds	r42,0x1,r42; (p07) adds	r36,0x2,r36; (p07) br.cond.dpnt.few	40000000000890E0; }

l40000000000893F6:
	{ (p18) chk.a.clr	f2,3FFFFFFFFF109636; nop; break.i	0x80000; }

l40000000000893FC:
	{ (p39) invala; cmp.eq	p00,p00,r32,r0; (p16) nop }

l4000000000089400:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x7D,r51; (p06) br.cond.dptk.few	4000000000089170 }

l4000000000089410:
	{ nop.m	0x0; adds	r42,0xFFFFFFFFFFFFFFFF,r42; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r42; (p07) br.cond.dptk.few	4000000000089330; }

l4000000000089430:
	{ nop.m	0x0; tbit.z	p07,p06,r35,0x0; (p07) br.cond.dpnt.few	4000000000089B10; }

l4000000000089440:
	{ (p06) adds	r8,0x0,r0; st4	[r36],r33; nop.i	0x0 }

l4000000000089446:
	{ mf.a; mov	pr,0x4000; break.i	0x80000 }

l4000000000089450:
	{ nop.m	0x0; mov	pr,r55,0xFFFFFFFFFFFFFFFE; nop.i	0x0; }
	{ nop.m	0x0; mov.i	ar.pfs,r53; mov.spnt	b0,r52,4000000000089460 }
	{ nop.m	0x0; adds	r12,0x40,r12; br.ret	b0 }

l4000000000089480:
	{ adds	r14,0x1,r37; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x28,r14; (p06) br.cond.dptk.few	4000000000089180 }

l40000000000894B0:
	{ adds	r36,0x2,r36; nop.m	0x0; adds	r56,0x0,r32 }
	{ adds	r57,0x0,r46; nop.m	0x0; adds	r58,0x0,r50; }
	{ st4	[r36],r46; nop.i	0x0; br.call.sptk.many	b0,extract_command_subst; }
	{ ld4	r36,[r46]; nop.m	0x0; adds	r1,0x0,r54; }
	{ nop.m	0x0; adds	r36,0x1,r36; br.cond.sptk.few	40000000000890E0 }

l4000000000089500:
	{ ld8	r14,[r41]; adds	r15,0x10,r12; adds	r56,0x0,r0 }
	{ adds	r57,0x0,r37; sub	r58,r45,r38; adds	r59,0x0,r41; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r15,0x10,r12; adds	r1,0x0,r54; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000089570; }

l4000000000089550:
	{ ld8	r14,[r15]; nop.m	0x0; adds	r36,0x1,r36; }
	{ st8	[r14],r41; nop.i	0x0; br.cond.sptk.few	4000000000089220 }

l4000000000089570:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r14,0x0,r8; (p07) br.cond.spnt.few	40000000000892E0; }

l400000000008958C:
	{ (p43) nop; break.i	0x1000; break.i	0x1000 }

l4000000000089590:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000895A0:
	{ nop.m	0x0; adds	r36,0x1,r36; br.cond.sptk.few	4000000000089220 }

l40000000000895B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r54; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	40000000000896E0; }

l40000000000895D0:
	{ ld1	r14,[r37]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r40; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000089640; }

l4000000000089620:
	{ (p06) addl	r14,1,r0; nop.m	0x0; nop.i	0x0; }

l4000000000089626:
	{ break.m	0x4000; nop; nop }

l4000000000089630:
	{ add	r36,r14,r36; adds	r39,0x0,r0; br.cond.sptk.few	40000000000890E0; }

l4000000000089640:
	{ ld8	r14,[r43]; adds	r56,0x0,r0; adds	r57,0x0,r37 }
	{ sub	r58,r45,r38; adds	r59,0x0,r43; adds	r39,0x0,r0; }
	{ st8	[r14],r47; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; nop.m	0x0; adds	r1,0x0,r54; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000896B0; }

l4000000000089690:
	{ ld8	r14,[r47]; nop.m	0x0; adds	r36,0x1,r36; }
	{ st8	[r14],r43; nop.i	0x0; br.cond.sptk.few	40000000000890E0 }

l40000000000896B0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r14,0x0,r8; (p07) br.cond.spnt.few	4000000000089630; }

l40000000000896CC:
	{ (p59) nop; break.i	0x1000; break.b	0x1000 }

l40000000000896D0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000896E0:
	{ adds	r36,0x1,r36; adds	r39,0x0,r0; br.cond.sptk.few	40000000000890E0 }

l40000000000896F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r54; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	4000000000089820; }

l4000000000089710:
	{ ld1	r14,[r37]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r17,r14,5,3; and	r16,0x1F,r14; }
	{ shladd	r14,r17,0x2,r40; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r16; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000089A50; }

l4000000000089760:
	{ (p06) addl	r14,1,r0; nop.m	0x0; nop.i	0x0; }

l4000000000089766:
	{ break.m	0x4000; nop; nop }

l4000000000089770:
	{ cmp4.eq	p08,p09,0x1,r44; cmp4.eq	p06,p07,0x25,r51; add	r36,r14,r36; }

l4000000000089772:
	{ nop; (p01) nop }
	{ break.m	0x48000; nop }

l4000000000089786:
	{ adds	r0,0xFFFFFFFFFFFFE000,r1; (p08) dep.z	r1,r0,63,9; (p02) nop }

l4000000000089790:
	{ (p09) adds	r16,0x0,r0; nop.m	0x0; (p07) adds	r17,0x0,r0; }

l4000000000089796:
	{ addp4	r0,0xFFFFFFFFFFFFE000,r1; (p08) mov.sptk	b0,r0,4000000000089896; break.i	0x80000 }

l40000000000897A0:
	{ nop.m	0x0; zxt1	r14,r16; and	r17,r17,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r17; (p06) br.cond.dptk.few	4000000000089870 }

l40000000000897C0:
	{ ld4	r17,[r33]; sub	r17,r36,r17; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,0x1,r17; (p07) br.cond.dpnt.few	4000000000089870 }

l40000000000897E0:
	{ nop.m	0x0; addl	r44,64,r0; br.cond.sptk.few	40000000000890E0; }

l40000000000897F0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r14,0x0,r8; (p07) br.cond.spnt.few	4000000000089770; }

l400000000008980C:
	{ (p59) nop; break.i	0x1000; break.b	0x1000 }

l4000000000089810:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000089820:
	{ cmp4.eq	p08,p09,0x1,r44; cmp4.eq	p06,p07,0x25,r51; adds	r36,0x1,r36; }
	{ (p08) addl	r16,1,r0; nop.m	0x0; (p06) addl	r17,1,r0; }

l4000000000089836:
	{ adds	r0,0xFFFFFFFFFFFFE000,r1; (p08) dep.z	r1,r0,63,9; (p02) nop }

l4000000000089840:
	{ (p09) adds	r16,0x0,r0; nop.m	0x0; (p07) adds	r17,0x0,r0; }

l4000000000089846:
	{ addp4	r0,0xFFFFFFFFFFFFE000,r1; (p08) mov.sptk	b0,r0,4000000000089946; break.i	0x80000 }

l4000000000089850:
	{ nop.m	0x0; zxt1	r14,r16; and	r17,r17,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r17; (p07) br.cond.dptk.few	40000000000897C0; }

l4000000000089870:
	{ cmp4.eq	p06,p07,0x23,r51; (p06) addl	r17,1,r0; nop.i	0x0; }

l400000000008987C:
	{ nop; (p02) nop; zxt1	r68,r3 }

l4000000000089886:
	{ Invalid; nop; break.b	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD4D1A6; nop; (p16) nop }

l40000000000898A0:
	{ ld4	r17,[r33]; sub	r17,r36,r17; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,0x1,r17; (p06) br.cond.dptk.few	40000000000897E0; }

l40000000000898C0:
	{ cmp4.eq	p06,p07,0x2F,r51; (p06) addl	r17,1,r0; nop.i	0x0; }

l40000000000898CC:
	{ nop; (p02) nop; zxt1	r68,r3 }

l40000000000898D6:
	{ Invalid; nop; break.b	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD4D1F6; nop; (p16) nop }

l40000000000898F0:
	{ ld4	r17,[r33]; sub	r17,r36,r17; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,0x1,r17; (p06) br.cond.dptk.few	40000000000897E0; }

l4000000000089910:
	{ cmp4.eq	p06,p07,0x5E,r51; (p06) addl	r17,1,r0; nop.i	0x0; }

l400000000008991C:
	{ nop; (p02) nop; zxt1	r68,r3 }

l4000000000089926:
	{ Invalid; nop; break.b	0x80000 }
	{ (p03) chk.a.clr	f0,3FFFFFFFFFD4D246; nop; (p32) nop }

l4000000000089940:
	{ cmp4.eq	p06,p07,0x2C,r51; (p06) addl	r17,1,r0; nop.i	0x0; }

l400000000008994C:
	{ nop; (p02) cmp.lt	p00,p16,r0,r64; zxt1	r68,r3 }

l4000000000089956:
	{ Invalid; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD4D246; nop; (p32) nop }

l4000000000089970:
	{ ld4	r14,[r33]; sub	r14,r36,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,0x1,r14; (p06) br.cond.dptk.few	40000000000897E0 }

l4000000000089990:
	{ addl	r56,-6812,r1; nop.m	0x0; adds	r57,0x0,r51; }
	{ ld8	r56,[r56]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B680; }
	{ cmp.eq	p07,p06,0x0,r8; nop.m	0x0; adds	r1,0x0,r54; }
	{ nop.m	0x0; (p06) addl	r44,2,r0; br.cond.sptk.few	40000000000890E0 }

l40000000000899CC:
	{ (p57) ld2	r126,[r36]; (p07) shladd	r55,r95,0x4,r114; zxt1	r0,r64 }

l40000000000899D0:
	{ addl	r58,-6820,r1; adds	r36,0x1,r36; adds	r56,0x0,r32 }
	{ adds	r57,0x0,r46; adds	r59,0x0,r50; nop.i	0x0 }
	{ st4	[r36],r46; ld8	r58,[r58]; br.call.sptk.many	b0,fn4000000000088B40; }
	{ ld4	r36,[r46]; nop.m	0x0; adds	r1,0x0,r54; }
	{ nop.m	0x0; adds	r36,0x1,r36; br.cond.sptk.few	4000000000089340; }

l4000000000089A20:
	{ adds	r58,0x1,r36; adds	r56,0x0,r32; adds	r57,0x0,r45; }
	{ st4	[r58],r46; nop.i	0x0; br.call.sptk.many	b0,fn4000000000089DC0; }
	{ adds	r1,0x0,r54; adds	r36,0x0,r8; br.cond.sptk.few	40000000000890E0 }

l4000000000089A50:
	{ ld8	r14,[r43]; adds	r15,0x20,r12; adds	r56,0x0,r0 }
	{ adds	r57,0x0,r37; sub	r58,r45,r38; adds	r59,0x0,r43; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; nop.m	0x0; cmp4.eq	p08,p09,0x1,r44 }
	{ adds	r15,0x20,r12; nop.m	0x0; adds	r1,0x0,r54; }
	{ cmp.ltu	p06,p07,0x1,r14; (p08) addl	r16,1,r0; (p06) br.cond.dpnt.few	40000000000897F0; }

l4000000000089AAC:
	{ (p42) chk.a.nc	r127,4000000000A9CA9C; zxt1	r0,r64; Invalid }

l4000000000089AB0:
	{ (p09) adds	r16,0x0,r0; nop.m	0x0; cmp4.eq	p06,p07,0x25,r51 }

l4000000000089AB6:
	{ break.m	0x4000; (p03) nop; (p32) nop }
	{ break.m	0x4000; (p18) nop; addl	r64,144227,r2 }
	{ Invalid; (p07) cmp4.ltu	p00,p00,0x10,r16; (p17) nop.b	0x4; }

l4000000000089ADC:
	{ nop; (p02) nop; zxt1	r68,r3; }

l4000000000089AE6:
	{ Invalid; nop; break.b	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD4D406; nop; break.i	0x80000 }

l4000000000089B00:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000897C0 }

l4000000000089B10:
	{ adds	r56,0x0,r32; ld4	r57,[r33]; adds	r58,0x0,r36 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,substring; }
	{ nop.m	0x0; adds	r1,0x0,r54; nop.i	0x0 }
	{ st4	[r36],r33; nop.m	0x0; br.cond.sptk.few	4000000000089450 }

l4000000000089B50:
	{ ld4	r17,[r33]; sub	r17,r36,r17; nop.i	0x0; }
	{ cmp4.lt	p06,p07,0x1,r17; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000089940; }

l4000000000089B70:
	{ nop.m	0x0; addl	r44,64,r0; br.cond.sptk.few	40000000000890E0 }

l4000000000089B80:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r54; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	4000000000089330; }

l4000000000089BA0:
	{ ld1	r14,[r37]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r40; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000089C70; }

l4000000000089BF0:
	{ (p06) addl	r14,1,r0; nop.m	0x0; nop.i	0x0; }

l4000000000089BF6:
	{ break.m	0x4000; nop; break.i	0x80000 }

l4000000000089C00:
	{ nop.m	0x0; add	r36,r14,r36; br.cond.sptk.few	40000000000890E0 }

l4000000000089C10:
	{ cmp4.eq	p06,p07,0x0,r16; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000089990; }

l4000000000089C20:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2,r44; (p06) br.cond.dptk.few	40000000000890E0 }

l4000000000089C30:
	{ addl	r56,-6812,r1; nop.m	0x0; adds	r57,0x0,r51; }
	{ ld8	r56,[r56]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B680; }
	{ cmp.eq	p07,p06,0x0,r8; adds	r1,0x0,r54; (p06) addl	r44,2,r0; }

l4000000000089C60:
	{ nop.m	0x0; (p07) addl	r44,4,r0; br.cond.sptk.few	40000000000890E0 }

l4000000000089C6C:
	{ (p36) cmp.lt.unc	p62,p08,r63,r36; (p01) cmp.eq.unc	p32,p08,r10,r6; zxt1	r10,r64 }

l4000000000089C70:
	{ ld8	r14,[r43]; adds	r15,0x28,r12; adds	r56,0x0,r0 }
	{ adds	r57,0x0,r37; sub	r58,r45,r38; adds	r59,0x0,r43; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r15,0x28,r12; adds	r1,0x0,r54; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000089CE0; }

l4000000000089CC0:
	{ ld8	r14,[r15]; nop.m	0x0; adds	r36,0x1,r36; }
	{ st8	[r14],r43; nop.i	0x0; br.cond.sptk.few	40000000000890E0 }

l4000000000089CE0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ (p07) adds	r14,0x0,r8; nop.i	0x0; (p07) br.cond.spnt.few	4000000000089C00; }

l4000000000089CF6:
	{ chk.a.nc	f0,3FFFFFFFFF08A4F6; nop; break.i	0x80000 }

l4000000000089D00:
	{ nop.m	0x0; adds	r36,0x1,r36; br.cond.sptk.few	4000000000089340 }

l4000000000089D10:
	{ addl	r57,-6804,r1; addl	r58,5,r0; adds	r56,0x0,r0; }
	{ ld8	r57,[r57]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r54; adds	r56,0x0,r8; adds	r58,0x0,r32; }
	{ nop.m	0x0; addl	r57,-6796,r1; nop.i	0x0; }
	{ ld8	r57,[r57]; nop.i	0x0; br.call.sptk.many	b0,report_error; }
	{ adds	r1,0x0,r54; addl	r15,1,r0; addl	r56,2,r0; }
	{ addl	r14,9044,r1; nop.m	0x0; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,fn4000000000085DC0; }
	{ nop.m	0x0; break.f	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

;; fn4000000000089DC0: 4000000000089DC0
;;   Called from:
;;     400000000008846C (in skipsubscript)
;;     4000000000089A3C (in fn4000000000089000)
;;     4000000000089DBC (in fn4000000000089000)
;;     400000000008AA7C (in fn400000000008A3C0)
;;     400000000008C4FC (in skip_to_delim)
;;     400000000008D07C (in char_is_quoted)
;;     400000000008D77C (in unclosed_pair)
;;     400000000008D77C (in unclosed_pair)
fn4000000000089DC0 proc
	{ alloc	r42,ar.pfs,0x10,0x0,0xC; adds	r12,0xFFFFFFFFFFFFFFD0,r12; nop.b	0x0 }
	{ addl	r40,-9996,r1; mov	r41,b1; adds	r43,0x0,r1; }
	{ adds	r39,0x28,r12; adds	r38,0x0,r0; adds	r37,0x0,r0 }
	{ ld8	r40,[r40]; st8	[r0],r39; nop.i	0x0; }

l4000000000089E00:
	{ nop.m	0x0; sxt4	r36,r34; add	r35,r32,r36; }
	{ ld1	r15,[r35]; nop.m	0x0; sxt1	r15,r15; }
	{ adds	r14,0x0,r15; cmp4.eq	p07,p06,0x0,r15; (p07) br.cond.dpnt.few	4000000000089F60; }

l4000000000089E30:
	{ cmp4.eq	p06,p07,0x0,r37; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000089F80; }

l4000000000089E40:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5C,r14; nop.i	0x0; }
	{ (p07) adds	r34,0x1,r34; (p07) addl	r37,1,r0; (p07) br.cond.dpnt.few	4000000000089E00; }

l4000000000089E56:
	{ (p18) chk.a.clr	f1,3FFFFFFFFF289E56; nop; break.b	0x80000; }

l4000000000089E5C:
	{ Invalid; cmp.lt	p00,p00,r32,r0; nop }

l4000000000089E60:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r38; (p06) br.cond.dptk.few	400000000008A010; }

l4000000000089E70:
	{ cmp4.eq	p07,p06,0x60,r14; (p06) addl	r14,1,r0; nop.i	0x0; }

l4000000000089E7C:
	{ nop; cmp4.eq.and	p00,p32,r32,r0; zxt1	r0,r64 }

l4000000000089E8C:
	{ cmp.lt	p00,p17,r1,r0; zxt1	r64,r64; break.i	0x1000 }
	{ (p17) nop; cmp.eq.unc	p32,p16,r10,r64; (p16) nop }
	{ (p16) cmp.lt	p00,p11,r64,r33; Invalid; cmp.lt	p00,p00,r32,r0 }

l4000000000089EB0:
	{ ld1	r14,[r35]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r40; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x0; (p07) br.cond.dpnt.few	400000000008A240 }

l4000000000089F00:
	{ addl	r14,1,r0; nop.m	0x0; nop.i	0x0; }

l4000000000089F10:
	{ add	r34,r14,r34; nop.m	0x0; sxt4	r36,r34; }
	{ add	r35,r32,r36; ld1	r15,[r35]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ adds	r14,0x0,r15; cmp4.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	4000000000089E30; }

l4000000000089F50:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000089F60:
	{ adds	r8,0x0,r34; mov.i	ar.pfs,r42; mov.spnt	b0,r41,4000000000089F60 }
	{ nop.m	0x0; adds	r12,0x30,r12; br.ret	b0; }

l4000000000089F80:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r43; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	400000000008A0E0; }

l4000000000089FA0:
	{ ld1	r14,[r35]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r40; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	400000000008A1D0; }

l4000000000089FF0:
	{ (p06) addl	r14,1,r0; nop.m	0x0; nop.i	0x0; }

l4000000000089FF6:
	{ break.m	0x4000; nop; (p32) nop }

l400000000008A000:
	{ add	r34,r14,r34; adds	r37,0x0,r0; br.cond.sptk.few	4000000000089E00 }

l400000000008A010:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x60,r14; nop.i	0x0; }
	{ (p07) adds	r34,0x1,r34; (p07) addl	r38,1,r0; (p07) br.cond.dpnt.few	4000000000089E00; }

l400000000008A026:
	{ (p19) chk.a.clr	f1,3FFFFFFFFF28A026; nop; (p48) nop; }

l400000000008A02C:
	{ (p47) cmp.eq.unc	p63,p17,r127,r37; czx1.r	r73,r97; mov	pr,r32,0x0 }

l400000000008A030:
	{ cmp4.eq	p07,p06,0x24,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000008A2B0; }

l400000000008A040:
	{ cmp4.eq	p06,p07,0x22,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000008A0F0; }

l400000000008A050:
	{ nop.m	0x0; adds	r34,0x1,r34; nop.i	0x0; }
	{ adds	r8,0x0,r34; mov.i	ar.pfs,r42; mov.spnt	b0,r41,400000000008A060 }
	{ nop.m	0x0; adds	r12,0x30,r12; br.ret	b0 }

l400000000008A080:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r14,0x0,r8; (p07) br.cond.spnt.few	4000000000089F10; }

l400000000008A09C:
	{ (p52) invala; dep	r0,r32,r0,63,1; zxt1	r64,r64 }

l400000000008A0A0:
	{ nop.m	0x0; adds	r34,0x1,r34; br.cond.sptk.few	4000000000089E00 }

l400000000008A0B0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r14,0x0,r8; (p07) br.cond.spnt.few	400000000008A000; }

l400000000008A0CC:
	{ (p58) nop; break.i	0x1000; break.i	0x1000 }

l400000000008A0D0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000008A0E0:
	{ adds	r34,0x1,r34; adds	r37,0x0,r0; br.cond.sptk.few	4000000000089E00 }

l400000000008A0F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r43; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	400000000008A0A0; }

l400000000008A110:
	{ ld1	r14,[r35]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r40; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x0; (p06) br.cond.dptk.few	4000000000089F00 }

l400000000008A160:
	{ ld8	r14,[r39]; adds	r15,0x10,r12; adds	r44,0x0,r0 }
	{ adds	r45,0x0,r35; sub	r46,r33,r36; adds	r47,0x0,r39; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r15,0x10,r12; adds	r1,0x0,r43; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000008A080; }

l400000000008A1B0:
	{ ld8	r14,[r15]; nop.m	0x0; adds	r34,0x1,r34; }
	{ st8	[r14],r39; nop.i	0x0; br.cond.sptk.few	4000000000089E00 }

l400000000008A1D0:
	{ ld8	r14,[r39]; adds	r15,0x20,r12; adds	r44,0x0,r0 }
	{ adds	r45,0x0,r35; sub	r46,r33,r36; adds	r47,0x0,r39; }
	{ st8	[r14],r15; adds	r37,0x0,r0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r15,0x20,r12; adds	r1,0x0,r43; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000008A0B0; }

l400000000008A220:
	{ ld8	r14,[r15]; nop.m	0x0; adds	r34,0x1,r34; }
	{ st8	[r14],r39; nop.i	0x0; br.cond.sptk.few	4000000000089E00 }

l400000000008A240:
	{ ld8	r14,[r39]; adds	r15,0x18,r12; adds	r44,0x0,r0 }
	{ adds	r45,0x0,r35; sub	r46,r33,r36; adds	r47,0x0,r39; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r15,0x18,r12; adds	r1,0x0,r43; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000008A080; }

l400000000008A290:
	{ ld8	r14,[r15]; nop.m	0x0; adds	r34,0x1,r34; }
	{ st8	[r14],r39; nop.i	0x0; br.cond.sptk.few	4000000000089E00 }

l400000000008A2B0:
	{ adds	r14,0x1,r35; ld1	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ cmp4.eq	p08,p09,0x28,r15; cmp4.eq	p06,p07,0x7B,r15; (p08) addl	r14,1,r0; }

l400000000008A2E0:
	{ nop.m	0x0; (p09) adds	r14,0x0,r0; nop.i	0x0; }

l400000000008A2EC:
	{ Invalid; cmp.lt	p00,p00,r32,r0; (p08) mov	pr,r99,0xE580 }
	{ (p48) cmp.lt.unc	p63,p08,r63,r37; dep	r64,r99,r97,62,13; (p36) cmp.lt.unc	p00,p16,r8,r64 }

l400000000008A300:
	{ cmp4.eq	p06,p07,0x0,r14; adds	r34,0x2,r34; adds	r14,0x30,r12 }
	{ adds	r44,0x0,r32; adds	r45,0x30,r12; addl	r46,1,r0; }
	{ st4	[r34],r14; nop.m	0x0; addl	r47,1,r0 }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	400000000008A370; br.call.sptk.many	b0,fn4000000000089000; }

l400000000008A33C:
	{ (p38) cmp.eq.unc	p61,p09,r63,r44; (p01) invala; nop.b	0x1000 }
	{ nop; dep	r0,r32,r0,63,1; Invalid }
	{ invala; dep	r0,r32,r0,63,1; zxt1	r64,r64 }
	{ (p21) nop; (p05) cmp.lt.unc	p00,p16,r3,r64; zxt4	r0,r0 }

l400000000008A370:
	{ adds	r45,0x0,r14; addl	r46,1,r0; br.call.sptk.many	b0,extract_command_subst; }
	{ adds	r15,0x30,r12; nop.m	0x0; adds	r1,0x0,r43; }
	{ nop.m	0x0; ld4	r34,[r15]; nop.i	0x0; }
	{ nop.m	0x0; adds	r34,0x1,r34; br.cond.sptk.few	4000000000089E00; }
400000000008A3B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn400000000008A3C0: 400000000008A3C0
;;   Called from:
;;     4000000000088A8C (in skipsubscript)
;;     400000000008AD2C (in fn400000000008A3C0)
;;     400000000008B29C (in fn400000000008A3C0)
;;     400000000008B54C (in extract_process_subst)
;;     400000000008B5BC (in extract_arithmetic_subst)
;;     400000000008B6FC (in extract_command_subst)
;;     400000000008CB9C (in skip_to_delim)
;;     400000000008CDDC (in skip_to_delim)
fn400000000008A3C0 proc
	{ alloc	r62,ar.pfs,0x27,0x0,0x21; adds	r12,0xFFFFFFFFFFFFFFC0,r12; nop.b	0x0 }
	{ ld4	r38,[r33]; mov	r64,pr; adds	r63,0x0,r1; }
	{ nop.m	0x0; mov	r61,b5; sxt4	r41,r38 }
	{ nop.m	0x0; adds	r45,0x40,r12; nop.b	0x0; }
	{ st8	[r0],r45; add	r65,r32,r41; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r63; nop.m	0x0; cmp.eq	p06,p07,0x0,r34 }
	{ add	r47,r8,r41; nop.m	0x0; (p06) br.cond.dpnt.few	400000000008A820; }

l400000000008A430:
	{ ld1	r14,[r34]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000008A820 }

l400000000008A450:
	{ adds	r14,0x1,r34; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r49,1,r0; (p06) br.cond.dptk.few	400000000008A4C0 }

l400000000008A47C:
	{ (p02) cmp.lt	p00,p11,r0,r33; (p33) cmp.lt.unc	p00,p16,r8,r64; (p01) rfi }

l400000000008A480:
	{ adds	r14,0x2,r34; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	400000000008B380; }

l400000000008A4B0:
	{ (p06) addl	r49,2,r0; nop.m	0x0; nop.i	0x0 }

l400000000008A4B6:
	{ break.m	0x4000; nop; break.i	0x80000 }

l400000000008A4C0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r35; (p06) br.cond.dpnt.few	400000000008A840 }

l400000000008A4C2:
	{ Invalid; (p48) nop.i	0x720E8; Invalid }

l400000000008A4C6:
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD0DEF6; nop; (p32) nop }

l400000000008A4CC:
	{ (p28) cmp.lt	p00,p11,r64,r33; Invalid; cmp.lt	p00,p00,r32,r0 }

l400000000008A4D0:
	{ ld1	r14,[r35]; nop.m	0x0; sxt1	r14,r14; }

l400000000008A4D2:
	{ (p48) break.m	0x20008; mov	pr,r0,0x40; Invalid }
	{ Invalid; (p32) cmp.lt.unc	p35,p01,r97,r92; Invalid }

l400000000008A4F0:
	{ adds	r14,0x1,r35; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r53,1,r0; (p06) br.cond.dptk.few	400000000008A560 }

l400000000008A51C:
	{ (p02) cmp.lt	p00,p11,r0,r33; (p33) cmp.lt.unc	p32,p16,r8,r64; (p01) rfi }

l400000000008A520:
	{ adds	r14,0x2,r35; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	400000000008B3A0; }

l400000000008A550:
	{ (p06) addl	r53,2,r0; nop.m	0x0; nop.i	0x0 }

l400000000008A556:
	{ break.m	0x4000; nop; break.i	0x80000 }

l400000000008A560:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r36; (p06) br.cond.dpnt.few	400000000008A860 }

l400000000008A562:
	{ Invalid; nop.i	0x720E9; Invalid }

l400000000008A566:
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD0DFA6; nop; (p32) nop }

l400000000008A56C:
	{ (p24) cmp.lt	p00,p11,r64,r33; Invalid; cmp.lt	p00,p00,r32,r0 }

l400000000008A570:
	{ ld1	r14,[r36]; nop.m	0x0; sxt1	r14,r14; }

l400000000008A572:
	{ break.m	0x20009; mov	pr,r0,0x40; Invalid }
	{ Invalid; (p32) cmp.lt.unc	p35,p01,r97,r92; Invalid }

l400000000008A590:
	{ adds	r14,0x1,r36; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r52,1,r0; (p06) br.cond.dptk.few	400000000008A610 }

l400000000008A5BC:
	{ (p03) cmp.lt	p00,p11,r0,r33; (p33) cmp.lt	p00,p16,r9,r64; Invalid }

l400000000008A5C0:
	{ adds	r14,0x2,r36; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r52,2,r0; (p06) br.cond.dptk.few	400000000008A610 }

l400000000008A5EC:
	{ (p01) nop; zxt1	r0,r64; break.b	0x1000 }

l400000000008A5F0:
	{ adds	r65,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; adds	r1,0x0,r63; adds	r52,0x0,r8; }

l400000000008A610:
	{ addl	r44,-9996,r1; addl	r56,-18556,r1; nop.b	0x0 }
	{ adds	r42,0x0,r0; adds	r43,0x0,r0; tnat.z	p16,p17,r37; }
	{ cmp4.eq	p18,p19,0x0,r49; adds	r46,0x48,r12; or	r51,0x1,r37 }
	{ cmp4.eq	p20,p21,0x0,r53; cmp4.eq	p23,p22,0x0,r52; adds	r50,0x18,r12; }
	{ ld8	r44,[r44]; addl	r57,8192,r0; sxt4	r58,r52 }
	{ adds	r54,0x30,r12; adds	r48,0x38,r12; sxt4	r59,r53; }
	{ nop.m	0x0; sxt4	r55,r49; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000008A6A0:
	{ add	r40,r32,r41; ld1	r14,[r40]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; adds	r60,0x0,r14 }
	{ adds	r39,0x0,r14; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	400000000008A7C0; }

l400000000008A6D0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r42; (p06) br.cond.dptk.few	400000000008A950; }

l400000000008A6E0:
	{ cmp4.eq	p07,p06,0xA,r39; (p06) addl	r39,1,r0; nop.i	0x0; }

l400000000008A6EC:
	{ cmp4.eq.or.andcm	p00,p49,r1,r0; zxt1	r0,r64; break.i	0x1000 }

l400000000008A6F6:
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ add	r0,r0,r1; nop; (p48) nop }
	{ chk.a.nc	r0,3FFFFFFFFF08AF16; nop; (p32) nop }

l400000000008A720:
	{ ld1	r14,[r40]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r44; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x0; (p07) br.cond.dpnt.few	400000000008A8E0 }

l400000000008A770:
	{ addl	r14,1,r0; nop.m	0x0; nop.i	0x0; }

l400000000008A780:
	{ add	r38,r14,r38; nop.m	0x0; sxt4	r41,r38; }
	{ add	r40,r32,r41; ld1	r14,[r40]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; adds	r39,0x0,r14 }
	{ adds	r60,0x0,r14; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	400000000008A6D0; }

l400000000008A7C0:
	{ addl	r14,7548,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.spnt.few	400000000008B450; }

l400000000008A7E0:
	{ (p07) adds	r39,0x0,r0; (p07) st4	[r38],r33; nop.i	0x0; }

l400000000008A7E6:
	{ mf.a; Invalid; nop; }

l400000000008A7EC:
	{ Invalid; (p01) cmp.eq.unc	p32,p16,r9,r64; (p15) nop.i	0xDFE10 }
	{ (p31) break.m	0x1540; break.i	0x1000; (p16) break.i	0xC002F }
	{ shladdp4	r0,r1,0x1,r0; zxt1	r16,r64; add	r0,r32,r0 }
	{ nop; (p06) cmp.lt	p00,p16,r0,r64; mov	pr,r104,0xE4C0 }

l400000000008A820:
	{ adds	r49,0x0,r0; cmp.eq	p06,p07,0x0,r35; (p07) br.cond.dptk.few	400000000008A4D0; }

l400000000008A830:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000008A840:
	{ adds	r53,0x0,r0; cmp.eq	p06,p07,0x0,r36; (p07) br.cond.dptk.few	400000000008A570; }

l400000000008A850:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000008A860:
	{ adds	r52,0x0,r0; addl	r44,-9996,r1; addl	r56,-18556,r1 }
	{ adds	r42,0x0,r0; adds	r43,0x0,r0; cmp4.eq	p18,p19,0x0,r49; }
	{ adds	r46,0x48,r12; or	r51,0x1,r37; tnat.z	p16,p17,r37 }
	{ cmp4.eq	p20,p21,0x0,r53; cmp4.eq	p23,p22,0x0,r52; adds	r50,0x18,r12; }
	{ ld8	r44,[r44]; addl	r57,8192,r0; sxt4	r58,r52 }
	{ adds	r54,0x30,r12; adds	r48,0x38,r12; sxt4	r59,r53; }
	{ nop.m	0x0; sxt4	r55,r49; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; br.cond.sptk.few	400000000008A6A0 }

l400000000008A8E0:
	{ nop.m	0x0; ld8	r14,[r45]; sub	r67,r47,r41 }
	{ adds	r65,0x0,r0; adds	r66,0x0,r40; adds	r68,0x0,r45; }
	{ st8	[r14],r48; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; nop.m	0x0; adds	r1,0x0,r63; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000008AAA0; }

l400000000008A930:
	{ ld8	r14,[r48]; nop.m	0x0; adds	r38,0x1,r38; }
	{ st8	[r14],r45; sxt4	r41,r38; br.cond.sptk.few	400000000008A6A0 }

l400000000008A950:
	{ cmp4.eq	p06,p07,0x0,r43; (p07) br.cond.dpnt.few	400000000008AE10; (p17) br.cond.dptk.few	400000000008AAE0; }

l400000000008A95C:
	{ (p12) nop; cmp.lt	p00,p00,r32,r0; (p16) nop }

l400000000008A960:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x1,r39; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x5C,r39; (p06) br.cond.dptk.few	400000000008AB10; }

l400000000008A980:
	{ nop.m	0x0; nop.i	0x0; (p18) br.cond.dpnt.few	400000000008AD00; }

l400000000008A990:
	{ ld1	r15,[r34]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r15,r39; (p07) br.cond.dpnt.few	400000000008ACD0 }

l400000000008A9B0:
	{ nop.m	0x0; nop.i	0x0; (p20) br.cond.dptk.few	400000000008A9E0 }

l400000000008A9C0:
	{ ld1	r15,[r35]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r15,r39; (p07) br.cond.dpnt.few	400000000008B240 }

l400000000008A9E0:
	{ nop.m	0x0; nop.i	0x0; (p23) br.cond.dpnt.few	400000000008AD80; }

l400000000008A9F0:
	{ ld1	r15,[r36]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r15,r39; (p07) br.cond.dpnt.few	400000000008AD50; }

l400000000008AA10:
	{ cmp4.eq	p07,p06,0x60,r60; cmp4.eq	p08,p09,0x27,r60; nop.i	0x0 }
	{ adds	r65,0x0,r32; adds	r66,0x0,r47; (p07) br.cond.dpnt.few	400000000008B330; }

l400000000008AA30:
	{ (p08) addl	r15,1,r0; cmp4.eq	p06,p07,0x22,r60; (p09) adds	r15,0x0,r0; }

l400000000008AA36:
	{ (p03) addl	r34,96700,r3; (p07) nop; (p32) nop }

l400000000008AA40:
	{ cmp.ne.or.andcm	p06,p07,0x0,r15; nop.i	0x0; (p07) br.cond.dpnt.few	400000000008B120; }

l400000000008AA50:
	{ adds	r38,0x1,r38; nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; }
	{ st4	[r38],r46; (p07) st8	[r0],r50; adds	r67,0x0,r38 }

l400000000008AA6C:
	{ rsm	0x308026; Invalid; Invalid }

l400000000008AA7C:
	{ (p26) nop; nop; Invalid }
	{ invala; break.x	0x8000016100 }
	{ (p32) nop; cmp.lt	p00,p00,r32,r0; nop }

l400000000008AAA0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r14,0x0,r8; (p07) br.cond.spnt.few	400000000008A780; }

l400000000008AABC:
	{ (p38) nop; cmp.lt	p00,p00,r32,r0; (p20) epc }

l400000000008AAC0:
	{ nop.m	0x0; adds	r38,0x1,r38; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r41,r38; br.cond.sptk.few	400000000008A6A0 }

l400000000008AAE0:
	{ cmp4.eq	p07,p06,0x23,r39; nop.i	0x0; (p07) br.cond.dpnt.few	400000000008B020; }

l400000000008AAF0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x1,r39; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x5C,r39; (p07) br.cond.dptk.few	400000000008AF50 }

l400000000008AB10:
	{ adds	r38,0x1,r38; nop.m	0x0; addl	r43,1,r0; }
	{ nop.m	0x0; sxt4	r41,r38; br.cond.sptk.few	400000000008A6A0; }

l400000000008AB30:
	{ ld8	r14,[r50]; adds	r15,0x10,r12; adds	r65,0x0,r0 }
	{ adds	r66,0x0,r39; sub	r67,r47,r41; adds	r68,0x0,r50; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r15,0x10,r12; adds	r1,0x0,r63; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000008AF20; }

l400000000008AB80:
	{ ld8	r14,[r15]; nop.m	0x0; adds	r38,0x1,r38; }
	{ st8	[r14],r50; nop.m	0x0; nop.i	0x0 }

l400000000008ABA0:
	{ nop.m	0x0; sxt4	r41,r38; add	r39,r32,r41; }
	{ nop.m	0x0; ld1	r14,[r39]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x0,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x27,r14; (p07) br.cond.dpnt.few	400000000008ACA0 }

l400000000008ABE0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r63; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	400000000008AF40; }

l400000000008AC00:
	{ ld1	r14,[r39]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r44; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	400000000008AB30; }

l400000000008AC50:
	{ (p06) addl	r14,1,r0; nop.m	0x0; nop.i	0x0; }

l400000000008AC56:
	{ break.m	0x4000; nop; (p32) nop }

l400000000008AC60:
	{ add	r38,r14,r38; nop.m	0x0; sxt4	r41,r38; }
	{ add	r39,r32,r41; ld1	r14,[r39]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x0,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x27,r14; (p06) br.cond.dptk.few	400000000008ABE0; }

l400000000008ACA0:
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000008A6A0; }

l400000000008ACB0:
	{ nop.m	0x0; adds	r38,0x1,r38; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r41,r38; br.cond.sptk.few	400000000008A6A0 }

l400000000008ACD0:
	{ adds	r65,0x0,r40; nop.m	0x0; adds	r66,0x0,r34 }
	{ adds	r67,0x0,r55; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C020; }
	{ adds	r1,0x0,r63; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	400000000008A9B0 }

l400000000008AD00:
	{ add	r38,r38,r49; adds	r65,0x0,r32; adds	r66,0x0,r46 }
	{ adds	r67,0x0,r34; adds	r68,0x0,r35; adds	r69,0x0,r36; }
	{ st4	[r38],r46; adds	r70,0x0,r51; br.call.sptk.many	b0,fn400000000008A3C0; }
	{ ld4	r38,[r46]; adds	r1,0x0,r63; adds	r38,0x1,r38; }
	{ nop.m	0x0; sxt4	r41,r38; br.cond.sptk.few	400000000008A6A0 }

l400000000008AD50:
	{ adds	r65,0x0,r40; nop.m	0x0; adds	r66,0x0,r36 }
	{ adds	r67,0x0,r58; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C020; }
	{ adds	r1,0x0,r63; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dptk.few	400000000008AA10; }

l400000000008AD80:
	{ adds	r15,0xFFFFFFFFFFFFFFFF,r52; ld4	r14,[r33]; nop.b	0x0 }
	{ adds	r40,0x48,r12; nop.m	0x0; tbit.z	p07,p06,r37,0x0; }
	{ add	r38,r38,r15; (p06) adds	r39,0x0,r0; sub	r14,r38,r14; }

l400000000008ADAC:
	{ Invalid; (p38) cmp.lt	p03,p16,r45,r1; zxt1	r0,r64; }
	{ invala.e	f0; (p32) mov	pr,r10,0x4606; Invalid }

l400000000008ADCC:
	{ nop; Invalid; break.i	0x1000 }
	{ Invalid; (p01) cmp.eq.unc	p32,p16,r9,r64; (p15) nop.i	0xDFE10 }

l400000000008ADE0:
	{ adds	r8,0x0,r39; mov	pr,r64,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r62; }
	{ nop.m	0x0; mov.spnt	b0,r61,400000000008ADF0; nop.i	0x0 }
	{ adds	r12,0x40,r12; nop.m	0x0; br.ret	b0; }

l400000000008AE10:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r63; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	400000000008B000; }

l400000000008AE30:
	{ ld1	r14,[r40]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r44; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	400000000008AEB0; }

l400000000008AE80:
	{ (p06) addl	r14,1,r0; nop.m	0x0; nop.i	0x0; }

l400000000008AE86:
	{ break.m	0x4000; nop; (p32) nop }

l400000000008AE90:
	{ add	r38,r14,r38; nop.m	0x0; adds	r43,0x0,r0; }
	{ nop.m	0x0; sxt4	r41,r38; br.cond.sptk.few	400000000008A6A0; }

l400000000008AEB0:
	{ ld8	r14,[r45]; sub	r67,r47,r41; adds	r65,0x0,r0 }
	{ adds	r66,0x0,r40; adds	r68,0x0,r45; adds	r43,0x0,r0; }
	{ st8	[r14],r54; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; nop.m	0x0; adds	r1,0x0,r63; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000008AFE0; }

l400000000008AF00:
	{ ld8	r14,[r54]; nop.m	0x0; adds	r38,0x1,r38; }
	{ st8	[r14],r45; sxt4	r41,r38; br.cond.sptk.few	400000000008A6A0 }

l400000000008AF20:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r14,0x0,r8; (p07) br.cond.spnt.few	400000000008AC60; }

l400000000008AF3C:
	{ (p41) invala; cmp.lt	p00,p00,r32,r0; (p20) epc }

l400000000008AF40:
	{ nop.m	0x0; adds	r38,0x1,r38; br.cond.sptk.few	400000000008ABA0 }

l400000000008AF50:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x24,r39; (p06) br.cond.dptk.few	400000000008A980 }

l400000000008AF60:
	{ adds	r15,0x1,r40; ld1	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x28,r15; (p06) br.cond.dptk.few	400000000008A980 }

l400000000008AF90:
	{ adds	r38,0x2,r38; nop.m	0x0; adds	r65,0x0,r32 }
	{ adds	r66,0x0,r46; nop.m	0x0; adds	r67,0x0,r51; }
	{ st4	[r38],r46; nop.i	0x0; br.call.sptk.many	b0,extract_command_subst; }
	{ ld4	r38,[r46]; adds	r1,0x0,r63; adds	r38,0x1,r38; }
	{ nop.m	0x0; sxt4	r41,r38; br.cond.sptk.few	400000000008A6A0 }

l400000000008AFE0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r14,0x0,r8; (p07) br.cond.spnt.few	400000000008AE90; }

l400000000008AFFC:
	{ (p53) cmp.lt.unc	p63,p09,r127,r36; zxt1	r64,r64; nop }

l400000000008B000:
	{ adds	r38,0x1,r38; nop.m	0x0; adds	r43,0x0,r0; }
	{ nop.m	0x0; sxt4	r41,r38; br.cond.sptk.few	400000000008A6A0 }

l400000000008B020:
	{ adds	r15,0xFFFFFFFFFFFFFFFF,r40; cmp4.eq	p06,p07,0x0,r38; (p06) br.cond.dpnt.few	400000000008B080; }

l400000000008B030:
	{ ld1	r15,[r15]; nop.m	0x0; sxt1	r15,r15; }
	{ cmp4.eq	p06,p07,0xA,r15; zxt1	r15,r15; (p06) br.cond.dpnt.few	400000000008B080; }

l400000000008B050:
	{ shladd	r15,r15,0x2,r56; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; and	r15,r57,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	400000000008A980 }

l400000000008B080:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r63; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	400000000008B220; }

l400000000008B0A0:
	{ ld1	r14,[r40]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r44; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	400000000008B2C0; }

l400000000008B0F0:
	{ (p06) addl	r14,1,r0; nop.m	0x0; nop.i	0x0; }

l400000000008B0F6:
	{ break.m	0x4000; nop; (p32) nop }

l400000000008B100:
	{ add	r38,r14,r38; nop.m	0x0; addl	r42,1,r0; }
	{ nop.m	0x0; sxt4	r41,r38; br.cond.sptk.few	400000000008A6A0 }

l400000000008B120:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r63; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	400000000008AAC0; }

l400000000008B140:
	{ ld1	r14,[r40]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r44; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x0; (p06) br.cond.dptk.few	400000000008A770 }

l400000000008B190:
	{ ld8	r14,[r45]; adds	r15,0x20,r12; sub	r67,r47,r41 }
	{ adds	r65,0x0,r0; adds	r66,0x0,r40; adds	r68,0x0,r45; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r15,0x20,r12; adds	r1,0x0,r63; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000008AAA0; }

l400000000008B1E0:
	{ ld8	r14,[r15]; nop.m	0x0; adds	r38,0x1,r38; }
	{ st8	[r14],r45; sxt4	r41,r38; br.cond.sptk.few	400000000008A6A0 }

l400000000008B200:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ nop.m	0x0; (p07) adds	r14,0x0,r8; (p07) br.cond.spnt.few	400000000008B100; }

l400000000008B21C:
	{ (p55) cmp.lt.unc	p63,p09,r127,r36; zxt1	r64,r64; br.cond.sptk.few	400000000008B41C }

l400000000008B220:
	{ adds	r38,0x1,r38; nop.m	0x0; addl	r42,1,r0; }
	{ nop.m	0x0; sxt4	r41,r38; br.cond.sptk.few	400000000008A6A0 }

l400000000008B240:
	{ adds	r65,0x0,r40; nop.m	0x0; adds	r66,0x0,r35 }
	{ adds	r67,0x0,r59; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C020; }
	{ adds	r1,0x0,r63; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	400000000008A9E0 }

l400000000008B270:
	{ add	r38,r38,r53; adds	r65,0x0,r32; adds	r66,0x0,r46 }
	{ adds	r67,0x0,r35; adds	r68,0x0,r35; adds	r69,0x0,r36; }
	{ st4	[r38],r46; adds	r70,0x0,r51; br.call.sptk.many	b0,fn400000000008A3C0; }
	{ ld4	r38,[r46]; adds	r1,0x0,r63; adds	r38,0x1,r38; }
	{ nop.m	0x0; sxt4	r41,r38; br.cond.sptk.few	400000000008A6A0; }

l400000000008B2C0:
	{ ld8	r14,[r45]; adds	r15,0x28,r12; sub	r67,r47,r41 }
	{ adds	r65,0x0,r0; adds	r66,0x0,r40; adds	r68,0x0,r45; }
	{ st8	[r14],r15; addl	r42,1,r0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r15,0x28,r12; adds	r1,0x0,r63; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000008B200; }

l400000000008B310:
	{ ld8	r14,[r15]; nop.m	0x0; adds	r38,0x1,r38; }
	{ st8	[r14],r45; sxt4	r41,r38; br.cond.sptk.few	400000000008A6A0 }

l400000000008B330:
	{ addl	r67,-6820,r1; adds	r38,0x1,r38; adds	r65,0x0,r32 }
	{ adds	r66,0x0,r46; adds	r68,0x0,r51; nop.i	0x0 }
	{ st4	[r38],r46; ld8	r67,[r67]; br.call.sptk.many	b0,fn4000000000088B40; }
	{ ld4	r38,[r46]; adds	r1,0x0,r63; adds	r38,0x1,r38; }
	{ nop.m	0x0; sxt4	r41,r38; br.cond.sptk.few	400000000008A6A0 }

l400000000008B380:
	{ adds	r65,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r63; adds	r49,0x0,r8; br.cond.sptk.few	400000000008A4C0 }

l400000000008B3A0:
	{ adds	r65,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r63; adds	r53,0x0,r8; br.cond.sptk.few	400000000008A560 }

l400000000008B3C0:
	{ nop.m	0x0; adds	r65,0x2,r52; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r65,r65; br.call.sptk.many	b0,xmalloc; }
	{ ld4	r14,[r33]; adds	r1,0x0,r63; adds	r39,0x0,r8 }
	{ adds	r65,0x0,r8; ld4	r15,[r40]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r66,r14; sxt4	r67,r15; }
	{ add	r66,r32,r66; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B920; }
	{ ld4	r14,[r40]; adds	r1,0x0,r63; sxt4	r14,r14; }
	{ add	r14,r39,r14; nop.i	0x0; nop.i	0x0 }
	{ st1	[r0],r14; st4	[r38],r33; br.cond.sptk.few	400000000008ADE0 }

l400000000008B450:
	{ addl	r66,-6804,r1; adds	r65,0x0,r0; addl	r67,5,r0; }
	{ ld8	r66,[r66]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r63; adds	r65,0x0,r8; nop.i	0x0 }
	{ adds	r66,0x0,r36; adds	r67,0x0,r32; br.call.sptk.many	b0,report_error; }
	{ adds	r1,0x0,r63; addl	r15,1,r0; addl	r65,2,r0; }
	{ addl	r14,9044,r1; nop.m	0x0; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,fn4000000000085DC0; }
	{ nop.m	0x0; break.f	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

;; extract_process_subst: 400000000008B500
;;   Called from:
;;     400000000008B4FC (in fn400000000008A3C0)
;;     400000000008C686 (in skip_to_delim)
;;     40000000000A272C (in fn40000000000A1400)
extract_process_subst proc
	{ alloc	r16,ar.pfs,0x6,0x0,0x6; adds	r14,0x0,r33; nop.i	0x0 }
	{ addl	r35,-6836,r1; addl	r36,-6828,r1; adds	r33,0x0,r34; }
	{ ld8	r35,[r35]; nop.m	0x0; adds	r34,0x0,r14 }
	{ adds	r37,0x0,r0; ld8	r36,[r36]; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x6,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn400000000008A3C0; }
400000000008B550 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
400000000008B560 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000008B570 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; extract_arithmetic_subst: 400000000008B580
extract_arithmetic_subst proc
	{ alloc	r16,ar.pfs,0x6,0x0,0x6; addl	r34,-6788,r1; addl	r35,-6780,r1 }
	{ addl	r36,-6772,r1; ld8	r34,[r34]; adds	r37,0x0,r0 }
	{ ld8	r35,[r35]; ld8	r36,[r36]; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x6,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn400000000008A3C0; }
400000000008B5C0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
400000000008B5D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000008B5E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000008B5F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; extract_command_subst: 400000000008B600
;;   Called from:
;;     40000000000894DC (in fn4000000000089000)
;;     400000000008A37C (in fn4000000000089DC0)
;;     400000000008AFBC (in fn400000000008A3C0)
;;     400000000008C09C (in fn400000000008B740)
;;     40000000000C4FEC (in fn40000000000C4A00)
extract_command_subst proc
	{ alloc	r39,ar.pfs,0xD,0x0,0x9; ld4	r42,[r33]; mov	r38,b6 }
	{ adds	r37,0x0,r34; adds	r40,0x0,r1; adds	r43,0x0,r33; }
	{ nop.m	0x0; sxt4	r42,r42; adds	r41,0x0,r32; }
	{ nop.m	0x0; add	r42,r32,r42; nop.i	0x0; }
	{ ld1	r14,[r42]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x28,r14; addl	r14,7548,r1; (p07) br.cond.dpnt.few	400000000008B6B0; }

l400000000008B660:
	{ ld4	r14,[r14]; cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; }
	{ (p06) adds	r44,0x0,r0; (p07) addl	r44,64,r0; nop.i	0x0; }

l400000000008B676:
	{ Invalid; nop; nop; }

l400000000008B67C:
	{ shladd	r0,r1,0x2,r0; zxt1	r9,r3; break.i	0x1000 }
	{ (p02) nop; invala; break.i	0x1000 }
	{ Invalid; break.i	0x1000; Invalid }
	{ ld8	r0,[r0]; (p04) ldfps	f49,f95,[r114]; Invalid }

l400000000008B6B0:
	{ addl	r34,-6844,r1; addl	r35,-6836,r1; nop.b	0x0 }
	{ addl	r36,-6828,r1; or	r37,0x8,r37; mov.spnt	b0,r38,400000000008B6C0; }
	{ nop.m	0x0; ld8	r34,[r34]; mov.i	ar.pfs,r39 }
	{ ld8	r35,[r35]; ld8	r36,[r36]; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x6,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn400000000008A3C0; }
400000000008B700 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
400000000008B710 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000008B720 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000008B730 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn400000000008B740: 400000000008B740
;;   Called from:
;;     40000000000A2E2C (in fn40000000000A1400)
;;     40000000000A62BC (in fn40000000000A5B80)
fn400000000008B740 proc
	{ alloc	r53,ar.pfs,0x1D,0x0,0x19; adds	r12,0xFFFFFFFFFFFFFFE0,r12; mov	r56,LC }
	{ ld4	r14,[r33]; addl	r43,-9996,r1; adds	r54,0x0,r1; }
	{ addl	r51,7548,r1; adds	r44,0x18,r12; sxt4	r36,r14 }
	{ ld8	r43,[r43]; adds	r46,0x0,r0; adds	r41,0x0,r0; }
	{ adds	r39,0x0,r0; add	r57,r32,r36; mov	r55,pr }
	{ st8	[r0],r44; cmp4.eq	p16,p17,0x0,r34; adds	r35,0x0,r0; }
	{ nop.m	0x0; mov	r52,b4; adds	r38,0x0,r0 }
	{ (p16) addl	r42,1,r0; addl	r50,36,r0; br.call.sptk.many	b0,fn400000000001B6C0; }

l400000000008B7B6:
	{ Invalid; (p32) nop; (p16) nop }
	{ Invalid; nop; (p16) nop }
	{ Invalid; nop }

l400000000008B7DC:
	{ (p46) nop; nop; }
	{ Invalid; break.x	0x8000001000; }
	{ Invalid; (p04) nop; epc }
	{ Invalid; (p04) nop; }
	{ (p16) cmp.eq	p37,p03,r0,r64; Invalid; cmp.eq	p00,p00,r32,r0; }
	{ nop; break.i	0x1000; break.i	0x1000; }
	{ nop.m	0x80; break.i	0x1000; (p02) break.i	0x101E0 }

l400000000008B840:
	{ nop.m	0x0; zxt1	r16,r15; nop.i	0x0; }
	{ adds	r14,0x0,r16; cmp4.eq	p07,p06,0x0,r16; (p07) br.cond.dpnt.few	400000000008BA10; }

l400000000008B860:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r39; (p06) br.cond.dptk.few	400000000008BBE0; }

l400000000008B870:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x22,r14; nop.i	0x0; }
	{ nop.m	0x0; tbit.z.or.andcm	p07,p06,r42,0x0; (p06) br.cond.dptk.few	400000000008BB60 }

l400000000008B890:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dptk.few	400000000008B8E0; }

l400000000008B8A0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r46; (p06) br.cond.dptk.few	400000000008BB60 }

l400000000008B8B0:
	{ nop.m	0x0; sxt4	r14,r14; shladd	r14,r14,0x2,r48; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x6; (p07) br.cond.dptk.few	400000000008BB60; }

l400000000008B8E0:
	{ add	r39,r32,r37; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r54; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	400000000008BB90 }

l400000000008B900:
	{ ld1	r15,[r39]; addl	r8,1,r0; sxt1	r15,r15; }
	{ nop.m	0x0; extr.u	r17,r15,5,3; and	r18,0x1F,r15; }
	{ shladd	r17,r17,0x2,r43; ld4	r17,[r17]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r17,r17,r18; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r17,0x0; (p07) br.cond.dpnt.few	400000000008BAB0; }

l400000000008B950:
	{ adds	r18,0xFFFFFFFFFFFFFFFF,r8; cmp.eq	p06,p07,0x0,r8; add	r16,r40,r38 }
	{ add	r17,r32,r37,0x1; adds	r14,0x0,r35; mov.i	LC,r18; }
	{ nop.m	0x0; (p07) mov.i	LC,r18; (p06) mov.i	LC,0x0; }

l400000000008B97C:
	{ nop; cmp.lt	p00,p00,r32,r0; zxt1	r64,r64 }

l400000000008B980:
	{ nop.m	0x0; adds	r14,0x1,r14; nop.i	0x0 }
	{ st1	[r16],r1,1; nop.m	0x0; br.cloop.sptk.few	400000000008BA60; }

l400000000008B9A0:
	{ add	r15,r36,r14; nop.i	0x0; sub	r15,r15,r35; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000008B9C0:
	{ nop.m	0x0; adds	r36,0x0,r15; sxt4	r37,r15 }
	{ adds	r35,0x0,r14; adds	r39,0x0,r0; sxt4	r38,r14; }
	{ add	r15,r32,r37; ld1	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; zxt1	r16,r15; }
	{ adds	r14,0x0,r16; cmp4.eq	p07,p06,0x0,r16; (p06) br.cond.dptk.few	400000000008B860 }

l400000000008BA10:
	{ add	r38,r40,r38; nop.m	0x0; adds	r8,0x0,r40; }
	{ st1	[r0],r38; st4	[r36],r33; mov	pr,r55,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r53; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r56; mov.spnt	b0,r52,400000000008BA40 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0 }

l400000000008BA60:
	{ ld1	r15,[r17],1; nop.m	0x0; adds	r14,0x1,r14; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0 }
	{ st1	[r16],r1,1; add	r15,r36,r14; br.cloop.sptk.few	400000000008BA60; }

l400000000008BA90:
	{ sub	r15,r15,r35; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000008B9C0; }

l400000000008BAB0:
	{ adds	r15,0x10,r12; ld8	r14,[r44]; adds	r57,0x0,r0 }
	{ adds	r58,0x0,r39; sub	r59,r47,r39; adds	r60,0x0,r44; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r18,0x10,r12; adds	r1,0x0,r54; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000008C040; }

l400000000008BB00:
	{ nop.m	0x0; ld8	r14,[r18]; addl	r8,1,r0 }
	{ ld1	r15,[r39]; st8	[r14],r44; sxt1	r15,r15 }

l400000000008BB20:
	{ adds	r18,0xFFFFFFFFFFFFFFFF,r8; cmp.eq	p06,p07,0x0,r8; nop.i	0x0 }
	{ add	r16,r40,r38; add	r17,r32,r37,0x1; adds	r14,0x0,r35; }
	{ nop.m	0x0; mov.i	LC,r18; (p07) mov.i	LC,r18; }

l400000000008BB50:
	{ nop.m	0x0; (p06) mov.i	LC,0x0; br.cond.sptk.few	400000000008B980 }

l400000000008BB5C:
	{ (p49) cmp.lt.unc	p63,p09,r63,r36; (p04) nop; Invalid }

l400000000008BB60:
	{ add	r38,r40,r38; adds	r35,0x1,r35; add	r39,r32,r37; }
	{ st1	[r45],r38; sxt4	r38,r35; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r54; cmp.ltu	p07,p06,0x1,r8; (p07) br.cond.dptk.few	400000000008B900 }

l400000000008BB90:
	{ adds	r36,0x1,r36; ld1	r14,[r39]; add	r38,r40,r38 }
	{ adds	r35,0x1,r35; adds	r39,0x0,r0; sxt4	r37,r36 }
	{ st1	[r14],r38; sxt4	r38,r35; add	r14,r32,r37; }
	{ nop.m	0x0; ld1	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; br.cond.sptk.few	400000000008B840 }

l400000000008BBE0:
	{ cmp4.eq	p07,p06,0x5C,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000008BCD0; }

l400000000008BBF0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r41; (p06) br.cond.dptk.few	400000000008BC60; }

l400000000008BC00:
	{ cmp4.eq	p07,p06,0x60,r14; adds	r36,0x1,r36; add	r38,r40,r38 }
	{ adds	r35,0x1,r35; (p06) addl	r14,1,r0; sxt4	r37,r36 }

l400000000008BC1C:
	{ nop; nop }
	{ cmp4.eq.and	p35,p43,r22,r0; (p05) nop }

l400000000008BC36:
	{ Invalid; (p07) nop; break.b	0x80000 }
	{ (p07) fwb; nop; break.b	0x80000 }
	{ (p07) break.m	0x50780; nop; nop }

l400000000008BC60:
	{ cmp4.eq	p07,p06,0x60,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000008BD00; }

l400000000008BC70:
	{ cmp4.eq	p07,p06,0x24,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000008BD50; }

l400000000008BC80:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x22,r14; (p06) br.cond.dptk.few	400000000008B8E0 }

l400000000008BC90:
	{ nop.m	0x0; nop.i	0x0; (p16) br.cond.dptk.few	400000000008BF80 }

l400000000008BCA0:
	{ adds	r36,0x1,r36; xor	r46,0x1,r46; sxt4	r37,r36; }
	{ add	r14,r32,r37; ld1	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; br.cond.sptk.few	400000000008B840 }

l400000000008BCD0:
	{ adds	r36,0x1,r36; addl	r39,1,r0; sxt4	r37,r36; }
	{ add	r14,r32,r37; ld1	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; br.cond.sptk.few	400000000008B840 }

l400000000008BD00:
	{ adds	r36,0x1,r36; nop.m	0x0; add	r38,r40,r38 }
	{ adds	r35,0x1,r35; addl	r41,1,r0; sxt4	r37,r36 }
	{ st1	[r15],r38; sxt4	r38,r35; add	r14,r32,r37; }
	{ nop.m	0x0; ld1	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; br.cond.sptk.few	400000000008B840 }

l400000000008BD50:
	{ add	r49,r32,r37,0x1; ld1	r14,[r49]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r14; nop.i	0x0; }
	{ cmp4.eq	p08,p09,0x28,r15; cmp4.eq	p06,p07,0x7B,r15; (p08) addl	r14,1,r0; }

l400000000008BD80:
	{ nop.m	0x0; (p09) adds	r14,0x0,r0; nop.i	0x0; }

l400000000008BD8C:
	{ Invalid; cmp.lt	p00,p00,r32,r0; (p08) mov	pr,r99,0xE580 }
	{ (p26) cmp.lt.unc	p63,p08,r63,r37; Invalid; Invalid }

l400000000008BDA0:
	{ cmp4.eq	p06,p07,0x0,r14; adds	r36,0x2,r36; adds	r14,0x20,r12 }
	{ adds	r57,0x0,r32; adds	r58,0x20,r12; addl	r59,1,r0; }
	{ st4	[r36],r14; nop.m	0x0; adds	r60,0x0,r0 }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	400000000008C080; br.call.sptk.many	b0,fn4000000000089000; }

l400000000008BDDC:
	{ (p17) cmp.lt.unc	p58,p08,r63,r44; (p17) cmp.lt.unc	p32,p16,r8,r64; (p04) brp.sptk	b1,400000000008C27C }
	{ cmp.eq	p54,p09,r0,r66; (p01) nop; (p36) cmp.eq.unc	p32,p16,r8,r64 }
	{ break.m	0xC8308; cmp.lt	p00,p00,r32,r0; (p01) break.i	0x161C0 }
	{ nop; Invalid; break.i	0x1000 }
	{ cmp.lt	p00,p09,r1,r0; (p01) cmp.eq.unc	p10,p16,r3,r0; Invalid }
	{ invala; Invalid; mov	pr,r32,0x0 }
	{ (p14) nop; zxt4	r0,r0; break.b	0x1000 }

l400000000008BE40:
	{ addl	r17,1,r0; nop.m	0x0; nop.i	0x0 }

l400000000008BE50:
	{ ld1	r14,[r8]; sxt4	r15,r35; adds	r16,0x1,r8; }
	{ nop.m	0x0; sxt1	r14,r14; add	r15,r40,r15; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	400000000008BEB0; }

l400000000008BE80:
	{ st1	[r15],r1,1; nop.m	0x0; adds	r35,0x1,r35; }
	{ ld1	r14,[r16],1; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	400000000008BE80; }

l400000000008BEB0:
	{ adds	r15,0x20,r12; adds	r18,0x20,r12; sxt4	r38,r35 }
	{ cmp4.eq	p07,p06,0x0,r17; ld4	r15,[r15]; nop.i	0x0 }
	{ ld4.a	r36,[r18]; nop.m	0x0; sxt4	r14,r15 }
	{ add	r15,r40,r38; sxt4	r37,r36; add	r14,r32,r14 }
	{ add	r49,r32,r37; ld1	r14,[r14]; nop.i	0x0; }
	{ st1	[r14],r15; chk.a.clr	r36,400000000008C100; nop.i	0x0 }

l400000000008BF0C:
	{ nop; break.i	0x1000; break.i	0x1000 }

l400000000008BF10:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }
	{ ld1	r14,[r49]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p08,p09,0x0,r14; (p09) adds	r36,0x1,r36; (p09) adds	r35,0x1,r35; }

l400000000008BF3C:
	{ Invalid; Invalid; Invalid }

l400000000008BF40:
	{ nop.m	0x0; sxt4	r37,r36; sxt4	r38,r35; }
	{ (p09) add	r49,r32,r37; nop.i	0x0; (p06) br.cond.dpnt.few	400000000008BFD0; }

l400000000008BF56:
	{ chk.a.nc	r0,3FFFFFFFFF08C756; nop; break.i	0x80000 }

l400000000008BF60:
	{ nop.m	0x0; ld1	r15,[r49]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; br.cond.sptk.few	400000000008B840 }

l400000000008BF80:
	{ add	r38,r40,r38; adds	r36,0x1,r36; adds	r8,0x0,r40; }
	{ st1	[r0],r38; st4	[r36],r33; mov	pr,r55,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r53; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r56; mov.spnt	b0,r52,400000000008BFB0 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0; }

l400000000008BFD0:
	{ adds	r57,0x0,r8; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ ld1	r15,[r49]; nop.m	0x0; adds	r1,0x0,r54; }
	{ nop.m	0x0; sxt1	r15,r15; br.cond.sptk.few	400000000008B840 }

l400000000008C000:
	{ nop.m	0x0; ld4	r14,[r51]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; (p07) adds	r8,0x2,r37; (p07) adds	r17,0x0,r0; }

l400000000008C01C:
	{ invala; mov	pr,r32,0x0; (p01) mov	pr,r2,0x8010 }

l400000000008C020:
	{ nop.m	0x0; (p07) add	r8,r32,r8; (p07) br.cond.dptk.few	400000000008BE50 }

l400000000008C02C:
	{ Invalid; nop; (p18) nop }

l400000000008C030:
	{ nop.m	0x0; addl	r17,1,r0; br.cond.sptk.few	400000000008BE50; }

l400000000008C040:
	{ cmp.eq	p06,p07,0x0,r8; (p07) ld1	r15,[r39]; nop.i	0x0; }

l400000000008C04C:
	{ Invalid; cmp4.eq.or.andcm	p00,p32,r32,r0; (p01) mov	pr,r3,0xC0 }
	{ (p08) cmp.eq.unc	p63,p09,r127,r36; Invalid; break.i	0x1000 }

l400000000008C060:
	{ ld1	r15,[r39]; nop.m	0x0; addl	r8,1,r0; }
	{ nop.m	0x0; sxt1	r15,r15; br.cond.sptk.few	400000000008BB20 }

l400000000008C080:
	{ adds	r58,0x0,r14; nop.m	0x0; adds	r59,0x0,r0 }
	{ add	r38,r40,r38; nop.m	0x0; br.call.sptk.many	b0,extract_command_subst; }
	{ adds	r14,0x1,r35; ld1.a	r15,[r49]; adds	r1,0x0,r54 }
	{ st1	[r50],r38; adds	r35,0x2,r35; cmp.eq	p07,p06,0x0,r8; }
	{ nop.m	0x0; sxt4	r14,r14; nop.i	0x0 }
	{ ld1.c.clr	r15,[r49]; add	r14,r40,r14; nop.i	0x0; }
	{ st1	[r15],r14; nop.i	0x0; (p06) br.cond.dptk.few	400000000008BE40 }

l400000000008C0F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000008C000 }

l400000000008C100:
	{ ld4	r36,[r18]; nop.m	0x0; sxt4	r37,r36; }
	{ nop.m	0x0; add	r49,r32,r37; br.cond.sptk.few	400000000008BF10; }
400000000008C120 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000008C130 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; skip_to_delim: 400000000008C140
;;   Called from:
;;     400000000008E11C (in split_at_delims)
;;     40000000000B3AFC (in setup_ignore_patterns)
skip_to_delim proc
	{ alloc	r51,ar.pfs,0x1C,0x0,0x16; adds	r12,0xFFFFFFFFFFFFFFC0,r12; sxt4	r36,r33 }
	{ addl	r43,7548,r1; adds	r52,0x0,r1; and	r46,0x2,r35; }
	{ adds	r40,0x38,r12; add	r54,r32,r36; mov	r53,pr }
	{ adds	r41,0x0,r0; adds	r44,0x0,r0; sxt4	r37,r33; }
	{ nop.m	0x0; mov	r50,b2; nop.i	0x0 }
	{ st8	[r0],r40; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; tbit.z	p06,p07,r35,0x0; adds	r1,0x0,r52 }
	{ nop.m	0x0; add	r45,r8,r36; nop.b	0x0; }
	{ (p07) addl	r14,1,r0; addl	r42,-9996,r1; nop.b	0x0 }

l400000000008C1C6:
	{ Invalid; nop; (p48) nop }
	{ break.m	0x4000; (p08) cmp.ltu	p04,p40,r35,r17; (p01) nop }

l400000000008C1E6:
	{ break.m	0x4000; (p03) nop; (p32) nop }
	{ break.m	0x4000; addp4	r0,0x0,r1; (p33) nop }

l400000000008C206:
	{ (p11) chk.a.nc	f8,3FFFFFFFFFA97C36; (p07) nop; break.i	0x80000 }

l400000000008C210:
	{ nop.m	0x0; cmp4.eq	p18,p19,0x0,r14; cmp4.eq	p21,p20,0x0,r14 }

l400000000008C220:
	{ add	r38,r32,r37; ld1	r14,[r38]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r55,r14; (p16) adds	r14,0x0,r0; }

l400000000008C240:
	{ adds	r36,0x0,r55; adds	r39,0x0,r55; cmp4.eq	p07,p06,0x0,r55 }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	400000000008C700; (p16) br.cond.dptk.few	400000000008C290; }

l400000000008C25C:
	{ (p02) cmp.lt	p00,p09,r0,r33; czx1.r	r8,r97; break.i	0x1000 }

l400000000008C260:
	{ cmp4.eq	p06,p07,0x22,r36; nop.m	0x0; cmp4.eq	p08,p09,0x27,r36; }
	{ (p08) addl	r14,1,r0; nop.m	0x0; (p06) addl	r15,1,r0; }

l400000000008C276:
	{ adds	r0,0xFFFFFFFFFFFFE000,r1; (p07) dep	r1,r0,r0,43,9; (p34) cmp.eq.or.andcm	p03,p00,r0,r0 }

l400000000008C280:
	{ (p09) adds	r14,0x0,r0; (p07) adds	r15,0x0,r0; or	r14,r14,r15 }

l400000000008C286:
	{ Invalid; (p07) nop; break.b	0x80000; }

l400000000008C28C:
	{ Invalid; cmp.eq	p00,p00,r32,r0; mov	pr,r75,0xE600; }

l400000000008C290:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r44; (p06) br.cond.dptk.few	400000000008C390; }

l400000000008C2A0:
	{ cmp4.eq	p07,p06,0x5C,r39; (p07) adds	r33,0x1,r33; (p07) addl	r44,1,r0; }

l400000000008C2AC:
	{ Invalid; Invalid; Invalid }

l400000000008C2B0:
	{ nop.m	0x0; sxt4	r37,r33; (p07) br.cond.dpnt.few	400000000008C220; }

l400000000008C2C0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r41; (p06) br.cond.dptk.few	400000000008C430; }

l400000000008C2D0:
	{ cmp4.eq	p07,p06,0x60,r39; (p06) addl	r39,1,r0; nop.i	0x0; }

l400000000008C2DC:
	{ cmp4.eq.or.andcm	p00,p49,r1,r0; zxt1	r0,r64; break.i	0x1000 }

l400000000008C2E6:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ add	r0,r0,r1; nop; (p48) nop }
	{ chk.a.nc	r0,3FFFFFFFFF08CB06; nop; (p48) nop }

l400000000008C310:
	{ ld1	r15,[r38]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; extr.u	r16,r15,5,3; and	r14,0x1F,r15; }
	{ shladd	r15,r16,0x2,r42; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r15,r15,r14; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r15,0x0; (p07) br.cond.dpnt.few	400000000008C910 }

l400000000008C360:
	{ addl	r14,1,r0; nop.m	0x0; nop.i	0x0; }

l400000000008C370:
	{ nop.m	0x0; add	r33,r14,r33; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r37,r33; br.cond.sptk.few	400000000008C220 }

l400000000008C390:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r52; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	400000000008C540; }

l400000000008C3B0:
	{ ld1	r15,[r38]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; extr.u	r16,r15,5,3; and	r14,0x1F,r15; }
	{ shladd	r15,r16,0x2,r42; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r15,r15,r14; tbit.z	p07,p06,r15,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	400000000008C890; }

l400000000008C400:
	{ (p06) addl	r14,1,r0; nop.m	0x0; nop.i	0x0; }

l400000000008C406:
	{ break.m	0x4000; nop; (p16) nop }

l400000000008C410:
	{ add	r33,r14,r33; nop.m	0x0; adds	r44,0x0,r0; }
	{ nop.m	0x0; sxt4	r37,r33; br.cond.sptk.few	400000000008C220 }

l400000000008C430:
	{ cmp4.eq	p07,p06,0x60,r39; nop.m	0x0; or	r49,r46,r14; }
	{ (p07) adds	r33,0x1,r33; nop.m	0x0; (p07) addl	r41,1,r0; }

l400000000008C446:
	{ addp4	r0,0xFFFFFFFFFFFFE000,r1; (p20) nop; cmp.lt	p00,p00,r0,r32 }

l400000000008C450:
	{ nop.m	0x0; sxt4	r37,r33; (p07) br.cond.dpnt.few	400000000008C220; }

l400000000008C460:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r49; (p07) br.cond.dptk.few	400000000008C490 }

l400000000008C470:
	{ adds	r54,0x0,r34; adds	r55,0x0,r39; br.call.sptk.many	b0,mbschr; }
	{ adds	r1,0x0,r52; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dpnt.few	400000000008C700; }
