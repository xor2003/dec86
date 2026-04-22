;;; Segment .init (4000000000019230)

;; _init: 4000000000019230
;;   Called from:
;;     4000000000137D1C (in __libc_csu_init)
_init proc
	{ alloc	r34,ar.pfs,0x3,0x0,0x3; adds	r32,0x0,r12; mov	r33,b1 }
	{ adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.i	0x0; nop.i	0x0; }
	{ adds	r12,0x0,r32; mov.i	ar.pfs,r34; mov.spnt	b0,r33,4000000000019250 }
	{ nop.m	0x0; nop.i	0x0; br.ret	b0; }
