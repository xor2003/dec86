;;; Segment .text (400000000001C480)

l400000000006C510:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,shell_version_string; }
	{ adds	r1,0x0,r50; adds	r54,0x0,r0; adds	r53,0x0,r8; }
	{ nop.m	0x0; addl	r52,-1516,r1; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r1,0x0,r50; addl	r52,-1508,r1; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,unbind_variable; }
	{ adds	r1,0x0,r50; addl	r52,-1508,r1; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,make_new_array_variable; }
	{ adds	r1,0x0,r50; adds	r14,0x8,r8; nop.i	0x0 }
	{ addl	r54,32,r0; adds	r38,0x0,r8; adds	r52,0x10,r12; }
	{ addl	r15,6092,r1; ld8	r34,[r14]; adds	r38,0x28,r38; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld8	r53,[r15]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BAE0; }
	{ adds	r1,0x0,r50; nop.m	0x0; adds	r52,0x10,r12 }
	{ addl	r53,46,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B680; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r36,0x0,r8; adds	r1,0x0,r50 }
	{ adds	r53,0x0,r0; adds	r54,0x10,r12; adds	r52,0x0,r34; }
	{ (p07) st1	[r36],r1,1; nop.i	0x0; br.call.sptk.many	b0,array_insert; }

l400000000006C626:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; nop; (p16) nop }
	{ Invalid; (p32) nop; (p16) nop }
	{ Invalid; (p27) nop; (p32) nop }
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ (p26) fwb; nop; break.i	0x80000 }
	{ (p26) break.m	0x59A00; (p32) nop; (p16) nop }
	{ Invalid; nop; (p16) nop }
	{ Invalid; (p32) nop; (p16) nop }
	{ Invalid; (p27) nop; (p32) nop }
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ (p26) fwb; nop; break.i	0x80000 }
	{ (p26) break.m	0x59A00; (p32) nop; (p16) nop }
	{ Invalid; nop; (p16) nop }
	{ Invalid; (p32) nop; (p16) nop }
	{ Invalid; (p26) nop; (p32) nop }
	{ break.m	0x4000; nop; (p32) nop }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; (p26) nop; break.i	0x80000 }
	{ Invalid; nop; (p32) nop }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ (p07) fwb; (p27) nop; (p48) nop }
	{ Invalid; (p26) nop; break.i	0x80000 }
	{ mf.a; nop; break.i	0x80000 }
	{ (p26) fwb; nop; nop }
	{ chk.a.nc	r0,3FFFFFFFFF06CFB6; nop; nop }

l400000000006C7C0:
	{ ld8	r52,[r52]; br.call.sptk.many	b0,bind_variable; nop.b	0x0; }
	{ adds	r1,0x0,r50; nop.m	0x0; nop.i	0x0; }

l400000000006C7E0:
	{ nop.m	0x0; addl	r52,-1492,r1; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r14,0x28,r8; nop.m	0x0; adds	r1,0x0,r50 }
	{ cmp.eq	p07,p06,0x0,r8; nop.m	0x0; (p07) br.cond.dpnt.few	400000000006DBE0; }

l400000000006C820:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0xF; (p07) br.cond.dpnt.few	400000000006D720 }

l400000000006C840:
	{ addl	r34,6116,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000006C920 }

l400000000006C870:
	{ addl	r14,6456,r1; nop.m	0x0; adds	r53,0x0,r0; }
	{ nop.m	0x0; ld4	r52,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r52; (p07) addl	r52,-1708,r1; nop.i	0x0; }

l400000000006C89C:
	{ pavg2.raz	r0,r1,r0; (p06) nop; Invalid }

l400000000006C8A6:
	{ (p26) fwb; nop; (p01) nop; }

l400000000006C8AC:
	{ pshladd2	r0,r1,1,r0; Invalid; break.i	0x1000 }

l400000000006C8B6:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; (p26) nop; break.i	0x80000 }
	{ Invalid; nop; nop }
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; (p26) nop; break.b	0x80000 }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; nop; break.i	0x80000 }

l400000000006C920:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000060240; }
	{ ld4	r14,[r37]; nop.m	0x0; adds	r1,0x0,r50; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dpnt.few	400000000006D400 }

l400000000006C950:
	{ ld4	r52,[r35]; nop.m	0x0; adds	r53,0x10,r12 }
	{ addl	r54,11,r0; nop.m	0x0; br.call.sptk.many	b0,inttostr; }
	{ adds	r1,0x0,r50; adds	r34,0x0,r8; addl	r52,-1436,r1; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x0,r50; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	400000000006DB90 }

l400000000006C9A0:
	{ adds	r15,0x4,r35; ld4	r14,[r35]; adds	r53,0x10,r12 }
	{ addl	r54,11,r0; ld4	r52,[r15]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,r14,r52; addp4	r52,r52,r0; (p06) br.cond.dpnt.few	400000000006C9F0; }

l400000000006C9D0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,inttostr; }
	{ nop.m	0x0; adds	r1,0x0,r50; adds	r34,0x0,r8; }

l400000000006C9F0:
	{ nop.m	0x0; addl	r52,-1428,r1; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x0,r50; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	400000000006D9A0; }

l400000000006CA20:
	{ nop.m	0x0; addl	r52,-1420,r1; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r14,0x28,r8; nop.m	0x0; adds	r1,0x0,r50 }
	{ cmp.eq	p06,p07,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	400000000006CA80; }

l400000000006CA60:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0xF; (p07) br.cond.dpnt.few	400000000006D260 }

l400000000006CA80:
	{ nop.m	0x0; addl	r52,-1412,r1; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x0,r50; cmp.eq	p06,p07,0x0,r8; adds	r34,0x8,r8; }
	{ (p06) adds	r53,0x0,r0; addl	r35,7212,r1; (p06) br.cond.dpnt.few	400000000006CB00; }

l400000000006CAB6:
	{ (p17) chk.a.clr	r44,3FFFFFFFFF288AC6; nop; break.b	0x80000 }

l400000000006CAC0:
	{ nop.m	0x0; adds	r53,0x0,r35; nop.i	0x0 }
	{ ld8	r52,[r34]; nop.m	0x0; br.call.sptk.many	b0,legal_number; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r8; adds	r1,0x0,r50 }
	{ ld8	r53,[r34]; (p07) st8	[r0],r35; nop.i	0x0 }

l400000000006CAFC:
	{ Invalid; Invalid; cmp.lt	p00,p00,r32,r0 }

l400000000006CB00:
	{ addl	r52,-1412,r1; nop.m	0x0; adds	r54,0x0,r0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r1,0x0,r50; adds	r14,0x18,r8; adds	r8,0x20,r8 }
	{ adds	r53,0x0,r0; adds	r54,0x0,r0; addl	r15,-2124,r1 }
	{ addl	r52,-1404,r1; ld8	r15,[r15]; nop.i	0x0 }
	{ ld8	r52,[r52]; st8	[r15],r14; addl	r14,-2132,r1; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ st8	[r14],r8; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r1,0x0,r50; adds	r14,0x18,r8; adds	r8,0x20,r8 }
	{ adds	r53,0x0,r0; adds	r54,0x0,r0; addl	r15,-2164,r1 }
	{ addl	r52,-1396,r1; st8	[r0],r8; nop.i	0x0; }
	{ ld8	r15,[r15]; ld8	r52,[r52]; nop.i	0x0; }
	{ st8	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r1,0x0,r50; adds	r14,0x18,r8; adds	r8,0x20,r8 }
	{ adds	r53,0x0,r0; adds	r54,0x0,r0; addl	r15,-2212,r1 }
	{ addl	r52,-1388,r1; ld8	r15,[r15]; nop.i	0x0 }
	{ ld8	r52,[r52]; st8	[r15],r14; addl	r14,-2180,r1; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ st8	[r14],r8; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r1,0x0,r50; adds	r14,0x28,r8; adds	r16,0x18,r8 }
	{ adds	r8,0x20,r8; adds	r53,0x0,r0; adds	r54,0x0,r0; }
	{ addl	r17,-1284,r1; ld4	r15,[r14]; addl	r52,-1380,r1; }
	{ nop.m	0x0; ld8	r17,[r17]; or	r15,0x10,r15 }
	{ ld8	r52,[r52]; st8	[r17],r16; addl	r16,-2060,r1 }
	{ st4	[r15],r14; ld8	r16,[r16]; nop.i	0x0; }
	{ st8	[r16],r8; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r1,0x0,r50; adds	r14,0x28,r8; adds	r16,0x18,r8 }
	{ adds	r8,0x20,r8; adds	r53,0x0,r0; adds	r54,0x0,r0; }
	{ addl	r17,-2068,r1; ld4	r15,[r14]; addl	r52,-1372,r1; }
	{ nop.m	0x0; ld8	r17,[r17]; or	r15,0x10,r15 }
	{ ld8	r52,[r52]; st8	[r17],r16; addl	r16,-2188,r1 }
	{ st4	[r15],r14; ld8	r16,[r16]; nop.i	0x0; }
	{ st8	[r16],r8; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r1,0x0,r50; adds	r14,0x28,r8; adds	r16,0x18,r8 }
	{ adds	r8,0x20,r8; adds	r53,0x0,r0; adds	r54,0x0,r0; }
	{ addl	r17,-2140,r1; ld4	r15,[r14]; addl	r52,-1364,r1; }
	{ nop.m	0x0; ld8	r17,[r17]; or	r15,0x12,r15 }
	{ ld8	r52,[r52]; st8	[r17],r16; addl	r16,-2300,r1 }
	{ st4	[r15],r14; ld8	r16,[r16]; nop.i	0x0; }
	{ st8	[r16],r8; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r1,0x0,r50; adds	r14,0x28,r8; adds	r16,0x18,r8 }
	{ adds	r8,0x20,r8; adds	r53,0x0,r0; adds	r54,0x0,r0; }
	{ ld4	r15,[r14]; addl	r17,-2076,r1; addl	r52,-1356,r1 }
	{ st8	[r0],r8; ld8	r17,[r17]; or	r15,0x10,r15 }
	{ ld8	r52,[r52]; st8	[r17],r16; nop.i	0x0 }
	{ st4	[r15],r14; nop.m	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r1,0x0,r50; adds	r14,0x18,r8; adds	r8,0x20,r8 }
	{ adds	r55,0x0,r0; addl	r15,-2084,r1; addl	r52,-1348,r1 }
	{ addl	r53,-2092,r1; nop.m	0x0; addl	r54,-2100,r1; }
	{ ld8	r15,[r15]; ld8	r52,[r52]; nop.i	0x0; }
	{ st8	[r15],r14; nop.m	0x0; addl	r14,-2172,r1 }
	{ ld8	r53,[r53]; ld8	r54,[r54]; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ st8	[r14],r8; nop.i	0x0; br.call.sptk.many	b0,fn4000000000067B00; }
	{ adds	r1,0x0,r50; nop.m	0x0; addl	r55,16384,r0; }
	{ addl	r52,-1340,r1; addl	r53,-2028,r1; addl	r54,-2292,r1; }
	{ ld8	r52,[r52]; ld8	r53,[r53]; nop.i	0x0; }
	{ ld8	r54,[r54]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000067B00; }
	{ adds	r1,0x0,r50; nop.m	0x0; addl	r55,24576,r0; }
	{ addl	r52,-1732,r1; addl	r53,-2284,r1; addl	r54,-2292,r1; }
	{ ld8	r52,[r52]; ld8	r53,[r53]; nop.i	0x0; }
	{ ld8	r54,[r54]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000067B00; }
	{ adds	r1,0x0,r50; nop.m	0x0; addl	r55,24576,r0; }
	{ addl	r52,-1740,r1; addl	r53,-2284,r1; addl	r54,-2292,r1; }
	{ ld8	r52,[r52]; ld8	r53,[r53]; nop.i	0x0; }
	{ ld8	r54,[r54]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000067B00; }
	{ adds	r1,0x0,r50; nop.m	0x0; addl	r55,24576,r0; }
	{ addl	r52,-1332,r1; addl	r53,-2284,r1; addl	r54,-2292,r1; }
	{ ld8	r52,[r52]; ld8	r53,[r53]; nop.i	0x0; }
	{ ld8	r54,[r54]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000067B00; }
	{ adds	r1,0x0,r50; nop.m	0x0; addl	r55,24576,r0; }
	{ addl	r52,-1324,r1; addl	r53,-2284,r1; addl	r54,-2292,r1; }
	{ ld8	r53,[r53]; ld8	r54,[r54]; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000067B00; }
	{ adds	r1,0x0,r50; addl	r52,-1316,r1; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x0,r50; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	400000000006D830; }

l400000000006CFD0:
	{ nop.m	0x0; addl	r52,-1308,r1; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x0,r50; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	400000000006D8E0; }

l400000000006D000:
	{ nop.m	0x0; addl	r52,-1964,r1; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x0,r50; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	400000000006D790; }

l400000000006D030:
	{ nop.m	0x0; mov	pr,r51,0xFFFFFFFFFFFFFFFE; nop.i	0x0; }
	{ nop.m	0x0; mov.i	ar.pfs,r49; mov.spnt	b0,r48,400000000006D040 }
	{ nop.m	0x0; adds	r12,0x30,r12; br.ret	b0 }

l400000000006D060:
	{ addl	r52,-1692,r1; adds	r53,0x0,r34; addl	r54,4,r0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C020; }
	{ adds	r1,0x0,r50; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	400000000006BEF0 }

l400000000006D090:
	{ adds	r52,0x0,r34; adds	r47,0xFFFFFFFFFFFFFFFF,r38; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r8,0x3,r8; adds	r1,0x0,r50; add	r47,r35,r47; }
	{ nop.m	0x0; add	r52,r37,r8; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r52,r52; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r50; adds	r37,0x0,r8; nop.i	0x0 }
	{ adds	r52,0x0,r8; adds	r53,0x0,r35; br.call.sptk.many	b0,fn400000000001B180; }
	{ add	r14,r37,r38; nop.m	0x0; adds	r53,0x0,r34 }
	{ adds	r1,0x0,r50; nop.m	0x0; add	r52,r37,r38,0x1; }
	{ st1	[r45],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r53,0x0,r35; addl	r54,5,r0; nop.i	0x0 }
	{ adds	r1,0x0,r50; adds	r52,0x0,r37; br.call.sptk.many	b0,parse_and_execute; }
	{ ld1	r14,[r47]; adds	r1,0x0,r50; adds	r52,0x0,r35; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x29,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000006DDA0; }

l400000000006D170:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,find_function; }
	{ cmp.eq	p18,p19,0x0,r8; adds	r1,0x0,r50; adds	r34,0x0,r8; }
	{ (p19) adds	r14,0x28,r8; (p18) addl	r53,-1684,r1; (p18) adds	r52,0x0,r0 }

l400000000006D196:
	{ Invalid; Invalid; Invalid }

l400000000006D19C:
	{ Invalid; Invalid; Invalid }

l400000000006D1A0:
	{ (p18) addl	r54,5,r0; (p19) st4	[r42],r41; nop.i	0x0; }

l400000000006D1A6:
	{ mf.a; (p52) nop }

l400000000006D1AC:
	{ cmp.ge.or.andcm	p00,p41,r0,r0; (p01) nop; Invalid }

l400000000006D1B6:
	{ Invalid; Invalid; Invalid }

l400000000006D1BC:
	{ nop; cmp.ge.or.andcm	p00,p32,r0,r0; zxt1	r106,r3 }

l400000000006D1CC:
	{ Invalid; Invalid; chk.s.i	r32,3FFFFFFFFF06D1CC }

l400000000006D1D6:
	{ nop; (p32) addl	r25,2037467,r2; (p20) nop }

l400000000006D1E0:
	{ (p18) adds	r1,0x0,r50; nop.m	0x0; (p18) adds	r52,0x0,r8 }

l400000000006D1E6:
	{ nop; (p26) nop; (p20) nop }

l400000000006D1F0:
	{ (p18) adds	r53,0x0,r35; nop.m	0x0; (p18) br.call.dpnt.many	b0,report_error; }

l400000000006D1F6:
	{ nop; Invalid; (p32) addl	r3,131168,r3 }

l400000000006D200:
	{ ld1	r14,[r47]; (p18) adds	r1,0x0,r50; sxt1	r14,r14; }

l400000000006D20C:
	{ invala; cmp.eq	p00,p00,r32,r0; (p16) mov	pr,r67,0xE694; }
	{ Invalid; (p48) cmp.lt	p09,p08,r9,r96; (p01) epc }

l400000000006D220:
	{ st1	[r39],r36; adds	r14,0x28,r34; (p18) br.cond.spnt.few	400000000006BE00; }

l400000000006D230:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x3; (p06) br.cond.dptk.few	400000000006BE00 }

l400000000006D250:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000006BFA0 }

l400000000006D260:
	{ ld8	r52,[r8]; nop.i	0x0; br.call.sptk.many	b0,sv_xtracefd; }
	{ nop.m	0x0; adds	r1,0x0,r50; br.cond.sptk.few	400000000006CA80 }

l400000000006D280:
	{ adds	r14,0x1,r52; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2F,r14; (p06) br.cond.dptk.few	400000000006C430 }

l400000000006D2B0:
	{ nop.m	0x0; addl	r52,-1812,r1; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,get_string_value; }
	{ adds	r1,0x0,r50; cmp.eq	p06,p07,0x0,r8; nop.i	0x0 }
	{ adds	r36,0x0,r8; adds	r52,0x0,r8; (p06) br.cond.dpnt.few	400000000006D9F0; }

l400000000006D2F0:
	{ nop.m	0x0; addl	r35,-22276,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r50; nop.m	0x0; sxt4	r39,r8 }
	{ ld8	r52,[r38]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r50; add	r52,r8,r39,0x1; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r50; adds	r34,0x0,r8; nop.i	0x0 }
	{ adds	r52,0x0,r8; adds	r53,0x0,r36; br.call.sptk.many	b0,fn400000000001B180; }
	{ ld8	r53,[r38]; adds	r1,0x0,r50; add	r52,r34,r39; }
	{ adds	r53,0x1,r53; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r50; adds	r53,0x0,r34; adds	r54,0x0,r0; }
	{ nop.m	0x0; addl	r52,-1532,r1; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r1,0x0,r50; adds	r52,0x0,r34; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r50; addl	r52,-1524,r1; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x0,r50; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	400000000006C510 }

l400000000006D3F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000006D740; }

l400000000006D400:
	{ nop.m	0x0; addl	r52,-1476,r1; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r14,0x28,r8; nop.m	0x0; adds	r1,0x0,r50 }
	{ cmp.eq	p07,p06,0x0,r8; nop.m	0x0; (p07) br.cond.dpnt.few	400000000006DF50; }

l400000000006D440:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0xF; (p07) br.cond.dpnt.few	400000000006DB70 }

l400000000006D460:
	{ nop.m	0x0; ld4	r14,[r37]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.spnt.few	400000000006C950; }

l400000000006D480:
	{ nop.m	0x0; ld4	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000006C950 }

l400000000006D4A0:
	{ nop.m	0x0; addl	r52,-1460,r1; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,sv_history_control; }
	{ adds	r1,0x0,r50; addl	r52,-1452,r1; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,setup_history_ignore; }
	{ adds	r1,0x0,r50; addl	r52,-1444,r1; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,sv_histtimefmt; }
	{ adds	r1,0x0,r50; ld4	r52,[r35]; nop.i	0x0 }
	{ adds	r53,0x10,r12; addl	r54,11,r0; br.call.sptk.many	b0,inttostr; }
	{ adds	r1,0x0,r50; adds	r34,0x0,r8; addl	r52,-1436,r1; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x0,r50; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	400000000006C9A0 }

l400000000006D550:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000006DB90; }

l400000000006D560:
	{ addl	r14,5708,r1; nop.m	0x0; addl	r52,-1644,r1; }
	{ nop.m	0x0; ld8	r52,[r52]; nop.i	0x0; }
	{ ld8	r53,[r14]; nop.i	0x0; br.call.sptk.many	b0,set_if_not; }
	{ adds	r1,0x0,r50; addl	r14,5700,r1; addl	r52,-1636,r1; }
	{ nop.m	0x0; ld8	r52,[r52]; nop.i	0x0; }
	{ ld8	r53,[r14]; nop.i	0x0; br.call.sptk.many	b0,set_if_not; }
	{ nop.m	0x0; adds	r1,0x0,r50; br.cond.sptk.few	400000000006C110; }

l400000000006D5D0:
	{ addl	r14,6456,r1; nop.m	0x0; addl	r38,6476,r1; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000006DAD0; }

l400000000006D600:
	{ nop.m	0x0; ld8	r52,[r38]; nop.i	0x0; }
	{ ld1	r14,[r52]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2F,r14; (p07) br.cond.dpnt.few	400000000006DA00 }

l400000000006D630:
	{ addl	r35,-22276,r1; nop.m	0x0; nop.i	0x0; }
	{ adds	r34,0x18,r35; ld8	r52,[r34]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r52; nop.i	0x0; (p07) br.cond.dpnt.few	400000000006DE90; }

l400000000006D660:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r50; adds	r52,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r14,0x18,r35; adds	r1,0x0,r50; adds	r52,0x0,r8; }
	{ ld8	r53,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; adds	r1,0x0,r50; adds	r34,0x0,r8; }

l400000000006D6B0:
	{ addl	r52,-1532,r1; adds	r53,0x0,r34; adds	r54,0x0,r0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r1,0x0,r50; adds	r52,0x0,r34; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r50; addl	r52,-1524,r1; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x0,r50; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	400000000006C510 }

l400000000006D710:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000006D740 }

l400000000006D720:
	{ ld8	r52,[r8]; nop.i	0x0; br.call.sptk.many	b0,sv_strict_posix; }
	{ nop.m	0x0; adds	r1,0x0,r50; br.cond.sptk.few	400000000006C840; }

l400000000006D740:
	{ adds	r34,0x18,r35; addl	r52,-1524,r1; adds	r54,0x0,r0; }
	{ nop.m	0x0; ld8	r53,[r34]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r53; nop.i	0x0; (p07) br.cond.dpnt.few	400000000006DF00; }

l400000000006D770:
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ nop.m	0x0; adds	r1,0x0,r50; br.cond.sptk.few	400000000006C510; }

l400000000006D790:
	{ nop.m	0x0; addl	r52,-1964,r1; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,make_new_array_variable; }
	{ adds	r1,0x0,r50; adds	r14,0x28,r8; adds	r16,0x18,r8 }
	{ adds	r8,0x20,r8; addl	r17,-2276,r1; nop.i	0x0 }
	{ ld4	r15,[r14]; ld8	r17,[r17]; nop.i	0x0; }
	{ st8	[r17],r16; addl	r16,20480,r0; or	r15,r16,r15 }
	{ addl	r16,-2292,r1; ld8	r16,[r16]; nop.i	0x0 }
	{ st4	[r15],r14; st8	[r16],r8; mov	pr,r51,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r49; mov.spnt	b0,r48,400000000006D810 }
	{ nop.m	0x0; adds	r12,0x30,r12; br.ret	b0 }

l400000000006D830:
	{ nop.m	0x0; addl	r52,-1316,r1; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,make_new_assoc_variable; }
	{ adds	r1,0x0,r50; nop.m	0x0; adds	r14,0x28,r8 }
	{ adds	r16,0x18,r8; nop.m	0x0; adds	r8,0x20,r8; }
	{ addl	r17,-2148,r1; ld4	r15,[r14]; addl	r52,-1308,r1; }
	{ ld8	r17,[r17]; ld8	r52,[r52]; nop.i	0x0; }
	{ st8	[r17],r16; nop.m	0x0; addl	r16,131072,r0; }
	{ or	r15,r16,r15; nop.m	0x0; addl	r16,-2108,r1; }
	{ ld8	r16,[r16]; st4	[r15],r14; nop.i	0x0; }
	{ st8	[r16],r8; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x0,r50; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	400000000006D000; }

l400000000006D8E0:
	{ nop.m	0x0; addl	r52,-1308,r1; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,make_new_assoc_variable; }
	{ adds	r1,0x0,r50; nop.m	0x0; adds	r14,0x28,r8 }
	{ adds	r16,0x18,r8; nop.m	0x0; adds	r8,0x20,r8; }
	{ addl	r17,-2156,r1; ld4	r15,[r14]; addl	r52,-1964,r1; }
	{ ld8	r17,[r17]; ld8	r52,[r52]; nop.i	0x0; }
	{ st8	[r17],r16; nop.m	0x0; addl	r16,131072,r0; }
	{ or	r15,r16,r15; nop.m	0x0; addl	r16,-2116,r1; }
	{ ld8	r16,[r16]; st4	[r15],r14; nop.i	0x0; }
	{ st8	[r16],r8; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x0,r50; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	400000000006D030 }

l400000000006D990:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000006D790; }

l400000000006D9A0:
	{ addl	r52,-1428,r1; adds	r53,0x0,r34; adds	r54,0x0,r0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r8,0x28,r8; nop.m	0x0; adds	r1,0x0,r50; }
	{ ld4	r14,[r8]; or	r14,0x12,r14; nop.i	0x0; }
	{ st4	[r14],r8; nop.i	0x0; br.cond.sptk.few	400000000006CA20 }

l400000000006D9F0:
	{ ld8	r52,[r38]; nop.m	0x0; nop.i	0x0 }

l400000000006DA00:
	{ nop.m	0x0; addl	r35,-22276,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r50; adds	r52,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r50; nop.m	0x0; adds	r52,0x0,r8 }
	{ ld8	r53,[r38]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r50; adds	r34,0x0,r8; adds	r54,0x0,r0; }
	{ addl	r52,-1532,r1; nop.m	0x0; adds	r53,0x0,r34; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r1,0x0,r50; adds	r52,0x0,r34; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r50; addl	r52,-1524,r1; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x0,r50; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	400000000006C510 }

l400000000006DAC0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000006D740; }

l400000000006DAD0:
	{ nop.m	0x0; addl	r52,-1820,r1; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x0,r50; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	400000000006E080; }

l400000000006DB00:
	{ nop.m	0x0; ld4	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x1,r14; (p07) br.cond.dpnt.few	400000000006C3E0 }

l400000000006DB20:
	{ addl	r38,6476,r1; nop.m	0x0; nop.i	0x0; }
	{ ld8	r52,[r38]; ld1	r14,[r52]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2F,r14; (p06) br.cond.dptk.few	400000000006D630 }

l400000000006DB60:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000006DA00 }

l400000000006DB70:
	{ ld8	r52,[r8]; nop.i	0x0; br.call.sptk.many	b0,sv_ignoreeof; }
	{ nop.m	0x0; adds	r1,0x0,r50; br.cond.sptk.few	400000000006D460; }

l400000000006DB90:
	{ addl	r52,-1436,r1; adds	r53,0x0,r34; adds	r54,0x0,r0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r8,0x28,r8; nop.m	0x0; adds	r1,0x0,r50; }
	{ ld4	r14,[r8]; or	r14,0x12,r14; nop.i	0x0; }
	{ st4	[r14],r8; nop.i	0x0; br.cond.sptk.few	400000000006C9A0 }

l400000000006DBE0:
	{ nop.m	0x0; addl	r52,-1484,r1; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x0,r50; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.sptk.few	400000000006C840 }

l400000000006DC10:
	{ adds	r14,0x28,r8; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0xF; (p06) br.cond.dptk.few	400000000006C840 }

l400000000006DC30:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000006D720 }

l400000000006DC40:
	{ addl	r35,6476,r1; ld8	r52,[r38]; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,file_status; }
	{ adds	r1,0x0,r50; tbit.z	p06,p07,r8,0x1; (p06) br.cond.dptk.few	400000000006D630; }

l400000000006DC70:
	{ addl	r52,-1812,r1; ld8	r34,[r35]; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,get_string_value; }
	{ adds	r1,0x0,r50; nop.m	0x0; adds	r52,0x0,r34 }
	{ adds	r53,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,make_absolute; }
	{ ld8	r14,[r35]; adds	r1,0x0,r50; adds	r34,0x0,r8; }
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r14; (p07) br.cond.dpnt.few	400000000006DFB0 }

l400000000006DCE0:
	{ addl	r35,-22276,r1; nop.m	0x0; addl	r52,-1532,r1 }
	{ adds	r53,0x0,r34; adds	r54,0x0,r0; nop.i	0x0 }
	{ nop.m	0x0; ld8	r52,[r52]; br.call.sptk.many	b0,bind_variable; }
	{ adds	r1,0x0,r50; adds	r52,0x0,r34; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r50; addl	r52,-1524,r1; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x0,r50; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	400000000006C510 }

l400000000006DD50:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000006D740 }

l400000000006DD60:
	{ adds	r14,0xFFFFFFFFFFFFFFFE,r38; add	r14,r35,r14; nop.i	0x0; }
	{ nop.m	0x0; ld1	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; cmp4.eq	p07,p06,0x0,r15; }
	{ (p07) st1	[r46],r14; nop.i	0x0; br.cond.sptk.few	400000000006D220 }

l400000000006DD96:
	{ break.m	0x4000; Invalid; (p32) nop }

l400000000006DDA0:
	{ adds	r14,0xFFFFFFFFFFFFFFFE,r38; adds	r52,0x0,r35; add	r14,r35,r14; }
	{ nop.m	0x0; ld1	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; cmp4.eq	p07,p06,0x28,r15; }
	{ (p07) st1	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,find_function; }

l400000000006DDD6:
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ Invalid; (p17) cmp.eq.or	p00,p02,r8,r0; Invalid }

l400000000006DDF6:
	{ Invalid; Invalid; Invalid }

l400000000006DDFC:
	{ Invalid; Invalid; Invalid }

l400000000006DE00:
	{ (p18) addl	r54,5,r0; (p19) st4	[r42],r41; nop.i	0x0; }

l400000000006DE06:
	{ mf.a; (p52) nop }

l400000000006DE0C:
	{ cmp.ge.or.andcm	p00,p41,r0,r0; (p01) nop; Invalid }

l400000000006DE16:
	{ Invalid; Invalid; Invalid }

l400000000006DE1C:
	{ nop; cmp.ge.or.andcm	p00,p32,r0,r0; zxt1	r106,r3 }

l400000000006DE2C:
	{ Invalid; Invalid; chk.s.i	r32,3FFFFFFFFF06DE2C }

l400000000006DE36:
	{ nop; (p32) addl	r83,2037465,r2; (p20) nop }

l400000000006DE40:
	{ (p18) adds	r1,0x0,r50; nop.m	0x0; (p18) adds	r52,0x0,r8 }

l400000000006DE46:
	{ nop; (p26) nop; (p20) nop }

l400000000006DE50:
	{ (p18) adds	r53,0x0,r35; nop.m	0x0; (p18) br.call.dpnt.many	b0,report_error; }

l400000000006DE56:
	{ nop; Invalid; (p32) addl	r3,131168,r3 }

l400000000006DE60:
	{ ld1	r14,[r47]; (p18) adds	r1,0x0,r50; sxt1	r14,r14; }

l400000000006DE6C:
	{ invala; cmp.eq	p00,p00,r32,r0; (p16) mov	pr,r67,0xE694; }
	{ (p29) invala; break.i	0x1000; break.b	0x1000 }

l400000000006DE80:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000006DD60 }

l400000000006DE90:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,get_current_user_info; }
	{ nop.m	0x0; adds	r1,0x0,r50; nop.i	0x0 }
	{ ld8	r52,[r34]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r50; adds	r52,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r14,0x18,r35; adds	r1,0x0,r50; adds	r52,0x0,r8; }
	{ ld8	r53,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r50; adds	r34,0x0,r8; br.cond.sptk.few	400000000006D6B0 }

l400000000006DF00:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,get_current_user_info; }
	{ adds	r1,0x0,r50; ld8	r53,[r34]; adds	r54,0x0,r0; }
	{ nop.m	0x0; addl	r52,-1524,r1; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ nop.m	0x0; adds	r1,0x0,r50; br.cond.sptk.few	400000000006C510; }

l400000000006DF50:
	{ nop.m	0x0; addl	r52,-1468,r1; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x0,r50; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.sptk.few	400000000006D460 }

l400000000006DF80:
	{ adds	r14,0x28,r8; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0xF; (p06) br.cond.dptk.few	400000000006D460 }

l400000000006DFA0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000006DB70 }

l400000000006DFB0:
	{ addl	r53,3,r0; adds	r52,0x0,r8; br.call.sptk.many	b0,sh_canonpath; }
	{ adds	r1,0x0,r50; nop.m	0x0; cmp.eq	p06,p07,0x0,r8 }
	{ adds	r52,0x0,r34; nop.m	0x0; (p06) br.cond.dpnt.few	400000000006DCE0; }

l400000000006DFE0:
	{ addl	r35,-22276,r1; nop.m	0x0; adds	r34,0x0,r8; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r50; adds	r53,0x0,r34; adds	r54,0x0,r0; }
	{ nop.m	0x0; addl	r52,-1532,r1; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r1,0x0,r50; adds	r52,0x0,r34; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r50; addl	r52,-1524,r1; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x0,r50; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	400000000006C510 }

l400000000006E070:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000006D740 }

l400000000006E080:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_get_home_dir; }
	{ adds	r1,0x0,r50; adds	r53,0x0,r8; adds	r54,0x0,r0; }
	{ nop.m	0x0; addl	r52,-1820,r1; nop.i	0x0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ ld4	r14,[r34]; nop.m	0x0; adds	r1,0x0,r50; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x1,r14; (p06) br.cond.dptk.few	400000000006DB20 }

l400000000006E0E0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000006C3E0; }
400000000006E0F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; assign_in_env: 400000000006E100
assign_in_env proc
	{ alloc	r40,ar.pfs,0xE,0x0,0xA; ld8	r34,[r32]; nop.b	0x0 }
	{ adds	r41,0x0,r1; nop.m	0x0; mov	r39,b7; }
	{ adds	r43,0x0,r0; adds	r42,0x0,r34; br.call.sptk.many	b0,assignment; }
	{ adds	r42,0x0,r34; nop.m	0x0; adds	r1,0x0,r41 }
	{ adds	r35,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; sxt4	r35,r35; nop.i	0x0 }
	{ adds	r1,0x0,r41; adds	r42,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r43,0x0,r34; nop.m	0x0; adds	r1,0x0,r41 }
	{ adds	r42,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ add	r14,r8,r35; adds	r1,0x0,r41; adds	r34,0x0,r8; }
	{ ld1	r15,[r14]; addl	r37,7140,r1; sxt1	r15,r15; }
	{ cmp4.eq	p07,p06,0x3D,r15; nop.i	0x0; (p07) br.cond.dpnt.few	400000000006E4D0; }

l400000000006E1C0:
	{ ld8	r43,[r37]; nop.m	0x0; (p06) adds	r35,0x0,r0; }

l400000000006E1D0:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r43; (p07) br.cond.dpnt.few	400000000006E710 }

l400000000006E1E0:
	{ adds	r42,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000005F7C0; }
	{ adds	r38,0x8,r8; adds	r1,0x0,r41; nop.i	0x0 }
	{ cmp.eq	p07,p06,0x0,r8; adds	r36,0x0,r8; (p07) br.cond.dpnt.few	400000000006E770; }

l400000000006E210:
	{ nop.m	0x0; ld8	r42,[r38]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r42; nop.i	0x0; (p06) br.cond.dpnt.few	400000000006E250; }

l400000000006E230:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r41; nop.m	0x0; nop.i	0x0 }

l400000000006E250:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p07) br.cond.dpnt.few	400000000006E6E0; }

l400000000006E260:
	{ adds	r14,0x28,r36; adds	r37,0x10,r36; addl	r15,7148,r1 }
	{ addl	r17,1048577,r0; st8	[r35],r38; adds	r36,0x2C,r36; }
	{ ld4	r16,[r14]; ld8	r42,[r37]; nop.i	0x0; }
	{ ld4	r15,[r15]; or	r16,r17,r16; cmp.eq	p06,p07,0x0,r42; }
	{ st4	[r15],r36; st4	[r16],r14; nop.i	0x0 }
	{ nop.b	0x0; (p06) br.cond.dpnt.few	400000000006E2D0; br.call.sptk.many	b0,fn400000000001A7E0; }

l400000000006E2BC:
	{ (p41) nop; invala; rfi }
	{ cmpxchg4.acq	r0,[r0],r1; zxt1	r64,r64; break.i	0x1000 }

l400000000006E2D0:
	{ adds	r42,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ ld1	r14,[r35]; adds	r38,0x0,r8; adds	r1,0x0,r41; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) adds	r8,0x0,r0; (p06) br.cond.dptk.few	400000000006E3A0 }

l400000000006E30C:
	{ (p05) cmp.lt	p00,p11,r0,r33; (p17) cmp.lt.unc	p32,p16,r8,r64; Invalid }

l400000000006E310:
	{ adds	r14,0x1,r35; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r8,1,r0; (p06) br.cond.dptk.few	400000000006E3A0 }

l400000000006E33C:
	{ (p03) cmp.lt	p00,p11,r0,r33; (p33) cmp.lt.unc	p32,p16,r8,r64; (p01) rfi }

l400000000006E340:
	{ adds	r14,0x2,r35; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r8,2,r0; (p06) br.cond.dptk.few	400000000006E3A0 }

l400000000006E36C:
	{ Invalid; dep	r0,r32,r0,63,1; zxt1	r96,r64 }

l400000000006E370:
	{ nop.m	0x0; adds	r42,0x0,r35; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r41; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000006E3A0:
	{ adds	r14,0x2,r38; add	r42,r14,r8; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r42,r42; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r41; adds	r36,0x0,r8; nop.i	0x0 }
	{ adds	r42,0x0,r8; adds	r43,0x0,r34; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; sxt4	r42,r38; addl	r15,61,r0 }
	{ adds	r1,0x0,r41; add	r14,r36,r42; nop.i	0x0; }
	{ st1	[r15],r14; ld1	r15,[r35]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r15; addl	r15,1,r0; (p07) br.cond.dpnt.few	400000000006E640; }

l400000000006E430:
	{ (p06) adds	r14,0x1,r14; (p06) st1	[r0],r14; addl	r14,5780,r1 }

l400000000006E436:
	{ mf.a; (p07) nop; nop; }

l400000000006E43C:
	{ (p10) nop; Invalid; cmp.lt	p00,p00,r32,r0; }
	{ invala; Invalid; mov	pr,r32,0x0 }
	{ (p13) cmp.lt	p00,p11,r64,r33; zxt4	r51,r14; break.i	0x1000 }

l400000000006E460:
	{ addl	r14,7372,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	400000000006E5B0 }

l400000000006E490:
	{ adds	r42,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r41; addl	r8,1,r0 }

l400000000006E4B0:
	{ nop.m	0x0; mov.i	ar.pfs,r40; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r39,400000000006E4C0; br.ret	b0 }

l400000000006E4D0:
	{ adds	r15,0xFFFFFFFFFFFFFFFF,r35; st1	[r0],r14; adds	r42,0x0,r8; }
	{ add	r14,r8,r15; ld1	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; cmp4.eq	p07,p06,0x2B,r15; }
	{ (p07) st1	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,find_variable; }

l400000000006E506:
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ Invalid; nop; (p16) nop }
	{ (p07) chk.a.clr	r2,3FFFFFFFFF2AE526; nop; (p32) br.call.sptk.few	b3,b0 }

l400000000006E530:
	{ ld8	r14,[r8]; and	r14,r14,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000006E690 }

l400000000006E550:
	{ ld4	r14,[r8]; nop.m	0x0; adds	r42,0x0,r34; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x1; (p07) br.cond.dpnt.few	400000000006E740; }

l400000000006E570:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r41; adds	r8,0x0,r0 }

l400000000006E590:
	{ nop.m	0x0; mov.i	ar.pfs,r40; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r39,400000000006E5A0; br.ret	b0; }

l400000000006E5B0:
	{ adds	r42,0x0,r34; adds	r43,0x0,r35; nop.i	0x0 }
	{ adds	r44,0x0,r0; addl	r45,1,r0; br.call.sptk.many	b0,xtrace_print_assignment; }
	{ adds	r1,0x0,r41; adds	r42,0x0,r34; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r41; addl	r8,1,r0; br.cond.sptk.few	400000000006E4B0 }

l400000000006E5F0:
	{ adds	r42,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,stupidly_hack_special_variables; }
	{ adds	r1,0x0,r41; addl	r14,7372,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	400000000006E490 }

l400000000006E630:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000006E5B0 }

l400000000006E640:
	{ add	r42,r36,r42,0x1; adds	r43,0x0,r35; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r41; nop.m	0x0; addl	r15,1,r0 }
	{ st8	[r36],r37; cmp4.eq	p06,p07,0x0,r33; addl	r14,5780,r1; }
	{ st4	[r15],r14; nop.i	0x0; (p06) br.cond.dptk.few	400000000006E460 }

l400000000006E680:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000006E5F0 }

l400000000006E690:
	{ add	r42,r34,r35,0x1; adds	r43,0x0,r0; br.call.sptk.many	b0,expand_assignment_string_to_string; }
	{ adds	r1,0x0,r41; adds	r35,0x0,r8; addl	r37,7140,r1; }
	{ nop.m	0x0; ld8	r43,[r37]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r43; (p06) br.cond.dptk.few	400000000006E1E0 }

l400000000006E6D0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000006E710 }

l400000000006E6E0:
	{ addl	r42,1,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ nop.m	0x0; adds	r1,0x0,r41; adds	r35,0x0,r8 }
	{ nop.m	0x0; st1	[r0],r8; br.cond.sptk.few	400000000006E260 }

l400000000006E710:
	{ addl	r42,4,r0; nop.i	0x0; br.call.sptk.many	b0,hash_create; }
	{ nop.m	0x0; adds	r1,0x0,r41; adds	r43,0x0,r8 }
	{ nop.m	0x0; st8	[r8],r37; br.cond.sptk.few	400000000006E1E0 }

l400000000006E740:
	{ adds	r42,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,err_readonly; }
	{ adds	r1,0x0,r41; adds	r42,0x0,r34; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r41; adds	r8,0x0,r0; br.cond.sptk.few	400000000006E590 }

l400000000006E770:
	{ nop.m	0x0; adds	r42,0x0,r34; nop.i	0x0 }
	{ ld8	r43,[r37]; nop.m	0x0; br.call.sptk.many	b0,fn4000000000066B80; }
	{ adds	r1,0x0,r41; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r38,0x8,r8; cmp.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	400000000006E260 }

l400000000006E7B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000006E6E0; }

;; reinit_special_variables: 400000000006E7C0
;;   Called from:
;;     400000000001D12C (in main)
reinit_special_variables proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; addl	r36,-1356,r1; mov	r33,b1 }
	{ nop.m	0x0; adds	r35,0x0,r1; nop.i	0x0; }
	{ ld8	r36,[r36]; nop.i	0x0; br.call.sptk.many	b0,sv_comp_wordbreaks; }
	{ adds	r1,0x0,r35; addl	r36,-1300,r1; addl	r32,-1948,r1; }
	{ nop.m	0x0; ld8	r36,[r36]; nop.i	0x0 }
	{ ld8	r32,[r32]; nop.m	0x0; br.call.sptk.many	b0,sv_globignore; }
	{ adds	r1,0x0,r35; mov.spnt	b0,r33,400000000006E820; mov.i	ar.pfs,r34; }
	{ alloc	r2,ar.pfs,0x1,0x0,0x0; nop.i	0x0; br.cond.sptk.many	sv_opterr; }
400000000006E840 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
400000000006E850 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000006E860 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000006E870 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; set_pipestatus_array: 400000000006E880
;;   Called from:
;;     400000000006EFAC (in set_pipestatus_from_exit)
;;     4000000000077DAC (in fn4000000000077C00)
set_pipestatus_array proc
	{ alloc	r41,ar.pfs,0xF,0x0,0xC; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ addl	r44,-1292,r1; adds	r42,0x0,r1; mov	r40,b0; }
	{ ld8	r44,[r44]; mov	r43,LC; br.call.sptk.many	b0,find_variable; }
	{ adds	r1,0x0,r42; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	400000000006EB80 }

l400000000006E8C0:
	{ adds	r14,0x28,r8; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x2; (p06) br.cond.dptk.few	400000000006EAA0 }

l400000000006E8E0:
	{ adds	r8,0x8,r8; ld8	r35,[r8]; nop.i	0x0; }
	{ adds	r39,0x10,r35; cmp.eq	p06,p07,0x0,r35; (p06) br.cond.dpnt.few	400000000006EAD0; }

l400000000006E900:
	{ nop.m	0x0; ld4	r14,[r39]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	400000000006EAD0; }

l400000000006E920:
	{ cmp4.eq	p07,p06,r33,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000006ECB0; }

l400000000006E930:
	{ nop.m	0x0; cmp4.lt	p06,p07,r33,r14; (p06) br.cond.dpnt.few	400000000006EBB0; }

l400000000006E940:
	{ cmp4.lt	p07,p06,0x0,r14; adds	r15,0x18,r35; adds	r38,0x0,r32; }
	{ nop.m	0x0; (p06) adds	r34,0x0,r0; nop.i	0x0 }

l400000000006E95C:
	{ shladdp4	r0,r1,0x2,r0; Invalid; mov	pr,r32,0x0 }
	{ (p05) cmpxchg2.acq	r0,[r33],r64; zxt1	r0,r64; break.i	0x1000 }

l400000000006E970:
	{ adds	r34,0x0,r0; nop.m	0x0; nop.i	0x0; }

l400000000006E980:
	{ adds	r36,0x10,r36; nop.m	0x0; adds	r34,0x1,r34; }
	{ ld8	r36,[r36]; adds	r37,0x8,r36; nop.i	0x0; }
	{ ld8	r44,[r37]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ ld4	r44,[r38],4; nop.m	0x0; adds	r1,0x0,r42; }
	{ nop.m	0x0; sxt4	r44,r44; br.call.sptk.many	b0,itos; }
	{ nop.m	0x0; ld4	r14,[r39]; adds	r1,0x0,r42 }
	{ nop.m	0x0; st8	[r8],r37; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r34,r14; (p06) br.cond.dptk.few	400000000006E980; }

l400000000006EA00:
	{ nop.m	0x0; sxt4	r37,r34; sub	r14,r33,r34,0x1 }
	{ adds	r36,0x0,r0; cmp4.lt	p06,p07,r34,r33; (p07) br.cond.dpnt.few	400000000006EAA0; }

l400000000006EA20:
	{ addp4	r14,r14,r0; shladd	r32,r37,0x2,r32; mov.i	LC,r14; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000006EA40:
	{ ld4	r44,[r32],4; adds	r45,0x10,r12; addl	r46,12,r0; }
	{ nop.m	0x0; sxt4	r44,r44; br.call.sptk.many	b0,inttostr; }
	{ adds	r1,0x0,r42; add	r45,r37,r36; adds	r44,0x0,r35 }
	{ adds	r46,0x0,r8; adds	r36,0x1,r36; br.call.sptk.many	b0,array_insert; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cloop.sptk.few	400000000006EA40; }

l400000000006EA90:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000006EAA0:
	{ nop.m	0x0; mov.i	ar.pfs,r41; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r43; mov.spnt	b0,r40,400000000006EAB0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l400000000006EAD0:
	{ cmp4.lt	p07,p06,0x0,r33; nop.m	0x0; adds	r33,0xFFFFFFFFFFFFFFFF,r33 }
	{ adds	r34,0x0,r0; nop.m	0x0; (p06) br.cond.dpnt.few	400000000006EAA0; }

l400000000006EAF0:
	{ addp4	r33,r33,r0; nop.i	0x0; mov.i	LC,r33; }

l400000000006EB00:
	{ ld4	r44,[r32],4; adds	r45,0x10,r12; addl	r46,12,r0; }
	{ nop.m	0x0; sxt4	r44,r44; br.call.sptk.many	b0,inttostr; }
	{ adds	r1,0x0,r42; adds	r45,0x0,r34; adds	r44,0x0,r35 }
	{ adds	r46,0x0,r8; adds	r34,0x1,r34; br.call.sptk.many	b0,array_insert; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cloop.sptk.few	400000000006EB00 }

l400000000006EB50:
	{ nop.m	0x0; mov.i	ar.pfs,r41; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r43; mov.spnt	b0,r40,400000000006EB60 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l400000000006EB80:
	{ nop.m	0x0; addl	r44,-1292,r1; nop.i	0x0; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,make_new_array_variable; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	400000000006E8C0 }

l400000000006EBB0:
	{ adds	r44,0x0,r35; adds	r34,0x0,r0; br.call.sptk.many	b0,array_flush; }
	{ ld4	r44,[r32]; adds	r32,0x4,r32; adds	r1,0x0,r42; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r44; (p06) br.cond.dpnt.few	400000000006EAA0; }

l400000000006EBE0:
	{ nop.m	0x0; sxt4	r44,r44; nop.i	0x0 }
	{ adds	r45,0x10,r12; addl	r46,12,r0; br.call.sptk.many	b0,inttostr; }
	{ adds	r45,0x0,r34; adds	r1,0x0,r42; adds	r44,0x0,r35 }
	{ adds	r46,0x0,r8; adds	r34,0x1,r34; br.call.sptk.many	b0,array_insert; }
	{ ld4	r44,[r32],4; nop.m	0x0; adds	r45,0x10,r12 }
	{ addl	r46,12,r0; nop.m	0x0; adds	r1,0x0,r42; }
	{ cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r44; sxt4	r44,r44; (p07) br.cond.dpnt.few	400000000006EAA0; }

l400000000006EC50:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,inttostr; }
	{ adds	r1,0x0,r42; adds	r44,0x0,r35; adds	r45,0x0,r34 }
	{ adds	r46,0x0,r8; adds	r34,0x1,r34; br.call.sptk.many	b0,array_insert; }
	{ ld4	r44,[r32],4; nop.m	0x0; adds	r1,0x0,r42; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r44; (p06) br.cond.dptk.few	400000000006EBE0 }

l400000000006ECA0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000006EAA0; }

l400000000006ECB0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x1,r33; (p06) br.cond.dptk.few	400000000006E940 }

l400000000006ECC0:
	{ adds	r35,0x18,r35; ld8	r14,[r35]; nop.i	0x0; }
	{ adds	r14,0x10,r14; ld8	r34,[r14]; nop.i	0x0; }
	{ nop.m	0x0; adds	r34,0x8,r34; nop.i	0x0; }
	{ ld8	r44,[r34]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ ld4	r44,[r32]; nop.m	0x0; adds	r1,0x0,r42; }
	{ nop.m	0x0; sxt4	r44,r44; br.call.sptk.many	b0,itos; }
	{ adds	r1,0x0,r42; st8	[r8],r34; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.i	LC,r43; mov.spnt	b0,r40,400000000006ED30 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }
400000000006ED50 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000006ED60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000006ED70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; save_pipestatus_array: 400000000006ED80
;;   Called from:
;;     400000000003DDBC (in save_parser_state)
;;     40000000000AC8AC (in fn40000000000AC6C0)
;;     40000000000AE85C (in run_exit_trap)
;;     40000000000AF12C (in run_pending_traps)
save_pipestatus_array proc
	{ alloc	r33,ar.pfs,0x4,0x0,0x3; addl	r35,-1292,r1; mov	r32,b0 }
	{ nop.m	0x0; adds	r34,0x0,r1; nop.i	0x0; }
	{ ld8	r35,[r35]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r14,0x28,r8; adds	r1,0x0,r34; nop.i	0x0 }
	{ adds	r15,0x8,r8; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	400000000006EE40; }

l400000000006EDD0:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x2; (p06) br.cond.dpnt.few	400000000006EE40; }

l400000000006EDF0:
	{ nop.m	0x0; ld8	r35,[r15]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r35; nop.i	0x0; (p06) br.cond.dpnt.few	400000000006EE40; }

l400000000006EE10:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,array_copy; }
	{ adds	r1,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ nop.m	0x0; mov.spnt	b0,r32,400000000006EE30; br.ret	b0 }

l400000000006EE40:
	{ adds	r8,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ nop.m	0x0; mov.spnt	b0,r32,400000000006EE50; br.ret	b0; }
400000000006EE60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000006EE70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; restore_pipestatus_array: 400000000006EE80
;;   Called from:
;;     400000000003E0DC (in restore_parser_state)
;;     40000000000ACA6C (in fn40000000000AC6C0)
;;     40000000000ACCCC (in fn40000000000AC6C0)
;;     40000000000AE89C (in run_exit_trap)
;;     40000000000AF1EC (in run_pending_traps)
restore_pipestatus_array proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; addl	r36,-1292,r1; mov	r33,b1 }
	{ nop.m	0x0; adds	r35,0x0,r1; nop.i	0x0; }
	{ ld8	r36,[r36]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r15,0x28,r8; adds	r1,0x0,r35; nop.i	0x0 }
	{ adds	r14,0x8,r8; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	400000000006EF30; }

l400000000006EED0:
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r15,0x2; (p06) br.cond.dpnt.few	400000000006EF30; }

l400000000006EEF0:
	{ nop.m	0x0; ld8	r36,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r36; nop.i	0x0; (p06) br.cond.dpnt.few	400000000006EF30; }

l400000000006EF10:
	{ st8	[r32],r14; br.call.sptk.many	b0,array_dispose; nop.b	0x0; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l400000000006EF30:
	{ nop.m	0x0; mov.i	ar.pfs,r34; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r33,400000000006EF40; br.ret	b0; }
400000000006EF50 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000006EF60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000006EF70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; set_pipestatus_from_exit: 400000000006EF80
;;   Called from:
;;     4000000000085DEC (in fn4000000000085DC0)
set_pipestatus_from_exit proc
	{ alloc	r16,ar.pfs,0x2,0x0,0x2; nop.m	0x0; addl	r14,5796,r1; }
	{ st4	[r32],r14; addl	r33,1,r0; adds	r32,0x0,r14; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	set_pipestatus_array; }
400000000006EFB0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; copy_word: 400000000006EFC0
;;   Called from:
;;     400000000006F21C (in copy_word_list)
;;     400000000006F43C (in copy_redirect)
;;     400000000006F48C (in copy_redirect)
;;     400000000006F52C (in copy_redirect)
;;     400000000007046C (in copy_function_def_contents)
;;     40000000000DE3EC (in redirection_expand)
;;     40000000000E37DC (in fn40000000000E3740)
;;     40000000000E38EC (in fn40000000000E3740)
copy_word proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; nop.m	0x0; mov	r33,b1 }
	{ adds	r35,0x0,r1; ld8	r36,[r32],8; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,make_bare_word; }
	{ ld4	r15,[r32]; adds	r14,0x8,r8; nop.b	0x0 }
	{ adds	r1,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ st4	[r15],r14; mov.spnt	b0,r33,400000000006F010; br.ret	b0; }
400000000006F020 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000006F030 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000006F040 09 18 19 0A 80 05 40 02 04 00 42 40 04 00 C4 00 ......@...B@....
400000000006F050 11 28 A1 00 00 24 00 00 00 02 00 00 78 9C 07 50 .(...$......x..P
400000000006F060 08 78 00 40 00 21 30 81 80 00 42 C0 01 40 00 84 .x.@.!0...B..@..
400000000006F070 09 88 20 10 00 21 10 02 20 00 42 40 82 00 01 84 .. ..!.. .B@....
400000000006F080 08 00 00 00 01 00 00 21 3C 20 28 20 00 20 01 84 .......!< ( . ..
400000000006F090 0A 40 00 26 18 10 40 80 38 20 2B C0 00 40 1C E4 .@.&..@.8 +..@..
400000000006F0A0 09 80 00 1E 10 10 F0 00 48 20 20 A0 04 40 00 84 ........H  ..@..
400000000006F0B0 08 00 40 1C 90 11 00 78 44 20 23 00 00 00 04 00 ..@....xD #.....
400000000006F0C0 17 00 00 00 00 88 01 10 00 80 21 00 08 FF FF 58 ..........!....X
400000000006F0D0 08 08 00 48 00 21 00 00 00 02 00 00 00 00 04 00 ...H.!..........
400000000006F0E0 09 78 60 40 00 21 00 00 00 02 00 C0 01 09 01 84 .x`@.!..........
400000000006F0F0 09 28 01 1E 18 10 00 40 38 30 23 00 00 00 04 00 .(.....@80#.....
400000000006F100 09 00 00 00 01 00 60 00 94 0E 72 00 00 00 04 00 ......`...r.....
400000000006F110 D1 40 00 00 00 21 00 00 00 02 00 03 30 00 00 43 .@...!......0..C
400000000006F120 11 00 00 00 01 00 00 00 00 02 00 00 28 FF FF 58 ............(..X
400000000006F130 08 08 00 48 00 21 00 00 00 02 00 00 00 00 04 00 ...H.!..........
400000000006F140 09 00 81 40 00 21 00 00 00 02 00 C0 81 09 01 84 ...@.!..........
400000000006F150 09 28 01 40 18 10 00 40 38 30 23 00 00 00 04 00 .(.@...@80#.....
400000000006F160 09 00 00 00 01 00 60 00 94 0E 72 00 00 00 04 00 ......`...r.....
400000000006F170 D1 78 00 00 00 21 00 00 00 02 00 03 30 00 00 43 .x...!......0..C
400000000006F180 11 00 00 00 01 00 00 00 00 02 00 00 C8 FE FF 58 ...............X
400000000006F190 08 00 00 00 01 00 10 00 90 00 42 E0 01 40 00 84 ..........B..@..
400000000006F1A0 09 70 80 42 00 21 80 00 84 00 42 00 30 02 AA 00 .p.B.!....B.0...
400000000006F1B0 11 00 3C 1C 98 11 00 10 05 80 03 80 08 00 84 00 ..<.............

;; copy_word_list: 400000000006F1C0
;;   Called from:
;;     40000000000A797C (in fn40000000000A7940)
;;     40000000000ED12C (in command_builtin)
;;     40000000000EECAC (in remember_args)
;;     40000000000FF3DC (in jobs_builtin)
copy_word_list proc
	{ alloc	r35,ar.pfs,0x7,0x0,0x5; adds	r36,0x0,r1; mov	r34,b2 }
	{ cmp.eq	p07,p06,0x0,r32; nop.m	0x0; (p07) br.cond.dpnt.few	400000000006F2D0; }

l400000000006F1E0:
	{ adds	r33,0x0,r0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000006F200:
	{ nop.m	0x0; adds	r14,0x8,r32; nop.i	0x0; }
	{ ld8	r37,[r14]; nop.i	0x0; br.call.sptk.many	b0,copy_word; }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r38,0x0,r33 }
	{ adds	r37,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,make_word_list; }
	{ ld8	r32,[r32]; adds	r1,0x0,r36; adds	r33,0x0,r8; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p06) br.cond.dptk.few	400000000006F200; }

l400000000006F260:
	{ cmp.eq	p06,p07,0x0,r8; adds	r37,0x0,r8; (p06) br.cond.dpnt.few	400000000006F2D0; }

l400000000006F270:
	{ nop.m	0x0; ld8	r14,[r8]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000006F2B0; }

l400000000006F290:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,list_reverse; }
	{ nop.m	0x0; adds	r1,0x0,r36; adds	r33,0x0,r8; }

l400000000006F2B0:
	{ adds	r8,0x0,r33; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,400000000006F2C0; br.ret	b0 }

l400000000006F2D0:
	{ adds	r33,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ adds	r8,0x0,r33; mov.spnt	b0,r34,400000000006F2E0; br.ret	b0; }
400000000006F2F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; copy_redirect: 400000000006F300
;;   Called from:
;;     40000000000471EC (in fn40000000000470C0)
;;     400000000006F5BC (in copy_redirects)
;;     400000000006F60C (in copy_redirects)
copy_redirect proc
	{ alloc	r36,ar.pfs,0x8,0x0,0x6; adds	r37,0x0,r1; mov	r35,b3; }
	{ addl	r38,48,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r16,0x0,r32; adds	r33,0x0,r8; nop.i	0x0 }
	{ adds	r17,0x10,r32; adds	r1,0x0,r37; adds	r34,0x0,r8; }
	{ ld8	r14,[r16],8; st8	[r33],r8,8; adds	r15,0x0,r16; }
	{ ld8	r18,[r15],8; nop.m	0x0; adds	r14,0x0,r33; }
	{ st8	[r14],r8,8; ld8	r18,[r15],8; nop.i	0x0; }
	{ st8	[r14],r8,8; ld8	r18,[r15],8; nop.i	0x0 }
	{ ld4	r17,[r17]; st8	[r14],r8,8; tbit.z	p06,p07,r17,0x0; }
	{ ld8	r17,[r15],8; st8	[r14],r8,8; nop.i	0x0; }
	{ nop.m	0x0; ld8	r15,[r15]; nop.i	0x0; }
	{ st8	[r15],r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000006F480 }

l400000000006F3C0:
	{ nop.m	0x0; adds	r14,0x18,r32; nop.i	0x0; }
	{ ld4	r14,[r14]; nop.i	0x0; sxt4	r15,r14 }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x13,r14; (p06) br.cond.dptk.few	400000000006F460 }

l400000000006F3F0:
	{ addl	r14,1,r0; addl	r16,272,r0; shl	r14,r14,r15 }
	{ addl	r15,949295,r0; and	r15,r15,r14; and	r14,r16,r14; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r15; (p07) br.cond.dptk.few	400000000006F4B0 }

l400000000006F420:
	{ nop.m	0x0; adds	r32,0x20,r32; nop.i	0x0; }
	{ ld8	r38,[r32]; nop.i	0x0; br.call.sptk.many	b0,copy_word; }
	{ adds	r14,0x20,r34; nop.m	0x0; adds	r1,0x0,r37; }
	{ st8	[r8],r14; nop.m	0x0; nop.i	0x0 }

l400000000006F460:
	{ adds	r8,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,400000000006F470; br.ret	b0; }

l400000000006F480:
	{ ld8	r38,[r16]; nop.i	0x0; br.call.sptk.many	b0,copy_word; }
	{ nop.m	0x0; adds	r1,0x0,r37; nop.i	0x0 }
	{ st8	[r8],r33; nop.m	0x0; br.cond.sptk.few	400000000006F3C0 }

l400000000006F4B0:
	{ adds	r33,0x28,r32; cmp.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	400000000006F460; }

l400000000006F4C0:
	{ ld8	r38,[r33]; adds	r32,0x20,r32; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r37; adds	r38,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r37; ld8	r39,[r33]; adds	r38,0x0,r8 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; adds	r14,0x28,r34; adds	r1,0x0,r37 }
	{ nop.m	0x0; ld8	r38,[r32]; nop.i	0x0; }
	{ st8	[r8],r14; nop.i	0x0; br.call.sptk.many	b0,copy_word; }
	{ adds	r14,0x20,r34; nop.m	0x0; adds	r1,0x0,r37; }
	{ st8	[r8],r14; nop.i	0x0; br.cond.sptk.few	400000000006F460; }
400000000006F550 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000006F560 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000006F570 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; copy_redirects: 400000000006F580
;;   Called from:
;;     400000000006F76C (in copy_command)
copy_redirects proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; cmp.eq	p06,p07,0x0,r32; mov	r34,b2 }
	{ adds	r36,0x0,r1; nop.m	0x0; adds	r37,0x0,r32; }
	{ (p06) adds	r8,0x0,r0; adds	r33,0x0,r0; (p06) br.cond.dpnt.few	400000000006F670; }

l400000000006F5A6:
	{ (p16) chk.a.clr	r0,3FFFFFFFFF0EF5A6; nop; break.b	0x80000 }

l400000000006F5B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,copy_redirect; }
	{ st8	[r33],r8; nop.m	0x0; adds	r1,0x0,r36; }
	{ nop.m	0x0; ld8	r32,[r32]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p07) br.cond.dpnt.few	400000000006F640; }

l400000000006F5F0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000006F600:
	{ adds	r33,0x0,r8; adds	r37,0x0,r32; br.call.sptk.many	b0,copy_redirect; }
	{ st8	[r33],r8; nop.m	0x0; adds	r1,0x0,r36; }
	{ nop.m	0x0; ld8	r32,[r32]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p06) br.cond.dptk.few	400000000006F600; }

l400000000006F640:
	{ cmp.eq	p06,p07,0x0,r33; adds	r37,0x0,r8; (p06) br.cond.dpnt.few	400000000006F670; }

l400000000006F650:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,list_reverse; }
	{ adds	r1,0x0,r36; nop.m	0x0; nop.i	0x0 }

l400000000006F670:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r34,400000000006F680; br.ret	b0; }
400000000006F690 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000006F6A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000006F6B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; copy_command: 400000000006F6C0
;;   Called from:
;;     400000000004B31C (in named_function_string)
;;     400000000004B54C (in named_function_string)
;;     4000000000059EAC (in fn4000000000059C80)
;;     40000000000648EC (in bind_function)
;;     40000000000704AC (in copy_function_def_contents)
copy_command proc
	{ alloc	r39,ar.pfs,0xC,0x0,0x9; cmp.eq	p06,p07,0x0,r32; mov	r38,b6 }
	{ adds	r40,0x0,r1; nop.m	0x0; (p06) br.cond.dpnt.few	400000000006F7C0; }

l400000000006F6E0:
	{ addl	r41,32,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r40; adds	r33,0x0,r8; adds	r41,0x0,r8 }
	{ adds	r42,0x0,r32; addl	r43,32,r0; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ adds	r18,0x10,r32; adds	r15,0x4,r32; adds	r14,0x8,r32 }
	{ adds	r17,0x4,r33; adds	r16,0x8,r33; adds	r1,0x0,r40; }
	{ ld8	r41,[r18]; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r15]; cmp.eq	p06,p07,0x0,r41 }
	{ nop.m	0x0; st4	[r14],r16; nop.i	0x0; }
	{ st4	[r15],r17; (p06) br.cond.dpnt.few	400000000006F790; br.call.sptk.many	b0,copy_redirects; }

l400000000006F76C:
	{ (p49) cmp.lt.unc	p63,p09,r63,r44; (p01) invala; nop }
	{ nop; Invalid; break.i	0x1000 }
	{ nop; cmp.lt	p00,p00,r32,r0; Invalid }

l400000000006F790:
	{ nop.m	0x0; ld4	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0xE,r14; (p07) br.cond.dptk.few	400000000006F7E0; }

l400000000006F7B0:
	{ (p06) adds	r32,0x0,r33; nop.m	0x0; nop.i	0x0; }

l400000000006F7B6:
	{ break.m	0x4000; nop; nop }

l400000000006F7C0:
	{ adds	r8,0x0,r32; nop.m	0x0; mov.i	ar.pfs,r39; }

l400000000006F7C2:
	{ break.m	0x42008; cmp.eq	p32,p00,r0,r0; Invalid }
	{ cmp.lt	p32,p00,r0,r0; (p20) nop; Invalid }

l400000000006F7E0:
	{ adds	r15,0x0,r14; nop.m	0x0; addl	r14,580,r1; }
	{ ld8	r14,[r14]; shladd	r14,r15,0x3,r14; nop.i	0x0; }
	{ ld8	r15,[r14]; add	r14,r14,r15; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r14,400000000006F810; br.cond	b6; }
400000000006F820 09 70 60 40 00 21 00 02 84 00 42 20 84 09 01 84 .p`@.!....B ....
400000000006F830 11 48 01 1C 18 10 00 00 00 02 00 00 18 0B 00 50 .H.............P
400000000006F840 08 08 00 50 00 21 00 40 84 30 23 00 70 02 AA 00 ...P.!.@.0#.p...
400000000006F850 09 00 00 00 01 00 80 00 80 00 42 00 00 00 04 00 ..........B.....
400000000006F860 10 00 00 00 01 00 00 30 05 80 03 80 08 00 84 00 .......0........
400000000006F870 09 00 61 40 00 21 00 00 00 02 00 20 85 01 00 90 ..a@.!..... ....
400000000006F880 11 18 01 40 18 10 00 00 00 02 00 00 48 94 07 50 ...@........H..P
400000000006F890 08 70 00 46 00 21 40 02 20 00 42 20 00 40 01 84 .p.F.!@. .B .@..
400000000006F8A0 0B 10 01 10 00 21 F0 40 38 20 28 00 00 00 04 00 .....!.@8 (.....
400000000006F8B0 08 00 00 00 01 00 80 78 90 20 2B 00 00 00 04 00 .......x. +.....
400000000006F8C0 19 48 01 1C 18 10 00 00 00 02 00 00 08 F9 FF 58 .H.............X
400000000006F8D0 09 70 40 46 00 21 00 40 90 30 23 20 00 40 01 84 .p@F.!.@.0# .@..
400000000006F8E0 0B 48 01 1C 18 10 60 00 A4 0E 72 00 00 00 04 00 .H....`...r.....
400000000006F8F0 D1 40 00 00 00 21 00 00 00 02 00 03 30 00 00 43 .@...!......0..C
400000000006F900 11 00 00 00 01 00 00 00 00 02 00 00 88 FC FF 58 ...............X
400000000006F910 08 08 00 50 00 21 00 00 00 02 00 00 00 00 04 00 ...P.!..........
400000000006F920 08 18 11 46 00 21 10 81 88 00 42 00 70 02 AA 00 ...F.!....B.p...
400000000006F930 09 80 10 44 00 21 F0 C0 84 00 42 00 04 08 01 84 ...D.!....B.....
400000000006F940 08 70 00 46 10 10 00 40 44 30 23 00 60 0A 00 07 .p.F...@D0#.`...
400000000006F950 02 40 00 40 00 21 00 00 00 02 00 00 00 00 04 00 .@.@.!..........
400000000006F960 18 00 38 20 90 11 00 10 3D 30 23 80 08 00 84 00 ..8 ....=0#.....
400000000006F970 09 00 61 40 00 21 00 00 00 02 00 20 05 02 00 90 ..a@.!..... ....
400000000006F980 11 18 01 40 18 10 00 00 00 02 00 00 48 93 07 50 ...@........H..P
400000000006F990 08 70 00 46 00 21 40 02 20 00 42 40 04 40 00 84 .p.F.!@. .B@.@..
400000000006F9A0 0B 08 00 50 00 21 F0 40 38 20 28 00 00 00 04 00 ...P.!.@8 (.....
400000000006F9B0 08 00 00 00 01 00 80 78 90 20 2B 00 00 00 04 00 .......x. +.....
400000000006F9C0 19 48 01 1C 18 10 00 00 00 02 00 00 08 FD FF 58 .H.............X
400000000006F9D0 08 70 40 46 00 21 00 00 00 02 00 20 00 40 01 84 .p@F.!..... .@..
400000000006F9E0 09 00 20 48 98 11 00 00 00 02 00 60 84 19 01 84 .. H.......`....
400000000006F9F0 11 48 01 1C 18 10 00 00 00 02 00 00 D8 FC FF 58 .H.............X
400000000006FA00 09 48 01 46 18 10 E0 80 88 00 42 20 00 40 01 84 .H.F......B .@..
400000000006FA10 08 00 00 00 01 00 60 00 A4 0E 72 00 00 00 04 00 ......`...r.....
400000000006FA20 19 00 20 1C 98 11 00 00 00 02 00 03 30 00 00 43 .. .........0..C
400000000006FA30 11 00 00 00 01 00 00 00 00 02 00 00 98 FC FF 58 ...............X
400000000006FA40 08 00 00 00 01 00 10 00 A0 00 42 20 05 40 00 84 ..........B .@..
400000000006FA50 18 78 60 44 00 21 E0 C0 84 00 42 00 00 00 00 20 .x`D.!....B.... 
400000000006FA60 09 00 01 42 00 21 00 00 00 02 00 00 70 02 AA 00 ...B.!......p...
400000000006FA70 18 00 A4 1E 98 11 80 00 80 00 42 00 00 00 00 20 ..........B.... 
400000000006FA80 10 00 88 1C 98 11 00 30 05 80 03 80 08 00 84 00 .......0........
400000000006FA90 08 70 60 40 00 21 00 00 00 02 00 20 85 01 00 90 .p`@.!..... ....
400000000006FAA0 09 00 01 42 00 21 00 00 00 02 00 20 84 09 01 84 ...B.!..... ....
400000000006FAB0 11 20 01 1C 18 10 00 00 00 02 00 00 18 92 07 50 . .............P
400000000006FAC0 08 70 00 48 00 21 30 02 20 00 42 00 00 00 04 00 .p.H.!0. .B.....
400000000006FAD0 09 10 01 10 00 21 10 00 A0 00 42 80 04 21 01 84 .....!....B..!..
400000000006FAE0 0A 78 20 1C 10 14 90 02 38 30 20 00 00 00 04 00 .x .....80 .....
400000000006FAF0 19 40 3C 46 90 15 00 00 00 02 00 00 D8 FB FF 58 .@<F...........X
400000000006FB00 08 08 00 50 00 21 00 40 8C 30 23 00 00 00 04 00 ...P.!.@.0#.....
400000000006FB10 19 48 01 48 18 10 00 00 00 02 00 00 B8 FB FF 58 .H.H...........X
400000000006FB20 09 70 40 44 00 21 00 00 00 02 00 20 00 40 01 84 .p@D.!..... .@..
400000000006FB30 08 00 20 1C 98 11 00 10 85 30 23 00 00 00 04 00 .. ......0#.....
400000000006FB40 09 40 00 40 00 21 00 00 00 02 00 00 70 02 AA 00 .@.@.!......p...
400000000006FB50 10 00 00 00 01 00 00 30 05 80 03 80 08 00 84 00 .......0........
400000000006FB60 09 00 61 40 00 21 00 00 00 02 00 20 85 01 00 90 ..a@.!..... ....
400000000006FB70 11 10 01 40 18 10 00 00 00 02 00 00 58 91 07 50 ...@........X..P
400000000006FB80 08 78 00 44 00 21 E0 00 20 00 42 20 82 10 01 84 .x.D.!.. .B ....
400000000006FB90 09 10 41 44 00 21 50 02 20 00 42 20 00 40 01 84 ..AD.!P. .B .@..
400000000006FBA0 09 80 10 1E 10 14 90 02 44 30 20 00 00 00 04 00 ........D0 .....
400000000006FBB0 09 20 40 1C 90 15 F0 00 3C 20 20 00 00 00 04 00 . @.....<  .....
400000000006FBC0 11 00 3C 1C 90 11 00 00 00 02 00 00 08 F4 FF 58 ..<............X
400000000006FBD0 09 10 01 44 18 10 E0 40 94 00 42 20 00 40 01 84 ...D...@..B .@..
400000000006FBE0 08 00 00 00 01 00 60 00 88 0E 72 00 00 00 04 00 ......`...r.....
400000000006FBF0 19 00 20 1C 98 11 00 00 00 02 00 03 70 06 00 43 .. .........p..C
400000000006FC00 E9 20 01 00 00 21 00 00 00 02 00 00 00 00 04 00 . ...!..........
400000000006FC10 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000006FC20 11 48 81 00 00 24 00 00 00 02 00 00 A8 90 07 50 .H...$.........P
400000000006FC30 09 70 20 44 00 21 30 02 20 00 42 20 00 40 01 84 .p D.!0. .B .@..
400000000006FC40 11 48 01 1C 18 10 00 00 00 02 00 00 88 F5 FF 58 .H.............X
400000000006FC50 09 70 40 44 00 21 F0 40 8C 00 42 20 00 40 01 84 .p@D.!.@..B .@..
400000000006FC60 08 00 00 00 01 00 90 02 38 30 20 00 00 00 04 00 ........80 .....
400000000006FC70 19 00 20 1E 98 11 00 00 00 02 00 00 58 FA FF 58 .. .........X..X
400000000006FC80 08 70 60 44 00 21 00 20 8D 30 23 00 00 00 04 00 .p`D.!. .0#.....
400000000006FC90 09 80 40 46 00 21 F0 C0 8C 00 42 20 00 40 01 84 ..@F.!....B .@..
400000000006FCA0 08 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
400000000006FCB0 09 00 20 20 98 11 20 02 88 30 20 00 00 00 04 00 ..  .. ..0 .....
400000000006FCC0 11 00 38 1E 90 11 70 00 88 0C F2 03 F0 05 00 43 ..8...p........C
400000000006FCD0 10 00 00 00 01 00 40 02 8C 00 42 00 50 FF FF 48 ......@...B.P..H
400000000006FCE0 08 70 60 40 00 21 00 00 00 02 00 20 05 01 00 90 .p`@.!..... ....
400000000006FCF0 09 00 01 42 00 21 00 00 00 02 00 20 84 09 01 84 ...B.!..... ....
400000000006FD00 11 18 01 1C 18 10 00 00 00 02 00 00 C8 8F 07 50 ...............P
400000000006FD10 09 70 20 46 00 21 20 02 20 00 42 20 00 40 01 84 .p F.! . .B .@..
400000000006FD20 11 48 01 1C 18 10 00 00 00 02 00 00 A8 F9 FF 58 .H.............X
400000000006FD30 18 70 00 46 10 10 F0 40 88 00 42 00 00 00 00 20 .p.F...@..B.... 
400000000006FD40 09 08 00 50 00 21 00 00 00 02 00 00 70 02 AA 00 ...P.!......p...
400000000006FD50 18 00 20 1E 98 11 00 70 88 20 23 00 00 00 00 20 .. ....p. #.... 
400000000006FD60 09 40 00 40 00 21 00 00 00 02 00 00 60 0A 00 07 .@.@.!......`...
400000000006FD70 10 00 88 42 98 11 00 00 00 02 00 80 08 00 84 00 ...B............
400000000006FD80 08 70 60 40 00 21 00 00 00 02 00 20 85 01 00 90 .p`@.!..... ....
400000000006FD90 09 00 01 42 00 21 00 00 00 02 00 20 84 09 01 84 ...B.!..... ....
400000000006FDA0 11 18 01 1C 18 10 00 00 00 02 00 00 28 8F 07 50 ............(..P
400000000006FDB0 09 20 21 46 00 21 20 02 20 00 42 20 00 40 01 84 . !F.! . .B .@..
400000000006FDC0 11 48 01 48 18 10 00 00 00 02 00 00 08 B9 FA 58 .H.H...........X
400000000006FDD0 11 08 00 50 00 21 90 0A 20 00 42 00 F8 8E 07 50 ...P.!.. .B....P
400000000006FDE0 08 08 00 50 00 21 A0 02 90 30 20 20 05 40 00 84 ...P.!...0  .@..
400000000006FDF0 19 00 00 00 01 00 00 00 00 02 00 00 98 B3 FA 58 ...............X
400000000006FE00 09 78 20 44 00 21 E0 80 8C 00 42 20 00 40 01 84 .x D.!....B .@..
400000000006FE10 08 00 00 00 01 00 90 02 38 30 20 00 00 00 04 00 ........80 .....
400000000006FE20 19 00 20 1E 98 11 00 00 00 02 00 00 A8 F8 FF 58 .. ............X
400000000006FE30 18 70 00 46 10 10 F0 80 88 00 42 00 00 00 00 20 .p.F......B.... 
400000000006FE40 09 08 00 50 00 21 00 00 00 02 00 00 70 02 AA 00 ...P.!......p...
400000000006FE50 18 00 20 1E 98 11 00 70 88 20 23 00 00 00 00 20 .. ....p. #.... 
400000000006FE60 09 40 00 40 00 21 00 00 00 02 00 00 60 0A 00 07 .@.@.!......`...
400000000006FE70 10 00 88 42 98 11 00 00 00 02 00 80 08 00 84 00 ...B............
400000000006FE80 08 70 60 40 00 21 00 00 00 02 00 20 85 02 00 90 .p`@.!..... ....
400000000006FE90 09 00 01 42 00 21 00 00 00 02 00 20 84 09 01 84 ...B.!..... ....
400000000006FEA0 11 18 01 1C 18 10 00 00 00 02 00 00 28 8E 07 50 ............(..P
400000000006FEB0 08 78 00 46 00 21 E0 00 20 00 42 00 00 00 04 00 .x.F.!.. .B.....
400000000006FEC0 09 88 20 46 00 21 20 02 20 00 42 20 00 40 01 84 .. F.! . .B .@..
400000000006FED0 09 80 10 1E 10 14 90 02 44 30 20 00 00 00 04 00 ........D0 .....
400000000006FEE0 09 20 40 1C 90 15 F0 00 3C 20 20 00 00 00 04 00 . @.....<  .....
400000000006FEF0 11 00 3C 1C 90 11 00 00 00 02 00 00 D8 F2 FF 58 ..<............X
400000000006FF00 09 70 20 44 00 21 F0 80 8C 00 42 20 00 40 01 84 .p D.!....B .@..
400000000006FF10 08 00 00 00 01 00 90 02 3C 30 20 00 00 00 04 00 ........<0 .....
400000000006FF20 19 00 20 1C 98 11 00 00 00 02 00 00 A8 F2 FF 58 .. ............X
400000000006FF30 08 78 60 46 00 21 00 00 00 02 00 C0 01 11 01 84 .x`F.!..........
400000000006FF40 02 08 00 50 00 21 30 02 8D 00 42 00 00 00 04 00 ...P.!0...B.....
400000000006FF50 19 48 01 1E 18 10 00 40 38 30 23 00 78 F2 FF 58 .H.....@80#.x..X
400000000006FF60 08 00 00 00 01 00 E0 C0 88 00 42 20 00 40 01 84 ..........B .@..
400000000006FF70 09 00 00 00 01 00 90 02 8C 30 20 00 00 00 04 00 .........0 .....
400000000006FF80 11 00 20 1C 98 11 00 00 00 02 00 00 48 F7 FF 58 .. .........H..X
400000000006FF90 09 70 80 44 00 21 10 00 A0 00 42 00 70 02 AA 00 .p.D.!....B.p...
400000000006FFA0 08 00 20 1C 98 11 00 00 00 02 00 00 60 0A 00 07 .. .........`...
400000000006FFB0 18 40 00 40 00 21 00 10 85 30 23 80 08 00 84 00 .@.@.!...0#.....
400000000006FFC0 09 70 60 40 00 21 00 02 84 00 42 20 84 09 01 84 .p`@.!....B ....
400000000006FFD0 11 48 01 1C 18 10 00 00 00 02 00 00 78 F0 FF 58 .H..........x..X
400000000006FFE0 08 08 00 50 00 21 00 40 84 30 23 00 70 02 AA 00 ...P.!.@.0#.p...
400000000006FFF0 09 00 00 00 01 00 80 00 80 00 42 00 00 00 04 00 ..........B.....
4000000000070000 10 00 00 00 01 00 00 30 05 80 03 80 08 00 84 00 .......0........
4000000000070010 08 70 60 40 00 21 00 00 00 02 00 20 05 01 00 90 .p`@.!..... ....
4000000000070020 09 00 01 42 00 21 00 00 00 02 00 20 84 09 01 84 ...B.!..... ....
4000000000070030 11 20 01 1C 18 10 00 00 00 02 00 00 98 8C 07 50 . .............P
4000000000070040 08 70 00 48 00 21 30 02 20 00 42 00 00 00 04 00 .p.H.!0. .B.....
4000000000070050 09 10 01 10 00 21 10 00 A0 00 42 80 44 20 01 84 .....!....B.D ..
4000000000070060 0A 78 20 1C 10 14 80 78 8C 20 2B 00 00 00 04 00 .x ....x. +.....
4000000000070070 19 48 01 1C 18 10 00 00 00 02 00 00 58 F1 FF 58 .H..........X..X
4000000000070080 08 00 00 00 01 00 E0 00 90 20 20 E0 41 10 01 84 .........  .A...
4000000000070090 09 00 20 46 98 11 10 00 A0 00 42 00 01 00 01 84 .. F......B.....
40000000000700A0 08 00 00 00 01 00 00 70 3C 20 23 00 70 02 AA 00 .......p< #.p...
40000000000700B0 09 00 00 00 01 00 00 10 85 30 23 00 00 00 04 00 .........0#.....
40000000000700C0 10 00 00 00 01 00 00 30 05 80 03 80 08 00 84 00 .......0........
40000000000700D0 08 70 60 40 00 21 00 00 00 02 00 20 05 01 00 90 .p`@.!..... ....
40000000000700E0 09 00 01 42 00 21 00 00 00 02 00 20 84 09 01 84 ...B.!..... ....
40000000000700F0 11 18 01 1C 18 10 00 00 00 02 00 00 D8 8B 07 50 ...............P
4000000000070100 09 18 21 46 00 21 20 02 20 00 42 20 00 40 01 84 ..!F.! . .B .@..
4000000000070110 11 48 01 46 18 10 00 00 00 02 00 00 B8 F5 FF 58 .H.F...........X
4000000000070120 09 70 20 44 00 21 10 00 A0 00 42 00 70 02 AA 00 .p D.!....B.p...
4000000000070130 08 00 20 1C 98 11 00 00 00 02 00 00 60 0A 00 07 .. .........`...
4000000000070140 18 40 00 40 00 21 00 10 85 30 23 80 08 00 84 00 .@.@.!...0#.....
4000000000070150 09 70 60 40 00 21 00 02 84 00 42 20 84 09 01 84 .p`@.!....B ....
4000000000070160 11 48 01 1C 18 10 00 00 00 02 00 00 28 04 00 50 .H..........(..P
4000000000070170 08 08 00 50 00 21 00 40 84 30 23 00 70 02 AA 00 ...P.!.@.0#.p...
4000000000070180 09 00 00 00 01 00 80 00 80 00 42 00 00 00 04 00 ..........B.....
4000000000070190 11 00 00 00 01 00 00 30 05 80 03 80 08 00 84 00 .......0........
40000000000701A0 08 18 61 40 00 21 90 02 01 00 48 00 00 00 04 00 ..a@.!....H.....
40000000000701B0 19 00 01 42 00 21 10 C2 84 00 42 00 18 8B 07 50 ...B.!....B....P
40000000000701C0 08 70 00 46 18 10 00 C1 20 00 42 40 04 40 00 84 .p.F.... .B@.@..
40000000000701D0 0B 08 00 50 00 21 F0 C0 38 00 42 C0 81 70 00 84 ...P.!..8.B..p..
40000000000701E0 09 78 00 1E 10 10 90 02 38 30 20 00 00 00 04 00 .x......80 .....
40000000000701F0 11 00 3C 20 90 11 00 00 00 02 00 00 D8 F4 FF 58 ..< ...........X
4000000000070200 09 70 20 44 00 21 00 00 00 02 00 20 00 40 01 84 .p D.!..... .@..
4000000000070210 0B 00 20 1C 98 11 E0 00 8C 30 20 00 00 00 04 00 .. ......0 .....
4000000000070220 09 00 00 00 01 00 E0 80 38 00 42 00 00 00 04 00 ........8.B.....
4000000000070230 11 48 01 1C 18 10 00 00 00 02 00 00 98 F4 FF 58 .H.............X
4000000000070240 02 70 40 44 00 21 10 00 A0 00 42 00 00 00 04 00 .p@D.!....B.....
4000000000070250 18 00 20 1C 98 11 00 10 85 30 23 00 F0 F8 FF 48 .. ......0#....H
4000000000070260 08 18 01 00 00 21 00 00 00 02 00 00 00 00 04 00 .....!..........
4000000000070270 09 78 40 4A 00 21 E0 C0 84 00 42 00 04 08 01 84 .x@J.!....B.....
4000000000070280 08 00 8C 1E 98 11 00 28 39 30 23 00 00 00 04 00 .......(90#.....
4000000000070290 09 40 00 40 00 21 00 00 00 02 00 00 70 02 AA 00 .@.@.!......p...
40000000000702A0 10 00 00 00 01 00 00 30 05 80 03 80 08 00 84 00 .......0........
40000000000702B0 08 30 00 48 07 39 00 00 00 02 00 20 05 18 01 84 .0.H.9..... ....
40000000000702C0 19 00 01 42 00 21 00 00 00 02 00 03 B0 FF FF 4B ...B.!.........K
40000000000702D0 11 00 00 00 01 00 00 00 00 02 00 00 38 8B 06 50 ............8..P
40000000000702E0 08 78 40 4A 00 21 30 02 20 00 42 C0 81 09 01 84 .x@J.!0. .B.....
40000000000702F0 0A 08 00 50 00 21 00 18 3D 30 23 00 00 00 04 00 ...P.!..=0#.....
4000000000070300 19 00 94 1C 98 11 00 00 00 02 00 00 90 FF FF 48 ...............H
4000000000070310 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000070320 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000070330 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000070340 01 18 19 0A 80 05 20 02 00 62 00 80 04 08 00 84 ...... ..b......
4000000000070350 11 28 81 00 00 24 00 00 00 02 00 00 78 89 07 50 .(...$......x..P
4000000000070360 08 78 00 40 00 21 E0 00 20 00 42 00 00 00 04 00 .x.@.!.. .B.....
4000000000070370 09 88 20 40 00 21 10 02 20 00 42 20 00 20 01 84 .. @.!.. .B . ..
4000000000070380 09 80 10 1E 10 14 50 02 44 30 20 00 00 00 04 00 ......P.D0 .....
4000000000070390 09 20 40 1C 90 15 F0 00 3C 20 20 00 00 00 04 00 . @.....<  .....
40000000000703A0 11 00 3C 1C 90 11 00 00 00 02 00 00 28 EC FF 58 ..<.........(..X
40000000000703B0 08 78 40 40 00 21 00 00 00 02 00 C0 81 08 01 84 .x@@.!..........
40000000000703C0 02 08 00 48 00 21 00 C2 80 00 42 00 00 00 04 00 ...H.!....B.....
40000000000703D0 19 28 01 1E 18 10 00 40 38 30 23 00 F8 ED FF 58 .(.....@80#....X
40000000000703E0 08 00 00 00 01 00 E0 80 84 00 42 20 00 20 01 84 ..........B . ..
40000000000703F0 09 00 00 00 01 00 50 02 80 30 20 00 00 00 04 00 ......P..0 .....
4000000000070400 11 00 20 1C 98 11 00 00 00 02 00 00 C8 F2 FF 58 .. ............X
4000000000070410 09 70 60 42 00 21 10 00 90 00 42 00 30 02 AA 00 .p`B.!....B.0...
4000000000070420 08 00 00 00 01 00 00 40 38 30 23 00 20 0A 00 07 .......@80#. ...
4000000000070430 19 00 00 00 01 00 80 00 84 00 42 80 08 00 84 00 ..........B.....

;; copy_function_def_contents: 4000000000070440
;;   Called from:
;;     4000000000064AFC (in bind_function_def)
;;     40000000000705CC (in copy_function_def)
copy_function_def_contents proc
	{ alloc	r36,ar.pfs,0x8,0x0,0x6; adds	r14,0x8,r32; nop.b	0x0 }
	{ adds	r37,0x0,r1; mov	r35,b3; adds	r34,0x18,r32; }
	{ ld8	r38,[r14]; nop.i	0x0; br.call.sptk.many	b0,copy_word; }
	{ adds	r15,0x10,r32; adds	r14,0x8,r33; adds	r1,0x0,r37; }
	{ ld8	r15,[r15]; st8	[r8],r14; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r15; adds	r38,0x0,r15; (p06) br.cond.dpnt.few	40000000000704C0; }

l40000000000704A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,copy_command; }
	{ nop.m	0x0; adds	r1,0x0,r37; adds	r15,0x0,r8 }

l40000000000704C0:
	{ ld8	r14,[r34]; nop.m	0x0; adds	r16,0x0,r33 }
	{ adds	r18,0x10,r33; ld4	r17,[r32],4; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; st8	[r15],r18; nop.i	0x0 }
	{ st4	[r16],r4,4; ld4	r15,[r32]; adds	r38,0x0,r14; }
	{ st4	[r15],r16; (p06) br.cond.dpnt.few	4000000000070550; br.call.sptk.many	b0,fn400000000001B6C0; }

l400000000007050C:
	{ (p14) nop; cmp.lt	p32,p16,r9,r64; zxt1	r0,r64 }
	{ (p61) nop; invala; Invalid }
	{ cmp.eq	p08,p25,r0,r66; break.x	0x80C2200801000 }
	{ (p34) nop; nop; Invalid }
	{ cmp.eq	p08,p09,r0,r66; zxt1	r38,r64; zxt1	r32,r64; }

l4000000000070550:
	{ adds	r15,0x18,r33; adds	r8,0x0,r33; mov.i	ar.pfs,r36; }
	{ st8	[r14],r15; mov.spnt	b0,r35,4000000000070560; br.ret	b0; }
4000000000070570 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; copy_function_def: 4000000000070580
;;   Called from:
;;     4000000000064B3C (in bind_function_def)
copy_function_def proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; mov	r34,b2; adds	r36,0x0,r1; }
	{ addl	r37,32,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r36; adds	r33,0x0,r8; mov.spnt	b0,r34,40000000000705A0; }
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	copy_function_def_contents; }
40000000000705D0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000705E0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000705F0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; get_name_for_error: 4000000000070600
;;   Called from:
;;     400000000007085C (in fn4000000000070840)
;;     400000000007145C (in parser_error)
;;     400000000007A03C (in fn4000000000079240)
;;     40000000000ED3EC (in fn40000000000ED3C0)
;;     40000000000EF4CC (in get_working_directory)
get_name_for_error proc
	{ alloc	r33,ar.pfs,0x5,0x0,0x3; addl	r14,6512,r1; mov	r32,b0 }
	{ adds	r34,0x0,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	40000000000706D0 }

l4000000000070640:
	{ addl	r14,6476,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld8	r35,[r14]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r35; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000070690; }

l4000000000070670:
	{ ld1	r14,[r35]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000707E0 }

l4000000000070690:
	{ nop.m	0x0; addl	r8,-8804,r1; nop.i	0x0; }
	{ ld8	r8,[r8]; nop.m	0x0; nop.i	0x0 }

l40000000000706B0:
	{ nop.m	0x0; mov.i	ar.pfs,r33; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r32,40000000000706C0; br.ret	b0 }

l40000000000706D0:
	{ nop.m	0x0; addl	r35,-8796,r1; nop.i	0x0; }
	{ ld8	r35,[r35]; nop.i	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r14,0x28,r8; nop.m	0x0; adds	r1,0x0,r34 }
	{ cmp.eq	p07,p06,0x0,r8; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000707A0; }

l4000000000070710:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x2; (p06) br.cond.dptk.few	40000000000707A0 }

l4000000000070730:
	{ adds	r8,0x8,r8; nop.m	0x0; adds	r36,0x0,r0; }
	{ nop.m	0x0; ld8	r35,[r8]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r35; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000707A0; }

l4000000000070760:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,array_reference; }
	{ adds	r1,0x0,r34; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.spnt.few	40000000000707A0; }

l4000000000070780:
	{ ld1	r14,[r8]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	40000000000706B0 }

l40000000000707A0:
	{ addl	r14,23444,r1; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ nop.m	0x0; nop.m	0x0; mov.spnt	b0,r32,40000000000707B0; }
	{ nop.m	0x0; ld8	r8,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r8; (p06) br.cond.spnt.few	4000000000070640; br.ret	b0; }

l40000000000707DC:
	{ Invalid; break.m	0x1000; break.i	0x1000 }

l40000000000707E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,base_pathname; }
	{ adds	r1,0x0,r34; cmp.eq	p06,p07,0x0,r8; (p07) br.cond.spnt.few	40000000000706B0; }

l4000000000070800:
	{ nop.m	0x0; addl	r8,-8804,r1; nop.i	0x0; }
	{ ld8	r8,[r8]; nop.i	0x0; br.cond.sptk.few	40000000000706B0; }
4000000000070820 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000070830 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000070840: 4000000000070840
;;   Called from:
;;     4000000000070DBC (in report_error)
;;     4000000000070FFC (in fatal_error)
;;     40000000000710FC (in internal_error)
;;     40000000000711FC (in internal_warning)
;;     400000000007134C (in sys_error)
fn4000000000070840 proc
	{ alloc	r37,ar.pfs,0xD,0x0,0x7; adds	r38,0x0,r1; mov	r36,b4; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,get_name_for_error; }
	{ nop.m	0x0; adds	r1,0x0,r38; adds	r33,0x0,r8 }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r32; (p06) br.cond.dptk.few	40000000000708B0; }

l4000000000070880:
	{ addl	r14,6512,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	4000000000070910 }

l40000000000708B0:
	{ addl	r14,-10652,r1; nop.m	0x0; addl	r41,-8764,r1 }
	{ addl	r40,1,r0; nop.m	0x0; adds	r42,0x0,r33; }
	{ ld8	r14,[r14]; ld8	r41,[r41]; nop.i	0x0; }
	{ ld8	r39,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ adds	r1,0x0,r38; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,4000000000070900; br.ret	b0; }

l4000000000070910:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,executing_line_number; }
	{ adds	r1,0x0,r38; cmp4.lt	p07,p06,0x0,r8; adds	r35,0x0,r8 }
	{ addl	r40,1,r0; adds	r42,0x0,r33; (p06) br.cond.spnt.few	40000000000708B0; }

l4000000000070940:
	{ addl	r15,-10652,r1; addl	r14,7248,r1; nop.i	0x0 }
	{ addl	r41,-8772,r1; addl	r43,-8788,r1; adds	r44,0x0,r35; }
	{ ld8	r15,[r15]; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; ld8	r43,[r43]; nop.i	0x0; }
	{ ld8	r34,[r15]; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000709E0; }

l4000000000070990:
	{ nop.m	0x0; adds	r39,0x0,r34; nop.i	0x0 }
	{ ld8	r41,[r41]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ adds	r1,0x0,r38; nop.m	0x0; nop.i	0x0 }

l40000000000709C0:
	{ nop.m	0x0; mov.i	ar.pfs,r37; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r36,40000000000709D0; br.ret	b0 }

l40000000000709E0:
	{ addl	r40,-8780,r1; adds	r39,0x0,r0; addl	r41,5,r0; }
	{ ld8	r40,[r40]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r38; adds	r43,0x0,r8; adds	r39,0x0,r34 }
	{ addl	r40,1,r0; adds	r42,0x0,r33; adds	r44,0x0,r35; }
	{ nop.m	0x0; addl	r41,-8772,r1; nop.i	0x0; }
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ nop.m	0x0; adds	r1,0x0,r38; br.cond.sptk.few	40000000000709C0; }
4000000000070A50 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000070A60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000070A70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; programming_error: 4000000000070A80
;;   Called from:
;;     400000000004489C (in make_redirection)
;;     400000000004571C (in fn4000000000045480)
;;     4000000000071A0C (in command_error)
;;     4000000000079636 (in fn4000000000079240)
;;     40000000000796EC (in fn4000000000079240)
;;     400000000007C6EC (in describe_pid)
;;     40000000000AF83C (in trap_handler)
;;     40000000000E893C (in progcomp_insert)
programming_error proc
	{ alloc	r44,ar.pfs,0x13,0x0,0xF; adds	r16,0x8,r12; adds	r17,0x0,r12 }
	{ adds	r12,0xFFFFFFFFFFFFFFC0,r12; addl	r14,5896,r1; addl	r40,-10652,r1; }
	{ mov.m	r46,UNAT; st8.spill	[r16],r112,-16; mov	r43,b3 }
	{ nop.m	0x0; adds	r45,0x0,r1; adds	r48,0x0,r0; }
	{ nop.m	0x0; st8.spill	[r17],r112,-16; nop.i	0x0 }
	{ st8.spill	[r16],r112,-16; ld8	r40,[r40]; nop.i	0x0; }
	{ st8.spill	[r17],r112,-16; st8.spill	[r16],r112,-16; nop.i	0x0; }
	{ st8.spill	[r34],r17; st8.spill	[r33],r16; nop.i	0x0; }
	{ ld4	r47,[r14]; nop.i	0x0; br.call.sptk.many	b0,give_terminal_to; }
	{ adds	r50,0x18,r12; adds	r49,0x0,r32; adds	r1,0x0,r45 }
	{ ld8	r47,[r40]; addl	r48,1,r0; br.call.sptk.many	b0,fn400000000001A560; }
	{ adds	r1,0x0,r45; nop.m	0x0; addl	r47,10,r0 }
	{ ld8	r48,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BD80; }
	{ adds	r1,0x0,r45; addl	r49,5,r0; adds	r47,0x0,r0; }
	{ addl	r14,6116,r1; nop.m	0x0; addl	r48,-8740,r1; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000070C00; }

l4000000000070B90:
	{ nop.m	0x0; ld8	r48,[r48]; nop.i	0x0 }
	{ ld8	r41,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ addl	r48,1,r0; adds	r49,0x0,r8; nop.i	0x0 }
	{ adds	r1,0x0,r45; adds	r47,0x0,r41; br.call.sptk.many	b0,fn400000000001C040; }
	{ nop.m	0x0; adds	r1,0x0,r45; nop.i	0x0 }
	{ ld8	r47,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ nop.m	0x0; adds	r1,0x0,r45; br.call.sptk.many	b0,fn400000000001C1A0; }

l4000000000070C00:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,last_history_line; }
	{ nop.m	0x0; adds	r1,0x0,r45; adds	r41,0x0,r8 }
	{ ld8	r42,[r40]; adds	r47,0x0,r0; addl	r49,5,r0; }
	{ nop.m	0x0; addl	r48,-8748,r1; nop.i	0x0; }
	{ ld8	r48,[r48]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ cmp.eq	p07,p06,0x0,r41; adds	r1,0x0,r45; adds	r47,0x0,r42 }
	{ addl	r48,1,r0; adds	r49,0x0,r8; (p07) addl	r50,-8756,r1; }

l4000000000070C70:
	{ nop.m	0x0; (p06) adds	r50,0x0,r41; nop.i	0x0; }

l4000000000070C7C:
	{ getf.s	r0,f1; Invalid; break.i	0x1000 }

l4000000000070C86:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ add	r0,r0,r1; (p24) mov.sptk	b5,r0,4000000000071096; (p16) nop }
	{ Invalid; (p24) nop; br.call.sptk.few	b4,b0 }
	{ break.m	0x4000; (p32) nop; nop }
	{ Invalid; nop; (p16) nop.b	0x2D000 }
	{ Invalid; (p32) nop; break.b	0x80000 }
	{ Invalid; nop; (p48) br.call.sptk.few	b3,b0 }
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; (p32) nop; break.b	0x80000 }
	{ break.m	0x0; nop; break.i	0x80000 }
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ break.m	0x4000; nop; Invalid }

;; report_error: 4000000000070D40
;;   Called from:
;;     400000000001E1AC (in main)
;;     400000000001E72C (in main)
;;     400000000001F3BC (in main)
;;     4000000000020A5C (in main)
;;     400000000006D1FC (in initialize_shell_variables)
;;     400000000006DE5C (in initialize_shell_variables)
;;     4000000000070D3C (in programming_error)
;;     4000000000070F3C (in file_error)
;;     4000000000071B3C (in err_badarraysub)
;;     4000000000071BEC (in err_unboundvar)
;;     4000000000071C6C (in err_readonly)
;;     4000000000089D5C (in fn4000000000089000)
;;     400000000008B48C (in fn400000000008A3C0)
;;     400000000009933C (in fn4000000000099100)
;;     40000000000A4FFC (in fn40000000000A1400)
;;     40000000000A8F5C (in fn40000000000A7940)
;;     40000000000BF15C (in find_or_make_array_variable)
;;     40000000000C066C (in assign_compound_array_list)
;;     40000000000C0BFC (in assign_compound_array_list)
;;     40000000000EFA8C (in get_job_by_name)
report_error proc
	{ alloc	r42,ar.pfs,0x11,0x0,0xD; adds	r16,0x8,r12; adds	r17,0x0,r12 }
	{ adds	r12,0xFFFFFFFFFFFFFFC0,r12; addl	r40,-10652,r1; adds	r43,0x0,r1; }
	{ mov.m	r44,UNAT; st8.spill	[r16],r112,-16; nop.b	0x0 }
	{ ld8	r40,[r40]; mov	r41,b1; addl	r45,1,r0; }
	{ st8.spill	[r17],r112,-16; st8.spill	[r16],r112,-16; nop.i	0x0; }
	{ st8.spill	[r17],r112,-16; st8.spill	[r16],r112,-16; nop.i	0x0; }
	{ nop.m	0x0; st8.spill	[r34],r17; nop.i	0x0 }
	{ st8.spill	[r33],r16; nop.m	0x0; br.call.sptk.many	b0,fn4000000000070840; }
	{ adds	r1,0x0,r43; ld8	r45,[r40]; adds	r47,0x0,r32 }
	{ adds	r48,0x18,r12; addl	r46,1,r0; br.call.sptk.many	b0,fn400000000001A560; }
	{ adds	r1,0x0,r43; nop.m	0x0; addl	r45,10,r0 }
	{ ld8	r46,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BD80; }
	{ adds	r1,0x0,r43; addl	r14,7404,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.spnt.few	4000000000070E60; }

l4000000000070E30:
	{ nop.m	0x0; mov.i	ar.pfs,r42; nop.i	0x0 }
	{ mov.m	UNAT,r44; nop.i	0x0; mov.spnt	b0,r41,4000000000070E40 }
	{ nop.m	0x0; adds	r12,0x40,r12; br.ret	b0 }

l4000000000070E60:
	{ addl	r14,9044,r1; nop.m	0x0; nop.i	0x0; }
	{ ld4	r15,[r14]; cmp4.eq	p07,p06,0x0,r15; nop.i	0x0; }
	{ (p07) addl	r15,1,r0; (p07) st4	[r15],r14; nop.i	0x0; }

l4000000000070E86:
	{ mf.a; nop; (p16) nop; }

l4000000000070E8C:
	{ nop; Invalid; break.i	0x1000 }
	{ Invalid; break.m	0x1000; break.b	0x0 }
	{ nop; break.i	0x1000; break.i	0x1000 }
	{ shladdp4	r0,r1,0x1,r0; (p52) nop; zxt1	r0,r64 }

;; file_error: 4000000000070EC0
;;   Called from:
;;     4000000000020CDC (in main)
;;     4000000000020F4C (in main)
;;     400000000005036C (in shell_execve)
;;     4000000000070EBC (in report_error)
;;     40000000000F493C (in fn40000000000F4180)
;;     40000000000F493C (in fn40000000000F4180)
;;     40000000000F493C (in fn40000000000F4180)
;;     40000000000F84FC (in exec_builtin)
file_error proc
	{ alloc	r36,ar.pfs,0x7,0x0,0x6; adds	r33,0x0,r32; nop.b	0x0 }
	{ addl	r32,-8732,r1; mov	r35,b3; adds	r37,0x0,r1; }
	{ ld8	r32,[r32]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ nop.m	0x0; adds	r1,0x0,r37; nop.i	0x0 }
	{ ld4	r38,[r8]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B4A0; }
	{ adds	r1,0x0,r37; adds	r34,0x0,r8; mov.spnt	b0,r35,4000000000070F10; }
	{ nop.m	0x0; mov.i	ar.pfs,r36; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x3,0x0,0x0; nop.i	0x0; br.cond.sptk.many	report_error; }
4000000000070F40 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
4000000000070F50 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000070F60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000070F70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fatal_error: 4000000000070F80
;;   Called from:
;;     40000000000E8BAC (in fn40000000000E8B00)
;;     40000000000E8C6C (in fn40000000000E8B00)
fatal_error proc
	{ alloc	r42,ar.pfs,0x11,0x0,0xD; adds	r16,0x8,r12; adds	r17,0x0,r12 }
	{ adds	r12,0xFFFFFFFFFFFFFFC0,r12; addl	r40,-10652,r1; adds	r43,0x0,r1; }
	{ mov.m	r44,UNAT; st8.spill	[r16],r112,-16; nop.b	0x0 }
	{ ld8	r40,[r40]; mov	r41,b1; adds	r45,0x0,r0; }
	{ st8.spill	[r17],r112,-16; st8.spill	[r16],r112,-16; nop.i	0x0; }
	{ st8.spill	[r17],r112,-16; st8.spill	[r16],r112,-16; nop.i	0x0; }
	{ nop.m	0x0; st8.spill	[r34],r17; nop.i	0x0 }
	{ st8.spill	[r33],r16; nop.m	0x0; br.call.sptk.many	b0,fn4000000000070840; }
	{ adds	r47,0x0,r32; adds	r48,0x18,r12; adds	r1,0x0,r43 }
	{ ld8	r45,[r40]; addl	r46,1,r0; br.call.sptk.many	b0,fn400000000001A560; }
	{ adds	r1,0x0,r43; nop.m	0x0; addl	r45,10,r0 }
	{ ld8	r46,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BD80; }
	{ adds	r1,0x0,r43; addl	r45,2,r0; br.call.sptk.many	b0,sh_exit; }
	{ nop.m	0x0; break.f	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

;; internal_error: 4000000000071080
;;   Called from:
;;     4000000000020B8C (in main)
;;     4000000000020E5C (in main)
;;     400000000003F8BC (in check_identifier)
;;     40000000000446FC (in make_here_document)
;;     40000000000479EC (in xtrace_set)
;;     4000000000047A4C (in xtrace_set)
;;     400000000005041C (in shell_execve)
;;     400000000005057C (in shell_execve)
;;     400000000005B34C (in fn4000000000059C80)
;;     400000000006276C (in sv_xtracefd)
;;     400000000006286C (in sv_xtracefd)
;;     400000000006594C (in all_local_variables)
;;     4000000000067D9C (in make_local_variable)
;;     400000000006A05C (in pop_var_context)
;;     400000000006A0AC (in pop_var_context)
;;     400000000006A3DC (in pop_scope)
;;     400000000007107C (in fatal_error)
;;     4000000000071F3C (in fn4000000000071E00)
;;     4000000000071F8C (in fn4000000000071E00)
;;     400000000007F74C (in initialize_job_control)
;;     400000000007F9DC (in initialize_job_control)
;;     400000000007FB9C (in initialize_job_control)
;;     400000000007FDAC (in initialize_job_control)
;;     4000000000080A1C (in wait_for)
;;     400000000008170C (in wait_for_single_pid)
;;     40000000000821FC (in start_job)
;;     40000000000826DC (in start_job)
;;     40000000000B157C (in save_bash_input)
;;     40000000000C997C (in pre_process_line)
;;     40000000000E0F1C (in redirection_error)
;;     40000000000E14CC (in redirection_error)
;;     40000000000E155C (in redirection_error)
;;     40000000000E6BBC (in gen_compspec_completions)
;;     400000000012BE0C (in netopen)
;;     400000000012BE9C (in netopen)
;;     400000000012BF1C (in netopen)
internal_error proc
	{ alloc	r42,ar.pfs,0x11,0x0,0xD; adds	r16,0x8,r12; adds	r17,0x0,r12 }
	{ adds	r12,0xFFFFFFFFFFFFFFC0,r12; addl	r40,-10652,r1; adds	r43,0x0,r1; }
	{ mov.m	r44,UNAT; st8.spill	[r16],r112,-16; nop.b	0x0 }
	{ ld8	r40,[r40]; mov	r41,b1; addl	r45,1,r0; }
	{ st8.spill	[r17],r112,-16; st8.spill	[r16],r112,-16; nop.i	0x0; }
	{ st8.spill	[r17],r112,-16; st8.spill	[r16],r112,-16; nop.i	0x0; }
	{ nop.m	0x0; st8.spill	[r34],r17; nop.i	0x0 }
	{ st8.spill	[r33],r16; nop.m	0x0; br.call.sptk.many	b0,fn4000000000070840; }
	{ adds	r1,0x0,r43; ld8	r45,[r40]; adds	r47,0x0,r32 }
	{ adds	r48,0x18,r12; addl	r46,1,r0; br.call.sptk.many	b0,fn400000000001A560; }
	{ adds	r1,0x0,r43; nop.m	0x0; addl	r45,10,r0 }
	{ ld8	r46,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BD80; }
	{ nop.m	0x0; adds	r1,0x0,r43; mov.i	ar.pfs,r42 }
	{ mov.m	UNAT,r44; nop.i	0x0; mov.spnt	b0,r41,4000000000071150 }
	{ nop.m	0x0; adds	r12,0x40,r12; br.ret	b0; }
4000000000071170 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; internal_warning: 4000000000071180
;;   Called from:
;;     400000000004443C (in make_here_document)
;;     400000000004796C (in xtrace_set)
;;     40000000000694EC (in adjust_shell_level)
;;     400000000007BC7C (in delete_job)
;;     400000000007DB5C (in fn400000000007D580)
;;     400000000007DB5C (in fn400000000007D580)
;;     400000000008130C (in wait_for_job)
;;     40000000000AF49C (in run_pending_traps)
;;     40000000000AF49C (in run_pending_traps)
;;     40000000000AF51C (in run_pending_traps)
;;     40000000000AF51C (in run_pending_traps)
;;     40000000000B1D5C (in fn40000000000B1B00)
;;     40000000000B1E4C (in discard_unwind_frame)
;;     40000000000DB30C (in set_locale_var)
;;     40000000000DB57C (in set_locale_var)
;;     40000000000DB75C (in set_locale_var)
;;     40000000000DB7DC (in set_locale_var)
;;     40000000000E7A6C (in programmable_completions)
internal_warning proc
	{ alloc	r43,ar.pfs,0x12,0x0,0xE; adds	r16,0x8,r12; adds	r17,0x0,r12 }
	{ adds	r12,0xFFFFFFFFFFFFFFC0,r12; addl	r40,-10652,r1; adds	r44,0x0,r1; }
	{ mov.m	r45,UNAT; st8.spill	[r16],r112,-16; mov	r42,b2 }
	{ ld8	r40,[r40]; nop.m	0x0; addl	r46,1,r0; }
	{ st8.spill	[r17],r112,-16; st8.spill	[r16],r112,-16; nop.i	0x0; }
	{ st8.spill	[r17],r112,-16; st8.spill	[r16],r112,-16; nop.i	0x0; }
	{ nop.m	0x0; st8.spill	[r34],r17; nop.i	0x0 }
	{ st8.spill	[r33],r16; nop.m	0x0; br.call.sptk.many	b0,fn4000000000070840; }
	{ adds	r1,0x0,r44; ld8	r41,[r40]; addl	r48,5,r0 }
	{ adds	r46,0x0,r0; addl	r47,-8724,r1; nop.i	0x0; }
	{ ld8	r47,[r47]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r44; adds	r46,0x0,r41; nop.i	0x0 }
	{ addl	r47,1,r0; adds	r48,0x0,r8; br.call.sptk.many	b0,fn400000000001C040; }
	{ adds	r1,0x0,r44; ld8	r46,[r40]; adds	r48,0x0,r32 }
	{ adds	r49,0x18,r12; addl	r47,1,r0; br.call.sptk.many	b0,fn400000000001A560; }
	{ adds	r1,0x0,r44; nop.m	0x0; addl	r46,10,r0 }
	{ ld8	r47,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BD80; }
	{ nop.m	0x0; adds	r1,0x0,r44; mov.i	ar.pfs,r43 }
	{ mov.m	UNAT,r45; nop.i	0x0; mov.spnt	b0,r42,40000000000712A0 }
	{ nop.m	0x0; adds	r12,0x40,r12; br.ret	b0; }

;; sys_error: 40000000000712C0
;;   Called from:
;;     4000000000050B7C (in shell_execve)
;;     4000000000050DBC (in shell_execve)
;;     400000000007B34C (in start_pipeline)
;;     400000000007CB0C (in set_tty_state)
;;     400000000007F89C (in initialize_job_control)
;;     400000000007F99C (in initialize_job_control)
;;     400000000007FDEC (in initialize_job_control)
;;     40000000000828EC (in make_child)
;;     4000000000082D6C (in make_child)
;;     400000000008334C (in make_child)
;;     400000000009517C (in command_substitute)
;;     40000000000954CC (in command_substitute)
;;     40000000000A552C (in fn40000000000A1400)
;;     40000000000A55DC (in fn40000000000A1400)
;;     40000000000A561C (in fn40000000000A1400)
;;     40000000000B06AC (in getc_with_restart)
;;     40000000000B171C (in save_bash_input)
;;     400000000012BC8C (in netopen)
;;     400000000012BD3C (in netopen)
sys_error proc
	{ alloc	r43,ar.pfs,0x12,0x0,0xE; adds	r16,0x8,r12; adds	r17,0x0,r12 }
	{ adds	r12,0xFFFFFFFFFFFFFFC0,r12; addl	r40,-10652,r1; adds	r44,0x0,r1; }
	{ mov.m	r45,UNAT; st8.spill	[r16],r112,-16; mov	r42,b2 }
	{ ld8	r40,[r40]; st8.spill	[r17],r112,-16; nop.i	0x0 }
	{ st8.spill	[r16],r112,-16; st8.spill	[r17],r112,-16; nop.i	0x0 }
	{ st8.spill	[r16],r112,-16; st8.spill	[r34],r17; nop.i	0x0 }
	{ st8.spill	[r33],r16; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ adds	r1,0x0,r44; ld4	r41,[r8]; adds	r46,0x0,r0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn4000000000070840; }
	{ adds	r48,0x0,r32; adds	r49,0x18,r12; adds	r1,0x0,r44 }
	{ addl	r47,1,r0; ld8	r46,[r40]; br.call.sptk.many	b0,fn400000000001A560; }
	{ adds	r1,0x0,r44; nop.m	0x0; adds	r46,0x0,r41 }
	{ ld8	r40,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B4A0; }
	{ adds	r1,0x0,r44; nop.m	0x0; adds	r46,0x0,r40 }
	{ addl	r47,1,r0; adds	r49,0x0,r8; addl	r48,-8716,r1; }
	{ ld8	r48,[r48]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ nop.m	0x0; adds	r1,0x0,r44; mov.i	ar.pfs,r43 }
	{ mov.m	UNAT,r45; nop.i	0x0; mov.spnt	b0,r42,40000000000713D0 }
	{ nop.m	0x0; adds	r12,0x40,r12; br.ret	b0; }
40000000000713F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; parser_error: 4000000000071400
;;   Called from:
;;     400000000002486C (in fn4000000000024740)
;;     400000000002CCAC (in fn400000000002AC80)
;;     400000000002F46C (in fn400000000002D840)
;;     400000000003009C (in yyerror)
;;     40000000000302EC (in yyerror)
;;     400000000003047C (in yyerror)
;;     400000000003082C (in yyerror)
;;     4000000000035FDC (in fn4000000000030880)
;;     40000000000361AC (in fn4000000000030880)
;;     400000000003629C (in fn4000000000030880)
;;     4000000000036B1C (in fn4000000000036A40)
;;     4000000000036EAC (in fn4000000000036A40)
;;     4000000000036F7C (in fn4000000000036A40)
;;     400000000003720C (in fn4000000000036A40)
;;     400000000003729C (in fn4000000000036A40)
;;     40000000000374BC (in fn4000000000036A40)
;;     400000000003763C (in fn4000000000036A40)
;;     400000000003775C (in fn4000000000036A40)
;;     40000000000377EC (in fn4000000000036A40)
;;     400000000003789C (in fn4000000000036A40)
;;     400000000003792C (in fn4000000000036A40)
;;     400000000004346C (in make_arith_for_command)
;;     40000000000434CC (in make_arith_for_command)
parser_error proc
	{ alloc	r45,ar.pfs,0x17,0x0,0x10; adds	r16,0x8,r12; nop.i	0x0 }
	{ adds	r17,0x0,r12; adds	r12,0xFFFFFFFFFFFFFFD0,r12; adds	r46,0x0,r1; }
	{ mov.m	r47,UNAT; st8.spill	[r16],r112,-16; mov	r44,b4; }
	{ st8.spill	[r17],r112,-16; st8.spill	[r16],r112,-16; nop.i	0x0; }
	{ st8.spill	[r17],r112,-16; st8.spill	[r35],r16; nop.i	0x0; }
	{ st8.spill	[r34],r17; nop.i	0x0; br.call.sptk.many	b0,get_name_for_error; }
	{ adds	r1,0x0,r46; adds	r41,0x0,r8; br.call.sptk.many	b0,yy_input_name; }
	{ adds	r1,0x0,r46; adds	r42,0x0,r8; addl	r14,6516,r1; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; addl	r14,6512,r1; (p07) br.cond.dpnt.few	4000000000071790; }

l40000000000714A0:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000071600 }

l40000000000714C0:
	{ addl	r40,-10652,r1; addl	r14,7248,r1; addl	r53,-8788,r1 }
	{ addl	r50,-8708,r1; addl	r49,1,r0; adds	r51,0x0,r41; }
	{ ld8	r40,[r40]; adds	r52,0x0,r42; adds	r54,0x0,r32 }
	{ ld4	r14,[r14]; cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; }
	{ ld8	r43,[r40]; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000071890; }

l4000000000071510:
	{ adds	r48,0x0,r43; ld8	r53,[r53]; nop.i	0x0 }
	{ ld8	r50,[r50]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ adds	r1,0x0,r46; nop.m	0x0; nop.i	0x0 }

l4000000000071540:
	{ nop.m	0x0; adds	r50,0x0,r33; adds	r51,0x10,r12 }
	{ ld8	r48,[r40]; addl	r49,1,r0; br.call.sptk.many	b0,fn400000000001A560; }
	{ addl	r48,10,r0; nop.m	0x0; adds	r1,0x0,r46 }
	{ ld8	r49,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BD80; }
	{ adds	r1,0x0,r46; addl	r14,7404,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; (p07) addl	r14,9044,r1; (p07) addl	r15,2,r0 }

l40000000000715AC:
	{ Invalid; zxt4	r0,r0; break.i	0x1000; }

l40000000000715B0:
	{ (p07) addl	r48,2,r0; nop.m	0x0; nop.i	0x0; }

l40000000000715B6:
	{ break.m	0x4000; cmp4.eq	p00,p00,r0,r1; (p01) nop }

l40000000000715C6:
	{ chk.a.nc	f0,3FFFFFFFFF071DC6; Invalid; break.i	0x80000 }

l40000000000715D0:
	{ nop.m	0x0; mov.i	ar.pfs,r45; nop.i	0x0 }
	{ mov.m	UNAT,r47; nop.i	0x0; mov.spnt	b0,r44,40000000000715E0 }
	{ nop.m	0x0; adds	r12,0x30,r12; br.ret	b0 }

l4000000000071600:
	{ ld1	r15,[r41]; ld1	r14,[r8]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r15,r14; (p06) br.cond.dptk.few	40000000000714C0 }

l4000000000071630:
	{ adds	r48,0x0,r41; adds	r49,0x0,r8; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r46; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000000714C0; }

l4000000000071650:
	{ addl	r40,-10652,r1; addl	r14,7248,r1; addl	r52,-8788,r1 }
	{ addl	r50,-8772,r1; addl	r49,1,r0; adds	r51,0x0,r41; }
	{ nop.m	0x0; ld8	r40,[r40]; adds	r53,0x0,r32 }
	{ ld4	r14,[r14]; cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; }
	{ ld8	r42,[r40]; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000071900; }

l40000000000716A0:
	{ adds	r48,0x0,r42; ld8	r52,[r52]; nop.i	0x0 }
	{ ld8	r50,[r50]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ adds	r1,0x0,r46; nop.m	0x0; nop.i	0x0 }

l40000000000716D0:
	{ nop.m	0x0; adds	r50,0x0,r33; adds	r51,0x10,r12 }
	{ ld8	r48,[r40]; addl	r49,1,r0; br.call.sptk.many	b0,fn400000000001A560; }
	{ addl	r48,10,r0; nop.m	0x0; adds	r1,0x0,r46 }
	{ ld8	r49,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BD80; }
	{ adds	r1,0x0,r46; addl	r14,7404,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; (p07) addl	r14,9044,r1; (p07) addl	r15,2,r0 }

l400000000007173C:
	{ Invalid; zxt4	r0,r0; break.i	0x1000; }

l4000000000071740:
	{ (p07) addl	r48,2,r0; nop.m	0x0; nop.i	0x0; }

l4000000000071746:
	{ break.m	0x4000; cmp4.eq	p00,p00,r0,r1; (p01) nop }

l4000000000071756:
	{ chk.a.nc	f0,3FFFFFFFFF071F56; Invalid; break.i	0x80000 }

l4000000000071760:
	{ nop.m	0x0; mov.i	ar.pfs,r45; nop.i	0x0 }
	{ mov.m	UNAT,r47; nop.i	0x0; mov.spnt	b0,r44,4000000000071770 }
	{ nop.m	0x0; adds	r12,0x30,r12; br.ret	b0 }

l4000000000071790:
	{ addl	r40,-10652,r1; nop.m	0x0; addl	r50,-8764,r1 }
	{ adds	r51,0x0,r41; nop.m	0x0; addl	r49,1,r0; }
	{ ld8	r40,[r40]; ld8	r50,[r50]; nop.i	0x0; }
	{ ld8	r48,[r40]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ adds	r50,0x0,r33; adds	r51,0x10,r12; adds	r1,0x0,r46 }
	{ ld8	r48,[r40]; addl	r49,1,r0; br.call.sptk.many	b0,fn400000000001A560; }
	{ addl	r48,10,r0; nop.m	0x0; adds	r1,0x0,r46 }
	{ ld8	r49,[r40]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BD80; }
	{ adds	r1,0x0,r46; addl	r14,7404,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; (p07) addl	r14,9044,r1; (p07) addl	r15,2,r0 }

l400000000007183C:
	{ Invalid; zxt4	r0,r0; break.i	0x1000; }

l4000000000071840:
	{ (p07) addl	r48,2,r0; nop.m	0x0; nop.i	0x0; }

l4000000000071846:
	{ break.m	0x4000; cmp4.eq	p00,p00,r0,r1; (p01) nop }

l4000000000071856:
	{ chk.a.nc	f0,3FFFFFFFFF072056; Invalid; break.i	0x80000 }

l4000000000071860:
	{ nop.m	0x0; mov.i	ar.pfs,r45; nop.i	0x0 }
	{ mov.m	UNAT,r47; nop.i	0x0; mov.spnt	b0,r44,4000000000071870 }
	{ nop.m	0x0; adds	r12,0x30,r12; br.ret	b0 }

l4000000000071890:
	{ addl	r49,-8780,r1; adds	r48,0x0,r0; addl	r50,5,r0; }
	{ ld8	r49,[r49]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r46; adds	r53,0x0,r8; adds	r48,0x0,r43 }
	{ addl	r49,1,r0; adds	r51,0x0,r41; adds	r52,0x0,r42; }
	{ addl	r50,-8708,r1; nop.m	0x0; adds	r54,0x0,r32; }
	{ ld8	r50,[r50]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ nop.m	0x0; adds	r1,0x0,r46; br.cond.sptk.few	4000000000071540; }

l4000000000071900:
	{ addl	r49,-8780,r1; adds	r48,0x0,r0; addl	r50,5,r0; }
	{ ld8	r49,[r49]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r46; adds	r52,0x0,r8; adds	r48,0x0,r42 }
	{ addl	r49,1,r0; adds	r51,0x0,r41; adds	r53,0x0,r32; }
	{ nop.m	0x0; addl	r50,-8772,r1; nop.i	0x0; }
	{ ld8	r50,[r50]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ nop.m	0x0; adds	r1,0x0,r46; br.cond.sptk.few	40000000000716D0; }
4000000000071970 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; command_error: 4000000000071980
;;   Called from:
;;     4000000000021CEC (in fn4000000000021C00)
;;     4000000000023D5C (in reader_loop)
;;     400000000004504C (in clean_simple_command)
;;     40000000000496C6 (in fn4000000000049600)
;;     400000000004C05C (in dispose_command)
;;     40000000000F657C (in parse_and_execute)
;;     40000000000F78DC (in parse_string)
command_error proc
	{ alloc	r36,ar.pfs,0xA,0x0,0x6; cmp4.lt	p06,p07,0x3,r33; nop.b	0x0 }
	{ addl	r14,-8676,r1; mov	r35,b3; adds	r37,0x0,r1; }
	{ (p06) adds	r33,0x0,r0; ld8	r14,[r14]; adds	r38,0x0,r0 }

l40000000000719A6:
	{ (p07) fwb; (p19) nop; break.i	0x80000 }
	{ Invalid; Invalid; break.i	0x80000 }
	{ (p16) add	r0,r33,r22; (p16) nop; (p48) br.call.sptk.few	b1,b0 }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ add	r0,r0,r1; (p19) mov.sptk	b0,r32,4000000000071AE6; nop }
	{ Invalid; (p19) nop; (p32) br.call.sptk.few	b1,b0 }
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ break.m	0x0; nop; break.i	0x80000 }
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ break.m	0x4000; nop; Invalid }

;; command_errstr: 4000000000071A40
;;   Called from:
;;     4000000000071A3C (in command_error)
command_errstr proc
	{ alloc	r34,ar.pfs,0x7,0x0,0x4; cmp4.lt	p06,p07,0x3,r32; nop.b	0x0 }
	{ addl	r14,-8676,r1; mov	r33,b1; adds	r35,0x0,r1; }
	{ (p06) adds	r32,0x0,r0; ld8	r14,[r14]; adds	r36,0x0,r0 }

l4000000000071A66:
	{ (p07) fwb; (p18) nop; break.i	0x80000 }
	{ Invalid; Invalid; break.i	0x80000 }
	{ (p16) break.m	0x59000; (p16) nop; (p16) nop }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ Invalid; (p34) nop; Invalid }

;; err_badarraysub: 4000000000071AC0
;;   Called from:
;;     40000000000C083C (in assign_compound_array_list)
;;     40000000000C0F0C (in array_variable_name)
;;     40000000000C124C (in assign_array_element)
;;     40000000000C1ACC (in fn40000000000C14C0)
;;     40000000000C1C9C (in fn40000000000C14C0)
;;     40000000000C1CFC (in fn40000000000C14C0)
err_badarraysub proc
	{ alloc	r36,ar.pfs,0x9,0x0,0x6; addl	r14,6100,r1; mov	r35,b3 }
	{ adds	r33,0x0,r32; addl	r32,-8732,r1; adds	r37,0x0,r1; }
	{ nop.m	0x0; nop.m	0x0; adds	r38,0x0,r0 }
	{ addl	r40,5,r0; ld8	r32,[r32]; nop.i	0x0; }
	{ ld8	r39,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r37; adds	r34,0x0,r8; mov.spnt	b0,r35,4000000000071B10; }
	{ nop.m	0x0; mov.i	ar.pfs,r36; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x3,0x0,0x0; nop.i	0x0; br.cond.sptk.many	report_error; }
4000000000071B40 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
4000000000071B50 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000071B60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000071B70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; err_unboundvar: 4000000000071B80
;;   Called from:
;;     4000000000074E9C (in fn4000000000074880)
;;     400000000007583C (in fn4000000000074880)
;;     400000000009E2EC (in fn400000000009A180)
err_unboundvar proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; mov	r34,b2; nop.b	0x0 }
	{ addl	r38,-8692,r1; adds	r36,0x0,r1; adds	r33,0x0,r32; }
	{ adds	r37,0x0,r0; nop.m	0x0; addl	r39,5,r0 }
	{ ld8	r38,[r38]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; adds	r32,0x0,r8; mov.spnt	b0,r34,4000000000071BC0; }
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	report_error; }
4000000000071BF0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; err_readonly: 4000000000071C00
;;   Called from:
;;     40000000000670AC (in fn4000000000066D40)
;;     400000000006E74C (in assign_in_env)
;;     40000000000BED1C (in bind_array_variable)
;;     40000000000BEECC (in bind_assoc_variable)
;;     40000000000BF08C (in find_or_make_array_variable)
;;     400000000010187C (in mapfile_builtin)
err_readonly proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; mov	r34,b2; nop.b	0x0 }
	{ addl	r38,-8684,r1; adds	r36,0x0,r1; adds	r33,0x0,r32; }
	{ adds	r37,0x0,r0; nop.m	0x0; addl	r39,5,r0 }
	{ ld8	r38,[r38]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; adds	r32,0x0,r8; mov.spnt	b0,r34,4000000000071C40; }
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	report_error; }
4000000000071C70 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; fn4000000000071C80: 4000000000071C80
;;   Called from:
;;     4000000000074EEC (in fn4000000000074880)
;;     40000000000761EC (in evalexp)
fn4000000000071C80 proc
	{ alloc	r36,ar.pfs,0x7,0x0,0x6; addl	r33,7284,r1; nop.b	0x0 }
	{ addl	r15,7276,r1; mov	r35,b3; adds	r37,0x0,r1; }
	{ ld4	r14,[r33]; ld8	r34,[r15]; nop.i	0x0; }
	{ nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; }
	{ st4	[r14],r33; cmp4.lt	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	4000000000071DB0; }

l4000000000071CD0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000071CE0:
	{ nop.m	0x0; sxt4	r14,r14; shladd	r32,r14,0x3,r34; }
	{ ld8	r14,[r32]; adds	r15,0x28,r14; nop.i	0x0; }
	{ nop.m	0x0; ld8	r15,[r15]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r15; adds	r38,0x0,r15; (p06) br.cond.dpnt.few	4000000000071D40; }

l4000000000071D20:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r37; ld8	r14,[r32]; nop.i	0x0; }

l4000000000071D40:
	{ adds	r15,0x8,r14; ld8	r15,[r15]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r15; adds	r38,0x0,r15; (p06) br.cond.dpnt.few	4000000000071D80; }

l4000000000071D60:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r37; ld8	r14,[r32]; nop.i	0x0; }

l4000000000071D80:
	{ adds	r38,0x0,r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ ld4	r14,[r33]; adds	r1,0x0,r37; adds	r14,0xFFFFFFFFFFFFFFFF,r14; }
	{ st4	[r14],r33; cmp4.lt	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000071CE0 }

l4000000000071DB0:
	{ nop.m	0x0; sxt4	r14,r14; shladd	r34,r14,0x3,r34; }
	{ ld8	r38,[r34]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r37; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ addl	r14,7252,r1; nop.m	0x0; mov.spnt	b0,r35,4000000000071DE0; }
	{ st4	[r0],r14; nop.i	0x0; br.ret	b0; }

;; fn4000000000071E00: 4000000000071E00
;;   Called from:
;;     400000000007278C (in fn4000000000072100)
;;     4000000000072B2C (in fn40000000000729C0)
;;     4000000000072DDC (in fn4000000000072B40)
;;     4000000000073AEC (in fn4000000000073740)
;;     4000000000073D3C (in fn4000000000073B40)
;;     4000000000073FAC (in fn4000000000073B40)
;;     400000000007486C (in fn40000000000741C0)
;;     4000000000075B2C (in fn4000000000074880)
;;     4000000000075EFC (in fn4000000000074880)
;;     4000000000075F9C (in fn4000000000074880)
;;     4000000000075FEC (in fn4000000000074880)
;;     400000000007601C (in fn4000000000074880)
;;     400000000007604C (in fn4000000000074880)
fn4000000000071E00 proc
	{ alloc	r36,ar.pfs,0xC,0x0,0x6; addl	r14,7268,r1; mov	r35,b3 }
	{ adds	r37,0x0,r1; ld8	r33,[r14]; addl	r14,9036,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld8	r34,[r14]; ld1	r14,[r33]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x9,r14; }
	{ cmp4.eq.or.andcm	p07,p06,0x20,r14; adds	r14,0x1,r33; (p06) br.cond.dpnt.few	4000000000071E90; }

l4000000000071E60:
	{ adds	r33,0x0,r14; ld1	r15,[r14],1; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; cmp4.eq	p06,p07,0x20,r15; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x9,r15; (p06) br.cond.dptk.few	4000000000071E60 }

l4000000000071E90:
	{ addl	r39,780,r1; addl	r40,5,r0; adds	r38,0x0,r0; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r37; cmp.eq	p06,p07,0x0,r34; adds	r38,0x0,r8; }
	{ addl	r14,7316,r1; (p06) addl	r34,772,r1; (p07) addl	r40,764,r1; }

l4000000000071ECC:
	{ (p62) ldfp8	f1,f5,[r72]; (p04) nop; }

l4000000000071ED0:
	{ ld8	r43,[r14]; (p06) ld8	r34,[r34]; nop.i	0x0; }

l4000000000071EDC:
	{ nop; mov	pr,r32,0x0; Invalid }

l4000000000071EEC:
	{ Invalid; (p05) cmp.eq.unc	p00,p16,r8,r64; mov	pr,r74,0xE4C0 }

l4000000000071EF6:
	{ (p03) chk.a.clr	f0,3FFFFFFFFFCF51A6; nop; (p32) br.call.sptk.few	b3,b0 }

l4000000000071F00:
	{ ld1	r14,[r43]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000071F60 }

l4000000000071F20:
	{ adds	r39,0x0,r34; nop.m	0x0; adds	r41,0x0,r33 }
	{ adds	r42,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,internal_error; }
	{ adds	r1,0x0,r37; addl	r39,1,r0; addl	r38,14196,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BBE0 }

l4000000000071F60:
	{ addl	r43,772,r1; nop.m	0x0; adds	r39,0x0,r34 }
	{ adds	r41,0x0,r33; nop.m	0x0; adds	r42,0x0,r32; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,internal_error; }
	{ adds	r1,0x0,r37; addl	r39,1,r0; addl	r38,14196,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BBE0; }
	{ nop.m	0x0; break.f	0x0; nop.i	0x0; }

;; fn4000000000071FC0: 4000000000071FC0
;;   Called from:
;;     4000000000072676 (in fn4000000000072100)
;;     4000000000072836 (in fn4000000000072100)
;;     4000000000073E0C (in fn4000000000073B40)
fn4000000000071FC0 proc
	{ alloc	r39,ar.pfs,0xF,0x0,0x9; adds	r12,0xFFFFFFFFFFFFFFE0,r12; mov	r38,b6 }
	{ adds	r40,0x0,r1; nop.m	0x0; adds	r41,0x0,r33; }
	{ addl	r44,22,r0; adds	r45,0x0,r0; nop.i	0x0 }
	{ adds	r43,0x10,r12; addl	r42,10,r0; br.call.sptk.many	b0,fmtumax; }
	{ adds	r42,0x0,r0; adds	r43,0x0,r0; adds	r1,0x0,r40 }
	{ adds	r37,0x0,r8; adds	r41,0x0,r32; br.call.sptk.many	b0,array_variable_name; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r36,0x0,r8 }
	{ adds	r41,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r40; adds	r41,0x19,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r40; addl	r43,-1,r0; adds	r45,0x0,r36 }
	{ adds	r46,0x0,r37; adds	r35,0x0,r8; adds	r41,0x0,r8; }
	{ addl	r44,788,r1; nop.m	0x0; addl	r42,1,r0; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C440; }
	{ adds	r42,0x0,r34; nop.m	0x0; adds	r1,0x0,r40 }
	{ adds	r41,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,bind_int_variable; }
	{ adds	r1,0x0,r40; adds	r41,0x0,r35; br.call.sptk.many	b0,stupidly_hack_special_variables; }
	{ adds	r1,0x0,r40; adds	r41,0x0,r36; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r40; adds	r41,0x0,r35; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r40; mov.i	ar.pfs,r39; mov.spnt	b0,r38,40000000000720E0 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0; }

;; fn4000000000072100: 4000000000072100
;;   Called from:
;;     40000000000721BC (in fn4000000000072100)
;;     400000000007225C (in fn4000000000072100)
;;     40000000000729EC (in fn40000000000729C0)
fn4000000000072100 proc
	{ alloc	r57,ar.pfs,0x1E,0x0,0x1B; mov	r56,b0; adds	r58,0x0,r1 }
	{ addl	r33,7304,r1; nop.m	0x0; addl	r35,1,r0 }

l4000000000072120:
	{ ld4	r32,[r33]; nop.m	0x0; addl	r34,7304,r1; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x21,r32; (p07) br.cond.dpnt.few	40000000000721A0; }

l4000000000072140:
	{ cmp4.eq	p07,p06,0x7E,r32; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000072240; }

l4000000000072150:
	{ cmp4.eq	p07,p06,0x2D,r32; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000072220; }

l4000000000072160:
	{ cmp4.eq	p07,p06,0x2B,r32; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000722B0; }

l4000000000072170:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ adds	r1,0x0,r58; ld4	r32,[r33]; nop.i	0x0; }
	{ addl	r34,7304,r1; cmp4.eq	p07,p06,0x21,r32; (p06) br.cond.dptk.few	4000000000072140 }

l40000000000721A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ adds	r1,0x0,r58; nop.i	0x0; br.call.sptk.many	b0,fn4000000000072100; }
	{ cmp.eq	p06,p07,0x0,r8; setf.sig	f7,r35; nop.b	0x0 }
	{ adds	r1,0x0,r58; nop.m	0x0; mov.i	ar.pfs,r57; }
	{ (p06) addl	r36,1,r0; mov.spnt	b0,r56,40000000000721E0; (p07) adds	r36,0x0,r0; }

l40000000000721E6:
	{ chk.a.nc	f56,3FFFFFFFFF1521F6; (p18) nop; break.i	0x80000 }

l40000000000721F0:
	{ nop.m	0x0; setf.sig	f6,r36; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; xma.l	f6,f6,f7,f0; }
	{ getf.sig	r8,f6; nop.i	0x0; br.ret	b0; }

l4000000000072220:
	{ sub	r35,r0,r35; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ nop.m	0x0; adds	r1,0x0,r58; br.cond.sptk.few	4000000000072120 }

l4000000000072240:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ adds	r1,0x0,r58; nop.i	0x0; br.call.sptk.many	b0,fn4000000000072100; }
	{ andcm	r36,0xFFFFFFFFFFFFFFFF,r8; setf.sig	f7,r35; nop.b	0x0 }
	{ adds	r1,0x0,r58; nop.m	0x0; mov.i	ar.pfs,r57; }
	{ setf.sig	f6,r36; nop.m	0x0; mov.spnt	b0,r56,4000000000072280; }
	{ nop.m	0x0; nop.m	0x0; xma.l	f6,f6,f7,f0; }
	{ getf.sig	r8,f6; nop.i	0x0; br.ret	b0 }

l40000000000722B0:
	{ adds	r14,0xFFFFFFFFFFFFFFF2,r32; nop.m	0x0; addl	r37,7308,r1; }
	{ cmp4.ltu	p06,p07,0x1,r14; adds	r14,0xFFFFFFFFFFFFFFFB,r32; (p07) br.cond.dpnt.few	4000000000072580; }

l40000000000722D0:
	{ cmp4.eq	p07,p06,0x28,r32; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000072710; }

l40000000000722E0:
	{ cmp4.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.spnt.few	4000000000072980; }

l40000000000722F0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5,r32; nop.i	0x0 }
	{ ld8	r36,[r37]; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000072370 }

l4000000000072310:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ adds	r1,0x0,r58; nop.m	0x0; nop.i	0x0 }

l4000000000072330:
	{ setf.sig	f6,r36; setf.sig	f7,r35; mov.i	ar.pfs,r57; }
	{ nop.m	0x0; mov.spnt	b0,r56,4000000000072340; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; xma.l	f6,f6,f7,f0; }
	{ getf.sig	r8,f6; nop.i	0x0; br.ret	b0 }

l4000000000072370:
	{ addl	r38,-20772,r1; addl	r39,7260,r1; addl	r40,7252,r1 }
	{ addl	r42,7300,r1; addl	r44,7292,r1; addl	r43,7316,r1; }
	{ nop.m	0x0; nop.m	0x0; addl	r14,1,r0 }
	{ ld8	r51,[r39]; st8	[r0],r39; nop.i	0x0; }
	{ adds	r41,0x0,r38; adds	r46,0x10,r38; adds	r45,0x18,r38 }
	{ ld4	r50,[r40]; st4	[r14],r40; nop.i	0x0; }
	{ ld8	r52,[r41],8; ld8	r48,[r46]; nop.i	0x0; }
	{ ld8	r49,[r41]; ld8	r47,[r45]; nop.i	0x0; }
	{ ld4	r55,[r42]; ld8	r54,[r44]; nop.i	0x0; }
	{ ld8	r53,[r43]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ ld4	r14,[r34]; adds	r1,0x0,r58; adds	r15,0xFFFFFFFFFFFFFFF0,r14; }
	{ cmp4.ltu	p06,p07,0x1,r15; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000072790; }

l4000000000072430:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5,r14; (p07) br.cond.dpnt.few	40000000000724D0 }

l4000000000072440:
	{ adds	r14,0x0,r38; adds	r15,0x10,r38; addl	r16,5,r0 }
	{ st4	[r55],r42; st8	[r54],r44; adds	r38,0x18,r38; }
	{ st8	[r14],r8,8; st4	[r16],r33; nop.i	0x0; }
	{ st8	[r53],r43; st8	[r36],r37; nop.i	0x0; }
	{ nop.m	0x0; st8	[r51],r39; nop.i	0x0 }
	{ st4	[r50],r40; st8	[r49],r14; nop.i	0x0 }
	{ st8	[r48],r15; st8	[r47],r38; nop.i	0x0 }

l40000000000724B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ nop.m	0x0; adds	r1,0x0,r58; br.cond.sptk.few	4000000000072330 }

l40000000000724D0:
	{ nop.m	0x0; ld8	r59,[r39]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r59; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000072440; }

l40000000000724F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r14,0x0,r38; adds	r15,0x10,r38; addl	r16,5,r0 }
	{ adds	r38,0x18,r38; st4	[r55],r42; adds	r1,0x0,r58; }
	{ st8	[r14],r8,8; st8	[r54],r44; nop.i	0x0; }
	{ st4	[r16],r33; st8	[r53],r43; nop.i	0x0; }
	{ st8	[r36],r37; st8	[r51],r39; nop.i	0x0; }
	{ st4	[r50],r40; st8	[r49],r14; nop.i	0x0; }
	{ nop.m	0x0; st8	[r48],r15; nop.i	0x0 }
	{ st8	[r47],r38; nop.m	0x0; br.cond.sptk.few	40000000000724B0 }

l4000000000072580:
	{ nop.m	0x0; addl	r14,7300,r1; nop.i	0x0; }
	{ st4	[r32],r14; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ ld4	r14,[r34]; nop.m	0x0; adds	r1,0x0,r58; }
	{ cmp4.eq	p06,p07,0x5,r14; addl	r14,7308,r1; (p07) addl	r60,796,r1; }

l40000000000725C0:
	{ (p07) ld8	r60,[r60]; nop.i	0x0; (p07) br.cond.spnt.few	4000000000072770; }

l40000000000725C6:
	{ chk.a.nc	f0,3FFFFFFFFF072DC6; nop; (p48) nop }

l40000000000725D0:
	{ cmp4.eq	p07,p06,0xE,r32; ld8	r14,[r14]; nop.i	0x0; }
	{ (p06) addl	r32,-1,r0; (p07) addl	r32,1,r0; nop.i	0x0; }

l40000000000725E6:
	{ Invalid; nop; break.i	0x80000; }

l40000000000725EC:
	{ nop; add	r0,r32,r0; zxt1	r72,r0 }
	{ ldfps	f0,f1,[r0]; zxt1	r0,r64; break.i	0x1000 }
	{ (p38) nop; invala; (p04) nop }
	{ Invalid; Invalid; Invalid }
	{ cmp.eq	p00,p17,r1,r0; cmp.lt.unc	p00,p28,r67,r97; (p01) mov	pr,r63,0x9D6E }
	{ Invalid; cmp.eq	p00,p00,r32,r0; zxt1	r70,r64 }

l4000000000072640:
	{ nop.m	0x0; adds	r15,0x18,r14; nop.i	0x0; }
	{ nop.m	0x0; ld8	r60,[r15]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r60; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000728A0; }

l4000000000072670:
	{ ld8	r59,[r14]; br.call.sptk.many	b0,fn4000000000071FC0; nop.b	0x0; }
	{ adds	r1,0x0,r58; nop.m	0x0; nop.i	0x0 }

l4000000000072690:
	{ adds	r59,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ addl	r14,6,r0; adds	r1,0x0,r58; nop.i	0x0 }
	{ st4	[r14],r33; nop.m	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ adds	r1,0x0,r58; nop.m	0x0; nop.i	0x0 }

l40000000000726D0:
	{ setf.sig	f6,r36; setf.sig	f7,r35; mov.i	ar.pfs,r57; }
	{ nop.m	0x0; mov.spnt	b0,r56,40000000000726E0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; xma.l	f6,f6,f7,f0; }
	{ getf.sig	r8,f6; nop.i	0x0; br.ret	b0; }

l4000000000072710:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ adds	r1,0x0,r58; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074100; }
	{ ld4	r14,[r34]; adds	r1,0x0,r58; adds	r36,0x0,r8; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x29,r14; (p06) br.cond.sptk.few	4000000000072310 }

l4000000000072750:
	{ nop.m	0x0; addl	r60,804,r1; nop.i	0x0; }
	{ ld8	r60,[r60]; nop.m	0x0; nop.i	0x0 }

l4000000000072770:
	{ addl	r61,5,r0; adds	r59,0x0,r0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r58; adds	r59,0x0,r8; br.call.sptk.many	b0,fn4000000000071E00 }

l4000000000072790:
	{ cmp4.eq	p07,p06,0x10,r14; st4	[r32],r42; nop.i	0x0 }
	{ st8	[r51],r39; (p06) addl	r59,-1,r0; nop.i	0x0 }

l40000000000727AC:
	{ nop; Invalid; Invalid }
	{ nop; zxt4	r0,r0; Invalid }

l40000000000727C6:
	{ mf.a; nop; nop }
	{ add	r0,r0,r1; (p29) nop; break.i	0x80000 }
	{ mf.a; (p32) nop; (p32) nop }
	{ Invalid; (p16) nop; break.b	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD358E6; nop; br.call.sptk.few	b7,b0 }

l4000000000072810:
	{ ld8	r60,[r45]; adds	r14,0xFFFFFFFFFFFFFFE8,r45; adds	r61,0x0,r8; }
	{ cmp.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r60; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000072920; }

l4000000000072830:
	{ ld8	r59,[r14]; br.call.sptk.many	b0,fn4000000000071FC0; nop.b	0x0; }
	{ adds	r1,0x0,r58; nop.m	0x0; nop.i	0x0 }

l4000000000072850:
	{ adds	r59,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ addl	r14,6,r0; nop.m	0x0; adds	r1,0x0,r58; }
	{ st4	[r14],r33; nop.m	0x0; nop.i	0x0 }

l4000000000072880:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ nop.m	0x0; adds	r1,0x0,r58; br.cond.sptk.few	4000000000072330; }

l40000000000728A0:
	{ addl	r14,7260,r1; nop.m	0x0; adds	r60,0x0,r8; }
	{ nop.m	0x0; ld8	r34,[r14]; nop.i	0x0; }
	{ adds	r59,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,bind_int_variable; }
	{ adds	r1,0x0,r58; adds	r59,0x0,r34; br.call.sptk.many	b0,stupidly_hack_special_variables; }
	{ adds	r1,0x0,r58; adds	r59,0x0,r32; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ addl	r14,6,r0; nop.m	0x0; adds	r1,0x0,r58; }
	{ st4	[r14],r33; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ nop.m	0x0; adds	r1,0x0,r58; br.cond.sptk.few	40000000000726D0 }

l4000000000072920:
	{ ld8	r34,[r39]; nop.m	0x0; adds	r60,0x0,r8; }
	{ adds	r59,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,bind_int_variable; }
	{ adds	r1,0x0,r58; adds	r59,0x0,r34; br.call.sptk.many	b0,stupidly_hack_special_variables; }
	{ adds	r1,0x0,r58; adds	r59,0x0,r32; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ addl	r14,6,r0; nop.m	0x0; adds	r1,0x0,r58; }
	{ st4	[r14],r33; nop.i	0x0; br.cond.sptk.few	4000000000072880 }

l4000000000072980:
	{ nop.m	0x0; addl	r60,812,r1; nop.i	0x0; }
	{ ld8	r60,[r60]; nop.i	0x0; br.cond.sptk.few	4000000000072770; }
40000000000729A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000729B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000729C0: 40000000000729C0
;;   Called from:
;;     4000000000072A2C (in fn40000000000729C0)
;;     4000000000072B6C (in fn4000000000072B40)
;;     4000000000072BFC (in fn4000000000072B40)
;;     4000000000072CFC (in fn4000000000072B40)
fn40000000000729C0 proc
	{ alloc	r35,ar.pfs,0x9,0x0,0x6; addl	r32,7304,r1; mov	r34,b2 }
	{ nop.m	0x0; adds	r36,0x0,r1; nop.i	0x0; }
	{ nop.m	0x0; mov	r37,LC; br.call.sptk.many	b0,fn4000000000072100; }
	{ ld4	r14,[r32]; adds	r1,0x0,r36; adds	r33,0x0,r8; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0xD,r14; (p07) br.cond.dpnt.few	4000000000072AB0 }

l4000000000072A10:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ adds	r1,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,fn40000000000729C0; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r14,0xFFFFFFFFFFFFFFFF,r8; nop.i	0x0 }
	{ addl	r15,1,r0; adds	r1,0x0,r36; (p06) br.cond.dpnt.few	4000000000072AD0; }

l4000000000072A50:
	{ cmp.lt	p06,p07,r8,r0; mov.i	LC,r14; (p06) br.cond.spnt.few	4000000000072B00 }

l4000000000072A60:
	{ setf.sig	f6,r15; setf.sig	f7,r33; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; xma.l	f6,f6,f7,f0; }
	{ getf.sig	r15,f6; nop.i	0x0; br.cloop.sptk.few	4000000000072A60; }

l4000000000072A90:
	{ ld4	r14,[r32]; getf.sig	r33,f6; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0xD,r14; (p06) br.cond.dptk.few	4000000000072A10 }

l4000000000072AB0:
	{ adds	r8,0x0,r33; mov.i	ar.pfs,r35; mov.i	LC,r37; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000072AC0; br.ret	b0 }

l4000000000072AD0:
	{ addl	r33,1,r0; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ adds	r8,0x0,r33; nop.m	0x0; mov.i	LC,r37; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000072AF0; br.ret	b0 }

l4000000000072B00:
	{ addl	r39,820,r1; addl	r40,5,r0; adds	r38,0x0,r0; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; adds	r38,0x0,r8; br.call.sptk.many	b0,fn4000000000071E00; }
	{ nop.m	0x0; break.f	0x0; nop.i	0x0; }

;; fn4000000000072B40: 4000000000072B40
;;   Called from:
;;     4000000000072B3C (in fn40000000000729C0)
;;     4000000000072E2C (in fn4000000000072E00)
;;     4000000000072EAC (in fn4000000000072E00)
fn4000000000072B40 proc
	{ alloc	r40,ar.pfs,0xD,0x0,0xA; adds	r41,0x0,r1; nop.b	0x0 }
	{ addl	r37,7304,r1; nop.m	0x0; mov	r39,b7; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000729C0; }
	{ adds	r1,0x0,r41; adds	r36,0x0,r8; addl	r38,7252,r1; }

l4000000000072B80:
	{ ld4	r32,[r37]; cmp4.eq	p06,p07,0x2F,r32; cmp4.eq	p08,p09,0x2A,r32; }
	{ (p06) addl	r33,1,r0; nop.m	0x0; (p08) addl	r14,1,r0; }

l4000000000072B96:
	{ Invalid; (p07) cmp.eq.and	p01,p08,0x0,r0; (p17) nop }

l4000000000072BA0:
	{ (p07) adds	r33,0x0,r0; (p09) adds	r14,0x0,r0; zxt1	r34,r33 }

l4000000000072BA6:
	{ Invalid; (p17) nop; (p48) nop }

l4000000000072BAC:
	{ ldfp8	f33,f16,[r0]; (p33) nop }
	{ Invalid; cmp.eq	p00,p00,r32,r0; mov	pr,r67,0xE680 }
	{ (p09) cmp.lt	p00,p17,r64,r33; czx1.r	r9,r97; (p20) mov	pr,r0,0x9000 }

l4000000000072BD0:
	{ cmp4.eq	p06,p07,0x25,r32; addl	r32,1,r0; (p07) br.cond.dpnt.few	4000000000072D90; }

l4000000000072BE0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ nop.m	0x0; adds	r1,0x0,r41; br.call.sptk.many	b0,fn40000000000729C0; }
	{ adds	r1,0x0,r41; nop.m	0x0; nop.i	0x0 }

l4000000000072C10:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	4000000000072C40 }

l4000000000072C20:
	{ ld4	r14,[r38]; nop.m	0x0; addl	r8,1,r0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.spnt.few	4000000000072DB0; }

l4000000000072C40:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r35; (p07) br.cond.dpnt.few	4000000000072D40; }

l4000000000072C50:
	{ cmp4.eq	p06,p07,0x0,r33; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000072D70; }

l4000000000072C60:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r32; (p06) br.cond.dptk.few	4000000000072B80 }

l4000000000072C70:
	{ adds	r42,0x0,r36; adds	r43,0x0,r8; br.call.sptk.many	b0,fn4000000000137A00; }
	{ ld4	r32,[r37]; adds	r1,0x0,r41; adds	r36,0x0,r8; }
	{ cmp4.eq	p06,p07,0x2F,r32; cmp4.eq	p08,p09,0x2A,r32; (p07) adds	r33,0x0,r0 }

l4000000000072CA0:
	{ (p08) addl	r14,1,r0; (p06) addl	r33,1,r0; (p09) adds	r14,0x0,r0; }

l4000000000072CA6:
	{ (p16) chk.s	f0,4000000000272CB6; (p07) mov	pr,r0,0x1000; break.b	0x80000; }

l4000000000072CAC:
	{ nop.m	0x8000; dep	r0,r32,r0,63,1; (p04) nop; }

l4000000000072CB0:
	{ nop.m	0x0; zxt1	r34,r33; adds	r35,0x0,r14; }
	{ nop.m	0x0; or	r14,r34,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	4000000000072BD0; }

l4000000000072CE0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ adds	r1,0x0,r41; nop.i	0x0; br.call.sptk.many	b0,fn40000000000729C0; }
	{ cmp4.eq	p06,p07,0x25,r32; adds	r1,0x0,r41; (p06) addl	r32,1,r0; }

l4000000000072D10:
	{ (p07) adds	r32,0x0,r0; or	r34,r34,r32; nop.i	0x0; }

l4000000000072D16:
	{ Invalid; nop; (p32) nop }
	{ chk.a.nc	f0,3FFFFFFFFF073526; nop; (p01) nop }

l4000000000072D30:
	{ (p06) adds	r32,0x0,r0; cmp4.eq	p06,p07,0x0,r35; (p06) br.cond.dptk.few	4000000000072C50 }

l4000000000072D36:
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD36766; nop; (p32) nop }

l4000000000072D40:
	{ setf.sig	f6,r36; setf.sig	f7,r8; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; xma.l	f6,f6,f7,f0; }
	{ getf.sig	r36,f6; nop.i	0x0; br.cond.sptk.few	4000000000072B80; }

l4000000000072D70:
	{ adds	r42,0x0,r36; adds	r43,0x0,r8; br.call.sptk.many	b0,fn4000000000137910; }
	{ adds	r1,0x0,r41; adds	r36,0x0,r8; br.cond.sptk.few	4000000000072B80; }

l4000000000072D90:
	{ adds	r8,0x0,r36; nop.m	0x0; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.spnt	b0,r39,4000000000072DA0; br.ret	b0 }

l4000000000072DB0:
	{ addl	r43,828,r1; addl	r44,5,r0; adds	r42,0x0,r0; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r41; adds	r42,0x0,r8; br.call.sptk.many	b0,fn4000000000071E00; }
	{ nop.m	0x0; break.f	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

;; fn4000000000072E00: 4000000000072E00
;;   Called from:
;;     4000000000072DFC (in fn4000000000072B40)
;;     4000000000072F6C (in fn4000000000072F40)
;;     4000000000072FBC (in fn4000000000072F40)
fn4000000000072E00 proc
	{ alloc	r37,ar.pfs,0x7,0x0,0x7; adds	r38,0x0,r1; nop.b	0x0 }
	{ addl	r33,7304,r1; nop.m	0x0; mov	r36,b4; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000072B40; }
	{ nop.m	0x0; adds	r1,0x0,r38; adds	r34,0x0,r8 }

l4000000000072E40:
	{ ld4	r15,[r33]; cmp4.eq	p06,p07,0x2B,r15; cmp4.eq	p08,p09,0x2D,r15; }
	{ (p06) addl	r14,1,r0; nop.m	0x0; (p08) addl	r15,1,r0; }

l4000000000072E56:
	{ addl	r0,0,r1; (p07) cmp4.eq.or	p01,p08,r0,r0; (p33) nop }

l4000000000072E60:
	{ (p07) adds	r14,0x0,r0; nop.m	0x0; (p09) adds	r15,0x0,r0; }

l4000000000072E66:
	{ addl	r0,16384,r1; (p07) nop; nop }

l4000000000072E70:
	{ or	r16,r15,r14; adds	r32,0x0,r15; adds	r35,0x0,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r16; (p07) br.cond.dpnt.few	4000000000072F20 }

l4000000000072E90:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ adds	r1,0x0,r38; nop.i	0x0; br.call.sptk.many	b0,fn4000000000072B40; }
	{ cmp4.eq	p06,p07,0x0,r35; nop.m	0x0; adds	r1,0x0,r38; }
	{ (p07) add	r34,r34,r8; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000072E40; }

l4000000000072EC6:
	{ chk.a.nc	f0,3FFFFFFFFF0736C6; Invalid; (p48) nop }

l4000000000072ED0:
	{ ld4	r15,[r33]; cmp4.eq	p06,p07,0x0,r32; cmp4.eq	p08,p09,0x2D,r15 }
	{ (p07) sub	r34,r34,r8; cmp4.eq	p06,p07,0x2B,r15; (p06) addl	r14,1,r0 }

l4000000000072EE6:
	{ (p03) chk.a.clr	r43,3FFFFFFFFFD367D6; (p07) nop; (p50) cmp.eq	p35,p00,0x0,r0 }

l4000000000072EF0:
	{ (p08) addl	r15,1,r0; (p07) adds	r14,0x0,r0; (p09) adds	r15,0x0,r0; }

l4000000000072EF6:
	{ (p07) addl	r0,24832,r0; (p07) nop; nop; }

l4000000000072EFC:
	{ nop; zxt1	r67,r3; (p04) nop; }

l4000000000072F00:
	{ or	r16,r15,r14; adds	r32,0x0,r15; adds	r35,0x0,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r16; (p06) br.cond.dptk.few	4000000000072E90 }

l4000000000072F20:
	{ adds	r8,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,4000000000072F30; br.ret	b0; }

;; fn4000000000072F40: 4000000000072F40
;;   Called from:
;;     400000000007306C (in fn4000000000073040)
;;     40000000000730DC (in fn4000000000073040)
;;     400000000007315C (in fn4000000000073040)
fn4000000000072F40 proc
	{ alloc	r36,ar.pfs,0x6,0x0,0x6; addl	r34,7304,r1; mov	r35,b3 }
	{ nop.m	0x0; adds	r37,0x0,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000072E00; }
	{ ld4	r32,[r34]; adds	r1,0x0,r37; adds	r33,0x0,r8; }
	{ nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFFF7,r32; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p07,p06,0x1,r14; (p07) br.cond.dpnt.few	4000000000073010; }

l4000000000072FA0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ adds	r1,0x0,r37; nop.i	0x0; br.call.sptk.many	b0,fn4000000000072E00; }
	{ cmp4.eq	p07,p06,0x9,r32; nop.m	0x0; sxt4	r14,r8 }
	{ ld4	r32,[r34]; nop.m	0x0; adds	r1,0x0,r37; }
	{ (p07) adds	r8,0x0,r14; (p06) shr	r33,r33,r14; adds	r14,0xFFFFFFFFFFFFFFF7,r32; }

l4000000000072FE6:
	{ (p16) flushrs; (p07) chk.s.i	r32,4000000000212F56; Invalid; }

l4000000000072FEC:
	{ (p59) break.m	0x19FA0; nop; (p20) nop; }

l4000000000072FFC:
	{ cmp.eq	p00,p25,r1,r0; Invalid; mov	pr,r32,0x0 }
	{ (p61) nop; zxt1	r32,r64; break.i	0x1000 }

l4000000000073010:
	{ adds	r8,0x0,r33; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,4000000000073020; br.ret	b0; }
4000000000073030 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000073040: 4000000000073040
;;   Called from:
;;     400000000007326C (in fn4000000000073240)
;;     40000000000732BC (in fn4000000000073240)
fn4000000000073040 proc
	{ alloc	r37,ar.pfs,0x7,0x0,0x7; adds	r38,0x0,r1; nop.b	0x0 }
	{ addl	r35,7304,r1; nop.m	0x0; mov	r36,b4; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000072F40; }
	{ nop.m	0x0; adds	r1,0x0,r38; adds	r33,0x0,r8; }

l4000000000073080:
	{ nop.m	0x0; ld4	r32,[r35]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x3C,r32; adds	r15,0xFFFFFFFFFFFFFFFD,r32; cmp4.eq	p08,p09,0x3E,r32; }
	{ (p06) addl	r14,1,r0; (p07) adds	r14,0x0,r0; cmp4.ltu	p07,p06,0x1,r15; }

l40000000000730A6:
	{ Invalid; (p03) nop; (p32) nop; }

l40000000000730AC:
	{ ld4	r15,[r107]; (p04) cmp.lt.unc	p00,p16,r3,r64; (p08) nop }
	{ (p04) invala.e	f0; Invalid; rfi }

l40000000000730C0:
	{ nop.m	0x0; (p09) br.cond.dpnt.few	4000000000073200; br.call.sptk.many	b0,fn4000000000074880; }

l40000000000730CC:
	{ Invalid; nop; zxt1	r64,r64 }
	{ (p51) nop; invala; break.b	0x1000 }
	{ cmp.lt	p00,p09,r1,r0; czx1.l	r34,r1; Invalid }

l40000000000730F0:
	{ cmp.lt	p06,p07,r8,r33; ld4	r32,[r35]; nop.i	0x0; }
	{ (p07) adds	r33,0x0,r0; adds	r15,0xFFFFFFFFFFFFFFFD,r32; cmp4.eq	p08,p09,0x3E,r32; }

l4000000000073106:
	{ Invalid; (p04) addl	r62,162208,r1; (p17) nop.b	0x28 }

l4000000000073116:
	{ break.m	0x4000; (p03) addl	r60,129440,r3; (p33) cmp.eq	p35,p00,0x0,r0 }

l4000000000073126:
	{ Invalid; (p03) nop; (p32) nop; }

l400000000007312C:
	{ ld4	r15,[r107]; (p04) cmp.lt.unc	p00,p16,r3,r64; (p08) nop }
	{ Invalid; break.i	0x1000; break.b	0x1000 }

l4000000000073140:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ adds	r1,0x0,r38; nop.i	0x0; br.call.sptk.many	b0,fn4000000000072F40; }
	{ cmp.lt	p09,p08,r8,r33; nop.m	0x0; adds	r1,0x0,r38 }
	{ cmp4.eq	p07,p06,0x3,r32; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000731A0; }

l4000000000073180:
	{ nop.m	0x0; (p08) addl	r33,1,r0; nop.i	0x0; }

l400000000007318C:
	{ invala; nop; zxt1	r0,r64 }

l400000000007319C:
	{ (p55) cmp.eq.unc	p63,p17,r63,r36; czx1.r	r1,r97; br.cond	b0 }

l40000000000731A0:
	{ cmp4.eq	p07,p06,0x4,r32; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000731E0; }

l40000000000731B0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r34; (p06) br.cond.dptk.few	40000000000730F0; }

l40000000000731C0:
	{ cmp.lt	p06,p07,r33,r8; (p06) addl	r33,1,r0; nop.i	0x0; }

l40000000000731CC:
	{ Invalid; nop; zxt1	r0,r64 }

l40000000000731DC:
	{ (p53) cmp.eq.unc	p63,p11,r63,r36; (p16) nop; (p20) nop }

l40000000000731E0:
	{ cmp.lt	p07,p06,r33,r8; (p06) addl	r33,1,r0; nop.i	0x0; }

l40000000000731EC:
	{ Invalid; nop; zxt1	r0,r64 }

l40000000000731FC:
	{ (p52) nop; zxt1	r32,r64; break.b	0x1000 }

l4000000000073200:
	{ adds	r8,0x0,r33; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,4000000000073210; br.ret	b0; }
4000000000073220 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000073230 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000073240: 4000000000073240
;;   Called from:
;;     400000000007336C (in fn4000000000073340)
;;     40000000000733BC (in fn4000000000073340)
fn4000000000073240 proc
	{ alloc	r36,ar.pfs,0x6,0x0,0x6; addl	r34,7304,r1; mov	r35,b3 }
	{ nop.m	0x0; adds	r37,0x0,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000073040; }
	{ ld4	r32,[r34]; adds	r1,0x0,r37; adds	r33,0x0,r8; }
	{ nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFFFF,r32; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p07,p06,0x1,r14; (p07) br.cond.dpnt.few	4000000000073300; }

l40000000000732A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ adds	r1,0x0,r37; nop.i	0x0; br.call.sptk.many	b0,fn4000000000073040; }
	{ cmp4.eq	p09,p08,0x1,r32; nop.m	0x0; cmp.eq	p07,p06,r8,r33 }
	{ ld4	r32,[r34]; nop.m	0x0; adds	r1,0x0,r37; }
	{ (p09) cmp.eq	p06,p07,r8,r33; adds	r14,0xFFFFFFFFFFFFFFFF,r32; (p06) addl	r33,1,r0; }

l40000000000732E6:
	{ Invalid; (p16) cmp4.eq.or.andcm	p01,p08,r0,r0; (p17) nop }

l40000000000732F0:
	{ (p07) adds	r33,0x0,r0; cmp4.ltu	p07,p06,0x1,r14; (p06) br.cond.dptk.few	40000000000732A0; }

l40000000000732F6:
	{ (p03) chk.a.clr	r1,3FFFFFFFFFB363D6; nop; nop.b	0x21002 }

l4000000000073300:
	{ adds	r8,0x0,r33; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,4000000000073310; br.ret	b0; }
4000000000073320 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000073330 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000073340: 4000000000073340
;;   Called from:
;;     400000000007342C (in fn4000000000073400)
;;     400000000007347C (in fn4000000000073400)
fn4000000000073340 proc
	{ alloc	r35,ar.pfs,0x5,0x0,0x5; addl	r33,7304,r1; mov	r34,b2 }
	{ nop.m	0x0; adds	r36,0x0,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000073240; }
	{ ld4	r14,[r33]; adds	r1,0x0,r36; adds	r32,0x0,r8; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x26,r14; (p06) br.cond.dpnt.few	40000000000733E0; }

l4000000000073390:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000733A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ adds	r1,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,fn4000000000073240; }
	{ ld4	r14,[r33]; adds	r1,0x0,r36; and	r32,r8,r32; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x26,r14; (p06) br.cond.dptk.few	40000000000733A0 }

l40000000000733E0:
	{ adds	r8,0x0,r32; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000733F0; br.ret	b0; }

;; fn4000000000073400: 4000000000073400
;;   Called from:
;;     40000000000734EC (in fn40000000000734C0)
;;     400000000007353C (in fn40000000000734C0)
fn4000000000073400 proc
	{ alloc	r35,ar.pfs,0x5,0x0,0x5; addl	r33,7304,r1; mov	r34,b2 }
	{ nop.m	0x0; adds	r36,0x0,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000073340; }
	{ ld4	r14,[r33]; adds	r1,0x0,r36; adds	r32,0x0,r8; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5E,r14; (p06) br.cond.dpnt.few	40000000000734A0; }

l4000000000073450:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000073460:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ adds	r1,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,fn4000000000073340; }
	{ ld4	r14,[r33]; adds	r1,0x0,r36; xor	r32,r8,r32; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x5E,r14; (p06) br.cond.dptk.few	4000000000073460 }

l40000000000734A0:
	{ adds	r8,0x0,r32; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000734B0; br.ret	b0; }

;; fn40000000000734C0: 40000000000734C0
;;   Called from:
;;     40000000000735AC (in fn4000000000073580)
;;     400000000007361C (in fn4000000000073580)
;;     40000000000736BC (in fn4000000000073580)
fn40000000000734C0 proc
	{ alloc	r35,ar.pfs,0x5,0x0,0x5; addl	r33,7304,r1; mov	r34,b2 }
	{ nop.m	0x0; adds	r36,0x0,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000073400; }
	{ ld4	r14,[r33]; adds	r1,0x0,r36; adds	r32,0x0,r8; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x7C,r14; (p06) br.cond.dpnt.few	4000000000073560; }

l4000000000073510:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000073520:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ adds	r1,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,fn4000000000073400; }
	{ ld4	r14,[r33]; adds	r1,0x0,r36; or	r32,r8,r32; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x7C,r14; (p06) br.cond.dptk.few	4000000000073520 }

l4000000000073560:
	{ adds	r8,0x0,r32; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000073570; br.ret	b0; }

;; fn4000000000073580: 4000000000073580
;;   Called from:
;;     400000000007376C (in fn4000000000073740)
;;     40000000000737DC (in fn4000000000073740)
;;     400000000007386C (in fn4000000000073740)
fn4000000000073580 proc
	{ alloc	r37,ar.pfs,0x8,0x0,0x8; nop.m	0x0; mov	r39,pr }
	{ addl	r33,7304,r1; adds	r38,0x0,r1; mov	r36,b4 }
	{ addl	r35,7,r0; nop.m	0x0; br.call.sptk.many	b0,fn40000000000734C0; }
	{ adds	r1,0x0,r38; ld4	r14,[r33]; nop.i	0x0; }
	{ nop.m	0x0; addl	r34,7300,r1; addl	r32,7252,r1 }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x7,r14; (p06) br.cond.dpnt.few	4000000000073680; }

l40000000000735E0:
	{ nop.m	0x0; cmp.eq	p17,p16,0x0,r8; (p16) br.cond.dptk.few	40000000000736A0; }

l40000000000735F0:
	{ ld4	r14,[r32]; adds	r14,0x1,r14; nop.i	0x0; }
	{ st4	[r14],r32; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ adds	r1,0x0,r38; nop.i	0x0; br.call.sptk.many	b0,fn40000000000734C0; }
	{ ld4	r14,[r32]; cmp.eq	p07,p06,0x0,r8; (p16) addl	r15,1,r0 }

l4000000000073630:
	{ adds	r1,0x0,r38; st4	[r35],r34; nop.i	0x0; }
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r14; (p06) addl	r8,1,r0; (p17) adds	r15,0x0,r0; }

l400000000007364C:
	{ nop; break.i	0x1000; (p32) mov	pr,r8,0x4606; }

l4000000000073650:
	{ nop.m	0x0; st4	[r14],r32; (p07) adds	r8,0x0,r0 }

l4000000000073660:
	{ nop.m	0x0; ld4	r14,[r33]; nop.i	0x0; }
	{ and	r8,r15,r8; cmp4.eq	p06,p07,0x7,r14; (p06) br.cond.dptk.few	40000000000735E0; }

l4000000000073680:
	{ nop.m	0x0; mov	pr,r39,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,4000000000073690; br.ret	b0; }

l40000000000736A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ adds	r1,0x0,r38; nop.i	0x0; br.call.sptk.many	b0,fn40000000000734C0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r8; (p16) addl	r15,1,r0 }

l40000000000736D0:
	{ ld4	r14,[r33]; st4	[r35],r34; adds	r1,0x0,r38; }
	{ (p06) addl	r8,1,r0; nop.m	0x0; (p17) adds	r15,0x0,r0; }

l40000000000736E6:
	{ nop; (p07) cmp4.eq.or	p00,p02,r0,r0; (p01) nop }

l40000000000736F0:
	{ (p07) adds	r8,0x0,r0; nop.m	0x0; cmp4.eq	p06,p07,0x7,r14; }

l40000000000736F6:
	{ break.m	0x4000; (p03) nop; break.i	0x80000 }
	{ (p04) chk.a.clr	r15,3FFFFFFFFF079786; nop; break.i	0x80000 }

l4000000000073710:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000073680; }
4000000000073720 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000073730 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000073740: 4000000000073740
;;   Called from:
;;     40000000000739FC (in fn4000000000073740)
;;     4000000000073A6C (in fn4000000000073740)
;;     4000000000073B5C (in fn4000000000073B40)
fn4000000000073740 proc
	{ alloc	r38,ar.pfs,0xB,0x0,0x8; addl	r34,7304,r1; nop.b	0x0 }
	{ adds	r39,0x0,r1; nop.m	0x0; mov	r37,b5; }
	{ addl	r35,8,r0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000073580; }
	{ adds	r1,0x0,r39; ld4	r14,[r34]; adds	r32,0x0,r8; }
	{ nop.m	0x0; addl	r36,7300,r1; addl	r33,7252,r1 }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x8,r14; (p06) br.cond.dpnt.few	4000000000073820; }

l40000000000737A0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r32; (p06) br.cond.dptk.few	4000000000073850 }

l40000000000737B0:
	{ ld4	r14,[r33]; adds	r14,0x1,r14; nop.i	0x0; }
	{ st4	[r14],r33; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ adds	r1,0x0,r39; nop.i	0x0; br.call.sptk.many	b0,fn4000000000073580; }
	{ ld4	r14,[r33]; or	r32,r32,r8; adds	r1,0x0,r39 }
	{ st4	[r35],r36; adds	r14,0xFFFFFFFFFFFFFFFF,r14; cmp.eq	p09,p08,0x0,r32; }
	{ st4	[r14],r33; ld4	r14,[r34]; (p08) addl	r32,1,r0; }

l4000000000073810:
	{ cmp4.eq	p06,p07,0x8,r14; (p09) adds	r32,0x0,r0; (p06) br.cond.dptk.few	40000000000737A0; }

l400000000007381C:
	{ (p60) cmp.eq.unc	p63,p17,r63,r37; czx1.r	r79,r97; (p32) br.ia	b0 }

l4000000000073820:
	{ cmp4.eq	p07,p06,0x3F,r14; mov.i	ar.pfs,r38; (p07) br.cond.dpnt.few	40000000000738C0; }

l4000000000073830:
	{ nop.m	0x0; mov.spnt	b0,r37,4000000000073830; nop.i	0x0 }
	{ (p06) adds	r8,0x0,r32; nop.m	0x0; br.ret	b0; }

l4000000000073846:
	{ break.m	0x4000; (p34) nop; break.i	0x80000 }

l4000000000073850:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ adds	r1,0x0,r39; nop.i	0x0; br.call.sptk.many	b0,fn4000000000073580; }
	{ or	r32,r32,r8; ld4	r14,[r34]; adds	r1,0x0,r39 }
	{ st4	[r35],r36; cmp.eq	p09,p08,0x0,r32; cmp4.eq	p06,p07,0x8,r14; }
	{ nop.m	0x0; (p08) addl	r32,1,r0; nop.i	0x0; }

l400000000007389C:
	{ invala; Invalid; (p04) mov	pr,r0,0x8400 }

l40000000000738AC:
	{ (p56) invala; break.i	0x1000; break.i	0x1000 }

l40000000000738B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000073820 }

l40000000000738C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ ld4	r14,[r34]; adds	r1,0x0,r39; cmp4.eq	p07,p06,0x3A,r14; }
	{ cmp4.eq.or.andcm	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.spnt.few	4000000000073AB0; }

l40000000000738F0:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p06) br.cond.dptk.few	4000000000073A90 }

l4000000000073900:
	{ addl	r33,7252,r1; ld4	r14,[r33]; nop.i	0x0; }
	{ nop.m	0x0; adds	r14,0x1,r14; nop.i	0x0; }
	{ st4	[r14],r33; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074100; }
	{ ld4	r14,[r33]; adds	r1,0x0,r39; adds	r35,0x0,r8; }
	{ nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; }
	{ st4	[r14],r33; nop.m	0x0; nop.i	0x0 }

l4000000000073960:
	{ nop.m	0x0; ld4	r14,[r34]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x3A,r14; nop.i	0x0; (p07) br.cond.spnt.few	4000000000073AF0; }

l4000000000073980:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ adds	r1,0x0,r39; addl	r14,7304,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.spnt.few	4000000000073AB0; }

l40000000000739C0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r32; (p06) br.cond.dptk.few	4000000000073A60 }

l40000000000739D0:
	{ addl	r33,7252,r1; ld4	r14,[r33]; nop.i	0x0; }
	{ nop.m	0x0; adds	r14,0x1,r14; nop.i	0x0; }
	{ st4	[r14],r33; nop.i	0x0; br.call.sptk.many	b0,fn4000000000073740; }
	{ ld4	r14,[r33]; nop.m	0x0; adds	r1,0x0,r39 }
	{ addl	r15,12,r0; adds	r8,0x0,r35; adds	r14,0xFFFFFFFFFFFFFFFF,r14; }
	{ st4	[r14],r33; nop.m	0x0; addl	r14,7300,r1; }
	{ st4	[r15],r14; nop.m	0x0; nop.i	0x0 }

l4000000000073A40:
	{ nop.m	0x0; mov.i	ar.pfs,r38; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r37,4000000000073A50; br.ret	b0; }

l4000000000073A60:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000073740; }
	{ adds	r1,0x0,r39; addl	r15,12,r0; addl	r14,7300,r1; }
	{ st4	[r15],r14; nop.i	0x0; br.cond.sptk.few	4000000000073A40 }

l4000000000073A90:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074100; }
	{ adds	r1,0x0,r39; adds	r35,0x0,r8; br.cond.sptk.few	4000000000073960; }

l4000000000073AB0:
	{ nop.m	0x0; addl	r41,836,r1; nop.i	0x0; }
	{ ld8	r41,[r41]; nop.m	0x0; nop.i	0x0 }

l4000000000073AD0:
	{ addl	r42,5,r0; adds	r40,0x0,r0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r39; adds	r40,0x0,r8; br.call.sptk.many	b0,fn4000000000071E00; }

l4000000000073AF0:
	{ nop.m	0x0; addl	r41,844,r1; nop.i	0x0; }
	{ ld8	r41,[r41]; nop.i	0x0; br.cond.sptk.few	4000000000073AD0; }
4000000000073B10 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000073B20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000073B30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000073B40: 4000000000073B40
;;   Called from:
;;     4000000000073C7C (in fn4000000000073B40)
;;     4000000000073F2C (in fn4000000000073B40)
;;     400000000007412C (in fn4000000000074100)
;;     400000000007417C (in fn4000000000074100)
fn4000000000073B40 proc
	{ alloc	r38,ar.pfs,0xB,0x0,0x8; mov	r37,b5; adds	r39,0x0,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000073740; }
	{ adds	r1,0x0,r39; adds	r32,0x0,r8; addl	r14,7304,r1 }
	{ addl	r33,7260,r1; ld4	r15,[r14]; nop.i	0x0; }
	{ cmp4.eq	p08,p09,0xB,r15; cmp4.eq	p06,p07,0x3D,r15; (p08) addl	r14,1,r0; }

l4000000000073B90:
	{ (p09) adds	r14,0x0,r0; nop.i	0x0; cmp.ne.or.andcm	p06,p07,0x0,r14 }

l4000000000073B96:
	{ break.m	0x4000; (p35) nop; (p48) nop }
	{ (p07) chk.a.clr	f4,3FFFFFFFFF2903B6; nop; (p32) nop }

l4000000000073BB0:
	{ ld4	r14,[r14]; cmp4.eq	p06,p07,0x5,r14; nop.i	0x0; }
	{ nop.m	0x0; (p07) addl	r41,852,r1; nop.i	0x0; }

l4000000000073BCC:
	{ nop; Invalid; mov	pr,r32,0x0 }

l4000000000073BD6:
	{ chk.a.nc	f0,3FFFFFFFFF0743D6; nop; nop }

l4000000000073BE0:
	{ ld8	r40,[r33]; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dptk.few	4000000000073EB0 }

l4000000000073BF0:
	{ nop.m	0x0; addl	r14,7324,r1; nop.i	0x0; }
	{ ld4	r34,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r39; adds	r40,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r41,[r33]; nop.m	0x0; adds	r40,0x0,r8 }
	{ adds	r1,0x0,r39; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r39; adds	r35,0x0,r8; addl	r14,-20772,r1; }
	{ nop.m	0x0; adds	r14,0x18,r14; nop.i	0x0; }
	{ ld8	r36,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ adds	r1,0x0,r39; nop.i	0x0; br.call.sptk.many	b0,fn4000000000073B40; }
	{ cmp4.eq	p10,p11,0x25,r34; cmp4.eq	p08,p09,0x2F,r34; adds	r1,0x0,r39; }
	{ (p10) cmp.eq.unc	p06,p00,r0,r0; nop.m	0x0; (p11) cmp.eq.unc	p07,p00,r0,r0; }

l4000000000073C96:
	{ addl	r0,49152,r1; (p35) nop; break.i	0x80000 }

l4000000000073CA0:
	{ nop.m	0x0; (p08) cmp4.eq.or.andcm	p06,p07,0x0,r0; (p06) br.cond.dptk.few	4000000000073F40; }

l4000000000073CB0:
	{ cmp4.eq	p06,p07,0x2B,r34; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000740D0; }

l4000000000073CC0:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x2B,r34; (p07) br.cond.dptk.few	4000000000073D40; }

l4000000000073CD0:
	{ cmp4.lt	p06,p07,0x2F,r34; (p08) br.cond.dpnt.few	40000000000740B0; (p06) br.cond.dptk.few	4000000000074020; }

l4000000000073CDC:
	{ (p26) invala; cmp.lt	p00,p00,r32,r0; (p16) nop }

l4000000000073CE0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2D,r34; (p06) br.cond.dpnt.few	4000000000074050 }

l4000000000073CF0:
	{ adds	r40,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r39; nop.i	0x0; addl	r41,860,r1; }
	{ ld8	r41,[r41]; nop.m	0x0; nop.i	0x0 }

l4000000000073D20:
	{ addl	r42,5,r0; adds	r40,0x0,r0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r39; adds	r40,0x0,r8; br.call.sptk.many	b0,fn4000000000071E00 }

l4000000000073D40:
	{ cmp4.eq	p06,p07,0x26,r34; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000740E0; }

l4000000000073D50:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x26,r34; (p06) br.cond.dptk.few	4000000000073FE0; }

l4000000000073D60:
	{ cmp4.eq	p06,p07,0x9,r34; (p10) br.cond.dpnt.few	4000000000074060; (p06) br.cond.dpnt.few	4000000000074090; }

l4000000000073D6C:
	{ (p25) invala; cmp.lt	p00,p00,r32,r0; (p32) nop }

l4000000000073D70:
	{ nop.m	0x0; cmp4.eq	p06,p07,0xA,r34; (p07) br.cond.dptk.few	4000000000073CF0 }

l4000000000073D80:
	{ nop.m	0x0; sxt4	r8,r8; shr	r32,r32,r8; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000073DA0:
	{ adds	r40,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,itos; }
	{ adds	r1,0x0,r39; adds	r34,0x0,r8; addl	r14,7252,r1; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000073E20; }

l4000000000073DE0:
	{ cmp.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r36; adds	r40,0x0,r35; nop.i	0x0 }
	{ adds	r41,0x0,r36; adds	r42,0x0,r8; (p06) br.cond.dpnt.few	4000000000073FB0; }

l4000000000073E00:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000071FC0; }
	{ adds	r1,0x0,r39; nop.m	0x0; nop.i	0x0 }

l4000000000073E20:
	{ adds	r40,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r39; adds	r40,0x0,r35; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ ld8	r40,[r33]; nop.m	0x0; adds	r1,0x0,r39; }
	{ cmp.eq	p06,p07,0x0,r40; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000073E80; }

l4000000000073E60:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r39; nop.m	0x0; nop.i	0x0 }

l4000000000073E80:
	{ st8	[r0],r33; nop.m	0x0; nop.i	0x0 }

l4000000000073E90:
	{ adds	r8,0x0,r32; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,4000000000073EA0; br.ret	b0; }

l4000000000073EB0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r39; adds	r40,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r41,[r33]; nop.m	0x0; adds	r40,0x0,r8 }
	{ adds	r1,0x0,r39; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r39; adds	r35,0x0,r8; addl	r14,-20772,r1; }
	{ nop.m	0x0; adds	r14,0x18,r14; nop.i	0x0; }
	{ ld8	r36,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ adds	r1,0x0,r39; nop.i	0x0; br.call.sptk.many	b0,fn4000000000073B40; }
	{ adds	r1,0x0,r39; adds	r32,0x0,r8; br.cond.sptk.few	4000000000073DA0 }

l4000000000073F40:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	4000000000073CB0; }

l4000000000073F50:
	{ addl	r14,7252,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; }
	{ nop.m	0x0; (p06) addl	r8,1,r0; (p06) br.cond.sptk.few	4000000000073CB0 }

l4000000000073F7C:
	{ (p42) nop; (p05) dep	r47,r64,r1,62,3; zxt4	r1,r0 }

l4000000000073F80:
	{ addl	r41,828,r1; addl	r42,5,r0; adds	r40,0x0,r0; }
	{ ld8	r41,[r41]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r39; adds	r40,0x0,r8; br.call.sptk.many	b0,fn4000000000071E00; }

l4000000000073FB0:
	{ adds	r41,0x0,r8; adds	r40,0x0,r35; br.call.sptk.many	b0,bind_int_variable; }
	{ adds	r1,0x0,r39; adds	r40,0x0,r35; br.call.sptk.many	b0,stupidly_hack_special_variables; }
	{ nop.m	0x0; adds	r1,0x0,r39; br.cond.sptk.few	4000000000073E20 }

l4000000000073FE0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2A,r34; (p07) br.cond.dptk.few	4000000000073CF0 }

l4000000000073FF0:
	{ setf.sig	f7,r32; setf.sig	f6,r8; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; xma.l	f6,f6,f7,f0; }
	{ getf.sig	r32,f6; nop.i	0x0; br.cond.sptk.few	4000000000073DA0 }

l4000000000074020:
	{ cmp4.eq	p06,p07,0x5E,r34; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000074080; }

l4000000000074030:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x7C,r34; (p07) br.cond.dptk.few	4000000000073CF0 }

l4000000000074040:
	{ nop.m	0x0; or	r32,r32,r8; br.cond.sptk.few	4000000000073DA0; }

l4000000000074050:
	{ nop.m	0x0; sub	r32,r32,r8; br.cond.sptk.few	4000000000073DA0; }

l4000000000074060:
	{ adds	r40,0x0,r32; adds	r41,0x0,r8; br.call.sptk.many	b0,fn4000000000137A00; }
	{ adds	r1,0x0,r39; adds	r32,0x0,r8; br.cond.sptk.few	4000000000073DA0; }

l4000000000074080:
	{ nop.m	0x0; xor	r32,r32,r8; br.cond.sptk.few	4000000000073DA0 }

l4000000000074090:
	{ nop.m	0x0; sxt4	r8,r8; nop.i	0x0; }
	{ nop.m	0x0; shl	r32,r32,r8; br.cond.sptk.few	4000000000073DA0; }

l40000000000740B0:
	{ adds	r40,0x0,r32; adds	r41,0x0,r8; br.call.sptk.many	b0,fn4000000000137910; }
	{ adds	r1,0x0,r39; adds	r32,0x0,r8; br.cond.sptk.few	4000000000073DA0; }

l40000000000740D0:
	{ nop.m	0x0; add	r32,r8,r32; br.cond.sptk.few	4000000000073DA0; }

l40000000000740E0:
	{ nop.m	0x0; and	r32,r32,r8; br.cond.sptk.few	4000000000073DA0; }
40000000000740F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000074100: 4000000000074100
;;   Called from:
;;     400000000007272C (in fn4000000000072100)
;;     400000000007392C (in fn4000000000073740)
;;     4000000000073A9C (in fn4000000000073740)
;;     40000000000745AC (in fn40000000000741C0)
fn4000000000074100 proc
	{ alloc	r34,ar.pfs,0x4,0x0,0x4; addl	r32,7304,r1; mov	r33,b1 }
	{ nop.m	0x0; adds	r35,0x0,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000073B40; }
	{ ld4	r14,[r32]; nop.m	0x0; adds	r1,0x0,r35; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2C,r14; (p06) br.cond.dpnt.few	40000000000741A0; }

l4000000000074150:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000074160:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ adds	r1,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn4000000000073B40; }
	{ ld4	r14,[r32]; nop.m	0x0; adds	r1,0x0,r35; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2C,r14; (p06) br.cond.dptk.few	4000000000074160 }

l40000000000741A0:
	{ nop.m	0x0; mov.i	ar.pfs,r34; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r33,40000000000741B0; br.ret	b0; }

;; fn40000000000741C0: 40000000000741C0
;;   Called from:
;;     40000000000756BC (in fn4000000000074880)
;;     400000000007627C (in evalexp)
fn40000000000741C0 proc
	{ alloc	r46,ar.pfs,0x14,0x0,0x11; nop.m	0x0; mov	r48,LC }
	{ cmp.eq	p06,p07,0x0,r32; nop.m	0x0; adds	r47,0x0,r1; }
	{ nop.m	0x0; mov	r45,b5; (p06) br.cond.dpnt.few	4000000000074260; }

l40000000000741F0:
	{ ld1	r14,[r32]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000074260; }

l4000000000074210:
	{ (p06) andcm	r16,0xFFFFFFFFFFFFFFFF,r32; (p06) adds	r15,0x0,r32; (p06) mov.i	LC,r16; }

l4000000000074216:
	{ (p07) chk.a.clr	r0,3FFFFFFFFF0F4416; nop; break.b	0x80000; }

l400000000007421C:
	{ (p08) nop; cmp.lt	p00,p00,r32,r0; czx1.r	r72,r97 }

l4000000000074220:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x20,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x9,r14; (p06) br.cond.dptk.few	4000000000074250; }

l4000000000074240:
	{ nop.m	0x0; cmp4.eq	p06,p07,0xA,r14; (p07) br.cond.dpnt.few	40000000000742C0 }

l4000000000074250:
	{ nop.m	0x0; adds	r15,0x1,r15; br.cloop.sptk.few	4000000000074290 }

l4000000000074260:
	{ adds	r33,0x0,r0; nop.m	0x0; nop.i	0x0; }

l4000000000074270:
	{ adds	r8,0x0,r33; mov.i	ar.pfs,r46; mov.i	LC,r48; }
	{ nop.m	0x0; mov.spnt	b0,r45,4000000000074280; br.ret	b0 }

l4000000000074290:
	{ ld1	r14,[r15]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000074220 }

l40000000000742B0:
	{ nop.m	0x0; adds	r33,0x0,r0; br.cond.sptk.few	4000000000074270 }

l40000000000742C0:
	{ ld1	r14,[r15]; addl	r37,7284,r1; addl	r15,1023,r0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.spnt.few	4000000000074260; }

l40000000000742F0:
	{ ld4	r14,[r37]; cmp4.lt	p07,p06,r15,r14; addl	r15,7328,r1; }
	{ nop.m	0x0; (p07) addl	r50,868,r1; nop.i	0x0; }

l400000000007430C:
	{ getf.s	r0,f1; Invalid; mov	pr,r32,0x0 }

l4000000000074316:
	{ chk.a.nc	f0,3FFFFFFFFF074B16; nop; break.i	0x80000 }

l4000000000074320:
	{ nop.m	0x0; ld4	r16,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r14,r16; (p07) br.cond.dpnt.few	40000000000747E0; }

l4000000000074340:
	{ (p06) addl	r42,7276,r1; nop.m	0x0; nop.i	0x0 }

l4000000000074346:
	{ break.m	0x4000; nop; nop }

l4000000000074350:
	{ addl	r36,-20772,r1; nop.m	0x0; addl	r49,88,r0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r33,0x0,r36; adds	r1,0x0,r47; adds	r14,0x40,r8 }
	{ ld4	r16,[r37]; adds	r20,0x38,r8; adds	r15,0x0,r8; }
	{ ld8	r19,[r33],8; addl	r38,7304,r1; addl	r34,7260,r1 }
	{ addl	r35,7268,r1; addl	r41,7300,r1; addl	r40,7292,r1; }
	{ ld8	r18,[r33],8; addl	r39,7308,r1; addl	r44,7316,r1 }
	{ st8	[r19],r20; addl	r43,7252,r1; sxt4	r25,r16; }
	{ ld8	r19,[r33],8; st8	[r18],r14; adds	r14,0x48,r8 }
	{ adds	r31,0x8,r8; adds	r30,0x10,r8; adds	r29,0x18,r8; }
	{ ld4	r17,[r38]; adds	r28,0x20,r8; adds	r27,0x28,r8 }
	{ adds	r26,0x30,r8; adds	r16,0x1,r16; adds	r49,0x0,r32; }
	{ ld8	r18,[r42]; st4	[r15],r4,4; nop.i	0x0 }
	{ st8	[r19],r14; ld8	r17,[r33]; adds	r14,0x50,r8; }
	{ shladd	r25,r25,0x3,r18; ld8	r24,[r35]; nop.i	0x0 }
	{ st8	[r17],r14; st4	[r16],r37; nop.i	0x0; }
	{ nop.m	0x0; ld4	r23,[r41]; nop.i	0x0 }
	{ st8	[r24],r31; ld8	r22,[r40]; nop.i	0x0; }
	{ ld8	r21,[r44]; st4	[r23],r15; nop.i	0x0 }
	{ st8	[r22],r30; ld8	r20,[r39]; nop.i	0x0; }
	{ ld8	r19,[r34]; st8	[r21],r29; nop.i	0x0 }
	{ st8	[r20],r28; ld4	r18,[r43]; nop.i	0x0; }
	{ st8	[r19],r27; st4	[r18],r26; nop.i	0x0; }
	{ st8	[r8],r25; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r47; adds	r49,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r50,0x0,r32; nop.m	0x0; adds	r49,0x0,r8 }
	{ adds	r1,0x0,r47; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r47; addl	r15,-1,r0; adds	r16,0x0,r36 }
	{ st8	[r8],r35; st8	[r8],r40; adds	r17,0x8,r36; }
	{ addl	r14,-20740,r1; st8	[r16],r16,16; nop.i	0x0 }
	{ st8	[r15],r33; nop.m	0x0; nop.i	0x0 }
	{ st8	[r0],r16; st8	[r15],r17; nop.i	0x0; }
	{ st4	[r0],r41; st4	[r0],r38; nop.i	0x0; }
	{ st8	[r14],r8,8; st8	[r0],r34; nop.i	0x0; }
	{ st8	[r14],r8,8; st8	[r0],r39; nop.i	0x0; }
	{ nop.m	0x0; st8	[r14],r8,8; nop.i	0x0; }
	{ st8	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ adds	r1,0x0,r47; nop.i	0x0; br.call.sptk.many	b0,fn4000000000074100; }
	{ ld4	r14,[r38]; adds	r1,0x0,r47; adds	r33,0x0,r8; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.spnt.few	4000000000074830; }

l40000000000745D0:
	{ nop.m	0x0; ld8	r49,[r34]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r49; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000074610; }

l40000000000745F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r47; nop.m	0x0; nop.i	0x0 }

l4000000000074610:
	{ nop.m	0x0; ld8	r49,[r35]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r49; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000074650; }

l4000000000074630:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r47; nop.m	0x0; nop.i	0x0; }

l4000000000074650:
	{ ld4	r14,[r37]; addl	r18,7284,r1; adds	r15,0x0,r36; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFFFF,r14; }
	{ (p07) addl	r50,884,r1; nop.m	0x0; sxt4	r17,r14; }

l4000000000074676:
	{ add	r0,r0,r1; (p08) cmp4.eq	p00,p00,r14,r22; (p33) nop }

l4000000000074686:
	{ chk.a.nc	f0,3FFFFFFFFF074E86; nop; nop }

l4000000000074690:
	{ ld8	r16,[r42]; st4	[r14],r18; nop.i	0x0; }
	{ shladd	r14,r17,0x3,r16; ld8	r14,[r14]; nop.i	0x0; }
	{ adds	r17,0x0,r14; adds	r20,0x38,r14; adds	r26,0x10,r14 }
	{ adds	r25,0x18,r14; adds	r16,0x40,r14; adds	r19,0x8,r14; }
	{ ld4	r18,[r17],4; adds	r24,0x20,r14; adds	r22,0x28,r14 }
	{ adds	r21,0x30,r14; ld8	r23,[r20]; adds	r49,0x0,r14; }
	{ nop.m	0x0; ld4	r20,[r17]; nop.i	0x0 }
	{ st4	[r18],r38; ld8	r17,[r25]; nop.i	0x0; }
	{ ld8	r18,[r26]; st4	[r20],r41; nop.i	0x0 }
	{ st8	[r17],r44; ld8	r19,[r19]; nop.i	0x0; }
	{ st8	[r15],r8,8; ld8	r23,[r16]; adds	r16,0x48,r14 }
	{ st8	[r19],r35; ld8	r19,[r24]; nop.i	0x0; }
	{ ld8	r20,[r16]; st8	[r15],r8,8; adds	r16,0x50,r14 }
	{ st8	[r18],r40; ld4	r17,[r21]; nop.i	0x0; }
	{ ld8	r18,[r22]; st8	[r15],r8,8; nop.i	0x0 }
	{ st8	[r19],r39; ld8	r14,[r16]; nop.i	0x0; }
	{ st8	[r18],r34; st4	[r17],r43; nop.i	0x0; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r8,0x0,r33; adds	r1,0x0,r47; mov.i	ar.pfs,r46; }
	{ nop.m	0x0; mov.i	LC,r48; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r45,40000000000747D0; br.ret	b0 }

l40000000000747E0:
	{ adds	r16,0xA,r16; addl	r42,7276,r1; sxt4	r50,r16 }
	{ st4	[r16],r15; ld8	r49,[r42]; nop.i	0x0; }
	{ shladd	r50,r50,0x3,r0; nop.i	0x0; br.call.sptk.many	b0,xrealloc; }
	{ nop.m	0x0; adds	r1,0x0,r47; nop.i	0x0 }
	{ st8	[r8],r42; nop.m	0x0; br.cond.sptk.few	4000000000074350; }

l4000000000074830:
	{ nop.m	0x0; addl	r50,876,r1; nop.i	0x0; }
	{ ld8	r50,[r50]; nop.m	0x0; nop.i	0x0 }

l4000000000074850:
	{ addl	r51,5,r0; adds	r49,0x0,r0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r47; adds	r49,0x0,r8; br.call.sptk.many	b0,fn4000000000071E00; }
	{ nop.m	0x0; break.f	0x0; nop.i	0x0; }

;; fn4000000000074880: 4000000000074880
;;   Called from:
;;     400000000007217C (in fn4000000000072100)
;;     40000000000721AC (in fn4000000000072100)
;;     400000000007222C (in fn4000000000072100)
;;     400000000007224C (in fn4000000000072100)
;;     400000000007231C (in fn4000000000072100)
;;     400000000007240C (in fn4000000000072100)
;;     40000000000724BC (in fn4000000000072100)
;;     400000000007259C (in fn4000000000072100)
;;     40000000000726BC (in fn4000000000072100)
;;     400000000007271C (in fn4000000000072100)
;;     400000000007288C (in fn4000000000072100)
;;     400000000007290C (in fn4000000000072100)
;;     4000000000072A1C (in fn40000000000729C0)
;;     4000000000072BEC (in fn4000000000072B40)
;;     4000000000072CEC (in fn4000000000072B40)
;;     4000000000072E9C (in fn4000000000072E00)
;;     4000000000072FAC (in fn4000000000072F40)
;;     40000000000730CC (in fn4000000000073040)
;;     400000000007314C (in fn4000000000073040)
;;     40000000000732AC (in fn4000000000073240)
;;     40000000000733AC (in fn4000000000073340)
;;     400000000007346C (in fn4000000000073400)
;;     400000000007352C (in fn40000000000734C0)
;;     400000000007360C (in fn4000000000073580)
;;     40000000000736AC (in fn4000000000073580)
;;     40000000000737CC (in fn4000000000073740)
;;     400000000007385C (in fn4000000000073740)
;;     40000000000738CC (in fn4000000000073740)
;;     400000000007398C (in fn4000000000073740)
;;     4000000000073C6C (in fn4000000000073B40)
;;     4000000000073F1C (in fn4000000000073B40)
;;     400000000007416C (in fn4000000000074100)
;;     400000000007459C (in fn40000000000741C0)
;;     400000000007487C (in fn40000000000741C0)
;;     4000000000074CAC (in fn4000000000074880)
fn4000000000074880 proc
	{ alloc	r58,ar.pfs,0x22,0x0,0x1E; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ addl	r35,7292,r1; mov	r60,pr; adds	r59,0x0,r1; }
	{ ld8	r33,[r35]; mov	r61,LC; mov	r57,b1 }
	{ cmp.eq	p06,p07,0x0,r33; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000074A80; }

l40000000000748C0:
	{ nop.m	0x0; ld1	r32,[r33]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r32; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000074A80; }

l40000000000748E0:
	{ (p06) andcm	r14,0xFFFFFFFFFFFFFFFF,r33; nop.i	0x0; (p06) mov.i	LC,r14; }

l40000000000748E6:
	{ chk.a.nc	r0,3FFFFFFFFF0750E6; nop; break.i	0x80000 }

l40000000000748F0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000074900:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x20,r32; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x9,r32; (p06) br.cond.dptk.few	4000000000074930; }

l4000000000074920:
	{ nop.m	0x0; cmp4.eq	p06,p07,0xA,r32; (p07) br.cond.dpnt.few	4000000000074F10 }

l4000000000074930:
	{ nop.m	0x0; adds	r33,0x1,r33; br.cloop.sptk.few	4000000000074A60; }

l4000000000074940:
	{ addl	r34,1,r0; cmp4.eq	p06,p07,0x0,r32; (p06) br.cond.dpnt.few	4000000000074A80 }

l4000000000074950:
	{ addl	r40,7316,r1; st8	[r33],r35; nop.i	0x0; }
	{ st8	[r33],r40; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C3C0; }
	{ nop.m	0x0; zxt1	r14,r32; nop.i	0x0 }
	{ ld8	r15,[r8]; adds	r1,0x0,r59; shladd	r14,r14,0x1,r15; }
	{ nop.m	0x0; ld2	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0xA; (p07) br.cond.dptk.few	4000000000074AF0; }

l40000000000749B0:
	{ cmp4.eq	p07,p06,0x5F,r32; nop.m	0x0; adds	r16,0xFFFFFFFFFFFFFFD0,r32; }
	{ (p07) adds	r14,0xBE,r15; nop.m	0x0; zxt1	r16,r16; }

l40000000000749C6:
	{ break.m	0x4000; (p08) cmp4.eq	p00,p00,r16,r16; (p33) nop }

l40000000000749D6:
	{ chk.a.nc	f0,3FFFFFFFFF0751D6; nop; break.i	0x80000 }

l40000000000749E0:
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x9,r16; (p06) br.cond.dptk.few	4000000000074FA0; }

l40000000000749F0:
	{ (p07) adds	r16,0x0,r34; nop.m	0x0; nop.i	0x0; }

l40000000000749F6:
	{ break.m	0x4000; nop; break.i	0x80000 }

l4000000000074A00:
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x3; (p06) br.cond.dptk.few	4000000000074A40; }

l4000000000074A02:
	{ cmp.eq.and	p32,p48,r0,r0; (p32) add	r67,r1,r74,0x1; Invalid }

l4000000000074A10:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x23,r32; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x40,r32; (p06) br.cond.dptk.few	4000000000074A40; }

l4000000000074A30:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x5F,r32; (p07) br.cond.dpnt.few	4000000000075090 }

l4000000000074A40:
	{ ld1	r32,[r16],1; shladd	r14,r32,0x1,r15; nop.i	0x0; }
	{ ld2	r14,[r14]; nop.i	0x0; br.cond.sptk.few	4000000000074A00 }

l4000000000074A60:
	{ nop.m	0x0; ld1	r32,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r32; (p06) br.cond.dptk.few	4000000000074900 }

l4000000000074A80:
	{ addl	r14,7304,r1; st8	[r33],r35; nop.i	0x0; }
	{ ld4	r15,[r14]; st4	[r0],r14; addl	r14,7300,r1; }
	{ st4	[r15],r14; mov	pr,r60,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r58; }
	{ nop.m	0x0; mov.i	LC,r61; mov.spnt	b0,r57,4000000000074AB0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000074AD0:
	{ ld1	r32,[r34],1; nop.i	0x0; shladd	r14,r32,0x1,r15; }
	{ ld2	r14,[r14]; nop.m	0x0; nop.i	0x0; }

l4000000000074AF0:
	{ nop.m	0x0; tbit.z	p07,p06,r14,0x3; (p06) br.cond.dptk.few	4000000000074AD0; }

l4000000000074B00:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x5F,r32; (p06) br.cond.dptk.few	4000000000074AD0 }

l4000000000074B10:
	{ adds	r36,0xFFFFFFFFFFFFFFFF,r34; ld1	r41,[r36]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5B,r41; (p07) br.cond.dpnt.few	40000000000753F0; }

l4000000000074B30:
	{ (p06) adds	r56,0x0,r0; nop.m	0x0; nop.i	0x0 }

l4000000000074B36:
	{ break.m	0x4000; nop; break.i	0x80000 }

l4000000000074B40:
	{ nop.m	0x0; addl	r33,-20772,r1; addl	r42,7260,r1 }
	{ st1	[r0],r36; nop.m	0x0; nop.i	0x0 }
	{ ld8	r62,[r42]; ld8	r14,[r33]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000074B90; }

l4000000000074B80:
	{ nop.m	0x0; cmp.eq	p07,p06,r62,r14; (p07) br.cond.dpnt.few	4000000000075460; }

l4000000000074B90:
	{ cmp.eq	p06,p07,0x0,r62; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000074BC0; }

l4000000000074BA0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r59; nop.m	0x0; nop.i	0x0; }

l4000000000074BC0:
	{ addl	r32,7304,r1; ld8	r62,[r35]; adds	r34,0x0,r33 }
	{ adds	r47,0x10,r33; adds	r46,0x18,r33; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r59; nop.m	0x0; adds	r62,0x1,r8; }
	{ addl	r37,7252,r1; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r59; ld8	r43,[r35]; adds	r62,0x0,r8; }
	{ addl	r39,7300,r1; nop.m	0x0; addl	r38,7308,r1 }
	{ adds	r63,0x0,r43; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ addl	r14,1,r0; st1	[r41],r36; adds	r1,0x0,r59 }
	{ ld4	r48,[r37]; st8	[r0],r42; adds	r45,0x0,r8; }
	{ ld8	r55,[r34],8; st4	[r14],r37; addl	r14,5,r0 }
	{ st8	[r36],r35; ld4	r41,[r32]; addl	r49,7260,r1; }
	{ ld4	r44,[r39]; st4	[r14],r32; nop.i	0x0 }
	{ ld8	r54,[r40]; ld8	r53,[r38]; nop.i	0x0 }
	{ ld8	r52,[r34]; ld8	r51,[r47]; nop.i	0x0 }
	{ ld8	r50,[r46]; nop.m	0x0; br.call.sptk.many	b0,fn4000000000074880; }
	{ ld4	r14,[r32]; adds	r1,0x0,r59; adds	r15,0xFFFFFFFFFFFFFFF2,r44; }
	{ cmp4.eq	p07,p06,0x5,r14; addl	r16,7292,r1; (p07) br.cond.dpnt.few	4000000000075570; }

l4000000000074CD0:
	{ nop.m	0x0; cmp4.ltu	p07,p06,0x1,r15; addl	r15,-20772,r1 }
	{ st8	[r43],r16; st4	[r41],r32; addl	r16,7316,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }
	{ st4	[r44],r39; st8	[r54],r16; nop.i	0x0; }
	{ st8	[r53],r38; st8	[r45],r49; nop.i	0x0; }
	{ st4	[r48],r37; st8	[r55],r15; nop.i	0x0; }
	{ st8	[r52],r34; st8	[r51],r47; nop.i	0x0; }
	{ st8	[r50],r46; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000074D60; }

l4000000000074D50:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x3D,r14; (p06) br.cond.dpnt.few	40000000000752E0; }

l4000000000074D60:
	{ addl	r14,-20740,r1; adds	r15,0x0,r33; cmp4.eq	p07,p06,0x0,r48; }
	{ nop.m	0x0; ld8	r16,[r15],8; nop.i	0x0; }
	{ st8	[r14],r8,8; ld8	r16,[r15],8; nop.i	0x0; }
	{ st8	[r14],r8,8; ld8	r16,[r15],8; nop.i	0x0; }
	{ st8	[r14],r8,8; ld8	r15,[r15]; nop.i	0x0; }
	{ st8	[r15],r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000074F20 }

l4000000000074DC0:
	{ cmp4.eq	p17,p16,0x5D,r56; nop.m	0x0; adds	r62,0x0,r45; }
	{ (p17) adds	r63,0x0,r0; (p17) adds	r64,0x0,r0; (p17) br.call.dpnt.many	b0,array_variable_part; }

l4000000000074DD6:
	{ (p32) nop; break.x	0x98262FC080000 }

l4000000000074DDC:
	{ Invalid; break.m	0x1000; break.b	0x101000 }

l4000000000074DE0:
	{ nop.m	0x0; nop.i	0x0; (p16) br.call.dptk.many	b0,find_variable; }

l4000000000074DF0:
	{ adds	r14,0x28,r8; adds	r1,0x0,r59; nop.i	0x0 }
	{ adds	r34,0x0,r8; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	4000000000074E30; }

l4000000000074E10:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0xC; (p06) br.cond.dptk.few	4000000000075310 }

l4000000000074E30:
	{ addl	r14,7380,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000075310 }

l4000000000074E60:
	{ addl	r14,9044,r1; nop.m	0x0; adds	r62,0x0,r45 }
	{ addl	r15,1,r0; nop.m	0x0; (p17) br.cond.dpnt.few	40000000000757F0; }

l4000000000074E80:
	{ nop.m	0x0; nop.i	0x0; nop.i	0x0 }
	{ st4	[r15],r14; nop.m	0x0; br.call.sptk.many	b0,err_unboundvar; }
	{ adds	r1,0x0,r59; nop.m	0x0; nop.i	0x0; }

l4000000000074EB0:
	{ addl	r14,6512,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000075880 }

l4000000000074EE0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000071C80; }
	{ adds	r1,0x0,r59; nop.i	0x0; br.call.sptk.many	b0,top_level_cleanup; }
	{ adds	r1,0x0,r59; addl	r62,2,r0; br.call.sptk.many	b0,jump_to_top_level }

l4000000000074F10:
	{ nop.m	0x0; adds	r34,0x1,r33; br.cond.sptk.few	4000000000074950 }

l4000000000074F20:
	{ adds	r8,0x0,r0; ld4	r41,[r32]; nop.i	0x0; }
	{ st8	[r8],r38; nop.m	0x0; nop.i	0x0 }

l4000000000074F40:
	{ addl	r14,5,r0; st4	[r41],r39; nop.i	0x0; }
	{ st4	[r14],r32; nop.m	0x0; nop.i	0x0 }

l4000000000074F60:
	{ st8	[r36],r35; nop.m	0x0; nop.i	0x0 }

l4000000000074F70:
	{ nop.m	0x0; mov	pr,r60,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r58; }
	{ nop.m	0x0; mov.i	LC,r61; mov.spnt	b0,r57,4000000000074F80 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000074FA0:
	{ adds	r14,0x1,r33; adds	r36,0x2,r33; cmp4.eq	p06,p07,0x3D,r32; }
	{ ld1	r16,[r14]; adds	r18,0x0,r36; cmp4.eq	p08,p09,0x3D,r16; }
	{ (p08) addl	r17,1,r0; (p09) adds	r17,0x0,r0; nop.i	0x0; }

l4000000000074FC6:
	{ Invalid; break.b	0x4000; break.b	0x80000 }

l4000000000074FCC:
	{ nop.m	0x80; cmp.lt	p00,p00,r32,r0; (p01) break.i	0x10220 }
	{ Invalid; cmp.eq	p00,p00,r32,r0; mov	pr,r67,0x5980 }
	{ (p53) cmp.lt	p00,p11,r0,r33; (p16) nop; zxt4	r0,r0 }

l4000000000074FF0:
	{ cmp4.eq	p06,p07,0x21,r32; (p06) addl	r19,1,r0; nop.i	0x0; }

l4000000000074FFC:
	{ setf.exp	f0,r1; (p02) nop; zxt1	r68,r3 }

l4000000000075006:
	{ Invalid; nop; break.b	0x80000 }
	{ (p03) chk.a.clr	f0,3FFFFFFFFFD38946; nop; (p32) nop }

l4000000000075020:
	{ cmp4.eq	p06,p07,0x3E,r32; (p06) addl	r19,1,r0; nop.i	0x0; }

l400000000007502C:
	{ setf.exp	f0,r1; (p02) shladd	r0,r0,0x1,r64; zxt1	r68,r3 }

l4000000000075036:
	{ Invalid; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD38986; nop; nop }

l4000000000075050:
	{ addl	r32,7304,r1; addl	r33,4,r0; nop.i	0x0 }
	{ addl	r15,7300,r1; ld4	r14,[r32]; nop.i	0x0 }
	{ st4	[r33],r32; st4	[r14],r15; nop.i	0x0 }

l4000000000075080:
	{ st8	[r36],r35; nop.i	0x0; br.cond.sptk.few	4000000000074F70 }

l4000000000075090:
	{ nop.m	0x0; adds	r16,0xFFFFFFFFFFFFFFFF,r16; nop.i	0x0 }
	{ ld1.a	r14,[r33]; setf.sig	f6,r0; nop.i	0x0; }
	{ ld1	r15,[r16]; st1	[r0],r16; adds	r36,0x0,r16; }
	{ ld1.c.clr	r14,[r33]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; sxt1	r14,r14; adds	r20,0x0,r15; }
	{ cmp4.eq	p07,p06,0x30,r14; zxt1	r14,r14; (p07) br.cond.dpnt.few	4000000000075710; }

l40000000000750F0:
	{ nop.m	0x0; (p06) adds	r19,0x0,r0; (p06) addl	r17,10,r0 }

l40000000000750FC:
	{ (p05) nop; cmp.lt	p00,p00,r32,r0; mov	pr,r99,0xE680 }

l4000000000075100:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	4000000000075290; }

l4000000000075110:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000075120:
	{ cmp4.eq	p07,p06,0x23,r14; zxt1	r18,r14; (p07) br.cond.dpnt.few	40000000000754B0; }

l4000000000075130:
	{ ld8	r15,[r8]; shladd	r15,r18,0x1,r15; nop.i	0x0; }
	{ nop.m	0x0; ld2	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r15,0x3; (p06) br.cond.dptk.few	4000000000075180; }

l4000000000075160:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x40,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x5F,r14; (p06) br.cond.dpnt.few	4000000000075290 }

l4000000000075180:
	{ adds	r18,0xFFFFFFFFFFFFFFD0,r14; nop.m	0x0; zxt1	r18,r18; }
	{ adds	r15,0x0,r18; cmp4.ltu	p06,p07,0x9,r18; (p07) br.cond.dptk.few	4000000000075240; }

l40000000000751A0:
	{ adds	r15,0xFFFFFFFFFFFFFF9F,r14; nop.m	0x0; zxt1	r15,r15; }
	{ cmp4.ltu	p06,p07,0x19,r15; (p07) adds	r18,0xFFFFFFFFFFFFFFA9,r14; nop.i	0x0; }

l40000000000751BC:
	{ nop.m	0x80; dep	r0,r32,r0,49,1; (p02) break.i	0x10240 }
	{ Invalid; cmp4.eq.or.andcm	p00,p32,r32,r0; (p01) mov	pr,r4,0x8480 }

l40000000000751DC:
	{ (p03) cmp.eq	p00,p11,r0,r33; zxt2	r79,r79; Invalid }

l40000000000751E0:
	{ adds	r15,0xFFFFFFFFFFFFFFBF,r14; nop.m	0x0; zxt1	r15,r15; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x19,r15; (p06) br.cond.dptk.few	4000000000075530; }

l4000000000075200:
	{ cmp4.lt	p06,p07,0x24,r17; (p06) addl	r18,29,r0; nop.i	0x0; }

l400000000007520C:
	{ getf.exp	r0,f1; (p50) dep	r13,r0,r0,62,3; zxt1	r67,r1 }

l4000000000075216:
	{ Invalid; Invalid; break.i	0x80000 }
	{ (p09) add	r0,r18,r16; (p07) nop; break.i	0x80000 }
	{ break.m	0x4000; break.i	0x4000; break.i	0x80000 }

l4000000000075240:
	{ nop.m	0x0; sxt4	r14,r17; zxt1	r15,r15 }
	{ cmp4.lt	p06,p07,r18,r17; nop.m	0x0; (p07) br.cond.spnt.few	4000000000075B00; }

l4000000000075260:
	{ setf.sig	f7,r14; setf.sig	f8,r15; nop.i	0x0 }
	{ ld1	r14,[r34],1; cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; }
	{ nop.m	0x0; xma.l	f6,f6,f7,f8; (p06) br.cond.dptk.few	4000000000075120 }

l4000000000075290:
	{ st1	[r20],r16; addl	r16,7308,r1; addl	r14,7304,r1; }
	{ nop.m	0x0; stf8	[r16],f6; addl	r16,6,r0 }
	{ ld4	r15,[r14]; st4	[r16],r14; addl	r14,7300,r1 }
	{ nop.m	0x0; st4	[r15],r14; nop.i	0x0 }

l40000000000752D0:
	{ st8	[r36],r35; nop.i	0x0; br.cond.sptk.few	4000000000074F70 }

l40000000000752E0:
	{ nop.m	0x0; addl	r14,5,r0; nop.i	0x0 }
	{ st8	[r0],r38; st4	[r41],r39; nop.i	0x0; }
	{ st4	[r14],r32; nop.i	0x0; br.cond.sptk.few	4000000000074F60 }

l4000000000075310:
	{ addl	r14,-1,r0; adds	r15,0x10,r12; nop.i	0x0 }
	{ (p17) adds	r62,0x0,r45; (p17) adds	r63,0x0,r0; (p17) adds	r64,0x0,r0; }

l4000000000075326:
	{ Invalid; Invalid; Invalid }

l400000000007532C:
	{ Invalid; (p32) nop; mov	r96,ip }

l4000000000075330:
	{ st8	[r14],r15; (p17) adds	r65,0x0,r15; (p17) br.call.dpnt.many	b0,get_array_value; }

l400000000007533C:
	{ (p20) cmp.gt	p25,p17,r0,r41; (p07) invala; break.b	0x101000 }

l4000000000075340:
	{ (p16) adds	r62,0x0,r34; nop.i	0x0; (p16) br.call.dptk.many	b0,get_variable_value; }

l4000000000075346:
	{ nop; (p32) nop; (p16) nop }

l4000000000075350:
	{ adds	r1,0x0,r59; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	4000000000075380; }

l4000000000075360:
	{ ld1	r14,[r8]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	40000000000756B0 }

l4000000000075380:
	{ adds	r14,0x0,r33; nop.m	0x0; adds	r15,0x10,r33 }
	{ adds	r8,0x0,r0; nop.m	0x0; adds	r33,0x18,r33; }
	{ st8	[r14],r8,8; st8	[r34],r15; nop.i	0x0 }
	{ adds	r15,0x10,r12; st8	[r8],r14; nop.i	0x0 }
	{ ld8	r14,[r15]; st8	[r14],r33; nop.i	0x0 }

l40000000000753D0:
	{ nop.m	0x0; st8	[r8],r38; nop.i	0x0 }
	{ ld4	r41,[r32]; nop.m	0x0; br.cond.sptk.few	4000000000074F40 }

l40000000000753F0:
	{ adds	r62,0x0,r36; adds	r63,0x0,r0; nop.i	0x0 }
	{ adds	r64,0x0,r0; addl	r56,93,r0; br.call.sptk.many	b0,skipsubscript; }
	{ nop.m	0x0; sxt4	r8,r8; adds	r1,0x0,r59; }
	{ add	r14,r36,r8; nop.m	0x0; add	r36,r36,r8,0x1; }
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x5D,r14; nop.i	0x0; (p06) br.cond.spnt.few	4000000000075FD0; }

l4000000000075450:
	{ ld1	r41,[r36]; nop.i	0x0; br.cond.sptk.few	4000000000074B40 }

l4000000000075460:
	{ adds	r14,0x0,r33; addl	r15,-1,r0; adds	r17,0x18,r33 }
	{ adds	r16,0x8,r33; st8	[r14],r16,16; nop.i	0x0 }
	{ st8	[r15],r17; st8	[r0],r14; nop.i	0x0 }
	{ st8	[r15],r16; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r59; br.cond.sptk.few	4000000000074BC0 }

l40000000000754B0:
	{ getf.sig	r15,f6; nop.m	0x0; cmp4.eq	p06,p07,0x0,r19 }
	{ addl	r19,1,r0; nop.m	0x0; (p07) br.cond.spnt.few	4000000000076020; }

l40000000000754D0:
	{ getf.sig	r17,f6; setf.sig	f6,r0; nop.i	0x0; }
	{ nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFFFE,r15; nop.i	0x0; }
	{ cmp.ltu	p07,p06,0x3E,r14; nop.i	0x0; (p07) br.cond.spnt.few	4000000000075FF0; }

l4000000000075500:
	{ nop.m	0x0; ld1	r14,[r34],1; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000075120 }

l4000000000075520:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000075290; }

l4000000000075530:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x40,r14; nop.i	0x0; }
	{ (p06) addl	r18,62,r0; (p06) addl	r15,62,r0; (p06) br.cond.dpnt.few	4000000000075240; }

l4000000000075546:
	{ (p07) chk.a.clr	r62,3FFFFFFFFF275546; nop; Invalid; }

l400000000007554C:
	{ (p40) cmp.lt.unc	p63,p11,r127,r37; (p48) dep	r87,r99,r97,48,13; (p02) cmp4.ne.or.andcm	p00,p16,r3,r64 }

l4000000000075550:
	{ cmp4.eq	p06,p07,0x5F,r14; (p07) adds	r18,0x0,r14; (p06) addl	r15,63,r0; }

l400000000007555C:
	{ (p31) cmp4.eq.or.andcm	p00,p48,r0,r72; (p01) dep	r64,r4,r64,50,1; (p50) nop; }

l4000000000075560:
	{ (p07) adds	r15,0x0,r18; (p06) addl	r18,63,r0; br.cond.sptk.few	4000000000075240 }

l4000000000075566:
	{ Invalid; nop; break.i	0x80000; }

l400000000007556C:
	{ (p39) nop; cmp.lt	p00,p00,r32,r0; Invalid }

l4000000000075570:
	{ nop.m	0x0; ld8	r62,[r49]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r62; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000755B0; }

l4000000000075590:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r59; nop.m	0x0; nop.i	0x0 }

l40000000000755B0:
	{ adds	r14,0x0,r33; adds	r15,0x18,r33; adds	r16,0x10,r33 }
	{ st4	[r41],r32; st4	[r44],r39; cmp4.eq	p07,p06,0x0,r48; }
	{ st8	[r14],r8,8; st8	[r50],r15; adds	r15,0x0,r33; }
	{ st8	[r52],r14; nop.m	0x0; addl	r14,-20740,r1 }
	{ st8	[r51],r16; ld8	r16,[r15],8; nop.i	0x0; }
	{ nop.m	0x0; st8	[r43],r35; nop.i	0x0 }
	{ st8	[r54],r40; st8	[r53],r38; nop.i	0x0 }
	{ st8	[r45],r42; st8	[r14],r8,8; nop.i	0x0 }
	{ ld8	r16,[r15],8; st4	[r48],r37; nop.i	0x0; }
	{ st8	[r14],r8,8; ld8	r16,[r15],8; nop.i	0x0; }
	{ st8	[r14],r8,8; ld8	r15,[r15]; nop.i	0x0; }
	{ st8	[r15],r14; nop.i	0x0; (p07) br.cond.dptk.few	4000000000074DC0 }

l4000000000075670:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000074F20 }

l4000000000075680:
	{ addl	r32,7304,r1; addl	r33,1,r0; addl	r15,7300,r1; }
	{ ld4	r14,[r32]; st4	[r33],r32; nop.i	0x0; }
	{ st4	[r14],r15; nop.i	0x0; br.cond.sptk.few	4000000000075080 }

l40000000000756B0:
	{ adds	r62,0x0,r8; nop.i	0x0; br.call.sptk.many	b0,fn40000000000741C0; }
	{ adds	r14,0x0,r33; nop.m	0x0; adds	r15,0x10,r33 }
	{ adds	r33,0x18,r33; nop.m	0x0; adds	r1,0x0,r59; }
	{ st8	[r14],r8,8; st8	[r34],r15; adds	r15,0x10,r12; }
	{ st8	[r8],r14; ld8	r14,[r15]; nop.i	0x0; }
	{ st8	[r14],r33; nop.i	0x0; br.cond.sptk.few	40000000000753D0 }

l4000000000075710:
	{ adds	r14,0x1,r33; setf.sig	f6,r0; nop.i	0x0; }
	{ nop.m	0x0; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; sxt1	r15,r14 }
	{ cmp4.eq	p06,p07,0x0,r14; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000758F0; }

l4000000000075750:
	{ and	r15,0xFFFFFFFFFFFFFFDF,r15; cmp4.eq	p06,p07,0x58,r15; nop.i	0x0; }
	{ (p06) adds	r14,0x2,r33; (p07) adds	r34,0x1,r34; (p07) addl	r19,1,r0 }

l4000000000075766:
	{ Invalid; (p09) cmp.eq.or	p01,p08,0x0,r0; (p17) nop; }

l400000000007576C:
	{ nop; Invalid; (p01) br.cond.dpnt.many	400000000027579C }

l4000000000075770:
	{ (p07) addl	r17,8,r0; (p06) ld1	r14,[r14]; (p06) adds	r34,0x3,r33 }

l4000000000075776:
	{ (p07) chk.a.nc	r0,3FFFFFFFFF875856; (p17) addl	r3,24865,r0; (p49) nop; }

l400000000007577C:
	{ Invalid; Invalid; Invalid }

l4000000000075780:
	{ (p06) addl	r19,1,r0; nop.m	0x0; (p06) addl	r17,16,r0; }

l4000000000075786:
	{ adds	r0,0xFFFFFFFFFFFFE000,r1; (p08) mov.sptk	b0,r0,4000000000075B86; add	r0,r0,r32 }

l4000000000075790:
	{ nop.m	0x0; sxt1	r14,r14; zxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	4000000000075120 }

l40000000000757B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000075290 }

l40000000000757C0:
	{ addl	r32,7304,r1; addl	r33,2,r0; addl	r15,7300,r1; }
	{ ld4	r14,[r32]; st4	[r33],r32; nop.i	0x0; }
	{ st4	[r14],r15; nop.i	0x0; br.cond.sptk.few	4000000000075080 }

l40000000000757F0:
	{ adds	r63,0x0,r0; adds	r64,0x0,r0; br.call.sptk.many	b0,array_variable_name; }
	{ adds	r1,0x0,r59; nop.m	0x0; addl	r15,1,r0 }
	{ adds	r32,0x0,r8; adds	r62,0x0,r8; addl	r14,9044,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,err_unboundvar; }
	{ cmp.eq	p06,p07,0x0,r32; nop.m	0x0; adds	r62,0x0,r32 }
	{ adds	r1,0x0,r59; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000074EB0; }

l4000000000075860:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r59; br.cond.sptk.few	4000000000074EB0 }

l4000000000075880:
	{ nop.m	0x0; addl	r62,1,r0; br.call.sptk.many	b0,jump_to_top_level }

l4000000000075890:
	{ cmp4.eq	p06,p07,0x3C,r32; (p06) addl	r20,1,r0; nop.i	0x0; }

l400000000007589C:
	{ nop; (p02) cmp.lt	p00,p16,r0,r64; zxt1	r69,r3 }

l40000000000758A6:
	{ Invalid; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD39196; nop; nop }

l40000000000758C0:
	{ addl	r32,7304,r1; addl	r33,3,r0; addl	r15,7300,r1; }
	{ ld4	r14,[r32]; st4	[r33],r32; nop.i	0x0; }
	{ st4	[r14],r15; nop.i	0x0; br.cond.sptk.few	4000000000075080 }

l40000000000758F0:
	{ setf.sig	f6,r0; st1	[r20],r16; addl	r16,7308,r1 }
	{ nop.m	0x0; addl	r14,7304,r1; nop.i	0x0; }
	{ ld4	r15,[r14]; stf8	[r16],f6; addl	r16,6,r0; }
	{ st4	[r16],r14; nop.m	0x0; addl	r14,7300,r1; }
	{ st4	[r15],r14; nop.i	0x0; br.cond.sptk.few	40000000000752D0 }

l4000000000075940:
	{ cmp4.eq	p06,p07,0x3C,r16; (p06) addl	r14,1,r0; nop.i	0x0; }

l400000000007594C:
	{ cmp4.eq.and	p00,p43,r1,r0; (p01) shladd	r0,r0,0x1,r64; zxt1	r3,r3 }

l4000000000075956:
	{ Invalid; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD392A6; nop; (p32) nop }

l4000000000075970:
	{ ld1	r14,[r36]; addl	r32,7304,r1; addl	r15,7300,r1; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x3D,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000075A40; }

l40000000000759A0:
	{ ld4	r14,[r32]; addl	r33,9,r0; nop.i	0x0 }
	{ st4	[r33],r32; st4	[r14],r15; br.cond.sptk.few	4000000000075080 }

l40000000000759C0:
	{ cmp4.eq	p06,p07,0x3E,r16; (p06) addl	r14,1,r0; nop.i	0x0; }

l40000000000759CC:
	{ cmp4.eq.and	p00,p43,r1,r0; (p01) nop; zxt1	r99,r3 }

l40000000000759D6:
	{ Invalid; nop; break.b	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD39316; nop; (p32) nop }

l40000000000759F0:
	{ ld1	r14,[r36]; addl	r32,7304,r1; addl	r15,7300,r1; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x3D,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000075FA0; }

l4000000000075A20:
	{ ld4	r14,[r32]; addl	r33,10,r0; nop.i	0x0 }
	{ st4	[r33],r32; st4	[r14],r15; br.cond.sptk.few	4000000000075080 }

l4000000000075A40:
	{ addl	r14,7324,r1; nop.m	0x0; addl	r15,9,r0 }
	{ adds	r36,0x3,r33; nop.m	0x0; addl	r33,11,r0; }
	{ st4	[r15],r14; ld4	r14,[r32]; nop.i	0x0 }

l4000000000075A70:
	{ addl	r15,7300,r1; st4	[r33],r32; nop.i	0x0; }
	{ st4	[r14],r15; nop.i	0x0; br.cond.sptk.few	4000000000075080 }

l4000000000075A90:
	{ cmp4.eq	p06,p07,0x26,r16; nop.m	0x0; cmp4.eq	p08,p09,0x26,r32; }
	{ (p06) addl	r19,1,r0; nop.m	0x0; (p08) addl	r14,1,r0; }

l4000000000075AA6:
	{ Invalid; (p07) cmp4.eq.and	p01,p08,0x0,r0; (p49) nop }

l4000000000075AB0:
	{ (p07) adds	r19,0x0,r0; (p09) adds	r14,0x0,r0; and	r14,r14,r19; }

l4000000000075AB6:
	{ Invalid; (p07) nop; break.i	0x80000 }

l4000000000075ABC:
	{ (p07) invala; cmp.lt	p00,p00,r32,r0; mov	pr,r99,0xE680; }
	{ (p03) nop; (p04) nop; Invalid }

l4000000000075AD0:
	{ addl	r32,7304,r1; addl	r33,7,r0; addl	r15,7300,r1; }
	{ ld4	r14,[r32]; st4	[r33],r32; nop.i	0x0; }
	{ st4	[r14],r15; nop.i	0x0; br.cond.sptk.few	4000000000075080 }

l4000000000075B00:
	{ addl	r63,908,r1; addl	r64,5,r0; adds	r62,0x0,r0; }
	{ ld8	r63,[r63]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r59; adds	r62,0x0,r8; br.call.sptk.many	b0,fn4000000000071E00 }

l4000000000075B30:
	{ cmp4.eq	p06,p07,0x7C,r16; nop.m	0x0; cmp4.eq	p08,p09,0x7C,r32; }
	{ (p06) addl	r19,1,r0; nop.m	0x0; (p08) addl	r14,1,r0; }

l4000000000075B46:
	{ Invalid; (p07) cmp4.eq.and	p01,p08,0x0,r0; (p49) nop }

l4000000000075B50:
	{ (p07) adds	r19,0x0,r0; (p09) adds	r14,0x0,r0; and	r14,r14,r19; }

l4000000000075B56:
	{ Invalid; (p07) nop; break.i	0x80000 }

l4000000000075B5C:
	{ Invalid; cmp.lt	p00,p00,r32,r0; mov	pr,r99,0xE680; }
	{ (p04) cmp.lt	p00,p09,r0,r33; czx1.r	r10,r97; break.i	0x1000 }

l4000000000075B70:
	{ cmp4.eq	p06,p07,0x2A,r16; nop.m	0x0; cmp4.eq	p08,p09,0x2A,r32; }
	{ (p06) addl	r19,1,r0; nop.m	0x0; (p08) addl	r14,1,r0; }

l4000000000075B86:
	{ Invalid; (p07) cmp4.eq.and	p01,p08,0x0,r0; (p49) nop }

l4000000000075B90:
	{ (p07) adds	r19,0x0,r0; (p09) adds	r14,0x0,r0; and	r14,r14,r19; }

l4000000000075B96:
	{ Invalid; (p07) nop; break.i	0x80000 }

l4000000000075B9C:
	{ (p07) invala; cmp.lt	p00,p00,r32,r0; mov	pr,r99,0xE680; }
	{ (p03) nop; (p04) nop; Invalid }

l4000000000075BB0:
	{ addl	r32,7304,r1; addl	r33,13,r0; addl	r15,7300,r1; }
	{ ld4	r14,[r32]; st4	[r33],r32; nop.i	0x0; }
	{ st4	[r14],r15; nop.i	0x0; br.cond.sptk.few	4000000000075080 }

l4000000000075BE0:
	{ addl	r32,7304,r1; addl	r33,8,r0; addl	r15,7300,r1; }
	{ ld4	r14,[r32]; st4	[r33],r32; nop.i	0x0; }
	{ st4	[r14],r15; nop.i	0x0; br.cond.sptk.few	4000000000075080 }

l4000000000075C10:
	{ cmp4.eq	p08,p09,0x2D,r32; (p08) cmp.eq.unc	p06,p00,r0,r0; (p09) cmp.eq.unc	p07,p00,r0,r0; }

l4000000000075C1C:
	{ Invalid; cmp.lt	p00,p00,r32,r0; (p48) mov	pr,r104,0xE714 }

l4000000000075C20:
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x2B,r32; (p07) br.cond.dptk.few	4000000000075C40; }

l4000000000075C30:
	{ nop.m	0x0; cmp4.eq	p07,p06,r32,r16; (p07) br.cond.dpnt.few	4000000000075CA0; }

l4000000000075C40:
	{ adds	r33,0x0,r32; cmp4.eq	p06,p07,0x0,r17; (p07) br.cond.dpnt.few	4000000000075F00 }

l4000000000075C50:
	{ adds	r62,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C7A0; }
	{ adds	r1,0x0,r59; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	4000000000075E50; }

l4000000000075C70:
	{ addl	r32,7304,r1; addl	r15,7300,r1; adds	r36,0x0,r34; }
	{ ld4	r14,[r32]; st4	[r33],r32; nop.i	0x0; }
	{ st4	[r14],r15; nop.i	0x0; br.cond.sptk.few	4000000000075080 }

l4000000000075CA0:
	{ addl	r32,7304,r1; ld4	r14,[r32]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x5,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000075E20; }

l4000000000075CC0:
	{ ld1	r17,[r36]; nop.m	0x0; sxt1	r17,r17; }
	{ cmp4.eq	p07,p06,0x0,r17; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000075DD0; }

l4000000000075CE0:
	{ (p06) andcm	r19,0xFFFFFFFFFFFFFFFF,r36; nop.i	0x0; (p06) mov.i	LC,r19 }

l4000000000075CE6:
	{ chk.a.nc	r0,3FFFFFFFFF0764E6; nop; break.i	0x80000 }

l4000000000075CF0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x20,r17; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x9,r17; (p06) br.cond.dptk.few	4000000000075D20; }

l4000000000075D10:
	{ nop.m	0x0; cmp4.eq	p06,p07,0xA,r17; (p07) br.cond.dpnt.few	4000000000075D30 }

l4000000000075D20:
	{ nop.m	0x0; adds	r18,0x1,r18; br.cloop.sptk.few	4000000000075DB0; }

l4000000000075D30:
	{ ld1	r17,[r18]; nop.m	0x0; sxt1	r17,r17; }
	{ nop.m	0x0; zxt1	r18,r17; shladd	r15,r18,0x1,r15; }
	{ nop.m	0x0; ld2	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r15,0xA; (p06) br.cond.dptk.few	4000000000075DF0; }

l4000000000075D70:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x5F,r17; (p06) br.cond.dpnt.few	4000000000075DF0 }

l4000000000075D80:
	{ adds	r33,0x0,r16; addl	r15,7300,r1; adds	r36,0x0,r34; }
	{ nop.m	0x0; st4	[r33],r32; nop.i	0x0 }
	{ st4	[r14],r15; nop.m	0x0; br.cond.sptk.few	4000000000075080 }

l4000000000075DB0:
	{ ld1	r17,[r18]; nop.m	0x0; sxt1	r17,r17; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r17; (p06) br.cond.dptk.few	4000000000075CF0 }

l4000000000075DD0:
	{ nop.m	0x0; ld2	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r15,0xA; (p07) br.cond.dptk.few	4000000000075D80; }

l4000000000075DF0:
	{ cmp4.eq	p06,p07,0x2D,r16; addl	r15,7300,r1; (p06) addl	r33,15,r0 }

l4000000000075E00:
	{ st4	[r14],r15; (p07) addl	r33,14,r0; nop.i	0x0; }

l4000000000075E0C:
	{ invala; Invalid; break.i	0x1000 }
	{ (p19) nop; zxt4	r4,r0; Invalid }

l4000000000075E20:
	{ (p08) addl	r33,17,r0; nop.m	0x0; addl	r15,7300,r1; }

l4000000000075E26:
	{ add	r0,r0,r1; (p07) dep.z	r4,0x1,6,9; (p18) nop }

l4000000000075E36:
	{ mf.a; nop; nop }
	{ break.m	0x4000; nop; (p32) nop }

l4000000000075E50:
	{ addl	r14,7304,r1; ld4	r32,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r32; adds	r62,0x0,r32; (p06) br.cond.spnt.few	4000000000075ED0; }

l4000000000075E70:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C7A0; }
	{ cmp4.eq	p07,p06,0x0,r8; adds	r1,0x0,r59; (p06) br.cond.spnt.few	4000000000075ED0; }

l4000000000075E90:
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x11,r32; (p06) br.cond.dptk.few	4000000000075F70 }

l4000000000075EA0:
	{ addl	r15,1,r0; sxt4	r32,r32; addl	r14,262046,r0; }
	{ nop.m	0x0; shl	r15,r15,r32; and	r14,r14,r15; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	4000000000075F70 }

l4000000000075ED0:
	{ addl	r63,812,r1; addl	r64,5,r0; adds	r62,0x0,r0; }
	{ ld8	r63,[r63]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r59; adds	r62,0x0,r8; br.call.sptk.many	b0,fn4000000000071E00; }

l4000000000075F00:
	{ addl	r62,916,r1; nop.m	0x0; adds	r63,0x0,r32; }
	{ ld8	r62,[r62]; nop.i	0x0; br.call.sptk.many	b0,mbschr; }
	{ adds	r1,0x0,r59; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	4000000000075C50; }

l4000000000075F30:
	{ addl	r14,7324,r1; addl	r32,7304,r1; addl	r15,7300,r1; }
	{ st4	[r33],r14; ld4	r14,[r32]; addl	r33,11,r0; }
	{ nop.m	0x0; st4	[r33],r32; nop.i	0x0 }
	{ st4	[r14],r15; nop.m	0x0; br.cond.sptk.few	4000000000075080 }

l4000000000075F70:
	{ addl	r63,924,r1; addl	r64,5,r0; adds	r62,0x0,r0; }
	{ ld8	r63,[r63]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r59; adds	r62,0x0,r8; br.call.sptk.many	b0,fn4000000000071E00; }

l4000000000075FA0:
	{ addl	r14,7324,r1; addl	r15,10,r0; adds	r36,0x3,r33 }
	{ addl	r33,11,r0; st4	[r15],r14; nop.i	0x0 }
	{ ld4	r14,[r32]; nop.m	0x0; br.cond.sptk.few	4000000000075A70; }

l4000000000075FD0:
	{ addl	r14,6100,r1; nop.m	0x0; nop.i	0x0; }
	{ ld8	r62,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000071E00; }

l4000000000075FF0:
	{ addl	r63,900,r1; addl	r64,5,r0; adds	r62,0x0,r0; }
	{ ld8	r63,[r63]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r59; adds	r62,0x0,r8; br.call.sptk.many	b0,fn4000000000071E00; }

l4000000000076020:
	{ addl	r63,892,r1; addl	r64,5,r0; adds	r62,0x0,r0; }
	{ ld8	r63,[r63]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r59; adds	r62,0x0,r8; br.call.sptk.many	b0,fn4000000000071E00; }
	{ nop.m	0x0; break.f	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

;; evalexp: 4000000000076080
;;   Called from:
;;     4000000000063CEC (in make_variable_value)
;;     4000000000063D3C (in make_variable_value)
;;     400000000006448C (in make_variable_value)
;;     400000000007607C (in fn4000000000074880)
;;     40000000000B58CC (in binary_test)
;;     40000000000B59EC (in binary_test)
;;     40000000000BFF8C (in array_expand_index)
;;     40000000001008BC (in let_builtin)
;;     400000000010093C (in let_builtin)
evalexp proc
	{ alloc	r36,ar.pfs,0x8,0x0,0x5; adds	r16,0x8,r12; nop.i	0x0 }
	{ adds	r12,0xFFFFFFFFFFFFFD20,r12; addl	r14,7252,r1; addl	r34,14196,r1; }
	{ st8.spill	[r1],r16; nop.m	0x0; adds	r15,0x2D0,r12 }
	{ st4	[r0],r14; adds	r14,0x2D8,r12; adds	r37,0x10,r12; }
	{ nop.m	0x0; mov	r35,b3; adds	r38,0x0,r34 }
	{ addl	r39,704,r0; st8	[r32],r14; nop.b	0x0; }
	{ st8	[r33],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ adds	r1,0x2E8,r12; adds	r37,0x0,r34; addl	r38,1,r0; }
	{ ld8	r1,[r1]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BD60; }
	{ adds	r1,0x2E8,r12; nop.m	0x0; cmp4.eq	p06,p07,0x0,r8; }
	{ ld8	r1,[r1]; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000076260; }

l4000000000076130:
	{ addl	r14,7260,r1; ld8	r37,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r37; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000076180; }

l4000000000076150:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x2E8,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0; }

l4000000000076180:
	{ addl	r14,7268,r1; ld8	r37,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r37; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000761D0; }

l40000000000761A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x2E8,r12; nop.i	0x0; }
	{ ld8	r1,[r1]; nop.m	0x0; nop.i	0x0; }

l40000000000761D0:
	{ addl	r14,7268,r1; st8	[r0],r14; addl	r14,7260,r1; }
	{ st8	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,fn4000000000071C80; }
	{ adds	r14,0x2D0,r12; nop.m	0x0; adds	r1,0x2E8,r12; }
	{ ld8	r14,[r14]; ld8	r1,[r1]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; nop.i	0x0; }
	{ (p06) adds	r34,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000076240; }

l4000000000076226:
	{ chk.a.nc	r0,3FFFFFFFFF076A26; nop; break.i	0x80000 }

l4000000000076230:
	{ nop.m	0x0; st4	[r0],r14; adds	r34,0x0,r0; }

l4000000000076240:
	{ adds	r8,0x0,r34; mov.i	ar.pfs,r36; mov.spnt	b0,r35,4000000000076240 }
	{ nop.m	0x0; adds	r12,0x2E0,r12; br.ret	b0; }

l4000000000076260:
	{ nop.m	0x0; adds	r14,0x2D8,r12; nop.i	0x0; }
	{ ld8	r37,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn40000000000741C0; }
	{ adds	r15,0x2D0,r12; adds	r1,0x2E8,r12; nop.i	0x0 }
	{ adds	r34,0x0,r8; adds	r38,0x10,r12; addl	r39,704,r0; }
	{ ld8	r15,[r15]; ld8	r1,[r1]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r15; nop.m	0x0; addl	r37,14196,r1; }
	{ (p07) addl	r14,1,r0; nop.m	0x0; nop.i	0x0; }

l40000000000762C6:
	{ break.m	0x4000; cmp4.eq	p00,p00,r0,r1; (p01) nop }

l40000000000762D6:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; Invalid; (p16) nop }
	{ break.m	0xAA024; nop; break.i	0x80000 }
	{ Invalid; (p34) break.i	0x84000; (p32) break.i	0x80001 }
4000000000076310 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
4000000000076320 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
4000000000076330 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; find_flag: 4000000000076340
;;   Called from:
;;     4000000000108F4C (in minus_o_option_value)
;;     400000000010916C (in list_minus_o_opts)
;;     400000000010993C (in set_shellopts)
find_flag proc
	{ cmp4.eq	p06,p07,0x61,r32; adds	r16,0x0,r0; (p06) br.cond.dpnt.few	4000000000076410; }

l4000000000076350:
	{ nop.m	0x0; (p07) addl	r14,5812,r1; nop.i	0x0; }

l400000000007635C:
	{ cmp4.eq.and	p00,p41,r1,r0; Invalid; break.i	0x1000 }

l4000000000076366:
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ break.m	0x4000; nop; (p48) nop }

l4000000000076380:
	{ ld1	r15,[r14]; adds	r16,0x1,r16; adds	r14,0x10,r14; }

l4000000000076382:
	{ (p32) nop; mov	pr,r64,0x108; (p34) break.i	0xC2003 }
	{ Invalid; (p48) break.i	0x283; nop }
	{ (p48) break.m	0x730C3; cmp.lt	p32,p01,r0,r96; Invalid }

l40000000000763B0:
	{ nop.m	0x0; cmp4.eq	p07,p06,r32,r15; (p06) br.cond.dptk.few	4000000000076380 }

l40000000000763C0:
	{ addl	r14,-25372,r1; nop.m	0x0; sxt4	r16,r16; }
	{ nop.m	0x0; adds	r14,0x8,r14; nop.i	0x0; }
	{ nop.m	0x0; shladd	r16,r16,0x4,r14; nop.i	0x0; }
	{ ld8	r8,[r16]; nop.i	0x0; br.ret	b0; }

l4000000000076400:
	{ nop.m	0x0; adds	r8,0x0,r0; br.ret	b0 }

l4000000000076410:
	{ addl	r14,-25372,r1; nop.m	0x0; adds	r16,0x0,r0; }
	{ nop.m	0x0; sxt4	r16,r16; adds	r14,0x8,r14; }
	{ nop.m	0x0; shladd	r16,r16,0x4,r14; nop.i	0x0; }
	{ ld8	r8,[r16]; nop.i	0x0; br.ret	b0; }
4000000000076450 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000076460 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000076470 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; change_flag: 4000000000076480
;;   Called from:
;;     400000000001E6BC (in main)
;;     4000000000047D5C (in indirection_level_string)
;;     4000000000047D8C (in indirection_level_string)
;;     4000000000050DFC (in shell_execve)
;;     400000000007F80C (in initialize_job_control)
;;     40000000001094CC (in set_minus_o_option)
;;     400000000010A0EC (in set_builtin)
;;     400000000010A49C (in set_builtin)
;;     400000000010A4BC (in set_builtin)
change_flag proc
	{ alloc	r36,ar.pfs,0x7,0x0,0x6; addl	r14,7352,r1; mov	r35,b3 }
	{ adds	r37,0x0,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	40000000000764D0; }

l40000000000764B0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x72,r32; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ne.or.andcm	p07,p06,0x2B,r33; (p06) br.cond.dpnt.few	4000000000076620; }

l40000000000764D0:
	{ cmp4.eq	p06,p07,0x61,r32; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000767D0; }

l40000000000764E0:
	{ (p07) addl	r14,5820,r1; nop.m	0x0; (p07) adds	r16,0x0,r0; }

l40000000000764E6:
	{ chk.a.nc	f0,3FFFFFFFFF076CE6; (p08) cmp4.eq.or	p00,p02,r0,r0; (p33) nop }

l40000000000764F0:
	{ (p07) ld8	r14,[r14]; nop.m	0x0; nop.i	0x0; }

l40000000000764F6:
	{ break.m	0x4000; nop; (p48) nop }

l4000000000076500:
	{ ld1	r15,[r14]; adds	r16,0x1,r16; adds	r14,0x10,r14; }

l4000000000076502:
	{ (p32) nop; mov	pr,r64,0x108; (p34) break.i	0xC2003 }
	{ Invalid; (p48) break.i	0x283; nop }
	{ (p48) break.m	0x730C3; nop.i	0x80020; Invalid }

l4000000000076530:
	{ nop.m	0x0; cmp4.eq	p07,p06,r15,r32; (p06) br.cond.dptk.few	4000000000076500 }

l4000000000076540:
	{ addl	r14,-25372,r1; sxt4	r16,r16; adds	r32,0xFFFFFFFFFFFFFFB8,r32; }
	{ nop.m	0x0; adds	r14,0x8,r14; nop.i	0x0; }
	{ shladd	r16,r16,0x4,r14; ld8	r14,[r16]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.spnt.few	4000000000076620; }

l4000000000076580:
	{ cmp4.eq	p07,p06,0x2B,r33; (p06) cmp.eq.unc	p08,p00,r0,r0; (p07) cmp.eq.unc	p09,p00,r0,r0; }

l400000000007658C:
	{ nop; (p17) flushrs; Invalid; }

l4000000000076590:
	{ cmp4.eq.or.andcm	p09,p08,0x2D,r33; nop.i	0x0; (p08) br.cond.dpnt.few	4000000000076620; }

l40000000000765A0:
	{ cmp4.eq	p08,p09,0x2D,r33; ld4	r34,[r14]; nop.i	0x0; }
	{ nop.m	0x0; (p08) addl	r33,1,r0; nop.i	0x0; }

l40000000000765BC:
	{ nop; zxt1	r0,r64; (p33) cmp.lt	p10,p26,r40,r98 }

l40000000000765C6:
	{ Invalid; (p19) nop; break.i	0x80000 }
	{ nop; nop; (p32) nop }

l40000000000765E0:
	{ addl	r14,-4412,r1; nop.m	0x0; addp4	r32,r32,r0; }
	{ ld8	r14,[r14]; shladd	r32,r32,0x3,r14; nop.i	0x0; }
	{ ld8	r14,[r32]; add	r32,r32,r14; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r32,4000000000076610; br.cond	b6; }

l4000000000076620:
	{ addl	r34,-1,r0; nop.m	0x0; nop.i	0x0; }

l4000000000076630:
	{ adds	r8,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,4000000000076640; br.ret	b0 }
4000000000076650 10 00 00 00 01 00 60 00 84 0E 73 03 E0 FF FF 4A ......`...s....J
4000000000076660 0B 70 30 02 33 24 00 00 00 02 00 00 00 00 04 00 .p0.3$..........
4000000000076670 09 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
4000000000076680 10 00 00 00 01 00 60 00 38 0E 73 03 B0 FF FF 4A ......`.8.s....J
4000000000076690 0B 70 30 03 32 24 00 00 00 02 00 00 00 00 04 00 .p0.2$..........
40000000000766A0 11 30 01 1C 18 10 00 00 00 02 00 00 68 C0 FA 58 .0..........h..X
40000000000766B0 09 40 00 44 00 21 10 00 94 00 42 00 40 02 AA 00 .@.D.!....B.@...
40000000000766C0 10 00 00 00 01 00 00 18 05 80 03 80 08 00 84 00 ................
40000000000766D0 11 00 00 00 01 00 00 00 00 02 00 03 60 FF FF 4A ............`..J
40000000000766E0 11 00 00 00 01 00 00 00 00 02 00 00 E8 C1 FA 58 ...............X
40000000000766F0 09 40 00 44 00 21 10 00 94 00 42 00 40 02 AA 00 .@.D.!....B.@...
4000000000076700 10 00 00 00 01 00 00 18 05 80 03 80 08 00 84 00 ................
4000000000076710 09 70 C0 03 32 24 80 00 88 00 42 00 40 02 AA 00 .p..2$....B.@...
4000000000076720 09 00 00 00 01 00 00 00 00 02 00 00 30 0A 00 07 ............0...
4000000000076730 0B 70 00 1C 10 10 60 00 38 0E 73 00 00 00 04 00 .p....`.8.s.....
4000000000076740 09 00 00 00 01 C0 E1 00 07 72 48 00 00 00 04 00 .........rH.....
4000000000076750 F1 00 00 1C 90 11 00 00 00 02 00 80 08 00 84 00 ................
4000000000076760 11 00 00 00 01 00 00 00 00 02 00 00 28 E9 00 50 ............(..P
4000000000076770 09 40 00 44 00 21 10 00 94 00 42 00 40 02 AA 00 .@.D.!....B.@...
4000000000076780 10 00 00 00 01 00 00 18 05 80 03 80 08 00 84 00 ................
4000000000076790 11 00 00 00 01 00 60 00 84 0E 73 03 A0 FE FF 4A ......`...s....J
40000000000767A0 11 00 00 00 01 00 00 00 00 02 00 00 28 11 05 50 ............(..P
40000000000767B0 09 40 00 44 00 21 10 00 94 00 42 00 40 02 AA 00 .@.D.!....B.@...
40000000000767C0 10 00 00 00 01 00 00 18 05 80 03 80 08 00 84 00 ................

l40000000000767D0:
	{ nop.m	0x0; adds	r16,0x0,r0; br.cond.sptk.few	4000000000076540; }
40000000000767E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000767F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; which_set_flags: 4000000000076800
which_set_flags proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; addl	r32,8916,r1; nop.b	0x0 }
	{ addl	r33,8868,r1; adds	r36,0x0,r1; mov	r34,b2; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4	r14,[r32]; ld4	r15,[r33]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r37,r14; sxt4	r14,r15; }
	{ nop.m	0x0; add	r37,r37,r14; nop.i	0x0; }
	{ adds	r37,0x18,r37; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r36; adds	r20,0x0,r8; addl	r15,97,r0 }
	{ adds	r16,0x0,r0; addl	r14,5828,r1; nop.i	0x0; }
	{ ld8	r14,[r14]; nop.m	0x0; nop.i	0x0; }

l40000000000768A0:
	{ ld8	r18,[r14]; sxt4	r19,r16; adds	r14,0x10,r14; }
	{ add	r19,r20,r19; nop.m	0x0; adds	r17,0xFFFFFFFFFFFFFFF8,r14; }
	{ nop.m	0x0; ld4	r18,[r18]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r18; (p07) st1	[r15],r19; (p07) adds	r16,0x1,r16; }

l40000000000768DC:
	{ cmp.eq	p16,p11,r0,r66; (p01) rfi; Invalid }

l40000000000768E0:
	{ ld1	r15,[r17]; nop.m	0x0; sxt1	r15,r15; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	40000000000768A0 }

l4000000000076900:
	{ ld4	r14,[r33]; adds	r8,0x0,r20; mov.i	ar.pfs,r35 }
	{ nop.m	0x0; sxt4	r15,r16; nop.b	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; add	r15,r20,r15; mov.spnt	b0,r34,4000000000076920; }
	{ (p07) addl	r14,99,r0; nop.m	0x0; (p07) adds	r16,0x1,r16; }

l4000000000076936:
	{ chk.a.nc	f0,3FFFFFFFFF077136; (p08) cmp4.eq.or	p01,p02,r16,r0; (p01) nop }

l4000000000076940:
	{ (p07) st1	[r14],r15; nop.m	0x0; sxt4	r15,r16; }

l4000000000076946:
	{ add	r0,r0,r1; Invalid; (p32) nop }
	{ Invalid; (p03) cmp.eq.and	p00,p51,0xE,r7; Invalid }

l4000000000076966:
	{ Invalid; (p08) cmp4.ltu	p00,p00,0x10,r22; (p01) nop; }

l400000000007696C:
	{ Invalid; (p32) addp4	r99,r3,r96; zxt1	r5,r0 }

l4000000000076976:
	{ Invalid; nop; nop }
	{ break.m	0x4000; (p34) nop; break.i	0x80000 }
4000000000076990 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000769A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000769B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; reset_shell_flags: 40000000000769C0
;;   Called from:
;;     400000000005061C (in shell_execve)
reset_shell_flags proc
	{ addl	r15,7400,r1; nop.m	0x0; addl	r14,1,r0; }
	{ st4	[r0],r15; nop.m	0x0; addl	r15,7404,r1; }
	{ st4	[r0],r15; nop.m	0x0; addl	r15,7412,r1; }
	{ st4	[r0],r15; nop.m	0x0; addl	r15,7388,r1; }
	{ st4	[r0],r15; nop.m	0x0; addl	r15,7392,r1; }
	{ st4	[r0],r15; nop.m	0x0; addl	r15,7396,r1; }
	{ st4	[r0],r15; nop.m	0x0; addl	r15,7376,r1; }
	{ st4	[r0],r15; nop.m	0x0; addl	r15,7380,r1; }
	{ st4	[r0],r15; nop.m	0x0; addl	r15,7384,r1; }
	{ st4	[r0],r15; nop.m	0x0; addl	r15,7364,r1; }
	{ st4	[r0],r15; nop.m	0x0; addl	r15,7368,r1; }
	{ st4	[r0],r15; nop.m	0x0; addl	r15,7372,r1; }
	{ st4	[r0],r15; nop.m	0x0; addl	r15,7332,r1; }
	{ st4	[r0],r15; nop.m	0x0; addl	r15,7344,r1; }
	{ st4	[r0],r15; nop.m	0x0; addl	r15,7356,r1; }
	{ st4	[r0],r15; nop.m	0x0; addl	r15,7360,r1; }
	{ st4	[r0],r15; nop.m	0x0; addl	r15,5856,r1; }
	{ st4	[r14],r15; nop.m	0x0; addl	r15,5864,r1; }
	{ st4	[r14],r15; nop.m	0x0; addl	r15,7408,r1; }
	{ st4	[r0],r15; nop.m	0x0; addl	r15,5860,r1; }
	{ st4	[r14],r15; nop.m	0x0; addl	r15,5852,r1; }
	{ st4	[r14],r15; nop.m	0x0; addl	r14,7352,r1; }
	{ st4	[r0],r14; nop.i	0x0; br.ret	b0; }
4000000000076B30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; initialize_flags: 4000000000076B40
initialize_flags proc
	{ addl	r14,5836,r1; addl	r15,97,r0; adds	r16,0x0,r0; }
	{ ld8	r17,[r14]; addl	r14,5844,r1; nop.i	0x0; }
	{ ld8	r14,[r14]; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000076B80:
	{ adds	r14,0x10,r14; st1	[r17],r1,1; adds	r16,0x1,r16; }
	{ adds	r15,0xFFFFFFFFFFFFFFF0,r14; ld1	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	4000000000076B80 }

l4000000000076BC0:
	{ adds	r17,0x1,r16; nop.m	0x0; adds	r15,0x2,r16 }
	{ addl	r14,-20708,r1; nop.m	0x0; adds	r16,0x3,r16; }
	{ nop.m	0x0; sxt4	r16,r16; sxt4	r17,r17; }
	{ nop.m	0x0; sxt4	r15,r15; add	r17,r14,r17; }
	{ add	r15,r14,r15; add	r14,r14,r16; addl	r16,111,r0; }
	{ st1	[r16],r17; addl	r16,59,r0; nop.i	0x0 }
	{ st1	[r16],r15; st1	[r0],r14; br.ret	b0; }
4000000000076C30 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; fn4000000000076C40: 4000000000076C40
;;   Called from:
;;     4000000000076EBC (in fn4000000000076DC0)
;;     400000000007C47C (in get_job_by_pid)
;;     400000000007C52C (in get_job_by_pid)
;;     400000000007C61C (in describe_pid)
;;     400000000008081C (in wait_for)
;;     40000000000814BC (in wait_for_single_pid)
fn4000000000076C40 proc
	{ addl	r14,-20676,r1; adds	r8,0x0,r0; addl	r19,255,r0 }
	{ cmp4.eq	p08,p09,0x0,r33; nop.m	0x0; nop.i	0x0; }
	{ adds	r14,0x1C,r14; ld4	r20,[r14]; addl	r14,7444,r1; }
	{ nop.m	0x0; cmp4.lt	p07,p06,0x0,r20; (p06) br.cond.dpnt.few	4000000000076D40; }

l4000000000076C80:
	{ ld8	r18,[r14]; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000076CA0:
	{ nop.m	0x0; ld8	r14,[r18],8; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; adds	r14,0x8,r14; (p06) br.cond.dpnt.few	4000000000076D20; }

l4000000000076CC0:
	{ ld8	r16,[r14]; nop.i	0x0; adds	r14,0x0,r16; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000076CE0:
	{ adds	r15,0x8,r14; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r32,r15; (p07) br.cond.dpnt.few	4000000000076D50 }

l4000000000076D00:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r14,r16; (p06) br.cond.dptk.few	4000000000076CE0 }

l4000000000076D20:
	{ nop.m	0x0; adds	r8,0x1,r8; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r20,r8; (p06) br.cond.dptk.few	4000000000076CA0 }

l4000000000076D40:
	{ nop.m	0x0; addl	r8,-1,r0; br.ret	b0 }

l4000000000076D50:
	{ adds	r15,0x10,r14; adds	r17,0xC,r14; (p08) br.cond.dpnt.few	4000000000076DA0; }

l4000000000076D60:
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x1,r15; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000076DA0; }

l4000000000076D80:
	{ ld4	r15,[r17]; and	r15,r19,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x7F,r15; (p06) br.cond.dptk.few	4000000000076D00; }

l4000000000076DA0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r34; nop.i	0x0; }
	{ (p07) st8	[r14],r34; nop.i	0x0; br.ret	b0; }

l4000000000076DB6:
	{ break.m	0x4000; (p34) nop; Invalid }

;; fn4000000000076DC0: 4000000000076DC0
;;   Called from:
;;     400000000007CDAC (in kill_pid)
;;     400000000008001C (in wait_for)
;;     40000000000813DC (in wait_for_single_pid)
fn4000000000076DC0 proc
	{ alloc	r36,ar.pfs,0x9,0x0,0x6; adds	r12,0xFFFFFFFFFFFFFFF0,r12; addl	r14,7428,r1 }
	{ cmp.eq	p06,p07,0x0,r34; cmp4.eq	p08,p09,0x0,r33; adds	r37,0x0,r1; }
	{ ld8	r15,[r14]; (p07) addl	r14,-1,r0; nop.b	0x0 }

l4000000000076DEC:
	{ nop; zxt4	r31,r0; nop }
	{ Invalid; nop }

l4000000000076E06:
	{ add	r0,r0,r1; (p03) nop; nop }
	{ chk.a.nc	f0,3FFFFFFFFF077616; nop; add	r0,r0,r32 }

l4000000000076E20:
	{ nop.m	0x0; (p06) adds	r14,0x10,r12; nop.i	0x0; }

l4000000000076E2C:
	{ Invalid; Invalid; break.i	0x1000 }

l4000000000076E36:
	{ break.m	0x4000; nop; (p32) nop }

l4000000000076E40:
	{ adds	r14,0x8,r8; ld4	r14,[r14]; nop.i	0x0; }

l4000000000076E42:
	{ Invalid; (p32) break.i	0x20203; nop }
	{ (p36) break.m	0x710C3; cmp.eq	p32,p01,r0,r96; Invalid }

l4000000000076E60:
	{ nop.m	0x0; ld8	r8,[r8]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r8,r15; (p06) br.cond.dptk.few	4000000000076E40 }

l4000000000076E80:
	{ nop.m	0x0; adds	r14,0x10,r12; nop.i	0x0; }
	{ st8	[r15],r14; nop.m	0x0; nop.i	0x0 }

l4000000000076EA0:
	{ adds	r38,0x0,r32; nop.m	0x0; adds	r39,0x0,r33 }
	{ adds	r40,0x10,r12; nop.m	0x0; br.call.sptk.many	b0,fn4000000000076C40; }
	{ cmp.eq	p07,p06,0x0,r34; nop.m	0x0; adds	r1,0x0,r37; }
	{ (p06) st4	[r8],r34; cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r8; sxt4	r8,r8; }

l4000000000076ED6:
	{ Invalid; (p04) cmp4.ltu	p00,p00,r8,r22; (p33) nop }

l4000000000076EE6:
	{ chk.a.nc	r0,3FFFFFFFFF0776E6; (p04) cmp4.eq.or	p00,p02,0x0,r0; (p33) cmp.ltu	p03,p06,r64,r3 }

l4000000000076EF0:
	{ (p07) ld8	r14,[r14]; (p07) shladd	r8,r8,0x3,r14; nop.i	0x0; }

l4000000000076EF6:
	{ Invalid; cmp4.lt	p00,p00,0x0,r1; (p33) nop; }

l4000000000076EFC:
	{ cmp4.eq.and	p00,p35,r1,r0; Invalid; cmp4.eq.and	p00,p32,r32,r0 }

l4000000000076F06:
	{ chk.a.nc	f0,3FFFFFFFFF077706; (p07) cmp.eq.or	p08,p02,r14,r0; (p01) nop }

l4000000000076F10:
	{ (p07) ld8	r8,[r14]; nop.m	0x0; nop.i	0x0 }

l4000000000076F16:
	{ break.m	0x4000; Invalid; break.i	0x80000 }

l4000000000076F20:
	{ nop.m	0x0; mov.i	ar.pfs,r36; mov.spnt	b0,r35,4000000000076F20 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000076F40:
	{ adds	r14,0x10,r8; adds	r16,0xC,r8; (p08) br.cond.dpnt.few	4000000000076F20; }

l4000000000076F50:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000076F20; }

l4000000000076F70:
	{ ld4	r14,[r16]; and	r14,r17,r14; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x7F,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000076F20; }

l4000000000076F90:
	{ nop.m	0x0; ld8	r8,[r8]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r8,r15; (p06) br.cond.dptk.few	4000000000076E40 }

l4000000000076FB0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000076E80; }

;; fn4000000000076FC0: 4000000000076FC0
;;   Called from:
;;     400000000008035C (in wait_for)
;;     4000000000080B9C (in wait_for)
fn4000000000076FC0 proc
	{ addl	r14,7444,r1; sxt4	r32,r32; addl	r18,255,r0; }
	{ ld8	r14,[r14]; shladd	r14,r32,0x3,r14; nop.i	0x0; }
	{ ld8	r14,[r14]; adds	r14,0x8,r14; nop.i	0x0; }
	{ ld8	r17,[r14]; nop.i	0x0; adds	r14,0x0,r17; }

l4000000000077000:
	{ nop.m	0x0; adds	r15,0xC,r14; nop.i	0x0; }
	{ ld4	r8,[r15]; and	r15,0x7F,r8; and	r16,r18,r8; }
	{ adds	r15,0x1,r15; cmp4.eq	p08,p09,0x7F,r16; extr.u	r15,r15,1,7; }
	{ cmp4.lt	p07,p06,0x0,r15; nop.i	0x0; (p07) br.ret	b0; }

l4000000000077040:
	{ nop.m	0x0; nop.i	0x0; (p08) br.ret	b0; }

l4000000000077050:
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r14,r17; (p06) br.cond.dptk.few	4000000000077000 }

l4000000000077070:
	{ nop.m	0x0; nop.i	0x0; br.ret	b0; }

;; fn4000000000077080: 4000000000077080
;;   Called from:
;;     400000000007D14C (in kill_pid)
;;     400000000008207C (in start_job)
;;     40000000000823AC (in start_job)
fn4000000000077080 proc
	{ addl	r14,7444,r1; sxt4	r32,r32; addl	r17,255,r0 }
	{ addl	r18,1,r0; ld8	r14,[r14]; nop.i	0x0; }
	{ shladd	r14,r32,0x3,r14; ld8	r19,[r14]; nop.i	0x0; }
	{ nop.m	0x0; adds	r14,0x8,r19; nop.i	0x0; }
	{ ld8	r16,[r14]; nop.i	0x0; adds	r14,0x0,r16; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000770E0:
	{ adds	r15,0xC,r14; ld4	r15,[r15]; nop.i	0x0; }
	{ and	r15,r17,r15; cmp4.eq	p07,p06,0x7F,r15; nop.i	0x0; }
	{ (p07) adds	r15,0x10,r14; ld8	r14,[r14]; nop.i	0x0; }

l4000000000077106:
	{ (p07) fwb; cmp.eq	p00,p00,r0,r1; (p01) nop }

l4000000000077116:
	{ (p03) chk.a.clr	r14,3FFFFFFFFFC7A216; nop; (p48) nop.b	0x13284 }

l4000000000077120:
	{ adds	r19,0x14,r19; nop.m	0x0; addl	r14,1,r0; }
	{ st4	[r14],r19; nop.i	0x0; br.ret	b0; }

;; fn4000000000077140: 4000000000077140
;;   Called from:
;;     400000000007E5DC (in fn400000000007D580)
;;     400000000007E74C (in fn400000000007D580)
;;     400000000007E7AC (in fn400000000007D580)
;;     40000000000803EC (in wait_for)
;;     40000000000804EC (in wait_for)
;;     4000000000080A2C (in wait_for)
;;     4000000000080E5C (in wait_for)
;;     4000000000080F3C (in wait_for)
;;     4000000000080FFC (in wait_for)
fn4000000000077140 proc
	{ alloc	r35,ar.pfs,0x7,0x0,0x5; addl	r32,5916,r1; nop.b	0x0 }
	{ addl	r33,-9940,r1; mov	r34,b2; adds	r36,0x0,r1; }
	{ nop.m	0x0; ld8	r33,[r33]; addl	r37,2,r0 }
	{ nop.m	0x0; ld8	r14,[r32]; nop.i	0x0; }
	{ cmp.eq	p06,p07,r33,r14; adds	r38,0x0,r14; (p06) br.cond.dpnt.few	40000000000771B0; }

l4000000000077190:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,set_signal_handler; }
	{ adds	r1,0x0,r36; st8	[r33],r32; nop.i	0x0 }

l40000000000771B0:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000771C0; br.ret	b0; }
40000000000771D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000771E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000771F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000077200: 4000000000077200
;;   Called from:
;;     400000000007A43C (in fn400000000007A300)
;;     400000000007A50C (in fn400000000007A300)
;;     400000000007A58C (in fn400000000007A300)
;;     400000000007A6EC (in fn400000000007A5C0)
;;     400000000007A71C (in fn400000000007A5C0)
fn4000000000077200 proc
	{ alloc	r36,ar.pfs,0xA,0x0,0x7; adds	r12,0xFFFFFFFFFFFFFF00,r12; nop.b	0x0 }
	{ adds	r37,0x0,r1; nop.m	0x0; mov	r35,b3; }
	{ adds	r39,0x90,r12; mov	r38,LC; br.call.sptk.many	b0,fn400000000001BC20; }
	{ addl	r40,17,r0; nop.m	0x0; adds	r1,0x0,r37 }
	{ adds	r39,0x90,r12; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B400; }
	{ adds	r1,0x0,r37; adds	r39,0x10,r12; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r37; adds	r39,0x0,r0; nop.i	0x0 }
	{ adds	r40,0x90,r12; adds	r41,0x10,r12; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r8,0xFFFFFFFFFFFFFFFF,r32; }
	{ nop.m	0x0; addl	r15,7444,r1; sxt4	r14,r8 }
	{ cmp4.lt	p06,p07,r8,r0; addp4	r16,r8,r0; (p06) br.cond.dpnt.few	4000000000077310; }

l40000000000772B0:
	{ ld8	r15,[r15]; mov.i	LC,r16; shladd	r15,r14,0x3,r15; }

l40000000000772C0:
	{ nop.m	0x0; ld8	r14,[r15],-8; nop.i	0x0; }
	{ adds	r16,0x14,r14; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	4000000000077300; }

l40000000000772E0:
	{ nop.m	0x0; ld4	r14,[r16]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,r33,r14; (p06) br.cond.dpnt.few	4000000000077360 }

l4000000000077300:
	{ nop.m	0x0; adds	r8,0xFFFFFFFFFFFFFFFF,r8; br.cloop.sptk.few	40000000000772C0 }

l4000000000077310:
	{ addl	r34,-1,r0; addl	r39,2,r0; nop.i	0x0 }
	{ adds	r40,0x10,r12; adds	r41,0x0,r0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r8,0x0,r34; adds	r1,0x0,r37; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.i	LC,r38; mov.spnt	b0,r35,4000000000077340 }
	{ nop.m	0x0; adds	r12,0x100,r12; br.ret	b0; }

l4000000000077360:
	{ adds	r34,0x0,r8; addl	r39,2,r0; nop.i	0x0 }
	{ adds	r40,0x10,r12; adds	r41,0x0,r0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r8,0x0,r34; adds	r1,0x0,r37; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.i	LC,r38; mov.spnt	b0,r35,4000000000077390 }
	{ nop.m	0x0; adds	r12,0x100,r12; br.ret	b0; }
40000000000773B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000773C0: 40000000000773C0
;;   Called from:
;;     40000000000789EC (in fn40000000000780C0)
;;     4000000000079EBC (in fn4000000000079240)
;;     4000000000079F9C (in fn4000000000079240)
;;     4000000000081E1C (in start_job)
fn40000000000773C0 proc
	{ alloc	r33,ar.pfs,0x5,0x0,0x3; addl	r35,-8228,r1; nop.b	0x0 }
	{ adds	r34,0x0,r1; nop.m	0x0; mov	r32,b0; }
	{ ld8	r35,[r35]; nop.i	0x0; br.call.sptk.many	b0,get_string_value; }
	{ adds	r1,0x0,r34; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	4000000000077420 }

l4000000000077400:
	{ nop.m	0x0; mov.i	ar.pfs,r33; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r32,4000000000077410; br.ret	b0 }

l4000000000077420:
	{ addl	r14,8380,r1; addl	r35,14924,r1; addl	r36,4096,r0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld8	r8,[r14]; nop.m	0x0; addl	r14,7360,r1; }
	{ cmp.eq	p06,p07,0x0,r8; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000077480; }

l4000000000077460:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000077400 }

l4000000000077480:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B540; }
	{ adds	r1,0x0,r34; cmp.eq	p06,p07,0x0,r8; mov.i	ar.pfs,r33; }
	{ (p06) addl	r8,-8236,r1; mov.spnt	b0,r32,40000000000774A0; (p07) addl	r8,14924,r1; }

l40000000000774A6:
	{ chk.a.nc	f32,3FFFFFFFFF1574B6; (p04) nop; add	r0,r0,r32 }

l40000000000774B0:
	{ nop.m	0x0; (p06) ld8	r8,[r8]; nop.i	0x0; }

l40000000000774BC:
	{ Invalid; break.i	0x1000; add	r0,r32,r0 }
	{ nop; break.m	0x1000; break.i	0x1000 }
40000000000774D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000774E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000774F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000077500: 4000000000077500
;;   Called from:
;;     40000000000818DC (in wait_for_background_pids)
;;     4000000000084B3C (in delete_all_jobs)
;;     4000000000084C0C (in delete_all_jobs)
fn4000000000077500 proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; addl	r33,14900,r1; nop.b	0x0 }
	{ adds	r36,0x0,r1; nop.m	0x0; mov	r34,b2; }
	{ nop.m	0x0; ld8	r37,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r37; (p07) br.cond.dpnt.few	4000000000077570; }

l4000000000077540:
	{ ld8	r32,[r37]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r36; adds	r37,0x0,r32 }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p06) br.cond.dptk.few	4000000000077540 }

l4000000000077570:
	{ adds	r14,0x0,r33; adds	r33,0x8,r33; mov.i	ar.pfs,r35; }
	{ st8	[r14],r16,16; st8	[r0],r33; mov.spnt	b0,r34,4000000000077580; }
	{ st4	[r0],r14; nop.i	0x0; br.ret	b0; }
40000000000775A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000775B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000775C0: 40000000000775C0
;;   Called from:
;;     40000000000815DC (in wait_for_single_pid)
fn40000000000775C0 proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; addl	r17,14900,r1; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld8	r16,[r17]; nop.i	0x0; }
	{ adds	r14,0x8,r16; cmp.eq	p06,p07,0x0,r16; (p06) br.cond.dpnt.few	4000000000077680; }

l4000000000077600:
	{ ld4	r15,[r14]; nop.m	0x0; adds	r14,0x0,r16; }
	{ cmp4.eq	p06,p07,r32,r15; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000077780; }

l4000000000077620:
	{ nop.m	0x0; ld8	r36,[r14]; nop.i	0x0; }
	{ adds	r15,0x8,r36; cmp.eq	p07,p06,0x0,r36; (p07) br.cond.dpnt.few	4000000000077680; }

l4000000000077640:
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,r32,r15; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000776A0; }

l4000000000077660:
	{ adds	r14,0x0,r36; ld8	r36,[r14]; nop.i	0x0; }
	{ adds	r15,0x8,r36; cmp.eq	p07,p06,0x0,r36; (p06) br.cond.dptk.few	4000000000077640 }

l4000000000077680:
	{ adds	r8,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,4000000000077690; br.ret	b0 }

l40000000000776A0:
	{ ld8	r15,[r36]; adds	r18,0x8,r17; cmp.eq	p06,p07,r36,r16; }
	{ st8	[r15],r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000077780; }

l40000000000776C0:
	{ ld8	r15,[r18]; nop.i	0x0; cmp.eq	p07,p06,r15,r36; }
	{ (p07) st8	[r14],r18; nop.m	0x0; nop.i	0x0 }

l40000000000776D6:
	{ break.m	0x4000; nop; (p48) nop }

l40000000000776E0:
	{ adds	r15,0x0,r17; nop.m	0x0; adds	r17,0x10,r17; }

l40000000000776E2:
	{ (p16) break.m	0x42004; Invalid; Invalid }
	{ (p16) chk.a.nc	r4,400000000007B732; (p49) cmp4.eq.or.andcm	p03,p32,r64,r16; (p47) nop }
	{ (p32) cmp.lt.unc	p03,p00,r97,r28; (p17) break.i	0x23204; Invalid }
	{ nop.m	0x80020; break.i	0x23304; Invalid }

l400000000007771C:
	{ Invalid; Invalid; mov	pr,r32,0x0 }

l4000000000077726:
	{ chk.a.nc	f0,3FFFFFFFFF077F26; Invalid; (p48) nop }

l4000000000077730:
	{ cmp4.eq	p07,p06,0x1,r14; nop.i	0x0; (p07) adds	r16,0x8,r15 }

l4000000000077740:
	{ (p07) ld8	r14,[r15]; (p07) st8	[r14],r16; nop.i	0x0 }

l4000000000077746:
	{ mf.a; nop; break.i	0x80000; }

l400000000007774C:
	{ Invalid; break.i	0x1000; break.i	0x1000 }

l4000000000077750:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ addl	r8,1,r0; adds	r1,0x0,r35; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,4000000000077770; br.ret	b0 }

l4000000000077780:
	{ ld8	r14,[r16]; nop.m	0x0; adds	r36,0x0,r16; }
	{ st8	[r14],r17; nop.i	0x0; br.cond.sptk.few	40000000000776E0; }
40000000000777A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000777B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000777C0: 40000000000777C0
;;   Called from:
;;     400000000007B0AC (in cleanup_the_pipeline)
;;     400000000007B20C (in restore_pipeline)
;;     400000000007B58C (in delete_job)
;;     400000000007BA9C (in delete_job)
fn40000000000777C0 proc
	{ alloc	r37,ar.pfs,0x8,0x0,0x7; mov	r36,b4; adds	r38,0x0,r1 }
	{ adds	r33,0x0,r32; nop.m	0x0; adds	r34,0x0,r0; }

l40000000000777E0:
	{ adds	r14,0x0,r33; nop.m	0x0; adds	r34,0x1,r34; }
	{ ld8	r35,[r14],24; ld8	r39,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r39; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000077830; }

l4000000000077810:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r38; nop.m	0x0; nop.i	0x0 }

l4000000000077830:
	{ adds	r39,0x0,r33; adds	r33,0x0,r35; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r38; cmp.eq	p07,p06,r35,r32; (p06) br.cond.dptk.few	40000000000777E0 }

l4000000000077850:
	{ adds	r8,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,4000000000077860; br.ret	b0; }
4000000000077870 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000077880 08 18 1D 0A 80 05 10 C2 07 76 48 40 04 00 C4 00 .........vH@....
4000000000077890 09 00 11 03 41 24 40 02 04 00 42 E0 41 EB CF 9E ....A$@...B.A...
40000000000778A0 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000778B0 09 00 00 00 01 00 E0 00 84 20 20 00 00 00 04 00 .........  .....
40000000000778C0 11 38 00 1C 86 39 00 00 00 02 00 03 70 00 00 43 .8...9......p..C
40000000000778D0 09 00 00 00 01 00 E0 00 80 30 20 00 00 00 04 00 .........0 .....
40000000000778E0 11 38 00 1C 06 39 00 00 00 02 80 03 30 00 00 43 .8...9......0..C
40000000000778F0 09 00 00 00 01 00 F0 00 3C 30 20 00 00 00 04 00 ........<0 .....
4000000000077900 10 00 00 00 01 00 70 78 38 0C F0 03 30 00 00 43 ......px8...0..C
4000000000077910 09 78 04 00 00 24 E0 A0 05 74 48 00 30 02 AA 00 .x...$...tH.0...
4000000000077920 10 00 3C 1C 90 11 00 10 05 80 03 80 08 00 84 00 ..<.............
4000000000077930 09 70 50 03 46 24 00 00 00 02 00 E0 11 00 00 90 .pP.F$..........
4000000000077940 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000077950 11 00 3C 1C 90 11 00 00 00 02 00 00 F8 F7 FF 58 ..<............X
4000000000077960 09 08 00 48 00 21 E0 00 80 30 20 00 00 00 04 00 ...H.!...0 .....
4000000000077970 11 78 D0 FA B3 27 60 00 38 0E 72 03 30 00 00 43 .x...'`.8.r.0..C
4000000000077980 09 00 00 00 01 00 F0 00 3C 30 20 00 00 00 04 00 ........<0 .....
4000000000077990 10 00 00 00 01 00 70 78 38 0C F0 03 00 01 00 43 ......px8......C
40000000000779A0 09 00 11 02 3C 24 00 00 00 02 00 C0 C1 0F EC 90 ....<$..........
40000000000779B0 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000779C0 0B 78 00 40 B0 10 F0 08 3C 00 42 00 00 00 04 00 .x.@....<.B.....
40000000000779D0 0B 00 3C 40 B0 11 F0 00 38 60 21 00 00 00 04 00 ..<@....8`!.....
40000000000779E0 11 30 00 1E 87 39 00 00 00 02 80 03 70 00 00 43 .0...9......p..C
40000000000779F0 09 00 00 00 01 00 E0 00 80 60 21 00 00 00 04 00 .........`!.....
4000000000077A00 10 00 00 00 01 00 60 00 38 0E 73 03 10 FF FF 4A ......`.8.s....J
4000000000077A10 11 00 00 00 01 00 00 00 00 02 00 00 F8 CA 03 50 ...............P
4000000000077A20 09 08 00 48 00 21 F0 08 00 00 48 00 30 02 AA 00 ...H.!....H.0...
4000000000077A30 09 70 D0 02 3A 24 00 00 00 02 00 00 20 0A 00 07 .p..:$...... ...
4000000000077A40 11 00 3C 1C 90 11 00 00 00 02 00 80 08 00 84 00 ..<.............
4000000000077A50 11 28 01 1C B0 10 00 00 00 02 00 00 38 D2 03 50 .(..........8..P
4000000000077A60 09 70 00 40 B0 10 00 00 00 02 00 20 00 20 01 84 .p.@....... . ..
4000000000077A70 10 00 00 00 01 00 60 00 38 0E 73 03 A0 FE FF 4A ......`.8.s....J
4000000000077A80 10 00 00 00 01 00 00 00 00 02 00 00 90 FF FF 48 ...............H
4000000000077A90 11 28 09 00 00 24 00 00 00 02 00 00 78 81 03 50 .(...$......x..P
4000000000077AA0 10 08 00 48 00 21 60 00 20 0E 73 03 00 FF FF 4A ...H.!`. .s....J
4000000000077AB0 11 28 09 00 00 24 00 00 00 02 00 00 58 5E 03 50 .(...$......X^.P
4000000000077AC0 0B 08 00 48 00 21 E0 20 F7 69 4F 00 00 00 04 00 ...H.!. .iO.....
4000000000077AD0 09 00 00 00 01 00 E0 00 38 30 20 00 00 00 04 00 ........80 .....
4000000000077AE0 10 00 00 00 01 00 70 40 38 0C 70 03 C0 FE FF 48 ......p@8.p....H
4000000000077AF0 08 00 00 00 01 00 50 12 00 00 48 00 00 00 04 00 ......P...H.....
4000000000077B00 19 00 00 42 90 11 00 00 00 02 00 00 48 7B 03 50 ...B........H{.P
4000000000077B10 09 08 00 48 00 21 F0 10 00 00 48 C0 14 00 00 90 ...H.!....H.....
4000000000077B20 09 70 B0 02 47 24 00 00 00 02 00 A0 44 0E 28 93 .p..G$......D.(.
4000000000077B30 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000077B40 11 00 3C 1C 90 11 00 00 00 02 00 00 A8 40 FA 58 ..<..........@.X
4000000000077B50 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
4000000000077B60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000077B70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000077B80: 4000000000077B80
;;   Called from:
;;     4000000000077D0C (in fn4000000000077C00)
;;     4000000000077D5C (in fn4000000000077C00)
;;     400000000007B81C (in delete_job)
;;     400000000007CBDC (in job_exit_status)
;;     400000000007E54C (in fn400000000007D580)
;;     4000000000080A7C (in wait_for)
fn4000000000077B80 proc
	{ and	r8,0x7F,r32; adds	r14,0x1,r8; adds	r8,0x80,r8; }
	{ nop.m	0x0; extr.u	r14,r14,1,7; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,0x0,r14; (p07) br.ret	b0 }

l4000000000077BB0:
	{ nop.m	0x0; extr.u	r8,r32,8,8; zxt1	r32,r32; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x7F,r32; nop.i	0x0; }
	{ nop.m	0x0; (p06) adds	r8,0x0,r0; br.ret	b0; }

l4000000000077BDC:
	{ nop; break.m	0x1000; break.i	0x1000 }
4000000000077BE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000077BF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000077C00: 4000000000077C00
;;   Called from:
;;     4000000000080B1C (in wait_for)
;;     40000000000843FC (in stop_pipeline)
fn4000000000077C00 proc
	{ alloc	r41,ar.pfs,0xE,0x0,0xC; addl	r39,7444,r1; mov	r43,pr }
	{ adds	r42,0x0,r1; nop.m	0x0; sxt4	r32,r32; }
	{ shladd	r36,r32,0x3,r0; ld8	r14,[r39]; nop.b	0x0 }
	{ addl	r15,1,r0; mov	r40,b0; add	r14,r14,r36; }
	{ ld8	r14,[r14]; adds	r14,0x8,r14; nop.i	0x0; }
	{ nop.m	0x0; ld8	r34,[r14]; nop.i	0x0; }
	{ ld8	r33,[r34]; cmp.eq	p16,p17,r33,r34; adds	r14,0x0,r33; }
	{ nop.m	0x0; (p16) addl	r35,2,r0; (p16) br.cond.dpnt.few	4000000000077CB0; }

l4000000000077C7C:
	{ (p02) cmp.lt	p00,p09,r64,r33; Invalid; cmp.eq	p00,p00,r32,r0 }

l4000000000077C80:
	{ ld8	r14,[r14]; nop.m	0x0; adds	r15,0x1,r15; }
	{ nop.m	0x0; cmp.eq	p07,p06,r14,r34; (p06) br.cond.dptk.few	4000000000077C80 }

l4000000000077CA0:
	{ adds	r35,0x1,r15; nop.m	0x0; nop.i	0x0 }

l4000000000077CB0:
	{ addl	r38,7500,r1; ld4	r14,[r38]; nop.i	0x0; }
	{ cmp4.lt	p06,p07,r14,r35; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000077DD0; }

l4000000000077CD0:
	{ (p07) addl	r14,7508,r1; nop.m	0x0; adds	r35,0x0,r0; }

l4000000000077CD6:
	{ add	r0,r0,r1; (p17) cmp.eq.and	p00,p02,0x0,r0; (p17) nop }

l4000000000077CE6:
	{ Invalid; (p18) nop; (p32) nop }

l4000000000077CF0:
	{ adds	r14,0xC,r14; nop.m	0x0; adds	r35,0x1,r35; }
	{ ld4	r44,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000077B80; }
	{ nop.m	0x0; adds	r14,0x0,r33; adds	r1,0x0,r42 }
	{ nop.m	0x0; st4	[r36],r4,4; (p16) br.cond.dpnt.few	4000000000077D80; }

l4000000000077D30:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000077D40:
	{ adds	r14,0xC,r14; ld8	r33,[r33]; adds	r35,0x1,r35; }
	{ ld4	r44,[r14]; cmp.eq	p16,p17,r33,r34; br.call.sptk.many	b0,fn4000000000077B80; }
	{ nop.m	0x0; adds	r1,0x0,r42; adds	r14,0x0,r33 }
	{ nop.m	0x0; st4	[r36],r4,4; (p17) br.cond.dptk.few	4000000000077D40; }

l4000000000077D80:
	{ nop.m	0x0; sxt4	r14,r35; adds	r44,0x0,r37 }
	{ adds	r45,0x0,r35; shladd	r37,r14,0x2,r37; addl	r14,-1,r0; }
	{ st4	[r14],r37; nop.i	0x0; br.call.sptk.many	b0,set_pipestatus_array; }
	{ adds	r1,0x0,r42; mov	pr,r43,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.spnt	b0,r40,4000000000077DC0; br.ret	b0 }

l4000000000077DD0:
	{ addl	r33,7508,r1; nop.m	0x0; sxt4	r45,r35; }
	{ ld8	r44,[r33]; shladd	r45,r45,0x2,r0; br.call.sptk.many	b0,xrealloc; }
	{ nop.m	0x0; ld8	r14,[r39]; adds	r37,0x0,r8 }
	{ st8	[r8],r33; st4	[r35],r38; adds	r1,0x0,r42; }
	{ add	r36,r14,r36; nop.m	0x0; adds	r35,0x0,r0; }
	{ ld8	r14,[r36]; adds	r36,0x0,r37; adds	r14,0x8,r14; }
	{ ld8	r34,[r14]; adds	r14,0x0,r34; nop.i	0x0; }
	{ nop.m	0x0; ld8	r33,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p16,p17,r33,r34; br.cond.sptk.few	4000000000077CF0; }
4000000000077E60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000077E70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000077E80: 4000000000077E80
;;   Called from:
;;     40000000000794CC (in fn4000000000079240)
;;     400000000007CBAC (in job_exit_status)
;;     400000000007CC2C (in job_exit_signal)
fn4000000000077E80 proc
	{ addl	r14,7332,r1; adds	r8,0x0,r0; sxt4	r15,r32; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4	r14,[r14]; cmp4.eq	p06,p07,0x0,r14; addl	r14,7444,r1; }
	{ ld8	r14,[r14]; nop.i	0x0; (p06) br.cond.dptk.few	4000000000077F40; }

l4000000000077EC0:
	{ shladd	r15,r15,0x3,r14; ld8	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; adds	r14,0x8,r14; nop.i	0x0; }
	{ ld8	r16,[r14]; nop.i	0x0; adds	r14,0x0,r16; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000077F00:
	{ adds	r15,0xC,r14; ld8	r14,[r14]; nop.i	0x0; }
	{ ld4	r15,[r15]; cmp.eq	p07,p06,r14,r16; cmp4.eq	p09,p08,0x0,r15; }
	{ nop.m	0x0; (p08) adds	r8,0x0,r15; (p06) br.cond.dptk.few	4000000000077F00 }

l4000000000077F2C:
	{ (p63) invala; break.i	0x1000; add	r0,r32,r0 }

l4000000000077F30:
	{ nop.m	0x0; nop.i	0x0; br.ret	b0 }

l4000000000077F40:
	{ shladd	r32,r15,0x3,r14; ld8	r14,[r32]; nop.i	0x0; }
	{ adds	r14,0x8,r14; ld8	r16,[r14]; nop.i	0x0; }
	{ adds	r15,0x0,r16; ld8	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r14,r16; (p07) br.cond.dpnt.few	4000000000077FA0; }

l4000000000077F80:
	{ adds	r15,0x0,r14; ld8	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r14,r16; (p06) br.cond.dptk.few	4000000000077F80 }

l4000000000077FA0:
	{ nop.m	0x0; adds	r15,0xC,r15; nop.i	0x0; }
	{ ld4	r8,[r15]; nop.i	0x0; br.ret	b0; }

;; fn4000000000077FC0: 4000000000077FC0
;;   Called from:
;;     400000000007895C (in fn40000000000780C0)
;;     4000000000078CFC (in fn40000000000780C0)
;;     4000000000079A6C (in fn4000000000079240)
fn4000000000077FC0 proc
	{ alloc	r34,ar.pfs,0x9,0x0,0x4; nop.m	0x0; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; adds	r36,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AF00; }
	{ adds	r1,0x0,r35; cmp.eq	p07,p06,0x0,r8; mov.i	ar.pfs,r34 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000078020; }

l4000000000078010:
	{ nop.m	0x0; mov.spnt	b0,r33,4000000000078010; br.ret	b0 }

l4000000000078020:
	{ addl	r37,-8220,r1; adds	r36,0x0,r0; addl	r38,5,r0; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r35; addl	r37,1,r0; addl	r38,64,r0 }
	{ adds	r39,0x0,r8; adds	r40,0x0,r32; addl	r36,19020,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C440; }
	{ adds	r1,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ addl	r8,19020,r1; nop.m	0x0; mov.spnt	b0,r33,4000000000078080; }
	{ nop.m	0x0; nop.i	0x0; br.ret	b0; }
40000000000780A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000780B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000780C0: 40000000000780C0
;;   Called from:
;;     40000000000790FC (in fn4000000000079080)
;;     4000000000079846 (in fn4000000000079240)
;;     4000000000079936 (in fn4000000000079240)
;;     4000000000079EEC (in fn4000000000079240)
;;     4000000000079FBC (in fn4000000000079240)
;;     400000000007A09C (in fn4000000000079240)
;;     400000000007C76C (in list_one_job)
fn40000000000780C0 proc
	{ alloc	r61,ar.pfs,0x25,0x0,0x20; mov	r63,pr; nop.b	0x0 }
	{ cmp4.eq	p07,p06,0x2,r33; adds	r62,0x0,r1; sxt4	r43,r32; }
	{ nop.m	0x0; mov	r60,b4; (p07) br.cond.dpnt.few	4000000000078FF0; }

l40000000000780F0:
	{ cmp4.eq	p07,p06,0x3,r33; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000078E70; }

l4000000000078100:
	{ cmp4.eq	p07,p06,0x4,r33; nop.i	0x0; (p07) addl	r45,7444,r1 }

l4000000000078110:
	{ (p07) shladd	r43,r43,0x3,r0; (p07) addl	r33,1,r0; (p07) br.cond.dpnt.few	40000000000781C0; }

l4000000000078116:
	{ (p16) chk.a.clr	f1,3FFFFFFFFF278116; nop; break.b	0x80000; }

l400000000007811C:
	{ (p05) nop; nop; nop }

l4000000000078120:
	{ nop.m	0x0; addl	r45,7444,r1; shladd	r43,r43,0x3,r0 }

l4000000000078130:
	{ addl	r14,-20676,r1; nop.m	0x0; adds	r67,0x1,r32; }
	{ nop.m	0x0; adds	r15,0x30,r14; adds	r14,0x34,r14; }
	{ ld4	r15,[r15]; cmp4.eq	p06,p07,r32,r15; nop.i	0x0; }
	{ (p06) addl	r68,43,r0; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000078190; }

l4000000000078166:
	{ chk.a.nc	r0,3FFFFFFFFF078966; nop; nop }

l4000000000078170:
	{ ld4	r68,[r14]; cmp4.eq	p07,p06,r32,r68; nop.i	0x0; }
	{ (p06) addl	r68,32,r0; nop.i	0x0; (p07) addl	r68,45,r0 }

l4000000000078186:
	{ chk.a.nc	f0,3FFFFFFFFF078986; (p34) nop; (p32) nop }

l4000000000078190:
	{ addl	r66,-8180,r1; adds	r64,0x0,r34; addl	r65,1,r0; }
	{ ld8	r66,[r66]; br.call.sptk.many	b0,fn400000000001C040; nop.b	0x0; }
	{ adds	r1,0x0,r62; nop.m	0x0; nop.i	0x0 }

l40000000000781C0:
	{ ld8	r14,[r45]; add	r14,r14,r43; nop.i	0x0; }
	{ ld8	r15,[r14]; adds	r15,0x8,r15; nop.i	0x0; }
	{ nop.m	0x0; ld8	r37,[r15]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r37; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000789A0; }

l4000000000078200:
	{ (p07) adds	r38,0x0,r37; ld8	r14,[r38]; nop.i	0x0; }

l4000000000078206:
	{ (p07) fwb; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	f14,3FFFFFFFFFC7B466; nop; (p32) nop.b	0xE009 }

l4000000000078220:
	{ adds	r38,0x0,r14; ld8	r14,[r38]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r14,r37; (p06) br.cond.dptk.few	4000000000078220; }

l4000000000078240:
	{ cmp4.eq	p07,p06,0x0,r33; andcm	r32,0xFFFFFFFFFFFFFFFF,r32; andcm	r33,0xFFFFFFFFFFFFFFFF,r33 }
	{ addl	r49,7408,r1; addl	r56,19020,r1; addl	r54,6456,r1; }
	{ (p06) addl	r40,1,r0; addl	r50,6516,r1; extr.u	r32,r32,31,1 }

l4000000000078266:
	{ Invalid; (p16) nop; (p48) nop }
	{ add	r0,r0,r1; (p23) cmp.ne.or	p63,p08,r0,r1; (p01) nop }

l4000000000078286:
	{ Invalid; (p24) nop; nop.b	0x2520D }
	{ Invalid; (p21) nop; nop }
	{ Invalid; (p25) nop; (p48) nop }
	{ break.m	0x4000; (p20) addl	r0,262184,r0; (p33) nop }

l40000000000782C6:
	{ Invalid; (p16) nop; break.b	0x80000 }
	{ Invalid; (p29) cmp4.eq.or	p20,p08,r1,r58; (p33) nop }

l40000000000782E6:
	{ break.m	0x4000; nop; add	r0,r0,r32 }
	{ (p23) fwb; cmp.ltu	p00,p00,r0,r1; (p33) nop; }

l40000000000782FC:
	{ cmp4.eq.and	p00,p40,r1,r0; Invalid; break.i	0x1000 }

l4000000000078306:
	{ break.m	0x4000; nop; break.i	0x80000 }

l4000000000078310:
	{ nop.m	0x0; nop.i	0x0; (p19) br.cond.dpnt.few	4000000000078800 }

l4000000000078312:
	{ break.m	0x20; cmp.eq	p32,p04,r0,r96; Invalid }

l4000000000078320:
	{ adds	r65,0x0,r34; nop.m	0x0; addl	r64,32,r0 }
	{ cmp.eq	p17,p16,r35,r37; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BD80; }
	{ nop.m	0x0; adds	r1,0x0,r62; (p21) br.cond.dptk.few	4000000000078680; }

l4000000000078350:
	{ addl	r65,-8164,r1; nop.m	0x0; adds	r64,0x0,r0 }
	{ addl	r66,5,r0; nop.m	0x0; adds	r39,0x0,r38; }
	{ ld8	r65,[r65]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ nop.m	0x0; ld8	r14,[r45]; adds	r1,0x0,r62 }
	{ st8	[r8],r48; add	r14,r14,r43; addl	r44,7492,r1; }
	{ ld8	r14,[r14]; adds	r14,0x14,r14; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2,r14; (p07) br.cond.dpnt.few	4000000000078C10; }

l40000000000783D0:
	{ adds	r41,0xC,r39; cmp4.eq	p07,p06,0x1,r14; (p07) br.cond.dpnt.few	4000000000078DF0; }

l40000000000783E0:
	{ ld4	r14,[r41]; and	r15,r47,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x7F,r15; (p07) br.cond.dpnt.few	4000000000078940 }

l4000000000078400:
	{ and	r64,0x7F,r14; and	r14,r53,r14; addl	r66,5,r0; }
	{ adds	r16,0x1,r64; extr	r36,r14,8,24; extr.u	r16,r16,1,7; }
	{ cmp4.lt	p07,p06,0x0,r16; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000078CF0; }

l4000000000078430:
	{ cmp4.eq	p07,p06,0x0,r64; adds	r64,0x0,r0; (p06) br.cond.dpnt.few	4000000000078E30; }

l4000000000078440:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r36; nop.i	0x0 }
	{ st8	[r56],r44; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000078EE0; }

l4000000000078460:
	{ ld4	r14,[r54]; cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; }
	{ (p07) addl	r65,-8132,r1; (p06) addl	r65,-8124,r1; nop.i	0x0; }

l4000000000078476:
	{ Invalid; nop; Invalid; }

l400000000007847C:
	{ nop; nop; Invalid }

l400000000007848C:
	{ nop; Invalid; break.i	0x1000 }

l4000000000078496:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; (p32) mov.sptk	b1,r0,40000000000788A6; (p32) nop }
	{ Invalid; (p32) nop; break.b	0x80000 }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ (p18) fwb; nop; (p32) nop }

l40000000000784E0:
	{ cmp.eq	p06,p07,r35,r37; nop.m	0x0; adds	r14,0x10,r39; }
	{ (p06) cmp.eq	p17,p16,r0,r0; (p06) br.cond.dpnt.few	4000000000078530; (p18) br.cond.dptk.few	40000000000786B0; }

l40000000000784F6:
	{ nop; nop; break.i	0x80000; }

l40000000000784FC:
	{ (p14) nop; cmp.eq	p00,p00,r32,r0; Invalid }

l4000000000078500:
	{ nop.m	0x0; ld4	r15,[r14]; cmp.eq	p16,p17,r0,r0 }
	{ nop.m	0x0; ld4	r14,[r52]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r15; (p07) br.cond.dpnt.few	4000000000078D20; }

l4000000000078530:
	{ adds	r41,0xC,r39; cmp.eq	p06,p07,0x0,r36; (p06) br.cond.spnt.few	4000000000078680 }

l4000000000078540:
	{ adds	r64,0x0,r36; adds	r65,0x0,r34; br.call.sptk.many	b0,fn400000000001C260; }
	{ ld1	r14,[r36]; adds	r1,0x0,r62; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000078CE0 }

l4000000000078570:
	{ adds	r14,0x1,r36; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ nop.m	0x0; (p06) addl	r67,23,r0; (p06) br.cond.dptk.few	4000000000078600 }

l400000000007859C:
	{ (p03) cmp.lt	p00,p11,r0,r33; (p33) cmp.lt	p00,p16,r9,r64; (p01) rfi }

l40000000000785A0:
	{ adds	r14,0x2,r36; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000078CE0 }

l40000000000785D0:
	{ adds	r64,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; sub	r67,0x18,r8; adds	r1,0x0,r62 }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.spnt.few	4000000000078CE0; }

l4000000000078600:
	{ addl	r66,-8108,r1; nop.m	0x0; addl	r68,-8196,r1 }
	{ adds	r64,0x0,r34; addl	r65,1,r0; nop.i	0x0 }
	{ ld8	r66,[r66]; ld8	r68,[r68]; br.call.sptk.many	b0,fn400000000001C040; }
	{ ld4	r14,[r41]; adds	r1,0x0,r62; and	r15,r47,r14; }
	{ cmp4.eq	p06,p07,0x7F,r15; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000078680; }

l4000000000078650:
	{ cmp4.eq	p06,p07,r51,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000078680; }

l4000000000078660:
	{ nop.m	0x0; and	r14,r14,r55; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	4000000000078D70 }

l4000000000078680:
	{ (p16) addl	r14,1,r0; (p17) adds	r14,0x0,r0; nop.i	0x0; }

l4000000000078686:
	{ Invalid; break.x	0x20000080000 }

l400000000007868C:
	{ nop; cmp.lt	p00,p00,r32,r0; zxt1	r3,r3 }
	{ invala; cmp.lt	p00,p00,r32,r0; mov	pr,r99,0xE680 }
	{ (p34) cmp.lt	p00,p09,r64,r33; zxt1	r102,r64; nop }

l40000000000786B0:
	{ adds	r14,0x18,r35; nop.m	0x0; adds	r65,0x0,r34; }
	{ nop.m	0x0; ld8	r64,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r64; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000078700; }

l40000000000786E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C260; }
	{ adds	r1,0x0,r62; nop.m	0x0; nop.i	0x0 }

l4000000000078700:
	{ cmp.eq	p06,p07,r35,r38; (p06) addl	r39,1,r0; nop.i	0x0; }

l400000000007870C:
	{ nop; cmp4.eq.or.andcm	p00,p32,r32,r0; zxt1	r0,r64 }

l400000000007871C:
	{ Invalid; add	r0,r32,r0; (p04) cmp.lt.unc	p32,p00,r9,r4 }
	{ (p21) invala; cmp.eq	p00,p00,r32,r0; mov	pr,r67,0xE680; }
	{ (p21) nop; add	r0,r32,r0; (p04) epc }

l4000000000078740:
	{ nop.m	0x0; or	r36,r40,r36; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r36; (p06) br.cond.dptk.few	40000000000787C0 }

l4000000000078760:
	{ nop.m	0x0; ld4	r14,[r49]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000787A0; }

l4000000000078780:
	{ nop.m	0x0; ld4	r14,[r50]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	4000000000078B20 }

l40000000000787A0:
	{ addl	r64,10,r0; adds	r65,0x0,r34; br.call.sptk.many	b0,fn400000000001BD80; }
	{ adds	r1,0x0,r62; cmp4.eq	p07,p06,0x0,r39; (p06) br.cond.dpnt.few	4000000000078980 }

l40000000000787C0:
	{ ld8	r35,[r35]; nop.m	0x0; adds	r64,0x0,r34 }
	{ addl	r65,1,r0; nop.m	0x0; adds	r66,0x0,r46; }
	{ cmp.eq	p17,p16,r35,r37; (p17) br.cond.dpnt.few	4000000000078310; br.call.sptk.many	b0,fn400000000001C040; }

l40000000000787EC:
	{ Invalid; nop; chk.s.i	r15,3FFFFFFFFF498BEC }
	{ (p25) cmp.lt.unc	p63,p08,r63,r37; (p01) dep	r98,r8,r64,62,1; (p08) nop }

l4000000000078800:
	{ adds	r14,0x8,r35; addl	r66,-8172,r1; adds	r64,0x0,r34 }
	{ addl	r65,1,r0; addl	r44,7492,r1; cmp.eq	p17,p16,r35,r37; }
	{ ld4	r67,[r14]; ld8	r66,[r66]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r67,r67; br.call.sptk.many	b0,fn400000000001C040; }
	{ adds	r1,0x0,r62; nop.m	0x0; adds	r65,0x0,r34 }
	{ addl	r64,32,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BD80; }
	{ adds	r1,0x0,r62; nop.m	0x0; and	r14,r33,r42 }
	{ adds	r64,0x0,r0; addl	r66,5,r0; addl	r65,-8164,r1 }
	{ cmp4.eq	p07,p06,0x0,r14; nop.m	0x0; (p07) br.cond.dptk.few	4000000000078680; }

l4000000000078890:
	{ ld8	r65,[r65]; nop.m	0x0; nop.i	0x0 }
	{ adds	r39,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ nop.m	0x0; ld8	r14,[r45]; adds	r1,0x0,r62 }
	{ st8	[r8],r48; add	r14,r14,r43; nop.i	0x0; }
	{ ld8	r14,[r14]; adds	r14,0x14,r14; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2,r14; (p07) br.cond.dptk.few	40000000000783D0 }

l4000000000078900:
	{ adds	r39,0x0,r35; adds	r41,0xC,r39; nop.i	0x0; }
	{ ld4	r14,[r41]; and	r15,r47,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x7F,r15; (p06) br.cond.dptk.few	4000000000078400; }

l4000000000078930:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000078940:
	{ nop.m	0x0; and	r64,r53,r14; nop.i	0x0; }
	{ nop.m	0x0; extr.u	r64,r64,8,8; br.call.sptk.many	b0,fn4000000000077FC0; }
	{ nop.m	0x0; adds	r1,0x0,r62; adds	r36,0x0,r8 }
	{ nop.m	0x0; st8	[r8],r44; br.cond.sptk.few	40000000000784E0 }

l4000000000078980:
	{ adds	r64,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ ld8	r14,[r45]; adds	r1,0x0,r62; add	r14,r14,r43; }

l40000000000789A0:
	{ ld8	r14,[r14]; nop.m	0x0; mov	pr,r63,0xFFFFFFFFFFFFFFFE; }
	{ adds	r14,0x18,r14; nop.m	0x0; mov.i	ar.pfs,r61; }
	{ ld4	r15,[r14]; mov.spnt	b0,r60,40000000000789C0; or	r15,0x2,r15; }
	{ st4	[r15],r14; nop.i	0x0; br.ret	b0; }

l40000000000789E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000773C0; }
	{ ld8	r14,[r45]; adds	r1,0x0,r62; adds	r41,0x0,r8; }
	{ add	r14,r14,r43; ld8	r15,[r14]; nop.i	0x0; }
	{ adds	r16,0x14,r15; ld4	r16,[r16]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x1,r16; (p07) br.cond.dpnt.few	4000000000078B70 }

l4000000000078A30:
	{ ld8	r14,[r14]; nop.m	0x0; adds	r64,0x0,r41; }
	{ ld8	r65,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r62; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	4000000000078740; }

l4000000000078A60:
	{ addl	r65,-8076,r1; addl	r66,5,r0; adds	r64,0x0,r0; }
	{ ld8	r65,[r65]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ ld8	r14,[r45]; adds	r1,0x0,r62; adds	r41,0x0,r8; }
	{ add	r14,r14,r43; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r64,[r14]; nop.i	0x0; br.call.sptk.many	b0,polite_directory_format; }
	{ adds	r1,0x0,r62; adds	r64,0x0,r34; addl	r65,1,r0 }
	{ adds	r66,0x0,r41; adds	r67,0x0,r8; br.call.sptk.many	b0,fn400000000001C040; }
	{ nop.m	0x0; adds	r1,0x0,r62; br.cond.sptk.few	4000000000078740; }

l4000000000078AE0:
	{ addl	r64,-8092,r1; nop.m	0x0; addl	r65,1,r0 }
	{ addl	r66,2,r0; nop.m	0x0; adds	r67,0x0,r34; }
	{ ld8	r64,[r64]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B000; }
	{ nop.m	0x0; adds	r1,0x0,r62; br.cond.sptk.few	40000000000786B0; }

l4000000000078B20:
	{ addl	r64,-8068,r1; nop.m	0x0; addl	r65,1,r0 }
	{ addl	r66,2,r0; nop.m	0x0; adds	r67,0x0,r34; }
	{ ld8	r64,[r64]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B000; }
	{ adds	r1,0x0,r62; cmp4.eq	p07,p06,0x0,r39; (p07) br.cond.dptk.few	40000000000787C0 }

l4000000000078B60:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000078980 }

l4000000000078B70:
	{ adds	r15,0x18,r15; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r15,0x0; (p06) br.cond.dptk.few	4000000000078A30 }

l4000000000078B90:
	{ addl	r64,-8084,r1; nop.m	0x0; addl	r65,1,r0 }
	{ addl	r66,2,r0; nop.m	0x0; adds	r67,0x0,r34; }
	{ ld8	r64,[r64]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B000; }
	{ ld8	r14,[r59]; adds	r1,0x0,r62; adds	r64,0x0,r41; }
	{ add	r14,r14,r43; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r65,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r62; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	4000000000078740 }

l4000000000078C00:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000078A60; }

l4000000000078C10:
	{ ld4	r14,[r54]; nop.m	0x0; addl	r65,-8156,r1 }
	{ adds	r64,0x0,r0; addl	r66,5,r0; cmp4.eq	p06,p07,0x0,r14 }
	{ ld8	r65,[r65]; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000078C60; }

l4000000000078C40:
	{ ld4	r14,[r58]; and	r14,r47,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x7F,r14; (p06) br.cond.dpnt.few	4000000000078F40 }

l4000000000078C60:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r62; nop.m	0x0; adds	r36,0x0,r8 }
	{ st8	[r8],r48; nop.m	0x0; nop.i	0x0 }

l4000000000078C90:
	{ nop.m	0x0; cmp.eq	p17,p16,r35,r37; nop.i	0x0; }
	{ (p17) adds	r39,0x0,r38; (p16) addl	r14,1,r0; (p17) br.cond.dpnt.few	4000000000078530; }

l4000000000078CA6:
	{ (p07) nop; (p36) nop }

l4000000000078CAC:
	{ (p04) cmp.le.and	p63,p43,r0,r37; (p01) cmp.lt	p00,p16,r0,r64; (p33) epc }

l4000000000078CB0:
	{ (p17) adds	r14,0x0,r0; and	r14,r14,r40; nop.i	0x0; }

l4000000000078CB6:
	{ Invalid; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD3C5A6; nop; break.i	0x80000 }

l4000000000078CD0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000078AE0 }

l4000000000078CE0:
	{ nop.m	0x0; addl	r67,22,r0; br.cond.sptk.few	4000000000078600 }

l4000000000078CF0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000077FC0; }
	{ nop.m	0x0; adds	r1,0x0,r62; adds	r36,0x0,r8 }
	{ nop.m	0x0; st8	[r8],r44; br.cond.sptk.few	40000000000784E0 }

l4000000000078D20:
	{ adds	r41,0xC,r39; ld4	r14,[r57]; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r41]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,r14,r15; (p07) br.cond.dptk.few	4000000000078530 }

l4000000000078D50:
	{ addl	r36,-8196,r1; nop.m	0x0; cmp.eq	p16,p17,r0,r0; }
	{ ld8	r36,[r36]; nop.i	0x0; br.cond.sptk.few	4000000000078540 }

l4000000000078D70:
	{ addl	r65,-8100,r1; addl	r66,5,r0; adds	r64,0x0,r0; }
	{ ld8	r65,[r65]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r62; adds	r64,0x0,r34; nop.i	0x0 }
	{ addl	r65,1,r0; adds	r66,0x0,r8; br.call.sptk.many	b0,fn400000000001C040; }
	{ (p16) addl	r14,1,r0; adds	r1,0x0,r62; (p17) adds	r14,0x0,r0; }

l4000000000078DB6:
	{ nop; (p07) nop; break.b	0x80000 }

l4000000000078DC0:
	{ nop.m	0x0; and	r14,r14,r40; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000786B0 }

l4000000000078DE0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000078AE0 }

l4000000000078DF0:
	{ addl	r65,-8140,r1; adds	r64,0x0,r0; addl	r66,5,r0; }
	{ ld8	r65,[r65]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ nop.m	0x0; adds	r1,0x0,r62; adds	r36,0x0,r8 }
	{ nop.m	0x0; st8	[r8],r44; br.cond.sptk.few	40000000000784E0; }

l4000000000078E30:
	{ addl	r65,-8116,r1; adds	r64,0x0,r0; addl	r66,5,r0; }
	{ ld8	r65,[r65]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ nop.m	0x0; adds	r1,0x0,r62; adds	r36,0x0,r8 }
	{ nop.m	0x0; st8	[r8],r44; br.cond.sptk.few	40000000000784E0; }

l4000000000078E70:
	{ addl	r45,7444,r1; nop.m	0x0; shladd	r43,r43,0x3,r0; }
	{ ld8	r14,[r45]; add	r14,r14,r43; nop.i	0x0; }
	{ ld8	r14,[r14]; adds	r14,0x18,r14; nop.i	0x0; }
	{ ld4	r14,[r14]; nop.m	0x0; tbit.z	p07,p06,r14,0x1; }
	{ nop.m	0x0; (p07) adds	r33,0x0,r0; (p07) br.cond.dptk.few	4000000000078130 }

l4000000000078EBC:
	{ Invalid; cmp.eq	p00,p00,r32,r0; (p63) nop.i	0xDFE0F }

l4000000000078EC0:
	{ nop.m	0x0; mov	pr,r63,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r61; }
	{ nop.m	0x0; mov.spnt	b0,r60,4000000000078ED0; br.ret	b0 }

l4000000000078EE0:
	{ addl	r65,-8164,r1; adds	r64,0x0,r0; addl	r66,5,r0; }
	{ ld8	r65,[r65]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r62; addl	r66,64,r0; adds	r65,0x0,r8; }
	{ addl	r64,19020,r1; nop.m	0x0; nop.i	0x0; }
	{ adds	r36,0x0,r64; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BAE0; }
	{ nop.m	0x0; adds	r1,0x0,r62; br.cond.sptk.few	40000000000784E0; }

l4000000000078F40:
	{ addl	r65,-8148,r1; nop.m	0x0; addl	r66,5,r0 }
	{ st8	[r56],r44; nop.m	0x0; adds	r64,0x0,r0; }
	{ ld8	r65,[r65]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ ld4	r14,[r58]; adds	r1,0x0,r62; adds	r36,0x0,r8; }
	{ nop.m	0x0; and	r64,r53,r14; nop.i	0x0; }
	{ nop.m	0x0; extr.u	r64,r64,8,8; br.call.sptk.many	b0,signal_name; }
	{ adds	r1,0x0,r62; adds	r67,0x0,r36; addl	r65,1,r0 }
	{ addl	r66,64,r0; adds	r68,0x0,r8; addl	r64,19020,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C440; }
	{ nop.m	0x0; adds	r1,0x0,r62; nop.i	0x0 }
	{ ld8	r36,[r44]; nop.m	0x0; br.cond.sptk.few	4000000000078C90; }

l4000000000078FF0:
	{ nop.m	0x0; addl	r14,7444,r1; sxt4	r32,r32 }
	{ addl	r66,-8188,r1; adds	r64,0x0,r34; addl	r65,1,r0; }
	{ ld8	r14,[r14]; ld8	r66,[r66]; nop.i	0x0; }
	{ shladd	r14,r32,0x3,r14; ld8	r14,[r14]; nop.i	0x0; }
	{ adds	r14,0x8,r14; ld8	r14,[r14]; nop.i	0x0; }
	{ adds	r14,0x8,r14; ld4	r67,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r67,r67; br.call.sptk.many	b0,fn400000000001C040; }
	{ adds	r1,0x0,r62; mov	pr,r63,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r61; }
	{ nop.m	0x0; mov.spnt	b0,r60,4000000000079070; br.ret	b0; }

;; fn4000000000079080: 4000000000079080
;;   Called from:
;;     400000000007A24C (in fn400000000007A100)
fn4000000000079080 proc
	{ alloc	r37,ar.pfs,0xA,0x0,0x7; mov	r36,b4; adds	r32,0x14,r32 }
	{ adds	r38,0x0,r1; cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r34; (p06) br.cond.dpnt.few	40000000000790D0; }

l40000000000790A0:
	{ ld4	r14,[r32]; adds	r8,0x0,r0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r34,r14; mov.spnt	b0,r36,40000000000790B0 }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	40000000000790D0; br.ret	b0 }

l40000000000790CC:
	{ cmp.lt	p00,p09,r33,r0; (p01) cmp.eq	p59,p19,r127,r107; zxt1	r96,r64 }

l40000000000790D0:
	{ addl	r14,-10260,r1; adds	r39,0x0,r35; adds	r40,0x0,r33; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r41,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn40000000000780C0; }
	{ adds	r8,0x0,r0; adds	r1,0x0,r38; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,4000000000079110; br.ret	b0; }
4000000000079120 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000079130 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000079140: 4000000000079140
;;   Called from:
;;     4000000000079CFC (in fn4000000000079240)
;;     400000000007AC9C (in fn400000000007A7C0)
;;     400000000007ADAC (in fn400000000007A7C0)
;;     400000000007B7CC (in delete_job)
;;     400000000008114C (in wait_for_job)
;;     400000000008193C (in wait_for_background_pids)
;;     4000000000081BCC (in wait_for_background_pids)
;;     4000000000081BCC (in wait_for_background_pids)
;;     400000000008229C (in start_job)
fn4000000000079140 proc
	{ addl	r14,7444,r1; nop.m	0x0; sxt4	r32,r32; }
	{ ld8	r14,[r14]; shladd	r14,r32,0x3,r14; nop.i	0x0; }
	{ ld8	r14,[r14]; adds	r14,0x8,r14; nop.i	0x0; }
	{ nop.m	0x0; ld8	r15,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r15; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000079220; }

l4000000000079190:
	{ nop.m	0x0; ld8	r8,[r15]; nop.i	0x0; }
	{ cmp.eq	p07,p06,r8,r15; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000079210; }

l40000000000791B0:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	4000000000079200; }

l40000000000791C0:
	{ nop.m	0x0; ld8	r14,[r8]; nop.i	0x0; }
	{ cmp.eq	p07,p06,r14,r15; nop.i	0x0; (p07) br.ret	b0; }

l40000000000791E0:
	{ nop.m	0x0; adds	r8,0x0,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	40000000000791C0 }

l4000000000079200:
	{ nop.m	0x0; nop.i	0x0; br.ret	b0; }

l4000000000079210:
	{ nop.m	0x0; nop.i	0x0; br.ret	b0; }

l4000000000079220:
	{ nop.m	0x0; adds	r8,0x0,r0; br.ret	b0; }
4000000000079230 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000079240: 4000000000079240
;;   Called from:
;;     400000000007E37C (in fn400000000007D580)
;;     400000000007EC2C (in notify_and_cleanup)
fn4000000000079240 proc
	{ alloc	r54,ar.pfs,0x1D,0x0,0x18; adds	r12,0xFFFFFFFFFFFFFF00,r12; nop.b	0x0 }
	{ addl	r38,-20676,r1; addl	r37,7444,r1; mov	r53,b5; }
	{ nop.m	0x0; nop.m	0x0; adds	r55,0x0,r1 }
	{ addl	r41,7484,r1; ld8	r14,[r37]; nop.i	0x0; }
	{ adds	r32,0x1C,r38; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	40000000000794A0; }

l4000000000079290:
	{ nop.m	0x0; ld4	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000794A0 }

l40000000000792B0:
	{ nop.m	0x0; ld8	r15,[r41]; adds	r56,0x90,r12 }
	{ adds	r33,0x0,r0; adds	r46,0x0,r0; addl	r51,128,r0; }
	{ cmp.eq	p06,p07,0x0,r15; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000079B30; }

l40000000000792E0:
	{ adds	r38,0x1C,r38; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r55; nop.m	0x0; adds	r56,0x90,r12 }
	{ addl	r57,17,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B400; }
	{ addl	r57,22,r0; nop.m	0x0; adds	r1,0x0,r55 }
	{ adds	r56,0x90,r12; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B400; }
	{ adds	r1,0x0,r55; adds	r56,0x10,r12; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r55; adds	r56,0x0,r0; nop.i	0x0 }
	{ adds	r57,0x90,r12; adds	r58,0x10,r12; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r55; ld4	r14,[r32]; adds	r32,0x0,r0; }
	{ addl	r42,6496,r1; addl	r45,6512,r1; addl	r47,-10652,r1 }
	{ addl	r52,6648,r1; addl	r48,9028,r1; addl	r43,5868,r1; }
	{ nop.m	0x0; addl	r50,5872,r1; addl	r49,7444,r1 }
	{ cmp4.lt	p06,p07,0x0,r14; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000079450; }

l40000000000793B0:
	{ ld8	r47,[r47]; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000793E0:
	{ ld8	r14,[r37]; add	r14,r14,r33; nop.i	0x0; }
	{ nop.m	0x0; ld8	r34,[r14]; nop.i	0x0; }
	{ adds	r36,0x18,r34; cmp.eq	p06,p07,0x0,r34; (p06) br.cond.dpnt.few	4000000000079430; }

l4000000000079410:
	{ nop.m	0x0; ld4	r35,[r36]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r35,0x1; (p07) br.cond.dpnt.few	40000000000794C0 }

l4000000000079430:
	{ adds	r32,0x1,r32; ld4	r14,[r38]; adds	r33,0x8,r33; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r32,r14; (p06) br.cond.dptk.few	40000000000793E0 }

l4000000000079450:
	{ ld8	r14,[r41]; nop.m	0x0; addl	r56,2,r0 }
	{ adds	r57,0x10,r12; nop.m	0x0; adds	r58,0x0,r0; }
	{ cmp.eq	p07,p06,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000079BD0; }

l4000000000079480:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r55; nop.m	0x0; nop.i	0x0 }

l40000000000794A0:
	{ nop.m	0x0; mov.i	ar.pfs,r54; mov.spnt	b0,r53,40000000000794A0 }
	{ nop.m	0x0; adds	r12,0x100,r12; br.ret	b0; }

l40000000000794C0:
	{ adds	r56,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn4000000000077E80; }
	{ ld4	r15,[r42]; adds	r39,0x0,r8; adds	r1,0x0,r55; }
	{ cmp4.eq	p06,p07,0x0,r15; and	r40,0x7F,r39; (p07) adds	r34,0x14,r34; }

l40000000000794F0:
	{ (p07) ld4	r14,[r34]; nop.i	0x0; (p07) br.cond.dptk.few	4000000000079530 }

l40000000000794F6:
	{ chk.a.nc	f0,3FFFFFFFFF079CF6; Invalid; nop }

l4000000000079500:
	{ adds	r44,0x1,r40; adds	r34,0x14,r34; extr.u	r44,r44,1,7 }
	{ nop.m	0x0; ld4	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,0x0,r44; (p06) br.cond.dpnt.few	4000000000079700 }

l4000000000079530:
	{ nop.m	0x0; ld4	r16,[r43]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r16; (p06) br.cond.dptk.few	40000000000795F0 }

l4000000000079550:
	{ nop.m	0x0; ld4	r16,[r45]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p09,p08,0x0,r16; (p09) br.cond.dptk.few	40000000000795F0 }

l4000000000079570:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x4,r14; (p06) br.cond.dptk.few	4000000000079430 }

l4000000000079580:
	{ nop.m	0x0; ld4	r14,[r45]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	4000000000079CF0 }

l40000000000795A0:
	{ nop.m	0x0; or	r35,0x2,r35; nop.i	0x0; }
	{ st4	[r35],r36; nop.m	0x0; nop.i	0x0 }

l40000000000795C0:
	{ adds	r32,0x1,r32; ld4	r14,[r38]; adds	r33,0x8,r33; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r32,r14; (p06) br.cond.dptk.few	40000000000793E0 }

l40000000000795E0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000079450 }

l40000000000795F0:
	{ nop.m	0x0; cmp4.eq	p09,p08,0x2,r15; (p09) br.cond.dpnt.few	4000000000079680; }

l4000000000079600:
	{ cmp4.eq	p08,p09,0x2,r14; nop.i	0x0; (p08) br.cond.dpnt.few	40000000000798E0; }

l4000000000079610:
	{ nop.m	0x0; cmp4.lt	p08,p09,0x2,r14; (p08) br.cond.dptk.few	40000000000796C0 }

l4000000000079620:
	{ cmp4.eq	p06,p07,0x1,r14; addl	r56,-8036,r1; (p06) br.cond.dpnt.few	4000000000079430; }

l4000000000079630:
	{ ld8	r56,[r56]; br.call.sptk.many	b0,programming_error; nop.b	0x0; }
	{ adds	r1,0x0,r55; nop.m	0x0; nop.i	0x0 }

l4000000000079650:
	{ adds	r32,0x1,r32; ld4	r14,[r38]; adds	r33,0x8,r33; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r32,r14; (p06) br.cond.dptk.few	40000000000793E0 }

l4000000000079670:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000079450 }

l4000000000079680:
	{ nop.m	0x0; ld4	r15,[r48]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p08,p09,r15,0x2; (p08) br.cond.dptk.few	4000000000079600 }

l40000000000796A0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x4,r14; (p06) br.cond.dptk.few	4000000000079430 }

l40000000000796B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000079580; }

l40000000000796C0:
	{ cmp4.eq	p08,p09,0x4,r14; addl	r56,-8036,r1; (p08) br.cond.dpnt.few	4000000000079750; }

l40000000000796D0:
	{ cmp4.eq	p06,p07,0x8,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000079430; }

l40000000000796E0:
	{ ld8	r56,[r56]; nop.i	0x0; br.call.sptk.many	b0,programming_error; }
	{ nop.m	0x0; adds	r1,0x0,r55; br.cond.sptk.few	4000000000079650 }

l4000000000079700:
	{ cmp4.eq	p07,p06,0x4,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000079E70; }

l4000000000079710:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2,r14; (p07) br.cond.dptk.few	4000000000079530 }

l4000000000079720:
	{ adds	r32,0x1,r32; ld4	r14,[r38]; adds	r33,0x8,r33; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r32,r14; (p06) br.cond.dptk.few	40000000000793E0 }

l4000000000079740:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000079450 }

l4000000000079750:
	{ nop.m	0x0; ld4	r14,[r45]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p09,p08,0x0,r14; (p08) br.cond.dptk.few	40000000000799E0; }

l4000000000079770:
	{ nop.m	0x0; cmp4.eq	p08,p09,0x0,r40; (p08) br.cond.dptk.few	4000000000079C10; }

l4000000000079780:
	{ adds	r44,0x1,r40; cmp4.eq	p09,p08,0x2,r40; extr.u	r14,r44,1,7; }
	{ cmp4.lt	p07,p06,0x0,r14; (p08) addl	r14,1,r0; (p06) br.cond.dpnt.few	40000000000797D0; }

l400000000007979C:
	{ (p02) cmp.eq	p00,p03,r64,r33; (p16) cmp.lt	p03,p60,0x4A,r97; (p01) cmp4.eq.or.andcm	p00,p16,r0,r64 }

l40000000000797A0:
	{ cmp4.eq	p07,p06,0xD,r40; (p09) adds	r14,0x0,r0; (p06) addl	r15,1,r0; }

l40000000000797AC:
	{ cmp4.eq.or.andcm	p00,p43,r0,r72; (p01) cmp.lt	p00,p16,r0,r64; (p33) epc; }

l40000000000797B0:
	{ (p07) adds	r15,0x0,r0; and	r14,r14,r15; nop.i	0x0; }

l40000000000797B6:
	{ Invalid; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	f0,3FFFFFFFFFD3D0A6; nop; break.i	0x80000 }

l40000000000797D0:
	{ nop.m	0x0; tbit.z	p07,p06,r35,0x0; (p06) br.cond.dptk.few	4000000000079A10 }

l40000000000797E0:
	{ ld4	r16,[r43]; nop.i	0x0; cmp4.eq	p07,p06,0x0,r16; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000079800:
	{ nop.m	0x0; nop.i	0x0; (p07) br.cond.dptk.few	4000000000079AE0; }

l4000000000079810:
	{ addl	r35,-10652,r1; nop.m	0x0; cmp.eq	p07,p06,0x0,r46 }
	{ adds	r56,0x0,r32; nop.m	0x0; adds	r57,0x0,r0; }
	{ ld8	r35,[r35]; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000079F90; }

l4000000000079840:
	{ ld8	r58,[r47]; br.call.sptk.many	b0,fn40000000000780C0; nop.b	0x0; }
	{ adds	r1,0x0,r55; nop.m	0x0; nop.i	0x0 }

l4000000000079860:
	{ ld8	r14,[r37]; adds	r56,0x0,r46; add	r14,r14,r33; }
	{ ld8	r34,[r14]; adds	r36,0x18,r34; nop.i	0x0; }
	{ ld8	r57,[r34]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A540; }
	{ nop.m	0x0; adds	r1,0x0,r55; cmp4.eq	p07,p06,0x0,r8 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000079D40; }

l40000000000798B0:
	{ ld4	r35,[r36]; nop.m	0x0; nop.i	0x0; }

l40000000000798C0:
	{ nop.m	0x0; or	r35,0x2,r35; nop.i	0x0; }
	{ st4	[r35],r36; nop.i	0x0; br.cond.sptk.few	40000000000795C0 }

l40000000000798E0:
	{ nop.m	0x0; addl	r34,-10652,r1; addl	r56,10,r0 }
	{ nop.m	0x0; ld8	r57,[r47]; nop.i	0x0; }
	{ ld8	r34,[r34]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BD80; }
	{ cmp.eq	p07,p06,0x0,r46; adds	r1,0x0,r55; nop.i	0x0 }
	{ adds	r56,0x0,r32; adds	r57,0x0,r0; (p07) br.cond.dpnt.few	4000000000079EB0; }

l4000000000079930:
	{ ld8	r58,[r34]; br.call.sptk.many	b0,fn40000000000780C0; nop.b	0x0; }
	{ adds	r1,0x0,r55; nop.m	0x0; nop.i	0x0 }

l4000000000079950:
	{ ld8	r14,[r37]; adds	r56,0x0,r46; add	r14,r14,r33; }
	{ nop.m	0x0; ld8	r34,[r14]; nop.i	0x0; }
	{ ld8	r57,[r34]; adds	r34,0x18,r34; br.call.sptk.many	b0,fn400000000001A540; }
	{ adds	r1,0x0,r55; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dpnt.few	4000000000079C40; }

l4000000000079990:
	{ ld4	r14,[r34]; nop.i	0x0; or	r14,0x2,r14; }
	{ st4	[r14],r34; nop.m	0x0; nop.i	0x0 }

l40000000000799B0:
	{ adds	r32,0x1,r32; ld4	r14,[r38]; adds	r33,0x8,r33; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r32,r14; (p06) br.cond.dptk.few	40000000000793E0 }

l40000000000799D0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000079450 }

l40000000000799E0:
	{ nop.m	0x0; tbit.z	p08,p09,r35,0x0; (p08) br.cond.dptk.few	4000000000079800; }

l40000000000799F0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r40; (p06) br.cond.dptk.few	40000000000795A0 }

l4000000000079A00:
	{ adds	r44,0x1,r40; nop.m	0x0; nop.i	0x0; }

l4000000000079A10:
	{ nop.m	0x0; extr.u	r44,r44,1,7; nop.i	0x0; }
	{ cmp4.lt	p06,p07,0x0,r44; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000079AE0; }

l4000000000079A30:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2,r40; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0xD,r40; (p07) br.cond.dptk.few	4000000000079AE0 }

l4000000000079A50:
	{ ld8	r34,[r47]; nop.m	0x0; adds	r56,0x0,r40 }
	{ and	r39,r39,r51; nop.m	0x0; br.call.sptk.many	b0,fn4000000000077FC0; }
	{ adds	r1,0x0,r55; nop.m	0x0; adds	r56,0x0,r8 }
	{ adds	r57,0x0,r34; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C260; }
	{ cmp4.eq	p06,p07,0x0,r39; nop.m	0x0; adds	r1,0x0,r55 }
	{ addl	r56,10,r0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000079DE0; }

l4000000000079AB0:
	{ ld8	r57,[r47]; br.call.sptk.many	b0,fn400000000001BD80; nop.b	0x0; }
	{ adds	r1,0x0,r55; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000079AE0:
	{ ld8	r14,[r37]; add	r14,r14,r33; nop.i	0x0; }
	{ ld8	r34,[r14]; nop.i	0x0; adds	r36,0x18,r34; }
	{ ld4	r35,[r36]; nop.m	0x0; nop.i	0x0; }

l4000000000079B10:
	{ nop.m	0x0; or	r35,0x2,r35; nop.i	0x0; }
	{ st4	[r35],r36; nop.i	0x0; br.cond.sptk.few	40000000000795C0 }

l4000000000079B30:
	{ addl	r15,7472,r1; addl	r42,6496,r1; addl	r45,6512,r1 }
	{ addl	r47,-10652,r1; addl	r52,6648,r1; addl	r48,9028,r1; }
	{ ld4	r16,[r15]; adds	r33,0x0,r0; adds	r46,0x0,r0 }
	{ adds	r32,0x0,r0; addl	r51,128,r0; addl	r43,5868,r1; }
	{ adds	r16,0x1,r16; nop.m	0x0; addl	r50,5872,r1 }
	{ adds	r38,0x1C,r38; addl	r49,7444,r1; cmp4.lt	p06,p07,0x0,r14; }
	{ st4	[r16],r15; nop.m	0x0; nop.i	0x0 }
	{ ld8	r47,[r47]; nop.i	0x0; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dptk.few	40000000000793E0 }

l4000000000079BC0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000079450 }

l4000000000079BD0:
	{ addl	r14,7472,r1; ld4	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; adds	r15,0xFFFFFFFFFFFFFFFF,r15; nop.i	0x0; }
	{ st4	[r15],r14; mov.i	ar.pfs,r54; mov.spnt	b0,r53,4000000000079BF0 }
	{ nop.m	0x0; adds	r12,0x100,r12; br.ret	b0 }

l4000000000079C10:
	{ nop.m	0x0; tbit.z	p09,p08,r35,0x0; (p09) br.cond.dptk.few	4000000000079800 }

l4000000000079C20:
	{ nop.m	0x0; or	r35,0x2,r35; nop.i	0x0; }
	{ st4	[r35],r36; nop.i	0x0; br.cond.sptk.few	40000000000795C0 }

l4000000000079C40:
	{ addl	r57,-8044,r1; ld8	r34,[r47]; addl	r58,5,r0 }
	{ nop.m	0x0; adds	r56,0x0,r0; nop.i	0x0; }
	{ ld8	r57,[r57]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r55; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r56,0x0,r46; nop.m	0x0; br.call.sptk.many	b0,polite_directory_format; }
	{ adds	r1,0x0,r55; adds	r56,0x0,r34; addl	r57,1,r0 }
	{ adds	r58,0x0,r35; adds	r59,0x0,r8; br.call.sptk.many	b0,fn400000000001C040; }
	{ ld8	r14,[r49]; adds	r1,0x0,r55; add	r14,r14,r33; }
	{ ld8	r34,[r14]; adds	r34,0x18,r34; nop.i	0x0; }
	{ ld4	r14,[r34]; or	r14,0x2,r14; nop.i	0x0; }
	{ st4	[r14],r34; nop.i	0x0; br.cond.sptk.few	40000000000799B0 }

l4000000000079CF0:
	{ adds	r56,0x0,r32; or	r35,0x2,r35; br.call.sptk.many	b0,fn4000000000079140; }
	{ adds	r8,0x8,r8; ld4	r14,[r50]; adds	r1,0x0,r55; }
	{ nop.m	0x0; ld4	r15,[r8]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,r15,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000079430; }

l4000000000079D30:
	{ st4	[r35],r36; nop.i	0x0; br.cond.sptk.few	40000000000795C0 }

l4000000000079D40:
	{ addl	r57,-8044,r1; ld8	r34,[r35]; addl	r58,5,r0 }
	{ nop.m	0x0; adds	r56,0x0,r0; nop.i	0x0; }
	{ ld8	r57,[r57]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r55; nop.m	0x0; adds	r35,0x0,r8 }
	{ adds	r56,0x0,r46; nop.m	0x0; br.call.sptk.many	b0,polite_directory_format; }
	{ adds	r1,0x0,r55; adds	r56,0x0,r34; adds	r58,0x0,r35 }
	{ addl	r57,1,r0; adds	r59,0x0,r8; br.call.sptk.many	b0,fn400000000001C040; }
	{ ld8	r14,[r49]; adds	r1,0x0,r55; add	r14,r14,r33; }
	{ ld8	r34,[r14]; adds	r36,0x18,r34; nop.i	0x0; }
	{ ld4	r35,[r36]; nop.i	0x0; br.cond.sptk.few	40000000000798C0 }

l4000000000079DE0:
	{ addl	r14,-10652,r1; nop.m	0x0; addl	r57,-8052,r1 }
	{ addl	r58,5,r0; nop.m	0x0; adds	r56,0x0,r0; }
	{ ld8	r14,[r14]; ld8	r57,[r57]; nop.i	0x0; }
	{ ld8	r34,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r55; adds	r56,0x0,r34; nop.i	0x0 }
	{ adds	r58,0x0,r8; addl	r57,1,r0; br.call.sptk.many	b0,fn400000000001C040; }
	{ adds	r1,0x0,r55; nop.m	0x0; addl	r56,10,r0 }
	{ ld8	r57,[r47]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BD80; }
	{ nop.m	0x0; adds	r1,0x0,r55; br.cond.sptk.few	4000000000079AE0 }

l4000000000079E70:
	{ nop.m	0x0; tbit.z	p06,p07,r35,0x0; (p07) br.cond.dptk.few	4000000000079530 }

l4000000000079E80:
	{ adds	r32,0x1,r32; ld4	r14,[r38]; adds	r33,0x8,r33; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r32,r14; (p06) br.cond.dptk.few	40000000000793E0 }

l4000000000079EA0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000079450 }

l4000000000079EB0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000773C0; }
	{ nop.m	0x0; adds	r1,0x0,r55; adds	r46,0x0,r8 }
	{ ld8	r58,[r34]; adds	r56,0x0,r32; adds	r57,0x0,r0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000780C0; }
	{ adds	r1,0x0,r55; cmp.eq	p07,p06,0x0,r46; (p06) br.cond.spnt.few	4000000000079950; }

l4000000000079F00:
	{ ld8	r14,[r37]; add	r14,r14,r33; nop.i	0x0; }
	{ ld8	r34,[r14]; adds	r34,0x18,r34; nop.i	0x0; }
	{ ld4	r14,[r34]; or	r14,0x2,r14; nop.i	0x0; }
	{ st4	[r14],r34; nop.i	0x0; br.cond.sptk.few	40000000000799B0 }

l4000000000079F40:
	{ adds	r56,0x0,r40; nop.i	0x0; br.call.sptk.many	b0,signal_is_trapped; }
	{ adds	r1,0x0,r55; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	400000000007A000; }

l4000000000079F60:
	{ ld8	r14,[r37]; add	r14,r14,r33; nop.i	0x0; }
	{ ld8	r14,[r14]; adds	r14,0x18,r14; nop.i	0x0; }
	{ ld4	r35,[r14]; nop.i	0x0; br.cond.sptk.few	40000000000797D0 }

l4000000000079F90:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000773C0; }
	{ adds	r1,0x0,r55; adds	r46,0x0,r8; adds	r56,0x0,r32 }
	{ adds	r57,0x0,r0; ld8	r58,[r47]; br.call.sptk.many	b0,fn40000000000780C0; }
	{ adds	r1,0x0,r55; cmp.eq	p07,p06,0x0,r46; (p06) br.cond.spnt.few	4000000000079860; }

l4000000000079FD0:
	{ ld8	r14,[r37]; add	r14,r14,r33; nop.i	0x0; }
	{ ld8	r34,[r14]; adds	r36,0x18,r34; nop.i	0x0; }
	{ ld4	r35,[r36]; nop.i	0x0; br.cond.sptk.few	4000000000079B10 }

l400000000007A000:
	{ addl	r57,-8060,r1; ld8	r34,[r47]; adds	r56,0x0,r0 }
	{ nop.m	0x0; addl	r58,5,r0; nop.i	0x0; }
	{ ld8	r57,[r57]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r55; adds	r35,0x0,r8; br.call.sptk.many	b0,get_name_for_error; }
	{ ld4	r14,[r52]; adds	r1,0x0,r55; adds	r58,0x0,r35 }
	{ adds	r59,0x0,r8; adds	r56,0x0,r34; addl	r57,1,r0; }
	{ cmp4.eq	p07,p06,0x0,r14; (p06) adds	r60,0x0,r14; nop.i	0x0; }

l400000000007A06C:
	{ nop; zxt4	r0,r0; break.i	0x1000 }

l400000000007A076:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; nop; (p16) nop }
	{ (p29) fwb; Invalid; (p32) nop }
	{ Invalid; (p07) nop; (p32) br.call.sptk.few	b0,b0 }
	{ Invalid; nop; (p48) nop }
	{ break.m	0x4000; nop; break.i	0x80000 }
400000000007A0D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007A0E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007A0F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn400000000007A100: 400000000007A100
;;   Called from:
;;     400000000007ECBC (in list_all_jobs)
;;     400000000007ED3C (in list_running_jobs)
;;     400000000007EDBC (in list_stopped_jobs)
fn400000000007A100 proc
	{ alloc	r41,ar.pfs,0xF,0x0,0xB; adds	r12,0xFFFFFFFFFFFFFF00,r12; nop.b	0x0 }
	{ addl	r39,-20676,r1; mov	r40,b0; adds	r42,0x0,r1; }
	{ nop.m	0x0; adds	r36,0x0,r0; adds	r39,0x1C,r39 }
	{ adds	r8,0x0,r36; ld4	r14,[r39]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000007A170; }

l400000000007A150:
	{ nop.m	0x0; mov.i	ar.pfs,r41; mov.spnt	b0,r40,400000000007A150 }
	{ nop.m	0x0; adds	r12,0x100,r12; br.ret	b0; }

l400000000007A170:
	{ addl	r37,7444,r1; adds	r43,0x90,r12; adds	r35,0x0,r0 }
	{ adds	r34,0x0,r0; adds	r38,0x0,r39; br.call.sptk.many	b0,fn400000000001BC20; }
	{ addl	r44,17,r0; nop.m	0x0; adds	r1,0x0,r42 }
	{ adds	r43,0x90,r12; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B400; }
	{ adds	r1,0x0,r42; adds	r43,0x10,r12; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r42; adds	r43,0x0,r0; nop.i	0x0 }
	{ adds	r44,0x90,r12; adds	r45,0x10,r12; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ ld4	r14,[r39]; nop.m	0x0; adds	r1,0x0,r42; }
	{ nop.m	0x0; cmp4.lt	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	400000000007A290; }

l400000000007A200:
	{ ld8	r14,[r37]; adds	r46,0x0,r34; adds	r44,0x0,r32 }
	{ adds	r34,0x1,r34; adds	r45,0x0,r33; add	r14,r14,r35 }
	{ adds	r35,0x8,r35; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r14; adds	r43,0x0,r14; (p07) br.cond.dpnt.few	400000000007A270; }

l400000000007A240:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000079080; }
	{ nop.m	0x0; adds	r1,0x0,r42; adds	r36,0x0,r8 }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r8; (p07) br.cond.dpnt.few	400000000007A2A0 }

l400000000007A270:
	{ nop.m	0x0; ld4	r14,[r38]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r34,r14; (p06) br.cond.dptk.few	400000000007A200 }

l400000000007A290:
	{ adds	r36,0x0,r0; nop.m	0x0; nop.i	0x0 }

l400000000007A2A0:
	{ addl	r43,2,r0; nop.m	0x0; adds	r44,0x10,r12 }
	{ adds	r45,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r8,0x0,r36; adds	r1,0x0,r42; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.spnt	b0,r40,400000000007A2D0; nop.i	0x0 }
	{ adds	r12,0x100,r12; nop.m	0x0; br.ret	b0; }
400000000007A2F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn400000000007A300: 400000000007A300
;;   Called from:
;;     400000000007A78C (in fn400000000007A5C0)
;;     400000000007DA0C (in fn400000000007D580)
;;     40000000000824FC (in start_job)
fn400000000007A300 proc
	{ alloc	r36,ar.pfs,0x8,0x0,0x6; addl	r33,-20676,r1; mov	r35,b3 }
	{ adds	r37,0x0,r1; nop.m	0x0; nop.i	0x0; }
	{ adds	r15,0x30,r33; ld4	r14,[r15]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,r32,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000007A4C0; }

l400000000007A340:
	{ (p06) adds	r16,0x34,r33; (p06) st4	[r32],r15; nop.i	0x0; }

l400000000007A346:
	{ mf.a; addl	r0,0,r1; (p01) nop; }

l400000000007A34C:
	{ Invalid; Invalid; break.i	0x1000 }

l400000000007A356:
	{ break.m	0x4000; nop; (p32) nop }

l400000000007A360:
	{ addl	r34,7444,r1; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r14; sxt4	r14,r14; }

l400000000007A362:
	{ (p18) cmp.ne.or.andcm	p00,p48,r14,r18; (p47) mov	pr,r97,0x186; brp.sptk	400000000007A792; }
	{ (p32) break.m	0x20308; cmp.lt	p32,p01,r0,r96; Invalid }

l400000000007A376:
	{ chk.a.nc	f0,3FFFFFFFFF07AB76; nop; (p48) nop }

l400000000007A380:
	{ ld8	r15,[r34]; shladd	r14,r14,0x3,r15; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; adds	r14,0x14,r14; (p06) br.cond.dpnt.few	400000000007A3D0; }

l400000000007A3B0:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2,r14; (p06) br.cond.dpnt.few	400000000007A470 }

l400000000007A3D0:
	{ nop.m	0x0; sxt4	r14,r32; shladd	r15,r14,0x3,r15; }
	{ ld8	r14,[r15]; adds	r14,0x14,r14; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x2,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000007A500; }

l400000000007A410:
	{ cmp4.eq	p07,p06,0x1,r14; (p06) adds	r14,0x1C,r33; (p07) adds	r38,0x0,r32 }

l400000000007A41C:
	{ cmp4.eq.or.andcm	p32,p42,r0,r66; nop }

l400000000007A420:
	{ (p07) addl	r39,1,r0; nop.m	0x0; (p06) addl	r39,1,r0 }

l400000000007A426:
	{ adds	r0,0xFFFFFFFFFFFFE000,r1; (p19) nop; add	r0,r0,r32 }

l400000000007A430:
	{ nop.m	0x0; (p06) ld4	r38,[r14]; br.call.sptk.many	b0,fn4000000000077200; }

l400000000007A43C:
	{ (p46) nop; cmp.lt	p32,p16,r9,r64; (p48) nop }
	{ (p02) nop; nop; (p04) epc }

l400000000007A450:
	{ nop.m	0x0; adds	r33,0x34,r33; nop.i	0x0; }
	{ st4	[r8],r33; nop.m	0x0; nop.i	0x0 }

l400000000007A470:
	{ nop.m	0x0; mov.i	ar.pfs,r36; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r35,400000000007A480; br.ret	b0 }

l400000000007A490:
	{ adds	r14,0x30,r33; adds	r33,0x34,r33; mov.i	ar.pfs,r36; }
	{ ld4	r14,[r14]; nop.m	0x0; mov.spnt	b0,r35,400000000007A4A0; }
	{ st4	[r14],r33; nop.i	0x0; br.ret	b0 }

l400000000007A4C0:
	{ adds	r15,0x34,r33; ld4	r15,[r15]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,r15,r32; (p07) addl	r34,7444,r1; nop.i	0x0; }

l400000000007A4DC:
	{ cmp4.eq.or.andcm	p00,p49,r1,r0; Invalid; mov	pr,r32,0x0 }

l400000000007A4E6:
	{ chk.a.nc	f0,3FFFFFFFFF07ACE6; nop; nop }

l400000000007A4F0:
	{ adds	r32,0x0,r14; adds	r14,0x0,r15; br.cond.sptk.few	400000000007A360; }

l400000000007A500:
	{ adds	r38,0x0,r32; addl	r39,2,r0; br.call.sptk.many	b0,fn4000000000077200; }
	{ adds	r1,0x0,r37; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p06) br.cond.dptk.few	400000000007A450 }

l400000000007A520:
	{ adds	r15,0x30,r33; ld8	r14,[r34]; nop.i	0x0; }
	{ ld4	r32,[r15]; nop.m	0x0; sxt4	r15,r32; }
	{ shladd	r14,r15,0x3,r14; ld8	r14,[r14]; nop.i	0x0; }
	{ adds	r14,0x14,r14; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x1,r14; (p06) adds	r14,0x1C,r33; (p07) adds	r38,0x0,r32 }

l400000000007A56C:
	{ cmp4.eq.or.andcm	p32,p42,r0,r66; nop }

l400000000007A570:
	{ (p07) addl	r39,1,r0; nop.m	0x0; (p06) addl	r39,1,r0 }

l400000000007A576:
	{ adds	r0,0xFFFFFFFFFFFFE000,r1; (p19) nop; add	r0,r0,r32 }

l400000000007A580:
	{ nop.m	0x0; (p06) ld4	r38,[r14]; br.call.sptk.many	b0,fn4000000000077200; }

l400000000007A58C:
	{ (p36) nop; cmp.lt	p32,p16,r9,r64; (p48) mov	pr,r98,0xEE3E }
	{ Invalid; break.i	0x1000; break.i	0x1000 }

l400000000007A5A0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000007A490; }
400000000007A5B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn400000000007A5C0: 400000000007A5C0
;;   Called from:
;;     400000000007B7BC (in delete_job)
;;     400000000007E3BC (in fn400000000007D580)
;;     400000000008213C (in start_job)
;;     400000000008410C (in stop_pipeline)
;;     400000000008455C (in stop_pipeline)
;;     40000000000845AC (in stop_pipeline)
fn400000000007A5C0 proc
	{ alloc	r36,ar.pfs,0x8,0x0,0x6; addl	r33,-20676,r1; mov	r35,b3 }
	{ adds	r37,0x0,r1; nop.m	0x0; nop.i	0x0; }
	{ adds	r14,0x1C,r33; ld4	r38,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r38; (p06) br.cond.dptk.few	400000000007A670 }

l400000000007A600:
	{ adds	r14,0x30,r33; ld4	r8,[r14]; addl	r14,7444,r1; }
	{ cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r8; sxt4	r15,r8; (p06) br.cond.dpnt.few	400000000007A670; }

l400000000007A620:
	{ ld8	r14,[r14]; shladd	r14,r15,0x3,r14; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; adds	r14,0x14,r14; (p06) br.cond.dpnt.few	400000000007A670; }

l400000000007A650:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2,r14; (p06) br.cond.dpnt.few	400000000007A770 }

l400000000007A670:
	{ adds	r14,0x34,r33; ld4	r8,[r14]; addl	r14,7444,r1; }
	{ cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r8; sxt4	r15,r8; (p06) br.cond.dpnt.few	400000000007A6E0; }

l400000000007A690:
	{ ld8	r14,[r14]; shladd	r14,r15,0x3,r14; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; adds	r14,0x14,r14; (p06) br.cond.dpnt.few	400000000007A6E0; }

l400000000007A6C0:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2,r14; (p06) br.cond.dpnt.few	400000000007A770 }

l400000000007A6E0:
	{ addl	r39,2,r0; adds	r33,0x1C,r33; br.call.sptk.many	b0,fn4000000000077200; }
	{ cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r8; adds	r1,0x0,r37; nop.i	0x0 }
	{ adds	r34,0xFFFFFFFFFFFFFFE4,r33; addl	r39,1,r0; (p07) br.cond.spnt.few	400000000007A770; }

l400000000007A710:
	{ ld4	r38,[r33]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000077200; }
	{ cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r8; nop.m	0x0; mov.i	ar.pfs,r36 }
	{ adds	r1,0x0,r37; nop.m	0x0; (p07) br.cond.spnt.few	400000000007A770; }

l400000000007A740:
	{ (p06) adds	r14,0x34,r34; (p06) adds	r34,0x30,r34; mov.spnt	b0,r35,400000000007A740; }

l400000000007A746:
	{ Invalid; nop; add	r0,r0,r32; }

l400000000007A74C:
	{ (p17) nop; mov	pr,r32,0x0; rfi }

l400000000007A75C:
	{ Invalid; Invalid; add	r0,r32,r0 }

l400000000007A766:
	{ break.m	0x4000; Invalid; nop }

l400000000007A770:
	{ adds	r32,0x0,r8; mov.spnt	b0,r35,400000000007A770; mov.i	ar.pfs,r36; }
	{ alloc	r2,ar.pfs,0x1,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn400000000007A300; }
400000000007A790 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
400000000007A7A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007A7B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn400000000007A7C0: 400000000007A7C0
;;   Called from:
;;     400000000007EB1C (in reap_dead_jobs)
;;     40000000000818BC (in wait_for_background_pids)
fn400000000007A7C0 proc
	{ alloc	r41,ar.pfs,0x10,0x0,0xD; adds	r12,0xFFFFFFFFFFFFFF00,r12; nop.b	0x0 }
	{ addl	r33,-20676,r1; mov	r43,pr; adds	r42,0x0,r1; }
	{ nop.m	0x0; nop.m	0x0; mov	r44,LC; }
	{ adds	r35,0x1C,r33; nop.m	0x0; mov	r40,b0; }
	{ nop.m	0x0; ld4	r14,[r35]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000007A850; }

l400000000007A820:
	{ nop.m	0x0; mov	pr,r43,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.i	LC,r44; mov.spnt	b0,r40,400000000007A830 }
	{ nop.m	0x0; adds	r12,0x100,r12; br.ret	b0; }

l400000000007A850:
	{ adds	r45,0x90,r12; nop.m	0x0; adds	r34,0x0,r0 }
	{ adds	r36,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BC20; }
	{ addl	r46,17,r0; nop.m	0x0; adds	r1,0x0,r42 }
	{ adds	r45,0x90,r12; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B400; }
	{ adds	r1,0x0,r42; adds	r45,0x10,r12; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r42; adds	r45,0x0,r0; nop.i	0x0 }
	{ adds	r46,0x90,r12; adds	r47,0x10,r12; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ nop.m	0x0; adds	r1,0x0,r42; nop.i	0x0 }
	{ ld4	r14,[r35]; cmp4.eq	p07,p06,0x0,r32; (p07) br.cond.dptk.few	400000000007A9F0; }

l400000000007A8E0:
	{ adds	r15,0xFFFFFFFFFFFFFFFF,r14; cmp4.lt	p06,p07,0x0,r14; nop.i	0x0 }
	{ addl	r14,6512,r1; addl	r16,5872,r1; (p07) br.cond.dpnt.few	400000000007A990; }

l400000000007A900:
	{ nop.m	0x0; nop.m	0x0; addp4	r15,r15,r0 }
	{ ld4	r36,[r16]; nop.m	0x0; addl	r16,7444,r1; }
	{ ld8	r35,[r16]; nop.m	0x0; mov.i	LC,r15; }
	{ ld4	r14,[r14]; nop.i	0x0; cmp4.eq	p17,p16,0x0,r14; }

l400000000007A940:
	{ nop.m	0x0; ld8	r33,[r35],8; nop.i	0x0; }
	{ adds	r14,0x14,r33; cmp.eq	p06,p07,0x0,r33; (p06) br.cond.dpnt.few	400000000007A980; }

l400000000007A960:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x4,r14; (p07) br.cond.dpnt.few	400000000007AC30 }

l400000000007A980:
	{ nop.m	0x0; adds	r34,0x1,r34; br.cloop.sptk.few	400000000007A940 }

l400000000007A990:
	{ addl	r45,2,r0; nop.m	0x0; adds	r46,0x10,r12 }
	{ adds	r47,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r42; nop.m	0x0; nop.i	0x0 }

l400000000007A9C0:
	{ nop.m	0x0; mov	pr,r43,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r41; }
	{ nop.m	0x0; mov.i	LC,r44; mov.spnt	b0,r40,400000000007A9D0 }
	{ nop.m	0x0; adds	r12,0x100,r12; br.ret	b0 }

l400000000007A9F0:
	{ cmp4.lt	p06,p07,0x0,r14; adds	r19,0xFFFFFFFFFFFFFFFF,r14; addl	r14,7444,r1; }
	{ (p07) adds	r35,0x0,r0; addp4	r19,r19,r0; (p07) br.cond.dpnt.few	400000000007AB00; }

l400000000007AA06:
	{ (p09) chk.a.clr	f19,3FFFFFFFFF07EA06; nop; break.b	0x80000 }

l400000000007AA10:
	{ nop.m	0x0; ld8	r17,[r14]; nop.i	0x0; }
	{ adds	r15,0x8,r17; nop.i	0x0; shladd	r19,r19,0x3,r15; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000007AA40:
	{ ld8	r14,[r17]; nop.m	0x0; adds	r17,0x0,r15; }
	{ adds	r16,0x14,r14; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	400000000007AA80; }

l400000000007AA60:
	{ nop.m	0x0; ld4	r16,[r16]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x4,r16; (p07) br.cond.dpnt.few	400000000007AAA0; }

l400000000007AA80:
	{ nop.m	0x0; cmp.eq	p07,p06,r19,r15; (p07) br.cond.dpnt.few	400000000007AAF0 }

l400000000007AA90:
	{ nop.m	0x0; adds	r15,0x8,r15; br.cond.sptk.few	400000000007AA40 }

l400000000007AAA0:
	{ adds	r14,0x8,r14; nop.m	0x0; adds	r16,0x0,r0; }
	{ ld8	r18,[r14]; nop.i	0x0; adds	r14,0x0,r18; }

l400000000007AAC0:
	{ ld8	r14,[r14]; nop.m	0x0; adds	r16,0x1,r16; }
	{ nop.m	0x0; cmp.eq	p07,p06,r14,r18; (p06) br.cond.dptk.few	400000000007AAC0; }

l400000000007AAE0:
	{ add	r36,r36,r16; cmp.eq	p07,p06,r19,r15; (p06) br.cond.dptk.few	400000000007AA90; }

l400000000007AAF0:
	{ nop.m	0x0; sxt4	r35,r36; nop.i	0x0 }

l400000000007AB00:
	{ ld8	r38,[r33]; addl	r37,-20676,r1; adds	r34,0x0,r0; }
	{ nop.m	0x0; cmp.lt	p07,p06,r38,r0; (p07) br.cond.dpnt.few	400000000007AE00; }

l400000000007AB20:
	{ adds	r33,0x1C,r33; cmp.lt	p07,p06,r38,r35; nop.i	0x0 }
	{ addl	r14,6512,r1; addl	r15,5872,r1; (p06) br.cond.dpnt.few	400000000007A990; }

l400000000007AB40:
	{ nop.m	0x0; ld4	r37,[r33]; nop.i	0x0; }
	{ cmp4.lt	p06,p07,0x0,r37; nop.i	0x0; (p07) br.cond.dpnt.few	400000000007A990; }

l400000000007AB60:
	{ nop.m	0x0; ld4	r39,[r15]; addl	r15,7444,r1; }
	{ nop.m	0x0; ld8	r35,[r15]; nop.i	0x0; }
	{ ld4	r14,[r14]; nop.i	0x0; cmp4.eq	p17,p16,0x0,r14; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000007ABA0:
	{ nop.m	0x0; ld8	r33,[r35],8; nop.i	0x0; }
	{ adds	r14,0x14,r33; cmp.eq	p06,p07,0x0,r33; (p06) br.cond.dpnt.few	400000000007ABE0; }

l400000000007ABC0:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x4,r14; (p07) br.cond.dpnt.few	400000000007ACF0 }

l400000000007ABE0:
	{ nop.m	0x0; adds	r34,0x1,r34; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r37,r34; (p06) br.cond.dptk.few	400000000007ABA0 }

l400000000007AC00:
	{ addl	r45,2,r0; nop.m	0x0; adds	r46,0x10,r12 }
	{ adds	r47,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.cond.sptk.few	400000000007A9C0 }

l400000000007AC30:
	{ nop.m	0x0; nop.i	0x0; (p17) br.cond.dpnt.few	400000000007AC90; }

l400000000007AC40:
	{ adds	r33,0x18,r33; ld4	r14,[r33]; nop.i	0x0; }
	{ nop.m	0x0; or	r14,0x2,r14; nop.i	0x0; }
	{ st4	[r14],r33; nop.m	0x0; nop.i	0x0 }

l400000000007AC70:
	{ nop.m	0x0; adds	r34,0x1,r34; br.cloop.sptk.few	400000000007A940 }

l400000000007AC80:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000007A990; }

l400000000007AC90:
	{ adds	r45,0x0,r34; adds	r33,0x18,r33; br.call.sptk.many	b0,fn4000000000079140; }
	{ adds	r8,0x8,r8; nop.m	0x0; adds	r1,0x0,r42; }
	{ nop.m	0x0; ld4	r14,[r8]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,r14,r36; nop.i	0x0; (p06) br.cond.dpnt.few	400000000007A980; }

l400000000007ACD0:
	{ ld4	r14,[r33]; or	r14,0x2,r14; nop.i	0x0; }
	{ st4	[r14],r33; nop.i	0x0; br.cond.sptk.few	400000000007AC70 }

l400000000007ACF0:
	{ adds	r14,0x8,r33; adds	r15,0x0,r0; (p17) br.cond.dpnt.few	400000000007ADA0; }

l400000000007AD00:
	{ ld8	r16,[r14]; nop.i	0x0; adds	r14,0x0,r16; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000007AD20:
	{ ld8	r14,[r14]; nop.m	0x0; adds	r15,0x1,r15; }
	{ nop.m	0x0; cmp.eq	p07,p06,r14,r16; (p06) br.cond.dptk.few	400000000007AD20 }

l400000000007AD40:
	{ sub	r36,r36,r15; adds	r33,0x18,r33; adds	r34,0x1,r34; }
	{ nop.m	0x0; sxt4	r14,r36; nop.i	0x0; }
	{ cmp.lt	p07,p06,r38,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000007A990; }

l400000000007AD70:
	{ ld4	r14,[r33]; cmp4.eq	p07,p06,r37,r34; or	r14,0x2,r14; }
	{ st4	[r14],r33; nop.i	0x0; (p06) br.cond.dptk.few	400000000007ABA0 }

l400000000007AD90:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000007AC00 }

l400000000007ADA0:
	{ adds	r45,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn4000000000079140; }
	{ adds	r8,0x8,r8; adds	r1,0x0,r42; adds	r15,0x0,r0; }
	{ nop.m	0x0; ld4	r14,[r8]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,r14,r39; adds	r14,0x8,r33; (p06) br.cond.dpnt.few	400000000007ABE0; }

l400000000007ADE0:
	{ nop.m	0x0; ld8	r16,[r14]; nop.i	0x0; }
	{ nop.m	0x0; adds	r14,0x0,r16; br.cond.sptk.few	400000000007AD20 }

l400000000007AE00:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,getmaxchild; }
	{ cmp.lt	p07,p06,r8,r0; nop.m	0x0; adds	r38,0x0,r8 }
	{ st8	[r8],r37; nop.m	0x0; adds	r1,0x0,r42; }
	{ (p07) addl	r14,32,r0; nop.m	0x0; (p07) addl	r38,32,r0; }

l400000000007AE36:
	{ chk.a.nc	f0,3FFFFFFFFF07B636; (p19) cmp4.eq.or.andcm	p32,p08,r0,r0; (p01) nop }

l400000000007AE40:
	{ (p07) st8	[r14],r37; nop.i	0x0; br.cond.sptk.few	400000000007AB20; }

l400000000007AE46:
	{ break.m	0x4000; nop; break.i	0x80000 }
400000000007AE50 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007AE60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007AE70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; init_job_stats: 400000000007AE80
;;   Called from:
;;     400000000005060C (in shell_execve)
init_job_stats proc
	{ addl	r15,-7044,r1; nop.m	0x0; addl	r14,-20676,r1 }
	{ addl	r16,-1,r0; nop.m	0x0; addl	r18,5904,r1; }
	{ ld8	r15,[r15]; st4	[r16],r18; addl	r18,5908,r1 }
	{ nop.m	0x0; st4	[r16],r18; nop.i	0x0; }
	{ nop.m	0x0; ld8	r17,[r15],8; nop.i	0x0; }
	{ st8	[r14],r8,8; ld8	r17,[r15],8; nop.i	0x0; }
	{ st8	[r14],r8,8; ld8	r17,[r15],8; nop.i	0x0; }
	{ st8	[r14],r8,8; ld8	r16,[r15],8; nop.i	0x0; }
	{ st8	[r14],r8,8; ld8	r16,[r15],8; nop.i	0x0; }
	{ st8	[r14],r8,8; ld8	r16,[r15],8; nop.i	0x0; }
	{ st8	[r14],r8,8; ld8	r16,[r15],8; nop.i	0x0; }
	{ st8	[r14],r8,8; ld8	r16,[r15],8; nop.i	0x0; }
	{ st8	[r14],r8,8; ld8	r15,[r15]; nop.i	0x0; }
	{ st8	[r15],r14; nop.i	0x0; br.ret	b0; }
400000000007AF60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007AF70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; stop_making_children: 400000000007AF80
;;   Called from:
;;     400000000009408C (in command_substitute)
;;     40000000000948BC (in command_substitute)
;;     40000000000A2A7C (in fn40000000000A1400)
;;     40000000000A527C (in fn40000000000A1400)
;;     40000000000AED9C (in run_debug_trap)
stop_making_children proc
	{ nop.m	0x0; addl	r14,7420,r1; nop.i	0x0; }
	{ st4	[r0],r14; nop.i	0x0; br.ret	b0; }
400000000007AFA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007AFB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; cleanup_the_pipeline: 400000000007AFC0
;;   Called from:
;;     400000000007B28C (in start_pipeline)
;;     4000000000093FFC (in command_substitute)
cleanup_the_pipeline proc
	{ alloc	r34,ar.pfs,0x7,0x0,0x4; adds	r12,0xFFFFFFFFFFFFFF00,r12; mov	r33,b1 }
	{ nop.m	0x0; adds	r35,0x0,r1; nop.i	0x0; }
	{ adds	r36,0x90,r12; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BC20; }
	{ addl	r37,17,r0; nop.m	0x0; adds	r1,0x0,r35 }
	{ adds	r36,0x90,r12; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B400; }
	{ adds	r1,0x0,r35; adds	r36,0x10,r12; br.call.sptk.many	b0,fn400000000001BC20; }
	{ adds	r1,0x0,r35; adds	r36,0x0,r0; nop.i	0x0 }
	{ adds	r37,0x90,r12; adds	r38,0x10,r12; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ adds	r1,0x0,r35; nop.m	0x0; addl	r36,2,r0 }
	{ adds	r37,0x10,r12; adds	r38,0x0,r0; addl	r14,7428,r1; }
	{ nop.m	0x0; ld8	r32,[r14]; nop.i	0x0 }
	{ st8	[r0],r14; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A6C0; }
	{ cmp.eq	p06,p07,0x0,r32; nop.m	0x0; adds	r1,0x0,r35 }
	{ adds	r36,0x0,r32; nop.m	0x0; (p06) br.cond.dpnt.few	400000000007B0C0; }

l400000000007B0A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000777C0; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l400000000007B0C0:
	{ nop.m	0x0; mov.i	ar.pfs,r34; mov.spnt	b0,r33,400000000007B0C0 }
	{ nop.m	0x0; adds	r12,0x100,r12; br.ret	b0; }
400000000007B0E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007B0F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; save_pipeline: 400000000007B100
;;   Called from:
;;     40000000000A2A1C (in fn40000000000A1400)
;;     40000000000AED6C (in run_debug_trap)
save_pipeline proc
	{ addl	r14,7428,r1; nop.m	0x0; addl	r15,7420,r1 }
	{ cmp4.eq	p06,p07,0x0,r32; nop.m	0x0; addl	r17,7452,r1; }
	{ ld4	r16,[r15]; ld8	r15,[r14]; nop.i	0x0 }
	{ (p07) st8	[r0],r14; addl	r14,7460,r1; nop.i	0x0 }

l400000000007B136:
	{ Invalid; nop; nop }
	{ mf.a; (p34) nop; break.i	0x80000 }
400000000007B150 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007B160 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007B170 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; restore_pipeline: 400000000007B180
;;   Called from:
;;     40000000000A2AAC (in fn40000000000A1400)
;;     40000000000AEDDC (in run_debug_trap)
restore_pipeline proc
	{ addl	r14,7428,r1; cmp4.eq	p07,p06,0x0,r32; addl	r16,7452,r1 }
	{ addl	r17,7460,r1; ld8	r15,[r14]; (p06) addl	r18,1,r0 }

l400000000007B1A0:
	{ ld8	r16,[r16]; (p07) adds	r18,0x0,r0; cmp.eq	p07,p06,0x0,r15 }

l400000000007B1AC:
	{ nop; nop; Invalid }
	{ nop; cmp4.eq.and	p00,p00,r32,r0; zxt4	r0,r0 }

l400000000007B1CC:
	{ cmp4.eq.and	p00,p43,r1,r0; zxt1	r0,r64; (p36) cmp.lt.unc	p03,p16,r4,r3 }

l400000000007B1D6:
	{ Invalid; (p07) nop; nop }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD3EBE6; (p34) nop; break.i	0x80000 }

l400000000007B1F0:
	{ nop.m	0x0; adds	r32,0x0,r15; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x1,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000777C0; }
400000000007B210 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
400000000007B220 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007B230 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; start_pipeline: 400000000007B240
;;   Called from:
;;     400000000007B3B6 (in making_children)
;;     400000000007C41C (in kill_current_pipeline)
;;     40000000000850EC (in without_job_control)
start_pipeline proc
	{ alloc	r33,ar.pfs,0x6,0x0,0x3; addl	r14,7428,r1; nop.b	0x0 }
	{ adds	r34,0x0,r1; nop.m	0x0; mov	r32,b0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000007B2C0; }

l400000000007B280:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,cleanup_the_pipeline; }
	{ adds	r1,0x0,r34; addl	r14,7436,r1; addl	r35,5880,r1; }
	{ st4	[r0],r14; br.call.sptk.many	b0,sh_closepipe; nop.b	0x0; }
	{ adds	r1,0x0,r34; nop.m	0x0; nop.i	0x0; }

l400000000007B2C0:
	{ addl	r14,5868,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dpnt.few	400000000007B300 }

l400000000007B2E0:
	{ nop.m	0x0; mov.i	ar.pfs,r33; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r32,400000000007B2F0; br.ret	b0; }

l400000000007B300:
	{ addl	r35,5880,r1; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB40; }
	{ adds	r1,0x0,r34; cmp4.eq	p07,p06,0xFFFFFFFFFFFFFFFF,r8; (p06) br.cond.dptk.few	400000000007B2E0; }

l400000000007B320:
	{ addl	r36,-8028,r1; addl	r37,5,r0; adds	r35,0x0,r0; }
	{ ld8	r36,[r36]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r34; adds	r35,0x0,r8; br.call.sptk.many	b0,sys_error; }
	{ adds	r1,0x0,r34; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ nop.m	0x0; mov.spnt	b0,r32,400000000007B360; br.ret	b0; }
400000000007B370 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; making_children: 400000000007B380
;;   Called from:
;;     40000000000827FC (in make_child)
making_children proc
	{ addl	r14,7420,r1; ld4	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r15; (p06) br.ret	b0 }

l400000000007B3A0:
	{ nop.m	0x0; addl	r15,1,r0; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.cond.sptk.many	start_pipeline; }
400000000007B3C0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
400000000007B3D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007B3E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007B3F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; delete_job: 400000000007B400
;;   Called from:
;;     400000000007EABC (in fn400000000007E8C0)
;;     4000000000084AEC (in delete_all_jobs)
;;     40000000000FFAAC (in disown_builtin)
delete_job proc
	{ alloc	r43,ar.pfs,0x10,0x0,0xD; addl	r34,-20676,r1; mov	r42,b2 }
	{ adds	r44,0x0,r1; nop.m	0x0; nop.i	0x0; }
	{ adds	r14,0x1C,r34; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; addl	r14,7464,r1; (p07) br.cond.dpnt.few	400000000007B6F0; }

l400000000007B440:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000007B6F0; }

l400000000007B460:
	{ nop.m	0x0; tbit.z	p07,p06,r33,0x0; (p07) br.cond.dptk.few	400000000007B710 }

l400000000007B470:
	{ addl	r14,9028,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	400000000007B710 }

l400000000007B4A0:
	{ addl	r37,7444,r1; nop.m	0x0; sxt4	r38,r32; }
	{ shladd	r38,r38,0x3,r0; ld8	r36,[r37]; nop.i	0x0; }
	{ add	r36,r36,r38; ld8	r35,[r36]; nop.i	0x0; }
	{ adds	r39,0x14,r35; ld4	r14,[r39]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x2,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000007BC10; }

l400000000007B4F0:
	{ nop.m	0x0; tbit.z	p07,p06,r33,0x1; (p07) br.cond.dpnt.few	400000000007B7C0; }

l400000000007B500:
	{ adds	r14,0x38,r34; st8	[r0],r36; adds	r36,0x0,r35; }
	{ nop.m	0x0; ld8	r15,[r14]; nop.i	0x0; }
	{ cmp.eq	p07,p06,r35,r15; nop.i	0x0; (p07) br.cond.dpnt.few	400000000007BA60; }

l400000000007B530:
	{ addl	r14,-20676,r1; nop.m	0x0; nop.i	0x0; }
	{ adds	r14,0x40,r14; ld8	r15,[r14]; nop.i	0x0; }
	{ cmp.eq	p07,p06,r35,r15; nop.i	0x0; (p07) br.cond.dpnt.few	400000000007BA60; }

l400000000007B560:
	{ ld8	r45,[r36],8; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r44; nop.i	0x0 }
	{ ld8	r45,[r36]; nop.m	0x0; br.call.sptk.many	b0,fn40000000000777C0; }
	{ adds	r14,0x10,r34; ld4	r16,[r39]; adds	r1,0x0,r44; }
	{ ld4	r15,[r14]; cmp4.eq	p06,p07,0x4,r16; sub	r15,r15,r8; }
	{ st4	[r15],r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000007BA10 }

l400000000007B5C0:
	{ adds	r14,0x20,r35; ld8	r45,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r45; nop.i	0x0; (p06) br.cond.dpnt.few	400000000007B600; }

l400000000007B5E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,dispose_command; }
	{ adds	r1,0x0,r44; nop.m	0x0; nop.i	0x0 }

l400000000007B600:
	{ adds	r45,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r15,0x28,r34; nop.m	0x0; adds	r1,0x0,r44; }
	{ ld4	r14,[r15]; adds	r14,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; }
	{ st4	[r14],r15; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	400000000007B780 }

l400000000007B640:
	{ adds	r18,0x24,r34; ld8	r15,[r37]; adds	r16,0x20,r34; }
	{ ld4	r14,[r18]; nop.m	0x0; sxt4	r17,r14; }
	{ shladd	r17,r17,0x3,r15; ld8	r17,[r17]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r17; nop.i	0x0; (p06) br.cond.dpnt.few	400000000007BCA0; }

l400000000007B680:
	{ ld4	r16,[r16]; nop.m	0x0; sxt4	r14,r16; }
	{ shladd	r14,r14,0x3,r15; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	400000000007BB40 }

l400000000007B6B0:
	{ adds	r34,0x30,r34; ld4	r14,[r34]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,r14,r32; adds	r14,0x4,r34; (p06) br.cond.dpnt.few	400000000007B7A0; }

l400000000007B6D0:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r32; (p07) br.cond.dpnt.few	400000000007B7A0 }

l400000000007B6F0:
	{ nop.m	0x0; mov.i	ar.pfs,r43; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r42,400000000007B700; br.ret	b0 }

l400000000007B710:
	{ nop.m	0x0; sxt4	r38,r32; addl	r37,7444,r1; }
	{ shladd	r38,r38,0x3,r0; ld8	r36,[r37]; nop.i	0x0; }
	{ nop.m	0x0; add	r36,r36,r38; nop.i	0x0; }
	{ ld8	r35,[r36]; nop.m	0x0; nop.i	0x0; }

l400000000007B750:
	{ cmp.eq	p06,p07,0x0,r35; adds	r39,0x14,r35; (p06) br.cond.dpnt.few	400000000007B6F0; }

l400000000007B760:
	{ nop.m	0x0; tbit.z	p07,p06,r33,0x1; (p06) br.cond.dptk.few	400000000007B500 }

l400000000007B770:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000007B7C0 }

l400000000007B780:
	{ adds	r14,0x20,r34; adds	r16,0x24,r34; nop.i	0x0 }
	{ st4	[r0],r14; st4	[r0],r16; br.cond.sptk.few	400000000007B6B0 }

l400000000007B7A0:
	{ nop.m	0x0; mov.spnt	b0,r42,400000000007B7A0; mov.i	ar.pfs,r43; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn400000000007A5C0; }

l400000000007B7C0:
	{ adds	r45,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn4000000000079140; }
	{ adds	r1,0x0,r44; cmp.eq	p06,p07,0x0,r8; nop.i	0x0 }
	{ adds	r14,0x8,r8; adds	r8,0xC,r8; (p06) br.cond.dpnt.few	400000000007B500; }

l400000000007B7F0:
	{ nop.m	0x0; addl	r36,14900,r1; nop.i	0x0 }
	{ ld4	r41,[r14]; ld4	r45,[r8]; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000077B80; }
	{ adds	r1,0x0,r44; nop.m	0x0; adds	r40,0x0,r8 }
	{ addl	r45,16,r0; nop.m	0x0; br.call.sptk.many	b0,xmalloc; }
	{ ld8	r15,[r36]; adds	r16,0xC,r8; adds	r17,0x8,r8 }
	{ st8	[r0],r8; ld8	r14,[r34]; adds	r1,0x0,r44; }
	{ cmp.eq	p07,p06,0x0,r15; st4	[r40],r16; adds	r16,0x8,r36 }
	{ st4	[r41],r17; adds	r40,0x10,r36; (p06) adds	r15,0x10,r36 }

l400000000007B880:
	{ (p06) ld8	r17,[r16]; (p07) st8	[r8],r36; nop.i	0x0; }

l400000000007B886:
	{ mf.a; adds	r0,0x0,r1; (p49) cmp.ltu	p03,p04,r96,r3; }

l400000000007B88C:
	{ cmp4.eq.or.andcm	p00,p02,r1,r0; (p01) nop; (p18) cmp4.eq.or.andcm	p00,p18,r0,r0 }

l400000000007B896:
	{ Invalid; (p07) addl	r1,24847,r0; (p01) br.call.spnt.few	b0,b2; }

l400000000007B89C:
	{ Invalid; Invalid; rfi; }

l400000000007B8A0:
	{ (p06) st8	[r8],r17; st8	[r8],r16; nop.i	0x0; }

l400000000007B8A6:
	{ mf.a; cmp.lt	p00,p00,0x0,r1; (p49) nop }

l400000000007B8B6:
	{ adds	r0,0xFFFFFFFFFFFFE000,r1; (p08) nop; break.i	0x80000 }
	{ mf.a; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r14,3FFFFFFFFF87F1E6; nop; break.i	0x80000 }

l400000000007B8E0:
	{ nop.m	0x0; ld8	r36,[r37]; nop.i	0x0; }
	{ nop.m	0x0; add	r36,r36,r38; br.cond.sptk.few	400000000007B500; }

l400000000007B900:
	{ ld8	r14,[r36]; adds	r45,0x0,r14; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ st8	[r14],r36; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; ld4	r14,[r40]; adds	r1,0x0,r44 }
	{ nop.m	0x0; ld8	r15,[r34]; nop.i	0x0; }
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; sxt4	r16,r14 }
	{ nop.m	0x0; st4	[r14],r40; nop.i	0x0; }
	{ cmp.lt	p06,p07,r15,r16; nop.i	0x0; (p07) br.cond.dpnt.few	400000000007B8E0; }

l400000000007B980:
	{ ld8	r14,[r36]; adds	r45,0x0,r14; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ st8	[r14],r36; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; ld4	r14,[r40]; adds	r1,0x0,r44 }
	{ nop.m	0x0; ld8	r15,[r34]; nop.i	0x0; }
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; sxt4	r16,r14 }
	{ nop.m	0x0; st4	[r14],r40; nop.i	0x0; }
	{ nop.m	0x0; cmp.lt	p06,p07,r15,r16; (p06) br.cond.dptk.few	400000000007B900 }

l400000000007BA00:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000007B8E0 }

l400000000007BA10:
	{ adds	r14,0xC,r34; nop.m	0x0; adds	r17,0x2C,r34; }
	{ ld4	r16,[r14]; ld4	r15,[r17]; nop.i	0x0; }
	{ sub	r8,r16,r8; adds	r15,0xFFFFFFFFFFFFFFFF,r15; cmp4.lt	p07,p06,r8,r0 }
	{ st4	[r8],r14; st4	[r15],r17; nop.i	0x0; }
	{ (p07) st4	[r0],r14; nop.i	0x0; br.cond.sptk.few	400000000007B5C0 }

l400000000007BA56:
	{ break.m	0x4000; nop; nop }

l400000000007BA60:
	{ st8	[r0],r14; nop.m	0x0; adds	r36,0x0,r35; }
	{ ld8	r45,[r36],8; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r44; nop.i	0x0 }
	{ ld8	r45,[r36]; nop.m	0x0; br.call.sptk.many	b0,fn40000000000777C0; }
	{ adds	r14,0x10,r34; ld4	r16,[r39]; adds	r1,0x0,r44; }
	{ ld4	r15,[r14]; cmp4.eq	p06,p07,0x4,r16; sub	r15,r15,r8; }
	{ st4	[r15],r14; nop.i	0x0; (p07) br.cond.dptk.few	400000000007B5C0 }

l400000000007BAD0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000007BA10 }

l400000000007BAE0:
	{ cmp4.eq	p06,p07,r17,r14; adds	r16,0x24,r34; adds	r14,0x20,r34; }
	{ st4	[r17],r16; nop.i	0x0; (p06) br.cond.spnt.few	400000000007BD40; }

l400000000007BB00:
	{ ld4	r16,[r14]; nop.m	0x0; sxt4	r14,r16; }
	{ shladd	r14,r14,0x3,r0; add	r14,r15,r14; nop.i	0x0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.sptk.few	400000000007B6B0; }

l400000000007BB40:
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r16; cmp4.lt	p07,p06,r16,r0; adds	r17,0x20,r34; }
	{ st4	[r14],r17; (p07) adds	r16,0x0,r0; adds	r17,0x1C,r34; }

l400000000007BB5C:
	{ (p14) cmp.lt	p34,p17,r0,r66; czx1.r	r68,r33; mov	pr,r32,0x0 }
	{ (p04) cmpxchg1.acq.nt1	r0,[r33],r64; Invalid; dep	r0,r32,r0,63,1 }

l400000000007BB70:
	{ ld4	r18,[r17]; nop.i	0x0; adds	r18,0xFFFFFFFFFFFFFFFF,r18; }

l400000000007BB80:
	{ cmp4.lt	p07,p06,r14,r0; (p07) adds	r14,0x0,r18; nop.i	0x0; }

l400000000007BB8C:
	{ nop.m	0x80; nop; (p02) break.i	0x161C0 }
	{ (p07) nop; (p18) nop; Invalid; }
	{ cmp.eq	p00,p19,r1,r0; mov	pr,r68,0xE440; Invalid }

l400000000007BBBC:
	{ (p01) nop; cmp.lt	p00,p00,r32,r0; (p49) nop }

l400000000007BBC0:
	{ nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r16,r14; (p06) br.cond.dptk.few	400000000007BB80 }

l400000000007BBE0:
	{ adds	r16,0x28,r34; adds	r15,0x20,r34; adds	r14,0x24,r34; }
	{ st4	[r0],r16; st4	[r0],r15; nop.i	0x0; }
	{ st4	[r0],r14; nop.i	0x0; br.cond.sptk.few	400000000007B6B0 }

l400000000007BC10:
	{ addl	r46,-8020,r1; adds	r45,0x0,r0; addl	r47,5,r0; }
	{ ld8	r46,[r46]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ ld8	r14,[r37]; nop.m	0x0; adds	r1,0x0,r44 }
	{ adds	r45,0x0,r8; adds	r46,0x1,r32; add	r14,r14,r38; }
	{ ld8	r14,[r14]; adds	r14,0x10,r14; nop.i	0x0; }
	{ nop.m	0x0; ld4	r47,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r47,r47; br.call.sptk.many	b0,internal_warning; }
	{ ld8	r36,[r37]; adds	r1,0x0,r44; add	r36,r36,r38; }
	{ ld8	r35,[r36]; nop.i	0x0; br.cond.sptk.few	400000000007B750 }

l400000000007BCA0:
	{ adds	r16,0x1C,r34; nop.m	0x0; adds	r17,0x1,r14; }
	{ ld4	r19,[r16]; st4	[r17],r18; nop.i	0x0; }
	{ cmp4.lt	p07,p06,r14,r19; (p06) adds	r14,0xFFFFFFFFFFFFFFFF,r19; nop.i	0x0; }

l400000000007BCCC:
	{ Invalid; cmp.lt	p00,p00,r32,r0; (p32) mov	pr,r100,0xE246 }
	{ (p03) cmp.eq	p00,p01,r64,r33; (p16) dep	r100,r68,r33,62,9; (p02) break.b	0x16220 }

l400000000007BCE0:
	{ cmp4.lt	p07,p06,r17,r19; sxt4	r18,r17; adds	r16,0x0,r0; }
	{ (p07) shladd	r16,r18,0x3,r0; (p06) adds	r17,0x0,r0; add	r16,r15,r16 }

l400000000007BCF6:
	{ Invalid; (p08) nop; nop; }

l400000000007BCFC:
	{ Invalid; (p17) nop; (p02) rfi }
	{ cmp.eq	p00,p19,r1,r0; mov	pr,r68,0xE400; Invalid }

l400000000007BD1C:
	{ (p01) nop; nop; (p18) epc }

l400000000007BD20:
	{ nop.m	0x0; adds	r17,0x1,r17; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r17; (p06) br.cond.dptk.few	400000000007BCE0 }

l400000000007BD40:
	{ adds	r14,0x0,r0; adds	r19,0x28,r34; adds	r18,0x20,r34 }
	{ adds	r17,0x24,r34; adds	r16,0x0,r0; add	r14,r15,r14 }
	{ st4	[r0],r19; st4	[r0],r18; nop.i	0x0; }
	{ ld8	r14,[r14]; st4	[r0],r17; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.sptk.few	400000000007B6B0 }

l400000000007BD90:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000007BB40; }

l400000000007BDA0:
	{ adds	r15,0x20,r34; nop.m	0x0; cmp4.eq	p07,p06,r14,r16; }
	{ st4	[r14],r15; nop.i	0x0; (p06) br.cond.sptk.few	400000000007B6B0 }

l400000000007BDC0:
	{ adds	r16,0x28,r34; adds	r15,0x20,r34; adds	r14,0x24,r34; }
	{ st4	[r0],r16; st4	[r0],r15; nop.i	0x0; }
	{ st4	[r0],r14; nop.i	0x0; br.cond.sptk.few	400000000007B6B0; }
400000000007BDF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; nohup_job: 400000000007BE00
;;   Called from:
;;     40000000000FFA9C (in disown_builtin)
nohup_job proc
	{ addl	r14,-20676,r1; nop.m	0x0; sxt4	r32,r32; }
	{ nop.m	0x0; adds	r14,0x1C,r14; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; addl	r14,7444,r1; (p06) br.ret	b0; }

l400000000007BE40:
	{ ld8	r14,[r14]; shladd	r32,r32,0x3,r14; nop.i	0x0; }
	{ ld8	r14,[r32]; adds	r15,0x18,r14; cmp.eq	p06,p07,0x0,r14; }
	{ (p07) ld4	r14,[r15]; (p07) or	r14,0x8,r14; nop.i	0x0; }

l400000000007BE66:
	{ Invalid; cmp4.eq	p00,p00,r0,r1; (p01) nop; }

l400000000007BE6C:
	{ Invalid; Invalid; add	r0,r32,r0 }

l400000000007BE76:
	{ break.m	0x4000; (p34) nop; Invalid }

;; append_process: 400000000007BE80
append_process proc
	{ alloc	r37,ar.pfs,0x8,0x0,0x7; nop.m	0x0; mov	r36,b4 }
	{ adds	r38,0x0,r1; nop.m	0x0; sxt4	r35,r35; }
	{ addl	r39,32,r0; dep.z	r34,r34,8,8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r38; adds	r16,0x18,r8; adds	r14,0x0,r8 }
	{ adds	r18,0xC,r8; adds	r17,0x10,r8; addl	r15,7444,r1 }
	{ st8	[r32],r16; ld8	r15,[r15]; nop.i	0x0 }
	{ st8	[r14],r8,8; shladd	r35,r35,0x3,r15; addl	r15,-20676,r1 }
	{ nop.m	0x0; st4	[r33],r14; nop.i	0x0; }
	{ nop.m	0x0; ld8	r16,[r35]; nop.i	0x0 }
	{ st4	[r0],r17; adds	r15,0xC,r15; adds	r16,0x8,r16; }
	{ nop.m	0x0; ld4	r14,[r15]; nop.i	0x0 }
	{ st4	[r34],r18; ld8	r16,[r16]; nop.i	0x0; }
	{ adds	r14,0x1,r14; st4	[r14],r15; adds	r15,0x0,r16; }
	{ nop.m	0x0; ld8	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r14,r16; (p07) br.cond.dpnt.few	400000000007BFA0; }

l400000000007BF70:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000007BF80:
	{ adds	r15,0x0,r14; ld8	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r14,r16; (p06) br.cond.dptk.few	400000000007BF80 }

l400000000007BFA0:
	{ ld8.a	r14,[r35]; st8	[r8],r15; mov.i	ar.pfs,r37; }
	{ ld8.c.clr	r14,[r35]; mov.spnt	b0,r36,400000000007BFB0; adds	r14,0x8,r14; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ st8	[r14],r8; nop.i	0x0; br.ret	b0; }
400000000007BFE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007BFF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; terminate_current_pipeline: 400000000007C000
;;   Called from:
;;     40000000000828FC (in make_child)
terminate_current_pipeline proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x4; addl	r32,7436,r1; nop.b	0x0 }
	{ addl	r15,5896,r1; mov	r33,b1; adds	r35,0x0,r1; }
	{ ld4	r14,[r32]; nop.m	0x0; addl	r37,15,r0; }
	{ cmp4.eq	p06,p07,0x0,r14; adds	r36,0x0,r14; (p06) br.cond.dpnt.few	400000000007C0A0; }

l400000000007C040:
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,r15,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000007C0A0; }

l400000000007C060:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001ACE0; }
	{ adds	r1,0x0,r35; ld4	r36,[r32]; addl	r37,18,r0 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001ACE0; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l400000000007C0A0:
	{ nop.m	0x0; mov.i	ar.pfs,r34; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r33,400000000007C0B0; br.ret	b0; }

;; terminate_stopped_jobs: 400000000007C0C0
;;   Called from:
;;     400000000008522C (in end_job_control)
terminate_stopped_jobs proc
	{ alloc	r38,ar.pfs,0xA,0x0,0x8; addl	r35,-20676,r1; nop.b	0x0 }
	{ addl	r34,7444,r1; adds	r39,0x0,r1; mov	r37,b5; }
	{ nop.m	0x0; nop.m	0x0; adds	r32,0x0,r0 }
	{ adds	r33,0x0,r0; adds	r36,0x0,r34; adds	r35,0x1C,r35; }
	{ nop.m	0x0; ld4	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	400000000007C190; }

l400000000007C120:
	{ ld8	r14,[r34]; adds	r33,0x1,r33; add	r14,r14,r32; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ adds	r15,0x14,r14; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	400000000007C170; }

l400000000007C150:
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2,r15; (p07) br.cond.dpnt.few	400000000007C1B0 }

l400000000007C170:
	{ ld4	r14,[r35]; nop.m	0x0; adds	r32,0x8,r32; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r33,r14; (p06) br.cond.dptk.few	400000000007C120 }

l400000000007C190:
	{ nop.m	0x0; mov.i	ar.pfs,r38; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r37,400000000007C1A0; br.ret	b0 }

l400000000007C1B0:
	{ adds	r14,0x10,r14; nop.m	0x0; addl	r41,15,r0; }
	{ ld4	r40,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001ACE0; }
	{ ld8	r14,[r36]; adds	r1,0x0,r39; addl	r41,18,r0; }
	{ add	r14,r14,r32; nop.m	0x0; adds	r32,0x8,r32; }
	{ ld8	r14,[r14]; adds	r14,0x10,r14; nop.i	0x0; }
	{ ld4	r40,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001ACE0; }
	{ ld4	r14,[r35]; nop.m	0x0; adds	r1,0x0,r39; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r33,r14; (p06) br.cond.dptk.few	400000000007C120 }

l400000000007C230:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000007C190; }

;; hangup_all_jobs: 400000000007C240
;;   Called from:
;;     400000000002250C (in exit_shell)
;;     40000000000B4ECC (in termsig_handler)
hangup_all_jobs proc
	{ alloc	r38,ar.pfs,0xA,0x0,0x8; addl	r35,-20676,r1; nop.b	0x0 }
	{ addl	r34,7444,r1; adds	r39,0x0,r1; mov	r37,b5; }
	{ nop.m	0x0; nop.m	0x0; adds	r32,0x0,r0 }
	{ adds	r33,0x0,r0; adds	r36,0x0,r34; adds	r35,0x1C,r35; }
	{ nop.m	0x0; ld4	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	400000000007C310; }

l400000000007C2A0:
	{ ld8	r14,[r34]; adds	r33,0x1,r33; add	r14,r14,r32; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ adds	r15,0x18,r14; cmp.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	400000000007C2F0; }

l400000000007C2D0:
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r15,0x3; (p07) br.cond.dpnt.few	400000000007C330 }

l400000000007C2F0:
	{ ld4	r14,[r35]; nop.m	0x0; adds	r32,0x8,r32; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r33,r14; (p06) br.cond.dptk.few	400000000007C2A0 }

l400000000007C310:
	{ nop.m	0x0; mov.i	ar.pfs,r38; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r37,400000000007C320; br.ret	b0 }

l400000000007C330:
	{ adds	r14,0x10,r14; nop.m	0x0; addl	r41,1,r0; }
	{ ld4	r40,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001ACE0; }
	{ ld8	r14,[r36]; adds	r1,0x0,r39; add	r14,r14,r32; }
	{ ld8	r14,[r14]; adds	r15,0x14,r14; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2,r15; (p06) br.cond.dptk.few	400000000007C2F0 }

l400000000007C390:
	{ adds	r14,0x10,r14; addl	r41,18,r0; adds	r32,0x8,r32; }
	{ ld4	r40,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001ACE0; }
	{ ld4	r14,[r35]; nop.m	0x0; adds	r1,0x0,r39; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r33,r14; (p06) br.cond.dptk.few	400000000007C2A0 }

l400000000007C3D0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000007C310; }
400000000007C3E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000007C3F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; kill_current_pipeline: 400000000007C400
;;   Called from:
;;     400000000008292C (in make_child)
kill_current_pipeline proc
	{ nop.m	0x0; addl	r14,7420,r1; nop.i	0x0; }
	{ st4	[r0],r14; nop.i	0x0; br.cond.sptk.many	start_pipeline; }
400000000007C420 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
400000000007C430 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; get_job_by_pid: 400000000007C440
;;   Called from:
;;     40000000000FFB6C (in disown_builtin)
get_job_by_pid proc
	{ alloc	r36,ar.pfs,0x9,0x0,0x6; adds	r12,0xFFFFFFFFFFFFFF00,r12; mov	r35,b3 }
	{ cmp4.eq	p06,p07,0x0,r33; adds	r37,0x0,r1; (p07) br.cond.dpnt.few	400000000007C4B0; }

l400000000007C460:
	{ adds	r39,0x0,r0; nop.m	0x0; adds	r40,0x0,r0 }
	{ adds	r38,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,fn4000000000076C40; }
	{ adds	r34,0x0,r8; nop.m	0x0; adds	r1,0x0,r37; }
	{ adds	r8,0x0,r34; mov.i	ar.pfs,r36; mov.spnt	b0,r35,400000000007C490 }
	{ nop.m	0x0; adds	r12,0x100,r12; br.ret	b0; }
