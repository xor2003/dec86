#region License
/* 
 * Copyright (C) 1999-2026 John Källén.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#endregion

using NUnit.Framework;
using Reko.Arch.IA64;
using Reko.Core;

namespace Reko.UnitTests.Arch.IA64;

public class IA64DisassemblerTests : DisassemblerTestBase<IA64Bundle>
{
    private readonly IA64Architecture arch;
    private readonly Address addrLoad;

    public IA64DisassemblerTests()
    {
        this.arch = new IA64Architecture(CreateServiceContainer(), "ia64", []);
        this.addrLoad = Address.Ptr64(0x10_0000_0000);
    }

    public override IProcessorArchitecture Architecture => arch;

    public override Address LoadAddress => addrLoad;

    private void AssertCode(string sExpected, string hexBytes)
    {
        var instr = base.DisassembleHexBytes(hexBytes);
        if (instr.ToString().Contains("Nyi"))        //$DEBUG
        Assert.AreEqual(sExpected, instr.ToString());
    }

    [Test]
    public void Ia64Dis_add()
    {
        AssertCode("{ nop.m\t0x0; sxt4\tr17,r17; add\tr19,r19,r17; }", "0300000001001001442C006032890080");
    }

    [Test]
    public void Ia64Dis_addp4()
    {
        AssertCode("{ nop.m\t0x0; addp4\tr17,r17,r0; nop.i\t0x0; }", "09000000010010890010400000000400");
    }

    [Test]
    public void Ia64Dis_addp4_imm()
    {
        AssertCode("{ adds\tr44,0x0,r0; adds\tr33,0x20,r12; addp4\tr41,0xFFFFFFFFFFFFFFFF,r0; }", "096001000021100231004220F507FC8E");
    }

    [Test]
    public void IA64Dis_alloc_mlx()
    {
        AssertCode(
            "{ alloc\tr2,ar.pfs,0x7,0x0,0x0; movl\tr3,0x9804C0270033F }",
            "04101C008045024C80090060F0131A60");
    }

    [Test]
    public void Ia64Dis_br_call()
    {
        AssertCode("{ nop.m\t0x0; nop.i\t0x0; br.call.sptk.many\tb0,0000000FFFFFDC20; }", "11000000010000000002000028DCFF58");
    }

    [Test]
    public void Ia64Dis_br_call_indirect()
    {
        AssertCode("{ adds\tr34,0x0,r1; ld8\tr1,[r14]; br.call.sptk.many\tb0,b6; }", "19100102002110003830200068008010");
    }

    [Test]
    public void Ia64Dis_br_cond()
    {
        AssertCode("{ nop.m\t0x0; mov.i\tLC,r17; (p09) br.cond.sptk.few\t0000001000000020; }", "11000000010000880455800420000040");
    }

    [Test]
    public void Ia64Dis_br_ret()
    {
        AssertCode("{ nop.m\t0x0; mov.i\tLC,r2; br.ret\tb0; }", "11000000010000100455008008008400");
    }

    [Test]
    public void Ia64Dis_break_f()
    {
        AssertCode("{ nop.m\t0x0; break.f\t0x0; nop.i\t0x0; }", "0D000000010000000000000000000400");
    }

    [Test]
    public void IA64Dis_break_mii()
    {
        AssertCode(
            "{ (p63) break.m\t0x0; break.i\t0x0; break.i\t0x0 }",
            "E0070000 00000000 00000000 00000000");
    }

    [Test]
    public void Ia64Dis_chk_a_clr()
    {
        AssertCode("{ chk.a.clr\tr14,0000001000000090; nop.i\t0x0; nop.i\t0x0 }", "00702400400100000002000000000400");
    }

    [Test]
    public void Ia64Dis_chk_s_i()
    {
        AssertCode("@@@", "31023A240000000200808408B8900970");
    }

    [Test]
    public void Ia64Dis_cmp4_br_cond()
    {
        AssertCode(
            "{ nop.m\t0x0; cmp4.eq\tp06,p07,0x0,r14; (p06) br.cond.dptk.few\t0000001000000160 }",
            "1000000001006000380E730360010042");
    }

    [Test]
    public void Ia64Dis_cmp4_br_cond2()
    {
        AssertCode("{ nop.m\t0x0; cmp4.lt\tp07,p06,0x29,r15; (p06) br.cond.dptk.few\t0000001000000130 }", "10000000010070483D0C630330010042");
    }

    [Test]
    public void Ia64Dis_dep_z()
    {
        AssertCode("{ nop.m\t0x0; extr\tr14,r14,6,25; dep.z\tr14,r14,6,26; }", "030000000100E060383229C0E1C86553");
    }

    [Test]
    public void Ia64Dis_deposit()
    {
        AssertCode("@@@", "00000002000000000400080000000140");
    }

    [Test]
    public void Ia64Dis_extr()
    {
        AssertCode("{ nop.m\t0x0; extr\tr39,r39,4,27; nop.i\t0x0 }", "00000000010070429C36290000000400");
    }

    [Test]
    public void Ia64Dis_extr_u()
    {
        AssertCode("{ nop.m\t0x0; extr.u\tr16,r14,5,2; and\tr15,0x1F,r14; }", "0100000001000051380429E0F171B080");
    }

    [Test]
    public void Ia64Dis_fcvt_xf()
    {
        AssertCode("{ nop.m\t0x0; fcvt.xf\tf2,f6; br.call.sptk.many\tb0,0000000FFFFFD230; }", "1D000000010020300038000038D2FF58");
    }

    [Test]
    public void Ia64Dis_fcvt_fxu_trunc_sf()
    {
        AssertCode("{ nop.m\t0x0; fcvt.fxu.trunc.s1\tf10,f10; nop.i\t0x0; }", "0D0000000100A0500036010000000400");
    }

    [Test]
    public void Ia64Dis_getf()
    {
        AssertCode("{ getf.sig\tr14,f11; extr\tr17,r18,14,49; dep.z\tr18,0xF,5,59; }", "01702C00E11010E948622940F2D0E953");
    }

    [Test]
    public void Ia64Dis_getf_sig()
    {
        AssertCode("{ getf.sig\tr18,f9; extr.u\tr15,r17,18,45; shladd\tr39,r23,0x1,r2; }", "01902400E110F028455A29E074114080");
    }

    [Test]
    public void Ia64Dis_ld4()
    {
        AssertCode("{ nop.m\t0x0; ld4\tr16,[r15]; addl\tr15,6720,r1 }", "08000000010000013C2020E0010CD090");
    }

    [Test]
    public void Ia64Dis_ld8_sxt4()
    {
        AssertCode("{ ld8\tr19,[r18]; ld4\tr15,[r15]; sxt4\tr18,r16; }", "0B9800241810F0003C20204002805800");
    }

    [Test]
    public void Ia64Dis_ldf_fill()
    {
        AssertCode("{ ldf.fill\tf2,[r17]; adds\tr12,0x150,r12; br.ret\tb0 }", "18100022D818C0803204428008008400");
    }

    [Test]
    public void Ia64Dis_mix4_l()
    {
        AssertCode("{ nop.m\t0x0; mix4.l\tr99,r99,r14; (p07) adds\tr34,0x18,r34; }", "010000000100301E3B28BE4384110184");
    }

    [Test]
    public void Ia64Dis_mov_breg()
    {
        AssertCode("{ nop.m\t0x0; mov.spnt\tb0,r33,0000001000000000; adds\tr1,0x0,r35 }", "00000000010000080580032000180184");
    }

    [Test]
    public void Ia64Dis_mov_m_ar_imm()
    {
        AssertCode("{ mov.m\tFPSR,0x3; sub\tr1,r9,r1; adds\tr38,0x10,r12; }", "01000C502A041048040A40C004610084");
    }

    [Test]
    public void Ia64Dis_mov_m_r_ar()
    {
        AssertCode("{ ld8\tr33,[r34],8; mov.m\tr10,BSP; mov\tr9,ip; }", "090821441814A000444408200100C000");
    }

    [Test]
    public void Ia64Dis_mov_r_br()
    {
        AssertCode("{ alloc\tr34,ar.pfs,0x7,0x0,0x4; addl\tr37,-9244,r1; mov\tr33,b1 }", "08101D0880055022F76F4F200400C400");
    }

    [Test]
    public void Ia64Dis_mov_r_lc()
    {
        AssertCode("{ adds\tr12,0xFFFFFFFFFFFFFEE0,r12; mov\tr17,LC; addl\tr50,25252,r1; }", "016080193D23100104650040460A1493");
    }

    [Test]
    public void Ia64Dis_mov_i_lc_0()
    {
        AssertCode("{ nop.m\t0x0; mov.i\tLC,0x0; nop.i\t0x0; }", "01000000010000000415000000000400");
    }

    [Test]
    public void Ia64Dis_nop_b()
    {
        AssertCode("{ alloc\tr49,ar.pfs,0x16,0x0,0x12; adds\tr16,0x0,r12; nop.b\t0x0 }", "18885924800500013000420000000020");
    }

    [Test]
    public void IA64Dis_mov_nop_i()
    {
        AssertCode(
            "{ adds\tr2,0x0,r14; addl\tr14,-10732,r2; nop.i\t0x0; }",
            "0B10001C0021E0A0F8594F0000000400");
    }

    [Test]
    public void Ia64Dis_mov_pr_imm()
    {
        AssertCode("@@@", "00000002000000000400010000000100");
    }

    [Test]
    public void Ia64Dis_nop_m()
    {
        AssertCode("{ nop.m\t0x0; movl\tr20,0x803FFFFF80000000; }", "05000000010080FFFFFF7F8002000068");
    }

    [Test]
    public void Ia64Dis_setf_sig()
    {
        AssertCode("{ adds\tr15,0x23,r12; setf.sig\tf6,r14; adds\tr14,0x24,r12 }", "0A788C180021607000C231C041620084");
    }

    [Test]
    public void Ia64Dis_shl()
    {
        AssertCode("{ nop.m\t0x0; shl\tr16,r17,r16; nop.i\t0x0 }", "000000000100008940903C0000000400");
    }

    [Test]
    public void Ia64Dis_shladd()
    {
        AssertCode("{ setf.sig\tf7,r14; shladd\tr15,r14,0x4,r0; sub\tr15,r15,r14; }", "03383800E118F070002640E0F1701480");
    }

    [Test]
    public void Ia64Dis_shrp()
    {
        AssertCode("@@@", "0000000280081817F75B2B0A00520061");
    }

    [Test]
    public void Ia64Dis_st4()
    {
        AssertCode("{ st4\t[r8],r14; nop.m\t0x0; br.call.sptk.many\tb0,000000100010C310; }", "1900201C901100000002000018C31050");
    }

    [Test]
    public void Ia64Dis_st8_spill()
    {
        AssertCode("{ st8\t[r16],r8,8; st8.spill\t[r1],r16; adds\tr16,0x110,r12; }", "0B4044209815000840B0230002610884");
    }

    [Test]
    public void Ia64Dis_stf_spill()
    {
        AssertCode("{ addl\tr36,9252,r1; stf.spill\t[r16],f2; nop.b\t0x0 }", "182091024824001040B0330000000020");
    }

    [Test]
    public void Ia64Dis_stf8()
    {
        AssertCode("{ nop.m\t0x0; stf8\t[r16],f6; addl\tr16,6,r0 }", "08000000010000304010330062000090");
    }

    [Test]
    public void Ia64Dis_sub()
    {
        AssertCode("{ sub\tr17,r15,r16; add\tr18,r19,r18; nop.i\t0x0 }", "08883C20052020994800400000000400");
    }

    [Test]
    public void Ia64Dis_tbit_z()
    {
        AssertCode("{ nop.m\t0x0; tbit.z\tp06,p07,r38,0x0; nop.i\t0x0 }", "0000000001006000980E280000000400");
    }

    [Test]
    public void Ia64Dis_tnat()
    {
        AssertCode("{ nop.m\t0x0; cmp4.eq\tp31,p30,0x44,r15; tnat.z\tp26,p27,r36 }", "080000000100F0213E3C7340A3206D50");
    }

    // Reko: a decoder for the instruction 00840900000001000088386023000000 at address 400000000001DE1E has not been implemented. (x_2a = 0)
    [Test]
    public void Ia64Dis_00840900000001000088386023000000()
    {
        AssertCode("@@@", "00840900000001000088386023000000");
    }
}
