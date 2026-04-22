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

using Reko.Core;
using Reko.Core.Expressions;
using Reko.Core.Intrinsics;
using Reko.Core.Memory;
using Reko.Core.Operators;
using Reko.Core.Rtl;
using Reko.Core.Services;
using Reko.Core.Types;
using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Reko.Arch.IA64;

public partial class IA64Rewriter : IEnumerable<RtlInstructionCluster>
{
    private readonly IA64Architecture arch;
    private readonly EndianImageReader rdr;
    private readonly ProcessorState state;
    private readonly IStorageBinder binder;
    private readonly IRewriterHost host;
    private readonly IEnumerator<IA64Bundle> dasm;
    private readonly List<RtlInstruction> rtls;
    private readonly List<RtlInstruction> rtlsConditional;
    private RtlEmitter m;
    private RtlEmitter mUnconditional;
    private RtlEmitter mConditional;
    private IA64Bundle bundle;
    private InstrClass iclass;

    public IA64Rewriter(
        IA64Architecture arch,
        EndianImageReader rdr,
        ProcessorState state,
        IStorageBinder binder,
        IRewriterHost host)
    {
        this.arch = arch;
        this.rdr = rdr;
        this.state = state;
        this.binder = binder;
        this.host = host;
        this.dasm = new IA64Disassembler(arch, rdr).GetEnumerator();
        this.rtls = [];
        this.rtlsConditional = [];
        this.mUnconditional = new RtlEmitter(rtls);
        this.mConditional = new RtlEmitter(rtlsConditional);
        this.m = this.mUnconditional;
        this.bundle = default!;
    }

    public IEnumerator<RtlInstructionCluster> GetEnumerator()
    {
        while (dasm.MoveNext())
        {
            this.bundle = dasm.Current;
            foreach (var instr in bundle.Instructions)
            {
                iclass = instr.InstructionClass;
                if (instr.Mnemonic == Mnemonic._long_immediate)
                {
                    // Skip long immediate pseudo-instructions
                    continue;
                }
                MaybeEmitUnconditional(instr);
                var p = MaybeEmitPredicateBranch(instr);
                Rewrite(instr);
                if (p is not null)
                {
                    mUnconditional.If(binder.EnsureFlagGroup(p), rtlsConditional.ToArray());
                    m = mUnconditional;
                }
                yield return m.MakeCluster(instr.Address, instr.Length, iclass);
                rtls.Clear();
                rtlsConditional.Clear();
            }
        }
    }

    private void MaybeEmitUnconditional(IA64Instruction instr)
    {
        switch (instr.Mnemonic)
        {
        case Mnemonic.cmp4_eq_unc:
        case Mnemonic.cmp4_lt_unc:
        case Mnemonic.cmp4_ltu_unc:
        case Mnemonic.cmp_eq_unc:
        case Mnemonic.cmp_lt_unc:
        case Mnemonic.cmp_ltu_unc:
        case Mnemonic.fcmp_eq_unc:
        case Mnemonic.fcmp_lt_unc:
        case Mnemonic.fcmp_le_unc:
        case Mnemonic.fcmp_unord_unc:
        case Mnemonic.fpcmp_unord_unc:
            var p1 = (FlagGroupStorage) instr.Operands[0];
            var p2 = (FlagGroupStorage) instr.Operands[1];
            m.Assign(binder.EnsureFlagGroup(p1), 0);
            m.Assign(binder.EnsureFlagGroup(p2), 0);
            break;
        case Mnemonic.tbit_nz_unc:
        case Mnemonic.tnat_nz_unc:
        case Mnemonic.tbit_z_unc:
        case Mnemonic.tnat_z_unc:
        case Mnemonic.fclass_m_unc:
            Debug.Assert(false);
            break;
        }
    }

    private FlagGroupStorage? MaybeEmitPredicateBranch(IA64Instruction instr)
    {
        var p = instr.QualifyingPredicate;
        if (p is null || p == Registers.PredicateRegisters[0])
            return null;
        switch (instr.Mnemonic)
        {
        case Mnemonic.cmp_eq_and:
        case Mnemonic.cmp_eq_or:
        case Mnemonic.cmp_eq_or_andcm:
        case Mnemonic.cmp_ge_and:
        case Mnemonic.cmp_ge_or:
        case Mnemonic.cmp_gt_or_andcm:
        case Mnemonic.cmp_gt_and:
        case Mnemonic.cmp_gt_or:
        case Mnemonic.cmp_le_or_andcm:
        case Mnemonic.cmp_le_and:
        case Mnemonic.cmp_le_or:
        case Mnemonic.cmp_lt_or_andcm:
        case Mnemonic.cmp_lt_and:
        case Mnemonic.cmp_lt_or:
        case Mnemonic.cmp_ne_or_andcm:
        case Mnemonic.cmp_ne_and:
        case Mnemonic.cmp_ne_or:
            return null;
        case Mnemonic.cmp4_eq_and:
        case Mnemonic.cmp4_eq_or:
        case Mnemonic.cmp4_eq_or_andcm:
        case Mnemonic.cmp4_ge_and:
        case Mnemonic.cmp4_ge_or:
        case Mnemonic.cmp4_gt_or_andcm:
        case Mnemonic.cmp4_gt_and:
        case Mnemonic.cmp4_gt_or:
        case Mnemonic.cmp4_le_or_andcm:
        case Mnemonic.cmp4_le_and:
        case Mnemonic.cmp4_le_or:
        case Mnemonic.cmp4_lt_or_andcm:
        case Mnemonic.cmp4_lt_and:
        case Mnemonic.cmp4_lt_or:
        case Mnemonic.cmp4_ne_or_andcm:
        case Mnemonic.cmp4_ne_and:
        case Mnemonic.cmp4_ne_or:
            return null;
        }
        // Switch to adding RTL instructions to the conditional branch.
        m = mConditional;
        return p;
    }

    private bool Rewrite(IA64Instruction instr)
    {
        switch (instr.Mnemonic)
        {
        default:
            EmitUnitTest(instr);
            break;
        case Mnemonic.Invalid: m.Invalid(); iclass  = InstrClass.Invalid; break;
        case Mnemonic._long_immediate: return false;
        case Mnemonic.add: RewriteAdd(instr); break;
        case Mnemonic.addl: RewriteAdd(instr); break;
        case Mnemonic.addp4: RewriteAddp4(instr); break;
        case Mnemonic.adds: RewriteAdd(instr); break;
        case Mnemonic.alloc: RewriteAlloc(instr); break;
        case Mnemonic.and: RewriteAnd(instr); break;
        case Mnemonic.andcm: RewriteAndcm(instr); break;
        case Mnemonic.br_ret: RewriteBr_ret(instr); break;
        case Mnemonic.br_call: RewriteBr_call(instr); break;
        case Mnemonic.br_cloop: RewriteBr_cloop(instr); break;
        case Mnemonic.br_cond: RewriteBr_cond(instr); break;
        case Mnemonic.break_b: RewriteBreak(instr); break;
        case Mnemonic.break_f: RewriteBreak(instr); break;
        case Mnemonic.break_i: RewriteBreak(instr); break;
        case Mnemonic.break_m: RewriteBreak(instr); break;
        case Mnemonic.break_x: RewriteBreak(instr); break;
        case Mnemonic.chk_a_clr: RewriteChk_a_clr(instr); break;  //$REVIEW: very vague interpretation of spec.
        case Mnemonic.chk_a_nc: RewriteChk_a_clr(instr); break;
        case Mnemonic.chk_s_m: RewriteChk_a_clr(instr); break;
        case Mnemonic.clrrrb: RewriteClrrrb(instr, clrrrb_intrinsic); break;
        case Mnemonic.clrrrb_pr: RewriteClrrrb(instr, clrrrb_pr_intrinsic); break;
        case Mnemonic.cmp_eq:
        case Mnemonic.cmp_eq_unc: RewriteCmp(instr, BinaryOperator.Eq, BinaryOperator.Ne); break;
        case Mnemonic.cmp_eq_and: RewriteCmp(instr, BinaryOperator.Eq, BinaryOperator.Ne, BinaryOperator.Cand, BinaryOperator.Cor); break;
        case Mnemonic.cmp_eq_or: RewriteCmp(instr, BinaryOperator.Eq, BinaryOperator.Ne, BinaryOperator.Cor, BinaryOperator.Cand); break;
        case Mnemonic.cmp_eq_or_andcm: RewriteCmpCm(instr, BinaryOperator.Eq, BinaryOperator.Ne, BinaryOperator.Cor, BinaryOperator.Cand); break;
        case Mnemonic.cmp_ge:
        case Mnemonic.cmp_ge_unc: RewriteCmp(instr, BinaryOperator.Ge, BinaryOperator.Lt); break;
        case Mnemonic.cmp_ge_and: RewriteCmp(instr, BinaryOperator.Ge, BinaryOperator.Lt, BinaryOperator.Cand, BinaryOperator.Cor); break;
        case Mnemonic.cmp_ge_or: RewriteCmp(instr, BinaryOperator.Ge, BinaryOperator.Lt, BinaryOperator.Cor, BinaryOperator.Cand); break;
        case Mnemonic.cmp_ge_or_andcm: RewriteCmpCm(instr, BinaryOperator.Ge, BinaryOperator.Lt, BinaryOperator.Cor, BinaryOperator.Cand); break;
        case Mnemonic.cmp_gt:
        case Mnemonic.cmp_gt_unc: RewriteCmp(instr, BinaryOperator.Gt, BinaryOperator.Le); break;
        case Mnemonic.cmp_gt_and: RewriteCmp(instr, BinaryOperator.Gt, BinaryOperator.Le, BinaryOperator.Cand, BinaryOperator.Cor); break;
        case Mnemonic.cmp_gt_or: RewriteCmp(instr, BinaryOperator.Gt, BinaryOperator.Le, BinaryOperator.Cor, BinaryOperator.Cand); break;
        case Mnemonic.cmp_gt_or_andcm: RewriteCmpCm(instr, BinaryOperator.Gt, BinaryOperator.Le, BinaryOperator.Cor, BinaryOperator.Cand); break;
        case Mnemonic.cmp_lt:
        case Mnemonic.cmp_lt_unc: RewriteCmp(instr, BinaryOperator.Lt, BinaryOperator.Ge); break;
        case Mnemonic.cmp_lt_or_andcm: RewriteCmpCm(instr, BinaryOperator.Lt, BinaryOperator.Ge, BinaryOperator.Cor, BinaryOperator.Cand); break;
        case Mnemonic.cmp_ltu:
        case Mnemonic.cmp_ltu_unc: RewriteCmp(instr, BinaryOperator.Ult, BinaryOperator.Uge); break;
        case Mnemonic.cmp_ltu_or_andcm: RewriteCmpCm(instr, BinaryOperator.Ult, BinaryOperator.Uge, BinaryOperator.Cor, BinaryOperator.Cand); break;
        case Mnemonic.cmp_ne:
        case Mnemonic.cmp_ne_unc: RewriteCmp(instr, BinaryOperator.Ne, BinaryOperator.Eq); break;
        case Mnemonic.cmp_ne_and: RewriteCmp(instr, BinaryOperator.Ne, BinaryOperator.Eq, BinaryOperator.Cand, BinaryOperator.Cor); break;
        case Mnemonic.cmp_ne_or: RewriteCmp(instr, BinaryOperator.Ne, BinaryOperator.Eq, BinaryOperator.Cor, BinaryOperator.Cand); break;
        case Mnemonic.cmp_ne_or_andcm: RewriteCmpCm(instr, BinaryOperator.Ne, BinaryOperator.Eq, BinaryOperator.Cor, BinaryOperator.Cand); break;
        case Mnemonic.cmp4_eq:
        case Mnemonic.cmp4_eq_unc: RewriteCmp4(instr, BinaryOperator.Eq, BinaryOperator.Ne); break;
        case Mnemonic.cmp4_eq_and: RewriteCmp4(instr, BinaryOperator.Eq, BinaryOperator.Ne, BinaryOperator.Cand, BinaryOperator.Cor); break;
        case Mnemonic.cmp4_eq_or: RewriteCmp4(instr, BinaryOperator.Eq, BinaryOperator.Ne, BinaryOperator.Cor, BinaryOperator.Cand); break;
        case Mnemonic.cmp4_eq_or_andcm: RewriteCmp4Cm(instr, BinaryOperator.Eq, BinaryOperator.Ne, BinaryOperator.Cor, BinaryOperator.Cand); break;
        case Mnemonic.cmp4_ge:
        case Mnemonic.cmp4_ge_unc: RewriteCmp4(instr, BinaryOperator.Ge, BinaryOperator.Lt); break;
        case Mnemonic.cmp4_ge_and: RewriteCmp4(instr, BinaryOperator.Ge, BinaryOperator.Lt, BinaryOperator.Cand, BinaryOperator.Cor); break;
        case Mnemonic.cmp4_ge_or: RewriteCmp4(instr, BinaryOperator.Ge, BinaryOperator.Lt, BinaryOperator.Cor, BinaryOperator.Cand); break;
        case Mnemonic.cmp4_ge_or_andcm: RewriteCmp4Cm(instr, BinaryOperator.Ge, BinaryOperator.Lt, BinaryOperator.Cor, BinaryOperator.Cand); break;
        case Mnemonic.cmp4_gt:
        case Mnemonic.cmp4_gt_unc: RewriteCmp4(instr, BinaryOperator.Gt, BinaryOperator.Le); break;
        case Mnemonic.cmp4_gt_and: RewriteCmp4(instr, BinaryOperator.Gt, BinaryOperator.Le, BinaryOperator.Cand, BinaryOperator.Cor); break;
        case Mnemonic.cmp4_gt_or: RewriteCmp4(instr, BinaryOperator.Gt, BinaryOperator.Le, BinaryOperator.Cor, BinaryOperator.Cand); break;
        case Mnemonic.cmp4_gt_or_andcm: RewriteCmp4Cm(instr, BinaryOperator.Gt, BinaryOperator.Le, BinaryOperator.Cor, BinaryOperator.Cand); break;
        case Mnemonic.cmp4_le:
        case Mnemonic.cmp4_le_unc: RewriteCmp4(instr, BinaryOperator.Le, BinaryOperator.Gt); break;
        case Mnemonic.cmp4_le_and: RewriteCmp4(instr, BinaryOperator.Le, BinaryOperator.Gt, BinaryOperator.Cand, BinaryOperator.Cor); break;
        case Mnemonic.cmp4_le_or: RewriteCmp4(instr, BinaryOperator.Le, BinaryOperator.Gt, BinaryOperator.Cor, BinaryOperator.Cand); break;
        case Mnemonic.cmp4_le_or_andcm: RewriteCmp4Cm(instr, BinaryOperator.Le, BinaryOperator.Gt, BinaryOperator.Cor, BinaryOperator.Cand); break;
        case Mnemonic.cmp4_lt:
        case Mnemonic.cmp4_lt_unc: RewriteCmp4(instr, BinaryOperator.Lt, BinaryOperator.Ge); break;
        case Mnemonic.cmp4_lt_or_andcm: RewriteCmp4Cm(instr, BinaryOperator.Lt, BinaryOperator.Ge, BinaryOperator.Cor, BinaryOperator.Cand); break;
        case Mnemonic.cmp4_ltu:
        case Mnemonic.cmp4_ltu_unc: RewriteCmp4(instr, BinaryOperator.Ult, BinaryOperator.Uge); break;
        case Mnemonic.cmp4_ltu_or_andcm: RewriteCmp4Cm(instr, BinaryOperator.Ult, BinaryOperator.Uge, BinaryOperator.Cor, BinaryOperator.Cand); break;
        case Mnemonic.cmp4_ne:
        case Mnemonic.cmp4_ne_unc: RewriteCmp4(instr, BinaryOperator.Ne, BinaryOperator.Eq); break;
        case Mnemonic.cmp4_ne_and: RewriteCmp4(instr, BinaryOperator.Ne, BinaryOperator.Eq, BinaryOperator.Cand, BinaryOperator.Cor); break;
        case Mnemonic.cmp4_ne_or: RewriteCmp4(instr, BinaryOperator.Ne, BinaryOperator.Eq, BinaryOperator.Cor, BinaryOperator.Cand); break;
        case Mnemonic.cmp4_ne_or_andcm: RewriteCmp4Cm(instr, BinaryOperator.Ne, BinaryOperator.Eq, BinaryOperator.Cor, BinaryOperator.Cand); break;
        case Mnemonic.cmpxchg1_acq: RewriteCmpxchg(instr, PrimitiveType.Byte, cmpxchg_acq_intrinsic); break;
        case Mnemonic.cmpxchg2_acq: RewriteCmpxchg(instr, PrimitiveType.Word16, cmpxchg_acq_intrinsic); break;
        case Mnemonic.cmpxchg4_acq: RewriteCmpxchg(instr, PrimitiveType.Word32, cmpxchg_acq_intrinsic); break;
        case Mnemonic.cmpxchg8_acq: RewriteCmpxchg(instr, PrimitiveType.Word64, cmpxchg_acq_intrinsic); break;
        case Mnemonic.czx1_l: RewriteCzx(instr, PrimitiveType.Byte, czx_l_intrinsic); break;
        case Mnemonic.czx1_r: RewriteCzx(instr, PrimitiveType.Byte, czx_r_intrinsic); break;
        case Mnemonic.czx2_l: RewriteCzx(instr, PrimitiveType.Word16, czx_l_intrinsic); break;
        case Mnemonic.czx2_r: RewriteCzx(instr, PrimitiveType.Word16, czx_r_intrinsic); break;
        case Mnemonic.dep: RewriteDep(instr); break;
        case Mnemonic.dep_z: RewriteDep_z(instr); break;
        case Mnemonic.epc: RewriteEpc(instr); break;
        case Mnemonic.extr: RewriteExtr(instr); break;
        case Mnemonic.extr_u: RewriteExtr_u(instr); break;
        case Mnemonic.fma: RewriteFma(instr); break;
        case Mnemonic.fselect: RewriteFselect(instr); break;
        case Mnemonic.fwb: RewriteFwb(instr); break;
        case Mnemonic.getf_sig: RewriteGetfSig(instr); break;
        case Mnemonic.invala: RewriteInvala(instr); break;
        case Mnemonic.ld1: RewriteLd(instr, PrimitiveType.Byte); break;
        case Mnemonic.ld2: RewriteLd(instr, PrimitiveType.Word16); break;
        case Mnemonic.ld4: RewriteLd(instr, PrimitiveType.Word32); break;
        case Mnemonic.ld8: RewriteLd(instr, PrimitiveType.Word64); break;
        case Mnemonic.ld1_a: RewriteLd(instr, PrimitiveType.Byte); break;   //$REVIEW: is .a correct here?
        case Mnemonic.ld2_a: RewriteLd(instr, PrimitiveType.Word16); break;
        case Mnemonic.ld4_a: RewriteLd(instr, PrimitiveType.Word32); break;
        case Mnemonic.ld8_a: RewriteLd(instr, PrimitiveType.Word64); break;
        case Mnemonic.ld1_c_clr: RewriteLd(instr, PrimitiveType.Byte); break;   //$REVIEW: is .c.clr correct here?
        case Mnemonic.ld2_c_clr: RewriteLd(instr, PrimitiveType.Word16); break;
        case Mnemonic.ld4_c_clr: RewriteLd(instr, PrimitiveType.Word32); break;
        case Mnemonic.ld8_c_clr: RewriteLd(instr, PrimitiveType.Word64); break;
        case Mnemonic.ld1_acq: RewriteLd_acq(instr, PrimitiveType.Byte); break;
        case Mnemonic.ld2_acq: RewriteLd_acq(instr, PrimitiveType.Word16); break;
        case Mnemonic.ld4_acq: RewriteLd_acq(instr, PrimitiveType.Word32); break;
        case Mnemonic.ld8_acq: RewriteLd_acq(instr, PrimitiveType.Word64); break;
        case Mnemonic.ldf_fill: RewriteLd(instr, PrimitiveType.Word64); break;
        case Mnemonic.ldfe: RewriteLdfe(instr); break;
        case Mnemonic.ldfs: RewriteLd(instr, PrimitiveType.Real32); break;
        case Mnemonic.ldfps: RewriteLdfps(instr); break;
        case Mnemonic.ldfps_c_nc: RewriteLdfps(instr); break;       //$REVIEW: is .c.nc correct?
        case Mnemonic.mix1_l: RewriteMix(instr, mix_l_intrinsic, PrimitiveType.Byte); break;
        case Mnemonic.mix1_r: RewriteMix(instr, mix_r_intrinsic, PrimitiveType.Byte); break;
        case Mnemonic.mix2_l: RewriteMix(instr, mix_l_intrinsic, PrimitiveType.Word16); break;
        case Mnemonic.mix2_r: RewriteMix(instr, mix_r_intrinsic, PrimitiveType.Word16); break;
        case Mnemonic.mix4_l: RewriteMix(instr, mix_l_intrinsic, PrimitiveType.Word32); break;
        case Mnemonic.mix4_r: RewriteMix(instr, mix_r_intrinsic, PrimitiveType.Word32); break;
        case Mnemonic.mov: RewriteMov(instr); break;
        case Mnemonic.mov_i: RewriteMov(instr); break;
        case Mnemonic.mov_m: RewriteMov(instr); break;
        case Mnemonic.movl: RewriteMov(instr); break;
        case Mnemonic.nop: RewriteNop(instr); break;
        case Mnemonic.nop_b: RewriteNop(instr); break;
        case Mnemonic.nop_i: RewriteNop(instr); break;
        case Mnemonic.nop_m: RewriteNop(instr); break;
        case Mnemonic.or: RewriteOr(instr); break;
        case Mnemonic.probe_r: RewriteProbe(instr, probe_r_intrinsic); break;
        case Mnemonic.probe_w: RewriteProbe(instr, probe_w_intrinsic); break;
        case Mnemonic.rfi: RewriteRfi(instr); break;
        case Mnemonic.rum: RewriteRum(instr); break;
        case Mnemonic.setf_sig: RewriteSetf_sig(instr); break;
        case Mnemonic.shl: RewriteShift(instr, BinaryOperator.Shl); break;
        case Mnemonic.shr: RewriteShift(instr, BinaryOperator.Sar); break;
        case Mnemonic.shr_u: RewriteShift(instr, BinaryOperator.Shr); break;
        case Mnemonic.shladd: RewriteShladd(instr); break;
        case Mnemonic.srlz_d: RewriteSerialize(instr, srlz_d_intrinsic); break;
        case Mnemonic.srlz_i: RewriteSerialize(instr, srlz_i_intrinsic); break;
        case Mnemonic.st1: RewriteSt(instr, PrimitiveType.Byte); break;
        case Mnemonic.st2: RewriteSt(instr, PrimitiveType.Word16); break;
        case Mnemonic.st4: RewriteSt(instr, PrimitiveType.Word32); break;
        case Mnemonic.st8: RewriteSt(instr, PrimitiveType.Word64); break;
        case Mnemonic.st1_rel: RewriteSt_rel(instr, PrimitiveType.Byte); break;
        case Mnemonic.st2_rel: RewriteSt_rel(instr, PrimitiveType.Word16); break;
        case Mnemonic.st4_rel: RewriteSt_rel(instr, PrimitiveType.Word32); break;
        case Mnemonic.st8_rel: RewriteSt_rel(instr, PrimitiveType.Word64); break;
        case Mnemonic.st8_spill: RewriteSt(instr, PrimitiveType.Word64); break; //$REVIEW: unclear if this is correct
        case Mnemonic.stf_spill: RewriteSt(instr, PrimitiveType.Word64); break; //$REVIEW: unclear if this is correct
        case Mnemonic.stfe: RewriteSt(instr, PrimitiveType.Word80); break; //$REVIEW: unclear if this is correct
        case Mnemonic.sub: RewriteSub(instr); break;
        case Mnemonic.sxt1: RewriteSxt(instr, PrimitiveType.Int8); break;
        case Mnemonic.sxt2: RewriteSxt(instr, PrimitiveType.Int16); break;
        case Mnemonic.sxt4: RewriteSxt(instr, PrimitiveType.Int32); break;
        case Mnemonic.tbit_nz:
        case Mnemonic.tbit_nz_unc: RewriteTbit(instr, false); break;
        case Mnemonic.tbit_nz_and: RewriteTbit(instr, false, Operator.Cand); break;
        case Mnemonic.tbit_nz_or: RewriteTbit(instr, false, Operator.Cand); break;
        case Mnemonic.tbit_nz_or_andcm: RewriteTbitCm(instr, false, Operator.Cand); break;
        case Mnemonic.tbit_z:
        case Mnemonic.tbit_z_unc: RewriteTbit(instr, true); break;
        case Mnemonic.tbit_z_and: RewriteTbit(instr, true, Operator.Cand); break;
        case Mnemonic.tbit_z_or: RewriteTbit(instr, true, Operator.Cand); break;
        case Mnemonic.tbit_z_or_andcm: RewriteTbitCm(instr, true, Operator.Cand); break;
        case Mnemonic.tnat_nz:
        case Mnemonic.tnat_nz_unc: RewriteTnat(instr, false); break;
        case Mnemonic.tnat_nz_and: RewriteTnat(instr, false, Operator.Cand); break;
        case Mnemonic.tnat_nz_or: RewriteTnat(instr, false, Operator.Cand); break;
        case Mnemonic.tnat_nz_or_andcm: RewriteTnatCm(instr, false, Operator.Cand); break;
        case Mnemonic.tnat_z:
        case Mnemonic.tnat_z_unc: RewriteTnat(instr, true); break;
        case Mnemonic.tnat_z_and: RewriteTnat(instr, true, Operator.Cand); break;
        case Mnemonic.tnat_z_or: RewriteTnat(instr, true, Operator.Cand); break;
        case Mnemonic.tnat_z_or_andcm: RewriteTnatCm(instr, true, Operator.Cand); break;
        case Mnemonic.xma_h: RewriteXma(instr, Operator.SMul, 64); break;
        case Mnemonic.xma_hu: RewriteXma(instr, Operator.UMul, 64); break;
        case Mnemonic.xma_l: RewriteXma(instr, Operator.IMul, 0); break;
        case Mnemonic.xor: RewriteXor(instr); break;
        case Mnemonic.zxt1: RewriteZxt(instr, PrimitiveType.Byte); break;
        case Mnemonic.zxt2: RewriteZxt(instr, PrimitiveType.Word16); break;
        case Mnemonic.zxt4: RewriteZxt(instr, PrimitiveType.Word32); break;
        }
        return true;
    }

    System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
    {
        return GetEnumerator();
    }

    private void EmitUnitTest(IA64Instruction instr)
    {
        var testGenSvc = arch.Services.GetService<ITestGenerationService>();
        testGenSvc?.ReportMissingRewriter("Ia64Rw", bundle, instr.MnemonicAsString, rdr, "");
    }

    private Expression MaybeExtendZ(Expression expr, DataType dt)
    {
        if (expr.DataType.BitSize >= dt.BitSize)
            return expr;
        var tmp = binder.CreateTemporary(expr.DataType);
        m.Assign(tmp, expr);
        return m.ExtendZ(tmp, dt);
    }

    private Expression ReadOp(IA64Instruction instr, int iop, DataType? dt = null)
    {
        var op = instr.Operands[iop];
        switch (op)
        {
        case RegisterStorage reg:
            if (reg.Number == 0)
                return Constant.Word64(0);
            if (reg == Registers.FpRegisters[0])
                return m.Word64(0);
            if (reg == Registers.FpRegisters[1])
                return m.Word64(fpOne);
            return binder.EnsureRegister(reg);
        case Constant c:
            return c;
        case Address addr:
            return addr;
        case MemoryOperand mem:
            Debug.Assert(dt is not null);
            var ea = binder.EnsureRegister(mem.Base);
            return m.Mem(dt, ea);
        default:
            throw new NotImplementedException($"Operand type {op.GetType().Name} not implemented.");
        }
    }

    private Expression WriteOp(IA64Instruction instr, int iop, Expression src, DataType? dt = null)
    {
        var op = instr.Operands[iop];
        Expression dst;
        switch (op)
        {
        case RegisterStorage reg:
            if (reg.Number == 0)
            {
                // "attempting to write to GR 0 causes an Illegal Operation fault" -- IA64 manual
                m.Invalid();
                return InvalidConstant.Create(reg.DataType);
            }
            dst = binder.EnsureRegister(reg);
            m.Assign(dst, MaybeExtendZ(src, dst.DataType));
            return src;
        case FlagGroupStorage grf:
            if (grf.FlagGroupBits == 1)
            {
                m.SideEffect(src);
                return src;
            }
            dst = binder.EnsureFlagGroup(grf);
            break;
        case MemoryOperand mem:
            Debug.Assert(dt is not null);
            var ea = binder.EnsureRegister(mem.Base);
            dst = m.Mem(dt, ea);
            if (dt.Domain == Domain.Real && dt.BitSize > src.DataType.BitSize)
            {
                src = m.Convert(src, src.DataType, dt);
            }
            break;
        default:
            throw new NotImplementedException($"Operand type {op.GetType().Name} not implemented.");
        }
        m.Assign(dst, src);
        return src;
    }

    private Expression? WriteOpIgnoreQp0(IA64Instruction instr, int iop, Expression src, DataType? dt = null)
    {
        var op = instr.Operands[iop];
        Expression dst;
        switch (op)
        {
        case RegisterStorage reg:
            if (reg.Number == 0)
            {
                // "attempting to write to GR 0 causes an Illegal Operation fault" -- IA64 manual
                m.Invalid();
                return InvalidConstant.Create(reg.DataType);
            }
            dst = binder.EnsureRegister(reg);
            break;
        case FlagGroupStorage grf:
            if (grf.FlagGroupBits == 1)
            {
                return null;
            }
            dst = binder.EnsureFlagGroup(grf);
            break;
        case MemoryOperand mem:
            Debug.Assert(dt is not null);
            var ea = binder.EnsureRegister(mem.Base);
            dst = m.Mem(dt, ea);
            break;
        default:
            throw new NotImplementedException($"Operand type {op.GetType().Name} not implemented.");
        }
        m.Assign(dst, src);
        return src;
    }

    private static readonly ulong fpOne = BitConverter.DoubleToUInt64Bits(1.0);

    private static readonly IntrinsicProcedure addp4_intrinsic = IntrinsicBuilder.Binary("__addp4", PrimitiveType.Word32);

    private static readonly IntrinsicProcedure break_intrinsic = IntrinsicBuilder.SideEffect("__break").Void();

    private static readonly IntrinsicProcedure chk_intrinsic = new IntrinsicBuilder("__speculation_check", true)
        .Param(PrimitiveType.Word64)
        .Returns(PrimitiveType.Bool);
    private static readonly IntrinsicProcedure clrrrb_intrinsic = IntrinsicBuilder.SideEffect("__clear_register_rename_base")
        .Void();
    private static readonly IntrinsicProcedure clrrrb_pr_intrinsic = IntrinsicBuilder.SideEffect("__clear_predicate_register_rename_base")
        .Void();
    private readonly static IntrinsicProcedure cmpxchg_acq_intrinsic = IntrinsicBuilder.SideEffect("__cmpxchg")
        .GenericTypes("T")
        .PtrParam("T")
        .Param("T")
        .Param(PrimitiveType.Word64)
        .Returns("T");
    private static readonly IntrinsicProcedure czx_l_intrinsic = new IntrinsicBuilder("__count_zero_index_msb", false)
        .GenericTypes("T")
        .Param(PrimitiveType.Word64)
        .Returns(PrimitiveType.Int64);
    private static readonly IntrinsicProcedure czx_r_intrinsic = new IntrinsicBuilder("__count_zero_index_lsb", false)
        .GenericTypes("T")
        .Param(PrimitiveType.Word64)
        .Returns(PrimitiveType.Int64);

    private static readonly IntrinsicProcedure epc_intrinsic = IntrinsicBuilder.SideEffect("__enter_privieleged_code").Void();

    private static readonly IntrinsicProcedure fselect_intrinsic = new IntrinsicBuilder("__fselect", false)
        .Param(PrimitiveType.Word64)
        .Param(PrimitiveType.Word64)
        .Param(PrimitiveType.Word64)
        .Returns(PrimitiveType.Word64);

    private static readonly IntrinsicProcedure fwb_intrinsic = IntrinsicBuilder.SideEffect("__flush_write_buffers").Void();

    private static readonly IntrinsicProcedure getf_sig_intrinsic = new IntrinsicBuilder("__get_significand", false)
        .Param(PrimitiveType.Real64)
        .Returns(PrimitiveType.Int64);

    private static readonly IntrinsicProcedure invala_intrinsic = IntrinsicBuilder.SideEffect("__invala")
        .Void();

    private static readonly IntrinsicProcedure ld_acq_intrinsic = new IntrinsicBuilder("__ld_acquire", true)
        .GenericTypes("T")
        .PtrParam("T")
        .Returns("T");

    private static readonly IntrinsicProcedure mix_l_intrinsic = new IntrinsicBuilder("__mix_l", false)
        .GenericTypes("T")
        .Param(PrimitiveType.Word64)
        .Param(PrimitiveType.Word64)
        .Returns(PrimitiveType.Word64);
    private static readonly IntrinsicProcedure mix_r_intrinsic = new IntrinsicBuilder("__mix_r", false)
        .GenericTypes("T")
        .Param(PrimitiveType.Word64)
        .Param(PrimitiveType.Word64)
        .Returns(PrimitiveType.Word64);

    private static readonly IntrinsicProcedure probe_r_intrinsic = IntrinsicBuilder.SideEffect("__probe_read")
        .Param(PrimitiveType.Ptr64)
        .Param(PrimitiveType.Word64)
        .Returns(PrimitiveType.Word64);
    private static readonly IntrinsicProcedure probe_w_intrinsic = IntrinsicBuilder.SideEffect("__probe_write")
        .Param(PrimitiveType.Ptr64)
        .Param(PrimitiveType.Word64)
        .Returns(PrimitiveType.Word64);

    private static readonly IntrinsicProcedure rfi_intrinsic = IntrinsicBuilder.SideEffect("__return_from_interrupt")
        .Void();
    private static readonly IntrinsicProcedure rum_intrinsic = IntrinsicBuilder.SideEffect("__reset_user_mask")
        .Param(PrimitiveType.Word64)
        .Void();

    private static readonly IntrinsicProcedure setf_sig_intrinsic = new IntrinsicBuilder("__setf_sig", false)
        .Param(PrimitiveType.UInt64)
        .Returns(PrimitiveType.Real64);
    private static readonly IntrinsicProcedure srlz_d_intrinsic = IntrinsicBuilder.SideEffect("__serialize_data")
        .Void();
    private static readonly IntrinsicProcedure srlz_i_intrinsic = IntrinsicBuilder.SideEffect("__serialize_instructions")
        .Void();
    private static readonly IntrinsicProcedure st_rel_intrinsic = new IntrinsicBuilder("__st_release", true)
        .GenericTypes("T")
        .PtrParam("T")
        .Param("T")
        .Void();

    private static readonly IntrinsicProcedure tnat_intrinsic = IntrinsicBuilder.Predicate("__is_nat", PrimitiveType.Word64);

}