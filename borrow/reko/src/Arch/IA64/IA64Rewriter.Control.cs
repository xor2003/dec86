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

namespace Reko.Arch.IA64;

public partial class IA64Rewriter
{
    private void RewriteBr_call(IA64Instruction instr)
    {
        var target = ReadOp(instr, 1);
        m.Call(target, 0);
    }

    private void RewriteBr_cloop(IA64Instruction instr)
    {
        var target = ReadOp(instr, 0);
        var lc = binder.EnsureRegister(Registers.LC);
        var addrNext = instr.Address + instr.Length;
        m.BranchInMiddleOfInstruction(m.Eq0(lc), addrNext, InstrClass.ConditionalTransfer);
        m.Assign(lc, m.ISub(lc, 1));
        m.Goto(target);
    }

    private void RewriteClrrrb(IA64Instruction instr, IntrinsicProcedure intrinsic)
    {
        m.SideEffect(m.Fn(intrinsic));
    }

    private void RewriteBr_cond(IA64Instruction instr)
    {
        var target = ReadOp(instr, 0);
        m.Goto(target, 0);
    }

    private void RewriteBr_ret(IA64Instruction instr)
    {
        var target = ReadOp(instr, 0);
        m.Return(0, 0);
    }

    private void RewriteBreak(IA64Instruction instr)
    {
        m.SideEffect(m.Fn(break_intrinsic));
    }

    private void RewriteEpc(IA64Instruction instr)
    {
        m.SideEffect(m.Fn(epc_intrinsic));
    }

    private void RewriteChk_a_clr(IA64Instruction instr)
    {
        var op = ReadOp(instr, 0);
        m.Branch(m.Fn(chk_intrinsic, op), (Address) instr.Operands[1]);
    }

    private void RewriteFwb(IA64Instruction instr)
    {
        m.SideEffect(m.Fn(fwb_intrinsic));
    }

    private void RewriteInvala(IA64Instruction instr)
    {
        m.SideEffect(m.Fn(invala_intrinsic));
    }

    private void RewriteProbe(IA64Instruction instr, IntrinsicProcedure intrinsic)
    {
        var ea = ReadOp(instr, 1);
        var perm = ReadOp(instr, 2);
        WriteOp(instr, 0, m.Fn(intrinsic, ea, perm));
    }

    private void RewriteRfi(IA64Instruction instr)
    {
        m.SideEffect(m.Fn(rfi_intrinsic));
        m.Return(0, 0);
    }

    private void RewriteRum(IA64Instruction instr)
    {
        m.SideEffect(m.Fn(rum_intrinsic, ReadOp(instr, 0)));
    }

    private void RewriteSerialize(IA64Instruction instr, IntrinsicProcedure intrinsic)
    {
        m.SideEffect(m.Fn(intrinsic));
    }
}
