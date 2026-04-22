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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Reko.Arch.IA64;

public partial class IA64Rewriter
{
    private void RewriteFma(IA64Instruction instr)
    {
        var op1 = ReadOp(instr, 1);
        var op2 = ReadOp(instr, 2);
        var src = ReadOp(instr, 0);
        WriteOp(instr, 0, m.FAdd(src, m.FMul(op1, op2)));
    }

    private void RewriteFselect(IA64Instruction instr)
    {
        var op1 = ReadOp(instr, 1);
        var op2 = ReadOp(instr, 2);
        var op3 = ReadOp(instr, 3);
        WriteOp(instr, 0, m.Fn(fselect_intrinsic, op1, op2, op3));
    }

    private void RewriteGetfSig(IA64Instruction instr)
    {
        var op = ReadOp(instr, 1);
        WriteOp(instr, 0, m.Fn(getf_sig_intrinsic, op));
    }

}
