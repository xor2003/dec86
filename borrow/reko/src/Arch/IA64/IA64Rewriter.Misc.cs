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
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Reko.Arch.IA64;

public partial class IA64Rewriter
{
    private void RewriteAlloc(IA64Instruction instr)
    {
        //$TODO: this is a placeholder implementation, just to get things working.
        var r1 = binder.EnsureRegister((RegisterStorage)instr.Operands[0]);
        var sof = instr.Operands[1];
        m.Assign(r1, binder.EnsureIdentifier(Registers.PFS));
    }

    private void RewriteNop(IA64Instruction instr)
    {
        m.Nop();
    }
}
