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

public partial class IA64Disassembler
{
    private static UnitDecoder MakeBdecoders()
    {
        var indirectBranch = Sparse(6, 3, "  indirectBranch", invalid,
            (0, Instr(Mnemonic.br_cond, InstrClass.Transfer, B4)),
            (1, Instr(Mnemonic.br_ia, B4)));
        var indirectReturn = Sparse(6, 3, "  indirectReturn", invalid,
            (4, Instr(Mnemonic.br_ret, InstrClass.Transfer | InstrClass.Return, B4)));
        var miscIndirectBranch = Sparse(27, 6, "  Misc/IndirectBranch", prReserved,
            (0x00, Instr(Mnemonic.break_b, InstrClass.Terminates, B9)),
            (0x02, Instr(Mnemonic.cover, B8)),
            (0x04, Instr(Mnemonic.clrrrb, B8)),
            (0x05, Instr(Mnemonic.clrrrb_pr, B8)),
            (0x08, Instr(Mnemonic.rfi, InstrClass.Return | InstrClass.Privileged, B8)),
            (0x0C, Instr(Mnemonic.bsw_0, B8)),
            (0x0D, Instr(Mnemonic.bsw_1, B8)),
            (0x10, Instr(Mnemonic.epc, InstrClass.Linear | InstrClass.Privileged, B8)),
            (0x20, indirectBranch),
            (0x21, indirectReturn));
        var indirectCall = Instr(Mnemonic.br_call, InstrClass.Transfer | InstrClass.Call, B5);
        var indirectPredictNop = Sparse(27, 6, "  Indirect Predict/Nop", prReserved,
            (0x00, Instr(Mnemonic.nop_b, B9)),
            (0x10, Instr(Mnemonic.brp, B7)),
            (0x11, Instr(Mnemonic.brp_ret, B7)));
        var ipRelativeBranch = Mask(6, 3, "IP-relative Branch",
            Instr(Mnemonic.br_cond, InstrClass.Transfer, B1),
            invalid,
            Instr(Mnemonic.br_wexit, B1),
            Instr(Mnemonic.br_wtop, B1),

            invalid,
            Instr(Mnemonic.br_cloop, InstrClass.ConditionalTransfer, B2),
            Instr(Mnemonic.br_cond, InstrClass.Transfer, B2),
            Instr(Mnemonic.br_cond, InstrClass.Transfer, B2));
        var ipRelativeCall = Instr(Mnemonic.br_call, InstrClass.Transfer | InstrClass.Call, B3);
        var ipRelativePredict = Instr(Mnemonic.brp, B6);

        return new UnitDecoder('b', Mask(37, 4, "  B",
            miscIndirectBranch,
            indirectCall,
            indirectPredictNop,
            nop,

            ipRelativeBranch,
            ipRelativeCall,
            nop,
            ipRelativePredict,

            reserved,
            reserved,
            reserved,
            reserved,

            reserved,
            reserved,
            reserved,
            reserved));
    }
}
