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

namespace Reko.Arch.IA64;

public partial class IA64Disassembler
{
    private static UnitDecoder MakeXdecoders()
    {
        var misc = Sparse(27, 6, "X-misc", prReserved,
            (0b000000, Instr(Mnemonic.break_x, X1)),
            (0b000001, Instr(Mnemonic.nop_x, X1)));
        var longBranch = prReserved; // Nyi("Long Branch");
        var longCall = prReserved; //  Nyi("Long Call");
        return new UnitDecoder('x', Mask(37, 4, "  X",
            misc,
            prReserved,
            prReserved,
            prReserved,

            prReserved,
            prReserved,
            Mask(20, 1, "  movl",
                Instr(Mnemonic.movl, r1, X2_imm(), qp),
                invalid),
            prReserved,

            prReserved,
            prReserved,
            prReserved,
            prReserved,

            longBranch,
            longCall,
            prReserved,
            prReserved));
    }
}
