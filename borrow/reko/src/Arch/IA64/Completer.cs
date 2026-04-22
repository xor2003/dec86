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

public enum Completer
{
    Invalid = -1,

    None = 0,

    LdMask = 3,
    Nt1 = 1,
    Nta = 2,

    Prefetch_Mask = 12,
    Prefetch_None = 0,
    Prefetch_Few = 4,
    Prefetch_Many = 8,

    Whether_Mask = 0b111_0000,
    Whether_None = 0,
    Whether_Sptk = 16,
    Whether_Spnt = 32,
    Whether_Dptk = 64,
    Whether_Dpnt = 96,

    BranchCache_None = 0,
    BranchCache_Clr = 128,

    Important = 0x100,

    FpStatusMask = 0xE00,
    FpS0 = 0x200,
    FpS1 = 0x400,
    FpS2 = 0x600,
    FpS3 = 0x800,
}
