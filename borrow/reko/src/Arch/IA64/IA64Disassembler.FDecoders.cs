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
    private static UnitDecoder MakeFdecoders()
    {
        var fp6bitExt0 = Sparse(27, 6, "  6 bit ext 0", prReserved,
            (0, Instr(Mnemonic.break_f, InstrClass.Terminates, F15)),
            (1, Instr(Mnemonic.nop_f, InstrClass.Linear | InstrClass.Padding, F15)),
            (0x10, Instr(Mnemonic.fmerge_s, F9)),
            (0x11, Instr(Mnemonic.fmerge_ns, F9)),
            (0x12, Instr(Mnemonic.fmerge_se, F9)),
            (0x1A, Instr(Mnemonic.fcvt_fx_trunc, F10)),
            (0x1B, Instr(Mnemonic.fcvt_fxu_trunc, F10)),
            (0x1C, Instr(Mnemonic.fcvt_xf, F11)),

            (0x28, Instr(Mnemonic.fpack, F9)),
            (0x2C, Instr(Mnemonic.fand, F9)),
            (0x2D, Instr(Mnemonic.fandcm, F9)),
            (0x2E, Instr(Mnemonic.@for, F9)),
            (0x2F, Instr(Mnemonic.fxor, F9)),

            (0x34, Instr(Mnemonic.fswap, F9)),
            (0x35, Instr(Mnemonic.fswap_nl, F9)),
            (0x36, Instr(Mnemonic.fswap_nr, F9)),
            (0x39, Instr(Mnemonic.fmix_lr, F9)),
            (0x3A, Instr(Mnemonic.fmix_r, F9)),
            (0x3B, Instr(Mnemonic.fmix_l, F9)),
            (0x3C, Instr(Mnemonic.fsxt_r, F9)),
            (0x3D, Instr(Mnemonic.fsxt_l, F9))
            );
        var fpReciprocalApprox0 = Mask(36, 1, "  Reciprocal approx 0",
            Instr(Mnemonic.frcpa, F6),
            Instr(Mnemonic.frsqrta, F7));
        var fpReciprocalApprox1 = Mask(36, 1, "  Reciprocal approx 0",
            Instr(Mnemonic.fprcpa, F6),
            Instr(Mnemonic.fprsqrta, F7));
        var fp6bitExt1 = Sparse(27, 6, "  6 bit ext 1", prReserved,
            (0x10, Instr(Mnemonic.fpmerge_s, F9)),
            (0x11, Instr(Mnemonic.fpmerge_ns, F9)),
            (0x12, Instr(Mnemonic.fpmerge_se, F9)),
            (0x14, Instr(Mnemonic.fpmin, F8)),
            (0x15, Instr(Mnemonic.fpmax, F8)),
            (0x16, Instr(Mnemonic.fpamin, F8)),
            (0x17, Instr(Mnemonic.fpamax, F8)),

            (0x18, Instr(Mnemonic.fpcvt_fx, F10)),
            (0x19, Instr(Mnemonic.fpcvt_fxu, F10)),
            (0x1A, Instr(Mnemonic.fpcvt_fx_trunc, F10)),
            (0x1B, Instr(Mnemonic.fpcvt_fxu_trunc, F10)),

            (0x30, Instr(Mnemonic.fpcmp_eq, F8)),
            (0x31, Instr(Mnemonic.fpcmp_lt, F8)),
            (0x32, Instr(Mnemonic.fpcmp_le, F8)),
            (0x33, Instr(Mnemonic.fpcmp_unord, F8)),
            (0x34, Instr(Mnemonic.fpcmp_neq, F8)),
            (0x35, Instr(Mnemonic.fpcmp_nlt, F8)),
            (0x36, Instr(Mnemonic.fpcmp_nle, F8)),
            (0x37, Instr(Mnemonic.fpcmp_ord, F8)));

        var fpMisc0 = Mask(33, 1, "  FP Misc 0",
            fp6bitExt0,
            fpReciprocalApprox0);

        var fpMisc1 = Mask(33, 1, "  FP Misc 1",
            fp6bitExt1,
            fpReciprocalApprox1);

        var fpCompare = Mask(Bf((33,1),(36,1),(12,1)), "  FP Compare",
            Instr(Mnemonic.fcmp_eq, F4),
            Instr(Mnemonic.fcmp_eq_unc, F4),
            Instr(Mnemonic.fcmp_lt, F4),
            Instr(Mnemonic.fcmp_lt_unc, F4),
            Instr(Mnemonic.fcmp_le, F4),
            Instr(Mnemonic.fcmp_le_unc, F4),
            Instr(Mnemonic.fcmp_unord, F4),
            Instr(Mnemonic.fcmp_unord_unc, F4));

        var fpClass = Mask(12, 1, "  FP Class",
            Instr(Mnemonic.fclass_m, F5),
            Instr(Mnemonic.fclass_m_unc, F5));

        var fma = Mask(36, 2, "  fma",
            Instr(Mnemonic.fma, F1),
            Instr(Mnemonic.fma_s, F1),
            Instr(Mnemonic.fma_d, F1),
            Instr(Mnemonic.fpma, F1));
        var fms = Mask(36, 2, "  fms",
            Instr(Mnemonic.fms, F1),
            Instr(Mnemonic.fms_s, F1),
            Instr(Mnemonic.fms_d, F1),
            Instr(Mnemonic.fpms, F1));
        var fnma = Mask(36, 2, "  fnma",
            Instr(Mnemonic.fpma, F1),
            Instr(Mnemonic.fnma_s, F1),
            Instr(Mnemonic.fnma_d, F1),
            Instr(Mnemonic.fpnma, F1));
        var fselectXma = Mask(36, 1, "  fselect/xma",
            Instr(Mnemonic.fselect, F3),
            Mask(34, 2, "  xma",
                Instr(Mnemonic.xma_l, F2),
                prReserved,
                Instr(Mnemonic.xma_hu, F2),
                Instr(Mnemonic.xma_h, F2)));

        return new UnitDecoder('f', Mask(37, 4, "  F",
            fpMisc0,
            fpMisc1,
            prReserved,
            prReserved,

            fpCompare,
            fpClass,
            prReserved,
            prReserved,

            fma,
            fma,
            fms,
            fms,

            fnma,
            fnma,
            fselectXma,
            prReserved));
    }
}
