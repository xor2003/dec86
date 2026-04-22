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
using Reko.Core.Machine;

namespace Reko.Arch.IA64;

using WideDecoder = WideDecoder<IA64Disassembler, Mnemonic, IA64Instruction>;

public partial class IA64Disassembler
{

    private static UnitDecoder MakeIdecoders(
        WideDecoder compare,
        WideDecoder aluMmAlu,
        WideDecoder addImm22)
    {
        var misc6bitExt = Mask(31, 2, "  Misc I-Unit 6-bit Opcode Extensions",
            Sparse(27, 4, "  0", invalid,
                (0b0000, Instr(Mnemonic.break_i, InstrClass.Terminates, I32_1_20, qp)),
                (0b0001, Instr(Mnemonic.nop_i, InstrClass.Linear | InstrClass.Padding, I32_1_20, qp)),
                (0b1010, Instr(Mnemonic.mov_i, I27))),
            Mask(27, 4, "  1",
                Instr(Mnemonic.zxt1, I29),
                Instr(Mnemonic.zxt2, I29),
                Instr(Mnemonic.zxt4, I29),
                invalid,

                Instr(Mnemonic.sxt1, I29),
                Instr(Mnemonic.sxt2, I29),
                Instr(Mnemonic.sxt4, I29),
                invalid,

                Instr(Mnemonic.czx1_l, I29),
                Instr(Mnemonic.czx2_l, I29),
                invalid,
                invalid,

                Instr(Mnemonic.czx1_r, I29),
                Instr(Mnemonic.czx2_r, I29),
                invalid,
                invalid),
            Sparse(27, 4, "  2", invalid,
                (0xA, Instr(Mnemonic.mov_i, I26))),
            Sparse(27, 4, "  3", invalid,
                (0x0, Instr(Mnemonic.mov, r1, ip)),
                (0x1, Instr(Mnemonic.mov, I22)),
                (0x2, Instr(Mnemonic.mov, I28)),
                (0x3, Instr(Mnemonic.mov, r1, pr))));

        var misc = Mask(33, 3, "  misc",
            misc6bitExt,
            Instr(Mnemonic.chk_s_i, I20),
            Instr(Mnemonic.mov, I24),
            Instr(Mnemonic.mov, pr, I23),

            invalid,
            invalid,
            invalid,
            Instr(Mnemonic.mov, I21));

        var testbit = Mask(31, 1, "  y",
            Mask(Bf((33, 1), (36, 1), (12, 1)), "  test",
                Instr(Mnemonic.tbit_z, I16),
                Instr(Mnemonic.tbit_z_unc, I16),
                Instr(Mnemonic.tbit_z_and, I16),
                Instr(Mnemonic.tbit_nz_and, I16),
                Instr(Mnemonic.tbit_z_or, I16),
                Instr(Mnemonic.tbit_nz_or, I16),
                Instr(Mnemonic.tbit_z_or_andcm, I16),
                Instr(Mnemonic.tbit_nz_or_andcm, I16)),
            Mask(Bf((33, 1), (36, 1), (12, 1)), "  tnat",
                Instr(Mnemonic.tnat_z, I17),
                Instr(Mnemonic.tnat_z_unc, I17),
                Instr(Mnemonic.tnat_z_and, I17),
                Instr(Mnemonic.tnat_nz_and, I17),
                Instr(Mnemonic.tnat_z_or, I17),
                Instr(Mnemonic.tnat_nz_or, I17),
                Instr(Mnemonic.tnat_z_or_andcm, I17),
                Instr(Mnemonic.tnat_nz_or_andcm, I17)));

        var shiftTestBit = Mask(33, 1, "  shift/test bit",
            Mask(34, 2, "  x_2",
                testbit,
                Mask(31, 1, "  y",
                    Instr(Mnemonic.extr_u, I11),
                    Instr(Mnemonic.extr, I11)),
                invalid,
                Instr(Mnemonic.shrp, I10)),
            Mask(34, 2, "  0",
                testbit,
                Mask(13, 1, "  y",
                    Instr(Mnemonic.dep_z, I12),
                    Instr(Mnemonic.dep_z, I13)),
                invalid,
                Instr(Mnemonic.dep, I14)));
        var variableShift = Mask(34, 2, "  x_2a",
            Sparse(28, 4, "x_2c:x_2b", invalid,
                (0, Instr(Mnemonic.shr_u, I5)),
                (2, Instr(Mnemonic.shr, I5)),
                (4, Instr(Mnemonic.shl, I7))),
            invalid,
            invalid,
            invalid);

        var mmSize1 = Mask(32, 1, "  mm size 1",
             Mask(34, 2, "  x_2a",
                 invalid,
                 invalid,
                 Mask(28, 2, "  x_2a = 2",
                     Nyi("x_2c = 0"),
                     Nyi("x_2c = 1"),
                     Nyi("x_2c = 2"),
                     Nyi("x_2c = 3")),
                 Mask(28, 2, "  x_2a = 3",
                     invalid,
                     invalid,
                     Mask(30, 2, "x_2b = 2",
                         invalid,
                         invalid,
                         Nyi("Mnemonic.mux1, I3"),
                         invalid),
                     invalid)
             ),
             prReserved);

        var mmSize2 = Mask(32, 1, "  mm size 2",
            Mask(34, 2, "  x_2a",
                Mask(28, 2, "  x_2a = 0",
                    Mask(30, 2, "  x_2b = 0",
                        Instr(Mnemonic.pshr4_u, I5),
                        Instr(Mnemonic.pshl4, I5),
                        prReserved,
                        prReserved),
                    prReserved,
                    Mask(30, 2, "  x_2b = 0",
                        Instr(Mnemonic.pshr4_u, I6),
                        prReserved,
                        prReserved,
                        prReserved),
                    prReserved),
                Mask(28, 2, "x_2a = 1",
                    prReserved,
                    Mask(30, 2, "  x_2b = 1",
                        Instr(Mnemonic.pshr2_u, I6),
                        prReserved,
                        Instr(Mnemonic.popcnt, I9),
                        prReserved),
                    prReserved,
                    Mask(30, 2, "  x_2b = 3",
                        Instr(Mnemonic.pshr2, I6),
                        prReserved,
                        prReserved,
                        prReserved)),
                Mask(28, 2, "  x_2a = 2",
                    Mask(30, 2, "  x_2b = 0",
                        Instr(Mnemonic.pack2_uss, I2),
                        Instr(Mnemonic.unpack2_h, I2),
                        Instr(Mnemonic.mix2_r, I2),
                        prReserved),
                    Mask(30, 2, "  x_2b = 1",
                        prReserved,
                        prReserved,
                        prReserved,
                        Instr(Mnemonic.pmpy2_r, I2)),
                    Mask(30, 2, "  x_2b = 2",
                        Instr(Mnemonic.pack2_sss, I2),
                        Instr(Mnemonic.unpack2_l, I2),
                        Instr(Mnemonic.mix2_l, I2),
                        prReserved),
                    Mask(30, 2, "  x_2b = 3",
                        Instr(Mnemonic.pmin2, I2),
                        Instr(Mnemonic.pmax2, I2),
                        prReserved,
                        Instr(Mnemonic.pmpy2_l, I2))),
                Mask(28, 2, "x_2a = 3",
                    prReserved,
                    Mask(30, 2, "  x_2b = 1",
                        prReserved,
                        Instr(Mnemonic.pshl2, I8),
                        prReserved,
                        prReserved),
                    Mask(30, 2, "  x_2b = 2",
                        prReserved,
                        prReserved,
                        Instr(Mnemonic.mux2, I4),
                        prReserved),
                    prReserved)
            ),
            prReserved);

        var mmSize4 = Mask(32, 1, "  mm size 4",
            Mask(34, 2, "  x_2a",
                Mask(28, 2, "  x_2a = 0",
                    Mask(30, 2, "  x_2b = 0",
                        Instr(Mnemonic.pshr4_u, I5),
                        Instr(Mnemonic.pshl4, I7),
                        invalid,
                        invalid),
                    invalid,
                    Mask(30, 2, "  x_2b = 2",
                        Instr(Mnemonic.pshr4, I5),
                        invalid,
                        invalid,
                        invalid),
                    invalid),
                Mask(28, 2, "  x_2a = 1",
                    prReserved,
                    Mask(30, 2, "  x_2b = 1",
                        Instr(Mnemonic.pshr4_u, I6),
                        prReserved,
                        prReserved,
                        prReserved),
                    prReserved,
                    prReserved),
                Sparse(28, 2, "  x_2a = 2", Nyi("x_2a = 2"),
                    (2, Mask(30, 2, "  x_2b = 2",
                        Nyi("pack4.sss I2"),
                        Nyi("upack4.l I2"),
                        Instr(Mnemonic.mix4_l, I2),
                        invalid))),
                Nyi("x_2a = 3")
            ),
            prReserved);


        var mmMpyShift = Mask(Bf((36, 1), (33, 1)), "  mm/mpy shift",
            mmSize1,
            mmSize2,
            mmSize4,
            variableShift);

        return new UnitDecoder('i', Mask(37, 4, "  I",
            misc,
            prReserved,
            prReserved,
            prReserved,

            Instr(Mnemonic.dep, I15),
            shiftTestBit,
            prReserved,
            mmMpyShift,

            aluMmAlu,
            addImm22,
            prReserved,
            prReserved,

            compare,
            compare,
            compare,
            prReserved));
    }
}
