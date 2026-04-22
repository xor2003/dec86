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
    private static UnitDecoder MakeMdecoders(
        WideDecoder compare,
        WideDecoder aluMmAlu,
        WideDecoder addImm22)
    {
        var sysMemMgmt4_2bit = Sparse(27, 4, "  Sys/Mem Mgmt 4+2-bit opcode extensions", Nyi(""),
            (0, Mask(31, 2, "  2-bits",
                Instr(Mnemonic.break_m, InstrClass.Terminates, I32_1_20, qp),
                Instr(Mnemonic.invala, M24),
                Instr(Mnemonic.fwb, M24),
                Instr(Mnemonic.srlz_d, M24))),
            (1u, Mask(31, 2, "  2-bits",
                Instr(Mnemonic.nop_m, InstrClass.Linear | InstrClass.Padding, I32_1_20, qp),
                invalid,
                invalid,
                Instr(Mnemonic.srlz_i, M24))),
            (2, Mask(31, 2, "  0010",
                invalid,
                Instr(Mnemonic.invala_e, M26),
                Instr(Mnemonic.mf, M24),
                invalid)),
            (3, Mask(31, 2, "  0010",
                invalid,
                Instr(Mnemonic.invala_e, M27),
                Instr(Mnemonic.mf_a, M24),
                Instr(Mnemonic.sync_i, M24))),
            (4, Instr(Mnemonic.sum, M44)),
            (5, Instr(Mnemonic.rum, M44)),
            (6, Instr(Mnemonic.ssm, M44)),
            (7, Instr(Mnemonic.rsm, M44)),
            (8, Mask(31, 2, "  1000",
                prReserved,
                prReserved,
                Instr(Mnemonic.mov_m, M30),
                prReserved)),
            (9, prReserved),
            (0xAu, Instr(Mnemonic.loadrs, M25)),
            (0xBu, invalid),
            (0xCu, Instr(Mnemonic.flushrs, M25)),
            (0xDu, invalid),
            (0xEu, invalid),
            (0xFu, invalid));


        var sysMemMgmt3bit = Mask(33, 3, "  Sys/Mem Mgmt 3-bit opcode extensions",
            sysMemMgmt4_2bit,
            invalid,
            invalid,
            invalid,

            Instr(Mnemonic.chk_a_nc, M22),
            Instr(Mnemonic.chk_a_clr, M22),
            Instr(Mnemonic.chk_a_nc, M23),
            Instr(Mnemonic.chk_a_clr, M23));

        var sysMemMgmt6bit = Sparse(27, 6, "  sysMemMgmt6bit", prReserved, //  Nyi("sysMemMgmt6bit"),
            (0x00, Instr(Mnemonic.mov_m, M42)),  //$TODO: specify regs
            (0x01, Instr(Mnemonic.mov_m, M42)),  //$TODO: specify regs
            (0x02, Instr(Mnemonic.mov_m, M42)),  //$TODO: specify regs
            (0x03, Instr(Mnemonic.mov_m, M42)),  //$TODO: specify regs
            (0x04, Instr(Mnemonic.mov_m, M42)),  //$TODO: specify regs
            (0x05, Instr(Mnemonic.mov_m, M42)),  //$TODO: specify regs

            (0x22, Instr(Mnemonic.mov_m, M31)),
            (0x2A, Instr(Mnemonic.mov_m, M29)),
            (0x38, Instr(Mnemonic.probe_r, M38)));
        var sysMemMgmt = Sparse(33, 3, "Sys/Mem Mgmt", prReserved,
            (0, sysMemMgmt6bit),
            (1, Instr(Mnemonic.chk_s_m, M20)),
            (3, Instr(Mnemonic.chk_s, M21)),
            (6, Instr(Mnemonic.alloc, r1, ar_pfs, I13_7, I27_4, I20_7)));
        var loadStore = Mask(30, 6, "  Load/Store",
            Instr(Mnemonic.ld1, M1_1),
            Instr(Mnemonic.ld2, M1_2),
            Instr(Mnemonic.ld4, M1_4),
            Instr(Mnemonic.ld8, M1_8),

            Instr(Mnemonic.ld1_s, M1_1),
            Instr(Mnemonic.ld2_s, M1_2),
            Instr(Mnemonic.ld4_s, M1_4),
            Instr(Mnemonic.ld8_s, M1_8),

            Instr(Mnemonic.ld1_a, M1_1),
            Instr(Mnemonic.ld2_a, M1_2),
            Instr(Mnemonic.ld4_a, M1_4),
            Instr(Mnemonic.ld8_a, M1_8),

            Instr(Mnemonic.ld1_sa, M1_1),
            Instr(Mnemonic.ld2_sa, M1_2),
            Instr(Mnemonic.ld4_sa, M1_4),
            Instr(Mnemonic.ld8_sa, M1_8),

            // 0x10
            Instr(Mnemonic.ld1_bias, M1_1),
            Instr(Mnemonic.ld2_bias, M1_2),
            Instr(Mnemonic.ld4_bias, M1_4),
            Instr(Mnemonic.ld8_bias, M1_8),

            Instr(Mnemonic.ld1_acq, M1_1),
            Instr(Mnemonic.ld2_acq, M1_2),
            Instr(Mnemonic.ld4_acq, M1_4),
            Instr(Mnemonic.ld8_acq, M1_8),

            invalid,
            invalid,
            invalid,
            Instr(Mnemonic.ld8_fill, M1_8),

            invalid,
            invalid,
            invalid,
            invalid,

            // 0x20
            Instr(Mnemonic.ld1_c_clr, M1_1),
            Instr(Mnemonic.ld2_c_clr, M1_2),
            Instr(Mnemonic.ld4_c_clr, M1_4),
            Instr(Mnemonic.ld8_c_clr, M1_8),

            Instr(Mnemonic.ld1_c_nc, M1_1),
            Instr(Mnemonic.ld2_c_nc, M1_2),
            Instr(Mnemonic.ld4_c_nc, M1_4),
            Instr(Mnemonic.ld8_c_nc, M1_8),

            Instr(Mnemonic.ld1_c_clr_acq, M1_1),
            Instr(Mnemonic.ld2_c_clr_acq, M1_2),
            Instr(Mnemonic.ld4_c_clr_acq, M1_4),
            Instr(Mnemonic.ld8_c_clr_acq, M1_8),

            invalid,
            invalid,
            invalid,
            invalid,

            Instr(Mnemonic.st1, M4_1),
            Instr(Mnemonic.st2, M4_2),
            Instr(Mnemonic.st4, M4_4),
            Instr(Mnemonic.st8, M4_8),

            Instr(Mnemonic.st1_rel, M4_1),
            Instr(Mnemonic.st2_rel, M4_2),
            Instr(Mnemonic.st4_rel, M4_4),
            Instr(Mnemonic.st8_rel, M4_8),

            invalid,
            invalid,
            invalid,
            Instr(Mnemonic.st8_spill, M4_8),

            invalid,
            invalid,
            invalid,
            invalid);
        var intLdStImm = Mask(30, 6, "  Load/Store",
            Instr(Mnemonic.ld1, M3_1),
            Instr(Mnemonic.ld2, M3_2),
            Instr(Mnemonic.ld4, M3_4),
            Instr(Mnemonic.ld8, M3_8),

            Instr(Mnemonic.ld1_s, M3_1),
            Instr(Mnemonic.ld2_s, M3_2),
            Instr(Mnemonic.ld4_s, M3_4),
            Instr(Mnemonic.ld8_s, M3_8),

            Instr(Mnemonic.ld1_a, M3_1),
            Instr(Mnemonic.ld2_a, M3_2),
            Instr(Mnemonic.ld4_a, M3_4),
            Instr(Mnemonic.ld8_a, M3_8),

            Instr(Mnemonic.ld1_sa, M3_1),
            Instr(Mnemonic.ld2_sa, M3_2),
            Instr(Mnemonic.ld4_sa, M3_4),
            Instr(Mnemonic.ld8_sa, M3_8),

            // 0x10
            Instr(Mnemonic.ld1_bias, M3_1),
            Instr(Mnemonic.ld2_bias, M3_2),
            Instr(Mnemonic.ld4_bias, M3_4),
            Instr(Mnemonic.ld8_bias, M3_8),

            Instr(Mnemonic.ld1_acq, M3_1),
            Instr(Mnemonic.ld2_acq, M3_2),
            Instr(Mnemonic.ld4_acq, M3_4),
            Instr(Mnemonic.ld8_acq, M3_8),

            invalid,
            invalid,
            invalid,
            Instr(Mnemonic.ld8_fill, M3_8),

            invalid,
            invalid,
            invalid,
            invalid,

            // 0x20
            Instr(Mnemonic.ld1_c_clr, M3_1),
            Instr(Mnemonic.ld2_c_clr, M3_2),
            Instr(Mnemonic.ld4_c_clr, M3_4),
            Instr(Mnemonic.ld8_c_clr, M3_8),

            Instr(Mnemonic.ld1_c_nc, M3_1),
            Instr(Mnemonic.ld2_c_nc, M3_2),
            Instr(Mnemonic.ld4_c_nc, M3_4),
            Instr(Mnemonic.ld8_c_nc, M3_8),

            Instr(Mnemonic.ld1_c_clr_acq, M3_1),
            Instr(Mnemonic.ld2_c_clr_acq, M3_2),
            Instr(Mnemonic.ld4_c_clr_acq, M3_4),
            Instr(Mnemonic.ld8_c_clr_acq, M3_8),

            invalid,
            invalid,
            invalid,
            invalid,

            Instr(Mnemonic.st1, M5_1),
            Instr(Mnemonic.st2, M5_2),
            Instr(Mnemonic.st4, M5_4),
            Instr(Mnemonic.st8, M5_8),

            Instr(Mnemonic.st1_rel, M5_1),
            Instr(Mnemonic.st2_rel, M5_2),
            Instr(Mnemonic.st4_rel, M5_4),
            Instr(Mnemonic.st8_rel, M5_8),

            invalid,
            invalid,
            invalid,
            Instr(Mnemonic.st8_spill, M5_8),

            invalid,
            invalid,
            invalid,
            invalid);

        var semaphoreGetf = Sparse(30, 6, "  Semaphore Getf", prReserved,
            (0x00, Instr(Mnemonic.cmpxchg1_acq, M16)),
            (0x01, Instr(Mnemonic.cmpxchg2_acq, M16)),
            (0x02, Instr(Mnemonic.cmpxchg4_acq, M16)),
            (0x03, Instr(Mnemonic.cmpxchg8_acq, M16)),
            (0x04, Instr(Mnemonic.cmpxchg1_rel, M16)),
            (0x05, Instr(Mnemonic.cmpxchg2_rel, M16)),
            (0x06, Instr(Mnemonic.cmpxchg4_rel, M16)),
            (0x07, Instr(Mnemonic.cmpxchg8_rel, M16)),
            (0x08, Instr(Mnemonic.xchg1, M16)),
            (0x09, Instr(Mnemonic.xchg2, M16)),
            (0x0A, Instr(Mnemonic.xchg4, M16)),
            (0x0B, Instr(Mnemonic.xchg8, M16)),
            (0x12, Instr(Mnemonic.fetchadd4_acq, M17)),
            (0x13, Instr(Mnemonic.fetchadd8_acq, M17)),
            (0x16, Instr(Mnemonic.fetchadd4_rel, M17)),
            (0x17, Instr(Mnemonic.fetchadd8_rel, M17)),
            (0x1C, Instr(Mnemonic.getf_sig, M19)),
            (0x1D, Instr(Mnemonic.getf_exp, M19)),
            (0x1E, Instr(Mnemonic.getf_s, M19)),
            (0x1F, Instr(Mnemonic.getf_d, M19))
            );

        var loadReg = Sparse(30, 6, "   load int + reg", prReserved,
            (0x00, Instr(Mnemonic.ld1, M2)),
            (0x01, Instr(Mnemonic.ld2, M2)),
            (0x02, Instr(Mnemonic.ld4, M2)),
            (0x03, Instr(Mnemonic.ld8, M2)),
            (0x04, Instr(Mnemonic.ld1_s, M2)),
            (0x05, Instr(Mnemonic.ld2_s, M2)),
            (0x06, Instr(Mnemonic.ld4_s, M2)),
            (0x07, Instr(Mnemonic.ld8_s, M2)),
            (0x08, Instr(Mnemonic.ld1_a, M2)),
            (0x09, Instr(Mnemonic.ld2_a, M2)),
            (0x0A, Instr(Mnemonic.ld4_a, M2)),
            (0x0B, Instr(Mnemonic.ld8_a, M2)),
            (0x0C, Instr(Mnemonic.ld1_sa, M2)),
            (0x0D, Instr(Mnemonic.ld2_sa, M2)),
            (0x0E, Instr(Mnemonic.ld4_sa, M2)),
            (0x0F, Instr(Mnemonic.ld8_sa, M2)));

        var intLdRegGetf = Mask(Bf((36, 1), (27, 1)), "  Int Ld +Reg/getf",
            loadStore,
            semaphoreGetf,
            loadReg,
            invalid);

        var flLoadStore = Sparse(30, 6, "  fpLoadStore", prReserved,
            (0x00, Instr(Mnemonic.ldfe, M6)),
            (0x01, Instr(Mnemonic.ldf8, M6)),
            (0x02, Instr(Mnemonic.ldfs, M6)),
            (0x03, Instr(Mnemonic.ldfd, M6)),
            (0x04, Instr(Mnemonic.ldfe_s, M6)),
            (0x05, Instr(Mnemonic.ldf8_s, M6)),
            (0x06, Instr(Mnemonic.ldfs_s, M6)),
            (0x07, Instr(Mnemonic.ldfd_s, M6)),
            (0x08, Instr(Mnemonic.ldfe_a, M6)),
            (0x09, Instr(Mnemonic.ldf8_a, M6)),
            (0x0A, Instr(Mnemonic.ldfs_a, M6)),
            (0x0B, Instr(Mnemonic.ldfd_a, M6)),
            (0x0C, Instr(Mnemonic.ldfe_sa, M6)),
            (0x0D, Instr(Mnemonic.ldf8_sa, M6)),
            (0x0E, Instr(Mnemonic.ldfs_sa, M6)),
            (0x0F, Instr(Mnemonic.ldfd_sa, M6)),
            (0x1B, Instr(Mnemonic.ldf_fill, M6)),
            (0x30, Instr(Mnemonic.stfe, M9)),
            (0x31, Instr(Mnemonic.stf8, M9)),
            (0x32, Instr(Mnemonic.stfs, M9)),
            (0x33, Instr(Mnemonic.stfd, M9)),
            (0x3B, Instr(Mnemonic.stf_spill, M9)));

        var fpLoadPair_setFr = Sparse(30, 6, "  fpLoadPair/set FR", prReserved,
            (0x01, Instr(Mnemonic.ldfp8, M11)),
            (0x02, Instr(Mnemonic.ldfps, M11)),
            (0x03, Instr(Mnemonic.ldfpd, M11)),
            (0x05, Instr(Mnemonic.ldfp8_s, M11)),
            (0x06, Instr(Mnemonic.ldfps_s, M11)),
            (0x07, Instr(Mnemonic.ldfpd_s, M11)),
            (0x09, Instr(Mnemonic.ldfp8_a, M11)),
            (0x0A, Instr(Mnemonic.ldfps_a, M11)),
            (0x0B, Instr(Mnemonic.ldfpd_a, M11)),
            (0x0D, Instr(Mnemonic.ldfp8_sa, M11)),
            (0x0E, Instr(Mnemonic.ldfps_sa, M11)),
            (0x0F, Instr(Mnemonic.ldfpd_sa, M11)),
            (0x1C, Instr(Mnemonic.setf_sig, M18)),
            (0x1D, Instr(Mnemonic.setf_exp, M18)),
            (0x1E, Instr(Mnemonic.setf_s, M18)),
            (0x1F, Instr(Mnemonic.setf_d, M18)),
            (0x21, Instr(Mnemonic.ldfp8_c_clr, M11)),
            (0x22, Instr(Mnemonic.ldfps_c_clr, M11)),
            (0x23, Instr(Mnemonic.ldfpd_c_clr, M11)),
            (0x25, Instr(Mnemonic.ldfp8_c_nc, M11)),
            (0x26, Instr(Mnemonic.ldfps_c_nc, M11)),
            (0x27, Instr(Mnemonic.ldfpd_c_nc, M11)));

        var fpLoad_reg = Sparse(30, 6, "fpLoad_reg", prReserved,
            (0x00, Instr(Mnemonic.ldfe, M7)),
            (0x01, Instr(Mnemonic.ldf8, M7)),
            (0x02, Instr(Mnemonic.ldfs, M7)),
            (0x03, Instr(Mnemonic.ldfd, M7)),
            (0x04, Instr(Mnemonic.ldfe_s, M7)),
            (0x05, Instr(Mnemonic.ldf8_s, M7)),
            (0x06, Instr(Mnemonic.ldfs_s, M7)),
            (0x07, Instr(Mnemonic.ldfd_s, M7)),
            (0x08, Instr(Mnemonic.ldfe_a, M7)),
            (0x09, Instr(Mnemonic.ldf8_a, M7)),
            (0x0A, Instr(Mnemonic.ldfs_a, M7)),
            (0x0B, Instr(Mnemonic.ldfd_a, M7)),
            (0x0C, Instr(Mnemonic.ldfe_sa, M7)),
            (0x0D, Instr(Mnemonic.ldf8_sa, M7)),
            (0x0E, Instr(Mnemonic.ldfs_sa, M7)),
            (0x0F, Instr(Mnemonic.ldfd_sa, M7)),
            (0x1B, Instr(Mnemonic.ldf_fill, M7)),
            (0x20, Instr(Mnemonic.ldfe_c_clr, M7)),
            (0x21, Instr(Mnemonic.ldf8_c_clr, M7)),
            (0x22, Instr(Mnemonic.ldfs_c_clr, M7)),
            (0x23, Instr(Mnemonic.ldfd_c_clr, M7)),
            (0x24, Instr(Mnemonic.ldfe_c_nc, M7)),
            (0x25, Instr(Mnemonic.ldf8_c_nc, M7)),
            (0x26, Instr(Mnemonic.ldfs_c_nc, M7)),
            (0x27, Instr(Mnemonic.ldfd_c_nc, M7)),
            (0x2C, Instr(Mnemonic.lfetch, M14)),
            (0x2D, Instr(Mnemonic.lfetch_excl, M14)),
            (0x2E, Instr(Mnemonic.lfetch_fault, M14)),
            (0x2F, Instr(Mnemonic.lfetch_fault_excl, M14))

            );
        var fpLoadPair_imm = Sparse(30, 6, "  fpLoadPair_imm", prReserved,
            (0x01, Instr(Mnemonic.ldfp8, M12, N16)),
            (0x02, Instr(Mnemonic.ldfps, M12, N8)),
            (0x03, Instr(Mnemonic.ldfpd, M12, N16)),
            (0x05, Instr(Mnemonic.ldfp8_s, M12, N16)),
            (0x06, Instr(Mnemonic.ldfps_s, M12, N8)),
            (0x07, Instr(Mnemonic.ldfpd_s, M12, N16)),
            (0x09, Instr(Mnemonic.ldfp8_a, M12, N16)),
            (0x0A, Instr(Mnemonic.ldfps_a, M12, N8)),
            (0x0B, Instr(Mnemonic.ldfpd_a, M12, N16)),
            (0x0D, Instr(Mnemonic.ldfp8_sa, M12, N16)),
            (0x0E, Instr(Mnemonic.ldfps_sa, M12, N8)),
            (0x0F, Instr(Mnemonic.ldfpd_sa, M12, N16)),
            (0x21, Instr(Mnemonic.ldfp8_c_clr, M12, N16)),
            (0x22, Instr(Mnemonic.ldfps_c_clr, M12, N8)),
            (0x23, Instr(Mnemonic.ldfpd_c_clr, M12, N16)),
            (0x25, Instr(Mnemonic.ldfp8_c_nc, M12, N16)),
            (0x26, Instr(Mnemonic.ldfps_c_nc, M12, N8)),
            (0x27, Instr(Mnemonic.ldfpd_c_nc, M12, N16)));

        var fpLdStRegSetf = Mask(Bf((36, 1), (27, 1)), "  FP Ld/St +Reg/setf",
            flLoadStore,
            fpLoadPair_setFr,
            fpLoad_reg,
            fpLoadPair_imm);
        var fpLdStImm = Sparse(30, 6, "  FP Ld/St +Imm", prReserved,
            (0x00, Instr(Mnemonic.ldfe, M8)),
            (0x01, Instr(Mnemonic.ldf8, M8)),
            (0x02, Instr(Mnemonic.ldfs, M8)),
            (0x03, Instr(Mnemonic.ldfd, M8)),
            (0x04, Instr(Mnemonic.ldfe_s, M8)),
            (0x05, Instr(Mnemonic.ldf8_s, M8)),
            (0x06, Instr(Mnemonic.ldfs_s, M8)),
            (0x07, Instr(Mnemonic.ldfd_s, M8)),
            (0x08, Instr(Mnemonic.ldfe_a, M8)),
            (0x09, Instr(Mnemonic.ldf8_a, M8)),
            (0x0A, Instr(Mnemonic.ldfs_a, M8)),
            (0x0B, Instr(Mnemonic.ldfd_a, M8)),
            (0x0C, Instr(Mnemonic.ldfe_sa, M8)),
            (0x0D, Instr(Mnemonic.ldf8_sa, M8)),
            (0x0E, Instr(Mnemonic.ldfs_sa, M8)),
            (0x0F, Instr(Mnemonic.ldfd_sa, M8)),

            (0x1B, Instr(Mnemonic.ldf_fill, M8)),

            (0x20, Instr(Mnemonic.ldfe_c_clr, M8)),
            (0x21, Instr(Mnemonic.ldf8_c_clr, M8)),
            (0x22, Instr(Mnemonic.ldfs_c_clr, M8)),
            (0x23, Instr(Mnemonic.ldfd_c_clr, M8)),
            (0x24, Instr(Mnemonic.ldfe_c_nc, M8)),
            (0x25, Instr(Mnemonic.ldf8_c_nc, M8)),
            (0x26, Instr(Mnemonic.ldfs_c_nc, M8)),
            (0x27, Instr(Mnemonic.ldfd_c_nc, M8)),
            (0x2C, Instr(Mnemonic.lfetch, M15)),
            (0x2D, Instr(Mnemonic.lfetch_excl, M15)),
            (0x2E, Instr(Mnemonic.lfetch_fault, M15)),
            (0x2F, Instr(Mnemonic.lfetch_fault_excl, M15)),
            (0x30, Instr(Mnemonic.stfe, M10)),
            (0x31, Instr(Mnemonic.stf8, M10)),
            (0x32, Instr(Mnemonic.stfs, M10)),
            (0x33, Instr(Mnemonic.stfd, M10)),

            (0x3B, Instr(Mnemonic.stf_fill, M10)));


        return new UnitDecoder('m', Mask(37, 4, "  M",
            sysMemMgmt3bit,
            sysMemMgmt,
            prReserved,
            prReserved,

            intLdRegGetf,
            intLdStImm,
            fpLdStRegSetf,
            fpLdStImm,

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
