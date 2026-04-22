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
using Reko.Core.Lib;
using Reko.Core.Machine;
using Reko.Core.Memory;
using Reko.Core.Services;
using Reko.Core.Types;
using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Reko.Arch.IA64;

#pragma warning disable IDE1006

using WideDecoder = WideDecoder<IA64Disassembler, Mnemonic, IA64Instruction>;
using WideMutator = WideMutator<IA64Disassembler>;

public partial class IA64Disassembler : DisassemblerBase<IA64Bundle, Mnemonic>
{
    private const ulong slot0Mask = (1ul << 41) - 1u;
    private const ulong slot1MaskLo = (1ul << 18) - 1u;
    private const ulong slot1MaskHi = (1ul << 23) - 1u;
    private const ulong slot2Mask = (1ul << 41) - 1u;

    private static readonly TemplateDecoders[] templates;
    private static InstrDecoder invalid;
    private static InstrDecoder nop;
    private static InstrDecoder reserved;
    private static InstrDecoder prReserved;
    private static WideDecoder Bdecoders;
    private static WideDecoder Idecoders;
    private static WideDecoder Fdecoders;
    private static WideDecoder Ldecoders;
    private static WideDecoder Mdecoders;
    private static WideDecoder Xdecoders;
    private static readonly Bitfield bf0_6 = new Bitfield(0, 6);
    private static readonly Bitfield bf0_41 = new Bitfield(0, 41);
    private static readonly Bitfield bf3_2 = new Bitfield(3, 2);
    private static readonly Bitfield bf6_3 = new Bitfield(6, 3);
    private static readonly Bitfield bf6_7 = new Bitfield(6, 7);
    private static readonly Bitfield bf6_6 = new Bitfield(6, 6);
    private static readonly Bitfield bf12_1 = new Bitfield(12, 1);
    private static readonly Bitfield bf13_2 = new Bitfield(13, 2);
    private static readonly Bitfield bf13_3 = new Bitfield(13, 3);
    private static readonly Bitfield bf13_7 = new Bitfield(13, 7);
    private static readonly Bitfield bf14_5 = new Bitfield(14, 5);
    private static readonly Bitfield bf14_6 = new Bitfield(14, 6);
    private static readonly Bitfield bf15_1 = new Bitfield(15, 1);
    private static readonly Bitfield bf20_2 = new Bitfield(20, 2);
    private static readonly Bitfield bf20_5 = new Bitfield(20, 5);
    private static readonly Bitfield bf20_6 = new Bitfield(20, 6);
    private static readonly Bitfield bf20_7 = new Bitfield(20, 7);
    private static readonly Bitfield bf20_8 = new Bitfield(20, 8);
    private static readonly Bitfield bf23_1 = new Bitfield(23, 1);
    private static readonly Bitfield bf24_9 = new Bitfield(24, 9);
    private static readonly Bitfield bf27_2 = new Bitfield(27, 2);
    private static readonly Bitfield bf27_4 = new Bitfield(27, 4);
    private static readonly Bitfield bf27_6 = new Bitfield(27, 6);
    private static readonly Bitfield bf27_7 = new Bitfield(27, 7);
    private static readonly Bitfield bf28_2 = new Bitfield(28, 2);
    private static readonly Bitfield bf31_6 = new Bitfield(31, 6);
    private static readonly Bitfield bf33_2 = new Bitfield(33, 2);
    private static readonly Bitfield[] bf33_2_6_7 = Bf((33, 2), (6, 7));
    private static readonly Bitfield[] bf33_2_20_7 = Bf((33, 2), (20, 7));
    private static readonly Bitfield bf34_2 = new Bitfield(34, 2);
    private static readonly Bitfield bf35_1 = new Bitfield(35, 1);
    private static readonly Bitfield[] bf36_1_6_20 = Bf((36, 1), (6, 20));
    private static readonly Bitfield[] bf36_1_6_27 = Bf((36, 1), (6, 27));
    private static readonly Bitfield[] bf36_1_13_7 = Bf((36, 1), (13, 7));
    private static readonly Bitfield[] bf36_1_13_20 = Bf((36, 1), (13, 20));
    private static readonly Bitfield[] bf36_1_20_13_6_7 = Bf((36, 1), (20, 13), (6, 7));
    private static readonly Bitfield[] bf36_1_24_8_6_7 = Bf((36, 1), (24, 8), (6, 7));
    private static readonly Bitfield[] bf36_1_27_1_13_7 = Bf((36, 1), (27, 1), (13, 7));
    private static readonly Bitfield[] bf36_1_27_6_13_7 = Bf((36, 1), (27, 6), (13, 7));
    private static readonly Bitfield[] bf36_1_27_1_6_7 = Bf((36, 1), (27, 1), (6, 7));
    private static readonly Bitfield[] bf36_1_31_2_6_21 = Bf((36, 1), (31, 2), (6, 21));
    
    private readonly IA64Architecture arch;
    private readonly EndianImageReader rdr;
    private readonly List<MachineOperand> ops;
    private Address addr;
    private FlagGroupStorage qpReg;
    private ulong imm41;            // 41-bit value of an L instruction.
    private Completer completer;

    public IA64Disassembler(IA64Architecture arch, EndianImageReader rdr)
    {
        this.arch = arch;
        this.rdr = rdr;
        this.ops = [];
        this.qpReg = Registers.PredicateRegisters[0];
    }

    public override IA64Bundle? DisassembleInstruction()
    {
        this.addr = rdr.Address;
        if ((addr.Offset & 0x0f) != 0)
        {
            // IA-64 instructions must be 16-byte aligned.
            _ = this; //$DEBUG
        }
        if (!rdr.TryReadUInt64(out ulong uBundleLo) ||
            !rdr.TryReadUInt64(out ulong uBundleHi))
        {
            return null;
        }
        var iTemplate = uBundleLo & 0x1F;
        var uSlot0 = (uBundleLo >> 5) & slot0Mask;
        var uSlot1 = ((uBundleLo >> 46) & slot1MaskLo) | ((uBundleHi & slot1MaskHi) << 18);
        var uSlot2 = (uBundleHi >> 23) & slot2Mask;

        var template = templates[iTemplate];
        var instr0 = DisassembleSlot(uSlot0, template, template.Slot0, 0x100, 0, 6);
        var instr1 = DisassembleSlot(uSlot1, template, template.Slot1, 0x010, 6, 6);
        var instr2 = DisassembleSlot(uSlot2, template, template.Slot2, 0x001, 12, 4);

        var result = MakeBundle(instr0, instr1, instr2);
        result.Address = addr;
        result.Length = (int) (rdr.Address - addr);
        return result;
    }

    private IA64Instruction DisassembleSlot(
        ulong uInstr, 
        TemplateDecoders template,
        WideDecoder decoder,
        int stopMask,
        int offset,
        int length)
    {
        var instr = decoder.Decode(uInstr, this);
        instr.Address = addr + offset;
        instr.Length = length;
        instr.Stop = (template.StopMask & stopMask) != 0;
        Clear();
        return instr;
    }

    private static IA64Bundle MakeBundle(IA64Instruction slot0, IA64Instruction slot1, IA64Instruction slot2)
    {
        return new IA64Bundle([slot0, slot1, slot2]);
    }

    private void Clear()
    {
        this.ops.Clear();
        this.completer = 0;
        this.qpReg = Registers.PredicateRegisters[0];
    }

    public override IA64Bundle MakeInstruction(InstrClass iclass, Mnemonic mnemonic)
    {
        throw new NotImplementedException();
    }

    public override IA64Bundle CreateInvalidInstruction()
    {
        var invalid = new IA64Instruction
        {
            InstructionClass = InstrClass.Invalid,
            Mnemonic = Mnemonic.Invalid,
            Operands = []
        };
        return MakeBundle(invalid, invalid, invalid);
    }

    #region Mutators

    private static WideMutator GpReg(int bitpos, int length)
    {
        var field = new Bitfield(bitpos, length);
        return (u, d) =>
        {
            var iReg = field.Read(u);
            var reg = Registers.GpRegisters[iReg];
            d.ops.Add(reg);
            return true;
        };
    }
    private static readonly WideMutator r1 = GpReg(6, 7);
    private static readonly WideMutator r2 = GpReg(13, 7);
    private static readonly WideMutator r3 = GpReg(20, 7);
    private static readonly WideMutator r3_2 = GpReg(20, 2);

    private static WideMutator FpReg(int bitpos, int length)
    {
        var field = new Bitfield(bitpos, length);
        return (u, d) =>
        {
            var iReg = field.Read(u);
            var reg = Registers.FpRegisters[iReg];
            d.ops.Add(reg);
            return true;
        };
    }
    private static readonly WideMutator f1 = FpReg(6, 7);
    private static readonly WideMutator f2 = FpReg(13, 7);
    private static readonly WideMutator f3 = FpReg(20, 7);
    private static readonly WideMutator f4 = FpReg(27, 7);

    private static WideMutator BranchReg(int bitpos, int length)
    {
        var field = new Bitfield(bitpos, length);
        return (u, d) =>
        {
            var iReg = field.Read(u);
            var reg = Registers.BranchRegisters[iReg];
            d.ops.Add(reg);
            return true;
        };
    }
    private static readonly WideMutator b1 = BranchReg(6, 3);
    private static readonly WideMutator b2 = BranchReg(13, 3);

    private static WideMutator PredReg(int bitpos, int length)
    {
        var field = new Bitfield(bitpos, length);
        return (u, d) =>
        {
            var iReg = field.Read(u);
            var reg = Registers.PredicateRegisters[iReg];
            d.ops.Add(reg);
            return true;
        };
    }
    private static readonly WideMutator p1 = PredReg(6, 6);
    private static readonly WideMutator p2 = PredReg(27, 6);

    private static WideMutator ApplicationReg(int bitpos, int length)
    {
        var field = new Bitfield(bitpos, length);
        return (u, d) =>
        {
            var iReg = field.Read(u);
            var reg = Registers.ApplicationRegisters[iReg];
            d.ops.Add(reg);
            return true;
        };
    }
    private static readonly WideMutator ar3 = ApplicationReg(20, 7);

    private static WideMutator Register(RegisterStorage reg)
    {
        return (u, d) =>
        {
            d.ops.Add(reg);
            return true;
        };
    }
    private static readonly WideMutator r0 = Register(Registers.GpRegisters[0]);
    private static readonly WideMutator ar_pfs = Register(Registers.PFS);
    private static readonly WideMutator ip = Register(Registers.IP);
    private static readonly WideMutator pr = Register(Registers.PR);

    private static WideMutator Imm(PrimitiveType dt, Bitfield[] fields)
    {
        return (u, d) =>
        {
            var imm = Bitfield.ReadFields(fields, u);
            var op = Constant.Create(dt, imm);
            d.ops.Add(op);
            return true;
        };
    }
    private static readonly WideMutator I9 = Imm(PrimitiveType.UInt16, Bf((6, 7), (27, 1), (36, 1)));
    private static readonly WideMutator I13_7 = Imm(PrimitiveType.UInt32, Bf((13, 7)));
    private static readonly WideMutator I20_7 = Imm(PrimitiveType.UInt32, Bf((20, 7)));
    private static readonly WideMutator I27_4 = Imm(PrimitiveType.UInt32, Bf((27, 4)));
    private static readonly WideMutator I32_1_20 = Imm(PrimitiveType.Word32, Bf((36, 1), (6, 20)));
    private static readonly WideMutator I41 = Imm(PrimitiveType.Word64, Bf((0, 41)));
    private static readonly WideMutator I64 = Imm(PrimitiveType.Word64, Bf((0, 64)));

    private static WideMutator ImmS(PrimitiveType dt, Bitfield[] fields)
    {
        return (u, d) =>
        {
            var imm = Bitfield.ReadSignedFields(fields, u);
            var op = Constant.Create(dt, imm);
            d.ops.Add(op);
            return true;
        };
    }

    private static readonly WideMutator IsImm9 = ImmS(PrimitiveType.Int64, Bf((13, 7), (27, 1), (36, 1)));
    private static readonly WideMutator IsImm22 = ImmS(PrimitiveType.Int64, Bf((36, 1), (22, 5), (27, 9), (13, 7)));

    /// <summary>
    /// Add a literal number to the operand list.
    /// </summary>
    /// <param name="n"></param>
    private static WideMutator Number(int n)
    {
        return (u, d) =>
        {
            var c = Constant.Int32(n);
            d.ops.Add(c);
            return true;
        };
    }
    private static readonly WideMutator N8 = Number(8);
    private static readonly WideMutator N16 = Number(16);

    private static bool LImmediate(ulong uInstr, IA64Disassembler dasm)
    {
        dasm.imm41 = bf0_41.Read(uInstr);
        return true;
    }

    private static WideMutator X2_imm()
    {
        var X2_fields = Bf((21,1),(22,5),(27,9),(13,7));
        return (uInstr, dasm) =>
        {
            ulong imm = (uInstr >> 36) & 1;
            imm = (imm << 41) | dasm.imm41;
            imm = (imm << 22) | Bitfield.ReadFields(X2_fields, uInstr);
            dasm.ops.Add(Constant.Create(PrimitiveType.Word64, imm));
            return true;
        };
    }

    private static bool one(ulong uInstr, IA64Disassembler dasm)
    {
        dasm.ops.Add(Constant.UInt64(1));
        return true;
    }

    /// <summary>
    /// PC-relative branch target (25-bit signed immediate, shifted by 4)
    /// </summary>
    private static bool Target25(ulong uInstr, IA64Disassembler dasm)
    {
        var offset = Bitfield.ReadSignedFields(Bf((6, 20), (36, 1), (13, 4)), uInstr);
        var target = dasm.addr + (offset << 4);
        dasm.ops.Add(target);
        return true;
    }

    /// <summary>
    /// Qualifying predicate.
    /// </summary>
    private static bool qp(ulong uInstr, IA64Disassembler dasm)
    {
        dasm.qpReg = Registers.PredicateRegisters[(int)uInstr & 0x3F];
        return true;
    }

    /// <summary>
    /// Instruction format A1
    /// </summary>
    private static bool A1(ulong uInstr, IA64Disassembler dasm)
    {
        var src1 = Registers.GpRegisters[bf13_7.Read(uInstr)];
        var src2 = Registers.GpRegisters[bf20_7.Read(uInstr)];
        var dst = Registers.GpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(dst);
        dasm.ops.Add(src1);
        dasm.ops.Add(src2);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format A2
    /// </summary>
    private static bool A2(ulong uInstr, IA64Disassembler dasm)
    {
        var src1 = Registers.GpRegisters[bf13_7.Read(uInstr)];
        var src2 = Constant.UInt32(bf27_2.Read(uInstr) + 1);
        var src3 = Registers.GpRegisters[bf20_7.Read(uInstr)];
        var dst = Registers.GpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(dst);
        dasm.ops.Add(src1);
        dasm.ops.Add(src2);
        dasm.ops.Add(src3);
        return qp(uInstr, dasm);
    }


    /// <summary>
    /// Instruction format A3
    /// </summary>
    private static bool A3(ulong uInstr, IA64Disassembler dasm)
    {
        var src1 = Constant.Word64(Bitfield.ReadSignedFields(bf36_1_13_7, uInstr));
        var src2 = Registers.GpRegisters[bf20_7.Read(uInstr)];
        var dst = Registers.GpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(dst);
        dasm.ops.Add(src1);
        dasm.ops.Add(src2);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format A4.
    /// </summary>
    private static bool A4(ulong uInstr, IA64Disassembler dasm)
    {
        var imm = Constant.Word64(Bitfield.ReadSignedFields(bf36_1_27_6_13_7, uInstr));
        var src2 = Registers.GpRegisters[bf20_7.Read(uInstr)];
        var dst = Registers.GpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(dst);
        dasm.ops.Add(imm);
        dasm.ops.Add(src2);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format A6
    /// </summary>
    private static bool A6(ulong uInstr, IA64Disassembler dasm)
    {
        var p1 = Registers.PredicateRegisters[bf6_6.Read(uInstr)];
        var p2 = Registers.PredicateRegisters[bf27_6.Read(uInstr)];
        var r2 = Registers.GpRegisters[bf13_7.Read(uInstr)];
        var r3 = Registers.GpRegisters[bf20_7.Read(uInstr)];
        dasm.ops.Add(p1);
        dasm.ops.Add(p2);
        dasm.ops.Add(r2);
        dasm.ops.Add(r3);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format A7
    /// </summary>
    private static bool A7(ulong uInstr, IA64Disassembler dasm)
    {
        var p1 = Registers.PredicateRegisters[bf6_6.Read(uInstr)];
        var p2 = Registers.PredicateRegisters[bf27_6.Read(uInstr)];
        var r3 = Registers.GpRegisters[bf20_7.Read(uInstr)];
        dasm.ops.Add(p1);
        dasm.ops.Add(p2);
        dasm.ops.Add(Registers.GpRegisters[0]);
        dasm.ops.Add(r3);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format A8
    /// </summary>
    private static bool A8(ulong uInstr, IA64Disassembler dasm)
    {
        var p1 = Registers.PredicateRegisters[bf6_6.Read(uInstr)];
        var p2 = Registers.PredicateRegisters[bf27_6.Read(uInstr)];
        var r3 = Registers.GpRegisters[bf20_7.Read(uInstr)];
        var imm = Constant.Word64(Bitfield.ReadSignedFields(bf36_1_13_7, uInstr));
        dasm.ops.Add(p1);
        dasm.ops.Add(p2);
        dasm.ops.Add(imm);
        dasm.ops.Add(r3);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format A9.
    /// </summary>
    private static bool A9(ulong uInstr, IA64Disassembler dasm)
    {
        var r2 = Registers.GpRegisters[bf13_7.Read(uInstr)];
        var r3 = Registers.GpRegisters[bf20_7.Read(uInstr)];
        var r1 = Registers.GpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(r1);
        dasm.ops.Add(r2);
        dasm.ops.Add(r3);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format A10.
    /// </summary>
    private static bool A10(ulong uInstr, IA64Disassembler dasm)
    {
        var r2 = Registers.GpRegisters[bf13_7.Read(uInstr)];
        var ct = Constant.Int32((int) bf27_2.Read(uInstr));
        var r3 = Registers.GpRegisters[bf20_7.Read(uInstr)];
        var r1 = Registers.GpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(r1);
        dasm.ops.Add(r2);
        dasm.ops.Add(ct);
        dasm.ops.Add(r3);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format F4.
    /// </summary>
    private static bool F4(ulong uInstr, IA64Disassembler dasm)
    {
        var f2 = Registers.FpRegisters[bf13_7.Read(uInstr)];
        var f3 = Registers.FpRegisters[bf13_7.Read(uInstr)];
        var p1 = Registers.PredicateRegisters[bf6_6.Read(uInstr)];
        var p2 = Registers.PredicateRegisters[bf27_6.Read(uInstr)];
        dasm.ops.Add(p1);
        dasm.ops.Add(p2);
        dasm.ops.Add(f2);
        dasm.ops.Add(f3);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format F5.
    /// </summary>
    private static bool F5(ulong uInstr, IA64Disassembler dasm)
    {
        var f2 = Registers.FpRegisters[bf13_7.Read(uInstr)];
        var fclass = (uint)Bitfield.ReadFields(bf33_2_20_7, uInstr);
        var p1 = Registers.PredicateRegisters[bf6_6.Read(uInstr)];
        var p2 = Registers.PredicateRegisters[bf27_6.Read(uInstr)];
        dasm.ops.Add(p1);
        dasm.ops.Add(p2);
        dasm.ops.Add(f2);
        dasm.ops.Add(Constant.UInt32(fclass));
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format F6.
    /// </summary>
    private static bool F6(ulong uInstr, IA64Disassembler dasm)
    {
        var f2 = Registers.FpRegisters[bf13_7.Read(uInstr)];
        var f3 = Registers.FpRegisters[bf20_7.Read(uInstr)];
        var f1 = Registers.FpRegisters[bf6_7.Read(uInstr)];
        var p2 = Registers.PredicateRegisters[bf20_6.Read(uInstr)];
        dasm.ops.Add(f1);
        dasm.ops.Add(p2);
        dasm.ops.Add(f2);
        dasm.ops.Add(f3);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format F7.
    /// </summary>
    private static bool F7(ulong uInstr, IA64Disassembler dasm)
    {
        var f3 = Registers.FpRegisters[bf20_7.Read(uInstr)];
        var f1 = Registers.FpRegisters[bf6_7.Read(uInstr)];
        var p2 = Registers.PredicateRegisters[bf20_6.Read(uInstr)];
        dasm.ops.Add(f1);
        dasm.ops.Add(p2);
        dasm.ops.Add(f3);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format F8.
    /// </summary>
    private static bool F8(ulong uInstr, IA64Disassembler dasm)
    {
        var f2 = Registers.FpRegisters[bf13_7.Read(uInstr)];
        var f3 = Registers.FpRegisters[bf20_7.Read(uInstr)];
        var f1 = Registers.FpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(f1);
        dasm.ops.Add(f2);
        dasm.ops.Add(f3);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format F9.
    /// </summary>
    private static bool F9(ulong uInstr, IA64Disassembler dasm)
    {
        var src1 = Registers.FpRegisters[bf13_7.Read(uInstr)];
        var src2 = Registers.FpRegisters[bf20_7.Read(uInstr)];
        var dst = Registers.FpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(dst);
        dasm.ops.Add(src1);
        dasm.ops.Add(src2);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format F10.
    /// </summary>
    private static bool F10(ulong uInstr, IA64Disassembler dasm)
    {
        var f2 = Registers.FpRegisters[bf13_7.Read(uInstr)];
        var f1 = Registers.FpRegisters[bf6_7.Read(uInstr)];
        var completer = fpStatusField[bf34_2.Read(uInstr)];
        dasm.completer |= completer;
        dasm.ops.Add(f1);
        dasm.ops.Add(f2);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format F11.
    /// </summary>
    private static bool F11(ulong uInstr, IA64Disassembler dasm)
    {
        var f2 = Registers.FpRegisters[bf13_7.Read(uInstr)];
        var f1 = Registers.FpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(f1);
        dasm.ops.Add(f2);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format F15.
    /// </summary>
    private static bool F15(ulong uInstr, IA64Disassembler dasm)
    {
        var imm = Bitfield.ReadFields(bf36_1_6_20, uInstr);
        dasm.ops.Add(Constant.Word64(imm));
        return qp(uInstr, dasm);
    }

    private static readonly Completer[] whether = [
        Completer.Whether_Sptk,
        Completer.Whether_Spnt,
        Completer.Whether_Dptk,
        Completer.Whether_Dpnt
    ];

    private static readonly Completer[] branchPrefetch = [
        Completer.Prefetch_Few,
        Completer.Prefetch_Many,
    ];

    private static readonly Completer[] branchCacheDealloc = [
        Completer.BranchCache_None,
        Completer.BranchCache_Clr,
    ];

    /// <summary>
    /// Instruction format B1
    /// </summary>
    private static bool B1(ulong uInstr, IA64Disassembler dasm)
    {
        dasm.completer |= whether[bf33_2.Read(uInstr)];
        dasm.completer |= branchPrefetch[bf12_1.Read(uInstr)];
        dasm.completer |= branchCacheDealloc[bf35_1.Read(uInstr)];
        var target = dasm.addr + (Bitfield.ReadSignedFields(bf36_1_13_20, uInstr) << 4);
        dasm.ops.Add(target);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format B2
    /// </summary>
    private static bool B2(ulong uInstr, IA64Disassembler dasm)
    {
        dasm.completer |= whether[bf33_2.Read(uInstr)];
        dasm.completer |= branchPrefetch[bf12_1.Read(uInstr)];
        dasm.completer |= branchCacheDealloc[bf35_1.Read(uInstr)];
        var target = dasm.addr + (Bitfield.ReadSignedFields(bf36_1_13_20, uInstr) << 4);
        dasm.ops.Add(target);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format B3.
    /// </summary>
    private static bool B3(ulong uInstr, IA64Disassembler dasm)
    {
        dasm.completer |= whether[bf33_2.Read(uInstr)];
        dasm.completer |= branchPrefetch[bf12_1.Read(uInstr)];
        dasm.completer |= branchCacheDealloc[bf35_1.Read(uInstr)];
        var b = Registers.BranchRegisters[bf6_3.Read(uInstr)];
        var target = dasm.addr + (Bitfield.ReadSignedFields(bf36_1_13_20, uInstr) << 4);
        dasm.ops.Add(b);
        dasm.ops.Add(target);
        return qp(uInstr, dasm);
    }


    /// <summary>
    /// Instruction format B4.
    /// </summary>
    private static bool B4(ulong uInstr, IA64Disassembler dasm)
    {
        var b = Registers.BranchRegisters[bf13_3.Read(uInstr)];
        dasm.ops.Add(b);
        return qp(uInstr, dasm);
    }


    /// <summary>
    /// Instruction format B5.
    /// </summary>
    private static bool B5(ulong uInstr, IA64Disassembler dasm)
    {
        dasm.completer |= whether[bf33_2.Read(uInstr)];
        dasm.completer |= branchPrefetch[bf12_1.Read(uInstr)];
        dasm.completer |= branchCacheDealloc[bf35_1.Read(uInstr)];
        var b1 = Registers.BranchRegisters[bf6_3.Read(uInstr)];
        var b2 = Registers.BranchRegisters[bf13_3.Read(uInstr)];
        dasm.ops.Add(b1);
        dasm.ops.Add(b2);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format B6.
    /// </summary>
    private static bool B6(ulong uInstr, IA64Disassembler dasm)
    {
        dasm.completer |= importance[bf35_1.Read(uInstr)];
        dasm.completer |= whether[bf3_2.Read(uInstr)];
        var target = dasm.addr + (Bitfield.ReadSignedFields(bf33_2_6_7, uInstr) << 4);
        dasm.ops.Add(target);
        return true;
    }

    /// <summary>
    /// Instruction format B7.
    /// </summary>
    private static bool B7(ulong uInstr, IA64Disassembler dasm)
    {
        dasm.completer |= importance[bf33_2.Read(uInstr)];
        dasm.completer |= whether[bf33_2.Read(uInstr)];
        var b2 = Registers.BranchRegisters[bf13_3.Read(uInstr)];
        var tag13 = dasm.addr + (Bitfield.ReadSignedFields(bf33_2_6_7, uInstr) << 4);
        dasm.ops.Add(b2);
        dasm.ops.Add(tag13);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format B8.
    /// </summary>
    private static bool B8(ulong uInstr, IA64Disassembler dasm)
    {
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format B9.
    /// </summary>
    private static bool B9(ulong uInstr, IA64Disassembler dasm)
    {
        var imm = Constant.Word64(Bitfield.ReadFields(bf36_1_6_20, uInstr));
        dasm.ops.Add(imm);
        return qp(uInstr, dasm);
    }

    private static readonly Completer[] fpStatusField = [
        Completer.FpS0,
        Completer.FpS1,
        Completer.FpS2,
        Completer.FpS3,
    ];

    /// <summary>
    /// Instruction format F1.
    /// </summary>
    private static bool F1(ulong uInstr, IA64Disassembler dasm)
    {
        var sf = fpStatusField[bf34_2.Read(uInstr)];
        var f3 = Registers.FpRegisters[bf20_7.Read(uInstr)];
        var f4 = Registers.FpRegisters[bf27_7.Read(uInstr)];
        var f2 = Registers.FpRegisters[bf13_7.Read(uInstr)];
        var f1 = Registers.FpRegisters[bf6_7.Read(uInstr)];
        dasm.completer |= sf;
        dasm.ops.Add(f1);
        dasm.ops.Add(f3);
        dasm.ops.Add(f4);
        dasm.ops.Add(f2);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format F2.
    /// </summary>
    private static bool F2(ulong uInstr, IA64Disassembler dasm)
    {
        var f3 = Registers.FpRegisters[bf20_7.Read(uInstr)];
        var f4 = Registers.FpRegisters[bf27_7.Read(uInstr)];
        var f2 = Registers.FpRegisters[bf13_7.Read(uInstr)];
        var f1 = Registers.FpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(f1);
        dasm.ops.Add(f3);
        dasm.ops.Add(f4);
        dasm.ops.Add(f2);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format F3.
    /// </summary>
    private static bool F3(ulong uInstr, IA64Disassembler dasm)
    {
        var f3 = Registers.FpRegisters[bf20_7.Read(uInstr)];
        var f4 = Registers.FpRegisters[bf27_7.Read(uInstr)];
        var f2 = Registers.FpRegisters[bf13_7.Read(uInstr)];
        var dst = Registers.FpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(dst);
        dasm.ops.Add(f3);
        dasm.ops.Add(f4);
        dasm.ops.Add(f2);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format I2.
    /// </summary>
    private static bool I2(ulong uInstr, IA64Disassembler dasm)
    {
        var r2 = Registers.GpRegisters[bf13_7.Read(uInstr)];
        var r3 = Registers.GpRegisters[bf20_7.Read(uInstr)];
        var r1 = Registers.GpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(r1);
        dasm.ops.Add(r2);
        dasm.ops.Add(r3);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format I4.
    /// </summary>
    private static bool I4(ulong uInstr, IA64Disassembler dasm)
    {
        var r2 = Registers.GpRegisters[bf13_7.Read(uInstr)];
        var r1 = Registers.GpRegisters[bf6_7.Read(uInstr)];
        var mhtype = Constant.Byte((byte) bf20_8.Read(uInstr));
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format I5.
    /// </summary>
    private static bool I5(ulong uInstr, IA64Disassembler dasm)
    {
        var src1 = Registers.GpRegisters[bf20_7.Read(uInstr)];
        var src2 = Registers.GpRegisters[bf13_7.Read(uInstr)];
        var dst = Registers.GpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(dst);
        dasm.ops.Add(src1);
        dasm.ops.Add(src2);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format I6.
    /// </summary>
    private static bool I6(ulong uInstr, IA64Disassembler dasm)
    {
        var src1 = Registers.GpRegisters[bf20_7.Read(uInstr)];
        var count = Constant.Int32((int)bf14_5.Read(uInstr));
        var dst = Registers.GpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(dst);
        dasm.ops.Add(src1);
        dasm.ops.Add(count);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format I8.
    /// </summary>
    private static bool I8(ulong uInstr, IA64Disassembler dasm)
    {
        var r2 = Registers.GpRegisters[bf13_7.Read(uInstr)];
        var count = 31 - (int) bf20_5.Read(uInstr);
        var r1 = Registers.GpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(r1);
        dasm.ops.Add(r2);
        dasm.ops.Add(Constant.Int32(count));
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format I11.
    /// </summary>
    private static bool I11(ulong uInstr, IA64Disassembler dasm)
    {
        var r3 = Registers.GpRegisters[bf20_7.Read(uInstr)];
        var pos6 = Constant.Int32((int)bf14_6.Read(uInstr));
        var len6 = Constant.Int32((int)bf27_6.Read(uInstr)+1);
        var dst = Registers.GpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(dst);
        dasm.ops.Add(r3);
        dasm.ops.Add(pos6);
        dasm.ops.Add(len6);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format I12.
    /// </summary>
    private static bool I12(ulong uInstr, IA64Disassembler dasm)
    {
        var r2 = Registers.GpRegisters[bf13_7.Read(uInstr)];
        var pos = Constant.Int32(63 - (int) bf20_6.Read(uInstr));
        var len = Constant.Int32(1 +  (int) bf27_6.Read(uInstr));
        var dst = Registers.GpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(dst);
        dasm.ops.Add(r2);
        dasm.ops.Add(pos);
        dasm.ops.Add(len);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format I13.
    /// </summary>
    private static bool I13(ulong uInstr, IA64Disassembler dasm)
    {
        var imm = Constant.Word64(Bitfield.ReadSignedFields(bf36_1_13_7, uInstr));
        var pos = Constant.Int32(63 - (int) bf20_6.Read(uInstr));
        var len = Constant.Int32(1 + (int) bf27_6.Read(uInstr));
        var dst = Registers.GpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(dst);
        dasm.ops.Add(imm);
        dasm.ops.Add(pos);
        dasm.ops.Add(len);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format I14.
    /// </summary>
    private static bool I14(ulong uInstr, IA64Disassembler dasm)
    {
        var r2 = Registers.GpRegisters[bf13_7.Read(uInstr)];
        var r3 = Registers.GpRegisters[bf20_7.Read(uInstr)];
        var pos = 63 - (int) bf31_6.Read(uInstr);
        var len = (int) bf27_4.Read(uInstr);
        var r1 = Registers.GpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(r1);
        dasm.ops.Add(r2);
        dasm.ops.Add(r3);
        dasm.ops.Add(Constant.Int32(pos));
        dasm.ops.Add(Constant.Int32(len));
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format I7.
    /// </summary>
    private static bool I7(ulong uInstr, IA64Disassembler dasm)
    {
        var src1 = Registers.GpRegisters[bf13_7.Read(uInstr)];
        var src2 = Registers.GpRegisters[bf20_7.Read(uInstr)];
        var dst = Registers.GpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(dst);
        dasm.ops.Add(src1);
        dasm.ops.Add(src2);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format I10.
    /// </summary>
    private static bool I10(ulong uInstr, IA64Disassembler dasm)
    {
        var r2 = Registers.GpRegisters[bf13_7.Read(uInstr)];
        var r3 = Registers.GpRegisters[bf20_7.Read(uInstr)];
        var r1 = Registers.GpRegisters[bf6_7.Read(uInstr)];
        var count = Constant.Int32((int) bf27_6.Read(uInstr));
        dasm.ops.Add(r1);
        dasm.ops.Add(r2);
        dasm.ops.Add(r3);
        dasm.ops.Add(count);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format I15.
    /// </summary>
    private static bool I15(ulong uInstr, IA64Disassembler dasm)
    {
        var r2 = Registers.GpRegisters[bf13_7.Read(uInstr)];
        var r3 = Registers.GpRegisters[bf20_7.Read(uInstr)];
        var pos = Constant.Int32(63-(int)bf31_6.Read(uInstr));
        var len = Constant.Int32((int) bf27_4.Read(uInstr) + 1);
        var dst = Registers.GpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(dst);
        dasm.ops.Add(r2);
        dasm.ops.Add(r3);
        dasm.ops.Add(pos);
        dasm.ops.Add(len);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format I16.
    /// </summary>
    private static bool I16(ulong uInstr, IA64Disassembler dasm)
    {
        var p1 = Registers.PredicateRegisters[bf6_6.Read(uInstr)];
        var p2 = Registers.PredicateRegisters[bf27_6.Read(uInstr)];
        var src = Registers.GpRegisters[bf20_7.Read(uInstr)];
        var pos = Constant.Word32(bf14_6.Read(uInstr));
        dasm.ops.Add(p1);
        dasm.ops.Add(p2);
        dasm.ops.Add(src);
        dasm.ops.Add(pos);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format I17.
    /// </summary>
    private static bool I17(ulong uInstr, IA64Disassembler dasm)
    {
        var p1 = Registers.PredicateRegisters[bf6_6.Read(uInstr)];
        var p2 = Registers.PredicateRegisters[bf27_6.Read(uInstr)];
        var src = Registers.GpRegisters[bf20_7.Read(uInstr)];
        dasm.ops.Add(p1);
        dasm.ops.Add(p2);
        dasm.ops.Add(src);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format I20.
    /// </summary>
    private static bool I20(ulong uInstr, IA64Disassembler dasm)
    {
        var r2 = Registers.GpRegisters[bf13_7.Read(uInstr)];
        var offset = Bitfield.ReadSignedFields(bf36_1_20_13_6_7, uInstr) << 4;
        var target = dasm.addr + offset;
        dasm.ops.Add(r2);
        dasm.ops.Add(target);
        return qp(uInstr, dasm);
    }


    private static readonly Completer[] importance = [

        Completer.None,
        Completer.Important
    ];

    /// <summary>
    /// Instruction format I21.
    /// </summary>
    private static bool I21(ulong uInstr, IA64Disassembler dasm)
    {
        var src = Registers.GpRegisters[bf13_7.Read(uInstr)];
        var tag = bf24_9.ReadSigned(uInstr);
        var b = Registers.BranchRegisters[bf6_3.Read(uInstr)];
        var wh = whether[bf20_2.Read(uInstr)];
        var ih = importance[bf23_1.Read(uInstr)];
        dasm.completer |= wh;
        dasm.completer |= ih;
        dasm.ops.Add(b);
        dasm.ops.Add(src);
        dasm.ops.Add(dasm.addr + (tag << 4));
        return qp(uInstr, dasm);
    }
    
    /// <summary>
    /// Instruction format I22.
    /// </summary>
    private static bool I22(ulong uInstr, IA64Disassembler dasm)
    {
        var src = Registers.BranchRegisters[bf6_3.Read(uInstr)];
        var dst = Registers.GpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(dst);
        dasm.ops.Add(src);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format I23.
    /// </summary>
    private static bool I23(ulong uInstr, IA64Disassembler dasm)
    {
        var r2 = Registers.GpRegisters[bf13_7.Read(uInstr)];
        var mask = Constant.Word64(Bitfield.ReadSignedFields(bf36_1_24_8_6_7, uInstr) << 1);
        dasm.ops.Add(r2);
        dasm.ops.Add(mask);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format I24.
    /// </summary>
    private static bool I24(ulong uInstr, IA64Disassembler dasm)
    {
        var imm = Constant.Word64(Bitfield.ReadFields(bf36_1_6_27, uInstr));
        dasm.ops.Add(Registers.PR);
        dasm.ops.Add(imm);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format I26.
    /// </summary>
    private static bool I26(ulong uInstr, IA64Disassembler dasm)
    {
        var src = Registers.GpRegisters[bf13_7.Read(uInstr)];
        if (!Registers.ApplicationRegisters.TryGetValue(bf20_7.Read(uInstr), out var dst))
            return false;
        dasm.ops.Add(dst);
        dasm.ops.Add(src);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format I27
    /// </summary>
    private static bool I27(ulong uInstr, IA64Disassembler dasm)
    {
        var src = Constant.Word64(Bitfield.ReadSignedFields(bf36_1_13_7, uInstr));
        if (!Registers.ApplicationRegisters.TryGetValue(bf20_7.Read(uInstr), out var dst))
            return false;
        dasm.ops.Add(dst);
        dasm.ops.Add(src);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format I28
    /// </summary>
    private static bool I28(ulong uInstr, IA64Disassembler dasm)
    {
        if (!Registers.ApplicationRegisters.TryGetValue(bf20_7.Read(uInstr), out var src))
            return false;
        var dst = Registers.GpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(dst);
        dasm.ops.Add(src);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format I29
    /// </summary>
    private static bool I29(ulong uInstr, IA64Disassembler dasm)
    {
        var src = Registers.GpRegisters[bf20_7.Read(uInstr)];
        var dst = Registers.GpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(dst);
        dasm.ops.Add(src);
        return true;
    }


    private static readonly Completer[] ldHints = [
        Completer.None,
        Completer.Nt1,
        Completer.Invalid,
        Completer.Nta
    ];

    private static readonly Completer[] stHints = [
        Completer.None,
        Completer.Invalid,
        Completer.Invalid,
        Completer.Nta
    ];

    /// <summary>
    /// Instruction format M1
    /// </summary>
    private static WideMutator M1(PrimitiveType dt)
    {
        return (u, d) =>
        {
            var completer = ldHints[bf28_2.Read(u)];
            if (completer == Completer.Invalid)
                return false;
            var src = Registers.GpRegisters[bf20_7.Read(u)];
            var dst = Registers.GpRegisters[bf6_7.Read(u)];
            d.completer = completer;
            d.ops.Add(dst);
            d.ops.Add(new MemoryOperand(src, dt));
            return qp(u, d);
        };
    }
    private static readonly WideMutator M1_1 = M1(PrimitiveType.Byte);
    private static readonly WideMutator M1_2 = M1(PrimitiveType.Word16);
    private static readonly WideMutator M1_4 = M1(PrimitiveType.Word32);
    private static readonly WideMutator M1_8 = M1(PrimitiveType.Word64);

    /// <summary>
    /// Instruction format M2.
    /// </summary>
    private static bool M2(ulong uInstr, IA64Disassembler dasm)
    {
        var completer = ldHints[bf28_2.Read(uInstr)];
        if (completer == Completer.Invalid)
            return false;
        var r3 = Registers.GpRegisters[bf20_7.Read(uInstr)];
        var r2 = Registers.GpRegisters[bf13_7.Read(uInstr)];
        var r1 = Registers.GpRegisters[bf6_7.Read(uInstr)];
        dasm.completer = completer;
        dasm.ops.Add(r1);
        dasm.ops.Add(new MemoryOperand(r3, PrimitiveType.Byte));
        dasm.ops.Add(r2);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format M3
    /// </summary>
    private static WideMutator M3(PrimitiveType dt)
    {
        return (u, d) =>
        {
            var completer = ldHints[bf28_2.Read(u)];
            if (completer == Completer.Invalid)
                return false;
            var src = Registers.GpRegisters[bf20_7.Read(u)];
            var offset = Bitfield.ReadSignedFields(bf36_1_27_1_13_7, u);
            var dst = Registers.GpRegisters[bf6_7.Read(u)];
            d.completer = completer;
            d.ops.Add(dst);
            d.ops.Add(new MemoryOperand(src, dt));
            d.ops.Add(Constant.Int64(offset));
            return qp(u, d);
        };
    }
    private static readonly WideMutator M3_1 = M3(PrimitiveType.Byte);
    private static readonly WideMutator M3_2 = M3(PrimitiveType.Word16);
    private static readonly WideMutator M3_4 = M3(PrimitiveType.Word32);
    private static readonly WideMutator M3_8 = M3(PrimitiveType.Word64);


    /// <summary>
    /// Instruction format M4
    /// </summary>
    private static WideMutator M4(PrimitiveType dt)
    {
        return (u, d) =>
        {
            var completer = stHints[bf28_2.Read(u)];
            if (completer == Completer.Invalid)
                return false;
            var src = Registers.GpRegisters[bf13_7.Read(u)];
            var dst = Registers.GpRegisters[bf20_7.Read(u)];
            d.completer = completer;
            d.ops.Add(new MemoryOperand(src, dt));
            d.ops.Add(dst);
            return qp(u, d);
        };
    }
    private static readonly WideMutator M4_1 = M4(PrimitiveType.Byte);
    private static readonly WideMutator M4_2 = M4(PrimitiveType.Word16);
    private static readonly WideMutator M4_4 = M4(PrimitiveType.Word32);
    private static readonly WideMutator M4_8 = M4(PrimitiveType.Word64);


    /// <summary>
    /// Instruction format M5.
    /// </summary>
    private static WideMutator M5(PrimitiveType dt)
    {
        return (u, d) =>
        {
            var completer = stHints[bf28_2.Read(u)];
            if (completer == Completer.Invalid)
                return false;
            var dst = Registers.GpRegisters[bf20_7.Read(u)];
            var offset = Bitfield.ReadSignedFields(bf36_1_27_1_6_7, u);
            var src = Registers.GpRegisters[bf6_7.Read(u)];
            d.completer = completer;
            d.ops.Add(new MemoryOperand(dst, dt));
            d.ops.Add(src);
            d.ops.Add(Constant.Int64(offset));
            return qp(u, d);
        };
    }
    private static readonly WideMutator M5_1 = M5(PrimitiveType.Byte);
    private static readonly WideMutator M5_2 = M5(PrimitiveType.Word16);
    private static readonly WideMutator M5_4 = M5(PrimitiveType.Word32);
    private static readonly WideMutator M5_8 = M5(PrimitiveType.Word64);

    /// <summary>
    /// Instruction format M6.
    /// </summary>
    private static bool M6(ulong uInstr, IA64Disassembler dasm)
    {
        var r3 = Registers.GpRegisters[bf20_7.Read(uInstr)];
        var f1 = Registers.FpRegisters[bf6_7.Read(uInstr)];
        var completer = ldHints[bf28_2.Read(uInstr)];
        if (completer == Completer.Invalid)
            return false;
        dasm.completer |= completer;
        dasm.ops.Add(f1);
        dasm.ops.Add(new MemoryOperand(r3, PrimitiveType.Byte));
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format M7.
    /// </summary>
    private static bool M7(ulong uInstr, IA64Disassembler dasm)
    {
        var r3 = Registers.GpRegisters[bf20_7.Read(uInstr)];
        var r2 = Registers.GpRegisters[bf13_7.Read(uInstr)];
        var f1 = Registers.FpRegisters[bf6_7.Read(uInstr)];
        var completer = ldHints[bf28_2.Read(uInstr)];
        if (completer == Completer.Invalid)
            return false;
        dasm.completer |= completer;
        dasm.ops.Add(f1);
        dasm.ops.Add(new MemoryOperand(r3, PrimitiveType.Byte));
        dasm.ops.Add(r2);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format M8.
    /// </summary>
    private static bool M8(ulong uInstr, IA64Disassembler dasm)
    {
        var r3 = Registers.GpRegisters[bf20_7.Read(uInstr)];
        var imm9 = Constant.Int64(Bitfield.ReadSignedFields(bf36_1_27_1_13_7, uInstr));
        var f1 = Registers.FpRegisters[bf6_7.Read(uInstr)];
        var completer = ldHints[bf28_2.Read(uInstr)];
        if (completer == Completer.Invalid)
            return false;
        dasm.completer |= completer;
        dasm.ops.Add(f1);
        dasm.ops.Add(new MemoryOperand(r3, PrimitiveType.Byte));
        dasm.ops.Add(imm9);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format M9.
    /// </summary>
    private static bool M9(ulong uInstr, IA64Disassembler dasm)
    {
        var f2 = Registers.FpRegisters[bf13_7.Read(uInstr)];
        var r3 = Registers.GpRegisters[bf20_7.Read(uInstr)];
        var completer = stHints[bf28_2.Read(uInstr)];
        if (completer == Completer.Invalid)
            return false;
        dasm.completer |= completer;
        dasm.ops.Add(new MemoryOperand(r3, PrimitiveType.Byte));
        dasm.ops.Add(f2);
        return qp(uInstr, dasm);
    }


    /// <summary>
    /// Instruction format M10.
    /// </summary>
    private static bool M10(ulong uInstr, IA64Disassembler dasm)
    {
        var f2 = Registers.FpRegisters[bf13_7.Read(uInstr)];
        var r3 = Registers.GpRegisters[bf20_7.Read(uInstr)];
        var imm9 = Constant.Int64(Bitfield.ReadSignedFields(bf36_1_27_1_6_7, uInstr));
        var completer = stHints[bf28_2.Read(uInstr)];
        if (completer == Completer.Invalid)
            return false;
        dasm.completer |= completer;
        dasm.ops.Add(new MemoryOperand(r3, PrimitiveType.Byte));
        dasm.ops.Add(f2);
        dasm.ops.Add(imm9);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format M11.
    /// </summary>
    private static bool M11(ulong uInstr, IA64Disassembler dasm)
    {
        var r3 = Registers.GpRegisters[bf20_7.Read(uInstr)];
        var f1 = Registers.FpRegisters[bf6_7.Read(uInstr)];
        var f2 = Registers.FpRegisters[bf13_7.Read(uInstr)];
        dasm.ops.Add(f1);
        dasm.ops.Add(f2);
        dasm.ops.Add(new MemoryOperand(r3, PrimitiveType.Byte));
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format M12.
    /// </summary>
    private static bool M12(ulong uInstr, IA64Disassembler dasm)
    {
        var r3 = Registers.GpRegisters[bf20_7.Read(uInstr)];
        var f1 = Registers.FpRegisters[bf6_7.Read(uInstr)];
        var f2 = Registers.FpRegisters[bf13_7.Read(uInstr)];
        var completer = stHints[bf28_2.Read(uInstr)];
        if (completer == Completer.Invalid)
            return false;
        dasm.completer |= completer;
        dasm.ops.Add(f1);
        dasm.ops.Add(f2);
        dasm.ops.Add(new MemoryOperand(r3, PrimitiveType.Byte));
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format M14.
    /// </summary>
    private static bool M14(ulong uInstr, IA64Disassembler dasm)
    {
        var r3 = Registers.GpRegisters[bf20_7.Read(uInstr)];
        var r2 = Registers.GpRegisters[bf13_7.Read(uInstr)];
        var completer = ldHints[bf28_2.Read(uInstr)];
        if (completer == Completer.Invalid)
            return false;
        dasm.completer |= completer;
        dasm.ops.Add(new MemoryOperand(r3, PrimitiveType.Byte));
        dasm.ops.Add(r2);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format M15.
    /// </summary>
    private static bool M15(ulong uInstr, IA64Disassembler dasm)
    {
        var r3 = Registers.GpRegisters[bf20_7.Read(uInstr)];
        var imm9 = Constant.Int64(Bitfield.ReadSignedFields(bf36_1_27_1_13_7, uInstr));
        var completer = ldHints[bf28_2.Read(uInstr)];
        if (completer == Completer.Invalid)
            return false;
        dasm.completer |= completer;
        dasm.ops.Add(new MemoryOperand(r3, PrimitiveType.Byte));
        dasm.ops.Add(imm9);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format M16.
    /// </summary>
    private static bool M16(ulong uInstr, IA64Disassembler dasm)
    {
        var r2 = Registers.GpRegisters[bf13_7.Read(uInstr)];
        var r3 = Registers.GpRegisters[bf20_7.Read(uInstr)];
        var r1 = Registers.GpRegisters[bf6_7.Read(uInstr)];
        var completer = ldHints[bf28_2.Read(uInstr)];
        if (completer == Completer.Invalid)
            return false;
        dasm.completer |= completer;
        dasm.ops.Add(r1);
        dasm.ops.Add(new MemoryOperand(r3, PrimitiveType.Byte));
        dasm.ops.Add(r2);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format M17.
    /// </summary>
    private static bool M17(ulong uInstr, IA64Disassembler dasm)
    {
        var r3 = Registers.GpRegisters[bf20_7.Read(uInstr)];
        var r1 = Registers.GpRegisters[bf6_7.Read(uInstr)];
        var i2b = (int) bf13_2.Read(uInstr);
        var s = (int) bf15_1.Read(uInstr);
        var inc3 =
            (((s!= 0) ? -1 : 1) * ((i2b == 3) ? 1 : 1 << (4 - i2b ))) & 0x3F;
        var completer = ldHints[bf28_2.Read(uInstr)];
        if (completer == Completer.Invalid)
            return false;
        dasm.completer |= completer;
        dasm.ops.Add(r1);
        dasm.ops.Add(new MemoryOperand(r3, PrimitiveType.Byte));
        dasm.ops.Add(Constant.Int32(inc3));
        return qp(uInstr, dasm);
    }


    /// <summary>
    /// Instruction format M18.
    /// </summary>
    private static bool M18(ulong uInstr, IA64Disassembler dasm)
    {
        var r2 = Registers.GpRegisters[bf13_7.Read(uInstr)];
        var f1 = Registers.FpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(f1);
        dasm.ops.Add(r2);
        return qp(uInstr, dasm);
    }


    /// <summary>
    /// Instruction format M19.
    /// </summary>
    private static bool M19(ulong uInstr, IA64Disassembler dasm)
    {
        var f2 = Registers.FpRegisters[bf13_7.Read(uInstr)];
        var r1 = Registers.GpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(r1);
        dasm.ops.Add(f2);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format M20.
    /// </summary>
    private static bool M20(ulong uInstr, IA64Disassembler dasm)
    {
        var r2 = Registers.GpRegisters[bf13_7.Read(uInstr)];
        var target = dasm.addr + (Bitfield.ReadSignedFields(bf36_1_20_13_6_7, uInstr) << 4);
        dasm.ops.Add(r2);
        dasm.ops.Add(target);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format M21.
    /// </summary>
    private static bool M21(ulong uInstr, IA64Disassembler dasm)
    {
        var f2 = Registers.FpRegisters[bf13_7.Read(uInstr)];
        var target = dasm.addr + (Bitfield.ReadSignedFields(bf36_1_20_13_6_7, uInstr) << 4);
        dasm.ops.Add(f2);
        dasm.ops.Add(target);
        return qp(uInstr, dasm);

    }

    /// <summary>
    /// Instruction format M22.
    /// </summary>
    private static bool M22(ulong uInstr, IA64Disassembler dasm)
    {
        var target = dasm.addr + (Bitfield.ReadSignedFields(bf36_1_13_20, uInstr) << 4);
        var dst = Registers.GpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(dst);
        dasm.ops.Add(target);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format M23.
    /// </summary>
    private static bool M23(ulong uInstr, IA64Disassembler dasm)
    {
        var target = dasm.addr + (Bitfield.ReadSignedFields(bf36_1_13_20, uInstr) << 4);
        var dst = Registers.FpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(dst);
        dasm.ops.Add(target);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format M24.
    /// </summary>
    private static bool M24(ulong uInstr, IA64Disassembler dasm)
    {
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format M25.
    /// </summary>
    private static bool M25(ulong uInstr, IA64Disassembler dasm)
    {
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format M26.
    /// </summary>
    private static bool M26(ulong uInstr, IA64Disassembler dasm)
    {
        var r1 = Registers.GpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(r1);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format M27.
    /// </summary>
    private static bool M27(ulong uInstr, IA64Disassembler dasm)
    {
        var f1 = Registers.FpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(f1);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format M29.
    /// </summary>
    private static bool M29(ulong uInstr, IA64Disassembler dasm)
    {
        if (!Registers.ApplicationRegisters.TryGetValue(bf20_7.Read(uInstr), out var dst))
            return false;

        var r2 = Registers.GpRegisters[bf13_7.Read(uInstr)];
        dasm.ops.Add(dst);
        dasm.ops.Add(r2);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format M30.
    /// </summary>
    private static bool M30(ulong uInstr, IA64Disassembler dasm)
    {
        if (!Registers.ApplicationRegisters.TryGetValue(bf20_7.Read(uInstr), out var dst))
            return false;

        var imm = Constant.Word64(Bitfield.ReadSignedFields(bf36_1_13_7, uInstr));
        dasm.ops.Add(dst);
        dasm.ops.Add(imm);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format M31.
    /// </summary>
    private static bool M31(ulong uInstr, IA64Disassembler dasm)
    {
        if (!Registers.ApplicationRegisters.TryGetValue(bf20_7.Read(uInstr), out var ar3))
            return false;
        var dst = Registers.GpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(dst);
        dasm.ops.Add(ar3);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format M38.
    /// </summary>
    private static bool M38(ulong uInstr, IA64Disassembler dasm)
    {
        var r3 = Registers.GpRegisters[bf20_7.Read(uInstr)];
        var r2 = Registers.GpRegisters[bf13_7.Read(uInstr)];
        var r1 = Registers.GpRegisters[bf6_7.Read(uInstr)];
        dasm.ops.Add(r1);
        dasm.ops.Add(r3);
        dasm.ops.Add(r2);
        return qp(uInstr, dasm);
    }

    /// <summary>
    /// Instruction format M42.
    /// </summary>
    private static bool M42(ulong uInstr, IA64Disassembler dasm)
    {
        //$TODO
        return false;
    }

    /// <summary>
    /// Instruction format M44.
    /// </summary>
    private static bool M44(ulong uInstr, IA64Disassembler dasm)
    {
        var imm24 = Constant.Word64(Bitfield.ReadFields(bf36_1_31_2_6_21, uInstr));
        dasm.ops.Add(imm24);
        return qp(uInstr, dasm);
    }


    /// <summary>
    /// Instruction format X1.
    /// </summary>
    private static bool X1(ulong uInstr, IA64Disassembler dasm)
    {
        var loPart = Bitfield.ReadFields(bf36_1_6_20, uInstr);
        var imm62 = dasm.imm41 << 21 | loPart;
        dasm.ops.Add(Constant.Word64(imm62));
        return true;
    }

    #endregion

    #region Decoders 

    public override IA64Bundle NotYetImplemented(string message)
    {
        var testGenSvc = arch.Services.GetService<ITestGenerationService>();
        testGenSvc?.ReportMissingDecoder("Ia64Dis", this.addr, rdr, message);
        var nyi = new IA64Instruction
        {
            InstructionClass = InstrClass.Invalid,
            Mnemonic = Mnemonic.Nyi,
            Operands = []
        };
        return MakeBundle(nyi, nyi, nyi);
    }

    private struct TemplateDecoders
    {
        public readonly WideDecoder Slot0;
        public readonly WideDecoder Slot1;
        public readonly WideDecoder Slot2;
        public readonly int StopMask;

        public TemplateDecoders(
            WideDecoder slot0Decoder,
            WideDecoder slot1Decoder,
            WideDecoder slot2Decoder,
            int stopMask)
        {
            this.Slot0 = slot0Decoder;
            this.Slot1 = slot1Decoder;
            this.Slot2 = slot2Decoder;
            this.StopMask = stopMask;
        }
    }

    private class UnitDecoder : WideDecoder
    {
        private readonly char unit;
        private readonly WideDecoder innerDecoder;

        public UnitDecoder(char unit, WideDecoder innerDecoder)
        {
            this.unit = unit;
            this.innerDecoder = innerDecoder;
        }

        public override IA64Instruction Decode(ulong wInstr, IA64Disassembler dasm)
        {
            var instr = innerDecoder.Decode(wInstr, dasm);
            instr.Unit = unit;
            return instr;
        }
    }

    protected class InstrDecoder : WideDecoder
    {
        private readonly InstrClass iclass;
        private readonly Mnemonic mnemonic;
        private readonly WideMutator<IA64Disassembler>[] mutators;

        public InstrDecoder(InstrClass iclass, Mnemonic mnemonic, params WideMutator[] mutators)
        {
            this.iclass = iclass;
            this.mnemonic = mnemonic;
            this.mutators = mutators;
        }

        public override IA64Instruction Decode(ulong ulInstr, IA64Disassembler dasm)
        {
            foreach (var m in mutators)
            {
                if (!m(ulInstr, dasm))
                    return dasm.CreateInvalidInstruction().Instructions[0];
            }
            return new IA64Instruction
            {
                InstructionClass = iclass,
                Mnemonic = mnemonic,
                Completer = dasm.completer,
                Operands = dasm.ops.ToArray(),
                QualifyingPredicate = dasm.qpReg,
            };
        }
    }

    protected class MaskDecoder : WideDecoder
    {
        private readonly Bitfield bitfield;
        private readonly WideDecoder[] decoders;
        private readonly string tag;

        public MaskDecoder(Bitfield bitfield, string tag, params WideDecoder[] decoders)
        {
            this.bitfield = bitfield;
            Debug.Assert(decoders.Length == (1 << bitfield.Length), $"Inconsistent number of decoders {decoders.Length} (bitPos {bitfield.Position} bitSize{bitfield.Length:X})");
            this.decoders = decoders;
            this.tag = tag;
        }

        public override IA64Instruction Decode(ulong ulInstr, IA64Disassembler dasm)
        {
            TraceDecoder(ulInstr);
            uint op = bitfield.Read(ulInstr);
            return decoders[op].Decode(ulInstr, dasm);
        }

        [Conditional("DEBUG")]
        public void TraceDecoder(ulong wInstr)
        {
            var shMask = (ulong) this.bitfield.Mask << this.bitfield.Position;
            DumpMaskedInstruction(64, wInstr, shMask, tag);
        }

        public override string ToString()
        {
            return $"{{Mask {bitfield}}}";
        }
    }

    protected class BitfieldDecoder : WideDecoder
    {
        private readonly Bitfield[] bitfields;
        private readonly WideDecoder[] decoders;
        private readonly string tag;
        public BitfieldDecoder(Bitfield[] bitfields, string tag, params WideDecoder[] decoders)
        {
            this.bitfields = bitfields;
            var totalBits = 0;
            foreach (var bf in bitfields)
            {
                totalBits += bf.Length;
            }
            Debug.Assert(decoders.Length == (1 << totalBits), $"Inconsistent number of decoders {decoders.Length} (bitSize{totalBits:X})");
            this.decoders = decoders;
            this.tag = tag;
        }

        public override IA64Instruction Decode(ulong ulInstr, IA64Disassembler dasm)
        {
            TraceDecoder(ulInstr);
            ulong op = Bitfield.ReadFields(bitfields, ulInstr);
            return decoders[op].Decode(ulInstr, dasm);
        }

        [Conditional("DEBUG")]
        public void TraceDecoder(ulong wInstr)
        {
            ulong shMask = 0;
            foreach (var bf in bitfields)
            {
                shMask |= (ulong) bf.Mask << bf.Position;
            }
            DumpMaskedInstruction(64, wInstr, shMask, tag);
        }
        public override string ToString()
        {
            return $"{{Bitfield Mask}}";
        }
    }

    private class PrReservedDecoder : InstrDecoder
    {
        public PrReservedDecoder() :
            base(InstrClass.Linear, Mnemonic.nop)
        {
        }

        public override IA64Instruction Decode(ulong ulInstr, IA64Disassembler dasm)
        {
            var pr = ulInstr & 0x3F;
            if (pr == 0)
                return base.Decode(ulInstr, dasm);
            IA64Disassembler.qp(ulInstr, dasm);
            return base.Decode(ulInstr, dasm);
        }
    }


    public class NyiDecoder : WideDecoder
    {
        private readonly string message;

        public NyiDecoder(string message)
        {
            this.message = message;
        }

        public override IA64Instruction Decode(ulong uInstr, IA64Disassembler dasm)
        {
            dasm.NotYetImplemented(message);
            return new IA64Instruction
            {
                InstructionClass = InstrClass.Invalid,
                Mnemonic = Mnemonic.Nyi,
                Address = dasm.addr,
                Length = 6,
            };
        }
    }

    protected static InstrDecoder Instr(Mnemonic mnemonic, params WideMutator<IA64Disassembler>[] mutators)
    {
        return new InstrDecoder(InstrClass.Linear, mnemonic, mutators);
    }

    protected static InstrDecoder Instr(Mnemonic mnemonic, InstrClass iclass, params WideMutator[] mutators)
    {
        return new InstrDecoder(iclass, mnemonic, mutators);
    }

    private static NyiDecoder Nyi(string message)
    {
        return new NyiDecoder(message);
    }

    protected static MaskDecoder Mask(int bitPos, int bitLength, string tag, params WideDecoder[] decoders)
    {
        return new MaskDecoder(new Bitfield(bitPos, bitLength), tag, decoders);
    }

    protected static BitfieldDecoder Mask(Bitfield[] bitfields, string tag, params WideDecoder[] decoders)
    {
        return new BitfieldDecoder(bitfields, tag, decoders);
    }


    private static MaskDecoder Sparse(
        int bitPosition, int bits, string tag,
        WideDecoder defaultDecoder,
        params (uint, WideDecoder)[] sparseDecoders)
    {
        var decoders = BuildSparseDecoderArray(bits, defaultDecoder, sparseDecoders);
        return new MaskDecoder(new Bitfield(bitPosition, bits), tag, decoders);
    }

    private static WideDecoder[] BuildSparseDecoderArray(int bits, WideDecoder defaultDecoder, (uint, WideDecoder)[] sparseDecoders)
    {
        var decoders = new WideDecoder[1 << bits];
        foreach (var (code, decoder) in sparseDecoders)
        {
            Debug.Assert(0 <= code && code < decoders.Length);
            Debug.Assert(decoders[code] is null, $"Decoder {code:X} has already a value!");
            decoders[code] = decoder;
        }
        for (int i = 0; i < decoders.Length; ++i)
        {
            if (decoders[i] is null)
                decoders[i] = defaultDecoder;
        }
        return decoders;
    }

    #endregion

    static IA64Disassembler()
    {
        invalid = Instr(Mnemonic.Invalid, InstrClass.Invalid);
        reserved = Instr(Mnemonic.Invalid, InstrClass.Invalid);
        nop = Instr(Mnemonic.nop, InstrClass.Invalid);
        prReserved = new PrReservedDecoder();

        MaskDecoder compare = MakeCompareDecoders();

        MaskDecoder aluMmAlu = MakeAluMmDecoders();
        var addImm22 = Instr(Mnemonic.addl, r1, IsImm22, r3_2, qp);

        Idecoders = MakeIdecoders(compare, aluMmAlu, addImm22);
        Mdecoders = MakeMdecoders(compare, aluMmAlu, addImm22);
        Fdecoders = MakeFdecoders();
        Bdecoders = MakeBdecoders();
        Ldecoders = MakeLdecoders();
        Xdecoders = MakeXdecoders();
        templates = BuildTemplateDecoders();
    }

    private static MaskDecoder MakeAluMmDecoders()
    {
        var shladd = Instr(Mnemonic.shladd, A2);
        var shladdp4 = Instr(Mnemonic.shladdp4, A2);
        var alu4_2ext = Sparse(27, 6, " Integer ALU 4-bit+2-bit Opcode Extensions", invalid,
            (0x00, Instr(Mnemonic.add, A1)),
            (0x01, Instr(Mnemonic.add, A1, one)),
            (0x04, Instr(Mnemonic.sub, A1, one)),
            (0x05, Instr(Mnemonic.sub, A1)),
            (0x08, Instr(Mnemonic.addp4, A1)),
            (0x0C, Instr(Mnemonic.and, A1)),
            (0x0D, Instr(Mnemonic.andcm, A1)),
            (0x0E, Instr(Mnemonic.or, A1)),
            (0x0F, Instr(Mnemonic.xor, A1)),
            (0x10, shladd),
            (0x11, shladd),
            (0x12, shladd),
            (0x13, shladd),
            (0x18, shladdp4),
            (0x19, shladdp4),
            (0x1A, shladdp4),
            (0x1B, shladdp4),
            (0x25, Instr(Mnemonic.sub, A3)),
            (0x2C, Instr(Mnemonic.and, A3)),
            (0x2D, Instr(Mnemonic.andcm, A3)),
            (0x2E, Instr(Mnemonic.or, A3)),
            (0x2F, Instr(Mnemonic.xor, A3))
            );

        var multimediaAluSize1 = Sparse(27, 6, "  multimediaAluSize1", prReserved,
                (0x00, Instr(Mnemonic.padd1, A9)),
                (0x01, Instr(Mnemonic.padd1_sss, A9)),
                (0x02, Instr(Mnemonic.padd1_uuu, A9)),
                (0x03, Instr(Mnemonic.padd1_uus, A9)),

                (0x04, Instr(Mnemonic.psub1, A9)),
                (0x05, Instr(Mnemonic.psub1_sss, A9)),
                (0x06, Instr(Mnemonic.psub1_uuu, A9)),
                (0x07, Instr(Mnemonic.psub1_uus, A9)),

                (0x0A, Instr(Mnemonic.pavg1, A9)),
                (0x0B, Instr(Mnemonic.pavg1_raz, A9)),
                (0x0E, Instr(Mnemonic.pavgsub1, A9)),

                (0x24, Instr(Mnemonic.pcmp2_eq, A9)),
                (0x25, Instr(Mnemonic.pcmp2_gt, A9)));

        var multimediaAluSize2 = Sparse(27, 6, "  multimediaAluSize2", prReserved,
                (0x00, Instr(Mnemonic.padd2, A9)),
                (0x01, Instr(Mnemonic.padd2_sss, A9)),
                (0x02, Instr(Mnemonic.padd2_uuu, A9)),
                (0x03, Instr(Mnemonic.padd2_uus, A9)),

                (0x04, Instr(Mnemonic.psub2, A9)),
                (0x05, Instr(Mnemonic.psub2_sss, A9)),
                (0x06, Instr(Mnemonic.psub2_uuu, A9)),
                (0x07, Instr(Mnemonic.psub2_uus, A9)),

                (0x0A, Instr(Mnemonic.pavg2, A9)),
                (0x0B, Instr(Mnemonic.pavg2_raz, A9)),
                (0x0E, Instr(Mnemonic.pavgsub2, A9)),

                (0x10, Instr(Mnemonic.pshladd2, A10)),
                (0x11, Instr(Mnemonic.pshladd2, A10)),
                (0x12, Instr(Mnemonic.pshladd2, A10)),
                (0x13, Instr(Mnemonic.pshladd2, A10)),

                (0x18, Instr(Mnemonic.pshradd2, A10)),
                (0x19, Instr(Mnemonic.pshradd2, A10)),
                (0x1A, Instr(Mnemonic.pshradd2, A10)),
                (0x1B, Instr(Mnemonic.pshradd2, A10)),

                (0x24, Instr(Mnemonic.pcmp2_eq, A9)),
                (0x25, Instr(Mnemonic.pcmp2_gt, A9)));

        var multimediaAluSize4 = Sparse(27, 6, "multimediaAluSize4", prReserved,
                (0x00, Instr(Mnemonic.padd4, A9)),
                (0x04, Instr(Mnemonic.psub4, A9)),
                (0x24, Instr(Mnemonic.pcmp4_eq, A9)),
                (0x25, Instr(Mnemonic.pcmp4_gt, A9)));

        var multimediaAlu1_2ext = Mask(Bf((36, 1), (33, 1)), "  Multimedia ALU 1-bit+2-bit Ext",
            multimediaAluSize1,
            multimediaAluSize2,
            multimediaAluSize4,
            invalid);

        var aluMmAlu = Mask(33, 1, "  ALU/mm ALU",
            Mask(34, 2, "  0",
                alu4_2ext,
                multimediaAlu1_2ext,
                Instr(Mnemonic.adds, A4),
                Instr(Mnemonic.addp4, A4)),
            Mask(34, 2, "  1",
                invalid,
                multimediaAlu1_2ext,
                invalid,
                invalid));
        return aluMmAlu;
    }

    private static MaskDecoder MakeCompareDecoders()
    {
        var bfSelector01 = Bf((34, 1), (36, 1), (33, 1), (12, 1));
        var compare01 = Sparse(37, 4, "  compare0-1", invalid,
            (0xC, Mask(bfSelector01, "compare C",
                Instr(Mnemonic.cmp_lt, A6),
                Instr(Mnemonic.cmp_lt_unc, A6),
                Instr(Mnemonic.cmp_eq_and, A6),
                Instr(Mnemonic.cmp_ne_and, A6),

                Instr(Mnemonic.cmp_gt, A7),
                Instr(Mnemonic.cmp_le_and, A7),
                Instr(Mnemonic.cmp_ge_and, A7),
                Instr(Mnemonic.cmp_lt_and, A7),

                Instr(Mnemonic.cmp4_lt, A6),
                Instr(Mnemonic.cmp4_lt_unc, A6),
                Instr(Mnemonic.cmp4_eq_and, A6),
                Instr(Mnemonic.cmp4_ne_and, A6),

                Instr(Mnemonic.cmp4_gt_and, A7),
                Instr(Mnemonic.cmp4_le_and, A7),
                Instr(Mnemonic.cmp4_ge_and, A7),
                Instr(Mnemonic.cmp4_lt_and, A7)
                )),
            (0xD, Mask(bfSelector01, "compare D",
                Instr(Mnemonic.cmp_ltu, A6),
                Instr(Mnemonic.cmp_ltu_unc, A6),
                Instr(Mnemonic.cmp_eq_or, A6),
                Instr(Mnemonic.cmp_ne_or, A6),

                Instr(Mnemonic.cmp_gt_or, A7),
                Instr(Mnemonic.cmp_le_or, A7),
                Instr(Mnemonic.cmp_ge_or, A7),
                Instr(Mnemonic.cmp_lt_or, A7),

                Instr(Mnemonic.cmp4_ltu, A6),
                Instr(Mnemonic.cmp4_ltu_unc, A6),
                Instr(Mnemonic.cmp4_eq_or, A6),
                Instr(Mnemonic.cmp4_ne_or, A6),

                Instr(Mnemonic.cmp4_gt, A7),
                Instr(Mnemonic.cmp4_le_or, A7),
                Instr(Mnemonic.cmp4_ge_or, A7),
                Instr(Mnemonic.cmp4_lt_or, A7)
                )),
            (0xE, Mask(bfSelector01, "compare E",
                Instr(Mnemonic.cmp_eq, A6),
                Instr(Mnemonic.cmp_eq_unc, A6),
                Instr(Mnemonic.cmp_eq_or_andcm, A6),
                Instr(Mnemonic.cmp_ne_or_andcm, A6),

                Instr(Mnemonic.cmp_gt_or_andcm, A7),
                Instr(Mnemonic.cmp_le_or_andcm, A7),
                Instr(Mnemonic.cmp_ge_or_andcm, A7),
                Instr(Mnemonic.cmp_lt_or_andcm, A7),

                Instr(Mnemonic.cmp4_eq, A6),
                Instr(Mnemonic.cmp4_eq_unc, A6),
                Instr(Mnemonic.cmp4_eq_or_andcm, A6),
                Instr(Mnemonic.cmp4_ne_or_andcm, A6),

                Instr(Mnemonic.cmp4_gt_or_andcm, A7),
                Instr(Mnemonic.cmp4_le_or_andcm, A7),
                Instr(Mnemonic.cmp4_ge_or_andcm, A7),
                Instr(Mnemonic.cmp4_lt_or_andcm, A7)
            )));

        var bfSelector23 = Bf((34, 1), (33, 1), (12, 1));
        var compare23 = Sparse(37, 4, "  compare2-3", invalid,
            (0xC, Mask(bfSelector23, "compare C",
                Instr(Mnemonic.cmp_lt, A8),
                Instr(Mnemonic.cmp_lt_unc, A8),
                Instr(Mnemonic.cmp_eq_and, A8),
                Instr(Mnemonic.cmp_ne_and, A8),

                Instr(Mnemonic.cmp4_lt, A8),
                Instr(Mnemonic.cmp4_lt_unc, A8),
                Instr(Mnemonic.cmp4_eq_and, A8),
                Instr(Mnemonic.cmp4_ne_and, A8)
            )),
            (0xD, Mask(bfSelector23, "compare D",
                Instr(Mnemonic.cmp_ltu, A8),
                Instr(Mnemonic.cmp_ltu_unc, A8),
                Instr(Mnemonic.cmp_eq_or, A8),
                Instr(Mnemonic.cmp_ne_or, A8),

                Instr(Mnemonic.cmp4_ltu, A8),
                Instr(Mnemonic.cmp4_ltu_unc, A8),
                Instr(Mnemonic.cmp4_eq_or, A8),
                Instr(Mnemonic.cmp4_ne_or, A8)
            )),
            (0xE, Mask(bfSelector23, "compare E",
                Instr(Mnemonic.cmp_eq, A8),
                Instr(Mnemonic.cmp_eq_unc, A8),
                Instr(Mnemonic.cmp_eq_or_andcm, A8),
                Instr(Mnemonic.cmp_ne_or_andcm, A8),

                Instr(Mnemonic.cmp4_eq, A8),
                Instr(Mnemonic.cmp4_eq_unc, A8),
                Instr(Mnemonic.cmp4_eq_or_andcm, A8),
                Instr(Mnemonic.cmp4_ne_or_andcm, A8)
            )));

        var compare = Mask(35, 1, "  compare",
            compare01,
            compare23);
        return compare;
    }

    private static UnitDecoder MakeLdecoders()
    {
        return new UnitDecoder('l', Instr(Mnemonic._long_immediate, InstrClass.None, LImmediate));
    }

    private static TemplateDecoders[] BuildTemplateDecoders()
    {
        var invalid = Instr(Mnemonic.Invalid, InstrClass.Invalid);

        var invalidBundle = new TemplateDecoders(invalid, invalid, invalid, 0);
        WideDecoder b = Bdecoders;
        WideDecoder i = Idecoders;
        WideDecoder f = Fdecoders;
        WideDecoder l = Ldecoders;
        WideDecoder m = Mdecoders;
        WideDecoder x = Xdecoders;
        return new TemplateDecoders[32] 
        {
            new TemplateDecoders(m,i,i,0b000),
            new TemplateDecoders(m,i,i,0b001),
            new TemplateDecoders(m,i,i,0b010),
            new TemplateDecoders(m,i,i,0b011),

            new TemplateDecoders(m,l,x,0b000),
            new TemplateDecoders(m,l,x,0b001),
            invalidBundle,
            invalidBundle,

            new TemplateDecoders(m,m,i,0b000),
            new TemplateDecoders(m,m,i,0b001),
            new TemplateDecoders(m,m,i,0b100),
            new TemplateDecoders(m,m,i,0b101),

            new TemplateDecoders(m,f,i,0b000),
            new TemplateDecoders(m,f,i,0b001),
            new TemplateDecoders(m,m,f,0b000),
            new TemplateDecoders(m,m,f,0b001),

            // 10
            new TemplateDecoders(m,i,b,0b000),
            new TemplateDecoders(m,i,b,0b001),
            new TemplateDecoders(m,b,b,0b000),
            new TemplateDecoders(m,b,b,0b001),

            invalidBundle,
            invalidBundle,
            new TemplateDecoders(b,b,b,0b000),
            new TemplateDecoders(b,b,b,0b001),
            
            new TemplateDecoders(m,m,b,0b000),
            new TemplateDecoders(m,m,b,0b001),
            invalidBundle,
            invalidBundle,

            new TemplateDecoders(m,f,b,0b000),
            new TemplateDecoders(m,f,b,0b001),
            invalidBundle,
            invalidBundle,
        };
    }
}