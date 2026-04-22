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
using Reko.Core.Machine;
using Reko.Core.Types;
using System.Collections.Generic;
using System.Text;

namespace Reko.Arch.IA64;

public sealed class IA64Instruction : MachineInstruction
{
    private static readonly Dictionary<Completer, string> completerRender = new()
    {
        { Completer.Nt1, ".nt1" },
        { Completer.Nta, ".nta" },
        { Completer.Prefetch_Few, ".few" },
        { Completer.Prefetch_Many, ".many" },
        { Completer.Whether_Sptk, ".sptk"},
        { Completer.Whether_Spnt, ".spnt"},
        { Completer.Whether_Dptk, ".dptk"},
        { Completer.Whether_Dpnt, ".dpnt" },
        { Completer.BranchCache_Clr, ".clr" },
        { Completer.Important, ".imp" },
        { Completer.FpS0, ".s0" },
        { Completer.FpS1, ".s1" },
        { Completer.FpS2, ".s2" },
        { Completer.FpS3, ".s3" },
    };

    public bool Stop { get; set; }
    public Mnemonic Mnemonic { get; set; }
    public Completer Completer { get; set; }

    public FlagGroupStorage? QualifyingPredicate { get; set; }

    /// <summary>
    /// Execution unit.
    /// </summary>
    /*[Obsolete]*/public char Unit { get; set; }


    public override int MnemonicAsInteger => (int) Mnemonic;
    public override string MnemonicAsString => Mnemonic.ToString();

    protected override void DoRender(MachineInstructionRenderer renderer, MachineInstructionRendererOptions options)
    {
        RenderQualifyingPredicate(renderer);
        RenderMnemonic(renderer);
        RenderOperands(renderer, options);
        if (Stop)
            renderer.WriteChar(';');
    }

    private void RenderQualifyingPredicate(MachineInstructionRenderer renderer)
    {
        if (QualifyingPredicate is null || QualifyingPredicate == Registers.PredicateRegisters[0])
            return;
        renderer.WriteFormat("({0}) ", QualifyingPredicate.Name);
    }

    private void RenderMnemonic(MachineInstructionRenderer renderer)
    {
        var sb = new StringBuilder();
        sb.Append(Mnemonic.ToString().Replace('_', '.'));
        var ld = Completer & Completer.LdMask;
        if (ld != 0)
        {
            sb.Append(completerRender[ld]);
        }
        var wh = Completer & Completer.Whether_Mask;
        if (wh != 0)
        {
            sb.Append(completerRender[wh]);
        }
        var ph = Completer & Completer.Prefetch_Mask;
        if (ph != 0)
        {
            sb.Append(completerRender[ph]);
        }
        var dh = Completer & Completer.BranchCache_Clr;
        if (dh != 0)
        {
            sb.Append(completerRender[dh]);
        }
        var ih = Completer & Completer.Important;
        if (ih != 0)
        {
            sb.Append(completerRender[ih]);
        }
        var sh = Completer & Completer.FpStatusMask;
        if (sh != 0)
        {
            sb.Append(completerRender[sh]);
        }
        renderer.WriteMnemonic(sb.ToString());
    }

    protected override void RenderOperand(MachineOperand operand, MachineInstructionRenderer renderer, MachineInstructionRendererOptions options)
    {
        switch (operand)
        {
        case Constant imm:
            if (imm.DataType.Domain == Domain.SignedInt)
            {
                renderer.WriteFormat("{0}", imm.ToInt64());
            }
            else
            {
                renderer.WriteFormat("0x{0:X}", imm.ToUInt64());
            }
            return;
        }
        base.RenderOperand(operand, renderer, options);
    }
}