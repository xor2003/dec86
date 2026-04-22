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
using Reko.Core.Types;
using System.Collections.Generic;
using System.Linq;

namespace Reko.Arch.IA64;

public static class Registers
{
    static Registers()
    {
        var factory = new StorageFactory();
        GpRegisters = factory.RangeOfReg64(128, "r{0}");
        FpRegisters = factory.RangeOfReg64(128, "f{0}");
        BranchRegisters = factory.RangeOfReg64(8, "b{0}");

        var sysregs = new StorageFactory(StorageDomain.SystemRegister);
        IP = sysregs.Reg64("ip");
        PR = sysregs.Reg64("pr");

        PredicateRegisters = Enumerable.Range(0, 64)
            .Select(i => new FlagGroupStorage(PR, 1ul << i, $"p{i:00}"))
            .ToArray();
        
        ApplicationRegisters = new Dictionary<uint, RegisterStorage>
        {
            { 0, (KR0 = sysregs.Reg64("KR0")) },        // Kernel Registers 0
            { 1, (KR1 = sysregs.Reg64("KR1")) },        // Kernel Registers 1
            { 2, (KR2 = sysregs.Reg64("KR2")) },        // Kernel Registers 2
            { 3, (KR3 = sysregs.Reg64("KR3")) },        // Kernel Registers 3
            { 4, (KR4 = sysregs.Reg64("KR4")) },        // Kernel Registers 4
            { 5, (KR5 = sysregs.Reg64("KR5")) },        // Kernel Registers 5
            { 6, (KR6 = sysregs.Reg64("KR6")) },        // Kernel Registers 6
            { 7, (KR7 = sysregs.Reg64("KR7")) },        // Kernel Registers 7
            { 16, (RSC = sysregs.Reg64("RSC")) },       // Register Stack Configuration Register
            { 17, (BSP = sysregs.Reg64("BSP")) },       // Backing Store Pointer (read-only)
            { 18, (BSPSTORE = sysregs.Reg64("BSPSTORE")) },    // Backing Store Pointer for Memory Stores
            { 19, (RNAT = sysregs.Reg64("RNAT")) },     // RSE NaT Collection Register
            { 21, (FCR = sysregs.Reg64("FCR")) },       // IA-32 Floating-point Control Register
            { 24, (EFLAG = sysregs.Reg64("EFLAG")) },   // IA-32 EFLAG register
            { 25, (CSD = sysregs.Reg64("CSD")) },       // IA-32 Code Segment Descriptor
            { 26, (SSD = sysregs.Reg64("SSD")) },       // IA-32 Stack Segment Descriptor
            { 27, (CFLG = sysregs.Reg64("CFLG")) },     // IA-32 Combined CR0 and CR4 register
            { 28, (FSR = sysregs.Reg64("FSR")) },       // IA-32 Floating-point Status Register
            { 29, (FIR = sysregs.Reg64("FIR")) },       // IA-32 Floating-point Instruction Register
            { 30, (FDR = sysregs.Reg64("FDR")) },       // IA-32 Floating-point Data Register
            { 32, (CCV = sysregs.Reg64("CCV")) },       // Compare and Exchange Compare Value Register
            { 36, (UNAT = sysregs.Reg64("UNAT")) },     // User NaT Collection Register
            { 40, (FPSR = sysregs.Reg64("FPSR")) },     // Floating-point Status Register
            { 44, (ITC = sysregs.Reg64("ITC")) },       // Interval Time Counter
            { 64, (PFS = sysregs.Reg64("ar.pfs")) },       // Previous Function State I
            { 65, (LC = sysregs.Reg64("LC")) },         // Loop Count Register
            { 66, (EC = sysregs.Reg64("EC")) },         // Epilog Count Register
        };
        RegistersByDomain = factory.DomainsToRegisters;
        RegistersByName = factory.NamesToRegisters;
    }

    public static RegisterStorage[] GpRegisters { get; }
    public static RegisterStorage[] FpRegisters { get; }
    public static RegisterStorage[] BranchRegisters { get; }
    public static FlagGroupStorage[] PredicateRegisters { get; }

    public static Dictionary<uint, RegisterStorage> ApplicationRegisters { get; }
    public static Dictionary<StorageDomain, RegisterStorage> RegistersByDomain{ get; }
    public static Dictionary<string, RegisterStorage> RegistersByName { get; }


    public static RegisterStorage IP { get; }    // Instruction Pointer
    public static RegisterStorage PR { get; }    // Predicate register

    public static RegisterStorage KR0 { get; }    // Kernel Registers 0
    public static RegisterStorage KR1 { get; }    // Kernel Registers 1
    public static RegisterStorage KR2 { get; }    // Kernel Registers 2
    public static RegisterStorage KR3 { get; }    // Kernel Registers 3
    public static RegisterStorage KR4 { get; }    // Kernel Registers 4
    public static RegisterStorage KR5 { get; }    // Kernel Registers 5
    public static RegisterStorage KR6 { get; }    // Kernel Registers 6
    public static RegisterStorage KR7 { get; }    // Kernel Registers 7
    public static RegisterStorage RSC { get; }    // Register Stack Configuration Register
    public static RegisterStorage BSP { get; }    // Backing Store Pointer (read-only)
    public static RegisterStorage BSPSTORE { get; }    // Backing Store Pointer for Memory Stores
    public static RegisterStorage RNAT { get; }    // RSE NaT Collection Register
    public static RegisterStorage FCR { get; }    // IA-32 Floating-point Control Register
    public static RegisterStorage EFLAG { get; }    // IA-32 EFLAG register
    public static RegisterStorage CSD { get; }    // IA-32 Code Segment Descriptor
    public static RegisterStorage SSD { get; }    // IA-32 Stack Segment Descriptor
    public static RegisterStorage CFLG { get; }    // IA-32 Combined CR0 and CR4 register
    public static RegisterStorage FSR { get; }    // IA-32 Floating-point Status Register
    public static RegisterStorage FIR { get; }    // IA-32 Floating-point Instruction Register
    public static RegisterStorage FDR { get; }    // IA-32 Floating-point Data Register
    public static RegisterStorage CCV { get; }    // Compare and Exchange Compare Value Register
    public static RegisterStorage UNAT { get; }    // User NaT Collection Register
    public static RegisterStorage FPSR { get; }    // Floating-point Status Register
    public static RegisterStorage ITC { get; }    // Interval Time Counter
    public static RegisterStorage PFS { get; }    // Previous Function State I
    public static RegisterStorage LC { get; }    // Loop Count Register
    public static RegisterStorage EC { get; }    // Epilog Count Register
}
