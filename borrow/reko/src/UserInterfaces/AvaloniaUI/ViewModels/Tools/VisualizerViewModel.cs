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

using Dock.Model.ReactiveUI.Controls;
using ReactiveUI;
using Reko.Core;
using Reko.Core.Memory;
using Reko.Gui;
using Reko.Gui.Services;
using Reko.Gui.Visualizers;
using System;
using System.Collections.Generic;
using System.ComponentModel.Design;
using System.Diagnostics;
using System.Linq;

namespace Reko.UserInterfaces.AvaloniaUI.ViewModels.Tools;

public class VisualizerViewModel : Tool
{
    private readonly ISelectedAddressService selAddrSvc;
    private readonly ISelectionService selSvc;

    public VisualizerViewModel(ISelectedAddressService selAddrSvc, ISelectionService selSvc)
    {
        this.selAddrSvc = selAddrSvc;
        this.selSvc = selSvc;
        this.selAddrSvc.SelectedAddressChanged += SelAddrSvc_SelectedAddressChanged;
        this.selAddrSvc.SelectedProcedureChanged += SelAddrSvc_SelectedProcedureChanged;
        this.selAddrSvc.SelectedProgramChanged += SelAddrSvc_SelectedProgramChanged;
        this.selSvc.SelectionChanged += SelSvc_SelectionChanged;
        this.selectedVisualizer = Visualizers[0];

        // Create sample data - 10240 bytes
        Bytes = new ByteMemoryArea(Address.Ptr32(0x123400), new byte[10240]);
        var random = new Random(42);
        for (int i = 0; i < Bytes.Length; i++)
        {
            // Create some pattern for demonstration
            Bytes.Bytes[i] = (byte) (Math.Sin(i * 0.1) * 127 + 128);
        }
    }

    public ByteMemoryArea? Bytes
    {
        get => bytes;
        set { this.RaiseAndSetIfChanged(ref bytes, value); }
    }
    private ByteMemoryArea? bytes;

    public Program? Program
    {
        get => program;
        set { this.RaiseAndSetIfChanged(ref program, value); }
    }
    private Program? program;

    public ListOption SelectedVisualizer
    {
        get => selectedVisualizer;
        set { this.RaiseAndSetIfChanged(ref selectedVisualizer, value); }
    }
    private ListOption selectedVisualizer;

    public List<ListOption> Visualizers { get; } = 
    [
        new ListOption("ASCII strings", new AsciiStringVisualizer()),
        new ListOption("Code and data", new CodeDataVisualizer()),
        new ListOption("Heat map", new HeatmapVisualizer()),
    ];

    private void SelAddrSvc_SelectedProgramChanged(object? sender, EventArgs e)
    {
        this.Program = this.selAddrSvc.SelectedProgram;
        if (program is null)
        {
            this.Bytes = null;
            //this.Address = null;
        }
        else
        {
            if (!program.SegmentMap.TryFindSegment(program.SegmentMap.BaseAddress, out var segment))
                return;
            if (segment.MemoryArea is not ByteMemoryArea bmem)
                return;
            this.Bytes = bmem;
            //this.Address = segment.MemoryArea.BaseAddress;
        }
    }

    private void SelAddrSvc_SelectedProcedureChanged(object? sender, EventArgs e)
    {
        var proc = this.selAddrSvc.SelectedProcedure;
        this.Program = this.selAddrSvc.SelectedProgram;
        if (proc is null || program is null) // || proc.EntryAddress == this.Address)
            return;
        Debug.Assert(program is not null);
        if (!program.Memory.SegmentMap.TryFindSegment(proc.EntryAddress, out var segment))
            return;
        if (segment.MemoryArea is not ByteMemoryArea bmem)
            return;
        this.Bytes = bmem;
        //this.Address = proc.EntryAddress;
    }

    private void SelAddrSvc_SelectedAddressChanged(object? sender, EventArgs e)
    {
        var addrRange = this.selAddrSvc.SelectedAddressRange;
        this.Program = this.selAddrSvc.SelectedProgram;
        if (addrRange is null || Program is null) // || addrRange.Address == this.Address)
            return;
        if (!Program.Memory.SegmentMap.TryFindSegment(addrRange.Address, out var segment))
            return;
        if (segment.MemoryArea is not ByteMemoryArea bmem)
            return;
        this.Bytes = bmem;
        //this.Address = addrRange.Address;
    }

    //$TODO: this should happen in VisualizerViewModel.
    private void SelSvc_SelectionChanged(object? sender, EventArgs e)
    {
        if (Program is null)
            return;
        var ar = selSvc.GetSelectedComponents()
           .OfType<AddressRange>()
           .FirstOrDefault();
        if (ar is null)
            return;
        if (!Program.Memory.SegmentMap.TryFindSegment(ar.Begin, out var seg))
        {
            return;
        }
        if (seg.MemoryArea is not ByteMemoryArea bmem)
            return;
        this.Bytes = bmem;
    }
}
