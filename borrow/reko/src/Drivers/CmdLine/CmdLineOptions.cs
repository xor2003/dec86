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

using System.Collections.Generic;

namespace Reko.CmdLine;

public class CmdLineOptions
{
    public CmdLineOptions(MajorCommand majorCommand)
    {
        this.MajorCommand = majorCommand;
        this.Regs = [];
        this.Heuristics = [];
        this.DebugTraceProc = [];
        this.Filenames = [];
        this.ArchOptions = [];
        this.DebugTypes = (0, -1);
    }

    public MajorCommand MajorCommand { get; set; }
    public string? Architecture { get; set; }
    public string? LocaleName { get; set; }
    public string? Environment { get; set; }
    public string? Base { get; set; }
    public string? Entry { get; set; }
    public string? Loader { get; set; }
    public string? DefaultTo { get; set; }
    public string? Metadata { get; set; }
    public string? Data { get; set; }
    public List<string> Regs { get; }
    public List<string>Heuristics { get; }
    public int TimeLimit { get; set; }
    public bool DasmAddress { get; set; }
    public bool DasmBytes { get; set; }
    public string? ExtractResources { get; set; }
    public (int, int) DebugTypes { get; set; }
    public List<string> DebugTraceProc { get; set; }
    public bool AggressiveBranchRemoval { get; set; }
    public List<string> Filenames { get; set; }
    public bool DasmBaseInstrs { get; set; }
    public Dictionary<string, object> ArchOptions { get; }
    public string? Syntax { get;  set; }
}
