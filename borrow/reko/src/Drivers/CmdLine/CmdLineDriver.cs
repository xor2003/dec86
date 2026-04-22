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
using Reko.Core.Collections;
using Reko.Core.Configuration;
using Reko.Core.Expressions;
using Reko.Core.Loading;
using Reko.Core.Memory;
using Reko.Core.Services;
using Reko.Loading;
using Reko.Services;
using System;
using System.Collections.Generic;
using System.ComponentModel.Design;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;

namespace Reko.CmdLine
{
    public class CmdLineDriver
    {
        private readonly IServiceProvider services;
        private readonly ILoader ldr;
        private readonly IDecompilerService dcSvc;
        private readonly IConfigurationService config;
        private readonly CmdLineListener listener;
        private Timer? timer;

        public static void Main(string[] args)
        {
            var services = new ServiceContainer();
            var listener = new CmdLineListener
            {
                Quiet = Console.IsOutputRedirected
            };
            var config = RekoConfigurationService.Load(services);
            var fsSvc = new FileSystemService();
            var dcSvc = new DecompilerService();
            services.AddService<IDecompilerService>(dcSvc);
            services.AddService<IEventListener>(listener);
            services.AddService<IDecompilerEventListener>(listener);
            services.AddService<IConfigurationService>(config);
            services.AddService<ITypeLibraryLoaderService>(new TypeLibraryLoaderServiceImpl(services));
            services.AddService<IFileSystemService>(fsSvc);
            services.AddService<IDecompiledFileService>(new DecompiledFileService(services, fsSvc, listener));
            services.AddService<IPluginLoaderService>(new PluginLoaderService());
            services.AddService<ITestGenerationService>(new TestGenerationService(services));
            services.AddService<IOutputService>(new CmdOutputService());
            var ldr = new Loader(services);
            var driver = new CmdLineDriver(services, ldr, dcSvc, listener);
            driver.Execute(args);
        }

        public CmdLineDriver(
            IServiceProvider services,
            ILoader ldr,
            IDecompilerService dcSvc,
            CmdLineListener listener)
        {
            this.services = services;
            this.ldr = ldr;
            this.dcSvc = dcSvc;
            this.listener = listener;
            this.config = services.RequireService<IConfigurationService>();
        }

        public void Execute(string[] args)
        {
            var options = ProcessArguments(Console.Out, args);
            if (options is null)
                return;

            if (!string.IsNullOrEmpty(options.LocaleName)) { 
                Thread.CurrentThread.CurrentUICulture = new CultureInfo(options.LocaleName);
            }

            if (!string.IsNullOrEmpty(options.DefaultTo))
            {
                ldr.DefaultToFormat = options.DefaultTo;
            }

            StartTimer(options);

            switch (options.MajorCommand)
            {
            case MajorCommand.Assemble:
                Assemble(options);
                return;
            case MajorCommand.Dump:
                Dump(options);
                return;
            }
            if (OverridesRequested(options))
            {
                DecompileRawImage(options);
            }
            else if (options.Filenames.Count > 0)
            {
                Decompile(options, args);
            }
            else
            {
                Usage(Console.Out);
            }
        }

        private void StartTimer(CmdLineOptions options)
        {
            if (options.TimeLimit > 0)
            {
                int msecLimit = 1000 * options.TimeLimit;
                this.timer = new Timer(TimeLimitExpired, null, msecLimit, Timeout.Infinite);
            }
        }

        private void TimeLimitExpired(object? state)
        {
            this.listener.CancelDecompilation("User-specified time limit has expired.");
        }

        public static bool OverridesRequested(CmdLineOptions options)
        {
            if (!string.IsNullOrEmpty(options.Architecture) ||
                !string.IsNullOrEmpty(options.Environment) ||
                !string.IsNullOrEmpty(options.Base) ||
                !string.IsNullOrEmpty(options.Entry) ||
                !string.IsNullOrEmpty(options.Loader))
            {
                // User must supply these arguments for a meaningful
                // decompilation.
                if (!string.IsNullOrEmpty(options.Architecture) &&
                    (options.Filenames.Count > 0 || !string.IsNullOrEmpty(options.Data)))
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        }

        private void Decompile(CmdLineOptions options, string[] args)
        {
            if (options.Filenames.Count <= 0)
            {
                listener.Error("You must provide a file name.");
                return;
            }
            var addrLoad = ParseAddress(options.Base);
            try
            {
                var fileName = options.Filenames[0];
                var filePath = Path.GetFullPath(fileName);
                var imageLocation = ImageLocation.FromUri(filePath);
                var loadedImage = ldr.Load(imageLocation, options.Loader, options.Environment, addrLoad);
                Project project;
                switch (loadedImage)
                {
                case Program loadedProgram:
                    project = Project.FromSingleProgram(loadedProgram);
                    break;
                case Project loadedProject:
                    project = loadedProject;
                    break;
                default:
                    this.listener.Error("Cannot decompile {0}.", fileName);
                    return;
                }
                var decompiler = new Decompiler(project, services);
                dcSvc.Decompiler = decompiler;

                var program = decompiler.Project.Programs[0];
                program.User.ExtractResources = ShouldExtractResources(program, options);

                if (options.Heuristics.Count > 0)
                {
                    decompiler.Project.Programs[0].User.Heuristics = options.Heuristics.ToSortedSet();
                }
                if (!string.IsNullOrEmpty(options.Metadata))
                {
                    decompiler.Project.MetadataFiles.Add(new MetadataFile
                    {
                        Location = ImageLocation.FromUri(options.Metadata)
                    });
                }
                if (options.DasmAddress)
                {
                    decompiler.Project.Programs[0].User.ShowAddressesInDisassembly = true;
                }
                if (options.DasmAddress)
                {
                    decompiler.Project.Programs[0].User.RenderInstructionsCanonically = true;
                }
                if (options.DasmBytes)
                {
                    decompiler.Project.Programs[0].User.ShowBytesInDisassembly = true;
                }
                if (options.AggressiveBranchRemoval)
                {
                    decompiler.Project.Programs[0].User.Heuristics.Add("aggressive-branch-removal");
                }
                if (options.DebugTypes.Item1 <= options.DebugTypes.Item2)
                {
                    decompiler.Project.Programs[0].DebugProcedureRange = options.DebugTypes;
                }
                if (options.DebugTraceProc.Count > 0)
                {
                    decompiler.Project.Programs[0].User.DebugTraceProcedures 
                        = options.DebugTraceProc.ToHashSet();
                }
                decompiler.ExtractResources();
                decompiler.ScanPrograms();
                if (options.MajorCommand == MajorCommand.Decompile)
                {
                    decompiler.AnalyzeDataFlow();
                    decompiler.ReconstructTypes();
                    decompiler.StructureProgram();
                    decompiler.WriteDecompilerProducts();
                }
            }
            catch (Exception ex)
            {
                listener.Error(ex, "An error occurred during decompilation.");
            }
        }

        private void Dump(CmdLineOptions options)
        {
            if (options.Filenames.Count < 1)
            {
                listener.Error("You must provide a file name.");
                return;
            }
            var addrLoad = ParseAddress(options.Base);
            try
            {
                var fileName = options.Filenames[0];
                var filePath = Path.GetFullPath(fileName);
                var imageLocation = ImageLocation.FromUri(filePath);
                var bytes = ldr.LoadImageBytes(imageLocation);
                var loadedImage = ldr.ParseBinaryImage(
                    imageLocation,
                    bytes,
                    options.Loader,
                    options.Environment,
                    null,
                    addrLoad);
                Project project;
                switch (loadedImage)
                {
                case Program loadedProgram:
                    project = Project.FromSingleProgram(loadedProgram);
                    break;
                case Project loadedProject:
                    project = loadedProject;
                    break;
                default:
                    this.listener.Error("Cannot dump {0}.", fileName);
                    return;
                }
                var decompiler = new Decompiler(project, services);
                dcSvc.Decompiler = decompiler;

                var program = decompiler.Project.Programs[0];

                if (!string.IsNullOrEmpty(options.Metadata))
                {
                    decompiler.Project.MetadataFiles.Add(new MetadataFile
                    {
                        Location = ImageLocation.FromUri(options.Metadata)
                    });
                }
                decompiler.Project.Programs[0].User.ShowAddressesInDisassembly |= options.DasmAddress;
                decompiler.Project.Programs[0].User.RenderInstructionsCanonically |= options.DasmBaseInstrs;
                decompiler.Project.Programs[0].User.ShowBytesInDisassembly |= options.DasmBytes;
                
                decompiler.ExtractResources();
                decompiler.ScanPrograms();
                if (options.MajorCommand == MajorCommand.Decompile)
                {
                    decompiler.AnalyzeDataFlow();
                    decompiler.ReconstructTypes();
                    decompiler.StructureProgram();
                    decompiler.WriteDecompilerProducts();
                }
            }
            catch (Exception ex)
            {
                listener.Error(ex, "An error occurred during decompilation.");
            }
        }

        private void Assemble(CmdLineOptions options)
        {
            if (options.Filenames.Count < 1)
            {
                listener.Error("You must provide a file name.");
                return;
            }
            var filename = options.Filenames[0];
            if (string.IsNullOrEmpty(options.Architecture))
            {
                listener.Error("You must specify a processor architecture.");
                return;
            }
            string sArch = options.Architecture;

            string? syntax = null;
            if (!string.IsNullOrEmpty(options.Syntax))
            {
                syntax = options.Syntax;
            }
            var arch = config.GetArchitecture(sArch);
            if (arch is null)
            {
                listener.Error($"Unknown architecture moniker {sArch}.");
                return;
            }
            Address addrBase = Address.Ptr64(0);
            if (!string.IsNullOrEmpty(options.Base))
            {
                if (!arch.TryParseAddress(options.Base, out addrBase))
                {
                    listener.Error($"'{options.Base} couldn't be recognized as an address.");
                    return;
                }
            }
            var asm = arch.CreateAssembler(syntax);
            using (TextReader rdr = new StreamReader(filename))
            {
                var program = asm.Assemble(addrBase, filename, rdr);
                var seg = program.Memory.SegmentMap.Segments.Values.First();
                var binPath = Path.ChangeExtension(filename, ".bin");
                File.WriteAllBytes(binPath, ((ByteMemoryArea) seg.MemoryArea).Bytes);
            }
        }

        /// <summary>
        /// Determine whether a command line directive overrides the extract resources flag in the userdata.
        /// </summary>
        private static bool ShouldExtractResources(Program program, CmdLineOptions options)
        {
            if (string.IsNullOrEmpty(options.ExtractResources))
                return program.User.ExtractResources;
            var sExtractResources = options.ExtractResources;
            return sExtractResources != "no" && sExtractResources != "false";
        }

        private static Address? ParseAddress(string? sAddress)
        {
            if (sAddress is null)
                return null;
            if (ulong.TryParse(sAddress, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ulong uAddr))
            {
                return Address.Ptr64(uAddr);
            }
            else
            {
                return null;
            }
        }

        private void DecompileRawImage(CmdLineOptions options)
        {
            try
            {
                if (string.IsNullOrEmpty(options.Architecture))
                    throw new ApplicationException("You must specify a processor architecture with the --arch option.");
                var arch = config.GetArchitecture(options.Architecture);
                if (arch is null)
                    throw new ApplicationException($"Unknown architecture {options.Architecture}.");
                Dictionary<string, object> archOptions;
                if (options.ArchOptions.Count > 0)
                {
                    arch.LoadUserOptions(options.ArchOptions);
                    archOptions = options.ArchOptions;
                }
                else
                {
                    archOptions = new Dictionary<string,object>(StringComparer.OrdinalIgnoreCase);
                }
                string sAddrBase = options.Base ?? "0";
                if (!arch.TryParseAddress(sAddrBase, out Address addrBase))
                    throw new ApplicationException($"'{sAddrBase}' doesn't appear to be a valid address.");

                string sAddrEntry = options.Entry ?? sAddrBase;
                if (!arch.TryParseAddress(sAddrEntry.ToString(), out _))
                    throw new ApplicationException($"'{sAddrEntry}' doesn't appear to be a valid address.");

                var loadDetails = new LoadDetails
                {
                    Location = options.Filenames.Count > 0
                        ? ImageLocation.FromUri(options.Filenames[0])
                        : null,
                    LoaderName = options.Loader,
                    ArchitectureName = options.Architecture,
                    ArchitectureOptions = archOptions,
                    PlatformName = options.Environment,
                    LoadAddress = sAddrBase,
                    EntryPoint = new EntryPointDefinition { Address = sAddrEntry }
                };
                var program = LoadProgram(options, loadDetails);
                var project = Project.FromSingleProgram(program);
                var decompiler = new Decompiler(project, services);
                dcSvc.Decompiler = decompiler;

                var state = CreateInitialState(arch, program.SegmentMap, options);
                if (options.Heuristics.Count > 0)
                {
                    program.User.Heuristics = options.Heuristics.ToSortedSet();
                }
                program.User.ShowAddressesInDisassembly |= options.DasmAddress;
                program.User.RenderInstructionsCanonically |= options.DasmBaseInstrs;
                program.User.ShowBytesInDisassembly |= options.DasmBytes;

                if (options.AggressiveBranchRemoval)
                {
                    program.User.Heuristics.Add("aggressive-branch-removal");
                }
                decompiler.ScanPrograms();
                if (options.MajorCommand == MajorCommand.Decompile)
                {
                    decompiler.AnalyzeDataFlow();
                    decompiler.ReconstructTypes();
                    decompiler.StructureProgram();
                    decompiler.WriteDecompilerProducts();
                }
            }
            catch (Exception ex)
            {
                listener.Error(ex, "An error occurred during decompilation.");
            }
        }

        private Program LoadProgram(CmdLineOptions options, LoadDetails loadDetails)
        {
            listener.Progress.ShowStatus("Loading raw bytes.");
            Program program;
            if (!string.IsNullOrEmpty(options.Data))
            {
                var hexBytes = options.Data;
                var image = BytePattern.FromHexBytes(hexBytes);
                program = ldr.LoadRawImage(image, loadDetails);
            }
            else
            {
                program = ldr.LoadRawImage(loadDetails);
                program.Location = loadDetails.Location!;
            }
            listener.Progress.ShowStatus("Raw bytes loaded.");
            return program;
        }

        private static ProcessorState CreateInitialState(IProcessorArchitecture arch, SegmentMap map, CmdLineOptions args)
        {
            var state = arch.CreateProcessorState();
            if (args.Regs.Count <= 0)
                return state;
            foreach (var regValue in args.Regs.Where(r => !string.IsNullOrEmpty(r)))
            {
                var rr = regValue.Split(':');
                if (rr is null || rr.Length != 2)
                    continue;
                var reg = arch.GetRegister(rr[0]);
                if (reg is null)
                    continue;
                state.SetRegister(reg, Constant.Create(reg.DataType, Convert.ToInt64(rr[1], 16)));
            }
            return state;
        }

        private CmdLineOptions? ProcessArguments(TextWriter w, string[] args)
        {
            if (args.Length == 0)
            {
                Usage(w);
                return null;
            }

            // Eat major commands. The default major command is
            // "decompile".
            CmdLineOptions parsedArgs = new(MajorCommand.Decompile);
            int i = 0;
            switch (args[0])
            {
            case "asm":
            case "assemble":
                parsedArgs.MajorCommand = MajorCommand.Assemble;
                ++i;
                break;
            case "decompile":
                parsedArgs.MajorCommand = MajorCommand.Decompile;
                ++i;
                break;
            case "dasm":
            case "disassemble":
                parsedArgs.MajorCommand = MajorCommand.Disassemble;
                ++i;
                break;
            case "dump":
                parsedArgs.MajorCommand = MajorCommand.Dump;
                ++i;
                break;
            }
            // Now eat options
            // With major commands we now have the possibility
            // to have specific options for each major command.
            for (; i < args.Length; ++i)
            {
                if (string.IsNullOrEmpty(args[i]))
                    continue;
                var arg = args[i];
                if (arg == "-?" || arg.StartsWith("-h") || arg.StartsWith("--help"))
                {
                    Usage(w);
                    return null;
                }
                if (arg == "-q" || arg == "--quiet")
                {
                    listener.Quiet = true;
                }
                else if (arg.StartsWith("--version"))
                {
                    ShowVersion(w);
                    return null;
                }
                else if (args[i] == "--locale")
                {
                    if (i < args.Length - 1)
                        parsedArgs.LocaleName = args[++i];
                }
                else if (args[i] == "--arch")
                {
                    if (i < args.Length - 1)
                        parsedArgs.Architecture = args[++i];
                }
                else if (args[i] == "--arch-option")
                {
                    if (i < args.Length - 1)
                        ParseArchitectureOption(args[++i], parsedArgs);
                }
                else if (args[i] == "--env")
                {
                    if (i < args.Length - 1)
                        parsedArgs.Environment = args[++i];
                }
                else if (args[i] == "--base")
                {
                    if (i < args.Length - 1)
                        parsedArgs.Base = args[++i];
                }
                else if (args[i] == "--entry")
                {
                    if (i < args.Length - 1)
                        parsedArgs.Entry = args[++i];
                }
                else if (args[i] == "--default-to")
                {
                    if (i < args.Length - 1)
                        parsedArgs.DefaultTo = args[++i];
                }
                else if (args[i] == "-l" || args[i] == "--loader")
                {
                    if (i < args.Length - 1)
                        parsedArgs.Loader = args[++i];
                }
                else if (args[i] == "--reg" || args[i] == "-r")
                {
                    if (i < args.Length - 1)
                    {
                        parsedArgs.Regs.Add(args[++i]);
                    }
                }
                else if (args[i] == "--heuristic")
                {
                    if (i < args.Length - 1 && !string.IsNullOrEmpty(args[i + 1]))
                    {
                        parsedArgs.Heuristics.AddRange(args[i + 1].Split(','));
                        ++i;
                    }
                }
                else if (args[i] == "--metadata")
                {
                    if (i >= args.Length - 1)
                    {
                        w.WriteLine("error: expected metadata file name.");
                    }
                    ++i;
                    parsedArgs.Metadata = args[i];
                }
                else if (args[i] == "--time-limit")
                {
                    if (i >= args.Length - 1 || !int.TryParse(args[i + 1], out int timeLimit))
                    {
                        w.WriteLine("error: time-limit option expects a numerical argument.");
                        return null;
                    }
                    parsedArgs.TimeLimit = timeLimit;
                    ++i;
                }
                else if (args[i] == "--data")
                {
                    if (i >= args.Length - 1)
                    {
                        w.WriteLine("error: --data option expects a string of hex bytes.");
                        return null;
                    }
                    ++i;
                    parsedArgs.Data = args[i];
                }
                else if (args[i] == "--dasm-address")
                {
                    parsedArgs.DasmAddress = true;
                }
                else if (args[i] == "--dasm-bytes")
                {
                    parsedArgs.DasmBytes = true;
                }
                else if (args[i] == "--dasm-base-instrs")
                {
                    parsedArgs.DasmBaseInstrs = true;
                }
                else if (args[i] == "--scan-only")
                {
                    //$TODO: deprecate this command
                    w.WriteLine("error: --scan-only parameter is deprecated. Use 'reko disassemble' instead.");
                    Usage(w);
                    return null;
                }
                else if (args[i] == "--extract-resources")
                {
                    if (i < args.Length - 1)
                    {
                        parsedArgs.ExtractResources = args[++i];
                    }
                    else
                    {
                        parsedArgs.ExtractResources = "yes";
                    }
                }
                else if (args[i] == "--aggressive-branch-removal")
                {
                    parsedArgs.AggressiveBranchRemoval = true;
                }
                else if (args[i] == "--debug-types")
                {
                    if (i < args.Length - 1)
                    {
                        parsedArgs.DebugTypes = ParseIntRange(args[++i]);
                    }
                }
                else if (args[i] == "--debug-trace-proc")
                {
                    if (i < args.Length - 1)
                    {
                        ++i;
                        parsedArgs.DebugTraceProc.AddRange(args[i].Split(',').Distinct());
                    }
                }
                else if (args[i] == "--syntax")
                {
                    if (i < args.Length - 1)
                    {
                        parsedArgs.Syntax = args[++i];
                    }
                }
                else if (arg.StartsWith("-"))
                {
                    w.WriteLine("error: unrecognized option {0}", arg);
                    return null;
                }
                else
                {
                    parsedArgs.Filenames.Add(args[i]);
                }
            }
            return parsedArgs;
        }

        private static (int, int) ParseIntRange(string sRange)
        {
            int iColon = sRange.IndexOf(':');
            if (iColon <= 0)
            {
                return (0, Convert.ToInt32(sRange));
            }
            else
            {
                var nStart = Convert.ToInt32(sRange.Remove(iColon));
                ++iColon;
                var nEnd = (iColon < sRange.Length)
                    ? Convert.ToInt32(sRange.Substring(iColon))
                    : 0;
                return (nStart, nEnd);
            }
        }

        /// <summary>
        /// Parses an architecture specific option and adds it 
        /// to the "--arch-options" dictionary.
        /// </summary>
        /// <remarks>
        /// Architecture options are written as follows
        /// --arch-option {name}={value}
        /// </remarks>
        /// <param name="nameValue">String containing the name of the option 
        /// and its value.</param>
        /// <param name="parsedArgs">The dictionary of values parsed so far.
        /// </param>
        private static void ParseArchitectureOption(string nameValue, CmdLineOptions parsedArgs)
        {
            var name_value = nameValue.Split('=');
            parsedArgs.ArchOptions[name_value[0]] = string.Join("=", name_value.Skip(1));
        }

        private static void ShowVersion(TextWriter w)
        {
            var attrs = Assembly.GetExecutingAssembly().GetCustomAttributes(typeof(AssemblyFileVersionAttribute), true);
            if (attrs.Length < 1)
                return;
            var attr = (AssemblyFileVersionAttribute)attrs[0];
            w.Write("Reko decompiler version {0}", attr.Version);
            var githashAttr = typeof(AssemblyMetadata).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
                .FirstOrDefault(a => a.Key == "GitHash");
            if (githashAttr is not null)
            {
                w.Write(" (git:{0})", githashAttr.Value);
            }
            w.WriteLine();
        }

        private void Usage(TextWriter w)
        {
            w.WriteLine("Usage:");
            w.WriteLine("  reko decompile [options] <filename>");
            w.WriteLine("  reko disassemble [options] <filename>");
            w.WriteLine("  reko assemble [options] <filename>");
            w.WriteLine("    <filename> can be either an executable file or a project file.");
            w.WriteLine();
            w.WriteLine("Options:");
            w.WriteLine(" --version                Show version number and exit.");
            w.WriteLine(" -h, --help               Show this message and exit.");
            w.WriteLine(" -l, --loader <ldr>       Use a custom loader where <ldr> is either the file");
            w.WriteLine("                          name containing a loader script or the CLR type name");
            w.WriteLine("                          of the loader.");
            w.WriteLine(" --arch <architecture>    Use an architecture from the following:");
            DumpArchitectures(config, w, "    {0,-25} {1}");
            w.WriteLine(" --arch-option <name>=<value>  Set the value of the architecture-specific");
            w.WriteLine("                          option <name> to <value>.");
            w.WriteLine(" --env <environment>      Use an operating environment from the following:");
            DumpEnvironments(config, w, "    {0,-25} {1}");
            w.WriteLine(" --base <address>         Use <address> as the base address of the program.");
            w.WriteLine(" --dasm-address           Display addresses in disassembled machine code.");
            w.WriteLine(" --dasm-base-instrs       Don't display pseudo- or aliased instructions.");
            w.WriteLine(" --dasm-bytes             Display individual bytes in disassembled machine code.");
            w.WriteLine(" --data <hex-bytes>       Supply machine code as hex bytes");
            w.WriteLine(" --default-to <format>    If no executable format can be recognized, default");
            w.WriteLine("                          to one of the following formats:");
            DumpRawFiles(config, w, "    {0,-25} {1}");
            w.WriteLine(" --entry <address>        Use <address> as an entry point to the program.");
            w.WriteLine(" --extract-resources <flag>  If <flag> is true, extract any embedded");
            w.WriteLine("                          resources (defaults to true).");
            w.WriteLine(" -q, --quiet              Suppress most output during execution.");
            w.WriteLine(" --reg <regInit>          Set register to value, where regInit is formatted as");
            w.WriteLine("                          reg_name:value, e.g. sp:FF00");
            w.WriteLine(" --heuristic <h1>[,<h2>...]  Use one of the following heuristics to examine");
            w.WriteLine("                          the binary:");
            w.WriteLine("    shingle               Use shingle assembler to discover more procedures");
            w.WriteLine("    calls-respect-abi     Assume procedure calls respect the platform ABI");
            w.WriteLine(" --aggressive-branch-removal Be more aggressive in removing unused branches");
            w.WriteLine(" --metadata <filename>    Use the file <filename> as a source of metadata");
            w.WriteLine(" --time-limit <s>         Limit execution time to s seconds");
            w.WriteLine(" --debug-trace-proc <p1>[,<p2>...]  Debug: trace Reko analysis phases of the");
            w.WriteLine("                          given procedure names p1, p2 etc.");
            //           01234567890123456789012345678901234567890123456789012345678901234567890123456789
        }

        private static void DumpArchitectures(IConfigurationService config, TextWriter w, string fmtString)
        {
            foreach (var arch in config.GetArchitectures()
                .OfType<ArchitectureDefinition>()
                .OrderBy(a => a.Name))
            {
                w.WriteLine(fmtString, arch.Name, arch.Description);
            }
        }

        private static void DumpEnvironments(IConfigurationService config, TextWriter w, string fmtString)
        {
            foreach (var arch in config.GetEnvironments()
                .OfType<PlatformDefinition>()
                .OrderBy(a => a.Name))
            {
                w.WriteLine(fmtString, arch.Name, arch.Description);
            }
        }

        private static void DumpRawFiles(IConfigurationService config, TextWriter w, string fmtString)
        {
            foreach (var raw in config.GetRawFiles()
                .OfType<RawFileDefinition>()
                .OrderBy(a => a.Name))
            {
                w.WriteLine(fmtString, raw.Name, raw.Description);
            }
        }
    }
}
