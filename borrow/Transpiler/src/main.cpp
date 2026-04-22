#include "analysis_report.h"
#include "cfg.h"
#include "decoder.h"
#include "emitter.h"
#include "entry_analysis.h"
#include "mz_exe.h"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <set>
#include <stdexcept>
#include <string_view>
#include <vector>
#include <cstdlib>

namespace {

std::uint16_t parse_hex16(const std::string_view text) {
    const unsigned long value = std::stoul(std::string(text), nullptr, 16);
    if (value > 0xFFFFu) {
        throw std::runtime_error("hex value out of 16-bit range");
    }
    return static_cast<std::uint16_t>(value);
}

std::pair<std::uint16_t, std::uint16_t> parse_code_location(const std::string_view text) {
    const std::size_t colon = text.find(':');
    if (colon == std::string_view::npos) {
        throw std::runtime_error("code location must use cs:ip format");
    }
    return {
        parse_hex16(text.substr(0, colon)),
        parse_hex16(text.substr(colon + 1)),
    };
}

struct CommandLine {
    std::filesystem::path input_path = "Game/cfix.exe";
    std::size_t relocation_preview_count = 12;
    std::size_t disasm_instruction_count = 32;
    std::size_t cfg_block_limit = 0;
    std::size_t cfg_instruction_limit = 64;
    std::optional<std::pair<std::uint16_t, std::uint16_t>> block_preview;
    std::vector<std::pair<std::uint16_t, std::uint16_t>> indirect_debug_sites;
    std::optional<std::filesystem::path> emit_output_dir;
};

std::filesystem::path dynamic_target_db_path_for_input(const std::filesystem::path& input_path) {
    if (const char* explicit_path = std::getenv("MZ2CPP_DYNAMIC_TARGET_DB");
        explicit_path != nullptr && explicit_path[0] != '\0') {
        return std::filesystem::path(explicit_path);
    }
    const std::filesystem::path input_dir = input_path.has_parent_path() ? input_path.parent_path() : std::filesystem::path(".");
    return input_dir / "mz2cpp_dynamic_targets.txt";
}

std::filesystem::path labels_path_for_input(const std::filesystem::path& input_path) {
    const std::filesystem::path input_dir =
        input_path.has_parent_path() ? input_path.parent_path() : std::filesystem::path(".");
    return input_dir / "labels.txt";
}

struct ObservedDynamicTargetRecord {
    mz2cpp::CodeLocation target{};
    std::optional<mz2cpp::CodeLocation> source{};
};

std::uint32_t location_key(const mz2cpp::CodeLocation location) {
    return (static_cast<std::uint32_t>(location.cs) << 16u) | location.ip;
}

std::uint64_t transfer_key(const mz2cpp::CodeLocation source, const mz2cpp::CodeLocation target) {
    return (static_cast<std::uint64_t>(location_key(source)) << 32u) | location_key(target);
}

std::vector<ObservedDynamicTargetRecord> load_observed_dynamic_targets(const std::filesystem::path& db_path) {
    std::ifstream input(db_path);
    if (!input) {
        return {};
    }

    std::set<std::uint64_t> seen;
    std::vector<ObservedDynamicTargetRecord> records;
    std::string line;
    while (std::getline(input, line)) {
        unsigned src_cs = 0u;
        unsigned src_ip = 0u;
        unsigned target_cs = 0u;
        unsigned target_ip = 0u;
        if (std::sscanf(line.c_str(), "SRC %x:%x TARGET %x:%x", &src_cs, &src_ip, &target_cs, &target_ip) == 4) {
            const ObservedDynamicTargetRecord record{
                mz2cpp::CodeLocation{static_cast<std::uint16_t>(target_cs), static_cast<std::uint16_t>(target_ip)},
                mz2cpp::CodeLocation{static_cast<std::uint16_t>(src_cs), static_cast<std::uint16_t>(src_ip)},
            };
            const std::uint64_t key = transfer_key(*record.source, record.target);
            if (seen.insert(key).second) {
                records.push_back(record);
            }
            continue;
        }

        if (std::sscanf(line.c_str(), "PC %x:%x", &target_cs, &target_ip) == 2) {
            const ObservedDynamicTargetRecord record{
                mz2cpp::CodeLocation{static_cast<std::uint16_t>(target_cs), static_cast<std::uint16_t>(target_ip)},
                std::nullopt,
            };
            const std::uint64_t key =
                (static_cast<std::uint64_t>(0xFFFFFFFFu) << 32u) | location_key(record.target);
            if (seen.insert(key).second) {
                records.push_back(record);
            }
        }
    }
    return records;
}

std::set<std::uint32_t> collect_discovered_locations(const mz2cpp::CfgSnapshot& cfg) {
    std::set<std::uint32_t> discovered;
    for (const mz2cpp::CodeLocation root : cfg.discovered_function_roots) {
        discovered.insert(location_key(root));
    }
    for (const mz2cpp::BlockRecord& block : cfg.blocks) {
        discovered.insert(location_key(block.start));
    }
    return discovered;
}

std::set<std::uint64_t> collect_discovered_transfers(const mz2cpp::CfgSnapshot& cfg) {
    std::set<std::uint64_t> transfers;
    for (const mz2cpp::CfgEdge& edge : cfg.edges) {
        transfers.insert(transfer_key(edge.from, edge.to));
    }
    return transfers;
}

bool interface_surface_contains_target(const mz2cpp::InterfaceSurfaceRecord& surface,
                                       const mz2cpp::CodeLocation target) {
    for (const mz2cpp::InterfaceSurfaceEntry& entry : surface.entries) {
        if (entry.target_is_valid && entry.target.cs == target.cs && entry.target.ip == target.ip) {
            return true;
        }
    }
    return false;
}

bool target_is_covered_by_bridge_surface(const mz2cpp::MzImage& image,
                                         const mz2cpp::CfgSnapshot& cfg,
                                         const mz2cpp::CodeLocation source,
                                         const mz2cpp::CodeLocation target) {
    const mz2cpp::DecodedInstruction instruction = mz2cpp::decode_instruction(image, source.cs, source.ip);
    if (!instruction.indirect.has_value() || instruction.flow != mz2cpp::FlowKind::Call) {
        return false;
    }
    const mz2cpp::IndirectTransferInfo& indirect = *instruction.indirect;
    if (!indirect.is_far || indirect.operand_kind != mz2cpp::IndirectOperandKind::MemoryDirect ||
        !indirect.memory_offset.has_value()) {
        return false;
    }

    for (const mz2cpp::InterfaceSurfaceRecord& surface : cfg.interface_surfaces) {
        if (!interface_surface_contains_target(surface, target)) {
            continue;
        }
        if (*indirect.memory_offset == 0x0788u &&
            surface.kind != mz2cpp::InterfaceSurfaceKind::EngineApiJumpTable) {
            return true;
        }
        if (*indirect.memory_offset == 0x078Eu &&
            surface.kind == mz2cpp::InterfaceSurfaceKind::EngineApiJumpTable) {
            return true;
        }
    }
    return false;
}

bool target_is_covered_by_indirect_site(const mz2cpp::CfgSnapshot& cfg,
                                        const mz2cpp::CodeLocation source,
                                        const mz2cpp::CodeLocation target) {
    for (const mz2cpp::IndirectSiteRecord& site : cfg.indirect_sites) {
        if (site.from.cs != source.cs || site.from.ip != source.ip) {
            continue;
        }
        for (const mz2cpp::CodeLocation resolved : site.resolved_targets) {
            if (resolved.cs == target.cs && resolved.ip == target.ip) {
                return true;
            }
        }
        for (const mz2cpp::IndirectDispatchEntry& entry : site.dispatch_entries) {
            if (entry.target_is_valid &&
                entry.target.cs == target.cs &&
                entry.target.ip == target.ip) {
                return true;
            }
        }
        return false;
    }
    return false;
}

bool observed_target_is_satisfied(const mz2cpp::MzImage& image,
                                  const mz2cpp::CfgSnapshot& cfg,
                                  const std::set<std::uint32_t>& discovered,
                                  const std::set<std::uint64_t>& discovered_transfers,
                                  const ObservedDynamicTargetRecord& observed) {
    if (!observed.source.has_value()) {
        return discovered.contains(location_key(observed.target));
    }
    if (discovered_transfers.contains(transfer_key(*observed.source, observed.target))) {
        return true;
    }
    if (target_is_covered_by_indirect_site(cfg, *observed.source, observed.target)) {
        return true;
    }
    if (target_is_covered_by_bridge_surface(image, cfg, *observed.source, observed.target)) {
        return true;
    }
    return false;
}

std::vector<ObservedDynamicTargetRecord> collect_missing_observed_targets(
    const std::vector<ObservedDynamicTargetRecord>& observed_targets,
    const mz2cpp::MzImage& image,
    const mz2cpp::CfgSnapshot& cfg) {
    const std::set<std::uint32_t> discovered = collect_discovered_locations(cfg);
    const std::set<std::uint64_t> discovered_transfers = collect_discovered_transfers(cfg);
    std::vector<ObservedDynamicTargetRecord> missing;
    for (const ObservedDynamicTargetRecord& observed : observed_targets) {
        if (!observed_target_is_satisfied(image, cfg, discovered, discovered_transfers, observed)) {
            missing.push_back(observed);
        }
    }
    return missing;
}

void rewrite_observed_dynamic_targets_db(const std::filesystem::path& db_path,
                                         const std::vector<ObservedDynamicTargetRecord>& records) {
    std::ofstream output(db_path, std::ios::trunc);
    if (!output) {
        throw std::runtime_error("failed to rewrite observed dynamic target database: " + db_path.string());
    }
    for (const ObservedDynamicTargetRecord& record : records) {
        if (record.source.has_value()) {
            output << "SRC "
                   << std::uppercase << std::hex << std::setw(4) << std::setfill('0') << record.source->cs
                   << ":" << std::setw(4) << record.source->ip
                   << " TARGET " << std::setw(4) << record.target.cs
                   << ":" << std::setw(4) << record.target.ip << "\n";
        } else {
            output << "PC "
                   << std::uppercase << std::hex << std::setw(4) << std::setfill('0') << record.target.cs
                   << ":" << std::setw(4) << record.target.ip << "\n";
        }
    }
}

CommandLine parse_command_line(const int argc, char** argv) {
    CommandLine command_line{};

    for (int i = 1; i < argc; ++i) {
        const std::string_view arg(argv[i]);
        if (arg == "--input") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--input requires a path");
            }
            command_line.input_path = argv[++i];
            continue;
        }
        if (arg == "--reloc-preview") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--reloc-preview requires a count");
            }
            command_line.relocation_preview_count = static_cast<std::size_t>(std::stoul(argv[++i]));
            continue;
        }
        if (arg == "--disasm") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--disasm requires an instruction count");
            }
            command_line.disasm_instruction_count = static_cast<std::size_t>(std::stoul(argv[++i]));
            continue;
        }
        if (arg == "--cfg-blocks") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--cfg-blocks requires a block count");
            }
            command_line.cfg_block_limit = static_cast<std::size_t>(std::stoul(argv[++i]));
            continue;
        }
        if (arg == "--cfg-instrs") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--cfg-instrs requires an instruction count");
            }
            command_line.cfg_instruction_limit = static_cast<std::size_t>(std::stoul(argv[++i]));
            continue;
        }
        if (arg == "--block") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--block requires a cs:ip location");
            }
            command_line.block_preview = parse_code_location(argv[++i]);
            continue;
        }
        if (arg == "--debug-indirect") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--debug-indirect requires a cs:ip location");
            }
            command_line.indirect_debug_sites.push_back(parse_code_location(argv[++i]));
            continue;
        }
        if (arg == "--emit") {
            if (i + 1 >= argc) {
                throw std::runtime_error("--emit requires an output directory");
            }
            command_line.emit_output_dir = std::filesystem::path(argv[++i]);
            continue;
        }
        if (arg == "--help" || arg == "-h") {
            std::cout
                << "Usage: Transpiler [--input <path>] [--reloc-preview <count>] [--disasm <count>] [--cfg-blocks <count>] [--cfg-instrs <count>] [--block <cs:ip>] [--debug-indirect <cs:ip>] [--emit <dir>]\n"
                << "Default input is Game/cfix.exe\n"
                << "Default --cfg-blocks is 0 (unlimited); use 0 for --cfg-blocks or --cfg-instrs to remove that limit.\n";
            std::exit(0);
        }

        throw std::runtime_error("unknown argument: " + std::string(arg));
    }

    return command_line;
}

} // namespace

int main(int argc, char** argv) {
    try {
        const CommandLine command_line = parse_command_line(argc, argv);
        const mz2cpp::MzImage image = mz2cpp::load_mz_image(command_line.input_path);
        const std::filesystem::path dynamic_target_db_path = dynamic_target_db_path_for_input(command_line.input_path);
        const std::vector<ObservedDynamicTargetRecord> observed_dynamic_targets =
            load_observed_dynamic_targets(dynamic_target_db_path);
        const mz2cpp::CfgSnapshot cfg = mz2cpp::build_cfg_snapshot(
            image,
            mz2cpp::CodeLocation{image.entry_cs, image.entry_ip},
            command_line.cfg_block_limit,
            command_line.cfg_instruction_limit);
        std::cout << mz2cpp::format_mz_report(image, command_line.relocation_preview_count);
        if (!observed_dynamic_targets.empty()) {
            const std::vector<ObservedDynamicTargetRecord> missing_observed_targets =
                collect_missing_observed_targets(observed_dynamic_targets, image, cfg);
            const std::size_t resolved_count =
                observed_dynamic_targets.size() - missing_observed_targets.size();
            std::cout << "Observed runtime targets loaded: " << observed_dynamic_targets.size()
                      << " from " << dynamic_target_db_path.string() << "\n"
                      << "Observed runtime targets now covered by static analysis: "
                      << resolved_count << "\n"
                      << "Observed runtime targets still missing from static analysis: "
                      << missing_observed_targets.size() << "\n";
            if (resolved_count != 0u) {
                rewrite_observed_dynamic_targets_db(dynamic_target_db_path, missing_observed_targets);
                std::cout << "Pruned covered entries from " << dynamic_target_db_path.string() << "\n";
            }
            for (const ObservedDynamicTargetRecord& record : missing_observed_targets) {
                std::cout << "  missing: ";
                if (record.source.has_value()) {
                    std::cout << "0x"
                              << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
                              << record.source->cs << ':'
                              << std::setw(4) << std::setfill('0') << record.source->ip
                              << " -> ";
                }
                std::cout << "0x"
                          << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
                          << record.target.cs << ':'
                          << std::setw(4) << std::setfill('0') << record.target.ip
                          << std::dec << "\n";
            }
        }
        std::cout << '\n' << mz2cpp::format_entry_analysis(image, command_line.disasm_instruction_count);
        if (command_line.block_preview.has_value()) {
            const auto [block_cs, block_ip] = *command_line.block_preview;
            std::cout << '\n' << mz2cpp::format_basic_block_analysis(
                image,
                block_cs,
                block_ip,
                command_line.disasm_instruction_count,
                "Requested basic block preview");
        }
        std::cout << '\n' << mz2cpp::format_cfg_snapshot(cfg);
        for (const auto [site_cs, site_ip] : command_line.indirect_debug_sites) {
            std::cout << '\n'
                      << mz2cpp::format_indirect_site_debug(
                             image,
                             cfg,
                             mz2cpp::CodeLocation{site_cs, site_ip});
        }
        if (command_line.emit_output_dir.has_value()) {
            mz2cpp::emit_standalone_project(
                image,
                cfg,
                *command_line.emit_output_dir,
                labels_path_for_input(command_line.input_path));
            std::cout << "\nStandalone project emitted to: " << command_line.emit_output_dir->string() << '\n';
        }
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Transpiler error: " << ex.what() << '\n';
        return 1;
    }
}
