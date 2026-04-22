#include "emitter.h"

#include <filesystem>
#include <algorithm>
#include <cctype>
#include <fstream>
#include <map>
#include <limits>
#include <set>
#include <optional>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string_view>

namespace mz2cpp {

namespace {

struct EmissionSymbolMap {
    std::map<std::uint32_t, std::string> names_by_location;
    std::map<std::uint32_t, std::string> offset_constant_names_by_location;
    std::vector<std::pair<std::uint32_t, std::string>> ordered_offset_constants;
    std::optional<std::uint16_t> default_data_segment;
};

struct GeneratedDataRegion {
    enum class Kind {
        Code,
        NamedStatic,
        Residual,
    };

    Kind kind = Kind::Residual;
    std::uint32_t physical = 0;
    CodeLocation location{};
    std::string name;
    bool writable = false;
    std::size_t relocation_count = 0u;
    std::size_t direct_access_count = 0u;
    std::size_t stride_hint = 0u;
    std::string classification;
    std::string storage_kind;
    std::vector<std::uint32_t> direct_access_offsets;
    std::vector<std::uint8_t> direct_access_widths;
    std::vector<std::uint8_t> bytes;
};

struct GeneratedDataLayout {
    std::vector<GeneratedDataRegion> code_regions;
    std::vector<GeneratedDataRegion> named_static_regions;
    std::vector<GeneratedDataRegion> residual_regions;
};

struct TrackedSegmentState;

std::string trim_ascii(std::string text);
bool is_likely_ascii_text_region(const GeneratedDataRegion& region);
bool is_c_string_region(const GeneratedDataRegion& region);
std::string generated_region_family_name(const std::string& name);
bool family_prefers_text_storage(const std::string& family_name);
bool family_discourages_text_storage(const std::string& family_name);
bool family_prefers_u16_array_storage(const std::string& family_name);
bool family_prefers_u8_array_storage(const std::string& family_name);
std::optional<std::size_t> preferred_named_region_record_size(const std::string& family_name);
bool family_is_table_descriptor_record(const std::string& family_name);
void merge_named_region_record_patterns(GeneratedDataLayout& layout);
void promote_repeated_opaque_record_families(GeneratedDataLayout& layout);
void promote_family_specific_opaque_records(GeneratedDataLayout& layout);
bool is_probable_u16_array_region(const GeneratedDataRegion& region);
std::string escape_c_string_literal(const std::vector<std::uint8_t>& bytes);
bool is_printable_ascii_byte(std::uint8_t value);
bool is_zero_fill_region(const GeneratedDataRegion& region);
bool is_sparse_zero_region(const GeneratedDataRegion& region);
std::size_t detect_region_stride_hint(const GeneratedDataRegion& region);
std::string classify_generated_data_region(const GeneratedDataRegion& region);
std::string classify_generated_data_storage_kind(const GeneratedDataRegion& region);
std::vector<std::string> instruction_operand_texts(const DecodedInstruction& instruction);
bool is_simple_direct_memory_operand_text(const std::string& operand_text);
std::optional<std::string> parse_tracked_register_name(const std::string& operand_text);
std::optional<std::uint16_t> parse_immediate_hex16_operand(const std::string& operand_text);
std::size_t operand_text_width_hint_bytes(const std::string& operand_text);
std::size_t direct_memory_operand_width_bytes(const DecodedInstruction& instruction,
                                              const std::vector<std::string>& operands,
                                              std::size_t operand_index);
const GeneratedDataRegion* find_named_static_region_covering(const GeneratedDataLayout& data_layout,
                                                             std::uint16_t segment,
                                                             std::uint16_t offset,
                                                             std::size_t* byte_offset_out);

struct DirectMemoryOperandRef {
    std::string segment_name;
    std::uint16_t offset = 0;
};

std::optional<DirectMemoryOperandRef> parse_direct_memory_operand_text(const std::string& operand_text);
std::optional<DirectMemoryOperandRef> resolve_static_memory_operand_text(
    const std::string& operand_text,
    const std::map<std::string, std::uint16_t>& tracked_register_offsets,
    const std::optional<std::uint16_t>& default_data_segment,
    const std::uint16_t current_cs);
bool mnemonic_writes_first_operand(std::string_view mnemonic);
bool mnemonic_writes_any_memory_operand(std::string_view mnemonic);

const EmissionSymbolMap* g_emission_symbol_map = nullptr;
const GeneratedDataLayout* g_generated_data_layout = nullptr;

std::string hex4(const std::uint16_t value) {
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << value;
    return oss.str();
}

std::uint16_t parse_hex16_text(const std::string_view text) {
    const unsigned long value = std::stoul(std::string(text), nullptr, 16);
    if (value > 0xFFFFu) {
        throw std::runtime_error("hex value out of range in labels.txt");
    }
    return static_cast<std::uint16_t>(value);
}

std::string sanitize_identifier_component(const std::string_view text) {
    std::string sanitized;
    sanitized.reserve(text.size());
    bool previous_was_underscore = false;
    for (const unsigned char ch : text) {
        if ((ch >= 'a' && ch <= 'z') ||
            (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9')) {
            sanitized.push_back(static_cast<char>(ch));
            previous_was_underscore = false;
        } else if (!previous_was_underscore) {
            sanitized.push_back('_');
            previous_was_underscore = true;
        }
    }

    while (!sanitized.empty() && sanitized.front() == '_') {
        sanitized.erase(sanitized.begin());
    }
    while (!sanitized.empty() && sanitized.back() == '_') {
        sanitized.pop_back();
    }

    if (sanitized.empty() || (sanitized.front() >= '0' && sanitized.front() <= '9')) {
        sanitized.insert(0, "loc_");
    }
    return sanitized;
}

std::uint32_t location_key(const CodeLocation location) {
    return (static_cast<std::uint32_t>(location.cs) << 16u) | location.ip;
}

std::string location_symbol_base(const CodeLocation location) {
    if (g_emission_symbol_map != nullptr) {
        const auto it = g_emission_symbol_map->names_by_location.find(location_key(location));
        if (it != g_emission_symbol_map->names_by_location.end()) {
            return it->second;
        }
    }
    return hex4(location.cs) + "_" + hex4(location.ip);
}

std::string function_name(const CodeLocation location) {
    return "fn_" + location_symbol_base(location);
}

std::string block_label_name(const CodeLocation location) {
    return "block_" + location_symbol_base(location);
}

std::string calltable_name(const CodeLocation location) {
    return "generated_calltable_" + hex4(location.cs) + "_" + hex4(location.ip);
}

std::optional<std::pair<std::uint16_t, std::string>> proven_symbol_segment_for_field(
    const std::string& segment_field,
    const std::uint16_t current_cs,
    const TrackedSegmentState* tracked_state);
std::string generated_static_symbol_offset_constant_name(const GeneratedDataRegion& region);

std::string direct_offset_text(const std::string& segment_field,
                               const std::uint16_t current_cs,
                               const std::uint16_t offset) {
    if (g_emission_symbol_map != nullptr) {
        if (const auto segment = proven_symbol_segment_for_field(segment_field, current_cs, nullptr);
            segment.has_value()) {
            const auto it = g_emission_symbol_map->offset_constant_names_by_location.find(
                location_key(CodeLocation{segment->first, offset}));
            if (it != g_emission_symbol_map->offset_constant_names_by_location.end()) {
                return it->second;
            }
            if (g_generated_data_layout != nullptr) {
                std::size_t byte_offset = 0u;
                if (const GeneratedDataRegion* region =
                        find_named_static_region_covering(*g_generated_data_layout, segment->first, offset, &byte_offset);
                    region != nullptr) {
                    std::ostringstream oss;
                    oss << generated_static_symbol_offset_constant_name(*region);
                    if (byte_offset != 0u) {
                        oss << " + 0x" << hex4(static_cast<std::uint16_t>(byte_offset)) << "u";
                    }
                    return oss.str();
                }
            }
        }
    }
    return "0x" + hex4(offset);
}

std::string canonical_calltable_name(const std::map<std::uint32_t, std::uint32_t>& canonical_calltable_keys,
                                     const CodeLocation location) {
    const std::uint32_t site_key = location_key(location);
    if (const auto it = canonical_calltable_keys.find(site_key); it != canonical_calltable_keys.end()) {
        return calltable_name(CodeLocation{
            static_cast<std::uint16_t>((it->second >> 16u) & 0xFFFFu),
            static_cast<std::uint16_t>(it->second & 0xFFFFu),
        });
    }
    return calltable_name(location);
}

std::string interface_surface_array_name(const InterfaceSurfaceRecord& surface) {
    std::string sanitized;
    sanitized.reserve(surface.name.size());
    for (const char ch : surface.name) {
        if ((ch >= 'a' && ch <= 'z') ||
            (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9')) {
            sanitized.push_back(ch);
        } else {
            sanitized.push_back('_');
        }
    }
    return "generated_interface_surface_" + sanitized;
}

void emit_direct_call_return_setup(std::ostringstream& oss,
                                   const std::uint16_t return_cs,
                                   const std::string& return_ip_text,
                                   const bool far_call) {
    if (far_call) {
        oss << "    generated_push_u16(state, 0x" << hex4(return_cs) << "u);\n";
    }
    oss << "    generated_push_u16(state, " << return_ip_text << ");\n";
}

void emit_direct_call_resume(std::ostringstream& oss,
                             const std::uint16_t return_cs,
                             const std::string& return_ip_text) {
    oss << "    if (!generated_resume_after_direct_call(state, 0x" << hex4(return_cs)
        << "u, " << return_ip_text << ")) return;\n";
}

std::uint8_t instruction_opcode(const DecodedInstruction& instruction);

bool instruction_is_opcode(const DecodedInstruction& instruction, const std::uint8_t opcode) {
    return instruction_opcode(instruction) == opcode;
}

bool sequence_crosses_internal_entry(const std::vector<DecodedInstruction>& instructions,
                                     const std::size_t start_index,
                                     const std::size_t length,
                                     const std::set<std::uint32_t>& body_entry_keys,
                                     const std::set<std::uint32_t>& function_label_keys) {
    for (std::size_t index = start_index + 1u; index < start_index + length; ++index) {
        const CodeLocation location{instructions[index].cs, instructions[index].ip};
        const std::uint32_t key = location_key(location);
        if (body_entry_keys.contains(key) || function_label_keys.contains(key)) {
            return true;
        }
    }
    return false;
}

std::size_t match_push_regs_save_sequence(const std::vector<DecodedInstruction>& instructions,
                                          const std::size_t start_index,
                                          const std::size_t instruction_limit,
                                          const std::set<std::uint32_t>& body_entry_keys,
                                          const std::set<std::uint32_t>& function_label_keys) {
    static constexpr std::uint8_t kPattern[] = {
        0x50u, 0x53u, 0x51u, 0x52u, 0x55u, 0x56u, 0x57u, 0x06u, 0x1Eu,
    };
    constexpr std::size_t kPatternLength = sizeof(kPattern) / sizeof(kPattern[0]);
    if ((start_index + kPatternLength) > instruction_limit) {
        return 0u;
    }
    if (sequence_crosses_internal_entry(instructions, start_index, kPatternLength, body_entry_keys, function_label_keys)) {
        return 0u;
    }
    for (std::size_t i = 0; i < kPatternLength; ++i) {
        if (!instruction_is_opcode(instructions[start_index + i], kPattern[i])) {
            return 0u;
        }
    }
    return kPatternLength;
}

std::size_t match_pop_regs_restore_sequence(const std::vector<DecodedInstruction>& instructions,
                                            const std::size_t start_index,
                                            const std::size_t instruction_limit,
                                            const std::set<std::uint32_t>& body_entry_keys,
                                            const std::set<std::uint32_t>& function_label_keys) {
    static constexpr std::uint8_t kPattern[] = {
        0x1Fu, 0x07u, 0x5Fu, 0x5Eu, 0x5Du, 0x5Au, 0x59u, 0x5Bu, 0x58u,
    };
    constexpr std::size_t kPatternLength = sizeof(kPattern) / sizeof(kPattern[0]);
    if ((start_index + kPatternLength) > instruction_limit) {
        return 0u;
    }
    if (sequence_crosses_internal_entry(instructions, start_index, kPatternLength, body_entry_keys, function_label_keys)) {
        return 0u;
    }
    for (std::size_t i = 0; i < kPatternLength; ++i) {
        if (!instruction_is_opcode(instructions[start_index + i], kPattern[i])) {
            return 0u;
        }
    }
    return kPatternLength;
}

void emit_ip_advance(std::ostringstream& oss,
                     const std::string& next_ip_text,
                     const bool emit_ip_advance_line) {
    if (emit_ip_advance_line) {
        oss << "    state->ip = " << next_ip_text << ";\n";
    }
}

std::string register8_set_statement(const std::uint8_t index, const std::string& value_expression);

void emit_assign_add_u8(std::ostringstream& oss,
                        const std::string& target_lvalue,
                        const std::string& left_expression,
                        const std::string& right_expression) {
    oss << "    " << target_lvalue << " = generated_add_u8(state, "
        << left_expression << ", " << right_expression << ");\n";
}

void emit_assign_add_u16(std::ostringstream& oss,
                         const std::string& target_lvalue,
                         const std::string& left_expression,
                         const std::string& right_expression) {
    oss << "    " << target_lvalue << " = generated_add_u16(state, "
        << left_expression << ", " << right_expression << ");\n";
}

void emit_assign_sub_u8(std::ostringstream& oss,
                        const std::string& target_lvalue,
                        const std::string& left_expression,
                        const std::string& right_expression) {
    oss << "    " << target_lvalue << " = generated_sub_u8(state, "
        << left_expression << ", " << right_expression << ");\n";
}

void emit_assign_sub_u16(std::ostringstream& oss,
                         const std::string& target_lvalue,
                         const std::string& left_expression,
                         const std::string& right_expression) {
    oss << "    " << target_lvalue << " = generated_sub_u16(state, "
        << left_expression << ", " << right_expression << ");\n";
}

void emit_assign_logic_u8(std::ostringstream& oss,
                          const std::string& target_lvalue,
                          const std::string& value_expression) {
    oss << "    " << target_lvalue << " = generated_logic_u8(state, "
        << value_expression << ");\n";
}

void emit_assign_logic_u16(std::ostringstream& oss,
                           const std::string& target_lvalue,
                           const std::string& value_expression) {
    oss << "    " << target_lvalue << " = generated_logic_u16(state, "
        << value_expression << ");\n";
}

void emit_assign_add_u8_register(std::ostringstream& oss,
                                 const std::uint8_t index,
                                 const std::string& left_expression,
                                 const std::string& right_expression) {
    oss << "    {\n";
    oss << "        const unsigned char generated_new = generated_add_u8(state, "
        << left_expression << ", " << right_expression << ");\n";
    oss << register8_set_statement(index, "generated_new");
    oss << "    }\n";
}

void emit_assign_sub_u8_register(std::ostringstream& oss,
                                 const std::uint8_t index,
                                 const std::string& left_expression,
                                 const std::string& right_expression) {
    oss << "    {\n";
    oss << "        const unsigned char generated_new = generated_sub_u8(state, "
        << left_expression << ", " << right_expression << ");\n";
    oss << register8_set_statement(index, "generated_new");
    oss << "    }\n";
}

void emit_assign_logic_u8_register(std::ostringstream& oss,
                                   const std::uint8_t index,
                                   const std::string& value_expression) {
    oss << "    {\n";
    oss << "        const unsigned char generated_new = generated_logic_u8(state, "
        << value_expression << ");\n";
    oss << register8_set_statement(index, "generated_new");
    oss << "    }\n";
}

void emit_assign_inc_u8_register(std::ostringstream& oss,
                                 const std::uint8_t index,
                                 const std::string& old_expression) {
    oss << "    {\n";
    oss << "        const unsigned char generated_new = generated_inc_u8(state, "
        << old_expression << ");\n";
    oss << register8_set_statement(index, "generated_new");
    oss << "    }\n";
}

void emit_assign_dec_u8_register(std::ostringstream& oss,
                                 const std::uint8_t index,
                                 const std::string& old_expression) {
    oss << "    {\n";
    oss << "        const unsigned char generated_new = generated_dec_u8(state, "
        << old_expression << ");\n";
    oss << register8_set_statement(index, "generated_new");
    oss << "    }\n";
}

void emit_assign_adc_u8_register(std::ostringstream& oss,
                                 const std::uint8_t index,
                                 const std::string& left_expression,
                                 const std::string& right_expression) {
    oss << "    {\n";
    oss << "        const unsigned char generated_new = generated_adc_u8(state, "
        << left_expression << ", " << right_expression << ");\n";
    oss << register8_set_statement(index, "generated_new");
    oss << "    }\n";
}

void emit_assign_sbb_u8_register(std::ostringstream& oss,
                                 const std::uint8_t index,
                                 const std::string& left_expression,
                                 const std::string& right_expression) {
    oss << "    {\n";
    oss << "        const unsigned char generated_new = generated_sbb_u8(state, "
        << left_expression << ", " << right_expression << ");\n";
    oss << register8_set_statement(index, "generated_new");
    oss << "    }\n";
}

void emit_assign_inc_u16(std::ostringstream& oss,
                         const std::string& target_lvalue,
                         const std::string& old_expression) {
    oss << "    " << target_lvalue << " = generated_inc_u16(state, "
        << old_expression << ");\n";
}

void emit_assign_dec_u16(std::ostringstream& oss,
                         const std::string& target_lvalue,
                         const std::string& old_expression) {
    oss << "    " << target_lvalue << " = generated_dec_u16(state, "
        << old_expression << ");\n";
}

void emit_assign_adc_u8(std::ostringstream& oss,
                        const std::string& target_lvalue,
                        const std::string& left_expression,
                        const std::string& right_expression) {
    oss << "    " << target_lvalue << " = generated_adc_u8(state, "
        << left_expression << ", " << right_expression << ");\n";
}

void emit_assign_adc_u16(std::ostringstream& oss,
                         const std::string& target_lvalue,
                         const std::string& left_expression,
                         const std::string& right_expression) {
    oss << "    " << target_lvalue << " = generated_adc_u16(state, "
        << left_expression << ", " << right_expression << ");\n";
}

void emit_assign_sbb_u8(std::ostringstream& oss,
                        const std::string& target_lvalue,
                        const std::string& left_expression,
                        const std::string& right_expression) {
    oss << "    " << target_lvalue << " = generated_sbb_u8(state, "
        << left_expression << ", " << right_expression << ");\n";
}

void emit_assign_sbb_u16(std::ostringstream& oss,
                         const std::string& target_lvalue,
                         const std::string& left_expression,
                         const std::string& right_expression) {
    oss << "    " << target_lvalue << " = generated_sbb_u16(state, "
        << left_expression << ", " << right_expression << ");\n";
}

void emit_assign_shift_rotate_u8_register(std::ostringstream& oss,
                                          const std::uint8_t index,
                                          const std::uint8_t reg_field,
                                          const std::string& value_expression,
                                          const std::string& steps_expression) {
    oss << "    {\n";
    oss << "        const unsigned char generated_new = generated_shift_rotate_u8(state, "
        << static_cast<unsigned>(reg_field) << "u, " << value_expression << ", "
        << steps_expression << ");\n";
    oss << register8_set_statement(index, "generated_new");
    oss << "    }\n";
}

void emit_assign_shift_rotate_u16(std::ostringstream& oss,
                                  const std::string& target_lvalue,
                                  const std::uint8_t reg_field,
                                  const std::string& value_expression,
                                  const std::string& steps_expression) {
    oss << "    " << target_lvalue << " = generated_shift_rotate_u16(state, "
        << static_cast<unsigned>(reg_field) << "u, " << value_expression << ", "
        << steps_expression << ");\n";
}

bool same_location(const CodeLocation left, const CodeLocation right) {
    return left.cs == right.cs && left.ip == right.ip;
}

std::set<std::uint32_t> build_location_key_set(const std::vector<CodeLocation>& locations) {
    std::set<std::uint32_t> keys;
    for (const CodeLocation location : locations) {
        keys.insert(location_key(location));
    }
    return keys;
}

CodeLocation key_to_location(const std::uint32_t key) {
    return CodeLocation{
        static_cast<std::uint16_t>((key >> 16u) & 0xFFFFu),
        static_cast<std::uint16_t>(key & 0xFFFFu),
    };
}

std::string load_template_text(const std::string_view relative_path) {
    namespace fs = std::filesystem;

    fs::path probe = fs::current_path();
    for (;;) {
        const fs::path candidate = probe / fs::path(relative_path);
        if (fs::exists(candidate)) {
            std::ifstream input(candidate, std::ios::binary);
            if (!input) {
                throw std::runtime_error("failed to open template file: " + candidate.string());
            }
            std::ostringstream buffer;
            buffer << input.rdbuf();
            return buffer.str();
        }
        if (probe == probe.root_path() || probe.empty()) {
            break;
        }
        probe = probe.parent_path();
    }

    throw std::runtime_error("failed to locate template file: " + std::string(relative_path));
}

std::size_t instruction_prefix_length(const DecodedInstruction& instruction) {
    std::size_t offset = 0;
    while (offset < instruction.bytes.size()) {
        switch (instruction.bytes[offset]) {
        case 0x26u:
        case 0x2Eu:
        case 0x36u:
        case 0x3Eu:
        case 0xF2u:
        case 0xF3u:
            ++offset;
            break;
        default:
            return offset;
        }
    }
    return offset;
}

bool instruction_has_prefix(const DecodedInstruction& instruction, const std::uint8_t prefix) {
    const std::size_t prefix_length = instruction_prefix_length(instruction);
    for (std::size_t index = 0; index < prefix_length; ++index) {
        if (instruction.bytes[index] == prefix) {
            return true;
        }
    }
    return false;
}

std::uint8_t instruction_opcode(const DecodedInstruction& instruction) {
    const std::size_t offset = instruction_prefix_length(instruction);
    if (offset >= instruction.bytes.size()) {
        return 0u;
    }
    return instruction.bytes[offset];
}

std::uint16_t instruction_u16(const DecodedInstruction& instruction, const std::size_t offset) {
    return static_cast<std::uint16_t>(instruction.bytes.at(offset)) |
           static_cast<std::uint16_t>(instruction.bytes.at(offset + 1u) << 8u);
}

std::string register16_field_name(const std::uint8_t index) {
    static const char* kNames[8] = {"ax", "cx", "dx", "bx", "sp", "bp", "si", "di"};
    return std::string("state->") + kNames[index & 7u];
}

std::optional<std::uint8_t> register16_index_from_text(const std::string& text) {
    static const char* kNames[8] = {"ax", "cx", "dx", "bx", "sp", "bp", "si", "di"};
    for (std::uint8_t i = 0; i < 8u; ++i) {
        if (text == kNames[i]) {
            return i;
        }
    }
    return std::nullopt;
}

bool site_uses_generated_calltable(const IndirectSiteRecord& site) {
    return site.kind == EdgeKind::Call &&
           !site.is_far &&
           !site.dispatch_entries.empty() &&
           (site.dispatch_kind == IndirectDispatchKind::CurrentCsWordTable ||
            site.dispatch_kind == IndirectDispatchKind::CurrentCsPairTable);
}

EmissionSymbolMap load_emission_symbol_map(const MzImage& image,
                                           const std::optional<std::filesystem::path>& labels_path) {
    EmissionSymbolMap symbol_map{};
    if (!labels_path.has_value() || labels_path->empty() || !std::filesystem::exists(*labels_path)) {
        return symbol_map;
    }

    std::ifstream input(*labels_path);
    if (!input) {
        throw std::runtime_error("failed to open labels file: " + labels_path->string());
    }

    std::map<std::string, std::uint16_t> segments_by_name;
    std::vector<std::pair<CodeLocation, std::string>> pending_labels;
    enum class Section {
        None,
        Segments,
        Labels,
    };
    Section section = Section::None;

    std::string line;
    while (std::getline(input, line)) {
        if (line == "[SEGMENTS]") {
            section = Section::Segments;
            continue;
        }
        if (line == "[LABELS]") {
            section = Section::Labels;
            continue;
        }
        if (line.empty()) {
            continue;
        }

        if (section == Section::Segments) {
            if (!line.starts_with("SEG ")) {
                continue;
            }
            const std::size_t name_begin = 4u;
            const std::size_t name_end = line.find(' ', name_begin);
            const std::size_t sel_pos = line.find("sel=");
            if (name_end == std::string::npos || sel_pos == std::string::npos) {
                continue;
            }
            const std::string segment_name = line.substr(name_begin, name_end - name_begin);
            std::size_t sel_end = sel_pos + 4u;
            while (sel_end < line.size()) {
                const char ch = line[sel_end];
                if (!((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f'))) {
                    break;
                }
                ++sel_end;
            }
            segments_by_name[segment_name] = parse_hex16_text(
                std::string_view(line).substr(sel_pos + 4u, sel_end - (sel_pos + 4u)));
            continue;
        }

        if (section == Section::Labels) {
            if (!line.starts_with("PC ")) {
                continue;
            }
            const std::size_t location_begin = 3u;
            const std::size_t location_end = line.find(' ', location_begin);
            if (location_end == std::string::npos || location_end + 1u >= line.size()) {
                continue;
            }

            const std::string_view location_token(line.c_str() + location_begin, location_end - location_begin);
            const std::size_t colon = location_token.find(':');
            if (colon == std::string::npos) {
                continue;
            }

            const std::string segment_name(location_token.substr(0, colon));
            const auto segment_it = segments_by_name.find(segment_name);
            if (segment_it == segments_by_name.end()) {
                continue;
            }

            const std::string_view offset_text = location_token.substr(colon + 1u);
            const std::string raw_name = line.substr(location_end + 1u);
            pending_labels.push_back({
                CodeLocation{segment_it->second, parse_hex16_text(offset_text)},
                raw_name,
            });
        }
    }

    std::uint16_t ida_base_segment = 0x1000u;
    if (const auto it = segments_by_name.find("seg000"); it != segments_by_name.end()) {
        ida_base_segment = it->second;
    }
    const std::int32_t segment_delta =
        static_cast<std::int32_t>(image.layout.load_segment()) - static_cast<std::int32_t>(ida_base_segment);

    std::set<std::string> used_names;
    for (const auto& [ida_location, raw_name] : pending_labels) {
        const std::int32_t runtime_cs_signed = static_cast<std::int32_t>(ida_location.cs) + segment_delta;
        if (runtime_cs_signed < 0 || runtime_cs_signed > 0xFFFF) {
            continue;
        }

        const CodeLocation runtime_location{
            static_cast<std::uint16_t>(runtime_cs_signed),
            ida_location.ip,
        };
        const std::uint32_t key = location_key(runtime_location);
        if (symbol_map.names_by_location.contains(key)) {
            continue;
        }

        const std::string base_name = sanitize_identifier_component(raw_name);
        std::string unique_name = base_name;
        if (used_names.contains(unique_name)) {
            unique_name += "_" + hex4(runtime_location.cs) + "_" + hex4(runtime_location.ip);
        }
        while (used_names.contains(unique_name)) {
            unique_name.push_back('_');
        }
        used_names.insert(unique_name);
        symbol_map.names_by_location.emplace(key, std::move(unique_name));
    }

    if (const auto it = segments_by_name.find("seg002"); it != segments_by_name.end()) {
        const std::int32_t runtime_segment =
            static_cast<std::int32_t>(it->second) + segment_delta;
        if (runtime_segment >= 0 && runtime_segment <= 0xFFFF) {
            symbol_map.default_data_segment = static_cast<std::uint16_t>(runtime_segment);
        }
    }

    std::set<std::string> used_offset_constant_names;
    for (const auto& [key, name] : symbol_map.names_by_location) {
        std::string constant_name = "off_" + name;
        while (used_offset_constant_names.contains(constant_name)) {
            constant_name.push_back('_');
        }
        used_offset_constant_names.insert(constant_name);
        symbol_map.offset_constant_names_by_location.emplace(key, constant_name);
        symbol_map.ordered_offset_constants.emplace_back(key, std::move(constant_name));
    }
    std::sort(
        symbol_map.ordered_offset_constants.begin(),
        symbol_map.ordered_offset_constants.end(),
        [](const auto& left, const auto& right) { return left.first < right.first; });

    return symbol_map;
}

class ScopedEmissionSymbolMap {
public:
    explicit ScopedEmissionSymbolMap(const EmissionSymbolMap& symbol_map)
        : previous_(g_emission_symbol_map) {
        g_emission_symbol_map = &symbol_map;
    }

    ~ScopedEmissionSymbolMap() {
        g_emission_symbol_map = previous_;
    }

    ScopedEmissionSymbolMap(const ScopedEmissionSymbolMap&) = delete;
    ScopedEmissionSymbolMap& operator=(const ScopedEmissionSymbolMap&) = delete;

private:
    const EmissionSymbolMap* previous_ = nullptr;
};

class ScopedGeneratedDataLayout {
public:
    explicit ScopedGeneratedDataLayout(const GeneratedDataLayout& data_layout)
        : previous_(g_generated_data_layout) {
        g_generated_data_layout = &data_layout;
    }

    ~ScopedGeneratedDataLayout() {
        g_generated_data_layout = previous_;
    }

    ScopedGeneratedDataLayout(const ScopedGeneratedDataLayout&) = delete;
    ScopedGeneratedDataLayout& operator=(const ScopedGeneratedDataLayout&) = delete;

private:
    const GeneratedDataLayout* previous_ = nullptr;
};

bool physical_in_loaded_module(const MzImage& image, const std::uint32_t physical) {
    return physical >= image.load_module_physical &&
           physical < image.load_module_physical + image.relocated_load_module_bytes.size();
}

std::size_t module_index_from_physical(const MzImage& image, const std::uint32_t physical) {
    return static_cast<std::size_t>(physical - image.load_module_physical);
}

CodeLocation add_location_linear_offset(const CodeLocation base, const std::size_t delta) {
    const std::uint32_t linear = real_mode_phys(base.cs, base.ip) + static_cast<std::uint32_t>(delta);
    return CodeLocation{
        static_cast<std::uint16_t>(linear >> 4u),
        static_cast<std::uint16_t>(linear & 0x000Fu),
    };
}

GeneratedDataLayout build_generated_data_layout(const MzImage& image,
                                                const CfgSnapshot& snapshot,
                                                const EmissionSymbolMap& symbol_map) {
    GeneratedDataLayout layout{};
    const std::size_t module_size = image.relocated_load_module_bytes.size();
    if (module_size == 0u) {
        return layout;
    }

    std::vector<unsigned char> code_mask(module_size, 0u);
    for (const BlockRecord& block : snapshot.blocks) {
        for (const DecodedInstruction& instruction : block.preview.instructions) {
            if (!physical_in_loaded_module(image, instruction.physical)) {
                continue;
            }
            const std::size_t start_index = module_index_from_physical(image, instruction.physical);
            const std::size_t end_index =
                std::min(module_size, start_index + instruction.length);
            for (std::size_t index = start_index; index < end_index; ++index) {
                code_mask[index] = 1u;
            }
        }
    }

    std::vector<std::size_t> next_code_index(module_size + 1u, module_size);
    for (std::size_t index = module_size; index-- > 0u;) {
        next_code_index[index] = code_mask[index] ? index : next_code_index[index + 1u];
    }

    struct NamedAnchor {
        std::uint32_t physical = 0;
        CodeLocation location{};
        std::string name;
        bool preferred_data_segment = false;
        bool synthetic = false;
        std::map<std::uint32_t, std::size_t> accessor_root_counts;
    };

    std::map<std::uint32_t, NamedAnchor> named_anchors_by_physical;
    for (const auto& [key, name] : symbol_map.names_by_location) {
        const CodeLocation location = key_to_location(key);
        const std::uint32_t physical = real_mode_phys(location.cs, location.ip);
        if (!physical_in_loaded_module(image, physical)) {
            continue;
        }
        const std::size_t start_index = module_index_from_physical(image, physical);
        if (code_mask[start_index] != 0u) {
            continue;
        }

        NamedAnchor anchor{};
        anchor.physical = physical;
        anchor.location = location;
        anchor.name = name;
        anchor.preferred_data_segment =
            symbol_map.default_data_segment.has_value() &&
            *symbol_map.default_data_segment == location.cs;

        auto it = named_anchors_by_physical.find(physical);
        if (it == named_anchors_by_physical.end()) {
            named_anchors_by_physical.emplace(physical, std::move(anchor));
            continue;
        }
        if (!it->second.preferred_data_segment && anchor.preferred_data_segment) {
            it->second = std::move(anchor);
        }
    }

    std::map<std::uint32_t, CodeLocation> primary_owner_by_block_start;
    for (const BlockOwnershipRecord& ownership : snapshot.block_ownerships) {
        if (ownership.owners.empty()) {
            continue;
        }
        primary_owner_by_block_start.emplace(location_key(ownership.block), ownership.owners.front());
    }

    const auto block_primary_owner = [&](const BlockRecord& block) -> std::optional<CodeLocation> {
        if (const auto it = primary_owner_by_block_start.find(location_key(block.start));
            it != primary_owner_by_block_start.end()) {
            return it->second;
        }
        return std::nullopt;
    };

    const auto note_anchor_accessor_root = [&](NamedAnchor& anchor,
                                               const std::optional<CodeLocation>& accessor_root) {
        if (!anchor.synthetic || !accessor_root.has_value()) {
            return;
        }
        ++anchor.accessor_root_counts[location_key(*accessor_root)];
    };

    const auto note_direct_named_anchor = [&](const std::uint16_t segment,
                                              const std::uint16_t offset,
                                              const bool prefer_data_segment,
                                              const std::optional<CodeLocation>& accessor_root) {
        const std::uint32_t physical = real_mode_phys(segment, offset);
        if (!physical_in_loaded_module(image, physical)) {
            return;
        }
        const std::size_t module_index = module_index_from_physical(image, physical);
        if (module_index >= module_size || code_mask[module_index] != 0u) {
            return;
        }
        if (named_anchors_by_physical.contains(physical)) {
            auto it = named_anchors_by_physical.find(physical);
            note_anchor_accessor_root(it->second, accessor_root);
            return;
        }
        NamedAnchor anchor{};
        anchor.physical = physical;
        anchor.location = CodeLocation{segment, offset};
        anchor.name = "g_static_seg" + hex4(segment) + "_off_" + hex4(offset);
        anchor.preferred_data_segment = prefer_data_segment;
        anchor.synthetic = true;
        note_anchor_accessor_root(anchor, accessor_root);
        named_anchors_by_physical.emplace(physical, std::move(anchor));
    };

    std::set<std::size_t> data_split_indexes;
    std::vector<unsigned char> protected_split_mask(module_size + 1u, 0u);
    const auto note_direct_data_access = [&](const std::size_t module_index, const std::size_t width) {
        if (module_index >= module_size) {
            return;
        }
        const std::size_t clamped_width = std::max<std::size_t>(1u, std::min(width, module_size - module_index));
        data_split_indexes.insert(module_index);
        if (module_index + clamped_width < module_size) {
            data_split_indexes.insert(module_index + clamped_width);
        }
        for (std::size_t protected_index = module_index + 1u;
             protected_index < module_index + clamped_width && protected_index < protected_split_mask.size();
             ++protected_index) {
            protected_split_mask[protected_index] = 1u;
        }
    };
    for (const RelocationEntry& relocation : image.relocations) {
        const std::size_t fixup_index =
            static_cast<std::size_t>(relocation.segment) * 16u + static_cast<std::size_t>(relocation.offset);
        if (fixup_index < module_size) {
            data_split_indexes.insert(fixup_index);
        }
        if (fixup_index + 2u < module_size) {
            data_split_indexes.insert(fixup_index + 2u);
        }
    }

    const auto direct_operand_module_index = [&](const DirectMemoryOperandRef& operand,
                                                 const std::uint16_t current_cs) -> std::optional<std::size_t> {
        std::optional<std::uint16_t> segment;
        if (operand.segment_name == "cs") {
            segment = current_cs;
        } else if (operand.segment_name == "ds" && symbol_map.default_data_segment.has_value()) {
            segment = *symbol_map.default_data_segment;
        } else {
            return std::nullopt;
        }
        const std::uint32_t physical = real_mode_phys(*segment, operand.offset);
        if (!physical_in_loaded_module(image, physical)) {
            return std::nullopt;
        }
        return module_index_from_physical(image, physical);
    };

    for (const BlockRecord& block : snapshot.blocks) {
        const std::optional<CodeLocation> accessor_root = block_primary_owner(block);
        for (const DecodedInstruction& instruction : block.preview.instructions) {
            const std::vector<std::string> operands = instruction_operand_texts(instruction);
            for (std::size_t operand_index = 0u; operand_index < operands.size(); ++operand_index) {
                const std::string& operand_text = operands[operand_index];
                const auto operand = parse_direct_memory_operand_text(operand_text);
                if (!operand.has_value()) {
                    continue;
                }
                const auto module_index = direct_operand_module_index(*operand, instruction.cs);
                if (module_index.has_value()) {
                    note_direct_data_access(*module_index,
                                            direct_memory_operand_width_bytes(instruction, operands, operand_index));
                    if (operand->segment_name == "cs") {
                        note_direct_named_anchor(instruction.cs, operand->offset, false, accessor_root);
                    } else if (operand->segment_name == "ds" && symbol_map.default_data_segment.has_value()) {
                        note_direct_named_anchor(*symbol_map.default_data_segment, operand->offset, true, accessor_root);
                    }
                }
            }
        }
    }

    for (const BlockRecord& block : snapshot.blocks) {
        const std::optional<CodeLocation> accessor_root = block_primary_owner(block);
        std::map<std::string, std::uint16_t> tracked_register_offsets;
        for (const DecodedInstruction& instruction : block.preview.instructions) {
            const std::size_t first_space = instruction.text.find(' ');
            const std::string_view mnemonic =
                first_space == std::string::npos
                    ? std::string_view(instruction.text)
                    : std::string_view(instruction.text).substr(0u, first_space);
            const std::vector<std::string> operands = instruction_operand_texts(instruction);

            for (std::size_t operand_index = 0u; operand_index < operands.size(); ++operand_index) {
                const std::string& operand_text = operands[operand_index];
                const auto operand = resolve_static_memory_operand_text(
                    operand_text, tracked_register_offsets, symbol_map.default_data_segment, instruction.cs);
                if (!operand.has_value()) {
                    continue;
                }
                const auto module_index = direct_operand_module_index(*operand, instruction.cs);
                if (module_index.has_value()) {
                    note_direct_data_access(*module_index,
                                            direct_memory_operand_width_bytes(instruction, operands, operand_index));
                    if (operand->segment_name == "cs") {
                        note_direct_named_anchor(instruction.cs, operand->offset, false, accessor_root);
                    } else if (operand->segment_name == "ds" && symbol_map.default_data_segment.has_value()) {
                        note_direct_named_anchor(*symbol_map.default_data_segment, operand->offset, true, accessor_root);
                    }
                }
            }

            if (!operands.empty()) {
                if (const auto target_register = parse_tracked_register_name(operands[0u]); target_register.has_value()) {
                    bool handled = false;
                    if (mnemonic == "mov" && operands.size() >= 2u) {
                        if (const auto immediate = parse_immediate_hex16_operand(operands[1u]); immediate.has_value()) {
                            tracked_register_offsets[*target_register] = *immediate;
                            handled = true;
                        }
                    } else if (mnemonic == "lea" && operands.size() >= 2u) {
                        if (const auto direct = parse_direct_memory_operand_text(operands[1u]); direct.has_value()) {
                            tracked_register_offsets[*target_register] = direct->offset;
                            handled = true;
                        }
                    } else if ((mnemonic == "xor" || mnemonic == "sub") && operands.size() >= 2u) {
                        const auto source_register = parse_tracked_register_name(operands[1u]);
                        if (source_register.has_value() && *source_register == *target_register) {
                            tracked_register_offsets[*target_register] = 0u;
                            handled = true;
                        }
                    }
                    if (!handled && mnemonic_writes_first_operand(mnemonic)) {
                        tracked_register_offsets.erase(*target_register);
                    }
                }
            }
        }
    }

    std::vector<NamedAnchor> named_anchors;
    named_anchors.reserve(named_anchors_by_physical.size());
    for (auto& [physical, anchor] : named_anchors_by_physical) {
        (void)physical;
        named_anchors.push_back(std::move(anchor));
    }

    const auto synthetic_anchor_base_name = [&](const CodeLocation root) {
        std::string base;
        if (const auto it = symbol_map.names_by_location.find(location_key(root));
            it != symbol_map.names_by_location.end()) {
            base = it->second;
        } else {
            base = "root_" + hex4(root.cs) + "_" + hex4(root.ip);
        }
        if (base.rfind("fn_", 0u) == 0u) {
            base.erase(0u, 3u);
        }
        if (base.rfind("block_", 0u) == 0u) {
            base.erase(0u, 6u);
        }
        return sanitize_identifier_component(base);
    };

    std::set<std::string> used_anchor_names;
    for (const NamedAnchor& anchor : named_anchors) {
        used_anchor_names.insert(anchor.name);
    }
    for (NamedAnchor& anchor : named_anchors) {
        if (!anchor.synthetic || anchor.accessor_root_counts.empty()) {
            continue;
        }
        std::uint32_t dominant_root_key = 0u;
        std::size_t dominant_count = 0u;
        std::size_t total_count = 0u;
        for (const auto& [root_key, count] : anchor.accessor_root_counts) {
            total_count += count;
            if (count > dominant_count) {
                dominant_count = count;
                dominant_root_key = root_key;
            }
        }
        if (dominant_count < 2u || dominant_count * 100u < total_count * 70u) {
            continue;
        }
        const CodeLocation dominant_root = key_to_location(dominant_root_key);
        std::string candidate_name =
            "g_" + synthetic_anchor_base_name(dominant_root) + "_seg" + hex4(anchor.location.cs) +
            "_off_" + hex4(anchor.location.ip);
        if (candidate_name == anchor.name) {
            continue;
        }
        if (used_anchor_names.contains(candidate_name)) {
            continue;
        }
        used_anchor_names.erase(anchor.name);
        anchor.name = std::move(candidate_name);
        used_anchor_names.insert(anchor.name);
    }

    for (std::size_t scan_index = 0u; scan_index < module_size;) {
        if (code_mask[scan_index] != 0u || !is_printable_ascii_byte(image.relocated_load_module_bytes[scan_index])) {
            ++scan_index;
            continue;
        }
        const std::size_t run_start = scan_index;
        while (scan_index < module_size &&
               code_mask[scan_index] == 0u &&
               is_printable_ascii_byte(image.relocated_load_module_bytes[scan_index])) {
            ++scan_index;
        }
        if (scan_index < module_size &&
            code_mask[scan_index] == 0u &&
            image.relocated_load_module_bytes[scan_index] == 0u &&
            scan_index - run_start >= 4u) {
            data_split_indexes.insert(run_start);
            if (scan_index + 1u < module_size) {
                data_split_indexes.insert(scan_index + 1u);
            }
            ++scan_index;
        }
    }

    for (std::size_t scan_index = 0u; scan_index < module_size;) {
        if (code_mask[scan_index] != 0u || image.relocated_load_module_bytes[scan_index] != 0u) {
            ++scan_index;
            continue;
        }
        const std::size_t run_start = scan_index;
        while (scan_index < module_size &&
               code_mask[scan_index] == 0u &&
               image.relocated_load_module_bytes[scan_index] == 0u) {
            ++scan_index;
        }
        constexpr std::size_t kLongZeroRunThreshold = 32u;
        if (scan_index - run_start >= kLongZeroRunThreshold) {
            data_split_indexes.insert(run_start);
            if (scan_index < module_size) {
                data_split_indexes.insert(scan_index);
            }
        }
    }

    const auto collect_chunk_starts = [&](const std::size_t start_index,
                                          const std::size_t end_index) {
        std::vector<std::size_t> interior_splits;
        auto split_it = data_split_indexes.upper_bound(start_index);
        while (split_it != data_split_indexes.end() && *split_it < end_index) {
            if (*split_it < protected_split_mask.size() && protected_split_mask[*split_it] != 0u) {
                ++split_it;
                continue;
            }
            interior_splits.push_back(*split_it);
            ++split_it;
        }

        std::vector<std::size_t> chunk_starts;
        chunk_starts.push_back(start_index);
        if (!interior_splits.empty()) {
            constexpr std::size_t kMaxInteriorSplitsPerRegion = 128u;
            std::size_t min_gap = 1u;
            std::vector<std::size_t> filtered_splits;
            for (;;) {
                filtered_splits.clear();
                std::size_t last_kept = start_index;
                for (const std::size_t candidate : interior_splits) {
                    if (candidate - last_kept >= min_gap) {
                        filtered_splits.push_back(candidate);
                        last_kept = candidate;
                    }
                }
                if (filtered_splits.size() <= kMaxInteriorSplitsPerRegion || min_gap >= 1024u) {
                    break;
                }
                min_gap *= 2u;
            }
            chunk_starts.insert(chunk_starts.end(), filtered_splits.begin(), filtered_splits.end());
        }
        return chunk_starts;
    };

    std::vector<unsigned char> named_mask(module_size, 0u);
    for (std::size_t anchor_index = 0u; anchor_index < named_anchors.size(); ++anchor_index) {
        const NamedAnchor& anchor = named_anchors[anchor_index];
        const std::size_t start_index = module_index_from_physical(image, anchor.physical);
        if (named_mask[start_index] != 0u) {
            continue;
        }

        std::size_t end_index = module_size;
        if (anchor_index + 1u < named_anchors.size()) {
            end_index = module_index_from_physical(image, named_anchors[anchor_index + 1u].physical);
        }
        end_index = std::min(end_index, next_code_index[start_index]);
        if (end_index <= start_index) {
            continue;
        }

        while (end_index > start_index && named_mask[end_index - 1u] != 0u) {
            --end_index;
        }
        std::size_t first_covered = end_index;
        for (std::size_t index = start_index; index < end_index; ++index) {
            if (named_mask[index] != 0u) {
                first_covered = index;
                break;
            }
        }
        end_index = std::min(end_index, first_covered);
        if (end_index <= start_index) {
            continue;
        }

        std::vector<std::size_t> chunk_starts = collect_chunk_starts(start_index, end_index);
        if (const auto record_size = preferred_named_region_record_size(
                generated_region_family_name(anchor.name));
            record_size.has_value() && *record_size > 0u) {
            chunk_starts.clear();
            for (std::size_t chunk_start = start_index; chunk_start < end_index; chunk_start += *record_size) {
                chunk_starts.push_back(chunk_start);
            }
            if (chunk_starts.empty()) {
                chunk_starts.push_back(start_index);
            }
        }

        for (std::size_t chunk_index = 0u; chunk_index < chunk_starts.size(); ++chunk_index) {
            const std::size_t chunk_start = chunk_starts[chunk_index];
            const std::size_t chunk_end =
                (chunk_index + 1u < chunk_starts.size()) ? chunk_starts[chunk_index + 1u] : end_index;
            if (chunk_end <= chunk_start) {
                continue;
            }

            GeneratedDataRegion region{};
            region.kind = GeneratedDataRegion::Kind::NamedStatic;
            region.physical = image.load_module_physical + static_cast<std::uint32_t>(chunk_start);
            region.location = add_location_linear_offset(anchor.location, chunk_start - start_index);
            region.name = (chunk_start == start_index)
                ? anchor.name
                : anchor.name + "_off_" + hex4(static_cast<std::uint16_t>(chunk_start - start_index));
            region.bytes.assign(image.relocated_load_module_bytes.begin() + static_cast<std::ptrdiff_t>(chunk_start),
                                image.relocated_load_module_bytes.begin() + static_cast<std::ptrdiff_t>(chunk_end));
            layout.named_static_regions.push_back(std::move(region));
        }

        for (std::size_t covered_index = start_index; covered_index < end_index; ++covered_index) {
            named_mask[covered_index] = 1u;
        }
    }

    std::size_t index = 0u;
    while (index < module_size) {
        if (named_mask[index] != 0u) {
            ++index;
            continue;
        }

        const bool is_code_region = code_mask[index] != 0u;
        const std::size_t start_index = index;
        while (index < module_size &&
               named_mask[index] == 0u &&
               (code_mask[index] != 0u) == is_code_region) {
            ++index;
        }

        if (is_code_region) {
            GeneratedDataRegion region{};
            region.kind = GeneratedDataRegion::Kind::Code;
            region.physical = image.load_module_physical + static_cast<std::uint32_t>(start_index);
            region.bytes.assign(image.relocated_load_module_bytes.begin() + static_cast<std::ptrdiff_t>(start_index),
                                image.relocated_load_module_bytes.begin() + static_cast<std::ptrdiff_t>(index));
            layout.code_regions.push_back(std::move(region));
            continue;
        }

        const std::vector<std::size_t> chunk_starts = collect_chunk_starts(start_index, index);
        for (std::size_t chunk_index = 0u; chunk_index < chunk_starts.size(); ++chunk_index) {
            const std::size_t chunk_start = chunk_starts[chunk_index];
            const std::size_t chunk_end =
                (chunk_index + 1u < chunk_starts.size()) ? chunk_starts[chunk_index + 1u] : index;
            if (chunk_end <= chunk_start) {
                continue;
            }

            GeneratedDataRegion region{};
            region.kind = GeneratedDataRegion::Kind::Residual;
            region.physical = image.load_module_physical + static_cast<std::uint32_t>(chunk_start);
            region.bytes.assign(image.relocated_load_module_bytes.begin() + static_cast<std::ptrdiff_t>(chunk_start),
                                image.relocated_load_module_bytes.begin() + static_cast<std::ptrdiff_t>(chunk_end));
            layout.residual_regions.push_back(std::move(region));
        }
    }

    std::vector<std::pair<std::uint32_t, std::size_t>> named_region_starts;
    named_region_starts.reserve(layout.named_static_regions.size());
    for (std::size_t region_index = 0u; region_index < layout.named_static_regions.size(); ++region_index) {
        named_region_starts.emplace_back(layout.named_static_regions[region_index].physical, region_index);
    }
    std::sort(named_region_starts.begin(), named_region_starts.end());
    std::vector<std::pair<std::uint32_t, std::size_t>> residual_region_starts;
    residual_region_starts.reserve(layout.residual_regions.size());
    for (std::size_t region_index = 0u; region_index < layout.residual_regions.size(); ++region_index) {
        residual_region_starts.emplace_back(layout.residual_regions[region_index].physical, region_index);
    }
    std::sort(residual_region_starts.begin(), residual_region_starts.end());

    const auto find_named_region_index = [&](const std::uint32_t physical) -> std::optional<std::size_t> {
        auto it = std::upper_bound(named_region_starts.begin(),
                                   named_region_starts.end(),
                                   std::pair<std::uint32_t, std::size_t>{physical, std::numeric_limits<std::size_t>::max()});
        if (it == named_region_starts.begin()) {
            return std::nullopt;
        }
        --it;
        const GeneratedDataRegion& region = layout.named_static_regions[it->second];
        const std::uint32_t region_end = region.physical + static_cast<std::uint32_t>(region.bytes.size());
        if (physical >= region.physical && physical < region_end) {
            return it->second;
        }
        return std::nullopt;
    };

    const auto find_residual_region_index = [&](const std::uint32_t physical) -> std::optional<std::size_t> {
        auto it = std::upper_bound(residual_region_starts.begin(),
                                   residual_region_starts.end(),
                                   std::pair<std::uint32_t, std::size_t>{physical, std::numeric_limits<std::size_t>::max()});
        if (it == residual_region_starts.begin()) {
            return std::nullopt;
        }
        --it;
        const GeneratedDataRegion& region = layout.residual_regions[it->second];
        const std::uint32_t region_end = region.physical + static_cast<std::uint32_t>(region.bytes.size());
        if (physical >= region.physical && physical < region_end) {
            return it->second;
        }
        return std::nullopt;
    };

    for (const RelocationEntry& relocation : image.relocations) {
        const std::uint32_t physical =
            image.load_module_physical +
            static_cast<std::uint32_t>(static_cast<std::size_t>(relocation.segment) * 16u +
                                       static_cast<std::size_t>(relocation.offset));
        const auto region_index = find_named_region_index(physical);
        if (region_index.has_value()) {
            ++layout.named_static_regions[*region_index].relocation_count;
            continue;
        }
        const auto residual_index = find_residual_region_index(physical);
        if (residual_index.has_value()) {
            ++layout.residual_regions[*residual_index].relocation_count;
        }
    }

    const auto resolve_operand_segment = [&](const DecodedInstruction& instruction,
                                             const DirectMemoryOperandRef& operand) -> std::optional<std::uint16_t> {
        if (operand.segment_name == "cs") {
            return instruction.cs;
        }
        if (operand.segment_name == "ds") {
            return symbol_map.default_data_segment;
        }
        return std::nullopt;
    };

    const auto mark_named_region_writable = [&](const std::uint32_t physical) {
        const auto region_index = find_named_region_index(physical);
        if (region_index.has_value()) {
            layout.named_static_regions[*region_index].writable = true;
            return;
        }
        const auto residual_index = find_residual_region_index(physical);
        if (residual_index.has_value()) {
            layout.residual_regions[*residual_index].writable = true;
        }
    };

    const auto note_named_region_access = [&](const std::uint32_t physical, const std::size_t width) {
        const auto region_index = find_named_region_index(physical);
        if (region_index.has_value()) {
            GeneratedDataRegion& region = layout.named_static_regions[*region_index];
            ++region.direct_access_count;
            region.direct_access_offsets.push_back(physical - region.physical);
            region.direct_access_widths.push_back(static_cast<std::uint8_t>(std::min<std::size_t>(width, 255u)));
            return;
        }
        const auto residual_index = find_residual_region_index(physical);
        if (residual_index.has_value()) {
            GeneratedDataRegion& region = layout.residual_regions[*residual_index];
            ++region.direct_access_count;
            region.direct_access_offsets.push_back(physical - region.physical);
            region.direct_access_widths.push_back(static_cast<std::uint8_t>(std::min<std::size_t>(width, 255u)));
        }
    };

    for (const BlockRecord& block : snapshot.blocks) {
        std::map<std::string, std::uint16_t> tracked_register_offsets;
        for (const DecodedInstruction& instruction : block.preview.instructions) {
            const std::size_t first_space = instruction.text.find(' ');
            const std::string_view mnemonic =
                first_space == std::string::npos
                    ? std::string_view(instruction.text)
                    : std::string_view(instruction.text).substr(0u, first_space);
            const std::vector<std::string> operands = instruction_operand_texts(instruction);
            if (operands.empty()) {
                continue;
            }

            std::vector<std::size_t> memory_operand_indexes;
            for (std::size_t operand_index = 0u; operand_index < operands.size(); ++operand_index) {
                if (resolve_static_memory_operand_text(
                        operands[operand_index], tracked_register_offsets, symbol_map.default_data_segment, instruction.cs)
                        .has_value()) {
                    memory_operand_indexes.push_back(operand_index);
                }
            }
            if (!memory_operand_indexes.empty()) {
                std::vector<std::size_t> written_operand_indexes;
                if (mnemonic_writes_first_operand(mnemonic)) {
                    written_operand_indexes.push_back(0u);
                }
                if (mnemonic_writes_any_memory_operand(mnemonic)) {
                    written_operand_indexes.insert(written_operand_indexes.end(),
                                                  memory_operand_indexes.begin(),
                                                  memory_operand_indexes.end());
                }

                std::sort(written_operand_indexes.begin(), written_operand_indexes.end());
                written_operand_indexes.erase(std::unique(written_operand_indexes.begin(), written_operand_indexes.end()),
                                              written_operand_indexes.end());

                for (const std::size_t operand_index : written_operand_indexes) {
                    if (operand_index >= operands.size()) {
                        continue;
                    }
                    const auto memory_operand = resolve_static_memory_operand_text(
                        operands[operand_index], tracked_register_offsets, symbol_map.default_data_segment, instruction.cs);
                    if (!memory_operand.has_value()) {
                        continue;
                    }
                    const auto segment = resolve_operand_segment(instruction, *memory_operand);
                    if (!segment.has_value()) {
                        continue;
                    }
                    const std::uint32_t physical = real_mode_phys(*segment, memory_operand->offset);
                    if (!physical_in_loaded_module(image, physical)) {
                        continue;
                    }
                    mark_named_region_writable(physical);
                }
            }

            if (const auto target_register = parse_tracked_register_name(operands[0u]); target_register.has_value()) {
                bool handled = false;
                if (mnemonic == "mov" && operands.size() >= 2u) {
                    if (const auto immediate = parse_immediate_hex16_operand(operands[1u]); immediate.has_value()) {
                        tracked_register_offsets[*target_register] = *immediate;
                        handled = true;
                    }
                } else if (mnemonic == "lea" && operands.size() >= 2u) {
                    if (const auto direct = parse_direct_memory_operand_text(operands[1u]); direct.has_value()) {
                        tracked_register_offsets[*target_register] = direct->offset;
                        handled = true;
                    }
                } else if ((mnemonic == "xor" || mnemonic == "sub") && operands.size() >= 2u) {
                    const auto source_register = parse_tracked_register_name(operands[1u]);
                    if (source_register.has_value() && *source_register == *target_register) {
                        tracked_register_offsets[*target_register] = 0u;
                        handled = true;
                    }
                }
                if (!handled && mnemonic_writes_first_operand(mnemonic)) {
                    tracked_register_offsets.erase(*target_register);
                }
            }
        }
    }

    for (const BlockRecord& block : snapshot.blocks) {
        std::map<std::string, std::uint16_t> tracked_register_offsets;
        for (const DecodedInstruction& instruction : block.preview.instructions) {
            const std::size_t first_space = instruction.text.find(' ');
            const std::string_view mnemonic =
                first_space == std::string::npos
                    ? std::string_view(instruction.text)
                    : std::string_view(instruction.text).substr(0u, first_space);
            const std::vector<std::string> operands = instruction_operand_texts(instruction);
            for (std::size_t operand_index = 0u; operand_index < operands.size(); ++operand_index) {
                const std::string& operand_text = operands[operand_index];
                const auto memory_operand = resolve_static_memory_operand_text(
                    operand_text, tracked_register_offsets, symbol_map.default_data_segment, instruction.cs);
                if (!memory_operand.has_value()) {
                    continue;
                }
                const auto segment = resolve_operand_segment(instruction, *memory_operand);
                if (!segment.has_value()) {
                    continue;
                }
                const std::uint32_t physical = real_mode_phys(*segment, memory_operand->offset);
                if (!physical_in_loaded_module(image, physical)) {
                    continue;
                }
                note_named_region_access(
                    physical,
                    direct_memory_operand_width_bytes(instruction, operands, operand_index));
            }

            if (!operands.empty()) {
                if (const auto target_register = parse_tracked_register_name(operands[0u]); target_register.has_value()) {
                    bool handled = false;
                    if (mnemonic == "mov" && operands.size() >= 2u) {
                        if (const auto immediate = parse_immediate_hex16_operand(operands[1u]); immediate.has_value()) {
                            tracked_register_offsets[*target_register] = *immediate;
                            handled = true;
                        }
                    } else if (mnemonic == "lea" && operands.size() >= 2u) {
                        if (const auto direct = parse_direct_memory_operand_text(operands[1u]); direct.has_value()) {
                            tracked_register_offsets[*target_register] = direct->offset;
                            handled = true;
                        }
                    } else if ((mnemonic == "xor" || mnemonic == "sub") && operands.size() >= 2u) {
                        const auto source_register = parse_tracked_register_name(operands[1u]);
                        if (source_register.has_value() && *source_register == *target_register) {
                            tracked_register_offsets[*target_register] = 0u;
                            handled = true;
                        }
                    }
                    if (!handled && mnemonic_writes_first_operand(mnemonic)) {
                        tracked_register_offsets.erase(*target_register);
                    }
                }
            }
        }
    }

    merge_named_region_record_patterns(layout);

    for (GeneratedDataRegion& region : layout.named_static_regions) {
        region.stride_hint = detect_region_stride_hint(region);
        region.classification = classify_generated_data_region(region);
        region.storage_kind = classify_generated_data_storage_kind(region);
    }
    promote_repeated_opaque_record_families(layout);
    promote_family_specific_opaque_records(layout);
    for (GeneratedDataRegion& region : layout.code_regions) {
        region.stride_hint = detect_region_stride_hint(region);
        region.classification = classify_generated_data_region(region);
        region.storage_kind = classify_generated_data_storage_kind(region);
    }
    for (GeneratedDataRegion& region : layout.residual_regions) {
        region.stride_hint = detect_region_stride_hint(region);
        region.classification = classify_generated_data_region(region);
        region.storage_kind = classify_generated_data_storage_kind(region);
    }

    return layout;
}

void emit_byte_array(std::ostringstream& oss,
                     const std::string& array_name,
                     const bool is_const,
                     const std::vector<std::uint8_t>& bytes) {
    oss << "static " << (is_const ? "const " : "") << "unsigned char " << array_name << "[] = {\n";
    for (std::size_t index = 0u; index < bytes.size(); ++index) {
        if ((index % 12u) == 0u) {
            oss << "    ";
        }
        oss << "0x"
            << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
            << static_cast<unsigned>(bytes[index]);
        if (index + 1u != bytes.size()) {
            oss << ", ";
        }
        if ((index % 12u) == 11u || index + 1u == bytes.size()) {
            oss << '\n';
        }
    }
    oss << "};\n\n";
    oss << std::dec;
}

std::uint16_t read_u16_le(const std::vector<std::uint8_t>& bytes, const std::size_t offset) {
    return static_cast<std::uint16_t>(bytes[offset]) |
           static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[offset + 1u]) << 8u);
}

std::uint32_t read_u32_le(const std::vector<std::uint8_t>& bytes, const std::size_t offset) {
    return static_cast<std::uint32_t>(bytes[offset]) |
           (static_cast<std::uint32_t>(bytes[offset + 1u]) << 8u) |
           (static_cast<std::uint32_t>(bytes[offset + 2u]) << 16u) |
           (static_cast<std::uint32_t>(bytes[offset + 3u]) << 24u);
}

std::string generated_static_symbol_storage_name(const GeneratedDataRegion& region) {
    return "kGeneratedStaticSymbolData_" + region.name;
}

std::string generated_static_symbol_phys_constant_name(const GeneratedDataRegion& region) {
    return "kGeneratedStaticSymbolPhys_" + region.name;
}

std::string generated_static_symbol_offset_constant_name(const GeneratedDataRegion& region) {
    return "off_static_" + region.name;
}

std::string generated_static_symbol_byte_view_name(const GeneratedDataRegion& region) {
    return generated_static_symbol_storage_name(region) + "_Bytes";
}

std::optional<std::string> named_static_phys_expression(
    const std::string& segment_field,
    const std::uint16_t current_cs,
    const std::uint16_t offset,
    const std::size_t width,
    const bool require_readonly,
    const TrackedSegmentState* tracked_state) {
    if (g_generated_data_layout == nullptr) {
        return std::nullopt;
    }
    const auto segment = proven_symbol_segment_for_field(segment_field, current_cs, tracked_state);
    if (!segment.has_value()) {
        return std::nullopt;
    }
    std::size_t byte_offset = 0u;
    const GeneratedDataRegion* region =
        find_named_static_region_covering(*g_generated_data_layout, segment->first, offset, &byte_offset);
    if (region == nullptr) {
        return std::nullopt;
    }
    if (require_readonly && region->writable) {
        return std::nullopt;
    }
    if (byte_offset + width > region->bytes.size()) {
        return std::nullopt;
    }
    std::ostringstream oss;
    oss << generated_static_symbol_phys_constant_name(*region);
    if (byte_offset != 0u) {
        oss << " + 0x" << hex4(static_cast<std::uint16_t>(byte_offset)) << "u";
    }
    return oss.str();
}

std::optional<std::string> named_static_read_u8_expression(const std::string& segment_field,
                                                           const std::uint16_t current_cs,
                                                           const std::uint16_t offset,
                                                           const TrackedSegmentState* tracked_state,
                                                           const bool require_readonly) {
    if (const auto phys =
            named_static_phys_expression(segment_field, current_cs, offset, 1u, require_readonly, tracked_state);
        phys.has_value()) {
        return "generated_read_static_u8_phys(state, " + *phys + ")";
    }
    return std::nullopt;
}

std::optional<std::string> named_static_read_u16_expression(const std::string& segment_field,
                                                            const std::uint16_t current_cs,
                                                            const std::uint16_t offset,
                                                            const TrackedSegmentState* tracked_state,
                                                            const bool require_readonly) {
    if (const auto phys =
            named_static_phys_expression(segment_field, current_cs, offset, 2u, require_readonly, tracked_state);
        phys.has_value()) {
        return "generated_read_static_u16_phys(state, " + *phys + ")";
    }
    return std::nullopt;
}

std::optional<std::string> named_static_write_u8_statement(const std::string& segment_field,
                                                           const std::uint16_t current_cs,
                                                           const std::uint16_t offset,
                                                           const std::string& value_expression,
                                                           const TrackedSegmentState* tracked_state) {
    if (g_generated_data_layout == nullptr) {
        return std::nullopt;
    }
    const auto segment = proven_symbol_segment_for_field(segment_field, current_cs, tracked_state);
    if (!segment.has_value()) {
        return std::nullopt;
    }
    std::size_t byte_offset = 0u;
    const GeneratedDataRegion* region =
        find_named_static_region_covering(*g_generated_data_layout, segment->first, offset, &byte_offset);
    if (region == nullptr || !region->writable || byte_offset + 1u > region->bytes.size()) {
        return std::nullopt;
    }
    if (segment->second == "ds_seeded_default") {
        return std::nullopt;
    }
    std::ostringstream oss;
    oss << "    generated_write_static_u8_phys(state, " << generated_static_symbol_phys_constant_name(*region);
    if (byte_offset != 0u) {
        oss << " + 0x" << hex4(static_cast<std::uint16_t>(byte_offset)) << "u";
    }
    oss << ", " << value_expression << ");\n";
    return oss.str();
}

std::optional<std::string> named_static_write_u16_statement(const std::string& segment_field,
                                                            const std::uint16_t current_cs,
                                                            const std::uint16_t offset,
                                                            const std::string& value_expression,
                                                            const TrackedSegmentState* tracked_state) {
    if (g_generated_data_layout == nullptr) {
        return std::nullopt;
    }
    const auto segment = proven_symbol_segment_for_field(segment_field, current_cs, tracked_state);
    if (!segment.has_value()) {
        return std::nullopt;
    }
    std::size_t byte_offset = 0u;
    const GeneratedDataRegion* region =
        find_named_static_region_covering(*g_generated_data_layout, segment->first, offset, &byte_offset);
    if (region == nullptr || !region->writable || byte_offset + 2u > region->bytes.size()) {
        return std::nullopt;
    }
    if (segment->second == "ds_seeded_default") {
        return std::nullopt;
    }
    std::ostringstream oss;
    oss << "    generated_write_static_u16_phys(state, " << generated_static_symbol_phys_constant_name(*region);
    if (byte_offset != 0u) {
        oss << " + 0x" << hex4(static_cast<std::uint16_t>(byte_offset)) << "u";
    }
    oss << ", " << value_expression << ");\n";
    return oss.str();
}

const GeneratedDataRegion* find_named_static_region_covering(const GeneratedDataLayout& data_layout,
                                                             const std::uint16_t segment,
                                                             const std::uint16_t offset,
                                                             std::size_t* byte_offset_out) {
    const std::uint32_t physical =
        (((static_cast<std::uint32_t>(segment) << 4u) + static_cast<std::uint32_t>(offset)) & 0xFFFFFu);
    for (const GeneratedDataRegion& region : data_layout.named_static_regions) {
        const std::uint32_t region_end = region.physical + static_cast<std::uint32_t>(region.bytes.size());
        if (physical >= region.physical && physical < region_end) {
            if (byte_offset_out != nullptr) {
                *byte_offset_out = static_cast<std::size_t>(physical - region.physical);
            }
            return &region;
        }
    }
    return nullptr;
}

std::optional<std::string> readonly_named_static_read_u8_expression(const std::string& segment_field,
                                                                    const std::uint16_t current_cs,
                                                                    const std::uint16_t offset) {
    return named_static_read_u8_expression(segment_field, current_cs, offset, nullptr, true);
}

std::optional<std::string> readonly_named_static_read_u16_expression(const std::string& segment_field,
                                                                     const std::uint16_t current_cs,
                                                                     const std::uint16_t offset) {
    return named_static_read_u16_expression(segment_field, current_cs, offset, nullptr, true);
}

void emit_u16_array(std::ostringstream& oss,
                    const std::string& array_name,
                    const bool is_const,
                    const std::vector<std::uint8_t>& bytes) {
    oss << "static " << (is_const ? "const " : "") << "uint16_t " << array_name << "[] = {\n";
    const std::size_t count = bytes.size() / 2u;
    for (std::size_t index = 0u; index < count; ++index) {
        if ((index % 8u) == 0u) {
            oss << "    ";
        }
        oss << "0x"
            << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
            << read_u16_le(bytes, index * 2u) << "u";
        if (index + 1u != count) {
            oss << ", ";
        }
        if ((index % 8u) == 7u || index + 1u == count) {
            oss << '\n';
        }
    }
    oss << "};\n\n";
    oss << std::dec;
}

void emit_u8_array(std::ostringstream& oss,
                   const std::string& array_name,
                   const bool is_const,
                   const std::vector<std::uint8_t>& bytes) {
    oss << "static " << (is_const ? "const " : "") << "uint8_t " << array_name << "[] = {\n";
    for (std::size_t index = 0u; index < bytes.size(); ++index) {
        if ((index % 12u) == 0u) {
            oss << "    ";
        }
        oss << "0x"
            << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
            << static_cast<unsigned>(bytes[index]) << "u";
        if (index + 1u != bytes.size()) {
            oss << ", ";
        }
        if ((index % 12u) == 11u || index + 1u == bytes.size()) {
            oss << '\n';
        }
    }
    oss << "};\n\n";
    oss << std::dec;
}

void emit_u32_array(std::ostringstream& oss,
                    const std::string& array_name,
                    const bool is_const,
                    const std::vector<std::uint8_t>& bytes) {
    oss << "static " << (is_const ? "const " : "") << "uint32_t " << array_name << "[] = {\n";
    const std::size_t count = bytes.size() / 4u;
    for (std::size_t index = 0u; index < count; ++index) {
        if ((index % 6u) == 0u) {
            oss << "    ";
        }
        oss << "0x"
            << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
            << read_u32_le(bytes, index * 4u) << "u";
        if (index + 1u != count) {
            oss << ", ";
        }
        if ((index % 6u) == 5u || index + 1u == count) {
            oss << '\n';
        }
    }
    oss << "};\n\n";
    oss << std::dec;
}

void emit_far_ptr_array(std::ostringstream& oss,
                        const std::string& array_name,
                        const bool is_const,
                        const std::vector<std::uint8_t>& bytes) {
    oss << "static " << (is_const ? "const " : "") << "GeneratedFarPtr16 " << array_name << "[] = {\n";
    const std::size_t count = bytes.size() / 4u;
    for (std::size_t index = 0u; index < count; ++index) {
        if ((index % 4u) == 0u) {
            oss << "    ";
        }
        const std::uint16_t offset = read_u16_le(bytes, index * 4u);
        const std::uint16_t segment = read_u16_le(bytes, index * 4u + 2u);
        oss << "{ 0x"
            << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << offset
            << "u, 0x" << std::setw(4) << segment << "u }";
        if (index + 1u != count) {
            oss << ", ";
        }
        if ((index % 4u) == 3u || index + 1u == count) {
            oss << '\n';
        }
    }
    oss << "};\n\n";
    oss << std::dec;
}

void emit_zero_fill_array(std::ostringstream& oss,
                          const std::string& array_name,
                          const bool is_const,
                          const std::string& element_type,
                          const std::size_t count) {
    oss << "static " << (is_const ? "const " : "") << element_type << ' ' << array_name << '[' << count
        << "] = {};\n\n";
}

void emit_c_string(std::ostringstream& oss,
                   const std::string& name,
                   const std::vector<std::uint8_t>& bytes) {
    oss << "static const char " << name << "[] = "
        << escape_c_string_literal(bytes) << ";\n\n";
}

void emit_table_descriptor_record(std::ostringstream& oss,
                                  const std::string& name,
                                  const bool is_const,
                                  const std::vector<std::uint8_t>& bytes) {
    oss << "static " << (is_const ? "const " : "") << "GeneratedTableDescriptorRecord " << name << " = { ";
    for (std::size_t index = 0u; index < 8u; ++index) {
        if (index != 0u) {
            oss << ", ";
        }
        oss << "0x"
            << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
            << read_u16_le(bytes, index * 2u) << "u";
    }
    oss << " };\n\n";
    oss << std::dec;
}

void emit_load_level_scratch_record(std::ostringstream& oss,
                                    const std::string& name,
                                    const bool is_const,
                                    const std::vector<std::uint8_t>& bytes,
                                    const std::size_t payload_size) {
    oss << "static " << (is_const ? "const " : "") << "GeneratedLoadLevelScratchRecord" << payload_size
        << ' ' << name << " = { ";
    oss << "0x"
        << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
        << read_u16_le(bytes, 0u) << "u, { ";
    for (std::size_t index = 0u; index < payload_size; ++index) {
        if (index != 0u) {
            oss << ", ";
        }
        oss << "0x"
            << std::setw(2)
            << static_cast<unsigned>(bytes[2u + index]) << "u";
    }
    oss << " } };\n\n";
    oss << std::dec;
}

void emit_opaque_record(std::ostringstream& oss,
                        const std::string& name,
                        const bool is_const,
                        const std::vector<std::uint8_t>& bytes) {
    oss << "static " << (is_const ? "const " : "") << "GeneratedOpaqueRecord<" << bytes.size() << "> "
        << name << " = { { ";
    for (std::size_t index = 0u; index < bytes.size(); ++index) {
        if (index != 0u) {
            oss << ", ";
        }
        oss << "0x"
            << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
            << static_cast<unsigned>(bytes[index]) << "u";
    }
    oss << " } };\n\n";
    oss << std::dec;
}

void emit_savegame_record(std::ostringstream& oss,
                          const std::string& name,
                          const bool is_const,
                          const std::vector<std::uint8_t>& bytes) {
    oss << "static " << (is_const ? "const " : "") << "GeneratedSavegameRecord32 "
        << name << " = { { ";
    const std::size_t word_count = bytes.size() / 2u;
    for (std::size_t index = 0u; index < word_count; ++index) {
        if (index != 0u) {
            oss << ", ";
        }
        oss << "0x"
            << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
            << read_u16_le(bytes, index * 2u) << "u";
    }
    oss << " } };\n\n";
    oss << std::dec;
}

void emit_named_static_region_storage(std::ostringstream& oss,
                                      const GeneratedDataRegion& region) {
    const std::string storage_name = generated_static_symbol_storage_name(region);
    const std::string byte_view_name = generated_static_symbol_byte_view_name(region);

    if (region.storage_kind == "farptr_array") {
        emit_far_ptr_array(oss, storage_name, !region.writable, region.bytes);
    } else if (region.storage_kind == "u8_array") {
        emit_u8_array(oss, storage_name, !region.writable, region.bytes);
    } else if (region.storage_kind == "u8_scalar") {
        oss << "static " << (!region.writable ? "const " : "") << "uint8_t " << storage_name
            << " = 0x" << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
            << static_cast<unsigned>(region.bytes[0u]) << "u;\n" << std::dec;
    } else if (region.storage_kind == "u16_scalar") {
        oss << "static " << (!region.writable ? "const " : "") << "uint16_t " << storage_name
            << " = 0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
            << read_u16_le(region.bytes, 0u) << "u;\n" << std::dec;
    } else if (region.storage_kind == "farptr_scalar") {
        const std::uint16_t offset = read_u16_le(region.bytes, 0u);
        const std::uint16_t segment = read_u16_le(region.bytes, 2u);
        oss << "static " << (!region.writable ? "const " : "") << "GeneratedFarPtr16 " << storage_name
            << " = { 0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << offset
            << "u, 0x" << std::setw(4) << segment << "u };\n" << std::dec;
    } else if (region.storage_kind == "u32_scalar") {
        oss << "static " << (!region.writable ? "const " : "") << "uint32_t " << storage_name
            << " = 0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
            << read_u32_le(region.bytes, 0u) << "u;\n" << std::dec;
    } else if (region.storage_kind == "u8_zero_array") {
        emit_zero_fill_array(oss, storage_name, !region.writable, "uint8_t", region.bytes.size());
    } else if (region.storage_kind == "u16_zero_array") {
        emit_zero_fill_array(oss, storage_name, !region.writable, "uint16_t", region.bytes.size() / 2u);
    } else if (region.storage_kind == "u32_zero_array") {
        emit_zero_fill_array(oss, storage_name, !region.writable, "uint32_t", region.bytes.size() / 4u);
    } else if (region.storage_kind == "c_string") {
        emit_c_string(oss, storage_name, region.bytes);
    } else if (region.storage_kind == "table_descriptor_record") {
        emit_table_descriptor_record(oss, storage_name, !region.writable, region.bytes);
    } else if (region.storage_kind == "load_level_scratch_record_12") {
        emit_load_level_scratch_record(oss, storage_name, !region.writable, region.bytes, 12u);
    } else if (region.storage_kind == "load_level_scratch_record_34") {
        emit_load_level_scratch_record(oss, storage_name, !region.writable, region.bytes, 34u);
    } else if (region.storage_kind == "savegame_record_32") {
        emit_savegame_record(oss, storage_name, !region.writable, region.bytes);
    } else if (region.storage_kind.rfind("opaque_record_", 0u) == 0u) {
        emit_opaque_record(oss, storage_name, !region.writable, region.bytes);
    } else if (region.storage_kind == "u32_array") {
        emit_u32_array(oss, storage_name, !region.writable, region.bytes);
    } else if (region.storage_kind == "u16_array") {
        emit_u16_array(oss, storage_name, !region.writable, region.bytes);
    } else {
        emit_byte_array(oss, storage_name, !region.writable, region.bytes);
    }

    oss << "static const unsigned char* " << byte_view_name
        << " = reinterpret_cast<const unsigned char*>(&" << storage_name << ");\n\n";
}

std::string trim_ascii(std::string text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) {
        text.erase(text.begin());
    }
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) {
        text.pop_back();
    }
    return text;
}

bool is_likely_ascii_text_region(const GeneratedDataRegion& region) {
    if (region.writable || region.bytes.size() < 4u) {
        return false;
    }

    std::size_t first_nul = region.bytes.size();
    std::size_t printable_count = 0u;
    std::size_t considered_count = 0u;
    for (std::size_t index = 0u; index < region.bytes.size(); ++index) {
        const unsigned char ch = region.bytes[index];
        if (ch == 0u) {
            first_nul = index;
            break;
        }
        ++considered_count;
        if ((ch >= 0x20u && ch <= 0x7Eu) || ch == '\r' || ch == '\n' || ch == '\t') {
            ++printable_count;
        } else {
            return false;
        }
    }

    if (first_nul == region.bytes.size()) {
        return false;
    }
    if (considered_count < 4u) {
        return false;
    }
    return printable_count == considered_count;
}

bool is_c_string_region(const GeneratedDataRegion& region) {
    if (!is_likely_ascii_text_region(region) || region.writable || region.bytes.size() < 2u) {
        return false;
    }
    if (region.bytes.back() != 0u) {
        return false;
    }
    const std::size_t text_length = region.bytes.size() - 1u;
    std::size_t visible_count = 0u;
    std::size_t alpha_count = 0u;
    std::size_t digit_count = 0u;
    std::size_t punctuation_count = 0u;
    bool has_space = false;
    for (std::size_t index = 0u; index + 1u < region.bytes.size(); ++index) {
        const std::uint8_t value = region.bytes[index];
        if (value == 0u || value < 0x20u || value > 0x7Eu) {
            return false;
        }
        if ((value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z')) {
            ++alpha_count;
        } else if (value >= '0' && value <= '9') {
            ++digit_count;
        } else if (value == ' ') {
            has_space = true;
        } else {
            switch (value) {
            case '.':
            case ',':
            case '!':
            case '?':
            case ':':
            case ';':
            case '\'':
            case '"':
            case '/':
            case '\\':
            case '-':
            case '_':
            case '(':
            case ')':
                ++punctuation_count;
                break;
            default:
                return false;
            }
        }
        if (value != ' ') {
            ++visible_count;
        }
    }
    if (visible_count < 2u) {
        return false;
    }
    const std::string family_name = generated_region_family_name(region.name);
    const bool prefers_text = family_prefers_text_storage(family_name);
    const bool discourages_text = family_discourages_text_storage(family_name);
    if (text_length <= 5u) {
        return prefers_text && alpha_count >= 3u && punctuation_count == 0u;
    }
    if (alpha_count * 2u < text_length) {
        return false;
    }
    if (punctuation_count * 3u > text_length) {
        return false;
    }
    if (discourages_text && text_length < 12u && !has_space) {
        return false;
    }
    if (discourages_text && digit_count > alpha_count && !has_space) {
        return false;
    }
    return prefers_text || has_space || text_length >= 12u;
}

std::string generated_region_family_name(const std::string& name) {
    const std::size_t off = name.find("_off_");
    if (off != std::string::npos) {
        return name.substr(0u, off);
    }
    return name;
}

bool family_prefers_text_storage(const std::string& family_name) {
    if (family_name.empty()) {
        return false;
    }
    if (family_name[0] == 'a') {
        return true;
    }
    return family_name.find("Filename") != std::string::npos ||
           family_name.find("Filemask") != std::string::npos ||
           family_name.find("g_str_") != std::string::npos ||
           family_name.find("Title") != std::string::npos ||
           family_name.find("Message") != std::string::npos ||
           family_name.find("Prompt") != std::string::npos ||
           family_name.find("String") != std::string::npos;
}

bool family_discourages_text_storage(const std::string& family_name) {
    return family_name.rfind("g_TableDescriptor", 0u) == 0u ||
           family_name.rfind("g_SaveProcessPlayerDataPtr", 0u) == 0u ||
           family_name.rfind("g_LoadLevelScratchBuffer", 0u) == 0u ||
           family_name.rfind("g_File_TotalBytesRead", 0u) == 0u ||
           family_name.rfind("g_p", 0u) == 0u ||
           family_name.rfind("DbgPause_", 0u) == 0u;
}

bool family_prefers_u16_array_storage(const std::string& family_name) {
    return family_name.find("IndexBlock") != std::string::npos ||
           family_name.find("HeaderBlock") != std::string::npos ||
           family_name.find("DescriptorArray") != std::string::npos ||
           family_name.find("JumpTable") != std::string::npos ||
           family_name.find("HandlerTable") != std::string::npos ||
           family_name.find("DispatchTable") != std::string::npos ||
           family_name.find("_Table") != std::string::npos ||
           family_name.rfind("Table_", 0u) == 0u ||
           family_name.find("PaletteData") != std::string::npos ||
           family_name.find("NameIndices") != std::string::npos;
}

bool family_prefers_u8_array_storage(const std::string& family_name) {
    return family_name.find("PaletteData") != std::string::npos ||
           family_name.find("NameIndices") != std::string::npos ||
           family_name.find("characterArray") != std::string::npos;
}

std::optional<std::size_t> preferred_named_region_record_size(const std::string& family_name) {
    if (family_name == "g_TableDescriptorArray") {
        return 16u;
    }
    return std::nullopt;
}

bool family_is_table_descriptor_record(const std::string& family_name) {
    return family_name == "g_TableDescriptorArray";
}

void merge_named_region_record_patterns(GeneratedDataLayout& layout) {
    if (layout.named_static_regions.empty()) {
        return;
    }

    std::sort(layout.named_static_regions.begin(),
              layout.named_static_regions.end(),
              [](const GeneratedDataRegion& left, const GeneratedDataRegion& right) {
                  if (left.physical != right.physical) {
                      return left.physical < right.physical;
                  }
                  return left.name < right.name;
              });

    std::vector<GeneratedDataRegion> merged_regions;
    merged_regions.reserve(layout.named_static_regions.size());

    for (std::size_t index = 0u; index < layout.named_static_regions.size(); ++index) {
        GeneratedDataRegion current = std::move(layout.named_static_regions[index]);

        const std::string family_name = generated_region_family_name(current.name);
        const bool is_scratch_header =
            family_name == "g_LoadLevelScratchBuffer" &&
            !current.writable &&
            current.bytes.size() == 2u &&
            current.relocation_count == 1u &&
            current.direct_access_count == 0u;

        if (is_scratch_header && index + 1u < layout.named_static_regions.size()) {
            GeneratedDataRegion& next = layout.named_static_regions[index + 1u];
            const bool contiguous =
                current.physical + static_cast<std::uint32_t>(current.bytes.size()) == next.physical;
            const bool same_family = generated_region_family_name(next.name) == family_name;
            const bool mergeable_size = next.bytes.size() == 12u || next.bytes.size() == 34u;
            const bool mergeable_tail =
                !next.writable &&
                next.relocation_count == 0u &&
                next.direct_access_count == 0u;

            if (contiguous && same_family && mergeable_size && mergeable_tail) {
                current.bytes.insert(current.bytes.end(), next.bytes.begin(), next.bytes.end());
                current.direct_access_offsets.clear();
                current.direct_access_widths.clear();
                ++index;
            }
        }

        merged_regions.push_back(std::move(current));
    }

    layout.named_static_regions = std::move(merged_regions);
}

void promote_repeated_opaque_record_families(GeneratedDataLayout& layout) {
    struct FamilySizeKey {
        std::string family_name;
        std::size_t size = 0u;

        bool operator<(const FamilySizeKey& other) const {
            if (family_name != other.family_name) {
                return family_name < other.family_name;
            }
            return size < other.size;
        }
    };

    std::map<FamilySizeKey, std::size_t> counts;
    for (const GeneratedDataRegion& region : layout.named_static_regions) {
        if (region.writable || region.storage_kind != "byte_array") {
            continue;
        }
        if (region.classification == "string" || region.classification == "pointer_table" ||
            region.classification == "pointer_table_writable") {
            continue;
        }
        if (region.bytes.size() < 16u || region.bytes.size() > 64u) {
            continue;
        }
        ++counts[{generated_region_family_name(region.name), region.bytes.size()}];
    }

    for (GeneratedDataRegion& region : layout.named_static_regions) {
        if (region.writable || region.storage_kind != "byte_array") {
            continue;
        }
        if (region.classification == "string" || region.classification == "pointer_table" ||
            region.classification == "pointer_table_writable") {
            continue;
        }
        const FamilySizeKey key{generated_region_family_name(region.name), region.bytes.size()};
        const auto it = counts.find(key);
        if (it == counts.end() || it->second < 8u) {
            continue;
        }
        region.storage_kind = "opaque_record_" + std::to_string(region.bytes.size());
    }
}

void promote_family_specific_opaque_records(GeneratedDataLayout& layout) {
    for (GeneratedDataRegion& region : layout.named_static_regions) {
        if (region.writable || region.bytes.size() != 32u) {
            continue;
        }
        if (generated_region_family_name(region.name) == "aSavegame" &&
            region.storage_kind == "opaque_record_32") {
            region.storage_kind = "savegame_record_32";
        }
    }
}

std::string escape_c_string_literal(const std::vector<std::uint8_t>& bytes) {
    std::ostringstream oss;
    oss << '"';
    for (const std::uint8_t value : bytes) {
        switch (value) {
        case '\0':
            oss << "\\0";
            break;
        case '\n':
            oss << "\\n";
            break;
        case '\r':
            oss << "\\r";
            break;
        case '\t':
            oss << "\\t";
            break;
        case '\\':
            oss << "\\\\";
            break;
        case '"':
            oss << "\\\"";
            break;
        default:
            if (value >= 0x20u && value <= 0x7Eu) {
                oss << static_cast<char>(value);
            } else {
                oss << "\\x"
                    << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                    << static_cast<unsigned>(value)
                    << std::dec;
            }
            break;
        }
    }
    oss << '"';
    return oss.str();
}

bool is_printable_ascii_byte(const std::uint8_t value) {
    return (value >= 0x20u && value <= 0x7Eu) || value == '\r' || value == '\n' || value == '\t';
}

bool is_zero_fill_region(const GeneratedDataRegion& region) {
    return !region.bytes.empty() &&
           std::all_of(region.bytes.begin(), region.bytes.end(), [](const std::uint8_t value) {
               return value == 0u;
           });
}

bool is_sparse_zero_region(const GeneratedDataRegion& region) {
    if (region.bytes.size() < 64u || is_zero_fill_region(region)) {
        return false;
    }

    std::size_t zero_count = 0u;
    std::set<std::uint8_t> distinct_nonzero_bytes;
    for (const std::uint8_t value : region.bytes) {
        if (value == 0u) {
            ++zero_count;
        } else {
            distinct_nonzero_bytes.insert(value);
            if (distinct_nonzero_bytes.size() > 16u) {
                return false;
            }
        }
    }

    return zero_count * 100u >= region.bytes.size() * 85u;
}

std::size_t detect_region_stride_hint(const GeneratedDataRegion& region) {
    if (region.direct_access_offsets.size() < 3u) {
        return 0u;
    }

    std::vector<std::uint32_t> offsets = region.direct_access_offsets;
    std::sort(offsets.begin(), offsets.end());
    offsets.erase(std::unique(offsets.begin(), offsets.end()), offsets.end());
    if (offsets.size() < 3u) {
        return 0u;
    }

    std::map<std::uint32_t, std::size_t> diff_counts;
    for (std::size_t index = 1u; index < offsets.size(); ++index) {
        const std::uint32_t diff = offsets[index] - offsets[index - 1u];
        if (diff >= 2u && diff <= 64u) {
            ++diff_counts[diff];
        }
    }

    std::uint32_t best_diff = 0u;
    std::size_t best_count = 0u;
    for (const auto& [diff, count] : diff_counts) {
        if (count > best_count || (count == best_count && diff < best_diff)) {
            best_diff = diff;
            best_count = count;
        }
    }

    if (best_diff == 0u) {
        return 0u;
    }
    const std::size_t gap_count = offsets.size() - 1u;
    if (best_count < 2u || best_count * 2u < gap_count) {
        return 0u;
    }
    if (region.bytes.size() / best_diff < 4u) {
        return 0u;
    }
    return best_diff;
}

std::string classify_generated_data_region(const GeneratedDataRegion& region) {
    if (region.kind == GeneratedDataRegion::Kind::Code) {
        return "code";
    }
    if (is_zero_fill_region(region) && region.bytes.size() >= 8u) {
        return region.writable ? "zero_fill_writable" : "zero_fill";
    }
    if (is_sparse_zero_region(region)) {
        return region.writable ? "sparse_zero_writable" : "sparse_zero";
    }
    if (is_likely_ascii_text_region(region)) {
        return "string";
    }
    if (region.relocation_count >= 2u) {
        const std::size_t bytes_per_relocation =
            region.bytes.size() / std::max<std::size_t>(1u, region.relocation_count);
        if (bytes_per_relocation <= 8u) {
            return region.writable ? "pointer_table_writable" : "pointer_table";
        }
    }
    if (region.stride_hint >= 2u && region.direct_access_count >= 4u) {
        return region.writable ? "record_array_writable" : "record_array";
    }
    if (!region.writable && region.direct_access_count >= 4u) {
        return "table";
    }
    if (region.writable && region.bytes.size() <= 8u) {
        return "scalar_writable";
    }
    if (!region.writable && region.bytes.size() <= 8u) {
        return "scalar_readonly";
    }
    return region.writable ? "blob_writable" : "blob_readonly";
}

std::string classify_generated_data_storage_kind(const GeneratedDataRegion& region) {
    const std::string family_name = generated_region_family_name(region.name);

    if (!region.writable &&
        family_is_table_descriptor_record(family_name) &&
        region.bytes.size() == 16u) {
        return "table_descriptor_record";
    }

    if (!region.writable &&
        family_name == "g_LoadLevelScratchBuffer" &&
        region.relocation_count == 1u &&
        region.direct_access_count == 0u) {
        if (region.bytes.size() == 14u) {
            return "load_level_scratch_record_12";
        }
        if (region.bytes.size() == 36u) {
            return "load_level_scratch_record_34";
        }
    }

    if (!region.writable &&
        family_name == "aSavegame" &&
        region.bytes.size() == 32u &&
        region.storage_kind == "savegame_record_32") {
        return "savegame_record_32";
    }

    if ((region.classification == "pointer_table" || region.classification == "pointer_table_writable") &&
        region.bytes.size() == 4u) {
        return "farptr_scalar";
    }

    if (region.classification == "string" && is_c_string_region(region)) {
        return "c_string";
    }

    if ((region.classification == "pointer_table" || region.classification == "pointer_table_writable") &&
        (region.bytes.size() % 4u) == 0u) {
        return "farptr_array";
    }

    if (!region.writable && family_prefers_u8_array_storage(family_name) &&
        region.classification != "string" && region.classification != "zero_fill" &&
        region.classification != "zero_fill_writable" && region.classification != "sparse_zero" &&
        region.classification != "sparse_zero_writable") {
        return "u8_array";
    }

    if (region.classification == "scalar_readonly" || region.classification == "scalar_writable") {
        if (region.bytes.size() == 1u) {
            return "u8_scalar";
        }
        if (region.bytes.size() == 2u) {
            return "u16_scalar";
        }
        if (region.bytes.size() == 4u && region.relocation_count > 0u) {
            return "farptr_scalar";
        }
        if (region.bytes.size() == 4u) {
            return "u32_scalar";
        }
        if ((region.bytes.size() % 2u) == 0u && region.bytes.size() >= 4u) {
            return "u16_array";
        }
    }

    if (region.classification == "table" || region.classification == "record_array" ||
        region.classification == "record_array_writable") {
        if ((region.bytes.size() % 4u) == 0u && region.stride_hint >= 4u) {
            return "u32_array";
        }
        if ((region.bytes.size() % 2u) == 0u) {
            return "u16_array";
        }
    }

    if (is_probable_u16_array_region(region)) {
        return "u16_array";
    }

    if (region.classification == "zero_fill" || region.classification == "zero_fill_writable" ||
        region.classification == "sparse_zero" || region.classification == "sparse_zero_writable") {
        if (region.bytes.size() == 1u) {
            return "u8_scalar";
        }
        if (region.bytes.size() == 2u) {
            return "u16_scalar";
        }
        if (region.bytes.size() == 4u && region.relocation_count > 0u) {
            return "farptr_scalar";
        }
        if (region.bytes.size() == 4u) {
            return "u32_scalar";
        }
        if ((region.bytes.size() % 4u) == 0u && region.stride_hint >= 4u) {
            return "u32_zero_array";
        }
        if ((region.bytes.size() % 2u) == 0u && region.stride_hint >= 2u) {
            return "u16_zero_array";
        }
        return "u8_zero_array";
    }

    return "byte_array";
}

bool is_probable_u16_array_region(const GeneratedDataRegion& region) {
    if (region.writable || region.relocation_count != 0u ||
        (region.bytes.size() % 2u) != 0u || region.bytes.size() < 4u ||
        region.classification == "string") {
        return false;
    }

    const std::string family_name = generated_region_family_name(region.name);
    if (family_prefers_u16_array_storage(family_name)) {
        return true;
    }

    std::size_t high_zero_or_ff = 0u;
    std::size_t repeated_words = 0u;
    const std::size_t word_count = region.bytes.size() / 2u;
    std::uint16_t previous_word = 0u;
    bool have_previous_word = false;
    for (std::size_t index = 0u; index < word_count; ++index) {
        const std::uint16_t word = read_u16_le(region.bytes, index * 2u);
        const std::uint8_t high = static_cast<std::uint8_t>(word >> 8u);
        if (high == 0u || high == 0xFFu) {
            ++high_zero_or_ff;
        }
        if (have_previous_word && previous_word == word) {
            ++repeated_words;
        }
        previous_word = word;
        have_previous_word = true;
    }

    if (word_count < 8u) {
        return false;
    }
    if (high_zero_or_ff * 4u >= word_count * 3u) {
        return true;
    }
    return region.direct_access_count >= 4u && repeated_words * 4u < word_count;
}

std::vector<std::string> instruction_operand_texts(const DecodedInstruction& instruction) {
    const std::size_t first_space = instruction.text.find(' ');
    if (first_space == std::string::npos || first_space + 1u >= instruction.text.size()) {
        return {};
    }

    std::vector<std::string> operands;
    std::string remaining = instruction.text.substr(first_space + 1u);
    for (;;) {
        const std::size_t comma = remaining.find(", ");
        if (comma == std::string::npos) {
            if (!remaining.empty()) {
                operands.push_back(remaining);
            }
            break;
        }
        operands.push_back(remaining.substr(0u, comma));
        remaining = remaining.substr(comma + 2u);
    }
    return operands;
}

bool is_simple_direct_memory_operand_text(const std::string& operand_text) {
    const std::size_t left = operand_text.find('[');
    const std::size_t right = operand_text.find(']');
    if (left == std::string::npos || right == std::string::npos || right <= left + 1u) {
        return false;
    }
    const std::string inner = operand_text.substr(left + 1u, right - left - 1u);
    return inner.find("bx") == std::string::npos &&
           inner.find("bp") == std::string::npos &&
           inner.find("si") == std::string::npos &&
           inner.find("di") == std::string::npos &&
           inner.find('+') == std::string::npos &&
           inner.find('-') == std::string::npos;
}

std::optional<DirectMemoryOperandRef> parse_direct_memory_operand_text(const std::string& operand_text) {
    std::string text = trim_ascii(operand_text);
    if (!is_simple_direct_memory_operand_text(text)) {
        return std::nullopt;
    }

    std::string segment_name = "ds";
    if (const std::size_t colon = text.find(':'); colon != std::string::npos) {
        const std::string prefix = trim_ascii(text.substr(0u, colon));
        const std::size_t last_space = prefix.find_last_of(" \t");
        segment_name = trim_ascii(last_space == std::string::npos ? prefix : prefix.substr(last_space + 1u));
    }

    const std::size_t left = text.find('[');
    const std::size_t right = text.find(']');
    if (left == std::string::npos || right == std::string::npos || right <= left + 1u) {
        return std::nullopt;
    }

    const std::string inner = text.substr(left + 1u, right - left - 1u);
    const std::size_t hex = inner.find("0x");
    if (hex == std::string::npos) {
        return std::nullopt;
    }

    return DirectMemoryOperandRef{
        segment_name,
        parse_hex16_text(std::string_view(inner).substr(hex + 2u)),
    };
}

std::optional<std::string> parse_tracked_register_name(const std::string& operand_text) {
    const std::string text = trim_ascii(operand_text);
    if (text == "bx" || text == "bp" || text == "si" || text == "di") {
        return text;
    }
    return std::nullopt;
}

std::optional<std::string> parse_word_register_name(const std::string& operand_text) {
    const std::string text = trim_ascii(operand_text);
    if (text == "ax" || text == "cx" || text == "dx" || text == "bx" ||
        text == "sp" || text == "bp" || text == "si" || text == "di") {
        return text;
    }
    return std::nullopt;
}

std::optional<std::string> parse_segment_register_name(const std::string& operand_text) {
    const std::string text = trim_ascii(operand_text);
    if (text == "cs" || text == "ds" || text == "es" || text == "ss") {
        return text;
    }
    return std::nullopt;
}

std::optional<std::uint16_t> parse_immediate_hex16_operand(const std::string& operand_text) {
    const std::string text = trim_ascii(operand_text);
    if (!text.starts_with("0x")) {
        return std::nullopt;
    }
    return parse_hex16_text(std::string_view(text).substr(2u));
}

std::size_t operand_text_width_hint_bytes(const std::string& operand_text) {
    const std::string text = trim_ascii(operand_text);
    if (text == "al" || text == "ah" || text == "bl" || text == "bh" ||
        text == "cl" || text == "ch" || text == "dl" || text == "dh") {
        return 1u;
    }
    if (text == "ax" || text == "bx" || text == "cx" || text == "dx" ||
        text == "sp" || text == "bp" || text == "si" || text == "di" ||
        text == "cs" || text == "ds" || text == "es" || text == "ss" ||
        text == "ip" || text == "flags") {
        return 2u;
    }
    if (const auto immediate = parse_immediate_hex16_operand(text); immediate.has_value()) {
        return (*immediate > 0xFFu || text.size() > 4u) ? 2u : 1u;
    }
    return 0u;
}

std::size_t direct_memory_operand_width_bytes(const DecodedInstruction& instruction,
                                              const std::vector<std::string>& operands,
                                              std::size_t operand_index) {
    const std::size_t first_space = instruction.text.find(' ');
    const std::string_view mnemonic =
        first_space == std::string::npos
            ? std::string_view(instruction.text)
            : std::string_view(instruction.text).substr(0u, first_space);

    if (operand_index < operands.size()) {
        if (const std::size_t self_width = operand_text_width_hint_bytes(operands[operand_index]); self_width != 0u) {
            return self_width;
        }
    }

    for (std::size_t other_index = 0u; other_index < operands.size(); ++other_index) {
        if (other_index == operand_index) {
            continue;
        }
        if (const std::size_t other_width = operand_text_width_hint_bytes(operands[other_index]); other_width != 0u) {
            return other_width;
        }
    }

    if (mnemonic == "push" || mnemonic == "pop" || mnemonic == "call" || mnemonic == "jmp" ||
        mnemonic == "ret" || mnemonic == "retn" || mnemonic == "retf" || mnemonic == "iret" ||
        mnemonic == "enter" || mnemonic == "leave") {
        return 2u;
    }
    if (mnemonic == "lds" || mnemonic == "les") {
        return 4u;
    }

    return 1u;
}

std::optional<DirectMemoryOperandRef> resolve_static_memory_operand_text(
    const std::string& operand_text,
    const std::map<std::string, std::uint16_t>& tracked_register_offsets,
    const std::optional<std::uint16_t>& default_data_segment,
    const std::uint16_t current_cs) {
    if (const auto direct = parse_direct_memory_operand_text(operand_text); direct.has_value()) {
        return direct;
    }

    std::string text = trim_ascii(operand_text);
    const std::size_t left = text.find('[');
    const std::size_t right = text.find(']');
    if (left == std::string::npos || right == std::string::npos || right <= left + 1u) {
        return std::nullopt;
    }

    std::string segment_name = "ds";
    if (const std::size_t colon = text.find(':'); colon != std::string::npos) {
        const std::string prefix = trim_ascii(text.substr(0u, colon));
        const std::size_t last_space = prefix.find_last_of(" \t");
        segment_name = trim_ascii(last_space == std::string::npos ? prefix : prefix.substr(last_space + 1u));
    }

    std::string inner = text.substr(left + 1u, right - left - 1u);
    inner.erase(std::remove(inner.begin(), inner.end(), ' '), inner.end());
    if (inner.empty() || inner.find('-') != std::string::npos) {
        return std::nullopt;
    }

    std::uint32_t resolved_offset = 0u;
    std::size_t tracked_base_count = 0u;
    bool uses_bp = false;
    std::size_t token_start = 0u;
    while (token_start <= inner.size()) {
        const std::size_t plus = inner.find('+', token_start);
        const std::size_t token_end = (plus == std::string::npos) ? inner.size() : plus;
        const std::string token = inner.substr(token_start, token_end - token_start);
        if (token.empty()) {
            return std::nullopt;
        }

        if (token == "bp") {
            uses_bp = true;
        }
        if (const auto register_name = parse_tracked_register_name(token); register_name.has_value()) {
            if (const auto it = tracked_register_offsets.find(*register_name); it != tracked_register_offsets.end()) {
                resolved_offset += it->second;
                ++tracked_base_count;
            }
        } else if (token.starts_with("0x")) {
            resolved_offset += parse_hex16_text(std::string_view(token).substr(2u));
        } else {
            return std::nullopt;
        }

        if (plus == std::string::npos) {
            break;
        }
        token_start = plus + 1u;
    }

    if (tracked_base_count != 1u || resolved_offset > 0xFFFFu) {
        return std::nullopt;
    }

    if (segment_name == "cs") {
        return DirectMemoryOperandRef{"cs", static_cast<std::uint16_t>(resolved_offset)};
    }
    if (segment_name == "ds" || segment_name.empty()) {
        if (!default_data_segment.has_value() || uses_bp) {
            return std::nullopt;
        }
        return DirectMemoryOperandRef{"ds", static_cast<std::uint16_t>(resolved_offset)};
    }
    if (segment_name == "ss" || segment_name == "es") {
        return std::nullopt;
    }
    (void)current_cs;
    return std::nullopt;
}

bool mnemonic_writes_first_operand(const std::string_view mnemonic) {
    return mnemonic == "mov" ||
           mnemonic == "add" ||
           mnemonic == "adc" ||
           mnemonic == "sub" ||
           mnemonic == "sbb" ||
           mnemonic == "and" ||
           mnemonic == "or" ||
           mnemonic == "xor" ||
           mnemonic == "inc" ||
           mnemonic == "dec" ||
           mnemonic == "neg" ||
           mnemonic == "not" ||
           mnemonic == "rol" ||
           mnemonic == "ror" ||
           mnemonic == "rcl" ||
           mnemonic == "rcr" ||
           mnemonic == "shl" ||
           mnemonic == "shr" ||
           mnemonic == "sar" ||
           mnemonic == "pop";
}

bool mnemonic_writes_any_memory_operand(const std::string_view mnemonic) {
    return mnemonic == "xchg";
}

struct TrackedSegmentState {
    std::map<std::string, std::uint16_t> word_registers;
    std::map<std::string, std::uint16_t> segment_registers;
    std::set<std::string> seeded_segment_registers;
    std::vector<std::optional<std::uint16_t>> stack_words;
};

bool operator==(const TrackedSegmentState& left, const TrackedSegmentState& right) {
    return left.word_registers == right.word_registers &&
           left.segment_registers == right.segment_registers &&
           left.seeded_segment_registers == right.seeded_segment_registers &&
           left.stack_words == right.stack_words;
}

constexpr std::size_t kTrackedStackDepthLimit = 8u;

void tracked_state_push_word(TrackedSegmentState& state, const std::optional<std::uint16_t> value) {
    state.stack_words.push_back(value);
    if (state.stack_words.size() > kTrackedStackDepthLimit) {
        state.stack_words.erase(state.stack_words.begin());
    }
}

std::optional<std::uint16_t> tracked_state_pop_word(TrackedSegmentState& state) {
    if (state.stack_words.empty()) {
        return std::nullopt;
    }
    const std::optional<std::uint16_t> value = state.stack_words.back();
    state.stack_words.pop_back();
    return value;
}

void tracked_state_clear_stack(TrackedSegmentState& state) {
    state.stack_words.clear();
}

std::optional<std::pair<std::uint16_t, std::string>> proven_symbol_segment_for_field(
    const std::string& segment_field,
    const std::uint16_t current_cs,
    const TrackedSegmentState* tracked_state) {
    if (g_emission_symbol_map == nullptr) {
        return std::nullopt;
    }
    if (segment_field == "state->cs") {
        return std::pair<std::uint16_t, std::string>{current_cs, "cs_fixed"};
    }
    if (tracked_state == nullptr) {
        return std::nullopt;
    }
    if (segment_field == "state->ds") {
        const auto it = tracked_state->segment_registers.find("ds");
        if (it == tracked_state->segment_registers.end()) {
            return std::nullopt;
        }
        const bool seeded =
            tracked_state->seeded_segment_registers.find("ds") != tracked_state->seeded_segment_registers.end();
        const std::string proof_name =
            (g_emission_symbol_map->default_data_segment.has_value() &&
             it->second == *g_emission_symbol_map->default_data_segment)
                ? (seeded ? "ds_seeded_default" : "ds_default")
                : "ds_fixed_nondefault";
        return std::pair<std::uint16_t, std::string>{it->second, proof_name};
    }
    if (segment_field == "state->es") {
        const auto it = tracked_state->segment_registers.find("es");
        if (it == tracked_state->segment_registers.end()) {
            return std::nullopt;
        }
        return std::pair<std::uint16_t, std::string>{it->second, "es_fixed"};
    }
    if (segment_field == "state->ss") {
        const auto it = tracked_state->segment_registers.find("ss");
        if (it == tracked_state->segment_registers.end()) {
            return std::nullopt;
        }
        return std::pair<std::uint16_t, std::string>{it->second, "ss_fixed"};
    }
    return std::nullopt;
}

std::optional<std::uint16_t> tracked_state_known_word_value(const TrackedSegmentState& state,
                                                            const DecodedInstruction& instruction,
                                                            const std::string& operand_text) {
    if (const auto immediate = parse_immediate_hex16_operand(operand_text); immediate.has_value()) {
        return *immediate;
    }
    if (const auto word_register = parse_word_register_name(operand_text); word_register.has_value()) {
        if (const auto it = state.word_registers.find(*word_register); it != state.word_registers.end()) {
            return it->second;
        }
        return std::nullopt;
    }
    if (const auto segment_register = parse_segment_register_name(operand_text); segment_register.has_value()) {
        if (*segment_register == "cs") {
            return instruction.cs;
        }
        if (const auto it = state.segment_registers.find(*segment_register); it != state.segment_registers.end()) {
            return it->second;
        }
        return std::nullopt;
    }
    return std::nullopt;
}

TrackedSegmentState transfer_instruction_tracked_segment_state(TrackedSegmentState state,
                                                               const DecodedInstruction& instruction) {
    const std::size_t first_space = instruction.text.find(' ');
    const std::string_view mnemonic =
        first_space == std::string::npos
            ? std::string_view(instruction.text)
            : std::string_view(instruction.text).substr(0u, first_space);
    const std::vector<std::string> operands = instruction_operand_texts(instruction);
    if (operands.empty()) {
        return state;
    }

    const bool stack_pointer_written =
        !operands.empty() &&
        operands[0] == "sp" &&
        mnemonic_writes_first_operand(mnemonic);
    if (stack_pointer_written ||
        mnemonic == "enter" ||
        mnemonic == "leave" ||
        mnemonic == "call" ||
        mnemonic == "ret" ||
        mnemonic == "retn" ||
        mnemonic == "retf" ||
        mnemonic == "iret" ||
        mnemonic == "pushf" ||
        mnemonic == "popf" ||
        mnemonic == "pusha" ||
        mnemonic == "popa") {
        tracked_state_clear_stack(state);
    }

    if (mnemonic == "push" && operands.size() >= 1u) {
        tracked_state_push_word(state, tracked_state_known_word_value(state, instruction, operands[0]));
    } else if (mnemonic == "pop") {
        const std::optional<std::uint16_t> popped_value = tracked_state_pop_word(state);
        if (const auto target_word_register = parse_word_register_name(operands[0]);
            target_word_register.has_value()) {
            if (popped_value.has_value()) {
                state.word_registers[*target_word_register] = *popped_value;
            } else {
                state.word_registers.erase(*target_word_register);
            }
        }
        if (const auto target_segment_register = parse_segment_register_name(operands[0]);
            target_segment_register.has_value()) {
            if (popped_value.has_value()) {
                state.segment_registers[*target_segment_register] = *popped_value;
                state.seeded_segment_registers.erase(*target_segment_register);
            } else {
                state.segment_registers.erase(*target_segment_register);
                state.seeded_segment_registers.erase(*target_segment_register);
            }
        }
    }

    if (const auto target_word_register = parse_word_register_name(operands[0]); target_word_register.has_value()) {
        bool handled = false;
        if (mnemonic == "mov" && operands.size() >= 2u) {
            if (const auto value = tracked_state_known_word_value(state, instruction, operands[1]); value.has_value()) {
                state.word_registers[*target_word_register] = *value;
                handled = true;
            }
        } else if ((mnemonic == "xor" || mnemonic == "sub") && operands.size() >= 2u) {
            if (const auto source_word_register = parse_word_register_name(operands[1]);
                source_word_register.has_value() && *source_word_register == *target_word_register) {
                state.word_registers[*target_word_register] = 0u;
                handled = true;
            }
        } else if (mnemonic == "lds" || mnemonic == "les") {
            state.word_registers.erase(*target_word_register);
            handled = true;
        }
        if (!handled && mnemonic_writes_first_operand(mnemonic)) {
            state.word_registers.erase(*target_word_register);
        }
    }

    if (const auto target_segment_register = parse_segment_register_name(operands[0]);
        target_segment_register.has_value()) {
        bool handled = false;
        if (mnemonic == "mov" && operands.size() >= 2u) {
            if (const auto value = tracked_state_known_word_value(state, instruction, operands[1]); value.has_value()) {
                state.segment_registers[*target_segment_register] = *value;
                state.seeded_segment_registers.erase(*target_segment_register);
                handled = true;
            } else {
                state.segment_registers.erase(*target_segment_register);
                state.seeded_segment_registers.erase(*target_segment_register);
                handled = true;
            }
        }
        if (!handled && mnemonic_writes_first_operand(mnemonic)) {
            state.segment_registers.erase(*target_segment_register);
            state.seeded_segment_registers.erase(*target_segment_register);
        }
    }

    if (mnemonic == "lds" && !operands.empty()) {
        state.segment_registers.erase("ds");
        state.seeded_segment_registers.erase("ds");
    } else if (mnemonic == "les" && !operands.empty()) {
        state.segment_registers.erase("es");
        state.seeded_segment_registers.erase("es");
    }

    return state;
}

TrackedSegmentState intersect_tracked_segment_state(const TrackedSegmentState& left,
                                                    const TrackedSegmentState& right) {
    TrackedSegmentState result;
    for (const auto& [name, value] : left.word_registers) {
        if (const auto it = right.word_registers.find(name); it != right.word_registers.end() &&
            it->second == value) {
            result.word_registers.emplace(name, value);
        }
    }
    for (const auto& [name, value] : left.segment_registers) {
        if (const auto it = right.segment_registers.find(name); it != right.segment_registers.end() &&
            it->second == value) {
            result.segment_registers.emplace(name, value);
            const bool left_seeded = left.seeded_segment_registers.find(name) != left.seeded_segment_registers.end();
            const bool right_seeded = right.seeded_segment_registers.find(name) != right.seeded_segment_registers.end();
            if (left_seeded == right_seeded && left_seeded) {
                result.seeded_segment_registers.insert(name);
            }
        }
    }
    if (left.stack_words == right.stack_words) {
        result.stack_words = left.stack_words;
    }
    return result;
}

std::map<std::uint32_t, TrackedSegmentState> build_block_entry_segment_states(
    const CfgSnapshot& snapshot,
    const EmissionSymbolMap& symbol_map) {
    std::map<std::uint32_t, const BlockRecord*> blocks_by_start;
    std::map<std::uint32_t, std::vector<std::uint32_t>> predecessors_by_block_start;
    std::map<std::uint32_t, std::uint32_t> block_start_by_terminal;
    for (const BlockRecord& block : snapshot.blocks) {
        const std::uint32_t block_key = location_key(block.start);
        blocks_by_start.emplace(block_key, &block);
        if (!block.preview.instructions.empty()) {
            const DecodedInstruction& terminal = block.preview.instructions.back();
            block_start_by_terminal.emplace(location_key(CodeLocation{terminal.cs, terminal.ip}), block_key);
        }
    }
    for (const CfgEdge& edge : snapshot.edges) {
        const auto target_it = blocks_by_start.find(location_key(edge.to));
        if (target_it == blocks_by_start.end()) {
            continue;
        }
        if (const auto pred_it = block_start_by_terminal.find(location_key(edge.from));
            pred_it != block_start_by_terminal.end()) {
            predecessors_by_block_start[target_it->first].push_back(pred_it->second);
        }
    }

    std::map<std::uint32_t, TrackedSegmentState> entry_state_by_block_start;
    std::map<std::uint32_t, TrackedSegmentState> exit_state_by_block_start;
    if (const auto root_it = blocks_by_start.find(location_key(snapshot.root)); root_it != blocks_by_start.end()) {
        TrackedSegmentState root_state;
        if (symbol_map.default_data_segment.has_value()) {
            root_state.segment_registers.emplace("ds", *symbol_map.default_data_segment);
        }
        entry_state_by_block_start.emplace(root_it->first, root_state);
    }
    if (symbol_map.default_data_segment.has_value()) {
        for (const CodeLocation function_root : snapshot.discovered_function_roots) {
            if (function_root.cs != snapshot.root.cs || function_root.ip == snapshot.root.ip) {
                continue;
            }
            const std::uint32_t block_key = location_key(function_root);
            if (!blocks_by_start.contains(block_key) || entry_state_by_block_start.contains(block_key)) {
                continue;
            }
            TrackedSegmentState seeded_root_state;
            seeded_root_state.segment_registers.emplace("ds", *symbol_map.default_data_segment);
            seeded_root_state.seeded_segment_registers.insert("ds");
            entry_state_by_block_start.emplace(block_key, std::move(seeded_root_state));
        }
    }

    bool changed = true;
    while (changed) {
        changed = false;
        for (const BlockRecord& block : snapshot.blocks) {
            const std::uint32_t block_key = location_key(block.start);
            std::optional<TrackedSegmentState> merged_entry_state;
            if (const auto existing_it = entry_state_by_block_start.find(block_key);
                existing_it != entry_state_by_block_start.end()) {
                merged_entry_state = existing_it->second;
            }
            if (const auto pred_it = predecessors_by_block_start.find(block_key);
                pred_it != predecessors_by_block_start.end()) {
                for (const std::uint32_t predecessor_key : pred_it->second) {
                    const auto exit_it = exit_state_by_block_start.find(predecessor_key);
                    if (exit_it == exit_state_by_block_start.end()) {
                        continue;
                    }
                    if (!merged_entry_state.has_value()) {
                        merged_entry_state = exit_it->second;
                    } else {
                        merged_entry_state = intersect_tracked_segment_state(*merged_entry_state, exit_it->second);
                    }
                }
            }
            if (!merged_entry_state.has_value()) {
                continue;
            }
            if (const auto existing_it = entry_state_by_block_start.find(block_key);
                existing_it == entry_state_by_block_start.end() || !(existing_it->second == *merged_entry_state)) {
                entry_state_by_block_start[block_key] = *merged_entry_state;
                changed = true;
            }

            TrackedSegmentState exit_state = *merged_entry_state;
            for (const DecodedInstruction& instruction : block.preview.instructions) {
                exit_state = transfer_instruction_tracked_segment_state(std::move(exit_state), instruction);
            }
            if (const auto existing_it = exit_state_by_block_start.find(block_key);
                existing_it == exit_state_by_block_start.end() || !(existing_it->second == exit_state)) {
                exit_state_by_block_start[block_key] = std::move(exit_state);
                changed = true;
            }
        }
    }

    return entry_state_by_block_start;
}

std::map<std::uint32_t, TrackedSegmentState> build_instruction_entry_segment_states(
    const CfgSnapshot& snapshot,
    const EmissionSymbolMap& symbol_map) {
    const auto block_entry_states = build_block_entry_segment_states(snapshot, symbol_map);
    std::map<std::uint32_t, TrackedSegmentState> instruction_entry_states;
    for (const BlockRecord& block : snapshot.blocks) {
        TrackedSegmentState tracked_state;
        if (const auto entry_it = block_entry_states.find(location_key(block.start));
            entry_it != block_entry_states.end()) {
            tracked_state = entry_it->second;
        }
        for (const DecodedInstruction& instruction : block.preview.instructions) {
            instruction_entry_states.emplace(location_key(CodeLocation{instruction.cs, instruction.ip}), tracked_state);
            tracked_state = transfer_instruction_tracked_segment_state(std::move(tracked_state), instruction);
        }
    }
    return instruction_entry_states;
}

std::string shared_body_name(const CodeLocation location);

bool snapshot_uses_generated_calltables(const CfgSnapshot& snapshot) {
    for (const IndirectSiteRecord& site : snapshot.indirect_sites) {
        if (site_uses_generated_calltable(site)) {
            return true;
        }
    }
    return false;
}

bool snapshot_uses_interface_surfaces(const CfgSnapshot& snapshot) {
    for (const InterfaceSurfaceRecord& surface : snapshot.interface_surfaces) {
        if (!surface.entries.empty()) {
            return true;
        }
    }
    return false;
}

bool snapshot_uses_routine_pack_callable_surfaces(const CfgSnapshot& snapshot) {
    for (const InterfaceSurfaceRecord& surface : snapshot.interface_surfaces) {
        if ((surface.kind == InterfaceSurfaceKind::RoutinePackWordTable ||
             surface.kind == InterfaceSurfaceKind::RoutinePackDescriptorTable) &&
            !surface.entries.empty()) {
            return true;
        }
    }
    return false;
}

bool snapshot_uses_engine_api_surface(const CfgSnapshot& snapshot) {
    for (const InterfaceSurfaceRecord& surface : snapshot.interface_surfaces) {
        if (surface.kind == InterfaceSurfaceKind::EngineApiJumpTable &&
            !surface.entries.empty()) {
            return true;
        }
    }
    return false;
}

std::uint16_t interface_surface_target_cs(const InterfaceSurfaceRecord& surface) {
    for (const InterfaceSurfaceEntry& entry : surface.entries) {
        if (entry.target_is_valid) {
            return entry.target.cs;
        }
    }
    return 0u;
}

std::string register8_value_expression(const std::uint8_t index) {
    return "generated_get_reg8(state, " + std::to_string(static_cast<unsigned>(index)) + "u)";
}

std::string register8_set_statement(const std::uint8_t index, const std::string& value_expression) {
    return "    generated_set_reg8(state, " + std::to_string(static_cast<unsigned>(index)) +
           "u, " + value_expression + ");\n";
}

std::string segment_field_name_from_index(const std::uint8_t index) {
    switch (index & 0x03u) {
    case 0u: return "state->es";
    case 1u: return "state->cs";
    case 2u: return "state->ss";
    case 3u: return "state->ds";
    }
    return "state->ds";
}

std::string override_segment_field_name(const DecodedInstruction& instruction) {
    const std::size_t prefix_length = instruction_prefix_length(instruction);
    for (std::size_t index = 0; index < prefix_length; ++index) {
        switch (instruction.bytes[index]) {
        case 0x26u: return "state->es";
        case 0x2Eu: return "state->cs";
        case 0x36u: return "state->ss";
        case 0x3Eu: return "state->ds";
        default:
            break;
        }
    }
    return {};
}

std::string make_u16_add_expression(const std::string& base, const int displacement) {
    if (displacement == 0) {
        return base;
    }
    if (displacement > 0) {
        return "(uint16_t)(" + base + " + 0x" + hex4(static_cast<std::uint16_t>(displacement)) + ")";
    }
    return "(uint16_t)(" + base + " - 0x" + hex4(static_cast<std::uint16_t>(-displacement)) + ")";
}

std::string modrm_default_segment_field_name(const DecodedInstruction& instruction,
                                             const std::uint8_t mod,
                                             const std::uint8_t rm) {
    const std::string override_segment = override_segment_field_name(instruction);
    if (!override_segment.empty()) {
        return override_segment;
    }

    if (rm == 0x02u || rm == 0x03u || (rm == 0x06u && mod != 0x00u)) {
        return "state->ss";
    }
    return "state->ds";
}

struct DirectStandaloneHelperCallSpec {
    std::string wrapper_name;
    std::vector<std::string> input_registers;
    std::vector<std::string> output_registers;
    bool reads_flags = false;
};

struct DirectTypedHelperCallSpec {
    std::string wrapper_name;
    std::vector<std::string> input_registers;
    std::vector<std::string> output_registers;
};

void emit_direct_typed_helper_call(std::ostringstream& oss, const DirectTypedHelperCallSpec& spec);

void emit_direct_standalone_helper_call(std::ostringstream& oss, const DirectStandaloneHelperCallSpec& spec) {
    std::ostringstream call_expr;
    call_expr << spec.wrapper_name << '(';
    if (spec.input_registers.empty() && !spec.reads_flags) {
        call_expr << ')';
    } else {
        bool first = true;
        for (std::size_t index = 0u; index < spec.input_registers.size(); ++index) {
            if (!first) {
                call_expr << ", ";
            }
            first = false;
            call_expr << "state->" << spec.input_registers[index];
        }
        if (spec.reads_flags) {
            if (!first) {
                call_expr << ", ";
            }
            call_expr << "state->flags";
        }
        call_expr << ')';
    }

    if (spec.output_registers.size() == 1u) {
        oss << "    state->" << spec.output_registers.front() << " = "
            << call_expr.str() << ";\n";
        return;
    }

    oss << "    {\n";
    oss << "        const auto generated_helper_result = " << call_expr.str() << ";\n";
    for (const std::string& output : spec.output_registers) {
        oss << "        state->" << output << " = generated_helper_result." << output << ";\n";
    }
    oss << "    }\n";
}

bool decode_modrm_operand(const DecodedInstruction& instruction,
                          std::size_t& out_modrm_offset,
                          std::uint8_t& out_modrm,
                          bool& out_is_register,
                          std::string& out_segment_field,
                          std::string& out_offset_expression,
                          std::optional<std::uint16_t>* out_direct_offset = nullptr) {
    const std::size_t prefix_length = instruction_prefix_length(instruction);
    const std::size_t modrm_index = prefix_length + 1u;
    if (modrm_index >= instruction.bytes.size()) {
        return false;
    }

    out_modrm_offset = modrm_index;
    out_modrm = instruction.bytes[modrm_index];
    const std::uint8_t mod = static_cast<std::uint8_t>((out_modrm >> 6u) & 0x03u);
    const std::uint8_t rm = static_cast<std::uint8_t>(out_modrm & 0x07u);
    if (mod == 0x03u) {
        out_is_register = true;
        out_segment_field.clear();
        out_offset_expression.clear();
        if (out_direct_offset != nullptr) {
            *out_direct_offset = std::nullopt;
        }
        return true;
    }

    out_is_register = false;

    std::size_t operand_index = modrm_index + 1u;
    int displacement = 0;
    if (mod == 0x01u) {
        if (operand_index >= instruction.bytes.size()) {
            return false;
        }
        displacement = static_cast<std::int8_t>(instruction.bytes[operand_index]);
    } else if (mod == 0x02u || (mod == 0x00u && rm == 0x06u)) {
        if (operand_index + 1u >= instruction.bytes.size()) {
            return false;
        }
        displacement = static_cast<std::int16_t>(instruction_u16(instruction, operand_index));
    }

    out_segment_field = modrm_default_segment_field_name(instruction, mod, rm);
    if (mod == 0x00u && rm == 0x06u) {
        const std::uint16_t direct_offset = static_cast<std::uint16_t>(displacement);
        out_offset_expression = direct_offset_text(out_segment_field, instruction.cs, direct_offset);
        if (out_direct_offset != nullptr) {
            *out_direct_offset = direct_offset;
        }
        return true;
    }
    if (out_direct_offset != nullptr) {
        *out_direct_offset = std::nullopt;
    }

    std::string base_expression;
    switch (rm) {
    case 0x00u: base_expression = "(uint16_t)(state->bx + state->si)"; break;
    case 0x01u: base_expression = "(uint16_t)(state->bx + state->di)"; break;
    case 0x02u: base_expression = "(uint16_t)(state->bp + state->si)"; break;
    case 0x03u: base_expression = "(uint16_t)(state->bp + state->di)"; break;
    case 0x04u: base_expression = "state->si"; break;
    case 0x05u: base_expression = "state->di"; break;
    case 0x06u: base_expression = "state->bp"; break;
    case 0x07u: base_expression = "state->bx"; break;
    default: return false;
    }

    out_offset_expression = make_u16_add_expression(base_expression, displacement);
    return true;
}

bool emit_actual_instruction(std::ostringstream& oss,
                             const DecodedInstruction& instruction,
                             const bool should_emit_ip_advance,
                             const std::optional<CodeLocation>& next_emitted_location,
                             const std::set<std::uint32_t>& function_block_keys,
                             const std::set<std::uint32_t>& function_label_keys,
                             const std::map<std::uint32_t, TrackedSegmentState>& instruction_entry_segment_states,
                             const std::map<std::uint32_t, std::vector<CodeLocation>>& resolved_indirect_calls,
                             const std::map<std::uint32_t, std::vector<CodeLocation>>& resolved_indirect_branches,
                             const std::map<std::uint32_t, const IndirectSiteRecord*>& indirect_sites_by_key,
                             const std::map<std::uint32_t, std::uint32_t>& canonical_calltable_keys,
                             const std::set<std::uint32_t>& elidable_noop_call_target_keys,
                             const std::map<std::uint32_t, DirectStandaloneHelperCallSpec>& direct_standalone_call_target_specs,
                             const std::map<std::uint32_t, DirectTypedHelperCallSpec>& direct_typed_call_target_specs) {
    const std::uint8_t opcode = instruction_opcode(instruction);
    const bool rep_prefix = instruction_has_prefix(instruction, 0xF3u);
    const bool repne_prefix = instruction_has_prefix(instruction, 0xF2u);
    const std::uint16_t next_ip = static_cast<std::uint16_t>(instruction.ip + instruction.length);
    const std::string next_ip_text = "0x" + hex4(next_ip);
    const std::uint32_t instruction_key = location_key(CodeLocation{instruction.cs, instruction.ip});
    const TrackedSegmentState* instruction_entry_segment_state = nullptr;
    if (const auto state_it = instruction_entry_segment_states.find(instruction_key);
        state_it != instruction_entry_segment_states.end()) {
        instruction_entry_segment_state = &state_it->second;
    }

    if (instruction.indirect.has_value() && instruction.flow == FlowKind::Call) {
        if (instruction.indirect->is_far &&
            instruction.indirect->operand_kind == IndirectOperandKind::MemoryDirect &&
            instruction.indirect->memory_offset.has_value() &&
            *instruction.indirect->memory_offset == 0x0788u) {
            emit_direct_call_return_setup(oss, instruction.cs, next_ip_text, true);
            const std::string routine_pack_vector_off = direct_offset_text("state->ds", instruction.cs, 0x0788u);
            const std::string routine_pack_target_off = direct_offset_text("state->ds", instruction.cs, 0x078Cu);
            const std::string routine_pack_vector_expr =
                named_static_read_u16_expression("state->ds", instruction.cs, 0x0788u, instruction_entry_segment_state, false)
                    .value_or("generated_read_u16(state, state->ds, " + routine_pack_vector_off + ")");
            const std::string routine_pack_target_expr =
                named_static_read_u16_expression("state->ds", instruction.cs, 0x078Cu, instruction_entry_segment_state, false)
                    .value_or("generated_read_u16(state, state->ds, " + routine_pack_target_off + ")");
            oss << "    if (" << routine_pack_vector_expr << " == 0x0010u) {\n";
            oss << "        generated_call_routine_pack_init(state);\n";
            oss << "    } else {\n";
            oss << "        const uint16_t generated_routine_pack_target_ip = " << routine_pack_target_expr << ";\n";
            oss << "        if (!generated_call_routine_pack_bridge(state, generated_routine_pack_target_ip)) {\n";
            oss << "            generated_note_dynamic_target(state, 0x" << hex4(instruction.cs)
                << "u, 0x" << hex4(instruction.ip)
                << "u, 0x4A56u, generated_routine_pack_target_ip"
                << ", \"routine_pack_bridge\");\n";
            oss << "            generated_runtime_note_call(state, \"unsupported_dynamic_call\");\n";
            oss << "            return;\n";
            oss << "        }\n";
            oss << "    }\n";
            emit_direct_call_resume(oss, instruction.cs, next_ip_text);
            return true;
        }
        if (instruction.indirect->is_far &&
            instruction.indirect->operand_kind == IndirectOperandKind::MemoryDirect &&
            instruction.indirect->memory_offset.has_value() &&
            *instruction.indirect->memory_offset == 0x078Eu) {
            emit_direct_call_return_setup(oss, instruction.cs, next_ip_text, true);
            const std::string engine_api_vector_ip_off = direct_offset_text("state->ds", instruction.cs, 0x078Eu);
            const std::string engine_api_vector_cs_off = direct_offset_text("state->ds", instruction.cs, 0x0790u);
            const std::string engine_api_target_off = direct_offset_text("state->ds", instruction.cs, 0x0792u);
            const std::string engine_api_vector_ip_expr =
                named_static_read_u16_expression("state->ds", instruction.cs, 0x078Eu, instruction_entry_segment_state, false)
                    .value_or("generated_read_u16(state, state->ds, " + engine_api_vector_ip_off + ")");
            const std::string engine_api_vector_cs_expr =
                named_static_read_u16_expression("state->ds", instruction.cs, 0x0790u, instruction_entry_segment_state, false)
                    .value_or("generated_read_u16(state, state->ds, " + engine_api_vector_cs_off + ")");
            const std::string engine_api_target_expr =
                named_static_read_u16_expression("state->ds", instruction.cs, 0x0792u, instruction_entry_segment_state, false)
                    .value_or("generated_read_u16(state, state->ds, " + engine_api_target_off + ")");
            oss << "    if (" << engine_api_vector_ip_expr << " == 0x6019u &&\n";
            oss << "        " << engine_api_vector_cs_expr << " == 0x1010u) {\n";
            oss << "        const uint16_t generated_engine_api_target_ip = " << engine_api_target_expr << ";\n";
            oss << "        if (!generated_call_engine_api_bridge(state, generated_engine_api_target_ip)) {\n";
            oss << "            generated_note_dynamic_target(state, 0x" << hex4(instruction.cs)
                << "u, 0x" << hex4(instruction.ip)
                << "u, 0x1010u, generated_engine_api_target_ip"
                << ", \"engine_api_bridge\");\n";
            oss << "            generated_runtime_note_call(state, \"unsupported_dynamic_call\");\n";
            oss << "            return;\n";
            oss << "        }\n";
            oss << "    } else {\n";
            oss << "        const uint16_t generated_target_ip = " << engine_api_vector_ip_expr << ";\n";
            oss << "        const uint16_t generated_target_cs = " << engine_api_vector_cs_expr << ";\n";
            oss << "        generated_jump_far(state, generated_target_cs, generated_target_ip);\n";
            oss << "        if (state->terminated) return;\n";
            oss << "    }\n";
            emit_direct_call_resume(oss, instruction.cs, next_ip_text);
            return true;
        }

        const auto call_it = resolved_indirect_calls.find(instruction_key);
        const auto site_it = indirect_sites_by_key.find(instruction_key);
        const IndirectSiteRecord* indirect_site =
            site_it != indirect_sites_by_key.end() ? site_it->second : nullptr;
        if (call_it != resolved_indirect_calls.end()) {
            const std::vector<CodeLocation>& targets = call_it->second;
            if (targets.size() == 1u) {
                if (!instruction.indirect->is_far) {
                    const auto standalone_spec_it =
                        direct_standalone_call_target_specs.find(location_key(targets.front()));
                    if (standalone_spec_it != direct_standalone_call_target_specs.end()) {
                        emit_direct_standalone_helper_call(oss, standalone_spec_it->second);
                        return true;
                    }
                    const auto typed_spec_it =
                        direct_typed_call_target_specs.find(location_key(targets.front()));
                    if (typed_spec_it != direct_typed_call_target_specs.end()) {
                        emit_direct_typed_helper_call(oss, typed_spec_it->second);
                        return true;
                    }
                }
                if (!instruction.indirect->is_far && elidable_noop_call_target_keys.contains(location_key(targets.front()))) {
                    oss << "    /* elided no-op helper call: " << function_name(targets.front()) << " */\n";
                    return true;
                }
                emit_direct_call_return_setup(oss, instruction.cs, next_ip_text, instruction.indirect->is_far);
                oss << "    " << function_name(targets.front()) << "(state);\n";
                return true;
            }
        }

        std::size_t modrm_offset = 0u;
        std::uint8_t modrm = 0u;
        bool is_register = false;
        std::string segment_field;
        std::string offset_expression;
        std::optional<std::uint16_t> direct_offset;
        if (opcode == 0xFFu &&
            decode_modrm_operand(
                instruction, modrm_offset, modrm, is_register, segment_field, offset_expression, &direct_offset)) {
            oss << "    {\n";
            if (!is_register) {
                const std::string target_ip_expr =
                    direct_offset.has_value()
                        ? named_static_read_u16_expression(
                              segment_field, instruction.cs, *direct_offset, instruction_entry_segment_state, false)
                              .value_or("generated_read_u16(state, " + segment_field + ", " + offset_expression + ")")
                        : "generated_read_u16(state, " + segment_field + ", " + offset_expression + ")";
                if (instruction.indirect->is_far) {
                    const std::string target_cs_expr =
                        direct_offset.has_value()
                            ? named_static_read_u16_expression(
                                  segment_field,
                                  instruction.cs,
                                  static_cast<std::uint16_t>(*direct_offset + 2u),
                                  instruction_entry_segment_state,
                                  false)
                                  .value_or("generated_read_u16(state, " + segment_field + ", (uint16_t)(" +
                                            offset_expression + " + 2u))")
                            : "generated_read_u16(state, " + segment_field + ", (uint16_t)(" + offset_expression +
                              " + 2u))";
                    oss << "        const uint16_t generated_target_ip = " << target_ip_expr << ";\n";
                    oss << "        const uint16_t generated_target_cs = " << target_cs_expr << ";\n";
                } else {
                    oss << "        const uint16_t generated_target_ip = " << target_ip_expr << ";\n";
                    oss << "        const uint16_t generated_target_cs = 0x" << hex4(instruction.cs) << "u;\n";
                }
            } else {
                const auto register_index =
                    instruction.indirect.has_value() ? register16_index_from_text(instruction.indirect->operand_text) : std::nullopt;
                if (!register_index.has_value()) {
                    return false;
                }
                oss << "        const uint16_t generated_target_ip = " << register16_field_name(*register_index) << ";\n";
                oss << "        const uint16_t generated_target_cs = 0x" << hex4(instruction.cs) << "u;\n";
            }
            if (indirect_site != nullptr && site_uses_generated_calltable(*indirect_site)) {
                std::string index_expression;
                if (indirect_site->dispatch_kind == IndirectDispatchKind::CurrentCsWordTable) {
                    if (!is_register) {
                        index_expression = offset_expression;
                    } else if (indirect_site->dispatch_index_register.has_value()) {
                        index_expression = register16_field_name(*indirect_site->dispatch_index_register);
                    } else {
                        return false;
                    }
                } else {
                    if (!indirect_site->dispatch_index_register.has_value()) {
                        return false;
                    }
                    index_expression = register16_field_name(*indirect_site->dispatch_index_register);
                }
                oss << "        const uint16_t generated_calltable_offset = " << index_expression << ";\n";
                oss << "        unsigned generated_calltable_dispatched = 0u;\n";
                if (indirect_site->dispatch_kind == IndirectDispatchKind::CurrentCsWordTable) {
                    oss << "        for (unsigned generated_index = 0; generated_index < "
                        << indirect_site->dispatch_entries.size() << "u; ++generated_index) {\n";
                    oss << "            const GeneratedWordCallTableEntry* generated_entry = &"
                        << canonical_calltable_name(canonical_calltable_keys, indirect_site->from) << "[generated_index];\n";
                    oss << "            if (generated_entry->selector == generated_calltable_offset && "
                        << "generated_entry->fn != 0 && "
                        << "generated_entry->target_ip == generated_target_ip) {\n";
                    emit_direct_call_return_setup(oss, instruction.cs, next_ip_text, instruction.indirect->is_far);
                    oss << "                generated_entry->fn(state);\n";
                    oss << "                generated_calltable_dispatched = 1u;\n";
                    oss << "                break;\n";
                    oss << "            }\n";
                    oss << "        }\n";
                } else {
                    const std::uint16_t selector_distance =
                        static_cast<std::uint16_t>(indirect_site->dispatch_runtime_index_base -
                                                   indirect_site->dispatch_table_base);
                    oss << "        const uint16_t generated_raw_index = (uint16_t)(generated_calltable_offset - 0x"
                        << hex4(indirect_site->dispatch_runtime_index_base) << "u);\n";
                    oss << "        if ((generated_raw_index % " << indirect_site->dispatch_entry_stride << "u) == 0u) {\n";
                    oss << "            const unsigned generated_index = (unsigned)(generated_raw_index / "
                        << indirect_site->dispatch_entry_stride << "u);\n";
                    oss << "            if (generated_index < "
                        << indirect_site->dispatch_entries.size() << "u) {\n";
                    oss << "                const GeneratedPairCallTableEntry* generated_entry = &"
                        << canonical_calltable_name(canonical_calltable_keys, indirect_site->from) << "[generated_index];\n";
                    oss << "                const uint16_t generated_selector = generated_read_u16(state, state->cs, "
                        << "(uint16_t)(generated_calltable_offset - 0x" << hex4(selector_distance) << "u));\n";
                    oss << "                if (generated_entry->fn != 0 && "
                        << "generated_entry->selector == generated_selector && "
                        << "generated_entry->target_ip == generated_target_ip) {\n";
                    emit_direct_call_return_setup(oss, instruction.cs, next_ip_text, instruction.indirect->is_far);
                    oss << "                    generated_entry->fn(state);\n";
                    oss << "                    generated_calltable_dispatched = 1u;\n";
                    oss << "                }\n";
                    oss << "            }\n";
                    oss << "        }\n";
                }
            }
            const bool use_calltable_dispatch_fallback =
                indirect_site != nullptr && site_uses_generated_calltable(*indirect_site);
            if (call_it != resolved_indirect_calls.end() && !call_it->second.empty() && !use_calltable_dispatch_fallback) {
                const std::vector<CodeLocation>& targets = call_it->second;
                std::set<std::uint32_t> emitted_case_keys;
                oss << "        switch ((((uint32_t)generated_target_cs & 0xFFFFu) << 16u) | (uint32_t)generated_target_ip) {\n";
                for (const CodeLocation target : targets) {
                    if (!emitted_case_keys.insert(location_key(target)).second) {
                        continue;
                    }
                    oss << "        case 0x" << hex4(target.cs) << hex4(target.ip) << "u:\n";
                    if (!instruction.indirect->is_far) {
                        const auto standalone_spec_it =
                            direct_standalone_call_target_specs.find(location_key(target));
                        if (standalone_spec_it != direct_standalone_call_target_specs.end()) {
                            emit_direct_standalone_helper_call(oss, standalone_spec_it->second);
                            oss << "            break;\n";
                            continue;
                        }
                        const auto typed_spec_it =
                            direct_typed_call_target_specs.find(location_key(target));
                        if (typed_spec_it != direct_typed_call_target_specs.end()) {
                            emit_direct_typed_helper_call(oss, typed_spec_it->second);
                            oss << "            break;\n";
                            continue;
                        }
                    }
                    if (!instruction.indirect->is_far && elidable_noop_call_target_keys.contains(location_key(target))) {
                        oss << "            /* elided no-op helper call: " << function_name(target) << " */\n";
                    } else {
                        emit_direct_call_return_setup(oss, instruction.cs, next_ip_text, instruction.indirect->is_far);
                        oss << "            " << function_name(target) << "(state);\n";
                    }
                    oss << "            break;\n";
                }
                oss << "        default:\n";
                emit_direct_call_return_setup(oss, instruction.cs, next_ip_text, instruction.indirect->is_far);
                if (instruction.indirect->is_far) {
                    oss << "            generated_jump_far(state, generated_target_cs, generated_target_ip);\n";
                    oss << "            if (state->terminated) return;\n";
                    emit_direct_call_resume(oss, instruction.cs, next_ip_text);
                    oss << "            break;\n";
                } else {
                    oss << "            if (generated_dispatch_root(state, generated_target_cs, generated_target_ip)) {\n";
                    emit_direct_call_resume(oss, instruction.cs, next_ip_text);
                    oss << "                break;\n";
                    oss << "            }\n";
                }
                oss << "            generated_note_dynamic_target(state, 0x" << hex4(instruction.cs)
                    << "u, 0x" << hex4(instruction.ip)
                    << "u, generated_target_cs, generated_target_ip, \"indirect_call\");\n";
                oss << "            generated_runtime_note_call(state, \"unsupported_dynamic_call\");\n";
                oss << "            return;\n";
                oss << "        }\n";
            } else {
                if (use_calltable_dispatch_fallback) {
                    oss << "        if (generated_calltable_dispatched == 0u) {\n";
                }
                emit_direct_call_return_setup(oss, instruction.cs, next_ip_text, instruction.indirect->is_far);
                if (instruction.indirect->is_far) {
                    oss << "        generated_jump_far(state, generated_target_cs, generated_target_ip);\n";
                    oss << "        if (state->terminated) return;\n";
                    emit_direct_call_resume(oss, instruction.cs, next_ip_text);
                } else {
                    oss << "        if (generated_dispatch_root(state, generated_target_cs, generated_target_ip)) {\n";
                    emit_direct_call_resume(oss, instruction.cs, next_ip_text);
                    oss << "        } else {\n";
                    oss << "            generated_note_dynamic_target(state, 0x" << hex4(instruction.cs)
                        << "u, 0x" << hex4(instruction.ip)
                        << "u, generated_target_cs, generated_target_ip, \"indirect_call\");\n";
                    oss << "            generated_runtime_note_call(state, \"unsupported_dynamic_call\");\n";
                    oss << "            return;\n";
                    oss << "        }\n";
                }
                if (use_calltable_dispatch_fallback) {
                    oss << "        }\n";
                }
            }
            oss << "    }\n";
            return true;
        }
    }

    if (instruction.indirect.has_value() && instruction.flow == FlowKind::UnconditionalBranch) {
        const auto branch_it = resolved_indirect_branches.find(instruction_key);
        if (branch_it != resolved_indirect_branches.end()) {
            const std::vector<CodeLocation>& targets = branch_it->second;
            if (targets.size() == 1u) {
                const CodeLocation target = targets.front();
                const std::uint32_t target_key = location_key(target);
                if (function_label_keys.contains(target_key) || function_block_keys.contains(target_key)) {
                    oss << "    goto " << block_label_name(target) << ";\n";
                } else {
                    oss << "    generated_jump_far(state, 0x" << hex4(target.cs)
                        << "u, 0x" << hex4(target.ip) << "u);\n";
                    oss << "    return;\n";
                }
                return true;
            }

            std::size_t modrm_offset = 0u;
            std::uint8_t modrm = 0u;
            bool is_register = false;
            std::string segment_field;
            std::string offset_expression;
            std::optional<std::uint16_t> direct_offset;
            if (opcode == 0xFFu &&
                decode_modrm_operand(
                    instruction, modrm_offset, modrm, is_register, segment_field, offset_expression, &direct_offset) &&
                !is_register) {
                const std::string target_ip_expr =
                    direct_offset.has_value()
                        ? named_static_read_u16_expression(
                              segment_field, instruction.cs, *direct_offset, instruction_entry_segment_state, false)
                              .value_or("generated_read_u16(state, " + segment_field + ", " + offset_expression + ")")
                        : "generated_read_u16(state, " + segment_field + ", " + offset_expression + ")";
                if (instruction.indirect->is_far) {
                    std::set<std::uint32_t> emitted_case_keys;
                    oss << "    {\n";
                    const std::string target_cs_expr =
                        direct_offset.has_value()
                            ? named_static_read_u16_expression(
                                  segment_field,
                                  instruction.cs,
                                  static_cast<std::uint16_t>(*direct_offset + 2u),
                                  instruction_entry_segment_state,
                                  false)
                                  .value_or("generated_read_u16(state, " + segment_field + ", (uint16_t)(" +
                                            offset_expression + " + 2u))")
                            : "generated_read_u16(state, " + segment_field + ", (uint16_t)(" + offset_expression +
                              " + 2u))";
                    oss << "        const uint16_t generated_target_ip = " << target_ip_expr << ";\n";
                    oss << "        const uint16_t generated_target_cs = " << target_cs_expr << ";\n";
                    oss << "        switch ((((uint32_t)generated_target_cs & 0xFFFFu) << 16u) | (uint32_t)generated_target_ip) {\n";
                    for (const CodeLocation target : targets) {
                        if (!emitted_case_keys.insert(location_key(target)).second) {
                            continue;
                        }
                        oss << "        case 0x" << hex4(target.cs) << hex4(target.ip) << "u:\n";
                        if (function_label_keys.contains(location_key(target)) || function_block_keys.contains(location_key(target))) {
                            oss << "            goto " << block_label_name(target) << ";\n";
                        } else {
                            oss << "            generated_jump_far(state, 0x" << hex4(target.cs)
                                << "u, 0x" << hex4(target.ip) << "u);\n";
                            oss << "            return;\n";
                        }
                    }
                    oss << "        default:\n";
                    for (const std::uint32_t target_key : function_label_keys) {
                        const CodeLocation target = key_to_location(target_key);
                        oss << "            if (generated_target_cs == 0x" << hex4(target.cs)
                            << "u && generated_target_ip == 0x" << hex4(target.ip)
                            << "u) goto " << block_label_name(target) << ";\n";
                    }
                    for (const std::uint32_t target_key : function_block_keys) {
                        if (function_label_keys.contains(target_key)) {
                            continue;
                        }
                        const CodeLocation target = key_to_location(target_key);
                        oss << "            if (generated_target_cs == 0x" << hex4(target.cs)
                            << "u && generated_target_ip == 0x" << hex4(target.ip)
                            << "u) goto " << block_label_name(target) << ";\n";
                    }
                    oss << "            generated_jump_far(state, generated_target_cs, generated_target_ip);\n";
                    oss << "            return;\n";
                    oss << "        }\n";
                    oss << "    }\n";
                    return true;
                }

                std::set<std::uint32_t> emitted_case_keys;
                oss << "    {\n";
                oss << "        const uint16_t generated_target_ip = " << target_ip_expr << ";\n";
                oss << "        switch (generated_target_ip) {\n";
                for (const CodeLocation target : targets) {
                    if (!emitted_case_keys.insert(location_key(target)).second) {
                        continue;
                    }
                    oss << "    case 0x" << hex4(target.ip) << "u:\n";
                    if (function_label_keys.contains(location_key(target)) || function_block_keys.contains(location_key(target))) {
                        oss << "        goto " << block_label_name(target) << ";\n";
                    } else {
                        oss << "        generated_jump_far(state, 0x" << hex4(target.cs)
                            << "u, 0x" << hex4(target.ip) << "u);\n";
                        oss << "        return;\n";
                    }
                }
                oss << "    default:\n";
                for (const std::uint32_t target_key : function_label_keys) {
                    const CodeLocation target = key_to_location(target_key);
                    if (target.cs != instruction.cs) {
                        continue;
                    }
                    oss << "            if (generated_target_ip == 0x" << hex4(target.ip) << "u) goto "
                        << block_label_name(target) << ";\n";
                }
                for (const std::uint32_t target_key : function_block_keys) {
                    if (function_label_keys.contains(target_key)) {
                        continue;
                    }
                    const CodeLocation target = key_to_location(target_key);
                    if (target.cs != instruction.cs) {
                        continue;
                    }
                    oss << "            if (generated_target_ip == 0x" << hex4(target.ip) << "u) goto "
                        << block_label_name(target) << ";\n";
                }
                oss << "            generated_jump_far(state, 0x" << hex4(instruction.cs) << "u, generated_target_ip);\n";
                oss << "            return;\n";
                oss << "        }\n";
                oss << "    }\n";
                return true;
            }

            const auto register_index =
                instruction.indirect.has_value() ? register16_index_from_text(instruction.indirect->operand_text) : std::nullopt;
            if (!register_index.has_value()) {
                return false;
            }

            std::set<std::uint32_t> emitted_case_keys;
            oss << "    switch (" << register16_field_name(*register_index) << ") {\n";
            for (const CodeLocation target : targets) {
                if (!emitted_case_keys.insert(location_key(target)).second) {
                    continue;
                }
                oss << "    case 0x" << hex4(target.ip) << "u:\n";
                if (function_label_keys.contains(location_key(target)) || function_block_keys.contains(location_key(target))) {
                    oss << "        goto " << block_label_name(target) << ";\n";
                } else {
                    oss << "        generated_jump_far(state, 0x" << hex4(target.cs)
                        << "u, 0x" << hex4(target.ip) << "u);\n";
                    oss << "        return;\n";
                }
            }
            oss << "    default:\n";
            for (const std::uint32_t target_key : function_label_keys) {
                const CodeLocation target = key_to_location(target_key);
                if (target.cs != instruction.cs) {
                    continue;
                }
                oss << "        if (" << register16_field_name(*register_index) << " == 0x"
                    << hex4(target.ip) << "u) goto " << block_label_name(target) << ";\n";
            }
            for (const std::uint32_t target_key : function_block_keys) {
                if (function_label_keys.contains(target_key)) {
                    continue;
                }
                const CodeLocation target = key_to_location(target_key);
                if (target.cs != instruction.cs) {
                    continue;
                }
                oss << "        if (" << register16_field_name(*register_index) << " == 0x"
                    << hex4(target.ip) << "u) goto " << block_label_name(target) << ";\n";
            }
            oss << "        generated_jump_far(state, 0x" << hex4(instruction.cs) << "u, "
                << register16_field_name(*register_index) << ");\n";
            oss << "        return;\n";
            oss << "    }\n";
            return true;
        }

        if (!instruction.indirect->is_far) {
            std::size_t modrm_offset = 0u;
            std::uint8_t modrm = 0u;
            bool is_register = false;
            std::string segment_field;
            std::string offset_expression;
            std::optional<std::uint16_t> direct_offset;
            if (opcode == 0xFFu &&
                decode_modrm_operand(
                    instruction, modrm_offset, modrm, is_register, segment_field, offset_expression, &direct_offset)) {
                oss << "    {\n";
                if (is_register) {
                    const auto register_index =
                        instruction.indirect.has_value()
                            ? register16_index_from_text(instruction.indirect->operand_text)
                            : std::nullopt;
                    if (!register_index.has_value()) {
                        return false;
                    }
                    oss << "        const uint16_t generated_target_ip = "
                        << register16_field_name(*register_index) << ";\n";
                } else {
                    const std::string target_ip_expr =
                        direct_offset.has_value()
                            ? named_static_read_u16_expression(
                                  segment_field, instruction.cs, *direct_offset, instruction_entry_segment_state, false)
                                  .value_or("generated_read_u16(state, " + segment_field + ", " + offset_expression + ")")
                            : "generated_read_u16(state, " + segment_field + ", " + offset_expression + ")";
                    oss << "        const uint16_t generated_target_ip = " << target_ip_expr << ";\n";
                }
                oss << "        switch (generated_target_ip) {\n";
                for (const std::uint32_t target_key : function_label_keys) {
                    const CodeLocation target = key_to_location(target_key);
                    if (target.cs != instruction.cs) {
                        continue;
                    }
                    oss << "        case 0x" << hex4(target.ip) << "u:\n";
                    oss << "            goto " << block_label_name(target) << ";\n";
                }
                for (const std::uint32_t target_key : function_block_keys) {
                    if (function_label_keys.contains(target_key)) {
                        continue;
                    }
                    const CodeLocation target = key_to_location(target_key);
                    if (target.cs != instruction.cs) {
                        continue;
                    }
                    oss << "        case 0x" << hex4(target.ip) << "u:\n";
                    oss << "            goto " << block_label_name(target) << ";\n";
                }
                oss << "        default:\n";
                oss << "            generated_jump_far(state, 0x" << hex4(instruction.cs)
                    << "u, generated_target_ip);\n";
                oss << "            return;\n";
                oss << "        }\n";
                oss << "    }\n";
                return true;
            }
        }

        if (opcode == 0xFFu && instruction.indirect->operand_kind == IndirectOperandKind::MemoryComputed) {
            std::size_t modrm_offset = 0u;
            std::uint8_t modrm = 0u;
            bool is_register = false;
            std::string segment_field;
            std::string offset_expression;
            std::optional<std::uint16_t> direct_offset;
            if (decode_modrm_operand(
                    instruction, modrm_offset, modrm, is_register, segment_field, offset_expression, &direct_offset) &&
                !is_register) {
                const std::string target_ip_expr =
                    direct_offset.has_value()
                        ? named_static_read_u16_expression(
                              segment_field, instruction.cs, *direct_offset, instruction_entry_segment_state, false)
                              .value_or("generated_read_u16(state, " + segment_field + ", " + offset_expression + ")")
                        : "generated_read_u16(state, " + segment_field + ", " + offset_expression + ")";
                if (instruction.indirect->is_far) {
                    oss << "    {\n";
                    const std::string target_cs_expr =
                        direct_offset.has_value()
                            ? named_static_read_u16_expression(
                                  segment_field,
                                  instruction.cs,
                                  static_cast<std::uint16_t>(*direct_offset + 2u),
                                  instruction_entry_segment_state,
                                  false)
                                  .value_or("generated_read_u16(state, " + segment_field + ", (uint16_t)(" +
                                            offset_expression + " + 2u))")
                            : "generated_read_u16(state, " + segment_field + ", (uint16_t)(" + offset_expression +
                              " + 2u))";
                    oss << "        const uint16_t generated_target_ip = " << target_ip_expr << ";\n";
                    oss << "        const uint16_t generated_target_cs = " << target_cs_expr << ";\n";
                    oss << "        switch ((((uint32_t)generated_target_cs & 0xFFFFu) << 16u) | (uint32_t)generated_target_ip) {\n";
                    for (const std::uint32_t target_key : function_label_keys) {
                        const CodeLocation target = key_to_location(target_key);
                        oss << "        case 0x" << hex4(target.cs) << hex4(target.ip) << "u:\n";
                        oss << "            goto " << block_label_name(target) << ";\n";
                    }
                    for (const std::uint32_t target_key : function_block_keys) {
                        if (function_label_keys.contains(target_key)) {
                            continue;
                        }
                        const CodeLocation target = key_to_location(target_key);
                        oss << "        case 0x" << hex4(target.cs) << hex4(target.ip) << "u:\n";
                        oss << "            goto " << block_label_name(target) << ";\n";
                    }
                    oss << "        default:\n";
                    oss << "            generated_jump_far(state, generated_target_cs, generated_target_ip);\n";
                    oss << "            return;\n";
                    oss << "        }\n";
                    oss << "    }\n";
                    return true;
                }

                oss << "    {\n";
                oss << "        const uint16_t generated_target_ip = " << target_ip_expr << ";\n";
                oss << "        switch (generated_target_ip) {\n";
                for (const std::uint32_t target_key : function_label_keys) {
                    const CodeLocation target = key_to_location(target_key);
                    if (target.cs != instruction.cs) {
                        continue;
                    }
                    oss << "        case 0x" << hex4(target.ip) << "u:\n";
                    oss << "            goto " << block_label_name(target) << ";\n";
                }
                for (const std::uint32_t target_key : function_block_keys) {
                    if (function_label_keys.contains(target_key)) {
                        continue;
                    }
                    const CodeLocation target = key_to_location(target_key);
                    if (target.cs != instruction.cs) {
                        continue;
                    }
                    oss << "        case 0x" << hex4(target.ip) << "u:\n";
                    oss << "            goto " << block_label_name(target) << ";\n";
                }
                oss << "        default:\n";
                oss << "            generated_jump_far(state, 0x" << hex4(instruction.cs) << "u, generated_target_ip);\n";
                oss << "            return;\n";
                oss << "        }\n";
                oss << "    }\n";
                return true;
            }
        }

        const IndirectTransferInfo& indirect = *instruction.indirect;
        if (indirect.is_far &&
            indirect.operand_kind == IndirectOperandKind::MemoryDirect &&
            indirect.memory_uses_current_cs &&
            indirect.memory_offset.has_value()) {
            const std::uint16_t pointer_offset = *indirect.memory_offset;
            const std::string target_cs_expr =
                named_static_read_u16_expression(
                    "state->cs",
                    instruction.cs,
                    static_cast<std::uint16_t>(pointer_offset + 2u),
                    instruction_entry_segment_state,
                    false)
                    .value_or("generated_read_u16(state, state->cs, 0x" +
                              hex4(static_cast<std::uint16_t>(pointer_offset + 2u)) + ")");
            const std::string target_ip_expr =
                named_static_read_u16_expression(
                    "state->cs", instruction.cs, pointer_offset, instruction_entry_segment_state, false)
                    .value_or("generated_read_u16(state, state->cs, 0x" + hex4(pointer_offset) + ")");
            oss << "    generated_jump_far(state, "
                << target_cs_expr << ", "
                << target_ip_expr << ");\n";
            oss << "    return;\n";
            return true;
        }
    }

    switch (opcode) {
    case 0x06u:
        oss << "    generated_push_u16(state, state->es);\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    case 0x07u:
        oss << "    state->es = generated_pop_u16(state);\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    case 0x0Eu:
        oss << "    generated_push_u16(state, state->cs);\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    case 0x16u:
        oss << "    generated_push_u16(state, state->ss);\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    case 0x17u:
        oss << "    state->ss = generated_pop_u16(state);\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    case 0x1Eu:
        oss << "    generated_push_u16(state, state->ds);\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    case 0x1Fu:
        oss << "    state->ds = generated_pop_u16(state);\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    case 0xCFu:
        oss << "    generated_iret(state);\n";
        oss << "    return;\n";
        return true;
    case 0xD7u:
        oss << register8_set_statement(
            0u,
            "generated_read_u8(state, state->ds, (uint16_t)(state->bx + (uint16_t)(" +
                register8_value_expression(0u) + ")))");
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    case 0x05u: {
        const std::size_t imm_offset = instruction_prefix_length(instruction) + 1u;
        const std::uint16_t imm = instruction_u16(instruction, imm_offset);
        emit_assign_add_u16(oss, "state->ax", "state->ax", "0x" + hex4(imm) + "u");
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }
    case 0x04u: {
        const std::size_t imm_offset = instruction_prefix_length(instruction) + 1u;
        const std::uint8_t imm = instruction.bytes.at(imm_offset);
        emit_assign_add_u8_register(
            oss,
            0u,
            register8_value_expression(0u),
            "0x" + hex4(imm).substr(2) + "u");
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }
    case 0xFAu:
        oss << "    generated_set_flag(state, GENERATED_FLAG_IF, 0u);\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    case 0xFBu:
        oss << "    generated_set_flag(state, GENERATED_FLAG_IF, 1u);\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    case 0xF8u:
        oss << "    generated_set_flag(state, GENERATED_FLAG_CF, 0u);\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    case 0xF9u:
        oss << "    generated_set_flag(state, GENERATED_FLAG_CF, 1u);\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    case 0xFCu:
        oss << "    generated_set_flag(state, GENERATED_FLAG_DF, 0u);\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    case 0xFDu:
        oss << "    generated_set_flag(state, GENERATED_FLAG_DF, 1u);\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    case 0x9Cu:
        oss << "    generated_push_u16(state, state->flags);\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    case 0x9Du:
        oss << "    state->flags = generated_pop_u16(state);\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    case 0x9Fu:
        oss << register8_set_statement(
            4u,
            "(unsigned char)(((generated_get_flag(state, GENERATED_FLAG_CF) != 0u) ? 0x01u : 0u) | "
            "0x02u | "
            "((generated_get_flag(state, GENERATED_FLAG_PF) != 0u) ? 0x04u : 0u) | "
            "((generated_get_flag(state, GENERATED_FLAG_AF) != 0u) ? 0x10u : 0u) | "
            "((generated_get_flag(state, GENERATED_FLAG_ZF) != 0u) ? 0x40u : 0u) | "
            "((generated_get_flag(state, GENERATED_FLAG_SF) != 0u) ? 0x80u : 0u))");
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    case 0x9Eu:
        oss << "    generated_set_flag(state, GENERATED_FLAG_CF, (" << register8_value_expression(4u) << " & 0x01u) != 0u);\n";
        oss << "    generated_set_flag(state, GENERATED_FLAG_PF, (" << register8_value_expression(4u) << " & 0x04u) != 0u);\n";
        oss << "    generated_set_flag(state, GENERATED_FLAG_AF, (" << register8_value_expression(4u) << " & 0x10u) != 0u);\n";
        oss << "    generated_set_flag(state, GENERATED_FLAG_ZF, (" << register8_value_expression(4u) << " & 0x40u) != 0u);\n";
        oss << "    generated_set_flag(state, GENERATED_FLAG_SF, (" << register8_value_expression(4u) << " & 0x80u) != 0u);\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    case 0x98u:
        oss << "    state->ax = (uint16_t)((int16_t)(int8_t)(state->ax & 0x00FFu));\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    case 0x3Du: {
        const std::size_t imm_offset = instruction_prefix_length(instruction) + 1u;
        const std::uint16_t imm = instruction_u16(instruction, imm_offset);
        oss << "    generated_cmp_u16(state, state->ax, 0x" << hex4(imm) << ");\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }
    case 0x3Cu: {
        const std::size_t imm_offset = instruction_prefix_length(instruction) + 1u;
        const std::uint8_t imm = instruction.bytes.at(imm_offset);
        oss << "    generated_cmp_u8(state, " << register8_value_expression(0u)
            << ", 0x" << hex4(imm).substr(2) << "u);\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }
    case 0x2Cu: {
        const std::size_t imm_offset = instruction_prefix_length(instruction) + 1u;
        const std::uint8_t imm = instruction.bytes.at(imm_offset);
        emit_assign_sub_u8_register(
            oss,
            0u,
            register8_value_expression(0u),
            "0x" + hex4(imm).substr(2) + "u");
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }
    case 0x2Du: {
        const std::size_t imm_offset = instruction_prefix_length(instruction) + 1u;
        const std::uint16_t imm = instruction_u16(instruction, imm_offset);
        emit_assign_sub_u16(oss, "state->ax", "state->ax", "0x" + hex4(imm) + "u");
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }
    case 0xA8u: {
        const std::size_t imm_offset = instruction_prefix_length(instruction) + 1u;
        const std::uint8_t imm = instruction.bytes.at(imm_offset);
        oss << "    generated_test_u8(state, " << register8_value_expression(0u)
            << ", 0x" << hex4(imm).substr(2) << "u);\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }
    case 0x24u: {
        const std::size_t imm_offset = instruction_prefix_length(instruction) + 1u;
        const std::uint8_t imm = instruction.bytes.at(imm_offset);
        emit_assign_logic_u8_register(
            oss,
            0u,
            "(unsigned char)(" + register8_value_expression(0u) + " & 0x" + hex4(imm).substr(2) + "u)");
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }
    case 0x0Cu: {
        const std::size_t imm_offset = instruction_prefix_length(instruction) + 1u;
        const std::uint8_t imm = instruction.bytes.at(imm_offset);
        emit_assign_logic_u8_register(
            oss,
            0u,
            "(unsigned char)(" + register8_value_expression(0u) + " | 0x" + hex4(imm).substr(2) + "u)");
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }
    case 0x0Du: {
        const std::size_t imm_offset = instruction_prefix_length(instruction) + 1u;
        const std::uint16_t imm = instruction_u16(instruction, imm_offset);
        emit_assign_logic_u16(oss, "state->ax", "(uint16_t)(state->ax | 0x" + hex4(imm) + "u)");
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }
    case 0x25u: {
        const std::size_t imm_offset = instruction_prefix_length(instruction) + 1u;
        const std::uint16_t imm = instruction_u16(instruction, imm_offset);
        emit_assign_logic_u16(oss, "state->ax", "(uint16_t)(state->ax & 0x" + hex4(imm) + "u)");
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }
    case 0xA1u: {
        const std::size_t imm_offset = instruction_prefix_length(instruction) + 1u;
        const std::uint16_t direct_offset = instruction_u16(instruction, imm_offset);
        const std::string segment_field = override_segment_field_name(instruction).empty()
            ? "state->ds"
            : override_segment_field_name(instruction);
        if (const auto expr = named_static_read_u16_expression(
                segment_field, instruction.cs, direct_offset, instruction_entry_segment_state, false);
            expr.has_value()) {
            oss << "    state->ax = " << *expr << ";\n";
        } else {
            oss << "    state->ax = generated_read_u16(state, " << segment_field << ", "
                << direct_offset_text(segment_field, instruction.cs, direct_offset) << ");\n";
        }
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }
    case 0xA0u: {
        const std::size_t imm_offset = instruction_prefix_length(instruction) + 1u;
        const std::uint16_t direct_offset = instruction_u16(instruction, imm_offset);
        const std::string segment_field = override_segment_field_name(instruction).empty()
            ? "state->ds"
            : override_segment_field_name(instruction);
        const std::string value_expr =
            named_static_read_u8_expression(
                segment_field, instruction.cs, direct_offset, instruction_entry_segment_state, false)
                .value_or("generated_read_u8(state, " + segment_field + ", " +
                          direct_offset_text(segment_field, instruction.cs, direct_offset) + ")");
        oss << register8_set_statement(0u, value_expr);
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }
    case 0xA2u: {
        const std::size_t imm_offset = instruction_prefix_length(instruction) + 1u;
        const std::uint16_t direct_offset = instruction_u16(instruction, imm_offset);
        const std::string segment_field = override_segment_field_name(instruction).empty()
            ? "state->ds"
            : override_segment_field_name(instruction);
        if (const auto stmt = named_static_write_u8_statement(
                segment_field, instruction.cs, direct_offset, register8_value_expression(0u), instruction_entry_segment_state);
            stmt.has_value()) {
            oss << *stmt;
        } else {
            oss << "    generated_write_u8(state, " << segment_field << ", "
                << direct_offset_text(segment_field, instruction.cs, direct_offset)
                << ", " << register8_value_expression(0u) << ");\n";
        }
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }
    case 0xA3u: {
        const std::size_t imm_offset = instruction_prefix_length(instruction) + 1u;
        const std::uint16_t direct_offset = instruction_u16(instruction, imm_offset);
        const std::string segment_field = override_segment_field_name(instruction).empty()
            ? "state->ds"
            : override_segment_field_name(instruction);
        if (const auto stmt = named_static_write_u16_statement(
                segment_field, instruction.cs, direct_offset, "state->ax", instruction_entry_segment_state);
            stmt.has_value()) {
            oss << *stmt;
        } else {
            oss << "    generated_write_u16(state, " << segment_field << ", "
                << direct_offset_text(segment_field, instruction.cs, direct_offset)
                << ", state->ax);\n";
        }
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }
    case 0xCCu:
        oss << "    generated_interrupt(state, 0x03u);\n";
        oss << "    if (state->terminated) return;\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    case 0xCDu: {
        const std::size_t imm_offset = instruction_prefix_length(instruction) + 1u;
        const std::uint8_t vector = instruction.bytes.at(imm_offset);
        oss << "    generated_interrupt(state, 0x" << hex4(vector).substr(2) << "u);\n";
        oss << "    if (state->terminated) return;\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }
    case 0xE4u: {
        const std::size_t imm_offset = instruction_prefix_length(instruction) + 1u;
        const std::uint8_t port = instruction.bytes.at(imm_offset);
        oss << register8_set_statement(0u, "generated_port_in_u8(state, 0x" + hex4(port).substr(2) + "u)");
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }
    case 0xE5u: {
        const std::size_t imm_offset = instruction_prefix_length(instruction) + 1u;
        const std::uint8_t port = instruction.bytes.at(imm_offset);
        oss << "    state->ax = (uint16_t)((uint16_t)generated_port_in_u8(state, 0x" << hex4(port).substr(2) << "u) |\n";
        oss << "        (uint16_t)(((uint16_t)generated_port_in_u8(state, 0x"
            << hex4(static_cast<std::uint8_t>(port + 1u)).substr(2) << "u) & 0x00FFu) << 8u));\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }
    case 0xECu:
        oss << register8_set_statement(0u, "generated_port_in_u8(state, state->dx)");
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    case 0xEDu:
        oss << "    state->ax = (uint16_t)((uint16_t)generated_port_in_u8(state, state->dx) |\n";
        oss << "        (uint16_t)(((uint16_t)generated_port_in_u8(state, (uint16_t)(state->dx + 1u)) & 0x00FFu) << 8u));\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    case 0xEEu:
        oss << "    generated_port_out_u8(state, state->dx, " << register8_value_expression(0u) << ");\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    case 0xEFu:
        oss << "    generated_port_out_u16(state, state->dx, state->ax);\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    case 0x6Fu:
        oss << "    generated_port_out_u16(state, state->dx, generated_read_u16(state, state->ds, state->si));\n";
        oss << "    if (generated_get_flag(state, GENERATED_FLAG_DF)) {\n";
        oss << "        state->si = (uint16_t)(state->si - 2u);\n";
        oss << "    } else {\n";
        oss << "        state->si = (uint16_t)(state->si + 2u);\n";
        oss << "    }\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    case 0x9Au: {
        const std::size_t imm_offset = instruction_prefix_length(instruction) + 1u;
        const CodeLocation target{
            instruction_u16(instruction, imm_offset + 2u),
            instruction_u16(instruction, imm_offset),
        };
        emit_direct_call_return_setup(oss, instruction.cs, next_ip_text, true);
        oss << "    " << function_name(target) << "(state);\n";
        return true;
    }
    case 0xE6u: {
        const std::size_t imm_offset = instruction_prefix_length(instruction) + 1u;
        const std::uint8_t port = instruction.bytes.at(imm_offset);
        oss << "    generated_port_out_u8(state, 0x" << hex4(port).substr(2) << "u, "
            << register8_value_expression(0u) << ");\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }
    case 0xE8u: {
        if (!instruction.branch_target_ip.has_value()) {
            return false;
        }
        const CodeLocation target{
            instruction.branch_target_cs.value_or(instruction.cs),
            *instruction.branch_target_ip,
        };
        if (const auto standalone_spec_it = direct_standalone_call_target_specs.find(location_key(target));
            standalone_spec_it != direct_standalone_call_target_specs.end()) {
            emit_direct_standalone_helper_call(oss, standalone_spec_it->second);
            return true;
        }
        if (const auto typed_spec_it = direct_typed_call_target_specs.find(location_key(target));
            typed_spec_it != direct_typed_call_target_specs.end()) {
            emit_direct_typed_helper_call(oss, typed_spec_it->second);
            return true;
        }
        if (elidable_noop_call_target_keys.contains(location_key(target))) {
            oss << "    /* elided no-op helper call: " << function_name(target) << " */\n";
            return true;
        }
        emit_direct_call_return_setup(oss, instruction.cs, next_ip_text, false);
        oss << "    " << function_name(target) << "(state);\n";
        return true;
    }
    case 0xC2u: {
        const std::size_t imm_offset = instruction_prefix_length(instruction) + 1u;
        const std::uint16_t imm = instruction_u16(instruction, imm_offset);
        oss << "    state->ip = generated_pop_u16(state);\n";
        if (imm != 0u) {
            oss << "    state->sp = (uint16_t)(state->sp + 0x" << hex4(imm) << "u);\n";
        }
        oss << "    return;\n";
        return true;
    }
    case 0xC3u:
        oss << "    state->ip = generated_pop_u16(state);\n";
        oss << "    return;\n";
        return true;
    case 0xCBu:
        oss << "    state->ip = generated_pop_u16(state);\n";
        oss << "    state->cs = generated_pop_u16(state);\n";
        oss << "    return;\n";
        return true;
    case 0xCAu: {
        const std::size_t imm_offset = instruction_prefix_length(instruction) + 1u;
        const std::uint16_t imm = instruction_u16(instruction, imm_offset);
        oss << "    state->ip = generated_pop_u16(state);\n";
        oss << "    state->cs = generated_pop_u16(state);\n";
        if (imm != 0u) {
            oss << "    state->sp = (uint16_t)(state->sp + 0x" << hex4(imm) << "u);\n";
        }
        oss << "    return;\n";
        return true;
    }
    case 0xA4u:
    {
        const std::string source_segment_field = override_segment_field_name(instruction).empty()
            ? "state->ds"
            : override_segment_field_name(instruction);
        if (rep_prefix) {
            oss << "    while (state->cx != 0u) {\n";
            oss << "        const unsigned char generated_value = generated_read_u8(state, " << source_segment_field << ", state->si);\n";
            oss << "        generated_write_u8(state, state->es, state->di, generated_value);\n";
            oss << "        if (generated_get_flag(state, GENERATED_FLAG_DF)) {\n";
            oss << "            state->si = (uint16_t)(state->si - 1u);\n";
            oss << "            state->di = (uint16_t)(state->di - 1u);\n";
            oss << "        } else {\n";
            oss << "            state->si = (uint16_t)(state->si + 1u);\n";
            oss << "            state->di = (uint16_t)(state->di + 1u);\n";
            oss << "        }\n";
            oss << "        state->cx = (uint16_t)(state->cx - 1u);\n";
            oss << "    }\n";
        } else {
            oss << "    {\n";
            oss << "        const unsigned char generated_value = generated_read_u8(state, " << source_segment_field << ", state->si);\n";
            oss << "        generated_write_u8(state, state->es, state->di, generated_value);\n";
            oss << "    }\n";
            oss << "    if (generated_get_flag(state, GENERATED_FLAG_DF)) {\n";
            oss << "        state->si = (uint16_t)(state->si - 1u);\n";
            oss << "        state->di = (uint16_t)(state->di - 1u);\n";
            oss << "    } else {\n";
            oss << "        state->si = (uint16_t)(state->si + 1u);\n";
            oss << "        state->di = (uint16_t)(state->di + 1u);\n";
            oss << "    }\n";
        }
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }
    case 0xA5u:
    {
        const std::string source_segment_field = override_segment_field_name(instruction).empty()
            ? "state->ds"
            : override_segment_field_name(instruction);
        if (rep_prefix) {
            oss << "    while (state->cx != 0u) {\n";
            oss << "        const uint16_t generated_value = generated_read_u16(state, " << source_segment_field << ", state->si);\n";
            oss << "        generated_write_u16(state, state->es, state->di, generated_value);\n";
            oss << "        if (generated_get_flag(state, GENERATED_FLAG_DF)) {\n";
            oss << "            state->si = (uint16_t)(state->si - 2u);\n";
            oss << "            state->di = (uint16_t)(state->di - 2u);\n";
            oss << "        } else {\n";
            oss << "            state->si = (uint16_t)(state->si + 2u);\n";
            oss << "            state->di = (uint16_t)(state->di + 2u);\n";
            oss << "        }\n";
            oss << "        state->cx = (uint16_t)(state->cx - 1u);\n";
            oss << "    }\n";
        } else {
            oss << "    {\n";
            oss << "        const uint16_t generated_value = generated_read_u16(state, " << source_segment_field << ", state->si);\n";
            oss << "        generated_write_u16(state, state->es, state->di, generated_value);\n";
            oss << "    }\n";
            oss << "    if (generated_get_flag(state, GENERATED_FLAG_DF)) {\n";
            oss << "        state->si = (uint16_t)(state->si - 2u);\n";
            oss << "        state->di = (uint16_t)(state->di - 2u);\n";
            oss << "    } else {\n";
            oss << "        state->si = (uint16_t)(state->si + 2u);\n";
            oss << "        state->di = (uint16_t)(state->di + 2u);\n";
            oss << "    }\n";
        }
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }
    case 0xA6u:
    {
        const std::string source_segment_field = override_segment_field_name(instruction).empty()
            ? "state->ds"
            : override_segment_field_name(instruction);
        const bool repeat_compare = rep_prefix || repne_prefix;
        if (repeat_compare) {
            oss << "    while (state->cx != 0u) {\n";
            oss << "        const unsigned char generated_left = generated_read_u8(state, " << source_segment_field << ", state->si);\n";
            oss << "        const unsigned char generated_right = generated_read_u8(state, state->es, state->di);\n";
            oss << "        generated_cmp_u8(state, generated_left, generated_right);\n";
            oss << "        if (generated_get_flag(state, GENERATED_FLAG_DF)) {\n";
            oss << "            state->si = (uint16_t)(state->si - 1u);\n";
            oss << "            state->di = (uint16_t)(state->di - 1u);\n";
            oss << "        } else {\n";
            oss << "            state->si = (uint16_t)(state->si + 1u);\n";
            oss << "            state->di = (uint16_t)(state->di + 1u);\n";
            oss << "        }\n";
            oss << "        state->cx = (uint16_t)(state->cx - 1u);\n";
            if (rep_prefix) {
                oss << "        if (!generated_get_flag(state, GENERATED_FLAG_ZF)) break;\n";
            } else {
                oss << "        if (generated_get_flag(state, GENERATED_FLAG_ZF)) break;\n";
            }
            oss << "    }\n";
        } else {
            oss << "    generated_cmp_u8(state,\n";
            oss << "        generated_read_u8(state, " << source_segment_field << ", state->si),\n";
            oss << "        generated_read_u8(state, state->es, state->di));\n";
            oss << "    if (generated_get_flag(state, GENERATED_FLAG_DF)) {\n";
            oss << "        state->si = (uint16_t)(state->si - 1u);\n";
            oss << "        state->di = (uint16_t)(state->di - 1u);\n";
            oss << "    } else {\n";
            oss << "        state->si = (uint16_t)(state->si + 1u);\n";
            oss << "        state->di = (uint16_t)(state->di + 1u);\n";
            oss << "    }\n";
        }
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }
    case 0xAAu:
        if (rep_prefix) {
            oss << "    while (state->cx != 0u) {\n";
            oss << "        generated_write_u8(state, state->es, state->di, " << register8_value_expression(0u) << ");\n";
            oss << "        if (generated_get_flag(state, GENERATED_FLAG_DF)) {\n";
            oss << "            state->di = (uint16_t)(state->di - 1u);\n";
            oss << "        } else {\n";
            oss << "            state->di = (uint16_t)(state->di + 1u);\n";
            oss << "        }\n";
            oss << "        state->cx = (uint16_t)(state->cx - 1u);\n";
            oss << "    }\n";
        } else {
            oss << "    generated_write_u8(state, state->es, state->di, " << register8_value_expression(0u) << ");\n";
            oss << "    if (generated_get_flag(state, GENERATED_FLAG_DF)) {\n";
            oss << "        state->di = (uint16_t)(state->di - 1u);\n";
            oss << "    } else {\n";
            oss << "        state->di = (uint16_t)(state->di + 1u);\n";
            oss << "    }\n";
        }
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    case 0xABu:
        if (rep_prefix) {
            oss << "    while (state->cx != 0u) {\n";
            oss << "        generated_write_u16(state, state->es, state->di, state->ax);\n";
            oss << "        if (generated_get_flag(state, GENERATED_FLAG_DF)) {\n";
            oss << "            state->di = (uint16_t)(state->di - 2u);\n";
            oss << "        } else {\n";
            oss << "            state->di = (uint16_t)(state->di + 2u);\n";
            oss << "        }\n";
            oss << "        state->cx = (uint16_t)(state->cx - 1u);\n";
            oss << "    }\n";
        } else {
            oss << "    generated_write_u16(state, state->es, state->di, state->ax);\n";
            oss << "    if (generated_get_flag(state, GENERATED_FLAG_DF)) {\n";
            oss << "        state->di = (uint16_t)(state->di - 2u);\n";
            oss << "    } else {\n";
            oss << "        state->di = (uint16_t)(state->di + 2u);\n";
            oss << "    }\n";
        }
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    case 0xACu:
    {
        const std::string source_segment_field = override_segment_field_name(instruction).empty()
            ? "state->ds"
            : override_segment_field_name(instruction);
        if (rep_prefix) {
            oss << "    while (state->cx != 0u) {\n";
            oss << register8_set_statement(0u, "generated_read_u8(state, " + source_segment_field + ", state->si)");
            oss << "        if (generated_get_flag(state, GENERATED_FLAG_DF)) {\n";
            oss << "            state->si = (uint16_t)(state->si - 1u);\n";
            oss << "        } else {\n";
            oss << "            state->si = (uint16_t)(state->si + 1u);\n";
            oss << "        }\n";
            oss << "        state->cx = (uint16_t)(state->cx - 1u);\n";
            oss << "    }\n";
        } else {
            oss << register8_set_statement(0u, "generated_read_u8(state, " + source_segment_field + ", state->si)");
            oss << "    if (generated_get_flag(state, GENERATED_FLAG_DF)) {\n";
            oss << "        state->si = (uint16_t)(state->si - 1u);\n";
            oss << "    } else {\n";
            oss << "        state->si = (uint16_t)(state->si + 1u);\n";
            oss << "    }\n";
        }
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }
    case 0xADu:
    {
        const std::string source_segment_field = override_segment_field_name(instruction).empty()
            ? "state->ds"
            : override_segment_field_name(instruction);
        if (rep_prefix) {
            oss << "    while (state->cx != 0u) {\n";
            oss << "        state->ax = generated_read_u16(state, " << source_segment_field << ", state->si);\n";
            oss << "        if (generated_get_flag(state, GENERATED_FLAG_DF)) {\n";
                oss << "            state->si = (uint16_t)(state->si - 2u);\n";
            oss << "        } else {\n";
            oss << "            state->si = (uint16_t)(state->si + 2u);\n";
            oss << "        }\n";
            oss << "        state->cx = (uint16_t)(state->cx - 1u);\n";
            oss << "    }\n";
        } else {
            oss << "    state->ax = generated_read_u16(state, " << source_segment_field << ", state->si);\n";
            oss << "    if (generated_get_flag(state, GENERATED_FLAG_DF)) {\n";
            oss << "        state->si = (uint16_t)(state->si - 2u);\n";
            oss << "    } else {\n";
            oss << "        state->si = (uint16_t)(state->si + 2u);\n";
            oss << "    }\n";
        }
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }
    case 0xE9u:
    case 0xEBu: {
        if (!instruction.branch_target_ip.has_value()) {
            return false;
        }
        CodeLocation target{
            instruction.branch_target_cs.value_or(instruction.cs),
            *instruction.branch_target_ip,
        };
        const std::uint32_t target_key = location_key(target);
        if (function_block_keys.contains(target_key) ||
            (function_label_keys.contains(target_key) && target_key < instruction_key)) {
            oss << "    goto " << block_label_name(target) << ";\n";
            return true;
        }
        return false;
    }
    case 0x70u:
    case 0x71u:
    case 0x72u:
    case 0x73u:
    case 0x74u:
    case 0x75u:
    case 0x76u:
    case 0x77u:
    case 0x78u:
    case 0x79u:
    case 0x7Au:
    case 0x7Bu:
    case 0x7Cu:
    case 0x7Du:
    case 0x7Eu:
    case 0x7Fu:
        if (!instruction.branch_target_ip.has_value() || !instruction.branch_fallthrough_ip.has_value()) {
            return false;
        } else {
            CodeLocation branch_target{
                instruction.branch_target_cs.value_or(instruction.cs),
                *instruction.branch_target_ip,
            };
            CodeLocation fallthrough_target{instruction.cs, *instruction.branch_fallthrough_ip};
            const std::uint32_t branch_key = location_key(branch_target);
            const std::uint32_t fallthrough_key = location_key(fallthrough_target);
            const bool branch_ok = function_block_keys.contains(branch_key) ||
                (function_label_keys.contains(branch_key) && branch_key < instruction_key);
            const bool fallthrough_ok = function_block_keys.contains(fallthrough_key) ||
                (function_label_keys.contains(fallthrough_key) && fallthrough_key < instruction_key);
            if (!branch_ok || !fallthrough_ok) {
                return false;
            }
            oss << "    if (generated_check_condition(state, 0x" << hex4(opcode).substr(2) << "u)) goto "
                << block_label_name(branch_target) << ";\n";
            if (!next_emitted_location.has_value() || !same_location(*next_emitted_location, fallthrough_target)) {
                oss << "    goto " << block_label_name(fallthrough_target) << ";\n";
            }
            return true;
        }
    case 0xE2u:
        if (!instruction.branch_target_ip.has_value() || !instruction.branch_fallthrough_ip.has_value()) {
            return false;
        } else {
            CodeLocation branch_target{
                instruction.branch_target_cs.value_or(instruction.cs),
                *instruction.branch_target_ip,
            };
            CodeLocation fallthrough_target{instruction.cs, *instruction.branch_fallthrough_ip};
            const std::uint32_t branch_key = location_key(branch_target);
            const std::uint32_t fallthrough_key = location_key(fallthrough_target);
            const bool branch_ok = function_block_keys.contains(branch_key) ||
                (function_label_keys.contains(branch_key) && branch_key < instruction_key);
            const bool fallthrough_ok = function_block_keys.contains(fallthrough_key) ||
                (function_label_keys.contains(fallthrough_key) && fallthrough_key < instruction_key);
            if (!branch_ok || !fallthrough_ok) {
                return false;
            }
            oss << "    state->cx = (uint16_t)(state->cx - 1u);\n";
            oss << "    if (state->cx != 0u) goto " << block_label_name(branch_target) << ";\n";
            if (!next_emitted_location.has_value() || !same_location(*next_emitted_location, fallthrough_target)) {
                oss << "    goto " << block_label_name(fallthrough_target) << ";\n";
            }
            return true;
        }
    case 0xE3u:
        if (!instruction.branch_target_ip.has_value() || !instruction.branch_fallthrough_ip.has_value()) {
            return false;
        } else {
            CodeLocation branch_target{
                instruction.branch_target_cs.value_or(instruction.cs),
                *instruction.branch_target_ip,
            };
            CodeLocation fallthrough_target{instruction.cs, *instruction.branch_fallthrough_ip};
            const std::uint32_t branch_key = location_key(branch_target);
            const std::uint32_t fallthrough_key = location_key(fallthrough_target);
            const bool branch_ok = function_block_keys.contains(branch_key) ||
                (function_label_keys.contains(branch_key) && branch_key < instruction_key);
            const bool fallthrough_ok = function_block_keys.contains(fallthrough_key) ||
                (function_label_keys.contains(fallthrough_key) && fallthrough_key < instruction_key);
            if (!branch_ok || !fallthrough_ok) {
                return false;
            }
            oss << "    if (state->cx == 0u) goto " << block_label_name(branch_target) << ";\n";
            if (!next_emitted_location.has_value() || !same_location(*next_emitted_location, fallthrough_target)) {
                oss << "    goto " << block_label_name(fallthrough_target) << ";\n";
            }
            return true;
        }
    }

    if (opcode >= 0xB8u && opcode <= 0xBFu) {
        const std::size_t imm_offset = instruction_prefix_length(instruction) + 1u;
        const std::uint16_t imm = instruction_u16(instruction, imm_offset);
        oss << "    " << register16_field_name(static_cast<std::uint8_t>(opcode - 0xB8u))
            << " = 0x" << hex4(imm) << ";\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }

    if (opcode >= 0xB0u && opcode <= 0xB7u) {
        const std::size_t imm_offset = instruction_prefix_length(instruction) + 1u;
        const std::uint8_t imm = instruction.bytes.at(imm_offset);
        oss << register8_set_statement(static_cast<std::uint8_t>(opcode - 0xB0u), "0x" + hex4(imm).substr(2) + "u");
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }

    if (opcode >= 0x50u && opcode <= 0x57u) {
        oss << "    generated_push_u16(state, " << register16_field_name(static_cast<std::uint8_t>(opcode - 0x50u))
            << ");\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }

    if (opcode >= 0x58u && opcode <= 0x5Fu) {
        oss << "    " << register16_field_name(static_cast<std::uint8_t>(opcode - 0x58u))
            << " = generated_pop_u16(state);\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }

    if (opcode >= 0x90u && opcode <= 0x97u) {
        if (opcode == 0x90u) {
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }
        const std::string other = register16_field_name(static_cast<std::uint8_t>(opcode & 0x07u));
        oss << "    {\n";
        oss << "        const uint16_t generated_temp = state->ax;\n";
        oss << "        state->ax = " << other << ";\n";
        oss << "        " << other << " = generated_temp;\n";
        oss << "    }\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }

    if (opcode >= 0x40u && opcode <= 0x4Fu) {
        const std::string value = register16_field_name(static_cast<std::uint8_t>(opcode & 0x07u));
        const bool is_increment = opcode < 0x48u;
        if (is_increment) {
            emit_assign_inc_u16(oss, value, value);
        } else {
            emit_assign_dec_u16(oss, value, value);
        }
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }

    if (opcode == 0xACu) {
        oss << register8_set_statement(0u, "generated_read_u8(state, state->ds, state->si)");
        oss << "    if (generated_get_flag(state, GENERATED_FLAG_DF)) {\n";
        oss << "        state->si = (uint16_t)(state->si - 1u);\n";
        oss << "    } else {\n";
        oss << "        state->si = (uint16_t)(state->si + 1u);\n";
        oss << "    }\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }

    if (opcode == 0xADu) {
        oss << "    state->ax = generated_read_u16(state, state->ds, state->si);\n";
        oss << "    if (generated_get_flag(state, GENERATED_FLAG_DF)) {\n";
        oss << "        state->si = (uint16_t)(state->si - 2u);\n";
        oss << "    } else {\n";
        oss << "        state->si = (uint16_t)(state->si + 2u);\n";
        oss << "    }\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }

    if (opcode == 0xC8u) {
        const std::uint16_t frame_size = instruction_u16(instruction, 1u);
        const std::uint8_t nesting = static_cast<std::uint8_t>(instruction.bytes.at(3u) & 0x1Fu);
        oss << "    {\n";
        oss << "        const uint16_t generated_old_bp = state->bp;\n";
        oss << "        generated_push_u16(state, generated_old_bp);\n";
        oss << "        const uint16_t generated_frame = state->sp;\n";
        if (nesting != 0u) {
            for (std::uint8_t depth = 1u; depth < nesting; ++depth) {
                oss << "        state->bp = (uint16_t)(state->bp - 2u);\n";
                oss << "        generated_push_u16(state, generated_read_u16(state, state->ss, state->bp));\n";
            }
            oss << "        generated_push_u16(state, generated_frame);\n";
        }
        oss << "        state->bp = generated_frame;\n";
        if (frame_size != 0u) {
            oss << "        state->sp = (uint16_t)(state->sp - 0x" << hex4(frame_size) << "u);\n";
        }
        oss << "    }\n";
        emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
        return true;
    }

    if (opcode == 0x88u || opcode == 0x8Au || opcode == 0x8Cu || opcode == 0x8Du || opcode == 0x8Eu ||
        opcode == 0x89u || opcode == 0x8Bu || opcode == 0xC7u || opcode == 0xC6u ||
        opcode == 0x81u || opcode == 0x8Fu || opcode == 0xFFu ||
        opcode == 0xF6u || opcode == 0x80u || opcode == 0x83u || opcode == 0x33u ||
        opcode == 0x32u || opcode == 0xFEu || opcode == 0x20u || opcode == 0x21u || opcode == 0x22u ||
        opcode == 0x23u || opcode == 0x30u || opcode == 0x08u || opcode == 0x09u || opcode == 0x0Bu || opcode == 0x84u || opcode == 0x85u ||
        opcode == 0x2Bu || opcode == 0x2Au || opcode == 0x29u || opcode == 0x28u ||
        opcode == 0x01u || opcode == 0x03u || opcode == 0x00u || opcode == 0x39u || opcode == 0xC4u || opcode == 0xC5u || opcode == 0xD1u || opcode == 0xD0u ||
        opcode == 0xD2u || opcode == 0xD3u ||
        opcode == 0x02u || opcode == 0x0Au || opcode == 0x38u || opcode == 0x3Au || opcode == 0x86u || opcode == 0x87u || opcode == 0x3Bu || opcode == 0xF7u) {
        std::size_t modrm_offset = 0u;
        std::uint8_t modrm = 0u;
        bool is_register = false;
        std::string segment_field;
        std::string offset_expression;
        std::optional<std::uint16_t> direct_offset;
        if (!decode_modrm_operand(
                instruction, modrm_offset, modrm, is_register, segment_field, offset_expression, &direct_offset)) {
            return false;
        }

        const std::uint8_t reg_field = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
        const std::uint8_t rm_field = static_cast<std::uint8_t>(modrm & 0x07u);

        if (opcode == 0x88u) {
            if (is_register) {
                oss << register8_set_statement(rm_field, register8_value_expression(reg_field));
            } else {
                if (direct_offset.has_value()) {
                    if (const auto stmt = named_static_write_u8_statement(
                            segment_field, instruction.cs, *direct_offset, register8_value_expression(reg_field), instruction_entry_segment_state);
                        stmt.has_value()) {
                        oss << *stmt;
                    } else {
                        oss << "    generated_write_u8(state, " << segment_field << ", " << offset_expression
                            << ", " << register8_value_expression(reg_field) << ");\n";
                    }
                } else {
                    oss << "    generated_write_u8(state, " << segment_field << ", " << offset_expression
                        << ", " << register8_value_expression(reg_field) << ");\n";
                }
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x8Au) {
            if (is_register) {
                oss << register8_set_statement(reg_field, register8_value_expression(rm_field));
            } else {
                const std::string value_expr =
                    direct_offset.has_value()
                        ? named_static_read_u8_expression(
                              segment_field, instruction.cs, *direct_offset, instruction_entry_segment_state, false)
                              .value_or("generated_read_u8(state, " + segment_field + ", " + offset_expression + ")")
                        : "generated_read_u8(state, " + segment_field + ", " + offset_expression + ")";
                oss << register8_set_statement(
                    reg_field,
                    value_expr);
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x86u) {
            if (is_register) {
                oss << "    {\n";
                oss << "        const unsigned char generated_temp = " << register8_value_expression(rm_field) << ";\n";
                oss << register8_set_statement(rm_field, register8_value_expression(reg_field));
                oss << register8_set_statement(reg_field, "generated_temp");
                oss << "    }\n";
            } else {
                oss << "    {\n";
                oss << "        const unsigned char generated_temp = " <<
                    (direct_offset.has_value()
                        ? named_static_read_u8_expression(
                              segment_field, instruction.cs, *direct_offset, instruction_entry_segment_state, false)
                              .value_or("generated_read_u8(state, " + segment_field + ", " + offset_expression + ")")
                        : "generated_read_u8(state, " + segment_field + ", " + offset_expression + ")") << ";\n";
                if (direct_offset.has_value()) {
                    if (const auto stmt = named_static_write_u8_statement(
                            segment_field, instruction.cs, *direct_offset, register8_value_expression(reg_field), instruction_entry_segment_state);
                        stmt.has_value()) {
                        oss << *stmt;
                    } else {
                        oss << "        generated_write_u8(state, " << segment_field << ", " << offset_expression
                            << ", " << register8_value_expression(reg_field) << ");\n";
                    }
                } else {
                    oss << "        generated_write_u8(state, " << segment_field << ", " << offset_expression
                        << ", " << register8_value_expression(reg_field) << ");\n";
                }
                oss << register8_set_statement(reg_field, "generated_temp");
                oss << "    }\n";
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x87u) {
            if (is_register) {
                oss << "    {\n";
                oss << "        const uint16_t generated_temp = " << register16_field_name(rm_field) << ";\n";
                oss << "        " << register16_field_name(rm_field) << " = " << register16_field_name(reg_field) << ";\n";
                oss << "        " << register16_field_name(reg_field) << " = generated_temp;\n";
                oss << "    }\n";
            } else {
                oss << "    {\n";
                oss << "        const uint16_t generated_temp = " <<
                    (direct_offset.has_value()
                        ? named_static_read_u16_expression(
                              segment_field, instruction.cs, *direct_offset, instruction_entry_segment_state, false)
                              .value_or("generated_read_u16(state, " + segment_field + ", " + offset_expression + ")")
                        : "generated_read_u16(state, " + segment_field + ", " + offset_expression + ")") << ";\n";
                if (direct_offset.has_value()) {
                    if (const auto stmt = named_static_write_u16_statement(
                            segment_field, instruction.cs, *direct_offset, register16_field_name(reg_field), instruction_entry_segment_state);
                        stmt.has_value()) {
                        oss << *stmt;
                    } else {
                        oss << "        generated_write_u16(state, " << segment_field << ", " << offset_expression
                            << ", " << register16_field_name(reg_field) << ");\n";
                    }
                } else {
                    oss << "        generated_write_u16(state, " << segment_field << ", " << offset_expression
                        << ", " << register16_field_name(reg_field) << ");\n";
                }
                oss << "        " << register16_field_name(reg_field) << " = generated_temp;\n";
                oss << "    }\n";
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x8Cu) {
            const std::string source_field = segment_field_name_from_index(reg_field);
            if (is_register) {
                oss << "    " << register16_field_name(rm_field) << " = " << source_field << ";\n";
            } else {
                if (direct_offset.has_value()) {
                    if (const auto stmt =
                            named_static_write_u16_statement(segment_field, instruction.cs, *direct_offset, source_field, instruction_entry_segment_state);
                        stmt.has_value()) {
                        oss << *stmt;
                    } else {
                        oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                            << ", " << source_field << ");\n";
                    }
                } else {
                    oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                        << ", " << source_field << ");\n";
                }
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x8Eu) {
            if (is_register) {
                oss << "    " << segment_field_name_from_index(reg_field) << " = "
                    << register16_field_name(rm_field) << ";\n";
            } else {
                const std::string value_expr =
                    direct_offset.has_value()
                        ? named_static_read_u16_expression(
                              segment_field, instruction.cs, *direct_offset, instruction_entry_segment_state, false)
                              .value_or("generated_read_u16(state, " + segment_field + ", " + offset_expression + ")")
                        : "generated_read_u16(state, " + segment_field + ", " + offset_expression + ")";
                oss << "    " << segment_field_name_from_index(reg_field)
                    << " = " << value_expr << ";\n";
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x89u) {
            if (is_register) {
                oss << "    " << register16_field_name(rm_field) << " = "
                    << register16_field_name(reg_field) << ";\n";
            } else {
                if (direct_offset.has_value()) {
                    if (const auto stmt = named_static_write_u16_statement(
                            segment_field, instruction.cs, *direct_offset, register16_field_name(reg_field), instruction_entry_segment_state);
                        stmt.has_value()) {
                        oss << *stmt;
                    } else {
                        oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                            << ", " << register16_field_name(reg_field) << ");\n";
                    }
                } else {
                    oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                        << ", " << register16_field_name(reg_field) << ");\n";
                }
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x8Bu) {
            if (is_register) {
                oss << "    " << register16_field_name(reg_field) << " = "
                    << register16_field_name(rm_field) << ";\n";
            } else {
                const std::string value_expr =
                    direct_offset.has_value()
                        ? named_static_read_u16_expression(
                              segment_field, instruction.cs, *direct_offset, instruction_entry_segment_state, false)
                              .value_or("generated_read_u16(state, " + segment_field + ", " + offset_expression + ")")
                        : "generated_read_u16(state, " + segment_field + ", " + offset_expression + ")";
                oss << "    " << register16_field_name(reg_field)
                    << " = " << value_expr << ";\n";
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x8Du && !is_register) {
            oss << "    " << register16_field_name(reg_field) << " = " << offset_expression << ";\n";
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if ((opcode == 0xC4u || opcode == 0xC5u) && !is_register) {
            const std::string first_word_expr =
                direct_offset.has_value()
                    ? named_static_read_u16_expression(
                          segment_field, instruction.cs, *direct_offset, instruction_entry_segment_state, false)
                          .value_or("generated_read_u16(state, " + segment_field + ", " + offset_expression + ")")
                    : "generated_read_u16(state, " + segment_field + ", " + offset_expression + ")";
            oss << "    " << register16_field_name(reg_field) << " = " << first_word_expr << ";\n";
            oss << "    state->" << (opcode == 0xC4u ? "es" : "ds")
                << " = generated_read_u16(state, " << segment_field << ", (uint16_t)("
                << offset_expression << " + 2u));\n";
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        const std::uint8_t mod = static_cast<std::uint8_t>((modrm >> 6u) & 0x03u);
        const std::size_t displacement_size = is_register ? 0u
            : ((mod == 0x00u && rm_field == 0x06u) ? 2u
               : (mod == 0x01u ? 1u
                  : (mod == 0x02u ? 2u : 0u)));
        const std::string direct_read_u8_expr = is_register
            ? std::string{}
            : (direct_offset.has_value()
                   ? named_static_read_u8_expression(
                         segment_field, instruction.cs, *direct_offset, instruction_entry_segment_state, false)
                         .value_or("generated_read_u8(state, " + segment_field + ", " + offset_expression + ")")
                   : "generated_read_u8(state, " + segment_field + ", " + offset_expression + ")");
        const std::string direct_read_u16_expr = is_register
            ? std::string{}
            : (direct_offset.has_value()
                   ? named_static_read_u16_expression(
                         segment_field, instruction.cs, *direct_offset, instruction_entry_segment_state, false)
                         .value_or("generated_read_u16(state, " + segment_field + ", " + offset_expression + ")")
                   : "generated_read_u16(state, " + segment_field + ", " + offset_expression + ")");

        if (opcode == 0x8Fu && reg_field == 0u) {
            if (is_register) {
                oss << "    " << register16_field_name(rm_field) << " = generated_pop_u16(state);\n";
            } else {
                if (direct_offset.has_value()) {
                    if (const auto stmt = named_static_write_u16_statement(
                            segment_field, instruction.cs, *direct_offset, "generated_pop_u16(state)", instruction_entry_segment_state);
                        stmt.has_value()) {
                        oss << *stmt;
                    } else {
                        oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                            << ", generated_pop_u16(state));\n";
                    }
                } else {
                    oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                        << ", generated_pop_u16(state));\n";
                }
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0xFFu && reg_field <= 1u) {
            if (is_register) {
                const std::string value = register16_field_name(rm_field);
                if (reg_field == 0u) {
                    emit_assign_inc_u16(oss, value, value);
                } else {
                    emit_assign_dec_u16(oss, value, value);
                }
            } else {
                if (reg_field == 0u) {
                    if (direct_offset.has_value()) {
                        if (const auto stmt = named_static_write_u16_statement(
                                segment_field,
                                instruction.cs,
                                *direct_offset,
                                "generated_inc_u16(state, " + direct_read_u16_expr + ")",
                                instruction_entry_segment_state);
                            stmt.has_value()) {
                            oss << *stmt;
                        } else {
                            oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                                << ", generated_inc_u16(state, generated_read_u16(state, " << segment_field << ", "
                                << offset_expression << ")));\n";
                        }
                    } else {
                        oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                            << ", generated_inc_u16(state, generated_read_u16(state, " << segment_field << ", "
                            << offset_expression << ")));\n";
                    }
                } else {
                    if (direct_offset.has_value()) {
                        if (const auto stmt = named_static_write_u16_statement(
                                segment_field,
                                instruction.cs,
                                *direct_offset,
                                "generated_dec_u16(state, " + direct_read_u16_expr + ")",
                                instruction_entry_segment_state);
                            stmt.has_value()) {
                            oss << *stmt;
                        } else {
                            oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                                << ", generated_dec_u16(state, generated_read_u16(state, " << segment_field << ", "
                                << offset_expression << ")));\n";
                        }
                    } else {
                        oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                            << ", generated_dec_u16(state, generated_read_u16(state, " << segment_field << ", "
                            << offset_expression << ")));\n";
                    }
                }
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0xFFu && reg_field == 6u) {
            if (is_register) {
                oss << "    generated_push_u16(state, " << register16_field_name(rm_field) << ");\n";
            } else {
                oss << "    generated_push_u16(state, " << direct_read_u16_expr << ");\n";
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0xC7u && reg_field == 0u && !is_register) {
            const std::uint16_t imm = instruction_u16(instruction, modrm_offset + 1u + displacement_size);
            if (direct_offset.has_value()) {
                if (const auto stmt = named_static_write_u16_statement(
                        segment_field, instruction.cs, *direct_offset, "0x" + hex4(imm), instruction_entry_segment_state);
                    stmt.has_value()) {
                    oss << *stmt;
                } else {
                    oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                        << ", 0x" << hex4(imm) << "u);\n";
                }
            } else {
                oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                    << ", 0x" << hex4(imm) << "u);\n";
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0xC6u && reg_field == 0u && !is_register) {
            const std::uint8_t imm = instruction.bytes.at(modrm_offset + 1u + displacement_size);
            if (direct_offset.has_value()) {
                if (const auto stmt = named_static_write_u8_statement(
                        segment_field, instruction.cs, *direct_offset, "0x" + hex4(imm).substr(2) + "u", instruction_entry_segment_state);
                    stmt.has_value()) {
                    oss << *stmt;
                } else {
                    oss << "    generated_write_u8(state, " << segment_field << ", " << offset_expression
                        << ", 0x" << hex4(imm).substr(2) << "u);\n";
                }
            } else {
                oss << "    generated_write_u8(state, " << segment_field << ", " << offset_expression
                    << ", 0x" << hex4(imm).substr(2) << "u);\n";
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0xF6u && reg_field == 0u && !is_register) {
            const std::uint8_t imm = instruction.bytes.at(modrm_offset + 1u + displacement_size);
            oss << "    generated_test_u8(state, " << direct_read_u8_expr
                << ", 0x" << hex4(imm).substr(2) << "u);\n";
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0xF6u && reg_field == 0u && is_register) {
            const std::uint8_t imm = instruction.bytes.at(modrm_offset + 1u + displacement_size);
            oss << "    generated_test_u8(state, " << register8_value_expression(rm_field)
                << ", 0x" << hex4(imm).substr(2) << "u);\n";
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x84u) {
            if (is_register) {
                oss << "    generated_test_u8(state, " << register8_value_expression(rm_field)
                    << ", " << register8_value_expression(reg_field) << ");\n";
            } else {
                oss << "    generated_test_u8(state, " << direct_read_u8_expr
                    << ", " << register8_value_expression(reg_field) << ");\n";
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x38u) {
            if (is_register) {
                oss << "    generated_cmp_u8(state, " << register8_value_expression(rm_field)
                    << ", " << register8_value_expression(reg_field) << ");\n";
            } else {
                oss << "    generated_cmp_u8(state, " << direct_read_u8_expr
                    << ", " << register8_value_expression(reg_field) << ");\n";
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x85u) {
            if (is_register) {
                oss << "    generated_test_u16(state, " << register16_field_name(rm_field)
                    << ", " << register16_field_name(reg_field) << ");\n";
            } else {
                oss << "    generated_test_u16(state, " << direct_read_u16_expr
                    << ", " << register16_field_name(reg_field) << ");\n";
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0xF7u && reg_field == 0u) {
            const std::uint16_t imm = instruction_u16(instruction, modrm_offset + 1u + displacement_size);
            if (is_register) {
                oss << "    generated_test_u16(state, " << register16_field_name(rm_field)
                    << ", 0x" << hex4(imm) << "u);\n";
            } else {
                oss << "    generated_test_u16(state, " << direct_read_u16_expr
                    << ", 0x" << hex4(imm) << "u);\n";
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0xF6u && reg_field == 6u) {
            const std::string divisor = is_register
                ? register8_value_expression(rm_field)
                : direct_read_u8_expr;
            oss << "    {\n";
            oss << "        const unsigned char generated_divisor = " << divisor << ";\n";
            oss << "        const unsigned int generated_dividend = (unsigned int)state->ax;\n";
            oss << "        if (generated_divisor == 0u) {\n";
            oss << "            generated_runtime_note_call(state, \"divide_error_f6\");\n";
            oss << "            state->terminated = 1u;\n";
            oss << "            return;\n";
            oss << "        }\n";
            oss << "        const unsigned int generated_quotient = generated_dividend / generated_divisor;\n";
            oss << "        const unsigned int generated_remainder = generated_dividend % generated_divisor;\n";
            oss << "        if (generated_quotient > 0xFFu) {\n";
            oss << "            generated_runtime_note_call(state, \"divide_overflow_f6\");\n";
            oss << "            state->terminated = 1u;\n";
            oss << "            return;\n";
            oss << "        }\n";
            oss << "        state->ax = (uint16_t)(((generated_remainder & 0xFFu) << 8u) | (generated_quotient & 0xFFu));\n";
            oss << "    }\n";
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0xF6u && reg_field == 2u) {
            if (is_register) {
                oss << register8_set_statement(rm_field,
                    "(unsigned char)(~" + register8_value_expression(rm_field) + ")");
            } else {
                oss << "    generated_write_u8(state, " << segment_field << ", " << offset_expression
                    << ", (unsigned char)(~generated_read_u8(state, " << segment_field << ", " << offset_expression
                    << ")));\n";
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0xF6u && reg_field == 3u) {
            const std::string operand = is_register
                ? register8_value_expression(rm_field)
                : "generated_read_u8(state, " + segment_field + ", " + offset_expression + ")";
            if (is_register) {
                oss << register8_set_statement(rm_field, "generated_neg_u8(state, " + operand + ")");
            } else {
                oss << "        generated_write_u8(state, " << segment_field << ", " << offset_expression
                    << ", generated_neg_u8(state, " << operand << "));\n";
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0xF6u && reg_field == 4u) {
            const std::string multiplier = is_register
                ? register8_value_expression(rm_field)
                : direct_read_u8_expr;
            oss << "    generated_mul_u8(state, " << multiplier << ");\n";
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0xF6u && reg_field == 5u) {
            const std::string multiplier = is_register
                ? register8_value_expression(rm_field)
                : direct_read_u8_expr;
            oss << "    generated_imul_u8(state, " << multiplier << ");\n";
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0xF6u && reg_field == 7u) {
            const std::string divisor = is_register
                ? register8_value_expression(rm_field)
                : direct_read_u8_expr;
            oss << "    {\n";
            oss << "        const signed char generated_divisor = (signed char)" << divisor << ";\n";
            oss << "        const short generated_dividend = (short)state->ax;\n";
            oss << "        if (generated_divisor == 0) {\n";
            oss << "            generated_runtime_note_call(state, \"divide_error_f6_idiv\");\n";
            oss << "            state->terminated = 1u;\n";
            oss << "            return;\n";
            oss << "        }\n";
            oss << "        const int generated_quotient = (int)(generated_dividend / generated_divisor);\n";
            oss << "        const int generated_remainder = (int)(generated_dividend % generated_divisor);\n";
            oss << "        if (generated_quotient < -128 || generated_quotient > 127) {\n";
            oss << "            generated_runtime_note_call(state, \"divide_overflow_f6_idiv\");\n";
            oss << "            state->terminated = 1u;\n";
            oss << "            return;\n";
            oss << "        }\n";
            oss << "        state->ax = (uint16_t)((((unsigned int)((unsigned char)generated_remainder)) << 8u) | (unsigned int)((unsigned char)generated_quotient));\n";
            oss << "    }\n";
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0xF7u && reg_field == 2u) {
            if (is_register) {
                oss << "    " << register16_field_name(rm_field) << " = (uint16_t)(~"
                    << register16_field_name(rm_field) << ");\n";
            } else {
                oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                    << ", (uint16_t)(~generated_read_u16(state, " << segment_field << ", " << offset_expression
                    << ")));\n";
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0xF7u && reg_field == 3u) {
            const std::string operand = is_register
                ? register16_field_name(rm_field)
                : "generated_read_u16(state, " + segment_field + ", " + offset_expression + ")";
            if (is_register) {
                oss << "    " << register16_field_name(rm_field) << " = generated_neg_u16(state, " << operand << ");\n";
            } else {
                oss << "        generated_write_u16(state, " << segment_field << ", " << offset_expression
                    << ", generated_neg_u16(state, " << operand << "));\n";
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0xF7u && reg_field == 4u) {
            const std::string operand = is_register
                ? register16_field_name(rm_field)
                : direct_read_u16_expr;
            oss << "    generated_mul_u16(state, " << operand << ");\n";
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0xF7u && reg_field == 6u) {
            const std::string divisor = is_register
                ? register16_field_name(rm_field)
                : direct_read_u16_expr;
            oss << "    {\n";
            oss << "        const uint16_t generated_divisor = " << divisor << ";\n";
            oss << "        const unsigned int generated_dividend = ((unsigned int)state->dx << 16u) | (unsigned int)state->ax;\n";
            oss << "        if (generated_divisor == 0u) {\n";
            oss << "            generated_runtime_note_call(state, \"divide_error_f7\");\n";
            oss << "            state->terminated = 1u;\n";
            oss << "            return;\n";
            oss << "        }\n";
            oss << "        const unsigned int generated_quotient = generated_dividend / generated_divisor;\n";
            oss << "        const unsigned int generated_remainder = generated_dividend % generated_divisor;\n";
            oss << "        if (generated_quotient > 0xFFFFu) {\n";
            oss << "            generated_runtime_note_call(state, \"divide_overflow_f7\");\n";
            oss << "            state->terminated = 1u;\n";
            oss << "            return;\n";
            oss << "        }\n";
            oss << "        state->ax = (uint16_t)generated_quotient;\n";
            oss << "        state->dx = (uint16_t)generated_remainder;\n";
            oss << "    }\n";
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0xF7u && reg_field == 7u) {
            const std::string divisor = is_register
                ? register16_field_name(rm_field)
                : direct_read_u16_expr;
            oss << "    {\n";
            oss << "        const short generated_divisor = (short)" << divisor << ";\n";
            oss << "        const int generated_dividend = ((int)(short)state->dx << 16) | (int)state->ax;\n";
            oss << "        if (generated_divisor == 0) {\n";
            oss << "            generated_runtime_note_call(state, \"divide_error_f7_idiv\");\n";
            oss << "            state->terminated = 1u;\n";
            oss << "            return;\n";
            oss << "        }\n";
            oss << "        const int generated_quotient = generated_dividend / generated_divisor;\n";
            oss << "        const int generated_remainder = generated_dividend % generated_divisor;\n";
            oss << "        if (generated_quotient < -32768 || generated_quotient > 32767) {\n";
            oss << "            generated_runtime_note_call(state, \"divide_overflow_f7_idiv\");\n";
            oss << "            state->terminated = 1u;\n";
            oss << "            return;\n";
            oss << "        }\n";
            oss << "        state->ax = (uint16_t)(short)generated_quotient;\n";
            oss << "        state->dx = (uint16_t)(short)generated_remainder;\n";
            oss << "    }\n";
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x81u && reg_field == 7u) {
            const std::uint16_t imm = instruction_u16(instruction, modrm_offset + 1u + displacement_size);
            if (is_register) {
                oss << "    generated_cmp_u16(state, " << register16_field_name(rm_field)
                    << ", 0x" << hex4(imm) << ");\n";
            } else {
                oss << "    generated_cmp_u16(state, " << direct_read_u16_expr
                    << ", 0x" << hex4(imm) << ");\n";
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x81u && reg_field == 0u) {
            const std::uint16_t imm = instruction_u16(instruction, modrm_offset + 1u + displacement_size);
            if (is_register) {
                const std::string target = register16_field_name(rm_field);
                emit_assign_add_u16(oss, target, target, "0x" + hex4(imm) + "u");
            } else {
                const std::string expression =
                    "generated_add_u16(state, " + direct_read_u16_expr + ", 0x" + hex4(imm) + "u)";
                if (direct_offset.has_value()) {
                    if (const auto stmt = named_static_write_u16_statement(
                            segment_field, instruction.cs, *direct_offset, expression, instruction_entry_segment_state);
                        stmt.has_value()) {
                        oss << *stmt;
                    } else {
                        oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                            << ", " << expression << ");\n";
                    }
                } else {
                    oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                        << ", " << expression << ");\n";
                }
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x81u && reg_field == 2u) {
            const std::uint16_t imm = instruction_u16(instruction, modrm_offset + 1u + displacement_size);
            if (is_register) {
                const std::string target = register16_field_name(rm_field);
                emit_assign_adc_u16(oss, target, target, "0x" + hex4(imm) + "u");
            } else {
                const std::string expression =
                    "generated_adc_u16(state, " + direct_read_u16_expr + ", 0x" + hex4(imm) + "u)";
                if (direct_offset.has_value()) {
                    if (const auto stmt = named_static_write_u16_statement(
                            segment_field, instruction.cs, *direct_offset, expression, instruction_entry_segment_state);
                        stmt.has_value()) {
                        oss << *stmt;
                    } else {
                        oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                            << ", " << expression << ");\n";
                    }
                } else {
                    oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                        << ", " << expression << ");\n";
                }
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x81u && reg_field == 3u) {
            const std::uint16_t imm = instruction_u16(instruction, modrm_offset + 1u + displacement_size);
            if (is_register) {
                const std::string target = register16_field_name(rm_field);
                emit_assign_sbb_u16(oss, target, target, "0x" + hex4(imm) + "u");
            } else {
                const std::string expression =
                    "generated_sbb_u16(state, " + direct_read_u16_expr + ", 0x" + hex4(imm) + "u)";
                if (direct_offset.has_value()) {
                    if (const auto stmt = named_static_write_u16_statement(
                            segment_field, instruction.cs, *direct_offset, expression, instruction_entry_segment_state);
                        stmt.has_value()) {
                        oss << *stmt;
                    } else {
                        oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                            << ", " << expression << ");\n";
                    }
                } else {
                    oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                        << ", " << expression << ");\n";
                }
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x81u && reg_field == 1u) {
            const std::uint16_t imm = instruction_u16(instruction, modrm_offset + 1u + displacement_size);
            if (is_register) {
                const std::string left = register16_field_name(rm_field);
                emit_assign_logic_u16(oss, left, "(uint16_t)(" + left + " | 0x" + hex4(imm) + "u)");
            } else {
                const std::string expression =
                    "generated_logic_u16(state, (uint16_t)(" + direct_read_u16_expr + " | 0x" + hex4(imm) + "u))";
                if (direct_offset.has_value()) {
                    if (const auto stmt = named_static_write_u16_statement(
                            segment_field, instruction.cs, *direct_offset, expression, instruction_entry_segment_state);
                        stmt.has_value()) {
                        oss << *stmt;
                    } else {
                        oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                            << ", " << expression << ");\n";
                    }
                } else {
                    oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                        << ", " << expression << ");\n";
                }
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x81u && reg_field == 4u) {
            const std::uint16_t imm = instruction_u16(instruction, modrm_offset + 1u + displacement_size);
            if (is_register) {
                const std::string left = register16_field_name(rm_field);
                emit_assign_logic_u16(oss, left, "(uint16_t)(" + left + " & 0x" + hex4(imm) + "u)");
            } else {
                const std::string expression =
                    "generated_logic_u16(state, (uint16_t)(" + direct_read_u16_expr + " & 0x" + hex4(imm) + "u))";
                if (direct_offset.has_value()) {
                    if (const auto stmt = named_static_write_u16_statement(
                            segment_field, instruction.cs, *direct_offset, expression, instruction_entry_segment_state);
                        stmt.has_value()) {
                        oss << *stmt;
                    } else {
                        oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                            << ", " << expression << ");\n";
                    }
                } else {
                    oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                        << ", " << expression << ");\n";
                }
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x81u && reg_field == 5u) {
            const std::uint16_t imm = instruction_u16(instruction, modrm_offset + 1u + displacement_size);
            if (is_register) {
                const std::string left = register16_field_name(rm_field);
                emit_assign_sub_u16(oss, left, left, "0x" + hex4(imm) + "u");
            } else {
                const std::string expression =
                    "generated_sub_u16(state, " + direct_read_u16_expr + ", 0x" + hex4(imm) + "u)";
                if (direct_offset.has_value()) {
                    if (const auto stmt = named_static_write_u16_statement(
                            segment_field, instruction.cs, *direct_offset, expression, instruction_entry_segment_state);
                        stmt.has_value()) {
                        oss << *stmt;
                    } else {
                        oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                            << ", " << expression << ");\n";
                    }
                } else {
                    oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                        << ", " << expression << ");\n";
                }
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x81u && reg_field == 6u) {
            const std::uint16_t imm = instruction_u16(instruction, modrm_offset + 1u + displacement_size);
            if (is_register) {
                const std::string left = register16_field_name(rm_field);
                emit_assign_logic_u16(oss, left, "(uint16_t)(" + left + " ^ 0x" + hex4(imm) + "u)");
            } else {
                const std::string expression =
                    "generated_logic_u16(state, (uint16_t)(" + direct_read_u16_expr + " ^ 0x" + hex4(imm) + "u))";
                if (direct_offset.has_value()) {
                    if (const auto stmt = named_static_write_u16_statement(
                            segment_field, instruction.cs, *direct_offset, expression, instruction_entry_segment_state);
                        stmt.has_value()) {
                        oss << *stmt;
                    } else {
                        oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                            << ", " << expression << ");\n";
                    }
                } else {
                    oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                        << ", " << expression << ");\n";
                }
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x83u && reg_field == 7u) {
            const std::uint16_t imm = static_cast<std::uint16_t>(
                static_cast<std::int16_t>(static_cast<std::int8_t>(instruction.bytes.at(modrm_offset + 1u + displacement_size))));
            if (is_register) {
                oss << "    generated_cmp_u16(state, " << register16_field_name(rm_field)
                    << ", 0x" << hex4(imm) << ");\n";
            } else {
                oss << "    generated_cmp_u16(state, " << direct_read_u16_expr
                    << ", 0x" << hex4(imm) << ");\n";
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x83u && reg_field == 6u) {
            const std::uint16_t imm = static_cast<std::uint16_t>(
                static_cast<std::int16_t>(static_cast<std::int8_t>(instruction.bytes.at(modrm_offset + 1u + displacement_size))));
            if (is_register) {
                const std::string target = register16_field_name(rm_field);
                emit_assign_logic_u16(oss, target, "(uint16_t)(" + target + " ^ 0x" + hex4(imm) + "u)");
            } else {
                const std::string expression =
                    "generated_logic_u16(state, (uint16_t)(" + direct_read_u16_expr + " ^ 0x" + hex4(imm) + "u))";
                if (direct_offset.has_value()) {
                    if (const auto stmt = named_static_write_u16_statement(
                            segment_field, instruction.cs, *direct_offset, expression, instruction_entry_segment_state);
                        stmt.has_value()) {
                        oss << *stmt;
                    } else {
                        oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                            << ", " << expression << ");\n";
                    }
                } else {
                    oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                        << ", " << expression << ");\n";
                }
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x83u && reg_field == 0u) {
            const std::uint16_t imm = static_cast<std::uint16_t>(
                static_cast<std::int16_t>(static_cast<std::int8_t>(instruction.bytes.at(modrm_offset + 1u + displacement_size))));
            if (is_register) {
                const std::string target = register16_field_name(rm_field);
                emit_assign_add_u16(oss, target, target, "0x" + hex4(imm) + "u");
            } else {
                const std::string expression =
                    "generated_add_u16(state, " + direct_read_u16_expr + ", 0x" + hex4(imm) + "u)";
                if (direct_offset.has_value()) {
                    if (const auto stmt = named_static_write_u16_statement(
                            segment_field, instruction.cs, *direct_offset, expression, instruction_entry_segment_state);
                        stmt.has_value()) {
                        oss << *stmt;
                    } else {
                        oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                            << ", " << expression << ");\n";
                    }
                } else {
                    oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                        << ", " << expression << ");\n";
                }
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x83u && reg_field == 2u) {
            const std::uint16_t imm = static_cast<std::uint16_t>(
                static_cast<std::int16_t>(static_cast<std::int8_t>(instruction.bytes.at(modrm_offset + 1u + displacement_size))));
            if (is_register) {
                const std::string target = register16_field_name(rm_field);
                emit_assign_adc_u16(oss, target, target, "0x" + hex4(imm) + "u");
            } else {
                const std::string expression =
                    "generated_adc_u16(state, " + direct_read_u16_expr + ", 0x" + hex4(imm) + "u)";
                if (direct_offset.has_value()) {
                    if (const auto stmt = named_static_write_u16_statement(
                            segment_field, instruction.cs, *direct_offset, expression, instruction_entry_segment_state);
                        stmt.has_value()) {
                        oss << *stmt;
                    } else {
                        oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                            << ", " << expression << ");\n";
                    }
                } else {
                    oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                        << ", " << expression << ");\n";
                }
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x83u && reg_field == 3u) {
            const std::uint16_t imm = static_cast<std::uint16_t>(
                static_cast<std::int16_t>(static_cast<std::int8_t>(instruction.bytes.at(modrm_offset + 1u + displacement_size))));
            if (is_register) {
                const std::string target = register16_field_name(rm_field);
                emit_assign_sbb_u16(oss, target, target, "0x" + hex4(imm) + "u");
            } else {
                const std::string expression =
                    "generated_sbb_u16(state, " + direct_read_u16_expr + ", 0x" + hex4(imm) + "u)";
                if (direct_offset.has_value()) {
                    if (const auto stmt = named_static_write_u16_statement(
                            segment_field, instruction.cs, *direct_offset, expression, instruction_entry_segment_state);
                        stmt.has_value()) {
                        oss << *stmt;
                    } else {
                        oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                            << ", " << expression << ");\n";
                    }
                } else {
                    oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                        << ", " << expression << ");\n";
                }
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x83u && reg_field == 1u) {
            const std::uint16_t imm = static_cast<std::uint16_t>(
                static_cast<std::int16_t>(static_cast<std::int8_t>(instruction.bytes.at(modrm_offset + 1u + displacement_size))));
            if (is_register) {
                const std::string left = register16_field_name(rm_field);
                emit_assign_logic_u16(oss, left, "(uint16_t)(" + left + " | 0x" + hex4(imm) + "u)");
            } else {
                const std::string expression =
                    "generated_logic_u16(state, (uint16_t)(" + direct_read_u16_expr + " | 0x" + hex4(imm) + "u))";
                if (direct_offset.has_value()) {
                    if (const auto stmt = named_static_write_u16_statement(
                            segment_field, instruction.cs, *direct_offset, expression, instruction_entry_segment_state);
                        stmt.has_value()) {
                        oss << *stmt;
                    } else {
                        oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                            << ", " << expression << ");\n";
                    }
                } else {
                    oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                        << ", " << expression << ");\n";
                }
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x83u && reg_field == 4u) {
            const std::uint16_t imm = static_cast<std::uint16_t>(
                static_cast<std::int16_t>(static_cast<std::int8_t>(instruction.bytes.at(modrm_offset + 1u + displacement_size))));
            if (is_register) {
                const std::string left = register16_field_name(rm_field);
                emit_assign_logic_u16(oss, left, "(uint16_t)(" + left + " & 0x" + hex4(imm) + "u)");
            } else {
                const std::string expression =
                    "generated_logic_u16(state, (uint16_t)(" + direct_read_u16_expr + " & 0x" + hex4(imm) + "u))";
                if (direct_offset.has_value()) {
                    if (const auto stmt = named_static_write_u16_statement(
                            segment_field, instruction.cs, *direct_offset, expression, instruction_entry_segment_state);
                        stmt.has_value()) {
                        oss << *stmt;
                    } else {
                        oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                            << ", " << expression << ");\n";
                    }
                } else {
                    oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                        << ", " << expression << ");\n";
                }
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x83u && reg_field == 5u) {
            const std::uint16_t imm = static_cast<std::uint16_t>(
                static_cast<std::int16_t>(static_cast<std::int8_t>(instruction.bytes.at(modrm_offset + 1u + displacement_size))));
            if (is_register) {
                const std::string target = register16_field_name(rm_field);
                emit_assign_sub_u16(oss, target, target, "0x" + hex4(imm) + "u");
            } else {
                const std::string expression =
                    "generated_sub_u16(state, " + direct_read_u16_expr + ", 0x" + hex4(imm) + "u)";
                if (direct_offset.has_value()) {
                    if (const auto stmt = named_static_write_u16_statement(
                            segment_field, instruction.cs, *direct_offset, expression, instruction_entry_segment_state);
                        stmt.has_value()) {
                        oss << *stmt;
                    } else {
                        oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                            << ", " << expression << ");\n";
                    }
                } else {
                    oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                        << ", " << expression << ");\n";
                }
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x33u) {
            const std::string right = is_register
                ? register16_field_name(rm_field)
                : direct_read_u16_expr;
            const std::string left = register16_field_name(reg_field);
            emit_assign_logic_u16(oss, left, "(uint16_t)(" + left + " ^ " + right + ")");
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x32u) {
            const std::string left = register8_value_expression(reg_field);
            const std::string right = is_register
                ? register8_value_expression(rm_field)
                : direct_read_u8_expr;
            emit_assign_logic_u8_register(oss, reg_field, "(unsigned char)((" + left + " ^ " + right + ") & 0xFFu)");
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x02u) {
            const std::string left = register8_value_expression(reg_field);
            const std::string right = is_register
                ? register8_value_expression(rm_field)
                : direct_read_u8_expr;
            emit_assign_add_u8_register(oss, reg_field, left, right);
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x0Au) {
            const std::string left = register8_value_expression(reg_field);
            const std::string right = is_register
                ? register8_value_expression(rm_field)
                : direct_read_u8_expr;
            emit_assign_logic_u8_register(oss, reg_field, "(unsigned char)((" + left + " | " + right + ") & 0xFFu)");
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x03u) {
            const std::string left = register16_field_name(reg_field);
            const std::string right = is_register
                ? register16_field_name(rm_field)
                : direct_read_u16_expr;
            emit_assign_add_u16(oss, left, left, right);
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x3Au) {
            const std::string right = is_register
                ? register8_value_expression(rm_field)
                : direct_read_u8_expr;
            oss << "    generated_cmp_u8(state, " << register8_value_expression(reg_field)
                << ", " << right << ");\n";
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x3Bu) {
            const std::string right = is_register
                ? register16_field_name(rm_field)
                : direct_read_u16_expr;
            oss << "    generated_cmp_u16(state, " << register16_field_name(reg_field)
                << ", " << right << ");\n";
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x39u) {
            const std::string left = is_register
                ? register16_field_name(rm_field)
                : direct_read_u16_expr;
            oss << "    generated_cmp_u16(state, " << left
                << ", " << register16_field_name(reg_field) << ");\n";
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0xFEu && reg_field <= 1u) {
            if (is_register) {
                const std::string old_value = register8_value_expression(rm_field);
                if (reg_field == 0u) {
                    emit_assign_inc_u8_register(oss, rm_field, old_value);
                } else {
                    emit_assign_dec_u8_register(oss, rm_field, old_value);
                }
            } else {
                if (reg_field == 0u) {
                    oss << "    generated_write_u8(state, " << segment_field << ", " << offset_expression
                        << ", generated_inc_u8(state, generated_read_u8(state, " << segment_field << ", "
                        << offset_expression << ")));\n";
                } else {
                    oss << "    generated_write_u8(state, " << segment_field << ", " << offset_expression
                        << ", generated_dec_u8(state, generated_read_u8(state, " << segment_field << ", "
                        << offset_expression << ")));\n";
                }
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0xD0u &&
            (reg_field == 0u || reg_field == 1u || reg_field == 2u ||
             reg_field == 3u || reg_field == 4u || reg_field == 5u || reg_field == 7u)) {
            if (is_register) {
                emit_assign_shift_rotate_u8_register(
                    oss, rm_field, reg_field, register8_value_expression(rm_field), "1u");
            } else {
                oss << "    generated_write_u8(state, " << segment_field << ", " << offset_expression
                    << ", generated_shift_rotate_u8(state, " << static_cast<unsigned>(reg_field)
                    << "u, generated_read_u8(state, " << segment_field << ", " << offset_expression
                    << "), 1u));\n";
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0xD2u &&
            (reg_field == 0u || reg_field == 1u || reg_field == 2u ||
             reg_field == 3u || reg_field == 4u || reg_field == 5u || reg_field == 7u)) {
            oss << "    {\n";
            oss << "        const unsigned int generated_count = (unsigned int)(state->cx & 0x00FFu);\n";
            oss << "        const unsigned int generated_steps = generated_count & 0x1Fu;\n";
            oss << "        if (generated_steps != 0u) {\n";
            if (is_register) {
                oss << "            const unsigned char generated_new = generated_shift_rotate_u8(state, "
                    << static_cast<unsigned>(reg_field) << "u, " << register8_value_expression(rm_field)
                    << ", generated_steps);\n";
                oss << register8_set_statement(rm_field, "generated_new");
            } else {
                oss << "            generated_write_u8(state, " << segment_field << ", " << offset_expression
                    << ", generated_shift_rotate_u8(state, " << static_cast<unsigned>(reg_field)
                    << "u, generated_read_u8(state, " << segment_field << ", " << offset_expression
                    << "), generated_steps));\n";
            }
            oss << "        }\n";
            oss << "    }\n";
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0xD3u &&
            (reg_field == 0u || reg_field == 1u || reg_field == 2u ||
             reg_field == 3u || reg_field == 4u || reg_field == 5u || reg_field == 7u)) {
            oss << "    {\n";
            oss << "        const unsigned int generated_count = (unsigned int)(state->cx & 0x00FFu);\n";
            oss << "        const unsigned int generated_steps = generated_count & 0x1Fu;\n";
            oss << "        if (generated_steps != 0u) {\n";
            if (is_register) {
                emit_assign_shift_rotate_u16(
                    oss, register16_field_name(rm_field), reg_field, register16_field_name(rm_field), "generated_steps");
            } else {
                oss << "            generated_write_u16(state, " << segment_field << ", " << offset_expression
                    << ", generated_shift_rotate_u16(state, " << static_cast<unsigned>(reg_field)
                    << "u, generated_read_u16(state, " << segment_field << ", " << offset_expression
                    << "), generated_steps));\n";
            }
            oss << "        }\n";
            oss << "    }\n";
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x80u && !is_register) {
            const std::uint8_t imm = instruction.bytes.at(modrm_offset + 1u + displacement_size);
            if (reg_field == 0u) {
                oss << "    generated_write_u8(state, " << segment_field << ", " << offset_expression
                    << ", generated_add_u8(state, generated_read_u8(state, " << segment_field << ", "
                    << offset_expression << "), 0x" << hex4(imm).substr(2) << "u));\n";
                emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
                return true;
            }
            if (reg_field == 1u) {
                oss << "    generated_write_u8(state, " << segment_field << ", " << offset_expression
                    << ", generated_logic_u8(state, (unsigned char)(generated_read_u8(state, " << segment_field << ", "
                    << offset_expression << ") | 0x" << hex4(imm).substr(2) << "u)));\n";
                emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
                return true;
            }
            if (reg_field == 2u) {
                oss << "    generated_write_u8(state, " << segment_field << ", " << offset_expression
                    << ", generated_adc_u8(state, generated_read_u8(state, " << segment_field << ", "
                    << offset_expression << "), 0x" << hex4(imm).substr(2) << "u));\n";
                emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
                return true;
            }
            if (reg_field == 3u) {
                oss << "    generated_write_u8(state, " << segment_field << ", " << offset_expression
                    << ", generated_sbb_u8(state, generated_read_u8(state, " << segment_field << ", "
                    << offset_expression << "), 0x" << hex4(imm).substr(2) << "u));\n";
                emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
                return true;
            }
            if (reg_field == 5u) {
                oss << "    generated_write_u8(state, " << segment_field << ", " << offset_expression
                    << ", generated_sub_u8(state, generated_read_u8(state, " << segment_field << ", "
                    << offset_expression << "), 0x" << hex4(imm).substr(2) << "u));\n";
                emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
                return true;
            }
            if (reg_field == 4u) {
                oss << "    generated_and_u8_direct(state, " << segment_field << ", " << offset_expression
                    << ", 0x" << hex4(imm).substr(2) << "u);\n";
                emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
                return true;
            }
            if (reg_field == 7u) {
                oss << "    generated_cmp_u8(state, generated_read_u8(state, " << segment_field << ", "
                    << offset_expression << "), 0x" << hex4(imm).substr(2) << "u);\n";
                emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
                return true;
            }
            if (reg_field == 6u) {
                oss << "    {\n";
                oss << "        const unsigned char generated_new = (unsigned char)(generated_read_u8(state, " << segment_field
                    << ", " << offset_expression << ") ^ 0x" << hex4(imm).substr(2) << "u);\n";
                oss << "        generated_write_u8(state, " << segment_field << ", " << offset_expression
                    << ", generated_new);\n";
                oss << "        generated_set_flag(state, GENERATED_FLAG_CF, 0u);\n";
                oss << "        generated_set_flag(state, GENERATED_FLAG_OF, 0u);\n";
                oss << "        generated_set_flag(state, GENERATED_FLAG_AF, 0u);\n";
                oss << "        generated_set_flag(state, GENERATED_FLAG_SF, (generated_new & 0x80u) != 0u);\n";
                oss << "        generated_set_flag(state, GENERATED_FLAG_ZF, generated_new == 0u);\n";
                oss << "        generated_set_flag(state, GENERATED_FLAG_PF, generated_parity_u8(generated_new));\n";
                oss << "    }\n";
                emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
                return true;
            }
        }

        if (opcode == 0x80u && is_register) {
            const std::uint8_t imm = instruction.bytes.at(modrm_offset + 1u + displacement_size);
            if (reg_field == 0u) {
                const std::string left = register8_value_expression(rm_field);
                emit_assign_add_u8_register(oss, rm_field, left, "0x" + hex4(imm).substr(2) + "u");
                emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
                return true;
            }
            if (reg_field == 4u) {
                emit_assign_logic_u8_register(
                    oss,
                    rm_field,
                    "(unsigned char)(" + register8_value_expression(rm_field) + " & 0x" + hex4(imm).substr(2) + "u)");
                emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
                return true;
            }
            if (reg_field == 1u) {
                emit_assign_logic_u8_register(
                    oss,
                    rm_field,
                    "(unsigned char)(" + register8_value_expression(rm_field) + " | 0x" + hex4(imm).substr(2) + "u)");
                emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
                return true;
            }
            if (reg_field == 2u) {
                const std::string left = register8_value_expression(rm_field);
                emit_assign_adc_u8_register(oss, rm_field, left, "0x" + hex4(imm).substr(2) + "u");
                emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
                return true;
            }
            if (reg_field == 3u) {
                const std::string left = register8_value_expression(rm_field);
                emit_assign_sbb_u8_register(oss, rm_field, left, "0x" + hex4(imm).substr(2) + "u");
                emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
                return true;
            }
            if (reg_field == 5u) {
                const std::string left = register8_value_expression(rm_field);
                emit_assign_sub_u8_register(oss, rm_field, left, "0x" + hex4(imm).substr(2) + "u");
                emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
                return true;
            }
            if (reg_field == 7u) {
                oss << "    generated_cmp_u8(state, " << register8_value_expression(rm_field)
                    << ", 0x" << hex4(imm).substr(2) << "u);\n";
                emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
                return true;
            }
            if (reg_field == 6u) {
                emit_assign_logic_u8_register(
                    oss,
                    rm_field,
                    "(unsigned char)(" + register8_value_expression(rm_field) + " ^ 0x" + hex4(imm).substr(2) + "u)");
                emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
                return true;
            }
        }

        if (opcode == 0x08u) {
            const std::string right = register8_value_expression(reg_field);
            if (is_register) {
                const std::string left = register8_value_expression(rm_field);
                emit_assign_logic_u8_register(oss, rm_field, "(unsigned char)(" + left + " | " + right + ")");
            } else {
                oss << "    generated_write_u8(state, " << segment_field << ", " << offset_expression
                    << ", generated_logic_u8(state, (unsigned char)(generated_read_u8(state, "
                    << segment_field << ", " << offset_expression << ") | " << right << ")));\n";
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x00u) {
            const std::string right = register8_value_expression(reg_field);
            if (is_register) {
                const std::string left = register8_value_expression(rm_field);
                emit_assign_add_u8_register(oss, rm_field, left, right);
            } else {
                oss << "    generated_write_u8(state, " << segment_field << ", " << offset_expression
                    << ", generated_add_u8(state, generated_read_u8(state, " << segment_field << ", "
                    << offset_expression << "), " << right << "));\n";
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x09u) {
            const std::string right = register16_field_name(reg_field);
            if (is_register) {
                const std::string left = register16_field_name(rm_field);
                emit_assign_logic_u16(oss, left, "(uint16_t)(" + left + " | " + right + ")");
            } else {
                oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                    << ", generated_logic_u16(state, (uint16_t)(generated_read_u16(state, "
                    << segment_field << ", " << offset_expression << ") | " << right << ")));\n";
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x01u) {
            const std::string right = register16_field_name(reg_field);
            if (is_register) {
                const std::string left = register16_field_name(rm_field);
                emit_assign_add_u16(oss, left, left, right);
            } else {
                oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                    << ", generated_add_u16(state, generated_read_u16(state, " << segment_field << ", "
                    << offset_expression << "), " << right << "));\n";
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x2Bu) {
            const std::string left = register16_field_name(reg_field);
            const std::string right = is_register
                ? register16_field_name(rm_field)
                : direct_read_u16_expr;
            emit_assign_sub_u16(oss, left, left, right);
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x2Au) {
            const std::string left = register8_value_expression(reg_field);
            const std::string right = is_register
                ? register8_value_expression(rm_field)
                : direct_read_u8_expr;
            emit_assign_sub_u8_register(oss, reg_field, left, right);
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x29u) {
            const std::string right = register16_field_name(reg_field);
            if (is_register) {
                const std::string left = register16_field_name(rm_field);
                emit_assign_sub_u16(oss, left, left, right);
            } else {
                oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                    << ", generated_sub_u16(state, generated_read_u16(state, " << segment_field << ", "
                    << offset_expression << "), " << right << "));\n";
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x28u) {
            const std::string right = register8_value_expression(reg_field);
            if (is_register) {
                const std::string left = register8_value_expression(rm_field);
                emit_assign_sub_u8_register(oss, rm_field, left, right);
            } else {
                oss << "    generated_write_u8(state, " << segment_field << ", " << offset_expression
                    << ", generated_sub_u8(state, generated_read_u8(state, " << segment_field << ", "
                    << offset_expression << "), " << right << "));\n";
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0xD1u &&
            (reg_field == 0u || reg_field == 1u || reg_field == 2u ||
             reg_field == 3u || reg_field == 4u || reg_field == 5u || reg_field == 7u)) {
            if (is_register) {
                const std::string value = register16_field_name(rm_field);
                emit_assign_shift_rotate_u16(oss, value, reg_field, value, "1u");
            } else {
                oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                    << ", generated_shift_rotate_u16(state, " << static_cast<unsigned>(reg_field)
                    << "u, generated_read_u16(state, " << segment_field << ", " << offset_expression
                    << "), 1u));\n";
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x20u && is_register) {
            const std::string right = register8_value_expression(reg_field);
            const std::string left = register8_value_expression(rm_field);
            emit_assign_logic_u8_register(oss, rm_field, "(unsigned char)((" + left + " & " + right + ") & 0xFFu)");
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x20u && !is_register) {
            const std::string right = register8_value_expression(reg_field);
            oss << "    generated_write_u8(state, " << segment_field << ", " << offset_expression
                << ", generated_logic_u8(state, (unsigned char)((generated_read_u8(state, "
                << segment_field << ", " << offset_expression << ") & " << right << ") & 0xFFu)));\n";
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x30u) {
            const std::string right = register8_value_expression(reg_field);
            const std::string left = is_register
                ? register8_value_expression(rm_field)
                : "generated_read_u8(state, " + segment_field + ", " + offset_expression + ")";
            if (is_register) {
                emit_assign_logic_u8_register(oss, rm_field, "(unsigned char)((" + left + " ^ " + right + ") & 0xFFu)");
            } else {
                oss << "    generated_write_u8(state, " << segment_field << ", " << offset_expression
                    << ", generated_logic_u8(state, (unsigned char)((" << left << " ^ " << right << ") & 0xFFu)));\n";
            }
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x21u && is_register) {
            const std::string right = register16_field_name(reg_field);
            const std::string left = register16_field_name(rm_field);
            emit_assign_logic_u16(oss, left, "(uint16_t)(" + left + " & " + right + ")");
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x21u && !is_register) {
            oss << "    generated_write_u16(state, " << segment_field << ", " << offset_expression
                << ", generated_logic_u16(state, (uint16_t)(generated_read_u16(state, " << segment_field
                << ", " << offset_expression << ") & " << register16_field_name(reg_field) << ")));\n";
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x22u && is_register) {
            const std::string left = register8_value_expression(reg_field);
            const std::string right = register8_value_expression(rm_field);
            emit_assign_logic_u8_register(oss, reg_field, "(unsigned char)(" + left + " & " + right + ")");
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if (opcode == 0x22u && !is_register) {
            const std::string left = register8_value_expression(reg_field);
            emit_assign_logic_u8_register(
                oss,
                reg_field,
                "(unsigned char)(" + left + " & " + direct_read_u8_expr + ")");
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if ((opcode == 0x23u || opcode == 0x0Bu) && is_register) {
            const std::string left = register16_field_name(reg_field);
            const std::string right = register16_field_name(rm_field);
            const char* op = opcode == 0x23u ? "&" : "|";
            emit_assign_logic_u16(oss, left, "(uint16_t)(" + left + " " + op + " " + right + ")");
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }

        if ((opcode == 0x23u || opcode == 0x0Bu) && !is_register) {
            const std::string left = register16_field_name(reg_field);
            const char* op = opcode == 0x23u ? "&" : "|";
            emit_assign_logic_u16(oss, left, "(uint16_t)(" + left + " " + op
                + " " + direct_read_u16_expr + ")");
            emit_ip_advance(oss, next_ip_text, should_emit_ip_advance);
            return true;
        }
    }

    return false;
}

void write_text_file(const std::filesystem::path& path, const std::string& text) {
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        throw std::runtime_error("failed to open output file: " + path.string());
    }
    out.write(text.data(), static_cast<std::streamsize>(text.size()));
    if (!out) {
        throw std::runtime_error("failed to write output file: " + path.string());
    }
}

std::string build_project_text() {
    return
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
        "<Project DefaultTargets=\"Build\" xmlns=\"http://schemas.microsoft.com/developer/msbuild/2003\">\r\n"
        "  <ItemGroup Label=\"ProjectConfigurations\">\r\n"
        "    <ProjectConfiguration Include=\"Debug|x64\">\r\n"
        "      <Configuration>Debug</Configuration>\r\n"
        "      <Platform>x64</Platform>\r\n"
        "    </ProjectConfiguration>\r\n"
        "    <ProjectConfiguration Include=\"Release|x64\">\r\n"
        "      <Configuration>Release</Configuration>\r\n"
        "      <Platform>x64</Platform>\r\n"
        "    </ProjectConfiguration>\r\n"
        "  </ItemGroup>\r\n"
        "  <PropertyGroup Label=\"Globals\">\r\n"
        "    <VCProjectVersion>17.0</VCProjectVersion>\r\n"
        "    <Keyword>Win32Proj</Keyword>\r\n"
        "    <ProjectGuid>{C5D67F44-4F1E-4E89-9A17-D1B5A39D6A21}</ProjectGuid>\r\n"
        "    <RootNamespace>GeneratedGame</RootNamespace>\r\n"
        "    <WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion>\r\n"
        "  </PropertyGroup>\r\n"
        "  <Import Project=\"$(VCTargetsPath)\\Microsoft.Cpp.Default.props\" />\r\n"
        "  <PropertyGroup Condition=\"'$(Configuration)|$(Platform)'=='Debug|x64'\" Label=\"Configuration\">\r\n"
        "    <ConfigurationType>Application</ConfigurationType>\r\n"
        "    <UseDebugLibraries>true</UseDebugLibraries>\r\n"
        "    <PlatformToolset>v143</PlatformToolset>\r\n"
        "    <CharacterSet>MultiByte</CharacterSet>\r\n"
        "    <DebuggerFlavor>WindowsLocalDebugger</DebuggerFlavor>\r\n"
        "  </PropertyGroup>\r\n"
        "  <PropertyGroup Condition=\"'$(Configuration)|$(Platform)'=='Release|x64'\" Label=\"Configuration\">\r\n"
        "    <ConfigurationType>Application</ConfigurationType>\r\n"
        "    <UseDebugLibraries>false</UseDebugLibraries>\r\n"
        "    <PlatformToolset>v143</PlatformToolset>\r\n"
        "    <WholeProgramOptimization>true</WholeProgramOptimization>\r\n"
        "    <CharacterSet>MultiByte</CharacterSet>\r\n"
        "    <DebuggerFlavor>WindowsLocalDebugger</DebuggerFlavor>\r\n"
        "  </PropertyGroup>\r\n"
        "  <Import Project=\"$(VCTargetsPath)\\Microsoft.Cpp.props\" />\r\n"
        "  <ImportGroup Label=\"ExtensionSettings\" />\r\n"
        "  <ImportGroup Label=\"Shared\" />\r\n"
        "  <ImportGroup Label=\"PropertySheets\" Condition=\"'$(Configuration)|$(Platform)'=='Debug|x64'\">\r\n"
        "    <Import Project=\"$(UserRootDir)\\Microsoft.Cpp.$(Platform).user.props\" Condition=\"exists('$(UserRootDir)\\Microsoft.Cpp.$(Platform).user.props')\" Label=\"LocalAppDataPlatform\" />\r\n"
        "  </ImportGroup>\r\n"
        "  <ImportGroup Label=\"PropertySheets\" Condition=\"'$(Configuration)|$(Platform)'=='Release|x64'\">\r\n"
        "    <Import Project=\"$(UserRootDir)\\Microsoft.Cpp.$(Platform).user.props\" Condition=\"exists('$(UserRootDir)\\Microsoft.Cpp.$(Platform).user.props')\" Label=\"LocalAppDataPlatform\" />\r\n"
        "  </ImportGroup>\r\n"
        "  <PropertyGroup Label=\"UserMacros\" />\r\n"
        "  <PropertyGroup>\r\n"
        "    <OutDir>$(ProjectDir)Build\\$(Configuration)\\</OutDir>\r\n"
        "    <IntDir>$(ProjectDir)Build\\Intermediate\\$(Configuration)\\</IntDir>\r\n"
        "    <TargetName>GeneratedGame</TargetName>\r\n"
        "  </PropertyGroup>\r\n"
        "  <PropertyGroup Condition=\"'$(Configuration)|$(Platform)'=='Debug|x64'\">\r\n"
        "    <LocalDebuggerWorkingDirectory>$(ProjectDir)..\\..\\Game</LocalDebuggerWorkingDirectory>\r\n"
        "    <LocalDebuggerEnvironment>MZ2CPP_DYNAMIC_TARGET_DB=$(ProjectDir)..\\..\\Game\\mz2cpp_dynamic_targets.txt</LocalDebuggerEnvironment>\r\n"
        "    <LocalDebuggerEnvironmentMerge>true</LocalDebuggerEnvironmentMerge>\r\n"
        "  </PropertyGroup>\r\n"
        "  <PropertyGroup Condition=\"'$(Configuration)|$(Platform)'=='Release|x64'\">\r\n"
        "    <LocalDebuggerWorkingDirectory>$(ProjectDir)..\\..\\Game</LocalDebuggerWorkingDirectory>\r\n"
        "    <LocalDebuggerEnvironment>MZ2CPP_DYNAMIC_TARGET_DB=$(ProjectDir)..\\..\\Game\\mz2cpp_dynamic_targets.txt</LocalDebuggerEnvironment>\r\n"
        "    <LocalDebuggerEnvironmentMerge>true</LocalDebuggerEnvironmentMerge>\r\n"
        "  </PropertyGroup>\r\n"
        "  <ItemDefinitionGroup Condition=\"'$(Configuration)|$(Platform)'=='Debug|x64'\">\r\n"
        "    <ClCompile>\r\n"
        "      <WarningLevel>Level4</WarningLevel>\r\n"
        "      <SDLCheck>true</SDLCheck>\r\n"
        "      <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>\r\n"
        "      <SupportJustMyCode>false</SupportJustMyCode>\r\n"
        "      <PreprocessorDefinitions>_CRT_SECURE_NO_WARNINGS;WIN32;_DEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>\r\n"
        "      <ConformanceMode>true</ConformanceMode>\r\n"
        "      <LanguageStandard>stdcpp20</LanguageStandard>\r\n"
        "    </ClCompile>\r\n"
        "    <Link>\r\n"
        "      <SubSystem>Console</SubSystem>\r\n"
        "      <GenerateDebugInformation>true</GenerateDebugInformation>\r\n"
        "    </Link>\r\n"
        "  </ItemDefinitionGroup>\r\n"
        "  <ItemDefinitionGroup Condition=\"'$(Configuration)|$(Platform)'=='Release|x64'\">\r\n"
        "    <ClCompile>\r\n"
        "      <WarningLevel>Level4</WarningLevel>\r\n"
        "      <FunctionLevelLinking>true</FunctionLevelLinking>\r\n"
        "      <IntrinsicFunctions>true</IntrinsicFunctions>\r\n"
        "      <SDLCheck>true</SDLCheck>\r\n"
        "      <PreprocessorDefinitions>_CRT_SECURE_NO_WARNINGS;WIN32;NDEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>\r\n"
        "      <ConformanceMode>true</ConformanceMode>\r\n"
        "      <LanguageStandard>stdcpp20</LanguageStandard>\r\n"
        "    </ClCompile>\r\n"
        "    <Link>\r\n"
        "      <SubSystem>Console</SubSystem>\r\n"
        "      <EnableCOMDATFolding>true</EnableCOMDATFolding>\r\n"
        "      <OptimizeReferences>true</OptimizeReferences>\r\n"
        "      <GenerateDebugInformation>true</GenerateDebugInformation>\r\n"
        "    </Link>\r\n"
        "  </ItemDefinitionGroup>\r\n"
        "  <ItemGroup>\r\n"
        "    <ClCompile Include=\"src\\generated_game.cpp\" />\r\n"
        "    <ClCompile Include=\"src\\generated_runtime.cpp\" />\r\n"
        "    <ClCompile Include=\"src\\main.cpp\" />\r\n"
        "  </ItemGroup>\r\n"
        "  <ItemGroup>\r\n"
        "    <ClInclude Include=\"src\\generated_data.h\" />\r\n"
        "    <ClInclude Include=\"src\\generated_game.h\" />\r\n"
        "    <ClInclude Include=\"src\\generated_runtime.h\" />\r\n"
        "  </ItemGroup>\r\n"
        "  <Import Project=\"$(VCTargetsPath)\\Microsoft.Cpp.targets\" />\r\n"
        "  <ImportGroup Label=\"ExtensionTargets\" />\r\n"
        "</Project>\r\n";
}

std::string build_generated_data_text(const MzImage& image,
                                      const GeneratedDataLayout& data_layout) {
    std::ostringstream oss;

    oss << "#pragma once\n\n";
    oss << "#include <stddef.h>\n";
    oss << "#include <stdint.h>\n\n";
    oss << "struct GeneratedFarPtr16 { uint16_t offset; uint16_t segment; };\n";
    oss << "template <size_t N> struct GeneratedOpaqueRecord { uint8_t bytes[N]; };\n";
    oss << "struct GeneratedSavegameRecord32 { uint16_t words[16]; };\n";
    oss << "struct GeneratedTableDescriptorRecord { uint16_t field_00; uint16_t field_02; uint16_t field_04; uint16_t field_06; uint16_t field_08; uint16_t field_0A; uint16_t field_0C; uint16_t field_0E; };\n";
    oss << "struct GeneratedLoadLevelScratchRecord12 { uint16_t header; uint8_t payload[12]; };\n";
    oss << "struct GeneratedLoadLevelScratchRecord34 { uint16_t header; uint8_t payload[34]; };\n";
    oss << "struct GeneratedMemoryRegion { uint32_t physical; size_t size; const unsigned char* bytes; };\n";
    oss << "struct GeneratedNamedStaticSymbol { const char* name; const char* family_name; uint16_t segment; uint16_t offset; uint32_t physical; size_t size; unsigned writable; size_t relocation_count; size_t direct_access_count; size_t stride_hint; const char* classification; const char* storage_kind; const unsigned char* bytes; };\n\n";
    oss << "static const uint16_t kGeneratedEntryCS = 0x" << hex4(image.entry_cs) << ";\n";
    oss << "static const uint16_t kGeneratedEntryIP = 0x" << hex4(image.entry_ip) << ";\n";
    oss << "static const uint16_t kGeneratedStackSS = 0x" << hex4(image.stack_ss) << ";\n";
    oss << "static const uint16_t kGeneratedStackSP = 0x" << hex4(image.stack_sp) << ";\n";
    oss << "static const uint16_t kGeneratedLoadSegment = 0x" << hex4(image.layout.load_segment()) << ";\n";
    oss << "static const uint32_t kGeneratedPspPhysical = 0x"
        << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << image.psp_physical << "u;\n";
    oss << "static const uint32_t kGeneratedLoadModulePhysical = 0x"
        << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << image.load_module_physical << "u;\n";
    oss << "static const uint32_t kGeneratedImageEndPhysical = 0x"
        << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << image.image_end_physical << "u;\n";
    oss << std::dec;
    oss << "static const size_t kGeneratedCodeRegionCount = " << data_layout.code_regions.size() << "u;\n";
    oss << "static const size_t kGeneratedNamedStaticSymbolCount = " << data_layout.named_static_regions.size() << "u;\n";
    oss << "static const size_t kGeneratedResidualRegionCount = " << data_layout.residual_regions.size() << "u;\n\n";

    for (const GeneratedDataRegion& region : data_layout.named_static_regions) {
        oss << "static const uint16_t " << generated_static_symbol_offset_constant_name(region)
            << " = 0x"
            << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << region.location.ip
            << "u;\n";
        oss << "static const uint32_t " << generated_static_symbol_phys_constant_name(region)
            << " = 0x"
            << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << region.physical
            << "u;\n";
    }
    if (!data_layout.named_static_regions.empty()) {
        oss << '\n';
    }
    oss << std::dec;

    for (std::size_t index = 0u; index < data_layout.code_regions.size(); ++index) {
        emit_byte_array(oss,
                        "kGeneratedCodeRegionData_" + std::to_string(index),
                        true,
                        data_layout.code_regions[index].bytes);
    }
    for (const GeneratedDataRegion& region : data_layout.named_static_regions) {
        emit_named_static_region_storage(oss, region);
    }
    for (std::size_t index = 0u; index < data_layout.residual_regions.size(); ++index) {
        emit_byte_array(oss,
                        "kGeneratedResidualRegionData_" + std::to_string(index),
                        true,
                        data_layout.residual_regions[index].bytes);
    }

    oss << "static const GeneratedMemoryRegion kGeneratedCodeRegions[] = {\n";
    if (data_layout.code_regions.empty()) {
        oss << "    { 0u, 0u, nullptr },\n";
    } else {
        for (std::size_t index = 0u; index < data_layout.code_regions.size(); ++index) {
            const GeneratedDataRegion& region = data_layout.code_regions[index];
            const std::string index_text = std::to_string(index);
            oss << "    { 0x"
                << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << region.physical
                << "u, sizeof(kGeneratedCodeRegionData_" << index_text << "), kGeneratedCodeRegionData_" << index_text << " },\n";
        }
    }
    oss << "};\n\n";

    oss << "static const GeneratedNamedStaticSymbol kGeneratedNamedStaticSymbols[] = {\n";
    if (data_layout.named_static_regions.empty()) {
        oss << "    { \"\", \"\", 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, \"\", \"\", nullptr },\n";
    } else {
        for (const GeneratedDataRegion& region : data_layout.named_static_regions) {
            oss << "    { \"" << region.name << "\", "
                << "\"" << generated_region_family_name(region.name) << "\", 0x"
                << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << region.location.cs
                << "u, 0x" << std::setw(4) << region.location.ip
                << "u, 0x" << std::setw(8) << region.physical
                << "u, sizeof(" << generated_static_symbol_storage_name(region) << "), "
                << (region.writable ? "1u" : "0u") << ", "
                << std::dec << region.relocation_count << "u, "
                << region.direct_access_count << "u, "
                << region.stride_hint << "u, "
                << "\"" << region.classification << "\", "
                << "\"" << region.storage_kind << "\", "
                << generated_static_symbol_byte_view_name(region) << " },\n";
        }
    }
    oss << "};\n\n";

    oss << "static const GeneratedMemoryRegion kGeneratedResidualRegions[] = {\n";
    if (data_layout.residual_regions.empty()) {
        oss << "    { 0u, 0u, nullptr },\n";
    } else {
        for (std::size_t index = 0u; index < data_layout.residual_regions.size(); ++index) {
            const GeneratedDataRegion& region = data_layout.residual_regions[index];
            const std::string index_text = std::to_string(index);
            oss << "    { 0x"
                << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << region.physical
                << "u, sizeof(kGeneratedResidualRegionData_" << index_text << "), kGeneratedResidualRegionData_" << index_text << " },\n";
        }
    }
    oss << "};\n";
    return oss.str();
}

std::string build_generated_data_report_text(const MzImage& image,
                                             const GeneratedDataLayout& data_layout) {
    const auto region_family_name = [](const std::string& name) {
        constexpr std::string_view suffix = "_off_";
        if (const std::size_t pos = name.find(suffix); pos != std::string::npos) {
            return name.substr(0u, pos);
        }
        return name;
    };
    struct FamilySummary {
        std::size_t region_count = 0u;
        std::size_t total_bytes = 0u;
        std::size_t writable_bytes = 0u;
        std::size_t readonly_bytes = 0u;
        std::size_t relocation_count = 0u;
        std::size_t direct_access_count = 0u;
        std::map<std::string, std::size_t> class_counts;
    };

    const auto sum_region_sizes = [](const std::vector<GeneratedDataRegion>& regions) {
        std::size_t total = 0u;
        for (const GeneratedDataRegion& region : regions) {
            total += region.bytes.size();
        }
        return total;
    };

    const std::size_t total_module_bytes = image.relocated_load_module_bytes.size();
    const std::size_t code_bytes = sum_region_sizes(data_layout.code_regions);
    const std::size_t named_bytes = sum_region_sizes(data_layout.named_static_regions);
    const std::size_t residual_bytes = sum_region_sizes(data_layout.residual_regions);

    std::size_t writable_symbol_count = 0u;
    std::size_t writable_symbol_bytes = 0u;
    std::size_t readonly_symbol_bytes = 0u;
    std::map<std::string, std::size_t> named_class_counts;
    std::map<std::string, std::size_t> named_class_bytes;
    std::map<std::string, std::size_t> named_storage_counts;
    std::map<std::string, std::size_t> named_storage_bytes;
    std::map<std::string, FamilySummary> family_summaries;
    std::map<std::string, std::size_t> residual_class_counts;
    std::map<std::string, std::size_t> residual_class_bytes;
    for (const GeneratedDataRegion& region : data_layout.named_static_regions) {
        if (region.writable) {
            ++writable_symbol_count;
            writable_symbol_bytes += region.bytes.size();
        } else {
            readonly_symbol_bytes += region.bytes.size();
        }
        ++named_class_counts[region.classification];
        named_class_bytes[region.classification] += region.bytes.size();
        ++named_storage_counts[region.storage_kind];
        named_storage_bytes[region.storage_kind] += region.bytes.size();

        FamilySummary& family = family_summaries[region_family_name(region.name)];
        ++family.region_count;
        family.total_bytes += region.bytes.size();
        family.relocation_count += region.relocation_count;
        family.direct_access_count += region.direct_access_count;
        if (region.writable) {
            family.writable_bytes += region.bytes.size();
        } else {
            family.readonly_bytes += region.bytes.size();
        }
        ++family.class_counts[region.classification];
    }
    for (const GeneratedDataRegion& region : data_layout.residual_regions) {
        ++residual_class_counts[region.classification];
        residual_class_bytes[region.classification] += region.bytes.size();
    }

    auto largest_named_regions = data_layout.named_static_regions;
    std::sort(largest_named_regions.begin(), largest_named_regions.end(), [](const GeneratedDataRegion& left,
                                                                             const GeneratedDataRegion& right) {
        if (left.bytes.size() != right.bytes.size()) {
            return left.bytes.size() > right.bytes.size();
        }
        return left.physical < right.physical;
    });
    auto largest_residual_regions = data_layout.residual_regions;
    std::sort(largest_residual_regions.begin(), largest_residual_regions.end(), [](const GeneratedDataRegion& left,
                                                                                   const GeneratedDataRegion& right) {
        if (left.bytes.size() != right.bytes.size()) {
            return left.bytes.size() > right.bytes.size();
        }
        return left.physical < right.physical;
    });
    std::vector<std::pair<std::string, FamilySummary>> largest_families(family_summaries.begin(), family_summaries.end());
    std::sort(largest_families.begin(), largest_families.end(), [](const auto& left, const auto& right) {
        if (left.second.total_bytes != right.second.total_bytes) {
            return left.second.total_bytes > right.second.total_bytes;
        }
        return left.first < right.first;
    });

    std::ostringstream oss;
    oss << "Generated Data Extraction Report\n";
    oss << "==============================\n\n";
    oss << "Entry: " << hex4(image.entry_cs) << ':' << hex4(image.entry_ip).substr(2) << "\n";
    oss << "Load segment: 0x" << hex4(image.layout.load_segment()) << "\n";
    oss << "Load module bytes: " << total_module_bytes << "\n\n";

    oss << "Coverage\n";
    oss << "--------\n";
    oss << "Code regions: " << data_layout.code_regions.size() << " (" << code_bytes << " bytes)\n";
    oss << "Named static symbols: " << data_layout.named_static_regions.size() << " (" << named_bytes << " bytes)\n";
    oss << "Residual regions: " << data_layout.residual_regions.size() << " (" << residual_bytes << " bytes)\n";
    oss << "Writable named symbols: " << writable_symbol_count << " (" << writable_symbol_bytes << " bytes)\n";
    oss << "Readonly named symbols: " << (data_layout.named_static_regions.size() - writable_symbol_count)
        << " (" << readonly_symbol_bytes << " bytes)\n\n";

    oss << "Named Symbol Classification\n";
    oss << "---------------------------\n";
    for (const auto& [classification, count] : named_class_counts) {
        oss << classification << ": " << count << " (" << named_class_bytes[classification] << " bytes)\n";
    }
    oss << "\n";

    oss << "Named Symbol Storage Kinds\n";
    oss << "--------------------------\n";
    for (const auto& [storage_kind, count] : named_storage_counts) {
        oss << storage_kind << ": " << count << " (" << named_storage_bytes[storage_kind] << " bytes)\n";
    }
    oss << "\n";

    oss << "Residual Region Classification\n";
    oss << "------------------------------\n";
    for (const auto& [classification, count] : residual_class_counts) {
        oss << classification << ": " << count << " (" << residual_class_bytes[classification] << " bytes)\n";
    }
    oss << "\n";

    oss << "Top Named Static Regions\n";
    oss << "------------------------\n";
    const std::size_t named_limit = std::min<std::size_t>(20u, largest_named_regions.size());
    for (std::size_t index = 0u; index < named_limit; ++index) {
        const GeneratedDataRegion& region = largest_named_regions[index];
        oss << index + 1u << ". "
            << region.name
            << " seg=" << hex4(region.location.cs)
            << " off=" << hex4(region.location.ip)
            << " phys=0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << region.physical
            << std::dec
            << " size=" << region.bytes.size()
            << " writable=" << (region.writable ? "yes" : "no")
            << " class=" << region.classification
            << " storage=" << region.storage_kind
            << " relocs=" << region.relocation_count
            << " direct_refs=" << region.direct_access_count
            << " stride=" << region.stride_hint << "\n";
    }
    oss << "\n";

    oss << "Top Named Symbol Families\n";
    oss << "------------------------\n";
    const std::size_t family_limit = std::min<std::size_t>(20u, largest_families.size());
    for (std::size_t index = 0u; index < family_limit; ++index) {
        const auto& [family_name, family] = largest_families[index];
        std::string dominant_class;
        std::size_t dominant_count = 0u;
        for (const auto& [classification, count] : family.class_counts) {
            if (count > dominant_count || (count == dominant_count && classification < dominant_class)) {
                dominant_class = classification;
                dominant_count = count;
            }
        }
        oss << index + 1u << ". "
            << family_name
            << " regions=" << family.region_count
            << " bytes=" << family.total_bytes
            << " writable_bytes=" << family.writable_bytes
            << " readonly_bytes=" << family.readonly_bytes
            << " dominant_class=" << dominant_class
            << " relocs=" << family.relocation_count
            << " direct_refs=" << family.direct_access_count << "\n";
    }
    oss << "\n";

    oss << "Top Residual Regions\n";
    oss << "--------------------\n";
    const std::size_t residual_limit = std::min<std::size_t>(20u, largest_residual_regions.size());
    for (std::size_t index = 0u; index < residual_limit; ++index) {
        const GeneratedDataRegion& region = largest_residual_regions[index];
        oss << index + 1u << ". "
            << "phys=0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << region.physical
            << std::dec
            << " size=" << region.bytes.size()
            << " class=" << region.classification
            << " stride=" << region.stride_hint << "\n";
    }

    return oss.str();
}

std::string build_generated_data_symbols_csv_text(const GeneratedDataLayout& data_layout) {
    std::ostringstream oss;
    oss << "name,family_name,segment,offset,physical,size,writable,classification,storage_kind,relocation_count,direct_access_count,stride_hint\n";
    for (const GeneratedDataRegion& region : data_layout.named_static_regions) {
        oss << region.name << ','
            << generated_region_family_name(region.name) << ','
            << "0x" << hex4(region.location.cs) << ','
            << "0x" << hex4(region.location.ip) << ','
            << "0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << region.physical << std::dec << ','
            << region.bytes.size() << ','
            << (region.writable ? "1" : "0") << ','
            << region.classification << ','
            << region.storage_kind << ','
            << region.relocation_count << ','
            << region.direct_access_count << ','
            << region.stride_hint << '\n';
    }
    return oss.str();
}

std::string build_generated_data_families_csv_text(const GeneratedDataLayout& data_layout) {
    struct FamilySummary {
        std::size_t region_count = 0u;
        std::size_t total_bytes = 0u;
        std::size_t writable_bytes = 0u;
        std::size_t readonly_bytes = 0u;
        std::size_t relocation_count = 0u;
        std::size_t direct_access_count = 0u;
        std::map<std::string, std::size_t> class_counts;
    };
    const auto region_family_name = [](const std::string& name) {
        constexpr std::string_view suffix = "_off_";
        if (const std::size_t pos = name.find(suffix); pos != std::string::npos) {
            return name.substr(0u, pos);
        }
        return name;
    };

    std::map<std::string, FamilySummary> families;
    for (const GeneratedDataRegion& region : data_layout.named_static_regions) {
        FamilySummary& family = families[region_family_name(region.name)];
        ++family.region_count;
        family.total_bytes += region.bytes.size();
        family.relocation_count += region.relocation_count;
        family.direct_access_count += region.direct_access_count;
        if (region.writable) {
            family.writable_bytes += region.bytes.size();
        } else {
            family.readonly_bytes += region.bytes.size();
        }
        ++family.class_counts[region.classification];
    }

    std::ostringstream oss;
    oss << "family_name,region_count,total_bytes,writable_bytes,readonly_bytes,relocation_count,direct_access_count,dominant_class\n";
    for (const auto& [family_name, family] : families) {
        std::string dominant_class;
        std::size_t dominant_count = 0u;
        for (const auto& [classification, count] : family.class_counts) {
            if (count > dominant_count || (count == dominant_count && classification < dominant_class)) {
                dominant_class = classification;
                dominant_count = count;
            }
        }
        oss << family_name << ','
            << family.region_count << ','
            << family.total_bytes << ','
            << family.writable_bytes << ','
            << family.readonly_bytes << ','
            << family.relocation_count << ','
            << family.direct_access_count << ','
            << dominant_class << '\n';
    }
    return oss.str();
}

std::string build_generated_static_access_report_text(const CfgSnapshot& snapshot,
                                                      const MzImage& image,
                                                      const EmissionSymbolMap& symbol_map,
                                                      const GeneratedDataLayout& data_layout) {
    struct AccessBucket {
        std::size_t total = 0u;
        std::size_t reads = 0u;
        std::size_t writes = 0u;
    };

    struct NamedStaticBreakdown {
        std::size_t readonly_reads = 0u;
        std::size_t writable_reads = 0u;
        std::size_t writable_writes = 0u;
        std::size_t readonly_writes = 0u;
    };

    const auto build_region_starts = [](const std::vector<GeneratedDataRegion>& regions) {
        std::vector<std::pair<std::uint32_t, std::size_t>> starts;
        starts.reserve(regions.size());
        for (std::size_t index = 0u; index < regions.size(); ++index) {
            starts.emplace_back(regions[index].physical, index);
        }
        std::sort(starts.begin(), starts.end());
        return starts;
    };

    const auto find_region_index =
        [](const std::vector<GeneratedDataRegion>& regions,
           const std::vector<std::pair<std::uint32_t, std::size_t>>& starts,
           const std::uint32_t physical) -> std::optional<std::size_t> {
            auto it = std::upper_bound(
                starts.begin(),
                starts.end(),
                std::pair<std::uint32_t, std::size_t>{physical, std::numeric_limits<std::size_t>::max()});
            if (it == starts.begin()) {
                return std::nullopt;
            }
            --it;
            const GeneratedDataRegion& region = regions[it->second];
            const std::uint32_t region_end = region.physical + static_cast<std::uint32_t>(region.bytes.size());
            if (physical >= region.physical && physical < region_end) {
                return it->second;
            }
            return std::nullopt;
        };

    const auto named_starts = build_region_starts(data_layout.named_static_regions);
    const auto residual_starts = build_region_starts(data_layout.residual_regions);
    const auto code_starts = build_region_starts(data_layout.code_regions);

    AccessBucket named_bucket{};
    AccessBucket residual_bucket{};
    AccessBucket code_bucket{};
    AccessBucket image_gap_bucket{};
    AccessBucket outside_image_bucket{};
    std::size_t unresolved_direct_operands = 0u;
    std::map<std::string, std::size_t> named_family_counts;
    std::map<std::string, std::size_t> readonly_named_family_counts;
    std::map<std::string, std::size_t> writable_named_family_counts;
    std::map<std::string, std::size_t> readonly_named_storage_counts;
    std::map<std::string, AccessBucket> segment_proof_buckets;
    std::map<std::string, NamedStaticBreakdown> named_breakdown_by_proof;
    std::map<std::string, std::size_t> unresolved_direct_reason_counts;
    NamedStaticBreakdown named_breakdown{};

    const auto resolve_operand_segment = [&](const DecodedInstruction& instruction,
                                             const DirectMemoryOperandRef& operand,
                                             const std::map<std::string, std::uint16_t>& tracked_segment_registers)
        -> std::optional<std::pair<std::uint16_t, std::string>> {
        if (operand.segment_name == "cs") {
            return std::make_pair(instruction.cs, std::string("cs_fixed"));
        }
        if (operand.segment_name == "ds") {
            if (const auto it = tracked_segment_registers.find("ds"); it != tracked_segment_registers.end()) {
                if (symbol_map.default_data_segment.has_value() && it->second == *symbol_map.default_data_segment) {
                    return std::make_pair(it->second, std::string("ds_default"));
                }
                return std::make_pair(it->second, std::string("ds_fixed_nondefault"));
            }
            return std::nullopt;
        }
        if (operand.segment_name == "es") {
            if (const auto it = tracked_segment_registers.find("es"); it != tracked_segment_registers.end()) {
                return std::make_pair(it->second, std::string("es_fixed"));
            }
            return std::nullopt;
        }
        if (operand.segment_name == "ss") {
            if (const auto it = tracked_segment_registers.find("ss"); it != tracked_segment_registers.end()) {
                return std::make_pair(it->second, std::string("ss_fixed"));
            }
            return std::nullopt;
        }
        return std::nullopt;
    };

    std::map<std::uint32_t, const BlockRecord*> blocks_by_start;
    std::map<std::uint32_t, std::vector<std::uint32_t>> predecessors_by_block_start;
    std::map<std::uint32_t, std::uint32_t> block_start_by_terminal;
    for (const BlockRecord& block : snapshot.blocks) {
        const std::uint32_t block_key = location_key(block.start);
        blocks_by_start.emplace(block_key, &block);
        if (!block.preview.instructions.empty()) {
            const DecodedInstruction& terminal = block.preview.instructions.back();
            block_start_by_terminal.emplace(location_key(CodeLocation{terminal.cs, terminal.ip}), block_key);
        }
    }
    for (const CfgEdge& edge : snapshot.edges) {
        const auto target_it = blocks_by_start.find(location_key(edge.to));
        if (target_it == blocks_by_start.end()) {
            continue;
        }
        if (const auto pred_it = block_start_by_terminal.find(location_key(edge.from));
            pred_it != block_start_by_terminal.end()) {
            predecessors_by_block_start[target_it->first].push_back(pred_it->second);
        }
    }

    std::map<std::uint32_t, TrackedSegmentState> entry_state_by_block_start;
    std::map<std::uint32_t, TrackedSegmentState> exit_state_by_block_start;
    if (const auto root_it = blocks_by_start.find(location_key(snapshot.root)); root_it != blocks_by_start.end()) {
        TrackedSegmentState root_state;
        if (symbol_map.default_data_segment.has_value()) {
            root_state.segment_registers.emplace("ds", *symbol_map.default_data_segment);
        }
        entry_state_by_block_start.emplace(root_it->first, root_state);
    }

    bool changed = true;
    while (changed) {
        changed = false;
        for (const BlockRecord& block : snapshot.blocks) {
            const std::uint32_t block_key = location_key(block.start);
            std::optional<TrackedSegmentState> merged_entry_state;
            if (const auto existing_it = entry_state_by_block_start.find(block_key);
                existing_it != entry_state_by_block_start.end()) {
                merged_entry_state = existing_it->second;
            }
            if (const auto pred_it = predecessors_by_block_start.find(block_key);
                pred_it != predecessors_by_block_start.end()) {
                for (const std::uint32_t predecessor_key : pred_it->second) {
                    const auto exit_it = exit_state_by_block_start.find(predecessor_key);
                    if (exit_it == exit_state_by_block_start.end()) {
                        continue;
                    }
                    if (!merged_entry_state.has_value()) {
                        merged_entry_state = exit_it->second;
                    } else {
                        merged_entry_state = intersect_tracked_segment_state(*merged_entry_state, exit_it->second);
                    }
                }
            }
            if (!merged_entry_state.has_value()) {
                continue;
            }
            if (const auto existing_it = entry_state_by_block_start.find(block_key);
                existing_it == entry_state_by_block_start.end() || !(existing_it->second == *merged_entry_state)) {
                entry_state_by_block_start[block_key] = *merged_entry_state;
                changed = true;
            }

            TrackedSegmentState exit_state = *merged_entry_state;
            for (const DecodedInstruction& instruction : block.preview.instructions) {
                exit_state = transfer_instruction_tracked_segment_state(std::move(exit_state), instruction);
            }
            if (const auto existing_it = exit_state_by_block_start.find(block_key);
                existing_it == exit_state_by_block_start.end() || !(existing_it->second == exit_state)) {
                exit_state_by_block_start[block_key] = std::move(exit_state);
                changed = true;
            }
        }
    }

    const auto note_bucket = [](AccessBucket& bucket, const bool writes) {
        ++bucket.total;
        if (writes) {
            ++bucket.writes;
        } else {
            ++bucket.reads;
        }
    };

    for (const BlockRecord& block : snapshot.blocks) {
        std::map<std::string, std::uint16_t> tracked_register_offsets;
        TrackedSegmentState tracked_state;
        if (const auto entry_it = entry_state_by_block_start.find(location_key(block.start));
            entry_it != entry_state_by_block_start.end()) {
            tracked_state = entry_it->second;
        }
        for (const DecodedInstruction& instruction : block.preview.instructions) {
            const std::size_t first_space = instruction.text.find(' ');
            const std::string_view mnemonic =
                first_space == std::string::npos
                    ? std::string_view(instruction.text)
                    : std::string_view(instruction.text).substr(0u, first_space);
            const std::vector<std::string> operands = instruction_operand_texts(instruction);
            if (operands.empty()) {
                continue;
            }

            std::vector<std::size_t> memory_operand_indexes;
            for (std::size_t operand_index = 0u; operand_index < operands.size(); ++operand_index) {
                if (resolve_static_memory_operand_text(
                        operands[operand_index], tracked_register_offsets, symbol_map.default_data_segment, instruction.cs)
                        .has_value()) {
                    memory_operand_indexes.push_back(operand_index);
                }
            }

            std::vector<std::size_t> written_operand_indexes;
            if (!memory_operand_indexes.empty()) {
                if (mnemonic_writes_first_operand(mnemonic)) {
                    written_operand_indexes.push_back(0u);
                }
                if (mnemonic_writes_any_memory_operand(mnemonic)) {
                    written_operand_indexes.insert(written_operand_indexes.end(),
                                                  memory_operand_indexes.begin(),
                                                  memory_operand_indexes.end());
                }
                std::sort(written_operand_indexes.begin(), written_operand_indexes.end());
                written_operand_indexes.erase(
                    std::unique(written_operand_indexes.begin(), written_operand_indexes.end()),
                    written_operand_indexes.end());
            }

            for (std::size_t operand_index = 0u; operand_index < operands.size(); ++operand_index) {
                const std::optional<DirectMemoryOperandRef> parsed_direct =
                    parse_direct_memory_operand_text(operands[operand_index]);
                if (!parsed_direct.has_value()) {
                    continue;
                }

                const bool writes =
                    std::binary_search(written_operand_indexes.begin(), written_operand_indexes.end(), operand_index);
                const auto resolved_segment =
                    resolve_operand_segment(instruction, *parsed_direct, tracked_state.segment_registers);
                if (!resolved_segment.has_value()) {
                    ++unresolved_direct_operands;
                    const std::string segment_name =
                        parsed_direct->segment_name.empty() ? "ds" : parsed_direct->segment_name;
                    ++unresolved_direct_reason_counts[segment_name + "_unknown_or_dynamic"];
                    continue;
                }
                const std::uint32_t physical =
                    (((static_cast<std::uint32_t>(resolved_segment->first) << 4u) +
                      static_cast<std::uint32_t>(parsed_direct->offset)) &
                     0xFFFFFu);
                note_bucket(segment_proof_buckets[resolved_segment->second], writes);

                if (const auto named_index =
                        find_region_index(data_layout.named_static_regions, named_starts, physical);
                    named_index.has_value()) {
                    note_bucket(named_bucket, writes);
                    const GeneratedDataRegion& region = data_layout.named_static_regions[*named_index];
                    const std::string family_name = generated_region_family_name(region.name);
                    NamedStaticBreakdown& proof_breakdown = named_breakdown_by_proof[resolved_segment->second];
                    ++named_family_counts[family_name];
                    if (writes) {
                        if (region.writable) {
                            ++named_breakdown.writable_writes;
                            ++proof_breakdown.writable_writes;
                        } else {
                            ++named_breakdown.readonly_writes;
                            ++proof_breakdown.readonly_writes;
                        }
                    } else {
                        if (region.writable) {
                            ++named_breakdown.writable_reads;
                            ++proof_breakdown.writable_reads;
                            ++writable_named_family_counts[family_name];
                        } else {
                            ++named_breakdown.readonly_reads;
                            ++proof_breakdown.readonly_reads;
                            ++readonly_named_family_counts[family_name];
                            ++readonly_named_storage_counts[region.storage_kind];
                        }
                    }
                    continue;
                }
                if (find_region_index(data_layout.residual_regions, residual_starts, physical).has_value()) {
                    note_bucket(residual_bucket, writes);
                    continue;
                }
                if (find_region_index(data_layout.code_regions, code_starts, physical).has_value()) {
                    note_bucket(code_bucket, writes);
                    continue;
                }
                if (physical >= image.load_module_physical && physical < image.image_end_physical) {
                    note_bucket(image_gap_bucket, writes);
                    continue;
                }
                note_bucket(outside_image_bucket, writes);
            }

            if (operands.size() >= 2u) {
                if (const auto tracked = parse_tracked_register_name(operands[0]); tracked.has_value()) {
                    if (const auto immediate = parse_immediate_hex16_operand(operands[1]); immediate.has_value()) {
                        tracked_register_offsets[*tracked] = *immediate;
                    }
                }
            }
            tracked_state = transfer_instruction_tracked_segment_state(std::move(tracked_state), instruction);
        }
    }

    std::vector<std::pair<std::string, std::size_t>> top_named_families(
        named_family_counts.begin(), named_family_counts.end());
    std::sort(top_named_families.begin(),
              top_named_families.end(),
              [](const auto& left, const auto& right) {
                  if (left.second != right.second) {
                      return left.second > right.second;
                  }
                  return left.first < right.first;
              });

    const auto sort_count_map = [](const auto& source) {
        std::vector<std::pair<std::string, std::size_t>> items(source.begin(), source.end());
        std::sort(items.begin(),
                  items.end(),
                  [](const auto& left, const auto& right) {
                      if (left.second != right.second) {
                          return left.second > right.second;
                      }
                      return left.first < right.first;
                  });
        return items;
    };

    const std::vector<std::pair<std::string, std::size_t>> top_readonly_named_families =
        sort_count_map(readonly_named_family_counts);
    const std::vector<std::pair<std::string, std::size_t>> top_writable_named_families =
        sort_count_map(writable_named_family_counts);
    const std::vector<std::pair<std::string, std::size_t>> top_readonly_named_storage =
        sort_count_map(readonly_named_storage_counts);
    const std::vector<std::pair<std::string, std::size_t>> top_unresolved_direct_reasons =
        sort_count_map(unresolved_direct_reason_counts);

    const std::size_t resolved_total = named_bucket.total + residual_bucket.total + code_bucket.total +
                                       image_gap_bucket.total + outside_image_bucket.total;

    std::ostringstream oss;
    oss << "Generated Static Access Readiness Report\n";
    oss << "======================================\n";
    oss << "Resolved direct static accesses: " << resolved_total << "\n";
    oss << "Unresolved direct operands: " << unresolved_direct_operands << "\n\n";

    const auto emit_bucket = [&oss](const char* name, const AccessBucket& bucket) {
        oss << name << ": total=" << bucket.total
            << " reads=" << bucket.reads
            << " writes=" << bucket.writes << "\n";
    };

    emit_bucket("named_static", named_bucket);
    emit_bucket("residual", residual_bucket);
    emit_bucket("code_region", code_bucket);
    emit_bucket("image_gap", image_gap_bucket);
    emit_bucket("outside_image", outside_image_bucket);

    oss << "\nNamed static access breakdown:\n";
    oss << "  readonly reads (overlay-safe candidates): " << named_breakdown.readonly_reads << "\n";
    oss << "  writable reads: " << named_breakdown.writable_reads << "\n";
    oss << "  writes to writable named statics: " << named_breakdown.writable_writes << "\n";
    oss << "  writes to readonly named statics: " << named_breakdown.readonly_writes << "\n";

    oss << "\nNamed static breakdown by segment proof:\n";
    if (named_breakdown_by_proof.empty()) {
        oss << "  (none)\n";
    } else {
        for (const auto& [proof_name, breakdown] : named_breakdown_by_proof) {
            oss << "  " << proof_name
                << ": readonly_reads=" << breakdown.readonly_reads
                << " writable_reads=" << breakdown.writable_reads
                << " writable_writes=" << breakdown.writable_writes
                << " readonly_writes=" << breakdown.readonly_writes << "\n";
        }
    }

    oss << "\nDirect access segment proof buckets:\n";
    if (segment_proof_buckets.empty()) {
        oss << "  (none)\n";
    } else {
        for (const auto& [proof_name, bucket] : segment_proof_buckets) {
            oss << "  " << proof_name << ": total=" << bucket.total
                << " reads=" << bucket.reads
                << " writes=" << bucket.writes << "\n";
        }
    }

    oss << "\nUnresolved direct operand reasons:\n";
    if (top_unresolved_direct_reasons.empty()) {
        oss << "  (none)\n";
    } else {
        const std::size_t limit = std::min<std::size_t>(10u, top_unresolved_direct_reasons.size());
        for (std::size_t index = 0u; index < limit; ++index) {
            oss << "  " << top_unresolved_direct_reasons[index].first << ": "
                << top_unresolved_direct_reasons[index].second << "\n";
        }
    }

    oss << "\nTop readonly named storage kinds by direct reads:\n";
    if (top_readonly_named_storage.empty()) {
        oss << "  (none)\n";
    } else {
        const std::size_t limit = std::min<std::size_t>(10u, top_readonly_named_storage.size());
        for (std::size_t index = 0u; index < limit; ++index) {
            oss << "  " << top_readonly_named_storage[index].first << ": "
                << top_readonly_named_storage[index].second << "\n";
        }
    }

    oss << "\nTop named static families by direct accesses:\n";
    if (top_named_families.empty()) {
        oss << "  (none)\n";
    } else {
        const std::size_t limit = std::min<std::size_t>(20u, top_named_families.size());
        for (std::size_t index = 0u; index < limit; ++index) {
            oss << "  " << top_named_families[index].first << ": "
                << top_named_families[index].second << "\n";
        }
    }

    oss << "\nTop readonly named families by direct reads:\n";
    if (top_readonly_named_families.empty()) {
        oss << "  (none)\n";
    } else {
        const std::size_t limit = std::min<std::size_t>(20u, top_readonly_named_families.size());
        for (std::size_t index = 0u; index < limit; ++index) {
            oss << "  " << top_readonly_named_families[index].first << ": "
                << top_readonly_named_families[index].second << "\n";
        }
    }

    oss << "\nTop writable named families by direct reads:\n";
    if (top_writable_named_families.empty()) {
        oss << "  (none)\n";
    } else {
        const std::size_t limit = std::min<std::size_t>(20u, top_writable_named_families.size());
        for (std::size_t index = 0u; index < limit; ++index) {
            oss << "  " << top_writable_named_families[index].first << ": "
                << top_writable_named_families[index].second << "\n";
        }
    }

    return oss.str();
}

using BlockMap = std::map<std::uint32_t, const BlockRecord*>;

BlockMap build_block_map(const CfgSnapshot& snapshot) {
    BlockMap block_map;
    for (const BlockRecord& block : snapshot.blocks) {
        block_map.emplace(location_key(block.start), &block);
    }
    return block_map;
}

std::map<std::uint32_t, std::vector<CodeLocation>> build_resolved_indirect_call_targets(const CfgSnapshot& snapshot) {
    std::map<std::uint32_t, std::vector<CodeLocation>> targets;
    for (const IndirectSiteRecord& site : snapshot.indirect_sites) {
        if (site.kind != EdgeKind::Call || site.resolved_targets.empty()) {
            continue;
        }
        targets.emplace(location_key(site.from), site.resolved_targets);
    }
    return targets;
}

std::map<std::uint32_t, std::vector<CodeLocation>> build_resolved_indirect_branch_targets(const CfgSnapshot& snapshot) {
    std::map<std::uint32_t, std::vector<CodeLocation>> targets;
    for (const IndirectSiteRecord& site : snapshot.indirect_sites) {
        if (site.kind != EdgeKind::Branch || site.resolved_targets.empty()) {
            continue;
        }
        targets.emplace(location_key(site.from), site.resolved_targets);
    }
    return targets;
}

std::map<std::uint32_t, const IndirectSiteRecord*> build_indirect_site_map(const CfgSnapshot& snapshot) {
    std::map<std::uint32_t, const IndirectSiteRecord*> sites;
    for (const IndirectSiteRecord& site : snapshot.indirect_sites) {
        sites.emplace(location_key(site.from), &site);
    }
    return sites;
}

std::string build_calltable_signature(const IndirectSiteRecord& site) {
    std::ostringstream oss;
    oss << static_cast<unsigned>(site.dispatch_kind) << '|';
    for (const IndirectDispatchEntry& entry : site.dispatch_entries) {
        oss << hex4(entry.selector) << ':'
            << hex4(entry.target.cs) << ':'
            << hex4(entry.target.ip) << ':'
            << (entry.target_is_valid ? '1' : '0') << ';';
    }
    return oss.str();
}

std::map<std::uint32_t, std::uint32_t> build_canonical_calltable_keys(const CfgSnapshot& snapshot) {
    std::map<std::uint32_t, std::uint32_t> canonical_calltable_keys;
    std::map<std::string, std::uint32_t> canonical_by_signature;
    for (const IndirectSiteRecord& site : snapshot.indirect_sites) {
        if (!site_uses_generated_calltable(site)) {
            continue;
        }

        const std::string signature = build_calltable_signature(site);
        const std::uint32_t site_key = location_key(site.from);
        const auto [it, inserted] = canonical_by_signature.emplace(signature, site_key);
        canonical_calltable_keys.emplace(site_key, inserted ? site_key : it->second);
    }
    return canonical_calltable_keys;
}

void append_generated_calltable_definitions(std::ostringstream& oss,
                                            const CfgSnapshot& snapshot,
                                            const std::set<std::uint32_t>& emitted_function_keys,
                                            const std::map<std::uint32_t, std::uint32_t>& canonical_calltable_keys) {
    for (const IndirectSiteRecord& site : snapshot.indirect_sites) {
        if (!site_uses_generated_calltable(site)) {
            continue;
        }
        const std::uint32_t site_key = location_key(site.from);
        if (const auto canonical_it = canonical_calltable_keys.find(site_key);
            canonical_it != canonical_calltable_keys.end() && canonical_it->second != site_key) {
            continue;
        }

        if (site.dispatch_kind == IndirectDispatchKind::CurrentCsWordTable) {
            oss << "static const GeneratedWordCallTableEntry "
                << canonical_calltable_name(canonical_calltable_keys, site.from) << "[] = {\n";
            for (const IndirectDispatchEntry& entry : site.dispatch_entries) {
                oss << "    {0x" << hex4(entry.selector) << "u, 0x" << hex4(entry.target.ip) << "u, ";
                if (entry.target_is_valid && emitted_function_keys.contains(location_key(entry.target))) {
                    oss << function_name(entry.target);
                } else {
                    oss << "0";
                }
                oss << "},\n";
            }
            oss << "};\n\n";
            continue;
        }

        oss << "static const GeneratedPairCallTableEntry "
            << canonical_calltable_name(canonical_calltable_keys, site.from) << "[] = {\n";
        for (const IndirectDispatchEntry& entry : site.dispatch_entries) {
            oss << "    {0x" << hex4(entry.selector) << "u, 0x" << hex4(entry.target.ip) << "u, ";
            if (entry.target_is_valid && emitted_function_keys.contains(location_key(entry.target))) {
                oss << function_name(entry.target);
            } else {
                oss << "0";
            }
            oss << "},\n";
        }
        oss << "};\n\n";
    }
}

void append_generated_interface_surface_definitions(std::ostringstream& oss,
                                                    const CfgSnapshot& snapshot,
                                                    const std::set<std::uint32_t>& emitted_function_keys) {
    for (const InterfaceSurfaceRecord& surface : snapshot.interface_surfaces) {
        if (surface.entries.empty()) {
            continue;
        }

        oss << "static const GeneratedInterfaceSurfaceEntry " << interface_surface_array_name(surface) << "[] = {\n";
        for (const InterfaceSurfaceEntry& entry : surface.entries) {
            oss << "    {0x" << hex4(entry.ordinal) << "u, 0x" << hex4(entry.target.cs) << "u, 0x" << hex4(entry.target.ip) << "u, ";
            if (entry.target_is_valid && emitted_function_keys.contains(location_key(entry.target))) {
                oss << function_name(entry.target);
            } else {
                oss << "0";
            }
            oss << "},\n";
        }
        oss << "};\n\n";
    }
}

std::set<std::uint32_t> build_function_label_keys(const std::vector<CodeLocation>& function_blocks,
                                                  const BlockMap& block_map,
                                                  const std::set<std::uint32_t>& function_block_keys) {
    std::set<std::uint32_t> instruction_keys = function_block_keys;
    for (const CodeLocation block_location : function_blocks) {
        const auto it = block_map.find(location_key(block_location));
        if (it == block_map.end()) {
            continue;
        }
        const BlockRecord& block = *it->second;
        for (const DecodedInstruction& instruction : block.preview.instructions) {
            instruction_keys.insert(location_key(CodeLocation{instruction.cs, instruction.ip}));
        }
    }

    std::set<std::uint32_t> label_keys = function_block_keys;
    for (const CodeLocation block_location : function_blocks) {
        const auto it = block_map.find(location_key(block_location));
        if (it == block_map.end()) {
            continue;
        }
        const BlockRecord& block = *it->second;
        for (const DecodedInstruction& instruction : block.preview.instructions) {
            const std::uint32_t instruction_key = location_key(CodeLocation{instruction.cs, instruction.ip});
            if (instruction.branch_target_ip.has_value()) {
                const CodeLocation target{
                    instruction.branch_target_cs.value_or(instruction.cs),
                    *instruction.branch_target_ip,
                };
                const std::uint32_t target_key = location_key(target);
                if (function_block_keys.contains(target_key) ||
                    (instruction_keys.contains(target_key) && target_key < instruction_key)) {
                    label_keys.insert(target_key);
                }
            }
            if (instruction.branch_fallthrough_ip.has_value()) {
                const CodeLocation target{instruction.cs, *instruction.branch_fallthrough_ip};
                const std::uint32_t target_key = location_key(target);
                if (function_block_keys.contains(target_key) ||
                    (instruction_keys.contains(target_key) && target_key < instruction_key)) {
                    label_keys.insert(target_key);
                }
            }
        }
    }

    return label_keys;
}

bool preview_has_implicit_fallthrough(const BasicBlockPreview& preview) {
    return !preview.terminated && preview.termination_reason == "instruction limit reached";
}

bool block_needs_irq_checkpoint(const BlockRecord& block) {
    const BasicBlockPreview& preview = block.preview;
    if (preview.instructions.empty()) {
        return false;
    }

    const DecodedInstruction& terminal = preview.instructions.back();
    if (terminal.flow != FlowKind::ConditionalBranch || !terminal.branch_target_ip.has_value()) {
        return false;
    }

    if (terminal.cs != preview.cs || *terminal.branch_target_ip != preview.start_ip) {
        return false;
    }

    for (const DecodedInstruction& instruction : preview.instructions) {
        if (instruction.flow == FlowKind::Call ||
            instruction.flow == FlowKind::Interrupt ||
            instruction.flow == FlowKind::Return ||
            instruction.flow == FlowKind::Halt) {
            return false;
        }
    }

    return true;
}

std::vector<CodeLocation> build_non_call_reachable_blocks(const CfgSnapshot&,
                                                          const BlockMap& block_map,
                                                          const CodeLocation root,
                                                          const std::map<std::uint32_t, std::vector<CodeLocation>>& resolved_indirect_branches) {
    std::set<std::uint32_t> visited;
    std::vector<CodeLocation> ordered;
    std::vector<CodeLocation> worklist;
    worklist.push_back(root);
    while (!worklist.empty()) {
        const CodeLocation current = worklist.back();
        worklist.pop_back();
        const std::uint32_t current_key = location_key(current);
        if (!block_map.contains(current_key) || visited.contains(current_key)) {
            continue;
        }
        visited.insert(current_key);
        ordered.push_back(current);

        const BlockRecord& block = *block_map.at(current_key);
        std::vector<CodeLocation> block_successors;
        bool has_split_successor = false;
        for (std::size_t instruction_index = 1; instruction_index < block.preview.instructions.size(); ++instruction_index) {
            const DecodedInstruction& instruction = block.preview.instructions[instruction_index];
            const CodeLocation split_target{instruction.cs, instruction.ip};
            if (!block_map.contains(location_key(split_target))) {
                continue;
            }
            block_successors.push_back(split_target);
            has_split_successor = true;
            break;
        }

        if (!has_split_successor && !block.preview.instructions.empty()) {
            const DecodedInstruction& terminal = block.preview.instructions.back();
            if (terminal.flow == FlowKind::ConditionalBranch) {
                if (terminal.branch_target_ip.has_value()) {
                    block_successors.push_back(CodeLocation{
                        terminal.branch_target_cs.value_or(terminal.cs),
                        *terminal.branch_target_ip,
                    });
                }
                if (terminal.branch_fallthrough_ip.has_value()) {
                    block_successors.push_back(CodeLocation{terminal.cs, *terminal.branch_fallthrough_ip});
                }
            } else if (terminal.flow == FlowKind::UnconditionalBranch) {
                if (terminal.branch_target_ip.has_value()) {
                    block_successors.push_back(CodeLocation{
                        terminal.branch_target_cs.value_or(terminal.cs),
                        *terminal.branch_target_ip,
                    });
                } else if (terminal.indirect.has_value()) {
                    const auto branch_it =
                        resolved_indirect_branches.find(location_key(CodeLocation{terminal.cs, terminal.ip}));
                    if (branch_it != resolved_indirect_branches.end()) {
                        for (const CodeLocation target : branch_it->second) {
                            block_successors.push_back(target);
                        }
                    }
                }
            } else if (preview_has_implicit_fallthrough(block.preview) &&
                       terminal.branch_fallthrough_ip.has_value()) {
                block_successors.push_back(CodeLocation{terminal.cs, *terminal.branch_fallthrough_ip});
            }
        }

        block_successors.erase(
            std::remove_if(
                block_successors.begin(),
                block_successors.end(),
                [&block_map](const CodeLocation target) { return !block_map.contains(location_key(target)); }),
            block_successors.end());
        std::sort(block_successors.begin(), block_successors.end(), [](const CodeLocation& left, const CodeLocation& right) {
            return location_key(left) < location_key(right);
        });
        block_successors.erase(
            std::unique(block_successors.begin(), block_successors.end(), [](const CodeLocation& left, const CodeLocation& right) {
                return location_key(left) == location_key(right);
            }),
            block_successors.end());

        if (block_successors.empty()) {
            continue;
        }
        for (auto succ_it = block_successors.rbegin(); succ_it != block_successors.rend(); ++succ_it) {
            worklist.push_back(*succ_it);
        }
    }

    std::sort(ordered.begin(), ordered.end(), [](const CodeLocation& left, const CodeLocation& right) {
        return location_key(left) < location_key(right);
    });
    return ordered;
}

std::set<std::uint32_t> build_callable_root_keys(const CfgSnapshot& snapshot) {
    std::set<std::uint32_t> callable_root_keys;
    callable_root_keys.insert(location_key(snapshot.root));
    for (const BlockRecord& block : snapshot.blocks) {
        for (const DecodedInstruction& instruction : block.preview.instructions) {
            if (instruction.flow != FlowKind::Call || !instruction.branch_target_ip.has_value()) {
                continue;
            }
            callable_root_keys.insert(location_key(CodeLocation{
                instruction.branch_target_cs.value_or(instruction.cs),
                *instruction.branch_target_ip,
            }));
        }
    }
    for (const CfgEdge& edge : snapshot.edges) {
        if (edge.kind == EdgeKind::Call) {
            callable_root_keys.insert(location_key(edge.to));
        }
    }
    for (const IndirectSiteRecord& site : snapshot.indirect_sites) {
        if (site.kind != EdgeKind::Call) {
            continue;
        }
        for (const CodeLocation target : site.resolved_targets) {
            callable_root_keys.insert(location_key(target));
        }
    }
    return callable_root_keys;
}

std::set<std::uint32_t> build_direct_call_target_keys(const CfgSnapshot& snapshot) {
    std::set<std::uint32_t> direct_call_target_keys;
    for (const BlockRecord& block : snapshot.blocks) {
        for (const DecodedInstruction& instruction : block.preview.instructions) {
            if (instruction.flow != FlowKind::Call ||
                instruction.indirect.has_value() ||
                !instruction.branch_target_ip.has_value()) {
                continue;
            }
            direct_call_target_keys.insert(location_key(CodeLocation{
                instruction.branch_target_cs.value_or(instruction.cs),
                *instruction.branch_target_ip,
            }));
        }
    }
    return direct_call_target_keys;
}

std::map<std::uint32_t, std::set<std::uint32_t>> build_reachable_keys_by_root(
    const CfgSnapshot& snapshot,
    const BlockMap& block_map,
    const std::set<std::uint32_t>& root_keys) {
    const std::map<std::uint32_t, std::vector<CodeLocation>> resolved_indirect_branches =
        build_resolved_indirect_branch_targets(snapshot);
    std::map<std::uint32_t, std::set<std::uint32_t>> reachable_keys_by_root;
    for (const std::uint32_t root_key : root_keys) {
        if (!block_map.contains(root_key)) {
            continue;
        }
        std::set<std::uint32_t> reachable_keys;
        for (const CodeLocation block :
             build_non_call_reachable_blocks(snapshot, block_map, key_to_location(root_key), resolved_indirect_branches)) {
            reachable_keys.insert(location_key(block));
        }
        reachable_keys_by_root.emplace(root_key, std::move(reachable_keys));
    }
    return reachable_keys_by_root;
}

std::set<std::uint32_t> build_public_root_keys(const CfgSnapshot& snapshot, const BlockMap& block_map) {
    std::set<std::uint32_t> public_root_keys = build_callable_root_keys(snapshot);
    std::set<std::uint32_t> function_entry_root_keys;
    for (const FunctionRecord& function : snapshot.functions) {
        if (!function.entry_block_present || function.reachable_blocks.empty()) {
            continue;
        }
        function_entry_root_keys.insert(location_key(function.entry));
    }
    const std::map<std::uint32_t, std::set<std::uint32_t>> reachable_keys_by_root =
        build_reachable_keys_by_root(snapshot, block_map, function_entry_root_keys);

    for (const auto& [root_key, reachable_keys] : reachable_keys_by_root) {
        bool absorbed_by_other_root = false;
        for (const auto& [other_root_key, other_reachable_keys] : reachable_keys_by_root) {
            if (other_root_key == root_key) {
                continue;
            }
            if (other_reachable_keys.contains(root_key)) {
                absorbed_by_other_root = true;
                break;
            }
        }
        if (!absorbed_by_other_root) {
            public_root_keys.insert(root_key);
        }
    }

    for (const InterfaceSurfaceRecord& surface : snapshot.interface_surfaces) {
        for (const InterfaceSurfaceEntry& entry : surface.entries) {
            if (entry.target_is_valid) {
                public_root_keys.insert(location_key(entry.target));
            }
        }
    }
    if (snapshot_uses_routine_pack_callable_surfaces(snapshot)) {
        public_root_keys.insert(location_key(CodeLocation{0x4A56u, 0x0010u}));
    }

    // This label is an internal startup block, not a real callable function entry.
    public_root_keys.erase(location_key(CodeLocation{0x1010u, 0x0040u}));

    return public_root_keys;
}

std::set<std::uint32_t> build_dispatchable_root_keys(const CfgSnapshot& snapshot,
                                                     const std::set<std::uint32_t>& public_root_keys) {
    std::set<std::uint32_t> dispatchable_root_keys = public_root_keys;
    const std::set<std::uint32_t> direct_call_target_keys = build_direct_call_target_keys(snapshot);
    std::set<std::uint32_t> required_dispatch_keys;
    required_dispatch_keys.insert(location_key(snapshot.root));

    for (const IndirectSiteRecord& site : snapshot.indirect_sites) {
        for (const CodeLocation target : site.resolved_targets) {
            required_dispatch_keys.insert(location_key(target));
        }
    }

    for (const InterfaceSurfaceRecord& surface : snapshot.interface_surfaces) {
        for (const InterfaceSurfaceEntry& entry : surface.entries) {
            if (entry.target_is_valid) {
                required_dispatch_keys.insert(location_key(entry.target));
            }
        }
    }

    for (const FunctionRecord& function : snapshot.functions) {
        if (!function.external_entry_blocks.empty()) {
            required_dispatch_keys.insert(location_key(function.entry));
        }
    }

    for (auto it = dispatchable_root_keys.begin(); it != dispatchable_root_keys.end();) {
        if (direct_call_target_keys.contains(*it) && !required_dispatch_keys.contains(*it)) {
            it = dispatchable_root_keys.erase(it);
        } else {
            ++it;
        }
    }

    dispatchable_root_keys.erase(location_key(CodeLocation{0x1010u, 0x0040u}));

    return dispatchable_root_keys;
}

std::set<std::uint32_t> build_forced_self_owned_root_keys() {
    return {
        location_key(CodeLocation{0x1010u, 0x1187u}),
        location_key(CodeLocation{0x1010u, 0x11B8u}),
        location_key(CodeLocation{0x1010u, 0x1D67u}),
        location_key(CodeLocation{0x1010u, 0x1D6Fu}),
        location_key(CodeLocation{0x1010u, 0x1D83u}),
        location_key(CodeLocation{0x1010u, 0x1D8Bu}),
        location_key(CodeLocation{0x1010u, 0x1D93u}),
        location_key(CodeLocation{0x1010u, 0x1D95u}),
        location_key(CodeLocation{0x1010u, 0x1D9Du}),
        location_key(CodeLocation{0x1010u, 0x205Bu}),
        location_key(CodeLocation{0x1010u, 0x2108u}),
        location_key(CodeLocation{0x1010u, 0x21B0u}),
        location_key(CodeLocation{0x1010u, 0x22C4u}),
        location_key(CodeLocation{0x1010u, 0x288Au}),
        location_key(CodeLocation{0x1010u, 0x28A0u}),
        location_key(CodeLocation{0x1010u, 0x2A04u}),
        location_key(CodeLocation{0x1010u, 0x2A09u}),
        location_key(CodeLocation{0x1010u, 0x2C67u}),
        location_key(CodeLocation{0x1010u, 0x2C72u}),
        location_key(CodeLocation{0x1010u, 0x2FE3u}),
        location_key(CodeLocation{0x1010u, 0x31A3u}),
        location_key(CodeLocation{0x1010u, 0x34BFu}),
        location_key(CodeLocation{0x1010u, 0x34F4u}),
        location_key(CodeLocation{0x1010u, 0x407Fu}),
        location_key(CodeLocation{0x1010u, 0x40A4u}),
        location_key(CodeLocation{0x1010u, 0x40A9u}),
        location_key(CodeLocation{0x1010u, 0x410Eu}),
        location_key(CodeLocation{0x1010u, 0x5CB8u}),
        location_key(CodeLocation{0x1010u, 0x5CD4u}),
        location_key(CodeLocation{0x1010u, 0x5108u}),
        location_key(CodeLocation{0x1010u, 0x5114u}),
        location_key(CodeLocation{0x1010u, 0x51D8u}),
        location_key(CodeLocation{0x1010u, 0x51E2u}),
        location_key(CodeLocation{0x1010u, 0x6896u}),
        location_key(CodeLocation{0x1010u, 0x689Cu}),
        location_key(CodeLocation{0x1010u, 0x6A37u}),
        location_key(CodeLocation{0x1010u, 0x6A44u}),
        location_key(CodeLocation{0x1010u, 0x7736u}),
        location_key(CodeLocation{0x1010u, 0x779Fu}),
        location_key(CodeLocation{0x1010u, 0x7742u}),
        location_key(CodeLocation{0x1010u, 0x7755u}),
        location_key(CodeLocation{0x1010u, 0x77FDu}),
        location_key(CodeLocation{0x1010u, 0x7804u}),
        location_key(CodeLocation{0x1010u, 0x78D5u}),
        location_key(CodeLocation{0x1010u, 0x78DEu}),
        location_key(CodeLocation{0x1010u, 0x7902u}),
        location_key(CodeLocation{0x1010u, 0x799Au}),
        location_key(CodeLocation{0x1010u, 0x799Fu}),
        location_key(CodeLocation{0x1010u, 0x79BBu}),
        location_key(CodeLocation{0x1010u, 0x79C2u}),
        location_key(CodeLocation{0x1010u, 0x7B0Fu}),
        location_key(CodeLocation{0x1010u, 0x7D26u}),
        location_key(CodeLocation{0x1010u, 0x7D2Du}),
        location_key(CodeLocation{0x1010u, 0x7DB6u}),
        location_key(CodeLocation{0x1010u, 0x7DE1u}),
        location_key(CodeLocation{0x1010u, 0x81C3u}),
        location_key(CodeLocation{0x1010u, 0x81C8u}),
        location_key(CodeLocation{0x1010u, 0x826Du}),
        location_key(CodeLocation{0x1010u, 0x8275u}),
        location_key(CodeLocation{0x1010u, 0x865Eu}),
        location_key(CodeLocation{0x1010u, 0x8665u}),
        location_key(CodeLocation{0x1010u, 0x86B1u}),
        location_key(CodeLocation{0x1010u, 0x86CAu}),
        location_key(CodeLocation{0x1010u, 0x868Bu}),
        location_key(CodeLocation{0x1010u, 0x8692u}),
        location_key(CodeLocation{0x1010u, 0x9C97u}),
        location_key(CodeLocation{0x1010u, 0x9CABu}),
        location_key(CodeLocation{0x1010u, 0xA621u}),
        location_key(CodeLocation{0x1010u, 0xA623u}),
        location_key(CodeLocation{0x4A56u, 0x0001u}),
        location_key(CodeLocation{0x4A56u, 0x001Au}),
        location_key(CodeLocation{0x4A56u, 0x0004u}),
        location_key(CodeLocation{0x4A56u, 0x0010u}),
        location_key(CodeLocation{0x4A56u, 0x0208u}),
        location_key(CodeLocation{0x4A56u, 0x037Au}),
        location_key(CodeLocation{0x4A56u, 0x0753u}),
        location_key(CodeLocation{0x4A56u, 0x0764u}),
        location_key(CodeLocation{0x4A56u, 0x07AFu}),
        location_key(CodeLocation{0x4A56u, 0x07B4u}),
        location_key(CodeLocation{0x4A56u, 0x093Eu}),
        location_key(CodeLocation{0x4A56u, 0x0948u}),
        location_key(CodeLocation{0x4A56u, 0x095Eu}),
        location_key(CodeLocation{0x4A56u, 0x0973u}),
        location_key(CodeLocation{0x4A56u, 0x0AF5u}),
        location_key(CodeLocation{0x4A56u, 0x0B28u}),
        location_key(CodeLocation{0x4A56u, 0x0BA3u}),
    };
}

struct FunctionSignatureSummary {
    CodeLocation entry{};
    std::string name;
    std::size_t block_count = 0u;
    std::size_t instruction_count = 0u;
    std::size_t incoming_call_sites = 0u;
    std::size_t outgoing_call_sites = 0u;
    std::size_t indirect_call_sites = 0u;
    std::size_t indirect_branch_sites = 0u;
    std::size_t external_entry_count = 0u;
    std::size_t shared_block_count = 0u;
    bool reads_memory = false;
    bool writes_memory = false;
    bool uses_non_frame_memory = false;
    bool uses_return_frame_memory = false;
    bool reads_flags = false;
    bool writes_flags = false;
    bool touches_stack_pointer = false;
    bool uses_non_frame_stack_pointer = false;
    bool uses_return_frame_stack_pointer = false;
    enum class ReturnKind {
        None,
        Near,
        Far,
        Mixed,
    } return_kind = ReturnKind::None;
    std::set<std::string> candidate_inputs;
    std::set<std::string> written_registers;
    std::set<std::string> preserved_registers;
    std::set<int> stack_read_offsets;
    std::set<int> stack_write_offsets;
    int helper_score = 0;
    bool helper_candidate = false;
    std::string prototype_hint;
};

std::string instruction_mnemonic_text(const DecodedInstruction& instruction) {
    const std::string text = trim_ascii(instruction.text);
    if (text.empty()) {
        return {};
    }

    const auto next_token = [&](const std::size_t offset) {
        const std::size_t start = text.find_first_not_of(' ', offset);
        if (start == std::string::npos) {
            return std::string{};
        }
        const std::size_t end = text.find(' ', start);
        return trim_ascii(text.substr(start, end == std::string::npos ? std::string::npos : end - start));
    };

    std::string mnemonic = next_token(0u);
    if (mnemonic == "rep" || mnemonic == "repe" || mnemonic == "repne" ||
        mnemonic == "repz" || mnemonic == "repnz") {
        const std::size_t first_space = text.find(' ');
        if (first_space != std::string::npos) {
            const std::string next = next_token(first_space + 1u);
            if (!next.empty()) {
                mnemonic = next;
            }
        }
    }
    return mnemonic;
}

std::optional<std::string> normalize_signature_register_name(const std::string& operand_text) {
    const std::string text = trim_ascii(operand_text);
    if (text == "al" || text == "ah" || text == "ax") {
        return std::string("ax");
    }
    if (text == "bl" || text == "bh" || text == "bx") {
        return std::string("bx");
    }
    if (text == "cl" || text == "ch" || text == "cx") {
        return std::string("cx");
    }
    if (text == "dl" || text == "dh" || text == "dx") {
        return std::string("dx");
    }
    if (text == "sp" || text == "bp" || text == "si" || text == "di" || text == "ds" || text == "es" || text == "ss") {
        return text;
    }
    return std::nullopt;
}

bool operand_mentions_signature_register(const std::string& operand_text, const std::string& reg_name) {
    const std::string text = trim_ascii(operand_text);
    if (text.empty()) {
        return false;
    }
    if (const auto reg = normalize_signature_register_name(text); reg.has_value()) {
        return *reg == reg_name;
    }
    return text.find('[') != std::string::npos &&
           text.find(']') != std::string::npos &&
           text.find(reg_name) != std::string::npos;
}

std::string signature_return_kind_text(const FunctionSignatureSummary::ReturnKind kind) {
    switch (kind) {
    case FunctionSignatureSummary::ReturnKind::Near:
        return "near";
    case FunctionSignatureSummary::ReturnKind::Far:
        return "far";
    case FunctionSignatureSummary::ReturnKind::Mixed:
        return "mixed";
    case FunctionSignatureSummary::ReturnKind::None:
    default:
        return "none";
    }
}

void emit_direct_typed_helper_call(std::ostringstream& oss, const DirectTypedHelperCallSpec& spec) {
    std::ostringstream call_expr;
    call_expr << spec.wrapper_name << "(state";
    for (const std::string& input : spec.input_registers) {
        call_expr << ", state->" << input;
    }
    call_expr << ')';

    if (spec.output_registers.empty()) {
        oss << "    " << call_expr.str() << ";\n";
        return;
    }
    if (spec.output_registers.size() == 1u) {
        oss << "    state->" << spec.output_registers.front() << " = "
            << call_expr.str() << ";\n";
        return;
    }

    oss << "    {\n";
    oss << "        const auto generated_helper_result = " << call_expr.str() << ";\n";
    for (const std::string& output : spec.output_registers) {
        oss << "        state->" << output << " = generated_helper_result." << output << ";\n";
    }
    oss << "    }\n";
}

void observe_signature_return_kind(FunctionSignatureSummary& summary, const FunctionSignatureSummary::ReturnKind kind) {
    if (kind == FunctionSignatureSummary::ReturnKind::None) {
        return;
    }
    if (summary.return_kind == FunctionSignatureSummary::ReturnKind::None) {
        summary.return_kind = kind;
        return;
    }
    if (summary.return_kind != kind) {
        summary.return_kind = FunctionSignatureSummary::ReturnKind::Mixed;
    }
}

void append_memory_operand_dependency_registers(const std::string& operand_text,
                                                std::set<std::string>& reads) {
    const std::string text = trim_ascii(operand_text);
    const std::size_t left = text.find('[');
    const std::size_t right = text.find(']');
    if (left == std::string::npos || right == std::string::npos || right <= left + 1u) {
        return;
    }

    if (text.find("bx") != std::string::npos) {
        reads.insert("bx");
    }
    if (text.find("bp") != std::string::npos) {
        reads.insert("bp");
    }
    if (text.find("si") != std::string::npos) {
        reads.insert("si");
    }
    if (text.find("di") != std::string::npos) {
        reads.insert("di");
    }

    if (text.starts_with("ds:[")) {
        reads.insert("ds");
    } else if (text.starts_with("es:[")) {
        reads.insert("es");
    } else if (text.starts_with("ss:[")) {
        reads.insert("ss");
    } else if (!text.starts_with("cs:[")) {
        if (text.find("bp") != std::string::npos) {
            reads.insert("ss");
        } else {
            reads.insert("ds");
        }
    }
}

std::optional<int> parse_bp_stack_offset(const std::string& operand_text) {
    const std::string text = trim_ascii(operand_text);
    const std::size_t left = text.find('[');
    const std::size_t right = text.find(']');
    if (left == std::string::npos || right == std::string::npos || right <= left + 1u) {
        return std::nullopt;
    }

    const std::string inner = text.substr(left + 1u, right - left - 1u);
    if (inner.find("bp") == std::string::npos) {
        return std::nullopt;
    }

    int displacement = 0;
    int sign = 1;
    bool saw_bp = false;
    for (std::size_t i = 0u; i < inner.size();) {
        const char ch = inner[i];
        if (ch == ' ' || ch == '\t') {
            ++i;
            continue;
        }
        if (ch == '+') {
            sign = 1;
            ++i;
            continue;
        }
        if (ch == '-') {
            sign = -1;
            ++i;
            continue;
        }
        if (i + 1u < inner.size() && inner[i] == 'b' && inner[i + 1u] == 'p') {
            saw_bp = true;
            i += 2u;
            continue;
        }
        if (i + 1u < inner.size() && inner[i] == '0' && inner[i + 1u] == 'x') {
            std::size_t end = i + 2u;
            while (end < inner.size() && std::isxdigit(static_cast<unsigned char>(inner[end])) != 0) {
                ++end;
            }
            const std::uint16_t value = parse_hex16_text(std::string_view(inner).substr(i + 2u, end - (i + 2u)));
            displacement += sign * static_cast<int>(value);
            sign = 1;
            i = end;
            continue;
        }
        ++i;
    }

    if (!saw_bp) {
        return std::nullopt;
    }
    return displacement;
}

void append_operand_signature_access(const std::string& operand_text,
                                     const bool operand_read,
                                     const bool operand_write,
                                     std::set<std::string>& reads,
                                     std::set<std::string>& writes,
                                     bool& reads_memory,
                                     bool& writes_memory,
                                     std::set<int>& stack_reads,
                                     std::set<int>& stack_writes) {
    const std::string text = trim_ascii(operand_text);
    if (text.empty()) {
        return;
    }

    if (const auto reg = normalize_signature_register_name(text); reg.has_value()) {
        if (operand_read) {
            reads.insert(*reg);
        }
        if (operand_write) {
            writes.insert(*reg);
        }
        return;
    }

    if (text.find('[') != std::string::npos && text.find(']') != std::string::npos) {
        append_memory_operand_dependency_registers(text, reads);
        if (operand_read) {
            reads_memory = true;
            if (const auto stack_offset = parse_bp_stack_offset(text); stack_offset.has_value()) {
                stack_reads.insert(*stack_offset);
            }
        }
        if (operand_write) {
            writes_memory = true;
            if (const auto stack_offset = parse_bp_stack_offset(text); stack_offset.has_value()) {
                stack_writes.insert(*stack_offset);
            }
        }
    }
}

void collect_instruction_signature_effects(const DecodedInstruction& instruction,
                                           std::set<std::string>& reads,
                                           std::set<std::string>& writes,
                                           bool& reads_memory,
                                           bool& writes_memory,
                                           bool& non_frame_memory,
                                           bool& return_frame_memory,
                                           bool& reads_flags,
                                           bool& writes_flags,
                                           bool& non_frame_stack_pointer,
                                           bool& return_frame_stack_pointer,
                                           std::set<int>& stack_reads,
                                           std::set<int>& stack_writes) {
    const std::string mnemonic = instruction_mnemonic_text(instruction);
    const std::vector<std::string> operands = instruction_operand_texts(instruction);
    const auto access_operand = [&](const std::size_t index, const bool read, const bool write) {
        if (index >= operands.size()) {
            return;
        }
        append_operand_signature_access(
            operands[index], read, write, reads, writes, reads_memory, writes_memory, stack_reads, stack_writes);
    };
    const auto mark_non_frame_memory_if_any_operand = [&]() {
        for (const std::string& operand : operands) {
            if (operand.find('[') != std::string::npos && operand.find(']') != std::string::npos) {
                non_frame_memory = true;
                break;
            }
        }
    };

    if (mnemonic == "mov" || mnemonic == "lea" || mnemonic == "pop") {
        access_operand(0u, false, true);
        access_operand(1u, true, false);
        mark_non_frame_memory_if_any_operand();
        if (mnemonic == "pop") {
            non_frame_stack_pointer = true;
            non_frame_memory = true;
        } else {
            for (const std::string& operand : operands) {
                if (operand_mentions_signature_register(operand, "sp")) {
                    non_frame_stack_pointer = true;
                    break;
                }
            }
        }
        return;
    }
    if (mnemonic == "les") {
        access_operand(0u, false, true);
        writes.insert("es");
        access_operand(1u, true, false);
        non_frame_memory = true;
        return;
    }
    if (mnemonic == "lds") {
        access_operand(0u, false, true);
        writes.insert("ds");
        access_operand(1u, true, false);
        non_frame_memory = true;
        return;
    }
    if (mnemonic == "xchg") {
        access_operand(0u, true, true);
        access_operand(1u, true, true);
        for (const std::string& operand : operands) {
            if (operand_mentions_signature_register(operand, "sp")) {
                non_frame_stack_pointer = true;
                break;
            }
        }
        return;
    }
    if (mnemonic == "cmp" || mnemonic == "test") {
        access_operand(0u, true, false);
        access_operand(1u, true, false);
        mark_non_frame_memory_if_any_operand();
        for (const std::string& operand : operands) {
            if (operand_mentions_signature_register(operand, "sp")) {
                non_frame_stack_pointer = true;
                break;
            }
        }
        writes_flags = true;
        return;
    }
    if (mnemonic == "add" || mnemonic == "adc" || mnemonic == "sub" || mnemonic == "sbb" ||
        mnemonic == "and" || mnemonic == "or" || mnemonic == "xor" ||
        mnemonic == "inc" || mnemonic == "dec" || mnemonic == "neg" || mnemonic == "not" ||
        mnemonic == "rol" || mnemonic == "ror" || mnemonic == "rcl" || mnemonic == "rcr" ||
        mnemonic == "shl" || mnemonic == "shr" || mnemonic == "sar") {
        access_operand(0u, true, true);
        access_operand(1u, true, false);
        mark_non_frame_memory_if_any_operand();
        if (mnemonic == "adc" || mnemonic == "sbb" || mnemonic == "rcl" || mnemonic == "rcr") {
            reads_flags = true;
        }
        for (const std::string& operand : operands) {
            if (operand_mentions_signature_register(operand, "sp")) {
                non_frame_stack_pointer = true;
                break;
            }
        }
        writes_flags = true;
        return;
    }
    if (mnemonic == "push") {
        access_operand(0u, true, false);
        reads.insert("sp");
        writes.insert("sp");
        non_frame_stack_pointer = true;
        return;
    }
    if (mnemonic == "pop") {
        access_operand(0u, false, true);
        reads.insert("sp");
        writes.insert("sp");
        reads_memory = true;
        non_frame_stack_pointer = true;
        non_frame_memory = true;
        return;
    }
    if (mnemonic == "call" || mnemonic == "jmp") {
        access_operand(0u, true, false);
        mark_non_frame_memory_if_any_operand();
        if (mnemonic == "call") {
            reads.insert("sp");
            writes.insert("sp");
            non_frame_stack_pointer = true;
        }
        return;
    }
    if (mnemonic == "imul") {
        if (operands.size() >= 2u) {
            access_operand(0u, true, true);
            access_operand(1u, true, false);
        } else {
            access_operand(0u, true, false);
            writes.insert("ax");
            writes.insert("dx");
        }
        mark_non_frame_memory_if_any_operand();
        writes_flags = true;
        return;
    }
    if (mnemonic == "mul" || mnemonic == "div" || mnemonic == "idiv") {
        access_operand(0u, true, false);
        mark_non_frame_memory_if_any_operand();
        writes.insert("ax");
        writes.insert("dx");
        writes_flags = true;
        return;
    }
    if (mnemonic == "cbw") {
        reads.insert("ax");
        writes.insert("ax");
        return;
    }
    if (mnemonic == "cwd") {
        reads.insert("ax");
        writes.insert("dx");
        return;
    }
    if (mnemonic == "lodsb" || mnemonic == "lodsw") {
        reads.insert("si");
        reads.insert("ds");
        writes.insert("si");
        writes.insert("ax");
        reads_memory = true;
        non_frame_memory = true;
        return;
    }
    if (mnemonic == "stosb" || mnemonic == "stosw") {
        reads.insert("di");
        reads.insert("es");
        reads.insert("ax");
        writes.insert("di");
        writes_memory = true;
        non_frame_memory = true;
        return;
    }
    if (mnemonic == "movsb" || mnemonic == "movsw" || mnemonic == "cmpsb" || mnemonic == "cmpsw") {
        reads.insert("si");
        reads.insert("di");
        reads.insert("ds");
        reads.insert("es");
        writes.insert("si");
        writes.insert("di");
        reads_memory = true;
        non_frame_memory = true;
        if (mnemonic == "cmpsb" || mnemonic == "cmpsw") {
            writes_flags = true;
        } else {
            writes_memory = true;
        }
        return;
    }
    if (mnemonic == "scasb" || mnemonic == "scasw") {
        reads.insert("di");
        reads.insert("es");
        reads.insert("ax");
        writes.insert("di");
        reads_memory = true;
        non_frame_memory = true;
        writes_flags = true;
        return;
    }
    if (mnemonic == "loop" || mnemonic == "loopz" || mnemonic == "loopnz" || mnemonic == "jcxz") {
        reads.insert("cx");
        if (mnemonic != "jcxz") {
            writes.insert("cx");
        }
        if (mnemonic == "loopz" || mnemonic == "loopnz") {
            reads_flags = true;
        }
        return;
    }

    if (mnemonic.size() >= 2u && mnemonic[0] == 'j' && mnemonic != "jmp" && mnemonic != "jcxz") {
        reads_flags = true;
        return;
    }

    if (mnemonic == "pushf" || mnemonic == "lahf") {
        reads_flags = true;
        if (mnemonic == "pushf") {
            reads.insert("sp");
            writes.insert("sp");
            non_frame_stack_pointer = true;
        }
        return;
    }
    if (mnemonic == "popf" || mnemonic == "sahf" || mnemonic == "clc" || mnemonic == "stc" || mnemonic == "cmc") {
        writes_flags = true;
        if (mnemonic == "popf") {
            reads.insert("sp");
            writes.insert("sp");
            reads_memory = true;
            non_frame_stack_pointer = true;
            non_frame_memory = true;
        }
        return;
    }
    if (mnemonic == "retn" || mnemonic == "ret" || mnemonic == "retf" || mnemonic == "iret") {
        reads.insert("sp");
        writes.insert("sp");
        reads_memory = true;
        return_frame_memory = true;
        return_frame_stack_pointer = true;
        if (mnemonic == "retf" || mnemonic == "iret") {
            writes.insert("cs");
        }
        if (mnemonic == "iret") {
            writes_flags = true;
        }
        return;
    }
    if (mnemonic == "enter" || mnemonic == "leave" || mnemonic == "pusha" || mnemonic == "popa") {
        reads.insert("sp");
        writes.insert("sp");
        non_frame_stack_pointer = true;
        return;
    }

    for (std::size_t i = 0u; i < operands.size(); ++i) {
        access_operand(i, true, false);
    }
    mark_non_frame_memory_if_any_operand();
    for (const std::string& operand : operands) {
        if (operand_mentions_signature_register(operand, "sp")) {
            non_frame_stack_pointer = true;
            break;
        }
    }
}

std::string join_string_set(const std::set<std::string>& values) {
    std::ostringstream oss;
    bool first = true;
    for (const std::string& value : values) {
        if (!first) {
            oss << '|';
        }
        first = false;
        oss << value;
    }
    return oss.str();
}

std::string join_string_vector(const std::vector<std::string>& values) {
    std::ostringstream oss;
    bool first = true;
    for (const std::string& value : values) {
        if (!first) {
            oss << '|';
        }
        first = false;
        oss << value;
    }
    return oss.str();
}

std::string join_int_set(const std::set<int>& values) {
    std::ostringstream oss;
    bool first = true;
    for (const int value : values) {
        if (!first) {
            oss << '|';
        }
        first = false;
        if (value < 0) {
            oss << "-0x" << hex4(static_cast<std::uint16_t>(-value));
        } else {
            oss << "0x" << hex4(static_cast<std::uint16_t>(value));
        }
    }
    return oss.str();
}

bool signature_has_only_return_frame_stack_pointer(const FunctionSignatureSummary& summary) {
    return summary.uses_return_frame_stack_pointer &&
           !summary.uses_non_frame_stack_pointer &&
           summary.stack_read_offsets.empty() &&
           summary.stack_write_offsets.empty();
}

bool signature_has_only_return_frame_memory(const FunctionSignatureSummary& summary) {
    return summary.uses_return_frame_memory &&
           !summary.uses_non_frame_memory;
}

std::set<std::string> effective_signature_inputs(const FunctionSignatureSummary& summary) {
    std::set<std::string> inputs = summary.candidate_inputs;
    if (signature_has_only_return_frame_stack_pointer(summary)) {
        inputs.erase("sp");
    }
    return inputs;
}

std::set<std::string> effective_signature_written_registers(const FunctionSignatureSummary& summary) {
    std::set<std::string> outputs = summary.written_registers;
    if (signature_has_only_return_frame_stack_pointer(summary)) {
        outputs.erase("sp");
    }
    return outputs;
}

std::string build_signature_prototype_hint(const FunctionSignatureSummary& summary) {
    std::vector<std::string> parameters;
    for (const std::string& input : effective_signature_inputs(summary)) {
        parameters.push_back("uint16_t " + input);
    }
    for (const int stack_offset : summary.stack_read_offsets) {
        std::ostringstream name;
        name << "uint16_t stack_";
        if (stack_offset < 0) {
            name << "neg_" << hex4(static_cast<std::uint16_t>(-stack_offset));
        } else {
            name << hex4(static_cast<std::uint16_t>(stack_offset));
        }
        parameters.push_back(name.str());
    }

    std::ostringstream oss;
    const std::set<std::string> effective_outputs = effective_signature_written_registers(summary);
    const bool simple_ax_return =
        !summary.writes_memory &&
        effective_outputs == std::set<std::string>{"ax"};
    const bool simple_ax_dx_return =
        !summary.writes_memory &&
        effective_outputs == std::set<std::string>{"ax", "dx"};

    if (simple_ax_return) {
        oss << "uint16_t ";
    } else if (simple_ax_dx_return) {
        oss << "GeneratedFarPtr16 ";
    } else {
        oss << "void ";
    }
    oss << summary.name << '(';
    if (parameters.empty()) {
        oss << "void";
    } else {
        for (std::size_t i = 0u; i < parameters.size(); ++i) {
            if (i != 0u) {
                oss << ", ";
            }
            oss << parameters[i];
        }
    }
    oss << ')';
    if (!simple_ax_return && !simple_ax_dx_return) {
        oss << " /* out: " << (effective_outputs.empty() ? "none" : join_string_set(effective_outputs));
        if (summary.writes_flags) {
            oss << (effective_outputs.empty() ? "" : "|") << "flags";
        }
        oss << " */";
    }
    return oss.str();
}

std::vector<FunctionSignatureSummary> build_function_signature_summaries(const CfgSnapshot& snapshot) {
    const BlockMap block_map = build_block_map(snapshot);
    const std::set<std::uint32_t> public_root_keys = build_public_root_keys(snapshot, block_map);
    const std::set<std::string> register_universe = {"ax", "bx", "cx", "dx", "sp", "bp", "si", "di", "ds", "es", "ss", "flags"};

    std::map<std::uint32_t, std::size_t> incoming_call_counts;
    for (const CfgEdge& edge : snapshot.edges) {
        if (edge.kind == EdgeKind::Call) {
            ++incoming_call_counts[location_key(edge.to)];
        }
    }
    for (const IndirectSiteRecord& site : snapshot.indirect_sites) {
        if (site.kind != EdgeKind::Call) {
            continue;
        }
        for (const CodeLocation target : site.resolved_targets) {
            ++incoming_call_counts[location_key(target)];
        }
    }

    std::vector<FunctionSignatureSummary> summaries;
    for (const FunctionRecord& function : snapshot.functions) {
        const std::uint32_t entry_key = location_key(function.entry);
        if (!public_root_keys.contains(entry_key) ||
            !function.entry_block_present ||
            function.reachable_blocks.empty()) {
            continue;
        }

        FunctionSignatureSummary summary;
        summary.entry = function.entry;
        summary.name = function_name(function.entry);
        summary.block_count = function.reachable_blocks.size();
        summary.external_entry_count = function.external_entry_blocks.size();
        summary.shared_block_count = function.shared_blocks.size();
        summary.incoming_call_sites = incoming_call_counts[entry_key];

        std::set<std::uint32_t> function_block_keys;
        for (const CodeLocation location : function.reachable_blocks) {
            function_block_keys.insert(location_key(location));
        }

        std::map<std::uint32_t, std::set<std::string>> local_use_before_def_by_block;
        std::map<std::uint32_t, std::set<std::string>> local_def_by_block;
        std::map<std::uint32_t, std::set<std::uint32_t>> predecessors;
        for (const CfgEdge& edge : snapshot.edges) {
            if (edge.kind == EdgeKind::Call) {
                continue;
            }
            const std::uint32_t from_key = location_key(edge.from);
            const std::uint32_t to_key = location_key(edge.to);
            if (function_block_keys.contains(from_key) && function_block_keys.contains(to_key)) {
                predecessors[to_key].insert(from_key);
            }
        }

        for (const CodeLocation block_location : function.reachable_blocks) {
            const std::uint32_t block_key = location_key(block_location);
            const auto block_it = block_map.find(block_key);
            if (block_it == block_map.end()) {
                continue;
            }
            const BlockRecord& block = *block_it->second;
            std::set<std::string> local_defs;
            std::set<std::string> local_uses;
            for (const DecodedInstruction& instruction : block.preview.instructions) {
                ++summary.instruction_count;

                std::set<std::string> reads;
                std::set<std::string> writes;
                std::set<int> stack_reads;
                std::set<int> stack_writes;
                bool reads_memory = false;
                bool writes_memory = false;
                bool non_frame_memory = false;
                bool return_frame_memory = false;
                bool reads_flags = false;
                bool writes_flags = false;
                bool non_frame_stack_pointer = false;
                bool return_frame_stack_pointer = false;
                collect_instruction_signature_effects(
                    instruction, reads, writes, reads_memory, writes_memory, non_frame_memory, return_frame_memory,
                    reads_flags, writes_flags,
                    non_frame_stack_pointer, return_frame_stack_pointer, stack_reads, stack_writes);
                if (reads_flags) {
                    reads.insert("flags");
                }

                for (const std::string& reg : reads) {
                    if (!local_defs.contains(reg)) {
                        local_uses.insert(reg);
                    }
                }
                local_defs.insert(writes.begin(), writes.end());
                if (writes_flags) {
                    local_defs.insert("flags");
                }

                summary.written_registers.insert(writes.begin(), writes.end());
                summary.stack_read_offsets.insert(stack_reads.begin(), stack_reads.end());
                summary.stack_write_offsets.insert(stack_writes.begin(), stack_writes.end());
                summary.reads_memory = summary.reads_memory || reads_memory;
                summary.writes_memory = summary.writes_memory || writes_memory;
                summary.uses_non_frame_memory = summary.uses_non_frame_memory || non_frame_memory || writes_memory;
                summary.uses_return_frame_memory = summary.uses_return_frame_memory || return_frame_memory;
                summary.reads_flags = summary.reads_flags || reads_flags;
                summary.writes_flags = summary.writes_flags || writes_flags;
                summary.touches_stack_pointer = summary.touches_stack_pointer ||
                    reads.contains("sp") || writes.contains("sp");
                summary.uses_non_frame_stack_pointer = summary.uses_non_frame_stack_pointer || non_frame_stack_pointer;
                summary.uses_return_frame_stack_pointer =
                    summary.uses_return_frame_stack_pointer || return_frame_stack_pointer;

                if (instruction.flow == FlowKind::Call) {
                    ++summary.outgoing_call_sites;
                } else if (instruction.flow == FlowKind::Return) {
                    const std::uint8_t opcode = instruction_opcode(instruction);
                    if (opcode == 0xC2u || opcode == 0xC3u) {
                        observe_signature_return_kind(summary, FunctionSignatureSummary::ReturnKind::Near);
                    } else if (opcode == 0xCAu || opcode == 0xCBu || opcode == 0xCFu) {
                        observe_signature_return_kind(summary, FunctionSignatureSummary::ReturnKind::Far);
                    } else {
                        observe_signature_return_kind(summary, FunctionSignatureSummary::ReturnKind::Mixed);
                    }
                }
            }

            local_use_before_def_by_block.emplace(block_key, std::move(local_uses));
            local_def_by_block.emplace(block_key, std::move(local_defs));
        }

        for (const IndirectSiteRecord& site : snapshot.indirect_sites) {
            const std::uint32_t site_key = location_key(site.from);
            if (!function_block_keys.contains(site_key)) {
                continue;
            }
            if (site.kind == EdgeKind::Call) {
                ++summary.indirect_call_sites;
            } else {
                ++summary.indirect_branch_sites;
            }
        }

        std::map<std::uint32_t, std::set<std::string>> in_defs;
        std::map<std::uint32_t, std::set<std::string>> out_defs;
        bool changed = true;
        while (changed) {
            changed = false;
            for (const CodeLocation block_location : function.reachable_blocks) {
                const std::uint32_t block_key = location_key(block_location);
                std::set<std::string> new_in;
                if (block_key != entry_key) {
                    bool first_pred = true;
                    for (const std::uint32_t pred_key : predecessors[block_key]) {
                        if (first_pred) {
                            new_in = out_defs[pred_key];
                            first_pred = false;
                            continue;
                        }
                        std::set<std::string> intersection;
                        for (const std::string& value : new_in) {
                            if (out_defs[pred_key].contains(value)) {
                                intersection.insert(value);
                            }
                        }
                        new_in = std::move(intersection);
                    }
                }

                std::set<std::string> new_out = new_in;
                new_out.insert(local_def_by_block[block_key].begin(), local_def_by_block[block_key].end());
                if (in_defs[block_key] != new_in || out_defs[block_key] != new_out) {
                    in_defs[block_key] = std::move(new_in);
                    out_defs[block_key] = std::move(new_out);
                    changed = true;
                }
            }
        }

        for (const CodeLocation block_location : function.reachable_blocks) {
            const std::uint32_t block_key = location_key(block_location);
            for (const std::string& reg : local_use_before_def_by_block[block_key]) {
                if (!in_defs[block_key].contains(reg)) {
                    summary.candidate_inputs.insert(reg);
                }
            }
        }

        for (const std::string& reg : register_universe) {
            if (reg == "flags") {
                continue;
            }
            if (!summary.written_registers.contains(reg)) {
                summary.preserved_registers.insert(reg);
            }
        }

        if (summary.incoming_call_sites > 0u) {
            summary.helper_score += 3;
        }
        if (summary.outgoing_call_sites == 0u) {
            summary.helper_score += 4;
        } else if (summary.outgoing_call_sites == 1u) {
            summary.helper_score += 1;
        }
        if (summary.indirect_call_sites == 0u) {
            summary.helper_score += 2;
        }
        if (summary.indirect_branch_sites == 0u) {
            summary.helper_score += 2;
        }
        if (summary.block_count <= 3u) {
            summary.helper_score += 4;
        } else if (summary.block_count <= 6u) {
            summary.helper_score += 2;
        } else if (summary.block_count <= 10u) {
            summary.helper_score += 1;
        }
        if (summary.instruction_count <= 16u) {
            summary.helper_score += 4;
        } else if (summary.instruction_count <= 32u) {
            summary.helper_score += 2;
        } else if (summary.instruction_count <= 64u) {
            summary.helper_score += 1;
        }
        if (summary.external_entry_count == 0u) {
            summary.helper_score += 3;
        } else if (summary.external_entry_count == 1u) {
            summary.helper_score += 1;
        }
        if (summary.shared_block_count == 0u) {
            summary.helper_score += 2;
        } else if (summary.shared_block_count <= 2u) {
            summary.helper_score += 1;
        }
        if (summary.stack_write_offsets.empty()) {
            summary.helper_score += 1;
        }
        if (effective_signature_inputs(summary).size() <= 4u) {
            summary.helper_score += 1;
        }

        summary.helper_candidate =
            summary.helper_score >= 15 &&
            summary.outgoing_call_sites == 0u &&
            summary.indirect_call_sites == 0u &&
            summary.indirect_branch_sites == 0u &&
            summary.external_entry_count == 0u;
        summary.prototype_hint = build_signature_prototype_hint(summary);
        summaries.push_back(std::move(summary));
    }

    std::sort(summaries.begin(),
              summaries.end(),
              [](const FunctionSignatureSummary& left, const FunctionSignatureSummary& right) {
                  if (left.helper_candidate != right.helper_candidate) {
                      return left.helper_candidate > right.helper_candidate;
                  }
                  if (left.helper_score != right.helper_score) {
                      return left.helper_score > right.helper_score;
                  }
                  if (left.incoming_call_sites != right.incoming_call_sites) {
                      return left.incoming_call_sites > right.incoming_call_sites;
                  }
                  return location_key(left.entry) < location_key(right.entry);
              });
    return summaries;
}

std::string build_function_signature_report_text(const CfgSnapshot& snapshot) {
    const std::vector<FunctionSignatureSummary> summaries = build_function_signature_summaries(snapshot);
    std::ostringstream oss;
    oss << "Generated Function Signature Report\n";
    oss << "=================================\n\n";
    oss << "Analyzed functions: " << summaries.size() << '\n';
    oss << "Helper candidates: "
        << std::count_if(summaries.begin(), summaries.end(), [](const FunctionSignatureSummary& summary) {
               return summary.helper_candidate;
           })
        << "\n\n";

    oss << "Top Helper Candidates\n";
    oss << "---------------------\n";
    std::size_t printed = 0u;
    for (const FunctionSignatureSummary& summary : summaries) {
        if (!summary.helper_candidate) {
            continue;
        }
        ++printed;
        oss << printed << ". " << summary.name << " @" << hex4(summary.entry.cs) << ':' << hex4(summary.entry.ip)
            << " score=" << summary.helper_score
            << " calls_in=" << summary.incoming_call_sites
            << " blocks=" << summary.block_count
            << " instrs=" << summary.instruction_count << '\n';
        const std::set<std::string> effective_inputs = effective_signature_inputs(summary);
        const std::set<std::string> effective_outputs = effective_signature_written_registers(summary);
        oss << "   in=" << (effective_inputs.empty() ? "-" : join_string_set(effective_inputs))
            << " stack_in=" << (summary.stack_read_offsets.empty() ? "-" : join_int_set(summary.stack_read_offsets))
            << " out=" << (effective_outputs.empty() ? "-" : join_string_set(effective_outputs))
            << (summary.writes_flags ? "|flags" : "")
            << '\n';
        oss << "   preserved="
            << (summary.preserved_registers.empty() ? "-" : join_string_set(summary.preserved_registers))
            << " mem=" << (summary.reads_memory ? 'R' : '-')
            << (summary.writes_memory ? 'W' : '-')
            << " sp=" << (summary.touches_stack_pointer ? 'Y' : 'N')
            << (signature_has_only_return_frame_stack_pointer(summary) ? "(frame)" : "")
            << " ret=" << signature_return_kind_text(summary.return_kind) << '\n';
        oss << "   hint: " << summary.prototype_hint << '\n';
        if (printed >= 40u) {
            break;
        }
    }
    if (printed == 0u) {
        oss << "(none)\n";
    }

    oss << "\nLargest Non-Candidate Functions\n";
    oss << "-------------------------------\n";
    printed = 0u;
    for (const FunctionSignatureSummary& summary : summaries) {
        if (summary.helper_candidate) {
            continue;
        }
        ++printed;
        oss << printed << ". " << summary.name << " @" << hex4(summary.entry.cs) << ':' << hex4(summary.entry.ip)
            << " score=" << summary.helper_score
            << " calls_out=" << summary.outgoing_call_sites
            << " indirect=" << (summary.indirect_call_sites + summary.indirect_branch_sites)
            << " blocks=" << summary.block_count
            << " shared=" << summary.shared_block_count
            << " external_entries=" << summary.external_entry_count << '\n';
        if (printed >= 20u) {
            break;
        }
    }

    return oss.str();
}

std::string build_function_signatures_csv_text(const CfgSnapshot& snapshot) {
    const std::vector<FunctionSignatureSummary> summaries = build_function_signature_summaries(snapshot);
    std::ostringstream oss;
    oss << "name,entry_cs,entry_ip,helper_candidate,helper_score,callers,calls_out,indirect_calls,indirect_branches,blocks,instructions,external_entries,shared_blocks,reads_memory,writes_memory,reads_flags,writes_flags,touches_sp,frame_only_sp,return_kind,inputs,written,preserved,stack_reads,stack_writes,prototype_hint\n";
    for (const FunctionSignatureSummary& summary : summaries) {
        std::string prototype = summary.prototype_hint;
        std::replace(prototype.begin(), prototype.end(), ',', ';');
        oss << summary.name
            << ",0x" << hex4(summary.entry.cs)
            << ",0x" << hex4(summary.entry.ip)
            << ',' << (summary.helper_candidate ? 1 : 0)
            << ',' << summary.helper_score
            << ',' << summary.incoming_call_sites
            << ',' << summary.outgoing_call_sites
            << ',' << summary.indirect_call_sites
            << ',' << summary.indirect_branch_sites
            << ',' << summary.block_count
            << ',' << summary.instruction_count
            << ',' << summary.external_entry_count
            << ',' << summary.shared_block_count
            << ',' << (summary.reads_memory ? 1 : 0)
            << ',' << (summary.writes_memory ? 1 : 0)
            << ',' << (summary.reads_flags ? 1 : 0)
            << ',' << (summary.writes_flags ? 1 : 0)
            << ',' << (summary.touches_stack_pointer ? 1 : 0)
            << ',' << (signature_has_only_return_frame_stack_pointer(summary) ? 1 : 0)
            << ',' << signature_return_kind_text(summary.return_kind)
            << ',' << join_string_set(effective_signature_inputs(summary))
            << ',' << join_string_set(effective_signature_written_registers(summary))
            << ',' << join_string_set(summary.preserved_registers)
            << ',' << join_int_set(summary.stack_read_offsets)
            << ',' << join_int_set(summary.stack_write_offsets)
            << ',' << prototype
            << '\n';
    }
    return oss.str();
}

struct TypedHelperWrapperSpec {
    FunctionSignatureSummary summary;
    std::vector<std::string> input_registers;
    std::vector<std::string> output_registers;
};

std::vector<TypedHelperWrapperSpec> build_typed_helper_wrapper_specs(const CfgSnapshot& snapshot) {
    const std::vector<FunctionSignatureSummary> summaries = build_function_signature_summaries(snapshot);
    std::vector<TypedHelperWrapperSpec> specs;
    for (const FunctionSignatureSummary& summary : summaries) {
        if (!summary.helper_candidate ||
            !summary.stack_read_offsets.empty() ||
            !summary.stack_write_offsets.empty()) {
            continue;
        }

        TypedHelperWrapperSpec spec;
        spec.summary = summary;
        const std::set<std::string> effective_inputs = effective_signature_inputs(summary);
        const std::set<std::string> effective_outputs = effective_signature_written_registers(summary);
        spec.input_registers.assign(effective_inputs.begin(), effective_inputs.end());
        spec.output_registers.assign(effective_outputs.begin(), effective_outputs.end());
        if (summary.writes_flags) {
            spec.output_registers.push_back("flags");
        }
        specs.push_back(std::move(spec));
    }
    return specs;
}

std::string typed_helper_wrapper_name(const TypedHelperWrapperSpec& spec) {
    return "generated_typed_" + spec.summary.name;
}

std::string standalone_typed_helper_wrapper_name(const TypedHelperWrapperSpec& spec) {
    return "generated_standalone_" + spec.summary.name;
}

std::string typed_helper_result_struct_name(const TypedHelperWrapperSpec& spec) {
    return typed_helper_wrapper_name(spec) + "_result";
}

std::string typed_helper_return_type_name(const TypedHelperWrapperSpec& spec) {
    if (spec.output_registers.empty()) {
        return "void";
    }
    if (spec.output_registers.size() == 1u) {
        return "uint16_t";
    }
    return typed_helper_result_struct_name(spec);
}

std::vector<TypedHelperWrapperSpec> build_standalone_typed_helper_wrapper_specs(const CfgSnapshot& snapshot) {
    std::vector<TypedHelperWrapperSpec> specs;
    for (const TypedHelperWrapperSpec& spec : build_typed_helper_wrapper_specs(snapshot)) {
        const FunctionSignatureSummary& summary = spec.summary;
        if (summary.uses_non_frame_memory ||
            summary.writes_memory ||
            summary.outgoing_call_sites != 0u ||
            summary.indirect_call_sites != 0u ||
            summary.indirect_branch_sites != 0u ||
            summary.uses_non_frame_stack_pointer ||
            summary.return_kind == FunctionSignatureSummary::ReturnKind::Mixed ||
            summary.block_count > 6u ||
            summary.instruction_count > 16u) {
            continue;
        }
        specs.push_back(spec);
    }
    return specs;
}

bool typed_helper_spec_is_elidable_noop_call_target(const TypedHelperWrapperSpec& spec) {
    return spec.summary.return_kind == FunctionSignatureSummary::ReturnKind::Near &&
           spec.input_registers.empty() &&
           spec.output_registers.empty() &&
           !spec.summary.reads_flags &&
           !spec.summary.writes_flags;
}

bool typed_helper_spec_is_direct_standalone_call_target(const TypedHelperWrapperSpec& spec) {
    return spec.summary.return_kind == FunctionSignatureSummary::ReturnKind::Near &&
           !spec.output_registers.empty();
}

std::set<std::uint32_t> build_elidable_noop_call_target_keys(const CfgSnapshot& snapshot) {
    std::set<std::uint32_t> keys;
    for (const TypedHelperWrapperSpec& spec : build_standalone_typed_helper_wrapper_specs(snapshot)) {
        if (typed_helper_spec_is_elidable_noop_call_target(spec)) {
            keys.insert(location_key(spec.summary.entry));
        }
    }
    return keys;
}

std::map<std::uint32_t, DirectStandaloneHelperCallSpec> build_direct_standalone_call_target_specs(const CfgSnapshot& snapshot) {
    std::map<std::uint32_t, DirectStandaloneHelperCallSpec> specs_by_key;
    for (const TypedHelperWrapperSpec& spec : build_standalone_typed_helper_wrapper_specs(snapshot)) {
        if (typed_helper_spec_is_direct_standalone_call_target(spec)) {
            specs_by_key.emplace(location_key(spec.summary.entry), DirectStandaloneHelperCallSpec{
                standalone_typed_helper_wrapper_name(spec),
                spec.input_registers,
                spec.output_registers,
                spec.summary.reads_flags,
            });
        }
    }
    return specs_by_key;
}

std::map<std::uint32_t, DirectTypedHelperCallSpec> build_direct_typed_call_target_specs(const CfgSnapshot& snapshot) {
    std::map<std::uint32_t, DirectTypedHelperCallSpec> specs_by_key;
    for (const TypedHelperWrapperSpec& spec : build_typed_helper_wrapper_specs(snapshot)) {
        if (spec.summary.return_kind != FunctionSignatureSummary::ReturnKind::Near) {
            continue;
        }
        specs_by_key.emplace(location_key(spec.summary.entry), DirectTypedHelperCallSpec{
            typed_helper_wrapper_name(spec),
            spec.input_registers,
            spec.output_registers,
        });
    }
    return specs_by_key;
}

std::string build_typed_helper_callsite_candidate_report_text(const CfgSnapshot& snapshot) {
    const std::vector<TypedHelperWrapperSpec> specs = build_typed_helper_wrapper_specs(snapshot);
    const std::vector<TypedHelperWrapperSpec> standalone_specs = build_standalone_typed_helper_wrapper_specs(snapshot);
    std::map<std::uint32_t, std::vector<CodeLocation>> direct_callers_by_target;
    for (const CfgEdge& edge : snapshot.edges) {
        if (edge.kind != EdgeKind::Call) {
            continue;
        }
        direct_callers_by_target[location_key(edge.to)].push_back(edge.from);
    }

    std::ostringstream oss;
    oss << "Generated Typed Helper Callsite Candidate Report\n";
    oss << "===============================================\n\n";
    std::size_t printed = 0u;
    for (const TypedHelperWrapperSpec& spec : specs) {
        const auto it = direct_callers_by_target.find(location_key(spec.summary.entry));
        if (it == direct_callers_by_target.end() || it->second.empty()) {
            continue;
        }
        const bool is_standalone =
            std::any_of(standalone_specs.begin(), standalone_specs.end(), [&](const TypedHelperWrapperSpec& candidate) {
                return location_key(candidate.summary.entry) == location_key(spec.summary.entry);
            });
        ++printed;
        oss << printed << ". " << spec.summary.name
            << " @0x" << hex4(spec.summary.entry.cs) << ':' << hex4(spec.summary.entry.ip)
            << " direct_callers=" << it->second.size()
            << " standalone=" << (is_standalone ? "yes" : "no")
            << " flags_in=" << (spec.summary.reads_flags ? "yes" : "no")
            << '\n';
        oss << "   inputs: " << join_string_vector(spec.input_registers) << '\n';
        oss << "   outputs: " << (spec.output_registers.empty() ? "none" : join_string_vector(spec.output_registers)) << '\n';
        oss << "   callers:";
        for (const CodeLocation caller : it->second) {
            oss << ' ' << function_name(caller) << "@0x" << hex4(caller.cs) << ':' << hex4(caller.ip);
        }
        oss << "\n\n";
        if (printed >= 60u) {
            break;
        }
    }
    if (printed == 0u) {
        oss << "(none)\n";
    }
    return oss.str();
}

std::string build_typed_helper_callsite_candidates_csv_text(const CfgSnapshot& snapshot) {
    const std::vector<TypedHelperWrapperSpec> specs = build_typed_helper_wrapper_specs(snapshot);
    std::map<std::uint32_t, std::vector<CodeLocation>> direct_callers_by_target;
    for (const CfgEdge& edge : snapshot.edges) {
        if (edge.kind != EdgeKind::Call) {
            continue;
        }
        direct_callers_by_target[location_key(edge.to)].push_back(edge.from);
    }

    std::ostringstream oss;
    const std::vector<TypedHelperWrapperSpec> standalone_specs = build_standalone_typed_helper_wrapper_specs(snapshot);
    oss << "name,entry_cs,entry_ip,direct_callers,standalone,reads_memory,writes_memory,reads_flags,writes_flags,frame_only_sp,inputs,outputs,callers\n";
    for (const TypedHelperWrapperSpec& spec : specs) {
        const auto it = direct_callers_by_target.find(location_key(spec.summary.entry));
        if (it == direct_callers_by_target.end() || it->second.empty()) {
            continue;
        }
        const bool is_standalone =
            std::any_of(standalone_specs.begin(), standalone_specs.end(), [&](const TypedHelperWrapperSpec& candidate) {
                return location_key(candidate.summary.entry) == location_key(spec.summary.entry);
            });
        std::ostringstream callers;
        bool first = true;
        for (const CodeLocation caller : it->second) {
            if (!first) {
                callers << '|';
            }
            first = false;
            callers << function_name(caller) << "@0x" << hex4(caller.cs) << ':' << hex4(caller.ip);
        }
        oss << spec.summary.name
            << ",0x" << hex4(spec.summary.entry.cs)
            << ",0x" << hex4(spec.summary.entry.ip)
            << ',' << it->second.size()
            << ',' << (is_standalone ? 1 : 0)
            << ',' << (spec.summary.reads_memory ? 1 : 0)
            << ',' << (spec.summary.writes_memory ? 1 : 0)
            << ',' << (spec.summary.reads_flags ? 1 : 0)
            << ',' << (spec.summary.writes_flags ? 1 : 0)
            << ',' << (signature_has_only_return_frame_stack_pointer(spec.summary) ? 1 : 0)
            << ',' << join_string_vector(spec.input_registers)
            << ',' << join_string_vector(spec.output_registers)
            << ',' << callers.str()
            << '\n';
    }
    return oss.str();
}

std::string build_typed_helper_wrapper_report_text(const CfgSnapshot& snapshot) {
    const std::vector<TypedHelperWrapperSpec> specs = build_typed_helper_wrapper_specs(snapshot);
    std::ostringstream oss;
    oss << "Generated Typed Helper Wrapper Report\n";
    oss << "====================================\n\n";
    oss << "Wrapper candidates emitted: " << specs.size() << "\n\n";
    for (const TypedHelperWrapperSpec& spec : specs) {
        oss << spec.summary.name
            << " @0x" << hex4(spec.summary.entry.cs) << ':' << hex4(spec.summary.entry.ip) << "\n";
        oss << "  return: " << typed_helper_return_type_name(spec) << "\n";
        oss << "  inputs: " << join_string_vector(spec.input_registers) << "\n";
        oss << "  outputs: " << join_string_vector(spec.output_registers) << "\n";
        oss << "  mem: " << (spec.summary.reads_memory ? 'R' : '-')
            << (spec.summary.writes_memory ? 'W' : '-') << "\n";
        oss << "  hint: " << spec.summary.prototype_hint << "\n\n";
    }
    return oss.str();
}

std::string build_standalone_typed_helper_wrapper_report_text(const CfgSnapshot& snapshot) {
    const std::vector<TypedHelperWrapperSpec> specs = build_standalone_typed_helper_wrapper_specs(snapshot);
    std::ostringstream oss;
    oss << "Generated Standalone Typed Helper Wrapper Report\n";
    oss << "===============================================\n\n";
    oss << "Standalone wrapper candidates emitted: " << specs.size() << "\n\n";
    for (const TypedHelperWrapperSpec& spec : specs) {
        oss << spec.summary.name
            << " @0x" << hex4(spec.summary.entry.cs) << ':' << hex4(spec.summary.entry.ip) << "\n";
        oss << "  return: " << typed_helper_return_type_name(spec) << "\n";
        oss << "  inputs: " << join_string_vector(spec.input_registers) << "\n";
        oss << "  outputs: " << join_string_vector(spec.output_registers) << "\n";
        oss << "  blocks: " << spec.summary.block_count << " instrs: " << spec.summary.instruction_count << "\n";
        oss << "  hint: " << spec.summary.prototype_hint << "\n\n";
    }
    return oss.str();
}

std::string build_typed_helper_wrappers_csv_text(const CfgSnapshot& snapshot) {
    const std::vector<TypedHelperWrapperSpec> specs = build_typed_helper_wrapper_specs(snapshot);
    std::ostringstream oss;
    oss << "name,entry,return_type,inputs,outputs,reads_memory,writes_memory,frame_only_sp,prototype_hint\n";
    for (const TypedHelperWrapperSpec& spec : specs) {
        std::string prototype = spec.summary.prototype_hint;
        std::replace(prototype.begin(), prototype.end(), ',', ';');
        oss << spec.summary.name
            << ",0x" << hex4(spec.summary.entry.cs)
            << ":0x" << hex4(spec.summary.entry.ip)
            << ',' << typed_helper_return_type_name(spec)
            << ',' << join_string_vector(spec.input_registers)
            << ',' << join_string_vector(spec.output_registers)
            << ',' << (spec.summary.reads_memory ? 1 : 0)
            << ',' << (spec.summary.writes_memory ? 1 : 0)
            << ',' << (signature_has_only_return_frame_stack_pointer(spec.summary) ? 1 : 0)
            << ',' << prototype
            << '\n';
    }
    return oss.str();
}

std::string build_standalone_typed_helper_wrappers_csv_text(const CfgSnapshot& snapshot) {
    const std::vector<TypedHelperWrapperSpec> specs = build_standalone_typed_helper_wrapper_specs(snapshot);
    std::ostringstream oss;
    oss << "name,entry,return_type,inputs,outputs,blocks,instructions,frame_only_sp,prototype_hint\n";
    for (const TypedHelperWrapperSpec& spec : specs) {
        std::string prototype = spec.summary.prototype_hint;
        std::replace(prototype.begin(), prototype.end(), ',', ';');
        oss << spec.summary.name
            << ",0x" << hex4(spec.summary.entry.cs)
            << ":0x" << hex4(spec.summary.entry.ip)
            << ',' << typed_helper_return_type_name(spec)
            << ',' << join_string_vector(spec.input_registers)
            << ',' << join_string_vector(spec.output_registers)
            << ',' << spec.summary.block_count
            << ',' << spec.summary.instruction_count
            << ',' << (signature_has_only_return_frame_stack_pointer(spec.summary) ? 1 : 0)
            << ',' << prototype
            << '\n';
    }
    return oss.str();
}

std::size_t count_substring_occurrences(const std::string& text, const std::string& needle) {
    if (needle.empty()) {
        return 0u;
    }
    std::size_t count = 0u;
    std::size_t position = 0u;
    while ((position = text.find(needle, position)) != std::string::npos) {
        ++count;
        position += needle.size();
    }
    return count;
}

std::string build_typed_helper_lowering_report_text(const CfgSnapshot& snapshot,
                                                    const std::string& generated_game_cpp_text) {
    const std::vector<TypedHelperWrapperSpec> typed_specs = build_typed_helper_wrapper_specs(snapshot);
    const std::vector<TypedHelperWrapperSpec> standalone_specs = build_standalone_typed_helper_wrapper_specs(snapshot);
    std::set<std::uint32_t> standalone_keys;
    for (const TypedHelperWrapperSpec& spec : standalone_specs) {
        standalone_keys.insert(location_key(spec.summary.entry));
    }

    std::map<std::uint32_t, std::size_t> direct_callers_by_target;
    for (const CfgEdge& edge : snapshot.edges) {
        if (edge.kind != EdgeKind::Call) {
            continue;
        }
        ++direct_callers_by_target[location_key(edge.to)];
    }

    struct Row {
        const TypedHelperWrapperSpec* spec;
        bool standalone;
        std::size_t direct_callers;
        std::size_t typed_callsites;
        std::size_t standalone_callsites;
        std::size_t raw_state_calls;
        std::size_t raw_local_state_calls;
        std::size_t residual_raw_state_calls;
        std::size_t residual_raw_local_state_calls;
    };

    std::vector<Row> rows;
    rows.reserve(typed_specs.size());
    for (const TypedHelperWrapperSpec& spec : typed_specs) {
        const std::string raw_state_call = spec.summary.name + "(state);";
        const std::string raw_local_state_call = spec.summary.name + "(&state);";
        rows.push_back(Row{
            &spec,
            standalone_keys.contains(location_key(spec.summary.entry)),
            direct_callers_by_target[location_key(spec.summary.entry)],
            count_substring_occurrences(
                generated_game_cpp_text,
                "const auto generated_helper_result = " + typed_helper_wrapper_name(spec) + '('),
            count_substring_occurrences(
                generated_game_cpp_text,
                "const auto generated_helper_result = " + standalone_typed_helper_wrapper_name(spec) + '('),
            count_substring_occurrences(generated_game_cpp_text, raw_state_call),
            count_substring_occurrences(generated_game_cpp_text, raw_local_state_call),
            0u,
            0u,
        });
    }

    for (Row& row : rows) {
        row.residual_raw_state_calls = row.raw_state_calls > 0u ? (row.raw_state_calls - 1u) : 0u;
        const std::size_t expected_local_wrapper_calls = row.standalone ? 1u : 0u;
        row.residual_raw_local_state_calls =
            row.raw_local_state_calls > expected_local_wrapper_calls
                ? (row.raw_local_state_calls - expected_local_wrapper_calls)
                : 0u;
    }

    std::sort(rows.begin(), rows.end(), [](const Row& left, const Row& right) {
        const std::size_t left_lowered = left.typed_callsites + left.standalone_callsites;
        const std::size_t right_lowered = right.typed_callsites + right.standalone_callsites;
        if (left_lowered != right_lowered) {
            return left_lowered > right_lowered;
        }
        if (left.direct_callers != right.direct_callers) {
            return left.direct_callers > right.direct_callers;
        }
        return location_key(left.spec->summary.entry) < location_key(right.spec->summary.entry);
    });

    std::ostringstream oss;
    std::size_t total_typed_callsites = 0u;
    std::size_t total_standalone_callsites = 0u;
    std::size_t total_raw_state_calls = 0u;
    std::size_t total_raw_local_state_calls = 0u;
    std::size_t total_residual_raw_state_calls = 0u;
    std::size_t total_residual_raw_local_state_calls = 0u;
    for (const Row& row : rows) {
        total_typed_callsites += row.typed_callsites;
        total_standalone_callsites += row.standalone_callsites;
        total_raw_state_calls += row.raw_state_calls;
        total_raw_local_state_calls += row.raw_local_state_calls;
        total_residual_raw_state_calls += row.residual_raw_state_calls;
        total_residual_raw_local_state_calls += row.residual_raw_local_state_calls;
    }

    oss << "Generated Typed Helper Lowering Report\n";
    oss << "=====================================\n\n";
    oss << "Typed helper wrappers: " << typed_specs.size() << '\n';
    oss << "Standalone wrappers: " << standalone_specs.size() << '\n';
    oss << "Typed-wrapper callsites lowered: " << total_typed_callsites << '\n';
    oss << "Standalone-wrapper callsites lowered: " << total_standalone_callsites << '\n';
    oss << "Remaining raw helper calls with state: " << total_raw_state_calls << '\n';
    oss << "Remaining raw helper calls with local temp state: " << total_raw_local_state_calls << '\n';
    oss << "Residual raw helper calls outside wrappers (state): " << total_residual_raw_state_calls << '\n';
    oss << "Residual raw helper calls outside wrappers (local temp state): "
        << total_residual_raw_local_state_calls << "\n\n";

    std::size_t printed = 0u;
    for (const Row& row : rows) {
        if (row.direct_callers == 0u && row.typed_callsites == 0u && row.standalone_callsites == 0u) {
            continue;
        }
        ++printed;
        const TypedHelperWrapperSpec& spec = *row.spec;
        oss << printed << ". " << spec.summary.name
            << " @0x" << hex4(spec.summary.entry.cs) << ':' << hex4(spec.summary.entry.ip)
            << " direct_callers=" << row.direct_callers
            << " standalone=" << (row.standalone ? "yes" : "no") << '\n';
        oss << "   lowered typed callsites: " << row.typed_callsites << '\n';
        oss << "   lowered standalone callsites: " << row.standalone_callsites << '\n';
        oss << "   remaining raw calls (state): " << row.raw_state_calls << '\n';
        oss << "   remaining raw calls (temp state): " << row.raw_local_state_calls << '\n';
        oss << "   residual raw calls outside wrappers (state): " << row.residual_raw_state_calls << '\n';
        oss << "   residual raw calls outside wrappers (temp state): " << row.residual_raw_local_state_calls << '\n';
        oss << "   inputs: " << join_string_vector(spec.input_registers) << '\n';
        oss << "   outputs: " << (spec.output_registers.empty() ? "none" : join_string_vector(spec.output_registers)) << "\n\n";
        if (printed >= 80u) {
            break;
        }
    }
    if (printed == 0u) {
        oss << "(none)\n";
    }
    return oss.str();
}

std::string build_typed_helper_lowering_csv_text(const CfgSnapshot& snapshot,
                                                 const std::string& generated_game_cpp_text) {
    const std::vector<TypedHelperWrapperSpec> typed_specs = build_typed_helper_wrapper_specs(snapshot);
    const std::vector<TypedHelperWrapperSpec> standalone_specs = build_standalone_typed_helper_wrapper_specs(snapshot);
    std::set<std::uint32_t> standalone_keys;
    for (const TypedHelperWrapperSpec& spec : standalone_specs) {
        standalone_keys.insert(location_key(spec.summary.entry));
    }

    std::map<std::uint32_t, std::size_t> direct_callers_by_target;
    for (const CfgEdge& edge : snapshot.edges) {
        if (edge.kind != EdgeKind::Call) {
            continue;
        }
        ++direct_callers_by_target[location_key(edge.to)];
    }

    std::ostringstream oss;
    oss << "name,entry,direct_callers,standalone,typed_callsites,standalone_callsites,raw_state_calls,raw_local_state_calls,residual_raw_state_calls,residual_raw_local_state_calls,inputs,outputs\n";
    for (const TypedHelperWrapperSpec& spec : typed_specs) {
        const bool standalone = standalone_keys.contains(location_key(spec.summary.entry));
        const std::size_t raw_state_calls =
            count_substring_occurrences(generated_game_cpp_text, spec.summary.name + "(state);");
        const std::size_t raw_local_state_calls =
            count_substring_occurrences(generated_game_cpp_text, spec.summary.name + "(&state);");
        oss << spec.summary.name
            << ",0x" << hex4(spec.summary.entry.cs) << ":0x" << hex4(spec.summary.entry.ip)
            << ',' << direct_callers_by_target[location_key(spec.summary.entry)]
            << ',' << (standalone ? 1 : 0)
            << ',' << count_substring_occurrences(
                           generated_game_cpp_text,
                           "const auto generated_helper_result = " + typed_helper_wrapper_name(spec) + '(')
            << ',' << count_substring_occurrences(
                           generated_game_cpp_text,
                           "const auto generated_helper_result = " + standalone_typed_helper_wrapper_name(spec) + '(')
            << ',' << raw_state_calls
            << ',' << raw_local_state_calls
            << ',' << (raw_state_calls > 0u ? (raw_state_calls - 1u) : 0u)
            << ',' << (raw_local_state_calls > (standalone ? 1u : 0u)
                            ? (raw_local_state_calls - (standalone ? 1u : 0u))
                            : 0u)
            << ',' << join_string_vector(spec.input_registers)
            << ',' << join_string_vector(spec.output_registers)
            << '\n';
    }
    return oss.str();
}

void append_typed_helper_result_struct_declaration(std::ostringstream& oss, const TypedHelperWrapperSpec& spec) {
    if (spec.output_registers.size() <= 1u) {
        return;
    }
    oss << "struct " << typed_helper_result_struct_name(spec) << " {\n";
    for (const std::string& output : spec.output_registers) {
        oss << "    uint16_t " << output << ";\n";
    }
    oss << "};\n\n";
}

void append_typed_helper_wrapper_declaration(std::ostringstream& oss, const TypedHelperWrapperSpec& spec) {
    oss << typed_helper_return_type_name(spec) << ' ' << typed_helper_wrapper_name(spec)
        << "(GeneratedRuntimeState* state";
    for (const std::string& input : spec.input_registers) {
        oss << ", uint16_t " << input;
    }
    oss << ");\n";
}

void append_typed_helper_wrapper_definition(std::ostringstream& oss, const TypedHelperWrapperSpec& spec) {
    oss << typed_helper_return_type_name(spec) << ' ' << typed_helper_wrapper_name(spec)
        << "(GeneratedRuntimeState* state";
    for (const std::string& input : spec.input_registers) {
        oss << ", uint16_t " << input;
    }
    oss << ") {\n";
    oss << "    const uint16_t generated_saved_cs = state->cs;\n";
    oss << "    const uint16_t generated_saved_ip = state->ip;\n";
    for (const std::string& input : spec.input_registers) {
        oss << "    state->" << input << " = " << input << ";\n";
    }
    if (spec.summary.return_kind == FunctionSignatureSummary::ReturnKind::Far) {
        oss << "    generated_push_u16(state, 0xFEEEu);\n";
    }
    oss << "    generated_push_u16(state, 0xFEEFu);\n";
    oss << "    " << spec.summary.name << "(state);\n";
    oss << "    if (!state->terminated) {\n";
    oss << "        state->cs = generated_saved_cs;\n";
    oss << "        state->ip = generated_saved_ip;\n";
    oss << "    }\n";
    if (spec.output_registers.size() == 1u) {
        oss << "    return state->" << spec.output_registers.front() << ";\n";
    } else if (!spec.output_registers.empty()) {
        oss << "    return " << typed_helper_result_struct_name(spec) << '{';
        for (std::size_t index = 0; index < spec.output_registers.size(); ++index) {
            if (index != 0u) {
                oss << ", ";
            }
            oss << "state->" << spec.output_registers[index];
        }
        oss << "};\n";
    }
    oss << "}\n\n";
}

void append_standalone_typed_helper_wrapper_declaration(std::ostringstream& oss, const TypedHelperWrapperSpec& spec) {
    oss << typed_helper_return_type_name(spec) << ' ' << standalone_typed_helper_wrapper_name(spec) << '(';
    if (spec.input_registers.empty() && !spec.summary.reads_flags) {
        oss << "void";
    } else {
        bool first = true;
        for (const std::string& input : spec.input_registers) {
            if (!first) {
                oss << ", ";
            }
            first = false;
            oss << "uint16_t " << input;
        }
        if (spec.summary.reads_flags) {
            if (!first) {
                oss << ", ";
            }
            oss << "uint16_t flags";
        }
    }
    oss << ");\n";
}

void append_standalone_typed_helper_wrapper_definition(std::ostringstream& oss, const TypedHelperWrapperSpec& spec) {
    oss << typed_helper_return_type_name(spec) << ' ' << standalone_typed_helper_wrapper_name(spec) << '(';
    if (spec.input_registers.empty() && !spec.summary.reads_flags) {
        oss << "void";
    } else {
        bool first = true;
        for (const std::string& input : spec.input_registers) {
            if (!first) {
                oss << ", ";
            }
            first = false;
            oss << "uint16_t " << input;
        }
        if (spec.summary.reads_flags) {
            if (!first) {
                oss << ", ";
            }
            oss << "uint16_t flags";
        }
    }
    oss << ") {\n";
    oss << "    GeneratedRuntimeState* const generated_state = &g_generated_standalone_runtime_state;\n";
    oss << "    generated_reset_runtime_state(generated_state);\n";
    oss << "    generated_state->sp = 0xFFFEu;\n";
    for (const std::string& input : spec.input_registers) {
        oss << "    generated_state->" << input << " = " << input << ";\n";
    }
    if (spec.summary.reads_flags) {
        oss << "    generated_state->flags = flags;\n";
    }
    if (spec.summary.return_kind == FunctionSignatureSummary::ReturnKind::Far) {
        oss << "    generated_push_u16(generated_state, 0xFEEEu);\n";
    }
    oss << "    generated_push_u16(generated_state, 0xFEEFu);\n";
    oss << "    " << spec.summary.name << "(generated_state);\n";
    if (spec.output_registers.size() == 1u) {
        oss << "    return generated_state->" << spec.output_registers.front() << ";\n";
    } else if (!spec.output_registers.empty()) {
        oss << "    return " << typed_helper_result_struct_name(spec) << '{';
        for (std::size_t index = 0u; index < spec.output_registers.size(); ++index) {
            if (index != 0u) {
                oss << ", ";
            }
            oss << "generated_state->" << spec.output_registers[index];
        }
        oss << "};\n";
    }
    oss << "}\n\n";
}

std::string build_generated_game_header_text(const CfgSnapshot& snapshot) {
    std::ostringstream oss;
    oss << "#pragma once\n\n";
    oss << "#include \"generated_runtime.h\"\n\n";
    oss << "void generated_entry(GeneratedRuntimeState* state);\n";
    oss << "unsigned generated_dispatch_root(GeneratedRuntimeState* state, uint16_t cs, uint16_t ip);\n";
    const std::vector<TypedHelperWrapperSpec> specs = build_typed_helper_wrapper_specs(snapshot);
    const std::vector<TypedHelperWrapperSpec> standalone_specs = build_standalone_typed_helper_wrapper_specs(snapshot);
    for (const TypedHelperWrapperSpec& spec : specs) {
        append_typed_helper_result_struct_declaration(oss, spec);
    }
    for (const TypedHelperWrapperSpec& spec : specs) {
        append_typed_helper_wrapper_declaration(oss, spec);
    }
    for (const TypedHelperWrapperSpec& spec : standalone_specs) {
        append_standalone_typed_helper_wrapper_declaration(oss, spec);
    }
    return oss.str();
}

std::string shared_body_name(const CodeLocation location) {
    return function_name(location) + "__shared_body";
}

bool should_emit_actual_function(const std::set<std::uint32_t>& public_root_keys, const FunctionRecord& function) {
    if (!public_root_keys.contains(location_key(function.entry))) {
        return false;
    }
    return function.entry_block_present && !function.reachable_blocks.empty();
}

bool should_emit_noinline_body(const CodeLocation location) {
    switch (location_key(location)) {
    case ((std::uint32_t)0x2F26u << 16u) | 0x03ACu:
        return true;
    default:
        return false;
    }
}

bool block_tail_stays_within_emitted_body(const BlockRecord& block,
                                          const std::optional<CodeLocation>& split_successor,
                                          const std::set<std::uint32_t>& function_block_keys) {
    if (split_successor.has_value()) {
        return function_block_keys.contains(location_key(*split_successor));
    }

    if (block.preview.terminated || block.preview.instructions.empty()) {
        return false;
    }

    const DecodedInstruction& terminal = block.preview.instructions.back();
    if (!preview_has_implicit_fallthrough(block.preview) || !terminal.branch_fallthrough_ip.has_value()) {
        return false;
    }

    const CodeLocation fallthrough_target{terminal.cs, *terminal.branch_fallthrough_ip};
    return function_block_keys.contains(location_key(fallthrough_target));
}

bool block_start_is_targeted_within_function(
    const std::vector<CodeLocation>& function_blocks,
    const BlockMap& block_map,
    const std::set<std::uint32_t>& function_block_keys,
    const std::vector<CodeLocation>& body_entries,
    const CodeLocation target_block,
    const std::map<std::uint32_t, std::vector<CodeLocation>>& resolved_indirect_branches) {
    const std::uint32_t target_key = location_key(target_block);
    if (body_entries.size() > 1u) {
        for (const CodeLocation entry : body_entries) {
            if (location_key(entry) == target_key) {
                return true;
            }
        }
    }

    for (const CodeLocation block_location : function_blocks) {
        const auto block_it = block_map.find(location_key(block_location));
        if (block_it == block_map.end()) {
            continue;
        }
        const BlockRecord& block = *block_it->second;
        for (const DecodedInstruction& instruction : block.preview.instructions) {
            const std::uint32_t instruction_key =
                location_key(CodeLocation{instruction.cs, instruction.ip});
            if (instruction.indirect.has_value() &&
                instruction.flow == FlowKind::UnconditionalBranch) {
                return true;
            }
            if (instruction.branch_target_ip.has_value()) {
                const CodeLocation branch_target{
                    instruction.branch_target_cs.value_or(instruction.cs),
                    *instruction.branch_target_ip,
                };
                if (location_key(branch_target) == target_key &&
                    location_key(CodeLocation{instruction.cs, instruction.ip}) != target_key) {
                    return true;
                }
            }
            if (instruction.branch_fallthrough_ip.has_value()) {
                const CodeLocation fallthrough_target{instruction.cs, *instruction.branch_fallthrough_ip};
                if (location_key(fallthrough_target) == target_key &&
                    instruction_key != target_key) {
                    return true;
                }
            }

            const auto indirect_branch_it = resolved_indirect_branches.find(instruction_key);
            if (indirect_branch_it == resolved_indirect_branches.end()) {
                continue;
            }
            for (const CodeLocation branch_target : indirect_branch_it->second) {
                if (location_key(branch_target) == target_key &&
                    function_block_keys.contains(location_key(branch_target))) {
                    return true;
                }
            }
        }
    }

    return false;
}

void append_stub_function_body(std::ostringstream& oss,
                               const FunctionRecord& function) {
    oss << "static void " << function_name(function.entry) << "(GeneratedRuntimeState* state) {\n";
    oss << "    generated_runtime_note_call(state, \"" << function_name(function.entry) << "\");\n";
    oss << "    /* reachable_blocks=" << function.reachable_blocks.size()
        << " external_entries=" << function.external_entry_blocks.size() << " */\n";
    oss << "}\n\n";
}

void append_actual_body_for_entry(std::ostringstream& oss,
                                  const CfgSnapshot& snapshot,
                                  const std::vector<CodeLocation>& body_entries,
                                  const std::vector<CodeLocation>& function_blocks,
                                  const std::string& emitted_name,
                                  const std::string& note_call_name,
                                  const CodeLocation body_owner,
                                  const BlockMap& block_map,
                                  const std::map<std::uint32_t, const IndirectSiteRecord*>& indirect_sites_by_key,
                                  const std::map<std::uint32_t, std::uint32_t>& canonical_calltable_keys) {
    const std::map<std::uint32_t, std::vector<CodeLocation>> resolved_indirect_branches =
        build_resolved_indirect_branch_targets(snapshot);
    const std::set<std::uint32_t> body_entry_keys = build_location_key_set(body_entries);
    std::set<std::uint32_t> function_block_keys;
    for (const CodeLocation block_location : function_blocks) {
        const std::uint32_t block_key = location_key(block_location);
        if (!block_map.contains(block_key)) {
            continue;
        }
        function_block_keys.insert(block_key);
    }

    const std::set<std::uint32_t> function_label_keys =
        build_function_label_keys(function_blocks, block_map, function_block_keys);
    const std::map<std::uint32_t, std::vector<CodeLocation>> resolved_indirect_calls =
        build_resolved_indirect_call_targets(snapshot);
    const std::set<std::uint32_t> elidable_noop_call_target_keys =
        build_elidable_noop_call_target_keys(snapshot);
    const std::map<std::uint32_t, DirectStandaloneHelperCallSpec> direct_standalone_call_target_specs =
        build_direct_standalone_call_target_specs(snapshot);
    const std::map<std::uint32_t, DirectTypedHelperCallSpec> direct_typed_call_target_specs =
        build_direct_typed_call_target_specs(snapshot);
    const std::map<std::uint32_t, TrackedSegmentState> instruction_entry_segment_states =
        (g_emission_symbol_map != nullptr)
            ? build_instruction_entry_segment_states(snapshot, *g_emission_symbol_map)
            : std::map<std::uint32_t, TrackedSegmentState>{};

    if (function_block_keys.empty()) {
        return;
    }

    const std::uint32_t first_block_key = location_key(function_blocks.front());
    std::optional<std::uint32_t> first_entry_key;
    for (const CodeLocation entry : body_entries) {
        const std::uint32_t entry_key = location_key(entry);
        if (!function_block_keys.contains(entry_key)) {
            continue;
        }
        first_entry_key = entry_key;
        break;
    }
    const bool omit_first_block_entry_goto =
        body_entries.size() <= 1u && first_entry_key.has_value() && *first_entry_key == first_block_key;
    const bool omit_first_block_label =
        omit_first_block_entry_goto &&
        !block_start_is_targeted_within_function(
            function_blocks,
            block_map,
            function_block_keys,
            body_entries,
            function_blocks.front(),
            resolved_indirect_branches);

    oss << "static ";
    if (should_emit_noinline_body(body_owner)) {
        oss << "GENERATED_NOINLINE ";
    }
    if (body_entries.size() <= 1u) {
        oss << "void " << emitted_name << "(GeneratedRuntimeState* state) {\n";
        if (!note_call_name.empty()) {
            oss << "    generated_runtime_note_call(state, \"" << note_call_name << "\");\n";
        }
        for (const CodeLocation entry : body_entries) {
            if (!function_block_keys.contains(location_key(entry))) {
                continue;
            }
            if (!omit_first_block_entry_goto) {
                oss << "    goto " << block_label_name(entry) << ";\n\n";
            } else if (!note_call_name.empty()) {
                oss << "\n";
            }
            break;
        }
    } else {
        oss << "void " << emitted_name << "(GeneratedRuntimeState* state, uint32_t generated_entry_key) {\n";
        oss << "    switch (generated_entry_key) {\n";
        for (const CodeLocation entry : body_entries) {
            if (!function_block_keys.contains(location_key(entry))) {
                continue;
            }
            oss << "    case 0x" << hex4(entry.cs) << hex4(entry.ip) << "u:\n";
            oss << "        goto " << block_label_name(entry) << ";\n";
        }
        oss << "    default:\n";
        oss << "        generated_runtime_note_call(state, \"invalid_shared_entry\");\n";
        oss << "        return;\n";
        oss << "    }\n\n";
    }

    for (std::size_t block_index = 0; block_index < function_blocks.size(); ++block_index) {
        const CodeLocation block_location = function_blocks[block_index];
        const bool has_next_block = (block_index + 1u) < function_blocks.size();
        const CodeLocation next_block_location =
            has_next_block ? function_blocks[block_index + 1u] : CodeLocation{0u, 0u};
        const BlockRecord& block = *block_map.at(location_key(block_location));
        const bool block_has_irq_checkpoint = block_needs_irq_checkpoint(block);
        const bool suppress_block_start_label =
            omit_first_block_label && block_index == 0u && location_key(block_location) == first_block_key;
        if (block.preview.instructions.empty()) {
            if (!suppress_block_start_label) {
                oss << block_label_name(block_location) << ":\n";
            }
            if (body_entry_keys.contains(location_key(block_location)) || block_location.cs != body_owner.cs) {
                oss << "    state->cs = 0x" << hex4(block_location.cs) << ";\n";
            }
            oss << "    state->ip = 0x" << hex4(block_location.ip) << ";\n";
                oss << "    generated_runtime_note_call(state, \"unsupported_"
                    << emitted_name << "_" << block_label_name(block_location) << "\");\n";
                oss << "    return;\n\n";
                continue;
            }

        std::optional<CodeLocation> split_successor;
        std::size_t instruction_limit = block.preview.instructions.size();
        for (std::size_t instruction_index = 1; instruction_index < block.preview.instructions.size(); ++instruction_index) {
            const DecodedInstruction& instruction = block.preview.instructions[instruction_index];
            const CodeLocation split_target{instruction.cs, instruction.ip};
            if (!function_block_keys.contains(location_key(split_target))) {
                continue;
            }
            split_successor = split_target;
            instruction_limit = instruction_index;
            break;
        }

        bool block_supported = true;
        const bool block_tail_is_internal = block_tail_stays_within_emitted_body(
            block,
            split_successor,
            function_block_keys);
        for (std::size_t instruction_index = 0; instruction_index < instruction_limit; ++instruction_index) {
            const DecodedInstruction& instruction = block.preview.instructions[instruction_index];
            std::optional<CodeLocation> next_emitted_location;
            if ((instruction_index + 1u) < instruction_limit) {
                next_emitted_location = CodeLocation{
                    block.preview.instructions[instruction_index + 1u].cs,
                    block.preview.instructions[instruction_index + 1u].ip,
                };
            } else if (has_next_block) {
                next_emitted_location = next_block_location;
            }
            if (instruction_index == 0u ||
                function_label_keys.contains(location_key(CodeLocation{instruction.cs, instruction.ip}))) {
                const bool suppress_instruction_label =
                    suppress_block_start_label && instruction_index == 0u;
                if (!suppress_instruction_label) {
                    oss << block_label_name(CodeLocation{instruction.cs, instruction.ip}) << ":\n";
                }
                const CodeLocation instruction_location{instruction.cs, instruction.ip};
                if (body_entry_keys.contains(location_key(instruction_location)) || instruction.cs != body_owner.cs) {
                    oss << "    state->cs = 0x" << hex4(instruction.cs) << ";\n";
                }
                if (instruction_index == 0u && block_has_irq_checkpoint) {
                    oss << "    state->ip = 0x" << hex4(instruction.ip) << ";\n";
                    oss << "    generated_host_poll(state);\n";
                    oss << "    if (state->terminated) return;\n";
                }
            }
            if (!emit_actual_instruction(
                    oss,
                    instruction,
                    ((instruction_index + 1u) >= instruction_limit) && !block_tail_is_internal,
                    next_emitted_location,
                    function_block_keys,
                    function_label_keys,
                    instruction_entry_segment_states,
                    resolved_indirect_calls,
                    resolved_indirect_branches,
                    indirect_sites_by_key,
                    canonical_calltable_keys,
                    elidable_noop_call_target_keys,
                    direct_standalone_call_target_specs,
                    direct_typed_call_target_specs)) {
                block_supported = false;
                oss << "    generated_runtime_note_call(state, \"unsupported_"
                    << emitted_name << "_" << block_label_name(block_location)
                    << "_ip_" << hex4(instruction.ip) << "_op_" << hex4(instruction_opcode(instruction)).substr(2) << "\");\n";
                oss << "    return;\n";
                break;
            }
        }

        if (block_supported && split_successor.has_value()) {
            if (!has_next_block || !same_location(*split_successor, next_block_location)) {
                oss << "    goto " << block_label_name(*split_successor) << ";\n";
            }
        } else if (block_supported && !block.preview.terminated) {
            const DecodedInstruction& terminal = block.preview.instructions.back();
            if (preview_has_implicit_fallthrough(block.preview) && terminal.branch_fallthrough_ip.has_value()) {
                const CodeLocation fallthrough_target{terminal.cs, *terminal.branch_fallthrough_ip};
                if (function_block_keys.contains(location_key(fallthrough_target))) {
                    if (!has_next_block || !same_location(fallthrough_target, next_block_location)) {
                        oss << "    goto " << block_label_name(fallthrough_target) << ";\n";
                    }
                } else {
                    oss << "    state->cs = 0x" << hex4(fallthrough_target.cs) << ";\n";
                    oss << "    state->ip = 0x" << hex4(fallthrough_target.ip) << ";\n";
                    oss << "    return;\n";
                }
            } else if (terminal.branch_fallthrough_ip.has_value()) {
                const CodeLocation unsupported_target{terminal.cs, *terminal.branch_fallthrough_ip};
                oss << "    state->cs = 0x" << hex4(unsupported_target.cs) << ";\n";
                oss << "    state->ip = 0x" << hex4(unsupported_target.ip) << ";\n";
                oss << "    generated_runtime_note_call(state, \"unsupported_"
                    << emitted_name << "_" << block_label_name(block_location)
                    << "_next_" << hex4(unsupported_target.ip) << "\");\n";
                oss << "    return;\n";
            } else {
                oss << "    return;\n";
            }
        }
        oss << '\n';
    }

    oss << "}\n\n";
}

void append_actual_function_body(std::ostringstream& oss,
                                 const CfgSnapshot& snapshot,
                                 const std::vector<CodeLocation>& body_entries,
                                 const std::vector<CodeLocation>& function_blocks,
                                 const CodeLocation body_owner,
                                 const BlockMap& block_map,
                                 const std::map<std::uint32_t, const IndirectSiteRecord*>& indirect_sites_by_key,
                                 const std::map<std::uint32_t, std::uint32_t>& canonical_calltable_keys) {
    const bool single_entry_body = body_entries.size() <= 1u;
    append_actual_body_for_entry(
        oss,
        snapshot,
        body_entries,
        function_blocks,
        single_entry_body ? function_name(body_owner) : shared_body_name(body_owner),
        single_entry_body ? function_name(body_owner) : std::string{},
        body_owner,
        block_map,
        indirect_sites_by_key,
        canonical_calltable_keys);
}

void append_shared_body_wrapper(std::ostringstream& oss,
                                const CodeLocation wrapper_entry,
                                const CodeLocation body_owner,
                                bool body_needs_entry_key) {
    oss << "static void " << function_name(wrapper_entry) << "(GeneratedRuntimeState* state) {\n";
    oss << "    generated_runtime_note_call(state, \"" << function_name(wrapper_entry) << "\");\n";
    if (body_needs_entry_key) {
        oss << "    " << shared_body_name(body_owner) << "(state, 0x"
            << hex4(wrapper_entry.cs) << hex4(wrapper_entry.ip) << "u);\n";
    } else {
        oss << "    " << shared_body_name(body_owner) << "(state);\n";
    }
    oss << "}\n\n";
}

std::string build_generated_game_cpp_text(const CfgSnapshot& snapshot) {
    const BlockMap block_map = build_block_map(snapshot);
    const std::set<std::uint32_t> public_root_keys = build_public_root_keys(snapshot, block_map);
    const std::set<std::uint32_t> dispatchable_root_keys =
        build_dispatchable_root_keys(snapshot, public_root_keys);
    const std::set<std::uint32_t> forced_self_owned_root_keys =
        build_forced_self_owned_root_keys();
    const std::map<std::uint32_t, std::uint32_t> canonical_calltable_keys =
        build_canonical_calltable_keys(snapshot);
    const std::map<std::uint32_t, std::set<std::uint32_t>> reachable_keys_by_root =
        build_reachable_keys_by_root(snapshot, block_map, public_root_keys);
    const std::map<std::uint32_t, const IndirectSiteRecord*> indirect_sites_by_key =
        build_indirect_site_map(snapshot);
    std::map<std::uint32_t, const FunctionRecord*> function_records_by_key;
    for (const FunctionRecord& function : snapshot.functions) {
        function_records_by_key.emplace(location_key(function.entry), &function);
    }
    std::vector<std::uint32_t> ordered_public_root_keys(public_root_keys.begin(), public_root_keys.end());
    std::sort(ordered_public_root_keys.begin(), ordered_public_root_keys.end());
    std::vector<std::uint32_t> ordered_dispatchable_root_keys(dispatchable_root_keys.begin(), dispatchable_root_keys.end());
    std::sort(ordered_dispatchable_root_keys.begin(), ordered_dispatchable_root_keys.end());
    const std::uint32_t synthetic_startup_subentry_key = location_key(CodeLocation{0x1010u, 0x0040u});
    ordered_public_root_keys.erase(
        std::remove(ordered_public_root_keys.begin(), ordered_public_root_keys.end(), synthetic_startup_subentry_key),
        ordered_public_root_keys.end());
    ordered_dispatchable_root_keys.erase(
        std::remove(ordered_dispatchable_root_keys.begin(), ordered_dispatchable_root_keys.end(), synthetic_startup_subentry_key),
        ordered_dispatchable_root_keys.end());
    std::set<std::uint32_t> absorbed_root_keys;
    for (const auto& [root_key, reachable_keys] : reachable_keys_by_root) {
        for (const auto& [other_root_key, other_reachable_keys] : reachable_keys_by_root) {
            if (other_root_key == root_key) {
                continue;
            }
            if (other_reachable_keys.contains(root_key)) {
                absorbed_root_keys.insert(root_key);
                break;
            }
        }
    }
    std::set<std::uint32_t> shared_body_owner_keys;
    std::map<std::uint32_t, std::uint32_t> shared_body_owner_by_root;
    for (const std::uint32_t root_key : ordered_public_root_keys) {
        const auto reachable_it = reachable_keys_by_root.find(root_key);
        if (reachable_it == reachable_keys_by_root.end() ||
            forced_self_owned_root_keys.contains(root_key)) {
            shared_body_owner_by_root.emplace(root_key, root_key);
            shared_body_owner_keys.insert(root_key);
            continue;
        }

        std::uint32_t selected_owner = root_key;
        std::size_t selected_owner_size = std::numeric_limits<std::size_t>::max();
        bool found_owner = false;
        for (const auto& [owner_key, owner_reachable_keys] : reachable_keys_by_root) {
            if (owner_key == root_key || !owner_reachable_keys.contains(root_key)) {
                continue;
            }

            bool owner_is_absorbed = false;
            for (const auto& [other_key, other_reachable_keys] : reachable_keys_by_root) {
                if (other_key == owner_key) {
                    continue;
                }
                if (other_reachable_keys.contains(owner_key)) {
                    owner_is_absorbed = true;
                    break;
                }
            }
            if (owner_is_absorbed) {
                continue;
            }

            const std::size_t owner_size = owner_reachable_keys.size();
            if (!found_owner || owner_size < selected_owner_size ||
                (owner_size == selected_owner_size && owner_key < selected_owner)) {
                selected_owner = owner_key;
                selected_owner_size = owner_size;
                found_owner = true;
            }
        }

        shared_body_owner_by_root.emplace(root_key, selected_owner);
        shared_body_owner_keys.insert(selected_owner);
    }

    std::map<std::uint32_t, std::vector<CodeLocation>> shared_body_entries;
    std::map<std::uint32_t, std::set<std::uint32_t>> shared_body_block_keys;
    for (const std::uint32_t root_key : ordered_public_root_keys) {
        const std::uint32_t owner_key = shared_body_owner_by_root.at(root_key);
        if (block_map.contains(root_key)) {
            shared_body_entries[owner_key].push_back(key_to_location(root_key));
        }
        const auto reachable_it = reachable_keys_by_root.find(root_key);
        if (reachable_it == reachable_keys_by_root.end()) {
            continue;
        }
        shared_body_block_keys[owner_key].insert(
            reachable_it->second.begin(),
            reachable_it->second.end());
    }

    std::map<std::uint32_t, std::uint32_t> folded_owner_by_owner;
    for (const std::uint32_t owner_key : shared_body_owner_keys) {
        folded_owner_by_owner.emplace(owner_key, owner_key);
    }
    for (const std::uint32_t owner_key : shared_body_owner_keys) {
        if (forced_self_owned_root_keys.contains(owner_key)) {
            folded_owner_by_owner[owner_key] = owner_key;
            continue;
        }
        const std::set<std::uint32_t>& owner_blocks = shared_body_block_keys[owner_key];
        std::uint32_t selected_owner = owner_key;
        std::size_t selected_owner_size = owner_blocks.size();
        for (const std::uint32_t candidate_key : shared_body_owner_keys) {
            if (candidate_key == owner_key) {
                continue;
            }
            const std::set<std::uint32_t>& candidate_blocks = shared_body_block_keys[candidate_key];
            if (candidate_blocks.size() < owner_blocks.size()) {
                continue;
            }
            if (!std::includes(candidate_blocks.begin(), candidate_blocks.end(),
                               owner_blocks.begin(), owner_blocks.end())) {
                continue;
            }
            if (candidate_blocks.size() < selected_owner_size ||
                (candidate_blocks.size() == selected_owner_size && candidate_key < selected_owner)) {
                selected_owner = candidate_key;
                selected_owner_size = candidate_blocks.size();
            }
        }
        folded_owner_by_owner[owner_key] = selected_owner;
    }
    for (auto& [owner_key, folded_owner] : folded_owner_by_owner) {
        while (folded_owner_by_owner.contains(folded_owner) &&
               folded_owner_by_owner.at(folded_owner) != folded_owner) {
            folded_owner = folded_owner_by_owner.at(folded_owner);
        }
    }
    for (auto& [root_key, owner_key] : shared_body_owner_by_root) {
        if (const auto fold_it = folded_owner_by_owner.find(owner_key); fold_it != folded_owner_by_owner.end()) {
            owner_key = fold_it->second;
        }
    }
    shared_body_owner_keys.clear();
    shared_body_entries.clear();
    shared_body_block_keys.clear();
    for (const std::uint32_t root_key : ordered_public_root_keys) {
        const std::uint32_t owner_key = shared_body_owner_by_root.at(root_key);
        shared_body_owner_keys.insert(owner_key);
        if (block_map.contains(root_key)) {
            shared_body_entries[owner_key].push_back(key_to_location(root_key));
        }
        const auto reachable_it = reachable_keys_by_root.find(root_key);
        if (reachable_it == reachable_keys_by_root.end()) {
            continue;
        }
        shared_body_block_keys[owner_key].insert(
            reachable_it->second.begin(),
            reachable_it->second.end());
    }

    std::map<std::uint32_t, std::vector<CodeLocation>> ordered_shared_body_blocks;
    for (const std::uint32_t owner_key : shared_body_owner_keys) {
        std::vector<CodeLocation> blocks;
        for (const std::uint32_t block_key : shared_body_block_keys[owner_key]) {
            if (block_map.contains(block_key)) {
                blocks.push_back(key_to_location(block_key));
            }
        }
        std::sort(blocks.begin(), blocks.end(), [](const CodeLocation& left, const CodeLocation& right) {
            return location_key(left) < location_key(right);
        });
        ordered_shared_body_blocks.emplace(owner_key, std::move(blocks));

        std::vector<CodeLocation>& entries = shared_body_entries[owner_key];
        std::sort(entries.begin(), entries.end(), [](const CodeLocation& left, const CodeLocation& right) {
            return location_key(left) < location_key(right);
        });
        entries.erase(
            std::unique(entries.begin(), entries.end(), [](const CodeLocation& left, const CodeLocation& right) {
                return location_key(left) == location_key(right);
            }),
            entries.end());
    }
    std::ostringstream oss;
    oss << "#pragma warning(disable: 4102 4505)\n\n";
    oss << "#include \"generated_game.h\"\n";
    oss << '\n';
    if (g_emission_symbol_map != nullptr && !g_emission_symbol_map->ordered_offset_constants.empty()) {
        for (const auto& [key, constant_name] : g_emission_symbol_map->ordered_offset_constants) {
            const CodeLocation location = key_to_location(key);
            oss << "static constexpr uint16_t " << constant_name << " = 0x" << hex4(location.ip) << "u;\n";
        }
        oss << '\n';
    }

    for (const std::uint32_t root_key : ordered_public_root_keys) {
        oss << "static void " << function_name(key_to_location(root_key)) << "(GeneratedRuntimeState* state);\n";
    }
    for (const std::uint32_t owner_key : shared_body_owner_keys) {
        if (shared_body_entries[owner_key].size() > 1u) {
            oss << "static void " << shared_body_name(key_to_location(owner_key))
                << "(GeneratedRuntimeState* state, uint32_t generated_entry_key);\n";
        }
    }
    oss << '\n';
    if (snapshot_uses_generated_calltables(snapshot) || snapshot_uses_interface_surfaces(snapshot)) {
        oss << "typedef void (*GeneratedCallTargetFn)(GeneratedRuntimeState* state);\n";
        if (snapshot_uses_generated_calltables(snapshot)) {
            oss << "struct GeneratedWordCallTableEntry { uint16_t selector; uint16_t target_ip; GeneratedCallTargetFn fn; };\n";
            oss << "struct GeneratedPairCallTableEntry { uint16_t selector; uint16_t target_ip; GeneratedCallTargetFn fn; };\n";
        }
        if (snapshot_uses_interface_surfaces(snapshot)) {
            oss << "struct GeneratedInterfaceSurfaceEntry { uint16_t ordinal; uint16_t target_cs; uint16_t target_ip; GeneratedCallTargetFn fn; };\n";
        }
        oss << '\n';
    }
    append_generated_calltable_definitions(oss, snapshot, public_root_keys, canonical_calltable_keys);
    append_generated_interface_surface_definitions(oss, snapshot, public_root_keys);
    if (snapshot_uses_interface_surfaces(snapshot)) {
        oss << "static unsigned generated_call_interface_surface_entry("
               "GeneratedRuntimeState* state, const GeneratedInterfaceSurfaceEntry* entries, size_t entry_count, uint16_t ordinal) {\n";
        oss << "    for (size_t i = 0; i < entry_count; ++i) {\n";
        oss << "        if (entries[i].ordinal != ordinal) {\n";
        oss << "            continue;\n";
        oss << "        }\n";
        oss << "        if (entries[i].fn == 0) {\n";
        oss << "            generated_runtime_note_call(state, \"null_interface_surface_entry\");\n";
        oss << "            return 0u;\n";
        oss << "        }\n";
        oss << "        entries[i].fn(state);\n";
        oss << "        return 1u;\n";
        oss << "    }\n";
        oss << "    generated_runtime_note_call(state, \"missing_interface_surface_entry\");\n";
        oss << "    return 0u;\n";
        oss << "}\n\n";
        oss << "static unsigned generated_call_interface_surface_target("
               "GeneratedRuntimeState* state, const GeneratedInterfaceSurfaceEntry* entries, size_t entry_count, uint16_t target_cs, uint16_t target_ip) {\n";
        oss << "    if (target_ip == 0u) {\n";
        oss << "        generated_runtime_note_call(state, \"null_interface_surface_entry\");\n";
        oss << "        return 0u;\n";
        oss << "    }\n";
        oss << "    for (size_t i = 0; i < entry_count; ++i) {\n";
        oss << "        if (entries[i].target_cs != target_cs || entries[i].target_ip != target_ip) {\n";
        oss << "            continue;\n";
        oss << "        }\n";
        oss << "        if (entries[i].fn == 0) {\n";
        oss << "            generated_runtime_note_call(state, \"null_interface_surface_entry\");\n";
        oss << "            return 0u;\n";
        oss << "        }\n";
        oss << "        entries[i].fn(state);\n";
        oss << "        return 1u;\n";
        oss << "    }\n";
        oss << "    return 0u;\n";
        oss << "}\n\n";
    }
    if (snapshot_uses_routine_pack_callable_surfaces(snapshot)) {
        oss << "static void generated_call_routine_pack_init(GeneratedRuntimeState* state) {\n";
        oss << "    generated_runtime_note_call(state, \"fn_4A56_0010\");\n";
        oss << "    state->cs = 0x4A56u;\n";
        oss << "    state->ip = 0x0010u;\n";
        oss << "    state->ip = 0x0012u;\n";
        oss << "    const uint16_t generated_saved_ds = state->ds;\n";
        oss << "    state->ip = 0x0013u;\n";
        oss << "    state->ax = state->cs;\n";
        oss << "    state->ip = 0x0015u;\n";
        oss << "    state->ds = state->ax;\n";
        oss << "    state->ip = 0x0017u;\n";
        oss << "    state->si = 0x0E5Du;\n";
        oss << "    state->ip = 0x001Au;\n";
        oss << "    state->cx = 0x0010u;\n";
        oss << "    state->ip = 0x001Du;\n";
        oss << "    while (state->cx != 0u) {\n";
        oss << "        const uint16_t generated_value = generated_read_u16(state, state->ds, state->si);\n";
        oss << "        generated_write_u16(state, state->es, state->di, generated_value);\n";
        oss << "        if (generated_get_flag(state, GENERATED_FLAG_DF)) {\n";
        oss << "            state->si = (uint16_t)(state->si - 2u);\n";
        oss << "            state->di = (uint16_t)(state->di - 2u);\n";
        oss << "        } else {\n";
        oss << "            state->si = (uint16_t)(state->si + 2u);\n";
        oss << "            state->di = (uint16_t)(state->di + 2u);\n";
        oss << "        }\n";
        oss << "        state->cx = (uint16_t)(state->cx - 1u);\n";
        oss << "    }\n";
        oss << "    state->ip = 0x001Fu;\n";
        oss << "    state->ds = generated_saved_ds;\n";
        oss << "    state->ip = 0x0020u;\n";
        oss << "    state->bx = 0x0027u;\n";
        oss << "    state->ip = 0x0023u;\n";
        oss << "    state->ax = 0x002Cu;\n";
        oss << "    state->ip = 0x0026u;\n";
        oss << "    state->ip = generated_pop_u16(state);\n";
        oss << "    state->cs = generated_pop_u16(state);\n";
        oss << "}\n\n";
        oss << "static unsigned generated_call_interface_surface_near_target("
               "GeneratedRuntimeState* state, const GeneratedInterfaceSurfaceEntry* entries, size_t entry_count, uint16_t target_cs, uint16_t target_ip) {\n";
        oss << "    static const uint16_t kGeneratedBridgeReturnIp = 0xFFFFu;\n";
        oss << "    if (target_ip == 0u) {\n";
        oss << "        generated_runtime_note_call(state, \"null_interface_surface_entry\");\n";
        oss << "        return 0u;\n";
        oss << "    }\n";
        oss << "    for (size_t i = 0; i < entry_count; ++i) {\n";
        oss << "        if (entries[i].target_cs != target_cs || entries[i].target_ip != target_ip) {\n";
        oss << "            continue;\n";
        oss << "        }\n";
        oss << "        if (entries[i].fn == 0) {\n";
        oss << "            generated_runtime_note_call(state, \"null_interface_surface_entry\");\n";
        oss << "            return 0u;\n";
        oss << "        }\n";
        oss << "        generated_push_u16(state, kGeneratedBridgeReturnIp);\n";
        oss << "        entries[i].fn(state);\n";
        oss << "        if (state->terminated) {\n";
        oss << "            return 1u;\n";
        oss << "        }\n";
        oss << "        if (state->cs == target_cs && state->ip == kGeneratedBridgeReturnIp) {\n";
        oss << "            state->ip = generated_pop_u16(state);\n";
        oss << "            state->cs = generated_pop_u16(state);\n";
        oss << "        }\n";
        oss << "        return 1u;\n";
        oss << "    }\n";
        oss << "    return 0u;\n";
        oss << "}\n\n";
        oss << "static unsigned generated_call_routine_pack_bridge(GeneratedRuntimeState* state, uint16_t target_ip) {\n";
        for (const InterfaceSurfaceRecord& surface : snapshot.interface_surfaces) {
            if ((surface.kind != InterfaceSurfaceKind::RoutinePackWordTable &&
                 surface.kind != InterfaceSurfaceKind::RoutinePackDescriptorTable) ||
                surface.entries.empty()) {
                continue;
            }
            oss << "    if (generated_call_interface_surface_near_target(state, "
                << interface_surface_array_name(surface) << ", sizeof(" << interface_surface_array_name(surface)
                << ") / sizeof(" << interface_surface_array_name(surface) << "[0]), 0x"
                << hex4(surface.base.cs) << "u, target_ip)) {\n";
            oss << "        return 1u;\n";
            oss << "    }\n";
        }
        oss << "    if (generated_dispatch_root(state, 0x4A56u, target_ip)) {\n";
        oss << "        return 1u;\n";
        oss << "    }\n";
        oss << "    generated_runtime_note_call(state, \"missing_routine_pack_bridge_target\");\n";
        oss << "    return 0u;\n";
        oss << "}\n\n";
    }
    if (snapshot_uses_engine_api_surface(snapshot)) {
        oss << "static unsigned generated_call_engine_api_bridge(GeneratedRuntimeState* state, uint16_t target_ip) {\n";
        for (const InterfaceSurfaceRecord& surface : snapshot.interface_surfaces) {
            if (surface.kind != InterfaceSurfaceKind::EngineApiJumpTable ||
                surface.entries.empty()) {
                continue;
            }
            const std::uint16_t target_cs = interface_surface_target_cs(surface);
            oss << "    if (generated_call_interface_surface_near_target(state, "
                << interface_surface_array_name(surface) << ", sizeof(" << interface_surface_array_name(surface)
                << ") / sizeof(" << interface_surface_array_name(surface) << "[0]), 0x"
                << hex4(target_cs) << "u, target_ip)) {\n";
            oss << "        return 1u;\n";
            oss << "    }\n";
            oss << "    if (generated_dispatch_root(state, 0x" << hex4(target_cs) << "u, target_ip)) {\n";
            oss << "        return 1u;\n";
            oss << "    }\n";
        }
        oss << "    generated_runtime_note_call(state, \"missing_engine_api_bridge_target\");\n";
        oss << "    return 0u;\n";
        oss << "}\n\n";
    }
    oss << "static unsigned generated_resume_after_direct_call("
           "GeneratedRuntimeState* state, uint16_t expected_cs, uint16_t expected_ip) {\n";
    oss << "    if (state->terminated) {\n";
    oss << "        return 0u;\n";
    oss << "    }\n";
    oss << "    if (state->cs == expected_cs && state->ip == expected_ip) {\n";
    oss << "        return 1u;\n";
    oss << "    }\n";
    oss << "    if (generated_dispatch_root(state, state->cs, state->ip)) {\n";
    oss << "        return 0u;\n";
    oss << "    }\n";
    oss << "    generated_runtime_note_call(state, \"unsupported_return_target\");\n";
    oss << "    state->terminated = 1u;\n";
    oss << "    return 0u;\n";
    oss << "}\n\n";

    for (const std::uint32_t owner_key : ordered_public_root_keys) {
        if (!shared_body_owner_keys.contains(owner_key)) {
            continue;
        }
        append_actual_function_body(
            oss,
            snapshot,
            shared_body_entries[owner_key],
            ordered_shared_body_blocks[owner_key],
            key_to_location(owner_key),
            block_map,
            indirect_sites_by_key,
            canonical_calltable_keys);
    }

    for (const std::uint32_t root_key : ordered_public_root_keys) {
        const auto function_it = function_records_by_key.find(root_key);
        if (!block_map.contains(root_key)) {
            if (function_it != function_records_by_key.end()) {
                append_stub_function_body(oss, *function_it->second);
            } else {
                FunctionRecord synthetic_stub{};
                synthetic_stub.entry = key_to_location(root_key);
                append_stub_function_body(oss, synthetic_stub);
            }
            continue;
        }

        const std::uint32_t owner_key = shared_body_owner_by_root.at(root_key);
        if (shared_body_entries[owner_key].size() <= 1u && owner_key == root_key) {
            continue;
        }
        append_shared_body_wrapper(
            oss,
            key_to_location(root_key),
            key_to_location(owner_key),
            shared_body_entries[owner_key].size() > 1u);

    }

    for (const TypedHelperWrapperSpec& spec : build_typed_helper_wrapper_specs(snapshot)) {
        oss << "/* typed helper wrapper */\n";
        append_typed_helper_wrapper_definition(oss, spec);
    }
    for (const TypedHelperWrapperSpec& spec : build_standalone_typed_helper_wrapper_specs(snapshot)) {
        oss << "/* standalone typed helper wrapper */\n";
        append_standalone_typed_helper_wrapper_definition(oss, spec);
    }

    oss << "unsigned generated_dispatch_root(GeneratedRuntimeState* state, uint16_t cs, uint16_t ip) {\n";
    oss << "    switch ((((uint32_t)cs) << 16u) | (uint32_t)ip) {\n";
    for (const std::uint32_t root_key : ordered_dispatchable_root_keys) {
        const CodeLocation entry = key_to_location(root_key);
        oss << "    case 0x" << hex4(entry.cs) << hex4(entry.ip) << "u:\n";
        oss << "        " << function_name(entry) << "(state);\n";
        oss << "        return 1u;\n";
    }
    oss << "    default:\n";
    oss << "        return 0u;\n";
    oss << "    }\n";
    oss << "}\n\n";

    oss << "void generated_entry(GeneratedRuntimeState* state) {\n";
    oss << "    " << function_name(snapshot.root) << "(state);\n";
    oss << "}\n\n";
    return oss.str();
}

} // namespace

void emit_standalone_project(const MzImage& image,
                             const CfgSnapshot& snapshot,
                             const std::filesystem::path& output_dir,
                             const std::optional<std::filesystem::path>& labels_path) {
    const std::filesystem::path src_dir = output_dir / "src";
    std::filesystem::create_directories(src_dir);

    const std::filesystem::path project_path = output_dir / "GeneratedGame.vcxproj";
    if (!std::filesystem::exists(project_path)) {
        write_text_file(project_path, build_project_text());
    }

    const EmissionSymbolMap symbol_map = load_emission_symbol_map(image, labels_path);
    const GeneratedDataLayout data_layout = build_generated_data_layout(image, snapshot, symbol_map);
    const ScopedEmissionSymbolMap scoped_symbol_map(symbol_map);
    const ScopedGeneratedDataLayout scoped_generated_data_layout(data_layout);
    write_text_file(src_dir / "generated_data.h", build_generated_data_text(image, data_layout));
    write_text_file(output_dir / "generated_data_report.txt", build_generated_data_report_text(image, data_layout));
    write_text_file(output_dir / "generated_data_symbols.csv", build_generated_data_symbols_csv_text(data_layout));
    write_text_file(output_dir / "generated_data_families.csv", build_generated_data_families_csv_text(data_layout));
    write_text_file(output_dir / "generated_static_access_report.txt",
                    build_generated_static_access_report_text(snapshot, image, symbol_map, data_layout));
    write_text_file(output_dir / "generated_function_signature_report.txt",
                    build_function_signature_report_text(snapshot));
    write_text_file(output_dir / "generated_function_signatures.csv",
                    build_function_signatures_csv_text(snapshot));
    write_text_file(output_dir / "generated_typed_helper_wrapper_report.txt",
                    build_typed_helper_wrapper_report_text(snapshot));
    write_text_file(output_dir / "generated_typed_helper_wrappers.csv",
                    build_typed_helper_wrappers_csv_text(snapshot));
    write_text_file(output_dir / "generated_standalone_typed_helper_wrapper_report.txt",
                    build_standalone_typed_helper_wrapper_report_text(snapshot));
    write_text_file(output_dir / "generated_standalone_typed_helper_wrappers.csv",
                    build_standalone_typed_helper_wrappers_csv_text(snapshot));
    write_text_file(output_dir / "generated_typed_helper_callsite_candidates.txt",
                    build_typed_helper_callsite_candidate_report_text(snapshot));
    write_text_file(output_dir / "generated_typed_helper_callsite_candidates.csv",
                    build_typed_helper_callsite_candidates_csv_text(snapshot));
    write_text_file(src_dir / "generated_runtime.h", load_template_text("Transpiler/templates/generated_runtime.h.in"));
    write_text_file(src_dir / "generated_runtime.cpp", load_template_text("Transpiler/templates/generated_runtime.cpp.in"));
    write_text_file(src_dir / "generated_game.h", build_generated_game_header_text(snapshot));
    const std::string generated_game_cpp_text = build_generated_game_cpp_text(snapshot);
    write_text_file(src_dir / "generated_game.cpp", generated_game_cpp_text);
    write_text_file(output_dir / "generated_typed_helper_lowering_report.txt",
                    build_typed_helper_lowering_report_text(snapshot, generated_game_cpp_text));
    write_text_file(output_dir / "generated_typed_helper_lowering.csv",
                    build_typed_helper_lowering_csv_text(snapshot, generated_game_cpp_text));
    write_text_file(src_dir / "main.cpp", load_template_text("Transpiler/templates/main.cpp.in"));
}

} // namespace mz2cpp
