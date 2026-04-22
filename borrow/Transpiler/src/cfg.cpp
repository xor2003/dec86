#include "cfg.h"

#include <algorithm>
#include <array>
#include <deque>
#include <iomanip>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string_view>
#include <stdexcept>

namespace mz2cpp {

namespace {

enum class Register16Id {
    AX,
    CX,
    DX,
    BX,
    SP,
    BP,
    SI,
    DI,
};

enum class SegmentRegisterId {
    DS,
    ES,
    SS,
};

struct KnownWord {
    std::vector<std::uint16_t> values;
};

struct AbstractState {
    std::array<KnownWord, 8> regs{};
    KnownWord ds{};
    KnownWord es{};
    KnownWord ss{};
    std::map<std::uint32_t, std::uint16_t> direct_memory_words{};
    std::map<std::uint16_t, KnownWord> direct_offset_words{};
    std::map<std::uint16_t, std::vector<CodeLocation>> far_pointer_slots{};
};

struct DirectMemoryValue {
    KnownWord value{};
    bool came_from_override = false;
};

struct DirectWriteSummary {
    std::map<std::uint32_t, KnownWord> physical_words{};
    std::map<std::uint16_t, std::vector<CodeLocation>> far_pointer_slots{};
    std::map<std::uint16_t, std::vector<CodeLocation>> near_pointer_slots{};
};

std::uint32_t logical_key(const CodeLocation location) {
    return (static_cast<std::uint32_t>(location.cs) << 16u) | location.ip;
}

CodeLocation key_to_location(const std::uint32_t key) {
    return CodeLocation{
        static_cast<std::uint16_t>((key >> 16u) & 0xFFFFu),
        static_cast<std::uint16_t>(key & 0xFFFFu),
    };
}

std::uint64_t edge_key(const CfgEdge& edge) {
    const std::uint64_t from = logical_key(edge.from);
    const std::uint64_t to = logical_key(edge.to);
    return (from << 32u) ^ (to << 2u) ^ static_cast<std::uint64_t>(edge.kind);
}

std::uint64_t analysis_state_key(const std::uint32_t owner_root_key, const std::uint32_t block_key) {
    return (static_cast<std::uint64_t>(owner_root_key) << 32u) | block_key;
}

std::uint32_t analysis_owner_root_from_key(const std::uint64_t key) {
    return static_cast<std::uint32_t>(key >> 32u);
}

std::uint32_t analysis_block_from_key(const std::uint64_t key) {
    return static_cast<std::uint32_t>(key & 0xFFFFFFFFu);
}

std::string hex16(const std::uint16_t value) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << value;
    return oss.str();
}

std::string register16_name(const std::uint8_t index) {
    static const std::array<const char*, 8> kNames = {"ax", "cx", "dx", "bx", "sp", "bp", "si", "di"};
    return kNames.at(index & 7u);
}

std::string format_location(const CodeLocation location) {
    return hex16(location.cs) + ':' + hex16(location.ip).substr(2);
}

bool location_less(const CodeLocation& lhs, const CodeLocation& rhs) {
    return logical_key(lhs) < logical_key(rhs);
}

bool starts_with(const std::string_view text, const std::string_view prefix) {
    return text.size() >= prefix.size() && text.substr(0, prefix.size()) == prefix;
}

std::optional<std::uint16_t> parse_text_hex16(const std::string_view text) {
    try {
        const unsigned long value = std::stoul(std::string(text), nullptr, 16);
        if (value > 0xFFFFu) {
            return std::nullopt;
        }
        return static_cast<std::uint16_t>(value);
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<std::uint16_t> parse_mov_imm16(const std::string_view text, const std::string_view reg_name) {
    const std::string prefix = "mov " + std::string(reg_name) + ", 0x";
    if (!starts_with(text, prefix)) {
        return std::nullopt;
    }
    return parse_text_hex16(text.substr(prefix.size()));
}

bool is_interrupt_instruction(const DecodedInstruction& instruction, const std::uint8_t vector) {
    std::ostringstream oss;
    oss << "int 0x" << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
        << static_cast<unsigned>(vector);
    const std::string expected = oss.str();
    return instruction.text == expected;
}

std::string edge_kind_name(const EdgeKind kind) {
    switch (kind) {
    case EdgeKind::Branch: return "branch";
    case EdgeKind::Fallthrough: return "fallthrough";
    case EdgeKind::Call: return "call";
    }
    return "edge";
}

std::string interface_surface_kind_name(const InterfaceSurfaceKind kind) {
    switch (kind) {
    case InterfaceSurfaceKind::EngineApiJumpTable: return "engine_api_jump_table";
    case InterfaceSurfaceKind::RoutinePackWordTable: return "routine_pack_word_table";
    case InterfaceSurfaceKind::RoutinePackDescriptorTable: return "routine_pack_descriptor_table";
    case InterfaceSurfaceKind::RoutinePackPairTable: return "routine_pack_pair_table";
    }
    return "surface";
}

std::string fragment_disposition_name(const FunctionRecord::EntryFragmentRecord::Disposition disposition) {
    switch (disposition) {
    case FunctionRecord::EntryFragmentRecord::Disposition::SingleBlockClone: return "single_block_clone";
    case FunctionRecord::EntryFragmentRecord::Disposition::CloneFragment: return "clone_fragment";
    case FunctionRecord::EntryFragmentRecord::Disposition::SharedRegion: return "shared_region";
    case FunctionRecord::EntryFragmentRecord::Disposition::SplitRegion: return "split_region";
    }
    return "fragment";
}

std::string fragment_lowering_action_name(const FunctionRecord::EntryFragmentRecord::LoweringAction action) {
    switch (action) {
    case FunctionRecord::EntryFragmentRecord::LoweringAction::CloneLeaf: return "clone_leaf";
    case FunctionRecord::EntryFragmentRecord::LoweringAction::CloneWithRejoin: return "clone_with_rejoin";
    case FunctionRecord::EntryFragmentRecord::LoweringAction::KeepSharedRegion: return "keep_shared_region";
    case FunctionRecord::EntryFragmentRecord::LoweringAction::SplitBeforeLowering: return "split_before_lowering";
    }
    return "lower";
}

FunctionRecord::EntryFragmentRecord::Disposition classify_fragment_disposition(
    const FunctionRecord::EntryFragmentRecord& fragment) {
    const std::size_t reachable = fragment.reachable_blocks.size();
    const std::size_t clone_candidates = fragment.clone_candidate_blocks.size();
    const std::size_t shared = fragment.shared_blocks.size();

    if (reachable == 1u && clone_candidates == 1u && shared == 0u) {
        return FunctionRecord::EntryFragmentRecord::Disposition::SingleBlockClone;
    }
    if (clone_candidates == reachable && shared == 0u) {
        return FunctionRecord::EntryFragmentRecord::Disposition::CloneFragment;
    }
    if (clone_candidates == 0u && shared == reachable) {
        return FunctionRecord::EntryFragmentRecord::Disposition::SharedRegion;
    }
    return FunctionRecord::EntryFragmentRecord::Disposition::SplitRegion;
}

FunctionRecord::EntryFragmentRecord::LoweringAction classify_fragment_lowering_action(
    const FunctionRecord::EntryFragmentRecord& fragment) {
    switch (fragment.disposition) {
    case FunctionRecord::EntryFragmentRecord::Disposition::SingleBlockClone:
    case FunctionRecord::EntryFragmentRecord::Disposition::CloneFragment:
        if (fragment.exit_to_blocks.empty()) {
            return FunctionRecord::EntryFragmentRecord::LoweringAction::CloneLeaf;
        }
        return FunctionRecord::EntryFragmentRecord::LoweringAction::CloneWithRejoin;
    case FunctionRecord::EntryFragmentRecord::Disposition::SharedRegion:
        return FunctionRecord::EntryFragmentRecord::LoweringAction::KeepSharedRegion;
    case FunctionRecord::EntryFragmentRecord::Disposition::SplitRegion:
        return FunctionRecord::EntryFragmentRecord::LoweringAction::SplitBeforeLowering;
    }
    return FunctionRecord::EntryFragmentRecord::LoweringAction::SplitBeforeLowering;
}

void sort_locations(std::vector<CodeLocation>& locations) {
    std::sort(locations.begin(), locations.end(), location_less);
}

std::size_t strip_prefix_bytes(const DecodedInstruction& instruction) {
    std::size_t index = 0;
    while (index < instruction.bytes.size()) {
        switch (instruction.bytes[index]) {
        case 0x26u:
        case 0x2Eu:
        case 0x36u:
        case 0x3Eu:
        case 0xF2u:
        case 0xF3u:
            ++index;
            break;
        default:
            return index;
        }
    }
    return index;
}

bool starts_with(const std::string& text, const std::string_view prefix) {
    return text.size() >= prefix.size() &&
           text.compare(0, prefix.size(), prefix.data(), prefix.size()) == 0;
}

bool instruction_has_prefix(const DecodedInstruction& instruction, const std::uint8_t prefix) {
    const std::size_t prefix_length = strip_prefix_bytes(instruction);
    for (std::size_t i = 0; i < prefix_length; ++i) {
        if (instruction.bytes[i] == prefix) {
            return true;
        }
    }
    return false;
}

KnownWord& register_ref(AbstractState& state, const Register16Id id) {
    return state.regs[static_cast<std::size_t>(id)];
}

const KnownWord& register_ref(const AbstractState& state, const Register16Id id) {
    return state.regs[static_cast<std::size_t>(id)];
}

KnownWord& segment_ref(AbstractState& state, const SegmentRegisterId id) {
    switch (id) {
    case SegmentRegisterId::DS: return state.ds;
    case SegmentRegisterId::ES: return state.es;
    case SegmentRegisterId::SS: return state.ss;
    }
    return state.ds;
}

const KnownWord& segment_ref(const AbstractState& state, const SegmentRegisterId id) {
    switch (id) {
    case SegmentRegisterId::DS: return state.ds;
    case SegmentRegisterId::ES: return state.es;
    case SegmentRegisterId::SS: return state.ss;
    }
    return state.ds;
}

void set_unknown(KnownWord& value) {
    value.values.clear();
}

KnownWord make_known(const std::uint16_t value) {
    KnownWord known{};
    known.values.push_back(value);
    return known;
}

bool is_known(const KnownWord& value) {
    return !value.values.empty();
}

bool is_singleton(const KnownWord& value) {
    return value.values.size() == 1u;
}

std::optional<std::uint16_t> singleton_value(const KnownWord& value) {
    if (!is_singleton(value)) {
        return std::nullopt;
    }
    return value.values.front();
}

constexpr std::size_t kMaxTrackedWordValues = 16u;

bool insert_known_value(KnownWord& target, const std::uint16_t value) {
    if (std::find(target.values.begin(), target.values.end(), value) != target.values.end()) {
        return false;
    }
    target.values.push_back(value);
    std::sort(target.values.begin(), target.values.end());
    return true;
}

void invalidate_all_registers(AbstractState& state) {
    for (KnownWord& reg : state.regs) {
        set_unknown(reg);
    }
}

void invalidate_register(AbstractState& state, const Register16Id id) {
    set_unknown(register_ref(state, id));
}

std::optional<Register16Id> decode_register16(const std::uint8_t index) {
    switch (index & 0x07u) {
    case 0u: return Register16Id::AX;
    case 1u: return Register16Id::CX;
    case 2u: return Register16Id::DX;
    case 3u: return Register16Id::BX;
    case 4u: return Register16Id::SP;
    case 5u: return Register16Id::BP;
    case 6u: return Register16Id::SI;
    case 7u: return Register16Id::DI;
    }
    return std::nullopt;
}

std::optional<Register16Id> decode_register8_base(const std::uint8_t index) {
    switch (index & 0x03u) {
    case 0u: return Register16Id::AX;
    case 1u: return Register16Id::CX;
    case 2u: return Register16Id::DX;
    case 3u: return Register16Id::BX;
    }
    return std::nullopt;
}

bool is_high_byte_register(const std::uint8_t index) {
    return (index & 0x04u) != 0u;
}

void invalidate_register_from_byte_index(AbstractState& state, const std::uint8_t byte_index) {
    const auto reg = decode_register8_base(byte_index);
    if (reg.has_value()) {
        invalidate_register(state, *reg);
    }
}

KnownWord known_byte_from_word(const KnownWord& value, const bool high_byte) {
    KnownWord result{};
    if (!is_known(value)) {
        return result;
    }
    for (const std::uint16_t candidate : value.values) {
        const std::uint16_t byte_value =
            high_byte ? static_cast<std::uint16_t>((candidate >> 8u) & 0x00FFu)
                      : static_cast<std::uint16_t>(candidate & 0x00FFu);
        insert_known_value(result, byte_value);
        if (result.values.size() > kMaxTrackedWordValues) {
            set_unknown(result);
            return result;
        }
    }
    return result;
}

KnownWord combine_known_word_with_byte(const KnownWord& word_value,
                                       const KnownWord& byte_value,
                                       const bool high_byte) {
    KnownWord result{};
    if (!is_known(word_value) || !is_known(byte_value)) {
        return result;
    }
    for (const std::uint16_t word_candidate : word_value.values) {
        for (const std::uint16_t byte_candidate : byte_value.values) {
            const std::uint16_t combined =
                high_byte
                    ? static_cast<std::uint16_t>((word_candidate & 0x00FFu) |
                                                 ((byte_candidate & 0x00FFu) << 8u))
                    : static_cast<std::uint16_t>((word_candidate & 0xFF00u) |
                                                 (byte_candidate & 0x00FFu));
            insert_known_value(result, combined);
            if (result.values.size() > kMaxTrackedWordValues) {
                set_unknown(result);
                return result;
            }
        }
    }
    return result;
}

void set_known_byte_in_register(AbstractState& state,
                                const std::uint8_t byte_index,
                                const KnownWord& byte_value) {
    const auto reg = decode_register8_base(byte_index);
    if (!reg.has_value()) {
        return;
    }
    if (!is_known(byte_value)) {
        invalidate_register(state, *reg);
        return;
    }

    KnownWord& word = register_ref(state, *reg);
    if (!is_known(word)) {
        set_unknown(word);
        return;
    }

    const KnownWord combined =
        combine_known_word_with_byte(word, byte_value, is_high_byte_register(byte_index));
    if (!is_known(combined)) {
        set_unknown(word);
        return;
    }
    word = combined;
}

std::optional<Register16Id> parse_register16_name(const std::string& text) {
    if (text == "ax") return Register16Id::AX;
    if (text == "cx") return Register16Id::CX;
    if (text == "dx") return Register16Id::DX;
    if (text == "bx") return Register16Id::BX;
    if (text == "sp") return Register16Id::SP;
    if (text == "bp") return Register16Id::BP;
    if (text == "si") return Register16Id::SI;
    if (text == "di") return Register16Id::DI;
    return std::nullopt;
}

std::optional<SegmentRegisterId> decode_segment_register(const std::uint8_t field) {
    switch (field & 0x03u) {
    case 0u: return SegmentRegisterId::ES;
    case 2u: return SegmentRegisterId::SS;
    case 3u: return SegmentRegisterId::DS;
    default: return std::nullopt;
    }
}

bool merge_known_word(KnownWord& target, const KnownWord source) {
    if (!is_known(target)) {
        return false;
    }
    if (!is_known(source)) {
        set_unknown(target);
        return true;
    }

    bool changed = false;
    for (const std::uint16_t value : source.values) {
        changed = insert_known_value(target, value) || changed;
    }
    if (target.values.size() > kMaxTrackedWordValues) {
        set_unknown(target);
        return true;
    }
    return changed;
}

bool merge_abstract_state(AbstractState& target, const AbstractState& source) {
    bool changed = false;
    for (std::size_t i = 0; i < target.regs.size(); ++i) {
        changed = merge_known_word(target.regs[i], source.regs[i]) || changed;
    }
    changed = merge_known_word(target.ds, source.ds) || changed;
    changed = merge_known_word(target.es, source.es) || changed;
    changed = merge_known_word(target.ss, source.ss) || changed;

    std::set<std::uint32_t> addresses;
    for (const auto& [physical, value] : target.direct_memory_words) {
        (void)value;
        addresses.insert(physical);
    }
    for (const auto& [physical, value] : source.direct_memory_words) {
        (void)value;
        addresses.insert(physical);
    }

    for (const std::uint32_t physical : addresses) {
        const auto target_it = target.direct_memory_words.find(physical);
        const auto source_it = source.direct_memory_words.find(physical);
        if (target_it == target.direct_memory_words.end()) {
            continue;
        }
        if (source_it == source.direct_memory_words.end() || source_it->second != target_it->second) {
            target.direct_memory_words.erase(target_it);
            changed = true;
        }
    }

    for (const auto& [offset, values] : source.direct_offset_words) {
        auto it = target.direct_offset_words.find(offset);
        if (it == target.direct_offset_words.end()) {
            target.direct_offset_words.emplace(offset, values);
            changed = true;
        } else {
            changed = merge_known_word(it->second, values) || changed;
        }
    }

    for (const auto& [offset, targets] : source.far_pointer_slots) {
        std::vector<CodeLocation>& target_targets = target.far_pointer_slots[offset];
        const std::size_t before = target_targets.size();
        for (const CodeLocation target_location : targets) {
            const auto existing = std::find_if(target_targets.begin(),
                                               target_targets.end(),
                                               [&](const CodeLocation& candidate) {
                                                   return logical_key(candidate) == logical_key(target_location);
                                               });
            if (existing == target_targets.end()) {
                target_targets.push_back(target_location);
            }
        }
        if (target_targets.size() != before) {
            sort_locations(target_targets);
            changed = true;
        }
    }
    return changed;
}

std::uint16_t read_instruction_u16(const DecodedInstruction& instruction, const std::size_t index) {
    if (index + 1u >= instruction.bytes.size()) {
        throw std::runtime_error("decoder metadata is inconsistent with instruction byte length");
    }
    return static_cast<std::uint16_t>(instruction.bytes[index]) |
           static_cast<std::uint16_t>(instruction.bytes[index + 1u] << 8u);
}

std::optional<std::uint16_t> decode_immediate_add_to_register(const DecodedInstruction& instruction,
                                                              const Register16Id target_register) {
    if (instruction.bytes.empty()) {
        return std::nullopt;
    }

    const std::size_t prefix_length = strip_prefix_bytes(instruction);
    if (prefix_length >= instruction.bytes.size()) {
        return std::nullopt;
    }

    const std::uint8_t opcode = instruction.bytes[prefix_length];
    if (opcode == 0x81u) {
        if (prefix_length + 3u >= instruction.bytes.size()) {
            return std::nullopt;
        }
        const std::uint8_t modrm = instruction.bytes[prefix_length + 1u];
        const std::uint8_t mod = static_cast<std::uint8_t>((modrm >> 6u) & 0x03u);
        const std::uint8_t group = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
        const std::uint8_t rm = static_cast<std::uint8_t>(modrm & 0x07u);
        const auto dest = decode_register16(rm);
        if (mod != 0x03u || group != 0x00u || !dest.has_value() || *dest != target_register) {
            return std::nullopt;
        }
        const std::uint16_t imm16 = read_instruction_u16(instruction, prefix_length + 2u);
        if (imm16 < 0x0100u) {
            return std::nullopt;
        }
        return imm16;
    }

    if (opcode == 0x83u) {
        if (prefix_length + 2u >= instruction.bytes.size()) {
            return std::nullopt;
        }
        const std::uint8_t modrm = instruction.bytes[prefix_length + 1u];
        const std::uint8_t mod = static_cast<std::uint8_t>((modrm >> 6u) & 0x03u);
        const std::uint8_t group = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
        const std::uint8_t rm = static_cast<std::uint8_t>(modrm & 0x07u);
        const auto dest = decode_register16(rm);
        if (mod != 0x03u || group != 0x00u || !dest.has_value() || *dest != target_register) {
            return std::nullopt;
        }
        const std::int8_t imm8 = static_cast<std::int8_t>(instruction.bytes[prefix_length + 2u]);
        if (imm8 >= -0x7F && imm8 <= 0x7F) {
            return std::nullopt;
        }
        return static_cast<std::uint16_t>(static_cast<std::int16_t>(imm8));
    }

    return std::nullopt;
}

std::optional<SegmentRegisterId> direct_operand_segment_from_text(const std::string& operand_text) {
    if (starts_with(operand_text, "cs:[")) {
        return std::nullopt;
    }
    if (starts_with(operand_text, "ds:[")) {
        return SegmentRegisterId::DS;
    }
    if (starts_with(operand_text, "es:[")) {
        return SegmentRegisterId::ES;
    }
    if (starts_with(operand_text, "ss:[")) {
        return SegmentRegisterId::SS;
    }
    if (starts_with(operand_text, "[")) {
        return SegmentRegisterId::DS;
    }
    return std::nullopt;
}

std::optional<std::uint16_t> direct_operand_offset_from_text(const std::string& operand_text) {
    const std::size_t left = operand_text.find('[');
    const std::size_t right = operand_text.find(']');
    if (left == std::string::npos || right == std::string::npos || right <= left + 1u) {
        return std::nullopt;
    }
    const std::string inner = operand_text.substr(left + 1u, right - left - 1u);
    const std::size_t hex = inner.find("0x");
    if (hex == std::string::npos) {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(std::stoul(inner.substr(hex + 2u), nullptr, 16));
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

struct IndexedMemoryOperandInfo {
    Register16Id base_register = Register16Id::BX;
    std::int16_t displacement = 0;
    bool uses_current_cs = false;
};

struct CurrentCsIndexedLoadInfo {
    Register16Id base_register = Register16Id::BX;
    std::int16_t displacement = 0;
    CodeLocation location{};
    std::uint32_t block_key = 0u;
    std::uint32_t predecessor_key = 0u;
};

std::optional<IndexedMemoryOperandInfo> parse_indexed_memory_operand_text(const std::string& operand_text) {
    const std::size_t left = operand_text.find('[');
    const std::size_t right = operand_text.find(']');
    if (left == std::string::npos || right == std::string::npos || right <= left + 1u) {
        return std::nullopt;
    }

    IndexedMemoryOperandInfo info{};
    if (starts_with(operand_text, "cs:[")) {
        info.uses_current_cs = true;
    } else if (starts_with(operand_text, "ds:[") ||
               starts_with(operand_text, "es:[") ||
               starts_with(operand_text, "ss:[")) {
    } else if (!starts_with(operand_text, "[")) {
        return std::nullopt;
    }

    const std::string inner = operand_text.substr(left + 1u, right - left - 1u);
    auto try_base = [&](const std::string& name, const Register16Id id) -> bool {
        if (inner == name) {
            info.base_register = id;
            info.displacement = 0;
            return true;
        }
        const std::string plus_prefix = name + " + 0x";
        if (starts_with(inner, plus_prefix)) {
            const std::optional<std::uint16_t> disp = parse_text_hex16(inner.substr(plus_prefix.size()));
            if (!disp.has_value()) {
                return false;
            }
            info.base_register = id;
            info.displacement = static_cast<std::int16_t>(*disp);
            return true;
        }
        const std::string minus_prefix = name + " - 0x";
        if (starts_with(inner, minus_prefix)) {
            const std::optional<std::uint16_t> disp = parse_text_hex16(inner.substr(minus_prefix.size()));
            if (!disp.has_value()) {
                return false;
            }
            info.base_register = id;
            info.displacement = static_cast<std::int16_t>(-static_cast<std::int32_t>(*disp));
            return true;
        }
        return false;
    };

    if (try_base("bp", Register16Id::BP) ||
        try_base("si", Register16Id::SI) ||
        try_base("di", Register16Id::DI) ||
        try_base("bx", Register16Id::BX)) {
        return info;
    }
    return std::nullopt;
}

std::optional<std::string> mov_source_operand_text(const DecodedInstruction& instruction) {
    if (!starts_with(instruction.text, "mov ")) {
        return std::nullopt;
    }
    const std::size_t comma = instruction.text.find(", ");
    if (comma == std::string::npos || comma + 2u >= instruction.text.size()) {
        return std::nullopt;
    }
    return instruction.text.substr(comma + 2u);
}

std::optional<std::string> mov_destination_operand_text(const DecodedInstruction& instruction) {
    if (!starts_with(instruction.text, "mov ")) {
        return std::nullopt;
    }
    const std::size_t comma = instruction.text.find(", ");
    if (comma == std::string::npos || comma <= 4u) {
        return std::nullopt;
    }
    return instruction.text.substr(4u, comma - 4u);
}

KnownWord resolve_direct_segment_values(const AbstractState& state,
                                        const DecodedInstruction& instruction,
                                        const std::string& operand_text) {
    if (starts_with(operand_text, "cs:[")) {
        return make_known(instruction.cs);
    }
    const std::optional<SegmentRegisterId> segment_id = direct_operand_segment_from_text(operand_text);
    if (!segment_id.has_value()) {
        return KnownWord{};
    }
    return segment_ref(state, *segment_id);
}

KnownWord instruction_memory_segment_values(const AbstractState& state,
                                            const DecodedInstruction& instruction,
                                            const std::uint8_t mod,
                                            const std::uint8_t rm) {
    const std::size_t prefix_length = strip_prefix_bytes(instruction);
    for (std::size_t i = 0; i < prefix_length; ++i) {
        switch (instruction.bytes[i]) {
        case 0x26u: return state.es;
        case 0x2Eu: return make_known(instruction.cs);
        case 0x36u: return state.ss;
        case 0x3Eu: return state.ds;
        default: break;
        }
    }

    const bool uses_bp_base =
        rm == 0x02u || rm == 0x03u || (rm == 0x06u && mod != 0x00u);
    return uses_bp_base ? state.ss : state.ds;
}

KnownWord add_known_words(const KnownWord& left,
                          const KnownWord& right,
                          const std::int16_t displacement = 0) {
    KnownWord result{};
    if (!is_known(left) || !is_known(right)) {
        return result;
    }
    for (const std::uint16_t left_value : left.values) {
        for (const std::uint16_t right_value : right.values) {
            const std::uint16_t sum =
                static_cast<std::uint16_t>(left_value + right_value + displacement);
            insert_known_value(result, sum);
            if (result.values.size() > kMaxTrackedWordValues) {
                set_unknown(result);
                return result;
            }
        }
    }
    return result;
}

KnownWord add_known_word_and_displacement(const KnownWord& value, const std::int16_t displacement) {
    KnownWord result{};
    if (!is_known(value)) {
        return result;
    }
    for (const std::uint16_t candidate : value.values) {
        insert_known_value(result, static_cast<std::uint16_t>(candidate + displacement));
        if (result.values.size() > kMaxTrackedWordValues) {
            set_unknown(result);
            return result;
        }
    }
    return result;
}

KnownWord resolve_modrm_memory_offset_values(const AbstractState& state,
                                             const DecodedInstruction& instruction,
                                             const std::size_t prefix_length,
                                             const std::uint8_t mod,
                                             const std::uint8_t rm) {
    std::int16_t displacement = 0;
    if (mod == 0x01u) {
        displacement = static_cast<std::int8_t>(instruction.bytes[prefix_length + 2u]);
    } else if (mod == 0x02u || (mod == 0x00u && rm == 0x06u)) {
        displacement = static_cast<std::int16_t>(read_instruction_u16(instruction, prefix_length + 2u));
    }

    if (mod == 0x00u && rm == 0x06u) {
        return make_known(static_cast<std::uint16_t>(displacement));
    }

    switch (rm) {
    case 0x00u:
        return add_known_words(register_ref(state, Register16Id::BX),
                               register_ref(state, Register16Id::SI),
                               displacement);
    case 0x01u:
        return add_known_words(register_ref(state, Register16Id::BX),
                               register_ref(state, Register16Id::DI),
                               displacement);
    case 0x02u:
        return add_known_words(register_ref(state, Register16Id::BP),
                               register_ref(state, Register16Id::SI),
                               displacement);
    case 0x03u:
        return add_known_words(register_ref(state, Register16Id::BP),
                               register_ref(state, Register16Id::DI),
                               displacement);
    case 0x04u:
        return add_known_word_and_displacement(register_ref(state, Register16Id::SI), displacement);
    case 0x05u:
        return add_known_word_and_displacement(register_ref(state, Register16Id::DI), displacement);
    case 0x06u:
        return add_known_word_and_displacement(register_ref(state, Register16Id::BP), displacement);
    case 0x07u:
        return add_known_word_and_displacement(register_ref(state, Register16Id::BX), displacement);
    default:
        return KnownWord{};
    }
}

std::uint16_t read_memory_u16(const MzImage& image, const std::uint16_t segment, const std::uint16_t offset);
bool is_location_in_loaded_image(const MzImage& image, const CodeLocation location);
bool is_plausible_code_target(const MzImage& image, const CodeLocation location);
bool preview_has_implicit_fallthrough(const BasicBlockPreview& preview);
bool preview_looks_like_code_target(const BasicBlockPreview& preview);

DirectMemoryValue read_direct_memory_word(const MzImage& image,
                                          const std::map<std::uint32_t, std::uint16_t>& overrides,
                                          const KnownWord& segment_values,
                                          const std::uint16_t offset) {
    DirectMemoryValue result{};
    if (!is_known(segment_values)) {
        return result;
    }
    for (const std::uint16_t segment : segment_values.values) {
        const std::uint32_t physical = real_mode_phys(segment, offset);
        const auto it = overrides.find(physical);
        if (it != overrides.end()) {
            insert_known_value(result.value, it->second);
            result.came_from_override = true;
        } else {
            insert_known_value(result.value, read_memory_u16(image, segment, offset));
        }
        if (result.value.values.size() > kMaxTrackedWordValues) {
            set_unknown(result.value);
            break;
        }
    }
    return result;
}

DirectMemoryValue read_memory_word_from_candidates(const MzImage& image,
                                                   const std::map<std::uint32_t, std::uint16_t>& overrides,
                                                   const KnownWord& segment_values,
                                                   const KnownWord& offset_values) {
    DirectMemoryValue result{};
    if (!is_known(segment_values) || !is_known(offset_values)) {
        return result;
    }
    for (const std::uint16_t segment : segment_values.values) {
        for (const std::uint16_t offset : offset_values.values) {
            const std::uint32_t physical = real_mode_phys(segment, offset);
            const auto it = overrides.find(physical);
            if (it != overrides.end()) {
                insert_known_value(result.value, it->second);
                result.came_from_override = true;
            } else {
                insert_known_value(result.value, read_memory_u16(image, segment, offset));
            }
            if (result.value.values.size() > kMaxTrackedWordValues) {
                set_unknown(result.value);
                return result;
            }
        }
    }
    return result;
}

KnownWord read_memory_byte_from_candidates(const MzImage& image,
                                           const std::map<std::uint32_t, std::uint16_t>& overrides,
                                           const KnownWord& segment_values,
                                           const KnownWord& offset_values) {
    KnownWord result{};
    if (!is_known(segment_values) || !is_known(offset_values)) {
        return result;
    }

    for (const std::uint16_t segment : segment_values.values) {
        for (const std::uint16_t offset : offset_values.values) {
            const std::uint32_t physical = real_mode_phys(segment, offset);
            std::uint8_t byte_value = 0;
            bool found = false;

            const auto direct_it = overrides.find(physical);
            if (direct_it != overrides.end()) {
                byte_value = static_cast<std::uint8_t>(direct_it->second & 0x00FFu);
                found = true;
            } else if (physical > 0u) {
                const auto prev_it = overrides.find(physical - 1u);
                if (prev_it != overrides.end()) {
                    byte_value = static_cast<std::uint8_t>((prev_it->second >> 8u) & 0x00FFu);
                    found = true;
                }
            }

            if (!found) {
                if (physical >= image.initial_memory_image.size()) {
                    continue;
                }
                byte_value = image.initial_memory_image[physical];
            }

            insert_known_value(result, static_cast<std::uint16_t>(byte_value));
            if (result.values.size() > kMaxTrackedWordValues) {
                set_unknown(result);
                return result;
            }
        }
    }

    return result;
}

void write_direct_memory_word(std::map<std::uint32_t, std::uint16_t>& overrides,
                              const KnownWord& segment_values,
                              const std::uint16_t offset,
                              const KnownWord value) {
    if (!is_known(segment_values)) {
        return;
    }

    const std::optional<std::uint16_t> concrete_value = singleton_value(value);
    for (const std::uint16_t segment : segment_values.values) {
        const std::uint32_t physical = real_mode_phys(segment, offset);
        if (concrete_value.has_value()) {
            overrides[physical] = *concrete_value;
        } else {
            overrides.erase(physical);
        }
    }
}

void write_direct_offset_word(AbstractState& state,
                              const std::uint16_t offset,
                              const KnownWord value) {
    if (!is_known(value)) {
        state.direct_offset_words.erase(offset);
        return;
    }
    state.direct_offset_words[offset] = value;
}

void refresh_far_pointer_slot(AbstractState& state,
                              const MzImage& image,
                              const std::uint16_t offset_base) {
    const auto ip_it = state.direct_offset_words.find(offset_base);
    const auto cs_it = state.direct_offset_words.find(static_cast<std::uint16_t>(offset_base + 2u));
    if (ip_it == state.direct_offset_words.end() || cs_it == state.direct_offset_words.end()) {
        return;
    }
    if (!is_known(ip_it->second) || !is_known(cs_it->second)) {
        return;
    }
    std::vector<CodeLocation>& targets = state.far_pointer_slots[offset_base];
    for (const std::uint16_t target_cs : cs_it->second.values) {
        for (const std::uint16_t target_ip : ip_it->second.values) {
            const CodeLocation target{target_cs, target_ip};
            if (!is_plausible_code_target(image, target)) {
                continue;
            }
            const auto existing = std::find_if(targets.begin(),
                                               targets.end(),
                                               [&](const CodeLocation& candidate) {
                                                   return logical_key(candidate) == logical_key(target);
                                               });
            if (existing == targets.end()) {
                targets.push_back(target);
            }
        }
    }
    sort_locations(targets);
}

std::uint16_t far_pointer_slot_base(const std::uint16_t offset) {
    return (offset & 0x0002u) != 0u ? static_cast<std::uint16_t>(offset - 2u) : offset;
}

void write_memory_word_to_candidates(std::map<std::uint32_t, std::uint16_t>& overrides,
                                     const KnownWord& segment_values,
                                     const KnownWord& offset_values,
                                     const KnownWord value) {
    if (!is_known(segment_values) || !is_known(offset_values)) {
        return;
    }

    const std::optional<std::uint16_t> concrete_value = singleton_value(value);
    for (const std::uint16_t segment : segment_values.values) {
        for (const std::uint16_t offset : offset_values.values) {
            const std::uint32_t physical = real_mode_phys(segment, offset);
            if (concrete_value.has_value()) {
                overrides[physical] = *concrete_value;
            } else {
                overrides.erase(physical);
            }
        }
    }
}

void merge_summary_word(KnownWord& target, const std::uint16_t value) {
    insert_known_value(target, value);
    if (target.values.size() > kMaxTrackedWordValues) {
        set_unknown(target);
    }
}

KnownWord shift_left_known_word(const KnownWord& value, const unsigned int count) {
    KnownWord result{};
    if (!is_known(value)) {
        return result;
    }
    for (const std::uint16_t candidate : value.values) {
        insert_known_value(result, static_cast<std::uint16_t>(candidate << count));
        if (result.values.size() > kMaxTrackedWordValues) {
            set_unknown(result);
            return result;
        }
    }
    return result;
}

void record_direct_write_summary(DirectWriteSummary& summary,
                                 const std::uint32_t physical,
                                 const std::uint16_t value) {
    KnownWord& known = summary.physical_words[physical];
    if (!is_known(known)) {
        known = make_known(value);
        return;
    }
    merge_summary_word(known, value);
}

void record_far_pointer_slot_summary(DirectWriteSummary& summary,
                                     const std::uint16_t offset,
                                     const CodeLocation target) {
    std::vector<CodeLocation>& targets = summary.far_pointer_slots[offset];
    const std::uint32_t target_key = logical_key(target);
    const auto existing = std::find_if(targets.begin(),
                                       targets.end(),
                                       [&](const CodeLocation& candidate) {
                                           return logical_key(candidate) == target_key;
                                       });
    if (existing == targets.end()) {
        targets.push_back(target);
        sort_locations(targets);
    }
}

void record_near_pointer_slot_summary(DirectWriteSummary& summary,
                                      const std::uint16_t offset,
                                      const CodeLocation target) {
    std::vector<CodeLocation>& targets = summary.near_pointer_slots[offset];
    const std::uint32_t target_key = logical_key(target);
    const auto existing = std::find_if(targets.begin(),
                                       targets.end(),
                                       [&](const CodeLocation& candidate) {
                                           return logical_key(candidate) == target_key;
                                       });
    if (existing == targets.end()) {
        targets.push_back(target);
        sort_locations(targets);
    }
}

bool append_segmented_word_targets(const MzImage& image,
                                   const std::map<std::uint32_t, std::uint16_t>& direct_memory_overrides,
                                   const KnownWord& segment_values,
                                   const KnownWord& index_values,
                                   const std::int16_t displacement,
                                   const std::uint16_t target_cs,
                                   std::vector<CodeLocation>& out_targets,
                                   std::size_t* skipped_candidates = nullptr) {
    const KnownWord target_offsets = add_known_word_and_displacement(index_values, displacement);
    const DirectMemoryValue loaded =
        read_memory_word_from_candidates(image, direct_memory_overrides, segment_values, target_offsets);
    if (!is_known(loaded.value)) {
        return false;
    }

    bool changed = false;
    for (const std::uint16_t target_ip : loaded.value.values) {
        const CodeLocation target{target_cs, target_ip};
        if (!is_plausible_code_target(image, target)) {
            if (skipped_candidates != nullptr) {
                ++(*skipped_candidates);
            }
            continue;
        }
        const std::uint32_t target_key = logical_key(target);
        const auto existing = std::find_if(out_targets.begin(),
                                           out_targets.end(),
                                           [&](const CodeLocation& candidate) {
                                               return logical_key(candidate) == target_key;
                                           });
        if (existing == out_targets.end()) {
            out_targets.push_back(target);
            changed = true;
        }
    }
    if (changed) {
        sort_locations(out_targets);
    }
    return changed;
}

bool append_fallback_same_segment_word_targets(const MzImage& image,
                                               const std::map<std::uint32_t, std::uint16_t>& direct_memory_overrides,
                                               const KnownWord& index_values,
                                               const std::int16_t displacement,
                                               const std::initializer_list<std::uint16_t> candidate_segments,
                                               const std::uint16_t target_cs,
                                               std::vector<CodeLocation>& out_targets,
                                               std::size_t* skipped_candidates = nullptr) {
    bool changed = false;
    std::set<std::uint16_t> tested_segments;
    for (const std::uint16_t segment : candidate_segments) {
        if (!tested_segments.insert(segment).second) {
            continue;
        }
        changed =
            append_segmented_word_targets(image,
                                          direct_memory_overrides,
                                          make_known(segment),
                                          index_values,
                                          displacement,
                                          target_cs,
                                          out_targets,
                                          skipped_candidates) ||
            changed;
    }
    return changed;
}

void push_abstract_stack(std::vector<KnownWord>& abstract_stack, const KnownWord value) {
    abstract_stack.push_back(value);
}

KnownWord pop_abstract_stack(std::vector<KnownWord>& abstract_stack) {
    if (abstract_stack.empty()) {
        return KnownWord{};
    }
    const KnownWord value = abstract_stack.back();
    abstract_stack.pop_back();
    return value;
}

void apply_instruction_effect(const MzImage& image,
                              const DecodedInstruction& instruction,
                              AbstractState& state,
                              std::map<std::uint32_t, std::uint16_t>& direct_memory_overrides,
                              std::vector<KnownWord>& abstract_stack);

bool append_current_cs_word_table_targets(const MzImage& image,
                                          const CfgSnapshot& snapshot,
                                          const CodeLocation site_location,
                                          const Register16Id base_register,
                                          std::vector<CodeLocation>& out_targets,
                                          IndirectSiteRecord* site_metadata = nullptr);
bool append_current_cs_indexed_targets_via_block_entry_replay(
    const MzImage& image,
    const CfgSnapshot& snapshot,
    const std::map<std::uint64_t, std::map<std::uint32_t, AbstractState>>& entry_states,
    const std::uint64_t owner_state_key,
    const BlockRecord& block,
    const CodeLocation site_location,
    const CodeLocation source_location,
    std::vector<CodeLocation>& out_targets,
    IndirectSiteRecord* site_metadata = nullptr);
bool append_same_segment_bounded_word_table_targets(
    const MzImage& image,
    const std::uint16_t segment,
    const std::uint16_t table_base,
    const std::uint16_t entry_count,
    std::vector<CodeLocation>& out_targets,
    std::size_t* skipped_candidates = nullptr);
std::optional<std::uint16_t> discover_unsigned_upper_bound_from_predecessor_fallthrough(
    const CfgSnapshot& snapshot,
    const std::uint32_t predecessor_block_key,
    const CodeLocation target_block_start);
std::optional<std::uint16_t> discover_register_provenance_direct_offset_via_predecessor_chain_impl(
    const CfgSnapshot& snapshot,
    const std::map<std::uint64_t, std::map<std::uint32_t, AbstractState>>& entry_states,
    const std::uint64_t owner_state_key,
    const std::uint32_t predecessor_key,
    const Register16Id target_register);

DirectWriteSummary collect_direct_write_summary(
    const CfgSnapshot& snapshot,
    const std::map<std::uint64_t, std::map<std::uint32_t, AbstractState>>& entry_states,
    const MzImage& image) {
    DirectWriteSummary summary{};
    std::map<std::uint32_t, const BlockRecord*> blocks_by_key;
    for (const BlockRecord& block : snapshot.blocks) {
        blocks_by_key[logical_key(block.start)] = &block;
    }

    for (const auto& [state_key, predecessor_states] : entry_states) {
        const std::uint32_t block_key = analysis_block_from_key(state_key);
        const auto block_it = blocks_by_key.find(block_key);
        if (block_it == blocks_by_key.end()) {
            continue;
        }
        const CodeLocation owner_root = key_to_location(analysis_owner_root_from_key(state_key));

        for (const auto& [predecessor_key, entry_state] : predecessor_states) {
            (void)predecessor_key;
            AbstractState current = entry_state;
            std::map<std::uint32_t, std::uint16_t>& direct_memory_overrides = current.direct_memory_words;
            std::vector<KnownWord> abstract_stack;
            struct RegisterWriteProvenance {
                enum class Kind {
                    None,
                    IndexedLoad,
                };

                Kind kind = Kind::None;
                KnownWord segment_values{};
                KnownWord index_values{};
                Register16Id index_base_register = Register16Id::BX;
                std::int16_t indexed_displacement = 0;
                bool uses_current_cs = false;
            };
            std::array<RegisterWriteProvenance, 8> register_provenance{};
            for (const DecodedInstruction& instruction : block_it->second->preview.instructions) {
                std::optional<std::uint16_t> written_direct_offset;
                std::optional<std::string> written_direct_operand_text;
                std::optional<Register16Id> written_direct_source_register;
                if (!instruction.bytes.empty()) {
                    const std::size_t prefix_length = strip_prefix_bytes(instruction);
                    if (prefix_length < instruction.bytes.size()) {
                        const std::uint8_t opcode = instruction.bytes[prefix_length];
                        if (opcode == 0xA3u) {
                            written_direct_offset = read_instruction_u16(instruction, prefix_length + 1u);
                            written_direct_operand_text = mov_destination_operand_text(instruction);
                            written_direct_source_register = Register16Id::AX;
                        } else if ((opcode == 0x89u || opcode == 0x8Cu || opcode == 0xC7u) &&
                                   prefix_length + 1u < instruction.bytes.size()) {
                            const std::uint8_t modrm = instruction.bytes[prefix_length + 1u];
                            const std::uint8_t mod = static_cast<std::uint8_t>((modrm >> 6u) & 0x03u);
                            const std::uint8_t reg = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
                            const std::uint8_t rm = static_cast<std::uint8_t>(modrm & 0x07u);
                            if (mod == 0x00u && rm == 0x06u) {
                                written_direct_offset = read_instruction_u16(instruction, prefix_length + 2u);
                                written_direct_operand_text = mov_destination_operand_text(instruction);
                                if (opcode == 0x89u) {
                                    written_direct_source_register = decode_register16(reg);
                                }
                            }
                        }
                    }
                }

                const std::map<std::uint32_t, std::uint16_t> before = direct_memory_overrides;
                apply_instruction_effect(image, instruction, current, direct_memory_overrides, abstract_stack);
                for (const auto& [physical, value] : direct_memory_overrides) {
                    const auto before_it = before.find(physical);
                    if (before_it != before.end() && before_it->second == value) {
                        continue;
                    }
                    record_direct_write_summary(summary, physical, value);
                }

                if (written_direct_offset.has_value() && written_direct_operand_text.has_value()) {
                    const KnownWord segment_values =
                        resolve_direct_segment_values(current, instruction, *written_direct_operand_text);
                    const std::uint16_t ip_offset =
                        ((*written_direct_offset & 0x0002u) == 0u)
                            ? *written_direct_offset
                            : static_cast<std::uint16_t>(*written_direct_offset - 2u);
                    if (is_known(segment_values)) {
                        for (const std::uint16_t segment : segment_values.values) {
                            const auto ip_it = direct_memory_overrides.find(real_mode_phys(segment, ip_offset));
                            const auto cs_it =
                                direct_memory_overrides.find(real_mode_phys(segment, static_cast<std::uint16_t>(ip_offset + 2u)));
                            if (ip_it == direct_memory_overrides.end() || cs_it == direct_memory_overrides.end()) {
                                continue;
                            }
                            const CodeLocation target{cs_it->second, ip_it->second};
                            if (is_location_in_loaded_image(image, target)) {
                                record_far_pointer_slot_summary(summary, ip_offset, target);
                            }
                        }
                    }

                    if (written_direct_source_register.has_value()) {
                        const RegisterWriteProvenance& provenance =
                            register_provenance[static_cast<std::size_t>(*written_direct_source_register)];
                        if (provenance.kind == RegisterWriteProvenance::Kind::IndexedLoad) {
                            std::vector<CodeLocation> near_targets;
                            const KnownWord index_values =
                                is_known(provenance.index_values)
                                    ? provenance.index_values
                                    : register_ref(current, provenance.index_base_register);
                            if (append_segmented_word_targets(image,
                                                              direct_memory_overrides,
                                                              provenance.segment_values,
                                                              index_values,
                                                              provenance.indexed_displacement,
                                                              instruction.cs,
                                                              near_targets)) {
                                for (const CodeLocation target : near_targets) {
                                    record_near_pointer_slot_summary(summary, *written_direct_offset, target);
                                }
                            } else if (!is_known(provenance.segment_values) &&
                                       append_fallback_same_segment_word_targets(image,
                                                                                 direct_memory_overrides,
                                                                                 index_values,
                                                                                 provenance.indexed_displacement,
                                                                                 {instruction.cs, owner_root.cs},
                                                                                 instruction.cs,
                                                                                 near_targets)) {
                                for (const CodeLocation target : near_targets) {
                                    record_near_pointer_slot_summary(summary, *written_direct_offset, target);
                                }
                            } else if (provenance.uses_current_cs &&
                                       append_current_cs_word_table_targets(image,
                                                                            snapshot,
                                                                            CodeLocation{instruction.cs, instruction.ip},
                                                                            provenance.index_base_register,
                                                                            near_targets)) {
                                for (const CodeLocation target : near_targets) {
                                    record_near_pointer_slot_summary(summary, *written_direct_offset, target);
                                }
                            }
                        }
                    }
                }

                if (!instruction.bytes.empty()) {
                    const std::size_t prefix_length = strip_prefix_bytes(instruction);
                    if (prefix_length < instruction.bytes.size()) {
                        const std::uint8_t opcode = instruction.bytes[prefix_length];
                        if (opcode >= 0xB8u && opcode <= 0xBFu) {
                            if (const auto dest = decode_register16(static_cast<std::uint8_t>(opcode - 0xB8u));
                                dest.has_value()) {
                                register_provenance[static_cast<std::size_t>(*dest)] = RegisterWriteProvenance{};
                            }
                        } else if (opcode == 0xA1u) {
                            register_provenance[static_cast<std::size_t>(Register16Id::AX)] = RegisterWriteProvenance{};
                        } else if (opcode == 0x8Bu && prefix_length + 1u < instruction.bytes.size()) {
                            const std::uint8_t modrm = instruction.bytes[prefix_length + 1u];
                            const auto dest =
                                decode_register16(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
                            if (dest.has_value()) {
                                RegisterWriteProvenance next{};
                                const std::optional<std::string> source_operand =
                                    mov_source_operand_text(instruction);
                                if (source_operand.has_value()) {
                                    const std::optional<IndexedMemoryOperandInfo> indexed =
                                        parse_indexed_memory_operand_text(*source_operand);
                                    if (indexed.has_value()) {
                                        const std::uint8_t mod =
                                            static_cast<std::uint8_t>((modrm >> 6u) & 0x03u);
                                        const std::uint8_t rm =
                                            static_cast<std::uint8_t>(modrm & 0x07u);
                                        next.kind = RegisterWriteProvenance::Kind::IndexedLoad;
                                        next.segment_values =
                                            resolve_direct_segment_values(current, instruction, *source_operand);
                                        if (!is_known(next.segment_values)) {
                                            next.segment_values =
                                                instruction_memory_segment_values(current, instruction, mod, rm);
                                        }
                                        next.index_values = register_ref(current, indexed->base_register);
                                        next.index_base_register = indexed->base_register;
                                        next.indexed_displacement = indexed->displacement;
                                        next.uses_current_cs = indexed->uses_current_cs;
                                    }
                                }
                                register_provenance[static_cast<std::size_t>(*dest)] = next;
                            }
                        } else if (opcode >= 0x58u && opcode <= 0x5Fu) {
                            if (const auto dest = decode_register16(static_cast<std::uint8_t>(opcode - 0x58u));
                                dest.has_value()) {
                                register_provenance[static_cast<std::size_t>(*dest)] = RegisterWriteProvenance{};
                            }
                        }
                    }
                }
            }
        }
    }

    return summary;
}

void apply_instruction_effect(const MzImage& image,
                              const DecodedInstruction& instruction,
                              AbstractState& state,
                              std::map<std::uint32_t, std::uint16_t>& direct_memory_overrides,
                              std::vector<KnownWord>& abstract_stack) {
    if (instruction.bytes.empty()) {
        return;
    }

    const std::size_t prefix_length = strip_prefix_bytes(instruction);
    if (prefix_length >= instruction.bytes.size()) {
        return;
    }

    const std::uint8_t opcode = instruction.bytes[prefix_length];
    const auto read_modrm = [&](const std::size_t index) -> std::uint8_t {
        if (index >= instruction.bytes.size()) {
            throw std::runtime_error("modrm read ran past instruction bytes");
        }
        return instruction.bytes[index];
    };

    if (opcode >= 0xB8u && opcode <= 0xBFu) {
        register_ref(state, *decode_register16(opcode - 0xB8u)) = make_known(read_instruction_u16(instruction, prefix_length + 1u));
        return;
    }
    if (opcode >= 0xB0u && opcode <= 0xB7u) {
        invalidate_register_from_byte_index(state, static_cast<std::uint8_t>(opcode - 0xB0u));
        return;
    }
    if (opcode >= 0x50u && opcode <= 0x57u) {
        push_abstract_stack(abstract_stack, register_ref(state, *decode_register16(opcode - 0x50u)));
        return;
    }
    if (opcode >= 0x58u && opcode <= 0x5Fu) {
        register_ref(state, *decode_register16(opcode - 0x58u)) = pop_abstract_stack(abstract_stack);
        return;
    }

    switch (opcode) {
    case 0x06u:
        push_abstract_stack(abstract_stack, state.es);
        return;
    case 0x0Eu:
        push_abstract_stack(abstract_stack, make_known(instruction.cs));
        return;
    case 0x16u:
        push_abstract_stack(abstract_stack, state.ss);
        return;
    case 0x1Eu:
        push_abstract_stack(abstract_stack, state.ds);
        return;
    case 0x07u:
        state.es = pop_abstract_stack(abstract_stack);
        return;
    case 0x17u:
        state.ss = pop_abstract_stack(abstract_stack);
        return;
    case 0x1Fu:
        state.ds = pop_abstract_stack(abstract_stack);
        return;
    case 0xA1u: {
        const std::uint16_t offset = read_instruction_u16(instruction, prefix_length + 1u);
        const KnownWord segment = resolve_direct_segment_values(state, instruction, instruction.text.substr(8u));
        if (!is_known(segment)) {
            const auto it = state.direct_offset_words.find(offset);
            if (it != state.direct_offset_words.end()) {
                register_ref(state, Register16Id::AX) = it->second;
            } else {
                invalidate_register(state, Register16Id::AX);
            }
            return;
        }
        register_ref(state, Register16Id::AX) =
            read_direct_memory_word(image, direct_memory_overrides, segment, offset).value;
        return;
    }
    case 0xA3u: {
        const std::uint16_t offset = read_instruction_u16(instruction, prefix_length + 1u);
        const std::optional<std::string> destination_operand = mov_destination_operand_text(instruction);
        const KnownWord segment =
            destination_operand.has_value()
                ? resolve_direct_segment_values(state, instruction, *destination_operand)
                : KnownWord{};
        if (!is_known(segment)) {
            return;
        }
        write_direct_memory_word(direct_memory_overrides,
                                 segment,
                                 offset,
                                 register_ref(state, Register16Id::AX));
        write_direct_offset_word(state, offset, register_ref(state, Register16Id::AX));
        refresh_far_pointer_slot(state, image, far_pointer_slot_base(offset));
        return;
    }
    case 0xA2u:
        return;
    case 0x8Au:
    case 0x88u: {
        const std::uint8_t modrm = read_modrm(prefix_length + 1u);
        const std::uint8_t mod = static_cast<std::uint8_t>((modrm >> 6u) & 0x03u);
        const std::uint8_t reg = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
        const std::uint8_t rm = static_cast<std::uint8_t>(modrm & 0x07u);
        if (opcode == 0x8Au) {
            if (mod == 0x03u) {
                const auto source_reg = decode_register8_base(rm);
                if (!source_reg.has_value()) {
                    invalidate_register_from_byte_index(state, reg);
                    return;
                }
                set_known_byte_in_register(
                    state,
                    reg,
                    known_byte_from_word(register_ref(state, *source_reg), is_high_byte_register(rm)));
                return;
            }

            const KnownWord segment = instruction_memory_segment_values(state, instruction, mod, rm);
            const KnownWord offsets = resolve_modrm_memory_offset_values(state, instruction, prefix_length, mod, rm);
            set_known_byte_in_register(
                state,
                reg,
                read_memory_byte_from_candidates(image, direct_memory_overrides, segment, offsets));
            return;
        }

        if (mod == 0x03u) {
            const auto dest_reg = decode_register8_base(rm);
            if (!dest_reg.has_value()) {
                return;
            }
            invalidate_register(state, *dest_reg);
        }
        return;
    }
    case 0x30u:
    case 0x32u: {
        const std::uint8_t modrm = read_modrm(prefix_length + 1u);
        const std::uint8_t mod = static_cast<std::uint8_t>((modrm >> 6u) & 0x03u);
        const std::uint8_t reg = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
        const std::uint8_t rm = static_cast<std::uint8_t>(modrm & 0x07u);
        if (mod == 0x03u && reg == rm) {
            set_known_byte_in_register(state,
                                       opcode == 0x32u ? reg : rm,
                                       make_known(0u));
            return;
        }

        invalidate_register_from_byte_index(state, opcode == 0x32u ? reg : rm);
        return;
    }
    case 0x0Au: {
        const std::uint8_t modrm = read_modrm(prefix_length + 1u);
        const std::uint8_t mod = static_cast<std::uint8_t>((modrm >> 6u) & 0x03u);
        const std::uint8_t reg = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
        const std::uint8_t rm = static_cast<std::uint8_t>(modrm & 0x07u);
        if (mod == 0x03u && reg == rm) {
            return;
        }
        invalidate_register_from_byte_index(state, reg);
        return;
    }
    case 0x03u: {
        const std::uint8_t modrm = read_modrm(prefix_length + 1u);
        const std::uint8_t mod = static_cast<std::uint8_t>((modrm >> 6u) & 0x03u);
        const std::uint8_t reg = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
        const std::uint8_t rm = static_cast<std::uint8_t>(modrm & 0x07u);
        KnownWord source{};
        if (mod == 0x03u) {
            source = register_ref(state, *decode_register16(rm));
        } else {
            const KnownWord segment = instruction_memory_segment_values(state, instruction, mod, rm);
            const KnownWord offsets = resolve_modrm_memory_offset_values(state, instruction, prefix_length, mod, rm);
            source = read_memory_word_from_candidates(image, direct_memory_overrides, segment, offsets).value;
        }
        register_ref(state, *decode_register16(reg)) =
            add_known_words(register_ref(state, *decode_register16(reg)), source);
        return;
    }
    case 0x83u: {
        const std::uint8_t modrm = read_modrm(prefix_length + 1u);
        const std::uint8_t mod = static_cast<std::uint8_t>((modrm >> 6u) & 0x03u);
        const std::uint8_t group = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
        const std::uint8_t rm = static_cast<std::uint8_t>(modrm & 0x07u);
        const std::int16_t imm8 = static_cast<std::int8_t>(instruction.bytes.back());
        if (group == 0u && mod == 0x03u) {
            register_ref(state, *decode_register16(rm)) =
                add_known_word_and_displacement(register_ref(state, *decode_register16(rm)), imm8);
            return;
        }
        if ((group == 5u || group == 7u) && mod == 0x03u) {
            invalidate_register(state, *decode_register16(rm));
            return;
        }
        return;
    }
    case 0xD1u: {
        const std::uint8_t modrm = read_modrm(prefix_length + 1u);
        const std::uint8_t mod = static_cast<std::uint8_t>((modrm >> 6u) & 0x03u);
        const std::uint8_t group = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
        const std::uint8_t rm = static_cast<std::uint8_t>(modrm & 0x07u);
        if (mod == 0x03u && group == 4u) {
            register_ref(state, *decode_register16(rm)) =
                shift_left_known_word(register_ref(state, *decode_register16(rm)), 1u);
            return;
        }
        if (mod == 0x03u) {
            invalidate_register(state, *decode_register16(rm));
        }
        return;
    }
    case 0x31u:
    case 0x33u: {
        const std::uint8_t modrm = read_modrm(prefix_length + 1u);
        const std::uint8_t mod = static_cast<std::uint8_t>((modrm >> 6u) & 0x03u);
        const std::uint8_t reg = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
        const std::uint8_t rm = static_cast<std::uint8_t>(modrm & 0x07u);
        if (mod == 0x03u && reg == rm) {
            if (opcode == 0x33u) {
                register_ref(state, *decode_register16(reg)) = make_known(0u);
            } else {
                register_ref(state, *decode_register16(rm)) = make_known(0u);
            }
            return;
        }
        if (opcode == 0x33u) {
            invalidate_register(state, *decode_register16(reg));
        } else if (mod == 0x03u) {
            invalidate_register(state, *decode_register16(rm));
        }
        return;
    }
    case 0x8Cu: {
        const std::uint8_t modrm = read_modrm(prefix_length + 1u);
        const std::uint8_t mod = static_cast<std::uint8_t>((modrm >> 6u) & 0x03u);
        const std::uint8_t reg = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
        const std::uint8_t rm = static_cast<std::uint8_t>(modrm & 0x07u);
        const std::optional<SegmentRegisterId> segment_id = decode_segment_register(reg);
        if (!segment_id.has_value()) {
            return;
        }
        if (mod == 0x03u) {
            register_ref(state, *decode_register16(rm)) = segment_ref(state, *segment_id);
        }
        const KnownWord segment = instruction_memory_segment_values(state, instruction, mod, rm);
        const KnownWord offsets = resolve_modrm_memory_offset_values(state, instruction, prefix_length, mod, rm);
        write_memory_word_to_candidates(direct_memory_overrides,
                                        segment,
                                        offsets,
                                        segment_ref(state, *segment_id));
        if (mod == 0x00u && rm == 0x06u) {
            const std::uint16_t offset = read_instruction_u16(instruction, prefix_length + 2u);
            write_direct_offset_word(state, offset, segment_ref(state, *segment_id));
            refresh_far_pointer_slot(state, image, far_pointer_slot_base(offset));
        }
        return;
    }
    case 0x8Eu: {
        const std::uint8_t modrm = read_modrm(prefix_length + 1u);
        const std::uint8_t mod = static_cast<std::uint8_t>((modrm >> 6u) & 0x03u);
        const std::uint8_t reg = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
        const std::uint8_t rm = static_cast<std::uint8_t>(modrm & 0x07u);
        const std::optional<SegmentRegisterId> segment_id = decode_segment_register(reg);
        if (!segment_id.has_value()) {
            return;
        }
        if (mod == 0x03u) {
            segment_ref(state, *segment_id) = register_ref(state, *decode_register16(rm));
        } else {
            const KnownWord segment = instruction_memory_segment_values(state, instruction, mod, rm);
            const KnownWord offsets = resolve_modrm_memory_offset_values(state, instruction, prefix_length, mod, rm);
            segment_ref(state, *segment_id) =
                read_memory_word_from_candidates(image, direct_memory_overrides, segment, offsets).value;
        }
        return;
    }
    case 0x8Bu:
    case 0x89u: {
        const std::uint8_t modrm = read_modrm(prefix_length + 1u);
        const std::uint8_t mod = static_cast<std::uint8_t>((modrm >> 6u) & 0x03u);
        const std::uint8_t reg = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
        const std::uint8_t rm = static_cast<std::uint8_t>(modrm & 0x07u);
        if (opcode == 0x8Bu) {
            if (mod == 0x03u) {
                register_ref(state, *decode_register16(reg)) = register_ref(state, *decode_register16(rm));
            } else {
                const KnownWord segment = instruction_memory_segment_values(state, instruction, mod, rm);
                const KnownWord offsets = resolve_modrm_memory_offset_values(state, instruction, prefix_length, mod, rm);
                if (!is_known(segment) || !is_known(offsets)) {
                    if (mod == 0x00u && rm == 0x06u) {
                        const std::uint16_t offset = read_instruction_u16(instruction, prefix_length + 2u);
                        const auto it = state.direct_offset_words.find(offset);
                        if (it != state.direct_offset_words.end()) {
                            register_ref(state, *decode_register16(reg)) = it->second;
                        } else {
                            invalidate_register(state, *decode_register16(reg));
                        }
                    } else {
                        invalidate_register(state, *decode_register16(reg));
                    }
                } else {
                    register_ref(state, *decode_register16(reg)) =
                        read_memory_word_from_candidates(image, direct_memory_overrides, segment, offsets).value;
                }
            }
        } else if (mod == 0x03u) {
            register_ref(state, *decode_register16(rm)) = register_ref(state, *decode_register16(reg));
        } else {
            const KnownWord segment = instruction_memory_segment_values(state, instruction, mod, rm);
            const KnownWord offsets = resolve_modrm_memory_offset_values(state, instruction, prefix_length, mod, rm);
            write_memory_word_to_candidates(direct_memory_overrides,
                                            segment,
                                            offsets,
                                            register_ref(state, *decode_register16(reg)));
            if (mod == 0x00u && rm == 0x06u) {
                const std::uint16_t offset = read_instruction_u16(instruction, prefix_length + 2u);
                write_direct_offset_word(state, offset, register_ref(state, *decode_register16(reg)));
                refresh_far_pointer_slot(state, image, far_pointer_slot_base(offset));
            }
        }
        return;
    }
    case 0xC4u:
    case 0xC5u: {
        const std::uint8_t modrm = read_modrm(prefix_length + 1u);
        const std::uint8_t mod = static_cast<std::uint8_t>((modrm >> 6u) & 0x03u);
        const std::uint8_t reg = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
        const std::uint8_t rm = static_cast<std::uint8_t>(modrm & 0x07u);
        if (mod == 0x03u) {
            invalidate_register(state, *decode_register16(reg));
            set_unknown(opcode == 0xC4u ? state.es : state.ds);
            return;
        }
        const KnownWord segment = instruction_memory_segment_values(state, instruction, mod, rm);
        const KnownWord offsets = resolve_modrm_memory_offset_values(state, instruction, prefix_length, mod, rm);
        if (!is_known(segment) || !is_known(offsets)) {
            invalidate_register(state, *decode_register16(reg));
            set_unknown(opcode == 0xC4u ? state.es : state.ds);
            return;
        }
        register_ref(state, *decode_register16(reg)) =
            read_memory_word_from_candidates(image, direct_memory_overrides, segment, offsets).value;
        KnownWord loaded_segment = read_memory_word_from_candidates(
            image,
            direct_memory_overrides,
            segment,
            add_known_word_and_displacement(offsets, 2)).value;
        if (opcode == 0xC4u) {
            state.es = loaded_segment;
        } else {
            state.ds = loaded_segment;
        }
        return;
    }
    case 0xC7u: {
        const std::uint8_t modrm = read_modrm(prefix_length + 1u);
        const std::uint8_t mod = static_cast<std::uint8_t>((modrm >> 6u) & 0x03u);
        const std::uint8_t group = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
        const std::uint8_t rm = static_cast<std::uint8_t>(modrm & 0x07u);
        if (group != 0u) {
            return;
        }
        const KnownWord value = make_known(read_instruction_u16(instruction, instruction.bytes.size() - 2u));
        if (mod == 0x03u) {
            register_ref(state, *decode_register16(rm)) = value;
        } else {
            const KnownWord segment = instruction_memory_segment_values(state, instruction, mod, rm);
            const KnownWord offsets = resolve_modrm_memory_offset_values(state, instruction, prefix_length, mod, rm);
            write_memory_word_to_candidates(direct_memory_overrides, segment, offsets, value);
            if (mod == 0x00u && rm == 0x06u) {
                const std::uint16_t offset = read_instruction_u16(instruction, prefix_length + 2u);
                write_direct_offset_word(state, offset, value);
                refresh_far_pointer_slot(state, image, far_pointer_slot_base(offset));
            }
        }
        return;
    }
    case 0xCDu:
        invalidate_all_registers(state);
        return;
    case 0xE8u:
    case 0x9Au:
        invalidate_all_registers(state);
        return;
    case 0xFFu: {
        const std::uint8_t modrm = read_modrm(prefix_length + 1u);
        const std::uint8_t mod = static_cast<std::uint8_t>((modrm >> 6u) & 0x03u);
        const std::uint8_t group = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
        const std::uint8_t rm = static_cast<std::uint8_t>(modrm & 0x07u);
        if (group == 6u) {
            if (mod == 0x03u) {
                set_unknown(register_ref(state, *decode_register16(rm)));
            } else if (mod == 0x00u && rm == 0x06u) {
                const std::uint16_t offset = read_instruction_u16(instruction, prefix_length + 2u);
                const KnownWord segment = resolve_direct_segment_values(state, instruction, instruction.text.substr(5u));
                if (is_known(segment)) {
                    write_direct_memory_word(direct_memory_overrides, segment, offset, make_known(0u));
                }
                write_direct_offset_word(state, offset, make_known(0u));
                refresh_far_pointer_slot(state, image, far_pointer_slot_base(offset));
            }
            return;
        }
        if (group == 2u || group == 3u) {
            invalidate_all_registers(state);
            return;
        }
        return;
    }
    default:
        return;
    }
}

std::optional<std::uint16_t> discover_cs_table_base_before_register_jump(const BlockRecord& block,
                                                                         const std::size_t site_instruction_index,
                                                                         const Register16Id target_register,
                                                                         const CodeLocation owner_root) {
    if (site_instruction_index == 0u) {
        return std::nullopt;
    }

    const DecodedInstruction& load = block.preview.instructions[site_instruction_index - 1u];
    const std::size_t prefix_length = strip_prefix_bytes(load);
    if (prefix_length + 1u >= load.bytes.size()) {
        return std::nullopt;
    }
    if (load.bytes[prefix_length] != 0x8Bu || !instruction_has_prefix(load, 0x2Eu)) {
        return std::nullopt;
    }

    const std::uint8_t modrm = load.bytes[prefix_length + 1u];
    const std::uint8_t mod = static_cast<std::uint8_t>((modrm >> 6u) & 0x03u);
    const std::uint8_t reg = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
    const std::uint8_t rm = static_cast<std::uint8_t>(modrm & 0x07u);
    const std::optional<Register16Id> load_target = decode_register16(reg);
    if (!load_target.has_value() || *load_target != target_register || mod != 0x00u) {
        return std::nullopt;
    }

    std::optional<Register16Id> address_register;
    switch (rm) {
    case 0x04u: address_register = Register16Id::SI; break;
    case 0x05u: address_register = Register16Id::DI; break;
    case 0x07u: address_register = Register16Id::BX; break;
    default: return std::nullopt;
    }

    for (std::size_t i = site_instruction_index - 1u; i-- > 0u;) {
        const DecodedInstruction& instruction = block.preview.instructions[i];
        const std::size_t op_prefix_length = strip_prefix_bytes(instruction);
        if (op_prefix_length >= instruction.bytes.size()) {
            continue;
        }
        const std::uint8_t opcode = instruction.bytes[op_prefix_length];
        if (opcode < 0xB8u || opcode > 0xBFu) {
            continue;
        }
        const std::optional<Register16Id> move_target =
            decode_register16(static_cast<std::uint8_t>(opcode - 0xB8u));
        if (!move_target.has_value() || *move_target != *address_register) {
            continue;
        }
        const std::uint16_t base = read_instruction_u16(instruction, op_prefix_length + 1u);
        if (instruction.cs != owner_root.cs || base >= owner_root.ip) {
            return std::nullopt;
        }
        return base;
    }

    return std::nullopt;
}

std::optional<std::uint16_t> discover_recent_table_base_before_indirect_site(const CfgSnapshot& snapshot,
                                                                             const CodeLocation site_location,
                                                                             const Register16Id base_register) {
    const BlockRecord* site_block = nullptr;
    std::size_t site_instruction_index = 0u;
    for (const BlockRecord& block : snapshot.blocks) {
        if (block.start.cs != site_location.cs) {
            continue;
        }
        for (std::size_t instruction_index = 0u; instruction_index < block.preview.instructions.size(); ++instruction_index) {
            if (block.preview.instructions[instruction_index].ip == site_location.ip) {
                site_block = &block;
                site_instruction_index = instruction_index;
                break;
            }
        }
        if (site_block != nullptr) {
            break;
        }
    }

    if (site_block == nullptr || site_instruction_index == 0u) {
        return std::nullopt;
    }

    std::optional<std::uint16_t> table_base;
    std::optional<std::uint16_t> table_base_source_ip;
    for (std::size_t i = 0u; i < site_instruction_index; ++i) {
        const DecodedInstruction& instruction = site_block->preview.instructions[i];
        std::optional<std::uint16_t> candidate_base =
            parse_mov_imm16(instruction.text, register16_name(static_cast<std::uint8_t>(base_register)));
        if (!candidate_base.has_value()) {
            candidate_base = decode_immediate_add_to_register(instruction, base_register);
        }
        if (!candidate_base.has_value()) {
            continue;
        }
        if (!table_base.has_value() || !table_base_source_ip.has_value() || instruction.ip > *table_base_source_ip) {
            table_base = *candidate_base;
            table_base_source_ip = instruction.ip;
        }
    }

    if (table_base.has_value()) {
        return table_base;
    }

    for (const BlockRecord& block : snapshot.blocks) {
        if (block.start.cs != site_location.cs) {
            continue;
        }
        for (const DecodedInstruction& instruction : block.preview.instructions) {
            std::optional<std::uint16_t> candidate_base =
                parse_mov_imm16(instruction.text, register16_name(static_cast<std::uint8_t>(base_register)));
            if (!candidate_base.has_value()) {
                candidate_base = decode_immediate_add_to_register(instruction, base_register);
            }
            if (!candidate_base.has_value() || instruction.ip >= site_location.ip) {
                continue;
            }
            if (static_cast<std::uint16_t>(site_location.ip - instruction.ip) > 0x0080u) {
                continue;
            }
            if (!table_base.has_value() || !table_base_source_ip.has_value() || instruction.ip > *table_base_source_ip) {
                table_base = *candidate_base;
                table_base_source_ip = instruction.ip;
            }
        }
    }

    return table_base;
}

std::optional<std::uint16_t> discover_recent_table_base_before_register_chain(
    const BlockRecord& block,
    const std::optional<CodeLocation> stop_before,
    Register16Id& tracked_register) {
    std::size_t end_index = block.preview.instructions.size();
    if (stop_before.has_value()) {
        for (std::size_t i = 0u; i < block.preview.instructions.size(); ++i) {
            const DecodedInstruction& instruction = block.preview.instructions[i];
            if (logical_key(CodeLocation{instruction.cs, instruction.ip}) == logical_key(*stop_before)) {
                end_index = i;
                break;
            }
        }
    }

    for (std::size_t i = end_index; i > 0u; --i) {
        const DecodedInstruction& instruction = block.preview.instructions[i - 1u];
        if (instruction.bytes.empty()) {
            continue;
        }

        const std::size_t prefix_length = strip_prefix_bytes(instruction);
        if (prefix_length >= instruction.bytes.size()) {
            continue;
        }

        if (const std::optional<std::uint16_t> immediate =
                parse_mov_imm16(instruction.text,
                                register16_name(static_cast<std::uint8_t>(tracked_register)));
            immediate.has_value()) {
            return immediate;
        }
        if (const std::optional<std::uint16_t> immediate_add =
                decode_immediate_add_to_register(instruction, tracked_register);
            immediate_add.has_value()) {
            return immediate_add;
        }

        const std::uint8_t opcode = instruction.bytes[prefix_length];
        if ((opcode == 0x8Bu || opcode == 0x89u || opcode == 0x87u || opcode == 0x03u || opcode == 0x01u) &&
            prefix_length + 1u < instruction.bytes.size()) {
            const std::uint8_t modrm = instruction.bytes[prefix_length + 1u];
            const std::uint8_t mod = static_cast<std::uint8_t>((modrm >> 6u) & 0x03u);
            const std::uint8_t reg = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
            const std::uint8_t rm = static_cast<std::uint8_t>(modrm & 0x07u);
            const auto reg_id = decode_register16(reg);
            const auto rm_id = decode_register16(rm);
            if (!reg_id.has_value() || !rm_id.has_value()) {
                continue;
            }

            if (opcode == 0x8Bu && mod == 0x03u && *reg_id == tracked_register) {
                tracked_register = *rm_id;
                continue;
            }
            if (opcode == 0x89u && mod == 0x03u && *rm_id == tracked_register) {
                tracked_register = *reg_id;
                continue;
            }
            if (opcode == 0x87u && mod == 0x03u) {
                if (*reg_id == tracked_register) {
                    tracked_register = *rm_id;
                    continue;
                }
                if (*rm_id == tracked_register) {
                    tracked_register = *reg_id;
                    continue;
                }
            }
            if ((opcode == 0x03u && mod == 0x03u && *reg_id == tracked_register) ||
                (opcode == 0x01u && mod == 0x03u && *rm_id == tracked_register)) {
                continue;
            }
            if ((opcode == 0x8Bu && *reg_id == tracked_register) ||
                (opcode == 0x89u && mod == 0x03u && *rm_id == tracked_register) ||
                (opcode == 0x03u && mod == 0x03u && *reg_id == tracked_register) ||
                (opcode == 0x01u && mod == 0x03u && *rm_id == tracked_register) ||
                (opcode == 0x87u && mod == 0x03u &&
                 (*reg_id == tracked_register || *rm_id == tracked_register))) {
                return std::nullopt;
            }
        }

        if (opcode >= 0x58u && opcode <= 0x5Fu) {
            const auto dest = decode_register16(static_cast<std::uint8_t>(opcode - 0x58u));
            if (dest.has_value() && *dest == tracked_register) {
                return std::nullopt;
            }
        }
        if ((opcode & 0xF8u) == 0x90u && (opcode & 0x07u) != 0u) {
            const auto other = decode_register16(static_cast<std::uint8_t>(opcode & 0x07u));
            if (tracked_register == Register16Id::AX && other.has_value()) {
                tracked_register = *other;
                continue;
            }
            if (other.has_value() && *other == tracked_register) {
                tracked_register = Register16Id::AX;
                continue;
            }
        }
    }

    return std::nullopt;
}

std::optional<CodeLocation> find_transfer_instruction_to_block(const BlockRecord& predecessor_block,
                                                               const CodeLocation target_block_start) {
    for (const DecodedInstruction& instruction : predecessor_block.preview.instructions) {
        if (instruction.branch_target_ip.has_value()) {
            const CodeLocation target{
                instruction.branch_target_cs.value_or(instruction.cs),
                *instruction.branch_target_ip,
            };
            if (logical_key(target) == logical_key(target_block_start)) {
                return CodeLocation{instruction.cs, instruction.ip};
            }
        }
        if (instruction.branch_fallthrough_ip.has_value()) {
            const CodeLocation target{instruction.cs, *instruction.branch_fallthrough_ip};
            if (logical_key(target) == logical_key(target_block_start)) {
                return CodeLocation{instruction.cs, instruction.ip};
            }
        }
    }
    return std::nullopt;
}

std::optional<std::uint16_t> discover_recent_table_base_via_predecessor_chain_impl(
    const CfgSnapshot& snapshot,
    const std::map<std::uint64_t, std::map<std::uint32_t, AbstractState>>& entry_states,
    const std::uint64_t owner_state_key,
    const std::uint32_t start_block_key,
    const std::optional<CodeLocation> stop_before,
    const std::uint32_t predecessor_key,
    Register16Id tracked_register) {
    std::map<std::uint32_t, const BlockRecord*> blocks_by_key;
    for (const BlockRecord& block : snapshot.blocks) {
        blocks_by_key[logical_key(block.start)] = &block;
    }

    std::set<std::uint32_t> visited;
    std::uint32_t current_block_key = start_block_key;
    std::uint32_t current_predecessor_key = predecessor_key;
    std::optional<CodeLocation> current_stop_before = stop_before;

    while (visited.insert(current_block_key).second) {
        const auto block_it = blocks_by_key.find(current_block_key);
        if (block_it == blocks_by_key.end()) {
            break;
        }

        if (const std::optional<std::uint16_t> table_base =
                discover_recent_table_base_before_register_chain(*block_it->second,
                                                                 current_stop_before,
                                                                 tracked_register);
            table_base.has_value()) {
            return table_base;
        }

        if (current_predecessor_key == current_block_key) {
            break;
        }

        const CodeLocation current_block_start = block_it->second->start;
        current_block_key = current_predecessor_key;
        const auto predecessor_block_it = blocks_by_key.find(current_block_key);
        current_stop_before =
            predecessor_block_it != blocks_by_key.end()
                ? find_transfer_instruction_to_block(*predecessor_block_it->second, current_block_start)
                : std::nullopt;

        const auto state_it = entry_states.find(
            analysis_state_key(analysis_owner_root_from_key(owner_state_key), current_block_key));
        if (state_it == entry_states.end() || state_it->second.size() != 1u) {
            break;
        }

        const std::uint32_t next_predecessor_key = state_it->second.begin()->first;
        if (next_predecessor_key == current_block_key) {
            break;
        }
        current_predecessor_key = next_predecessor_key;
    }

    return std::nullopt;
}

std::optional<CurrentCsIndexedLoadInfo> discover_current_cs_indexed_load_via_predecessor_chain_impl(
    const CfgSnapshot& snapshot,
    const std::map<std::uint64_t, std::map<std::uint32_t, AbstractState>>& entry_states,
    const std::uint64_t owner_state_key,
    const std::uint32_t start_block_key,
    const std::optional<CodeLocation> stop_before,
    const std::uint32_t predecessor_key,
    const Register16Id target_register) {
    std::map<std::uint32_t, const BlockRecord*> blocks_by_key;
    for (const BlockRecord& block : snapshot.blocks) {
        blocks_by_key[logical_key(block.start)] = &block;
    }

    std::set<std::uint32_t> visited;
    std::uint32_t current_block_key = start_block_key;
    std::uint32_t current_predecessor_key = predecessor_key;
    std::optional<CodeLocation> current_stop_before = stop_before;

    while (visited.insert(current_block_key).second) {
        const auto block_it = blocks_by_key.find(current_block_key);
        if (block_it == blocks_by_key.end()) {
            break;
        }

        std::size_t end_index = block_it->second->preview.instructions.size();
        if (current_stop_before.has_value()) {
            for (std::size_t i = 0u; i < block_it->second->preview.instructions.size(); ++i) {
                const DecodedInstruction& instruction = block_it->second->preview.instructions[i];
                if (logical_key(CodeLocation{instruction.cs, instruction.ip}) == logical_key(*current_stop_before)) {
                    end_index = i;
                    break;
                }
            }
        }

        for (std::size_t i = end_index; i > 0u; --i) {
            const DecodedInstruction& instruction = block_it->second->preview.instructions[i - 1u];
            if (instruction.bytes.empty()) {
                continue;
            }

            const std::size_t prefix_length = strip_prefix_bytes(instruction);
            if (prefix_length >= instruction.bytes.size()) {
                continue;
            }

            const std::uint8_t opcode = instruction.bytes[prefix_length];
            if (opcode != 0x8Bu || prefix_length + 1u >= instruction.bytes.size()) {
                continue;
            }

            const std::uint8_t modrm = instruction.bytes[prefix_length + 1u];
            const auto dest = decode_register16(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
            if (!dest.has_value() || *dest != target_register) {
                continue;
            }

            const auto source_operand = mov_source_operand_text(instruction);
            if (!source_operand.has_value()) {
                continue;
            }
            const auto indexed = parse_indexed_memory_operand_text(*source_operand);
            if (!indexed.has_value() || !indexed->uses_current_cs) {
                continue;
            }

            return CurrentCsIndexedLoadInfo{
                indexed->base_register,
                indexed->displacement,
                CodeLocation{instruction.cs, instruction.ip},
                current_block_key,
                current_predecessor_key,
            };
        }

        if (current_predecessor_key == current_block_key) {
            break;
        }

        const CodeLocation current_block_start = block_it->second->start;
        current_block_key = current_predecessor_key;
        const auto predecessor_block_it = blocks_by_key.find(current_block_key);
        current_stop_before =
            predecessor_block_it != blocks_by_key.end()
                ? find_transfer_instruction_to_block(*predecessor_block_it->second, current_block_start)
                : std::nullopt;

        const auto state_it = entry_states.find(
            analysis_state_key(analysis_owner_root_from_key(owner_state_key), current_block_key));
        if (state_it == entry_states.end() || state_it->second.size() != 1u) {
            break;
        }

        const std::uint32_t next_predecessor_key = state_it->second.begin()->first;
        if (next_predecessor_key == current_block_key) {
            break;
        }
        current_predecessor_key = next_predecessor_key;
    }

    return std::nullopt;
}

bool uses_recent_current_cs_pair_table_layout_before_location(const BlockRecord& block,
                                                              const std::optional<CodeLocation> stop_before,
                                                              const Register16Id base_register) {
    std::size_t end_index = block.preview.instructions.size();
    if (stop_before.has_value()) {
        for (std::size_t i = 0u; i < block.preview.instructions.size(); ++i) {
            const DecodedInstruction& instruction = block.preview.instructions[i];
            if (logical_key(CodeLocation{instruction.cs, instruction.ip}) == logical_key(*stop_before)) {
                end_index = i;
                break;
            }
        }
    }

    if (end_index == 0u) {
        return false;
    }

    for (std::size_t i = 0u; i < end_index; ++i) {
        const DecodedInstruction& instruction = block.preview.instructions[i];
        const auto source_operand = mov_source_operand_text(instruction);
        if (!source_operand.has_value()) {
            continue;
        }
        const auto indexed = parse_indexed_memory_operand_text(*source_operand);
        if (!indexed.has_value() ||
            !indexed->uses_current_cs ||
            indexed->base_register != base_register ||
            indexed->displacement != -2) {
            continue;
        }
        return true;
    }

    return false;
}

bool uses_recent_current_cs_pair_table_layout(const CfgSnapshot& snapshot,
                                              const CodeLocation site_location,
                                              const Register16Id base_register) {
    for (const BlockRecord& block : snapshot.blocks) {
        if (block.start.cs != site_location.cs) {
            continue;
        }
        for (const DecodedInstruction& instruction : block.preview.instructions) {
            if (instruction.ip == site_location.ip) {
                return uses_recent_current_cs_pair_table_layout_before_location(
                    block,
                    site_location,
                    base_register);
            }
        }
    }
    return false;
}

bool uses_recent_current_cs_pair_table_layout_via_predecessor_chain_impl(
    const CfgSnapshot& snapshot,
    const std::map<std::uint64_t, std::map<std::uint32_t, AbstractState>>& entry_states,
    const std::uint64_t owner_state_key,
    const std::uint32_t start_block_key,
    const CodeLocation source_location,
    const std::uint32_t predecessor_key,
    const Register16Id base_register) {
    std::map<std::uint32_t, const BlockRecord*> blocks_by_key;
    for (const BlockRecord& block : snapshot.blocks) {
        blocks_by_key[logical_key(block.start)] = &block;
    }

    std::set<std::uint32_t> visited;
    std::uint32_t current_block_key = start_block_key;
    std::uint32_t current_predecessor_key = predecessor_key;
    std::optional<CodeLocation> current_stop_before = source_location;

    while (visited.insert(current_block_key).second) {
        const auto block_it = blocks_by_key.find(current_block_key);
        if (block_it == blocks_by_key.end()) {
            break;
        }
        if (uses_recent_current_cs_pair_table_layout_before_location(
                *block_it->second,
                current_stop_before,
                base_register)) {
            return true;
        }

        if (current_predecessor_key == current_block_key) {
            break;
        }

        const CodeLocation current_block_start = block_it->second->start;
        current_block_key = current_predecessor_key;
        const auto predecessor_block_it = blocks_by_key.find(current_block_key);
        current_stop_before =
            predecessor_block_it != blocks_by_key.end()
                ? find_transfer_instruction_to_block(*predecessor_block_it->second, current_block_start)
                : std::nullopt;

        const auto state_it = entry_states.find(
            analysis_state_key(analysis_owner_root_from_key(owner_state_key), current_block_key));
        if (state_it == entry_states.end() || state_it->second.size() != 1u) {
            break;
        }

        const std::uint32_t next_predecessor_key = state_it->second.begin()->first;
        if (next_predecessor_key == current_block_key) {
            break;
        }
        current_predecessor_key = next_predecessor_key;
    }

    return false;
}

bool append_near_jump_table_targets(const MzImage& image,
                                    const CodeLocation owner_root,
                                    const std::uint16_t table_base,
                                    std::vector<CodeLocation>& out_targets) {
    bool changed = false;
    for (std::uint16_t offset = table_base; offset + 1u < owner_root.ip; offset = static_cast<std::uint16_t>(offset + 2u)) {
        const CodeLocation target{owner_root.cs, read_memory_u16(image, owner_root.cs, offset)};
        if (!is_plausible_code_target(image, target)) {
            continue;
        }
        const std::uint32_t target_key = logical_key(target);
        const auto existing = std::find_if(out_targets.begin(),
                                           out_targets.end(),
                                           [&](const CodeLocation& candidate) {
                                               return logical_key(candidate) == target_key;
                                           });
        if (existing == out_targets.end()) {
            out_targets.push_back(target);
            changed = true;
        }
    }
    return changed;
}

std::vector<IndirectDispatchEntry> collect_current_cs_pair_table_entries_from_base(const MzImage& image,
                                                                                   const CfgSnapshot& snapshot,
                                                                                   const CodeLocation site_location,
                                                                                   const std::uint16_t table_base) {
    std::optional<std::uint16_t> table_limit;
    for (const BlockRecord& block : snapshot.blocks) {
        if (block.start.cs != site_location.cs || block.start.ip <= table_base) {
            continue;
        }
        if (!table_limit.has_value() || block.start.ip < *table_limit) {
            table_limit = block.start.ip;
        }
    }
    if (!table_limit.has_value() || *table_limit <= static_cast<std::uint16_t>(table_base + 2u)) {
        return {};
    }

    std::vector<IndirectDispatchEntry> entries;
    for (std::uint16_t offset = table_base;
         static_cast<std::uint32_t>(offset) + 3u < *table_limit;
         offset = static_cast<std::uint16_t>(offset + 4u)) {
        const std::uint16_t selector = read_memory_u16(image, site_location.cs, offset);
        const CodeLocation target{
            site_location.cs,
            read_memory_u16(image, site_location.cs, static_cast<std::uint16_t>(offset + 2u))};
        entries.push_back(IndirectDispatchEntry{
            selector,
            target,
            is_plausible_code_target(image, target),
        });
    }

    return entries;
}

bool append_unique_dispatch_targets(const std::vector<IndirectDispatchEntry>& entries,
                                    std::vector<CodeLocation>& out_targets) {
    bool changed = false;
    for (const IndirectDispatchEntry& entry : entries) {
        if (!entry.target_is_valid) {
            continue;
        }
        const std::uint32_t target_key = logical_key(entry.target);
        const auto existing = std::find_if(out_targets.begin(),
                                           out_targets.end(),
                                           [&](const CodeLocation& candidate) {
                                               return logical_key(candidate) == target_key;
                                           });
        if (existing == out_targets.end()) {
            out_targets.push_back(entry.target);
            changed = true;
        }
    }
    return changed;
}

void assign_dispatch_metadata(IndirectSiteRecord& site,
                              const IndirectDispatchKind kind,
                              const std::uint16_t table_base,
                              const std::uint16_t runtime_index_base,
                              const std::uint16_t entry_stride,
                              const std::optional<std::uint8_t> index_register,
                              const std::vector<IndirectDispatchEntry>& entries) {
    if (entries.empty()) {
        return;
    }
    if (site.dispatch_kind == IndirectDispatchKind::CurrentCsPairTable &&
        kind == IndirectDispatchKind::CurrentCsWordTable) {
        return;
    }
    const bool prefer_pair_over_word =
        kind == IndirectDispatchKind::CurrentCsPairTable &&
        site.dispatch_kind == IndirectDispatchKind::CurrentCsWordTable;
    if (site.dispatch_entries.empty() || entries.size() > site.dispatch_entries.size() || prefer_pair_over_word) {
        site.dispatch_kind = kind;
        site.dispatch_table_base = table_base;
        site.dispatch_runtime_index_base = runtime_index_base;
        site.dispatch_entry_stride = entry_stride;
        site.dispatch_index_register = index_register;
        site.dispatch_entries = entries;
    }
}

bool append_current_cs_pair_table_targets_from_base(const MzImage& image,
                                                    const CfgSnapshot& snapshot,
                                                    const CodeLocation site_location,
                                                    const std::uint16_t table_base,
                                                    std::vector<CodeLocation>& out_targets,
                                                    IndirectSiteRecord* site_metadata,
                                                    const std::optional<std::uint8_t> index_register) {
    const std::vector<IndirectDispatchEntry> entries =
        collect_current_cs_pair_table_entries_from_base(image, snapshot, site_location, table_base);
    if (site_metadata != nullptr) {
        assign_dispatch_metadata(*site_metadata,
                                 IndirectDispatchKind::CurrentCsPairTable,
                                 table_base,
                                 static_cast<std::uint16_t>(table_base + 2u),
                                 4u,
                                 index_register,
                                 entries);
    }
    return append_unique_dispatch_targets(entries, out_targets);
}

bool append_current_cs_pair_table_targets(const MzImage& image,
                                          const CfgSnapshot& snapshot,
                                          const CodeLocation site_location,
                                          const Register16Id base_register,
                                          std::vector<CodeLocation>& out_targets,
                                          IndirectSiteRecord* site_metadata) {
    const std::optional<std::uint16_t> table_base =
        discover_recent_table_base_before_indirect_site(snapshot, site_location, base_register);
    if (!table_base.has_value()) {
        return false;
    }

    return append_current_cs_pair_table_targets_from_base(
        image,
        snapshot,
        site_location,
        *table_base,
        out_targets,
        site_metadata,
        static_cast<std::uint8_t>(base_register));
}

std::vector<IndirectDispatchEntry> collect_current_cs_word_table_entries_from_base(const MzImage& image,
                                                                                   const CfgSnapshot& snapshot,
                                                                                   const CodeLocation site_location,
                                                                                   const std::uint16_t table_base) {
    std::optional<std::uint16_t> table_limit;
    for (const BlockRecord& block : snapshot.blocks) {
        if (block.start.cs != site_location.cs || block.start.ip <= table_base) {
            continue;
        }
        if (!table_limit.has_value() || block.start.ip < *table_limit) {
            table_limit = block.start.ip;
        }
    }
    if (!table_limit.has_value() || *table_limit <= table_base) {
        return {};
    }

    bool tightened_limit = true;
    while (tightened_limit) {
        tightened_limit = false;
        for (std::uint16_t offset = table_base;
             static_cast<std::uint32_t>(offset) + 1u < *table_limit;
             offset = static_cast<std::uint16_t>(offset + 2u)) {
            const CodeLocation target{site_location.cs, read_memory_u16(image, site_location.cs, offset)};
            if (!is_plausible_code_target(image, target)) {
                continue;
            }
            if (target.ip <= table_base || target.ip >= *table_limit) {
                continue;
            }
            table_limit = target.ip;
            tightened_limit = true;
            break;
        }
    }

    std::vector<IndirectDispatchEntry> entries;
    for (std::uint16_t offset = table_base;
         static_cast<std::uint32_t>(offset) + 1u < *table_limit;
         offset = static_cast<std::uint16_t>(offset + 2u)) {
        const CodeLocation target{site_location.cs, read_memory_u16(image, site_location.cs, offset)};
        entries.push_back(IndirectDispatchEntry{
            offset,
            target,
            is_plausible_code_target(image, target),
        });
    }
    return entries;
}

std::vector<IndirectDispatchEntry> collect_current_cs_word_table_entries_from_runtime_offsets(
    const MzImage& image,
    const CodeLocation site_location,
    const KnownWord& runtime_offsets) {
    if (!is_known(runtime_offsets)) {
        return {};
    }

    std::vector<IndirectDispatchEntry> entries;
    std::set<std::uint16_t> seen_offsets;
    for (const std::uint16_t offset : runtime_offsets.values) {
        if (!seen_offsets.insert(offset).second) {
            continue;
        }
        const CodeLocation target{site_location.cs, read_memory_u16(image, site_location.cs, offset)};
        entries.push_back(IndirectDispatchEntry{
            offset,
            target,
            is_plausible_code_target(image, target),
        });
    }

    std::sort(entries.begin(),
              entries.end(),
              [](const IndirectDispatchEntry& left, const IndirectDispatchEntry& right) {
                  return left.selector < right.selector;
              });
    return entries;
}

std::optional<std::pair<std::uint16_t, std::vector<IndirectDispatchEntry>>>
collect_interleaved_pair_entries_from_word_table(const std::uint16_t table_base,
                                                 const std::vector<IndirectDispatchEntry>& word_entries,
                                                 const std::vector<CodeLocation>& resolved_targets) {
    if (word_entries.size() < 4u) {
        return std::nullopt;
    }

    std::set<std::uint32_t> resolved_target_keys;
    for (const CodeLocation target : resolved_targets) {
        resolved_target_keys.insert(logical_key(target));
    }
    if (resolved_target_keys.size() < 3u) {
        return std::nullopt;
    }

    for (std::uint16_t target_parity = 0u; target_parity < 2u; ++target_parity) {
        const std::uint16_t selector_parity = static_cast<std::uint16_t>(target_parity ^ 1u);
        std::size_t matched_targets = 0u;
        std::size_t matched_selectors = 0u;
        std::vector<IndirectDispatchEntry> entries;
        for (std::size_t pair_index = 0u; pair_index + 1u < word_entries.size(); pair_index += 2u) {
            const std::size_t first_index = pair_index;
            const std::size_t second_index = pair_index + 1u;
            const std::size_t selector_index = selector_parity == 0u ? first_index : second_index;
            const std::size_t target_index = target_parity == 0u ? first_index : second_index;
            const IndirectDispatchEntry& selector_entry = word_entries[selector_index];
            const IndirectDispatchEntry& target_entry = word_entries[target_index];
            if (resolved_target_keys.contains(logical_key(target_entry.target))) {
                ++matched_targets;
            }
            if (resolved_target_keys.contains(logical_key(selector_entry.target))) {
                ++matched_selectors;
            }
            entries.push_back(IndirectDispatchEntry{
                selector_entry.target.ip,
                target_entry.target,
                target_entry.target_is_valid,
            });
        }

        if (matched_targets < 3u || matched_targets <= matched_selectors) {
            continue;
        }

        const std::uint16_t runtime_index_base =
            static_cast<std::uint16_t>(table_base + (target_parity == 0u ? 0u : 2u));
        return std::make_pair(runtime_index_base, std::move(entries));
    }

    return std::nullopt;
}

std::optional<std::pair<std::uint16_t, std::vector<IndirectDispatchEntry>>>
collect_selector_target_pair_entries_from_word_table(const std::uint16_t table_base,
                                                     const std::vector<IndirectDispatchEntry>& word_entries,
                                                     const std::vector<CodeLocation>& resolved_targets) {
    if (word_entries.size() < 4u) {
        return std::nullopt;
    }

    std::set<std::uint32_t> resolved_target_keys;
    for (const CodeLocation target : resolved_targets) {
        resolved_target_keys.insert(logical_key(target));
    }
    if (resolved_target_keys.size() < 3u) {
        return std::nullopt;
    }

    for (std::uint16_t target_parity = 0u; target_parity < 2u; ++target_parity) {
        const std::uint16_t selector_parity = static_cast<std::uint16_t>(target_parity ^ 1u);
        std::size_t matched_targets = 0u;
        std::size_t matched_selectors = 0u;
        std::size_t invalid_targets = 0u;
        std::vector<IndirectDispatchEntry> entries;
        for (std::size_t pair_index = 0u; pair_index + 1u < word_entries.size(); pair_index += 2u) {
            const std::size_t first_index = pair_index;
            const std::size_t second_index = pair_index + 1u;
            const std::size_t selector_index = selector_parity == 0u ? first_index : second_index;
            const std::size_t target_index = target_parity == 0u ? first_index : second_index;
            const IndirectDispatchEntry& selector_entry = word_entries[selector_index];
            const IndirectDispatchEntry& target_entry = word_entries[target_index];
            if (!target_entry.target_is_valid) {
                ++invalid_targets;
                continue;
            }
            if (resolved_target_keys.contains(logical_key(target_entry.target))) {
                ++matched_targets;
            }
            if (resolved_target_keys.contains(logical_key(selector_entry.target))) {
                ++matched_selectors;
            }
            entries.push_back(IndirectDispatchEntry{
                selector_entry.target.ip,
                target_entry.target,
                true,
            });
        }

        if (entries.size() < 3u || invalid_targets != 0u || matched_targets < 3u || matched_targets <= matched_selectors) {
            continue;
        }

        const std::uint16_t runtime_index_base =
            static_cast<std::uint16_t>(table_base + 2u + (target_parity * 2u));
        return std::make_pair(runtime_index_base, std::move(entries));
    }

    return std::nullopt;
}

bool append_current_cs_word_table_targets_from_base(const MzImage& image,
                                                    const CfgSnapshot& snapshot,
                                                    const CodeLocation site_location,
                                                    const std::uint16_t table_base,
                                                    std::vector<CodeLocation>& out_targets,
                                                    IndirectSiteRecord* site_metadata,
                                                    const std::optional<std::uint8_t> index_register) {
    const std::vector<IndirectDispatchEntry> entries =
        collect_current_cs_word_table_entries_from_base(image, snapshot, site_location, table_base);
    if (site_metadata != nullptr) {
        if (const auto selector_target_pairs =
                collect_selector_target_pair_entries_from_word_table(table_base, entries, out_targets);
            selector_target_pairs.has_value()) {
            assign_dispatch_metadata(*site_metadata,
                                     IndirectDispatchKind::CurrentCsPairTable,
                                     table_base,
                                     selector_target_pairs->first,
                                     4u,
                                     index_register,
                                     selector_target_pairs->second);
        }
        if (const auto pair_entries =
                collect_interleaved_pair_entries_from_word_table(table_base, entries, out_targets);
            pair_entries.has_value()) {
            assign_dispatch_metadata(*site_metadata,
                                     IndirectDispatchKind::CurrentCsPairTable,
                                     table_base,
                                     pair_entries->first,
                                     4u,
                                     index_register,
                                     pair_entries->second);
        }
        assign_dispatch_metadata(*site_metadata,
                                 IndirectDispatchKind::CurrentCsWordTable,
                                 table_base,
                                 table_base,
                                 2u,
                                 index_register,
                                 entries);
    }
    return append_unique_dispatch_targets(entries, out_targets);
}

bool append_current_cs_word_table_targets_from_runtime_offsets(const MzImage& image,
                                                               const CodeLocation site_location,
                                                               const std::uint16_t table_base,
                                                               const KnownWord& runtime_offsets,
                                                               std::vector<CodeLocation>& out_targets,
                                                               IndirectSiteRecord* site_metadata,
                                                               const std::optional<std::uint8_t> index_register) {
    const std::vector<IndirectDispatchEntry> entries =
        collect_current_cs_word_table_entries_from_runtime_offsets(image, site_location, runtime_offsets);
    const bool changed = append_unique_dispatch_targets(entries, out_targets);
    if (site_metadata != nullptr) {
        if (const auto selector_target_pairs =
                collect_selector_target_pair_entries_from_word_table(table_base, entries, out_targets);
            selector_target_pairs.has_value()) {
            assign_dispatch_metadata(*site_metadata,
                                     IndirectDispatchKind::CurrentCsPairTable,
                                     table_base,
                                     selector_target_pairs->first,
                                     4u,
                                     index_register,
                                     selector_target_pairs->second);
        }
        assign_dispatch_metadata(*site_metadata,
                                 IndirectDispatchKind::CurrentCsWordTable,
                                 table_base,
                                 table_base,
                                 0u,
                                 index_register,
                                 entries);
        if (const auto pair_entries =
                collect_interleaved_pair_entries_from_word_table(table_base, entries, out_targets);
            pair_entries.has_value()) {
            assign_dispatch_metadata(*site_metadata,
                                     IndirectDispatchKind::CurrentCsPairTable,
                                     table_base,
                                     pair_entries->first,
                                     4u,
                                     index_register,
                                     pair_entries->second);
        }
    }
    return changed;
}

bool append_current_cs_word_table_targets_from_known_context(const MzImage& image,
                                                             const CfgSnapshot& snapshot,
                                                             const CodeLocation site_location,
                                                             const std::optional<std::uint16_t> table_base,
                                                             const KnownWord& runtime_offsets,
                                                             std::vector<CodeLocation>& out_targets,
                                                             IndirectSiteRecord* site_metadata,
                                                             const std::optional<std::uint8_t> index_register) {
    bool changed = false;
    std::optional<std::uint16_t> inferred_table_base = table_base;
    if (!inferred_table_base.has_value() && is_known(runtime_offsets)) {
        inferred_table_base =
            *std::min_element(runtime_offsets.values.begin(), runtime_offsets.values.end());
    }
    if (is_known(runtime_offsets)) {
        changed =
            append_current_cs_word_table_targets_from_runtime_offsets(
                image,
                site_location,
                inferred_table_base.value_or(singleton_value(runtime_offsets).value_or(0u)),
                runtime_offsets,
                out_targets,
                site_metadata,
                index_register) ||
            changed;
    }
    if (inferred_table_base.has_value()) {
        changed =
            append_current_cs_word_table_targets_from_base(
                image,
                snapshot,
                site_location,
                *inferred_table_base,
                out_targets,
                site_metadata,
                index_register) ||
            changed;
    }
    return changed;
}

bool append_current_cs_word_table_targets(const MzImage& image,
                                          const CfgSnapshot& snapshot,
                                          const CodeLocation site_location,
                                          const Register16Id base_register,
                                          std::vector<CodeLocation>& out_targets,
                                          IndirectSiteRecord* site_metadata) {
    const std::optional<std::uint16_t> table_base =
        discover_recent_table_base_before_indirect_site(snapshot, site_location, base_register);
    if (!table_base.has_value()) {
        return false;
    }

    return append_current_cs_word_table_targets_from_base(
        image,
        snapshot,
        site_location,
        *table_base,
        out_targets,
        site_metadata,
        static_cast<std::uint8_t>(base_register));
}

bool append_current_cs_indexed_targets_via_block_entry_replay(
    const MzImage& image,
    const CfgSnapshot& snapshot,
    const std::map<std::uint64_t, std::map<std::uint32_t, AbstractState>>& entry_states,
    const std::uint64_t owner_state_key,
    const BlockRecord& block,
    const CodeLocation site_location,
    const CodeLocation source_location,
    std::vector<CodeLocation>& out_targets,
    IndirectSiteRecord* site_metadata) {
    const auto source_it =
        std::find_if(block.preview.instructions.begin(),
                     block.preview.instructions.end(),
                     [&](const DecodedInstruction& instruction) {
                         return logical_key(CodeLocation{instruction.cs, instruction.ip}) ==
                                logical_key(source_location);
                     });
    if (source_it == block.preview.instructions.end()) {
        return false;
    }

    const std::optional<std::string> source_operand = mov_source_operand_text(*source_it);
    if (!source_operand.has_value()) {
        return false;
    }

    const std::optional<IndexedMemoryOperandInfo> indexed =
        parse_indexed_memory_operand_text(*source_operand);
    if (!indexed.has_value() || !indexed->uses_current_cs) {
        return false;
    }

    const auto block_state_it =
        entry_states.find(analysis_state_key(analysis_owner_root_from_key(owner_state_key),
                                             logical_key(block.start)));
    if (block_state_it == entry_states.end()) {
        return false;
    }

    const bool use_pair_table =
        uses_recent_current_cs_pair_table_layout(snapshot, source_location, indexed->base_register);
    bool changed = false;

    for (const auto& [predecessor_key, entry_state] : block_state_it->second) {
        (void)predecessor_key;
        AbstractState current = entry_state;
        std::map<std::uint32_t, std::uint16_t>& direct_memory_overrides = current.direct_memory_words;
        std::vector<KnownWord> abstract_stack;

        for (const DecodedInstruction& instruction : block.preview.instructions) {
            if (logical_key(CodeLocation{instruction.cs, instruction.ip}) == logical_key(source_location)) {
                Register16Id tracked_register = indexed->base_register;
                std::optional<std::uint16_t> table_base =
                    discover_recent_table_base_before_register_chain(block,
                                                                     source_location,
                                                                     tracked_register);
                if (!table_base.has_value()) {
                    table_base = singleton_value(register_ref(entry_state, tracked_register));
                }

                if (use_pair_table) {
                    if (table_base.has_value()) {
                        changed =
                            append_current_cs_pair_table_targets_from_base(
                                image,
                                snapshot,
                                site_location,
                                *table_base,
                                out_targets,
                                site_metadata,
                                static_cast<std::uint8_t>(indexed->base_register)) ||
                            changed;
                    }
                } else {
                    const KnownWord runtime_offsets =
                        add_known_word_and_displacement(register_ref(current, indexed->base_register),
                                                        indexed->displacement);
                    changed =
                        append_current_cs_word_table_targets_from_known_context(
                            image,
                            snapshot,
                            site_location,
                            table_base,
                            runtime_offsets,
                            out_targets,
                            site_metadata,
                            static_cast<std::uint8_t>(indexed->base_register)) ||
                        changed;
                }
                break;
            }

            apply_instruction_effect(image, instruction, current, direct_memory_overrides, abstract_stack);
        }
    }

    return changed;
}

bool append_same_segment_bounded_word_table_targets(
    const MzImage& image,
    const std::uint16_t segment,
    const std::uint16_t table_base,
    const std::uint16_t entry_count,
    std::vector<CodeLocation>& out_targets,
    std::size_t* skipped_candidates) {
    bool changed = false;
    for (std::uint32_t index = 0u; index < entry_count; ++index) {
        const std::uint16_t offset =
            static_cast<std::uint16_t>(table_base + static_cast<std::uint16_t>(index * 2u));
        const CodeLocation target{segment, read_memory_u16(image, segment, offset)};
        if (!is_plausible_code_target(image, target)) {
            if (skipped_candidates != nullptr) {
                ++(*skipped_candidates);
            }
            continue;
        }
        const std::uint32_t target_key = logical_key(target);
        const auto existing = std::find_if(out_targets.begin(),
                                           out_targets.end(),
                                           [&](const CodeLocation& candidate) {
                                               return logical_key(candidate) == target_key;
                                           });
        if (existing == out_targets.end()) {
            out_targets.push_back(target);
            changed = true;
        }
    }
    if (changed) {
        sort_locations(out_targets);
    }
    return changed;
}

std::optional<std::uint16_t> discover_unsigned_upper_bound_from_predecessor_fallthrough(
    const CfgSnapshot& snapshot,
    const std::uint32_t predecessor_block_key,
    const CodeLocation target_block_start) {
    const auto predecessor_block_it = std::find_if(
        snapshot.blocks.begin(),
        snapshot.blocks.end(),
        [&](const BlockRecord& candidate) {
            return logical_key(candidate.start) == predecessor_block_key;
        });
    if (predecessor_block_it == snapshot.blocks.end() ||
        predecessor_block_it->preview.instructions.empty()) {
        return std::nullopt;
    }

    const DecodedInstruction& terminal = predecessor_block_it->preview.instructions.back();
    if (terminal.flow != FlowKind::ConditionalBranch ||
        !terminal.branch_fallthrough_ip.has_value() ||
        terminal.cs != target_block_start.cs ||
        *terminal.branch_fallthrough_ip != target_block_start.ip) {
        return std::nullopt;
    }

    if (predecessor_block_it->preview.instructions.size() < 2u) {
        return std::nullopt;
    }
    const DecodedInstruction& compare =
        predecessor_block_it->preview.instructions[predecessor_block_it->preview.instructions.size() - 2u];
    if (compare.bytes.size() < 2u) {
        return std::nullopt;
    }

    const std::size_t compare_prefix = strip_prefix_bytes(compare);
    const std::size_t terminal_prefix = strip_prefix_bytes(terminal);
    if (compare_prefix >= compare.bytes.size() || terminal_prefix >= terminal.bytes.size()) {
        return std::nullopt;
    }

    const std::uint8_t compare_opcode = compare.bytes[compare_prefix];
    const std::uint8_t branch_opcode = terminal.bytes[terminal_prefix];
    if (compare_opcode == 0x3Cu && branch_opcode == 0x73u && compare_prefix + 1u < compare.bytes.size()) {
        return static_cast<std::uint16_t>(compare.bytes[compare_prefix + 1u]);
    }
    if (compare_opcode == 0x3Du && branch_opcode == 0x73u && compare_prefix + 2u < compare.bytes.size()) {
        return read_instruction_u16(compare, compare_prefix + 1u);
    }

    return std::nullopt;
}

std::optional<std::uint16_t> discover_unsigned_upper_bound_for_block(const CfgSnapshot& snapshot,
                                                                     const CodeLocation target_block_start) {
    std::optional<std::uint16_t> best_bound;

    for (const CfgEdge& edge : snapshot.edges) {
        if (edge.kind != EdgeKind::Fallthrough ||
            edge.to.cs != target_block_start.cs ||
            edge.to.ip != target_block_start.ip) {
            continue;
        }

        std::optional<std::uint32_t> predecessor_block_key;
        for (const BlockRecord& block : snapshot.blocks) {
            const bool contains_source = std::any_of(
                block.preview.instructions.begin(),
                block.preview.instructions.end(),
                [&](const DecodedInstruction& instruction) {
                    return instruction.cs == edge.from.cs && instruction.ip == edge.from.ip;
                });
            if (contains_source) {
                predecessor_block_key = logical_key(block.start);
                break;
            }
        }
        if (!predecessor_block_key.has_value()) {
            continue;
        }

        const std::optional<std::uint16_t> candidate =
            discover_unsigned_upper_bound_from_predecessor_fallthrough(
                snapshot,
                *predecessor_block_key,
                target_block_start);
        if (!candidate.has_value()) {
            continue;
        }

        if (!best_bound.has_value() || *candidate < *best_bound) {
            best_bound = candidate;
        }
    }

    return best_bound;
}

bool append_current_cs_structured_table_targets(const MzImage& image,
                                                const CfgSnapshot& snapshot,
                                                const CodeLocation site_location,
                                                const Register16Id base_register,
                                                const bool use_pair_table,
                                                std::vector<CodeLocation>& out_targets,
                                                IndirectSiteRecord* site_metadata,
                                                const std::optional<std::uint16_t> table_base_override) {
    if (use_pair_table) {
        return table_base_override.has_value()
                   ? append_current_cs_pair_table_targets_from_base(image,
                                                                    snapshot,
                                                                    site_location,
                                                                    *table_base_override,
                                                                    out_targets,
                                                                    site_metadata,
                                                                    static_cast<std::uint8_t>(base_register))
                   : append_current_cs_pair_table_targets(
                         image, snapshot, site_location, base_register, out_targets, site_metadata);
    }

    return table_base_override.has_value()
               ? append_current_cs_word_table_targets_from_base(image,
                                                                snapshot,
                                                                site_location,
                                                                *table_base_override,
                                                                out_targets,
                                                                site_metadata,
                                                                static_cast<std::uint8_t>(base_register))
               : append_current_cs_word_table_targets(
                     image, snapshot, site_location, base_register, out_targets, site_metadata);
}

void enqueue_if_new(std::deque<CodeLocation>& worklist,
                    std::set<std::uint32_t>& enqueued,
                    const CodeLocation location) {
    if (enqueued.insert(logical_key(location)).second) {
        worklist.push_back(location);
    }
}

void enqueue_if_new_front(std::deque<CodeLocation>& worklist,
                          std::set<std::uint32_t>& enqueued,
                          const CodeLocation location) {
    if (enqueued.insert(logical_key(location)).second) {
        worklist.push_front(location);
    }
}

bool is_location_in_loaded_image(const MzImage& image, const CodeLocation location) {
    const std::uint32_t physical = real_mode_phys(location.cs, location.ip);
    return physical >= image.load_module_physical &&
           physical < image.image_end_physical &&
           physical < image.initial_memory_image.size();
}

CodeLocation module_offset_to_location(const MzImage& image, const std::uint32_t module_offset) {
    return CodeLocation{
        static_cast<std::uint16_t>(image.layout.load_segment() + ((module_offset >> 4u) & 0xFFFFu)),
        static_cast<std::uint16_t>(module_offset & 0x000Fu),
    };
}

void seed_interface_surface_roots(const std::vector<InterfaceSurfaceRecord>& surfaces,
                                  std::deque<CodeLocation>& worklist,
                                  std::set<std::uint32_t>& enqueued,
                                  std::set<std::uint32_t>& function_roots,
                                  std::set<std::uint32_t>& seeded_roots) {
    for (const InterfaceSurfaceRecord& surface : surfaces) {
        for (const InterfaceSurfaceEntry& entry : surface.entries) {
            if (!entry.target_is_valid) {
                continue;
            }
            enqueue_if_new(worklist, enqueued, entry.target);
            function_roots.insert(logical_key(entry.target));
            seeded_roots.insert(logical_key(entry.target));
        }
    }
}

bool loaded_bytes_look_like_zero_fill(const MzImage& image, const CodeLocation location) {
    const std::uint32_t physical = real_mode_phys(location.cs, location.ip);
    if (physical >= image.initial_memory_image.size()) {
        return true;
    }

    const std::size_t available =
        std::min<std::size_t>(32u, image.initial_memory_image.size() - physical);
    if (available < 16u) {
        return false;
    }

    std::size_t zero_count = 0u;
    for (std::size_t i = 0u; i < available; ++i) {
        if (image.initial_memory_image[physical + i] == 0u) {
            ++zero_count;
        }
    }

    return zero_count * 4u >= available * 3u;
}

bool is_plausible_code_target(const MzImage& image, const CodeLocation location) {
    if (!is_location_in_loaded_image(image, location)) {
        return false;
    }
    if (loaded_bytes_look_like_zero_fill(image, location)) {
        return false;
    }
    const BasicBlockPreview preview = decode_basic_block_preview(image, location.cs, location.ip, 8u);
    return preview_looks_like_code_target(preview);
}

bool preview_has_implicit_fallthrough(const BasicBlockPreview& preview) {
    return !preview.terminated && preview.termination_reason == "instruction limit reached";
}

bool preview_looks_like_zero_fill_data(const BasicBlockPreview& preview) {
    if (preview.instructions.size() < 16u) {
        return false;
    }

    std::size_t repeated_zero_adds = 0u;
    for (const DecodedInstruction& instruction : preview.instructions) {
        if (instruction.bytes.size() == 2u &&
            instruction.bytes[0] == 0x00u &&
            instruction.bytes[1] == 0x00u &&
            instruction.text.rfind("add [bx + si], al", 0u) == 0u) {
            ++repeated_zero_adds;
        }
    }

    return repeated_zero_adds * 4u >= preview.instructions.size() * 3u;
}

bool is_decoded_block_start(const CfgSnapshot& snapshot, const CodeLocation location) {
    return std::any_of(snapshot.blocks.begin(),
                       snapshot.blocks.end(),
                       [&](const BlockRecord& block) {
                           return logical_key(block.start) == logical_key(location);
                       });
}

bool overlaps_existing_decoded_block_interior(const CfgSnapshot& snapshot, const CodeLocation location) {
    for (const BlockRecord& block : snapshot.blocks) {
        if (block.start.cs != location.cs) {
            continue;
        }
        if (logical_key(block.start) == logical_key(location)) {
            return false;
        }
        for (const DecodedInstruction& instruction : block.preview.instructions) {
            const std::uint32_t start_ip = static_cast<std::uint32_t>(instruction.ip);
            const std::uint32_t end_ip = start_ip + static_cast<std::uint32_t>(instruction.length);
            if (location.ip == instruction.ip) {
                return true;
            }
            if (location.ip > start_ip && location.ip < end_ip) {
                return true;
            }
        }
    }
    return false;
}

bool is_mid_instruction_overlap(const CfgSnapshot& snapshot, const CodeLocation location) {
    for (const BlockRecord& block : snapshot.blocks) {
        if (block.start.cs != location.cs) {
            continue;
        }
        if (logical_key(block.start) == logical_key(location)) {
            continue;
        }
        for (const DecodedInstruction& instruction : block.preview.instructions) {
            const std::uint32_t start_ip = static_cast<std::uint32_t>(instruction.ip);
            const std::uint32_t end_ip = start_ip + static_cast<std::uint32_t>(instruction.length);
            if (location.ip > start_ip && location.ip < end_ip) {
                return true;
            }
        }
    }
    return false;
}

void prune_overlapping_indirect_targets(const CfgSnapshot& snapshot, IndirectSiteRecord& site) {
    std::vector<CodeLocation> filtered;
    filtered.reserve(site.resolved_targets.size());
    std::size_t pruned_count = 0u;
    for (const CodeLocation target : site.resolved_targets) {
        if (!is_decoded_block_start(snapshot, target) &&
            overlaps_existing_decoded_block_interior(snapshot, target)) {
            ++pruned_count;
            continue;
        }
        const std::uint32_t target_key = logical_key(target);
        const auto existing = std::find_if(filtered.begin(),
                                           filtered.end(),
                                           [&](const CodeLocation& candidate) {
                                               return logical_key(candidate) == target_key;
                                           });
        if (existing == filtered.end()) {
            filtered.push_back(target);
        }
    }
    if (pruned_count != 0u) {
        std::ostringstream note;
        if (!site.resolution_note.empty()) {
            note << site.resolution_note << "; ";
        }
        note << "pruned " << pruned_count << " overlapping decoded-block interior targets";
        site.resolution_note = note.str();
    }
    site.resolved_targets = std::move(filtered);
}

void prune_invalid_overlapping_blocks_and_targets(const MzImage& image, CfgSnapshot& snapshot) {
    std::set<std::uint32_t> invalid_block_keys;
    std::set<std::uint32_t> preferred_root_keys;
    if (is_plausible_code_target(image, snapshot.root)) {
        preferred_root_keys.insert(logical_key(snapshot.root));
    }
    for (const CfgEdge& edge : snapshot.edges) {
        if (edge.kind != EdgeKind::Call) {
            continue;
        }
        if (is_plausible_code_target(image, edge.to)) {
            preferred_root_keys.insert(logical_key(edge.to));
        }
    }
    for (const InterfaceSurfaceRecord& surface : snapshot.interface_surfaces) {
        for (const InterfaceSurfaceEntry& entry : surface.entries) {
            if (!entry.target_is_valid || !is_plausible_code_target(image, entry.target)) {
                continue;
            }
            preferred_root_keys.insert(logical_key(entry.target));
        }
    }

    for (const BlockRecord& block : snapshot.blocks) {
        const std::uint32_t block_key = logical_key(block.start);
        if (preferred_root_keys.contains(block_key)) {
            continue;
        }

        bool covered_preferred_root = false;
        for (const DecodedInstruction& instruction : block.preview.instructions) {
            const std::uint32_t start_ip = static_cast<std::uint32_t>(instruction.ip);
            const std::uint32_t end_ip = start_ip + static_cast<std::uint32_t>(instruction.length);
            for (const std::uint32_t preferred_root_key : preferred_root_keys) {
                const CodeLocation preferred_root = key_to_location(preferred_root_key);
                if (preferred_root.cs != instruction.cs) {
                    continue;
                }
                if (preferred_root.ip > start_ip && preferred_root.ip < end_ip) {
                    covered_preferred_root = true;
                    break;
                }
            }
            if (covered_preferred_root) {
                break;
            }
        }

        if (covered_preferred_root) {
            invalid_block_keys.insert(block_key);
        }
    }

    for (const BlockRecord& block : snapshot.blocks) {
        const std::uint32_t block_key = logical_key(block.start);
        if (preferred_root_keys.contains(block_key)) {
            if (!is_plausible_code_target(image, block.start)) {
                invalid_block_keys.insert(block_key);
            }
            continue;
        }
        if (is_mid_instruction_overlap(snapshot, block.start) ||
            !is_plausible_code_target(image, block.start)) {
            invalid_block_keys.insert(block_key);
        }
    }
    if (invalid_block_keys.empty()) {
        return;
    }

    snapshot.blocks.erase(std::remove_if(snapshot.blocks.begin(),
                                         snapshot.blocks.end(),
                                         [&](const BlockRecord& block) {
                                             return invalid_block_keys.contains(logical_key(block.start));
                                         }),
                          snapshot.blocks.end());

    snapshot.edges.erase(std::remove_if(snapshot.edges.begin(),
                                        snapshot.edges.end(),
                                        [&](const CfgEdge& edge) {
                                            return invalid_block_keys.contains(logical_key(edge.from)) ||
                                                   invalid_block_keys.contains(logical_key(edge.to));
                                        }),
                         snapshot.edges.end());

    for (IndirectSiteRecord& site : snapshot.indirect_sites) {
        site.resolved_targets.erase(
            std::remove_if(site.resolved_targets.begin(),
                           site.resolved_targets.end(),
                           [&](const CodeLocation target) {
                               return invalid_block_keys.contains(logical_key(target));
                           }),
            site.resolved_targets.end());
        if (!site.resolved_targets.empty()) {
            continue;
        }
        if (!site.resolution_note.empty()) {
            site.resolution_note += "; ";
        }
        site.resolution_note += "all targets pruned as mid-instruction overlaps";
    }

    snapshot.discovered_function_roots.erase(
        std::remove_if(snapshot.discovered_function_roots.begin(),
                       snapshot.discovered_function_roots.end(),
                       [&](const CodeLocation root) {
                           return invalid_block_keys.contains(logical_key(root));
                       }),
        snapshot.discovered_function_roots.end());
}

bool preview_looks_like_code_target(const BasicBlockPreview& preview) {
    if (preview.instructions.empty()) {
        return false;
    }
    if (preview_looks_like_zero_fill_data(preview)) {
        return false;
    }
    if (preview.terminated || preview_has_implicit_fallthrough(preview)) {
        return true;
    }
    if (preview.termination_reason == "unsupported FEh group variant" ||
        preview.termination_reason == "unsupported FFh group variant") {
        return false;
    }

    constexpr std::string_view kUnsupportedOpcodePrefix = "unsupported opcode 0x";
    if (preview.termination_reason.rfind(kUnsupportedOpcodePrefix, 0u) == 0u &&
        preview.termination_reason.size() >= kUnsupportedOpcodePrefix.size() + 2u) {
        const std::string_view opcode_text =
            std::string_view(preview.termination_reason).substr(kUnsupportedOpcodePrefix.size(), 2u);
        const unsigned long opcode = std::stoul(std::string(opcode_text), nullptr, 16);
        if (opcode >= 0xD8u && opcode <= 0xDFu) {
            return false;
        }
    }

    return true;
}

std::uint16_t read_memory_u16(const MzImage& image, const std::uint16_t segment, const std::uint16_t offset) {
    const std::uint32_t physical = real_mode_phys(segment, offset);
    if (physical + 1u >= image.initial_memory_image.size()) {
        throw std::runtime_error("indirect target read ran off the end of the real-mode address space");
    }
    const std::uint8_t lo = image.initial_memory_image[physical];
    const std::uint8_t hi = image.initial_memory_image[physical + 1u];
    return static_cast<std::uint16_t>(lo) | static_cast<std::uint16_t>(hi << 8u);
}

std::optional<CodeLocation> direct_target_of(const DecodedInstruction& instruction) {
    if (!instruction.branch_target_ip.has_value()) {
        return std::nullopt;
    }
    return CodeLocation{
        instruction.branch_target_cs.value_or(instruction.cs),
        *instruction.branch_target_ip,
    };
}

void append_edge(CfgSnapshot& snapshot,
                 std::set<std::uint64_t>& emitted_edges,
                 const CfgEdge& edge) {
    if (emitted_edges.insert(edge_key(edge)).second) {
        snapshot.edges.push_back(edge);
    }
}

IndirectSiteRecord build_indirect_site_record(const MzImage& image, const DecodedInstruction& instruction) {
    IndirectSiteRecord site{};
    site.from = CodeLocation{instruction.cs, instruction.ip};
    site.kind = (instruction.flow == FlowKind::Call) ? EdgeKind::Call : EdgeKind::Branch;

    if (!instruction.indirect.has_value()) {
        site.resolution_note = "not an indirect control transfer";
        return site;
    }

    const IndirectTransferInfo& indirect = *instruction.indirect;
    site.is_far = indirect.is_far;
    site.operand_text = indirect.operand_text;

    switch (indirect.operand_kind) {
    case IndirectOperandKind::Register:
        site.resolution_note = "target held in register";
        return site;
    case IndirectOperandKind::MemoryComputed:
        site.resolution_note = "target address depends on runtime memory indexing";
        return site;
    case IndirectOperandKind::MemoryDirect:
        break;
    }

    if (!indirect.memory_offset.has_value()) {
        site.resolution_note = "direct memory operand missing offset metadata";
        return site;
    }
    if (!indirect.memory_uses_current_cs) {
        site.resolution_note = "direct memory operand does not use current CS";
        return site;
    }

    try {
        const std::uint16_t pointer_offset = *indirect.memory_offset;
        if (indirect.is_far) {
            const std::uint16_t target_ip = read_memory_u16(image, instruction.cs, pointer_offset);
            const std::uint16_t target_cs = read_memory_u16(
                image, instruction.cs, static_cast<std::uint16_t>(pointer_offset + 2u));
            const CodeLocation target{target_cs, target_ip};
            if (is_location_in_loaded_image(image, target)) {
                site.resolved_targets.push_back(target);
                site.resolution_note = "resolved from static far pointer in cs memory";
            } else {
                site.resolution_note = "static far pointer resolved outside loaded image";
            }
        } else {
            const CodeLocation target{
                instruction.cs,
                read_memory_u16(image, instruction.cs, pointer_offset),
            };
            if (is_location_in_loaded_image(image, target)) {
                site.resolved_targets.push_back(target);
                site.resolution_note = "resolved from static near pointer in cs memory";
            } else {
                site.resolution_note = "static near pointer resolved outside loaded image";
            }
        }
    } catch (const std::exception& ex) {
        site.resolution_note = ex.what();
    }

    return site;
}

std::map<std::uint64_t, std::map<std::uint32_t, AbstractState>> analyze_rooted_block_entry_states(
    const MzImage& image,
    const CfgSnapshot& snapshot) {
    std::map<std::uint32_t, const BlockRecord*> blocks_by_key;
    std::map<std::uint32_t, std::vector<CfgEdge>> edges_by_source;

    for (const BlockRecord& block : snapshot.blocks) {
        blocks_by_key[logical_key(block.start)] = &block;
    }
    for (const CfgEdge& edge : snapshot.edges) {
        edges_by_source[logical_key(edge.from)].push_back(edge);
    }

    std::map<std::uint64_t, std::map<std::uint32_t, AbstractState>> entry_states;
    std::deque<std::pair<std::uint64_t, std::uint32_t>> worklist;
    std::set<std::pair<std::uint64_t, std::uint32_t>> queued;
    const std::uint32_t root_key = logical_key(snapshot.root);
    const std::uint64_t rooted_root_key = analysis_state_key(root_key, root_key);
    entry_states[rooted_root_key][root_key] = AbstractState{};
    worklist.push_back({rooted_root_key, root_key});
    queued.insert({rooted_root_key, root_key});

    while (!worklist.empty()) {
        const auto [rooted_key, predecessor_key] = worklist.front();
        worklist.pop_front();
        queued.erase({rooted_key, predecessor_key});

        const std::uint32_t owner_root_key = analysis_owner_root_from_key(rooted_key);
        const std::uint32_t block_key = analysis_block_from_key(rooted_key);

        const auto block_it = blocks_by_key.find(block_key);
        if (block_it == blocks_by_key.end()) {
            continue;
        }

        AbstractState current = entry_states[rooted_key][predecessor_key];
        std::map<std::uint32_t, std::uint16_t>& direct_memory_overrides = current.direct_memory_words;
        std::vector<KnownWord> abstract_stack;

        for (const DecodedInstruction& instruction : block_it->second->preview.instructions) {
            const std::uint32_t source_key = logical_key(CodeLocation{instruction.cs, instruction.ip});

            const auto edge_it = edges_by_source.find(source_key);
            if (edge_it != edges_by_source.end()) {
                for (const CfgEdge& edge : edge_it->second) {
                    if (edge.kind != EdgeKind::Call) {
                        continue;
                    }
                    const std::uint32_t target_key = logical_key(edge.to);
                    const std::uint64_t rooted_target_key = analysis_state_key(target_key, target_key);
                    auto& predecessors = entry_states[rooted_target_key];
                    const auto [state_it, inserted] = predecessors.emplace(block_key, current);
                    const bool changed = inserted ? true : merge_abstract_state(state_it->second, current);
                    if (changed && queued.insert({rooted_target_key, block_key}).second) {
                        worklist.push_back({rooted_target_key, block_key});
                    }
                }
            }

            apply_instruction_effect(image, instruction, current, direct_memory_overrides, abstract_stack);

            if (edge_it != edges_by_source.end()) {
                for (const CfgEdge& edge : edge_it->second) {
                    if (edge.kind == EdgeKind::Call) {
                        continue;
                    }
                    const std::uint32_t target_key = logical_key(edge.to);
                    const std::uint64_t rooted_target_key = analysis_state_key(owner_root_key, target_key);
                    auto& predecessors = entry_states[rooted_target_key];
                    const auto [state_it, inserted] = predecessors.emplace(block_key, current);
                    const bool changed = inserted ? true : merge_abstract_state(state_it->second, current);
                    if (changed && queued.insert({rooted_target_key, block_key}).second) {
                        worklist.push_back({rooted_target_key, block_key});
                    }
                }
            }
        }
    }

    return entry_states;
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

std::optional<std::uint32_t> location_to_module_offset(const MzImage& image, const CodeLocation location) {
    if (!is_location_in_loaded_image(image, location)) {
        return std::nullopt;
    }
    const std::uint32_t physical = real_mode_phys(location.cs, location.ip);
    if (physical < image.load_module_physical) {
        return std::nullopt;
    }
    return physical - image.load_module_physical;
}

std::optional<std::uint32_t> resolve_direct_operand_module_offset(const MzImage& image,
                                                                  const AbstractState& state,
                                                                  const DecodedInstruction& instruction,
                                                                  const std::string& operand_text) {
    if (!is_simple_direct_memory_operand_text(operand_text)) {
        return std::nullopt;
    }

    const std::optional<std::uint16_t> offset = direct_operand_offset_from_text(operand_text);
    if (!offset.has_value()) {
        return std::nullopt;
    }

    const KnownWord segment_values = resolve_direct_segment_values(state, instruction, operand_text);
    const std::optional<std::uint16_t> segment = singleton_value(segment_values);
    if (!segment.has_value()) {
        return std::nullopt;
    }

    return location_to_module_offset(image, CodeLocation{*segment, *offset});
}

std::set<std::uint32_t> collect_known_direct_memory_module_offsets(
    const MzImage& image,
    const CfgSnapshot& snapshot,
    const std::map<std::uint64_t, std::map<std::uint32_t, AbstractState>>& entry_states) {
    std::set<std::uint32_t> offsets;
    std::map<std::uint32_t, const BlockRecord*> blocks_by_key;
    for (const BlockRecord& block : snapshot.blocks) {
        blocks_by_key[logical_key(block.start)] = &block;
    }

    for (const auto& [state_key, predecessor_states] : entry_states) {
        const auto block_it = blocks_by_key.find(analysis_block_from_key(state_key));
        if (block_it == blocks_by_key.end()) {
            continue;
        }

        for (const auto& [predecessor_key, entry_state] : predecessor_states) {
            (void)predecessor_key;
            AbstractState current = entry_state;
            std::map<std::uint32_t, std::uint16_t>& direct_memory_overrides = current.direct_memory_words;
            std::vector<KnownWord> abstract_stack;

            for (const DecodedInstruction& instruction : block_it->second->preview.instructions) {
                for (const std::string& operand_text : instruction_operand_texts(instruction)) {
                    const std::optional<std::uint32_t> module_offset =
                        resolve_direct_operand_module_offset(image, current, instruction, operand_text);
                    if (module_offset.has_value()) {
                        offsets.insert(*module_offset);
                    }
                }
                apply_instruction_effect(image, instruction, current, direct_memory_overrides, abstract_stack);
            }
        }
    }

    return offsets;
}

std::optional<std::uint32_t> find_next_known_module_boundary(const MzImage& image,
                                                             const CfgSnapshot& snapshot,
                                                             const std::set<std::uint32_t>& direct_data_offsets,
                                                             const std::uint32_t table_module_offset) {
    std::optional<std::uint32_t> best;

    for (const BlockRecord& block : snapshot.blocks) {
        const std::optional<std::uint32_t> module_offset = location_to_module_offset(image, block.start);
        if (!module_offset.has_value() || *module_offset <= table_module_offset) {
            continue;
        }
        if (!best.has_value() || *module_offset < *best) {
            best = *module_offset;
        }
    }

    for (const std::uint32_t module_offset : direct_data_offsets) {
        if (module_offset <= table_module_offset) {
            continue;
        }
        if (!best.has_value() || module_offset < *best) {
            best = module_offset;
        }
    }

    return best;
}

bool is_valid_interface_table_target(const MzImage& image,
                                     const CfgSnapshot& snapshot,
                                     const CodeLocation target) {
    return is_location_in_loaded_image(image, target) &&
           is_plausible_code_target(image, target) &&
           !is_mid_instruction_overlap(snapshot, target);
}

std::uint32_t require_module_offset(const MzImage& image,
                                    const CodeLocation location,
                                    const std::string_view description) {
    const std::optional<std::uint32_t> module_offset = location_to_module_offset(image, location);
    if (!module_offset.has_value()) {
        throw std::runtime_error(std::string(description) + " is outside the loaded image");
    }
    return *module_offset;
}

std::uint32_t require_next_known_module_boundary(const MzImage& image,
                                                 const CfgSnapshot& snapshot,
                                                 const std::set<std::uint32_t>& direct_data_offsets,
                                                 const std::uint32_t table_module_offset,
                                                 const std::string_view description) {
    const std::optional<std::uint32_t> module_limit =
        find_next_known_module_boundary(image, snapshot, direct_data_offsets, table_module_offset);
    if (!module_limit.has_value() || *module_limit <= table_module_offset) {
        throw std::runtime_error(std::string(description) + " discovery could not find a valid table boundary");
    }
    return *module_limit;
}

InterfaceSurfaceRecord build_validated_near_word_table_surface(const MzImage& image,
                                                               const CfgSnapshot& snapshot,
                                                               const std::set<std::uint32_t>& direct_data_offsets,
                                                               const std::string_view description,
                                                               const std::string& surface_name,
                                                               const InterfaceSurfaceKind kind,
                                                               const CodeLocation base,
                                                               const std::uint16_t target_cs,
                                                               const bool tighten_with_later_target_boundary,
                                                               const bool allow_zero_targets,
                                                               const bool require_preexisting_function_root,
                                                               const bool preserve_zero_entries) {
    const std::uint32_t table_module_offset = require_module_offset(image, base, description);
    std::uint32_t module_limit = require_next_known_module_boundary(
        image, snapshot, direct_data_offsets, table_module_offset, description);
    std::set<std::uint32_t> existing_root_keys;
    if (require_preexisting_function_root) {
        for (const CodeLocation root : snapshot.discovered_function_roots) {
            existing_root_keys.insert(logical_key(root));
        }
    }

    if (tighten_with_later_target_boundary) {
        bool tightened_limit = true;
        while (tightened_limit) {
            tightened_limit = false;
            for (std::uint32_t entry_offset = table_module_offset;
                 entry_offset + sizeof(std::uint16_t) <= module_limit;
                 entry_offset += sizeof(std::uint16_t)) {
                const std::uint16_t entry_ip = read_u16(image.relocated_load_module_bytes, entry_offset);
                if (!allow_zero_targets && entry_ip == 0u) {
                    continue;
                }
                const CodeLocation target{target_cs, entry_ip};
                if (!is_plausible_code_target(image, target)) {
                    continue;
                }
                const std::optional<std::uint32_t> target_module_offset =
                    location_to_module_offset(image, target);
                if (!target_module_offset.has_value() ||
                    *target_module_offset <= table_module_offset ||
                    *target_module_offset >= module_limit) {
                    continue;
                }
                module_limit = *target_module_offset;
                tightened_limit = true;
                break;
            }
        }
    }

    InterfaceSurfaceRecord surface{};
    surface.name = surface_name;
    surface.kind = kind;
    surface.base = base;

    const std::size_t max_entry_count =
        static_cast<std::size_t>((module_limit - table_module_offset) / sizeof(std::uint16_t));
    surface.entries.reserve(max_entry_count);
    for (std::size_t index = 0u; index < max_entry_count; ++index) {
        const std::size_t entry_offset =
            static_cast<std::size_t>(table_module_offset + index * sizeof(std::uint16_t));
        const std::uint16_t entry_ip = read_u16(image.relocated_load_module_bytes, entry_offset);
        if (preserve_zero_entries && entry_ip == 0u) {
            InterfaceSurfaceEntry entry{};
            entry.ordinal = static_cast<std::uint16_t>(index);
            entry.target = CodeLocation{target_cs, 0u};
            entry.target_is_valid = false;
            surface.entries.push_back(entry);
            continue;
        }
        if (!allow_zero_targets && entry_ip == 0u) {
            break;
        }
        const CodeLocation target{target_cs, entry_ip};
        if (require_preexisting_function_root &&
            !existing_root_keys.contains(logical_key(target))) {
            break;
        }
        if (!is_valid_interface_table_target(image, snapshot, target)) {
            break;
        }

        InterfaceSurfaceEntry entry{};
        entry.ordinal = static_cast<std::uint16_t>(index);
        entry.target = target;
        entry.target_is_valid = true;
        surface.entries.push_back(entry);
    }

    if (surface.entries.empty()) {
        throw std::runtime_error(std::string(description) + " discovery found no valid table entries");
    }

    return surface;
}

InterfaceSurfaceRecord build_validated_pair_table_surface(const MzImage& image,
                                                          const CfgSnapshot& snapshot,
                                                          const std::string_view description,
                                                          const std::string& surface_name,
                                                          const CodeLocation base,
                                                          const std::uint16_t target_cs,
                                                          const std::uint16_t terminator_selector) {
    const std::uint32_t table_module_offset = require_module_offset(image, base, description);

    InterfaceSurfaceRecord surface{};
    surface.name = surface_name;
    surface.kind = InterfaceSurfaceKind::RoutinePackPairTable;
    surface.base = base;

    constexpr std::size_t kPairEntrySize = sizeof(std::uint16_t) * 2u;
    const std::size_t max_entry_count =
        (image.relocated_load_module_bytes.size() > table_module_offset)
            ? (image.relocated_load_module_bytes.size() - table_module_offset) / kPairEntrySize
            : 0u;

    for (std::size_t index = 0u; index < max_entry_count; ++index) {
        const std::size_t entry_offset = static_cast<std::size_t>(table_module_offset + index * kPairEntrySize);
        const std::uint16_t selector = read_u16(image.relocated_load_module_bytes, entry_offset);
        if (selector == terminator_selector) {
            break;
        }

        const std::uint16_t target_ip =
            read_u16(image.relocated_load_module_bytes, entry_offset + sizeof(std::uint16_t));
        const CodeLocation target{target_cs, target_ip};
        if (!is_valid_interface_table_target(image, snapshot, target)) {
            break;
        }

        InterfaceSurfaceEntry entry{};
        entry.ordinal = selector;
        entry.target = target;
        entry.target_is_valid = true;
        surface.entries.push_back(entry);
    }

    if (surface.entries.empty()) {
        throw std::runtime_error(std::string(description) + " discovery found no valid pair-table entries");
    }

    return surface;
}

std::uint32_t discover_validated_descriptor_region_limit(const MzImage& image,
                                                         const CfgSnapshot& snapshot,
                                                         const std::set<std::uint32_t>& direct_data_offsets,
                                                         const std::string_view description,
                                                         const CodeLocation base,
                                                         const std::uint16_t target_cs,
                                                         const std::uint16_t field_offset,
                                                         const std::uint16_t target_delta,
                                                         const std::uint16_t record_stride) {
    const std::uint32_t table_module_offset = require_module_offset(image, base, description);
    std::uint32_t module_limit = require_next_known_module_boundary(
        image, snapshot, direct_data_offsets, table_module_offset, description);

    bool tightened_limit = true;
    while (tightened_limit) {
        tightened_limit = false;
        for (std::uint32_t entry_offset = table_module_offset;
             entry_offset + field_offset + sizeof(std::uint16_t) <= module_limit;
             entry_offset += record_stride) {
            const std::uint16_t raw_target_ip = read_u16(
                image.relocated_load_module_bytes,
                static_cast<std::size_t>(entry_offset + field_offset));
            const std::uint16_t target_ip = static_cast<std::uint16_t>(raw_target_ip + target_delta);
            const CodeLocation target{target_cs, target_ip};
            if (!is_plausible_code_target(image, target)) {
                continue;
            }

            const std::optional<std::uint32_t> target_module_offset =
                location_to_module_offset(image, target);
            if (!target_module_offset.has_value() ||
                *target_module_offset <= table_module_offset ||
                *target_module_offset >= module_limit) {
                continue;
            }

            module_limit = *target_module_offset;
            tightened_limit = true;
            break;
        }
    }

    return module_limit;
}

InterfaceSurfaceRecord build_validated_descriptor_call_surface(const MzImage& image,
                                                              const CfgSnapshot& snapshot,
                                                              const std::set<std::uint32_t>& direct_data_offsets,
                                                              const std::string_view description,
                                                              const std::string& surface_name,
                                                              const CodeLocation base,
                                                              const std::uint16_t target_cs,
                                                              const std::uint16_t field_offset,
                                                              const std::uint16_t target_delta,
                                                              const std::uint16_t record_stride) {
    const std::uint32_t table_module_offset = require_module_offset(image, base, description);
    const std::uint32_t module_limit = discover_validated_descriptor_region_limit(
        image,
        snapshot,
        direct_data_offsets,
        description,
        base,
        target_cs,
        field_offset,
        target_delta,
        record_stride);

    InterfaceSurfaceRecord surface{};
    surface.name = surface_name;
    surface.kind = InterfaceSurfaceKind::RoutinePackDescriptorTable;
    surface.base = base;

    if (record_stride == 0u) {
        throw std::runtime_error(std::string(description) + " record stride must be non-zero");
    }

    for (std::uint32_t entry_offset = table_module_offset;
         entry_offset + field_offset + sizeof(std::uint16_t) <= module_limit;
         entry_offset += record_stride) {
        const std::uint16_t raw_target_ip =
            read_u16(image.relocated_load_module_bytes, static_cast<std::size_t>(entry_offset + field_offset));
        const std::uint16_t target_ip = static_cast<std::uint16_t>(raw_target_ip + target_delta);
        const CodeLocation target{target_cs, target_ip};
        if (!is_location_in_loaded_image(image, target) || !is_plausible_code_target(image, target)) {
            continue;
        }

        InterfaceSurfaceEntry entry{};
        entry.ordinal = static_cast<std::uint16_t>((entry_offset - table_module_offset) / record_stride);
        entry.target = target;
        entry.target_is_valid = true;
        surface.entries.push_back(entry);
    }

    if (surface.entries.empty()) {
        throw std::runtime_error(std::string(description) + " discovery found no valid descriptor entries");
    }

    return surface;
}

std::vector<InterfaceSurfaceRecord> build_validated_descriptor_inline_subtable_surfaces(
    const MzImage& image,
    const CfgSnapshot& snapshot,
    const std::set<std::uint32_t>& direct_data_offsets,
    const std::string_view description,
    const std::string_view surface_name_prefix,
    const CodeLocation base,
    const std::uint16_t target_cs,
    const std::uint16_t first_field_target_delta,
    const std::uint16_t record_stride,
    const std::uint16_t max_inline_gap) {
    const std::uint32_t table_module_offset = require_module_offset(image, base, description);
    const std::uint32_t module_limit = discover_validated_descriptor_region_limit(
        image,
        snapshot,
        direct_data_offsets,
        description,
        base,
        target_cs,
        0u,
        first_field_target_delta,
        record_stride);

    std::vector<InterfaceSurfaceRecord> surfaces;
    std::set<std::uint16_t> seen_bases;
    for (std::uint32_t entry_offset = table_module_offset;
         entry_offset + record_stride <= module_limit;
         entry_offset += record_stride) {
        const std::uint16_t first_raw =
            read_u16(image.relocated_load_module_bytes, static_cast<std::size_t>(entry_offset));
        const std::uint16_t second_raw = read_u16(
            image.relocated_load_module_bytes,
            static_cast<std::size_t>(entry_offset + sizeof(std::uint16_t)));
        if (second_raw == 0u || second_raw == 0xFFFFu || seen_bases.contains(second_raw)) {
            continue;
        }
        if (second_raw <= first_raw || static_cast<std::uint16_t>(second_raw - first_raw) > max_inline_gap) {
            continue;
        }

        try {
            InterfaceSurfaceRecord surface = build_validated_near_word_table_surface(
                image,
                snapshot,
                direct_data_offsets,
                description,
                std::string(surface_name_prefix) + hex16(second_raw).substr(2),
                InterfaceSurfaceKind::RoutinePackWordTable,
                CodeLocation{target_cs, second_raw},
                target_cs,
                true,
                false,
                false,
                false);
            seen_bases.insert(second_raw);
            surfaces.push_back(std::move(surface));
        } catch (...) {
        }
    }

    return surfaces;
}

InterfaceSurfaceRecord build_benchmark_engine_api_surface(const MzImage& image,
                                                          const CfgSnapshot& snapshot,
                                                          const std::set<std::uint32_t>& direct_data_offsets) {
    static constexpr std::uint32_t kEngineApiTableModuleOffset = 0x060C56u;
    static constexpr std::array<std::uint16_t, 4> kEngineApiPrefix = {
        0x410Eu, 0x7E1Cu, 0x407Fu, 0x81C8u,
    };
    static constexpr std::size_t kEngineApiEntryCount = 30u;

    for (std::size_t index = 0u; index < kEngineApiPrefix.size(); ++index) {
        const std::size_t entry_offset =
            static_cast<std::size_t>(kEngineApiTableModuleOffset + index * sizeof(std::uint16_t));
        const std::uint16_t entry_ip = read_u16(image.relocated_load_module_bytes, entry_offset);
        if (entry_ip != kEngineApiPrefix[index]) {
            throw std::runtime_error("engine API surface discovery prefix validation failed");
        }
    }

    InterfaceSurfaceRecord surface = build_validated_near_word_table_surface(
        image,
        snapshot,
        direct_data_offsets,
        "engine API surface",
        "engine_api_pack_to_engine",
        InterfaceSurfaceKind::EngineApiJumpTable,
        module_offset_to_location(image, kEngineApiTableModuleOffset),
        image.layout.load_segment(),
        false,
        true,
        false,
        false);

    if (surface.entries.size() < kEngineApiEntryCount) {
        throw std::runtime_error("engine API surface discovery found fewer than 30 validated entries");
    }
    surface.entries.resize(kEngineApiEntryCount);
    return surface;
}

std::vector<InterfaceSurfaceRecord> build_benchmark_routine_pack_surfaces(
    const MzImage& image,
    const CfgSnapshot& snapshot,
    const std::set<std::uint32_t>& direct_data_offsets) {
    static constexpr std::uint16_t kRoutinePackSegment = 0x4A56u;

    std::vector<InterfaceSurfaceRecord> surfaces;
    surfaces.push_back(build_validated_near_word_table_surface(
        image,
        snapshot,
        direct_data_offsets,
        "routine pack simple table 06DC",
        "routine_pack_table_06dc",
        InterfaceSurfaceKind::RoutinePackWordTable,
        CodeLocation{kRoutinePackSegment, 0x06DCu},
        kRoutinePackSegment,
        true,
        false,
        false,
        false));
    surfaces.push_back(build_validated_near_word_table_surface(
        image,
        snapshot,
        direct_data_offsets,
        "routine pack simple table 081E",
        "routine_pack_table_081e",
        InterfaceSurfaceKind::RoutinePackWordTable,
        CodeLocation{kRoutinePackSegment, 0x081Eu},
        kRoutinePackSegment,
        true,
        false,
        false,
        false));
    surfaces.push_back(build_validated_near_word_table_surface(
        image,
        snapshot,
        direct_data_offsets,
        "routine pack simple table 0C3F",
        "routine_pack_table_0c3f",
        InterfaceSurfaceKind::RoutinePackWordTable,
        CodeLocation{kRoutinePackSegment, 0x0C3Fu},
        kRoutinePackSegment,
        true,
        false,
        false,
        true));
    surfaces.push_back(build_validated_descriptor_call_surface(
        image,
        snapshot,
        direct_data_offsets,
        "routine pack descriptor table",
        "routine_pack_descriptor_table",
        CodeLocation{kRoutinePackSegment, 0x002Cu},
        kRoutinePackSegment,
        0u,
        0x0002u,
        0x0004u));
    std::vector<InterfaceSurfaceRecord> inline_subtables =
        build_validated_descriptor_inline_subtable_surfaces(
            image,
            snapshot,
            direct_data_offsets,
            "routine pack inline descriptor subtable",
            "routine_pack_inline_subtable_",
            CodeLocation{kRoutinePackSegment, 0x002Cu},
            kRoutinePackSegment,
            0x0002u,
            0x0004u,
            0x0010u);
    surfaces.insert(surfaces.end(), inline_subtables.begin(), inline_subtables.end());
    return surfaces;
}

std::vector<InterfaceSurfaceRecord> collect_benchmark_interface_surfaces(const MzImage& image,
                                                                         const CfgSnapshot& snapshot) {
    const auto entry_states = analyze_rooted_block_entry_states(image, snapshot);
    const std::set<std::uint32_t> direct_data_offsets =
        collect_known_direct_memory_module_offsets(image, snapshot, entry_states);

    std::vector<InterfaceSurfaceRecord> surfaces;
    surfaces.push_back(build_benchmark_engine_api_surface(image, snapshot, direct_data_offsets));
    std::vector<InterfaceSurfaceRecord> routine_pack_surfaces =
        build_benchmark_routine_pack_surfaces(image, snapshot, direct_data_offsets);
    surfaces.insert(surfaces.end(), routine_pack_surfaces.begin(), routine_pack_surfaces.end());
    return surfaces;
}

std::optional<CodeLocation> resolve_indirect_site_with_analysis(const MzImage& image,
                                                                const CfgSnapshot& snapshot,
                                                                const std::map<std::uint64_t, std::map<std::uint32_t, AbstractState>>& entry_states,
                                                                const DirectWriteSummary& direct_write_summary,
                                                                IndirectSiteRecord& site) {
    for (const BlockRecord& block : snapshot.blocks) {
        const std::uint32_t block_key = logical_key(block.start);
        auto instruction_it = std::find_if(block.preview.instructions.begin(),
                                           block.preview.instructions.end(),
                                           [&](const DecodedInstruction& instruction) {
                                               return instruction.cs == site.from.cs && instruction.ip == site.from.ip;
                                           });
        if (instruction_it == block.preview.instructions.end()) {
            continue;
        }

        struct OwnerStateEntry {
            std::uint64_t state_key = 0;
            std::uint32_t predecessor_key = 0;
            const AbstractState* state = nullptr;
        };
        std::vector<OwnerStateEntry> owner_states;
        for (const auto& [state_key, predecessor_states] : entry_states) {
            if (analysis_block_from_key(state_key) == block_key) {
                for (const auto& [predecessor_key, state] : predecessor_states) {
                    owner_states.push_back(OwnerStateEntry{state_key, predecessor_key, &state});
                }
            }
        }
        if (owner_states.empty()) {
            if (!site.is_far) {
                if (const std::optional<IndexedMemoryOperandInfo> indexed =
                        parse_indexed_memory_operand_text(site.operand_text);
                    indexed.has_value() && !indexed->uses_current_cs) {
                    Register16Id tracked_base_register = indexed->base_register;
                    if (const std::optional<std::uint16_t> table_base =
                            discover_recent_table_base_before_register_chain(
                                block,
                                std::optional<CodeLocation>{site.from},
                                tracked_base_register);
                        table_base.has_value()) {
                        if (const std::optional<std::uint16_t> entry_count =
                                discover_unsigned_upper_bound_for_block(snapshot, block.start);
                            entry_count.has_value() && *entry_count > 0u) {
                            if (append_same_segment_bounded_word_table_targets(image,
                                                                               instruction_it->cs,
                                                                               *table_base,
                                                                               *entry_count,
                                                                               site.resolved_targets,
                                                                               nullptr)) {
                                prune_overlapping_indirect_targets(snapshot, site);
                                if (!site.resolved_targets.empty()) {
                                    site.resolution_note =
                                        "resolved from local bounded same-segment word table";
                                    return site.resolved_targets.front();
                                }
                            }
                        }
                    }
                }
            }
            continue;
        }

        std::size_t resolved_owner_contexts = 0;
        std::size_t unresolved_owner_contexts = 0;
        std::size_t skipped_candidates_total = 0;
        bool target_from_override = false;
        const std::optional<std::uint16_t> pointer_offset = direct_operand_offset_from_text(site.operand_text);
        const std::optional<Register16Id> register_target = parse_register16_name(site.operand_text);

        for (const OwnerStateEntry& owner_state_entry : owner_states) {
            const std::uint64_t owner_state_key = owner_state_entry.state_key;
            const CodeLocation owner_root = key_to_location(analysis_owner_root_from_key(owner_state_key));
            AbstractState current = *owner_state_entry.state;
            std::map<std::uint32_t, std::uint16_t>& direct_memory_overrides = current.direct_memory_words;
            std::vector<KnownWord> abstract_stack;
            bool owner_resolved = false;
            const auto infer_table_base_from_block_entry =
                [&](const Register16Id initial_register,
                    const std::optional<CodeLocation> stop_before) -> std::optional<std::uint16_t> {
                Register16Id tracked_register = initial_register;
                if (const std::optional<std::uint16_t> discovered =
                        discover_recent_table_base_before_register_chain(block, stop_before, tracked_register);
                    discovered.has_value()) {
                    return discovered;
                }
                return singleton_value(register_ref(*owner_state_entry.state, tracked_register));
            };
                struct RegisterTargetProvenance {
                    enum class Kind {
                        None,
                        DirectMemoryLoad,
                        IndexedLoad,
                    };

                    Kind kind = Kind::None;
                KnownWord segment_values{};
                std::uint16_t direct_offset = 0;
                KnownWord index_values{};
                Register16Id index_base_register = Register16Id::BX;
                std::int16_t indexed_displacement = 0;
                std::optional<CodeLocation> source_location{};
            } target_provenance{};

            for (std::size_t instruction_index = 0; instruction_index < block.preview.instructions.size(); ++instruction_index) {
                const DecodedInstruction& instruction = block.preview.instructions[instruction_index];
                    if (instruction.cs == site.from.cs && instruction.ip == site.from.ip) {
                        if (register_target.has_value()) {
                            const KnownWord target_values = register_ref(current, *register_target);
                            std::optional<std::uint16_t> table_base_override;
                            bool uses_pair_table_layout = false;
                            if (target_provenance.source_location.has_value()) {
                                table_base_override =
                                    discover_recent_table_base_via_predecessor_chain_impl(snapshot,
                                                                                          entry_states,
                                                                                          owner_state_key,
                                                                                          logical_key(block.start),
                                                                                          target_provenance.source_location,
                                                                                          owner_state_entry.predecessor_key,
                                                                                          target_provenance.index_base_register);
                                uses_pair_table_layout =
                                    uses_recent_current_cs_pair_table_layout_via_predecessor_chain_impl(
                                        snapshot,
                                        entry_states,
                                        owner_state_key,
                                        logical_key(block.start),
                                        *target_provenance.source_location,
                                        owner_state_entry.predecessor_key,
                                        target_provenance.index_base_register);
                            }
                            const bool use_current_cs_pair_table =
                                target_provenance.kind == RegisterTargetProvenance::Kind::IndexedLoad &&
                                !site.is_far &&
                                is_known(target_provenance.segment_values) &&
                                singleton_value(target_provenance.segment_values) == instruction.cs &&
                                (uses_pair_table_layout ||
                                 uses_recent_current_cs_pair_table_layout(snapshot,
                                                                          target_provenance.source_location.value_or(site.from),
                                                                          target_provenance.index_base_register));
                            auto append_near_target = [&](const std::uint16_t target_ip) {
                                const CodeLocation target{
                                    site.is_far ? 0u : instruction.cs,
                                    target_ip,
                                };
                            if (!is_location_in_loaded_image(image, target)) {
                                ++skipped_candidates_total;
                                return;
                            }
                            const std::uint32_t target_key = logical_key(target);
                            const auto existing = std::find_if(site.resolved_targets.begin(),
                                                               site.resolved_targets.end(),
                                                               [&](const CodeLocation& candidate) {
                                                                   return logical_key(candidate) == target_key;
                                                               });
                            if (existing == site.resolved_targets.end()) {
                                site.resolved_targets.push_back(target);
                            }
                            owner_resolved = true;
                        };

                        if (use_current_cs_pair_table) {
                            owner_resolved =
                                append_current_cs_pair_table_targets(
                                    image,
                                    snapshot,
                                    site.from,
                                    target_provenance.index_base_register,
                                    site.resolved_targets,
                                    &site) ||
                                owner_resolved;
                        } else if (target_provenance.kind == RegisterTargetProvenance::Kind::IndexedLoad &&
                                   !site.is_far &&
                                   is_known(target_provenance.segment_values) &&
                                   singleton_value(target_provenance.segment_values) == instruction.cs &&
                                   is_known(target_provenance.index_values)) {
                            const KnownWord runtime_offsets =
                                add_known_word_and_displacement(target_provenance.index_values,
                                                                target_provenance.indexed_displacement);
                            const std::optional<std::uint16_t> effective_table_base =
                                table_base_override.has_value()
                                    ? table_base_override
                                    : infer_table_base_from_block_entry(target_provenance.index_base_register,
                                                                        target_provenance.source_location);
                            owner_resolved =
                                append_current_cs_word_table_targets_from_known_context(
                                    image,
                                    snapshot,
                                    site.from,
                                    effective_table_base,
                                    runtime_offsets,
                                    site.resolved_targets,
                                    &site,
                                    static_cast<std::uint8_t>(target_provenance.index_base_register)) ||
                                owner_resolved;
                        } else if (is_known(target_values)) {
                            for (const std::uint16_t target_ip : target_values.values) {
                                append_near_target(target_ip);
                            }
                            if (target_provenance.kind == RegisterTargetProvenance::Kind::IndexedLoad &&
                                !site.is_far &&
                                is_known(target_provenance.segment_values) &&
                                singleton_value(target_provenance.segment_values) == instruction.cs &&
                                target_provenance.source_location.has_value()) {
                                owner_resolved =
                                    append_current_cs_structured_table_targets(image,
                                                                              snapshot,
                                                                              site.from,
                                                                              target_provenance.index_base_register,
                                                                              use_current_cs_pair_table,
                                                                              site.resolved_targets,
                                                                              &site,
                                                                              table_base_override) ||
                                    owner_resolved;
                            }
                        } else {
                            switch (target_provenance.kind) {
                            case RegisterTargetProvenance::Kind::DirectMemoryLoad:
                            {
                                KnownWord candidate_values{};
                                if (is_known(target_provenance.segment_values)) {
                                    for (const std::uint16_t segment : target_provenance.segment_values.values) {
                                        const std::uint32_t physical = real_mode_phys(segment, target_provenance.direct_offset);
                                        const auto summary_it = direct_write_summary.physical_words.find(physical);
                                        if (summary_it != direct_write_summary.physical_words.end() &&
                                            is_known(summary_it->second)) {
                                            for (const std::uint16_t target_ip : summary_it->second.values) {
                                                merge_summary_word(candidate_values, target_ip);
                                            }
                                            continue;
                                        }
                                        try {
                                            merge_summary_word(
                                                candidate_values,
                                                read_memory_u16(image, segment, target_provenance.direct_offset));
                                        } catch (...) {
                                        }
                                    }
                                }
                                if (!is_known(candidate_values)) {
                                    const auto direct_offset_it =
                                        current.direct_offset_words.find(target_provenance.direct_offset);
                                    if (direct_offset_it != current.direct_offset_words.end()) {
                                        candidate_values = direct_offset_it->second;
                                    }
                                }
                                if (is_known(candidate_values)) {
                                    for (const std::uint16_t target_ip : candidate_values.values) {
                                        append_near_target(target_ip);
                                    }
                                }
                                if (!site.is_far) {
                                    const auto near_slot_it =
                                        direct_write_summary.near_pointer_slots.find(target_provenance.direct_offset);
                                    if (near_slot_it != direct_write_summary.near_pointer_slots.end()) {
                                        for (const CodeLocation target : near_slot_it->second) {
                                            const std::uint32_t target_key = logical_key(target);
                                            const auto existing = std::find_if(
                                                site.resolved_targets.begin(),
                                                site.resolved_targets.end(),
                                                [&](const CodeLocation& candidate) {
                                                    return logical_key(candidate) == target_key;
                                                });
                                            if (existing == site.resolved_targets.end()) {
                                                site.resolved_targets.push_back(target);
                                            }
                                            owner_resolved = true;
                                        }
                                    }
                                }
                                break;
                            }
                            case RegisterTargetProvenance::Kind::IndexedLoad:
                            {
                                const std::optional<std::uint16_t> effective_table_base =
                                    table_base_override.has_value()
                                        ? table_base_override
                                        : infer_table_base_from_block_entry(target_provenance.index_base_register,
                                                                            target_provenance.source_location);
                                append_segmented_word_targets(image,
                                                              direct_memory_overrides,
                                                              target_provenance.segment_values,
                                                              target_provenance.index_values,
                                                              target_provenance.indexed_displacement,
                                                              instruction.cs,
                                                              site.resolved_targets,
                                                              &skipped_candidates_total);
                                if (!owner_resolved &&
                                    !is_known(target_provenance.segment_values)) {
                                    owner_resolved =
                                        append_fallback_same_segment_word_targets(image,
                                                                                  direct_memory_overrides,
                                                                                  target_provenance.index_values,
                                                                                  target_provenance.indexed_displacement,
                                                                                  {instruction.cs, owner_root.cs},
                                                                                  instruction.cs,
                                                                                  site.resolved_targets,
                                                                                  &skipped_candidates_total) ||
                                        owner_resolved;
                                }
                                owner_resolved = !site.resolved_targets.empty() || owner_resolved;
                                if (!owner_resolved) {
                                    if (site.is_far && is_known(target_provenance.segment_values) &&
                                        singleton_value(target_provenance.segment_values) == instruction.cs) {
                                        owner_resolved =
                                            append_current_cs_pair_table_targets(
                                                image,
                                                snapshot,
                                                site.from,
                                                target_provenance.index_base_register,
                                                site.resolved_targets,
                                                &site) ||
                                            owner_resolved;
                                    } else if (!site.is_far &&
                                               is_known(target_provenance.segment_values) &&
                                               singleton_value(target_provenance.segment_values) == instruction.cs) {
                                        owner_resolved =
                                            append_current_cs_structured_table_targets(
                                                image,
                                                snapshot,
                                                site.from,
                                                target_provenance.index_base_register,
                                                uses_pair_table_layout ||
                                                    uses_recent_current_cs_pair_table_layout(
                                                        snapshot,
                                                        target_provenance.source_location.value_or(site.from),
                                                        target_provenance.index_base_register),
                                                site.resolved_targets,
                                                &site,
                                                effective_table_base) ||
                                            owner_resolved;
                                    }
                                }
                                if (!owner_resolved &&
                                    !site.is_far &&
                                    is_known(target_provenance.segment_values) &&
                                    singleton_value(target_provenance.segment_values) == instruction.cs &&
                                    target_provenance.source_location.has_value()) {
                                    owner_resolved =
                                        append_current_cs_indexed_targets_via_block_entry_replay(
                                            image,
                                            snapshot,
                                            entry_states,
                                            owner_state_key,
                                            block,
                                            site.from,
                                            *target_provenance.source_location,
                                            site.resolved_targets,
                                            &site) ||
                                        owner_resolved;
                                }
                                break;
                            }
                            case RegisterTargetProvenance::Kind::None:
                                if (const std::optional<std::uint16_t> predecessor_direct_offset =
                                        discover_register_provenance_direct_offset_via_predecessor_chain_impl(
                                            snapshot,
                                            entry_states,
                                            owner_state_key,
                                            owner_state_entry.predecessor_key,
                                            *register_target);
                                    predecessor_direct_offset.has_value()) {
                                    if (!site.is_far) {
                                        const auto near_slot_it =
                                            direct_write_summary.near_pointer_slots.find(*predecessor_direct_offset);
                                        if (near_slot_it != direct_write_summary.near_pointer_slots.end()) {
                                            for (const CodeLocation target : near_slot_it->second) {
                                                const std::uint32_t target_key = logical_key(target);
                                                const auto existing = std::find_if(
                                                    site.resolved_targets.begin(),
                                                    site.resolved_targets.end(),
                                                    [&](const CodeLocation& candidate) {
                                                        return logical_key(candidate) == target_key;
                                                    });
                                                if (existing == site.resolved_targets.end()) {
                                                    site.resolved_targets.push_back(target);
                                                }
                                                owner_resolved = true;
                                            }
                                        }
                                    } else {
                                        const auto far_slot_it =
                                            direct_write_summary.far_pointer_slots.find(*predecessor_direct_offset);
                                        if (far_slot_it != direct_write_summary.far_pointer_slots.end()) {
                                            for (const CodeLocation target : far_slot_it->second) {
                                                const std::uint32_t target_key = logical_key(target);
                                                const auto existing = std::find_if(
                                                    site.resolved_targets.begin(),
                                                    site.resolved_targets.end(),
                                                    [&](const CodeLocation& candidate) {
                                                        return logical_key(candidate) == target_key;
                                                    });
                                                if (existing == site.resolved_targets.end()) {
                                                    site.resolved_targets.push_back(target);
                                                }
                                                owner_resolved = true;
                                            }
                                        }
                                    }
                                }
                                if (!owner_resolved && !site.is_far) {
                                    if (const auto current_cs_load =
                                            discover_current_cs_indexed_load_via_predecessor_chain_impl(
                                                snapshot,
                                                entry_states,
                                                owner_state_key,
                                                logical_key(block.start),
                                                site.from,
                                                owner_state_entry.predecessor_key,
                                                *register_target);
                                        current_cs_load.has_value()) {
                                        const auto source_block_it = std::find_if(
                                            snapshot.blocks.begin(),
                                            snapshot.blocks.end(),
                                            [&](const BlockRecord& candidate) {
                                                return logical_key(candidate.start) ==
                                                       current_cs_load->block_key;
                                            });
                                        if (source_block_it != snapshot.blocks.end()) {
                                            owner_resolved =
                                                append_current_cs_indexed_targets_via_block_entry_replay(
                                                    image,
                                                    snapshot,
                                                    entry_states,
                                                    owner_state_key,
                                                    *source_block_it,
                                                    site.from,
                                                    current_cs_load->location,
                                                    site.resolved_targets,
                                                    &site) ||
                                                owner_resolved;
                                        }
                                    }
                                }
                                if (!owner_resolved && !site.is_far) {
                                    if (const auto current_cs_load =
                                            discover_current_cs_indexed_load_via_predecessor_chain_impl(
                                                snapshot,
                                                entry_states,
                                                owner_state_key,
                                                logical_key(block.start),
                                                site.from,
                                                owner_state_entry.predecessor_key,
                                                *register_target);
                                        current_cs_load.has_value()) {
                                        if (const auto table_base =
                                                discover_recent_table_base_via_predecessor_chain_impl(
                                                    snapshot,
                                                    entry_states,
                                                    owner_state_key,
                                                    current_cs_load->block_key,
                                                    current_cs_load->location,
                                                    current_cs_load->predecessor_key,
                                                    current_cs_load->base_register);
                                            table_base.has_value()) {
                                            const bool use_pair_table =
                                                uses_recent_current_cs_pair_table_layout(
                                                    snapshot,
                                                    current_cs_load->location,
                                                    current_cs_load->base_register);
                                            owner_resolved =
                                                (use_pair_table
                                                     ? append_current_cs_pair_table_targets_from_base(
                                                           image,
                                                           snapshot,
                                                           site.from,
                                                           *table_base,
                                                           site.resolved_targets,
                                                           &site,
                                                           static_cast<std::uint8_t>(current_cs_load->base_register))
                                                     : append_current_cs_word_table_targets_from_base(
                                                           image,
                                                           snapshot,
                                                           site.from,
                                                           *table_base,
                                                           site.resolved_targets,
                                                           &site,
                                                           static_cast<std::uint8_t>(current_cs_load->base_register))) ||
                                                owner_resolved;
                                        }
                                    }
                                }
                                break;
                            }
                        }

                        if (!site.is_far) {
                            const std::optional<std::uint16_t> table_base =
                                discover_cs_table_base_before_register_jump(
                                    block,
                                    instruction_index,
                                    *register_target,
                                    owner_root);
                            if (table_base.has_value()) {
                                owner_resolved =
                                    append_near_jump_table_targets(image, owner_root, *table_base, site.resolved_targets) ||
                                    owner_resolved;
                            }
                            if (!owner_resolved && owner_state_entry.predecessor_key != block_key) {
                                const CodeLocation predecessor_location = key_to_location(owner_state_entry.predecessor_key);
                                const auto predecessor_block_it = std::find_if(
                                    snapshot.blocks.begin(),
                                    snapshot.blocks.end(),
                                    [&](const BlockRecord& candidate) {
                                        return logical_key(candidate.start) == logical_key(predecessor_location);
                                    });
                                if (predecessor_block_it != snapshot.blocks.end()) {
                                    std::optional<Register16Id> predecessor_base_register;
                                    std::optional<CodeLocation> predecessor_load_location;
                                    const bool predecessor_loaded_from_current_cs = std::any_of(
                                        predecessor_block_it->preview.instructions.begin(),
                                        predecessor_block_it->preview.instructions.end(),
                                        [&](const DecodedInstruction& predecessor_instruction) {
                                            const std::optional<std::string> source_operand =
                                                mov_source_operand_text(predecessor_instruction);
                                            if (!source_operand.has_value()) {
                                                return false;
                                            }
                                            const std::size_t prefix_length = strip_prefix_bytes(predecessor_instruction);
                                            if (prefix_length >= predecessor_instruction.bytes.size() ||
                                                predecessor_instruction.bytes[prefix_length] != 0x8Bu ||
                                                !instruction_has_prefix(predecessor_instruction, 0x2Eu)) {
                                                return false;
                                            }
                                            const std::uint8_t modrm = predecessor_instruction.bytes[prefix_length + 1u];
                                            const auto dest =
                                                decode_register16(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
                                            if (!dest.has_value() || *dest != *register_target) {
                                                return false;
                                            }
                                            const auto indexed = parse_indexed_memory_operand_text(*source_operand);
                                            if (!indexed.has_value() || !indexed->uses_current_cs) {
                                                return false;
                                            }
                                            predecessor_base_register = indexed->base_register;
                                            predecessor_load_location =
                                                CodeLocation{predecessor_instruction.cs, predecessor_instruction.ip};
                                            return true;
                                        });
                                    if (predecessor_loaded_from_current_cs && predecessor_base_register.has_value()) {
                                        if (predecessor_load_location.has_value()) {
                                            owner_resolved =
                                                append_current_cs_indexed_targets_via_block_entry_replay(
                                                    image,
                                                    snapshot,
                                                    entry_states,
                                                    owner_state_key,
                                                    *predecessor_block_it,
                                                    site.from,
                                                    *predecessor_load_location,
                                                    site.resolved_targets,
                                                    &site) ||
                                                owner_resolved;
                                        }
                                        owner_resolved =
                                            append_current_cs_word_table_targets(
                                                image,
                                                snapshot,
                                                site.from,
                                                *predecessor_base_register,
                                                site.resolved_targets,
                                                &site) ||
                                            owner_resolved;
                                    }
                                }
                            }
                        }

                        if (owner_resolved) {
                            ++resolved_owner_contexts;
                        } else {
                            ++unresolved_owner_contexts;
                        }
                        break;
                    }

                    if (instruction.indirect.has_value() &&
                        instruction.indirect->operand_kind == IndirectOperandKind::MemoryComputed) {
                        const std::size_t prefix_length = strip_prefix_bytes(instruction);
                        const std::size_t modrm_index = prefix_length + 1u;
                        if (modrm_index >= instruction.bytes.size()) {
                            site.resolution_note = "indirect computed-memory operand is missing modrm";
                            return std::nullopt;
                        }

                        const std::uint8_t modrm = instruction.bytes[modrm_index];
                        const std::uint8_t mod = static_cast<std::uint8_t>((modrm >> 6u) & 0x03u);
                        const std::uint8_t rm = static_cast<std::uint8_t>(modrm & 0x07u);
                        const KnownWord pointer_segments =
                            instruction_memory_segment_values(current, instruction, mod, rm);
                        const KnownWord pointer_offsets =
                            resolve_modrm_memory_offset_values(current, instruction, prefix_length, mod, rm);
                        const auto try_current_cs_table_fallback = [&]() {
                            const std::optional<IndexedMemoryOperandInfo> indexed =
                                parse_indexed_memory_operand_text(site.operand_text);
                            if (!indexed.has_value() || !indexed->uses_current_cs) {
                                return false;
                            }
                            const std::optional<std::uint16_t> table_base =
                                infer_table_base_from_block_entry(indexed->base_register, std::nullopt);
                            if (!site.is_far &&
                                is_known(pointer_segments) &&
                                singleton_value(pointer_segments) == instruction.cs &&
                                is_known(pointer_offsets)) {
                                return append_current_cs_word_table_targets_from_known_context(
                                    image,
                                    snapshot,
                                    site.from,
                                    table_base,
                                    pointer_offsets,
                                    site.resolved_targets,
                                    &site,
                                    static_cast<std::uint8_t>(indexed->base_register));
                            }
                            if (site.is_far) {
                                return append_current_cs_pair_table_targets(
                                    image,
                                    snapshot,
                                    site.from,
                                    indexed->base_register,
                                    site.resolved_targets,
                                    &site);
                            }
                            return append_current_cs_word_table_targets(
                                image,
                                snapshot,
                                site.from,
                                indexed->base_register,
                                site.resolved_targets,
                                &site);
                        };
                        std::size_t bounded_table_skipped_candidates = 0u;
                        const auto try_bounded_same_segment_table_fallback = [&]() {
                            if (site.is_far) {
                                return false;
                            }
                            const std::optional<IndexedMemoryOperandInfo> indexed =
                                parse_indexed_memory_operand_text(site.operand_text);
                            if (!indexed.has_value() || indexed->uses_current_cs) {
                                return false;
                            }
                            const std::optional<std::uint16_t> table_base =
                                infer_table_base_from_block_entry(indexed->base_register, std::nullopt);
                            const std::optional<std::uint16_t> entry_count =
                                discover_unsigned_upper_bound_from_predecessor_fallthrough(
                                    snapshot,
                                    owner_state_entry.predecessor_key,
                                    block.start);
                            if (!table_base.has_value() || !entry_count.has_value() || *entry_count == 0u) {
                                return false;
                            }

                            bool changed = false;
                            std::set<std::uint16_t> candidate_segments;
                            if (is_known(pointer_segments)) {
                                candidate_segments.insert(pointer_segments.values.begin(), pointer_segments.values.end());
                            } else {
                                candidate_segments.insert(instruction.cs);
                                candidate_segments.insert(owner_root.cs);
                            }

                            for (const std::uint16_t segment : candidate_segments) {
                                changed =
                                    append_same_segment_bounded_word_table_targets(image,
                                                                                   segment,
                                                                                   *table_base,
                                                                                   *entry_count,
                                                                                   site.resolved_targets,
                                                                                   &bounded_table_skipped_candidates) ||
                                    changed;
                            }
                            return changed;
                        };
                        if (!is_known(pointer_segments) || !is_known(pointer_offsets)) {
                            if (try_current_cs_table_fallback()) {
                                owner_resolved = true;
                                ++resolved_owner_contexts;
                            } else if (try_bounded_same_segment_table_fallback()) {
                                owner_resolved = true;
                                skipped_candidates_total += bounded_table_skipped_candidates;
                                ++resolved_owner_contexts;
                            } else {
                                ++unresolved_owner_contexts;
                            }
                            break;
                        }

                        try {
                            std::size_t owner_skipped_candidates = 0;
                            bool owner_target_from_override = false;
                            const DirectMemoryValue target_ip_value = read_memory_word_from_candidates(
                                image,
                                direct_memory_overrides,
                                pointer_segments,
                                pointer_offsets);
                            if (!is_known(target_ip_value.value)) {
                                if (try_current_cs_table_fallback()) {
                                    owner_resolved = true;
                                    ++resolved_owner_contexts;
                                } else {
                                    ++unresolved_owner_contexts;
                                }
                                break;
                            }

                            KnownWord target_cs_values = make_known(instruction.cs);
                            DirectMemoryValue target_cs_value{};
                            if (site.is_far) {
                                target_cs_value = read_memory_word_from_candidates(
                                    image,
                                    direct_memory_overrides,
                                    pointer_segments,
                                    add_known_word_and_displacement(pointer_offsets, 2));
                                if (!is_known(target_cs_value.value)) {
                                    ++unresolved_owner_contexts;
                                    break;
                                }
                                target_cs_values = target_cs_value.value;
                            }

                            for (const std::uint16_t target_cs : target_cs_values.values) {
                                for (const std::uint16_t target_ip : target_ip_value.value.values) {
                                    const CodeLocation target{target_cs, target_ip};
                                    if (!is_location_in_loaded_image(image, target)) {
                                        ++owner_skipped_candidates;
                                        continue;
                                    }

                                    const std::uint32_t target_key = logical_key(target);
                                    const auto existing = std::find_if(site.resolved_targets.begin(),
                                                                       site.resolved_targets.end(),
                                                                       [&](const CodeLocation& candidate) {
                                                                           return logical_key(candidate) == target_key;
                                                                       });
                                    if (existing == site.resolved_targets.end()) {
                                        site.resolved_targets.push_back(target);
                                    }
                                    owner_resolved = true;
                                }
                            }

                            const std::optional<IndexedMemoryOperandInfo> indexed =
                                parse_indexed_memory_operand_text(site.operand_text);
                            if (!site.is_far &&
                                indexed.has_value() &&
                                indexed->uses_current_cs &&
                                is_known(pointer_segments) &&
                                singleton_value(pointer_segments) == instruction.cs &&
                                is_known(pointer_offsets)) {
                                const std::optional<std::uint16_t> table_base =
                                    infer_table_base_from_block_entry(indexed->base_register, std::nullopt);
                                owner_resolved =
                                    append_current_cs_word_table_targets_from_known_context(
                                        image,
                                        snapshot,
                                        site.from,
                                        table_base,
                                        pointer_offsets,
                                        site.resolved_targets,
                                        &site,
                                        static_cast<std::uint8_t>(indexed->base_register)) ||
                                    owner_resolved;
                            }
                            if (!owner_resolved) {
                                owner_resolved = try_bounded_same_segment_table_fallback() || owner_resolved;
                            }

                            skipped_candidates_total += owner_skipped_candidates;
                            skipped_candidates_total += bounded_table_skipped_candidates;
                            if (owner_resolved) {
                                owner_target_from_override =
                                    owner_target_from_override || target_ip_value.came_from_override;
                                owner_target_from_override =
                                    owner_target_from_override || target_cs_value.came_from_override;
                                ++resolved_owner_contexts;
                                target_from_override = target_from_override || owner_target_from_override;
                            } else {
                                ++unresolved_owner_contexts;
                            }
                        } catch (const std::exception& ex) {
                            site.resolution_note = ex.what();
                            return std::nullopt;
                        }
                        break;
                    }

                    if (!pointer_offset.has_value()) {
                        site.resolution_note = "indirect operand is not a direct memory pointer or tracked register";
                        return std::nullopt;
                    }

                    const KnownWord pointer_segments =
                        resolve_direct_segment_values(current, instruction, site.operand_text);
                    try {
                        std::size_t owner_skipped_candidates = 0;
                        bool owner_target_from_override = false;
                        if (!is_known(pointer_segments)) {
                            if (site.is_far) {
                                const auto local_far_slot_it = current.far_pointer_slots.find(*pointer_offset);
                                if (local_far_slot_it != current.far_pointer_slots.end()) {
                                    for (const CodeLocation& target : local_far_slot_it->second) {
                                        const std::uint32_t target_key = logical_key(target);
                                        const auto existing = std::find_if(site.resolved_targets.begin(),
                                                                           site.resolved_targets.end(),
                                                                           [&](const CodeLocation& candidate) {
                                                                               return logical_key(candidate) == target_key;
                                                                           });
                                        if (existing == site.resolved_targets.end()) {
                                            site.resolved_targets.push_back(target);
                                        }
                                        owner_resolved = true;
                                    }
                                }
                            }
                            if (!owner_resolved && site.is_far) {
                                const auto far_slot_it = direct_write_summary.far_pointer_slots.find(*pointer_offset);
                                if (far_slot_it != direct_write_summary.far_pointer_slots.end()) {
                                    for (const CodeLocation& target : far_slot_it->second) {
                                        const std::uint32_t target_key = logical_key(target);
                                        const auto existing = std::find_if(site.resolved_targets.begin(),
                                                                           site.resolved_targets.end(),
                                                                           [&](const CodeLocation& candidate) {
                                                                               return logical_key(candidate) == target_key;
                                                                           });
                                        if (existing == site.resolved_targets.end()) {
                                            site.resolved_targets.push_back(target);
                                        }
                                        owner_resolved = true;
                                    }
                                }
                            }
                            if (owner_resolved) {
                                ++resolved_owner_contexts;
                            } else {
                                ++unresolved_owner_contexts;
                            }
                            break;
                        }

                        for (const std::uint16_t pointer_segment : pointer_segments.values) {
                            const DirectMemoryValue target_ip_value = read_direct_memory_word(
                                image,
                                direct_memory_overrides,
                                make_known(pointer_segment),
                                *pointer_offset);
                            const std::optional<std::uint16_t> target_ip = singleton_value(target_ip_value.value);
                            if (!target_ip.has_value()) {
                                ++owner_skipped_candidates;
                                continue;
                            }

                            std::uint16_t target_cs = instruction.cs;
                            if (site.is_far) {
                                const DirectMemoryValue target_cs_value = read_direct_memory_word(
                                    image,
                                    direct_memory_overrides,
                                    make_known(pointer_segment),
                                    static_cast<std::uint16_t>(*pointer_offset + 2u));
                                const std::optional<std::uint16_t> target_cs_single =
                                    singleton_value(target_cs_value.value);
                                if (!target_cs_single.has_value()) {
                                    ++owner_skipped_candidates;
                                    continue;
                                }
                                target_cs = *target_cs_single;
                                owner_target_from_override =
                                    owner_target_from_override || target_cs_value.came_from_override;
                            }

                            const CodeLocation target{target_cs, *target_ip};
                            if (!is_location_in_loaded_image(image, target)) {
                                ++owner_skipped_candidates;
                                continue;
                            }

                            const std::uint32_t target_key = logical_key(target);
                            const auto existing = std::find_if(site.resolved_targets.begin(),
                                                               site.resolved_targets.end(),
                                                               [&](const CodeLocation& candidate) {
                                                                   return logical_key(candidate) == target_key;
                                                               });
                            if (existing == site.resolved_targets.end()) {
                                site.resolved_targets.push_back(target);
                            }
                            owner_target_from_override =
                                owner_target_from_override || target_ip_value.came_from_override;
                            owner_resolved = true;
                        }

                        if (!owner_resolved && site.is_far) {
                            const auto local_far_slot_it = current.far_pointer_slots.find(*pointer_offset);
                            if (local_far_slot_it != current.far_pointer_slots.end()) {
                                for (const CodeLocation& target : local_far_slot_it->second) {
                                    const std::uint32_t target_key = logical_key(target);
                                    const auto existing = std::find_if(site.resolved_targets.begin(),
                                                                       site.resolved_targets.end(),
                                                                       [&](const CodeLocation& candidate) {
                                                                           return logical_key(candidate) == target_key;
                                                                       });
                                    if (existing == site.resolved_targets.end()) {
                                        site.resolved_targets.push_back(target);
                                    }
                                    owner_resolved = true;
                                }
                            }
                        }

                        if (!owner_resolved && site.is_far) {
                            const auto far_slot_it = direct_write_summary.far_pointer_slots.find(*pointer_offset);
                            if (far_slot_it != direct_write_summary.far_pointer_slots.end()) {
                                for (const CodeLocation& target : far_slot_it->second) {
                                    const std::uint32_t target_key = logical_key(target);
                                    const auto existing = std::find_if(site.resolved_targets.begin(),
                                                                       site.resolved_targets.end(),
                                                                       [&](const CodeLocation& candidate) {
                                                                           return logical_key(candidate) == target_key;
                                                                       });
                                    if (existing == site.resolved_targets.end()) {
                                        site.resolved_targets.push_back(target);
                                    }
                                    owner_resolved = true;
                                }
                            }
                        }

                        skipped_candidates_total += owner_skipped_candidates;
                        if (owner_resolved) {
                            ++resolved_owner_contexts;
                            target_from_override = target_from_override || owner_target_from_override;
                        } else {
                            ++unresolved_owner_contexts;
                        }
                    } catch (const std::exception& ex) {
                        site.resolution_note = ex.what();
                        return std::nullopt;
                    }
                        break;
                    }

                if (register_target.has_value()) {
                    const std::size_t local_prefix_length = strip_prefix_bytes(instruction);
                    if (local_prefix_length < instruction.bytes.size()) {
                        const std::uint8_t local_opcode = instruction.bytes[local_prefix_length];
                        bool writes_target_register = false;
                        RegisterTargetProvenance next_provenance{};

                        if (local_opcode >= 0xB8u && local_opcode <= 0xBFu) {
                            const auto dest = decode_register16(static_cast<std::uint8_t>(local_opcode - 0xB8u));
                            writes_target_register = dest.has_value() && *dest == *register_target;
                        } else if (local_opcode == 0xA1u && *register_target == Register16Id::AX) {
                            writes_target_register = true;
                            const std::optional<std::string> source_operand = mov_source_operand_text(instruction);
                            if (source_operand.has_value() && is_simple_direct_memory_operand_text(*source_operand)) {
                                const std::optional<std::uint16_t> offset = direct_operand_offset_from_text(*source_operand);
                                if (offset.has_value()) {
                                    next_provenance.kind = RegisterTargetProvenance::Kind::DirectMemoryLoad;
                                    next_provenance.segment_values =
                                        resolve_direct_segment_values(current, instruction, *source_operand);
                                    next_provenance.direct_offset = *offset;
                                }
                            }
                        } else if (local_opcode == 0x8Bu && local_prefix_length + 1u < instruction.bytes.size()) {
                            const std::uint8_t modrm = instruction.bytes[local_prefix_length + 1u];
                            const auto dest = decode_register16(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
                            writes_target_register = dest.has_value() && *dest == *register_target;
                            if (writes_target_register) {
                                const std::optional<std::string> source_operand = mov_source_operand_text(instruction);
                                if (source_operand.has_value()) {
                                    if (is_simple_direct_memory_operand_text(*source_operand)) {
                                        const std::optional<std::uint16_t> offset =
                                            direct_operand_offset_from_text(*source_operand);
                                        if (offset.has_value()) {
                                            next_provenance.kind = RegisterTargetProvenance::Kind::DirectMemoryLoad;
                                            next_provenance.segment_values =
                                                resolve_direct_segment_values(current, instruction, *source_operand);
                                            next_provenance.direct_offset = *offset;
                                        }
                                    } else {
                                        const std::optional<IndexedMemoryOperandInfo> indexed =
                                            parse_indexed_memory_operand_text(*source_operand);
                                        if (indexed.has_value()) {
                                            const std::uint8_t mod =
                                                static_cast<std::uint8_t>((modrm >> 6u) & 0x03u);
                                            const std::uint8_t rm =
                                                static_cast<std::uint8_t>(modrm & 0x07u);
                                            next_provenance.kind = RegisterTargetProvenance::Kind::IndexedLoad;
                                            next_provenance.segment_values =
                                                resolve_direct_segment_values(current, instruction, *source_operand);
                                            if (!is_known(next_provenance.segment_values)) {
                                                next_provenance.segment_values =
                                                    instruction_memory_segment_values(current, instruction, mod, rm);
                                            }
                                            next_provenance.index_values =
                                                register_ref(current, indexed->base_register);
                                            next_provenance.index_base_register = indexed->base_register;
                                            next_provenance.indexed_displacement = indexed->displacement;
                                            next_provenance.source_location =
                                                CodeLocation{instruction.cs, instruction.ip};
                                        }
                                    }
                                }
                            }
                        } else if (local_opcode == 0xC4u || local_opcode == 0xC5u) {
                            if (local_prefix_length + 1u < instruction.bytes.size()) {
                                const std::uint8_t modrm = instruction.bytes[local_prefix_length + 1u];
                                const auto dest = decode_register16(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
                                writes_target_register = dest.has_value() && *dest == *register_target;
                            }
                        } else if (local_opcode >= 0x58u && local_opcode <= 0x5Fu) {
                            const auto dest = decode_register16(static_cast<std::uint8_t>(local_opcode - 0x58u));
                            writes_target_register = dest.has_value() && *dest == *register_target;
                        } else if ((local_opcode & 0xF8u) == 0x90u && (local_opcode & 0x07u) != 0u) {
                            const std::uint8_t reg = static_cast<std::uint8_t>(local_opcode & 0x07u);
                            writes_target_register =
                                (*register_target == Register16Id::AX) ||
                                (decode_register16(reg).has_value() && *decode_register16(reg) == *register_target);
                        }

                        if (writes_target_register) {
                            target_provenance = next_provenance;
                        }
                    }
                }

                apply_instruction_effect(image, instruction, current, direct_memory_overrides, abstract_stack);
            }
        }

        if (site.resolved_targets.empty()) {
            if (unresolved_owner_contexts > 0u || skipped_candidates_total > 0u) {
                site.resolution_note = "context-partitioned states did not produce an in-image static target";
            } else {
                site.resolution_note = "indirect site context was not reached by current analysis";
            }
            return std::nullopt;
        }

        prune_overlapping_indirect_targets(snapshot, site);
        if (site.resolved_targets.empty()) {
            if (site.resolution_note.empty()) {
                site.resolution_note = "all resolved targets overlapped existing decoded block interiors";
            }
            return std::nullopt;
        }

        std::ostringstream note;
        note << "resolved from context-partitioned abstract state and direct memory";
        if (resolved_owner_contexts > 1u) {
            note << " across " << resolved_owner_contexts << " contexts";
        }
        if (site.resolved_targets.size() > 1u) {
            note << " with " << site.resolved_targets.size() << " candidate targets";
        }
        if (unresolved_owner_contexts > 0u) {
            note << "; unresolved contexts=" << unresolved_owner_contexts;
        }
        if (skipped_candidates_total > 0u) {
            note << "; skipped candidate segments=" << skipped_candidates_total;
        }
        if (target_from_override) {
            note << " with same-block stores";
        }
        site.resolution_note = note.str();
        return site.resolved_targets.front();
    }

    site.resolution_note = "indirect site is outside the current decoded block set";
    return std::nullopt;
}

void refine_indirect_sites_with_analysis(const MzImage& image, CfgSnapshot& snapshot) {
    if (snapshot.indirect_sites.empty()) {
        return;
    }

    const std::map<std::uint64_t, std::map<std::uint32_t, AbstractState>> entry_states =
        analyze_rooted_block_entry_states(image, snapshot);
    const DirectWriteSummary direct_write_summary =
        collect_direct_write_summary(snapshot, entry_states, image);
    std::set<std::uint64_t> emitted_edges;
    std::set<std::uint32_t> function_roots;
    for (const CfgEdge& edge : snapshot.edges) {
        emitted_edges.insert(edge_key(edge));
    }
    for (const CodeLocation root : snapshot.discovered_function_roots) {
        function_roots.insert(logical_key(root));
    }

    for (IndirectSiteRecord& site : snapshot.indirect_sites) {
        if (!resolve_indirect_site_with_analysis(image, snapshot, entry_states, direct_write_summary, site).has_value()) {
            continue;
        }
        for (const CodeLocation target : site.resolved_targets) {
            append_edge(snapshot, emitted_edges, CfgEdge{site.from, target, site.kind});
            if (site.kind == EdgeKind::Call) {
                function_roots.insert(logical_key(target));
            }
        }
    }

    snapshot.discovered_function_roots.clear();
    snapshot.discovered_function_roots.reserve(function_roots.size());
    for (const std::uint32_t key : function_roots) {
        snapshot.discovered_function_roots.push_back(key_to_location(key));
    }
    std::sort(snapshot.discovered_function_roots.begin(),
              snapshot.discovered_function_roots.end(),
              [](const CodeLocation& lhs, const CodeLocation& rhs) {
                  return logical_key(lhs) < logical_key(rhs);
              });
}

std::size_t resolved_target_count(const CfgSnapshot& snapshot) {
    std::size_t count = 0;
    for (const IndirectSiteRecord& site : snapshot.indirect_sites) {
        count += site.resolved_targets.size();
    }
    return count;
}

std::string format_known_word_debug(const KnownWord& value) {
    if (!is_known(value)) {
        return "?";
    }
    std::ostringstream oss;
    for (std::size_t i = 0; i < value.values.size(); ++i) {
        if (i != 0u) {
            oss << ", ";
        }
        oss << hex16(value.values[i]);
    }
    return oss.str();
}

void sync_function_roots(CfgSnapshot& snapshot, const std::set<std::uint32_t>& function_roots) {
    snapshot.discovered_function_roots.clear();
    snapshot.discovered_function_roots.reserve(function_roots.size());
    for (const std::uint32_t key : function_roots) {
        snapshot.discovered_function_roots.push_back(key_to_location(key));
    }
    std::sort(snapshot.discovered_function_roots.begin(),
              snapshot.discovered_function_roots.end(),
              [](const CodeLocation& lhs, const CodeLocation& rhs) {
                  return logical_key(lhs) < logical_key(rhs);
              });
}

void enqueue_pending_edge_targets(const MzImage& image,
                                  const CfgSnapshot& snapshot,
                                  const std::set<std::uint32_t>& emitted_blocks,
                                  std::deque<CodeLocation>& worklist,
                                  std::set<std::uint32_t>& enqueued) {
    for (const CfgEdge& edge : snapshot.edges) {
        const std::uint32_t key = logical_key(edge.to);
        if (emitted_blocks.contains(key)) {
            continue;
        }
        if (!is_location_in_loaded_image(image, edge.to)) {
            continue;
        }
        enqueue_if_new(worklist, enqueued, edge.to);
    }
}

void process_cfg_worklist(const MzImage& image,
                         CfgSnapshot& snapshot,
                         const std::size_t max_blocks,
                         const std::size_t max_instructions_per_block,
                         std::deque<CodeLocation>& worklist,
                         std::set<std::uint32_t>& enqueued,
                         std::set<std::uint32_t>& emitted_blocks,
                         std::set<std::uint32_t>& function_roots,
                         std::set<std::uint64_t>& emitted_edges) {
    const std::size_t block_budget =
        (max_blocks == 0u) ? std::numeric_limits<std::size_t>::max() : max_blocks;

    while (!worklist.empty() && snapshot.blocks.size() < block_budget) {
        const CodeLocation location = worklist.front();
        worklist.pop_front();

        const std::uint32_t block_key = logical_key(location);
        if (!emitted_blocks.insert(block_key).second) {
            continue;
        }

        BlockRecord record{};
        record.start = location;
        record.preview = decode_basic_block_preview(image, location.cs, location.ip, max_instructions_per_block);

        for (const DecodedInstruction& instruction : record.preview.instructions) {
            if (instruction.flow != FlowKind::Call) {
                continue;
            }

            if (const std::optional<CodeLocation> direct_target = direct_target_of(instruction);
                direct_target.has_value()) {
                append_edge(snapshot,
                            emitted_edges,
                            CfgEdge{CodeLocation{instruction.cs, instruction.ip}, *direct_target, EdgeKind::Call});
                function_roots.insert(logical_key(*direct_target));
                enqueue_if_new(worklist, enqueued, *direct_target);
                continue;
            }

            if (instruction.indirect.has_value()) {
                IndirectSiteRecord site = build_indirect_site_record(image, instruction);
                for (const CodeLocation target : site.resolved_targets) {
                    append_edge(snapshot,
                                emitted_edges,
                                CfgEdge{CodeLocation{instruction.cs, instruction.ip}, target, EdgeKind::Call});
                    function_roots.insert(logical_key(target));
                    enqueue_if_new(worklist, enqueued, target);
                }
                snapshot.indirect_sites.push_back(std::move(site));
            }
        }

        if (!record.preview.instructions.empty()) {
            const DecodedInstruction& terminal = record.preview.instructions.back();
            if (terminal.flow == FlowKind::ConditionalBranch) {
                if (const std::optional<CodeLocation> direct_target = direct_target_of(terminal);
                    direct_target.has_value()) {
                    append_edge(snapshot,
                                emitted_edges,
                                CfgEdge{CodeLocation{terminal.cs, terminal.ip}, *direct_target, EdgeKind::Branch});
                    enqueue_if_new(worklist, enqueued, *direct_target);
                }
            }
            if (terminal.flow == FlowKind::ConditionalBranch && terminal.branch_fallthrough_ip.has_value()) {
                const CodeLocation target{terminal.cs, *terminal.branch_fallthrough_ip};
                append_edge(snapshot,
                            emitted_edges,
                            CfgEdge{CodeLocation{terminal.cs, terminal.ip}, target, EdgeKind::Fallthrough});
                enqueue_if_new(worklist, enqueued, target);
            } else if (terminal.flow == FlowKind::UnconditionalBranch) {
                if (const std::optional<CodeLocation> direct_target = direct_target_of(terminal);
                    direct_target.has_value()) {
                    append_edge(snapshot,
                                emitted_edges,
                                CfgEdge{CodeLocation{terminal.cs, terminal.ip}, *direct_target, EdgeKind::Branch});
                    enqueue_if_new(worklist, enqueued, *direct_target);
                } else if (terminal.indirect.has_value()) {
                    IndirectSiteRecord site = build_indirect_site_record(image, terminal);
                    for (const CodeLocation target : site.resolved_targets) {
                        append_edge(snapshot,
                                    emitted_edges,
                                    CfgEdge{CodeLocation{terminal.cs, terminal.ip}, target, EdgeKind::Branch});
                        enqueue_if_new(worklist, enqueued, target);
                    }
                    snapshot.indirect_sites.push_back(std::move(site));
                }
            } else if (preview_has_implicit_fallthrough(record.preview) &&
                       terminal.branch_fallthrough_ip.has_value()) {
                const CodeLocation target{terminal.cs, *terminal.branch_fallthrough_ip};
                append_edge(snapshot,
                            emitted_edges,
                            CfgEdge{CodeLocation{terminal.cs, terminal.ip}, target, EdgeKind::Fallthrough});
                enqueue_if_new(worklist, enqueued, target);
            }
        }

        snapshot.blocks.push_back(std::move(record));
    }
}

std::vector<CodeLocation> discover_interrupt_install_roots(const MzImage& image, const CfgSnapshot& snapshot) {
    std::set<std::uint32_t> discovered;

    for (const BlockRecord& block : snapshot.blocks) {
        std::vector<std::optional<std::uint16_t>> value_stack;
        std::optional<std::uint16_t> ax_value;
        std::optional<std::uint16_t> dx_value;
        std::optional<std::uint16_t> ds_value;

        for (const DecodedInstruction& instruction : block.preview.instructions) {
            const std::string_view text = instruction.text;

            if (const std::optional<std::uint16_t> ax_imm = parse_mov_imm16(text, "ax"); ax_imm.has_value()) {
                ax_value = ax_imm;
            } else if (text == "mov ax, cs") {
                ax_value = instruction.cs;
            } else if (text == "mov ax, ds") {
                ax_value = ds_value;
            } else if (const std::optional<std::uint16_t> dx_imm = parse_mov_imm16(text, "dx"); dx_imm.has_value()) {
                dx_value = dx_imm;
            } else if (text == "mov ds, ax") {
                ds_value = ax_value;
            } else if (text == "push cs") {
                value_stack.push_back(instruction.cs);
            } else if (text == "push ds") {
                value_stack.push_back(ds_value);
            } else if (text == "push ax") {
                value_stack.push_back(ax_value);
            } else if (text == "push dx") {
                value_stack.push_back(dx_value);
            } else if (text == "pop ds") {
                if (!value_stack.empty()) {
                    ds_value = value_stack.back();
                    value_stack.pop_back();
                } else {
                    ds_value.reset();
                }
            } else if (starts_with(text, "pop ")) {
                if (!value_stack.empty()) {
                    value_stack.pop_back();
                }
            }

            if (!is_interrupt_instruction(instruction, 0x21u) || !ax_value.has_value() || !dx_value.has_value()) {
                continue;
            }
            if (((*ax_value >> 8u) & 0x00FFu) != 0x25u) {
                continue;
            }

            std::uint16_t target_segment = ds_value.value_or(instruction.cs);
            CodeLocation target{target_segment, *dx_value};
            if (!is_location_in_loaded_image(image, target)) {
                target_segment = instruction.cs;
                target = CodeLocation{target_segment, *dx_value};
            }
            if (!is_location_in_loaded_image(image, target)) {
                continue;
            }
            discovered.insert(logical_key(target));
        }
    }

    std::vector<CodeLocation> roots;
    roots.reserve(discovered.size());
    for (const std::uint32_t key : discovered) {
        roots.push_back(key_to_location(key));
    }
    std::sort(roots.begin(), roots.end(), location_less);
    return roots;
}

void summarize_functions(CfgSnapshot& snapshot) {
    std::set<std::uint32_t> block_keys;
    std::map<std::uint32_t, std::vector<std::uint32_t>> instruction_to_block_keys;
    std::map<std::uint32_t, std::vector<std::uint32_t>> outgoing_intra_edges;
    std::map<std::uint32_t, std::vector<std::uint32_t>> incoming_intra_edges;
    std::map<std::uint32_t, std::set<std::uint32_t>> block_reachers;

    for (const BlockRecord& block : snapshot.blocks) {
        const std::uint32_t block_key = logical_key(block.start);
        block_keys.insert(block_key);
        instruction_to_block_keys[block_key].push_back(block_key);
        for (const DecodedInstruction& instruction : block.preview.instructions) {
            instruction_to_block_keys[logical_key(CodeLocation{instruction.cs, instruction.ip})].push_back(block_key);
        }
    }

    for (const CfgEdge& edge : snapshot.edges) {
        if (edge.kind == EdgeKind::Call) {
            continue;
        }
        const auto from_it = instruction_to_block_keys.find(logical_key(edge.from));
        if (from_it == instruction_to_block_keys.end()) {
            continue;
        }
        const std::uint32_t to_key = logical_key(edge.to);
        if (!block_keys.contains(to_key)) {
            continue;
        }
        for (const std::uint32_t from_key : from_it->second) {
            std::vector<std::uint32_t>& outgoing = outgoing_intra_edges[from_key];
            if (std::find(outgoing.begin(), outgoing.end(), to_key) == outgoing.end()) {
                outgoing.push_back(to_key);
            }
            std::vector<std::uint32_t>& incoming = incoming_intra_edges[to_key];
            if (std::find(incoming.begin(), incoming.end(), from_key) == incoming.end()) {
                incoming.push_back(from_key);
            }
        }
    }

    snapshot.functions.clear();
    snapshot.functions.reserve(snapshot.discovered_function_roots.size());
    snapshot.block_ownerships.clear();

    for (const CodeLocation root : snapshot.discovered_function_roots) {
        FunctionRecord function{};
        function.entry = root;

        const std::uint32_t root_key = logical_key(root);
        function.entry_block_present = block_keys.contains(root_key);
        if (!function.entry_block_present) {
            snapshot.functions.push_back(std::move(function));
            continue;
        }

        std::deque<std::uint32_t> worklist;
        std::set<std::uint32_t> visited;
        worklist.push_back(root_key);
        visited.insert(root_key);

        while (!worklist.empty()) {
            const std::uint32_t key = worklist.front();
            worklist.pop_front();
            block_reachers[key].insert(root_key);
            function.reachable_blocks.push_back(key_to_location(key));

            const auto edge_it = outgoing_intra_edges.find(key);
            if (edge_it == outgoing_intra_edges.end()) {
                continue;
            }
            for (const std::uint32_t next_key : edge_it->second) {
                if (visited.insert(next_key).second) {
                    worklist.push_back(next_key);
                }
            }
        }

        snapshot.functions.push_back(std::move(function));
    }

    for (FunctionRecord& function : snapshot.functions) {
        if (!function.entry_block_present) {
            continue;
        }
        const std::uint32_t function_root_key = logical_key(function.entry);

        std::set<std::uint32_t> reachable_keys;
        for (const CodeLocation block : function.reachable_blocks) {
            reachable_keys.insert(logical_key(block));
        }

        std::set<std::uint32_t> external_entry_keys;
        for (const CodeLocation block : function.reachable_blocks) {
            const std::uint32_t block_key = logical_key(block);
            const std::set<std::uint32_t>& reachers = block_reachers[block_key];
            if (reachers.size() > 1u) {
                function.shared_blocks.push_back(block);
            } else {
                function.owned_blocks.push_back(block);
            }

            const auto incoming_it = incoming_intra_edges.find(block_key);
            if (incoming_it == incoming_intra_edges.end()) {
                continue;
            }
            for (const std::uint32_t source_key : incoming_it->second) {
                if (!reachable_keys.contains(source_key)) {
                    external_entry_keys.insert(block_key);
                    break;
                }
            }
        }

        for (const std::uint32_t key : external_entry_keys) {
            function.external_entry_blocks.push_back(key_to_location(key));
        }

        const auto build_fragment =
            [&](const std::uint32_t start_key,
                const std::set<std::uint32_t>& blocked_external_entries) -> std::set<std::uint32_t> {
                std::deque<std::uint32_t> worklist;
                std::set<std::uint32_t> visited;
                worklist.push_back(start_key);
                visited.insert(start_key);

                while (!worklist.empty()) {
                    const std::uint32_t key = worklist.front();
                    worklist.pop_front();

                    const auto edge_it = outgoing_intra_edges.find(key);
                    if (edge_it == outgoing_intra_edges.end()) {
                        continue;
                    }
                    for (const std::uint32_t next_key : edge_it->second) {
                        if (!reachable_keys.contains(next_key)) {
                            continue;
                        }
                        if (next_key != start_key && blocked_external_entries.contains(next_key)) {
                            continue;
                        }
                        if (visited.insert(next_key).second) {
                            worklist.push_back(next_key);
                        }
                    }
                }

                return visited;
            };

        const std::set<std::uint32_t> primary_fragment_keys = build_fragment(function_root_key, external_entry_keys);
        std::map<std::uint32_t, std::size_t> fragment_cover_count;
        std::map<std::uint32_t, std::set<std::uint32_t>> fragment_keys_by_entry;

        for (const std::uint32_t key : primary_fragment_keys) {
            ++fragment_cover_count[key];
        }

        for (const std::uint32_t entry_key : external_entry_keys) {
            std::set<std::uint32_t> blocked_entries = external_entry_keys;
            blocked_entries.erase(entry_key);
            std::set<std::uint32_t> fragment_keys = build_fragment(entry_key, blocked_entries);
            fragment_keys_by_entry.emplace(entry_key, fragment_keys);
            for (const std::uint32_t key : fragment_keys) {
                ++fragment_cover_count[key];
            }
        }

        for (const std::uint32_t entry_key : external_entry_keys) {
            FunctionRecord::EntryFragmentRecord fragment{};
            fragment.entry_block = key_to_location(entry_key);

            const auto incoming_it = incoming_intra_edges.find(entry_key);
            if (incoming_it != incoming_intra_edges.end()) {
                std::set<std::uint32_t> incoming_sources;
                for (const std::uint32_t source_key : incoming_it->second) {
                    if (!reachable_keys.contains(source_key)) {
                        incoming_sources.insert(source_key);
                    }
                }
                for (const std::uint32_t source_key : incoming_sources) {
                    fragment.incoming_from_blocks.push_back(key_to_location(source_key));
                }
            }
            sort_locations(fragment.incoming_from_blocks);

            const std::set<std::uint32_t>& fragment_keys = fragment_keys_by_entry[entry_key];
            for (const std::uint32_t key : fragment_keys) {
                fragment.reachable_blocks.push_back(key_to_location(key));
                const bool in_primary_fragment = primary_fragment_keys.contains(key);
                const bool covered_multiple_times = fragment_cover_count[key] > 1u;
                if (!in_primary_fragment && !covered_multiple_times) {
                    fragment.clone_candidate_blocks.push_back(key_to_location(key));
                } else {
                    fragment.shared_blocks.push_back(key_to_location(key));
                }
            }

            std::set<std::uint32_t> exit_targets;
            for (const std::uint32_t key : fragment_keys) {
                const auto edge_it = outgoing_intra_edges.find(key);
                if (edge_it == outgoing_intra_edges.end()) {
                    continue;
                }
                for (const std::uint32_t next_key : edge_it->second) {
                    if (!reachable_keys.contains(next_key)) {
                        continue;
                    }
                    if (!fragment_keys.contains(next_key)) {
                        exit_targets.insert(next_key);
                    }
                }
            }
            for (const std::uint32_t exit_key : exit_targets) {
                fragment.exit_to_blocks.push_back(key_to_location(exit_key));
            }

            sort_locations(fragment.reachable_blocks);
            sort_locations(fragment.clone_candidate_blocks);
            sort_locations(fragment.shared_blocks);
            sort_locations(fragment.exit_to_blocks);
            fragment.disposition = classify_fragment_disposition(fragment);
            fragment.lowering_action = classify_fragment_lowering_action(fragment);

            function.entry_fragments.push_back(std::move(fragment));
        }
    }

    for (const std::uint32_t block_key : block_keys) {
        BlockOwnershipRecord ownership{};
        ownership.block = key_to_location(block_key);
        const auto reachers_it = block_reachers.find(block_key);
        if (reachers_it != block_reachers.end()) {
            for (const std::uint32_t owner_key : reachers_it->second) {
                ownership.owners.push_back(key_to_location(owner_key));
            }
        }
        snapshot.block_ownerships.push_back(std::move(ownership));
    }

    std::sort(snapshot.block_ownerships.begin(),
              snapshot.block_ownerships.end(),
              [](const BlockOwnershipRecord& lhs, const BlockOwnershipRecord& rhs) {
                  return logical_key(lhs.block) < logical_key(rhs.block);
              });
}

} // namespace

CfgSnapshot build_cfg_snapshot(const MzImage& image,
                               const CodeLocation root,
                               const std::size_t max_blocks,
                               const std::size_t max_instructions_per_block,
                               const std::vector<CodeLocation>& additional_roots) {
    CfgSnapshot snapshot{};
    snapshot.root = root;

    std::deque<CodeLocation> worklist;
    std::set<std::uint32_t> enqueued;
    std::set<std::uint32_t> emitted_blocks;
    std::set<std::uint32_t> function_roots;
    std::set<std::uint32_t> seeded_roots;
    std::set<std::uint64_t> emitted_edges;
    enqueue_if_new(worklist, enqueued, root);
    function_roots.insert(logical_key(root));
    seeded_roots.insert(logical_key(root));
    for (const CodeLocation extra_root : additional_roots) {
        if (!is_location_in_loaded_image(image, extra_root)) {
            continue;
        }
        enqueue_if_new(worklist, enqueued, extra_root);
        function_roots.insert(logical_key(extra_root));
        seeded_roots.insert(logical_key(extra_root));
    }
    process_cfg_worklist(image,
                         snapshot,
                         max_blocks,
                         max_instructions_per_block,
                         worklist,
                         enqueued,
                         emitted_blocks,
                         function_roots,
                         emitted_edges);
    sync_function_roots(snapshot, function_roots);

    for (;;) {
        const std::size_t block_count_before = snapshot.blocks.size();
        const std::size_t edge_count_before = snapshot.edges.size();
        const std::size_t root_count_before = snapshot.discovered_function_roots.size();
        const std::size_t resolved_before = resolved_target_count(snapshot);

        refine_indirect_sites_with_analysis(image, snapshot);
        for (const CodeLocation root_location : snapshot.discovered_function_roots) {
            function_roots.insert(logical_key(root_location));
        }
        for (const std::uint32_t seeded_root_key : seeded_roots) {
            function_roots.insert(seeded_root_key);
        }
        for (const CodeLocation interrupt_root : discover_interrupt_install_roots(image, snapshot)) {
            if (function_roots.insert(logical_key(interrupt_root)).second) {
                enqueue_if_new_front(worklist, enqueued, interrupt_root);
            }
        }
        sync_function_roots(snapshot, function_roots);

        enqueue_pending_edge_targets(image, snapshot, emitted_blocks, worklist, enqueued);
        process_cfg_worklist(image,
                             snapshot,
                             max_blocks,
                             max_instructions_per_block,
                             worklist,
                             enqueued,
                             emitted_blocks,
                             function_roots,
                             emitted_edges);
        sync_function_roots(snapshot, function_roots);

        if (snapshot.blocks.size() == block_count_before &&
            snapshot.edges.size() == edge_count_before &&
            snapshot.discovered_function_roots.size() == root_count_before &&
            resolved_target_count(snapshot) == resolved_before) {
            break;
        }
    }

    {
        const std::vector<CodeLocation> interrupt_roots = discover_interrupt_install_roots(image, snapshot);
        std::size_t missing_interrupt_root_count = 0u;
        for (const CodeLocation root_location : interrupt_roots) {
            if (!emitted_blocks.contains(logical_key(root_location))) {
                enqueue_if_new_front(worklist, enqueued, root_location);
                ++missing_interrupt_root_count;
            }
        }
        if (missing_interrupt_root_count != 0u) {
            const std::size_t extended_block_budget = snapshot.blocks.size() + missing_interrupt_root_count * 128u;
            process_cfg_worklist(image,
                                 snapshot,
                                 extended_block_budget,
                                 max_instructions_per_block,
                                 worklist,
                                 enqueued,
                                 emitted_blocks,
                                 function_roots,
                                 emitted_edges);
            sync_function_roots(snapshot, function_roots);
        }
    }

    snapshot.interface_surfaces = collect_benchmark_interface_surfaces(image, snapshot);
    seed_interface_surface_roots(snapshot.interface_surfaces, worklist, enqueued, function_roots, seeded_roots);
    sync_function_roots(snapshot, function_roots);

    {
        std::size_t missing_seed_root_count = 0u;
        for (const std::uint32_t root_key : seeded_roots) {
            function_roots.insert(root_key);
            if (!emitted_blocks.contains(root_key)) {
                enqueue_if_new_front(worklist, enqueued, key_to_location(root_key));
                ++missing_seed_root_count;
            }
        }
        if (missing_seed_root_count != 0u) {
            const std::size_t extended_block_budget =
                (max_blocks == 0u)
                    ? std::numeric_limits<std::size_t>::max()
                    : snapshot.blocks.size() + missing_seed_root_count * 128u;
            process_cfg_worklist(image,
                                 snapshot,
                                 extended_block_budget,
                                 max_instructions_per_block,
                                 worklist,
                                 enqueued,
                                 emitted_blocks,
                                 function_roots,
                                 emitted_edges);
        }
        sync_function_roots(snapshot, function_roots);
    }

    {
        std::deque<CodeLocation> pending_worklist;
        std::set<std::uint32_t> pending_enqueued;
        enqueue_pending_edge_targets(image, snapshot, emitted_blocks, pending_worklist, pending_enqueued);

        const std::size_t pending_decode_budget = snapshot.blocks.size() + 256u;
        while (!pending_worklist.empty() && snapshot.blocks.size() < pending_decode_budget) {
            const std::size_t block_count_before = snapshot.blocks.size();
            process_cfg_worklist(image,
                                 snapshot,
                                 pending_decode_budget,
                                 max_instructions_per_block,
                                 pending_worklist,
                                 pending_enqueued,
                                 emitted_blocks,
                                 function_roots,
                                 emitted_edges);
            sync_function_roots(snapshot, function_roots);
            if (snapshot.blocks.size() == block_count_before) {
                break;
            }
            enqueue_pending_edge_targets(image, snapshot, emitted_blocks, pending_worklist, pending_enqueued);
        }
    }

    prune_invalid_overlapping_blocks_and_targets(image, snapshot);
    summarize_functions(snapshot);

    return snapshot;
}

std::string format_cfg_snapshot(const CfgSnapshot& snapshot) {
    std::ostringstream oss;
    oss << "CFG snapshot:\n";
    oss << "  Root: " << format_location(snapshot.root) << '\n';
    oss << "  Blocks: " << snapshot.blocks.size() << '\n';
    oss << "  Edges: " << snapshot.edges.size() << '\n';
    oss << "  Indirect sites: " << snapshot.indirect_sites.size() << '\n';
    oss << "  Interface surfaces: " << snapshot.interface_surfaces.size() << '\n';
    oss << "  Function roots: " << snapshot.discovered_function_roots.size() << '\n';

    if (!snapshot.discovered_function_roots.empty()) {
        oss << "  Root set:\n";
        for (const CodeLocation root : snapshot.discovered_function_roots) {
            oss << "    " << format_location(root) << '\n';
        }
    }

    if (!snapshot.blocks.empty()) {
        oss << "  Blocks detail:\n";
        for (const BlockRecord& block : snapshot.blocks) {
            oss << "    " << format_location(block.start)
                << "  instrs=" << block.preview.instructions.size()
                << "  terminated=" << (block.preview.terminated ? "yes" : "no")
                << "  reason=" << block.preview.termination_reason << '\n';
        }
    }

    if (!snapshot.edges.empty()) {
        oss << "  Edge detail:\n";
        for (const CfgEdge& edge : snapshot.edges) {
            oss << "    " << format_location(edge.from)
                << " -> " << format_location(edge.to)
                << "  (" << edge_kind_name(edge.kind) << ")\n";
        }
    }

    if (!snapshot.indirect_sites.empty()) {
        oss << "  Indirect detail:\n";
        for (const IndirectSiteRecord& site : snapshot.indirect_sites) {
            oss << "    " << format_location(site.from)
                << "  (" << edge_kind_name(site.kind) << ')';
            if (site.is_far) {
                oss << " far";
            }
            if (!site.operand_text.empty()) {
                oss << "  operand=" << site.operand_text;
            }
            if (!site.resolution_note.empty()) {
                oss << "  note=" << site.resolution_note;
            }
            oss << '\n';
            for (const CodeLocation target : site.resolved_targets) {
                oss << "      -> " << format_location(target) << '\n';
            }
        }
    }

    if (!snapshot.interface_surfaces.empty()) {
        oss << "  Interface surface detail:\n";
        for (const InterfaceSurfaceRecord& surface : snapshot.interface_surfaces) {
            oss << "    " << surface.name
                << "  kind=" << interface_surface_kind_name(surface.kind)
                << "  base=" << format_location(surface.base)
                << "  entries=" << surface.entries.size() << '\n';
            for (const InterfaceSurfaceEntry& entry : surface.entries) {
                oss << "      [" << entry.ordinal << "] -> ";
                if (entry.target_is_valid) {
                    oss << format_location(entry.target);
                } else {
                    oss << "<invalid>";
                }
                oss << '\n';
            }
        }
    }

    if (!snapshot.functions.empty()) {
        oss << "  Function detail:\n";
        for (const FunctionRecord& function : snapshot.functions) {
            oss << "    " << format_location(function.entry)
                << "  entry_present=" << (function.entry_block_present ? "yes" : "no")
                << "  reachable=" << function.reachable_blocks.size()
                << "  owned=" << function.owned_blocks.size()
                << "  shared=" << function.shared_blocks.size()
                << "  external_entries=" << function.external_entry_blocks.size() << '\n';
        }
    }

    if (!snapshot.functions.empty()) {
        bool printed_external_entries = false;
        for (const FunctionRecord& function : snapshot.functions) {
            if (function.external_entry_blocks.empty()) {
                continue;
            }
            if (!printed_external_entries) {
                oss << "  External entry detail:\n";
                printed_external_entries = true;
            }
            oss << "    " << format_location(function.entry)
                << "  external_blocks=" << function.external_entry_blocks.size() << '\n';
            for (const CodeLocation block : function.external_entry_blocks) {
                oss << "      -> " << format_location(block) << '\n';
            }
        }
    }

    if (!snapshot.functions.empty()) {
        bool printed_fragments = false;
        for (const FunctionRecord& function : snapshot.functions) {
            if (function.entry_fragments.empty()) {
                continue;
            }
            if (!printed_fragments) {
                oss << "  Entry fragment detail:\n";
                printed_fragments = true;
            }
            oss << "    " << format_location(function.entry)
                << "  fragments=" << function.entry_fragments.size() << '\n';
            for (const FunctionRecord::EntryFragmentRecord& fragment : function.entry_fragments) {
                oss << "      entry=" << format_location(fragment.entry_block)
                    << "  disposition=" << fragment_disposition_name(fragment.disposition)
                    << "  lowering=" << fragment_lowering_action_name(fragment.lowering_action)
                    << "  incoming=" << fragment.incoming_from_blocks.size()
                    << "  reachable=" << fragment.reachable_blocks.size()
                    << "  clone_candidates=" << fragment.clone_candidate_blocks.size()
                    << "  shared=" << fragment.shared_blocks.size()
                    << "  exits=" << fragment.exit_to_blocks.size() << '\n';
                for (const CodeLocation source : fragment.incoming_from_blocks) {
                    oss << "        from " << format_location(source) << '\n';
                }
                for (const CodeLocation target : fragment.exit_to_blocks) {
                    oss << "        exit " << format_location(target) << '\n';
                }
            }
        }
    }

    if (!snapshot.block_ownerships.empty()) {
        oss << "  Shared block detail:\n";
        for (const BlockOwnershipRecord& ownership : snapshot.block_ownerships) {
            if (ownership.owners.size() <= 1u) {
                continue;
            }
            oss << "    " << format_location(ownership.block)
                << "  owners=" << ownership.owners.size() << '\n';
            for (const CodeLocation owner : ownership.owners) {
                oss << "      <- " << format_location(owner) << '\n';
            }
        }
    }

    return oss.str();
}

std::optional<std::uint16_t> discover_register_provenance_direct_offset_before(
    const BlockRecord& block,
    const std::optional<CodeLocation> stop_before,
    const Register16Id target_register) {
    std::optional<std::uint16_t> direct_offset;
    for (const DecodedInstruction& instruction : block.preview.instructions) {
        if (stop_before.has_value() &&
            logical_key(CodeLocation{instruction.cs, instruction.ip}) == logical_key(*stop_before)) {
            break;
        }

        if (instruction.bytes.empty()) {
            continue;
        }

        const std::size_t prefix_length = strip_prefix_bytes(instruction);
        if (prefix_length >= instruction.bytes.size()) {
            continue;
        }

        const std::uint8_t opcode = instruction.bytes[prefix_length];
        bool writes_target_register = false;
        std::optional<std::uint16_t> next_direct_offset;

        if (opcode >= 0xB8u && opcode <= 0xBFu) {
            const auto dest = decode_register16(static_cast<std::uint8_t>(opcode - 0xB8u));
            writes_target_register = dest.has_value() && *dest == target_register;
        } else if (opcode == 0xA1u && target_register == Register16Id::AX) {
            writes_target_register = true;
            const std::optional<std::string> source_operand = mov_source_operand_text(instruction);
            if (source_operand.has_value() && is_simple_direct_memory_operand_text(*source_operand)) {
                next_direct_offset = direct_operand_offset_from_text(*source_operand);
            }
        } else if (opcode == 0x8Bu && prefix_length + 1u < instruction.bytes.size()) {
            const std::uint8_t modrm = instruction.bytes[prefix_length + 1u];
            const auto dest = decode_register16(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
            writes_target_register = dest.has_value() && *dest == target_register;
            if (writes_target_register) {
                const std::optional<std::string> source_operand = mov_source_operand_text(instruction);
                if (source_operand.has_value() && is_simple_direct_memory_operand_text(*source_operand)) {
                    next_direct_offset = direct_operand_offset_from_text(*source_operand);
                }
            }
        } else if (opcode == 0xC4u || opcode == 0xC5u) {
            if (prefix_length + 1u < instruction.bytes.size()) {
                const std::uint8_t modrm = instruction.bytes[prefix_length + 1u];
                const auto dest = decode_register16(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
                writes_target_register = dest.has_value() && *dest == target_register;
            }
        } else if (opcode >= 0x58u && opcode <= 0x5Fu) {
            const auto dest = decode_register16(static_cast<std::uint8_t>(opcode - 0x58u));
            writes_target_register = dest.has_value() && *dest == target_register;
        } else if ((opcode & 0xF8u) == 0x90u && (opcode & 0x07u) != 0u) {
            const std::uint8_t reg = static_cast<std::uint8_t>(opcode & 0x07u);
            writes_target_register =
                target_register == Register16Id::AX ||
                (decode_register16(reg).has_value() && *decode_register16(reg) == target_register);
        }

        if (writes_target_register) {
            direct_offset = next_direct_offset;
        }
    }

    return direct_offset;
}

namespace {

std::optional<std::uint16_t> discover_register_provenance_direct_offset(
    const BlockRecord& block,
    const CodeLocation site_location,
    const Register16Id target_register) {
    return discover_register_provenance_direct_offset_before(block, site_location, target_register);
}

std::optional<std::uint16_t> discover_register_provenance_direct_offset_via_predecessor_chain_impl(
    const CfgSnapshot& snapshot,
    const std::map<std::uint64_t, std::map<std::uint32_t, AbstractState>>& entry_states,
    const std::uint64_t owner_state_key,
    const std::uint32_t predecessor_key,
    const Register16Id target_register) {
    std::map<std::uint32_t, const BlockRecord*> blocks_by_key;
    for (const BlockRecord& block : snapshot.blocks) {
        blocks_by_key[logical_key(block.start)] = &block;
    }

    std::set<std::uint32_t> visited;
    std::uint32_t current_block_key = predecessor_key;
    while (visited.insert(current_block_key).second) {
        const auto block_it = blocks_by_key.find(current_block_key);
        if (block_it == blocks_by_key.end()) {
            break;
        }

        if (const std::optional<std::uint16_t> direct_offset =
                discover_register_provenance_direct_offset_before(*block_it->second, std::nullopt, target_register);
            direct_offset.has_value()) {
            return direct_offset;
        }

        const auto state_it = entry_states.find(analysis_state_key(analysis_owner_root_from_key(owner_state_key),
                                                                   current_block_key));
        if (state_it == entry_states.end() || state_it->second.size() != 1u) {
            break;
        }

        const std::uint32_t next_predecessor_key = state_it->second.begin()->first;
        if (next_predecessor_key == current_block_key) {
            break;
        }
        current_block_key = next_predecessor_key;
    }

    return std::nullopt;
}

} // namespace

std::string format_indirect_site_debug(const MzImage& image,
                                       const CfgSnapshot& snapshot,
                                       const CodeLocation site_location) {
    std::ostringstream oss;
    oss << "Indirect site debug:\n";
    oss << "  Site: " << format_location(site_location) << '\n';

    const auto site_it = std::find_if(snapshot.indirect_sites.begin(),
                                      snapshot.indirect_sites.end(),
                                      [&](const IndirectSiteRecord& site) {
                                          return logical_key(site.from) == logical_key(site_location);
                                      });
    if (site_it == snapshot.indirect_sites.end()) {
        oss << "  Not present in current indirect-site set.\n";
        return oss.str();
    }

    oss << "  Operand: " << site_it->operand_text << '\n';
    oss << "  Kind: " << edge_kind_name(site_it->kind) << (site_it->is_far ? " far" : "") << '\n';
    oss << "  Note: " << site_it->resolution_note << '\n';
    if (site_it->dispatch_kind != IndirectDispatchKind::None) {
        oss << "  Dispatch metadata:\n";
        oss << "    kind: "
            << (site_it->dispatch_kind == IndirectDispatchKind::CurrentCsPairTable ? "current_cs_pair_table"
                                                                                   : "current_cs_word_table")
            << '\n';
        oss << "    table_base: " << hex16(site_it->dispatch_table_base) << '\n';
        oss << "    runtime_index_base: " << hex16(site_it->dispatch_runtime_index_base) << '\n';
        oss << "    entry_stride: " << site_it->dispatch_entry_stride << '\n';
        if (site_it->dispatch_index_register.has_value()) {
            oss << "    index_register: "
                << register16_name(*site_it->dispatch_index_register) << '\n';
        }
        if (!site_it->dispatch_entries.empty()) {
            oss << "    entries:\n";
            for (const IndirectDispatchEntry& entry : site_it->dispatch_entries) {
                oss << "      ";
                if (site_it->dispatch_kind == IndirectDispatchKind::CurrentCsPairTable) {
                    oss << "selector=" << hex16(entry.selector) << ' ';
                }
                oss << "target=" << format_location(entry.target)
                    << (entry.target_is_valid ? "" : " invalid") << '\n';
            }
        }
    }
    if (!site_it->resolved_targets.empty()) {
        oss << "  Resolved targets:\n";
        for (const CodeLocation target : site_it->resolved_targets) {
            oss << "    -> " << format_location(target) << '\n';
        }
    }

    const auto entry_states = analyze_rooted_block_entry_states(image, snapshot);
    const DirectWriteSummary direct_write_summary = collect_direct_write_summary(snapshot, entry_states, image);
    const auto debug_block_it = std::find_if(snapshot.blocks.begin(),
                                             snapshot.blocks.end(),
                                             [&](const BlockRecord& block) {
                                                 return std::any_of(
                                                     block.preview.instructions.begin(),
                                                     block.preview.instructions.end(),
                                                     [&](const DecodedInstruction& instruction) {
                                                         return logical_key(CodeLocation{instruction.cs, instruction.ip}) ==
                                                                logical_key(site_location);
                                                     });
                                             });
    if (debug_block_it == snapshot.blocks.end()) {
        oss << "  Block not present in current decoded block set.\n";
        return oss.str();
    }

    oss << "  Block start: " << format_location(debug_block_it->start) << '\n';
    oss << "  Owner contexts:\n";
    const std::uint32_t block_key = logical_key(debug_block_it->start);
    bool printed_context = false;
    for (const auto& [state_key, predecessor_states] : entry_states) {
        if (analysis_block_from_key(state_key) != block_key) {
            continue;
        }
        const CodeLocation owner_root = key_to_location(analysis_owner_root_from_key(state_key));
        for (const auto& [predecessor_key, entry_state] : predecessor_states) {
            printed_context = true;
            oss << "    root=" << format_location(owner_root)
                << " pred=" << format_location(key_to_location(predecessor_key)) << '\n';
            oss << "      ds=" << format_known_word_debug(entry_state.ds)
                << " es=" << format_known_word_debug(entry_state.es)
                << " ss=" << format_known_word_debug(entry_state.ss) << '\n';
            oss << "      ax=" << format_known_word_debug(register_ref(entry_state, Register16Id::AX))
                << " bx=" << format_known_word_debug(register_ref(entry_state, Register16Id::BX))
                << " cx=" << format_known_word_debug(register_ref(entry_state, Register16Id::CX))
                << " dx=" << format_known_word_debug(register_ref(entry_state, Register16Id::DX))
                << " bp=" << format_known_word_debug(register_ref(entry_state, Register16Id::BP))
                << " si=" << format_known_word_debug(register_ref(entry_state, Register16Id::SI))
                << " di=" << format_known_word_debug(register_ref(entry_state, Register16Id::DI))
                << '\n';
            if (!entry_state.direct_offset_words.empty()) {
                oss << "      direct offsets:\n";
                for (const auto& [offset, values] : entry_state.direct_offset_words) {
                    oss << "        [" << hex16(offset) << "] = " << format_known_word_debug(values) << '\n';
                }
            }
            if (!entry_state.far_pointer_slots.empty()) {
                oss << "      far pointer slots:\n";
                for (const auto& [offset, targets] : entry_state.far_pointer_slots) {
                    oss << "        [" << hex16(offset) << "]\n";
                    for (const CodeLocation target : targets) {
                        oss << "          -> " << format_location(target) << '\n';
                    }
                }
            }
        }
    }
    if (!printed_context) {
        oss << "    (none)\n";
    }

    std::optional<std::uint16_t> debug_offset = direct_operand_offset_from_text(site_it->operand_text);
    if (!debug_offset.has_value()) {
        if (const std::optional<Register16Id> register_target = parse_register16_name(site_it->operand_text);
            register_target.has_value()) {
            debug_offset = discover_register_provenance_direct_offset(*debug_block_it, site_location, *register_target);
            if (!debug_offset.has_value()) {
                for (const auto& [state_key, predecessor_states] : entry_states) {
                    if (analysis_block_from_key(state_key) != block_key) {
                        continue;
                    }
                    for (const auto& [predecessor_key, entry_state] : predecessor_states) {
                        (void)entry_state;
                        debug_offset = discover_register_provenance_direct_offset_via_predecessor_chain_impl(
                            snapshot,
                            entry_states,
                            state_key,
                            predecessor_key,
                            *register_target);
                        if (debug_offset.has_value()) {
                            break;
                        }
                    }
                    if (debug_offset.has_value()) {
                        break;
                    }
                }
            }
            if (debug_offset.has_value()) {
                oss << "  Provenance direct slot: [" << hex16(*debug_offset) << "]\n";
            }
        }
    }

    if (debug_offset.has_value()) {
        const auto near_slot_it = direct_write_summary.near_pointer_slots.find(*debug_offset);
        if (near_slot_it != direct_write_summary.near_pointer_slots.end()) {
            oss << "  Global near pointer slot summary:\n";
            oss << "    [" << hex16(*debug_offset) << "]\n";
            for (const CodeLocation target : near_slot_it->second) {
                oss << "      -> " << format_location(target) << '\n';
            }
        }
        const auto far_slot_it = direct_write_summary.far_pointer_slots.find(*debug_offset);
        if (far_slot_it != direct_write_summary.far_pointer_slots.end()) {
            oss << "  Global far pointer slot summary:\n";
            oss << "    [" << hex16(*debug_offset) << "]\n";
            for (const CodeLocation target : far_slot_it->second) {
                oss << "      -> " << format_location(target) << '\n';
            }
        }
    }

    return oss.str();
}

} // namespace mz2cpp
