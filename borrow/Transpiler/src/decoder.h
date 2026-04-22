#pragma once

#include "mz_exe.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace mz2cpp {

enum class FlowKind {
    Fallthrough,
    ConditionalBranch,
    UnconditionalBranch,
    Call,
    Return,
    Interrupt,
    Halt,
};

enum class IndirectOperandKind {
    Register,
    MemoryComputed,
    MemoryDirect,
};

struct IndirectTransferInfo {
    IndirectOperandKind operand_kind = IndirectOperandKind::Register;
    bool is_far = false;
    bool memory_uses_current_cs = false;
    std::optional<std::uint16_t> memory_offset;
    std::string operand_text;
};

struct DecodedInstruction {
    std::uint16_t cs = 0;
    std::uint16_t ip = 0;
    std::uint32_t physical = 0;
    std::vector<std::uint8_t> bytes;
    std::string text;
    std::size_t length = 0;
    FlowKind flow = FlowKind::Fallthrough;
    std::optional<std::uint16_t> branch_target_cs;
    std::optional<std::uint16_t> branch_target_ip;
    std::optional<std::uint16_t> branch_fallthrough_ip;
    std::optional<IndirectTransferInfo> indirect;
};

struct BasicBlockPreview {
    std::uint16_t cs = 0;
    std::uint16_t start_ip = 0;
    std::vector<DecodedInstruction> instructions;
    bool terminated = false;
    std::string termination_reason;
};

DecodedInstruction decode_instruction(const MzImage& image, std::uint16_t cs, std::uint16_t ip);
BasicBlockPreview decode_basic_block_preview(const MzImage& image,
                                             std::uint16_t cs,
                                             std::uint16_t start_ip,
                                             std::size_t max_instructions);

} // namespace mz2cpp
