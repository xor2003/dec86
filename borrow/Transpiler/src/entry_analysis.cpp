#include "entry_analysis.h"

#include <iomanip>
#include <sstream>

namespace mz2cpp {

namespace {

std::string hex16(const std::uint16_t value) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << value;
    return oss.str();
}

std::string hex32(const std::uint32_t value) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << value;
    return oss.str();
}

std::string format_bytes(const std::vector<std::uint8_t>& bytes) {
    std::ostringstream oss;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i != 0) {
            oss << ' ';
        }
        oss << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
            << static_cast<unsigned>(bytes[i]);
    }
    return oss.str();
}

} // namespace

std::string format_basic_block_analysis(const MzImage& image,
                                        const std::uint16_t cs,
                                        const std::uint16_t ip,
                                        const std::size_t max_instructions,
                                        const std::string& title) {
    const BasicBlockPreview block = decode_basic_block_preview(image, cs, ip, max_instructions);
    std::ostringstream oss;
    oss << title << ":\n";
    oss << "  Start: " << hex16(block.cs) << ':' << hex16(block.start_ip).substr(2) << '\n';
    oss << "  Instructions decoded: " << block.instructions.size() << '\n';
    oss << "  Terminated: " << (block.terminated ? "yes" : "no") << '\n';
    oss << "  Stop reason: " << block.termination_reason << '\n';

    for (const DecodedInstruction& inst : block.instructions) {
        oss << "  " << hex16(inst.cs) << ':' << hex16(inst.ip).substr(2)
            << "  [" << format_bytes(inst.bytes) << "]"
            << "  " << inst.text;
        if (inst.branch_target_ip.has_value()) {
            oss << "  ; target=" << hex16(inst.cs) << ':' << hex16(*inst.branch_target_ip).substr(2);
        }
        if (inst.branch_fallthrough_ip.has_value() && inst.flow != FlowKind::UnconditionalBranch) {
            oss << "  ; next=" << hex16(inst.cs) << ':' << hex16(*inst.branch_fallthrough_ip).substr(2);
        }
        oss << "  ; phys=" << hex32(inst.physical) << '\n';
    }

    return oss.str();
}

std::string format_entry_analysis(const MzImage& image, const std::size_t max_instructions) {
    return format_basic_block_analysis(
        image,
        image.entry_cs,
        image.entry_ip,
        max_instructions,
        "Entrypoint basic block preview");
}

} // namespace mz2cpp
