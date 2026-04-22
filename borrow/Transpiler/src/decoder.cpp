#include "decoder.h"

#include <array>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace mz2cpp {

namespace {

enum class SegmentRegister {
    ES,
    CS,
    SS,
    DS,
};

std::string hex8(const std::uint8_t value) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
        << static_cast<unsigned>(value);
    return oss.str();
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

std::string register8_name(const std::uint8_t index) {
    static const std::array<const char*, 8> kNames = {"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"};
    return kNames.at(index & 7u);
}

std::string segment_register_name(const SegmentRegister segment) {
    switch (segment) {
    case SegmentRegister::ES: return "es";
    case SegmentRegister::CS: return "cs";
    case SegmentRegister::SS: return "ss";
    case SegmentRegister::DS: return "ds";
    }
    return "?";
}

std::string group1_op_name_8(const std::uint8_t group) {
    switch (group & 0x07u) {
    case 0u: return "add";
    case 1u: return "or";
    case 2u: return "adc";
    case 3u: return "sbb";
    case 4u: return "and";
    case 5u: return "sub";
    case 6u: return "xor";
    case 7u: return "cmp";
    default: return {};
    }
}

std::string group1_op_name_16(const std::uint8_t group) {
    return group1_op_name_8(group);
}

SegmentRegister decode_segment_register(const std::uint8_t field) {
    switch (field & 0x03u) {
    case 0: return SegmentRegister::ES;
    case 1: return SegmentRegister::CS;
    case 2: return SegmentRegister::SS;
    case 3: return SegmentRegister::DS;
    }
    return SegmentRegister::DS;
}

std::uint8_t read_u8_at(const MzImage& image, const std::uint16_t cs, const std::uint16_t ip, const std::size_t delta) {
    const std::uint32_t physical = real_mode_phys(cs, static_cast<std::uint16_t>(ip + delta));
    if (physical >= image.initial_memory_image.size()) {
        throw std::runtime_error("decode ran off the end of the real-mode address space");
    }
    return image.initial_memory_image[physical];
}

std::uint16_t read_u16_at(const MzImage& image, const std::uint16_t cs, const std::uint16_t ip, const std::size_t delta) {
    const std::uint8_t lo = read_u8_at(image, cs, ip, delta);
    const std::uint8_t hi = read_u8_at(image, cs, ip, delta + 1u);
    return static_cast<std::uint16_t>(lo) | static_cast<std::uint16_t>(hi << 8u);
}

std::int8_t read_s8_at(const MzImage& image, const std::uint16_t cs, const std::uint16_t ip, const std::size_t delta) {
    return static_cast<std::int8_t>(read_u8_at(image, cs, ip, delta));
}

std::int16_t read_s16_at(const MzImage& image, const std::uint16_t cs, const std::uint16_t ip, const std::size_t delta) {
    return static_cast<std::int16_t>(read_u16_at(image, cs, ip, delta));
}

std::string displacement_text(const std::int16_t disp) {
    if (disp == 0) {
        return {};
    }
    std::ostringstream oss;
    if (disp > 0) {
        oss << " + " << hex16(static_cast<std::uint16_t>(disp));
    } else {
        oss << " - " << hex16(static_cast<std::uint16_t>(-disp));
    }
    return oss.str();
}

std::string format_rm16_operand(const MzImage& image,
                                const std::uint16_t cs,
                                const std::uint16_t ip,
                                const std::size_t modrm_offset,
                                const std::string& segment_override,
                                std::size_t& out_length) {
    const std::uint8_t modrm = read_u8_at(image, cs, ip, modrm_offset);
    const std::uint8_t mod = static_cast<std::uint8_t>((modrm >> 6u) & 0x03u);
    const std::uint8_t rm = static_cast<std::uint8_t>(modrm & 0x07u);

    if (mod == 0x03u) {
        out_length = 1;
        return register16_name(rm);
    }

    static const std::array<const char*, 8> kEaBases = {
        "bx + si", "bx + di", "bp + si", "bp + di", "si", "di", "bp", "bx"
    };

    std::string operand;
    if (!segment_override.empty()) {
        operand += segment_override;
        operand += ':';
    }
    operand += "[";
    std::size_t disp_length = 0;
    std::int16_t disp = 0;

    if (mod == 0x00u && rm == 0x06u) {
        disp = static_cast<std::int16_t>(read_u16_at(image, cs, ip, modrm_offset + 1u));
        disp_length = 2;
        operand += hex16(static_cast<std::uint16_t>(disp));
    } else {
        operand += kEaBases[rm];
        if (mod == 0x01u) {
            disp = read_s8_at(image, cs, ip, modrm_offset + 1u);
            disp_length = 1;
        } else if (mod == 0x02u) {
            disp = read_s16_at(image, cs, ip, modrm_offset + 1u);
            disp_length = 2;
        }
        operand += displacement_text(disp);
    }

    operand += "]";
    out_length = 1u + disp_length;
    return operand;
}

std::string format_rm8_operand(const MzImage& image,
                               const std::uint16_t cs,
                               const std::uint16_t ip,
                               const std::size_t modrm_offset,
                               const std::string& segment_override,
                               std::size_t& out_length) {
    const std::uint8_t modrm = read_u8_at(image, cs, ip, modrm_offset);
    const std::uint8_t mod = static_cast<std::uint8_t>((modrm >> 6u) & 0x03u);
    const std::uint8_t rm = static_cast<std::uint8_t>(modrm & 0x07u);
    if (mod == 0x03u) {
        out_length = 1;
        return register8_name(rm);
    }
    return format_rm16_operand(image, cs, ip, modrm_offset, segment_override, out_length);
}

bool modrm_uses_register_operand(const MzImage& image,
                                 const std::uint16_t cs,
                                 const std::uint16_t ip,
                                 const std::size_t modrm_offset) {
    const std::uint8_t modrm = read_u8_at(image, cs, ip, modrm_offset);
    return ((modrm >> 6u) & 0x03u) == 0x03u;
}

IndirectTransferInfo make_indirect_transfer_info(const MzImage& image,
                                                 const std::uint16_t cs,
                                                 const std::uint16_t ip,
                                                 const std::size_t modrm_offset,
                                                 const std::string& segment_override,
                                                 const bool is_far,
                                                 const std::string& operand_text) {
    IndirectTransferInfo info{};
    info.is_far = is_far;
    info.operand_text = operand_text;

    const std::uint8_t modrm = read_u8_at(image, cs, ip, modrm_offset);
    const std::uint8_t mod = static_cast<std::uint8_t>((modrm >> 6u) & 0x03u);
    const std::uint8_t rm = static_cast<std::uint8_t>(modrm & 0x07u);
    if (mod == 0x03u) {
        info.operand_kind = IndirectOperandKind::Register;
        return info;
    }

    if (mod == 0x00u && rm == 0x06u) {
        info.operand_kind = IndirectOperandKind::MemoryDirect;
        info.memory_offset = read_u16_at(image, cs, ip, modrm_offset + 1u);
        info.memory_uses_current_cs = (segment_override == "cs");
        return info;
    }

    info.operand_kind = IndirectOperandKind::MemoryComputed;
    return info;
}

std::string condition_name(const std::uint8_t opcode) {
    switch (opcode & 0x0Fu) {
    case 0x04u: return "jz";
    case 0x05u: return "jnz";
    case 0x02u: return "jb";
    case 0x03u: return "jnb";
    case 0x06u: return "jbe";
    case 0x07u: return "ja";
    case 0x0Cu: return "jl";
    case 0x0Du: return "jge";
    case 0x0Eu: return "jle";
    case 0x0Fu: return "jg";
    default: return "jcc";
    }
}

DecodedInstruction make_base_instruction(const std::uint16_t cs, const std::uint16_t ip) {
    DecodedInstruction inst{};
    inst.cs = cs;
    inst.ip = ip;
    inst.physical = real_mode_phys(cs, ip);
    return inst;
}

void capture_bytes(const MzImage& image, DecodedInstruction& inst) {
    inst.bytes.reserve(inst.length);
    for (std::size_t i = 0; i < inst.length; ++i) {
        inst.bytes.push_back(read_u8_at(image, inst.cs, inst.ip, i));
    }
}

} // namespace

DecodedInstruction decode_instruction(const MzImage& image, const std::uint16_t cs, const std::uint16_t ip) {
    DecodedInstruction inst = make_base_instruction(cs, ip);
    std::size_t prefix_length = 0;
    std::string repeat_prefix;
    std::string segment_override;

    for (;;) {
        const std::uint8_t prefix = read_u8_at(image, cs, ip, prefix_length);
        switch (prefix) {
        case 0x26u:
            segment_override = "es";
            ++prefix_length;
            continue;
        case 0x2Eu:
            segment_override = "cs";
            ++prefix_length;
            continue;
        case 0x36u:
            segment_override = "ss";
            ++prefix_length;
            continue;
        case 0x3Eu:
            segment_override = "ds";
            ++prefix_length;
            continue;
        case 0xF2u:
            repeat_prefix = "repne";
            ++prefix_length;
            continue;
        case 0xF3u:
            repeat_prefix = "rep";
            ++prefix_length;
            continue;
        default:
            break;
        }
        break;
    }

    const std::uint8_t opcode = read_u8_at(image, cs, ip, prefix_length);
    auto rd8 = [&](const std::size_t delta) {
        return read_u8_at(image, cs, ip, prefix_length + delta);
    };
    auto rd16 = [&](const std::size_t delta) {
        return read_u16_at(image, cs, ip, prefix_length + delta);
    };
    auto rs8 = [&](const std::size_t delta) {
        return read_s8_at(image, cs, ip, prefix_length + delta);
    };
    auto rs16 = [&](const std::size_t delta) {
        return read_s16_at(image, cs, ip, prefix_length + delta);
    };

    if (opcode == 0xFAu) {
        inst.text = "cli";
        inst.length = 1;
    } else if (opcode == 0xFBu) {
        inst.text = "sti";
        inst.length = 1;
    } else if (opcode == 0xF9u) {
        inst.text = "stc";
        inst.length = 1;
    } else if (opcode == 0xFCu) {
        inst.text = "cld";
        inst.length = 1;
    } else if (opcode == 0xFDu) {
        inst.text = "std";
        inst.length = 1;
    } else if (opcode == 0x9Cu) {
        inst.text = "pushf";
        inst.length = 1;
    } else if (opcode == 0x9Du) {
        inst.text = "popf";
        inst.length = 1;
    } else if (opcode == 0x98u) {
        inst.text = "cbw";
        inst.length = 1;
    } else if (opcode == 0x9Eu) {
        inst.text = "sahf";
        inst.length = 1;
    } else if (opcode == 0x9Fu) {
        inst.text = "lahf";
        inst.length = 1;
    } else if (opcode == 0xF8u) {
        inst.text = "clc";
        inst.length = 1;
    } else if (opcode == 0x06u) {
        inst.text = "push es";
        inst.length = 1;
    } else if (opcode == 0x07u) {
        inst.text = "pop es";
        inst.length = 1;
    } else if (opcode == 0x1Eu) {
        inst.text = "push ds";
        inst.length = 1;
    } else if (opcode == 0x1Fu) {
        inst.text = "pop ds";
        inst.length = 1;
    } else if (opcode == 0x16u) {
        inst.text = "push ss";
        inst.length = 1;
    } else if (opcode == 0x17u) {
        inst.text = "pop ss";
        inst.length = 1;
    } else if (opcode == 0x0Eu) {
        inst.text = "push cs";
        inst.length = 1;
    } else if ((opcode & 0xF8u) == 0x50u) {
        inst.text = "push " + register16_name(static_cast<std::uint8_t>(opcode & 0x07u));
        inst.length = 1;
    } else if ((opcode & 0xF8u) == 0x58u) {
        inst.text = "pop " + register16_name(static_cast<std::uint8_t>(opcode & 0x07u));
        inst.length = 1;
    } else if ((opcode & 0xF8u) == 0x90u) {
        const std::uint8_t reg = static_cast<std::uint8_t>(opcode & 0x07u);
        if (reg == 0u) {
            inst.text = "nop";
        } else {
            inst.text = "xchg ax, " + register16_name(reg);
        }
        inst.length = 1;
    } else if ((opcode & 0xF8u) == 0x40u) {
        inst.text = "inc " + register16_name(static_cast<std::uint8_t>(opcode & 0x07u));
        inst.length = 1;
    } else if ((opcode & 0xF8u) == 0x48u) {
        inst.text = "dec " + register16_name(static_cast<std::uint8_t>(opcode & 0x07u));
        inst.length = 1;
    } else if ((opcode & 0xF8u) == 0xB0u) {
        const std::uint8_t imm = rd8(1);
        inst.text = "mov " + register8_name(static_cast<std::uint8_t>(opcode & 0x07u)) + ", " + hex8(imm);
        inst.length = 2;
    } else if ((opcode & 0xF8u) == 0xB8u) {
        const std::uint16_t imm = rd16(1);
        inst.text = "mov " + register16_name(static_cast<std::uint8_t>(opcode & 0x07u)) + ", " + hex16(imm);
        inst.length = 3;
    } else if (opcode == 0x8Au) {
        const std::uint8_t modrm = rd8(1);
        const std::string dest = register8_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        std::size_t operand_length = 0;
        const std::string source = format_rm8_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "mov " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0x88u) {
        const std::uint8_t modrm = rd8(1);
        const std::string source = register8_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        std::size_t operand_length = 0;
        const std::string dest = format_rm8_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "mov " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0x8Bu) {
        const std::uint8_t modrm = rd8(1);
        const std::string dest = register16_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        std::size_t operand_length = 0;
        const std::string source = format_rm16_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "mov " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0x8Du) {
        if (modrm_uses_register_operand(image, cs, ip, prefix_length + 1u)) {
            throw std::runtime_error("unsupported lea with register operand");
        }
        const std::uint8_t modrm = rd8(1);
        const std::string dest = register16_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        std::size_t operand_length = 0;
        const std::string source = format_rm16_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "lea " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0xC4u || opcode == 0xC5u) {
        if (modrm_uses_register_operand(image, cs, ip, prefix_length + 1u)) {
            throw std::runtime_error("unsupported far-pointer load with register operand");
        }
        const std::uint8_t modrm = rd8(1);
        const std::string dest = register16_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        std::size_t operand_length = 0;
        const std::string source = format_rm16_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = (opcode == 0xC4u ? "les " : "lds ") + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0x8Eu) {
        const std::uint8_t modrm = rd8(1);
        const SegmentRegister seg = decode_segment_register(static_cast<std::uint8_t>((modrm >> 3u) & 0x03u));
        std::size_t operand_length = 0;
        const std::string source = format_rm16_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "mov " + segment_register_name(seg) + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0xC8u) {
        const std::uint16_t frame_size = rd16(1);
        const std::uint8_t nesting = rd8(3);
        inst.text = "enter " + hex16(frame_size) + ", " + hex8(nesting);
        inst.length = 4u;
    } else if (opcode == 0x8Cu) {
        const std::uint8_t modrm = rd8(1);
        const SegmentRegister seg = decode_segment_register(static_cast<std::uint8_t>((modrm >> 3u) & 0x03u));
        std::size_t operand_length = 0;
        const std::string dest = format_rm16_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "mov " + dest + ", " + segment_register_name(seg);
        inst.length = 1u + operand_length;
    } else if (opcode == 0x89u) {
        const std::uint8_t modrm = rd8(1);
        const std::string source = register16_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        std::size_t operand_length = 0;
        const std::string dest = format_rm16_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "mov " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0x84u) {
        const std::uint8_t modrm = rd8(1);
        const std::string source = register8_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        std::size_t operand_length = 0;
        const std::string dest = format_rm8_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "test " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0x85u) {
        const std::uint8_t modrm = rd8(1);
        const std::string source = register16_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        std::size_t operand_length = 0;
        const std::string dest = format_rm16_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "test " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0x86u) {
        const std::uint8_t modrm = rd8(1);
        const std::string source = register8_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        std::size_t operand_length = 0;
        const std::string dest = format_rm8_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "xchg " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0x87u) {
        const std::uint8_t modrm = rd8(1);
        const std::string source = register16_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        std::size_t operand_length = 0;
        const std::string dest = format_rm16_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "xchg " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0x00u) {
        const std::uint8_t modrm = rd8(1);
        const std::string source = register8_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        std::size_t operand_length = 0;
        const std::string dest = format_rm8_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "add " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0x01u) {
        const std::uint8_t modrm = rd8(1);
        const std::string source = register16_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        std::size_t operand_length = 0;
        const std::string dest = format_rm16_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "add " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0xA0u) {
        const std::uint16_t off = rd16(1);
        inst.text = "mov al, " + (segment_override.empty() ? "" : segment_override + ":") + "[" + hex16(off) + "]";
        inst.length = 3;
    } else if (opcode == 0xA1u) {
        const std::uint16_t off = rd16(1);
        inst.text = "mov ax, " + (segment_override.empty() ? "" : segment_override + ":") + "[" + hex16(off) + "]";
        inst.length = 3;
    } else if (opcode == 0xA2u) {
        const std::uint16_t off = rd16(1);
        inst.text = "mov " + (segment_override.empty() ? "" : segment_override + ":") + "[" + hex16(off) + "], al";
        inst.length = 3;
    } else if (opcode == 0xA3u) {
        const std::uint16_t off = rd16(1);
        inst.text = "mov " + (segment_override.empty() ? "" : segment_override + ":") + "[" + hex16(off) + "], ax";
        inst.length = 3;
    } else if (opcode == 0xA8u) {
        const std::uint8_t imm = rd8(1);
        inst.text = "test al, " + hex8(imm);
        inst.length = 2;
    } else if (opcode == 0xAAu) {
        inst.text = "stosb";
        inst.length = 1;
    } else if (opcode == 0xC6u) {
        const std::uint8_t modrm = rd8(1);
        const std::uint8_t group = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
        if (group != 0u) {
            throw std::runtime_error("unsupported C6 group variant");
        }
        std::size_t operand_length = 0;
        const std::string dest = format_rm8_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        const std::uint8_t imm = rd8(1u + operand_length);
        inst.text = "mov " + dest + ", " + hex8(imm);
        inst.length = 1u + operand_length + 1u;
    } else if (opcode == 0xC7u) {
        const std::uint8_t modrm = rd8(1);
        const std::uint8_t group = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
        if (group != 0u) {
            throw std::runtime_error("unsupported C7 group variant");
        }
        std::size_t operand_length = 0;
        const std::string dest = format_rm16_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        const std::uint16_t imm = rd16(1u + operand_length);
        inst.text = "mov " + dest + ", " + hex16(imm);
        inst.length = 1u + operand_length + 2u;
    } else if (opcode == 0xE8u) {
        const std::int16_t rel = rs16(1);
        const std::uint16_t target = static_cast<std::uint16_t>(ip + prefix_length + 3u + rel);
        inst.text = "call " + hex16(cs) + ':' + hex16(target).substr(2);
        inst.length = 3;
        inst.flow = FlowKind::Call;
        inst.branch_target_cs = cs;
        inst.branch_target_ip = target;
        inst.branch_fallthrough_ip = static_cast<std::uint16_t>(ip + prefix_length + inst.length);
    } else if (opcode == 0x9Au) {
        const std::uint16_t target_ip = rd16(1);
        const std::uint16_t target_cs = rd16(3);
        inst.text = "call far " + hex16(target_cs) + ':' + hex16(target_ip).substr(2);
        inst.length = 5;
        inst.flow = FlowKind::Call;
        inst.branch_target_cs = target_cs;
        inst.branch_target_ip = target_ip;
        inst.branch_fallthrough_ip = static_cast<std::uint16_t>(ip + prefix_length + inst.length);
    } else if (opcode == 0xE9u) {
        const std::int16_t rel = rs16(1);
        const std::uint16_t target = static_cast<std::uint16_t>(ip + prefix_length + 3u + rel);
        inst.text = "jmp " + hex16(cs) + ':' + hex16(target).substr(2);
        inst.length = 3;
        inst.flow = FlowKind::UnconditionalBranch;
        inst.branch_target_cs = cs;
        inst.branch_target_ip = target;
    } else if (opcode == 0xEBu) {
        const std::int8_t rel = rs8(1);
        const std::uint16_t target = static_cast<std::uint16_t>(ip + prefix_length + 2u + rel);
        inst.text = "jmp " + hex16(cs) + ':' + hex16(target).substr(2);
        inst.length = 2;
        inst.flow = FlowKind::UnconditionalBranch;
        inst.branch_target_cs = cs;
        inst.branch_target_ip = target;
    } else if ((opcode & 0xF0u) == 0x70u) {
        const std::int8_t rel = rs8(1);
        const std::uint16_t target = static_cast<std::uint16_t>(ip + prefix_length + 2u + rel);
        inst.text = condition_name(opcode) + " " + hex16(cs) + ':' + hex16(target).substr(2);
        inst.length = 2;
        inst.flow = FlowKind::ConditionalBranch;
        inst.branch_target_cs = cs;
        inst.branch_target_ip = target;
        inst.branch_fallthrough_ip = static_cast<std::uint16_t>(ip + prefix_length + inst.length);
    } else if (opcode == 0x3Du) {
        const std::uint16_t imm = rd16(1);
        inst.text = "cmp ax, " + hex16(imm);
        inst.length = 3;
    } else if (opcode == 0x05u) {
        const std::uint16_t imm = rd16(1);
        inst.text = "add ax, " + hex16(imm);
        inst.length = 3;
    } else if (opcode == 0x04u) {
        const std::uint8_t imm = rd8(1);
        inst.text = "add al, " + hex8(imm);
        inst.length = 2;
    } else if (opcode == 0x0Cu) {
        const std::uint8_t imm = rd8(1);
        inst.text = "or al, " + hex8(imm);
        inst.length = 2;
    } else if (opcode == 0x0Du) {
        const std::uint16_t imm = rd16(1);
        inst.text = "or ax, " + hex16(imm);
        inst.length = 3;
    } else if (opcode == 0x3Cu) {
        const std::uint8_t imm = rd8(1);
        inst.text = "cmp al, " + hex8(imm);
        inst.length = 2;
    } else if (opcode == 0x3Au) {
        const std::uint8_t modrm = rd8(1);
        const std::string dest = register8_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        std::size_t operand_length = 0;
        const std::string source = format_rm8_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "cmp " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0x38u) {
        const std::uint8_t modrm = rd8(1);
        std::size_t operand_length = 0;
        const std::string dest = format_rm8_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        const std::string source = register8_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        inst.text = "cmp " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0x24u) {
        const std::uint8_t imm = rd8(1);
        inst.text = "and al, " + hex8(imm);
        inst.length = 2;
    } else if (opcode == 0x25u) {
        const std::uint16_t imm = rd16(1);
        inst.text = "and ax, " + hex16(imm);
        inst.length = 3;
    } else if (opcode == 0x20u) {
        const std::uint8_t modrm = rd8(1);
        std::size_t operand_length = 0;
        const std::string dest = format_rm8_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        const std::string source = register8_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        inst.text = "and " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0x21u) {
        const std::uint8_t modrm = rd8(1);
        std::size_t operand_length = 0;
        const std::string dest = format_rm16_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        const std::string source = register16_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        inst.text = "and " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0x22u) {
        const std::uint8_t modrm = rd8(1);
        const std::string dest = register8_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        std::size_t operand_length = 0;
        const std::string source = format_rm8_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "and " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0x30u) {
        const std::uint8_t modrm = rd8(1);
        const std::string source = register8_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        std::size_t operand_length = 0;
        const std::string dest = format_rm8_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "xor " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0x2Cu) {
        const std::uint8_t imm = rd8(1);
        inst.text = "sub al, " + hex8(imm);
        inst.length = 2;
    } else if (opcode == 0x2Du) {
        const std::uint16_t imm = rd16(1);
        inst.text = "sub ax, " + hex16(imm);
        inst.length = 3;
    } else if (opcode == 0x29u) {
        const std::uint8_t modrm = rd8(1);
        const std::string source = register16_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        std::size_t operand_length = 0;
        const std::string dest = format_rm16_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "sub " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0x28u) {
        const std::uint8_t modrm = rd8(1);
        const std::string source = register8_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        std::size_t operand_length = 0;
        const std::string dest = format_rm8_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "sub " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0x2Au) {
        const std::uint8_t modrm = rd8(1);
        const std::string dest = register8_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        std::size_t operand_length = 0;
        const std::string source = format_rm8_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "sub " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0x2Bu) {
        const std::uint8_t modrm = rd8(1);
        const std::string dest = register16_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        std::size_t operand_length = 0;
        const std::string source = format_rm16_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "sub " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0x32u) {
        const std::uint8_t modrm = rd8(1);
        const std::string dest = register8_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        std::size_t operand_length = 0;
        const std::string source = format_rm8_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "xor " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0x03u) {
        const std::uint8_t modrm = rd8(1);
        const std::string dest = register16_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        std::size_t operand_length = 0;
        const std::string source = format_rm16_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "add " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0x02u) {
        const std::uint8_t modrm = rd8(1);
        const std::string dest = register8_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        std::size_t operand_length = 0;
        const std::string source = format_rm8_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "add " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0x33u) {
        const std::uint8_t modrm = rd8(1);
        const std::string dest = register16_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        std::size_t operand_length = 0;
        const std::string source = format_rm16_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "xor " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0x08u) {
        const std::uint8_t modrm = rd8(1);
        const std::string source = register8_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        std::size_t operand_length = 0;
        const std::string dest = format_rm8_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "or " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0x09u) {
        const std::uint8_t modrm = rd8(1);
        const std::string source = register16_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        std::size_t operand_length = 0;
        const std::string dest = format_rm16_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "or " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0x0Au) {
        const std::uint8_t modrm = rd8(1);
        const std::string dest = register8_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        std::size_t operand_length = 0;
        const std::string source = format_rm8_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "or " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0x23u) {
        const std::uint8_t modrm = rd8(1);
        const std::string dest = register16_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        std::size_t operand_length = 0;
        const std::string source = format_rm16_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "and " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0x3Bu) {
        const std::uint8_t modrm = rd8(1);
        const std::string dest = register16_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        std::size_t operand_length = 0;
        const std::string source = format_rm16_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "cmp " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0x39u) {
        const std::uint8_t modrm = rd8(1);
        const std::string source = register16_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        std::size_t operand_length = 0;
        const std::string dest = format_rm16_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "cmp " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0x81u) {
        const std::uint8_t modrm = rd8(1);
        const std::uint8_t group = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
        std::size_t operand_length = 0;
        const std::string operand = format_rm16_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        const std::uint16_t imm = rd16(1u + operand_length);
        const std::string op_name = group1_op_name_16(group);
        if (op_name.empty()) {
            throw std::runtime_error("unsupported 81h group variant");
        }
        inst.text = op_name + " " + operand + ", " + hex16(imm);
        inst.length = 1u + operand_length + 2u;
    } else if (opcode == 0x8Fu) {
        const std::uint8_t modrm = rd8(1);
        const std::uint8_t group = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
        if (group != 0u) {
            throw std::runtime_error("unsupported 8Fh group variant");
        }
        std::size_t operand_length = 0;
        const std::string operand = format_rm16_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "pop " + operand;
        inst.length = 1u + operand_length;
    } else if (opcode == 0x0Bu) {
        const std::uint8_t modrm = rd8(1);
        const std::string dest = register16_name(static_cast<std::uint8_t>((modrm >> 3u) & 0x07u));
        std::size_t operand_length = 0;
        const std::string source = format_rm16_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        inst.text = "or " + dest + ", " + source;
        inst.length = 1u + operand_length;
    } else if (opcode == 0xF7u) {
        const std::uint8_t modrm = rd8(1);
        const std::uint8_t group = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
        std::size_t operand_length = 0;
        const std::string operand = format_rm16_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        const std::size_t base_length = 1u + operand_length;
        switch (group) {
        case 0u: {
            const std::uint16_t imm = rd16(1u + operand_length);
            inst.text = "test " + operand + ", " + hex16(imm);
            break;
        }
        case 2u:
            inst.text = "not " + operand;
            break;
        case 3u:
            inst.text = "neg " + operand;
            break;
        case 4u:
            inst.text = "mul " + operand;
            break;
        case 6u:
            inst.text = "div " + operand;
            break;
        case 7u:
            inst.text = "idiv " + operand;
            break;
        default:
            throw std::runtime_error("unsupported F7h group variant");
        }
        inst.length = (group == 0u) ? (base_length + 2u) : base_length;
    } else if (opcode == 0xF6u) {
        const std::uint8_t modrm = rd8(1);
        const std::uint8_t group = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
        std::size_t operand_length = 0;
        const std::string operand = format_rm8_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        switch (group) {
        case 0u: {
            const std::uint8_t imm = rd8(1u + operand_length);
            inst.text = "test " + operand + ", " + hex8(imm);
            inst.length = 1u + operand_length + 1u;
            break;
        }
        case 2u:
            inst.text = "not " + operand;
            inst.length = 1u + operand_length;
            break;
        case 3u:
            inst.text = "neg " + operand;
            inst.length = 1u + operand_length;
            break;
        case 4u:
            inst.text = "mul " + operand;
            inst.length = 1u + operand_length;
            break;
        case 5u:
            inst.text = "imul " + operand;
            inst.length = 1u + operand_length;
            break;
        case 6u:
            inst.text = "div " + operand;
            inst.length = 1u + operand_length;
            break;
        case 7u:
            inst.text = "idiv " + operand;
            inst.length = 1u + operand_length;
            break;
        default:
            throw std::runtime_error("unsupported F6 group variant");
        }
    } else if (opcode == 0x80u) {
        const std::uint8_t modrm = rd8(1);
        const std::uint8_t group = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
        std::size_t operand_length = 0;
        const std::string operand = format_rm8_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        const std::uint8_t imm = rd8(1u + operand_length);
        const std::string op_name = group1_op_name_8(group);
        if (op_name.empty()) {
            throw std::runtime_error("unsupported 80h group variant");
        }
        inst.text = op_name + " " + operand + ", " + hex8(imm);
        inst.length = 1u + operand_length + 1u;
    } else if (opcode == 0x83u) {
        const std::uint8_t modrm = rd8(1);
        const std::uint8_t group = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
        std::size_t operand_length = 0;
        const std::string operand = format_rm16_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        const std::int8_t imm = rs8(1u + operand_length);
        const std::string op_name = group1_op_name_16(group);
        if (op_name.empty()) {
            throw std::runtime_error("unsupported 83h group variant");
        }
        inst.text = op_name + " " + operand + ", " + hex16(static_cast<std::uint16_t>(imm));
        inst.length = 1u + operand_length + 1u;
    } else if (opcode == 0xD1u) {
        const std::uint8_t modrm = rd8(1);
        const std::uint8_t group = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
        std::size_t operand_length = 0;
        const std::string operand = format_rm16_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        switch (group) {
        case 0u:
            inst.text = "rol " + operand + ", 1";
            break;
        case 1u:
            inst.text = "ror " + operand + ", 1";
            break;
        case 2u:
            inst.text = "rcl " + operand + ", 1";
            break;
        case 3u:
            inst.text = "rcr " + operand + ", 1";
            break;
        case 4u:
            inst.text = "shl " + operand + ", 1";
            break;
        case 5u:
            inst.text = "shr " + operand + ", 1";
            break;
        case 7u:
            inst.text = "sar " + operand + ", 1";
            break;
        default:
            throw std::runtime_error("unsupported D1h group variant");
        }
        inst.length = 1u + operand_length;
    } else if (opcode == 0xD0u) {
        const std::uint8_t modrm = rd8(1);
        const std::uint8_t group = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
        std::size_t operand_length = 0;
        const std::string operand = format_rm8_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        switch (group) {
        case 0u:
            inst.text = "rol " + operand + ", 1";
            break;
        case 1u:
            inst.text = "ror " + operand + ", 1";
            break;
        case 2u:
            inst.text = "rcl " + operand + ", 1";
            break;
        case 3u:
            inst.text = "rcr " + operand + ", 1";
            break;
        case 4u:
            inst.text = "shl " + operand + ", 1";
            break;
        case 5u:
            inst.text = "shr " + operand + ", 1";
            break;
        case 7u:
            inst.text = "sar " + operand + ", 1";
            break;
        default:
            throw std::runtime_error("unsupported D0h group variant");
        }
        inst.length = 1u + operand_length;
    } else if (opcode == 0xD2u) {
        const std::uint8_t modrm = rd8(1);
        const std::uint8_t group = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
        std::size_t operand_length = 0;
        const std::string operand = format_rm8_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        switch (group) {
        case 0u:
            inst.text = "rol " + operand + ", cl";
            break;
        case 1u:
            inst.text = "ror " + operand + ", cl";
            break;
        case 2u:
            inst.text = "rcl " + operand + ", cl";
            break;
        case 3u:
            inst.text = "rcr " + operand + ", cl";
            break;
        case 4u:
            inst.text = "shl " + operand + ", cl";
            break;
        case 5u:
            inst.text = "shr " + operand + ", cl";
            break;
        case 7u:
            inst.text = "sar " + operand + ", cl";
            break;
        default:
            throw std::runtime_error("unsupported D2h group variant");
        }
        inst.length = 1u + operand_length;
    } else if (opcode == 0xD3u) {
        const std::uint8_t modrm = rd8(1);
        const std::uint8_t group = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
        std::size_t operand_length = 0;
        const std::string operand = format_rm16_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        switch (group) {
        case 0u:
            inst.text = "rol " + operand + ", cl";
            break;
        case 1u:
            inst.text = "ror " + operand + ", cl";
            break;
        case 2u:
            inst.text = "rcl " + operand + ", cl";
            break;
        case 3u:
            inst.text = "rcr " + operand + ", cl";
            break;
        case 4u:
            inst.text = "shl " + operand + ", cl";
            break;
        case 5u:
            inst.text = "shr " + operand + ", cl";
            break;
        case 7u:
            inst.text = "sar " + operand + ", cl";
            break;
        default:
            throw std::runtime_error("unsupported D3h group variant");
        }
        inst.length = 1u + operand_length;
    } else if (opcode == 0xFEu) {
        const std::uint8_t modrm = rd8(1);
        const std::uint8_t group = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
        std::size_t operand_length = 0;
        const std::string operand = format_rm8_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        switch (group) {
        case 0u:
            inst.text = "inc " + operand;
            break;
        case 1u:
            inst.text = "dec " + operand;
            break;
        default:
            throw std::runtime_error("unsupported FEh group variant");
        }
        inst.length = 1u + operand_length;
    } else if (opcode == 0xABu) {
        inst.text = "stosw";
        inst.length = 1;
    } else if (opcode == 0xA4u) {
        inst.text = "movsb";
        inst.length = 1;
    } else if (opcode == 0xA5u) {
        inst.text = "movsw";
        inst.length = 1;
    } else if (opcode == 0xA6u) {
        inst.text = repeat_prefix.empty() ? "cmpsb" : (repeat_prefix + " cmpsb");
        inst.length = 1;
    } else if (opcode == 0xACu) {
        inst.text = "lodsb";
        inst.length = 1;
    } else if (opcode == 0xADu) {
        inst.text = "lodsw";
        inst.length = 1;
    } else if (opcode == 0xE4u) {
        const std::uint8_t port = rd8(1);
        inst.text = "in al, " + hex8(port);
        inst.length = 2;
    } else if (opcode == 0xE5u) {
        const std::uint8_t port = rd8(1);
        inst.text = "in ax, " + hex8(port);
        inst.length = 2;
    } else if (opcode == 0xECu) {
        inst.text = "in al, dx";
        inst.length = 1;
    } else if (opcode == 0xEDu) {
        inst.text = "in ax, dx";
        inst.length = 1;
    } else if (opcode == 0xE6u) {
        const std::uint8_t port = rd8(1);
        inst.text = "out " + hex8(port) + ", al";
        inst.length = 2;
    } else if (opcode == 0xEEu) {
        inst.text = "out dx, al";
        inst.length = 1;
    } else if (opcode == 0xEFu) {
        inst.text = "out dx, ax";
        inst.length = 1;
    } else if (opcode == 0x6Fu) {
        inst.text = "outsw";
        inst.length = 1;
    } else if (opcode == 0xE2u) {
        const std::int8_t rel = rs8(1);
        const std::uint16_t target = static_cast<std::uint16_t>(ip + prefix_length + 2u + rel);
        inst.text = "loop " + hex16(cs) + ':' + hex16(target).substr(2);
        inst.length = 2;
        inst.flow = FlowKind::ConditionalBranch;
        inst.branch_target_cs = cs;
        inst.branch_target_ip = target;
        inst.branch_fallthrough_ip = static_cast<std::uint16_t>(ip + prefix_length + inst.length);
    } else if (opcode == 0xE3u) {
        const std::int8_t rel = rs8(1);
        const std::uint16_t target = static_cast<std::uint16_t>(ip + prefix_length + 2u + rel);
        inst.text = "jcxz " + hex16(cs) + ':' + hex16(target).substr(2);
        inst.length = 2;
        inst.flow = FlowKind::ConditionalBranch;
        inst.branch_target_cs = cs;
        inst.branch_target_ip = target;
        inst.branch_fallthrough_ip = static_cast<std::uint16_t>(ip + prefix_length + inst.length);
    } else if (opcode == 0xFFu) {
        const std::uint8_t modrm = rd8(1);
        const std::uint8_t group = static_cast<std::uint8_t>((modrm >> 3u) & 0x07u);
        std::size_t operand_length = 0;
        const std::string operand = format_rm16_operand(image, cs, ip, prefix_length + 1, segment_override, operand_length);
        switch (group) {
        case 0u:
            inst.text = "inc " + operand;
            inst.length = 1u + operand_length;
            break;
        case 1u:
            inst.text = "dec " + operand;
            inst.length = 1u + operand_length;
            break;
        case 2u:
            inst.text = "call " + operand;
            inst.length = 1u + operand_length;
            inst.flow = FlowKind::Call;
            inst.indirect = make_indirect_transfer_info(
                image, cs, ip, prefix_length + 1u, segment_override, false, operand);
            inst.branch_fallthrough_ip = static_cast<std::uint16_t>(ip + prefix_length + inst.length);
            break;
        case 3u:
            if (modrm_uses_register_operand(image, cs, ip, prefix_length + 1u)) {
                throw std::runtime_error("unsupported far call with register operand");
            }
            inst.text = "call far " + operand;
            inst.length = 1u + operand_length;
            inst.flow = FlowKind::Call;
            inst.indirect = make_indirect_transfer_info(
                image, cs, ip, prefix_length + 1u, segment_override, true, operand);
            inst.branch_fallthrough_ip = static_cast<std::uint16_t>(ip + prefix_length + inst.length);
            break;
        case 4u:
            inst.text = "jmp " + operand;
            inst.length = 1u + operand_length;
            inst.flow = FlowKind::UnconditionalBranch;
            inst.indirect = make_indirect_transfer_info(
                image, cs, ip, prefix_length + 1u, segment_override, false, operand);
            break;
        case 5u:
            if (modrm_uses_register_operand(image, cs, ip, prefix_length + 1u)) {
                throw std::runtime_error("unsupported far jump with register operand");
            }
            inst.text = "jmp far " + operand;
            inst.length = 1u + operand_length;
            inst.flow = FlowKind::UnconditionalBranch;
            inst.indirect = make_indirect_transfer_info(
                image, cs, ip, prefix_length + 1u, segment_override, true, operand);
            break;
        case 6u:
            inst.text = "push " + operand;
            inst.length = 1u + operand_length;
            break;
        default:
            throw std::runtime_error("unsupported FFh group variant");
        }
    } else if (opcode == 0xCCu) {
        inst.text = "int " + hex8(0x03u);
        inst.length = 1;
        inst.flow = FlowKind::Interrupt;
    } else if (opcode == 0xCDu) {
        const std::uint8_t int_num = rd8(1);
        inst.text = "int " + hex8(int_num);
        inst.length = 2;
        inst.flow = FlowKind::Interrupt;
    } else if (opcode == 0xC2u) {
        const std::uint16_t imm = rd16(1);
        inst.text = "ret " + hex16(imm);
        inst.length = 3;
        inst.flow = FlowKind::Return;
    } else if (opcode == 0xC3u) {
        inst.text = "ret";
        inst.length = 1;
        inst.flow = FlowKind::Return;
    } else if (opcode == 0xCFu) {
        inst.text = "iret";
        inst.length = 1;
        inst.flow = FlowKind::Return;
    } else if (opcode == 0xCAu) {
        const std::uint16_t imm = rd16(1);
        inst.text = "retf " + hex16(imm);
        inst.length = 3;
        inst.flow = FlowKind::Return;
    } else if (opcode == 0xCBu) {
        inst.text = "retf";
        inst.length = 1;
        inst.flow = FlowKind::Return;
    } else if (opcode == 0xD7u) {
        inst.text = "xlat";
        inst.length = 1;
    } else {
        std::ostringstream oss;
        oss << "unsupported opcode " << hex8(opcode);
        throw std::runtime_error(oss.str());
    }

    if (!repeat_prefix.empty()) {
        inst.text = repeat_prefix + " " + inst.text;
    }
    inst.length += prefix_length;
    capture_bytes(image, inst);
    if (inst.flow == FlowKind::Fallthrough) {
        inst.branch_fallthrough_ip = static_cast<std::uint16_t>(ip + inst.length);
    }
    return inst;
}

BasicBlockPreview decode_basic_block_preview(const MzImage& image,
                                             const std::uint16_t cs,
                                             const std::uint16_t start_ip,
                                             const std::size_t max_instructions) {
    BasicBlockPreview preview{};
    preview.cs = cs;
    preview.start_ip = start_ip;

    std::uint16_t ip = start_ip;
    const std::size_t instruction_budget =
        (max_instructions == 0u) ? std::numeric_limits<std::size_t>::max() : max_instructions;

    for (std::size_t i = 0; i < instruction_budget; ++i) {
        try {
            DecodedInstruction inst = decode_instruction(image, cs, ip);
            ip = static_cast<std::uint16_t>(ip + inst.length);
            const FlowKind flow = inst.flow;
            preview.instructions.push_back(std::move(inst));
            if (flow == FlowKind::ConditionalBranch ||
                flow == FlowKind::UnconditionalBranch ||
                flow == FlowKind::Return ||
                flow == FlowKind::Halt) {
                preview.terminated = true;
                preview.termination_reason = "control-transfer terminator";
                return preview;
            }
        } catch (const std::exception& ex) {
            preview.terminated = false;
            preview.termination_reason = ex.what();
            return preview;
        }
    }

    preview.terminated = false;
    preview.termination_reason = "instruction limit reached";
    return preview;
}

} // namespace mz2cpp
