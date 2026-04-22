#include "mz_exe.h"

#include <fstream>
#include <sstream>
#include <stdexcept>

namespace mz2cpp {

namespace {

constexpr std::uint32_t kRealModeAddressSpaceSize = 1u << 20u;

std::vector<std::uint8_t> read_file_bytes(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("failed to open input file: " + path.string());
    }

    in.seekg(0, std::ios::end);
    const std::streamoff size = in.tellg();
    if (size < 0) {
        throw std::runtime_error("failed to measure input file: " + path.string());
    }
    in.seekg(0, std::ios::beg);

    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size), 0);
    if (!bytes.empty()) {
        in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    }
    if (!in && !bytes.empty()) {
        throw std::runtime_error("failed to read input file: " + path.string());
    }
    return bytes;
}

[[nodiscard]] std::uint32_t compute_expected_file_size(const MzHeader& header) {
    if (header.page_count == 0) {
        return 0;
    }
    const std::uint32_t page_bytes = static_cast<std::uint32_t>(header.page_count - 1u) * 512u;
    const std::uint32_t tail_bytes = (header.bytes_in_last_page == 0) ? 512u : header.bytes_in_last_page;
    return page_bytes + tail_bytes;
}

[[nodiscard]] MzHeader parse_header(const std::vector<std::uint8_t>& bytes) {
    if (bytes.size() < 0x1Cu) {
        throw std::runtime_error("file is too small to contain an MZ header");
    }

    MzHeader header{};
    header.signature = read_u16(bytes, 0x00);
    header.bytes_in_last_page = read_u16(bytes, 0x02);
    header.page_count = read_u16(bytes, 0x04);
    header.relocation_count = read_u16(bytes, 0x06);
    header.header_paragraphs = read_u16(bytes, 0x08);
    header.min_alloc_paragraphs = read_u16(bytes, 0x0A);
    header.max_alloc_paragraphs = read_u16(bytes, 0x0C);
    header.initial_ss = read_u16(bytes, 0x0E);
    header.initial_sp = read_u16(bytes, 0x10);
    header.checksum = read_u16(bytes, 0x12);
    header.initial_ip = read_u16(bytes, 0x14);
    header.initial_cs = read_u16(bytes, 0x16);
    header.relocation_table_offset = read_u16(bytes, 0x18);
    header.overlay_number = read_u16(bytes, 0x1A);
    return header;
}

[[nodiscard]] std::vector<RelocationEntry> parse_relocations(
    const std::vector<std::uint8_t>& bytes,
    const MzHeader& header) {
    const std::size_t table_offset = header.relocation_table_offset;
    const std::size_t table_size = static_cast<std::size_t>(header.relocation_count) * 4u;
    if (table_offset + table_size > bytes.size()) {
        throw std::runtime_error("relocation table extends past the end of the file");
    }

    std::vector<RelocationEntry> relocations;
    relocations.reserve(header.relocation_count);
    for (std::size_t i = 0; i < header.relocation_count; ++i) {
        const std::size_t entry_offset = table_offset + i * 4u;
        relocations.push_back(RelocationEntry{
            read_u16(bytes, entry_offset),
            read_u16(bytes, entry_offset + 2u),
        });
    }
    return relocations;
}

void apply_relocations(MzImage& image) {
    for (const RelocationEntry& relocation : image.relocations) {
        const std::size_t fixup_offset =
            static_cast<std::size_t>(relocation.segment) * 16u + relocation.offset;
        if (fixup_offset + 1u >= image.relocated_load_module_bytes.size()) {
            std::ostringstream oss;
            oss << "relocation target is outside the load module: segment="
                << relocation.segment << " offset=" << relocation.offset;
            throw std::runtime_error(oss.str());
        }

        const std::uint16_t current =
            static_cast<std::uint16_t>(image.relocated_load_module_bytes[fixup_offset]) |
            static_cast<std::uint16_t>(image.relocated_load_module_bytes[fixup_offset + 1u] << 8u);
        const std::uint16_t relocated =
            static_cast<std::uint16_t>(current + image.layout.load_segment());

        image.relocated_load_module_bytes[fixup_offset] =
            static_cast<std::uint8_t>(relocated & 0x00FFu);
        image.relocated_load_module_bytes[fixup_offset + 1u] =
            static_cast<std::uint8_t>((relocated >> 8u) & 0x00FFu);
    }
}

void build_initial_memory_image(MzImage& image) {
    image.initial_memory_image.assign(kRealModeAddressSpaceSize, 0u);
    image.psp_physical = real_mode_phys(image.layout.psp_segment, 0u);
    image.load_module_physical = real_mode_phys(image.layout.load_segment(), 0u);
    image.image_end_physical = image.load_module_physical + image.module_size;

    if (image.image_end_physical > image.initial_memory_image.size()) {
        throw std::runtime_error("load module does not fit inside the 20-bit real-mode address space");
    }

    std::copy(image.relocated_load_module_bytes.begin(),
              image.relocated_load_module_bytes.end(),
              image.initial_memory_image.begin() + static_cast<std::ptrdiff_t>(image.load_module_physical));

    // Match the minimal PSP bootstrap currently used by the old runtime:
    // `INT 20h`, a conventional-memory marker word, and an empty command tail.
    image.initial_memory_image[image.psp_physical + 0x0000u] = 0xCDu;
    image.initial_memory_image[image.psp_physical + 0x0001u] = 0x20u;
    image.initial_memory_image[image.psp_physical + 0x0002u] = 0xFFu;
    image.initial_memory_image[image.psp_physical + 0x0003u] = 0x9Fu;
    image.initial_memory_image[image.psp_physical + 0x0080u] = 0x00u;
}

} // namespace

std::uint16_t read_u16(const std::vector<std::uint8_t>& bytes, const std::size_t offset) {
    if (offset + 1u >= bytes.size()) {
        throw std::runtime_error("attempted to read past the end of a byte buffer");
    }
    return static_cast<std::uint16_t>(bytes[offset]) |
           static_cast<std::uint16_t>(bytes[offset + 1u] << 8u);
}

std::uint32_t real_mode_phys(const std::uint16_t segment, const std::uint16_t offset) {
    return ((static_cast<std::uint32_t>(segment) << 4u) + static_cast<std::uint32_t>(offset)) & 0xFFFFFu;
}

MzImage load_mz_image(const std::filesystem::path& path, const LoadLayout& layout) {
    MzImage image{};
    image.source_path = path;
    image.layout = layout;
    image.file_bytes = read_file_bytes(path);
    image.header = parse_header(image.file_bytes);

    if (image.header.signature != 0x5A4Du) {
        throw std::runtime_error("input file is not an MZ executable: " + path.string());
    }

    image.expected_file_size = compute_expected_file_size(image.header);
    if (image.expected_file_size != image.file_bytes.size()) {
        std::ostringstream oss;
        oss << "header-declared file size (" << image.expected_file_size
            << ") does not match actual file size (" << image.file_bytes.size() << ')';
        throw std::runtime_error(oss.str());
    }

    image.module_file_offset = static_cast<std::uint32_t>(image.header.header_paragraphs) * 16u;
    if (image.module_file_offset > image.file_bytes.size()) {
        throw std::runtime_error("header paragraphs place the load module past the end of the file");
    }

    image.module_size = image.expected_file_size - image.module_file_offset;
    image.load_module_bytes.assign(
        image.file_bytes.begin() + static_cast<std::ptrdiff_t>(image.module_file_offset),
        image.file_bytes.end());
    image.relocated_load_module_bytes = image.load_module_bytes;
    image.relocations = parse_relocations(image.file_bytes, image.header);

    apply_relocations(image);

    image.entry_cs = static_cast<std::uint16_t>(image.layout.load_segment() + image.header.initial_cs);
    image.entry_ip = image.header.initial_ip;
    image.stack_ss = static_cast<std::uint16_t>(image.layout.load_segment() + image.header.initial_ss);
    image.stack_sp = image.header.initial_sp;
    image.entry_physical = real_mode_phys(image.entry_cs, image.entry_ip);
    image.stack_physical = real_mode_phys(image.stack_ss, image.stack_sp);
    build_initial_memory_image(image);

    return image;
}

} // namespace mz2cpp
