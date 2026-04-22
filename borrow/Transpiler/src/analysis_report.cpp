#include "analysis_report.h"

#include <algorithm>
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

} // namespace

std::string format_mz_report(const MzImage& image, const std::size_t relocation_preview_count) {
    std::ostringstream oss;
    oss << "Input: " << image.source_path.string() << '\n';
    oss << "Format: DOS MZ executable\n";
    oss << "File size: " << image.file_bytes.size() << " bytes\n";
    oss << "Header size: " << static_cast<std::uint32_t>(image.header.header_paragraphs) * 16u << " bytes\n";
    oss << "Load module offset: " << hex32(image.module_file_offset) << '\n';
    oss << "Load module size: " << image.module_size << " bytes\n";
    oss << "Relocations: " << image.relocations.size() << '\n';
    oss << "Overlay number: " << image.header.overlay_number << '\n';
    oss << "Minimum allocation: " << image.header.min_alloc_paragraphs << " paragraphs\n";
    oss << "Maximum allocation: " << image.header.max_alloc_paragraphs << " paragraphs\n";
    oss << "PSP segment assumption: " << hex16(image.layout.psp_segment) << '\n';
    oss << "Load segment assumption: " << hex16(image.layout.load_segment()) << '\n';
    oss << "PSP physical: " << hex32(image.psp_physical) << '\n';
    oss << "Load module physical: " << hex32(image.load_module_physical) << '\n';
    oss << "Image end physical: " << hex32(image.image_end_physical) << '\n';
    oss << "Entrypoint: " << hex16(image.entry_cs) << ':' << hex16(image.entry_ip).substr(2) << '\n';
    oss << "Entrypoint physical: " << hex32(image.entry_physical) << '\n';
    oss << "Initial stack: " << hex16(image.stack_ss) << ':' << hex16(image.stack_sp).substr(2) << '\n';
    oss << "Initial stack physical: " << hex32(image.stack_physical) << '\n';

    const std::size_t preview_count = std::min(relocation_preview_count, image.relocations.size());
    if (preview_count != 0) {
        oss << "Relocation preview:\n";
        for (std::size_t i = 0; i < preview_count; ++i) {
            const RelocationEntry& relocation = image.relocations[i];
            const std::uint32_t linear_offset =
                static_cast<std::uint32_t>(relocation.segment) * 16u + relocation.offset;
            oss << "  [" << i << "] "
                << hex16(relocation.segment) << ':' << hex16(relocation.offset).substr(2)
                << " -> load-module offset " << hex32(linear_offset) << '\n';
        }
    }

    return oss.str();
}

} // namespace mz2cpp
