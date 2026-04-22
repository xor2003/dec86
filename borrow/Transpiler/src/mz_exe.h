#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace mz2cpp {

struct RelocationEntry {
    std::uint16_t offset = 0;
    std::uint16_t segment = 0;
};

struct MzHeader {
    std::uint16_t signature = 0;
    std::uint16_t bytes_in_last_page = 0;
    std::uint16_t page_count = 0;
    std::uint16_t relocation_count = 0;
    std::uint16_t header_paragraphs = 0;
    std::uint16_t min_alloc_paragraphs = 0;
    std::uint16_t max_alloc_paragraphs = 0;
    std::uint16_t initial_ss = 0;
    std::uint16_t initial_sp = 0;
    std::uint16_t checksum = 0;
    std::uint16_t initial_ip = 0;
    std::uint16_t initial_cs = 0;
    std::uint16_t relocation_table_offset = 0;
    std::uint16_t overlay_number = 0;
};

struct LoadLayout {
    std::uint16_t psp_segment = 0x1000;

    [[nodiscard]] std::uint16_t load_segment() const {
        return static_cast<std::uint16_t>(psp_segment + 0x0010u);
    }
};

struct MzImage {
    std::filesystem::path source_path;
    MzHeader header;
    LoadLayout layout;
    std::vector<RelocationEntry> relocations;
    std::vector<std::uint8_t> file_bytes;
    std::vector<std::uint8_t> load_module_bytes;
    std::vector<std::uint8_t> relocated_load_module_bytes;
    std::uint32_t expected_file_size = 0;
    std::uint32_t module_file_offset = 0;
    std::uint32_t module_size = 0;
    std::uint32_t psp_physical = 0;
    std::uint32_t load_module_physical = 0;
    std::uint32_t image_end_physical = 0;
    std::uint16_t entry_cs = 0;
    std::uint16_t entry_ip = 0;
    std::uint16_t stack_ss = 0;
    std::uint16_t stack_sp = 0;
    std::uint32_t entry_physical = 0;
    std::uint32_t stack_physical = 0;
    std::vector<std::uint8_t> initial_memory_image;
};

MzImage load_mz_image(const std::filesystem::path& path, const LoadLayout& layout = {});

[[nodiscard]] std::uint16_t read_u16(const std::vector<std::uint8_t>& bytes, std::size_t offset);
[[nodiscard]] std::uint32_t real_mode_phys(std::uint16_t segment, std::uint16_t offset);

} // namespace mz2cpp
