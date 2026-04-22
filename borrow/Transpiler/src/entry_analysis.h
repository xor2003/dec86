#pragma once

#include "decoder.h"

#include <string>

namespace mz2cpp {

std::string format_basic_block_analysis(const MzImage& image,
                                        std::uint16_t cs,
                                        std::uint16_t ip,
                                        std::size_t max_instructions,
                                        const std::string& title);

std::string format_entry_analysis(const MzImage& image, std::size_t max_instructions);

} // namespace mz2cpp
