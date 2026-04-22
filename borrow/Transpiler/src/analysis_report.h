#pragma once

#include "mz_exe.h"

#include <cstddef>
#include <string>

namespace mz2cpp {

std::string format_mz_report(const MzImage& image, std::size_t relocation_preview_count);

} // namespace mz2cpp
