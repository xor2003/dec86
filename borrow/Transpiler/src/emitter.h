#pragma once

#include "cfg.h"
#include "mz_exe.h"

#include <filesystem>
#include <optional>

namespace mz2cpp {

void emit_standalone_project(const MzImage& image,
                             const CfgSnapshot& snapshot,
                             const std::filesystem::path& output_dir,
                             const std::optional<std::filesystem::path>& labels_path = std::nullopt);

} // namespace mz2cpp
