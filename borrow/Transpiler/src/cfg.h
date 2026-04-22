#pragma once

#include "decoder.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace mz2cpp {

enum class EdgeKind {
    Branch,
    Fallthrough,
    Call,
};

struct CodeLocation {
    std::uint16_t cs = 0;
    std::uint16_t ip = 0;
};

struct CfgEdge {
    CodeLocation from{};
    CodeLocation to{};
    EdgeKind kind = EdgeKind::Branch;
};

enum class IndirectDispatchKind {
    None,
    CurrentCsWordTable,
    CurrentCsPairTable,
};

enum class InterfaceSurfaceKind {
    EngineApiJumpTable,
    RoutinePackWordTable,
    RoutinePackDescriptorTable,
    RoutinePackPairTable,
};

struct IndirectDispatchEntry {
    std::uint16_t selector = 0;
    CodeLocation target{};
    bool target_is_valid = false;
};

struct IndirectSiteRecord {
    CodeLocation from{};
    EdgeKind kind = EdgeKind::Branch;
    bool is_far = false;
    std::string operand_text;
    std::string resolution_note;
    std::vector<CodeLocation> resolved_targets;
    IndirectDispatchKind dispatch_kind = IndirectDispatchKind::None;
    std::uint16_t dispatch_table_base = 0;
    std::uint16_t dispatch_runtime_index_base = 0;
    std::uint16_t dispatch_entry_stride = 0;
    std::optional<std::uint8_t> dispatch_index_register{};
    std::vector<IndirectDispatchEntry> dispatch_entries;
};

struct BlockRecord {
    CodeLocation start{};
    BasicBlockPreview preview{};
};

struct FunctionRecord {
    struct EntryFragmentRecord {
        enum class Disposition {
            SingleBlockClone,
            CloneFragment,
            SharedRegion,
            SplitRegion,
        };

        enum class LoweringAction {
            CloneLeaf,
            CloneWithRejoin,
            KeepSharedRegion,
            SplitBeforeLowering,
        };

        CodeLocation entry_block{};
        std::vector<CodeLocation> incoming_from_blocks;
        std::vector<CodeLocation> reachable_blocks;
        std::vector<CodeLocation> clone_candidate_blocks;
        std::vector<CodeLocation> shared_blocks;
        std::vector<CodeLocation> exit_to_blocks;
        Disposition disposition = Disposition::SplitRegion;
        LoweringAction lowering_action = LoweringAction::SplitBeforeLowering;
    };

    CodeLocation entry{};
    bool entry_block_present = false;
    std::vector<CodeLocation> reachable_blocks;
    std::vector<CodeLocation> owned_blocks;
    std::vector<CodeLocation> shared_blocks;
    std::vector<CodeLocation> external_entry_blocks;
    std::vector<EntryFragmentRecord> entry_fragments;
};

struct BlockOwnershipRecord {
    CodeLocation block{};
    std::vector<CodeLocation> owners;
};

struct InterfaceSurfaceEntry {
    std::uint16_t ordinal = 0;
    CodeLocation target{};
    bool target_is_valid = false;
};

struct InterfaceSurfaceRecord {
    std::string name;
    InterfaceSurfaceKind kind = InterfaceSurfaceKind::EngineApiJumpTable;
    CodeLocation base{};
    std::vector<InterfaceSurfaceEntry> entries;
};

struct CfgSnapshot {
    CodeLocation root{};
    std::vector<BlockRecord> blocks;
    std::vector<CfgEdge> edges;
    std::vector<IndirectSiteRecord> indirect_sites;
    std::vector<InterfaceSurfaceRecord> interface_surfaces;
    std::vector<CodeLocation> discovered_function_roots;
    std::vector<FunctionRecord> functions;
    std::vector<BlockOwnershipRecord> block_ownerships;
};

CfgSnapshot build_cfg_snapshot(const MzImage& image,
                               CodeLocation root,
                               std::size_t max_blocks,
                               std::size_t max_instructions_per_block,
                               const std::vector<CodeLocation>& additional_roots = {});

std::string format_cfg_snapshot(const CfgSnapshot& snapshot);
std::string format_indirect_site_debug(const MzImage& image, const CfgSnapshot& snapshot, CodeLocation site);

} // namespace mz2cpp
