from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tools.dosunit.complexity import analyze_function_complexity
from tools.dosunit.data_compare import compare_loaded_data_images
from tools.dosunit.discovery import discover_functions
from tools.dosunit.dosunit import main as dosunit_main
from tools.dosunit.failure_report import render_failure_report
from tools.dosunit import ir_edges
from tools.dosunit.generate import generate_vectors
from tools.dosunit.kvikdos_backend import KvikdosSession, build_harness
from tools.dosunit.libdosbox_import import import_libdosbox_trace
from tools.dosunit.mapping import MappingResolutionError, apply_candidate_mapping, make_mapping_document
from tools.dosunit.region_effects import compare_region_effect_documents, summarize_region_effects
from tools.dosunit.runner import compare_vectors, record_oracle
from tools.dosunit.straightline_ssa import compare_ssa_documents, lower_straightline_ssa_document
from tools.dosunit.vectors import select_vectors


def _write(path: Path, text: str) -> Path:
    path.write_text(text)
    return path


def _mz_exe(image: bytes, *, relocs: tuple[tuple[int, int], ...] = (), minalloc: int = 0x1000) -> bytes:
    reloc_pos = 0x1C
    header_size = max(0x20, ((reloc_pos + len(relocs) * 4 + 15) // 16) * 16)
    file_size = header_size + len(image)
    blocks, lastsize = divmod(file_size, 512)
    if lastsize:
        blocks += 1
    header = bytearray(header_size)
    header[0:2] = b"MZ"
    header[0x02:0x04] = lastsize.to_bytes(2, "little")
    header[0x04:0x06] = blocks.to_bytes(2, "little")
    header[0x06:0x08] = len(relocs).to_bytes(2, "little")
    header[0x08:0x0A] = (header_size // 16).to_bytes(2, "little")
    header[0x0A:0x0C] = minalloc.to_bytes(2, "little")
    header[0x0C:0x0E] = (0xFFFF).to_bytes(2, "little")
    header[0x0E:0x10] = (0x0080).to_bytes(2, "little")
    header[0x10:0x12] = (0xFFFE).to_bytes(2, "little")
    header[0x14:0x16] = (0).to_bytes(2, "little")
    header[0x16:0x18] = (0).to_bytes(2, "little")
    header[0x18:0x1A] = reloc_pos.to_bytes(2, "little")
    for idx, (off, seg) in enumerate(relocs):
        at = reloc_pos + idx * 4
        header[at : at + 2] = off.to_bytes(2, "little")
        header[at + 2 : at + 4] = seg.to_bytes(2, "little")
    return bytes(header) + image


def _leaf_vector() -> dict[str, object]:
    return {
        "schema": "dosunit.vector.v1",
        "module": "demo.exe",
        "function": {"name": "leaf", "entry": {"cs": "0x0000", "ip": "0x0200", "kind": "near"}},
        "source": {"kind": "manual", "origin": "test", "assumptions": []},
        "pre": {
            "regs": {
                "ax": "0x0000",
                "bx": "0x0000",
                "cx": "0x0000",
                "dx": "0x0000",
                "si": "0x0000",
                "di": "0x0000",
                "bp": "0x0000",
                "sp": "0xff00",
                "flags": "0x0202",
            },
            "sregs": {"cs": "auto", "ds": "auto", "es": "auto", "ss": "auto"},
            "memory": [],
        },
        "observe": {
            "regs": ["ax", "sp"],
            "sregs": ["cs", "ds", "ss"],
            "flags_mask": "0xffff",
            "memory": [],
            "calls": True,
            "return": True,
        },
        "expected": None,
    }


def test_dosunit_discovers_mzre_map_and_ida_listing(tmp_path: Path):
    exe = tmp_path / "EGAME.EXE"
    exe.write_bytes(
        b"MZ"
        + b"\x00\x00"
        + b"\x00\x00"
        + b"\x00\x00"
        + b"\x00\x00"
        + b"\x20\x00"
        + b"\x00\x00" * 2
        + b"\x00\x00"
        + b"\x00\x10"
        + b"\x10\x00"
        + b"\x00\x00"
        + b"\x00\x00"
        + b"\x1c\x00"
        + b"\x00" * 96
    )
    mzre_map = _write(
        tmp_path / "egame.map",
        "\n".join(
            [
                "Size 28f70",
                "seg000 CODE 0000",
                "Data1 DATA 228b",
                "main: seg000 NEAR 0010-0146 R0010-0146 complete",
                "lookupSineFar: seg000 FAR 3bc1-3bc4 R3bc1-3bc4 assembly",
            ]
        ),
    )
    ida_lst = _write(
        tmp_path / "egame.lst",
        "\n".join(
            [
                "seg000:0000 ; Base Address: 1000h Range: 10000h-3D0D0h Loaded length: 28F70h",
                "seg000:0000 seg000 segment byte public 'CODE' use16",
                "seg000:0010 _main proc near",
                "seg000:3BC1 _lookupSineFar proc far",
                "seg000:E5BF __exit proc near",
            ]
        ),
    )

    catalog = discover_functions(exe_path=exe, map_path=mzre_map, ida_listing_path=ida_lst, module="egame.exe")

    assert catalog["schema"] == "dosunit.functions.v1"
    assert catalog["program_kind"] == "mz_exe"
    by_id = {item["id"]: item for item in catalog["functions"]}
    assert by_id["egame.exe:main"]["entry"]["offset"] == "0x0010"
    assert by_id["egame.exe:main"]["entry"]["segment_para"] == "0x0000"
    assert by_id["egame.exe:main"]["confidence"] == "high"
    assert by_id["egame.exe:lookupSineFar"]["return_kind"] == "far"
    assert by_id["egame.exe:__exit"]["entry"]["offset"] == "0xe5bf"
    assert catalog["segments"][1]["name"] == "Data1"
    assert catalog["segments"][1]["paragraph"] == "0x228b"


def test_dosunit_imports_libdosbox_runtime_json_as_priorities(tmp_path: Path):
    functions = {
        "schema": "dosunit.functions.v1",
        "id": "functions:test",
        "module": "egame.exe",
        "program_kind": "mz_exe",
        "functions": [
            {
                "id": "egame.exe:hot_func",
                "names": ["hot_func"],
                "entry": {"kind": "module_relative", "segment": "seg000", "offset": "0x0010", "linear": "0x1a20"},
                "return_kind": "near",
                "sources": ["fixture"],
                "confidence": "medium",
                "size": 0x20,
                "safe_traps": [],
            }
        ],
        "diagnostics": [],
    }
    trace = {
        "Meta": {"DosboxLoadSeg": 0x192, "ImageSizeBytes": 0x100},
        "Code": {
            "0x1a23": {
                "cs": [0x192],
                "ds": [0x200],
                "es": [0x192],
                "ss": [0x192],
                "ExecCount": 5,
                "Accdat": [0x3000],
            }
        },
        "AccessSites": {
            "0x1": {
                "Csip": "0x1a23",
                "MinAddr": "0x3000",
                "MaxAddr": "0x3002",
                "Count": 4,
                "RwMask": 3,
                "SizeMask": 2,
                "ValueClasses": ["data_offset"],
                "Samples": [{"Addr": "0x3000", "Value": 1}],
            }
        },
    }
    functions_path = tmp_path / "functions.json"
    trace_path = tmp_path / "trace.json"
    functions_path.write_text(json.dumps(functions))
    trace_path.write_text(json.dumps(trace))

    imported = import_libdosbox_trace(trace_path=trace_path, functions_path=functions_path)

    assert imported["schema"] == "dosunit.libdosbox_import.v1"
    assert imported["priorities"][0]["function_id"] == "egame.exe:hot_func"
    assert imported["priorities"][0]["module_offset"] == "0x103"
    assert imported["access_ranges"][0]["rw_mask"] == 3
    assert imported["refusals"][0]["reason"] == "oracle_unavailable"


def test_dosunit_generate_entry_vectors_uses_z3_seed(tmp_path: Path):
    catalog = {
        "schema": "dosunit.functions.v1",
        "id": "functions:test",
        "module": "demo.exe",
        "program_kind": "mz_exe",
        "functions": [
            {
                "id": "demo.exe:leaf",
                "names": ["leaf"],
                "entry": {"kind": "module_relative", "segment": "seg000", "segment_para": "0x1000", "offset": "0x0020"},
                "return_kind": "near",
                "sources": ["fixture"],
                "confidence": "medium",
                "size": 4,
                "safe_traps": [],
            }
        ],
        "diagnostics": [],
    }

    generated = generate_vectors(functions_catalog=catalog, strategy="entry")

    vector = generated["vectors"][0]
    assert generated["counters"]["vectors_emitted"] == 1
    assert vector["source"]["kind"] == "z3"
    assert vector["pre"]["regs"]["sp"] == "0xff00"
    assert vector["pre"]["regs"]["flags"] == "0x0202"
    assert vector["function"]["entry"]["cs"] == "0x1000"
    assert vector["id"].startswith("vector:")


def test_dosunit_generate_edge_vectors_for_simple_cmp_ax_jcc(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x206] = b"\x3d\x34\x12\x74\x01\xc3"  # cmp ax, 0x1234; je +1; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = {
        "schema": "dosunit.functions.v1",
        "id": "functions:test",
        "module": "demo.exe",
        "program_kind": "mz_exe",
        "functions": [
            {
                "id": "demo.exe:branch",
                "names": ["branch"],
                "entry": {"kind": "module_relative", "segment": "seg000", "segment_para": "0x0000", "offset": "0x0200"},
                "return_kind": "near",
                "sources": ["fixture"],
                "confidence": "medium",
                "size": 6,
                "safe_traps": [],
            }
        ],
        "diagnostics": [],
    }

    generated = generate_vectors(functions_catalog=catalog, exe_path=exe, strategy="edge", max_vectors_per_function=2)

    assert generated["counters"]["vectors_emitted"] == 2
    assert generated["counters"]["branches_seen"] == 1
    assert generated["counters"]["edge_sources"] == {"lifter_vex": 1}
    assert generated["counters"]["lifter_blocks_lifted"] > 0
    assert {vector["pre"]["regs"]["ax"] for vector in generated["vectors"]} == {"0x1234", "0x1235"}
    assert generated["vectors"][0]["source"]["origin"] == "original_side_branch_solver"
    assert generated["vectors"][0]["source"]["coverage"]["binary"] == "oracle"
    assert generated["vectors"][0]["source"]["coverage"]["kind"] == "edge"
    assert {vector["source"]["coverage"]["discovery_source"] for vector in generated["vectors"]} == {"lifter_vex"}


def test_dosunit_generate_edge_vectors_for_cmp_reg_reg_jne(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x205] = b"\x39\xcb\x75\x01\xc3"  # cmp bx, cx; jne +1; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:reg_branch", "reg_branch", offset=0x0200, size=5)

    generated = generate_vectors(functions_catalog=catalog, exe_path=exe, strategy="edge", max_vectors_per_function=2)

    assert generated["counters"]["vectors_emitted"] == 2
    predicates = {vector["source"]["coverage"]["predicate"] for vector in generated["vectors"]}
    assert "bx != cx" in predicates
    assert "bx == cx" in predicates
    assert any(vector["pre"]["regs"]["bx"] != vector["pre"]["regs"]["cx"] for vector in generated["vectors"])
    assert any(vector["pre"]["regs"]["bx"] == vector["pre"]["regs"]["cx"] for vector in generated["vectors"])


def test_dosunit_generate_edge_vectors_for_test_reg_jz(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x205] = b"\x85\xc0\x74\x01\xc3"  # test ax, ax; jz +1; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:test_branch", "test_branch", offset=0x0200, size=5)

    generated = generate_vectors(functions_catalog=catalog, exe_path=exe, strategy="edge", max_vectors_per_function=2)

    assert generated["counters"]["vectors_emitted"] == 2
    assert {vector["pre"]["regs"]["ax"] for vector in generated["vectors"]} == {"0x0000", "0x0001"}
    assert {vector["source"]["coverage"]["label"] for vector in generated["vectors"]} == {"taken", "fallthrough"}


def test_tiny_example_or_reg_reg_jz_becomes_zero_test(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x205] = b"\x09\xc0\x74\x01\xc3"  # or ax, ax; jz +1; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:or_zero", "or_zero", offset=0x0200, size=5)

    generated = generate_vectors(functions_catalog=catalog, exe_path=exe, strategy="edge", max_vectors_per_function=2)

    assert generated["counters"]["vectors_emitted"] == 2
    assert {vector["pre"]["regs"]["ax"] for vector in generated["vectors"]} == {"0x0000", "0x0001"}
    assert {vector["source"]["coverage"]["predicate"] for vector in generated["vectors"]} == {
        "(ax & ax) == 0x0000",
        "(ax & ax) != 0x0000",
    }


def test_tiny_example_test_ax_imm_jnz_solves_bit_mask(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x207] = b"\xa9\x08\x00\x75\x01\xc3\xc3"  # test ax, 8; jnz +1; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:bit_test", "bit_test", offset=0x0200, size=7)

    generated = generate_vectors(functions_catalog=catalog, exe_path=exe, strategy="edge", max_vectors_per_function=2)

    assert generated["counters"]["vectors_emitted"] == 2
    assert {vector["pre"]["regs"]["ax"] for vector in generated["vectors"]} == {"0x0000", "0x0008"}
    assert {vector["source"]["coverage"]["label"] for vector in generated["vectors"]} == {"taken", "fallthrough"}


def test_tiny_example_cmp_al_imm_jcc_solves_partial_register(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x205] = b"\x3c\x12\x74\x01\xc3"  # cmp al, 0x12; je +1; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:byte_cmp", "byte_cmp", offset=0x0200, size=5)

    generated = generate_vectors(functions_catalog=catalog, exe_path=exe, strategy="edge", max_vectors_per_function=2)

    assert generated["counters"]["vectors_emitted"] == 2
    assert {vector["pre"]["regs"]["ax"] for vector in generated["vectors"]} == {"0x0012", "0x0013"}
    assert {vector["source"]["coverage"]["predicate"] for vector in generated["vectors"]} == {"al == 0x12", "al != 0x12"}


def test_dosunit_edge_generation_reports_byte_decoder_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    image = bytearray(0x240)
    image[0x200:0x206] = b"\x3d\x34\x12\x74\x01\xc3"  # cmp ax, 0x1234; je +1; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:fallback_branch", "fallback_branch", offset=0x0200, size=6)

    def _fail_lifter_project(_exe_path: Path):
        raise RuntimeError("forced lifter failure")

    monkeypatch.setattr(ir_edges, "_load_lifter_project", _fail_lifter_project)

    generated = generate_vectors(functions_catalog=catalog, exe_path=exe, strategy="edge", max_vectors_per_function=2)

    assert generated["counters"]["vectors_emitted"] == 2
    assert generated["counters"]["edge_sources"] == {"byte_decoder": 1}
    assert generated["counters"]["edge_fallback_diagnostics"] == 1
    assert generated["counters"]["lifter_blocks_lifted"] == 0
    assert {vector["source"]["coverage"]["discovery_source"] for vector in generated["vectors"]} == {"byte_decoder"}


def test_dosunit_generate_edge_vectors_refuses_unsupported_control_and_memory(tmp_path: Path):
    image = bytearray(0x280)
    image[0x200:0x202] = b"\xff\xe0"  # jmp ax
    image[0x240:0x247] = b"\x83\x3e\x00\x03\x00\x74\x01"  # cmp word [0x0300], 0; je +1
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = {
        "schema": "dosunit.functions.v1",
        "id": "functions:test",
        "module": "demo.exe",
        "program_kind": "mz_exe",
        "functions": [
            _edge_function("demo.exe:indirect", "indirect", offset=0x0200, size=2),
            _edge_function("demo.exe:memory", "memory", offset=0x0240, size=7),
        ],
        "diagnostics": [],
    }

    generated = generate_vectors(functions_catalog=catalog, exe_path=exe, strategy="edge", max_vectors_per_function=2)

    assert generated["counters"]["vectors_emitted"] == 0
    assert generated["counters"]["refusals_by_reason"]["unbounded_indirect_control"] == 1
    assert generated["counters"]["refusals_by_reason"]["unbounded_memory"] == 1


def test_dosunit_region_effects_capture_instruction_arguments_and_memory_effects(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x20B] = b"\x8b\x5c\x04\x01\xc3\x89\x55\xfe\x75\x01\xc3"
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:region", "region", offset=0x0200, size=0x0B)

    document = summarize_region_effects(exe_path=exe, functions_catalog=catalog, max_regions_per_function=4)

    assert document["schema"] == "dosunit.regions.v1"
    assert document["counters"]["regions_emitted"] >= 1
    assert document["counters"]["lifter_blocks_lifted"] > 0
    region = document["regions"][0]
    assert [instruction["mnemonic"] for instruction in region["instructions"]] == ["mov", "add", "mov", "jne"]
    assert region["instructions"][0]["operands"][1]["memory"] == {
        "space": "DS",
        "explicit_segment": None,
        "base": "si",
        "index": None,
        "scale": 1,
        "disp": "0x0004",
        "width": 16,
        "access": "read",
        "expr": "DS:[si + 0x0004]",
    }
    assert region["instructions"][2]["operands"][0]["memory"] == {
        "space": "DS",
        "explicit_segment": None,
        "base": "di",
        "index": None,
        "scale": 1,
        "disp": "-0x0002",
        "width": 16,
        "access": "write",
        "expr": "DS:[di - 0x0002]",
    }
    assert region["effects"]["memory_read"][0]["expr"] == "DS:[si + 0x0004]"
    assert region["effects"]["memory_written"][0]["expr"] == "DS:[di - 0x0002]"
    assert {exit_["kind"] for exit_ in region["exits"]} == {"taken", "fallthrough"}


def test_dosunit_region_compare_detects_changed_instruction_argument(tmp_path: Path):
    oracle_image = bytearray(0x240)
    candidate_image = bytearray(0x240)
    oracle_image[0x200:0x20B] = b"\x8b\x5c\x04\x01\xc3\x89\x55\xfe\x75\x01\xc3"  # [di-2]
    candidate_image[0x200:0x20B] = b"\x8b\x5c\x04\x01\xc3\x89\x56\xfe\x75\x01\xc3"  # [bp-2]
    oracle_exe = tmp_path / "oracle.exe"
    candidate_exe = tmp_path / "candidate.exe"
    oracle_exe.write_bytes(_mz_exe(bytes(oracle_image)))
    candidate_exe.write_bytes(_mz_exe(bytes(candidate_image)))
    catalog = _edge_catalog("demo.exe:region", "region", offset=0x0200, size=0x0B)
    oracle = summarize_region_effects(exe_path=oracle_exe, functions_catalog=catalog, max_regions_per_function=1)
    candidate = summarize_region_effects(exe_path=candidate_exe, functions_catalog=catalog, max_regions_per_function=1)

    comparison = compare_region_effect_documents(oracle=oracle, candidate=candidate)

    assert comparison["summary"]["failed"] == 1
    mismatches = comparison["results"][0]["mismatches"]
    assert any(item["kind"] == "instruction_operands_changed" for item in mismatches)
    assert any(item["kind"] == "instruction_effects_changed" for item in mismatches)
    operand_mismatch = next(item for item in mismatches if item["kind"] == "instruction_operands_changed")
    assert operand_mismatch["oracle"][0]["base"] == "di"
    assert operand_mismatch["candidate"][0]["base"] == "bp"
    assert operand_mismatch["candidate"][0]["space"] == "SS"
    report = render_failure_report(comparison)
    assert "instruction_operands_changed" in report
    assert "Oracle instruction" in report
    assert "0x0205" in report
    assert "mov word ptr [di - 2], dx" in report
    assert "mov word ptr [bp - 2], dx" in report
    assert '"base":"di"' in report
    assert '"base":"bp"' in report
    assert '"space":"SS"' in report


def test_dosunit_region_compare_normalizes_signed_branch_targets(tmp_path: Path):
    oracle_image = bytearray(0x240)
    candidate_image = bytearray(0x240)
    oracle_image[0x200:0x202] = b"\x7d\x01"  # jge target
    candidate_image[0x200:0x202] = b"\x7d\x03"  # same branch, different layout target
    oracle_exe = tmp_path / "oracle.exe"
    candidate_exe = tmp_path / "candidate.exe"
    oracle_exe.write_bytes(_mz_exe(bytes(oracle_image)))
    candidate_exe.write_bytes(_mz_exe(bytes(candidate_image)))
    catalog = _edge_catalog("demo.exe:branch", "branch", offset=0x0200, size=2)
    oracle = summarize_region_effects(exe_path=oracle_exe, functions_catalog=catalog, max_regions_per_function=1)
    candidate = summarize_region_effects(exe_path=candidate_exe, functions_catalog=catalog, max_regions_per_function=1)

    comparison = compare_region_effect_documents(oracle=oracle, candidate=candidate)

    assert comparison["summary"]["passed"] == 1
    assert comparison["results"][0]["mismatches"] == []


def test_dosunit_complexity_marks_simple_leaf_as_whole_function_part(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x206] = b"\x89\xd8\x83\xc0\x01\xc3"  # mov ax, bx; add ax, 1; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:leaf_math", "leaf_math", offset=0x0200, size=6)

    document = analyze_function_complexity(exe_path=exe, functions_catalog=catalog)

    function = document["functions"][0]
    assert document["schema"] == "dosunit.complexity.v1"
    assert document["counters"]["simple_whole_functions"] == 1
    assert function["classification"] == "simple_whole_function"
    assert function["metrics"]["condition_count"] == 0
    assert function["metrics"]["call_count"] == 0
    assert function["comparison_parts"][0]["kind"] == "whole_function"
    assert function["comparison_parts"][0]["instruction_count"] == 3


def test_dosunit_complexity_blocks_conditional_function_from_whole_function_part(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x207] = b"\x3d\x01\x00\x75\x01\xc3\xc3"  # cmp ax, 1; jne +1; ret; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:branchy", "branchy", offset=0x0200, size=7)

    document = analyze_function_complexity(exe_path=exe, functions_catalog=catalog)

    function = document["functions"][0]
    assert function["classification"] == "complex"
    assert function["metrics"]["condition_count"] == 1
    assert any(blocker["kind"] == "conditions" for blocker in function["blockers"])
    assert function["comparison_parts"] == []
    assert function["risk_points"][0]["kinds"] == ["condition"]
    assert "jne" in function["risk_points"][0]["disassembly"]


def test_dosunit_complexity_counts_symbolic_segmented_memory(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x204] = b"\x8b\x44\x04\xc3"  # mov ax, [si+4]; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:load_indexed", "load_indexed", offset=0x0200, size=4)

    document = analyze_function_complexity(exe_path=exe, functions_catalog=catalog)

    function = document["functions"][0]
    assert function["classification"] == "complex"
    assert function["metrics"]["explicit_symbolic_memory_count"] == 1
    assert any(blocker["kind"] == "symbolic_memory" for blocker in function["blockers"])
    assert any("symbolic_memory" in point["kinds"] for point in function["risk_points"])


def test_dosunit_cli_complexity_writes_report(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x207] = b"\x3d\x01\x00\x75\x01\xc3\xc3"  # cmp ax, 1; jne +1; ret; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:branchy", "branchy", offset=0x0200, size=7)
    functions_path = tmp_path / "functions.json"
    out_path = tmp_path / "complexity.json"
    report_path = tmp_path / "complexity.md"
    functions_path.write_text(json.dumps(catalog))

    rc = dosunit_main(["complexity", "--exe", str(exe), "--functions", str(functions_path), "--out", str(out_path)])

    assert rc == 0
    document = json.loads(out_path.read_text())
    assert document["schema"] == "dosunit.complexity.v1"
    assert document["counters"]["complex_functions"] == 1
    assert dosunit_main(["report-failures", "--results", str(out_path), "--out", str(report_path)]) == 0
    report = report_path.read_text()
    assert "Complex Functions" in report
    assert "branchy" in report
    assert "conditions" in report
    assert "jne" in report
    assert "0x0203" in report


def test_dosunit_straightline_ssa_drops_flag_noise_and_return_ip_load(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x206] = b"\x89\xd8\x83\xc0\x01\xc3"  # mov ax, bx; add ax, 1; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:leaf_math", "leaf_math", offset=0x0200, size=6)

    document = lower_straightline_ssa_document(exe_path=exe, functions_catalog=catalog, output_regs=("ax", "bx"))

    assert document["schema"] == "dosunit.ssa.v1"
    assert document["counters"]["functions_lowered"] == 1
    function = document["functions"][0]
    assert set(function["outputs"]) == {"ax", "bx"}
    assert function["outputs"]["bx"] == {"op": "input", "name": "bx", "width": 16}
    serialized = json.dumps(function["assignments"], sort_keys=True)
    assert "add" in serialized
    assert "flags" not in serialized
    assert "load" not in serialized.lower()


def test_dosunit_compare_ssa_proves_equivalent_and_finds_counterexample(tmp_path: Path):
    original_image = bytearray(0x240)
    equivalent_image = bytearray(0x240)
    changed_image = bytearray(0x240)
    original_image[0x200:0x206] = b"\x89\xd8\x83\xc0\x01\xc3"  # mov ax, bx; add ax, 1; ret
    equivalent_image[0x200:0x204] = b"\x89\xd8\x40\xc3"  # mov ax, bx; inc ax; ret
    changed_image[0x200:0x206] = b"\x89\xd8\x83\xc0\x02\xc3"  # mov ax, bx; add ax, 2; ret
    original = tmp_path / "original.exe"
    equivalent = tmp_path / "equivalent.exe"
    changed = tmp_path / "changed.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    equivalent.write_bytes(_mz_exe(bytes(equivalent_image)))
    changed.write_bytes(_mz_exe(bytes(changed_image)))
    original_catalog = _edge_catalog("demo.exe:leaf_math", "leaf_math", offset=0x0200, size=6)
    equivalent_catalog = _edge_catalog("demo.exe:leaf_math", "leaf_math", offset=0x0200, size=4)

    oracle = lower_straightline_ssa_document(exe_path=original, functions_catalog=original_catalog, output_regs=("ax", "bx"))
    equivalent_ssa = lower_straightline_ssa_document(exe_path=equivalent, functions_catalog=equivalent_catalog, output_regs=("ax", "bx"))
    changed_ssa = lower_straightline_ssa_document(exe_path=changed, functions_catalog=original_catalog, output_regs=("ax", "bx"))

    passed = compare_ssa_documents(oracle=oracle, candidate=equivalent_ssa)
    failed = compare_ssa_documents(oracle=oracle, candidate=changed_ssa)

    assert passed["summary"]["passed"] == 1
    assert failed["summary"]["failed"] == 1
    mismatch = failed["results"][0]["mismatches"][0]
    assert mismatch["kind"] == "output_expr_changed"
    assert mismatch["reg"] == "ax"
    assert mismatch["counterexample"]["bx"] == "0x0000"


def test_dosunit_compare_ssa_uses_mapping_and_skips_unmapped(tmp_path: Path):
    original_image = bytearray(0x280)
    candidate_image = bytearray(0x280)
    original_image[0x200:0x206] = b"\x89\xd8\x83\xc0\x01\xc3"  # mov ax, bx; add ax, 1; ret
    original_image[0x210:0x214] = b"\xb8\x34\x12\xc3"  # mov ax, 0x1234; ret
    candidate_image[0x220:0x224] = b"\x89\xd8\x40\xc3"  # mov ax, bx; inc ax; ret
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    original_catalog = {
        "schema": "dosunit.functions.v1",
        "id": "functions:original",
        "module": "demo.exe",
        "program_kind": "mz_exe",
        "functions": [
            _edge_function("demo.exe:orig_leaf", "orig_leaf", offset=0x0200, size=6),
            _edge_function("demo.exe:unmapped_leaf", "unmapped_leaf", offset=0x0210, size=4),
        ],
        "diagnostics": [],
    }
    candidate_catalog = {
        "schema": "dosunit.functions.v1",
        "id": "functions:candidate",
        "module": "demo.exe",
        "program_kind": "mz_exe",
        "functions": [_edge_function("demo.exe:rebuilt_leaf", "rebuilt_leaf", offset=0x0220, size=4)],
        "diagnostics": [],
    }
    mapping = {
        "schema": "dosunit.mapping.v1",
        "id": "mapping:test",
        "functions": [
            {
                "oracle_id": "demo.exe:orig_leaf",
                "oracle_name": "orig_leaf",
                "candidate_id": "demo.exe:rebuilt_leaf",
                "candidate_name": "rebuilt_leaf",
                "candidate_entry": {"cs": "0x0000", "ip": "0x0220", "kind": "near"},
                "sources": ["fixture"],
            }
        ],
    }

    oracle = lower_straightline_ssa_document(exe_path=original, functions_catalog=original_catalog, output_regs=("ax", "bx"))
    candidate_ssa = lower_straightline_ssa_document(exe_path=candidate, functions_catalog=candidate_catalog, output_regs=("ax", "bx"))
    compared = compare_ssa_documents(oracle=oracle, candidate=candidate_ssa, mapping_document=mapping, include_unmapped=False)

    assert compared["summary"]["total"] == 1
    assert compared["summary"]["passed"] == 1
    assert compared["summary"]["skipped_unmapped"] == 1
    assert compared["results"][0]["candidate_function"] == candidate_ssa["functions"][0]["id"]
    report = render_failure_report(compared)
    assert "Skipped unmapped: 1" in report


def test_dosunit_straightline_ssa_refuses_memory_load_in_output_slice(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x204] = b"\x8b\x44\x04\xc3"  # mov ax, [si+4]; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:load_indexed", "load_indexed", offset=0x0200, size=4)

    document = lower_straightline_ssa_document(exe_path=exe, functions_catalog=catalog, output_regs=("ax",))

    assert document["counters"]["functions_refused"] == 1
    assert document["refusals"][0]["reason"] == "unbounded_memory"


def test_dosunit_straightline_ssa_lowers_vex_normalized_partial_register_write(tmp_path: Path):
    image = bytearray(0x240)
    image[0x200:0x203] = b"\xb0\x12\xc3"  # mov al, 0x12; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = _edge_catalog("demo.exe:partial_reg", "partial_reg", offset=0x0200, size=3)

    document = lower_straightline_ssa_document(exe_path=exe, functions_catalog=catalog, output_regs=("ax",))

    assert document["counters"]["functions_lowered"] == 1
    function = document["functions"][0]
    assert function["inputs"] == [{"name": "ax", "width": 16}]
    serialized = json.dumps(function["assignments"], sort_keys=True)
    assert "0xff00" in serialized
    assert "0x12" in serialized
    assert '"and"' in serialized
    assert '"or"' in serialized


def test_dosunit_cli_ssa_and_compare_ssa(tmp_path: Path):
    original_image = bytearray(0x240)
    candidate_image = bytearray(0x240)
    original_image[0x200:0x204] = b"\xb8\x34\x12\xc3"  # mov ax, 0x1234; ret
    candidate_image[0x200:0x204] = b"\xb8\x35\x12\xc3"  # mov ax, 0x1235; ret
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    catalog = _edge_catalog("demo.exe:imm_leaf", "imm_leaf", offset=0x0200, size=4)
    functions_path = tmp_path / "functions.json"
    oracle_ssa_path = tmp_path / "oracle.ssa.json"
    candidate_ssa_path = tmp_path / "candidate.ssa.json"
    results_path = tmp_path / "ssa.results.json"
    report_path = tmp_path / "ssa.report.md"
    functions_path.write_text(json.dumps(catalog))

    assert dosunit_main(["ssa", "--exe", str(original), "--functions", str(functions_path), "--output-reg", "ax", "--out", str(oracle_ssa_path)]) == 0
    assert dosunit_main(["ssa", "--exe", str(candidate), "--functions", str(functions_path), "--output-reg", "ax", "--out", str(candidate_ssa_path)]) == 0
    rc = dosunit_main(["compare-ssa", "--oracle-ssa", str(oracle_ssa_path), "--candidate-ssa", str(candidate_ssa_path), "--out", str(results_path)])

    assert rc == 1
    result = json.loads(results_path.read_text())
    assert result["schema"] == "dosunit.ssa_compare.v1"
    assert result["summary"]["failed"] == 1
    assert dosunit_main(["report-failures", "--results", str(results_path), "--out", str(report_path)]) == 0
    report = report_path.read_text()
    assert "Failed Or Refused SSA Functions" in report
    assert "Register: `ax`" in report
    assert "Counterexample" in report


def test_dosunit_cli_regions_and_compare_regions(tmp_path: Path):
    oracle_image = bytearray(0x240)
    candidate_image = bytearray(0x240)
    oracle_image[0x200:0x20B] = b"\x8b\x5c\x04\x01\xc3\x89\x55\xfe\x75\x01\xc3"
    candidate_image[0x200:0x20B] = b"\x8b\x5c\x04\x01\xc3\x89\x56\xfe\x75\x01\xc3"
    oracle_exe = tmp_path / "oracle.exe"
    candidate_exe = tmp_path / "candidate.exe"
    oracle_exe.write_bytes(_mz_exe(bytes(oracle_image)))
    candidate_exe.write_bytes(_mz_exe(bytes(candidate_image)))
    catalog = _edge_catalog("demo.exe:region", "region", offset=0x0200, size=0x0B)
    functions_path = tmp_path / "functions.json"
    oracle_regions_path = tmp_path / "oracle.regions.json"
    candidate_regions_path = tmp_path / "candidate.regions.json"
    comparison_path = tmp_path / "region.compare.json"
    report_path = tmp_path / "region.report.md"
    functions_path.write_text(json.dumps(catalog))

    assert dosunit_main(["regions", "--exe", str(oracle_exe), "--functions", str(functions_path), "--out", str(oracle_regions_path)]) == 0
    assert dosunit_main(["regions", "--exe", str(candidate_exe), "--functions", str(functions_path), "--out", str(candidate_regions_path)]) == 0
    rc = dosunit_main(
        [
            "compare-regions",
            "--oracle-regions",
            str(oracle_regions_path),
            "--candidate-regions",
            str(candidate_regions_path),
            "--out",
            str(comparison_path),
        ]
    )

    assert rc == 1
    comparison = json.loads(comparison_path.read_text())
    assert comparison["summary"]["failed"] == 1
    assert dosunit_main(["report-failures", "--results", str(comparison_path), "--out", str(report_path)]) == 0
    report = report_path.read_text()
    assert "# DOS Unit Failure Report" in report
    assert "instruction_operands_changed" in report
    assert "Oracle region entry" in report
    assert "Candidate instruction" in report
    assert "candidate" in report


def _edge_catalog(function_id: str, name: str, *, offset: int, size: int) -> dict[str, object]:
    return {
        "schema": "dosunit.functions.v1",
        "id": "functions:test",
        "module": "demo.exe",
        "program_kind": "mz_exe",
        "functions": [_edge_function(function_id, name, offset=offset, size=size)],
        "diagnostics": [],
    }


def _edge_function(function_id: str, name: str, *, offset: int, size: int) -> dict[str, object]:
    return {
        "id": function_id,
        "names": [name],
        "entry": {"kind": "module_relative", "segment": "seg000", "segment_para": "0x0000", "offset": f"0x{offset:04x}"},
        "return_kind": "near",
        "sources": ["fixture"],
        "confidence": "medium",
        "size": size,
        "safe_traps": [],
    }


def test_candidate_mapping_resolves_by_function_name():
    vector = _leaf_vector()
    mapping = {
        "schema": "dosunit.mapping.v1",
        "oracle_module": "demo.exe",
        "candidate_module": "candidate.exe",
        "functions": [
            {
                "oracle_name": "leaf",
                "candidate_name": "leaf_rebuilt",
                "candidate_entry": {"cs": "0x0001", "ip": "0x0220", "kind": "near"},
            }
        ],
    }

    mapped = apply_candidate_mapping(vector, mapping_document=mapping)

    assert mapped["module"] == "candidate.exe"
    assert mapped["function"]["name"] == "leaf_rebuilt"
    assert mapped["function"]["entry"] == {"cs": "0x0001", "ip": "0x0220", "kind": "near"}


def test_candidate_mapping_missing_is_typed_refusal():
    vector = _leaf_vector()

    with pytest.raises(MappingResolutionError) as exc:
        apply_candidate_mapping(vector, mapping_document={"schema": "dosunit.mapping.v1", "functions": []})

    assert exc.value.reason == "mapping_missing"


def test_make_mapping_document_matches_catalogs_by_name():
    oracle = {
        "schema": "dosunit.functions.v1",
        "module": "orig.exe",
        "functions": [
            {
                "id": "orig.exe:leaf",
                "names": ["leaf"],
                "entry": {"segment_para": "0x0000", "offset": "0x0200"},
                "return_kind": "near",
            }
        ],
    }
    candidate = {
        "schema": "dosunit.functions.v1",
        "module": "rebuilt.exe",
        "functions": [
            {
                "id": "rebuilt.exe:leaf",
                "names": ["leaf"],
                "entry": {"segment_para": "0x0001", "offset": "0x0300"},
                "return_kind": "near",
            }
        ],
    }

    mapping = make_mapping_document(oracle_catalog=oracle, candidate_catalog=candidate)

    assert mapping["summary"]["mapped"] == 1
    assert mapping["functions"][0]["oracle_id"] == "orig.exe:leaf"
    assert mapping["functions"][0]["candidate_entry"]["cs"] == "0x0001"
    assert mapping["functions"][0]["candidate_entry"]["ip"] == "0x0300"


def test_select_vectors_filters_by_function_name_and_limit():
    vectors = {"schema": "dosunit.vectors.v1", "vectors": [_leaf_vector(), {**_leaf_vector(), "function": {"name": "other", "entry": {"cs": "0x0000", "ip": "0x0210", "kind": "near"}}}]}

    selected = select_vectors(vectors, names=["other"], limit=1)

    assert len(selected["vectors"]) == 1
    assert selected["vectors"][0]["function"]["name"] == "other"


def test_dosunit_record_oracle_and_compare_fixture_passes_and_fails():
    observed = {
        "status": "trapped",
        "regs": {"ax": "0x0001"},
        "sregs": {},
        "flags": {"value": "0x0202", "mask": "0xffff"},
        "memory": [],
        "return": {"kind": "near"},
        "calls": [],
    }
    vector = {
        "schema": "dosunit.vector.v1",
        "module": "demo.exe",
        "function": {"name": "leaf", "entry": {"cs": "auto", "ip": "0x0100", "kind": "near"}},
        "source": {"kind": "manual", "origin": "manual_fixture", "assumptions": []},
        "pre": {"regs": {"sp": "0xff00", "flags": "0x0202"}, "sregs": {"cs": "auto"}, "memory": []},
        "observe": {"regs": ["ax"], "sregs": [], "flags_mask": "0xffff", "memory": [], "calls": True, "return": True},
        "expected": None,
        "backend_fixture": {
            "oracle": observed,
            "candidate": {**observed, "regs": {"ax": "0x0002"}},
        },
    }

    recorded = record_oracle({"schema": "dosunit.vectors.v1", "vectors": [vector]}, backend="fixture")
    assert recorded["vectors"][0]["expected"]["regs"]["ax"] == "0x0001"

    failed = compare_vectors(recorded, backend="fixture")
    assert failed["results"][0]["status"] == "failed"
    assert failed["results"][0]["verdict"]["changed_fields"] == ["regs"]

    ignored = compare_vectors(recorded, backend="fixture", ignore_fields={"regs"})
    assert ignored["results"][0]["status"] == "passed"
    assert ignored["ignore_fields"] == ["regs"]

    recorded["vectors"][0]["backend_fixture"]["candidate"] = observed
    passed = compare_vectors(recorded, backend="fixture")
    assert passed["results"][0]["status"] == "passed"


def test_dosunit_cli_discover_writes_catalog(tmp_path: Path):
    map_path = _write(
        tmp_path / "demo.map",
        "\n".join(
            [
                "seg000 CODE 0000",
                "leaf: seg000 NEAR 0010-0015 R0010-0015 complete",
            ]
        ),
    )
    out_path = tmp_path / "catalog.json"

    rc = dosunit_main(["discover", "--map", str(map_path), "--module", "demo.exe", "--out", str(out_path)])

    assert rc == 0
    catalog = json.loads(out_path.read_text())
    assert catalog["functions"][0]["id"] == "demo.exe:leaf"


def test_dosunit_cli_make_mapping_and_select_vectors(tmp_path: Path):
    oracle = {
        "schema": "dosunit.functions.v1",
        "module": "orig.exe",
        "functions": [{"id": "orig.exe:leaf", "names": ["leaf"], "entry": {"segment_para": "0x0000", "offset": "0x0200"}, "return_kind": "near"}],
    }
    candidate = {
        "schema": "dosunit.functions.v1",
        "module": "rebuilt.exe",
        "functions": [{"id": "rebuilt.exe:leaf", "names": ["leaf"], "entry": {"segment_para": "0x0001", "offset": "0x0300"}, "return_kind": "near"}],
    }
    vectors = {"schema": "dosunit.vectors.v1", "vectors": [_leaf_vector()]}
    oracle_path = tmp_path / "oracle.json"
    candidate_path = tmp_path / "candidate.json"
    vectors_path = tmp_path / "vectors.json"
    mapping_path = tmp_path / "mapping.json"
    selected_path = tmp_path / "selected.json"
    oracle_path.write_text(json.dumps(oracle))
    candidate_path.write_text(json.dumps(candidate))
    vectors_path.write_text(json.dumps(vectors))

    assert dosunit_main(["make-mapping", "--oracle-functions", str(oracle_path), "--candidate-functions", str(candidate_path), "--out", str(mapping_path)]) == 0
    assert dosunit_main(["select-vectors", "--vectors", str(vectors_path), "--function", "leaf", "--out", str(selected_path)]) == 0

    assert json.loads(mapping_path.read_text())["summary"]["mapped"] == 1
    assert len(json.loads(selected_path.read_text())["vectors"]) == 1


def test_dosunit_cli_compare_returns_nonzero_for_refused_vector(tmp_path: Path):
    vectors_path = tmp_path / "vectors.json"
    results_path = tmp_path / "results.json"
    vectors_path.write_text(json.dumps({"schema": "dosunit.vectors.v1", "vectors": [_leaf_vector()]}))

    rc = dosunit_main(["compare", "--backend", "fixture", "--vectors", str(vectors_path), "--out", str(results_path)])

    assert rc == 1
    result = json.loads(results_path.read_text())["results"][0]
    assert result["status"] == "refused"
    assert result["verdict"]["kind"] == "oracle_unavailable"


def test_compare_loaded_data_images_applies_relocations_zero_tail_and_normalizes_code_pointer(tmp_path: Path):
    data_para = 0x0030
    pointer_offset = 0x0010
    reloc_offset = 0x0020
    original_image = bytearray(0x340)
    candidate_image = bytearray(0x340)
    original_image[data_para * 16 : data_para * 16 + 0x40] = bytes(range(0x40))
    candidate_image[data_para * 16 : data_para * 16 + 0x40] = bytes(range(0x40))
    original_image[data_para * 16 + pointer_offset : data_para * 16 + pointer_offset + 2] = (0x0123).to_bytes(2, "little")
    candidate_image[data_para * 16 + pointer_offset : data_para * 16 + pointer_offset + 2] = (0x0140).to_bytes(2, "little")
    original_image[data_para * 16 + reloc_offset : data_para * 16 + reloc_offset + 2] = (0x0000).to_bytes(2, "little")
    candidate_image[data_para * 16 + reloc_offset : data_para * 16 + reloc_offset + 2] = (0x0001).to_bytes(2, "little")
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    relocs = ((reloc_offset, data_para),)
    original.write_bytes(_mz_exe(bytes(original_image), relocs=relocs, minalloc=0x0010))
    candidate.write_bytes(_mz_exe(bytes(candidate_image), relocs=relocs, minalloc=0x0010))
    oracle_catalog = _data_catalog(data_para=data_para, exit_offset=0x0123)
    candidate_catalog = _data_catalog(data_para=data_para, exit_offset=0x0140)

    failed = compare_loaded_data_images(
        oracle_exe=original,
        candidate_exe=candidate,
        oracle_catalog=oracle_catalog,
        candidate_catalog=candidate_catalog,
        ranges=["DATA:0x0000..0x0080"],
        oracle_load_base_para=0x0001,
        candidate_load_base_para=0x0000,
    )
    passed = compare_loaded_data_images(
        oracle_exe=original,
        candidate_exe=candidate,
        oracle_catalog=oracle_catalog,
        candidate_catalog=candidate_catalog,
        ranges=["DATA:0x0000..0x0080"],
        code_pointer_normalizations=["DATA:0x0010:__exit"],
        oracle_load_base_para=0x0001,
        candidate_load_base_para=0x0000,
    )

    assert failed["status"] == "failed"
    assert failed["summary"]["literal_mismatches"] > 0
    failed_report = render_failure_report(failed)
    assert "Failed Data Ranges" in failed_report
    assert "Offset" in failed_report
    assert "oracle" in failed_report
    assert "candidate" in failed_report
    assert passed["status"] == "passed"
    assert passed["summary"]["literal_mismatches"] == 0
    assert passed["normalizations"][0]["oracle_value"] == "0x0123"
    assert passed["normalizations"][0]["candidate_value"] == "0x0140"
    assert passed["ranges"][0]["normalized_bytes"] == 2


def test_dosunit_cli_compare_data_supports_segment_mapping_and_code_pointer_normalization(tmp_path: Path):
    data_para = 0x0030
    original_image = bytearray(0x330)
    candidate_image = bytearray(0x330)
    original_image[data_para * 16 : data_para * 16 + 0x20] = b"A" * 0x20
    candidate_image[data_para * 16 : data_para * 16 + 0x20] = b"A" * 0x20
    original_image[data_para * 16 + 0x0010 : data_para * 16 + 0x0012] = (0x0200).to_bytes(2, "little")
    candidate_image[data_para * 16 + 0x0010 : data_para * 16 + 0x0012] = (0x0210).to_bytes(2, "little")
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image), minalloc=0x0010))
    candidate.write_bytes(_mz_exe(bytes(candidate_image), minalloc=0x0010))
    oracle_catalog = _data_catalog(data_para=data_para, exit_offset=0x0200, data_segment_name="Data1")
    candidate_catalog = _data_catalog(data_para=data_para, exit_offset=0x0210, data_segment_name="DGROUP")
    oracle_path = tmp_path / "oracle.functions.json"
    candidate_path = tmp_path / "candidate.functions.json"
    out_path = tmp_path / "data.results.json"
    oracle_path.write_text(json.dumps(oracle_catalog))
    candidate_path.write_text(json.dumps(candidate_catalog))

    rc = dosunit_main(
        [
            "compare-data",
            "--oracle-exe",
            str(original),
            "--candidate-exe",
            str(candidate),
            "--oracle-functions",
            str(oracle_path),
            "--candidate-functions",
            str(candidate_path),
            "--range",
            "Data1=DGROUP:0x0000..0x0040",
            "--normalize-code-pointer",
            "Data1:0x0010=DGROUP:0x0010:__exit",
            "--out",
            str(out_path),
        ]
    )

    assert rc == 0
    result = json.loads(out_path.read_text())
    assert result["status"] == "passed"
    assert result["ranges"][0]["oracle_segment"] == "Data1"
    assert result["ranges"][0]["candidate_segment"] == "DGROUP"


def _data_catalog(*, data_para: int, exit_offset: int, data_segment_name: str = "DATA") -> dict[str, object]:
    return {
        "schema": "dosunit.functions.v1",
        "module": "demo.exe",
        "segments": [{"name": data_segment_name, "class": "DATA", "paragraph": f"0x{data_para:04x}"}],
        "functions": [
            {
                "id": "demo.exe:__exit",
                "names": ["__exit"],
                "entry": {"segment_para": "0x0000", "offset": f"0x{exit_offset:04x}"},
                "return_kind": "near",
            }
        ],
    }


def test_root_dosunit_wrapper_exposes_cli_help():
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, str(root / "dosunit.py"), "--help"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    assert result.returncode == 0
    assert "record-oracle" in result.stdout


def test_kvikdos_harness_builds_for_near_mz_function(tmp_path: Path):
    image = bytearray(0x300)
    image[0x200:0x204] = b"\xb8\x34\x12\xc3"  # mov ax, 0x1234; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))

    harness = build_harness(_leaf_vector(), exe_path=exe)

    assert harness.exe_bytes[:2] == b"MZ"
    assert harness.observation_linear > 0


@pytest.mark.skipif(
    not os.access("/dev/kvm", os.R_OK | os.W_OK) or not Path("/home/xor/kvikdos/kvikdos.c").exists(),
    reason="real libkvikdos smoke requires writable /dev/kvm and /home/xor/kvikdos/kvikdos.c",
)
def test_libkvikdos_backend_records_real_near_function_oracle(tmp_path: Path):
    image = bytearray(0x300)
    image[0x200:0x204] = b"\xb8\x34\x12\xc3"  # mov ax, 0x1234; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))

    recorded = record_oracle(
        {"schema": "dosunit.vectors.v1", "vectors": [_leaf_vector()]},
        backend="libkvikdos",
        exe_path=exe,
    )

    result = recorded["results"][0]
    assert result["status"] == "passed"
    assert recorded["vectors"][0]["expected"]["status"] == "returned"
    assert recorded["vectors"][0]["expected"]["regs"]["ax"] == "0x1234"
    assert recorded["vectors"][0]["expected"]["regs"]["sp"] == "0xff02"


@pytest.mark.skipif(
    not os.access("/dev/kvm", os.R_OK | os.W_OK) or not Path("/home/xor/kvikdos/kvikdos.c").exists(),
    reason="real libkvikdos smoke requires writable /dev/kvm and /home/xor/kvikdos/kvikdos.c",
)
def test_libkvikdos_session_snapshot_restore_roundtrip(tmp_path: Path):
    image = bytearray(0x300)
    image[0x200:0x204] = b"\xb8\x34\x12\xc3"  # mov ax, 0x1234; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    harness = build_harness(_leaf_vector(), exe_path=exe)

    with KvikdosSession() as session:
        session.run_harness(harness.exe_bytes)
        before = session.read_memory(harness.observation_linear, 4)
        snapshot = session.snapshot_create()
        try:
            session.write_memory(harness.observation_linear, b"BAD!")
            assert session.read_memory(harness.observation_linear, 4) == b"BAD!"
            session.snapshot_restore(snapshot)
            assert session.read_memory(harness.observation_linear, 4) == before
        finally:
            session.snapshot_destroy(snapshot)


@pytest.mark.skipif(
    not os.access("/dev/kvm", os.R_OK | os.W_OK) or not Path("/home/xor/kvikdos/kvikdos.c").exists(),
    reason="real libkvikdos smoke requires writable /dev/kvm and /home/xor/kvikdos/kvikdos.c",
)
def test_libkvikdos_backend_observes_segmented_ds_memory(tmp_path: Path):
    image = bytearray(0x500)
    image[0x200:0x204] = b"\xa3\x00\x03\xc3"  # mov [0x0300], ax; ret
    exe = tmp_path / "demo.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    vector = _leaf_vector()
    vector["pre"]["regs"]["ax"] = "0x1234"  # type: ignore[index]
    vector["observe"]["memory"] = [{"space": "DS", "offset": "0x0300", "size": "0x0002"}]  # type: ignore[index]

    recorded = record_oracle(
        {"schema": "dosunit.vectors.v1", "vectors": [vector]},
        backend="libkvikdos",
        exe_path=exe,
    )

    assert recorded["results"][0]["status"] == "passed"
    assert recorded["vectors"][0]["expected"]["memory"][0]["bytes"] == "3412"


@pytest.mark.skipif(
    not os.access("/dev/kvm", os.R_OK | os.W_OK) or not Path("/home/xor/kvikdos/kvikdos.c").exists(),
    reason="real libkvikdos smoke requires writable /dev/kvm and /home/xor/kvikdos/kvikdos.c",
)
def test_libkvikdos_compare_uses_candidate_mapping(tmp_path: Path):
    original_image = bytearray(0x300)
    original_image[0x200:0x204] = b"\xb8\x11\x11\xc3"  # mov ax, 0x1111; ret
    candidate_image = bytearray(0x330)
    candidate_image[0x200:0x204] = b"\xb8\x22\x22\xc3"  # wrong same-layout function
    candidate_image[0x210:0x214] = b"\xb8\x11\x11\xc3"  # mapped rebuilt function
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    vector = _leaf_vector()
    oracle = record_oracle(
        {"schema": "dosunit.vectors.v1", "vectors": [vector]},
        backend="libkvikdos",
        exe_path=original,
    )
    mapping = {
        "schema": "dosunit.mapping.v1",
        "oracle_module": "demo.exe",
        "candidate_module": "candidate.exe",
        "functions": [{"oracle_name": "leaf", "candidate_entry": {"cs": "0x0000", "ip": "0x0210", "kind": "near"}}],
    }

    result = compare_vectors(oracle, backend="libkvikdos", candidate_path=candidate, mapping_document=mapping)

    assert result["results"][0]["status"] == "passed"


@pytest.mark.skipif(
    not os.access("/dev/kvm", os.R_OK | os.W_OK) or not Path("/home/xor/kvikdos/kvikdos.c").exists(),
    reason="real libkvikdos smoke requires writable /dev/kvm and /home/xor/kvikdos/kvikdos.c",
)
def test_branch_generated_vector_replays_on_rebuilt_function_boundary(tmp_path: Path):
    branch_code = b"\x3d\x01\x00\x74\x04\xb8\x22\x22\xc3\xb8\x11\x11\xc3"  # cmp ax, 1; je taken; mov ax, 0x2222; ret; taken: mov ax, 0x1111; ret
    original_image = bytearray(0x320)
    original_image[0x200 : 0x200 + len(branch_code)] = branch_code
    candidate_image = bytearray(0x280)
    candidate_image[0x200:0x204] = b"\xb8\x99\x99\xc3"  # wrong same-layout address
    candidate_image[0x250 : 0x250 + len(branch_code)] = branch_code
    original = tmp_path / "original.exe"
    candidate = tmp_path / "candidate.exe"
    original.write_bytes(_mz_exe(bytes(original_image)))
    candidate.write_bytes(_mz_exe(bytes(candidate_image)))
    catalog = _edge_catalog("demo.exe:branchy", "branchy", offset=0x0200, size=len(branch_code))

    generated = generate_vectors(functions_catalog=catalog, exe_path=original, strategy="edge", max_vectors_per_function=1)
    oracle = record_oracle(generated, backend="libkvikdos", exe_path=original)
    mapping = {
        "schema": "dosunit.mapping.v1",
        "oracle_module": "demo.exe",
        "candidate_module": "candidate.exe",
        "functions": [{"oracle_name": "branchy", "candidate_entry": {"cs": "0x0000", "ip": "0x0250", "kind": "near"}}],
    }
    result = compare_vectors(oracle, backend="libkvikdos", candidate_path=candidate, mapping_document=mapping)

    assert generated["vectors"][0]["source"]["coverage"]["binary"] == "oracle"
    assert generated["vectors"][0]["source"]["coverage"]["label"] == "taken"
    assert oracle["vectors"][0]["expected"]["regs"]["ax"] == "0x1111"
    assert result["results"][0]["status"] == "passed"
