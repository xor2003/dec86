from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from tools.dosunit.complexity import analyze_function_complexity
from tools.dosunit.data_compare import compare_loaded_data_images
from tools.dosunit.discovery import discover_functions
from tools.dosunit.failure_report import render_failure_report
from tools.dosunit.generate import generate_vectors
from tools.dosunit.libdosbox_import import import_libdosbox_trace
from tools.dosunit.mapping import make_mapping_document
from tools.dosunit.model import DosUnitError, load_json, write_json
from tools.dosunit.region_effects import compare_region_effect_documents, summarize_region_effects
from tools.dosunit.runner import compare_vectors, record_oracle, summarize_results
from tools.dosunit.straightline_ssa import DEFAULT_OUTPUT_REGS, compare_ssa_documents, lower_straightline_ssa_document
from tools.dosunit.vectors import select_vectors


def _path_or_none(value: str | None) -> Path | None:
    return None if value is None else Path(value)


def cmd_discover(args: argparse.Namespace) -> int:
    catalog = discover_functions(
        exe_path=_path_or_none(args.exe),
        map_path=_path_or_none(args.map),
        ida_listing_path=_path_or_none(args.ida_listing),
        module=args.module,
    )
    write_json(Path(args.out), catalog)
    return 0


def cmd_gen_vectors(args: argparse.Namespace) -> int:
    catalog = load_json(Path(args.functions))
    document = generate_vectors(
        functions_catalog=catalog,
        exe_path=_path_or_none(args.exe),
        strategy=args.strategy,
        max_vectors_per_function=args.max_vectors_per_function,
        max_branches=args.max_branches,
        max_blocks=args.max_blocks,
        max_loop_unroll=args.max_loop_unroll,
        solver_timeout_ms=args.solver_timeout_ms,
    )
    write_json(Path(args.out), document)
    return 0


def cmd_import_libdosbox(args: argparse.Namespace) -> int:
    document = import_libdosbox_trace(
        trace_path=Path(args.trace),
        functions_path=_path_or_none(args.functions),
        dump_path=_path_or_none(args.dump),
        meta_path=_path_or_none(args.meta),
    )
    write_json(Path(args.out), document)
    return 0


def cmd_regions(args: argparse.Namespace) -> int:
    catalog = load_json(Path(args.functions))
    document = summarize_region_effects(
        exe_path=Path(args.exe),
        functions_catalog=catalog,
        max_regions_per_function=args.max_regions_per_function,
        max_insns_per_region=args.max_insns_per_region,
        scan_limit=args.scan_limit,
    )
    write_json(Path(args.out), document)
    return 0


def cmd_complexity(args: argparse.Namespace) -> int:
    catalog = load_json(Path(args.functions))
    document = analyze_function_complexity(
        exe_path=Path(args.exe),
        functions_catalog=catalog,
        max_blocks_per_function=args.max_blocks_per_function,
        max_insns_per_function=args.max_insns_per_function,
        max_simple_insns=args.max_simple_insns,
        simple_score_threshold=args.simple_score_threshold,
        max_simple_symbolic_memory=args.max_simple_symbolic_memory,
        max_risk_points=args.max_risk_points,
        scan_limit=args.scan_limit,
    )
    write_json(Path(args.out), document)
    return 0


def cmd_ssa(args: argparse.Namespace) -> int:
    catalog = load_json(Path(args.functions))
    output_regs = tuple(args.output_reg or DEFAULT_OUTPUT_REGS)
    document = lower_straightline_ssa_document(
        exe_path=Path(args.exe),
        functions_catalog=catalog,
        output_regs=output_regs,
        max_insns_per_function=args.max_insns_per_function,
        scan_limit=args.scan_limit,
    )
    write_json(Path(args.out), document)
    return 0


def cmd_compare_ssa(args: argparse.Namespace) -> int:
    oracle = load_json(Path(args.oracle_ssa))
    candidate = load_json(Path(args.candidate_ssa))
    mapping = load_json(Path(args.mapping)) if args.mapping else None
    document = compare_ssa_documents(
        oracle=oracle,
        candidate=candidate,
        mapping_document=mapping,
        include_unmapped=bool(args.include_unmapped),
        timeout_ms=args.solver_timeout_ms,
    )
    write_json(Path(args.out), document)
    summary = document.get("summary", {})
    return 0 if summary.get("failed") == 0 and summary.get("refused") == 0 else 1


def cmd_compare_regions(args: argparse.Namespace) -> int:
    oracle = load_json(Path(args.oracle_regions))
    candidate = load_json(Path(args.candidate_regions))
    document = compare_region_effect_documents(oracle=oracle, candidate=candidate)
    write_json(Path(args.out), document)
    return 0 if document.get("summary", {}).get("failed") == 0 and document.get("summary", {}).get("refused") == 0 else 1


def cmd_make_mapping(args: argparse.Namespace) -> int:
    oracle = load_json(Path(args.oracle_functions))
    candidate = load_json(Path(args.candidate_functions))
    document = make_mapping_document(oracle_catalog=oracle, candidate_catalog=candidate, mode=args.mode)
    write_json(Path(args.out), document)
    return 0


def cmd_select_vectors(args: argparse.Namespace) -> int:
    vectors = load_json(Path(args.vectors))
    document = select_vectors(vectors, names=args.function, limit=args.limit)
    write_json(Path(args.out), document)
    return 0


def cmd_record_oracle(args: argparse.Namespace) -> int:
    vectors = load_json(Path(args.vectors))
    functions = load_json(Path(args.functions)) if args.functions else None
    document = record_oracle(
        vectors,
        backend=args.backend,
        exe_path=_path_or_none(args.exe),
        functions_catalog=functions,
        kvikdos_path=_path_or_none(args.kvikdos),
    )
    write_json(Path(args.out), document)
    return 0 if _all_results_passed(document) else 1


def cmd_compare(args: argparse.Namespace) -> int:
    vectors = load_json(Path(args.vectors))
    functions = load_json(Path(args.functions)) if args.functions else None
    mapping = load_json(Path(args.mapping)) if args.mapping else None
    document = compare_vectors(
        vectors,
        backend=args.backend,
        candidate_path=_path_or_none(args.candidate),
        functions_catalog=functions,
        mapping_document=mapping,
        kvikdos_path=_path_or_none(args.kvikdos),
        ignore_fields=set(args.ignore_field or []),
    )
    write_json(Path(args.out), document)
    return 0 if _all_results_passed(document) else 1


def cmd_compare_data(args: argparse.Namespace) -> int:
    oracle_catalog = load_json(Path(args.oracle_functions))
    candidate_catalog = load_json(Path(args.candidate_functions))
    document = compare_loaded_data_images(
        oracle_exe=Path(args.oracle_exe),
        candidate_exe=Path(args.candidate_exe),
        oracle_catalog=oracle_catalog,
        candidate_catalog=candidate_catalog,
        ranges=args.range,
        code_pointer_normalizations=args.normalize_code_pointer or [],
        oracle_load_base_para=_parse_cli_int(args.oracle_load_base, field="--oracle-load-base"),
        candidate_load_base_para=_parse_cli_int(args.candidate_load_base, field="--candidate-load-base"),
    )
    write_json(Path(args.out), document)
    return 0 if document.get("status") == "passed" else 1


def cmd_summarize(args: argparse.Namespace) -> int:
    document = load_json(Path(args.results))
    results = document.get("results", []) if isinstance(document, dict) else []
    summary = summarize_results(results if isinstance(results, list) else [])
    if args.out:
        write_json(Path(args.out), summary)
    else:
        for key, value in summary.items():
            print(f"{key}: {value}")
    return 0


def cmd_report_failures(args: argparse.Namespace) -> int:
    document = load_json(Path(args.results))
    if not isinstance(document, dict):
        raise DosUnitError("--results must be a JSON object")
    report = render_failure_report(document, limit=args.limit, mismatch_limit=args.mismatch_limit)
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(report)
    else:
        print(report, end="")
    return 0


def _all_results_passed(document: dict[str, Any]) -> bool:
    results = document.get("results", [])
    return isinstance(results, list) and all(isinstance(result, dict) and result.get("status") == "passed" for result in results)


def _parse_cli_int(value: str, *, field: str) -> int:
    try:
        return int(value, 0)
    except ValueError as ex:
        raise DosUnitError(f"{field} must be an integer or hex string") from ex


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dosunit", description="DOS function unit-test tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    discover = subparsers.add_parser("discover", help="Discover function catalog from DOS metadata")
    discover.add_argument("--exe")
    discover.add_argument("--map")
    discover.add_argument("--ida-listing")
    discover.add_argument("--module")
    discover.add_argument("--out", required=True)
    discover.set_defaults(func=cmd_discover)

    gen = subparsers.add_parser("gen-vectors", help="Generate input vectors")
    gen.add_argument("--exe")
    gen.add_argument("--functions", required=True)
    gen.add_argument("--strategy", default="entry", choices=["entry", "edge", "hot", "manual_seed"])
    gen.add_argument("--max-vectors-per-function", type=int, default=1)
    gen.add_argument("--max-branches", type=int)
    gen.add_argument("--max-blocks", type=int)
    gen.add_argument("--max-loop-unroll", type=int, default=0)
    gen.add_argument("--solver-timeout-ms", type=int, default=1000)
    gen.add_argument("--out", required=True)
    gen.set_defaults(func=cmd_gen_vectors)

    importer = subparsers.add_parser("import-libdosbox", help="Import libdosbox runtime trace")
    importer.add_argument("--trace", required=True)
    importer.add_argument("--dump")
    importer.add_argument("--meta")
    importer.add_argument("--functions")
    importer.add_argument("--out", required=True)
    importer.set_defaults(func=cmd_import_libdosbox)

    regions = subparsers.add_parser("regions", help="Summarize lifter-backed region operand/effects")
    regions.add_argument("--exe", required=True)
    regions.add_argument("--functions", required=True)
    regions.add_argument("--max-regions-per-function", type=int, default=8)
    regions.add_argument("--max-insns-per-region", type=int, default=32)
    regions.add_argument("--scan-limit", type=lambda value: int(value, 0), default=0x200)
    regions.add_argument("--out", required=True)
    regions.set_defaults(func=cmd_regions)

    complexity = subparsers.add_parser("complexity", help="Analyze per-function Z3/solver complexity")
    complexity.add_argument("--exe", required=True)
    complexity.add_argument("--functions", required=True)
    complexity.add_argument("--max-blocks-per-function", type=int, default=32)
    complexity.add_argument("--max-insns-per-function", type=int, default=128)
    complexity.add_argument("--max-simple-insns", type=int, default=16)
    complexity.add_argument("--simple-score-threshold", type=int, default=8)
    complexity.add_argument("--max-simple-symbolic-memory", type=int, default=0)
    complexity.add_argument("--max-risk-points", type=int, default=16)
    complexity.add_argument("--scan-limit", type=lambda value: int(value, 0), default=0x200)
    complexity.add_argument("--out", required=True)
    complexity.set_defaults(func=cmd_complexity)

    ssa = subparsers.add_parser("ssa", help="Lower bounded straight-line VEX slices into compact SSA")
    ssa.add_argument("--exe", required=True)
    ssa.add_argument("--functions", required=True)
    ssa.add_argument("--output-reg", action="append")
    ssa.add_argument("--max-insns-per-function", type=int, default=24)
    ssa.add_argument("--scan-limit", type=lambda value: int(value, 0), default=0x100)
    ssa.add_argument("--out", required=True)
    ssa.set_defaults(func=cmd_ssa)

    compare_ssa = subparsers.add_parser("compare-ssa", help="Compare compact SSA artifacts with Z3")
    compare_ssa.add_argument("--oracle-ssa", required=True)
    compare_ssa.add_argument("--candidate-ssa", required=True)
    compare_ssa.add_argument("--mapping")
    compare_ssa.add_argument("--include-unmapped", action="store_true")
    compare_ssa.add_argument("--solver-timeout-ms", type=int, default=1000)
    compare_ssa.add_argument("--out", required=True)
    compare_ssa.set_defaults(func=cmd_compare_ssa)

    compare_regions = subparsers.add_parser("compare-regions", help="Compare region operand/effect artifacts")
    compare_regions.add_argument("--oracle-regions", required=True)
    compare_regions.add_argument("--candidate-regions", required=True)
    compare_regions.add_argument("--out", required=True)
    compare_regions.set_defaults(func=cmd_compare_regions)

    mapping = subparsers.add_parser("make-mapping", help="Build candidate mapping from function catalogs")
    mapping.add_argument("--oracle-functions", required=True)
    mapping.add_argument("--candidate-functions", required=True)
    mapping.add_argument("--mode", default="name", choices=["name"])
    mapping.add_argument("--out", required=True)
    mapping.set_defaults(func=cmd_make_mapping)

    selector = subparsers.add_parser("select-vectors", help="Select a bounded vector subset")
    selector.add_argument("--vectors", required=True)
    selector.add_argument("--function", action="append", default=[])
    selector.add_argument("--limit", type=int)
    selector.add_argument("--out", required=True)
    selector.set_defaults(func=cmd_select_vectors)

    record = subparsers.add_parser("record-oracle", help="Record oracle outputs")
    record.add_argument("--exe")
    record.add_argument("--vectors", required=True)
    record.add_argument("--functions")
    record.add_argument("--kvikdos")
    record.add_argument("--backend", default="fixture", choices=["fixture", "libkvikdos", "kvikdos"])
    record.add_argument("--out", required=True)
    record.set_defaults(func=cmd_record_oracle)

    compare = subparsers.add_parser("compare", help="Compare candidate outputs")
    compare.add_argument("--candidate")
    compare.add_argument("--vectors", required=True)
    compare.add_argument("--mapping")
    compare.add_argument("--functions")
    compare.add_argument("--kvikdos")
    compare.add_argument("--ignore-field", action="append", choices=["status", "regs", "sregs", "flags", "memory", "return", "calls"])
    compare.add_argument("--backend", default="fixture", choices=["fixture", "libkvikdos", "kvikdos"])
    compare.add_argument("--out", required=True)
    compare.set_defaults(func=cmd_compare)

    compare_data = subparsers.add_parser("compare-data", help="Compare loaded MZ data ranges")
    compare_data.add_argument("--oracle-exe", required=True)
    compare_data.add_argument("--candidate-exe", required=True)
    compare_data.add_argument("--oracle-functions", required=True)
    compare_data.add_argument("--candidate-functions", required=True)
    compare_data.add_argument("--range", action="append", required=True)
    compare_data.add_argument("--normalize-code-pointer", action="append")
    compare_data.add_argument("--oracle-load-base", default="0x0000")
    compare_data.add_argument("--candidate-load-base", default="0x0000")
    compare_data.add_argument("--out", required=True)
    compare_data.set_defaults(func=cmd_compare_data)

    summarize = subparsers.add_parser("summarize", help="Summarize result JSON")
    summarize.add_argument("--results", required=True)
    summarize.add_argument("--out")
    summarize.set_defaults(func=cmd_summarize)

    report = subparsers.add_parser("report-failures", help="Render a visible failure report from result JSON")
    report.add_argument("--results", required=True)
    report.add_argument("--limit", type=int, default=50)
    report.add_argument("--mismatch-limit", type=int, default=8)
    report.add_argument("--out")
    report.set_defaults(func=cmd_report_failures)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except DosUnitError as ex:
        print(f"dosunit: {ex}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
