from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tools.dosunit.ir_edges import CAPSTONE_OP_MEM, _load_lifter_project
from tools.dosunit.model import DosUnitError, normalize_hex, parse_int, stable_id


REG_BY_OFFSET = {
    0: ("ax", 16),
    2: ("cx", 16),
    4: ("dx", 16),
    6: ("bx", 16),
    8: ("sp", 16),
    10: ("bp", 16),
    12: ("si", 16),
    14: ("di", 16),
    16: ("ip", 16),
    18: ("flags", 16),
    20: ("cs", 16),
    22: ("ds", 16),
    24: ("es", 16),
    30: ("ss", 16),
}
DEFAULT_OUTPUT_REGS = ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp")
CONTROL_MNEMONICS = {
    "call",
    "lcall",
    "int",
    "jmp",
    "ljmp",
    "jo",
    "jno",
    "jb",
    "jnae",
    "jc",
    "jnb",
    "jae",
    "jnc",
    "je",
    "jz",
    "jne",
    "jnz",
    "jbe",
    "jna",
    "ja",
    "jnbe",
    "js",
    "jns",
    "jp",
    "jpe",
    "jnp",
    "jpo",
    "jl",
    "jnge",
    "jge",
    "jnl",
    "jle",
    "jng",
    "jg",
    "jnle",
    "jcxz",
    "loop",
    "loope",
    "loopne",
    "loopz",
    "loopnz",
}
SUPPORTED_BINOPS = {
    "Add": "add",
    "Sub": "sub",
    "Mul": "mul",
    "And": "and",
    "Or": "or",
    "Xor": "xor",
    "Shl": "shl",
    "Shr": "lshr",
    "Sar": "ashr",
    "CmpEQ": "eq",
    "CmpNE": "ne",
}


@dataclass(frozen=True)
class SsaExpr:
    op: str
    width: int
    args: tuple["SsaExpr", ...] = ()
    value: int | None = None
    name: str | None = None

    def key(self) -> tuple[Any, ...]:
        return (self.op, self.width, self.value, self.name, tuple(arg.key() for arg in self.args))


@dataclass(frozen=True)
class LowerFailure:
    reason: str
    message: str


def lower_straightline_ssa_document(
    *,
    exe_path: Path,
    functions_catalog: dict[str, Any],
    output_regs: tuple[str, ...] = DEFAULT_OUTPUT_REGS,
    max_insns_per_function: int = 24,
    scan_limit: int = 0x100,
) -> dict[str, Any]:
    functions = list(functions_catalog.get("functions", []) or [])
    project = _load_lifter_project(exe_path)
    linked_base = int(getattr(project.loader.main_object, "linked_base", 0))
    lowered: list[dict[str, Any]] = []
    refusals: list[dict[str, Any]] = []
    counters = {
        "functions_seen": len(functions),
        "functions_attempted": 0,
        "functions_lowered": 0,
        "functions_refused": 0,
        "lifter_blocks_lifted": 0,
        "assignments_emitted": 0,
        "refusals_by_reason": {},
    }

    for function in functions:
        counters["functions_attempted"] += 1
        result, refusal, blocks_lifted = _lower_function(
            project=project,
            linked_base=linked_base,
            function=function,
            output_regs=output_regs,
            max_insns_per_function=max_insns_per_function,
            scan_limit=scan_limit,
        )
        counters["lifter_blocks_lifted"] += blocks_lifted
        if result is None:
            counters["functions_refused"] += 1
            refusals.append(refusal or _refusal(function, "unsupported_ir", "lowering failed without detail"))
            continue
        lowered.append(result)
        counters["functions_lowered"] += 1
        counters["assignments_emitted"] += len(result.get("assignments", []) or [])

    counters["refusals_by_reason"] = _refusal_counts(refusals)
    document_without_id = {
        "schema": "dosunit.ssa.v1",
        "exe": str(exe_path),
        "source_ir": "vex",
        "module": str(functions_catalog.get("module", exe_path.name)),
        "parameters": {
            "output_regs": list(output_regs),
            "max_insns_per_function": max_insns_per_function,
            "scan_limit": scan_limit,
        },
        "functions": lowered,
        "refusals": refusals,
        "counters": counters,
    }
    document = dict(document_without_id)
    document["id"] = stable_id("ssa", document_without_id)
    return document


def compare_ssa_documents(
    *,
    oracle: dict[str, Any],
    candidate: dict[str, Any],
    mapping_document: dict[str, Any] | None = None,
    include_unmapped: bool = True,
    timeout_ms: int = 1000,
) -> dict[str, Any]:
    candidate_by_key = _functions_by_name_and_ordinal(list(candidate.get("functions", []) or []))
    candidate_by_id = _functions_by_id(list(candidate.get("functions", []) or []))
    mapped_candidates = _ssa_candidate_mapping(mapping_document) if mapping_document is not None else {}
    ordinals: dict[str, int] = defaultdict(int)
    results: list[dict[str, Any]] = []
    solver_time_ms = 0
    skipped_unmapped = 0
    for oracle_function in list(oracle.get("functions", []) or []):
        function = oracle_function.get("function", {}) if isinstance(oracle_function, dict) else {}
        function_id = str(function.get("id", ""))
        function_name = str(function.get("name", function_id))
        if mapping_document is not None:
            mapped = mapped_candidates.get(function_id) or mapped_candidates.get(function_name)
            if mapped is None:
                skipped_unmapped += 1
                if not include_unmapped:
                    continue
                candidate_function = None
            else:
                candidate_function = candidate_by_id.get(str(mapped.get("candidate_id")))
                if candidate_function is None:
                    candidate_name = str(mapped.get("candidate_name", ""))
                    candidate_function = candidate_by_key.get((candidate_name, 0))
        else:
            function_key = function_name or function_id
            ordinal = ordinals[function_key]
            ordinals[function_key] += 1
            candidate_function = candidate_by_key.get((function_key, ordinal))
        if candidate_function is None:
            results.append(
                {
                    "status": "refused",
                    "reason": "mapping_missing",
                    "function": {"id": function_id, "name": function_name},
                    "mismatches": [{"kind": "function_missing", "detail": "candidate SSA function ordinal is missing"}],
                }
            )
            continue
        comparison = _compare_functions(oracle_function, candidate_function, timeout_ms=timeout_ms)
        solver_time_ms += int(comparison.pop("solver_time_ms", 0))
        results.append(
            {
                "status": comparison["status"],
                "reason": comparison.get("reason"),
                "function": {"id": function_id, "name": function_name},
                "oracle_function": oracle_function.get("id"),
                "candidate_function": candidate_function.get("id"),
                "mismatches": comparison.get("mismatches", []),
            }
        )

    summary = {
        "total": len(results),
        "passed": sum(1 for result in results if result.get("status") == "passed"),
        "failed": sum(1 for result in results if result.get("status") == "failed"),
        "refused": sum(1 for result in results if result.get("status") == "refused"),
        "skipped_unmapped": skipped_unmapped,
        "solver_time_ms": solver_time_ms,
    }
    document_without_id = {
        "schema": "dosunit.ssa_compare.v1",
        "oracle": oracle.get("exe"),
        "candidate": candidate.get("exe"),
        "mapping": None if mapping_document is None else mapping_document.get("id"),
        "include_unmapped": include_unmapped,
        "summary": summary,
        "results": results,
    }
    document = dict(document_without_id)
    document["id"] = stable_id("ssa-compare", document_without_id)
    return document


def _lower_function(
    *,
    project: Any,
    linked_base: int,
    function: dict[str, Any],
    output_regs: tuple[str, ...],
    max_insns_per_function: int,
    scan_limit: int,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, int]:
    function_id = str(function.get("id", "<unknown>"))
    names = function.get("names", []) if isinstance(function.get("names"), list) else []
    function_name = str(names[0]) if names else function_id
    entry = function.get("entry", {})
    if not isinstance(entry, dict):
        return None, _refusal(function, "unsupported_ir", "function entry is missing"), 0
    try:
        segment_para = parse_int(entry.get("segment_para"), field="function.entry.segment_para")
        entry_ip = parse_int(entry.get("offset"), field="function.entry.offset")
    except DosUnitError as ex:
        return None, _refusal(function, "unsupported_ir", str(ex)), 0
    function_base = linked_base + (segment_para << 4)
    start = function_base + entry_ip
    size = function.get("size")
    limit = int(size) if isinstance(size, int) and size > 0 else scan_limit
    limit = max(1, min(limit, scan_limit))
    try:
        block = project.factory.block(start, size=limit, opt_level=0)
        irsb = block.vex
    except Exception as ex:  # noqa: BLE001
        return None, _refusal(function, "unsupported_ir", f"lifter block failed at {normalize_hex(start)}: {type(ex).__name__}: {ex}"), 0

    capstone_insns = [item.insn for item in block.capstone.insns]
    if not capstone_insns:
        return None, _refusal(function, "unsupported_ir", "lifter produced no instructions"), 1
    if len(capstone_insns) > max_insns_per_function:
        return None, _refusal(function, "unsupported_ir", f"instruction limit reached: {len(capstone_insns)} > {max_insns_per_function}"), 1
    for insn in capstone_insns:
        mnemonic = str(insn.mnemonic).lower()
        if any(getattr(operand, "type", None) == CAPSTONE_OP_MEM for operand in getattr(insn, "operands", []) or []):
            return None, _refusal(function, "unbounded_memory", f"memory operand is not modeled for SSA: {_instruction_disassembly(insn)} at {normalize_hex(int(insn.address))}"), 1
        if mnemonic in CONTROL_MNEMONICS:
            return None, _refusal(function, "unbounded_indirect_control", f"control instruction is not straight-line: {mnemonic} at {normalize_hex(int(insn.address))}"), 1
    if str(irsb.jumpkind) not in {"Ijk_Ret", "Ijk_Boring"}:
        return None, _refusal(function, "unbounded_indirect_control", f"unsupported VEX jumpkind for straight-line SSA: {irsb.jumpkind}"), 1

    lowered = _lower_irsb(irsb, output_regs=output_regs)
    if isinstance(lowered, LowerFailure):
        return None, _refusal(function, lowered.reason, lowered.message), 1
    body_without_id = {
        "function": {"id": function_id, "name": function_name},
        "entry": {
            "cs": normalize_hex(segment_para, width=4),
            "ip": normalize_hex(entry_ip, width=4),
            "linear": normalize_hex(start),
        },
        "source": {
            "ir": "vex",
            "jumpkind": str(irsb.jumpkind),
            "instruction_count": len(capstone_insns),
            "instructions": [_instruction_text(insn, function_base=function_base) for insn in capstone_insns],
        },
        **lowered,
    }
    body = dict(body_without_id)
    body["id"] = stable_id("ssa-function", body_without_id)
    return body, None, 1


def _lower_irsb(irsb: Any, *, output_regs: tuple[str, ...]) -> dict[str, Any] | LowerFailure:
    temp_defs: dict[int, SsaExpr] = {}
    temp_failures: dict[int, LowerFailure] = {}
    reg_versions: dict[str, SsaExpr] = {name: SsaExpr("input", width, name=name) for _offset, (name, width) in REG_BY_OFFSET.items()}

    for statement in irsb.statements:
        tag = statement.tag
        if tag == "Ist_IMark":
            continue
        if tag == "Ist_WrTmp":
            expr = _lower_expr(statement.data, temp_defs=temp_defs, temp_failures=temp_failures, tyenv=irsb.tyenv)
            if isinstance(expr, LowerFailure):
                temp_failures[int(statement.tmp)] = expr
            else:
                temp_defs[int(statement.tmp)] = expr
            continue
        if tag == "Ist_Put":
            reg = REG_BY_OFFSET.get(int(statement.offset))
            if reg is None:
                continue
            expr = _lower_expr(statement.data, temp_defs=temp_defs, temp_failures=temp_failures, tyenv=irsb.tyenv)
            if isinstance(expr, LowerFailure):
                reg_versions[reg[0]] = SsaExpr("unsupported", reg[1], name=f"{expr.reason}|{expr.message}")
            else:
                if expr.width != reg[1]:
                    return LowerFailure("unsupported_ir", f"partial register write is not modeled: offset {statement.offset} width {expr.width}")
                reg_versions[reg[0]] = _coerce_width(expr, reg[1])
            continue
        if tag == "Ist_Store":
            return LowerFailure("unsupported_effect", "straight-line SSA does not yet model memory stores")
        if tag == "Ist_Exit":
            return LowerFailure("unbounded_indirect_control", "straight-line SSA does not model VEX exits")
        if tag in {"Ist_NoOp", "Ist_AbiHint", "Ist_MBE"}:
            continue
        return LowerFailure("unsupported_ir", f"unsupported VEX statement: {tag}")

    requested: dict[str, SsaExpr] = {}
    for reg in output_regs:
        if reg not in reg_versions:
            return LowerFailure("unsupported_ir", f"unsupported output register: {reg}")
        expr = reg_versions[reg]
        failure = _expr_failure(expr)
        if failure is not None:
            return failure
        requested[reg] = expr

    assignments: list[dict[str, Any]] = []
    memo: dict[tuple[Any, ...], str] = {}
    outputs = {reg: _materialize(expr, assignments=assignments, memo=memo) for reg, expr in requested.items()}
    return {
        "inputs": [{"name": reg, "width": width} for _offset, (reg, width) in sorted(REG_BY_OFFSET.items()) if reg in set(_collect_inputs(requested.values()))],
        "outputs": outputs,
        "assignments": assignments,
    }


def _lower_expr(expr: Any, *, temp_defs: dict[int, SsaExpr], temp_failures: dict[int, LowerFailure], tyenv: Any) -> SsaExpr | LowerFailure:
    tag = expr.tag
    if tag == "Iex_RdTmp":
        tmp = int(expr.tmp)
        if tmp in temp_failures:
            return temp_failures[tmp]
        if tmp not in temp_defs:
            return LowerFailure("unsupported_ir", f"read of undefined VEX tmp t{tmp}")
        return temp_defs[tmp]
    if tag == "Iex_Get":
        reg = REG_BY_OFFSET.get(int(expr.offset))
        if reg is None:
            return LowerFailure("unsupported_ir", f"unsupported VEX register offset {expr.offset}")
        width = int(expr.result_size(tyenv))
        if width != reg[1]:
            return LowerFailure("unsupported_ir", f"partial register read is not modeled: offset {expr.offset} width {width}")
        return SsaExpr("input", width, name=reg[0])
    if tag == "Iex_Const":
        return SsaExpr("const", int(expr.con.size), value=int(expr.con.value) & _mask(int(expr.con.size)))
    if tag == "Iex_Binop":
        return _lower_binop(expr, temp_defs=temp_defs, temp_failures=temp_failures, tyenv=tyenv)
    if tag == "Iex_Unop":
        return _lower_unop(expr, temp_defs=temp_defs, temp_failures=temp_failures, tyenv=tyenv)
    if tag == "Iex_ITE":
        cond = _lower_expr(expr.cond, temp_defs=temp_defs, temp_failures=temp_failures, tyenv=tyenv)
        if isinstance(cond, LowerFailure):
            return cond
        iftrue = _lower_expr(expr.iftrue, temp_defs=temp_defs, temp_failures=temp_failures, tyenv=tyenv)
        if isinstance(iftrue, LowerFailure):
            return iftrue
        iffalse = _lower_expr(expr.iffalse, temp_defs=temp_defs, temp_failures=temp_failures, tyenv=tyenv)
        if isinstance(iffalse, LowerFailure):
            return iffalse
        return SsaExpr("ite", int(expr.result_size(tyenv)), (_coerce_width(cond, 1), iftrue, iffalse))
    if tag == "Iex_Load":
        return LowerFailure("unbounded_memory", "output slice depends on a memory load")
    return LowerFailure("unsupported_ir", f"unsupported VEX expression: {tag}")


def _lower_binop(expr: Any, *, temp_defs: dict[int, SsaExpr], temp_failures: dict[int, LowerFailure], tyenv: Any) -> SsaExpr | LowerFailure:
    op = _strip_iop(str(expr.op))
    base = _strip_width_suffix(op)
    lowered_op = SUPPORTED_BINOPS.get(base)
    if lowered_op is None:
        return LowerFailure("unsupported_ir", f"unsupported VEX binop: {op}")
    args: list[SsaExpr] = []
    for arg in expr.args:
        lowered = _lower_expr(arg, temp_defs=temp_defs, temp_failures=temp_failures, tyenv=tyenv)
        if isinstance(lowered, LowerFailure):
            return lowered
        args.append(lowered)
    width = int(expr.result_size(tyenv))
    if lowered_op in {"eq", "ne"}:
        return SsaExpr(lowered_op, 1, (_coerce_width(args[0], args[1].width), args[1]))
    if lowered_op in {"shl", "lshr", "ashr"}:
        return SsaExpr(lowered_op, width, (_coerce_width(args[0], width), args[1]))
    return SsaExpr(lowered_op, width, tuple(_coerce_width(arg, width) for arg in args))


def _lower_unop(expr: Any, *, temp_defs: dict[int, SsaExpr], temp_failures: dict[int, LowerFailure], tyenv: Any) -> SsaExpr | LowerFailure:
    op = _strip_iop(str(expr.op))
    if len(expr.args) != 1:
        return LowerFailure("unsupported_ir", f"unsupported VEX unop arity: {op}")
    arg = _lower_expr(expr.args[0], temp_defs=temp_defs, temp_failures=temp_failures, tyenv=tyenv)
    if isinstance(arg, LowerFailure):
        return arg
    width = int(expr.result_size(tyenv))
    if op.startswith("Not"):
        return SsaExpr("not", width, (_coerce_width(arg, width),))
    if "Uto" in op:
        return SsaExpr("zext", width, (arg,))
    if "Sto" in op:
        return SsaExpr("sext", width, (arg,))
    if "to" in op:
        return SsaExpr("trunc", width, (arg,))
    return LowerFailure("unsupported_ir", f"unsupported VEX unop: {op}")


def _materialize(expr: SsaExpr, *, assignments: list[dict[str, Any]], memo: dict[tuple[Any, ...], str]) -> dict[str, Any]:
    if expr.op == "input":
        return {"op": "input", "name": expr.name, "width": expr.width}
    if expr.op == "const":
        return {"op": "const", "value": normalize_hex(expr.value or 0), "width": expr.width}
    key = expr.key()
    if key in memo:
        return {"ref": memo[key]}
    args = [_materialize(arg, assignments=assignments, memo=memo) for arg in expr.args]
    ident = f"v{len(assignments)}"
    memo[key] = ident
    assignments.append({"id": ident, "op": expr.op, "width": expr.width, "args": args})
    return {"ref": ident}


def _compare_functions(oracle: dict[str, Any], candidate: dict[str, Any], *, timeout_ms: int) -> dict[str, Any]:
    try:
        import z3  # type: ignore
    except Exception:  # noqa: BLE001
        return {"status": "refused", "reason": "unsupported_ir", "mismatches": [{"kind": "z3_unavailable"}], "solver_time_ms": 0}

    import time

    started = time.monotonic()
    oracle_outputs = oracle.get("outputs", {}) if isinstance(oracle.get("outputs"), dict) else {}
    candidate_outputs = candidate.get("outputs", {}) if isinstance(candidate.get("outputs"), dict) else {}
    output_regs = sorted(set(oracle_outputs) & set(candidate_outputs))
    if not output_regs:
        return {"status": "refused", "reason": "unsupported_ir", "mismatches": [{"kind": "no_common_outputs"}], "solver_time_ms": 0}

    inputs = _z3_inputs(oracle, candidate, z3)
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    differing: list[Any] = []
    pairs: list[tuple[str, Any, Any]] = []
    for reg in output_regs:
        oracle_expr = _z3_term(oracle_outputs[reg], document=oracle, inputs=inputs, z3=z3)
        candidate_expr = _z3_term(candidate_outputs[reg], document=candidate, inputs=inputs, z3=z3)
        oracle_expr, candidate_expr = _align_z3_widths(oracle_expr, candidate_expr, z3)
        pairs.append((reg, oracle_expr, candidate_expr))
        differing.append(oracle_expr != candidate_expr)
    solver.add(z3.Or(*differing))
    status = solver.check()
    elapsed = int((time.monotonic() - started) * 1000)
    if status == z3.unknown:
        return {"status": "refused", "reason": "timeout", "mismatches": [{"kind": "z3_unknown", "detail": solver.reason_unknown()}], "solver_time_ms": elapsed}
    if status != z3.sat:
        return {"status": "passed", "reason": None, "mismatches": [], "solver_time_ms": elapsed}
    model = solver.model()
    counterexample = {name: normalize_hex(model.eval(value, model_completion=True).as_long(), width=width // 4) for name, (value, width) in inputs.items()}
    mismatches: list[dict[str, Any]] = []
    for reg, oracle_expr, candidate_expr in pairs:
        oracle_value = model.eval(oracle_expr, model_completion=True).as_long()
        candidate_value = model.eval(candidate_expr, model_completion=True).as_long()
        if oracle_value != candidate_value:
            mismatches.append(
                {
                    "kind": "output_expr_changed",
                    "reg": reg,
                    "oracle_value": normalize_hex(oracle_value),
                    "candidate_value": normalize_hex(candidate_value),
                    "counterexample": counterexample,
                }
            )
    return {"status": "failed", "reason": "observable_mismatch", "mismatches": mismatches, "solver_time_ms": elapsed}


def _z3_inputs(oracle: dict[str, Any], candidate: dict[str, Any], z3: Any) -> dict[str, tuple[Any, int]]:
    widths: dict[str, int] = {}
    for document in (oracle, candidate):
        for item in document.get("inputs", []) or []:
            if isinstance(item, dict) and item.get("name"):
                widths[str(item["name"])] = max(int(item.get("width", 16)), widths.get(str(item["name"]), 0))
    return {name: (z3.BitVec(name, width), width) for name, width in sorted(widths.items())}


def _z3_term(term: dict[str, Any], *, document: dict[str, Any], inputs: dict[str, tuple[Any, int]], z3: Any) -> Any:
    if "ref" in term:
        assignments = {item["id"]: item for item in document.get("assignments", []) or [] if isinstance(item, dict) and "id" in item}
        return _z3_assignment(str(term["ref"]), assignments=assignments, document=document, inputs=inputs, z3=z3, cache={})
    op = term.get("op")
    width = int(term.get("width", 16))
    if op == "input":
        return _resize_z3(inputs[str(term["name"])][0], inputs[str(term["name"])][1], width, signed=False, z3=z3)
    if op == "const":
        return z3.BitVecVal(parse_int(term.get("value"), field="ssa.const"), width)
    raise DosUnitError(f"unsupported SSA term: {term}")


def _z3_assignment(
    ident: str,
    *,
    assignments: dict[str, dict[str, Any]],
    document: dict[str, Any],
    inputs: dict[str, tuple[Any, int]],
    z3: Any,
    cache: dict[str, Any],
) -> Any:
    if ident in cache:
        return cache[ident]
    item = assignments[ident]
    op = str(item.get("op"))
    width = int(item.get("width", 16))
    args = [_z3_term(arg, document={**document, "assignments": list(assignments.values())}, inputs=inputs, z3=z3) for arg in item.get("args", []) or []]
    result = _z3_apply(op, width, args, z3)
    cache[ident] = result
    return result


def _z3_apply(op: str, width: int, args: list[Any], z3: Any) -> Any:
    if op == "add":
        return _resize_z3(args[0] + args[1], args[0].size(), width, signed=False, z3=z3)
    if op == "sub":
        return _resize_z3(args[0] - args[1], args[0].size(), width, signed=False, z3=z3)
    if op == "mul":
        return _resize_z3(args[0] * args[1], args[0].size(), width, signed=False, z3=z3)
    if op == "and":
        return args[0] & args[1]
    if op == "or":
        return args[0] | args[1]
    if op == "xor":
        return args[0] ^ args[1]
    if op == "not":
        return ~args[0]
    if op == "shl":
        return _resize_z3(args[0] << _resize_z3(args[1], args[1].size(), args[0].size(), signed=False, z3=z3), args[0].size(), width, signed=False, z3=z3)
    if op == "lshr":
        return z3.LShR(args[0], _resize_z3(args[1], args[1].size(), args[0].size(), signed=False, z3=z3))
    if op == "ashr":
        return args[0] >> _resize_z3(args[1], args[1].size(), args[0].size(), signed=False, z3=z3)
    if op == "eq":
        return z3.If(args[0] == args[1], z3.BitVecVal(1, 1), z3.BitVecVal(0, 1))
    if op == "ne":
        return z3.If(args[0] != args[1], z3.BitVecVal(1, 1), z3.BitVecVal(0, 1))
    if op == "zext":
        return _resize_z3(args[0], args[0].size(), width, signed=False, z3=z3)
    if op == "sext":
        return _resize_z3(args[0], args[0].size(), width, signed=True, z3=z3)
    if op == "trunc":
        return _resize_z3(args[0], args[0].size(), width, signed=False, z3=z3)
    if op == "ite":
        return z3.If(args[0] != z3.BitVecVal(0, args[0].size()), args[1], args[2])
    raise DosUnitError(f"unsupported SSA op: {op}")


def _resize_z3(value: Any, from_width: int, to_width: int, *, signed: bool, z3: Any) -> Any:
    if from_width == to_width:
        return value
    if from_width > to_width:
        return z3.Extract(to_width - 1, 0, value)
    extend = z3.SignExt if signed else z3.ZeroExt
    return extend(to_width - from_width, value)


def _align_z3_widths(left: Any, right: Any, z3: Any) -> tuple[Any, Any]:
    left_width = int(left.size())
    right_width = int(right.size())
    width = max(left_width, right_width)
    return _resize_z3(left, left_width, width, signed=False, z3=z3), _resize_z3(right, right_width, width, signed=False, z3=z3)


def _coerce_width(expr: SsaExpr, width: int) -> SsaExpr:
    if expr.width == width:
        return expr
    if expr.width < width:
        return SsaExpr("zext", width, (expr,))
    return SsaExpr("trunc", width, (expr,))


def _expr_failure(expr: SsaExpr) -> LowerFailure | None:
    if expr.op == "unsupported":
        if expr.name and "|" in expr.name:
            reason, message = expr.name.split("|", 1)
            return LowerFailure(reason, message)
        return LowerFailure("unsupported_ir", expr.name or "unsupported expression reached output slice")
    for arg in expr.args:
        failure = _expr_failure(arg)
        if failure is not None:
            return failure
    return None


def _collect_inputs(expressions: Any) -> set[str]:
    found: set[str] = set()
    for expr in expressions:
        if expr.op == "input" and expr.name:
            found.add(expr.name)
        found.update(_collect_inputs(expr.args))
    return found


def _strip_iop(op: str) -> str:
    return op[4:] if op.startswith("Iop_") else op


def _strip_width_suffix(op: str) -> str:
    while op and op[-1].isdigit():
        op = op[:-1]
    return op


def _mask(width: int) -> int:
    return (1 << width) - 1


def _functions_by_name_and_ordinal(functions: list[dict[str, Any]]) -> dict[tuple[str, int], dict[str, Any]]:
    counts: dict[str, int] = defaultdict(int)
    indexed: dict[tuple[str, int], dict[str, Any]] = {}
    for function in functions:
        info = function.get("function", {}) if isinstance(function.get("function"), dict) else {}
        function_id = str(info.get("id", ""))
        function_name = str(info.get("name", function_id))
        key = function_name or function_id
        ordinal = counts[key]
        counts[key] += 1
        indexed[(key, ordinal)] = function
    return indexed


def _functions_by_id(functions: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for function in functions:
        info = function.get("function", {}) if isinstance(function.get("function"), dict) else {}
        function_id = str(info.get("id", ""))
        if function_id:
            indexed[function_id] = function
    return indexed


def _ssa_candidate_mapping(mapping_document: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not isinstance(mapping_document, dict) or mapping_document.get("schema") != "dosunit.mapping.v1":
        return {}
    indexed: dict[str, dict[str, Any]] = {}
    for item in mapping_document.get("functions", []) or []:
        if not isinstance(item, dict):
            continue
        oracle_id = item.get("oracle_id")
        oracle_name = item.get("oracle_name")
        if oracle_id is not None:
            indexed[str(oracle_id)] = item
        if oracle_name is not None:
            indexed[str(oracle_name)] = item
    return indexed


def _instruction_disassembly(insn: Any) -> str:
    mnemonic = str(insn.mnemonic).lower()
    op_str = str(insn.op_str).lower()
    return mnemonic if not op_str else f"{mnemonic} {op_str}"


def _instruction_text(insn: Any, *, function_base: int) -> dict[str, Any]:
    return {
        "address": {
            "ip": normalize_hex((int(insn.address) - function_base) & 0xFFFF, width=4),
            "linear": normalize_hex(int(insn.address)),
        },
        "size": int(insn.size),
        "disassembly": _instruction_disassembly(insn),
    }


def _refusal(function: dict[str, Any], reason: str, message: str) -> dict[str, Any]:
    return {
        "status": "refused",
        "reason": reason,
        "detail": {
            "function_id": function.get("id"),
            "strategy": "straightline_ssa",
            "message": message,
        },
    }


def _refusal_counts(refusals: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in refusals:
        reason = str(item.get("reason", "unknown"))
        counts[reason] = counts.get(reason, 0) + 1
    return dict(sorted(counts.items()))
