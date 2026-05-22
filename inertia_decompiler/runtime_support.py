from __future__ import annotations

import contextlib
import io
import logging
import os
import pickle
import re
import resource
import select
import signal
import sys
import threading
import traceback
import time
import weakref
from collections.abc import Callable
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures.thread import _threads_queues, _worker
from datetime import datetime
from _pytest.capture import EncodedFile

from .variable_recovery_sub_guard import (
    build_guarded_handle_binop_mul_8616,
    build_guarded_handle_binop_sub_8616,
)


DEFAULT_FREE_RAM_BUDGET_FRACTION = 0.45
DEFAULT_WORKER_MEMORY_FLOOR_MB = 1536
FORCE_SERIAL_FUNCTION_DECOMP_ENV = "INERTIA_FORCE_SERIAL_FUNCTION_DECOMPILATION"
_FORK_CHILD_PID: int | None = None

START_TIME = time.perf_counter()
LAST_STEP_TIME = START_TIME
DECOMPILATION_PREP_LOCK = threading.Lock()
_REAL_STDOUT = sys.stdout
_REAL_STDERR = sys.stderr
_CURRENT_PROJECT = None
_FORMAT_FIRST_BLOCK_ASM: Callable[[object, int], str] | None = None
PEEPHOLE_COMPLEX_EXPR_NODE_LIMIT = 96


def timing_output_enabled() -> bool:
    value = os.environ.get("INERTIA_DEBUG_TIMING")
    if value is None:
        return False
    return value.strip().lower() not in {"", "0", "false", "no", "off"}


def _expr_child_nodes(expr) -> tuple[object, ...]:  # noqa: ANN001
    children: list[object] = []
    operand = getattr(expr, "operand", None)
    if operand is not None:
        children.append(operand)
    operands = getattr(expr, "operands", None)
    if isinstance(operands, tuple | list):
        children.extend(node for node in operands if node is not None)
    for attr in ("addr", "cond", "iftrue", "iffalse"):
        node = getattr(expr, attr, None)
        if node is not None:
            children.append(node)
    return tuple(children)


def _expr_tree_node_count(expr, cache: dict[int, int]) -> int:  # noqa: ANN001
    expr_id = id(expr)
    cached = cache.get(expr_id)
    if cached is not None:
        return cached
    total = 1
    for child in _expr_child_nodes(expr):
        if hasattr(child, "__dict__") or hasattr(type(child), "__slots__"):
            total += _expr_tree_node_count(child, cache)
            if total > PEEPHOLE_COMPLEX_EXPR_NODE_LIMIT:
                break
    cache[expr_id] = total
    return total


def _stmt_expr_children(stmt) -> tuple[object, ...]:  # noqa: ANN001
    children: list[object] = []
    for attr in ("dst", "src", "addr", "data", "condition", "true_target", "false_target", "ret_exprs"):
        value = getattr(stmt, attr, None)
        if isinstance(value, tuple | list):
            children.extend(node for node in value if node is not None)
        elif value is not None:
            children.append(value)
    return tuple(children)


def _block_has_pathologically_complex_expr(block, limit: int = PEEPHOLE_COMPLEX_EXPR_NODE_LIMIT) -> bool:  # noqa: ANN001
    cache: dict[int, int] = {}
    for stmt in getattr(block, "statements", ()) or ():
        for expr in _stmt_expr_children(stmt):
            if _expr_tree_node_count(expr, cache) > limit:
                return True
    return False


def install_jumpkind_logging_context(project, formatter: Callable[[object, int], str] | None) -> None:
    global _CURRENT_PROJECT, _FORMAT_FIRST_BLOCK_ASM
    _CURRENT_PROJECT = project
    _FORMAT_FIRST_BLOCK_ASM = formatter


def default_exe_showcase_cap(total_functions: int, timeout: int) -> int:
    if total_functions > 256:
        return 4
    return min(24, max(8, timeout))


def install_angr_peephole_expr_bitwidth_guard(walker_cls, project=None) -> object:
    original_handle_expr = walker_cls._handle_expr

    def _normalize_replacement_bits(expr, replacement):  # noqa: ANN001
        expr_bits = getattr(expr, "bits", None)
        replacement_bits = getattr(replacement, "bits", None)
        if expr_bits is None or replacement_bits is None or expr_bits == replacement_bits:
            return replacement

        try:
            from angr.ailment.expression import BasePointerOffset, Const
        except ImportError:
            return replacement

        if isinstance(replacement, BasePointerOffset):
            return BasePointerOffset(
                replacement.idx,
                expr_bits,
                replacement.base,
                replacement.offset,
                variable=getattr(replacement, "variable", None),
                variable_offset=getattr(replacement, "variable_offset", None),
                **getattr(replacement, "tags", {}),
            )

        if isinstance(replacement, Const) and isinstance(replacement.value, int):
            mask = (1 << expr_bits) - 1
            return Const(
                replacement.idx,
                getattr(replacement, "variable", None),
                replacement.value & mask,
                expr_bits,
                **getattr(replacement, "tags", {}),
            )

        return replacement

    def _guarded_handle_expr(self, expr_idx, expr, stmt_idx, stmt, block):
        try:
            expr = super(walker_cls, self)._handle_expr(expr_idx, expr, stmt_idx, stmt, block)
        except AssertionError:
            if timing_output_enabled() or os.environ.get("INERTIA_DEBUG_CLINIC_COMPLEX_EXPR"):
                block_addr = getattr(block, "addr", None)
                print(
                    "[dbg] clinic:skip-expr-assertion "
                    f"block={block_addr:#x} stmt_idx={stmt_idx} expr_idx={expr_idx}"
                    f"{_project_current_function_context_suffix(project)}",
                    file=sys.stderr,
                )
                sys.stderr.flush()
            return expr
        old_expr = expr
        if not getattr(project, "_inertia_disable_complex_expr_scan", False):
            expr_node_cache = getattr(self, "_inertia_expr_node_cache", None)
            if not isinstance(expr_node_cache, dict):
                expr_node_cache = {}
                self._inertia_expr_node_cache = expr_node_cache
            expr_node_count = _expr_tree_node_count(expr, expr_node_cache)
            if expr_node_count > PEEPHOLE_COMPLEX_EXPR_NODE_LIMIT:
                complex_seen = getattr(self, "_inertia_complex_expr_skip_seen", None)
                if not isinstance(complex_seen, set):
                    complex_seen = set()
                    self._inertia_complex_expr_skip_seen = complex_seen
                block_addr = getattr(block, "addr", None)
                skip_key = (block_addr, stmt_idx, expr_idx, type(expr).__name__)
                if skip_key not in complex_seen:
                    complex_seen.add(skip_key)
                    if timing_output_enabled() or os.environ.get("INERTIA_DEBUG_CLINIC_COMPLEX_EXPR"):
                        print(
                            "[dbg] clinic:skip-peephole-complex-expr "
                            f"block={block_addr:#x} "
                            f"stmt_idx={stmt_idx} "
                            f"expr_idx={expr_idx} "
                            f"expr_type={type(expr).__name__} "
                            f"node_count={expr_node_count}",
                            file=sys.stderr,
                        )
                        sys.stderr.flush()
                return expr
        redo = True
        rewrite_iter = 0
        seen_shapes: set[tuple[str, int | None]] = set()
        while redo:
            redo = False
            rewrite_iter += 1
            expr_shape = (type(expr).__name__, getattr(expr, "bits", None))
            if expr_shape in seen_shapes or rewrite_iter > 32:
                if timing_output_enabled() or os.environ.get("INERTIA_DEBUG_CLINIC_COMPLEX_EXPR"):
                    block_addr = getattr(block, "addr", None)
                    print(
                        "[dbg] clinic:stop-peephole-rewrite-loop "
                        f"block={block_addr:#x} "
                        f"stmt_idx={stmt_idx} expr_idx={expr_idx} "
                        f"iter={rewrite_iter} shape={expr_shape!r}",
                        file=sys.stderr,
                    )
                    sys.stderr.flush()
                break
            seen_shapes.add(expr_shape)
            for expr_opt in self.expr_opts:
                if isinstance(expr, expr_opt.expr_classes):
                    try:
                        replacement = expr_opt.optimize(expr, stmt_idx=stmt_idx, block=block)
                    except AssertionError:
                        continue
                    if replacement is not None and replacement is not expr:
                        replacement = _normalize_replacement_bits(expr, replacement)
                        if getattr(expr, "bits", None) != getattr(replacement, "bits", None):
                            block_addr = getattr(block, "addr", None)
                            if timing_output_enabled() or os.environ.get("INERTIA_DEBUG_CLINIC_COMPLEX_EXPR"):
                                print(
                                    "[dbg] clinic:peephole-bits-mismatch "
                                    f"opt={type(expr_opt).__name__} "
                                    f"block={block_addr:#x} "
                                    f"stmt_idx={stmt_idx} "
                                    f"expr_bits={getattr(expr, 'bits', None)} "
                                    f"replacement_bits={getattr(replacement, 'bits', None)} "
                                    f"expr={expr!s} replacement={replacement!s}",
                                    file=sys.stderr,
                                )
                                sys.stderr.flush()
                            continue
                        expr = replacement
                        redo = True
                        break
        if expr is not old_expr:
            self.any_update = True
        return expr

    walker_cls._handle_expr = _guarded_handle_expr
    return original_handle_expr


def enable_line_buffered_stdio() -> None:
    for stream in (_REAL_STDOUT, _REAL_STDERR):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(line_buffering=True)
            except Exception:
                pass


def _project_current_function_context(project) -> tuple[int | None, str | None, int | None]:
    context = getattr(project, "_inertia_current_function_debug", None)
    if not isinstance(context, dict):
        return (None, None, None)
    addr = context.get("addr")
    name = context.get("name")
    slice_addr = context.get("slice_addr")
    return (
        addr if isinstance(addr, int) else None,
        name if isinstance(name, str) else None,
        slice_addr if isinstance(slice_addr, int) else None,
    )


def _project_current_function_context_suffix(project) -> str:
    addr, name, slice_addr = _project_current_function_context(project)
    parts: list[str] = []
    if isinstance(addr, int):
        parts.append(f"addr={addr:#x}")
    if isinstance(slice_addr, int) and slice_addr != addr:
        parts.append(f"slice={slice_addr:#x}")
    if isinstance(name, str) and name:
        parts.append(f"name={name}")
    return f" {' '.join(parts)}" if parts else ""


def install_angr_variable_recovery_binop_sub_size_guard(
    engine_cls,
    *,
    richr_cls=None,
    typevars_module=None,
    project=None,
) -> object:
    if richr_cls is None or typevars_module is None:
        from angr.analyses.typehoon import typevars as angr_typevars
        from angr.analyses.variable_recovery import engine_ail as variable_recovery_engine

        richr_cls = variable_recovery_engine.RichR
        typevars_module = angr_typevars

    original_handle_binop_sub = engine_cls._handle_binop_Sub
    original_handle_binop_mul = engine_cls._handle_binop_Mul
    engine_cls._handle_binop_Sub = build_guarded_handle_binop_sub_8616(
        richr_cls=richr_cls,
        typevars_module=typevars_module,
        project=project,
        context_suffix=(_project_current_function_context, _project_current_function_context_suffix),
    )
    engine_cls._handle_binop_Mul = build_guarded_handle_binop_mul_8616(
        richr_cls=richr_cls,
        typevars_module=typevars_module,
        project=project,
        context_suffix=(_project_current_function_context, _project_current_function_context_suffix),
    )
    return original_handle_binop_sub, original_handle_binop_mul


def install_angr_basepointeroffset_codegen_guard(codegen_cls) -> object:
    original_handle = codegen_cls._handle

    def _guarded_handle(self, node, *args, **kwargs):  # noqa: ANN001
        try:
            from angr.ailment.expression import BasePointerOffset
        except ImportError:
            return original_handle(self, node, *args, **kwargs)

        if isinstance(node, BasePointerOffset):
            stackbase_handler = getattr(self, "_handle_Expr_StackBaseOffset", None)
            if callable(stackbase_handler):
                return stackbase_handler(node, *args, **kwargs)
        return original_handle(self, node, *args, **kwargs)

    codegen_cls._handle = _guarded_handle
    return original_handle


@contextlib.contextmanager
def guard_angr_peephole_expr_bitwidth_assertion(project=None):
    if project is not None and getattr(project, "_inertia_disable_peephole_expr_guard", False):
        yield
        return
    from angr.analyses.decompiler import utils as decompiler_utils

    walker_cls = decompiler_utils._PeepholeExprsWalker
    original_handle_expr = install_angr_peephole_expr_bitwidth_guard(walker_cls, project=project)
    try:
        yield
    finally:
        walker_cls._handle_expr = original_handle_expr


@contextlib.contextmanager
def guard_angr_basepointeroffset_codegen_support():
    from angr.analyses.decompiler.structured_codegen import c as structured_codegen_c

    codegen_cls = structured_codegen_c.CStructuredCodeGenerator
    original_handle = install_angr_basepointeroffset_codegen_guard(codegen_cls)
    try:
        yield
    finally:
        codegen_cls._handle = original_handle


@contextlib.contextmanager
def guard_angr_variable_recovery_binop_sub_size_mismatch(project=None):
    from angr.analyses.variable_recovery import engine_ail as variable_recovery_engine

    engine_cls = variable_recovery_engine.SimEngineVRAIL
    original_handle_binop_sub, original_handle_binop_mul = install_angr_variable_recovery_binop_sub_size_guard(
        engine_cls, project=project
    )
    try:
        yield
    finally:
        engine_cls._handle_binop_Sub = original_handle_binop_sub
        engine_cls._handle_binop_Mul = original_handle_binop_mul


@contextlib.contextmanager
def guard_angr_clinic_stage_markers(project):
    if not timing_output_enabled():
        yield
        return
    import time as _time
    from angr.analyses.decompiler.block_simplifier import BlockSimplifier
    from angr.analyses.decompiler.clinic import Clinic
    from angr.analyses.decompiler.utils import peephole_optimize_multistmts, peephole_optimize_stmts

    orig_stage_pre_ssa = Clinic._stage_pre_ssa_level1_simplifications
    orig_stage_ssa_level1 = Clinic._stage_transform_to_ssa_level1
    orig_stage_post_ssa = Clinic._stage_post_ssa_level1_simplifications
    orig_stage_recover_vars = Clinic._stage_recover_variables
    orig_simplify_block = Clinic._simplify_block
    orig_peephole_optimize = BlockSimplifier._peephole_optimize
    _t0 = _time.perf_counter()
    _last_stage: list[str] = ["start"]
    _stage_entry: list[float] = [_t0]

    def _emit_stage_time(new_stage: str) -> None:
        now = _time.perf_counter()
        elapsed_since_start = now - _t0
        elapsed_in_prev = now - _stage_entry[0]
        print(f"[dbg] stage-time: {new_stage} elapsed={elapsed_since_start:.2f}s (prev={_last_stage[0]} took {elapsed_in_prev:.2f}s)")
        sys.stderr.flush()
        _last_stage[0] = new_stage
        _stage_entry[0] = now

    def _stage_pre_ssa_level1_simplifications(self, *args, **kwargs):  # noqa: ANN001
        _emit_stage_time("clinic:pre_ssa_l1")
        project._inertia_decompiler_stage = "core:clinic:pre_ssa_level1_simplifications"
        if getattr(project, "_inertia_skip_clinic_pre_ssa", False):
            return self._ail_graph
        return orig_stage_pre_ssa(self, *args, **kwargs)

    def _stage_transform_to_ssa_level1(self, *args, **kwargs):  # noqa: ANN001
        _emit_stage_time("clinic:ssa_level1")
        project._inertia_decompiler_stage = "core:clinic:ssa_level1_transformation"
        if getattr(project, "_inertia_tiny_core_disable_peephole", False):
            return None
        return orig_stage_ssa_level1(self, *args, **kwargs)

    def _stage_post_ssa_level1_simplifications(self, *args, **kwargs):  # noqa: ANN001
        _emit_stage_time("clinic:post_ssa_l1")
        project._inertia_decompiler_stage = "core:clinic:post_ssa_level1_simplifications"
        return orig_stage_post_ssa(self, *args, **kwargs)

    def _stage_recover_variables(self, *args, **kwargs):  # noqa: ANN001
        _emit_stage_time("clinic:recover_vars")
        project._inertia_decompiler_stage = "core:clinic:recover_variables"
        return orig_stage_recover_vars(self, *args, **kwargs)

    _simplify_count: list[int] = [0]
    _peephole_count: list[int] = [0]
    _simplify_total: list[float] = [0.0]
    _peephole_total: list[float] = [0.0]

    def _simplify_block(self, *args, **kwargs):  # noqa: ANN001
        project._inertia_decompiler_stage = "core:clinic:simplify_block"
        block = args[0] if args else kwargs.get("block")
        if getattr(project, "_inertia_tiny_core_disable_peephole", False):
            if block is not None:
                return block
        _simplify_count[0] += 1
        _t_start = _time.perf_counter()
        try:
            result = orig_simplify_block(self, *args, **kwargs)
        except AssertionError:
            if block is not None:
                if timing_output_enabled() or os.environ.get("INERTIA_DEBUG_CLINIC_COMPLEX_EXPR"):
                    print(
                        "[dbg] clinic:skip-simplify-block-assertion "
                        f"block={getattr(block, 'addr', None)!r}"
                        f"{_project_current_function_context_suffix(project)}",
                        file=sys.stderr,
                    )
                    sys.stderr.flush()
                return block
            raise
        _simplify_total[0] += _time.perf_counter() - _t_start
        if (
            (timing_output_enabled() or os.environ.get("INERTIA_DEBUG_CLINIC_COMPLEX_EXPR"))
            and _simplify_count[0] % 20 == 0
        ):
            print(f"[dbg] stage-time: simplify_block x{_simplify_count[0]} cumulative={_simplify_total[0]:.2f}s (peephole x{_peephole_count[0]} cumulative={_peephole_total[0]:.2f}s)")
            sys.stderr.flush()
        return result

    def _peephole_optimize(self, *args, **kwargs):  # noqa: ANN001
        project._inertia_decompiler_stage = "core:clinic:peephole_optimize"
        _peephole_count[0] += 1
        _t_start = _time.perf_counter()
        try:
            block = args[0] if args else kwargs.get("block")
            if block is not None and getattr(project, "_inertia_tiny_core_disable_peephole", False):
                return block
            if block is not None and getattr(project, "_inertia_fast_block_peephole", False):
                statements, stmts_updated = peephole_optimize_stmts(block, self._stmt_peephole_opts)
                new_block = block.copy(statements=statements) if stmts_updated else block
                statements, multi_stmts_updated = peephole_optimize_multistmts(new_block, self._multistmt_peephole_opts)
                if not multi_stmts_updated:
                    return new_block
                return new_block.copy(statements=statements)
            if block is not None and _block_has_pathologically_complex_expr(block):
                skipped = getattr(project, "_inertia_complex_block_skip_seen", None)
                if not isinstance(skipped, set):
                    skipped = set()
                    setattr(project, "_inertia_complex_block_skip_seen", skipped)
                block_addr = getattr(block, "addr", None)
                if block_addr not in skipped:
                    skipped.add(block_addr)
                    if timing_output_enabled() or os.environ.get("INERTIA_DEBUG_CLINIC_COMPLEX_EXPR"):
                        print(
                            "[dbg] clinic:skip-peephole-complex-block "
                            f"block={block_addr:#x}{_project_current_function_context_suffix(project)}",
                            file=sys.stderr,
                        )
                        sys.stderr.flush()
                statements, stmts_updated = peephole_optimize_stmts(block, self._stmt_peephole_opts)
                new_block = block.copy(statements=statements) if stmts_updated else block
                statements, multi_stmts_updated = peephole_optimize_multistmts(new_block, self._multistmt_peephole_opts)
                if not multi_stmts_updated:
                    return new_block
                return new_block.copy(statements=statements)
            return orig_peephole_optimize(self, *args, **kwargs)
        finally:
            _peephole_total[0] += _time.perf_counter() - _t_start

    Clinic._stage_pre_ssa_level1_simplifications = _stage_pre_ssa_level1_simplifications
    Clinic._stage_transform_to_ssa_level1 = _stage_transform_to_ssa_level1
    Clinic._stage_post_ssa_level1_simplifications = _stage_post_ssa_level1_simplifications
    Clinic._stage_recover_variables = _stage_recover_variables
    Clinic._simplify_block = _simplify_block
    BlockSimplifier._peephole_optimize = _peephole_optimize
    try:
        yield
    finally:
        Clinic._stage_pre_ssa_level1_simplifications = orig_stage_pre_ssa
        Clinic._stage_transform_to_ssa_level1 = orig_stage_ssa_level1
        Clinic._stage_post_ssa_level1_simplifications = orig_stage_post_ssa
        Clinic._stage_recover_variables = orig_stage_recover_vars
        Clinic._simplify_block = orig_simplify_block
        BlockSimplifier._peephole_optimize = orig_peephole_optimize


@contextlib.contextmanager
def guard_angr_fast_post_ssa_8616(project):
    """Skip redundant ``_simplify_function`` calls in angr Clinic for 86_16.

    Clinic calls ``_simplify_function`` seven times across stages.  Calls 4 and 5 (0-indexed)
    are the 3rd and 4th whole-graph simplification rounds inside
    ``_stage_post_ssa_level1_simplifications``, which redundantly redo variable unification
    and expression narrowing that the x86_16 platform handles in its own structuring and
    postprocess passes.  We turn those two calls into no-ops.

    This wrapper is more robust than replacing the entire stage method because it does not
    duplicate angr's internal stage implementation — it only intercepts one leaf method.
    """
    if getattr(getattr(project, "arch", None), "name", None) != "86_16":
        yield
        return

    from angr.analyses.decompiler.clinic import Clinic

    orig_simplify_function = Clinic._simplify_function
    _counter: dict[int, int] = {}  # id(instance) -> call count

    def _fast_simplify_function(self, ail_graph, **kwargs):  # noqa: ANN001
        c = _counter.get(id(self), 0)
        _counter[id(self)] = c + 1
        if getattr(project, "_inertia_tiny_core_aggressive_simplify", False) and c >= 1:
            return
        # Calls 0-2 are earlier stages; calls 3 and 4 are the 3rd and 4th
        # post-SSA whole-graph rounds that 86_16 does not need.
        if c in (3, 4):
            return
        return orig_simplify_function(self, ail_graph, **kwargs)

    Clinic._simplify_function = _fast_simplify_function
    try:
        yield
    finally:
        Clinic._simplify_function = orig_simplify_function


@contextlib.contextmanager
def guard_angr_ail_narrowing(project):
    from angr.analyses.decompiler.ail_simplifier import AILSimplifier

    original_narrow_exprs = AILSimplifier._narrow_exprs

    def _guarded_narrow_exprs(self, *args, **kwargs):  # noqa: ANN001
        if getattr(project, "_inertia_disable_ail_narrowing", False):
            project._inertia_decompiler_stage = "core:clinic:narrowing-skipped"
            return False
        return original_narrow_exprs(self, *args, **kwargs)

    AILSimplifier._narrow_exprs = _guarded_narrow_exprs
    try:
        yield
    finally:
        AILSimplifier._narrow_exprs = original_narrow_exprs


class ThreadBoundTextIO(io.TextIOBase):
    def __init__(self, fallback: EncodedFile) -> None:
        self._fallback = fallback
        self._local = threading.local()

    @contextlib.contextmanager
    def target(self, stream):
        previous = getattr(self._local, "stream", None)
        self._local.stream = stream
        try:
            yield
        finally:
            if previous is None:
                with contextlib.suppress(AttributeError):
                    delattr(self._local, "stream")
            else:
                self._local.stream = previous

    def _stream(self):
        return getattr(self._local, "stream", self._fallback)

    def write(self, data):
        return self._stream().write(data)

    def flush(self):
        try:
            return self._stream().flush()
        except ValueError:
            return None

    def isatty(self):
        target = self._stream()
        return bool(getattr(target, "isatty", lambda: False)())

    @property
    def encoding(self):
        return getattr(self._stream(), "encoding", getattr(self._fallback, "encoding", "utf-8"))

    @property
    def errors(self):
        return getattr(self._stream(), "errors", getattr(self._fallback, "errors", "strict"))

    def __getattr__(self, item):
        return getattr(self._stream(), item)


_THREAD_STDOUT = ThreadBoundTextIO(_REAL_STDOUT)
_THREAD_STDERR = ThreadBoundTextIO(_REAL_STDERR)
sys.stdout = _THREAD_STDOUT
sys.stderr = _THREAD_STDERR


class DaemonThreadPoolExecutor(ThreadPoolExecutor):
    def _adjust_thread_count(self):  # noqa: D401
        if self._idle_semaphore.acquire(timeout=0):
            return

        def weakref_cb(_, q=self._work_queue):
            q.put(None)

        num_threads = len(self._threads)
        if num_threads < self._max_workers:
            thread_name = "%s_%d" % (self._thread_name_prefix or self, num_threads)
            t = threading.Thread(
                name=thread_name,
                target=_worker,
                args=(
                    weakref.ref(self, weakref_cb),
                    self._create_worker_context(),
                    self._work_queue,
                ),
                daemon=True,
            )
            t.start()
            self._threads.add(t)
            _threads_queues[t] = self._work_queue

    def shutdown(self, wait=True, *, cancel_futures=False):  # noqa: D401
        try:
            return super().shutdown(wait=wait, cancel_futures=cancel_futures)
        finally:
            if not wait:
                for thread in list(self._threads):
                    _threads_queues.pop(thread, None)


def log_step(step: str) -> None:
    global LAST_STEP_TIME
    now = time.perf_counter()
    elapsed_total = now - START_TIME
    since_last = now - LAST_STEP_TIME
    LAST_STEP_TIME = now
    timestamp = datetime.utcnow().isoformat()
    print(f"[dbg][{timestamp}] {step} (total {elapsed_total:.2f}s, +{since_last:.2f}s)")
    sys.stdout.flush()


def format_address(addr: int) -> str:
    return f"{addr:#x}"


class JumpkindLoggingHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        msg = record.getMessage()
        if "Unsupported jumpkind" in msg and "address" in msg:
            match = re.search(r"address\s+(0x[0-9a-fA-F]+|[0-9]+)", msg)
            if match and _CURRENT_PROJECT is not None and _FORMAT_FIRST_BLOCK_ASM is not None:
                try:
                    addr = int(match.group(1), 0)
                    asm = _FORMAT_FIRST_BLOCK_ASM(_CURRENT_PROJECT, addr)
                    print(f"[dbg][{datetime.utcnow().isoformat()}] NON-DECODED BLOCK {addr:#x}:\n{asm}")
                except Exception as exc:
                    print(f"[dbg] failed to format assembly for {msg}: {exc}")
            else:
                print(f"[dbg] {msg}")


class AnalysisTimeout(BaseException):
    pass


def raise_timeout(_signum, _frame):
    raise AnalysisTimeout()


@contextlib.contextmanager
def analysis_timeout(timeout: int):
    if timeout <= 0:
        yield
        return
    if threading.current_thread() is not threading.main_thread():
        if _FORK_CHILD_PID != os.getpid():
            yield
            return

    old_handler = signal.signal(signal.SIGALRM, raise_timeout)
    signal.alarm(timeout)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


def run_with_timeout_in_daemon_thread(
    func,
    *,
    timeout: int,
    thread_name_prefix: str,
):
    executor = DaemonThreadPoolExecutor(max_workers=1, thread_name_prefix=thread_name_prefix)
    future = executor.submit(func)
    try:
        return future.result(timeout=max(1, timeout))
    finally:
        finished = future.done()
        executor.shutdown(wait=finished, cancel_futures=not finished)


def run_with_timeout_in_fork(
    func,
    *,
    timeout: int,
) -> object:
    if os.name != "posix" or not hasattr(os, "fork"):
        raise RuntimeError("fork unavailable")
    if threading.current_thread() is not threading.main_thread():
        raise RuntimeError("fork-only supported from main thread")
    if threading.active_count() != 1:
        raise RuntimeError("fork-only supported without extra live threads")

    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        _FORK_CHILD_PID = os.getpid()
        try:
            os.close(read_fd)
            try:
                payload = ("ok", func())
            except BaseException as ex:  # noqa: BLE001
                payload = ("err", type(ex).__name__, str(ex) + "\n" + traceback.format_exc())
            try:
                data = pickle.dumps(payload, protocol=pickle.HIGHEST_PROTOCOL)
            except BaseException as ex:  # noqa: BLE001
                payload = ("err", type(ex).__name__, f"fork result is not pickleable: {ex}")
                data = pickle.dumps(payload, protocol=pickle.HIGHEST_PROTOCOL)
            os.write(write_fd, len(data).to_bytes(8, "little"))
            os.write(write_fd, data)
        finally:
            with contextlib.suppress(OSError):
                os.close(write_fd)
            os._exit(0)

    def _child_exit_detail(p: int, status: int) -> str:
        if os.WIFEXITED(status):
            return f"exitcode={os.WEXITSTATUS(status)}"
        if os.WIFSIGNALED(status):
            sig = os.WTERMSIG(status)
            sig_name = getattr(signal, "Signals", lambda x: f"SIG={x}")(sig) if hasattr(signal, "strsignal") else f"SIG={sig}"
            try:
                sig_name = signal.strsignal(sig)  # type: ignore[attr-defined]
            except Exception:
                sig_name = f"signal={sig}"
            return f"killed_by={sig_name}"
        return f"exit_status_raw={int(status)}"

    os.close(write_fd)
    try:
        ready, _, _ = select.select([read_fd], [], [], max(1, timeout))
        if not ready:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
            _pid, _status = os.waitpid(pid, 0)
            raise TimeoutError(f"Timed out after {timeout}s (child {_child_exit_detail(pid, _status)}).")
        header = b""
        while len(header) < 8:
            chunk = os.read(read_fd, 8 - len(header))
            if not chunk:
                break
            header += chunk
        if len(header) != 8:
            _pid, _status = os.waitpid(pid, 0)
            raise RuntimeError(f"fork child exited without result ({_child_exit_detail(pid, _status)})")
        expected = int.from_bytes(header, "little")
        data = bytearray()
        while len(data) < expected:
            chunk = os.read(read_fd, min(65536, expected - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        _pid, _status = os.waitpid(pid, 0)
        if len(data) != expected:
            raise RuntimeError(f"fork child returned incomplete result (expected={expected}B got={len(data)}B {_child_exit_detail(pid, _status)})")
        payload = pickle.loads(bytes(data))
        if not isinstance(payload, tuple) or not payload:
            raise RuntimeError(f"fork child returned invalid payload ({_child_exit_detail(pid, _status)})")
        if payload[0] == "ok":
            return payload[1]
        if payload[0] == "err":
            if payload[1] in {"TimeoutError", "AnalysisTimeout"}:
                raise TimeoutError(payload[2] or f"Timed out after {timeout}s.")
            raise RuntimeError(f"{payload[1]}: {payload[2]} ({_child_exit_detail(pid, _status)})")
        raise RuntimeError(f"fork child returned unknown status ({_child_exit_detail(pid, _status)})")
    finally:
        with contextlib.suppress(OSError):
            os.close(read_fd)


def _read_framed_pickle(fd: int):
    header = b""
    while len(header) < 8:
        chunk = os.read(fd, 8 - len(header))
        if not chunk:
            return None
        header += chunk
    expected = int.from_bytes(header, "little")
    data = bytearray()
    while len(data) < expected:
        chunk = os.read(fd, min(65536, expected - len(data)))
        if not chunk:
            return None
        data.extend(chunk)
    return pickle.loads(bytes(data))


def _write_framed_pickle(fd: int, payload) -> None:
    data = pickle.dumps(payload, protocol=pickle.HIGHEST_PROTOCOL)
    os.write(fd, len(data).to_bytes(8, "little"))
    os.write(fd, data)


class PreforkJobPool:
    def __init__(self, *, max_workers: int, worker_func: Callable[[object], object], name_prefix: str = "prefork"):
        if os.name != "posix" or not hasattr(os, "fork"):
            raise RuntimeError("prefork unavailable")
        if threading.current_thread() is not threading.main_thread():
            raise RuntimeError("prefork must start on main thread")
        if threading.active_count() != 1:
            raise RuntimeError("prefork requires a single-threaded parent")
        self._worker_func = worker_func
        self._workers: list[dict[str, object]] = []
        self._closed = False
        worker_count = max(1, int(max_workers))
        for index in range(worker_count):
            job_read, job_write = os.pipe()
            result_read, result_write = os.pipe()
            pid = os.fork()
            if pid == 0:
                try:
                    os.close(job_write)
                    os.close(result_read)
                    while True:
                        job = _read_framed_pickle(job_read)
                        if job is None or job == ("shutdown",):
                            break
                        job_id, payload = job
                        try:
                            result = self._worker_func(payload)
                            _write_framed_pickle(result_write, (job_id, "ok", result))
                        except BaseException as ex:  # noqa: BLE001
                            _write_framed_pickle(result_write, (job_id, "err", type(ex).__name__, str(ex)))
                finally:
                    with contextlib.suppress(OSError):
                        os.close(job_read)
                    with contextlib.suppress(OSError):
                        os.close(result_write)
                    os._exit(0)
            os.close(job_read)
            os.close(result_write)
            self._workers.append(
                {
                    "pid": pid,
                    "job_write": job_write,
                    "result_read": result_read,
                    "busy": False,
                    "job_id": None,
                    "name": f"{name_prefix}_{index}",
                }
            )

    def run_unordered(self, jobs: list[tuple[object, object]], *, poll_timeout: float = 0.25):
        pending = deque(jobs)
        remaining = len(jobs)

        def _dispatch_available() -> None:
            for worker in self._workers:
                if not pending:
                    break
                if worker["busy"]:
                    continue
                job_id, payload = pending.popleft()
                _write_framed_pickle(worker["job_write"], (job_id, payload))
                worker["busy"] = True
                worker["job_id"] = job_id

        _dispatch_available()
        while remaining > 0:
            ready_fds = [
                int(worker["result_read"])
                for worker in self._workers
                if worker["busy"]
            ]
            if not ready_fds:
                break
            ready, _, _ = select.select(ready_fds, [], [], poll_timeout)
            if not ready:
                continue
            for fd in ready:
                worker = next(
                    worker for worker in self._workers if int(worker["result_read"]) == fd
                )
                payload = _read_framed_pickle(fd)
                worker["busy"] = False
                worker["job_id"] = None
                remaining -= 1
                if payload is None:
                    yield None, RuntimeError(f"{worker['name']} exited without result")
                elif payload[1] == "ok":
                    yield payload[0], payload[2]
                else:
                    yield payload[0], RuntimeError(f"{payload[2]}: {payload[3]}")
                _dispatch_available()

    def shutdown(self) -> None:
        if self._closed:
            return
        self._closed = True
        for worker in self._workers:
            with contextlib.suppress(Exception):
                _write_framed_pickle(worker["job_write"], ("shutdown",))
        for worker in self._workers:
            with contextlib.suppress(OSError):
                os.close(int(worker["job_write"]))
            with contextlib.suppress(OSError):
                os.close(int(worker["result_read"]))
            with contextlib.suppress(Exception):
                os.waitpid(int(worker["pid"]), 0)


def emit_timeout_and_exit(args_timeout: int, recovery_detail: str | None) -> None:
    if recovery_detail is None:
        print(f"/* Timed out while recovering a function after {args_timeout}s. */")
    else:
        print(f"/* Timed out while recovering a function after {args_timeout}s {recovery_detail}. */")
    print("/* Tip: try a larger --timeout for larger binaries. */")
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(3)


def apply_memory_limit(max_memory_mb: int | None) -> None:
    if max_memory_mb is None or max_memory_mb <= 0:
        return
    limit = max_memory_mb * 1024 * 1024
    try:
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    except (ValueError, OSError):
        pass


def memory_available_mb() -> int | None:
    try:
        meminfo = {}
        with open("/proc/meminfo", "r", encoding="utf-8") as fp:
            for line in fp:
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                parts = value.strip().split()
                if parts:
                    meminfo[key] = int(parts[0])
        available = meminfo.get("MemAvailable")
        if available:
            return available // 1024
    except OSError:
        pass
    return None


def prefer_low_memory_path() -> bool:
    available_mb = memory_available_mb()
    return available_mb is not None and available_mb < 4096


def lower_process_priority() -> None:
    try:
        os.nice(10)
    except (AttributeError, OSError):
        pass


def choose_function_parallelism(function_count: int) -> int:
    if function_count <= 1:
        return 1
    if os.environ.get(FORCE_SERIAL_FUNCTION_DECOMP_ENV, "").strip().lower() in {"1", "true", "yes", "on"}:
        return 1
    if prefer_low_memory_path():
        return 1
    cpu_count = os.cpu_count() or 1
    workers = max(1, cpu_count - 1)
    available_mb = memory_available_mb()
    if available_mb is None:
        return min(workers, function_count)
    budget_mb = int(available_mb * DEFAULT_FREE_RAM_BUDGET_FRACTION)
    if budget_mb < DEFAULT_WORKER_MEMORY_FLOOR_MB:
        return 1
    workers_by_mem = max(1, budget_mb // DEFAULT_WORKER_MEMORY_FLOOR_MB)
    return min(workers, function_count, workers_by_mem)


@contextlib.contextmanager
def guard_angr_structurer_codegen_timing(project):
    """Emit per-stage timing for RecursiveStructurer, RegionSimplifier, and StructuredCodeGenerator."""
    if not timing_output_enabled():
        yield
        return
    import time as _time

    from angr.analyses.decompiler.structuring.recursive_structurer import RecursiveStructurer
    from angr.analyses.decompiler.region_simplifiers.region_simplifier import RegionSimplifier
    from angr.analyses.decompiler.structured_codegen.c import CStructuredCodeGenerator

    orig_rs_init = RecursiveStructurer.__init__
    orig_ri_init = RegionSimplifier.__init__
    orig_codegen_init = CStructuredCodeGenerator.__init__

    def _timed_rs_init(self, *args, **kwargs):  # noqa: ANN001
        _t0 = _time.perf_counter()
        print(f"[dbg] stage-time: structurer:recursive start")
        sys.stderr.flush()
        try:
            return orig_rs_init(self, *args, **kwargs)
        finally:
            _elapsed = _time.perf_counter() - _t0
            print(f"[dbg] stage-time: structurer:recursive done elapsed={_elapsed:.2f}s")
            sys.stderr.flush()

    def _timed_ri_init(self, *args, **kwargs):  # noqa: ANN001
        _t0 = _time.perf_counter()
        print(f"[dbg] stage-time: region_simplifier start")
        sys.stderr.flush()
        try:
            return orig_ri_init(self, *args, **kwargs)
        finally:
            _elapsed = _time.perf_counter() - _t0
            print(f"[dbg] stage-time: region_simplifier done elapsed={_elapsed:.2f}s")
            sys.stderr.flush()

    def _timed_codegen_init(self, *args, **kwargs):  # noqa: ANN001
        _t0 = _time.perf_counter()
        print(f"[dbg] stage-time: codegen:C start")
        sys.stderr.flush()
        try:
            return orig_codegen_init(self, *args, **kwargs)
        finally:
            _elapsed = _time.perf_counter() - _t0
            print(f"[dbg] stage-time: codegen:C done elapsed={_elapsed:.2f}s")
            sys.stderr.flush()

    RecursiveStructurer.__init__ = _timed_rs_init
    RegionSimplifier.__init__ = _timed_ri_init
    CStructuredCodeGenerator.__init__ = _timed_codegen_init
    try:
        yield
    finally:
        RecursiveStructurer.__init__ = orig_rs_init
        RegionSimplifier.__init__ = orig_ri_init
        CStructuredCodeGenerator.__init__ = orig_codegen_init


@contextlib.contextmanager
def guard_angr_tail_validation_collection_timing():
    """Emit timing for the tail validation 'before' collection in _decompile_structuring_8616."""
    if not timing_output_enabled():
        yield
        return
    import time as _time

    from angr_platforms.X86_16.tail_validation import (
        fingerprint_x86_16_tail_validation_boundary,
        collect_x86_16_tail_validation_summary,
    )

    orig_fingerprint = fingerprint_x86_16_tail_validation_boundary
    orig_collect = collect_x86_16_tail_validation_summary

    def _timed_fingerprint(project, codegen, *, mode):  # noqa: ANN001
        _t0 = _time.perf_counter()
        print(f"[dbg] stage-time: tail_validation:fingerprint:before start")
        sys.stderr.flush()
        try:
            return orig_fingerprint(project, codegen, mode=mode)
        finally:
            _elapsed = _time.perf_counter() - _t0
            print(f"[dbg] stage-time: tail_validation:fingerprint:before done elapsed={_elapsed:.2f}s")
            sys.stderr.flush()

    def _timed_collect(project, codegen, *, mode):  # noqa: ANN001
        _t0 = _time.perf_counter()
        print(f"[dbg] stage-time: tail_validation:collect:before start")
        sys.stderr.flush()
        try:
            return orig_collect(project, codegen, mode=mode)
        finally:
            _elapsed = _time.perf_counter() - _t0
            print(f"[dbg] stage-time: tail_validation:collect:before done elapsed={_elapsed:.2f}s")
            sys.stderr.flush()

    # Patch the module that _decompile_structuring_8616 imports from
    import angr_platforms.X86_16.decompiler_structuring_stage as _ds_mod

    _ds_mod.fingerprint_x86_16_tail_validation_boundary = _timed_fingerprint
    _ds_mod.collect_x86_16_tail_validation_summary = _timed_collect
    try:
        yield
    finally:
        _ds_mod.fingerprint_x86_16_tail_validation_boundary = orig_fingerprint
        _ds_mod.collect_x86_16_tail_validation_summary = orig_collect


@contextlib.contextmanager
def guard_angr_structuring_codegen_internal_timing():
    """Emit timing for internal steps of _structuring_codegen_8616 before the pass loop."""
    emit_timing = timing_output_enabled()
    import time as _time
    import angr_platforms.X86_16.decompiler_structuring_stage as _ds_mod
    import angr_platforms.X86_16.pipeline.contracts as _contracts_mod

    orig_alias = _ds_mod._assert_alias_complete_8616
    orig_contracts = _contracts_mod.assert_pipeline_contracts_8616

    def _timed_alias_complete(codegen):  # noqa: ANN001
        _t0 = _time.perf_counter()
        if emit_timing:
            print(f"[dbg] stage-time: x86_16:_assert_alias_complete start")
            sys.stderr.flush()
        try:
            return orig_alias(codegen)
        finally:
            if emit_timing:
                _elapsed = _time.perf_counter() - _t0
                print(f"[dbg] stage-time: x86_16:_assert_alias_complete done elapsed={_elapsed:.2f}s")
                sys.stderr.flush()

    def _timed_contracts(codegen):  # noqa: ANN001
        _t0 = _time.perf_counter()
        if emit_timing:
            print(f"[dbg] stage-time: x86_16:assert_pipeline_contracts start")
            sys.stderr.flush()
        try:
            return orig_contracts(codegen)
        finally:
            if emit_timing:
                _elapsed = _time.perf_counter() - _t0
                print(f"[dbg] stage-time: x86_16:assert_pipeline_contracts done elapsed={_elapsed:.2f}s")
                sys.stderr.flush()

    _ds_mod._assert_alias_complete_8616 = _timed_alias_complete
    _contracts_mod.assert_pipeline_contracts_8616 = _timed_contracts

    # Patch lowering functions at source
    _orig_rml = None
    _orig_slf = None
    _rml_mod = None
    _slf_mod = None
    _sl_mod = None
    _orig_rml_sl = None
    _rml_timed_out = [False]  # mutable cell so _timed_rml closure can write
    try:
        import angr_platforms.X86_16.lowering.real_mode_linear as _rml_mod
        _orig_rml = _rml_mod.lower_stable_ss_linear_stack_dereferences_8616
        _BOUNDED_STAGE_SECONDS = 30
        def _timed_rml(codegen, **kwargs):  # noqa: ANN001
            if _rml_timed_out[0]:
                return False
            _t0 = _time.perf_counter()
            if emit_timing:
                print(f"[dbg] stage-time: x86_16:lower_ss_linear_stack start")
                sys.stderr.flush()
            try:
                with analysis_timeout(int(_BOUNDED_STAGE_SECONDS)):
                    return _orig_rml(codegen, **kwargs)
            except AnalysisTimeout:
                _rml_timed_out[0] = True
                if emit_timing:
                    _elapsed = _time.perf_counter() - _t0
                    print(f"[dbg] stage-time: x86_16:lower_ss_linear_stack TIMEOUT elapsed={_elapsed:.2f}s budget={_BOUNDED_STAGE_SECONDS}s", file=sys.stderr, flush=True)
                return False
            finally:
                if emit_timing:
                    _elapsed = _time.perf_counter() - _t0
                    print(f"[dbg] stage-time: x86_16:lower_ss_linear_stack done elapsed={_elapsed:.2f}s")
                    sys.stderr.flush()
        _rml_mod.lower_stable_ss_linear_stack_dereferences_8616 = _timed_rml
        # Also patch the import-time reference in stack_lowering.py that
        # bypasses the module-level monkey-patch (see issue with
        # "from .real_mode_linear import lower_stable_ss..." at module load).
        import angr_platforms.X86_16.lowering.stack_lowering as _sl_mod
        _orig_rml_sl = _sl_mod.lower_stable_ss_linear_stack_dereferences_8616
        _sl_mod.lower_stable_ss_linear_stack_dereferences_8616 = _timed_rml
    except Exception:
        pass
    try:
        import angr_platforms.X86_16.lowering.stack_lowering_from_facts as _slf_mod
        _orig_slf = _slf_mod.lower_stack_accesses_from_alias_facts_8616
        def _timed_slf(codegen, *args, **kwargs):  # noqa: ANN001
            _t0 = _time.perf_counter()
            if emit_timing:
                print(f"[dbg] stage-time: x86_16:lower_stack_from_facts start")
                sys.stderr.flush()
            try:
                return _orig_slf(codegen, *args, **kwargs)
            finally:
                if emit_timing:
                    _elapsed = _time.perf_counter() - _t0
                    print(f"[dbg] stage-time: x86_16:lower_stack_from_facts done elapsed={_elapsed:.2f}s")
                    sys.stderr.flush()
        _slf_mod.lower_stack_accesses_from_alias_facts_8616 = _timed_slf
    except Exception:
        pass

    try:
        yield
    finally:
        _ds_mod._assert_alias_complete_8616 = orig_alias
        _contracts_mod.assert_pipeline_contracts_8616 = orig_contracts
        # NOTE: lower_stable_ss_linear_stack_dereferences_8616 is KEPT patched
        # with the 30s bounded-stage guard.  Without this, post-decompilation
        # passes (tail_validation snapshots, recompilable storage, etc.) can
        # re-enter unconstrained lower_ss_linear walks that consume the entire
        # remaining fork budget.
        if _orig_slf is not None and _slf_mod is not None:
            _slf_mod.lower_stack_accesses_from_alias_facts_8616 = _orig_slf


def should_force_serial_supplemental_decompilation(function_count: int) -> bool:
    if function_count > 8:
        return False
    if prefer_low_memory_path():
        return True
    available_mb = memory_available_mb()
    if available_mb is None:
        return True
    return available_mb < (DEFAULT_WORKER_MEMORY_FLOOR_MB * 4)


@contextlib.contextmanager
def capture_thread_output():
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    with _THREAD_STDOUT.target(stdout_buf), _THREAD_STDERR.target(stderr_buf):
        yield stdout_buf, stderr_buf


enable_line_buffered_stdio()
