from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

__all__ = [
    "FunctionEffectSummary",
    "summarize_x86_16_function_effects",
]


@dataclass(frozen=True, slots=True)
class FunctionEffectSummary:
    register_inputs: tuple[str, ...] = ()
    register_outputs: tuple[str, ...] = ()
    register_clobbers: tuple[str, ...] = ()
    frame_stack_reads: tuple[int, ...] = ()
    frame_stack_writes: tuple[int, ...] = ()
    memory_reads: tuple[str, ...] = ()
    memory_writes: tuple[str, ...] = ()
    direct_call_count: int = 0
    indirect_call_count: int = 0
    direct_branch_count: int = 0
    indirect_branch_count: int = 0
    return_kind: str = "unknown"

    def frame_only_stack(self) -> bool:
        return bool(self.frame_stack_reads or self.frame_stack_writes) and not (
            self.memory_reads or self.memory_writes
        )

    def has_indirect_control(self) -> bool:
        return self.indirect_call_count > 0 or self.indirect_branch_count > 0

    def brief(self) -> str:
        return (
            f"regs_in={len(self.register_inputs)} "
            f"regs_out={len(self.register_outputs)} "
            f"regs_clobber={len(self.register_clobbers)} "
            f"frame_reads={len(self.frame_stack_reads)} "
            f"frame_writes={len(self.frame_stack_writes)} "
            f"direct_calls={self.direct_call_count} "
            f"indirect_calls={self.indirect_call_count} "
            f"direct_branches={self.direct_branch_count} "
            f"indirect_branches={self.indirect_branch_count} "
            f"return={self.return_kind}"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "register_inputs": list(self.register_inputs),
            "register_outputs": list(self.register_outputs),
            "register_clobbers": list(self.register_clobbers),
            "frame_stack_reads": list(self.frame_stack_reads),
            "frame_stack_writes": list(self.frame_stack_writes),
            "memory_reads": list(self.memory_reads),
            "memory_writes": list(self.memory_writes),
            "direct_call_count": self.direct_call_count,
            "indirect_call_count": self.indirect_call_count,
            "direct_branch_count": self.direct_branch_count,
            "indirect_branch_count": self.indirect_branch_count,
            "return_kind": self.return_kind,
            "frame_only_stack": self.frame_only_stack(),
        }


def _value(source: Any, name: str, default: Any) -> Any:
    if isinstance(source, Mapping):
        return source.get(name, default)
    return getattr(source, name, default)


def _sorted_str_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list, set)):
        return ()
    return tuple(sorted(str(item) for item in value))


def _sorted_int_tuple(value: Any) -> tuple[int, ...]:
    if not isinstance(value, (tuple, list, set)):
        return ()
    ints = [item for item in value if isinstance(item, int)]
    return tuple(sorted(ints))


def _count(source: Any, name: str) -> int:
    value = _value(source, name, 0)
    if value is None:
        return 0
    return int(value)


def summarize_x86_16_function_effects(source: Any) -> FunctionEffectSummary:
    return FunctionEffectSummary(
        register_inputs=_sorted_str_tuple(_value(source, "register_inputs", ())),
        register_outputs=_sorted_str_tuple(_value(source, "register_outputs", ())),
        register_clobbers=_sorted_str_tuple(_value(source, "register_clobbers", ())),
        frame_stack_reads=_sorted_int_tuple(_value(source, "frame_stack_reads", ())),
        frame_stack_writes=_sorted_int_tuple(_value(source, "frame_stack_writes", ())),
        memory_reads=_sorted_str_tuple(_value(source, "memory_reads", ())),
        memory_writes=_sorted_str_tuple(_value(source, "memory_writes", ())),
        direct_call_count=_count(source, "direct_call_count"),
        indirect_call_count=_count(source, "indirect_call_count"),
        direct_branch_count=_count(source, "direct_branch_count"),
        indirect_branch_count=_count(source, "indirect_branch_count"),
        return_kind=str(_value(source, "return_kind", "unknown")),
    )
