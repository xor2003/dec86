"""Build semantic AIL values for multi-register returns.

Layer: Structuring.
Responsibility: combine proven return-register sources without losing either
word and fold exact constants before C code generation.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Callable

from angr import ailment
from angr.ailment.expression import Expression


def combine_word_return_sources_8616(
    high_word: Expression,
    low_word: Expression,
    *,
    next_atom: Callable[[], int],
    ins_addr: int | None,
) -> Expression:
    """Combine high:low AIL words, folding a fully proven constant pair."""
    if isinstance(high_word, ailment.Expr.Const) and isinstance(low_word, ailment.Expr.Const):
        value = ((int(high_word.value) & 0xFFFF) << 16) | (int(low_word.value) & 0xFFFF)
        if value & 0x80000000:
            value -= 0x100000000
        return ailment.Expr.Const(next_atom(), None, value, 32, ins_addr=ins_addr)
    return ailment.Expr.BinaryOp(
        next_atom(),
        "Concat",
        [high_word, low_word],
        bits=32,
        ins_addr=ins_addr,
    )
