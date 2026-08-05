"""Regression tests for identity-safe protected structured call arguments."""

from angr_platforms.X86_16.lowering.call_argument_state import (
    ProtectedCallArgument8616,
    ProtectedCallArgumentStore8616,
)


def test_protected_call_argument_store_refuses_reused_object_id_entry() -> None:
    """A stale entry must not attach to a different regenerated call object."""
    stale_call = object()
    live_call = object()
    stale_expression = object()
    live_expression = object()
    key = (id(live_call), 0)
    store = ProtectedCallArgumentStore8616(
        entries={key: ProtectedCallArgument8616(stale_call, stale_expression, 10)}
    )

    assert store.get(live_call, 0) is None

    store.remember(live_call, 0, live_expression, 1)

    entry = store.get(live_call, 0)
    assert entry is not None
    assert entry.expression is live_expression
