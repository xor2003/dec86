"""Retain request-local decoded x86-16 block evidence.

Layer: Frontend.
Responsibility: reuse exact Capstone block requests, prefer closed direct byte
decoding, and preserve the legacy VEX-backed factory as a fail-closed fallback.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, cast

from .frontend_capstone_decode import decode_bounded_capstone_block_8616


class _InstructionBoundary8616(Protocol):
    """angr wrapper fields for one decoded Capstone instruction."""

    address: int
    mnemonic: str


class _CapstoneBoundary8616(Protocol):
    """Decoded instruction sequence exposed by an angr block."""

    insns: Sequence[_InstructionBoundary8616]


class _BlockBoundary8616(Protocol):
    """angr block fields consumed by the frontend inventory."""

    capstone: _CapstoneBoundary8616


class _FactoryBoundary8616(Protocol):
    """Dynamic angr block factory boundary."""

    def block(
        self,
        addr: int,
        *,
        opt_level: int,
        num_inst: int | None = None,
    ) -> _BlockBoundary8616:
        """Decode one block at ``addr``."""


class _MainObjectBoundary8616(Protocol):
    """Loaded-image upper bound required by direct decoding."""

    max_addr: int


class _LoaderBoundary8616(Protocol):
    """Loaded project image required by direct decoding."""

    main_object: _MainObjectBoundary8616


class _ProjectBoundary8616(Protocol):
    """Dynamic project boundary used by the block inventory."""

    factory: _FactoryBoundary8616
    loader: _LoaderBoundary8616
    _inertia_decoded_block_inventories_8616: dict[
        DecodedBlockRequest8616,
        DecodedBlockEvidence8616,
    ]


@dataclass(frozen=True, slots=True)
class DecodedBlockRequest8616:
    """Exact request identity for one request-local frontend block decode."""

    address: int
    instruction_limit: int | None
    optimization_level: int


class DecodedBlockStatus8616(Enum):
    """Typed outcome of one immutable frontend block decode request."""

    DECODED = "decoded"
    REFUSED = "refused"


@dataclass(frozen=True, slots=True)
class DecodedBlockEvidence8616:
    """Cached instructions or a deterministic decode refusal."""

    request: DecodedBlockRequest8616
    status: DecodedBlockStatus8616
    instructions: tuple[Any, ...]
    block: object | None
    failure_type: type[Exception] | None
    failure_message: str | None


def _raise_cached_decode_failure_8616(evidence: DecodedBlockEvidence8616) -> None:
    """Re-raise a cached refusal without retaining a traceback object."""
    failure_type = evidence.failure_type or RuntimeError
    message = evidence.failure_message or "cached x86-16 block decode refusal"
    try:
        failure = failure_type(message)
    except Exception:
        failure = RuntimeError(f"{failure_type.__name__}: {message}")
    raise failure


def collect_decoded_block_evidence_8616(
    project: object,
    address: int,
    *,
    num_inst: int | None = None,
    opt_level: int = 0,
) -> DecodedBlockEvidence8616:
    """Collect one exact request, using VEX only when direct decode refuses."""
    boundary = cast(_ProjectBoundary8616, project)
    request = DecodedBlockRequest8616(int(address), num_inst, int(opt_level))
    try:
        inventories = boundary._inertia_decoded_block_inventories_8616
    except AttributeError:
        inventories = {}
        boundary._inertia_decoded_block_inventories_8616 = inventories
    cached = inventories.get(request)
    if cached is not None:
        if cached.status is DecodedBlockStatus8616.DECODED:
            return cached
        _raise_cached_decode_failure_8616(cached)

    block: object | None = None
    instructions: tuple[Any, ...] = ()
    if num_inst is None and opt_level == 0:
        try:
            region_end = int(boundary.loader.main_object.max_addr) + 1
        except (AttributeError, TypeError, ValueError):
            region_end = address
        direct = decode_bounded_capstone_block_8616(project, address, region_end)
        if direct.complete and direct.block is not None:
            block = direct.block
            instructions = cast(tuple[Any, ...], direct.block.instructions)
    if block is None:
        try:
            if num_inst is None:
                lifted_block = boundary.factory.block(address, opt_level=opt_level)
            else:
                lifted_block = boundary.factory.block(
                    address,
                    num_inst=num_inst,
                    opt_level=opt_level,
                )
        except Exception as exc:
            inventories[request] = DecodedBlockEvidence8616(
                request=request,
                status=DecodedBlockStatus8616.REFUSED,
                instructions=(),
                block=None,
                failure_type=type(exc),
                failure_message=str(exc),
            )
            raise
        block = lifted_block
        instructions = tuple(lifted_block.capstone.insns)
    evidence = DecodedBlockEvidence8616(
        request=request,
        status=DecodedBlockStatus8616.DECODED,
        instructions=instructions,
        block=block,
        failure_type=None,
        failure_message=None,
    )
    inventories[request] = evidence
    return evidence


def decoded_block_instructions_8616(
    project: object,
    address: int,
    *,
    num_inst: int | None = None,
    opt_level: int = 0,
) -> tuple[Any, ...]:
    """Return instructions from one exact typed frontend decode request."""
    return collect_decoded_block_evidence_8616(
        project,
        address,
        num_inst=num_inst,
        opt_level=opt_level,
    ).instructions


__all__ = [
    "DecodedBlockEvidence8616",
    "DecodedBlockRequest8616",
    "DecodedBlockStatus8616",
    "collect_decoded_block_evidence_8616",
    "decoded_block_instructions_8616",
]
