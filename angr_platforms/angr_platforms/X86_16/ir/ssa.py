"""Build block-local SSA over typed IR values.

Layer: IR.
Responsibility: owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from .core import IRAtom, IRBinaryValue, IRBlock, IRCondition, IRInstr, IRValue, MemSpace

__all__ = ["SSABinding", "SSABlock", "build_x86_16_block_local_ssa"]

_VersionKey = tuple[str, str | None, int]
_TemporarySnapshots = dict[int, IRValue]


@dataclass(frozen=True, slots=True)
class SSABinding:
    """Version assigned to one typed IR value definition inside a block."""

    target: IRValue
    version: int
    instr_index: int

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "target": self.target.to_dict(),
            "version": self.version,
            "instr_index": self.instr_index,
        }


@dataclass(frozen=True, slots=True)
class SSABlock:
    """Block-local SSA view of typed IR instructions and definitions."""

    addr: int
    instrs: tuple[IRInstr, ...]
    bindings: tuple[SSABinding, ...]
    refusals: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "addr": self.addr,
            "instrs": [item.to_dict() for item in self.instrs],
            "bindings": [item.to_dict() for item in self.bindings],
            "refusals": list(self.refusals),
        }


def _version_key(value: IRValue) -> _VersionKey:
    return (value.space.value, value.name, value.offset)


def _versioned(value: IRValue, version: int) -> IRValue:
    """Assign one SSA version without dropping value provenance."""
    return replace(value, version=version)


def _rewrite_binary_value(
    value: IRBinaryValue,
    versions: dict[_VersionKey, int],
    snapshots: _TemporarySnapshots,
) -> IRBinaryValue:
    """Rewrite both operands of one typed binary value into current SSA versions."""
    return replace(
        value,
        lhs=_rewrite_value_expression(value.lhs, versions, snapshots),
        rhs=_rewrite_value_expression(value.rhs, versions, snapshots),
    )


def _rewrite_value_expression(
    value: IRValue | IRBinaryValue,
    versions: dict[_VersionKey, int],
    snapshots: _TemporarySnapshots,
) -> IRValue | IRBinaryValue:
    """Rewrite a scalar or nested typed value expression into current SSA versions."""
    if isinstance(value, IRBinaryValue):
        return _rewrite_binary_value(value, versions, snapshots)
    return _rewrite_value(value, versions, snapshots)


def _rewrite_value(
    value: IRValue,
    versions: dict[_VersionKey, int],
    snapshots: _TemporarySnapshots,
) -> IRValue:
    """Rewrite one value and its indexed-address provenance into current SSA versions."""
    if value.space in {MemSpace.CONST, MemSpace.UNKNOWN}:
        return value
    key = _version_key(value)
    snapshot = None if value.source_tmp is None else snapshots.get(value.source_tmp)
    if (
        snapshot is not None
        and snapshot.version is not None
        and snapshot.size == value.size
        and _version_key(snapshot) == key
    ):
        version = snapshot.version
    else:
        version = versions.setdefault(key, 0)
    rewritten_index = (
        None
        if value.index is None
        else _rewrite_value_expression(value.index, versions, snapshots)
    )
    return replace(_versioned(value, version), index=rewritten_index)


def _rewrite_atom(
    atom: IRAtom,
    versions: dict[_VersionKey, int],
    snapshots: _TemporarySnapshots,
) -> IRAtom:
    """Rewrite every value-bearing IR atom without losing typed metadata."""
    if isinstance(atom, IRCondition):
        return IRCondition(
            op=atom.op,
            args=tuple(_rewrite_atom(arg, versions, snapshots) for arg in atom.args),
            expr=atom.expr,
            width_bits=atom.width_bits,
        )
    if isinstance(atom, IRBinaryValue):
        return _rewrite_binary_value(atom, versions, snapshots)
    if isinstance(atom, IRValue):
        return _rewrite_value(atom, versions, snapshots)
    return atom


def _record_temporary_snapshot(
    instruction: IRInstr,
    destination: IRValue | None,
    arguments: tuple[IRAtom, ...],
    snapshots: _TemporarySnapshots,
) -> None:
    """Record the exact scalar version captured by one VEX temporary MOV."""
    if (
        instruction.op == "MOV"
        and destination is not None
        and destination.space is MemSpace.TMP
        and destination.source_tmp is not None
        and len(arguments) == 1
        and isinstance(arguments[0], IRValue)
    ):
        snapshots[destination.source_tmp] = arguments[0]


def build_x86_16_block_local_ssa(block: IRBlock) -> SSABlock:
    """Rewrite a typed IR block into deterministic block-local SSA form."""
    versions: dict[_VersionKey, int] = {}
    snapshots: _TemporarySnapshots = {}
    rewritten: list[IRInstr] = []
    bindings: list[SSABinding] = []
    for index, instr in enumerate(block.instrs):
        rewritten_args: list[IRAtom] = []
        for arg in instr.args:
            rewritten_args.append(_rewrite_atom(arg, versions, snapshots))
        rewritten_dst = instr.dst
        if rewritten_dst is not None and rewritten_dst.space not in {MemSpace.CONST, MemSpace.UNKNOWN}:
            key = _version_key(rewritten_dst)
            version = versions.get(key, -1) + 1
            versions[key] = version
            rewritten_dst = _versioned(rewritten_dst, version)
            bindings.append(SSABinding(target=rewritten_dst, version=version, instr_index=index))
        rewritten_args_tuple = tuple(rewritten_args)
        _record_temporary_snapshot(instr, rewritten_dst, rewritten_args_tuple, snapshots)
        rewritten.append(
            IRInstr(
                op=instr.op,
                dst=rewritten_dst,
                args=rewritten_args_tuple,
                size=instr.size,
                addr=instr.addr,
                call_stack_effect=instr.call_stack_effect,
            )
        )
    return SSABlock(addr=block.addr, instrs=tuple(rewritten), bindings=tuple(bindings))
