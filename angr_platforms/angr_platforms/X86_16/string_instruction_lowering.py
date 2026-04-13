from __future__ import annotations

from dataclasses import dataclass

from .string_instruction_artifact import StringInstructionArtifact, StringInstructionRecord

__all__ = [
    "StringIntrinsicArtifact",
    "StringIntrinsicRecord",
    "StringIntrinsicRefusal",
    "apply_x86_16_string_instruction_lowering",
    "build_x86_16_string_intrinsic_artifact",
    "render_x86_16_string_intrinsic_c",
]


@dataclass(frozen=True, slots=True)
class StringIntrinsicRecord:
    index: int
    family: str
    record_indexes: tuple[int, ...]
    width: int
    direction_mode: str
    repeat_kind: str


@dataclass(frozen=True, slots=True)
class StringIntrinsicRefusal:
    kind: str
    detail: str
    record_indexes: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class StringIntrinsicArtifact:
    records: tuple[StringIntrinsicRecord, ...] = ()
    refusals: tuple[StringIntrinsicRefusal, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "records": [
                {
                    "index": rec.index,
                    "family": rec.family,
                    "record_indexes": list(rec.record_indexes),
                    "width": rec.width,
                    "direction_mode": rec.direction_mode,
                    "repeat_kind": rec.repeat_kind,
                }
                for rec in self.records
            ],
            "refusals": [
                {
                    "kind": item.kind,
                    "detail": item.detail,
                    "record_indexes": list(item.record_indexes),
                }
                for item in self.refusals
            ],
        }


def _single_record_family(record: StringInstructionRecord) -> str | None:
    if record.family == "movs" and record.repeat_kind != "none":
        return "memmove_class" if record.direction_mode == "backward" else "memcpy_class"
    if record.family == "stos" and record.repeat_kind != "none":
        return "memset_class"
    if (
        record.family == "scas"
        and record.repeat_kind == "repnz"
        and record.width == 1
        and bool(record.zero_seeded_accumulator)
    ):
        return "strlen_class"
    if record.family == "cmps" and record.repeat_kind == "repz":
        return "memcmp_class"
    return None


def build_x86_16_string_intrinsic_artifact(artifact: StringInstructionArtifact) -> StringIntrinsicArtifact:
    if artifact.refusals:
        return StringIntrinsicArtifact(
            refusals=tuple(
                StringIntrinsicRefusal(item.kind, item.detail) for item in artifact.refusals
            )
        )
    if not artifact.records:
        return StringIntrinsicArtifact(
            refusals=(StringIntrinsicRefusal("no_string_artifact", "no string instruction artifact available"),)
        )

    records = artifact.records
    if len(records) == 2:
        first_family = _single_record_family(records[0])
        second_family = _single_record_family(records[1])
        if (
            first_family == "strlen_class"
            and second_family in {"memcpy_class", "memmove_class"}
            and records[1].width == 1
        ):
            return StringIntrinsicArtifact(
                records=(
                    StringIntrinsicRecord(
                        index=0,
                        family="strlen_copy_class",
                        record_indexes=(records[0].index, records[1].index),
                        width=1,
                        direction_mode=records[1].direction_mode,
                        repeat_kind=records[1].repeat_kind,
                    ),
                )
            )

    lowered_records: list[StringIntrinsicRecord] = []
    refusals: list[StringIntrinsicRefusal] = []
    for rec in records:
        family = _single_record_family(rec)
        if family is None:
            refusals.append(
                StringIntrinsicRefusal(
                    "unsupported_string_family",
                    f"no proven generic lowering for {rec.repeat_kind} {rec.mnemonic}",
                    (rec.index,),
                )
            )
            continue
        lowered_records.append(
            StringIntrinsicRecord(
                index=len(lowered_records),
                family=family,
                record_indexes=(rec.index,),
                width=rec.width,
                direction_mode=rec.direction_mode,
                repeat_kind=rec.repeat_kind,
            )
        )
    if not lowered_records and not refusals:
        refusals.append(StringIntrinsicRefusal("no_lowering_signal", "string artifact produced no generic lowering"))
    return StringIntrinsicArtifact(records=tuple(lowered_records), refusals=tuple(refusals))


def _render_header() -> str:
    return (
        "typedef struct {\n"
        "    unsigned short cx;\n"
        "    unsigned short si;\n"
        "    unsigned short di;\n"
        "    unsigned short ax;\n"
        "    unsigned short ds;\n"
        "    unsigned short es;\n"
        "    unsigned char direction;\n"
        "} __x86_16_string_state;\n\n"
        "void __x86_16_movs(__x86_16_string_state *state, unsigned short width);\n"
        "void __x86_16_stos(__x86_16_string_state *state, unsigned short width);\n"
        "unsigned short __x86_16_scas_zterm_len(__x86_16_string_state *state, unsigned short width);\n"
        "int __x86_16_cmps(__x86_16_string_state *state, unsigned short width);\n\n"
    )


def render_x86_16_string_intrinsic_c(name: str, artifact: StringIntrinsicArtifact) -> str | None:
    if not artifact.records:
        return None

    lines = [_render_header(), f"void {name}(void)\n{{", "    __x86_16_string_state __x86_16_state;"]
    declared_length = False
    declared_compare = False
    for rec in artifact.records:
        if rec.family in {"memcpy_class", "memmove_class"}:
            lines.append(f"    /* {rec.family}, width={rec.width}, direction={rec.direction_mode} */")
            lines.append(f"    __x86_16_movs(&__x86_16_state, {rec.width});")
            continue
        if rec.family == "memset_class":
            lines.append(f"    /* memset_class, width={rec.width}, direction={rec.direction_mode} */")
            lines.append(f"    __x86_16_stos(&__x86_16_state, {rec.width});")
            continue
        if rec.family == "strlen_class":
            if not declared_length:
                lines.append("    unsigned short __x86_16_length;")
                declared_length = True
            lines.append("    /* strlen_class */")
            lines.append(f"    __x86_16_length = __x86_16_scas_zterm_len(&__x86_16_state, {rec.width});")
            continue
        if rec.family == "memcmp_class":
            if not declared_compare:
                lines.append("    int __x86_16_compare;")
                declared_compare = True
            lines.append(f"    /* memcmp_class, width={rec.width} */")
            lines.append(f"    __x86_16_compare = __x86_16_cmps(&__x86_16_state, {rec.width});")
            continue
        if rec.family == "strlen_copy_class":
            if not declared_length:
                lines.append("    unsigned short __x86_16_length;")
                declared_length = True
            lines.append("    /* strlen_copy_class */")
            lines.append("    __x86_16_length = __x86_16_scas_zterm_len(&__x86_16_state, 1);")
            lines.append("    __x86_16_state.cx = (unsigned short)(__x86_16_length + 1);")
            lines.append("    __x86_16_movs(&__x86_16_state, 1);")
            continue
    lines.append("}")
    return "\n".join(lines) + "\n"


def apply_x86_16_string_instruction_lowering(project, codegen) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    func_addr = getattr(cfunc, "addr", None)
    if not isinstance(func_addr, int):
        return False
    function = project.kb.functions.function(addr=func_addr, create=False)
    if function is None:
        return False
    string_artifact = getattr(codegen, "_inertia_string_instruction_artifact", None)
    if not isinstance(string_artifact, StringInstructionArtifact):
        return False
    intrinsic_artifact = build_x86_16_string_intrinsic_artifact(string_artifact)
    setattr(codegen, "_inertia_string_intrinsic_artifact", intrinsic_artifact)
    info = getattr(function, "info", None)
    if isinstance(info, dict):
        info["x86_16_string_intrinsic_artifact"] = intrinsic_artifact.to_dict()
    return False
