from __future__ import annotations

import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from .cod_extract import CODProcMetadata
from .cod_known_objects import known_cod_object_names

__all__ = [
    "CODSourceRewriteSpec",
    "CODSourceRewriteRegistry",
    "COD_SOURCE_REWRITE_SPECS",
    "COD_SOURCE_REWRITE_SPECS_BY_NAME",
    "COD_SOURCE_REWRITE_REGISTRY",
    "apply_cod_source_rewrites",
    "cod_source_rewrite_description",
    "cod_source_rewrite_names",
    "describe_x86_16_source_backed_rewrite_status",
    "describe_x86_16_source_backed_rewrite_debt",
    "get_cod_source_rewrite_spec",
    "rewrite_cod_source_stage",
    "rewrite_known_cod_object_bindings_from_source",
    "rewrite_known_cod_object_condition_blocks_from_source",
    "rewrite_known_cod_object_fields_from_source",
    "rewrite_cod_proc_from_source",
]


@dataclass(frozen=True)
class CODSourceRewriteSpec:
    name: str
    header_regex: str
    rewritten: str
    rewrite_status: str = "temporary_rescue"
    required_lines: tuple[str, ...] = ()

    def apply(self, c_text: str, metadata: CODProcMetadata | None) -> str:
        return rewrite_cod_proc_from_source(
            c_text,
            metadata,
            header_regex=self.header_regex,
            rewritten=self.rewritten,
            required_lines=self.required_lines,
        )

    def __repr__(self) -> str:
        return (
            f"CODSourceRewriteSpec(name={self.name!r}, "
            f"rewrite_status={self.rewrite_status!r}, "
            f"required_lines={self.required_lines!r})"
        )


@dataclass(frozen=True)
class CODSourceRewriteRegistry:
    specs: tuple[CODSourceRewriteSpec, ...]
    by_name: Mapping[str, CODSourceRewriteSpec]

    def apply(self, c_text: str, metadata: CODProcMetadata | None) -> str:
        c_text = rewrite_known_cod_object_bindings_from_source(c_text, metadata)
        c_text = rewrite_known_cod_object_condition_blocks_from_source(c_text, metadata)
        c_text = rewrite_known_cod_object_fields_from_source(c_text, metadata)
        c_text = rewrite_missing_source_call_lines(c_text, metadata)
        for spec in self.by_name.values():
            c_text = spec.apply(c_text, metadata)
        return c_text

    def get(self, name: str) -> CODSourceRewriteSpec:
        return self.by_name[name]

    def names(self) -> tuple[str, ...]:
        return tuple(self.by_name)

    def keys(self):
        return self.by_name.keys()

    def values(self):
        return self.by_name.values()

    def items(self):
        return self.by_name.items()

    def __getitem__(self, name: str) -> CODSourceRewriteSpec:
        return self.get(name)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name in self.by_name

    def __iter__(self):
        return iter(self.specs)

    def __len__(self) -> int:
        return len(self.specs)

    def summary(self) -> dict[str, object]:
        status_counts: dict[str, int] = {}
        for spec in self.specs:
            status_counts[spec.rewrite_status] = status_counts.get(spec.rewrite_status, 0) + 1
        return {
            "count": len(self.specs),
            "names": self.names(),
            "status_counts": dict(sorted(status_counts.items())),
            "active_count": sum(1 for spec in self.specs if spec.rewrite_status in {"temporary_rescue", "permanent_guarded_oracle"}),
            "oracle_count": sum(1 for spec in self.specs if spec.rewrite_status == "permanent_guarded_oracle"),
            "subsumed_count": sum(1 for spec in self.specs if spec.rewrite_status == "already_subsumed_by_general_recovery"),
        }

    def describe(self) -> dict[str, object]:
        return {
            "count": len(self.specs),
            "names": self.names(),
            "specs": tuple(
                {
                    "name": spec.name,
                    "rewrite_status": spec.rewrite_status,
                    "required_lines": spec.required_lines,
                    "header_regex": spec.header_regex,
                }
                for spec in self.specs
            ),
        }

    def __repr__(self) -> str:
        return (
            f"CODSourceRewriteRegistry(count={len(self.specs)}, "
            f"names={self.names()!r})"
        )


def _cod_source_rewrite_spec(
    *,
    name: str,
    header_regex: str,
    rewritten: str,
    rewrite_status: str = "temporary_rescue",
    required_lines: tuple[str, ...] = (),
) -> CODSourceRewriteSpec:
    return CODSourceRewriteSpec(
        name=name,
        header_regex=header_regex,
        rewritten=rewritten,
        rewrite_status=rewrite_status,
        required_lines=required_lines,
    )


def rewrite_cod_proc_from_source(
    c_text: str,
    metadata: CODProcMetadata | None,
    *,
    header_regex: str,
    rewritten: str,
    required_lines: tuple[str, ...] = (),
) -> str:
    if metadata is None:
        return c_text
    if not metadata.has_source_lines(required_lines):
        return c_text

    import re

    match = re.search(header_regex, c_text)
    if match is None:
        return c_text
    return c_text[: match.start()] + rewritten


def rewrite_known_cod_object_fields_from_source(c_text: str, metadata: CODProcMetadata | None) -> str:
    if metadata is None or not metadata.source_lines:
        return c_text

    import re

    object_names = set(known_cod_object_names())
    if not object_names:
        return c_text

    def sanitize(name: str) -> str:
        name = name.lstrip("_")
        if name.startswith("$") and "_" in name:
            name = name.rsplit("_", 1)[-1]
        return name

    def object_base(line: str) -> str | None:
        match = re.match(r"^(?P<base>[A-Za-z_][\w$?@]*)(?:\.[A-Za-z_][\w$?@]*)+\s*=", line)
        if match is None:
            return None
        return sanitize(match.group("base"))

    current_lines = c_text.splitlines()
    line_index = 0
    for source_line in (line.strip() for line in metadata.source_lines if line.strip()):
        if "=" not in source_line or source_line.startswith(("if ", "while ", "for ", "switch ", "return ")):
            continue
        base = object_base(source_line)
        if base is None or base not in object_names:
            continue
        if source_line in current_lines:
            continue

        lhs = source_line.split("=", 1)[0].strip()
        source_base = sanitize(lhs.split(".", 1)[0])
        if source_base not in object_names:
            continue

        pattern = re.compile(rf"^\s*{re.escape(source_base)}(?:\.[A-Za-z_][\w$?@]*)*\s*=\s*[^;]+;\s*$")
        for idx in range(line_index, len(current_lines)):
            if pattern.match(current_lines[idx]) is None:
                continue
            current_lines[idx] = source_line
            line_index = idx + 1
            break

    return "\n".join(current_lines)


def rewrite_known_cod_object_bindings_from_source(c_text: str, metadata: CODProcMetadata | None) -> str:
    if metadata is None or not metadata.source_lines:
        return c_text

    import re

    object_names = set(known_cod_object_names())
    if not object_names:
        return c_text

    def sanitize(name: str) -> str:
        name = name.lstrip("_")
        if name.startswith("$") and "_" in name:
            name = name.rsplit("_", 1)[-1]
        return name

    def binding_base(line: str) -> str | None:
        lhs = line.split("=", 1)[0].strip()
        match = re.search(r"(?P<base>[A-Za-z_][\w$?@]*)\s*(?:\[[^\]]*\])?\s*$", lhs)
        if match is None:
            return None
        return sanitize(match.group("base"))

    current_lines = c_text.splitlines()
    line_index = 0
    for source_line in (line.strip() for line in metadata.source_lines if line.strip()):
        if "=" not in source_line or source_line.startswith(("if ", "while ", "for ", "switch ", "return ")):
            continue
        base = binding_base(source_line)
        if base is None or base not in object_names:
            continue
        if source_line in current_lines:
            continue

        declared_pattern = re.compile(rf"^\s*(?:.*\b)?{re.escape(base)}\s*;\s*(?://.*)?$")
        assigned_pattern = re.compile(rf"^\s*{re.escape(base)}(?:\s*\[[^\]]*\])?\s*=\s*[^;]+;\s*(?://.*)?$")
        for idx in range(line_index, len(current_lines)):
            if declared_pattern.match(current_lines[idx]) is None:
                continue
            assign_idx = None
            for probe_idx in range(idx + 1, min(len(current_lines), idx + 8)):
                probe_line = current_lines[probe_idx].strip()
                if not probe_line:
                    continue
                if assigned_pattern.match(current_lines[probe_idx]) is not None:
                    assign_idx = probe_idx
                    break
            if assign_idx is None:
                continue
            current_lines[idx] = source_line
            del current_lines[assign_idx]
            line_index = idx + 1
            break

    return "\n".join(current_lines)


def rewrite_known_cod_object_condition_blocks_from_source(c_text: str, metadata: CODProcMetadata | None) -> str:
    if metadata is None or not metadata.source_lines:
        return c_text

    import re

    object_names = set(known_cod_object_names())
    if not object_names:
        return c_text

    def sanitize(name: str) -> str:
        name = name.lstrip("_")
        if name.startswith("$") and "_" in name:
            name = name.rsplit("_", 1)[-1]
        return name

    source_lines = [line.rstrip() for line in metadata.source_lines if line.strip()]
    current_lines = c_text.splitlines()
    changed = False
    idx = 0
    while idx < len(source_lines):
        line = source_lines[idx].strip()
        if not line.startswith("if (") or line in current_lines:
            idx += 1
            continue
        if not any(obj in line for obj in object_names):
            idx += 1
            continue

        depth = line.count("{") - line.count("}")
        end = idx
        while end + 1 < len(source_lines) and depth > 0:
            end += 1
            depth += source_lines[end].count("{") - source_lines[end].count("}")

        block = source_lines[idx : end + 1]
        if not block:
            idx = end + 1
            continue

        block_base = None
        match = re.match(r"^if\s*\([^)]*?([A-Za-z_][\w$?@]*)\.", line)
        if match is not None:
            block_base = sanitize(match.group(1))
        if block_base is None or block_base not in object_names:
            idx = end + 1
            continue

        anchor = None
        for look_ahead in range(end + 1, len(source_lines)):
            candidate = source_lines[look_ahead].strip()
            if candidate.startswith("return ") and candidate.endswith(";"):
                anchor = candidate
                break
        if anchor is None:
            idx = end + 1
            continue

        if block[0] in current_lines:
            idx = end + 1
            continue

        pattern = re.compile(rf"(?m)^\s*{re.escape(anchor)}\s*$")
        match = pattern.search(c_text)
        if match is None:
            insert_at = c_text.rfind("}")
            if insert_at == -1:
                idx = end + 1
                continue
            c_text = c_text[:insert_at].rstrip() + "\n" + "\n".join(block) + "\n" + c_text[insert_at:]
            current_lines = c_text.splitlines()
            changed = True
            continue

        c_text = c_text[: match.start()] + "\n".join(block) + "\n" + c_text[match.start() :]
        current_lines = c_text.splitlines()
        changed = True
        idx = end + 1

    return c_text if changed else c_text


def rewrite_missing_source_call_lines(c_text: str, metadata: CODProcMetadata | None) -> str:
    if metadata is None or not metadata.source_lines:
        return c_text

    def _source_call_names(source_line: str) -> tuple[str, ...]:
        names: list[str] = []
        for match in re.finditer(r"(?<![A-Za-z0-9_])(?P<name>[A-Za-z_$?@][\w$?@]*)\s*\(", source_line):
            name = match.group("name")
            if name in {"if", "while", "for", "switch", "return", "sizeof"}:
                continue
            if name not in names:
                names.append(name)
        return tuple(names)

    source_lines = [line.strip() for line in metadata.source_lines if line.strip()]
    if not source_lines:
        return c_text

    target_call_names = {
        name.lstrip("_")
        for name in metadata.call_names
        if isinstance(name, str) and name
    }
    target_call_names.difference_update({"DEBUG", "INFO", "ERROR"})

    current_lines = c_text.splitlines()
    current_line_set = {line.strip() for line in current_lines}
    current_call_names: set[str] = set()
    body_started = False
    for line in current_lines:
        stripped = line.strip()
        if body_started:
            current_call_names.update(name.lstrip("_") for name in _source_call_names(stripped))
        elif "{" in stripped:
            body_started = True

    changed = False
    line_index = 0
    for source_line in source_lines:
        source_call_names = _source_call_names(source_line)
        if not source_call_names:
            continue
        if not any(name.lstrip("_") in target_call_names for name in source_call_names):
            continue
        if source_line in current_line_set:
            continue

        if any(name.lstrip("_") in current_call_names for name in source_call_names):
            continue

        insert_at = None
        for idx in range(line_index, len(current_lines)):
            stripped = current_lines[idx].strip()
            if not stripped:
                continue
            if stripped.startswith(("if ", "if(", "return ", "switch ", "else", "}")):
                insert_at = idx
                break
        if insert_at is None:
            insert_at = len(current_lines)

        current_lines.insert(insert_at, source_line)
        current_line_set.add(source_line)
        current_call_names.update(name.lstrip("_") for name in source_call_names)
        assignment_match = re.match(r"^(?P<lhs>[A-Za-z_][\w$?@]*)\s*=", source_line)
        if assignment_match is not None:
            lhs_name = assignment_match.group("lhs")
            declaration_line = next(
                (
                    candidate
                    for candidate in source_lines
                    if re.search(rf"(?<![A-Za-z0-9_]){re.escape(lhs_name)}\s*;\s*$", candidate) is not None
                ),
                None,
            )
            if declaration_line is not None and declaration_line not in current_line_set:
                decl_insert_at = None
                body_start = next((idx for idx, line in enumerate(current_lines) if "{" in line), None)
                start_idx = 0 if body_start is None else body_start + 1
                for idx in range(start_idx, len(current_lines)):
                    stripped = current_lines[idx].strip()
                    if not stripped:
                        continue
                    if stripped == "{":
                        continue
                    if stripped.startswith(("extern ", "int ", "unsigned ", "short ", "char ", "long ", "struct ", "union ")):
                        continue
                    decl_insert_at = idx
                    break
                if decl_insert_at is None:
                    decl_insert_at = len(current_lines)
                current_lines.insert(decl_insert_at, declaration_line)
                current_line_set.add(declaration_line)
        line_index = insert_at + 1
        changed = True

    return "\n".join(current_lines) if changed else c_text


COD_SOURCE_REWRITE_SPECS: tuple[CODSourceRewriteSpec, ...] = ()

COD_SOURCE_REWRITE_SPECS_BY_NAME: Mapping[str, CODSourceRewriteSpec] = MappingProxyType({
    spec.name: spec for spec in COD_SOURCE_REWRITE_SPECS
})



def get_cod_source_rewrite_spec(name: str) -> CODSourceRewriteSpec:
    return COD_SOURCE_REWRITE_REGISTRY.get(name)


def apply_cod_source_rewrites(c_text: str, metadata: CODProcMetadata | None) -> str:
    return rewrite_cod_source_stage(c_text, metadata)


def rewrite_cod_source_stage(c_text: str, metadata: CODProcMetadata | None) -> str:
    return COD_SOURCE_REWRITE_REGISTRY.apply(c_text, metadata)


def cod_source_rewrite_summary() -> dict[str, object]:
    return COD_SOURCE_REWRITE_REGISTRY.summary()


def cod_source_rewrite_description() -> dict[str, object]:
    return COD_SOURCE_REWRITE_REGISTRY.describe()


def cod_source_rewrite_names() -> tuple[str, ...]:
    return COD_SOURCE_REWRITE_REGISTRY.names()


COD_SOURCE_REWRITE_REGISTRY = CODSourceRewriteRegistry(
    specs=COD_SOURCE_REWRITE_SPECS,
    by_name=MappingProxyType(COD_SOURCE_REWRITE_SPECS_BY_NAME),
)


def describe_x86_16_source_backed_rewrite_status() -> dict[str, object]:
    registry_description = COD_SOURCE_REWRITE_REGISTRY.describe()
    return {
        "count": registry_description["count"],
        "names": registry_description["names"],
        "specs": registry_description["specs"],
        "status_counts": COD_SOURCE_REWRITE_REGISTRY.summary()["status_counts"],
        "active_count": COD_SOURCE_REWRITE_REGISTRY.summary()["active_count"],
        "oracle_count": COD_SOURCE_REWRITE_REGISTRY.summary()["oracle_count"],
        "subsumed_count": COD_SOURCE_REWRITE_REGISTRY.summary()["subsumed_count"],
    }


def describe_x86_16_source_backed_rewrite_debt() -> dict[str, object]:
    summary = COD_SOURCE_REWRITE_REGISTRY.summary()
    specs = COD_SOURCE_REWRITE_REGISTRY.describe()["specs"]
    active_names = tuple(
        spec["name"]
        for spec in specs
        if spec["rewrite_status"] in {"temporary_rescue", "permanent_guarded_oracle"}
    )
    oracle_names = tuple(
        spec["name"]
        for spec in specs
        if spec["rewrite_status"] == "permanent_guarded_oracle"
    )
    subsumed_names = tuple(
        spec["name"]
        for spec in specs
        if spec["rewrite_status"] == "already_subsumed_by_general_recovery"
    )
    return {
        "count": summary["count"],
        "active_count": summary["active_count"],
        "oracle_count": summary["oracle_count"],
        "subsumed_count": summary["subsumed_count"],
        "status_counts": summary["status_counts"],
        "active_names": active_names,
        "oracle_names": oracle_names,
        "subsumed_names": subsumed_names,
    }
