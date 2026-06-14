from __future__ import annotations

import re

_RAW_REGISTER_FRAGMENT_RE = re.compile(r"\b(?P<name>[A-Za-z_]\w*)\{r\d+\|\d+b\}")
_CALLEE_NAMESPACE_RE = re.compile(r"::0x[0-9a-fA-F]+::(?P<name>[A-Za-z_]\w*)")
_PLACEHOLDER_RE = re.compile(r"<(?P<body>0x[^>\n]+)>")


def _placeholder_name(body: str, ordinal: int) -> str:
    stack_match = re.search(
        r"Stack bp(?P<sign>[+-])0x(?P<offset>[0-9A-Fa-f]+),\s*(?P<size>\d+)\s*B",
        body,
    )
    if stack_match is not None:
        sign = "p" if stack_match.group("sign") == "+" else "m"
        offset = stack_match.group("offset").lower()
        size = stack_match.group("size")
        return f"stack_bp_{sign}{offset}_b{size}"
    return f"tmp_slot_{ordinal}"


def _sanitize_placeholder_names(c_text: str) -> str:
    mapping: dict[str, str] = {}

    def _replace(match: re.Match[str]) -> str:
        token = match.group(0)
        existing = mapping.get(token)
        if existing is not None:
            return existing
        name = _placeholder_name(match.group("body"), len(mapping) + 1)
        mapping[token] = name
        return name

    return _PLACEHOLDER_RE.sub(_replace, c_text)


def _dedupe_local_declarations(c_text: str) -> str:
    def _impl():
        trailing_newline = c_text.endswith("\n")
        lines = c_text.splitlines()
        header_re = re.compile(
            r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)\s*(?P<suffix>[{;]?)\s*$"
        )
        decl_re = re.compile(
            r"^(?P<indent>\s*)(?!(?:return|if|while|for|switch|goto|case|default)\b)(?P<type>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*;\s*(?P<comment>//.*)?$"
        )

        changed = False
        index = 0
        while index < len(lines):
            match = header_re.match(lines[index])
            if match is None:
                index += 1
                continue
            brace_index = None
            scan_index = index
            while scan_index < len(lines):
                if "{" in lines[scan_index]:
                    brace_index = scan_index
                    break
                if ";" in lines[scan_index] and "{" not in lines[scan_index]:
                    break
                scan_index += 1
            if brace_index is None:
                index = scan_index + 1
                continue

            body_start = brace_index + 1
            body_end = body_start
            brace_depth = lines[brace_index].count("{") - lines[brace_index].count("}")
            while body_end < len(lines) and brace_depth > 0:
                brace_depth += lines[body_end].count("{") - lines[body_end].count("}")
                body_end += 1

            decls_by_name: dict[str, list[tuple[int, bool]]] = {}
            for line_index in range(body_start, body_end):
                decl_match = decl_re.match(lines[line_index])
                if decl_match is None:
                    continue
                name = decl_match.group("name")
                decls_by_name.setdefault(name, []).append((line_index, decl_match.group("comment") is not None))

            remove_lines: set[int] = set()
            for decls in decls_by_name.values():
                if len(decls) < 2:
                    continue
                changed = True
                best_index, _ = max(decls, key=lambda item: (item[1], item[0]))
                for line_index, _ in decls:
                    if line_index != best_index:
                        remove_lines.add(line_index)

            if remove_lines:
                lines = [line for i, line in enumerate(lines) if i not in remove_lines]
                index = max(index - len([i for i in remove_lines if i < index]), 0)
                continue
            index = body_end

        normalized = "\n".join(lines)
        if trailing_newline:
            normalized += "\n"
        return normalized

    return _impl()


def normalize_unresolved_c_text(c_text: str) -> str:
    """Normalize still-structured decompiler output into valid-ish C identifiers."""
    normalized = _CALLEE_NAMESPACE_RE.sub(lambda match: match.group("name"), c_text)
    normalized = _RAW_REGISTER_FRAGMENT_RE.sub(lambda match: match.group("name"), normalized)
    normalized = _normalize_concat_insert_artifacts(normalized)
    normalized = _normalize_numeric_call_targets(normalized)
    normalized = _sanitize_placeholder_names(normalized)
    normalized = _rewrite_linear_segment_word_dereferences(normalized)
    normalized = _synthesize_ellipsis_word_borrow_arithmetic(normalized)
    normalized = _rewrite_unresolved_ellipsis_assignments(normalized)
    normalized = _rewrite_unresolved_missing_label_gotos(normalized)
    normalized = _rewrite_unresolved_for_updates(normalized)
    normalized = _rewrite_unresolved_boolean_ellipsis_conditions(normalized)
    normalized = _rewrite_invalid_void_object_decls(normalized)
    normalized = _dedupe_local_declarations(normalized)
    normalized = _prune_unreachable_after_return(normalized)
    normalized = re.sub(r"\s*/\*\s*do not return\s*\*/", "", normalized)
    return normalized


def _rewrite_unresolved_ellipsis_assignments(c_text: str) -> str:
    # Compile-hygiene fallback for unresolved value carriers.
    return re.sub(
        r"(?m)^(?P<indent>\s*)(?P<lhs>[A-Za-z_]\w*)\s*=\s*\.\.\.\s*;\s*$",
        lambda m: f"{m.group('indent')}{m.group('lhs')} = 0;",
        c_text,
    )


def _rewrite_unresolved_missing_label_gotos(c_text: str) -> str:
    # Normalize synthetic unresolved goto targets that were not materialized
    # into labels, keeping generated C compilable under strict compilers.
    defined_labels = {m.group("label") for m in re.finditer(r"(?m)^\s*(?P<label>LABEL_0x[0-9a-fA-F]+)\s*:\s*$", c_text)}

    def _replace(match: re.Match[str]) -> str:
        label = match.group("label")
        if label in defined_labels:
            return match.group(0)
        indent = match.group("indent")
        return f"{indent}/* unresolved goto {label} */ return;"

    return re.sub(
        r"(?m)^(?P<indent>\s*)goto\s+(?P<label>LABEL_0x[0-9a-fA-F]+)\s*;\s*$",
        _replace,
        c_text,
    )


def _rewrite_unresolved_for_updates(c_text: str) -> str:
    # Recover the common unresolved loop update form: `for (...; ...; i = ...)`
    # into a stable update that preserves forward loop progress.
    pattern = re.compile(r"for\s*\((?P<head>[^;]*;[^;]*;)\s*(?P<var>[A-Za-z_]\w*)\s*=\s*\.\.\.\s*\)")
    return pattern.sub(lambda m: f"for ({m.group('head')} {m.group('var')}++)", c_text)


def _rewrite_unresolved_boolean_ellipsis_conditions(c_text: str) -> str:
    # Recover unresolved boolean ellipsis emitted as:
    #   if ((... ? 0 : 1))
    # using immediately preceding split-word temporaries:
    #   vA = word;
    #   vB = lo;
    #   vC = hi;
    # -> if ((((vB | vC * 0x100) == vA) ? 0 : 1))
    lines = c_text.splitlines()
    if not lines:
        return c_text

    cond_re = re.compile(r"^(?P<indent>\s*)if\s*\(\s*\(\s*\.\.\.\s*\?\s*0\s*:\s*1\s*\)\s*\)\s*$")
    assign_re = re.compile(r"^\s*(?P<dst>[A-Za-z_]\w*)\s*=\s*(?P<src>[^;]+?)\s*;\s*$")
    byte_re = re.compile(r"^(?P<lo>[A-Za-z_]\w*)\s*\|\s*(?P<hi>[A-Za-z_]\w*)\s*\*\s*0x100$")

    changed = False
    for idx, line in enumerate(lines):
        m_cond = cond_re.match(line)
        if m_cond is None or idx < 3:
            continue
        m_a = assign_re.match(lines[idx - 3])
        m_b = assign_re.match(lines[idx - 2])
        m_c = assign_re.match(lines[idx - 1])
        if m_a is None or m_b is None or m_c is None:
            continue
        m_word = byte_re.match(m_a.group("src").strip())
        if m_word is None:
            continue
        lhs = m_a.group("dst")
        lo = m_b.group("dst")
        hi = m_c.group("dst")
        indent = m_cond.group("indent")
        lines[idx] = f"{indent}if (((( {lo} | {hi} * 0x100) == {lhs}) ? 0 : 1))"
        changed = True

    return "\n".join(lines) if changed else c_text


def _rewrite_invalid_void_object_decls(c_text: str) -> str:
    # C does not allow object declarations with type `void` (only pointers).
    # When unresolved typing leaks `void g_xxx;`, keep the object as scalar storage.
    pattern = re.compile(
        r"^(?P<indent>\s*)(?P<storage>(?:extern|static)\s+)?void\s+(?P<name>[A-Za-z_]\w*)\s*;\s*$",
        flags=re.M,
    )

    def _replace(match: re.Match[str]) -> str:
        indent = match.group("indent") or ""
        storage = match.group("storage") or ""
        name = match.group("name")
        return f"{indent}{storage}unsigned short {name};"

    return pattern.sub(_replace, c_text)


def _synthesize_ellipsis_word_borrow_arithmetic(c_text: str) -> str:
    def _impl():
        lines = c_text.splitlines()
        if not lines:
            return c_text

        unresolved_re = re.compile(r"^(?P<indent>\s*)(?P<lhs>[A-Za-z_]\w*)\s*=\s*\.\.\.;\s*$")
        low_sub_re = re.compile(
            r"^(?P<indent>\s*)(?P<dst>[A-Za-z_]\w*)\s*=\s*(?P<left>[A-Za-z_]\w*)\s*-\s*\(\s*(?P<lo>[A-Za-z_]\w*)\s*\|\s*(?P<hi>[A-Za-z_]\w*)\s*\*\s*0x100\s*\)\s*;\s*$"
        )
        packed_word_re_tmpl = r"^\s*{lhs}\s*=\s*(?P<lo>[A-Za-z_]\w*)\s*\|\s*(?P<hi>[A-Za-z_]\w*)\s*\*\s*0x100\s*;\s*$"

        def _bump_hex_suffix(name: str, delta: int = 2) -> str | None:
            m = re.match(r"^(?P<prefix>.*?)(?P<num>[0-9A-Fa-f]+)$", name)
            if m is None:
                return None
            num_text = m.group("num")
            try:
                value = int(num_text, 16)
            except ValueError:
                return None
            width = len(num_text)
            bumped = f"{value + delta:0{width}x}"
            return f"{m.group('prefix')}{bumped}"

        changed = False
        for idx, line in enumerate(lines):
            unresolved = unresolved_re.match(line)
            if unresolved is None:
                continue
            lhs_name = unresolved.group("lhs")
            low_match = None
            for look_ahead in range(idx + 1, min(idx + 12, len(lines))):
                m = low_sub_re.match(lines[look_ahead])
                if m is not None:
                    low_match = m
                    break
            if low_match is None:
                continue

            low_left_name = low_match.group("left")
            right_lo = low_match.group("lo")
            right_hi = low_match.group("hi")

            left_lo = None
            left_hi = None
            packed_word_re = re.compile(packed_word_re_tmpl.format(lhs=re.escape(low_left_name)))
            for back in range(idx - 1, max(-1, idx - 24), -1):
                m = packed_word_re.match(lines[back])
                if m is not None:
                    left_lo = m.group("lo")
                    left_hi = m.group("hi")
                    break
            if not (isinstance(left_lo, str) and isinstance(left_hi, str)):
                continue

            right_lo_hi = _bump_hex_suffix(right_lo)
            right_hi_hi = _bump_hex_suffix(right_hi)
            if not (isinstance(right_lo_hi, str) and isinstance(right_hi_hi, str)):
                continue

            indent = unresolved.group("indent")
            low_expr = f"({low_left_name} < ({right_lo} | {right_hi} * 0x100))"
            synth_expr = (
                f"(({left_lo} | {left_hi} * 0x100) - ({right_lo_hi} | {right_hi_hi} * 0x100) - ({low_expr} ? 1 : 0))"
            )
            lines[idx] = f"{indent}{lhs_name} = {synth_expr};"
            changed = True

        return "\n".join(lines) if changed else c_text

    return _impl()


def _normalize_concat_insert_artifacts(c_text: str) -> str:
    # Normalize textual CONCAT/_INSERT artifacts emitted by upstream IR printer.
    normalized = re.sub(r"\(\s*([A-Za-z_]\w*)\s+CONCAT\s+0\s*\)", r"\1", c_text)
    normalized = re.sub(r"(?<![A-Za-z_])([A-Za-z_]\w*)\s+CONCAT\s+0(?![A-Za-z_])", r"\1", normalized)
    normalized = re.sub(r"0\s+CONCAT\s+([A-Za-z_]\w*)", r"\1", normalized)
    normalized = re.sub(
        r"_INSERT\s*\(\s*[^,]+,\s*0\s*,\s*([^)]+?)\s*\)",
        r"\1",
        normalized,
    )
    return normalized


def _normalize_numeric_call_targets(c_text: str) -> str:
    # Rewrite numeric call targets like `1169()` into stable identifiers.
    return re.sub(r"(?<![A-Za-z0-9_])(?P<num>\d+)\s*\(", lambda m: f"sub_{m.group('num')}(", c_text)


def _rewrite_linear_segment_word_dereferences(c_text: str) -> str:
    # Normalize unresolved x86-16 linearized stack/data word dereferences into
    # segment-aware helpers so emitted C remains compilable and explicit.
    # Example: *((v3 * 16 + X)) -> SEG_U16(v3, X)
    patterns = [
        re.compile(
            r"\*\s*\(\s*\(\s*(?:unsigned\s+|signed\s+)?(?:short|int|long)\s*\*\s*\)\s*\(\s*(?P<seg>[A-Za-z_]\w*)\s*\*\s*16\s*\+\s*(?P<off>[^)]+?)\s*\)\s*\)"
        ),
        re.compile(
            r"\*\s*\(\s*\(\s*(?:unsigned\s+|signed\s+)?(?:short|int|long)\s*\*\s*\)\s*\(\s*\(\s*(?P<seg>[A-Za-z_]\w*)\s*<<\s*4\s*\)\s*\+\s*(?P<off>[^)]+?)\s*\)\s*\)"
        ),
        re.compile(r"\*\s*\(\s*\(\s*(?P<seg>[A-Za-z_]\w*)\s*\*\s*16\s*\)\s*\+\s*(?P<off>[^)]+?)\s*\)"),
        re.compile(r"\*\s*\(\s*(?P<seg>[A-Za-z_]\w*)\s*\*\s*16\s*\+\s*(?P<off>[^)]+?)\s*\)"),
        re.compile(r"\*\s*\(\s*\(\s*(?P<seg>[A-Za-z_]\w*)\s*<<\s*4\s*\)\s*\+\s*(?P<off>[^)]+?)\s*\)"),
        re.compile(r"\*\s*\(\s*(?P<seg>[A-Za-z_]\w*)\s*<<\s*4\s*\+\s*(?P<off>[^)]+?)\s*\)"),
    ]
    out = c_text
    for pat in patterns:
        out = pat.sub(lambda m: f"SEG_U16({m.group('seg')}, {m.group('off').strip()})", out)
    # Repair malformed cast+deref remnants after linear-deref normalization.
    out = re.sub(
        r"\*\s*\(\s*\(\s*(?:unsigned\s+|signed\s+)?short\s+SEG_U16\(([^)]*)\)\s*\)\s*\)",
        r"SEG_U16(\1)",
        out,
    )
    out = re.sub(
        r"\*\s*\(\s*\(\s*(?:unsigned\s+|signed\s+)?short\s+SEG_U16\(([^)]*)\)\s*\)\s*",
        r"SEG_U16(\1)",
        out,
    )
    out = re.sub(
        r"\*\s*\(\s*\(\s*(?:unsigned\s+|signed\s+)?short\s+SEG_U16\(([^)]*)\)\s*\)\)",
        r"SEG_U16(\1)",
        out,
    )
    out = re.sub(
        r"\*\s*\(\s*(?:unsigned\s+|signed\s+)?short\s+SEG_U16\(([^)]*)\)\s*\)",
        r"SEG_U16(\1)",
        out,
    )
    out = re.sub(
        r"\*\s*\(\s*\(\s*(?:unsigned\s+|signed\s+)?short\s+SEG_U16\(([\s\S]*?)\)\s*\)\s*\)",
        r"SEG_U16(\1)",
        out,
    )
    return out


def _prune_unreachable_after_return(c_text: str) -> str:
    def _impl():
        lines = c_text.splitlines()
        if not lines:
            return c_text
        out: list[str] = []
        saw_return = False
        return_indent: int | None = None
        brace_depth = 0
        for line in lines:
            stripped = line.strip()
            opens = line.count("{")
            closes = line.count("}")
            indent = len(line) - len(line.lstrip(" \t"))
            if (
                saw_return
                and return_indent is not None
                and stripped
                and not stripped.startswith("}")
                and indent <= return_indent
            ):
                saw_return = False
                return_indent = None
            if saw_return and brace_depth > 0 and stripped and not stripped.startswith(("}", "/*", "*", "//")):
                if "{" in line or "}" in line:
                    out.append(line)
                    brace_depth += opens - closes
                    if closes > 0 and brace_depth <= 0:
                        saw_return = False
                        return_indent = None
                    continue
                # Drop statements that are clearly unreachable in the same block.
                if not stripped.startswith("#"):
                    brace_depth += opens - closes
                    continue
            out.append(line)
            if re.match(r"^\s*return\b", stripped):
                saw_return = True
                return_indent = indent
            if saw_return and closes > 0 and brace_depth + opens - closes <= 0:
                saw_return = False
                return_indent = None
            brace_depth += opens - closes
            if brace_depth < 0:
                brace_depth = 0
        normalized = "\n".join(out)
        if c_text.endswith("\n"):
            normalized += "\n"
        return normalized

    return _impl()
