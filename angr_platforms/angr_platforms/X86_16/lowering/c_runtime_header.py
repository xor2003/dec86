"""Render C runtime helper declarations required by lowered output.

Layer: Types/Lowering.
Responsibility: owns C runtime helper declarations for lowered output.
Consumes alias, widening, and typed facts by emitting only the helper surface
needed for already-materialized segmented memory and runtime abstractions.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

LOWERED_RUNTIME_HELPER_DECLARATIONS_8616: dict[str, str] = {
    "clock": "clock_t clock(void);",
    "rand": "int rand(void);",
    "srand": "void srand(unsigned int seed);",
    "time": "time_t time(time_t *out);",
}

KNOWN_EXTERNAL_DECLARATIONS_8616: dict[str, str] = {
    "memset": "void * memset(void *dst, int value, unsigned short count);",
    "outtext": "void outtext(char *a0);",
    "sprintf": "int sprintf(char *buf, const char *fmt, ...);",
}

LOWERED_ZERO_ARG_RUNTIME_HELPER_DECLARATIONS_8616: dict[str, str] = {
    name: LOWERED_RUNTIME_HELPER_DECLARATIONS_8616[name]
    for name in ("clock", "rand")
}

# Exact external return ABIs override caller-use inference. An unused result
# proves only that the caller discards it; it does not change the callee ABI.
KNOWN_EXTERNAL_RETURN_TYPES_8616: dict[str, str] = {
    "getvideoconfig": "unsigned short",
    "memset": "void *",
    "outtext": "void",
}

_MSC_COMPILER_RUNTIME_HELPER_DECLARATIONS_8616: tuple[str, ...] = (
    "long aNldiv(long dividend, long divisor);",
)

_PORTABLE_COMPILER_RUNTIME_HELPER_DECLARATIONS_8616: tuple[str, ...] = (
    "int32_t aNldiv(int32_t dividend, int32_t divisor);",
)

_TARGET_COMPILER_RUNTIME_HELPER_DECLARATIONS_8616: dict[str, dict[str, str]] = {
    "msc-dos": {
        "aNldiv": _MSC_COMPILER_RUNTIME_HELPER_DECLARATIONS_8616[0],
        "setbkcolor": "long setbkcolor(long color);",
    },
    "portable-flat": {
        "aNldiv": _PORTABLE_COMPILER_RUNTIME_HELPER_DECLARATIONS_8616[0],
        "setbkcolor": "int32_t setbkcolor(int32_t color);",
    },
}


def runtime_helper_declaration_8616(name: str, target: str | None) -> str | None:
    """Return an exact external declaration owned by the selected C ABI."""
    normalized_target = str(target or "").strip().lower()
    target_declarations = _TARGET_COMPILER_RUNTIME_HELPER_DECLARATIONS_8616.get(normalized_target, {})
    declaration = target_declarations.get(name)
    if declaration is not None:
        return declaration
    declaration = KNOWN_EXTERNAL_DECLARATIONS_8616.get(name)
    if declaration is not None:
        return declaration
    return LOWERED_RUNTIME_HELPER_DECLARATIONS_8616.get(name)


def render_c_runtime_header_8616(target: str | None) -> str:
    """Return the C helper header for the requested generated-C target."""
    normalized = str(target or "").strip().lower()
    runtime_helper_declarations = "\n".join(LOWERED_RUNTIME_HELPER_DECLARATIONS_8616.values())
    if normalized == "msc-dos":
        compiler_helper_declarations = "\n".join(_MSC_COMPILER_RUNTIME_HELPER_DECLARATIONS_8616)
        return (
            "#include <DOS.H>\n"
            "\n"
            "typedef signed char    int8_t;\n"
            "typedef signed short   int16_t;\n"
            "typedef signed long    int32_t;\n"
            "typedef unsigned char  uint8_t;\n"
            "typedef unsigned short uint16_t;\n"
            "typedef unsigned long  uint32_t;\n"
            "typedef long clock_t;\n"
            "typedef long time_t;\n"
            "\n"
            f"{runtime_helper_declarations}\n"
            f"{compiler_helper_declarations}\n"
            "\n"
            "#ifndef MK_FP\n"
            "#define MK_FP(seg, off) ((uint8_t far *)((((unsigned long)(unsigned short)(seg)) << 16) | (unsigned short)(off)))\n"
            "#endif\n"
            "\n"
            "#define SEG_PTR(seg, off)  MK_FP((seg), (off))\n"
            "#define SEG_U8(seg, off)   (*(uint8_t  far *)MK_FP((seg), (off)))\n"
            "#define SEG_U16(seg, off)  (*(uint16_t far *)MK_FP((seg), (off)))\n"
            "#define SEG_U32(seg, off)  (*(uint32_t far *)MK_FP((seg), (off)))\n"
            "#define MEM_U8(ptr)        (*(uint8_t  *)(ptr))\n"
            "#define MEM_U16(ptr)       (*(uint16_t *)(ptr))\n"
            "#define MEM_U32(ptr)       (*(uint32_t *)(ptr))\n"
        )
    if normalized == "portable-flat":
        compiler_helper_declarations = "\n".join(_PORTABLE_COMPILER_RUNTIME_HELPER_DECLARATIONS_8616)
        return (
            "#include <stdbool.h>\n"
            "#include <stdint.h>\n"
            "\n"
            "typedef long clock_t;\n"
            "typedef long time_t;\n"
            "\n"
            f"{runtime_helper_declarations}\n"
            f"{compiler_helper_declarations}\n"
            "\n"
            "extern uint8_t inertia_memory[];\n"
            "\n"
            "#ifndef far\n"
            "#define far\n"
            "#endif\n"
            "\n"
            "#define SEG_LINEAR(seg, off) ((((uint32_t)(uintptr_t)(seg)) << 4) + ((uint16_t)(uintptr_t)(off)))\n"
            "#define MK_FP(seg, off)      (&inertia_memory[SEG_LINEAR((seg), (off))])\n"
            "#define SEG_PTR(seg, off)    (&inertia_memory[SEG_LINEAR((seg), (off))])\n"
            "#define SEG_U8(seg, off)     (*(uint8_t  *)&inertia_memory[SEG_LINEAR((seg), (off))])\n"
            "#define SEG_U16(seg, off)    (*(uint16_t *)&inertia_memory[SEG_LINEAR((seg), (off))])\n"
            "#define SEG_U32(seg, off)    (*(uint32_t *)&inertia_memory[SEG_LINEAR((seg), (off))])\n"
            "#define MEM_U8(ptr)          (*(uint8_t  *)(ptr))\n"
            "#define MEM_U16(ptr)         (*(uint16_t *)(ptr))\n"
            "#define MEM_U32(ptr)         (*(uint32_t *)(ptr))\n"
        )
    return ""


__all__ = [
    "KNOWN_EXTERNAL_DECLARATIONS_8616",
    "KNOWN_EXTERNAL_RETURN_TYPES_8616",
    "LOWERED_RUNTIME_HELPER_DECLARATIONS_8616",
    "LOWERED_ZERO_ARG_RUNTIME_HELPER_DECLARATIONS_8616",
    "render_c_runtime_header_8616",
    "runtime_helper_declaration_8616",
]
