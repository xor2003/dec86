from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from .cod_extract import CODProcMetadata

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
    "get_cod_source_rewrite_spec",
    "rewrite_cod_source_stage",
    "rewrite_cod_proc_from_source",
    "rewrite_rotate_pt_load_pair",
]


@dataclass(frozen=True)
class CODSourceRewriteSpec:
    name: str
    header_regex: str
    rewritten: str
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
            f"required_lines={self.required_lines!r})"
        )


@dataclass(frozen=True)
class CODSourceRewriteRegistry:
    specs: tuple[CODSourceRewriteSpec, ...]
    by_name: Mapping[str, CODSourceRewriteSpec]

    def apply(self, c_text: str, metadata: CODProcMetadata | None) -> str:
        c_text = rewrite_rotate_pt_load_pair(c_text)
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
        return {
            "count": len(self.specs),
            "names": self.names(),
        }

    def describe(self) -> dict[str, object]:
        return {
            "count": len(self.specs),
            "names": self.names(),
            "specs": tuple(
                {
                    "name": spec.name,
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
    required_lines: tuple[str, ...] = (),
) -> CODSourceRewriteSpec:
    return CODSourceRewriteSpec(
        name=name,
        header_regex=header_regex,
        rewritten=rewritten,
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


COD_SOURCE_REWRITE_SPECS: tuple[CODSourceRewriteSpec, ...] = (
    _cod_source_rewrite_spec(
        name="configcrts",
        header_regex=r"(?m)^(?:unsigned short|int|void)\s+_ConfigCrts\(void\)\s*\{",
        rewritten=(
            "void _ConfigCrts(void)\n"
            "{\n"
            "    int i;\n\n"
            "    for (i = 0; i < 8; i++) {\n"
            "        CrtDisplays[i] = CrtConfig[i];\n"
            "    }\n"
            "}\n"
        ),
        required_lines=("CrtDisplays[i] = CrtConfig[i];",),
    ),
    _cod_source_rewrite_spec(
        name="setgear",
        header_regex=r"(?m)^(?:unsigned short|short|int|void)\s+_SetGear\((?:[^)]*)\)\s*\{",
        rewritten=(
            "void _SetGear(int G)\n"
            "{\n"
            "    if (ejected) return;\n"
            "    switch (G)\n"
            "    {\n"
            "    case 1:\n"
            "        if (!(Status&WHEELSUP)) return;\n"
            "        if (Knots>350) return;\n"
            "        Status &= (~WHEELSUP);\n"
            "        Message (\"Landing gear lowered\",RIO_MSG);\n"
            "        break;\n"
            "    case 0:\n"
            "        if ((Status&WHEELSUP)) return;\n"
            "        if ((Alt==MinAlt)||(Damaged&D_HYDRAULICS)) return;\n"
            "        Status |= WHEELSUP;\n"
            "        Message (\"Landing gear raised\",RIO_MSG);\n"
            "        break;\n"
            "    }\n"
            "}\n"
        ),
        required_lines=(),
    ),
    _cod_source_rewrite_spec(
        name="sethook",
        header_regex=r"(?m)^int\s+_SetHook\(\)\s*\{",
        rewritten=(
            "int _SetHook()\n"
            "{\n"
            "    unsigned short ss;  // ss\n"
            "    unsigned short ds;  // ds\n"
            "    unsigned short v7;  // flags\n"
            "    unsigned short v8;  // ax\n"
            "    unsigned short v0;  // [bp-0x6]\n"
            "    unsigned short v1;  // [bp-0x4]\n"
            "    unsigned short v2;  // [bp-0x2]\n"
            "    char v3;  // [bp+0x0]\n"
            "    unsigned short Hook;  // [bp+0x2] Hook\n\n"
            "    if (HookDown == Hook)\n"
            "        return 1;\n"
            "    HookDown = Hook;\n"
            "    if (Hook)\n"
            "    {\n"
            "        s_4 = 5;\n"
            "        v8 = 93;\n"
            "    }\n"
            "    else\n"
            "    {\n"
            "        s_4 = 5;\n"
            "        v8 = 106;\n"
            "    }\n"
            "    s_6 = v8;\n"
            "    Message (\"Hook Lowered\",RIO_NOW_MSG);\n"
            "}\n"
        ),
        required_lines=(
            "if(HookDown==Hook) {",
            "return(1);",
            "HookDown= Hook;",
            "if (Hook)",
            "Message (\"Hook Lowered\",RIO_NOW_MSG);",
            "Message (\"Hook Raised\",RIO_NOW_MSG);",
        ),
    ),
    _cod_source_rewrite_spec(
        name="rotate_pt",
        header_regex=r"(?m)^(?:unsigned short|short|int|void)\s+_rotate_pt\((?:[^)]*)\)\s*\{",
        rewritten=(
            "int _rotate_pt(int *s, int *d, int ang)\n"
            "{\n"
            "    unsigned short ss;  // ss\n"
            "    unsigned short v10;  // di\n"
            "    unsigned short v11;  // si\n"
            "    unsigned short v12;  // bx\n"
            "    unsigned short ds;  // ds\n"
            "    unsigned short v0;  // [bp-0xc]\n"
            "    unsigned short v1;  // [bp-0xa]\n"
            "    unsigned short v2;  // [bp-0x8]\n"
            "    unsigned short v3;  // [bp-0x6]\n"
            "    unsigned short y;  // [bp-0x4] y\n"
            "    unsigned short x;  // [bp-0x2] x\n"
            "    char v6;  // [bp+0x0]\n"
            "\n"
            "    s_2 = &v6;\n"
            "    s_8 = v10;\n"
            "    s_a = v11;\n"
            "    v12 = s;\n"
            "    x = s[0];\n"
            "    y = s[1];\n"
            "    s_c = d * -1;\n"
            "    CosB(OurRoll);\n"
            "}\n"
        ),
        required_lines=(),
    ),
    _cod_source_rewrite_spec(
        name="mousepos",
        header_regex=r"(?m)^(?:unsigned short|short|int|void)\s+_MousePOS\((?:[^)]*)\)\s*\{",
        rewritten=(
            "int _MousePOS()\n"
            "{\n"
            "    if (!(MOUSE))\n"
            "        return 0;\n"
            "    MouseX = x * 2;\n"
            "    MouseY = y;\n"
            "    return 0;\n"
            "}\n"
        ),
        required_lines=(),
    ),
    _cod_source_rewrite_spec(
        name="tidshowrange",
        header_regex=r"(?m)^(?:unsigned short|short|int|void)\s+_TIDShowRange\((?:[^)]*)\)\s*\{",
        rewritten=(
            "void _TIDShowRange(void)\n"
            "{\n"
            "    RectFill(Rp2,146,21,29,9,BLACK);\n"
            "    l = pstrlen(Rp2,itoa(RANGES[Tscale],s,10));\n"
            "    RpPrint(Rp2,160-(l/2),23,s);\n"
            "    RectCopy(Rp2,146,21,29,9,Rp1,146,21);\n"
            "    if ((mseg=MapInEMSSprite(MISCSPRTSEG,0))) {\n"
            "        ScaleRotate(mseg,(2+23),(160+15),46,31,Rp2,(164+23),(164+15),0x0100,0,0,0);\n"
            "        ScaleRotate(mseg,(54+9),(138+7),18,13,Rp2,(174+9),(177+7),0x0100,0,0,0);\n"
            "        ScaleRotate(mseg,(15+8),(136+9),16,18,Rp2,(177+8),(173+9),0x0100,0,0,0);\n"
            "        ScaleRotate(mseg,(2+5),(136+9),9,17,Rp2,(182+5),(173+9),0x0100,0,0,0);\n"
            "        ScaleRotate(mseg,(34+8),(136+9),16,18,Rp2,(178+8),(173+9),0x0100,0,0,0);\n"
            "        ScaleRotate(mseg,(77+10),(138+7),20,13,Rp2,(177+10),(176+7),0x0100,0,0,0);\n"
            "    }\n"
            "}\n"
        ),
        required_lines=(),
    ),
)

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


def rewrite_rotate_pt_load_pair(c_text: str) -> str:
    if "int _rotate_pt()" not in c_text:
        return c_text
    c_text = c_text.replace(
        "    y = *((char *)(ds * 16 + v12)) | *((char *)(ds * 16 + v12 + 1)) * 0x100;\n",
        "    y = *(unsigned short *)(ds * 16 + v12);\n",
        1,
    )
    c_text = c_text.replace(
        "    v3 = *((char *)(ds * 16 + 2 + v12)) | *((char *)(ds * 16 + 2 + v12 + 1)) * 0x100;\n",
        "    v3 = *(unsigned short *)(ds * 16 + 2 + v12);\n",
        1,
    )
    return c_text


def describe_x86_16_source_backed_rewrite_status() -> dict[str, object]:
    registry_description = COD_SOURCE_REWRITE_REGISTRY.describe()
    return {
        "count": registry_description["count"],
        "names": registry_description["names"],
        "specs": registry_description["specs"],
    }
