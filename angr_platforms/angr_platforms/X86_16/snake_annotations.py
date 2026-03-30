from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from angr.calling_conventions import SerializableListIterator, SimCC, SimRegArg, SimStackArg
from angr.sim_type import SimTypeChar

from .annotations import annotate_function
from .arch_86_16 import Arch86_16
from .lst_extract import LSTMetadata


class _SnakeBaseCC(SimCC):
    FP_ARG_REGS = []
    STACKARG_SP_DIFF = 2
    RETURN_ADDR = SimStackArg(0, 2)
    ARCH = Arch86_16
    STACK_ALIGNMENT = 2
    CALLEE_CLEANUP = True


class SimCC8616SnakeDX(_SnakeBaseCC):
    @property
    def int_args(self):
        return SerializableListIterator([SimRegArg("dx", 2)])


class SimCC8616SnakeDXBX(_SnakeBaseCC):
    @property
    def int_args(self):
        return SerializableListIterator([SimRegArg("dx", 2), SimRegArg("bx", 2)])


class SimCC8616SnakeDXBL(_SnakeBaseCC):
    @property
    def int_args(self):
        return SerializableListIterator([SimRegArg("dx", 2), SimRegArg("bx", 1)])


class SimCC8616SnakeRetBL(_SnakeBaseCC):
    RETURN_VAL = SimRegArg("bx", 1)

    @property
    def int_args(self):
        return SerializableListIterator([])


class SimCC8616SnakeDXRetBL(_SnakeBaseCC):
    RETURN_VAL = SimRegArg("bx", 1)

    @property
    def int_args(self):
        return SerializableListIterator([SimRegArg("dx", 2)])


class SimCC8616SnakeRetDL(_SnakeBaseCC):
    RETURN_VAL = SimRegArg("dx", 1)

    @property
    def int_args(self):
        return SerializableListIterator([])


class SimCC8616SnakeDL(_SnakeBaseCC):
    @property
    def int_args(self):
        return SerializableListIterator([SimRegArg("dx", 1)])


class SimCC8616SnakeAX(_SnakeBaseCC):
    @property
    def int_args(self):
        return SerializableListIterator([SimRegArg("ax", 2)])


@dataclass(frozen=True)
class SnakeFunctionAnnotation:
    c_decl: str
    cc_cls: type[SimCC]


SNAKE_DATA_GLOBAL_NAMES: frozenset[str] = frozenset(
    {
        "msg",
        "instructions",
        "gameovermsg",
        "scoremsg",
        "head",
        "body",
        "segmentcount",
        "fruitactive",
        "fruitx",
        "fruity",
        "gameover",
        "quit",
        "delaytime",
        "aThanksForPlayi",
    }
)

SNAKE_TYPED_DATA_GLOBALS: frozenset[str] = frozenset(
    {
        "instructions",
        "gameovermsg",
        "scoremsg",
        "head",
        "body",
        "segmentcount",
        "fruitactive",
        "fruitx",
        "fruity",
        "gameover",
        "quit",
        "delaytime",
    }
)


SNAKE_FUNCTION_ANNOTATIONS: dict[str, SnakeFunctionAnnotation] = {
    "setcursorpos": SnakeFunctionAnnotation(
        "void setcursorpos(unsigned short rowcol);",
        SimCC8616SnakeDX,
    ),
    "writecharat": SnakeFunctionAnnotation(
        "void writecharat(unsigned short rowcol, unsigned char ch);",
        SimCC8616SnakeDXBL,
    ),
    "readcharat": SnakeFunctionAnnotation(
        "unsigned char readcharat(unsigned short rowcol);",
        SimCC8616SnakeDXRetBL,
    ),
    "writestringat": SnakeFunctionAnnotation(
        "void writestringat(unsigned short rowcol, const char *s);",
        SimCC8616SnakeDXBX,
    ),
    "readchar": SnakeFunctionAnnotation(
        "unsigned char readchar(void);",
        SimCC8616SnakeRetDL,
    ),
    "dispdigit": SnakeFunctionAnnotation(
        "void dispdigit(unsigned char digit);",
        SimCC8616SnakeDL,
    ),
    "dispnum": SnakeFunctionAnnotation(
        "void dispnum(unsigned short value);",
        SimCC8616SnakeAX,
    ),
}


def is_snake_binary(binary_path: Path | None) -> bool:
    return binary_path is not None and binary_path.name.lower() == "snake.exe"


def _snake_global_vars(project, lst_metadata: LSTMetadata | None) -> dict[int, str | dict]:
    if lst_metadata is None or not lst_metadata.data_labels:
        return {}

    main_object = getattr(project.loader, "main_object", None)
    data_base = getattr(main_object, "mapped_base", None)
    if not isinstance(data_base, int):
        return {}

    global_vars: dict[int, str | dict] = {}
    for offset, name in lst_metadata.data_labels.items():
        if name in SNAKE_DATA_GLOBAL_NAMES:
            if name in SNAKE_TYPED_DATA_GLOBALS:
                global_vars[data_base + offset] = {"name": name, "type": SimTypeChar(False)}
            else:
                global_vars[data_base + offset] = name
    return global_vars


def apply_snake_recompilation_annotations(project, binary_path: Path | None, lst_metadata: LSTMetadata | None) -> bool:
    if not is_snake_binary(binary_path) or lst_metadata is None:
        return False

    global_vars = _snake_global_vars(project, lst_metadata)
    changed = False
    for offset, name in lst_metadata.code_labels.items():
        spec = SNAKE_FUNCTION_ANNOTATIONS.get(name)
        if spec is None:
            continue
        annotate_function(
            project,
            project.entry + offset,
            name=name,
            c_decl=spec.c_decl,
            calling_convention=spec.cc_cls(project.arch),
            global_vars=global_vars or None,
        )
        changed = True
    return changed
