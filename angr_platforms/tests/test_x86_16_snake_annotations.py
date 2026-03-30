from __future__ import annotations

from types import SimpleNamespace

from angr.calling_conventions import SimRegArg
from angr.sim_type import SimTypeChar

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lst_extract import extract_lst_metadata
from angr_platforms.X86_16.snake_annotations import (
    SNAKE_FUNCTION_ANNOTATIONS,
    SNAKE_TYPED_DATA_GLOBALS,
    SimCC8616SnakeDXBL,
    SimCC8616SnakeDXBX,
    SimCC8616SnakeDXRetBL,
    _snake_global_vars,
    is_snake_binary,
)

SNAKE_LST = __import__("pathlib").Path(__file__).resolve().parents[2] / "examples" / "snake.lst"


def test_snake_annotation_registry_covers_register_helper_surface():
    assert "setcursorpos" in SNAKE_FUNCTION_ANNOTATIONS
    assert "writecharat" in SNAKE_FUNCTION_ANNOTATIONS
    assert "readcharat" in SNAKE_FUNCTION_ANNOTATIONS
    assert "writestringat" in SNAKE_FUNCTION_ANNOTATIONS


def test_snake_dxbl_calling_convention_uses_rowcol_and_low_byte_char():
    cc = SimCC8616SnakeDXBL(Arch86_16())
    args = list(cc.int_args)
    assert args == [SimRegArg("dx", 2), SimRegArg("bx", 1)]


def test_snake_dxbx_calling_convention_uses_rowcol_and_pointer_register():
    cc = SimCC8616SnakeDXBX(Arch86_16())
    args = list(cc.int_args)
    assert args == [SimRegArg("dx", 2), SimRegArg("bx", 2)]


def test_snake_readcharat_calling_convention_returns_low_byte_of_bx():
    cc = SimCC8616SnakeDXRetBL(Arch86_16())
    assert cc.RETURN_VAL == SimRegArg("bx", 1)


def test_snake_binary_detection_is_narrow():
    assert is_snake_binary(__import__("pathlib").Path("snake.EXE"))
    assert not is_snake_binary(__import__("pathlib").Path("other.exe"))


def test_snake_global_annotations_include_typed_byte_globals():
    metadata = extract_lst_metadata(SNAKE_LST)
    fake_project = SimpleNamespace(loader=SimpleNamespace(main_object=SimpleNamespace(mapped_base=0x1000)))

    global_vars = _snake_global_vars(fake_project, metadata)

    assert global_vars[0x1000 + 0xF4] == {"name": "segmentcount", "type": SimTypeChar(False)}
    assert global_vars[0x1000 + 0xF5] == {"name": "fruitactive", "type": SimTypeChar(False)}
    assert global_vars[0x1000 + 0xF6] == {"name": "fruitx", "type": SimTypeChar(False)}
    assert global_vars[0x1000 + 0xF7] == {"name": "fruity", "type": SimTypeChar(False)}
    assert global_vars[0x1000 + 0xFA] == {"name": "delaytime", "type": SimTypeChar(False)}
    assert "head" in SNAKE_TYPED_DATA_GLOBALS
