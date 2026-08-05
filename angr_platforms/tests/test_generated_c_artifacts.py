from __future__ import annotations

from pathlib import Path

from inertia_decompiler.cli_arg_parser import parse_cli_arguments
from inertia_decompiler.generated_c_artifacts import write_generated_function_c


def test_generated_function_artifact_preserves_validated_payload(tmp_path: Path) -> None:
    payload = "void sub_1234(void)\n{\n    return;\n}\n"

    destination = write_generated_function_c(
        tmp_path,
        address=0x1234,
        name="unsafe/name",
        payload=payload,
    )

    assert destination.name == "00001234-unsafe_name.c"
    assert destination.read_text(encoding="utf-8") == payload


def test_output_c_directory_can_be_selected_from_cli(tmp_path: Path) -> None:
    args = parse_cli_arguments(["sample.exe", "--output-c-dir", str(tmp_path)])

    assert args.output_c_dir == tmp_path
