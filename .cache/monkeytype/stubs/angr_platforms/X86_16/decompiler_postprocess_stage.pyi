from types import SimpleNamespace
from typing import Tuple


def _build_decompiler_postprocess_passes(
) -> Tuple[DecompilerPostprocessPassSpec, DecompilerPostprocessPassSpec, DecompilerPostprocessPassSpec, DecompilerPostprocessPassSpec, DecompilerPostprocessPassSpec, DecompilerPostprocessPassSpec, DecompilerPostprocessPassSpec, DecompilerPostprocessPassSpec, DecompilerPostprocessPassSpec, DecompilerPostprocessPassSpec, DecompilerPostprocessPassSpec, DecompilerPostprocessPassSpec, DecompilerPostprocessPassSpec, DecompilerPostprocessPassSpec]: ...


def _postprocess_codegen_8616(project: SimpleNamespace, codegen: SimpleNamespace) -> bool: ...


def _restore_codegen_cfunc(codegen: SimpleNamespace, snapshot: SimpleNamespace) -> bool: ...


def _snapshot_codegen_cfunc(codegen: SimpleNamespace) -> SimpleNamespace: ...


def apply_x86_16_decompiler_postprocess() -> None: ...
