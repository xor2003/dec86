#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path


REPO_ROOT = Path("/home/xor/vextest")
DEFAULT_EXAMPLES_DIR = REPO_ROOT / "examples" / "msc6_constructs"
DEFAULT_OUT_DIR = REPO_ROOT / "examples" / "build_msc6"
DEFAULT_KVIKDOS = Path("/home/xor/kvikdos/kvikdos")
DEFAULT_MSC6_ROOT = Path("/home/xor/inertia_player/dos_compilers/Microsoft C v6ax")
DEFAULT_DECOMPILE = REPO_ROOT / "decompile.py"


@dataclass(frozen=True)
class ExampleResult:
    name: str
    source: str
    exe: str
    obj: str
    map: str
    build_ok: bool
    decompile_skipped: bool
    decompile_ok: bool
    compile_stdout: str
    compile_stderr: str
    link_stdout: str
    link_stderr: str
    decompile_stdout_path: str | None
    decompile_stderr_path: str | None


def _run(cmd: list[str], *, cwd: Path | None = None, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )


def _compile_and_link(source_path: Path, out_dir: Path, *, kvikdos: Path, msc6_root: Path) -> tuple[bool, str, str, str, str]:
    stem = source_path.stem.upper()
    obj_name = f"{stem}.OBJ"
    exe_name = f"{stem}.EXE"
    map_name = f"{stem}.MAP"

    compile_cmd = [
        str(kvikdos),
        f"--mount=c:{out_dir}/",
        f"--mount=e:{msc6_root}/",
        "--drive=c",
        "--cwd-dos=c:\\",
        "--path-dos=e:\\BIN",
        "--env=INCLUDE=E:\\INCLUDE",
        "--env=LIB=E:\\LIB",
        "--prog=e:\\BIN\\CL.EXE",
        "e:\\BIN\\CL.EXE",
        "/nologo",
        "/Od",
        "/c",
        f"/Foc:\\{obj_name}",
        f"c:\\{source_path.name}",
    ]
    compile_proc = _run(compile_cmd, timeout=120)

    link_cmd = [
        str(kvikdos),
        f"--mount=c:{out_dir}/",
        f"--mount=e:{msc6_root}/",
        "--drive=c",
        "--cwd-dos=c:\\",
        "--env=LIB=E:\\LIB",
        "--prog=e:\\BIN\\LINK.EXE",
        "e:\\BIN\\LINK.EXE",
        f"c:\\{obj_name},c:\\{exe_name},c:\\{map_name},E:\\LIB\\SLIBCE.LIB;",
    ]
    link_proc = _run(link_cmd, timeout=120)

    built = (out_dir / exe_name).exists()
    return built, compile_proc.stdout, compile_proc.stderr, link_proc.stdout, link_proc.stderr


def _decompile(exe_path: Path, out_dir: Path, *, decompile_py: Path) -> tuple[bool, Path, Path]:
    stdout_path = out_dir / f"{exe_path.stem}.dec.txt"
    stderr_path = out_dir / f"{exe_path.stem}.dec.err.txt"
    cmd = [
        str(shutil.which("python3") or "python3"),
        str(decompile_py),
        "--alternate-source-c",
        "--max-functions",
        "16",
        "--timeout",
        "20",
        str(exe_path),
    ]
    try:
        proc = _run(cmd, cwd=REPO_ROOT, timeout=45)
        stdout_path.write_text(proc.stdout, encoding="utf-8")
        stderr_path.write_text(proc.stderr, encoding="utf-8")
        return proc.returncode == 0, stdout_path, stderr_path
    except subprocess.TimeoutExpired as ex:
        stdout_data = ex.stdout.decode("utf-8", errors="replace") if isinstance(ex.stdout, bytes) else (ex.stdout or "")
        stderr_data = ex.stderr.decode("utf-8", errors="replace") if isinstance(ex.stderr, bytes) else (ex.stderr or "")
        stdout_path.write_text(stdout_data, encoding="utf-8")
        stderr_path.write_text(stderr_data + "\ndecompile timeout\n", encoding="utf-8")
        return False, stdout_path, stderr_path


def main() -> int:
    ap = argparse.ArgumentParser(description="Build simple/medium MS C 6 examples via kvikdos and try decompilation.")
    ap.add_argument("--examples-dir", type=Path, default=DEFAULT_EXAMPLES_DIR)
    ap.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    ap.add_argument("--kvikdos", type=Path, default=DEFAULT_KVIKDOS)
    ap.add_argument("--msc6-root", type=Path, default=DEFAULT_MSC6_ROOT)
    ap.add_argument("--decompile-py", type=Path, default=DEFAULT_DECOMPILE)
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    results: list[ExampleResult] = []
    dos_names = {
        "simple_control": "SIMPLE.C",
        "medium_structs": "MEDIUM.C",
        "compare32": "COMP32.C",
        "loops_jumps": "LOOPS.C",
        "scalar_types_io": "TYPES.C",
        "pointer_memory": "POINT.C",
        "enum_union": "EUNION.C",
        "function_pointers": "FPTR.C",
        "storage_classes": "STORE.C",
    }
    decompile_skip = {"medium_structs"}

    for source_path in sorted(args.examples_dir.glob("*.c")):
        dos_name = dos_names.get(source_path.stem, source_path.name.upper())
        local_source = args.out_dir / dos_name
        shutil.copy2(source_path, local_source)
        build_ok, c_out, c_err, l_out, l_err = _compile_and_link(
            local_source,
            args.out_dir,
            kvikdos=args.kvikdos,
            msc6_root=args.msc6_root,
        )
        exe_path = args.out_dir / f"{local_source.stem.upper()}.EXE"
        obj_path = args.out_dir / f"{local_source.stem.upper()}.OBJ"
        map_path = args.out_dir / f"{local_source.stem.upper()}.MAP"
        decompile_skipped = source_path.stem in decompile_skip
        decompile_ok = False
        dec_out: Path | None = None
        dec_err: Path | None = None
        if build_ok and exe_path.exists() and not decompile_skipped:
            decompile_ok, dec_out, dec_err = _decompile(exe_path, args.out_dir, decompile_py=args.decompile_py)
        results.append(
            ExampleResult(
                name=source_path.stem,
                source=str(local_source),
                exe=str(exe_path),
                obj=str(obj_path),
                map=str(map_path),
                build_ok=build_ok,
                decompile_skipped=decompile_skipped,
                decompile_ok=decompile_ok,
                compile_stdout=c_out,
                compile_stderr=c_err,
                link_stdout=l_out,
                link_stderr=l_err,
                decompile_stdout_path=str(dec_out) if dec_out is not None else None,
                decompile_stderr_path=str(dec_err) if dec_err is not None else None,
            )
        )

    report_path = args.out_dir / "report.json"
    report_path.write_text(json.dumps([asdict(item) for item in results], indent=2), encoding="utf-8")
    print(report_path)
    for item in results:
        print(
            f"{item.name}: build={'ok' if item.build_ok else 'fail'} "
            f"decompile={'skipped' if item.decompile_skipped else ('ok' if item.decompile_ok else 'fail')} exe={item.exe}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
