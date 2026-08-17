"""Contracts for source-bound MS C runtime-gate artifact reuse."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from scripts.msc6_runtime_gate_artifacts import (
    MSC6RuntimeGateInputs,
    load_or_run_msc6_runtime_gate,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def _write_fake_gate(path: Path, *, marker: str = "first") -> None:
    path.write_text(
        "\n".join(
            (
                "import argparse",
                "import time",
                "from pathlib import Path",
                "",
                "parser = argparse.ArgumentParser()",
                'parser.add_argument("--example")',
                'parser.add_argument("--out-dir", type=Path)',
                'args, _unknown = parser.parse_known_args()',
                "counter = args.out_dir.parent.parent / 'producer-count.txt'",
                "count = int(counter.read_text()) if counter.exists() else 0",
                "counter.write_text(str(count + 1))",
                "time.sleep(0.2)",
                "args.out_dir.mkdir(parents=True, exist_ok=True)",
                f"(args.out_dir / 'artifact.txt').write_text({marker!r})",
                "print('status=passed')",
                "print('run_exit=255')",
                "",
            )
        ),
        encoding="utf-8",
    )


def _inputs(tmp_path: Path) -> MSC6RuntimeGateInputs:
    gate_path = tmp_path / "fake_gate.py"
    _write_fake_gate(gate_path)
    executable = tmp_path / "SAMPLE.EXE"
    for path in (
        executable,
        executable.with_suffix(".COD"),
        executable.with_suffix(".MAP"),
        executable.with_suffix(".C"),
    ):
        path.write_bytes(path.name.encode("ascii"))
    kvikdos = tmp_path / "kvikdos"
    kvikdos.write_bytes(b"emulator")
    msc6_root = tmp_path / "msc6"
    msc6_root.mkdir()
    (msc6_root / "compiler.exe").write_bytes(b"compiler")
    return MSC6RuntimeGateInputs(
        repo_root=REPO_ROOT,
        cache_root=tmp_path / "cache",
        fallback_output_root=tmp_path / "fallback",
        runtime_gate_path=gate_path,
        kvikdos_path=kvikdos,
        msc6_root=msc6_root,
        examples=(("sample", executable),),
    )


def test_runtime_gate_cache_reuses_verified_artifacts(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)

    produced = load_or_run_msc6_runtime_gate(inputs)
    reused = load_or_run_msc6_runtime_gate(inputs)

    assert not produced.cache_hit
    assert reused.cache_hit
    assert reused.results["sample"] is not None
    assert (inputs.cache_root / "producer-count.txt").read_text(encoding="utf-8") == "1"


def test_runtime_gate_cache_rebuilds_corrupt_artifact(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    produced = load_or_run_msc6_runtime_gate(inputs)
    artifact = produced.output_root / "sample_runtime_gate" / "artifact.txt"
    artifact.write_text("corrupt", encoding="utf-8")

    rebuilt = load_or_run_msc6_runtime_gate(inputs)

    assert not rebuilt.cache_hit
    assert artifact.read_text(encoding="utf-8") == "first"
    assert (inputs.cache_root / "producer-count.txt").read_text(encoding="utf-8") == "2"


def test_runtime_gate_cache_key_tracks_gate_content(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    first = load_or_run_msc6_runtime_gate(inputs)
    _write_fake_gate(inputs.runtime_gate_path, marker="second")

    second = load_or_run_msc6_runtime_gate(inputs)

    assert first.output_root != second.output_root
    assert not second.cache_hit
    assert (second.output_root / "sample_runtime_gate" / "artifact.txt").read_text() == "second"


def test_runtime_gate_cache_serializes_concurrent_producers(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(lambda _index: load_or_run_msc6_runtime_gate(inputs), range(2)))

    assert sorted(result.cache_hit for result in results) == [False, True]
    assert (inputs.cache_root / "producer-count.txt").read_text(encoding="utf-8") == "1"
