"""Backfill measured pytest jobs under exact CPU and RSS reservations.

Layer: Tooling/gates.
Responsibility: keep independently measured pytest workers busy without wave
barriers while enforcing conservative reservations and a live aggregate limit.
"""

from __future__ import annotations

import os
import time
from collections.abc import Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

if __package__:
    from .pytest_partition_execution import (
        WaveResult,
        WorkerProcess,
        WorkerSpec,
        start_pytest_worker,
        terminate_worker_processes,
    )
    from .pytest_partition_plugin import WorkerActivity, WorkerReport
    from .pytest_process_metrics import process_trees_rss_kib
else:
    from pytest_partition_execution import (
        WaveResult,
        WorkerProcess,
        WorkerSpec,
        start_pytest_worker,
        terminate_worker_processes,
    )
    from pytest_partition_plugin import WorkerActivity, WorkerReport
    from pytest_process_metrics import process_trees_rss_kib


@dataclass(frozen=True, slots=True)
class ScheduledWorkerSpec:
    """One worker plus its conservative admission-control reservation."""

    spec: WorkerSpec
    reserved_rss_kib: int


def run_pytest_schedule(
    scheduled_specs: Sequence[ScheduledWorkerSpec],
    *,
    repo_root: Path,
    run_root: Path,
    weights_path: Path,
    durations: int,
    max_workers: int,
    reservation_limit_kib: int,
    max_rss_kib: int,
) -> WaveResult:
    """Backfill measured workers while enforcing reservations and live RSS."""

    if max_workers < 1 or reservation_limit_kib < 1 or max_rss_kib < 1:
        raise ValueError("schedule limits must be positive")
    if any(item.reserved_rss_kib < 1 for item in scheduled_specs):
        raise ValueError("worker reservations must be positive")
    names = [item.spec.name for item in scheduled_specs]
    if len(names) != len(set(names)):
        raise ValueError("scheduled worker names must be unique")
    if not scheduled_specs:
        return WaveResult({}, (), {}, {}, 0, {}, False)

    pending = list(scheduled_specs)
    workers: list[WorkerProcess] = []
    outputs: dict[str, str] = {}
    exit_codes: dict[str, int] = {}
    worker_peak_rss_kib: dict[str, int] = {}
    peak_rss_kib = 0
    memory_exceeded = False
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        active: dict[Future[tuple[str, str | None]], tuple[WorkerProcess, int]] = {}

        def launch_available() -> None:
            """Fill free CPU and reservation capacity without queue blocking."""

            while pending and len(active) < max_workers:
                reserved = sum(reservation for _worker, reservation in active.values())
                available = reservation_limit_kib - reserved
                selected = next(
                    (
                        index
                        for index, item in enumerate(pending)
                        if item.reserved_rss_kib <= available
                    ),
                    None,
                )
                if selected is None:
                    if active:
                        return
                    selected = 0
                item = pending.pop(selected)
                worker = start_pytest_worker(
                    item.spec,
                    repo_root=repo_root,
                    run_root=run_root,
                    weights_path=weights_path,
                    durations=durations,
                )
                workers.append(worker)
                worker_peak_rss_kib[worker.name] = 0
                active[executor.submit(worker.process.communicate)] = (
                    worker,
                    item.reserved_rss_kib,
                )

        try:
            launch_available()
            while active:
                roots = (os.getpid(), *(worker.process.pid for worker, _rss in active.values()))
                rss_by_root = process_trees_rss_kib(roots)
                if rss_by_root is not None:
                    aggregate_rss_kib = rss_by_root.get(os.getpid(), 0)
                    peak_rss_kib = max(peak_rss_kib, aggregate_rss_kib)
                    for worker, _reservation in active.values():
                        worker_peak_rss_kib[worker.name] = max(
                            worker_peak_rss_kib[worker.name],
                            rss_by_root.get(worker.process.pid, 0),
                        )
                    if aggregate_rss_kib > max_rss_kib:
                        memory_exceeded = True
                        terminate_worker_processes([worker for worker, _rss in active.values()])
                completed = [future for future in active if future.done()]
                for future in completed:
                    worker, _reservation = active.pop(future)
                    stdout, _stderr = future.result()
                    outputs[worker.name] = stdout
                    exit_codes[worker.name] = worker.process.returncode
                if memory_exceeded:
                    break
                launch_available()
                if active and not completed:
                    time.sleep(0.2)
        except KeyboardInterrupt:
            terminate_worker_processes([worker for worker, _rss in active.values()])
            raise
        for future, (worker, _reservation) in active.items():
            stdout, _stderr = future.result()
            outputs[worker.name] = stdout
            exit_codes[worker.name] = worker.process.returncode

    reports = tuple(
        WorkerReport.from_path(worker.report_path) for worker in workers if worker.report_path.exists()
    )
    active_nodeids = {
        worker.name: WorkerActivity.from_path(worker.activity_path).nodeid
        for worker in workers
        if worker.activity_path.exists()
    }
    return WaveResult(
        outputs=outputs,
        reports=reports,
        exit_codes=exit_codes,
        active_nodeids=active_nodeids,
        peak_rss_kib=peak_rss_kib,
        worker_peak_rss_kib=worker_peak_rss_kib,
        memory_exceeded=memory_exceeded,
    )
