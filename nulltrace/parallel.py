"""Concurrency helpers shared by the network modules.

Network-bound work does not benefit from a C extension: the time is spent
waiting on sockets and DNS, not running Python bytecode. What actually helps is
more concurrent work in flight and not creating one future per task up front
(a /16 port sweep would otherwise allocate 65k futures before the first result).
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable, Iterator, TypeVar

T = TypeVar("T")
R = TypeVar("R")

MAX_WORKERS = 512
CHUNK = 2048


def worker_count(tasks: int, ceiling: int = MAX_WORKERS) -> int:
    """Enough threads to keep the network busy without oversubscribing."""
    return max(1, min(ceiling, tasks))


def batched(items: Iterable[T], size: int = CHUNK) -> Iterator[list[T]]:
    batch: list[T] = []
    for item in items:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def map_parallel(func: Callable[[T], R], items: Iterable[T], workers: int | None = None,
                 should_stop: Callable[[], bool] | None = None,
                 on_progress: Callable[[int, int], None] | None = None,
                 total: int | None = None) -> list[R]:
    """Run ``func`` over ``items`` in bounded batches, preserving input not order."""
    items = list(items)
    total = len(items) if total is None else total
    pool = ThreadPoolExecutor(max_workers=workers or worker_count(len(items)))
    results: list[R] = []
    done = 0
    stopped = False
    try:
        for chunk in batched(items):
            if stopped or (should_stop and should_stop()):
                break
            futures = [pool.submit(func, item) for item in chunk]
            for future in as_completed(futures):
                if should_stop and should_stop():
                    stopped = True
                    for pending in futures:
                        pending.cancel()
                    break
                done += 1
                results.append(future.result())
                if on_progress:
                    on_progress(done, total)
            if stopped:
                break
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return results
