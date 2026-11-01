"""Concurrency helpers: bounded batches, adaptive workers and early stop."""

from __future__ import annotations

import unittest

from nulltrace.parallel import CHUNK, batched, map_parallel, worker_count


class ParallelTests(unittest.TestCase):
    def test_worker_count_bounds(self) -> None:
        self.assertEqual(worker_count(0), 1)
        self.assertEqual(worker_count(4), 4)
        self.assertEqual(worker_count(100_000), 512)

    def test_batched_sizes(self) -> None:
        items = list(range(10))
        chunks = list(batched(items, size=4))
        self.assertEqual([len(c) for c in chunks], [4, 4, 2])
        self.assertEqual([x for c in chunks for x in c], items)

    def test_batched_exact_multiple(self) -> None:
        self.assertEqual([len(c) for c in batched(range(8), 4)], [4, 4])

    def test_map_parallel_collects_all(self) -> None:
        self.assertEqual(sorted(map_parallel(lambda n: n * 2, range(20), workers=4)),
                         [n * 2 for n in range(20)])

    def test_map_parallel_stops_early(self) -> None:
        calls = {"n": 0}

        def work(value: int) -> int:
            calls["n"] += 1
            return value

        results = map_parallel(work, range(10_000), workers=2,
                               should_stop=lambda: calls["n"] >= 4)
        self.assertLess(len(results), 10_000)
        self.assertLess(calls["n"], 10_000)

    def test_chunk_constant(self) -> None:
        self.assertGreaterEqual(CHUNK, 256)


if __name__ == "__main__":
    unittest.main()
