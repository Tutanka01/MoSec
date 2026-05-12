"""
Small concurrency helpers for bounded, order-preserving parallel work.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable, TypeVar

T = TypeVar("T")
R = TypeVar("R")


def resolve_workers(max_workers: int | None, default: int = 1) -> int:
    """Normalise a user/config supplied worker count."""
    if max_workers is None:
        return max(1, default)
    return max(1, max_workers)


def ordered_parallel(
    items: Iterable[T],
    worker: Callable[[T], R | None],
    *,
    max_workers: int,
    logger: logging.Logger,
    error_label: Callable[[T], str],
) -> list[R]:
    """
    Run independent tasks with bounded concurrency and return results in input order.

    Worker exceptions are logged and treated as missing results so one bad item does
    not abort the whole phase.
    """
    item_list = list(items)
    if not item_list:
        return []

    if max_workers <= 1 or len(item_list) == 1:
        results: list[R] = []
        for item in item_list:
            try:
                result = worker(item)
                if result is not None:
                    results.append(result)
            except Exception as exc:
                logger.error("%s: %s", error_label(item), exc)
        return results

    ordered: list[R | None] = [None] * len(item_list)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(worker, item): (idx, item)
            for idx, item in enumerate(item_list)
        }
        for future in as_completed(futures):
            idx, item = futures[future]
            try:
                ordered[idx] = future.result()
            except Exception as exc:
                logger.error("%s: %s", error_label(item), exc)

    return [result for result in ordered if result is not None]
