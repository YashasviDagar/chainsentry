"""The interface every check implements.

A *check* looks at the list of :class:`~chainsentry.models.PackageReport`
objects and **adds** findings or vulnerabilities to them. It never prints,
never scores and never decides the exit code - those are other layers' jobs.

Design decisions
----------------
* **Batch interface** (``run(packages)``, not ``run(package)``): OSV answers
  1,000 packages in one request, and registry lookups run in a thread pool.
  A per-package interface would force one-request-per-package.
* **Errors are returned, not raised.** If PyPI is down, OSV results are
  still worth reporting. ``run`` returns human-readable error strings; the
  scanner marks the check as incomplete in the report.
* ``typing.Protocol`` instead of an abstract base class: any object with a
  ``name`` and a matching ``run`` method is a check ("duck typing" that the
  type checker can still verify).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Protocol, TypeVar

from chainsentry import config
from chainsentry.models import PackageReport

T = TypeVar("T")
R = TypeVar("R")


class Check(Protocol):
    """Something that inspects packages and annotates their reports."""

    #: Short identifier used in reports and ``--skip``, e.g. ``"osv"``.
    name: str
    #: Whether the check talks to the network (skipped with ``--offline``).
    needs_network: bool

    def run(self, packages: list[PackageReport]) -> list[str]:
        """Annotate ``packages`` in place. Returns error messages (empty = complete)."""
        ...


def chunked(items: list[T], size: int) -> Iterator[list[T]]:
    """Yield successive ``size``-length slices of ``items``."""
    for start in range(0, len(items), size):
        yield items[start : start + size]


def parallel_map(fn: Callable[[T], R], items: Iterable[T]) -> list[R]:
    """``[fn(x) for x in items]`` run on a small thread pool, preserving order.

    Threads (not asyncio) because the work is waiting on HTTP, the GIL is
    released while waiting, and the code stays plain synchronous Python.
    """
    items = list(items)
    if len(items) <= 1:
        return [fn(x) for x in items]
    with ThreadPoolExecutor(max_workers=config.MAX_WORKERS) as pool:
        return list(pool.map(fn, items))
