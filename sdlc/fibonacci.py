"""Small Fibonacci helpers."""

from __future__ import annotations


def fibonacci_series(count: int) -> list[int]:
    """Return the first ``count`` Fibonacci numbers starting at zero."""

    if not isinstance(count, int):
        raise TypeError("count must be an integer")
    if count < 0:
        raise ValueError("count must be non-negative")

    series: list[int] = []
    current, next_value = 0, 1
    for _ in range(count):
        series.append(current)
        current, next_value = next_value, current + next_value
    return series
