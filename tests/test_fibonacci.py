from __future__ import annotations

import unittest

from sdlc.fibonacci import fibonacci_series


class FibonacciSeriesTests(unittest.TestCase):
    def test_returns_requested_number_of_values(self) -> None:
        self.assertEqual(fibonacci_series(10), [0, 1, 1, 2, 3, 5, 8, 13, 21, 34])

    def test_zero_values(self) -> None:
        self.assertEqual(fibonacci_series(0), [])

    def test_rejects_negative_count(self) -> None:
        with self.assertRaises(ValueError):
            fibonacci_series(-1)

    def test_rejects_non_integer_count(self) -> None:
        with self.assertRaises(TypeError):
            fibonacci_series(3.5)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
