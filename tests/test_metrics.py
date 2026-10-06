import unittest
from helpers import BASE  # noqa: F401  (path bootstrap)
from chronotrace import build


class MetricsTests(unittest.TestCase):
    def test_peak_memory_is_a_positive_number_or_none_never_an_exception(self):
        v = build._peak_mb()
        self.assertTrue(v is None or v > 0)


if __name__ == "__main__":
    unittest.main()
