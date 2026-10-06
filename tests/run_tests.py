"""Runs every test and writes a machine-readable report to tests/test-report.json."""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


class Recorder(unittest.TextTestResult):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.records = []

    def _rec(self, test, status, detail=""):
        self.records.append({"test": test.id(), "status": status, "detail": detail})

    def addSuccess(self, test):
        super().addSuccess(test)
        self._rec(test, "pass")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self._rec(test, "fail", self._exc_info_to_string(err, test))

    def addError(self, test, err):
        super().addError(test, err)
        self._rec(test, "error", self._exc_info_to_string(err, test))

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            self._rec(subtest, "fail", self._exc_info_to_string(err, test))


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.discover(HERE, pattern="test_*.py")
    res = unittest.TextTestRunner(verbosity=1, resultclass=Recorder).run(suite)
    recs = sorted(res.records, key=lambda r: r["test"])
    rep = {"total": res.testsRun, "passed": sum(r["status"] == "pass" for r in recs),
           "failed": len(res.failures), "errors": len(res.errors), "results": recs}
    with open(os.path.join(HERE, "test-report.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(rep, f, indent=2, sort_keys=True)
        f.write("\n")
    sys.exit(0 if res.wasSuccessful() else 1)
