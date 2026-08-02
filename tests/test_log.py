"""Unit tests for core.log. Run: python3 -m unittest discover -s tests"""

import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import log  # noqa: E402
from core.jobs import JobManager  # noqa: E402


class TestLog(unittest.TestCase):
    def test_job_failure_lands_in_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            log.setup(tmp)
            try:
                jm = JobManager()

                def boom():
                    raise RuntimeError("fw-log-marker")

                job = jm.start("test/boom", boom)
                deadline = time.time() + 5
                while job.running and time.time() < deadline:
                    time.sleep(0.01)
                for handler in log.get().handlers:
                    handler.flush()
                text = (Path(tmp) / "logs" / "framework.log").read_text()
                self.assertIn("fw-log-marker", text)
                self.assertIn("job", text.lower())
            finally:
                # reset handlers so other tests aren't affected
                for handler in log.get().handlers[:]:
                    if not isinstance(handler, __import__("logging").NullHandler):
                        log.get().removeHandler(handler)


if __name__ == "__main__":
    unittest.main()
