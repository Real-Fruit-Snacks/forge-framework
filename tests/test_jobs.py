"""Unit tests for core.jobs. Run: python3 -m unittest discover -s tests"""

import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import output  # noqa: E402
from core.jobs import JobManager  # noqa: E402


def wait_for(job, timeout=5.0):
    deadline = time.time() + timeout
    while job.running and time.time() < deadline:
        time.sleep(0.01)
    return not job.running


class TestJobs(unittest.TestCase):
    def test_successful_job_captures_output(self):
        jm = JobManager()
        job = jm.start("test/ok", lambda: output.print_good("job says hi"))
        self.assertTrue(wait_for(job))
        self.assertEqual(job.status, "done")
        self.assertIn("job says hi", job.output_text())

    def test_failed_job_records_traceback(self):
        jm = JobManager()

        def boom():
            raise RuntimeError("kaboom")

        job = jm.start("test/fail", boom)
        self.assertTrue(wait_for(job))
        self.assertEqual(job.status, "failed")
        self.assertIn("kaboom", job.output_text())

    def test_poll_finished_reports_once(self):
        jm = JobManager()
        job = jm.start("test/once", lambda: None)
        self.assertTrue(wait_for(job))
        first = jm.poll_finished()
        self.assertEqual([j.id for j in first], [job.id])
        self.assertEqual(jm.poll_finished(), [])

    def test_dismiss_refuses_running_jobs(self):
        jm = JobManager()
        started = []

        def slow():
            started.append(True)
            time.sleep(0.5)

        job = jm.start("test/slow", slow)
        while not started:
            time.sleep(0.01)
        self.assertFalse(jm.dismiss(job.id))
        self.assertTrue(wait_for(job))
        self.assertTrue(jm.dismiss(job.id))
        self.assertIsNone(jm.get(job.id))


if __name__ == "__main__":
    unittest.main()
