"""Background job execution: run modules in threads with captured output.

A Job wraps a callable (usually a module instance's run()). Everything the
module prints through core.output is captured into job.log; the console
announces completion and shows the log with `jobs -o <id>`.

Honest limitation: Python threads can't be force-killed safely, so a
running job can't be aborted from the console — it runs to completion.
Finished jobs can be dismissed from the list.
"""

import threading
import time
import traceback
from typing import Callable, Dict, List, Optional

from core import log, output


class Job:
    def __init__(self, jid: int, name: str, target: Callable[[], None]):
        self.id = jid
        self.name = name
        self.status = "running"  # running | done | failed
        self.started = time.time()
        self.log: List[str] = []
        self.module = None  # set when the job runs a module instance
        self._target = target
        self._thread = threading.Thread(
            target=self._run, name=f"job-{jid}", daemon=True
        )

    def start(self) -> None:
        self._thread.start()

    def request_stop(self) -> bool:
        """Cooperative stop: works when the job's module implements stop()."""
        stop = getattr(self.module, "stop", None)
        if self.running and callable(stop):
            stop()
            return True
        return False

    def _run(self) -> None:
        with output.capture(self.log):
            try:
                self._target()
                self.status = "done"
            except Exception:
                self.log.append(traceback.format_exc())
                self.status = "failed"
                log.get().error(
                    "job %d (%s) failed\n%s", self.id, self.name, self.log[-1]
                )

    @property
    def running(self) -> bool:
        return self._thread.is_alive()

    @property
    def runtime(self) -> int:
        return int(time.time() - self.started)

    def output_text(self) -> str:
        return "\n".join(self.log)


class JobManager:
    def __init__(self) -> None:
        self._jobs: Dict[int, Job] = {}
        self._next_id = 1
        self._announced: set = set()
        self._lock = threading.Lock()

    def start(self, name: str, target: Callable[[], None], module=None) -> Job:
        with self._lock:
            job = Job(self._next_id, name, target)
            job.module = module
            self._jobs[job.id] = job
            self._next_id += 1
        job.start()
        return job

    def get(self, jid: int) -> Optional[Job]:
        return self._jobs.get(int(jid))

    def all(self) -> List[Job]:
        return [self._jobs[k] for k in sorted(self._jobs)]

    def running(self) -> List[Job]:
        return [j for j in self.all() if j.running]

    def poll_finished(self) -> List[Job]:
        """Jobs that finished since the last call (for prompt notifications)."""
        with self._lock:
            done = [
                j for j in self._jobs.values()
                if not j.running and j.id not in self._announced
            ]
            self._announced.update(j.id for j in done)
        return sorted(done, key=lambda j: j.id)

    def dismiss(self, jid: int) -> bool:
        """Remove a finished job from the list. Running jobs are refused."""
        job = self._jobs.get(int(jid))
        if job is None or job.running:
            return False
        del self._jobs[job.id]
        self._announced.discard(job.id)
        return True
