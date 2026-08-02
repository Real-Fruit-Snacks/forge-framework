"""Bounded-queue brute-force engine, shared by login modules.

Why not ThreadPoolExecutor like the scanners? Credential spaces
(users x passwords) get huge — submitting one future per combo would eat
memory. A bounded queue keeps memory constant, and the stop event makes
STOP_ON_SUCCESS actually stop early instead of draining a backlog.

attempt(user, pw) -> result (any) or None (transport problem, ignored)
classify(result)  -> "success" | "fail" | "error"

Returns (found, attempts, errors): found is the list of winning combos.
"""

import queue
import threading
from typing import Any, Callable, List, Optional, Tuple

from core import output


def brute_force(
    combos: List[Tuple[str, str]],
    attempt: Callable[[str, str], Any],
    classify: Callable[[Any], str],
    threads: int = 4,
    join_timeout: float = 7.0,
    on_success: Optional[Callable[[Tuple[str, str], Any], None]] = None,
    on_error: Optional[Callable[[Tuple[str, str], Any, int], None]] = None,
) -> Tuple[List[Tuple[str, str]], int, int]:
    stop = threading.Event()
    fed = threading.Event()  # producer has queued every combo
    work = queue.Queue(maxsize=threads * 4)
    found, attempts, errors = [], [0], [0]

    def worker():
        while not stop.is_set():
            try:
                user, pw = work.get(timeout=0.2)
            except queue.Empty:
                # no work right now: only give up once the producer
                # has queued everything (avoids the startup race)
                if fed.is_set():
                    return
                continue
            result = attempt(user, pw)
            attempts[0] += 1
            if result is None:
                continue
            verdict = classify(result)
            if verdict == "success":
                found.append((user, pw))
                if on_success:
                    on_success((user, pw), result)
                stop.set()
            elif verdict == "error":
                errors[0] += 1
                if on_error:
                    on_error((user, pw), result, errors[0])

    pool = [threading.Thread(target=worker, daemon=True) for _ in range(threads)]
    for t in pool:
        t.start()
    for combo in combos:
        while not stop.is_set():
            try:
                work.put(combo, timeout=0.2)
                break
            except queue.Full:
                if not any(t.is_alive() for t in pool):
                    stop.set()
        if stop.is_set():
            break
    fed.set()
    for t in pool:
        t.join(timeout=join_timeout)
    output.print_debug(
        f"brute engine: {attempts[0]}/{len(combos)} attempts, "
        f"{len(found)} hits, {errors[0]} errors, "
        f"{'stopped early' if stop.is_set() else 'exhausted'}"
    )
    return found, attempts[0], errors[0]
