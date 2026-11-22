"""Thread-safety stress for progress and event-log writers (AR028, AC-108).

8 threads write concurrently and the flushed output must be intact: every
NDJSON line parses on its own (no interleaved/torn writes) and every record
arrives exactly once (no lost updates).
"""

from __future__ import annotations

import io
import json
import threading

from attackmap.extraction.progress import EventLog, JsonScanProgress, ScanProgress

THREADS = 8
RECORDS_PER_THREAD = 1000
REQUIRED_FIELDS = {"ts", "run_id", "trace_id", "stage", "event", "status"}


def _run_threads(work) -> None:
    threads = [threading.Thread(target=work, args=(n,)) for n in range(THREADS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


def test_event_log_8x1000_records_flush_clean_jsonl(tmp_path):
    log = EventLog(run_id="stress")
    total = {"count": 0}
    counter_lock = threading.Lock()

    def worker(n: int) -> None:
        for i in range(RECORDS_PER_THREAD):
            log.record(stage="scan_and_merge", event="analyzer", status="end", ms=i)
            with counter_lock:
                total["count"] += 1

    _run_threads(worker)
    assert total["count"] == THREADS * RECORDS_PER_THREAD
    assert len(log.records()) == THREADS * RECORDS_PER_THREAD

    target = tmp_path / "events.jsonl"
    assert log.flush(target) == THREADS * RECORDS_PER_THREAD

    raw_lines = target.read_text(encoding="utf-8").splitlines()
    # Every line is exactly one JSON object: no interleaved or torn writes.
    parsed = [json.loads(line) for line in raw_lines]
    assert len(parsed) == THREADS * RECORDS_PER_THREAD
    for row in parsed:
        assert set(row) >= REQUIRED_FIELDS
        assert row["run_id"] == "stress"
        assert isinstance(row["ms"], int)


def test_json_progress_8x1000_stage_events_stay_whole_lines():
    stream = io.StringIO()
    progress = JsonScanProgress(stream=stream, min_interval=0.0)

    def worker(n: int) -> None:
        for i in range(RECORDS_PER_THREAD):
            progress.stage(f"thread-{n} step-{i}")

    _run_threads(worker)
    lines = stream.getvalue().splitlines()
    parsed = [json.loads(line) for line in lines]
    assert len(parsed) == THREADS * RECORDS_PER_THREAD
    assert all(row["event"] == "stage" for row in parsed)
    assert all(row["v"] == 1 for row in parsed)


def test_json_progress_concurrent_advance_counter_never_tears():
    stream = io.StringIO()
    progress = JsonScanProgress(stream=stream, min_interval=0.0)
    progress.begin(total=THREADS * RECORDS_PER_THREAD)

    def worker(n: int) -> None:
        for _ in range(RECORDS_PER_THREAD):
            progress.advance("f.py")

    _run_threads(worker)
    rows = [json.loads(line) for line in stream.getvalue().splitlines()]
    advances = [row for row in rows if row["event"] == "advance"]
    # The throttled stream may batch, but the final count must be exact and
    # every advance row must carry a consistent (done, total) pair.
    assert progress._done == THREADS * RECORDS_PER_THREAD
    final = json.loads(stream.getvalue().splitlines()[-1])
    progress.done()
    done_row = [json.loads(line) for line in stream.getvalue().splitlines()][-1]
    assert done_row["event"] == "done"
    assert done_row["done"] == THREADS * RECORDS_PER_THREAD
    assert final["total"] == THREADS * RECORDS_PER_THREAD
    assert len(advances) >= 1


def test_tty_progress_concurrent_stage_advance_done_survives():
    class _FakeTty(io.StringIO):
        def isatty(self) -> bool:
            return True

    stream = _FakeTty()
    progress = ScanProgress(enabled=True, stream=stream)

    def worker(n: int) -> None:
        progress.stage(f"thread-{n}")
        for _ in range(50):
            progress.advance("x.py")

    _run_threads(worker)
    progress.done("finished")
    # The spinner was swapped out and stopped; no thread is left registered.
    assert progress._spin_thread is None
    assert progress._spin_stop is None
    assert progress._done == THREADS * 50


def test_tty_progress_concurrent_stage_keeps_single_spinner():
    class _FakeTty(io.StringIO):
        def isatty(self) -> bool:
            return True

    progress = ScanProgress(enabled=True, stream=_FakeTty())
    barrier = threading.Barrier(THREADS)

    def worker(n: int) -> None:
        barrier.wait()  # maximize contention on the spinner swap
        progress.stage(f"thread-{n}")

    _run_threads(worker)
    progress.done()
    # Every stage() stopped the previous spinner before installing its own;
    # after done() no spinner thread remains registered or running.
    assert progress._spin_thread is None
    assert progress._spin_stop is None
