import http.client
import json
import math
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, wait
from urllib.parse import urlsplit


COUNT = int(os.environ.get("COUNT", "50000"))
CONCURRENCY = int(os.environ.get("CONCURRENCY", "16"))
REQUEST_BATCH_SIZE = int(os.environ.get("REQUEST_BATCH_SIZE", "1"))
PAYLOAD_BYTES = int(os.environ.get("PAYLOAD_BYTES", "1024"))
ROUNDS = int(os.environ.get("ROUNDS", "1"))
PAUSE_SECONDS = float(os.environ.get("PAUSE_SECONDS", "15"))
DURATION_SECONDS = float(os.environ.get("DURATION_SECONDS", "0"))
RATE_PER_SECOND = float(os.environ.get("RATE_PER_SECOND", "0"))
REPORT_INTERVAL_SECONDS = float(os.environ.get("REPORT_INTERVAL_SECONDS", "30"))
PAYLOAD_SIZES = tuple(int(size) for size in os.environ.get("PAYLOAD_SIZES", str(PAYLOAD_BYTES)).split(","))
ENDPOINT = urlsplit(os.environ.get("ENDPOINT", "http://127.0.0.1:18082"))
TIMINGS = (PAUSE_SECONDS, DURATION_SECONDS, RATE_PER_SECOND, REPORT_INTERVAL_SECONDS)
if not all(math.isfinite(value) for value in TIMINGS):
    raise SystemExit("Duration, rate, pauses and report interval must be finite")
if (
    min(COUNT, CONCURRENCY, ROUNDS, REQUEST_BATCH_SIZE) < 1
    or min(PAYLOAD_SIZES) < 0
    or min(TIMINGS) < 0
    or REPORT_INTERVAL_SECONDS == 0
):
    raise SystemExit("Counts and report interval must be positive; payload sizes, duration, rate and pauses cannot be negative")
if ENDPOINT.scheme != "http" or not ENDPOINT.hostname or ENDPOINT.username:
    raise SystemExit("ENDPOINT must be a plain HTTP URL without credentials")
MESSAGES = tuple("x" * size for size in PAYLOAD_SIZES)
PATH = ENDPOINT.path or "/"


def send(worker, run_id, started, progress):
    connection = http.client.HTTPConnection(ENDPOINT.hostname, ENDPOINT.port or 80, timeout=30)
    accepted = 0
    failed = 0
    accepted_bytes = 0
    first_error = None
    record_id = worker
    next_send = started + worker * REQUEST_BATCH_SIZE / RATE_PER_SECOND if RATE_PER_SECOND else started
    deadline = started + DURATION_SECONDS if DURATION_SECONDS else None
    try:
        while deadline is not None or record_id < COUNT:
            now = time.monotonic()
            if deadline is not None and now >= deadline:
                break
            if next_send > now:
                time.sleep(min(next_send - now, deadline - now) if deadline is not None else next_send - now)
            if deadline is not None and time.monotonic() >= deadline:
                break
            records = []
            for _ in range(REQUEST_BATCH_SIZE):
                if deadline is None and record_id >= COUNT:
                    break
                records.append({"message": MESSAGES[record_id % len(MESSAGES)], "record_id": str(record_id), "run_id": run_id})
                record_id += CONCURRENCY
            body = json.dumps(records[0] if REQUEST_BATCH_SIZE == 1 else records).encode()
            try:
                connection.request("POST", PATH, body, {"Content-Type": "application/json"})
                response = connection.getresponse()
                response.read()
                if 200 <= response.status < 300:
                    accepted += len(records)
                    accepted_bytes += len(body)
                else:
                    failed += len(records)
                    first_error = first_error or f"HTTP {response.status}"
            except (OSError, http.client.HTTPException) as error:
                failed += len(records)
                first_error = first_error or str(error)
                connection.close()
            progress[worker] = (accepted, failed, accepted_bytes, first_error)
            if RATE_PER_SECOND:
                next_send = max(next_send + CONCURRENCY * len(records) / RATE_PER_SECOND, time.monotonic())
    finally:
        connection.close()
    return accepted, failed, accepted_bytes, first_error


def report(current_round, run_id, started, results, complete):
    elapsed = time.monotonic() - started
    accepted = sum(result[0] for result in results)
    failed = sum(result[1] for result in results)
    print(json.dumps({
        "round": current_round, "run_id": run_id, "complete": complete,
        "accepted": accepted, "failed": failed,
        "accepted_bytes": sum(result[2] for result in results),
        "seconds": round(elapsed, 3), "accepted_per_second": round(accepted / elapsed, 1),
        "message_bytes": PAYLOAD_SIZES[0] if len(PAYLOAD_SIZES) == 1 else list(PAYLOAD_SIZES),
        "request_batch_size": REQUEST_BATCH_SIZE,
        "first_error": next((result[3] for result in results if result[3]), None),
    }), flush=True)
    return failed


failed_records = 0
with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
    for current_round in range(1, ROUNDS + 1):
        run_id = uuid.uuid4().hex
        started = time.monotonic()
        progress = [(0, 0, 0, None)] * CONCURRENCY
        futures = [pool.submit(send, worker, run_id, started, progress) for worker in range(CONCURRENCY)]
        pending = set(futures)
        while pending:
            _, pending = wait(pending, timeout=REPORT_INTERVAL_SECONDS)
            if pending:
                report(current_round, run_id, started, progress, False)
        failed_records += report(current_round, run_id, started, [future.result() for future in futures], True)
        if current_round < ROUNDS:
            time.sleep(PAUSE_SECONDS)
raise SystemExit(1 if failed_records else 0)
