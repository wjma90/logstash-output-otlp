import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.request import Request, urlopen


COUNT = 1000
WORKERS = 8
RUN_ID = uuid.uuid4().hex
SOURCE_TIME = datetime.now(timezone.utc).replace(microsecond=123456)
TIMESTAMP = SOURCE_TIME.isoformat()
TIMESTAMP_NANOS = str(int(SOURCE_TIME.timestamp()) * 1_000_000_000 + SOURCE_TIME.microsecond * 1000)


def send(record_id):
    event = {
        "@timestamp": TIMESTAMP,
        "message": "Concurrent timestamp test",
        "run_id": RUN_ID,
        "record_id": str(record_id),
        "source_time_unix_nano": TIMESTAMP_NANOS,
    }
    request = Request(
        "http://logstash:8080",
        data=json.dumps(event).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urlopen(request, timeout=30) as response:
        response.read()


print(f"run_id={RUN_ID}", flush=True)
print(f"timestamp={TIMESTAMP} records={COUNT} concurrent_senders={WORKERS}", flush=True)
with ThreadPoolExecutor(max_workers=WORKERS) as pool:
    for _ in pool.map(send, range(COUNT)):
        pass
print(f"Logstash accepted {COUNT} HTTP requests. Query Loki to check delivery.")
