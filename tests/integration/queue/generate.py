import json
import os
from concurrent.futures import ThreadPoolExecutor
from urllib.request import Request, urlopen


COUNT = int(os.environ.get("COUNT", "16"))


def send(record_id):
    request = Request(
        "http://127.0.0.1:18080",
        data=json.dumps({"message": "OTLP queue test", "record_id": str(record_id)}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urlopen(request, timeout=30) as response:
        response.read()


with ThreadPoolExecutor(max_workers=8) as pool:
    for _ in pool.map(send, range(COUNT)):
        pass
print(f"Logstash accepted {COUNT} HTTP requests. Check Collector metrics for delivery.")
