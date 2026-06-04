import json
import time
import urllib.parse
import urllib.request


LOKI = "http://loki:3100"
BASE_TS_NS = 1_780_598_742_704_000_000
LINE = "Transaccion completa"


def request_json(method, path, payload=None, params=None):
    url = LOKI + path
    if params:
        url += "?" + urllib.parse.urlencode(params)

    body = None
    headers = {}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=10) as resp:
        raw = resp.read()
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))


def wait_for_loki():
    for _ in range(60):
        try:
            with urllib.request.urlopen(LOKI + "/ready", timeout=2) as resp:
                if resp.status == 200:
                    return
        except Exception:
            time.sleep(1)
    raise RuntimeError("Loki was not ready in time")


def push(stream, values):
    request_json("POST", "/loki/api/v1/push", {"streams": [{"stream": stream, "values": values}]})


def query_count(selector):
    payload = request_json(
        "GET",
        "/loki/api/v1/query_range",
        params={
            "query": selector,
            "start": str(BASE_TS_NS - 1_000_000),
            "end": str(BASE_TS_NS + 2_000_000),
            "direction": "forward",
            "limit": "100",
        },
    )
    streams = payload.get("data", {}).get("result", [])
    return sum(len(stream.get("values", [])) for stream in streams), streams


def print_stream_values(name, streams):
    print(f"\n{name}")
    for stream in streams:
        print("labels=", stream.get("stream", {}))
        for timestamp, line in stream.get("values", []):
            print(f"  {timestamp} {line}")


def main():
    wait_for_loki()

    exact_values = [[str(BASE_TS_NS), LINE] for _ in range(5)]
    ns_values = [[str(BASE_TS_NS + offset), LINE] for offset in range(1, 6)]

    push({"job": "loki-dedupe-demo", "case": "exact_duplicate"}, exact_values)
    push({"job": "loki-dedupe-demo", "case": "ns_disambiguated"}, ns_values)

    time.sleep(1)

    exact_count, exact_streams = query_count('{job="loki-dedupe-demo",case="exact_duplicate"}')
    ns_count, ns_streams = query_count('{job="loki-dedupe-demo",case="ns_disambiguated"}')

    print_stream_values("exact_duplicate query result", exact_streams)
    print_stream_values("ns_disambiguated query result", ns_streams)

    print("\nsummary")
    print(f"exact_duplicate_input=5 exact_duplicate_query_count={exact_count}")
    print(f"ns_disambiguated_input=5 ns_disambiguated_query_count={ns_count}")

    if exact_count == 1 and ns_count == 5:
        print("result=PASS")
        return

    print("result=CHECK_BEHAVIOR")
    print("expected exact_duplicate_query_count=1 and ns_disambiguated_query_count=5")


if __name__ == "__main__":
    main()
