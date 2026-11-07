# Spring Logback over TCP

Compare two configurations from Spring/Logback through Logstash to the OTLP/gRPC
Collector, at a target of **13,000 log records/s**. These are logging calls, not
HTTP transactions.

| Case | Profile | `pipeline.workers` | `pipeline.batch.size` | `num_consumers` | `block_on_overflow` |
| --- | --- | ---: | ---: | ---: | --- |
| 1. Current configuration | `baseline.env` | 4 | 300 | 4 | false |
| 2. Tuned configuration | `tuned.env` | 4 | 300 | 10 | true |

Both use `queue_size=16384`, `max_batch_size=1000` and `schedule_delay_millis=100`.
Logback waits when its 8,192-slot buffer fills (`APPEND_TIMEOUT=-1`). Maximum heaps:
Logstash 1 GiB, Spring 512 MiB. Each run sends 3,900,000 messages of 8 KiB from
16 threads, targeting five minutes of generation.

Keep the Collector running in both cases. Envoy adds the same 700 ms delay per
gRPC request to simulate export latency. This is a shared test condition, not a
separate failure case. The Collector uses a debug exporter and does not persist logs.

## 1. Start the current configuration

Use Docker Compose, Java 17 for `make gem`, `curl` and `jq`. From the repository root:

```sh
make gem
cd tests/integration/spring-tcp
unset PIPELINE_WORKERS PIPELINE_BATCH_SIZE NUM_CONSUMERS QUEUE_SIZE MAX_BATCH_SIZE SCHEDULE_DELAY_MILLIS
unset BLOCK_ON_OVERFLOW APPEND_TIMEOUT RING_BUFFER_SIZE OTLP_TIMEOUT LS_JAVA_OPTS CLIENT_JAVA_OPTS OTLP_ENDPOINT
docker compose --env-file baseline.env -f compose.yml -f compose.latency.yml up -d --build --wait
until curl -fsS http://localhost:18090/health | jq -e '.connected == true' >/dev/null; do sleep 1; done
```

Open [Grafana](http://localhost:21300/d/spring-tcp-pressure). No login is required.

## 2. Prepare and send the load

Warm up without added latency:

```sh
curl -fsS -X POST 'http://localhost:18474/runtime_modify?fault.http.delay.fixed_delay_percent=0'
curl -fsS http://localhost:18090/runs -H 'Content-Type: application/json' \
  -d '{"records":40000,"threads":16,"payloadBytes":8192,"ratePerSecond":13000}'
curl -fsS http://localhost:18090/runs/current | jq
```

Wait for `finished=true`, `pending=0`, and zero plugin queue and exports in flight
in Grafana. Verify 40,000 Collector receipts and no drops. Record the counters,
then enable the delay and start the measured load:

```sh
curl -fsS -X POST 'http://localhost:18474/runtime_modify?fault.http.delay.fixed_delay_percent=100&fault.http.delay.fixed_duration_ms=700'
sleep 20
curl -fsS http://localhost:18090/runs -H 'Content-Type: application/json' \
  -d '{"records":3900000,"threads":16,"payloadBytes":8192,"ratePerSecond":13000,"maxDurationSeconds":900}'
curl -fsS http://localhost:18090/runs/current | jq
```

Wait for the same drain conditions. Blocking or host saturation can extend
execution beyond five minutes; the generator stops after 900 seconds if unfinished.
Save the Grafana interval and counter changes before switching configurations.

## 3. Run the tuned configuration

After the current configuration drains, recreate Spring and Logstash. Prometheus
stays running so both cases remain visible:

```sh
docker compose --env-file tuned.env -f compose.yml -f compose.latency.yml \
  up -d --no-deps --force-recreate --wait logstash spring-client
until curl -fsS http://localhost:18090/health | jq -e '.connected == true' >/dev/null; do sleep 1; done
```

Repeat step 2 with exactly the same load.

## 4. Compare end-to-end results

Use [monitoring.md](monitoring.md) to compare both intervals:

- Delivery: generated logs, Logback drops, plugin `queue_full`, successful exports
  and Collector receipts. Use counter changes to exclude warmup and previous runs.
- Application impact: actual logs/s, logger latency and pending Logback events.
- Logstash: plugin queue peak, blocked producers, pipeline pressure, CPU and heap.
- Collector: received logs/s, refusals, export failures, CPU and memory. Verify it
  can receive the full target load before attributing a slowdown to Logstash.

The current configuration is expected to drop logs when its plugin queue fills.
The tuned configuration should deliver all records without sustained queue blocking
at the target rate. A slower generator with no drops still indicates backpressure.
Client `sent` counts TCP writes; final Collector receipt is the delivery check here.

## 5. Stop

Save the results before removing the stack and its history:

```sh
docker compose --env-file tuned.env -f compose.yml -f compose.latency.yml down -v
```
