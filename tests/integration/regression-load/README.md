# Load, timestamps and recovery

Send 1,440,000 records at a target of 12,000 records/s through Logstash, Toxiproxy,
the Collector and Loki. Compare nanosecond timestamps with the original timestamps,
then repeat with a 35-second export outage.

Use Java 17, Docker Compose, local Python 3, `curl` and `jq`. Stop other scenarios
first: shared ports include Logstash input `18082`, its API `20600`, Prometheus
`20090`, Toxiproxy `18474`, Collector metrics `19888` and Loki `13100`.

Defaults: two consumers, a 24,576-record queue, batches of up to 3,000, a 1 GiB heap,
four pipeline workers and a 10-second request timeout (`timeout`). The reused
[consumer pipeline](../consumers/logstash.conf) exports over gRPC to `http://toxiproxy:4317`
with plugin ID `consumers_test` and service name `otlp-consumers-test`.

## Start with 300 ms export latency

Run `make gem` from the repository root. Clear earlier environment overrides and apply latency before starting Logstash:

```sh
cd tests/integration/regression-load
unset NUM_CONSUMERS QUEUE_SIZE MAX_BATCH_SIZE LS_JAVA_OPTS SCHEDULE_DELAY_MILLIS OTLP_TIMEOUT
docker compose up -d collector toxiproxy
curl --retry 10 --retry-connrefused --retry-delay 1 -fsS -X POST http://localhost:18474/proxies/otlp/toxics \
  -H 'Content-Type: application/json' \
  -d '{"name":"response_latency","type":"latency","stream":"downstream","attributes":{"latency":300,"jitter":0}}'
docker compose up -d --build --wait
```

Optionally warm up with 60,000 records at 2,000 records/s (about 30 seconds), without grouped source timestamps:

```sh
COUNT=60000 DURATION_SECONDS=0 RATE_PER_SECOND=2000 REQUEST_BATCH_SIZE=100 TIMESTAMP_GROUP_SIZE=0 python3 ../consumers/generate.py
```

Drain the queues and record counters before each measured run; warmup and earlier runs remain in cumulative totals.

## Run the load and compare Loki counts

```sh
load_report=$(mktemp)
COUNT=1440000 DURATION_SECONDS=0 RATE_PER_SECOND=12000 REQUEST_BATCH_SIZE=100 TIMESTAMP_GROUP_SIZE=1000 python3 ../consumers/generate.py | tee "$load_report"
run_id=$(jq -r 'select(.complete == true) | .run_id' "$load_report")
jq 'select(.complete == true)' "$load_report"
```

The generator uses 16 threads and 1 KiB messages, with 100 records per HTTP request.
Groups of 1,000 IDs share an original timestamp; successive groups differ by 1 ms.
Expect `accepted: 1440000` and `failed: 0` in about two minutes; check the printed
duration and rate. HTTP acceptance does not confirm persistence in Loki.

Check load and recovery in [Prometheus](http://localhost:20090/query):

| Check | Query |
| --- | --- |
| Waiting records | `otel_sdk_processor_log_queue_size{plugin_id="consumers_test"}` |
| Records in flight | `sum(otel_sdk_exporter_log_inflight{plugin_id="consumers_test"})` |
| Successful exports | `sum(otel_sdk_exporter_log_exported_total{plugin_id="consumers_test",error_type=""})` |
| Failed exports | `sum(otel_sdk_exporter_log_exported_total{plugin_id="consumers_test",error_type!=""})` |
| Queue drops | `sum(otel_sdk_processor_log_processed_total{plugin_id="consumers_test",error_type="queue_full"})` |
| CPU cores used | `rate(logstash_process_cpu_milliseconds_total[30s]) / 1000` |
| Heap used | `logstash_jvm_heap_used_bytes` |

Sum exporter series across consumers; error series may be absent before an error.
CPU and heap describe the process. Compare API and Collector counters per run:

```sh
curl -fsS http://localhost:20600/_node/stats/pipelines/main \
  | jq '.pipelines.main.plugins.outputs[] | select(.id == "consumers_test") | .sdk_metrics'
curl -fsS http://localhost:19888/metrics \
  | grep -E '^otelcol_(receiver_accepted_log_records|exporter_(queue_size|sent_log_records|send_failed_log_records))'
```

Wait for queue/inflight and both Collector exporter queues to reach zero.
With all records accepted and no drops or failures, successful plugin exports,
Collector accepted records and each Collector exporter's sent records should
increase by 1,440,000. Query Loki for this run:

```sh
curl -fsSG http://localhost:13100/loki/api/v1/query \
  --data-urlencode "query=sum by(service_name)(count_over_time({service_name=~\"otlp-consumers-test|timestamp-control\"} | run_id=\"$run_id\"[1h]))" \
  | jq '.data.result'
```

Expect 1,440,000 records for `otlp-consumers-test` and much fewer for `timestamp-control`,
which restores shared timestamps for Loki to deduplicate identical messages.
Loki stream sharding can change the control count. SDK success confirms the
Collector acknowledgment; this query checks Loki storage.

[collector.yaml](collector.yaml) caps batches at 1,000 in both pipelines to mitigate
Loki's internal 4 MiB gRPC limit for these 1 KiB messages; larger records can still
exceed it. Plugin batches remain at 3,000. Only this scenario overrides the shared
[Loki service](../common/loki/compose.yml) to allow 64 MB/s ingestion and a 128 MB burst.

## Interrupt exports for 35 seconds

Repeat the generator block above to capture a new `run_id`. In another terminal,
disable the proxy about 30 seconds into the load, then re-enable it:

```sh
curl -fsS -X POST http://localhost:18474/proxies/otlp \
  -H 'Content-Type: application/json' -d '{"enabled":false}'
sleep 35
curl -fsS -X POST http://localhost:18474/proxies/otlp \
  -H 'Content-Type: application/json' -d '{"enabled":true}'
```

If interrupted, run the `enabled:true` command before continuing. Expect WARN
`OTLP export queue full` and ERROR `OTLP export failed` in Logstash:

```sh
docker compose logs logstash | grep -E 'OTLP export queue full|OTLP export failed'
```

Queue drops and failed-export counters should increase and retain their totals
after recovery. Queue/inflight must return to zero and successful exports resume.
Drain the Collector queues and repeat the Loki query with the new run ID. Queue
drops are lost; failed exports can have uncertain delivery if the receiver
accepted records before the connection failed.

## Check resources and stop

Watch resources before, during and after load; press Ctrl-C to stop watching:

```sh
docker stats $(docker compose ps -q logstash collector loki)
```

After the queues drain, export workers should wait and CPU approach its idle
baseline. Optionally compare thread dumps after equal loads, then stop:

```sh
docker compose exec -T logstash /usr/share/logstash/jdk/bin/jcmd 1 Thread.print > /tmp/otlp-regression-threads.txt
time docker compose stop -t 120 logstash
docker inspect --format '{{.State.ExitCode}} {{.State.OOMKilled}}' $(docker compose ps -aq logstash)
docker compose down
rm "$load_report"
```

Expect exit code `0` and `OOMKilled=false` after draining. See [consumers](../consumers/README.md)
for shutdown with pending records, reloads and DNS recovery. This test does not inject `partial_success` or exercise TLS.
