# Queue backpressure

Compare `block_on_overflow=false` and `true` with the same 720,000 records and
300 ms of gRPC response latency. Defaults: one export worker, a 2,048-record
queue, batches of up to 512, four Logstash pipeline workers and a 512 MiB heap.
The Collector acknowledges records and exposes counts; this test has no storage backend.

Use Java 17, Docker Compose, local Python 3, `curl` and `jq`. Stop other scenarios
using ports `18082`, `20600`, `19888`, `18979`, `20090` or `18474` first.

1. Run `make gem` from the repository root. Start the dependencies and apply
   latency before starting Logstash:

   ```sh
   cd tests/integration/backpressure
   unset NUM_CONSUMERS QUEUE_SIZE MAX_BATCH_SIZE LS_JAVA_OPTS SCHEDULE_DELAY_MILLIS OTLP_TIMEOUT BLOCK_ON_OVERFLOW
   docker compose build logstash
   docker compose up -d collector toxiproxy
   LATENCY_MS=300
   curl --retry 10 --retry-connrefused --retry-delay 1 -fsS -X POST http://localhost:18474/proxies/otlp/toxics \
     -H 'Content-Type: application/json' \
     -d "{\"name\":\"response_latency\",\"type\":\"latency\",\"stream\":\"downstream\",\"attributes\":{\"latency\":$LATENCY_MS,\"jitter\":0}}"
   BLOCK_ON_OVERFLOW=false docker compose up -d --wait
   ```

   Queue, batch, worker, heap and timeout settings accept the environment
   overrides shown above. Keep them identical between runs. Reusing an existing
   proxy also reuses its toxic; remove `response_latency` before creating it again.

2. Open [Prometheus](http://localhost:20090/query). In another terminal, watch
   container resources with `docker stats $(docker compose ps -q logstash collector)`.
   Record Collector counts before each run, then send the fixed dataset:

   ```sh
   curl -fsS http://localhost:19888/metrics | grep '^otelcol_receiver_accepted_log_records'
   COUNT=720000 DURATION_SECONDS=0 RATE_PER_SECOND=12000 REQUEST_BATCH_SIZE=100 CONCURRENCY=16 PAYLOAD_BYTES=1024 ROUNDS=1 TIMESTAMP_GROUP_SIZE=0 python3 ../consumers/generate.py
   ```

   The target is 12,000 records/s, about 60 seconds without downstream pressure.
   `COUNT` keeps both runs equal; use the same smaller count for a shorter test.
   Check the actual duration, accepted count and failures. HTTP acceptance does
   not confirm OTLP delivery. With `false`, expect `queue_full` drops when the
   queue fills. Wait for the plugin queue and inflight records to reach zero,
   then save its counters:

   ```sh
   curl -fsS http://localhost:20600/_node/stats \
     | jq '{jvm: .jvm, process: .process, flow: .pipelines.main.flow, output: (.pipelines.main.plugins.outputs[] | select(.id == "consumers_test"))}'
   curl -fsS http://localhost:19888/metrics | grep '^otelcol_receiver_accepted_log_records'
   ```

   Generator duration ends after the last HTTP response. Time until drained starts
   with the generator and also includes exporting the remaining records; it is
   not an additional duration. The injected latency deliberately makes the
   destination slow, so a blocking run can take much longer than 60 seconds.

3. Recreate only Logstash, then repeat the exact generator command and snapshots
   from step 2:

   ```sh
   BLOCK_ON_OVERFLOW=true docker compose up -d --no-deps --force-recreate --wait logstash
   ```

   Plugin counters restart; Collector counters continue. Compare the Collector
   increase for each run. With `true`, full-queue producers wait for space, the
   input slows down, and the run can take several minutes. There is no separate
   queue-wait timeout; interruption or processor shutdown cancels the wait.
   Healthy exports should yield no `queue_full` drops. After a complete run with
   no HTTP or export failures and a drained queue, successful exports and the
   Collector increase should equal the accepted count. HTTP timeouts leave
   acceptance uncertain; repeat both runs at a lower load if they occur.

4. Compare the load and idle intervals with these queries:

   | Check | PromQL |
   | --- | --- |
   | Waiting records | `otel_sdk_processor_log_queue_size{plugin_id="consumers_test"}` |
   | Highest queue occupancy since startup | `otlp_processor_log_queue_peak_size{plugin_id="consumers_test"}` |
   | Queue drops | `sum(otel_sdk_processor_log_processed_total{plugin_id="consumers_test",error_type="queue_full"})` |
   | Producers waiting for space | `otlp_processor_log_queue_blocked_producers{plugin_id="consumers_test"}` |
   | Completed wait seconds per second | `rate(otlp_processor_log_queue_blocked_duration_seconds_total{plugin_id="consumers_test"}[5m])` |
   | Pipeline input pressure | `logstash_pipeline_queue_backpressure{pipeline="main"}` |
   | Output worker use (%) | `logstash_output_worker_utilization{plugin_id="consumers_test"}` |
   | Records in flight | `sum(otel_sdk_exporter_log_inflight{plugin_id="consumers_test"})` |
   | Successful exports | `sum(otel_sdk_exporter_log_exported_total{plugin_id="consumers_test",error_type=""})` |
   | Failed exports | `sum(otel_sdk_exporter_log_exported_total{plugin_id="consumers_test",error_type!=""})` |
   | CPU cores used | `rate(logstash_process_cpu_milliseconds_total[30s]) / 1000` |
   | Heap used | `logstash_jvm_heap_used_bytes` |
   | Live JVM threads | `logstash_jvm_threads` |
   | GC seconds per second | `(rate(logstash_jvm_gc_young_collection_milliseconds_total[30s]) + rate(logstash_jvm_gc_old_collection_milliseconds_total[30s])) / 1000` |

   The two `otlp_processor_log_queue_blocked_*` metrics are plugin metrics,
   with `otel_component_type="shared_queue_log_processor"` and
   `otel_component_name="shared_queue_log_processor/consumers_test". The duration counter adds each producer's
   elapsed wait when that wait ends, including cancellation. Concurrent waits
   add together, so its rate can exceed one. A wait still in progress is absent
   from this counter until it ends. Error series may be absent before an error.

   The peak metric updates on every enqueue, independently of scraping. After
   filling and draining this queue, current size should be `0` and peak should
   stay at `2048` (or your configured capacity). Repeated reads do not reset it;
   recreating Logstash resets it to `0`. It excludes batches outside the queue.
   It retains the highest occupancy, not the timing or frequency of peaks.

   Prometheus scrapes every 5 seconds here. With a production scrape interval
   of 60 seconds, the blocked-producer gauge can miss brief peaks. Use the
   duration counter with `rate(...[5m])` as well; it measures completed waits,
   and does not count blocked producers directly. A five-minute rate window
   can include the preceding run; select the time range accordingly. Logstash's
   [flow metrics](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestats)
   measure input queue pressure and worker time separately from the plugin queue.

5. Once queue and inflight records reach zero, compare CPU, heap and threads with the idle
   baseline. For a separate recovery check, repeat the same load with `true`
   and remove the latency while it is running:

   ```sh
   curl -fsS -X DELETE http://localhost:18474/proxies/otlp/toxics/response_latency
   ```

   Exports should speed up; queue, inflight records and blocked producers should
   return to zero after the load finishes. The duration counter keeps its total.
   Restore the same latency before any further false/true comparison. With
   the queue drained, stop the stack:

   ```sh
   docker compose stop -t 120 logstash
   docker inspect --format '{{.State.ExitCode}} {{.State.OOMKilled}}' $(docker compose ps -aq logstash)
   docker compose down
   ```

   Expect exit code `0` and `OOMKilled=false`. This checks queue pressure and
   recovery with an acknowledging Collector; it does not prove persistence or
   loss-free delivery during destination failures.
