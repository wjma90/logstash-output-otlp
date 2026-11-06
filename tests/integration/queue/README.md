# Test export queue metrics

This test uses a shared 32-record queue, one consumer, batches of 1, and a JSON exporter for Prometheus.
Metrics appear under the output's `sdk_metrics` in Logstash's Node Stats API.
Prometheus exposes these SDK and plugin series:

| Metric | Meaning |
| --- | --- |
| `otel_sdk_processor_log_queue_size` | Records waiting in the shared queue, excluding the export in progress. |
| `otel_sdk_processor_log_queue_capacity` | Queue capacity. |
| `otlp_processor_log_queue_peak_size` | Highest queue occupancy since this output instance started; retained after draining. |
| `otel_sdk_processor_log_processed_total{error_type="queue_full"}` | Total records dropped because the queue was full. |

Metrics refresh every second. Drops produce a `WARN`, limited to one every 30 seconds.
Run the generator locally with Python 3; use `curl` and `jq` to check the results.
The `otel_sdk_*` series use OTel SDK names. The peak is a plugin-specific gauge;
it resets when the output instance is recreated, not when the queue drains.

This demo uses JSON Exporter with explicit mappings. `kuskoman/logstash-exporter`
v1.9.2 ignores these custom fields; using it alone requires adding support in its
[output model and collector](https://github.com/kuskoman/logstash-exporter/blob/v1.9.2/fetcher/responses/nodestats_response.go#L170-L192).

1. Build with Java 17 and `make gem` from the repository root, then start:

   ```sh
   cd tests/integration/queue
   docker compose up -d --build --force-recreate --wait
   ```

2. **Success:** send 16 records, then inspect the output's native metrics:

   ```sh
   python3 generate.py
   sleep 3
   curl -fsS http://localhost:19600/_node/stats/pipelines/main \
     | jq '.pipelines.main.plugins.outputs[] | select(.id == "queue_test") | .sdk_metrics'
   ```

   Expect queue size 0, capacity 32 and no drops. The Collector receives all 16
   records and no overflow WARN appears. The SDK emits the `queue_full` error
   series only after a drop, so it may be absent in this case.

3. Open [Prometheus](http://localhost:19090/query). Query each metric and select
   the graph view to see its history:

   ```promql
   otel_sdk_processor_log_queue_size
   otel_sdk_processor_log_queue_capacity
   otlp_processor_log_queue_peak_size
   otel_sdk_processor_log_processed_total{error_type="queue_full"}
   otel_sdk_exporter_log_inflight
   otel_sdk_exporter_log_exported_total{error_type=""}
   otel_sdk_exporter_operation_duration_seconds_sum / otel_sdk_exporter_operation_duration_seconds_count
   ```

   To check whether the queue is full (1) or not (0), query:

   ```promql
   otel_sdk_processor_log_queue_size == bool otel_sdk_processor_log_queue_capacity
   ```

   `exported` counts completed exports, including failures. Empty `error_type`
   selects successes; `error_type!=""` selects failures. After step 2, successful
   exported records should be 16 and inflight should be 0.
   The last query gives the average export duration since startup, in seconds, including retries.

   Queue drops are reported by `otel_sdk_processor_log_processed_total{error_type="queue_full"}`.
   They do not appear in `otel_sdk_exporter_log_exported_total`: those records were
   dropped before reaching the exporter. Exporter errors describe failed sends,
   such as HTTP 404 or timeouts.

4. **Full queue:** run this block together. The 30-second sleep after generation
   gives you time to inspect Prometheus while the queue is full. Keep the total
   Collector pause below the 120-second request timeout, including generation time.

   ```sh
   docker compose up -d --force-recreate --wait
   docker compose pause collector
   COUNT=1000 python3 generate.py
   sleep 30
   curl -fsS http://localhost:19600/_node/stats/pipelines/main \
     | jq '.pipelines.main.plugins.outputs[] | select(.id == "queue_test") | .sdk_metrics'
   docker compose unpause collector
   sleep 3
   ```

5. Repeat the query from step 2 and check the Prometheus graphs over the last 15 minutes:

   | Metric | Success | Collector paused | After resuming |
   | --- | ---: | ---: | ---: |
   | SDK processed with `error_type="queue_full"` | Absent (no drops) | 967 | 967 |
   | SDK queue size | 0 | 32 | 0 |
   | SDK queue capacity | 32 | 32 | 32 |
   | Plugin queue peak | ≤16 | 32 | 32 |
   | Queue-full query above | 0 | 1 | 0 |

   After resuming, 33 records reach the Collector. The drop counter remains at
   967 because those records were already lost, even though the queue is now empty.

   ```sh
   docker compose logs logstash | grep 'OTLP export queue full'
   ```

The first WARN may appear before the burst ends and show fewer drops than the final metric.

6. **Export failure:** use an invalid receiver path and send 16 records:

   ```sh
   OTLP_ENDPOINT=http://collector:4318/missing docker compose up -d --force-recreate --wait
   python3 generate.py
   sleep 3
   ```

   Query `otel_sdk_exporter_log_exported_total{error_type="404"}` in Prometheus:
   expect 16 failed records, 0 inflight and no queue drops. Logstash also prints
   `OTLP export failed`. To stop:

   ```sh
   docker compose down
   ```

SDK metric conventions are in Development; see [SDK self-monitoring](https://opentelemetry.io/docs/languages/java/sdk/#sdk-self-monitoring-metrics).
