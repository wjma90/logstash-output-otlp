# Monitor pressure and delivery

Start the stack using the [README](README.md), then open [Grafana](http://localhost:21300/d/spring-tcp-pressure). No login is needed locally.
Prometheus scrapes every 2 seconds; dashboard rates use 30-second windows.

## Read the timeline

1. Compare the current and tuned configurations at 13,000 logs/s. Select each full run interval, including idle time and drain.
2. Compare client attempts, Logback admission, TCP writes and Collector receipt.
3. Check queue size, blocked producers and client pending events alongside logger latency, CPU and memory.
4. After generation finishes, wait for client pending events, the plugin queue and exports in flight to reach zero. Compare counter deltas and resource levels after drain.

Java Agent 2.27.0 measures Spring's JVM; the SDK measures logging calls and Logback events.
Both send metrics through a separate Collector. Keep both Collectors running during the comparison.

## Useful queries

Run these in [Prometheus](http://localhost:21090/query). The dashboard also shows exporter failures and Collector refusals.

| Check | PromQL |
| --- | --- |
| Client attempts, records/s | `sum(rate(spring_tcp_logs_attempted_total{job="spring-otel"}[30s]))` |
| Collector receipt, records/s | `sum(rate({__name__="otelcol_receiver_accepted_log_records_{records}_total",job="collector"}[30s]))` |
| Current plugin queue | `otel_sdk_processor_log_queue_size{plugin_id="consumers_test"}` |
| Retained queue peak | `otlp_processor_log_queue_peak_size{plugin_id="consumers_test"}` |
| Plugin queue drops, total | `otel_sdk_processor_log_processed_total{plugin_id="consumers_test",error_type="queue_full"}` |
| Blocked producers | `otlp_processor_log_queue_blocked_producers{plugin_id="consumers_test"}` |
| Logger calls in progress | `spring_tcp_logging_calls_inflight{job="spring-otel"}` |
| Client pending events | `spring_tcp_pending_events{job="spring-otel"}` |
| Completed logger calls, p99 | `histogram_quantile(0.99, sum by (le) (rate(spring_tcp_log_call_duration_seconds_bucket{job="spring-otel"}[30s])))` |
| Records in export | `sum(otel_sdk_exporter_log_inflight{plugin_id="consumers_test"})` |
| Logstash CPU, cores | `rate(logstash_process_cpu_milliseconds_total{job="logstash"}[30s]) / 1000` |
| Logstash heap, bytes | `logstash_jvm_heap_used_bytes{job="logstash"}` |
| Collector CPU, cores | `sum(rate(otelcol_process_cpu_seconds_total{job="collector"}[30s]))` |
| Collector RSS, bytes | `sum(otelcol_process_memory_rss_bytes{job="collector"})` |

## Interpretation

- Counters include warmup. Compare before/after deltas. Client `sent` counts TCP writes; verify receipt at the Collector. This test does not persist logs in a backend.
- Exporter metrics have one series per consumer. Sum them to measure the whole output.
- Logger and queue-wait durations update when calls finish. During blocking, watch calls in progress and blocked producers first. The p99 is a bucket estimate.
- Logstash 8.11.3 reports fixed zeros for internal memory-queue occupancy. Use input wait and worker activity; `events.in - events.out` is not queue depth.
- The plugin queue has its own occupancy metric. Its retained peak resets when the output restarts, not on each scrape; records in export are outside that queue.
- CPU value `1` means one busy core. RSS is resident process memory; Go heap measures allocated objects. Do not add RSS and heap or treat them as equivalent.
- The local Collector uses an OTLP receiver and debug exporter. Envoy adds 700 ms per gRPC request; this does not reproduce production Collector capacity. Check actual SDK export duration.
- `up{job="spring-otel"}` checks the metrics Collector scrape. Use [client health](http://localhost:18090/health) for Spring and TCP status. App series expire after 10 seconds without updates.
- Error series may appear only after the first failure. Confirm scrape health and queue metrics before interpreting an absent error series as no errors.
- HTTP metrics cover control endpoints. The workload generates logs. `jvm_thread_count` counts platform threads, including the generator's threads, and excludes Spring API virtual threads.
