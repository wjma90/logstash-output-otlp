# Shared queue consumers

Compare one and four consumers with the same queue, batches and input load.
The default queue holds 16,384 waiting records; each consumer exports up to 512.
Use Java 17, Docker Compose, local Python 3, `curl` and `jq`.

1. Build the gem with `make gem` from the repository root, then start:

   ```sh
   cd tests/integration/consumers
   NUM_CONSUMERS=1 docker compose up -d --build --wait
   ```

2. Open [Prometheus](http://localhost:20090/query). In another terminal, watch
   container CPU and memory before, during and after the load:

   ```sh
   docker stats $(docker compose ps -q logstash collector)
   ```

   Send three rounds of 50,000 records, with a 1 KiB message per record:

   ```sh
   COUNT=50000 CONCURRENCY=16 PAYLOAD_BYTES=1024 ROUNDS=3 PAUSE_SECONDS=15 python3 generate.py
   sleep 30
   curl -fsS http://localhost:20600/_node/stats \
     | jq '{jvm: .jvm, process: .process, output: .pipelines.main.plugins.outputs[] | select(.id == "consumers_test")}'
   ```

   The generator prints HTTP acceptance, elapsed seconds and accepted records/s
   for each round. HTTP acceptance does not confirm OTLP delivery. On a fresh
   successful run, the exporter and Collector should report 150,000 successful
   records, no drops or failed exports, and queue/inflight should return to zero.
   If the generator reports failures, reduce `CONCURRENCY` before comparing runs.

3. Use these Prometheus queries. Select a range covering the load and recovery:

   | Check | Query |
   | --- | --- |
   | Waiting records | `otel_sdk_processor_log_queue_size{plugin_id="consumers_test"}` |
   | Drops | `sum(otel_sdk_processor_log_processed_total{plugin_id="consumers_test",error_type="queue_full"})` |
   | Records in flight | `sum(otel_sdk_exporter_log_inflight{plugin_id="consumers_test"})` |
   | Successful records | `sum(otel_sdk_exporter_log_exported_total{plugin_id="consumers_test",error_type=""})` |
   | Failed records | `sum(otel_sdk_exporter_log_exported_total{plugin_id="consumers_test",error_type!=""})` |
   | Successful records/s | `sum(rate(otel_sdk_exporter_log_exported_total{plugin_id="consumers_test",error_type=""}[30s]))` |
   | Collector accepted records | `sum(otelcol_receiver_accepted_log_records__records__total{job="collector"})` |
   | Heap used | `logstash_jvm_heap_used_bytes` |
   | Live JVM threads | `logstash_jvm_threads` |
   | CPU cores used | `rate(logstash_process_cpu_milliseconds_total[30s]) / 1000` |
   | GC seconds/s | `(rate(logstash_jvm_gc_young_collection_milliseconds_total[30s]) + rate(logstash_jvm_gc_old_collection_milliseconds_total[30s])) / 1000` |

   Error series may be absent until the first error. Exporter metrics have one
   component series per consumer, so use `sum` for output totals.

4. Compare four consumers. Recreate only Logstash to preserve the Prometheus
   graphs, then repeat the same generator command from step 2:

   ```sh
   NUM_CONSUMERS=4 docker compose up -d --no-deps --force-recreate --wait logstash
   ```

   Plugin counters restart; Collector counters continue. Compare their increase
   during each run. Record successful records/s, drops, peak heap, CPU and thread
   count. More consumers need not improve a run limited by the generator or CPU.

5. Check retention after repeated rounds. Once queue and inflight are zero, take
   a live-object histogram and thread dump, repeat the load, wait for idle, and
   take them again:

   ```sh
   docker compose exec -T logstash /usr/share/logstash/jdk/bin/jcmd 1 GC.class_histogram > /tmp/otlp-heap-before.txt
   docker compose exec -T logstash /usr/share/logstash/jdk/bin/jcmd 1 Thread.print > /tmp/otlp-threads-before.txt
   COUNT=50000 CONCURRENCY=16 PAYLOAD_BYTES=1024 ROUNDS=3 PAUSE_SECONDS=15 python3 generate.py
   sleep 30
   docker compose exec -T logstash /usr/share/logstash/jdk/bin/jcmd 1 GC.class_histogram > /tmp/otlp-heap-after.txt
   docker compose exec -T logstash /usr/share/logstash/jdk/bin/jcmd 1 Thread.print > /tmp/otlp-threads-after.txt
   ```

   Histogram collection can pause the JVM; do it outside throughput measurements.
   At idle, export workers should be waiting and CPU should approach its baseline.
   Live records and thread counts should not keep growing across equal rounds.
   JVM committed memory can stay high after GC; this alone does not indicate a leak.

   With the queue drained, exercise three pipeline reloads. Change the config
   text before each SIGHUP: an unchanged config does not recreate this pipeline.
   The first two reloads add a blank line; the third restores the original file.

   ```sh
   curl -fsS http://localhost:20600/_node/stats/reloads | jq '.reloads'
   reload_backup=$(mktemp)
   cp logstash.conf "$reload_backup"
   for run in 1 2; do
     printf '\n' >> logstash.conf
     docker compose kill -s SIGHUP logstash
     sleep 10
     COUNT=16 python3 generate.py
     sleep 2
     curl -fsS http://localhost:20600/_node/stats/reloads | jq '.reloads'
     docker compose exec -T logstash /usr/share/logstash/jdk/bin/jcmd 1 Thread.print | grep -c '^"otlp-export-worker-'
   done
   cat "$reload_backup" > logstash.conf
   rm "$reload_backup"
   docker compose kill -s SIGHUP logstash
   sleep 10
   COUNT=16 python3 generate.py
   sleep 2
   curl -fsS http://localhost:20600/_node/stats/reloads | jq '.reloads'
   docker compose exec -T logstash /usr/share/logstash/jdk/bin/jcmd 1 Thread.print | grep -c '^"otlp-export-worker-'
   ```

   Sending records starts the consumers of each new pipeline. Expect `successes`
   to increase by three, no new failures, and four consumer threads after each
   reload. If a reload is still running, wait for its success
   before sending the next SIGHUP.

6. Saturation and recovery: restart with a small shared queue, pause the Collector
   and send a burst. Run the block together:

   ```sh
   QUEUE_SIZE=32 MAX_BATCH_SIZE=1 NUM_CONSUMERS=4 OTLP_TIMEOUT=60 docker compose up -d --no-deps --force-recreate --wait logstash
   docker compose pause collector
   COUNT=1000 CONCURRENCY=16 PAYLOAD_BYTES=1024 python3 generate.py
   sleep 5
   curl -fsS http://localhost:20600/_node/stats/pipelines/main \
     | jq '.pipelines.main.plugins.outputs[] | select(.id == "consumers_test") | .sdk_metrics'
   docker compose unpause collector
   sleep 5
   docker compose logs logstash | grep 'OTLP export queue full'
   ```

   While paused, expect queue size 32, four records in flight and drops. Once
   resumed, queue/inflight return to zero; dropped records remain lost.

   To exercise request timeouts, repeat with `OTLP_TIMEOUT=2` and leave the
   Collector paused for 10 seconds after sending. Failed exports should increase
   and Logstash should print `OTLP export failed`. Unpause the Collector, wait
   for the queue to drain and send 16 more records to verify recovery.

7. Run for 30 minutes with mixed message sizes and a target of 200 records/s:

   ```sh
   NUM_CONSUMERS=4 docker compose up -d --no-deps --force-recreate --wait logstash
   DURATION_SECONDS=1800 RATE_PER_SECOND=200 PAYLOAD_SIZES=1024,8192,65536 CONCURRENCY=16 python3 generate.py
   sleep 30
   ```

   `DURATION_SECONDS` replaces `COUNT`; other defaults stay unchanged. Progress
   prints every 30 seconds, ending with `complete: true`. Compare the final
   accepted count with exporter and Collector counter increases. Expect zero
   failures/drops and queue/inflight zero. Repeat the idle histogram/thread checks
   from step 5; live objects and threads should not grow with elapsed time.

   For a separate one-hour run with native JVM memory tracking:

   ```sh
   LS_JAVA_OPTS='-Xms256m -Xmx512m -XX:NativeMemoryTracking=detail' NUM_CONSUMERS=4 docker compose up -d --no-deps --force-recreate --wait logstash
   DURATION_SECONDS=120 RATE_PER_SECOND=600 PAYLOAD_SIZES=1024,8192,65536 CONCURRENCY=16 python3 generate.py
   docker compose exec -T logstash /usr/share/logstash/jdk/bin/jcmd 1 VM.native_memory baseline
   DURATION_SECONDS=3600 RATE_PER_SECOND=200 PAYLOAD_SIZES=1024,8192,65536 CONCURRENCY=16 python3 generate.py
   sleep 180
   docker compose exec -T logstash /usr/share/logstash/jdk/bin/jcmd 1 VM.native_memory summary.diff
   ```

   Compare the NMT categories, process memory from `docker stats`, and the live
   histograms from step 5. NMT adds diagnostic overhead and does not track every
   native allocation; a stable heap alone does not rule out a native-memory leak.

   After saving the final snapshots, check whether the C allocator retains free
   pages. Compare process memory before and after this Linux JVM diagnostic:

   ```sh
   docker compose exec -T logstash /usr/share/logstash/jdk/bin/jcmd 1 System.trim_native_heap
   ```

8. Reload with pending records and an unavailable Collector:

   ```sh
   QUEUE_SIZE=32 MAX_BATCH_SIZE=1 NUM_CONSUMERS=4 OTLP_TIMEOUT=2 docker compose up -d --no-deps --force-recreate --wait logstash
   docker compose pause collector
   COUNT=1000 python3 generate.py
   curl -fsS http://localhost:20600/_node/stats/reloads | jq '.reloads'
   reload_backup=$(mktemp)
   cp logstash.conf "$reload_backup"
   printf '\n' >> logstash.conf
   docker compose kill -s SIGHUP logstash
   sleep 30
   curl -fsS http://localhost:20600/_node/stats/reloads | jq '.reloads'
   docker compose unpause collector
   COUNT=16 python3 generate.py
   sleep 5
   docker compose exec -T logstash /usr/share/logstash/jdk/bin/jcmd 1 Thread.print | grep -c '^"otlp-export-worker-'
   cat "$reload_backup" > logstash.conf
   rm "$reload_backup"
   ```

   Expect one successful reload, four consumer threads after the new records,
   successful delivery of those 16 records, and errors for expired old batches.
   Reload resets plugin counters. If the reload is still running, wait for its
   success before sending new records. The old queue is not transferred.

9. Stop while records are pending. Keep the small queue and two-second timeout
   from step 8:

   ```sh
   docker compose pause collector
   COUNT=1000 python3 generate.py
   time docker compose stop -t 120 logstash
   docker inspect --format '{{.State.ExitCode}} {{.State.OOMKilled}}' $(docker compose ps -aq logstash)
   docker compose logs logstash | grep -E 'OTLP export failed|OTLP shutdown failed|Logstash shut down'
   docker compose unpause collector
   ```

   Expect exit code `0`, `OOMKilled=false`, and failed-export logs. Failed batches
   are not requeued. `timeout` applies to each batch export; draining many batches
   can take longer. Exit code `137` indicates a forced kill, not a successful drain.

10. Replace the Collector with a different IP behind the same DNS name:

   ```sh
   docker compose down
   COLLECTOR_IP=172.30.99.10 NUM_CONSUMERS=4 docker compose -f compose.yml -f compose.dns.yml up -d --wait
   COUNT=16 python3 generate.py
   sleep 5
   logstash_id=$(docker compose ps -q logstash)
   docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $(docker compose ps -q collector)
   COLLECTOR_IP=172.30.99.11 docker compose -f compose.yml -f compose.dns.yml up -d --no-deps --force-recreate collector
   docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $(docker compose ps -q collector)
   DURATION_SECONDS=60 RATE_PER_SECOND=10 python3 generate.py
   sleep 5
   test "$logstash_id" = "$(docker compose ps -q logstash)"
   curl -fsS http://localhost:20600/_node/stats/pipelines/main | jq '.pipelines.main.plugins.outputs[] | select(.id == "consumers_test") | .sdk_metrics'
   curl -fsS http://localhost:19888/metrics | grep otelcol_receiver_accepted_log_records
   ```

   The endpoint remains `http://collector:4318/v1/logs`; verify `.10` changes to
   `.11`, Logstash keeps the same container ID, and the new Collector receives
   records. DNS cache expiry can delay recovery and cause failed batches during
   the transition. Collector counters restart; plugin counters continue. The
   override reserves `172.30.99.0/24`; change it if that range is already in use.

11. With the Collector running and the queue drained, clean up:

   ```sh
   docker compose stop -t 120 logstash
   docker compose logs --tail=30 logstash
   docker compose -f compose.yml -f compose.dns.yml down
   ```

   Expect a normal Logstash shutdown without a forced kill. These runs can expose
   retention and idle CPU regressions; they do not prove the absence of every leak.

## Compare consumers with a slow Collector connection

Use this after stopping the previous Compose. Toxiproxy adds network latency
between Logstash and the local Collector; no production endpoint is used.

1. Start one consumer with a queue of 24,576 records and batches of up to 3,000:

   ```sh
   export QUEUE_SIZE=24576 MAX_BATCH_SIZE=3000 LS_JAVA_OPTS='-Xms1g -Xmx1g'
   docker compose -f compose.yml -f compose.latency.yml up -d collector toxiproxy
   curl --retry 10 --retry-connrefused --retry-delay 1 -fsS -X POST http://localhost:18474/proxies/otlp/toxics \
     -H 'Content-Type: application/json' \
     -d '{"name":"response_latency","type":"latency","stream":"downstream","attributes":{"latency":300,"jitter":0}}'
   NUM_CONSUMERS=1 docker compose -f compose.yml -f compose.latency.yml up -d --build --wait
   ```

2. Warm up, then send 12,000 records/s for two minutes:

   ```sh
   DURATION_SECONDS=30 RATE_PER_SECOND=2000 REQUEST_BATCH_SIZE=100 python3 generate.py
   DURATION_SECONDS=120 RATE_PER_SECOND=12000 REQUEST_BATCH_SIZE=100 python3 generate.py
   ```

   `REQUEST_BATCH_SIZE=100` sends JSON arrays to Logstash: 120 HTTP requests/s
   carry 12,000 records/s. It does not set the OTLP batch size. HTTP/2 flow
   control can make export duration exceed the configured 300 ms network delay;
   compare the measured duration and actual accepted rate between runs.
   Apply the delay before starting Logstash in both runs so connections start
   under the same conditions.

3. Wait for queue and inflight to reach zero. Record the counter increases and
   CPU/memory from steps 2–3 above. Recreate Logstash with two consumers and
   repeat the same warm-up and load commands:

   ```sh
   NUM_CONSUMERS=2 docker compose -f compose.yml -f compose.latency.yml up -d --no-deps --force-recreate --wait logstash
   ```

   Compare successful records, `queue_full` drops and resource use. After
   draining, accepted records must equal successful exports plus drops and
   failed exports. The Collector's accepted increase should match successful
   exports. More consumers should help when export waiting limits throughput;
   they do not guarantee higher throughput when CPU or the receiver is saturated.

4. Remove the test containers:

   ```sh
   docker compose -f compose.yml -f compose.latency.yml down
   unset QUEUE_SIZE MAX_BATCH_SIZE LS_JAVA_OPTS
   ```
