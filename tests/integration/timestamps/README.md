# Test identical timestamps in Loki

Loki can treat logs with the same stream labels, timestamp, and message as
duplicates, returning only one entry. The plugin adds a nanosecond offset to
distinguish those events.

This demo sends 1,000 logs concurrently with the same microsecond timestamp and
message. The Collector sends two copies to Loki: `timestamp-fixed` keeps the
plugin's timestamp; `timestamp-control` restores the original timestamp to
simulate sending without the fix.

1. Build the plugin gem (`make gem` from the repository root). With Docker running,
   start the demo:

   ```sh
   cd tests/integration/timestamps
   docker compose up -d --build --wait
   ```

2. Generate the logs and copy the printed `run_id`:

   ```sh
   docker compose run --rm generator
   ```

3. Wait a few seconds, then query Loki using `curl` and `jq`:

   ```sh
   run_id="REPLACE_WITH_PRINTED_RUN_ID"
   curl -fsSG http://localhost:13100/loki/api/v1/query_range \
     -H 'X-Loki-Response-Encoding-Flags: categorize-labels' \
     --data-urlencode "query={service_name=~\"timestamp-(control|fixed)\"} | run_id=\"$run_id\"" \
     --data-urlencode 'since=1h' \
     --data-urlencode 'limit=2000' \
     | jq '.data.result[] | {
         service: .stream.service_name,
         records: (.values | length),
         unique_ids: ([.values[][2].structuredMetadata.record_id // empty] | unique | length),
         unique_timestamps: ([.values[][0]] | unique | length)
       }'
   ```

   Expected results:

   | Service | Records | Unique IDs | Unique timestamps |
   | --- | ---: | ---: | ---: |
   | `timestamp-control` | 1 | 1 | 1 |
   | `timestamp-fixed` | 1,000 | 1,000 | 1,000 |

   This difference reproduces the problem and verifies that the fix preserves all
   1,000 events. If both return 1,000, the problem was not reproduced. If results
   are empty or incomplete, repeat the query after a few seconds and check
   `docker compose logs logstash collector` for export errors.

4. Stop the demo:

   ```sh
   docker compose down
   ```

## Test with the fix disabled in Java

Temporarily change this line in `src/main/java/org/otlp/Otlp.java`:

```diff
- Instant adjustedTimestamp = timestampWithNanosecondDisambiguation(eventTimestamp);
+ Instant adjustedTimestamp = eventTimestamp;
```

From the repository root, rebuild and run:

```sh
make gem
docker compose -f tests/integration/timestamps/compose.yml up -d --build --force-recreate --wait
docker compose -f tests/integration/timestamps/compose.yml run --rm generator
```

Repeat the query above with the new `run_id`: `timestamp-fixed` should now also
return only **1 record**. Restore the original Java line and repeat these commands
and the query; `timestamp-fixed` should return **1,000 records** again.
