# Test identical timestamps in Loki

Loki can deduplicate logs with identical labels, timestamp and message. This test
sends 1,000 concurrent records: `timestamp-control` uses the original microsecond
timestamp; `timestamp-fixed` keeps the plugin's nanosecond adjustment.

1. Build the gem with Java 17 and `make gem` from the repository root, then start:

   ```sh
   cd tests/integration/timestamps
   docker compose up -d --build --wait
   ```

2. Run locally with Python 3 and copy the printed `run_id`:

   ```sh
   python3 generate.py
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
         unique_timestamps: ([.values[][0]] | unique | length)
       }'
   ```

   Expected results:

   | Service | Records | Unique timestamps |
   | --- | ---: | ---: |
   | `timestamp-control` | 1 | 1 |
   | `timestamp-fixed` | 1,000 | 1,000 |

   If both return 1,000, the deduplication was not reproduced. If results are
   incomplete, wait a few seconds and repeat the query.

4. Optionally check Loki directly, using local Python 3:

   ```sh
   python3 reproduce_loki_dedupe.py
   ```

   Expect `exact_duplicate_query_count=1`, `ns_disambiguated_query_count=5` and `result=PASS`.

5. Stop the demo:

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
python3 tests/integration/timestamps/generate.py
```

Repeat the query above with the new `run_id`: `timestamp-fixed` should now also
return only **1 record**. Restore the original Java line and repeat these commands
and the query; `timestamp-fixed` should return **1,000 records** again.
