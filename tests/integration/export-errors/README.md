# Export error logging

This test sends five events to an OTLP/HTTP Collector without authentication.
Build the gem with Java 17 and `make gem` from the repository root.

1. Send the events:

   ```sh
   cd tests/integration/export-errors
   docker compose build
   docker compose up -d collector
   docker compose run --rm logstash
   docker compose logs collector
   ```

   The Collector should print `OTLP manual export test` for the five events.

2. Stop the destination and send again:

   ```sh
   docker compose stop collector
   docker compose run --rm --no-deps logstash
   ```

   Logstash should print `OTLP export failed: output_id=manual_otlp` with
   `records=5`.

3. Stop the test:

   ```sh
   docker compose down
   ```
