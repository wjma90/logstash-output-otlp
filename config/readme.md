# Loki Dedupe Test

This compose setup contains two independent checks:

- `loki-repro`: proves how Loki handles exact duplicate timestamps.
- `logstash`: verifies the OTLP plugin sends timestamps with nanosecond disambiguation.

## Prerequisites

Build the Logstash core jar and the local plugin gem before building the Logstash image.
The project expects the Logstash core jar to exist under `assets/logstash-9.0.0/logstash-core/build/libs`.

```bash
cd /Users/willianmarchan/Projects/BCP/O11Y/logstash-output-otlp
make gem
docker compose build
```

The Dockerfile installs the local `*.gem` with `--no-verify --local` only to test a gem built from this repository.
For a production-like image, install the published gem from RubyGems instead:

```dockerfile
FROM docker.elastic.co/logstash/logstash:9.0.0
RUN logstash-plugin install logstash-output-otlp
```

Gem page: https://rubygems.org/gems/logstash-output-otlp

The certificates in `config/tls` are local test certificates for this compose setup.
Do not reuse these private keys or certificates outside local testing.

## Test 1: Loki Exact Dedupe

Run:

```bash
docker compose up --abort-on-container-exit loki-repro
```

What this test sends:

```text
case=exact_duplicate
input=5 log lines
timestamp=1780598742704000000
line=Transaction completed
```

Expected result:

```text
exact_duplicate_input=5 exact_duplicate_query_count=1
```

Why:

Loki treats entries with the same stream labels, timestamp, and line as exact duplicates.

## Test 2: Loki With Nanosecond Disambiguation

The same `loki-repro` run also sends:

```text
case=ns_disambiguated
input=5 log lines
timestamps:
  1780598742704000001
  1780598742704000002
  1780598742704000003
  1780598742704000004
  1780598742704000005
line=Transaccion completa
```

Expected result:

```text
ns_disambiguated_input=5 ns_disambiguated_query_count=5
result=PASS
```

Why:

The log lines still share the same millisecond, but their nanosecond timestamps are different.

## Test 3: Logstash OTLP Plugin Output

Run:

```bash
docker compose up --abort-on-container-exit logstash
```

Show the collector output:

```bash
docker compose logs otel | rg "LogRecord #|ObservedTimestamp:|Timestamp:"
```

Expected evidence:

```text
ObservedTimestamp: 2026-06-04 20:05:25.763 +0000 UTC
Timestamp: 2026-06-04 20:05:25.763000001 +0000 UTC
```

The expected pattern is:

```text
ObservedTimestamp keeps millisecond precision.
Timestamp contains the same millisecond plus a nanosecond offset.
```

## Cleanup

Run:

```bash
docker compose down
```
