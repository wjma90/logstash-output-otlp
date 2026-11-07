# Integration tests

Build the local gem with Java 17 and `make gem` from the repository root.
Use Docker Compose, `curl` and `jq`. Load generators use local Python 3;
the TLS test uses OpenSSL.

| Test | What to verify |
| --- | --- |
| [export-errors](export-errors/README.md) | Successful delivery and the error log when the destination is unavailable. |
| [tls](tls/README.md) | HTTP and gRPC delivery with a trusted CA, rejection with an unrelated CA, and optional verification bypass. |
| [queue](queue/README.md) | Queue metrics in Logstash and Prometheus, and the overflow WARN. |
| [timestamps](timestamps/README.md) | Loki deduplication with identical timestamps and the nanosecond fix. |
| [consumers](consumers/README.md) | Compare consumers, resource use, shutdown/reload with pending records and DNS recovery. |
| [backpressure](backpressure/README.md) | Compare queue drops with producer blocking under the same load and export latency, then verify recovery. |
| [spring-tcp](spring-tcp/README.md) | Compare current and tuned configurations at 13,000 logs/s: 4 versus 10 consumers, both with 4 pipeline workers and batches of 300. |
| [regression-load](regression-load/README.md) | Combine load at a target of 12,000 records/s, Loki timestamp checks and recovery after a 35-second export outage. |

Each README contains the commands to run manually. `Dockerfile` and
`Dockerfile.dockerignore` are shared by these tests. The shared Loki service and
configuration in [common/loki](common/loki/) support timestamps and regression-load;
that directory is not a standalone test. Stop other scenarios before starting a
test that uses the same host ports.
