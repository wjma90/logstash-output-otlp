# Integration tests

Build the local gem with Java 17 and `make gem` from the repository root.
Use Docker Compose, `curl` and `jq`; the queue, timestamp and consumer tests also need local Python 3.

| Test | What to verify |
| --- | --- |
| [export-errors](export-errors/README.md) | Successful delivery and the error log when the destination is unavailable. |
| [queue](queue/README.md) | Queue metrics in Logstash and Prometheus, and the overflow WARN. |
| [timestamps](timestamps/README.md) | Loki deduplication with identical timestamps and the nanosecond fix. |
| [consumers](consumers/README.md) | Shared queue, sustained load, resources, shutdown/reload with pending records and DNS recovery. |

Each README contains the commands to run manually. `Dockerfile` and
`Dockerfile.dockerignore` are shared by these tests.
