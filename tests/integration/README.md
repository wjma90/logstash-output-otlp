# Integration tests

Build the local gem with Java 17 and `make gem` from the repository root.
Use Docker Compose, `curl` and `jq`; all tests except export-errors also need local Python 3.

| Test | What to verify |
| --- | --- |
| [export-errors](export-errors/README.md) | Successful delivery and the error log when the destination is unavailable. |
| [queue](queue/README.md) | Queue metrics in Logstash and Prometheus, and the overflow WARN. |
| [timestamps](timestamps/README.md) | Loki deduplication with identical timestamps and the nanosecond fix. |
| [consumers](consumers/README.md) | Compare consumers, resource use, shutdown/reload with pending records and DNS recovery. |
| [regression-load](regression-load/README.md) | Combine load at a target of 12,000 records/s, Loki timestamp checks and recovery after a 35-second export outage. |

Each README contains the commands to run manually. `Dockerfile` and
`Dockerfile.dockerignore` are shared by these tests. The shared Loki service and
configuration in [common/loki](common/loki/) support timestamps and regression-load;
that directory is not a standalone test. Stop other scenarios before starting a
test that uses the same host ports.
