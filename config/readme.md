# Local example configuration

The root Compose sends ten logs from Logstash to the Collector's `debug` exporter.
Run it with the commands in [Running locally](../README.md#running-locally).

- `logstash/`: settings and pipeline for the local example.
- `otel/`: OTLP/HTTP receiver and debug exporter.
- `tls/`: sample certificates for the TLS configuration examples.

Loki and the integration cases are in [tests/integration](../tests/integration/README.md).
