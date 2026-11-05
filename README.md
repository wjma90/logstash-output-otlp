# Logstash Output Plugin for OpenTelemetry

[![Java CI with Gradle](https://github.com/wjma90/logstash-output-otlp/actions/workflows/gradle.yml/badge.svg)](https://github.com/wjma90/logstash-output-otlp/actions/workflows/gradle.yml)

This is a Java-based plugin for [Logstash](https://github.com/elastic/logstash).

It is fully free and fully open source. The license is Apache 2.0, meaning you are free to use it however you want.

## OpenTelemetry

This plugin allows Logstash to output looks to an OpenTelemetry otlp endpoint.

Default field mapping is as per the spec: https://opentelemetry.io/docs/reference/specification/logs/data-model/#elastic-common-schema

```
@timestamp >> Timestamp
message >> Body
```

All other fields are attached as Attributes.

## Installation

`logstash-plugin install logstash-output-otlp`

The published gem is available at https://rubygems.org/gems/logstash-output-otlp.

## Usage
### Basic
```
input {
    generator {
        count => 10
        add_field => {
            "log.level" => "WARN"
            "trace.id" => "5b8aa5a2d2c872e8321cf37308d69df2"
            "span.id" => "051581bf3cb55c13"
        }
    }
}
output {
    otlp {
        endpoint => "http://otel:4317"
        protocol => "grpc"
        compression => "none"
    }
}
```

### TLS with Otel Collector + SelfSigned Certificate
```
input {
    generator {
        count => 10
        add_field => {
            "log.level" => "WARN"
            "trace.id" => "5b8aa5a2d2c872e8321cf37308d69df2"
            "span.id" => "051581bf3cb55c13"
        }
    }
}
output {
    otlp {
        endpoint => "https://otel:4317"
        protocol => "grpc"
        compression => "none"
        ssl_certificate_authorities => "/etc/otel/ca.crt"
    }
}
```

### TLS with TLS Verification Disabled

This mode disables server certificate verification and should only be used for local testing.

```
input {
    generator {
        count => 10
        add_field => {
            "log.level" => "WARN"
            "trace.id" => "5b8aa5a2d2c872e8321cf37308d69df2"
            "span.id" => "051581bf3cb55c13"
        }
    }
}
output {
    otlp {
        endpoint => "https://otel:4317"
        protocol => "grpc"
        compression => "none"
        ssl_disable_tls_verification => true
    }
}
```

## Options

| Setting                      | Input Type                                                                                                                | Required |
|:-----------------------------|:--------------------------------------------------------------------------------------------------------------------------|:--|
| endpoint                     | [uri](https://www.elastic.co/guide/en/logstash/current/configuration-file-structure.html#uri)                             | Yes |
| endpoint_type                | [string](https://www.elastic.co/guide/en/logstash/8.12/configuration-file-structure.html#string)                          | No (Deprecated) |
| protocol                     | [string](https://www.elastic.co/guide/en/logstash/8.12/configuration-file-structure.html#string), one of ["grpc", "http"] | No |
| compression                  | [string](https://www.elastic.co/guide/en/logstash/8.12/configuration-file-structure.html#string), one of ["gzip", "none"] | No |
| connect_timeout              | [long](https://www.elastic.co/guide/en/logstash/8.12/configuration-file-structure.html#number)                            | No |
| timeout                      | [long](https://www.elastic.co/guide/en/logstash/8.12/configuration-file-structure.html#number)   | No |
| retry_initial_backoff_millis | long | No |
| retry_max_backoff_millis     | long | No |
| retry_backoff_multiplier     | float | No |
| retry_max_attempts           | long | No |
| queue_size                   | long | No |
| num_consumers                | long | No |
| max_batch_size               | long | No |
| schedule_delay_millis        | long | No |
| ssl_disable_tls_verification | [boolean](https://www.elastic.co/guide/en/logstash/8.12/configuration-file-structure.html#string)                         | No |
| ssl_certificate_authorities  | [string](https://www.elastic.co/guide/en/logstash/8.12/configuration-file-structure.html#string)                          | No |
| resource                     | [Hash](https://www.elastic.co/guide/en/logstash/latest/configuration-file-structure.html#hash)                            | No |
| attributes                   | [Hash](https://www.elastic.co/guide/en/logstash/latest/configuration-file-structure.html#hash)                            | No |
| body                         | [Field Reference](https://www.elastic.co/guide/en/logstash/8.12/configuration-file-structure.html#field-reference)        | No |
| name                         | [Field Reference](https://www.elastic.co/guide/en/logstash/8.12/configuration-file-structure.html#field-reference)        | No; accepted but currently unused |
| severity_text                | [Field Reference](https://www.elastic.co/guide/en/logstash/8.12/configuration-file-structure.html#field-reference)        | No |
| trace_id                     | [Field Reference](https://www.elastic.co/guide/en/logstash/8.12/configuration-file-structure.html#field-reference)        | No |
| span_id                      | [Field Reference](https://www.elastic.co/guide/en/logstash/8.12/configuration-file-structure.html#field-reference)        | No |
| trace_flags                  | [Field Reference](https://www.elastic.co/guide/en/logstash/8.12/configuration-file-structure.html#field-reference)        | No |

`endpoint`

- This is a required setting.
- There is no default value for this setting.
- Value type is [uri](https://www.elastic.co/guide/en/logstash/current/configuration-file-structure.html#uri)

An endpoint that supports otlp to which logs are sent.

`endpoint_type`

- Deprecated. Replaced with `protocol`.

`connect_timeout`

- Value type is [long](https://www.elastic.co/guide/en/logstash/8.12/configuration-file-structure.html#number)
- Default is: `10` (seconds)

`timeout`

- Value type is [long](https://www.elastic.co/guide/en/logstash/8.12/configuration-file-structure.html#number)
- Default is: `10` (seconds)
- Must be positive. Each consumer waits for the SDK export result before taking another batch.

Batch settings:

| Setting | Default | Purpose |
| --- | --- | --- |
| `queue_size` | `2048` | Maximum log records waiting in one shared memory queue. |
| `num_consumers` | `1` | Consumers exporting batches concurrently to the same endpoint (1–256). |
| `max_batch_size` | `512` | Maximum records per consumer batch. |
| `schedule_delay_millis` | `1000` | Maximum wait to fill a batch after its first record is taken; full batches send immediately. |

All four values must be positive integers, and `max_batch_size` must not exceed
`queue_size`. Invalid or overflowing values fail at startup. Queue capacity is
shared by all consumers and always counts individual log records. Batches being
formed or exported are outside the queue; allow memory for up to
`queue_size + num_consumers * max_batch_size` records plus transport buffers.

Consumers wait without polling when there is no work. Each consumer has its own
SDK exporter and waits for completion before starting its next batch. Batches may
arrive out of order. Shutdown stops admission, drains accepted records and closes
all exporters and metric callbacks. The batch delay does not bound time spent
waiting in the queue while all consumers are busy.

Exporters and worker threads start on the first non-empty output batch. Instances
created only for Logstash configuration validation do not start background work.
Queue capacity and an initial size of zero are visible before the first event.

`max_queue_size` remains a deprecated alias for `queue_size`; configure only one.
Remove `export_timeout_millis` from existing configurations: it is no longer
supported. Network limits remain `connect_timeout` and `timeout`, in seconds.

The HTTP and gRPC exporters use the SDK's exponential backoff for transient failures:

| Setting | Default | Purpose |
| --- | --- | --- |
| `retry_initial_backoff_millis` | `1000` | Initial retry delay in milliseconds. |
| `retry_max_backoff_millis` | `10000` | Maximum nominal retry delay in milliseconds, before jitter. |
| `retry_backoff_multiplier` | `1.5` | Multiplies the nominal delay after each retry; must be finite and at least 1. |
| `retry_max_attempts` | `5` | Total attempts per batch, including the original request; the SDK supports 2–5. |

Delays must be positive and the maximum must be at least the initial delay.
The SDK applies ±20% jitter after the nominal cap: `10000` ms can produce a
calculated delay of up to `12000` ms. Allow for this when choosing the cap.
Each consumer retries its own batch; `timeout` includes retries and may end the
export before all attempts finish. See the [SDK retry behavior](https://github.com/open-telemetry/opentelemetry-java/blob/v1.62.0/exporters/sender/okhttp/src/main/java/io/opentelemetry/exporter/sender/okhttp/internal/RetryInterceptor.java).

The queue is bounded and in memory: excess events are dropped when it fills, and batches that exhaust
their retries are not requeued. This does not guarantee delivery during an outage.

See [the consumer integration test](tests/integration/consumers/README.md) to compare consumers,
queue drops, CPU, heap and thread counts with Logstash.

`protocol`

- Value type is [string](https://www.elastic.co/guide/en/logstash/8.12/configuration-file-structure.html#string)
- Default is: `grpc`

Possible values are `grpc` or `http`

`compression`

- Value type is [string](https://www.elastic.co/guide/en/logstash/8.12/configuration-file-structure.html#string)
- Default is: `none`

Possible values are `gzip` or `none`

`ssl_disable_tls_verification`

- Value type is [boolean](https://www.elastic.co/guide/en/logstash/8.12/configuration-file-structure.html#string)
- Default is: `false`

Use this field only when you want to disable TLS certificate verification for local testing.
When enabled, the plugin trusts any server certificate and logs a warning during startup.
The `ssl_certificate_authorities` field is ignored.

`ssl_certificate_authorities`

- Value type is [string](https://www.elastic.co/guide/en/logstash/8.12/configuration-file-structure.html#string)
- Default is: `null`

Use this field when you want to add a CA certificate.
This field is ignored when `ssl_disable_tls_verification => true` is set.

`resource`

- Value type is [hash](https://www.elastic.co/guide/en/logstash/latest/configuration-file-structure.html#hash)
- Default is empty

This hash allows additional fields to be added to the [OpenTelemetry Resource field](https://opentelemetry.io/docs/reference/specification/logs/data-model/#field-resource)
Hash values must be strings.

`attributes`

- Value type is [hash](https://www.elastic.co/guide/en/logstash/latest/configuration-file-structure.html#hash)
- Default is unset

When `attributes` is not configured, the plugin sends all event fields as OpenTelemetry log attributes except `@timestamp`.
For production pipelines, prefer an explicit allowlist or filter sensitive fields before this output.
The OpenTelemetry Collector should also include redaction, transform, or drop processors for secrets and regulated data because it receives the final OTLP attributes.

`body`

- Value type is [Field Reference](https://www.elastic.co/guide/en/logstash/8.12/configuration-file-structure.html#field-reference)
- Default is `message`

The field to reference as the [Otel Body field](https://opentelemetry.io/docs/reference/specification/logs/data-model/#field-body).

`severity_text`

- Value type is [Field Reference](https://www.elastic.co/guide/en/logstash/8.12/configuration-file-structure.html#field-reference)

The field to reference as the [Otel Severity Text field](https://opentelemetry.io/docs/reference/specification/logs/data-model/#field-severitytext).

`trace_id`

- Value type is [Field Reference](https://www.elastic.co/guide/en/logstash/8.12/configuration-file-structure.html#field-reference)

The field to reference as the [Otel Trace ID field](https://opentelemetry.io/docs/reference/specification/logs/data-model/#field-traceid).

`span_id`

- Value type is [Field Reference](https://www.elastic.co/guide/en/logstash/8.12/configuration-file-structure.html#field-reference)

The field to reference as the [Otel Span ID field](https://opentelemetry.io/docs/reference/specification/logs/data-model/#field-spanid).

`trace_flags`

- Value type is [Field Reference](https://www.elastic.co/guide/en/logstash/8.12/configuration-file-structure.html#field-reference)

The field to reference as the [Otel Trace Flags field](https://opentelemetry.io/docs/reference/specification/logs/data-model/#field-traceflags).

## Building

`make gem`

For unit tests, build the Logstash core jar first:

```bash
make logstashcorejar
./gradlew test -PLOGSTASH_CORE_PATH="$PWD/assets/logstash-9.0.0/logstash-core"
```

`make gem` also builds the Logstash core jar before packaging the local plugin gem.

## Monitoring

The output exposes the Java SDK's `LATEST` exporter metrics and the shared
queue's `otel.sdk.processor.log.*` metrics under `sdk_metrics` in Logstash's
Node Stats API, preserving component, endpoint and error attributes. The processor
component type is `shared_queue_log_processor`. Exporter series are per consumer;
sum them to get output totals. The [metrics demo](tests/integration/queue/README.md)
shows successful exports, failures and queue saturation in Prometheus.
`kuskoman/logstash-exporter` v1.9.2 needs additional collector support for these
custom fields; the demo uses JSON Exporter mappings.

For OTLP `partial_success` responses over HTTP or gRPC, the plugin emits a `WARN`
with the output ID, rejected count and receiver's message, limited to once every
30 seconds per output. It counts every rejection in
`sdk_metrics.otlp_exporter_log_rejected`, summed across consumers. This custom
counter appears in the demos as
`otlp_exporter_log_rejected_total{error_type="partial_success"}` in Prometheus;
it resets when the output is recreated. A warning with zero rejected records
does not increase the counter. The receiver's message is bounded and is not a metric label.

Partial batches are not retried, as required by [OTLP](https://opentelemetry.io/docs/specs/otlp/#partial-success).
SDK 1.62.0 still counts the whole batch as successful in `otel.sdk.exporter.log.exported`;
the rejection counter makes those losses visible without changing that SDK metric.
Malformed responses produce a separate diagnostic `WARN` without inventing a rejected count.
Run `./gradlew test --tests 'org.otlp.*PartialSuccess*'` to test these cases.

## Running locally

With Java 17 and Docker running:

```sh
make gem
docker compose up --build
```

Logstash sends ten records over OTLP/HTTP. The Collector (`otel`) prints them
using its `debug` exporter with the body `OTLP local example`.

From another terminal:

```sh
docker compose logs otel
docker compose down
```

The Dockerfile installs the local gem built from this repository.

For a production-like image that installs the published gem from RubyGems, use:

```dockerfile
FROM docker.elastic.co/logstash/logstash:9.4.4@sha256:c1aeca2bbf56148c1c868957e1d0ea5aa020cba5b3dca3493a097f54c0efc544
RUN logstash-plugin install logstash-output-otlp
```

### Integration tests

See [tests/integration](tests/integration/README.md) for manual tests of export
errors, queue metrics, consumer stress and the timestamp fix for Loki.

## Notes

**Warning** This plugin depends on OpenTelemetry logging libraries.
