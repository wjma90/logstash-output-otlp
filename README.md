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
| max_queue_size               | long | No |
| max_batch_size               | long | No |
| schedule_delay_millis        | long | No |
| export_timeout_millis        | long | No |
| ssl_disable_tls_verification | [boolean](https://www.elastic.co/guide/en/logstash/8.12/configuration-file-structure.html#string)                         | No |
| ssl_certificate_authorities  | [string](https://www.elastic.co/guide/en/logstash/8.12/configuration-file-structure.html#string)                          | No |
| resource                     | [Hash](https://www.elastic.co/guide/en/logstash/latest/configuration-file-structure.html#hash)                            | No |
| attributes                   | [Hash](https://www.elastic.co/guide/en/logstash/latest/configuration-file-structure.html#hash)                            | No |
| body                         | [Field Reference](https://www.elastic.co/guide/en/logstash/8.12/configuration-file-structure.html#field-reference)        | No |
| name                         | [Field Reference](https://www.elastic.co/guide/en/logstash/8.12/configuration-file-structure.html#field-reference)        | No |
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
- Must be positive and no greater than `export_timeout_millis / 1000`.

Batch settings:

| Setting | Default | Purpose |
| --- | --- | --- |
| `max_queue_size` | `2048` | Maximum records waiting in memory. |
| `max_batch_size` | `512` | Maximum records in one export. |
| `schedule_delay_millis` | `1000` | Interval for exporting an incomplete batch; a full batch can send earlier. |
| `export_timeout_millis` | `30000` | Maximum wait for an export result in the batch processor. |

All four values must be positive integers, and `max_batch_size` must not exceed
`max_queue_size`. Invalid or overflowing values fail at startup.

The OTLP SDK retries transient failures with exponential backoff and jitter,
up to five attempts including the original request. The initial delay is about
one second, multiplied by 1.5, with a nominal five-second backoff cap. The request
`timeout` can end retries earlier; five attempts are not guaranteed. See the
[SDK retry policy](https://github.com/open-telemetry/opentelemetry-java/blob/v1.62.0/sdk/common/src/main/java/io/opentelemetry/sdk/common/export/RetryPolicy.java).

Keep `export_timeout_millis` above the request timeout with some margin; the
processor's wait does not cancel the network request. The queue is bounded and
in memory: excess events are dropped when it fills, and batches that exhaust
their retries are not requeued. This does not guarantee delivery during an outage.

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

## Running locally

`docker-compose up`

The local Dockerfile installs a gem built from this repository with `logstash-plugin install --no-verify --local`.
That pattern is intended for local smoke tests of the local gem only.

For a production-like image that installs the published gem from RubyGems, use:

```dockerfile
FROM docker.elastic.co/logstash/logstash:9.4.4@sha256:c1aeca2bbf56148c1c868957e1d0ea5aa020cba5b3dca3493a097f54c0efc544
RUN logstash-plugin install logstash-output-otlp
```

The certificates under `config/tls` are local test certificates used by the Docker Compose example.
Do not reuse those private keys or certificates in shared, staging, or production environments.

### Check export error logging manually

The small Compose example uses one Logstash output and an OTLP/HTTP Collector,
without authentication. With Java 17 and Docker Compose available, build the gem
and send five events:

```sh
make gem
docker compose -f tests/integration/compose.yml build
docker compose -f tests/integration/compose.yml up -d collector
docker compose -f tests/integration/compose.yml run --rm logstash
docker compose -f tests/integration/compose.yml logs collector
```

The Collector should print `OTLP manual export test` for the received events.
To simulate an unavailable destination, stop it and send again:

```sh
docker compose -f tests/integration/compose.yml stop collector
docker compose -f tests/integration/compose.yml run --rm --no-deps logstash
docker compose -f tests/integration/compose.yml down
```

Logstash should print `OTLP export failed: output_id=manual_otlp
endpoint=http://collector:4318/v1/logs records=5`. Repeated failures are logged
at most once every 30 seconds per output. This diagnostic does not resend events.

## Notes

**Warning** This plugin depends on OpenTelemetry logging libraries.
