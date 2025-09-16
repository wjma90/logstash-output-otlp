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

### TLS with Tls Verification Disabled
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

| Setting | Input Type                                                                                                                | Required |
|:--|:--------------------------------------------------------------------------------------------------------------------------|:--|
| endpoint | [uri](https://www.elastic.co/guide/en/logstash/current/configuration-file-structure.html#uri)                             | Yes |
| endpoint_type | [string](https://www.elastic.co/guide/en/logstash/7.16/configuration-file-structure.html#string)                          | No (Deprecated) |
| protocol | [string](https://www.elastic.co/guide/en/logstash/7.16/configuration-file-structure.html#string), one of ["grpc", "http"] | No |
| compression | [string](https://www.elastic.co/guide/en/logstash/7.16/configuration-file-structure.html#string), one of ["gzip", "none"] | No |
| ssl_disable_tls_verification | [boolean](https://www.elastic.co/guide/en/logstash/7.16/configuration-file-structure.html#string)                         | No |
| ssl_certificate_authorities | [string](https://www.elastic.co/guide/en/logstash/7.16/configuration-file-structure.html#string)                          | No |
| resource | [Hash](https://www.elastic.co/guide/en/logstash/latest/configuration-file-structure.html#hash)                            | No |
| body | [Field Reference](https://www.elastic.co/guide/en/logstash/7.16/configuration-file-structure.html#field-reference)        | No |
| name | [Field Reference](https://www.elastic.co/guide/en/logstash/7.16/configuration-file-structure.html#field-reference)        | No |
| severity_text | [Field Reference](https://www.elastic.co/guide/en/logstash/7.16/configuration-file-structure.html#field-reference)        | No |
| trace_id | [Field Reference](https://www.elastic.co/guide/en/logstash/7.16/configuration-file-structure.html#field-reference)        | No |
| span_id | [Field Reference](https://www.elastic.co/guide/en/logstash/7.16/configuration-file-structure.html#field-reference)        | No |
| trace_flags | [Field Reference](https://www.elastic.co/guide/en/logstash/7.16/configuration-file-structure.html#field-reference)        | No |

`endpoint`

- This is a required setting.
- There is no default value for this setting.
- Value type is [uri](https://www.elastic.co/guide/en/logstash/current/configuration-file-structure.html#uri)

An endpoint that supports otlp to which logs are sent.

`endpoint_type`

- Deprecated. Replaced with `protocol`.

`protocol`

- Value type is [string](https://www.elastic.co/guide/en/logstash/7.16/configuration-file-structure.html#string)
- Default is: `grpc`

Possible values are `grpc` or `http`

`compression`

- Value type is [string](https://www.elastic.co/guide/en/logstash/7.16/configuration-file-structure.html#string)
- Default is: `none`

Possible values are `gzip` or `none`

`ssl_disable_tls_verification`

- Value type is [boolean](https://www.elastic.co/guide/en/logstash/7.16/configuration-file-structure.html#string)
- Default is: `false`

Use this field when you want to disable tls certificate verification.
The `ssl_certificate_authorities` field is ignored.

`ssl_certificate_authorities`

- Value type is [string](https://www.elastic.co/guide/en/logstash/7.16/configuration-file-structure.html#string)
- Default is: `null`

Use this field when you want to add a CA certificate.
This field is ignored when `ssl_disable_tls_verification => true` is set.

`resource`

- Value type is [hash](https://www.elastic.co/guide/en/logstash/latest/configuration-file-structure.html#hash)
- Default is empty

This hash allows additional fields to be added to the [OpenTelemetry Resource field](https://opentelemetry.io/docs/reference/specification/logs/data-model/#field-resource)
Hash values must be strings.

`body`

- Value type is [Field Reference](https://www.elastic.co/guide/en/logstash/7.16/configuration-file-structure.html#field-reference)
- Default is `message`

The field to reference as the [Otel Body field](https://opentelemetry.io/docs/reference/specification/logs/data-model/#field-body).

`severity_text`

- Value type is [Field Reference](https://www.elastic.co/guide/en/logstash/7.16/configuration-file-structure.html#field-reference)

The field to reference as the [Otel Severity Text field](https://opentelemetry.io/docs/reference/specification/logs/data-model/#field-severitytext).

`trace_id`

- Value type is [Field Reference](https://www.elastic.co/guide/en/logstash/7.16/configuration-file-structure.html#field-reference)

The field to reference as the [Otel Trace ID field](https://opentelemetry.io/docs/reference/specification/logs/data-model/#field-traceid).

`span_id`

- Value type is [Field Reference](https://www.elastic.co/guide/en/logstash/7.16/configuration-file-structure.html#field-reference)

The field to reference as the [Otel Span ID field](https://opentelemetry.io/docs/reference/specification/logs/data-model/#field-spanid).

`trace_flags`

- Value type is [Field Reference](https://www.elastic.co/guide/en/logstash/7.16/configuration-file-structure.html#field-reference)

The field to reference as the [Otel Trace Flags field](https://opentelemetry.io/docs/reference/specification/logs/data-model/#field-traceflags).

## Building

`make gem`

## Running locally

`docker-compose up`

## Notes

**Warning** This plugin depends on OpenTelemetry logging libraries.
