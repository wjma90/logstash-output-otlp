# OTLP over TLS

Send logs from Logstash to a Collector with a trusted test CA, then verify that
an unrelated CA causes an export error. Both HTTP and gRPC use TLS, with
`block_on_overflow => true`. This test does not use client certificates or authentication.

1. From the repository root, build the gem with Java 17 and generate test certificates:

   ```sh
   make gem
   mkdir -p build/tls-certs
   openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=OTLP Test CA' \
     -addext 'basicConstraints=critical,CA:TRUE' \
     -keyout build/tls-certs/ca.key -out build/tls-certs/ca.crt
   openssl req -newkey rsa:2048 -nodes -subj '/CN=collector' \
     -keyout build/tls-certs/collector.key -out build/tls-certs/collector.csr
   printf 'subjectAltName=DNS:collector\nextendedKeyUsage=serverAuth\n' > build/tls-certs/server.ext
   openssl x509 -req -days 2 -in build/tls-certs/collector.csr \
     -CA build/tls-certs/ca.crt -CAkey build/tls-certs/ca.key -CAcreateserial \
     -extfile build/tls-certs/server.ext -out build/tls-certs/collector.crt
   openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=Unrelated Test CA' \
     -addext 'basicConstraints=critical,CA:TRUE' \
     -keyout build/tls-certs/wrong-ca.key -out build/tls-certs/wrong-ca.crt
   chmod 644 build/tls-certs/collector.key
   cd tests/integration/tls
   unset OTLP_ENDPOINT OTLP_PROTOCOL OTLP_CA TLS_SKIP_VERIFY
   docker compose up -d --build --wait
   ```

2. Send a record and check the Collector:

   ```sh
   curl -fsS http://localhost:18480 -H 'Content-Type: application/json' \
     -d '{"message":"TLS trusted CA"}'
   docker compose logs --since 1m collector | grep 'TLS trusted CA'
   ```

   Allow a few seconds for export. The Collector should print the message.
   To repeat over gRPC, recreate Logstash and send another record:

   ```sh
   export OTLP_PROTOCOL=grpc OTLP_ENDPOINT=https://collector:4317
   export OTLP_CA=/certs/ca.crt TLS_SKIP_VERIFY=false
   docker compose up -d --force-recreate --wait logstash
   ```

3. Use the unrelated CA and send a new record:

   ```sh
   export OTLP_CA=/certs/wrong-ca.crt
   docker compose up -d --force-recreate --wait logstash
   curl -fsS http://localhost:18480 -H 'Content-Type: application/json' \
     -d '{"message":"TLS rejected CA"}'
   docker compose logs --since 1m logstash | grep 'OTLP export failed: output_id=tls_test'
   curl -fsS http://localhost:19640/_node/stats/pipelines/main | jq '.pipelines.main.plugins.outputs[] | select(.id == "tls_test") | .sdk_metrics'
   ```

   After a few seconds, expect an export failure and an increased
   `otel_sdk_exporter_log_exported` series with a nonempty `error_type`.
   The Collector must not print `TLS rejected CA`. HTTP acceptance by Logstash
   does not confirm delivery. To repeat steps 2–3 over HTTP, first restore the
   trusted CA and recreate Logstash:

   ```sh
   export OTLP_PROTOCOL=http OTLP_ENDPOINT=https://collector:4318/v1/logs
   export OTLP_CA=/certs/ca.crt TLS_SKIP_VERIFY=false
   docker compose up -d --force-recreate --wait logstash
   ```

   To exercise the optional local bypass:

   ```sh
   export OTLP_CA=/certs/wrong-ca.crt TLS_SKIP_VERIFY=true
   docker compose up -d --force-recreate --wait logstash
   curl -fsS http://localhost:18480 -H 'Content-Type: application/json' \
     -d '{"message":"TLS local bypass"}'
   ```

   The record should arrive despite the unrelated CA. Logstash should warn that
   TLS verification is disabled.

   To check hostname verification with the trusted CA, use the Collector alias
   absent from the certificate:

   ```sh
   export OTLP_PROTOCOL=http OTLP_ENDPOINT=https://collector-wrong:4318/v1/logs
   export OTLP_CA=/certs/ca.crt TLS_SKIP_VERIFY=false
   docker compose up -d --force-recreate --wait logstash
   curl -fsS http://localhost:18480 -H 'Content-Type: application/json' \
     -d '{"message":"TLS rejected hostname"}'
   docker compose logs logstash | grep 'OTLP export failed: output_id=tls_test'
   ```

   Expect an export error and no matching body in the Collector. For gRPC, repeat
   with `OTLP_PROTOCOL=grpc` and `OTLP_ENDPOINT=https://collector-wrong:4317`.

4. Clean up:

   ```sh
   docker compose down
   unset OTLP_ENDPOINT OTLP_PROTOCOL OTLP_CA TLS_SKIP_VERIFY
   ```

Certificates expire after two days. Regenerate them before a later run.
