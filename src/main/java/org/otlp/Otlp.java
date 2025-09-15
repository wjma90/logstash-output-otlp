package org.otlp;

import co.elastic.logstash.api.*;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.common.AttributesBuilder;
import io.opentelemetry.api.logs.Logger;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanContext;
import io.opentelemetry.api.trace.TraceFlags;
import io.opentelemetry.api.trace.TraceState;
import io.opentelemetry.exporter.otlp.http.logs.OtlpHttpLogRecordExporter;
import io.opentelemetry.exporter.otlp.http.logs.OtlpHttpLogRecordExporterBuilder;
import io.opentelemetry.exporter.otlp.logs.OtlpGrpcLogRecordExporter;
import io.opentelemetry.exporter.otlp.logs.OtlpGrpcLogRecordExporterBuilder;
import io.opentelemetry.sdk.logs.LogRecordProcessor;
import io.opentelemetry.sdk.logs.SdkLoggerProvider;
import io.opentelemetry.sdk.logs.export.BatchLogRecordProcessor;
import io.opentelemetry.sdk.logs.export.LogRecordExporter;
import io.opentelemetry.sdk.logs.export.SimpleLogRecordProcessor;
import io.opentelemetry.sdk.resources.Resource;
import org.logstash.ConvertedList;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.CountDownLatch;

// class name must match plugin name
@LogstashPlugin(name = "otlp")
public class Otlp implements Output {

    public static final PluginConfigSpec<URI> ENDPOINT_CONFIG =
            PluginConfigSpec.uriSetting("endpoint", null, false, true);
    public static final PluginConfigSpec<String> ENDPOINT_TYPE_CONFIG =
            PluginConfigSpec.stringSetting("endpoint_type", "", true, false);
    public static final PluginConfigSpec<String> PROTOCOL_CONFIG =
            PluginConfigSpec.stringSetting("protocol", "", false, false);
    public static final PluginConfigSpec<String> COMPRESSION_CONFIG =
            PluginConfigSpec.stringSetting("compression", "none");
    public static final PluginConfigSpec<String> SSL_CERTIFICATE_AUTHORITIES =
            PluginConfigSpec.stringSetting("ssl_certificate_authorities", null);
    public static final PluginConfigSpec<Boolean> SSL_DISABLE_TLS_VERIFICATION =
            PluginConfigSpec.booleanSetting("ssl_disable_tls_verification", false);

    public static final PluginConfigSpec<Map<String, Object>>  ATTRIBUTES_CONFIG = PluginConfigSpec.hashSetting("attributes",null, false, false);
    public static final PluginConfigSpec<Map<String, Object>> RESOURCE_CONFIG = PluginConfigSpec.hashSetting("resource", null, false, false);
    public static final PluginConfigSpec<String> TRACE_ID_CONFIG = PluginConfigSpec.stringSetting("trace_id", null, false, false);
    public static final PluginConfigSpec<String> SPAN_ID_CONFIG = PluginConfigSpec.stringSetting("span_id", null, false, false);
    public static final PluginConfigSpec<String> SEVERITY_TEXT_CONFIG = PluginConfigSpec.stringSetting("severity_text", null, false, false);
    public static final PluginConfigSpec<String> TRACE_FLAGS_CONFIG = PluginConfigSpec.stringSetting("trace_flags", null, false, false);
    public static final PluginConfigSpec<String> NAME_CONFIG = PluginConfigSpec.stringSetting("name", null, false, false);
    public static final PluginConfigSpec<String> BODY_CONFIG = PluginConfigSpec.stringSetting("body", "message", false, false);

    private enum VALID_PROTOCOL_OPTIONS {grpc, http}
    private final String id;
    private final Configuration configuration;
    private final CountDownLatch done = new CountDownLatch(1);
    private volatile boolean stopped = false;
    private final SdkLoggerProvider sdkLoggerProvider;

    private final PrintStream testOut;

    // all plugins must provide a constructor that accepts id, Configuration, and Context
    public Otlp(final String id, final Configuration configuration, final Context context) {
        this(id, configuration, context, System.out, false);
    }

    public Otlp(final String id, final Configuration configuration, final Context context, final Boolean testEnabled) {
        this(id, configuration, context, System.out, testEnabled);
    }

    private String extractFieldForEvent(Event event, String field) {
        if(field == null) return "";
        String output = "";
        Object o = event.getField(field);
        if(o instanceof String) {
            output = (String) event.getField(field);
            if (output == null || output.equals(field)) return "";
        }
        return output;
    }

    private io.opentelemetry.context.Context getContextForEvent(Event event) {
        TraceState ts = TraceState.getDefault();
        TraceFlags tf = TraceFlags.getDefault();
        String traceFlagsField = extractFieldForEvent(event, configuration.get(TRACE_FLAGS_CONFIG));
        if(!traceFlagsField.isEmpty()) {
            tf = TraceFlags.fromByte(Byte.parseByte(traceFlagsField));
        }

        String traceId = extractFieldForEvent(event, configuration.get(TRACE_ID_CONFIG));
        String spanId = extractFieldForEvent(event, configuration.get(SPAN_ID_CONFIG));

        SpanContext sp = SpanContext.create(traceId, spanId, tf, ts);
        return io.opentelemetry.context.Context.root().with(Span.wrap(sp));
    }

    private List<String> decodeConvertedList(ConvertedList convertedList) {
        String[] output = convertedList.unconvert().stream().toArray(String[]::new);
        return Arrays.asList(output);
    }

    private Attributes getDefaultAttributes(Event event) {
        Map<String, Object> eventData = event.getData();
        AttributesBuilder a = Attributes.builder();

        for (Map.Entry<String, Object> e : eventData.entrySet()) {
            String key = e.getKey();
            if (key.equals("@timestamp")) continue;

            Object value = e.getValue();
            if (value instanceof ConvertedList) {
                a.put(AttributeKey.stringArrayKey(key), decodeConvertedList((ConvertedList) value));
            } else {
                a.put(AttributeKey.stringKey(key), (String) value.toString());
            }
        }
        return a.build();
    }

    private Attributes getAttributesForConfigAndEvent(Map<String, Object> config, Event event) {
        AttributesBuilder a = Attributes.builder();
        for(String key: config.keySet()) {
            String fieldValue = extractFieldForEvent(event, (String)config.get(key));
            a.put(key, fieldValue);
        }
        return a.build();
    }

    private Attributes getAttributesForEvent(Event event) {
        Map<String, Object> attributeConfig = configuration.get(ATTRIBUTES_CONFIG);
        if(attributeConfig == null) return getDefaultAttributes(event);

        return getAttributesForConfigAndEvent(attributeConfig, event);
    }

    private void emitLog(Event event) {
        io.opentelemetry.context.Context c = getContextForEvent(event);
        String body = extractFieldForEvent(event, configuration.get(BODY_CONFIG));
        String severityText = extractFieldForEvent(event, configuration.get(SEVERITY_TEXT_CONFIG));
        Attributes attributes = getAttributesForEvent(event);

        Logger logger = sdkLoggerProvider.get("logstash-output-otlp");
        logger.logRecordBuilder()
                .setTimestamp(event.getEventTimestamp())
                .setSeverityText(severityText)
                .setBody(body)
                .setAllAttributes(attributes)
                .setContext(c)
                .emit();
    }

    private String protocolForConfig(Configuration configuration) {
        String endpointType = configuration.get(ENDPOINT_TYPE_CONFIG);
        String protocol = configuration.get(PROTOCOL_CONFIG);

        if( !protocol.isEmpty() ) {
            for (VALID_PROTOCOL_OPTIONS option : VALID_PROTOCOL_OPTIONS.values()) {
                if(option.name().equals(protocol)) return protocol;
            }
            throw new IllegalArgumentException(String.format("protocol (%s) is not valid.", protocol));
        }

        if( endpointType.isEmpty() ) {
            return VALID_PROTOCOL_OPTIONS.grpc.name();
        }

        for (VALID_PROTOCOL_OPTIONS option : VALID_PROTOCOL_OPTIONS.values()){
            if(option.name().equals(endpointType)) return endpointType;
        }

        throw new IllegalArgumentException(String.format("endpoint_type (%s) is not valid", endpointType));
    }

    private LogRecordExporter logExporterForConfig(Configuration configuration) {
        URI endpoint = configuration.get(ENDPOINT_CONFIG);
        String compression = configuration.get(COMPRESSION_CONFIG);
        String caPath = configuration.get(SSL_CERTIFICATE_AUTHORITIES);
        Boolean sslDisableTlsVerification = configuration.get(SSL_DISABLE_TLS_VERIFICATION);
        SSLContext sslContext = sslDisableTlsVerification ? getInsecureSSLContext() : null;

        byte[] caFile = caPath == null ? null :getSSLCertificateAuthority(caPath);

        if (protocolForConfig(configuration).equals(VALID_PROTOCOL_OPTIONS.http.name())) {
            OtlpHttpLogRecordExporterBuilder builder = OtlpHttpLogRecordExporter.builder();

            builder.setEndpoint(endpoint.toString())
                    .setCompression(compression);

            if(!sslDisableTlsVerification && caFile != null && caFile.length > 0)  builder.setTrustedCertificates(caFile);
            if(sslDisableTlsVerification) builder.setSslContext(sslContext, getInsecureSSLTrustManager());

            return builder.build();
        } else {
            OtlpGrpcLogRecordExporterBuilder builder = OtlpGrpcLogRecordExporter.builder();

            builder.setEndpoint(endpoint.toString())
                    .setCompression(compression);

            if(!sslDisableTlsVerification && caFile != null && caFile.length > 0)  builder.setTrustedCertificates(caFile);
            if(sslDisableTlsVerification) builder.setSslContext(sslContext, getInsecureSSLTrustManager());

            return builder.build();
        }
    }

    Attributes getResourceAttributes() {
        Package p = getClass().getPackage();
        String version = p.getImplementationVersion();
        AttributesBuilder attributesBuilder = Attributes.builder()
                .put("telemetry.sdk.name","logstash-output-otlp")
                .put("telemetry.sdk.language", "java")
                .put("telemetry.sdk.version",version)
                .put("agent.id", id);
        Map<String, Object> resourceConfig = configuration.get(RESOURCE_CONFIG);

        if(resourceConfig != null) {
            for(String key: resourceConfig.keySet()) {
                attributesBuilder.put(key, (String)resourceConfig.get(key));
            }
        }
        return attributesBuilder.build();
    }

    Otlp(final String id, final Configuration config, final Context context, OutputStream targetStream, final Boolean testEnabled) {
        // constructors should validate configuration options
        this.id = id;
        this.configuration = config;
        this.testOut = (!testEnabled ? null : new PrintStream(targetStream));

        Resource resource = Resource.create(getResourceAttributes());

        LogRecordExporter exporter = (testEnabled) ? new StreamLogRecordExporter(testOut, config.get(ENDPOINT_CONFIG)) : logExporterForConfig(config);
        LogRecordProcessor processor = (testEnabled) ? SimpleLogRecordProcessor.create(exporter) : BatchLogRecordProcessor.builder(exporter).build();

        sdkLoggerProvider = SdkLoggerProvider.builder()
                .setResource(resource)
                .addLogRecordProcessor(processor)
                .build();
    }

    private SSLContext getInsecureSSLContext() {
        SSLContext sslContext = null;

        try {
            sslContext = javax.net.ssl.SSLContext.getInstance("TLS");
            sslContext.init(null, new X509TrustManager[]{getInsecureSSLTrustManager()}, new java.security.SecureRandom());
        } catch (Exception e) {
            throw new RuntimeException("Failed to create insecure SSLContext", e);
        }
        return sslContext;
    }

    private X509TrustManager getInsecureSSLTrustManager() {
        return new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                };
    }

    private byte[] getSSLCertificateAuthority(String caPath) {
        byte[] caBytes = null;
        try {
            caBytes = Files.readAllBytes(Paths.get(caPath));
        } catch (IOException e) {
            throw new IllegalArgumentException("Cannot read CA file: " + caPath, e);
        }
        return caBytes;
    }

    @Override
    public void output(final Collection<Event> events) {
        Iterator<Event> z = events.iterator();
        while (z.hasNext() && !stopped) {
            emitLog(z.next());
        }
    }

    @Override
    public void stop() {
        stopped = true;
        sdkLoggerProvider.forceFlush();
        sdkLoggerProvider.shutdown();
        done.countDown();
    }

    @Override
    public void awaitStop() throws InterruptedException {
        done.await();
    }

    @Override
    public Collection<PluginConfigSpec<?>> configSchema() {
        return PluginHelper.commonOutputSettings(Arrays.asList(
                ENDPOINT_TYPE_CONFIG,
                ENDPOINT_CONFIG,
                PROTOCOL_CONFIG,
                COMPRESSION_CONFIG,
                BODY_CONFIG,
                NAME_CONFIG,
                ATTRIBUTES_CONFIG,
                RESOURCE_CONFIG,
                TRACE_FLAGS_CONFIG,
                TRACE_ID_CONFIG,
                SPAN_ID_CONFIG,
                SEVERITY_TEXT_CONFIG,
                SSL_CERTIFICATE_AUTHORITIES,
                SSL_DISABLE_TLS_VERIFICATION
        ));
    }

    @Override
    public String getId() {
        return id;
    }
}
