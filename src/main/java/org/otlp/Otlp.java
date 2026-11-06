package org.otlp;

import co.elastic.logstash.api.*;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.common.AttributesBuilder;
import io.opentelemetry.api.logs.Logger;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanContext;
import io.opentelemetry.api.trace.SpanId;
import io.opentelemetry.api.trace.TraceFlags;
import io.opentelemetry.api.trace.TraceId;
import io.opentelemetry.api.trace.TraceState;
import io.opentelemetry.exporter.otlp.http.logs.OtlpHttpLogRecordExporter;
import io.opentelemetry.exporter.otlp.http.logs.OtlpHttpLogRecordExporterBuilder;
import io.opentelemetry.exporter.otlp.logs.OtlpGrpcLogRecordExporter;
import io.opentelemetry.exporter.otlp.logs.OtlpGrpcLogRecordExporterBuilder;
import io.opentelemetry.sdk.common.CompletableResultCode;
import io.opentelemetry.sdk.common.InternalTelemetryVersion;
import io.opentelemetry.sdk.common.export.RetryPolicy;
import io.opentelemetry.sdk.logs.LogRecordProcessor;
import io.opentelemetry.sdk.logs.SdkLoggerProvider;
import io.opentelemetry.sdk.logs.export.LogRecordExporter;
import io.opentelemetry.sdk.logs.export.SimpleLogRecordProcessor;
import io.opentelemetry.sdk.resources.Resource;
import org.apache.logging.log4j.LogManager;
import org.logstash.ConvertedList;

import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;

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
    public static final PluginConfigSpec<Long> CONNECT_TIMEOUT =
            PluginConfigSpec.numSetting("connect_timeout", 10);
    public static final PluginConfigSpec<Long> TIMEOUT =
            PluginConfigSpec.numSetting("timeout", 10);
    public static final PluginConfigSpec<Long> RETRY_INITIAL_BACKOFF_CONFIG =
            PluginConfigSpec.numSetting("retry_initial_backoff_millis", 1000);
    public static final PluginConfigSpec<Long> RETRY_MAX_BACKOFF_CONFIG =
            PluginConfigSpec.numSetting("retry_max_backoff_millis", 10000);
    public static final PluginConfigSpec<Double> RETRY_BACKOFF_MULTIPLIER_CONFIG =
            PluginConfigSpec.floatSetting("retry_backoff_multiplier", 1.5);
    public static final PluginConfigSpec<Long> RETRY_MAX_ATTEMPTS_CONFIG =
            PluginConfigSpec.numSetting("retry_max_attempts", 5);
    public static final PluginConfigSpec<Long> QUEUE_SIZE_CONFIG =
            PluginConfigSpec.numSetting("queue_size", 2048);
    public static final PluginConfigSpec<Boolean> BLOCK_ON_OVERFLOW_CONFIG =
            PluginConfigSpec.booleanSetting("block_on_overflow", false);
    public static final PluginConfigSpec<Long> MAX_QUEUE_SIZE_CONFIG =
            PluginConfigSpec.numSetting("max_queue_size", 2048, true, false);
    public static final PluginConfigSpec<Long> NUM_CONSUMERS_CONFIG =
            PluginConfigSpec.numSetting("num_consumers", 1);
    public static final PluginConfigSpec<Long> MAX_BATCH_SIZE_CONFIG =
            PluginConfigSpec.numSetting("max_batch_size", 512);
    public static final PluginConfigSpec<Long> SCHEDULE_DELAY_CONFIG =
            PluginConfigSpec.numSetting("schedule_delay_millis", 1000);
    public static final PluginConfigSpec<Long> EXPORT_TIMEOUT_CONFIG =
            PluginConfigSpec.numSetting("export_timeout_millis", 30000, true, false);

    public static final PluginConfigSpec<Map<String, Object>>  ATTRIBUTES_CONFIG = PluginConfigSpec.hashSetting("attributes",null, false, false);
    public static final PluginConfigSpec<Map<String, Object>> RESOURCE_CONFIG = PluginConfigSpec.hashSetting("resource", null, false, false);
    public static final PluginConfigSpec<String> TRACE_ID_CONFIG = PluginConfigSpec.stringSetting("trace_id", null, false, false);
    public static final PluginConfigSpec<String> SPAN_ID_CONFIG = PluginConfigSpec.stringSetting("span_id", null, false, false);
    public static final PluginConfigSpec<String> SEVERITY_TEXT_CONFIG = PluginConfigSpec.stringSetting("severity_text", null, false, false);
    public static final PluginConfigSpec<String> TRACE_FLAGS_CONFIG = PluginConfigSpec.stringSetting("trace_flags", null, false, false);
    public static final PluginConfigSpec<String> NAME_CONFIG = PluginConfigSpec.stringSetting("name", null, false, false);
    public static final PluginConfigSpec<String> BODY_CONFIG = PluginConfigSpec.stringSetting("body", "message", false, false);
    private static final long NANOSECONDS_PER_MILLISECOND = 1_000_000L;
    private static final long NANOSECOND_DISAMBIGUATION_WINDOW = (NANOSECONDS_PER_MILLISECOND / 2) - 1;

    private enum VALID_PROTOCOL_OPTIONS {grpc, http}
    private final String id;
    private final Configuration configuration;
    private final boolean blockOnOverflow;
    private final CountDownLatch done = new CountDownLatch(1);
    private final AtomicBoolean shutdownStarted = new AtomicBoolean();
    private final Object lifecycleLock = new Object();
    private volatile boolean stopped = false;
    private volatile SdkLoggerProvider sdkLoggerProvider;
    private Supplier<SdkLoggerProvider> providerFactory;
    private volatile LogstashSdkMetrics sdkMetrics;
    private final AtomicLong emittedLogRecordSequence = new AtomicLong(0);
    private final org.apache.logging.log4j.Logger pluginLogger;

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
        String traceId = extractFieldForEvent(event, configuration.get(TRACE_ID_CONFIG));
        String spanId = extractFieldForEvent(event, configuration.get(SPAN_ID_CONFIG));

        if(traceId.isEmpty() && spanId.isEmpty()) {
            return io.opentelemetry.context.Context.root();
        }

        if(!TraceId.isValid(traceId) || !SpanId.isValid(spanId)) {
            pluginLogger.debug("Malformed trace_id or span_id value; emitting log without trace context.");
            return io.opentelemetry.context.Context.root();
        }

        TraceFlags tf = getTraceFlagsForEvent(event);
        SpanContext sp = SpanContext.create(traceId, spanId, tf, ts);
        return io.opentelemetry.context.Context.root().with(Span.wrap(sp));
    }

    private TraceFlags getTraceFlagsForEvent(Event event) {
        String traceFlagsField = extractFieldForEvent(event, configuration.get(TRACE_FLAGS_CONFIG));
        if(traceFlagsField.isEmpty()) {
            return TraceFlags.getDefault();
        }

        try {
            int traceFlags = traceFlagsField.length() == 2
                    ? Integer.parseUnsignedInt(traceFlagsField, 16)
                    : Integer.parseInt(traceFlagsField);
            if(traceFlags < 0 || traceFlags > 255) {
                throw new NumberFormatException("trace_flags out of byte range");
            }
            return TraceFlags.fromByte((byte) traceFlags);
        } catch (NumberFormatException e) {
            pluginLogger.debug("Invalid trace_flags value; using default trace flags.");
            return TraceFlags.getDefault();
        }
    }

    private List<String> decodeConvertedList(ConvertedList convertedList) {
        return convertedList.unconvert().stream()
                .map(String::valueOf)
                .toList();
    }

    private Attributes getDefaultAttributes(Event event) {
        Map<String, Object> eventData = event.getData();
        AttributesBuilder a = Attributes.builder();

        for (Map.Entry<String, Object> e : eventData.entrySet()) {
            String key = e.getKey();
            if (key.equals("@timestamp")) continue;

            Object value = e.getValue();
            putDefaultAttribute(a, key, value);
        }
        return a.build();
    }

    void putDefaultAttribute(AttributesBuilder attributesBuilder, String key, Object value) {
        try {
            if (value instanceof ConvertedList) {
                attributesBuilder.put(AttributeKey.stringArrayKey(key), decodeConvertedList((ConvertedList) value));
            } else {
                attributesBuilder.put(AttributeKey.stringKey(key), String.valueOf(value));
            }
        } catch (RuntimeException e) {
            pluginLogger.warn("Skipping OTLP attribute because it could not be converted: {}", key, e);
        }
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

    Instant timestampWithNanosecondDisambiguation(Instant eventTimestamp) {
        long offsetNanos = (emittedLogRecordSequence.getAndIncrement() % NANOSECOND_DISAMBIGUATION_WINDOW) + 1;
        return timestampWithNanosecondDisambiguation(eventTimestamp, offsetNanos);
    }

    static Instant timestampWithNanosecondDisambiguation(Instant eventTimestamp, long offsetNanos) {
        return Instant.ofEpochMilli(eventTimestamp.toEpochMilli()).plusNanos(offsetNanos);
    }

    private void emitLog(Event event, SdkLoggerProvider provider) {
        io.opentelemetry.context.Context c = getContextForEvent(event);
        Instant eventTimestamp = event.getEventTimestamp();
        Instant adjustedTimestamp = timestampWithNanosecondDisambiguation(eventTimestamp);
        String body = extractFieldForEvent(event, configuration.get(BODY_CONFIG));
        String severityText = extractFieldForEvent(event, configuration.get(SEVERITY_TEXT_CONFIG));
        Attributes attributes = getAttributesForEvent(event);

        Logger logger = provider.get("logstash-output-otlp");
        logger.logRecordBuilder()
                .setTimestamp(adjustedTimestamp)
                .setObservedTimestamp(eventTimestamp)
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

    private Supplier<LogRecordExporter> exporterFactoryForConfig(Configuration configuration, LogstashSdkMetrics metrics,
                                                                RetryPolicy retryPolicy) {
        URI endpoint = configuration.get(ENDPOINT_CONFIG);
        String compression = configuration.get(COMPRESSION_CONFIG);
        String caPath = configuration.get(SSL_CERTIFICATE_AUTHORITIES);
        boolean sslDisableTlsVerification = Boolean.TRUE.equals(configuration.get(SSL_DISABLE_TLS_VERIFICATION));
        SSLContext sslContext = sslDisableTlsVerification ? getInsecureSSLContext() : null;

        long connectTimeout = positiveSetting(CONNECT_TIMEOUT, Long.MAX_VALUE / 1_000_000_000);
        long timeout = positiveSetting(TIMEOUT, Long.MAX_VALUE / 1_000_000_000);

        byte[] caFile = sslDisableTlsVerification || caPath == null ? null : getSSLCertificateAuthority(caPath);

        if(sslDisableTlsVerification) {
            pluginLogger.warn("ssl_disable_tls_verification is enabled. The OTLP exporter will trust any TLS certificate; use only for local testing.");
            if(caPath != null) {
                pluginLogger.warn("ssl_certificate_authorities is ignored because ssl_disable_tls_verification is enabled.");
            }
        }

        if (protocolForConfig(configuration).equals(VALID_PROTOCOL_OPTIONS.http.name())) {
            OtlpHttpLogRecordExporterBuilder builder = OtlpHttpLogRecordExporter.builder();

            builder.setEndpoint(endpoint.toString())
                    .setComponentLoader(new PartialSuccessComponentLoader(metrics))
                    .setInternalTelemetryVersion(InternalTelemetryVersion.LATEST)
                    .setConnectTimeout(connectTimeout, TimeUnit.SECONDS)
                    .setTimeout(timeout, TimeUnit.SECONDS)
                    .setRetryPolicy(retryPolicy)
                    .setCompression(compression);

            if(!sslDisableTlsVerification && caFile != null && caFile.length > 0)  builder.setTrustedCertificates(caFile);
            if(sslDisableTlsVerification) builder.setSslContext(sslContext, getInsecureSSLTrustManager());

            return () -> builder.setMeterProvider(metrics.meterProvider()).build();
        } else {
            OtlpGrpcLogRecordExporterBuilder builder = OtlpGrpcLogRecordExporter.builder();

            builder.setEndpoint(endpoint.toString())
                    .setComponentLoader(new PartialSuccessComponentLoader(metrics))
                    .setInternalTelemetryVersion(InternalTelemetryVersion.LATEST)
                    .setConnectTimeout(connectTimeout, TimeUnit.SECONDS)
                    .setTimeout(timeout, TimeUnit.SECONDS)
                    .setRetryPolicy(retryPolicy)
                    .setCompression(compression);

            if(!sslDisableTlsVerification && caFile != null && caFile.length > 0)  builder.setTrustedCertificates(caFile);
            if(sslDisableTlsVerification) builder.setSslContext(sslContext, getInsecureSSLTrustManager());

            return () -> builder.setMeterProvider(metrics.meterProvider()).build();
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
        this(id, config, context, targetStream, testEnabled, null);
    }

    Otlp(final String id, final Configuration config, final Context context,
         LogRecordExporter delegate, boolean batchEnabled) {
        this(id, config, context, null, !batchEnabled, () -> Objects.requireNonNull(delegate));
    }

    Otlp(final String id, final Configuration config, final Context context,
         Supplier<LogRecordExporter> exporterFactory, boolean batchEnabled) {
        this(id, config, context, null, !batchEnabled, Objects.requireNonNull(exporterFactory));
    }

    private Otlp(final String id, final Configuration config, final Context context,
                 OutputStream targetStream, boolean testEnabled, Supplier<LogRecordExporter> suppliedExporterFactory) {
        this.id = id;
        this.configuration = config;
        this.blockOnOverflow = config.get(BLOCK_ON_OVERFLOW_CONFIG);
        this.pluginLogger = context == null ? LogManager.getLogger(Otlp.class) : context.getLogger(this);

        int maxQueueSize = queueSize();
        int numConsumers = (int) positiveSetting(NUM_CONSUMERS_CONFIG, 256);
        int maxBatchSize = (int) positiveSetting(MAX_BATCH_SIZE_CONFIG, Integer.MAX_VALUE);
        long scheduleDelay = positiveSetting(SCHEDULE_DELAY_CONFIG, Long.MAX_VALUE / 1_000_000);
        positiveSetting(TIMEOUT, Long.MAX_VALUE / 1_000_000_000);
        positiveSetting(CONNECT_TIMEOUT, Long.MAX_VALUE / 1_000_000_000);
        RetryPolicy retryPolicy = retryPolicyForConfig();
        if (maxBatchSize > maxQueueSize) {
            throw new IllegalArgumentException("max_batch_size must not exceed queue_size");
        }
        if (config.contains(EXPORT_TIMEOUT_CONFIG)) {
            pluginLogger.warn("export_timeout_millis is deprecated and ignored. Remove it from the configuration; use timeout (seconds) to limit each export request, including retries.");
        }

        Resource resource = Resource.create(getResourceAttributes());
        sdkMetrics = testEnabled ? null : new LogstashSdkMetrics(pluginLogger, id, maxQueueSize,
                context == null ? null : context.getMetric(this));
        try {
            Supplier<LogRecordExporter> exporterFactory = suppliedExporterFactory != null ? suppliedExporterFactory
                    : testEnabled ? () -> new StreamLogRecordExporter(new PrintStream(targetStream), config.get(ENDPOINT_CONFIG))
                    : exporterFactoryForConfig(config, sdkMetrics, retryPolicy);
            providerFactory = () -> createProvider(exporterFactory, testEnabled, resource, numConsumers,
                    maxQueueSize, maxBatchSize, scheduleDelay);
        } catch (RuntimeException | Error failure) {
            if (sdkMetrics != null) sdkMetrics.close();
            throw failure;
        }
    }

    private SdkLoggerProvider createProvider(Supplier<LogRecordExporter> exporterFactory, boolean testEnabled,
                                            Resource resource, int numConsumers, int maxQueueSize,
                                            int maxBatchSize, long scheduleDelay) {
        List<LogRecordExporter> exporters = new ArrayList<>();
        boolean exportersTransferred = false;
        LogRecordProcessor processor = null;
        try {
            DiagnosticLogRecordExporter.FailureLogLimiter limiter = new DiagnosticLogRecordExporter.FailureLogLimiter();
            for (int consumer = 0; consumer < (testEnabled ? 1 : numConsumers); consumer++) {
                LogRecordExporter exporter = exporterFactory.get();
                exporters.add(new DiagnosticLogRecordExporter(exporter, pluginLogger, id, configuration.get(ENDPOINT_CONFIG), limiter));
            }
            if (testEnabled) {
                processor = SimpleLogRecordProcessor.create(exporters.get(0));
                exportersTransferred = true;
            } else {
                var meterProvider = sdkMetrics.meterProvider();
                exportersTransferred = true;
                processor = new SharedQueueLogRecordProcessor(id, exporters, maxQueueSize, maxBatchSize,
                        scheduleDelay, blockOnOverflow, meterProvider);
            }
            return SdkLoggerProvider.builder()
                    .setResource(resource)
                    .addLogRecordProcessor(processor)
                    .build();
        } catch (RuntimeException | Error failure) {
            List<CompletableResultCode> shutdowns = new ArrayList<>();
            if (processor != null) {
                shutdowns.add(processor.shutdown());
            } else if (!exportersTransferred) {
                for (LogRecordExporter exporter : exporters) {
                    try {
                        shutdowns.add(exporter.shutdown());
                    } catch (RuntimeException shutdownFailure) {
                        failure.addSuppressed(shutdownFailure);
                    }
                }
            }
            CompletableResultCode.ofAll(shutdowns).whenComplete(this::finishShutdown);
            throw failure;
        }
    }

    private SdkLoggerProvider ensureStarted() {
        SdkLoggerProvider current = sdkLoggerProvider;
        if (current != null) return stopped ? null : current;
        synchronized (lifecycleLock) {
            if (stopped) return null;
            if (sdkLoggerProvider == null) {
                try {
                    sdkLoggerProvider = providerFactory.get();
                } catch (RuntimeException | Error failure) {
                    stopped = true;
                    shutdownStarted.set(true);
                    throw failure;
                } finally {
                    providerFactory = null;
                }
            }
            return sdkLoggerProvider;
        }
    }

    private int queueSize() {
        if (configuration.contains(MAX_QUEUE_SIZE_CONFIG)) {
            if (configuration.contains(QUEUE_SIZE_CONFIG)) {
                throw new IllegalArgumentException("Use queue_size or max_queue_size, not both");
            }
            int size = (int) positiveSetting(MAX_QUEUE_SIZE_CONFIG, Integer.MAX_VALUE);
            pluginLogger.warn("max_queue_size is deprecated; use queue_size instead.");
            return size;
        }
        return (int) positiveSetting(QUEUE_SIZE_CONFIG, Integer.MAX_VALUE);
    }

    private long positiveSetting(PluginConfigSpec<Long> setting, long maximum) {
        Object raw = configuration.getRawValue(setting);
        long value;
        try {
            value = raw instanceof String text ? Long.parseLong(text.trim()) : configuration.get(setting);
        } catch (NumberFormatException invalidNumber) {
            throw new IllegalArgumentException(setting.name() + " must be an integer", invalidNumber);
        }
        if (value <= 0 || value > maximum) {
            throw new IllegalArgumentException(setting.name() + " must be between 1 and " + maximum);
        }
        return value;
    }

    RetryPolicy retryPolicyForConfig() {
        long initialBackoff = positiveSetting(RETRY_INITIAL_BACKOFF_CONFIG, Long.MAX_VALUE / 1_000_000);
        long maxBackoff = positiveSetting(RETRY_MAX_BACKOFF_CONFIG, Long.MAX_VALUE / 1_000_000);
        long maxAttempts = positiveSetting(RETRY_MAX_ATTEMPTS_CONFIG, 5);
        if (maxAttempts < 2) throw new IllegalArgumentException("retry_max_attempts must be between 2 and 5");
        if (maxBackoff < initialBackoff) {
            throw new IllegalArgumentException("retry_max_backoff_millis must be at least retry_initial_backoff_millis");
        }
        Object raw = configuration.getRawValue(RETRY_BACKOFF_MULTIPLIER_CONFIG);
        double multiplier;
        try {
            multiplier = raw instanceof String text ? Double.parseDouble(text.trim())
                    : configuration.get(RETRY_BACKOFF_MULTIPLIER_CONFIG);
        } catch (NumberFormatException invalidNumber) {
            throw new IllegalArgumentException("retry_backoff_multiplier must be a finite number of at least 1", invalidNumber);
        }
        if (!Double.isFinite(multiplier) || multiplier < 1) {
            throw new IllegalArgumentException("retry_backoff_multiplier must be a finite number of at least 1");
        }
        return RetryPolicy.builder()
                .setInitialBackoff(Duration.ofMillis(initialBackoff))
                .setMaxBackoff(Duration.ofMillis(maxBackoff))
                .setBackoffMultiplier(multiplier)
                .setMaxAttempts((int) maxAttempts)
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
        if (events.isEmpty()) return;
        SdkLoggerProvider provider = ensureStarted();
        if (provider == null) return;
        Iterator<Event> z = events.iterator();
        while (z.hasNext() && !stopped) {
            emitLog(z.next(), provider);
        }
    }

    @Override
    public void stop() {
        boolean startShutdown;
        synchronized (lifecycleLock) {
            stopped = true;
            providerFactory = null;
            startShutdown = shutdownStarted.compareAndSet(false, true);
        }
        if (startShutdown) initiateShutdown();
        boolean interrupted = false;
        while (true) {
            try {
                done.await();
                break;
            } catch (InterruptedException interruption) {
                interrupted = true;
            }
        }
        if (interrupted) Thread.currentThread().interrupt();
    }

    private void initiateShutdown() {
        if (sdkLoggerProvider == null) {
            finishShutdown();
            return;
        }
        try {
            CompletableResultCode result = sdkLoggerProvider.shutdown();
            result.whenComplete(() -> {
                try {
                    if (!result.isSuccess()) {
                        pluginLogger.error("OTLP shutdown failed: output_id={}", id, result.getFailureThrowable());
                    }
                } finally {
                    finishShutdown();
                }
            });
        } catch (RuntimeException failure) {
            try {
                pluginLogger.error("OTLP shutdown failed: output_id={}", id, failure);
            } finally {
                finishShutdown();
            }
        }
    }

    private void finishShutdown() {
        LogstashSdkMetrics metrics = sdkMetrics;
        sdkMetrics = null;
        sdkLoggerProvider = null;
        try {
            if (metrics != null) metrics.close();
        } finally {
            done.countDown();
        }
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
                SSL_DISABLE_TLS_VERIFICATION,
                CONNECT_TIMEOUT,
                TIMEOUT,
                RETRY_INITIAL_BACKOFF_CONFIG,
                RETRY_MAX_BACKOFF_CONFIG,
                RETRY_BACKOFF_MULTIPLIER_CONFIG,
                RETRY_MAX_ATTEMPTS_CONFIG,
                QUEUE_SIZE_CONFIG,
                BLOCK_ON_OVERFLOW_CONFIG,
                MAX_QUEUE_SIZE_CONFIG,
                NUM_CONSUMERS_CONFIG,
                MAX_BATCH_SIZE_CONFIG,
                SCHEDULE_DELAY_CONFIG,
                EXPORT_TIMEOUT_CONFIG
        ));
    }

    @Override
    public String getId() {
        return id;
    }
}
