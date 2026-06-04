package org.otlp;

import co.elastic.logstash.api.Configuration;
import co.elastic.logstash.api.Event;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;
import org.junit.jupiter.api.Test;
import org.logstash.plugins.ConfigurationImpl;

import java.io.ByteArrayOutputStream;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

public class OtlpTest {

    @Test
    public void logstashOtlpBasic() {
        String endpoint = "http://localhost:4317";
        Map<String, Object> configValues = new HashMap<>();
        configValues.put(Otlp.ENDPOINT_CONFIG.name(), endpoint);
        configValues.put(Otlp.TRACE_ID_CONFIG.name(), "trace.id");
        configValues.put(Otlp.SPAN_ID_CONFIG.name(), "span.id");

        Configuration config = new ConfigurationImpl(configValues);
        ByteArrayOutputStream bas = new ByteArrayOutputStream();
        Otlp output = new Otlp("test-id", config, null, bas, true);

        String sourceField = "message";
        int eventCount = 5;
        Collection<Event> events = new ArrayList<>();
        for (int k = 0; k < eventCount; k++) {
            Event e = new org.logstash.Event();
            e.setField(sourceField, "message " + k);
            // https://opentelemetry.io/docs/concepts/signals/traces/
            e.setField("trace.id", "5b8aa5a2d2c872e8321cf37308d69df2");
            e.setField("span.id", "051581bf3cb55c13");
            events.add(e);
        }

        output.output(events);

        String outputString = bas.toString();
        int index = 0;
        int lastIndex = 0;
        while (index < eventCount) {
            lastIndex = outputString.indexOf(endpoint, lastIndex);
            assertTrue(lastIndex > -1, "Prefix should exist in output string");
            lastIndex = outputString.indexOf("message " + index);
            assertTrue(lastIndex > -1, "Message should exist in output string");
            index++;
        }

        output.stop();
    }

    @Test
    public void logstashOtlpDoesNotWarnWhenTlsVerificationIsEnabled() {
        String endpoint = "https://localhost:4317";
        Map<String, Object> configValues = new HashMap<>();
        configValues.put(Otlp.ENDPOINT_CONFIG.name(), endpoint);

        Configuration config = new ConfigurationImpl(configValues);

        try (LogCapture logs = LogCapture.start(Level.DEBUG)) {
            Otlp output = new Otlp("test-id", config, null, false);
            output.stop();

            assertFalse(logs.contains(Level.WARN, "ssl_disable_tls_verification is enabled"));
        }
    }

    @Test
    public void logstashOtlpWarnsWhenTlsVerificationIsDisabled() {
        String endpoint = "https://localhost:4317";
        Map<String, Object> configValues = new HashMap<>();
        configValues.put(Otlp.ENDPOINT_CONFIG.name(), endpoint);
        configValues.put(Otlp.SSL_DISABLE_TLS_VERIFICATION.name(), true);

        Configuration config = new ConfigurationImpl(configValues);

        try (LogCapture logs = LogCapture.start(Level.DEBUG)) {
            Otlp output = new Otlp("test-id", config, null, false);
            output.stop();

            assertTrue(logs.contains(Level.WARN, "ssl_disable_tls_verification is enabled"));
            assertTrue(logs.contains(Level.WARN, "trust any TLS certificate"));
        }
    }

    @Test
    public void logstashOtlpAcceptsValidTraceContextFields() {
        String endpoint = "http://localhost:4317";
        Map<String, Object> configValues = new HashMap<>();
        configValues.put(Otlp.ENDPOINT_CONFIG.name(), endpoint);
        configValues.put(Otlp.TRACE_ID_CONFIG.name(), "trace.id");
        configValues.put(Otlp.SPAN_ID_CONFIG.name(), "span.id");
        configValues.put(Otlp.TRACE_FLAGS_CONFIG.name(), "traceflags");

        Configuration config = new ConfigurationImpl(configValues);
        ByteArrayOutputStream bas = new ByteArrayOutputStream();

        try (LogCapture logs = LogCapture.start(Level.DEBUG)) {
            Otlp output = new Otlp("test-id", config, null, bas, true);

            Event event = new org.logstash.Event();
            event.setField("message", "valid trace context");
            event.setField("trace.id", "5b8aa5a2d2c872e8321cf37308d69df2");
            event.setField("span.id", "051581bf3cb55c13");
            event.setField("traceflags", "01");

            output.output(List.of(event));
            output.stop();

            assertTrue(bas.toString().contains("valid trace context"));
            assertFalse(logs.contains(Level.DEBUG, "Malformed trace_id"));
            assertFalse(logs.contains(Level.DEBUG, "Invalid trace_flags"));
        }
    }

    @Test
    public void logstashOtlpLogsMalformedTraceIdAndEmitsLog() {
        String endpoint = "http://localhost:4317";
        Map<String, Object> configValues = new HashMap<>();
        configValues.put(Otlp.ENDPOINT_CONFIG.name(), endpoint);
        configValues.put(Otlp.TRACE_ID_CONFIG.name(), "trace.id");
        configValues.put(Otlp.SPAN_ID_CONFIG.name(), "span.id");
        configValues.put(Otlp.TRACE_FLAGS_CONFIG.name(), "traceflags");

        Configuration config = new ConfigurationImpl(configValues);
        ByteArrayOutputStream bas = new ByteArrayOutputStream();

        try (LogCapture logs = LogCapture.start(Level.DEBUG)) {
            Otlp output = new Otlp("test-id", config, null, bas, true);

            Event event = new org.logstash.Event();
            event.setField("message", "malformed trace id");
            event.setField("trace.id", "not-a-trace-id");
            event.setField("span.id", "051581bf3cb55c13");
            event.setField("traceflags", "01");

            output.output(List.of(event));
            output.stop();

            assertTrue(bas.toString().contains("malformed trace id"));
            assertTrue(logs.contains(Level.DEBUG, "Malformed trace_id or span_id value"));
        }
    }

    @Test
    public void logstashOtlpDoesNotFailOnInvalidTraceContextFields() {
        String endpoint = "http://localhost:4317";
        Map<String, Object> configValues = new HashMap<>();
        configValues.put(Otlp.ENDPOINT_CONFIG.name(), endpoint);
        configValues.put(Otlp.TRACE_ID_CONFIG.name(), "trace.id");
        configValues.put(Otlp.SPAN_ID_CONFIG.name(), "span.id");
        configValues.put(Otlp.TRACE_FLAGS_CONFIG.name(), "traceflags");

        Configuration config = new ConfigurationImpl(configValues);
        ByteArrayOutputStream bas = new ByteArrayOutputStream();
        Otlp output = new Otlp("test-id", config, null, bas, true);

        Collection<Event> events = new ArrayList<>();

        Event invalidIds = new org.logstash.Event();
        invalidIds.setField("message", "invalid trace ids");
        invalidIds.setField("trace.id", "not-a-trace-id");
        invalidIds.setField("span.id", "not-a-span-id");
        invalidIds.setField("traceflags", "zz");
        events.add(invalidIds);

        Event invalidFlags = new org.logstash.Event();
        invalidFlags.setField("message", "invalid trace flags");
        invalidFlags.setField("trace.id", "5b8aa5a2d2c872e8321cf37308d69df2");
        invalidFlags.setField("span.id", "051581bf3cb55c13");
        invalidFlags.setField("traceflags", "zz");
        events.add(invalidFlags);

        output.output(events);
        output.stop();

        String outputString = bas.toString();
        assertTrue(outputString.contains("invalid trace ids"));
        assertTrue(outputString.contains("invalid trace flags"));
        assertEquals(2, outputString.trim().split("\\R").length);
    }

    @Test
    public void logstashOtlpDisambiguatesSameTimestampPerLogRecord() {
        String endpoint = "http://localhost:4317";
        Map<String, Object> configValues = new HashMap<>();
        configValues.put(Otlp.ENDPOINT_CONFIG.name(), endpoint);

        Configuration config = new ConfigurationImpl(configValues);
        ByteArrayOutputStream bas = new ByteArrayOutputStream();
        Otlp output = new Otlp("test-id", config, null, bas, true);

        Instant sourceTimestamp = Instant.parse("2026-06-04T18:45:42.704Z");
        long sourceTimestampNanos = toEpochNanos(sourceTimestamp);
        int eventCount = 5;
        Collection<Event> events = new ArrayList<>();

        for (int k = 0; k < eventCount; k++) {
            Event e = new org.logstash.Event();
            e.setEventTimestamp(sourceTimestamp);
            e.setField("message", "Transaccion completa");
            e.setField("ReferenceTransactionID", "BCBTSW25051212442400000" + k + ".001");
            events.add(e);
        }

        output.output(events);
        output.stop();

        String[] outputLines = bas.toString().trim().split("\\R");
        Set<Long> timestamps = new HashSet<>();
        assertEquals(eventCount, outputLines.length);

        for (String line : outputLines) {
            String[] parts = line.split(" ", 4);
            assertEquals(endpoint, parts[0]);

            long timestampNanos = Long.parseLong(parts[1]);
            long observedTimestampNanos = Long.parseLong(parts[2]);

            assertTrue(timestampNanos > sourceTimestampNanos);
            assertTrue(timestampNanos <= sourceTimestampNanos + 499_999L);
            assertEquals(sourceTimestamp.toEpochMilli(), truncateEpochNanosToMillis(timestampNanos));
            assertEquals(sourceTimestamp.toEpochMilli(), roundEpochNanosToMillis(timestampNanos));
            assertEquals(sourceTimestampNanos, observedTimestampNanos);
            timestamps.add(timestampNanos);
        }

        assertEquals(eventCount, timestamps.size(), "Each LogRecord should receive a distinct timestamp nanosecond");
    }

    @Test
    public void logstashOtlpKeepsDisambiguatedTimestampWithinSourceMillisecond() {
        Instant[] sourceTimestamps = new Instant[] {
                Instant.parse("2026-06-04T18:45:42.704Z"),
                Instant.parse("2026-06-04T18:45:42.704999999Z"),
                Instant.parse("2026-06-04T18:45:59.999999999Z")
        };
        long[] offsets = new long[] {1L, 250_000L, 499_999L};

        for (Instant sourceTimestamp : sourceTimestamps) {
            for (long offsetNanos : offsets) {
                long adjustedTimestampNanos = toEpochNanos(
                        Otlp.timestampWithNanosecondDisambiguation(sourceTimestamp, offsetNanos)
                );

                assertEquals(
                        sourceTimestamp.toEpochMilli(),
                        truncateEpochNanosToMillis(adjustedTimestampNanos),
                        "Truncating to milliseconds should preserve " + sourceTimestamp
                );
                assertEquals(
                        sourceTimestamp.toEpochMilli(),
                        roundEpochNanosToMillis(adjustedTimestampNanos),
                        "Rounding to milliseconds should preserve " + sourceTimestamp
                );
            }
        }
    }

    private long toEpochNanos(Instant instant) {
        return TimeUnit.SECONDS.toNanos(instant.getEpochSecond()) + instant.getNano();
    }

    private long truncateEpochNanosToMillis(long epochNanos) {
        return TimeUnit.NANOSECONDS.toMillis(epochNanos);
    }

    private long roundEpochNanosToMillis(long epochNanos) {
        return (epochNanos + 500_000L) / 1_000_000L;
    }

    private static final class LogCapture implements AutoCloseable {
        private final CapturingAppender appender;
        private final org.apache.logging.log4j.core.Logger logger;
        private final Level originalLevel;

        private LogCapture(CapturingAppender appender, org.apache.logging.log4j.core.Logger logger, Level originalLevel) {
            this.appender = appender;
            this.logger = logger;
            this.originalLevel = originalLevel;
        }

        static LogCapture start(Level level) {
            org.apache.logging.log4j.core.Logger logger =
                    (org.apache.logging.log4j.core.Logger) LogManager.getLogger(Otlp.class);
            Level originalLevel = logger.getLevel();
            CapturingAppender appender = new CapturingAppender("otlp-test-" + System.nanoTime());
            appender.start();
            logger.addAppender(appender);
            logger.setLevel(level);
            return new LogCapture(appender, logger, originalLevel);
        }

        boolean contains(Level level, String text) {
            return appender.events.stream().anyMatch(event ->
                    event.getLevel().equals(level) && event.getMessage().getFormattedMessage().contains(text)
            );
        }

        @Override
        public void close() {
            logger.removeAppender(appender);
            logger.setLevel(originalLevel);
            appender.stop();
        }
    }

    private static final class CapturingAppender extends AbstractAppender {
        private final List<LogEvent> events = new ArrayList<>();

        private CapturingAppender(String name) {
            super(name, null, null, false, Property.EMPTY_ARRAY);
        }

        @Override
        public void append(LogEvent event) {
            events.add(event.toImmutable());
        }
    }
}
