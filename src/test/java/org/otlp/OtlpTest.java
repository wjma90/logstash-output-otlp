package org.otlp;

import co.elastic.logstash.api.Configuration;
import co.elastic.logstash.api.Event;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.logstash.plugins.ConfigurationImpl;

import java.io.ByteArrayOutputStream;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.HashMap;
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
}
