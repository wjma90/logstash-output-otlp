package org.otlp;

import co.elastic.logstash.api.Event;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.sdk.common.CompletableResultCode;
import io.opentelemetry.sdk.logs.data.LogRecordData;
import io.opentelemetry.sdk.logs.export.LogRecordExporter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.logstash.plugins.ConfigurationImpl;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(value = 10, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
class OtlpMappingTest {
    private final ConcurrentLinkedQueue<LogRecordData> records = new ConcurrentLinkedQueue<>();
    private final AtomicInteger exportersCreated = new AtomicInteger();
    private final AtomicInteger exportersClosed = new AtomicInteger();
    private Otlp output;

    @AfterEach
    void closeOutput() {
        if (output != null) output.stop();
    }

    @Test
    void preservesConfiguredPayloadThroughSharedQueueConsumers() {
        output = newOutput(Map.of(
                "body", "custom_body",
                "severity_text", "level",
                "trace_id", "[context][trace_id]",
                "span_id", "[context][span_id]",
                "trace_flags", "[context][trace_flags]",
                "resource", Map.of("service.name", "mapping-regression", "deployment.environment.name", "local"),
                "attributes", Map.of("http.route", "[http][request][path]", "selected.value", "selected")));
        Instant original = Instant.parse("2026-06-04T18:45:42.704321Z");
        String traceId = "5b8aa5a2d2c872e8321cf37308d69df2";
        String spanId = "051581bf3cb55c13";
        List<Event> events = new ArrayList<>();
        for (int index = 0; index < 6; index++) {
            Event event = new org.logstash.Event();
            event.setEventTimestamp(original);
            event.setField("message", "unused default body");
            event.setField("custom_body", "configured " + index);
            event.setField("level", "WARN");
            event.setField("selected", "selected " + index);
            event.setField("[http][request][path]", "/records/" + index);
            event.setField("[context][trace_id]", traceId);
            event.setField("[context][span_id]", spanId);
            event.setField("[context][trace_flags]", "01");
            event.setField("unmapped", "excluded");
            events.add(event);
        }

        output.output(events);
        output.stop();

        assertEquals(2, exportersCreated.get());
        assertEquals(2, exportersClosed.get());
        assertEquals(6, records.size());
        assertEquals(6, records.stream().map(record -> record.getBodyValue().getValue()).distinct().count());
        for (LogRecordData record : records) {
            String body = String.valueOf(record.getBodyValue().getValue());
            int index = Integer.parseInt(body.substring("configured ".length()));
            assertEquals("WARN", record.getSeverityText());
            assertEquals(Attributes.builder().put("http.route", "/records/" + index)
                    .put("selected.value", "selected " + index).build(), record.getAttributes());
            assertEquals(traceId, record.getSpanContext().getTraceId());
            assertEquals(spanId, record.getSpanContext().getSpanId());
            assertTrue(record.getSpanContext().isSampled());
            assertEquals(1, record.getSpanContext().getTraceFlags().asByte());
            Instant eventTimestamp = events.get(index).getEventTimestamp();
            assertEquals(eventTimestamp.getEpochSecond() * 1_000_000_000L + eventTimestamp.getNano(),
                    record.getObservedTimestampEpochNanos());
            assertEquals(original.toEpochMilli(), Math.floorDiv(record.getTimestampEpochNanos(), 1_000_000L));
            assertNotEquals(record.getObservedTimestampEpochNanos(), record.getTimestampEpochNanos());
            Attributes resource = record.getResource().getAttributes();
            assertEquals("mapping-regression", resource.get(AttributeKey.stringKey("service.name")));
            assertEquals("local", resource.get(AttributeKey.stringKey("deployment.environment.name")));
        }
    }

    @Test
    void missingMappedFieldsStillEmitWithoutTraceContext() {
        output = newOutput(Map.of(
                "body", "missing_body",
                "severity_text", "missing_severity",
                "trace_id", "missing_trace_id",
                "span_id", "missing_span_id",
                "trace_flags", "missing_flags",
                "attributes", Map.of("missing.attribute", "[missing][nested]")));
        Event event = new org.logstash.Event();
        event.setField("message", "default body is not selected");

        output.output(List.of(event));
        output.stop();

        assertEquals(1, records.size());
        LogRecordData record = records.element();
        assertEquals("", record.getBodyValue().getValue());
        assertEquals("", record.getSeverityText());
        assertFalse(record.getSpanContext().isValid());
        assertEquals(Attributes.of(AttributeKey.stringKey("missing.attribute"), ""), record.getAttributes());
        assertEquals(2, exportersClosed.get());
    }

    @Test
    void defaultMappingPreservesBodyAttributesAndPluginMetadata() {
        output = newOutput(Map.of());
        Event event = new org.logstash.Event();
        event.setField("message", "default body");
        event.setField("category", "application");
        event.setField("count", 42);

        output.output(List.of(event));
        output.stop();

        assertEquals(1, records.size());
        LogRecordData record = records.element();
        assertEquals("default body", record.getBodyValue().getValue());
        assertEquals("", record.getSeverityText());
        assertFalse(record.getSpanContext().isValid());
        assertEquals("application", record.getAttributes().get(AttributeKey.stringKey("category")));
        assertEquals("42", record.getAttributes().get(AttributeKey.stringKey("count")));
        assertNull(record.getAttributes().get(AttributeKey.stringKey("@timestamp")));
        Attributes resource = record.getResource().getAttributes();
        assertEquals("logstash-output-otlp", resource.get(AttributeKey.stringKey("telemetry.sdk.name")));
        assertEquals("java", resource.get(AttributeKey.stringKey("telemetry.sdk.language")));
        assertEquals(Otlp.class.getPackage().getImplementationVersion(), resource.get(AttributeKey.stringKey("telemetry.sdk.version")));
        assertEquals("mapping-test", resource.get(AttributeKey.stringKey("agent.id")));
        assertEquals("logstash-output-otlp", record.getInstrumentationScopeInfo().getName());
        assertEquals(2, exportersClosed.get());
    }

    private Otlp newOutput(Map<String, Object> settings) {
        Map<String, Object> config = new HashMap<>(settings);
        config.put("endpoint", "http://127.0.0.1:4318/v1/logs");
        config.put("protocol", "http");
        config.put("num_consumers", 2L);
        config.put("queue_size", 16L);
        config.put("max_batch_size", 4L);
        config.put("schedule_delay_millis", 60000L);
        return new Otlp("mapping-test", new ConfigurationImpl(config), null, () -> {
            exportersCreated.incrementAndGet();
            return new CapturingExporter();
        }, true);
    }

    private final class CapturingExporter implements LogRecordExporter {
        @Override
        public CompletableResultCode export(Collection<LogRecordData> logs) {
            records.addAll(logs);
            return CompletableResultCode.ofSuccess();
        }

        @Override
        public CompletableResultCode flush() { return CompletableResultCode.ofSuccess(); }

        @Override
        public CompletableResultCode shutdown() {
            exportersClosed.incrementAndGet();
            return CompletableResultCode.ofSuccess();
        }
    }
}
