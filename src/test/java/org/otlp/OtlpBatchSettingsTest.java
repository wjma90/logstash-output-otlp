package org.otlp;

import co.elastic.logstash.api.Event;
import io.opentelemetry.sdk.common.CompletableResultCode;
import io.opentelemetry.sdk.logs.data.LogRecordData;
import io.opentelemetry.sdk.logs.export.LogRecordExporter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.logstash.plugins.ConfigurationImpl;

import java.time.Duration;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.LinkedBlockingQueue;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.jupiter.api.Assertions.*;

@Timeout(value = 5, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
class OtlpBatchSettingsTest {
    private final StubExporter exporter = new StubExporter();
    private Otlp output;

    @AfterEach
    void closeOutput() {
        exporter.firstResult.succeed();
        if (output != null) output.stop();
    }

    @Test
    void registersBatchOptionsWithSdkDefaults() {
        output = newOutput(Map.of());
        List<String> names = output.configSchema().stream().map(setting -> setting.name()).toList();
        assertTrue(names.containsAll(List.of("max_queue_size", "max_batch_size",
                "schedule_delay_millis", "export_timeout_millis")));

        ConfigurationImpl defaults = new ConfigurationImpl(Map.of());
        assertEquals(2048L, defaults.get(Otlp.MAX_QUEUE_SIZE_CONFIG));
        assertEquals(512L, defaults.get(Otlp.MAX_BATCH_SIZE_CONFIG));
        assertEquals(1000L, defaults.get(Otlp.SCHEDULE_DELAY_CONFIG));
        assertEquals(30000L, defaults.get(Otlp.EXPORT_TIMEOUT_CONFIG));
    }

    @Test
    void rejectsInvalidSettingsBeforeStartingTheExporter() {
        for (String name : List.of("max_queue_size", "max_batch_size",
                "schedule_delay_millis", "export_timeout_millis", "timeout")) {
            for (long value : new long[]{0, -1, Long.MAX_VALUE}) {
                IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                        () -> output = newOutput(Map.of(name, value)));
                assertTrue(error.getMessage().contains(name));
            }
        }
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> output = newOutput(Map.of("max_queue_size", 2L, "max_batch_size", 3L)));
        assertTrue(error.getMessage().contains("max_batch_size must not exceed max_queue_size"));
        error = assertThrows(IllegalArgumentException.class,
                () -> output = newOutput(Map.of("export_timeout_millis", 9999L)));
        assertTrue(error.getMessage().contains("export_timeout_millis must be at least timeout * 1000"));
        assertEquals(0, exporter.shutdownCalls);
        assertTrue(exporter.batches.isEmpty());
    }

    @Test
    void fullBatchExportsBeforeTheScheduledDelay() throws Exception {
        output = newOutput(Map.of("max_queue_size", 4L, "max_batch_size", 2L,
                "schedule_delay_millis", 60000L));
        output.output(List.of(event("first")));
        assertNull(exporter.batches.poll(100, MILLISECONDS));

        output.output(List.of(event("second")));

        assertEquals(List.of("first", "second"), exporter.batches.poll(2, SECONDS));
    }

    @Test
    void scheduledDelayExportsAnIncompleteBatch() throws Exception {
        output = newOutput(Map.of("schedule_delay_millis", 50L));

        output.output(List.of(event("single event")));

        assertEquals(List.of("single event"), exporter.batches.poll(750, MILLISECONDS));
    }

    @Test
    void fullQueueDropsExcessEventsWhileAnExportIsPending() throws Exception {
        exporter.firstResult = new CompletableResultCode();
        output = newOutput(Map.of("max_queue_size", 2L, "max_batch_size", 1L));
        output.output(List.of(event("in flight")));
        assertEquals(List.of("in flight"), exporter.batches.poll(2, SECONDS));

        output.output(List.of(event("queued first"), event("queued second"), event("dropped")));
        exporter.firstResult.succeed();
        output.stop();

        assertEquals(List.of("in flight", "queued first", "queued second"), List.copyOf(exporter.bodies));
    }

    @Test
    void exportTimeoutBoundsHowLongTheProcessorWaits() throws Exception {
        exporter.firstResult = new CompletableResultCode();
        output = newOutput(Map.of("max_batch_size", 1L, "export_timeout_millis", 1000L,
                "timeout", 1L));
        output.output(List.of(event("pending export")));
        assertEquals(List.of("pending export"), exporter.batches.poll(2, SECONDS));

        assertTimeoutPreemptively(Duration.ofSeconds(3), output::stop);

        assertEquals(1, exporter.shutdownCalls);
        assertFalse(exporter.firstResult.isDone());
    }

    private Otlp newOutput(Map<String, Object> settings) {
        Map<String, Object> config = new HashMap<>(settings);
        config.put("endpoint", "http://127.0.0.1:4318/v1/logs");
        config.put("protocol", "http");
        return new Otlp("batch-test", new ConfigurationImpl(config), null, exporter, true);
    }

    private static Event event(String body) {
        Event event = new org.logstash.Event();
        event.setField("message", body);
        return event;
    }

    private static final class StubExporter implements LogRecordExporter {
        private final BlockingQueue<List<String>> batches = new LinkedBlockingQueue<>();
        private final ConcurrentLinkedQueue<String> bodies = new ConcurrentLinkedQueue<>();
        private CompletableResultCode firstResult = CompletableResultCode.ofSuccess();
        private int exportCalls;
        private int shutdownCalls;

        @Override
        public CompletableResultCode export(Collection<LogRecordData> logs) {
            List<String> batch = logs.stream().map(log -> String.valueOf(log.getBodyValue().getValue())).toList();
            bodies.addAll(batch);
            batches.add(batch);
            return exportCalls++ == 0 ? firstResult : CompletableResultCode.ofSuccess();
        }

        @Override
        public CompletableResultCode flush() {
            return CompletableResultCode.ofSuccess();
        }

        @Override
        public CompletableResultCode shutdown() {
            shutdownCalls++;
            return CompletableResultCode.ofSuccess();
        }
    }
}
