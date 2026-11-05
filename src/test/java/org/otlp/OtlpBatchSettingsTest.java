package org.otlp;

import co.elastic.logstash.api.Event;
import io.opentelemetry.sdk.common.CompletableResultCode;
import io.opentelemetry.sdk.logs.data.LogRecordData;
import io.opentelemetry.sdk.logs.export.LogRecordExporter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.logstash.plugins.ConfigurationImpl;

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
    void registersSharedQueueOptionsWithCompatibleDefaults() {
        output = newOutput(Map.of());
        List<String> names = output.configSchema().stream().map(setting -> setting.name()).toList();
        assertTrue(names.containsAll(List.of("queue_size", "num_consumers", "max_batch_size",
                "schedule_delay_millis", "max_queue_size")));
        assertFalse(names.contains("export_timeout_millis"));

        ConfigurationImpl defaults = new ConfigurationImpl(Map.of());
        assertEquals(2048L, defaults.get(Otlp.QUEUE_SIZE_CONFIG));
        assertEquals(1L, defaults.get(Otlp.NUM_CONSUMERS_CONFIG));
        assertEquals(512L, defaults.get(Otlp.MAX_BATCH_SIZE_CONFIG));
        assertEquals(1000L, defaults.get(Otlp.SCHEDULE_DELAY_CONFIG));
        assertTrue(Otlp.MAX_QUEUE_SIZE_CONFIG.deprecated());
    }

    @Test
    void rejectsInvalidSettingsBeforeStartingTheExporter() {
        for (String name : List.of("queue_size", "max_queue_size", "num_consumers", "max_batch_size",
                "schedule_delay_millis", "timeout", "connect_timeout")) {
            for (long value : new long[]{0, -1, Long.MAX_VALUE}) {
                IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                        () -> output = newOutput(Map.of(name, value)));
                assertTrue(error.getMessage().contains(name));
            }
        }
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> output = newOutput(Map.of("queue_size", 2L, "max_batch_size", 3L)));
        assertTrue(error.getMessage().contains("max_batch_size must not exceed queue_size"));
        error = assertThrows(IllegalArgumentException.class,
                () -> output = newOutput(Map.of("num_consumers", 257L)));
        assertTrue(error.getMessage().contains("num_consumers"));
        error = assertThrows(IllegalArgumentException.class,
                () -> output = newOutput(Map.of("queue_size", 2048L, "max_queue_size", 2048L)));
        assertTrue(error.getMessage().contains("not both"));
        assertEquals(0, exporter.shutdownCalls);
        assertTrue(exporter.batches.isEmpty());
    }

    @Test
    void acceptsNumericEnvironmentValuesAndRejectsInvalidText() throws Exception {
        for (String name : List.of("queue_size", "num_consumers", "max_batch_size", "schedule_delay_millis",
                "timeout", "connect_timeout")) {
            IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                    () -> newOutput(Map.of(name, "1.5")));
            assertTrue(error.getMessage().contains(name));
        }
        output = newOutput(Map.of("queue_size", "32", "num_consumers", "1", "max_batch_size", "1",
                "schedule_delay_millis", "100", "timeout", "10", "connect_timeout", "10"));
        output.output(List.of(event("environment config")));
        assertEquals(List.of("environment config"), exporter.batches.poll(2, SECONDS));
    }

    @Test
    void fullBatchExportsBeforeTheScheduledDelay() throws Exception {
        output = newOutput(Map.of("queue_size", 4L, "max_batch_size", 2L,
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
    void requestTimeoutIsIndependentOfTheBatchFormationDelay() {
        output = newOutput(Map.of("timeout", 60L, "schedule_delay_millis", 10L));
        output.output(List.of(event("independent timeouts")));
        output.stop();
        assertEquals(1, exporter.shutdownCalls);
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
