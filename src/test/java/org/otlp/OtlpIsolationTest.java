package org.otlp;

import co.elastic.logstash.api.Event;
import io.opentelemetry.sdk.common.CompletableResultCode;
import io.opentelemetry.sdk.logs.data.LogRecordData;
import io.opentelemetry.sdk.logs.export.LogRecordExporter;
import org.apache.logging.log4j.LogManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.logstash.plugins.ConfigurationImpl;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.jupiter.api.Assertions.*;

@Timeout(value = 15, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
class OtlpIsolationTest {
    @Test
    void aFullQueueAndClosingOneOutputDoNotAffectAnotherOutput() throws Exception {
        RecordingPluginContext blockedMetrics = new RecordingPluginContext("blocked-output", LogManager.getLogger(getClass()));
        RecordingPluginContext healthyMetrics = new RecordingPluginContext("healthy-output", LogManager.getLogger(getClass()));
        RecordingExporter blockedExporter = new RecordingExporter(new CompletableResultCode());
        RecordingExporter healthyExporter = new RecordingExporter(CompletableResultCode.ofSuccess());
        Otlp blocked = output("blocked-output", 2, blockedMetrics, blockedExporter);
        Otlp healthy = output("healthy-output", 4, healthyMetrics, healthyExporter);
        var caller = Executors.newSingleThreadExecutor();
        Set<Thread> workers = Set.of();
        try {
            blocked.output(List.of(event("blocked-inflight")));
            assertTrue(blockedExporter.started.await(3, SECONDS));
            blocked.output(List.of(event("blocked-queued-1"), event("blocked-queued-2"), event("blocked-dropped")));
            healthy.output(List.of(event("healthy-1"), event("healthy-2")));

            blockedMetrics.awaitValue("otel.sdk.processor.log.processed", "queue_full", 1);
            healthyMetrics.awaitValue("otel.sdk.processor.log.processed", "", 2);
            assertEquals(2, blockedMetrics.value("otel.sdk.processor.log.queue.size", ""));
            assertEquals(2, blockedMetrics.value("otel.sdk.processor.log.queue.capacity", ""));
            assertEquals(4, healthyMetrics.value("otel.sdk.processor.log.queue.capacity", ""));
            assertEquals(0, healthyMetrics.value("otel.sdk.processor.log.processed", "queue_full"));
            assertEquals("shared_queue_log_processor/blocked-output", blockedMetrics.component("otel.sdk.processor.log.queue.size"));
            assertEquals("shared_queue_log_processor/healthy-output", healthyMetrics.component("otel.sdk.processor.log.queue.size"));

            workers = workers();
            assertEquals(4, workers.size());
            var closing = caller.submit(blocked::stop);
            healthy.output(List.of(event("healthy-during-other-stop")));
            healthyMetrics.awaitValue("otel.sdk.processor.log.processed", "", 3);
            assertFalse(closing.isDone());
            assertEquals(0, healthyExporter.closed.get());

            blockedExporter.result.succeed();
            closing.get(3, SECONDS);
            assertEquals(1, blockedExporter.closed.get());
            assertEquals(0, healthyExporter.closed.get());

            healthy.output(List.of(event("healthy-after-other-stop")));
            healthy.stop();
            assertEquals(List.of("blocked-inflight", "blocked-queued-1", "blocked-queued-2"), blockedExporter.bodies);
            assertEquals(List.of("healthy-1", "healthy-2", "healthy-during-other-stop", "healthy-after-other-stop"), healthyExporter.bodies);
            assertEquals(1, healthyExporter.closed.get());
        } finally {
            blockedExporter.result.succeed();
            blocked.stop();
            healthy.stop();
            caller.shutdownNow();
            assertTrue(caller.awaitTermination(3, SECONDS));
            for (Thread worker : workers) {
                worker.join(TimeUnit.SECONDS.toMillis(3));
                assertFalse(worker.isAlive(), worker.getName());
            }
        }
    }

    private static Otlp output(String id, long capacity, RecordingPluginContext context, RecordingExporter exporter) {
        return new Otlp(id, new ConfigurationImpl(Map.of(
                "endpoint", "http://127.0.0.1:4318/v1/logs", "protocol", "http",
                "queue_size", capacity, "max_batch_size", 1L)), context, () -> exporter, true);
    }

    private static Event event(String body) {
        Event event = new org.logstash.Event();
        event.setField("message", body);
        return event;
    }

    private static Set<Thread> workers() {
        return Thread.getAllStackTraces().keySet().stream().filter(thread -> thread.isAlive()
                && (thread.getName().startsWith("otlp-export-worker-blocked-output-")
                || thread.getName().startsWith("otlp-export-worker-healthy-output-")
                || thread.getName().equals("otlp-sdk-metrics-blocked-output")
                || thread.getName().equals("otlp-sdk-metrics-healthy-output"))).collect(Collectors.toSet());
    }

    private static final class RecordingExporter implements LogRecordExporter {
        private final CompletableResultCode result;
        private final CountDownLatch started = new CountDownLatch(1);
        private final List<String> bodies = new CopyOnWriteArrayList<>();
        private final AtomicInteger closed = new AtomicInteger();

        private RecordingExporter(CompletableResultCode result) { this.result = result; }

        @Override
        public CompletableResultCode export(Collection<LogRecordData> logs) {
            logs.forEach(log -> bodies.add(String.valueOf(log.getBodyValue().getValue())));
            started.countDown();
            return result;
        }

        @Override
        public CompletableResultCode flush() { return CompletableResultCode.ofSuccess(); }

        @Override
        public CompletableResultCode shutdown() {
            closed.incrementAndGet();
            return CompletableResultCode.ofSuccess();
        }
    }
}
