package org.otlp;

import co.elastic.logstash.api.Event;
import io.opentelemetry.sdk.common.CompletableResultCode;
import io.opentelemetry.sdk.logs.data.LogRecordData;
import io.opentelemetry.sdk.logs.export.LogRecordExporter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.parallel.Isolated;
import org.logstash.plugins.ConfigurationImpl;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Handler;
import java.util.logging.Logger;

import static java.util.concurrent.TimeUnit.SECONDS;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static org.junit.jupiter.api.Assertions.*;

@Isolated
@Timeout(value = 10, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
class OtlpLifecycleTest {
    private final StubExporter exporter = new StubExporter();
    private final Set<Thread> workers = new HashSet<>();
    private final ExecutorService executor = Executors.newFixedThreadPool(3, action -> {
        Thread thread = new Thread(action, "otlp-lifecycle-test");
        thread.setDaemon(true);
        return thread;
    });
    private Otlp output;

    @AfterEach
    void closeResources() throws Exception {
        exporter.exportResult.succeed();
        exporter.shutdownResult.succeed();
        try {
            if (output != null) executor.submit(output::stop).get(5, SECONDS);
        } finally {
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(5, SECONDS));
            for (Thread worker : workers) {
                worker.join(5000);
                assertFalse(worker.isAlive(), "SDK worker remains after shutdown");
            }
        }
    }

    @Test
    void stopClosesOnceAndPreventsFurtherExports() throws Exception {
        output = newOutput(false);
        output.output(List.of(event("before stop")));

        output.stop();
        output.stop();
        output.awaitStop();
        output.output(List.of(event("after stop")));

        assertEquals(1, exporter.shutdownCalls.get());
        assertEquals(List.of("before stop"), List.copyOf(exporter.bodies));
    }

    @Test
    void stopAndAwaitStopWaitUntilShutdownCompletes() throws Exception {
        exporter.shutdownResult = new CompletableResultCode();
        output = newOutput(false);
        Future<?> stopping = executor.submit(output::stop);
        assertTrue(exporter.shutdownStarted.await(5, SECONDS));
        Future<?> repeatedStop = executor.submit(output::stop);
        Future<?> waiting = executor.submit(() -> { output.awaitStop(); return null; });

        assertThrows(TimeoutException.class, () -> stopping.get(100, MILLISECONDS));
        assertThrows(TimeoutException.class, () -> repeatedStop.get(100, MILLISECONDS));
        assertThrows(TimeoutException.class, () -> waiting.get(100, MILLISECONDS));
        assertEquals(1, exporter.shutdownCalls.get());

        exporter.shutdownResult.succeed();
        stopping.get(5, SECONDS);
        repeatedStop.get(5, SECONDS);
        waiting.get(5, SECONDS);
    }

    @Test
    void failedShutdownAlsoReleasesStop() throws Exception {
        exporter.shutdownResult = new CompletableResultCode();
        output = newOutput(false);
        Future<?> stopping = executor.submit(output::stop);
        assertTrue(exporter.shutdownStarted.await(5, SECONDS));

        exporter.shutdownResult.fail();

        stopping.get(5, SECONDS);
        output.awaitStop();
        assertEquals(1, exporter.shutdownCalls.get());
    }

    @Test
    void interruptedStopStillWaitsAndRestoresTheInterrupt() throws Exception {
        exporter.shutdownResult = new CompletableResultCode();
        output = newOutput(false);
        Future<Boolean> stopping = executor.submit(() -> {
            Thread.currentThread().interrupt();
            output.stop();
            return Thread.currentThread().isInterrupted();
        });
        assertTrue(exporter.shutdownStarted.await(5, SECONDS));
        assertThrows(TimeoutException.class, () -> stopping.get(100, MILLISECONDS));

        exporter.shutdownResult.succeed();

        assertTrue(stopping.get(5, SECONDS));
    }

    @Test
    void shutdownExceptionStillReleasesTheBatchWorker() {
        exporter.shutdownException = new IllegalStateException("shutdown failed");
        output = newOutput(true);
        output.output(List.of(event("before shutdown")));

        output.stop();

        assertEquals(List.of("before shutdown"), List.copyOf(exporter.bodies));
        assertEquals(1, exporter.shutdownCalls.get());
    }

    @Test
    void stopWaitsForQueuedEventsToBeExported() throws Exception {
        exporter.exportResult = new CompletableResultCode();
        output = newOutput(true);
        output.output(List.of(event("first"), event("second"), event("third")));
        Future<?> stopping = executor.submit(output::stop);
        assertTrue(exporter.exportStarted.await(5, SECONDS));
        assertThrows(TimeoutException.class, () -> stopping.get(100, MILLISECONDS));
        assertEquals(0, exporter.shutdownCalls.get());

        exporter.exportResult.succeed();
        stopping.get(5, SECONDS);

        assertEquals(List.of("first", "second", "third"), List.copyOf(exporter.bodies));
        assertEquals(1, exporter.shutdownCalls.get());
    }

    @Test
    void repeatedOutputsLeaveNoWorkersOrJulHandlers() throws Exception {
        Logger logger = Logger.getLogger("io.opentelemetry");
        Handler[] originalHandlers = logger.getHandlers();
        for (int cycle = 0; cycle < 3; cycle++) {
            output = newOutput(true);
            assertEquals(cycle + 1, workers.size());
            output.output(List.of(event("cycle " + cycle)));
            output.stop();

            for (Thread worker : workers) {
                worker.join(5000);
                assertFalse(worker.isAlive(), "SDK worker remains after shutdown");
            }
            assertArrayEquals(originalHandlers, logger.getHandlers());
        }
        assertEquals(3, exporter.shutdownCalls.get());
        assertEquals(List.of("cycle 0", "cycle 1", "cycle 2"), List.copyOf(exporter.bodies));
    }

    private Otlp newOutput(boolean batchEnabled) {
        Set<Thread> previous = batchWorkers();
        Otlp plugin = new Otlp("lifecycle-test", new ConfigurationImpl(Map.of(
                Otlp.ENDPOINT_CONFIG.name(), "http://127.0.0.1:4318/v1/logs",
                Otlp.PROTOCOL_CONFIG.name(), "http")), null, exporter, batchEnabled);
        Set<Thread> created = batchWorkers();
        created.removeAll(previous);
        workers.addAll(created);
        return plugin;
    }

    private static Set<Thread> batchWorkers() {
        Set<Thread> result = new HashSet<>();
        for (Thread thread : Thread.getAllStackTraces().keySet()) {
            if (thread.getName().startsWith("BatchLogRecordProcessor_WorkerThread")) result.add(thread);
        }
        return result;
    }

    private static Event event(String body) {
        Event event = new org.logstash.Event();
        event.setField("message", body);
        return event;
    }

    private static final class StubExporter implements LogRecordExporter {
        private final AtomicInteger shutdownCalls = new AtomicInteger();
        private final ConcurrentLinkedQueue<String> bodies = new ConcurrentLinkedQueue<>();
        private final CountDownLatch exportStarted = new CountDownLatch(1);
        private final CountDownLatch shutdownStarted = new CountDownLatch(1);
        private CompletableResultCode exportResult = CompletableResultCode.ofSuccess();
        private CompletableResultCode shutdownResult = CompletableResultCode.ofSuccess();
        private RuntimeException shutdownException;

        @Override
        public CompletableResultCode export(Collection<LogRecordData> logs) {
            logs.forEach(log -> bodies.add(String.valueOf(log.getBodyValue().getValue())));
            exportStarted.countDown();
            return exportResult;
        }

        @Override
        public CompletableResultCode flush() {
            return CompletableResultCode.ofSuccess();
        }

        @Override
        public CompletableResultCode shutdown() {
            shutdownCalls.incrementAndGet();
            shutdownStarted.countDown();
            if (shutdownException != null) throw shutdownException;
            return shutdownResult;
        }
    }
}
