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

import java.util.ArrayList;
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
    private final Set<Thread> metricWorkers = new HashSet<>();
    private final Set<Thread> previousWorkers = batchWorkers();
    private final Set<Thread> previousMetricWorkers = metricWorkers();
    private final ExecutorService executor = Executors.newFixedThreadPool(3, action -> {
        Thread thread = new Thread(action, "otlp-lifecycle-test");
        thread.setDaemon(true);
        return thread;
    });
    private Otlp output;

    @AfterEach
    void closeResources() throws Exception {
        trackWorkers();
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
            for (Thread worker : metricWorkers) {
                worker.join(5000);
                assertFalse(worker.isAlive(), "Queue metric worker remains after shutdown");
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
        output.output(List.of(event("before stop")));
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
        output.output(List.of(event("before stop")));
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
        output.output(List.of(event("before stop")));
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
    void concurrentStopsDrainEveryPendingBatchEvenWhenExportsFail() throws Exception {
        exporter.exportResult = new CompletableResultCode();
        output = new Otlp("failed-drain", new ConfigurationImpl(Map.of(
                "endpoint", "http://127.0.0.1:4318/v1/logs", "protocol", "http",
                "queue_size", 8L, "max_batch_size", 1L)), null, exporter, true);
        output.output(List.of(event("in flight")));
        assertTrue(exporter.exportStarted.await(3, SECONDS));
        output.output(List.of(event("queued-1"), event("queued-2"), event("queued-3")));
        trackWorkers();

        Future<?> firstStop = executor.submit(output::stop);
        Future<?> secondStop = executor.submit(output::stop);
        assertThrows(TimeoutException.class, () -> firstStop.get(100, MILLISECONDS));
        assertThrows(TimeoutException.class, () -> secondStop.get(100, MILLISECONDS));
        assertEquals(0, exporter.shutdownCalls.get());

        exporter.exportResult.fail();
        firstStop.get(3, SECONDS);
        secondStop.get(3, SECONDS);
        output.awaitStop();

        assertEquals(List.of("in flight", "queued-1", "queued-2", "queued-3"), List.copyOf(exporter.bodies));
        assertEquals(1, exporter.shutdownCalls.get());
    }

    @Test
    void allConsumersAreClosedExactlyOnce() throws Exception {
        List<StubExporter> delegates = new ArrayList<>();
        output = new Otlp("multi-lifecycle", new ConfigurationImpl(Map.of(
                "endpoint", "http://127.0.0.1:4318/v1/logs", "protocol", "http",
                "num_consumers", 3L, "max_batch_size", 1L)), null, () -> {
            StubExporter delegate = new StubExporter();
            delegates.add(delegate);
            return delegate;
        }, true);
        for (int i = 0; i < 20; i++) output.output(List.of(event("record-" + i)));
        trackWorkers();
        assertEquals(3, workers.size());
        output.stop();
        output.stop();

        assertEquals(20, delegates.stream().mapToInt(delegate -> delegate.bodies.size()).sum());
        assertEquals(20, delegates.stream().flatMap(delegate -> delegate.bodies.stream()).distinct().count());
        for (StubExporter delegate : delegates) assertEquals(1, delegate.shutdownCalls.get());
    }

    @Test
    void exporterCreationFailureClosesEarlierExportersAndMetrics() throws Exception {
        AtomicInteger created = new AtomicInteger();
        output = new Otlp(
                "construction-failure", new ConfigurationImpl(Map.of(
                        "endpoint", "http://127.0.0.1:4318/v1/logs", "protocol", "http",
                        "num_consumers", 3L)), null, () -> {
                    if (created.incrementAndGet() == 2) throw new IllegalStateException("second exporter failed");
                    return exporter;
                }, true);
        assertEquals(0, created.get());
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> output.output(List.of(event("initialization fails"))));

        assertEquals("second exporter failed", failure.getMessage());
        assertEquals(1, exporter.shutdownCalls.get());
        output.output(List.of(event("after failed initialization")));
        assertEquals(2, created.get());
        Set<Thread> createdMetrics = metricWorkers();
        createdMetrics.removeAll(previousMetricWorkers);
        for (Thread thread : createdMetrics) {
            thread.join(2000);
            assertFalse(thread.isAlive());
        }
        assertTrue(batchWorkers().stream().noneMatch(thread ->
                thread.getName().contains("construction-failure") && thread.isAlive()));
    }

    @Test
    void repeatedOutputsLeaveNoWorkersOrJulHandlers() throws Exception {
        Logger logger = Logger.getLogger("io.opentelemetry");
        Handler[] originalHandlers = logger.getHandlers();
        for (int cycle = 0; cycle < 3; cycle++) {
            output = newOutput(true);
            output.output(List.of(event("cycle " + cycle)));
            trackWorkers();
            assertEquals(cycle + 1, workers.size());
            output.stop();

            for (Thread worker : workers) {
                worker.join(5000);
                assertFalse(worker.isAlive(), "SDK worker remains after shutdown");
            }
            for (Thread worker : metricWorkers) {
                worker.join(5000);
                assertFalse(worker.isAlive(), "Queue metric worker remains after shutdown");
            }
            assertArrayEquals(originalHandlers, logger.getHandlers());
        }
        assertEquals(3, exporter.shutdownCalls.get());
        assertEquals(List.of("cycle 0", "cycle 1", "cycle 2"), List.copyOf(exporter.bodies));
    }

    @Test
    void validationInstancesAndEmptyOutputDoNotCreateResources() {
        AtomicInteger created = new AtomicInteger();
        List<Otlp> validationInstances = new ArrayList<>();
        try {
            for (int i = 0; i < 3; i++) {
                Otlp instance = new Otlp("validation-" + i, new ConfigurationImpl(Map.of(
                        "endpoint", "http://127.0.0.1:4318/v1/logs", "protocol", "http",
                        "num_consumers", 4L)), null, () -> {
                    created.incrementAndGet();
                    return new StubExporter();
                }, true);
                validationInstances.add(instance);
                assertFalse(instance.configSchema().isEmpty());
                instance.output(List.of());
            }
            assertEquals(0, created.get());
            assertEquals(previousWorkers, batchWorkers());
            assertEquals(previousMetricWorkers, metricWorkers());
        } finally {
            validationInstances.forEach(Otlp::stop);
        }
        assertEquals(0, created.get());
        assertEquals(previousWorkers, batchWorkers());
        assertEquals(previousMetricWorkers, metricWorkers());
    }

    @Test
    void stopBeforeFirstOutputDoesNotCreateExporters() throws Exception {
        AtomicInteger created = new AtomicInteger();
        output = new Otlp("unused-output", new ConfigurationImpl(Map.of(
                "endpoint", "http://127.0.0.1:4318/v1/logs", "protocol", "http")), null, () -> {
            created.incrementAndGet();
            return new StubExporter();
        }, true);

        output.stop();
        output.awaitStop();
        output.output(List.of(event("after stop")));

        assertEquals(0, created.get());
        assertEquals(previousWorkers, batchWorkers());
        assertEquals(previousMetricWorkers, metricWorkers());
    }

    @Test
    void concurrentFirstOutputsCreateOneSetOfConsumers() throws Exception {
        AtomicInteger created = new AtomicInteger();
        ConcurrentLinkedQueue<StubExporter> delegates = new ConcurrentLinkedQueue<>();
        output = new Otlp("concurrent-start", new ConfigurationImpl(Map.of(
                "endpoint", "http://127.0.0.1:4318/v1/logs", "protocol", "http",
                "num_consumers", 4L, "max_batch_size", 1L)), null, () -> {
            created.incrementAndGet();
            StubExporter delegate = new StubExporter();
            delegates.add(delegate);
            return delegate;
        }, true);
        CountDownLatch ready = new CountDownLatch(3);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<?>> producers = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            int producer = i;
            producers.add(executor.submit(() -> {
                ready.countDown();
                assertTrue(start.await(5, SECONDS));
                for (int record = 0; record < 8; record++) {
                    output.output(List.of(event(producer + "-" + record)));
                }
                return null;
            }));
        }
        try {
            assertTrue(ready.await(5, SECONDS));
        } finally {
            start.countDown();
        }
        for (Future<?> producer : producers) producer.get(5, SECONDS);
        trackWorkers();
        assertEquals(4, created.get());
        assertEquals(4, workers.size());

        output.stop();

        assertEquals(24, delegates.stream().mapToInt(delegate -> delegate.bodies.size()).sum());
        assertEquals(24, delegates.stream().flatMap(delegate -> delegate.bodies.stream()).distinct().count());
        for (StubExporter delegate : delegates) assertEquals(1, delegate.shutdownCalls.get());
    }

    @Test
    void stopDuringFirstOutputClosesCreatedExportersAndPreventsRestart() throws Exception {
        AtomicInteger created = new AtomicInteger();
        ConcurrentLinkedQueue<StubExporter> delegates = new ConcurrentLinkedQueue<>();
        CountDownLatch factoryEntered = new CountDownLatch(1);
        CountDownLatch finishFactory = new CountDownLatch(1);
        CountDownLatch stopRequested = new CountDownLatch(1);
        output = new Otlp("stop-during-start", new ConfigurationImpl(Map.of(
                "endpoint", "http://127.0.0.1:4318/v1/logs", "protocol", "http",
                "num_consumers", 3L, "max_batch_size", 1L)), null, () -> {
            if (created.incrementAndGet() == 1) {
                factoryEntered.countDown();
                try {
                    if (!finishFactory.await(5, SECONDS)) throw new IllegalStateException("factory was not released");
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException(interrupted);
                }
            }
            StubExporter delegate = new StubExporter();
            delegates.add(delegate);
            return delegate;
        }, true);
        Future<?> producing = executor.submit(() -> output.output(List.of(event("first"))));
        Future<?> stopping;
        try {
            assertTrue(factoryEntered.await(5, SECONDS));
            stopping = executor.submit(() -> {
                stopRequested.countDown();
                output.stop();
            });
            assertTrue(stopRequested.await(5, SECONDS));
        } finally {
            finishFactory.countDown();
        }
        producing.get(5, SECONDS);
        stopping.get(5, SECONDS);
        int createdBeforeStoppedOutput = created.get();
        assertEquals(3, createdBeforeStoppedOutput);
        output.output(List.of(event("after stop")));
        output.stop();

        assertEquals(createdBeforeStoppedOutput, created.get());
        assertFalse(delegates.isEmpty());
        for (StubExporter delegate : delegates) assertEquals(1, delegate.shutdownCalls.get());
        assertTrue(delegates.stream().noneMatch(delegate -> delegate.bodies.contains("after stop")));
    }

    private Otlp newOutput(boolean batchEnabled) {
        return new Otlp("lifecycle-test", new ConfigurationImpl(Map.of(
                Otlp.ENDPOINT_CONFIG.name(), "http://127.0.0.1:4318/v1/logs",
                Otlp.PROTOCOL_CONFIG.name(), "http")), null, exporter, batchEnabled);
    }

    private void trackWorkers() {
        Set<Thread> created = batchWorkers();
        created.removeAll(previousWorkers);
        workers.addAll(created);
        Set<Thread> createdMetrics = metricWorkers();
        createdMetrics.removeAll(previousMetricWorkers);
        metricWorkers.addAll(createdMetrics);
    }

    private static Set<Thread> metricWorkers() {
        Set<Thread> result = new HashSet<>();
        for (Thread thread : Thread.getAllStackTraces().keySet()) {
            if (thread.getName().startsWith("otlp-sdk-metrics-")) result.add(thread);
        }
        return result;
    }

    private static Set<Thread> batchWorkers() {
        Set<Thread> result = new HashSet<>();
        for (Thread thread : Thread.getAllStackTraces().keySet()) {
            if (thread.getName().startsWith("otlp-export-worker-")) result.add(thread);
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
