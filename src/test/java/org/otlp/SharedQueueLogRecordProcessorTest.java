package org.otlp;

import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.metrics.MeterProvider;
import io.opentelemetry.sdk.common.CompletableResultCode;
import io.opentelemetry.sdk.logs.SdkLoggerProvider;
import io.opentelemetry.sdk.logs.data.LogRecordData;
import io.opentelemetry.sdk.logs.export.LogRecordExporter;
import io.opentelemetry.sdk.metrics.InstrumentType;
import io.opentelemetry.sdk.metrics.SdkMeterProvider;
import io.opentelemetry.sdk.metrics.data.AggregationTemporality;
import io.opentelemetry.sdk.metrics.data.MetricDataType;
import io.opentelemetry.sdk.metrics.export.CollectionRegistration;
import io.opentelemetry.sdk.metrics.export.MetricReader;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.parallel.Isolated;

import java.lang.management.ManagementFactory;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.jupiter.api.Assertions.*;

@Isolated
@Timeout(value = 10, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
class SharedQueueLogRecordProcessorTest {
    private final List<StubExporter> exporters = new ArrayList<>();
    private final List<Thread> threads = new CopyOnWriteArrayList<>();
    private final List<Thread> producers = new CopyOnWriteArrayList<>();
    private final Collection<Throwable> producerFailures = new ConcurrentLinkedQueue<>();
    private final List<CompletableResultCode> pending = new ArrayList<>();
    private SharedQueueLogRecordProcessor processor;
    private SdkLoggerProvider provider;

    @AfterEach
    void closeResources() throws Exception {
        pending.forEach(CompletableResultCode::succeed);
        if (processor != null) assertTrue(processor.shutdown().join(3, SECONDS).isDone());
        if (provider != null) provider.close();
        for (Thread producer : producers) {
            producer.join(3000);
            assertFalse(producer.isAlive(), "Producer survived shutdown");
        }
        assertTrue(producerFailures.isEmpty(), () -> "Producer failed: " + producerFailures);
        for (Thread thread : threads) {
            thread.join(3000);
            assertFalse(thread.isAlive(), "Consumer survived shutdown");
        }
    }

    @Test
    void concurrentProducersExportEveryRecordOnce() throws Exception {
        start(4, 4096, 16, 20, MeterProvider.noop());
        Set<String> seen = ConcurrentHashMap.newKeySet();
        AtomicInteger duplicates = new AtomicInteger();
        exporters.forEach(exporter -> exporter.onRecord = body -> {
            if (!seen.add(body)) duplicates.incrementAndGet();
        });
        var producers = Executors.newFixedThreadPool(4);
        try {
            List<java.util.concurrent.Future<?>> tasks = new ArrayList<>();
            for (int producer = 0; producer < 4; producer++) {
                int index = producer;
                tasks.add(producers.submit(() -> {
                    for (int record = 0; record < 500; record++) emit(index + ":" + record);
                }));
            }
            for (var task : tasks) task.get(3, SECONDS);
            assertTrue(processor.forceFlush().join(3, SECONDS).isSuccess());
            assertEquals(2000, seen.size());
            assertEquals(0, duplicates.get());
            for (StubExporter exporter : exporters) {
                assertTrue(exporter.batchSizes.stream().allMatch(size -> size <= 16));
                assertEquals(0, exporter.concurrentCalls.get());
            }
        } finally {
            producers.shutdownNow();
            assertTrue(producers.awaitTermination(3, SECONDS));
        }
    }

    @Test
    void consumersShareOneCapacityWhileTheirExportsArePending() throws Exception {
        Reader reader = new Reader();
        try (SdkMeterProvider metrics = SdkMeterProvider.builder().registerMetricReader(reader).build()) {
            start(2, 2, 1, 1000, metrics);
            exporters.forEach(exporter -> exporter.nextResults.add(pendingResult()));
            emit("active one");
            emit("active two");
            for (StubExporter exporter : exporters) assertNotNull(exporter.batches.poll(2, SECONDS));
            emit("queued one");
            emit("queued two");
            emit("dropped");

            assertEquals(2, reader.value("otel.sdk.processor.log.queue.size", ""));
            assertEquals(2, reader.value("otel.sdk.processor.log.queue.capacity", ""));
            assertEquals(2, reader.gaugeValue("otlp.processor.log.queue.peak.size"));
            assertEquals(1, reader.value("otel.sdk.processor.log.processed", "queue_full"));
            assertEquals(2, exporters.stream().mapToInt(exporter -> exporter.received.size()).sum());

            pending.forEach(CompletableResultCode::succeed);
            assertTrue(processor.forceFlush().join(2, SECONDS).isSuccess());
            assertEquals(4, exporters.stream().mapToInt(exporter -> exporter.received.size()).sum());
            assertEquals(0, reader.value("otel.sdk.processor.log.queue.size", ""));
            assertEquals(2, reader.gaugeValue("otlp.processor.log.queue.peak.size"));
            assertEquals(4, reader.value("otel.sdk.processor.log.processed", ""));
            assertTrue(processor.shutdown().join(2, SECONDS).isSuccess());
            assertEquals(0, reader.points("otel.sdk.processor.log.queue.size"));
            assertEquals(0, reader.points("otel.sdk.processor.log.queue.capacity"));
            assertEquals(0, reader.points("otlp.processor.log.queue.peak.size"));
            assertEquals(0, reader.points("otlp.processor.log.queue.blocked.producers"));
        }
    }

    @Test
    void queuePeakSurvivesDrainBeforeFirstCollectionAndSmallerBursts() throws Exception {
        Reader reader = new Reader();
        try (SdkMeterProvider metrics = SdkMeterProvider.builder().registerMetricReader(reader).build()) {
            start(1, 4, 1, 60000, metrics);
            CompletableResultCode first = pendingResult();
            exporters.get(0).nextResults.add(first);
            emit("in flight");
            assertEquals(List.of("in flight"), exporters.get(0).batches.poll(2, SECONDS));
            for (int index = 0; index < 4; index++) emit("queued " + index);
            emit("dropped first");
            emit("dropped second");
            first.succeed();
            assertTrue(processor.forceFlush().join(2, SECONDS).isSuccess());

            var peak = reader.registration.collectAllMetrics().stream()
                    .filter(metric -> metric.getName().equals("otlp.processor.log.queue.peak.size"))
                    .findFirst().orElseThrow();
            assertEquals(MetricDataType.LONG_GAUGE, peak.getType());
            assertEquals("{log_record}", peak.getUnit());
            var point = peak.getLongGaugeData().getPoints().iterator().next();
            assertEquals(4, point.getValue());
            assertEquals("shared_queue_log_processor",
                    point.getAttributes().get(AttributeKey.stringKey("otel.component.type")));
            assertEquals("shared_queue_log_processor/unit-test",
                    point.getAttributes().get(AttributeKey.stringKey("otel.component.name")));
            assertEquals(0, reader.value("otel.sdk.processor.log.queue.size", ""));
            assertEquals(2, reader.value("otel.sdk.processor.log.processed", "queue_full"));
            assertEquals(5, reader.value("otel.sdk.processor.log.processed", ""));

            exporters.get(0).batches.clear();
            CompletableResultCode second = pendingResult();
            exporters.get(0).nextResults.add(second);
            emit("in flight again");
            assertEquals(List.of("in flight again"), exporters.get(0).batches.poll(2, SECONDS));
            emit("smaller first");
            emit("smaller second");
            assertEquals(2, reader.value("otel.sdk.processor.log.queue.size", ""));
            assertEquals(4, reader.gaugeValue("otlp.processor.log.queue.peak.size"));
            second.succeed();
            assertTrue(processor.forceFlush().join(2, SECONDS).isSuccess());
            assertEquals(0, reader.value("otel.sdk.processor.log.queue.size", ""));
            assertEquals(4, reader.gaugeValue("otlp.processor.log.queue.peak.size"));
            assertEquals(4, reader.gaugeValue("otlp.processor.log.queue.peak.size"));
        }
    }

    @Test
    void newProcessorInstanceStartsWithZeroQueuePeak() throws Exception {
        Reader reader = new Reader();
        try (SdkMeterProvider metrics = SdkMeterProvider.builder().registerMetricReader(reader).build()) {
            start(1, 2, 1, 60000, metrics);
            CompletableResultCode first = pendingResult();
            exporters.get(0).nextResults.add(first);
            emit("in flight");
            assertEquals(List.of("in flight"), exporters.get(0).batches.poll(2, SECONDS));
            emit("queued first");
            emit("queued second");
            first.succeed();
            assertTrue(processor.forceFlush().join(2, SECONDS).isSuccess());
            assertEquals(2, reader.gaugeValue("otlp.processor.log.queue.peak.size"));
            assertTrue(processor.shutdown().join(2, SECONDS).isSuccess());
            provider.close();
            exporters.clear();

            start(1, 2, 1, 60000, metrics);

            assertEquals(1, reader.points("otlp.processor.log.queue.peak.size"));
            assertEquals(0, reader.gaugeValue("otlp.processor.log.queue.peak.size"));
        }
    }

    @Test
    void blockingProducerResumesWhenQueueSpaceIsAvailableAndRecordsItsWait() throws Exception {
        Reader reader = new Reader();
        try (SdkMeterProvider metrics = SdkMeterProvider.builder().registerMetricReader(reader).build()) {
            start(1, 1, 1, 60000, true, metrics);
            CompletableResultCode first = pendingResult();
            CompletableResultCode second = pendingResult();
            exporters.get(0).nextResults.add(first);
            exporters.get(0).nextResults.add(second);
            emit("in flight");
            assertEquals(List.of("in flight"), exporters.get(0).batches.poll(2, SECONDS));
            emit("queued");
            CountDownLatch returned = new CountDownLatch(1);
            startProducer(() -> {
                emit("blocked");
                returned.countDown();
            });

            awaitBlocked(reader, 1);
            assertFalse(returned.await(100, MILLISECONDS));
            assertEquals(1, reader.value("otel.sdk.processor.log.queue.size", ""));
            assertEquals(0, reader.value("otel.sdk.processor.log.processed", "queue_full"));
            assertEquals("{thread}", reader.unit("otlp.processor.log.queue.blocked.producers"));
            first.succeed();

            assertTrue(returned.await(2, SECONDS));
            assertEquals(List.of("queued"), exporters.get(0).batches.poll(2, SECONDS));
            assertFalse(second.isDone());
            assertEquals(0, reader.value("otlp.processor.log.queue.blocked.producers", ""));
            assertTrue(reader.doubleValue("otlp.processor.log.queue.blocked.duration") > 0);
            assertEquals("s", reader.unit("otlp.processor.log.queue.blocked.duration"));
            second.succeed();
            assertTrue(processor.forceFlush().join(2, SECONDS).isSuccess());
            assertEquals(List.of("in flight", "queued", "blocked"), List.copyOf(exporters.get(0).received));
            assertEquals(3, reader.value("otel.sdk.processor.log.processed", ""));
            assertEquals(0, reader.value("otel.sdk.processor.log.processed", "queue_full"));
            assertTrue(processor.shutdown().join(2, SECONDS).isSuccess());
            assertEquals(0, reader.points("otlp.processor.log.queue.blocked.producers"));
        }
    }

    @Test
    void blockedProducerFillsTheNextBatchWithoutWaitingForItsFormationDelay() throws Exception {
        Reader reader = new Reader();
        try (SdkMeterProvider metrics = SdkMeterProvider.builder().registerMetricReader(reader).build()) {
            start(1, 2, 2, 60000, true, metrics);
            CompletableResultCode first = pendingResult();
            exporters.get(0).nextResults.add(first);
            emit("active first");
            emit("active second");
            assertEquals(List.of("active first", "active second"), exporters.get(0).batches.poll(2, SECONDS));
            emit("queued first");
            emit("queued second");
            CountDownLatch returned = new CountDownLatch(1);
            startProducer(() -> {
                emit("next first");
                emit("next second");
                returned.countDown();
            });
            awaitBlocked(reader, 1);

            first.succeed();

            assertTrue(returned.await(2, SECONDS));
            assertEquals(List.of("queued first", "queued second"), exporters.get(0).batches.poll(2, SECONDS));
            assertEquals(List.of("next first", "next second"), exporters.get(0).batches.poll(2, SECONDS));
            assertTrue(processor.forceFlush().join(2, SECONDS).isSuccess());
            assertEquals(6, reader.value("otel.sdk.processor.log.processed", ""));
            assertEquals(0, reader.value("otel.sdk.processor.log.processed", "queue_full"));
        }
    }

    @Test
    void concurrentBlockingProducersShareTinyQueueAcrossConsumersWithoutLoss() throws Exception {
        Reader reader = new Reader();
        try (SdkMeterProvider metrics = SdkMeterProvider.builder().registerMetricReader(reader).build()) {
            start(3, 1, 1, 60000, true, metrics);
            Set<String> seen = ConcurrentHashMap.newKeySet();
            AtomicInteger duplicates = new AtomicInteger();
            exporters.forEach(exporter -> {
                exporter.nextResults.add(pendingResult());
                exporter.onRecord = body -> {
                    if (!seen.add(body)) duplicates.incrementAndGet();
                };
            });
            for (int index = 0; index < 3; index++) emit("active " + index);
            for (StubExporter exporter : exporters) assertNotNull(exporter.batches.poll(2, SECONDS));
            emit("queued");
            var executor = Executors.newFixedThreadPool(4);
            CountDownLatch ready = new CountDownLatch(4);
            CountDownLatch begin = new CountDownLatch(1);
            try {
                List<java.util.concurrent.Future<?>> tasks = new ArrayList<>();
                for (int producer = 0; producer < 4; producer++) {
                    int index = producer;
                    tasks.add(executor.submit(() -> {
                        ready.countDown();
                        assertTrue(begin.await(2, SECONDS));
                        for (int record = 0; record < 250; record++) emit(index + ":" + record);
                        return null;
                    }));
                }
                assertTrue(ready.await(2, SECONDS));
                begin.countDown();
                awaitBlocked(reader, 4);
                assertTrue(tasks.stream().noneMatch(java.util.concurrent.Future::isDone));
                assertEquals(1, reader.gaugeValue("otlp.processor.log.queue.peak.size"));

                pending.forEach(CompletableResultCode::succeed);

                for (var task : tasks) task.get(3, SECONDS);
                assertTrue(processor.forceFlush().join(3, SECONDS).isSuccess());
                assertEquals(1004, seen.size());
                assertEquals(0, duplicates.get());
                assertEquals(1004, reader.value("otel.sdk.processor.log.processed", ""));
                assertEquals(0, reader.value("otel.sdk.processor.log.processed", "queue_full"));
                assertEquals(0, reader.value("otlp.processor.log.queue.blocked.producers", ""));
                assertEquals(1, reader.gaugeValue("otlp.processor.log.queue.peak.size"));
                assertTrue(reader.gaugeValue("otlp.processor.log.queue.peak.size")
                        <= reader.value("otel.sdk.processor.log.queue.capacity", ""));
                for (StubExporter exporter : exporters) assertEquals(0, exporter.concurrentCalls.get());
            } finally {
                begin.countDown();
                executor.shutdownNow();
                assertTrue(executor.awaitTermination(3, SECONDS));
            }
        }
    }

    @Test
    void interruptedProducerKeepsItsInterruptFlagAndDoesNotEnqueue() throws Exception {
        Reader reader = new Reader();
        try (SdkMeterProvider metrics = SdkMeterProvider.builder().registerMetricReader(reader).build()) {
            start(1, 1, 1, 60000, true, metrics);
            CompletableResultCode first = pendingResult();
            exporters.get(0).nextResults.add(first);
            emit("in flight");
            assertNotNull(exporters.get(0).batches.poll(2, SECONDS));
            emit("queued");
            AtomicBoolean interrupted = new AtomicBoolean();
            CountDownLatch returned = new CountDownLatch(1);
            Thread producer = startProducer(() -> {
                emit("cancelled");
                interrupted.set(Thread.currentThread().isInterrupted());
                returned.countDown();
            });
            awaitBlocked(reader, 1);

            producer.interrupt();

            assertTrue(returned.await(2, SECONDS));
            assertTrue(interrupted.get());
            assertEquals(0, reader.value("otlp.processor.log.queue.blocked.producers", ""));
            assertTrue(reader.doubleValue("otlp.processor.log.queue.blocked.duration") > 0);
            assertEquals(1, reader.value("otel.sdk.processor.log.processed", "interrupted"));
            assertEquals(0, reader.value("otel.sdk.processor.log.processed", "queue_full"));
            first.succeed();
            assertTrue(processor.forceFlush().join(2, SECONDS).isSuccess());
            assertEquals(List.of("in flight", "queued"), List.copyOf(exporters.get(0).received));
        }
    }

    @Test
    void shutdownReleasesAllBlockedProducersWhileAcceptedExportsArePending() throws Exception {
        Reader reader = new Reader();
        try (SdkMeterProvider metrics = SdkMeterProvider.builder().registerMetricReader(reader).build()) {
            start(1, 1, 1, 60000, true, metrics);
            CompletableResultCode first = pendingResult();
            exporters.get(0).nextResults.add(first);
            emit("in flight");
            assertNotNull(exporters.get(0).batches.poll(2, SECONDS));
            emit("queued");
            CountDownLatch returned = new CountDownLatch(3);
            for (int index = 0; index < 3; index++) {
                startProducer(() -> {
                    emit("cancelled");
                    returned.countDown();
                });
            }
            awaitBlocked(reader, 3);

            CompletableResultCode stopping = processor.shutdown();

            assertTrue(returned.await(2, SECONDS));
            assertFalse(stopping.isDone());
            assertEquals(0, reader.value("otlp.processor.log.queue.blocked.producers", ""));
            assertTrue(reader.doubleValue("otlp.processor.log.queue.blocked.duration") > 0);
            assertEquals(3, reader.value("otel.sdk.processor.log.processed", "shutdown"));
            assertEquals(0, reader.value("otel.sdk.processor.log.processed", "queue_full"));
            first.succeed();
            assertTrue(stopping.join(2, SECONDS).isSuccess());
            assertEquals(List.of("in flight", "queued"), List.copyOf(exporters.get(0).received));
            assertEquals(1, exporters.get(0).shutdownCalls.get());
            assertEquals(0, reader.points("otel.sdk.processor.log.queue.size"));
            assertEquals(0, reader.points("otel.sdk.processor.log.queue.capacity"));
            assertEquals(0, reader.points("otlp.processor.log.queue.peak.size"));
            assertEquals(0, reader.points("otlp.processor.log.queue.blocked.producers"));
        }
    }

    @Test
    void fullBatchDoesNotWaitForTheDelay() throws Exception {
        start(1, 4, 2, 60000, MeterProvider.noop());
        emit("first");
        assertNull(exporters.get(0).batches.poll(100, MILLISECONDS));
        emit("second");
        assertEquals(List.of("first", "second"), exporters.get(0).batches.poll(2, SECONDS));
    }

    @Test
    void partialBatchExportsWhenItsDelayExpires() throws Exception {
        start(1, 4, 4, 40, MeterProvider.noop());
        emit("partial");
        assertEquals(List.of("partial"), exporters.get(0).batches.poll(1, SECONDS));
    }

    @Test
    void forceFlushDoesNotWaitForLaterRecords() throws Exception {
        start(1, 4, 1, 60000, MeterProvider.noop());
        CompletableResultCode first = pendingResult();
        CompletableResultCode later = pendingResult();
        exporters.get(0).nextResults.add(first);
        exporters.get(0).nextResults.add(later);
        emit("before flush");
        assertNotNull(exporters.get(0).batches.poll(2, SECONDS));

        CompletableResultCode flushing = processor.forceFlush();
        emit("after flush");
        assertFalse(flushing.isDone());
        assertNull(exporters.get(0).batches.poll(100, MILLISECONDS));
        first.succeed();

        assertTrue(flushing.join(2, SECONDS).isSuccess());
        assertEquals(List.of("after flush"), exporters.get(0).batches.poll(2, SECONDS));
        assertFalse(later.isDone());
    }

    @Test
    void forceFlushReportsPendingExportFailureAndCanRecover() throws Exception {
        start(1, 4, 1, 1000, MeterProvider.noop());
        CompletableResultCode failed = pendingResult();
        exporters.get(0).nextResults.add(failed);
        emit("failed");
        assertNotNull(exporters.get(0).batches.poll(2, SECONDS));
        CompletableResultCode flushing = processor.forceFlush();
        failed.fail();
        assertFalse(flushing.join(2, SECONDS).isSuccess());
        emit("recovered");
        assertTrue(processor.forceFlush().join(2, SECONDS).isSuccess());
    }

    @Test
    void repeatedFlushesCoalesceWhileAConsumerIsSlow() throws Exception {
        start(2, 1024, 1, 1000, MeterProvider.noop());
        CompletableResultCode slow = pendingResult();
        CompletableResultCode fast = pendingResult();
        exporters.get(0).nextResults.add(slow);
        exporters.get(1).nextResults.add(fast);
        emit("slow");
        emit("fast");
        for (StubExporter exporter : exporters) assertNotNull(exporter.batches.poll(2, SECONDS));
        CompletableResultCode firstFlush = processor.forceFlush();
        fast.succeed();
        emit("later first");
        CompletableResultCode nextFlush = processor.forceFlush();
        assertNotSame(firstFlush, nextFlush);
        for (int index = 0; index < 300; index++) {
            emit("later " + index);
            assertSame(nextFlush, processor.forceFlush());
        }
        assertFalse(firstFlush.isDone());
        slow.succeed();
        assertTrue(firstFlush.join(2, SECONDS).isSuccess());
        assertTrue(nextFlush.join(2, SECONDS).isSuccess());
        assertEquals(303, exporters.stream().mapToInt(exporter -> exporter.received.size()).sum());
    }

    @Test
    void forceFlushSendsPartialBatchImmediately() throws Exception {
        start(2, 8, 4, 60000, MeterProvider.noop());
        emit("one");
        assertTrue(processor.forceFlush().join(2, SECONDS).isSuccess());
        assertEquals(1, exporters.stream().mapToInt(exporter -> exporter.received.size()).sum());
    }

    @Test
    void shutdownWaitsForEveryConsumerAndClosesEachExporterOnce() throws Exception {
        start(2, 4, 1, 1000, MeterProvider.noop());
        CompletableResultCode first = pendingResult();
        CompletableResultCode second = pendingResult();
        exporters.get(0).nextResults.add(first);
        exporters.get(1).nextResults.add(second);
        CompletableResultCode lastShutdown = pendingResult();
        exporters.get(1).shutdownResult = lastShutdown;
        exporters.get(0).shutdownException = new IllegalStateException("close failed");
        emit("first");
        emit("second");
        for (StubExporter exporter : exporters) assertNotNull(exporter.batches.poll(2, SECONDS));

        CompletableResultCode stopping = processor.shutdown();
        assertSame(stopping, processor.shutdown());
        emit("after stop");
        assertFalse(stopping.isDone());
        first.succeed();
        second.succeed();
        assertFalse(stopping.join(100, MILLISECONDS).isDone());
        lastShutdown.succeed();

        assertTrue(stopping.join(2, SECONDS).isDone());
        assertFalse(stopping.isSuccess());
        assertEquals(2, exporters.stream().mapToInt(exporter -> exporter.received.size()).sum());
        for (StubExporter exporter : exporters) assertEquals(1, exporter.shutdownCalls.get());
    }

    @Test
    void shutdownWaitsForAnEarlierAsynchronousFlush() throws Exception {
        start(2, 4, 1, 1000, MeterProvider.noop());
        CompletableResultCode exportFlush = pendingResult();
        exporters.get(0).flushResult = exportFlush;
        CompletableResultCode flushing = processor.forceFlush();
        CompletableResultCode stopping = processor.shutdown();
        for (Thread thread : threads) thread.join(1000);
        assertTrue(threads.stream().noneMatch(Thread::isAlive));
        assertFalse(flushing.isDone());
        assertFalse(stopping.isDone());

        exportFlush.succeed();

        assertTrue(flushing.join(2, SECONDS).isSuccess());
        assertTrue(stopping.join(2, SECONDS).isSuccess());
        for (StubExporter exporter : exporters) assertEquals(1, exporter.shutdownCalls.get());
    }

    @Test
    void pendingFlushFailureAlsoFailsShutdown() throws Exception {
        start(1, 4, 1, 1000, MeterProvider.noop());
        CompletableResultCode exportFlush = pendingResult();
        exporters.get(0).flushResult = exportFlush;
        CompletableResultCode flushing = processor.forceFlush();
        CompletableResultCode stopping = processor.shutdown();
        threads.get(0).join(1000);
        assertFalse(stopping.isDone());

        exportFlush.fail();

        assertTrue(flushing.join(2, SECONDS).isDone());
        assertFalse(flushing.isSuccess());
        assertTrue(stopping.join(2, SECONDS).isDone());
        assertFalse(stopping.isSuccess());
    }

    @Test
    void idleConsumersBlockAndReleaseCompletedBatchReferences() throws Exception {
        start(2, 4, 1, 1000, MeterProvider.noop());
        emit("released after export");
        assertTrue(processor.forceFlush().join(2, SECONDS).isSuccess());
        long deadline = System.nanoTime() + SECONDS.toNanos(2);
        while (threads.stream().anyMatch(thread -> thread.getState() != Thread.State.WAITING)
                && System.nanoTime() < deadline) Thread.sleep(5);
        for (Thread thread : threads) assertEquals(Thread.State.WAITING, thread.getState());
        for (StubExporter exporter : exporters) {
            if (exporter.lastBatch != null) assertTrue(exporter.lastBatch.isEmpty());
        }
        var threadBean = ManagementFactory.getThreadMXBean();
        if (threadBean.isThreadCpuTimeSupported() && threadBean.isThreadCpuTimeEnabled()) {
            long before = threads.stream().mapToLong(thread -> threadBean.getThreadCpuTime(thread.getId())).sum();
            Thread.sleep(150);
            long after = threads.stream().mapToLong(thread -> threadBean.getThreadCpuTime(thread.getId())).sum();
            assertTrue(after - before < MILLISECONDS.toNanos(30), "Idle consumers consumed CPU");
        }
    }

    @Test
    void incompleteExportRetainsItsBatchUntilItActuallyCompletes() throws Exception {
        start(1, 4, 1, 10, MeterProvider.noop());
        CompletableResultCode result = pendingResult();
        exporters.get(0).nextResults.add(result);
        emit("pending");
        assertNotNull(exporters.get(0).batches.poll(2, SECONDS));
        emit("next");
        assertFalse(processor.forceFlush().join(100, MILLISECONDS).isDone());
        assertEquals(1, exporters.get(0).lastBatch.size());
        assertNull(exporters.get(0).batches.poll(100, MILLISECONDS));
        result.succeed();
        assertTrue(processor.forceFlush().join(2, SECONDS).isSuccess());
        assertEquals(List.of("pending", "next"), List.copyOf(exporters.get(0).received));
    }

    @Test
    void invalidConfigurationClosesTransferredExporters() {
        StubExporter first = new StubExporter();
        StubExporter second = new StubExporter();
        assertThrows(IllegalArgumentException.class, () -> new SharedQueueLogRecordProcessor("invalid",
                List.of(first, second), 2, 3, 10, MeterProvider.noop()));
        assertEquals(1, first.shutdownCalls.get());
        assertEquals(1, second.shutdownCalls.get());
    }

    @Test
    void initializationFailureUnregistersAlreadyCreatedQueueMetrics() {
        Reader reader = new Reader();
        try (SdkMeterProvider metrics = SdkMeterProvider.builder().registerMetricReader(reader).build()) {
            StubExporter exporter = new StubExporter();
            assertThrows(IllegalStateException.class, () -> new SharedQueueLogRecordProcessor("failed-init",
                    List.of(exporter), 4, 1, 10, metrics, action -> {
                        throw new IllegalStateException("Cannot create worker");
                    }));
            assertEquals(1, exporter.shutdownCalls.get());
            assertEquals(0, reader.points("otel.sdk.processor.log.queue.size"));
            assertEquals(0, reader.points("otel.sdk.processor.log.queue.capacity"));
            assertEquals(0, reader.points("otlp.processor.log.queue.peak.size"));
            assertEquals(0, reader.points("otlp.processor.log.queue.blocked.producers"));
        }
    }

    @Test
    void partialThreadStartupFailureClosesAllResources() {
        StubExporter first = new StubExporter();
        StubExporter second = new StubExporter();
        AtomicInteger created = new AtomicInteger();
        ThreadFactory factory = action -> {
            Thread thread = created.getAndIncrement() == 0 ? new Thread(action) : new Thread(action) {
                @Override
                public synchronized void start() { throw new IllegalStateException("start failed"); }
            };
            threads.add(thread);
            return thread;
        };
        Reader reader = new Reader();
        try (SdkMeterProvider metrics = SdkMeterProvider.builder().registerMetricReader(reader).build()) {
            assertThrows(IllegalStateException.class, () -> new SharedQueueLogRecordProcessor("startup",
                    List.of(first, second), 4, 1, 10, metrics, factory));
            assertEquals(1, first.shutdownCalls.get());
            assertEquals(1, second.shutdownCalls.get());
            assertTrue(threads.stream().noneMatch(Thread::isAlive));
            assertEquals(0, reader.points("otlp.processor.log.queue.peak.size"));
        }
    }

    private void start(int consumers, int capacity, int batchSize, long delayMillis, MeterProvider metrics) {
        for (int index = 0; index < consumers; index++) exporters.add(new StubExporter());
        processor = new SharedQueueLogRecordProcessor("unit-test", new ArrayList<>(exporters), capacity,
                batchSize, delayMillis, metrics, action -> {
                    Thread thread = new Thread(action);
                    threads.add(thread);
                    return thread;
                });
        provider = SdkLoggerProvider.builder().addLogRecordProcessor(processor).build();
    }

    private void start(int consumers, int capacity, int batchSize, long delayMillis,
                       boolean blockOnOverflow, MeterProvider metrics) {
        for (int index = 0; index < consumers; index++) exporters.add(new StubExporter());
        processor = new SharedQueueLogRecordProcessor("unit-test", new ArrayList<>(exporters), capacity,
                batchSize, delayMillis, blockOnOverflow, metrics, action -> {
                    Thread thread = new Thread(action);
                    threads.add(thread);
                    return thread;
                });
        provider = SdkLoggerProvider.builder().addLogRecordProcessor(processor).build();
    }

    private Thread startProducer(Runnable action) {
        Thread producer = new Thread(() -> {
            try {
                action.run();
            } catch (Throwable failure) {
                producerFailures.add(failure);
            }
        }, "test-log-producer");
        producer.setDaemon(true);
        producers.add(producer);
        producer.start();
        return producer;
    }

    private static void awaitBlocked(Reader reader, int count) throws InterruptedException {
        long deadline = System.nanoTime() + SECONDS.toNanos(2);
        while (reader.value("otlp.processor.log.queue.blocked.producers", "") != count
                && System.nanoTime() < deadline) Thread.sleep(5);
        assertEquals(count, reader.value("otlp.processor.log.queue.blocked.producers", ""));
    }

    private void emit(String body) {
        provider.get("shared-queue-test").logRecordBuilder().setBody(body).emit();
    }

    private CompletableResultCode pendingResult() {
        CompletableResultCode result = new CompletableResultCode();
        pending.add(result);
        return result;
    }

    private static final class StubExporter implements LogRecordExporter {
        private final BlockingQueue<List<String>> batches = new LinkedBlockingQueue<>();
        private final ConcurrentLinkedQueue<String> received = new ConcurrentLinkedQueue<>();
        private final ConcurrentLinkedQueue<CompletableResultCode> nextResults = new ConcurrentLinkedQueue<>();
        private final List<Integer> batchSizes = new CopyOnWriteArrayList<>();
        private final AtomicInteger active = new AtomicInteger();
        private final AtomicInteger concurrentCalls = new AtomicInteger();
        private final AtomicInteger shutdownCalls = new AtomicInteger();
        private volatile Collection<LogRecordData> lastBatch;
        private java.util.function.Consumer<String> onRecord = body -> {};
        private CompletableResultCode shutdownResult = CompletableResultCode.ofSuccess();
        private CompletableResultCode flushResult = CompletableResultCode.ofSuccess();
        private RuntimeException shutdownException;

        @Override
        public CompletableResultCode export(Collection<LogRecordData> logs) {
            if (active.incrementAndGet() > 1) concurrentCalls.incrementAndGet();
            lastBatch = logs;
            List<String> bodies = logs.stream().map(log -> String.valueOf(log.getBodyValue().getValue())).toList();
            received.addAll(bodies);
            bodies.forEach(onRecord);
            batchSizes.add(bodies.size());
            CompletableResultCode result = nextResults.poll();
            if (result == null) result = CompletableResultCode.ofSuccess();
            result.whenComplete(active::decrementAndGet);
            batches.add(bodies);
            return result;
        }

        @Override
        public CompletableResultCode flush() { return flushResult; }

        @Override
        public CompletableResultCode shutdown() {
            shutdownCalls.incrementAndGet();
            if (shutdownException != null) throw shutdownException;
            return shutdownResult;
        }
    }

    private static final class Reader implements MetricReader {
        private CollectionRegistration registration;

        @Override
        public void register(CollectionRegistration registration) { this.registration = registration; }

        @Override
        public AggregationTemporality getAggregationTemporality(InstrumentType type) { return AggregationTemporality.CUMULATIVE; }

        @Override
        public CompletableResultCode forceFlush() { return CompletableResultCode.ofSuccess(); }

        @Override
        public CompletableResultCode shutdown() { return CompletableResultCode.ofSuccess(); }

        private long value(String name, String error) {
            return registration.collectAllMetrics().stream().filter(metric -> metric.getName().equals(name))
                    .flatMap(metric -> metric.getLongSumData().getPoints().stream())
                    .filter(point -> error.equals(java.util.Objects.toString(point.getAttributes().get(AttributeKey.stringKey("error.type")), "")))
                    .mapToLong(point -> point.getValue()).sum();
        }

        private long points(String name) {
            return registration.collectAllMetrics().stream().filter(metric -> metric.getName().equals(name))
                    .mapToLong(metric -> metric.getData().getPoints().size()).sum();
        }

        private long gaugeValue(String name) {
            return registration.collectAllMetrics().stream().filter(metric -> metric.getName().equals(name))
                    .flatMap(metric -> metric.getLongGaugeData().getPoints().stream())
                    .mapToLong(point -> point.getValue()).sum();
        }

        private double doubleValue(String name) {
            return registration.collectAllMetrics().stream().filter(metric -> metric.getName().equals(name))
                    .flatMap(metric -> metric.getDoubleSumData().getPoints().stream())
                    .mapToDouble(point -> point.getValue()).sum();
        }

        private String unit(String name) {
            return registration.collectAllMetrics().stream().filter(metric -> metric.getName().equals(name))
                    .map(metric -> metric.getUnit()).findFirst().orElseThrow();
        }
    }
}
