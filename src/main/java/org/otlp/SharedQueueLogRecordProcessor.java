package org.otlp;

import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.metrics.LongCounter;
import io.opentelemetry.api.metrics.DoubleCounter;
import io.opentelemetry.api.metrics.MeterProvider;
import io.opentelemetry.api.metrics.ObservableLongUpDownCounter;
import io.opentelemetry.api.metrics.ObservableLongGauge;
import io.opentelemetry.context.Context;
import io.opentelemetry.sdk.common.CompletableResultCode;
import io.opentelemetry.sdk.logs.LogRecordProcessor;
import io.opentelemetry.sdk.logs.ReadWriteLogRecord;
import io.opentelemetry.sdk.logs.data.LogRecordData;
import io.opentelemetry.sdk.logs.export.LogRecordExporter;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

final class SharedQueueLogRecordProcessor implements LogRecordProcessor {
    private static final AttributeKey<String> ERROR_TYPE = AttributeKey.stringKey("error.type");
    private final ReentrantLock lock = new ReentrantLock();
    private final Condition changed = lock.newCondition();
    private final Condition spaceAvailable = lock.newCondition();
    private final ArrayDeque<QueuedLog> queue = new ArrayDeque<>();
    private final List<Worker> workers = new ArrayList<>();
    private final CompletableResultCode shutdownResult = new CompletableResultCode();
    private final AtomicReference<Throwable> shutdownFailure = new AtomicReference<>();
    private final AtomicInteger remainingWorkers;
    private final int capacity;
    private final int maxBatchSize;
    private final long scheduleDelayNanos;
    private final boolean blockOnOverflow;
    private final Attributes attributes;
    private final Attributes droppedAttributes;
    private final LongCounter processed;
    private final DoubleCounter blockedDuration;
    private ObservableLongUpDownCounter queueSizeMetric;
    private ObservableLongUpDownCounter queueCapacityMetric;
    private ObservableLongUpDownCounter blockedProducersMetric;
    private ObservableLongGauge queuePeakMetric;
    private int blockedProducers;
    private int queuePeakSize;
    private long accepted;
    private boolean stopping;
    private boolean startupFailed;
    private FlushRequest activeFlush;
    private FlushRequest nextFlush;
    private boolean flushingExporters;
    private boolean finishingShutdown;

    SharedQueueLogRecordProcessor(String outputId, List<LogRecordExporter> exporters, int queueSize,
                                 int maxBatchSize, long scheduleDelayMillis, MeterProvider meterProvider) {
        this(outputId, exporters, queueSize, maxBatchSize, scheduleDelayMillis, false, meterProvider, Thread::new);
    }

    SharedQueueLogRecordProcessor(String outputId, List<LogRecordExporter> exporters, int queueSize,
                                 int maxBatchSize, long scheduleDelayMillis, MeterProvider meterProvider,
                                 ThreadFactory threadFactory) {
        this(outputId, exporters, queueSize, maxBatchSize, scheduleDelayMillis, false, meterProvider, threadFactory);
    }

    SharedQueueLogRecordProcessor(String outputId, List<LogRecordExporter> exporters, int queueSize,
                                 int maxBatchSize, long scheduleDelayMillis, boolean blockOnOverflow,
                                 MeterProvider meterProvider) {
        this(outputId, exporters, queueSize, maxBatchSize, scheduleDelayMillis, blockOnOverflow, meterProvider, Thread::new);
    }

    SharedQueueLogRecordProcessor(String outputId, List<LogRecordExporter> exporters, int queueSize,
                                 int maxBatchSize, long scheduleDelayMillis, boolean blockOnOverflow,
                                 MeterProvider meterProvider, ThreadFactory threadFactory) {
        List<LogRecordExporter> ownedExporters = new ArrayList<>(Objects.requireNonNull(exporters));
        remainingWorkers = new AtomicInteger(ownedExporters.size());
        capacity = queueSize;
        this.maxBatchSize = maxBatchSize;
        this.blockOnOverflow = blockOnOverflow;
        scheduleDelayNanos = TimeUnit.MILLISECONDS.toNanos(scheduleDelayMillis);
        attributes = Attributes.builder()
                .put("otel.component.type", "shared_queue_log_processor")
                .put("otel.component.name", "shared_queue_log_processor/" + outputId).build();
        droppedAttributes = attributes.toBuilder().put(ERROR_TYPE, "queue_full").build();
        LongCounter counter;
        DoubleCounter durationCounter;
        try {
            if (ownedExporters.isEmpty()) throw new IllegalArgumentException("num_consumers must be positive");
            if (queueSize <= 0) throw new IllegalArgumentException("queue_size must be positive");
            if (maxBatchSize <= 0 || maxBatchSize > queueSize) {
                throw new IllegalArgumentException("max_batch_size must be positive and not exceed queue_size");
            }
            if (scheduleDelayMillis <= 0 || scheduleDelayMillis > Long.MAX_VALUE / 1_000_000) {
                throw new IllegalArgumentException("schedule_delay_millis is outside the supported range");
            }
            var meter = Objects.requireNonNull(meterProvider).get("org.otlp.shared_queue");
            counter = meter.counterBuilder("otel.sdk.processor.log.processed")
                    .setUnit("{log_record}").build();
            durationCounter = meter.counterBuilder("otlp.processor.log.queue.blocked.duration")
                    .ofDoubles().setUnit("s").build();
            durationCounter.add(0, attributes);
            queueSizeMetric = meter.upDownCounterBuilder("otel.sdk.processor.log.queue.size")
                    .setUnit("{log_record}").buildWithCallback(value -> value.record(queueSize(), attributes));
            queueCapacityMetric = meter.upDownCounterBuilder("otel.sdk.processor.log.queue.capacity")
                    .setUnit("{log_record}").buildWithCallback(value -> value.record(capacity, attributes));
            queuePeakMetric = meter.gaugeBuilder("otlp.processor.log.queue.peak.size").ofLongs()
                    .setUnit("{log_record}").buildWithCallback(value -> value.record(queuePeakSize(), attributes));
            blockedProducersMetric = meter.upDownCounterBuilder("otlp.processor.log.queue.blocked.producers")
                    .setUnit("{thread}").buildWithCallback(value -> value.record(blockedProducers(), attributes));
            for (int index = 0; index < ownedExporters.size(); index++) {
                Worker worker = new Worker(Objects.requireNonNull(ownedExporters.get(index)));
                worker.thread = Objects.requireNonNull(threadFactory.newThread(worker));
                worker.thread.setName("otlp-export-worker-" + outputId + "-" + index);
                worker.thread.setDaemon(true);
                workers.add(worker);
            }
        } catch (RuntimeException | Error failure) {
            try {
                closeMetrics();
            } catch (RuntimeException | Error cleanupFailure) {
                failure.addSuppressed(cleanupFailure);
            } finally {
                shutdownUnstarted(ownedExporters);
            }
            throw failure;
        }
        processed = counter;
        blockedDuration = durationCounter;
        int started = 0;
        try {
            for (Worker worker : workers) {
                worker.thread.start();
                started++;
            }
        } catch (RuntimeException | Error failure) {
            lock.lock();
            try {
                startupFailed = true;
                stopping = true;
                changed.signalAll();
                spaceAvailable.signalAll();
            } finally {
                lock.unlock();
            }
            shutdownUnstarted(ownedExporters.subList(started, ownedExporters.size()));
            for (int index = started; index < workers.size(); index++) workerFinished();
            boolean interrupted = false;
            for (int index = 0; index < started; index++) {
                while (workers.get(index).thread.isAlive()) {
                    try {
                        workers.get(index).thread.join();
                    } catch (InterruptedException ignored) {
                        interrupted = true;
                    }
                }
            }
            if (interrupted) Thread.currentThread().interrupt();
            throw failure;
        }
    }

    @Override
    public void onEmit(Context context, ReadWriteLogRecord logRecord) {
        if (logRecord == null) return;
        String error = null;
        boolean waited = false;
        long started = 0;
        lock.lock();
        try {
            if (stopping) return;
            while (queue.size() == capacity && !stopping) {
                if (!blockOnOverflow) {
                    error = "queue_full";
                    break;
                }
                if (!waited) {
                    waited = true;
                    started = System.nanoTime();
                    blockedProducers++;
                }
                try {
                    spaceAvailable.await();
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    error = "interrupted";
                    break;
                }
            }
            if (error == null && stopping) error = "shutdown";
            if (error == null) {
                queue.addLast(new QueuedLog(++accepted, logRecord.toLogRecordData()));
                queuePeakSize = Math.max(queuePeakSize, queue.size());
                changed.signal();
            } else {
                processed.add(1, "queue_full".equals(error) ? droppedAttributes
                        : attributes.toBuilder().put(ERROR_TYPE, error).build());
            }
        } finally {
            if (waited) {
                blockedProducers--;
                blockedDuration.add((System.nanoTime() - started) / 1_000_000_000.0, attributes);
            }
            lock.unlock();
        }
        if (waited) finishShutdownWhenReady();
    }

    @Override
    public CompletableResultCode forceFlush() {
        FlushRequest request;
        FlushRequest ready;
        lock.lock();
        try {
            if (stopping) return shutdownResult;
            if (activeFlush == null) {
                request = new FlushRequest(accepted);
                activeFlush = request;
            } else if (accepted <= activeFlush.target) {
                return activeFlush.result;
            } else {
                if (nextFlush == null) nextFlush = new FlushRequest(accepted);
                else nextFlush.target = accepted;
                request = nextFlush;
            }
            ready = readyFlush();
            changed.signalAll();
        } finally {
            lock.unlock();
        }
        if (ready != null) finishFlush(ready);
        return request.result;
    }

    @Override
    public CompletableResultCode shutdown() {
        lock.lock();
        try {
            stopping = true;
            changed.signalAll();
            spaceAvailable.signalAll();
        } finally {
            lock.unlock();
        }
        return shutdownResult;
    }

    private int queueSize() {
        lock.lock();
        try {
            return queue.size();
        } finally {
            lock.unlock();
        }
    }

    private int blockedProducers() {
        lock.lock();
        try {
            return blockedProducers;
        } finally {
            lock.unlock();
        }
    }

    private int queuePeakSize() {
        lock.lock();
        try {
            return queuePeakSize;
        } finally {
            lock.unlock();
        }
    }

    private void signalSpace(int released) {
        for (int index = 0; index < Math.min(released, blockedProducers); index++) spaceAvailable.signal();
    }

    private boolean finishedThrough(long target) {
        if (!queue.isEmpty() && queue.getFirst().sequence <= target) return false;
        for (Worker worker : workers) {
            if (worker.firstSequence != 0 && worker.firstSequence <= target) return false;
        }
        return true;
    }

    private boolean flushRequested(long firstSequence) {
        return activeFlush != null && firstSequence <= activeFlush.target
                || nextFlush != null && firstSequence <= nextFlush.target;
    }

    private FlushRequest readyFlush() {
        if (activeFlush == null || flushingExporters || !finishedThrough(activeFlush.target)) return null;
        flushingExporters = true;
        return activeFlush;
    }

    private void finishBatch(Worker worker, boolean failed) {
        FlushRequest ready;
        lock.lock();
        try {
            if (failed) {
                if (activeFlush != null && worker.firstSequence <= activeFlush.target) activeFlush.failed = true;
                if (nextFlush != null && worker.firstSequence <= nextFlush.target) nextFlush.failed = true;
                if (stopping) shutdownFailure.compareAndSet(null, new IllegalStateException("Log export failed during shutdown"));
            }
            worker.firstSequence = 0;
            ready = readyFlush();
        } finally {
            lock.unlock();
        }
        if (ready != null) finishFlush(ready);
    }

    private void finishFlush(FlushRequest request) {
        List<CompletableResultCode> results = new ArrayList<>(workers.size());
        for (Worker worker : workers) {
            if (worker.shutdownStarted) continue;
            try {
                results.add(Objects.requireNonNull(worker.exporter.flush(), "Exporter returned no flush result"));
            } catch (RuntimeException failure) {
                results.add(CompletableResultCode.ofExceptionalFailure(failure));
            }
        }
        CompletableResultCode result = CompletableResultCode.ofAll(results);
        result.whenComplete(() -> {
            FlushRequest ready;
            boolean failed = !result.isSuccess() || request.failed;
            lock.lock();
            try {
                if (activeFlush == request) {
                    activeFlush = nextFlush;
                    nextFlush = null;
                    flushingExporters = false;
                }
                if (stopping && failed) shutdownFailure.compareAndSet(null, new IllegalStateException("Exporter flush failed during shutdown"));
                ready = readyFlush();
            } finally {
                lock.unlock();
            }
            if (ready != null) finishFlush(ready);
            finishShutdownWhenReady();
            if (failed) request.result.fail();
            else request.result.succeed();
        });
    }

    private void shutdownUnstarted(List<LogRecordExporter> exporters) {
        List<CompletableResultCode> results = new ArrayList<>();
        for (LogRecordExporter exporter : exporters) {
            if (exporter == null) continue;
            try {
                results.add(Objects.requireNonNull(exporter.shutdown(), "Exporter returned no shutdown result"));
            } catch (RuntimeException failure) {
                shutdownFailure.compareAndSet(null, failure);
            }
        }
        boolean interrupted = false;
        for (CompletableResultCode result : results) {
            CountDownLatch done = new CountDownLatch(1);
            result.whenComplete(done::countDown);
            while (!result.isDone()) {
                try {
                    done.await();
                } catch (InterruptedException ignored) {
                    interrupted = true;
                }
            }
            if (!result.isSuccess()) shutdownFailure.compareAndSet(null, new IllegalStateException("Exporter shutdown failed"));
        }
        if (interrupted) Thread.currentThread().interrupt();
    }

    private void closeMetrics() {
        ObservableLongUpDownCounter size = queueSizeMetric;
        ObservableLongUpDownCounter limit = queueCapacityMetric;
        ObservableLongUpDownCounter blocked = blockedProducersMetric;
        ObservableLongGauge peak = queuePeakMetric;
        queueSizeMetric = null;
        queueCapacityMetric = null;
        blockedProducersMetric = null;
        queuePeakMetric = null;
        try {
            if (size != null) size.close();
        } finally {
            try {
                if (limit != null) limit.close();
            } finally {
                try {
                    if (blocked != null) blocked.close();
                } finally {
                    if (peak != null) peak.close();
                }
            }
        }
    }

    private void workerFinished() {
        if (remainingWorkers.decrementAndGet() != 0) return;
        finishShutdownWhenReady();
    }

    private void finishShutdownWhenReady() {
        lock.lock();
        try {
            if (remainingWorkers.get() != 0 || blockedProducers != 0
                    || activeFlush != null || nextFlush != null || finishingShutdown) return;
            finishingShutdown = true;
        } finally {
            lock.unlock();
        }
        try {
            closeMetrics();
        } catch (RuntimeException failure) {
            shutdownFailure.compareAndSet(null, failure);
        }
        Throwable failure = shutdownFailure.get();
        if (failure == null) shutdownResult.succeed();
        else shutdownResult.failExceptionally(failure);
    }

    private final class Worker implements Runnable {
        private final LogRecordExporter exporter;
        private Thread thread;
        private long firstSequence;
        private boolean interrupted;
        private volatile boolean shutdownStarted;

        private Worker(LogRecordExporter exporter) {
            this.exporter = exporter;
        }

        @Override
        public void run() {
            try {
                while (true) {
                    List<LogRecordData> batch = takeBatch();
                    if (batch == null) break;
                    boolean failed = true;
                    try {
                        failed = exportBatch(batch);
                    } finally {
                        batch.clear();
                        finishBatch(this, failed);
                    }
                    batch = null;
                }
            } finally {
                try {
                    shutdownStarted = true;
                    CompletableResultCode result = Objects.requireNonNull(exporter.shutdown(), "Exporter returned no shutdown result");
                    await(result);
                    if (!result.isSuccess()) {
                        Throwable failure = result.getFailureThrowable();
                        shutdownFailure.compareAndSet(null, failure == null
                                ? new IllegalStateException("Exporter shutdown failed") : failure);
                    }
                } catch (RuntimeException failure) {
                    shutdownFailure.compareAndSet(null, failure);
                } finally {
                    workerFinished();
                    if (interrupted) Thread.currentThread().interrupt();
                }
            }
        }

        private List<LogRecordData> takeBatch() {
            lock.lock();
            try {
                while (queue.isEmpty() && !stopping) waitForChange(0);
                if (startupFailed || queue.isEmpty()) return null;
                ArrayList<LogRecordData> batch = new ArrayList<>(Math.min(maxBatchSize, queue.size()));
                QueuedLog first = queue.removeFirst();
                signalSpace(1);
                firstSequence = first.sequence;
                batch.add(first.record);
                long started = System.nanoTime();
                while (batch.size() < maxBatchSize) {
                    if (!queue.isEmpty()) {
                        int previousSize = queue.size();
                        while (!queue.isEmpty() && batch.size() < maxBatchSize) batch.add(queue.removeFirst().record);
                        signalSpace(previousSize - queue.size());
                    }
                    if (batch.size() == maxBatchSize || stopping || flushRequested(firstSequence)) break;
                    long remaining = scheduleDelayNanos - (System.nanoTime() - started);
                    if (remaining <= 0) break;
                    waitForChange(remaining);
                }
                return batch;
            } finally {
                lock.unlock();
            }
        }

        private void waitForChange(long nanos) {
            try {
                if (nanos == 0) changed.await();
                else changed.awaitNanos(nanos);
            } catch (InterruptedException ignored) {
                interrupted = true;
            }
        }

        private boolean exportBatch(List<LogRecordData> batch) {
            String error = null;
            try {
                CompletableResultCode result = Objects.requireNonNull(exporter.export(Collections.unmodifiableList(batch)),
                        "Exporter returned no export result");
                await(result);
                if (!result.isSuccess()) {
                    error = result.getFailureThrowable() == null ? "export_failed"
                            : result.getFailureThrowable().getClass().getName();
                }
            } catch (RuntimeException failure) {
                error = failure.getClass().getName();
            } finally {
                processed.add(batch.size(), error == null ? attributes : attributes.toBuilder().put(ERROR_TYPE, error).build());
            }
            return error != null;
        }

        private void await(CompletableResultCode result) {
            if (result.isDone()) return;
            CountDownLatch completed = new CountDownLatch(1);
            result.whenComplete(completed::countDown);
            while (!result.isDone()) {
                try {
                    completed.await();
                } catch (InterruptedException ignored) {
                    interrupted = true;
                }
            }
        }
    }

    private record QueuedLog(long sequence, LogRecordData record) {}
    private static final class FlushRequest {
        private long target;
        private final CompletableResultCode result = new CompletableResultCode();
        private boolean failed;

        private FlushRequest(long target) {
            this.target = target;
        }
    }
}
