package org.otlp;

import io.opentelemetry.sdk.common.CompletableResultCode;
import io.opentelemetry.sdk.logs.data.LogRecordData;
import io.opentelemetry.sdk.logs.export.LogRecordExporter;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

import java.lang.ref.Reference;
import java.lang.ref.WeakReference;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Isolated("Temporarily configures a Log4j logger to inspect real diagnostic events")
class DiagnosticLogRecordExporterTest {
    private static final URI ENDPOINT = URI.create("http://127.0.0.1:4318/v1/logs");
    private static final long INTERVAL_NANOS = TimeUnit.SECONDS.toNanos(30);

    @Test
    void synchronousSuccessCountsRecordsAndReturnsDelegateResult() {
        try (LogCapture capture = new LogCapture()) {
            CompletableResultCode success = CompletableResultCode.ofSuccess();
            AtomicReference<Collection<LogRecordData>> received = new AtomicReference<>();
            StubExporter delegate = new StubExporter(logs -> {
                received.set(logs);
                return success;
            });
            DiagnosticLogRecordExporter exporter = diagnostic(delegate, capture, new AtomicLong());
            List<LogRecordData> logs = records(3);

            assertSame(success, exporter.export(logs));
            assertSame(logs, received.get());
            assertCounts(exporter, 3, 0, 0);
            assertTrue(capture.events.isEmpty());
        }
    }

    @Test
    void asynchronousSuccessCountsOriginalBatchAfterProcessorClearsIt() {
        try (LogCapture capture = new LogCapture()) {
            CompletableResultCode pending = new CompletableResultCode();
            DiagnosticLogRecordExporter exporter = diagnostic(new StubExporter(pending), capture, new AtomicLong());
            List<LogRecordData> logs = records(4);

            assertSame(pending, exporter.export(logs));
            assertFalse(pending.isDone());
            assertCounts(exporter, 0, 0, 0);
            logs.clear();
            pending.succeed();

            assertCounts(exporter, 4, 0, 0);
            assertTrue(capture.events.isEmpty());
        }
    }

    @Test
    void asynchronousFailureCountsOriginalBatchAndPreservesThrowable() {
        try (LogCapture capture = new LogCapture()) {
            CompletableResultCode pending = new CompletableResultCode();
            RuntimeException failure = new IllegalArgumentException("invalid collector response");
            DiagnosticLogRecordExporter exporter = diagnostic(new StubExporter(pending), capture, new AtomicLong());
            List<LogRecordData> logs = records(5);

            assertSame(pending, exporter.export(logs));
            assertFalse(pending.isDone());
            assertCounts(exporter, 0, 0, 0);
            logs.clear();
            pending.failExceptionally(failure);

            assertCounts(exporter, 0, 1, 5);
            assertEquals(1, capture.events.size());
            assertEquals(Level.ERROR, capture.events.get(0).getLevel());
            assertSame(failure, capture.events.get(0).getThrown());
            assertContext(capture.events.get(0), "test-output", ENDPOINT.toString(), 5, 0);
        }
    }

    @Test
    void failureWithoutThrowableReportsUnavailableCause() {
        try (LogCapture capture = new LogCapture()) {
            DiagnosticLogRecordExporter exporter = diagnostic(
                    new StubExporter(CompletableResultCode.ofFailure()), capture, new AtomicLong());

            exporter.export(records(1));

            assertCounts(exporter, 0, 1, 1);
            assertEquals(1, capture.events.size());
            LogEvent event = capture.events.get(0);
            assertNull(event.getThrown());
            assertEquals("OTLP export failed: output_id=test-output endpoint=" + ENDPOINT
                    + " records=1 suppressed_failures=0 cause=unavailable", event.getMessage().getFormattedMessage());
        }
    }

    @Test
    void synchronousDelegateExceptionBecomesCountedFailedResult() {
        try (LogCapture capture = new LogCapture()) {
            RuntimeException failure = new IllegalStateException("synchronous transport failure");
            DiagnosticLogRecordExporter exporter = diagnostic(new StubExporter(logs -> {
                throw failure;
            }), capture, new AtomicLong());

            CompletableResultCode result = exporter.export(records(3));

            assertTrue(result.isDone());
            assertFalse(result.isSuccess());
            assertSame(failure, result.getFailureThrowable());
            assertCounts(exporter, 0, 1, 3);
            assertEquals(1, capture.events.size());
            assertSame(failure, capture.events.get(0).getThrown());
        }
    }

    @Test
    void throttlesForThirtySecondsButCountsEveryFailedBatchAndRecord() {
        try (LogCapture capture = new LogCapture()) {
            AtomicLong clock = new AtomicLong();
            DiagnosticLogRecordExporter exporter = diagnostic(
                    new StubExporter(CompletableResultCode.ofFailure()), capture, clock);

            exporter.export(records(1));
            exporter.export(records(2));
            clock.set(INTERVAL_NANOS - 1);
            exporter.export(records(3));
            assertEquals(1, capture.events.size());
            assertCounts(exporter, 0, 3, 6);

            clock.set(INTERVAL_NANOS);
            exporter.export(records(4));
            assertEquals(2, capture.events.size());
            assertContext(capture.events.get(1), "test-output", ENDPOINT.toString(), 4, 2);

            clock.set(INTERVAL_NANOS * 2);
            exporter.export(records(5));
            assertEquals(3, capture.events.size());
            assertContext(capture.events.get(2), "test-output", ENDPOINT.toString(), 5, 0);
            assertCounts(exporter, 0, 5, 15);
        }
    }

    @Test
    void outputInstancesKeepCountersAndSuppressionIndependent() {
        try (LogCapture capture = new LogCapture()) {
            AtomicLong clock = new AtomicLong();
            DiagnosticLogRecordExporter first = new DiagnosticLogRecordExporter(
                    new StubExporter(CompletableResultCode.ofFailure()), capture.logger,
                    "first-output", ENDPOINT, clock::get);
            CompletableResultCode secondFailure = new CompletableResultCode();
            DiagnosticLogRecordExporter second = new DiagnosticLogRecordExporter(
                    new StubExporter(logs -> logs.size() == 3 ? CompletableResultCode.ofSuccess() : secondFailure),
                    capture.logger, "second-output", ENDPOINT, clock::get);

            first.export(records(1));
            first.export(records(2));
            second.export(records(3));
            second.export(records(4));
            secondFailure.fail();

            assertCounts(first, 0, 2, 3);
            assertCounts(second, 3, 1, 4);
            assertEquals(2, capture.events.size());
            assertContext(capture.events.get(1), "second-output", ENDPOINT.toString(), 4, 0);

            clock.set(INTERVAL_NANOS);
            first.export(records(5));
            assertContext(capture.events.get(2), "first-output", ENDPOINT.toString(), 5, 1);
            assertCounts(first, 0, 3, 8);
            assertCounts(second, 3, 1, 4);
        }
    }

    @Test
    void pendingCompletionDoesNotRetainSubmittedCollectionOrRecord() throws InterruptedException {
        try (LogCapture capture = new LogCapture()) {
            CompletableResultCode pending = new CompletableResultCode();
            DiagnosticLogRecordExporter exporter = diagnostic(new StubExporter(pending), capture, new AtomicLong());
            List<WeakReference<?>> payload = submitCollectiblePayload(exporter);
            try {
                for (int attempt = 0; attempt < 20 && payload.stream().anyMatch(ref -> ref.get() != null); attempt++) {
                    System.gc();
                    Thread.sleep(50);
                }
                payload.forEach(reference -> assertNull(reference.get(), "Pending callbacks must not retain the payload"));
                assertFalse(pending.isDone());
                assertCounts(exporter, 0, 0, 0);

                pending.succeed();
                assertCounts(exporter, 1, 0, 0);
            } finally {
                Reference.reachabilityFence(exporter);
                Reference.reachabilityFence(pending);
                Reference.reachabilityFence(payload);
            }
        }
    }

    @Test
    void flushAndShutdownDelegateAndPreserveTheirResults() {
        try (LogCapture capture = new LogCapture()) {
            StubExporter delegate = new StubExporter(CompletableResultCode.ofSuccess());
            DiagnosticLogRecordExporter exporter = diagnostic(delegate, capture, new AtomicLong());

            assertSame(delegate.flushResult, exporter.flush());
            assertSame(delegate.shutdownResult, exporter.shutdown());
            assertEquals(1, delegate.flushCalls);
            assertEquals(1, delegate.shutdownCalls);
            delegate.flushResult.fail();
            delegate.shutdownResult.succeed();
            assertCounts(exporter, 0, 0, 0);
            assertTrue(capture.events.isEmpty());
        }
    }

    @Test
    void synchronousFlushAndShutdownExceptionsBecomeExceptionalResults() {
        try (LogCapture capture = new LogCapture()) {
            StubExporter delegate = new StubExporter(CompletableResultCode.ofSuccess());
            delegate.flushFailure = new IllegalStateException("flush failed");
            delegate.shutdownFailure = new IllegalStateException("shutdown failed");
            DiagnosticLogRecordExporter exporter = diagnostic(delegate, capture, new AtomicLong());

            CompletableResultCode flush = exporter.flush();
            CompletableResultCode shutdown = exporter.shutdown();

            assertTrue(flush.isDone());
            assertFalse(flush.isSuccess());
            assertSame(delegate.flushFailure, flush.getFailureThrowable());
            assertTrue(shutdown.isDone());
            assertFalse(shutdown.isSuccess());
            assertSame(delegate.shutdownFailure, shutdown.getFailureThrowable());
            assertEquals(1, delegate.flushCalls);
            assertEquals(1, delegate.shutdownCalls);
            assertCounts(exporter, 0, 0, 0);
        }
    }

    private static List<WeakReference<?>> submitCollectiblePayload(DiagnosticLogRecordExporter exporter) {
        List<LogRecordData> logs = records(1);
        List<WeakReference<?>> references = List.of(
                new WeakReference<>(logs), new WeakReference<>(logs.get(0)));
        exporter.export(logs);
        return references;
    }

    private static DiagnosticLogRecordExporter diagnostic(StubExporter delegate, LogCapture capture, AtomicLong clock) {
        return new DiagnosticLogRecordExporter(delegate, capture.logger, "test-output", ENDPOINT, clock::get);
    }

    private static List<LogRecordData> records(int count) {
        List<LogRecordData> records = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            records.add((LogRecordData) Proxy.newProxyInstance(LogRecordData.class.getClassLoader(),
                    new Class<?>[]{LogRecordData.class}, (proxy, method, args) -> {
                        throw new AssertionError("Unexpected record access: " + method.getName());
                    }));
        }
        return records;
    }

    private static void assertCounts(DiagnosticLogRecordExporter exporter, long exported, long batches, long failed) {
        assertEquals(exported, exporter.getExportedRecordsCount());
        assertEquals(batches, exporter.getFailedBatchesCount());
        assertEquals(failed, exporter.getFailedRecordsCount());
    }

    private static void assertContext(LogEvent event, String outputId, String endpoint, int records, int suppressed) {
        String message = event.getMessage().getFormattedMessage();
        assertTrue(message.contains("output_id=" + outputId + " endpoint=" + endpoint
                + " records=" + records + " suppressed_failures=" + suppressed), message);
    }

    private static final class StubExporter implements LogRecordExporter {
        private final Function<Collection<LogRecordData>, CompletableResultCode> export;
        private CompletableResultCode flushResult = new CompletableResultCode();
        private CompletableResultCode shutdownResult = new CompletableResultCode();
        private RuntimeException flushFailure;
        private RuntimeException shutdownFailure;
        private int flushCalls;
        private int shutdownCalls;

        private StubExporter(CompletableResultCode result) {
            this(logs -> result);
        }

        private StubExporter(Function<Collection<LogRecordData>, CompletableResultCode> export) {
            this.export = export;
        }

        @Override
        public CompletableResultCode export(Collection<LogRecordData> logs) {
            return export.apply(logs);
        }

        @Override
        public CompletableResultCode flush() {
            flushCalls++;
            if (flushFailure != null) {
                throw flushFailure;
            }
            return flushResult;
        }

        @Override
        public CompletableResultCode shutdown() {
            shutdownCalls++;
            if (shutdownFailure != null) {
                throw shutdownFailure;
            }
            return shutdownResult;
        }
    }

    private static final class LogCapture implements AutoCloseable {
        private final org.apache.logging.log4j.core.Logger logger =
                (org.apache.logging.log4j.core.Logger) LogManager.getLogger(DiagnosticLogRecordExporterTest.class);
        private final List<LogEvent> events = new CopyOnWriteArrayList<>();
        private final Level originalLevel = logger.getLevel();
        private final boolean originalAdditive = logger.isAdditive();
        private final AbstractAppender appender = new AbstractAppender(
                "diagnostic-exporter-test", null, null, false, Property.EMPTY_ARRAY) {
            @Override
            public void append(LogEvent event) {
                events.add(event.toImmutable());
            }
        };

        private LogCapture() {
            appender.start();
            logger.addAppender(appender);
            logger.setLevel(Level.ERROR);
            logger.setAdditive(false);
        }

        @Override
        public void close() {
            logger.removeAppender(appender);
            logger.setLevel(originalLevel);
            logger.setAdditive(originalAdditive);
            appender.stop();
        }
    }
}
