package org.otlp;

import co.elastic.logstash.api.CounterMetric;
import co.elastic.logstash.api.Metric;
import co.elastic.logstash.api.NamespacedMetric;
import co.elastic.logstash.api.TimerMetric;
import com.sun.net.httpserver.HttpServer;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.metrics.LongCounter;
import io.opentelemetry.exporter.otlp.http.logs.OtlpHttpLogRecordExporter;
import io.opentelemetry.sdk.common.CompletableResultCode;
import io.opentelemetry.sdk.common.InternalTelemetryVersion;
import io.opentelemetry.sdk.common.InstrumentationScopeInfo;
import io.opentelemetry.sdk.logs.SdkLoggerProvider;
import io.opentelemetry.sdk.logs.data.LogRecordData;
import io.opentelemetry.sdk.logs.export.LogRecordExporter;
import io.opentelemetry.sdk.metrics.SdkMeterProvider;
import io.opentelemetry.sdk.metrics.data.AggregationTemporality;
import io.opentelemetry.sdk.metrics.internal.data.ImmutableLongPointData;
import io.opentelemetry.sdk.metrics.internal.data.ImmutableMetricData;
import io.opentelemetry.sdk.metrics.internal.data.ImmutableSumData;
import io.opentelemetry.sdk.resources.Resource;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.parallel.Isolated;

import java.util.Collection;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.ArrayList;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.jupiter.api.Assertions.*;

@Isolated
@Timeout(value = 10, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
class LogstashSdkMetricsTest {
    private static final Attributes DROPPED = Attributes.of(AttributeKey.stringKey("error.type"), "queue_full");

    @Test
    void validationOnlyInstancePublishesQueueStateWithoutStartingAReader() {
        RecordingMetrics nativeMetrics = new RecordingMetrics();
        try (LogCapture capture = new LogCapture();
             LogstashSdkMetrics metrics = new LogstashSdkMetrics(capture.logger, "validation-only", 64, nativeMetrics)) {
            assertTrue(metricWorkers("validation-only").isEmpty());
            assertEquals(Set.of("sdk_metrics"), nativeMetrics.values.keySet());
            assertEquals(0, nativeMetrics.metricValue("otel.sdk.processor.log.queue.size", ""));
            assertEquals(64, nativeMetrics.metricValue("otel.sdk.processor.log.queue.capacity", ""));
            assertEquals("shared_queue_log_processor/validation-only",
                    nativeMetrics.point("otel.sdk.processor.log.queue.size", "").get("otel_component_name"));
            assertEquals("{log_record}",
                    nativeMetrics.point("otel.sdk.processor.log.queue.capacity", "").get("unit"));
        }
        assertTrue(metricWorkers("validation-only").isEmpty());
    }

    @Test
    void closingBeforeFirstUseDoesNotStartResourcesAndPreventsLaterStartup() {
        try (LogCapture capture = new LogCapture()) {
            LogstashSdkMetrics metrics = new LogstashSdkMetrics(capture.logger, "never-started", 32, new RecordingMetrics());
            metrics.close();
            metrics.close();
            assertThrows(IllegalStateException.class, metrics::meterProvider);
            assertTrue(metricWorkers("never-started").isEmpty());
        }
    }

    @Test
    void concurrentFirstUseCreatesOneProviderAndOneReader() throws Exception {
        try (LogCapture capture = new LogCapture();
             LogstashSdkMetrics metrics = new LogstashSdkMetrics(capture.logger, "lazy-start", 32, new RecordingMetrics())) {
            var callers = Executors.newFixedThreadPool(4);
            Set<Thread> readers;
            try {
                List<Future<io.opentelemetry.api.metrics.MeterProvider>> calls = new ArrayList<>();
                for (int index = 0; index < 20; index++) calls.add(callers.submit(metrics::meterProvider));
                var expected = calls.get(0).get(2, SECONDS);
                for (var call : calls) assertSame(expected, call.get(2, SECONDS));
                readers = metricWorkers("lazy-start");
                assertEquals(1, readers.size());
            } finally {
                callers.shutdownNow();
                assertTrue(callers.awaitTermination(2, SECONDS));
            }
            metrics.close();
            for (Thread reader : readers) {
                reader.join(2000);
                assertFalse(reader.isAlive());
            }
            assertThrows(IllegalStateException.class, metrics::meterProvider);
        }
    }

    @Test
    void publishesQueueStateAndActualDropsAndDetectsDrainingWithoutNewEvents() throws Exception {
        RecordingMetrics nativeMetrics = new RecordingMetrics();
        try (LogCapture capture = new LogCapture();
             LogstashSdkMetrics metrics = new LogstashSdkMetrics(capture.logger, "queue-test", 2, nativeMetrics)) {
            BlockingExporter exporter = new BlockingExporter();
            SdkLoggerProvider provider = SdkLoggerProvider.builder()
                    .addLogRecordProcessor(new SharedQueueLogRecordProcessor("queue-test", List.of(exporter),
                            2, 1, 1000, metrics.meterProvider()))
                    .build();
            try {
                var logger = provider.get("queue-test");
                logger.logRecordBuilder().setBody("in flight").emit();
                assertTrue(exporter.started.await(2, SECONDS));
                logger.logRecordBuilder().setBody("queued first").emit();
                logger.logRecordBuilder().setBody("queued second").emit();
                collect(metrics);
                assertTrue(capture.events.isEmpty());
                assertEquals(Set.of("sdk_metrics"), nativeMetrics.values.keySet());
                assertEquals(0, nativeMetrics.droppedRecords());
                assertEquals(2, nativeMetrics.metricValue("otel.sdk.processor.log.queue.capacity", ""));
                assertEquals(2, nativeMetrics.metricValue("otel.sdk.processor.log.queue.size", ""));

                logger.logRecordBuilder().setBody("dropped").emit();
                collect(metrics);

                assertEquals(1, nativeMetrics.droppedRecords());
                assertEquals(1L, nativeMetrics.point("otel.sdk.processor.log.processed", "queue_full").get("value"));
                assertEquals(1, capture.events.size());
                assertEquals(Level.WARN, capture.events.get(0).getLevel());
                assertEquals("OTLP export queue full: output_id=queue-test queue_size=2 dropped_records=1 total_dropped_records=1",
                        capture.message(0));

                exporter.pending.succeed();
                assertTrue(provider.forceFlush().join(2, SECONDS).isSuccess());
                long deadline = System.nanoTime() + SECONDS.toNanos(3);
                while (nativeMetrics.metricValue("otel.sdk.processor.log.queue.size", "") != 0 && System.nanoTime() < deadline) Thread.sleep(10);
                assertEquals(0, nativeMetrics.metricValue("otel.sdk.processor.log.queue.size", ""));
                assertEquals(1, nativeMetrics.droppedRecords());
            } finally {
                exporter.pending.succeed();
                provider.close();
            }
        }
    }

    @Test
    void publishesInflightAndCompletedExportsWithTheirActualErrorType() throws Exception {
        RecordingMetrics nativeMetrics = new RecordingMetrics();
        AtomicInteger status = new AtomicInteger(200);
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch respond = new CountDownLatch(1);
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/logs", exchange -> {
            exchange.getRequestBody().readAllBytes();
            started.countDown();
            try {
                if (!respond.await(3, SECONDS)) throw new IllegalStateException("Response was not released");
                exchange.sendResponseHeaders(status.get(), -1);
            } catch (InterruptedException failure) {
                Thread.currentThread().interrupt();
            } finally {
                exchange.close();
            }
        });
        server.start();
        try (LogCapture capture = new LogCapture();
             LogstashSdkMetrics metrics = new LogstashSdkMetrics(capture.logger, "http-test", 32, nativeMetrics)) {
            nativeMetrics.registrationClosed = true;
            var exporter = OtlpHttpLogRecordExporter.builder()
                    .setEndpoint("http://127.0.0.1:" + server.getAddress().getPort() + "/v1/logs")
                    .setMeterProvider(metrics.meterProvider())
                    .setInternalTelemetryVersion(InternalTelemetryVersion.LATEST)
                    .setTimeout(3, SECONDS).build();
            SdkLoggerProvider provider = SdkLoggerProvider.builder()
                    .addLogRecordProcessor(new SharedQueueLogRecordProcessor("http-test", List.of(exporter),
                            32, 1, 1000, metrics.meterProvider())).build();
            try {
                var logger = provider.get("http-test");
                logger.logRecordBuilder().setBody("successful export").emit();
                assertTrue(started.await(2, SECONDS));
                collect(metrics);
                assertEquals(1L, nativeMetrics.point("otel.sdk.exporter.log.inflight", "").get("value"));
                respond.countDown();
                assertTrue(provider.forceFlush().join(3, SECONDS).isSuccess());
                collect(metrics);
                var success = nativeMetrics.point("otel.sdk.exporter.log.exported", "");
                assertEquals(1L, success.get("value"));
                assertEquals("{log_record}", success.get("unit"));
                assertEquals("127.0.0.1", success.get("server_address"));
                assertEquals((long) server.getAddress().getPort(), success.get("server_port"));
                assertNotNull(success.get("otel_component_name"));

                status.set(400);
                logger.logRecordBuilder().setBody("failed export").emit();
                assertTrue(provider.forceFlush().join(3, SECONDS).isDone());
                collect(metrics);
                assertEquals(1L, nativeMetrics.point("otel.sdk.exporter.log.exported", "400").get("value"));
                assertEquals(1L, nativeMetrics.point("otel.sdk.exporter.log.exported", "").get("value"));
                assertEquals(0L, nativeMetrics.point("otel.sdk.exporter.log.inflight", "").get("value"));
                assertEquals(0, nativeMetrics.droppedRecords());
                assertTrue(capture.events.isEmpty());
                var duration = nativeMetrics.point("otel.sdk.exporter.operation.duration", "400");
                assertEquals(1L, duration.get("count"));
                assertEquals("s", duration.get("unit"));
                assertTrue((double) duration.get("sum") >= 0);
            } finally {
                respond.countDown();
                provider.close();
            }
        } finally {
            respond.countDown();
            server.stop(0);
        }
    }

    @Test
    void limitsWarningsAndIncludesDropsSinceThePreviousWarning() {
        AtomicLong clock = new AtomicLong();
        RecordingMetrics nativeMetrics = new RecordingMetrics();
        try (LogCapture capture = new LogCapture();
             LogstashSdkMetrics metrics = new LogstashSdkMetrics(capture.logger, "queue-test", 32, nativeMetrics, clock::get)) {
            LongCounter counter = counter(metrics);
            counter.add(100, Attributes.empty());
            collect(metrics);
            assertTrue(capture.events.isEmpty());
            assertEquals(0, nativeMetrics.droppedRecords());

            counter.add(3, DROPPED);
            collect(metrics);
            assertEquals(3, nativeMetrics.droppedRecords());
            counter.add(4, DROPPED);
            clock.set(SECONDS.toNanos(29));
            collect(metrics);
            assertEquals(1, capture.events.size());
            assertEquals(7, nativeMetrics.droppedRecords());

            clock.set(SECONDS.toNanos(30));
            collect(metrics);
            assertEquals(2, capture.events.size());
            assertTrue(capture.message(1).endsWith("dropped_records=4 total_dropped_records=7"));
            clock.set(SECONDS.toNanos(60));
            collect(metrics);
            assertEquals(2, capture.events.size());
            assertEquals(7, nativeMetrics.droppedRecords());
        }
    }

    @Test
    void eachOutputHasIndependentCountersAndWarningLimits() {
        RecordingMetrics firstNative = new RecordingMetrics();
        RecordingMetrics secondNative = new RecordingMetrics();
        try (LogCapture capture = new LogCapture();
             LogstashSdkMetrics first = new LogstashSdkMetrics(capture.logger, "first", 32, firstNative);
             LogstashSdkMetrics second = new LogstashSdkMetrics(capture.logger, "second", 64, secondNative)) {
            counter(first).add(3, DROPPED);
            counter(second).add(1, DROPPED);
            collect(first);
            collect(second);
            assertEquals(3, firstNative.droppedRecords());
            assertEquals(1, secondNative.droppedRecords());
            assertEquals(2, capture.events.size());
            assertTrue(capture.message(0).contains("output_id=first"));
            assertTrue(capture.message(0).endsWith("total_dropped_records=3"));
            assertTrue(capture.message(1).contains("output_id=second"));
            assertTrue(capture.message(1).endsWith("total_dropped_records=1"));
        }
    }

    @Test
    void partialSuccessCountsEveryRejectionAndLimitsWarningsWithoutKeepingMessages() {
        AtomicLong clock = new AtomicLong();
        RecordingMetrics nativeMetrics = new RecordingMetrics();
        try (LogCapture capture = new LogCapture();
             LogstashSdkMetrics metrics = new LogstashSdkMetrics(capture.logger, "partial-test", 32,
                     nativeMetrics, clock::get)) {
            metrics.recordPartialSuccess(2, "bad\nrecord\r\t" + "x".repeat(2000));
            clock.set(SECONDS.toNanos(29));
            metrics.recordPartialSuccess(3, "another rejection");
            metrics.export(List.of());

            assertEquals(5, nativeMetrics.metricValue("otlp.exporter.log.rejected", "partial_success"));
            assertEquals(1, capture.events.size());
            assertFalse(capture.message(0).contains("\n"));
            assertFalse(capture.message(0).contains("\r"));
            assertFalse(capture.message(0).contains("\t"));
            assertTrue(capture.message(0).length() < 1250);

            clock.set(SECONDS.toNanos(30));
            metrics.recordPartialSuccess(1, "invalid field");
            metrics.export(List.of());
            assertEquals(2, capture.events.size());
            assertTrue(capture.message(1).contains("total_rejected_records=6 suppressed_responses=1"));
            assertEquals(6, nativeMetrics.metricValue("otlp.exporter.log.rejected", "partial_success"));

            metrics.close();
            clock.set(SECONDS.toNanos(60));
            metrics.recordPartialSuccess(100, "late callback");
            metrics.recordInvalidResponse();
            metrics.export(List.of());
            assertEquals(2, capture.events.size());
            assertEquals(6, nativeMetrics.metricValue("otlp.exporter.log.rejected", "partial_success"));
            assertTrue(metricWorkers("partial-test").isEmpty());
        }
    }

    @Test
    void partialSuccessCounterCannotOverflowAndInvalidResponseWarningsAreLimited() {
        RecordingMetrics nativeMetrics = new RecordingMetrics();
        try (LogCapture capture = new LogCapture();
             LogstashSdkMetrics metrics = new LogstashSdkMetrics(capture.logger, "invalid-response", 32, nativeMetrics)) {
            metrics.recordPartialSuccess(Long.MAX_VALUE, "rejected");
            metrics.recordPartialSuccess(1, "rejected");
            metrics.recordInvalidResponse();
            metrics.recordInvalidResponse();
            metrics.export(List.of());

            assertEquals(Long.MAX_VALUE, nativeMetrics.metricValue("otlp.exporter.log.rejected", "partial_success"));
            assertEquals(2, capture.events.size());
            assertTrue(capture.message(1).startsWith("OTLP response diagnostics failed:"));
        }
    }

    @Test
    void concurrentChecksDoNotDuplicateWarnings() throws Exception {
        RecordingMetrics nativeMetrics = new RecordingMetrics();
        try (LogCapture capture = new LogCapture();
             LogstashSdkMetrics metrics = new LogstashSdkMetrics(capture.logger, "queue-test", 32, nativeMetrics)) {
            var snapshot = List.of(ImmutableMetricData.createLongSum(Resource.empty(),
                    InstrumentationScopeInfo.create("io.opentelemetry.sdk.logs"), "otel.sdk.processor.log.processed", "", "",
                    ImmutableSumData.create(true, AggregationTemporality.CUMULATIVE,
                            List.of(ImmutableLongPointData.create(0, 1, DROPPED, 100)))));
            var executor = Executors.newFixedThreadPool(4);
            try {
                List<Future<?>> checks = new ArrayList<>();
                for (int i = 0; i < 20; i++) checks.add(executor.submit(() -> metrics.export(snapshot)));
                for (Future<?> check : checks) check.get(2, SECONDS);
                executor.shutdown();
                assertTrue(executor.awaitTermination(2, SECONDS));
                assertEquals(1, capture.events.size());
                assertTrue(capture.message(0).endsWith("total_dropped_records=100"));
                assertEquals(100, nativeMetrics.droppedRecords());
            } finally {
                executor.shutdownNow();
            }
        }
    }

    @Test
    void closingStopsTheWorkerAndMetricUpdatesAndIsSafeToRepeat() throws Exception {
        AtomicLong clock = new AtomicLong();
        RecordingMetrics nativeMetrics = new RecordingMetrics();
        try (LogCapture capture = new LogCapture();
             LogstashSdkMetrics metrics = new LogstashSdkMetrics(capture.logger, "close-test", 32, nativeMetrics, clock::get)) {
            LongCounter counter = counter(metrics);
            Thread worker = Thread.getAllStackTraces().keySet().stream()
                    .filter(thread -> thread.getName().equals("otlp-sdk-metrics-close-test"))
                    .findFirst().orElseThrow();
            counter.add(1, DROPPED);
            collect(metrics);
            metrics.close();
            worker.join(2000);
            assertFalse(worker.isAlive());
            clock.set(SECONDS.toNanos(30));
            counter.add(1, DROPPED);
            metrics.export(List.of());
            assertEquals(1, capture.events.size());
            assertEquals(1, nativeMetrics.droppedRecords());
        }
    }

    private static LongCounter counter(LogstashSdkMetrics metrics) {
        return metrics.meterProvider().get("io.opentelemetry.sdk.logs").counterBuilder("otel.sdk.processor.log.processed").build();
    }

    private static Set<Thread> metricWorkers(String outputId) {
        return Thread.getAllStackTraces().keySet().stream()
                .filter(thread -> thread.isAlive() && thread.getName().equals("otlp-sdk-metrics-" + outputId))
                .collect(java.util.stream.Collectors.toSet());
    }

    private static void collect(LogstashSdkMetrics metrics) {
        assertTrue(((SdkMeterProvider) metrics.meterProvider()).forceFlush().join(2, SECONDS).isSuccess());
    }

    private static final class RecordingMetrics implements NamespacedMetric {
        private final Map<String, Object> values = new ConcurrentHashMap<>();
        private boolean registrationClosed;

        @SuppressWarnings("unchecked")
        private Collection<Map<String, Object>> points(String name) {
            Map<String, Map<String, Map<String, Object>>> sdk =
                    (Map<String, Map<String, Map<String, Object>>>) values.get("sdk_metrics");
            return sdk.getOrDefault(name.replace('.', '_'), Map.of()).values();
        }
        private Map<String, Object> point(String name, String errorType) {
            return points(name).stream().filter(point -> point.get("error_type").equals(errorType))
                    .findFirst().orElseThrow();
        }
        private long metricValue(String name, String errorType) {
            return ((Number) point(name, errorType).get("value")).longValue();
        }
        private long droppedRecords() {
            return points("otel.sdk.processor.log.processed").stream()
                    .filter(point -> point.get("error_type").equals("queue_full"))
                    .mapToLong(point -> ((Number) point.get("value")).longValue()).sum();
        }
        public void gauge(String name, Object value) {
            assertFalse(registrationClosed && !values.containsKey(name), "Metrics must be registered at startup");
            values.put(name, value);
        }
        public CounterMetric counter(String name) { throw new UnsupportedOperationException(); }
        public TimerMetric timer(String name) { throw new UnsupportedOperationException(); }
        public void increment(String name) { throw new UnsupportedOperationException(); }
        public void increment(String name, int delta) { throw new UnsupportedOperationException(); }
        public <T> T time(String name, Supplier<T> action) { throw new UnsupportedOperationException(); }
        public void reportTime(String name, long duration) { throw new UnsupportedOperationException(); }
        public String[] namespaceName() { return new String[]{"outputs", "queue-test"}; }
        public Metric root() { throw new UnsupportedOperationException(); }
        public NamespacedMetric namespace(String... names) { throw new UnsupportedOperationException(); }
    }

    private static final class BlockingExporter implements LogRecordExporter {
        private final CountDownLatch started = new CountDownLatch(1);
        private final CompletableResultCode pending = new CompletableResultCode();

        @Override
        public CompletableResultCode export(Collection<LogRecordData> logs) {
            started.countDown();
            return pending;
        }

        @Override
        public CompletableResultCode flush() { return CompletableResultCode.ofSuccess(); }

        @Override
        public CompletableResultCode shutdown() { return CompletableResultCode.ofSuccess(); }
    }

    private static final class LogCapture implements AutoCloseable {
        private final org.apache.logging.log4j.core.Logger logger =
                (org.apache.logging.log4j.core.Logger) LogManager.getLogger(LogstashSdkMetricsTest.class);
        private final List<LogEvent> events = new CopyOnWriteArrayList<>();
        private final Level originalLevel = logger.getLevel();
        private final boolean originalAdditive = logger.isAdditive();
        private final AbstractAppender appender = new AbstractAppender("queue-test", null, null, false, Property.EMPTY_ARRAY) {
            @Override
            public void append(LogEvent event) { events.add(event.toImmutable()); }
        };

        private LogCapture() {
            appender.start();
            logger.addAppender(appender);
            logger.setLevel(Level.WARN);
            logger.setAdditive(false);
        }

        private String message(int index) { return events.get(index).getMessage().getFormattedMessage(); }

        @Override
        public void close() {
            logger.removeAppender(appender);
            logger.setLevel(originalLevel);
            logger.setAdditive(originalAdditive);
            appender.stop();
        }
    }
}
