package org.otlp;

import co.elastic.logstash.api.Event;
import com.sun.net.httpserver.HttpServer;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Property;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.parallel.Isolated;
import org.logstash.plugins.ConfigurationImpl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.jupiter.api.Assertions.*;

@Isolated
@Timeout(value = 10, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
class OtlpPartialSuccessTest {
    private static final String REJECTED = "otlp.exporter.log.rejected";

    @Test
    void rejectedLogsAreCountedAndWarnedWithoutRetryingTheSuccessfulBatch() throws Exception {
        try (ResponseServer server = new ResponseServer(partialSuccess(1, "invalid log"));
             LogCapture capture = new LogCapture()) {
            RecordingPluginContext metrics = new RecordingPluginContext("partial-success", capture.logger);
            Otlp output = output("partial-success", server, metrics, 2, 1);
            try {
                output.output(List.of(event("accepted"), event("rejected")));

                assertSuccessfulBatch(metrics, 2);
                metrics.awaitValue(REJECTED, "partial_success", 1);
                assertEquals(1, capture.events.size());
                assertPartialWarning(capture.events.get(0), "partial-success", 1, 1, "invalid log");
            } finally {
                output.stop();
            }
            assertEquals(1, server.attempts.get());
        }
    }

    @Test
    void collectorWarningWithNoRejectedLogsIsStillReported() throws Exception {
        try (ResponseServer server = new ResponseServer(partialSuccess(0, "collector warning"));
             LogCapture capture = new LogCapture()) {
            RecordingPluginContext metrics = new RecordingPluginContext("warning-only", capture.logger);
            Otlp output = output("warning-only", server, metrics, 1, 1);
            try {
                output.output(List.of(event("accepted")));

                assertSuccessfulBatch(metrics, 1);
                assertEquals(0, metrics.value(REJECTED, "partial_success"));
                assertEquals(1, capture.events.size());
                assertPartialWarning(capture.events.get(0), "warning-only", 0, 0, "collector warning");
            } finally {
                output.stop();
            }
            assertEquals(1, server.attempts.get());
        }
    }

    @Test
    void emptySuccessfulResponseDoesNotWarnOrCountRejections() throws Exception {
        assertSilentSuccess(new byte[0]);
    }

    @Test
    void emptyPartialSuccessDoesNotWarnOrCountRejections() throws Exception {
        assertSilentSuccess(new byte[]{0x0a, 0x00});
    }

    @Test
    void allConsumersAccumulateRejectedLogsWhileSharingTheWarningLimit() throws Exception {
        try (ResponseServer server = new ResponseServer(partialSuccess(1, "invalid log"), 2);
             LogCapture capture = new LogCapture()) {
            RecordingPluginContext metrics = new RecordingPluginContext("shared-warning", capture.logger);
            Otlp output = output("shared-warning", server, metrics, 1, 2);
            try {
                output.output(List.of(event("rejected-1"), event("rejected-2")));
                assertSuccessfulBatch(metrics, 2);
                metrics.awaitValue(REJECTED, "partial_success", 2);

                output.output(List.of(event("rejected-3"), event("rejected-4")));
                assertSuccessfulBatch(metrics, 4);
                metrics.awaitValue(REJECTED, "partial_success", 4);

                assertEquals(1, capture.events.size());
                assertPartialWarning(capture.events.get(0), "shared-warning", 1, 1, "invalid log");
            } finally {
                output.stop();
            }
            assertEquals(4, server.attempts.get());
        }
    }

    @Test
    void outputInstancesKeepRejectedCountersAndWarningLimitsIndependent() throws Exception {
        try (ResponseServer server = new ResponseServer(partialSuccess(1, "invalid log"));
             LogCapture capture = new LogCapture()) {
            RecordingPluginContext firstMetrics = new RecordingPluginContext("first-output", capture.logger);
            RecordingPluginContext secondMetrics = new RecordingPluginContext("second-output", capture.logger);
            Otlp first = output("first-output", server, firstMetrics, 1, 1);
            Otlp second = output("second-output", server, secondMetrics, 1, 1);
            try {
                first.output(List.of(event("first-1"), event("first-2")));
                assertSuccessfulBatch(firstMetrics, 2);
                firstMetrics.awaitValue(REJECTED, "partial_success", 2);
                assertEquals(0, secondMetrics.value(REJECTED, "partial_success"));

                second.output(List.of(event("second-1")));
                assertSuccessfulBatch(secondMetrics, 1);
                secondMetrics.awaitValue(REJECTED, "partial_success", 1);
                assertEquals(2, firstMetrics.value(REJECTED, "partial_success"));

                assertEquals(2, capture.events.size());
                assertPartialWarning(capture.events.get(0), "first-output", 1, 1, "invalid log");
                assertPartialWarning(capture.events.get(1), "second-output", 1, 1, "invalid log");
            } finally {
                first.stop();
                second.stop();
            }
            assertEquals(3, server.attempts.get());
        }
    }

    @Test
    void malformedResponseWarnsWithoutHangingCountingRejectionsOrRetrying() throws Exception {
        try (ResponseServer server = new ResponseServer(new byte[]{0x0a, 0x02, 0x08});
             LogCapture capture = new LogCapture()) {
            RecordingPluginContext metrics = new RecordingPluginContext("invalid-response", capture.logger);
            Otlp output = output("invalid-response", server, metrics, 1, 1);
            try {
                output.output(List.of(event("accepted")));

                assertSuccessfulBatch(metrics, 1);
                assertEquals(0, metrics.value(REJECTED, "partial_success"));
                assertEquals(1, capture.events.size());
                LogEvent warning = capture.events.get(0);
                assertEquals(Level.WARN, warning.getLevel());
                assertTrue(warning.getMessage().getFormattedMessage().startsWith("OTLP response diagnostics failed:"));
                assertTrue(warning.getMessage().getFormattedMessage().contains("output_id=invalid-response"));
            } finally {
                output.stop();
            }
            assertEquals(1, server.attempts.get());
        }
    }

    private static void assertSilentSuccess(byte[] response) throws Exception {
        try (ResponseServer server = new ResponseServer(response);
             LogCapture capture = new LogCapture()) {
            RecordingPluginContext metrics = new RecordingPluginContext("full-success", capture.logger);
            Otlp output = output("full-success", server, metrics, 1, 1);
            try {
                output.output(List.of(event("accepted")));

                assertSuccessfulBatch(metrics, 1);
                assertEquals(0, metrics.value(REJECTED, "partial_success"));
                assertTrue(capture.events.isEmpty());
            } finally {
                output.stop();
            }
            assertEquals(1, server.attempts.get());
        }
    }

    private static void assertSuccessfulBatch(RecordingPluginContext metrics, long records) throws InterruptedException {
        metrics.awaitValue("otel.sdk.exporter.log.exported", "", records);
        metrics.awaitValue("otel.sdk.processor.log.processed", "", records);
        assertEquals(0, metrics.value("otel.sdk.processor.log.processed", "export_failed"));
        assertEquals(0, metrics.value("otel.sdk.exporter.log.inflight", ""));
    }

    private static void assertPartialWarning(LogEvent warning, String id, long rejected, long total, String reason) {
        assertEquals(Level.WARN, warning.getLevel());
        String message = warning.getMessage().getFormattedMessage();
        assertTrue(message.startsWith("OTLP partial success:"), message);
        assertTrue(message.contains("output_id=" + id), message);
        assertTrue(message.contains(" rejected_records=" + rejected), message);
        assertTrue(message.contains(" total_rejected_records=" + total), message);
        assertTrue(message.contains(" error_message=" + reason), message);
    }

    private static Otlp output(String id, ResponseServer server, RecordingPluginContext metrics,
                               long batchSize, long consumers) {
        return new Otlp(id, new ConfigurationImpl(Map.of(
                "endpoint", "http://127.0.0.1:" + server.server.getAddress().getPort() + "/v1/logs",
                "protocol", "http", "max_batch_size", batchSize, "num_consumers", consumers,
                "schedule_delay_millis", 60000L, "timeout", 5L)), metrics);
    }

    private static byte[] partialSuccess(int rejected, String message) {
        byte[] reason = message.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream response = new ByteArrayOutputStream();
        response.write(0x0a);
        response.write(4 + reason.length);
        response.write(0x08);
        response.write(rejected);
        response.write(0x12);
        response.write(reason.length);
        response.writeBytes(reason);
        return response.toByteArray();
    }

    private static Event event(String body) {
        Event event = new org.logstash.Event();
        event.setField("message", body);
        return event;
    }

    private static final class ResponseServer implements AutoCloseable {
        private final HttpServer server;
        private final ExecutorService executor;
        private final AtomicInteger attempts = new AtomicInteger();

        private ResponseServer(byte[] response) throws IOException {
            this(response, 1);
        }

        private ResponseServer(byte[] response, int concurrentRequests) throws IOException {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            executor = Executors.newFixedThreadPool(concurrentRequests);
            CountDownLatch firstRequests = new CountDownLatch(concurrentRequests);
            server.setExecutor(executor);
            server.createContext("/v1/logs", exchange -> {
                try {
                    exchange.getRequestBody().readAllBytes();
                    attempts.incrementAndGet();
                    firstRequests.countDown();
                    if (!firstRequests.await(3, SECONDS)) throw new IOException("concurrent requests did not arrive");
                    exchange.getResponseHeaders().set("Content-Type", "application/x-protobuf");
                    exchange.sendResponseHeaders(200, response.length == 0 ? -1 : response.length);
                    if (response.length > 0) exchange.getResponseBody().write(response);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new IOException(interrupted);
                } finally {
                    exchange.close();
                }
            });
            server.start();
        }

        @Override
        public void close() throws InterruptedException {
            server.stop(0);
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(3, SECONDS));
        }
    }

    private static final class LogCapture implements AutoCloseable {
        private final org.apache.logging.log4j.core.Logger logger =
                (org.apache.logging.log4j.core.Logger) LogManager.getLogger(OtlpPartialSuccessTest.class);
        private final List<LogEvent> events = new CopyOnWriteArrayList<>();
        private final Level originalLevel = logger.getLevel();
        private final boolean originalAdditive = logger.isAdditive();
        private final AbstractAppender appender = new AbstractAppender("partial-success-test", null, null, false, Property.EMPTY_ARRAY) {
            @Override
            public void append(LogEvent event) { events.add(event.toImmutable()); }
        };

        private LogCapture() {
            appender.start();
            logger.addAppender(appender);
            logger.setLevel(Level.WARN);
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
