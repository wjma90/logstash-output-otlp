package org.otlp;

import co.elastic.logstash.api.Event;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.logstash.plugins.ConfigurationImpl;

import java.io.ByteArrayInputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.GZIPInputStream;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.jupiter.api.Assertions.*;

@Timeout(value = 15, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
class OtlpTransportTest {
    private final BlockingQueue<ReceivedRequest> requests = new LinkedBlockingQueue<>();
    private final ExecutorService serverExecutor = Executors.newFixedThreadPool(4, action -> {
        Thread thread = new Thread(action, "otlp-http-test");
        thread.setDaemon(true);
        return thread;
    });
    private CountDownLatch respond = new CountDownLatch(0);
    private HttpServer server;
    private Otlp output;

    @AfterEach
    void closeResources() throws Exception {
        respond.countDown();
        try {
            if (output != null) output.stop();
        } finally {
            if (server != null) server.stop(0);
            serverExecutor.shutdownNow();
            assertTrue(serverExecutor.awaitTermination(3, SECONDS));
        }
    }

    @Test
    void httpProtocolAndLegacyEndpointTypeSendProtobuf() throws Exception {
        startServer(200);
        for (String setting : List.of("protocol", "endpoint_type")) {
            output = newOutput(Map.of(setting, "http"));
            output.output(List.of(event("transport-" + setting)));
            output.stop();

            ReceivedRequest request = nextRequest();
            assertEquals("application/x-protobuf", request.contentType());
            assertNull(request.contentEncoding());
            assertTrue(request.text().contains("transport-" + setting));
        }
        assertTrue(requests.isEmpty());
    }

    @Test
    void gzipCompressionPreservesTheLogBody() throws Exception {
        startServer(200);
        output = newOutput(Map.of("protocol", "http", "compression", "gzip"));
        output.output(List.of(event("compressed-transport-record")));
        output.stop();

        ReceivedRequest request = nextRequest();
        assertEquals("application/x-protobuf", request.contentType());
        assertEquals("gzip", request.contentEncoding());
        try (GZIPInputStream compressed = new GZIPInputStream(new ByteArrayInputStream(request.body()))) {
            String decoded = new String(compressed.readAllBytes(), StandardCharsets.UTF_8);
            assertTrue(decoded.contains("compressed-transport-record"));
        }
        assertTrue(requests.isEmpty());
    }

    @Test
    void transientServiceUnavailableRetriesTheSameBatch() throws Exception {
        startServer(503, 200);
        output = newOutput(Map.of("protocol", "http"));
        output.output(List.of(event("retryable-transport-record")));
        output.stop();

        ReceivedRequest failed = nextRequest();
        ReceivedRequest successful = nextRequest();
        assertArrayEquals(failed.body(), successful.body());
        assertTrue(successful.text().contains("retryable-transport-record"));
        assertTrue(requests.isEmpty());
    }

    @Test
    void badRequestIsNotRetried() throws Exception {
        startServer(400);
        output = newOutput(Map.of("protocol", "http"));
        output.output(List.of(event("invalid-transport-record")));
        output.stop();

        assertTrue(nextRequest().text().contains("invalid-transport-record"));
        assertTrue(requests.isEmpty());
    }

    @Test
    void rejectsInvalidTransportSettingsBeforeTheFirstEvent() throws Exception {
        startServer(200);
        for (Map<String, Object> settings : List.of(
                Map.<String, Object>of("protocol", "invalid"),
                Map.<String, Object>of("endpoint_type", "invalid"),
                Map.<String, Object>of("protocol", "http", "compression", "invalid"))) {
            assertThrows(IllegalArgumentException.class, () -> newOutput(settings));
        }
        assertTrue(requests.isEmpty());
    }

    @Test
    void twoConsumersSendEachRecordOnceWhileRequestsOverlap() throws Exception {
        respond = new CountDownLatch(1);
        startServer(200);
        output = newOutput(Map.of("protocol", "http", "num_consumers", 2L));
        List<Event> events = new ArrayList<>();
        for (int i = 0; i < 8; i++) events.add(event("parallel-transport-record-" + i));
        output.output(events);

        List<ReceivedRequest> received = new ArrayList<>();
        try {
            received.add(nextRequest());
            received.add(nextRequest());
        } finally {
            respond.countDown();
        }
        output.stop();
        requests.drainTo(received);

        assertEquals(8, received.size());
        for (int i = 0; i < 8; i++) {
            String expected = "parallel-transport-record-" + i;
            assertEquals(1, received.stream().filter(request -> request.text().contains(expected)).count());
        }
    }

    private void startServer(int... statuses) throws Exception {
        AtomicInteger attempts = new AtomicInteger();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(serverExecutor);
        server.createContext("/v1/logs", exchange -> {
            try {
                requests.add(new ReceivedRequest(exchange.getRequestHeaders().getFirst("Content-Type"),
                        exchange.getRequestHeaders().getFirst("Content-Encoding"),
                        exchange.getRequestBody().readAllBytes()));
                if (!respond.await(5, SECONDS)) throw new IllegalStateException("response was not released");
                int attempt = attempts.getAndIncrement();
                exchange.getResponseHeaders().set("Content-Type", "application/x-protobuf");
                exchange.sendResponseHeaders(statuses[Math.min(attempt, statuses.length - 1)], -1);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            } finally {
                exchange.close();
            }
        });
        server.start();
    }

    private Otlp newOutput(Map<String, Object> settings) {
        Map<String, Object> config = new HashMap<>(settings);
        config.put("endpoint", "http://127.0.0.1:" + server.getAddress().getPort() + "/v1/logs");
        config.put("queue_size", 32L);
        config.put("max_batch_size", 1L);
        config.put("schedule_delay_millis", 100L);
        config.put("connect_timeout", 2L);
        config.put("timeout", 5L);
        config.put("attributes", Map.of());
        return new Otlp("transport-test", new ConfigurationImpl(config), null);
    }

    private ReceivedRequest nextRequest() throws Exception {
        ReceivedRequest request = requests.poll(3, SECONDS);
        assertNotNull(request, "Expected an OTLP HTTP request");
        return request;
    }

    private static Event event(String message) {
        Event event = new org.logstash.Event();
        event.setField("message", message);
        return event;
    }

    private record ReceivedRequest(String contentType, String contentEncoding, byte[] body) {
        String text() {
            return new String(body, StandardCharsets.UTF_8);
        }
    }
}
