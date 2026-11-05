package org.otlp;

import co.elastic.logstash.api.Event;
import com.sun.net.httpserver.HttpServer;
import io.opentelemetry.sdk.common.export.RetryPolicy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.logstash.plugins.ConfigurationImpl;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static org.junit.jupiter.api.Assertions.*;

@Timeout(value = 10, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
class OtlpRetrySettingsTest {
    private HttpServer server;
    private Otlp output;
    private final List<byte[]> requests = new CopyOnWriteArrayList<>();
    private final List<Long> requestTimes = new CopyOnWriteArrayList<>();

    @AfterEach
    void closeResources() {
        try {
            if (output != null) output.stop();
        } finally {
            if (server != null) server.stop(0);
        }
    }

    @Test
    void registersRetrySettingsWithATenSecondNominalCap() {
        output = newOutput(Map.of());
        List<String> names = output.configSchema().stream().map(setting -> setting.name()).toList();
        assertTrue(names.containsAll(List.of("retry_initial_backoff_millis", "retry_max_backoff_millis",
                "retry_backoff_multiplier", "retry_max_attempts")));
        RetryPolicy policy = output.retryPolicyForConfig();
        assertEquals(Duration.ofSeconds(1), policy.getInitialBackoff());
        assertEquals(Duration.ofSeconds(10), policy.getMaxBackoff());
        assertEquals(1.5, policy.getBackoffMultiplier());
        assertEquals(5, policy.getMaxAttempts());
    }

    @Test
    void rejectsInvalidRetrySettingsBeforeCreatingResources() {
        for (String name : List.of("retry_initial_backoff_millis", "retry_max_backoff_millis", "retry_max_attempts")) {
            for (Object value : List.of(0L, -1L, Long.MAX_VALUE, "1.5", "invalid")) {
                IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                        () -> newOutput(Map.of(name, value)));
                assertTrue(error.getMessage().contains(name));
            }
        }
        for (Object value : List.of(0.0, -1.0, 0.5, Double.NaN, Double.POSITIVE_INFINITY,
                "NaN", "Infinity", "invalid")) {
            IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                    () -> newOutput(Map.of("retry_backoff_multiplier", value)));
            assertTrue(error.getMessage().contains("retry_backoff_multiplier"));
        }
        for (long attempts : new long[]{1, 6}) {
            assertThrows(IllegalArgumentException.class, () -> newOutput(Map.of("retry_max_attempts", attempts)));
        }
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> newOutput(Map.of("retry_initial_backoff_millis", 200L, "retry_max_backoff_millis", 100L)));
        assertTrue(error.getMessage().contains("retry_max_backoff_millis"));
    }

    @Test
    void acceptsEnvironmentValuesForHttpAndGrpc() {
        for (String protocol : List.of("http", "grpc")) {
            output = newOutput(Map.of("protocol", protocol,
                    "retry_initial_backoff_millis", "20", "retry_max_backoff_millis", "80",
                    "retry_backoff_multiplier", "2.5", "retry_max_attempts", "3"));
            RetryPolicy policy = output.retryPolicyForConfig();
            assertEquals(Duration.ofMillis(20), policy.getInitialBackoff());
            assertEquals(Duration.ofMillis(80), policy.getMaxBackoff());
            assertEquals(2.5, policy.getBackoffMultiplier());
            assertEquals(3, policy.getMaxAttempts());
            output.stop();
        }
    }

    @Test
    void retriesTheSameBatchWithTheConfiguredAttemptLimitAndBackoff() throws Exception {
        startServer(503);
        output = newOutput(Map.of("timeout", 1L, "retry_initial_backoff_millis", 40L,
                "retry_max_backoff_millis", 80L, "retry_backoff_multiplier", 100.0, "retry_max_attempts", 3L));

        output.output(List.of(event()));
        output.stop();

        assertEquals(3, requests.size());
        assertArrayEquals(requests.get(0), requests.get(1));
        assertArrayEquals(requests.get(0), requests.get(2));
        assertTrue(requestTimes.get(1) - requestTimes.get(0) >= MILLISECONDS.toNanos(30));
        assertTrue(requestTimes.get(2) - requestTimes.get(1) >= MILLISECONDS.toNanos(60));
        assertEquals(Duration.ofMillis(80), output.retryPolicyForConfig().getMaxBackoff());
    }

    @Test
    void successfulRetryStopsBeforeTheAttemptLimit() throws Exception {
        startServer(503, 200);
        output = newOutput(Map.of("retry_initial_backoff_millis", 10L,
                "retry_max_backoff_millis", 20L, "retry_max_attempts", 5L));

        output.output(List.of(event()));
        output.stop();

        assertEquals(2, requests.size());
        assertArrayEquals(requests.get(0), requests.get(1));
    }

    @Test
    void requestTimeoutCanEndRetriesBeforeTheAttemptLimit() throws Exception {
        startServer(503);
        output = newOutput(Map.of("timeout", 1L, "retry_initial_backoff_millis", 1500L,
                "retry_max_backoff_millis", 1500L, "retry_max_attempts", 5L));

        output.output(List.of(event()));
        output.stop();

        assertEquals(1, requests.size());
    }

    private void startServer(int... statuses) throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/logs", exchange -> {
            try {
                requestTimes.add(System.nanoTime());
                requests.add(exchange.getRequestBody().readAllBytes());
                exchange.getResponseHeaders().set("Content-Type", "application/x-protobuf");
                exchange.sendResponseHeaders(statuses[Math.min(requests.size() - 1, statuses.length - 1)], -1);
            } finally {
                exchange.close();
            }
        });
        server.start();
    }

    private Otlp newOutput(Map<String, Object> settings) {
        Map<String, Object> config = new HashMap<>();
        config.put("endpoint", "http://127.0.0.1:" + (server == null ? 4318 : server.getAddress().getPort()) + "/v1/logs");
        config.put("protocol", "http");
        config.put("max_batch_size", 1L);
        config.put("timeout", 5L);
        config.putAll(settings);
        return new Otlp("retry-test", new ConfigurationImpl(config), null);
    }

    private static Event event() {
        Event event = new org.logstash.Event();
        event.setField("message", "retry-policy-record");
        return event;
    }
}
