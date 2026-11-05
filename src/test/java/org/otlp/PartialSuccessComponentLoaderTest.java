package org.otlp;

import io.opentelemetry.common.ComponentLoader;
import io.opentelemetry.sdk.common.CompletableResultCode;
import io.opentelemetry.sdk.common.export.*;
import org.apache.logging.log4j.LogManager;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.*;

class PartialSuccessComponentLoaderTest {
    @Test
    void grpcSuccessRecordsRejectionsAndPreservesTheResponseAndShutdown() {
        var logger = LogManager.getLogger(getClass());
        var context = new RecordingPluginContext("grpc-partial", logger);
        try (var metrics = new LogstashSdkMetrics(logger, "grpc-partial", 32, context)) {
            var sender = new TestGrpcSender();
            GrpcSender observed = wrap(sender, metrics);
            var received = new AtomicReference<GrpcResponse>();
            observed.send(null, received::set, failure -> fail(failure));

            metrics.export(List.of());
            assertSame(sender.response, received.get());
            assertEquals(2, context.value("otlp.exporter.log.rejected", "partial_success"));
            assertEquals(1, sender.sends);
            assertSame(sender.shutdown, observed.shutdown());
            assertEquals(1, sender.shutdowns);
        }
    }

    @Test
    void grpcFailureAndTransportErrorAreForwardedWithoutCountingRejections() {
        var logger = LogManager.getLogger(getClass());
        var context = new RecordingPluginContext("grpc-error", logger);
        try (var metrics = new LogstashSdkMetrics(logger, "grpc-error", 32, context)) {
            var sender = new TestGrpcSender();
            sender.status = GrpcStatusCode.UNAVAILABLE;
            GrpcSender observed = wrap(sender, metrics);
            observed.send(null, response -> assertSame(sender.response, response), failure -> fail(failure));
            sender.failure = new IllegalStateException("connection closed");
            var error = new AtomicReference<Throwable>();
            observed.send(null, response -> fail("Unexpected response"), error::set);

            metrics.export(List.of());
            assertSame(sender.failure, error.get());
            assertEquals(0, context.value("otlp.exporter.log.rejected", "partial_success"));
            assertEquals(2, sender.sends);
        }
    }

    @Test
    void invalidGrpcBodyStillCompletesTheSdkCallbackOnce() {
        var logger = LogManager.getLogger(getClass());
        try (var metrics = new LogstashSdkMetrics(logger, "grpc-invalid", 32, null)) {
            var sender = new TestGrpcSender();
            sender.body = new byte[]{10};
            GrpcSender observed = wrap(sender, metrics);
            var callbacks = new AtomicInteger();

            observed.send(null, response -> callbacks.incrementAndGet(), failure -> fail(failure));

            assertEquals(1, callbacks.get());
            RuntimeException callbackFailure = new IllegalStateException("callback failure");
            assertSame(callbackFailure, assertThrows(RuntimeException.class, () ->
                    observed.send(null, response -> { throw callbackFailure; }, failure -> fail(failure))));
        }
    }

    private static GrpcSender wrap(TestGrpcSender sender, LogstashSdkMetrics metrics) {
        ComponentLoader original = new ComponentLoader() {
            @Override
            public <T> Iterable<T> load(Class<T> spiClass) {
                return List.of(spiClass.cast((GrpcSenderProvider) config -> sender));
            }
        };
        return new PartialSuccessComponentLoader(original, metrics)
                .load(GrpcSenderProvider.class).iterator().next().createSender(null);
    }

    private static final class TestGrpcSender implements GrpcSender {
        private byte[] body = {10, 2, 8, 2};
        private GrpcStatusCode status = GrpcStatusCode.OK;
        private Throwable failure;
        private int sends;
        private int shutdowns;
        private final CompletableResultCode shutdown = new CompletableResultCode();
        private final GrpcResponse response = new GrpcResponse() {
            public GrpcStatusCode getStatusCode() { return status; }
            public String getStatusDescription() { return ""; }
            public byte[] getResponseMessage() { return body; }
        };

        @Override
        public void send(MessageWriter writer, Consumer<GrpcResponse> onResponse, Consumer<Throwable> onError) {
            sends++;
            if (failure == null) onResponse.accept(response);
            else onError.accept(failure);
        }

        @Override
        public CompletableResultCode shutdown() {
            shutdowns++;
            return shutdown;
        }
    }
}
