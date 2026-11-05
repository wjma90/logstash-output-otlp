package org.otlp;

import io.opentelemetry.common.ComponentLoader;
import io.opentelemetry.sdk.common.CompletableResultCode;
import io.opentelemetry.sdk.common.export.GrpcResponse;
import io.opentelemetry.sdk.common.export.GrpcSender;
import io.opentelemetry.sdk.common.export.GrpcSenderProvider;
import io.opentelemetry.sdk.common.export.GrpcStatusCode;
import io.opentelemetry.sdk.common.export.HttpResponse;
import io.opentelemetry.sdk.common.export.HttpSender;
import io.opentelemetry.sdk.common.export.HttpSenderProvider;
import io.opentelemetry.sdk.common.export.MessageWriter;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

final class PartialSuccessComponentLoader implements ComponentLoader {
    private final ComponentLoader delegate;
    private final LogstashSdkMetrics metrics;

    PartialSuccessComponentLoader(LogstashSdkMetrics metrics) {
        this(ComponentLoader.forClassLoader(PartialSuccessComponentLoader.class.getClassLoader()), metrics);
    }

    PartialSuccessComponentLoader(ComponentLoader delegate, LogstashSdkMetrics metrics) {
        this.delegate = delegate;
        this.metrics = metrics;
    }

    @Override
    public <T> Iterable<T> load(Class<T> spiClass) {
        if (spiClass != HttpSenderProvider.class && spiClass != GrpcSenderProvider.class) {
            return delegate.load(spiClass);
        }
        List<T> providers = new ArrayList<>();
        for (T provider : delegate.load(spiClass)) {
            if (provider instanceof HttpSenderProvider http) {
                providers.add(spiClass.cast((HttpSenderProvider) config -> observe(http.createSender(config))));
            } else if (provider instanceof GrpcSenderProvider grpc) {
                providers.add(spiClass.cast((GrpcSenderProvider) config -> observe(grpc.createSender(config))));
            }
        }
        return providers;
    }

    private HttpSender observe(HttpSender sender) {
        return new HttpSender() {
            @Override
            public void send(MessageWriter writer, Consumer<HttpResponse> onResponse, Consumer<Throwable> onError) {
                sender.send(writer, response -> {
                    try {
                        if (response.getStatusCode() >= 200 && response.getStatusCode() < 300) {
                            record(response.getResponseBody());
                        }
                    } catch (RuntimeException failure) {
                        metrics.recordInvalidResponse();
                    } finally {
                        onResponse.accept(response);
                    }
                }, onError);
            }

            @Override
            public CompletableResultCode shutdown() {
                return sender.shutdown();
            }
        };
    }

    private GrpcSender observe(GrpcSender sender) {
        return new GrpcSender() {
            @Override
            public void send(MessageWriter writer, Consumer<GrpcResponse> onResponse, Consumer<Throwable> onError) {
                sender.send(writer, response -> {
                    try {
                        if (response.getStatusCode() == GrpcStatusCode.OK) {
                            record(response.getResponseMessage());
                        }
                    } catch (RuntimeException failure) {
                        metrics.recordInvalidResponse();
                    } finally {
                        onResponse.accept(response);
                    }
                }, onError);
            }

            @Override
            public CompletableResultCode shutdown() {
                return sender.shutdown();
            }
        };
    }

    private void record(byte[] response) {
        OtlpPartialSuccess partial = OtlpPartialSuccess.parse(response);
        metrics.recordPartialSuccess(partial.rejectedLogRecords(), partial.errorMessage());
    }
}
