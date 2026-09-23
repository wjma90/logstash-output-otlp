package org.otlp;

import io.opentelemetry.sdk.common.CompletableResultCode;
import io.opentelemetry.sdk.logs.data.LogRecordData;
import io.opentelemetry.sdk.logs.export.LogRecordExporter;
import org.apache.logging.log4j.Logger;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;

final class DiagnosticLogRecordExporter implements LogRecordExporter {
    private static final long FAILURE_LOG_INTERVAL_NANOS = TimeUnit.SECONDS.toNanos(30);
    private final LogRecordExporter delegate;
    private final Logger logger;
    private final String outputId;
    private final String endpoint;
    private final LongSupplier nanoTime;
    private final AtomicLong failedBatches = new AtomicLong();
    private final AtomicLong failedRecords = new AtomicLong();
    private final AtomicLong exportedRecords = new AtomicLong();
    private final AtomicLong suppressedFailures = new AtomicLong();
    private final AtomicReference<Long> lastFailureLog = new AtomicReference<>();

    DiagnosticLogRecordExporter(LogRecordExporter delegate, Logger logger, String outputId, URI endpoint) {
        this(delegate, logger, outputId, endpoint, System::nanoTime);
    }

    DiagnosticLogRecordExporter(LogRecordExporter delegate, Logger logger, String outputId,
                                URI endpoint, LongSupplier nanoTime) {
        this.delegate = Objects.requireNonNull(delegate);
        this.logger = Objects.requireNonNull(logger);
        this.outputId = Objects.requireNonNull(outputId);
        this.endpoint = diagnosticEndpoint(endpoint);
        this.nanoTime = Objects.requireNonNull(nanoTime);
    }

    @Override
    public CompletableResultCode export(Collection<LogRecordData> logs) {
        final int recordCount = logs.size();
        CompletableResultCode result;
        try {
            result = Objects.requireNonNull(delegate.export(logs), "Exporter returned no result");
        } catch (RuntimeException failure) {
            result = CompletableResultCode.ofExceptionalFailure(failure);
        }
        observe(result, recordCount);
        return result;
    }

    private void observe(CompletableResultCode result, int recordCount) {
        result.whenComplete(() -> {
            if (result.isSuccess()) {
                exportedRecords.addAndGet(recordCount);
            } else {
                failedBatches.incrementAndGet();
                failedRecords.addAndGet(recordCount);
                logFailure(recordCount, result.getFailureThrowable());
            }
        });
    }

    private void logFailure(int recordCount, Throwable failure) {
        long now = nanoTime.getAsLong();
        Long previous = lastFailureLog.get();
        if ((previous == null || now - previous >= FAILURE_LOG_INTERVAL_NANOS)
                && lastFailureLog.compareAndSet(previous, now)) {
            long suppressed = suppressedFailures.getAndSet(0);
            if (failure == null) {
                logger.error("OTLP export failed: output_id={} endpoint={} records={} suppressed_failures={} cause=unavailable",
                        outputId, endpoint, recordCount, suppressed);
            } else {
                logger.error("OTLP export failed: output_id={} endpoint={} records={} suppressed_failures={}",
                        outputId, endpoint, recordCount, suppressed, failure);
            }
        } else {
            suppressedFailures.incrementAndGet();
        }
    }

    private static String diagnosticEndpoint(URI endpoint) {
        Objects.requireNonNull(endpoint);
        try {
            return new URI(endpoint.getScheme(), null, endpoint.getHost(), endpoint.getPort(),
                    endpoint.getPath(), null, null).toString();
        } catch (URISyntaxException invalidEndpoint) {
            return "<invalid endpoint>";
        }
    }

    @Override
    public CompletableResultCode flush() {
        try {
            return Objects.requireNonNull(delegate.flush(), "Exporter returned no flush result");
        } catch (RuntimeException failure) {
            return CompletableResultCode.ofExceptionalFailure(failure);
        }
    }

    @Override
    public CompletableResultCode shutdown() {
        try {
            return Objects.requireNonNull(delegate.shutdown(), "Exporter returned no shutdown result");
        } catch (RuntimeException failure) {
            return CompletableResultCode.ofExceptionalFailure(failure);
        }
    }

    long getFailedBatchesCount() { return failedBatches.get(); }
    long getFailedRecordsCount() { return failedRecords.get(); }
    long getExportedRecordsCount() { return exportedRecords.get(); }
}
