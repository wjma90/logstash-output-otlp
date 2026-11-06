package org.otlp;

import co.elastic.logstash.api.NamespacedMetric;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.metrics.MeterProvider;
import io.opentelemetry.sdk.common.CompletableResultCode;
import io.opentelemetry.sdk.metrics.InstrumentType;
import io.opentelemetry.sdk.metrics.SdkMeterProvider;
import io.opentelemetry.sdk.metrics.data.AggregationTemporality;
import io.opentelemetry.sdk.metrics.data.LongPointData;
import io.opentelemetry.sdk.metrics.data.DoublePointData;
import io.opentelemetry.sdk.metrics.data.MetricData;
import io.opentelemetry.sdk.metrics.data.MetricDataType;
import io.opentelemetry.sdk.metrics.data.PointData;
import io.opentelemetry.sdk.metrics.export.MetricExporter;
import io.opentelemetry.sdk.metrics.export.PeriodicMetricReader;
import org.apache.logging.log4j.Logger;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

final class LogstashSdkMetrics implements MetricExporter {
    private static final long WARNING_INTERVAL_NANOS = TimeUnit.SECONDS.toNanos(30);
    private static final AttributeKey<String> ERROR_TYPE = AttributeKey.stringKey("error.type");
    private static final String QUEUE_SIZE = "otel.sdk.processor.log.queue.size";
    private static final String PROCESSED = "otel.sdk.processor.log.processed";
    private static final Set<String> SDK_METRICS = Set.of(QUEUE_SIZE, PROCESSED,
            "otel.sdk.processor.log.queue.capacity", "otel.sdk.exporter.log.inflight",
            "otel.sdk.exporter.log.exported", "otel.sdk.exporter.operation.duration",
            "otlp.processor.log.queue.blocked.producers", "otlp.processor.log.queue.blocked.duration",
            "otlp.processor.log.queue.peak.size");
    private final Logger logger;
    private final String outputId;
    private final int capacity;
    private final NamespacedMetric metrics;
    private final LongSupplier nanoTime;
    private SdkMeterProvider meterProvider;
    private Long lastWarning;
    private long reportedDrops;
    private long rejectedRecords;
    private long suppressedPartialResponses;
    private Long lastPartialWarning;
    private Long lastInvalidResponseWarning;
    private boolean closed;

    LogstashSdkMetrics(Logger logger, String outputId, int capacity, NamespacedMetric metrics) {
        this(logger, outputId, capacity, metrics, System::nanoTime);
    }

    LogstashSdkMetrics(Logger logger, String outputId, int capacity, NamespacedMetric metrics, LongSupplier nanoTime) {
        this.logger = logger;
        this.outputId = outputId;
        this.capacity = capacity;
        this.metrics = metrics;
        this.nanoTime = nanoTime;
        if (metrics != null) {
            metrics.gauge("sdk_metrics", Map.of(
                    "otel_sdk_processor_log_queue_size", Map.of("0", initialQueuePoint(0)),
                    "otel_sdk_processor_log_queue_capacity", Map.of("0", initialQueuePoint(capacity)),
                    "otlp_processor_log_queue_peak_size", Map.of("0", initialQueuePoint(0)),
                    "otlp_processor_log_queue_blocked_producers", Map.of("0", initialPoint(0, "{thread}")),
                    "otlp_processor_log_queue_blocked_duration", Map.of("0", initialPoint(0, "s")),
                    "otlp_exporter_log_rejected", rejectedPoint()));
        }
    }

    synchronized MeterProvider meterProvider() {
        if (closed) throw new IllegalStateException("OTLP SDK metrics are closed");
        if (meterProvider != null) return meterProvider;
        var executor = Executors.newSingleThreadScheduledExecutor(action -> {
            Thread thread = new Thread(action, "otlp-sdk-metrics-" + outputId);
            thread.setDaemon(true);
            return thread;
        });
        PeriodicMetricReader reader = PeriodicMetricReader.builder(this)
                .setInterval(1, TimeUnit.SECONDS).setExecutor(executor).build();
        try {
            meterProvider = SdkMeterProvider.builder().registerMetricReader(reader).build();
        } catch (RuntimeException | Error failure) {
            reader.shutdown();
            throw failure;
        }
        return meterProvider;
    }

    @Override
    public synchronized CompletableResultCode export(Collection<MetricData> data) {
        if (closed) return CompletableResultCode.ofSuccess();
        long total = 0;
        Map<String, Map<String, Object>> snapshot = new LinkedHashMap<>();
        for (MetricData metric : data) {
            if (!SDK_METRICS.contains(metric.getName())) continue;
            Map<String, Object> points = snapshot.computeIfAbsent(
                    metric.getName().replace('.', '_'), key -> new LinkedHashMap<>());
            if (metric.getName().equals("otel.sdk.exporter.operation.duration")) {
                metric.getHistogramData().getPoints().forEach(point -> {
                    Map<String, Object> value = pointAttributes(point, metric.getUnit());
                    value.put("count", point.getCount());
                    value.put("sum", point.getSum());
                    value.put("bounds", point.getBoundaries());
                    value.put("bucket_counts", point.getCounts());
                    points.put(Integer.toString(points.size()), value);
                });
                continue;
            }
            for (DoublePointData point : metric.getDoubleSumData().getPoints()) {
                Map<String, Object> value = pointAttributes(point, metric.getUnit());
                value.put("value", point.getValue());
                points.put(Integer.toString(points.size()), value);
            }
            Collection<LongPointData> longPoints = metric.getType() == MetricDataType.LONG_GAUGE
                    ? metric.getLongGaugeData().getPoints() : metric.getLongSumData().getPoints();
            for (LongPointData point : longPoints) {
                Map<String, Object> value = pointAttributes(point, metric.getUnit());
                value.put("value", point.getValue());
                points.put(Integer.toString(points.size()), value);
                if (metric.getName().equals(PROCESSED)
                        && "queue_full".equals(point.getAttributes().get(ERROR_TYPE))) {
                    total += point.getValue();
                }
            }
        }
        snapshot.put("otlp_exporter_log_rejected", rejectedPoint());
        if (metrics != null) metrics.gauge("sdk_metrics", snapshot);
        long now = nanoTime.getAsLong();
        if (total > reportedDrops && (lastWarning == null || now - lastWarning >= WARNING_INTERVAL_NANOS)) {
            logger.warn("OTLP export queue full: output_id={} queue_size={} dropped_records={} total_dropped_records={}",
                    outputId, capacity, total - reportedDrops, total);
            reportedDrops = total;
            lastWarning = now;
        }
        return CompletableResultCode.ofSuccess();
    }

    synchronized void recordPartialSuccess(long rejected, String message) {
        if (closed || (rejected == 0 && message.isEmpty())) return;
        rejectedRecords = rejected > Long.MAX_VALUE - rejectedRecords ? Long.MAX_VALUE : rejectedRecords + rejected;
        long now = nanoTime.getAsLong();
        if (lastPartialWarning == null || now - lastPartialWarning >= WARNING_INTERVAL_NANOS) {
            String reason = message.substring(0, Math.min(message.length(), 1024))
                    .replace('\n', ' ').replace('\r', ' ').replace('\t', ' ');
            logger.warn("OTLP partial success: output_id={} rejected_records={} total_rejected_records={} suppressed_responses={} error_message={}",
                    outputId, rejected, rejectedRecords, suppressedPartialResponses, reason);
            lastPartialWarning = now;
            suppressedPartialResponses = 0;
        } else {
            suppressedPartialResponses++;
        }
    }

    synchronized void recordInvalidResponse() {
        if (closed) return;
        long now = nanoTime.getAsLong();
        if (lastInvalidResponseWarning == null || now - lastInvalidResponseWarning >= WARNING_INTERVAL_NANOS) {
            logger.warn("OTLP response diagnostics failed: output_id={} reason=invalid_response partial_success could not be read",
                    outputId);
            lastInvalidResponseWarning = now;
        }
    }

    private Map<String, Object> rejectedPoint() {
        return Map.of("0", Map.of("unit", "{log_record}", "error_type", "partial_success", "value", rejectedRecords));
    }

    @Override
    public AggregationTemporality getAggregationTemporality(InstrumentType instrumentType) {
        return AggregationTemporality.CUMULATIVE;
    }

    @Override
    public CompletableResultCode flush() {
        return CompletableResultCode.ofSuccess();
    }

    @Override
    public synchronized CompletableResultCode shutdown() {
        closed = true;
        return CompletableResultCode.ofSuccess();
    }

    @Override
    public void close() {
        SdkMeterProvider provider;
        synchronized (this) {
            closed = true;
            provider = meterProvider;
            meterProvider = null;
        }
        if (provider != null) provider.close();
    }

    private Map<String, Object> initialQueuePoint(long value) {
        return initialPoint(value, "{log_record}");
    }

    private Map<String, Object> initialPoint(long value, String unit) {
        return Map.of("unit", unit, "error_type", "",
                "otel_component_type", "shared_queue_log_processor",
                "otel_component_name", "shared_queue_log_processor/" + outputId,
                "value", value);
    }

    private static Map<String, Object> pointAttributes(PointData point, String unit) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("unit", unit);
        value.put("error_type", "");
        point.getAttributes().forEach((name, attribute) -> value.put(name.getKey().replace('.', '_'), attribute));
        return value;
    }
}
