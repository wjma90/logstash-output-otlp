package org.otlp;

import co.elastic.logstash.api.NamespacedMetric;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.metrics.MeterProvider;
import io.opentelemetry.sdk.common.CompletableResultCode;
import io.opentelemetry.sdk.metrics.InstrumentType;
import io.opentelemetry.sdk.metrics.SdkMeterProvider;
import io.opentelemetry.sdk.metrics.data.AggregationTemporality;
import io.opentelemetry.sdk.metrics.data.LongPointData;
import io.opentelemetry.sdk.metrics.data.MetricData;
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
            "otel.sdk.exporter.log.exported", "otel.sdk.exporter.operation.duration");
    private final Logger logger;
    private final String outputId;
    private final int capacity;
    private final NamespacedMetric metrics;
    private final LongSupplier nanoTime;
    private final SdkMeterProvider meterProvider;
    private Long lastWarning;
    private long reportedDrops;
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
            metrics.gauge("sdk_metrics", Map.of());
        }
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
    }

    MeterProvider meterProvider() {
        return meterProvider;
    }

    @Override
    public synchronized CompletableResultCode export(Collection<MetricData> data) {
        if (closed) return CompletableResultCode.ofSuccess();
        long total = 0;
        Map<String, Object> snapshot = new LinkedHashMap<>();
        for (MetricData metric : data) {
            if (!SDK_METRICS.contains(metric.getName())) continue;
            Map<String, Object> points = new LinkedHashMap<>();
            snapshot.put(metric.getName().replace('.', '_'), points);
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
            for (LongPointData point : metric.getLongSumData().getPoints()) {
                Map<String, Object> value = pointAttributes(point, metric.getUnit());
                value.put("value", point.getValue());
                points.put(Integer.toString(points.size()), value);
                if (metric.getName().equals(PROCESSED)
                        && "queue_full".equals(point.getAttributes().get(ERROR_TYPE))) {
                    total += point.getValue();
                }
            }
        }
        if (metrics != null) metrics.gauge("sdk_metrics", snapshot);
        long now = nanoTime.getAsLong();
        if (total > reportedDrops && (lastWarning == null || now - lastWarning >= WARNING_INTERVAL_NANOS)) {
            logger.warn("OTLP export queue full: output_id={} max_queue_size={} dropped_records={} total_dropped_records={}",
                    outputId, capacity, total - reportedDrops, total);
            reportedDrops = total;
            lastWarning = now;
        }
        return CompletableResultCode.ofSuccess();
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
        meterProvider.close();
    }

    private static Map<String, Object> pointAttributes(PointData point, String unit) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("unit", unit);
        value.put("error_type", "");
        point.getAttributes().forEach((name, attribute) -> value.put(name.getKey().replace('.', '_'), attribute));
        return value;
    }
}
