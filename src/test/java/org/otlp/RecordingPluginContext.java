package org.otlp;

import co.elastic.logstash.api.Context;
import co.elastic.logstash.api.CounterMetric;
import co.elastic.logstash.api.DeadLetterQueueWriter;
import co.elastic.logstash.api.DeprecationLogger;
import co.elastic.logstash.api.EventFactory;
import co.elastic.logstash.api.Metric;
import co.elastic.logstash.api.NamespacedMetric;
import co.elastic.logstash.api.Plugin;
import co.elastic.logstash.api.TimerMetric;
import org.apache.logging.log4j.Logger;

import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;

final class RecordingPluginContext implements Context, NamespacedMetric {
    private final String id;
    private final Logger logger;
    private volatile Map<?, ?> snapshot = Map.of();

    RecordingPluginContext(String id, Logger logger) {
        this.id = id;
        this.logger = logger;
    }

    @Override
    public synchronized void gauge(String name, Object value) {
        if (name.equals("sdk_metrics")) snapshot = (Map<?, ?>) value;
        notifyAll();
    }

    long value(String name, String errorType) {
        Object metric = snapshot.get(name.replace('.', '_'));
        if (!(metric instanceof Map<?, ?> points)) return 0;
        long total = 0;
        for (Object entry : points.values()) {
            Map<?, ?> point = (Map<?, ?>) entry;
            if (errorType.equals(point.get("error_type"))) {
                total += ((Number) point.get("value")).longValue();
            }
        }
        return total;
    }

    String component(String name) {
        Map<?, ?> points = (Map<?, ?>) snapshot.get(name.replace('.', '_'));
        Map<?, ?> point = (Map<?, ?>) points.values().iterator().next();
        return String.valueOf(point.get("otel_component_name"));
    }

    synchronized void awaitValue(String name, String errorType, long expected) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
        long remaining;
        while (value(name, errorType) != expected && (remaining = deadline - System.nanoTime()) > 0) {
            TimeUnit.NANOSECONDS.timedWait(this, remaining);
        }
        assertEquals(expected, value(name, errorType), name + " error.type=" + errorType);
    }

    @Override
    public NamespacedMetric getMetric(Plugin plugin) { return this; }

    @Override
    public Logger getLogger(Plugin plugin) { return logger; }

    @Override
    public DeadLetterQueueWriter getDlqWriter() { return null; }

    @Override
    public DeprecationLogger getDeprecationLogger(Plugin plugin) { return null; }

    @Override
    public EventFactory getEventFactory() { return null; }

    @Override
    public String[] namespaceName() { return new String[]{"outputs", id}; }

    @Override
    public CounterMetric counter(String name) { throw new UnsupportedOperationException(); }

    @Override
    public TimerMetric timer(String name) { throw new UnsupportedOperationException(); }

    @Override
    public void increment(String name) { throw new UnsupportedOperationException(); }

    @Override
    public void increment(String name, int delta) { throw new UnsupportedOperationException(); }

    @Override
    public <T> T time(String name, Supplier<T> action) { throw new UnsupportedOperationException(); }

    @Override
    public void reportTime(String name, long duration) { throw new UnsupportedOperationException(); }

    @Override
    public Metric root() { throw new UnsupportedOperationException(); }

    @Override
    public NamespacedMetric namespace(String... names) { throw new UnsupportedOperationException(); }
}
