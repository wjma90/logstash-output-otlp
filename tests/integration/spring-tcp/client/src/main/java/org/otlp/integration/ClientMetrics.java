package org.otlp.integration;

import io.opentelemetry.api.metrics.BatchCallback;
import io.opentelemetry.api.metrics.DoubleHistogram;
import io.opentelemetry.api.metrics.Meter;

import java.util.List;

final class ClientMetrics implements AutoCloseable {
    private final DoubleHistogram callDuration;
    private final BatchCallback callback;

    ClientMetrics(Meter meter, int bufferCapacity) {
        var attempted = meter.counterBuilder("spring_tcp.logs.attempted")
                .setDescription("Logging calls attempted since process start").buildObserver();
        var appended = meter.counterBuilder("spring_tcp.logs.appended")
                .setDescription("Events admitted to the TCP appender since process start").buildObserver();
        var dropped = meter.counterBuilder("spring_tcp.logs.dropped")
                .setDescription("Events rejected by the TCP appender since process start").buildObserver();
        var sent = meter.counterBuilder("spring_tcp.logs.sent")
                .setDescription("Events written to the socket, without downstream acknowledgement").buildObserver();
        var failures = meter.counterBuilder("spring_tcp.send.failures")
                .setDescription("Terminal appender send failures since process start").buildObserver();
        var active = meter.gaugeBuilder("spring_tcp.active.producers").ofLongs()
                .setDescription("Active log producer tasks, including pacing and logging waits").buildObserver();
        var pending = meter.gaugeBuilder("spring_tcp.pending.events").ofLongs()
                .setDescription("Estimated admitted events not yet sent or failed in the current run").buildObserver();
        var connected = meter.gaugeBuilder("spring_tcp.connected").ofLongs()
                .setDescription("One when the appender socket is connected, zero otherwise").buildObserver();
        var inflight = meter.gaugeBuilder("spring_tcp.logging.calls.inflight").ofLongs()
                .setDescription("Logger calls currently executing, including calls blocked by the appender").buildObserver();
        var capacity = meter.gaugeBuilder("spring_tcp.buffer.capacity").ofLongs()
                .setDescription("Configured TCP appender ring buffer capacity in events").buildObserver();
        var runActive = meter.gaugeBuilder("spring_tcp.run.active").ofLongs()
                .setDescription("One while the current run is generating logs, zero after generation finishes").buildObserver();
        var maximum = meter.gaugeBuilder("spring_tcp.log.call.max").setUnit("s")
                .setDescription("Maximum completed logger call duration in the current run, reset on the next run")
                .buildObserver();
        callDuration = meter.histogramBuilder("spring_tcp.log.call.duration").setUnit("s")
                .setDescription("Duration of completed logger calls, including appender blocking")
                .setExplicitBucketBoundariesAdvice(List.of(0.000001, 0.00001, 0.0001, 0.001,
                        0.01, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0)).build();
        callback = meter.batchCallback(() -> {
            RunState state = TcpMetricsListener.CURRENT.get();
            attempted.record(TcpMetricsListener.ATTEMPTED.sum());
            appended.record(TcpMetricsListener.APPENDED.sum());
            dropped.record(TcpMetricsListener.DROPPED.sum());
            sent.record(TcpMetricsListener.SENT.sum());
            failures.record(TcpMetricsListener.SEND_FAILURES.sum());
            active.record(state == null ? 0 : state.active.get());
            pending.record(state == null ? 0 : state.pending());
            connected.record(TcpMetricsListener.CONNECTED.get() ? 1 : 0);
            inflight.record(state == null ? 0 : state.loggingCallsInflight.get());
            capacity.record(bufferCapacity);
            runActive.record(state != null && state.generationEnded == 0 ? 1 : 0);
            maximum.record(state == null ? 0 : state.maxCallNanos.get() / 1_000_000_000.0);
        }, attempted, appended, dropped, sent, failures, active, pending, connected, inflight,
                capacity, runActive, maximum);
    }

    void recordCall(long nanos) {
        callDuration.record(nanos / 1_000_000_000.0);
    }

    @Override
    public void close() {
        callback.close();
    }
}
