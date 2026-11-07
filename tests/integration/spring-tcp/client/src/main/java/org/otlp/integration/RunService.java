package org.otlp.integration;

import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.metrics.Meter;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;

@Service
public final class RunService {
    private static final Logger LOAD = LoggerFactory.getLogger("load");
    private final ScheduledThreadPoolExecutor deadlines;
    private final ClientMetrics metrics;
    private boolean closed;

    @Autowired
    public RunService(@Value("${RING_BUFFER_SIZE:8192}") int bufferCapacity) {
        this(GlobalOpenTelemetry.getMeter("org.otlp.integration.spring-tcp"), bufferCapacity);
    }

    RunService(Meter meter, int bufferCapacity) {
        deadlines = new ScheduledThreadPoolExecutor(1,
                Thread.ofPlatform().name("load-deadline").daemon(true).factory());
        deadlines.setRemoveOnCancelPolicy(true);
        metrics = new ClientMetrics(meter, bufferCapacity);
    }

    public synchronized RunSnapshot start(RunRequest request) {
        RunState previous = TcpMetricsListener.CURRENT.get();
        if (closed) throw new IllegalStateException("Client is shutting down");
        if (previous != null && (previous.generationEnded == 0 || previous.pending() != 0)) {
            throw new IllegalStateException("The previous run must finish and its appender must drain first");
        }
        RunState state = new RunState(request);
        String padding = "x".repeat(Math.max(0, request.payloadBytes() - 15));
        CountDownLatch gate = new CountDownLatch(1);
        state.executor = Executors.newFixedThreadPool(request.threads(),
                Thread.ofPlatform().name("load-producer-", 0).factory());
        TcpMetricsListener.CURRENT.set(state);
        state.deadline = deadlines.schedule(() -> stop(state), request.maxDurationSeconds(), TimeUnit.SECONDS);
        for (int worker = 0; worker < request.threads(); worker++) {
            int index = worker;
            state.executor.execute(() -> produce(state, index, padding, gate));
        }
        gate.countDown();
        return state.snapshot();
    }

    private void produce(RunState state, int worker, String padding, CountDownLatch gate) {
        try {
            gate.await();
            MDC.put("run_id", state.id);
            long next = state.started;
            long spacing = state.request.ratePerSecond() == 0 ? 0
                    : 1_000_000_000L * state.request.threads() / state.request.ratePerSecond();
            if (spacing != 0) next += spacing * worker / state.request.threads();
            for (int record = worker; record < state.request.records(); record += state.request.threads()) {
                while (spacing != 0 && next > System.nanoTime() && !state.cancelled.get() && !Thread.currentThread().isInterrupted()) {
                    LockSupport.parkNanos(next - System.nanoTime());
                }
                if (state.cancelled.get() || Thread.currentThread().isInterrupted()) break;
                MDC.put("record_id", Integer.toString(record));
                String message = "id=" + (10_000_000_000L + record) + " " + padding;
                if (state.request.payloadBytes() < 15) message = message.substring(0, state.request.payloadBytes());
                state.attempted.increment();
                TcpMetricsListener.ATTEMPTED.increment();
                state.loggingCallsInflight.incrementAndGet();
                long started = System.nanoTime();
                try {
                    LOAD.info(message);
                } finally {
                    long elapsed = System.nanoTime() - started;
                    state.loggingCallsInflight.decrementAndGet();
                    state.callNanos.add(elapsed);
                    state.maxCallNanos.accumulateAndGet(elapsed, Math::max);
                    metrics.recordCall(elapsed);
                    state.completed.increment();
                }
                if (spacing != 0) next = Math.max(next + spacing, System.nanoTime());
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            MDC.clear();
            if (state.active.decrementAndGet() == 0) {
                state.generationEnded = System.nanoTime();
                state.deadline.cancel(false);
                state.executor.shutdown();
            }
        }
    }

    public RunSnapshot current() {
        RunState state = TcpMetricsListener.CURRENT.get();
        return state == null ? null : state.snapshot();
    }

    public synchronized RunSnapshot stop() {
        RunState state = TcpMetricsListener.CURRENT.get();
        if (state != null) stop(state);
        return state == null ? null : state.snapshot();
    }

    private void stop(RunState state) {
        if (state.generationEnded == 0) {
            state.cancelled.set(true);
            state.executor.shutdownNow();
        }
    }

    @PreDestroy
    public synchronized void close() {
        closed = true;
        RunState state = TcpMetricsListener.CURRENT.get();
        if (state != null) stop(state);
        deadlines.shutdownNow();
        if (state != null) {
            try {
                if (!state.executor.awaitTermination(10, TimeUnit.SECONDS)) {
                    LoggerFactory.getLogger(RunService.class).warn("Load producers did not stop within 10 seconds");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        metrics.close();
    }
}
