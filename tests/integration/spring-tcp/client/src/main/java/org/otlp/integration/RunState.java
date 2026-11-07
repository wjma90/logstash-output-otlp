package org.otlp.integration;

import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;

final class RunState {
    final String id = UUID.randomUUID().toString();
    final RunRequest request;
    final long started = System.nanoTime();
    final LongAdder attempted = new LongAdder();
    final LongAdder completed = new LongAdder();
    final LongAdder appended = new LongAdder();
    final LongAdder dropped = new LongAdder();
    final LongAdder sent = new LongAdder();
    final LongAdder sendFailures = new LongAdder();
    final LongAdder callNanos = new LongAdder();
    final AtomicLong maxCallNanos = new AtomicLong();
    final AtomicInteger loggingCallsInflight = new AtomicInteger();
    final AtomicInteger active;
    final AtomicBoolean cancelled = new AtomicBoolean();
    volatile long generationEnded;
    volatile ExecutorService executor;
    volatile ScheduledFuture<?> deadline;

    RunState(RunRequest request) {
        this.request = request;
        active = new AtomicInteger(request.threads());
    }

    long pending() {
        return Math.max(0, appended.sum() - sent.sum() - sendFailures.sum());
    }

    RunSnapshot snapshot() {
        long end = generationEnded;
        double elapsed = (System.nanoTime() - started) / 1_000_000_000.0;
        double generation = ((end == 0 ? System.nanoTime() : end) - started) / 1_000_000_000.0;
        long calls = attempted.sum();
        long accepted = appended.sum();
        long rejected = dropped.sum();
        return new RunSnapshot(id, request, calls, completed.sum(), end != 0,
                cancelled.get(), elapsed, generation, completed.sum() / Math.max(generation, 0.000001),
                accepted, rejected, sent.sum(), sendFailures.sum(), pending(),
                Math.max(0, calls - accepted - rejected), callNanos.sum(), maxCallNanos.get(),
                active.get(), TcpMetricsListener.CONNECTED.get());
    }
}
