package org.otlp.integration;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.Appender;
import net.logstash.logback.appender.listener.TcpAppenderListener;

import java.net.Socket;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.LongAdder;

public final class TcpMetricsListener implements TcpAppenderListener<ILoggingEvent> {
    static final AtomicReference<RunState> CURRENT = new AtomicReference<>();
    static final AtomicBoolean CONNECTED = new AtomicBoolean();
    static final LongAdder ATTEMPTED = new LongAdder();
    static final LongAdder APPENDED = new LongAdder();
    static final LongAdder DROPPED = new LongAdder();
    static final LongAdder SENT = new LongAdder();
    static final LongAdder SEND_FAILURES = new LongAdder();

    private RunState state(ILoggingEvent event) {
        RunState current = CURRENT.get();
        return current != null && current.id.equals(event.getMDCPropertyMap().get("run_id")) ? current : null;
    }

    @Override
    public void eventAppended(Appender<ILoggingEvent> appender, ILoggingEvent event, long durationInNanos) {
        RunState run = state(event);
        if (run != null) {
            run.appended.increment();
            APPENDED.increment();
        }
    }

    @Override
    public void eventAppendFailed(Appender<ILoggingEvent> appender, ILoggingEvent event, Throwable reason) {
        RunState run = state(event);
        if (run != null) {
            run.dropped.increment();
            DROPPED.increment();
        }
    }

    @Override
    public void eventSent(Appender<ILoggingEvent> appender, Socket socket, ILoggingEvent event, long durationInNanos) {
        RunState run = state(event);
        if (run != null) {
            run.sent.increment();
            SENT.increment();
        }
    }

    @Override
    public void eventSendFailure(Appender<ILoggingEvent> appender, ILoggingEvent event, Throwable reason) {
        RunState run = state(event);
        if (run != null) {
            run.sendFailures.increment();
            SEND_FAILURES.increment();
        }
    }

    @Override
    public void connectionOpened(Appender<ILoggingEvent> appender, Socket socket) {
        CONNECTED.set(true);
    }

    @Override
    public void connectionClosed(Appender<ILoggingEvent> appender, Socket socket) {
        CONNECTED.set(false);
    }
}
