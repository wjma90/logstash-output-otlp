package org.otlp.integration;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.LoggingEvent;
import ch.qos.logback.core.AppenderBase;
import io.opentelemetry.sdk.metrics.SdkMeterProvider;
import io.opentelemetry.sdk.metrics.data.MetricData;
import io.opentelemetry.sdk.testing.exporter.InMemoryMetricReader;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class ClientControlTest {
    private InMemoryMetricReader reader;
    private SdkMeterProvider provider;

    @BeforeEach
    void createSdk() {
        reader = InMemoryMetricReader.create();
        provider = SdkMeterProvider.builder().registerMetricReader(reader).build();
    }

    @AfterEach
    void clearRun() {
        TcpMetricsListener.CURRENT.set(null);
        provider.close();
    }

    @Test
    void distinguishesAppenderAdmissionFromTcpDeliveryAndIgnoresOtherRuns() {
        try (ClientMetrics metrics = new ClientMetrics(provider.get("test"), 8192)) {
            Collection<MetricData> before = reader.collectAllMetrics();
            RunState run = new RunState(new RunRequest(3, 1, 128, 0, 10));
            TcpMetricsListener.CURRENT.set(run);
            TcpMetricsListener listener = new TcpMetricsListener();
            LoggingEvent accepted = event(run.id);
            listener.eventAppended(null, accepted, 1);
            listener.eventAppendFailed(null, event(run.id), new IllegalStateException("buffer full"));
            listener.eventSent(null, null, event("another-run"), 1);
            assertEquals(1, run.appended.sum());
            assertEquals(1, run.dropped.sum());
            assertEquals(1, run.pending());
            assertEquals(0, run.sent.sum());
            Collection<MetricData> queued = reader.collectAllMetrics();
            assertEquals(1, gauge(queued, "spring_tcp.pending.events"));
            assertEquals(8192, gauge(queued, "spring_tcp.buffer.capacity"));
            listener.eventSent(null, null, accepted, 1);
            assertEquals(0, run.pending());
            assertEquals(1, run.sent.sum());
            LoggingEvent failedSend = event(run.id);
            listener.eventAppended(null, failedSend, 1);
            listener.eventSendFailure(null, failedSend, new IllegalStateException("encoding failure"));
            assertEquals(0, run.pending());
            assertEquals(1, run.sendFailures.sum());
            Collection<MetricData> after = reader.collectAllMetrics();
            assertEquals(2, counter(after, "spring_tcp.logs.appended") - counter(before, "spring_tcp.logs.appended"));
            assertEquals(1, counter(after, "spring_tcp.logs.dropped") - counter(before, "spring_tcp.logs.dropped"));
            assertEquals(1, counter(after, "spring_tcp.logs.sent") - counter(before, "spring_tcp.logs.sent"));
            assertEquals(1, counter(after, "spring_tcp.send.failures") - counter(before, "spring_tcp.send.failures"));
            assertEquals(0, gauge(after, "spring_tcp.pending.events"));
            assertTrue(metric(after, "spring_tcp.logs.appended").getLongSumData().isMonotonic());
            assertTrue(after.stream().flatMap(data -> data.getData().getPoints().stream())
                    .allMatch(point -> point.getAttributes().isEmpty()));
        }
    }

    @Test
    void cancellationInterruptsBlockedProducersAndReleasesTheExecutor() throws Exception {
        Logger logger = (Logger) LoggerFactory.getLogger("load");
        CountDownLatch entered = new CountDownLatch(1);
        AppenderBase<ILoggingEvent> appender = new AppenderBase<>() {
            @Override
            protected void append(ILoggingEvent event) {
                entered.countDown();
                try {
                    new CountDownLatch(1).await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        };
        Level previous = logger.getLevel();
        boolean additive = logger.isAdditive();
        logger.setLevel(Level.INFO);
        logger.setAdditive(false);
        appender.start();
        logger.addAppender(appender);
        try {
            RunService service = new RunService(provider.get("test"), 8192);
            try {
                service.start(new RunRequest(100, 1, 128, 0, 10));
                assertTrue(entered.await(2, TimeUnit.SECONDS));
                Collection<MetricData> blocked = reader.collectAllMetrics();
                assertEquals(1, gauge(blocked, "spring_tcp.logging.calls.inflight"));
                assertEquals(1, gauge(blocked, "spring_tcp.active.producers"));
                assertEquals(1, gauge(blocked, "spring_tcp.run.active"));
                assertThrows(IllegalStateException.class,
                        () -> service.start(new RunRequest(1, 1, 1, 0, 10)));
                service.stop();
                RunState state = TcpMetricsListener.CURRENT.get();
                assertTrue(state.executor.awaitTermination(2, TimeUnit.SECONDS));
                assertTrue(service.current().cancelled());
                assertTrue(service.current().finished());
                assertEquals(0, service.current().activeProducers());
                assertEquals(1, service.current().unaccountedAdmissions());
                Collection<MetricData> stopped = reader.collectAllMetrics();
                assertEquals(0, gauge(stopped, "spring_tcp.logging.calls.inflight"));
                assertEquals(0, gauge(stopped, "spring_tcp.run.active"));
                assertEquals(0, gauge(stopped, "spring_tcp.active.producers"));
                var duration = metric(stopped, "spring_tcp.log.call.duration");
                var point = duration.getHistogramData().getPoints().iterator().next();
                assertEquals("s", duration.getUnit());
                assertEquals(1, point.getCount());
                assertEquals(service.current().logCallNanosTotal() / 1_000_000_000.0, point.getSum());
                assertEquals(60.0, point.getBoundaries().getLast());
                assertEquals(service.current().logCallNanosMax() / 1_000_000_000.0,
                        metric(stopped, "spring_tcp.log.call.max").getDoubleGaugeData()
                                .getPoints().iterator().next().getValue());
            } finally {
                service.close();
            }
        } finally {
            logger.detachAppender(appender);
            appender.stop();
            logger.setLevel(previous);
            logger.setAdditive(additive);
        }
    }

    @Test
    void maximumResetsWithNextRunAndClosingCallbacksKeepsTheSdkAvailable() {
        ClientMetrics metrics = new ClientMetrics(provider.get("test"), 4096);
        try {
            RunState first = new RunState(new RunRequest(1, 1, 128, 0, 10));
            first.maxCallNanos.set(TimeUnit.SECONDS.toNanos(15));
            TcpMetricsListener.CURRENT.set(first);
            assertEquals(15.0, metric(reader.collectAllMetrics(), "spring_tcp.log.call.max")
                    .getDoubleGaugeData().getPoints().iterator().next().getValue());
            TcpMetricsListener.CURRENT.set(new RunState(new RunRequest(1, 1, 128, 0, 10)));
            assertEquals(0.0, metric(reader.collectAllMetrics(), "spring_tcp.log.call.max")
                    .getDoubleGaugeData().getPoints().iterator().next().getValue());
        } finally {
            metrics.close();
        }
        provider.get("test").counterBuilder("sdk.available").build().add(1);
        Collection<MetricData> afterClose = reader.collectAllMetrics();
        assertEquals(1, counter(afterClose, "sdk.available"));
        assertTrue(afterClose.stream().noneMatch(data -> data.getName().startsWith("spring_tcp.")));
    }

    @Test
    void rejectsUnboundedOrInvalidRequests() {
        assertThrows(IllegalArgumentException.class, () -> new RunRequest(5_000_001, 1, 1, 1, 10));
        assertThrows(IllegalArgumentException.class, () -> new RunRequest(1, 65, 1, 1, 10));
        assertThrows(IllegalArgumentException.class, () -> new RunRequest(1, 1, 65537, 1, 10));
        assertThrows(IllegalArgumentException.class, () -> new RunRequest(1, 1, 1, -1, 10));
        assertThrows(IllegalArgumentException.class, () -> new RunRequest(1, 1, 1, 1, 0));
    }

    private static LoggingEvent event(String run) {
        LoggingEvent event = new LoggingEvent();
        event.setMDCPropertyMap(Map.of("run_id", run));
        return event;
    }

    private static MetricData metric(Collection<MetricData> metrics, String name) {
        return metrics.stream().filter(metric -> metric.getName().equals(name)).findFirst().orElseThrow();
    }

    private static long counter(Collection<MetricData> metrics, String name) {
        return metric(metrics, name).getLongSumData().getPoints().iterator().next().getValue();
    }

    private static long gauge(Collection<MetricData> metrics, String name) {
        return metric(metrics, name).getLongGaugeData().getPoints().iterator().next().getValue();
    }
}
