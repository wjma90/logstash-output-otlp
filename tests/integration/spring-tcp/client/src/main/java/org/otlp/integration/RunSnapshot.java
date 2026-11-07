package org.otlp.integration;

public record RunSnapshot(String runId, RunRequest request, long attempted, long completed,
                          boolean finished, boolean cancelled, double elapsedSeconds,
                          double generationSeconds, double actualRate, long appended,
                          long dropped, long sent, long sendFailures, long pending,
                          long unaccountedAdmissions, long logCallNanosTotal,
                          long logCallNanosMax, int activeProducers, boolean connected) {
}
