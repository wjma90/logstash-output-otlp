package org.otlp.integration;

public record RunRequest(int records, int threads, int payloadBytes, int ratePerSecond,
                         Integer maxDurationSeconds) {
    public RunRequest {
        if (records < 1 || records > 5_000_000) throw new IllegalArgumentException("records must be between 1 and 5000000");
        if (threads < 1 || threads > 64) throw new IllegalArgumentException("threads must be between 1 and 64");
        if (payloadBytes < 1 || payloadBytes > 65536) throw new IllegalArgumentException("payloadBytes must be between 1 and 65536");
        if (ratePerSecond < 0 || ratePerSecond > 1_000_000) throw new IllegalArgumentException("ratePerSecond must be between 0 and 1000000");
        if (maxDurationSeconds == null) maxDurationSeconds = 600;
        if (maxDurationSeconds < 1 || maxDurationSeconds > 1800) throw new IllegalArgumentException("maxDurationSeconds must be between 1 and 1800");
    }
}
