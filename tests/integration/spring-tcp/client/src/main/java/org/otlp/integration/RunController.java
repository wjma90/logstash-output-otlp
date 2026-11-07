package org.otlp.integration;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public final class RunController {
    private final RunService runs;

    public RunController(RunService runs) {
        this.runs = runs;
    }

    @GetMapping("/health")
    public Map<String, Object> health() {
        return Map.of("status", "UP", "connected", TcpMetricsListener.CONNECTED.get());
    }

    @PostMapping("/runs")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public RunSnapshot start(@RequestBody RunRequest request) {
        return runs.start(request);
    }

    @GetMapping("/runs/current")
    public RunSnapshot current() {
        return runs.current();
    }

    @PostMapping("/runs/stop")
    public RunSnapshot stop() {
        return runs.stop();
    }

    @ExceptionHandler(IllegalStateException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public Map<String, String> conflict(IllegalStateException error) {
        return Map.of("error", error.getMessage());
    }

    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, String> invalid(IllegalArgumentException error) {
        return Map.of("error", error.getMessage());
    }
}
