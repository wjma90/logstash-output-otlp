package org.otlp;

import io.opentelemetry.sdk.common.CompletableResultCode;
import io.opentelemetry.sdk.logs.data.LogRecordData;
import io.opentelemetry.sdk.logs.export.LogRecordExporter;

import java.io.PrintStream;
import java.net.URI;
import java.util.Collection;

public class StreamLogRecordExporter implements LogRecordExporter {
    private final PrintStream out;
    private final String endpoint;

    StreamLogRecordExporter(PrintStream out, URI endpoint) {
        this.out = out;
        this.endpoint = endpoint.toString();
    }
    public CompletableResultCode export(Collection<LogRecordData> logs) {
        logs.forEach(lr ->  out.println(endpoint + " " + lr.getBody().asString()));
        out.flush();
        return CompletableResultCode.ofSuccess();
    }
    public CompletableResultCode flush()    { out.flush(); return CompletableResultCode.ofSuccess(); }
    public CompletableResultCode shutdown() { out.flush(); return CompletableResultCode.ofSuccess(); }
}
