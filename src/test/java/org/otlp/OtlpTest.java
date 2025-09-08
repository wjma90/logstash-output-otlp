package org.otlp;

import co.elastic.logstash.api.Configuration;
import co.elastic.logstash.api.Event;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.logstash.plugins.ConfigurationImpl;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class OtlpTest {

    @Test
    public void logstashOtlpBasic() {
        String endpoint = "http://localhost:4317";
        Map<String, Object> configValues = new HashMap<>();
        configValues.put(Otlp.ENDPOINT_CONFIG.name(), endpoint);
        configValues.put(Otlp.TRACE_ID_CONFIG.name(), "trace.id");
        configValues.put(Otlp.SPAN_ID_CONFIG.name(), "span.id");

        Configuration config = new ConfigurationImpl(configValues);
        ByteArrayOutputStream bas = new ByteArrayOutputStream();
        Otlp output = new Otlp("test-id", config, null, bas, true);

        String sourceField = "message";
        int eventCount = 5;
        Collection<Event> events = new ArrayList<>();
        for (int k = 0; k < eventCount; k++) {
            Event e = new org.logstash.Event();
            e.setField(sourceField, "message " + k);
            // https://opentelemetry.io/docs/concepts/signals/traces/
            e.setField("trace.id", "5b8aa5a2d2c872e8321cf37308d69df2");
            e.setField("span.id", "051581bf3cb55c13");
            events.add(e);
        }

        output.output(events);

        String outputString = bas.toString();
        int index = 0;
        int lastIndex = 0;
        while (index < eventCount) {
            lastIndex = outputString.indexOf(endpoint, lastIndex);
            assertTrue(lastIndex > -1, "Prefix should exist in output string");
            lastIndex = outputString.indexOf("message " + index);
            assertTrue(lastIndex > -1, "Message should exist in output string");
            index++;
        }

        output.stop();
    }
}
