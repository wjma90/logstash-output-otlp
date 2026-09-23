FROM docker.elastic.co/logstash/logstash:8.11.3

COPY logstash-output-otlp-*-java.gem /tmp/logstash/
RUN /usr/share/logstash/jdk/bin/jar --create --file /tmp/otlp-offline.zip --no-manifest -C /tmp logstash \
    && bin/logstash-plugin install --local file:///tmp/otlp-offline.zip \
    && rm /tmp/otlp-offline.zip
