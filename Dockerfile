FROM docker.elastic.co/logstash/logstash:9.4.4@sha256:c1aeca2bbf56148c1c868957e1d0ea5aa020cba5b3dca3493a097f54c0efc544
COPY logstash-output-otlp-*-java.gem /tmp/logstash/
RUN /usr/share/logstash/jdk/bin/jar --create --file /tmp/otlp-offline.zip --no-manifest -C /tmp logstash \
    && bin/logstash-plugin install --local file:///tmp/otlp-offline.zip \
    && rm /tmp/otlp-offline.zip
