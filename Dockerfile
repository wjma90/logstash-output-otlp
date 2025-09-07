FROM docker.elastic.co/logstash/logstash:9.0.0
COPY *.gem .
RUN logstash-plugin install --no-verify --local *gem
