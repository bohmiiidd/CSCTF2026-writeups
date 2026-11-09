FROM python:3.11-slim

RUN useradd --system --create-home --home-dir /var/lib/helioform --shell /usr/sbin/nologin helio \
    && mkdir -p /opt/helioform /etc/helioform /var/log/helioform/streams /var/lib/helioform/runbooks \
    && chown -R helio:helio /var/lib/helioform /var/log/helioform

WORKDIR /opt/helioform
COPY src/relay.py /opt/helioform/relay.py
COPY src/relay.env /etc/helioform/relay.env
COPY src/collector.env /etc/helioform/collector.env
COPY run.sh /opt/helioform/run.sh
COPY flag.txt /flag

RUN sed -i 's/\r$//' /opt/helioform/relay.py /opt/helioform/run.sh \
        /etc/helioform/relay.env /etc/helioform/collector.env /flag \
    && chown -R helio:helio /var/lib/helioform /var/log/helioform /opt/helioform \
    && chown helio:helio /etc/helioform/relay.env /etc/helioform/collector.env /flag \
    && chmod 0600 /flag \
    && chmod 0444 /etc/helioform/relay.env /etc/helioform/collector.env \
    && chmod 0755 /opt/helioform/run.sh \
    && chmod 0750 /var/lib/helioform /var/lib/helioform/runbooks /var/log/helioform /var/log/helioform/streams

USER helio
EXPOSE 8080
CMD ["sh", "/opt/helioform/run.sh"]
