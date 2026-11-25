# Credential-isolated Lab Assistant broker. The Workbench has no provider key or egress route.
FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN groupadd --gid 10001 opentrace && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin opentrace
COPY requirements-dev.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt
WORKDIR /opt/opentrace
COPY src/core ./src/core
COPY services/assistant_provider ./services/assistant_provider
COPY deploy/docker/assistant-provider-entrypoint.sh /opt/opentrace/assistant-provider-entrypoint.sh
RUN chmod 0555 /opt/opentrace/assistant-provider-entrypoint.sh \
 && mkdir -p /var/lib/opentrace/assistant \
 && chown -R 10001:10001 /var/lib/opentrace/assistant \
 && chmod 0700 /var/lib/opentrace/assistant   # the SpendLedger refuses a directory that is not owner-owned and private (no group/other bits); a new named volume copies this mode
USER 10001:10001
ENV PYTHONPATH=/opt/opentrace/src/core:/opt/opentrace
EXPOSE 8766
ENTRYPOINT ["/opt/opentrace/assistant-provider-entrypoint.sh"]
