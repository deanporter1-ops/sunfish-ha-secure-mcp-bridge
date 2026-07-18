FROM ghcr.io/home-assistant/amd64-base:3.22@sha256:368b5fcd266d1e5a643bad9bc9e84760760032e911ecfdef2a7fc148d76035d1

ARG BUILD_VERSION
ARG BUILD_ARCH

LABEL \
    io.hass.name="Sunfish Secure MCP Bridge" \
    io.hass.description="OpenAI Secure MCP Tunnel with a Home Assistant MCP policy proxy" \
    io.hass.arch="amd64" \
    io.hass.type="app" \
    io.hass.version="${BUILD_VERSION}"

ARG TUNNEL_VERSION="0.0.10"
ARG TUNNEL_SHA256="b9e0388a343f2d7adeff3992f411a0bd3d916a64bc56534aac5fd15ac1b20cd5"

RUN apk add --no-cache python3 ca-certificates \
    && apk add --no-cache --virtual .fetch-deps curl unzip \
    && curl --fail --show-error --silent --location \
       "https://github.com/openai/tunnel-client/releases/download/v${TUNNEL_VERSION}/tunnel-client-v${TUNNEL_VERSION}-linux-amd64.zip" \
       --output /tmp/tunnel-client.zip \
    && echo "${TUNNEL_SHA256}  /tmp/tunnel-client.zip" | sha256sum -c - \
    && mkdir -p /tmp/tunnel-client \
    && unzip -q /tmp/tunnel-client.zip -d /tmp/tunnel-client \
    && install -m 0755 "$(find /tmp/tunnel-client -type f -name tunnel-client -print -quit)" /usr/bin/tunnel-client \
    && tunnel-client help quickstart >/dev/null \
    && rm -rf /tmp/tunnel-client /tmp/tunnel-client.zip \
    && apk del .fetch-deps

COPY bridge.py /opt/sunfish/bridge.py

ENTRYPOINT ["python3", "/opt/sunfish/bridge.py"]
