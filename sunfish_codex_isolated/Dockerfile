FROM ghcr.io/home-assistant/amd64-base@sha256:322c4492f25f9c2ca04b0789101a44350c516f4d3cd928fca14847ef19668ede

ARG BUILD_VERSION="0.1.2"
LABEL io.hass.version="${BUILD_VERSION}" io.hass.type="app" io.hass.arch="amd64"

# Signed Alpine v3.23 packages, direct versions pinned. Transitive packages are
# not yet locked; capture apk info in the build review before deployment.
RUN apk add --no-cache \
    python3=3.12.15-r0 \
    nginx=1.28.3-r7 \
    ttyd=1.7.7-r0 \
    su-exec=0.3-r0 \
 && addgroup -g 1000 codex \
 && adduser -D -u 1000 -G codex -h /data/home -s /bin/bash codex

COPY build_download.py /opt/sunfish/build_download.py
RUN python3 /opt/sunfish/build_download.py \
 && /usr/local/bin/codex --version \
 && apk info -v > /opt/sunfish/alpine-packages.txt

COPY mcp_proxy.py init.py security.py readiness.py /opt/sunfish/
COPY nginx.conf /etc/nginx/nginx.conf
COPY codex-session /usr/local/bin/codex-session
RUN chmod 755 /usr/local/bin/codex-session \
 && test -x /usr/sbin/nginx && test -x /sbin/su-exec && test -x /usr/bin/ttyd \
 && chmod 644 /opt/sunfish/*.py /etc/nginx/nginx.conf \
 && python3 -m compileall -q /opt/sunfish \
 && /bin/bash -n /usr/local/bin/codex-session \
 && /usr/local/bin/codex sandbox --help > /dev/null \
 && /usr/local/bin/bwrap --version > /dev/null \
 && ttyd --version > /dev/null

ENTRYPOINT []
CMD ["python3", "-u", "/opt/sunfish/init.py"]
