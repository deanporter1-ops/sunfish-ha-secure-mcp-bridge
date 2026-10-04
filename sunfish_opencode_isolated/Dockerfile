FROM ghcr.io/home-assistant/amd64-base@sha256:322c4492f25f9c2ca04b0789101a44350c516f4d3cd928fca14847ef19668ede

ARG BUILD_VERSION="0.1.0"
LABEL io.hass.version="${BUILD_VERSION}" io.hass.type="app" io.hass.arch="amd64"

# Direct signed Alpine v3.23 packages are pinned. Transitive dependencies are
# recorded during the build; this is not a claim of a fully hermetic build.
RUN apk add --no-cache \
    python3=3.12.15-r0 \
    nginx=1.28.3-r7 \
    ttyd=1.7.7-r0 \
    su-exec=0.3-r0 \
 && addgroup -g 1000 opencode \
 && adduser -D -u 1000 -G opencode -h /run/sunfish-opencode-home -s /bin/bash opencode

COPY build_download.py /opt/sunfish/build_download.py
RUN python3 /opt/sunfish/build_download.py \
 && test "$(/usr/local/bin/opencode --version)" = "1.18.34" \
 && apk info -v > /opt/sunfish/alpine-packages.txt

COPY mcp_proxy.py init.py security.py readiness.py runtime_config.py unprivileged_exec.py /opt/sunfish/
COPY nginx.conf /etc/nginx/nginx.conf
COPY opencode-session /usr/local/bin/opencode-session
RUN chmod 755 /usr/local/bin/opencode-session \
 && test -x /usr/sbin/nginx && test -x /sbin/su-exec && test -x /usr/bin/ttyd \
 && test -x /bin/bash \
 && chmod 644 /opt/sunfish/*.py /etc/nginx/nginx.conf \
 && python3 -m compileall -q /opt/sunfish \
 && /bin/bash -n /usr/local/bin/opencode-session \
 && /usr/bin/ttyd --version > /dev/null \
 && python3 -c "import sys;sys.path.insert(0,'/opt/sunfish');from security import render_nginx_config;from pathlib import Path;p=Path('/run/sunfish-build-nginx.conf');p.write_text(render_nginx_config(Path('/etc/nginx/nginx.conf').read_text(),'a1'*16))" \
 && /usr/sbin/nginx -t -c /run/sunfish-build-nginx.conf \
 && rm /run/sunfish-build-nginx.conf

ENTRYPOINT []
CMD ["python3", "-u", "/opt/sunfish/init.py"]
