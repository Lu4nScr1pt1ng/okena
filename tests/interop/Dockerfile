# okena as a server for the QUIC interop runner
# (https://github.com/quic-interop/quic-interop-runner): build it from the
# tests/interop/build.sh (after `make`), which puts this file, the scripts
# and build/okena in a context of their own.
#
# okena terminates QUIC on 443 (HTTP/3, or hq-interop: HTTP/0.9) and
# proxies to a file server on loopback serving /www.
FROM martenseemann/quic-network-simulator-endpoint:latest
RUN apt-get update && apt-get install -y --no-install-recommends python3 \
 && rm -rf /var/lib/apt/lists/*
COPY okena /usr/local/bin/okena
COPY run_endpoint.sh /run_endpoint.sh
COPY files.py /files.py
RUN chmod +x /run_endpoint.sh
ENTRYPOINT ["/run_endpoint.sh"]
