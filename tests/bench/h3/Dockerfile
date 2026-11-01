# h2load speaking HTTP/3 (nghttp2 on ngtcp2 + nghttp3, OpenSSL 3.5's QUIC
# API): the load generator for tests/bench/h3.sh
FROM debian:trixie-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git build-essential autoconf automake libtool pkg-config \
      libssl-dev libev-dev zlib1g-dev libc-ares-dev libbrotli-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone --depth 1 -b v1.11.0 https://github.com/ngtcp2/nghttp3 && cd nghttp3 \
 && git submodule update --init --depth 1 && autoreconf -i && ./configure --prefix=/opt/q --enable-lib-only \
 && make -j"$(nproc)" install
RUN git clone --depth 1 -b v1.14.0 https://github.com/ngtcp2/ngtcp2 && cd ngtcp2 \
 && git submodule update --init --depth 1 && autoreconf -i \
 && PKG_CONFIG_PATH=/opt/q/lib/pkgconfig ./configure --prefix=/opt/q --enable-lib-only --with-openssl \
 && make -j"$(nproc)" install
RUN git clone --depth 1 -b v1.66.0 https://github.com/nghttp2/nghttp2 && cd nghttp2 \
 && git submodule update --init --depth 1 && autoreconf -i \
 && PKG_CONFIG_PATH=/opt/q/lib/pkgconfig ./configure --prefix=/opt/q --enable-app --enable-http3 \
      --disable-python-bindings LDFLAGS="-Wl,-rpath,/opt/q/lib" \
 && make -j"$(nproc)" install

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      libssl3t64 libev4t64 zlib1g libc-ares2 libbrotli1 && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/q /opt/q
ENTRYPOINT ["/opt/q/bin/h2load"]
