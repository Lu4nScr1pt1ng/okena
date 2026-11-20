# okena container image: the static binary on an empty filesystem.
#
#   docker run -p 8080:8080 ghcr.io/lu4nscr1pt1ng/okena          # a page that says it runs
#   docker run --network host -v ./okena.conf:/etc/okena/okena.conf:ro ghcr.io/lu4nscr1pt1ng/okena
#   docker run --network host ghcr.io/lu4nscr1pt1ng/okena tcp :5432 to 10.0.0.11:5432
#   docker build -t okena .                                     # the same image, from source
#
# Without the seccomp profile okena runs on its epoll engine (Docker's
# default profile blocks io_uring) and says so at startup.

FROM debian:trixie-slim AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git make \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY scripts/fetch-fasm2.sh scripts/
RUN ./scripts/fetch-fasm2.sh .toolchain/fasm2
COPY Makefile ./
COPY src src
COPY contrib/ranges contrib/ranges
RUN make

FROM scratch
LABEL org.opencontainers.image.title="okena" \
      org.opencontainers.image.description="L4/L7 load balancer, reverse proxy and API gateway, in x86-64 assembly" \
      org.opencontainers.image.source="https://github.com/Lu4nScr1pt1ng/okena" \
      org.opencontainers.image.licenses="Apache-2.0"
ARG VERSION=dev
LABEL org.opencontainers.image.version="$VERSION"
COPY --from=build /src/build/okena /okena
COPY LICENSE NOTICE /
COPY docker/okena.conf /etc/okena/okena.conf
EXPOSE 8080 9090
USER 65532:65532
ENTRYPOINT ["/okena"]
CMD ["run"]
