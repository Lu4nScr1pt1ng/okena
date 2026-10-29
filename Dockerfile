# okena container image: the static binary on an empty filesystem.
#
#   docker build -t okena .
#   docker run --network host okena tcp :5432 to 10.0.0.11:5432
#   docker run --network host --security-opt seccomp=docker/okena.seccomp.json \
#       -v ./okena.conf:/etc/okena/okena.conf:ro okena
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
RUN make

FROM scratch
COPY --from=build /src/build/okena /okena
COPY LICENSE /LICENSE
USER 65532:65532
ENTRYPOINT ["/okena"]
CMD ["run"]
