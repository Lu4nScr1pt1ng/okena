# The XDP bench's lab: libbpf (the Katran loader), clang (Katran's program,
# built with the libbpf it is loaded with), iproute2 and ethtool.
FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
	libbpf-dev libelf-dev zlib1g-dev gcc libc6-dev clang llvm iproute2 ethtool procps util-linux \
	&& rm -rf /var/lib/apt/lists/*
