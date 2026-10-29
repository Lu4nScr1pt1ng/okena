#!/usr/bin/env sh
# Fetch the pinned fasm2 toolchain into .toolchain/fasm2 and verify the
# assembler binary, so local builds and the Docker build use the same bits.
set -eu

COMMIT="8658cc9d125b3fb3b347b9a8b88e0c803104da0f"
FASMG_SHA256="db544ed5a530dde139ef01ddc3fbc352bdec89fdda7fc1e9553e7da9361ac2e3"
DEST="${1:-.toolchain/fasm2}"

if [ -x "$DEST/fasmg.x64" ] && [ "$(cat "$DEST/.commit" 2>/dev/null)" = "$COMMIT" ]; then
	exit 0
fi

rm -rf "$DEST"
mkdir -p "$DEST"
git -C "$DEST" init -q
git -C "$DEST" fetch -q --depth 1 https://github.com/tgrysztar/fasm2 "$COMMIT"
git -C "$DEST" checkout -q FETCH_HEAD

actual="$(sha256sum "$DEST/fasmg.x64" | cut -d' ' -f1)"
if [ "$actual" != "$FASMG_SHA256" ]; then
	echo "fasmg.x64 checksum mismatch: $actual" >&2
	exit 1
fi
chmod +x "$DEST/fasmg.x64"
echo "$COMMIT" > "$DEST/.commit"
