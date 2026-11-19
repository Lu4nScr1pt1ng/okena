#!/usr/bin/env sh
# Install okena from its GitHub release: the binary, checked against its
# published SHA-256, into /usr/local/bin (or $PREFIX/bin), and a configuration
# to start from in /etc/okena/okena.conf when there is none.
#
#   curl -fsSL https://raw.githubusercontent.com/Lu4nScr1pt1ng/okena/main/scripts/install.sh | sh
#   ... | sh -s -- --version 0.1.0 --systemd
#
# Options:
#   --version V   that release (default: the latest)
#   --prefix DIR  install under DIR/bin (default /usr/local)
#   --systemd     also install okena.service and okena.socket, and enable the service
#   --no-config   leave /etc/okena alone
set -eu

REPO="Lu4nScr1pt1ng/okena"
VERSION=""
PREFIX="${PREFIX:-/usr/local}"
SYSTEMD=0
CONFIG=1

while [ $# -gt 0 ]; do
	case "$1" in
	--version) VERSION="${2#v}"; shift 2 ;;
	--prefix) PREFIX="$2"; shift 2 ;;
	--systemd) SYSTEMD=1; shift ;;
	--no-config) CONFIG=0; shift ;;
	-h|--help) sed -n '2,16p' "$0" 2>/dev/null || true; exit 0 ;;
	*) echo "install.sh: unknown option $1" >&2; exit 2 ;;
	esac
done

say() { printf '%s\n' "$*"; }
die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = Linux ] || die "okena runs on Linux only"
case "$(uname -m)" in
x86_64|amd64) ;;
*) die "okena is built for x86-64 only (this is $(uname -m))" ;;
esac

if command -v curl >/dev/null 2>&1; then
	fetch() { curl -fsSL "$1" -o "$2"; }
	fetch_out() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
	fetch() { wget -qO "$2" "$1"; }
	fetch_out() { wget -qO- "$1"; }
else
	die "needs curl or wget"
fi
command -v sha256sum >/dev/null 2>&1 || die "needs sha256sum"
command -v tar >/dev/null 2>&1 || die "needs tar"

if [ -z "$VERSION" ]; then
	VERSION=$(fetch_out "https://api.github.com/repos/$REPO/releases/latest" \
		| sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' | head -n 1)
	[ -n "$VERSION" ] || die "could not find the latest release (set --version)"
fi

NAME="okena-$VERSION-linux-x86_64"
URL="${OKENA_URL:-https://github.com/$REPO/releases/download/v$VERSION}"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

say "okena $VERSION: downloading"
fetch "$URL/$NAME.tar.gz" "$TMP/$NAME.tar.gz" || die "no such release: v$VERSION"
fetch "$URL/$NAME.tar.gz.sha256" "$TMP/$NAME.tar.gz.sha256" || die "its checksum is missing"
(cd "$TMP" && sha256sum -c "$NAME.tar.gz.sha256" >/dev/null) || die "checksum mismatch: not installed"
tar -C "$TMP" -xzf "$TMP/$NAME.tar.gz"

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
	if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else die "run as root (or install sudo)"; fi
fi

$SUDO install -D -m 0755 "$TMP/$NAME/okena" "$PREFIX/bin/okena"
say "installed $PREFIX/bin/okena"

if [ "$CONFIG" = 1 ]; then
	$SUDO install -d -m 0755 /etc/okena
	if [ ! -e /etc/okena/okena.conf ]; then
		$SUDO install -m 0644 "$TMP/$NAME/examples/reverse-proxy.conf" /etc/okena/okena.conf
		say "wrote /etc/okena/okena.conf (an example: edit it, then okena check)"
	fi
	$SUDO install -d -m 0755 /usr/local/share/doc/okena/examples
	$SUDO cp "$TMP/$NAME/examples/"*.conf /usr/local/share/doc/okena/examples/
fi

if [ "$SYSTEMD" = 1 ]; then
	command -v systemctl >/dev/null 2>&1 || die "no systemd here"
	sed "s#/usr/local/bin/okena#$PREFIX/bin/okena#" "$TMP/$NAME/systemd/okena.service" \
		| $SUDO tee /etc/systemd/system/okena.service >/dev/null
	$SUDO install -m 0644 "$TMP/$NAME/systemd/okena.socket" /etc/systemd/system/okena.socket
	$SUDO systemctl daemon-reload
	$SUDO systemctl enable okena.service >/dev/null
	say "okena.service enabled (start it: sudo systemctl start okena; okena.socket is there for socket activation)"
fi

"$PREFIX/bin/okena" version
say "next: okena check /etc/okena/okena.conf && okena -c /etc/okena/okena.conf"
