#!/bin/bash
# The interop runner's entry point (server role only): TESTCASE picks the
# configuration; a case okena does not support exits 127.
set -e
/setup.sh

if [ "$ROLE" != "server" ]; then
	echo "okena is a server only"
	exit 127
fi

H3=on
case "$TESTCASE" in
	handshake|transfer|multiplexing|longrtt|chacha20|multiconnect|blackhole|keyupdate| \
	handshakeloss|transferloss|handshakecorruption|transfercorruption|amplificationlimit| \
	ipv6|rebind-port|rebind-addr|goodput|crosstraffic|http3|resumption|ecn) ;;
	retry) H3=retry ;;
	v2) H3=v2 ;;
	*) echo "test case $TESTCASE not supported"; exit 127 ;;
esac

python3 /files.py /www 127.0.0.1 8000 &
/wait-for-it.sh -q -t 10 127.0.0.1:8000
cat > /okena.conf <<EOC
okena { workers 1 }
http :443 {
	http3 $H3
	access_log stderr
	tls { cert /certs/cert.pem; key /certs/priv.key }
	route /* { to 127.0.0.1:8000 }
}
EOC
exec okena -c /okena.conf
