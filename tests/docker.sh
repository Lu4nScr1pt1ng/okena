#!/usr/bin/env sh
# Container checks (needs Docker): the image runs under Docker's default
# seccomp profile on the epoll engine, under docker/okena.seccomp.json on
# io_uring, proxies bytes either way, and stops gracefully.
set -eu
cd "$(dirname "$0")/.."
docker build -q -t okena:test . >/dev/null
python3 -I -c '
import socket, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 21900)); s.listen()
def h(c):
    while (d := c.recv(4096)): c.sendall(d)
    c.close()
while True:
    c, _ = s.accept(); threading.Thread(target=h, args=(c,), daemon=True).start()
' & echo_pid=$!
trap 'kill $echo_pid 2>/dev/null; docker rm -f okena-t >/dev/null 2>&1 || true' EXIT
sleep 0.3
for profile in default okena; do
	opt=""
	[ "$profile" = okena ] && opt="--security-opt seccomp=docker/okena.seccomp.json"
	# shellcheck disable=SC2086
	docker run -d --name okena-t --network host $opt okena:test \
		'okena { workers 2 }' tcp 127.0.0.1:21901 to 127.0.0.1:21900 >/dev/null
	sleep 1
	python3 -I -c '
import socket; c = socket.create_connection(("127.0.0.1", 21901), timeout=3)
c.sendall(b"ping"); assert c.recv(10) == b"ping"'
	logs=$(docker logs okena-t 2>&1)
	if [ "$profile" = default ]; then
		echo "$logs" | grep -q "using the epoll engine" || { echo "FAIL default profile: no epoll fallback"; exit 1; }
	else
		echo "$logs" | grep -q "epoll" && { echo "FAIL okena profile: fell back to epoll"; exit 1; }
	fi
	docker stop -t 10 okena-t >/dev/null
	status=$(docker inspect -f '{{.State.ExitCode}}' okena-t)
	docker rm okena-t >/dev/null
	[ "$status" = 0 ] || { echo "FAIL $profile profile: exit status $status"; exit 1; }
	echo "ok   $profile seccomp profile"
done
echo "docker: all passed"
