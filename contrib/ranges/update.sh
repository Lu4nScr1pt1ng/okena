#!/bin/sh
# A fresher list of Cloudflare's ranges, for `trusted_proxies file:PATH` and
# `allow file:PATH`, from where Cloudflare publishes them. Run it from cron, then
# `okena reload`. Usage: update.sh /etc/okena/cloudflare.txt
set -eu
out=${1:?where to write it}
tmp=$(mktemp "${out}.XXXXXX")
trap 'rm -f "$tmp"' EXIT
{
	echo "# Cloudflare, fetched $(date -u +%Y-%m-%dT%H:%MZ)"
	curl -fsS --max-time 20 https://www.cloudflare.com/ips-v4
	echo
	curl -fsS --max-time 20 https://www.cloudflare.com/ips-v6
	echo
} > "$tmp"
# a list that came back empty or odd is not put in place
lines=$(grep -c '/' "$tmp" || true)
[ "$lines" -ge 10 ] || { echo "update.sh: only $lines ranges came: kept the old list" >&2; exit 1; }
mv "$tmp" "$out"
trap - EXIT
