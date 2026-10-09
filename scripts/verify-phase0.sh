#!/usr/bin/env bash
# Phase 0 exit check: start the debug instance in port-only mode with a
# user-supplied config, proxy a request through it, stop it, and confirm
# routes, DNS, system proxy settings, and interfaces are unchanged.
set -euo pipefail
cd "$(dirname "$0")/.."

BIN=bin/mihomac
CONFIG=examples/config.example.yaml
export MIHOMAC_HOME="${MIHOMAC_HOME:-$PWD/.mihomac-dev}"
PORT=17990

# Routes minus cloned/link-layer entries, which come and go on their own.
snapshot() {
  echo "## routes";     netstat -rn | awk '$3 !~ /[WL]/'
  echo "## dns";        scutil --dns | grep -E 'nameserver|search domain' | sort -u
  echo "## proxy";      scutil --proxy
  echo "## interfaces"; ifconfig -l | tr ' ' '\n' | sort
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"; "$BIN" stop --instance debug >/dev/null 2>&1 || true' EXIT

snapshot >"$tmp/before"

echo "==> start"
"$BIN" start --instance debug --config "$CONFIG"

echo "==> proxy request through 127.0.0.1:$PORT"
code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 -x "http://127.0.0.1:$PORT" https://example.com)
echo "HTTP $code"
[[ "$code" =~ ^[23] ]] || { echo "FAIL: proxied request returned $code"; exit 1; }

echo "==> TUN device must not exist while running"
if ifconfig utun1991 >/dev/null 2>&1; then echo "FAIL: utun1991 exists"; exit 1; fi

echo "==> stop"
"$BIN" stop --instance debug

snapshot >"$tmp/after"
if diff -u "$tmp/before" "$tmp/after"; then
  echo "PASS: routes, DNS, proxy settings, and interfaces unchanged"
else
  echo "FAIL: system network state changed (diff above)"
  exit 1
fi
