#!/bin/sh

set -e

export GOPROXY=https://goproxy.io

go get -v ./...

if [ -n "$CAMO_IP4" ]; then
    IP4FLAGS="-ip4 $CAMO_IP4 -nat4"
fi

if [ -n "$CAMO_IP6" ]; then
    IP6FLAGS="-ip6 $CAMO_IP6 -nat6"
fi

exec camo-server $IP4FLAGS $IP6FLAGS -autocert-host "$CAMO_HOST" -pprof -log-level "$CAMO_LOG_LEVEL"
