#!/bin/sh

set -e

export GOPROXY=https://goproxy.io

go get -v ./...

if [ "$CAMO_ENABLE_IP4" = true ]; then
    IP4FLAGS="--tun-ip4 $CAMO_TUN_IP4 -nat4"
fi

if [ "$CAMO_ENABLE_IP6" = true ]; then
    IP6FLAGS="--tun-ip6 $CAMO_TUN_IP6 -nat6"
fi

exec camo-server $IP4FLAGS $IP6FLAGS --autocert-host "$CAMO_HOST" --log-level "$CAMO_LOG_LEVEL" --debug-http :6060 --password camodev
