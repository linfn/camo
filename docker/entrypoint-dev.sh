#!/bin/sh

set -e

go get -v ./...

# allexport
set -a

CAMO_PASSWORD=
CAMO_AUTOCERT_HOST=
CAMO_ENABLE_IP4=true
CAMO_TUN_IP4=10.20.0.1/24
CAMO_ENABLE_IP6=false
CAMO_TUN_IP6=fd01:cafe::1/64
CAMO_LOG_LEVEL=debug
CAMO_NAT=true
CAMO_DEBUG_HTTP=:6060

[ -f .env ] && . .env

set +a

if [ "$CAMO_ENABLE_IP4" != true ]; then
    CAMO_TUN_IP4=
fi

if [ "$CAMO_ENABLE_IP6" != true ]; then
    CAMO_TUN_IP6=
fi

exec camo-server $*
