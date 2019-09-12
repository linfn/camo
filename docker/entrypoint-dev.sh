#!/bin/sh

set -e

go get -v ./...

# allexport
set -a

CAMO_PASSWORD=
CAMO_AUTOCERT_HOST=
CAMO_ENABLE_IP4=
CAMO_TUN_IP4=10.20.0.1/24
CAMO_ENABLE_IP6=
CAMO_TUN_IP6=fd01:cafe::1/64
CAMO_LOG_LEVEL=debug
CAMO_NAT=true
CAMO_DEBUG_HTTP=:6060
CAMO_AUTOCERT_DIR=/camo/certs

[ -f .env ] && . .env

set +a

if [ "$CAMO_ENABLE_IP4" = false ]; then
    CAMO_TUN_IP4=
fi

if [ "$CAMO_ENABLE_IP6" = false ]; then
    CAMO_TUN_IP6=
elif [ "$CAMO_ENABLE_IP6" != true ]; then
    if [ "$(sysctl net.ipv6.conf.all.disable_ipv6)" != "net.ipv6.conf.all.disable_ipv6 = 0" ]; then
        CAMO_TUN_IP6=
    fi
fi

exec camo-server $*
