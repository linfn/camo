#!/bin/sh

set -e

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

exec ./camo-server $*
