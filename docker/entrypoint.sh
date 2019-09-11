#!/bin/sh

set -e

if [ ! -f /var/lib/dbus/machine-id ]; then
    dbus-uuidgen > /var/lib/dbus/machine-id
fi

if [ "$CAMO_ENABLE_IP4" != true ]; then
    CAMO_TUN_IP4=
fi

if [ "$CAMO_ENABLE_IP6" != true ]; then
    CAMO_TUN_IP6=
fi

exec ./camo-server $*
