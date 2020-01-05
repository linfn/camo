#!/bin/sh

set -e

# if dual stack
if [ "$CAMO_ENABLE_IP4" != true -a "$CAMO_ENABLE_IP6" != true ]; then	
    if [ "$(sysctl net.ipv6.conf.all.disable_ipv6)" != "net.ipv6.conf.all.disable_ipv6 = 0" ]; then	
        CAMO_ENABLE_IP4=true
    fi	
fi

exec ./camo $*
