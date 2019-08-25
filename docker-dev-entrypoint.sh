#!/bin/sh

set -e

export GOPROXY=https://goproxy.io

go get -v ./...

exec camo-server -ip4 10.20.0.1/24 -nat4 -autocert-host "$CAMO_HOST" -pprof -log-level "$CAMO_LOG_LEVEL"
