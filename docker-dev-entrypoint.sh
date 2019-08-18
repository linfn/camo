#!/bin/sh

set -e

export GOPROXY=https://goproxy.io

go get -v ./...

exec camo-server -autocert-host "$CAMO_HOST" -pprof -log-level "$CAMO_LOG_LEVEL"
