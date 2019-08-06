#!/bin/sh

set -e

export GOPROXY=https://goproxy.io

go get -v ./...

exec camo-server
