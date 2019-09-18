.PHONY: all
all: server client

commit = $(shell git rev-parse HEAD)
date = $(shell date -u +'%Y.%m.%d')

.PHONY: server client
server:
	go build -ldflags '-s -w -X main.buildDate=$(date) -X main.buildCommit=$(commit)' ./cmd/camo-server

client:
	go build -ldflags '-s -w -X main.buildDate=$(date) -X main.buildCommit=$(commit)' ./cmd/camo-client

.PHONY: release
release:
	goreleaser --snapshot --skip-publish --rm-dist



.PHONY: lint unit test

lint:
	golangci-lint run

unit:
	go test -race -coverprofile=coverage.txt ./...

test: lint unit



docker-release:
	docker build -t linfn/camo -f docker/Dockerfile .
	docker build -t linfn/camo-client -f docker/Dockerfile.client .


DEV_CONTAINER_NAME=camo-dev
DOCKER_NETWORK=bridge

.PHONY: docker-dev
docker-dev:
	docker build -t camo:dev -f docker/Dockerfile.dev .
	docker rm -f $(DEV_CONTAINER_NAME) 2>/dev/null || true
	docker create -it -v `pwd`:/camo -p 443:443 -p 6060 \
		--cap-add=NET_ADMIN --device /dev/net/tun \
		--sysctl net.ipv6.conf.all.disable_ipv6=0 \
		--sysctl net.ipv6.conf.default.forwarding=1 \
		--sysctl net.ipv6.conf.all.forwarding=1 \
		--network $(DOCKER_NETWORK) \
		-v `pwd`/.certs:/camo/certs \
		--name $(DEV_CONTAINER_NAME) camo:dev


.PHONY: run
run:
	@[ -n "`docker ps -aq -f name=$(DEV_CONTAINER_NAME)`" ] || $(MAKE) docker-dev
	docker restart $(DEV_CONTAINER_NAME)
	docker attach $(DEV_CONTAINER_NAME)
