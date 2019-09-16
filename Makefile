.PHONY: all
all: server client

.PHONY: server client
server:
	go build ./cmd/camo-server

client:
	go build ./cmd/camo-client

.PHONY: test
test:
	golangci-lint run
	go test -race -coverprofile=coverage.txt ./...


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

docker-release:
	docker build -t linfn/camo -f docker/Dockerfile .

.PHONY: run
run:
	@[ -n "`docker ps -aq -f name=$(DEV_CONTAINER_NAME)`" ] || $(MAKE) docker-dev
	docker restart $(DEV_CONTAINER_NAME)
	docker attach $(DEV_CONTAINER_NAME)
