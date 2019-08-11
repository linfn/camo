.PHONY: all
all: server client

.PHONY: server client
server:
	go build ./cmd/camo-server

client:
	go build ./cmd/camo-client

DEV_CONTAINER_NAME=camo-dev

.PHONY: docker-dev
docker-dev:
	docker build -t camo:dev -f Dockerfile.dev .
	docker rm -f $(DEV_CONTAINER_NAME) 2>/dev/null || true
	docker create -it -v `pwd`:/camo -p 2019:2019 --cap-add=NET_ADMIN --device /dev/net/tun --name $(DEV_CONTAINER_NAME) camo:dev

.PHONY: run
run:
	@[ -n "`docker ps -aq -f name=$(DEV_CONTAINER_NAME)`" ] || $(MAKE) docker-dev
	docker restart $(DEV_CONTAINER_NAME) 
	docker attach $(DEV_CONTAINER_NAME)
