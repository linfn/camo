.PHONY: all
all: server client

.PHONY: server client
server:
	go build ./cmd/camo-server

client:
	go build ./cmd/camo-client

DEV_CONTAINER_NAME=camo-dev
DOCKER_NETWORK=bridge

.PHONY: docker-dev
docker-dev:
	docker build -t camo:dev -f Dockerfile.dev --build-arg USE_CN_APT_SOURCES .
	docker rm -f $(DEV_CONTAINER_NAME) 2>/dev/null || true
	docker create -it -v `pwd`:/camo -p 443:443 --cap-add=NET_ADMIN --device /dev/net/tun --network $(DOCKER_NETWORK) --env-file .env --name $(DEV_CONTAINER_NAME) camo:dev

.PHONY: run
run:
	@[ -n "`docker ps -aq -f name=$(DEV_CONTAINER_NAME)`" ] || $(MAKE) docker-dev
	docker restart $(DEV_CONTAINER_NAME) 
	docker attach $(DEV_CONTAINER_NAME)
