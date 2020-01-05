commit = $(shell git rev-parse HEAD)
date = $(shell date -u +'%Y.%m.%d')

.PHONY: build
build:
	go build -ldflags '-s -w -X main.buildDate=$(date) -X main.buildCommit=$(commit)' .

.PHONY: release
release:
	goreleaser --snapshot --skip-publish --rm-dist

.PHONY: docker
docker:
	docker build -t linfn/camo .


.PHONY: lint unit test

lint:
	golangci-lint run

unit:
	go test -race -coverprofile=coverage.txt ./...

test: lint unit
