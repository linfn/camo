.PHONY: proto
proto:
	protoc --gofast_out=plugins=grpc:. tunnel.proto
