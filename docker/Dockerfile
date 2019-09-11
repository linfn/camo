FROM golang:alpine as build

RUN apk add --no-cache git

WORKDIR /camo
COPY . .

RUN go get -d -v ./...
RUN go build ./cmd/camo-server

FROM alpine

RUN apk add --no-cache iproute2 iptables ip6tables ca-certificates

WORKDIR /camo

COPY --from=build /camo/camo-server .
COPY --from=build /camo/docker/entrypoint.sh .

ENV CAMO_PASSWORD=
ENV CAMO_ENABLE_IP4=true
ENV CAMO_TUN_IP4=10.20.0.1/24
ENV CAMO_ENABLE_IP6=false
ENV CAMO_TUN_IP6=fd01:cafe::1/64
ENV CAMO_NAT=true

EXPOSE 443

ENTRYPOINT [ "./entrypoint.sh" ]
