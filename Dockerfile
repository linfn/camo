FROM golang:alpine as build

WORKDIR /camo
COPY . .

RUN go get -d -v ./...
RUN make all

FROM alpine

RUN apk update && apk add iproute2 iptables ip6tables

WORKDIR /camo

COPY --from=build /camo/camo-server .
COPY --from=build /camo/camo-client .
COPY --from=build /camo/docker-entrypoint.sh .

ENV CAMO_PASSWORD=
ENV CAMO_HOST=
ENV CAMO_LOG_LEVEL=info
ENV CAMO_ENABLE_IP4=true
ENV CAMO_TUN_IP4=10.20.0.1/24
ENV CAMO_ENABLE_IP6=false
ENV CAMO_TUN_IP6=fc00:ca::1/64

EXPOSE 443

CMD [ "./docker-entrypoint.sh" ]
