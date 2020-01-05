FROM golang:alpine as build

RUN apk add --no-cache git make

WORKDIR /camo
COPY . .

RUN go get -d -v ./...
RUN make

FROM alpine

RUN apk add --no-cache iproute2 iptables ip6tables ca-certificates

WORKDIR /camo

COPY --from=build /camo/camo .
COPY --from=build /camo/docker_entrypoint.sh .

ENV CAMO_AUTOCERT_DIR=/camo/certs

EXPOSE 443
EXPOSE 443/udp

ENTRYPOINT [ "./docker_entrypoint.sh" ]
