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

ENV CAMO_AUTOCERT_DIR=/camo/certs

EXPOSE 443

ENTRYPOINT [ "./camo" ]
