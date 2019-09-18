FROM golang:alpine as build

RUN apk add --no-cache git make

WORKDIR /camo
COPY . .

RUN go get -d -v ./...
RUN make client

FROM alpine

RUN apk add --no-cache iproute2 ca-certificates

WORKDIR /camo

COPY --from=build /camo/camo-client .

ENV CAMO_PASSWORD=

ENTRYPOINT [ "./camo-client" ]
