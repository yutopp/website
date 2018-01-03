FROM golang:1.9-alpine3.7 as builder

WORKDIR /go/src/yutopp.net-builder
COPY . .
RUN go build

FROM alpine:latest
LABEL maintainer="yutopp@gmail.com"

RUN apk --update --no-cache add git hugo

COPY --from=builder /go/src/yutopp.net-builder/yutopp.net-builder /yutopp.net-builder

RUN mkdir /workspace

EXPOSE 8080
ENTRYPOINT ["/yutopp.net-builder"]
