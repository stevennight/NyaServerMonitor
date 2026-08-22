# syntax=docker/dockerfile:1.7
FROM golang:1.26-alpine AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false -ldflags='-s -w' -o /out/nyasm-controller ./cmd/controller
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false -ldflags='-s -w' -o /out/nyasm-node ./cmd/node

FROM alpine:3.22
RUN addgroup -S nyasm && adduser -S -G nyasm nyasm
COPY --from=build /out/nyasm-controller /usr/local/bin/nyasm-controller
COPY --from=build /out/nyasm-node /usr/local/bin/nyasm-node
USER nyasm
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8080
ENV NYASM_DATA=/data
ENTRYPOINT ["/usr/local/bin/nyasm-controller"]
