# syntax=docker/dockerfile:1.7
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG NYASM_VERSION=0.1.0-dev
ARG NYASM_COMMIT=unknown
ARG NYASM_BUILD_DATE=unknown
WORKDIR /src
RUN mkdir -p /out/nodes
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN set -eux; \
	LDFLAGS="-s -w -X nyaservermonitor/internal/shared/version.Version=${NYASM_VERSION} -X nyaservermonitor/internal/shared/version.Commit=${NYASM_COMMIT} -X nyaservermonitor/internal/shared/version.BuildDate=${NYASM_BUILD_DATE}"; \
	CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o /out/nyasm-controller ./cmd/controller
RUN set -eux; \
	LDFLAGS="-s -w -X nyaservermonitor/internal/shared/version.Version=${NYASM_VERSION} -X nyaservermonitor/internal/shared/version.Commit=${NYASM_COMMIT} -X nyaservermonitor/internal/shared/version.BuildDate=${NYASM_BUILD_DATE}"; \
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o /out/nodes/nyasm-node-linux-amd64 ./cmd/node
RUN set -eux; \
	LDFLAGS="-s -w -X nyaservermonitor/internal/shared/version.Version=${NYASM_VERSION} -X nyaservermonitor/internal/shared/version.Commit=${NYASM_COMMIT} -X nyaservermonitor/internal/shared/version.BuildDate=${NYASM_BUILD_DATE}"; \
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -buildvcs=false -ldflags "$LDFLAGS" -o /out/nodes/nyasm-node-linux-arm64 ./cmd/node
RUN cp "/out/nodes/nyasm-node-${TARGETOS}-${TARGETARCH}" /out/nyasm-node

FROM alpine:3.22
RUN apk add --no-cache su-exec \
	&& addgroup -S nyasm \
	&& adduser -S -G nyasm nyasm
COPY --from=build /out/nyasm-controller /usr/local/bin/nyasm-controller
COPY --from=build /out/nyasm-node /usr/local/bin/nyasm-node
COPY --from=build /out/nodes /usr/local/lib/nyasm
COPY deploy/docker/entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh
WORKDIR /data
EXPOSE 8080
ENV NYASM_DATA=/data
ENV NYASM_NODE_BINARY=/usr/local/bin/nyasm-node
ENV NYASM_NODE_BINARY_DIR=/usr/local/lib/nyasm
ENTRYPOINT ["/entrypoint.sh"]
