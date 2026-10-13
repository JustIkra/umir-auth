# syntax=docker/dockerfile:1
FROM golang:1.26.9-alpine AS build
WORKDIR /src
ENV GOWORK=off CGO_ENABLED=0
COPY go.mod go.sum ./
RUN go mod download
COPY bootstrap bootstrap
COPY cmd cmd
COPY internal internal
RUN go build -trimpath -o /out/server ./cmd/server
FROM alpine:3.22 AS runtime
ARG SOURCE_REVISION
LABEL org.opencontainers.image.source="https://github.com/JustIkra/umir-auth" org.opencontainers.image.revision=$SOURCE_REVISION
RUN apk add --no-cache ca-certificates tzdata && mkdir -p /var/lib/umir-auth /usr/local/lib/umir && chown 65532:65532 /var/lib/umir-auth && chmod 0700 /var/lib/umir-auth
COPY --from=build /out/server /server
COPY --from=build /usr/local/go/lib/time/zoneinfo.zip /usr/local/lib/umir/zoneinfo.zip
USER 65532:65532
ENTRYPOINT ["/server"]
