# syntax=docker/dockerfile:1

# ---- build (Go 1.26) ----
FROM golang:1.26 AS build
WORKDIR /src
ENV GOWORK=off GOTOOLCHAIN=auto CGO_ENABLED=0
COPY go.mod ./
RUN go mod download || true
COPY . .
ARG VERSION=dev
RUN go build -ldflags "-s -w -X main.version=${VERSION}" -o /out/biogate ./cmd/biogate

# ---- runtime (small, with a shell for `make docker-shell`) ----
FROM alpine:3.20
RUN adduser -D -u 10001 biogate
COPY --from=build /out/biogate /usr/local/bin/biogate
USER biogate
ENTRYPOINT ["biogate"]
CMD ["version"]
