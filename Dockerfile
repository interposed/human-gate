# syntax=docker/dockerfile:1

# ---- build (Go 1.26) ----
FROM golang:1.26 AS build
WORKDIR /src
ENV GOWORK=off GOTOOLCHAIN=auto CGO_ENABLED=0
COPY go.mod ./
RUN go mod download || true
COPY . .
ARG VERSION=dev
RUN go build -ldflags "-s -w -X main.version=${VERSION}" -o /out/humangate ./cmd/humangate

# ---- runtime (small, with a shell for `make docker-shell`) ----
FROM alpine:3.20
RUN adduser -D -u 10001 humangate
COPY --from=build /out/humangate /usr/local/bin/humangate
USER humangate
ENTRYPOINT ["humangate"]
CMD ["version"]
