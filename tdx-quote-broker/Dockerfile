FROM golang:1.26.6-bookworm AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/tdx-quote-broker ./tdx-quote-broker

WORKDIR /src/tdx-cli
RUN CGO_ENABLED=1 \
        CGO_CFLAGS="-O2 -D_FORTIFY_SOURCE=2 -fstack-protector-all" \
        go build -buildmode=pie -trimpath \
            -ldflags "-s -linkmode=external -extldflags '-Wl,-O1,-z,relro,-z,lazy'" \
            -o /out/trustauthority-cli .

FROM ubuntu:24.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/tdx-quote-broker /usr/local/bin/tdx-quote-broker
COPY --from=builder /out/trustauthority-cli /usr/local/bin/trustauthority-cli

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/tdx-quote-broker", "--healthcheck"]

USER 0:0
ENTRYPOINT ["/usr/local/bin/tdx-quote-broker"]