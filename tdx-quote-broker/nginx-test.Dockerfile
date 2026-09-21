FROM golang:1.26.6-bookworm AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

WORKDIR /src/tdx-cli
RUN CGO_ENABLED=1 \
        CGO_CFLAGS="-O2 -D_FORTIFY_SOURCE=2 -fstack-protector-all" \
        go build -buildmode=pie -trimpath \
            -ldflags "-s -linkmode=external -extldflags '-Wl,-O1,-z,relro,-z,lazy'" \
            -o /out/trustauthority-cli .

FROM nginxinc/nginx-unprivileged:1.27.5-bookworm

COPY --from=builder /out/trustauthority-cli /usr/local/bin/trustauthority-cli