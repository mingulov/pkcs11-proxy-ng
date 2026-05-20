# R5 consumer image — Go-based PKCS#11 consumers.
# Bundles: miekg/pkcs11 + ThalesGroup/crypto11 harnesses + the shim.

FROM pkcs11-proxy-ng:test-alpine3.23 AS pkcs11ng

FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git build-base

WORKDIR /src
COPY pkcs11-proxy-ng/tests/consumers/harnesses/go/go.mod ./
COPY pkcs11-proxy-ng/tests/consumers/harnesses/go/go.sum ./
# go.sum might not exist on first build — synthesise with `go mod download`.
RUN if [ ! -f go.sum ]; then touch go.sum; fi
COPY pkcs11-proxy-ng/tests/consumers/harnesses/go/ ./
RUN go mod tidy && go build -o /out/harness_miekg    ./cmd/miekg \
    && go build -o /out/harness_crypto11 ./cmd/crypto11 \
    && go build -o /out/harness_vendor   ./cmd/vendor

FROM alpine:3.23

RUN apk add --no-cache bash opensc libgcc

RUN --mount=type=bind,from=pkcs11ng,source=/apk,target=/apk \
    apk --no-cache add --allow-untrusted --repository /apk \
        pkcs11-proxy-ng-shim \
        pkcs11-proxy-ng-cli

COPY --from=builder /out/harness_miekg    /usr/local/bin/
COPY --from=builder /out/harness_crypto11 /usr/local/bin/
COPY --from=builder /out/harness_vendor   /usr/local/bin/
COPY pkcs11-proxy-ng/tests/consumers/scripts /scripts
RUN chmod +x /scripts/*.sh

ENV PKCS11_MODULE_PATH=/usr/lib/pkcs11/libpkcs11_proxy_ng_shim.so
WORKDIR /work
CMD ["sleep", "infinity"]
