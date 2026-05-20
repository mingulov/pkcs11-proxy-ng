# R5 daemon image — NSS softokn backend.
# NSS softokn3 is the PKCS#11 token shipped with NSS (Firefox/Chrome's
# crypto). It exposes a different mechanism set than SoftHSM2 (notably
# fewer AES wrap modes, no SHA-3 by default, different DH/EC support).

FROM pkcs11-proxy-ng:test-alpine3.23 AS pkcs11ng

FROM alpine:3.23

# NSS tooling: `certutil` initializes the NSS DB; `softokn3.so` is the
# actual PKCS#11 module the daemon loads.
RUN apk add --no-cache nss nss-tools bash opensc

RUN --mount=type=bind,from=pkcs11ng,source=/apk,target=/apk \
    apk --no-cache add --allow-untrusted --repository /apk \
        pkcs11-proxy-ng-daemon \
        pkcs11-proxy-ng-cli

# NSS DB lives under $NSS_LIB_PARAMS; softokn3 reads it via the
# slot parameters string. We bake a fresh DB at image build time.
ENV NSSDB=/var/lib/nssdb
RUN mkdir -p "$NSSDB" \
 && echo "1234" > /tmp/pin.txt \
 && certutil -N -d "sql:$NSSDB" -f /tmp/pin.txt \
 && rm /tmp/pin.txt

# NSS softokn needs its slot parameters via the C_GetSlotList path —
# we configure that through environment variables read by softokn3.so
# at load time (`NSS_DEFAULT_DB_TYPE=sql`, `NSS_LIB_PARAMS`).
ENV NSS_DEFAULT_DB_TYPE=sql
ENV NSS_LIB_PARAMS="configdir='sql:/var/lib/nssdb' tokenDescription='r5-token' minPWLen=4"

COPY pkcs11-proxy-ng/tests/consumers/proxy.toml /etc/pkcs11-proxy-ng/proxy.toml
RUN sed -i 's|@BACKEND_MODULE@|/usr/lib/libsoftokn3.so|' \
        /etc/pkcs11-proxy-ng/proxy.toml

EXPOSE 7512
ENTRYPOINT ["/usr/bin/pkcs11-proxy-ng", "/etc/pkcs11-proxy-ng/proxy.toml"]
