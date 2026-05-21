# consumer image — Java PKCS11 (SunPKCS11 provider).
# OpenJDK 17 ships a built-in PKCS11 provider that loads a native
# module via a config file. We point it at the shim.

FROM pkcs11-proxy-ng:test-alpine3.23 AS pkcs11ng

FROM alpine:3.23

RUN apk add --no-cache bash opensc openjdk17-jdk libgcc

RUN --mount=type=bind,from=pkcs11ng,source=/apk,target=/apk \
    apk --no-cache add --allow-untrusted --repository /apk \
        pkcs11-proxy-ng-shim \
        pkcs11-proxy-ng-cli

COPY pkcs11-proxy-ng/tests/consumers/harnesses/java /harness
COPY pkcs11-proxy-ng/tests/consumers/scripts /scripts
RUN chmod +x /scripts/*.sh \
 && cd /harness && javac Harness.java && jar cf /usr/local/lib/harness.jar *.class

ENV PKCS11_MODULE_PATH=/usr/lib/pkcs11/libpkcs11_proxy_ng_shim.so
WORKDIR /work
CMD ["sleep", "infinity"]
