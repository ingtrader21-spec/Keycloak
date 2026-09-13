ARG KEYCLOAK_BASE_IMAGE=quay.io/keycloak/keycloak:26.7.2@sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067

FROM scratch AS netty-security-fix
ADD --checksum=sha256:d0e4c6ee4779f59f6ab2fb5d388e4f57147c82270164b37945764bb9bda96a44 \
    https://repo.maven.apache.org/maven2/io/netty/netty-handler/4.1.137.Final/netty-handler-4.1.137.Final.jar \
    /io.netty.netty-handler-4.1.137.Final.jar
ADD --checksum=sha256:0535bb5a736472bef5c948d15eb273c4ab9f796656fc7c5d6b982ad92bddbd49 \
    https://repo.maven.apache.org/maven2/io/netty/netty-codec-http/4.1.137.Final/netty-codec-http-4.1.137.Final.jar \
    /io.netty.netty-codec-http-4.1.137.Final.jar

FROM maven:3.9.11-eclipse-temurin-21@sha256:6fdc855a6ed81d288ca7ca37ac6ff5e9308b612485c0801d70b25a858c83d237 AS extension-builder
WORKDIR /src
COPY extensions/moneybee-email-otp/ ./
RUN mvn --batch-mode --no-transfer-progress verify

FROM ${KEYCLOAK_BASE_IMAGE} AS builder
ENV KC_DB=postgres \
    KC_HEALTH_ENABLED=true \
    KC_METRICS_ENABLED=true
COPY --from=extension-builder /src/target/moneybee-email-otp-1.0.0.jar /opt/keycloak/providers/moneybee-email-otp.jar
COPY themes /opt/keycloak/themes
RUN /opt/keycloak/bin/kc.sh build
USER 0
# Quarkus records the original dependency filenames during augmentation. Keep
# those paths stable while replacing their contents with the fixed artifacts.
COPY --from=netty-security-fix --chown=1000:0 --chmod=0644 /io.netty.netty-handler-4.1.137.Final.jar /opt/keycloak/lib/lib/main/io.netty.netty-handler-4.1.136.Final.jar
COPY --from=netty-security-fix --chown=1000:0 --chmod=0644 /io.netty.netty-codec-http-4.1.137.Final.jar /opt/keycloak/lib/lib/main/io.netty.netty-codec-http-4.1.136.Final.jar
USER 1000

FROM ${KEYCLOAK_BASE_IMAGE}
USER 0
COPY --from=builder /opt/keycloak/ /opt/keycloak/
RUN rm -f /opt/keycloak/lib/lib/main/com.microsoft.sqlserver.mssql-jdbc-*.jar \
    && test -z "$(find /opt/keycloak -type f -name 'com.microsoft.sqlserver.mssql-jdbc-*.jar' -print -quit)" \
    && printf '%s  %s\n%s  %s\n' \
      'd0e4c6ee4779f59f6ab2fb5d388e4f57147c82270164b37945764bb9bda96a44' \
      '/opt/keycloak/lib/lib/main/io.netty.netty-handler-4.1.136.Final.jar' \
      '0535bb5a736472bef5c948d15eb273c4ab9f796656fc7c5d6b982ad92bddbd49' \
      '/opt/keycloak/lib/lib/main/io.netty.netty-codec-http-4.1.136.Final.jar' \
      | sha256sum -c -
USER 1000
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized"]
