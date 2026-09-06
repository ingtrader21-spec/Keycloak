ARG KEYCLOAK_BASE_IMAGE=quay.io/keycloak/keycloak:26.7.2@sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067

FROM maven:3.9.11-eclipse-temurin-21 AS extension-builder
WORKDIR /src
COPY extensions/moneybee-email-otp/ ./
RUN mvn --batch-mode --no-transfer-progress -DskipTests package

FROM ${KEYCLOAK_BASE_IMAGE} AS builder
ENV KC_DB=postgres \
    KC_HEALTH_ENABLED=true \
    KC_METRICS_ENABLED=true
COPY --from=extension-builder /src/target/moneybee-email-otp-1.0.0.jar /opt/keycloak/providers/moneybee-email-otp.jar
COPY themes/codestra-identity/ /opt/keycloak/themes/codestra-identity/
RUN /opt/keycloak/bin/kc.sh build

FROM ${KEYCLOAK_BASE_IMAGE}
COPY --from=builder /opt/keycloak/ /opt/keycloak/
USER 1000
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized"]
