ARG KEYCLOAK_VERSION=26.7.2

FROM maven:3.9.11-eclipse-temurin-21 AS registration-gate-builder
WORKDIR /src
COPY extensions/codestra-registration-gate/ ./
RUN mvn --batch-mode --no-transfer-progress -DskipTests package

FROM quay.io/keycloak/keycloak:${KEYCLOAK_VERSION} AS builder

ENV KC_DB=postgres \
    KC_HEALTH_ENABLED=true \
    KC_METRICS_ENABLED=true

COPY --from=registration-gate-builder /src/target/codestra-registration-gate-1.0.0.jar /opt/keycloak/providers/codestra-registration-gate.jar
RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:${KEYCLOAK_VERSION}

COPY --from=builder /opt/keycloak/ /opt/keycloak/

USER 1000

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized"]
