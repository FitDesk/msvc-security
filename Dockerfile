# FROM maven:3.9-eclipse-temurin-21 AS build
# WORKDIR /workspace
# COPY . .
# RUN mvn clean package -DskipTests

# FROM eclipse-temurin:21-jre-alpine
# VOLUME /tmp
# RUN apk add --no-cache curl
# COPY --from=build /workspace/target/*.jar app.jar

# EXPOSE 9091
# ENV SPRING_PROFILES_ACTIVE=prod
# CMD ["java", "-jar", "app.jar"]


FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /workspace

COPY security-common ./security-common
WORKDIR /workspace/security-common
RUN mvn clean install -DskipTests -q

WORKDIR /workspace/msvc-security
COPY msvc-security .
RUN mvn clean package -DskipTests -q


FROM eclipse-temurin:21-jre-alpine
VOLUME /tmp

RUN apk add --no-cache curl wget


RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

COPY --from=build /workspace/msvc-security/target/*.jar app.jar

RUN chown appuser:appgroup app.jar

USER appuser

EXPOSE 9091
ENV SPRING_PROFILES_ACTIVE=prod
ENV JAVA_OPTS="-Xmx512m -Xms256m -server"

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:9091/actuator/health || exit 1

CMD ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]