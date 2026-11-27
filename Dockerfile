ARG JAVA_BASE_IMAGE=eclipse-temurin:21-jre
FROM ${JAVA_BASE_IMAGE}
WORKDIR /app
RUN mkdir /app/data && chown 10001:10001 /app/data
COPY backend/target/threat-detection-0.0.1-SNAPSHOT.jar /app/app.jar
USER 10001:10001
EXPOSE 8081
HEALTHCHECK --interval=30s --timeout=3s --start-period=45s --retries=3 \
    CMD ["bash", "-ec", "exec 3<>/dev/tcp/127.0.0.1/8081; printf 'GET /api/health HTTP/1.0\r\nHost: localhost\r\n\r\n' >&3; read -r version status remainder <&3; test \"$status\" = 200"]
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
