FROM eclipse-temurin:21-jre
WORKDIR /app
RUN mkdir /app/data && chown 10001:10001 /app/data
COPY backend/target/threat-detection-0.0.1-SNAPSHOT.jar /app/app.jar
USER 10001:10001
EXPOSE 8081
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
