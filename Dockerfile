FROM openjdk:8-jdk-alpine
COPY target/authentication-1.0-SNAPSHOT.jar authentication-1.0-SNAPSHOT.jar
ENTRYPOINT ["java","-jar","/authentication-1.0-SNAPSHOT.jar"]
