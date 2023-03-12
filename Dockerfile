FROM openjdk:11
COPY target/authentication-1.0-SNAPSHOT.jar authentication-1.0-SNAPSHOT.jar
ENTRYPOINT exec java -Xmx2g -Xms2g -jar authentication-1.0-SNAPSHOT.jar