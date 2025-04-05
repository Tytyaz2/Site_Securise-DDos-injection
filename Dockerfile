# Use the official OpenJDK 17 slim image as the base
FROM openjdk:17-jdk-slim

# Set Java environment variables
ENV export JAVA_HOME=/usr/lib/jvm/java-17-openjdk/
ENV export PATH=$JAVA_HOME/bin:$PATH

# Install necessary dependencies (wget, unzip)
RUN apt-get update && apt-get install -y \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Gradle
RUN wget https://services.gradle.org/distributions/gradle-7.5.1-bin.zip -P /tmp && \
    unzip /tmp/gradle-7.5.1-bin.zip -d /opt && \
    rm /tmp/gradle-7.5.1-bin.zip && \
    ln -s /opt/gradle-7.5.1/bin/gradle /usr/local/bin/gradle

# Set the working directory inside the container
WORKDIR /app

# Copy the Gradle wrapper and build files
COPY gradlew .
COPY gradle ./gradle
COPY build.gradle.kts .
COPY settings.gradle.kts .

# Copy the source code
COPY src ./src

# Give execute permissions to the gradlew script
RUN chmod +x gradlew

# Run Gradle build and start the app using bootRun
CMD ["./gradlew", "bootRun"]
