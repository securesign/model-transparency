FROM gcr.io/google.com/cloudsdktool/cloud-sdk:547.0.0-slim@sha256:67b0396db626cfbb0c26069ecc958d5935c04e5d985d931425f8578c0c95f2a7
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install coreutils -y
COPY . /src
WORKDIR /src
RUN chmod +x /src/upload.sh
