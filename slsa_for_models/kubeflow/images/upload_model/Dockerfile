FROM gcr.io/google.com/cloudsdktool/cloud-sdk:551.0.0-slim@sha256:a13dd2915c13546d0b01fe620b5fa72caee799b23722995420a715225266aed6
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install coreutils -y
COPY . /src
WORKDIR /src
RUN chmod +x /src/upload.sh
