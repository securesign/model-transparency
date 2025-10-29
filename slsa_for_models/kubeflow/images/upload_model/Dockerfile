FROM gcr.io/google.com/cloudsdktool/cloud-sdk:545.0.0-slim@sha256:3e441df6b51810d6a4e704408686f342a986c5f1cbaeea3b14cd7124945dfced
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install coreutils -y
COPY . /src
WORKDIR /src
RUN chmod +x /src/upload.sh
