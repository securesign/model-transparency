FROM gcr.io/google.com/cloudsdktool/cloud-sdk:548.0.0-slim@sha256:17a274eee28444fbdc1ce7410a064943c0dead47042cac07944a9020bd93cbc6
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install coreutils -y
COPY . /src
WORKDIR /src
RUN chmod +x /src/upload.sh
