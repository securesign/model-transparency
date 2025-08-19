FROM gcr.io/google.com/cloudsdktool/cloud-sdk:534.0.0-slim@sha256:7f729a5f78e980d226cb4bf57944fe669c4b2b226cf7209a4e6814fac8e0309f
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install coreutils -y
COPY . /src
WORKDIR /src
RUN chmod +x /src/upload.sh
