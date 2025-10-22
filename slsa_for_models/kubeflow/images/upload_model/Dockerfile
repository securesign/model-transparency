FROM gcr.io/google.com/cloudsdktool/cloud-sdk:544.0.0-slim@sha256:48b7e0f098781c836cfdd0a352db9e3389114f7b1bbec1fcf3e547b1acc362f5
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install coreutils -y
COPY . /src
WORKDIR /src
RUN chmod +x /src/upload.sh
