FROM gcr.io/google.com/cloudsdktool/cloud-sdk:539.0.0-slim@sha256:e4becddb20bee30d23af51c892cb537d0a322889a11414aef46f2724630801de
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install coreutils -y
COPY . /src
WORKDIR /src
RUN chmod +x /src/upload.sh
