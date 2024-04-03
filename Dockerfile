ARG SRVC_DIR="/root/kesl-service"
ARG PATH="/sbin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin"

FROM  oraclelinux:9 as deploy

ARG PATH
ARG SRVC_DIR
#
# proxy (optional)
#
# ENV http_proxy=http://user:password@server:port/
# ENV https_proxy=http://user:password@server:port/

ADD kesl-12.0.0-6672.x86_64.rpm /
ADD klnagent.rpm /
ADD repo.ext /etc/yum.repos.d/new.repo
RUN yum update -y && \
    yum -y install perl which python3-pip podman openssl && yum clean all   && \
    pip3 install --no-cache-dir --default-timeout=100 flask           && \
    pip3 install --no-cache-dir --default-timeout=100 waitress        && \
    pip3 install --no-cache-dir --default-timeout=100 pyyaml          && \
    pip3 install --no-cache-dir --default-timeout=100 requests        && \
    pip3 install --no-cache-dir --default-timeout=100 setuptools      && \
    pip3 install --no-cache-dir --default-timeout=100 validators      && \
    pip3 install --no-cache-dir --default-timeout=100 pydantic        && \
    pip3 install --no-cache-dir --default-timeout=100 python-dateutil
RUN rpm -ivh /klnagent.rpm /kesl-12.0.0-6672.x86_64.rpm
RUN ["rm", "/klnagent.rpm", "/kesl-12.0.0-6672.x86_64.rpm"]

FROM scratch

ARG PATH
ARG SRVC_DIR
ENV KESL_MODE=docker
LABEL maintainer="Kaspersky <support@kaspersky.com>"

COPY --from=deploy / /
COPY /kesl-service $SRVC_DIR
RUN chmod +x $SRVC_DIR/startup.sh

EXPOSE 8085
WORKDIR $SRVC_DIR
ENTRYPOINT ["python3", "main.py"]
