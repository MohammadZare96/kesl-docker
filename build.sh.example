#!/bin/sh
SERVER_VERSION_FULLY=$(docker version -f "{{.Server.Version}}")
SERVER_VERSION_MAJOR=$(echo "$SERVER_VERSION_FULLY"| cut -d'.' -f 1)
SERVER_VERSION_MINOR=$(echo "$SERVER_VERSION_FULLY"| cut -d'.' -f 2)

# COMMON_ARGS='
#    --build-arg http_proxy=http://user:password@server:port/ 
#    --build-arg https_proxy=http://user:password@server:port/ '
COMMON_ARGS=

if [ "$SERVER_VERSION_MAJOR" -lt 18 ] || ( [ "$SERVER_VERSION_MAJOR" -eq 18 ] && [ "$SERVER_VERSION_MINOR" -lt 9 ] ); then
    echo "($SERVER_VERSION_FULLY) DOCKER VERSION < 18.09 (RUN W/OUT BUILDKIT)"
    docker build $COMMON_ARGS -t kesl-service .
else
    echo "($SERVER_VERSION_FULLY) DOCKER VERSION >= 18.09 (RUN WITH BUILDKIT)"
    DOCKER_BUILDKIT=1 docker build $COMMON_ARGS -t kesl-service -f Dockerfile.1809 .
fi
