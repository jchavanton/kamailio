#!/bin/sh
DIR_PREFIX=`pwd`
CONTAINER=rtp_media_server
IMAGE=rtp_media_server:latest
docker stop ${CONTAINER}
docker rm ${CONTAINER}
docker run -d --net=host --name=${CONTAINER} ${IMAGE} /bin/sh -c "tail -f /dev/null"

