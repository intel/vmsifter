#!/bin/bash

# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

set -e

usage() {
    echo "Usage $0 [options] -- [vmsifter args]"
    echo "Options:"
    echo "  -h, --help          Show this message"
    echo "  -i <ARG>            Use <ARG> Docker image (Default: vmsifter-dev)"
    echo "  -w <ARG>            Set workdir path (Default: $PWD/workdir)"
    echo "  -b <ARG>            Use <ARG> as Dockerfile baseimage (Default: See Dockerfile.dev)"
    echo "  -u <ARG>            Toggle image building (Default: true)"
    echo "  -t <ARG>            Toogle pseudo-tty allocation (Default: true)"
    echo "  -n <ARG>            Name the container as <ARG>"
}

IMAGE="vmsifter-dev"
USER="$(id -u):$(id -g)"
BASEIMAGE=""
WORKDIR_PATH="$PWD/workdir"
IMAGE_BUILD_ENABLED="true"
TTY_ENABLED="true"
CONTAINER_NAME="false"

OPTSTRING=':i:w:b:u:t:n:'
while getopts ${OPTSTRING} opt; do
    case ${opt} in
        i)
            # use dev image
            IMAGE="${OPTARG}"
            ;;
        w)
            # set workdir
            # ensure absolute path
            WORKDIR_PATH="$(realpath ${OPTARG})"
            ;;
        b)
            # use given baseimage
            BASEIMAGE="${OPTARG}"
            ;;
        u)
            # toggle imahe build
            # convert to lowercase
            IMAGE_BUILD_ENABLED="${OPTARG,,}"
            ;;
        t)
            # toggle pseudo-tty allocation
            # convert to lowercase
            TTY_ENABLED="${OPTARG,,}"
            ;;
        n)
            # name the container
            CONTAINER_NAME="${OPTARG}"
            ;;
        --)
            shift
            break
            ;;
        *)
            usage
            exit 1
            ;;
    esac
done

shift "$((OPTIND-1))"

# create workdir directory as current user, otherwise Docker daemon will create it as root
mkdir -p $WORKDIR_PATH

# check if .env to reinject it into the container
ENV_FILE_PARAM=""
if [ -f "$PWD/.env" ]; then
    ENV_FILE_PARAM="--env-file $PWD/.env"
fi

BUILDARG=""
if [ -n "$BASEIMAGE" ]; then
    BUILDARG="--build-arg BASEIMAGE=${BASEIMAGE}"
fi

if [[ "$IMAGE_BUILD_ENABLED" == "true" || "$IMAGE_BUILD_ENABLED" == "yes" ]]; then
    # ensure image is up to date
    docker build \
        ${BUILDARG} \
        --target $IMAGE \
        -t $IMAGE \
        -f Dockerfile \
        .
fi

# try to guess if one of vmsifter args is a file
# then mount it as a volume to expose them transparently
ADDITIONAL_VOLUMES=""
vmsifter_args=("$@")
for i in "${!vmsifter_args[@]}"; do
    # check if existing file
    arg="${vmsifter_args[$i]}"
    if [ -f "$arg" ]; then
        # get abs path
        abs_path=$(realpath "$arg")
        # add it as volume
        ADDITIONAL_VOLUMES+=" -v $abs_path:$abs_path"
        # rewrite vmsifter argument
        vmsifter_args[$i]="$abs_path"
    fi
done

TTY_ARG=""
if [[ "$TTY_ENABLED" == "true" || "$TTY_ENABLED" == "yes" ]]; then
    TTY_ARG="-t"
fi

CONTAINER_NAME_ARG=""
if [[ "$CONTAINER_NAME" != "false" ]]; then
    CONTAINER_NAME_ARG="--name $CONTAINER_NAME"
fi

docker run --rm -i \
    $TTY_ARG \
    --privileged \
    $ENV_FILE_PARAM \
    -v "${WORKDIR_PATH}:/workdir" \
    $ADDITIONAL_VOLUMES \
    --user $USER \
    --group-add sudo \
    $CONTAINER_NAME_ARG \
    $IMAGE "${vmsifter_args[@]}"
