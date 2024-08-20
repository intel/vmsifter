#!/bin/bash -x

# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

mkdir -p "$PWD/workdir"
rm $PWD/workdir/results.csv || :

docker run --rm -ti \
    --privileged \
    -e XENSIFTER_X86.EXEC_MODE=64 \
    -e XENSIFTER_MIN_PREFIX_COUNT=0 \
    -e XENSIFTER_MAX_PREFIX_COUNT=1 \
    -e XENSIFTER_INSN_BUF_SIZE=8095 \
    -e XENSIFTER_FUZZER.DRIZZLER.NUM_SEEDS=10 \
    -e XENSIFTER_FUZZER.DRIZZLER.INJECTIONS=4 \
    -v $PWD/workdir:/workdir \
    --user $(id -u):$(id -g) \
    --group-add sudo \
    xensifter --fuzzer-mode DRIZZLER "$@"
