/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#include "private.h"

static struct sigaction act;

static void close_handler(int sig)
{
    printf("Close signal received\n");
    interrupted = sig;

    if ( vmi )
        vmi_pause_vm(vmi);
}

void setup_signal_handlers(void)
{
    act.sa_handler = close_handler;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);
}
