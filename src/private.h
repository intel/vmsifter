/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#ifndef PRIVATE_H
#define PRIVATE_H

#define _GNU_SOURCE
#include <fcntl.h>
#include <getopt.h>
#include <glib.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <unistd.h>

#include <libxl.h>
#include <xenctrl.h>

#include "signal.h"
#include "vmi.h"
#include "forkvm.h"

extern char *domain;
extern uint32_t domid;

extern xc_interface *xc;
extern vmi_instance_t vmi;
extern addr_t target_pagetable;
extern addr_t start_rip;
extern page_mode_t pm;
extern int interrupted;
extern bool debug;

#endif
