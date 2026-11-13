/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: MIT
 */

#include "private.h"

uint32_t domid;

xc_interface *xc;
vmi_instance_t vmi;
int interrupted;

