/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#include "forkvm.h"
#include "private.h"

extern xc_interface *xc;

static bool pin_fork(uint32_t domid, uint32_t forkdomid, uint16_t pinned_cpu)
{
    // unused parameter
    // keeping it if we switch to xenctrl API in the future
    domid = domid;
    // use xl toolstack as xenctrl API is hard to figure out / work with
    char cmd[128] = {'\0'};
    // keyword "all" is used to apply the affinity to all VCPUs
    // Note: --force and 'all' as VCPU not allowed
    sprintf(cmd, "sudo xl vcpu-pin --ignore-global-affinity-masks %d all %d -", forkdomid, pinned_cpu);
    if (debug)
        printf("[%d] Executing: %s\n", pinned_cpu, cmd);
    if (system(cmd)) {
        printf("[%d] xl vcpu-pin failed.\n", pinned_cpu);
        return false;
    }
    return true;
}

bool fork_vm(uint32_t domid, uint32_t *forkdomid, uint16_t pinned_cpu)
{
    if ( !domid || !forkdomid )
        return false;

    struct xen_domctl_createdomain create = {0};
    create.flags |= XEN_DOMCTL_CDF_hvm;
    create.flags |= XEN_DOMCTL_CDF_hap;
    create.flags |= XEN_DOMCTL_CDF_oos_off;
    //create.flags |= XEN_DOMCTL_CDF_nested_virt;
    create.arch.emulation_flags = (XEN_X86_EMU_ALL & ~XEN_X86_EMU_VPCI);
    create.ssidref = 11; // SECINITSID_DOMU
    create.max_vcpus = 1;
    create.max_evtchn_port = 1023;
    create.max_grant_frames = LIBXL_MAX_GRANT_FRAMES_DEFAULT;
    create.max_maptrack_frames = LIBXL_MAX_MAPTRACK_FRAMES_DEFAULT;
    create.grant_opts = 2;

    if ( xc_domain_create(xc, forkdomid, &create) )
        return false;

    if ( xc_memshr_fork(xc, domid, *forkdomid, true, true) )
    {
        printf("[%d] Failed to create fork\n", pinned_cpu);
        xc_domain_destroy(xc, *forkdomid);
        return false;
    }

    if ( !pin_fork(domid, *forkdomid, pinned_cpu) )
    {
        printf("[%d] Failed to pin fork vcpus\n", pinned_cpu);
        return false;
    }

    return true;
}
