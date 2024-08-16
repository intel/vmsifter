/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: MIT
 */

#include "private.h"

bool setup_vmi(vmi_instance_t *vmi, char* domain, uint64_t domid, bool init_events, bool init_paging)
{
    if ( debug )
        printf("Init vmi, init_events: %i init_paging %i domain %s domid %lu\n",
            init_events, init_paging, domain, domid);

    uint64_t options = (init_events ? VMI_INIT_EVENTS : 0) |
        (domain ? VMI_INIT_DOMAINNAME : VMI_INIT_DOMAINID);
    vmi_mode_t mode = VMI_XEN;
    const void *d = domain ?: (void*)&domid;

    status_t status = vmi_init(vmi, mode, d, options, NULL, NULL);

    if ( VMI_FAILURE == status )
        return false;

    if ( init_paging && VMI_PM_UNKNOWN == (pm = vmi_init_paging(*vmi, 0)) )
    {
        fprintf(stderr, "Error in vmi_init_paging!\n");
        vmi_destroy(*vmi);
        return false;
    }

    registers_t regs = {0};
    if ( VMI_FAILURE == vmi_get_vcpuregs(*vmi, &regs, 0) )
    {
        fprintf(stderr, "Error in vmi_get_vcpuregs!\n");
        vmi_destroy(*vmi);
        return false;
    }

    target_pagetable = regs.x86.cr3;
    start_rip = regs.x86.rip;

    return true;
}

void loop(vmi_instance_t vmi)
{
    if ( !vmi )
        return;

    vmi_resume_vm(vmi);

    while (!interrupted)
    {
        if ( vmi_events_listen(vmi, 100) == VMI_FAILURE )
        {
            fprintf(stderr, "Error in vmi_events_listen!\n");
            break;
        }
    }

    interrupted = 0;
}
