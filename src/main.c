/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: MIT
 */

#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include "private.h"

bool debug;
static registers_t start_regs;

static xc_vcpumsr_t perfct_msrs[] = {
    // Fixed perf counters
    { .index = 0x309 }, // IA32_FIXED_CTR0
    { .index = 0x30a }, // IA32_FIXED_CTR1
    { .index = 0x30b }, // IA32_FIXED_CTR2
    // Programmable perf counters
    { .index = 0xc1 }, // IA32_PMC0 (PERFCTR0)
    { .index = 0xc2 }, // IA32_PMC1 (PERFCTR1)
    { .index = 0xc3 }, // IA32_PMC2 (PERFCTR2)
    { .index = 0xc4 }, // IA32_PMC3 (PERFCTR3)
};
#define NUMBER_OF_PERF_COUNTERS sizeof(perfct_msrs)/sizeof(xc_vcpumsr_t)
#define DEFAULT_PINNED_CPU 0

enum regs {
    _RIP,
    _RAX,
    _RBX,
    _RCX,
    _RDX,
    _RSI,
    _RDI,
    _RSP,
    _RBP,
    _R8,
    _R9,
    _R10,
    _R11,
    _R12,
    _R13,
    _R14,
    _R15,
    _CR2,
    NUMBER_OF_REGISTERS
};

struct init_reg {
    unsigned int libvmi_id;
    uint64_t init_val;
    const char* name;
};

static struct init_reg init_regs[NUMBER_OF_REGISTERS] = {
    [_RIP] = { .libvmi_id = RIP, .init_val = ~0, .name = "rip" }, // by default set to the tlb_fill address
    [_RAX] = { .libvmi_id = RAX, .init_val = 0x1100 + _RAX, .name = "rax" },
    [_RBX] = { .libvmi_id = RBX, .init_val = 0x1100 + _RBX, .name = "rbx" },
    [_RCX] = { .libvmi_id = RCX, .init_val = 0x1100 + _RCX, .name = "rcx" },
    [_RDX] = { .libvmi_id = RDX, .init_val = 0x1100 + _RDX, .name = "rdx" },
    [_RSI] = { .libvmi_id = RSI, .init_val = 0x1100 + _RSI, .name = "rsi" },
    [_RDI] = { .libvmi_id = RDI, .init_val = 0x1100 + _RDI, .name = "rdi" },
    [_RSP] = { .libvmi_id = RSP, .init_val = 0x1100 + _RSP, .name = "rsp" },
    [_RBP] = { .libvmi_id = RBP, .init_val = 0x1100 + _RBP, .name = "rbp" },
    [_R8]  = { .libvmi_id = R8,  .init_val = 0x1100 + _R8,  .name = "r8" },
    [_R9]  = { .libvmi_id = R9,  .init_val = 0x1100 + _R9,  .name = "r9" },
    [_R10] = { .libvmi_id = R10, .init_val = 0x1100 + _R10, .name = "r10" },
    [_R11] = { .libvmi_id = R11, .init_val = 0x1100 + _R11, .name = "r11" },
    [_R12] = { .libvmi_id = R12, .init_val = 0x1100 + _R12, .name = "r12" },
    [_R13] = { .libvmi_id = R13, .init_val = 0x1100 + _R13, .name = "r13" },
    [_R14] = { .libvmi_id = R14, .init_val = 0x1100 + _R14, .name = "r14" },
    [_R15] = { .libvmi_id = R15, .init_val = 0x1100 + _R15, .name = "r15" },
    [_CR2] = { .libvmi_id = CR2, .init_val = 0x1100 + _CR2, .name = "cr2" },
};

static const unsigned int unset_hvm_params[] =
{
    HVM_PARAM_STORE_PFN,
    HVM_PARAM_STORE_EVTCHN,
    HVM_PARAM_CONSOLE_PFN,
    HVM_PARAM_IOREQ_PFN,
    HVM_PARAM_BUFIOREQ_PFN,
    HVM_PARAM_CONSOLE_EVTCHN,
    HVM_PARAM_PAGING_RING_PFN,
    HVM_PARAM_IDENT_PT,
    HVM_PARAM_CONSOLE_PFN,
    HVM_PARAM_ACPI_IOPORTS_LOCATION,
    HVM_PARAM_VM_GENERATION_ID_ADDR,
    HVM_PARAM_CALLBACK_IRQ,
};

struct __attribute__ ((__packed__)) InjectorInputMessage {
    uint32_t insn_size;
    unsigned char insn[];
};

struct __attribute__ ((__packed__)) InjectorResultMessage {
    uint64_t reason;
    uint64_t qualification;
    uint64_t stack_value;
    uint64_t perfct[NUMBER_OF_PERF_COUNTERS];
    uint64_t regs[NUMBER_OF_REGISTERS];
    uint64_t gla;
    uint32_t intr_info;
    uint32_t intr_error;
    uint32_t vec_info;
    uint32_t vec_error;
    uint32_t insn_size;
    uint32_t insn_info;
};

struct config {
    int sockfd;
    FILE *inputfd;
    uint64_t perfct_init_value[NUMBER_OF_PERF_COUNTERS];
    struct InjectorInputMessage input_msg;
    struct InjectorResultMessage result_msg;
};

static bool mtf, drizzler;
static bool enable_sse, enable_syscall, enable_fpu_emulation;
static unsigned int insn_buf_size;
static uint64_t perfct_config[4];
static uint16_t pinned_cpu;
static vmi_event_t singlestep_event, cpuid_event, exit_event, mem_event;

static GHashTable *pagetable_pages;
static void populate_pagetable_pages(vmi_instance_t vmi, addr_t pt, addr_t va);

static event_response_t cpuid_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    event->x86_regs->rip += event->cpuid_event.insn_length;

    if ( event->cpuid_event.leaf == 0x13371337 )
    {
        switch ( event->cpuid_event.subleaf )
        {
        case 0:
            vmi_pause_vm(vmi);

            interrupted = 1;

            unsigned int i;
            for ( i = 0; i < sizeof(unset_hvm_params)/sizeof(unsigned int); i++ )
                xc_hvm_param_set(xc, domid, unset_hvm_params[i], 0);

            for ( i = 0; i < NUMBER_OF_REGISTERS; i++ )
                vmi_set_vcpureg(vmi, init_regs[i].init_val, init_regs[i].libvmi_id, event->vcpu_id);

            xc_vcpu_get_msrs(xc, domid, 0, NUMBER_OF_PERF_COUNTERS, (xc_vcpumsr_t *)&perfct_msrs);
            if ( debug )
                for ( unsigned i=0; i<NUMBER_OF_PERF_COUNTERS; i++ )
                    printf("[%d] Perfct[%x] parent value: %lu\n", pinned_cpu, perfct_msrs[i].index, perfct_msrs[i].value);

            if ( debug ) printf("[%d] Parent setup complete.\n", pinned_cpu);
            return 0;

        case 1:
            event->x86_regs->rax = perfct_config[0];
            event->x86_regs->rbx = perfct_config[1];
            event->x86_regs->rcx = perfct_config[2];
            event->x86_regs->rdx = perfct_config[3];
            if ( debug )
                printf("[%d] Sending performance counter settings %lx %lx %lx %lx.\n",
                   pinned_cpu,
                   perfct_config[0],
                   perfct_config[1],
                   perfct_config[2],
                   perfct_config[3]);
            break;

        case 2:
            event->x86_regs->rax = enable_sse;
            if ( debug ) printf("[%d] Sending SSE setting %i.\n", pinned_cpu, enable_sse);
            break;

        case 3:
            event->x86_regs->rax = enable_syscall;
            if ( debug ) printf("[%d] Sending SYSCALL setting %i.\n", pinned_cpu, enable_syscall);
            break;

        case 4:
            event->x86_regs->rax = enable_fpu_emulation;
            if ( debug ) printf("[%d] Sending FPU Emulation setting %i.\n", pinned_cpu, enable_fpu_emulation);
            break;

        default:
            break;
        }
    }

    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}

static void setup_parent(uint32_t domid, char *perfcts, char *init_regs_override)
{
    if ( !(xc = xc_interface_open(0, 0, 0)) )
    {
        perror("Failed to grab xc interface\n");
        return;
    }

    if ( !setup_vmi(&vmi, NULL, domid, true, false) )
    {
        perror("Failed to initialize\n");
        return;
    }

    if ( perfcts )
    {
        int c = 0;
        char *token = strtok(perfcts, ",");
        while ( token && c < 4 )
        {
            perfct_config[c++] = strtoull(token, NULL, 0);
            token = strtok(NULL, ",");
        }
    }

    if ( init_regs_override )
    {
        char *regs = strtok(init_regs_override, ":");
        do
        {
            unsigned i = 0;
            for ( ; i < NUMBER_OF_REGISTERS; i++ )
            {
                if ( strcmp(regs, init_regs[i].name) )
                    continue;
                break;
            }

            if ( i >= NUMBER_OF_REGISTERS )
            {
                printf("[%d] '%s' is invalid as a register name\n", pinned_cpu, regs);
                return;
            }

            regs = strtok(NULL, ",");

            if ( !regs )
            {
                printf("[%d] No value provided for register %s initialization\n", pinned_cpu, init_regs[i].name);
                return;
            }

            init_regs[i].init_val = strtoull(regs, NULL, 0);
        } while ( (regs = strtok(NULL, ":")) );
    }

    cpuid_event.version = VMI_EVENTS_VERSION;
    cpuid_event.type = VMI_EVENT_CPUID;
    cpuid_event.callback = cpuid_cb;

    if ( VMI_FAILURE == vmi_register_event(vmi, &cpuid_event) )
        return;

    loop(vmi);

    vmi_destroy(vmi);
    xc_interface_close(xc);
}

/*
 * Trigger full dedup of the underlying pages
 */
static inline void page_dedup(vmi_instance_t vmi, addr_t addr, vmi_mem_access_t perm)
{
    uint8_t tmp = ~0;
    vmi_read_8_pa(vmi, addr, &tmp);
    vmi_write_8_pa(vmi, addr, &tmp);
    vmi_set_mem_event(vmi, addr>>12, perm, 0);
}

static void setup_memory(vmi_instance_t vmi)
{
    /* populate ept entries with shared pages and set permissions */
    page_dedup(vmi, start_regs.x86.idtr_base, VMI_MEMACCESS_WX);
    page_dedup(vmi, start_regs.x86.gdtr_base, VMI_MEMACCESS_WX);
    page_dedup(vmi, start_regs.x86.rsp, VMI_MEMACCESS_X);

    for ( unsigned long i = 2; i<0xa; i++ )
        page_dedup(vmi, i<<12, VMI_MEMACCESS_RW);

    /* populate pagetable pages with deduped pages so we won't get vmexit for a/d bit setting */
    if ( vmi_get_page_mode(vmi, 0) != VMI_PM_NONE )
    {
        for ( unsigned long i = 1; i<0xa; i++ )
            populate_pagetable_pages(vmi, start_regs.x86.cr3, i << 12); // where we may inject code to

        populate_pagetable_pages(vmi, start_regs.x86.cr3, start_regs.x86.rsp);
    }

    /* for drizzler we make more pages readable */
    if ( drizzler )
        for (unsigned long i = 0xB; i<0x20; i++ )
        {
            uint8_t canary[] = { [0 ... 0x1000] = 0x41 };
            vmi_write_pa(vmi, i << 12, 0x1000, &canary, NULL);
            vmi_set_mem_event(vmi, i, VMI_MEMACCESS_X, 0);
            if ( vmi_get_page_mode(vmi, 0) != VMI_PM_NONE )
            {
                populate_pagetable_pages(vmi, start_regs.x86.cr3, i<<12);
            }
        }

    vmi_set_mem_event(vmi, 0, VMI_MEMACCESS_RWX, 0);
}

static event_response_t exit_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    struct config *conf = (struct config *)event->data;
    struct InjectorInputMessage *input_msg = &conf->input_msg;
    struct InjectorResultMessage *result_msg = &conf->result_msg;

    xc_vcpu_get_msrs(xc, vmi_get_vmid(vmi), event->vcpu_id, NUMBER_OF_PERF_COUNTERS, (xc_vcpumsr_t *)&perfct_msrs);

    if ( debug )
    {
        printf("[%d] vmexit: ", pinned_cpu);

        for (unsigned int i = 0; i<input_msg->insn_size;i++)
            printf("%.2x", input_msg->insn[i]);

         printf(", cpu_len: %u, info: %u, exit: %lu, qual: %lx, intr_info: %u, intr_vector: %llx, intr_error: %u, gla: %lx, rip: %lx, rsp: %lx, cr2: %lx, rcx: %lx, rax: %lx",
                event->vmexit_event.instruction_length,
                event->vmexit_event.instruction_info,
                event->vmexit_event.reason,
                event->vmexit_event.qualification,
                event->vmexit_event.interruption_info,
                event->vmexit_event.interruption_info & VMI_BIT_MASK(0,7),
                event->vmexit_event.interruption_error,
                event->vmexit_event.gla,
                event->x86_regs->rip,
                event->x86_regs->rsp,
                event->x86_regs->cr2,
                event->x86_regs->rcx,
                event->x86_regs->rax
                );

        for (unsigned int i=0; i<NUMBER_OF_PERF_COUNTERS; i++ )
           printf(", perfct[%x]: %lu", perfct_msrs[i].index, perfct_msrs[i].value - conf->perfct_init_value[i]);

        printf("\n");
    }

    if ( conf->sockfd )
    {
        result_msg->reason = event->vmexit_event.reason;
        result_msg->qualification = event->vmexit_event.qualification;
        result_msg->gla = event->vmexit_event.gla;
        result_msg->intr_info = event->vmexit_event.interruption_info;
        result_msg->intr_error = event->vmexit_event.interruption_error;
        result_msg->vec_info = event->vmexit_event.idt_vectoring_info;
        result_msg->vec_error = event->vmexit_event.idt_vectoring_error;
        result_msg->insn_size = event->vmexit_event.instruction_length;
        result_msg->insn_info = event->vmexit_event.instruction_info;

        result_msg->regs[_RIP] = event->x86_regs->rip;
        result_msg->regs[_RSP] = event->x86_regs->rsp;
        result_msg->regs[_RAX] = event->x86_regs->rax;
        result_msg->regs[_RBX] = event->x86_regs->rbx;
        result_msg->regs[_RCX] = event->x86_regs->rcx;
        result_msg->regs[_RDX] = event->x86_regs->rdx;
        result_msg->regs[_RSI] = event->x86_regs->rsi;
        result_msg->regs[_RDI] = event->x86_regs->rdi;
        result_msg->regs[_RSP] = event->x86_regs->rsp;
        result_msg->regs[_RBP] = event->x86_regs->rbp;
        result_msg->regs[_R8] = event->x86_regs->r8;
        result_msg->regs[_R9] = event->x86_regs->r9;
        result_msg->regs[_R10] = event->x86_regs->r10;
        result_msg->regs[_R11] = event->x86_regs->r11;
        result_msg->regs[_R12] = event->x86_regs->r12;
        result_msg->regs[_R13] = event->x86_regs->r13;
        result_msg->regs[_R14] = event->x86_regs->r14;
        result_msg->regs[_R15] = event->x86_regs->r15;
        result_msg->regs[_CR2] = event->x86_regs->cr2;

        for ( unsigned i=0; i<NUMBER_OF_PERF_COUNTERS; i++ )
            result_msg->perfct[i] = perfct_msrs[i].value - conf->perfct_init_value[i];

        ACCESS_CONTEXT(ctx,
            .translate_mechanism = event->page_mode == VMI_PM_NONE ? VMI_TM_NONE : VMI_TM_PROCESS_DTB,
            .addr = event->x86_regs->rsp,
            .pt = event->x86_regs->cr3);
        vmi_read_64(vmi, &ctx, &result_msg->stack_value);

        // send message
        int sockfd = conf->sockfd;
        unsigned int sr = send(sockfd, result_msg, sizeof(struct InjectorResultMessage), 0);
        if ( sr != sizeof(struct InjectorResultMessage) )
            goto error;

        // wait for reply from Python frontend
        
        ssize_t res = recv(sockfd, input_msg->insn, insn_buf_size, 0);
        if (res < 0) {
            // connection closed
            perror("recv");
            goto error;
        }
        input_msg->insn_size = res;
    }

    if ( conf->inputfd )
        input_msg->insn_size = fread(input_msg->insn, 1, insn_buf_size, conf->inputfd);

    if ( !input_msg->insn_size ) goto error;

    if ( debug )
    {
        printf("[%d] Received buffer size %u: ", pinned_cpu, input_msg->insn_size);
        for (unsigned int i=0; i<input_msg->insn_size;i++)
            printf("%.2x", input_msg->insn[i]);
        printf("\n");
    }

    ACCESS_CONTEXT(ctx,
        .pm = event->page_mode,
        .pt = start_regs.x86.cr3);

    ctx.addr = 0xa000 - input_msg->insn_size;
    if ( VMI_FAILURE == vmi_write(vmi, &ctx, input_msg->insn_size, &input_msg->insn, NULL) )
    {
        perror("Write new instruction failed\n");
        goto error;
    }

    memcpy(event->x86_regs, &start_regs.x86, sizeof(x86_registers_t));
    event->x86_regs->rip = 0xa000 - input_msg->insn_size; // set RIP to the new instruction start address

    return VMI_EVENT_RESPONSE_RESET_FORK_STATE | VMI_EVENT_RESPONSE_SET_REGISTERS;

error:
    interrupted = 1;
    vmi_pause_vm(vmi);
    return 0;
}

void save_page(addr_t addr)
{
    if ( !g_hash_table_lookup(pagetable_pages, GSIZE_TO_POINTER(addr >> 12)) )
        g_hash_table_insert(pagetable_pages, GSIZE_TO_POINTER(addr >> 12), GINT_TO_POINTER(1));
}

/*
 * Pagetables in the guest should be deduplicated and mapped r/w in EPT
 */
static void populate_pagetable_pages(vmi_instance_t vmi, addr_t pt, addr_t va)
{
    page_info_t info = {0};
    if ( VMI_FAILURE == vmi_pagetable_lookup_extended(vmi, pt, va, &info) )
        return;

    switch ( info.pm ) {
        case VMI_PM_LEGACY:
        case VMI_PM_PAE:
        case VMI_PM_IA32E:
            break;
        default:
            return;
    };

    save_page(info.pt);
    page_dedup(vmi, info.pt, VMI_MEMACCESS_WX);
    save_page(info.x86_legacy.pte_location);
    page_dedup(vmi, info.x86_legacy.pte_location, VMI_MEMACCESS_WX);
    save_page(info.x86_legacy.pgd_location);
    page_dedup(vmi, info.x86_legacy.pgd_location, VMI_MEMACCESS_WX);

    if ( info.pm == VMI_PM_LEGACY )
        return;

    save_page(info.x86_pae.pdpe_location);
    page_dedup(vmi, info.x86_pae.pdpe_location, VMI_MEMACCESS_WX);

    if ( info.pm == VMI_PM_PAE )
        return;

    save_page(info.x86_ia32e.pml4e_location);
    page_dedup(vmi, info.x86_ia32e.pml4e_location, VMI_MEMACCESS_WX);
}

static void fuzz(uint32_t domid, char *input, char *sock, uint16_t pinned_cpu)
{
    struct config *conf = NULL;
    int sockfd = 0;
    FILE *inputfd = NULL;
    uint32_t forkid = 0;

    if ( sock )
    {
        // create Unix socket
        if (((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)) {
            perror("socket");
            return;
        }
        // set server address
        struct sockaddr_un server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sun_family = AF_UNIX;
        strncpy(server_addr.sun_path, sock, sizeof(server_addr.sun_path) - 1);
        socklen_t server_addr_len = sizeof(server_addr);

        // connect to server
        if (connect(sockfd, (struct sockaddr*)&server_addr, server_addr_len) == -1) {
            perror("connect");
            goto done;
        }
    } else if ( input && !(inputfd = fopen(input, "r")) )
    {
        perror("Failed to open input\n");
        goto done;
    }

    pagetable_pages = g_hash_table_new(g_direct_hash, g_direct_equal);
    if ( ! pagetable_pages )
        goto done;

    if ( !(xc = xc_interface_open(0, 0, 0)) )
    {
        perror("Failed to grab xc interface\n");
        goto done;
    }
    
    if ( !fork_vm(domid, &forkid, pinned_cpu) )
    {
        perror("Forking failed\n");
        goto done;
    }

    if ( !setup_vmi(&vmi, NULL, forkid, true, true) )
    {
        perror("Failed to initialize\n");
        goto done;
    }

    if ( VMI_FAILURE == vmi_get_vcpuregs(vmi, &start_regs, 0) )
        goto done;

    if ( debug )
    {
        printf("[%d] CR3: 0x%lx\n", pinned_cpu, start_regs.x86.cr3);
        printf("[%d] RSP: 0x%lx\n", pinned_cpu, start_regs.x86.rsp);
        printf("[%d] IDT: 0x%lx\n", pinned_cpu, start_regs.x86.idtr_base);
        printf("[%d] GDT: 0x%lx\n", pinned_cpu, start_regs.x86.gdtr_base);
    }

    conf = malloc(sizeof(struct config) + insn_buf_size);
    memset(conf, 0, sizeof(struct config) + insn_buf_size);

    conf->inputfd = inputfd;
    conf->sockfd = sockfd;

    xc_vcpu_get_msrs(xc, forkid, 0, sizeof(perfct_msrs)/sizeof(xc_vcpumsr_t), (xc_vcpumsr_t *)&perfct_msrs);
    for ( unsigned i=0; i<NUMBER_OF_PERF_COUNTERS; i++ )
    {
        conf->perfct_init_value[i] = perfct_msrs[i].value;
        if ( debug ) printf("[%d] Perfct[%x] init value: %lu\n", pinned_cpu, perfct_msrs[i].index, perfct_msrs[i].value);
    }

    exit_event.version = VMI_EVENTS_VERSION;
    exit_event.type = VMI_EVENT_VMEXIT;
    exit_event.callback = exit_cb;
    exit_event.data = conf;
    exit_event.vmexit_event.sync = 1;

    if ( mtf )
    {
        SETUP_SINGLESTEP_EVENT(&singlestep_event, 1, exit_cb, 1);
        vmi_register_event(vmi, &singlestep_event);
    }

    /* allow setting ept permission, we won't actually get callbacks */
    SETUP_MEM_EVENT(&mem_event, ~0ull, VMI_MEMACCESS_RWX, exit_cb, 1);
    if ( VMI_FAILURE == vmi_register_event(vmi, &mem_event) )
        goto done;

    setup_memory(vmi);
    vmi_register_event(vmi, &exit_event);

    loop(vmi);

done:
    if ( pagetable_pages )
        g_hash_table_destroy(pagetable_pages);
    if ( conf )
        free(conf);
    if ( inputfd )
        fclose(inputfd);
    if ( sockfd )
        close(sockfd);
    if ( vmi )
    {
        if ( mtf ) vmi_clear_event(vmi, &singlestep_event, NULL);
        vmi_clear_event(vmi, &mem_event, NULL);
        vmi_clear_event(vmi, &exit_event, NULL);
        vmi_destroy(vmi);
    }
    if ( xc )
    {
        xc_domain_destroy(xc, forkid);
        xc_interface_close(xc);
    }
}

static void help(void)
{
    printf("vmsifter\n");
}

int main(int argc, char** argv)
{
    bool setup = false;
    char *input = NULL, *sock = NULL;
    pinned_cpu = DEFAULT_PINNED_CPU;
    printf("VMSifter C starts\n");

    int c, long_index = 0;
    const struct option long_opts[] =
    {
        {"help", no_argument, NULL, 'h'},
        {"debug", no_argument, NULL, 'D'},
        {"domid", required_argument, NULL, 'd'},
        {"setup", no_argument, NULL, 's'},
        {"input", required_argument, NULL, 'i'},
        {"socket", required_argument, NULL, 'S'},
        {"perfcts", required_argument, NULL, 'c'},
        {"sse", no_argument, NULL, 'e'},
        {"syscall", no_argument, NULL, 'l'},
        {"fpu-emulation", no_argument, NULL, 'f'},
        {"insn-buf-size", required_argument, NULL, 'm'},
        {"mtf", no_argument, NULL, 't'},
        {"drizzler", no_argument, NULL, 'z'},
        {"regs-init-value", required_argument, NULL, 'r'},
        {"pin-cpu", required_argument, NULL, 'p'},
        {NULL, 0, NULL, 0}
    };
    const char* opts = "hd:si:c:elfm:tzr:D";

    // read domid from env by default
    char* envvar = getenv("VMSIFTER_DOMID");
    if (envvar) {
        domid = atoi(envvar);
    }

    char* perfcts = getenv("VMSIFTER_PERFCTS");
    char* init_regs_override = getenv("VMSIFTER_INIT_REGS");
    enable_sse = atoi(getenv("VMSIFTER_ENABLE_SSE")?:"1");
    enable_syscall = atoi(getenv("VMSIFTER_ENABLE_SYSCALL")?:"1");
    enable_fpu_emulation = atoi(getenv("VMSIFTER_ENABLE_FPU_EMULATION")?:"0");
    insn_buf_size = atoi(getenv("VMSIFTER_INSN_BUF_SIZE")?:"15");

    while ((c = getopt_long (argc, argv, opts, long_opts, &long_index)) != -1)
    {
        switch(c)
        {
        case 'h':
            help();
            return 0;
        case 'D':
            debug = 1;
            break;
        case 'd':
            domid = atoi(optarg);
            break;
        case 's':
            setup = true;
            break;
        case 'i':
            input = optarg;
            break;
        case 'c':
            perfcts = optarg;
            break;
        case 'S':
            sock = optarg;
            break;
        case 'e':
            enable_sse = 1;
            break;
        case 'l':
            enable_syscall = 1;
            break;
        case 'f':
            enable_fpu_emulation = 1;
            break;
        case 'm':
            insn_buf_size = atoi(optarg);
            break;
        case 't':
            mtf = 1;
            break;
        case 'z':
            drizzler = 1;
            break;
        case 'r':
            init_regs_override = optarg;
            break;
        case 'p':
            pinned_cpu = atoi(optarg);
            break;
        default:
            break;
        }
    }

    if ( !domid )
    {
        perror("Must specify either domid or domain\n");
        return 1;
    }

    if ( !setup && !input && !sock)
    {
        perror("Need either --setup or --input or --socket\n");
        return 1;
    }

    setup_signal_handlers();

    if ( setup )
        setup_parent(domid, perfcts, init_regs_override);
    else
        fuzz(domid, input, sock, pinned_cpu);

    return 0;
}
