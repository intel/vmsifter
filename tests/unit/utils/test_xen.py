from typing import List

from xensifter.utils.xen import XL, XlInfo, XlVcpuInfo, parse_cfg_prefix_name


def test_parse_info():
    output = """host                   : abc.intel.com
release                : 5.15.0-73-generic
version                : #80~20.04.1-Ubuntu SMP Wed May 17 14:58:14 UTC 2023
machine                : x86_64
nr_cpus                : 56
max_cpu_id             : 111
nr_nodes               : 2
cores_per_socket       : 28
threads_per_core       : 1
cpu_mhz                : 2494.141
virt_caps              : pv hvm hap shadow vmtrace gnttab-v1 gnttab-v2
total_memory           : 522954
free_memory            : 507728
sharing_freed_memory   : 0
sharing_used_memory    : 0
outstanding_claims     : 0
free_cpus              : 0
xen_major              : 4
xen_minor              : 18
xen_extra              : .0
xen_version            : 4.18.0
xen_caps               : xen-3.0-x86_64 hvm-3.0-x86_32 hvm-3.0-x86_32p hvm-3.0-x86_64
xen_scheduler          : credit2
xen_pagesize           : 4096
platform_params        : virt_start=0xffff800000000000
xen_changeset          :
xen_commandline        : placeholder console=vga dom0_mem=10096M hpet=legacy-replacement dom0_max_vcpus=8 dom0_vcpus_pin=1 ept=ad=0 iommu=no-sharept spec-ctrl=0 altp2m=1 xpti=0 loglvl=all guest_loglvl=all smt=0 vpmu=bts apicv=0 cpufreq=hwp:hdc=0;xen:performance,verbose no-real-mode edd=off
cc_compiler            : gcc (Ubuntu 10.5.0-1ubuntu1~20.04) 10.5.0
cc_compile_by          : mtarral
cc_compile_domain      : abc.intel.com
cc_compile_date        : Wed Jan 10 07:39:03 PST 2024
build_id               : 3c0e18caf113475da6ee3d76048a0aad7fcd4942
xend_config_format     : 4
    """
    info = XL._parse_info(output)
    expect = XlInfo(nr_cpus=56, max_cpu_id=111, nr_nodes=2, cores_per_socket=28, threads_per_core=1)
    assert info == expect


def test_parse_vcpu_info():
    output = """Name                                ID  VCPU   CPU State   Time(s) Affinity (Hard / Soft)
Domain-0                             0     0    0   -b-     406.4  0 / all
Domain-0                             0     1    2   r--     363.7  2 / all
Domain-0                             0     2    4   -b-     340.9  4 / all
Domain-0                             0     3    6   -b-     320.2  6 / all
Domain-0                             0     4    8   -b-     313.5  8 / all
Domain-0                             0     5   10   -b-     280.7  10 / all
Domain-0                             0     6   12   -b-     210.9  12 / all
Domain-0                             0     7   14   -b-     212.7  14 / al
    """
    vcpu_list: List[XlVcpuInfo] = list(XL._parse_vcpu_list(output))
    expect_cpu = [i for i in range(15) if not i % 2]
    expect_vcpu = [i for i in range(8)]
    assert [info.cpu_id for info in vcpu_list] == expect_cpu
    assert [info.vcpu_id for info in vcpu_list] == expect_vcpu


def test_parse_cfg_prefix_name():
    file_content = """
name="test-hvm32pse-xensifter"

vcpus=1

type="hvm"
builder="hvm" # Legacy for before Xen 4.10

memory=128
firmware_override="/root/xensifter/xtf/tests/xensifter/test-hvm32pse-xensifter"

# The framework doesn't reboot.  A reboot signal is almost certainly a triple
# fault instead.  Prevent it turning into a runaway domain.
on_reboot = "destroy"

# Test Extra Configuration:
shadow_memory=128"""
    new_content = parse_cfg_prefix_name(file_content, "suffix42")
    expected_content = """
name="test-hvm32pse-xensifter-suffix42"

vcpus=1

type="hvm"
builder="hvm" # Legacy for before Xen 4.10

memory=128
firmware_override="/root/xensifter/xtf/tests/xensifter/test-hvm32pse-xensifter"

# The framework doesn't reboot.  A reboot signal is almost certainly a triple
# fault instead.  Prevent it turning into a runaway domain.
on_reboot = "destroy"

# Test Extra Configuration:
shadow_memory=128"""
    assert expected_content == new_content
