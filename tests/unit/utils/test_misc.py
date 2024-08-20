# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

from vmsifter.utils import _filter_pcpu_for_injector
from vmsifter.utils.xen import XlInfo, XlVcpuInfo


# TODO: SMT enabled
def test_filter_pcpu_for_injector():
    info = XlInfo(nr_cpus=8, max_cpu_id=8 * 2 - 1, nr_nodes=1, cores_per_socket=4, threads_per_core=1)
    vcpu_list = (XlVcpuInfo("Domain-0", 0, i, i * 2) for i in range(4))

    result = list(_filter_pcpu_for_injector(info, vcpu_list))
    expected = [8, 10, 12, 14]
    assert result == expected
