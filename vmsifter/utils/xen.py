# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

import json
import logging
import re
import subprocess
import uuid
from contextlib import contextmanager
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Generator, List, Optional

from attr import define, field

from xensifter.config import settings


def parse_cfg_prefix_name(cfg_content: str, name_suffix: str) -> str:
    new_file_content: List[str] = []
    for line in cfg_content.splitlines():
        m = re.match('^name="(?P<name>.*)"$', line)
        new_line = line
        if m:
            name = m.group("name")
            # add suffix
            new_line = f'name="{name}-{name_suffix}"'
        new_file_content.append(new_line)
    return "\n".join(new_file_content)


@contextmanager
def gen_tmp_xenvm_configfile() -> Generator[Path, None, None]:
    """Generate a temporary copy of xtf/tests/xensifter/test-xxx-xensifter.cfg, with a temporary non-unique VM name"""
    with NamedTemporaryFile(mode="w") as tmp_cfg:
        xtf_cfg_file_path = Path(
            f"{settings.injector.xenvm.XTF_PATH}/tests/xensifter/test-{settings.injector.xenvm.xl.config}-xensifter.cfg"
        )
        with open(xtf_cfg_file_path) as f:
            content = f.read()
            suffix = str(uuid.uuid4())
            logging.debug("Parent VM name suffix: %s", suffix)
            new_content = parse_cfg_prefix_name(content, suffix)
            tmp_cfg.write(new_content)
            tmp_cfg.flush()
        yield Path(tmp_cfg.name)


@contextmanager
def xtf_vm(cfg_file_path: Path) -> Generator[int, None, None]:
    """Creates XTF VMs and destroy it when the resource is released"""
    cmd: List[str] = [
        "sudo",
        "xl",
        "create",
        "-p",
        str(cfg_file_path),
    ]
    logging.debug("exec: %s", cmd)
    subprocess.check_call(cmd)
    output = subprocess.check_output(["sudo", "xl", "list", "--long"])
    xl_list_info = json.loads(output)
    # look for vm whose name matches xensifter
    xensifter_vm_list = [vm for vm in xl_list_info if "xensifter" in vm["config"]["c_info"]["name"]]
    assert len(xensifter_vm_list) == 1
    xensifter_vm = xensifter_vm_list.pop()
    # get domid
    domid = xensifter_vm["domid"]
    try:
        yield domid
    finally:
        logging.info("Destroying parent VM (%s)", domid)
        cmd = ["sudo", "xl", "destroy", str(domid)]
        logging.debug("exec: %s", cmd)
        subprocess.check_call(cmd)


@define
class XlInfo:
    nr_cpus: int = field(converter=int)
    max_cpu_id: int = field(converter=int)
    nr_nodes: int = field(converter=int)
    cores_per_socket: int = field(converter=int)
    threads_per_core: int = field(converter=int)


@define
class XlVcpuInfo:
    name: str = field()
    dom_id: int = field(converter=int)
    vcpu_id: int = field(converter=int)
    cpu_id: int = field(converter=int)


class XL:
    """Bindings to Xen XL toolstack"""

    @classmethod
    def _parse_info(cls, output: str) -> XlInfo:
        data = {}
        for line in output.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                data[k.strip()] = v.strip()

        return XlInfo(
            nr_cpus=data.get("nr_cpus", 0),
            max_cpu_id=data.get("max_cpu_id", 0),
            nr_nodes=data.get("nr_nodes", 0),
            cores_per_socket=data.get("cores_per_socket", 0),
            threads_per_core=data.get("threads_per_core", 0),
        )

    @classmethod
    def info(cls) -> XlInfo:
        """xl info"""
        cmd = ["xl", "info"]
        output = subprocess.check_output(cmd, text=True)
        return cls._parse_info(output)

    @classmethod
    def _parse_vcpu_list(cls, output: str) -> Generator[XlVcpuInfo, None, None]:
        # skip header and empty lines
        lines_w_header = (line for i, line in enumerate(output.splitlines()) if i > 0 and line.strip())
        for line in lines_w_header:
            fields = line.split()
            yield XlVcpuInfo(name=fields[0], dom_id=fields[1], vcpu_id=fields[2], cpu_id=fields[3])

    @classmethod
    def vcpu_list(cls, domain: Optional[str] = None) -> Generator[XlVcpuInfo, None, None]:
        """xl vcpu-list <domain>"""
        cmd = ["xl", "vcpu-list"]
        if domain:
            cmd.append(domain)
        output = subprocess.check_output(cmd, text=True)
        for x in cls._parse_vcpu_list(output):
            yield x
