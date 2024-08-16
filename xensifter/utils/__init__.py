import logging
from functools import partial
from itertools import filterfalse
from pprint import pformat
from typing import Generator

from attrs import Factory

from xensifter.config import settings

from .xen import XL, XlInfo, XlVcpuInfo


def get_available_pcpus() -> Generator[int, None, None]:
    """From XL commands determine the PCPU allocation available for injectors"""
    info = XL.info()
    gen_vcpu_info = (vcpu_info for vcpu_info in XL.vcpu_list("Domain-0"))
    for x in _filter_pcpu_for_injector(info, gen_vcpu_info):
        yield x


def _filter_pcpu_for_injector(
    info: XlInfo, gen_vcpu_info: Generator[XlVcpuInfo, None, None]
) -> Generator[int, None, None]:
    # set range all available pcpus
    range_av_pcpus = range(info.max_cpu_id + 1)
    # filter Dom0 allocated CPU
    dom0_pcpu = [vcpu_info.cpu_id for vcpu_info in gen_vcpu_info]
    filtered_av_pcpus = filterfalse(lambda x: x in dom0_pcpu, range_av_pcpus)
    # filter SMT disabled
    if not settings.smt:
        filtered_av_pcpus = filterfalse(lambda x: x % 2, filtered_av_pcpus)
    for x in filtered_av_pcpus:
        yield x


pformat = partial(pformat, indent=4)
# attrs factories
fact_logging = Factory(lambda self: logging.getLogger(f"{self.__module__}.{self.__class__.__name__}"), takes_self=True)
