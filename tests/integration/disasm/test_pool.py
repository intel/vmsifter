from itertools import count

import pytest
from capstone import CS_MODE_64

from xensifter.disasm.capstone import CapstoneDisasmAdaptee
from xensifter.disasm.interface import DisasmEngineType, DisasmResult
from xensifter.disasm.pool import DisasmPoolExecutor
from xensifter.disasm.yaxpeax import YaxpeaxDisasmAdaptee
from xensifter.fuzzer.tunnel import FuzzerExecResult, TunnelFuzzer


def test_pool_disasm_one():
    # arrange
    cap_adaptee = CapstoneDisasmAdaptee(mode=CS_MODE_64)
    yaxpeax_adaptee = YaxpeaxDisasmAdaptee()
    engines = {DisasmEngineType.CAPSTONE: cap_adaptee, DisasmEngineType.YAXPEAX: yaxpeax_adaptee}
    buffer = b"\x55"
    expected_res = DisasmResult(1, "push rbp")
    with DisasmPoolExecutor(engines) as pool:
        # act
        pool.submit_disasm(buffer)
        # assert
        result = list(pool.as_completed())
        print(result)
        assert len(result) == len(engines)
        for res in result:
            assert res.disas_res == expected_res


@pytest.mark.parametrize("max_count", [10**3, 10**4, 10**5])
def test_capstone_tunnel(max_count: int):
    # arrange
    cap_adaptee = CapstoneDisasmAdaptee()
    yaxpeax_adaptee = YaxpeaxDisasmAdaptee()
    tun = TunnelFuzzer()
    gen = tun.gen()

    # act
    result = None
    engines = {DisasmEngineType.CAPSTONE: cap_adaptee, DisasmEngineType.YAXPEAX: yaxpeax_adaptee}

    with DisasmPoolExecutor(engines) as pool:
        for i in count():
            if i == max_count:
                break
            next_buff = gen.send(result)
            # disasm
            pool.submit_disasm(next_buff.tobytes())
            pool_res = next(pool.as_completed())
            if pool_res.disas_res is None:
                result = FuzzerExecResult(pagefault=True)
            else:
                result = FuzzerExecResult(length=pool_res.disas_res.size)
