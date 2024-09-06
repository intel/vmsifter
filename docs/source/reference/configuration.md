# Configuration

VMSifter configuration can be updated via configuration files, environment variables and command line switches.

The [Dynaconf](https://www.dynaconf.com/) framework is used behind the scenes for configuration management, so everything that you learn from Dynaconf’s documentation should also be applicable for VMSifter.

## Configuration sources and precedence

All configuration files are using the [`TOML`](https://toml.io/en/) format.

1. Default configuration file [`vmsifter/config/settings.toml`](https://github.com/intel/vmsifter/blob/main/vmsifter/config/settings.toml)
2. Current directory `.secret.TOML`
3. Command line arguments
4. Configuration keys specified by environment variables prefixed by `VMSIFTER_`. (Ex: `VMSIFTER_DEBUG=TRUE`)

## Keys

### `jobs`

How many cores should VMSifter use to parallelize its execution.

Default: `1`

### `fuzzer_mode`

Select which fuzzing mode to use.

Choices:
- `RANDOM`: run random instructions
- `TUNNEL`: sandsifter-style black-box instruction discovery
- `CSV`: run instruction(s) from CSV file
- `DRIZZLER`: experimental

Default: `TUNNEL`

### `refresh_frequency`

Refresh rate for logging the fuzzing progress per `x` instructions.

### `insn_buf_size`

Size of the instruction buffer.

Default: `15`

### `min_prefix_count`

Minimum amount of prefixes that should inserted by the fuzzer into the candidate instruction.

Default: `0`

### `max_prefix_count`

Maximum amount of prefixes that should be inserted by the fuzzer into the candidate instruction.

Default: `0`

### `socket_name`

Filename for the Unix socket used to communicate with the injector.

Will be created inside the [workdir](#workdir).

Default: `vmsifter_sock`

### `workdir`

VMSifter's working directory containing runtime information and CSV files output.

Default: `$PWD/workdir`

### `debug`

Toggle debug output logging.

### `pdb`

Toggle post-mortem debugging upon an unhandled exception by invoking Python PDB.

### `csv_log_diff_only`

Compare the registers state and log only their differences between the last and the current execution result.

Default: `0`

### `extra_byte`

The number of extra byte(s) to add at the end of the generated instructions in the range `0x0 .. 0xff` sequentially. 

Default: `0`

### `smt`

Whether _Simultaneous multithreading_ is enabled on the host. Used to exclude PCPU from the available pool allocation for injectors.

:::{Note}
Xen returns an "Invalid argument" when trying to pin an SMT PCPU to an injector VM.

This is likely bug, so we must filter this in VMSifter.
:::

Default: `false`

### `x86`

#### `prefix`

List of valid x86-32 prefixes to be used by the fuzzer.

Default:

```TOML
prefix = [
    0xF0,  # lock
    0xF2,  # repne / bound
    0xF3,  # rep
    0x2E,  # cs / branch taken
    0x36,  # ss / branch not taken
    0x3E,  # ds
    0x26,  # es
    0x64,  # fs
    0x65,  # gs
    0x66,  # data
    0x67,  # addr
]
```

#### `prefix_64`

List of valid x86-64 prefixes to be used by the fuzzer.

Default:

```python
[i for i in range(0x40, 0x50)]
```

#### `exec_mode`

Desired x86 execution mode.

Default: `32`

### `fuzzer`

#### `drizzler`

##### `num_seeds`

TODO

Default: `1`

##### `injections`

TODO

Default: `300`

##### `aggressive`

TODO

Default: `false`

### `injector`

#### `xenvm`

##### `injector_path`

Path to the Xen injector.

Default:

```python
shutil.which('injector')
```

##### `xtf_path`

Path to [`XTF`](https://xenbits.xenproject.org/docs/xtf/) framework with VMsifter patches applied and compiled.

##### `perfcts`

Chose the value to be set for the 4 configurable performance counters. These values are CPU specific and should be set accordingly.
Performance counters are automatically configured to freeze counting when in VMM or SMM modes and no PMI is enabled.

See `SDM Chapter 20 Performance Monitoring` for detailed documentation on performance counter settings and [`https://perfmon-events.intel.com`](https://perfmon-events.intel.com)

For example, to select `UOPS_ISSUED.ANY` on a Ice Lake processor we can find `EventSel=0EH UMask=01H`, therefore we would set `0x43010e` for one of the performance counters to enable it in both OS and USR modes.

```TOML
24-31b:     CMask
22b:        Enable
17b:        OS  // monitor active in OS mode (ring0)
16b:        USR // monitor active in USR mode (ring3)
8-15b:      UMask
0-7b:       EventSel
```

Default: `"0x043010e,0x04301c2,0x04307c1,0x44304a3"`

##### `sse`

Toggle to enable SSE and AVX instructions. Specificially enable the following control register bits:

```TOML
CR4: X86_CR4_OSFXSR | X86_CR4_OSXSAVE | X86_CR4_OSXMMEXCPT
XCR0: XSTATE_SSE | XSTATE_YMM
```

Default: `true`

##### `syscall`

Toggle to enable syscall instructions.

Default: `true`

##### `fpu_emulation`

Toggle to enable x87 FPU emulation. Specifically enable to set the following control register bit:

```TOML
CR0: X86_CR0_EM
```

Default: `false`
