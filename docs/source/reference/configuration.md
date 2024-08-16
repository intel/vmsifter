# Configuration

Xensifter configuration can be updated via configuration files, environment variables and command line switches.

The [Dynaconf](https://www.dynaconf.com/) framework is used behind the scenes for configuration management, so everything that you learn from Dynaconf’s documentation should also be applicable for Xensifter.

## Configuration sources and precedence

All configuration files are using the [`TOML`](https://toml.io/en/) format.

1. Default configuration file [`xensifter/config/settings.toml`](https://github.com/intel-sandbox/xensifter/blob/main/xensifter/config/settings.toml)
2. Current directory `.secret.TOML`
3. Command line arguments
4. Configuration keys specified by environment variables prefixed by `XENSIFTER_`. (Ex: `XENSIFTER_DEBUG=TRUE`)

## Keys

### `jobs`

How many cores should Xensifter use to parallelize its execution.

Default: `1`

### `fuzzer_mode`

Which fuzzing mode to use.

Choices:
- `random`
- `tunnel`
- `csv`
- `drizzler`

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

Default: `xensifter_sock`

### `workdir`

Xensifter's working directory containing runtime information and CSV files output.

Default: `$PWD/workdir`

### `debug`

Toggle debug output logging.

### `pdb`

Toggle post-mortem debugging upon an unhandled exception by invoking Python PDB.

### `csv_log_diff_only`

Compare the registers state and log only their differences between the last and the current execution result.

Default: `0`

### `extra_byte`

TODO

Default: `0`

### `smt`

Whether _Simultaneous multithreading_ is enabled on the host. Used to exclude PCPU from the available pool allocation for injectors.

:::{Note}
Xen returns an "Invalid argument" when trying to pin an SMT PCPU to an injector VM.

This is likely bug, so we must filter this in Xensifter.
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

Path to modified [`XTF`](https://xenbits.xenproject.org/docs/xtf/) framework with Xensifter patches applied and compiled.

##### `perfcts`

TODO

##### `sse`

TODO

##### `syscall`

TODO

##### `fpu_emulation`

TODO