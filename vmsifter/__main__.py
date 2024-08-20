# Copyright (C) 2022 Intel Corporation
# SPDX-License-Identifier: MIT

"""VMSifter

Usage:
  vmsifter [options]

Options:
  -h --help                                     Show this screen.
  -d --debug                                    Toggle debugging
  -r <VALUE> --refresh-freq=<VALUE>             Refresh frequency per <VALUE> instructions
  -m <mode>, --fuzzer-mode <mode>               Enable fuzzing mode [default: TUNNEL]
  -i <injector>, --injector-mode <injector>     Select injector mode [default: XENVM]
  -j <JOBS>, --jobs <JOBS>                      Use at most <JOBS> jobs
  -e <PARAM>, --fuzzer-param <PARAM>...         Pass extra parameter for fuzzer
  --version                                     Show version.
"""

import logging
from contextlib import suppress
from functools import wraps
from logging.config import dictConfig
from pathlib import Path
from typing import List, Optional, Union

import coloredlogs
import yaml
from docopt import docopt

from vmsifter.config import FuzzerType, InjectorType, settings
from vmsifter.executor import SifterExecutor


def post_mortem(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception:
            if settings.PDB:
                import pdb
                import sys

                _, _, trace = sys.exc_info()
                logging.exception("Entering post mortem debugging")
                pdb.post_mortem(trace)
            else:
                raise

    return wrapper


def setup_logging(debug_enabled: bool = False):
    log_config_path = Path(__file__).parent / "logging.yaml"
    with open(log_config_path) as f:
        config = yaml.safe_load(f)

    root_level = "INFO"
    if debug_enabled:
        root_level = "DEBUG"

    format = config["formatters"]["colored"]["format"]
    settings.logging.format = logging.Formatter(format)

    dictConfig(config)
    coloredlogs.install(level=root_level, fmt=format)


# poetry's entrypoint can't be specified with an executable package
# we need to add a function
@post_mortem
def main():
    args = docopt(__doc__, version="0.1")
    settings["debug"] = args["--debug"]
    if args["--jobs"]:
        settings["jobs"] = int(args["--jobs"])
    setup_logging(settings["debug"])

    with suppress(KeyboardInterrupt):
        # set fuzzing mode
        try:
            fuzzer_mode_str = args["--fuzzer-mode"].upper()
            settings.fuzzer_mode = FuzzerType[fuzzer_mode_str]
        except KeyError:
            logging.critical("Unknown fuzzer mode %s", fuzzer_mode_str)
            logging.info("Available modes: %s", [option.name for option in FuzzerType])
            return 1

        # set injector mode
        try:
            injector_mode_str = args["--injector-mode"].upper()
            settings.injector_mode = InjectorType[injector_mode_str]
        except KeyError:
            logging.critical("Unknown injector mode %s", injector_mode_str)
            logging.info("Available modes: %s", [option.name for option in InjectorType])
            return 1

        if args["--refresh-freq"]:
            settings["refresh_frequency"] = int(args["--refresh-freq"])

        logging.info("VMSifter started !")

        extra_params: Optional[Union[List[str], str]] = args["--fuzzer-param"]
        if isinstance(extra_params, str):
            extra_params = [extra_params]
        with SifterExecutor() as executor:
            executor.run(extra_params)


# needed when vmsifter is invoked as executable package
# python -m vmsifter
if __name__ == "__main__":
    main()
