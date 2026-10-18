"""ScanContext — what every module receives. Keeps modules decoupled from the CLI."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Callable

from .iocs import IocSet


@dataclass
class ScanContext:
    iocs: IocSet
    deep: bool = False
    # Skip the file-fingerprinting check, which is the slowest part of the scan
    # by far and the weakest signal in it. See cli.py for why.
    quick: bool = False
    verbose: bool = True
    # progress sink; defaults to stderr so stdout stays the clean human report
    emit: Callable[[str], None] = field(
        default=lambda msg: print(msg, file=sys.stderr))
