#  Copyright (c) 2024 Devkit Contributors
#  SPDX-License-Identifier: MIT
# !/usr/bin/env python3
"""Devkit package entry point.

Allows running devkit as a package:
    python -m cli
"""

import sys

from cli.main import main

if __name__ == "__main__":
    sys.exit(main())
