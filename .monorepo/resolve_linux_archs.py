#!/usr/bin/env python3
"""Emit GitHub Actions outputs for the Linux x86 cibuildwheel runner.

Reads [tool.monorepo.native] from pyproject.toml and writes three outputs:
  linux-x86-archs   — space-separated CIBW_ARCHS string
  qemu-platforms    — comma-separated docker/setup-qemu-action platform string
  needs-qemu        — 'true' if any QEMU-emulated arch is present, else 'false'

Usage: python .monorepo/native_config.py [--slow]
  --slow   Use linux-x86-archs (full set with QEMU arches).
           Without this flag, uses linux-x86-archs-pr (host-only).
"""

import argparse
import os
import tomllib

QEMU_MAP = {
    "i686": "linux/386",
    "ppc64le": "linux/ppc64le",
    "s390x": "linux/s390x",
    "armv7l": "linux/arm/v7",
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--slow", action="store_true", help="Use full arch list (with QEMU arches)")
    args = parser.parse_args()

    with open("pyproject.toml", "rb") as f:
        cfg = tomllib.load(f)

    native = cfg["tool"]["monorepo"]["native"]
    key = "linux-x86-archs" if args.slow else "linux-x86-archs-pr"
    archs = native[key]

    archs_str = " ".join(archs)
    qemu_platforms = ",".join(QEMU_MAP[a] for a in archs if a in QEMU_MAP)
    needs_qemu = "true" if qemu_platforms else "false"

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as out:
            out.write(f"linux-x86-archs={archs_str}\n")
            out.write(f"qemu-platforms={qemu_platforms}\n")
            out.write(f"needs-qemu={needs_qemu}\n")
    else:
        # Useful for local debugging.
        print(f"linux-x86-archs={archs_str}")
        print(f"qemu-platforms={qemu_platforms}")
        print(f"needs-qemu={needs_qemu}")


if __name__ == "__main__":
    main()
