# dissect.ntfs

A Dissect module implementing a parser for the NTFS file system, used by the Windows operating system. For more
information, please see [the documentation](https://docs.dissect.tools/en/latest/projects/dissect.ntfs/index.html).

## Requirements

This project is part of the Dissect framework and requires Python.

Information on the supported Python versions can be found in the Getting Started section of [the documentation](https://docs.dissect.tools/en/latest/index.html#getting-started).

## Installation

`dissect.ntfs` is available on [PyPI](https://pypi.org/project/dissect.ntfs/).

```bash
pip install dissect.ntfs
```

This module is also automatically installed if you install the `dissect` package.

## Build and test instructions

This project is part of the [dissect monorepo](https://github.com/fox-it/dissect). Building and testing is managed from the monorepo root.

To run the tests for this project, run the following command from the monorepo root:

```bash
just test dissect.ntfs
```

To build source and wheel distributions:

```bash
uv build --package dissect.ntfs --out-dir dist/dissect.ntfs
```

The build artifacts can be found in the `dist/dissect.ntfs/` directory.

For a more elaborate explanation on how to build and test the project, please see [the recipes](../../doc/recipes.md) or [the documentation](https://docs.dissect.tools/en/latest/contributing/tooling.html).

## Contributing

The Dissect project encourages any contribution to the codebase. To make your contribution fit into the project, please
refer to [the development guide](https://docs.dissect.tools/en/latest/contributing/developing.html).

## Copyright and license

Dissect is released as open source by Fox-IT (<https://www.fox-it.com>) part of NCC Group Plc
(<https://www.nccgroup.com>).

Developed by the Dissect Team (<dissect@fox-it.com>) and made available at <https://github.com/fox-it/dissect>.

License terms: AGPL3 (<https://www.gnu.org/licenses/agpl-3.0.html>). For more information, see the LICENSE file.
