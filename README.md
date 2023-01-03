# boltlib - Bitcoin Lightning BoltCard library

[![Tests](https://github.com/titusz/boltlib/actions/workflows/tests.yml/badge.svg)](https://github.com/titusz/boltlib/actions/workflows/tests.yml)

`boltlib` is a Python library and command line tool for easy reading and writing of
[BoltCards](https://boltcard.org) based on [pyscard](https://github.com/LudovicRousseau/pyscard)

## Requirements

- [Python 3.8](https://www.python.org/) or higher.

## Installation

```shell
$ pip install boltlib
```

> **Note**: On Linux you might need to first run `sudo apt install libpcsclite-dev swig`

## Command line usage

```shell
$ boltcard
Usage: boltcard [OPTIONS] COMMAND [ARGS]...

Options:
  --version     Show the version and exit.
  -s, --silent  Silence debug output.
  --help        Show this message and exit.

Commands:
  read   Read BoltCard UID and URI
  write  Write URI to BoltCard (unprovisioned only)
```

## Library usage

```python
import boltlib
uri = boltlib.read_uri()
print(uri)
```

## Development

### Requirements
- [Python 3.8](https://www.python.org/) or higher.
- [Poetry](https://python-poetry.org/) for installation and dependency management.

### Setup

```shell
git clone https://github.com/titusz/boltlib.git
cd boltlib
poetry install
```

### Run Tasks

Before committing changes run code formatting and tests with:

```shell
poe all
```


