# -*- coding: utf-8 -*-
import sys
import json
import click
import boltlib
from loguru import logger as log


log.remove()
fmt = "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <5}</level> | <level>{message}</level>"
log.add(sys.stderr, format=fmt)


@click.group()
@click.version_option(version=boltlib.__version__, message="BoltCard - %(version)s")
@click.option(
    "-s", "--silent", is_flag=True, default=False, help="Silence debug output."
)
def cli(silent):
    if silent:
        log.remove()


@click.command()
def read():
    """Read BoltCard UID and URI"""
    cs = boltlib.wait_for_card()
    uid = boltlib.read_uid(cs)
    uri = boltlib.read_uri(cs)
    result = dict(uid=uid, uri=uri)
    click.echo(json.dumps(result))
    cs.connection.disconnect()


@click.command()
@click.argument("uri", type=click.STRING)
def write(uri: str):
    """Write URI to BoltCard (unprovisioned only)"""
    cs = boltlib.wait_for_card()
    boltlib.write_uri(uri, cs=cs)
    click.echo(f"Success - Wrote {uri} to card")
    cs.connection.disconnect()


cli.add_command(read)
cli.add_command(write)


if __name__ == "__main__":
    cli()
