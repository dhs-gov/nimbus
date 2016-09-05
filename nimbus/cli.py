"""
Nimbus Command Line Interface
"""


import click

from .aws import AWSManager

# TODO DEBUG
from .logs import set_log_debug_mode
set_log_debug_mode()

# `cli` is the click command object that callers should access

@click.group()
def cli():
    pass

@cli.command()
def auth():
    click.echo('Starting auth process')
    mgr = AWSManager()
    mgr.connect_to_aws()

@cli.group()
def ec2():
    pass

@ec2.command(name='ls')
def ec2_ls():
    click.echo('Listing instances')
