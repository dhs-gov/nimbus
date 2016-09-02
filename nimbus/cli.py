"""
Nimbus Command Line Interface
"""

import click

# `cli` is the click command object that callers should access

@click.group()
def cli():
    pass

@cli.command()
def auth():
    click.echo('Starting auth process')

@cli.group()
def ec2():
    pass

@ec2.command(name='ls')
def ec2_ls():
    click.echo('Listing instances')
