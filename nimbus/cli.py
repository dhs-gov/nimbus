"""
Nimbus Command Line Interface
"""

import sys

import click

from .aws import AWSManager

# TODO DEBUG
from .logs import set_log_debug_mode
set_log_debug_mode()

# `cli` is the click command object that callers should access

@click.group()
#@click.option('--debug', help='Increase log verbosity', default=False)
def cli():
    pass

@cli.command()
@click.option('--region', help='AWS region')
@click.option('--account', help='AWS account nickname / ID')
@click.option('--role', help='IAM role to assume')
@click.option('--interactive/--batch', help='Prompt to choose role', default=None,
              is_flag=True)
@click.argument('account', default='foo')
def auth(region, account, role, interactive):
    """Authenticate to AWS via SSO provider + SAML"""
    # TODO: allow configuring region, account, role
    # allow prompting for values not provided in defaults
    click.echo('Starting auth process')

    if interactive is None:
        interactive = sys.stdin.isatty() and sys.stderr.isatty()

    mgr = AWSManager(region=region, account=account)
    mgr.connect_to_aws(interactive=interactive, role_name=role)


@cli.command()
@click.argument('host')
def ssh():
    """SSH to an EC2 instance"""
    raise NotImplementedError

@cli.group()
def ec2():
    pass

@ec2.command(name='ls')
def ec2_ls():
    click.echo('Listing instances')
