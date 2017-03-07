"""
Nimbus Command Line Interface
"""

import os
import subprocess
import sys

import click
import yaml

from .aws import AWSManager
from .config import Config
from .logs import set_log_debug_mode

if os.getenv('NIMBUS_DEBUG'):
    set_log_debug_mode()

# `cli` is the click command object that callers should access

@click.group(context_settings={'help_option_names': ['--help', '-h']})
@click.version_option()
#@click.option('--debug', help='Increase log verbosity', default=False)
def cli():
    pass

@cli.command()
@click.option('--region', help='AWS region')
@click.option('--role', help='IAM role to assume')
@click.option('--interactive/--batch', help='Prompt to choose role', default=None,
              is_flag=True)
@click.argument('account', default=None, required=False)
def auth(region, account, role, interactive):
    """Authenticate to AWS via SSO provider + SAML."""
    # TODO: allow configuring region, account, role
    # allow prompting for values not provided in defaults
    click.echo('Starting auth process')

    if interactive is None:
        interactive = sys.stdin.isatty() and sys.stderr.isatty()

    mgr = AWSManager(region=region, account=account, load_cached=False,
                     interactive=interactive)
    mgr.auth_to_aws_via_sso(role_name=role)

@cli.command()
@click.option('-u', '--upgrade', help='Git pull to upgrade existing config',
              is_flag=True)
@click.option('-d', '--dump', help='Dump current config values',
              is_flag=True)
@click.argument('config_repo', required=False)
def configure(upgrade, dump, config_repo=None):
    """
    Set up configuration for nimbus.

    If CONFIG_REPO is given, clone it and use it as the basis for nimbus
    configuration.

    (TODO: Implement interactive prompts for config in addition to git clone.)
    """

    if len(filter(None, [upgrade, config_repo, dump])) > 1:
        raise click.UsageError(
            'Can only pass one of --upgrade, CONFIG_REPO, or --dump')

    config = Config(auto_load=False)

    if upgrade:
        click.secho('Upgrading config repo...', fg='blue', bold=True)
        config.upgrade_config()
    elif dump:
        click.secho('Printing config from {0}:'.format(config.config_dir),
                    fg='blue', bold=True)
        config.load_config()
        yaml.dump(config.data, sys.stdout)
    else:
        if not config_repo:
            raise click.UsageError('Must pass CONFIG_REPO or --upgrade')
        click.secho('Cloning config repo...', fg='blue', bold=True)
        config.clone_config(config_repo)

    click.secho('Done', fg='blue', bold=True)

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
    click.secho('Listing instances', fg='blue', bold=True)

    mgr = AWSManager()
    ec2 = mgr.ec2_client()

    click.echo(repr(ec2.describe_instances().iteritems()))
