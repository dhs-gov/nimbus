"""
Nimbus Command Line Interface
"""

from __future__ import print_function

import os
import subprocess
import sys
import time

import click
import yaml

from .aws import AWSManager
from .awslib import ec2lib
from .config import Config
from .logs import set_log_debug_mode
from .utils import is_interactive_default

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
@click.option('--interactive/--batch', help='Prompt to choose role', default=None,
              is_flag=True)
@click.option('-l', '--loop', help='Loop forever, refreshing credentials hourly',
              default=None, is_flag=True)
@click.argument('account', default=None, required=False)
@click.argument('role', default=None, required=False)
def auth(region, account, role, interactive, loop):
    """Authenticate to AWS via SSO provider + SAML."""
    while True:
        click.secho('Starting auth process', err=True, fg='blue', bold=True)

        if interactive is None:
            interactive = is_interactive_default()

        mgr = AWSManager(region=region, account=account, load_cached=False,
                         interactive=interactive)

        # Auth via SSO to get STS credentials and print the AWS_PROFILE environment
        # variable of the resulting saved credentials.
        mgr.auth_to_aws_via_sso(role_name=role, print_profile=True)

        if loop:
            click.secho('Done. Sleeping for 55 minutes.', fg='blue', bold=True)
            time.sleep(55 * 60)
        else:
            break

    click.secho('Done', err=True, fg='blue', bold=True)

@cli.group(name='config')
def config_group():
    """Subcommand for managing nimbus configuration"""

@config_group.command(name='clone')
@click.argument('config_repo')
def config_clone(config_repo):
    """
    Set up configuration for nimbus.

    Clone CONFIG_REPO and use it as the basis for nimbus configuration.
    """
    click.secho('Cloning config repo...', fg='blue', bold=True)
    config = Config(auto_load=False)
    config.clone_config(config_repo)
    click.secho('Done', fg='blue', bold=True)

@config_group.command(name='dump')
def config_dump():
    """Dump nimbus config as yaml."""
    config = Config(auto_load=False)
    click.secho('Printing config from {0}:'.format(config.config_dir),
                fg='blue', bold=True, err=True)
    config.load_config()
    print('---')
    yaml.dump(config.data, sys.stdout, default_flow_style=False)

@config_group.command(name='ls-accounts')
@click.option('-d', '--dump', help='Display verbose info', default=False,
              is_flag=True)
def ls_accounts(dump):
    """List known AWS accounts from nimbus.yaml"""
    click.secho('Listing available AWS accounts', err=True, fg='green',
                bold=True)

    mgr = AWSManager()
    config = mgr.config

    click.secho('Loaded config from {}\n'.format(config.config_file), err=True)

    if dump:
        print('---')
        print(config.aws_accounts_pretty(), end='')
    else:
        accounts = config.aws_accounts()
        click.echo('\t'.join(['name', 'description', 'account_id']))
        for ac in accounts:
            click.echo('\t'.join([
                click.style(ac['name'], fg='blue', bold=True),
                ac['description'],
                ac['account_id'],
            ]))

@config_group.command(name='upgrade')
def config_upgrade():
    """Run git pull to update config."""
    config = Config(auto_load=False)
    click.secho('Upgrading config repo...', fg='blue', bold=True)
    config.upgrade_config()
    click.secho('Done', fg='blue', bold=True)

@cli.command()
@click.argument('host')
def ssh(host):
    """
    SSH to an EC2 instance.

    HOST may be:
        - EC2 instance ID: i-12abcdef
        - IP address: 10.0.0.0
        - Instance Name tag: my-host.example.com

    Examples:
        nimbus ssh ubuntu@i-12abcdef
    """

    mgr = AWSManager()
    ec2lib = ec2lib.EC2Lib()

    ec2lib.parse_ssh_host_arg(host)

@cli.group()
def ec2():
    pass

@ec2.command(name='ls')
def ec2_ls():
    click.secho('Listing instances', fg='blue', bold=True)

    mgr = AWSManager()
    ec2 = mgr.ec2_client()

    click.echo(repr(ec2.describe_instances().iteritems()))
