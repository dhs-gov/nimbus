"""
AWS stuff
"""

import ConfigParser
import os
import time

from datetime import datetime

import atomicwrites
import boto3
import click

from .logs import log
from .config import Config
from .errors import ManyFound
from .saml import SSOProvider
from .utils import prompt_choices

# TODO: read existing ~/.aws/credentials for nimbus creds

class AWSManager(object):
    def __init__(self, region=None, account=None):
        self.config = Config()

        if region is None:
            self.region = self.config.default_region()
        else:
            self.region = region

        if account is None:
            try:
                account = self.config.default_account_id()
            except KeyError:
                pass

        self.account_info = self.get_account_info(account)

    @property
    def account_id(self):
        return self.account_info['account_id']

    @property
    def account_name(self):
        return self.account_info['name']

    @property
    def account_description(self):
        return self.account_info['description']

    @property
    def account_is_prod(self):
        return self.account_info['description']

    def get_account_info(self, account):
        """
        Parse an account ID or nickname. An account ID will be returned as is,
        while a nickname will be checked against ~/.aws/nimbus.yaml

        :param account: An account ID or nickname string.
        :type account: str

        :return: Dict of account info containing 'account_id', etc.
        :rtype: dict<str: str>
        """
        if account.isdigit():
            return self.config.get_aws_account(account_id=account)
        else:
            return self.config.get_aws_account(name=account)

    def connect_to_aws(self, interactive=False, role_name=None, print_env=True,
                       save_creds=True):
        """
        Connect to the SSO provider specified by config, get a SAML assertion.
        Use that SAML assertion to assume the specified role in AWS.
        """
        log.debug('connect_to_aws()')

        if role_name is None:
            try:
                role_name = self.config.default_role()
            except KeyError:
                pass

        # initialize SSO provider
        sso = SSOProvider.new_from_config(self.config)

        # authenticate to SSO provider, get SAML assertion
        ret = sso.get_assertion_and_roles(aws_account=self.account_id)

        assertion = ret['assertion']
        roles = ret['roles']

        assert roles

        if len(roles) <= 1:
            role = roles[0]
        else:
            if interactive:
                arn = prompt_choices(choices=[r.role_arn for r in roles],
                                     prompt='Please choose a role:')
                role = [r for r in roles if r.role_arn == arn][0]
            else:
                raise ManyFound("Multiple roles found: " + repr(roles))

        log.info('Assuming role with SAML: %s', role.role_arn)

        resp = assume_role_with_saml(region=self.region, role_arn=role.role_arn,
                                     provider_arn=role.provider_arn,
                                     assertion=assertion)

        creds = resp['Credentials']

        # 'AccessKeyId': 'string',
        # 'SecretAccessKey': 'string',
        # 'SessionToken': 'string',
        # 'Expiration': datetime(2015, 1, 1)

        log.debug('Got STS API keys')

        if print_env:
            print_env_credentials(creds)

        if save_creds:
            write_creds_to_file(role=role, creds=creds, region=self.region)

        return creds

    def find_cached_creds(self, account=None, role=None, allow_expired=False):
        log.debug('find_cached_creds: %r, %r', account, role)
        conf = read_aws_credentials()

        nimbus_sections = [s for s in conf.sections() if
                           s.startswith('nimbus_')]

        for section in nimbus_sections:
            if not allow_expired:

                exp = datetime.utcfromtimestamp(
                    conf.getfloat(section, 'expiration'))

                if exp < datetime.utcnow():
                    continue

            _, s_account, s_role = section.split('_')

            if account is not None:
                if account != s_account:
                    continue

            if role is not None:
                if role != s_role:
                    continue

            log.debug('Found valid credentials in section %r', section)
            return dict(conf.items(section))


DEFAULT_AWS_CREDENTIALS = os.path.join(os.path.expanduser('~'), '.aws',
                                       'credentials')
def write_creds_to_file(role, creds, region, path=DEFAULT_AWS_CREDENTIALS):
    log.debug('Writing credentials to %r', path)

    config = read_aws_credentials(path=path)

    section = '_'.join(['nimbus', role.account, role.role])

    if not config.has_section(section):
        config.add_section(section)

    config.set(section, 'region', region)
    config.set(section, 'aws_access_key_id', creds['AccessKeyId'])
    config.set(section, 'aws_secret_access_key', creds['SecretAccessKey'])
    config.set(section, 'aws_session_token', creds['SecretAccessKey'])
    config.set(section, 'expiration',
               time.mktime(creds['Expiration'].timetuple()))
    config.set(section, 'expiration_str', creds['Expiration'])

    with atomicwrites.atomic_write(path, overwrite=True) as f:
        config.write(f)

    log.debug('Saved credential section %r', section)

def read_aws_credentials(path=DEFAULT_AWS_CREDENTIALS):
    config = ConfigParser.RawConfigParser()
    config.read(path)

    return config

def print_env_credentials(creds, region=None):
    if region:
        print 'export AWS_DEFAULT_REGION=' + region
    for item, env in [('AccessKeyId', 'AWS_ACCESS_KEY_ID'),
                      ('SecretAccessKey', 'AWS_SECRET_ACCESS_KEY'),
                      ('SessionToken', 'AWS_SESSION_TOKEN')]:
        print 'export {}={}'.format(env, creds[item])


def assume_role_with_saml(region, role_arn, provider_arn, assertion):
    log.debug('assume_role_with_saml(%r, %r, %r, ...)', region, role_arn,
              provider_arn)
    sts = boto3.client('sts', region_name=region)
    return sts.assume_role_with_saml(RoleArn=role_arn,
                                     PrincipalArn=provider_arn,
                                     SAMLAssertion=assertion)

