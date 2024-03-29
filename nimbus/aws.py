"""
AWS stuff
"""

from __future__ import print_function

import os
import time

from datetime import datetime

import atomicwrites
import boto3
import click
import configobj

from .logs import log
from .config import Config
from .errors import ManyFound, NotFound
from .saml import SSOProvider
from .utils import prompt_choices

# Default AWS credentials file. This is probably not correct on Windows.
DEFAULT_AWS_CREDENTIALS = os.path.join(os.path.expanduser('~'), '.aws',
                                       'credentials')

class AWSManager(object):
    def __init__(self, region=None, account=None, load_cached=True,
                 interactive=False):
        self.config = Config()

        self.interactive = interactive

        if region is None:
            self.region = self.config.default_region()
        else:
            self.region = region

        if account is None:
            try:
                account = self.config.default_account_id()
            except KeyError:
                pass

        if account is None:
            self.account_info = None
        else:
            self.set_account(account)

        self.aws_creds = None

        if load_cached:
            try:
                self.load_cached_creds(account=account)
            except ManyFound:
                log.error('Not interactive, but multiple cached creds found')
                raise

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

    def set_account(self, account):
        """
        Look up account in nimbus config and save associated info to
        self.account_info as a dict.

        :param account: The account name or ID
        :type account: str
        """
        log.debug('AWSManager#set_account(%r)', account)
        self.account_info = self.get_account_info(account)

    def set_credentials(self, creds_dict):
        log.debug('set_credentials')

        self.aws_creds = {}
        for key in ['aws_access_key_id', 'aws_secret_access_key']:
            self.aws_creds[key] = creds_dict[key]

        if 'aws_session_token' in creds_dict:
            self.aws_creds['aws_session_token'] = \
                creds_dict['aws_session_token']

    def get_credentials(self):
        if self.aws_creds:
            return self.aws_creds

        if 'AWS_PROFILE' in os.environ:
            log.debug('Found AWS_PROFILE, assuming creds will be there')
            return {}
        if ('AWS_ACCESS_KEY_ID' in os.environ and
            'AWS_SECRET_ACCESS_KEY' in os.environ):
            log.debug('Found AWS_ACCESS_KEY_ID, assuming creds will be there')
            return {}

        log.error('Expected to find self.aws_creds populated or AWS_PROFILE in env')
        raise NotFound('No AWS credentials found on object or in env')

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

    def aws_client(self, service):
        creds = self.get_credentials()
        return boto3.client(service, region_name=self.region, **creds)

    def ec2_client(self):
        return self.aws_client('ec2')

    def _find_role_by_name(self, roles, role_name):
        log.debug("Looking for role named %r among %r", role_name, roles)
        for r in roles:
            if r.role == role_name:
                return r
        log.error("Could not find %r among %r", role_name, roles)
        raise NotFound("Role name not found: " + repr(role_name))

    def _choose_role_interactive(self, roles):
        log.debug("Interactively prompting for role")
        arn = prompt_choices(choices=[r.role_arn for r in roles],
                             prompt='Please choose a role:')
        return [r for r in roles if r.role_arn == arn][0]

    def auth_to_aws_via_sso(self, role_name=None, print_env=False,
                            print_profile=True, save_creds=True):
        """
        Connect to the SSO provider specified by config, get a SAML assertion.
        Use that SAML assertion to assume the specified role in AWS.

        :return: A tuple of the role (nimbus.sso.RoleInfo) and a dict of the
                 STS credentials.
        :rtype: 2-tuple of (nimbus.sso.RoleInfo, dict) containing role info,
                dict of credentials
        """
        log.debug('connect_to_aws()')

        if role_name is None:
            try:
                role_name = self.config.default_role()
            except KeyError:
                pass

        # initialize SSO provider
        sso = SSOProvider.new_from_config(self.config)

        if self.account_info:
            aws_account = self.account_id
        else:
            aws_account = None

        # authenticate to SSO provider, get SAML assertion
        ret = sso.get_assertion_and_roles(aws_account=aws_account)

        assertion = ret['assertion']
        roles = ret['roles']

        assert roles

        # if role name was given, choose that one
        if role_name:
            role = self._find_role_by_name(roles=roles, role_name=role_name)
        else:
            if len(roles) <= 1:
                # with only one role, just use it
                role = roles[0]
            else:
                if self.interactive:
                    role = self._choose_role_interactive(roles)
                else:
                    raise ManyFound("Multiple roles found: " + repr(roles))

        profile_name = profile_name_for_role(role=role)

        log.info('Assuming role with SAML: %s', role.role_arn)

        resp = assume_role_with_saml(region=self.region, role_arn=role.role_arn,
                                     provider_arn=role.provider_arn,
                                     assertion=assertion)

        creds = resp['Credentials']

        # creds contents:
        # 'AccessKeyId': 'string',
        # 'SecretAccessKey': 'string',
        # 'SessionToken': 'string',
        # 'Expiration': datetime(2015, 1, 1)

        log.debug('Got STS API keys')

        # save newly chosen account information on self
        if not self.account_info:
            self.set_account(account)

        if print_env:
            print_env_credentials(creds)

        if print_profile:
            print_env_profile(role)

        if save_creds:
            write_creds_to_file(role=role, creds=creds, region=self.region)

        return profile_name, creds

    def load_cached_creds(self, account=None, role=None, allow_expired=False):
        log.debug('find_cached_creds: %r, %r', account, role)
        conf = read_aws_credentials()

        nimbus_sections = [s for s in conf.sections if
                           s.startswith('nimbus_')]

        found = {}

        for section in nimbus_sections:
            if not allow_expired:

                exp = datetime.utcfromtimestamp(
                    conf[section].as_float('expiration'))

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
            found[(s_account, s_role)] = dict(conf[section])

        if not found:
            return False

        if len(found) == 1:
            chosen = found.keys()[0]

        else:
            # with multiple cached creds found, either interactively prompt or
            # raise ManyFound

            if self.interactive:
                chosen = prompt_choices(choices=found.keys(),
                                        prompt='Choose an account/role:')
            else:
                log.info('Found multiple valid cached nimbus creds in ' +
                         'AWS credentials file')
                raise ManyFound("Multiple cached creds found: " +
                                ', '.join(':'.join(x) for x in
                                          found.iterkeys()))

        chosen_account, chosen_role = chosen

        # save chosen account on self
        if not self.account_info:
            self.set_account(chosen_account)

        return {
            'account': chosen_account,
            'role': chosen_role,
            'creds': found[chosen],
        }

def profile_name_for_role(role):
    """
    Return the name of the AWS profile used to save/use given credentials.

    :param role: A namedtuple containing info about an assumed role
    :type role: nimbus.sso.RoleInfo

    :return: AWS profile name
    :rtype: string
    """
    return profile_name(account=role.account, role_name=role.role)

def profile_name(account, role_name):
    return '_'.join(['nimbus', account, role_name])

def write_creds_to_file(role, creds, region, path=DEFAULT_AWS_CREDENTIALS):
    """
    Save credentials for the given role to the AWS credentials file, creating a
    new nimbus section for the purpose of storing them.

    :param role: The namedtuple containing info about the role
    :type role: nimbus.sso.RoleInfo

    :param creds: Dictionary of credentials from the assumeRoleWithSAML call
    :type creds: dict

    :param region: AWS region to connect to
    :type region: str

    :param path: Path to AWS credentials ini file
    :type path: str
    """

    log.debug('Writing credentials to %r', path)

    config = read_aws_credentials(path=path)

    section = profile_name_for_role(role)

    if not section in config:
        config[section] = {}

    config[section]['region'] = region
    config[section]['aws_access_key_id'] = creds['AccessKeyId']
    config[section]['aws_secret_access_key'] = creds['SecretAccessKey']
    config[section]['aws_session_token'] = creds['SessionToken']
    config[section]['expiration'] = \
        time.mktime(creds['Expiration'].timetuple())
    config[section]['expiration_str'] = creds['Expiration']

    with atomicwrites.atomic_write(path, overwrite=True) as f:
        config.write(outfile=f)

    log.debug('Saved credential section %r', section)

def read_aws_credentials(path=DEFAULT_AWS_CREDENTIALS):
    config = configobj.ConfigObj(path)

    return config

def print_env_credentials(creds, region=None):
    if region:
        print('export AWS_DEFAULT_REGION=' + region)
    for item, env in [('AccessKeyId', 'AWS_ACCESS_KEY_ID'),
                      ('SecretAccessKey', 'AWS_SECRET_ACCESS_KEY'),
                      ('SessionToken', 'AWS_SESSION_TOKEN')]:
        print('export {}={}'.format(env, creds[item]))

def print_env_profile(role, region=None):
    if region:
        print('export AWS_DEFAULT_REGION=' + region)

    section = profile_name_for_role(role=role)
    print('export AWS_PROFILE=' + section)

def assume_role_with_saml(region, role_arn, provider_arn, assertion):
    log.debug('assume_role_with_saml(%r, %r, %r, ...)', region, role_arn,
              provider_arn)
    sts = boto3.client('sts', region_name=region)
    return sts.assume_role_with_saml(RoleArn=role_arn,
                                     PrincipalArn=provider_arn,
                                     SAMLAssertion=assertion)

