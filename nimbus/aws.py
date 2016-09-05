"""
AWS stuff
"""

import ConfigParser

import boto3

from .logs import log
from .config import Config
from .errors import ManyFound
from .saml import SSOProvider

# TODO: read existing ~/.aws/credentials for nimbus creds

class AWSManager(object):
    def __init__(self):
        self.config = Config()

    def connect_to_aws(self, region=None, account_id=None, interactive=False,
                       print_env=True, save_creds=False):
        if region is None:
            region = self.config.default_region()

        if account_id is None:
            account_id = self.config.default_account_id()

        # initialize SSO provider
        sso = SSOProvider.new_from_config(self.config)

        # authenticate to SSO provider, get SAML assertion
        ret = sso.get_assertion_and_roles(aws_account=account_id)

        assertion = ret['assertion']
        roles = ret['roles']

        assert roles

        if len(roles) > 1:
            if interactive:
                raise NotImplementedError
            else:
                raise ManyFound("Multiple roles found: " + repr(roles))

        role = roles[0]

        resp = assume_role_with_saml(region=region, role_arn=role.role_arn,
                                     provider_arn=role.provider_arn,
                                     assertion=assertion)

        creds = resp['Credentials']

        # 'AccessKeyId': 'string',
        # 'SecretAccessKey': 'string',
        # 'SessionToken': 'string',
        # 'Expiration': datetime(2015, 1, 1)

        if print_env:
            print_env_credentials(creds)

        if save_creds:
            # TODO: save to ~/.aws/credentials
            raise NotImplementedError


def print_env_credentials(creds, region=None):
    if region:
        print 'export AWS_DEFAULT_REGION=' + region
    for item, env in [('AccessKeyId', 'AWS_ACCESS_KEY_ID'),
                      ('SecretAccessKey', 'AWS_SECRET_ACCESS_KEY'),
                      ('SessionToken', 'AWS_SESSION_TOKEN')]:
        print 'export {}={}'.format(env, creds[item])


def assume_role_with_saml(region, role_arn, provider_arn, assertion):
    sts = boto3.client('sts', region_name=region)
    return sts.assume_role_with_saml(RoleArn=role_arn,
                                     PrincipalArn=provider_arn,
                                     SAMLAssertion=assertion)

