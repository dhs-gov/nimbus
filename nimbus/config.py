"""
Configuration functions
"""

import os
from collections import namedtuple
from functools import wraps

import requests
import yaml

from .errors import NotFound, ManyFound
from .logs import log

DEFAULT_CONFIG_PATH = os.path.join(os.path.expanduser('~'), '.aws', 'nimbus.yaml')

class Config(object):

    def __init__(self, config_file=None):
        if config_file is None:
            config_file = DEFAULT_CONFIG_PATH
        self.config_file = config_file

        self.__memoized = {}

        try:
            self._load_config()
        except IOError as e:
            if e.errno == 2:
                log.warning(
                    'No config found. Use `nimbus configure` to set up.')
                raise NotFound("No config found: {!r}".format(e.filename))
            else:
                raise

    def _load_config(self):
        log.debug('Loading config from %r', self.config_file)
        with open(self.config_file, 'r') as f:
            self.data = yaml.safe_load(f)

    def validate(self):
        # ensure default stuff like region, sso, accounts exist
        raise NotImplementedError()

    def default_aws_options(self):
        return self.data.get('default_options', {})

    def default_region(self):
        return self.default_aws_options()['region']

    def aws_accounts(self):
        return self.data['aws_accounts']

    def aws_accounts_names(self):
        return [x['name'] for x in self.aws_accounts()]

    def aws_accounts_ids(self):
        return [x['account_id'] for x in self.aws_accounts()]

    def _aws_accounts_filter(self, func):
        return [x for x in self.aws_accounts() if func(x)]

    def get_aws_account(self, name=None, account_id=None):
        if name and account_id:
            raise ValueError('Must pass name or account_id, not both')
        if name is None and account_id is None:
            raise ValueError('Must pass name or account_id')

        if name:
            attr = 'name'
            desc = 'name'
            value = name
        elif account_id:
            attr = 'account_id'
            desc = 'id'
            value = account_id
        else:
            assert False

        found = self._aws_accounts_filter(lambda x: x[attr] == value)
        if not found:
            log.error("Account %s %r not found", desc, value)
            log.error("Known accounts: %r" % self.aws_accounts())
            raise NotFound('Account %s not found: %r' % (desc, value))
        if len(found) > 1:
            raise ManyFound("Multiple accts with %s %r found: %r" % (
                desc, value, found))

        return found[0]

    def default_account(self):
        info = self.data['default_account']
        if 'account_id' in info:
            return self.get_aws_account(account_id=info['account_id'])
        elif 'name' in info:
            return self.get_aws_account(name=info['name'])
        else:
            raise ValueError("Must have name or account_id in default_account")

    def default_account_id(self):
        return self.default_account()['account_id']

    def default_role(self):
        self.data['default_account']['role']

    def save(self):
        # TODO: make atomic
        log.debug('Writing config to %r', self.config_file)
        with open(self.config_file, 'w') as f:
            yaml.safe_dump(self.data, f)

    def interactive_create_config(self):
        raise NotImplementedError

    def download_configuration(self, url):
        """
        Download configuration from a given URL
        """

        log.info('Downloading configuration from %r', url)

        resp = requests.get(url)
        resp.raise_for_status()

        log.debug('Loading')

        # ensure yaml loadable
        self.data = yaml.safe_load(resp.text)

        self.save()

        log.info('Saved configuration to %r', self.config_file)

