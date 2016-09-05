"""
Functions for authenticating to AWS via a SAML Identity Provider (IDP).
"""

import base64
import os
import re
import xml.etree.ElementTree as ElementTree
from collections import namedtuple

import requests
from bs4 import BeautifulSoup
from requests_kerberos import HTTPKerberosAuth, OPTIONAL

from .logs import log
from .errors import NotFound

class SSOProvider(object):

    @classmethod
    def new_from_config(klass, config):
        info = config.data['sso']
        return klass(auth_method=info['auth_method'],
                     idp_start_url=info['url'],
                     idp_ssl_verify=os.path.expanduser(info['ca_file']))

    def __init__(self, auth_method, idp_start_url, idp_ssl_verify):
        self.auth_method = auth_method
        self.idp_start_url = idp_start_url
        self.idp_ssl_verify = idp_ssl_verify
        log.debug('Initialized SSOProvider(%r, %r, %r)',
                  auth_method, idp_start_url, idp_ssl_verify)

    def get_assertion_and_roles(self, aws_account=None):
        response = self.do_auth_request(auth_method=self.auth_method,
                                        idp_start_url=self.idp_start_url,
                                        idp_ssl_verify=self.idp_ssl_verify)

        assertion = self._get_assertion_from_html(response.text)
        roles = self._get_roles_in_assertion(assertion)

        log.debug('Received %d roles', len(roles))

        if aws_account:
            log.debug('Searching for roles for account %r', aws_account)

            found = [x for x in roles if x.account == aws_account]
            if not found:
                raise NotFound(
                    'No roles found for account {!r}'.format(aws_account))
        else:
            found = roles

        if not found:
            raise NotFound('No roles found in SAML response')

        return {'assertion': assertion, 'roles': found}

    def do_auth_request(self, auth_method, idp_start_url, idp_ssl_verify=True,
                       print_response=False):
        """
        Authenticate to the SSO provider to get the SAML assertion.
        """

        log.info('Initiating auth request to %r', idp_start_url)

        # Initiate session handler
        session = requests.Session()

        # set up authentication
        try:
            setup_method = self._AUTH_METHOD_MAP[auth_method]
        except KeyError:
            raise ValueError(
                "Bad auth_method {0!r}, expected one of {1!r}".format(
                    auth_method, self._AUTH_METHOD_MAP.keys()))
        setup_method(self, requests_session=session)

        log.debug('Sending HTTP request')

        # Opens the initial IDP URL and follows all of the HTTP 302 redirects
        resp = session.get(idp_start_url, verify=idp_ssl_verify)

        if print_response:
            print(resp.body)

        if resp.status_code != 200:
            log.warning("Received HTTP status code %d when requesting %r",
                        resp.status_code, resp.url)
            resp.raise_for_status()

        return resp

    def _setup_auth_kerberos(self, requests_session):
        log.debug('Setting up kerberos auth')

        # Set up the kerberos authentication handler
        requests_session.auth = HTTPKerberosAuth(mutual_authentication=OPTIONAL)

    _AUTH_METHOD_MAP = {
        'kerberos': _setup_auth_kerberos,
    }

    def _get_assertion_from_html(self, body):
        """
        Given a string containing an HTML SAML response, extract the SAML
        assertion and parse out the AWS ARN of the roles.

        :param body: The HTML text
        :type body: str

        :return: The SAML response string
        :rtype: str

        """

        # decode the response and extract the SAML assertion
        soup = BeautifulSoup(body, 'html.parser')
        assertion = None

        # look for <input name=SAMLResponse />
        for inputtag in soup.find_all('input'):
            if inputtag.get('name') == 'SAMLResponse':
                log.debug('<input name=SAMLResponse /> found')
                #log.debug(inputtag.get('value'))
                assertion = inputtag['value']

        if assertion is None:
            raise NotFound('No <input name=SAMLResponse /> found in response')

        if not assertion:
            raise ValueError('SAMLResponse <input> tag was empty')

        return assertion

    def _get_roles_in_assertion(self, assertion):
        """
        Decode a SAML assertion and parse all the AWS roles.

        :param assertion: The SAML assertion in base64-encoded XML
        :type assertion: str

        :return: A list of AWS role info (namedtuples)
        :rtype: list<RoleInfo>
        """

        # Parse the returned assertion and extract the authorized roles
        awsroles = []
        root = ElementTree.fromstring(base64.b64decode(assertion))

        for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
            if saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role':
                for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                    awsroles.append(saml2attributevalue.text)

        # parse role ARN strings into RoleInfo namedtuples
        return map(self._parse_role_arns, awsroles)

    def _parse_role_arns(self, arnstring):
        """
        Note the format of the attribute value should be role_arn,principal_arn
        but lots of blogs list it as principal_arn,role_arn.

        "arn:aws:iam::111111111111:role/ReadOnly,arn:aws:iam::111111111111:saml-provider/MYSSO"

        :param arnstring: The ARN string, as above.
        :type arnstring: str

        :rtype: RoleInfo
        """
        role, provider = arnstring.split(',')

        # must have been out-of-order
        if ':saml-provider/' in role:
            role, provider = provider, role

        r = re.search(r'^arn:aws:iam::(\d+):role/([^,]+)', role)
        if not r:
            raise RuntimeError("Failed to parse role arn {!r}".format(role))

        account = r.group(1)
        role_name = r.group(2)

        return RoleInfo(role_arn=role, provider_arn=provider,
                        account=account, role=role_name)

RoleInfo = namedtuple('RoleInfo',
                      ['role_arn', 'provider_arn', 'role', 'account'])

