"""
Bitbucket OAuth support.

This adds support for Bitbucket OAuth service. An application must
be registered first on Bitbucket and the settings BITBUCKET_CONSUMER_KEY
and BITBUCKET_CONSUMER_SECRET must be defined with the corresponding
values.

By default username, email, token expiration time, first name and last name are
stored in extra_data field, check OAuthBackend class for details on how to
extend it.
"""
from __future__ import absolute_import

import simplejson

from six.moves.urllib.error import HTTPError
from six.moves.urllib.parse import urlencode
from social_auth.backends import BaseOAuth2, OAuthBackend
from social_auth.utils import dsa_urlopen

# Bitbucket configuration
BITBUCKET_AUTHORIZATION_URL = 'https://bitbucket.org/site/oauth2/authorize'
BITBUCKET_ACCESS_TOKEN_URL = 'https://bitbucket.org/site/oauth2/access_token'
BITBUCKET_USER_DATA_URL = 'https://bitbucket.org/api/2.0/user/'


class BitbucketBackend(OAuthBackend):
    """Bitbucket OAuth authentication backend"""
    name = 'bitbucket'
    EXTRA_DATA = [
        ('username', 'username'),
        ('expires', 'expires'),
        ('email', 'email'),
        ('first_name', 'first_name'),
        ('last_name', 'last_name')
    ]

    def _fetch_primary_email(self, access_token):
        """Fetch primary email from Bitbucket account"""
        url = BITBUCKET_USER_DATA_URL + '/emails?' + urlencode({
            'fields': '-values.links',
            'pagelen': 100,
            'access_token': access_token
        })

        try:
            emails = simplejson.load(dsa_urlopen(url)).get('values', [])
        except (ValueError, HTTPError):
            emails = []
        primary = ''
        for email in emails:
            if email.get('is_primary', False):
                primary = email.get('email', '')
                break
        return primary

    def get_user_details(self, response):
        """Return user details from Bitbucket account"""
        name = response.get('display_name') or ''
        details = {'username': response.get('username')}

        details['email'] = self._fetch_primary_email(
            response.get('access_token'))

        try:
            # Bitbucket doesn't separate first and last names. Let's try.
            first_name, last_name = name.split(' ', 1)
        except ValueError:
            details['first_name'] = name
        else:
            details['first_name'] = first_name
            details['last_name'] = last_name
        return details

    def get_user_id(self, details, response):
        """Return the user id, Bitbucket provides uuid as a unique
        identifier"""
        return response['uuid']


class BitbucketAuth(BaseOAuth2):
    """Bitbucket OAuth2 mechanism"""
    AUTHORIZATION_URL = BITBUCKET_AUTHORIZATION_URL
    ACCESS_TOKEN_URL = BITBUCKET_ACCESS_TOKEN_URL
    AUTH_BACKEND = BitbucketBackend
    SETTINGS_KEY_NAME = 'BITBUCKET_CONSUMER_KEY'
    SETTINGS_SECRET_NAME = 'BITBUCKET_CONSUMER_SECRET'
    DEFAULT_SCOPE = ['email', 'account', 'webhook', 'repository', 'issue']

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service"""
        url = BITBUCKET_USER_DATA_URL + '?' + urlencode({
            'fields': '-links',
            'access_token': access_token
        })

        try:
            data = simplejson.load(dsa_urlopen(url))
        except ValueError:
            data = None

        return data

# Backend definition
BACKENDS = {
    'bitbucket': BitbucketAuth,
}
