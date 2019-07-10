# -*- coding: UTF-8 -*-
"""
All the things can override via Environment variables are keep in this one file.
"""
from os import environ
from collections import namedtuple, OrderedDict


DEFINED = OrderedDict([
            ('INF_VCENTER_SERVER', environ.get('INF_VCENTER_SERVER', 'localhost')),
            ('INF_VCENTER_PORT', int(environ.get('INFO_VCENTER_PORT', 443))),
            ('INF_VCENTER_USER', environ.get('INF_VCENTER_USER', 'tester')),
            ('INF_VCENTER_PASSWORD', environ.get('INF_VCENTER_PASSWORD', 'a')),
            ('INF_VCENTER_TOP_LVL_DIR', environ.get('INF_VCENTER_TOP_LVL_DIR', 'users')),
            ('INF_VCENTER_VERIFY_CERT', environ.get('INF_VCENTER_VERIFY_CERT', False)),
            ('AUTH_PRIVATE_KEY_LOCATION', environ.get('AUTH_PRIVATE_KEY_LOCATION', False)),
            ('AUTH_TOKEN_ALGORITHM', environ.get('AUTH_TOKEN_ALGORITHM', 'HS256')),
            ('VLAB_URL', environ.get('VLAB_URL', 'https://some.vlab.org')),
            ('VLAB_IP', environ.get('VLAB_IP', '127.0.0.1')),
            ('AUTH_LDAP_URL', environ.get('AUTH_LDAP_URL', 'ldaps://localhost')),
            ('AUTH_BIND_USER', environ.get('AUTH_BIND_USER', 'noone')),
            ('AUTH_BIND_PASSWORD', environ.get('AUTH_BIND_PASSWORD', 'a')),
            ('AUTH_SEARCH_BASE', environ.get('AUTH_SEARCH_BASE','DC=localhost,DC=local')),
            ('AUTH_TOKEN_VERSION', int(environ.get('AUTH_TOKEN_VERSION', 2)))
          ])

Constants = namedtuple('Constants', list(DEFINED.keys()))

# The '*' expands the list, just liked passing a function *args
const = Constants(*list(DEFINED.values()))
