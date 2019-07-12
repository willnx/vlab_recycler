# -*- coding: UTF-8 -*-
"""A suite of unit tests for the ``constants.py`` module"""
import unittest

from recycler.constants import const


class TestConst(unittest.TestCase):
    """A suite of test cases for the ``consts`` object"""
    def test_expected_constants(self):
        """``const`` contains the expected constants"""
        the_consts = [x for x in dir(const) if x.isupper()]
        expected = ['AUTH_BIND_PASSWORD_LOCATION', 'AUTH_BIND_USER', 'AUTH_LDAP_URL',
                    'AUTH_PRIVATE_KEY_LOCATION', 'AUTH_SEARCH_BASE',
                    'AUTH_TOKEN_ALGORITHM', 'AUTH_TOKEN_VERSION',
                    'INF_VCENTER_PASSWORD', 'INF_VCENTER_PORT',
                    'INF_VCENTER_SERVER', 'INF_VCENTER_TOP_LVL_DIR',
                    'INF_VCENTER_USER', 'INF_VCENTER_VERIFY_CERT',
                    'VLAB_IP', 'VLAB_URL']


        self.assertEqual(set(the_consts), set(expected))


if __name__ == '__main__':
    unittest.main()
