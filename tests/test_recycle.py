# -*- coding: UTF-8 -*-
"""A suite of unit tests for the ``recycle`` module"""
import unittest
from unittest.mock import patch, MagicMock

from recycler import recycle


class TestGetAuthTokenSecret(unittest.TestCase):
    """A suite of test cases for the ``_get_auth_token_secret`` function"""
    def test_no_location(self):
        """``_get_auth_token_secret`` raises RuntimeError if the 'location' parameter is not true"""
        with self.assertRaises(RuntimeError):
            recycle._get_auth_token_secret(location=None)

    @patch("recycler.recycle.open", create=True)
    def test_reads_file(self, fake_open):
        """``_get_auth_token_secret`` reads the secret out of the supplied file"""
        fake_file = MagicMock()
        fake_file.read.return_value = 'aa.bb.cc'
        fake_open.return_value.__enter__.return_value = fake_file

        secret = recycle._get_auth_token_secret(location='/some/path/location')
        expected = 'aa.bb.cc'

        self.assertEqual(secret, expected)


class TestGenerateToken(unittest.TestCase):
    """A suite of tests cases for the ``generate_token`` function"""
    @patch.object(recycle, '_get_auth_token_secret')
    @patch.object(recycle.jwt, 'encode')
    def test_token(self, fake_encode, fake_get_auth_token_secret):
        """``generate_token`` returns an encoded JSON Web Token"""
        fake_encode.return_value = 'aa.bb.cc'

        token = recycle.generate_token(username='bob')
        expected = 'aa.bb.cc'

        self.assertEqual(token, expected)


class TestGetLdapConn(unittest.TestCase):
    """A suite of test cases for the ``get_ldap_conn`` function"""
    @patch.object(recycle.ldap3, 'Server')
    @patch.object(recycle.ldap3, 'Connection')
    def test_get_ldap_conn(self, fake_Connection, fake_Server):
        """``get_ldap_conn`` returns a tuple"""
        fake_server = MagicMock()
        fake_Server.return_value = fake_server
        fake_conn = MagicMock()
        fake_Connection.return_value = fake_conn

        result = recycle.get_ldap_conn()
        expected = (fake_conn, fake_server)

        self.assertEqual(result, expected)


class TestUserDisabled(unittest.TestCase):
    """A suite of test cases for the ``user_disabled`` function"""
    @classmethod
    def setUp(cls):
        """Runs before every test case"""
        cls.fake_ldap_conn = MagicMock()
        cls.fake_ldap_conn.search.return_value = True
        cls.fake_user = MagicMock()
        cls.fake_user.userAccountControl.value = 0
        cls.fake_ldap_conn.entries = [cls.fake_user]

    def test_user_disabled_true(self):
        """``user_disabled`` returns True if the user account is disabled"""
        self.fake_user.userAccountControl.value = 2
        disabled = recycle.user_disabled(username='alice', ldap_conn=self.fake_ldap_conn)

        self.assertTrue(disabled is True)

    def test_user_disabled_false(self):
        """``user_disabled`` returns False if the user account is not disabled"""
        disabled = recycle.user_disabled(username='alice', ldap_conn=self.fake_ldap_conn)

        self.assertTrue(disabled is False)

    def test_user_disabled_not_found(self):
        """``user_disabled`` raises RuntimeError when unable to find the user in LDAP"""
        self.fake_ldap_conn.search.return_value = False
        with self.assertRaises(RuntimeError):
            recycle.user_disabled(username='alice', ldap_conn=self.fake_ldap_conn)


class TestNukeLab(unittest.TestCase):
    """A suite of test cases for the ``nuke_lab`` function"""
    @patch.object(recycle, 'generate_token')
    @patch.object(recycle, 'power_off_vms')
    @patch.object(recycle, 'delete_inventory')
    @patch.object(recycle, 'delete_networks')
    def test_nuke_lab(self, fake_delete_networks, fake_delete_inventory, fake_power_off_vms, fake_generate_token):
        """``nuke_lab`` is just a convenient wrapper to delete a user's lab resources"""
        recycle.nuke_lab(username='pat')

        self.assertTrue(fake_delete_networks.called)
        self.assertTrue(fake_delete_inventory.called)
        self.assertTrue(fake_power_off_vms.called)
        self.assertTrue(fake_generate_token.called)


class TestNukeLabFunctions(unittest.TestCase):
    """A suite of test cases for the functions called by the ``nuke_lab`` function"""
    @classmethod
    def setUp(cls):
        """Runs before every test case"""
        cls.headers = {'X-Auth' : 'aa.bb.cc'}
        cls.fake_resp = MagicMock()

    @patch.object(recycle.requests, 'post')
    def test_power_off_vms(self, fake_post):
        """``power_off_vms`` Makes the correct API call to turn off a user's VMs"""
        fake_url = 'https://some.vlab.server'
        fake_post.return_value = self.fake_resp

        recycle.power_off_vms(self.headers, fake_url)

        the_args, _ = fake_post.call_args
        called_url = the_args[0]
        expected_url = 'https://some.vlab.server/api/1/inf/power'

        self.assertEqual(called_url, expected_url)

    @patch.object(recycle.requests, 'delete')
    def test_delete_inventory(self, fake_delete):
        """``delete_inventory`` Makes the correct API call to turn off a user's VMs"""
        fake_url = 'https://some.vlab.server'
        fake_delete.return_value = self.fake_resp

        recycle.delete_inventory(self.headers, fake_url)

        the_args, _ = fake_delete.call_args
        called_url = the_args[0]
        expected_url = 'https://some.vlab.server/api/2/inf/inventory'

        self.assertEqual(called_url, expected_url)

    @patch.object(recycle.requests, 'get')
    @patch.object(recycle.requests, 'delete')
    def test_delete_networks(self, fake_delete, fake_get):
        """``delete_networks`` Makes the correct API call to turn off a user's VMs"""
        fake_url = 'https://some.vlab.server'
        fake_delete.return_value = self.fake_resp
        fake_get_resp = MagicMock()
        fake_get_resp.json.return_value = {'content' : {'someNet': 123}}
        fake_get.return_value = fake_get_resp

        recycle.delete_networks(self.headers, fake_url)

        the_args, _ = fake_delete.call_args
        called_url = the_args[0]
        expected_url = 'https://some.vlab.server/api/2/inf/network'

        self.assertEqual(called_url, expected_url)


class TestMain(unittest.TestCase):
    """A suite of test cases for the ``main`` function"""
    @patch.object(recycle, 'get_logger')
    @patch.object(recycle, 'vCenter')
    @patch.object(recycle, 'get_ldap_conn')
    @patch.object(recycle, 'user_disabled')
    @patch.object(recycle, 'nuke_lab')
    @patch.object(recycle.time, 'sleep')
    def test_main(self, fake_sleep, fake_nuke_lab, fake_user_disabled, fake_get_ldap_conn, fake_vCenter, fake_get_logger):
        """``main`` sleeps after every loop to check for disabled user accounts"""
        fake_ldap_conn = MagicMock()
        fake_ldap_server = MagicMock()
        fake_get_ldap_conn.return_value = (fake_ldap_conn, fake_ldap_server)
        fake_user = MagicMock()
        fake_user.name = 'pat'
        fake_folder = MagicMock()
        fake_folder.childEntity = [fake_user]
        fake_vcenter = MagicMock()
        fake_vcenter.get_by_name.return_value = fake_folder
        fake_vCenter.return_value.__enter__.return_value = fake_vcenter
        fake_user_disabled.return_value = True
        # Hack to break the while True loop
        fake_sleep.side_effect = [1, SystemError('testing')]

        with self.assertRaises(SystemError):
            recycle.main()

        sleep_count = fake_sleep.call_count
        loops_ran = 2 # 2 loops ran because of the side_effect on the mock object

        self.assertEqual(sleep_count, loops_ran)

    @patch.object(recycle, 'get_logger')
    @patch.object(recycle, 'vCenter')
    @patch.object(recycle, 'get_ldap_conn')
    @patch.object(recycle, 'user_disabled')
    @patch.object(recycle, 'nuke_lab')
    @patch.object(recycle.time, 'sleep')
    def test_main_errors(self, fake_sleep, fake_nuke_lab, fake_user_disabled, fake_get_ldap_conn, fake_vCenter, fake_get_logger):
        """``main`` Logs and error and proceeds to the next user while looping"""
        fake_log = MagicMock()
        fake_get_logger.return_value = fake_log
        fake_ldap_conn = MagicMock()
        fake_ldap_server = MagicMock()
        fake_get_ldap_conn.return_value = (fake_ldap_conn, fake_ldap_server)
        fake_user = MagicMock()
        fake_user.name = 'pat'
        fake_folder = MagicMock()
        fake_folder.childEntity = [fake_user]
        fake_vcenter = MagicMock()
        fake_vcenter.get_by_name.return_value = fake_folder
        fake_vCenter.return_value.__enter__.return_value = fake_vcenter
        fake_user_disabled.return_value = True
        # Hack to break the while True loop
        fake_sleep.side_effect = [1, SystemError('testing')]
        fake_nuke_lab.side_effect = [1, RuntimeError('fake error')]

        with self.assertRaises(SystemError):
            recycle.main()

        self.assertTrue(fake_log.exception.called)



if __name__ == '__main__':
    unittest.main()
