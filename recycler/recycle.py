# -*- coding: UTF-8 -*-
"""Reclaim the labs of users who no longer work for the company"""
import time

import jwt
import ldap3
import requests
from vlab_api_common.std_logger import get_logger
from vlab_inf_common.vmware import vim, vCenter

from recycler.constants import const

LOOP_INTERVAL = 3600 # once an hour


def _get_auth_token_secret(location=const.AUTH_PRIVATE_KEY_LOCATION):
    """
    :Returns: String

    :Raises: RuntimeError

    :param location: The filesystem path to the auth token secret.
    """
    if not location:
        raise RuntimeError('Must supply location of auth secret, supplied: {}'.format(location))
    else:
        with open(location) as the_file:
            secret = the_file.read()
    return secret


def generate_token(username, version=const.AUTH_TOKEN_VERSION, client_ip=const.VLAB_IP):
    """Create an auth token

    :Returns: String

    :param username: The user who's account has been disabled
    :type username: String

    :param version: The version of the auth token to create
    :type version: Integer

    :param client_ip: The IP of the machine that will send requests
    :type client_ip: String
    """
    issued_at_timestamp = time.time()
    claims = {'exp' : issued_at_timestamp + 1800, # 30 minutes
              'iat' : issued_at_timestamp,
              'iss' : const.VLAB_URL,
              'username' : username,
              'version' : version,
              'client_ip' : client_ip,
             }
    return jwt.encode(claims, _get_auth_token_secret(), algorithm=const.AUTH_TOKEN_ALGORITHM)


def get_ldap_conn():
    """Simple factory for obtaining an authenticated connection to an LDAP server.

    :Returns: Tuple
    """
    server = ldap3.Server(const.AUTH_LDAP_URL)
    conn = ldap3.Connection(server, const.AUTH_BIND_USER, const.AUTH_BIND_PASSWORD, auto_bind=True)
    return conn, server


def user_disabled(username, ldap_conn):
    """Check if a user account is disabled. Returns True when the account is disabled.

    :Returns: Boolean

    :Raises: RuntimeError - If user not found in LDAP server

    :param username: The samAccountName of the vLab user
    :type username: String

    :param ldap_conn: An authenicated, bound connection to an LDAP server
    :type ldap_conn: ldap3.Connection
    """
    search_filter = '(&(objectclass=User)(sAMAccountName=%s))' % username
    if ldap_conn.search(search_base=const.AUTH_SEARCH_BASE,
                        search_filter=search_filter,
                        attributes=['userAccountControl']):
        user = ldap_conn.entries[0]
        disabled = user.userAccountControl.value >> 1 & 1
        return bool(disabled)
    else:
        raise RuntimeError('Unable to find a user by samAccoutName {}'.format(username))


def nuke_lab(username):
    """A wrapper to delete all lab resources owned by a given user

    :Returns: None

    :param username: The user to reclaim lab resource from
    :type username: String
    """
    token = generate_token(username)
    headers = {'X-Auth': token}
    power_off_vms(headers, const.VLAB_URL)
    delete_inventory(headers, const.VLAB_URL)
    delete_networks(headers, const.VLAB_URL)


def power_off_vms(headers, vlab_url):
    """Turn off all VMs a user owns

    :Returns: None

    :param headers: The headers to send when powering off all VMs
    :type headers: Dictionary

    :param vlab_url: The URL of the vLab server
    :type vlab_url: String
    """
    url = '{}/api/1/inf/power'.format(vlab_url)
    payload = {'power': "off", "machine": "all"}
    resp = requests.post(url, headers=headers, json=payload, verify=False)
    resp.raise_for_status()


def delete_inventory(headers, vlab_url):
    """Destroy all VMs a user owns

    :Returns: None

    :param headers: The headers to send when powering off all VMs
    :type headers: Dictionary

    :param vlab_url: The URL of the vLab server
    :type vlab_url: String
    """
    url = '{}/api/2/inf/inventory'.format(vlab_url)
    resp = requests.delete(url, headers=headers, verify=False)
    resp.raise_for_status()


def delete_networks(headers, vlab_url):
    """Destory all VLAN networks a user owns

    :Returns: None

    :param headers: The headers to send when powering off all VMs
    :type headers: Dictionary

    :param vlab_url: The URL of the vLab server
    :type vlab_url: String
    """
    url = '{}/api/2/inf/network'.format(vlab_url)
    networks = requests.get(url, headers=headers, verify=False).json()['content']
    for network in networks.keys():
        payload = {'vlan' : network}
        resp = requests.delete(url, json=payload, headers=headers, verify=False)
        resp.raise_for_status()


def main():
    """Entry point logic"""
    logger = get_logger(name=__name__)
    logger.info('Starting vLab salvager')
    logger.info("Looking for disabled users once every {} seconds".format(LOOP_INTERVAL))
    logger.info("Connecting to vCenter: {} as {}".format(const.INF_VCENTER_SERVER, const.INF_VCENTER_USER))
    logger.info("Connecting to domain {} as {}".format(const.AUTH_LDAP_URL, const.AUTH_BIND_USER))
    while True:
        loop_start = time.time()
        ldap_conn, ldap_server = get_ldap_conn()
        with vCenter(host=const.INF_VCENTER_SERVER, user=const.INF_VCENTER_USER, \
                     password=const.INF_VCENTER_PASSWORD) as vcenter:
            vlab_folder = vcenter.get_by_name(name=const.INF_VCENTER_TOP_LVL_DIR, vimtype=vim.Folder)
            for user in vlab_folder.childEntity:
                try:
                    if user_disabled(user.name, ldap_conn):
                        logger.info('User {} disabled, deleting lab'.format(user.name))
                        nuke_lab(user.name)
                except RuntimeError as doh:
                    logger.exception(doh)
        ldap_conn.unbind()
        loop_ran_for = time.time() - loop_start
        loop_interval_delta = max(0, LOOP_INTERVAL - loop_ran_for)
        time.sleep(loop_interval_delta)


if __name__ == '__main__':
    main()
