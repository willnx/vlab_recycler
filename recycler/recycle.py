# -*- coding: UTF-8 -*-
"""Reclaim the labs of users who no longer work for the company"""
import time
import urllib3

import jwt
import ldap3
import requests
from vlab_api_common.std_logger import get_logger
from vlab_inf_common.vmware import vim, vCenter

from recycler.constants import const

LOOP_INTERVAL = 3600 # once an hour
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _get_secret(location=const.AUTH_PRIVATE_KEY_LOCATION):
    """Reads a file containing some sort of secret/password

    :Returns: String

    :Raises: RuntimeError

    :param location: The filesystem path to the auth token secret.
    """
    if not location:
        raise RuntimeError('Must supply location of auth secret, supplied: {}'.format(location))
    else:
        with open(location) as the_file:
            secret = the_file.read().strip()
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
    return jwt.encode(claims, _get_secret(), algorithm=const.AUTH_TOKEN_ALGORITHM)


def get_ldap_conn(password):
    """Simple factory for obtaining an authenticated connection to an LDAP server.

    :Returns: Tuple
    """
    server = ldap3.Server(const.AUTH_LDAP_URL)
    conn = ldap3.Connection(server, const.AUTH_BIND_USER, password, auto_bind=True)
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
    # Order matters.
    # Cannot delete a powered on VM
    # Cannot delete a network with VMs attached to it
    power_off_vms(token, const.VLAB_URL)
    delete_inventory(token, const.VLAB_URL)
    delete_networks(token, const.VLAB_URL)


def power_off_vms(token, vlab_url):
    """Turn off all VMs a user owns

    :Returns: None

    :param token: The auth token representing the user
    :type token: String

    :param vlab_url: The URL of the vLab server
    :type vlab_url: String
    """
    url = '{}/api/1/inf/power'.format(vlab_url)
    payload = {'power': "off", "machine": "all"}
    call_api(url, token, method='post', payload=payload)


def delete_inventory(token, vlab_url):
    """Destroy all VMs a user owns

    :Returns: None

    :param token: The auth token representing the user
    :type token: String

    :param vlab_url: The URL of the vLab server
    :type vlab_url: String
    """
    url = '{}/api/1/inf/inventory'.format(vlab_url)
    call_api(url,token, method='delete')


def delete_networks(token, vlab_url):
    """Destroy all VLAN networks a user owns

    :Returns: None

    :param token: The auth token representing the user
    :type token: String

    :param vlab_url: The URL of the vLab server
    :type vlab_url: String
    """
    url = '{}/api/2/inf/vlan'.format(vlab_url)
    networks = call_api(url, token)
    for network in networks.keys():
        payload = {'vlan-name' : network}
        call_api(url, token, method='delete', payload=payload)


def call_api(url, token, method='get', payload=None):
    """The infrastructure API in vLab is asynchronous. This function will block
    until the request is completely done.

    :Returns: requests.Response

    :param token: The user's authentication token
    :type token: String

    :param method: The HTTP method to evoke
    :type method: String

    :param payload: Optionally supply an HTTP body (will be converted to JSON)
    :type payload: PyObject
    """
    headers = {'X-Auth': token}
    caller =  getattr(requests, method.lower())
    resp = caller(url, headers=headers, json=payload, verify=False)
    resp.raise_for_status()
    task_url = resp.links['status']['url']
    task_resp = requests.get(task_url, headers=headers, verify=False)
    while task_resp.status_code == 202:
        time.sleep(1)
        task_resp = requests.get(task_url, headers=headers, verify=False)
    task_resp.raise_for_status()
    return task_resp.json()['content']


def main():
    """Entry point logic"""
    logger = get_logger(name=__name__)
    logger.info('Starting vLab salvager')
    logger.info("Looking for disabled users once every {} seconds".format(LOOP_INTERVAL))
    logger.info("Connecting to vCenter: {} as {}".format(const.INF_VCENTER_SERVER, const.INF_VCENTER_USER))
    logger.info("Connecting to domain {} as {}".format(const.AUTH_LDAP_URL, const.AUTH_BIND_USER))
    while True:
        ldap_password = _get_secret(const.AUTH_BIND_PASSWORD_LOCATION)
        loop_start = time.time()
        ldap_conn, ldap_server = get_ldap_conn(ldap_password)
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
