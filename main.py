# Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file
# except in compliance with the License. A copy of the License is located at
#
#     http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS"
# BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under the License.
"""
Remove a node from Chef server when a termination event is received
joshcb@amazon.com

Extended by corey.hemminger@nativex.com for multiple chef organizations and to clean up
AD, DNS, spacewalk, solarwinds, chef Automate.

Please follow instructions found at https://aws.amazon.com/blogs/apn/automatically-delete-terminated-instances-in-chef-server-with-aws-lambda-and-cloudwatch-events/
or the original github repo found at https://github.com/awslabs/lambda-chef-node-cleanup/blob/master/lambda/main.py
v3.0.0
"""
from __future__ import print_function
import logging
# only needed to using self signed certificate as noted below on line 52
import os
from base64 import b64decode
from botocore.exceptions import ClientError
import boto3
from chef import ChefAPI, Node, Search, Client
from chef.exceptions import ChefServerNotFoundError
import paramiko
import winrm
import xmlrpclib

def decrypt(file_name):
    """Decrypt the Ciphertext Blob to get USERNAME's pem or password"""
    try:
        with open(file_name, 'r') as encrypted_file:
            hash_file = encrypted_file.read()
        kms = boto3.client('kms')
        return kms.decrypt(CiphertextBlob=b64decode(hash_file))['Plaintext']
    except (IOError, ClientError, KeyError) as err:
        LOGGER.error(err)
        return False

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)
CHEF_SERVER_URLS = (
    'https://chef-automate-zddqq0w8qotvayto.us-west-2.opsworks-cm.io/organizations/default',
    'https://chef-automate-zddqq0w8qotvayto.us-west-2.opsworks-cm.io/organizations/corey-dev',
    'https://chef-automate-zddqq0w8qotvayto.us-west-2.opsworks-cm.io/organizations/dan-dev'
)
CHEF_USERNAME = 'lambda_aws'
CHEF_PEM = decrypt('encrypted_chef_pem.txt')
# Needed if using self signed certs such as when using a test Chef Server.
# Include the certificate in the Lambda package at the location specified.
os.environ["SSL_CERT_FILE"] = "opsworks-cm-ca-2016-root.pem"
SATELLITE_URL = "http://spacewalk.teamfreeze.com/rpc/api"
SATELLITE_LOGIN = 'rpc.user'
SATELLITE_PASSWORD = decrypt('encrypted_spacewalk_password.txt')
AD_USER = 'lambda.aws'
AD_PASSWORD = decrypt('encrypted_AD_password.txt')
AD_SERVER = 'paw2am-ad01.teamfreeze.com'
SW_SERVER = 'solar.teamfreeze.com'
SW_USER = 'auto.manage'
SW_PASSWORD = decrypt('encrypted_SW_password.txt')
sshhostname = 'chef-automate-zddqq0w8qotvayto.us-west-2.opsworks-cm.io'
sshuser = 'ec2-user'
sshkey = 'aws_ssh_key_pem.txt'

def chef_automate_cleanup(machine_name):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(sshhostname, username=sshuser, key_filename=sshkey)
    try:
        stdin, stdout, stderr = ssh.exec_command('automate-ctl delete-visibility-node {}'.format(machine_name))
        LOGGER.info('=====SUCCESSFULLY REMOVED INSTANCE {} FROM Chef Automate===== '.format(machine_name))
        LOGGER.info(stdout.readlines())
    except Exception as err:
        LOGGER.error(err)
    ssh.close()

def active_directory_cleanup(machine_name):
    if machine_name:
        ps_script = """Remove-ADComputer -Identity "{}" -confirm:$false""".format(machine_name)

        s = winrm.Session(AD_SERVER, auth=(AD_USER, AD_PASSWORD))
        try:
            r = s.run_ps(ps_script)
            LOGGER.info('=====SUCCESSFULLY REMOVED INSTANCE {} FROM AD===== '.format(machine_name))
        except r.std_err as err:
            LOGGER.error(err)

def dns_cleanup(machine_name):
    if machine_name:
        ps_script = """$NodeToDelete = "{}"
            $DNSServer = "{}"
            $ZoneName = "teamfreeze.com"
            $NodeDNS = $null
            $NodeDNS = Get-DnsServerResourceRecord -ZoneName $ZoneName -ComputerName $DNSServer -Node $NodeToDelete -RRType A -ErrorAction SilentlyContinue
            if($NodeDNS -eq $null){{
                Write-Host "No DNS record found"
            }}
            else {{
                Remove-DnsServerResourceRecord -ZoneName $ZoneName -ComputerName $DNSServer -InputObject $NodeDNS -Force
            }} """.format(machine_name, AD_SERVER)

        s = winrm.Session(AD_SERVER, auth=(AD_USER, AD_PASSWORD))
        try:
            r = s.run_ps(ps_script)
            LOGGER.info('=====SUCCESSFULLY REMOVED INSTANCE {} FROM DNS===== '.format(machine_name))
        except r.std_err as err:
            LOGGER.error(err)

def solarwinds_cleanup(machine_ip, machine_name):
    if machine_name:
        ps_script = """Add-PSSnapin SwisSnapin
            $Username = '{}'
            $Password = ConvertTo-SecureString -String '{}' -AsPlainText -Force
            $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $Password
            $ORIONSERVERNAME = '{}'
            $nodeIP = '{}'
            $swis = Connect-Swis -Credential $cred -host $orionservername
            $nodeuri = Get-SwisData $swis "SELECT uri FROM Orion.Nodes WHERE IP LIKE '$nodeIP'"
            Remove-SwisObject $swis -Uri $nodeuri """.format(SW_USER, SW_PASSWORD, SW_SERVER, machine_ip)

        s = winrm.Session(AD_SERVER, auth=(AD_USER, AD_PASSWORD))
        try:
            s.run_ps(ps_script)
            LOGGER.info('=====SUCCESSFULLY REMOVED INSTANCE {} FROM SolarWinds===== '.format(machine_name))
        except Exception as err:
            LOGGER.error(err)

def spacewalk_cleanup(machine_ip):
    if machine_ip:
        client = xmlrpclib.Server(SATELLITE_URL, verbose=0)

        key = client.auth.login(SATELLITE_LOGIN, SATELLITE_PASSWORD)
        list = client.system.search.ip(key, machine_ip)
        for system in list:
            name = system.get('name')
            id = system.get('id')
            try:
                client.system.deleteSystem(key, id)
                LOGGER.info('=====SUCCESSFULLY REMOVED INSTANCE {} FROM Spacewalk Server===== '.format(name))
            except Exception as err:
                LOGGER.error(err)

        client.auth.logout(key)

def log_event(event):
    """Logs event information for debugging"""
    LOGGER.info("========================================================")
    LOGGER.info(event)
    LOGGER.info("========================================================")

def get_instance_id(event):
    """Parses InstanceID from the event dict and gets the FQDN from EC2 API"""
    try:
        return event['detail']['instance-id']
    except KeyError as err:
        LOGGER.error(err)
        return False

def handle(event, _context):
    """Lambda Handler"""
    log_event(event)
    node_name = None
    node_ip = None

    # Remove from one of the chef servers
    for URL in CHEF_SERVER_URLS:
        with ChefAPI(URL, CHEF_PEM, CHEF_USERNAME):
            instance_id = get_instance_id(event)
            try:
                search = Search('node', 'ec2_instance_id:' + instance_id)
            except ChefServerNotFoundError as err:
                LOGGER.error(err)
                return False

            if len(search) != 0:
                for instance in search:
                    node_name = instance.object.name
                    node = Node(node_name)
                    node_ip = node['ipaddress']
                    client = Client(node_name)

                    try:
                        node.delete()
                        client.delete()
                        LOGGER.info('=====SUCCESSFULLY REMOVED INSTANCE FROM CHEF SERVER===== {}'.format(URL))
                        break
                    except ChefServerNotFoundError as err:
                        LOGGER.error(err)
                        return False
            else:
                LOGGER.info('===Instance does not appear to be Chef Server managed.=== {}'.format(URL))

    # Remove from Spacewalk
    spacewalk_cleanup(node_ip)

    # Remove from DNS
    dns_cleanup(node_name)

    # Remove from AD
    active_directory_cleanup(node_name)

    # Remove fom Solarwinds
    solarwinds_cleanup(node_ip, node_name)

    # Remove from Chef Automate
    chef_automate_cleanup(node_name)
