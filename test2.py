from base64 import b64decode
from botocore.exceptions import ClientError
import boto3
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
        print err
        return False

AD_USER = 'lambda.aws'
AD_PASSWORD = decrypt('encrypted_AD_password.txt')
AD_SERVER = 'paw2am-ad01.teamfreeze.com'
SW_SERVER = 'solar.teamfreeze.com'
SW_USER = 'auto.manage'
SW_PASSWORD = decrypt('encrypted_SW_password.txt')

machine_name = 'taw2al-tstlam01'
machine_ip = '172.21.16.188'

if machine_name:
    ps_script = """Add-PSSnapin SwisSnapin
        $Username = '{}'
        $Password = ConvertTo-SecureString -String '{}' -AsPlainText -Force
        $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $Password
        $ORIONSERVERNAME = '{}'
        $swis = Connect-Swis -Credential $cred -host $orionservername
        $nodeuri = Get-SwisData $swis "SELECT uri FROM Orion.Nodes WHERE IP LIKE '{}'"
        Remove-SwisObject $swis -Uri $nodeuri """.format(SW_USER, SW_PASSWORD, SW_SERVER, machine_ip)
    print ps_script

    s = winrm.Session(AD_SERVER, auth=(AD_USER, AD_PASSWORD))
    try:
        r = s.run_ps(ps_script)
        print("====== Status Code =======")
        print(r.status_code)
        print("====== Standard Out =======")
        print(r.std_out)
        print("====== ERROR =======")
        print(r.std_err)
        print '=====SUCCESSFULLY REMOVED INSTANCE {} FROM SolarWinds===== '.format(machine_name)

    except Exception as err:
        print err
