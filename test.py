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
        LOGGER.error(err)
        return False

AD_USER = 'user_with_ad_admin_access'
AD_PASSWORD = decrypt('encrypted_AD_password.txt')
AD_SERVER = 'ad-server.example.com'
machine_name = 'testhostname'

if machine_name:
    s = winrm.Session(AD_SERVER, auth=(AD_USER, AD_PASSWORD))
    r = s.run_cmd('ipconfig', ['/all'])

    print "====== Status Code ======="
    print r.status_code
    print "====== Standard Out ======="
    print r.std_out
    print "====== ERROR ======="
    print r.std_err
