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
Unit Tests for chef_node_cleanup Lambda function
"""
from botocore.exceptions import ClientError
from mock import MagicMock, patch
from main import log_event
from main import get_instance_id
from main import get_pem

def test_log_event():
    """
    Test the log_event function
    """
    assert log_event

def test_get_instance_id():
    """
    Test the get_instance_id function with valid event
    """
    event = {'detail': {'instance-id': 'i-abcde123'}}
    assert get_instance_id(event) == 'i-abcde123'

def test_get_instance_id_with_invalid_event():
    """
    Test the get_instance_id function with invalid event
    """
    event = {}
    assert get_instance_id(event) is False

@patch('__builtin__.open')
@patch('boto3.client')
def test_decrypt(mock_client, mock_open):
    """
    Test the decrypt function with valid data
    """
    kms = MagicMock()
    mock_client.return_value = kms

    mock_open.return_value.__enter__ = lambda s: s
    mock_open.return_value.__exit__ = MagicMock()
    mock_open.return_value.read.return_value = 'blah'

    decrypted_blob = {'Plaintext': 'super_secret_key'}
    kms.decrypt.return_value = decrypted_blob
    assert decrypt() == 'super_secret_key'

@patch('boto3.client')
def test_get_pem_with_boto_failure(mock_client):
    """
    Test the decrypt function when a boto exception occurs
    """
    kms = MagicMock()
    mock_client.return_value = kms
    err_msg = {
        'Error': {
            'Code': 400,
            'Message': 'Boom!'
        }
    }
    kms.decrypt.side_effect = ClientError(err_msg, 'Test')
    assert decrypt() is False
