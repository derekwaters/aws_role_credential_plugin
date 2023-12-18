"""This module provides the ability to retrieve AWS credentials from a short-lived
assumed STS role"""
import collections
import datetime
import hashlib
import boto3

try:
    from botocore.exceptions import ClientError
    from botocore.exceptions import ParamValidationError
except ImportError:
    pass  # caught by AnsibleAWSModule

_aws_cred_cache = {}

CredentialPlugin = collections.namedtuple('CredentialPlugin', ['name', 'inputs', 'backend'])

def aws_role_credential_backend(**kwargs):
    """This backend function actually contacts AWS to assume a given role for the specified user"""
    access_key = kwargs.get('access_key')
    secret_key = kwargs.get('secret_key')
    role_arn = kwargs.get('role_arn')
    aws_region = kwargs.get('aws_region')
    identifier = kwargs.get('identifier')

    now = datetime.datetime.now()

    # Generate a hash unique MD5 for combo of user access key and ARN
    # This should allow two users requesting the same ARN role to have
    # separate credentials, and should allow the same user to request
    # multiple roles.
    #
    credential_key = hashlib.md5(access_key + role_arn)

    credentials = _aws_cred_cache.get(credential_key, None)

    # If there are no credentials for this user/ARN *or* the credentials
    # we have in the cache have expired, then we need to contact AWS again.
    #
    if (credentials is None) or (credentials['Expiration'] < now):

        # Now call out to boto to assume the role
        connection = boto3.client(
            service_name="sts",
            region_name=aws_region,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key
        )
        response = connection.assume_role(
            RoleArn=role_arn,
            RoleSessionName='AAP_AWS_Role_Session1'
        )

        credentials = response.get("Credentials", {})

        _aws_cred_cache[credential_key] = credentials

    credentials = _aws_cred_cache.get(credential_key, None)

    if identifier in credentials:
        return credentials[identifier]

    raise ValueError(f'Could not find a value for {identifier}.')

aws_role_credential_plugin = CredentialPlugin(
    'AWS Role Credential Plugin',
    # see: https://docs.ansible.com/ansible-tower/latest/html/userguide/credential_types.html
    # inputs will be used to create a new CredentialType() instance
    # see: https://github.com/ansible/awx-custom-credential-plugin-example
    inputs={
        'fields': [{
            'id': 'access_key',
            'label': 'AWS Access Key',
            'type': 'string',
        }, {
            'id': 'secret_key',
            'label': 'AWS Secret Key',
            'type': 'password',
        }, {
            'id': 'aws_region',
            'label': 'AWS Default Region',
            'type': 'string',
        }, {
            'id': 'role_arn',
            'label': 'AWS ARN Role Name',
            'type': 'string',
        }],
        'metadata': [{
            'id': 'identifier',
            'label': 'Identifier',
            'type': 'string',
            'help_text': 'The name of the key in the assumed AWS' +
                ' role to fetch [AccessKeyId | SecretAccessKey | SessionToken].'
        }],
        'required': ['access_key', 'secret_key', 'role_arn', 'aws_region'],
    },
    backend = aws_role_credential_backend
)
