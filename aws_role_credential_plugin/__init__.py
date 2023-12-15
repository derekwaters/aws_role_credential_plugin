import collections
import boto3
import os

try:
    from botocore.exceptions import ClientError
    from botocore.exceptions import ParamValidationError
except ImportError:
    pass  # caught by AnsibleAWSModule

_aws_cred_cache = {}

CredentialPlugin = collections.namedtuple('CredentialPlugin', ['name', 'inputs', 'backend'])


def aws_role_credential_backend(**kwargs):
    access_key = kwargs.get('access_key')
    secret_key = kwargs.get('secret_key')
    role_arn = kwargs.get('role_arn')
    aws_region = kwargs.get('aws_region')
    identifier = kwargs.get('identifier')

    credentials = _aws_cred_cache.get(role_arn, None)
    # TODO: If credentials do exist, have they expired?

    if credentials == None:

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

        #new_connection = boto3.Session(aws_access_key_id=credentials['AccessKeyId'],
        #              aws_secret_access_key=credentials['SecretAccessKey'],
        #              aws_session_token=credentials['SessionToken'])

        _aws_cred_cache[role_arn] = credentials

    credentials = _aws_cred_cache.get(role_arn, None)

    if identifier in credentials:
        return credentials[identifier]

    raise ValueError(f'Could not find a value for {identifier}.')

aws_role_credential_plugin = CredentialPlugin(
    'AWS Role Credential Plugin',
    # see: https://docs.ansible.com/ansible-tower/latest/html/userguide/credential_types.html
    # inputs will be used to create a new CredentialType() instance
    #
    # inputs.fields represents fields the user will specify *when they create*
    # a credential of this type; they generally represent fields
    # used for authentication (URL to the credential management system, any
    # fields necessary for authentication, such as an OAuth2.0 token, or
    # a username and password). They're the types of values you set up _once_
    # in AWX
    #
    # inputs.metadata represents values the user will specify *every time
    # they link two credentials together*
    # this is generally _pathing_ information about _where_ in the external
    # management system you can find the value you care about i.e.,
    #
    # "I would like Machine Credential A to retrieve its username using
    # Credential-O-Matic B at identifier=some_key"
    inputs={
        'fields': [{
            'id': 'access_key',
            'label': 'AWS Access Key',
            'type': 'string',
        }, {
            'id': 'secret_key',
            'label': 'AWS Secret Key',
            'type': 'string',
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
            'help_text': 'The name of the key in My Credential System to fetch.'
        }],
        'required': ['access_key', 'secret_key', 'role_arn', 'aws_region'],
    },

    # backend is a callable function which will be passed all of the values
    # defined in `inputs`; this function is responsible for taking the arguments,
    # interacting with the third party credential management system in question
    # using Python code, and returning the value from the third party
    # credential management system
    backend = aws_role_credential_backend
)