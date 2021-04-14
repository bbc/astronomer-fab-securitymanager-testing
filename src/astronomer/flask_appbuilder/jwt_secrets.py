import boto3
import json
import logging
import os


def get_jwt_secret(jwt_secret_aws_path, jwt_secret_override):
    """Return the secret for decoding jwt's"""
    key = os.getenv('JWT_SECRET_KEY', jwt_secret_override)

    if not key:
        update_jwt_secret(jwt_secret_aws_path)
        raise RuntimeError('JWT_SECRET_AWS_PATH must be in app config'
                           'OR JWT_SECRET_KEY must be set to a value')

    return key


def update_jwt_secret(jwt_secret_aws_path, region='eu-west-1'):
    """Update environment variable holding the secret key for decoding jwt's

    Will look for JWT_SECRET_AWS_PATH in app config for the path to the secret in aws
    If not set then instead will fall back to getting static secret from app config (default behaviour)
    """
    if jwt_secret_aws_path:
        try:
            os.environ['JWT_SECRET_KEY'] = get_secret_from_aws(jwt_secret_aws_path, region)
        except Exception as e:
            logging.warning(f"Issue updating jwt secret from aws, will fallback to default: {e}")


def get_secret_from_aws(jwt_secret_aws_path, region='eu-west-1'):
    """Get secret value from aws
    Will look for JWT_SECRET_AWS_PATH in app config for the path to the secret

    Expects a secret of the form
    {
      "SecretString": "..."
    }
    """

    client = boto3.client(
        service_name='secretsmanager',
        region_name=region
    )

    secret = client.get_secret_value(SecretId=jwt_secret_aws_path)
    secret_dict = json.loads(secret['SecretString'])
    return secret_dict['SecretString']
