import boto3
import os
import base64
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend

ssm = boto3.client('ssm')
sns = boto3.client('sns')

def get_all_certificate_parameters(parameter_path):
    """Recursively get all parameters under a given path."""
    paginator = ssm.get_paginator('get_parameters_by_path')
    cert_params = []
    for page in paginator.paginate(Path=parameter_path, Recursive=True, WithDecryption=True):
        cert_params.extend(page.get('Parameters', []))
    return cert_params

def get_expiry_from_pem(pem_data):
    """Parse a leaf x509 certificate and return its notValidAfter date."""
    cert = x509.load_pem_x509_certificate(pem_data.encode(), default_backend())
    return cert.not_valid_after

def lambda_handler(event, context):
    parameter_path = os.getenv('CERT_PARAMETER_PATH')  # e.g. '/certs'
    sns_topic_arn = os.getenv('SNS_TOPIC_ARN')
    threshold_days = int(os.getenv('EXPIRY_THRESHOLD_DAYS', '60'))

    now = datetime.now(timezone.utc)
    expiry_limit = now + timedelta(days=threshold_days)
    soon_expiring = []

    # 1. List all parameters under the path
    parameters = get_all_certificate_parameters(parameter_path)

    for param in parameters:
        name = param['Name']
        cert_pem = param['Value']
        try:
            expiry = get_expiry_from_pem(cert_pem)
            if now < expiry <= expiry_limit:
                soon_expiring.append(f"{name}: {expiry.isoformat()}")
        except Exception as e:
            print(f"Error parsing {name}: {e}")
            continue

    if soon_expiring:
        message = "The following certificates are expiring soon:\n" + "\n".join(soon_expiring)
        subject = f"ALERT: Certificates Expiring Within {threshold_days} Days"
        sns.publish(
            TopicArn=sns_topic_arn,
            Subject=subject,
            Message=message
        )
    # For AWS Config custom rule compliance (optional)
    return {
        'compliance_type': 'NON_COMPLIANT' if soon_expiring else 'COMPLIANT',
        'annotation': 'Expiring certificates detected' if soon_expiring else 'All certs valid'
    }
