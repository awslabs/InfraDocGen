# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import boto3
from botocore.exceptions import ClientError
import logging

logger = logging.getLogger(__name__)

def get_aws_session(aws_access_key_id=None, aws_secret_access_key=None, aws_session_token=None, region='us-east-1'):
    if aws_access_key_id and aws_secret_access_key:
        logger.info("Using provided credentials")
        return boto3.Session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
            region_name=region
        )
    logger.info("Using default credentials (e.g., environment or shared config)")
    return boto3.Session(region_name=region)

def get_account_id(session):
    try:
        return session.client('sts').get_caller_identity()['Account']
    except Exception as e:
        logger.error(f"Unable to get account ID: {e}")
        return "unknown"

def assume_role(account_id, role_name, session):
    sts = session.client('sts')
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    try:
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="CrossAccountSession"
        )
        creds = response['Credentials']
        return boto3.Session(
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken']
        )
    except Exception as e:
        logger.warning(f"Error assuming role {role_arn}: {e}")
        raise

def get_all_regions(session):
    try:
        ec2 = session.client('ec2', region_name='us-east-1')
        regions = ec2.describe_regions(AllRegions=True)['Regions']
        return [r['RegionName'] for r in regions if r['OptInStatus'] in ('opt-in-not-required', 'opted-in')]
    except Exception as e:
        logger.error(f"Unable to list regions: {e}")
        return ['us-east-1']
