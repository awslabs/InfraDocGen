# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import boto3

def get_all_iam_entities(session):
    iam = session.client('iam')
    users = iam.list_users().get('Users', [])
    roles = iam.list_roles().get('Roles', [])
    groups = iam.list_groups().get('Groups', [])
    return users, roles, groups

def get_policies_for_user(iam, user_name):
    attached = iam.list_attached_user_policies(UserName=user_name).get("AttachedPolicies", [])
    inline_names = iam.list_user_policies(UserName=user_name).get("PolicyNames", [])
    inline = [iam.get_user_policy(UserName=user_name, PolicyName=name)["PolicyDocument"] for name in inline_names]
    return attached, inline

def get_policies_for_role(iam, role_name):
    attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
    inline_names = iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])
    inline = [iam.get_role_policy(RoleName=role_name, PolicyName=name)["PolicyDocument"] for name in inline_names]
    return attached, inline

def get_policies_for_group(iam, group_name):
    attached = iam.list_attached_group_policies(GroupName=group_name).get("AttachedPolicies", [])
    inline_names = iam.list_group_policies(GroupName=group_name).get("PolicyNames", [])
    inline = [iam.get_group_policy(GroupName=group_name, PolicyName=name)["PolicyDocument"] for name in inline_names]
    return attached, inline

def get_resource_based_policy(client, service, resource_name):
    try:
        if service == 's3':
            return client.get_bucket_policy(Bucket=resource_name).get("Policy")
        elif service == 'lambda':
            return client.get_policy(FunctionName=resource_name).get("Policy")
        elif service == 'sns':
            return client.get_topic_attributes(TopicArn=resource_name).get("Attributes", {}).get("Policy")
        elif service == 'sqs':
            return client.get_queue_attributes(QueueUrl=resource_name, AttributeNames=['Policy']).get("Attributes", {}).get("Policy")
    except Exception:
        return None
