# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import concurrent.futures
import time
import logging
from constants import SERVICE_SCAN_FUNCTIONS, GLOBAL_SERVICES, SERVICE_REGION_EXCLUSIONS, RESOURCE_ESSENTIAL_FIELDS
from session import get_aws_session, get_account_id, get_all_regions, assume_role
from services.dependency_mapper import build_dependency_graph

logger = logging.getLogger(__name__)

def filter_resource_fields(resource, service_name, subservice_name):
    """Filter resource to include only essential fields"""
    # Get essential fields from constants
    service_fields = RESOURCE_ESSENTIAL_FIELDS.get(service_name, {})
    essential_fields = service_fields.get(subservice_name)
    
    if not essential_fields:
        return resource
    
    # Handle string resources (like queue URLs, topic ARNs)
    if isinstance(resource, str):
        return resource
    
    # Handle dictionary resources
    if isinstance(resource, dict):
        filtered_resource = {}
        for field in essential_fields:
            if field in resource:
                filtered_resource[field] = resource[field]
        
        # Always preserve some basic fields if they exist
        basic_fields = ['Name', 'Arn', 'Id']
        for field in basic_fields:
            if field in resource and field not in filtered_resource:
                filtered_resource[field] = resource[field]
        
        return filtered_resource
    
    return resource

def scan_service_in_region(service_name, region, session, scan_info):
    try:
        client = session.client(service_name, region_name=region)
        function_name = scan_info['function']
        result_key = scan_info['key']
        subkey = scan_info.get('subkey', None)
        params = scan_info.get('params', {})

        if function_name == "list_custom_models" and region in ['eu-north-1', 'ap-northeast-3']:
            return None

        function = getattr(client, function_name)
        response = function(**params)

        if result_key in response:
            if isinstance(response[result_key], list):
                if subkey:
                    resources = [item.get(subkey, []) for item in response[result_key]]
                    resources = [item for sublist in resources for item in sublist]
                else:
                    resources = response[result_key]
            elif subkey:
                resources = response[result_key].get(subkey, [])
            else:
                resources = response[result_key]
        else:
            resources = []

        if isinstance(resources, list) and all(isinstance(item, str) for item in resources):
            resources = [{'Name': item, 'Arn': f"arn:aws:{service_name}:{region}:{get_account_id(session)}:{item}"} for item in resources]

        # Apply field filtering
        subservice = scan_info['name'] if 'name' in scan_info else scan_info['key']
        
        if isinstance(resources, list):
            filtered_resources = []
            for resource in resources:
                filtered_resource = filter_resource_fields(resource, service_name, subservice)
                filtered_resources.append(filtered_resource)
            resources = filtered_resources

        return {
            'service': service_name,
            'region': region,
            'function': function_name,
            'resources': resources,
            'resource_count': len(resources)
        }

    except Exception as e:
        logger.warning(f"Error scanning {service_name}.{function_name} in {region}: {e}")
        return None

def scan_resources(aws_access_key_id=None, aws_secret_access_key=None, aws_session_token=None, target_account=None, role_name=None):
    start_time = time.time()

    try:
        session = get_aws_session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token
        )
        account_id = get_account_id(session)
    except Exception as e:
        logger.error(f"Failed to establish AWS session: {str(e)}")
        return {
            'error': 'AWS credentials not configured or invalid',
            'message': 'Please configure valid AWS credentials to scan resources',
            'account_id': 'unknown',
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'regions_scanned': [],
            'services_scanned': [],
            'resources': [],
            'resource_counts': {},
            'policy_summary': {
                'total_resources': 0,
                'resources_with_policies': 0,
                'policy_types_found': [],
                'services_with_policies': [],
                'policy_counts': {
                    'resource_based': 0,
                    'identity_based': 0,
                    'access_control': 0
                }
            }
        }

    if target_account and role_name:
        try:
            session = assume_role(target_account, role_name, session)
            logger.info(f"Successfully assumed role in account {target_account}")
        except Exception as e:
            logger.error(f"Failed to assume role in account {target_account}: {e}")
            return {"error": str(e)}

    try:
        regions = get_all_regions(session)
    except Exception as e:
        logger.warning(f"Failed to get regions, using default: {str(e)}")
        regions = ['us-east-1']
    
    service_list = list(SERVICE_SCAN_FUNCTIONS.keys())

    all_results = {
        'account_id': account_id,
        'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
        'regions_scanned': regions,
        'services_scanned': service_list,
        'resources': [],
        'resource_counts': {}
    }

    logger.info("Scanning using service-specific APIs...")
    scan_tasks = []

    for service_name in service_list:
        scan_functions = SERVICE_SCAN_FUNCTIONS.get(service_name, [])
        if not scan_functions:
            continue

        if service_name in GLOBAL_SERVICES:
            service_regions = ['us-east-1']
        elif service_name in SERVICE_REGION_EXCLUSIONS:
            service_regions = [r for r in regions if r not in SERVICE_REGION_EXCLUSIONS[service_name]]
        else:
            service_regions = regions

        for region in service_regions:
            for scan_info in scan_functions:
                scan_tasks.append((service_name, region, scan_info))

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_task = {
            executor.submit(scan_service_in_region, service_name, region, session, scan_info):
            (service_name, region, scan_info)
            for service_name, region, scan_info in scan_tasks
        }

        for future in concurrent.futures.as_completed(future_to_task):
            service_name, region, scan_info = future_to_task[future]
            try:
                result = future.result()
                if result and result.get('resource_count', 0) > 0:
                    subservice = scan_info['name'] if 'name' in scan_info else scan_info['key']
                    result['subservice'] = subservice
                    all_results['resources'].append(result)

                    service_counts = all_results['resource_counts'].setdefault(service_name, {'total': 0, 'subservices': {}})
                    service_counts['total'] += result['resource_count']
                    sub_counts = service_counts['subservices'].setdefault(subservice, {'total': 0, 'regions': {}})
                    sub_counts['total'] += result['resource_count']
                    sub_counts['regions'][region] = sub_counts['regions'].get(region, 0) + result['resource_count']

            except Exception as e:
                logger.error(f"Error processing result for {service_name} in {region}: {str(e)}")

    # Build dependency graph and attach policies directly to resources
    resource_access_graph = build_dependency_graph(session, all_results['resources'])
    all_results["resource_access_graph"] = resource_access_graph

    # Add resource-based policies to specific services
    try:
        logger.info("Adding resource-based policies for Lambda, SQS, SNS, S3, EC2, and other services...")
        add_resource_based_policies(session, all_results['resources'])
        logger.info("Resource-based policies added successfully")
    except Exception as e:
        logger.error(f"Error adding resource-based policies: {str(e)}")

    total_time = time.time() - start_time
    logger.info(f"Scan complete in {total_time:.2f} seconds")
    return all_results

def add_resource_based_policies(session, discovered_resources):
    """
    Add resource-based policies to Lambda, SQS, SNS, S3, EC2, Glue, EventBridge, Step Functions, EFS, CloudWatch, KMS, API Gateway
    """
    for resource_group in discovered_resources:
        service = resource_group.get('service')
        region = resource_group.get('region')
        
        if service == 'lambda':
            add_lambda_resource_policies(session, resource_group, region)
        elif service == 'sqs':
            add_sqs_resource_policies(session, resource_group, region)
        elif service == 'sns':
            add_sns_resource_policies(session, resource_group, region)
        elif service == 's3':
            add_s3_resource_policies(session, resource_group, region)
        elif service == 'ec2':
            add_ec2_instance_profile_policies(session, resource_group, region)
        elif service == 'glue':
            add_glue_resource_policies(session, resource_group, region)
        elif service == 'events':  # EventBridge
            add_eventbridge_resource_policies(session, resource_group, region)
        elif service == 'stepfunctions':
            add_stepfunctions_resource_policies(session, resource_group, region)
        elif service == 'efs':
            add_efs_resource_policies(session, resource_group, region)
        elif service == 'cloudwatch':
            add_cloudwatch_resource_policies(session, resource_group, region)
        elif service == 'kms':
            add_kms_resource_policies(session, resource_group, region)
        elif service == 'apigateway':
            add_apigateway_resource_policies(session, resource_group, region)

def add_lambda_resource_policies(session, resource_group, region):
    """Add resource-based policies to Lambda functions"""
    from botocore.exceptions import ClientError
    lambda_client = session.client('lambda', region_name=region)
    
    for resource in resource_group.get('resources', []):
        if isinstance(resource, dict):
            function_name = resource.get('FunctionName')
            if function_name:
                try:
                    response = lambda_client.get_policy(FunctionName=function_name)
                    policy_json = response.get('Policy')
                    if policy_json:
                        import json
                        policy_document = json.loads(policy_json)
                        resource['resource_based_policy'] = policy_document
                    else:
                        resource['resource_based_policy'] = None
                except ClientError as e:
                    error_code = e.response['Error']['Code']
                    if error_code == 'ResourceNotFoundException':
                        resource['resource_based_policy'] = None
                    else:
                        logger.debug(f"Error getting Lambda policy for {function_name}: {str(e)}")
                        resource['resource_based_policy'] = None
                except Exception as e:
                    logger.debug(f"Error getting Lambda policy for {function_name}: {str(e)}")
                    resource['resource_based_policy'] = None

def add_sqs_resource_policies(session, resource_group, region):
    """Add resource-based policies to SQS queues"""
    sqs_client = session.client('sqs', region_name=region)
    
    for resource in resource_group.get('resources', []):
        if isinstance(resource, dict):
            queue_url = resource.get('Name')  # SQS resources store URL in Name field
            if queue_url:
                try:
                    response = sqs_client.get_queue_attributes(
                        QueueUrl=queue_url,
                        AttributeNames=['Policy']
                    )
                    policy_str = response.get('Attributes', {}).get('Policy')
                    if policy_str:
                        import json
                        policy_document = json.loads(policy_str)
                        resource['resource_based_policy'] = policy_document
                    else:
                        resource['resource_based_policy'] = None
                except Exception as e:
                    logger.debug(f"Error getting SQS policy for {queue_url}: {str(e)}")
                    resource['resource_based_policy'] = None

def add_sns_resource_policies(session, resource_group, region):
    """Add resource-based policies to SNS topics"""
    sns_client = session.client('sns', region_name=region)
    
    for resource in resource_group.get('resources', []):
        if isinstance(resource, dict):
            topic_arn = resource.get('TopicArn')
            if topic_arn:
                try:
                    response = sns_client.get_topic_attributes(TopicArn=topic_arn)
                    policy_str = response.get('Attributes', {}).get('Policy')
                    if policy_str:
                        import json
                        policy_document = json.loads(policy_str)
                        resource['resource_based_policy'] = policy_document
                    else:
                        resource['resource_based_policy'] = None
                except Exception as e:
                    logger.debug(f"Error getting SNS policy for {topic_arn}: {str(e)}")
                    resource['resource_based_policy'] = None

def add_s3_resource_policies(session, resource_group, region):
    """Add bucket policies to S3 buckets"""
    from botocore.exceptions import ClientError
    s3_client = session.client('s3')
    
    for resource in resource_group.get('resources', []):
        if isinstance(resource, dict):
            bucket_name = resource.get('Name')
            if bucket_name:
                try:
                    response = s3_client.get_bucket_policy(Bucket=bucket_name)
                    policy_str = response.get('Policy')
                    if policy_str:
                        import json
                        policy_document = json.loads(policy_str)
                        resource['resource_based_policy'] = policy_document
                    else:
                        resource['resource_based_policy'] = None
                except ClientError as e:
                    # Handle the case where no bucket policy exists
                    error_code = e.response['Error']['Code']
                    if error_code == 'NoSuchBucketPolicy':
                        resource['resource_based_policy'] = None
                    else:
                        logger.debug(f"Error getting S3 bucket policy for {bucket_name}: {str(e)}")
                        resource['resource_based_policy'] = None
                except Exception as e:
                    logger.debug(f"Error getting S3 bucket policy for {bucket_name}: {str(e)}")
                    resource['resource_based_policy'] = None

def add_glue_resource_policies(session, resource_group, region):
    """Add resource-based policies to Glue resources"""
    from botocore.exceptions import ClientError
    glue_client = session.client('glue', region_name=region)
    
    for resource in resource_group.get('resources', []):
        if isinstance(resource, dict):
            # Glue databases have resource policies
            database_name = resource.get('Name')
            if database_name:
                try:
                    response = glue_client.get_resource_policy()
                    policy_str = response.get('PolicyInJson')
                    if policy_str:
                        import json
                        policy_document = json.loads(policy_str)
                        resource['resource_based_policy'] = policy_document
                    else:
                        resource['resource_based_policy'] = None
                except ClientError as e:
                    error_code = e.response['Error']['Code']
                    if error_code == 'EntityNotFoundException':
                        resource['resource_based_policy'] = None
                    else:
                        logger.debug(f"Error getting Glue policy for {database_name}: {str(e)}")
                        resource['resource_based_policy'] = None
                except Exception as e:
                    logger.debug(f"Error getting Glue policy for {database_name}: {str(e)}")
                    resource['resource_based_policy'] = None

def add_eventbridge_resource_policies(session, resource_group, region):
    """Add resource-based policies to EventBridge rules"""
    events_client = session.client('events', region_name=region)
    
    for resource in resource_group.get('resources', []):
        if isinstance(resource, dict):
            rule_name = resource.get('Name')
            if rule_name:
                try:
                    response = events_client.describe_rule(Name=rule_name)
                    # EventBridge rules don't have resource-based policies like other services
                    # They use IAM roles for permissions, so we'll set this to None
                    resource['resource_based_policy'] = None
                except Exception as e:
                    logger.debug(f"Error checking EventBridge rule {rule_name}: {str(e)}")
                    resource['resource_based_policy'] = None

def add_stepfunctions_resource_policies(session, resource_group, region):
    """Add resource-based policies to Step Functions state machines"""
    stepfunctions_client = session.client('stepfunctions', region_name=region)
    
    for resource in resource_group.get('resources', []):
        if isinstance(resource, dict):
            state_machine_arn = resource.get('stateMachineArn')
            if state_machine_arn:
                try:
                    # Step Functions don't have resource-based policies
                    # They use IAM roles for execution, so we'll set this to None
                    resource['resource_based_policy'] = None
                except Exception as e:
                    logger.debug(f"Error checking Step Functions state machine {state_machine_arn}: {str(e)}")
                    resource['resource_based_policy'] = None

def add_efs_resource_policies(session, resource_group, region):
    """Add resource-based policies to EFS file systems"""
    from botocore.exceptions import ClientError
    efs_client = session.client('efs', region_name=region)
    
    for resource in resource_group.get('resources', []):
        if isinstance(resource, dict):
            file_system_id = resource.get('FileSystemId')
            if file_system_id:
                try:
                    response = efs_client.describe_file_system_policy(FileSystemId=file_system_id)
                    policy_str = response.get('Policy')
                    if policy_str:
                        import json
                        policy_document = json.loads(policy_str)
                        resource['resource_based_policy'] = policy_document
                    else:
                        resource['resource_based_policy'] = None
                except ClientError as e:
                    error_code = e.response['Error']['Code']
                    if error_code == 'PolicyNotFound':
                        resource['resource_based_policy'] = None
                    else:
                        logger.debug(f"Error getting EFS policy for {file_system_id}: {str(e)}")
                        resource['resource_based_policy'] = None
                except Exception as e:
                    logger.debug(f"Error getting EFS policy for {file_system_id}: {str(e)}")
                    resource['resource_based_policy'] = None

def add_cloudwatch_resource_policies(session, resource_group, region):
    """Add resource-based policies to CloudWatch resources"""
    # CloudWatch alarms don't have resource-based policies
    # They use IAM for permissions, so we'll set this to None for all resources
    for resource in resource_group.get('resources', []):
        if isinstance(resource, dict):
            resource['resource_based_policy'] = None

def add_kms_resource_policies(session, resource_group, region):
    """Add key policies to KMS keys"""
    kms_client = session.client('kms', region_name=region)
    
    for resource in resource_group.get('resources', []):
        if isinstance(resource, dict):
            key_id = resource.get('KeyId')
            if key_id:
                try:
                    response = kms_client.get_key_policy(
                        KeyId=key_id,
                        PolicyName='default'
                    )
                    policy_str = response.get('Policy')
                    if policy_str:
                        import json
                        policy_document = json.loads(policy_str)
                        resource['resource_based_policy'] = policy_document
                    else:
                        resource['resource_based_policy'] = None
                except Exception as e:
                    logger.debug(f"Error getting KMS key policy for {key_id}: {str(e)}")
                    resource['resource_based_policy'] = None

def add_ec2_instance_profile_policies(session, resource_group, region):
    """Add IAM instance profile policies to EC2 instances (what the instance can access)"""
    from botocore.exceptions import ClientError
    ec2_client = session.client('ec2', region_name=region)
    iam_client = session.client('iam')
    
    for resource in resource_group.get('resources', []):
        if isinstance(resource, dict):
            instance_id = resource.get('InstanceId')
            if instance_id:
                try:
                    # Get instance details to find IAM instance profile
                    response = ec2_client.describe_instances(InstanceIds=[instance_id])
                    
                    instance_profile_arn = None
                    for reservation in response['Reservations']:
                        for instance in reservation['Instances']:
                            if instance['InstanceId'] == instance_id:
                                iam_instance_profile = instance.get('IamInstanceProfile')
                                if iam_instance_profile:
                                    instance_profile_arn = iam_instance_profile.get('Arn')
                                break
                    
                    if instance_profile_arn:
                        # Extract instance profile name from ARN
                        instance_profile_name = instance_profile_arn.split('/')[-1]
                        
                        # Get the instance profile and its roles
                        profile_response = iam_client.get_instance_profile(
                            InstanceProfileName=instance_profile_name
                        )
                        
                        roles = profile_response['InstanceProfile']['Roles']
                        instance_policies = []
                        
                        for role in roles:
                            role_name = role['RoleName']
                            
                            # Get attached managed policies
                            attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
                            for policy in attached_policies['AttachedPolicies']:
                                policy_arn = policy['PolicyArn']
                                policy_name = policy['PolicyName']
                                
                                # Get policy document to see what resources it can access
                                try:
                                    policy_response = iam_client.get_policy(PolicyArn=policy_arn)
                                    version_id = policy_response['Policy']['DefaultVersionId']
                                    
                                    policy_version = iam_client.get_policy_version(
                                        PolicyArn=policy_arn,
                                        VersionId=version_id
                                    )
                                    
                                    policy_document = policy_version['PolicyVersion']['Document']
                                    accessible_resources = extract_accessible_resources_from_policy(policy_document)
                                    
                                    instance_policies.append({
                                        'policy_name': policy_name,
                                        'policy_arn': policy_arn,
                                        'policy_type': 'managed',
                                        'attached_to_role': role_name,
                                        'accessible_resources': accessible_resources
                                    })
                                    
                                except Exception as e:
                                    logger.debug(f"Error getting policy details for {policy_arn}: {str(e)}")
                            
                            # Get inline policies
                            inline_policies = iam_client.list_role_policies(RoleName=role_name)
                            for policy_name in inline_policies['PolicyNames']:
                                try:
                                    policy_response = iam_client.get_role_policy(
                                        RoleName=role_name,
                                        PolicyName=policy_name
                                    )
                                    
                                    policy_document = policy_response['PolicyDocument']
                                    accessible_resources = extract_accessible_resources_from_policy(policy_document)
                                    
                                    instance_policies.append({
                                        'policy_name': policy_name,
                                        'policy_arn': None,  # Inline policies don't have ARNs
                                        'policy_type': 'inline',
                                        'attached_to_role': role_name,
                                        'accessible_resources': accessible_resources
                                    })
                                    
                                except Exception as e:
                                    logger.debug(f"Error getting inline policy {policy_name}: {str(e)}")
                        
                        resource['instance_profile_policies'] = {
                            'instance_profile_arn': instance_profile_arn,
                            'instance_profile_name': instance_profile_name,
                            'roles': [role['RoleName'] for role in roles],
                            'policies': instance_policies
                        }
                    else:
                        # No instance profile attached
                        resource['instance_profile_policies'] = None
                        
                except ClientError as e:
                    logger.debug(f"Error getting instance profile for EC2 instance {instance_id}: {str(e)}")
                    resource['instance_profile_policies'] = None
                except Exception as e:
                    logger.debug(f"Error processing EC2 instance {instance_id}: {str(e)}")
                    resource['instance_profile_policies'] = None

def extract_accessible_resources_from_policy(policy_document):
    """
    Extract resource ARNs/patterns that this policy can access
    Returns only unique, essential resource patterns (limited for size)
    """
    resources = set()
    statements = policy_document.get('Statement', [])
    
    if not isinstance(statements, list):
        statements = [statements]
    
    for stmt in statements:
        # Only look at Allow statements
        if stmt.get('Effect') != 'Allow':
            continue
            
        stmt_resources = stmt.get('Resource', [])
        if isinstance(stmt_resources, str):
            stmt_resources = [stmt_resources]
        
        for resource in stmt_resources:
            if isinstance(resource, str):
                resources.add(resource)
                
                # Limit to prevent size explosion
                if len(resources) >= 10:
                    break
    
    # Convert to list and limit size
    resource_list = list(resources)
    return resource_list[:10] if len(resource_list) > 10 else resource_list

def add_apigateway_resource_policies(session, resource_group, region):
    """Add resource-based policies to API Gateway REST APIs"""
    apigateway_client = session.client('apigateway', region_name=region)
    
    for resource in resource_group.get('resources', []):
        if isinstance(resource, dict):
            api_id = resource.get('id')
            if api_id:
                try:
                    response = apigateway_client.get_rest_api(restApiId=api_id)
                    policy_str = response.get('policy')
                    if policy_str:
                        import json
                        policy_document = json.loads(policy_str)
                        resource['resource_based_policy'] = policy_document
                    else:
                        resource['resource_based_policy'] = None
                except Exception as e:
                    logger.debug(f"Error getting API Gateway policy for {api_id}: {str(e)}")
                    resource['resource_based_policy'] = None
