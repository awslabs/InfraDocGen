# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Policy Extractor Service - Extract resource-based policies
Pure Python implementation - no Bedrock required
"""

import json
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

def extract_resource_policies(infrastructure_data: Dict[str, Any]) -> Dict[str, Any]:
    try:
        # Extract basic metadata
        account_id = infrastructure_data.get('account_id', 'unknown')
        scan_time = infrastructure_data.get('scan_time', 'unknown')
        regions_scanned = infrastructure_data.get('regions_scanned', [])
        services_scanned = infrastructure_data.get('services_scanned', [])
        
        # Extract resources with policies
        resources_with_policies = []
        total_resources = 0
        resources_with_policies_count = 0
        policy_types_found = set()
        services_with_policies = set()
        
        # Process each resource group
        for resource_group in infrastructure_data.get('resources', []):
            service = resource_group.get('service')
            region = resource_group.get('region')
            subservice = resource_group.get('subservice')
            
            # Process each resource in the group
            for resource in resource_group.get('resources', []):
                total_resources += 1
                
                # Extract resource identifier
                resource_id = extract_resource_identifier(resource, service, subservice)
                resource_arn = extract_resource_arn(resource, service, region, account_id, subservice)
                
                # Check for resource-based policy
                resource_policy = None
                has_policy = False
                
                if isinstance(resource, dict):
                    # Check for resource_based_policy field
                    if 'resource_based_policy' in resource and resource['resource_based_policy'] is not None:
                        resource_policy = resource['resource_based_policy']
                        has_policy = True
                        resources_with_policies_count += 1
                        services_with_policies.add(service)
                        policy_types_found.add('resource_based')
                    
                    # Check for other policy fields based on service
                    elif service == 'ec2' and 'instance_profile_policies' in resource and resource['instance_profile_policies'] is not None:
                        resource_policy = resource['instance_profile_policies']
                        has_policy = True
                        resources_with_policies_count += 1
                        services_with_policies.add(service)
                        policy_types_found.add('instance_profile')
                
                # Only include resources that have policies - be very selective
                if has_policy:
                    resource_entry = {
                        'resource_arn': resource_arn,
                        'service': service,
                        'region': region,
                        'resource_policy': resource_policy
                    }
                    
                    resources_with_policies.append(resource_entry)
        

        
        # Create policy summary
        policy_summary = {
            'total_resources': total_resources,
            'resources_with_policies': resources_with_policies_count,
            'resources_with_policies_count': len(resources_with_policies),
            'policy_types_found': list(policy_types_found),
            'services_with_policies': list(services_with_policies),
            'policy_counts': {
                'resource_based': len([r for r in resources_with_policies if r.get('resource_policy') and r.get('has_resource_policy')]),
                'instance_profiles': len([r for r in resources_with_policies if r.get('service') == 'ec2' and r.get('resource_policy')]),
                'access_control': len([r for r in resources_with_policies if r.get('resource_policy')])
            }
        }
        
        # Build the minimal response - only essentials for resource mapping
        clean_response = {
            'account_id': account_id,
            'resources_with_policies': resources_with_policies,
        }
        
        logger.info(f"Policy extraction complete: {len(resources_with_policies)} resources with policies from {total_resources} total resources")
        
        return clean_response
        
    except Exception as e:
        logger.error(f"Error extracting resource policies: {str(e)}")
        return {
            'error': 'Policy extraction failed',
            'message': str(e),
            'account_id': infrastructure_data.get('account_id', 'unknown'),
            'scan_time': infrastructure_data.get('scan_time', 'unknown')
        }



def extract_resource_identifier(resource: Any, service: str, subservice: str) -> str:
    """Extract the primary identifier for a resource"""
    if isinstance(resource, str):
        return resource
    
    if isinstance(resource, dict):
        # Try common identifier fields
        identifier_fields = [
            'Arn', 'ARN', 'arn',
            'Id', 'ID', 'id',
            'Name', 'name',
            'FunctionName', 'functionName',
            'TopicArn', 'topicArn',
            'QueueUrl', 'queueUrl',
            'BucketName', 'bucketName',
            'InstanceId', 'instanceId',
            'VolumeId', 'volumeId',
            'KeyId', 'keyId',
            'FileSystemId', 'fileSystemId',
            'stateMachineArn'
        ]
        
        for field in identifier_fields:
            if field in resource and resource[field]:
                return str(resource[field])
        
        # Fallback to first string value
        for key, value in resource.items():
            if isinstance(value, str) and value:
                return value
    
    return f"unknown_{service}_{subservice}_resource"

def extract_resource_arn(resource: Any, service: str, region: str, account_id: str, subservice: str = None) -> Optional[str]:
    """Extract or construct ARN for a resource using comprehensive mapping"""
    from constants import ARN_CONSTRUCTION_MAP
    
    if isinstance(resource, dict):
        # Check for existing ARN fields first
        arn_fields = ['Arn', 'ARN', 'arn', 'TopicArn', 'FunctionArn', 'stateMachineArn', 
                     'ResourceARN', 'LoadBalancerArn', 'TargetGroupArn', 'CertificateArn',
                     'AcceleratorArn', 'EntityRecognizerArn', 'TaskArn', 'LocationArn',
                     'CostCategoryArn', 'modelArn', 'jobArn', 'provisionedModelArn']
        
        for field in arn_fields:
            if field in resource and resource[field]:
                return resource[field]
        
        # Use ARN construction mapping
        if service in ARN_CONSTRUCTION_MAP and subservice in ARN_CONSTRUCTION_MAP[service]:
            arn_config = ARN_CONSTRUCTION_MAP[service][subservice]
            pattern = arn_config['pattern']
            id_field = arn_config['id_field']
            
            # Get the resource ID
            resource_id = None
            if id_field in resource and resource[id_field]:
                resource_id = resource[id_field]
                
                # Handle special cases
                if arn_config.get('extract_name') and service == 'sqs':
                    # Extract queue name from URL
                    resource_id = resource_id.split('/')[-1] if '/' in resource_id else resource_id
                elif arn_config.get('extract_id'):
                    # Extract ID from existing ARN
                    if resource_id.startswith('arn:aws:'):
                        resource_id = resource_id.split('/')[-1].split(':')[-1]
                
                # Handle special patterns
                if pattern == '{resource_id}':
                    # Resource ID is already the ARN
                    return resource_id
                elif 'route53' in pattern and resource_id.startswith('/hostedzone/'):
                    # Route53 hosted zone ID cleanup
                    resource_id = resource_id.replace('/hostedzone/', '')
                
                # Construct ARN using pattern
                if resource_id:
                    arn = pattern.format(
                        region=region,
                        account_id=account_id,
                        resource_id=resource_id
                    )
                    return arn
        
        # Fallback for unmapped services - try common patterns
        resource_id = extract_resource_identifier(resource, service, subservice)
        if resource_id and resource_id != f"unknown_{service}_{subservice}_resource":
            # Generic ARN construction
            if service == 'dynamodb' and isinstance(resource, str):
                return f"arn:aws:dynamodb:{region}:{account_id}:table/{resource}"
            elif service == 'kinesis' and isinstance(resource, str):
                return f"arn:aws:kinesis:{region}:{account_id}:stream/{resource}"
    
    return None

