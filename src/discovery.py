# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import boto3
from botocore.exceptions import ClientError
import json
import concurrent.futures
import time
import logging
from constants import SERVICE_SCAN_FUNCTIONS,GLOBAL_SERVICES,SERVICE_REGION_EXCLUSIONS
from session import get_aws_session,get_account_id,get_all_regions,assume_role

logger = logging.getLogger(__name__)

def scan_resource_explorer(session, regions):
    """Use AWS Resource Explorer to discover resources if enabled."""
    results = []

    for region in regions:
        try:
            # Check if Resource Explorer is enabled in this region
            client = session.client('resource-explorer-2', region_name=region)

            try:
                # Try to get the default view
                views = client.list_views()
                # logger.info(f"Views {views}")
                if not views.get('Views'):
                    continue
                
                view_arn = views['Views'][0]

                # logger.info(f"View arn {view_arn}")
                # Search for all resources
                paginator = client.get_paginator('search')
                page_iterator = paginator.paginate(
                    ViewArn=view_arn,
                    QueryString='*'
                )
                # logger.info(f"Page iterator {page_iterator}")
                resources = []
                for page in page_iterator:
                    resources.extend(page.get('Resources', []))

                results.append({
                    'service': 'resource-explorer',
                    'region': region,
                    'function': 'search',
                    'resources': resources,
                    'resource_count': len(resources)
                })

            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException':
                    # Resource Explorer view not found (not set up)
                    logger.info(f"Resource Explorer not configured in {region}")
                else:
                    logger.warning(f"Error using Resource Explorer in {region}: {e}")
        except Exception as e:
            # Skip regions where Resource Explorer is not available
            logger.debug(f"Resource Explorer not available in {region}: {e}")

    return results

def scan_aws_config(session, regions):
    """Use AWS Config to discover resources if enabled."""
    results = []

    for region in regions:
        try:
            client = session.client('config', region_name=region)

            try:
                # Check if AWS Config is recording
                status = client.describe_configuration_recorder_status()
                if not status.get('ConfigurationRecordersStatus') or not status['ConfigurationRecordersStatus'][0].get('recording'):
                    logger.info(f"AWS Config not recording in {region}")
                    return results

                # Get resource types
                resource_types = client.describe_configuration_recorders()
                if not resource_types.get('ConfigurationRecorders'):
                    logger.info(f"No configuration recorders in {region}")
                    return results

                # List all resources
                paginator = client.get_paginator('list_discovered_resources')

                resources = []
                for resource_type in ['AWS::EC2::Instance', 'AWS::S3::Bucket', 'AWS::lambda::Function',
                                     'AWS::RDS::DBInstance', 'AWS::DynamoDB::Table']:
                    try:
                        page_iterator = paginator.paginate(resourceType=resource_type)
                        for page in page_iterator:
                            resources.extend(page.get('resourceIdentifiers', []))
                    except Exception as e:
                        logger.debug(f"Error listing {resource_type} in {region}: {e}")

                results.append({
                    'service': 'config',
                    'region': region,
                    'function': 'list_discovered_resources',
                    'resources': resources,
                    'resource_count': len(resources)
                })

            except ClientError as e:
                # AWS Config not set up
                logger.info(f"AWS Config not available in {region}: {e}")
        except Exception as e:
            # Skip regions where Config is not available
            logger.debug(f"Config service not available in {region}: {e}")

    return results
    
def scan_service_in_region(service_name, region, session, scan_info):
    """Scan a specific AWS service in a specific region."""
    try:
        client = session.client(service_name, region_name=region)
        function_name = scan_info['function']
        result_key = scan_info['key']
        subkey = scan_info.get('subkey', None)
        params = scan_info.get('params', {})

        #bedrock custom models does not exist in regions eu-north-1 and ap-northeast-3 so skip that
        if function_name=="list_custom_models" and region in ['eu-north-1','ap-northeast-3']:
            return None

        function = getattr(client, function_name)
        response = function(**params)

         # Handle the case where response[result_key] is an array
        if result_key in response:
            if isinstance(response[result_key], list):
                if subkey:
                    # If subkey is specified, try to extract it from each item in the array
                    resources = [item.get(subkey, []) for item in response[result_key]]
                    # Flatten the list of lists
                    resources = [item for sublist in resources for item in sublist]
                else:
                    # If no subkey, use the array as is
                    resources = response[result_key]
            elif subkey:
                resources = response[result_key].get(subkey, [])
            else:
                resources = response[result_key]
        else:
            resources = []

        # For simple list results (like DynamoDB tables), convert to a more standardized format
        if isinstance(resources, list) and all(isinstance(item, str) for item in resources):
            resources = [{'Name': item, 'Arn': f"arn:aws:{service_name}:{region}:{get_account_id(session)}:{item}"}
                        for item in resources]

        return {
            'service': service_name,
            'region': region,
            'function': function_name,
            'resources': resources,
            'resource_count': len(resources)
        }
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']

        # Skip region not enabled errors
        if 'not enabled' in error_message.lower() or 'not authorized' in error_message.lower():
            return None

        # For other errors, log them but continue
        print(f"Error scanning {service_name}.{function_name} in {region}: {error_code} - {error_message}")
        return None
    except Exception as e:
        print(f"Unexpected error scanning {service_name}.{function_name} in {region}: {str(e)}")
        return None

def scan_resources(profile=None, regions=None, services=None, output_file=None, max_workers=10, credentials_file=None, target_account=None, role_name=None):
    """Scan AWS resources across specified regions and services."""
    start_time = time.time()
    # Create a session
    session = get_aws_session(profile,credentials_file=credentials_file)
    account_id = get_account_id(session)

    logger.info(f"Session: {session}")
    logger.info(f"Account ID: {account_id}")

    # If target account is specified, assume role in that account
    if target_account and role_name:
        try:
            session = assume_role(target_account, role_name, session)
            logger.info(f"Successfully assumed role in account {target_account}")
        except Exception as e:
            logger.error(f"Failed to assume role in account {target_account}: {e}")
            return None

    # # Get all regions if not specified
    if not regions:
        regions = get_all_regions(session)

    # # Filter services if specified
    if services:
        service_list = services
    else:
        service_list = list(SERVICE_SCAN_FUNCTIONS.keys())


    print(f"Scanning {len(service_list)} services across {len(regions)} regions for account {account_id}")
    # # Structure to hold all scan results
    all_results = {
        'account_id': account_id,
        'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
        'regions_scanned': regions,
        'services_scanned': service_list,
        'resources': [],
        'resource_counts': {}
    }


    # # # Try Resource Explorer first if available (fastest way to discover resources)
    # logger.info("Scanning using Resource Explorer...")
    # resource_explorer_results = scan_resource_explorer(session, regions)
    # if resource_explorer_results:
    #     all_results['resources'].extend(resource_explorer_results)
    #     # print(f"Found resources using Resource Explorer,{resource_explorer_results}")


    # # Try AWS Config next if available
    # logger.info("Scanning using AWS Config...")
    # config_results = scan_aws_config(session, regions)
    # if config_results:
    #     all_results['resources'].extend(config_results)
    #     # print(f"Found resources using AWS Config,{config_results}")


    logger.info("Scanning using service-specific APIs...")
    # Use the service-specific APIs for comprehensive discovery
    scan_tasks = []
    # # Prepare scan tasks
    for service_name in service_list:
        scan_functions = SERVICE_SCAN_FUNCTIONS.get(service_name, [])
        if not scan_functions:
            continue
        # For global services, only scan in us-east-1
        if service_name in GLOBAL_SERVICES:
            service_regions = ['us-east-1']
        elif service_name in SERVICE_REGION_EXCLUSIONS:
            # Remove excluded regions
            service_regions = [region for region in regions if region not in SERVICE_REGION_EXCLUSIONS[service_name]]
        else:
            service_regions = regions
        for region in service_regions:
            for scan_info in scan_functions:
                scan_tasks.append((service_name, region, scan_info))
    # # Execute scan tasks using thread pool
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_task = {
            executor.submit(scan_service_in_region, service_name, region, session, scan_info):
            (service_name, region, scan_info)
            for service_name, region, scan_info in scan_tasks
        }
        completed = 0
        for future in concurrent.futures.as_completed(future_to_task):
            service_name, region, scan_info = future_to_task[future]
            try:
                result = future.result()
                if result and result.get('resource_count', 0) > 0:
                    subservice = scan_info['name'] if 'name' in scan_info else scan_info['key']
                    result['subservice'] = subservice
                    all_results['resources'].append(result)
                    # Update resource counts
                    
                    # Initialize service in resource_counts if it doesn't exist
                    if service_name not in all_results['resource_counts']:
                        all_results['resource_counts'][service_name] = {
                            'total': 0,
                            'subservices': {}
                        }

                    # Update total count for the service
                    all_results['resource_counts'][service_name]['total'] += result['resource_count']

                    # Initialize subservice if it doesn't exist
                    if subservice not in all_results['resource_counts'][service_name]['subservices']:
                        all_results['resource_counts'][service_name]['subservices'][subservice] = {
                            'total': 0,
                            'regions': {}
                        }

                    # Update subservice total
                    all_results['resource_counts'][service_name]['subservices'][subservice]['total'] += result['resource_count']

                    # Initialize and update region count
                    if region not in all_results['resource_counts'][service_name]['subservices'][subservice]['regions']:
                        all_results['resource_counts'][service_name]['subservices'][subservice]['regions'][region] = 0
                    all_results['resource_counts'][service_name]['subservices'][subservice]['regions'][region] += result['resource_count']

            except Exception as e:
                print(f"Error processing result for {service_name} in {region}: {str(e)}")
            completed += 1
            if completed % 50 == 0:
                print(f"Completed {completed}/{len(scan_tasks)} scan tasks...")
    # Calculate summary
    total_resources = sum(service_data['total'] for service_data in all_results['resource_counts'].values())
    # # Print summary
    print(f"\nScan completed in {time.time() - start_time:.2f} seconds")
    print(f"Total resources discovered: {total_resources}")
    print("Resources by service:")
    for service, data in sorted(all_results['resource_counts'].items()):
        if data['total'] > 0:
            print(f"\n{service}: {data['total']}")
            for subservice, subdata in sorted(data['subservices'].items()):
                print(f"  └─ {subservice}: {subdata['total']}")
                for region, count in sorted(subdata['regions'].items()):
                    print(f"     └─ {region}: {count}")
    # # Write results to file
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(all_results, f, indent=2, default=str)
        print(f"Results written to {output_file}")
    return all_results
