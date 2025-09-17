# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# List of regions to scan
# You can modify this list or use the describe_regions API to get all available regions
DEFAULT_REGIONS = [
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'eu-west-1', 'eu-west-2', 'eu-west-3',
    'eu-central-1', 'eu-north-1',
    'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
    'ap-southeast-1', 'ap-southeast-2',
    'ap-south-1',
    'sa-east-1',
    'ca-central-1'
]

# Global services that don't need region iteration
GLOBAL_SERVICES = ['s3', 'iam', 'route53', 'cloudfront', 'organizations', 'wafglobal', 'globalaccelerator', 'shield']

SERVICE_REGION_EXCLUSIONS={
    'bedrock':['us-west-1'],
    'bedrock-agent':['us-west-1'],
    'lightsail':['sa-east-1','ap-northeast-3','us-west-1'],
    'comprehend':['eu-west-3','sa-east-1','us-west-1','eu-north-1','ap-northeast-3'],
    'iot':['ap-northeast-3'],
    'greengrass':['ap-northeast-3','eu-north-1','eu-west-3','sa-east-1','us-west-1','ca-central-1'],
    'codeartifact':['sa-east-1','ap-northeast-2','us-west-1','ap-northeast-3','ca-central-1'],
    'medialive':['us-west-1'],
    'workmail':['ap-northeast-1','ap-southeast-1','ap-northeast-3','eu-north-1','sa-east-1','eu-central-1','ap-northeast-2','ca-central-1','eu-west-2','eu-west-3','ap-south-1','ap-southeast-2','us-west-1','us-east-2'],
    'workspaces':['eu-north-1','us-west-1','ap-northeast-3','us-east-2']
}
# Services to scan and their corresponding list functions
SERVICE_SCAN_FUNCTIONS = {
    'ec2': [
        {'function': 'describe_instances', 'key': 'Reservations', 'subkey': 'Instances', 'name':'Instances'},
        {'function': 'describe_security_groups', 'key': 'SecurityGroups', 'name':'SecurityGroups'},
        {'function': 'describe_vpcs', 'key': 'Vpcs', 'name':'Vpcs'},
        {'function': 'describe_subnets', 'key': 'Subnets', 'name':'Subnets'},
        {'function': 'describe_route_tables', 'key': 'RouteTables', 'name':'RouteTables'},
        {'function': 'describe_internet_gateways', 'key': 'InternetGateways', 'name':'InternetGateways'},
        {'function': 'describe_nat_gateways', 'key': 'NatGateways', 'name':'NatGateways'},
        {'function': 'describe_volumes', 'key': 'Volumes', 'name':'Volumes'},
        {'function': 'describe_snapshots', 'key': 'Snapshots', 'params': {'OwnerIds': ['self']}, 'name':'Snapshots'},
        {'function': 'describe_images', 'key': 'Images', 'params': {'Owners': ['self']}, 'name':'Images'},
        {'function': 'describe_transit_gateways', 'key': 'TransitGateways'},
    ],
    's3': [
        {'function': 'list_buckets', 'key': 'Buckets', 'name':'Buckets'},
    ],
    'rds': [
        {'function': 'describe_db_instances', 'key': 'DBInstances', 'name': 'DBInstances' },
        {'function': 'describe_db_clusters', 'key': 'DBClusters' , 'name': 'DBClusters'},
        {'function': 'describe_db_snapshots', 'key': 'DBSnapshots' , 'name': 'DBSnapshots'},
    ],
    'lambda': [
        {'function': 'list_functions', 'key': 'Functions', 'name':'Functions'},
        {'function': 'list_layers', 'key': 'Layers', 'name':'Layers'},
    ],
    'iam': [
        {'function': 'list_users', 'key': 'Users', 'name':'Users'},
        {'function': 'list_groups', 'key': 'Groups', 'name':'Groups'},
        {'function': 'list_roles', 'key': 'Roles', 'name':'Roles'},
        {'function': 'list_policies', 'key': 'Policies', 'params': {'Scope': 'Local'},'name': 'Policies'},
    ],
    'dynamodb': [
        {'function': 'list_tables', 'key': 'TableNames', 'name':'TableNames'},
    ],
    'elasticache': [
        {'function': 'describe_cache_clusters', 'key': 'CacheClusters', 'params': {'ShowCacheNodeInfo': True},'name': 'CacheClusters'},
        {'function': 'describe_serverless_caches', 'key': 'ServerlessCaches','name': 'ServerlessCaches'},
        {'function': 'describe_cache_subnet_groups', 'key': 'CacheSubnetGroups', 'name': 'SubnetGroups'},
        {'function': 'describe_cache_parameter_groups', 'key': 'CacheParameterGroups', 'name': 'ParameterGroups'},
    ],
    'eks': [
        {'function': 'list_clusters', 'key': 'clusters', 'name':'Clusters'},
    ],
    'ecs': [
        {'function': 'list_clusters', 'key': 'clusterArns', 'name':'ClusterArns'},
    ],
    'cloudformation': [
        {'function': 'list_stacks', 'key': 'StackSummaries' ,'name':'StackSummaries'},
    ],
    'cloudfront': [
        {'function': 'list_distributions', 'key': 'DistributionList', 'subkey': 'Items', 'name':'DistributionList'},
    ],
    'apigateway': [
        {'function': 'get_rest_apis', 'key': 'items', 'name':'REST APIs'},
    ],
    'route53': [
        {'function': 'list_hosted_zones', 'key': 'HostedZones', 'name':'HostedZones'},
    ],
    'sns': [
        {'function': 'list_topics', 'key': 'Topics', 'name': 'Topics'},
    ],
    'sqs': [
        {'function': 'list_queues', 'key': 'QueueUrls', 'name':'QueueUrls'},
    ],
    'kms': [
        {'function': 'list_keys', 'key': 'Keys', 'name':'Keys'},
    ],
    'secretsmanager': [
        {'function': 'list_secrets', 'key': 'SecretList', 'name':'SecretList'},
    ],
    'ssm': [
        {'function': 'describe_parameters', 'key': 'Parameters','name':'Parameters'},
    ],
    'ecr': [
        {'function': 'describe_repositories', 'key': 'repositories','name':'repositories'},
    ],
    'elasticbeanstalk': [
        {'function': 'describe_applications', 'key': 'Applications','name':'Applications'},
        {'function': 'describe_environments', 'key': 'Environments','name':'Environments'},
    ],
    'redshift': [
        {'function': 'describe_clusters', 'key': 'Clusters','name':'Clusters'},
    ],
    'organizations': [
        {'function': 'list_accounts', 'key': 'Accounts','name':'Account'},
    ],
    'guardduty': [
        {'function': 'list_detectors', 'key': 'DetectorIds','name':'DetectorIds'},
    ],
    'waf': [
        {'function': 'list_web_acls', 'key': 'WebACLs','name':'WebACLs'},
    ],
    'wafv2': [
        {'function': 'list_web_acls', 'key': 'WebACLs','params': {'Scope': 'REGIONAL'},'name':'RegionalWebACLs'},
    ],
    'cloudwatch': [
        {'function': 'describe_alarms', 'key': 'MetricAlarms','name':'MetricAlarms'},
    ],
    'resourcegroupstaggingapi': [
        {'function': 'get_resources', 'key': 'ResourceTagMappingList', 'name':'ResourceTagMappingList'},
    ],
    'lightsail': [
        {'function': 'get_instances', 'key': 'instances', 'name':'Instances'},
        {'function': 'get_load_balancers', 'key': 'loadBalancers', 'name':'LoadBalancers'},
        {'function': 'get_relational_databases', 'key': 'relationalDatabases', 'name':'relationalDatabases'},
        {'function': 'get_static_ips', 'key': 'staticIps', 'name':'staticIps'},
        {'function': 'get_buckets', 'key': 'buckets', 'name':'buckets'},
        {'function': 'get_disks', 'key': 'disks', 'name':'disks'},
    ],
    'batch': [
        {'function': 'describe_compute_environments', 'key': 'computeEnvironments', 'name':'computeEnvironments'},
        {'function': 'describe_job_queues', 'key': 'jobQueues', 'name':'jobQueues'},
        {'function': 'describe_job_definitions', 'key': 'jobDefinitions', 'name':'jobDefinitions'},
    ],
    # Additional Database Services
    'docdb': [
        {'function': 'describe_db_clusters', 'key': 'DBClusters', 'name': 'DBClusters'},
        {'function': 'describe_db_instances', 'key': 'DBInstances', 'name': 'DBInstances'},
    ],
    'neptune': [
        {'function': 'describe_db_clusters', 'key': 'DBClusters', 'name': 'DBClusters'},
        {'function': 'describe_db_instances', 'key': 'DBInstances', 'name': 'DBInstances'},
    ],
    # Storage Services
    'fsx': [
        {'function': 'describe_file_systems', 'key': 'FileSystems'},
        {'function': 'describe_backups', 'key': 'Backups'},
    ],
    'efs': [
        {'function': 'describe_file_systems', 'key': 'FileSystems'},
    ],
    'backup': [
        {'function': 'list_backup_vaults', 'key': 'BackupVaultList'},
        {'function': 'list_backup_plans', 'key': 'BackupPlansList'},
    ],
    # Networking Services
    'directconnect': [
        {'function': 'describe_connections', 'key': 'connections'},
        {'function': 'describe_virtual_interfaces', 'key': 'virtualInterfaces'},
    ],
    'globalaccelerator': [
        {'function': 'list_accelerators', 'key': 'Accelerators'},
    ],
    # Security Services
    'acm': [
        {'function': 'list_certificates', 'key': 'CertificateSummaryList'},
    ],
    'shield': [
        {'function': 'list_protections', 'key': 'Protections'},
    ],
    'network-firewall': [
        {'function': 'list_firewalls', 'key': 'Firewalls'},
        {'function': 'list_firewall_policies', 'key': 'FirewallPolicies'},
    ],
    'macie2': [
        {'function': 'list_classification_jobs', 'key': 'items'},
    ],
    # Application Integration
    'mq': [
        {'function': 'list_brokers', 'key': 'BrokerSummaries'},
    ],
    'events': [
        {'function': 'list_rules', 'key': 'Rules'},
        {'function': 'list_event_buses', 'key': 'EventBuses'},
    ],
    'stepfunctions': [
        {'function': 'list_state_machines', 'key': 'stateMachines'},
    ],
    # Analytics
    'kinesis': [
        {'function': 'list_streams', 'key': 'StreamNames'},
    ],
    'es': [
        {'function': 'list_domain_names', 'key': 'DomainNames'},
    ],
    'athena': [
        {'function': 'list_work_groups', 'key': 'WorkGroups'},
        {'function': 'list_data_catalogs', 'key': 'DataCatalogsSummary'},
    ],
    'glue': [
        {'function': 'get_databases', 'key': 'DatabaseList'},
        {'function': 'get_crawlers', 'key': 'Crawlers'},
        {'function': 'get_jobs', 'key': 'Jobs'},
    ],
    # Machine Learning
    'sagemaker': [
        {'function': 'list_notebook_instances', 'key': 'NotebookInstances'},
        {'function': 'list_training_jobs', 'key': 'TrainingJobSummaries'},
        {'function': 'list_endpoints', 'key': 'Endpoints'},
    ],
    'comprehend': [
        {'function': 'list_document_classification_jobs', 'key': 'DocumentClassificationJobPropertiesList'},
        {'function': 'list_entity_recognizers', 'key': 'EntityRecognizerPropertiesList'},
    ],
    # IoT Services
    'iot': [
        {'function': 'list_things', 'key': 'things'},
        {'function': 'list_policies', 'key': 'policies'},
        {'function': 'list_certificates', 'key': 'certificates'},
    ],
    'greengrass': [
        {'function': 'list_groups', 'key': 'Groups'},
    ],
    # Developer Tools
    'codecommit': [
        {'function': 'list_repositories', 'key': 'repositories'},
    ],
    'codebuild': [
        {'function': 'list_projects', 'key': 'projects'},
    ],
    'codepipeline': [
        {'function': 'list_pipelines', 'key': 'pipelines'},
    ],
    'codeartifact': [
        {'function': 'list_domains', 'key': 'domains'},
    ],
    # Media Services
    'mediaconvert': [
        {'function': 'list_queues', 'key': 'Queues'},
        {'function': 'list_presets', 'key': 'Presets'},
    ],
    'medialive': [
        {'function': 'list_channels', 'key': 'Channels'},
        {'function': 'list_inputs', 'key': 'Inputs'},
    ],
    # Migration & Transfer
    'datasync': [
        {'function': 'list_tasks', 'key': 'Tasks'},
        {'function': 'list_locations', 'key': 'Locations'},
    ],
    'transfer': [
        {'function': 'list_servers', 'key': 'Servers'},
    ],
    # Cost Management
    'ce': [
        {'function': 'list_cost_category_definitions', 'key': 'CostCategoryReferences'},
    ],
    'savingsplans': [
        {'function': 'describe_savings_plans', 'key': 'savingsPlans'},
    ],
    # Business Applications
    'workmail': [
        {'function': 'list_organizations', 'key': 'OrganizationSummaries'},
    ],
    'workspaces': [
        {'function': 'describe_workspaces', 'key': 'Workspaces'},
    ],
    'bedrock': [
        {'function': 'list_foundation_models', 'key': 'modelSummaries', 'name':'FoundationModels'},
        {'function': 'list_custom_models', 'key': 'modelSummaries', 'name':'CustomModels'},
        {'function': 'list_evaluation_jobs', 'key': 'jobSummaries', 'name':'jobSummaries'},
        {'function': 'list_provisioned_model_throughputs', 'key': 'provisionedModelSummaries', 'name': 'provisionedModelSummaries'},
    ],
    'bedrock-agent': [
        {'function': 'list_agents', 'key': 'agentSummaries', 'name': 'agents'},
        {'function': 'list_knowledge_bases', 'key': 'knowledgeBaseSummaries', 'name': 'knowledgeBases'},
    ],
    'elbv2': [  # Application Load Balancer (ALB) and Network Load Balancer (NLB)
        {'function': 'describe_load_balancers', 'key': 'LoadBalancers', 'name': 'LoadBalancers'},
        {'function': 'describe_target_groups', 'key': 'TargetGroups', 'name': 'TargetGroups'},
    ],
    'elb': [  # Classic Load Balancer (ELB)
        {'function': 'describe_load_balancers', 'key': 'LoadBalancerDescriptions', 'name': 'LoadBalancerDescriptions'},
    ],
    'opensearch': [
        {'function': 'list_versions', 'key': 'Versions', 'name': 'Versions'},
        {'function': 'list_domain_names', 'key': 'DomainNames', 'params':{'EngineType':'OpenSearch'},'name': 'OpensearchDomainNames'},
        {'function': 'list_domain_names', 'key': 'DomainNames', 'params':{'EngineType':'Elasticsearch'},'name': 'ElasticSearchDomainNames'},
        {'function': 'list_vpc_endpoints', 'key': 'VpcEndpointSummaryList', 'name': 'VpcEndpointSummaryList'},
    ],
    'opensearchserverless': [
        {'function': 'list_collections', 'key': 'collectionSummaries', 'name': 'collectionSummaries'},
        {'function': 'list_vpc_endpoints', 'key': 'vpcEndpointSummaries', 'name': 'vpcEndpointSummaries'},
        {'function': 'list_security_policies', 'key': 'securityPolicySummaries', 'params':{'type':'encryption'}, 'name': 'EncryptionSecurityPolicyDetails'},
        {'function': 'list_security_policies', 'key': 'securityPolicySummaries', 'params':{'type':'network'}, 'name': 'NetworkSecurityPolicyDetails'},
        {'function': 'list_security_configs', 'key': 'securityConfigSummaries', 'params':{'type':'saml'}, 'name': 'SAMLsecurityConfigDetails'},
        {'function': 'list_security_configs', 'key': 'securityConfigSummaries', 'params':{'type':'iamidentitycenter'}, 'name': 'IAMsecurityConfigDetails'},
        {'function': 'list_access_policies', 'key': 'accessPolicySummaries', 'params':{'type':'data'}, 'name': 'accessPolicyDetails'},
    ],
}

# Essential fields to extract for each resource type
# Structure: service_name -> subservice_name -> list of fields
RESOURCE_ESSENTIAL_FIELDS = {
    'ec2': {
        'Instances': [
            'InstanceId', 'State', 'InstanceType', 'ImageId', 'SecurityGroups', 
            'VpcId', 'SubnetId', 'IamInstanceProfile', 'Monitoring', 'Tags', 
            'EbsOptimized', 'Platform'
        ],
        'SecurityGroups': [
            'GroupId', 'GroupName', 'VpcId', 'IpPermissions', 'IpPermissionsEgress', 'Tags'
        ],
        'Vpcs': [
            'VpcId', 'State', 'CidrBlock', 'IsDefault', 'InstanceTenancy', 'Tags'
        ],
        'Subnets': [
            'SubnetId', 'VpcId', 'CidrBlock', 'AvailabilityZone', 'MapPublicIpOnLaunch', 'Tags'
        ],
        'RouteTables': [
            'RouteTableId', 'VpcId', 'Routes', 'Associations', 'Tags', 'OwnerId'
        ],
        'InternetGateways': [
            'InternetGatewayId', 'Attachments', 'Tags', 'OwnerId'
        ],
        'NatGateways': [
            'NatGatewayId', 'State', 'VpcId', 'SubnetId', 'Tags', 'ConnectivityType'
        ],
        'Volumes': [
            'VolumeId', 'Size', 'VolumeType', 'Iops', 'Encrypted', 'Attachments', 'Tags', 'Throughput'
        ],
        'Snapshots': [
            'SnapshotId', 'VolumeId', 'VolumeSize', 'Progress', 'Encrypted', 'Tags', 'OwnerId'
        ],
        'Images': [
            'ImageId', 'OwnerId', 'Public', 'Architecture', 'Name', 'RootDeviceType', 
            'Platform', 'EnaSupport', 'Tags', 'BootMode'
        ],
        'TransitGateways': [
            'TransitGatewayId', 'TransitGatewayArn', 'State', 'OwnerId', 
            'Description', 'CreationTime', 'Options', 'Tags'
        ]
    },
    's3': {
        'Buckets': [
            'Name', 'CreationDate'
        ]
    },
    'rds': {
        'DBInstances': [
            'DBInstanceIdentifier', 'DBInstanceClass', 'Engine', 'EngineVersion', 
            'DBInstanceStatus', 'StorageEncrypted', 'MultiAZ', 'PubliclyAccessible', 
            'VpcSecurityGroups', 'BackupRetentionPeriod', 'DeletionProtection', 'Tags'
        ],
        'DBClusters': [
            'DBClusterIdentifier', 'Engine', 'EngineVersion', 'Status', 'StorageEncrypted', 
            'VpcSecurityGroups', 'BackupRetentionPeriod', 'MultiAZ', 'DeletionProtection', 
            'DBClusterMembers', 'Tags'
        ],
        'DBSnapshots': [
            'DBSnapshotIdentifier', 'DBInstanceIdentifier', 'Engine', 'Status', 
            'Encrypted', 'SnapshotType', 'Tags'
        ]
    },
    'lambda': {
        'Functions': [
            'FunctionName', 'FunctionArn', 'Runtime', 'Role', 'Timeout', 
            'MemorySize', 'VpcConfig', 'TracingConfig', 'Tags'
        ],
        'Layers': [
            'LayerName', 'LayerArn', 'LatestMatchingVersion'
        ]
    },
    'iam': {
        'Users': [
            'UserName', 'UserId', 'Arn', 'Path', 'CreateDate', 'PasswordLastUsed', 'Tags'
        ],
        'Groups': [
            'GroupName', 'GroupId', 'Arn', 'Path', 'CreateDate'
        ],
        'Roles': [
            'RoleName', 'RoleId', 'Arn', 'Path', 'CreateDate', 'AssumeRolePolicyDocument', 
            'MaxSessionDuration', 'Tags'
        ],
        'Policies': [
            'PolicyName', 'PolicyId', 'Arn', 'DefaultVersionId', 'AttachmentCount', 
            'IsAttachable', 'CreateDate', 'UpdateDate', 'Tags'
        ]
    },
    'dynamodb': {
        'TableNames': [
            'TableNames'
        ]
    },
    'elasticache': {
        'CacheClusters': [
            'CacheClusterId', 'CacheNodeType', 'Engine', 'EngineVersion', 
            'CacheClusterStatus', 'SecurityGroups', 'TransitEncryptionEnabled', 
            'AtRestEncryptionEnabled', 'ARN'
        ],
        'ServerlessCaches': [
            'ServerlessCacheName', 'Status', 'Engine', 'MajorEngineVersion', 
            'KmsKeyId', 'SecurityGroupIds', 'ARN'
        ],
        'SubnetGroups': [
            'CacheSubnetGroupName', 'CacheSubnetGroupDescription', 'VpcId', 'Subnets'
        ],
        'ParameterGroups': [
            'CacheParameterGroupName', 'CacheParameterGroupFamily', 'Description', 'ARN'
        ]
    },
    'eks': {
        'Clusters': [
            'clusters'
        ]
    },
    'ecs': {
        'ClusterArns': [
            'clusterArns'
        ]
    },
    'cloudformation': {
        'StackSummaries': [
            'StackId', 'StackName', 'StackStatus', 'StackStatusReason', 
            'EnableTerminationProtection', 'Tags', 'DriftInformation'
        ]
    },
    'cloudfront': {
        'DistributionList': [
            'Id', 'ARN', 'Status', 'DomainName', 'Origins', 'Enabled', 'ViewerCertificate', 'Tags'
        ]
    },
    'apigateway': {
        'REST APIs': [
            'id', 'name', 'description', 'endpointConfiguration', 'policy', 'tags'
        ]
    },
    'route53': {
        'HostedZones': [
            'Id', 'Name', 'ResourceRecordSetCount', 'PrivateZone'
        ]
    },
    'sns': {
        'Topics': [
            'TopicArn', 'Attributes'
        ]
    },
    'sqs': {
        'QueueUrls': [
            'QueueUrls'
        ]
    },
    'kms': {
        'Keys': [
            'KeyId', 'Arn', 'KeyUsage', 'KeyState', 'Origin', 'Description'
        ]
    },
    'secretsmanager': {
        'SecretList': [
            'ARN', 'Name', 'KmsKeyId', 'RotationEnabled', 'DeletedDate', 'Tags', 'OwningService'
        ]
    },
    'ssm': {
        'Parameters': [
            'Name', 'Type', 'Version', 'Tier'
        ]
    },
    'ecr': {
        'repositories': [
            'repositoryArn', 'repositoryName', 'repositoryUri', 'imageTagMutability', 
            'imageScanningConfiguration', 'encryptionConfiguration'
        ]
    },
    'elasticbeanstalk': {
        'Applications': [
            'ApplicationArn', 'ApplicationName', 'Description', 'ResourceLifecycleConfig'
        ],
        'Environments': [
            'EnvironmentName', 'EnvironmentId', 'ApplicationName', 'Status', 
            'Health', 'HealthStatus', 'Tier', 'EnvironmentArn'
        ]
    },
    'redshift': {
        'Clusters': [
            'ClusterIdentifier', 'NodeType', 'ClusterStatus', 'NumberOfNodes', 
            'PubliclyAccessible', 'Encrypted', 'VpcSecurityGroups', 'VpcId', 
            'AutomatedSnapshotRetentionPeriod', 'Tags', 'KmsKeyId', 'EnhancedVpcRouting'
        ]
    },
    'organizations': {
        'Account': [
            'Id', 'Arn', 'Email', 'Name', 'Status', 'JoinedTimestamp'
        ]
    },
    'guardduty': {
        'DetectorIds': [
            'DetectorIds'
        ]
    },
    'waf': {
        'WebACLs': [
            'WebACLId', 'Name', 'DefaultAction', 'Rules', 'WebACLArn', 'Tags'
        ]
    },
    'wafv2': {
        'RegionalWebACLs': [
            'Name', 'Id', 'Description', 'ARN', 'DefaultAction', 'Tags'
        ]
    },
    'cloudwatch': {
        'MetricAlarms': [
            'AlarmName', 'AlarmArn', 'AlarmDescription', 'StateValue', 'StateReason', 
            'MetricName', 'Namespace', 'Threshold', 'ComparisonOperator', 
            'EvaluationPeriods', 'ActionsEnabled', 'Tags'
        ]
    },
    'resourcegroupstaggingapi': {
        'ResourceTagMappingList': [
            'ResourceARN', 'Tags', 'ResourceType', 'Region', 'ResourceCreationTime'
        ]
    },
    'lightsail': {
        'Instances': [
            'name', 'arn', 'location', 'resourceType', 'tags', 'blueprintId', 
            'bundleId', 'state', 'hardware', 'isStaticIp'
        ],
        'LoadBalancers': [
            'name', 'arn', 'location', 'resourceType', 'tags', 'state', 'protocol', 'healthCheckPath'
        ],
        'relationalDatabases': [
            'name', 'arn', 'location', 'resourceType', 'tags', 'engine', 
            'engineVersion', 'state', 'backupRetentionEnabled', 'publiclyAccessible'
        ],
        'staticIps': [
            'name', 'arn', 'location', 'resourceType', 'ipAddress', 'isAttached'
        ],
        'buckets': [
            'name', 'arn', 'bundleId', 'location', 'resourceType', 'tags'
        ],
        'disks': [
            'name', 'arn', 'location', 'resourceType', 'tags', 'sizeInGb', 'state', 'isAttached'
        ]
    },
    'batch': {
        'computeEnvironments': [
            'computeEnvironmentName', 'computeEnvironmentArn', 'type', 'state', 
            'status', 'computeResources', 'serviceRole', 'tags'
        ],
        'jobQueues': [
            'jobQueueName', 'jobQueueArn', 'state', 'status', 'priority', 
            'computeEnvironmentOrder', 'tags'
        ],
        'jobDefinitions': [
            'jobDefinitionName', 'jobDefinitionArn', 'revision', 'status', 
            'type', 'containerProperties', 'timeout', 'tags'
        ]
    },
    'docdb': {
        'DBClusters': [
            'DBClusterIdentifier', 'Engine', 'EngineVersion', 'Status', 'StorageEncrypted', 
            'VpcSecurityGroups', 'BackupRetentionPeriod', 'MultiAZ', 'DeletionProtection', 
            'DBClusterMembers', 'Tags'
        ],
        'DBInstances': [
            'DBInstanceIdentifier', 'DBInstanceClass', 'Engine', 'DBInstanceStatus', 
            'EngineVersion', 'StorageEncrypted', 'VpcSecurityGroups', 'DBClusterIdentifier', 
            'PubliclyAccessible', 'DeletionProtection'
        ]
    },
    'neptune': {
        'DBClusters': [
            'DBClusterIdentifier', 'Engine', 'EngineVersion', 'Status', 'StorageEncrypted', 
            'VpcSecurityGroups', 'BackupRetentionPeriod', 'MultiAZ', 'DeletionProtection', 
            'DBClusterMembers', 'Tags', 'StorageType'
        ],
        'DBInstances': [
            'DBInstanceIdentifier', 'DBInstanceClass', 'Engine', 'DBInstanceStatus', 
            'EngineVersion', 'StorageEncrypted', 'VpcSecurityGroups', 'DBClusterIdentifier', 
            'PubliclyAccessible', 'DeletionProtection'
        ]
    },
    'fsx': {
        'FileSystems': [
            'FileSystemId', 'FileSystemType', 'Lifecycle', 'StorageCapacity', 
            'VpcId', 'KmsKeyId', 'ResourceARN', 'Tags'
        ],
        'Backups': [
            'BackupId', 'Lifecycle', 'Type', 'ProgressPercent', 'KmsKeyId', 'ResourceARN', 'Tags'
        ]
    },
    'efs': {
        'FileSystems': [
            'FileSystemId', 'FileSystemArn', 'LifeCycleState', 'PerformanceMode', 
            'ThroughputMode', 'Encrypted', 'KmsKeyId', 'Tags'
        ]
    },
    'backup': {
        'BackupVaultList': [
            'BackupVaultName', 'BackupVaultArn', 'EncryptionKeyArn', 'NumberOfRecoveryPoints', 'LockDate'
        ],
        'BackupPlansList': [
            'BackupPlanArn', 'BackupPlanId', 'BackupPlanName', 'LastExecutionDate', 'VersionId'
        ]
    },
    'directconnect': {
        'connections': [
            'connectionId', 'connectionName', 'connectionState', 'location', 'bandwidth', 'portEncryptionStatus'
        ],
        'virtualInterfaces': [
            'virtualInterfaceId', 'virtualInterfaceName', 'virtualInterfaceType', 
            'connectionId', 'vlan', 'virtualInterfaceState', 'asn', 'amazonSideAsn'
        ]
    },
    'globalaccelerator': {
        'Accelerators': [
            'AcceleratorArn', 'Name', 'IpAddressType', 'Enabled', 'Status'
        ]
    },
    'acm': {
        'CertificateSummaryList': [
            'CertificateArn', 'DomainName', 'Status', 'Type', 'Tags'
        ]
    },
    'shield': {
        'Protections': [
            'Id', 'Name', 'ResourceArn', 'ProtectionArn'
        ]
    },
    'network-firewall': {
        'Firewalls': [
            'FirewallName', 'FirewallArn', 'FirewallPolicyArn', 'VpcId', 'DeleteProtection', 'Tags'
        ],
        'FirewallPolicies': [
            'Name', 'Arn', 'FirewallPolicyStatus', 'NumberOfAssociations'
        ]
    },
    'macie2': {
        'items': [
            'jobId', 'name', 'jobStatus', 'jobType', 'tags'
        ]
    },
    'mq': {
        'BrokerSummaries': [
            'BrokerArn', 'BrokerId', 'BrokerName', 'BrokerState', 'DeploymentMode', 
            'EngineType', 'PubliclyAccessible', 'Tags'
        ]
    },
    'events': {
        'Rules': [
            'Name', 'Arn', 'EventPattern', 'State', 'ScheduleExpression', 'Tags'
        ],
        'EventBuses': [
            'Name', 'Arn', 'Description', 'EventSourceName', 'Tags'
        ]
    },
    'stepfunctions': {
        'stateMachines': [
            'stateMachineArn', 'name', 'type', 'status', 'roleArn', 'tags'
        ]
    },
    'kinesis': {
        'StreamNames': [
            'StreamNames'
        ]
    },
    'es': {
        'DomainNames': [
            'DomainNames'
        ]
    },
    'athena': {
        'WorkGroups': [
            'Name', 'State', 'EnforceWorkGroupConfiguration', 'Tags'
        ],
        'DataCatalogsSummary': [
            'CatalogName', 'Type', 'Tags', 'Owner'
        ]
    },
    'glue': {
        'DatabaseList': [
            'Name', 'Description', 'CatalogId', 'Tags', 'Parameters', 'CreateTime'
        ],
        'Crawlers': [
            'Name', 'Role', 'Targets', 'DatabaseName', 'State', 'Schedule', 'Tags', 'CrawlerSecurityConfiguration'
        ],
        'Jobs': [
            'Name', 'Role', 'Command', 'MaxRetries', 'Timeout', 'WorkerType', 
            'SecurityConfiguration', 'GlueVersion', 'Tags', 'AllocatedCapacity'
        ]
    },
    'sagemaker': {
        'NotebookInstances': [
            'NotebookInstanceName', 'NotebookInstanceArn', 'NotebookInstanceStatus', 
            'InstanceType', 'PlatformIdentifier', 'Tags'
        ],
        'TrainingJobSummaries': [
            'TrainingJobName', 'TrainingJobArn', 'TrainingJobStatus', 'RoleArn', 
            'ResourceConfig', 'AlgorithmSpecification', 'Tags', 'VpcConfig'
        ],
        'Endpoints': [
            'EndpointName', 'EndpointArn', 'EndpointStatus', 'EndpointConfigName', 
            'ProductionVariants', 'Tags'
        ]
    },
    'comprehend': {
        'DocumentClassificationJobPropertiesList': [
            'JobId', 'JobArn', 'JobName', 'JobStatus', 'DocumentClassifierArn', 'DataAccessRoleArn', 'Tags'
        ],
        'EntityRecognizerPropertiesList': [
            'EntityRecognizerArn', 'LanguageCode', 'Status', 'TrainingStartTime', 
            'TrainingEndTime', 'DataAccessRoleArn', 'Tags'
        ]
    },
    'iot': {
        'things': [
            'thingName', 'thingTypeName', 'thingArn', 'attributes', 'tags'
        ],
        'policies': [
            'policyName', 'policyArn', 'policyVersionId', 'isDefaultVersion'
        ],
        'certificates': [
            'certificateArn', 'certificateId', 'status', 'validity', 'tags'
        ]
    },
    'greengrass': {
        'Groups': [
            'Arn', 'Id', 'Name', 'CreationTimestamp', 'tags'
        ]
    },
    'codecommit': {
        'repositories': [
            'repositoryName', 'repositoryId', 'repositoryDescription', 'defaultBranch', 'tags'
        ]
    },
    'codebuild': {
        'projects': [
            'name', 'arn', 'description', 'tags'
        ]
    },
    'codepipeline': {
        'pipelines': [
            'name', 'version', 'roleArn', 'stages', 'tags'
        ]
    },
    'codeartifact': {
        'domains': [
            'name', 'owner', 'arn', 'status', 'tags'
        ]
    },
    'mediaconvert': {
        'Queues': [
            'Arn', 'Name', 'Status', 'Type', 'PricingPlan', 'Tags'
        ],
        'Presets': [
            'Arn', 'Name', 'Category', 'Type', 'Tags'
        ]
    },
    'medialive': {
        'Channels': [
            'Arn', 'Id', 'Name', 'ChannelClass', 'State', 'RoleArn', 'Tags'
        ],
        'Inputs': [
            'Arn', 'Id', 'Name', 'InputClass', 'InputSourceType', 'State', 'Tags'
        ]
    },
    'datasync': {
        'Tasks': [
            'TaskArn', 'Status', 'Name', 'SourceLocationArn', 'DestinationLocationArn'
        ],
        'Locations': [
            'LocationArn', 'LocationUri', 'S3StorageClass', 'Tags'
        ]
    },
    'transfer': {
        'Servers': [
            'Arn', 'Domain', 'IdentityProviderType', 'EndpointType', 'State', 'Tags'
        ]
    },
    'ce': {
        'CostCategoryReferences': [
            'CostCategoryArn', 'Name', 'EffectiveStart', 'EffectiveEnd', 'NumberOfRules'
        ]
    },
    'savingsplans': {
        'savingsPlans': [
            'savingsPlansId', 'savingsPlansArn', 'start', 'end', 'state', 
            'savingsPlansType', 'paymentOption', 'commitment'
        ]
    },
    'workmail': {
        'OrganizationSummaries': [
            'OrganizationId', 'Alias', 'DefaultMailDomain', 'State', 'DirectoryType'
        ]
    },
    'workspaces': {
        'Workspaces': [
            'WorkspaceId', 'DirectoryId', 'UserName', 'State', 'BundleId', 
            'VolumeEncryptionKey', 'UserVolumeEncryptionEnabled', 'RootVolumeEncryptionEnabled'
        ]
    },
    'bedrock': {
        'FoundationModels': [
            'modelArn', 'modelId', 'modelName', 'providerName', 'customizationsSupported', 'inferenceTypesSupported'
        ],
        'CustomModels': [
            'modelArn', 'modelName', 'baseModelArn', 'baseModelName', 'customizationType', 'modelKmsKeyArn', 'tags'
        ],
        'jobSummaries': [
            'jobName', 'jobArn', 'status', 'jobType', 'evaluationTaskTypes', 'tags'
        ],
        'provisionedModelSummaries': [
            'provisionedModelName', 'provisionedModelArn', 'modelArn', 'desiredModelUnits', 
            'status', 'commitmentDuration', 'tags'
        ]
    },
    'bedrock-agent': {
        'agents': [
            'agentId', 'agentName', 'agentStatus', 'foundationModel', 'guardrailConfiguration', 'tags'
        ],
        'knowledgeBases': [
            'knowledgeBaseId', 'name', 'status', 'storageConfiguration', 'knowledgeBaseConfiguration', 'tags'
        ]
    },
    'elbv2': {
        'LoadBalancers': [
            'LoadBalancerArn', 'DNSName', 'CanonicalHostedZoneId', 'CreatedTime', 
            'LoadBalancerName', 'Scheme', 'VpcId', 'State', 'Type', 'AvailabilityZones', 
            'SecurityGroups', 'IpAddressType', 'CustomerOwnedIpv4Pool', 'Tags'
        ],
        'TargetGroups': [
            'TargetGroupArn', 'TargetGroupName', 'Protocol', 'VpcId', 'HealthCheckProtocol', 'TargetType', 'Tags'
        ]
    },
    'elb': {
        'LoadBalancerDescriptions': [
            'LoadBalancerName', 'AvailabilityZones', 'VPCId', 'Scheme', 'SecurityGroups', 'HealthCheck', 'Instances', 'Tags'
        ]
    },
    'opensearch': {
        'Versions': [
            'Versions'
        ],
        'OpensearchDomainNames': [
            'DomainNames'
        ],
        'ElasticSearchDomainNames': [
            'DomainNames'
        ],
        'VpcEndpointSummaryList': [
            'VpcEndpointId', 'DomainArn', 'Status', 'Endpoint', 'Tags'
        ]
    },
    'opensearchserverless': {
        'collectionSummaries': [
            'id', 'name', 'status', 'type', 'arn', 'kmsKeyArn', 'tags'
        ],
        'vpcEndpointSummaries': [
            'id', 'name', 'vpcId', 'securityGroupIds', 'status', 'tags'
        ],
        'EncryptionSecurityPolicyDetails': [
            'name', 'type', 'policyVersion', 'description', 'tags'
        ],
        'NetworkSecurityPolicyDetails': [
            'name', 'type', 'policyVersion', 'description', 'tags'
        ],
        'SAMLsecurityConfigDetails': [
            'id', 'type', 'configVersion', 'description', 'tags'
        ],
        'IAMsecurityConfigDetails': [
            'id', 'type', 'configVersion', 'description', 'tags'
        ],
        'accessPolicyDetails': [
            'name', 'type', 'policyVersion', 'description', 'tags'
        ]
    }
}
# 
# Structure: service_name -> subservice_name -> ARN pattern configuration
ARN_CONSTRUCTION_MAP = {
    'ec2': {
        'Instances': {
            'pattern': 'arn:aws:ec2:{region}:{account_id}:instance/{resource_id}',
            'id_field': 'InstanceId'
        },
        'SecurityGroups': {
            'pattern': 'arn:aws:ec2:{region}:{account_id}:security-group/{resource_id}',
            'id_field': 'GroupId'
        },
        'Vpcs': {
            'pattern': 'arn:aws:ec2:{region}:{account_id}:vpc/{resource_id}',
            'id_field': 'VpcId'
        },
        'Subnets': {
            'pattern': 'arn:aws:ec2:{region}:{account_id}:subnet/{resource_id}',
            'id_field': 'SubnetId'
        },
        'RouteTables': {
            'pattern': 'arn:aws:ec2:{region}:{account_id}:route-table/{resource_id}',
            'id_field': 'RouteTableId'
        },
        'InternetGateways': {
            'pattern': 'arn:aws:ec2:{region}:{account_id}:internet-gateway/{resource_id}',
            'id_field': 'InternetGatewayId'
        },
        'NatGateways': {
            'pattern': 'arn:aws:ec2:{region}:{account_id}:natgateway/{resource_id}',
            'id_field': 'NatGatewayId'
        },
        'Volumes': {
            'pattern': 'arn:aws:ec2:{region}:{account_id}:volume/{resource_id}',
            'id_field': 'VolumeId'
        },
        'Snapshots': {
            'pattern': 'arn:aws:ec2:{region}:{account_id}:snapshot/{resource_id}',
            'id_field': 'SnapshotId'
        },
        'Images': {
            'pattern': 'arn:aws:ec2:{region}:{account_id}:image/{resource_id}',
            'id_field': 'ImageId'
        },
        'TransitGateways': {
            'pattern': 'arn:aws:ec2:{region}:{account_id}:transit-gateway/{resource_id}',
            'id_field': 'TransitGatewayId'
        }
    },
    's3': {
        'Buckets': {
            'pattern': 'arn:aws:s3:::{resource_id}',
            'id_field': 'Name'
        }
    },
    'rds': {
        'DBInstances': {
            'pattern': 'arn:aws:rds:{region}:{account_id}:db:{resource_id}',
            'id_field': 'DBInstanceIdentifier'
        },
        'DBClusters': {
            'pattern': 'arn:aws:rds:{region}:{account_id}:cluster:{resource_id}',
            'id_field': 'DBClusterIdentifier'
        },
        'DBSnapshots': {
            'pattern': 'arn:aws:rds:{region}:{account_id}:snapshot:{resource_id}',
            'id_field': 'DBSnapshotIdentifier'
        }
    },
    'lambda': {
        'Functions': {
            'pattern': 'arn:aws:lambda:{region}:{account_id}:function:{resource_id}',
            'id_field': 'FunctionName'
        },
        'Layers': {
            'pattern': 'arn:aws:lambda:{region}:{account_id}:layer:{resource_id}',
            'id_field': 'LayerName'
        }
    },
    'iam': {
        'Users': {
            'pattern': 'arn:aws:iam::{account_id}:user/{resource_id}',
            'id_field': 'UserName'
        },
        'Groups': {
            'pattern': 'arn:aws:iam::{account_id}:group/{resource_id}',
            'id_field': 'GroupName'
        },
        'Roles': {
            'pattern': 'arn:aws:iam::{account_id}:role/{resource_id}',
            'id_field': 'RoleName'
        },
        'Policies': {
            'pattern': 'arn:aws:iam::{account_id}:policy/{resource_id}',
            'id_field': 'PolicyName'
        }
    },
    'dynamodb': {
        'TableNames': {
            'pattern': 'arn:aws:dynamodb:{region}:{account_id}:table/{resource_id}',
            'id_field': 'TableName'
        }
    },
    'elasticache': {
        'CacheClusters': {
            'pattern': 'arn:aws:elasticache:{region}:{account_id}:cluster:{resource_id}',
            'id_field': 'CacheClusterId'
        },
        'ServerlessCaches': {
            'pattern': 'arn:aws:elasticache:{region}:{account_id}:serverlesscache:{resource_id}',
            'id_field': 'ServerlessCacheName'
        },
        'SubnetGroups': {
            'pattern': 'arn:aws:elasticache:{region}:{account_id}:subnetgroup:{resource_id}',
            'id_field': 'CacheSubnetGroupName'
        },
        'ParameterGroups': {
            'pattern': 'arn:aws:elasticache:{region}:{account_id}:parametergroup:{resource_id}',
            'id_field': 'CacheParameterGroupName'
        }
    },
    'eks': {
        'Clusters': {
            'pattern': 'arn:aws:eks:{region}:{account_id}:cluster/{resource_id}',
            'id_field': 'name'
        }
    },
    'ecs': {
        'ClusterArns': {
            'pattern': '{resource_id}',  # Already ARN
            'id_field': 'clusterArn'
        }
    },
    'cloudformation': {
        'StackSummaries': {
            'pattern': 'arn:aws:cloudformation:{region}:{account_id}:stack/{resource_id}/*',
            'id_field': 'StackName'
        }
    },
    'cloudfront': {
        'DistributionList': {
            'pattern': 'arn:aws:cloudfront::{account_id}:distribution/{resource_id}',
            'id_field': 'Id'
        }
    },
    'apigateway': {
        'REST APIs': {
            'pattern': 'arn:aws:apigateway:{region}::/restapis/{resource_id}',
            'id_field': 'id'
        }
    },
    'route53': {
        'HostedZones': {
            'pattern': 'arn:aws:route53:::hostedzone/{resource_id}',
            'id_field': 'Id'
        }
    },
    'sns': {
        'Topics': {
            'pattern': '{resource_id}',  # Already ARN
            'id_field': 'TopicArn'
        }
    },
    'sqs': {
        'QueueUrls': {
            'pattern': 'arn:aws:sqs:{region}:{account_id}:{resource_id}',
            'id_field': 'Name',
            'extract_name': True  # Extract queue name from URL
        }
    },
    'kms': {
        'Keys': {
            'pattern': 'arn:aws:kms:{region}:{account_id}:key/{resource_id}',
            'id_field': 'KeyId'
        }
    },
    'secretsmanager': {
        'SecretList': {
            'pattern': 'arn:aws:secretsmanager:{region}:{account_id}:secret:{resource_id}',
            'id_field': 'Name'
        }
    },
    'ssm': {
        'Parameters': {
            'pattern': 'arn:aws:ssm:{region}:{account_id}:parameter{resource_id}',
            'id_field': 'Name'
        }
    },
    'ecr': {
        'repositories': {
            'pattern': 'arn:aws:ecr:{region}:{account_id}:repository/{resource_id}',
            'id_field': 'repositoryName'
        }
    },
    'elasticbeanstalk': {
        'Applications': {
            'pattern': 'arn:aws:elasticbeanstalk:{region}:{account_id}:application/{resource_id}',
            'id_field': 'ApplicationName'
        },
        'Environments': {
            'pattern': 'arn:aws:elasticbeanstalk:{region}:{account_id}:environment/{resource_id}',
            'id_field': 'EnvironmentName'
        }
    },
    'redshift': {
        'Clusters': {
            'pattern': 'arn:aws:redshift:{region}:{account_id}:cluster:{resource_id}',
            'id_field': 'ClusterIdentifier'
        }
    },
    'organizations': {
        'Account': {
            'pattern': 'arn:aws:organizations::{account_id}:account/o-example/{resource_id}',
            'id_field': 'Id'
        }
    },
    'guardduty': {
        'DetectorIds': {
            'pattern': 'arn:aws:guardduty:{region}:{account_id}:detector/{resource_id}',
            'id_field': 'DetectorId'
        }
    },
    'waf': {
        'WebACLs': {
            'pattern': 'arn:aws:waf::{account_id}:webacl/{resource_id}',
            'id_field': 'WebACLId'
        }
    },
    'wafv2': {
        'RegionalWebACLs': {
            'pattern': 'arn:aws:wafv2:{region}:{account_id}:regional/webacl/{resource_id}',
            'id_field': 'Id'
        }
    },
    'cloudwatch': {
        'MetricAlarms': {
            'pattern': 'arn:aws:cloudwatch:{region}:{account_id}:alarm:{resource_id}',
            'id_field': 'AlarmName'
        }
    },
    'resourcegroupstaggingapi': {
        'ResourceTagMappingList': {
            'pattern': '{resource_id}',  # Already ARN
            'id_field': 'ResourceARN'
        }
    },
    'lightsail': {
        'Instances': {
            'pattern': 'arn:aws:lightsail:{region}:{account_id}:Instance/{resource_id}',
            'id_field': 'name'
        },
        'LoadBalancers': {
            'pattern': 'arn:aws:lightsail:{region}:{account_id}:LoadBalancer/{resource_id}',
            'id_field': 'name'
        },
        'relationalDatabases': {
            'pattern': 'arn:aws:lightsail:{region}:{account_id}:RelationalDatabase/{resource_id}',
            'id_field': 'name'
        },
        'staticIps': {
            'pattern': 'arn:aws:lightsail:{region}:{account_id}:StaticIp/{resource_id}',
            'id_field': 'name'
        },
        'buckets': {
            'pattern': 'arn:aws:lightsail:{region}:{account_id}:Bucket/{resource_id}',
            'id_field': 'name'
        },
        'disks': {
            'pattern': 'arn:aws:lightsail:{region}:{account_id}:Disk/{resource_id}',
            'id_field': 'name'
        }
    },
    'batch': {
        'computeEnvironments': {
            'pattern': 'arn:aws:batch:{region}:{account_id}:compute-environment/{resource_id}',
            'id_field': 'computeEnvironmentName'
        },
        'jobQueues': {
            'pattern': 'arn:aws:batch:{region}:{account_id}:job-queue/{resource_id}',
            'id_field': 'jobQueueName'
        },
        'jobDefinitions': {
            'pattern': 'arn:aws:batch:{region}:{account_id}:job-definition/{resource_id}',
            'id_field': 'jobDefinitionName'
        }
    },
    'docdb': {
        'DBClusters': {
            'pattern': 'arn:aws:rds:{region}:{account_id}:cluster:{resource_id}',
            'id_field': 'DBClusterIdentifier'
        },
        'DBInstances': {
            'pattern': 'arn:aws:rds:{region}:{account_id}:db:{resource_id}',
            'id_field': 'DBInstanceIdentifier'
        }
    },
    'neptune': {
        'DBClusters': {
            'pattern': 'arn:aws:rds:{region}:{account_id}:cluster:{resource_id}',
            'id_field': 'DBClusterIdentifier'
        },
        'DBInstances': {
            'pattern': 'arn:aws:rds:{region}:{account_id}:db:{resource_id}',
            'id_field': 'DBInstanceIdentifier'
        }
    },
    'fsx': {
        'FileSystems': {
            'pattern': 'arn:aws:fsx:{region}:{account_id}:file-system/{resource_id}',
            'id_field': 'FileSystemId'
        },
        'Backups': {
            'pattern': 'arn:aws:fsx:{region}:{account_id}:backup/{resource_id}',
            'id_field': 'BackupId'
        }
    },
    'efs': {
        'FileSystems': {
            'pattern': 'arn:aws:elasticfilesystem:{region}:{account_id}:file-system/{resource_id}',
            'id_field': 'FileSystemId'
        }
    },
    'backup': {
        'BackupVaultList': {
            'pattern': 'arn:aws:backup:{region}:{account_id}:backup-vault:{resource_id}',
            'id_field': 'BackupVaultName'
        },
        'BackupPlansList': {
            'pattern': 'arn:aws:backup:{region}:{account_id}:backup-plan:{resource_id}',
            'id_field': 'BackupPlanId'
        }
    },
    'directconnect': {
        'connections': {
            'pattern': 'arn:aws:directconnect:{region}:{account_id}:dxcon/{resource_id}',
            'id_field': 'connectionId'
        },
        'virtualInterfaces': {
            'pattern': 'arn:aws:directconnect:{region}:{account_id}:dxvif/{resource_id}',
            'id_field': 'virtualInterfaceId'
        }
    },
    'globalaccelerator': {
        'Accelerators': {
            'pattern': 'arn:aws:globalaccelerator::{account_id}:accelerator/{resource_id}',
            'id_field': 'AcceleratorArn',
            'extract_id': True  # Extract ID from ARN
        }
    },
    'acm': {
        'CertificateSummaryList': {
            'pattern': 'arn:aws:acm:{region}:{account_id}:certificate/{resource_id}',
            'id_field': 'CertificateArn',
            'extract_id': True  # Extract ID from ARN
        }
    },
    'shield': {
        'Protections': {
            'pattern': 'arn:aws:shield::{account_id}:protection/{resource_id}',
            'id_field': 'Id'
        }
    },
    'network-firewall': {
        'Firewalls': {
            'pattern': 'arn:aws:network-firewall:{region}:{account_id}:firewall/{resource_id}',
            'id_field': 'FirewallName'
        },
        'FirewallPolicies': {
            'pattern': 'arn:aws:network-firewall:{region}:{account_id}:firewall-policy/{resource_id}',
            'id_field': 'Name'
        }
    },
    'macie2': {
        'items': {
            'pattern': 'arn:aws:macie2:{region}:{account_id}:classification-job/{resource_id}',
            'id_field': 'jobId'
        }
    },
    'mq': {
        'BrokerSummaries': {
            'pattern': 'arn:aws:mq:{region}:{account_id}:broker:{resource_id}',
            'id_field': 'BrokerId'
        }
    },
    'events': {
        'Rules': {
            'pattern': 'arn:aws:events:{region}:{account_id}:rule/{resource_id}',
            'id_field': 'Name'
        },
        'EventBuses': {
            'pattern': 'arn:aws:events:{region}:{account_id}:event-bus/{resource_id}',
            'id_field': 'Name'
        }
    },
    'stepfunctions': {
        'stateMachines': {
            'pattern': '{resource_id}',  # Already ARN
            'id_field': 'stateMachineArn'
        }
    },
    'kinesis': {
        'StreamNames': {
            'pattern': 'arn:aws:kinesis:{region}:{account_id}:stream/{resource_id}',
            'id_field': 'StreamName'
        }
    },
    'es': {
        'DomainNames': {
            'pattern': 'arn:aws:es:{region}:{account_id}:domain/{resource_id}',
            'id_field': 'DomainName'
        }
    },
    'athena': {
        'WorkGroups': {
            'pattern': 'arn:aws:athena:{region}:{account_id}:workgroup/{resource_id}',
            'id_field': 'Name'
        },
        'DataCatalogsSummary': {
            'pattern': 'arn:aws:athena:{region}:{account_id}:datacatalog/{resource_id}',
            'id_field': 'CatalogName'
        }
    },
    'glue': {
        'DatabaseList': {
            'pattern': 'arn:aws:glue:{region}:{account_id}:database/{resource_id}',
            'id_field': 'Name'
        },
        'Crawlers': {
            'pattern': 'arn:aws:glue:{region}:{account_id}:crawler/{resource_id}',
            'id_field': 'Name'
        },
        'Jobs': {
            'pattern': 'arn:aws:glue:{region}:{account_id}:job/{resource_id}',
            'id_field': 'Name'
        }
    },
    'sagemaker': {
        'NotebookInstances': {
            'pattern': 'arn:aws:sagemaker:{region}:{account_id}:notebook-instance/{resource_id}',
            'id_field': 'NotebookInstanceName'
        },
        'TrainingJobSummaries': {
            'pattern': 'arn:aws:sagemaker:{region}:{account_id}:training-job/{resource_id}',
            'id_field': 'TrainingJobName'
        },
        'Endpoints': {
            'pattern': 'arn:aws:sagemaker:{region}:{account_id}:endpoint/{resource_id}',
            'id_field': 'EndpointName'
        }
    },
    'comprehend': {
        'DocumentClassificationJobPropertiesList': {
            'pattern': 'arn:aws:comprehend:{region}:{account_id}:document-classification-job/{resource_id}',
            'id_field': 'JobId'
        },
        'EntityRecognizerPropertiesList': {
            'pattern': 'arn:aws:comprehend:{region}:{account_id}:entity-recognizer/{resource_id}',
            'id_field': 'EntityRecognizerArn',
            'extract_id': True  # Extract ID from ARN
        }
    },
    'iot': {
        'things': {
            'pattern': 'arn:aws:iot:{region}:{account_id}:thing/{resource_id}',
            'id_field': 'thingName'
        },
        'policies': {
            'pattern': 'arn:aws:iot:{region}:{account_id}:policy/{resource_id}',
            'id_field': 'policyName'
        },
        'certificates': {
            'pattern': 'arn:aws:iot:{region}:{account_id}:cert/{resource_id}',
            'id_field': 'certificateId'
        }
    },
    'greengrass': {
        'Groups': {
            'pattern': 'arn:aws:greengrass:{region}:{account_id}:/greengrass/groups/{resource_id}',
            'id_field': 'Id'
        }
    },
    'codecommit': {
        'repositories': {
            'pattern': 'arn:aws:codecommit:{region}:{account_id}:{resource_id}',
            'id_field': 'repositoryName'
        }
    },
    'codebuild': {
        'projects': {
            'pattern': 'arn:aws:codebuild:{region}:{account_id}:project/{resource_id}',
            'id_field': 'name'
        }
    },
    'codepipeline': {
        'pipelines': {
            'pattern': 'arn:aws:codepipeline:{region}:{account_id}:pipeline/{resource_id}',
            'id_field': 'name'
        }
    },
    'codeartifact': {
        'domains': {
            'pattern': 'arn:aws:codeartifact:{region}:{account_id}:domain/{resource_id}',
            'id_field': 'name'
        }
    },
    'mediaconvert': {
        'Queues': {
            'pattern': 'arn:aws:mediaconvert:{region}:{account_id}:queues/{resource_id}',
            'id_field': 'Name'
        },
        'Presets': {
            'pattern': 'arn:aws:mediaconvert:{region}:{account_id}:presets/{resource_id}',
            'id_field': 'Name'
        }
    },
    'medialive': {
        'Channels': {
            'pattern': 'arn:aws:medialive:{region}:{account_id}:channel:{resource_id}',
            'id_field': 'Id'
        },
        'Inputs': {
            'pattern': 'arn:aws:medialive:{region}:{account_id}:input:{resource_id}',
            'id_field': 'Id'
        }
    },
    'datasync': {
        'Tasks': {
            'pattern': 'arn:aws:datasync:{region}:{account_id}:task/{resource_id}',
            'id_field': 'TaskArn',
            'extract_id': True  # Extract ID from ARN
        },
        'Locations': {
            'pattern': 'arn:aws:datasync:{region}:{account_id}:location/{resource_id}',
            'id_field': 'LocationArn',
            'extract_id': True  # Extract ID from ARN
        }
    },
    'transfer': {
        'Servers': {
            'pattern': 'arn:aws:transfer:{region}:{account_id}:server/{resource_id}',
            'id_field': 'ServerId'
        }
    },
    'ce': {
        'CostCategoryReferences': {
            'pattern': 'arn:aws:ce::{account_id}:costcategory/{resource_id}',
            'id_field': 'CostCategoryArn',
            'extract_id': True  # Extract ID from ARN
        }
    },
    'savingsplans': {
        'savingsPlans': {
            'pattern': 'arn:aws:savingsplans::{account_id}:savingsplan/{resource_id}',
            'id_field': 'savingsPlanId'
        }
    },
    'workmail': {
        'OrganizationSummaries': {
            'pattern': 'arn:aws:workmail:{region}:{account_id}:organization/{resource_id}',
            'id_field': 'OrganizationId'
        }
    },
    'workspaces': {
        'Workspaces': {
            'pattern': 'arn:aws:workspaces:{region}:{account_id}:workspace/{resource_id}',
            'id_field': 'WorkspaceId'
        }
    },
    'bedrock': {
        'FoundationModels': {
            'pattern': 'arn:aws:bedrock:{region}::foundation-model/{resource_id}',
            'id_field': 'modelId'
        },
        'CustomModels': {
            'pattern': 'arn:aws:bedrock:{region}:{account_id}:custom-model/{resource_id}',
            'id_field': 'modelArn',
            'extract_id': True  # Extract ID from ARN
        },
        'jobSummaries': {
            'pattern': 'arn:aws:bedrock:{region}:{account_id}:evaluation-job/{resource_id}',
            'id_field': 'jobArn',
            'extract_id': True  # Extract ID from ARN
        },
        'provisionedModelSummaries': {
            'pattern': 'arn:aws:bedrock:{region}:{account_id}:provisioned-model/{resource_id}',
            'id_field': 'provisionedModelArn',
            'extract_id': True  # Extract ID from ARN
        }
    },
    'bedrock-agent': {
        'agents': {
            'pattern': 'arn:aws:bedrock:{region}:{account_id}:agent/{resource_id}',
            'id_field': 'agentId'
        },
        'knowledgeBases': {
            'pattern': 'arn:aws:bedrock:{region}:{account_id}:knowledge-base/{resource_id}',
            'id_field': 'knowledgeBaseId'
        }
    },
    'elbv2': {
        'LoadBalancers': {
            'pattern': 'arn:aws:elasticloadbalancing:{region}:{account_id}:loadbalancer/{resource_id}',
            'id_field': 'LoadBalancerArn',
            'extract_id': True  # Extract ID from ARN
        },
        'TargetGroups': {
            'pattern': 'arn:aws:elasticloadbalancing:{region}:{account_id}:targetgroup/{resource_id}',
            'id_field': 'TargetGroupArn',
            'extract_id': True  # Extract ID from ARN
        }
    },
    'elb': {
        'LoadBalancerDescriptions': {
            'pattern': 'arn:aws:elasticloadbalancing:{region}:{account_id}:loadbalancer/{resource_id}',
            'id_field': 'LoadBalancerName'
        }
    },
    'opensearch': {
        'Versions': {
            'pattern': 'arn:aws:opensearch:{region}:{account_id}:version/{resource_id}',
            'id_field': 'Version'
        },
        'OpensearchDomainNames': {
            'pattern': 'arn:aws:opensearch:{region}:{account_id}:domain/{resource_id}',
            'id_field': 'DomainName'
        },
        'ElasticSearchDomainNames': {
            'pattern': 'arn:aws:es:{region}:{account_id}:domain/{resource_id}',
            'id_field': 'DomainName'
        },
        'VpcEndpointSummaryList': {
            'pattern': 'arn:aws:opensearch:{region}:{account_id}:vpc-endpoint/{resource_id}',
            'id_field': 'VpcEndpointId'
        }
    },
    'opensearchserverless': {
        'collectionSummaries': {
            'pattern': 'arn:aws:aoss:{region}:{account_id}:collection/{resource_id}',
            'id_field': 'id'
        },
        'vpcEndpointSummaries': {
            'pattern': 'arn:aws:aoss:{region}:{account_id}:vpc-endpoint/{resource_id}',
            'id_field': 'id'
        },
        'EncryptionSecurityPolicyDetails': {
            'pattern': 'arn:aws:aoss:{region}:{account_id}:security-policy/{resource_id}',
            'id_field': 'name'
        },
        'NetworkSecurityPolicyDetails': {
            'pattern': 'arn:aws:aoss:{region}:{account_id}:security-policy/{resource_id}',
            'id_field': 'name'
        },
        'SAMLsecurityConfigDetails': {
            'pattern': 'arn:aws:aoss:{region}:{account_id}:security-config/{resource_id}',
            'id_field': 'id'
        },
        'IAMsecurityConfigDetails': {
            'pattern': 'arn:aws:aoss:{region}:{account_id}:security-config/{resource_id}',
            'id_field': 'id'
        },
        'accessPolicyDetails': {
            'pattern': 'arn:aws:aoss:{region}:{account_id}:access-policy/{resource_id}',
            'id_field': 'name'
        }
    }
}