# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Chunking Utilities - Intelligent splitting of infrastructure data for Bedrock processing
Updated to cover ALL 69 services from SERVICE_SCAN_FUNCTIONS
"""

import json
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class InfrastructureChunker:
    def __init__(self):
        # COMPREHENSIVE service categorization covering ALL 69 services
        self.service_groups = {
            "compute": {
                "services": ["ec2", "lambda", "ecs", "eks", "batch", "lightsail", "elasticbeanstalk"],
                "focus": "Compute resources, serverless functions, container orchestration, and application platforms",
                "priority": 1
            },
            "storage": {
                "services": ["s3", "efs", "fsx", "backup", "datasync", "transfer"],
                "focus": "Storage systems, file systems, backup solutions, and data transfer services",
                "priority": 2
            },
            "database": {
                "services": ["rds", "dynamodb", "elasticache", "neptune", "docdb", "redshift"],
                "focus": "Database systems, caching, data warehousing, and analytics storage",
                "priority": 3
            },
            "security": {
                "services": ["iam", "kms", "secretsmanager", "acm", "guardduty", "macie2", "shield", "waf", "wafv2", "network-firewall"],
                "focus": "Identity management, encryption, secrets, security monitoring, and threat protection",
                "priority": 4
            },
            "networking": {
                "services": ["apigateway", "elb", "elbv2", "cloudfront", "route53", "directconnect", "globalaccelerator"],
                "focus": "API management, load balancing, CDN, DNS, and network connectivity",
                "priority": 5
            },
            "analytics": {
                "services": ["athena", "glue", "kinesis", "es", "opensearch", "opensearchserverless"],
                "focus": "Data analytics, search engines, data processing, and ETL services",
                "priority": 6
            },
            "ai": {
                "services": ["sagemaker", "comprehend", "bedrock", "bedrock-agent"],
                "focus": "Machine learning, AI services, natural language processing, and generative AI",
                "priority": 7
            },
            "devops_automation": {
                "services": ["cloudformation", "codecommit", "codebuild", "codepipeline", "codeartifact", "ecr", "ssm"],
                "focus": "Infrastructure as code, CI/CD pipelines, container registries, and systems management",
                "priority": 8
            },
            "monitoring_management": {
                "services": ["cloudwatch", "events", "stepfunctions", "sns", "sqs", "organizations", "resourcegroupstaggingapi"],
                "focus": "Monitoring, event processing, workflow orchestration, messaging, and resource management",
                "priority": 9
            },
            "media_iot": {
                "services": ["mediaconvert", "medialive", "iot", "greengrass"],
                "focus": "Media processing, IoT device management, and edge computing",
                "priority": 10
            },
            "enterprise_productivity": {
                "services": ["workmail", "workspaces", "mq"],
                "focus": "Enterprise productivity, virtual desktops, and message queuing",
                "priority": 11
            },
            "cost_billing": {
                "services": ["ce", "savingsplans"],
                "focus": "Cost management, billing analysis, and savings optimization",
                "priority": 12
            }
        }
        
        # Token estimation (rough approximation)
        self.chars_per_token = 4
        self.max_tokens_per_chunk = 150000  # Leave buffer for prompt
        
    def validate_service_coverage(self):
        """Validate that all services from constants are covered"""
        try:
            from constants import SERVICE_SCAN_FUNCTIONS
            all_services = set(SERVICE_SCAN_FUNCTIONS.keys())
            
            chunked_services = set()
            for group_config in self.service_groups.values():
                chunked_services.update(group_config["services"])
            
            missing_services = all_services - chunked_services
            covered_services = all_services & chunked_services
            
            logger.info(f"Service coverage: {len(covered_services)}/{len(all_services)} services covered")
            
            if missing_services:
                logger.warning(f"Missing services in chunking: {sorted(missing_services)}")
                return False, missing_services
            else:
                logger.info("✅ All services covered in chunking logic")
                return True, set()
                
        except ImportError:
            logger.warning("Could not import SERVICE_SCAN_FUNCTIONS for validation")
            return True, set()  # Assume OK if can't validate
    
    def estimate_tokens(self, data):
        """Estimate token count for data"""
        json_str = json.dumps(data, separators=(',', ':'))
        return len(json_str) // self.chars_per_token
    
    def create_chunks(self, infrastructure_data):
        """
        Create intelligent chunks from infrastructure data
        """
        logger.info("Creating intelligent chunks from infrastructure data...")
        
        # Validate service coverage first
        coverage_ok, missing = self.validate_service_coverage()
        if not coverage_ok:
            logger.warning(f"Some services may not be analyzed: {missing}")
        
        chunks = {}
        metadata = self._extract_metadata(infrastructure_data)
        
        # Create service-based chunks
        for group_name, group_config in self.service_groups.items():
            chunk_data = self._create_service_chunk(
                infrastructure_data, 
                group_config["services"], 
                group_name,
                group_config["focus"]
            )
            
            if chunk_data["resources"]:  # Only include non-empty chunks
                # Validate chunk size
                token_count = self.estimate_tokens(chunk_data)
                if token_count > self.max_tokens_per_chunk:
                    # Split large chunks further
                    sub_chunks = self._split_large_chunk(chunk_data, group_name)
                    chunks.update(sub_chunks)
                else:
                    chunks[group_name] = chunk_data
                    logger.info(f"Created {group_name} chunk: {token_count:,} tokens, {len(chunk_data['resources'])} resource groups")
        
        # Handle any uncategorized services (fallback)
        uncategorized_chunk = self._create_uncategorized_chunk(infrastructure_data, chunks)
        if uncategorized_chunk and uncategorized_chunk["resources"]:
            chunks["uncategorized"] = uncategorized_chunk
            logger.warning(f"Created uncategorized chunk with {len(uncategorized_chunk['resources'])} resource groups")
        
        # Add metadata to all chunks
        for chunk_name in chunks:
            chunks[chunk_name]["metadata"] = metadata
            chunks[chunk_name]["chunk_info"] = {
                "chunk_name": chunk_name,
                "total_chunks": len(chunks),
                "analysis_focus": self.service_groups.get(chunk_name, {}).get("focus", "General analysis")
            }
        
        logger.info(f"Created {len(chunks)} chunks for analysis")
        return chunks
    
    def _create_uncategorized_chunk(self, infrastructure_data, existing_chunks):
        """Create a chunk for any services not covered in existing chunks"""
        # Get all services already covered
        covered_services = set()
        for chunk_data in existing_chunks.values():
            covered_services.update(chunk_data.get("services_included", []))
        
        # Find uncategorized resources
        uncategorized_resources = []
        for resource_group in infrastructure_data.get("resources", []):
            service = resource_group.get("service")
            if service and service not in covered_services:
                uncategorized_resources.append(resource_group)
        
        if uncategorized_resources:
            return {
                "chunk_type": "uncategorized",
                "focus_area": "Uncategorized services and miscellaneous resources",
                "services_included": list(set(rg.get("service") for rg in uncategorized_resources)),
                "resources": uncategorized_resources,
                "resource_count": sum(rg.get("resource_count", 0) for rg in uncategorized_resources)
            }
        
        return None
    
    def _extract_metadata(self, infrastructure_data):
        """Extract account-level metadata for context"""
        return {
            "account_id": infrastructure_data.get("account_id", "unknown"),
            "scan_time": infrastructure_data.get("scan_time", "unknown"),
            "regions_scanned": infrastructure_data.get("regions_scanned", []),
            "services_scanned": infrastructure_data.get("services_scanned", []),
            "total_resource_count": self._count_total_resources(infrastructure_data)
        }
    
    def _create_service_chunk(self, infrastructure_data, target_services, chunk_name, focus):
        """Create a chunk for specific services"""
        chunk_resources = []
        
        for resource_group in infrastructure_data.get("resources", []):
            service = resource_group.get("service")
            if service in target_services:
                chunk_resources.append(resource_group)
        
        return {
            "chunk_type": chunk_name,
            "focus_area": focus,
            "services_included": target_services,
            "resources": chunk_resources,
            "resource_count": sum(rg.get("resource_count", 0) for rg in chunk_resources)
        }
    
    def _split_large_chunk(self, chunk_data, base_name):
        """Split a large chunk into smaller pieces by region"""
        logger.warning(f"Splitting large {base_name} chunk into smaller pieces")
        
        # Group by region
        region_groups = {}
        for resource_group in chunk_data["resources"]:
            region = resource_group.get("region", "unknown")
            if region not in region_groups:
                region_groups[region] = []
            region_groups[region].append(resource_group)
        
        # Create sub-chunks
        sub_chunks = {}
        for region, resources in region_groups.items():
            sub_chunk_name = f"{base_name}_{region.replace('-', '_')}"
            sub_chunks[sub_chunk_name] = {
                "chunk_type": sub_chunk_name,
                "focus_area": f"{chunk_data['focus_area']} in {region}",
                "services_included": chunk_data["services_included"],
                "resources": resources,
                "resource_count": sum(rg.get("resource_count", 0) for rg in resources),
                "region_specific": True
            }
        
        return sub_chunks
    
    def _count_total_resources(self, infrastructure_data):
        """Count total resources across all services"""
        total = 0
        for resource_group in infrastructure_data.get("resources", []):
            total += resource_group.get("resource_count", 0)
        return total
    
    def get_chunk_summary(self, chunks):
        """Get summary information about created chunks"""
        summary = {
            "total_chunks": len(chunks),
            "chunks": {}
        }
        
        for chunk_name, chunk_data in chunks.items():
            summary["chunks"][chunk_name] = {
                "services": len(chunk_data.get("services_included", [])),
                "resource_groups": len(chunk_data.get("resources", [])),
                "total_resources": chunk_data.get("resource_count", 0),
                "estimated_tokens": self.estimate_tokens(chunk_data),
                "focus_area": chunk_data.get("focus_area", "")
            }
        
        return summary

class ChunkPromptGenerator:
    def __init__(self):
        self.base_context = """You are a senior AWS Solutions Architect and Cloud Security Expert with 15+ years of experience analyzing enterprise AWS infrastructures.

IMPORTANT: You are analyzing ONE PART of a larger infrastructure. Other parts will be analyzed separately and combined later.

Your expertise includes:
- AWS Well-Architected Framework (Security, Reliability, Performance, Cost Optimization, Operational Excellence)
- Enterprise security best practices and compliance frameworks
- Cost optimization and resource right-sizing
- Performance tuning and scalability planning
- Infrastructure automation and DevOps practices

ANALYSIS REQUIREMENTS:
1. Focus ONLY on the services provided in this chunk
2. Provide detailed, specific findings with resource names and ARNs
3. Include actionable recommendations with implementation steps
4. Use severity levels: Critical, High, Medium, Low
5. Estimate cost impact where relevant
6. Consider cross-service relationships within this chunk
7. Maintain professional, expert-level analysis
"""

        # Updated chunk-specific prompts to cover all service categories
        self.chunk_specific_prompts = {
            "compute": """
COMPUTE INFRASTRUCTURE ANALYSIS FOCUS:
Analyze EC2 instances, Lambda functions, container services, batch processing, and application platforms.

Key areas to examine:
- Instance sizing and utilization patterns
- Auto-scaling configurations and policies
- Lambda function performance, memory allocation, and timeout settings
- Container orchestration and resource allocation
- Application platform configurations (Elastic Beanstalk)
- Compute cost optimization opportunities
- Performance bottlenecks and scaling limitations
- Security configurations (instance profiles, security groups)

Provide specific recommendations for:
- Right-sizing opportunities with cost impact
- Performance improvements
- Security hardening
- Operational efficiency
""",
            
            "storage": """
STORAGE INFRASTRUCTURE ANALYSIS FOCUS:
Analyze S3 buckets, EFS file systems, FSx, backup solutions, and data transfer services.

Key areas to examine:
- Storage classes and lifecycle policies
- Access patterns and cost optimization
- Backup strategies and retention policies
- Data encryption and security configurations
- Cross-region replication and disaster recovery
- Storage performance and throughput
- Access controls and bucket policies
- Data transfer optimization

Provide specific recommendations for:
- Storage class optimization with cost savings
- Security improvements (encryption, access controls)
- Backup and disaster recovery enhancements
- Performance optimization
""",
            
            "database": """
DATABASE INFRASTRUCTURE ANALYSIS FOCUS:
Analyze RDS instances, DynamoDB tables, ElastiCache, Neptune, DocumentDB, and Redshift.

Key areas to examine:
- Database sizing and performance metrics
- Backup and recovery configurations
- Security settings (encryption, access controls)
- High availability and disaster recovery
- Cost optimization opportunities
- Performance tuning and indexing
- Monitoring and alerting setup
- Data warehousing and analytics optimization

Provide specific recommendations for:
- Database right-sizing and cost optimization
- Performance improvements
- Security hardening
- Backup and recovery enhancements
""",
            
            "security": """
SECURITY INFRASTRUCTURE ANALYSIS FOCUS:
Analyze IAM policies, KMS keys, secrets management, security monitoring, and threat protection services.

Key areas to examine:
- IAM policy analysis and least privilege principles
- Resource-based policy optimization
- Encryption key management and rotation
- Secrets management best practices
- Security monitoring and compliance (GuardDuty, Macie)
- Threat protection and WAF configurations
- Network security and firewall rules
- Access patterns and unused permissions

Provide specific recommendations for:
- Policy optimization and security hardening
- Compliance improvements
- Access control enhancements
- Security monitoring setup
""",
            
            "networking": """
NETWORKING INFRASTRUCTURE ANALYSIS FOCUS:
Analyze API Gateway, load balancers, CloudFront, Route53, DirectConnect, and network acceleration.

Key areas to examine:
- API Gateway configurations and performance
- Load balancer setup and health checks
- CDN configuration and caching strategies
- DNS configuration and routing
- Network connectivity and hybrid setups
- Network security and access controls
- Performance and latency optimization
- Cost optimization for data transfer

Provide specific recommendations for:
- Performance improvements
- Cost optimization
- Security enhancements
- Reliability improvements
""",
            
            "analytics": """
ANALYTICS INFRASTRUCTURE ANALYSIS FOCUS:
Analyze Athena, Glue, Kinesis, OpenSearch, and OpenSearch Serverless services.

Key areas to examine:
- Data processing and ETL pipeline efficiency
- Search and analytics performance optimization
- Data lake and analytics architecture design
- Query performance and cost optimization
- Real-time data streaming and processing
- Data indexing and search capabilities

Provide specific recommendations for:
- Analytics performance optimization
- ETL pipeline improvements
- Search performance tuning
- Cost reduction strategies for data processing
- Data architecture best practices
- Security and access controls for analytics services
""",
            
            "ai": """
AI AND MACHINE LEARNING INFRASTRUCTURE ANALYSIS FOCUS:
Analyze SageMaker, Comprehend, Bedrock, and Bedrock Agent services.

Key areas to examine:
- Machine learning model deployment and scaling
- AI service usage and optimization patterns
- Model training and inference infrastructure
- Generative AI implementation and costs
- ML workflow automation and efficiency
- AI service integration and orchestration

Provide specific recommendations for:
- ML/AI workflow improvements
- Model deployment optimization
- Cost reduction for AI services
- Performance tuning for ML workloads
- AI security and governance
- Generative AI best practices
""",
            
            "devops_automation": """
DEVOPS AND AUTOMATION INFRASTRUCTURE ANALYSIS FOCUS:
Analyze CloudFormation, CodeCommit, CodeBuild, CodePipeline, ECR, and Systems Manager.

Key areas to examine:
- Infrastructure as Code best practices
- CI/CD pipeline efficiency and security
- Container registry management
- Systems management and automation
- Deployment strategies and rollback procedures
- Security scanning and compliance in pipelines
- Cost optimization for development workflows
- Operational efficiency and automation opportunities

Provide specific recommendations for:
- DevOps process improvements
- Security integration in CI/CD
- Cost optimization
- Automation enhancements
""",
            
            "monitoring_management": """
MONITORING AND MANAGEMENT INFRASTRUCTURE ANALYSIS FOCUS:
Analyze CloudWatch, EventBridge, Step Functions, SNS, SQS, and organizational management.

Key areas to examine:
- Monitoring and alerting configurations
- Event-driven architecture patterns
- Workflow orchestration efficiency
- Messaging and notification systems
- Resource organization and tagging
- Operational dashboards and metrics
- Cost monitoring and optimization
- Incident response and automation

Provide specific recommendations for:
- Monitoring improvements
- Operational efficiency
- Cost visibility enhancements
- Automation opportunities
""",
            
            "media_iot": """
MEDIA AND IOT INFRASTRUCTURE ANALYSIS FOCUS:
Analyze MediaConvert, MediaLive, IoT Core, and Greengrass services.

Key areas to examine:
- Media processing workflows and costs
- IoT device management and security
- Edge computing configurations
- Data ingestion and processing patterns
- Security for IoT and media services
- Cost optimization for media workloads
- Performance and scalability

Provide specific recommendations for:
- Media workflow optimization
- IoT security improvements
- Cost reduction strategies
- Performance enhancements
""",
            
            "enterprise_productivity": """
ENTERPRISE PRODUCTIVITY INFRASTRUCTURE ANALYSIS FOCUS:
Analyze WorkMail, WorkSpaces, and MQ services.

Key areas to examine:
- Virtual desktop infrastructure optimization
- Email and collaboration security
- Message queuing performance and reliability
- User access and security configurations
- Cost optimization for productivity services
- Performance and user experience
- Integration with enterprise systems

Provide specific recommendations for:
- Productivity service optimization
- Security improvements
- Cost management
- User experience enhancements
""",
            
            "cost_billing": """
COST AND BILLING INFRASTRUCTURE ANALYSIS FOCUS:
Analyze Cost Explorer, Savings Plans, and cost management services.

Key areas to examine:
- Cost allocation and tracking
- Savings opportunities and Reserved Instances
- Budget management and alerting
- Cost optimization recommendations
- Billing analysis and forecasting
- Resource utilization patterns
- Cost governance and controls

Provide specific recommendations for:
- Cost reduction strategies
- Savings plan optimization
- Budget and governance improvements
- Cost visibility enhancements
""",
            
            "uncategorized": """
UNCATEGORIZED SERVICES ANALYSIS FOCUS:
Analyze miscellaneous and specialized AWS services not covered in other categories.

Key areas to examine:
- Service-specific configurations and best practices
- Security and access controls
- Cost optimization opportunities
- Performance and reliability
- Integration with other services
- Operational considerations

Provide specific recommendations for:
- Service optimization
- Security improvements
- Cost management
- Operational efficiency
"""
        }
    
    def generate_chunk_prompt(self, chunk_data, custom_prompt=None, analysis_type="comprehensive"):
        """Generate specialized prompt for a specific chunk"""
        
        chunk_type = chunk_data.get("chunk_type", "general")
        chunk_info = chunk_data.get("chunk_info", {})
        metadata = chunk_data.get("metadata", {})
        
        # Get chunk-specific prompt
        specific_prompt = self.chunk_specific_prompts.get(
            chunk_type.split('_')[0],  # Handle region-specific chunks like "compute_us_east_1"
            self.chunk_specific_prompts.get(chunk_type, "Analyze the provided AWS infrastructure components with focus on security, cost, and performance.")
        )
        
        # Build the complete prompt
        prompt = f"""{self.base_context}

CHUNK CONTEXT:
- Chunk: {chunk_info.get('chunk_name', chunk_type)} ({chunk_info.get('analysis_focus', 'General analysis')})
- Part {chunk_info.get('chunk_name', '1')} of {chunk_info.get('total_chunks', 'multiple')} total chunks
- Account: {metadata.get('account_id', 'unknown')}
- Regions: {', '.join(metadata.get('regions_scanned', []))}
- Total Infrastructure Resources: {metadata.get('total_resource_count', 'unknown')}

{specific_prompt}

ANALYSIS TYPE: {analysis_type.upper()}
"""

        if custom_prompt:
            prompt += f"\nADDITIONAL REQUIREMENTS:\n{custom_prompt}\n"

        prompt += f"""
INFRASTRUCTURE DATA FOR THIS CHUNK:
```json
{json.dumps(chunk_data, indent=2)}
```

Generate a detailed Markdown analysis focusing on this chunk's services. Remember, this is part of a larger analysis that will be combined with other chunks.
"""

        return prompt
        
    def estimate_tokens(self, data):
        """Estimate token count for data"""
        json_str = json.dumps(data, separators=(',', ':'))
        return len(json_str) // self.chars_per_token
    
    def create_chunks(self, infrastructure_data):
        """
        Create intelligent chunks from infrastructure data
        """
        logger.info("Creating intelligent chunks from infrastructure data...")
        
        chunks = {}
        metadata = self._extract_metadata(infrastructure_data)
        
        # Create service-based chunks
        for group_name, group_config in self.service_groups.items():
            chunk_data = self._create_service_chunk(
                infrastructure_data, 
                group_config["services"], 
                group_name,
                group_config["focus"]
            )
            
            if chunk_data["resources"]:  # Only include non-empty chunks
                # Validate chunk size
                token_count = self.estimate_tokens(chunk_data)
                if token_count > self.max_tokens_per_chunk:
                    # Split large chunks further
                    sub_chunks = self._split_large_chunk(chunk_data, group_name)
                    chunks.update(sub_chunks)
                else:
                    chunks[group_name] = chunk_data
                    logger.info(f"Created {group_name} chunk: {token_count:,} tokens, {len(chunk_data['resources'])} resource groups")
        
        # Add metadata to all chunks
        for chunk_name in chunks:
            chunks[chunk_name]["metadata"] = metadata
            chunks[chunk_name]["chunk_info"] = {
                "chunk_name": chunk_name,
                "total_chunks": len(chunks),
                "analysis_focus": self.service_groups.get(chunk_name, {}).get("focus", "General analysis")
            }
        
        logger.info(f"Created {len(chunks)} chunks for analysis")
        return chunks
    
    def _extract_metadata(self, infrastructure_data):
        """Extract account-level metadata for context"""
        return {
            "account_id": infrastructure_data.get("account_id", "unknown"),
            "scan_time": infrastructure_data.get("scan_time", "unknown"),
            "regions_scanned": infrastructure_data.get("regions_scanned", []),
            "services_scanned": infrastructure_data.get("services_scanned", []),
            "total_resource_count": self._count_total_resources(infrastructure_data)
        }
    
    def _create_service_chunk(self, infrastructure_data, target_services, chunk_name, focus):
        """Create a chunk for specific services"""
        chunk_resources = []
        
        for resource_group in infrastructure_data.get("resources", []):
            service = resource_group.get("service")
            if service in target_services:
                chunk_resources.append(resource_group)
        
        return {
            "chunk_type": chunk_name,
            "focus_area": focus,
            "services_included": target_services,
            "resources": chunk_resources,
            "resource_count": sum(rg.get("resource_count", 0) for rg in chunk_resources)
        }
    
    def _split_large_chunk(self, chunk_data, base_name):
        """Split a large chunk into smaller pieces by region"""
        logger.warning(f"Splitting large {base_name} chunk into smaller pieces")
        
        # Group by region
        region_groups = {}
        for resource_group in chunk_data["resources"]:
            region = resource_group.get("region", "unknown")
            if region not in region_groups:
                region_groups[region] = []
            region_groups[region].append(resource_group)
        
        # Create sub-chunks
        sub_chunks = {}
        for region, resources in region_groups.items():
            sub_chunk_name = f"{base_name}_{region.replace('-', '_')}"
            sub_chunks[sub_chunk_name] = {
                "chunk_type": sub_chunk_name,
                "focus_area": f"{chunk_data['focus_area']} in {region}",
                "services_included": chunk_data["services_included"],
                "resources": resources,
                "resource_count": sum(rg.get("resource_count", 0) for rg in resources),
                "region_specific": True
            }
        
        return sub_chunks
    
    def _count_total_resources(self, infrastructure_data):
        """Count total resources across all services"""
        total = 0
        for resource_group in infrastructure_data.get("resources", []):
            total += resource_group.get("resource_count", 0)
        return total
    
    def get_chunk_summary(self, chunks):
        """Get summary information about created chunks"""
        summary = {
            "total_chunks": len(chunks),
            "chunks": {}
        }
        
        for chunk_name, chunk_data in chunks.items():
            summary["chunks"][chunk_name] = {
                "services": len(chunk_data.get("services_included", [])),
                "resource_groups": len(chunk_data.get("resources", [])),
                "total_resources": chunk_data.get("resource_count", 0),
                "estimated_tokens": self.estimate_tokens(chunk_data),
                "focus_area": chunk_data.get("focus_area", "")
            }
        
        return summary

class ChunkPromptGenerator:
    def __init__(self):
        self.base_context = """You are a senior AWS Solutions Architect and Cloud Security Expert with 15+ years of experience analyzing enterprise AWS infrastructures.

IMPORTANT: You are analyzing ONE PART of a larger infrastructure. Other parts will be analyzed separately and combined later.

Your expertise includes:
- AWS Well-Architected Framework (Security, Reliability, Performance, Cost Optimization, Operational Excellence)
- Enterprise security best practices and compliance frameworks
- Cost optimization and resource right-sizing
- Performance tuning and scalability planning
- Infrastructure automation and DevOps practices

ANALYSIS REQUIREMENTS:
1. Focus ONLY on the services provided in this chunk
2. Provide detailed, specific findings with resource names and ARNs
3. Include actionable recommendations with implementation steps
4. Use severity levels: Critical, High, Medium, Low
5. Estimate cost impact where relevant
6. Consider cross-service relationships within this chunk
7. Maintain professional, expert-level analysis
"""

        self.chunk_specific_prompts = {
            "compute": """
COMPUTE INFRASTRUCTURE ANALYSIS FOCUS:
Analyze EC2 instances, Lambda functions, container services, and batch processing.

Key areas to examine:
- Instance sizing and utilization patterns
- Auto-scaling configurations and policies
- Lambda function performance, memory allocation, and timeout settings
- Container orchestration and resource allocation
- Compute cost optimization opportunities
- Performance bottlenecks and scaling limitations
- Security configurations (instance profiles, security groups)

Provide specific recommendations for:
- Right-sizing opportunities with cost impact
- Performance improvements
- Security hardening
- Operational efficiency
""",
            
            "storage": """
STORAGE INFRASTRUCTURE ANALYSIS FOCUS:
Analyze S3 buckets, EFS file systems, FSx, and backup solutions.

Key areas to examine:
- Storage classes and lifecycle policies
- Access patterns and cost optimization
- Backup strategies and retention policies
- Data encryption and security configurations
- Cross-region replication and disaster recovery
- Storage performance and throughput
- Access controls and bucket policies

Provide specific recommendations for:
- Storage class optimization with cost savings
- Security improvements (encryption, access controls)
- Backup and disaster recovery enhancements
- Performance optimization
""",
            
            "database": """
DATABASE INFRASTRUCTURE ANALYSIS FOCUS:
Analyze RDS instances, DynamoDB tables, ElastiCache, and other database services.

Key areas to examine:
- Database sizing and performance metrics
- Backup and recovery configurations
- Security settings (encryption, access controls)
- High availability and disaster recovery
- Cost optimization opportunities
- Performance tuning and indexing
- Monitoring and alerting setup

Provide specific recommendations for:
- Database right-sizing and cost optimization
- Performance improvements
- Security hardening
- Backup and recovery enhancements
""",
            
            "security": """
SECURITY INFRASTRUCTURE ANALYSIS FOCUS:
Analyze IAM policies, KMS keys, secrets management, and security services.

Key areas to examine:
- IAM policy analysis and least privilege principles
- Resource-based policy optimization
- Encryption key management and rotation
- Secrets management best practices
- Security monitoring and compliance
- Access patterns and unused permissions
- Cross-account access and trust relationships

Provide specific recommendations for:
- Policy optimization and security hardening
- Compliance improvements
- Access control enhancements
- Security monitoring setup
""",
            
            "networking": """
NETWORKING INFRASTRUCTURE ANALYSIS FOCUS:
Analyze API Gateway, load balancers, CloudFront, Route53, and network connectivity.

Key areas to examine:
- API Gateway configurations and performance
- Load balancer setup and health checks
- CDN configuration and caching strategies
- DNS configuration and routing
- Network security and access controls
- Performance and latency optimization
- Cost optimization for data transfer

Provide specific recommendations for:
- Performance improvements
- Cost optimization
- Security enhancements
- Reliability improvements
"""
        }
    
    def generate_chunk_prompt(self, chunk_data, custom_prompt=None, analysis_type="comprehensive"):
        """Generate specialized prompt for a specific chunk"""
        
        chunk_type = chunk_data.get("chunk_type", "general")
        chunk_info = chunk_data.get("chunk_info", {})
        metadata = chunk_data.get("metadata", {})
        
        # Get chunk-specific prompt
        specific_prompt = self.chunk_specific_prompts.get(
            chunk_type.split('_')[0],  # Handle region-specific chunks like "compute_us_east_1"
            "Analyze the provided AWS infrastructure components with focus on security, cost, and performance."
        )
        
        # Build the complete prompt
        prompt = f"""{self.base_context}

CHUNK CONTEXT:
- Chunk: {chunk_info.get('chunk_name', chunk_type)} ({chunk_info.get('analysis_focus', 'General analysis')})
- Part {chunk_info.get('chunk_name', '1')} of {chunk_info.get('total_chunks', 'multiple')} total chunks
- Account: {metadata.get('account_id', 'unknown')}
- Regions: {', '.join(metadata.get('regions_scanned', []))}
- Total Infrastructure Resources: {metadata.get('total_resource_count', 'unknown')}

{specific_prompt}

ANALYSIS TYPE: {analysis_type.upper()}
"""

        if custom_prompt:
            prompt += f"\nADDITIONAL REQUIREMENTS:\n{custom_prompt}\n"

        prompt += f"""
INFRASTRUCTURE DATA FOR THIS CHUNK:
```json
{json.dumps(chunk_data, indent=2)}
```

Generate a detailed Markdown analysis focusing on this chunk's services. Remember, this is part of a larger analysis that will be combined with other chunks.
"""

        return prompt
