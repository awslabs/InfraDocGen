# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from fastapi import APIRouter, HTTPException, File, UploadFile, Form
from models.request_models import ScanRequest
from services.discovery_service import scan_resources
from services.bedrock_service import BedrockAnalysisService
from services.cache_service import InfrastructureCacheService
import json
import time
import logging

logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/infra-doc/generate")
def run_scan(request: ScanRequest):
    """
    Generate AWS infrastructure documentation with resource-based policies
    """
    try:
        result = scan_resources(
            aws_access_key_id=request.aws_access_key_id,
            aws_secret_access_key=request.aws_secret_access_key,
            aws_session_token=request.aws_session_token,
            target_account=request.target_account,
            role_name=request.role_name
        )
        return result
    except Exception as e:
        return {
            "error": "Scan failed",
            "message": str(e),
            "account_id": "unknown",
            "scan_time": "unknown",
            "regions_scanned": [],
            "services_scanned": [],
            "resources": [],
            "resource_counts": {}
        }

@router.post("/infra-analysis/generate-report-from-file")
async def generate_report_from_file(
    file: UploadFile = File(..., description="JSON file from /infra-doc/generate endpoint"),
    custom_prompt: str = Form(None, description="Additional analysis instructions"),
    analysis_type: str = Form("comprehensive", description="Type of analysis: comprehensive, security, cost, performance"),
    aws_access_key_id: str = Form(None, description="AWS Access Key ID for Bedrock"),
    aws_secret_access_key: str = Form(None, description="AWS Secret Access Key for Bedrock"),
    aws_session_token: str = Form(None, description="AWS Session Token for Bedrock"),
    bedrock_region: str = Form("us-east-1", description="AWS region for Bedrock API")
):
    """
    Generate comprehensive AWS infrastructure analysis report from uploaded JSON file using Bedrock Claude (with intelligent caching)
    
    BEST FOR LARGE FILES (2MB+): Upload the JSON file from /infra-doc/generate 
    along with your custom prompt to generate detailed Markdown analysis report.
    
    This endpoint uses intelligent caching and chunking to handle large infrastructure files efficiently.
    """
    start_time = time.time()
    
    try:
        from session import get_aws_session
        
        # Validate file type
        if not file.filename.endswith('.json'):
            return {
                "error": "Invalid file type",
                "message": "Please upload a JSON file (.json extension required)"
            }
        
        # Read and parse the uploaded JSON file
        try:
            file_content = await file.read()
            infrastructure_data = json.loads(file_content.decode('utf-8'))
        except json.JSONDecodeError as e:
            return {
                "error": "Invalid JSON file",
                "message": f"Could not parse JSON file: {str(e)}"
            }
        except Exception as e:
            return {
                "error": "File read error",
                "message": f"Could not read uploaded file: {str(e)}"
            }
        
        # Validate that it's infrastructure data (basic check)
        if not isinstance(infrastructure_data, dict) or 'account_id' not in infrastructure_data:
            return {
                "error": "Invalid infrastructure data",
                "message": "The uploaded JSON does not appear to be from /infra-doc/generate endpoint"
            }
        
        # Validate analysis type
        valid_analysis_types = ['comprehensive', 'security', 'cost', 'performance']
        if analysis_type not in valid_analysis_types:
            return {
                "error": "Invalid analysis type",
                "message": f"Analysis type must be one of: {', '.join(valid_analysis_types)}"
            }
        
        # Initialize cache service
        cache_service = InfrastructureCacheService()
        
        # Check cache first
        logger.info(f"🔍 Checking cache for AI report (type: {analysis_type})")
        cache_hit, cached_report = cache_service.check_ai_report_cache(infrastructure_data, analysis_type)
        
        if cache_hit and cached_report:
            # Cache hit - return cached result
            processing_time = round((time.time() - start_time) * 1000, 2)
            
            # Update cache metadata with current request info
            cached_report['cache_metadata'].update({
                'cache_hit': True,
                'processing_time_ms': processing_time,
                'served_from_cache': True
            })
            
            # Add file metadata
            cached_report['file_metadata'] = {
                'filename': file.filename,
                'file_size_mb': round(len(file_content) / (1024 * 1024), 2),
                'upload_method': 'file_upload_cached'
            }
            
            logger.info(f"🚀 Returning cached AI report in {processing_time}ms")
            return cached_report
        
        # Cache miss - generate new report
        logger.info(f"📝 Cache miss - generating new AI report via Bedrock")
        
        # Get AWS session for Bedrock
        session = get_aws_session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token
        )
        
        # Initialize Bedrock service
        bedrock_service = BedrockAnalysisService(session, region=bedrock_region)
        
        # Generate the analysis report
        report = bedrock_service.generate_infrastructure_report(
            infrastructure_data=infrastructure_data,
            custom_prompt=custom_prompt,
            analysis_type=analysis_type
        )
        
        # Cache the generated report
        cache_success = cache_service.cache_ai_report(infrastructure_data, analysis_type, report)
        
        # Add processing metadata
        processing_time = round((time.time() - start_time) * 1000, 2)
        
        # Add cache metadata to response
        report['cache_metadata'] = {
            'cache_hit': False,
            'processing_time_ms': processing_time,
            'served_from_cache': False,
            'cached_successfully': cache_success,
            'analysis_type': analysis_type
        }
        
        # Add file metadata to response
        report['file_metadata'] = {
            'filename': file.filename,
            'file_size_mb': round(len(file_content) / (1024 * 1024), 2),
            'upload_method': 'file_upload_generated'
        }
        
        logger.info(f"✅ Generated and cached new AI report in {processing_time}ms")
        return report
        
    except Exception as e:
        processing_time = round((time.time() - start_time) * 1000, 2)
        logger.error(f"❌ AI analysis failed after {processing_time}ms: {str(e)}")
        return {
            "error": "Analysis failed",
            "message": str(e),
            "analysis_type": analysis_type,
            "processing_time_ms": processing_time
        }



@router.post("/resource-mapping/generate-from-infra-data")
async def generate_resource_mapping_from_infra_data(
    file: UploadFile = File(..., description="JSON file from /infra-doc/generate endpoint"),
    custom_prompt: str = Form(None, description="Additional mapping instructions"),
    aws_access_key_id: str = Form(None, description="AWS Access Key ID for Bedrock (optional - uses environment if not provided)"),
    aws_secret_access_key: str = Form(None, description="AWS Secret Access Key for Bedrock (optional - uses environment if not provided)"),
    aws_session_token: str = Form(None, description="AWS Session Token for Bedrock (optional)"),
    bedrock_region: str = Form("us-east-1", description="AWS region for Bedrock API")
):
    """
    Generate comprehensive AWS resource dependency mapping using Bedrock Claude (with intelligent caching)
    
    Takes the JSON response from /infra-doc/generate and generates resource mapping:
    1. Checks cache for existing dependency graph
    2. Extracts resource-based policies from all resources
    3. Uses Bedrock Claude with continuation support for comprehensive analysis
    4. Generates detailed resource mapping in structured markdown format
    5. Caches results for future requests
    6. Returns frontend-compatible markdown data for UI display
    
    This endpoint handles the complete pipeline from infrastructure data to resource mapping with intelligent caching.
    """
    start_time = time.time()
    
    try:
        from session import get_aws_session
        
        # Validate file type
        if not file.filename.endswith('.json'):
            return {
                "error": "Invalid file type",
                "message": "Please upload a JSON file (.json extension required)"
            }
        
        # Read and parse the uploaded JSON file
        try:
            file_content = await file.read()
            infrastructure_data = json.loads(file_content.decode('utf-8'))
        except json.JSONDecodeError as e:
            return {
                "error": "Invalid JSON file",
                "message": f"Could not parse JSON file: {str(e)}"
            }
        except Exception as e:
            return {
                "error": "File read error",
                "message": f"Could not read uploaded file: {str(e)}"
            }
        
        # Validate that it's infrastructure data (basic check)
        if not isinstance(infrastructure_data, dict) or 'account_id' not in infrastructure_data:
            return {
                "error": "Invalid infrastructure data",
                "message": "The uploaded JSON does not appear to be from /infra-doc/generate endpoint"
            }
        
        # Initialize cache service
        cache_service = InfrastructureCacheService()
        
        # Check cache first
        logger.info(f"🔍 Checking cache for dependency graph")
        cache_hit, cached_graph = cache_service.check_dependency_graph_cache(infrastructure_data)
        
        if cache_hit and cached_graph:
            # Cache hit - return cached result
            processing_time = round((time.time() - start_time) * 1000, 2)
            
            # Update cache metadata with current request info
            cached_graph['cache_metadata'].update({
                'cache_hit': True,
                'processing_time_ms': processing_time,
                'served_from_cache': True
            })
            
            # Add file metadata
            cached_graph['file_metadata'] = {
                'filename': file.filename,
                'file_size_mb': round(len(file_content) / (1024 * 1024), 2),
                'processing_method': 'cached_dependency_graph',
                'steps_completed': ['cache_retrieval']
            }
            
            logger.info(f"🚀 Returning cached dependency graph in {processing_time}ms")
            return cached_graph
        
        # Cache miss - generate new dependency graph
        logger.info(f"📝 Cache miss - generating new dependency graph via Bedrock")
        
        # Get AWS session for Bedrock
        session = get_aws_session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token
        )
        
        # Initialize Bedrock service for resource mapping
        bedrock_service = BedrockAnalysisService(session, region=bedrock_region)
        
        # Generate comprehensive resource mapping directly from infrastructure data
        mapping_result = bedrock_service.generate_resource_mapping_from_infra_data(
            infrastructure_data=infrastructure_data,
            custom_prompt=custom_prompt
        )
        
        # Cache the generated dependency graph
        cache_success = cache_service.cache_dependency_graph(infrastructure_data, mapping_result)
        
        # Add processing metadata
        processing_time = round((time.time() - start_time) * 1000, 2)
        
        # Add cache metadata to response
        mapping_result['cache_metadata'] = {
            'cache_hit': False,
            'processing_time_ms': processing_time,
            'served_from_cache': False,
            'cached_successfully': cache_success
        }
        
        # Add file metadata to response
        mapping_result['file_metadata'] = {
            'filename': file.filename,
            'file_size_mb': round(len(file_content) / (1024 * 1024), 2),
            'processing_method': 'bedrock_resource_mapping_with_chunking_combined_cached',
            'steps_completed': ['policy_extraction', 'bedrock_analysis', 'caching']
        }
        
        logger.info(f"✅ Generated and cached new dependency graph in {processing_time}ms")
        return mapping_result
        
    except Exception as e:
        processing_time = round((time.time() - start_time) * 1000, 2)
        logger.error(f"❌ Resource mapping generation failed after {processing_time}ms: {str(e)}")
@router.get("/cache/stats")
def get_cache_stats():
    """
    Get cache statistics and information
    """
    try:
        cache_service = InfrastructureCacheService()
        stats = cache_service.get_cache_stats()
        
        return {
            "status": "success",
            "cache_stats": stats,
            "message": "Cache statistics retrieved successfully"
        }
        
    except Exception as e:
        logger.error(f"❌ Error getting cache stats: {str(e)}")
        return {
            "error": "Cache stats retrieval failed",
            "message": str(e)
        }

@router.post("/cache/cleanup")
def cleanup_cache(max_age_days: int = 30):
    """
    Clean up old cache files
    """
    try:
        cache_service = InfrastructureCacheService()
        cleaned_count = cache_service.cleanup_old_cache(max_age_days)
        
        return {
            "status": "success",
            "cleaned_files_count": cleaned_count,
            "max_age_days": max_age_days,
            "message": f"Cache cleanup completed. Removed {cleaned_count} old files."
        }
        
    except Exception as e:
        logger.error(f"❌ Error during cache cleanup: {str(e)}")
        return {
            "error": "Cache cleanup failed",
            "message": str(e)
        }
