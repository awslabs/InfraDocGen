# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Bedrock Service - Integration with AWS Bedrock Claude model for infrastructure analysis
Enhanced with intelligent chunking for large infrastructure data
"""

import json
import logging
import time
from botocore.exceptions import ClientError
from botocore.config import Config
from .chunking_utils import InfrastructureChunker, ChunkPromptGenerator
from .report_synthesis import ReportSynthesizer

logger = logging.getLogger(__name__)

class BedrockAnalysisService:
    def __init__(self, session, region='us-east-1'):
        self.session = session
        self.region = region
        
        # Configure extended timeouts for long-running operations
        config = Config(
            read_timeout=900,  # 15 minutes read timeout
            connect_timeout=60,  # 1 minute connect timeout
            retries={'max_attempts': 3}
        )
        
        self.bedrock_client = session.client('bedrock-runtime', region_name=region, config=config)
        self.model_id = 'us.anthropic.claude-3-7-sonnet-20250219-v1:0'
        
        # Initialize chunking components
        self.chunker = InfrastructureChunker()
        self.prompt_generator = ChunkPromptGenerator()
        self.synthesizer = ReportSynthesizer()
        
    def generate_infrastructure_report(self, infrastructure_data, custom_prompt=None, analysis_type='comprehensive'):
        """
        Generate a comprehensive AWS infrastructure report using Claude with intelligent chunking
        """
        try:
            report_start_time = time.time()
            logger.info("🚀 Starting infrastructure analysis with intelligent chunking...")
            
            # Estimate total size and determine if chunking is needed
            total_tokens = self.chunker.estimate_tokens(infrastructure_data)
            logger.info(f"📊 Estimated total tokens: {total_tokens:,}")
            
            if total_tokens <= 150000:  # Can fit in single call
                logger.info("✅ Infrastructure data fits in single call, using direct analysis")
                result = self._generate_single_report(infrastructure_data, custom_prompt, analysis_type)
            else:
                logger.info("🔄 Infrastructure data requires chunking, using multi-chunk analysis")
                result = self._generate_chunked_report(infrastructure_data, custom_prompt, analysis_type)
            
            total_duration = time.time() - report_start_time
            logger.info(f"🏁 Infrastructure analysis completed in {total_duration/60:.1f} minutes ({total_duration:.1f} seconds)")
            
            # Add timing metadata to result
            if isinstance(result, dict):
                result['total_processing_time_minutes'] = round(total_duration/60, 2)
                result['total_processing_time_seconds'] = round(total_duration, 1)
            
            return result
                
        except Exception as e:
            total_duration = time.time() - report_start_time if 'report_start_time' in locals() else 0
            logger.error(f"❌ Error generating infrastructure report after {total_duration:.1f}s: {str(e)}")
            return {
                'error': 'Report generation failed',
                'message': str(e),
                'analysis_type': analysis_type,
                'failed_after_seconds': round(total_duration, 1)
            }    

    def _generate_single_report(self, infrastructure_data, custom_prompt, analysis_type):
        """Generate report for small infrastructure that fits in single call"""
        try:
            # Create the detailed prompt
            prompt = self._create_single_analysis_prompt(infrastructure_data, custom_prompt, analysis_type)
            
            # Call Claude via Bedrock
            response = self._call_claude(prompt)
            
            # Format the response
            report = {
                'analysis_type': analysis_type,
                'model_used': self.model_id,
                'report_markdown': response,
                'chunking_used': False,
                'metadata': {
                    'account_id': infrastructure_data.get('account_id', 'unknown'),
                    'scan_time': infrastructure_data.get('scan_time', 'unknown'),
                    'total_resources': self._count_total_resources(infrastructure_data),
                    'services_analyzed': len(infrastructure_data.get('services_scanned', []))
                }
            }
            
            return report
            
        except Exception as e:
            raise Exception(f"Single report generation failed: {str(e)}")
    
    def _generate_chunked_report(self, infrastructure_data, custom_prompt, analysis_type):
        """Generate report using intelligent chunking for large infrastructure"""
        try:
            # Step 1: Create intelligent chunks
            logger.info("Creating intelligent chunks...")
            chunks = self.chunker.create_chunks(infrastructure_data)
            chunk_summary = self.chunker.get_chunk_summary(chunks)
            
            logger.info(f"Created {len(chunks)} chunks:")
            for chunk_name, info in chunk_summary['chunks'].items():
                logger.info(f"  - {chunk_name}: {info['total_resources']} resources, ~{info['estimated_tokens']:,} tokens")
            
            # Step 2: Process chunks in parallel
            logger.info("Processing chunks with Claude...")
            chunk_results = self._process_chunks_parallel(chunks, custom_prompt, analysis_type)
            
            # Step 3: Combine chunk results directly (no AI synthesis)
            logger.info("Combining chunk results into comprehensive report...")
            final_report = self._create_comprehensive_combined_report(
                chunk_results, 
                infrastructure_data, 
                custom_prompt, 
                analysis_type
            )
            
            # Step 4: Format final response
            report = {
                'analysis_type': analysis_type,
                'model_used': self.model_id,
                'report_markdown': final_report,
                'chunking_used': True,
                'synthesis_method': 'direct_combination',
                'chunk_summary': chunk_summary,
                'metadata': {
                    'account_id': infrastructure_data.get('account_id', 'unknown'),
                    'scan_time': infrastructure_data.get('scan_time', 'unknown'),
                    'total_resources': self._count_total_resources(infrastructure_data),
                    'services_analyzed': len(infrastructure_data.get('services_scanned', [])),
                    'chunks_processed': len(chunks),
                    'total_bedrock_calls': len(chunks)  # Only chunk calls, no synthesis
                }
            }
            
            logger.info(f"Chunked analysis complete: {len(chunks)} chunks processed with direct combination")
            return report
            
        except Exception as e:
            raise Exception(f"Chunked report generation failed: {str(e)}")    

    def _process_chunks_parallel(self, chunks, custom_prompt, analysis_type):
        """Process multiple chunks with ultra-conservative rate limiting"""
        chunk_results = {}
        
        def process_single_chunk_with_retry(chunk_item):
            chunk_name, chunk_data = chunk_item
            max_retries = 6  # Increased retries for better rate limit handling (was 4)
            last_error = None
            chunk_start_time = time.time()
            
            for attempt in range(max_retries):
                try:
                    attempt_start_time = time.time()
                    logger.info(f"🔄 Processing chunk: {chunk_name} (attempt {attempt + 1}/{max_retries})")
                    
                    # Generate specialized prompt for this chunk
                    chunk_prompt = self.prompt_generator.generate_chunk_prompt(
                        chunk_data, custom_prompt, analysis_type
                    )
                    
                    # Call Claude for this chunk with enhanced retry logic
                    result = self._call_claude_with_retry(chunk_prompt, max_retries=5)
                    
                    attempt_duration = time.time() - attempt_start_time
                    chunk_duration = time.time() - chunk_start_time
                    
                    logger.info(f"✅ Completed chunk: {chunk_name}")
                    logger.info(f"⏱️ Chunk timing - This attempt: {attempt_duration:.1f}s, Total chunk time: {chunk_duration:.1f}s")
                    
                    return chunk_name, {
                        "analysis_content": result,
                        "chunk_info": chunk_data.get("chunk_info", {}),
                        "resource_count": chunk_data.get("resource_count", 0),
                        "services_included": chunk_data.get("services_included", []),
                        "success": True,
                        "processing_time_seconds": chunk_duration,
                        "attempts_made": attempt + 1
                    }
                    
                except Exception as e:
                    last_error = e
                    error_msg = str(e)
                    attempt_duration = time.time() - attempt_start_time
                    
                    if "rate limit" in error_msg.lower() or "throttling" in error_msg.lower():
                        if attempt < max_retries - 1:
                            # Enhanced exponential backoff with longer delays for rate limit errors
                            delay = 120 + (attempt * 90)  # 120s, 210s, 300s, 390s, 480s
                            logger.warning(f"⚠️ Rate limit hit for {chunk_name} after {attempt_duration:.1f}s, retrying in {delay}s (attempt {attempt + 1}/{max_retries})")
                            time.sleep(delay) # nosemgrep: arbitrary-sleep
                            continue
                        else:
                            chunk_duration = time.time() - chunk_start_time
                            logger.error(f"❌ Rate limit exceeded for {chunk_name} after {max_retries} attempts and {chunk_duration:.1f}s total time")
                    else:
                        logger.error(f"❌ Error processing chunk {chunk_name} after {attempt_duration:.1f}s: {error_msg}")
                        break
            
            # Return error result if all retries failed
            return chunk_name, {
                "error": f"Failed after {max_retries} attempts: {str(last_error)}",
                "chunk_info": chunk_data.get("chunk_info", {}),
                "analysis_content": f"# {chunk_name.replace('_', ' ').title()} Analysis\n\n**Error:** Analysis failed due to API rate limits. This chunk contains {chunk_data.get('resource_count', 0)} resources that could not be analyzed.\n\n**Recommendation:** Try again later when API rate limits have reset, or contact support if the issue persists.",
                "success": False
            }
        
        # Process chunks sequentially with enhanced rate limiting and timing
        total_processing_start = time.time()
        logger.info(f"🚀 Processing {len(chunks)} chunks sequentially with enhanced rate limiting...")
        logger.info("⏱️ This will take 25-35 minutes for chunk processing (no synthesis step needed)")
        
        successful_chunks = 0
        failed_chunks = 0
        
        for i, chunk_item in enumerate(chunks.items()):
            chunk_name = chunk_item[0]
            chunk_processing_start = time.time()
            
            logger.info(f"📊 Processing chunk {i+1}/{len(chunks)}: {chunk_name}")
            
            chunk_name, result = process_single_chunk_with_retry(chunk_item)
            chunk_results[chunk_name] = result
            
            chunk_processing_duration = time.time() - chunk_processing_start
            elapsed_total = time.time() - total_processing_start
            
            if result.get("success", False):
                successful_chunks += 1
                logger.info(f"✅ Chunk {i+1}/{len(chunks)} completed successfully in {chunk_processing_duration:.1f}s")
            else:
                failed_chunks += 1
                logger.error(f"❌ Chunk {i+1}/{len(chunks)} failed after {chunk_processing_duration:.1f}s")
            
            logger.info(f"📈 Progress: {i+1}/{len(chunks)} chunks processed ({successful_chunks} success, {failed_chunks} failed) - Total elapsed: {elapsed_total/60:.1f} minutes")
            
            # Add longer delay between chunks (except for last chunk)
            if i < len(chunks) - 1:
                delay = 60  # 60 seconds between chunks for better rate limit avoidance
                remaining_chunks = len(chunks) - (i + 1)
                estimated_remaining = (remaining_chunks * 5 * 60) + (remaining_chunks * delay)  # rough estimate
                logger.info(f"⏳ Waiting {delay}s before processing next chunk (estimated {estimated_remaining/60:.0f} more minutes)...")
                time.sleep(delay) # nosemgrep: arbitrary-sleep
        
        total_processing_duration = time.time() - total_processing_start
        logger.info(f"🏁 All chunks processed in {total_processing_duration/60:.1f} minutes ({successful_chunks} successful, {failed_chunks} failed)")
        
        return chunk_results    

    def _call_claude_with_retry(self, prompt, max_retries=5):
        """Call Claude with enhanced retry logic for better rate limit handling"""
        last_error = None
        api_call_start_time = time.time()
        
        for attempt in range(max_retries):
            try:
                single_call_start = time.time()
                result = self._call_claude(prompt)
                single_call_duration = time.time() - single_call_start
                total_api_duration = time.time() - api_call_start_time
                
                logger.info(f"🎯 Bedrock API call successful - This call: {single_call_duration:.1f}s, Total API time: {total_api_duration:.1f}s")
                return result
                
            except Exception as e:
                last_error = e
                error_msg = str(e)
                single_call_duration = time.time() - single_call_start
                
                if ("rate limit" in error_msg.lower() or 
                    "throttling" in error_msg.lower() or
                    "ThrottlingException" in error_msg):
                    
                    if attempt < max_retries - 1:
                        # Enhanced exponential backoff with much longer delays for rate limits
                        delay = 150 + (attempt * 120)  # 150s, 270s, 390s, 510s
                        total_api_duration = time.time() - api_call_start_time
                        logger.warning(f"⚠️ Rate limit hit after {single_call_duration:.1f}s, retrying in {delay}s (attempt {attempt + 1}/{max_retries}) - Total API time so far: {total_api_duration:.1f}s")
                        time.sleep(delay) # nosemgrep: arbitrary-sleep
                        continue
                    else:
                        total_api_duration = time.time() - api_call_start_time
                        raise Exception(f"Rate limit exceeded after {max_retries} attempts and {total_api_duration:.1f}s total time: {str(last_error)}")
                else:
                    # Non-rate-limit error, don't retry
                    total_api_duration = time.time() - api_call_start_time
                    logger.warning(f"❌ Non-rate-limit error after {single_call_duration:.1f}s (total: {total_api_duration:.1f}s): {error_msg}")
                    raise e
        
        total_api_duration = time.time() - api_call_start_time
        raise Exception(f"Unexpected error in retry logic after {total_api_duration:.1f}s: {str(last_error)}")
    
    def _synthesize_final_report(self, chunk_results, infrastructure_data, custom_prompt, analysis_type):
        """Synthesize chunk results into final cohesive report with graceful error handling"""
        try:
            # Check how many chunks succeeded
            successful_chunks = {k: v for k, v in chunk_results.items() if v.get("success", True)}
            failed_chunks = {k: v for k, v in chunk_results.items() if not v.get("success", True)}
            
            logger.info(f"Synthesis: {len(successful_chunks)} successful, {len(failed_chunks)} failed chunks")
            
            if len(successful_chunks) == 0:
                logger.error("No chunks succeeded, cannot synthesize report")
                return self._create_fallback_report(chunk_results, infrastructure_data)
            
            # If we have some successful chunks, proceed with synthesis
            if len(failed_chunks) > 0:
                logger.warning(f"Synthesizing with partial data - {len(failed_chunks)} chunks failed due to rate limits")
            
            # Prepare synthesis data using only successful chunks
            synthesis_data = self.synthesizer.synthesize_reports(
                successful_chunks, 
                infrastructure_data, 
                custom_prompt, 
                analysis_type
            )
            
            # Add note about failed chunks to synthesis prompt
            if failed_chunks:
                failed_chunk_names = list(failed_chunks.keys())
                synthesis_data["synthesis_prompt"] += f"""

IMPORTANT NOTE: The following chunks failed due to API rate limits and are not included in this analysis:
- {', '.join(failed_chunk_names)}

Please note this limitation in your final report and recommend re-running the analysis for complete coverage.
"""
            
            # Generate final synthesis prompt
            synthesis_prompt = synthesis_data["synthesis_prompt"]
            
            # Call Claude for final synthesis with enhanced retry logic and timeout handling
            synthesis_start_time = time.time()
            logger.info("🔄 Generating final synthesized report...")
            
            try:
                final_report = self._call_claude_with_retry(synthesis_prompt, max_retries=3)  # Reduced retries for synthesis
                synthesis_duration = time.time() - synthesis_start_time
                logger.info(f"✅ Final synthesis completed in {synthesis_duration:.1f}s")
                
            except Exception as e:
                synthesis_duration = time.time() - synthesis_start_time
                error_msg = str(e)
                
                if "timeout" in error_msg.lower() or "Read timeout" in error_msg:
                    logger.error(f"❌ Synthesis timed out after {synthesis_duration:.1f}s - using comprehensive combined report")
                    logger.warning("The synthesis request was too large for Claude to process within 15 minutes")
                    return self._create_comprehensive_combined_report(chunk_results, infrastructure_data, 
                                                               custom_prompt, analysis_type)
                else:
                    logger.error(f"❌ Synthesis failed after {synthesis_duration:.1f}s: {error_msg}")
                    return self._create_comprehensive_combined_report(chunk_results, infrastructure_data, 
                                                               custom_prompt, analysis_type)
            
            # Add failed chunk information to the final report
            if failed_chunks:
                failed_chunk_section = f"""

## ⚠️ Analysis Limitations

**Note:** Due to API rate limits, the following infrastructure components could not be analyzed in this report:

"""
                for chunk_name, chunk_data in failed_chunks.items():
                    resource_count = chunk_data.get("resource_count", 0)
                    failed_chunk_section += f"- **{chunk_name.replace('_', ' ').title()}**: {resource_count} resources not analyzed\n"
                
                failed_chunk_section += f"""
**Recommendation:** Re-run the analysis later when API rate limits have reset to get complete coverage of all {len(chunk_results)} infrastructure components.

---

"""
                # Insert this section after the executive summary
                final_report = final_report.replace("## Infrastructure Overview", failed_chunk_section + "## Infrastructure Overview")
            
            return final_report
            
        except Exception as e:
            logger.error(f"Report synthesis failed: {str(e)}")
            # Fallback: combine chunk results without synthesis
            return self._create_comprehensive_combined_report(chunk_results, infrastructure_data, 
                                                       custom_prompt, analysis_type)
    
    def _create_comprehensive_combined_report(self, chunk_results, infrastructure_data, custom_prompt=None, analysis_type='comprehensive'):
        """Create a comprehensive combined report by directly combining chunk analyses"""
        logger.info("Generating comprehensive combined report from chunk analyses")
        
        successful_chunks = {k: v for k, v in chunk_results.items() if v.get("success", True)}
        failed_chunks = {k: v for k, v in chunk_results.items() if not v.get("success", True)}
        
        report_parts = [
            "# AWS Infrastructure Analysis Report",
            "",
            "## Executive Summary",
            "",
            f"This comprehensive report analyzes AWS infrastructure for account **{infrastructure_data.get('account_id', 'unknown')}**.",
            f"**Scan Time:** {infrastructure_data.get('scan_time', 'unknown')}",
            f"**Total Resources:** {self._count_total_resources(infrastructure_data)}",
            f"**Analysis Type:** {analysis_type.title()}",
            "",
            f"**Analysis Coverage:**",
            f"- ✅ Successfully analyzed: {len(successful_chunks)} infrastructure components",
        ]
        
        if failed_chunks:
            report_parts.append(f"- ⚠️ Failed due to rate limits: {len(failed_chunks)} infrastructure components")
        
        report_parts.extend([
            "",
            "## Infrastructure Components Analysis",
            "",
            "This report provides detailed analysis of each infrastructure component, including security recommendations, cost optimization opportunities, and best practices."
        ])
        
        # Add successful chunk results
        if successful_chunks:
            report_parts.append("")
            report_parts.append("---")
            report_parts.append("")
            
            for chunk_name, result in successful_chunks.items():
                report_parts.append(f"## {chunk_name.replace('_', ' ').title()} Infrastructure")
                report_parts.append("")
                
                # Add chunk metadata if available
                if 'services_included' in result:
                    services = result['services_included']
                    if services:
                        report_parts.append(f"**Services Analyzed:** {', '.join(services).upper()}")
                        report_parts.append("")
                
                if 'resource_count' in result:
                    report_parts.append(f"**Resources Analyzed:** {result['resource_count']}")
                    report_parts.append("")
                
                # Add the analysis content
                analysis_content = result.get("analysis_content", "Analysis not available")
                report_parts.append(analysis_content)
                report_parts.append("")
                report_parts.append("---")
                report_parts.append("")
        
        # Add failed chunk information
        if failed_chunks:
            report_parts.append("### ⚠️ Components Not Analyzed (Rate Limit Issues)")
            report_parts.append("")
            report_parts.append("The following infrastructure components could not be analyzed due to API rate limits:")
            report_parts.append("")
            
            for chunk_name, result in failed_chunks.items():
                resource_count = result.get("resource_count", 0)
                report_parts.append(f"- **{chunk_name.replace('_', ' ').title()}**: {resource_count} resources")
            
            report_parts.append("")
            report_parts.append("**Recommendation:** Re-run the analysis later to get complete coverage.")
            report_parts.append("")
        
        # Add simple footer
        report_parts.extend([
            "---",
            "",
            f"**Report Generated:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
            f"**Analysis Method:** Fallback (Direct Chunk Combination)",
            ""
        ])
        
        return "\n".join(report_parts)   
 
    def generate_resource_mapping_from_infra_data(self, infrastructure_data, custom_prompt=None):
        """
        Generate comprehensive AWS resource dependency mapping directly from infrastructure data using service-wise chunking
        
        Takes infrastructure data and generates detailed resource mapping in structured markdown format.
        This method handles the policy extraction internally and then generates the mapping service by service.
        """
        try:
            mapping_start_time = time.time()
            print("🚀 Starting service-wise resource mapping generation from infrastructure data...")
            
            # Step 1: Extract resource policies from infrastructure data
            print("🔄 Extracting resource policies from infrastructure data...")
            from services.policy_extractor import extract_resource_policies
            policy_data = extract_resource_policies(infrastructure_data)
            
            # Check if policy extraction failed
            if 'error' in policy_data:
                return policy_data
            
            print(f"✅ Extracted policies for {len(policy_data.get('resources_with_policies', []))} resources")
            
            # Step 2: Group resources by service
            print("🔄 Grouping resources by AWS service...")
            service_chunks = self._create_service_wise_policy_chunks(policy_data)
            
            print(f"📊 Created {len(service_chunks)} service chunks:")
            for service_name, chunk_info in service_chunks.items():
                print(f"  - {service_name.upper()}: {chunk_info['resource_count']} resources")
            
            # Step 3: Process each service chunk with continuation support
            print("🔄 Processing service chunks with AI analysis...")
            service_results = self._process_service_chunks_with_continuation(service_chunks, custom_prompt)
            
            # Step 4: Combine all service results into one markdown document
            print("🔄 Combining service results into comprehensive mapping...")
            combined_markdown = self._combine_service_markdown_results(service_results, policy_data)
            
            total_duration = time.time() - mapping_start_time
            print(f"🏁 Service-wise resource mapping generation completed in {total_duration/60:.1f} minutes ({total_duration:.1f} seconds)")
            
            # Calculate statistics
            successful_services = len([s for s in service_results.values() if s.get('success', False)])
            failed_services = len([s for s in service_results.values() if not s.get('success', False)])
            total_calls = sum([s.get('total_calls', 0) for s in service_results.values()])
            
            # Format the response
            result = {
                'model_used': self.model_id,
                'chunking_used': True,
                'chunking_method': 'service_wise',
                'output_format': 'structured_markdown',
                'markdown_content': combined_markdown,
                'continuation_used': total_calls > len(service_chunks),
                'total_calls': total_calls,
                'processing_metadata': {
                    'account_id': policy_data.get('account_id', 'unknown'),
                    'resources_analyzed': len(policy_data.get('resources_with_policies', [])),
                    'infrastructure_resources': self._count_total_resources(infrastructure_data),
                    'services_processed': len(service_chunks),
                    'successful_services': successful_services,
                    'failed_services': failed_services,
                    'model_used': self.model_id,
                    'generation_timestamp': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
                    'policy_extraction_completed': True,
                    'service_breakdown': {name: {'resources': info['resource_count'], 'success': service_results.get(name, {}).get('success', False)} for name, info in service_chunks.items()}
                },
                'total_processing_time_minutes': round(total_duration/60, 2),
                'total_processing_time_seconds': round(total_duration, 1)
            }
            
            return result
            
        except Exception as e:
            total_duration = time.time() - mapping_start_time if 'mapping_start_time' in locals() else 0
            print(f"❌ Error generating service-wise resource mapping after {total_duration:.1f}s: {str(e)}")
            return {
                'error': 'Service-wise resource mapping generation failed',
                'message': str(e),
                'markdown_content': '',
                'processing_metadata': {
                    'failed_after_seconds': round(total_duration, 1),
                    'account_id': infrastructure_data.get('account_id', 'unknown') if isinstance(infrastructure_data, dict) else 'unknown',
                    'policy_extraction_attempted': True,
                    'chunking_method': 'service_wise'
                }
            }

    def _create_service_wise_policy_chunks(self, policy_data):
        """Create chunks based on AWS services from policy data"""
        try:
            service_chunks = {}
            resources_with_policies = policy_data.get('resources_with_policies', [])
            
            # Group resources by service
            service_resources = {}
            for resource in resources_with_policies:
                service = resource.get('service', 'unknown')
                if service not in service_resources:
                    service_resources[service] = []
                service_resources[service].append(resource)
            
            # Create chunks for each service
            for service_name, resources in service_resources.items():
                if len(resources) > 0:  # Only create chunks for services with resources
                    service_chunks[service_name] = {
                        'service_name': service_name,
                        'resources_with_policies': resources,
                        'resource_count': len(resources),
                        'account_id': policy_data.get('account_id', 'unknown'),
                        'policy_data_subset': {
                            'account_id': policy_data.get('account_id', 'unknown'),
                            'resources_with_policies': resources,
                            'extraction_timestamp': policy_data.get('extraction_timestamp', 'unknown')
                        }
                    }
            
            print(f"✅ Created service chunks for {len(service_chunks)} services")
            return service_chunks
            
        except Exception as e:
            print(f"❌ Error creating service-wise chunks: {str(e)}")
            return {}

    def _process_service_chunks_with_continuation(self, service_chunks, custom_prompt):
        """Process service chunks with continuation support for each service"""
        service_results = {}
        
        def process_single_service_with_continuation(service_item):
            service_name, service_data = service_item
            
            # Skip services with no resources
            if service_data['resource_count'] == 0:
                print(f"⏭️ Skipping {service_name}: no resources with policies")
                return service_name, {
                    "markdown_content": "",
                    "success": True,
                    "skipped": True,
                    "total_calls": 0,
                    "resource_count": 0
                }
            
            max_retries = 3
            last_error = None
            service_start_time = time.time()
            
            for attempt in range(max_retries):
                try:
                    print(f"🔄 Processing service: {service_name.upper()} ({service_data['resource_count']} resources) - attempt {attempt + 1}/{max_retries}")
                    
                    # Create service-specific prompt
                    service_prompt = self._create_service_mapping_prompt(service_data, custom_prompt)
                    
                    # Generate mapping for this service with continuation support
                    service_markdown = self._generate_service_markdown_with_continuation(
                        service_prompt, 
                        service_data['policy_data_subset'],
                        service_name
                    )
                    
                    service_duration = time.time() - service_start_time
                    print(f"✅ Completed service: {service_name.upper()} in {service_duration:.1f}s")
                    
                    return service_name, {
                        "markdown_content": service_markdown['content'],
                        "success": True,
                        "total_calls": service_markdown['total_calls'],
                        "continuation_used": service_markdown['continuation_used'],
                        "resource_count": service_data['resource_count'],
                        "processing_time_seconds": service_duration,
                        "attempts_made": attempt + 1
                    }
                    
                except Exception as e:
                    last_error = e
                    error_msg = str(e)
                    
                    if "rate limit" in error_msg.lower() or "throttling" in error_msg.lower():
                        if attempt < max_retries - 1:
                            delay = 120 + (attempt * 60)  # 120s, 180s, 240s
                            print(f"⚠️ Rate limit hit for {service_name}, retrying in {delay}s (attempt {attempt + 1}/{max_retries})")
                            time.sleep(delay) # nosemgrep: arbitrary-sleep
                            continue
                        else:
                            service_duration = time.time() - service_start_time
                            print(f"❌ Rate limit exceeded for {service_name} after {max_retries} attempts and {service_duration:.1f}s")
                    else:
                        print(f"❌ Error processing service {service_name}: {error_msg}")
                        break
            
            # Return error result if all retries failed
            service_duration = time.time() - service_start_time
            return service_name, {
                "markdown_content": f"## {service_name.upper()} Service Analysis\n\n**Error:** Analysis failed due to API issues. This service contains {service_data['resource_count']} resources that could not be analyzed.\n\n**Recommendation:** Try again later.\n\n---\n",
                "success": False,
                "error": str(last_error),
                "total_calls": 0,
                "resource_count": service_data['resource_count'],
                "processing_time_seconds": service_duration
            }
        
        # Process services sequentially with rate limiting
        total_processing_start = time.time()
        print(f"🚀 Processing {len(service_chunks)} services sequentially...")
        
        successful_services = 0
        failed_services = 0
        
        for i, service_item in enumerate(service_chunks.items()):
            service_name = service_item[0]
            
            print(f"📊 Processing service {i+1}/{len(service_chunks)}: {service_name.upper()}")
            
            service_name, result = process_single_service_with_continuation(service_item)
            service_results[service_name] = result
            
            if result.get("success", False):
                successful_services += 1
                if not result.get("skipped", False):
                    print(f"✅ Service {i+1}/{len(service_chunks)} completed successfully")
                else:
                    print(f"⏭️ Service {i+1}/{len(service_chunks)} skipped (no resources)")
            else:
                failed_services += 1
                print(f"❌ Service {i+1}/{len(service_chunks)} failed")
            
            # Add delay between services (except for last service)
            if i < len(service_chunks) - 1:
                delay = 45  # 45 seconds between services
                print(f"⏳ Waiting {delay}s before processing next service...")
                time.sleep(delay) # nosemgrep: arbitrary-sleep
        
        total_processing_duration = time.time() - total_processing_start
        print(f"🏁 All services processed in {total_processing_duration/60:.1f} minutes ({successful_services} successful, {failed_services} failed)")
        
        return service_results

    def _create_service_mapping_prompt(self, service_data, custom_prompt):
        """Create specialized prompt for individual service mapping"""
        service_name = service_data['service_name']
        resource_count = service_data['resource_count']
        
        base_prompt = f"""You are a senior AWS Security Architect specializing in resource dependency mapping and access analysis.

Your task is to analyze AWS {service_name.upper()} service resources and create a comprehensive resource mapping in EXACTLY the structured Markdown format specified below.

CRITICAL FORMATTING REQUIREMENTS:
1. Output MUST follow the EXACT markdown structure shown below
2. Every resource MUST start with "### " followed by the resource identifier
3. Every field MUST use the "- **Field**: value" format with double asterisks
4. NO deviation from the format is allowed
5. NO additional text, explanations, or policy details outside the structure

MANDATORY MARKDOWN OUTPUT STRUCTURE (FOLLOW EXACTLY):

### arn:aws:{service_name}:region:account:resource-type/resource-name
- **Type**: [resource_type]
- **Service**: {service_name}
- **Region**: [region]
- **Connections**:
  - **[target_resource_id_1]**: [relationship_type]
  - **[target_resource_id_2]**: [relationship_type]

### arn:aws:{service_name}:region:account:resource-type/resource-name-2
- **Type**: [resource_type]
- **Service**: {service_name}
- **Region**: [region]
- **Connections**:
  - **[target_resource_id_3]**: [relationship_type]

STRICT FORMATTING RULES:
1. Each resource MUST start with "### " (three hashes and space)
2. Each field MUST use "- **FieldName**: value" format
3. Connections MUST be indented with two spaces: "  - **target**: relationship"
4. NO additional explanations, policy JSON, or analysis text
5. NO headers like "## Service Analysis" or similar
6. ONLY the resource entries in the exact format above

EXAMPLE OF CORRECT FORMAT:
### arn:aws:lambda:us-east-1:123456789012:function:my-function
- **Type**: Lambda Function
- **Service**: lambda
- **Region**: us-east-1
- **Connections**:
  - **arn:aws:execute-api:us-east-1:123456789012:api123/*/POST/**: lambda:InvokeFunction

WHAT NOT TO INCLUDE:
- NO policy JSON blocks
- NO analysis explanations
- NO additional headers
- NO "Policy:" sections
- NO "Analysis:" sections

CONTINUATION LOGIC:
- If you cannot complete all {resource_count} {service_name} resources, end with "CONTINUE_ANALYSIS"
- When ALL {service_name} resources are complete, end with "ANALYSIS_COMPLETE"
- Maintain EXACT formatting in continuation responses

SERVICE CONTEXT:
- Service: {service_name.upper()}
- Resources to analyze: {resource_count}
- Output: ONLY the structured markdown format above"""

        # Add custom prompt if provided
        if custom_prompt:
            base_prompt += f"\n\nADDITIONAL REQUIREMENTS:\n{custom_prompt}\n"

        base_prompt += f"\n\nIMPORTANT: Output ONLY the structured markdown format. No explanations, no policy details, no additional text."

        return base_prompt

    def _generate_service_markdown_with_continuation(self, initial_prompt, policy_data, service_name):
        """Generate service-specific markdown with continuation support"""
        try:
            complete_content = ""
            continuation_used = False
            total_calls = 0
            max_continuations = 5  # Per service limit
            analysis_complete_found = False
            
            # Add policy data to initial prompt
            policy_json = json.dumps(policy_data, indent=2)
            full_initial_prompt = f"{initial_prompt}\n\nPOLICY DATA FOR {service_name.upper()}:\n```json\n{policy_json}\n```\n\nGenerate the structured Markdown resource mapping for {service_name.upper()} service:"
            
            # First call with initial prompt
            print(f"📡 Making initial call for {service_name.upper()} service...")
            current_response = self._call_claude_with_retry(full_initial_prompt, max_retries=3)
            complete_content = current_response
            total_calls += 1
            
            # Check if we got ANALYSIS_COMPLETE in the first response
            if "ANALYSIS_COMPLETE" in current_response:
                analysis_complete_found = True
                print(f"🎯 {service_name.upper()} analysis complete in first call")
            
            # Continue until we get ANALYSIS_COMPLETE marker
            while (self._should_continue_service_analysis(current_response, analysis_complete_found, service_name) and 
                   total_calls < max_continuations):
                continuation_used = True
                print(f"⚠️ {service_name.upper()} needs continuation (call {total_calls + 1})...")
                
                # Remove continuation marker if present
                if "CONTINUE_ANALYSIS" in complete_content:
                    complete_content = complete_content.replace("CONTINUE_ANALYSIS", "").strip()
                
                # Create continuation prompt for this service
                continuation_prompt = self._create_service_continuation_prompt(complete_content, policy_data, service_name)
                
                # Add delay between calls
                time.sleep(30) # nosemgrep: arbitrary-sleep
                
                # Make continuation call
                print(f"📡 Making continuation call {total_calls + 1} for {service_name.upper()}...")
                continuation_response = self._call_claude_with_retry(continuation_prompt, max_retries=3)
                
                # Check for completion marker
                if "ANALYSIS_COMPLETE" in continuation_response:
                    analysis_complete_found = True
                    print(f"🎯 {service_name.upper()} analysis complete marker found")
                
                # Append continuation content
                cleaned_continuation = self._clean_continuation_response(continuation_response)
                complete_content += "\n\n" + cleaned_continuation
                
                current_response = continuation_response
                total_calls += 1
                
                print(f"✅ {service_name.upper()} continuation {total_calls - 1} completed")
            
            # Final cleanup
            complete_content = complete_content.replace("CONTINUE_ANALYSIS", "").strip()
            complete_content = complete_content.replace("ANALYSIS_COMPLETE", "").strip()
            
            print(f"🏁 {service_name.upper()} service analysis complete: {total_calls} calls, {len(complete_content)} characters")
            
            return {
                'content': complete_content,
                'continuation_used': continuation_used,
                'total_calls': total_calls,
                'analysis_complete_found': analysis_complete_found
            }
            
        except Exception as e:
            raise Exception(f"Service {service_name} markdown generation failed: {str(e)}")

    def _should_continue_service_analysis(self, response, analysis_complete_found, service_name):
        """Determine if service analysis should continue"""
        try:
            content = response.strip()
            
            # If we already found ANALYSIS_COMPLETE, stop
            if analysis_complete_found:
                print(f"✅ {service_name.upper()} analysis complete marker already found")
                return False
            
            # If we have ANALYSIS_COMPLETE marker in current response, stop
            if "ANALYSIS_COMPLETE" in content:
                print(f"✅ {service_name.upper()} analysis complete marker detected")
                return False
            
            # If we have CONTINUE_ANALYSIS marker, continue
            if "CONTINUE_ANALYSIS" in content:
                print(f"🔄 {service_name.upper()} continue marker detected")
                return True
            
            # Check if we have sufficient resource analysis for this service
            resource_count = content.count("### ")
            has_connections = "**Connections**:" in content
            
            print(f"🔍 {service_name.upper()} content check - Resources: {resource_count}, Connections: {has_connections}")
            
            # Be conservative - continue if we don't have much content
            if resource_count < 2 or not has_connections:
                print(f"🔄 {service_name.upper()} insufficient content - continuing")
                return True
            
            # Check for truncation
            if self._is_markdown_truncated(content):
                print(f"🔍 {service_name.upper()} appears truncated - continuing")
                return True
            
            # If we have reasonable content, assume complete
            print(f"✅ {service_name.upper()} appears complete with {resource_count} resources")
            return False
            
        except Exception as e:
            print(f"⚠️ Error checking {service_name} continuation: {str(e)}, continuing")
            return True

    def _create_service_continuation_prompt(self, existing_content, policy_data, service_name):
        """Create continuation prompt for service-specific analysis"""
        analyzed_resources = self._extract_analyzed_resources_from_content(existing_content)
        
        continuation_prompt = f"""You are continuing the {service_name.upper()} service resource mapping analysis that was truncated.

EXISTING ANALYSIS STATUS:
- Service: {service_name.upper()}
- Resources analyzed so far: {len(analyzed_resources)}
- Content length: {len(existing_content)} characters

CRITICAL FORMATTING REQUIREMENTS FOR CONTINUATION:
1. Continue with the EXACT same structured markdown format
2. Every resource MUST start with "### " followed by the resource identifier
3. Every field MUST use the "- **Field**: value" format with double asterisks
4. NO deviation from the format is allowed
5. NO additional text, explanations, or policy details outside the structure

MANDATORY CONTINUATION FORMAT (FOLLOW EXACTLY):

### arn:aws:{service_name}:region:account:resource-type/resource-name
- **Type**: [resource_type]
- **Service**: {service_name}
- **Region**: [region]
- **Connections**:
  - **[target_resource_id]**: [relationship_type]

STRICT CONTINUATION RULES:
1. Do NOT repeat any resources that were already analyzed
2. Continue with the next {service_name} resource in sequence
3. Use EXACT formatting: "### " then "- **Field**: value"
4. NO policy JSON blocks, NO analysis explanations, NO additional headers
5. When ALL {service_name} resources are analyzed, end with "ANALYSIS_COMPLETE"
6. If you cannot finish all {service_name} resources, end with "CONTINUE_ANALYSIS"

ALREADY ANALYZED {service_name.upper()} RESOURCES (do not repeat):
{', '.join(analyzed_resources[:10])}{'...' if len(analyzed_resources) > 10 else ''}

IMPORTANT: Output ONLY the structured markdown format for remaining resources. No explanations, no policy details, no additional text."""

        # Add policy data
        policy_json = json.dumps(policy_data, indent=2)
        full_prompt = f"{continuation_prompt}\n\nPOLICY DATA FOR {service_name.upper()}:\n```json\n{policy_json}\n```\n\nContinue the {service_name.upper()} analysis with EXACT formatting:"
        
        return full_prompt

    def _combine_service_markdown_results(self, service_results, policy_data):
        """Combine all service markdown results into one comprehensive document"""
        try:
            # Start with header
            combined_parts = [
                "# AWS Resource Dependency Mapping",
                "",
                "## Resource Relationships"
            ]
            
            # Calculate totals
            total_resources = len(policy_data.get('resources_with_policies', []))
            successful_services = [name for name, result in service_results.items() if result.get('success', False) and not result.get('skipped', False)]
            
            combined_parts.extend([
                f"- **Total Resources**: {total_resources}",
                f"- **Services Analyzed**: {', '.join(successful_services)}",
                "",
                "---",
                "",
                "## Resource Dependencies",
                ""
            ])
            
            # Add each service's content
            for service_name, result in service_results.items():
                if result.get('success', False) and not result.get('skipped', False):
                    service_content = result.get('markdown_content', '')
                    if service_content.strip():
                        # Clean up the service content (remove service headers if present)
                        cleaned_content = service_content.replace(f"## {service_name.upper()} Service Resources", "")
                        cleaned_content = cleaned_content.strip()
                        
                        if cleaned_content:
                            combined_parts.append(cleaned_content)
                            combined_parts.append("")
                elif result.get('success', False) and result.get('skipped', False):
                    print(f"⏭️ Skipped {service_name} (no resources)")
                else:
                    print(f"❌ Failed to process {service_name}")
                    # Add error placeholder
                    combined_parts.extend([
                        f"### {service_name.upper()} Service",
                        f"- **Error**: Failed to analyze {service_name} resources",
                        f"- **Resources**: {result.get('resource_count', 0)} resources not analyzed",
                        ""
                    ])
            
            # Add footer
            combined_parts.extend([
                "---",
                "",
                f"**Generated**: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
                f"**Method**: Service-wise Analysis with Continuation Support",
                ""
            ])
            
            combined_markdown = "\n".join(combined_parts)
            print(f"✅ Combined markdown: {len(combined_markdown)} characters from {len(successful_services)} services")
            
            return combined_markdown
            
        except Exception as e:
            print(f"❌ Error combining service results: {str(e)}")
            return f"# AWS Resource Dependency Mapping\n\n**Error**: Failed to combine service results: {str(e)}"

    def generate_resource_mapping_graph(self, policy_data, custom_prompt=None):
        """
        Generate comprehensive AWS resource dependency mapping using Claude with single markdown output
        
        Takes policy data from policy extractor and generates detailed resource mapping
        in structured markdown format for frontend visualization.
        """
        try:
            mapping_start_time = time.time()
            print("🚀 Starting resource mapping generation with single markdown output...")
            
            # Use single call approach with structured markdown output
            print("🔄 Using single markdown generation for all resources")
            result = self._generate_single_markdown_mapping(policy_data, custom_prompt)
            
            total_duration = time.time() - mapping_start_time
            print(f"🏁 Resource mapping generation completed in {total_duration/60:.1f} minutes ({total_duration:.1f} seconds)")
            
            # Add timing metadata to result
            if isinstance(result, dict):
                result['total_processing_time_minutes'] = round(total_duration/60, 2)
                result['total_processing_time_seconds'] = round(total_duration, 1)
            
            return result
            
        except Exception as e:
            total_duration = time.time() - mapping_start_time if 'mapping_start_time' in locals() else 0
            print(f"❌ Error generating resource mapping after {total_duration:.1f}s: {str(e)}")
            return {
                'error': 'Resource mapping generation failed',
                'message': str(e),
                'markdown_content': '',
                'processing_metadata': {
                    'failed_after_seconds': round(total_duration, 1),
                    'account_id': policy_data.get('account_id', 'unknown') if isinstance(policy_data, dict) else 'unknown'
                }
            }
    
    def _generate_single_markdown_mapping(self, policy_data, custom_prompt):
        """Generate resource mapping using single markdown output with continuation support"""
        try:
            # Create the specialized prompt for markdown resource mapping
            prompt = self._create_markdown_resource_mapping_prompt(policy_data, custom_prompt)
            
            # Call Claude via Bedrock with continuation support
            print("🔄 Analyzing resource policies and generating structured markdown mapping...")
            complete_markdown = self._generate_complete_markdown_with_continuation(prompt, policy_data)
            
            # Format the response
            result = {
                'model_used': self.model_id,
                'chunking_used': False,
                'output_format': 'structured_markdown',
                'markdown_content': complete_markdown['content'],
                'continuation_used': complete_markdown['continuation_used'],
                'total_calls': complete_markdown['total_calls'],
                'processing_metadata': {
                    'account_id': policy_data.get('account_id', 'unknown'),
                    'resources_analyzed': len(policy_data.get('resources_with_policies', [])),
                    'model_used': self.model_id,
                    'generation_timestamp': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
                    'continuation_calls': complete_markdown['total_calls'] - 1
                }
            }
            
            return result
            
        except Exception as e:
            raise Exception(f"Single markdown mapping generation failed: {str(e)}")
    
    def _generate_complete_markdown_with_continuation(self, initial_prompt, policy_data):
        """Generate complete markdown response using continuation when needed"""
        try:
            complete_content = ""
            continuation_used = False
            total_calls = 0
            max_continuations = 7  # Increased from 5 to allow more thorough analysis
            analysis_complete_found = False
            
            # First call with initial prompt
            print("📡 Making initial Bedrock call...")
            current_response = self._call_claude_with_retry(initial_prompt, max_retries=3)
            print(f"📄 Initial response length: {len(current_response)} characters")
            complete_content = current_response
            total_calls += 1
            
            # Check if we got ANALYSIS_COMPLETE in the first response
            if "ANALYSIS_COMPLETE" in current_response:
                analysis_complete_found = True
                print(f"🎯 ANALYSIS_COMPLETE marker found in initial response")
            
            # Continue until we get ANALYSIS_COMPLETE marker OR reach max continuations
            while (self._should_continue_analysis(current_response, analysis_complete_found) and 
                   total_calls < max_continuations):
                continuation_used = True
                print(f"⚠️ Response needs continuation, requesting continuation (call {total_calls + 1})...")
                
                # Remove continuation marker if present
                if "CONTINUE_ANALYSIS" in complete_content:
                    complete_content = complete_content.replace("CONTINUE_ANALYSIS", "").strip()
                
                # Create continuation prompt
                continuation_prompt = self._create_continuation_prompt(complete_content, policy_data)
                
                # Add delay between calls to avoid rate limits
                time.sleep(30) # nosemgrep: arbitrary-sleep # 30 second delay between continuation calls
                
                # Make continuation call
                print(f"📡 Making continuation call {total_calls + 1}...")
                continuation_response = self._call_claude_with_retry(continuation_prompt, max_retries=3)
                
                # Debug: Check what markers are in the response
                has_continue = "CONTINUE_ANALYSIS" in continuation_response
                has_complete = "ANALYSIS_COMPLETE" in continuation_response
                print(f"🔍 Response markers - CONTINUE_ANALYSIS: {has_continue}, ANALYSIS_COMPLETE: {has_complete}")
                
                # Track if we found the completion marker
                if has_complete:
                    analysis_complete_found = True
                    print(f"🎯 ANALYSIS_COMPLETE marker found in continuation response")
                
                # Append continuation content (remove any duplicate headers)
                cleaned_continuation = self._clean_continuation_response(continuation_response)
                complete_content += "\n\n" + cleaned_continuation
                
                current_response = continuation_response
                total_calls += 1
                
                print(f"✅ Continuation {total_calls - 1} completed. Total content length: {len(complete_content)} characters")
            
            # EXTRA VERIFICATION STEP: If we haven't seen ANALYSIS_COMPLETE, do one more check
            if not analysis_complete_found and total_calls < max_continuations:
                print(f"🔍 No ANALYSIS_COMPLETE marker found yet. Doing verification check...")
                
                # Create a verification prompt to check if analysis is truly complete
                verification_prompt = self._create_verification_prompt(complete_content, policy_data)
                
                time.sleep(30) # nosemgrep: arbitrary-sleep # Rate limit delay
                print(f"📡 Making verification call {total_calls + 1}...")
                verification_response = self._call_claude_with_retry(verification_prompt, max_retries=3)
                
                # Check if verification indicates more content is needed
                if ("CONTINUE_ANALYSIS" in verification_response or 
                    "MORE_RESOURCES" in verification_response or
                    len(verification_response.strip()) > 100):  # If substantial content returned
                    
                    print(f"⚠️ Verification indicates more content needed. Adding verification response.")
                    cleaned_verification = self._clean_continuation_response(verification_response)
                    complete_content += "\n\n" + cleaned_verification
                    continuation_used = True
                    total_calls += 1
                    
                    # Check if verification response has completion marker
                    if "ANALYSIS_COMPLETE" in verification_response:
                        analysis_complete_found = True
                        print(f"🎯 ANALYSIS_COMPLETE marker found in verification response")
                else:
                    print(f"✅ Verification confirms analysis is complete")
                    analysis_complete_found = True
            
            # Final cleanup - remove any remaining continuation markers
            complete_content = complete_content.replace("CONTINUE_ANALYSIS", "").strip()
            complete_content = complete_content.replace("ANALYSIS_COMPLETE", "").strip()
            
            # Final status reporting
            if analysis_complete_found:
                print(f"✅ Analysis completed successfully with completion marker")
            elif total_calls >= max_continuations:
                print(f"⚠️ Analysis stopped due to maximum continuation limit ({max_continuations})")
                print(f"⚠️ Response may be incomplete - consider increasing max_continuations")
            else:
                print(f"✅ Analysis completed based on content analysis")
            
            # Analyze final content for completeness
            final_resource_count = complete_content.count("### ")
            expected_resources = len(policy_data.get('resources_with_policies', []))
            completion_percentage = (final_resource_count / expected_resources * 100) if expected_resources > 0 else 0
            
            print(f"📊 Final analysis: {final_resource_count} resources analyzed out of {expected_resources} expected ({completion_percentage:.1f}%)")
            print(f"🏁 Markdown generation complete: {total_calls} total calls, {len(complete_content)} characters")
            
            return {
                'content': complete_content,
                'continuation_used': continuation_used,
                'total_calls': total_calls,
                'analysis_complete_found': analysis_complete_found,
                'completion_percentage': completion_percentage
            }
            
        except Exception as e:
            raise Exception(f"Markdown continuation generation failed: {str(e)}")    
 
    def _should_continue_analysis(self, response, analysis_complete_found=False):
        """Determine if analysis should continue based on response content"""
        try:
            content = response.strip()
            
            # Debug: Show last 200 characters of response
            last_chars = content[-200:] if len(content) > 200 else content
            print(f"🔍 Checking continuation for response ending with: '...{last_chars}'")
            
            # If we already found ANALYSIS_COMPLETE marker in previous responses, stop
            if analysis_complete_found:
                print(f"✅ Analysis complete marker already found - stopping continuation")
                return False
            
            # If we have ANALYSIS_COMPLETE marker in current response, stop
            if "ANALYSIS_COMPLETE" in content:
                print(f"✅ Analysis complete marker detected - stopping continuation")
                return False
            
            # If we have CONTINUE_ANALYSIS marker, definitely continue
            if "CONTINUE_ANALYSIS" in content:
                print(f"🔄 Continue analysis marker detected - requesting continuation")
                return True
            
            # Check if we have sufficient resource analysis
            resource_count = content.count("### ") 
            has_connections = "**Connections**:" in content
            
            print(f"🔍 Content check - Resources analyzed: {resource_count}, Has connections: {has_connections}")
            
            # If we don't have sufficient resource analysis, continue
            if resource_count < 1 or not has_connections:
                print(f"� Ressource analysis incomplete - requesting continuation")
                return True
            
            # If response appears truncated, continue
            if self._is_markdown_truncated(content):
                print(f"🔍 Response appears truncated - requesting continuation")
                return True
            
            # More conservative approach: continue unless we have strong evidence of completion
            resource_count = content.count("### ")
            connection_count = content.count("**Connections**:")
            
            print(f"🔍 Content analysis - Resources: {resource_count}, Connections: {connection_count}")
            
            # Be more conservative - only stop if we have substantial content AND no truncation indicators
            if resource_count >= 5 and connection_count >= 3:
                # Additional check: look for service diversity
                services_found = set()
                import re
                service_matches = re.findall(r'- \*\*Service\*\*:\s*([^\n]+)', content)
                for match in service_matches:
                    services_found.add(match.strip())
                
                print(f"🔍 Services found: {len(services_found)} - {list(services_found)}")
                
                # Only stop if we have multiple services and good content
                if len(services_found) >= 2:
                    print(f"✅ Content appears complete with {resource_count} resources across {len(services_found)} services")
                    return False
                else:
                    print(f"🔄 Limited service diversity - requesting continuation")
                    return True
            else:
                print(f"🔄 Insufficient content ({resource_count} resources, {connection_count} connections) - requesting continuation")
                return True
            
        except Exception as e:
            print(f"⚠️ Error checking continuation status: {str(e)}, assuming should continue")
            return True  # Changed to True to be more conservative

    def _is_markdown_truncated(self, markdown_content):
        """Check if markdown response appears to be truncated"""
        try:
            content = markdown_content.strip()
            
            # Check for explicit continuation marker first
            if "CONTINUE_ANALYSIS" in content:
                print(f"🔍 Continuation marker detected")
                return True
            
            # Don't check for continuation marker here - that's handled in _should_continue_analysis
            # This method only checks for technical truncation indicators
            truncation_indicators = [
                # Incomplete sentences
                content.endswith('**'),
                content.endswith('- **'),
                content.endswith('```'),
                content.endswith('```json'),
                # Incomplete sections for new format
                content.endswith('### '),
                content.endswith('- **Type**:'),
                content.endswith('- **Service**:'),
                content.endswith('- **Region**:'),
                content.endswith('- **Connections**:'),
                content.endswith('  - **'),
                # Incomplete resource sections
                content.endswith('- **Type**:'),
                content.endswith('- **Service**:'),
                content.endswith('- **Region**:'),
            ]
            
            # Check if any truncation indicator is present
            for indicator in truncation_indicators:
                if indicator:
                    print(f"🔍 Truncation detected: content ends with incomplete element")
                    return True
            
            # Check if content ends abruptly without proper section closure
            lines = content.split('\n')
            if len(lines) > 0:
                last_line = lines[-1].strip()
                
                # If last line is not a complete section or separator, likely truncated
                if (last_line and 
                    not last_line.startswith('---') and 
                    not last_line.endswith('.') and 
                    not last_line.endswith('```') and
                    len(last_line) > 10):  # Avoid flagging short complete lines
                    print(f"🔍 Truncation detected: last line appears incomplete: '{last_line}'")
                    return True
            
            # Check if we have sufficient resource content
            resource_count = content.count("### ")
            connection_count = content.count("**Connections**:")
            
            # If we have very few resources or connections, might be incomplete
            if resource_count > 0 and connection_count < resource_count * 0.5:
                print(f"🔍 Possible truncation: {resource_count} resources but only {connection_count} connection sections")
                return True
            
            print(f"✅ Content appears complete: {len(content)} characters")
            return False
            
        except Exception as e:
            print(f"⚠️ Error checking truncation: {str(e)}, assuming not truncated")
            return False
    
    def _create_continuation_prompt(self, existing_content, policy_data):
        """Create prompt for continuing truncated markdown response"""
        
        # Analyze existing content to determine where to continue
        last_resource = self._extract_last_resource_from_content(existing_content)
        analyzed_resources = self._extract_analyzed_resources_from_content(existing_content)
        
        continuation_prompt = f"""You are continuing a structured markdown resource mapping analysis that was truncated.

EXISTING CONTENT SUMMARY:
- Last resource analyzed: {last_resource}
- Resources already analyzed: {len(analyzed_resources)}
- Content length so far: {len(existing_content)} characters

CONTINUATION REQUIREMENTS:
1. Continue from where the previous response was cut off
2. Maintain the EXACT same structured markdown format
3. Do NOT repeat any content that was already generated
4. Continue with the next resource in sequence
5. When you complete ALL resource analysis, end with "ANALYSIS_COMPLETE" marker
6. If you cannot finish in this response, end with "CONTINUE_ANALYSIS" marker

MARKDOWN FORMAT TO CONTINUE:
Use this exact structure:

### [resource_id]
- **Type**: [resource_type]
- **Service**: [aws_service]
- **Region**: [region]
- **Connections**:
  - **[target_resource_id]**: [relationship_type]

Continue with the next resource in the Resource Dependencies section.

POLICY DATA CONTEXT:
- Account: {policy_data.get('account_id', 'unknown')}
- Total resources to analyze: {len(policy_data.get('resources_with_policies', []))}

ALREADY ANALYZED RESOURCES (do not repeat):
{', '.join(analyzed_resources[:10])}{'...' if len(analyzed_resources) > 10 else ''}

Continue the analysis from where it left off. Do not include any headers or introductory text, just continue with the next resource:"""

        # Add policy data
        policy_json = json.dumps(policy_data, indent=2)
        full_prompt = f"{continuation_prompt}\n\nPOLICY DATA:\n```json\n{policy_json}\n```\n\nContinue the markdown analysis:"
        
        return full_prompt
    
    def _create_verification_prompt(self, existing_content, policy_data):
        """Create prompt to verify if analysis is complete and get any missing resources"""
        
        # Analyze existing content to see what we have
        analyzed_resources = self._extract_analyzed_resources_from_content(existing_content)
        expected_resources = len(policy_data.get('resources_with_policies', []))
        
        verification_prompt = f"""You are verifying the completeness of an AWS resource dependency mapping analysis.

CURRENT ANALYSIS STATUS:
- Resources analyzed so far: {len(analyzed_resources)}
- Expected total resources: {expected_resources}
- Content length: {len(existing_content)} characters

VERIFICATION TASK:
1. Review the provided policy data to identify any resources that were NOT analyzed in the existing content
2. If there are missing resources, analyze them using the same structured markdown format
3. If all resources have been analyzed, respond with "ANALYSIS_COMPLETE"
4. If you find missing resources, provide their analysis and end with "CONTINUE_ANALYSIS" if more might be missing

ALREADY ANALYZED RESOURCES (do not repeat):
{', '.join(analyzed_resources[:15])}{'...' if len(analyzed_resources) > 15 else ''}

MARKDOWN FORMAT FOR ANY MISSING RESOURCES:
### [resource_id]
- **Type**: [resource_type]
- **Service**: [aws_service]
- **Region**: [region]
- **Connections**:
  - **[target_resource_id]**: [relationship_type]

POLICY DATA CONTEXT:
- Account: {policy_data.get('account_id', 'unknown')}
- Total resources to verify: {expected_resources}

Please verify completeness and provide any missing resource analysis:"""

        # Add policy data
        policy_json = json.dumps(policy_data, indent=2)
        full_prompt = f"{verification_prompt}\n\nPOLICY DATA:\n```json\n{policy_json}\n```\n\nVerification response:"
        
        return full_prompt
  
    def _extract_last_resource_from_content(self, content):
        """Extract the last resource being analyzed from existing content"""
        try:
            import re
            # Find all resource headers in new format
            resource_matches = re.findall(r'### ([^\n]+)', content)
            if resource_matches:
                # Get actual resource headers
                actual_resources = resource_matches
                if actual_resources:
                    return actual_resources[-1]
            return "unknown"
        except:
            return "unknown"
    
    def _extract_analyzed_resources_from_content(self, content):
        """Extract all resources that have been analyzed from existing content"""
        try:
            import re
            # Find all resource headers in new format
            resource_matches = re.findall(r'### ([^\n]+)', content)
            if resource_matches:
                # Get actual resource headers
                actual_resources = resource_matches
                return actual_resources
            return []
        except:
            return []
    
    def _clean_continuation_response(self, continuation_response):
        """Clean continuation response to avoid duplicate headers"""
        try:
            content = continuation_response.strip()
            
            # Remove any duplicate main headers that might appear
            lines = content.split('\n')
            cleaned_lines = []
            
            for line in lines:
                # Skip duplicate main headers
                if (line.strip().startswith('# AWS Resource Dependency Mapping') or
                    line.strip().startswith('## Account Overview')):
                    continue
                cleaned_lines.append(line)
            
            return '\n'.join(cleaned_lines)
            
        except Exception as e:
            print(f"⚠️ Error cleaning continuation response: {str(e)}")
            return continuation_response
    
    def _create_markdown_resource_mapping_prompt(self, policy_data, custom_prompt=None):
        """Create specialized prompt for structured markdown resource mapping with continuation support"""
        
        base_prompt = """You are a senior AWS Security Architect specializing in resource dependency mapping and access analysis.

Your task is to analyze AWS resource policies and create a comprehensive resource mapping in structured Markdown format that can be easily parsed by frontend applications for graph visualization.

CRITICAL REQUIREMENTS:
1. Output MUST be structured Markdown with consistent formatting
2. Use specific section headers and formatting patterns for easy parsing
3. Focus ONLY on resource relationships and dependencies
4. Organize resources by unique identifier
5. Provide clear resource relationship data

MARKDOWN OUTPUT STRUCTURE:

# AWS Resource Dependency Mapping

## Resource Relationships
- **Total Resources**: [count]
- **Services Analyzed**: [service_list]

---

## Resource Dependencies

### [resource_id_1]
- **Type**: [resource_type]
- **Service**: [aws_service]
- **Region**: [region]
- **Connections**:
  - **[target_resource_id_1]**: [relationship_type]
  - **[target_resource_id_2]**: [relationship_type]

### [resource_id_2]
- **Type**: [resource_type]
- **Service**: [aws_service]
- **Region**: [region]
- **Connections**:
  - **[target_resource_id_3]**: [relationship_type]
  - **[target_resource_id_4]**: [relationship_type]

---
ANALYSIS FOCUS:
- Identify all resource dependencies and relationships
- Map connections between resources across services
- Focus on cross-service access patterns
- Use clear, consistent identifiers for each resource

FORMATTING RULES:
- Use consistent header levels (##, ###)
- Always include the "---" separator between sections
- Use bullet points with "**Field**:" format for structured data
- Keep descriptions concise but informative
- Ensure each resource has a unique identifier

CONTINUATION LOGIC:
- If you cannot complete the full analysis in one response, end with "CONTINUE_ANALYSIS" marker
- Continue from where previous response ended when continuation is requested
- Maintain consistent formatting throughout
- Do not repeat already analyzed resources
- When analysis is complete, end with "ANALYSIS_COMPLETE" marker

COMPLETION MARKERS:
- Use "CONTINUE_ANALYSIS" if more resources need to be analyzed
- Use "ANALYSIS_COMPLETE" when all resources are finished

Remember: Generate structured Markdown that can be easily parsed to extract resource relationships and metadata for visualization.
"""

        # Add custom prompt if provided
        if custom_prompt:
            base_prompt += f"\n\nADDITIONAL REQUIREMENTS:\n{custom_prompt}\n"

        # Add policy data context
        resources_count = len(policy_data.get('resources_with_policies', []))
        account_id = policy_data.get('account_id', 'unknown')
        
        base_prompt += f"""

POLICY DATA CONTEXT:
- Account: {account_id}
- Resources with policies: {resources_count}
- Analysis scope: Resource-based policies and dependencies
"""

        # Add policy data
        policy_json = json.dumps(policy_data, indent=2)
        full_prompt = f"{base_prompt}\n\nAWS POLICY DATA TO ANALYZE:\n```json\n{policy_json}\n```\n\nGenerate the structured Markdown resource mapping now:"
        
        return full_prompt    

    def _create_single_analysis_prompt(self, infrastructure_data, custom_prompt, analysis_type):
        """Create prompt for single (non-chunked) analysis"""
        # Use the original comprehensive prompt for single analysis
        base_prompt = """You are a senior AWS Solutions Architect and Cloud Security Expert with 15+ years of experience. You have deep expertise in:
- AWS Well-Architected Framework (Security, Reliability, Performance, Cost Optimization, Operational Excellence, Sustainability)
- AWS Security Best Practices and Compliance
- Infrastructure as Code and DevOps practices
- Cost optimization and resource management
- Multi-account strategies and governance

You will analyze the provided AWS infrastructure JSON data and generate a comprehensive, detailed infrastructure report in Markdown format.

IMPORTANT INSTRUCTIONS:
1. Generate a VERY DETAILED report with specific findings and actionable recommendations
2. Use proper Markdown formatting with headers, tables, bullet points, and code blocks
3. Include specific resource names, ARNs, and configurations in your analysis
4. Provide concrete, actionable recommendations with implementation steps
5. Highlight security risks, cost optimization opportunities, and architectural improvements
6. Use tables for structured data presentation
7. Include severity levels (Critical, High, Medium, Low) for findings
8. Provide estimated cost impact where relevant

Generate your report with the following detailed structure:

# AWS Infrastructure Analysis Report

## Executive Summary
- Brief overview of the infrastructure
- Key findings summary (3-5 critical points)
- Overall risk assessment
- Priority recommendations

## Infrastructure Overview
### Account Information
- Account ID and scan details
- Regions and services in use
- Resource distribution by service

### Architecture Summary
- High-level architecture description
- Service interconnections
- Data flow patterns

## Detailed Service Analysis
For each service found, provide detailed analysis with specific findings and recommendations.

## Security Analysis
### IAM and Access Management
### Resource-Based Policies
### Network Security
### Encryption and Data Protection

## Cost Optimization Analysis
### Resource Utilization
### Cost Optimization Opportunities

## Performance and Scalability
### Performance Bottlenecks
### Reliability Assessment

## Best Practices Recommendations
### Immediate Actions (Critical - 0-30 days)
### Short-term Improvements (30-90 days)
### Long-term Strategic Initiatives (90+ days)

## Implementation Roadmap
### Phase 1: Critical Issues (Week 1-2)
### Phase 2: High Priority (Month 1)
### Phase 3: Medium Priority (Month 2-3)
### Phase 4: Long-term (Quarter 2+)

## Conclusion and Next Steps

---

"""

        # Add custom prompt if provided
        if custom_prompt:
            base_prompt += f"\nADDITIONAL REQUIREMENTS:\n{custom_prompt}\n"

        # Add analysis type focus
        if analysis_type != "comprehensive":
            base_prompt += f"\nANALYSIS FOCUS: Emphasize {analysis_type} aspects throughout the report.\n"

        # Add infrastructure data
        infrastructure_json = json.dumps(infrastructure_data, indent=2)
        full_prompt = f"{base_prompt}\nAWS INFRASTRUCTURE DATA TO ANALYZE:\n```json\n{infrastructure_json}\n```\n\nGenerate the detailed Markdown report now:"
        
        return full_prompt
    
    def _call_claude(self, prompt):
        """Call Claude via Bedrock API"""
        try:
            # Prepare the request body for Claude
            body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 100000,  # Large token limit for detailed reports
                "temperature": 0.1,    # Low temperature for consistent, factual analysis
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            }
            
            # Call Bedrock
            response = self.bedrock_client.invoke_model(
                modelId=self.model_id,
                body=json.dumps(body),
                contentType='application/json',
                accept='application/json'
            )
            
            # Parse response
            response_body = json.loads(response['body'].read())
            
            # Extract the generated text
            if 'content' in response_body and len(response_body['content']) > 0:
                return response_body['content'][0]['text']
            else:
                raise Exception("No content in Claude response")
                
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ValidationException':
                raise Exception(f"Invalid request to Bedrock: {str(e)}")
            elif error_code == 'ThrottlingException':
                raise Exception("Bedrock API rate limit exceeded. Please try again later.")
            elif error_code == 'AccessDeniedException':
                raise Exception("Access denied to Bedrock. Check IAM permissions.")
            else:
                raise Exception(f"Bedrock API error: {str(e)}")
        
        except Exception as e:
            error_msg = str(e)
            # Handle specific timeout errors
            if "Read timeout" in error_msg or "timeout" in error_msg.lower():
                raise Exception(f"Bedrock API timeout after 15 minutes - the request was too large or complex. Consider using smaller chunks or reducing the analysis scope: {error_msg}")
            elif "Connection" in error_msg:
                raise Exception(f"Connection error to Bedrock API: {error_msg}")
            else:
                raise Exception(f"Error calling Claude: {error_msg}")
    
    def _count_total_resources(self, infrastructure_data):
        """Count total resources in the infrastructure data"""
        total = 0
        for resource_group in infrastructure_data.get('resources', []):
            total += resource_group.get('resource_count', 0)
        return total
    
    def check_bedrock_access(self):
        """Check if Bedrock is accessible and Claude model is available"""
        try:
            bedrock_client = self.session.client('bedrock', region_name=self.region)
            
            # List available models to check access
            response = bedrock_client.list_foundation_models()
            
            # Check if Claude model is available
            claude_available = any(
                model['modelId'] == self.model_id 
                for model in response.get('modelSummaries', [])
            )
            
            return {
                'bedrock_accessible': True,
                'claude_available': claude_available,
                'model_id': self.model_id,
                'region': self.region,
                'chunking_enabled': True
            }
            
        except Exception as e:
            return {
                'bedrock_accessible': False,
                'claude_available': False,
                'error': str(e),
                'model_id': self.model_id,
                'region': self.region,
                'chunking_enabled': True
            }