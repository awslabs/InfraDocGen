# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Report Synthesis - Combine chunk analysis results into cohesive final report
"""

import json
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class ReportSynthesizer:
    def __init__(self):
        self.synthesis_prompt_template = """You are a senior AWS Solutions Architect creating the FINAL COMPREHENSIVE REPORT by combining analysis from multiple infrastructure chunks.

CONTEXT: You have received detailed analysis from multiple specialized teams who analyzed different parts of the same AWS infrastructure:

{chunk_summaries}

Your task is to create a UNIFIED, COHESIVE report that reads as if written by one expert, not multiple disconnected analyses.

CRITICAL REQUIREMENTS:
1. Write a comprehensive Executive Summary that synthesizes ALL findings across chunks
2. Create smooth transitions between sections
3. Identify cross-service patterns, relationships, and dependencies
4. Provide unified recommendations that consider all services together
5. Maintain consistent tone and expertise level throughout
6. Eliminate redundancy while preserving important details
7. Create an integrated implementation roadmap
8. Provide holistic cost and security impact analysis

REPORT STRUCTURE:
Generate a detailed Markdown report with the following structure:

# AWS Infrastructure Analysis Report

## Executive Summary
- Synthesized overview of the entire infrastructure
- Key findings across all service categories (3-5 critical points)
- Overall risk assessment and security posture
- Priority recommendations with business impact

## Infrastructure Overview
### Account Information
- Account details and scan metadata
- Architecture summary and service distribution
- Regional deployment patterns

### Service Ecosystem Analysis
- How services interconnect and depend on each other
- Data flow patterns and architectural decisions
- Scalability and reliability assessment

## Integrated Service Analysis
{service_analysis_structure}

## Cross-Service Security Analysis
### Unified Security Posture
- Overall security assessment combining all services
- Cross-service access patterns and risks
- Integrated policy recommendations

### Identity and Access Management
- Comprehensive IAM analysis across all services
- Resource-based policy optimization
- Access control improvements

## Comprehensive Cost Optimization
### Infrastructure-Wide Cost Analysis
- Total cost optimization opportunities
- Cross-service cost relationships
- Integrated savings recommendations with ROI

### Resource Utilization Assessment
- Overall utilization patterns
- Right-sizing opportunities across services
- Elimination of redundant resources

## Performance and Reliability Assessment
### System-Wide Performance Analysis
- End-to-end performance considerations
- Bottlenecks and scaling limitations
- Integrated performance improvements

### Reliability and Disaster Recovery
- Overall system resilience
- Single points of failure across services
- Integrated backup and recovery strategy

## Unified Best Practices Recommendations
### Immediate Actions (Critical - 0-30 days)
- Cross-service critical fixes prioritized by impact
- Security vulnerabilities requiring immediate attention
- High-impact cost optimizations

### Short-term Improvements (30-90 days)
- Integrated architectural improvements
- Cross-service operational enhancements
- Performance and security upgrades

### Long-term Strategic Initiatives (90+ days)
- Architectural modernization roadmap
- Advanced automation and DevOps integration
- Strategic technology adoption

## Integrated Implementation Roadmap
### Phase 1: Foundation (Week 1-4)
- Critical security and cost fixes
- Cross-service dependency resolution

### Phase 2: Optimization (Month 2-3)
- Performance improvements
- Operational efficiency gains

### Phase 3: Modernization (Month 4-6)
- Advanced features and automation
- Strategic architectural improvements

## Risk Assessment and Compliance
### Overall Risk Profile
- Integrated risk assessment across all services
- Compliance posture and gaps
- Mitigation strategies

### Governance and Monitoring
- Unified monitoring and alerting strategy
- Governance framework recommendations
- Operational procedures

## Conclusion and Success Metrics
- Summary of integrated recommendations
- Success metrics and KPIs for measuring improvement
- Next steps and follow-up actions

---

CHUNK ANALYSIS RESULTS:
{chunk_results}

Generate the comprehensive, unified report now. Ensure it flows naturally and provides integrated insights that wouldn't be possible from analyzing services in isolation.
"""

    def synthesize_reports(self, chunk_results, infrastructure_metadata, custom_prompt=None, analysis_type="comprehensive"):
        """
        Combine chunk analysis results into a cohesive final report
        """
        logger.info(f"Synthesizing {len(chunk_results)} chunk results into final report...")
        
        try:
            # Prepare chunk summaries for context
            chunk_summaries = self._create_chunk_summaries(chunk_results)
            
            # Structure service analysis sections
            service_analysis_structure = self._create_service_analysis_structure(chunk_results)
            
            # Format chunk results for synthesis
            formatted_chunk_results = self._format_chunk_results(chunk_results)
            
            # Create synthesis prompt
            synthesis_prompt = self.synthesis_prompt_template.format(
                chunk_summaries=chunk_summaries,
                service_analysis_structure=service_analysis_structure,
                chunk_results=formatted_chunk_results
            )
            
            # Add custom prompt if provided
            if custom_prompt:
                synthesis_prompt += f"\n\nADDITIONAL REQUIREMENTS:\n{custom_prompt}\n"
            
            # Add analysis type focus
            if analysis_type != "comprehensive":
                synthesis_prompt += f"\n\nANALYSIS FOCUS: Emphasize {analysis_type} aspects throughout the report while maintaining comprehensive coverage.\n"
            
            return {
                "synthesis_prompt": synthesis_prompt,
                "chunk_count": len(chunk_results),
                "metadata": infrastructure_metadata,
                "analysis_type": analysis_type
            }
            
        except Exception as e:
            logger.warning(f"Error synthesizing reports: {str(e)}")
            raise
    
    def _create_chunk_summaries(self, chunk_results):
        """Create summary of what each chunk analyzed"""
        summaries = []
        
        for chunk_name, result in chunk_results.items():
            # Extract key information from chunk result
            chunk_info = result.get("chunk_info", {})
            summary = f"- **{chunk_name.title()} Team**: Analyzed {chunk_info.get('analysis_focus', 'infrastructure components')}"
            
            # Add resource count if available
            if "resource_count" in result:
                summary += f" ({result['resource_count']} resources)"
            
            summaries.append(summary)
        
        return "\n".join(summaries)
    
    def _create_service_analysis_structure(self, chunk_results):
        """Create the service analysis section structure"""
        sections = []
        
        for chunk_name, result in chunk_results.items():
            section_title = chunk_name.replace('_', ' ').title()
            sections.append(f"### {section_title}")
            sections.append(f"- Detailed analysis from {chunk_name} chunk")
            sections.append(f"- Integration with other services")
            sections.append(f"- Specific recommendations and findings")
            sections.append("")
        
        return "\n".join(sections)
    
    def _format_chunk_results(self, chunk_results):
        """Format chunk results for inclusion in synthesis prompt"""
        formatted_results = []
        
        for chunk_name, result in chunk_results.items():
            formatted_results.append(f"## {chunk_name.upper()} CHUNK ANALYSIS:")
            
            # Include the actual analysis content
            if isinstance(result, dict) and "analysis_content" in result:
                formatted_results.append(result["analysis_content"])
            elif isinstance(result, str):
                formatted_results.append(result)
            else:
                formatted_results.append(json.dumps(result, indent=2))
            
            formatted_results.append("\n" + "="*50 + "\n")
        
        return "\n".join(formatted_results)
    
    def create_executive_summary_prompt(self, chunk_results, infrastructure_metadata):
        """Create a focused prompt for executive summary generation"""
        
        prompt = """You are creating an EXECUTIVE SUMMARY for a comprehensive AWS infrastructure analysis.

CONTEXT: Multiple specialized teams have analyzed different parts of the infrastructure:
"""
        
        # Add chunk summaries
        for chunk_name, result in chunk_results.items():
            prompt += f"\n- {chunk_name.title()}: {result.get('key_findings_summary', 'Analysis completed')}"
        
        prompt += f"""

INFRASTRUCTURE OVERVIEW:
- Account: {infrastructure_metadata.get('account_id', 'unknown')}
- Total Resources: {infrastructure_metadata.get('total_resource_count', 'unknown')}
- Services: {len(infrastructure_metadata.get('services_scanned', []))}
- Regions: {len(infrastructure_metadata.get('regions_scanned', []))}

Create a concise but comprehensive executive summary (3-4 paragraphs) that:
1. Provides overall infrastructure assessment
2. Highlights 3-5 most critical findings across all services
3. Summarizes key risks and opportunities
4. Gives clear priority recommendations for leadership

Focus on business impact and strategic recommendations rather than technical details.
"""
        
        return prompt
    
    def extract_key_metrics(self, chunk_results):
        """Extract key metrics from chunk results for dashboard/summary"""
        metrics = {
            "total_findings": 0,
            "critical_issues": 0,
            "cost_savings_opportunities": 0,
            "security_risks": 0,
            "performance_issues": 0,
            "services_analyzed": set(),
            "regions_covered": set()
        }
        
        for chunk_name, result in chunk_results.items():
            # Extract metrics from each chunk result
            if isinstance(result, dict):
                metrics["services_analyzed"].update(result.get("services_included", []))
                
                # Count findings by severity (if structured)
                findings = result.get("findings", [])
                if isinstance(findings, list):
                    metrics["total_findings"] += len(findings)
                    metrics["critical_issues"] += len([f for f in findings if f.get("severity") == "Critical"])
        
        # Convert sets to counts
        metrics["services_analyzed"] = len(metrics["services_analyzed"])
        metrics["regions_covered"] = len(metrics["regions_covered"])
        
        return metrics
