# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Cache Service - Intelligent caching for AI reports and dependency graphs
Handles JSON comparison, file management, and cache validation
"""

import os
import json
import hashlib
import logging
from typing import Dict, Any, Optional, Tuple
from pathlib import Path
from deepdiff import DeepDiff
import time

logger = logging.getLogger(__name__)

class InfrastructureCacheService:
    def __init__(self, base_dir: str = "reports_files"):
        self.base_dir = Path(base_dir)
        self.json_files_dir = self.base_dir / "json_files"
        self.ai_reports_dir = self.base_dir / "ai_reports"
        self.dependency_graphs_dir = self.base_dir / "dependency_graphs"
        
        # Create directories if they don't exist
        self._ensure_directories()
        
        # Analysis types supported
        self.analysis_types = ['comprehensive', 'security', 'cost', 'performance']
        
    def _ensure_directories(self):
        """Create cache directories if they don't exist"""
        for directory in [self.json_files_dir, self.ai_reports_dir, self.dependency_graphs_dir]:
            directory.mkdir(parents=True, exist_ok=True)
            logger.info(f"📁 Ensured directory exists: {directory}")
    
    def _generate_content_hash(self, data: Dict[Any, Any]) -> str:
        """Generate a hash for the infrastructure data content"""
        try:
            # Remove dynamic fields that change frequently but don't affect analysis
            cleaned_data = self._clean_data_for_hashing(data)
            
            # Convert to JSON string with sorted keys for consistent hashing
            json_str = json.dumps(cleaned_data, sort_keys=True, default=str)
            
            # Generate SHA256 hash
            return hashlib.sha256(json_str.encode()).hexdigest()[:16]  # Use first 16 chars
        except Exception as e:
            logger.error(f"❌ Error generating content hash: {e}")
            # Fallback to timestamp-based hash
            return hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]
    
    def _clean_data_for_hashing(self, data: Dict[Any, Any]) -> Dict[Any, Any]:
        """Remove dynamic fields that don't affect analysis results"""
        cleaned = data.copy()
        
        # Remove fields that change frequently but don't affect infrastructure analysis
        dynamic_fields = ['scan_time', 'timestamp', 'LastModified', 'CreationDate', 'LastAccessTime']
        
        def remove_dynamic_fields(obj):
            if isinstance(obj, dict):
                return {k: remove_dynamic_fields(v) for k, v in obj.items() 
                       if k not in dynamic_fields}
            elif isinstance(obj, list):
                return [remove_dynamic_fields(item) for item in obj]
            else:
                return obj
        
        return remove_dynamic_fields(cleaned)
    
    def _get_account_id(self, infrastructure_data: Dict[Any, Any]) -> str:
        """Extract account ID from infrastructure data"""
        return infrastructure_data.get('account_id', 'unknown')
    
    def _get_cache_filename(self, account_id: str, content_hash: str, cache_type: str, analysis_type: str = None) -> str:
        """Generate cache filename based on type"""
        if cache_type == 'json':
            return f"{account_id}_{content_hash}.json"
        elif cache_type == 'ai_report':
            return f"{account_id}_{content_hash}_{analysis_type}.json"
        elif cache_type == 'dependency':
            return f"{account_id}_{content_hash}_dependency.json"
        else:
            raise ValueError(f"Unknown cache type: {cache_type}")
    
    def _compare_infrastructure_data(self, data1: Dict[Any, Any], data2: Dict[Any, Any]) -> bool:
        """Compare two infrastructure JSON objects for meaningful differences"""
        try:
            # Clean both datasets
            cleaned_data1 = self._clean_data_for_hashing(data1)
            cleaned_data2 = self._clean_data_for_hashing(data2)
            
            # Use DeepDiff for comprehensive comparison
            diff = DeepDiff(
                cleaned_data1, 
                cleaned_data2,
                ignore_order=True,
                significant_digits=2,  # Ignore minor numerical differences
                exclude_paths=["root['scan_time']", "root['timestamp']"]  # Additional exclusions
            )
            
            # If no differences found, data is the same
            is_same = len(diff) == 0
            
            if not is_same:
                logger.info(f"🔍 Infrastructure data differences detected: {len(diff)} changes")
                logger.debug(f"Differences: {diff}")
            else:
                logger.info("✅ Infrastructure data is identical to cached version")
            
            return is_same
            
        except Exception as e:
            logger.error(f"❌ Error comparing infrastructure data: {e}")
            # If comparison fails, assume data is different to be safe
            return False
    
    def check_ai_report_cache(self, infrastructure_data: Dict[Any, Any], analysis_type: str) -> Tuple[bool, Optional[Dict[Any, Any]]]:
        """
        Check if AI report exists in cache for given infrastructure data and analysis type
        Returns: (cache_hit: bool, cached_report: Optional[Dict])
        """
        try:
            account_id = self._get_account_id(infrastructure_data)
            content_hash = self._generate_content_hash(infrastructure_data)
            
            logger.info(f"🔍 Checking AI report cache for account: {account_id}, type: {analysis_type}")
            
            # Check if we have any cached reports for this account
            cached_files = list(self.ai_reports_dir.glob(f"{account_id}_*_{analysis_type}.json"))
            
            if not cached_files:
                logger.info(f"📭 No cached AI reports found for account {account_id} with type {analysis_type}")
                return False, None
            
            # Check each cached file
            for cached_file in cached_files:
                try:
                    # Extract hash from filename
                    filename_parts = cached_file.stem.split('_')
                    if len(filename_parts) >= 3:
                        cached_hash = filename_parts[1]
                        
                        # Try to find corresponding JSON file
                        json_filename = f"{account_id}_{cached_hash}.json"
                        json_file_path = self.json_files_dir / json_filename
                        
                        if json_file_path.exists():
                            # Load and compare JSON data
                            with open(json_file_path, 'r', encoding='utf-8') as f:
                                cached_json_data = json.load(f)
                            
                            if self._compare_infrastructure_data(infrastructure_data, cached_json_data):
                                # Data matches, load and return cached report
                                with open(cached_file, 'r', encoding='utf-8') as f:
                                    cached_report = json.load(f)
                                
                                logger.info(f"🎯 Cache HIT! Found matching AI report: {cached_file.name}")
                                return True, cached_report
                
                except Exception as e:
                    logger.error(f"❌ Error processing cached file {cached_file}: {e}")
                    continue
            
            logger.info(f"📭 No matching cached AI reports found for account {account_id}")
            return False, None
            
        except Exception as e:
            logger.error(f"❌ Error checking AI report cache: {e}")
            return False, None
    
    def check_dependency_graph_cache(self, infrastructure_data: Dict[Any, Any]) -> Tuple[bool, Optional[Dict[Any, Any]]]:
        """
        Check if dependency graph exists in cache for given infrastructure data
        Returns: (cache_hit: bool, cached_graph: Optional[Dict])
        """
        try:
            account_id = self._get_account_id(infrastructure_data)
            content_hash = self._generate_content_hash(infrastructure_data)
            
            logger.info(f"🔍 Checking dependency graph cache for account: {account_id}")
            
            # Check if we have any cached dependency graphs for this account
            cached_files = list(self.dependency_graphs_dir.glob(f"{account_id}_*_dependency.json"))
            
            if not cached_files:
                logger.info(f"📭 No cached dependency graphs found for account {account_id}")
                return False, None
            
            # Check each cached file
            for cached_file in cached_files:
                try:
                    # Extract hash from filename
                    filename_parts = cached_file.stem.split('_')
                    if len(filename_parts) >= 3:
                        cached_hash = filename_parts[1]
                        
                        # Try to find corresponding JSON file
                        json_filename = f"{account_id}_{cached_hash}.json"
                        json_file_path = self.json_files_dir / json_filename
                        
                        if json_file_path.exists():
                            # Load and compare JSON data
                            with open(json_file_path, 'r', encoding='utf-8') as f:
                                cached_json_data = json.load(f)
                            
                            if self._compare_infrastructure_data(infrastructure_data, cached_json_data):
                                # Data matches, load and return cached graph
                                with open(cached_file, 'r', encoding='utf-8') as f:
                                    cached_graph = json.load(f)
                                
                                logger.info(f"🎯 Cache HIT! Found matching dependency graph: {cached_file.name}")
                                return True, cached_graph
                
                except Exception as e:
                    logger.error(f"❌ Error processing cached file {cached_file}: {e}")
                    continue
            
            logger.info(f"📭 No matching cached dependency graphs found for account {account_id}")
            return False, None
            
        except Exception as e:
            logger.error(f"❌ Error checking dependency graph cache: {e}")
            return False, None
    
    def cache_ai_report(self, infrastructure_data: Dict[Any, Any], analysis_type: str, report_data: Dict[Any, Any]) -> bool:
        """Cache AI report data"""
        try:
            account_id = self._get_account_id(infrastructure_data)
            content_hash = self._generate_content_hash(infrastructure_data)
            
            # Save original JSON file
            json_filename = self._get_cache_filename(account_id, content_hash, 'json')
            json_file_path = self.json_files_dir / json_filename
            
            with open(json_file_path, 'w', encoding='utf-8') as f:
                json.dump(infrastructure_data, f, indent=2, default=str)
            
            # Save AI report
            report_filename = self._get_cache_filename(account_id, content_hash, 'ai_report', analysis_type)
            report_file_path = self.ai_reports_dir / report_filename
            
            # Add cache metadata to report
            report_with_metadata = report_data.copy()
            report_with_metadata['cache_metadata'] = {
                'cached_at': time.time(),
                'account_id': account_id,
                'content_hash': content_hash,
                'analysis_type': analysis_type,
                'cache_version': '1.0'
            }
            
            with open(report_file_path, 'w', encoding='utf-8') as f:
                json.dump(report_with_metadata, f, indent=2, default=str)
            
            logger.info(f"💾 Cached AI report: {report_filename}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error caching AI report: {e}")
            return False
    
    def cache_dependency_graph(self, infrastructure_data: Dict[Any, Any], graph_data: Dict[Any, Any]) -> bool:
        """Cache dependency graph data"""
        try:
            account_id = self._get_account_id(infrastructure_data)
            content_hash = self._generate_content_hash(infrastructure_data)
            
            # Save original JSON file
            json_filename = self._get_cache_filename(account_id, content_hash, 'json')
            json_file_path = self.json_files_dir / json_filename
            
            with open(json_file_path, 'w', encoding='utf-8') as f:
                json.dump(infrastructure_data, f, indent=2, default=str)
            
            # Save dependency graph
            graph_filename = self._get_cache_filename(account_id, content_hash, 'dependency')
            graph_file_path = self.dependency_graphs_dir / graph_filename
            
            # Add cache metadata to graph
            graph_with_metadata = graph_data.copy()
            graph_with_metadata['cache_metadata'] = {
                'cached_at': time.time(),
                'account_id': account_id,
                'content_hash': content_hash,
                'cache_version': '1.0'
            }
            
            with open(graph_file_path, 'w', encoding='utf-8') as f:
                json.dump(graph_with_metadata, f, indent=2, default=str)
            
            logger.info(f"💾 Cached dependency graph: {graph_filename}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error caching dependency graph: {e}")
            return False
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        try:
            stats = {
                'json_files_count': len(list(self.json_files_dir.glob('*.json'))),
                'ai_reports_count': len(list(self.ai_reports_dir.glob('*.json'))),
                'dependency_graphs_count': len(list(self.dependency_graphs_dir.glob('*.json'))),
                'total_cache_size_mb': 0,
                'analysis_types_breakdown': {}
            }
            
            # Calculate total size
            for directory in [self.json_files_dir, self.ai_reports_dir, self.dependency_graphs_dir]:
                for file_path in directory.glob('*.json'):
                    stats['total_cache_size_mb'] += file_path.stat().st_size
            
            stats['total_cache_size_mb'] = round(stats['total_cache_size_mb'] / (1024 * 1024), 2)
            
            # Analysis types breakdown
            for analysis_type in self.analysis_types:
                count = len(list(self.ai_reports_dir.glob(f'*_{analysis_type}.json')))
                stats['analysis_types_breakdown'][analysis_type] = count
            
            return stats
            
        except Exception as e:
            logger.error(f"❌ Error getting cache stats: {e}")
            return {}
    
    def cleanup_old_cache(self, max_age_days: int = 30) -> int:
        """Clean up cache files older than specified days"""
        try:
            current_time = time.time()
            max_age_seconds = max_age_days * 24 * 60 * 60
            cleaned_count = 0
            
            for directory in [self.json_files_dir, self.ai_reports_dir, self.dependency_graphs_dir]:
                for file_path in directory.glob('*.json'):
                    file_age = current_time - file_path.stat().st_mtime
                    if file_age > max_age_seconds:
                        file_path.unlink()
                        cleaned_count += 1
                        logger.info(f"🗑️ Cleaned old cache file: {file_path.name}")
            
            logger.info(f"🧹 Cache cleanup completed. Removed {cleaned_count} old files.")
            return cleaned_count
            
        except Exception as e:
            logger.error(f"❌ Error during cache cleanup: {e}")
            return 0
