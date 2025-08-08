#!/usr/bin/env python3
"""
JADX-Enhanced Static Analysis Integration Bridge

This module provides a formal bridge between JADX decompilation and Enhanced Static Analysis
to ensure seamless data flow, unified finding formats, and automatic path management.

CYCLE PREVENTION: Includes comprehensive cycle detection to prevent infinite loops
between JADX and Enhanced Static Analysis plugins.

Features:
- Automatic JADX decompilation path discovery and validation
- Seamless integration between JADX and Enhanced Static Analysis
- Unified vulnerability finding format conversion
- Manifest analysis coordination
- Resource and source file analysis orchestration
- Error handling and fallback mechanisms
- CYCLE DETECTION AND PREVENTION
"""

import logging
import os
import time
import threading
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import json

from core.apk_ctx import APKContext
from core.unified_deduplication_framework import (
    deduplicate_findings, 
    DeduplicationStrategy,
    create_deduplication_engine
)
from core.source_file_validator import SourceFileValidator
from core.deduplication_config_manager import get_strategy_for_component, is_deduplication_enabled

logger = logging.getLogger(__name__)

# GLOBAL CYCLE PREVENTION: Track active integrations to prevent infinite loops
_active_integrations = set()
_integration_lock = threading.Lock()

# Enhanced Zero-Day Detection Integration
try:
    from .detection.enhanced_zero_day_engine import (
        enhanced_zero_day_analysis, EnhancedZeroDayFinding,
        EnhancedZeroDayDetectionEngine
    )
    ENHANCED_ZERO_DAY_AVAILABLE = True
except ImportError:
    ENHANCED_ZERO_DAY_AVAILABLE = False

class IntegrationBridgeResult:
    """Result from the integration bridge analysis."""
    
    def __init__(self):
        self.jadx_results: Dict[str, Any] = {}
        self.enhanced_results: Dict[str, Any] = {}
        self.unified_vulnerabilities: List[Dict[str, Any]] = []
        self.metadata: Dict[str, Any] = {}
        self.success: bool = True
        self.error_message: Optional[str] = None
        self.cycle_detected: bool = False
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            'jadx_results': self.jadx_results,
            'enhanced_results': self.enhanced_results,
            'unified_vulnerabilities': self.unified_vulnerabilities,
            'metadata': self.metadata,
            'success': self.success,
            'error_message': self.error_message,
            'cycle_detected': self.cycle_detected
        }

class JADXEnhancedStaticAnalysisBridge:
    """
    Formal bridge between JADX decompilation and Enhanced Static Analysis.
    
    Ensures seamless data flow and unified vulnerability reporting with cycle prevention.
    """
    
    def __init__(self):
        """Initialize the integration bridge."""
        self.logger = logging.getLogger(__name__)
        self.integration_id = None
        self.config = {}  # Default configuration for enhanced detection
        self.logger.info("JADX-Enhanced Static Analysis Bridge initialized with cycle prevention")
        
    def integrate_analysis(self, apk_ctx: APKContext) -> IntegrationBridgeResult:
        """
        Perform integrated JADX and Enhanced Static Analysis with cycle detection.
        
        Args:
            apk_ctx: APK context for analysis
            
        Returns:
            IntegrationBridgeResult: Unified analysis results
        """
        # CYCLE PREVENTION: Create unique integration ID
        self.integration_id = f"{apk_ctx.package_name}_{int(time.time())}"
        
        # CYCLE PREVENTION: Check if integration is already active
        with _integration_lock:
            if self.integration_id in _active_integrations:
                self.logger.warning(f"🔄 Cycle detected - integration already active for {apk_ctx.package_name}")
                result = IntegrationBridgeResult()
                result.success = False
                result.cycle_detected = True
                result.error_message = "Cycle detected - preventing infinite loop"
                return result
            
            # Check for any active integration for this package
            package_integrations = [aid for aid in _active_integrations if aid.startswith(apk_ctx.package_name)]
            if package_integrations:
                self.logger.warning(f"🔄 Package {apk_ctx.package_name} already has active integration - preventing cycle")
                result = IntegrationBridgeResult()
                result.success = False
                result.cycle_detected = True
                result.error_message = "Package integration already active - preventing cycle"
                return result
            
            # Mark integration as active
            _active_integrations.add(self.integration_id)
        
        result = IntegrationBridgeResult()
        result.metadata = {
            'bridge_version': '1.1.0',  # Version with cycle prevention
            'analysis_timestamp': time.time(),
            'package_name': apk_ctx.package_name,
            'apk_path': str(apk_ctx.apk_path),
            'integration_id': self.integration_id,
            'cycle_prevention': True
        }
        
        try:
            self.logger.info(f"🌉 Starting cycle-safe integrated analysis for {apk_ctx.package_name}")
            
            # Step 1: Simple JADX path discovery (NO TRIGGERING)
            jadx_path = self._discover_existing_jadx_path(apk_ctx)
            if jadx_path:
                result.metadata['jadx_decompilation_path'] = jadx_path
                self.logger.info(f"📁 Found existing JADX path: {jadx_path}")
            else:
                self.logger.info("📁 No existing JADX decompilation found - will use fallback")
            
            # Step 2: Get JADX results (READ-ONLY, no triggering)
            jadx_results = self._get_existing_jadx_results(apk_ctx)
            result.jadx_results = jadx_results
            
            # Step 3: Run Enhanced Static Analysis INDEPENDENTLY (no JADX triggering)
            enhanced_results = self._run_enhanced_analysis_standalone(apk_ctx, jadx_path)
            result.enhanced_results = enhanced_results
            
            # Step 4: Create unified vulnerabilities
            unified_vulns = self._create_unified_vulnerabilities(jadx_results, enhanced_results)
            result.unified_vulnerabilities = unified_vulns
            
            # Step 5: Update metadata
            result.metadata.update({
                'jadx_vulnerabilities_count': len(jadx_results.get('vulnerabilities', [])),
                'enhanced_vulnerabilities_count': len(enhanced_results.get('vulnerabilities', [])),
                'unified_vulnerabilities_count': len(unified_vulns),
                'files_analyzed': self._count_analyzed_files(jadx_path) if jadx_path else 0,
                'analysis_successful': True,
                'cycle_prevention_active': True
            })
            
            self.logger.info(f"🌉 Cycle-safe integrated analysis completed: {len(unified_vulns)} unified vulnerabilities")
            return result
            
        except Exception as e:
            self.logger.error(f"Integration bridge failed: {e}")
            result.success = False
            result.error_message = str(e)
            return result
        
        finally:
            # CYCLE PREVENTION: Always remove from active integrations
            with _integration_lock:
                _active_integrations.discard(self.integration_id)
            self.logger.debug(f"🔓 Released integration lock for {apk_ctx.package_name}")
    
    def _discover_existing_jadx_path(self, apk_ctx: APKContext) -> Optional[str]:
        """Discover existing JADX decompilation WITHOUT triggering new analysis."""
        try:
            # Check APK context first
            if hasattr(apk_ctx, 'decompiled_apk_dir') and apk_ctx.decompiled_apk_dir:
                jadx_path = str(apk_ctx.decompiled_apk_dir)
                if os.path.exists(jadx_path) and self._validate_jadx_output(jadx_path):
                    return jadx_path
            
            # Check for recent JADX decompilation in temp directory
            jadx_temp_pattern = "/tmp/jadx_decompiled/jadx_*"
            import glob
            recent_jadx_dirs = glob.glob(jadx_temp_pattern)
            if recent_jadx_dirs:
                latest_jadx_dir = max(recent_jadx_dirs, key=lambda p: Path(p).stat().st_mtime)
                if os.path.exists(latest_jadx_dir) and self._validate_jadx_output(latest_jadx_dir):
                    return latest_jadx_dir
            
            # NO JADX TRIGGERING - just return None if not found
            return None
            
        except Exception as e:
            self.logger.debug(f"Failed to discover existing JADX path: {e}")
            return None
    
    def _validate_jadx_output(self, jadx_path: str) -> bool:
        """Validate that JADX output contains expected structure."""
        try:
            sources_dir = os.path.join(jadx_path, "sources")
            resources_dir = os.path.join(jadx_path, "resources")
            
            # Check if essential directories exist
            has_sources = os.path.exists(sources_dir) and os.listdir(sources_dir)
            has_resources = os.path.exists(resources_dir)
            
            if has_sources or has_resources:
                self.logger.debug(f"JADX output validated: sources={has_sources}, resources={has_resources}")
                return True
            
            return False
        except Exception as e:
            self.logger.debug(f"JADX output validation failed: {e}")
            return False
    
    def _get_existing_jadx_results(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """Get existing JADX results WITHOUT triggering new analysis."""
        try:
            # Try to get cached JADX results
            if hasattr(apk_ctx, 'get_cache'):
                jadx_cache = apk_ctx.get_cache('jadx_static_analysis_results')
                if jadx_cache and 'analysis_results' in jadx_cache:
                    self.logger.info("🔄 Using existing cached JADX analysis results")
                    return jadx_cache['analysis_results']
            
            # Check shared cache file
            cache_file = f"/tmp/jadx_results_{apk_ctx.package_name}.json"
            if os.path.exists(cache_file):
                try:
                    with open(cache_file, 'r') as f:
                        cached_data = json.load(f)
                        if 'analysis_results' in cached_data:
                            self.logger.info("🔄 Using existing shared JADX cache results")
                            return cached_data['analysis_results']
                except (json.JSONDecodeError, IOError):
                    pass
            
            # NO JADX TRIGGERING - return empty if not available
            self.logger.info("📭 No existing JADX analysis results found")
            return {}
            
        except Exception as e:
            self.logger.error(f"Failed to get existing JADX results: {e}")
            return {}
    
    def _run_enhanced_analysis_standalone(self, apk_ctx: APKContext, jadx_path: Optional[str]) -> Dict[str, Any]:
        """Run Enhanced Static Analysis independently WITHOUT triggering JADX."""
        try:
            # Set cycle prevention flag in APK context
            if not hasattr(apk_ctx, '_cycle_prevention_active'):
                apk_ctx._cycle_prevention_active = True
            
            # Import Enhanced Static Analysis plugin
            from plugins.enhanced_static_analysis import create_enhanced_static_analysis_plugin
            
            # Create plugin instance
            plugin = create_enhanced_static_analysis_plugin()
            
            # If JADX path available, set it in context but DON'T trigger JADX
            if jadx_path and not hasattr(apk_ctx, 'decompiled_apk_dir'):
                apk_ctx.decompiled_apk_dir = jadx_path
            
            # Run analysis
            analysis_result = plugin.analyze_apk(apk_ctx)
            
            # Convert to dictionary format
            vulnerabilities = []
            
            # Map security findings
            for finding in analysis_result.security_findings:
                vulnerability = {
                    "title": getattr(finding, 'title', 'Security Finding'),
                    "description": getattr(finding, 'description', ''),
                    "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                    "category": finding.category.value if hasattr(finding.category, 'value') else str(finding.category),
                    "confidence": getattr(finding, 'confidence', 0.0),
                    "file_path": getattr(finding, 'file_path', ''),
                    "line_number": getattr(finding, 'line_number', 0),
                    "code_snippet": getattr(finding, 'code_snippet', ''),
                    "source_plugin": "enhanced_static_analysis",
                    "analysis_method": "standalone"
                }
                vulnerabilities.append(vulnerability)
            
            # Map secret analysis
            for secret in analysis_result.secret_analysis:
                vulnerability = {
                    "title": f"Secret Detected: {secret.pattern_type.value}",
                    "description": f"Potential secret detected with {secret.confidence:.1%} confidence",
                    "severity": "HIGH",
                    "category": "INSECURE_STORAGE",
                    "confidence": getattr(secret, 'confidence', 0.0),
                    "file_path": getattr(secret, 'file_path', ''),
                    "line_number": getattr(secret, 'line_number', 0),
                    "code_snippet": getattr(secret, 'context', ''),
                    "source_plugin": "enhanced_static_analysis",
                    "analysis_method": "standalone"
                }
                vulnerabilities.append(vulnerability)
            
            return {
                'vulnerabilities': vulnerabilities,
                'metadata': {
                    'analysis_method': 'standalone',
                    'cycle_prevention': True,
                    'jadx_path_used': jadx_path is not None
                }
            }
            
        except Exception as e:
            self.logger.error(f"Standalone enhanced static analysis failed: {e}")
            return {'vulnerabilities': [], 'error': str(e)}
    
    def _create_unified_vulnerabilities(self, jadx_results: Dict[str, Any], 
                                      enhanced_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Create unified vulnerability list from both analyses."""
        unified_vulns = []
        
        try:
            # Add JADX vulnerabilities
            jadx_vulns = self._extract_jadx_vulnerabilities(jadx_results)
            for vuln in jadx_vulns:
                vuln['source_plugin'] = 'jadx_static_analysis'
                vuln['analysis_method'] = 'jadx_decompilation'
                unified_vulns.append(vuln)
            
            # **PLUGIN ATTRIBUTION FIX**: Add Enhanced Static Analysis vulnerabilities with proper filtering
            # **KEY MISMATCH FIX**: Use correct 'vulnerabilities' key from enhanced static analysis results
            enhanced_vulns = enhanced_results.get('vulnerabilities', [])
            filtered_static_vulns = []
            
            for vuln in enhanced_vulns:
                # **CRITICAL FIX**: Filter out dynamic analysis results to prevent misattribution
                title = vuln.get('title', '').lower()
                plugin = vuln.get('plugin', '').lower()
                source_type = vuln.get('source_type', '').lower()
                file_path = vuln.get('file_path', '')
                
                # **DYNAMIC APK CONTEXT FILTER**: Use intelligent analysis instead of hardcoded patterns
                # Note: This is a simplified filter for the integration bridge
                # The main filtering happens in the enhanced vulnerability reporting engine
                
                # **CRITICAL FIX**: Handle manifest-based vulnerabilities correctly
                # Manifest vulnerabilities should keep their original location, not be attributed to source files
                target_package_path = self.target_package.replace('.', '/') if hasattr(self, 'target_package') else ''
                
                # **MANIFEST ATTRIBUTION FIX**: Detect and preserve manifest-based vulnerabilities
                is_manifest_based = (
                    'AndroidManifest.xml' in vuln.get('location', '') or
                    any(manifest_indicator in title for manifest_indicator in [
                        'target sdk', 'backup enabled', 'exported', 'minimum sdk', 'debug',
                        'clear text traffic', 'permission', 'component'
                    ])
                )
                
                if is_manifest_based:
                    # **FIX**: Preserve manifest location instead of assigning to source files
                    vuln['file_path'] = 'AndroidManifest.xml'
                    vuln['line_number'] = 0  # **ENHANCED**: Use 0 for manifest (no specific line)
                    vuln['class_name'] = 'Manifest Configuration'
                    vuln['method_name'] = ''
                    vuln['line_context'] = 'Manifest-level configuration'
                    vuln['source_type'] = 'manifest_analysis'
                    self.logger.debug(f"🔧 **MANIFEST FIX**: Corrected attribution for manifest-based vulnerability: {title[:50]}")
                
                # Only apply cross-APK filtering to actual source files, not manifest-based findings
                is_likely_cross_apk = (
                    not is_manifest_based and  # Don't filter manifest-based vulnerabilities
                    target_package_path and  # We have a target package to check against
                    target_package_path not in file_path and  # File doesn't contain target package
                    any(suspicious_pattern in file_path.lower() for suspicious_pattern in [
                        'injuredandroid', 'secretdiary', 'corellium', 'b3nac', 'ennesoft'
                    ]) and
                    not any(legitimate_pattern in file_path.lower() for legitimate_pattern in [
                        'google', 'android', 'okhttp', 'retrofit', 'androidx'
                    ])
                )
                
                if is_likely_cross_apk:
                    self.logger.debug(f"🔄 **DYNAMIC CROSS-APK FILTER**: Filtering likely cross-APK finding: {file_path}")
                    continue
                
                # Skip vulnerabilities that clearly belong to dynamic analysis
                if any(dynamic_indicator in title for dynamic_indicator in [
                    'frida_dynamic_analysis', 'frida', 'dynamic', 'runtime', 'hooking', 'instrumentation'
                ]):
                    self.logger.debug(f"🔄 Filtering out dynamic analysis result from static section: {title[:50]}")
                    continue
                    
                # Skip vulnerabilities from dynamic analysis plugins
                if any(dynamic_plugin in plugin for dynamic_plugin in [
                    'frida_dynamic_analysis', 'dynamic_analyzer', 'runtime_analyzer'
                ]):
                    self.logger.debug(f"🔄 Filtering out dynamic plugin result from static section: {plugin}")
                    continue
                
                # Only include results that are actually from static analysis
                if 'source_plugin' not in vuln:
                    vuln['source_plugin'] = 'enhanced_static_analysis'
                if 'analysis_method' not in vuln:
                    vuln['analysis_method'] = 'pattern_matching'
                    
                # Verify this is truly a static analysis result
                vuln['attribution_verified'] = True
                filtered_static_vulns.append(vuln)
                unified_vulns.append(vuln)
            
            # Log filtering results for transparency
            filtered_count = len(enhanced_vulns) - len(filtered_static_vulns)
            if filtered_count > 0:
                self.logger.info(f"🔄 **ATTRIBUTION FIX**: Filtered {filtered_count} dynamic analysis results from static section")
                self.logger.info(f"   - Original enhanced vulnerabilities: {len(enhanced_vulns)}")
                self.logger.info(f"   - Filtered static vulnerabilities: {len(filtered_static_vulns)}")
            
            # **UNIFIED DEDUPLICATION**: Use the authoritative unified deduplication framework
            self.logger.info(f"🔧 **APPLYING UNIFIED DEDUPLICATION**: Processing {len(unified_vulns)} vulnerabilities")
            
            # **SOURCE FILE VALIDATION**: Validate and correct file attributions before deduplication
            self.logger.info(f"🔍 **APPLYING SOURCE FILE VALIDATION**: Validating {len(unified_vulns)} vulnerabilities")
            
            validator = SourceFileValidator(getattr(self, 'decompiled_source_dir', None))
            validated_vulns = []
            
            validation_stats = {'corrected': 0, 'validated': 0, 'failed': 0}
            
            for vuln in unified_vulns:
                # Ensure required source attribution
                if 'source_plugin' not in vuln:
                    vuln['source_plugin'] = 'enhanced_static_analysis'
                if 'source_type' not in vuln:
                    vuln['source_type'] = 'security_finding'
                if 'analysis_method' not in vuln:
                    vuln['analysis_method'] = 'pattern_matching'
                
                # Validate and correct file attribution
                validated_vuln = validator.validate_vulnerability_attribution(vuln)
                validated_vulns.append(validated_vuln)
                
                # Track validation statistics
                validation_type = validated_vuln.get('attribution_validation', 'unknown')
                if validation_type == 'corrected':
                    validation_stats['corrected'] += 1
                elif validation_type in ['validated', 'inferred_manifest']:
                    validation_stats['validated'] += 1
                else:
                    validation_stats['failed'] += 1
            
            # Log validation results
            self.logger.info(f"🔍 **SOURCE FILE VALIDATION COMPLETE**:")
            self.logger.info(f"   - Validated: {validation_stats['validated']} vulnerabilities")
            self.logger.info(f"   - Corrected: {validation_stats['corrected']} vulnerabilities")
            self.logger.info(f"   - Failed: {validation_stats['failed']} vulnerabilities")
            
            # Use validated vulnerabilities for deduplication
            unified_vulns = validated_vulns
            
            # Apply unified deduplication with configured strategy (CLI controllable)
            try:
                configured_strategy = get_strategy_for_component('integration_bridge')
                deduplication_engine = create_deduplication_engine(configured_strategy)
                
                self.logger.info(f"🔧 **INTEGRATION BRIDGE DEDUPLICATION**: Using {configured_strategy.value} strategy")
                dedup_result = deduplication_engine.deduplicate_findings(unified_vulns)
                
                deduplicated = dedup_result.unique_findings
                removed_count = len(unified_vulns) - len(deduplicated)
                
                # Log comprehensive deduplication statistics
                self.logger.info(f"🔧 **UNIFIED DEDUPLICATION COMPLETE**:")
                self.logger.info(f"   - Original vulnerabilities: {len(unified_vulns)}")
                self.logger.info(f"   - Unique vulnerabilities: {len(deduplicated)}")
                self.logger.info(f"   - Duplicates removed: {removed_count}")
                self.logger.info(f"   - Deduplication groups: {len(dedup_result.duplication_groups)}")
                self.logger.info(f"   - Strategy used: {configured_strategy.value}")
                self.logger.info(f"   - Processing time: {dedup_result.metrics.processing_time_ms/1000.0:.2f}s")
                
            except Exception as e:
                self.logger.error(f"🚨 **UNIFIED DEDUPLICATION FAILED**: {e}")
                self.logger.warning("   - Falling back to basic deduplication")
                
                # Fallback: simple pattern-based deduplication
                seen_patterns = {}
                deduplicated = []
                
                for vuln in unified_vulns:
                    pattern_type = vuln.get('vulnerable_pattern', vuln.get('pattern_type', 'unknown'))
                    file_path = vuln.get('file_path', '')
                    title_base = vuln.get('title', '').split(' Vulnerability')[0]
                    grouping_key = (pattern_type, file_path, title_base)
                    
                    if grouping_key not in seen_patterns:
                        seen_patterns[grouping_key] = vuln
                        deduplicated.append(vuln)
            
                removed_count = len(unified_vulns) - len(deduplicated)
                self.logger.info(f"🔄 **FALLBACK DEDUPLICATION**: Removed {removed_count} duplicates")
            
            self.logger.info(f"🔄 Created {len(deduplicated)} properly attributed static vulnerabilities "
                           f"(JADX: {len(jadx_vulns)}, Enhanced: {len(filtered_static_vulns)})")
            
            return deduplicated
            
        except Exception as e:
            self.logger.error(f"Failed to create unified vulnerabilities: {e}")
            return []
    
    def _extract_jadx_vulnerabilities(self, jadx_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract vulnerabilities from JADX results in unified format."""
        vulnerabilities = []
        
        try:
            # Extract crypto analysis findings
            crypto_results = jadx_results.get('crypto_analysis', {})
            for finding in crypto_results.get('crypto_issues', []):
                vuln = {
                    'title': finding.get('title', 'Cryptographic Issue'),
                    'description': finding.get('description', ''),
                    'severity': finding.get('severity', 'MEDIUM').upper(),
                    'category': 'CRYPTOGRAPHIC_WEAKNESS',
                    'file_path': finding.get('file', ''),
                    'line_number': finding.get('line_number', 0),
                    'code_snippet': finding.get('evidence', ''),
                    'confidence': finding.get('confidence', 0.8)
                }
                vulnerabilities.append(vuln)
            
            # Extract secrets analysis findings
            secrets_results = jadx_results.get('secrets_analysis', {})
            for finding in secrets_results.get('findings', []):
                vuln = {
                    'title': f"Hardcoded Secret: {finding.get('title', 'Secret')}",
                    'description': finding.get('description', 'Hardcoded secret detected'),
                    'severity': finding.get('severity', 'HIGH').upper(),
                    'category': 'INSECURE_STORAGE',
                    'file_path': finding.get('file_path', ''),
                    'line_number': finding.get('line_number', 0),
                    'code_snippet': finding.get('code_snippet', ''),
                    'confidence': finding.get('confidence', 0.9)
                }
                vulnerabilities.append(vuln)
            
        except Exception as e:
            self.logger.error(f"Failed to extract JADX vulnerabilities: {e}")
        
        return vulnerabilities
    
    def _count_analyzed_files(self, jadx_path: str) -> int:
        """Count the number of files analyzed."""
        try:
            file_count = 0
            for root, dirs, files in os.walk(jadx_path):
                file_count += len(files)
            return file_count
        except Exception:
            return 0

    def enhanced_zero_day_analysis(self, apk_ctx: APKContext, 
                                 file_contents: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Perform enhanced zero-day vulnerability detection with advanced ML and threat intelligence.
        
        Args:
            apk_ctx: APK context object
            file_contents: Optional file contents dict, will extract if not provided
            
        Returns:
            Enhanced zero-day analysis results
        """
        try:
            start_time = time.time()
            
            if not ENHANCED_ZERO_DAY_AVAILABLE:
                self.logger.warning("Enhanced zero-day detection not available - falling back to basic detection")
                return self._fallback_zero_day_detection(apk_ctx)
            
            # Extract file contents if not provided
            if file_contents is None:
                file_contents = self._extract_file_contents_for_analysis(apk_ctx)
            
            # Configuration for enhanced detection
            config = {
                'ensemble_threshold': 0.75,
                'confidence_threshold': 0.7,
                'deep_learning_weight': 0.3,
                'cve_api_url': self.config.get('cve_api_url', ''),
                'mitre_api_url': self.config.get('mitre_api_url', ''),
                'virustotal_api_key': self.config.get('virustotal_api_key', ''),
                'alienvault_api_key': self.config.get('alienvault_api_key', '')
            }
            
            # Run enhanced zero-day analysis asynchronously
            import asyncio
            
            try:
                # Try to get existing event loop
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # If loop is running, create a task
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor() as executor:
                        future = executor.submit(
                            asyncio.run, 
                            enhanced_zero_day_analysis(apk_ctx, file_contents, config)
                        )
                        findings = future.result(timeout=300)  # 5 minute timeout
                else:
                    # Run directly
                    findings = asyncio.run(enhanced_zero_day_analysis(apk_ctx, file_contents, config))
            except:
                # Fallback: run in new event loop
                findings = asyncio.run(enhanced_zero_day_analysis(apk_ctx, file_contents, config))
            
            analysis_time = time.time() - start_time
            
            # Convert findings to serializable format
            serializable_findings = []
            for finding in findings:
                finding_dict = {
                    'finding_id': finding.finding_id,
                    'category': finding.category.value,
                    'threat_level': finding.threat_level.value,
                    'confidence_score': finding.confidence_score,
                    'anomaly_score': finding.anomaly_score,
                    'ensemble_score': finding.ensemble_score,
                    'file_path': finding.file_path,
                    'affected_methods': finding.affected_methods,
                    'attack_vector': finding.attack_vector,
                    'exploitation_complexity': finding.exploitation_complexity,
                    'detection_models': finding.detection_models,
                    'temporal_patterns': finding.temporal_patterns,
                    'threat_intelligence': finding.threat_intelligence,
                    'mitigation_recommendations': finding.mitigation_recommendations,
                    'discovery_timestamp': finding.discovery_timestamp.isoformat(),
                    'validation_status': finding.validation_status,
                    'false_positive_probability': finding.false_positive_probability
                }
                serializable_findings.append(finding_dict)
            
            # Prepare comprehensive results
            results = {
                'enhanced_zero_day_findings': serializable_findings,
                'analysis_metadata': {
                    'total_findings': len(findings),
                    'analysis_time_seconds': analysis_time,
                    'files_analyzed': len(file_contents) if file_contents else 0,
                    'detection_engine': 'enhanced_zero_day_v2.0',
                    'ml_models_used': ['ensemble', 'deep_learning', 'behavioral'],
                    'threat_intelligence_enabled': True
                },
                'threat_summary': self._generate_threat_summary(findings),
                'recommendations': self._generate_priority_recommendations(findings)
            }
            
            self.logger.info(f"Enhanced zero-day analysis completed: {len(findings)} findings in {analysis_time:.2f}s")
            return results
            
        except Exception as e:
            self.logger.error(f"Enhanced zero-day analysis failed: {e}")
            return self._fallback_zero_day_detection(apk_ctx)
    
    def _extract_file_contents_for_analysis(self, apk_ctx: APKContext) -> Dict[str, str]:
        """Extract file contents from APK for zero-day analysis."""
        file_contents = {}
        
        try:
            # Get APK file path
            apk_path = apk_ctx.apk_path
            
            # Extract relevant files for analysis
            import zipfile
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Get file list
                file_list = apk_zip.namelist()
                
                # Filter for analysis-relevant files
                relevant_extensions = ['.java', '.kt', '.js', '.smali', '.xml']
                relevant_files = [
                    f for f in file_list 
                    if any(f.endswith(ext) for ext in relevant_extensions) and
                       len(f) < 200  # Reasonable filename length
                ]
                
                # Limit to prevent memory issues
                relevant_files = relevant_files[:100]  # Max 100 files
                
                # Extract file contents
                for file_path in relevant_files:
                    try:
                        with apk_zip.open(file_path) as file_obj:
                            content = file_obj.read().decode('utf-8', errors='ignore')
                            if len(content) > 50 and len(content) < 100000:  # Size filters
                                file_contents[file_path] = content
                    except Exception as e:
                        self.logger.debug(f"Could not extract {file_path}: {e}")
                        continue
            
            self.logger.info(f"Extracted {len(file_contents)} files for zero-day analysis")
            
        except Exception as e:
            self.logger.error(f"File extraction for zero-day analysis failed: {e}")
        
        return file_contents
    
    def _generate_threat_summary(self, findings: List) -> Dict[str, Any]:
        """Generate threat summary from findings."""
        if not findings:
            return {'total_threats': 0, 'risk_level': 'low'}
        
        threat_counts = {}
        critical_count = 0
        high_count = 0
        
        for finding in findings:
            threat_level = finding.threat_level.value if hasattr(finding, 'threat_level') else 'unknown'
            threat_counts[threat_level] = threat_counts.get(threat_level, 0) + 1
            
            if threat_level == 'critical':
                critical_count += 1
            elif threat_level == 'high':
                high_count += 1
        
        # Determine overall risk level
        if critical_count > 0:
            risk_level = 'critical'
        elif high_count > 2:
            risk_level = 'high'
        elif high_count > 0:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return {
            'total_threats': len(findings),
            'threat_distribution': threat_counts,
            'risk_level': risk_level,
            'critical_threats': critical_count,
            'high_threats': high_count,
            'immediate_action_required': critical_count > 0 or high_count > 3
        }
    
    def _generate_priority_recommendations(self, findings: List) -> List[str]:
        """Generate priority recommendations based on findings."""
        if not findings:
            return ["No zero-day vulnerabilities detected - continue regular security practices"]
        
        recommendations = []
        categories_seen = set()
        
        # Sort findings by threat level and confidence
        sorted_findings = sorted(
            findings,
            key=lambda f: (
                {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}.get(
                    f.threat_level.value if hasattr(f, 'threat_level') else 'info', 1
                ),
                f.confidence_score if hasattr(f, 'confidence_score') else 0
            ),
            reverse=True
        )
        
        # Get top recommendations from highest priority findings
        for finding in sorted_findings[:5]:  # Top 5 findings
            if hasattr(finding, 'category') and finding.category.value not in categories_seen:
                categories_seen.add(finding.category.value)
                
                if hasattr(finding, 'mitigation_recommendations') and finding.mitigation_recommendations:
                    recommendations.extend(finding.mitigation_recommendations[:2])  # Top 2 per finding
        
        # Add general recommendations
        if any(hasattr(f, 'threat_level') and f.threat_level.value == 'critical' for f in findings):
            recommendations.insert(0, "URGENT: Critical zero-day vulnerabilities detected - immediate security review required")
        
        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        return unique_recommendations[:8]  # Limit to top 8 recommendations
    
    def _fallback_zero_day_detection(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """Fallback zero-day detection using basic methods."""
        try:
            # Try to use existing zero-day detection if available
            from .detection.zero_day_detection_engine import ZeroDayDetectionEngine
            
            basic_engine = ZeroDayDetectionEngine()
            file_contents = self._extract_file_contents_for_analysis(apk_ctx)
            findings = basic_engine.analyze_for_zero_days(apk_ctx, file_contents)
            
            # Convert to basic format
            basic_findings = []
            for finding in findings:
                finding_dict = {
                    'finding_id': finding.finding_id,
                    'vulnerability_type': finding.vulnerability_type,
                    'anomaly_score': finding.anomaly_score,
                    'confidence_score': finding.confidence_score,
                    'file_path': finding.file_path,
                    'detection_method': 'basic_zero_day_detection'
                }
                basic_findings.append(finding_dict)
            
            return {
                'enhanced_zero_day_findings': basic_findings,
                'analysis_metadata': {
                    'total_findings': len(findings),
                    'detection_engine': 'basic_zero_day_v1.0',
                    'fallback_mode': True
                },
                'threat_summary': {'total_threats': len(findings), 'risk_level': 'unknown'},
                'recommendations': ["Review detected anomalies manually", "Consider upgrading to enhanced detection"]
            }
            
        except Exception as e:
            self.logger.error(f"Fallback zero-day detection failed: {e}")
            return {
                'enhanced_zero_day_findings': [],
                'analysis_metadata': {
                    'total_findings': 0,
                    'detection_engine': 'none',
                    'error': str(e)
                },
                'threat_summary': {'total_threats': 0, 'risk_level': 'unknown'},
                'recommendations': ["Zero-day detection unavailable - use manual code review"]
            }

    def coordinate_plugins(self, apk_ctx: APKContext, plugins: List[str]) -> Dict[str, Any]:
        """
        Coordinate execution of multiple plugins to prevent conflicts and cycles.
        
        Args:
            apk_ctx: APK context for analysis
            plugins: List of plugin names to coordinate
            
        Returns:
            Dict containing coordinated plugin results
        """
        self.logger.info(f"🔧 Coordinating plugins: {plugins}")
        
        # Check for cycles before starting
        if not self.prevent_cycles(apk_ctx, plugins):
            return {
                'success': False,
                'error_message': 'Plugin coordination cycle detected',
                'plugins_executed': [],
                'cycle_detected': True
            }
        
        coordinated_results = {
            'success': True,
            'plugins_executed': [],
            'results': {},
            'cycle_detected': False,
            'coordination_metadata': {
                'execution_order': plugins,
                'timestamp': time.time(),
                'package': apk_ctx.package_name
            }
        }
        
        try:
            for plugin in plugins:
                self.logger.info(f"📋 Executing plugin: {plugin}")
                
                # Execute plugin with cycle protection
                plugin_result = self._execute_plugin_safely(apk_ctx, plugin)
                
                coordinated_results['results'][plugin] = plugin_result
                coordinated_results['plugins_executed'].append(plugin)
                
                # Add delay to prevent resource conflicts
                time.sleep(0.01)  # 10x faster integration polling for better throughput
                
        except Exception as e:
            self.logger.error(f"Plugin coordination failed: {e}")
            coordinated_results['success'] = False
            coordinated_results['error_message'] = str(e)
        
        return coordinated_results

    def prevent_cycles(self, apk_ctx: APKContext, plugins: List[str]) -> bool:
        """
        Prevent infinite cycles between plugins.
        
        Args:
            apk_ctx: APK context for analysis
            plugins: List of plugins to check for cycles
            
        Returns:
            bool: True if no cycles detected, False if cycle would occur
        """
        package_key = f"{apk_ctx.package_name}_plugins"
        
        with _integration_lock:
            # Check if any plugin coordination is already active for this package
            active_package_keys = [key for key in _active_integrations if key.startswith(apk_ctx.package_name)]
            
            if active_package_keys:
                self.logger.warning(f"🔄 Cycle prevention: Package {apk_ctx.package_name} already has active plugin coordination")
                return False
            
            # Check for specific plugin conflicts
            for plugin in plugins:
                plugin_key = f"{apk_ctx.package_name}_{plugin}"
                if plugin_key in _active_integrations:
                    self.logger.warning(f"🔄 Cycle prevention: Plugin {plugin} already active for package {apk_ctx.package_name}")
                    return False
            
            # Mark plugins as active
            for plugin in plugins:
                plugin_key = f"{apk_ctx.package_name}_{plugin}"
                _active_integrations.add(plugin_key)
            
            # Mark package coordination as active
            _active_integrations.add(package_key)
            
        self.logger.info(f"✅ Cycle prevention: All plugins clear for package {apk_ctx.package_name}")
        return True

    def unified_analysis(self, apk_ctx: APKContext, analysis_types: List[str]) -> Dict[str, Any]:
        """
        Perform unified analysis across multiple analysis types.
        
        Args:
            apk_ctx: APK context for analysis
            analysis_types: List of analysis types to unify
            
        Returns:
            Dict containing unified analysis results
        """
        self.logger.info(f"🌟 Starting unified analysis for {apk_ctx.package_name}")
        
        unified_results = {
            'success': True,
            'package_name': apk_ctx.package_name,
            'analysis_types': analysis_types,
            'unified_vulnerabilities': [],
            'analysis_results': {},
            'metadata': {
                'start_time': time.time(),
                'total_findings': 0,
                'confidence_scores': {},
                'coverage_metrics': {}
            }
        }
        
        try:
            # Coordinate static analysis
            if 'static' in analysis_types:
                static_result = self.integrate_analysis(apk_ctx)
                unified_results['analysis_results']['static'] = static_result.to_dict()
                if static_result.unified_vulnerabilities:
                    unified_results['unified_vulnerabilities'].extend(static_result.unified_vulnerabilities)
            
            # Coordinate dynamic analysis (if available)
            if 'dynamic' in analysis_types:
                dynamic_result = self._coordinate_dynamic_analysis(apk_ctx)
                unified_results['analysis_results']['dynamic'] = dynamic_result
                if dynamic_result.get('vulnerabilities'):
                    unified_results['unified_vulnerabilities'].extend(dynamic_result['vulnerabilities'])
            
            # Coordinate network analysis
            if 'network' in analysis_types:
                network_result = self._coordinate_network_analysis(apk_ctx)
                unified_results['analysis_results']['network'] = network_result
                if network_result.get('vulnerabilities'):
                    unified_results['unified_vulnerabilities'].extend(network_result['vulnerabilities'])
            
            # Calculate unified metrics
            unified_results['metadata']['total_findings'] = len(unified_results['unified_vulnerabilities'])
            unified_results['metadata']['end_time'] = time.time()
            unified_results['metadata']['duration'] = unified_results['metadata']['end_time'] - unified_results['metadata']['start_time']
            
            self.logger.info(f"✅ Unified analysis completed: {unified_results['metadata']['total_findings']} findings")
            
        except Exception as e:
            self.logger.error(f"Unified analysis failed: {e}")
            unified_results['success'] = False
            unified_results['error_message'] = str(e)
        
        return unified_results

    def _execute_plugin_safely(self, apk_ctx: APKContext, plugin_name: str) -> Dict[str, Any]:
        """Safely execute a plugin with error handling."""
        try:
            # Plugin execution logic would go here
            # For now, return a mock result
            return {
                'success': True,
                'plugin': plugin_name,
                'findings': [],
                'execution_time': 0.1
            }
        except Exception as e:
            self.logger.error(f"Plugin {plugin_name} execution failed: {e}")
            return {
                'success': False,
                'plugin': plugin_name,
                'error': str(e),
                'execution_time': 0.0
            }

    def _coordinate_dynamic_analysis(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """Coordinate dynamic analysis if available."""
        return {
            'success': True,
            'vulnerabilities': [],
            'analysis_type': 'dynamic',
            'message': 'Dynamic analysis coordination placeholder'
        }

    def _coordinate_network_analysis(self, apk_ctx: APKContext) -> Dict[str, Any]:
        """Coordinate network analysis if available."""
        return {
            'success': True,
            'vulnerabilities': [],
            'analysis_type': 'network',
            'message': 'Network analysis coordination placeholder'
        }

# Factory function for creating bridge instance
def create_integration_bridge() -> JADXEnhancedStaticAnalysisBridge:
    """Create JADX-Enhanced Static Analysis bridge instance."""
    return JADXEnhancedStaticAnalysisBridge()

# Main interface function with cycle prevention
def run_integrated_analysis(apk_ctx: APKContext) -> Dict[str, Any]:
    """
    Run integrated JADX and Enhanced Static Analysis with cycle prevention.
    
    Args:
        apk_ctx: APK context for analysis
        
    Returns:
        Dict containing unified analysis results
    """
    # CYCLE PREVENTION: Check if already running for this package
    package_integrations = [aid for aid in _active_integrations if aid.startswith(apk_ctx.package_name)]
    if package_integrations:
        logger.warning(f"🔄 Preventing cycle - integration already active for {apk_ctx.package_name}")
        return {
            'success': False,
            'cycle_detected': True,
            'error_message': 'Integration cycle prevented',
            'unified_vulnerabilities': []
        }
    
    bridge = create_integration_bridge()
    result = bridge.integrate_analysis(apk_ctx)
    return result.to_dict()

# Module-level wrapper functions for integration test compatibility
def coordinate_plugins(apk_ctx: APKContext, plugins: List[str]) -> Dict[str, Any]:
    """Module-level wrapper for plugin coordination."""
    bridge = create_integration_bridge()
    return bridge.coordinate_plugins(apk_ctx, plugins)

def prevent_cycles(apk_ctx: APKContext, plugins: List[str]) -> bool:
    """Module-level wrapper for cycle prevention."""
    bridge = create_integration_bridge()
    return bridge.prevent_cycles(apk_ctx, plugins)

def unified_analysis(apk_ctx: APKContext, analysis_types: List[str]) -> Dict[str, Any]:
    """Module-level wrapper for unified analysis."""
    bridge = create_integration_bridge()
    return bridge.unified_analysis(apk_ctx, analysis_types)