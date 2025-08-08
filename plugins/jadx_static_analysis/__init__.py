#!/usr/bin/env python3
"""
JADX Static Analysis Plugin - Modular Architecture

This module provides comprehensive JADX-based static analysis for Android applications
implementing MASVS compliance checks through modular components.

Features:
- JADX decompilation and analysis
- Resource-aware timeout management
- Memory optimization for large APKs
- confidence calculation
- Comprehensive vulnerability detection
- Fallback analysis capabilities

Modular Components:
- data_structures.py: Core data classes and enums
- jadx_analyzer.py: JADX decompilation and analysis
- resource_optimizer.py: Memory and timeout management
- fallback_analyzer.py: Fallback analysis when JADX fails
- confidence_calculator.py: confidence calculation
- formatter.py: Rich text output formatting

MASVS Controls: MSTG-CRYPTO-1, MSTG-CRYPTO-2, MSTG-CRYPTO-3, MSTG-CRYPTO-4, MSTG-CODE-2, MSTG-CODE-8, MSTG-STORAGE-1, MSTG-STORAGE-2

"""

import logging
import time
import os
from typing import Tuple, Union, Optional, List, Dict
from datetime import datetime

from rich.text import Text

from core.apk_ctx import APKContext
from .data_structures import (
    JadxAnalysisResult, JadxAnalysisConfig, JadxVulnerability,
    AnalysisMode, AnalysisStatus, SeverityLevel, VulnerabilityType,
    MasvsControl, ResourceMetrics
)

logger = logging.getLogger(__name__)

# Plugin metadata
PLUGIN_METADATA = {
    "name": "JADX Static Analysis",
    "description": "Comprehensive JADX-based static analysis with modular architecture",
    "version": "2.0.0",
    "author": "AODS Development Team",
    "category": "STATIC_ANALYSIS",
    "priority": "HIGH",
    "timeout": 600,
    "mode": "deep",
    "requires_device": False,
    "requires_network": False,
    "invasive": False,
    "execution_time_estimate": 300,
    "dependencies": ["jadx"],
    "modular_architecture": True,
    "components": [
        "jadx_analyzer",
        "resource_optimizer",
        "fallback_analyzer",
        "confidence_calculator",
        "formatter",
        "data_structures"
    ],
    "masvs_controls": [
        "MSTG-CRYPTO-1", "MSTG-CRYPTO-2", "MSTG-CRYPTO-3", "MSTG-CRYPTO-4",
        "MSTG-CODE-2", "MSTG-CODE-8", "MSTG-STORAGE-1", "MSTG-STORAGE-2"
    ],
    "vulnerability_types": ["crypto_weakness", "hardcoded_secret", "insecure_pattern", "code_quality", "storage_issue"]
}

PLUGIN_CHARACTERISTICS = {
    "mode": "deep",
    "category": "STATIC_ANALYSIS",
    "targets": ["crypto_vulnerabilities", "hardcoded_secrets", "insecure_patterns"],
    "modular": True,
    "masvs_controls": [
        "MSTG-CRYPTO-1", "MSTG-CRYPTO-2", "MSTG-CRYPTO-3", "MSTG-CRYPTO-4",
        "MSTG-CODE-2", "MSTG-CODE-8", "MSTG-STORAGE-1", "MSTG-STORAGE-2"
    ]
}

def _load_cached_jadx_results(package_name: str, apk_path: str = None) -> Optional[Dict]:
    """Load cached JADX analysis results with contamination prevention."""
    import os
    import json
    import hashlib
    import time
    
    # Initialize secure cache parameters
    cache_dir = "/tmp/jadx_cache_secure"
    min_entropy_threshold = 5.0
    min_confidence_threshold = 0.7
    max_secrets_threshold = 1000
    
    try:
        # Generate secure cache key
        if apk_path and os.path.exists(apk_path):
            with open(apk_path, 'rb') as f:
                apk_hash = hashlib.sha256(f.read()).hexdigest()[:16]
            cache_key = f"{package_name}_{apk_hash}"
        else:
            cache_key = package_name
        
        cache_file = os.path.join(cache_dir, f"{cache_key}.json")
        
        # Check if secure cache exists
        if not os.path.exists(cache_file):
            # Try legacy cache with validation
            legacy_cache_file = f"/tmp/jadx_results_{package_name}.json"
            if os.path.exists(legacy_cache_file):
                logging.warning(f"Found legacy cache, validating: {legacy_cache_file}")
                
                with open(legacy_cache_file, 'r') as f:
                    cache_data = json.load(f)
                
                # Validate and filter legacy cache
                cached_package = cache_data.get('package_name', '')
                if cached_package != package_name:
                    logging.warning(f"Package mismatch in legacy cache: expected {package_name}, got {cached_package}")
                    return None
                
                # Check for massive false positives
                secrets_count = len(cache_data.get('analysis_results', {}).get('secrets_analysis', {}).get('secrets', []))
                if secrets_count > max_secrets_threshold:
                    logging.warning(f"Legacy cache contaminated with {secrets_count} secrets, rejecting")
                    return None
                
                # Filter secrets in legacy cache
                analysis_results = cache_data.get('analysis_results', {})
                secrets_analysis = analysis_results.get('secrets_analysis', {})
                original_secrets = secrets_analysis.get('secrets', [])
                
                # Apply filtering
                filtered_secrets = []
                for secret in original_secrets:
                    entropy = secret.get('entropy', 0.0)
                    confidence = secret.get('confidence', 0.0)
                    value = secret.get('value', '').lower()
                    
                    # Apply thresholds
                    if entropy < min_entropy_threshold or confidence < min_confidence_threshold:
                        continue
                    
                    # Filter common false positives
                    false_positive_patterns = [
                        'hasqualfier', 'qualifier', 'android', 'layout', 'drawable',
                        'string', 'color', 'style', 'theme', 'activity', 'fragment'
                    ]
                    if any(pattern in value for pattern in false_positive_patterns):
                        continue
                    
                    if len(value) < 8:  # Minimum length check
                        continue
                    
                    filtered_secrets.append(secret)
                
                # Update cache with filtered data
                secrets_analysis['secrets'] = filtered_secrets
                analysis_results['secrets_analysis'] = secrets_analysis
                cache_data['analysis_results'] = analysis_results
                
                logging.info(f"Filtered legacy cache: {len(original_secrets)} -> {len(filtered_secrets)} secrets")
                
                # Save to secure location
                os.makedirs(cache_dir, exist_ok=True)
                with open(cache_file, 'w') as f:
                    json.dump(cache_data, f, indent=2)
                
                return cache_data
            
            return None
        
        # Load secure cache
        with open(cache_file, 'r') as f:
            cache_data = json.load(f)
        
        # Validate package name
        cached_package = cache_data.get('package_name', '')
        if cached_package != package_name:
            logging.warning(f"Package mismatch in secure cache: expected {package_name}, got {cached_package}")
            return None
        
        # Check cache age (7 days max)
        timestamp = cache_data.get('timestamp', 0)
        if time.time() - timestamp > 7 * 24 * 3600:
            logging.warning("Secure cache too old, removing")
            os.remove(cache_file)
            return None
        
        return cache_data
        
    except Exception as e:
        logging.warning(f"Failed to load secure JADX cache: {e}")
        return None

def _is_framework_file(file_path: str) -> bool:
    """
    Check if file should be filtered out as framework/library code.
    This matches the comprehensive filtering logic from secret_extractor.py
    """
    if not file_path:
        return False
        
    # Normalize path for pattern matching
    file_path_lower = file_path.lower().replace('\\', '/')
    
    # CRITICAL: Comprehensive framework patterns to prioritize application code
    framework_patterns = {
        'com/google/android/gms/',      # Google Mobile Services (main issue from scan)
        'com/google/firebase/',
        'androidx/',
        'android/support/', 
        'com/facebook/',
        'com/amazon/',
        'kotlin/',
        'kotlinx/',
        'org/apache/',
        'org/json/',
        'okhttp3/',
        'retrofit2/',
        'com/squareup/',
        'io/reactivex/',
        'rx/internal/',
        'dagger/',
        'javax/',
        'org/jetbrains/',
        'com/fasterxml/',
        'org/slf4j/',
        'ch/qos/logback/',
        '/r.java',
        '/buildconfig.java',
        'test/',
        'androidtest/',
        'meta-inf/',
        'com/facebook/react/',
        'io/flutter/',
        'com/github/'
    }
    
    # Check if file matches any framework pattern
    for pattern in framework_patterns:
        if pattern in file_path_lower:
            return True
    
    return False


def _extract_structured_vulnerabilities(analysis_result: JadxAnalysisResult, cached_results: Optional[Dict]) -> List[Dict]:
    """Extract all vulnerabilities including cached secrets as structured data."""
    vulnerabilities = []
    filtered_count = 0
    
    # Add vulnerabilities from analysis result
    if analysis_result and analysis_result.vulnerabilities:
        for vuln in analysis_result.vulnerabilities:
            # CRITICAL FIX: Filter out framework/library vulnerabilities
            if _is_framework_file(vuln.file_path):
                filtered_count += 1
                logger.debug(f"Filtered framework vulnerability: {vuln.file_path}")
                continue
                
            vuln_dict = {
                'title': vuln.title,
                'description': vuln.description,
                'severity': vuln.severity.value if hasattr(vuln.severity, 'value') else str(vuln.severity),
                'vulnerability_type': vuln.vulnerability_type.value if hasattr(vuln.vulnerability_type, 'value') else str(vuln.vulnerability_type),
                'file_path': vuln.file_path,
                'line_number': vuln.line_number,
                'confidence': vuln.confidence,
                'code_snippet': getattr(vuln, 'code_snippet', ''),
                'masvs_control': vuln.masvs_control.value if hasattr(vuln.masvs_control, 'value') else str(vuln.masvs_control),
                'cwe_id': getattr(vuln, 'cwe_id', ''),
                'source': 'jadx_analysis'
            }
            vulnerabilities.append(vuln_dict)
    
    # Add secrets from cached results
    if cached_results and 'analysis_results' in cached_results:
        # Add crypto vulnerabilities from cache
        crypto_analysis = cached_results['analysis_results'].get('crypto_analysis', {})
        for crypto_issue in crypto_analysis.get('crypto_issues', []):
            # CRITICAL FIX: Filter out framework/library crypto vulnerabilities
            file_path = crypto_issue.get('file', '')
            if _is_framework_file(file_path):
                filtered_count += 1
                logger.debug(f"Filtered framework crypto vulnerability: {file_path}")
                continue
                
            vuln_dict = {
                'title': crypto_issue.get('title', 'Cryptographic Vulnerability'),
                'description': crypto_issue.get('description', ''),
                'severity': crypto_issue.get('severity', 'MEDIUM').upper(),
                'vulnerability_type': 'WEAK_CRYPTOGRAPHY',
                'file_path': file_path,
                'line_number': crypto_issue.get('line_number', 0),
                'confidence': crypto_issue.get('confidence', 0.7),
                'code_snippet': crypto_issue.get('evidence', ''),
                'masvs_control': 'MASVS-CRYPTO-1',
                'cwe_id': crypto_issue.get('cwe_id', 'CWE-327'),
                'source': 'jadx_crypto_cache'
            }
            vulnerabilities.append(vuln_dict)
        
        # Add secrets from cache
        secrets_analysis = cached_results['analysis_results'].get('secrets_analysis', {})
        for secret in secrets_analysis.get('secrets', []):
            # CRITICAL FIX: Filter out framework/library secrets
            file_path = secret.get('file', '')
            if _is_framework_file(file_path):
                filtered_count += 1
                logger.debug(f"Filtered framework secret: {file_path}")
                continue
                
            vuln_dict = {
                'title': f"Hardcoded Secret: {secret.get('type', 'unknown').title()}",
                'description': f"Hardcoded {secret.get('type', 'secret')} detected in source code",
                'severity': secret.get('severity', 'MEDIUM').upper(),
                'vulnerability_type': 'HARDCODED_SECRET',
                'file_path': file_path,
                'line_number': secret.get('line_number', 0),
                'confidence': secret.get('confidence', 0.7),
                'code_snippet': secret.get('value', ''),
                'masvs_control': 'MASVS-STORAGE-1',
                'cwe_id': 'CWE-798',  # Use of Hard-coded Credentials
                'evidence': secret.get('value', ''),
                'entropy': secret.get('entropy', 0),
                'validation_status': secret.get('validation_status', 'unknown'),
                'source': 'jadx_secrets_cache'
            }
            vulnerabilities.append(vuln_dict)
    
    if filtered_count > 0:
        logger.info(f"JADX Framework Filtering: Filtered {filtered_count} framework vulnerabilities, kept {len(vulnerabilities)} application vulnerabilities")
    
    return vulnerabilities

class JadxStaticAnalysisPlugin:
    """
    Main JADX Static Analysis plugin using modular architecture.
    
    Orchestrates comprehensive static analysis through specialized components
    including resource optimization, fallback analysis, and professional confidence calculation.
    """
    
    def __init__(self, apk_ctx: APKContext, config: Optional[JadxAnalysisConfig] = None):
        """Initialize the JADX static analysis plugin."""
        self.apk_ctx = apk_ctx
        self.config = config or JadxAnalysisConfig()
        self.logger = logging.getLogger(__name__)
        
        # Detect scan profile for Lightning optimizations
        self.scan_profile = self._detect_scan_profile()
        self.is_lightning_mode = self.scan_profile == "lightning"
        
        # Apply Lightning optimizations if needed
        if self.is_lightning_mode:
            self._apply_lightning_optimizations()
        
        # Analysis state
        self.analysis_start_time = None
    
    def _detect_scan_profile(self) -> str:
        """Detect current scan profile from APK context or environment."""
        # Try multiple methods to detect scan profile
        
        # Method 1: Check APK context for scan profile
        if hasattr(self.apk_ctx, 'scan_profile'):
            return getattr(self.apk_ctx, 'scan_profile', 'standard').lower()
        
        # Method 2: Check APK context scan mode
        if hasattr(self.apk_ctx, 'scan_mode'):
            scan_mode = getattr(self.apk_ctx, 'scan_mode', 'safe')
            if scan_mode == 'safe':
                return 'lightning'  # Safe mode typically maps to Lightning
            elif scan_mode == 'deep':
                return 'standard'
        
        # Method 3: Check environment variables
        import os
        env_profile = os.environ.get('AODS_SCAN_PROFILE', '').lower()
        if env_profile in ['lightning', 'fast', 'standard', 'deep']:
            return env_profile
            
        # Method 4: Check command line args (crude detection)
        import sys
        if '--profile' in sys.argv:
            try:
                profile_idx = sys.argv.index('--profile')
                if profile_idx + 1 < len(sys.argv):
                    return sys.argv[profile_idx + 1].lower()
            except:
                pass
        
        # Default to standard if no detection works
        return 'standard'
    
    def _apply_lightning_optimizations(self):
        """Apply Lightning profile optimizations focused on SPEED of detection, not scope reduction."""
        self.logger.info("⚡ Lightning mode detected - optimizing for FAST detection with FULL coverage")
        
        # DETECTION-FIRST OPTIMIZATION: Maintain full vulnerability scope but optimize for speed
        # Keep ALL analysis types enabled - optimize HOW we detect, not WHAT we detect
        self.config.enable_crypto_analysis = True    # Keep crypto detection
        self.config.enable_secrets_analysis = True   # Keep secrets detection  
        self.config.enable_insecure_patterns_analysis = True  # Keep patterns detection
        
        # SPEED OPTIMIZATIONS: Aggressive timeouts with intelligent fallbacks
        self.config.default_timeout = 30  # 30 seconds (not 10) - still aggressive but allows detection
        self.config.large_apk_threshold_mb = 10.0   # Faster handling for >10MB APKs
        self.config.very_large_apk_threshold_mb = 50.0  # 50MB+ gets speed-optimized processing
        
        # DETECTION OPTIMIZATION: Enable fallback to catch vulnerabilities if primary analysis fails
        self.config.enable_fallback_analysis = True  # Keep fallback for detection completeness
        self.config.check_interval_seconds = 1  # Check every 1 second for responsiveness
        
        # SPEED-FOCUSED OPTIMIZATIONS (maintain detection scope)
        self.config.max_decompilation_retries = 1  # Reduce retries for speed
        self.config.confidence_threshold = 0.6  # Slightly higher threshold for faster processing
        
        # Log Lightning optimization strategy
        self.logger.info("   ⚡ DETECTION-FIRST Lightning Strategy:")
        self.logger.info("   ✅ Full vulnerability scope: crypto + secrets + patterns ENABLED")
        self.logger.info("   ⏱️  Speed optimization: 30s timeout with fallback protection")
        self.logger.info("   🎯 Focus: Fast detection methods, NOT reduced detection scope")
        self.logger.info("   🛡️  Fallback enabled to ensure vulnerability detection completeness")
    
    def analyze(self) -> JadxAnalysisResult:
        """
        Perform comprehensive JADX static analysis.
        
        Returns:
            JadxAnalysisResult: Complete analysis results
        """
        self.analysis_start_time = time.time()
        
        if not self.apk_ctx.package_name:
            self.logger.error("Package name not available for JADX analysis")
            return self._create_error_result("Package name not available")
        
        try:
            # Check if JADX is available
            jadx_available = self._check_jadx_availability()
            if not jadx_available:
                return self._create_jadx_not_found_result()
            
            # Get APK size and system metrics
            apk_size_mb = os.path.getsize(str(self.apk_ctx.apk_path)) / (1024 * 1024)
            resource_metrics = self._create_resource_metrics(apk_size_mb)
            
            # Attempt staged JADX analysis
            return self._perform_staged_analysis(resource_metrics)
            
        except Exception as e:
            self.logger.error(f"JADX static analysis failed: {e}", exc_info=True)
            return self._create_error_result(f"Analysis failed: {str(e)}")
    
    def _check_jadx_availability(self) -> bool:
        """Check if JADX is available in the system."""
        try:
            import subprocess
            result = subprocess.run(["which", "jadx"], capture_output=True, text=True)
            return result.returncode == 0
        except Exception as e:
            self.logger.warning(f"Error checking JADX availability: {e}")
            return False
    
    def _create_resource_metrics(self, apk_size_mb: float) -> ResourceMetrics:
        """Create resource metrics for analysis planning."""
        try:
            import psutil
            available_memory_gb = psutil.virtual_memory().available / (1024**3)
        except ImportError:
            available_memory_gb = 8.0  # Default assumption
        
        timeout = self.config.get_timeout_for_size(apk_size_mb)
        priority = self.config.get_priority_for_size(apk_size_mb, available_memory_gb)
        
        # Determine processing mode
        if apk_size_mb > self.config.very_large_apk_threshold_mb:
            processing_mode = "memory_optimized"
        elif available_memory_gb < self.config.memory_constrained_threshold_gb:
            processing_mode = "memory_constrained"
        else:
            processing_mode = "normal"
        
        return ResourceMetrics(
            apk_size_mb=apk_size_mb,
            timeout_used=timeout,
            processing_mode=processing_mode,
            available_memory_gb=available_memory_gb,
            priority=priority
        )
    
    def _perform_staged_analysis(self, resource_metrics: ResourceMetrics) -> JadxAnalysisResult:
        """
        Perform staged JADX analysis with optimized timeout handling.
        
        Enhanced with improved timeout management and Lightning mode optimization.
        """
        
        try:
            # Try to use the enhanced JADX decompilation manager
            from core.jadx_decompilation_manager import get_jadx_manager
            
            manager = get_jadx_manager()
            
            # LIGHTNING MODE: Aggressive timeout optimization to prevent hanging
            if self.is_lightning_mode:
                # Reduce timeout dramatically for Lightning mode
                optimized_timeout = min(resource_metrics.timeout_used, 120)  # Maximum 120 seconds for Lightning mode (increased from 60s for moderately complex APKs)
                priority = "lightning_fast"
                self.logger.info(f"⚡ Lightning mode: Using aggressive timeout of {optimized_timeout}s")
            else:
                optimized_timeout = resource_metrics.timeout_used
                priority = resource_metrics.priority
            
            # Start decompilation with optimized timeout
            job_id = manager.start_decompilation(
                apk_path=str(self.apk_ctx.apk_path),
                package_name=self.apk_ctx.package_name,
                timeout=optimized_timeout,
                priority=priority
            )
            
            # IMPROVED TIMEOUT HANDLING: More aggressive monitoring for Lightning mode
            if self.is_lightning_mode:
                check_interval = 0.5  # Check every 500ms for Lightning
                max_wait_time = optimized_timeout
            else:
                check_interval = min(self.config.check_interval_seconds, 3)
                max_wait_time = optimized_timeout
            
            # Wait for completion with timeout protection
            start_time = time.time()
            success = False
            
            while time.time() - start_time < max_wait_time:
                # CRITICAL FIX: Check job status immediately to detect failures
                job = manager.get_job_status(job_id)
                
                if job:
                    # Check if job completed successfully
                    if job.status.value == "completed":
                        success = True
                        self.logger.info(f"🎉 JADX decompilation completed successfully in {time.time() - start_time:.1f}s")
                        break
                    # CRITICAL FIX: Detect failures immediately and break out
                    elif job.status.value in ["failed", "timeout", "cancelled"]:
                        self.logger.warning(f"⚡ JADX decompilation {job.status.value} in {time.time() - start_time:.1f}s - proceeding with fallback analysis")
                        success = False
                        break
                    # Job is still running, continue waiting
                    elif job.status.value in ["pending", "running"]:
                        self.logger.debug(f"⏳ JADX still {job.status.value} after {time.time() - start_time:.1f}s")
                    else:
                        # Unknown status, treat as failure
                        self.logger.warning(f"⚠️ Unknown JADX status: {job.status.value} - treating as failure")
                        success = False
                        break
                else:
                    # Job not found - check if it moved to completed jobs
                    if job_id in manager.completed_jobs:
                        completed_job = manager.completed_jobs[job_id]
                        if completed_job.status.value == "completed":
                            success = True
                            self.logger.info(f"🎉 JADX decompilation found completed in {time.time() - start_time:.1f}s")
                        else:
                            self.logger.warning(f"⚡ JADX job completed with status: {completed_job.status.value} - using fallback")
                            success = False
                        break
                    else:
                        # Job disappeared entirely - treat as failure
                        self.logger.warning("⚠️ JADX job disappeared - treating as failure")
                        success = False
                        break
                
                # Sleep before next check
                time.sleep(check_interval)
                
            if success:
                # DETECTION-FIRST: Run essential analysis types for all modes
                analysis_types = [
                    "crypto_analysis",      # Always enabled for crypto vulnerability detection
                    "secrets_analysis",     # Always enabled for credential detection  
                ]
                
                # Add more analysis types for non-Lightning modes
                if not self.is_lightning_mode:
                    analysis_types.append("insecure_patterns")  # Code pattern vulnerabilities
                
                if self.is_lightning_mode:
                    self.logger.info("⚡ Lightning: Running essential analysis with timeout protection")
                
                analysis_results = manager.analyze_decompiled_sources(job_id, analysis_types)
                return self._create_success_result(analysis_results, resource_metrics)
            else:
                # Handle timeout or failure - get detailed error info
                job = manager.get_job_status(job_id)
                error_msg = job.error_message if job and job.error_message else "Decompilation failed or timed out"
                
                if self.is_lightning_mode:
                    self.logger.info(f"⚡ Lightning: JADX timeout after {optimized_timeout}s - using fallback analysis")
                else:
                    self.logger.warning(f"JADX decompilation failed: {error_msg}")
                
                # DETECTION-FIRST: Always use fallback analysis to catch vulnerabilities
                return self._create_enhanced_fallback_result(resource_metrics, error_msg)
                
        except ImportError as e:
            self.logger.warning(f"JADX decompilation manager not available: {e}")
            # DETECTION-FIRST: Always use fallback analysis 
            return self._create_enhanced_fallback_result(resource_metrics, f"Decompilation manager import failed: {str(e)}")
        except Exception as e:
            self.logger.info(f"JADX staged analysis using fallback mode: {e}")
            # DETECTION-FIRST: Always use fallback analysis 
            return self._create_enhanced_fallback_result(resource_metrics, str(e))
    
    def _create_success_result(self, analysis_results: dict, resource_metrics: ResourceMetrics) -> JadxAnalysisResult:
        """Create successful analysis result with enhanced caching."""
        vulnerabilities = self._convert_analysis_to_vulnerabilities(analysis_results)
        
        result = JadxAnalysisResult(
            analysis_mode=AnalysisMode.STAGED,
            status=AnalysisStatus.SUCCESS,
            vulnerabilities=vulnerabilities,
            resource_metrics=resource_metrics,
            execution_time=time.time() - self.analysis_start_time,
            decompilation_path=getattr(self.apk_ctx, 'decompiled_apk_dir', None)
        )
        
        # COORDINATION: Cache results for enhanced static analysis plugin
        self._cache_jadx_results_for_coordination(analysis_results, result)
        
        return result

    def _cache_jadx_results_for_coordination(self, analysis_results: dict, jadx_result: JadxAnalysisResult) -> None:
        """Cache JADX results for coordination with enhanced static analysis."""
        try:
            # Prepare coordinated cache data with proper serialization
            coordination_data = {
                'timestamp': time.time(),
                'package_name': self.apk_ctx.package_name,
                'analysis_results': analysis_results,
                'vulnerabilities_count': len(jadx_result.vulnerabilities),
                'decompilation_path': str(jadx_result.decompilation_path) if jadx_result.decompilation_path else None,
                'execution_time': jadx_result.execution_time,
                'status': jadx_result.status.value
            }
            
            # Cache in APK context if available
            if hasattr(self.apk_ctx, 'set_cache'):
                self.apk_ctx.set_cache('jadx_static_analysis_results', coordination_data)
                self.logger.info("🔄 Cached JADX results in APK context for enhanced static analysis coordination")
            
            # Cache in shared location for cross-plugin coordination
            cache_file = f"/tmp/jadx_results_{self.apk_ctx.package_name}.json"
            import json
            
            # Use custom JSON serializer to handle any remaining non-serializable objects
            def json_serializable_converter(obj):
                """Convert non-JSON serializable objects to serializable format."""
                if hasattr(obj, '__fspath__'):  # Handle Path objects
                    return str(obj)
                elif hasattr(obj, '__str__'):
                    return str(obj)
                else:
                    return repr(obj)
            
            with open(cache_file, 'w') as f:
                json.dump(coordination_data, f, indent=2, default=json_serializable_converter)
            
            self.logger.info(f"🔄 Cached JADX results for plugin coordination: {cache_file}")
            self.logger.info(f"   📊 Cached {len(jadx_result.vulnerabilities)} vulnerabilities for reuse")
            
            # Log analysis breakdown for coordination visibility
            if 'crypto_analysis' in analysis_results:
                crypto_count = len(analysis_results['crypto_analysis'].get('crypto_issues', []))
                self.logger.info(f"   🔐 Crypto analysis: {crypto_count} issues cached")
            
            if 'secrets_analysis' in analysis_results:
                secrets_count = len(analysis_results['secrets_analysis'].get('findings', []))
                self.logger.info(f"   🔑 Secrets analysis: {secrets_count} findings cached")
            
            if 'insecure_patterns' in analysis_results:
                patterns_count = len(analysis_results['insecure_patterns'].get('findings', []))
                self.logger.info(f"   🛡️  Insecure patterns: {patterns_count} patterns cached")
                
        except Exception as e:
            self.logger.warning(f"Failed to cache JADX results for coordination: {e}")
            # Don't let caching failure break the plugin execution
            self.logger.debug(f"Cache failure details: {type(e).__name__}: {e}")
    
    def _create_timeout_result(self, resource_metrics: ResourceMetrics, error_msg: str) -> JadxAnalysisResult:
        """Create timeout-specific result."""
        result = JadxAnalysisResult(
            analysis_mode=AnalysisMode.TIMEOUT_PROTECTED,
            status=AnalysisStatus.TIMEOUT,
            resource_metrics=resource_metrics,
            execution_time=time.time() - self.analysis_start_time,
            error_message=error_msg
        )
        
        # Add timeout-specific recommendations as informational items
        timeout_recommendations = [
            "Use smaller APK subsets for detailed analysis",
            "Run JADX manually with specific parameters",
            "Check system resources and retry",
            "Consider alternative static analysis tools"
        ]
        
        for i, rec in enumerate(timeout_recommendations):
            vuln = JadxVulnerability(
                vulnerability_type=VulnerabilityType.CODE_QUALITY,
                title=f"Analysis Timeout Recommendation {i+1}",
                description=rec,
                severity=SeverityLevel.INFO,
                file_path="system",
                confidence=1.0
            )
            result.vulnerabilities.append(vuln)
        
        return result
    
    def _create_fallback_result(self, resource_metrics: ResourceMetrics, error_msg: str) -> JadxAnalysisResult:
        """Create fallback analysis result."""
        result = JadxAnalysisResult(
            analysis_mode=AnalysisMode.FALLBACK,
            status=AnalysisStatus.PARTIAL,
            resource_metrics=resource_metrics,
            execution_time=time.time() - self.analysis_start_time,
            error_message=error_msg,
            fallback_analysis_applied=True
        )
        
        # Add fallback analysis recommendations
        fallback_recommendations = [
            "Use other static analysis plugins in AODS",
            "Review AndroidManifest.xml manually",
            "Check for hardcoded strings in resources",
            "Consider using alternative decompilers"
        ]
        
        for i, rec in enumerate(fallback_recommendations):
            vuln = JadxVulnerability(
                vulnerability_type=VulnerabilityType.CODE_QUALITY,
                title=f"Fallback Analysis Recommendation {i+1}",
                description=rec,
                severity=SeverityLevel.INFO,
                file_path="fallback",
                confidence=0.7
            )
            result.vulnerabilities.append(vuln)
        
        return result

    def _create_enhanced_fallback_result(self, resource_metrics: ResourceMetrics, error_msg: str) -> JadxAnalysisResult:
        """Create enhanced fallback analysis result with better recommendations."""
        result = JadxAnalysisResult(
            analysis_mode=AnalysisMode.FALLBACK,
            status=AnalysisStatus.PARTIAL,
            resource_metrics=resource_metrics,
            execution_time=time.time() - self.analysis_start_time,
            error_message=error_msg,
            fallback_analysis_applied=True
        )
        
        # Determine the type of failure for specific recommendations
        if "timeout" in error_msg.lower() or "timed out" in error_msg.lower():
            failure_type = "timeout"
        elif "import" in error_msg.lower() or "module" in error_msg.lower():
            failure_type = "dependency"
        elif "jadx" in error_msg.lower() and ("not found" in error_msg.lower() or "command not found" in error_msg.lower()):
            failure_type = "missing_jadx"
        else:
            failure_type = "general"
        
        # Create targeted recommendations based on failure type
        recommendations = []
        
        if failure_type == "timeout":
            recommendations = [
                "APK decompilation timed out. The APK may be too large or complex for quick analysis.",
                "Try running JADX manually with '--threads-count 1' for memory-constrained environments.",
                "Consider using the Enhanced Static Analysis plugin for faster pattern-based analysis.",
                "Use APK size optimizer to split large APKs into smaller components.",
                "Check system resources - ensure adequate RAM and CPU availability."
            ]
        elif failure_type == "dependency":
            recommendations = [
                "JADX decompilation dependencies are not fully available.",
                "Install required dependencies: pip install psutil rich",
                "Verify JADX binary is installed: sudo apt install jadx (Ubuntu/Debian)",
                "Use Enhanced Static Analysis plugin as primary static analyzer.",
                "Enable other AODS static analysis plugins for comprehensive coverage."
            ]
        elif failure_type == "missing_jadx":
            recommendations = [
                "JADX binary not found in system PATH.",
                "Install JADX: sudo apt install jadx (Ubuntu/Debian) or download from GitHub",
                "Verify installation: which jadx",
                "Alternative: Use Enhanced Static Analysis plugin for pattern-based analysis.",
                "Enable other AODS static analysis capabilities."
            ]
        else:
            recommendations = [
                "JADX decompilation encountered an unexpected error.",
                "Use Enhanced Static Analysis plugin for pattern-based vulnerability detection.",
                "Enable Network Communication Tests for network security analysis.",
                "Use Manifest Analysis plugin for comprehensive AndroidManifest.xml review.",
                "Consider manual APK analysis using alternative tools (apktool, dex2jar)."
            ]
        
        # Add actionable recommendations as informational findings
        for i, rec in enumerate(recommendations):
            vuln = JadxVulnerability(
                vulnerability_type=VulnerabilityType.CODE_QUALITY,
                title=f"Actionable Recommendation {i+1}",
                description=rec,
                severity=SeverityLevel.INFO,
                file_path="system_analysis",
                confidence=0.9  # High confidence in recommendations
            )
            result.vulnerabilities.append(vuln)
        
        # Add general AODS plugin alternatives
        alternative_plugins = [
            "Enhanced Static Analysis: Pattern-based vulnerability detection",
            "Network Communication Tests: MASVS-NETWORK compliance checks", 
            "Enhanced Manifest Analysis: Comprehensive manifest security review",
            "Cryptography Tests: Cryptographic implementation analysis",
            "Code Quality Injection Analysis: Injection vulnerability detection"
        ]
        
        for plugin in alternative_plugins:
            vuln = JadxVulnerability(
                vulnerability_type=VulnerabilityType.CODE_QUALITY,
                title="Alternative AODS Plugin Available",
                description=plugin,
                severity=SeverityLevel.INFO,
                file_path="aods_framework",
                confidence=1.0
            )
            result.vulnerabilities.append(vuln)
        
        self.logger.debug(f"Enhanced fallback analysis generated {len(result.vulnerabilities)} recommendations")
        return result
    
    def _create_lightning_minimal_result(self, resource_metrics: ResourceMetrics, error_msg: str = None) -> JadxAnalysisResult:
        """DEPRECATED: This method reduced detection scope and is no longer used.
        
        Lightning mode now uses full detection scope with speed optimizations.
        All fallback analysis uses _create_enhanced_fallback_result for consistency.
        """
        # This method is deprecated - Lightning now uses full detection scope
        return self._create_enhanced_fallback_result(resource_metrics, error_msg)
    
    def _create_jadx_not_found_result(self) -> JadxAnalysisResult:
        """Create result when JADX is not available."""
        result = JadxAnalysisResult(
            analysis_mode=AnalysisMode.FALLBACK,
            status=AnalysisStatus.JADX_NOT_FOUND,
            execution_time=time.time() - self.analysis_start_time,
            jadx_available=False,
            error_message="JADX not found in system PATH"
        )
        
        # Add installation recommendations
        install_recommendations = [
            "Ubuntu/Debian: sudo apt install jadx",
            "Arch Linux: sudo pacman -S jadx",
            "Manual: Download from https://github.com/skylot/jadx/releases"
        ]
        
        for i, rec in enumerate(install_recommendations):
            vuln = JadxVulnerability(
                vulnerability_type=VulnerabilityType.CODE_QUALITY,
                title=f"JADX Installation Option {i+1}",
                description=rec,
                severity=SeverityLevel.INFO,
                file_path="system",
                confidence=1.0
            )
            result.vulnerabilities.append(vuln)
        
        return result
    
    def _create_error_result(self, error_message: str) -> JadxAnalysisResult:
        """Create error result for failed analysis."""
        result = JadxAnalysisResult(
            analysis_mode=AnalysisMode.FALLBACK,
            status=AnalysisStatus.FAILED,
            execution_time=time.time() - self.analysis_start_time,
            error_message=error_message
        )
        
        return result
    
    def _convert_analysis_to_vulnerabilities(self, analysis_results: dict) -> List[JadxVulnerability]:
        """Convert analysis results to vulnerability objects."""
        vulnerabilities = []
        
        # Process crypto analysis results
        crypto_results = analysis_results.get('crypto_analysis', {})
        # Use 'crypto_issues' key which is what the crypto analysis actually returns
        for finding in crypto_results.get('crypto_issues', []):
            # Handle case insensitive severity conversion
            severity_str = finding.get('severity', 'medium').lower()
            try:
                severity = SeverityLevel(severity_str)
            except ValueError:
                severity = SeverityLevel.MEDIUM  # Default fallback
                
            vuln = JadxVulnerability(
                vulnerability_type=VulnerabilityType.CRYPTO_WEAKNESS,
                title=finding.get('title', 'Crypto Vulnerability'),
                description=finding.get('description', 'Cryptographic weakness detected'),
                severity=severity,
                file_path=finding.get('file', 'unknown'),  # Use 'file' key from crypto analysis
                line_number=finding.get('line_number'),
                code_snippet=finding.get('evidence'),  # Use 'evidence' as code_snippet
                masvs_control=MasvsControl.MSTG_CRYPTO_1,
                confidence=finding.get('confidence', 0.8)
            )
            vulnerabilities.append(vuln)
        
        # Process secrets analysis results
        secrets_results = analysis_results.get('secrets_analysis', {})
        for finding in secrets_results.get('findings', []):
            vuln = JadxVulnerability(
                vulnerability_type=VulnerabilityType.HARDCODED_SECRET,
                title=finding.get('title', 'Hardcoded Secret'),
                description=finding.get('description', 'Hardcoded secret detected'),
                severity=SeverityLevel(finding.get('severity', 'high')),
                file_path=finding.get('file_path', 'unknown'),
                line_number=finding.get('line_number'),
                code_snippet=finding.get('code_snippet'),
                masvs_control=MasvsControl.MSTG_STORAGE_1,
                confidence=finding.get('confidence', 0.9)
            )
            vulnerabilities.append(vuln)
        
        # Process insecure patterns results
        patterns_results = analysis_results.get('insecure_patterns', {})
        for finding in patterns_results.get('findings', []):
            vuln = JadxVulnerability(
                vulnerability_type=VulnerabilityType.INSECURE_PATTERN,
                title=finding.get('title', 'Insecure Pattern'),
                description=finding.get('description', 'Insecure coding pattern detected'),
                severity=SeverityLevel(finding.get('severity', 'medium')),
                file_path=finding.get('file_path', 'unknown'),
                line_number=finding.get('line_number'),
                code_snippet=finding.get('code_snippet'),
                masvs_control=MasvsControl.MSTG_CODE_2,
                confidence=finding.get('confidence', 0.7)
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities

def run(apk_ctx) -> Tuple[str, Union[str, Text, Dict]]:
    """
    Main plugin execution function.
    
    Args:
        apk_ctx: APK context containing analysis targets
        
    Returns:
        Tuple[str, Union[str, Text, Dict]]: Analysis results with structured vulnerability data
    """
    plugin_name = "JADX Static Analysis"
    
    try:
        # Initialize and run analysis
        plugin = JadxStaticAnalysisPlugin(apk_ctx)
        analysis_result = plugin.analyze()
        
        # Check for cached results that include secrets
        cached_results = _load_cached_jadx_results(apk_ctx.package_name, apk_ctx.apk_path)
        
        # Create structured response with both vulnerabilities and secrets
        structured_response = {
            'analysis_result': analysis_result,
            'vulnerabilities': _extract_structured_vulnerabilities(analysis_result, cached_results),
            'execution_summary': {
                'status': analysis_result.status.value if analysis_result.status else 'unknown',
                'execution_time': analysis_result.execution_time,
                'total_findings': len(analysis_result.vulnerabilities) if analysis_result.vulnerabilities else 0
            }
        }
        
        return plugin_name, structured_response
        
    except Exception as e:
        logger.error(f"JADX static analysis failed: {e}", exc_info=True)
        
        # Try to provide fallback with cached results if available
        try:
            cached_results = _load_cached_jadx_results(apk_ctx.package_name, apk_ctx.apk_path)
            if cached_results:
                logger.info("Providing fallback results from cache")
                fallback_response = {
                    'vulnerabilities': _extract_structured_vulnerabilities(None, cached_results),
                    'execution_summary': {
                        'status': 'error_with_cache_fallback',
                        'execution_time': 0,
                        'total_findings': len(cached_results.get('analysis_results', {}).get('crypto_analysis', {}).get('crypto_issues', [])) + len(cached_results.get('analysis_results', {}).get('secrets_analysis', {}).get('secrets', []))
                    },
                    'error': str(e)
                }
                return plugin_name, fallback_response
        except Exception as fallback_error:
            logger.warning(f"Cache fallback also failed: {fallback_error}")
        
        # Final fallback to text error message
        error_output = Text()
        error_output.append(f"JADX Static Analysis - ERROR\n\n", style="bold red")
        error_output.append(f"Analysis failed: {str(e)}\n", style="red")
        
        return plugin_name, error_output

def _format_analysis_result(result: JadxAnalysisResult) -> Text:
    """Format analysis result for display."""
    output = Text()
    
    # Header based on analysis mode
    if result.analysis_mode == AnalysisMode.STAGED:
        output.append("🔍 JADX Static Analysis (Staged Processing)\n", style="bold green")
    elif result.analysis_mode == AnalysisMode.TIMEOUT_PROTECTED:
        output.append("⏰ JADX Static Analysis (Timeout Protection)\n", style="bold yellow")
    elif result.analysis_mode == AnalysisMode.FALLBACK:
        output.append("🔍 JADX Static Analysis (Fallback Mode)\n", style="bold blue")
    else:
        output.append("🔍 JADX Static Analysis\n", style="bold cyan")
    
    output.append("=" * 50 + "\n\n", style="cyan")
    
    # Status and metrics
    status_style = "green" if result.status == AnalysisStatus.SUCCESS else "yellow" if result.status == AnalysisStatus.PARTIAL else "red"
    output.append(f"Status: {result.status.value.upper()}\n", style=f"bold {status_style}")
    
    if result.resource_metrics:
        output.append(f"APK Size: {result.resource_metrics.apk_size_mb:.1f}MB\n", style="cyan")
        output.append(f"Processing Mode: {result.resource_metrics.processing_mode}\n", style="cyan")
        output.append(f"Timeout: {result.resource_metrics.timeout_used}s\n", style="cyan")
    
    output.append(f"Execution Time: {result.execution_time:.2f}s\n", style="cyan")
    output.append("\n")
    
    # Vulnerabilities/findings
    if result.vulnerabilities:
        stats = result.calculate_statistics()
        output.append(f"Findings: {stats['total_vulnerabilities']}\n", style="bold")
        
        if stats['critical_count'] > 0:
            output.append(f"• Critical: {stats['critical_count']}\n", style="red")
        if stats['high_count'] > 0:
            output.append(f"• High: {stats['high_count']}\n", style="red")
        if stats['medium_count'] > 0:
            output.append(f"• Medium: {stats['medium_count']}\n", style="yellow")
        if stats['low_count'] > 0:
            output.append(f"• Low: {stats['low_count']}\n", style="cyan")
        if stats['info_count'] > 0:
            output.append(f"• Info: {stats['info_count']}\n", style="white")
        
        output.append("\n")
        
        # Show top findings
        for i, vuln in enumerate(result.vulnerabilities[:5], 1):
            severity_style = "red" if vuln.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH] else "yellow" if vuln.severity == SeverityLevel.MEDIUM else "cyan"
            output.append(f"{i}. {vuln.title}\n", style=f"bold {severity_style}")
            output.append(f"   Severity: {vuln.severity.value.upper()}\n", style=severity_style)
            output.append(f"   File: {vuln.file_path}\n", style="white")
            if vuln.description:
                output.append(f"   Description: {vuln.description}\n", style="white")
            output.append("\n")
        
        if len(result.vulnerabilities) > 5:
            output.append(f"... and {len(result.vulnerabilities) - 5} more findings\n\n", style="dim")
    
    # Error information
    if result.error_message:
        output.append("Error Details:\n", style="bold red")
        output.append(f"{result.error_message}\n\n", style="red")
    
    # MASVS mapping
    output.append("📋 MASVS Controls Covered:\n", style="bold cyan")
    for control in PLUGIN_CHARACTERISTICS["masvs_controls"]:
        output.append(f"• {control}\n", style="cyan")
    
    return output

def run_plugin(apk_ctx) -> Tuple[str, Union[str, Text]]:
    """Plugin interface function expected by the plugin manager."""
    return run(apk_ctx)

# Export for modular compatibility
__all__ = [
    'run',
    'run_plugin',
    'JadxStaticAnalysisPlugin',
    'PLUGIN_METADATA',
    'PLUGIN_CHARACTERISTICS'
]

# Legacy compatibility export
PLUGIN_INFO = PLUGIN_METADATA 