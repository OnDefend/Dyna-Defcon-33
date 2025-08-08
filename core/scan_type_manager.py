#!/usr/bin/env python3
"""
Enhanced Scan Type Manager for AODS

This module provides intelligent scan type management with advanced capabilities including:
- Intelligent scan management with AI-based decision making
- Adaptive scan strategies based on APK characteristics
- Performance-based selection using historical data
- Resource allocation optimization
- Scan result correlation across different scan types
- Advanced scheduling with priority queuing
- High-quality orchestration capabilities

Features:
- AI-powered scan type selection
- APK characteristic analysis
- Historical performance integration
- Resource optimization algorithms
- Cross-scan type correlation
- Priority-based scheduling
- Multi-tenant support
- Comprehensive monitoring and analytics
"""

import logging
import threading
import time
import json
import hashlib
import statistics
import psutil
from enum import Enum
from typing import Dict, Any, Optional, List, Set, Tuple, Union
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, Future
import zipfile
import xml.etree.ElementTree as ET

# Import AODS components
try:
    from .scan_mode_tracker import (
        get_scan_analytics, 
        PerformanceMetrics,
        get_predictive_recommendation
    )
    SCAN_MODE_TRACKER_AVAILABLE = True
except ImportError:
    SCAN_MODE_TRACKER_AVAILABLE = False

logger = logging.getLogger(__name__)

class ScanType(Enum):
    """Enhanced enumeration of supported scan types."""
    STATIC_ONLY = "static-only"
    DYNAMIC_ONLY = "dynamic-only"
    FULL_SCAN = "full-scan"
    AUTO_DETECT = "auto-detect"
    INTELLIGENT = "intelligent"
    ADAPTIVE = "adaptive"
    PERFORMANCE_OPTIMIZED = "performance-optimized"
    RESOURCE_CONSTRAINED = "resource-constrained"

class ScanPriority(Enum):
    """Scan priority levels for scheduling."""
    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"
    BACKGROUND = "background"

class ResourceProfile(Enum):
    """Resource allocation profiles."""
    MINIMAL = "minimal"
    STANDARD = "standard"
    AGGRESSIVE = "aggressive"
    UNLIMITED = "unlimited"

@dataclass
class APKCharacteristics:
    """APK characteristics for intelligent analysis."""
    file_size_mb: float
    package_name: str
    version_code: int
    version_name: str
    min_sdk_version: int
    target_sdk_version: int
    permissions_count: int
    activities_count: int
    services_count: int
    receivers_count: int
    providers_count: int
    native_libraries: List[str]
    has_native_code: bool
    obfuscated: bool
    complexity_score: float
    security_features: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

@dataclass
class ScanConfiguration:
    """Enhanced scan configuration with intelligent parameters."""
    scan_type: ScanType
    priority: ScanPriority
    resource_profile: ResourceProfile
    timeout_seconds: int
    max_memory_mb: int
    max_cpu_percent: float
    plugins: List[str]
    enable_static: bool
    enable_dynamic: bool
    enable_ai_analysis: bool
    adaptive_timeout: bool
    correlation_enabled: bool
    custom_parameters: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        data['scan_type'] = self.scan_type.value
        data['priority'] = self.priority.value
        data['resource_profile'] = self.resource_profile.value
        return data

@dataclass
class ScanRecommendation:
    """Intelligent scan recommendation."""
    recommended_type: ScanType
    confidence_score: float
    reasoning: str
    estimated_duration: int
    resource_requirements: Dict[str, float]
    expected_accuracy: float
    alternative_types: List[ScanType]
    risk_assessment: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        data['recommended_type'] = self.recommended_type.value
        data['alternative_types'] = [t.value for t in self.alternative_types]
        return data

@dataclass
class ScanJob:
    """Scan job for advanced scheduling."""
    job_id: str
    package_name: str
    apk_path: str
    scan_config: ScanConfiguration
    created_at: datetime
    scheduled_at: Optional[datetime]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    status: str
    progress: float
    result: Optional[Dict[str, Any]]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        data['scan_config'] = self.scan_config.to_dict()
        data['created_at'] = self.created_at.isoformat()
        data['scheduled_at'] = self.scheduled_at.isoformat() if self.scheduled_at else None
        data['started_at'] = self.started_at.isoformat() if self.started_at else None
        data['completed_at'] = self.completed_at.isoformat() if self.completed_at else None
        return data

class APKAnalyzer:
    """Advanced APK characteristic analyzer."""
    
    def __init__(self):
        self._cache = {}
        self._lock = threading.Lock()
    
    def analyze_apk(self, apk_path: str) -> APKCharacteristics:
        """Analyze APK characteristics for intelligent scan selection."""
        with self._lock:
            # Check cache first
            apk_hash = self._get_file_hash(apk_path)
            if apk_hash in self._cache:
                return self._cache[apk_hash]
            
            try:
                characteristics = self._extract_characteristics(apk_path)
                self._cache[apk_hash] = characteristics
                return characteristics
            except Exception as e:
                logger.error(f"APK analysis failed: {e}")
                return self._create_default_characteristics(apk_path)
    
    def _get_file_hash(self, apk_path: str) -> str:
        """Get file hash for caching."""
        try:
            with open(apk_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except Exception:
            return str(hash(apk_path))
    
    def _extract_characteristics(self, apk_path: str) -> APKCharacteristics:
        """Extract detailed APK characteristics."""
        file_size = Path(apk_path).stat().st_size / (1024 * 1024)  # MB
        
        # Basic characteristics
        characteristics = {
            'file_size_mb': file_size,
            'package_name': 'unknown',
            'version_code': 1,
            'version_name': '1.0',
            'min_sdk_version': 21,
            'target_sdk_version': 30,
            'permissions_count': 0,
            'activities_count': 0,
            'services_count': 0,
            'receivers_count': 0,
            'providers_count': 0,
            'native_libraries': [],
            'has_native_code': False,
            'obfuscated': False,
            'complexity_score': 0.5,
            'security_features': []
        }
        
        try:
            # Analyze APK using zipfile
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Check for native libraries
                native_libs = [f for f in apk_zip.namelist() if f.startswith('lib/') and f.endswith('.so')]
                characteristics['native_libraries'] = native_libs
                characteristics['has_native_code'] = len(native_libs) > 0
                
                # Try to read AndroidManifest.xml
                try:
                    manifest_data = apk_zip.read('AndroidManifest.xml')
                    # Basic manifest analysis (would need proper AXML parser for full analysis)
                    characteristics['permissions_count'] = manifest_data.count(b'android.permission')
                    
                    # Estimate complexity based on file count and size
                    file_count = len(apk_zip.namelist())
                    characteristics['complexity_score'] = min(1.0, (file_count / 1000.0) + (file_size / 100.0))
                    
                    # Check for obfuscation indicators
                    class_files = [f for f in apk_zip.namelist() if f.endswith('.dex')]
                    if class_files:
                        # Simple heuristic: small class names might indicate obfuscation
                        characteristics['obfuscated'] = file_size > 10 and len(class_files) > 1
                    
                except Exception as e:
                    logger.debug(f"Manifest analysis failed: {e}")
                
                # Security features detection
                security_features = []
                if any('proguard' in f.lower() for f in apk_zip.namelist()):
                    security_features.append('code_obfuscation')
                if characteristics['has_native_code']:
                    security_features.append('native_code')
                if file_size > 50:  # Large APKs often have more security measures
                    security_features.append('complex_application')
                
                characteristics['security_features'] = security_features
                
        except Exception as e:
            logger.error(f"Detailed APK analysis failed: {e}")
        
        return APKCharacteristics(**characteristics)
    
    def _create_default_characteristics(self, apk_path: str) -> APKCharacteristics:
        """Create default characteristics when analysis fails."""
        try:
            file_size = Path(apk_path).stat().st_size / (1024 * 1024)
        except Exception:
            file_size = 10.0
        
        return APKCharacteristics(
            file_size_mb=file_size,
            package_name='unknown',
            version_code=1,
            version_name='1.0',
            min_sdk_version=21,
            target_sdk_version=30,
            permissions_count=10,
            activities_count=5,
            services_count=2,
            receivers_count=3,
            providers_count=1,
            native_libraries=[],
            has_native_code=False,
            obfuscated=False,
            complexity_score=0.5,
            security_features=[]
        )

class IntelligentDecisionEngine:
    """AI-powered decision engine for scan type selection."""
    
    def __init__(self):
        self.apk_analyzer = APKAnalyzer()
        self._decision_cache = {}
        self._lock = threading.Lock()
    
    def recommend_scan_type(self, apk_path: str, context: Dict[str, Any] = None) -> ScanRecommendation:
        """Recommend optimal scan type using intelligent analysis."""
        with self._lock:
            # Analyze APK characteristics
            characteristics = self.apk_analyzer.analyze_apk(apk_path)
            
            # Get context information
            context = context or {}
            device_available = context.get('device_available', False)
            time_constraints = context.get('time_constraints', False)
            resource_constraints = context.get('resource_constraints', False)
            accuracy_priority = context.get('accuracy_priority', 'balanced')
            
            # Get historical performance data if available
            historical_data = None
            if SCAN_MODE_TRACKER_AVAILABLE:
                try:
                    historical_data = get_scan_analytics(characteristics.package_name)
                except Exception as e:
                    logger.debug(f"Failed to get historical data: {e}")
            
            # Intelligent decision making
            return self._make_intelligent_decision(
                characteristics, context, historical_data
            )
    
    def _make_intelligent_decision(self, characteristics: APKCharacteristics, 
                                 context: Dict[str, Any], 
                                 historical_data: Any) -> ScanRecommendation:
        """Make intelligent scan type decision."""
        
        # Decision factors
        factors = {
            'complexity': characteristics.complexity_score,
            'size': min(1.0, characteristics.file_size_mb / 100.0),
            'native_code': 1.0 if characteristics.has_native_code else 0.0,
            'obfuscation': 1.0 if characteristics.obfuscated else 0.0,
            'security_features': len(characteristics.security_features) / 5.0,
            'device_available': 1.0 if context.get('device_available', False) else 0.0,
            'time_constraints': 1.0 if context.get('time_constraints', False) else 0.0,
            'resource_constraints': 1.0 if context.get('resource_constraints', False) else 0.0
        }
        
        # Calculate scores for each scan type
        scores = self._calculate_scan_type_scores(factors, historical_data)
        
        # Select best scan type
        best_type = max(scores.keys(), key=lambda k: scores[k]['score'])
        best_score = scores[best_type]
        
        # Create recommendation
        return ScanRecommendation(
            recommended_type=ScanType(best_type),
            confidence_score=best_score['score'],
            reasoning=best_score['reasoning'],
            estimated_duration=best_score['duration'],
            resource_requirements=best_score['resources'],
            expected_accuracy=best_score['accuracy'],
            alternative_types=[ScanType(t) for t in sorted(scores.keys(), 
                             key=lambda k: scores[k]['score'], reverse=True)[1:3]],
            risk_assessment=self._assess_risk(characteristics, context)
        )
    
    def _calculate_scan_type_scores(self, factors: Dict[str, float], 
                                  historical_data: Any) -> Dict[str, Dict[str, Any]]:
        """Calculate scores for each scan type."""
        
        scores = {}
        
        # Static-only scan
        static_score = (
            0.3 * (1.0 - factors['time_constraints']) +
            0.2 * (1.0 - factors['device_available']) +
            0.2 * factors['complexity'] +
            0.15 * (1.0 - factors['resource_constraints']) +
            0.15 * factors['obfuscation']
        )
        
        scores['static-only'] = {
            'score': static_score,
            'reasoning': 'Fast analysis suitable for code review and basic security assessment',
            'duration': int(300 + factors['complexity'] * 600),
            'resources': {'cpu': 25, 'memory': 512, 'disk': 100},
            'accuracy': 0.7 + factors['complexity'] * 0.15
        }
        
        # Dynamic-only scan
        dynamic_score = (
            0.4 * factors['device_available'] +
            0.2 * factors['native_code'] +
            0.2 * (1.0 - factors['obfuscation']) +
            0.1 * (1.0 - factors['time_constraints']) +
            0.1 * (1.0 - factors['resource_constraints'])
        )
        
        scores['dynamic-only'] = {
            'score': dynamic_score,
            'reasoning': 'Runtime analysis for behavioral and network security assessment',
            'duration': int(600 + factors['complexity'] * 900),
            'resources': {'cpu': 40, 'memory': 1024, 'disk': 200},
            'accuracy': 0.75 + factors['native_code'] * 0.1
        }
        
        # Full scan
        full_score = (
            0.3 * factors['device_available'] +
            0.25 * factors['complexity'] +
            0.2 * factors['security_features'] +
            0.15 * (1.0 - factors['time_constraints']) +
            0.1 * (1.0 - factors['resource_constraints'])
        )
        
        scores['full-scan'] = {
            'score': full_score,
            'reasoning': 'Comprehensive analysis combining static and dynamic techniques',
            'duration': int(900 + factors['complexity'] * 1200),
            'resources': {'cpu': 60, 'memory': 2048, 'disk': 500},
            'accuracy': 0.9 + factors['complexity'] * 0.05
        }
        
        # Intelligent scan (adaptive)
        intelligent_score = (
            0.25 * factors['complexity'] +
            0.2 * factors['security_features'] +
            0.2 * factors['obfuscation'] +
            0.15 * factors['device_available'] +
            0.1 * (1.0 - factors['time_constraints']) +
            0.1 * (1.0 - factors['resource_constraints'])
        )
        
        scores['intelligent'] = {
            'score': intelligent_score,
            'reasoning': 'AI-powered adaptive analysis with optimal technique selection',
            'duration': int(600 + factors['complexity'] * 800),
            'resources': {'cpu': 45, 'memory': 1536, 'disk': 300},
            'accuracy': 0.85 + factors['complexity'] * 0.1
        }
        
        # Adjust scores based on historical data
        if historical_data and hasattr(historical_data, 'mode_distribution'):
            for mode, count in historical_data.mode_distribution.items():
                if mode in scores:
                    # Boost score for historically successful modes
                    boost = min(0.1, count / 10.0)
                    scores[mode]['score'] += boost
                    scores[mode]['reasoning'] += f" (Historical success: {count} scans)"
        
        return scores
    
    def _assess_risk(self, characteristics: APKCharacteristics, context: Dict[str, Any]) -> str:
        """Assess security risk level."""
        risk_factors = []
        
        if characteristics.has_native_code:
            risk_factors.append("native code")
        if characteristics.obfuscated:
            risk_factors.append("code obfuscation")
        if characteristics.complexity_score > 0.7:
            risk_factors.append("high complexity")
        if characteristics.permissions_count > 20:
            risk_factors.append("extensive permissions")
        
        if len(risk_factors) >= 3:
            return f"HIGH - Multiple risk factors: {', '.join(risk_factors)}"
        elif len(risk_factors) >= 1:
            return f"MEDIUM - Risk factors: {', '.join(risk_factors)}"
        else:
            return "LOW - Standard application profile"

class ResourceAllocationOptimizer:
    """Advanced resource allocation optimizer."""
    
    def __init__(self):
        self._resource_history = deque(maxlen=100)
        self._allocation_cache = {}
        self._lock = threading.Lock()
    
    def optimize_allocation(self, scan_config: ScanConfiguration, 
                          system_resources: Dict[str, float]) -> ScanConfiguration:
        """Optimize resource allocation for scan configuration."""
        with self._lock:
            # Get current system state
            available_cpu = system_resources.get('cpu_available', 50.0)
            available_memory = system_resources.get('memory_available_mb', 2048)
            available_disk = system_resources.get('disk_available_gb', 10.0) * 1024
            
            # Create optimized configuration
            optimized_config = self._create_optimized_config(
                scan_config, available_cpu, available_memory, available_disk
            )
            
            # Cache allocation decision
            cache_key = self._get_cache_key(scan_config, system_resources)
            self._allocation_cache[cache_key] = optimized_config
            
            return optimized_config
    
    def _create_optimized_config(self, config: ScanConfiguration, 
                               cpu: float, memory: float, disk: float) -> ScanConfiguration:
        """Create optimized configuration based on available resources."""
        
        # Resource profile adjustments
        if config.resource_profile == ResourceProfile.MINIMAL:
            cpu_limit = min(config.max_cpu_percent, cpu * 0.3)
            memory_limit = min(config.max_memory_mb, memory * 0.2)
        elif config.resource_profile == ResourceProfile.STANDARD:
            cpu_limit = min(config.max_cpu_percent, cpu * 0.6)
            memory_limit = min(config.max_memory_mb, memory * 0.5)
        elif config.resource_profile == ResourceProfile.AGGRESSIVE:
            cpu_limit = min(config.max_cpu_percent, cpu * 0.8)
            memory_limit = min(config.max_memory_mb, memory * 0.7)
        else:  # UNLIMITED
            cpu_limit = config.max_cpu_percent
            memory_limit = config.max_memory_mb
        
        # Adaptive timeout based on resources
        timeout_adjustment = 1.0
        if cpu < 30:  # Low CPU availability
            timeout_adjustment *= 1.5
        if memory < 1024:  # Low memory availability
            timeout_adjustment *= 1.3
        
        optimized_timeout = int(config.timeout_seconds * timeout_adjustment)
        
        # Create optimized configuration
        return ScanConfiguration(
            scan_type=config.scan_type,
            priority=config.priority,
            resource_profile=config.resource_profile,
            timeout_seconds=optimized_timeout,
            max_memory_mb=int(memory_limit),
            max_cpu_percent=cpu_limit,
            plugins=config.plugins.copy(),
            enable_static=config.enable_static,
            enable_dynamic=config.enable_dynamic,
            enable_ai_analysis=config.enable_ai_analysis,
            adaptive_timeout=True,
            correlation_enabled=config.correlation_enabled,
            custom_parameters=config.custom_parameters.copy()
        )
    
    def _get_cache_key(self, config: ScanConfiguration, resources: Dict[str, float]) -> str:
        """Generate cache key for resource allocation."""
        key_data = {
            'scan_type': config.scan_type.value,
            'resource_profile': config.resource_profile.value,
            'cpu': int(resources.get('cpu_available', 0)),
            'memory': int(resources.get('memory_available_mb', 0)),
        }
        return hashlib.md5(json.dumps(key_data, sort_keys=True).encode()).hexdigest()

class ScanResultCorrelator:
    """Correlates scan results across different scan types."""
    
    def __init__(self):
        self._correlation_data = defaultdict(list)
        self._lock = threading.Lock()
    
    def correlate_results(self, package_name: str, scan_type: ScanType, 
                         results: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate scan results with historical data."""
        with self._lock:
            # Store current results
            correlation_entry = {
                'scan_type': scan_type.value,
                'timestamp': datetime.now().isoformat(),
                'results': results,
                'vulnerability_count': results.get('vulnerability_count', 0),
                'severity_distribution': results.get('severity_distribution', {}),
                'scan_duration': results.get('scan_duration', 0)
            }
            
            self._correlation_data[package_name].append(correlation_entry)
            
            # Perform correlation analysis
            correlation_analysis = self._analyze_correlations(package_name)
            
            # Enhance results with correlation insights
            enhanced_results = results.copy()
            enhanced_results['correlation_analysis'] = correlation_analysis
            
            return enhanced_results
    
    def _analyze_correlations(self, package_name: str) -> Dict[str, Any]:
        """Analyze correlations across scan types."""
        package_data = self._correlation_data[package_name]
        
        if len(package_data) < 2:
            return {'status': 'insufficient_data', 'scans_count': len(package_data)}
        
        # Group by scan type
        by_type = defaultdict(list)
        for entry in package_data:
            by_type[entry['scan_type']].append(entry)
        
        # Calculate correlations
        correlations = {}
        
        # Vulnerability detection consistency
        vuln_counts = [entry['vulnerability_count'] for entry in package_data]
        if vuln_counts:
            correlations['vulnerability_consistency'] = {
                'mean': statistics.mean(vuln_counts),
                'std_dev': statistics.stdev(vuln_counts) if len(vuln_counts) > 1 else 0,
                'range': max(vuln_counts) - min(vuln_counts)
            }
        
        # Scan type effectiveness
        type_effectiveness = {}
        for scan_type, entries in by_type.items():
            if entries:
                avg_vulns = statistics.mean(entry['vulnerability_count'] for entry in entries)
                avg_duration = statistics.mean(entry['scan_duration'] for entry in entries)
                type_effectiveness[scan_type] = {
                    'avg_vulnerabilities': avg_vulns,
                    'avg_duration': avg_duration,
                    'efficiency_score': avg_vulns / (avg_duration / 60) if avg_duration > 0 else 0
                }
        
        correlations['type_effectiveness'] = type_effectiveness
        
        # Recommendations based on correlation
        recommendations = []
        if type_effectiveness:
            best_type = max(type_effectiveness.keys(), 
                          key=lambda k: type_effectiveness[k]['efficiency_score'])
            recommendations.append(f"Most efficient scan type: {best_type}")
        
        correlations['recommendations'] = recommendations
        
        return {
            'status': 'analyzed',
            'scans_count': len(package_data),
            'scan_types_used': list(by_type.keys()),
            'correlations': correlations
        }

class AdvancedScheduler:
    """Advanced scheduling system with priority queuing."""
    
    def __init__(self, max_concurrent_scans: int = 3):
        self.max_concurrent_scans = max_concurrent_scans
        self._job_queue = deque()
        self._running_jobs = {}
        self._completed_jobs = {}
        self._executor = ThreadPoolExecutor(max_workers=max_concurrent_scans)
        self._lock = threading.Lock()
        self._scheduler_thread = None
        self._running = False
    
    def start_scheduler(self):
        """Start the advanced scheduler."""
        with self._lock:
            if not self._running:
                self._running = True
                self._scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
                self._scheduler_thread.start()
                logger.info("Advanced scheduler started")
    
    def stop_scheduler(self):
        """Stop the advanced scheduler."""
        with self._lock:
            self._running = False
            if self._scheduler_thread:
                self._scheduler_thread.join(timeout=5.0)
            self._executor.shutdown(wait=True)
            logger.info("Advanced scheduler stopped")
    
    def schedule_scan(self, scan_job: ScanJob) -> str:
        """Schedule a scan job with priority queuing."""
        with self._lock:
            # Insert job in priority order
            inserted = False
            for i, existing_job in enumerate(self._job_queue):
                if self._compare_priority(scan_job.scan_config.priority, 
                                        existing_job.scan_config.priority):
                    self._job_queue.insert(i, scan_job)
                    inserted = True
                    break
            
            if not inserted:
                self._job_queue.append(scan_job)
            
            logger.info(f"Scheduled scan job {scan_job.job_id} with priority {scan_job.scan_config.priority.value}")
            return scan_job.job_id
    
    def _compare_priority(self, priority1: ScanPriority, priority2: ScanPriority) -> bool:
        """Compare scan priorities (True if priority1 > priority2)."""
        priority_order = {
            ScanPriority.CRITICAL: 5,
            ScanPriority.HIGH: 4,
            ScanPriority.NORMAL: 3,
            ScanPriority.LOW: 2,
            ScanPriority.BACKGROUND: 1
        }
        return priority_order[priority1] > priority_order[priority2]
    
    def _scheduler_loop(self):
        """Main scheduler loop."""
        while self._running:
            try:
                self._process_queue()
                time.sleep(1.0)  # Check every second
            except Exception as e:
                logger.error(f"Scheduler error: {e}")
                time.sleep(5.0)  # Wait before retry
    
    def _process_queue(self):
        """Process the job queue."""
        with self._lock:
            # Remove completed jobs
            completed_job_ids = []
            for job_id, future in self._running_jobs.items():
                if future.done():
                    completed_job_ids.append(job_id)
            
            for job_id in completed_job_ids:
                future = self._running_jobs.pop(job_id)
                try:
                    result = future.result()
                    self._completed_jobs[job_id] = result
                except Exception as e:
                    logger.error(f"Job {job_id} failed: {e}")
                    self._completed_jobs[job_id] = {'error': str(e)}
            
            # Start new jobs if capacity available
            while (len(self._running_jobs) < self.max_concurrent_scans and 
                   self._job_queue):
                
                job = self._job_queue.popleft()
                job.started_at = datetime.now()
                job.status = "running"
                
                future = self._executor.submit(self._execute_scan_job, job)
                self._running_jobs[job.job_id] = future
                
                logger.info(f"Started scan job {job.job_id}")
    
    def _execute_scan_job(self, job: ScanJob) -> Dict[str, Any]:
        """Execute a scan job."""
        try:
            # This would integrate with the actual AODS scan execution
            # For now, simulate scan execution
            time.sleep(job.scan_config.timeout_seconds / 10)  # Simulate work
            
            result = {
                'job_id': job.job_id,
                'package_name': job.package_name,
                'scan_type': job.scan_config.scan_type.value,
                'status': 'completed',
                'duration': (datetime.now() - job.started_at).total_seconds(),
                'vulnerability_count': 5,  # Simulated
                'severity_distribution': {'high': 1, 'medium': 2, 'low': 2}
            }
            
            job.completed_at = datetime.now()
            job.status = "completed"
            job.progress = 100.0
            job.result = result
            
            return result
            
        except Exception as e:
            job.status = "failed"
            job.completed_at = datetime.now()
            raise
    
    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a scheduled job."""
        with self._lock:
            # Check completed jobs
            if job_id in self._completed_jobs:
                return {'status': 'completed', 'result': self._completed_jobs[job_id]}
            
            # Check running jobs
            if job_id in self._running_jobs:
                return {'status': 'running', 'progress': 'unknown'}
            
            # Check queued jobs
            for job in self._job_queue:
                if job.job_id == job_id:
                    return {'status': 'queued', 'position': list(self._job_queue).index(job)}
            
            return None

class EnhancedScanTypeManager:
    """Enhanced scan type manager with intelligent capabilities."""
    
    def __init__(self, max_concurrent_scans: int = 3):
        """Initialize the enhanced scan type manager."""
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Core components
        self.decision_engine = IntelligentDecisionEngine()
        self.resource_optimizer = ResourceAllocationOptimizer()
        self.result_correlator = ScanResultCorrelator()
        self.scheduler = AdvancedScheduler(max_concurrent_scans)
        
        # Enhanced configurations
        self.enhanced_configs = self._create_enhanced_configurations()
        
        # Legacy support
        self.supported_types = [ScanType.STATIC_ONLY, ScanType.DYNAMIC_ONLY, 
                               ScanType.FULL_SCAN, ScanType.AUTO_DETECT]
        
        # Start scheduler
        self.scheduler.start_scheduler()
        
        self.logger.info("Enhanced Scan Type Manager initialized")
    
    def _create_enhanced_configurations(self) -> Dict[ScanType, ScanConfiguration]:
        """Create enhanced scan configurations."""
        configs = {}
        
        # Static-only configuration
        configs[ScanType.STATIC_ONLY] = ScanConfiguration(
            scan_type=ScanType.STATIC_ONLY,
            priority=ScanPriority.NORMAL,
            resource_profile=ResourceProfile.STANDARD,
            timeout_seconds=600,
            max_memory_mb=1024,
            max_cpu_percent=50.0,
            plugins=["static", "manifest", "permissions", "cryptography"],
            enable_static=True,
            enable_dynamic=False,
            enable_ai_analysis=True,
            adaptive_timeout=True,
            correlation_enabled=True,
            custom_parameters={}
        )
        
        # Dynamic-only configuration
        configs[ScanType.DYNAMIC_ONLY] = ScanConfiguration(
            scan_type=ScanType.DYNAMIC_ONLY,
            priority=ScanPriority.NORMAL,
            resource_profile=ResourceProfile.STANDARD,
            timeout_seconds=900,
            max_memory_mb=2048,
            max_cpu_percent=70.0,
            plugins=["dynamic", "network", "runtime", "component_exploitation"],
            enable_static=False,
            enable_dynamic=True,
            enable_ai_analysis=True,
            adaptive_timeout=True,
            correlation_enabled=True,
            custom_parameters={}
        )
        
        # Full scan configuration
        configs[ScanType.FULL_SCAN] = ScanConfiguration(
            scan_type=ScanType.FULL_SCAN,
            priority=ScanPriority.HIGH,
            resource_profile=ResourceProfile.AGGRESSIVE,
            timeout_seconds=1800,
            max_memory_mb=4096,
            max_cpu_percent=80.0,
            plugins=["static", "dynamic", "manifest", "permissions", "cryptography", 
                    "network", "runtime", "component_exploitation", "native_binary"],
            enable_static=True,
            enable_dynamic=True,
            enable_ai_analysis=True,
            adaptive_timeout=True,
            correlation_enabled=True,
            custom_parameters={}
        )
        
        # Intelligent scan configuration
        configs[ScanType.INTELLIGENT] = ScanConfiguration(
            scan_type=ScanType.INTELLIGENT,
            priority=ScanPriority.HIGH,
            resource_profile=ResourceProfile.STANDARD,
            timeout_seconds=1200,
            max_memory_mb=3072,
            max_cpu_percent=60.0,
            plugins=["auto"],  # Will be determined dynamically
            enable_static=True,
            enable_dynamic=True,
            enable_ai_analysis=True,
            adaptive_timeout=True,
            correlation_enabled=True,
            custom_parameters={"ai_driven": True}
        )
        
        return configs
    
    def get_intelligent_recommendation(self, apk_path: str, 
                                     context: Dict[str, Any] = None) -> ScanRecommendation:
        """Get intelligent scan type recommendation."""
        return self.decision_engine.recommend_scan_type(apk_path, context)
    
    def create_optimized_scan_job(self, package_name: str, apk_path: str,
                                scan_type: ScanType = None,
                                priority: ScanPriority = ScanPriority.NORMAL,
                                context: Dict[str, Any] = None) -> ScanJob:
        """Create an optimized scan job."""
        
        # Get recommendation if scan type not specified
        if scan_type is None:
            recommendation = self.get_intelligent_recommendation(apk_path, context)
            scan_type = recommendation.recommended_type
        
        # Get base configuration
        base_config = self.enhanced_configs.get(scan_type, 
                                               self.enhanced_configs[ScanType.FULL_SCAN])
        
        # Override priority if specified
        base_config.priority = priority
        
        # Optimize resource allocation
        system_resources = self._get_system_resources()
        optimized_config = self.resource_optimizer.optimize_allocation(
            base_config, system_resources
        )
        
        # Create scan job
        job_id = self._generate_job_id(package_name)
        scan_job = ScanJob(
            job_id=job_id,
            package_name=package_name,
            apk_path=apk_path,
            scan_config=optimized_config,
            created_at=datetime.now(),
            scheduled_at=None,
            started_at=None,
            completed_at=None,
            status="created",
            progress=0.0,
            result=None
        )
        
        return scan_job
    
    def schedule_scan(self, scan_job: ScanJob) -> str:
        """Schedule a scan job for execution."""
        return self.scheduler.schedule_scan(scan_job)
    
    def correlate_scan_results(self, package_name: str, scan_type: ScanType,
                             results: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate scan results with historical data."""
        return self.result_correlator.correlate_results(package_name, scan_type, results)
    
    def _get_system_resources(self) -> Dict[str, float]:
        """Get current system resource availability."""
        try:
            cpu_percent = psutil.cpu_percent(interval=1.0)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            return {
                'cpu_available': 100.0 - cpu_percent,
                'memory_available_mb': memory.available / (1024 * 1024),
                'disk_available_gb': disk.free / (1024 * 1024 * 1024)
            }
        except Exception as e:
            logger.warning(f"Failed to get system resources: {e}")
            return {
                'cpu_available': 50.0,
                'memory_available_mb': 2048.0,
                'disk_available_gb': 10.0
            }
    
    def _generate_job_id(self, package_name: str) -> str:
        """Generate unique job ID."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        package_hash = hashlib.md5(package_name.encode()).hexdigest()[:8]
        return f"scan_{timestamp}_{package_hash}"
    
    # Legacy compatibility methods
    def get_supported_types(self) -> List[ScanType]:
        """Get list of supported scan types (legacy compatibility)."""
        return self.supported_types.copy()
    
    def validate_scan_type(self, scan_type: str) -> bool:
        """Validate if a scan type is supported (legacy compatibility)."""
        try:
            ScanType(scan_type)
            return True
        except ValueError:
            return False
    
    def get_scan_type(self, scan_type_str: str) -> Optional[ScanType]:
        """Get ScanType enum from string (legacy compatibility)."""
        try:
            return ScanType(scan_type_str)
        except ValueError:
            self.logger.error(f"Invalid scan type: {scan_type_str}")
            return None
    
    def get_default_config(self, scan_type: ScanType) -> Dict[str, Any]:
        """Get default configuration for a scan type (legacy compatibility)."""
        config = self.enhanced_configs.get(scan_type)
        if config:
            return config.to_dict()
        
        # Fallback to basic configurations
        legacy_configs = {
            ScanType.STATIC_ONLY: {
                "enable_static": True,
                "enable_dynamic": False,
                "timeout": 600,
                "plugins": ["static", "manifest", "permissions"]
            },
            ScanType.DYNAMIC_ONLY: {
                "enable_static": False,
                "enable_dynamic": True,
                "timeout": 900,
                "plugins": ["dynamic", "network", "runtime"]
            },
            ScanType.FULL_SCAN: {
                "enable_static": True,
                "enable_dynamic": True,
                "timeout": 1800,
                "plugins": ["static", "dynamic", "manifest", "permissions", "network", "runtime"]
            },
            ScanType.AUTO_DETECT: {
                "enable_static": True,
                "enable_dynamic": True,
                "timeout": 1800,
                "plugins": ["auto"]
            }
        }
        
        return legacy_configs.get(scan_type, {}).copy()
    
    def auto_detect_scan_type(self, apk_path: str, device_available: bool = False) -> ScanType:
        """Auto-detect optimal scan type (enhanced with intelligence)."""
        context = {'device_available': device_available}
        recommendation = self.get_intelligent_recommendation(apk_path, context)
        return recommendation.recommended_type
    
    def shutdown(self):
        """Shutdown the enhanced scan type manager."""
        self.scheduler.stop_scheduler()
        self.logger.info("Enhanced Scan Type Manager shutdown complete")

# Global instance with enhanced capabilities
_enhanced_scan_type_manager = EnhancedScanTypeManager()

# Legacy compatibility functions
def get_scan_type_manager() -> EnhancedScanTypeManager:
    """Get the global enhanced scan type manager instance."""
    return _enhanced_scan_type_manager

def validate_scan_type(scan_type: str) -> bool:
    """Validate if a scan type is supported (compatibility function)."""
    return _enhanced_scan_type_manager.validate_scan_type(scan_type)

def get_supported_scan_types() -> List[str]:
    """Get list of supported scan type strings (compatibility function)."""
    return [st.value for st in _enhanced_scan_type_manager.get_supported_types()]

def auto_detect_optimal_scan_type(apk_path: str, device_available: bool = False) -> str:
    """Auto-detect optimal scan type (enhanced compatibility function)."""
    scan_type = _enhanced_scan_type_manager.auto_detect_scan_type(apk_path, device_available)
    return scan_type.value

# Enhanced functions for new capabilities
def get_intelligent_scan_recommendation(apk_path: str, context: Dict[str, Any] = None) -> ScanRecommendation:
    """Get intelligent scan type recommendation."""
    return _enhanced_scan_type_manager.get_intelligent_recommendation(apk_path, context)

def create_optimized_scan_job(package_name: str, apk_path: str,
                            scan_type: ScanType = None,
                            priority: ScanPriority = ScanPriority.NORMAL,
                            context: Dict[str, Any] = None) -> ScanJob:
    """Create an optimized scan job."""
    return _enhanced_scan_type_manager.create_optimized_scan_job(
        package_name, apk_path, scan_type, priority, context
    )

def schedule_scan_job(scan_job: ScanJob) -> str:
    """Schedule a scan job for execution."""
    return _enhanced_scan_type_manager.schedule_scan(scan_job)

def correlate_scan_results(package_name: str, scan_type: ScanType, results: Dict[str, Any]) -> Dict[str, Any]:
    """Correlate scan results with historical data."""
    return _enhanced_scan_type_manager.correlate_scan_results(package_name, scan_type, results)

def shutdown_scan_type_manager():
    """Shutdown the enhanced scan type manager."""
    _enhanced_scan_type_manager.shutdown() 