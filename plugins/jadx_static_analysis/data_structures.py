#!/usr/bin/env python3
"""
Data Structures for JADX Static Analysis Plugin

This module defines the core data structures used throughout the JADX static analysis
plugin for consistent data handling and type safety.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from datetime import datetime

class AnalysisMode(Enum):
    """JADX analysis mode"""
    STAGED = "staged"
    DIRECT = "direct"
    FALLBACK = "fallback"
    TIMEOUT_PROTECTED = "timeout_protected"

class AnalysisStatus(Enum):
    """Analysis execution status"""
    SUCCESS = "success"
    PARTIAL = "partial"
    TIMEOUT = "timeout"
    FAILED = "failed"
    JADX_NOT_FOUND = "jadx_not_found"

class SeverityLevel(Enum):
    """Severity level classification"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class VulnerabilityType(Enum):
    """Type of vulnerability detected"""
    CRYPTO_WEAKNESS = "crypto_weakness"
    HARDCODED_SECRET = "hardcoded_secret"
    INSECURE_PATTERN = "insecure_pattern"
    CODE_QUALITY = "code_quality"
    STORAGE_ISSUE = "storage_issue"

class MasvsControl(Enum):
    """MASVS control identifiers"""
    MSTG_CRYPTO_1 = "MSTG-CRYPTO-1"
    MSTG_CRYPTO_2 = "MSTG-CRYPTO-2"
    MSTG_CRYPTO_3 = "MSTG-CRYPTO-3"
    MSTG_CRYPTO_4 = "MSTG-CRYPTO-4"
    MSTG_CODE_2 = "MSTG-CODE-2"
    MSTG_CODE_8 = "MSTG-CODE-8"
    MSTG_STORAGE_1 = "MSTG-STORAGE-1"
    MSTG_STORAGE_2 = "MSTG-STORAGE-2"

@dataclass
class JadxVulnerability:
    """Individual vulnerability found by JADX analysis"""
    vulnerability_type: VulnerabilityType
    title: str
    description: str
    severity: SeverityLevel
    file_path: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    remediation: Optional[str] = None
    masvs_control: Optional[MasvsControl] = None
    confidence: float = 0.0
    cwe_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert vulnerability to dictionary format"""
        return {
            'vulnerability_type': self.vulnerability_type.value,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'code_snippet': self.code_snippet,
            'remediation': self.remediation,
            'masvs_control': self.masvs_control.value if self.masvs_control else None,
            'confidence': self.confidence,
            'cwe_id': self.cwe_id
        }

@dataclass
class ResourceMetrics:
    """Resource usage metrics for analysis"""
    apk_size_mb: float
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    timeout_used: int = 300
    processing_mode: str = "normal"
    available_memory_gb: float = 0.0
    priority: str = "normal"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary format"""
        return {
            'apk_size_mb': self.apk_size_mb,
            'memory_usage_mb': self.memory_usage_mb,
            'cpu_usage_percent': self.cpu_usage_percent,
            'timeout_used': self.timeout_used,
            'processing_mode': self.processing_mode,
            'available_memory_gb': self.available_memory_gb,
            'priority': self.priority
        }

@dataclass
class JadxAnalysisResult:
    """Complete JADX analysis results"""
    analysis_mode: AnalysisMode
    status: AnalysisStatus
    vulnerabilities: List[JadxVulnerability] = field(default_factory=list)
    resource_metrics: Optional[ResourceMetrics] = None
    execution_time: float = 0.0
    error_message: Optional[str] = None
    decompilation_path: Optional[str] = None
    analysis_timestamp: datetime = field(default_factory=datetime.now)
    jadx_available: bool = True
    fallback_analysis_applied: bool = False
    
    def calculate_statistics(self) -> Dict[str, int]:
        """Calculate vulnerability statistics"""
        stats = {
            'total_vulnerabilities': len(self.vulnerabilities),
            'critical_count': len([v for v in self.vulnerabilities if v.severity == SeverityLevel.CRITICAL]),
            'high_count': len([v for v in self.vulnerabilities if v.severity == SeverityLevel.HIGH]),
            'medium_count': len([v for v in self.vulnerabilities if v.severity == SeverityLevel.MEDIUM]),
            'low_count': len([v for v in self.vulnerabilities if v.severity == SeverityLevel.LOW]),
            'info_count': len([v for v in self.vulnerabilities if v.severity == SeverityLevel.INFO])
        }
        return stats
    
    def get_highest_severity(self) -> SeverityLevel:
        """Get the highest severity level from vulnerabilities"""
        if not self.vulnerabilities:
            return SeverityLevel.INFO
        
        severity_order = [
            SeverityLevel.CRITICAL,
            SeverityLevel.HIGH,
            SeverityLevel.MEDIUM,
            SeverityLevel.LOW,
            SeverityLevel.INFO
        ]
        
        for severity in severity_order:
            if any(v.severity == severity for v in self.vulnerabilities):
                return severity
        
        return SeverityLevel.INFO
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary format"""
        return {
            'analysis_mode': self.analysis_mode.value,
            'status': self.status.value,
            'vulnerabilities': [vuln.to_dict() for vuln in self.vulnerabilities],
            'resource_metrics': self.resource_metrics.to_dict() if self.resource_metrics else None,
            'execution_time': self.execution_time,
            'error_message': self.error_message,
            'decompilation_path': self.decompilation_path,
            'analysis_timestamp': self.analysis_timestamp.isoformat(),
            'jadx_available': self.jadx_available,
            'fallback_analysis_applied': self.fallback_analysis_applied,
            'statistics': self.calculate_statistics()
        }

@dataclass
class JadxAnalysisConfig:
    """Configuration for JADX analysis"""
    enable_crypto_analysis: bool = True
    enable_secrets_analysis: bool = True
    enable_insecure_patterns_analysis: bool = True
    default_timeout: int = 600  # PERFORMANCE FIX: Increased from 240 to 600 (10 minutes) for large APKs
    large_apk_threshold_mb: float = 50.0  # Reduced from 100 to 50MB to trigger large APK handling sooner
    very_large_apk_threshold_mb: float = 150.0  # Reduced from 300 to 150MB
    memory_constrained_threshold_gb: float = 4.0
    max_decompilation_retries: int = 2
    enable_fallback_analysis: bool = True  # Always enabled for robust error handling
    confidence_threshold: float = 0.5
    enable_progress_reporting: bool = True
    check_interval_seconds: int = 3  # Reduced from 5 to 3 seconds for more responsive monitoring
    
    # PERFORMANCE OPTIMIZATION: New settings for better throughput
    batch_size: int = 100  # Process files in smaller batches for better progress reporting
    max_concurrent_files: int = 8  # Increased from default 4 to speed up analysis
    enable_fast_mode: bool = True  # Skip detailed analysis for very large file sets
    
    def get_timeout_for_size(self, apk_size_mb: float) -> int:
        """Get appropriate timeout based on APK size"""
        if apk_size_mb > self.very_large_apk_threshold_mb:
            return 900  # PERFORMANCE FIX: 15 minutes for very large APKs (increased from 7 minutes)
        elif apk_size_mb > self.large_apk_threshold_mb:
            return 720  # PERFORMANCE FIX: 12 minutes for large APKs (increased from 6 minutes)
        else:
            return self.default_timeout  # 10 minutes for normal APKs (increased from 4 minutes)
    
    def get_priority_for_size(self, apk_size_mb: float, available_memory_gb: float) -> str:
        """Get processing priority based on APK size and system resources"""
        if available_memory_gb < self.memory_constrained_threshold_gb:
            return "memory_constrained"
        elif apk_size_mb > self.very_large_apk_threshold_mb:
            return "memory_optimized"
        elif apk_size_mb > self.large_apk_threshold_mb:
            return "balanced"
        else:
            return "normal"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary format"""
        return {
            'enable_crypto_analysis': self.enable_crypto_analysis,
            'enable_secrets_analysis': self.enable_secrets_analysis,
            'enable_insecure_patterns_analysis': self.enable_insecure_patterns_analysis,
            'default_timeout': self.default_timeout,
            'large_apk_threshold_mb': self.large_apk_threshold_mb,
            'very_large_apk_threshold_mb': self.very_large_apk_threshold_mb,
            'memory_constrained_threshold_gb': self.memory_constrained_threshold_gb,
            'max_decompilation_retries': self.max_decompilation_retries,
            'enable_fallback_analysis': self.enable_fallback_analysis,
            'confidence_threshold': self.confidence_threshold,
            'enable_progress_reporting': self.enable_progress_reporting,
            'check_interval_seconds': self.check_interval_seconds
        } 