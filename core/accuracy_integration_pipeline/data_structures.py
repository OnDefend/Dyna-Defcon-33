#!/usr/bin/env python3
"""
Accuracy Integration Pipeline - Detection-First Data Structures

Core data classes and enums for vulnerability detection pipeline with
maximum detection accuracy and comprehensive tracking capabilities.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional

class ProcessingStage(Enum):
    """Pipeline processing stages for vulnerability detection tracking"""
    RAW_INPUT = "raw_input"
    SEVERITY_FILTERED = "severity_filtered"
    CONFIDENCE_SCORED = "confidence_scored"
    DEDUPLICATED = "deduplicated"
    FINAL_OUTPUT = "final_output"
    COMPLETED = "completed"

class DetectionQuality(Enum):
    """Vulnerability detection quality levels"""
    EXCELLENT = "excellent"      # 95%+ detection accuracy
    GOOD = "good"               # 85-94% detection accuracy
    ACCEPTABLE = "acceptable"   # 75-84% detection accuracy
    NEEDS_IMPROVEMENT = "needs_improvement"  # 60-74% detection accuracy
    POOR = "poor"              # 50-59% detection accuracy
    CRITICAL = "critical"      # <50% detection accuracy

@dataclass
class AccuracyMetrics:
    """
    Comprehensive vulnerability detection accuracy metrics with
    detailed tracking for each pipeline processing stage.
    """
    stage: ProcessingStage
    total_findings: int
    filtered_findings: int
    reduction_percentage: float
    processing_time_ms: float
    memory_usage_mb: float = 0.0
    
    # Vulnerability detection tracking
    vulnerabilities_detected: int = 0
    vulnerabilities_preserved: int = 0
    false_positives_eliminated: int = 0
    detection_accuracy_percent: float = 0.0
    
    # Stage-specific metrics
    severity_distribution: Dict[str, int] = field(default_factory=dict)
    confidence_distribution: Dict[str, int] = field(default_factory=dict)
    duplication_stats: Dict[str, int] = field(default_factory=dict)
    
    # Quality indicators
    detection_quality: DetectionQuality = DetectionQuality.ACCEPTABLE
    quality_score: float = 0.0

@dataclass
class ConfidenceCalculationConfiguration:
    """
    Configuration for confidence calculation with detection-optimized defaults.
    """
    min_confidence_threshold: float = 0.7
    enable_vulnerability_preservation: bool = True
    enable_context_enhancement: bool = True
    enable_evidence_aggregation: bool = True
    enable_ml_scoring: bool = True
    confidence_adjustment_factor: float = 1.0

@dataclass
class PipelineConfiguration:
    """
    Detection-aware configuration for vulnerability accuracy pipeline
    with professional defaults optimized for maximum detection.
    """
    # Severity filtering configuration - optimized for detection
    from core.vulnerability_filter import VulnerabilitySeverity  # type: ignore  # noqa
    min_severity: Any = VulnerabilitySeverity.INFO  # include all severities
    enable_framework_filtering: bool = True
    enable_context_filtering: bool = True
    preserve_high_confidence_low_severity: bool = True  # Ensure no detection loss
    
    # Confidence scoring configuration - optimized for detection
    confidence_config: ConfidenceCalculationConfiguration = field(default_factory=lambda: ConfidenceCalculationConfiguration(
        min_confidence_threshold=0.7,
        enable_vulnerability_preservation=True,
        enable_context_enhancement=True,
        enable_evidence_aggregation=True
    ))
    
    # Context adjustment for dynamic confidence scoring
    enable_context_adjustment: bool = True
    
    # VULNERABLE APP MODE: Relaxed settings for vulnerable test applications
    vulnerable_app_mode: bool = False
    
    def apply_vulnerable_app_mode(self):
        """Apply relaxed settings for analyzing vulnerable test applications."""
        if self.vulnerable_app_mode:
            # Drastically lower confidence threshold for vulnerable apps
            self.confidence_config.min_confidence_threshold = 0.1
            
            # Reduce similarity threshold to preserve more findings
            self.similarity_threshold = 0.6
            
            # Include lower severity findings - import VulnerabilitySeverity if available
            try:
                from core.vulnerability_filter import VulnerabilitySeverity
                self.min_severity = VulnerabilitySeverity.INFO
            except ImportError:
                # Set to a low value if import fails
                self.min_severity = "INFO"
            
            # Disable framework filtering for maximum detection
            self.enable_framework_filtering = False
            
            # Disable context filtering to preserve findings
            self.enable_context_filtering = False
            
            # Enable vulnerability preservation
            self.preserve_high_confidence_low_severity = True
    
    # Deduplication configuration - intelligent consolidation
    enable_fingerprint_matching: bool = True
    enable_pattern_grouping: bool = True
    similarity_threshold: float = 0.85
    preserve_unique_vulnerabilities: bool = True  # Zero vulnerability loss tolerance
    
    # Performance configuration
    enable_parallel_processing: bool = True
    max_workers: int = 4
    enable_caching: bool = True
    cache_ttl_hours: int = 24
    
    # Detection quality assurance
    enable_detection_validation: bool = True
    require_vulnerability_preservation: bool = True
    detection_quality_threshold: DetectionQuality = DetectionQuality.GOOD

@dataclass
class DetectionQualityIndicators:
    """
    vulnerability detection quality indicators for
    comprehensive assessment of pipeline detection accuracy.
    """
    # Core detection metrics
    total_vulnerabilities_input: int
    total_vulnerabilities_output: int
    vulnerability_preservation_rate: float
    false_positive_elimination_rate: float
    overall_detection_accuracy: float
    
    # Quality assessment
    detection_quality: DetectionQuality
    quality_score: float
    meets_production_standards: bool
    
    # Detailed analysis
    severity_preservation: Dict[str, float] = field(default_factory=dict)
    framework_detection_rates: Dict[str, float] = field(default_factory=dict)
    confidence_score_distribution: Dict[str, int] = field(default_factory=dict)
    
    # Performance indicators
    processing_efficiency: float = 0.0
    memory_efficiency: float = 0.0
    throughput_findings_per_second: float = 0.0

@dataclass
class VulnerabilityPreservationReport:
    """
    Comprehensive report on vulnerability preservation throughout
    the accuracy pipeline processing stages.
    """
    # Preservation tracking
    original_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    preserved_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    lost_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    
    # Preservation metrics
    preservation_rate: float = 0.0
    critical_vulnerability_preservation: float = 0.0
    high_severity_preservation: float = 0.0
    
    # Quality indicators
    preservation_quality: DetectionQuality = DetectionQuality.ACCEPTABLE
    meets_detection_standards: bool = False
    
    # Detailed analysis
    preservation_by_stage: Dict[str, float] = field(default_factory=dict)
    preservation_by_category: Dict[str, float] = field(default_factory=dict)

@dataclass
class DetectionPipelineResult:
    """
    Comprehensive result from vulnerability detection pipeline processing
    with full traceability and quality indicators.
    """
    # Pipeline identification
    pipeline_id: str
    processing_timestamp: int
    configuration: Dict[str, Any]
    
    # Detection results
    final_findings: List[Dict[str, Any]]
    total_findings: int
    original_finding_count: int
    
    # Stage-by-stage results
    stage_results: Dict[str, Any]
    
    # Comprehensive metrics
    accuracy_metrics: AccuracyMetrics
    processing_metrics: Dict[str, Any]
    quality_indicators: DetectionQualityIndicators
    vulnerability_preservation: VulnerabilityPreservationReport
    
    # Detection validation
    detection_validation_passed: bool = False
    production_ready: bool = False
    quality_assurance_notes: List[str] = field(default_factory=list) 