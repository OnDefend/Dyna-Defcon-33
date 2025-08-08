#!/usr/bin/env python3
"""
Enhanced False Positive Reduction - Data Structures
==================================================

This module contains all data structures and result classes used throughout
the enhanced false positive reduction framework.

Features:
- Comprehensive analysis result structures
- Context analysis data models
- ML performance tracking structures
- Type-safe data containers with validation

"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

@dataclass
class SecretAnalysisResult:
    """Comprehensive analysis result for a potential secret."""

    content: str
    is_likely_secret: bool
    confidence_score: float
    analysis_details: Dict[str, Any] = field(default_factory=dict)
    false_positive_indicators: List[str] = field(default_factory=list)
    true_positive_indicators: List[str] = field(default_factory=list)
    file_context: Optional[str] = None
    line_number: Optional[int] = None
    context_analysis: Optional[Dict[str, Any]] = field(default_factory=dict)
    framework_classification: Optional[str] = None
    # Enhanced ML fields for technical reporting
    ml_confidence: Optional[float] = None
    explainable_features: Optional[Dict[str, float]] = field(default_factory=dict)
    usage_pattern: Optional[str] = None
    risk_assessment: Optional[Dict[str, Any]] = field(default_factory=dict)
    recommendation: Optional[str] = None

@dataclass
class ContextAnalysisResult:
    """Result of context analysis around a potential secret."""

    apis_found: List[str] = field(default_factory=list)
    context_score: float = 0.0
    context_type: Optional[str] = None
    confidence_adjustment: float = 0.0
    analysis_radius: int = 0
    method_context: Optional[str] = None
    # Enhanced context fields
    usage_patterns: List[str] = field(default_factory=list)
    security_context: Optional[str] = None
    framework_context: Optional[str] = None

@dataclass
class MLModelPerformance:
    """ML model performance metrics for monitoring."""
    false_positive_rate: float
    false_negative_rate: float
    precision: float
    recall: float
    f1_score: float
    accuracy: float
    model_version: str
    last_updated: str
    training_samples: int

@dataclass
class EntropyAnalysisResult:
    """Result of entropy analysis for content."""
    
    shannon_entropy: float
    base64_entropy: float
    hex_entropy: float
    ascii_entropy: float
    compressed_entropy: float
    entropy_score: float
    entropy_confidence: float
    is_high_entropy: bool
    entropy_details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class PatternMatchResult:
    """Result of pattern matching analysis."""
    
    matched_patterns: List[str] = field(default_factory=list)
    pattern_confidence: float = 0.0
    pattern_type: Optional[str] = None
    pattern_details: Dict[str, Any] = field(default_factory=dict)
    is_known_pattern: bool = False

@dataclass
class FrameworkAnalysisResult:
    """Result of framework-specific analysis."""
    
    detected_framework: Optional[str] = None
    framework_confidence: float = 0.0
    framework_noise_indicators: List[str] = field(default_factory=list)
    framework_specificity: float = 0.0
    is_framework_noise: bool = False 