"""
AODS Shared Confidence System

High-quality confidence calculation framework that provides consistent,
evidence-based confidence scoring across all AODS plugins.

Key Components:
- Universal confidence calculator with multi-factor evidence analysis
- Plugin-specific confidence calculators for specialized domains
- Pattern reliability database with historical accuracy tracking
- Evidence-based scoring with context-aware adjustments
- Cross-validation assessment capabilities
- Machine learning integration for improved accuracy

This system eliminates hardcoded confidence values and provides defensible,
professional-grade confidence scores suitable for enterprise deployment.
"""

from ..shared_analyzers.universal_confidence_calculator import (
    UniversalConfidenceCalculator,
    ConfidenceConfiguration,
    ConfidenceEvidence,
    ConfidenceFactorType,
    PatternReliability
)

from .plugin_confidence_calculators import (
    CryptoConfidenceCalculator,
    BinaryConfidenceCalculator,
    NetworkConfidenceCalculator,
    StorageConfidenceCalculator,
    PlatformConfidenceCalculator,
    WebViewConfidenceCalculator,
    InjectionConfidenceCalculator,
    StaticAnalysisConfidenceCalculator
)

from .evidence_based_scoring import (
    EvidenceAnalyzer,
    EvidenceWeightCalculator,
    CrossValidationAnalyzer,
    ContextAwareAdjuster,
    FalsePositiveAnalyzer
)

from .confidence_validation import (
    ConfidenceValidator,
    ValidationResult,
    AccuracyMetrics,
    CalibrationAnalyzer,
    validate_confidence_accuracy
)

__all__ = [
    # Universal confidence calculator
    'UniversalConfidenceCalculator',
    'ConfidenceConfiguration',
    'ConfidenceEvidence',
    'ConfidenceFactorType',
    'PatternReliability',
    
    # Plugin-specific calculators
    'CryptoConfidenceCalculator',
    'BinaryConfidenceCalculator',
    'NetworkConfidenceCalculator',
    'StorageConfidenceCalculator',
    'PlatformConfidenceCalculator',
    'WebViewConfidenceCalculator',
    'InjectionConfidenceCalculator',
    'StaticAnalysisConfidenceCalculator',
    
    # Evidence-based scoring
    'EvidenceAnalyzer',
    'EvidenceWeightCalculator',
    'CrossValidationAnalyzer',
    'ContextAwareAdjuster',
    'FalsePositiveAnalyzer',
    
    # Confidence validation
    'ConfidenceValidator',
    'ValidationResult',
    'AccuracyMetrics',
    'CalibrationAnalyzer',
    'validate_confidence_accuracy'
]

__version__ = "2.0.0"
__author__ = "AODS Development Team"
__description__ = "High-quality confidence calculation framework for AODS security analysis" 