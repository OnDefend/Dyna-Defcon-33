#!/usr/bin/env python3
"""
AODS Accuracy Integration Pipeline - Detection-First Modular Architecture

Professional modular architecture prioritizing maximum vulnerability detection accuracy
with zero regression tolerance. Transforms 707-line monolithic implementation into
focused, testable components while enhancing detection capabilities.

DETECTION-FIRST PRINCIPLES:
- Maximum vulnerability detection preservation (zero tolerance for regression)
- Enhanced detection through elimination of component conflicts
- Professional confidence systems with evidence-based scoring
- 100% test coverage for all components (vulnerability detection validation)
- Organic detection patterns maintained throughout pipeline
- Production validation against real vulnerable applications

Modular Components:
- detection_pipeline.py: Main vulnerability detection orchestrator
- severity_filter.py: Advanced severity-based vulnerability filtering
- confidence_calculator.py: Professional evidence-based confidence scoring
- deduplication_engine.py: Intelligent vulnerability consolidation
- production_validator.py: Real-world vulnerability detection validation
- metrics_tracker.py: Comprehensive detection accuracy metrics
- data_structures.py: Core detection data types and enums
- configuration_manager.py: Detection-aware configuration management

Original monolithic implementation has been successfully replaced by this modular architecture.
"""

from .data_structures import (
    ProcessingStage,
    AccuracyMetrics,
    PipelineConfiguration,
    DetectionQualityIndicators
)
from .detection_pipeline import AccuracyIntegrationPipeline
from .production_validator import ProductionAccuracyValidator
from .configuration_manager import DetectionConfigurationManager

# Legacy compatibility - maintain all original APIs
__all__ = [
    'AccuracyIntegrationPipeline',
    'ProductionAccuracyValidator', 
    'ProcessingStage',
    'AccuracyMetrics',
    'PipelineConfiguration',
    'DetectionQualityIndicators',
    'DetectionConfigurationManager'
] 
 
 