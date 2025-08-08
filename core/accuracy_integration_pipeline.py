#!/usr/bin/env python3
"""
AODS Accuracy Integration Pipeline - Modular Architecture

Modular accuracy integration pipeline focused on maximum vulnerability detection
with improved maintainability and standards.

This file now serves as a redirect to the modular implementation while
maintaining complete API compatibility and backward compatibility.

The modular architecture transforms the original monolithic implementation 
into focused, testable components with confidence systems that use 
evidence-based scoring and appropriate logging with zero tolerance 
for vulnerability detection regression.

Architecture Overview:
- core/accuracy_integration_pipeline/: Modular components
- data_structures.py: Core data types and processing stage enums
- configuration_manager.py: Detection-aware configuration management
- severity_filter.py: Severity filtering with preservation
- confidence_calculator.py: Evidence-based confidence scoring
- deduplication_engine.py: Intelligent vulnerability consolidation
- production_validator.py: Real-world vulnerability detection validation
- detection_pipeline.py: Main detection orchestrator (implementation)
"""

import logging
from typing import Dict, List, Any, Optional

# Import from modular implementation
try:
    from .accuracy_integration_pipeline import (
        AccuracyIntegrationPipeline,
        ProductionAccuracyValidator,
        ProcessingStage,
        AccuracyMetrics,
        PipelineConfiguration,
        DetectionQualityIndicators,
        DetectionConfigurationManager
    )
    MODULAR_AVAILABLE = True
except ImportError as e:
    MODULAR_AVAILABLE = False
    logging.warning(f"Modular architecture not available: {e}")

# Backward compatibility interface
def create_accuracy_pipeline(config: Optional[Dict[str, Any]] = None) -> Any:
    """Create accuracy integration pipeline instance."""
    if MODULAR_AVAILABLE:
        return AccuracyIntegrationPipeline(config)
    else:
        raise ImportError("Modular accuracy integration pipeline not available")

# Export for backward compatibility
__all__ = [
    'AccuracyIntegrationPipeline',
    'ProductionAccuracyValidator',
    'ProcessingStage',
    'AccuracyMetrics',
    'PipelineConfiguration',
    'DetectionQualityIndicators',
    'DetectionConfigurationManager',
    'create_accuracy_pipeline'
] 
 