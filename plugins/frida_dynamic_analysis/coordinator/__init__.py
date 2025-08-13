#!/usr/bin/env python3
"""
AODS Runtime Analysis Coordination Framework

Advanced coordination framework for managing real-time runtime analysis,
synchronizing hooks, app interaction, detection, and evidence collection.

Author: AODS Team
Date: January 2025
"""

from .analysis_coordinator import RuntimeAnalysisCoordinator
from .processing_pipeline import RealTimeProcessingPipeline
from .data_sync_manager import DataSynchronizationManager
from .phase_manager import AnalysisPhaseManager

__all__ = [
    'RuntimeAnalysisCoordinator',
    'RealTimeProcessingPipeline', 
    'DataSynchronizationManager',
    'AnalysisPhaseManager'
]