"""
Detection Package

Advanced vulnerability detection engine for runtime analysis.
Provides pattern-based detection, behavioral analysis, and evidence collection.

Author: AODS Team
Date: January 2025
"""

from .runtime_detector import (
    RuntimeVulnerabilityDetector,
    RuntimeVulnerability,
    VulnerabilityPattern,
    VulnerabilityType,
    Severity
)

__all__ = [
    'RuntimeVulnerabilityDetector',
    'RuntimeVulnerability',
    'VulnerabilityPattern',
    'VulnerabilityType',
    'Severity'
]

__version__ = '1.0.0'