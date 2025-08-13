"""
Evidence Package

Comprehensive evidence collection system for runtime vulnerability analysis.
Captures call stacks, runtime context, and forensic data for vulnerability verification.

Author: AODS Team
Date: January 2025
"""

from .collector import (
    RuntimeEvidenceCollector,
    EvidencePackage,
    RuntimeCallStack,
    RuntimeContext,
    EvidenceMetadata,
    EvidenceType
)

__all__ = [
    'RuntimeEvidenceCollector',
    'EvidencePackage',
    'RuntimeCallStack',
    'RuntimeContext',
    'EvidenceMetadata',
    'EvidenceType'
]

__version__ = '1.0.0'