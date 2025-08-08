#!/usr/bin/env python3
"""
Core Data Structures for Enhanced Static Analysis

Defines core data classes and structures used throughout the static analysis framework.
"""

from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class SecurityFinding:
    """Represents a security finding from static analysis."""

    finding_id: str
    title: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str  # CRYPTO, STORAGE, NETWORK, PLATFORM, etc.
    confidence: float  # 0.0 to 1.0
    file_path: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    owasp_refs: List[str] = field(default_factory=list)

@dataclass
class SecretAnalysis:
    """Represents analysis of potential secrets and sensitive data."""

    value: str
    entropy: float
    pattern_type: str
    confidence: float
    context: str
    file_path: str
    is_likely_secret: bool = False
    risk_level: str = "UNKNOWN"

# Export data structures
__all__ = [
    'SecurityFinding',
    'SecretAnalysis'
] 