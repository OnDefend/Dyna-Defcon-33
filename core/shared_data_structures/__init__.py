#!/usr/bin/env python3
"""
Shared Data Structures Module for AODS Plugin Modularization

This module provides standardized data structures used across all plugins,
ensuring consistency and eliminating duplication of vulnerability classes
and analysis result structures.

Components:
- BaseVulnerability: Base class for all vulnerability findings
- AnalysisConfiguration: Standard configuration data structures
- SeverityLevel: Standardized severity and risk assessment
- MAVSMapping: Centralized MASVS control mappings
"""

from .base_vulnerability import (
    BaseVulnerability,
    VulnerabilityType,
    VulnerabilitySeverity,
    VulnerabilityFinding,
    VulnerabilityMatch,
    VulnerabilityContext
)
from .analysis_configuration import (
    AnalysisConfiguration,
    PluginConfiguration,
    ScanConfiguration,
    PerformanceConfiguration
)
from .severity_levels import (
    SeverityLevel,
    RiskAssessment,
    ComplianceLevel,
    SecurityImpact
)
from .masvs_mappings import (
    MAVSMapping,
    MAVSControl,
    ComplianceStandard,
    SecurityRequirement
)

__version__ = "1.0.0"
__author__ = "AODS Development Team"

__all__ = [
    # Base vulnerability classes
    "BaseVulnerability",
    "VulnerabilityType",
    "VulnerabilitySeverity", 
    "VulnerabilityFinding",
    "VulnerabilityMatch",
    "VulnerabilityContext",
    
    # Configuration classes
    "AnalysisConfiguration",
    "PluginConfiguration",
    "ScanConfiguration",
    "PerformanceConfiguration",
    
    # Severity and risk assessment
    "SeverityLevel",
    "RiskAssessment",
    "ComplianceLevel",
    "SecurityImpact",
    
    # MASVS and compliance mappings
    "MAVSMapping",
    "MAVSControl",
    "ComplianceStandard",
    "SecurityRequirement"
] 