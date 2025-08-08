#!/usr/bin/env python3
"""
Severity Levels and Risk Assessment Data Structures

This module provides standardized severity levels and risk assessment classes
used across all AODS plugins for consistent vulnerability severity rating.

Features:
- Standardized severity enumeration
- Risk assessment calculations
- Compliance level mappings
- Security impact evaluation
- CVSS score integration
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from enum import Enum

logger = logging.getLogger(__name__)

class SeverityLevel(Enum):
    """Standardized vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"
    
    def __str__(self) -> str:
        return self.value
    
    @property
    def numeric_value(self) -> int:
        """Get numeric value for severity comparisons."""
        severity_values = {
            SeverityLevel.CRITICAL: 5,
            SeverityLevel.HIGH: 4,
            SeverityLevel.MEDIUM: 3,
            SeverityLevel.LOW: 2,
            SeverityLevel.INFO: 1,
            SeverityLevel.UNKNOWN: 0
        }
        return severity_values.get(self, 0)
    
    @property
    def color_code(self) -> str:
        """Get color code for display."""
        color_codes = {
            SeverityLevel.CRITICAL: "red",
            SeverityLevel.HIGH: "orange",
            SeverityLevel.MEDIUM: "yellow",
            SeverityLevel.LOW: "blue",
            SeverityLevel.INFO: "green",
            SeverityLevel.UNKNOWN: "gray"
        }
        return color_codes.get(self, "gray")
    
    @classmethod
    def from_cvss_score(cls, cvss_score: float) -> 'SeverityLevel':
        """Convert CVSS score to severity level."""
        if cvss_score >= 9.0:
            return cls.CRITICAL
        elif cvss_score >= 7.0:
            return cls.HIGH
        elif cvss_score >= 4.0:
            return cls.MEDIUM
        elif cvss_score >= 0.1:
            return cls.LOW
        else:
            return cls.INFO
    
    @classmethod
    def from_risk_score(cls, risk_score: int) -> 'SeverityLevel':
        """Convert risk score (0-100) to severity level."""
        if risk_score >= 90:
            return cls.CRITICAL
        elif risk_score >= 70:
            return cls.HIGH
        elif risk_score >= 40:
            return cls.MEDIUM
        elif risk_score >= 10:
            return cls.LOW
        else:
            return cls.INFO

class ComplianceLevel(Enum):
    """Compliance level for security standards."""
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    PARTIALLY_COMPLIANT = "PARTIALLY_COMPLIANT"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNKNOWN = "UNKNOWN"
    
    def __str__(self) -> str:
        return self.value
    
    @property
    def is_compliant(self) -> bool:
        """Check if compliance level indicates compliance."""
        return self in [ComplianceLevel.COMPLIANT, ComplianceLevel.NOT_APPLICABLE]

class SecurityImpact(Enum):
    """Security impact categories."""
    CONFIDENTIALITY = "CONFIDENTIALITY"
    INTEGRITY = "INTEGRITY"
    AVAILABILITY = "AVAILABILITY"
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    NON_REPUDIATION = "NON_REPUDIATION"
    PRIVACY = "PRIVACY"
    
    def __str__(self) -> str:
        return self.value

@dataclass
class RiskAssessment:
    """Comprehensive risk assessment for vulnerabilities."""
    
    # Core risk metrics
    severity_level: SeverityLevel
    risk_score: int = 0  # 0-100
    cvss_score: Optional[float] = None
    
    # Impact assessment
    confidentiality_impact: SecurityImpact = SecurityImpact.CONFIDENTIALITY
    integrity_impact: SecurityImpact = SecurityImpact.INTEGRITY
    availability_impact: SecurityImpact = SecurityImpact.AVAILABILITY
    
    # Exploitability metrics
    exploitability_score: float = 0.0  # 0.0-1.0
    attack_complexity: str = "UNKNOWN"  # LOW, MEDIUM, HIGH
    attack_vector: str = "UNKNOWN"  # NETWORK, ADJACENT, LOCAL, PHYSICAL
    privileges_required: str = "UNKNOWN"  # NONE, LOW, HIGH
    user_interaction: str = "UNKNOWN"  # NONE, REQUIRED
    
    # Business impact
    business_impact: str = ""
    data_sensitivity: str = "UNKNOWN"  # PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED
    asset_value: str = "UNKNOWN"  # LOW, MEDIUM, HIGH, CRITICAL
    
    # Compliance assessment
    compliance_levels: Dict[str, ComplianceLevel] = field(default_factory=dict)
    regulatory_requirements: List[str] = field(default_factory=list)
    
    # Remediation assessment
    remediation_effort: str = "UNKNOWN"  # LOW, MEDIUM, HIGH, VERY_HIGH
    remediation_cost: str = "UNKNOWN"  # LOW, MEDIUM, HIGH, VERY_HIGH
    remediation_time: str = "UNKNOWN"  # IMMEDIATE, DAYS, WEEKS, MONTHS
    
    # Contextual factors
    environment_type: str = "UNKNOWN"  # DEVELOPMENT, STAGING, PRODUCTION
    exposure_level: str = "UNKNOWN"  # INTERNAL, EXTERNAL, PUBLIC
    affected_users: str = "UNKNOWN"  # FEW, SOME, MANY, ALL
    
    def __post_init__(self):
        """Validate and calculate derived metrics."""
        if not 0 <= self.risk_score <= 100:
            self.risk_score = self._calculate_risk_score()
        
        if self.cvss_score is not None:
            if not 0.0 <= self.cvss_score <= 10.0:
                raise ValueError("CVSS score must be between 0.0 and 10.0")
            # Update severity based on CVSS if provided
            calculated_severity = SeverityLevel.from_cvss_score(self.cvss_score)
            if self.severity_level == SeverityLevel.UNKNOWN:
                self.severity_level = calculated_severity
        
        if not 0.0 <= self.exploitability_score <= 1.0:
            raise ValueError("Exploitability score must be between 0.0 and 1.0")
    
    def _calculate_risk_score(self) -> int:
        """Calculate risk score based on various factors."""
        base_score = self.severity_level.numeric_value * 20  # 0-100 scale
        
        # Adjust for exploitability
        exploitability_bonus = int(self.exploitability_score * 20)
        
        # Adjust for attack complexity
        complexity_adjustment = {
            "LOW": 10,
            "MEDIUM": 0,
            "HIGH": -10,
            "UNKNOWN": 0
        }.get(self.attack_complexity.upper(), 0)
        
        # Adjust for attack vector
        vector_adjustment = {
            "NETWORK": 10,
            "ADJACENT": 5,
            "LOCAL": 0,
            "PHYSICAL": -5,
            "UNKNOWN": 0
        }.get(self.attack_vector.upper(), 0)
        
        # Adjust for privileges required
        privileges_adjustment = {
            "NONE": 10,
            "LOW": 5,
            "HIGH": -5,
            "UNKNOWN": 0
        }.get(self.privileges_required.upper(), 0)
        
        # Calculate final score
        calculated_score = (
            base_score + 
            exploitability_bonus + 
            complexity_adjustment + 
            vector_adjustment + 
            privileges_adjustment
        )
        
        return max(0, min(100, calculated_score))
    
    def get_overall_compliance_level(self) -> ComplianceLevel:
        """Get overall compliance level across all standards."""
        if not self.compliance_levels:
            return ComplianceLevel.UNKNOWN
        
        levels = list(self.compliance_levels.values())
        
        if all(level.is_compliant for level in levels):
            return ComplianceLevel.COMPLIANT
        elif any(level == ComplianceLevel.NON_COMPLIANT for level in levels):
            return ComplianceLevel.NON_COMPLIANT
        elif any(level == ComplianceLevel.PARTIALLY_COMPLIANT for level in levels):
            return ComplianceLevel.PARTIALLY_COMPLIANT
        else:
            return ComplianceLevel.UNKNOWN
    
    def get_security_impacts(self) -> List[SecurityImpact]:
        """Get list of security impacts."""
        impacts = []
        
        if self.confidentiality_impact:
            impacts.append(SecurityImpact.CONFIDENTIALITY)
        if self.integrity_impact:
            impacts.append(SecurityImpact.INTEGRITY)
        if self.availability_impact:
            impacts.append(SecurityImpact.AVAILABILITY)
        
        return impacts
    
    def is_high_risk(self) -> bool:
        """Check if this is a high-risk vulnerability."""
        return self.severity_level in [SeverityLevel.CRITICAL, SeverityLevel.HIGH] or self.risk_score >= 70
    
    def is_exploitable(self) -> bool:
        """Check if vulnerability is easily exploitable."""
        return (
            self.exploitability_score >= 0.7 and
            self.attack_complexity.upper() == "LOW" and
            self.privileges_required.upper() == "NONE"
        )
    
    def get_remediation_priority(self) -> str:
        """Get remediation priority level."""
        if self.severity_level == SeverityLevel.CRITICAL:
            return "IMMEDIATE"
        elif self.severity_level == SeverityLevel.HIGH:
            return "HIGH"
        elif self.severity_level == SeverityLevel.MEDIUM:
            return "MEDIUM"
        else:
            return "LOW"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert risk assessment to dictionary."""
        return {
            'severity_level': self.severity_level.value,
            'risk_score': self.risk_score,
            'cvss_score': self.cvss_score,
            'exploitability_score': self.exploitability_score,
            'attack_complexity': self.attack_complexity,
            'attack_vector': self.attack_vector,
            'privileges_required': self.privileges_required,
            'user_interaction': self.user_interaction,
            'business_impact': self.business_impact,
            'data_sensitivity': self.data_sensitivity,
            'asset_value': self.asset_value,
            'compliance_levels': {
                standard: level.value 
                for standard, level in self.compliance_levels.items()
            },
            'regulatory_requirements': self.regulatory_requirements,
            'remediation_effort': self.remediation_effort,
            'remediation_cost': self.remediation_cost,
            'remediation_time': self.remediation_time,
            'environment_type': self.environment_type,
            'exposure_level': self.exposure_level,
            'affected_users': self.affected_users,
            'security_impacts': [impact.value for impact in self.get_security_impacts()],
            'overall_compliance': self.get_overall_compliance_level().value,
            'is_high_risk': self.is_high_risk(),
            'is_exploitable': self.is_exploitable(),
            'remediation_priority': self.get_remediation_priority()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RiskAssessment':
        """Create risk assessment from dictionary."""
        assessment = cls(
            severity_level=SeverityLevel(data.get('severity_level', 'UNKNOWN')),
            risk_score=data.get('risk_score', 0),
            cvss_score=data.get('cvss_score'),
            exploitability_score=data.get('exploitability_score', 0.0),
            attack_complexity=data.get('attack_complexity', 'UNKNOWN'),
            attack_vector=data.get('attack_vector', 'UNKNOWN'),
            privileges_required=data.get('privileges_required', 'UNKNOWN'),
            user_interaction=data.get('user_interaction', 'UNKNOWN'),
            business_impact=data.get('business_impact', ''),
            data_sensitivity=data.get('data_sensitivity', 'UNKNOWN'),
            asset_value=data.get('asset_value', 'UNKNOWN'),
            regulatory_requirements=data.get('regulatory_requirements', []),
            remediation_effort=data.get('remediation_effort', 'UNKNOWN'),
            remediation_cost=data.get('remediation_cost', 'UNKNOWN'),
            remediation_time=data.get('remediation_time', 'UNKNOWN'),
            environment_type=data.get('environment_type', 'UNKNOWN'),
            exposure_level=data.get('exposure_level', 'UNKNOWN'),
            affected_users=data.get('affected_users', 'UNKNOWN')
        )
        
        # Load compliance levels
        compliance_data = data.get('compliance_levels', {})
        assessment.compliance_levels = {
            standard: ComplianceLevel(level)
            for standard, level in compliance_data.items()
        }
        
        return assessment

# Utility functions for risk assessment
def calculate_composite_risk_score(assessments: List[RiskAssessment]) -> int:
    """Calculate composite risk score from multiple assessments."""
    if not assessments:
        return 0
    
    # Weight by severity
    weighted_scores = []
    for assessment in assessments:
        weight = assessment.severity_level.numeric_value / 5.0  # 0.0-1.0
        weighted_scores.append(assessment.risk_score * weight)
    
    if not weighted_scores:
        return 0
    
    # Calculate weighted average
    total_weight = sum(assessment.severity_level.numeric_value for assessment in assessments)
    if total_weight == 0:
        return 0
    
    composite_score = sum(weighted_scores) / len(weighted_scores)
    return max(0, min(100, int(composite_score)))

def get_severity_distribution(assessments: List[RiskAssessment]) -> Dict[SeverityLevel, int]:
    """Get distribution of severities across assessments."""
    distribution = {level: 0 for level in SeverityLevel}
    
    for assessment in assessments:
        distribution[assessment.severity_level] += 1
    
    return distribution

def get_highest_severity(assessments: List[RiskAssessment]) -> SeverityLevel:
    """Get the highest severity level from assessments."""
    if not assessments:
        return SeverityLevel.UNKNOWN
    
    return max(assessments, key=lambda a: a.severity_level.numeric_value).severity_level

def filter_by_severity(assessments: List[RiskAssessment], 
                      min_severity: SeverityLevel) -> List[RiskAssessment]:
    """Filter assessments by minimum severity level."""
    min_value = min_severity.numeric_value
    return [a for a in assessments if a.severity_level.numeric_value >= min_value]

def filter_high_risk(assessments: List[RiskAssessment]) -> List[RiskAssessment]:
    """Filter assessments to only high-risk vulnerabilities."""
    return [a for a in assessments if a.is_high_risk()]

def filter_exploitable(assessments: List[RiskAssessment]) -> List[RiskAssessment]:
    """Filter assessments to only exploitable vulnerabilities."""
    return [a for a in assessments if a.is_exploitable()] 