"""
Risk Calculator for AODS Security Analysis
Provides risk scoring and assessment functionality.
"""

import logging
from typing import Dict, List, Any, Optional
from enum import Enum

class RiskLevel(Enum):
    """Risk level enumeration."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class RiskCalculator:
    """Calculates risk scores for security findings."""
    
    def __init__(self):
        """Initialize the risk calculator."""
        self.logger = logging.getLogger(__name__)
        self.vulnerability_weights = {
            "cleartext_traffic": 0.8,
            "exported_components": 0.7,
            "hardcoded_secrets": 0.6,
            "excessive_permissions": 0.5,
            "debug_enabled": 0.7,
            "backup_allowed": 0.4,
            "weak_crypto": 0.8,
            "sql_injection": 0.9,
            "path_traversal": 0.8,
        }
    
    def calculate_risk_score(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate overall risk score from findings."""
        if not findings:
            return {
                "overall_score": 0.0,
                "risk_level": RiskLevel.INFO.value,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0
            }
        
        total_score = 0.0
        severity_counts = {level.value: 0 for level in RiskLevel}
        
        for finding in findings:
            severity = finding.get("severity", "LOW")
            severity_counts[severity] += 1
            
            # Calculate weighted score
            finding_type = finding.get("type", "unknown").lower()
            weight = self.vulnerability_weights.get(finding_type, 0.3)
            
            if severity == "CRITICAL":
                total_score += weight * 1.0
            elif severity == "HIGH":
                total_score += weight * 0.8
            elif severity == "MEDIUM":
                total_score += weight * 0.5
            elif severity == "LOW":
                total_score += weight * 0.2
        
        # Normalize score (0-100)
        max_possible_score = len(findings) * 1.0
        normalized_score = min(100, (total_score / max_possible_score) * 100) if max_possible_score > 0 else 0
        
        # Determine overall risk level
        if normalized_score >= 80:
            overall_risk = RiskLevel.CRITICAL.value
        elif normalized_score >= 60:
            overall_risk = RiskLevel.HIGH.value
        elif normalized_score >= 40:
            overall_risk = RiskLevel.MEDIUM.value
        elif normalized_score >= 20:
            overall_risk = RiskLevel.LOW.value
        else:
            overall_risk = RiskLevel.INFO.value
        
        return {
            "overall_score": round(normalized_score, 1),
            "risk_level": overall_risk,
            "critical_count": severity_counts.get("CRITICAL", 0),
            "high_count": severity_counts.get("HIGH", 0),
            "medium_count": severity_counts.get("MEDIUM", 0),
            "low_count": severity_counts.get("LOW", 0),
            "info_count": severity_counts.get("INFO", 0),
            "total_findings": len(findings)
        }
