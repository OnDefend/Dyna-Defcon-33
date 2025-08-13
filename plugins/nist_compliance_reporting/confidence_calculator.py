#!/usr/bin/env python3
"""
NIST Confidence Calculator

Calculates confidence scores for NIST compliance assessments.
"""

import logging
from typing import Dict, List, Any, Optional
import statistics

logger = logging.getLogger(__name__)

class NISTConfidenceCalculator:
    """Calculates confidence scores for NIST compliance assessments."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the confidence calculator."""
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
    
    def calculate_assessment_confidence(self, findings: List[Dict[str, Any]], 
                                      coverage_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall confidence in the NIST compliance assessment."""
        
        # Calculate component confidence scores
        findings_confidence = self._calculate_findings_confidence(findings)
        coverage_confidence = self._calculate_coverage_confidence(coverage_data)
        data_quality_confidence = self._assess_data_quality(findings)
        
        # Weight the components
        weights = {
            'findings_confidence': 0.4,
            'coverage_confidence': 0.3,
            'data_quality_confidence': 0.3
        }
        
        overall_confidence = (
            findings_confidence * weights['findings_confidence'] +
            coverage_confidence * weights['coverage_confidence'] +
            data_quality_confidence * weights['data_quality_confidence']
        )
        
        return {
            'overall_confidence': round(overall_confidence, 2),
            'confidence_level': self._categorize_confidence(overall_confidence),
            'component_scores': {
                'findings_confidence': round(findings_confidence, 2),
                'coverage_confidence': round(coverage_confidence, 2),
                'data_quality_confidence': round(data_quality_confidence, 2)
            },
            'confidence_factors': self._identify_confidence_factors(findings, coverage_data)
        }
    
    def _calculate_findings_confidence(self, findings: List[Dict[str, Any]]) -> float:
        """Calculate confidence based on findings quality and consistency."""
        if not findings:
            return 0.5  # Neutral confidence with no findings
        
        # Extract confidence scores from individual findings
        confidence_scores = []
        for finding in findings:
            confidence = finding.get('confidence_score', 0.5)
            if isinstance(confidence, (int, float)):
                confidence_scores.append(float(confidence))
        
        if not confidence_scores:
            return 0.5
        
        # Calculate weighted average (higher weight for higher confidence findings)
        avg_confidence = statistics.mean(confidence_scores)
        
        # Adjust based on number of findings (more findings = higher confidence)
        sample_size_factor = min(1.0, len(findings) / 20)  # Max benefit at 20+ findings
        
        # Penalize if there's high variance in confidence scores
        if len(confidence_scores) > 1:
            confidence_variance = statistics.variance(confidence_scores)
            variance_penalty = min(0.2, confidence_variance)  # Max 20% penalty
        else:
            variance_penalty = 0
        
        final_confidence = avg_confidence * (0.7 + 0.3 * sample_size_factor) - variance_penalty
        
        return max(0.0, min(1.0, final_confidence))
    
    def _calculate_coverage_confidence(self, coverage_data: Dict[str, Any]) -> float:
        """Calculate confidence based on NIST CSF coverage."""
        coverage_percentage = coverage_data.get('coverage_percentage', 0)
        total_subcategories = coverage_data.get('total_subcategories', 23)
        covered_subcategories = coverage_data.get('covered_subcategories', 0)
        
        # Base confidence from coverage percentage
        base_confidence = coverage_percentage / 100
        
        # Bonus for comprehensive coverage
        if covered_subcategories >= 15:  # Good coverage
            base_confidence += 0.1
        elif covered_subcategories >= 20:  # Excellent coverage
            base_confidence += 0.2
        
        # Penalty for very low coverage
        if coverage_percentage < 30:
            base_confidence *= 0.7
        
        return max(0.0, min(1.0, base_confidence))
    
    def _assess_data_quality(self, findings: List[Dict[str, Any]]) -> float:
        """Assess the quality of the input data."""
        if not findings:
            return 0.3  # Low confidence with no data
        
        quality_score = 0.5  # Base score
        
        # Check for completeness of finding data
        complete_findings = 0
        for finding in findings:
            required_fields = ['title', 'description', 'severity', 'category']
            if all(finding.get(field) for field in required_fields):
                complete_findings += 1
        
        completeness_ratio = complete_findings / len(findings)
        quality_score += 0.3 * completeness_ratio
        
        # Check for evidence and detailed information
        findings_with_evidence = sum(1 for f in findings if f.get('evidence'))
        if findings_with_evidence > 0:
            evidence_ratio = findings_with_evidence / len(findings)
            quality_score += 0.2 * evidence_ratio
        
        return max(0.0, min(1.0, quality_score))
    
    def _categorize_confidence(self, confidence_score: float) -> str:
        """Categorize confidence score into levels."""
        if confidence_score >= 0.8:
            return 'HIGH'
        elif confidence_score >= 0.6:
            return 'MEDIUM'
        elif confidence_score >= 0.4:
            return 'LOW'
        else:
            return 'VERY_LOW'
    
    def _identify_confidence_factors(self, findings: List[Dict[str, Any]], 
                                   coverage_data: Dict[str, Any]) -> Dict[str, List[str]]:
        """Identify factors that affect confidence levels."""
        positive_factors = []
        negative_factors = []
        
        # Coverage factors
        coverage_pct = coverage_data.get('coverage_percentage', 0)
        if coverage_pct >= 70:
            positive_factors.append('Good NIST CSF subcategory coverage')
        elif coverage_pct < 40:
            negative_factors.append('Limited NIST CSF subcategory coverage')
        
        # Findings factors
        if len(findings) >= 10:
            positive_factors.append('Substantial number of security findings')
        elif len(findings) < 3:
            negative_factors.append('Limited security analysis data')
        
        # Data quality factors
        complete_findings = sum(1 for f in findings 
                              if all(f.get(field) for field in ['title', 'severity', 'category']))
        if complete_findings >= len(findings) * 0.8:
            positive_factors.append('High data completeness')
        else:
            negative_factors.append('Incomplete finding data')
        
        # Confidence consistency
        if findings:
            confidences = [f.get('confidence_score', 0.5) for f in findings]
            if statistics.mean(confidences) >= 0.7:
                positive_factors.append('High individual finding confidence')
            elif statistics.mean(confidences) < 0.4:
                negative_factors.append('Low individual finding confidence')
        
        return {
            'positive_factors': positive_factors,
            'negative_factors': negative_factors
        } 