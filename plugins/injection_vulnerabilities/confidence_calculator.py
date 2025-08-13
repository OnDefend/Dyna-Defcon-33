"""
Injection Vulnerabilities - Professional Confidence Calculator

This module provides professional confidence calculation for injection vulnerabilities
using multi-factor evidence analysis and pattern reliability assessment.
"""

import logging
from typing import Dict, List, Optional, Any

from plugins.injection_vulnerabilities.data_structures import (
    InjectionVulnerability, VulnerabilityType, SeverityLevel, 
    AnalysisMethod, InjectionAnalysisConfiguration
)

class InjectionConfidenceCalculator:
    """confidence calculator for injection vulnerabilities."""
    
    def __init__(self, config: Optional[InjectionAnalysisConfiguration] = None):
        """Initialize the confidence calculator."""
        self.config = config or InjectionAnalysisConfiguration()
        self.logger = logging.getLogger(__name__)
        
        # Load pattern reliability data
        self.pattern_reliability = self._load_pattern_reliability()
        
        # Evidence weight configuration
        self.evidence_weights = {
            'analysis_method': 0.3,
            'evidence_quality': 0.25,
            'pattern_reliability': 0.2,
            'context_factors': 0.15,
            'cross_validation': 0.1
        }
    
    def _load_pattern_reliability(self) -> Dict[str, float]:
        """Load pattern reliability data based on historical accuracy."""
        return {
            # Dynamic analysis patterns (high reliability)
            'dynamic_drozer_injection': 0.95,
            'dynamic_sql_error': 0.90,
            'dynamic_database_error': 0.85,
            
            # Static code patterns (variable reliability)
            'string_concatenation_raw_query': 0.85,
            'string_concatenation_exec_sql': 0.90,
            'string_concatenation_query': 0.80,
            'user_input_in_sql': 0.85,
            'direct_string_in_query': 0.75,
            'sql_without_params': 0.60,
            'selection_args_concat': 0.70,
            'content_values_concat': 0.65,
            
            # Manifest patterns (moderate reliability)
            'exported_provider_unprotected': 0.75,
            'exported_provider_no_permissions': 0.70,
            'provider_grant_uri_permissions': 0.60,
            
            # Generic patterns (lower reliability)
            'generic_injection_pattern': 0.50,
            'suspicious_sql_pattern': 0.45
        }
    
    def calculate_confidence(self, vulnerability: InjectionVulnerability) -> float:
        """Calculate professional confidence score for injection vulnerability."""
        try:
            # Factor 1: Analysis method reliability
            method_confidence = self._calculate_method_confidence(vulnerability)
            
            # Factor 2: Evidence quality assessment
            evidence_confidence = self._calculate_evidence_confidence(vulnerability)
            
            # Factor 3: Pattern reliability
            pattern_confidence = self._calculate_pattern_confidence(vulnerability)
            
            # Factor 4: Context factors
            context_confidence = self._calculate_context_confidence(vulnerability)
            
            # Factor 5: Cross-validation impact
            cross_validation_confidence = self._calculate_cross_validation_confidence(vulnerability)
            
            # Calculate weighted confidence
            weighted_confidence = (
                method_confidence * self.evidence_weights['analysis_method'] +
                evidence_confidence * self.evidence_weights['evidence_quality'] +
                pattern_confidence * self.evidence_weights['pattern_reliability'] +
                context_confidence * self.evidence_weights['context_factors'] +
                cross_validation_confidence * self.evidence_weights['cross_validation']
            )
            
            # Apply confidence adjustments
            adjusted_confidence = self._apply_confidence_adjustments(
                weighted_confidence, vulnerability
            )
            
            # Ensure confidence is within valid range
            final_confidence = max(0.1, min(1.0, adjusted_confidence))
            
            self.logger.debug(f"Confidence calculation for {vulnerability.title}: {final_confidence:.3f}")
            
            return final_confidence
            
        except Exception as e:
            self.logger.error(f"Confidence calculation failed: {e}")
            return 0.5  # Conservative default
    
    def _calculate_method_confidence(self, vulnerability: InjectionVulnerability) -> float:
        """Calculate confidence based on analysis method."""
        method_confidence_map = {
            AnalysisMethod.DYNAMIC_DROZER: 0.9,
            AnalysisMethod.STATIC_CODE: 0.7,
            AnalysisMethod.STATIC_MANIFEST: 0.6,
            AnalysisMethod.STATIC_PATTERN: 0.5,
            AnalysisMethod.HYBRID: 0.85
        }
        
        base_confidence = method_confidence_map.get(vulnerability.method, 0.5)
        
        # Adjust based on method-specific factors
        if vulnerability.method == AnalysisMethod.DYNAMIC_DROZER:
            # Higher confidence for detailed error messages
            if vulnerability.evidence and len(vulnerability.evidence) > 50:
                base_confidence += 0.05
            
            # Higher confidence for multiple injection types
            if "projection" in vulnerability.evidence.lower() and "selection" in vulnerability.evidence.lower():
                base_confidence += 0.03
        
        elif vulnerability.method == AnalysisMethod.STATIC_CODE:
            # Higher confidence for code with line numbers
            if vulnerability.line_number:
                base_confidence += 0.05
            
            # Higher confidence for code snippets
            if vulnerability.code_snippet:
                base_confidence += 0.03
        
        elif vulnerability.method == AnalysisMethod.STATIC_MANIFEST:
            # Higher confidence for exported providers without permissions
            if "exported" in vulnerability.evidence.lower() and "permission" not in vulnerability.evidence.lower():
                base_confidence += 0.1
        
        return min(1.0, base_confidence)
    
    def _calculate_evidence_confidence(self, vulnerability: InjectionVulnerability) -> float:
        """Calculate confidence based on evidence quality."""
        base_confidence = 0.5
        
        if not vulnerability.evidence:
            return base_confidence
        
        evidence_lower = vulnerability.evidence.lower()
        
        # Strong evidence indicators
        strong_indicators = [
            'sql syntax error',
            'sqlite error',
            'database error',
            'injection successful',
            'data extracted',
            'rawquery',
            'execsql',
            'string concatenation'
        ]
        
        for indicator in strong_indicators:
            if indicator in evidence_lower:
                base_confidence += 0.1
        
        # Weak evidence indicators (reduce confidence)
        weak_indicators = [
            'might be vulnerable',
            'possibly vulnerable',
            'potential issue',
            'suspicious pattern'
        ]
        
        for indicator in weak_indicators:
            if indicator in evidence_lower:
                base_confidence -= 0.1
        
        # Evidence length factor
        if len(vulnerability.evidence) > 100:
            base_confidence += 0.05
        elif len(vulnerability.evidence) < 20:
            base_confidence -= 0.05
        
        # Code snippet presence
        if vulnerability.code_snippet:
            base_confidence += 0.05
        
        return max(0.1, min(1.0, base_confidence))
    
    def _calculate_pattern_confidence(self, vulnerability: InjectionVulnerability) -> float:
        """Calculate confidence based on pattern reliability."""
        # Try to match evidence to known patterns
        if not vulnerability.evidence:
            return 0.5
        
        evidence_lower = vulnerability.evidence.lower()
        
        # Check for specific patterns in evidence
        for pattern, reliability in self.pattern_reliability.items():
            if self._evidence_matches_pattern(evidence_lower, pattern):
                return reliability
        
        # Check method-specific patterns
        if vulnerability.method == AnalysisMethod.DYNAMIC_DROZER:
            if 'injection' in evidence_lower:
                return self.pattern_reliability.get('dynamic_drozer_injection', 0.8)
        
        elif vulnerability.method == AnalysisMethod.STATIC_CODE:
            if 'concatenation' in evidence_lower:
                return self.pattern_reliability.get('string_concatenation_query', 0.75)
        
        elif vulnerability.method == AnalysisMethod.STATIC_MANIFEST:
            if 'exported' in evidence_lower:
                return self.pattern_reliability.get('exported_provider_unprotected', 0.7)
        
        return 0.5  # Default pattern reliability
    
    def _evidence_matches_pattern(self, evidence: str, pattern: str) -> bool:
        """Check if evidence matches a specific pattern."""
        pattern_keywords = {
            'dynamic_drozer_injection': ['injection', 'drozer', 'scanner'],
            'dynamic_sql_error': ['sql', 'error', 'syntax'],
            'dynamic_database_error': ['database', 'error', 'sqlite'],
            'string_concatenation_raw_query': ['rawquery', 'concatenation'],
            'string_concatenation_exec_sql': ['execsql', 'concatenation'],
            'string_concatenation_query': ['query', 'concatenation'],
            'user_input_in_sql': ['user input', 'gettext', 'getstringextra'],
            'exported_provider_unprotected': ['exported', 'provider', 'permission']
        }
        
        keywords = pattern_keywords.get(pattern, [])
        return any(keyword in evidence for keyword in keywords)
    
    def _calculate_context_confidence(self, vulnerability: InjectionVulnerability) -> float:
        """Calculate confidence based on context factors."""
        base_confidence = 0.5
        
        # Location-based adjustments
        if vulnerability.location:
            location_lower = vulnerability.location.lower()
            
            # Higher confidence for specific locations
            if any(loc in location_lower for loc in ['contentprovider', 'provider']):
                base_confidence += 0.1
            
            # Higher confidence for production code
            if not any(test in location_lower for test in ['test', 'example', 'demo']):
                base_confidence += 0.05
            
            # Lower confidence for generated code
            if any(gen in location_lower for gen in ['generated', 'build', 'target']):
                base_confidence -= 0.1
        
        # Severity-based adjustments
        severity_adjustments = {
            SeverityLevel.CRITICAL: 0.1,
            SeverityLevel.HIGH: 0.05,
            SeverityLevel.MEDIUM: 0.0,
            SeverityLevel.LOW: -0.05,
            SeverityLevel.INFO: -0.1
        }
        
        base_confidence += severity_adjustments.get(vulnerability.severity, 0.0)
        
        # Vulnerability type adjustments
        if vulnerability.vulnerability_type == VulnerabilityType.SQL_INJECTION:
            base_confidence += 0.05  # Well-understood vulnerability type
        
        return max(0.1, min(1.0, base_confidence))
    
    def _calculate_cross_validation_confidence(self, vulnerability: InjectionVulnerability) -> float:
        """Calculate confidence based on cross-validation factors."""
        base_confidence = 0.5
        
        # Check for validation indicators in evidence
        if vulnerability.evidence:
            evidence_lower = vulnerability.evidence.lower()
            
            # Multiple validation sources
            validation_sources = ['drozer', 'static', 'manifest', 'code']
            found_sources = sum(1 for source in validation_sources if source in evidence_lower)
            
            if found_sources > 1:
                base_confidence += 0.2
            elif found_sources == 1:
                base_confidence += 0.1
        
        # MASVS control presence increases confidence
        if vulnerability.masvs_control:
            base_confidence += 0.05
        
        # CWE ID presence increases confidence
        if vulnerability.cwe_ids:
            base_confidence += 0.03
        
        # Recommendations presence (indicates thorough analysis)
        if vulnerability.recommendations:
            base_confidence += 0.02
        
        return max(0.1, min(1.0, base_confidence))
    
    def _apply_confidence_adjustments(self, base_confidence: float, vulnerability: InjectionVulnerability) -> float:
        """Apply final confidence adjustments."""
        adjusted_confidence = base_confidence
        
        # Conservative approach for low-severity findings
        if vulnerability.severity in [SeverityLevel.LOW, SeverityLevel.INFO]:
            adjusted_confidence *= 0.9
        
        # Boost confidence for high-severity findings with good evidence
        if vulnerability.severity == SeverityLevel.CRITICAL and vulnerability.evidence:
            adjusted_confidence *= 1.05
        
        # Reduce confidence for very old vulnerabilities (if timestamp available)
        # This would require additional timestamp checking logic
        
        # Apply sensitivity adjustment based on configuration
        if self.config.pattern_sensitivity == "high":
            adjusted_confidence *= 0.95  # More conservative
        elif self.config.pattern_sensitivity == "low":
            adjusted_confidence *= 1.05  # More aggressive
        
        return adjusted_confidence
    
    def get_confidence_explanation(self, vulnerability: InjectionVulnerability) -> Dict[str, Any]:
        """Get detailed explanation of confidence calculation."""
        return {
            'final_confidence': vulnerability.confidence,
            'method_confidence': self._calculate_method_confidence(vulnerability),
            'evidence_confidence': self._calculate_evidence_confidence(vulnerability),
            'pattern_confidence': self._calculate_pattern_confidence(vulnerability),
            'context_confidence': self._calculate_context_confidence(vulnerability),
            'cross_validation_confidence': self._calculate_cross_validation_confidence(vulnerability),
            'factors': {
                'analysis_method': vulnerability.method.value,
                'evidence_length': len(vulnerability.evidence) if vulnerability.evidence else 0,
                'has_code_snippet': bool(vulnerability.code_snippet),
                'has_line_number': bool(vulnerability.line_number),
                'severity': vulnerability.severity.value,
                'vulnerability_type': vulnerability.vulnerability_type.value
            }
        } 