#!/usr/bin/env python3
"""
Accuracy Integration Pipeline - Professional Confidence Calculator

Evidence-based confidence scoring system optimized for maximum vulnerability
detection accuracy with professional scoring algorithms.
"""

import logging
import time
from typing import Dict, List, Any, Tuple

from .data_structures import AccuracyMetrics, ProcessingStage, DetectionQuality

class ProfessionalConfidenceCalculator:
    """
    confidence calculator using evidence-based scoring
    algorithms optimized for maximum vulnerability detection accuracy.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Evidence weighting factors (professional calibration)
        self.evidence_weights = {
            'static_analysis': 0.25,      # Static code analysis evidence
            'dynamic_analysis': 0.35,     # Dynamic testing evidence  
            'pattern_matching': 0.20,     # Pattern-based detection
            'context_analysis': 0.15,     # Contextual analysis
            'ml_prediction': 0.05         # Machine learning prediction
        }
        
        # Vulnerability type confidence modifiers
        self.vulnerability_modifiers = {
            'sql_injection': 1.2,         # High confidence for SQL injection
            'xss': 1.15,                  # High confidence for XSS
            'authentication': 1.1,        # Authentication issues
            'authorization': 1.1,         # Authorization issues
            'cryptography': 1.25,         # Crypto vulnerabilities
            'hardcoded_secrets': 1.3,     # Hardcoded credentials
            'ssl_tls': 1.2,              # SSL/TLS issues
            'permissions': 1.0,           # Standard confidence
            'info_disclosure': 0.9,       # Lower confidence for info disclosure
            'generic': 0.8                # Lower confidence for generic findings
        }
    
    def calculate_confidence_scores(
        self,
        findings: List[Dict[str, Any]],
        config: Any,
        app_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Calculate professional confidence scores for vulnerability findings
        using evidence-based algorithms and contextual analysis.
        """
        start_time = time.time()
        
        self.logger.info(f"Starting professional confidence calculation")
        self.logger.info(f"Input: {len(findings)} findings")
        
        # Apply base confidence scoring
        try:
            from ..confidence_scorer import ConfidenceScorer
            base_scorer = ConfidenceScorer()
            base_result = base_scorer.score_findings(findings, app_context)
            
            # Handle the new direct list return format
            if isinstance(base_result, list):
                scored_findings = base_result
            else:
                # Legacy fallback for dict format
                scored_findings = base_result.get('scored_findings', findings)
                
        except ImportError:
            self.logger.warning("ConfidenceScorer not available - using enhanced scoring")
            scored_findings = self._apply_enhanced_confidence_scoring(findings, app_context)
        
        # Apply professional enhancements
        enhanced_findings = self._apply_professional_enhancements(
            scored_findings, config, app_context
        )
        
        # Filter by confidence threshold with vulnerability preservation
        final_findings = self._apply_confidence_filtering(
            enhanced_findings, config
        )
        
        processing_time = (time.time() - start_time) * 1000
        
        # Calculate comprehensive metrics
        stage_metrics = self._calculate_confidence_metrics(
            findings, final_findings, processing_time
        )
        
        result = {
            'filtered_findings': final_findings,
            'original_count': len(findings),
            'scored_count': len(enhanced_findings),
            'final_count': len(final_findings),
            'confidence_enhanced': True,
            'metrics': stage_metrics,
            'confidence_distribution': self._calculate_confidence_distribution(final_findings),
            'detection_quality': self._assess_confidence_quality(stage_metrics)
        }
        
        self.logger.info(f"Confidence scoring complete")
        self.logger.info(f"Result: {len(findings)} -> {len(final_findings)} (confidence-filtered)")
        
        return result
    
    def _apply_enhanced_confidence_scoring(
        self,
        findings: List[Dict[str, Any]],
        app_context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Apply enhanced confidence scoring when base scorer is not available.
        """
        enhanced_findings = []
        
        for finding in findings:
            enhanced_finding = finding.copy()
            
            # Calculate evidence-based confidence
            confidence_score = self._calculate_evidence_based_confidence(
                finding, app_context
            )
            
            enhanced_finding['confidence'] = confidence_score
            enhanced_finding['confidence_factors'] = self._get_confidence_factors(finding)
            enhanced_finding['professional_score'] = True
            
            enhanced_findings.append(enhanced_finding)
        
        return enhanced_findings
    
    def _calculate_evidence_based_confidence(
        self,
        finding: Dict[str, Any],
        app_context: Dict[str, Any]
    ) -> float:
        """
        Calculate evidence-based confidence score using professional algorithms.
        """
        base_confidence = finding.get('confidence', 0.5)
        
        # Evidence accumulation
        evidence_score = 0.0
        
        # Static analysis evidence
        if finding.get('static_analysis_confirmed'):
            evidence_score += self.evidence_weights['static_analysis']
        
        # Dynamic analysis evidence
        if finding.get('dynamic_analysis_confirmed'):
            evidence_score += self.evidence_weights['dynamic_analysis']
        
        # Pattern matching evidence
        if finding.get('pattern_matched'):
            evidence_score += self.evidence_weights['pattern_matching']
        
        # Context analysis evidence
        context_score = self._calculate_context_evidence(finding, app_context)
        evidence_score += context_score * self.evidence_weights['context_analysis']
        
        # ML prediction evidence (if available)
        if finding.get('ml_prediction'):
            ml_confidence = finding.get('ml_confidence', 0.5)
            evidence_score += ml_confidence * self.evidence_weights['ml_prediction']
        
        # Vulnerability type modifier
        vuln_type = self._identify_vulnerability_type(finding)
        type_modifier = self.vulnerability_modifiers.get(vuln_type, 1.0)
        
        # Calculate final confidence
        final_confidence = min(1.0, (base_confidence + evidence_score) * type_modifier)
        
        return final_confidence
    
    def _calculate_context_evidence(
        self,
        finding: Dict[str, Any],
        app_context: Dict[str, Any]
    ) -> float:
        """
        Calculate context-based evidence score.
        """
        context_score = 0.0
        
        # App category context
        app_category = app_context.get('app_category', 'unknown')
        if app_category == 'security_testing':
            context_score += 0.3  # Higher confidence for security test apps
        elif app_category == 'banking':
            context_score += 0.2  # Financial apps need higher confidence
        
        # Framework context
        if 'framework' in app_context:
            context_score += 0.1
        
        # Debug build context
        if app_context.get('is_debug_build'):
            context_score += 0.1
        
        return min(1.0, context_score)
    
    def _identify_vulnerability_type(self, finding: Dict[str, Any]) -> str:
        """
        Identify vulnerability type for appropriate confidence modification.
        """
        finding_type = str(finding.get('type', '')).lower()
        title = str(finding.get('title', '')).lower()
        description = str(finding.get('description', '')).lower()
        
        combined_text = f"{finding_type} {title} {description}"
        
        # Pattern matching for vulnerability types
        if any(pattern in combined_text for pattern in ['sql', 'injection', 'sqli']):
            return 'sql_injection'
        elif any(pattern in combined_text for pattern in ['xss', 'cross-site', 'script']):
            return 'xss'
        elif any(pattern in combined_text for pattern in ['auth', 'login', 'password']):
            return 'authentication'
        elif any(pattern in combined_text for pattern in ['permission', 'access', 'privilege']):
            return 'authorization'
        elif any(pattern in combined_text for pattern in ['crypto', 'encrypt', 'cipher', 'hash']):
            return 'cryptography'
        elif any(pattern in combined_text for pattern in ['hardcoded', 'embedded', 'secret']):
            return 'hardcoded_secrets'
        elif any(pattern in combined_text for pattern in ['ssl', 'tls', 'certificate']):
            return 'ssl_tls'
        elif any(pattern in combined_text for pattern in ['info', 'disclosure', 'leak']):
            return 'info_disclosure'
        else:
            return 'generic'
    
    def _get_confidence_factors(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get detailed confidence factors for transparency.
        """
        return {
            'base_confidence': finding.get('confidence', 0.5),
            'static_analysis': finding.get('static_analysis_confirmed', False),
            'dynamic_analysis': finding.get('dynamic_analysis_confirmed', False),
            'pattern_matched': finding.get('pattern_matched', False),
            'vulnerability_type': self._identify_vulnerability_type(finding),
            'professional_scoring': True
        }
    
    def _apply_professional_enhancements(
        self,
        findings: List[Dict[str, Any]],
        config: Any,
        app_context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Apply professional enhancements to confidence scores.
        """
        if not config.enable_context_adjustment:
            return findings
        
        enhanced_findings = []
        
        for finding in findings:
            enhanced_finding = finding.copy()
            
            # Apply context adjustments
            original_confidence = enhanced_finding.get('confidence', 0.5)
            adjusted_confidence = self._apply_context_adjustments(
                original_confidence, finding, app_context
            )
            
            enhanced_finding['confidence'] = adjusted_confidence
            enhanced_finding['confidence_adjusted'] = True
            enhanced_finding['original_confidence'] = original_confidence
            
            enhanced_findings.append(enhanced_finding)
        
        return enhanced_findings
    
    def _apply_context_adjustments(
        self,
        base_confidence: float,
        finding: Dict[str, Any],
        app_context: Dict[str, Any]
    ) -> float:
        """
        Apply context-based confidence adjustments.
        """
        adjusted_confidence = base_confidence
        
        # Security testing app adjustments
        if app_context.get('app_category') == 'security_testing':
            # Increase confidence for known vulnerable test apps
            adjusted_confidence = min(1.0, adjusted_confidence * 1.1)
        
        # Framework-specific adjustments
        framework = app_context.get('framework')
        if framework and framework.lower() in ['react_native', 'flutter', 'xamarin']:
            # Cross-platform frameworks may have different patterns
            adjusted_confidence = min(1.0, adjusted_confidence * 1.05)
        
        # High-severity findings get confidence boost
        severity = str(finding.get('severity', '')).upper()
        if severity in ['HIGH', 'CRITICAL']:
            adjusted_confidence = min(1.0, adjusted_confidence * 1.1)
        
        return adjusted_confidence
    
    def _apply_confidence_filtering(
        self,
        findings: List[Dict[str, Any]],
        config: Any
    ) -> List[Dict[str, Any]]:
        """
        Apply confidence-based filtering with vulnerability preservation.
        """
        # Handle nested confidence configuration structure
        if hasattr(config, 'confidence_config') and hasattr(config.confidence_config, 'min_confidence_threshold'):
            threshold = config.confidence_config.min_confidence_threshold
        elif hasattr(config, 'min_confidence_threshold'):
            threshold = config.min_confidence_threshold
        else:
            threshold = 0.7  # Default fallback
        
        filtered_findings = []
        
        for finding in findings:
            confidence = finding.get('confidence', 0.0)
            
            # Standard threshold check
            if confidence >= threshold:
                filtered_findings.append(finding)
            # Vulnerability preservation logic
            elif self._should_preserve_low_confidence(finding, config):
                filtered_findings.append(finding)
                self.logger.debug(f"Preserved low-confidence vulnerability: {finding.get('title', 'Unknown')}")
        
        return filtered_findings
    
    def _should_preserve_low_confidence(
        self,
        finding: Dict[str, Any],
        config: Any
    ) -> bool:
        """
        Determine if low-confidence finding should be preserved.
        """
        # Preserve high-severity findings even with lower confidence
        severity = str(finding.get('severity', '')).upper()
        if severity in ['HIGH', 'CRITICAL']:
            return finding.get('confidence', 0.0) >= 0.6
        
        # Preserve findings with strong evidence
        if finding.get('static_analysis_confirmed') and finding.get('dynamic_analysis_confirmed'):
            return finding.get('confidence', 0.0) >= 0.5
        
        # Preserve critical vulnerability types
        vuln_type = self._identify_vulnerability_type(finding)
        if vuln_type in ['sql_injection', 'xss', 'hardcoded_secrets', 'cryptography']:
            return finding.get('confidence', 0.0) >= 0.5
        
        return False
    
    def _calculate_confidence_metrics(
        self,
        original_findings: List[Dict[str, Any]],
        final_findings: List[Dict[str, Any]],
        processing_time: float
    ) -> AccuracyMetrics:
        """
        Calculate comprehensive metrics for confidence scoring stage.
        """
        total_findings = len(original_findings)
        final_count = len(final_findings)
        reduction_percentage = ((total_findings - final_count) / total_findings * 100) if total_findings > 0 else 0
        
        # Count high-confidence vulnerabilities
        high_confidence_vulns = sum(
            1 for f in final_findings 
            if f.get('confidence', 0.0) >= 0.8 and self._is_likely_vulnerability(f)
        )
        
        # Calculate detection accuracy
        detection_accuracy = (high_confidence_vulns / max(1, total_findings)) * 100
        
        return AccuracyMetrics(
            stage=ProcessingStage.CONFIDENCE_SCORED,
            total_findings=total_findings,
            filtered_findings=final_count,
            reduction_percentage=reduction_percentage,
            processing_time_ms=processing_time,
            vulnerabilities_detected=high_confidence_vulns,
            vulnerabilities_preserved=high_confidence_vulns,
            false_positives_eliminated=total_findings - final_count,
            detection_accuracy_percent=detection_accuracy,
            confidence_distribution=self._calculate_confidence_distribution(final_findings),
            detection_quality=self._calculate_detection_quality(detection_accuracy),
            quality_score=detection_accuracy / 100.0
        )
    
    def _calculate_confidence_distribution(
        self,
        findings: List[Dict[str, Any]]
    ) -> Dict[str, int]:
        """
        Calculate confidence score distribution.
        """
        distribution = {
            'very_high': 0,     # 0.9+
            'high': 0,          # 0.8-0.89
            'medium': 0,        # 0.6-0.79
            'low': 0,           # 0.4-0.59
            'very_low': 0       # <0.4
        }
        
        for finding in findings:
            confidence = finding.get('confidence', 0.0)
            
            if confidence >= 0.9:
                distribution['very_high'] += 1
            elif confidence >= 0.8:
                distribution['high'] += 1
            elif confidence >= 0.6:
                distribution['medium'] += 1
            elif confidence >= 0.4:
                distribution['low'] += 1
            else:
                distribution['very_low'] += 1
        
        return distribution
    
    def _is_likely_vulnerability(self, finding: Dict[str, Any]) -> bool:
        """Determine if finding is likely a real vulnerability."""
        confidence = finding.get('confidence', 0.0)
        severity = str(finding.get('severity', '')).upper()
        
        # High confidence or high severity indicates vulnerability
        return confidence >= 0.7 or severity in ['HIGH', 'CRITICAL']
    
    def _calculate_detection_quality(self, detection_accuracy: float) -> DetectionQuality:
        """Calculate detection quality based on accuracy."""
        if detection_accuracy >= 95:
            return DetectionQuality.EXCELLENT
        elif detection_accuracy >= 85:
            return DetectionQuality.GOOD
        elif detection_accuracy >= 75:
            return DetectionQuality.ACCEPTABLE
        elif detection_accuracy >= 65:
            return DetectionQuality.POOR
        else:
            return DetectionQuality.CRITICAL
    
    def _assess_confidence_quality(self, metrics: AccuracyMetrics) -> str:
        """Assess confidence scoring quality."""
        if metrics.detection_quality == DetectionQuality.EXCELLENT:
            return "Excellent confidence scoring accuracy"
        elif metrics.detection_quality == DetectionQuality.GOOD:
            return "Good confidence scoring accuracy"
        elif metrics.detection_quality == DetectionQuality.ACCEPTABLE:
            return "Acceptable confidence scoring accuracy"
        else:
            return "Confidence scoring quality needs improvement" 