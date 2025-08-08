
#!/usr/bin/env python3
"""
Accuracy Integration Pipeline - Advanced Severity Filter

severity-based vulnerability filtering with maximum detection
preservation and zero tolerance for vulnerability loss.
"""

import logging
import time
from typing import Dict, List, Any

from .data_structures import AccuracyMetrics, ProcessingStage, DetectionQuality

class AdvancedSeverityFilter:
    """
    Advanced severity-based vulnerability filter optimized for maximum
    detection accuracy with intelligent preservation mechanisms.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
    def filter_findings_with_preservation(
        self, 
        raw_findings: List[Dict[str, Any]], 
        config: Any,
        app_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Filter findings by severity while preserving all potential vulnerabilities
        through intelligent analysis and context awareness.
        """
        start_time = time.time()
        
        self.logger.info(f"Starting advanced severity filtering with preservation")
        self.logger.info(f"Input: {len(raw_findings)} findings")
        
        # Import vulnerability filter components
        try:
            from ..vulnerability_filter import VulnerabilityFilter
            vulnerability_filter = VulnerabilityFilter()
        except ImportError:
            self.logger.warning("VulnerabilityFilter not available - using fallback")
            return self._fallback_severity_filtering(raw_findings, config)
        
        # Apply base severity filtering
        base_result = vulnerability_filter.filter_findings_by_severity(
            raw_findings, 
            min_severity=config.min_severity
        )
        
        # Enhanced preservation logic
        preserved_findings = self._apply_preservation_logic(
            raw_findings, 
            base_result['vulnerabilities'],
            config,
            app_context
        )
        
        processing_time = (time.time() - start_time) * 1000
        
        # Calculate comprehensive metrics
        stage_metrics = self._calculate_severity_metrics(
            raw_findings, 
            preserved_findings, 
            processing_time,
            base_result.get('statistics', {})
        )
        
        result = {
            'filtered_findings': preserved_findings,
            'original_count': len(raw_findings),
            'filtered_count': len(preserved_findings),
            'base_filtered_count': len(base_result['vulnerabilities']),
            'preserved_additional': len(preserved_findings) - len(base_result['vulnerabilities']),
            'metrics': stage_metrics,
            'preservation_applied': True,
            'detection_quality': self._assess_detection_quality(stage_metrics)
        }
        
        self.logger.info(f"Severity filtering complete with preservation")
        self.logger.info(f"Result: {len(raw_findings)} -> {len(preserved_findings)} (preservation applied)")
        
        return result
    
    def _apply_preservation_logic(
        self,
        raw_findings: List[Dict[str, Any]],
        base_filtered: List[Dict[str, Any]],
        config: Any,
        app_context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Apply intelligent preservation logic to maintain maximum vulnerability detection.
        """
        preserved_findings = base_filtered.copy()
        
        if not config.preserve_high_confidence_low_severity:
            return preserved_findings
        
        # Get findings that were filtered out
        base_ids = {f.get('id', str(hash(str(f)))) for f in base_filtered}
        filtered_out = [f for f in raw_findings if f.get('id', str(hash(str(f)))) not in base_ids]
        
        # Preserve high-confidence low-severity findings
        for finding in filtered_out:
            if self._should_preserve_finding(finding, app_context):
                preserved_findings.append(finding)
                self.logger.debug(f"Preserved high-confidence finding: {finding.get('title', 'Unknown')}")
        
        return preserved_findings
    
    def _should_preserve_finding(
        self,
        finding: Dict[str, Any],
        app_context: Dict[str, Any]
    ) -> bool:
        """
        Determine if a finding should be preserved despite lower severity.
        """
        # High confidence threshold for preservation
        confidence = finding.get('confidence', 0.0)
        if confidence >= 0.85:
            return True
        
        # Context-aware preservation
        finding_type = finding.get('type', '').lower()
        
        # Preserve potential security-critical findings regardless of severity
        critical_patterns = [
            'sql_injection', 'xss', 'csrf', 'authentication', 'authorization',
            'encryption', 'certificate', 'ssl', 'tls', 'crypto', 'key',
            'password', 'hardcoded', 'backdoor', 'privilege', 'permission'
        ]
        
        for pattern in critical_patterns:
            if pattern in finding_type or pattern in str(finding.get('description', '')).lower():
                self.logger.debug(f"Preserving critical pattern: {pattern}")
                return True
        
        # App context-based preservation
        if app_context.get('app_category') == 'security_testing':
            # For security testing apps, preserve more findings for validation
            return confidence >= 0.6
        
        return False
    
    def _calculate_severity_metrics(
        self,
        raw_findings: List[Dict[str, Any]],
        filtered_findings: List[Dict[str, Any]],
        processing_time: float,
        base_statistics: Dict[str, Any]
    ) -> AccuracyMetrics:
        """
        Calculate comprehensive metrics for severity filtering stage.
        """
        total_findings = len(raw_findings)
        final_findings = len(filtered_findings)
        reduction_percentage = ((total_findings - final_findings) / total_findings * 100) if total_findings > 0 else 0
        
        # Count vulnerabilities vs noise
        vulnerabilities_detected = sum(1 for f in filtered_findings if self._is_likely_vulnerability(f))
        vulnerabilities_preserved = vulnerabilities_detected  # All detected are preserved
        
        # Calculate detection accuracy
        detection_accuracy = (vulnerabilities_preserved / max(1, total_findings)) * 100
        
        return AccuracyMetrics(
            stage=ProcessingStage.SEVERITY_FILTERED,
            total_findings=total_findings,
            filtered_findings=final_findings,
            reduction_percentage=reduction_percentage,
            processing_time_ms=processing_time,
            vulnerabilities_detected=vulnerabilities_detected,
            vulnerabilities_preserved=vulnerabilities_preserved,
            false_positives_eliminated=total_findings - final_findings,
            detection_accuracy_percent=detection_accuracy,
            severity_distribution=base_statistics,
            detection_quality=self._calculate_detection_quality(detection_accuracy),
            quality_score=detection_accuracy / 100.0
        )
    
    def _is_likely_vulnerability(self, finding: Dict[str, Any]) -> bool:
        """
        Determine if a finding is likely a real vulnerability.
        """
        # High confidence findings are likely vulnerabilities
        if finding.get('confidence', 0.0) >= 0.8:
            return True
        
        # Check for vulnerability indicators
        severity = str(finding.get('severity', '')).upper()
        if severity in ['HIGH', 'CRITICAL']:
            return True
        
        # Pattern-based vulnerability detection
        finding_type = str(finding.get('type', '')).lower()
        vuln_patterns = [
            'injection', 'xss', 'csrf', 'auth', 'crypto', 'ssl', 'tls',
            'permission', 'privilege', 'hardcoded', 'backdoor'
        ]
        
        return any(pattern in finding_type for pattern in vuln_patterns)
    
    def _calculate_detection_quality(self, detection_accuracy: float) -> DetectionQuality:
        """Calculate detection quality based on accuracy percentage."""
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
    
    def _assess_detection_quality(self, metrics: AccuracyMetrics) -> str:
        """Assess overall detection quality for the filtering stage."""
        if metrics.detection_quality == DetectionQuality.EXCELLENT:
            return "Excellent detection preservation"
        elif metrics.detection_quality == DetectionQuality.GOOD:
            return "Good detection preservation"
        elif metrics.detection_quality == DetectionQuality.ACCEPTABLE:
            return "Acceptable detection preservation"
        else:
            return "Detection quality needs improvement"
    
    def _fallback_severity_filtering(
        self, 
        raw_findings: List[Dict[str, Any]], 
        config: Any
    ) -> Dict[str, Any]:
        """
        Fallback severity filtering when VulnerabilityFilter is not available.
        """
        self.logger.warning("Using fallback severity filtering")
        
        # Simple severity-based filtering
        min_severity = str(config.min_severity).upper()
        severity_order = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        min_index = severity_order.index(min_severity) if min_severity in severity_order else 2
        
        filtered_findings = []
        for finding in raw_findings:
            severity = str(finding.get('severity', 'MEDIUM')).upper()
            if severity in severity_order and severity_order.index(severity) >= min_index:
                filtered_findings.append(finding)
        
        return {
            'vulnerabilities': filtered_findings,
            'statistics': {
                'reduction_percentage': ((len(raw_findings) - len(filtered_findings)) / len(raw_findings) * 100) if raw_findings else 0
            }
        } 

# Enhanced context-aware filtering
from core.app_type_detector import detect_app_type, AppType

class ContextAwareSeverityFilter(AdvancedSeverityFilter):
    """Enhanced severity filter with app type awareness."""
    
    def filter_vulnerabilities_with_context(self, vulnerabilities, apk_context):
        """Filter vulnerabilities based on app type context."""
        app_type = detect_app_type(apk_context)
        config = self._get_filtering_config(app_type)
        
        self.logger.info(f"Filtering {len(vulnerabilities)} vulnerabilities for {app_type.value}")
        self.logger.info(f"Using severity threshold: {config['severity_threshold']}")
        
        # Apply context-aware filtering
        filtered = []
        for vuln in vulnerabilities:
            if self._meets_threshold(vuln.severity, config['severity_threshold']):
                filtered.append(vuln)
        
        reduction_rate = (len(vulnerabilities) - len(filtered)) / len(vulnerabilities) * 100
        self.logger.info(f"Severity filtering: {len(vulnerabilities)} → {len(filtered)} ({reduction_rate:.1f}% reduction)")
        
        # Warn if filtering too aggressive for vulnerable apps
        if app_type == AppType.VULNERABLE_APP and reduction_rate > 60:
            self.logger.warning(f"High filtering rate ({reduction_rate:.1f}%) for vulnerable app")
        
        return filtered
    
    def _get_filtering_config(self, app_type: AppType):
        """Get filtering configuration for app type."""
        from core.app_type_detector import app_type_detector
        return app_type_detector.get_filtering_config(app_type)
    
    def _meets_threshold(self, severity, threshold):
        """Check if severity meets threshold."""
        severity_levels = {
            "INFO": 0,
            "LOW": 1, 
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4
        }
        
        severity_value = severity_levels.get(severity.upper(), 0)
        threshold_value = severity_levels.get(threshold.upper(), 2)
        
        return severity_value >= threshold_value
