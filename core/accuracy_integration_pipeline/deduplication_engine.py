#!/usr/bin/env python3
"""
Accuracy Integration Pipeline - Intelligent Deduplication Engine

deduplication system optimized for maximum vulnerability
detection preservation through intelligent consolidation algorithms.
"""

import logging
import time
from typing import Dict, List, Any, Set, Tuple
import hashlib

from .data_structures import AccuracyMetrics, ProcessingStage, DetectionQuality

class IntelligentDeduplicationEngine:
    """
    deduplication engine using intelligent consolidation
    algorithms optimized for maximum vulnerability preservation.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Similarity thresholds for different consolidation levels
        self.similarity_thresholds = {
            'exact_match': 1.0,           # Exact duplicates
            'high_similarity': 0.95,      # Very similar findings
            'moderate_similarity': 0.85,  # Moderately similar findings
            'low_similarity': 0.7         # Different but related findings
        }
        
        # Vulnerability type preservation priorities
        self.preservation_priorities = {
            'sql_injection': 10,          # Highest priority
            'xss': 9,
            'authentication': 8,
            'authorization': 8,
            'cryptography': 9,
            'hardcoded_secrets': 10,
            'ssl_tls': 8,
            'permissions': 6,
            'info_disclosure': 4,
            'generic': 2                  # Lowest priority
        }
    
    def deduplicate_with_preservation(
        self,
        findings: List[Dict[str, Any]],
        config: Any
    ) -> Dict[str, Any]:
        """
        Perform intelligent deduplication while preserving all unique
        vulnerabilities and maintaining maximum detection accuracy.
        """
        start_time = time.time()
        
        self.logger.info(f"Starting intelligent deduplication with preservation")
        self.logger.info(f"Input: {len(findings)} findings")
        
        # Apply base deduplication using unified framework
        try:
            from ..unified_deduplication_framework import UnifiedDeduplicationEngine, DeduplicationStrategy
            base_engine = UnifiedDeduplicationEngine()
            base_result = base_engine.deduplicate_findings(findings)
            base_unique = base_result.unique_findings
        except ImportError:
            self.logger.warning("UnifiedDeduplicationEngine not available - using enhanced deduplication")
            base_unique = self._apply_enhanced_deduplication(findings, config)
        
        # Apply vulnerability preservation logic
        preserved_findings = self._apply_vulnerability_preservation(
            findings, base_unique, config
        )
        
        processing_time = (time.time() - start_time) * 1000
        
        # Calculate comprehensive metrics
        stage_metrics = self._calculate_deduplication_metrics(
            findings, preserved_findings, processing_time
        )
        
        result = {
            'unique_findings': preserved_findings,
            'original_count': len(findings),
            'base_deduplicated_count': len(base_unique),
            'final_count': len(preserved_findings),
            'preserved_additional': len(preserved_findings) - len(base_unique),
            'metrics': stage_metrics,
            'preservation_applied': True,
            'detection_quality': self._assess_deduplication_quality(stage_metrics),
            'duplication_analysis': self._analyze_duplication_patterns(findings, preserved_findings)
        }
        
        self.logger.info(f"Deduplication complete with preservation")
        self.logger.info(f"Result: {len(findings)} -> {len(preserved_findings)} (unique preserved)")
        
        return result
    
    def _apply_enhanced_deduplication(
        self,
        findings: List[Dict[str, Any]],
        config: Any
    ) -> List[Dict[str, Any]]:
        """
        Apply enhanced deduplication when base engine is not available.
        """
        # Generate fingerprints for all findings
        fingerprinted_findings = []
        for finding in findings:
            fingerprint = self._generate_finding_fingerprint(finding)
            fingerprinted_findings.append({
                **finding,
                'fingerprint': fingerprint,
                'original_index': len(fingerprinted_findings)
            })
        
        # Group by similarity
        similarity_groups = self._group_by_similarity(
            fingerprinted_findings, config.similarity_threshold
        )
        
        # Select best representative from each group
        unique_findings = []
        for group in similarity_groups:
            representative = self._select_group_representative(group)
            unique_findings.append(representative)
        
        return unique_findings
    
    def _generate_finding_fingerprint(self, finding: Dict[str, Any]) -> str:
        """
        Generate a unique fingerprint for a finding based on key characteristics.
        """
        # Key fields for fingerprinting
        key_fields = [
            str(finding.get('type', '')).lower(),
            str(finding.get('title', '')).lower(),
            str(finding.get('file_path', '')),
            str(finding.get('line_number', '')),
            str(finding.get('severity', '')).upper(),
            str(finding.get('category', '')).lower()
        ]
        
        # Create fingerprint from normalized key fields
        fingerprint_content = '|'.join(key_fields)
        fingerprint = hashlib.md5(fingerprint_content.encode()).hexdigest()
        
        return fingerprint
    
    def _group_by_similarity(
        self,
        findings: List[Dict[str, Any]],
        threshold: float
    ) -> List[List[Dict[str, Any]]]:
        """
        Group findings by similarity using intelligent comparison algorithms.
        """
        groups = []
        processed_indices = set()
        
        for i, finding in enumerate(findings):
            if i in processed_indices:
                continue
                
            # Start new group with current finding
            current_group = [finding]
            processed_indices.add(i)
            
            # Find similar findings
            for j, other_finding in enumerate(findings[i+1:], i+1):
                if j in processed_indices:
                    continue
                    
                similarity = self._calculate_finding_similarity(finding, other_finding)
                if similarity >= threshold:
                    current_group.append(other_finding)
                    processed_indices.add(j)
            
            groups.append(current_group)
        
        return groups
    
    def _calculate_finding_similarity(
        self,
        finding1: Dict[str, Any],
        finding2: Dict[str, Any]
    ) -> float:
        """
        Calculate similarity score between two findings using multiple factors.
        """
        similarity_scores = []
        
        # Fingerprint similarity (most important)
        if finding1.get('fingerprint') == finding2.get('fingerprint'):
            similarity_scores.append(1.0)
        else:
            similarity_scores.append(0.0)
        
        # Type similarity
        type1 = str(finding1.get('type', '')).lower()
        type2 = str(finding2.get('type', '')).lower()
        type_similarity = 1.0 if type1 == type2 else 0.0
        similarity_scores.append(type_similarity)
        
        # Title similarity (using simple text comparison)
        title1 = str(finding1.get('title', '')).lower()
        title2 = str(finding2.get('title', '')).lower()
        title_similarity = self._calculate_text_similarity(title1, title2)
        similarity_scores.append(title_similarity)
        
        # File path similarity
        path1 = str(finding1.get('file_path', ''))
        path2 = str(finding2.get('file_path', ''))
        path_similarity = 1.0 if path1 == path2 else 0.0
        similarity_scores.append(path_similarity)
        
        # Severity similarity
        sev1 = str(finding1.get('severity', '')).upper()
        sev2 = str(finding2.get('severity', '')).upper()
        severity_similarity = 1.0 if sev1 == sev2 else 0.5
        similarity_scores.append(severity_similarity)
        
        # Calculate weighted average
        weights = [0.4, 0.2, 0.2, 0.1, 0.1]  # Fingerprint weighted highest
        weighted_similarity = sum(s * w for s, w in zip(similarity_scores, weights))
        
        return weighted_similarity
    
    def _calculate_text_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity between two text strings."""
        if text1 == text2:
            return 1.0
        
        # Simple character overlap calculation
        if not text1 or not text2:
            return 0.0
        
        # Calculate character overlap percentage
        chars1 = set(text1.lower())
        chars2 = set(text2.lower())
        
        intersection = len(chars1.intersection(chars2))
        union = len(chars1.union(chars2))
        
        return intersection / union if union > 0 else 0.0
    
    def _select_group_representative(self, group: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Select the best representative finding from a similarity group."""
        if len(group) == 1:
            return group[0]
        
        # Score each finding and select the best
        best_finding = None
        best_score = -1
        
        for finding in group:
            score = self._calculate_finding_quality_score(finding)
            if score > best_score:
                best_score = score
                best_finding = finding
        
        return best_finding or group[0]
    
    def _calculate_finding_quality_score(self, finding: Dict[str, Any]) -> float:
        """Calculate quality score for a finding to help select best representative."""
        score = 0.0
        
        # Score based on severity
        severity = str(finding.get('severity', '')).upper()
        severity_scores = {'CRITICAL': 10, 'HIGH': 8, 'MEDIUM': 6, 'LOW': 4, 'INFO': 2}
        score += severity_scores.get(severity, 1)
        
        # Score based on confidence if available
        confidence = finding.get('confidence', 0.5)
        score += confidence * 10
        
        # Score based on content richness
        content_length = len(str(finding.get('content', '')))
        score += min(content_length / 100, 5)  # Cap at 5 points
        
        # Score based on evidence count
        evidence_count = len(finding.get('evidence', []))
        score += min(evidence_count, 3)  # Cap at 3 points
        
        return score
    
    def _apply_vulnerability_preservation(
        self,
        original_findings: List[Dict[str, Any]],
        base_unique: List[Dict[str, Any]],
        config: Any
    ) -> List[Dict[str, Any]]:
        """
        Apply vulnerability preservation logic to ensure no critical vulnerabilities are lost.
        """
        preserved_findings = list(base_unique)
        
        # Create fingerprint sets for quick lookup
        preserved_fingerprints = set()
        for finding in preserved_findings:
            fingerprint = self._generate_finding_fingerprint(finding)
            preserved_fingerprints.add(fingerprint)
        
        # Check for high-priority vulnerabilities that might have been lost
        for original_finding in original_findings:
            original_fingerprint = self._generate_finding_fingerprint(original_finding)
            
            if original_fingerprint not in preserved_fingerprints:
                # Check if this is a high-priority vulnerability
                if self._is_high_priority_vulnerability(original_finding):
                    self.logger.info(f"Preserving high-priority vulnerability: {original_finding.get('title', 'Unknown')}")
                    preserved_findings.append(original_finding)
                    preserved_fingerprints.add(original_fingerprint)
        
        return preserved_findings
    
    def _is_high_priority_vulnerability(self, finding: Dict[str, Any]) -> bool:
        """Check if a finding represents a high-priority vulnerability."""
        # Check severity
        severity = str(finding.get('severity', '')).upper()
        if severity in ['CRITICAL', 'HIGH']:
            return True
        
        # Check vulnerability type
        vuln_type = str(finding.get('type', '')).lower()
        high_priority_types = ['sql_injection', 'hardcoded_secrets', 'cryptography', 'xss', 'authentication']
        
        for priority_type in high_priority_types:
            if priority_type in vuln_type:
                return True
        
        # Check confidence
        confidence = finding.get('confidence', 0.0)
        if confidence >= 0.9:  # Very high confidence
            return True
        
        return False
    
    def _is_likely_vulnerability(self, finding: Dict[str, Any]) -> bool:
        """Determine if a finding is likely a real vulnerability."""
        # Check for vulnerability indicators
        severity = str(finding.get('severity', '')).upper()
        if severity in ['CRITICAL', 'HIGH', 'MEDIUM']:
            return True
        
        # Check for vulnerability patterns in title/content
        content = str(finding.get('content', '')).lower()
        title = str(finding.get('title', '')).lower()
        text = f"{title} {content}"
        
        vulnerability_indicators = [
            'vulnerability', 'exploit', 'injection', 'xss', 'csrf', 
            'hardcoded', 'secret', 'password', 'authentication', 
            'authorization', 'permission', 'encryption', 'ssl', 'tls'
        ]
        
        for indicator in vulnerability_indicators:
            if indicator in text:
                return True
        
        return False
    
    def _calculate_deduplication_metrics(
        self,
        original_findings: List[Dict[str, Any]],
        final_findings: List[Dict[str, Any]],
        processing_time: float
    ) -> AccuracyMetrics:
        """
        Calculate comprehensive metrics for deduplication stage.
        """
        total_findings = len(original_findings)
        final_count = len(final_findings)
        reduction_percentage = ((total_findings - final_count) / total_findings * 100) if total_findings > 0 else 0
        
        # Count unique vulnerabilities preserved
        unique_vulnerabilities = sum(
            1 for f in final_findings 
            if self._is_likely_vulnerability(f)
        )
        
        # Calculate detection accuracy (assume all final findings are preserved vulnerabilities)
        detection_accuracy = (unique_vulnerabilities / max(1, total_findings)) * 100
        
        return AccuracyMetrics(
            stage=ProcessingStage.DEDUPLICATED,
            total_findings=total_findings,
            filtered_findings=final_count,
            reduction_percentage=reduction_percentage,
            processing_time_ms=processing_time,
            vulnerabilities_detected=unique_vulnerabilities,
            vulnerabilities_preserved=unique_vulnerabilities,
            false_positives_eliminated=total_findings - final_count,
            detection_accuracy_percent=detection_accuracy,
            duplication_stats=self._calculate_duplication_stats(original_findings, final_findings),
            detection_quality=self._calculate_detection_quality(detection_accuracy),
            quality_score=detection_accuracy / 100.0
        )
    
    def _calculate_duplication_stats(
        self,
        original_findings: List[Dict[str, Any]],
        final_findings: List[Dict[str, Any]]
    ) -> Dict[str, int]:
        """Calculate detailed duplication statistics."""
        return {
            'exact_duplicates_removed': 0,  # Would need more sophisticated calculation
            'similar_findings_consolidated': 0,
            'unique_findings_preserved': len(final_findings),
            'total_groups_created': 0
        }
    
    def _calculate_detection_quality(self, detection_accuracy: float) -> DetectionQuality:
        """Calculate detection quality based on accuracy percentage."""
        if detection_accuracy >= 95:
            return DetectionQuality.EXCELLENT
        elif detection_accuracy >= 85:
            return DetectionQuality.GOOD
        elif detection_accuracy >= 75:
            return DetectionQuality.ACCEPTABLE
        else:
            return DetectionQuality.POOR
    
    def _assess_deduplication_quality(self, metrics: AccuracyMetrics) -> str:
        """Assess the quality of deduplication results."""
        quality_indicators = []
        
        # Check reduction efficiency
        if metrics.reduction_percentage > 50:
            quality_indicators.append("High reduction efficiency")
        elif metrics.reduction_percentage > 25:
            quality_indicators.append("Moderate reduction efficiency")
        else:
            quality_indicators.append("Low reduction efficiency")
        
        # Check detection preservation
        if metrics.detection_accuracy_percent > 95:
            quality_indicators.append("Excellent detection preservation")
        elif metrics.detection_accuracy_percent > 85:
            quality_indicators.append("Good detection preservation")
        else:
            quality_indicators.append("Needs improvement in detection preservation")
        
        # Check processing performance
        if metrics.processing_time_ms < 1000:
            quality_indicators.append("Fast processing")
        elif metrics.processing_time_ms < 5000:
            quality_indicators.append("Acceptable processing time")
        else:
            quality_indicators.append("Slow processing")
        
        return "; ".join(quality_indicators)
    
    def _analyze_duplication_patterns(
        self,
        original_findings: List[Dict[str, Any]],
        final_findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Analyze patterns in the deduplication results."""
        original_count = len(original_findings)
        final_count = len(final_findings)
        
        # Analyze by severity
        severity_analysis = {}
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            original_sev_count = sum(1 for f in original_findings 
                                   if str(f.get('severity', '')).upper() == severity)
            final_sev_count = sum(1 for f in final_findings 
                                if str(f.get('severity', '')).upper() == severity)
            
            if original_sev_count > 0:
                preservation_rate = (final_sev_count / original_sev_count) * 100
                severity_analysis[severity] = {
                    'original': original_sev_count,
                    'final': final_sev_count,
                    'preservation_rate': preservation_rate
                }
        
        return {
            'total_reduction': original_count - final_count,
            'reduction_percentage': ((original_count - final_count) / original_count * 100) if original_count > 0 else 0,
            'severity_analysis': severity_analysis,
            'preservation_summary': f"{final_count}/{original_count} findings preserved"
        } 
 

