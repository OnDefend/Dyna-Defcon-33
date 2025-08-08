#!/usr/bin/env python3
"""
Unified Risk Scoring Engine

Comprehensive risk scoring system that ensures consistent severity classification,
risk categorization, and alignment between summary statistics and detailed findings.
"""

import logging
import math
from typing import Dict, List, Any, Tuple, Optional
from enum import Enum
from dataclasses import dataclass

logger = logging.getLogger(__name__)

class SeverityLevel(Enum):
    """Standardized severity levels with numeric values for comparison."""
    CRITICAL = 5
    HIGH = 4  
    MEDIUM = 3
    LOW = 2
    INFO = 1
    INFORMATIONAL = 1

class RiskCategory(Enum):
    """Risk categories for triage prioritization."""
    CRITICAL_RISK = "Critical Risk"      # Immediate action required
    HIGH_RISK = "High Risk"              # Urgent remediation needed
    MEDIUM_RISK = "Medium Risk"          # Planned remediation
    LOW_RISK = "Low Risk"                # Monitor and track
    INFORMATIONAL = "Informational"      # No immediate risk

@dataclass
class RiskScore:
    """Comprehensive risk score with breakdown."""
    base_score: float           # 0-10 base CVSS-like score
    adjusted_score: float       # Score adjusted for confidence/context
    severity: SeverityLevel     # Standardized severity
    risk_category: RiskCategory # Risk category for triage
    confidence_factor: float    # Confidence adjustment (0-1)
    context_multiplier: float   # Context-based multiplier
    explanation: str           # Human-readable explanation

@dataclass
class ScoringMetrics:
    """Metrics used in risk scoring calculation."""
    impact_score: float         # Potential impact (0-10)
    exploitability_score: float # Ease of exploitation (0-10)
    confidence_score: float     # Confidence in finding (0-1)
    confidence_factor: float    # Confidence adjustment factor (0-1) 
    context_score: float        # Environmental context (0-2)
    threat_intel_score: float   # Threat intelligence factor (0-2)

class UnifiedRiskScoringEngine:
    """
    Unified risk scoring engine that provides consistent risk assessment
    across all vulnerability sources and ensures alignment with summaries.
    """
    
    def __init__(self):
        """Initialize the unified risk scoring engine."""
        
        # Scoring thresholds for different categories
        self.risk_thresholds = {
            RiskCategory.CRITICAL_RISK: 9.0,
            RiskCategory.HIGH_RISK: 7.0,
            RiskCategory.MEDIUM_RISK: 4.0,
            RiskCategory.LOW_RISK: 2.0,
            RiskCategory.INFORMATIONAL: 0.0
        }
        
        # Severity to base score mapping
        self.severity_base_scores = {
            'CRITICAL': 9.5,
            'HIGH': 7.5,
            'MEDIUM': 5.0,
            'LOW': 2.5,
            'INFO': 1.0,
            'INFORMATIONAL': 1.0
        }
        
        # Vulnerability type impact scores
        self.vulnerability_impact_scores = {
            'sql_injection': 9.0,
            'remote_code_execution': 10.0,
            'authentication_bypass': 8.5,
            'privilege_escalation': 8.0,
            'hardcoded_credentials': 7.5,
            'insecure_storage': 6.5,
            'cleartext_communication': 6.0,
            'debug_enabled': 4.0,
            'permission_issue': 5.5,
            'information_disclosure': 5.0,
            'directory_traversal': 7.0,
            'xss': 6.5,
            'csrf': 5.5,
            'weak_crypto': 6.0,
            'default': 5.0
        }
        
        # Exploitability factors
        self.exploitability_factors = {
            'remote': 10.0,
            'local': 7.0,
            'physical': 3.0,
            'network': 9.0,
            'adjacent_network': 6.0,
            'unknown': 5.0
        }
        
        # Context multipliers
        self.context_multipliers = {
            'production': 2.0,
            'staging': 1.5,
            'development': 1.0,
            'test': 0.8,
            'unknown': 1.2
        }
        
        self.statistics = {
            'total_scored': 0,
            'score_adjustments': 0,
            'severity_changes': 0,
            'consistency_fixes': 0
        }
    
    def score_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]], 
                            context: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Apply unified risk scoring to all vulnerabilities.
        
        Args:
            vulnerabilities: List of vulnerability findings
            context: Optional context information (environment, app type, etc.)
            
        Returns:
            Vulnerabilities with unified risk scores and consistent classifications
        """
        logger.info(f"🎯 Applying unified risk scoring to {len(vulnerabilities)} vulnerabilities...")
        
        self.statistics['total_scored'] = len(vulnerabilities)
        scored_vulnerabilities = []
        
        # Get global context
        global_context = context or {}
        
        for vuln in vulnerabilities:
            try:
                scored_vuln = self._score_single_vulnerability(vuln, global_context)
                scored_vulnerabilities.append(scored_vuln)
                
            except Exception as e:
                logger.warning(f"Failed to score vulnerability '{vuln.get('title', 'Unknown')}': {e}")
                # Apply default scoring
                default_scored = self._apply_default_scoring(vuln)
                scored_vulnerabilities.append(default_scored)
        
        # Ensure consistency across all scores
        consistent_vulnerabilities = self._ensure_scoring_consistency(scored_vulnerabilities)
        
        logger.info(f"✅ Risk scoring complete:")
        logger.info(f"   Vulnerabilities scored: {self.statistics['total_scored']}")
        logger.info(f"   Score adjustments: {self.statistics['score_adjustments']}")
        logger.info(f"   Severity changes: {self.statistics['severity_changes']}")
        logger.info(f"   Consistency fixes: {self.statistics['consistency_fixes']}")
        
        return consistent_vulnerabilities
    
    def _score_single_vulnerability(self, vuln: Dict[str, Any], 
                                  context: Dict[str, Any]) -> Dict[str, Any]:
        """Apply comprehensive risk scoring to a single vulnerability."""
        
        # Calculate scoring metrics
        metrics = self._calculate_scoring_metrics(vuln, context)
        
        # Calculate base risk score using CVSS-inspired approach
        base_score = self._calculate_base_score(metrics)
        
        # Apply confidence and context adjustments
        adjusted_score = self._apply_score_adjustments(base_score, metrics)
        
        # Determine severity and risk category
        severity = self._determine_severity(adjusted_score, vuln)
        risk_category = self._determine_risk_category(adjusted_score, severity)
        
        # Create comprehensive risk score object
        risk_score = RiskScore(
            base_score=base_score,
            adjusted_score=adjusted_score,
            severity=severity,
            risk_category=risk_category,
            confidence_factor=metrics.confidence_score,
            context_multiplier=metrics.context_score,
            explanation=self._generate_score_explanation(metrics, adjusted_score, severity)
        )
        
        # Update vulnerability with unified scoring
        updated_vuln = vuln.copy()
        
        # Check if severity changed
        original_severity = vuln.get('severity', '').upper()
        new_severity = severity.name
        if original_severity != new_severity:
            self.statistics['severity_changes'] += 1
            logger.debug(f"Severity changed from {original_severity} to {new_severity} for '{vuln.get('title', 'Unknown')}'")
        
        updated_vuln.update({
            'severity': severity.name,
            'risk_score': round(adjusted_score, 2),
            'base_risk_score': round(base_score, 2),
            'risk_category': risk_category.value,
            'risk_level': risk_category.value,  # For backward compatibility
            'confidence': metrics.confidence_score,
            'unified_scoring': {
                'base_score': round(base_score, 2),
                'adjusted_score': round(adjusted_score, 2),
                'impact_score': round(metrics.impact_score, 2),
                'exploitability_score': round(metrics.exploitability_score, 2),
                'confidence_factor': round(metrics.confidence_factor, 2),
                'context_multiplier': round(metrics.context_score, 2),
                'threat_intel_factor': round(metrics.threat_intel_score, 2),
                'explanation': risk_score.explanation
            }
        })
        
        self.statistics['score_adjustments'] += 1
        return updated_vuln
    
    def _calculate_scoring_metrics(self, vuln: Dict[str, Any], 
                                 context: Dict[str, Any]) -> ScoringMetrics:
        """Calculate comprehensive scoring metrics for a vulnerability."""
        
        # Impact Score (0-10)
        impact_score = self._calculate_impact_score(vuln)
        
        # Exploitability Score (0-10)
        exploitability_score = self._calculate_exploitability_score(vuln)
        
        # Confidence Score (0-1)
        confidence_score = self._normalize_confidence_score(vuln.get('confidence', 0.7))
        
        # Context Score (0-2)
        context_score = self._calculate_context_score(vuln, context)
        
        # Threat Intelligence Score (0-2)
        threat_intel_score = self._calculate_threat_intel_score(vuln)
        
        return ScoringMetrics(
            impact_score=impact_score,
            exploitability_score=exploitability_score,
            confidence_score=confidence_score,
            confidence_factor=confidence_score,  # Use same value for compatibility
            context_score=context_score,
            threat_intel_score=threat_intel_score
        )
    
    def _calculate_impact_score(self, vuln: Dict[str, Any]) -> float:
        """Calculate potential impact score (0-10)."""
        
        # Get vulnerability type
        vuln_type = vuln.get('vulnerability_type', '').lower()
        category = vuln.get('category', '').lower()
        title = vuln.get('title', '').lower()
        
        # Try to map to known vulnerability types
        for vtype, score in self.vulnerability_impact_scores.items():
            if (vtype in vuln_type or vtype in category or 
                vtype.replace('_', ' ') in title or vtype.replace('_', '') in title):
                return score
        
        # Analyze severity for impact
        severity = vuln.get('severity', 'MEDIUM').upper()
        if severity in self.severity_base_scores:
            base_score = self.severity_base_scores[severity]
            # Convert from 10-point scale to impact scale
            return min(10.0, base_score * 1.05)  # Slight adjustment
        
        # Check for high-impact keywords in description
        description = vuln.get('description', '').lower()
        high_impact_keywords = [
            'remote code execution', 'rce', 'arbitrary code',
            'authentication bypass', 'privilege escalation',
            'sql injection', 'command injection', 'file inclusion'
        ]
        
        for keyword in high_impact_keywords:
            if keyword in description:
                return 8.5
        
        # Default impact based on MASVS controls if available
        masvs_controls = vuln.get('masvs_controls', [])
        if masvs_controls:
            # High-impact MASVS areas
            if any('CRYPTO' in control or 'AUTH' in control for control in masvs_controls):
                return 7.5
            elif any('STORAGE' in control or 'NETWORK' in control for control in masvs_controls):
                return 6.5
            else:
                return 5.5
        
        return self.vulnerability_impact_scores['default']
    
    def _calculate_exploitability_score(self, vuln: Dict[str, Any]) -> float:
        """Calculate exploitability score (0-10)."""
        
        # Check for network accessibility
        description = vuln.get('description', '').lower()
        title = vuln.get('title', '').lower()
        combined_text = f"{title} {description}"
        
        # Network-based vulnerabilities are more exploitable
        if any(keyword in combined_text for keyword in ['network', 'remote', 'http', 'url', 'api']):
            base_exploitability = self.exploitability_factors['network']
        elif any(keyword in combined_text for keyword in ['local', 'file', 'storage']):
            base_exploitability = self.exploitability_factors['local']
        else:
            base_exploitability = self.exploitability_factors['unknown']
        
        # Adjust based on complexity indicators
        complexity_reducers = ['complex', 'difficult', 'requires', 'needs', 'must have']
        complexity_score = 0
        for reducer in complexity_reducers:
            if reducer in combined_text:
                complexity_score += 1
        
        # Reduce exploitability for complex attacks
        complexity_penalty = min(3.0, complexity_score * 0.5)
        adjusted_exploitability = max(1.0, base_exploitability - complexity_penalty)
        
        # Increase for common/easy exploits
        easy_indicators = ['default', 'hardcoded', 'cleartext', 'debug', 'enabled']
        for indicator in easy_indicators:
            if indicator in combined_text:
                adjusted_exploitability = min(10.0, adjusted_exploitability + 0.5)
        
        return adjusted_exploitability
    
    def _normalize_confidence_score(self, raw_confidence: Any) -> float:
        """Normalize confidence score to 0-1 range."""
        
        try:
            confidence = float(raw_confidence)
            
            # Handle percentage values
            if confidence > 1.0:
                confidence = confidence / 100.0
            
            # Clamp to valid range
            return max(0.0, min(1.0, confidence))
            
        except (ValueError, TypeError):
            # Default confidence for non-numeric values
            return 0.7
    
    def _calculate_context_score(self, vuln: Dict[str, Any], 
                               context: Dict[str, Any]) -> float:
        """Calculate context-based score multiplier (0-2)."""
        
        # Environment context
        environment = context.get('environment', 'unknown').lower()
        env_multiplier = self.context_multipliers.get(environment, 1.2)
        
        # Application criticality
        criticality = context.get('criticality', 'medium').lower()
        criticality_multipliers = {
            'critical': 2.0,
            'high': 1.8,
            'medium': 1.4,
            'low': 1.0,
            'unknown': 1.2
        }
        crit_multiplier = criticality_multipliers.get(criticality, 1.2)
        
        # Data sensitivity
        data_sensitivity = context.get('data_sensitivity', 'medium').lower()
        sensitivity_multipliers = {
            'highly_sensitive': 2.0,
            'sensitive': 1.6,
            'medium': 1.2,
            'low': 1.0,
            'public': 0.8
        }
        sens_multiplier = sensitivity_multipliers.get(data_sensitivity, 1.2)
        
        # Calculate weighted context score
        context_score = (env_multiplier * 0.4 + crit_multiplier * 0.4 + sens_multiplier * 0.2)
        
        return min(2.0, context_score)
    
    def _calculate_threat_intel_score(self, vuln: Dict[str, Any]) -> float:
        """Calculate threat intelligence enhancement factor (0-2)."""
        
        threat_intel = vuln.get('threat_intelligence', {})
        
        if not threat_intel:
            return 1.0  # Neutral factor
        
        # Active threats increase score
        active_threats = threat_intel.get('active_threats', 0)
        if active_threats > 0:
            threat_score = 1.5 + min(0.5, active_threats * 0.1)
        else:
            threat_score = 1.0
        
        # CVE associations
        cve_count = threat_intel.get('cve_matches', 0)
        if cve_count > 0:
            threat_score += min(0.3, cve_count * 0.1)
        
        # Exploit availability
        exploit_available = threat_intel.get('exploit_available', False)
        if exploit_available:
            threat_score += 0.4
        
        # Recently disclosed (higher risk)
        recent_disclosure = threat_intel.get('recent_disclosure', False)
        if recent_disclosure:
            threat_score += 0.2
        
        return min(2.0, threat_score)
    
    def _calculate_base_score(self, metrics: ScoringMetrics) -> float:
        """Calculate base CVSS-inspired risk score (0-10)."""
        
        # CVSS v3 inspired formula with modifications
        impact = metrics.impact_score
        exploitability = metrics.exploitability_score
        
        # Normalize to 0-1 range for calculation
        impact_normalized = impact / 10.0
        exploitability_normalized = exploitability / 10.0
        
        # Calculate ISS (Impact Sub Score)
        iss = 1 - ((1 - impact_normalized) * (1 - impact_normalized) * (1 - impact_normalized))
        
        # Calculate base score
        if iss <= 0:
            base_score = 0
        else:
            # Modified CVSS formula
            base_score = min(10.0, (iss * 6.42 + exploitability_normalized * 8.22))
        
        return max(0.0, base_score)
    
    def _apply_score_adjustments(self, base_score: float, 
                               metrics: ScoringMetrics) -> float:
        """Apply confidence and context adjustments to base score."""
        
        # Confidence adjustment (reduce score for low confidence)
        confidence_factor = 0.7 + (metrics.confidence_score * 0.3)  # 0.7 to 1.0 range
        confidence_adjusted = base_score * confidence_factor
        
        # Context multiplier
        context_adjusted = confidence_adjusted * (metrics.context_score / 1.4)  # Normalize around 1.0
        
        # Threat intelligence adjustment
        threat_adjusted = context_adjusted * (metrics.threat_intel_score / 1.0)  # Normalize around 1.0
        
        # Ensure we don't exceed maximum score
        final_score = min(10.0, max(0.0, threat_adjusted))
        
        return final_score
    
    def _determine_severity(self, score: float, vuln: Dict[str, Any]) -> SeverityLevel:
        """Determine severity level based on adjusted score."""
        
        if score >= 9.0:
            return SeverityLevel.CRITICAL
        elif score >= 7.0:
            return SeverityLevel.HIGH
        elif score >= 4.0:
            return SeverityLevel.MEDIUM
        elif score >= 2.0:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFO
    
    def _determine_risk_category(self, score: float, 
                               severity: SeverityLevel) -> RiskCategory:
        """Determine risk category for triage purposes."""
        
        if score >= self.risk_thresholds[RiskCategory.CRITICAL_RISK]:
            return RiskCategory.CRITICAL_RISK
        elif score >= self.risk_thresholds[RiskCategory.HIGH_RISK]:
            return RiskCategory.HIGH_RISK
        elif score >= self.risk_thresholds[RiskCategory.MEDIUM_RISK]:
            return RiskCategory.MEDIUM_RISK
        elif score >= self.risk_thresholds[RiskCategory.LOW_RISK]:
            return RiskCategory.LOW_RISK
        else:
            return RiskCategory.INFORMATIONAL
    
    def _generate_score_explanation(self, metrics: ScoringMetrics, 
                                  final_score: float, 
                                  severity: SeverityLevel) -> str:
        """Generate human-readable explanation of the risk score."""
        
        explanation_parts = []
        
        # Base assessment
        explanation_parts.append(f"Risk score {final_score:.1f}/10 ({severity.name})")
        
        # Impact factors
        if metrics.impact_score >= 8.0:
            explanation_parts.append("High potential impact")
        elif metrics.impact_score >= 6.0:
            explanation_parts.append("Moderate potential impact")
        else:
            explanation_parts.append("Limited potential impact")
        
        # Exploitability factors
        if metrics.exploitability_score >= 8.0:
            explanation_parts.append("easily exploitable")
        elif metrics.exploitability_score >= 6.0:
            explanation_parts.append("moderately exploitable")
        else:
            explanation_parts.append("difficult to exploit")
        
        # Confidence factors
        if metrics.confidence_score >= 0.9:
            explanation_parts.append("high confidence detection")
        elif metrics.confidence_score >= 0.7:
            explanation_parts.append("moderate confidence detection")
        else:
            explanation_parts.append("low confidence detection")
        
        # Context factors
        if metrics.context_score >= 1.8:
            explanation_parts.append("critical environment context")
        elif metrics.context_score >= 1.4:
            explanation_parts.append("elevated environment context")
        
        # Threat intelligence
        if metrics.threat_intel_score >= 1.5:
            explanation_parts.append("active threat intelligence")
        
        return "; ".join(explanation_parts)
    
    def _apply_default_scoring(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Apply default scoring for vulnerabilities that failed comprehensive scoring."""
        
        default_vuln = vuln.copy()
        
        # Use existing severity or default to MEDIUM
        severity_str = vuln.get('severity', 'MEDIUM').upper()
        if severity_str in self.severity_base_scores:
            base_score = self.severity_base_scores[severity_str]
            severity = SeverityLevel[severity_str] if severity_str in SeverityLevel.__members__ else SeverityLevel.MEDIUM
        else:
            base_score = 5.0
            severity = SeverityLevel.MEDIUM
        
        # Apply default confidence adjustment
        confidence = self._normalize_confidence_score(vuln.get('confidence', 0.7))
        adjusted_score = base_score * (0.7 + confidence * 0.3)
        
        risk_category = self._determine_risk_category(adjusted_score, severity)
        
        default_vuln.update({
            'severity': severity.name,
            'risk_score': round(adjusted_score, 2),
            'base_risk_score': round(base_score, 2),
            'risk_category': risk_category.value,
            'risk_level': risk_category.value,
            'confidence': confidence,
            'unified_scoring': {
                'base_score': round(base_score, 2),
                'adjusted_score': round(adjusted_score, 2),
                'explanation': f"Default scoring applied ({severity.name})"
            }
        })
        
        return default_vuln
    
    def _ensure_scoring_consistency(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Ensure consistency across all vulnerability scores."""
        
        consistent_vulns = []
        
        # Group by risk category for validation
        risk_groups = {}
        for vuln in vulnerabilities:
            risk_cat = vuln.get('risk_category', 'Medium Risk')
            if risk_cat not in risk_groups:
                risk_groups[risk_cat] = []
            risk_groups[risk_cat].append(vuln)
        
        # Validate score ranges within categories
        for risk_cat, vulns in risk_groups.items():
            for vuln in vulns:
                score = vuln.get('risk_score', 5.0)
                severity = vuln.get('severity', 'MEDIUM')
                
                # Check for inconsistencies
                expected_category = self._determine_risk_category(score, SeverityLevel[severity])
                if expected_category.value != risk_cat:
                    # Fix inconsistency
                    vuln['risk_category'] = expected_category.value
                    vuln['risk_level'] = expected_category.value
                    self.statistics['consistency_fixes'] += 1
                    logger.debug(f"Fixed risk category inconsistency for '{vuln.get('title', 'Unknown')}'")
                
                consistent_vulns.append(vuln)
        
        return consistent_vulns
    
    def generate_scoring_summary(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive scoring summary that matches detailed findings."""
        
        # Count by severity
        severity_counts = {}
        for severity in SeverityLevel:
            severity_counts[severity.name] = 0
        
        # Count by risk category
        risk_category_counts = {}
        for risk_cat in RiskCategory:
            risk_category_counts[risk_cat.value] = 0
        
        # Calculate statistics
        total_score = 0.0
        confidence_scores = []
        high_confidence_count = 0
        code_level_count = 0
        masvs_tagged_count = 0
        
        for vuln in vulnerabilities:
            # Severity counts
            severity = vuln.get('severity', 'MEDIUM')
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            # Risk category counts
            risk_cat = vuln.get('risk_category', 'Medium Risk')
            if risk_cat in risk_category_counts:
                risk_category_counts[risk_cat] += 1
            
            # Score statistics
            score = vuln.get('risk_score', 5.0)
            total_score += score
            
            confidence = vuln.get('confidence', 0.7)
            confidence_scores.append(confidence)
            if confidence >= 0.9:
                high_confidence_count += 1
            
            # Additional metrics
            if vuln.get('file_path') and vuln.get('line_number', 0) > 0:
                code_level_count += 1
            
            if vuln.get('masvs_controls'):
                masvs_tagged_count += 1
        
        # Calculate overall risk level
        avg_score = total_score / len(vulnerabilities) if vulnerabilities else 0
        avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0
        
        if avg_score >= 8.5:
            overall_risk = "CRITICAL"
        elif avg_score >= 6.5:
            overall_risk = "HIGH"
        elif avg_score >= 4.0:
            overall_risk = "MEDIUM"
        else:
            overall_risk = "LOW"
        
        return {
            'total_vulnerabilities': len(vulnerabilities),
            'severity_breakdown': severity_counts,
            'risk_category_breakdown': risk_category_counts,
            'risk_score': round(avg_score, 2),
            'risk_level': overall_risk,
            'confidence_average': round(avg_confidence, 3),
            'high_confidence_findings': high_confidence_count,
            'code_level_findings': code_level_count,
            'masvs_tagged_findings': masvs_tagged_count,
            'scoring_statistics': self.statistics.copy()
        }

def apply_unified_risk_scoring(vulnerabilities: List[Dict[str, Any]], 
                             context: Dict[str, Any] = None) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Convenience function for applying unified risk scoring."""
    engine = UnifiedRiskScoringEngine()
    scored_vulnerabilities = engine.score_vulnerabilities(vulnerabilities, context)
    summary = engine.generate_scoring_summary(scored_vulnerabilities)
    return scored_vulnerabilities, summary 