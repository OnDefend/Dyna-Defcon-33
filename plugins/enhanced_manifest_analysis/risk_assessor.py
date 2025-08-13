"""
Enhanced Manifest Analysis - Risk Assessor

This module provides comprehensive risk assessment functionality for manifest analysis.
Full implementation with sophisticated risk calculation and recommendation system.
"""

import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from enum import Enum
import math

from .data_structures import (
    ManifestAnalysisResult, ManifestRiskAssessment, RiskLevel, SecurityStatus,
    ManifestAnalysisConfiguration, ManifestSecurityFinding
)

class RiskCategory(Enum):
    """Risk categories for detailed assessment."""
    PERMISSIONS = "permissions"
    COMPONENTS = "components"
    FEATURES = "features"
    CONFIGURATION = "configuration"
    NETWORKING = "networking"
    STORAGE = "storage"

@dataclass
class RiskFactor:
    """Individual risk factor with weight and score."""
    category: RiskCategory
    name: str
    description: str
    weight: float
    score: float
    evidence: str
    impact: str

class ManifestRiskAssessor:
    """Comprehensive manifest risk assessor with advanced analytics."""
    
    def __init__(self, config: Optional[ManifestAnalysisConfiguration] = None):
        """Initialize the risk assessor with configuration."""
        self.config = config or ManifestAnalysisConfiguration()
        self.logger = logging.getLogger(__name__)
        
        # Initialize risk calculation parameters
        self.risk_weights = self._initialize_risk_weights()
        self.severity_scores = self._initialize_severity_scores()
        self.risk_thresholds = self._initialize_risk_thresholds()
        
        # Risk calculation cache
        self._risk_cache = {}
    
    def assess_risk(self, result: ManifestAnalysisResult) -> ManifestRiskAssessment:
        """Perform comprehensive risk assessment on manifest analysis results."""
        try:
            self.logger.info("Starting comprehensive manifest risk assessment")
            
            # Calculate individual risk factors
            risk_factors = self._calculate_risk_factors(result)
            
            # Calculate overall risk score
            risk_score = self._calculate_overall_risk_score(risk_factors)
            
            # Determine risk level
            overall_risk = self._determine_risk_level(risk_score)
            
            # Determine security status
            security_status = self._determine_security_status(overall_risk, risk_factors)
            
            # Generate risk factors summary
            risk_factors_summary = self._generate_risk_factors_summary(risk_factors)
            
            # Generate priority actions
            priority_actions = self._generate_priority_actions(risk_factors, result)
            
            # Generate detailed recommendations
            recommendations = self._generate_recommendations(risk_factors, result)
            
            # Calculate confidence score
            confidence_score = self._calculate_confidence_score(result)
            
            # Generate risk trends
            risk_trends = self._analyze_risk_trends(result)
            
            assessment = ManifestRiskAssessment(
                overall_risk=overall_risk,
                security_status=security_status,
                risk_score=risk_score,
                risk_factors=risk_factors_summary,
                priority_actions=priority_actions
            )
            
            self.logger.info(f"Risk assessment completed: {overall_risk.value} risk level")
            
            return assessment
            
        except Exception as e:
            self.logger.error(f"Risk assessment failed: {e}")
            return ManifestRiskAssessment(
                overall_risk=RiskLevel.MEDIUM,
                security_status=SecurityStatus.NEEDS_ATTENTION,
                risk_score=0.5,
                risk_factors=[f"Assessment error: {str(e)}"],
                priority_actions=["Review manifest analysis for errors"]
            )
    
    def _calculate_risk_factors(self, result: ManifestAnalysisResult) -> List[RiskFactor]:
        """Calculate individual risk factors from analysis result."""
        risk_factors = []
        
        try:
            # Permissions risk factors
            risk_factors.extend(self._assess_permissions_risk(result))
            
            # Components risk factors
            risk_factors.extend(self._assess_components_risk(result))
            
            # Features risk factors
            risk_factors.extend(self._assess_features_risk(result))
            
            # Configuration risk factors
            risk_factors.extend(self._assess_configuration_risk(result))
            
            # Security findings risk factors
            risk_factors.extend(self._assess_findings_risk(result))
            
        except Exception as e:
            self.logger.error(f"Error calculating risk factors: {e}")
        
        return risk_factors
    
    def _assess_permissions_risk(self, result: ManifestAnalysisResult) -> List[RiskFactor]:
        """Assess permissions-related risk factors."""
        risk_factors = []
        
        try:
            if result.permission_analysis:
                perm_analysis = result.permission_analysis
                
                # Dangerous permissions risk
                dangerous_count = len(perm_analysis.dangerous_permissions)
                if dangerous_count > 0:
                    score = min(1.0, dangerous_count / 10.0)  # Normalize to 0-1
                    risk_factors.append(RiskFactor(
                        category=RiskCategory.PERMISSIONS,
                        name="dangerous_permissions",
                        description=f"App requests {dangerous_count} dangerous permissions",
                        weight=0.9,
                        score=score,
                        evidence=f"{dangerous_count} dangerous permissions",
                        impact="High - Can access sensitive user data and device features"
                    ))
                
                # Excessive permissions risk
                total_permissions = len(perm_analysis.requested_permissions)
                if total_permissions > 15:
                    score = min(1.0, (total_permissions - 15) / 20.0)
                    risk_factors.append(RiskFactor(
                        category=RiskCategory.PERMISSIONS,
                        name="excessive_permissions",
                        description=f"App requests {total_permissions} permissions",
                        weight=0.6,
                        score=score,
                        evidence=f"{total_permissions} total permissions",
                        impact="Medium - May indicate over-privileged application"
                    ))
                
                # Custom permissions risk
                custom_count = len(perm_analysis.custom_permissions)
                if custom_count > 0:
                    score = min(1.0, custom_count / 5.0)
                    risk_factors.append(RiskFactor(
                        category=RiskCategory.PERMISSIONS,
                        name="custom_permissions",
                        description=f"App defines {custom_count} custom permissions",
                        weight=0.4,
                        score=score,
                        evidence=f"{custom_count} custom permissions",
                        impact="Low - May expose internal APIs to other apps"
                    ))
                    
        except Exception as e:
            self.logger.error(f"Error assessing permissions risk: {e}")
        
        return risk_factors
    
    def _assess_components_risk(self, result: ManifestAnalysisResult) -> List[RiskFactor]:
        """Assess components-related risk factors."""
        risk_factors = []
        
        try:
            if result.component_analysis:
                comp_analysis = result.component_analysis
                
                # Exported components risk
                exported_count = len(comp_analysis.exported_components)
                if exported_count > 0:
                    score = min(1.0, exported_count / 8.0)
                    risk_factors.append(RiskFactor(
                        category=RiskCategory.COMPONENTS,
                        name="exported_components",
                        description=f"App has {exported_count} exported components",
                        weight=0.8,
                        score=score,
                        evidence=f"{exported_count} exported components",
                        impact="High - Increases attack surface for malicious apps"
                    ))
                
                # Unprotected exported components
                protected_count = len(comp_analysis.protected_components)
                unprotected_exported = exported_count - protected_count
                if unprotected_exported > 0:
                    score = min(1.0, unprotected_exported / 5.0)
                    risk_factors.append(RiskFactor(
                        category=RiskCategory.COMPONENTS,
                        name="unprotected_exported",
                        description=f"{unprotected_exported} exported components lack permission protection",
                        weight=0.9,
                        score=score,
                        evidence=f"{unprotected_exported} unprotected exported components",
                        impact="Critical - Can be accessed by any app without permission"
                    ))
                
                # Content providers risk
                provider_count = len(comp_analysis.providers)
                if provider_count > 0:
                    score = min(1.0, provider_count / 3.0)
                    risk_factors.append(RiskFactor(
                        category=RiskCategory.COMPONENTS,
                        name="content_providers",
                        description=f"App has {provider_count} content providers",
                        weight=0.7,
                        score=score,
                        evidence=f"{provider_count} content providers",
                        impact="Medium - May expose app data to other applications"
                    ))
                    
        except Exception as e:
            self.logger.error(f"Error assessing components risk: {e}")
        
        return risk_factors
    
    def _assess_features_risk(self, result: ManifestAnalysisResult) -> List[RiskFactor]:
        """Assess features-related risk factors."""
        risk_factors = []
        
        try:
            # Check for hardware features that may indicate sensitive functionality
            if hasattr(result, 'features') and result.features:
                sensitive_features = [
                    'android.hardware.camera',
                    'android.hardware.microphone',
                    'android.hardware.location',
                    'android.hardware.telephony',
                    'android.hardware.bluetooth',
                    'android.hardware.nfc'
                ]
                
                sensitive_count = sum(1 for feature in result.features if feature in sensitive_features)
                if sensitive_count > 0:
                    score = min(1.0, sensitive_count / 4.0)
                    risk_factors.append(RiskFactor(
                        category=RiskCategory.FEATURES,
                        name="sensitive_features",
                        description=f"App uses {sensitive_count} sensitive hardware features",
                        weight=0.6,
                        score=score,
                        evidence=f"{sensitive_count} sensitive features",
                        impact="Medium - Access to privacy-sensitive hardware"
                    ))
                    
        except Exception as e:
            self.logger.error(f"Error assessing features risk: {e}")
        
        return risk_factors
    
    def _assess_configuration_risk(self, result: ManifestAnalysisResult) -> List[RiskFactor]:
        """Assess configuration-related risk factors."""
        risk_factors = []
        
        try:
            # Check for debuggable flag
            if hasattr(result, 'debuggable') and result.debuggable:
                risk_factors.append(RiskFactor(
                    category=RiskCategory.CONFIGURATION,
                    name="debuggable",
                    description="App is debuggable in production",
                    weight=0.8,
                    score=1.0,
                    evidence="android:debuggable=\"true\"",
                    impact="High - Allows runtime debugging and code inspection"
                ))
            
            # Check for backup allowance
            if hasattr(result, 'backup_allowed') and result.backup_allowed:
                risk_factors.append(RiskFactor(
                    category=RiskCategory.CONFIGURATION,
                    name="backup_allowed",
                    description="App allows backup of app data",
                    weight=0.6,
                    score=0.7,
                    evidence="android:allowBackup=\"true\"",
                    impact="Medium - App data may be included in device backups"
                ))
            
            # Check for clear text traffic
            if hasattr(result, 'clear_text_traffic') and result.clear_text_traffic:
                risk_factors.append(RiskFactor(
                    category=RiskCategory.NETWORKING,
                    name="clear_text_traffic",
                    description="App allows clear text network traffic",
                    weight=0.7,
                    score=0.8,
                    evidence="android:usesCleartextTraffic=\"true\"",
                    impact="Medium - Network traffic may be intercepted"
                ))
                
        except Exception as e:
            self.logger.error(f"Error assessing configuration risk: {e}")
        
        return risk_factors
    
    def _assess_findings_risk(self, result: ManifestAnalysisResult) -> List[RiskFactor]:
        """Assess risk based on security findings."""
        risk_factors = []
        
        try:
            if result.security_findings:
                # Group findings by severity
                severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
                
                for finding in result.security_findings:
                    severity = finding.severity.value
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                
                # Calculate risk for each severity level
                for severity, count in severity_counts.items():
                    if count > 0:
                        severity_score = self.severity_scores.get(severity, 0.5)
                        score = min(1.0, count * severity_score / 10.0)
                        
                        risk_factors.append(RiskFactor(
                            category=RiskCategory.CONFIGURATION,
                            name=f"{severity.lower()}_findings",
                            description=f"{count} {severity.lower()} security findings",
                            weight=severity_score,
                            score=score,
                            evidence=f"{count} {severity} findings",
                            impact=f"{severity.capitalize()} - Multiple security issues detected"
                        ))
                        
        except Exception as e:
            self.logger.error(f"Error assessing findings risk: {e}")
        
        return risk_factors
    
    def _calculate_overall_risk_score(self, risk_factors: List[RiskFactor]) -> float:
        """Calculate overall risk score from individual risk factors."""
        try:
            if not risk_factors:
                return 0.0
            
            # Calculate weighted average
            total_weighted_score = 0.0
            total_weight = 0.0
            
            for factor in risk_factors:
                weighted_score = factor.score * factor.weight
                total_weighted_score += weighted_score
                total_weight += factor.weight
            
            if total_weight == 0:
                return 0.0
            
            base_score = total_weighted_score / total_weight
            
            # Apply risk amplification for multiple high-risk factors
            high_risk_count = sum(1 for factor in risk_factors if factor.score > 0.7)
            amplification_factor = 1.0 + (high_risk_count * 0.1)
            
            final_score = min(1.0, base_score * amplification_factor)
            
            return final_score
            
        except Exception as e:
            self.logger.error(f"Error calculating overall risk score: {e}")
            return 0.5
    
    def _determine_risk_level(self, risk_score: float) -> RiskLevel:
        """Determine risk level from risk score."""
        if risk_score >= self.risk_thresholds['critical']:
            return RiskLevel.CRITICAL
        elif risk_score >= self.risk_thresholds['high']:
            return RiskLevel.HIGH
        elif risk_score >= self.risk_thresholds['medium']:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _determine_security_status(self, risk_level: RiskLevel, risk_factors: List[RiskFactor]) -> SecurityStatus:
        """Determine security status based on risk level and factors."""
        if risk_level == RiskLevel.CRITICAL:
            return SecurityStatus.HIGH_RISK
        elif risk_level == RiskLevel.HIGH:
            return SecurityStatus.NEEDS_ATTENTION
        elif risk_level == RiskLevel.MEDIUM:
            # Check for specific critical factors
            critical_factors = [f for f in risk_factors if f.score > 0.8 and f.weight > 0.8]
            if critical_factors:
                return SecurityStatus.NEEDS_ATTENTION
            else:
                return SecurityStatus.SECURE
        else:
            return SecurityStatus.SECURE
    
    def _generate_risk_factors_summary(self, risk_factors: List[RiskFactor]) -> List[str]:
        """Generate human-readable risk factors summary."""
        summary = []
        
        try:
            # Group by category
            category_factors = {}
            for factor in risk_factors:
                category = factor.category.value
                if category not in category_factors:
                    category_factors[category] = []
                category_factors[category].append(factor)
            
            # Generate summary for each category
            for category, factors in category_factors.items():
                high_risk_factors = [f for f in factors if f.score > 0.6]
                if high_risk_factors:
                    factor_descriptions = [f.description for f in high_risk_factors]
                    summary.append(f"{category.capitalize()}: {', '.join(factor_descriptions)}")
                    
        except Exception as e:
            self.logger.error(f"Error generating risk factors summary: {e}")
            summary.append("Error generating risk summary")
        
        return summary
    
    def _generate_priority_actions(self, risk_factors: List[RiskFactor], result: ManifestAnalysisResult) -> List[str]:
        """Generate priority actions based on risk factors."""
        actions = []
        
        try:
            # Sort risk factors by impact (weight * score)
            sorted_factors = sorted(risk_factors, key=lambda f: f.weight * f.score, reverse=True)
            
            # Generate actions for top risk factors
            for factor in sorted_factors[:5]:  # Top 5 factors
                if factor.score > 0.6:  # Only significant risks
                    action = self._generate_action_for_factor(factor)
                    if action:
                        actions.append(action)
            
            # Add general actions based on findings
            if result.security_findings:
                critical_findings = [f for f in result.security_findings if f.severity == 'CRITICAL']
                if critical_findings:
                    actions.append("Address critical security findings immediately")
                
                high_findings = [f for f in result.security_findings if f.severity == 'HIGH']
                if high_findings:
                    actions.append("Review and fix high-severity security issues")
                    
        except Exception as e:
            self.logger.error(f"Error generating priority actions: {e}")
            actions.append("Review security analysis for issues")
        
        return actions[:10]  # Limit to top 10 actions
    
    def _generate_action_for_factor(self, factor: RiskFactor) -> str:
        """Generate specific action for a risk factor."""
        action_map = {
            'dangerous_permissions': "Review and minimize dangerous permissions",
            'excessive_permissions': "Reduce the number of requested permissions",
            'unprotected_exported': "Add permission protection to exported components",
            'exported_components': "Review necessity of exported components",
            'debuggable': "Disable debugging in production builds",
            'backup_allowed': "Disable backup or implement secure backup",
            'clear_text_traffic': "Enforce HTTPS for all network communication",
            'content_providers': "Review content provider security and access controls",
            'critical_findings': "Address critical security vulnerabilities immediately"
        }
        
        return action_map.get(factor.name, f"Address {factor.name} risk factor")
    
    def _generate_recommendations(self, risk_factors: List[RiskFactor], result: ManifestAnalysisResult) -> List[str]:
        """Generate detailed recommendations."""
        recommendations = []
        
        try:
            # Category-specific recommendations
            category_risks = {}
            for factor in risk_factors:
                category = factor.category.value
                if category not in category_risks:
                    category_risks[category] = []
                category_risks[category].append(factor)
            
            # Generate recommendations by category
            for category, factors in category_risks.items():
                high_risk_factors = [f for f in factors if f.score > 0.5]
                if high_risk_factors:
                    recommendations.extend(self._get_category_recommendations(category, high_risk_factors))
            
            # Add general security recommendations
            recommendations.extend(self._get_general_recommendations(result))
            
        except Exception as e:
            self.logger.error(f"Error generating recommendations: {e}")
            recommendations.append("Conduct comprehensive security review")
        
        return recommendations[:15]  # Limit to top 15 recommendations
    
    def _get_category_recommendations(self, category: str, factors: List[RiskFactor]) -> List[str]:
        """Get recommendations for a specific category."""
        recommendations = []
        
        category_recs = {
            'permissions': [
                "Follow principle of least privilege for permissions",
                "Use runtime permissions for sensitive operations",
                "Document permission usage for user transparency",
                "Consider permission alternatives where possible"
            ],
            'components': [
                "Minimize exported components to reduce attack surface",
                "Use signature-level permissions for internal components",
                "Implement proper input validation for exported components",
                "Consider using explicit intents where possible"
            ],
            'configuration': [
                "Use secure default configurations",
                "Implement proper certificate pinning",
                "Enable network security configuration",
                "Use secure coding practices"
            ],
            'networking': [
                "Implement certificate pinning",
                "Use secure communication protocols",
                "Validate all network inputs",
                "Implement proper error handling"
            ]
        }
        
        return category_recs.get(category, [])[:3]  # Top 3 per category
    
    def _get_general_recommendations(self, result: ManifestAnalysisResult) -> List[str]:
        """Get general security recommendations."""
        recommendations = [
            "Conduct regular security assessments",
            "Implement proper logging and monitoring",
            "Use static analysis tools in development pipeline",
            "Follow OWASP Mobile Security Guidelines",
            "Implement proper session management",
            "Use secure storage for sensitive data"
        ]
        
        return recommendations[:3]  # Top 3 general recommendations
    
    def _calculate_confidence_score(self, result: ManifestAnalysisResult) -> float:
        """Calculate confidence score for the assessment."""
        try:
            confidence_factors = []
            
            # Check completeness of analysis
            if result.permission_analysis:
                confidence_factors.append(0.3)
            if result.component_analysis:
                confidence_factors.append(0.3)
            if result.security_findings:
                confidence_factors.append(0.2)
            
            # Check quality of findings
            if result.security_findings:
                high_confidence_findings = [f for f in result.security_findings if f.confidence > 0.8]
                confidence_factors.append(len(high_confidence_findings) / len(result.security_findings) * 0.2)
            
            return sum(confidence_factors) if confidence_factors else 0.5
            
        except Exception as e:
            self.logger.error(f"Error calculating confidence score: {e}")
            return 0.5
    
    def _analyze_risk_trends(self, result: ManifestAnalysisResult) -> Dict[str, Any]:
        """Analyze risk trends (placeholder for future implementation)."""
        return {
            'trend_direction': 'stable',
            'risk_velocity': 0.0,
            'improvement_areas': [],
            'degradation_areas': []
        }
    
    def _generate_assessment_metadata(self, result: ManifestAnalysisResult) -> Dict[str, Any]:
        """Generate assessment metadata."""
        return {
            'assessment_timestamp': self._get_timestamp(),
            'analysis_completeness': self._calculate_completeness(result),
            'methodology_version': '1.0.0',
            'risk_model_version': '1.0.0'
        }
    
    def _get_timestamp(self) -> str:
        """Get current timestamp."""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def _calculate_completeness(self, result: ManifestAnalysisResult) -> float:
        """Calculate analysis completeness."""
        try:
            completeness_factors = []
            
            if result.permission_analysis:
                completeness_factors.append(0.4)
            if result.component_analysis:
                completeness_factors.append(0.4)
            if result.security_findings:
                completeness_factors.append(0.2)
            
            return sum(completeness_factors)
            
        except Exception as e:
            self.logger.error(f"Error calculating completeness: {e}")
            return 0.5
    
    def _initialize_risk_weights(self) -> Dict[str, float]:
        """Initialize risk calculation weights."""
        return {
            'permissions': 0.3,
            'components': 0.3,
            'configuration': 0.2,
            'findings': 0.2
        }
    
    def _initialize_severity_scores(self) -> Dict[str, float]:
        """Initialize severity scoring."""
        return {
            'CRITICAL': 1.0,
            'HIGH': 0.8,
            'MEDIUM': 0.6,
            'LOW': 0.4
        }
    
    def _initialize_risk_thresholds(self) -> Dict[str, float]:
        """Initialize risk level thresholds."""
        return {
            'critical': 0.8,
            'high': 0.6,
            'medium': 0.4,
            'low': 0.0
        } 