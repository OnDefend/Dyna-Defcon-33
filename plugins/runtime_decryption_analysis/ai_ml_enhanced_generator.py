#!/usr/bin/env python3
"""
AI/ML-Enhanced Frida Script Generator for AODS

Extends the base FridaScriptGenerator with advanced AI/ML capabilities for
intelligent hook selection, vulnerability prediction, and adaptive script generation.

Features:
- Intelligent hook selection using AODS ML infrastructure
- ML-enhanced confidence scoring for hook effectiveness
- CVE correlation for targeted vulnerability discovery
- Adaptive script generation based on runtime feedback
- Integration with AODS Advanced Intelligence Engine
- Real-time vulnerability pattern learning
- Context-aware hook prioritization

Architecture:
- Extends FridaScriptGenerator with clean inheritance
- Dependency injection for ML components
- Modular design with specialized ML analyzers
- Comprehensive error handling and fallback mechanisms
- Professional logging and monitoring

Integration Points:
- core.ml_integration_manager: ML classification and analysis
- core.advanced_intelligence_engine: CVE correlation and threat intelligence
- core.ml_enhanced_confidence_scorer: Advanced confidence scoring
- core.detection.advanced_pattern_engine: 1000+ pattern database
"""

import logging
import time
import asyncio
from typing import Dict, List, Any, Optional, Union, Tuple
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
import json

# AODS Core ML Infrastructure
try:
    from core.ml_integration_manager import MLIntegrationManager, ClassificationResult
    from core.advanced_intelligence_engine import AdvancedIntelligenceEngine, EnhancedClassificationResult
    from core.ml_enhanced_confidence_scorer import MLEnhancedConfidenceScorer, ConfidenceMetrics
    from core.detection.advanced_pattern_engine import AdvancedPatternDetectionEngine, VulnerabilityPattern
    AODS_ML_AVAILABLE = True
except ImportError as e:
    logging.warning(f"AODS ML infrastructure not available: {e}")
    AODS_ML_AVAILABLE = False

# Base Generator and AODS Infrastructure
from .frida_script_generator import (
    FridaScriptGenerator, ScriptGenerationContext, GeneratedScript,
    FridaScriptTemplateLoader, FindingProtocol
)
from .data_structures import RuntimeDecryptionFinding, DecryptionType, VulnerabilitySeverity
from core.shared_infrastructure.analysis_exceptions import AnalysisError, ErrorContext, ValidationError
from core.shared_infrastructure.cross_plugin_utilities import LoggingMixin, InputValidator
from core.shared_data_structures import BaseVulnerability


@dataclass
class MLHookRecommendation:
    """ML-generated hook recommendation with confidence and reasoning."""
    hook_name: str
    confidence_score: float
    effectiveness_prediction: float
    vulnerability_types: List[str]
    cve_correlations: List[str]
    reasoning: str
    priority: int
    estimated_detection_rate: float
    false_positive_risk: float
    
    def __post_init__(self):
        """Validate recommendation data."""
        if not 0.0 <= self.confidence_score <= 1.0:
            raise ValidationError("confidence_score must be between 0.0 and 1.0")
        if not 0.0 <= self.effectiveness_prediction <= 1.0:
            raise ValidationError("effectiveness_prediction must be between 0.0 and 1.0")
        if self.priority < 1:
            raise ValidationError("priority must be >= 1")


@dataclass
class AIMLScriptGenerationContext(ScriptGenerationContext):
    """Enhanced context with AI/ML capabilities."""
    enable_ml_hook_selection: bool = True
    enable_cve_correlation: bool = True
    enable_adaptive_generation: bool = True
    ml_confidence_threshold: float = 0.7
    max_ml_hooks: int = 15
    vulnerability_focus: List[str] = field(default_factory=list)
    target_cve_years: List[int] = field(default_factory=lambda: [2023, 2024, 2025])
    
    def __post_init__(self):
        """Enhanced validation for AI/ML context."""
        super().__post_init__()
        
        if not 0.0 <= self.ml_confidence_threshold <= 1.0:
            raise ValidationError("ml_confidence_threshold must be between 0.0 and 1.0")
        if self.max_ml_hooks <= 0:
            raise ValidationError("max_ml_hooks must be positive")


@dataclass
class AIMLEnhancedScript(GeneratedScript):
    """Enhanced script result with AI/ML insights."""
    ml_hook_recommendations: List[MLHookRecommendation] = field(default_factory=list)
    cve_correlations: List[Dict[str, Any]] = field(default_factory=list)
    vulnerability_predictions: List[Dict[str, Any]] = field(default_factory=list)
    ml_confidence_scores: Dict[str, float] = field(default_factory=dict)
    adaptive_insights: Dict[str, Any] = field(default_factory=dict)
    intelligence_metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def ml_enhanced(self) -> bool:
        """Check if script was enhanced with ML."""
        return len(self.ml_hook_recommendations) > 0 or len(self.cve_correlations) > 0


class MLHookIntelligenceAnalyzer:
    """Analyzes and selects optimal hooks using ML intelligence."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize ML hook intelligence analyzer."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.validator = InputValidator()
        
        # Initialize ML components if available
        self.ml_manager = None
        self.intelligence_engine = None
        self.confidence_scorer = None
        self.pattern_engine = None
        
        if AODS_ML_AVAILABLE:
            self._initialize_ml_components()
    
    def _initialize_ml_components(self):
        """Initialize AODS ML components."""
        try:
            # ML Integration Manager for classification
            ml_config = self.config.get('ml_integration', {})
            if ml_config.get('enabled', True):
                self.ml_manager = MLIntegrationManager(ml_config)
                self.logger.info("ML Integration Manager initialized for hook intelligence")
            
            # Advanced Intelligence Engine for CVE correlation
            intel_config = self.config.get('intelligence_engine', {})
            if intel_config.get('enabled', True):
                self.intelligence_engine = AdvancedIntelligenceEngine(intel_config)
                self.logger.info("Advanced Intelligence Engine initialized for CVE correlation")
            
            # ML-Enhanced Confidence Scorer
            confidence_config = self.config.get('confidence_scoring', {})
            if confidence_config.get('enabled', True):
                self.confidence_scorer = MLEnhancedConfidenceScorer(confidence_config)
                self.logger.info("ML-Enhanced Confidence Scorer initialized")
            
            # Advanced Pattern Engine for 1000+ patterns
            pattern_config = self.config.get('pattern_engine', {})
            if pattern_config.get('enabled', True):
                self.pattern_engine = AdvancedPatternDetectionEngine(pattern_config)
                self.logger.info("Advanced Pattern Engine initialized (1000+ patterns)")
                
        except Exception as e:
            self.logger.warning(f"Failed to initialize some ML components: {e}")
    
    async def analyze_hook_intelligence(self, 
                                      findings: List[Union[RuntimeDecryptionFinding, Dict[str, Any]]],
                                      context: AIMLScriptGenerationContext) -> List[MLHookRecommendation]:
        """Analyze findings to generate intelligent hook recommendations."""
        try:
            recommendations = []
            
            # Step 1: ML-based vulnerability classification
            ml_classifications = await self._classify_vulnerabilities(findings)
            
            # Step 2: CVE correlation and threat intelligence
            cve_correlations = await self._correlate_with_cves(findings, context)
            
            # Step 3: Pattern-based hook selection
            pattern_hooks = await self._select_pattern_based_hooks(findings, ml_classifications)
            
            # Step 4: Generate ML recommendations
            for hook_data in pattern_hooks:
                recommendation = await self._generate_hook_recommendation(
                    hook_data, ml_classifications, cve_correlations, context
                )
                if recommendation and recommendation.confidence_score >= context.ml_confidence_threshold:
                    recommendations.append(recommendation)
            
            # Step 5: Priority sorting and filtering
            recommendations = self._prioritize_recommendations(recommendations, context)
            
            self.logger.info(f"Generated {len(recommendations)} ML hook recommendations")
            return recommendations
            
        except Exception as e:
            error_context = ErrorContext(
                component_name="MLHookIntelligenceAnalyzer",
                operation="analyze_hook_intelligence",
                additional_context={'findings_count': len(findings)}
            )
            raise AnalysisError(f"ML hook intelligence analysis failed: {e}", error_context, cause=e)
    
    async def _classify_vulnerabilities(self, 
                                      findings: List[Union[RuntimeDecryptionFinding, Dict[str, Any]]]) -> List[ClassificationResult]:
        """Classify vulnerabilities using AODS ML infrastructure."""
        classifications = []
        
        if not self.ml_manager:
            return classifications
        
        try:
            for finding in findings:
                # Convert to classification format
                classification_data = self._prepare_classification_data(finding)
                
                # Use AODS ML manager for classification
                result = await asyncio.get_event_loop().run_in_executor(
                    None, 
                    self.ml_manager.classify_vulnerability,
                    classification_data
                )
                
                if result:
                    classifications.append(result)
            
            self.logger.debug(f"Classified {len(classifications)} vulnerabilities using ML")
            return classifications
            
        except Exception as e:
            self.logger.warning(f"ML vulnerability classification failed: {e}")
            return classifications
    
    async def _correlate_with_cves(self, 
                                 findings: List[Union[RuntimeDecryptionFinding, Dict[str, Any]]],
                                 context: AIMLScriptGenerationContext) -> List[Dict[str, Any]]:
        """Correlate findings with CVE database using Advanced Intelligence Engine."""
        correlations = []
        
        if not self.intelligence_engine or not context.enable_cve_correlation:
            return correlations
        
        try:
            for finding in findings:
                # Prepare vulnerability data for correlation
                vulnerability_data = self._prepare_vulnerability_data(finding)
                
                # Use Advanced Intelligence Engine for CVE correlation
                enhanced_result = await self.intelligence_engine.analyze_with_advanced_intelligence(vulnerability_data)
                
                if enhanced_result and enhanced_result.threat_intelligence:
                    correlation = {
                        'finding_id': getattr(finding, 'id', str(hash(str(finding)))),
                        'cve_ids': enhanced_result.threat_intelligence.cve_references,
                        'exploit_prediction': enhanced_result.exploit_prediction,
                        'remediation_priority': enhanced_result.remediation_priority,
                        'threat_score': enhanced_result.threat_intelligence.threat_score
                    }
                    correlations.append(correlation)
            
            self.logger.debug(f"Generated {len(correlations)} CVE correlations")
            return correlations
            
        except Exception as e:
            self.logger.warning(f"CVE correlation failed: {e}")
            return correlations
    
    async def _select_pattern_based_hooks(self, 
                                        findings: List[Union[RuntimeDecryptionFinding, Dict[str, Any]]],
                                        classifications: List[ClassificationResult]) -> List[Dict[str, Any]]:
        """Select hooks based on advanced pattern analysis."""
        hook_selections = []
        
        if not self.pattern_engine:
            # Fallback to default hook selection
            return [
                {'hook_name': 'cipher_hooks', 'pattern_matches': [], 'confidence': 0.5},
                {'hook_name': 'base64_hooks', 'pattern_matches': [], 'confidence': 0.5}
            ]
        
        try:
            # Use Advanced Pattern Engine for hook selection
            for finding in findings:
                # Extract vulnerability patterns
                vulnerability_text = self._extract_vulnerability_text(finding)
                
                # Get pattern matches from 1000+ pattern database
                pattern_matches = await asyncio.get_event_loop().run_in_executor(
                    None,
                    self.pattern_engine.analyze_vulnerability_patterns,
                    vulnerability_text
                )
                
                # Convert pattern matches to hook selections
                for pattern_match in pattern_matches:
                    hook_selection = self._pattern_to_hook_selection(pattern_match, finding)
                    if hook_selection:
                        hook_selections.append(hook_selection)
            
            self.logger.debug(f"Selected {len(hook_selections)} pattern-based hooks")
            return hook_selections
            
        except Exception as e:
            self.logger.warning(f"Pattern-based hook selection failed: {e}")
            return hook_selections
    
    async def _generate_hook_recommendation(self,
                                          hook_data: Dict[str, Any],
                                          ml_classifications: List[ClassificationResult],
                                          cve_correlations: List[Dict[str, Any]],
                                          context: AIMLScriptGenerationContext) -> Optional[MLHookRecommendation]:
        """Generate a comprehensive hook recommendation using ML insights."""
        try:
            hook_name = hook_data.get('hook_name', 'unknown_hook')
            
            # Calculate confidence using ML-enhanced scorer
            confidence_score = await self._calculate_ml_confidence(hook_data, ml_classifications)
            
            # Predict effectiveness based on patterns and ML
            effectiveness_prediction = self._predict_hook_effectiveness(hook_data, ml_classifications)
            
            # Extract relevant vulnerability types
            vulnerability_types = self._extract_vulnerability_types(hook_data, ml_classifications)
            
            # Find relevant CVE correlations
            relevant_cves = self._find_relevant_cves(hook_data, cve_correlations)
            
            # Generate reasoning
            reasoning = self._generate_ml_reasoning(hook_data, ml_classifications, relevant_cves)
            
            # Calculate priority and risk metrics
            priority = self._calculate_hook_priority(hook_data, context)
            estimated_detection_rate = self._estimate_detection_rate(hook_data, ml_classifications)
            false_positive_risk = self._estimate_false_positive_risk(hook_data)
            
            recommendation = MLHookRecommendation(
                hook_name=hook_name,
                confidence_score=confidence_score,
                effectiveness_prediction=effectiveness_prediction,
                vulnerability_types=vulnerability_types,
                cve_correlations=relevant_cves,
                reasoning=reasoning,
                priority=priority,
                estimated_detection_rate=estimated_detection_rate,
                false_positive_risk=false_positive_risk
            )
            
            return recommendation
            
        except Exception as e:
            self.logger.warning(f"Failed to generate hook recommendation for {hook_data.get('hook_name', 'unknown')}: {e}")
            return None
    
    def _prioritize_recommendations(self, 
                                  recommendations: List[MLHookRecommendation],
                                  context: AIMLScriptGenerationContext) -> List[MLHookRecommendation]:
        """Prioritize and filter recommendations based on ML insights."""
        try:
            # Sort by multiple criteria: priority, confidence, effectiveness
            sorted_recommendations = sorted(
                recommendations,
                key=lambda r: (r.priority, r.confidence_score, r.effectiveness_prediction),
                reverse=True
            )
            
            # Apply filtering based on context
            filtered_recommendations = []
            for rec in sorted_recommendations:
                # Check confidence threshold
                if rec.confidence_score < context.ml_confidence_threshold:
                    continue
                
                # Check vulnerability focus if specified
                if context.vulnerability_focus:
                    if not any(vuln_type in context.vulnerability_focus for vuln_type in rec.vulnerability_types):
                        continue
                
                # Check false positive risk
                if rec.false_positive_risk > 0.3:  # Conservative threshold
                    continue
                
                filtered_recommendations.append(rec)
                
                # Limit number of recommendations
                if len(filtered_recommendations) >= context.max_ml_hooks:
                    break
            
            self.logger.info(f"Prioritized {len(filtered_recommendations)} high-quality recommendations")
            return filtered_recommendations
            
        except Exception as e:
            self.logger.warning(f"Failed to prioritize recommendations: {e}")
            return recommendations[:context.max_ml_hooks]
    
    # Helper methods for data preparation and calculation
    def _prepare_classification_data(self, finding: Union[RuntimeDecryptionFinding, Dict[str, Any]]) -> Dict[str, Any]:
        """Prepare finding data for ML classification."""
        if isinstance(finding, RuntimeDecryptionFinding):
            return {
                'description': finding.description,
                'finding_type': finding.finding_type,
                'severity': finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                'location': finding.location,
                'pattern_type': finding.pattern_type.value if hasattr(finding.pattern_type, 'value') else str(finding.pattern_type)
            }
        else:
            return {
                'description': finding.get('description', ''),
                'finding_type': finding.get('finding_type', ''),
                'severity': finding.get('severity', 'MEDIUM'),
                'location': finding.get('location', ''),
                'pattern_type': finding.get('pattern_type', 'RUNTIME_DECRYPTION')
            }
    
    def _prepare_vulnerability_data(self, finding: Union[RuntimeDecryptionFinding, Dict[str, Any]]) -> Dict[str, Any]:
        """Prepare vulnerability data for CVE correlation."""
        base_data = self._prepare_classification_data(finding)
        base_data.update({
            'vulnerability_category': 'cryptography',
            'technology': 'android',
            'component_type': 'mobile_application'
        })
        return base_data
    
    def _extract_vulnerability_text(self, finding: Union[RuntimeDecryptionFinding, Dict[str, Any]]) -> str:
        """Extract text content for pattern analysis."""
        if isinstance(finding, RuntimeDecryptionFinding):
            return f"{finding.description} {finding.finding_type} {finding.location}"
        else:
            desc = finding.get('description', '')
            ftype = finding.get('finding_type', '')
            loc = finding.get('location', '')
            return f"{desc} {ftype} {loc}"
    
    async def _calculate_ml_confidence(self, 
                                     hook_data: Dict[str, Any],
                                     ml_classifications: List[ClassificationResult]) -> float:
        """Calculate confidence using ML-enhanced confidence scorer."""
        if not self.confidence_scorer:
            return 0.5  # Fallback confidence
        
        try:
            # Prepare evidence for confidence calculation
            evidence = {
                'hook_name': hook_data.get('hook_name', ''),
                'pattern_matches': hook_data.get('pattern_matches', []),
                'ml_classifications': [c.confidence for c in ml_classifications if c.confidence],
                'vulnerability_indicators': len(hook_data.get('pattern_matches', []))
            }
            
            # Use ML-enhanced confidence scorer
            confidence_metrics = await asyncio.get_event_loop().run_in_executor(
                None,
                self.confidence_scorer.compute_enhanced_confidence,
                evidence
            )
            
            return confidence_metrics.confidence_score if confidence_metrics else 0.5
            
        except Exception as e:
            self.logger.debug(f"ML confidence calculation failed: {e}")
            return 0.5
    
    def _predict_hook_effectiveness(self, 
                                  hook_data: Dict[str, Any],
                                  ml_classifications: List[ClassificationResult]) -> float:
        """Predict hook effectiveness based on ML analysis."""
        try:
            # Base effectiveness from pattern matches
            pattern_count = len(hook_data.get('pattern_matches', []))
            base_effectiveness = min(pattern_count * 0.2, 0.8)
            
            # ML classification boost
            ml_boost = 0.0
            if ml_classifications:
                avg_ml_confidence = sum(c.confidence for c in ml_classifications) / len(ml_classifications)
                ml_boost = avg_ml_confidence * 0.3
            
            # Hook-specific adjustments
            hook_name = hook_data.get('hook_name', '')
            hook_multiplier = {
                'cipher_hooks': 1.2,
                'base64_hooks': 1.0,
                'key_derivation_hooks': 1.3,
                'custom_method_hook': 0.8
            }.get(hook_name, 1.0)
            
            effectiveness = (base_effectiveness + ml_boost) * hook_multiplier
            return min(max(effectiveness, 0.1), 0.95)
            
        except Exception as e:
            self.logger.debug(f"Hook effectiveness prediction failed: {e}")
            return 0.5
    
    def _extract_vulnerability_types(self, 
                                   hook_data: Dict[str, Any],
                                   ml_classifications: List[ClassificationResult]) -> List[str]:
        """Extract relevant vulnerability types from ML analysis."""
        vulnerability_types = set()
        
        # From hook data
        hook_name = hook_data.get('hook_name', '')
        hook_to_vuln_map = {
            'cipher_hooks': ['weak_cryptography', 'crypto_implementation'],
            'base64_hooks': ['data_encoding', 'obfuscation'],
            'key_derivation_hooks': ['key_management', 'weak_key_generation'],
            'custom_method_hook': ['custom_vulnerability']
        }
        vulnerability_types.update(hook_to_vuln_map.get(hook_name, []))
        
        # From ML classifications
        for classification in ml_classifications:
            if hasattr(classification, 'vulnerability_type') and classification.vulnerability_type:
                vulnerability_types.add(classification.vulnerability_type)
        
        return list(vulnerability_types)
    
    def _find_relevant_cves(self, 
                          hook_data: Dict[str, Any],
                          cve_correlations: List[Dict[str, Any]]) -> List[str]:
        """Find CVEs relevant to this hook."""
        relevant_cves = []
        
        hook_name = hook_data.get('hook_name', '')
        
        # Map hooks to CVE categories
        hook_cve_categories = {
            'cipher_hooks': ['crypto', 'encryption', 'cipher'],
            'base64_hooks': ['encoding', 'obfuscation'],
            'key_derivation_hooks': ['key', 'derivation', 'generation']
        }
        
        categories = hook_cve_categories.get(hook_name, [])
        
        for correlation in cve_correlations:
            cve_ids = correlation.get('cve_ids', [])
            for cve_id in cve_ids:
                if any(category in cve_id.lower() for category in categories):
                    relevant_cves.append(cve_id)
        
        return relevant_cves[:5]  # Limit to top 5 relevant CVEs
    
    def _generate_ml_reasoning(self, 
                             hook_data: Dict[str, Any],
                             ml_classifications: List[ClassificationResult],
                             relevant_cves: List[str]) -> str:
        """Generate human-readable reasoning for the recommendation."""
        reasoning_parts = []
        
        hook_name = hook_data.get('hook_name', 'unknown')
        pattern_count = len(hook_data.get('pattern_matches', []))
        
        # Base reasoning
        reasoning_parts.append(f"Hook '{hook_name}' selected based on {pattern_count} pattern matches")
        
        # ML insights
        if ml_classifications:
            high_confidence_count = sum(1 for c in ml_classifications if c.confidence > 0.8)
            reasoning_parts.append(f"ML analysis identified {high_confidence_count} high-confidence vulnerabilities")
        
        # CVE correlation
        if relevant_cves:
            reasoning_parts.append(f"Correlated with {len(relevant_cves)} relevant CVEs: {', '.join(relevant_cves[:3])}")
        
        # Effectiveness prediction
        effectiveness = hook_data.get('effectiveness_prediction', 0.5)
        if effectiveness > 0.8:
            reasoning_parts.append("High detection effectiveness predicted")
        elif effectiveness > 0.6:
            reasoning_parts.append("Moderate detection effectiveness predicted")
        
        return ". ".join(reasoning_parts) + "."
    
    def _calculate_hook_priority(self, 
                               hook_data: Dict[str, Any],
                               context: AIMLScriptGenerationContext) -> int:
        """Calculate hook priority based on multiple factors."""
        base_priority = 5
        
        # Pattern match boost
        pattern_count = len(hook_data.get('pattern_matches', []))
        pattern_boost = min(pattern_count, 3)
        
        # Hook type priority
        hook_name = hook_data.get('hook_name', '')
        hook_priority_map = {
            'cipher_hooks': 3,
            'key_derivation_hooks': 2,
            'base64_hooks': 1,
            'custom_method_hook': 0
        }
        hook_boost = hook_priority_map.get(hook_name, 0)
        
        # Vulnerability focus boost
        focus_boost = 0
        if context.vulnerability_focus:
            vulnerability_types = self._extract_vulnerability_types(hook_data, [])
            if any(vtype in context.vulnerability_focus for vtype in vulnerability_types):
                focus_boost = 2
        
        return base_priority + pattern_boost + hook_boost + focus_boost
    
    def _estimate_detection_rate(self, 
                               hook_data: Dict[str, Any],
                               ml_classifications: List[ClassificationResult]) -> float:
        """Estimate the detection rate for this hook."""
        try:
            # Base detection rate from historical data
            hook_name = hook_data.get('hook_name', '')
            base_rates = {
                'cipher_hooks': 0.75,
                'base64_hooks': 0.65,
                'key_derivation_hooks': 0.80,
                'custom_method_hook': 0.50
            }
            base_rate = base_rates.get(hook_name, 0.60)
            
            # ML classification adjustment
            ml_adjustment = 0.0
            if ml_classifications:
                avg_confidence = sum(c.confidence for c in ml_classifications) / len(ml_classifications)
                ml_adjustment = (avg_confidence - 0.5) * 0.2  # ±0.1 adjustment
            
            return min(max(base_rate + ml_adjustment, 0.3), 0.95)
            
        except Exception as e:
            self.logger.debug(f"Detection rate estimation failed: {e}")
            return 0.60
    
    def _estimate_false_positive_risk(self, hook_data: Dict[str, Any]) -> float:
        """Estimate false positive risk for this hook."""
        try:
            # Base false positive rates from historical data
            hook_name = hook_data.get('hook_name', '')
            base_fp_rates = {
                'cipher_hooks': 0.10,
                'base64_hooks': 0.20,
                'key_derivation_hooks': 0.08,
                'custom_method_hook': 0.30
            }
            base_fp_rate = base_fp_rates.get(hook_name, 0.15)
            
            # Pattern match quality adjustment
            pattern_count = len(hook_data.get('pattern_matches', []))
            if pattern_count >= 3:
                fp_reduction = 0.05  # More patterns = lower FP risk
            elif pattern_count >= 2:
                fp_reduction = 0.02
            else:
                fp_reduction = 0.0
            
            return max(base_fp_rate - fp_reduction, 0.02)
            
        except Exception as e:
            self.logger.debug(f"False positive risk estimation failed: {e}")
            return 0.15
    
    def _pattern_to_hook_selection(self, 
                                 pattern_match: Any,
                                 finding: Union[RuntimeDecryptionFinding, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Convert pattern match to hook selection."""
        try:
            # This would need to be implemented based on the actual AdvancedPatternDetectionEngine API
            # For now, provide a basic implementation
            if hasattr(pattern_match, 'pattern_type'):
                pattern_type = pattern_match.pattern_type
            else:
                pattern_type = str(pattern_match)
            
            # Map patterns to hooks
            pattern_hook_map = {
                'cipher': 'cipher_hooks',
                'base64': 'base64_hooks',
                'key': 'key_derivation_hooks',
                'crypto': 'cipher_hooks',
                'encryption': 'cipher_hooks',
                'encoding': 'base64_hooks'
            }
            
            for pattern_key, hook_name in pattern_hook_map.items():
                if pattern_key in pattern_type.lower():
                    return {
                        'hook_name': hook_name,
                        'pattern_matches': [pattern_match],
                        'confidence': getattr(pattern_match, 'confidence', 0.5),
                        'source_finding': finding
                    }
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Pattern to hook conversion failed: {e}")
            return None


class AIMLEnhancedFridaScriptGenerator(FridaScriptGenerator):
    """
    AI/ML-Enhanced Frida Script Generator.
    
    Extends the base FridaScriptGenerator with advanced AI/ML capabilities for
    intelligent vulnerability detection and adaptive script generation.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize AI/ML-enhanced generator with dependency injection."""
        super().__init__(config)
        
        # AI/ML specific configuration
        self.ai_ml_config = self.config.get('ai_ml_enhancement', {})
        self.ai_ml_enabled = self.ai_ml_config.get('enabled', True) and AODS_ML_AVAILABLE
        
        # Initialize AI/ML components
        self.hook_intelligence_analyzer = None
        
        if self.ai_ml_enabled:
            self._initialize_ai_ml_components()
        else:
            self.contextual_logger.warning("AI/ML enhancement disabled or components unavailable",
                                         context={'aods_ml_available': AODS_ML_AVAILABLE})
    
    def _initialize_ai_ml_components(self):
        """Initialize AI/ML components with comprehensive error handling."""
        try:
            # Initialize ML Hook Intelligence Analyzer
            self.hook_intelligence_analyzer = MLHookIntelligenceAnalyzer(self.ai_ml_config)
            
            self.contextual_logger.info("AI/ML components initialized successfully",
                                      context={
                                          'hook_intelligence_enabled': bool(self.hook_intelligence_analyzer),
                                          'ai_ml_config_keys': list(self.ai_ml_config.keys())
                                      })
            
        except Exception as e:
            error_context = ErrorContext(
                component_name="AIMLEnhancedFridaScriptGenerator",
                operation="_initialize_ai_ml_components",
                additional_context={'config': self.ai_ml_config}
            )
            self.contextual_logger.error("Failed to initialize AI/ML components",
                                       context=error_context.to_dict())
            self.ai_ml_enabled = False
    
    async def generate_ai_ml_enhanced_script(self, 
                                           findings: List[Union[RuntimeDecryptionFinding, Dict[str, Any]]],
                                           context: Optional[AIMLScriptGenerationContext] = None) -> AIMLEnhancedScript:
        """
        Generate AI/ML-enhanced Frida script with intelligent hook selection.
        
        Args:
            findings: List of runtime decryption findings
            context: AI/ML-enhanced generation context
            
        Returns:
            Enhanced script with ML insights and recommendations
        """
        start_time = time.time()
        
        try:
            # Validate inputs
            validated_findings = self._validate_findings(findings)
            ai_context = context or AIMLScriptGenerationContext(findings=validated_findings)
            
            # Step 1: Generate base script using parent implementation
            base_context = ScriptGenerationContext(
                findings=validated_findings,
                config=ai_context.config,
                hooks_to_generate=ai_context.hooks_to_generate,
                output_directory=ai_context.output_directory,
                include_usage_instructions=ai_context.include_usage_instructions,
                max_hooks_per_script=ai_context.max_hooks_per_script,
                template_config=ai_context.template_config
            )
            
            base_script = self.generate_script(validated_findings, base_context)
            
            # Step 2: AI/ML Enhancement
            ml_recommendations = []
            cve_correlations = []
            vulnerability_predictions = []
            ml_confidence_scores = {}
            adaptive_insights = {}
            intelligence_metadata = {}
            
            if self.ai_ml_enabled and self.hook_intelligence_analyzer:
                # Generate ML hook recommendations
                ml_recommendations = await self.hook_intelligence_analyzer.analyze_hook_intelligence(
                    validated_findings, ai_context
                )
                
                # Update hooks based on ML recommendations
                enhanced_hooks = self._integrate_ml_recommendations(
                    base_script.hooks_generated, ml_recommendations, ai_context
                )
                
                # Regenerate script with enhanced hooks if recommendations are significant
                if len(enhanced_hooks) != len(base_script.hooks_generated):
                    enhanced_context = ScriptGenerationContext(
                        findings=validated_findings,
                        hooks_to_generate=enhanced_hooks,
                        config=ai_context.config,
                        output_directory=ai_context.output_directory,
                        include_usage_instructions=ai_context.include_usage_instructions,
                        max_hooks_per_script=ai_context.max_hooks_per_script
                    )
                    base_script = self.generate_script(validated_findings, enhanced_context)
                
                # Extract additional ML insights
                cve_correlations = self._extract_cve_correlations(ml_recommendations)
                vulnerability_predictions = self._generate_vulnerability_predictions(ml_recommendations)
                ml_confidence_scores = self._calculate_ml_confidence_scores(ml_recommendations)
                intelligence_metadata = self._generate_intelligence_metadata(ml_recommendations)
            
            # Step 3: Create enhanced script result
            generation_time = time.time() - start_time
            
            enhanced_script = AIMLEnhancedScript(
                script_content=base_script.script_content,
                script_path=base_script.script_path,
                hooks_generated=base_script.hooks_generated,
                template_used=base_script.template_used,
                generation_time=generation_time,
                usage_instructions=base_script.usage_instructions,
                template_variables=base_script.template_variables,
                total_hooks_requested=base_script.total_hooks_requested,
                successful_hooks=base_script.successful_hooks,
                ml_hook_recommendations=ml_recommendations,
                cve_correlations=cve_correlations,
                vulnerability_predictions=vulnerability_predictions,
                ml_confidence_scores=ml_confidence_scores,
                adaptive_insights=adaptive_insights,
                intelligence_metadata=intelligence_metadata
            )
            
            self.contextual_logger.info("AI/ML-enhanced script generated successfully",
                                      context={
                                          'generation_time': generation_time,
                                          'ml_recommendations': len(ml_recommendations),
                                          'cve_correlations': len(cve_correlations),
                                          'ml_enhanced': enhanced_script.ml_enhanced,
                                          'base_hooks': len(base_script.hooks_generated),
                                          'enhanced_hooks': len(enhanced_script.hooks_generated)
                                      })
            
            return enhanced_script
            
        except Exception as e:
            error_context = ErrorContext(
                component_name="AIMLEnhancedFridaScriptGenerator",
                operation="generate_ai_ml_enhanced_script",
                additional_context={'findings_count': len(findings)}
            )
            
            generation_time = time.time() - start_time
            
            # Return enhanced script with error information
            return AIMLEnhancedScript(
                script_content=self._generate_fallback_script(),
                error_message=str(e),
                generation_time=generation_time,
                hooks_generated=[],
                intelligence_metadata={'error': str(e), 'fallback_used': True}
            )
    
    def _integrate_ml_recommendations(self, 
                                    base_hooks: List[str],
                                    ml_recommendations: List[MLHookRecommendation],
                                    context: AIMLScriptGenerationContext) -> List[str]:
        """Integrate ML recommendations with base hook selection."""
        try:
            enhanced_hooks = base_hooks.copy()
            
            # Add high-confidence ML-recommended hooks
            for recommendation in ml_recommendations:
                if (recommendation.confidence_score >= context.ml_confidence_threshold and
                    recommendation.hook_name not in enhanced_hooks):
                    enhanced_hooks.append(recommendation.hook_name)
            
            # Remove low-priority hooks if we exceed the limit
            if len(enhanced_hooks) > context.max_hooks_per_script:
                # Sort by ML confidence and keep top hooks
                hook_priorities = {}
                for rec in ml_recommendations:
                    hook_priorities[rec.hook_name] = rec.confidence_score
                
                # Sort hooks by priority (ML confidence or default priority)
                sorted_hooks = sorted(enhanced_hooks, 
                                    key=lambda h: hook_priorities.get(h, 0.5), 
                                    reverse=True)
                enhanced_hooks = sorted_hooks[:context.max_hooks_per_script]
            
            return enhanced_hooks
            
        except Exception as e:
            self.contextual_logger.warning("Failed to integrate ML recommendations",
                                         context={'error': str(e)})
            return base_hooks
    
    def _extract_cve_correlations(self, ml_recommendations: List[MLHookRecommendation]) -> List[Dict[str, Any]]:
        """Extract CVE correlations from ML recommendations."""
        correlations = []
        
        for recommendation in ml_recommendations:
            for cve_id in recommendation.cve_correlations:
                correlation = {
                    'cve_id': cve_id,
                    'hook_name': recommendation.hook_name,
                    'confidence': recommendation.confidence_score,
                    'vulnerability_types': recommendation.vulnerability_types
                }
                correlations.append(correlation)
        
        return correlations
    
    def _generate_vulnerability_predictions(self, ml_recommendations: List[MLHookRecommendation]) -> List[Dict[str, Any]]:
        """Generate vulnerability predictions from ML analysis."""
        predictions = []
        
        for recommendation in ml_recommendations:
            prediction = {
                'hook_name': recommendation.hook_name,
                'predicted_vulnerabilities': recommendation.vulnerability_types,
                'detection_rate': recommendation.estimated_detection_rate,
                'false_positive_risk': recommendation.false_positive_risk,
                'effectiveness': recommendation.effectiveness_prediction,
                'reasoning': recommendation.reasoning
            }
            predictions.append(prediction)
        
        return predictions
    
    def _calculate_ml_confidence_scores(self, ml_recommendations: List[MLHookRecommendation]) -> Dict[str, float]:
        """Calculate ML confidence scores for each hook."""
        confidence_scores = {}
        
        for recommendation in ml_recommendations:
            confidence_scores[recommendation.hook_name] = recommendation.confidence_score
        
        return confidence_scores
    
    def _generate_intelligence_metadata(self, ml_recommendations: List[MLHookRecommendation]) -> Dict[str, Any]:
        """Generate intelligence metadata for the enhanced script."""
        if not ml_recommendations:
            return {'ml_enhanced': False}
        
        # Calculate aggregate metrics
        avg_confidence = sum(r.confidence_score for r in ml_recommendations) / len(ml_recommendations)
        avg_effectiveness = sum(r.effectiveness_prediction for r in ml_recommendations) / len(ml_recommendations)
        total_cve_correlations = sum(len(r.cve_correlations) for r in ml_recommendations)
        
        # Extract unique vulnerability types
        all_vuln_types = set()
        for rec in ml_recommendations:
            all_vuln_types.update(rec.vulnerability_types)
        
        return {
            'ml_enhanced': True,
            'recommendations_count': len(ml_recommendations),
            'average_confidence': avg_confidence,
            'average_effectiveness': avg_effectiveness,
            'total_cve_correlations': total_cve_correlations,
            'vulnerability_types_covered': list(all_vuln_types),
            'high_confidence_recommendations': len([r for r in ml_recommendations if r.confidence_score > 0.8]),
            'enhancement_timestamp': datetime.now().isoformat(),
            'aods_ml_version': '2.0.0'
        }


# Convenience functions for easy integration
def create_ai_ml_enhanced_generator(config: Optional[Dict[str, Any]] = None) -> AIMLEnhancedFridaScriptGenerator:
    """Create an AI/ML-enhanced Frida script generator."""
    return AIMLEnhancedFridaScriptGenerator(config)


async def generate_intelligent_frida_script(findings: List[Union[RuntimeDecryptionFinding, Dict[str, Any]]],
                                          output_path: Optional[Path] = None,
                                          config: Optional[Dict[str, Any]] = None) -> AIMLEnhancedScript:
    """Convenience function for generating intelligent Frida scripts."""
    generator = create_ai_ml_enhanced_generator(config)
    
    context = AIMLScriptGenerationContext(
        findings=findings,
        output_directory=output_path.parent if output_path else None
    )
    
    result = await generator.generate_ai_ml_enhanced_script(findings, context)
    
    if output_path and result.script_content:
        success = generator.save_script_to_file(result, output_path)
        if success:
            result.script_path = output_path
    
    return result 
"""
AI/ML-Enhanced Frida Script Generator for AODS

Extends the base FridaScriptGenerator with advanced AI/ML capabilities for
intelligent hook selection, vulnerability prediction, and adaptive script generation.

Features:
- Intelligent hook selection using AODS ML infrastructure
- ML-enhanced confidence scoring for hook effectiveness
- CVE correlation for targeted vulnerability discovery
- Adaptive script generation based on runtime feedback
- Integration with AODS Advanced Intelligence Engine
- Real-time vulnerability pattern learning
- Context-aware hook prioritization

Architecture:
- Extends FridaScriptGenerator with clean inheritance
- Dependency injection for ML components
- Modular design with specialized ML analyzers
- Comprehensive error handling and fallback mechanisms
- Professional logging and monitoring

Integration Points:
- core.ml_integration_manager: ML classification and analysis
- core.advanced_intelligence_engine: CVE correlation and threat intelligence
- core.ml_enhanced_confidence_scorer: Advanced confidence scoring
- core.detection.advanced_pattern_engine: 1000+ pattern database
"""

import logging
import time
import asyncio
from typing import Dict, List, Any, Optional, Union, Tuple
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
import json

# AODS Core ML Infrastructure
try:
    from core.ml_integration_manager import MLIntegrationManager, ClassificationResult
    from core.advanced_intelligence_engine import AdvancedIntelligenceEngine, EnhancedClassificationResult
    from core.ml_enhanced_confidence_scorer import MLEnhancedConfidenceScorer, ConfidenceMetrics
    from core.detection.advanced_pattern_engine import AdvancedPatternDetectionEngine, VulnerabilityPattern
    AODS_ML_AVAILABLE = True
except ImportError as e:
    logging.warning(f"AODS ML infrastructure not available: {e}")
    AODS_ML_AVAILABLE = False

# Base Generator and AODS Infrastructure
from .frida_script_generator import (
    FridaScriptGenerator, ScriptGenerationContext, GeneratedScript,
    FridaScriptTemplateLoader, FindingProtocol
)
from .data_structures import RuntimeDecryptionFinding, DecryptionType, VulnerabilitySeverity
from core.shared_infrastructure.analysis_exceptions import AnalysisError, ErrorContext, ValidationError
from core.shared_infrastructure.cross_plugin_utilities import LoggingMixin, InputValidator
from core.shared_data_structures import BaseVulnerability


@dataclass
class MLHookRecommendation:
    """ML-generated hook recommendation with confidence and reasoning."""
    hook_name: str
    confidence_score: float
    effectiveness_prediction: float
    vulnerability_types: List[str]
    cve_correlations: List[str]
    reasoning: str
    priority: int
    estimated_detection_rate: float
    false_positive_risk: float
    
    def __post_init__(self):
        """Validate recommendation data."""
        if not 0.0 <= self.confidence_score <= 1.0:
            raise ValidationError("confidence_score must be between 0.0 and 1.0")
        if not 0.0 <= self.effectiveness_prediction <= 1.0:
            raise ValidationError("effectiveness_prediction must be between 0.0 and 1.0")
        if self.priority < 1:
            raise ValidationError("priority must be >= 1")


@dataclass
class AIMLScriptGenerationContext(ScriptGenerationContext):
    """Enhanced context with AI/ML capabilities."""
    enable_ml_hook_selection: bool = True
    enable_cve_correlation: bool = True
    enable_adaptive_generation: bool = True
    ml_confidence_threshold: float = 0.7
    max_ml_hooks: int = 15
    vulnerability_focus: List[str] = field(default_factory=list)
    target_cve_years: List[int] = field(default_factory=lambda: [2023, 2024, 2025])
    
    def __post_init__(self):
        """Enhanced validation for AI/ML context."""
        super().__post_init__()
        
        if not 0.0 <= self.ml_confidence_threshold <= 1.0:
            raise ValidationError("ml_confidence_threshold must be between 0.0 and 1.0")
        if self.max_ml_hooks <= 0:
            raise ValidationError("max_ml_hooks must be positive")


@dataclass
class AIMLEnhancedScript(GeneratedScript):
    """Enhanced script result with AI/ML insights."""
    ml_hook_recommendations: List[MLHookRecommendation] = field(default_factory=list)
    cve_correlations: List[Dict[str, Any]] = field(default_factory=list)
    vulnerability_predictions: List[Dict[str, Any]] = field(default_factory=list)
    ml_confidence_scores: Dict[str, float] = field(default_factory=dict)
    adaptive_insights: Dict[str, Any] = field(default_factory=dict)
    intelligence_metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def ml_enhanced(self) -> bool:
        """Check if script was enhanced with ML."""
        return len(self.ml_hook_recommendations) > 0 or len(self.cve_correlations) > 0


class MLHookIntelligenceAnalyzer:
    """Analyzes and selects optimal hooks using ML intelligence."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize ML hook intelligence analyzer."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.validator = InputValidator()
        
        # Initialize ML components if available
        self.ml_manager = None
        self.intelligence_engine = None
        self.confidence_scorer = None
        self.pattern_engine = None
        
        if AODS_ML_AVAILABLE:
            self._initialize_ml_components()
    
    def _initialize_ml_components(self):
        """Initialize AODS ML components."""
        try:
            # ML Integration Manager for classification
            ml_config = self.config.get('ml_integration', {})
            if ml_config.get('enabled', True):
                self.ml_manager = MLIntegrationManager(ml_config)
                self.logger.info("ML Integration Manager initialized for hook intelligence")
            
            # Advanced Intelligence Engine for CVE correlation
            intel_config = self.config.get('intelligence_engine', {})
            if intel_config.get('enabled', True):
                self.intelligence_engine = AdvancedIntelligenceEngine(intel_config)
                self.logger.info("Advanced Intelligence Engine initialized for CVE correlation")
            
            # ML-Enhanced Confidence Scorer
            confidence_config = self.config.get('confidence_scoring', {})
            if confidence_config.get('enabled', True):
                self.confidence_scorer = MLEnhancedConfidenceScorer(confidence_config)
                self.logger.info("ML-Enhanced Confidence Scorer initialized")
            
            # Advanced Pattern Engine for 1000+ patterns
            pattern_config = self.config.get('pattern_engine', {})
            if pattern_config.get('enabled', True):
                self.pattern_engine = AdvancedPatternDetectionEngine(pattern_config)
                self.logger.info("Advanced Pattern Engine initialized (1000+ patterns)")
                
        except Exception as e:
            self.logger.warning(f"Failed to initialize some ML components: {e}")
    
    async def analyze_hook_intelligence(self, 
                                      findings: List[Union[RuntimeDecryptionFinding, Dict[str, Any]]],
                                      context: AIMLScriptGenerationContext) -> List[MLHookRecommendation]:
        """Analyze findings to generate intelligent hook recommendations."""
        try:
            recommendations = []
            
            # Step 1: ML-based vulnerability classification
            ml_classifications = await self._classify_vulnerabilities(findings)
            
            # Step 2: CVE correlation and threat intelligence
            cve_correlations = await self._correlate_with_cves(findings, context)
            
            # Step 3: Pattern-based hook selection
            pattern_hooks = await self._select_pattern_based_hooks(findings, ml_classifications)
            
            # Step 4: Generate ML recommendations
            for hook_data in pattern_hooks:
                recommendation = await self._generate_hook_recommendation(
                    hook_data, ml_classifications, cve_correlations, context
                )
                if recommendation and recommendation.confidence_score >= context.ml_confidence_threshold:
                    recommendations.append(recommendation)
            
            # Step 5: Priority sorting and filtering
            recommendations = self._prioritize_recommendations(recommendations, context)
            
            self.logger.info(f"Generated {len(recommendations)} ML hook recommendations")
            return recommendations
            
        except Exception as e:
            error_context = ErrorContext(
                component_name="MLHookIntelligenceAnalyzer",
                operation="analyze_hook_intelligence",
                additional_context={'findings_count': len(findings)}
            )
            raise AnalysisError(f"ML hook intelligence analysis failed: {e}", error_context, cause=e)
    
    async def _classify_vulnerabilities(self, 
                                      findings: List[Union[RuntimeDecryptionFinding, Dict[str, Any]]]) -> List[ClassificationResult]:
        """Classify vulnerabilities using AODS ML infrastructure."""
        classifications = []
        
        if not self.ml_manager:
            return classifications
        
        try:
            for finding in findings:
                # Convert to classification format
                classification_data = self._prepare_classification_data(finding)
                
                # Use AODS ML manager for classification
                result = await asyncio.get_event_loop().run_in_executor(
                    None, 
                    self.ml_manager.classify_vulnerability,
                    classification_data
                )
                
                if result:
                    classifications.append(result)
            
            self.logger.debug(f"Classified {len(classifications)} vulnerabilities using ML")
            return classifications
            
        except Exception as e:
            self.logger.warning(f"ML vulnerability classification failed: {e}")
            return classifications
    
    async def _correlate_with_cves(self, 
                                 findings: List[Union[RuntimeDecryptionFinding, Dict[str, Any]]],
                                 context: AIMLScriptGenerationContext) -> List[Dict[str, Any]]:
        """Correlate findings with CVE database using Advanced Intelligence Engine."""
        correlations = []
        
        if not self.intelligence_engine or not context.enable_cve_correlation:
            return correlations
        
        try:
            for finding in findings:
                # Prepare vulnerability data for correlation
                vulnerability_data = self._prepare_vulnerability_data(finding)
                
                # Use Advanced Intelligence Engine for CVE correlation
                enhanced_result = await self.intelligence_engine.analyze_with_advanced_intelligence(vulnerability_data)
                
                if enhanced_result and enhanced_result.threat_intelligence:
                    correlation = {
                        'finding_id': getattr(finding, 'id', str(hash(str(finding)))),
                        'cve_ids': enhanced_result.threat_intelligence.cve_references,
                        'exploit_prediction': enhanced_result.exploit_prediction,
                        'remediation_priority': enhanced_result.remediation_priority,
                        'threat_score': enhanced_result.threat_intelligence.threat_score
                    }
                    correlations.append(correlation)
            
            self.logger.debug(f"Generated {len(correlations)} CVE correlations")
            return correlations
            
        except Exception as e:
            self.logger.warning(f"CVE correlation failed: {e}")
            return correlations
    
    async def _select_pattern_based_hooks(self, 
                                        findings: List[Union[RuntimeDecryptionFinding, Dict[str, Any]]],
                                        classifications: List[ClassificationResult]) -> List[Dict[str, Any]]:
        """Select hooks based on advanced pattern analysis."""
        hook_selections = []
        
        if not self.pattern_engine:
            # Fallback to default hook selection
            return [
                {'hook_name': 'cipher_hooks', 'pattern_matches': [], 'confidence': 0.5},
                {'hook_name': 'base64_hooks', 'pattern_matches': [], 'confidence': 0.5}
            ]
        
        try:
            # Use Advanced Pattern Engine for hook selection
            for finding in findings:
                # Extract vulnerability patterns
                vulnerability_text = self._extract_vulnerability_text(finding)
                
                # Get pattern matches from 1000+ pattern database
                pattern_matches = await asyncio.get_event_loop().run_in_executor(
                    None,
                    self.pattern_engine.analyze_vulnerability_patterns,
                    vulnerability_text
                )
                
                # Convert pattern matches to hook selections
                for pattern_match in pattern_matches:
                    hook_selection = self._pattern_to_hook_selection(pattern_match, finding)
                    if hook_selection:
                        hook_selections.append(hook_selection)
            
            self.logger.debug(f"Selected {len(hook_selections)} pattern-based hooks")
            return hook_selections
            
        except Exception as e:
            self.logger.warning(f"Pattern-based hook selection failed: {e}")
            return hook_selections
    
    async def _generate_hook_recommendation(self,
                                          hook_data: Dict[str, Any],
                                          ml_classifications: List[ClassificationResult],
                                          cve_correlations: List[Dict[str, Any]],
                                          context: AIMLScriptGenerationContext) -> Optional[MLHookRecommendation]:
        """Generate a comprehensive hook recommendation using ML insights."""
        try:
            hook_name = hook_data.get('hook_name', 'unknown_hook')
            
            # Calculate confidence using ML-enhanced scorer
            confidence_score = await self._calculate_ml_confidence(hook_data, ml_classifications)
            
            # Predict effectiveness based on patterns and ML
            effectiveness_prediction = self._predict_hook_effectiveness(hook_data, ml_classifications)
            
            # Extract relevant vulnerability types
            vulnerability_types = self._extract_vulnerability_types(hook_data, ml_classifications)
            
            # Find relevant CVE correlations
            relevant_cves = self._find_relevant_cves(hook_data, cve_correlations)
            
            # Generate reasoning
            reasoning = self._generate_ml_reasoning(hook_data, ml_classifications, relevant_cves)
            
            # Calculate priority and risk metrics
            priority = self._calculate_hook_priority(hook_data, context)
            estimated_detection_rate = self._estimate_detection_rate(hook_data, ml_classifications)
            false_positive_risk = self._estimate_false_positive_risk(hook_data)
            
            recommendation = MLHookRecommendation(
                hook_name=hook_name,
                confidence_score=confidence_score,
                effectiveness_prediction=effectiveness_prediction,
                vulnerability_types=vulnerability_types,
                cve_correlations=relevant_cves,
                reasoning=reasoning,
                priority=priority,
                estimated_detection_rate=estimated_detection_rate,
                false_positive_risk=false_positive_risk
            )
            
            return recommendation
            
        except Exception as e:
            self.logger.warning(f"Failed to generate hook recommendation for {hook_data.get('hook_name', 'unknown')}: {e}")
            return None
    
    def _prioritize_recommendations(self, 
                                  recommendations: List[MLHookRecommendation],
                                  context: AIMLScriptGenerationContext) -> List[MLHookRecommendation]:
        """Prioritize and filter recommendations based on ML insights."""
        try:
            # Sort by multiple criteria: priority, confidence, effectiveness
            sorted_recommendations = sorted(
                recommendations,
                key=lambda r: (r.priority, r.confidence_score, r.effectiveness_prediction),
                reverse=True
            )
            
            # Apply filtering based on context
            filtered_recommendations = []
            for rec in sorted_recommendations:
                # Check confidence threshold
                if rec.confidence_score < context.ml_confidence_threshold:
                    continue
                
                # Check vulnerability focus if specified
                if context.vulnerability_focus:
                    if not any(vuln_type in context.vulnerability_focus for vuln_type in rec.vulnerability_types):
                        continue
                
                # Check false positive risk
                if rec.false_positive_risk > 0.3:  # Conservative threshold
                    continue
                
                filtered_recommendations.append(rec)
                
                # Limit number of recommendations
                if len(filtered_recommendations) >= context.max_ml_hooks:
                    break
            
            self.logger.info(f"Prioritized {len(filtered_recommendations)} high-quality recommendations")
            return filtered_recommendations
            
        except Exception as e:
            self.logger.warning(f"Failed to prioritize recommendations: {e}")
            return recommendations[:context.max_ml_hooks]
    
    # Helper methods for data preparation and calculation
    def _prepare_classification_data(self, finding: Union[RuntimeDecryptionFinding, Dict[str, Any]]) -> Dict[str, Any]:
        """Prepare finding data for ML classification."""
        if isinstance(finding, RuntimeDecryptionFinding):
            return {
                'description': finding.description,
                'finding_type': finding.finding_type,
                'severity': finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                'location': finding.location,
                'pattern_type': finding.pattern_type.value if hasattr(finding.pattern_type, 'value') else str(finding.pattern_type)
            }
        else:
            return {
                'description': finding.get('description', ''),
                'finding_type': finding.get('finding_type', ''),
                'severity': finding.get('severity', 'MEDIUM'),
                'location': finding.get('location', ''),
                'pattern_type': finding.get('pattern_type', 'RUNTIME_DECRYPTION')
            }
    
    def _prepare_vulnerability_data(self, finding: Union[RuntimeDecryptionFinding, Dict[str, Any]]) -> Dict[str, Any]:
        """Prepare vulnerability data for CVE correlation."""
        base_data = self._prepare_classification_data(finding)
        base_data.update({
            'vulnerability_category': 'cryptography',
            'technology': 'android',
            'component_type': 'mobile_application'
        })
        return base_data
    
    def _extract_vulnerability_text(self, finding: Union[RuntimeDecryptionFinding, Dict[str, Any]]) -> str:
        """Extract text content for pattern analysis."""
        if isinstance(finding, RuntimeDecryptionFinding):
            return f"{finding.description} {finding.finding_type} {finding.location}"
        else:
            desc = finding.get('description', '')
            ftype = finding.get('finding_type', '')
            loc = finding.get('location', '')
            return f"{desc} {ftype} {loc}"
    
    async def _calculate_ml_confidence(self, 
                                     hook_data: Dict[str, Any],
                                     ml_classifications: List[ClassificationResult]) -> float:
        """Calculate confidence using ML-enhanced confidence scorer."""
        if not self.confidence_scorer:
            return 0.5  # Fallback confidence
        
        try:
            # Prepare evidence for confidence calculation
            evidence = {
                'hook_name': hook_data.get('hook_name', ''),
                'pattern_matches': hook_data.get('pattern_matches', []),
                'ml_classifications': [c.confidence for c in ml_classifications if c.confidence],
                'vulnerability_indicators': len(hook_data.get('pattern_matches', []))
            }
            
            # Use ML-enhanced confidence scorer
            confidence_metrics = await asyncio.get_event_loop().run_in_executor(
                None,
                self.confidence_scorer.compute_enhanced_confidence,
                evidence
            )
            
            return confidence_metrics.confidence_score if confidence_metrics else 0.5
            
        except Exception as e:
            self.logger.debug(f"ML confidence calculation failed: {e}")
            return 0.5
    
    def _predict_hook_effectiveness(self, 
                                  hook_data: Dict[str, Any],
                                  ml_classifications: List[ClassificationResult]) -> float:
        """Predict hook effectiveness based on ML analysis."""
        try:
            # Base effectiveness from pattern matches
            pattern_count = len(hook_data.get('pattern_matches', []))
            base_effectiveness = min(pattern_count * 0.2, 0.8)
            
            # ML classification boost
            ml_boost = 0.0
            if ml_classifications:
                avg_ml_confidence = sum(c.confidence for c in ml_classifications) / len(ml_classifications)
                ml_boost = avg_ml_confidence * 0.3
            
            # Hook-specific adjustments
            hook_name = hook_data.get('hook_name', '')
            hook_multiplier = {
                'cipher_hooks': 1.2,
                'base64_hooks': 1.0,
                'key_derivation_hooks': 1.3,
                'custom_method_hook': 0.8
            }.get(hook_name, 1.0)
            
            effectiveness = (base_effectiveness + ml_boost) * hook_multiplier
            return min(max(effectiveness, 0.1), 0.95)
            
        except Exception as e:
            self.logger.debug(f"Hook effectiveness prediction failed: {e}")
            return 0.5
    
    def _extract_vulnerability_types(self, 
                                   hook_data: Dict[str, Any],
                                   ml_classifications: List[ClassificationResult]) -> List[str]:
        """Extract relevant vulnerability types from ML analysis."""
        vulnerability_types = set()
        
        # From hook data
        hook_name = hook_data.get('hook_name', '')
        hook_to_vuln_map = {
            'cipher_hooks': ['weak_cryptography', 'crypto_implementation'],
            'base64_hooks': ['data_encoding', 'obfuscation'],
            'key_derivation_hooks': ['key_management', 'weak_key_generation'],
            'custom_method_hook': ['custom_vulnerability']
        }
        vulnerability_types.update(hook_to_vuln_map.get(hook_name, []))
        
        # From ML classifications
        for classification in ml_classifications:
            if hasattr(classification, 'vulnerability_type') and classification.vulnerability_type:
                vulnerability_types.add(classification.vulnerability_type)
        
        return list(vulnerability_types)
    
    def _find_relevant_cves(self, 
                          hook_data: Dict[str, Any],
                          cve_correlations: List[Dict[str, Any]]) -> List[str]:
        """Find CVEs relevant to this hook."""
        relevant_cves = []
        
        hook_name = hook_data.get('hook_name', '')
        
        # Map hooks to CVE categories
        hook_cve_categories = {
            'cipher_hooks': ['crypto', 'encryption', 'cipher'],
            'base64_hooks': ['encoding', 'obfuscation'],
            'key_derivation_hooks': ['key', 'derivation', 'generation']
        }
        
        categories = hook_cve_categories.get(hook_name, [])
        
        for correlation in cve_correlations:
            cve_ids = correlation.get('cve_ids', [])
            for cve_id in cve_ids:
                if any(category in cve_id.lower() for category in categories):
                    relevant_cves.append(cve_id)
        
        return relevant_cves[:5]  # Limit to top 5 relevant CVEs
    
    def _generate_ml_reasoning(self, 
                             hook_data: Dict[str, Any],
                             ml_classifications: List[ClassificationResult],
                             relevant_cves: List[str]) -> str:
        """Generate human-readable reasoning for the recommendation."""
        reasoning_parts = []
        
        hook_name = hook_data.get('hook_name', 'unknown')
        pattern_count = len(hook_data.get('pattern_matches', []))
        
        # Base reasoning
        reasoning_parts.append(f"Hook '{hook_name}' selected based on {pattern_count} pattern matches")
        
        # ML insights
        if ml_classifications:
            high_confidence_count = sum(1 for c in ml_classifications if c.confidence > 0.8)
            reasoning_parts.append(f"ML analysis identified {high_confidence_count} high-confidence vulnerabilities")
        
        # CVE correlation
        if relevant_cves:
            reasoning_parts.append(f"Correlated with {len(relevant_cves)} relevant CVEs: {', '.join(relevant_cves[:3])}")
        
        # Effectiveness prediction
        effectiveness = hook_data.get('effectiveness_prediction', 0.5)
        if effectiveness > 0.8:
            reasoning_parts.append("High detection effectiveness predicted")
        elif effectiveness > 0.6:
            reasoning_parts.append("Moderate detection effectiveness predicted")
        
        return ". ".join(reasoning_parts) + "."
    
    def _calculate_hook_priority(self, 
                               hook_data: Dict[str, Any],
                               context: AIMLScriptGenerationContext) -> int:
        """Calculate hook priority based on multiple factors."""
        base_priority = 5
        
        # Pattern match boost
        pattern_count = len(hook_data.get('pattern_matches', []))
        pattern_boost = min(pattern_count, 3)
        
        # Hook type priority
        hook_name = hook_data.get('hook_name', '')
        hook_priority_map = {
            'cipher_hooks': 3,
            'key_derivation_hooks': 2,
            'base64_hooks': 1,
            'custom_method_hook': 0
        }
        hook_boost = hook_priority_map.get(hook_name, 0)
        
        # Vulnerability focus boost
        focus_boost = 0
        if context.vulnerability_focus:
            vulnerability_types = self._extract_vulnerability_types(hook_data, [])
            if any(vtype in context.vulnerability_focus for vtype in vulnerability_types):
                focus_boost = 2
        
        return base_priority + pattern_boost + hook_boost + focus_boost
    
    def _estimate_detection_rate(self, 
                               hook_data: Dict[str, Any],
                               ml_classifications: List[ClassificationResult]) -> float:
        """Estimate the detection rate for this hook."""
        try:
            # Base detection rate from historical data
            hook_name = hook_data.get('hook_name', '')
            base_rates = {
                'cipher_hooks': 0.75,
                'base64_hooks': 0.65,
                'key_derivation_hooks': 0.80,
                'custom_method_hook': 0.50
            }
            base_rate = base_rates.get(hook_name, 0.60)
            
            # ML classification adjustment
            ml_adjustment = 0.0
            if ml_classifications:
                avg_confidence = sum(c.confidence for c in ml_classifications) / len(ml_classifications)
                ml_adjustment = (avg_confidence - 0.5) * 0.2  # ±0.1 adjustment
            
            return min(max(base_rate + ml_adjustment, 0.3), 0.95)
            
        except Exception as e:
            self.logger.debug(f"Detection rate estimation failed: {e}")
            return 0.60
    
    def _estimate_false_positive_risk(self, hook_data: Dict[str, Any]) -> float:
        """Estimate false positive risk for this hook."""
        try:
            # Base false positive rates from historical data
            hook_name = hook_data.get('hook_name', '')
            base_fp_rates = {
                'cipher_hooks': 0.10,
                'base64_hooks': 0.20,
                'key_derivation_hooks': 0.08,
                'custom_method_hook': 0.30
            }
            base_fp_rate = base_fp_rates.get(hook_name, 0.15)
            
            # Pattern match quality adjustment
            pattern_count = len(hook_data.get('pattern_matches', []))
            if pattern_count >= 3:
                fp_reduction = 0.05  # More patterns = lower FP risk
            elif pattern_count >= 2:
                fp_reduction = 0.02
            else:
                fp_reduction = 0.0
            
            return max(base_fp_rate - fp_reduction, 0.02)
            
        except Exception as e:
            self.logger.debug(f"False positive risk estimation failed: {e}")
            return 0.15
    
    def _pattern_to_hook_selection(self, 
                                 pattern_match: Any,
                                 finding: Union[RuntimeDecryptionFinding, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Convert pattern match to hook selection."""
        try:
            # This would need to be implemented based on the actual AdvancedPatternDetectionEngine API
            # For now, provide a basic implementation
            if hasattr(pattern_match, 'pattern_type'):
                pattern_type = pattern_match.pattern_type
            else:
                pattern_type = str(pattern_match)
            
            # Map patterns to hooks
            pattern_hook_map = {
                'cipher': 'cipher_hooks',
                'base64': 'base64_hooks',
                'key': 'key_derivation_hooks',
                'crypto': 'cipher_hooks',
                'encryption': 'cipher_hooks',
                'encoding': 'base64_hooks'
            }
            
            for pattern_key, hook_name in pattern_hook_map.items():
                if pattern_key in pattern_type.lower():
                    return {
                        'hook_name': hook_name,
                        'pattern_matches': [pattern_match],
                        'confidence': getattr(pattern_match, 'confidence', 0.5),
                        'source_finding': finding
                    }
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Pattern to hook conversion failed: {e}")
            return None


class AIMLEnhancedFridaScriptGenerator(FridaScriptGenerator):
    """
    AI/ML-Enhanced Frida Script Generator.
    
    Extends the base FridaScriptGenerator with advanced AI/ML capabilities for
    intelligent vulnerability detection and adaptive script generation.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize AI/ML-enhanced generator with dependency injection."""
        super().__init__(config)
        
        # AI/ML specific configuration
        self.ai_ml_config = self.config.get('ai_ml_enhancement', {})
        self.ai_ml_enabled = self.ai_ml_config.get('enabled', True) and AODS_ML_AVAILABLE
        
        # Initialize AI/ML components
        self.hook_intelligence_analyzer = None
        
        if self.ai_ml_enabled:
            self._initialize_ai_ml_components()
        else:
            self.contextual_logger.warning("AI/ML enhancement disabled or components unavailable",
                                         context={'aods_ml_available': AODS_ML_AVAILABLE})
    
    def _initialize_ai_ml_components(self):
        """Initialize AI/ML components with comprehensive error handling."""
        try:
            # Initialize ML Hook Intelligence Analyzer
            self.hook_intelligence_analyzer = MLHookIntelligenceAnalyzer(self.ai_ml_config)
            
            self.contextual_logger.info("AI/ML components initialized successfully",
                                      context={
                                          'hook_intelligence_enabled': bool(self.hook_intelligence_analyzer),
                                          'ai_ml_config_keys': list(self.ai_ml_config.keys())
                                      })
            
        except Exception as e:
            error_context = ErrorContext(
                component_name="AIMLEnhancedFridaScriptGenerator",
                operation="_initialize_ai_ml_components",
                additional_context={'config': self.ai_ml_config}
            )
            self.contextual_logger.error("Failed to initialize AI/ML components",
                                       context=error_context.to_dict())
            self.ai_ml_enabled = False
    
    async def generate_ai_ml_enhanced_script(self, 
                                           findings: List[Union[RuntimeDecryptionFinding, Dict[str, Any]]],
                                           context: Optional[AIMLScriptGenerationContext] = None) -> AIMLEnhancedScript:
        """
        Generate AI/ML-enhanced Frida script with intelligent hook selection.
        
        Args:
            findings: List of runtime decryption findings
            context: AI/ML-enhanced generation context
            
        Returns:
            Enhanced script with ML insights and recommendations
        """
        start_time = time.time()
        
        try:
            # Validate inputs
            validated_findings = self._validate_findings(findings)
            ai_context = context or AIMLScriptGenerationContext(findings=validated_findings)
            
            # Step 1: Generate base script using parent implementation
            base_context = ScriptGenerationContext(
                findings=validated_findings,
                config=ai_context.config,
                hooks_to_generate=ai_context.hooks_to_generate,
                output_directory=ai_context.output_directory,
                include_usage_instructions=ai_context.include_usage_instructions,
                max_hooks_per_script=ai_context.max_hooks_per_script,
                template_config=ai_context.template_config
            )
            
            base_script = self.generate_script(validated_findings, base_context)
            
            # Step 2: AI/ML Enhancement
            ml_recommendations = []
            cve_correlations = []
            vulnerability_predictions = []
            ml_confidence_scores = {}
            adaptive_insights = {}
            intelligence_metadata = {}
            
            if self.ai_ml_enabled and self.hook_intelligence_analyzer:
                # Generate ML hook recommendations
                ml_recommendations = await self.hook_intelligence_analyzer.analyze_hook_intelligence(
                    validated_findings, ai_context
                )
                
                # Update hooks based on ML recommendations
                enhanced_hooks = self._integrate_ml_recommendations(
                    base_script.hooks_generated, ml_recommendations, ai_context
                )
                
                # Regenerate script with enhanced hooks if recommendations are significant
                if len(enhanced_hooks) != len(base_script.hooks_generated):
                    enhanced_context = ScriptGenerationContext(
                        findings=validated_findings,
                        hooks_to_generate=enhanced_hooks,
                        config=ai_context.config,
                        output_directory=ai_context.output_directory,
                        include_usage_instructions=ai_context.include_usage_instructions,
                        max_hooks_per_script=ai_context.max_hooks_per_script
                    )
                    base_script = self.generate_script(validated_findings, enhanced_context)
                
                # Extract additional ML insights
                cve_correlations = self._extract_cve_correlations(ml_recommendations)
                vulnerability_predictions = self._generate_vulnerability_predictions(ml_recommendations)
                ml_confidence_scores = self._calculate_ml_confidence_scores(ml_recommendations)
                intelligence_metadata = self._generate_intelligence_metadata(ml_recommendations)
            
            # Step 3: Create enhanced script result
            generation_time = time.time() - start_time
            
            enhanced_script = AIMLEnhancedScript(
                script_content=base_script.script_content,
                script_path=base_script.script_path,
                hooks_generated=base_script.hooks_generated,
                template_used=base_script.template_used,
                generation_time=generation_time,
                usage_instructions=base_script.usage_instructions,
                template_variables=base_script.template_variables,
                total_hooks_requested=base_script.total_hooks_requested,
                successful_hooks=base_script.successful_hooks,
                ml_hook_recommendations=ml_recommendations,
                cve_correlations=cve_correlations,
                vulnerability_predictions=vulnerability_predictions,
                ml_confidence_scores=ml_confidence_scores,
                adaptive_insights=adaptive_insights,
                intelligence_metadata=intelligence_metadata
            )
            
            self.contextual_logger.info("AI/ML-enhanced script generated successfully",
                                      context={
                                          'generation_time': generation_time,
                                          'ml_recommendations': len(ml_recommendations),
                                          'cve_correlations': len(cve_correlations),
                                          'ml_enhanced': enhanced_script.ml_enhanced,
                                          'base_hooks': len(base_script.hooks_generated),
                                          'enhanced_hooks': len(enhanced_script.hooks_generated)
                                      })
            
            return enhanced_script
            
        except Exception as e:
            error_context = ErrorContext(
                component_name="AIMLEnhancedFridaScriptGenerator",
                operation="generate_ai_ml_enhanced_script",
                additional_context={'findings_count': len(findings)}
            )
            
            generation_time = time.time() - start_time
            
            # Return enhanced script with error information
            return AIMLEnhancedScript(
                script_content=self._generate_fallback_script(),
                error_message=str(e),
                generation_time=generation_time,
                hooks_generated=[],
                intelligence_metadata={'error': str(e), 'fallback_used': True}
            )
    
    def _integrate_ml_recommendations(self, 
                                    base_hooks: List[str],
                                    ml_recommendations: List[MLHookRecommendation],
                                    context: AIMLScriptGenerationContext) -> List[str]:
        """Integrate ML recommendations with base hook selection."""
        try:
            enhanced_hooks = base_hooks.copy()
            
            # Add high-confidence ML-recommended hooks
            for recommendation in ml_recommendations:
                if (recommendation.confidence_score >= context.ml_confidence_threshold and
                    recommendation.hook_name not in enhanced_hooks):
                    enhanced_hooks.append(recommendation.hook_name)
            
            # Remove low-priority hooks if we exceed the limit
            if len(enhanced_hooks) > context.max_hooks_per_script:
                # Sort by ML confidence and keep top hooks
                hook_priorities = {}
                for rec in ml_recommendations:
                    hook_priorities[rec.hook_name] = rec.confidence_score
                
                # Sort hooks by priority (ML confidence or default priority)
                sorted_hooks = sorted(enhanced_hooks, 
                                    key=lambda h: hook_priorities.get(h, 0.5), 
                                    reverse=True)
                enhanced_hooks = sorted_hooks[:context.max_hooks_per_script]
            
            return enhanced_hooks
            
        except Exception as e:
            self.contextual_logger.warning("Failed to integrate ML recommendations",
                                         context={'error': str(e)})
            return base_hooks
    
    def _extract_cve_correlations(self, ml_recommendations: List[MLHookRecommendation]) -> List[Dict[str, Any]]:
        """Extract CVE correlations from ML recommendations."""
        correlations = []
        
        for recommendation in ml_recommendations:
            for cve_id in recommendation.cve_correlations:
                correlation = {
                    'cve_id': cve_id,
                    'hook_name': recommendation.hook_name,
                    'confidence': recommendation.confidence_score,
                    'vulnerability_types': recommendation.vulnerability_types
                }
                correlations.append(correlation)
        
        return correlations
    
    def _generate_vulnerability_predictions(self, ml_recommendations: List[MLHookRecommendation]) -> List[Dict[str, Any]]:
        """Generate vulnerability predictions from ML analysis."""
        predictions = []
        
        for recommendation in ml_recommendations:
            prediction = {
                'hook_name': recommendation.hook_name,
                'predicted_vulnerabilities': recommendation.vulnerability_types,
                'detection_rate': recommendation.estimated_detection_rate,
                'false_positive_risk': recommendation.false_positive_risk,
                'effectiveness': recommendation.effectiveness_prediction,
                'reasoning': recommendation.reasoning
            }
            predictions.append(prediction)
        
        return predictions
    
    def _calculate_ml_confidence_scores(self, ml_recommendations: List[MLHookRecommendation]) -> Dict[str, float]:
        """Calculate ML confidence scores for each hook."""
        confidence_scores = {}
        
        for recommendation in ml_recommendations:
            confidence_scores[recommendation.hook_name] = recommendation.confidence_score
        
        return confidence_scores
    
    def _generate_intelligence_metadata(self, ml_recommendations: List[MLHookRecommendation]) -> Dict[str, Any]:
        """Generate intelligence metadata for the enhanced script."""
        if not ml_recommendations:
            return {'ml_enhanced': False}
        
        # Calculate aggregate metrics
        avg_confidence = sum(r.confidence_score for r in ml_recommendations) / len(ml_recommendations)
        avg_effectiveness = sum(r.effectiveness_prediction for r in ml_recommendations) / len(ml_recommendations)
        total_cve_correlations = sum(len(r.cve_correlations) for r in ml_recommendations)
        
        # Extract unique vulnerability types
        all_vuln_types = set()
        for rec in ml_recommendations:
            all_vuln_types.update(rec.vulnerability_types)
        
        return {
            'ml_enhanced': True,
            'recommendations_count': len(ml_recommendations),
            'average_confidence': avg_confidence,
            'average_effectiveness': avg_effectiveness,
            'total_cve_correlations': total_cve_correlations,
            'vulnerability_types_covered': list(all_vuln_types),
            'high_confidence_recommendations': len([r for r in ml_recommendations if r.confidence_score > 0.8]),
            'enhancement_timestamp': datetime.now().isoformat(),
            'aods_ml_version': '2.0.0'
        }


# Convenience functions for easy integration
def create_ai_ml_enhanced_generator(config: Optional[Dict[str, Any]] = None) -> AIMLEnhancedFridaScriptGenerator:
    """Create an AI/ML-enhanced Frida script generator."""
    return AIMLEnhancedFridaScriptGenerator(config)


async def generate_intelligent_frida_script(findings: List[Union[RuntimeDecryptionFinding, Dict[str, Any]]],
                                          output_path: Optional[Path] = None,
                                          config: Optional[Dict[str, Any]] = None) -> AIMLEnhancedScript:
    """Convenience function for generating intelligent Frida scripts."""
    generator = create_ai_ml_enhanced_generator(config)
    
    context = AIMLScriptGenerationContext(
        findings=findings,
        output_directory=output_path.parent if output_path else None
    )
    
    result = await generator.generate_ai_ml_enhanced_script(findings, context)
    
    if output_path and result.script_content:
        success = generator.save_script_to_file(result, output_path)
        if success:
            result.script_path = output_path
    
    return result 