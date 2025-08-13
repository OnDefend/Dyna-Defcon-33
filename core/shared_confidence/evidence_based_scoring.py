"""
Evidence-Based Scoring Framework

Provides comprehensive evidence analysis for confidence calculation including:
- Multi-factor evidence analysis
- Evidence weight calculation
- Cross-validation assessment
- Context-aware adjustments
- False positive analysis

This framework enables systematic, defensible confidence scoring across all
security analysis domains.
"""

import logging
import statistics
from typing import Dict, List, Optional, Any, Tuple, Set, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import math

# Optional numpy import for type hints
try:
    import numpy as np
    NumpyArray = np.ndarray
except ImportError:
    np = None
    NumpyArray = List[List[float]]

from ..shared_analyzers.universal_confidence_calculator import (
    ConfidenceEvidence,
    ConfidenceFactorType,
    PatternReliability
)
from ..shared_infrastructure.pattern_reliability_database import (
    PatternReliabilityDatabase,
    get_reliability_database
)

logger = logging.getLogger(__name__)

@dataclass
class EvidenceAnalysisResult:
    """Result of evidence analysis with detailed breakdown."""
    overall_score: float
    factor_scores: Dict[ConfidenceFactorType, float]
    evidence_quality: float
    pattern_reliability: float
    context_relevance: float
    validation_sources: int
    cross_validation_score: float
    false_positive_risk: float
    confidence_factors: Dict[str, Any] = field(default_factory=dict)
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)

class EvidenceQualityLevel(Enum):
    """Evidence quality levels for assessment."""
    EXCELLENT = "excellent"  # 0.9+
    GOOD = "good"           # 0.7-0.9
    MODERATE = "moderate"    # 0.5-0.7
    POOR = "poor"           # 0.3-0.5
    MINIMAL = "minimal"      # 0.0-0.3

class EvidenceAnalyzer:
    """
    Analyzes evidence quality and provides detailed assessment for confidence calculation.
    """
    
    def __init__(self, reliability_db: Optional[PatternReliabilityDatabase] = None):
        """Initialize evidence analyzer."""
        self.reliability_db = reliability_db or get_reliability_database()
        self.logger = logging.getLogger(__name__)
        
        # Evidence quality thresholds
        self.quality_thresholds = {
            EvidenceQualityLevel.EXCELLENT: 0.9,
            EvidenceQualityLevel.GOOD: 0.7,
            EvidenceQualityLevel.MODERATE: 0.5,
            EvidenceQualityLevel.POOR: 0.3,
            EvidenceQualityLevel.MINIMAL: 0.0
        }
        
        # Evidence strength indicators
        self.strength_indicators = {
            'explicit_vulnerability': 0.95,
            'confirmed_exploitation': 0.9,
            'verified_bypass': 0.85,
            'working_proof_of_concept': 0.8,
            'detailed_code_analysis': 0.75,
            'pattern_match': 0.7,
            'heuristic_detection': 0.6,
            'statistical_anomaly': 0.5,
            'generic_indicator': 0.4
        }
    
    def analyze_evidence(self, 
                        evidence_list: List[ConfidenceEvidence],
                        context: Optional[Dict[str, Any]] = None) -> EvidenceAnalysisResult:
        """
        Analyze evidence quality and provide detailed assessment.
        
        Args:
            evidence_list: List of evidence items to analyze
            context: Optional context for analysis
            
        Returns:
            EvidenceAnalysisResult with detailed breakdown
        """
        context = context or {}
        
        # Calculate individual factor scores
        factor_scores = self._calculate_factor_scores(evidence_list)
        
        # Assess evidence quality
        evidence_quality = self._assess_evidence_quality(evidence_list, context)
        
        # Calculate pattern reliability
        pattern_reliability = self._calculate_pattern_reliability(evidence_list, context)
        
        # Assess context relevance
        context_relevance = self._assess_context_relevance(evidence_list, context)
        
        # Count validation sources
        validation_sources = self._count_validation_sources(evidence_list)
        
        # Calculate cross-validation score
        cross_validation_score = self._calculate_cross_validation_score(evidence_list)
        
        # Assess false positive risk
        false_positive_risk = self._assess_false_positive_risk(evidence_list, context)
        
        # Calculate overall score
        overall_score = self._calculate_overall_score(
            factor_scores, evidence_quality, pattern_reliability,
            context_relevance, cross_validation_score, false_positive_risk
        )
        
        # Create analysis metadata
        analysis_metadata = {
            'evidence_count': len(evidence_list),
            'analysis_timestamp': datetime.now().isoformat(),
            'context_provided': bool(context),
            'quality_level': self._determine_quality_level(evidence_quality),
            'risk_factors': self._identify_risk_factors(evidence_list, context)
        }
        
        return EvidenceAnalysisResult(
            overall_score=overall_score,
            factor_scores=factor_scores,
            evidence_quality=evidence_quality,
            pattern_reliability=pattern_reliability,
            context_relevance=context_relevance,
            validation_sources=validation_sources,
            cross_validation_score=cross_validation_score,
            false_positive_risk=false_positive_risk,
            confidence_factors=self._extract_confidence_factors(evidence_list),
            analysis_metadata=analysis_metadata
        )
    
    def _calculate_factor_scores(self, evidence_list: List[ConfidenceEvidence]) -> Dict[ConfidenceFactorType, float]:
        """Calculate scores for each confidence factor type."""
        factor_scores = {}
        
        for factor_type in ConfidenceFactorType:
            relevant_evidence = [e for e in evidence_list if e.factor_type == factor_type]
            
            if relevant_evidence:
                # Weight-adjusted average
                total_weighted_score = sum(e.score * e.weight for e in relevant_evidence)
                total_weight = sum(e.weight for e in relevant_evidence)
                
                if total_weight > 0:
                    factor_scores[factor_type] = total_weighted_score / total_weight
                else:
                    factor_scores[factor_type] = 0.5  # Default
            else:
                factor_scores[factor_type] = 0.5  # Default for missing factors
        
        return factor_scores
    
    def _assess_evidence_quality(self, evidence_list: List[ConfidenceEvidence], context: Dict[str, Any]) -> float:
        """Assess overall evidence quality."""
        base_quality = 0.5
        
        # Quality indicators
        quality_indicators = []
        
        for evidence in evidence_list:
            # Check for high-quality evidence indicators
            if evidence.score > 0.8:
                quality_indicators.append(0.9)
            elif evidence.score > 0.6:
                quality_indicators.append(0.7)
            else:
                quality_indicators.append(0.5)
            
            # Check evidence description quality
            if evidence.description and len(evidence.description) > 50:
                quality_indicators.append(0.8)
            elif evidence.description and len(evidence.description) > 20:
                quality_indicators.append(0.6)
            
            # Check for supporting data
            if evidence.supporting_data:
                quality_indicators.append(0.7)
        
        # Calculate quality score
        if quality_indicators:
            quality_score = statistics.mean(quality_indicators)
        else:
            quality_score = base_quality
        
        # Context-based adjustments
        if context.get('detailed_analysis'):
            quality_score += 0.1
        if context.get('expert_review'):
            quality_score += 0.15
        if context.get('automated_only'):
            quality_score -= 0.1
        
        return max(0.0, min(1.0, quality_score))
    
    def _calculate_pattern_reliability(self, evidence_list: List[ConfidenceEvidence], context: Dict[str, Any]) -> float:
        """Calculate pattern reliability score."""
        pattern_scores = []
        
        for evidence in evidence_list:
            if evidence.factor_type == ConfidenceFactorType.PATTERN_RELIABILITY:
                # Get pattern reliability from database if available
                pattern_id = context.get('pattern_id')
                if pattern_id:
                    pattern_data = self.reliability_db.get_pattern_reliability(pattern_id)
                    if pattern_data:
                        pattern_scores.append(pattern_data.reliability_score)
                    else:
                        pattern_scores.append(evidence.score)
                else:
                    pattern_scores.append(evidence.score)
        
        if pattern_scores:
            return statistics.mean(pattern_scores)
        else:
            return 0.5  # Default reliability
    
    def _assess_context_relevance(self, evidence_list: List[ConfidenceEvidence], context: Dict[str, Any]) -> float:
        """Assess context relevance of evidence."""
        context_scores = []
        
        for evidence in evidence_list:
            if evidence.factor_type == ConfidenceFactorType.CONTEXT_RELEVANCE:
                context_scores.append(evidence.score)
        
        # Context type adjustments
        context_type = context.get('context_type', 'unknown')
        context_adjustments = {
            'production_code': 1.0,
            'configuration_files': 0.9,
            'test_code': 0.4,
            'documentation': 0.2,
            'build_files': 0.3,
            'unknown': 0.5
        }
        
        base_score = statistics.mean(context_scores) if context_scores else 0.5
        adjustment = context_adjustments.get(context_type, 0.5)
        
        return base_score * adjustment
    
    def _count_validation_sources(self, evidence_list: List[ConfidenceEvidence]) -> int:
        """Count the number of validation sources."""
        validation_sources = set()
        
        for evidence in evidence_list:
            if evidence.factor_type == ConfidenceFactorType.VALIDATION_SOURCES:
                # Extract validation sources from supporting data
                if evidence.supporting_data:
                    sources = evidence.supporting_data.get('validation_sources', [])
                    validation_sources.update(sources)
        
        return len(validation_sources)
    
    def _calculate_cross_validation_score(self, evidence_list: List[ConfidenceEvidence]) -> float:
        """Calculate cross-validation score."""
        validation_count = self._count_validation_sources(evidence_list)
        
        # Score based on number of validation sources
        if validation_count >= 3:
            return 0.9
        elif validation_count == 2:
            return 0.7
        elif validation_count == 1:
            return 0.5
        else:
            return 0.3
    
    def _assess_false_positive_risk(self, evidence_list: List[ConfidenceEvidence], context: Dict[str, Any]) -> float:
        """Assess false positive risk."""
        risk_factors = []
        
        # Check for false positive indicators
        for evidence in evidence_list:
            if evidence.supporting_data:
                fp_indicators = evidence.supporting_data.get('false_positive_indicators', [])
                risk_factors.extend(fp_indicators)
        
        # Context-based risk factors
        if context.get('test_environment'):
            risk_factors.append('test_environment')
        if context.get('development_mode'):
            risk_factors.append('development_mode')
        if context.get('example_code'):
            risk_factors.append('example_code')
        
        # Calculate risk score
        base_risk = len(risk_factors) * 0.1
        return min(0.8, base_risk)  # Cap at 80% risk
    
    def _calculate_overall_score(self, 
                               factor_scores: Dict[ConfidenceFactorType, float],
                               evidence_quality: float,
                               pattern_reliability: float,
                               context_relevance: float,
                               cross_validation_score: float,
                               false_positive_risk: float) -> float:
        """Calculate overall evidence score."""
        
        # Weight the different components
        component_weights = {
            'evidence_quality': 0.25,
            'pattern_reliability': 0.25,
            'context_relevance': 0.20,
            'cross_validation': 0.20,
            'false_positive_adjustment': 0.10
        }
        
        # Calculate weighted score
        overall_score = (
            evidence_quality * component_weights['evidence_quality'] +
            pattern_reliability * component_weights['pattern_reliability'] +
            context_relevance * component_weights['context_relevance'] +
            cross_validation_score * component_weights['cross_validation'] +
            (1.0 - false_positive_risk) * component_weights['false_positive_adjustment']
        )
        
        return max(0.0, min(1.0, overall_score))
    
    def _determine_quality_level(self, evidence_quality: float) -> EvidenceQualityLevel:
        """Determine evidence quality level."""
        for level, threshold in self.quality_thresholds.items():
            if evidence_quality >= threshold:
                return level
        return EvidenceQualityLevel.MINIMAL
    
    def _identify_risk_factors(self, evidence_list: List[ConfidenceEvidence], context: Dict[str, Any]) -> List[str]:
        """Identify risk factors that might affect confidence."""
        risk_factors = []
        
        # Evidence-based risk factors
        for evidence in evidence_list:
            if evidence.score < 0.3:
                risk_factors.append('low_quality_evidence')
            if evidence.supporting_data:
                fp_indicators = evidence.supporting_data.get('false_positive_indicators', [])
                risk_factors.extend(fp_indicators)
        
        # Context-based risk factors
        if context.get('test_environment'):
            risk_factors.append('test_environment')
        if context.get('automated_analysis_only'):
            risk_factors.append('automated_analysis_only')
        if context.get('limited_validation'):
            risk_factors.append('limited_validation')
        
        return list(set(risk_factors))  # Remove duplicates
    
    def _extract_confidence_factors(self, evidence_list: List[ConfidenceEvidence]) -> Dict[str, Any]:
        """Extract confidence factors from evidence."""
        factors = {}
        
        for evidence in evidence_list:
            if evidence.supporting_data:
                factors.update(evidence.supporting_data)
        
        return factors

class EvidenceWeightCalculator:
    """
    Calculates optimal evidence weights based on historical performance and domain expertise.
    """
    
    def __init__(self, reliability_db: Optional[PatternReliabilityDatabase] = None):
        """Initialize evidence weight calculator."""
        self.reliability_db = reliability_db or get_reliability_database()
        self.logger = logging.getLogger(__name__)
        
        # Default weights by plugin type
        self.default_weights = {
            'cryptography': {
                ConfidenceFactorType.PATTERN_RELIABILITY: 0.30,
                ConfidenceFactorType.EVIDENCE_QUALITY: 0.25,
                ConfidenceFactorType.CONTEXT_RELEVANCE: 0.20,
                ConfidenceFactorType.VALIDATION_SOURCES: 0.15,
                ConfidenceFactorType.IMPLEMENTATION_CONTEXT: 0.10
            },
            'binary_analysis': {
                ConfidenceFactorType.EVIDENCE_QUALITY: 0.30,
                ConfidenceFactorType.PATTERN_RELIABILITY: 0.25,
                ConfidenceFactorType.CONTEXT_RELEVANCE: 0.20,
                ConfidenceFactorType.VALIDATION_SOURCES: 0.15,
                ConfidenceFactorType.IMPLEMENTATION_CONTEXT: 0.10
            },
            'network_security': {
                ConfidenceFactorType.PATTERN_RELIABILITY: 0.30,
                ConfidenceFactorType.CONTEXT_RELEVANCE: 0.25,
                ConfidenceFactorType.EVIDENCE_QUALITY: 0.25,
                ConfidenceFactorType.VALIDATION_SOURCES: 0.15,
                ConfidenceFactorType.IMPLEMENTATION_CONTEXT: 0.05
            }
        }
    
    def calculate_optimal_weights(self, 
                                plugin_type: str,
                                historical_data: Optional[List[Dict[str, Any]]] = None) -> Dict[ConfidenceFactorType, float]:
        """
        Calculate optimal evidence weights for a plugin type.
        
        Args:
            plugin_type: Type of plugin
            historical_data: Historical performance data
            
        Returns:
            Dictionary of optimal weights
        """
        # Start with default weights
        weights = self.default_weights.get(plugin_type, self.default_weights['cryptography'])
        
        # Adjust weights based on historical performance if available
        if historical_data:
            weights = self._adjust_weights_by_performance(weights, historical_data)
        
        # Normalize weights to sum to 1.0
        total_weight = sum(weights.values())
        if total_weight > 0:
            weights = {k: v / total_weight for k, v in weights.items()}
        
        return weights
    
    def _adjust_weights_by_performance(self, 
                                     base_weights: Dict[ConfidenceFactorType, float],
                                     historical_data: List[Dict[str, Any]]) -> Dict[ConfidenceFactorType, float]:
        """
        Adjust weights based on historical performance using machine learning optimization.
        
        Uses multiple ML algorithms to determine optimal weights:
        - Logistic regression for baseline optimization
        - Random forest for feature importance analysis
        - Gradient boosting for complex pattern detection
        - Bayesian optimization for continuous improvement
        
        Args:
            base_weights: Starting weights for optimization
            historical_data: Historical performance data with outcomes
            
        Returns:
            Optimized weights based on ML analysis
        """
        if not historical_data or len(historical_data) < 10:
            self.logger.warning("Insufficient historical data for ML optimization, using base weights")
            return base_weights
        
        try:
            # Attempt ML-based optimization
            optimized_weights = self._ml_weight_optimization(base_weights, historical_data)
            
            # Validate optimized weights
            if self._validate_optimized_weights(optimized_weights, base_weights):
                self.logger.info("ML-based weight optimization successful")
                return optimized_weights
            else:
                self.logger.warning("ML optimization validation failed, using enhanced heuristic optimization")
                return self._heuristic_weight_optimization(base_weights, historical_data)
                
        except Exception as e:
            self.logger.warning(f"ML optimization failed: {e}, falling back to heuristic optimization")
            return self._heuristic_weight_optimization(base_weights, historical_data)
    
    def _ml_weight_optimization(self, 
                              base_weights: Dict[ConfidenceFactorType, float],
                              historical_data: List[Dict[str, Any]]) -> Dict[ConfidenceFactorType, float]:
        """
        Perform ML-based weight optimization using multiple algorithms.
        
        Args:
            base_weights: Base weights to optimize
            historical_data: Historical performance data
            
        Returns:
            ML-optimized weights
        """
        try:
            # Optional ML imports for weight optimization
            from sklearn.ensemble import RandomForestRegressor, GradientBoostingRegressor
            from sklearn.linear_model import LogisticRegression, Ridge
            from sklearn.model_selection import cross_val_score, GridSearchCV
            from sklearn.preprocessing import StandardScaler
            from sklearn.metrics import mean_squared_error, accuracy_score
            import numpy as np
        except ImportError:
            raise ImportError("ML libraries not available for weight optimization")
        
        # Prepare training data
        features, targets, factor_contributions = self._prepare_ml_training_data(historical_data, base_weights)
        
        if len(features) < 5:
            raise ValueError("Insufficient training data for ML optimization")
        
        # Normalize features
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(features)
        
        # Method 1: Random Forest for feature importance analysis
        rf_weights = self._random_forest_optimization(features_scaled, targets, factor_contributions)
        
        # Method 2: Gradient Boosting for complex pattern detection
        gb_weights = self._gradient_boosting_optimization(features_scaled, targets, factor_contributions)
        
        # Method 3: Ridge regression for regularized optimization
        ridge_weights = self._ridge_regression_optimization(features_scaled, targets, factor_contributions)
        
        # Ensemble the results with weighted voting
        optimized_weights = self._ensemble_weight_optimization(
            [rf_weights, gb_weights, ridge_weights],
            [0.4, 0.35, 0.25],  # Weights for each method
            base_weights
        )
        
        return optimized_weights
    
    def _prepare_ml_training_data(self, 
                                historical_data: List[Dict[str, Any]], 
                                base_weights: Dict[ConfidenceFactorType, float]) -> Tuple[List[List[float]], List[float], Dict[ConfidenceFactorType, List[float]]]:
        """Prepare training data for ML optimization."""
        features = []
        targets = []
        factor_contributions = {factor: [] for factor in base_weights.keys()}
        
        for record in historical_data:
            if 'factor_scores' in record and 'actual_outcome' in record:
                factor_scores = record['factor_scores']
                actual_outcome = 1.0 if record['actual_outcome'] else 0.0
                
                # Create feature vector from factor scores
                feature_vector = []
                for factor_type in base_weights.keys():
                    score = factor_scores.get(factor_type, 0.5)
                    feature_vector.append(score)
                    factor_contributions[factor_type].append(score)
                
                features.append(feature_vector)
                targets.append(actual_outcome)
        
        return features, targets, factor_contributions
    
    def _random_forest_optimization(self, 
                                  features: NumpyArray, 
                                  targets: List[float],
                                  factor_contributions: Dict[ConfidenceFactorType, List[float]]) -> Dict[ConfidenceFactorType, float]:
        """Optimize weights using Random Forest feature importance."""
        try:
            from sklearn.ensemble import RandomForestRegressor
            import numpy as np
        except ImportError:
            raise ImportError("sklearn not available")
        
        # Train Random Forest
        rf = RandomForestRegressor(n_estimators=100, random_state=42, max_depth=5)
        rf.fit(features, targets)
        
        # Extract feature importances
        importances = rf.feature_importances_
        
        # Map importances back to factor types
        factor_types = list(factor_contributions.keys())
        optimized_weights = {}
        
        for i, factor_type in enumerate(factor_types):
            optimized_weights[factor_type] = max(0.05, min(0.6, importances[i]))
        
        # Normalize weights
        total_weight = sum(optimized_weights.values())
        if total_weight > 0:
            optimized_weights = {k: v / total_weight for k, v in optimized_weights.items()}
        
        return optimized_weights
    
    def _gradient_boosting_optimization(self, 
                                      features: NumpyArray, 
                                      targets: List[float],
                                      factor_contributions: Dict[ConfidenceFactorType, List[float]]) -> Dict[ConfidenceFactorType, float]:
        """Optimize weights using Gradient Boosting with cross-validation."""
        try:
            from sklearn.ensemble import GradientBoostingRegressor
            from sklearn.model_selection import GridSearchCV
            import numpy as np
        except ImportError:
            raise ImportError("sklearn not available")
        
        # Hyperparameter tuning
        param_grid = {
            'n_estimators': [50, 100],
            'learning_rate': [0.05, 0.1],
            'max_depth': [3, 5]
        }
        
        gb = GradientBoostingRegressor(random_state=42)
        grid_search = GridSearchCV(gb, param_grid, cv=3, scoring='neg_mean_squared_error')
        grid_search.fit(features, targets)
        
        # Get best model
        best_gb = grid_search.best_estimator_
        
        # Extract feature importances
        importances = best_gb.feature_importances_
        
        # Map importances back to factor types
        factor_types = list(factor_contributions.keys())
        optimized_weights = {}
        
        for i, factor_type in enumerate(factor_types):
            # Apply smoothing to avoid extreme weights
            smoothed_importance = 0.7 * importances[i] + 0.3 * (1.0 / len(factor_types))
            optimized_weights[factor_type] = max(0.05, min(0.6, smoothed_importance))
        
        # Normalize weights
        total_weight = sum(optimized_weights.values())
        if total_weight > 0:
            optimized_weights = {k: v / total_weight for k, v in optimized_weights.items()}
        
        return optimized_weights
    
    def _ridge_regression_optimization(self, 
                                     features: NumpyArray, 
                                     targets: List[float],
                                     factor_contributions: Dict[ConfidenceFactorType, List[float]]) -> Dict[ConfidenceFactorType, float]:
        """Optimize weights using Ridge regression for regularization."""
        try:
            from sklearn.linear_model import Ridge
            from sklearn.model_selection import GridSearchCV
            import numpy as np
        except ImportError:
            raise ImportError("sklearn not available")
        
        # Hyperparameter tuning for regularization
        alphas = [0.1, 1.0, 10.0]
        ridge = Ridge()
        grid_search = GridSearchCV(ridge, {'alpha': alphas}, cv=3, scoring='neg_mean_squared_error')
        grid_search.fit(features, targets)
        
        # Get best model
        best_ridge = grid_search.best_estimator_
        
        # Extract coefficients as weights
        coefficients = np.abs(best_ridge.coef_)  # Use absolute values
        
        # Map coefficients back to factor types
        factor_types = list(factor_contributions.keys())
        optimized_weights = {}
        
        for i, factor_type in enumerate(factor_types):
            optimized_weights[factor_type] = max(0.05, min(0.6, coefficients[i]))
        
        # Normalize weights
        total_weight = sum(optimized_weights.values())
        if total_weight > 0:
            optimized_weights = {k: v / total_weight for k, v in optimized_weights.items()}
        
        return optimized_weights
    
    def _ensemble_weight_optimization(self, 
                                    weight_sets: List[Dict[ConfidenceFactorType, float]],
                                    ensemble_weights: List[float],
                                    base_weights: Dict[ConfidenceFactorType, float]) -> Dict[ConfidenceFactorType, float]:
        """Ensemble multiple weight optimization results."""
        if not weight_sets or not ensemble_weights:
            return base_weights
        
        # Weighted ensemble of optimization results
        ensembled_weights = {}
        
        for factor_type in base_weights.keys():
            weighted_sum = 0.0
            total_ensemble_weight = 0.0
            
            for i, weight_set in enumerate(weight_sets):
                if factor_type in weight_set and i < len(ensemble_weights):
                    weighted_sum += weight_set[factor_type] * ensemble_weights[i]
                    total_ensemble_weight += ensemble_weights[i]
            
            if total_ensemble_weight > 0:
                ensembled_weights[factor_type] = weighted_sum / total_ensemble_weight
            else:
                ensembled_weights[factor_type] = base_weights[factor_type]
        
        # Normalize final weights
        total_weight = sum(ensembled_weights.values())
        if total_weight > 0:
            ensembled_weights = {k: v / total_weight for k, v in ensembled_weights.items()}
        
        return ensembled_weights
    
    def _heuristic_weight_optimization(self, 
                                     base_weights: Dict[ConfidenceFactorType, float],
                                     historical_data: List[Dict[str, Any]]) -> Dict[ConfidenceFactorType, float]:
        """
        Fallback heuristic optimization when ML methods are unavailable.
        
        Uses statistical analysis to adjust weights based on correlation 
        with actual outcomes.
        """
        if not historical_data:
            return base_weights
        
        # Calculate correlation between factor scores and actual outcomes
        factor_correlations = {}
        
        for factor_type in base_weights.keys():
            factor_scores = []
            outcomes = []
            
            for record in historical_data:
                if 'factor_scores' in record and 'actual_outcome' in record:
                    factor_score = record['factor_scores'].get(factor_type, 0.5)
                    outcome = 1.0 if record['actual_outcome'] else 0.0
                    factor_scores.append(factor_score)
                    outcomes.append(outcome)
            
            if len(factor_scores) > 3:
                # Calculate simple correlation
                correlation = self._calculate_correlation(factor_scores, outcomes)
                factor_correlations[factor_type] = abs(correlation)  # Use absolute correlation
            else:
                factor_correlations[factor_type] = 0.5  # Default correlation
        
        # Adjust weights based on correlations
        optimized_weights = {}
        for factor_type, base_weight in base_weights.items():
            correlation = factor_correlations.get(factor_type, 0.5)
            # Blend base weight with correlation-based adjustment
            adjusted_weight = 0.6 * base_weight + 0.4 * correlation
            optimized_weights[factor_type] = max(0.05, min(0.6, adjusted_weight))
        
        # Normalize weights
        total_weight = sum(optimized_weights.values())
        if total_weight > 0:
            optimized_weights = {k: v / total_weight for k, v in optimized_weights.items()}
        
        return optimized_weights
    
    def _calculate_correlation(self, x: List[float], y: List[float]) -> float:
        """Calculate Pearson correlation coefficient."""
        if len(x) != len(y) or len(x) < 2:
            return 0.0
        
        n = len(x)
        sum_x = sum(x)
        sum_y = sum(y)
        sum_xy = sum(xi * yi for xi, yi in zip(x, y))
        sum_x2 = sum(xi * xi for xi in x)
        sum_y2 = sum(yi * yi for yi in y)
        
        numerator = n * sum_xy - sum_x * sum_y
        denominator = ((n * sum_x2 - sum_x * sum_x) * (n * sum_y2 - sum_y * sum_y)) ** 0.5
        
        if denominator == 0:
            return 0.0
        
        return numerator / denominator
    
    def _validate_optimized_weights(self, 
                                  optimized_weights: Dict[ConfidenceFactorType, float],
                                  base_weights: Dict[ConfidenceFactorType, float]) -> bool:
        """Validate that optimized weights are reasonable."""
        # Check that all weights are present
        if set(optimized_weights.keys()) != set(base_weights.keys()):
            return False
        
        # Check weight ranges
        for weight in optimized_weights.values():
            if weight < 0.01 or weight > 0.8:  # Reasonable weight range
                return False
        
        # Check that weights sum to approximately 1.0
        total_weight = sum(optimized_weights.values())
        if abs(total_weight - 1.0) > 0.1:
            return False
        
        # Check that no single weight dominates excessively
        max_weight = max(optimized_weights.values())
        if max_weight > 0.7:
            return False
        
        return True

class CrossValidationAnalyzer:
    """
    Analyzes cross-validation results to improve confidence accuracy.
    """
    
    def __init__(self):
        """Initialize cross-validation analyzer."""
        self.logger = logging.getLogger(__name__)
    
    def analyze_cross_validation(self, 
                               validation_results: List[Dict[str, Any]],
                               primary_finding: Dict[str, Any]) -> float:
        """
        Analyze cross-validation results and return confidence adjustment.
        
        Args:
            validation_results: List of validation results from different sources
            primary_finding: Primary finding to validate
            
        Returns:
            Cross-validation confidence score (0.0-1.0)
        """
        if not validation_results:
            return 0.3  # Low confidence without validation
        
        # Analyze agreement between validation sources
        agreement_score = self._calculate_agreement_score(validation_results)
        
        # Assess validation source quality
        source_quality = self._assess_validation_source_quality(validation_results)
        
        # Calculate final cross-validation score
        cross_validation_score = (agreement_score * 0.7) + (source_quality * 0.3)
        
        return max(0.0, min(1.0, cross_validation_score))
    
    def _calculate_agreement_score(self, validation_results: List[Dict[str, Any]]) -> float:
        """Calculate agreement score between validation sources."""
        if len(validation_results) < 2:
            return 0.5
        
        # Extract vulnerability classifications
        classifications = [result.get('is_vulnerability', False) for result in validation_results]
        
        # Calculate agreement rate
        true_count = sum(classifications)
        false_count = len(classifications) - true_count
        
        # Agreement score based on consensus
        if true_count == len(classifications) or false_count == len(classifications):
            return 0.95  # Perfect agreement
        elif abs(true_count - false_count) <= 1:
            return 0.7   # Majority agreement
        else:
            return 0.4   # Disagreement
    
    def _assess_validation_source_quality(self, validation_results: List[Dict[str, Any]]) -> float:
        """Assess quality of validation sources."""
        source_quality_scores = []
        
        for result in validation_results:
            source_type = result.get('source_type', 'unknown')
            
            # Quality scores by source type
            source_quality = {
                'expert_review': 0.95,
                'automated_testing': 0.8,
                'static_analysis': 0.7,
                'dynamic_analysis': 0.85,
                'penetration_testing': 0.9,
                'code_review': 0.85,
                'unknown': 0.5
            }
            
            source_quality_scores.append(source_quality.get(source_type, 0.5))
        
        return statistics.mean(source_quality_scores) if source_quality_scores else 0.5

class ContextAwareAdjuster:
    """
    Provides context-aware adjustments to confidence scores.
    """
    
    def __init__(self):
        """Initialize context-aware adjuster."""
        self.logger = logging.getLogger(__name__)
        
        # Context adjustment factors
        self.context_adjustments = {
            'file_type': {
                'source_code': 1.0,
                'configuration': 0.9,
                'manifest': 0.95,
                'resources': 0.7,
                'test_files': 0.4,
                'build_files': 0.3,
                'documentation': 0.2
            },
            'environment': {
                'production': 1.0,
                'staging': 0.9,
                'development': 0.8,
                'test': 0.4,
                'example': 0.2
            },
            'analysis_depth': {
                'comprehensive': 1.0,
                'detailed': 0.9,
                'standard': 0.8,
                'basic': 0.6,
                'minimal': 0.4
            }
        }
    
    def adjust_confidence(self, 
                         base_confidence: float,
                         context: Dict[str, Any]) -> float:
        """
        Apply context-aware adjustments to confidence score.
        
        Args:
            base_confidence: Base confidence score
            context: Context information
            
        Returns:
            Adjusted confidence score
        """
        adjusted_confidence = base_confidence
        
        # Apply file type adjustment
        file_type = context.get('file_type', 'unknown')
        if file_type in self.context_adjustments['file_type']:
            file_adjustment = self.context_adjustments['file_type'][file_type]
            adjusted_confidence *= file_adjustment
        
        # Apply environment adjustment
        environment = context.get('environment', 'unknown')
        if environment in self.context_adjustments['environment']:
            env_adjustment = self.context_adjustments['environment'][environment]
            adjusted_confidence *= env_adjustment
        
        # Apply analysis depth adjustment
        analysis_depth = context.get('analysis_depth', 'standard')
        if analysis_depth in self.context_adjustments['analysis_depth']:
            depth_adjustment = self.context_adjustments['analysis_depth'][analysis_depth]
            adjusted_confidence *= depth_adjustment
        
        return max(0.0, min(1.0, adjusted_confidence))

class FalsePositiveAnalyzer:
    """
    Analyzes false positive risk and provides confidence adjustments.
    """
    
    def __init__(self):
        """Initialize false positive analyzer."""
        self.logger = logging.getLogger(__name__)
        
        # False positive risk factors
        self.risk_factors = {
            'test_environment': 0.3,
            'development_mode': 0.2,
            'example_code': 0.4,
            'documentation': 0.5,
            'build_artifacts': 0.3,
            'generic_patterns': 0.2,
            'automated_only': 0.15,
            'limited_validation': 0.25
        }
    
    def analyze_false_positive_risk(self, 
                                  evidence_list: List[ConfidenceEvidence],
                                  context: Dict[str, Any]) -> float:
        """
        Analyze false positive risk and return risk score.
        
        Args:
            evidence_list: List of evidence
            context: Analysis context
            
        Returns:
            False positive risk score (0.0-1.0)
        """
        risk_score = 0.0
        
        # Check for risk factors in evidence
        for evidence in evidence_list:
            if evidence.supporting_data:
                fp_indicators = evidence.supporting_data.get('false_positive_indicators', [])
                for indicator in fp_indicators:
                    if indicator in self.risk_factors:
                        risk_score += self.risk_factors[indicator]
        
        # Check for context-based risk factors
        for factor, risk_value in self.risk_factors.items():
            if context.get(factor, False):
                risk_score += risk_value
        
        return min(1.0, risk_score)
    
    def apply_false_positive_adjustment(self, 
                                      base_confidence: float,
                                      false_positive_risk: float) -> float:
        """
        Apply false positive adjustment to confidence score.
        
        Args:
            base_confidence: Base confidence score
            false_positive_risk: False positive risk score
            
        Returns:
            Adjusted confidence score
        """
        # Reduce confidence based on false positive risk
        adjustment_factor = 1.0 - (false_positive_risk * 0.5)  # Max 50% reduction
        
        adjusted_confidence = base_confidence * adjustment_factor
        
        return max(0.0, min(1.0, adjusted_confidence)) 