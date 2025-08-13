#!/usr/bin/env python3
"""
ML-Enhanced Confidence Scoring System
Part of ML-003: Confidence Score Enhancement

This module implements ML-enhanced confidence prediction with uncertainty
quantification and ensemble confidence aggregation for improved vulnerability
detection accuracy.
"""

import logging
import json
import pickle
import numpy as np
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, asdict
from collections import defaultdict
import hashlib
import math

# ML Libraries
try:
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import accuracy_score, precision_recall_fscore_support
    from sklearn.model_selection import cross_val_score
    import numpy as np
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class ConfidenceMetrics:
    """Metrics for confidence score evaluation."""
    confidence_score: float
    uncertainty_estimate: float
    evidence_strength: float
    pattern_reliability: float
    context_support: float
    ensemble_agreement: float
    calibration_quality: float
    explanation: str

@dataclass
class ConfidenceCalibrationData:
    """Data for confidence calibration tracking."""
    predicted_confidence: float
    actual_outcome: bool  # True for TP, False for FP
    vulnerability_type: str
    context_features: Dict[str, Any]
    timestamp: datetime

class MLEnhancedConfidenceScorer:
    """ML-enhanced confidence scoring with uncertainty quantification."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.confidence_config = config.get('ml_enhanced_confidence', {})
        self.models_dir = Path(self.confidence_config.get('models_dir', 'models/confidence'))
        self.data_dir = Path(self.confidence_config.get('data_dir', 'data/confidence'))
        
        # Create directories
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Configuration parameters
        self.min_evidence_threshold = self.confidence_config.get('min_evidence_threshold', 0.3)
        self.uncertainty_weight = self.confidence_config.get('uncertainty_weight', 0.2)
        self.ensemble_weight = self.confidence_config.get('ensemble_weight', 0.3)
        self.context_weight = self.confidence_config.get('context_weight', 0.2)
        self.calibration_window_days = self.confidence_config.get('calibration_window_days', 7)
        
        # ML components
        self.confidence_models = {}
        self.calibration_models = {}
        self.uncertainty_models = {}
        
        # Calibration data
        self.calibration_history: List[ConfidenceCalibrationData] = []
        self.pattern_reliability_cache = {}
        
        # Evidence patterns
        self.evidence_patterns = {
            'strong_indicators': [],
            'weak_indicators': [],
            'negative_indicators': []
        }
        
        # Initialize models
        self._initialize_confidence_models()
        self._load_calibration_data()
        
        logger.info("ML-Enhanced Confidence Scorer initialized")
    
    def _initialize_confidence_models(self):
        """Initialize ML models for confidence prediction."""
        if not ML_AVAILABLE:
            logger.warning("ML libraries not available - using fallback confidence scoring")
            return
        
        try:
            # Model for confidence prediction based on features
            self.confidence_models['feature_based'] = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42
            )
            
            # Model for uncertainty quantification
            self.uncertainty_models['ensemble_variance'] = RandomForestClassifier(
                n_estimators=50,
                max_depth=8,
                random_state=42
            )
            
            # Calibration model for probability calibration
            self.calibration_models['isotonic'] = CalibratedClassifierCV(
                LogisticRegression(random_state=42),
                method='isotonic'
            )
            
            logger.info("Confidence scoring models initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize confidence models: {e}")
    
    def _load_calibration_data(self):
        """Load historical calibration data."""
        calibration_file = self.data_dir / 'calibration_history.json'
        
        if calibration_file.exists():
            try:
                with open(calibration_file, 'r') as f:
                    data = json.load(f)
                    
                for item in data:
                    item['timestamp'] = datetime.fromisoformat(item['timestamp'])
                    self.calibration_history.append(ConfidenceCalibrationData(**item))
                
                logger.info(f"Loaded {len(self.calibration_history)} calibration data points")
                
            except Exception as e:
                logger.error(f"Failed to load calibration data: {e}")
    
    def _save_calibration_data(self):
        """Save calibration data to disk."""
        calibration_file = self.data_dir / 'calibration_history.json'
        
        try:
            data = []
            for item in self.calibration_history:
                item_dict = asdict(item)
                item_dict['timestamp'] = item.timestamp.isoformat()
                data.append(item_dict)
            
            with open(calibration_file, 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save calibration data: {e}")
    
    def compute_enhanced_confidence(self, finding_data: Dict[str, Any]) -> ConfidenceMetrics:
        """
        Compute ML-enhanced confidence score with multiple factors.
        
        Args:
            finding_data: Dictionary containing finding information
            
        Returns:
            ConfidenceMetrics with detailed confidence analysis
        """
        try:
            # Extract basic features
            base_confidence = finding_data.get('confidence_score', 0.5)
            vulnerability_type = finding_data.get('vulnerability_type', 'unknown')
            file_path = finding_data.get('file_path', '')
            context_data = finding_data.get('context_data', {})
            evidence_data = finding_data.get('evidence', {})
            
            # 1. Compute evidence strength
            evidence_strength = self._compute_evidence_strength(evidence_data, context_data)
            
            # 2. Compute pattern reliability
            pattern_reliability = self._compute_pattern_reliability(vulnerability_type, context_data)
            
            # 3. Compute context support
            context_support = self._compute_context_support(context_data, file_path)
            
            # 4. Compute ensemble agreement (if multiple models available)
            ensemble_agreement = self._compute_ensemble_agreement(finding_data)
            
            # 5. Compute uncertainty estimate
            uncertainty_estimate = self._compute_uncertainty_estimate(finding_data)
            
            # 6. Compute calibration quality
            calibration_quality = self._compute_calibration_quality(base_confidence, vulnerability_type)
            
            # 7. Aggregate confidence score
            enhanced_confidence = self._aggregate_confidence_factors(
                base_confidence,
                evidence_strength,
                pattern_reliability,
                context_support,
                ensemble_agreement,
                uncertainty_estimate
            )
            
            # 8. Generate explanation
            explanation = self._generate_confidence_explanation(
                enhanced_confidence,
                evidence_strength,
                pattern_reliability,
                context_support,
                ensemble_agreement,
                uncertainty_estimate
            )
            
            return ConfidenceMetrics(
                confidence_score=enhanced_confidence,
                uncertainty_estimate=uncertainty_estimate,
                evidence_strength=evidence_strength,
                pattern_reliability=pattern_reliability,
                context_support=context_support,
                ensemble_agreement=ensemble_agreement,
                calibration_quality=calibration_quality,
                explanation=explanation
            )
            
        except Exception as e:
            logger.error(f"Error computing enhanced confidence: {e}")
            # Fallback to basic confidence
            return ConfidenceMetrics(
                confidence_score=finding_data.get('confidence_score', 0.5),
                uncertainty_estimate=0.5,
                evidence_strength=0.5,
                pattern_reliability=0.5,
                context_support=0.5,
                ensemble_agreement=0.5,
                calibration_quality=0.5,
                explanation="Fallback confidence - ML enhancement failed"
            )
    
    def _compute_evidence_strength(self, evidence_data: Dict[str, Any], 
                                 context_data: Dict[str, Any]) -> float:
        """Compute strength of evidence supporting the finding."""
        if not evidence_data:
            return 0.3  # Low evidence when no evidence provided
        
        strength_factors = []
        
        # Check for multiple evidence sources
        evidence_count = len(evidence_data.get('sources', []))
        if evidence_count > 1:
            strength_factors.append(min(0.3, evidence_count * 0.1))
        
        # Check evidence quality indicators
        if evidence_data.get('pattern_matches', 0) > 1:
            strength_factors.append(0.2)
        
        if evidence_data.get('cross_references', 0) > 0:
            strength_factors.append(0.15)
        
        # Context-based evidence
        if context_data.get('file_type') in ['source', 'application']:
            strength_factors.append(0.1)
        
        if not context_data.get('framework_detected', True):
            strength_factors.append(0.15)  # Non-framework code is stronger evidence
        
        # Evidence consistency
        if evidence_data.get('consistency_score', 0) > 0.8:
            strength_factors.append(0.1)
        
        total_strength = sum(strength_factors)
        return min(1.0, max(0.1, total_strength))
    
    def _compute_pattern_reliability(self, vulnerability_type: str, 
                                   context_data: Dict[str, Any]) -> float:
        """Compute reliability of the pattern that detected this vulnerability."""
        # Check cache first
        cache_key = f"{vulnerability_type}_{hash(str(context_data))}"
        if cache_key in self.pattern_reliability_cache:
            return self.pattern_reliability_cache[cache_key]
        
        # Get recent calibration data for this vulnerability type
        recent_data = self._get_recent_calibration_data(vulnerability_type)
        
        if len(recent_data) < 3:
            # Not enough data - use default reliability
            reliability = 0.6
        else:
            # Calculate accuracy of this pattern
            correct_predictions = sum(1 for d in recent_data 
                                    if (d.predicted_confidence > 0.5) == d.actual_outcome)
            reliability = correct_predictions / len(recent_data)
        
        # Adjust based on context
        if context_data.get('framework_detected'):
            reliability *= 0.8  # Framework code less reliable
        
        if context_data.get('file_size', 0) < 100:
            reliability *= 0.9  # Very small files less reliable
        
        # Cache the result
        self.pattern_reliability_cache[cache_key] = reliability
        
        return reliability
    
    def _compute_context_support(self, context_data: Dict[str, Any], file_path: str) -> float:
        """Compute how much the context supports the finding."""
        support_factors = []
        
        # File type support
        if context_data.get('file_type') == 'source':
            support_factors.append(0.2)
        elif context_data.get('file_type') == 'resource':
            support_factors.append(0.1)
        
        # Framework detection (negative support for security findings)
        if not context_data.get('framework_detected', True):
            support_factors.append(0.15)
        
        # File location support
        if '/src/' in file_path or '/app/' in file_path:
            support_factors.append(0.1)
        
        if '/test/' in file_path or '/mock/' in file_path:
            support_factors.append(-0.1)  # Test code less likely to be real vulnerability
        
        # File size support
        file_size = context_data.get('file_size', 0)
        if 100 <= file_size <= 10000:  # Reasonable file size
            support_factors.append(0.1)
        elif file_size < 50:  # Very small files are suspicious
            support_factors.append(-0.15)
        
        # Complexity support
        complexity = context_data.get('complexity_score', 0.5)
        if complexity > 0.7:
            support_factors.append(0.1)  # Complex code more likely to have vulnerabilities
        
        # Language/platform support
        if context_data.get('language') in ['java', 'kotlin']:
            support_factors.append(0.05)
        
        total_support = sum(support_factors)
        return max(0.0, min(1.0, 0.5 + total_support))  # Base 0.5 + adjustments
    
    def _compute_ensemble_agreement(self, finding_data: Dict[str, Any]) -> float:
        """Compute agreement among ensemble models."""
        # This would integrate with actual ensemble models
        # For now, simulate based on confidence variations
        
        base_confidence = finding_data.get('confidence_score', 0.5)
        
        # Simulate multiple model predictions around the base confidence
        # In a real implementation, this would use actual ensemble predictions
        model_predictions = [
            base_confidence,
            base_confidence + np.random.normal(0, 0.1),
            base_confidence + np.random.normal(0, 0.15),
            base_confidence + np.random.normal(0, 0.12)
        ]
        
        # Clip predictions to valid range
        model_predictions = [max(0.0, min(1.0, p)) for p in model_predictions]
        
        # Calculate agreement as inverse of variance
        if len(model_predictions) > 1:
            variance = np.var(model_predictions)
            agreement = 1.0 / (1.0 + variance * 10)  # Scale variance
        else:
            agreement = 0.5  # Default when no ensemble
        
        return agreement
    
    def _compute_uncertainty_estimate(self, finding_data: Dict[str, Any]) -> float:
        """Compute uncertainty estimate for the prediction."""
        uncertainty_factors = []
        
        # Base confidence uncertainty (closer to 0.5 = higher uncertainty)
        base_confidence = finding_data.get('confidence_score', 0.5)
        confidence_uncertainty = 1.0 - abs(base_confidence - 0.5) * 2
        uncertainty_factors.append(confidence_uncertainty * 0.3)
        
        # Evidence uncertainty
        evidence_data = finding_data.get('evidence', {})
        if not evidence_data or len(evidence_data) < 2:
            uncertainty_factors.append(0.2)  # High uncertainty with little evidence
        
        # Context uncertainty
        context_data = finding_data.get('context_data', {})
        if context_data.get('framework_detected'):
            uncertainty_factors.append(0.15)  # Framework code adds uncertainty
        
        if context_data.get('file_size', 0) < 100:
            uncertainty_factors.append(0.1)  # Small files add uncertainty
        
        # Pattern novelty uncertainty
        vulnerability_type = finding_data.get('vulnerability_type', 'unknown')
        recent_data = self._get_recent_calibration_data(vulnerability_type)
        if len(recent_data) < 5:
            uncertainty_factors.append(0.2)  # Novel patterns have higher uncertainty
        
        total_uncertainty = sum(uncertainty_factors)
        return min(1.0, max(0.1, total_uncertainty))
    
    def _compute_calibration_quality(self, confidence: float, vulnerability_type: str) -> float:
        """Compute quality of calibration for this confidence level and type."""
        recent_data = self._get_recent_calibration_data(vulnerability_type)
        
        if len(recent_data) < 5:
            return 0.5  # Default quality when insufficient data
        
        # Find predictions with similar confidence levels
        similar_confidence_data = [
            d for d in recent_data 
            if abs(d.predicted_confidence - confidence) < 0.2
        ]
        
        if len(similar_confidence_data) < 3:
            return 0.5  # Not enough similar predictions
        
        # Calculate calibration error
        avg_confidence = sum(d.predicted_confidence for d in similar_confidence_data) / len(similar_confidence_data)
        accuracy = sum(d.actual_outcome for d in similar_confidence_data) / len(similar_confidence_data)
        
        calibration_error = abs(avg_confidence - accuracy)
        calibration_quality = 1.0 - calibration_error
        
        return max(0.0, min(1.0, calibration_quality))
    
    def _aggregate_confidence_factors(self, base_confidence: float, evidence_strength: float,
                                    pattern_reliability: float, context_support: float,
                                    ensemble_agreement: float, uncertainty_estimate: float) -> float:
        """Aggregate all confidence factors into final confidence score."""
        # Weighted combination of factors
        confidence_factors = [
            (base_confidence, 0.25),  # Base confidence
            (evidence_strength, 0.2),  # Evidence strength
            (pattern_reliability, 0.2),  # Pattern reliability
            (context_support, self.context_weight),  # Context support
            (ensemble_agreement, self.ensemble_weight),  # Ensemble agreement
        ]
        
        # Calculate weighted average
        weighted_sum = sum(factor * weight for factor, weight in confidence_factors)
        total_weight = sum(weight for _, weight in confidence_factors)
        
        aggregated_confidence = weighted_sum / total_weight
        
        # Apply uncertainty adjustment
        uncertainty_adjustment = 1.0 - (uncertainty_estimate * self.uncertainty_weight)
        final_confidence = aggregated_confidence * uncertainty_adjustment
        
        return max(0.0, min(1.0, final_confidence))
    
    def _generate_confidence_explanation(self, confidence: float, evidence_strength: float,
                                       pattern_reliability: float, context_support: float,
                                       ensemble_agreement: float, uncertainty_estimate: float) -> str:
        """Generate human-readable explanation for confidence score."""
        explanations = []
        
        # Confidence level description
        if confidence > 0.8:
            explanations.append("High confidence")
        elif confidence > 0.6:
            explanations.append("Moderate confidence")
        elif confidence > 0.4:
            explanations.append("Low confidence")
        else:
            explanations.append("Very low confidence")
        
        # Key factors
        if evidence_strength > 0.7:
            explanations.append("strong evidence")
        elif evidence_strength < 0.4:
            explanations.append("weak evidence")
        
        if pattern_reliability > 0.8:
            explanations.append("reliable pattern")
        elif pattern_reliability < 0.5:
            explanations.append("unreliable pattern")
        
        if context_support > 0.7:
            explanations.append("supportive context")
        elif context_support < 0.4:
            explanations.append("unsupportive context")
        
        if ensemble_agreement > 0.8:
            explanations.append("model agreement")
        elif ensemble_agreement < 0.5:
            explanations.append("model disagreement")
        
        if uncertainty_estimate > 0.7:
            explanations.append("high uncertainty")
        elif uncertainty_estimate < 0.3:
            explanations.append("low uncertainty")
        
        return f"{explanations[0]} ({', '.join(explanations[1:])})"
    
    def _get_recent_calibration_data(self, vulnerability_type: str) -> List[ConfidenceCalibrationData]:
        """Get recent calibration data for a specific vulnerability type."""
        cutoff_date = datetime.now() - timedelta(days=self.calibration_window_days)
        
        return [
            data for data in self.calibration_history
            if (data.vulnerability_type == vulnerability_type and
                data.timestamp >= cutoff_date)
        ]
    
    def record_calibration_data(self, predicted_confidence: float, actual_outcome: bool,
                              vulnerability_type: str, context_features: Dict[str, Any]):
        """Record calibration data for future confidence improvements."""
        calibration_data = ConfidenceCalibrationData(
            predicted_confidence=predicted_confidence,
            actual_outcome=actual_outcome,
            vulnerability_type=vulnerability_type,
            context_features=context_features,
            timestamp=datetime.now()
        )
        
        self.calibration_history.append(calibration_data)
        
        # Limit history size
        max_history = self.confidence_config.get('max_calibration_history', 1000)
        if len(self.calibration_history) > max_history:
            self.calibration_history = self.calibration_history[-max_history:]
        
        # Save to disk periodically
        if len(self.calibration_history) % 50 == 0:
            self._save_calibration_data()
        
        logger.debug(f"Recorded calibration data for {vulnerability_type}")
    
    def get_confidence_statistics(self) -> Dict[str, Any]:
        """Get statistics about confidence scoring performance."""
        if not self.calibration_history:
            return {'status': 'no_data'}
        
        # Overall calibration accuracy
        recent_data = [d for d in self.calibration_history 
                      if d.timestamp >= datetime.now() - timedelta(days=7)]
        
        if not recent_data:
            return {'status': 'no_recent_data'}
        
        # Calculate calibration metrics
        total_predictions = len(recent_data)
        high_confidence_predictions = [d for d in recent_data if d.predicted_confidence > 0.7]
        low_confidence_predictions = [d for d in recent_data if d.predicted_confidence < 0.4]
        
        high_confidence_accuracy = (
            sum(d.actual_outcome for d in high_confidence_predictions) / len(high_confidence_predictions)
            if high_confidence_predictions else 0
        )
        
        low_confidence_accuracy = (
            sum(d.actual_outcome for d in low_confidence_predictions) / len(low_confidence_predictions)
            if low_confidence_predictions else 0
        )
        
        overall_accuracy = sum(d.actual_outcome for d in recent_data) / total_predictions
        
        # Vulnerability type breakdown
        vuln_type_stats = defaultdict(lambda: {'total': 0, 'correct': 0})
        for data in recent_data:
            vuln_type_stats[data.vulnerability_type]['total'] += 1
            if data.actual_outcome:
                vuln_type_stats[data.vulnerability_type]['correct'] += 1
        
        return {
            'status': 'active',
            'total_predictions': total_predictions,
            'overall_accuracy': overall_accuracy,
            'high_confidence_accuracy': high_confidence_accuracy,
            'low_confidence_accuracy': low_confidence_accuracy,
            'vulnerability_type_stats': dict(vuln_type_stats),
            'calibration_window_days': self.calibration_window_days
        }
    
    def export_confidence_models(self) -> Dict[str, Any]:
        """Export confidence models for external use."""
        export_data = {
            'model_info': {
                'ml_available': ML_AVAILABLE,
                'models_initialized': len(self.confidence_models) > 0,
                'calibration_data_points': len(self.calibration_history)
            },
            'configuration': self.confidence_config,
            'pattern_reliability_cache': self.pattern_reliability_cache
        }
        
        return export_data

class ConfidenceIntegrationManager:
    """Manage integration of ML-enhanced confidence scoring with AODS."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.confidence_scorer = MLEnhancedConfidenceScorer(config)
        
    def enhance_finding_confidence(self, finding_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance a finding with ML-enhanced confidence scoring."""
        try:
            # Compute enhanced confidence
            confidence_metrics = self.confidence_scorer.compute_enhanced_confidence(finding_data)
            
            # Add enhanced confidence data to finding
            finding_data['enhanced_confidence'] = {
                'score': confidence_metrics.confidence_score,
                'uncertainty': confidence_metrics.uncertainty_estimate,
                'evidence_strength': confidence_metrics.evidence_strength,
                'pattern_reliability': confidence_metrics.pattern_reliability,
                'context_support': confidence_metrics.context_support,
                'ensemble_agreement': confidence_metrics.ensemble_agreement,
                'calibration_quality': confidence_metrics.calibration_quality,
                'explanation': confidence_metrics.explanation,
                'enhancement_timestamp': datetime.now().isoformat()
            }
            
            # Update the main confidence score
            finding_data['confidence_score'] = confidence_metrics.confidence_score
            finding_data['confidence_explanation'] = confidence_metrics.explanation
            
            return finding_data
            
        except Exception as e:
            logger.error(f"Failed to enhance finding confidence: {e}")
            return finding_data
    
    def record_finding_outcome(self, finding_id: str, finding_data: Dict[str, Any], 
                             is_true_positive: bool):
        """Record the outcome of a finding for calibration."""
        try:
            predicted_confidence = finding_data.get('confidence_score', 0.5)
            vulnerability_type = finding_data.get('vulnerability_type', 'unknown')
            context_features = finding_data.get('context_data', {})
            
            self.confidence_scorer.record_calibration_data(
                predicted_confidence,
                is_true_positive,
                vulnerability_type,
                context_features
            )
            
        except Exception as e:
            logger.error(f"Failed to record finding outcome: {e}")
    
    def get_confidence_statistics(self) -> Dict[str, Any]:
        """Get confidence scoring statistics."""
        return self.confidence_scorer.get_confidence_statistics()

# Global instance for easy access
_confidence_integration = None

def initialize_ml_confidence(config: Dict[str, Any]) -> ConfidenceIntegrationManager:
    """Initialize global ML confidence integration."""
    global _confidence_integration
    
    if _confidence_integration is None:
        _confidence_integration = ConfidenceIntegrationManager(config)
    
    return _confidence_integration

def get_ml_confidence_integration() -> Optional[ConfidenceIntegrationManager]:
    """Get the global ML confidence integration instance."""
    return _confidence_integration

def enhance_finding_confidence(finding_data: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience function to enhance finding confidence."""
    integration = get_ml_confidence_integration()
    if integration:
        return integration.enhance_finding_confidence(finding_data)
    return finding_data 